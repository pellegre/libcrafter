//! DHCPv6 packet layer.

use core::any::Any;
use core::net::Ipv6Addr;
use core::ops::Div;

use crate::error::{CrafterError, Result};
use crate::field::{Field, FieldState};
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

use super::constants::{
    DHCPV6_CLIENT_PORT, DHCPV6_CLIENT_SERVER_HEADER_LEN, DHCPV6_RELAY_FORW,
    DHCPV6_RELAY_HEADER_LEN, DHCPV6_RELAY_REPL, DHCPV6_SERVER_PORT, DHCPV6_TRANSACTION_ID_MAX,
};
use super::message::{dhcpv6_message_type_summary, Dhcpv6MessageType};
use super::option::{Dhcpv6Option, Dhcpv6OptionCode};

/// DHCPv6 packet layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcpv6 {
    message_type: Field<Dhcpv6MessageType>,
    transaction_id: Field<u32>,
    relay: Option<Dhcpv6RelayHeader>,
    options: Vec<Dhcpv6Option>,
}

/// DHCPv6 relay fixed-header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcpv6RelayHeader {
    hop_count: Field<u8>,
    link_address: Field<Ipv6Addr>,
    peer_address: Field<Ipv6Addr>,
}

impl Dhcpv6RelayHeader {
    /// Create a relay header with deterministic hop-count default.
    pub fn new(link_address: Ipv6Addr, peer_address: Ipv6Addr) -> Self {
        Self {
            hop_count: Field::defaulted(0),
            link_address: Field::user(link_address),
            peer_address: Field::user(peer_address),
        }
    }

    /// Set the relay hop count.
    pub fn hop_count(mut self, hop_count: u8) -> Self {
        self.hop_count.set_user(hop_count);
        self
    }

    /// Set the relay link-address field.
    pub fn link_address(mut self, link_address: Ipv6Addr) -> Self {
        self.link_address.set_user(link_address);
        self
    }

    /// Set the relay peer-address field.
    pub fn peer_address(mut self, peer_address: Ipv6Addr) -> Self {
        self.peer_address.set_user(peer_address);
        self
    }

    /// Relay hop-count value.
    pub fn hop_count_value(&self) -> u8 {
        self.hop_count.value().copied().unwrap_or(0)
    }

    /// State of the relay hop-count field.
    pub const fn hop_count_state(&self) -> FieldState {
        self.hop_count.state()
    }

    /// Relay link-address value.
    pub fn link_address_value(&self) -> Ipv6Addr {
        self.link_address
            .value()
            .copied()
            .unwrap_or(Ipv6Addr::UNSPECIFIED)
    }

    /// State of the relay link-address field.
    pub const fn link_address_state(&self) -> FieldState {
        self.link_address.state()
    }

    /// Relay peer-address value.
    pub fn peer_address_value(&self) -> Ipv6Addr {
        self.peer_address
            .value()
            .copied()
            .unwrap_or(Ipv6Addr::UNSPECIFIED)
    }

    /// State of the relay peer-address field.
    pub const fn peer_address_state(&self) -> FieldState {
        self.peer_address.state()
    }
}

impl Dhcpv6 {
    /// Create an empty DHCPv6 client/server message with deterministic defaults.
    pub fn new() -> Self {
        Self {
            message_type: Field::defaulted(Dhcpv6MessageType::Solicit),
            transaction_id: Field::defaulted(0),
            relay: None,
            options: Vec::new(),
        }
    }

    /// Create a DHCPv6 Solicit message with the supplied transaction ID.
    pub fn solicit(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Solicit, transaction_id)
    }

    /// Create a DHCPv6 Advertise message with the supplied transaction ID.
    pub fn advertise(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Advertise, transaction_id)
    }

    /// Create a DHCPv6 Request message with the supplied transaction ID.
    pub fn request(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Request, transaction_id)
    }

    /// Create a DHCPv6 Confirm message with the supplied transaction ID.
    pub fn confirm(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Confirm, transaction_id)
    }

    /// Create a DHCPv6 Renew message with the supplied transaction ID.
    pub fn renew(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Renew, transaction_id)
    }

    /// Create a DHCPv6 Rebind message with the supplied transaction ID.
    pub fn rebind(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Rebind, transaction_id)
    }

    /// Create a DHCPv6 Reply message with the supplied transaction ID.
    pub fn reply(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Reply, transaction_id)
    }

    /// Create a DHCPv6 Release message with the supplied transaction ID.
    pub fn release(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Release, transaction_id)
    }

    /// Create a DHCPv6 Decline message with the supplied transaction ID.
    pub fn decline(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Decline, transaction_id)
    }

    /// Create a DHCPv6 Reconfigure message with the supplied transaction ID.
    pub fn reconfigure(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Reconfigure, transaction_id)
    }

    /// Create a DHCPv6 Information-request message with the supplied transaction ID.
    pub fn information_request(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::InformationRequest, transaction_id)
    }

    /// Create a DHCPv6 Relay-forward message body.
    pub fn relay_forward(link_address: Ipv6Addr, peer_address: Ipv6Addr) -> Self {
        Self::new()
            .message_type(Dhcpv6MessageType::RelayForw)
            .relay_header(Dhcpv6RelayHeader::new(link_address, peer_address))
    }

    /// Create a DHCPv6 Relay-reply message body.
    pub fn relay_reply(link_address: Ipv6Addr, peer_address: Ipv6Addr) -> Self {
        Self::new()
            .message_type(Dhcpv6MessageType::RelayRepl)
            .relay_header(Dhcpv6RelayHeader::new(link_address, peer_address))
    }

    /// Decode a DHCPv6 message.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_dhcpv6(bytes)
    }

    fn client_server_message(message_type: Dhcpv6MessageType, transaction_id: u32) -> Self {
        Self::new()
            .message_type(message_type)
            .transaction_id(transaction_id)
    }

    /// Set the DHCPv6 message type.
    pub fn message_type(mut self, message_type: Dhcpv6MessageType) -> Self {
        self.message_type.set_user(message_type);
        self
    }

    /// Set the DHCPv6 message type from a raw codepoint.
    pub fn message_type_code(self, code: u8) -> Self {
        self.message_type(Dhcpv6MessageType::from_code(code))
    }

    /// Current message type value.
    pub fn message_type_value(&self) -> Dhcpv6MessageType {
        self.message_type
            .value()
            .copied()
            .unwrap_or(Dhcpv6MessageType::Solicit)
    }

    /// State of the message type field.
    pub const fn message_type_state(&self) -> FieldState {
        self.message_type.state()
    }

    /// Set the 24-bit DHCPv6 transaction ID.
    pub fn transaction_id(mut self, transaction_id: u32) -> Self {
        self.transaction_id.set_user(transaction_id);
        self
    }

    /// Try to set the 24-bit DHCPv6 transaction ID.
    pub fn try_transaction_id(mut self, transaction_id: u32) -> Result<Self> {
        validate_transaction_id(transaction_id)?;
        self.transaction_id.set_user(transaction_id);
        Ok(self)
    }

    /// Current transaction ID value.
    pub fn transaction_id_value(&self) -> u32 {
        self.transaction_id.value().copied().unwrap_or(0)
    }

    /// State of the transaction ID field.
    pub const fn transaction_id_state(&self) -> FieldState {
        self.transaction_id.state()
    }

    /// Set relay fixed-header fields.
    pub fn relay_header(mut self, relay: Dhcpv6RelayHeader) -> Self {
        self.relay = Some(relay);
        self
    }

    /// Set relay hop count when this message carries a relay header.
    pub fn hop_count(mut self, hop_count: u8) -> Self {
        if let Some(relay) = self.relay.take() {
            self.relay = Some(relay.hop_count(hop_count));
        }
        self
    }

    /// Set relay link-address when this message carries a relay header.
    pub fn link_address(mut self, link_address: Ipv6Addr) -> Self {
        if let Some(relay) = self.relay.take() {
            self.relay = Some(relay.link_address(link_address));
        }
        self
    }

    /// Set relay peer-address when this message carries a relay header.
    pub fn peer_address(mut self, peer_address: Ipv6Addr) -> Self {
        if let Some(relay) = self.relay.take() {
            self.relay = Some(relay.peer_address(peer_address));
        }
        self
    }

    /// Borrow relay fixed-header fields, when present.
    pub fn relay(&self) -> Option<&Dhcpv6RelayHeader> {
        self.relay.as_ref()
    }

    /// Mutably borrow relay fixed-header fields, when present.
    pub fn relay_mut(&mut self) -> Option<&mut Dhcpv6RelayHeader> {
        self.relay.as_mut()
    }

    /// Append an option and return the updated layer.
    pub fn option(mut self, option: Dhcpv6Option) -> Self {
        self.options.push(option);
        self
    }

    /// Append an OPTION_CLIENTID option.
    pub fn client_id(self, duid: impl Into<Vec<u8>>) -> Self {
        self.option(Dhcpv6Option::client_id(duid))
    }

    /// Append an OPTION_SERVERID option.
    pub fn server_id(self, duid: impl Into<Vec<u8>>) -> Self {
        self.option(Dhcpv6Option::server_id(duid))
    }

    /// Append an OPTION_ORO option.
    pub fn oro<I, C>(self, codes: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<Dhcpv6OptionCode>,
    {
        self.option(Dhcpv6Option::oro(codes))
    }

    /// Append an OPTION_PREFERENCE option.
    pub fn preference(self, preference: u8) -> Self {
        self.option(Dhcpv6Option::preference(preference))
    }

    /// Append an OPTION_ELAPSED_TIME option in hundredths of a second.
    pub fn elapsed_time(self, centiseconds: u16) -> Self {
        self.option(Dhcpv6Option::elapsed_time(centiseconds))
    }

    /// Append an OPTION_RAPID_COMMIT option.
    pub fn rapid_commit(self) -> Self {
        self.option(Dhcpv6Option::rapid_commit())
    }

    /// Replace the option list.
    pub fn options(mut self, options: impl Into<Vec<Dhcpv6Option>>) -> Self {
        self.options = options.into();
        self
    }

    /// Borrow the option list.
    pub fn options_ref(&self) -> &[Dhcpv6Option] {
        &self.options
    }

    /// Mutably borrow the option list.
    pub fn options_mut(&mut self) -> &mut Vec<Dhcpv6Option> {
        &mut self.options
    }

    /// Return OPTION_CLIENTID DUID bytes from the first Client ID option.
    pub fn client_id_value(&self) -> Option<&[u8]> {
        self.first_option(super::constants::DHCPV6_OPTION_CLIENTID)
            .and_then(Dhcpv6Option::client_id_value)
    }

    /// Return OPTION_SERVERID DUID bytes from the first Server ID option.
    pub fn server_id_value(&self) -> Option<&[u8]> {
        self.first_option(super::constants::DHCPV6_OPTION_SERVERID)
            .and_then(Dhcpv6Option::server_id_value)
    }

    /// Decode requested option codepoints from the first ORO option.
    pub fn oro_value(&self) -> Result<Option<Vec<Dhcpv6OptionCode>>> {
        match self.first_option(super::constants::DHCPV6_OPTION_ORO) {
            Some(option) => option.oro_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Preference option.
    pub fn preference_value(&self) -> Result<Option<u8>> {
        match self.first_option(super::constants::DHCPV6_OPTION_PREFERENCE) {
            Some(option) => option.preference_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Elapsed Time option.
    pub fn elapsed_time_value(&self) -> Result<Option<u16>> {
        match self.first_option(super::constants::DHCPV6_OPTION_ELAPSED_TIME) {
            Some(option) => option.elapsed_time_value(),
            None => Ok(None),
        }
    }

    /// Return true when a valid Rapid Commit option is present.
    pub fn rapid_commit_present(&self) -> Result<bool> {
        match self.first_option(super::constants::DHCPV6_OPTION_RAPID_COMMIT) {
            Some(option) => option.rapid_commit_present(),
            None => Ok(false),
        }
    }

    /// Encoded DHCPv6 client/server message length.
    pub fn encoded_dhcpv6_len(&self) -> usize {
        let header_len = if self.relay.is_some() {
            DHCPV6_RELAY_HEADER_LEN
        } else {
            DHCPV6_CLIENT_SERVER_HEADER_LEN
        };
        header_len
            + self
                .options
                .iter()
                .map(|option| super::constants::DHCPV6_OPTION_HEADER_LEN + option.payload_len())
                .sum::<usize>()
    }

    fn first_option(&self, code: u16) -> Option<&Dhcpv6Option> {
        self.options
            .iter()
            .find(|option| option.codepoint() == code)
    }
}

impl Default for Dhcpv6 {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Dhcpv6 {
    fn name(&self) -> &'static str {
        "Dhcpv6"
    }

    fn summary(&self) -> String {
        if let Some(relay) = &self.relay {
            return format!(
                "Dhcpv6(type={}, hop_count={}, link_address={}, peer_address={}, options={})",
                dhcpv6_message_type_summary(self.message_type_value()),
                relay.hop_count_value(),
                relay.link_address_value(),
                relay.peer_address_value(),
                self.options.len(),
            );
        }
        format!(
            "Dhcpv6(type={}, xid=0x{:06x}, options={})",
            dhcpv6_message_type_summary(self.message_type_value()),
            self.transaction_id_value(),
            self.options.len(),
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            (
                "message_type",
                dhcpv6_message_type_summary(self.message_type_value()),
            ),
            (
                "transaction_id",
                format!("0x{:06x}", self.transaction_id_value()),
            ),
            ("options", self.options.len().to_string()),
        ];
        if let Some(relay) = &self.relay {
            fields.push(("hop_count", relay.hop_count_value().to_string()));
            fields.push(("link_address", relay.link_address_value().to_string()));
            fields.push(("peer_address", relay.peer_address_value().to_string()));
        }
        fields
    }

    fn encoded_len(&self) -> usize {
        self.encoded_dhcpv6_len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        if let Some(relay) = &self.relay {
            out.reserve(self.encoded_dhcpv6_len());
            out.push(self.message_type_value().code());
            out.push(relay.hop_count_value());
            out.extend_from_slice(&relay.link_address_value().octets());
            out.extend_from_slice(&relay.peer_address_value().octets());
            for option in &self.options {
                option.encode_into(out)?;
            }
            return Ok(());
        }

        let transaction_id = self.transaction_id_value();
        validate_transaction_id(transaction_id)?;

        out.reserve(self.encoded_dhcpv6_len());
        out.push(self.message_type_value().code());
        out.push(((transaction_id >> 16) & 0xff) as u8);
        out.push(((transaction_id >> 8) & 0xff) as u8);
        out.push((transaction_id & 0xff) as u8);
        for option in &self.options {
            option.encode_into(out)?;
        }
        Ok(())
    }

    fn clone_layer(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl<R> Div<R> for Dhcpv6
where
    R: IntoPacket,
{
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        Packet::from_layer(self).concat(rhs)
    }
}

/// Append a decoded DHCPv6 message to an existing packet stack.
pub(crate) fn append_dhcpv6_packet(packet: Packet, bytes: &[u8]) -> Result<Packet> {
    Ok(packet.push(decode_dhcpv6(bytes)?))
}

/// Return true when a UDP source/destination pair is a DHCPv6 client/server pair.
pub(crate) const fn is_dhcpv6_port_pair(source_port: u16, destination_port: u16) -> bool {
    matches!(
        (source_port, destination_port),
        (DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT) | (DHCPV6_SERVER_PORT, DHCPV6_CLIENT_PORT)
    )
}

/// Return true when a UDP source/destination pair is a DHCPv6 relay/server pair.
pub(crate) const fn is_dhcpv6_relay_port_pair(source_port: u16, destination_port: u16) -> bool {
    matches!(
        (source_port, destination_port),
        (DHCPV6_SERVER_PORT, DHCPV6_SERVER_PORT)
    )
}

/// Return true when bytes have enough shape to decode as a DHCPv6 client/server message.
pub(crate) fn looks_like_dhcpv6_client_payload(bytes: &[u8]) -> bool {
    bytes.len() >= DHCPV6_CLIENT_SERVER_HEADER_LEN
        && !matches!(bytes[0], DHCPV6_RELAY_FORW | DHCPV6_RELAY_REPL)
}

/// Return true when bytes have enough shape to decode as a DHCPv6 relay message.
pub(crate) fn looks_like_dhcpv6_relay_payload(bytes: &[u8]) -> bool {
    bytes.len() >= DHCPV6_RELAY_HEADER_LEN
        && matches!(bytes[0], DHCPV6_RELAY_FORW | DHCPV6_RELAY_REPL)
}

/// Return true when the UDP port pair and payload shape plausibly carry DHCPv6.
pub(crate) fn looks_like_dhcpv6_payload(
    source_port: u16,
    destination_port: u16,
    bytes: &[u8],
) -> bool {
    if is_dhcpv6_port_pair(source_port, destination_port) {
        return looks_like_dhcpv6_client_payload(bytes);
    }

    is_dhcpv6_relay_port_pair(source_port, destination_port)
        && looks_like_dhcpv6_relay_payload(bytes)
}

fn decode_dhcpv6(bytes: &[u8]) -> Result<Dhcpv6> {
    match bytes.first().copied() {
        Some(DHCPV6_RELAY_FORW | DHCPV6_RELAY_REPL) => decode_dhcpv6_relay(bytes),
        _ => decode_dhcpv6_client_server(bytes),
    }
}

fn decode_dhcpv6_client_server(bytes: &[u8]) -> Result<Dhcpv6> {
    if bytes.len() < DHCPV6_CLIENT_SERVER_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "dhcpv6.client_server_header",
            DHCPV6_CLIENT_SERVER_HEADER_LEN,
            bytes.len(),
        ));
    }

    let transaction_id = ((bytes[1] as u32) << 16) | ((bytes[2] as u32) << 8) | bytes[3] as u32;
    Ok(Dhcpv6 {
        message_type: Field::user(Dhcpv6MessageType::from_code(bytes[0])),
        transaction_id: Field::user(transaction_id),
        relay: None,
        options: Dhcpv6Option::decode_all(&bytes[DHCPV6_CLIENT_SERVER_HEADER_LEN..])?,
    })
}

fn decode_dhcpv6_relay(bytes: &[u8]) -> Result<Dhcpv6> {
    if bytes.len() < DHCPV6_RELAY_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "dhcpv6.relay_header",
            DHCPV6_RELAY_HEADER_LEN,
            bytes.len(),
        ));
    }

    Ok(Dhcpv6 {
        message_type: Field::user(Dhcpv6MessageType::from_code(bytes[0])),
        transaction_id: Field::defaulted(0),
        relay: Some(Dhcpv6RelayHeader {
            hop_count: Field::user(bytes[1]),
            link_address: Field::user(Ipv6Addr::from(copy_array_16(&bytes[2..18]))),
            peer_address: Field::user(Ipv6Addr::from(copy_array_16(&bytes[18..34]))),
        }),
        options: Dhcpv6Option::decode_all(&bytes[DHCPV6_RELAY_HEADER_LEN..])?,
    })
}

fn validate_transaction_id(transaction_id: u32) -> Result<()> {
    if transaction_id > DHCPV6_TRANSACTION_ID_MAX {
        return Err(CrafterError::invalid_field_value(
            "dhcpv6.transaction_id",
            "value exceeds 24 bits",
        ));
    }
    Ok(())
}

fn copy_array_16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    out
}

#[cfg(test)]
mod dhcpv6_client_header_tests {
    use super::Dhcpv6;
    use crate::error::CrafterError;
    use crate::field::FieldState;
    use crate::packet::{Layer, Packet};
    use crate::protocols::dhcp::v6::{Dhcpv6MessageType, Dhcpv6Option};

    #[test]
    fn dhcpv6_client_header_default_compiles() {
        let bytes = Packet::from_layer(Dhcpv6::default()).compile().unwrap();

        assert_eq!(bytes.as_bytes(), &[1, 0, 0, 0]);
    }

    #[test]
    fn dhcpv6_client_header_compile_includes_options() {
        let dhcpv6 = Dhcpv6::new()
            .message_type(Dhcpv6MessageType::Request)
            .transaction_id(0x00ab_cdef)
            .option(Dhcpv6Option::raw(
                23u16,
                [0x20, 0x01, 0x0d, 0xb8].as_slice(),
            ));
        let bytes = Packet::from_layer(dhcpv6.clone()).compile().unwrap();

        assert_eq!(
            bytes.as_bytes(),
            &[3, 0xab, 0xcd, 0xef, 0x00, 0x17, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8],
        );
        assert_eq!(dhcpv6.encoded_len(), bytes.as_bytes().len());
    }

    #[test]
    fn dhcpv6_client_header_decode_marks_wire_fields_user_set() {
        let decoded = Dhcpv6::decode(&[7, 0x01, 0x02, 0x03, 0x00, 0x0e, 0x00, 0x00]).unwrap();

        assert_eq!(decoded.message_type_value(), Dhcpv6MessageType::Reply);
        assert_eq!(decoded.message_type_state(), FieldState::User);
        assert_eq!(decoded.transaction_id_value(), 0x010203);
        assert_eq!(decoded.transaction_id_state(), FieldState::User);
        assert_eq!(decoded.options_ref().len(), 1);
        assert_eq!(decoded.options_ref()[0].codepoint(), 14);

        let recompiled = Packet::from_layer(decoded).compile().unwrap();
        assert_eq!(
            recompiled.as_bytes(),
            &[7, 0x01, 0x02, 0x03, 0x00, 0x0e, 0x00, 0x00]
        );
    }

    #[test]
    fn dhcpv6_client_header_preserves_unknown_message_type() {
        let decoded = Dhcpv6::decode(&[200, 0, 0, 1]).unwrap();

        assert_eq!(
            decoded.message_type_value(),
            Dhcpv6MessageType::Unknown(200)
        );
        assert_eq!(
            Packet::from_layer(decoded).compile().unwrap().as_bytes(),
            &[200, 0, 0, 1]
        );
    }

    #[test]
    fn dhcpv6_client_header_rejects_truncated_header_and_oversized_xid() {
        assert_eq!(
            Dhcpv6::decode(&[1, 2, 3]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.client_server_header", 4, 3),
        );

        let error = Packet::from_layer(Dhcpv6::new().transaction_id(0x0100_0000))
            .compile()
            .unwrap_err();
        assert_eq!(
            error,
            CrafterError::invalid_field_value("dhcpv6.transaction_id", "value exceeds 24 bits",),
        );
    }
}

#[cfg(test)]
mod dhcpv6_transaction_id_tests {
    use super::Dhcpv6;
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::Dhcpv6MessageType;

    #[test]
    fn dhcpv6_transaction_id_default_is_deterministic() {
        let first = Packet::from_layer(Dhcpv6::new()).compile().unwrap();
        let second = Packet::from_layer(Dhcpv6::default()).compile().unwrap();

        assert_eq!(first.as_bytes(), &[1, 0, 0, 0]);
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn dhcpv6_transaction_id_explicit_value_roundtrips() {
        let packet = Dhcpv6::new()
            .message_type(Dhcpv6MessageType::InformationRequest)
            .transaction_id(0x0012_3456);
        let bytes = Packet::from_layer(packet).compile().unwrap();

        assert_eq!(bytes.as_bytes(), &[11, 0x12, 0x34, 0x56]);
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();
        assert_eq!(decoded.transaction_id_value(), 0x0012_3456);
        assert_eq!(
            Packet::from_layer(decoded).compile().unwrap().as_bytes(),
            bytes.as_bytes(),
        );
    }

    #[test]
    fn dhcpv6_transaction_id_maximum_value_works() {
        let packet = Dhcpv6::new().try_transaction_id(0x00ff_ffff).unwrap();
        let bytes = Packet::from_layer(packet).compile().unwrap();

        assert_eq!(bytes.as_bytes(), &[1, 0xff, 0xff, 0xff]);
        assert_eq!(
            Dhcpv6::decode(bytes.as_bytes())
                .unwrap()
                .transaction_id_value(),
            0x00ff_ffff
        );
    }

    #[test]
    fn dhcpv6_transaction_id_invalid_typed_values_are_structured_errors() {
        let expected =
            CrafterError::invalid_field_value("dhcpv6.transaction_id", "value exceeds 24 bits");

        assert_eq!(
            Dhcpv6::new().try_transaction_id(0x0100_0000).unwrap_err(),
            expected,
        );
        assert_eq!(
            Packet::from_layer(Dhcpv6::new().transaction_id(0x0100_0000))
                .compile()
                .unwrap_err(),
            expected,
        );
    }
}

#[cfg(test)]
mod dhcpv6_client_decode_tests {
    use super::{
        append_dhcpv6_packet, is_dhcpv6_port_pair, looks_like_dhcpv6_client_payload, Dhcpv6,
    };
    use crate::error::CrafterError;
    use crate::packet::{NetworkLayer, Packet, Raw};
    use crate::protocols::dhcp::v6::{Dhcpv6MessageType, Dhcpv6Option};
    use crate::protocols::ip::v6::Ipv6;
    use crate::protocols::transport::Udp;

    #[test]
    fn dhcpv6_client_decode_append_packet_preserves_unknown_message_type() {
        let packet = append_dhcpv6_packet(Packet::new(), &[200, 0x01, 0x02, 0x03]).unwrap();
        let dhcpv6 = packet.layer::<Dhcpv6>().unwrap();

        assert_eq!(dhcpv6.message_type_value(), Dhcpv6MessageType::Unknown(200));
        assert_eq!(dhcpv6.transaction_id_value(), 0x010203);
    }

    #[test]
    fn dhcpv6_client_decode_reports_short_header_and_truncated_options() {
        assert_eq!(
            Dhcpv6::decode(&[1, 2, 3]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.client_server_header", 4, 3),
        );
        assert_eq!(
            Dhcpv6::decode(&[1, 0, 0, 0, 0, 23, 0, 4, 1]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.payload", 8, 5),
        );
    }

    #[test]
    fn dhcpv6_client_decode_port_and_payload_gate_is_conservative() {
        assert!(is_dhcpv6_port_pair(546, 547));
        assert!(is_dhcpv6_port_pair(547, 546));
        assert!(!is_dhcpv6_port_pair(547, 547));
        assert!(looks_like_dhcpv6_client_payload(&[1, 0, 0, 0]));
        assert!(looks_like_dhcpv6_client_payload(&[250, 0, 0, 0]));
        assert!(!looks_like_dhcpv6_client_payload(&[12, 0, 0, 0]));
        assert!(!looks_like_dhcpv6_client_payload(&[1, 0, 0]));
    }

    #[test]
    fn dhcpv6_client_decode_udp_registry_decodes_client_server_payload() {
        let packet = Ipv6::new()
            / Udp::dhcpv6_client()
            / Dhcpv6::new()
                .message_type(Dhcpv6MessageType::Request)
                .transaction_id(0x00010203)
                .option(Dhcpv6Option::empty(14u16));
        let bytes = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let dhcpv6 = decoded.layer::<Dhcpv6>().unwrap();
        assert_eq!(dhcpv6.message_type_value(), Dhcpv6MessageType::Request);
        assert_eq!(dhcpv6.transaction_id_value(), 0x010203);
        assert_eq!(dhcpv6.options_ref().len(), 1);
        assert!(decoded.layer::<Raw>().is_none());
    }
}

#[cfg(test)]
mod dhcpv6_relay_header_tests {
    use core::net::Ipv6Addr;

    use super::{Dhcpv6, Dhcpv6RelayHeader};
    use crate::field::FieldState;
    use crate::packet::{Layer, Packet};
    use crate::protocols::dhcp::v6::Dhcpv6MessageType;

    fn link() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 1)
    }

    fn peer() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 2, 0, 0, 0, 0, 2)
    }

    #[test]
    fn dhcpv6_relay_header_relay_forward_builder_sets_packet_data() {
        let relay = Dhcpv6::relay_forward(link(), peer());
        let header = relay.relay().unwrap();

        assert_eq!(relay.message_type_value(), Dhcpv6MessageType::RelayForw);
        assert_eq!(header.hop_count_value(), 0);
        assert_eq!(header.hop_count_state(), FieldState::Defaulted);
        assert_eq!(header.link_address_value(), link());
        assert_eq!(header.link_address_state(), FieldState::User);
        assert_eq!(header.peer_address_value(), peer());
        assert_eq!(header.peer_address_state(), FieldState::User);
        assert_eq!(relay.encoded_len(), 34);
    }

    #[test]
    fn dhcpv6_relay_header_relay_reply_builder_sets_packet_data() {
        let relay = Dhcpv6::relay_reply(link(), peer()).hop_count(2);
        let header = relay.relay().unwrap();

        assert_eq!(relay.message_type_value(), Dhcpv6MessageType::RelayRepl);
        assert_eq!(header.hop_count_value(), 2);
        assert_eq!(header.hop_count_state(), FieldState::User);
    }

    #[test]
    fn dhcpv6_relay_header_peer_address_setter_updates_packet_data() {
        let new_peer = Ipv6Addr::new(0x2001, 0x0db8, 3, 0, 0, 0, 0, 3);
        let relay = Dhcpv6::relay_forward(link(), peer()).peer_address(new_peer);

        assert_eq!(relay.relay().unwrap().peer_address_value(), new_peer);
    }

    #[test]
    fn dhcpv6_relay_header_summary_and_inspection_include_peer_address() {
        let relay = Dhcpv6::relay_forward(link(), peer()).hop_count(1);

        let summary = relay.summary();
        assert!(summary.contains("relay-forw"));
        assert!(summary.contains("hop_count=1"));
        assert!(summary.contains("peer_address=2001:db8:2::2"));
        assert!(relay
            .inspection_fields()
            .iter()
            .any(|(name, value)| *name == "peer_address" && value == "2001:db8:2::2"));
    }

    #[test]
    fn dhcpv6_relay_header_compile_emits_fixed_header() {
        let bytes = Packet::from_layer(Dhcpv6::relay_forward(link(), peer()))
            .compile()
            .unwrap();

        assert_eq!(bytes.as_bytes()[0], 12);
        assert_eq!(bytes.as_bytes()[1], 0);
        assert_eq!(&bytes.as_bytes()[2..18], &link().octets());
        assert_eq!(&bytes.as_bytes()[18..34], &peer().octets());
        assert_eq!(bytes.as_bytes().len(), 34);
    }

    #[test]
    fn dhcpv6_relay_header_standalone_header_builder_tracks_fields() {
        let header = Dhcpv6RelayHeader::new(link(), peer()).hop_count(3);

        assert_eq!(header.hop_count_value(), 3);
        assert_eq!(header.link_address_value(), link());
        assert_eq!(header.peer_address_value(), peer());
    }
}

#[cfg(test)]
mod dhcpv6_relay_codec_tests {
    use core::net::Ipv6Addr;

    use super::{
        append_dhcpv6_packet, is_dhcpv6_relay_port_pair, looks_like_dhcpv6_relay_payload, Dhcpv6,
    };
    use crate::error::CrafterError;
    use crate::packet::{NetworkLayer, Packet, Raw};
    use crate::protocols::dhcp::v6::{Dhcpv6MessageType, Dhcpv6Option};
    use crate::protocols::ip::v6::Ipv6;
    use crate::protocols::transport::Udp;

    const RELAY_MESSAGE_OPTION: u16 = 9;

    fn link(segment: u16) -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, segment, 0, 0, 0, 0, 1)
    }

    fn peer(segment: u16) -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, segment, 0, 0, 0, 0, 2)
    }

    #[test]
    fn dhcpv6_relay_codec_encodes_and_decodes_relay_message_option() {
        let client_bytes =
            Packet::from_layer(Dhcpv6::solicit(0x010203).option(Dhcpv6Option::empty(14u16)))
                .compile()
                .unwrap();
        let relay = Dhcpv6::relay_forward(link(1), peer(1))
            .hop_count(1)
            .option(Dhcpv6Option::raw(
                RELAY_MESSAGE_OPTION,
                client_bytes.as_bytes(),
            ));
        let relay_bytes = Packet::from_layer(relay).compile().unwrap();

        assert_eq!(relay_bytes.as_bytes()[0], 12);
        assert_eq!(relay_bytes.as_bytes()[1], 1);
        assert_eq!(&relay_bytes.as_bytes()[2..18], &link(1).octets());
        assert_eq!(&relay_bytes.as_bytes()[18..34], &peer(1).octets());

        let decoded = append_dhcpv6_packet(Packet::new(), relay_bytes.as_bytes()).unwrap();
        let relay = decoded.layer::<Dhcpv6>().unwrap();
        let relay_header = relay.relay().unwrap();
        assert_eq!(relay.message_type_value(), Dhcpv6MessageType::RelayForw);
        assert_eq!(relay_header.hop_count_value(), 1);
        assert_eq!(relay_header.link_address_value(), link(1));
        assert_eq!(relay_header.peer_address_value(), peer(1));
        assert_eq!(relay.options_ref().len(), 1);

        let nested_option = &relay.options_ref()[0];
        assert_eq!(nested_option.codepoint(), RELAY_MESSAGE_OPTION);
        let nested = Dhcpv6::decode(nested_option.payload()).unwrap();
        assert_eq!(nested.message_type_value(), Dhcpv6MessageType::Solicit);
        assert_eq!(nested.transaction_id_value(), 0x010203);
        assert_eq!(nested.options_ref()[0].codepoint(), 14);
    }

    #[test]
    fn dhcpv6_relay_codec_preserves_multiple_encapsulation_levels() {
        let client_bytes = Packet::from_layer(
            Dhcpv6::new()
                .message_type(Dhcpv6MessageType::Request)
                .transaction_id(0x040506),
        )
        .compile()
        .unwrap();
        let inner_relay_bytes =
            Packet::from_layer(Dhcpv6::relay_forward(link(1), peer(1)).hop_count(2).option(
                Dhcpv6Option::raw(RELAY_MESSAGE_OPTION, client_bytes.as_bytes()),
            ))
            .compile()
            .unwrap();
        let outer_relay_bytes =
            Packet::from_layer(Dhcpv6::relay_forward(link(2), peer(2)).hop_count(3).option(
                Dhcpv6Option::raw(RELAY_MESSAGE_OPTION, inner_relay_bytes.as_bytes()),
            ))
            .compile()
            .unwrap();

        let outer = Dhcpv6::decode(outer_relay_bytes.as_bytes()).unwrap();
        assert_eq!(outer.relay().unwrap().hop_count_value(), 3);
        assert_eq!(outer.relay().unwrap().link_address_value(), link(2));

        let inner = Dhcpv6::decode(outer.options_ref()[0].payload()).unwrap();
        assert_eq!(inner.message_type_value(), Dhcpv6MessageType::RelayForw);
        assert_eq!(inner.relay().unwrap().hop_count_value(), 2);
        assert_eq!(inner.relay().unwrap().link_address_value(), link(1));

        let client = Dhcpv6::decode(inner.options_ref()[0].payload()).unwrap();
        assert_eq!(client.message_type_value(), Dhcpv6MessageType::Request);
        assert_eq!(client.transaction_id_value(), 0x040506);
    }

    #[test]
    fn dhcpv6_relay_codec_hop_count_roundtrips() {
        let relay = Dhcpv6::relay_reply(link(4), peer(4)).hop_count(31);
        let bytes = Packet::from_layer(relay).compile().unwrap();
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();

        assert_eq!(decoded.message_type_value(), Dhcpv6MessageType::RelayRepl);
        assert_eq!(decoded.relay().unwrap().hop_count_value(), 31);
        assert_eq!(
            Packet::from_layer(decoded).compile().unwrap().as_bytes(),
            bytes.as_bytes(),
        );
    }

    #[test]
    fn dhcpv6_relay_codec_reports_truncated_relay_header() {
        let mut bytes = vec![12, 0];
        bytes.resize(33, 0);

        assert_eq!(
            Dhcpv6::decode(&bytes).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.relay_header", 34, 33),
        );
    }

    #[test]
    fn dhcpv6_relay_codec_udp_registry_decodes_server_relay_payload() {
        assert!(is_dhcpv6_relay_port_pair(547, 547));

        let payload = Packet::from_layer(Dhcpv6::relay_reply(link(5), peer(5)))
            .compile()
            .unwrap();
        assert!(looks_like_dhcpv6_relay_payload(payload.as_bytes()));
        assert!(!looks_like_dhcpv6_relay_payload(&payload.as_bytes()[..33]));

        let packet = Ipv6::new()
            / Udp::new().source_port(547).destination_port(547)
            / Dhcpv6::relay_reply(link(5), peer(5)).hop_count(4);
        let bytes = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let dhcpv6 = decoded.layer::<Dhcpv6>().unwrap();
        assert_eq!(dhcpv6.message_type_value(), Dhcpv6MessageType::RelayRepl);
        assert_eq!(dhcpv6.relay().unwrap().hop_count_value(), 4);
        assert_eq!(dhcpv6.relay().unwrap().peer_address_value(), peer(5));
        assert!(decoded.layer::<Raw>().is_none());
    }
}

#[cfg(test)]
mod dhcpv6_udp_binding_tests {
    use core::net::Ipv6Addr;

    use super::{
        is_dhcpv6_port_pair, is_dhcpv6_relay_port_pair, looks_like_dhcpv6_payload, Dhcpv6,
    };
    use crate::packet::{NetworkLayer, Packet, Raw};
    use crate::protocols::dhcp::v6::Dhcpv6MessageType;
    use crate::protocols::ip::v6::Ipv6;
    use crate::protocols::transport::Udp;

    fn link() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 6, 0, 0, 0, 0, 1)
    }

    fn peer() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 6, 0, 0, 0, 0, 2)
    }

    #[test]
    fn dhcpv6_udp_binding_payload_gate_is_port_and_message_type_aware() {
        let mut relay = vec![12, 0];
        relay.resize(34, 0);

        assert!(is_dhcpv6_port_pair(546, 547));
        assert!(is_dhcpv6_port_pair(547, 546));
        assert!(is_dhcpv6_relay_port_pair(547, 547));
        assert!(!is_dhcpv6_port_pair(546, 546));
        assert!(!is_dhcpv6_relay_port_pair(546, 547));

        assert!(looks_like_dhcpv6_payload(546, 547, &[1, 0, 0, 0]));
        assert!(looks_like_dhcpv6_payload(547, 546, &[7, 0, 0, 1]));
        assert!(!looks_like_dhcpv6_payload(546, 547, &[12, 0, 0, 0]));
        assert!(!looks_like_dhcpv6_payload(546, 547, &[1, 0, 0]));

        assert!(looks_like_dhcpv6_payload(547, 547, &relay));
        assert!(!looks_like_dhcpv6_payload(547, 547, &[12, 0, 0, 0]));
        assert!(!looks_like_dhcpv6_payload(547, 547, &[1, 0, 0, 0]));
        assert!(!looks_like_dhcpv6_payload(546, 546, &[1, 0, 0, 0]));
    }

    #[test]
    fn dhcpv6_udp_binding_decodes_client_server_payload() {
        let packet = Ipv6::new() / Udp::dhcpv6_client() / Dhcpv6::solicit(0x010203);
        let bytes = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let dhcpv6 = decoded.layer::<Dhcpv6>().unwrap();
        assert_eq!(dhcpv6.message_type_value(), Dhcpv6MessageType::Solicit);
        assert_eq!(dhcpv6.transaction_id_value(), 0x010203);
        assert!(decoded.layer::<Raw>().is_none());
    }

    #[test]
    fn dhcpv6_udp_binding_decodes_relay_payload() {
        let packet = Ipv6::new() / Udp::dhcpv6_relay() / Dhcpv6::relay_forward(link(), peer());
        let bytes = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let dhcpv6 = decoded.layer::<Dhcpv6>().unwrap();
        assert_eq!(dhcpv6.message_type_value(), Dhcpv6MessageType::RelayForw);
        assert_eq!(dhcpv6.relay().unwrap().link_address_value(), link());
        assert_eq!(dhcpv6.relay().unwrap().peer_address_value(), peer());
        assert!(decoded.layer::<Raw>().is_none());
    }

    #[test]
    fn dhcpv6_udp_binding_leaves_unrelated_payload_raw() {
        let packet = Ipv6::new() / Udp::dhcpv6_client() / Raw::from_bytes([12, 0, 0, 0]);
        let bytes = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        assert!(decoded.layer::<Dhcpv6>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[12, 0, 0, 0],);
    }
}

#[cfg(test)]
mod dhcpv6_basic_options_layer_tests {
    use super::Dhcpv6;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{Dhcpv6MessageType, Dhcpv6OptionCode};

    #[test]
    fn dhcpv6_basic_options_layer_helpers_append_query_and_roundtrip() {
        let message = Dhcpv6::solicit(0x010203)
            .client_id([0x00, 0x03, 0xaa, 0xbb])
            .server_id([0x00, 0x01, 0xcc, 0xdd])
            .oro([23u16, 24u16])
            .preference(99)
            .elapsed_time(123)
            .rapid_commit();

        assert_eq!(
            message.client_id_value(),
            Some(&[0x00, 0x03, 0xaa, 0xbb][..])
        );
        assert_eq!(
            message.server_id_value(),
            Some(&[0x00, 0x01, 0xcc, 0xdd][..])
        );
        assert_eq!(
            message.oro_value().unwrap(),
            Some(vec![
                Dhcpv6OptionCode::from_code(23),
                Dhcpv6OptionCode::from_code(24),
            ]),
        );
        assert_eq!(message.preference_value().unwrap(), Some(99));
        assert_eq!(message.elapsed_time_value().unwrap(), Some(123));
        assert!(message.rapid_commit_present().unwrap());

        let bytes = Packet::from_layer(message).compile().unwrap();
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();

        assert_eq!(decoded.message_type_value(), Dhcpv6MessageType::Solicit);
        assert_eq!(decoded.transaction_id_value(), 0x010203);
        assert_eq!(
            decoded.client_id_value(),
            Some(&[0x00, 0x03, 0xaa, 0xbb][..])
        );
        assert_eq!(
            decoded.oro_value().unwrap(),
            Some(vec![
                Dhcpv6OptionCode::from_code(23),
                Dhcpv6OptionCode::from_code(24),
            ]),
        );
        assert_eq!(decoded.preference_value().unwrap(), Some(99));
        assert_eq!(decoded.elapsed_time_value().unwrap(), Some(123));
        assert!(decoded.rapid_commit_present().unwrap());
    }
}
