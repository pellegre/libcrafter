//! DHCPv6 client/server packet layer.

use core::any::Any;
use core::ops::Div;

use crate::error::{CrafterError, Result};
use crate::field::{Field, FieldState};
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

use super::constants::{DHCPV6_CLIENT_SERVER_HEADER_LEN, DHCPV6_TRANSACTION_ID_MAX};
use super::message::{dhcpv6_message_type_summary, Dhcpv6MessageType};
use super::option::Dhcpv6Option;

/// DHCPv6 client/server packet layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcpv6 {
    message_type: Field<Dhcpv6MessageType>,
    transaction_id: Field<u32>,
    options: Vec<Dhcpv6Option>,
}

impl Dhcpv6 {
    /// Create an empty DHCPv6 client/server message with deterministic defaults.
    pub fn new() -> Self {
        Self {
            message_type: Field::defaulted(Dhcpv6MessageType::Solicit),
            transaction_id: Field::defaulted(0),
            options: Vec::new(),
        }
    }

    /// Create a DHCPv6 Solicit message with the supplied transaction ID.
    pub fn solicit(transaction_id: u32) -> Self {
        Self::new()
            .message_type(Dhcpv6MessageType::Solicit)
            .transaction_id(transaction_id)
    }

    /// Decode a DHCPv6 client/server message.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_dhcpv6_client_server(bytes)
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

    /// Current transaction ID value.
    pub fn transaction_id_value(&self) -> u32 {
        self.transaction_id.value().copied().unwrap_or(0)
    }

    /// State of the transaction ID field.
    pub const fn transaction_id_state(&self) -> FieldState {
        self.transaction_id.state()
    }

    /// Append an option and return the updated layer.
    pub fn option(mut self, option: Dhcpv6Option) -> Self {
        self.options.push(option);
        self
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

    /// Encoded DHCPv6 client/server message length.
    pub fn encoded_dhcpv6_len(&self) -> usize {
        DHCPV6_CLIENT_SERVER_HEADER_LEN
            + self
                .options
                .iter()
                .map(|option| super::constants::DHCPV6_OPTION_HEADER_LEN + option.payload_len())
                .sum::<usize>()
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
        format!(
            "Dhcpv6(type={}, xid=0x{:06x}, options={})",
            dhcpv6_message_type_summary(self.message_type_value()),
            self.transaction_id_value(),
            self.options.len(),
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "message_type",
                dhcpv6_message_type_summary(self.message_type_value()),
            ),
            (
                "transaction_id",
                format!("0x{:06x}", self.transaction_id_value()),
            ),
            ("options", self.options.len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.encoded_dhcpv6_len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let transaction_id = self.transaction_id_value();
        if transaction_id > DHCPV6_TRANSACTION_ID_MAX {
            return Err(CrafterError::invalid_field_value(
                "dhcpv6.transaction_id",
                "value exceeds 24 bits",
            ));
        }

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
        options: Dhcpv6Option::decode_all(&bytes[DHCPV6_CLIENT_SERVER_HEADER_LEN..])?,
    })
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
