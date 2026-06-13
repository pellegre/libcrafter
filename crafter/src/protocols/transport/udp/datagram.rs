use crate::endian::read_u16_be;
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Layer, LayerContext, Packet, Raw, TransportChecksumContext};
use crate::protocols::dhcp::{Dhcp, DHCP_CLIENT_PORT, DHCP_SERVER_PORT};
use crate::protocols::dns::Dns;
use crate::protocols::ipv4::IPPROTO_UDP;
use crate::registry::ProtocolRegistry;

use super::super::common::{
    impl_layer_div, impl_layer_object, transport_checksum_context, value_or_copy,
};
use super::constants::UDP_HEADER_LEN;
use super::surplus::{udp_decoded_surplus_offset_in_ip_datagram, UdpOptions};

/// Inspection status for UDP checksum handling.
///
/// IPv6 zero-checksum UDP is not treated as normal UDP by default: RFC 8200
/// makes the UDP checksum mandatory for IPv6, while RFC 6935 and RFC 6936 only
/// define narrow, explicitly enabled tunnel exceptions. `crafter` preserves
/// decoded bytes and reports [`Self::Ipv6ZeroChecksum`] instead of silently
/// accepting or normalizing that condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpChecksumStatus {
    /// Checksum validation was not attempted.
    NotChecked,
    /// IPv4 UDP checksum field is zero, meaning no checksum was transmitted.
    Ipv4NoChecksum,
    /// Nonzero UDP checksum validates against the pseudo-header and UDP data.
    Valid,
    /// Nonzero UDP checksum failed validation.
    Invalid,
    /// IPv6 UDP checksum field is zero and requires an explicit exception model.
    Ipv6ZeroChecksum,
}

impl UdpChecksumStatus {
    /// Whether this status requires an explicit RFC 6935/RFC 6936 IPv6 zero
    /// checksum exception before being treated as valid tunnel traffic.
    pub const fn requires_ipv6_zero_checksum_exception(self) -> bool {
        matches!(self, Self::Ipv6ZeroChecksum)
    }
}

/// User Datagram Protocol header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp {
    source_port: Field<u16>,
    destination_port: Field<u16>,
    length: Field<u16>,
    checksum: Field<u16>,
    checksum_status: UdpChecksumStatus,
}

impl Udp {
    /// Create a UDP header with deterministic packet-builder defaults.
    pub fn new() -> Self {
        Self {
            source_port: Field::defaulted(53),
            destination_port: Field::defaulted(53),
            length: Field::unset(),
            checksum: Field::unset(),
            checksum_status: UdpChecksumStatus::NotChecked,
        }
    }

    /// Create a DHCP client-to-server UDP header.
    pub fn dhcp_client() -> Self {
        Self::new()
            .source_port(DHCP_CLIENT_PORT)
            .destination_port(DHCP_SERVER_PORT)
    }

    /// Create a DHCP server-to-client UDP header.
    pub fn dhcp_server() -> Self {
        Self::new()
            .source_port(DHCP_SERVER_PORT)
            .destination_port(DHCP_CLIENT_PORT)
    }

    /// Set the source port.
    pub fn source_port(mut self, source_port: u16) -> Self {
        self.source_port.set_user(source_port);
        self
    }

    /// Compatibility alias for source port.
    pub fn sport(self, source_port: u16) -> Self {
        self.source_port(source_port)
    }

    /// Set the destination port.
    pub fn destination_port(mut self, destination_port: u16) -> Self {
        self.destination_port.set_user(destination_port);
        self
    }

    /// Compatibility alias for destination port.
    pub fn dport(self, destination_port: u16) -> Self {
        self.destination_port(destination_port)
    }

    /// Set the UDP length field explicitly.
    pub fn length(mut self, length: u16) -> Self {
        self.length.set_user(length);
        self
    }

    /// Compatibility alias for UDP length.
    pub fn len(self, length: u16) -> Self {
        self.length(length)
    }

    /// Set the UDP checksum explicitly.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum.set_user(checksum);
        self
    }

    /// Compatibility alias for checksum.
    pub fn chksum(self, checksum: u16) -> Self {
        self.checksum(checksum)
    }

    /// Source port value.
    pub fn source_port_value(&self) -> u16 {
        value_or_copy(&self.source_port, 53)
    }

    /// Destination port value.
    pub fn destination_port_value(&self) -> u16 {
        value_or_copy(&self.destination_port, 53)
    }

    /// Stored UDP length value, when explicit or decoded.
    pub fn length_value(&self) -> Option<u16> {
        self.length.value().copied()
    }

    /// Stored checksum value, when explicit or decoded.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    /// Inspection status from decoded UDP checksum validation.
    ///
    /// A zero IPv6 UDP checksum is reported as
    /// [`UdpChecksumStatus::Ipv6ZeroChecksum`]. RFC 8200 makes that non-valid
    /// for ordinary IPv6 UDP, and RFC 6935/RFC 6936 only allow explicitly
    /// enabled tunnel exceptions.
    pub fn checksum_status(&self) -> UdpChecksumStatus {
        self.checksum_status
    }

    fn effective_length(&self, payload_len: usize) -> Result<u16> {
        if let Some(length) = self.length.value().copied() {
            return Ok(length);
        }

        u16::try_from(UDP_HEADER_LEN + payload_len).map_err(|_| {
            CrafterError::invalid_field_value("udp.length", "UDP datagram exceeds 65535 bytes")
        })
    }

    fn effective_checksum(&self, ctx: LayerContext<'_>, header: &[u8], payload: &[u8]) -> u16 {
        if let Some(checksum) = self.checksum.value().copied() {
            return checksum;
        }

        let mut transport = Vec::with_capacity(header.len() + payload.len());
        transport.extend_from_slice(header);
        transport.extend_from_slice(payload);

        match transport_checksum_context(ctx, IPPROTO_UDP) {
            Some(pseudo_header) => {
                let checksum = pseudo_header.checksum(&transport);
                if checksum == 0 {
                    0xffff
                } else {
                    checksum
                }
            }
            None => 0,
        }
    }

    fn validate(&self, payload_len: usize) -> Result<()> {
        let length = self.effective_length(payload_len)?;
        if length < UDP_HEADER_LEN as u16 {
            return Err(CrafterError::invalid_field_value(
                "udp.length",
                "UDP length must be at least 8 bytes",
            ));
        }
        Ok(())
    }
}

impl Default for Udp {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Udp {
    fn name(&self) -> &'static str {
        "Udp"
    }

    fn summary(&self) -> String {
        format!(
            "Udp(sport={}, dport={}, len={}, checksum_status={:?})",
            self.source_port_value(),
            self.destination_port_value(),
            self.length_value()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "auto".to_string()),
            self.checksum_status()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("sport", self.source_port_value().to_string()),
            ("dport", self.destination_port_value().to_string()),
            (
                "length",
                self.length_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            (
                "checksum",
                self.checksum_value()
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("checksum_status", format!("{:?}", self.checksum_status())),
        ]
    }

    fn encoded_len(&self) -> usize {
        UDP_HEADER_LEN
    }

    fn encoded_len_with_context(&self, ctx: &LayerContext<'_>) -> usize {
        let following = udp_following_lens_after(*ctx);
        UDP_HEADER_LEN + following.user_payload + following.surplus
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let following = udp_following_bytes_after(*ctx)?;
        self.validate(following.user_payload.len())?;

        let mut header = Vec::with_capacity(UDP_HEADER_LEN);
        header.extend_from_slice(&self.source_port_value().to_be_bytes());
        header.extend_from_slice(&self.destination_port_value().to_be_bytes());
        header.extend_from_slice(
            &self
                .effective_length(following.user_payload.len())?
                .to_be_bytes(),
        );
        header.extend_from_slice(&0u16.to_be_bytes());

        let checksum = self.effective_checksum(*ctx, &header, &following.user_payload);
        header[6..8].copy_from_slice(&checksum.to_be_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(&following.user_payload);
        out.extend_from_slice(&following.surplus);
        Ok(())
    }

    fn consumes_following(&self) -> bool {
        true
    }

    impl_layer_object!(Udp);
}

impl_layer_div!(Udp);

/// Append a decoded UDP datagram using an explicit registry.
pub(crate) fn append_udp_packet_with_registry(
    registry: &ProtocolRegistry,
    mut packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    let decoded = decode_udp_parts(bytes)?;
    let DecodedUdpDatagram {
        mut udp,
        user_payload,
        surplus,
    } = decoded;
    let source_port = udp.source_port_value();
    let destination_port = udp.destination_port_value();
    let udp_length = udp.length_value().unwrap_or(UDP_HEADER_LEN as u16) as usize;
    let udp_checksum = udp.checksum_value().unwrap_or(0);
    udp.checksum_status = decoded_udp_checksum_status(&packet, bytes, udp_length, udp_checksum);
    let surplus_offset = udp_decoded_surplus_offset_in_ip_datagram(&packet, udp_length);
    packet = packet.push(udp);
    if !user_payload.is_empty() {
        packet =
            registry.decode_udp_application(packet, source_port, destination_port, user_payload)?;
    }
    if !surplus.is_empty() {
        packet = packet.push(UdpOptions::from_decoded_surplus(
            surplus,
            user_payload,
            surplus_offset,
            udp_checksum,
        ));
    }
    Ok(packet)
}

pub(super) struct DecodedUdpDatagram<'a> {
    pub(super) udp: Udp,
    pub(super) user_payload: &'a [u8],
    pub(super) surplus: &'a [u8],
}

pub(super) fn decode_udp_parts(bytes: &[u8]) -> Result<DecodedUdpDatagram<'_>> {
    if bytes.len() < UDP_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "udp header",
            UDP_HEADER_LEN,
            bytes.len(),
        ));
    }

    let length = read_u16_be(&bytes[4..6])? as usize;
    if length < UDP_HEADER_LEN {
        return Err(CrafterError::invalid_field_value(
            "udp.length",
            "UDP length must be at least 8 bytes",
        ));
    }
    if bytes.len() < length {
        return Err(CrafterError::buffer_too_short(
            "udp datagram",
            length,
            bytes.len(),
        ));
    }

    let udp = Udp {
        source_port: Field::user(read_u16_be(&bytes[0..2])?),
        destination_port: Field::user(read_u16_be(&bytes[2..4])?),
        length: Field::user(length as u16),
        checksum: Field::user(read_u16_be(&bytes[6..8])?),
        checksum_status: UdpChecksumStatus::NotChecked,
    };

    Ok(DecodedUdpDatagram {
        udp,
        user_payload: &bytes[UDP_HEADER_LEN..length],
        surplus: &bytes[length..],
    })
}

pub(super) fn decoded_udp_checksum_status(
    packet_before_udp: &Packet,
    bytes: &[u8],
    udp_length: usize,
    checksum: u16,
) -> UdpChecksumStatus {
    let ctx = LayerContext::new(packet_before_udp, packet_before_udp.len());
    let Some(pseudo_header) = transport_checksum_context(ctx, IPPROTO_UDP) else {
        return UdpChecksumStatus::NotChecked;
    };

    match pseudo_header {
        TransportChecksumContext::Ipv4 { .. } if checksum == 0 => UdpChecksumStatus::Ipv4NoChecksum,
        TransportChecksumContext::Ipv6 { .. } if checksum == 0 => {
            UdpChecksumStatus::Ipv6ZeroChecksum
        }
        _ => {
            if pseudo_header.checksum(&bytes[..udp_length]) == 0 {
                UdpChecksumStatus::Valid
            } else {
                UdpChecksumStatus::Invalid
            }
        }
    }
}

#[derive(Debug, Default)]
struct UdpFollowingLens {
    user_payload: usize,
    surplus: usize,
}

#[derive(Debug, Default)]
struct UdpFollowingBytes {
    user_payload: Vec<u8>,
    surplus: Vec<u8>,
}

fn udp_following_lens_after(ctx: LayerContext<'_>) -> UdpFollowingLens {
    let mut lens = UdpFollowingLens::default();
    let mut seen_application_layer = false;
    let mut in_surplus = false;

    for (index, layer) in ctx.packet().iter().enumerate().skip(ctx.index() + 1) {
        let layer_ctx = LayerContext::new(ctx.packet(), index);
        let layer_len = layer.encoded_len_with_context(&layer_ctx);
        let current_is_surplus =
            in_surplus || is_current_udp_surplus_layer(layer, seen_application_layer);

        if current_is_surplus {
            lens.surplus += layer_len;
            in_surplus = true;
        } else {
            lens.user_payload += layer_len;
        }

        if layer.consumes_following() {
            break;
        }

        if !current_is_surplus && is_udp_application_layer(layer) {
            seen_application_layer = true;
        }
    }

    lens
}

fn udp_following_bytes_after(ctx: LayerContext<'_>) -> Result<UdpFollowingBytes> {
    let lens = udp_following_lens_after(ctx);
    let mut following = UdpFollowingBytes {
        user_payload: Vec::with_capacity(lens.user_payload),
        surplus: Vec::with_capacity(lens.surplus),
    };
    let mut seen_application_layer = false;
    let mut in_surplus = false;

    for (index, layer) in ctx.packet().iter().enumerate().skip(ctx.index() + 1) {
        let layer_ctx = LayerContext::new(ctx.packet(), index);
        let current_is_surplus =
            in_surplus || is_current_udp_surplus_layer(layer, seen_application_layer);

        if current_is_surplus {
            layer.compile(&layer_ctx, &mut following.surplus)?;
            in_surplus = true;
        } else {
            layer.compile(&layer_ctx, &mut following.user_payload)?;
        }

        // An encapsulating layer (e.g. UDP-encapsulated ESP, RFC 3948) already
        // embeds every following layer in its own compiled body. The packet
        // compiler stops after such a layer, so the UDP payload length must too —
        // otherwise the following layers are double-counted and the on-wire UDP
        // length over-reads (mirrors the IPv4/IPv6 `payload_len_after` fix).
        if layer.consumes_following() {
            break;
        }

        if !current_is_surplus && is_udp_application_layer(layer) {
            seen_application_layer = true;
        }
    }

    Ok(following)
}

pub(super) fn is_udp_application_layer(layer: &dyn Layer) -> bool {
    layer.as_any().is::<Dns>() || layer.as_any().is::<Dhcp>()
}

pub(super) fn is_current_udp_surplus_layer(
    layer: &dyn Layer,
    seen_application_layer: bool,
) -> bool {
    layer.as_any().is::<UdpOptions>() || (seen_application_layer && layer.as_any().is::<Raw>())
}
