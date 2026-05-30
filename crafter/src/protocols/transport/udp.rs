//! UDP protocol implementation.

use crate::endian::read_u16_be;
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Layer, LayerContext, Packet, Raw};
use crate::protocols::dhcp::{DHCP_CLIENT_PORT, DHCP_SERVER_PORT};
use crate::protocols::ip::IPPROTO_UDP;
use crate::registry::ProtocolRegistry;

use super::common::{
    impl_layer_div, impl_layer_object, payload_bytes_after, transport_checksum_context,
    value_or_copy,
};

/// UDP header length in bytes.
pub const UDP_HEADER_LEN: usize = 8;

/// UDP End of Options List option kind.
pub const UDP_OPTION_EOL: u8 = 0;
/// UDP No Operation option kind.
pub const UDP_OPTION_NOP: u8 = 1;
/// UDP Additional Payload Checksum option kind.
pub const UDP_OPTION_APC: u8 = 2;
/// UDP Fragmentation option kind.
pub const UDP_OPTION_FRAG: u8 = 3;
/// UDP Maximum Datagram Size option kind.
pub const UDP_OPTION_MDS: u8 = 4;
/// UDP Maximum Reassembled Datagram Size option kind.
pub const UDP_OPTION_MRDS: u8 = 5;
/// UDP Echo Request option kind.
pub const UDP_OPTION_REQ: u8 = 6;
/// UDP Echo Response option kind.
pub const UDP_OPTION_RES: u8 = 7;
/// UDP Timestamp option kind.
pub const UDP_OPTION_TIME: u8 = 8;
/// UDP option kind reserved for Authentication.
pub const UDP_OPTION_AUTH: u8 = 9;
/// First currently unassigned SAFE UDP option kind.
pub const UDP_OPTION_UNASSIGNED_SAFE_START: u8 = 10;
/// Last currently unassigned SAFE UDP option kind.
pub const UDP_OPTION_UNASSIGNED_SAFE_END: u8 = 126;
/// UDP RFC 3692-style SAFE experiment option kind.
pub const UDP_OPTION_EXP: u8 = 127;
/// First reserved SAFE UDP option kind.
pub const UDP_OPTION_RESERVED_SAFE_START: u8 = 128;
/// Last reserved SAFE UDP option kind.
pub const UDP_OPTION_RESERVED_SAFE_END: u8 = 191;
/// UDP option kind reserved for UNSAFE Compression.
pub const UDP_OPTION_UCMP: u8 = 192;
/// UDP option kind reserved for UNSAFE Encryption.
pub const UDP_OPTION_UENC: u8 = 193;
/// First currently unassigned UNSAFE UDP option kind.
pub const UDP_OPTION_UNASSIGNED_UNSAFE_START: u8 = 194;
/// Last currently unassigned UNSAFE UDP option kind.
pub const UDP_OPTION_UNASSIGNED_UNSAFE_END: u8 = 253;
/// UDP RFC 3692-style UNSAFE experiment option kind.
pub const UDP_OPTION_UEXP: u8 = 254;
/// Reserved UNSAFE UDP option kind.
pub const UDP_OPTION_RESERVED_UNSAFE: u8 = 255;

/// Inspection status for UDP checksum handling.
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

/// Inspection status for UDP surplus option processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpOptionStatus {
    /// No UDP surplus area is present.
    NoSurplus,
    /// UDP surplus option parsing has not been attempted.
    NotParsed,
    /// UDP surplus options are well-formed.
    Valid,
    /// UDP surplus options were intentionally ignored.
    Ignored,
    /// UDP surplus option bytes are malformed.
    Malformed,
    /// UDP surplus options include unsupported behavior.
    Unsupported,
    /// UDP Option Checksum validation failed.
    OptionChecksumInvalid,
    /// UDP Additional Payload Checksum validation failed.
    AdditionalPayloadChecksumInvalid,
}

/// User Datagram Protocol header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp {
    source_port: Field<u16>,
    destination_port: Field<u16>,
    length: Field<u16>,
    checksum: Field<u16>,
}

impl Udp {
    /// Create a UDP header with deterministic packet-builder defaults.
    pub fn new() -> Self {
        Self {
            source_port: Field::defaulted(53),
            destination_port: Field::defaulted(53),
            length: Field::unset(),
            checksum: Field::unset(),
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
            "Udp(sport={}, dport={}, len={})",
            self.source_port_value(),
            self.destination_port_value(),
            self.length_value()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "auto".to_string())
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
        ]
    }

    fn encoded_len(&self) -> usize {
        UDP_HEADER_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let payload = payload_bytes_after(*ctx)?;
        self.validate(payload.len())?;

        let mut header = Vec::with_capacity(UDP_HEADER_LEN);
        header.extend_from_slice(&self.source_port_value().to_be_bytes());
        header.extend_from_slice(&self.destination_port_value().to_be_bytes());
        header.extend_from_slice(&self.effective_length(payload.len())?.to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes());

        let checksum = self.effective_checksum(*ctx, &header, &payload);
        header[6..8].copy_from_slice(&checksum.to_be_bytes());
        out.extend_from_slice(&header);
        Ok(())
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
    let (udp, payload, rest) = decode_udp_parts(bytes)?;
    let source_port = udp.source_port_value();
    let destination_port = udp.destination_port_value();
    packet = packet.push(udp);
    if !payload.is_empty() {
        packet = registry.decode_udp_application(packet, source_port, destination_port, payload)?;
    }
    if !rest.is_empty() {
        packet = packet.push(Raw::from_bytes(rest));
    }
    Ok(packet)
}

fn decode_udp_parts(bytes: &[u8]) -> Result<(Udp, &[u8], &[u8])> {
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
    };

    Ok((udp, &bytes[UDP_HEADER_LEN..length], &bytes[length..]))
}

#[cfg(test)]
mod tests {
    use super::{
        Udp, UdpChecksumStatus, UdpOptionStatus, UDP_HEADER_LEN, UDP_OPTION_APC, UDP_OPTION_FRAG,
        UDP_OPTION_MDS, UDP_OPTION_MRDS, UDP_OPTION_NOP, UDP_OPTION_REQ, UDP_OPTION_RES,
    };
    use crate::checksum::ipv4_pseudo_header_checksum;
    use crate::{IpProtocol, Ipv4, LinkType, Packet, Raw, IPPROTO_UDP};
    use core::net::Ipv4Addr;

    const VLAN_FIXTURE: &[u8] = fixture_bytes!("bytes/ethernet-vlan-ipv4-udp-raw.bin");

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn udp_public_constants_and_statuses_are_stable() {
        assert_eq!(UDP_HEADER_LEN, 8);
        assert_eq!(UDP_OPTION_NOP, 1);
        assert_eq!(UDP_OPTION_APC, 2);
        assert_eq!(UDP_OPTION_FRAG, 3);
        assert_eq!(UDP_OPTION_MDS, 4);
        assert_eq!(UDP_OPTION_MRDS, 5);
        assert_eq!(UDP_OPTION_REQ, 6);
        assert_eq!(UDP_OPTION_RES, 7);

        let checksum_status = UdpChecksumStatus::NotChecked;
        let option_status = UdpOptionStatus::NotParsed;
        assert_eq!(checksum_status, UdpChecksumStatus::NotChecked);
        assert_eq!(option_status, UdpOptionStatus::NotParsed);
    }

    #[test]
    fn udp_autofills_length_and_ipv4_checksum_for_odd_payload() {
        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2222)
            / Udp::new().sport(0x1234).dport(53)
            / Raw::from_bytes([0xde, 0xad, 0xbe]))
        .compile()
        .unwrap();

        assert_eq!(&bytes.as_bytes()[2..4], &(31u16).to_be_bytes());
        assert_eq!(&bytes.as_bytes()[20..22], &0x1234u16.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[22..24], &53u16.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[24..26], &11u16.to_be_bytes());
        let mut udp = bytes.as_bytes()[20..].to_vec();
        udp[6] = 0;
        udp[7] = 0;
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[26], bytes.as_bytes()[27]]),
            ipv4_pseudo_header_checksum(src(), dst(), IPPROTO_UDP, &udp)
        );
    }

    #[test]
    fn udp_decode_from_ipv4_exposes_ports_and_payload() {
        let decoded = Packet::decode_from_link(LinkType::Ethernet, VLAN_FIXTURE).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(udp.source_port_value(), 53002);
        assert_eq!(udp.destination_port_value(), 9999);
        assert_eq!(udp.length_value(), Some(16));
        assert_eq!(udp.checksum_value(), Some(0xb3a1));
        assert_eq!(raw.as_bytes(), b"vlan-udp");
        assert_eq!(decoded.compile().unwrap().as_bytes(), VLAN_FIXTURE);
    }

    #[test]
    fn explicit_udp_checksum_is_preserved() {
        let bytes = (Ipv4::new().src(src()).dst(dst()) / Udp::new().checksum(0) / Raw::from("abc"))
            .compile()
            .unwrap();

        assert_eq!(&bytes.as_bytes()[26..28], &[0, 0]);
    }

    #[test]
    fn udp_decode_rejects_short_and_malformed_inputs() {
        let short = (Ipv4::new().proto(IpProtocol::Udp) / Raw::from_bytes([1, 2, 3, 4]))
            .compile()
            .unwrap();
        assert!(Packet::decode_from_l3(crate::NetworkLayer::Ipv4, short.as_bytes()).is_err());

        let bad_length = (Ipv4::new().proto(IpProtocol::Udp)
            / Raw::from_bytes([0x12, 0x34, 0x00, 0x35, 0x00, 0x07, 0, 0]))
        .compile()
        .unwrap();
        assert!(Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bad_length.as_bytes()).is_err());
    }
}
