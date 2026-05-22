//! IPv4 protocol implementation.

use core::any::Any;
use core::net::Ipv4Addr;
use core::ops::Div;
use core::str::FromStr;

use crate::checksum::ipv4_header_checksum;
use crate::endian::read_u16_be;
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet, Raw, TransportChecksumContext};
use crate::protocols::transport::{append_tcp_packet, append_udp_packet, Tcp, Udp};

/// IPv4 protocol number for ICMP.
pub const IPPROTO_ICMP: u8 = 1;
/// IPv4 protocol number for TCP.
pub const IPPROTO_TCP: u8 = 6;
/// IPv4 protocol number for UDP.
pub const IPPROTO_UDP: u8 = 17;
/// IPv4 protocol number for IPv6 encapsulation.
pub const IPPROTO_IPV6: u8 = 41;
/// IPv4 protocol number for ICMPv6.
pub const IPPROTO_ICMPV6: u8 = 58;

/// IPv4 "reserved" flag bit.
pub const IPV4_FLAG_RESERVED: u8 = 0b100;
/// IPv4 "don't fragment" flag bit.
pub const IPV4_FLAG_DONT_FRAGMENT: u8 = 0b010;
/// IPv4 "more fragments" flag bit.
pub const IPV4_FLAG_MORE_FRAGMENTS: u8 = 0b001;

const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_MAX_HEADER_LEN: usize = 60;
const IPV4_MAX_IHL: u8 = 15;
const IPV4_MAX_FLAGS: u8 = 0b111;
const IPV4_MAX_FRAGMENT_OFFSET: u16 = 0x1fff;

macro_rules! impl_layer_object {
    ($type:ty) => {
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
    };
}

macro_rules! impl_layer_div {
    ($type:ty) => {
        impl<R> Div<R> for $type
        where
            R: IntoPacket,
        {
            type Output = Packet;

            fn div(self, rhs: R) -> Self::Output {
                Packet::from_layer(self).concat(rhs)
            }
        }
    };
}

/// Common IPv4 protocol numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IpProtocol {
    /// IPv6 hop-by-hop option.
    HopByHop = 0,
    /// Internet Control Message Protocol.
    Icmp = IPPROTO_ICMP,
    /// Transmission Control Protocol.
    Tcp = IPPROTO_TCP,
    /// User Datagram Protocol.
    Udp = IPPROTO_UDP,
    /// IPv6 encapsulation.
    Ipv6 = IPPROTO_IPV6,
    /// ICMPv6.
    Icmpv6 = IPPROTO_ICMPV6,
}

impl From<IpProtocol> for u8 {
    fn from(value: IpProtocol) -> Self {
        value as u8
    }
}

/// IPv4 packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4 {
    version: Field<u8>,
    ihl: Field<u8>,
    tos: Field<u8>,
    total_length: Field<u16>,
    identification: Field<u16>,
    flags: Field<u8>,
    fragment_offset: Field<u16>,
    ttl: Field<u8>,
    protocol: Field<u8>,
    checksum: Field<u16>,
    source: Field<Ipv4Addr>,
    destination: Field<Ipv4Addr>,
    options: Vec<u8>,
}

impl Ipv4 {
    /// Create an IPv4 header with deterministic, Scapy-like defaults.
    pub fn new() -> Self {
        Self {
            version: Field::defaulted(4),
            ihl: Field::unset(),
            tos: Field::defaulted(0),
            total_length: Field::unset(),
            identification: Field::defaulted(1),
            flags: Field::defaulted(0),
            fragment_offset: Field::defaulted(0),
            ttl: Field::defaulted(64),
            protocol: Field::defaulted(0),
            checksum: Field::unset(),
            source: Field::defaulted(Ipv4Addr::LOCALHOST),
            destination: Field::defaulted(Ipv4Addr::LOCALHOST),
            options: Vec::new(),
        }
    }

    /// Create an IPv4 header with explicit source and destination addresses.
    pub fn with_addresses(source: Ipv4Addr, destination: Ipv4Addr) -> Self {
        Self::new().src(source).dst(destination)
    }

    /// Set the IP version field.
    pub fn version(mut self, version: u8) -> Self {
        self.version.set_user(version);
        self
    }

    /// Set the internet header length in 32-bit words.
    pub fn ihl(mut self, ihl: u8) -> Self {
        self.ihl.set_user(ihl);
        self
    }

    /// Set the type-of-service / DSCP+ECN byte.
    pub fn tos(mut self, tos: u8) -> Self {
        self.tos.set_user(tos);
        self
    }

    /// Set the total length field.
    pub fn total_length(mut self, total_length: u16) -> Self {
        self.total_length.set_user(total_length);
        self
    }

    /// Scapy/libcrafter-style alias for total length.
    pub fn len(self, total_length: u16) -> Self {
        self.total_length(total_length)
    }

    /// Set the identification field.
    pub fn identification(mut self, identification: u16) -> Self {
        self.identification.set_user(identification);
        self
    }

    /// Scapy/libcrafter-style alias for identification.
    pub fn id(self, identification: u16) -> Self {
        self.identification(identification)
    }

    /// Set the raw three IPv4 flag bits.
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags.set_user(flags);
        self
    }

    /// Set or clear the "don't fragment" flag.
    pub fn dont_fragment(mut self, enabled: bool) -> Self {
        let mut flags = self.flags_value();
        if enabled {
            flags |= IPV4_FLAG_DONT_FRAGMENT;
        } else {
            flags &= !IPV4_FLAG_DONT_FRAGMENT;
        }
        self.flags.set_user(flags);
        self
    }

    /// Set or clear the "more fragments" flag.
    pub fn more_fragments(mut self, enabled: bool) -> Self {
        let mut flags = self.flags_value();
        if enabled {
            flags |= IPV4_FLAG_MORE_FRAGMENTS;
        } else {
            flags &= !IPV4_FLAG_MORE_FRAGMENTS;
        }
        self.flags.set_user(flags);
        self
    }

    /// Set the fragment offset in 8-byte units.
    pub fn fragment_offset(mut self, fragment_offset: u16) -> Self {
        self.fragment_offset.set_user(fragment_offset);
        self
    }

    /// Scapy-style alias for fragment offset.
    pub fn frag(self, fragment_offset: u16) -> Self {
        self.fragment_offset(fragment_offset)
    }

    /// Set the time-to-live value.
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl.set_user(ttl);
        self
    }

    /// Set the raw protocol number.
    pub fn protocol(mut self, protocol: u8) -> Self {
        self.protocol.set_user(protocol);
        self
    }

    /// Scapy/libcrafter-style alias for a known protocol number.
    pub fn proto(self, protocol: IpProtocol) -> Self {
        self.protocol(protocol.into())
    }

    /// Set the IPv4 header checksum explicitly.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum.set_user(checksum);
        self
    }

    /// Scapy-style alias for checksum.
    pub fn chksum(self, checksum: u16) -> Self {
        self.checksum(checksum)
    }

    /// Set the source IPv4 address.
    pub fn src(mut self, source: Ipv4Addr) -> Self {
        self.source.set_user(source);
        self
    }

    /// Set the source IPv4 address from dotted-quad text.
    pub fn src_str(self, source: &str) -> Result<Self> {
        Ok(self.src(parse_ipv4(source)?))
    }

    /// Set the destination IPv4 address.
    pub fn dst(mut self, destination: Ipv4Addr) -> Self {
        self.destination.set_user(destination);
        self
    }

    /// Set the destination IPv4 address from dotted-quad text.
    pub fn dst_str(self, destination: &str) -> Result<Self> {
        Ok(self.dst(parse_ipv4(destination)?))
    }

    /// Append raw IPv4 option bytes.
    pub fn option(mut self, option: impl AsRef<[u8]>) -> Self {
        self.options.extend_from_slice(option.as_ref());
        self
    }

    /// Replace all IPv4 option bytes.
    pub fn options(mut self, options: impl Into<Vec<u8>>) -> Self {
        self.options = options.into();
        self
    }

    /// Remove all IPv4 option bytes.
    pub fn clear_options(mut self) -> Self {
        self.options.clear();
        self
    }

    /// IP version value.
    pub fn version_value(&self) -> u8 {
        value_or_copy(&self.version, 4)
    }

    /// Header length in 32-bit words.
    pub fn ihl_value(&self) -> u8 {
        self.effective_ihl()
    }

    /// Header length in bytes.
    pub fn header_len(&self) -> usize {
        self.effective_header_len()
    }

    /// Type-of-service / DSCP+ECN value.
    pub fn tos_value(&self) -> u8 {
        value_or_copy(&self.tos, 0)
    }

    /// Total length field value when explicitly stored or decoded.
    pub fn total_length_value(&self) -> Option<u16> {
        self.total_length.value().copied()
    }

    /// Identification field.
    pub fn identification_value(&self) -> u16 {
        value_or_copy(&self.identification, 1)
    }

    /// Raw three-bit flags value.
    pub fn flags_value(&self) -> u8 {
        value_or_copy(&self.flags, 0)
    }

    /// Return true when the "don't fragment" flag is set.
    pub fn is_dont_fragment(&self) -> bool {
        self.flags_value() & IPV4_FLAG_DONT_FRAGMENT != 0
    }

    /// Return true when the "more fragments" flag is set.
    pub fn has_more_fragments(&self) -> bool {
        self.flags_value() & IPV4_FLAG_MORE_FRAGMENTS != 0
    }

    /// Fragment offset in 8-byte units.
    pub fn fragment_offset_value(&self) -> u16 {
        value_or_copy(&self.fragment_offset, 0)
    }

    /// Time-to-live value.
    pub fn ttl_value(&self) -> u8 {
        value_or_copy(&self.ttl, 64)
    }

    /// Protocol number.
    pub fn protocol_value(&self) -> u8 {
        value_or_copy(&self.protocol, 0)
    }

    /// Header checksum when explicitly stored or decoded.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    /// Source address.
    pub fn source(&self) -> Ipv4Addr {
        value_or_copy(&self.source, Ipv4Addr::LOCALHOST)
    }

    /// Destination address.
    pub fn destination(&self) -> Ipv4Addr {
        value_or_copy(&self.destination, Ipv4Addr::LOCALHOST)
    }

    /// Raw IPv4 option bytes, including decode-time padding bytes.
    pub fn option_bytes(&self) -> &[u8] {
        &self.options
    }

    fn effective_ihl(&self) -> u8 {
        self.ihl
            .value()
            .copied()
            .unwrap_or((self.effective_header_len() / 4) as u8)
    }

    fn effective_header_len(&self) -> usize {
        if let Some(ihl) = self.ihl.value().copied() {
            (ihl as usize) * 4
        } else {
            IPV4_MIN_HEADER_LEN + padded_options_len(self.options.len())
        }
    }

    fn effective_total_length(&self, payload_len: usize) -> Result<u16> {
        if let Some(total_length) = self.total_length.value().copied() {
            return Ok(total_length);
        }

        let total = self.effective_header_len() + payload_len;
        u16::try_from(total).map_err(|_| {
            CrafterError::invalid_field_value("ipv4.total_length", "packet length exceeds 65535")
        })
    }

    fn effective_protocol(&self, next: Option<&dyn Layer>) -> u8 {
        if self.protocol.is_user_set() {
            return self.protocol_value();
        }

        next.and_then(layer_ipv4_protocol)
            .or_else(|| self.protocol.value().copied())
            .unwrap_or(0)
    }

    fn effective_checksum(&self, header: &[u8]) -> u16 {
        self.checksum
            .value()
            .copied()
            .unwrap_or_else(|| ipv4_header_checksum(header))
    }

    fn validate(&self, payload_len: usize) -> Result<()> {
        if self.version_value() != 4 {
            return Err(CrafterError::invalid_field_value(
                "ipv4.version",
                "IPv4 layer version must be 4",
            ));
        }
        if self.effective_ihl() < 5 {
            return Err(CrafterError::invalid_field_value(
                "ipv4.ihl",
                "internet header length must be at least 5 words",
            ));
        }
        if self.effective_ihl() > IPV4_MAX_IHL {
            return Err(CrafterError::invalid_field_value(
                "ipv4.ihl",
                "internet header length must be <= 15 words",
            ));
        }
        if self.effective_header_len() < IPV4_MIN_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "ipv4.ihl",
                "internet header length must be at least 20 bytes",
            ));
        }
        if self.effective_header_len() > IPV4_MAX_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "ipv4.ihl",
                "internet header length must be <= 60 bytes",
            ));
        }
        if self.options.len() > IPV4_MAX_HEADER_LEN - IPV4_MIN_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "ipv4.options",
                "IPv4 options must fit within the 60-byte maximum header",
            ));
        }
        if self.effective_header_len() < IPV4_MIN_HEADER_LEN + self.options.len() {
            return Err(CrafterError::invalid_field_value(
                "ipv4.ihl",
                "internet header length is too small for option bytes",
            ));
        }
        if self.flags_value() > IPV4_MAX_FLAGS {
            return Err(CrafterError::invalid_field_value(
                "ipv4.flags",
                "IPv4 flags must fit in three bits",
            ));
        }
        if self.fragment_offset_value() > IPV4_MAX_FRAGMENT_OFFSET {
            return Err(CrafterError::invalid_field_value(
                "ipv4.fragment_offset",
                "fragment offset must fit in 13 bits",
            ));
        }
        if self.effective_total_length(payload_len)? < self.effective_header_len() as u16 {
            return Err(CrafterError::invalid_field_value(
                "ipv4.total_length",
                "total length must be at least the IPv4 header length",
            ));
        }
        Ok(())
    }
}

impl Default for Ipv4 {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ipv4 {
    fn name(&self) -> &'static str {
        "Ipv4"
    }

    fn summary(&self) -> String {
        format!(
            "Ipv4(src={}, dst={}, proto={})",
            self.source(),
            self.destination(),
            protocol_summary(self.protocol_value())
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("version", self.version_value().to_string()),
            ("ihl", self.ihl_value().to_string()),
            ("tos", self.tos_value().to_string()),
            (
                "total_length",
                self.total_length_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("id", format!("0x{:04x}", self.identification_value())),
            ("flags", flags_summary(self.flags_value())),
            ("fragment_offset", self.fragment_offset_value().to_string()),
            ("ttl", self.ttl_value().to_string()),
            ("protocol", protocol_summary(self.protocol_value())),
            (
                "checksum",
                self.checksum_value()
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("src", self.source().to_string()),
            ("dst", self.destination().to_string()),
            ("options", hex_bytes(&self.options)),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.effective_header_len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let payload_len = payload_len_after(*ctx);
        self.validate(payload_len)?;

        let header_len = self.effective_header_len();
        let ihl = (header_len / 4) as u8;
        let total_length = self.effective_total_length(payload_len)?;
        let flags_fragment = ((self.flags_value() as u16) << 13) | self.fragment_offset_value();
        let protocol = self.effective_protocol(ctx.next());

        let mut header = Vec::with_capacity(header_len);
        header.push((self.version_value() << 4) | ihl);
        header.push(self.tos_value());
        header.extend_from_slice(&total_length.to_be_bytes());
        header.extend_from_slice(&self.identification_value().to_be_bytes());
        header.extend_from_slice(&flags_fragment.to_be_bytes());
        header.push(self.ttl_value());
        header.push(protocol);
        header.extend_from_slice(&0u16.to_be_bytes());
        header.extend_from_slice(&self.source().octets());
        header.extend_from_slice(&self.destination().octets());
        header.extend_from_slice(&self.options);
        header.resize(header_len, 0);

        let checksum = self.effective_checksum(&header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());
        out.extend_from_slice(&header);
        Ok(())
    }

    fn transport_checksum_context(
        &self,
        transport_protocol: u8,
    ) -> Option<TransportChecksumContext> {
        Some(TransportChecksumContext::Ipv4 {
            source: self.source(),
            destination: self.destination(),
            protocol: if self.protocol.is_user_set() {
                self.protocol_value()
            } else {
                transport_protocol
            },
        })
    }

    impl_layer_object!(Ipv4);
}

impl_layer_div!(Ipv4);

/// Decode an IPv4 packet into a packet stack.
pub(crate) fn decode_ipv4_packet(bytes: &[u8]) -> Result<Packet> {
    let (ipv4, payload, rest) = decode_ipv4_parts(bytes)?;
    append_ipv4_payload(Packet::new().push(ipv4), payload, rest)
}

/// Append a decoded IPv4 packet to an existing outer stack.
pub(crate) fn append_ipv4_packet(packet: Packet, bytes: &[u8]) -> Result<Packet> {
    let (ipv4, payload, rest) = decode_ipv4_parts(bytes)?;
    append_ipv4_payload(packet.push(ipv4), payload, rest)
}

fn decode_ipv4_parts(bytes: &[u8]) -> Result<(Ipv4, &[u8], &[u8])> {
    if bytes.len() < IPV4_MIN_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ipv4 header",
            IPV4_MIN_HEADER_LEN,
            bytes.len(),
        ));
    }

    let version = bytes[0] >> 4;
    let ihl = bytes[0] & 0x0f;
    if version != 4 {
        return Err(CrafterError::invalid_field_value(
            "ipv4.version",
            "IPv4 packets must have version 4",
        ));
    }
    if ihl < 5 {
        return Err(CrafterError::invalid_field_value(
            "ipv4.ihl",
            "internet header length must be at least 5 words",
        ));
    }

    let header_len = (ihl as usize) * 4;
    if bytes.len() < header_len {
        return Err(CrafterError::buffer_too_short(
            "ipv4 header",
            header_len,
            bytes.len(),
        ));
    }

    let total_length = read_u16_be(&bytes[2..4])? as usize;
    if total_length < header_len {
        return Err(CrafterError::invalid_field_value(
            "ipv4.total_length",
            "total length must be at least the IPv4 header length",
        ));
    }
    if bytes.len() < total_length {
        return Err(CrafterError::buffer_too_short(
            "ipv4 packet",
            total_length,
            bytes.len(),
        ));
    }

    let flags_fragment = read_u16_be(&bytes[6..8])?;
    let options = if header_len > IPV4_MIN_HEADER_LEN {
        bytes[IPV4_MIN_HEADER_LEN..header_len].to_vec()
    } else {
        Vec::new()
    };
    let ipv4 = Ipv4 {
        version: Field::user(version),
        ihl: Field::user(ihl),
        tos: Field::user(bytes[1]),
        total_length: Field::user(total_length as u16),
        identification: Field::user(read_u16_be(&bytes[4..6])?),
        flags: Field::user((flags_fragment >> 13) as u8),
        fragment_offset: Field::user(flags_fragment & IPV4_MAX_FRAGMENT_OFFSET),
        ttl: Field::user(bytes[8]),
        protocol: Field::user(bytes[9]),
        checksum: Field::user(read_u16_be(&bytes[10..12])?),
        source: Field::user(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
        destination: Field::user(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
        options,
    };

    Ok((
        ipv4,
        &bytes[header_len..total_length],
        &bytes[total_length..],
    ))
}

fn append_ipv4_payload(mut packet: Packet, payload: &[u8], rest: &[u8]) -> Result<Packet> {
    let protocol = packet
        .layer::<Ipv4>()
        .map(Ipv4::protocol_value)
        .unwrap_or_default();

    packet = match protocol {
        IPPROTO_TCP => append_tcp_packet(packet, payload)?,
        IPPROTO_UDP => append_udp_packet(packet, payload)?,
        _ => {
            if payload.is_empty() {
                packet
            } else {
                packet.push(Raw::from_bytes(payload))
            }
        }
    };

    if !rest.is_empty() {
        packet = packet.push(Raw::from_bytes(rest));
    }

    Ok(packet)
}

fn payload_len_after(ctx: LayerContext<'_>) -> usize {
    ctx.packet()
        .iter()
        .skip(ctx.index() + 1)
        .map(Layer::encoded_len)
        .sum()
}

fn layer_ipv4_protocol(layer: &dyn Layer) -> Option<u8> {
    if layer.as_any().is::<Tcp>() {
        Some(IPPROTO_TCP)
    } else if layer.as_any().is::<Udp>() {
        Some(IPPROTO_UDP)
    } else {
        None
    }
}

fn padded_options_len(len: usize) -> usize {
    (len + 3) & !3
}

fn parse_ipv4(input: &str) -> Result<Ipv4Addr> {
    Ipv4Addr::from_str(input).map_err(|_| {
        CrafterError::invalid_field_value("ipv4_address", "expected dotted-quad IPv4 address")
    })
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn protocol_summary(protocol: u8) -> String {
    match protocol {
        0 => "hopopt(0)".to_string(),
        IPPROTO_ICMP => "icmp(1)".to_string(),
        IPPROTO_TCP => "tcp(6)".to_string(),
        IPPROTO_UDP => "udp(17)".to_string(),
        IPPROTO_IPV6 => "ipv6(41)".to_string(),
        IPPROTO_ICMPV6 => "icmpv6(58)".to_string(),
        value => value.to_string(),
    }
}

fn flags_summary(flags: u8) -> String {
    let mut names = Vec::new();
    if flags & IPV4_FLAG_RESERVED != 0 {
        names.push("reserved");
    }
    if flags & IPV4_FLAG_DONT_FRAGMENT != 0 {
        names.push("DF");
    }
    if flags & IPV4_FLAG_MORE_FRAGMENTS != 0 {
        names.push("MF");
    }
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join("|")
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();

    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(&format!("{byte:02x}"));
    }

    output
}

#[cfg(test)]
mod ipv4 {
    use super::{
        IpProtocol, Ipv4, IPPROTO_ICMP, IPV4_FLAG_DONT_FRAGMENT, IPV4_FLAG_MORE_FRAGMENTS,
    };
    use crate::{LinkType, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    const IPV4_ICMP_FIXTURE: &[u8] =
        include_bytes!("../../../../tests/fixtures/scapy/ipv4-icmp.bin");

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn ipv4_header_matches_scapy_fixture_with_raw_icmp_payload() {
        let packet = Ipv4::new()
            .src(src())
            .dst(dst())
            .id(0x1234)
            .dont_fragment(true)
            .proto(IpProtocol::Icmp)
            / Raw::from_bytes(&IPV4_ICMP_FIXTURE[20..]);

        assert_eq!(packet.compile().unwrap().as_bytes(), IPV4_ICMP_FIXTURE);
    }

    #[test]
    fn ipv4_decode_exposes_header_fields_and_preserves_payload() {
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, IPV4_ICMP_FIXTURE).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(ipv4.version_value(), 4);
        assert_eq!(ipv4.ihl_value(), 5);
        assert_eq!(ipv4.total_length_value(), Some(43));
        assert_eq!(ipv4.identification_value(), 0x1234);
        assert_eq!(ipv4.flags_value(), IPV4_FLAG_DONT_FRAGMENT);
        assert_eq!(ipv4.fragment_offset_value(), 0);
        assert_eq!(ipv4.ttl_value(), 64);
        assert_eq!(ipv4.protocol_value(), IPPROTO_ICMP);
        assert_eq!(ipv4.checksum_value(), Some(0x3c4c));
        assert_eq!(ipv4.source(), src());
        assert_eq!(ipv4.destination(), dst());
        assert_eq!(raw.as_bytes(), &IPV4_ICMP_FIXTURE[20..]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), IPV4_ICMP_FIXTURE);
    }

    #[test]
    fn ipv4_decode_from_ethernet_stack_autofills_link_ethertype() {
        let frame = crate::Ethernet::new()
            .src("02:00:5e:00:53:01".parse::<crate::MacAddr>().unwrap())
            / (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Icmp)
                / Raw::from_bytes(&IPV4_ICMP_FIXTURE[20..]));

        let bytes = frame.compile().unwrap();
        assert_eq!(
            &bytes.as_bytes()[12..14],
            &crate::ETHERTYPE_IPV4.to_be_bytes()
        );

        let decoded = Packet::decode_from_link(LinkType::Ethernet, bytes.as_bytes()).unwrap();
        assert!(decoded.layer::<crate::Ethernet>().is_some());
        assert!(decoded.layer::<Ipv4>().is_some());
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv4_options_are_padded_and_update_ihl_and_total_length() {
        let packet = Ipv4::new()
            .src(src())
            .dst(dst())
            .ttl(60)
            .id(0x1239)
            .proto(IpProtocol::Icmp)
            .option([0x01])
            .option([0x07, 0x07, 0x04, 0xc0, 0x00, 0x02, 0x01])
            / Raw::from([0u8; 8]);
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[0], 0x47);
        assert_eq!(&bytes.as_bytes()[2..4], &(36u16).to_be_bytes());
        assert_eq!(
            &bytes.as_bytes()[20..28],
            &[0x01, 0x07, 0x07, 0x04, 0xc0, 0x00, 0x02, 0x01]
        );
    }

    #[test]
    fn ipv4_decode_rejects_short_and_malformed_headers() {
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv4, [0u8; 19]).is_err());

        let mut bad_version = IPV4_ICMP_FIXTURE.to_vec();
        bad_version[0] = 0x65;
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv4, bad_version).is_err());

        let mut bad_ihl = IPV4_ICMP_FIXTURE.to_vec();
        bad_ihl[0] = 0x44;
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv4, bad_ihl).is_err());

        let mut bad_total = IPV4_ICMP_FIXTURE.to_vec();
        bad_total[2..4].copy_from_slice(&(19u16).to_be_bytes());
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv4, bad_total).is_err());
    }

    #[test]
    fn ipv4_builder_validates_flags_fragments_and_lengths() {
        let bad_flags = Packet::new().push(Ipv4::new().flags(8));
        assert!(bad_flags
            .compile()
            .unwrap_err()
            .to_string()
            .contains("flags"));

        let bad_fragment = Packet::new().push(Ipv4::new().frag(0x2000));
        assert!(bad_fragment
            .compile()
            .unwrap_err()
            .to_string()
            .contains("fragment"));

        let bad_total = Packet::new().push(Ipv4::new().len(19));
        assert!(bad_total
            .compile()
            .unwrap_err()
            .to_string()
            .contains("total length"));

        let flags = Ipv4::new()
            .dont_fragment(true)
            .more_fragments(true)
            .flags_value();
        assert_eq!(flags, IPV4_FLAG_DONT_FRAGMENT | IPV4_FLAG_MORE_FRAGMENTS);
    }
}

#[cfg(test)]
mod ipv4_checksum {
    use super::{IpProtocol, Ipv4};
    use crate::{checksum::verify_internet_checksum, Raw};
    use core::net::Ipv4Addr;

    const IPV4_ICMP_FIXTURE: &[u8] =
        include_bytes!("../../../../tests/fixtures/scapy/ipv4-icmp.bin");

    #[test]
    fn ipv4_header_checksum_matches_scapy_fixture() {
        let packet = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            .id(0x1234)
            .dont_fragment(true)
            .proto(IpProtocol::Icmp)
            / Raw::from_bytes(&IPV4_ICMP_FIXTURE[20..]);
        let bytes = packet.compile().unwrap();

        assert_eq!(&bytes.as_bytes()[10..12], &[0x3c, 0x4c]);
        assert!(verify_internet_checksum(&bytes.as_bytes()[..20]));
    }

    #[test]
    fn explicit_ipv4_checksum_is_preserved() {
        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            .id(0x1234)
            .dont_fragment(true)
            .proto(IpProtocol::Icmp)
            .checksum(0x1111)
            / Raw::from_bytes(&IPV4_ICMP_FIXTURE[20..]))
        .compile()
        .unwrap();

        assert_eq!(&bytes.as_bytes()[10..12], &[0x11, 0x11]);
        assert!(!verify_internet_checksum(&bytes.as_bytes()[..20]));
    }

    #[test]
    fn decoded_ipv4_checksum_verifies() {
        let decoded =
            crate::Packet::decode_from_l3(crate::NetworkLayer::Ipv4, IPV4_ICMP_FIXTURE).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();

        assert_eq!(ipv4.checksum_value(), Some(0x3c4c));
        assert!(verify_internet_checksum(&IPV4_ICMP_FIXTURE[..20]));
    }
}
