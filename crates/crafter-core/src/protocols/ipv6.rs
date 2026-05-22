//! IPv6 base header implementation.

use core::any::Any;
use core::net::Ipv6Addr;
use core::ops::Div;
use core::str::FromStr;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet, Raw, TransportChecksumContext};
use crate::protocols::icmp::{append_icmpv6_packet, Icmpv6};
use crate::protocols::ip::{IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};
use crate::protocols::transport::{append_tcp_packet, append_udp_packet, Tcp, Udp};

const IPV6_HEADER_LEN: usize = 40;
const IPV6_MAX_FLOW_LABEL: u32 = 0x000f_ffff;

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

/// IPv6 base header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6 {
    version: Field<u8>,
    traffic_class: Field<u8>,
    flow_label: Field<u32>,
    payload_length: Field<u16>,
    next_header: Field<u8>,
    hop_limit: Field<u8>,
    source: Field<Ipv6Addr>,
    destination: Field<Ipv6Addr>,
}

impl Ipv6 {
    /// Create an IPv6 header with deterministic defaults.
    pub fn new() -> Self {
        Self {
            version: Field::defaulted(6),
            traffic_class: Field::defaulted(0),
            flow_label: Field::defaulted(0),
            payload_length: Field::unset(),
            next_header: Field::defaulted(0),
            hop_limit: Field::defaulted(64),
            source: Field::defaulted(Ipv6Addr::LOCALHOST),
            destination: Field::defaulted(Ipv6Addr::LOCALHOST),
        }
    }

    /// Create an IPv6 header with explicit source and destination addresses.
    pub fn with_addresses(source: Ipv6Addr, destination: Ipv6Addr) -> Self {
        Self::new().src(source).dst(destination)
    }

    /// Set the IP version field.
    pub fn version(mut self, version: u8) -> Self {
        self.version.set_user(version);
        self
    }

    /// Set the traffic class field.
    pub fn traffic_class(mut self, traffic_class: u8) -> Self {
        self.traffic_class.set_user(traffic_class);
        self
    }

    /// Scapy-style alias for traffic class.
    pub fn tc(self, traffic_class: u8) -> Self {
        self.traffic_class(traffic_class)
    }

    /// Set the flow label.
    pub fn flow_label(mut self, flow_label: u32) -> Self {
        self.flow_label.set_user(flow_label);
        self
    }

    /// Scapy-style alias for flow label.
    pub fn fl(self, flow_label: u32) -> Self {
        self.flow_label(flow_label)
    }

    /// Set the payload length field explicitly.
    pub fn payload_length(mut self, payload_length: u16) -> Self {
        self.payload_length.set_user(payload_length);
        self
    }

    /// Scapy-style alias for payload length.
    pub fn plen(self, payload_length: u16) -> Self {
        self.payload_length(payload_length)
    }

    /// Set the next-header field.
    pub fn next_header(mut self, next_header: u8) -> Self {
        self.next_header.set_user(next_header);
        self
    }

    /// Scapy/libcrafter-style alias for next header.
    pub fn nh(self, next_header: u8) -> Self {
        self.next_header(next_header)
    }

    /// Set the hop limit.
    pub fn hop_limit(mut self, hop_limit: u8) -> Self {
        self.hop_limit.set_user(hop_limit);
        self
    }

    /// Scapy/libcrafter-style alias for hop limit.
    pub fn hlim(self, hop_limit: u8) -> Self {
        self.hop_limit(hop_limit)
    }

    /// Set the source IPv6 address.
    pub fn src(mut self, source: Ipv6Addr) -> Self {
        self.source.set_user(source);
        self
    }

    /// Set the source IPv6 address from text.
    pub fn src_str(self, source: &str) -> Result<Self> {
        Ok(self.src(parse_ipv6(source)?))
    }

    /// Set the destination IPv6 address.
    pub fn dst(mut self, destination: Ipv6Addr) -> Self {
        self.destination.set_user(destination);
        self
    }

    /// Set the destination IPv6 address from text.
    pub fn dst_str(self, destination: &str) -> Result<Self> {
        Ok(self.dst(parse_ipv6(destination)?))
    }

    /// IP version value.
    pub fn version_value(&self) -> u8 {
        value_or_copy(&self.version, 6)
    }

    /// Traffic class value.
    pub fn traffic_class_value(&self) -> u8 {
        value_or_copy(&self.traffic_class, 0)
    }

    /// Flow label value.
    pub fn flow_label_value(&self) -> u32 {
        value_or_copy(&self.flow_label, 0)
    }

    /// Payload length when explicitly stored or decoded.
    pub fn payload_length_value(&self) -> Option<u16> {
        self.payload_length.value().copied()
    }

    /// Next-header value.
    pub fn next_header_value(&self) -> u8 {
        value_or_copy(&self.next_header, 0)
    }

    /// Hop limit value.
    pub fn hop_limit_value(&self) -> u8 {
        value_or_copy(&self.hop_limit, 64)
    }

    /// Source address.
    pub fn source(&self) -> Ipv6Addr {
        value_or_copy(&self.source, Ipv6Addr::LOCALHOST)
    }

    /// Destination address.
    pub fn destination(&self) -> Ipv6Addr {
        value_or_copy(&self.destination, Ipv6Addr::LOCALHOST)
    }

    fn effective_payload_length(&self, payload_len: usize) -> Result<u16> {
        if let Some(payload_length) = self.payload_length.value().copied() {
            return Ok(payload_length);
        }

        u16::try_from(payload_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "ipv6.payload_length",
                "IPv6 payload length exceeds 65535 bytes",
            )
        })
    }

    fn effective_next_header(&self, next: Option<&dyn Layer>) -> u8 {
        if self.next_header.is_user_set() {
            return self.next_header_value();
        }

        next.and_then(layer_ipv6_next_header)
            .or_else(|| self.next_header.value().copied())
            .unwrap_or(0)
    }

    fn validate(&self, payload_len: usize) -> Result<()> {
        if self.version_value() != 6 {
            return Err(CrafterError::invalid_field_value(
                "ipv6.version",
                "IPv6 layer version must be 6",
            ));
        }
        if self.flow_label_value() > IPV6_MAX_FLOW_LABEL {
            return Err(CrafterError::invalid_field_value(
                "ipv6.flow_label",
                "flow label must fit in 20 bits",
            ));
        }
        self.effective_payload_length(payload_len)?;
        Ok(())
    }
}

impl Default for Ipv6 {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ipv6 {
    fn name(&self) -> &'static str {
        "Ipv6"
    }

    fn summary(&self) -> String {
        format!(
            "Ipv6(src={}, dst={}, next={})",
            self.source(),
            self.destination(),
            next_header_summary(self.next_header_value())
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("version", self.version_value().to_string()),
            (
                "traffic_class",
                format!("0x{:02x}", self.traffic_class_value()),
            ),
            ("flow_label", format!("0x{:05x}", self.flow_label_value())),
            (
                "payload_length",
                self.payload_length_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("next_header", next_header_summary(self.next_header_value())),
            ("hop_limit", self.hop_limit_value().to_string()),
            ("src", self.source().to_string()),
            ("dst", self.destination().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        IPV6_HEADER_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let payload_len = payload_len_after(*ctx);
        self.validate(payload_len)?;

        let version_class_flow = ((self.version_value() as u32) << 28)
            | ((self.traffic_class_value() as u32) << 20)
            | self.flow_label_value();
        out.extend_from_slice(&version_class_flow.to_be_bytes());
        out.extend_from_slice(&self.effective_payload_length(payload_len)?.to_be_bytes());
        out.push(self.effective_next_header(ctx.next()));
        out.push(self.hop_limit_value());
        out.extend_from_slice(&self.source().octets());
        out.extend_from_slice(&self.destination().octets());
        Ok(())
    }

    fn transport_checksum_context(
        &self,
        transport_protocol: u8,
    ) -> Option<TransportChecksumContext> {
        Some(TransportChecksumContext::Ipv6 {
            source: self.source(),
            destination: self.destination(),
            next_header: if self.next_header.is_user_set() {
                self.next_header_value()
            } else {
                transport_protocol
            },
        })
    }

    impl_layer_object!(Ipv6);
}

impl_layer_div!(Ipv6);

/// Decode an IPv6 packet into a packet stack.
pub(crate) fn decode_ipv6_packet(bytes: &[u8]) -> Result<Packet> {
    let (ipv6, payload, rest) = decode_ipv6_parts(bytes)?;
    append_ipv6_payload(Packet::new().push(ipv6), payload, rest)
}

/// Append a decoded IPv6 packet to an existing outer stack.
pub(crate) fn append_ipv6_packet(packet: Packet, bytes: &[u8]) -> Result<Packet> {
    let (ipv6, payload, rest) = decode_ipv6_parts(bytes)?;
    append_ipv6_payload(packet.push(ipv6), payload, rest)
}

fn decode_ipv6_parts(bytes: &[u8]) -> Result<(Ipv6, &[u8], &[u8])> {
    if bytes.len() < IPV6_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ipv6 header",
            IPV6_HEADER_LEN,
            bytes.len(),
        ));
    }

    let version_class_flow = read_u32_be(&bytes[0..4])?;
    let version = (version_class_flow >> 28) as u8;
    if version != 6 {
        return Err(CrafterError::invalid_field_value(
            "ipv6.version",
            "IPv6 packets must have version 6",
        ));
    }

    let payload_length = read_u16_be(&bytes[4..6])? as usize;
    let total_length = IPV6_HEADER_LEN + payload_length;
    if bytes.len() < total_length {
        return Err(CrafterError::buffer_too_short(
            "ipv6 packet",
            total_length,
            bytes.len(),
        ));
    }

    let ipv6 = Ipv6 {
        version: Field::user(version),
        traffic_class: Field::user(((version_class_flow >> 20) & 0xff) as u8),
        flow_label: Field::user(version_class_flow & IPV6_MAX_FLOW_LABEL),
        payload_length: Field::user(payload_length as u16),
        next_header: Field::user(bytes[6]),
        hop_limit: Field::user(bytes[7]),
        source: Field::user(Ipv6Addr::from(copy_array_16(&bytes[8..24]))),
        destination: Field::user(Ipv6Addr::from(copy_array_16(&bytes[24..40]))),
    };

    Ok((
        ipv6,
        &bytes[IPV6_HEADER_LEN..total_length],
        &bytes[total_length..],
    ))
}

fn append_ipv6_payload(mut packet: Packet, payload: &[u8], rest: &[u8]) -> Result<Packet> {
    let next_header = packet
        .layer::<Ipv6>()
        .map(Ipv6::next_header_value)
        .unwrap_or_default();

    packet = match next_header {
        IPPROTO_TCP => append_tcp_packet(packet, payload)?,
        IPPROTO_UDP => append_udp_packet(packet, payload)?,
        IPPROTO_ICMPV6 => append_icmpv6_packet(packet, payload)?,
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

fn layer_ipv6_next_header(layer: &dyn Layer) -> Option<u8> {
    if layer.as_any().is::<Tcp>() {
        Some(IPPROTO_TCP)
    } else if layer.as_any().is::<Udp>() {
        Some(IPPROTO_UDP)
    } else if layer.as_any().is::<Icmpv6>() {
        Some(IPPROTO_ICMPV6)
    } else {
        None
    }
}

fn parse_ipv6(input: &str) -> Result<Ipv6Addr> {
    Ipv6Addr::from_str(input).map_err(|_| {
        CrafterError::invalid_field_value("ipv6_address", "expected textual IPv6 address")
    })
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn next_header_summary(next_header: u8) -> String {
    match next_header {
        IPPROTO_TCP => "tcp(6)".to_string(),
        IPPROTO_UDP => "udp(17)".to_string(),
        IPPROTO_ICMPV6 => "icmpv6(58)".to_string(),
        value => value.to_string(),
    }
}

fn copy_array_16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[..16]);
    out
}
