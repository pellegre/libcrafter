//! UDP protocol implementation.

use crate::endian::read_u16_be;
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Layer, LayerContext, Packet, Raw};
use crate::protocols::dhcp::{Dhcp, DHCP_CLIENT_PORT, DHCP_SERVER_PORT};
use crate::protocols::dns::Dns;
use crate::protocols::ip::IPPROTO_UDP;
use crate::registry::ProtocolRegistry;

use super::common::{
    hex_bytes, impl_layer_div, impl_layer_object, transport_checksum_context, value_or_copy,
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

const UDP_OPTION_SHORT_HEADER_LEN: usize = 2;
const UDP_OPTION_EXTENDED_HEADER_LEN: usize = 4;
const UDP_OPTION_EXTENDED_LEN_SENTINEL: u8 = 255;
const UDP_OPTION_MAX_CONSECUTIVE_NOPS: usize = 7;

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

/// Parsed or constructible UDP surplus option.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UdpOption {
    /// End of option list.
    EndOfList,
    /// One-byte no-operation padding.
    NoOperation,
    /// Unknown or caller-defined option with the standard one-byte length field.
    Generic {
        /// Raw option kind byte.
        kind: u8,
        /// Option payload bytes after kind and length.
        data: Vec<u8>,
    },
    /// Unknown or caller-defined option with the extended two-byte length field.
    ExtendedGeneric {
        /// Raw option kind byte.
        kind: u8,
        /// Option payload bytes after kind, sentinel length, and extended length.
        data: Vec<u8>,
    },
}

impl UdpOption {
    /// Create an end-of-option-list marker.
    pub const fn end_of_list() -> Self {
        Self::EndOfList
    }

    /// Create a no-operation padding option.
    pub const fn no_operation() -> Self {
        Self::NoOperation
    }

    /// Create a caller-defined option.
    pub fn generic(kind: u8, data: impl Into<Vec<u8>>) -> Self {
        let data = data.into();
        if UDP_OPTION_SHORT_HEADER_LEN + data.len() >= UDP_OPTION_EXTENDED_LEN_SENTINEL as usize {
            Self::ExtendedGeneric { kind, data }
        } else {
            Self::Generic { kind, data }
        }
    }

    /// Create a caller-defined option using the extended length encoding.
    pub fn extended_generic(kind: u8, data: impl Into<Vec<u8>>) -> Self {
        Self::ExtendedGeneric {
            kind,
            data: data.into(),
        }
    }

    /// Raw option kind byte.
    pub const fn kind(&self) -> u8 {
        match self {
            Self::EndOfList => UDP_OPTION_EOL,
            Self::NoOperation => UDP_OPTION_NOP,
            Self::Generic { kind, .. } | Self::ExtendedGeneric { kind, .. } => *kind,
        }
    }

    /// Option payload bytes after the option length fields.
    pub fn data(&self) -> &[u8] {
        match self {
            Self::EndOfList | Self::NoOperation => &[],
            Self::Generic { data, .. } | Self::ExtendedGeneric { data, .. } => data,
        }
    }

    /// Return true if this option uses the extended length format.
    pub const fn uses_extended_length(&self) -> bool {
        matches!(self, Self::ExtendedGeneric { .. })
    }

    /// Encoded option length in bytes.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::EndOfList | Self::NoOperation => 1,
            Self::Generic { data, .. } => UDP_OPTION_SHORT_HEADER_LEN + data.len(),
            Self::ExtendedGeneric { data, .. } => UDP_OPTION_EXTENDED_HEADER_LEN + data.len(),
        }
    }

    /// Encode this option to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let len = self.encoded_len();
        let mut bytes = Vec::with_capacity(len);
        match self {
            Self::EndOfList => bytes.push(UDP_OPTION_EOL),
            Self::NoOperation => bytes.push(UDP_OPTION_NOP),
            Self::Generic { kind, data } => {
                validate_udp_generic_option_kind(*kind)?;
                if len >= UDP_OPTION_EXTENDED_LEN_SENTINEL as usize {
                    return Err(CrafterError::invalid_field_value(
                        "udp.option.length",
                        "UDP option short length must be less than 255 bytes",
                    ));
                }
                bytes.extend_from_slice(&[*kind, len as u8]);
                bytes.extend_from_slice(data);
            }
            Self::ExtendedGeneric { kind, data } => {
                validate_udp_generic_option_kind(*kind)?;
                let len = u16::try_from(len).map_err(|_| {
                    CrafterError::invalid_field_value(
                        "udp.option.length",
                        "UDP option extended length must fit in two bytes",
                    )
                })?;
                bytes.extend_from_slice(&[*kind, UDP_OPTION_EXTENDED_LEN_SENTINEL]);
                bytes.extend_from_slice(&len.to_be_bytes());
                bytes.extend_from_slice(data);
            }
        }

        Ok(bytes)
    }

    /// Decode all options from a raw UDP option byte slice.
    pub fn decode_all(bytes: &[u8]) -> Result<Vec<Self>> {
        UdpOptionIter::new(bytes).collect()
    }
}

/// Iterator over encoded UDP surplus options.
#[derive(Debug, Clone)]
pub struct UdpOptionIter<'a> {
    bytes: &'a [u8],
    offset: usize,
    consecutive_nops: usize,
    eol_padding_offset: Option<usize>,
    done: bool,
}

impl<'a> UdpOptionIter<'a> {
    /// Create an iterator over raw UDP option bytes.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            consecutive_nops: 0,
            eol_padding_offset: None,
            done: false,
        }
    }
}

impl Iterator for UdpOptionIter<'_> {
    type Item = Result<UdpOption>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(offset) = self.eol_padding_offset.take() {
            self.done = true;
            if self.bytes[offset..].iter().any(|byte| *byte != 0) {
                return Some(Err(CrafterError::invalid_field_value(
                    "udp.option.eol_padding",
                    "bytes after EOL must be zero-fill",
                )));
            }
            return None;
        }

        if self.done || self.offset >= self.bytes.len() {
            return None;
        }

        let start = self.offset;
        let kind = self.bytes[start];
        match kind {
            UDP_OPTION_EOL => {
                self.consecutive_nops = 0;
                self.offset = start + 1;
                self.eol_padding_offset = Some(start + 1);
                Some(Ok(UdpOption::EndOfList))
            }
            UDP_OPTION_NOP => {
                self.offset += 1;
                self.consecutive_nops += 1;
                if self.consecutive_nops > UDP_OPTION_MAX_CONSECUTIVE_NOPS {
                    self.done = true;
                    return Some(Err(CrafterError::invalid_field_value(
                        "udp.option.nop",
                        "more than seven consecutive NOP options",
                    )));
                }
                Some(Ok(UdpOption::NoOperation))
            }
            _ => {
                self.consecutive_nops = 0;
                if start + UDP_OPTION_SHORT_HEADER_LEN > self.bytes.len() {
                    self.done = true;
                    return Some(Err(CrafterError::buffer_too_short(
                        "udp option",
                        start + UDP_OPTION_SHORT_HEADER_LEN,
                        self.bytes.len(),
                    )));
                }

                let len = self.bytes[start + 1];
                if len == UDP_OPTION_EXTENDED_LEN_SENTINEL {
                    self.decode_extended(start, kind)
                } else {
                    self.decode_short(start, kind, len as usize)
                }
            }
        }
    }
}

impl UdpOptionIter<'_> {
    fn decode_short(&mut self, start: usize, kind: u8, len: usize) -> Option<Result<UdpOption>> {
        if len < UDP_OPTION_SHORT_HEADER_LEN {
            self.done = true;
            return Some(Err(CrafterError::invalid_field_value(
                "udp.option.length",
                "option length must be at least 2 bytes",
            )));
        }

        let end = start + len;
        if end > self.bytes.len() {
            self.done = true;
            return Some(Err(CrafterError::buffer_too_short(
                "udp option",
                end,
                self.bytes.len(),
            )));
        }

        self.offset = end;
        Some(Ok(UdpOption::Generic {
            kind,
            data: self.bytes[start + UDP_OPTION_SHORT_HEADER_LEN..end].to_vec(),
        }))
    }

    fn decode_extended(&mut self, start: usize, kind: u8) -> Option<Result<UdpOption>> {
        if start + UDP_OPTION_EXTENDED_HEADER_LEN > self.bytes.len() {
            self.done = true;
            return Some(Err(CrafterError::buffer_too_short(
                "udp option extended length",
                start + UDP_OPTION_EXTENDED_HEADER_LEN,
                self.bytes.len(),
            )));
        }

        let len = u16::from_be_bytes([self.bytes[start + 2], self.bytes[start + 3]]) as usize;
        if len < UDP_OPTION_EXTENDED_HEADER_LEN {
            self.done = true;
            return Some(Err(CrafterError::invalid_field_value(
                "udp.option.length",
                "extended option length must be at least 4 bytes",
            )));
        }

        let end = start + len;
        if end > self.bytes.len() {
            self.done = true;
            return Some(Err(CrafterError::buffer_too_short(
                "udp option",
                end,
                self.bytes.len(),
            )));
        }

        self.offset = end;
        Some(Ok(UdpOption::ExtendedGeneric {
            kind,
            data: self.bytes[start + UDP_OPTION_EXTENDED_HEADER_LEN..end].to_vec(),
        }))
    }
}

/// UDP surplus option bytes.
///
/// This layer preserves the area after UDP Length in packets that carry RFC
/// 9868 UDP options and caches generic option parsing status for inspection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UdpOptions {
    bytes: Vec<u8>,
    options: Vec<UdpOption>,
    status: UdpOptionStatus,
}

impl UdpOptions {
    /// Create an empty UDP options layer.
    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            options: Vec::new(),
            status: UdpOptionStatus::NoSurplus,
        }
    }

    /// Create a UDP options layer by copying bytes.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        let bytes = bytes.as_ref().to_vec();
        let (options, status) = parse_udp_options_for_status(&bytes);
        Self {
            bytes,
            options,
            status,
        }
    }

    /// Create a UDP options layer from typed options.
    pub fn from_options(options: impl Into<Vec<UdpOption>>) -> Result<Self> {
        let bytes = encode_udp_options(&options.into())?;
        let (options, status) = parse_udp_options_for_status(&bytes);
        Ok(Self {
            bytes,
            options,
            status,
        })
    }

    /// Borrow the encoded UDP option bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Mutably borrow the encoded UDP option bytes.
    pub fn as_bytes_mut(&mut self) -> &mut Vec<u8> {
        self.options.clear();
        self.status = UdpOptionStatus::NotParsed;
        &mut self.bytes
    }

    /// Append encoded UDP option bytes.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(bytes);
        self.refresh_parse();
        self
    }

    /// Append a typed UDP option.
    pub fn udp_option(mut self, option: UdpOption) -> Result<Self> {
        self.bytes.extend_from_slice(&option.encode()?);
        self.refresh_parse();
        Ok(self)
    }

    /// Consume the layer and return its encoded UDP option bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Number of encoded UDP option bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when no UDP option bytes are present.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Inspection status from generic option parsing.
    pub const fn status(&self) -> UdpOptionStatus {
        self.status
    }

    /// Parsed options cached when the layer was created or last extended.
    pub fn options(&self) -> &[UdpOption] {
        &self.options
    }

    /// Iterate over the current encoded UDP option bytes.
    pub fn option_iter(&self) -> UdpOptionIter<'_> {
        UdpOptionIter::new(&self.bytes)
    }

    /// Decode the current encoded UDP option bytes into typed values.
    pub fn parsed_options(&self) -> Result<Vec<UdpOption>> {
        UdpOption::decode_all(&self.bytes)
    }

    fn refresh_parse(&mut self) {
        (self.options, self.status) = parse_udp_options_for_status(&self.bytes);
    }
}

impl Default for UdpOptions {
    fn default() -> Self {
        Self::new()
    }
}

fn encode_udp_options(options: &[UdpOption]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for option in options {
        bytes.extend_from_slice(&option.encode()?);
    }
    Ok(bytes)
}

fn parse_udp_options_for_status(bytes: &[u8]) -> (Vec<UdpOption>, UdpOptionStatus) {
    if bytes.is_empty() {
        return (Vec::new(), UdpOptionStatus::NoSurplus);
    }

    let mut options = Vec::new();
    for option in UdpOptionIter::new(bytes) {
        match option {
            Ok(option) => options.push(option),
            Err(_) => return (options, UdpOptionStatus::Malformed),
        }
    }

    (options, UdpOptionStatus::Valid)
}

fn udp_option_inspection_summary(option: &UdpOption) -> String {
    match option {
        UdpOption::EndOfList => "EOL".to_string(),
        UdpOption::NoOperation => "NOP".to_string(),
        UdpOption::Generic { kind, data } => {
            format!(
                "Generic(kind={kind},len={})",
                UDP_OPTION_SHORT_HEADER_LEN + data.len()
            )
        }
        UdpOption::ExtendedGeneric { kind, data } => format!(
            "ExtendedGeneric(kind={kind},len={})",
            UDP_OPTION_EXTENDED_HEADER_LEN + data.len()
        ),
    }
}

fn udp_options_inspection_summary(options: &[UdpOption]) -> String {
    if options.is_empty() {
        return "none".to_string();
    }

    options
        .iter()
        .map(udp_option_inspection_summary)
        .collect::<Vec<_>>()
        .join(",")
}

fn validate_udp_generic_option_kind(kind: u8) -> Result<()> {
    if kind == UDP_OPTION_EOL || kind == UDP_OPTION_NOP {
        return Err(CrafterError::invalid_field_value(
            "udp.option.kind",
            "EOL and NOP options do not carry a length field",
        ));
    }
    Ok(())
}

impl Layer for UdpOptions {
    fn name(&self) -> &'static str {
        "UdpOptions"
    }

    fn summary(&self) -> String {
        format!(
            "UdpOptions(len={}, status={:?})",
            self.bytes.len(),
            self.status
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("len", self.bytes.len().to_string()),
            ("status", format!("{:?}", self.status)),
            ("option_count", self.options.len().to_string()),
            ("options", udp_options_inspection_summary(&self.options)),
            ("bytes", hex_bytes(&self.bytes)),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.bytes.len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.bytes);
        Ok(())
    }

    impl_layer_object!(UdpOptions);
}

impl_layer_div!(UdpOptions);

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
        let payload = udp_user_payload_bytes_after(*ctx)?;
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
    let decoded = decode_udp_parts(bytes)?;
    let source_port = decoded.udp.source_port_value();
    let destination_port = decoded.udp.destination_port_value();
    packet = packet.push(decoded.udp);
    if !decoded.user_payload.is_empty() {
        packet = registry.decode_udp_application(
            packet,
            source_port,
            destination_port,
            decoded.user_payload,
        )?;
    }
    if !decoded.surplus.is_empty() {
        packet = packet.push(UdpOptions::from_bytes(decoded.surplus));
    }
    Ok(packet)
}

struct DecodedUdpDatagram<'a> {
    udp: Udp,
    user_payload: &'a [u8],
    surplus: &'a [u8],
}

fn decode_udp_parts(bytes: &[u8]) -> Result<DecodedUdpDatagram<'_>> {
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

    Ok(DecodedUdpDatagram {
        udp,
        user_payload: &bytes[UDP_HEADER_LEN..length],
        surplus: &bytes[length..],
    })
}

fn udp_user_payload_bytes_after(ctx: LayerContext<'_>) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    let mut seen_application_layer = false;

    for (index, layer) in ctx.packet().iter().enumerate().skip(ctx.index() + 1) {
        if is_current_udp_surplus_layer(layer, seen_application_layer) {
            break;
        }

        let layer_ctx = LayerContext::new(ctx.packet(), index);
        layer.compile(&layer_ctx, &mut payload)?;

        if is_udp_application_layer(layer) {
            seen_application_layer = true;
        }
    }

    Ok(payload)
}

fn is_udp_application_layer(layer: &dyn Layer) -> bool {
    layer.as_any().is::<Dns>() || layer.as_any().is::<Dhcp>()
}

fn is_current_udp_surplus_layer(layer: &dyn Layer, seen_application_layer: bool) -> bool {
    layer.as_any().is::<UdpOptions>() || (seen_application_layer && layer.as_any().is::<Raw>())
}

#[cfg(test)]
mod tests {
    use super::{
        Udp, UdpChecksumStatus, UdpOption, UdpOptionIter, UdpOptionStatus, UdpOptions,
        UDP_HEADER_LEN, UDP_OPTION_APC, UDP_OPTION_EOL, UDP_OPTION_EXP, UDP_OPTION_FRAG,
        UDP_OPTION_MDS, UDP_OPTION_MRDS, UDP_OPTION_NOP, UDP_OPTION_REQ, UDP_OPTION_RES,
    };
    use crate::checksum::ipv4_pseudo_header_checksum;
    use crate::{
        Dhcp, DhcpMessageType, Dns, IpProtocol, Ipv4, Layer, LinkType, MacAddr, Packet, Raw,
        DNS_PORT, DNS_TYPE_A, IPPROTO_UDP,
    };
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
    fn udp_option_encode_decode_generic_forms() {
        let short = UdpOption::generic(UDP_OPTION_MDS, [0x05, 0xb4]);
        assert_eq!(short.kind(), UDP_OPTION_MDS);
        assert_eq!(short.data(), &[0x05, 0xb4]);
        assert!(!short.uses_extended_length());
        assert_eq!(short.encoded_len(), 4);
        assert_eq!(short.encode().unwrap(), vec![UDP_OPTION_MDS, 4, 0x05, 0xb4]);

        let extended = UdpOption::extended_generic(UDP_OPTION_EXP, [0x12, 0x34]);
        assert!(extended.uses_extended_length());
        assert_eq!(extended.encoded_len(), 6);
        assert_eq!(
            extended.encode().unwrap(),
            vec![UDP_OPTION_EXP, 255, 0, 6, 0x12, 0x34]
        );

        let decoded =
            UdpOption::decode_all(&[UDP_OPTION_NOP, UDP_OPTION_EXP, 255, 0, 6, 0x12, 0x34])
                .unwrap();
        assert_eq!(
            decoded,
            vec![
                UdpOption::NoOperation,
                UdpOption::ExtendedGeneric {
                    kind: UDP_OPTION_EXP,
                    data: vec![0x12, 0x34]
                }
            ]
        );
    }

    #[test]
    fn udp_option_eol_encode_decode_and_inspection_output() {
        let eol = UdpOption::end_of_list();
        assert_eq!(eol, UdpOption::EndOfList);
        assert_eq!(eol.kind(), UDP_OPTION_EOL);
        assert_eq!(eol.data(), &[]);
        assert_eq!(eol.encoded_len(), 1);
        assert_eq!(eol.encode().unwrap(), vec![UDP_OPTION_EOL]);

        let decoded = UdpOption::decode_all(&[UDP_OPTION_NOP, UDP_OPTION_EOL, 0, 0, 0]).unwrap();
        assert_eq!(decoded, vec![UdpOption::NoOperation, UdpOption::EndOfList]);

        let udp_options = UdpOptions::from_bytes([UDP_OPTION_EOL, 0, 0]);
        assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
        assert_eq!(udp_options.options(), &[UdpOption::EndOfList]);
        assert_eq!(udp_options.as_bytes(), &[UDP_OPTION_EOL, 0, 0]);
        assert!(udp_options.summary().contains("status=Valid"));
        assert!(udp_options
            .inspection_fields()
            .iter()
            .any(|(name, value)| *name == "options" && value == "EOL"));
    }

    #[test]
    fn udp_option_nop_encode_decode_padding_and_limit() {
        let nop = UdpOption::no_operation();
        assert_eq!(nop, UdpOption::NoOperation);
        assert_eq!(nop.kind(), UDP_OPTION_NOP);
        assert_eq!(nop.data(), &[]);
        assert_eq!(nop.encoded_len(), 1);
        assert_eq!(nop.encode().unwrap(), vec![UDP_OPTION_NOP]);

        let seven_nops = [UDP_OPTION_NOP; 7];
        let decoded = UdpOption::decode_all(&seven_nops).unwrap();
        assert_eq!(decoded, vec![UdpOption::NoOperation; 7]);
        assert_eq!(
            UdpOptions::from_bytes(seven_nops).status(),
            UdpOptionStatus::Valid
        );

        let eight_nops = [UDP_OPTION_NOP; 8];
        assert_eq!(
            UdpOptions::from_bytes(eight_nops).status(),
            UdpOptionStatus::Malformed
        );
        match UdpOption::decode_all(&eight_nops).unwrap_err() {
            crate::CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "udp.option.nop");
            }
            other => panic!("expected excessive NOP validation error, got {other:?}"),
        }
    }

    #[test]
    fn udp_option_iterator_reports_malformed_lengths() {
        let mut iter = UdpOptionIter::new(&[UDP_OPTION_MDS, 1]);
        match iter.next().unwrap() {
            Err(crate::CrafterError::InvalidFieldValue { field, .. }) => {
                assert_eq!(field, "udp.option.length");
            }
            other => panic!("expected malformed short length, got {other:?}"),
        }
        assert!(iter.next().is_none());

        match UdpOption::decode_all(&[UDP_OPTION_EXP, 255, 0, 8, 0xaa]).unwrap_err() {
            crate::CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "udp option");
                assert_eq!(required, 8);
                assert_eq!(available, 5);
            }
            other => panic!("expected malformed extended length, got {other:?}"),
        }
    }

    #[test]
    fn udp_options_padding_empty_zero_fill_and_nonzero_after_eol() {
        let empty = UdpOptions::new();
        assert!(empty.is_empty());
        assert_eq!(empty.status(), UdpOptionStatus::NoSurplus);
        assert_eq!(empty.options(), &[]);

        let zero_fill = UdpOptions::from_bytes([UDP_OPTION_NOP, UDP_OPTION_EOL, 0, 0, 0]);
        assert_eq!(zero_fill.status(), UdpOptionStatus::Valid);
        assert_eq!(
            zero_fill.options(),
            &[UdpOption::NoOperation, UdpOption::EndOfList]
        );
        assert_eq!(
            zero_fill.as_bytes(),
            &[UDP_OPTION_NOP, UDP_OPTION_EOL, 0, 0, 0]
        );

        let nonzero_fill = UdpOptions::from_bytes([UDP_OPTION_EOL, 0, 0x5a]);
        assert_eq!(nonzero_fill.status(), UdpOptionStatus::Malformed);
        assert_eq!(nonzero_fill.options(), &[UdpOption::EndOfList]);
        assert_eq!(nonzero_fill.as_bytes(), &[UDP_OPTION_EOL, 0, 0x5a]);

        match UdpOption::decode_all(nonzero_fill.as_bytes()).unwrap_err() {
            crate::CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "udp.option.eol_padding");
            }
            other => panic!("expected EOL padding validation error, got {other:?}"),
        }
    }

    #[test]
    fn udp_options_layer_preserves_bytes_and_caches_parse_status() {
        let bytes = [UDP_OPTION_NOP, UDP_OPTION_EXP, 255, 0, 6, 0x12, 0x34];
        let udp_options = UdpOptions::from_bytes(bytes);

        assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
        assert_eq!(udp_options.as_bytes(), &bytes);
        assert_eq!(
            udp_options.options(),
            &[
                UdpOption::NoOperation,
                UdpOption::ExtendedGeneric {
                    kind: UDP_OPTION_EXP,
                    data: vec![0x12, 0x34]
                }
            ]
        );
        assert_eq!(udp_options.parsed_options().unwrap(), udp_options.options());

        let typed = UdpOptions::from_options(vec![
            UdpOption::NoOperation,
            UdpOption::generic(UDP_OPTION_MDS, [0x05, 0xb4]),
        ])
        .unwrap();
        assert_eq!(
            typed.as_bytes(),
            &[UDP_OPTION_NOP, UDP_OPTION_MDS, 4, 0x05, 0xb4]
        );

        let malformed = UdpOptions::from_bytes([UDP_OPTION_MDS, 1]);
        assert_eq!(malformed.status(), UdpOptionStatus::Malformed);
        assert_eq!(malformed.as_bytes(), &[UDP_OPTION_MDS, 1]);
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
    fn udp_length_eight_and_zero_ports_are_preserved() {
        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2223)
            / Udp::new().sport(0).dport(0).checksum(0))
        .compile()
        .unwrap();

        assert_eq!(&bytes.as_bytes()[20..22], &0u16.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[22..24], &0u16.to_be_bytes());
        assert_eq!(
            &bytes.as_bytes()[24..26],
            &(UDP_HEADER_LEN as u16).to_be_bytes()
        );

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        assert_eq!(udp.source_port_value(), 0);
        assert_eq!(udp.destination_port_value(), 0);
        assert_eq!(udp.length_value(), Some(UDP_HEADER_LEN as u16));
        assert!(decoded.layers::<Raw>().next().is_none());
        assert!(decoded.layers::<UdpOptions>().next().is_none());
    }

    #[test]
    fn explicit_udp_length_is_preserved() {
        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2224)
            / Udp::new().sport(0x1234).dport(0x5678).len(42)
            / Raw::from("abc"))
        .compile()
        .unwrap();

        assert_eq!(&bytes.as_bytes()[2..4], &(31u16).to_be_bytes());
        assert_eq!(&bytes.as_bytes()[24..26], &(42u16).to_be_bytes());
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
        for checksum in [0, 0x1badu16] {
            let bytes = (Ipv4::new().src(src()).dst(dst())
                / Udp::new().checksum(checksum)
                / Raw::from("abc"))
            .compile()
            .unwrap();

            assert_eq!(&bytes.as_bytes()[26..28], &checksum.to_be_bytes());
        }
    }

    #[test]
    fn dns_decode_uses_udp_user_payload_and_preserves_udp_options() {
        let dns = Dns::a_query("example.com").id(0xbeef);
        let dns_len = dns.encoded_len();
        let surplus = [UDP_OPTION_NOP, UDP_OPTION_EOL, 0, 0];

        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2226)
            / Udp::new().sport(53_001).dport(DNS_PORT)
            / dns
            / UdpOptions::from_bytes(surplus))
        .compile()
        .unwrap();

        assert_eq!(
            &bytes.as_bytes()[2..4],
            &((20 + UDP_HEADER_LEN + dns_len + surplus.len()) as u16).to_be_bytes()
        );
        assert_eq!(
            &bytes.as_bytes()[24..26],
            &((UDP_HEADER_LEN + dns_len) as u16).to_be_bytes()
        );

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let dns = decoded.layer::<Dns>().unwrap();
        let udp_options = decoded.layer::<UdpOptions>().unwrap();

        assert_eq!(udp.length_value(), Some((UDP_HEADER_LEN + dns_len) as u16));
        assert_eq!(dns.id_value(), 0xbeef);
        assert_eq!(dns.questions().len(), 1);
        assert_eq!(dns.questions()[0].name(), "example.com.");
        assert_eq!(dns.questions()[0].question_type(), DNS_TYPE_A);
        assert!(decoded.layers::<Raw>().next().is_none());
        assert_eq!(udp_options.as_bytes(), &surplus);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn dhcp_decode_uses_udp_user_payload_and_preserves_udp_options() {
        let client_mac = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
        let dhcp = Dhcp::discover(client_mac)
            .transaction_id(0x3903_f326)
            .flags(0x8000)
            .host_name("agent");
        let dhcp_len = dhcp.encoded_len();
        let surplus = [UDP_OPTION_NOP, UDP_OPTION_EOL, 0];

        let bytes = (Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
            .id(0x2227)
            / Udp::dhcp_client()
            / dhcp
            / UdpOptions::from_bytes(surplus))
        .compile()
        .unwrap();

        assert_eq!(
            &bytes.as_bytes()[2..4],
            &((20 + UDP_HEADER_LEN + dhcp_len + surplus.len()) as u16).to_be_bytes()
        );
        assert_eq!(
            &bytes.as_bytes()[24..26],
            &((UDP_HEADER_LEN + dhcp_len) as u16).to_be_bytes()
        );

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let dhcp = decoded.layer::<Dhcp>().unwrap();
        let udp_options = decoded.layer::<UdpOptions>().unwrap();

        assert_eq!(udp.length_value(), Some((UDP_HEADER_LEN + dhcp_len) as u16));
        assert_eq!(dhcp.transaction_id_value(), 0x3903_f326);
        assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Discover));
        assert_eq!(dhcp.host_name_value(), Some("agent"));
        assert!(decoded.layers::<Raw>().next().is_none());
        assert_eq!(udp_options.as_bytes(), &surplus);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn udp_options_compile_outside_udp_length_for_raw_payload() {
        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2228)
            / Udp::new().sport(1234).dport(4321)
            / Raw::from_bytes([0xaa, 0xbb, 0xcc])
            / UdpOptions::from_bytes([UDP_OPTION_NOP, UDP_OPTION_EOL]))
        .compile()
        .unwrap();

        assert_eq!(
            &bytes.as_bytes()[2..4],
            &((20 + UDP_HEADER_LEN + 3 + 2) as u16).to_be_bytes()
        );
        assert_eq!(
            &bytes.as_bytes()[24..26],
            &((UDP_HEADER_LEN + 3) as u16).to_be_bytes()
        );

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        assert_eq!(
            decoded.layer::<UdpOptions>().unwrap().as_bytes(),
            &[UDP_OPTION_NOP, UDP_OPTION_EOL]
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn udp_length_shorter_than_ip_payload_preserves_surplus_tail() {
        let udp_payload = [0xaa, 0xbb, 0xcc];
        let surplus = [0xde, 0xad, 0xbe, 0xef];
        let mut datagram = Vec::new();
        datagram.extend_from_slice(&0x1111u16.to_be_bytes());
        datagram.extend_from_slice(&0x2222u16.to_be_bytes());
        datagram.extend_from_slice(&((UDP_HEADER_LEN + udp_payload.len()) as u16).to_be_bytes());
        datagram.extend_from_slice(&0u16.to_be_bytes());
        datagram.extend_from_slice(&udp_payload);
        datagram.extend_from_slice(&surplus);
        let bytes = (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Udp)
            / Raw::from_bytes(datagram))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let raw_layers = decoded.layers::<Raw>().collect::<Vec<_>>();
        let udp_options = decoded.layer::<UdpOptions>().unwrap();
        assert_eq!(decoded.layer::<Udp>().unwrap().length_value(), Some(11));
        assert_eq!(raw_layers.len(), 1);
        assert_eq!(raw_layers[0].as_bytes(), udp_payload);
        assert_eq!(udp_options.as_bytes(), surplus);
    }

    #[test]
    fn udp_length_longer_than_ip_payload_reports_structured_error() {
        let mut datagram = Vec::new();
        datagram.extend_from_slice(&0x1111u16.to_be_bytes());
        datagram.extend_from_slice(&0x2222u16.to_be_bytes());
        datagram.extend_from_slice(&16u16.to_be_bytes());
        datagram.extend_from_slice(&0u16.to_be_bytes());
        datagram.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        let bytes = (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Udp)
            / Raw::from_bytes(datagram))
        .compile()
        .unwrap();

        match Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()) {
            Err(crate::CrafterError::BufferTooShort {
                context,
                required,
                available,
            }) => {
                assert_eq!(context, "udp datagram");
                assert_eq!(required, 16);
                assert_eq!(available, 11);
            }
            other => panic!("expected structured UDP length overrun error, got {other:?}"),
        }
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
