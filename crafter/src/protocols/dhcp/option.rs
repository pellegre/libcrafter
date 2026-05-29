//! DHCP option types and the option-area codec.

use core::net::Ipv4Addr;
use core::str;

use crate::endian::read_u32_be;
use crate::error::{CrafterError, Result};

use super::constants::{
    DHCP_OPTION_BROADCAST_ADDRESS, DHCP_OPTION_CLIENT_IDENTIFIER, DHCP_OPTION_DOMAIN_NAME,
    DHCP_OPTION_DOMAIN_NAME_SERVER, DHCP_OPTION_END, DHCP_OPTION_HOST_NAME,
    DHCP_OPTION_IP_ADDRESS_LEASE_TIME, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_OVERLOAD,
    DHCP_OPTION_PAD, DHCP_OPTION_PARAMETER_REQUEST_LIST, DHCP_OPTION_REBINDING_TIME,
    DHCP_OPTION_RENEWAL_TIME, DHCP_OPTION_REQUESTED_IP_ADDRESS, DHCP_OPTION_ROUTER,
    DHCP_OPTION_SERVER_IDENTIFIER, DHCP_OPTION_SUBNET_MASK, DHCP_OVERLOAD_BOTH, DHCP_OVERLOAD_FILE,
    DHCP_OVERLOAD_SNAME,
};
use super::message::DhcpMessageType;
use super::registry::{option_name, option_status, DhcpOptionStatus};

/// Source area a DHCPv4 option segment was decoded from.
///
/// Source: RFC 2131 section 4.1 (BOOTP `sname`/`file` fields) and option 52
/// "Option Overload" (RFC 2132 section 9.3), which lets the `file` and `sname`
/// fixed fields carry additional options. The normal options area always
/// follows the magic cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhcpOptionArea {
    /// The normal options area following the magic cookie.
    Options,
    /// The overloaded BOOTP `file` (boot file name) field.
    File,
    /// The overloaded BOOTP `sname` (server host name) field.
    Sname,
}

impl DhcpOptionArea {
    /// Stable lowercase label for summaries and diagnostics.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Options => "options",
            Self::File => "file",
            Self::Sname => "sname",
        }
    }
}

/// Typed value of the DHCPv4 "Option Overload" option (option 52).
///
/// Source: RFC 2132 section 9.3. Option 52 is a single octet whose value tells a
/// parser to interpret the BOOTP `file` field, the `sname` field, or both as
/// additional option areas: value `1` overloads `file`, value `2` overloads
/// `sname`, and value `3` overloads both. Any other value is unspecified by the
/// registry, so it is preserved verbatim as [`OptionOverload::Unknown`] rather
/// than silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptionOverload {
    /// Value 1: the `file` field is overloaded with options.
    File,
    /// Value 2: the `sname` field is overloaded with options.
    Sname,
    /// Value 3: both the `file` and `sname` fields are overloaded with options.
    Both,
    /// An unspecified overload value, preserved verbatim.
    Unknown(u8),
}

impl OptionOverload {
    /// Classify a raw overload octet (RFC 2132 section 9.3).
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCP_OVERLOAD_FILE => Self::File,
            DHCP_OVERLOAD_SNAME => Self::Sname,
            DHCP_OVERLOAD_BOTH => Self::Both,
            other => Self::Unknown(other),
        }
    }

    /// Wire octet value for this overload.
    pub const fn code(self) -> u8 {
        match self {
            Self::File => DHCP_OVERLOAD_FILE,
            Self::Sname => DHCP_OVERLOAD_SNAME,
            Self::Both => DHCP_OVERLOAD_BOTH,
            Self::Unknown(code) => code,
        }
    }

    /// True when the `file` field is overloaded with options.
    pub const fn overloads_file(self) -> bool {
        matches!(self, Self::File | Self::Both)
    }

    /// True when the `sname` field is overloaded with options.
    pub const fn overloads_sname(self) -> bool {
        matches!(self, Self::Sname | Self::Both)
    }

    /// True when the given area is overloaded with options.
    pub const fn overloads(self, area: DhcpOptionArea) -> bool {
        match area {
            DhcpOptionArea::Options => true,
            DhcpOptionArea::File => self.overloads_file(),
            DhcpOptionArea::Sname => self.overloads_sname(),
        }
    }
}

/// A DHCPv4 option codepoint with source-backed registry awareness.
///
/// Source: IANA "BOOTP Vendor Extensions and DHCP Options" registry (updated
/// 2026-02-02). Every wire codepoint maps to a `DhcpOptionCode`; the variant
/// distinguishes assigned codes from ambiguous, private-use, removed, and
/// unassigned ranges so unknown payloads can always be preserved as raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhcpOptionCode {
    /// Pad option (code 0), a single octet with no length or payload.
    Pad,
    /// End option (code 255), a single octet marking the end of options.
    End,
    /// A registered codepoint assigned to a single option by an RFC.
    Assigned(u8),
    /// A registered codepoint with multiple historical or vendor meanings.
    Ambiguous(u8),
    /// A codepoint in the private-use range (224-254).
    PrivateUse(u8),
    /// A codepoint removed or left unassigned by the registry.
    RemovedOrUnassigned(u8),
}

impl DhcpOptionCode {
    /// Classify a wire codepoint using the source-backed registry.
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCP_OPTION_PAD => Self::Pad,
            DHCP_OPTION_END => Self::End,
            _ => match option_status(code) {
                DhcpOptionStatus::Assigned => Self::Assigned(code),
                DhcpOptionStatus::Ambiguous => Self::Ambiguous(code),
                DhcpOptionStatus::PrivateUse => Self::PrivateUse(code),
                DhcpOptionStatus::RemovedOrUnassigned | DhcpOptionStatus::Unknown => {
                    Self::RemovedOrUnassigned(code)
                }
            },
        }
    }

    /// Wire codepoint value.
    pub const fn code(self) -> u8 {
        match self {
            Self::Pad => DHCP_OPTION_PAD,
            Self::End => DHCP_OPTION_END,
            Self::Assigned(code)
            | Self::Ambiguous(code)
            | Self::PrivateUse(code)
            | Self::RemovedOrUnassigned(code) => code,
        }
    }

    /// Registered short name when the registry assigns one.
    pub fn name(self) -> Option<&'static str> {
        option_name(self.code())
    }

    /// True when the codepoint is a single-octet option (pad or end).
    pub const fn is_single_octet(self) -> bool {
        matches!(self, Self::Pad | Self::End)
    }
}

impl From<u8> for DhcpOptionCode {
    fn from(code: u8) -> Self {
        Self::from_code(code)
    }
}

impl From<DhcpOptionCode> for u8 {
    fn from(code: DhcpOptionCode) -> Self {
        code.code()
    }
}

/// A reusable DHCPv4 option wire-format value family.
///
/// Source: RFC 2132 option formats and the IANA registry length column. This
/// is the logical decoded view of an option payload. Families that the codec
/// does not yet decode into a richer structure are preserved verbatim as
/// [`DhcpOptionValue::Opaque`] so no bytes are lost.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DhcpOptionValue {
    /// No payload (length zero), used by flag-style options.
    Empty,
    /// A single unsigned byte.
    U8(u8),
    /// A 16-bit big-endian unsigned integer.
    U16(u16),
    /// A 32-bit big-endian unsigned integer.
    U32(u32),
    /// A single IPv4 address.
    Ipv4(Ipv4Addr),
    /// A list of IPv4 addresses.
    Ipv4List(Vec<Ipv4Addr>),
    /// Text-like bytes. Not guaranteed to be UTF-8; raw bytes are preserved.
    Text(Vec<u8>),
    /// A DHCP message type (option 53).
    MessageType(DhcpMessageType),
    /// An option overload value (option 52).
    OptionOverload(OptionOverload),
    /// A parameter request list (option 55): a sequence of option codes.
    ParameterRequestList(Vec<u8>),
    /// Opaque bytes preserved verbatim for options without a richer decode yet.
    Opaque(Vec<u8>),
}

impl DhcpOptionValue {
    /// View the value as raw payload bytes when it is byte-like.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Text(bytes) | Self::ParameterRequestList(bytes) | Self::Opaque(bytes) => {
                Some(bytes)
            }
            _ => None,
        }
    }

    /// Lossy UTF-8 view for text-like values, preserving the raw bytes.
    pub fn as_text_lossy(&self) -> Option<String> {
        match self {
            Self::Text(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
            _ => None,
        }
    }
}

/// A raw decoded DHCPv4 option segment with full inspection metadata.
///
/// A segment is one on-the-wire option instance before any RFC 3396 logical
/// concatenation. It records the source area, codepoint, declared length byte,
/// data bytes, and the byte offset within its area so callers can inspect or
/// re-encode the exact wire bytes even for unknown or malformed options.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhcpOptionSegment {
    /// Source area this segment was decoded from.
    pub area: DhcpOptionArea,
    /// Option codepoint with registry classification.
    pub code: DhcpOptionCode,
    /// Declared length byte. `None` for the single-octet pad/end options.
    pub declared_len: Option<u8>,
    /// Byte offset of the option code within its source area.
    pub offset: usize,
    /// Option payload bytes (after code and length), empty for pad/end.
    pub data: Vec<u8>,
}

impl DhcpOptionSegment {
    /// Wire codepoint of this segment.
    pub const fn code_value(&self) -> u8 {
        self.code.code()
    }

    /// True when this segment is a pad or end single-octet option.
    pub const fn is_single_octet(&self) -> bool {
        self.code.is_single_octet()
    }
}

/// Scan a DHCPv4 option area into raw segments with inspection metadata.
///
/// This is the low-level segment scanner described by the plan: it understands
/// pad and end single-octet options and surfaces declared lengths, offsets, and
/// data bytes without applying option overload or RFC 3396 concatenation. It is
/// purely structural and does not enforce option-stream policy such as
/// requiring an end marker; the logical decoder layered on top owns that. The
/// scanner records every option instance in declaration order, including pad
/// and end markers and any bytes that follow an end marker, so callers can
/// inspect and re-encode the exact wire bytes even for malformed streams.
/// Truncated code/length/data are reported as structured [`CrafterError`]
/// values rather than panics.
pub fn scan_dhcp_option_segments(
    area: DhcpOptionArea,
    bytes: &[u8],
) -> Result<Vec<DhcpOptionSegment>> {
    let mut segments = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        let code = bytes[offset];
        let code_offset = offset;
        offset += 1;

        match code {
            DHCP_OPTION_PAD => segments.push(DhcpOptionSegment {
                area,
                code: DhcpOptionCode::Pad,
                declared_len: None,
                offset: code_offset,
                data: Vec::new(),
            }),
            DHCP_OPTION_END => segments.push(DhcpOptionSegment {
                area,
                code: DhcpOptionCode::End,
                declared_len: None,
                offset: code_offset,
                data: Vec::new(),
            }),
            _ => {
                if offset >= bytes.len() {
                    return Err(CrafterError::buffer_too_short(
                        "dhcp option length",
                        offset + 1,
                        bytes.len(),
                    ));
                }
                let len = bytes[offset] as usize;
                offset += 1;
                let end = offset + len;
                if end > bytes.len() {
                    return Err(CrafterError::buffer_too_short(
                        "dhcp option data",
                        end,
                        bytes.len(),
                    ));
                }
                segments.push(DhcpOptionSegment {
                    area,
                    code: DhcpOptionCode::from_code(code),
                    declared_len: Some(len as u8),
                    offset: code_offset,
                    data: bytes[offset..end].to_vec(),
                });
                offset = end;
            }
        }
    }

    Ok(segments)
}

/// Parsed or constructible DHCP option.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DhcpOption {
    /// Padding byte.
    Pad,
    /// End marker.
    End,
    /// DHCP message type.
    MessageType(DhcpMessageType),
    /// Option overload (option 52): which fixed fields carry options.
    OptionOverload(OptionOverload),
    /// Subnet mask.
    SubnetMask(Ipv4Addr),
    /// Router list.
    Router(Vec<Ipv4Addr>),
    /// DNS server list.
    DomainNameServer(Vec<Ipv4Addr>),
    /// Host name.
    HostName(String),
    /// Domain name.
    DomainName(String),
    /// Broadcast address.
    BroadcastAddress(Ipv4Addr),
    /// Requested IP address.
    RequestedIpAddress(Ipv4Addr),
    /// Lease time in seconds.
    IpAddressLeaseTime(u32),
    /// Server identifier.
    ServerIdentifier(Ipv4Addr),
    /// Parameter request list.
    ParameterRequestList(Vec<u8>),
    /// Renewal time in seconds.
    RenewalTime(u32),
    /// Rebinding time in seconds.
    RebindingTime(u32),
    /// Client identifier bytes.
    ClientIdentifier(Vec<u8>),
    /// Unknown or caller-defined DHCP option.
    Generic {
        /// Raw DHCP option code.
        code: u8,
        /// Option payload bytes after code and length.
        data: Vec<u8>,
    },
}

impl DhcpOption {
    /// Create a DHCP message type option.
    pub const fn message_type(message_type: DhcpMessageType) -> Self {
        Self::MessageType(message_type)
    }

    /// Create an option overload option (option 52).
    pub const fn option_overload(overload: OptionOverload) -> Self {
        Self::OptionOverload(overload)
    }

    /// Create a subnet mask option.
    pub const fn subnet_mask(mask: Ipv4Addr) -> Self {
        Self::SubnetMask(mask)
    }

    /// Create a router list option.
    pub fn router(routers: impl Into<Vec<Ipv4Addr>>) -> Self {
        Self::Router(routers.into())
    }

    /// Create a DNS server list option.
    pub fn domain_name_server(servers: impl Into<Vec<Ipv4Addr>>) -> Self {
        Self::DomainNameServer(servers.into())
    }

    /// Create a host name option.
    pub fn host_name(host_name: impl Into<String>) -> Self {
        Self::HostName(host_name.into())
    }

    /// Create a domain name option.
    pub fn domain_name(domain_name: impl Into<String>) -> Self {
        Self::DomainName(domain_name.into())
    }

    /// Create a requested IP address option.
    pub const fn requested_ip_address(address: Ipv4Addr) -> Self {
        Self::RequestedIpAddress(address)
    }

    /// Create a lease time option.
    pub const fn lease_time(seconds: u32) -> Self {
        Self::IpAddressLeaseTime(seconds)
    }

    /// Create a server identifier option.
    pub const fn server_identifier(address: Ipv4Addr) -> Self {
        Self::ServerIdentifier(address)
    }

    /// Create a parameter request list option.
    pub fn parameter_request_list(requests: impl Into<Vec<u8>>) -> Self {
        Self::ParameterRequestList(requests.into())
    }

    /// Create a client identifier option.
    pub fn client_identifier(identifier: impl Into<Vec<u8>>) -> Self {
        Self::ClientIdentifier(identifier.into())
    }

    /// Create a caller-defined option.
    pub fn generic(code: u8, data: impl Into<Vec<u8>>) -> Self {
        Self::Generic {
            code,
            data: data.into(),
        }
    }

    /// Raw DHCP option code.
    pub const fn code(&self) -> u8 {
        match self {
            Self::Pad => DHCP_OPTION_PAD,
            Self::End => DHCP_OPTION_END,
            Self::MessageType(_) => DHCP_OPTION_MESSAGE_TYPE,
            Self::OptionOverload(_) => DHCP_OPTION_OVERLOAD,
            Self::SubnetMask(_) => DHCP_OPTION_SUBNET_MASK,
            Self::Router(_) => DHCP_OPTION_ROUTER,
            Self::DomainNameServer(_) => DHCP_OPTION_DOMAIN_NAME_SERVER,
            Self::HostName(_) => DHCP_OPTION_HOST_NAME,
            Self::DomainName(_) => DHCP_OPTION_DOMAIN_NAME,
            Self::BroadcastAddress(_) => DHCP_OPTION_BROADCAST_ADDRESS,
            Self::RequestedIpAddress(_) => DHCP_OPTION_REQUESTED_IP_ADDRESS,
            Self::IpAddressLeaseTime(_) => DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
            Self::ServerIdentifier(_) => DHCP_OPTION_SERVER_IDENTIFIER,
            Self::ParameterRequestList(_) => DHCP_OPTION_PARAMETER_REQUEST_LIST,
            Self::RenewalTime(_) => DHCP_OPTION_RENEWAL_TIME,
            Self::RebindingTime(_) => DHCP_OPTION_REBINDING_TIME,
            Self::ClientIdentifier(_) => DHCP_OPTION_CLIENT_IDENTIFIER,
            Self::Generic { code, .. } => *code,
        }
    }

    /// Registry-classified codepoint for this option.
    pub fn option_code(&self) -> DhcpOptionCode {
        DhcpOptionCode::from_code(self.code())
    }

    /// Source-backed registry name for this option, when assigned.
    pub fn registry_name(&self) -> Option<&'static str> {
        option_name(self.code())
    }

    /// Logical wire-format value family for this option.
    ///
    /// Maps the typed enum onto the reusable [`DhcpOptionValue`] families so
    /// callers can reason about option payloads uniformly. Pad and end have no
    /// value family and return `None`.
    pub fn logical_value(&self) -> Option<DhcpOptionValue> {
        let value = match self {
            Self::Pad | Self::End => return None,
            Self::MessageType(message_type) => DhcpOptionValue::MessageType(*message_type),
            Self::OptionOverload(overload) => DhcpOptionValue::OptionOverload(*overload),
            Self::SubnetMask(address)
            | Self::BroadcastAddress(address)
            | Self::RequestedIpAddress(address)
            | Self::ServerIdentifier(address) => DhcpOptionValue::Ipv4(*address),
            Self::Router(addresses) | Self::DomainNameServer(addresses) => {
                DhcpOptionValue::Ipv4List(addresses.clone())
            }
            Self::HostName(text) | Self::DomainName(text) => {
                DhcpOptionValue::Text(text.as_bytes().to_vec())
            }
            Self::IpAddressLeaseTime(seconds)
            | Self::RenewalTime(seconds)
            | Self::RebindingTime(seconds) => DhcpOptionValue::U32(*seconds),
            Self::ParameterRequestList(requests) => {
                DhcpOptionValue::ParameterRequestList(requests.clone())
            }
            Self::ClientIdentifier(data) | Self::Generic { data, .. } => {
                if data.is_empty() {
                    DhcpOptionValue::Empty
                } else {
                    DhcpOptionValue::Opaque(data.clone())
                }
            }
        };
        Some(value)
    }

    /// Encoded option length in bytes.
    ///
    /// Accounts for RFC 3396 splitting: a logical payload longer than 255 bytes
    /// is emitted as several same-code segments, each carrying its own code and
    /// length byte, so the encoded length includes per-segment overhead.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Pad | Self::End => 1,
            Self::MessageType(_) | Self::OptionOverload(_) => 3,
            Self::SubnetMask(_)
            | Self::BroadcastAddress(_)
            | Self::RequestedIpAddress(_)
            | Self::ServerIdentifier(_) => 6,
            Self::Router(addresses) | Self::DomainNameServer(addresses) => {
                split_option_encoded_len(addresses.len() * 4)
            }
            Self::HostName(name) | Self::DomainName(name) => split_option_encoded_len(name.len()),
            Self::IpAddressLeaseTime(_) | Self::RenewalTime(_) | Self::RebindingTime(_) => 6,
            Self::ParameterRequestList(requests)
            | Self::ClientIdentifier(requests)
            | Self::Generic { data: requests, .. } => split_option_encoded_len(requests.len()),
        }
    }

    /// Encode this option to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut bytes)?;
        Ok(bytes)
    }

    /// Logical option payload bytes, without the option code or length byte(s).
    ///
    /// This is the full reassembled value (RFC 3396): for a long option that the
    /// codec concatenated across several wire segments, this returns the joined
    /// payload. Pad and end options have no payload and return an empty vector.
    pub fn payload(&self) -> Result<Vec<u8>> {
        self.payload_bytes()
    }

    /// Decode all DHCP options from a byte slice.
    pub fn decode_all(bytes: &[u8]) -> Result<Vec<Self>> {
        decode_dhcp_options(bytes)
    }

    pub(super) fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Pad => {
                out.push(DHCP_OPTION_PAD);
                Ok(())
            }
            Self::End => {
                out.push(DHCP_OPTION_END);
                Ok(())
            }
            _ => {
                if matches!(self.code(), DHCP_OPTION_PAD | DHCP_OPTION_END) {
                    return Err(CrafterError::invalid_field_value(
                        "dhcp.option.code",
                        "pad and end options do not carry a length byte",
                    ));
                }
                let data = self.payload_bytes()?;
                // RFC 3396: the option length field is a single octet, so a
                // logical value longer than 255 bytes is encoded as repeated
                // instances of the same option code, split into <=255-byte
                // segments in order. Empty payloads still emit one segment.
                encode_split_option(self.code(), &data, out);
                Ok(())
            }
        }
    }

    fn payload_bytes(&self) -> Result<Vec<u8>> {
        let bytes = match self {
            Self::Pad | Self::End => Vec::new(),
            Self::MessageType(message_type) => vec![message_type.code()],
            Self::OptionOverload(overload) => vec![overload.code()],
            Self::SubnetMask(address)
            | Self::BroadcastAddress(address)
            | Self::RequestedIpAddress(address)
            | Self::ServerIdentifier(address) => address.octets().to_vec(),
            Self::Router(addresses) | Self::DomainNameServer(addresses) => {
                encode_ipv4_list(addresses)
            }
            Self::HostName(host_name) | Self::DomainName(host_name) => {
                host_name.as_bytes().to_vec()
            }
            Self::IpAddressLeaseTime(seconds)
            | Self::RenewalTime(seconds)
            | Self::RebindingTime(seconds) => seconds.to_be_bytes().to_vec(),
            Self::ParameterRequestList(requests) | Self::ClientIdentifier(requests) => {
                requests.clone()
            }
            Self::Generic { code, data } => {
                if matches!(*code, DHCP_OPTION_PAD | DHCP_OPTION_END) {
                    return Err(CrafterError::invalid_field_value(
                        "dhcp.option.code",
                        "generic option code cannot be pad or end",
                    ));
                }
                data.clone()
            }
        };
        Ok(bytes)
    }
}

pub(super) fn decode_dhcp_options(bytes: &[u8]) -> Result<Vec<DhcpOption>> {
    decode_segments_to_options(&scan_dhcp_option_segments(DhcpOptionArea::Options, bytes)?)
}

/// Find the option-overload value (option 52) carried in a normal-area option
/// list, when present (RFC 2132 section 9.3).
pub(super) fn find_option_overload(options: &[DhcpOption]) -> Option<OptionOverload> {
    options.iter().find_map(|option| match option {
        DhcpOption::OptionOverload(overload) => Some(*overload),
        _ => None,
    })
}

/// Decode the options carried in an overloaded `file` or `sname` field.
///
/// Source: RFC 2131 section 4.1. An overloaded field begins at its first octet,
/// terminates with an `end` option, and is followed by padding to fill the
/// remainder of the fixed-width field. This decoder applies that layout: it
/// scans typed options until the `end` marker, after which only padding (zero
/// bytes / pad options) may appear. A missing end marker or non-padding data
/// after the end marker is reported as a structured error with a field name
/// scoped to the source area; truncation never panics.
pub(super) fn decode_overload_area_options(
    area: DhcpOptionArea,
    bytes: &[u8],
) -> Result<Vec<DhcpOption>> {
    let segments = scan_dhcp_option_segments(area, bytes)?;
    let mut order = SegmentOrder::new();
    let mut saw_end = false;

    for segment in &segments {
        match segment.code {
            DhcpOptionCode::Pad => {
                // Pad both before and after the end marker is allowed; the
                // remainder of the fixed-width field is zero-padded.
                if !saw_end {
                    order.push_pad();
                }
            }
            DhcpOptionCode::End if !saw_end => {
                order.push_end();
                saw_end = true;
            }
            _ => {
                if saw_end {
                    return Err(CrafterError::invalid_field_value(
                        overload_end_field(area),
                        "non-padding data follows the DHCP end option in an overloaded field",
                    ));
                }
                order.push_content(segment.code_value(), &segment.data);
            }
        }
    }

    // Decode (and RFC 3396 reassemble) the collected options first so a per-option
    // structural error surfaces ahead of the missing-end-marker check, matching the
    // ordering callers and the malformed corpus expect.
    let options = order.into_options()?;

    if !saw_end {
        return Err(CrafterError::invalid_field_value(
            overload_field(area),
            "overloaded DHCP field is missing an end marker",
        ));
    }

    Ok(options)
}

const fn overload_field(area: DhcpOptionArea) -> &'static str {
    match area {
        DhcpOptionArea::Options => "dhcp.options",
        DhcpOptionArea::File => "dhcp.file.options",
        DhcpOptionArea::Sname => "dhcp.sname.options",
    }
}

const fn overload_end_field(area: DhcpOptionArea) -> &'static str {
    match area {
        DhcpOptionArea::Options => "dhcp.option.end",
        DhcpOptionArea::File => "dhcp.file.option.end",
        DhcpOptionArea::Sname => "dhcp.sname.option.end",
    }
}

/// Encode an option list into a fixed-width overloaded field area.
///
/// Source: RFC 2131 section 4.1. The options are encoded starting at the first
/// octet, an `end` marker is appended when the caller did not supply one, and
/// the field is zero-padded to its fixed width. Returns an error when the
/// encoded options do not fit within the field.
pub(super) fn encode_overload_area_options(
    field: &'static str,
    options: &[DhcpOption],
    width: usize,
) -> Result<Vec<u8>> {
    let mut bytes = encode_dhcp_options(options)?;
    if bytes.len() > width {
        return Err(CrafterError::invalid_field_value(
            field,
            "overloaded DHCP field options exceed the fixed field width",
        ));
    }
    bytes.resize(width, 0);
    Ok(bytes)
}

/// Decode raw option segments into logical typed options.
///
/// This is the logical decoder layered on top of the raw segment scanner. It
/// enforces the structural policy for the normal options area: options must be
/// terminated by an end marker, and only padding may follow it. RFC 3396 long
/// option concatenation is applied here: repeated instances of the same option
/// code are reassembled, in declaration order, into one logical option whose
/// payload is the concatenation of every instance's data. The raw per-instance
/// segments stay inspectable through [`scan_dhcp_option_segments`].
fn decode_segments_to_options(segments: &[DhcpOptionSegment]) -> Result<Vec<DhcpOption>> {
    let mut order = SegmentOrder::new();
    let mut saw_end = false;

    for segment in segments {
        match segment.code {
            DhcpOptionCode::Pad => order.push_pad(),
            DhcpOptionCode::End if !saw_end => {
                order.push_end();
                saw_end = true;
            }
            _ => {
                if saw_end {
                    return Err(CrafterError::invalid_field_value(
                        "dhcp.option.end",
                        "non-padding data follows DHCP end option",
                    ));
                }
                order.push_content(segment.code_value(), &segment.data);
            }
        }
    }

    // Decode (and RFC 3396 reassemble) the collected options first so a per-option
    // structural error surfaces ahead of the missing-end-marker check, matching the
    // prior decode ordering and the malformed corpus expectations.
    let options = order.into_options()?;

    if !saw_end {
        return Err(CrafterError::invalid_field_value(
            "dhcp.options",
            "DHCP options are missing an end marker",
        ));
    }

    Ok(options)
}

/// Ordered accumulator that applies RFC 3396 concatenation while preserving the
/// declaration order of pad, end, and content options within one area.
///
/// Content segments sharing an option code are reassembled into a single logical
/// option positioned where the first portion appeared (RFC 3396 section 7), with
/// later portions' data appended in order. Pad and end markers are never
/// concatenated and keep their relative position.
struct SegmentOrder {
    slots: Vec<Slot>,
    content_index: std::collections::HashMap<u8, usize>,
}

enum Slot {
    Pad,
    End,
    Content { code: u8, data: Vec<u8> },
}

impl SegmentOrder {
    fn new() -> Self {
        Self {
            slots: Vec::new(),
            content_index: std::collections::HashMap::new(),
        }
    }

    fn push_pad(&mut self) {
        self.slots.push(Slot::Pad);
    }

    fn push_end(&mut self) {
        self.slots.push(Slot::End);
    }

    fn push_content(&mut self, code: u8, data: &[u8]) {
        if let Some(&index) = self.content_index.get(&code) {
            if let Slot::Content { data: existing, .. } = &mut self.slots[index] {
                existing.extend_from_slice(data);
                return;
            }
        }
        let index = self.slots.len();
        self.content_index.insert(code, index);
        self.slots.push(Slot::Content {
            code,
            data: data.to_vec(),
        });
    }

    fn into_options(self) -> Result<Vec<DhcpOption>> {
        let mut options = Vec::with_capacity(self.slots.len());
        for slot in self.slots {
            match slot {
                Slot::Pad => options.push(DhcpOption::Pad),
                Slot::End => options.push(DhcpOption::End),
                Slot::Content { code, data } => options.push(decode_dhcp_option(code, &data)?),
            }
        }
        Ok(options)
    }
}

pub(super) fn decode_dhcp_option(code: u8, data: &[u8]) -> Result<DhcpOption> {
    match code {
        DHCP_OPTION_MESSAGE_TYPE => {
            validate_fixed_len("dhcp.option.message_type", data.len(), 1)?;
            Ok(DhcpOption::MessageType(DhcpMessageType::from_code(data[0])))
        }
        DHCP_OPTION_OVERLOAD => {
            validate_fixed_len("dhcp.option.overload", data.len(), 1)?;
            let overload = OptionOverload::from_code(data[0]);
            Ok(DhcpOption::OptionOverload(overload))
        }
        DHCP_OPTION_SUBNET_MASK => Ok(DhcpOption::SubnetMask(decode_ipv4_option(
            "dhcp.option.subnet_mask",
            data,
        )?)),
        DHCP_OPTION_ROUTER => Ok(DhcpOption::Router(decode_ipv4_list(
            "dhcp.option.router",
            data,
        )?)),
        DHCP_OPTION_DOMAIN_NAME_SERVER => Ok(DhcpOption::DomainNameServer(decode_ipv4_list(
            "dhcp.option.domain_name_server",
            data,
        )?)),
        DHCP_OPTION_HOST_NAME => Ok(DhcpOption::HostName(decode_text_option(
            "dhcp.option.host_name",
            data,
        )?)),
        DHCP_OPTION_DOMAIN_NAME => Ok(DhcpOption::DomainName(decode_text_option(
            "dhcp.option.domain_name",
            data,
        )?)),
        DHCP_OPTION_BROADCAST_ADDRESS => Ok(DhcpOption::BroadcastAddress(decode_ipv4_option(
            "dhcp.option.broadcast_address",
            data,
        )?)),
        DHCP_OPTION_REQUESTED_IP_ADDRESS => Ok(DhcpOption::RequestedIpAddress(decode_ipv4_option(
            "dhcp.option.requested_ip_address",
            data,
        )?)),
        DHCP_OPTION_IP_ADDRESS_LEASE_TIME => Ok(DhcpOption::IpAddressLeaseTime(decode_u32_option(
            "dhcp.option.lease_time",
            data,
        )?)),
        DHCP_OPTION_SERVER_IDENTIFIER => Ok(DhcpOption::ServerIdentifier(decode_ipv4_option(
            "dhcp.option.server_identifier",
            data,
        )?)),
        DHCP_OPTION_PARAMETER_REQUEST_LIST => Ok(DhcpOption::ParameterRequestList(data.to_vec())),
        DHCP_OPTION_RENEWAL_TIME => Ok(DhcpOption::RenewalTime(decode_u32_option(
            "dhcp.option.renewal_time",
            data,
        )?)),
        DHCP_OPTION_REBINDING_TIME => Ok(DhcpOption::RebindingTime(decode_u32_option(
            "dhcp.option.rebinding_time",
            data,
        )?)),
        DHCP_OPTION_CLIENT_IDENTIFIER => Ok(DhcpOption::ClientIdentifier(data.to_vec())),
        _ => Ok(DhcpOption::Generic {
            code,
            data: data.to_vec(),
        }),
    }
}

pub(super) fn encode_dhcp_options(options: &[DhcpOption]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(encoded_options_len_lossy(options));
    let mut saw_end = false;

    for option in options {
        if saw_end && !matches!(option, DhcpOption::Pad) {
            return Err(CrafterError::invalid_field_value(
                "dhcp.options",
                "only padding may follow the DHCP end option",
            ));
        }
        if matches!(option, DhcpOption::End) {
            saw_end = true;
        }
        option.encode_into(&mut out)?;
    }

    if !saw_end {
        out.push(DHCP_OPTION_END);
    }
    Ok(out)
}

pub(super) fn encoded_options_len_lossy(options: &[DhcpOption]) -> usize {
    let len = options.iter().map(DhcpOption::encoded_len).sum::<usize>();
    if options
        .iter()
        .any(|option| matches!(option, DhcpOption::End))
    {
        len
    } else {
        len + 1
    }
}

fn validate_fixed_len(field: &'static str, actual: usize, expected: usize) -> Result<()> {
    if actual != expected {
        return Err(CrafterError::invalid_field_value(
            field,
            "DHCP option has an invalid fixed length",
        ));
    }
    Ok(())
}

fn decode_text_option(field: &'static str, data: &[u8]) -> Result<String> {
    str::from_utf8(data)
        .map(str::to_string)
        .map_err(|_| CrafterError::invalid_field_value(field, "option text is not valid UTF-8"))
}

fn decode_ipv4_option(field: &'static str, data: &[u8]) -> Result<Ipv4Addr> {
    validate_fixed_len(field, data.len(), 4)?;
    Ok(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
}

fn decode_ipv4_list(field: &'static str, data: &[u8]) -> Result<Vec<Ipv4Addr>> {
    if data.len() % 4 != 0 {
        return Err(CrafterError::invalid_field_value(
            field,
            "IPv4 address list option length must be a multiple of four",
        ));
    }
    Ok(data
        .chunks_exact(4)
        .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
        .collect())
}

fn decode_u32_option(field: &'static str, data: &[u8]) -> Result<u32> {
    validate_fixed_len(field, data.len(), 4)?;
    read_u32_be(data)
}

fn encode_ipv4_list(addresses: &[Ipv4Addr]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(addresses.len() * 4);
    for address in addresses {
        bytes.extend_from_slice(&address.octets());
    }
    bytes
}

/// Maximum payload an option length byte can describe (RFC 2132 section 2).
pub(super) const DHCP_MAX_OPTION_DATA_LEN: usize = u8::MAX as usize;

/// Encode a logical option payload as one or more on-the-wire segments.
///
/// RFC 3396: because the DHCP option length is a single octet, a logical value
/// longer than 255 octets is split into repeated instances of the same option
/// code. The split portions are emitted in sequential order, each at most 255
/// bytes; the first portion comes first. Payloads of 255 bytes or fewer emit a
/// single segment, and an empty payload emits one zero-length segment.
pub(super) fn encode_split_option(code: u8, data: &[u8], out: &mut Vec<u8>) {
    if data.is_empty() {
        out.push(code);
        out.push(0);
        return;
    }
    for chunk in data.chunks(DHCP_MAX_OPTION_DATA_LEN) {
        out.push(code);
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
}

/// Encoded byte length of a payload after RFC 3396 splitting, including the
/// per-segment code and length overhead.
pub(super) fn split_option_encoded_len(data_len: usize) -> usize {
    if data_len == 0 {
        return 2;
    }
    let segments = data_len.div_ceil(DHCP_MAX_OPTION_DATA_LEN);
    segments * 2 + data_len
}

#[cfg(test)]
mod dhcp_options {
    use super::super::{
        scan_dhcp_option_segments, Dhcp, DhcpMessageType, DhcpOption, DhcpOptionArea,
        DhcpOptionCode, DhcpOptionSegment, DhcpOptionStatus, DhcpOptionValue,
    };
    use crate::error::CrafterError;
    use core::net::Ipv4Addr;

    const OFFER_OPTIONS: &str = fixture_str!("bytes/dhcp-offer-options.hex");

    #[test]
    fn option_fixture_decodes_common_offer_values() {
        let options = DhcpOption::decode_all(&hex_fixture(OFFER_OPTIONS)).unwrap();
        let dhcp = Dhcp::new().options(options);

        assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Offer));
        assert_eq!(
            dhcp.server_identifier_value(),
            Some(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(
            dhcp.subnet_mask_value(),
            Some(Ipv4Addr::new(255, 255, 255, 0))
        );
        assert_eq!(dhcp.routers(), vec![Ipv4Addr::new(192, 0, 2, 1)]);
        assert_eq!(
            dhcp.domain_name_servers(),
            vec![
                Ipv4Addr::new(192, 0, 2, 53),
                Ipv4Addr::new(198, 51, 100, 53)
            ]
        );
        assert_eq!(dhcp.lease_time_value(), Some(3600));
    }

    #[test]
    fn typed_options_roundtrip_and_preserve_unknown_options() {
        let options = vec![
            DhcpOption::Pad,
            DhcpOption::message_type(DhcpMessageType::Ack),
            DhcpOption::host_name("agent-host"),
            DhcpOption::generic(224, [0xde, 0xad, 0xbe, 0xef]),
            DhcpOption::End,
            DhcpOption::Pad,
        ];

        let encoded = Dhcp::new()
            .options(options.clone())
            .encoded_options()
            .unwrap();
        let decoded = DhcpOption::decode_all(&encoded).unwrap();

        assert_eq!(decoded, options);
    }

    #[test]
    fn builder_appends_end_marker_deterministically() {
        let encoded = Dhcp::new()
            .message_type(DhcpMessageType::Discover)
            .encoded_options()
            .unwrap();

        assert_eq!(encoded.last(), Some(&super::DHCP_OPTION_END));
    }

    #[test]
    fn dhcp_offer_options_decode_through_new_model() {
        let bytes = hex_fixture(OFFER_OPTIONS);

        // The raw segment scanner surfaces each on-the-wire option instance
        // with source-area, codepoint, declared length, offset, and bytes.
        let segments = scan_dhcp_option_segments(DhcpOptionArea::Options, &bytes).unwrap();

        let codes: Vec<u8> = segments.iter().map(|s| s.code_value()).collect();
        assert_eq!(codes, vec![53, 54, 1, 3, 6, 51, 255]);

        // Every segment reports the area it came from.
        assert!(segments.iter().all(|s| s.area == DhcpOptionArea::Options));

        // Declared length and offsets are inspectable for non-single-octet
        // options; pad/end carry no declared length.
        let message_type = &segments[0];
        assert_eq!(message_type.code, DhcpOptionCode::Assigned(53));
        assert_eq!(message_type.declared_len, Some(1));
        assert_eq!(message_type.offset, 0);
        assert_eq!(message_type.data, vec![DhcpMessageType::Offer.code()]);

        let server_id = &segments[1];
        assert_eq!(server_id.declared_len, Some(4));
        assert_eq!(server_id.offset, 3);
        assert_eq!(server_id.data, vec![192, 0, 2, 1]);

        let end = segments.last().unwrap();
        assert_eq!(end.code, DhcpOptionCode::End);
        assert!(end.is_single_octet());
        assert_eq!(end.declared_len, None);

        // The logical typed decode bridges onto reusable value families.
        let options = DhcpOption::decode_all(&bytes).unwrap();
        let logical: Vec<Option<DhcpOptionValue>> =
            options.iter().map(DhcpOption::logical_value).collect();
        assert_eq!(
            logical[0],
            Some(DhcpOptionValue::MessageType(DhcpMessageType::Offer))
        );
        assert_eq!(
            logical[2],
            Some(DhcpOptionValue::Ipv4(Ipv4Addr::new(255, 255, 255, 0)))
        );
        assert_eq!(
            logical[4],
            Some(DhcpOptionValue::Ipv4List(vec![
                Ipv4Addr::new(192, 0, 2, 53),
                Ipv4Addr::new(198, 51, 100, 53),
            ]))
        );
        assert_eq!(logical[5], Some(DhcpOptionValue::U32(3_600)));
        // The end marker has no value family.
        assert_eq!(options.last().unwrap().logical_value(), None);

        // Registry names are source-backed for assigned codes.
        assert_eq!(options[0].registry_name(), Some("DHCP Msg Type"));
        assert_eq!(options[1].registry_name(), Some("DHCP Server Id"));
    }

    #[test]
    fn dhcp_option_model_preserves_unknown_private_bytes() {
        // Private-use code 224 and an unassigned/removed code 84 must both be
        // preserved as raw bytes with full segment metadata and classified by
        // the source-backed registry.
        let private_payload = [0xde, 0xad, 0xbe, 0xef];
        let removed_payload = [0x01, 0x02];

        let options = vec![
            DhcpOption::message_type(DhcpMessageType::Ack),
            DhcpOption::generic(224, private_payload),
            DhcpOption::generic(84, removed_payload),
            DhcpOption::End,
        ];

        let encoded = Dhcp::new()
            .options(options.clone())
            .encoded_options()
            .unwrap();

        // Round-trip through the typed decoder preserves the unknown bytes.
        let decoded = DhcpOption::decode_all(&encoded).unwrap();
        assert_eq!(decoded, options);

        // Codepoint classification is source-backed.
        assert_eq!(decoded[1].option_code(), DhcpOptionCode::PrivateUse(224));
        assert_eq!(
            decoded[2].option_code(),
            DhcpOptionCode::RemovedOrUnassigned(84)
        );
        assert_eq!(decoded[1].registry_name(), None);
        assert_eq!(decoded[2].registry_name(), Some("REMOVED/Unassigned"));

        // The logical value preserves opaque bytes verbatim.
        assert_eq!(
            decoded[1].logical_value(),
            Some(DhcpOptionValue::Opaque(private_payload.to_vec()))
        );
        assert_eq!(
            decoded[1]
                .logical_value()
                .and_then(|v| v.as_bytes().map(<[u8]>::to_vec)),
            Some(private_payload.to_vec())
        );

        // The raw segment scanner exposes declared length, offset, and bytes
        // for the unknown/private options without losing data.
        let segments = scan_dhcp_option_segments(DhcpOptionArea::Options, &encoded).unwrap();
        let private = segments
            .iter()
            .find(|s| s.code_value() == 224)
            .expect("private-use segment present");
        assert_eq!(private.code, DhcpOptionCode::PrivateUse(224));
        assert_eq!(private.declared_len, Some(private_payload.len() as u8));
        assert_eq!(private.data, private_payload);

        let removed = segments
            .iter()
            .find(|s| s.code_value() == 84)
            .expect("removed segment present");
        assert_eq!(removed.code, DhcpOptionCode::RemovedOrUnassigned(84));
        assert_eq!(removed.data, removed_payload);

        // Codepoint status is classified directly as well.
        assert_eq!(
            DhcpOptionCode::from_code(224),
            DhcpOptionCode::PrivateUse(224)
        );
        assert_eq!(
            super::option_status(84),
            DhcpOptionStatus::RemovedOrUnassigned
        );
    }

    #[test]
    fn dhcp_option_codec_preserves_raw_segments() {
        // A mixed stream with leading pad, several typed options, an unknown
        // private-use option, an end marker, and a trailing pad. The logical
        // decoder routes through the raw scanner, so the segment view and the
        // typed view must agree, and an exact byte round-trip must hold.
        let options = vec![
            DhcpOption::Pad,
            DhcpOption::message_type(DhcpMessageType::Ack),
            DhcpOption::subnet_mask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::generic(224, [0xde, 0xad, 0xbe, 0xef]),
            DhcpOption::End,
            DhcpOption::Pad,
        ];

        let encoded = Dhcp::new()
            .options(options.clone())
            .encoded_options()
            .unwrap();

        // Raw scanner records every on-the-wire instance in order, including
        // the leading and trailing pad and the end marker.
        let segments = scan_dhcp_option_segments(DhcpOptionArea::Options, &encoded).unwrap();
        let codes: Vec<u8> = segments.iter().map(DhcpOptionSegment::code_value).collect();
        assert_eq!(codes, vec![0, 53, 1, 224, 255, 0]);
        assert!(segments.iter().all(|s| s.area == DhcpOptionArea::Options));

        // The unknown private-use option keeps its declared length and bytes.
        let private = &segments[3];
        assert_eq!(private.code, DhcpOptionCode::PrivateUse(224));
        assert_eq!(private.declared_len, Some(4));
        assert_eq!(private.data, vec![0xde, 0xad, 0xbe, 0xef]);

        // The end marker is a single-octet option with no declared length, and
        // a pad segment may legally follow it.
        let end = &segments[4];
        assert_eq!(end.code, DhcpOptionCode::End);
        assert!(end.is_single_octet());
        assert_eq!(end.declared_len, None);
        assert_eq!(segments[5].code, DhcpOptionCode::Pad);

        // The logical decode matches the original options exactly, and a second
        // encode reproduces the original bytes (exact round-trip).
        let decoded = DhcpOption::decode_all(&encoded).unwrap();
        assert_eq!(decoded, options);
        let re_encoded = Dhcp::new().options(decoded).encoded_options().unwrap();
        assert_eq!(re_encoded, encoded);
    }

    #[test]
    fn dhcp_option_codec_rejects_non_padding_after_end() {
        // An end marker immediately followed by non-padding data is a structured
        // decode error, not a panic or a silently truncated decode.
        let bytes = [
            super::DHCP_OPTION_END,
            super::DHCP_OPTION_MESSAGE_TYPE,
            1,
            1,
        ];

        let error = DhcpOption::decode_all(&bytes).unwrap_err();
        assert!(matches!(
            error,
            CrafterError::InvalidFieldValue { field, .. } if field == "dhcp.option.end"
        ));

        // The raw scanner itself stays permissive and records the trailing
        // option as a segment so callers can still inspect the malformed bytes.
        let segments = scan_dhcp_option_segments(DhcpOptionArea::Options, &bytes).unwrap();
        let codes: Vec<u8> = segments.iter().map(DhcpOptionSegment::code_value).collect();
        assert_eq!(codes, vec![255, 53]);
    }

    #[test]
    fn dhcp_option_codec_rejects_missing_end_marker() {
        // A well-formed option with no terminating end marker is rejected by the
        // logical decoder with a stable field name.
        let bytes = [super::DHCP_OPTION_MESSAGE_TYPE, 1, 1];

        let error = DhcpOption::decode_all(&bytes).unwrap_err();
        assert!(matches!(
            error,
            CrafterError::InvalidFieldValue { field, .. } if field == "dhcp.options"
        ));
    }

    #[test]
    fn dhcp_option_codec_reports_truncated_segments() {
        // Truncated length and truncated data surface as buffer-too-short
        // errors from the raw scanner rather than panicking.
        let truncated_length = [super::DHCP_OPTION_MESSAGE_TYPE];
        let truncated_data = [super::DHCP_OPTION_MESSAGE_TYPE, 4, 0x01];

        for bytes in [truncated_length.as_slice(), truncated_data.as_slice()] {
            let error = scan_dhcp_option_segments(DhcpOptionArea::Options, bytes).unwrap_err();
            assert!(matches!(error, CrafterError::BufferTooShort { .. }));
            // The logical decoder propagates the same structured error.
            assert!(matches!(
                DhcpOption::decode_all(bytes),
                Err(CrafterError::BufferTooShort { .. })
            ));
        }
    }

    #[test]
    fn dhcp_option_codec_preserves_pad_and_unknown_options() {
        // Padding before and after content, plus an unknown removed/unassigned
        // codepoint, round-trip exactly and stay classified by the registry.
        let options = vec![
            DhcpOption::Pad,
            DhcpOption::Pad,
            DhcpOption::message_type(DhcpMessageType::Discover),
            DhcpOption::generic(84, [0x01, 0x02]),
            DhcpOption::End,
        ];

        let encoded = Dhcp::new()
            .options(options.clone())
            .encoded_options()
            .unwrap();
        let decoded = DhcpOption::decode_all(&encoded).unwrap();
        assert_eq!(decoded, options);

        assert_eq!(
            decoded[3].option_code(),
            DhcpOptionCode::RemovedOrUnassigned(84)
        );
        assert_eq!(
            decoded[3].logical_value(),
            Some(DhcpOptionValue::Opaque(vec![0x01, 0x02]))
        );
    }

    fn hex_fixture(input: &str) -> Vec<u8> {
        input
            .split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect()
    }
}

#[cfg(test)]
mod dhcp_rfc3396 {
    use super::super::{
        scan_dhcp_option_segments, Dhcp, DhcpMessageType, DhcpOption, DhcpOptionArea,
    };
    use super::{encode_split_option, split_option_encoded_len, DHCP_MAX_OPTION_DATA_LEN};
    use core::net::Ipv4Addr;

    // Codes used by the long-payload style options exercised below.
    const HOST_NAME: u8 = super::super::DHCP_OPTION_HOST_NAME;
    const DOMAIN_SEARCH: u8 = 119; // RFC 3397, decoded as opaque/generic here.
    const VENDOR_CLASS: u8 = 60; // Vendor class identifier, generic opaque.

    fn build_options(payload_options: Vec<DhcpOption>) -> Vec<u8> {
        Dhcp::new()
            .options(payload_options)
            .encoded_options()
            .unwrap()
    }

    #[test]
    fn dhcp_rfc3396_concatenates_repeated_option_segments() {
        // Build a wire stream by hand with one logical option (a long host name)
        // split into two same-code segments, exactly as RFC 3396 prescribes. The
        // logical decoder must reassemble them into one option whose value is the
        // concatenation, while the raw segment scanner still exposes both
        // on-the-wire portions for inspection.
        let part_one = vec![b'a'; DHCP_MAX_OPTION_DATA_LEN]; // 255 bytes
        let part_two = vec![b'b'; 40];
        let mut full = part_one.clone();
        full.extend_from_slice(&part_two);

        let mut wire = Vec::new();
        wire.push(HOST_NAME);
        wire.push(part_one.len() as u8);
        wire.extend_from_slice(&part_one);
        wire.push(HOST_NAME);
        wire.push(part_two.len() as u8);
        wire.extend_from_slice(&part_two);
        wire.push(super::super::DHCP_OPTION_END);

        // Raw segments: two separate host-name instances remain inspectable.
        let segments = scan_dhcp_option_segments(DhcpOptionArea::Options, &wire).unwrap();
        let host_segments: Vec<&super::DhcpOptionSegment> = segments
            .iter()
            .filter(|s| s.code_value() == HOST_NAME)
            .collect();
        assert_eq!(host_segments.len(), 2);
        assert_eq!(host_segments[0].data, part_one);
        assert_eq!(host_segments[1].data, part_two);

        // Logical decode: exactly one host-name option, value concatenated.
        let decoded = DhcpOption::decode_all(&wire).unwrap();
        let host_options: Vec<&DhcpOption> =
            decoded.iter().filter(|o| o.code() == HOST_NAME).collect();
        assert_eq!(host_options.len(), 1);
        match host_options[0] {
            DhcpOption::HostName(name) => {
                assert_eq!(name.as_bytes(), full.as_slice());
                assert_eq!(name.len(), DHCP_MAX_OPTION_DATA_LEN + 40);
            }
            other => panic!("expected concatenated host name, got {other:?}"),
        }
    }

    #[test]
    fn dhcp_rfc3396_encoder_splits_long_payloads() {
        // A typed option with a payload longer than 255 bytes must be encoded as
        // multiple same-code segments, each at most 255 bytes, in order.
        let long_name = "x".repeat(600);
        let encoded = build_options(vec![
            DhcpOption::host_name(long_name.clone()),
            DhcpOption::End,
        ]);

        let segments = scan_dhcp_option_segments(DhcpOptionArea::Options, &encoded).unwrap();
        let host_segments: Vec<&super::DhcpOptionSegment> = segments
            .iter()
            .filter(|s| s.code_value() == HOST_NAME)
            .collect();
        // 600 bytes -> 255 + 255 + 90 -> three segments.
        assert_eq!(host_segments.len(), 3);
        assert_eq!(host_segments[0].data.len(), DHCP_MAX_OPTION_DATA_LEN);
        assert_eq!(host_segments[1].data.len(), DHCP_MAX_OPTION_DATA_LEN);
        assert_eq!(host_segments[2].data.len(), 90);
        // Every emitted segment respects the one-byte length limit.
        assert!(host_segments
            .iter()
            .all(|s| s.declared_len.unwrap() as usize <= DHCP_MAX_OPTION_DATA_LEN));

        // Decoding the split bytes reassembles the original logical value, and a
        // re-encode reproduces the same wire bytes (the splits are canonical).
        let decoded = DhcpOption::decode_all(&encoded).unwrap();
        let host = decoded
            .iter()
            .find(|o| o.code() == HOST_NAME)
            .expect("host name present");
        assert_eq!(host, &DhcpOption::host_name(long_name));
        let re_encoded = Dhcp::new().options(decoded).encoded_options().unwrap();
        assert_eq!(re_encoded, encoded);
    }

    #[test]
    fn dhcp_rfc3396_exact_255_boundary_is_a_single_segment() {
        // A payload of exactly 255 bytes fits one segment; 256 needs two.
        let exactly_255 = vec![0xABu8; DHCP_MAX_OPTION_DATA_LEN];
        let mut out = Vec::new();
        encode_split_option(VENDOR_CLASS, &exactly_255, &mut out);
        // One segment: code + len(255) + 255 data bytes.
        assert_eq!(out.len(), 2 + DHCP_MAX_OPTION_DATA_LEN);
        assert_eq!(out[0], VENDOR_CLASS);
        assert_eq!(out[1], 255);

        let just_over = vec![0xCDu8; DHCP_MAX_OPTION_DATA_LEN + 1];
        let mut out = Vec::new();
        encode_split_option(VENDOR_CLASS, &just_over, &mut out);
        // Two segments: 255 + 1.
        let segments = scan_dhcp_option_segments(DhcpOptionArea::Options, &out).unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].data.len(), DHCP_MAX_OPTION_DATA_LEN);
        assert_eq!(segments[1].data.len(), 1);

        // Reported encoded length matches the encoder for both boundaries.
        assert_eq!(
            split_option_encoded_len(DHCP_MAX_OPTION_DATA_LEN),
            2 + DHCP_MAX_OPTION_DATA_LEN
        );
        assert_eq!(
            split_option_encoded_len(DHCP_MAX_OPTION_DATA_LEN + 1),
            2 + DHCP_MAX_OPTION_DATA_LEN + 2 + 1
        );
        assert_eq!(split_option_encoded_len(0), 2);
    }

    #[test]
    fn dhcp_rfc3396_multi_segment_roundtrip_for_long_vendor_and_message_payloads() {
        // A generic (vendor/message style) option with a 700-byte opaque payload
        // round-trips through encode -> decode -> encode. The encoded length the
        // option reports must match the actual encoded bytes so the layer length
        // accounting stays correct.
        let payload = (0u16..700).map(|n| n as u8).collect::<Vec<u8>>();
        let option = DhcpOption::generic(VENDOR_CLASS, payload.clone());
        assert_eq!(option.encode().unwrap().len(), option.encoded_len());

        let encoded = build_options(vec![option.clone(), DhcpOption::End]);
        let decoded = DhcpOption::decode_all(&encoded).unwrap();
        let vendor = decoded
            .iter()
            .find(|o| o.code() == VENDOR_CLASS)
            .expect("vendor option present");
        // Concatenated payload survives without data loss.
        assert_eq!(vendor.payload().unwrap(), payload);
        // Exact wire round-trip for canonical 255-byte splits.
        let re_encoded = Dhcp::new().options(decoded).encoded_options().unwrap();
        assert_eq!(re_encoded, encoded);
    }

    #[test]
    fn dhcp_rfc3396_concatenates_across_overloaded_areas() {
        // RFC 3396 section 5: the aggregate buffer is options, then file, then
        // sname. A domain-search style option split across all three areas must
        // reassemble into one logical value in aggregate order, while each area's
        // raw options stay separately inspectable.
        let dhcp = Dhcp::new()
            .message_type(DhcpMessageType::Ack)
            .server_identifier(Ipv4Addr::new(192, 0, 2, 1))
            .option(DhcpOption::generic(DOMAIN_SEARCH, b"aaa".to_vec()))
            .file_option(DhcpOption::generic(DOMAIN_SEARCH, b"bbb".to_vec()))
            .file_option(DhcpOption::End)
            .sname_option(DhcpOption::generic(DOMAIN_SEARCH, b"ccc".to_vec()))
            .sname_option(DhcpOption::End);

        let bytes = crate::Packet::from_layer(dhcp)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let parsed = Dhcp::decode(&bytes).unwrap();

        // Per-area raw options remain inspectable.
        assert!(parsed
            .options_value()
            .iter()
            .any(|o| o.code() == DOMAIN_SEARCH));
        assert!(parsed
            .file_options_value()
            .iter()
            .any(|o| o.code() == DOMAIN_SEARCH));
        assert!(parsed
            .sname_options_value()
            .iter()
            .any(|o| o.code() == DOMAIN_SEARCH));

        // The cross-area reassembly joins options, then file, then sname.
        let joined = parsed
            .concatenated_option(DOMAIN_SEARCH)
            .expect("option present in some area")
            .expect("decodes cleanly");
        assert_eq!(joined.payload().unwrap(), b"aaabbbccc".to_vec());

        // A code that appears in no area yields None.
        assert!(parsed.concatenated_option(200).is_none());
    }
}
