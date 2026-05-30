//! UDP protocol implementation.

use core::fmt;

use crate::checksum::{crc32c, internet_checksum_chunks};
use crate::endian::read_u16_be;
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Layer, LayerContext, Packet, Raw};
use crate::protocols::dhcp::{Dhcp, DHCP_CLIENT_PORT, DHCP_SERVER_PORT};
use crate::protocols::dns::Dns;
use crate::protocols::ip::{Ipv4, IPPROTO_UDP};
use crate::protocols::ipv6::Ipv6;
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
const UDP_OPTION_LENGTH_CONTEXT: &str = "udp option length";
const UDP_OPTION_PAYLOAD_CONTEXT: &str = "udp option payload";
const UDP_OPTION_EXTENDED_LENGTH_CONTEXT: &str = "udp option extended length";
const UDP_OPTION_EXTENDED_PAYLOAD_CONTEXT: &str = "udp option extended payload";
const UDP_OPTION_CHECKSUM_LEN: usize = 2;
const UDP_OPTION_APC_LEN: usize = 6;
const UDP_OPTION_FRAG_SHORT_LEN: usize = 10;
const UDP_OPTION_FRAG_LONG_LEN: usize = 12;
const UDP_OPTION_MDS_LEN: usize = 4;
const UDP_OPTION_MRDS_LEN: usize = 5;
const UDP_OPTION_REQ_LEN: usize = 6;
const UDP_OPTION_RES_LEN: usize = 6;
const UDP_OPTION_TIME_LEN: usize = 10;
const UDP_OPTION_EXPERIMENT_DATA_MIN_LEN: usize = 2;
const UDP_OPTION_EXPERIMENT_SHORT_MIN_LEN: usize =
    UDP_OPTION_SHORT_HEADER_LEN + UDP_OPTION_EXPERIMENT_DATA_MIN_LEN;
const UDP_OPTION_EXPERIMENT_EXTENDED_MIN_LEN: usize =
    UDP_OPTION_EXTENDED_HEADER_LEN + UDP_OPTION_EXPERIMENT_DATA_MIN_LEN;

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

/// Registry classification for a UDP option kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpOptionKindClass {
    /// Assigned SAFE option with behavior implemented by `crafter`.
    KnownSafe,
    /// Assigned UNSAFE option with behavior implemented by `crafter`.
    KnownUnsafe,
    /// Currently unassigned SAFE option kind.
    UnassignedSafe,
    /// Currently unassigned UNSAFE option kind.
    UnassignedUnsafe,
    /// SAFE experimental option kind.
    ExperimentalSafe,
    /// UNSAFE experimental option kind.
    ExperimentalUnsafe,
    /// Reserved SAFE option kind.
    ReservedSafe,
    /// Reserved UNSAFE option kind.
    ReservedUnsafe,
}

/// Parsed or constructible UDP surplus option.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UdpOption {
    /// End of option list.
    EndOfList,
    /// One-byte no-operation padding.
    NoOperation,
    /// Additional payload checksum over conventional UDP user data.
    AdditionalPayloadChecksum {
        /// CRC32c bytes in network byte order.
        checksum: [u8; 4],
    },
    /// Maximum Datagram Size option.
    MaximumDatagramSize {
        /// 16-bit size hint bytes in network byte order.
        size: [u8; 2],
    },
    /// Maximum Reassembled Datagram Size option.
    MaximumReassembledDatagramSize {
        /// 16-bit size followed by 8-bit segment count.
        size_and_segment_count: [u8; 3],
    },
    /// Echo Request option.
    EchoRequest {
        /// Opaque 32-bit token bytes in network byte order.
        token: [u8; 4],
    },
    /// Echo Response option.
    EchoResponse {
        /// Opaque 32-bit token bytes in network byte order.
        token: [u8; 4],
    },
    /// Timestamp option.
    Timestamp {
        /// 32-bit TSval followed by 32-bit TSecr in network byte order.
        timestamps: [u8; 8],
    },
    /// SAFE experimental option.
    Experimental {
        /// 16-bit ExID followed by experiment-specific bytes.
        exid_and_data: Vec<u8>,
    },
    /// SAFE experimental option using extended length encoding.
    ExtendedExperimental {
        /// 16-bit ExID followed by experiment-specific bytes.
        exid_and_data: Vec<u8>,
    },
    /// UNSAFE experimental option.
    UnsafeExperimental {
        /// 16-bit ExID followed by experiment-specific bytes.
        exid_and_data: Vec<u8>,
    },
    /// UNSAFE experimental option using extended length encoding.
    ExtendedUnsafeExperimental {
        /// 16-bit ExID followed by experiment-specific bytes.
        exid_and_data: Vec<u8>,
    },
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

    /// Create an Additional Payload Checksum option with an explicit value.
    pub fn additional_payload_checksum(checksum: u32) -> Self {
        Self::AdditionalPayloadChecksum {
            checksum: checksum.to_be_bytes(),
        }
    }

    /// Compatibility-style short alias for [`Self::additional_payload_checksum`].
    pub fn apc(checksum: u32) -> Self {
        Self::additional_payload_checksum(checksum)
    }

    /// Create a Maximum Datagram Size option.
    pub const fn maximum_datagram_size(size: u16) -> Self {
        Self::MaximumDatagramSize {
            size: size.to_be_bytes(),
        }
    }

    /// Compatibility-style short alias for [`Self::maximum_datagram_size`].
    pub const fn mds(size: u16) -> Self {
        Self::maximum_datagram_size(size)
    }

    /// Create a Maximum Reassembled Datagram Size option.
    pub const fn maximum_reassembled_datagram_size(size: u16, segment_count: u8) -> Self {
        let size = size.to_be_bytes();
        Self::MaximumReassembledDatagramSize {
            size_and_segment_count: [size[0], size[1], segment_count],
        }
    }

    /// Compatibility-style short alias for [`Self::maximum_reassembled_datagram_size`].
    pub const fn mrds(size: u16, segment_count: u8) -> Self {
        Self::maximum_reassembled_datagram_size(size, segment_count)
    }

    /// Create an Echo Request option with an opaque token.
    pub fn echo_request(token: u32) -> Self {
        Self::EchoRequest {
            token: token.to_be_bytes(),
        }
    }

    /// Compatibility-style short alias for [`Self::echo_request`].
    pub fn req(token: u32) -> Self {
        Self::echo_request(token)
    }

    /// Create an Echo Response option with an opaque token.
    pub fn echo_response(token: u32) -> Self {
        Self::EchoResponse {
            token: token.to_be_bytes(),
        }
    }

    /// Compatibility-style short alias for [`Self::echo_response`].
    pub fn res(token: u32) -> Self {
        Self::echo_response(token)
    }

    /// Create a Timestamp option with explicit TSval and TSecr values.
    pub fn timestamp(tsval: u32, tsecr: u32) -> Self {
        let tsval = tsval.to_be_bytes();
        let tsecr = tsecr.to_be_bytes();
        Self::Timestamp {
            timestamps: [
                tsval[0], tsval[1], tsval[2], tsval[3], tsecr[0], tsecr[1], tsecr[2], tsecr[3],
            ],
        }
    }

    /// Compatibility-style short alias for [`Self::timestamp`].
    pub fn time(tsval: u32, tsecr: u32) -> Self {
        Self::timestamp(tsval, tsecr)
    }

    /// Create a SAFE experimental option.
    pub fn experimental(exid: u16, data: impl Into<Vec<u8>>) -> Self {
        let exid_and_data = udp_experiment_payload(exid, data);
        if udp_option_needs_extended_length(exid_and_data.len()) {
            Self::ExtendedExperimental { exid_and_data }
        } else {
            Self::Experimental { exid_and_data }
        }
    }

    /// Compatibility-style short alias for [`Self::experimental`].
    pub fn exp(exid: u16, data: impl Into<Vec<u8>>) -> Self {
        Self::experimental(exid, data)
    }

    /// Create a SAFE experimental option using the extended length encoding.
    pub fn extended_experimental(exid: u16, data: impl Into<Vec<u8>>) -> Self {
        Self::ExtendedExperimental {
            exid_and_data: udp_experiment_payload(exid, data),
        }
    }

    /// Create an UNSAFE experimental option.
    pub fn unsafe_experimental(exid: u16, data: impl Into<Vec<u8>>) -> Self {
        let exid_and_data = udp_experiment_payload(exid, data);
        if udp_option_needs_extended_length(exid_and_data.len()) {
            Self::ExtendedUnsafeExperimental { exid_and_data }
        } else {
            Self::UnsafeExperimental { exid_and_data }
        }
    }

    /// Compatibility-style short alias for [`Self::unsafe_experimental`].
    pub fn uexp(exid: u16, data: impl Into<Vec<u8>>) -> Self {
        Self::unsafe_experimental(exid, data)
    }

    /// Create an UNSAFE experimental option using the extended length encoding.
    pub fn extended_unsafe_experimental(exid: u16, data: impl Into<Vec<u8>>) -> Self {
        Self::ExtendedUnsafeExperimental {
            exid_and_data: udp_experiment_payload(exid, data),
        }
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
            Self::AdditionalPayloadChecksum { .. } => UDP_OPTION_APC,
            Self::MaximumDatagramSize { .. } => UDP_OPTION_MDS,
            Self::MaximumReassembledDatagramSize { .. } => UDP_OPTION_MRDS,
            Self::EchoRequest { .. } => UDP_OPTION_REQ,
            Self::EchoResponse { .. } => UDP_OPTION_RES,
            Self::Timestamp { .. } => UDP_OPTION_TIME,
            Self::Experimental { .. } | Self::ExtendedExperimental { .. } => UDP_OPTION_EXP,
            Self::UnsafeExperimental { .. } | Self::ExtendedUnsafeExperimental { .. } => {
                UDP_OPTION_UEXP
            }
            Self::Generic { kind, .. } | Self::ExtendedGeneric { kind, .. } => *kind,
        }
    }

    /// Option payload bytes after the option length fields.
    pub fn data(&self) -> &[u8] {
        match self {
            Self::EndOfList | Self::NoOperation => &[],
            Self::AdditionalPayloadChecksum { checksum } => checksum,
            Self::MaximumDatagramSize { size } => size,
            Self::MaximumReassembledDatagramSize {
                size_and_segment_count,
            } => size_and_segment_count,
            Self::EchoRequest { token } | Self::EchoResponse { token } => token,
            Self::Timestamp { timestamps } => timestamps,
            Self::Experimental { exid_and_data }
            | Self::ExtendedExperimental { exid_and_data }
            | Self::UnsafeExperimental { exid_and_data }
            | Self::ExtendedUnsafeExperimental { exid_and_data } => exid_and_data,
            Self::Generic { data, .. } | Self::ExtendedGeneric { data, .. } => data,
        }
    }

    /// Return the APC checksum value, if this option is APC.
    pub fn additional_payload_checksum_value(&self) -> Option<u32> {
        match self {
            Self::AdditionalPayloadChecksum { checksum } => Some(u32::from_be_bytes(*checksum)),
            _ => None,
        }
    }

    /// Return the TIME TSval and TSecr values, if this option is TIME.
    pub fn timestamp_values(&self) -> Option<(u32, u32)> {
        match self {
            Self::Timestamp { timestamps } => Some((
                u32::from_be_bytes([timestamps[0], timestamps[1], timestamps[2], timestamps[3]]),
                u32::from_be_bytes([timestamps[4], timestamps[5], timestamps[6], timestamps[7]]),
            )),
            _ => None,
        }
    }

    /// Return the MDS size hint, if this option is MDS.
    pub fn maximum_datagram_size_value(&self) -> Option<u16> {
        match self {
            Self::MaximumDatagramSize { size } => Some(u16::from_be_bytes(*size)),
            _ => None,
        }
    }

    /// Return the MRDS size hint and segment count, if this option is MRDS.
    pub fn maximum_reassembled_datagram_size_values(&self) -> Option<(u16, u8)> {
        match self {
            Self::MaximumReassembledDatagramSize {
                size_and_segment_count,
            } => Some((
                u16::from_be_bytes([size_and_segment_count[0], size_and_segment_count[1]]),
                size_and_segment_count[2],
            )),
            _ => None,
        }
    }

    /// Return the REQ token value, if this option is REQ.
    pub fn echo_request_token(&self) -> Option<u32> {
        match self {
            Self::EchoRequest { token } => Some(u32::from_be_bytes(*token)),
            _ => None,
        }
    }

    /// Return the RES token value, if this option is RES.
    pub fn echo_response_token(&self) -> Option<u32> {
        match self {
            Self::EchoResponse { token } => Some(u32::from_be_bytes(*token)),
            _ => None,
        }
    }

    /// Return the EXP or UEXP experiment identifier.
    pub fn experiment_id(&self) -> Option<u16> {
        udp_experiment_parts(self).map(|(exid, _)| exid)
    }

    /// Return the EXP or UEXP experiment-specific bytes after ExID.
    pub fn experiment_data(&self) -> Option<&[u8]> {
        udp_experiment_parts(self).map(|(_, data)| data)
    }

    /// Return true when this option kind is in the UDP UNSAFE range.
    pub const fn is_unsafe(&self) -> bool {
        udp_option_kind_is_unsafe(self.kind())
    }

    /// Return the registry classification for this option kind.
    pub const fn kind_class(&self) -> UdpOptionKindClass {
        udp_option_kind_class(self.kind())
    }

    /// Return true when `crafter` preserves this option but does not process it.
    pub const fn is_unsupported(&self) -> bool {
        udp_option_kind_is_unsupported(self.kind())
    }

    /// Return true if this option uses the extended length format.
    pub const fn uses_extended_length(&self) -> bool {
        matches!(
            self,
            Self::ExtendedExperimental { .. }
                | Self::ExtendedUnsafeExperimental { .. }
                | Self::ExtendedGeneric { .. }
        )
    }

    /// Encoded option length in bytes.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::EndOfList | Self::NoOperation => 1,
            Self::AdditionalPayloadChecksum { .. } => UDP_OPTION_APC_LEN,
            Self::MaximumDatagramSize { .. } => UDP_OPTION_MDS_LEN,
            Self::MaximumReassembledDatagramSize { .. } => UDP_OPTION_MRDS_LEN,
            Self::EchoRequest { .. } => UDP_OPTION_REQ_LEN,
            Self::EchoResponse { .. } => UDP_OPTION_RES_LEN,
            Self::Timestamp { .. } => UDP_OPTION_TIME_LEN,
            Self::Experimental { exid_and_data } | Self::UnsafeExperimental { exid_and_data } => {
                UDP_OPTION_SHORT_HEADER_LEN + exid_and_data.len()
            }
            Self::ExtendedExperimental { exid_and_data }
            | Self::ExtendedUnsafeExperimental { exid_and_data } => {
                UDP_OPTION_EXTENDED_HEADER_LEN + exid_and_data.len()
            }
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
            Self::AdditionalPayloadChecksum { checksum } => {
                bytes.extend_from_slice(&[UDP_OPTION_APC, UDP_OPTION_APC_LEN as u8]);
                bytes.extend_from_slice(checksum);
            }
            Self::MaximumDatagramSize { size } => {
                bytes.extend_from_slice(&[UDP_OPTION_MDS, UDP_OPTION_MDS_LEN as u8]);
                bytes.extend_from_slice(size);
            }
            Self::MaximumReassembledDatagramSize {
                size_and_segment_count,
            } => {
                bytes.extend_from_slice(&[UDP_OPTION_MRDS, UDP_OPTION_MRDS_LEN as u8]);
                bytes.extend_from_slice(size_and_segment_count);
            }
            Self::EchoRequest { token } => {
                bytes.extend_from_slice(&[UDP_OPTION_REQ, UDP_OPTION_REQ_LEN as u8]);
                bytes.extend_from_slice(token);
            }
            Self::EchoResponse { token } => {
                bytes.extend_from_slice(&[UDP_OPTION_RES, UDP_OPTION_RES_LEN as u8]);
                bytes.extend_from_slice(token);
            }
            Self::Timestamp { timestamps } => {
                bytes.extend_from_slice(&[UDP_OPTION_TIME, UDP_OPTION_TIME_LEN as u8]);
                bytes.extend_from_slice(timestamps);
            }
            Self::Experimental { exid_and_data } => {
                encode_udp_experiment_option(
                    UDP_OPTION_EXP,
                    exid_and_data,
                    false,
                    "udp.option.exp.length",
                    &mut bytes,
                )?;
            }
            Self::ExtendedExperimental { exid_and_data } => {
                encode_udp_experiment_option(
                    UDP_OPTION_EXP,
                    exid_and_data,
                    true,
                    "udp.option.exp.length",
                    &mut bytes,
                )?;
            }
            Self::UnsafeExperimental { exid_and_data } => {
                encode_udp_experiment_option(
                    UDP_OPTION_UEXP,
                    exid_and_data,
                    false,
                    "udp.option.uexp.length",
                    &mut bytes,
                )?;
            }
            Self::ExtendedUnsafeExperimental { exid_and_data } => {
                encode_udp_experiment_option(
                    UDP_OPTION_UEXP,
                    exid_and_data,
                    true,
                    "udp.option.uexp.length",
                    &mut bytes,
                )?;
            }
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

impl fmt::Display for UdpOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&udp_option_inspection_summary(self))
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
                        UDP_OPTION_LENGTH_CONTEXT,
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

        let Some(end) = start.checked_add(len) else {
            self.done = true;
            return Some(Err(CrafterError::invalid_field_value(
                "udp.option.length",
                "option length overflows the option area",
            )));
        };
        if end > self.bytes.len() {
            self.done = true;
            return Some(Err(CrafterError::buffer_too_short(
                UDP_OPTION_PAYLOAD_CONTEXT,
                end,
                self.bytes.len(),
            )));
        }

        self.offset = end;
        if kind == UDP_OPTION_APC && len == UDP_OPTION_APC_LEN {
            let data_start = start + UDP_OPTION_SHORT_HEADER_LEN;
            return Some(Ok(UdpOption::AdditionalPayloadChecksum {
                checksum: [
                    self.bytes[data_start],
                    self.bytes[data_start + 1],
                    self.bytes[data_start + 2],
                    self.bytes[data_start + 3],
                ],
            }));
        }
        if kind == UDP_OPTION_MDS {
            if let Err(err) =
                validate_udp_option_len("udp.option.mds.length", len, UDP_OPTION_MDS_LEN)
            {
                self.done = true;
                return Some(Err(err));
            }
            let data_start = start + UDP_OPTION_SHORT_HEADER_LEN;
            return Some(Ok(UdpOption::MaximumDatagramSize {
                size: [self.bytes[data_start], self.bytes[data_start + 1]],
            }));
        }
        if kind == UDP_OPTION_MRDS {
            if let Err(err) =
                validate_udp_option_len("udp.option.mrds.length", len, UDP_OPTION_MRDS_LEN)
            {
                self.done = true;
                return Some(Err(err));
            }
            let data_start = start + UDP_OPTION_SHORT_HEADER_LEN;
            return Some(Ok(UdpOption::MaximumReassembledDatagramSize {
                size_and_segment_count: [
                    self.bytes[data_start],
                    self.bytes[data_start + 1],
                    self.bytes[data_start + 2],
                ],
            }));
        }
        if kind == UDP_OPTION_REQ {
            if let Err(err) =
                validate_udp_option_len("udp.option.req.length", len, UDP_OPTION_REQ_LEN)
            {
                self.done = true;
                return Some(Err(err));
            }
            let data_start = start + UDP_OPTION_SHORT_HEADER_LEN;
            return Some(Ok(UdpOption::EchoRequest {
                token: [
                    self.bytes[data_start],
                    self.bytes[data_start + 1],
                    self.bytes[data_start + 2],
                    self.bytes[data_start + 3],
                ],
            }));
        }
        if kind == UDP_OPTION_RES {
            if let Err(err) =
                validate_udp_option_len("udp.option.res.length", len, UDP_OPTION_RES_LEN)
            {
                self.done = true;
                return Some(Err(err));
            }
            let data_start = start + UDP_OPTION_SHORT_HEADER_LEN;
            return Some(Ok(UdpOption::EchoResponse {
                token: [
                    self.bytes[data_start],
                    self.bytes[data_start + 1],
                    self.bytes[data_start + 2],
                    self.bytes[data_start + 3],
                ],
            }));
        }
        if kind == UDP_OPTION_TIME {
            if let Err(err) =
                validate_udp_option_len("udp.option.time.length", len, UDP_OPTION_TIME_LEN)
            {
                self.done = true;
                return Some(Err(err));
            }
            let data_start = start + UDP_OPTION_SHORT_HEADER_LEN;
            return Some(Ok(UdpOption::Timestamp {
                timestamps: [
                    self.bytes[data_start],
                    self.bytes[data_start + 1],
                    self.bytes[data_start + 2],
                    self.bytes[data_start + 3],
                    self.bytes[data_start + 4],
                    self.bytes[data_start + 5],
                    self.bytes[data_start + 6],
                    self.bytes[data_start + 7],
                ],
            }));
        }
        if kind == UDP_OPTION_EXP {
            if let Err(err) = validate_udp_min_option_len(
                "udp.option.exp.length",
                len,
                UDP_OPTION_EXPERIMENT_SHORT_MIN_LEN,
            ) {
                self.done = true;
                return Some(Err(err));
            }
            let data_start = start + UDP_OPTION_SHORT_HEADER_LEN;
            return Some(Ok(UdpOption::Experimental {
                exid_and_data: self.bytes[data_start..end].to_vec(),
            }));
        }
        if kind == UDP_OPTION_UEXP {
            if let Err(err) = validate_udp_min_option_len(
                "udp.option.uexp.length",
                len,
                UDP_OPTION_EXPERIMENT_SHORT_MIN_LEN,
            ) {
                self.done = true;
                return Some(Err(err));
            }
            let data_start = start + UDP_OPTION_SHORT_HEADER_LEN;
            return Some(Ok(UdpOption::UnsafeExperimental {
                exid_and_data: self.bytes[data_start..end].to_vec(),
            }));
        }

        Some(Ok(UdpOption::Generic {
            kind,
            data: self.bytes[start + UDP_OPTION_SHORT_HEADER_LEN..end].to_vec(),
        }))
    }

    fn decode_extended(&mut self, start: usize, kind: u8) -> Option<Result<UdpOption>> {
        if start + UDP_OPTION_EXTENDED_HEADER_LEN > self.bytes.len() {
            self.done = true;
            return Some(Err(CrafterError::buffer_too_short(
                UDP_OPTION_EXTENDED_LENGTH_CONTEXT,
                start + UDP_OPTION_EXTENDED_HEADER_LEN,
                self.bytes.len(),
            )));
        }

        let len = u16::from_be_bytes([self.bytes[start + 2], self.bytes[start + 3]]) as usize;
        if len < UDP_OPTION_EXTENDED_HEADER_LEN {
            self.done = true;
            return Some(Err(CrafterError::invalid_field_value(
                "udp.option.extended_length",
                "extended option length must be at least 4 bytes",
            )));
        }

        let Some(end) = start.checked_add(len) else {
            self.done = true;
            return Some(Err(CrafterError::invalid_field_value(
                "udp.option.extended_length",
                "extended option length overflows the option area",
            )));
        };
        if end > self.bytes.len() {
            self.done = true;
            return Some(Err(CrafterError::buffer_too_short(
                UDP_OPTION_EXTENDED_PAYLOAD_CONTEXT,
                end,
                self.bytes.len(),
            )));
        }
        if kind == UDP_OPTION_MDS {
            self.done = true;
            return Some(Err(CrafterError::invalid_field_value(
                "udp.option.mds.length",
                "fixed-length UDP option must use the short length format",
            )));
        }
        if kind == UDP_OPTION_MRDS {
            self.done = true;
            return Some(Err(CrafterError::invalid_field_value(
                "udp.option.mrds.length",
                "fixed-length UDP option must use the short length format",
            )));
        }
        if kind == UDP_OPTION_REQ {
            self.done = true;
            return Some(Err(CrafterError::invalid_field_value(
                "udp.option.req.length",
                "fixed-length UDP option must use the short length format",
            )));
        }
        if kind == UDP_OPTION_RES {
            self.done = true;
            return Some(Err(CrafterError::invalid_field_value(
                "udp.option.res.length",
                "fixed-length UDP option must use the short length format",
            )));
        }
        if kind == UDP_OPTION_TIME {
            self.done = true;
            return Some(Err(CrafterError::invalid_field_value(
                "udp.option.time.length",
                "fixed-length UDP option must use the short length format",
            )));
        }
        if kind == UDP_OPTION_EXP {
            if let Err(err) = validate_udp_min_option_len(
                "udp.option.exp.length",
                len,
                UDP_OPTION_EXPERIMENT_EXTENDED_MIN_LEN,
            ) {
                self.done = true;
                return Some(Err(err));
            }
            self.offset = end;
            return Some(Ok(UdpOption::ExtendedExperimental {
                exid_and_data: self.bytes[start + UDP_OPTION_EXTENDED_HEADER_LEN..end].to_vec(),
            }));
        }
        if kind == UDP_OPTION_UEXP {
            if let Err(err) = validate_udp_min_option_len(
                "udp.option.uexp.length",
                len,
                UDP_OPTION_EXPERIMENT_EXTENDED_MIN_LEN,
            ) {
                self.done = true;
                return Some(Err(err));
            }
            self.offset = end;
            return Some(Ok(UdpOption::ExtendedUnsafeExperimental {
                exid_and_data: self.bytes[start + UDP_OPTION_EXTENDED_HEADER_LEN..end].to_vec(),
            }));
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
    option_checksum: Option<u16>,
    alignment: Option<Vec<u8>>,
    raw_surplus: Option<Vec<u8>>,
    auto_apc_offsets: Vec<usize>,
}

impl UdpOptions {
    /// Create an empty UDP options layer.
    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            options: Vec::new(),
            status: UdpOptionStatus::NoSurplus,
            option_checksum: None,
            alignment: None,
            raw_surplus: None,
            auto_apc_offsets: Vec::new(),
        }
    }

    /// Create a UDP options layer by copying option bytes after OCS.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        let bytes = bytes.as_ref().to_vec();
        let (options, status) = parse_udp_options_for_status(&bytes);
        Self {
            bytes,
            options,
            status,
            option_checksum: None,
            alignment: None,
            raw_surplus: None,
            auto_apc_offsets: Vec::new(),
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
            option_checksum: None,
            alignment: None,
            raw_surplus: None,
            auto_apc_offsets: Vec::new(),
        })
    }

    fn from_decoded_surplus(
        surplus: &[u8],
        user_payload: &[u8],
        surplus_offset_in_ip_datagram: usize,
        udp_checksum: u16,
    ) -> Self {
        if surplus.is_empty() {
            return Self::new();
        }

        let alignment_len = udp_options_alignment_len(surplus_offset_in_ip_datagram);
        if surplus.len() < alignment_len + UDP_OPTION_CHECKSUM_LEN {
            return Self {
                bytes: Vec::new(),
                options: Vec::new(),
                status: UdpOptionStatus::Malformed,
                option_checksum: None,
                alignment: Some(surplus[..surplus.len().min(alignment_len)].to_vec()),
                raw_surplus: Some(surplus.to_vec()),
                auto_apc_offsets: Vec::new(),
            };
        }

        let alignment = surplus[..alignment_len].to_vec();
        let option_checksum =
            u16::from_be_bytes([surplus[alignment_len], surplus[alignment_len + 1]]);
        let bytes = surplus[alignment_len + UDP_OPTION_CHECKSUM_LEN..].to_vec();
        let (options, parsed_status) = parse_udp_options_for_status(&bytes);
        let status = if alignment.iter().any(|byte| *byte != 0) {
            UdpOptionStatus::Ignored
        } else if !udp_options_ocs_valid(surplus, alignment_len, option_checksum, udp_checksum) {
            UdpOptionStatus::OptionChecksumInvalid
        } else if parsed_status == UdpOptionStatus::Valid {
            udp_options_apc_status(&options, user_payload)
        } else {
            parsed_status
        };

        Self {
            bytes,
            options,
            status,
            option_checksum: Some(option_checksum),
            alignment: Some(alignment),
            raw_surplus: None,
            auto_apc_offsets: Vec::new(),
        }
    }

    /// Borrow the encoded UDP option bytes after OCS.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Mutably borrow the encoded UDP option bytes after OCS.
    pub fn as_bytes_mut(&mut self) -> &mut Vec<u8> {
        self.options.clear();
        self.status = UdpOptionStatus::NotParsed;
        self.raw_surplus = None;
        self.auto_apc_offsets.clear();
        &mut self.bytes
    }

    /// Append encoded UDP option bytes.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(bytes);
        self.raw_surplus = None;
        self.refresh_parse();
        self
    }

    /// Append a typed UDP option.
    pub fn udp_option(mut self, option: UdpOption) -> Result<Self> {
        self.bytes.extend_from_slice(&option.encode()?);
        self.raw_surplus = None;
        self.refresh_parse();
        Ok(self)
    }

    /// Append an APC option whose CRC32c is filled from UDP user data at compile time.
    pub fn additional_payload_checksum(mut self) -> Self {
        let offset = self.bytes.len();
        self.bytes
            .extend_from_slice(&[UDP_OPTION_APC, UDP_OPTION_APC_LEN as u8]);
        self.bytes.extend_from_slice(&0u32.to_be_bytes());
        self.auto_apc_offsets.push(offset);
        self.raw_surplus = None;
        self.refresh_parse();
        self
    }

    /// Compatibility-style short alias for [`Self::additional_payload_checksum`].
    pub fn apc(self) -> Self {
        self.additional_payload_checksum()
    }

    /// Append an APC option with an explicit checksum value.
    pub fn additional_payload_checksum_value(mut self, checksum: u32) -> Self {
        self.bytes
            .extend_from_slice(&[UDP_OPTION_APC, UDP_OPTION_APC_LEN as u8]);
        self.bytes.extend_from_slice(&checksum.to_be_bytes());
        self.raw_surplus = None;
        self.refresh_parse();
        self
    }

    /// Compatibility-style short alias for [`Self::additional_payload_checksum_value`].
    pub fn apc_value(self, checksum: u32) -> Self {
        self.additional_payload_checksum_value(checksum)
    }

    /// Set the UDP Option Checksum field explicitly.
    pub fn option_checksum(mut self, checksum: u16) -> Self {
        self.option_checksum = Some(checksum);
        self.raw_surplus = None;
        self
    }

    /// Compatibility-style short alias for [`Self::option_checksum`].
    pub fn ocs(self, checksum: u16) -> Self {
        self.option_checksum(checksum)
    }

    /// Stored UDP Option Checksum value, when explicit or decoded.
    pub const fn option_checksum_value(&self) -> Option<u16> {
        self.option_checksum
    }

    /// Alignment bytes before OCS, when decoded or explicitly preserved.
    pub fn alignment_bytes(&self) -> Option<&[u8]> {
        self.alignment.as_deref()
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

    fn materialized_option_bytes(&self, ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        let mut bytes = self.bytes.clone();
        if self.auto_apc_offsets.is_empty() {
            return Ok(bytes);
        }

        let checksum = crc32c(&udp_user_payload_bytes_before_options(*ctx)?).to_be_bytes();
        for &offset in &self.auto_apc_offsets {
            if offset + UDP_OPTION_APC_LEN > bytes.len()
                || bytes[offset] != UDP_OPTION_APC
                || bytes[offset + 1] != UDP_OPTION_APC_LEN as u8
            {
                return Err(CrafterError::invalid_field_value(
                    "udp.option.apc",
                    "auto APC offset no longer points to an APC option",
                ));
            }
            bytes[offset + UDP_OPTION_SHORT_HEADER_LEN..offset + UDP_OPTION_APC_LEN]
                .copy_from_slice(&checksum);
        }

        Ok(bytes)
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

fn udp_experiment_payload(exid: u16, data: impl Into<Vec<u8>>) -> Vec<u8> {
    let mut exid_and_data = Vec::with_capacity(UDP_OPTION_EXPERIMENT_DATA_MIN_LEN);
    exid_and_data.extend_from_slice(&exid.to_be_bytes());
    exid_and_data.extend(data.into());
    exid_and_data
}

const fn udp_option_needs_extended_length(data_len: usize) -> bool {
    UDP_OPTION_SHORT_HEADER_LEN + data_len >= UDP_OPTION_EXTENDED_LEN_SENTINEL as usize
}

/// Return the registry classification for a UDP option kind.
pub const fn udp_option_kind_class(kind: u8) -> UdpOptionKindClass {
    match kind {
        UDP_OPTION_EOL | UDP_OPTION_NOP | UDP_OPTION_APC | UDP_OPTION_FRAG | UDP_OPTION_MDS
        | UDP_OPTION_MRDS | UDP_OPTION_REQ | UDP_OPTION_RES | UDP_OPTION_TIME => {
            UdpOptionKindClass::KnownSafe
        }
        UDP_OPTION_AUTH | UDP_OPTION_RESERVED_SAFE_START..=UDP_OPTION_RESERVED_SAFE_END => {
            UdpOptionKindClass::ReservedSafe
        }
        UDP_OPTION_UNASSIGNED_SAFE_START..=UDP_OPTION_UNASSIGNED_SAFE_END => {
            UdpOptionKindClass::UnassignedSafe
        }
        UDP_OPTION_EXP => UdpOptionKindClass::ExperimentalSafe,
        UDP_OPTION_UCMP | UDP_OPTION_UENC | UDP_OPTION_RESERVED_UNSAFE => {
            UdpOptionKindClass::ReservedUnsafe
        }
        UDP_OPTION_UNASSIGNED_UNSAFE_START..=UDP_OPTION_UNASSIGNED_UNSAFE_END => {
            UdpOptionKindClass::UnassignedUnsafe
        }
        UDP_OPTION_UEXP => UdpOptionKindClass::ExperimentalUnsafe,
    }
}

/// Return true when a UDP option kind is in the UNSAFE registry range.
pub const fn udp_option_kind_is_unsafe(kind: u8) -> bool {
    kind >= UDP_OPTION_UCMP
}

/// Return true when `crafter` preserves but does not process this option kind.
pub const fn udp_option_kind_is_unsupported(kind: u8) -> bool {
    matches!(
        kind,
        UDP_OPTION_FRAG | UDP_OPTION_UCMP | UDP_OPTION_UENC | UDP_OPTION_UNASSIGNED_UNSAFE_START
            ..=UDP_OPTION_UNASSIGNED_UNSAFE_END | UDP_OPTION_RESERVED_UNSAFE
    )
}

fn udp_experiment_parts(option: &UdpOption) -> Option<(u16, &[u8])> {
    match option {
        UdpOption::Experimental { exid_and_data }
        | UdpOption::ExtendedExperimental { exid_and_data }
        | UdpOption::UnsafeExperimental { exid_and_data }
        | UdpOption::ExtendedUnsafeExperimental { exid_and_data } => {
            udp_experiment_parts_from_data(exid_and_data)
        }
        _ => None,
    }
}

fn udp_experiment_parts_from_data(exid_and_data: &[u8]) -> Option<(u16, &[u8])> {
    if exid_and_data.len() < UDP_OPTION_EXPERIMENT_DATA_MIN_LEN {
        return None;
    }

    Some((
        u16::from_be_bytes([exid_and_data[0], exid_and_data[1]]),
        &exid_and_data[UDP_OPTION_EXPERIMENT_DATA_MIN_LEN..],
    ))
}

fn encode_udp_experiment_option(
    kind: u8,
    exid_and_data: &[u8],
    extended: bool,
    field: &'static str,
    bytes: &mut Vec<u8>,
) -> Result<()> {
    if exid_and_data.len() < UDP_OPTION_EXPERIMENT_DATA_MIN_LEN {
        return Err(CrafterError::invalid_field_value(
            field,
            "UDP experimental option requires a 16-bit ExID",
        ));
    }

    if extended {
        let len = UDP_OPTION_EXTENDED_HEADER_LEN + exid_and_data.len();
        let len = u16::try_from(len).map_err(|_| {
            CrafterError::invalid_field_value(
                field,
                "UDP experimental option extended length must fit in two bytes",
            )
        })?;
        bytes.extend_from_slice(&[kind, UDP_OPTION_EXTENDED_LEN_SENTINEL]);
        bytes.extend_from_slice(&len.to_be_bytes());
    } else {
        let len = UDP_OPTION_SHORT_HEADER_LEN + exid_and_data.len();
        if len >= UDP_OPTION_EXTENDED_LEN_SENTINEL as usize {
            return Err(CrafterError::invalid_field_value(
                field,
                "UDP experimental option short length must be less than 255 bytes",
            ));
        }
        bytes.extend_from_slice(&[kind, len as u8]);
    }

    bytes.extend_from_slice(exid_and_data);
    Ok(())
}

fn parse_udp_options_for_status(bytes: &[u8]) -> (Vec<UdpOption>, UdpOptionStatus) {
    if bytes.is_empty() {
        return (Vec::new(), UdpOptionStatus::NoSurplus);
    }

    let mut options = Vec::new();
    let mut has_malformed_apc = false;
    for option in UdpOptionIter::new(bytes) {
        match option {
            Ok(option) => {
                has_malformed_apc |= udp_option_is_malformed_apc(&option);
                let is_malformed_frag = udp_option_is_malformed_frag(&option);
                let is_unsupported = option.is_unsupported();
                options.push(option);
                if is_malformed_frag {
                    return (options, UdpOptionStatus::Malformed);
                }
                if is_unsupported {
                    let status = if has_malformed_apc {
                        UdpOptionStatus::AdditionalPayloadChecksumInvalid
                    } else {
                        UdpOptionStatus::Unsupported
                    };
                    return (options, status);
                }
            }
            Err(_) => return (options, UdpOptionStatus::Malformed),
        }
    }

    let status = if has_malformed_apc {
        UdpOptionStatus::AdditionalPayloadChecksumInvalid
    } else {
        UdpOptionStatus::Valid
    };

    (options, status)
}

fn udp_option_is_malformed_apc(option: &UdpOption) -> bool {
    matches!(
        option,
        UdpOption::Generic {
            kind: UDP_OPTION_APC,
            ..
        } | UdpOption::ExtendedGeneric {
            kind: UDP_OPTION_APC,
            ..
        }
    )
}

fn udp_option_is_malformed_frag(option: &UdpOption) -> bool {
    match option {
        UdpOption::Generic {
            kind: UDP_OPTION_FRAG,
            data,
        } => !matches!(
            UDP_OPTION_SHORT_HEADER_LEN + data.len(),
            UDP_OPTION_FRAG_SHORT_LEN | UDP_OPTION_FRAG_LONG_LEN
        ),
        UdpOption::ExtendedGeneric {
            kind: UDP_OPTION_FRAG,
            ..
        } => true,
        _ => false,
    }
}

fn udp_options_apc_status(options: &[UdpOption], user_payload: &[u8]) -> UdpOptionStatus {
    let expected = crc32c(user_payload).to_be_bytes();
    if options.iter().any(|option| match option {
        UdpOption::AdditionalPayloadChecksum { checksum } => checksum != &expected,
        option => udp_option_is_malformed_apc(option),
    }) {
        UdpOptionStatus::AdditionalPayloadChecksumInvalid
    } else {
        UdpOptionStatus::Valid
    }
}

fn udp_options_alignment_len(offset_in_ip_datagram: usize) -> usize {
    offset_in_ip_datagram & 1
}

fn udp_options_generated_ocs(alignment: &[u8], option_bytes: &[u8]) -> Result<u16> {
    let surplus_len = alignment
        .len()
        .checked_add(UDP_OPTION_CHECKSUM_LEN)
        .and_then(|len| len.checked_add(option_bytes.len()))
        .ok_or_else(|| {
            CrafterError::invalid_field_value(
                "udp.options.length",
                "UDP surplus area length overflows usize",
            )
        })?;
    let surplus_len = u16::try_from(surplus_len).map_err(|_| {
        CrafterError::invalid_field_value(
            "udp.options.length",
            "UDP surplus area length must fit in two bytes",
        )
    })?;

    // RFC 9868 aligns OCS relative to the IP datagram; pre-OCS bytes are
    // zero padding, while the OCS covers the remainder plus full surplus len.
    let mut checksummed = Vec::with_capacity(UDP_OPTION_CHECKSUM_LEN + option_bytes.len());
    checksummed.extend_from_slice(&0u16.to_be_bytes());
    checksummed.extend_from_slice(option_bytes);

    let len_bytes = surplus_len.to_be_bytes();
    let checksum = internet_checksum_chunks([len_bytes.as_slice(), checksummed.as_slice()]);
    Ok(if checksum == 0 { 0xffff } else { checksum })
}

fn udp_options_ocs_valid(
    surplus: &[u8],
    alignment_len: usize,
    option_checksum: u16,
    udp_checksum: u16,
) -> bool {
    if option_checksum == 0 {
        return udp_checksum == 0;
    }

    let Ok(surplus_len) = u16::try_from(surplus.len()) else {
        return false;
    };
    let len_bytes = surplus_len.to_be_bytes();
    internet_checksum_chunks([len_bytes.as_slice(), &surplus[alignment_len..]]) == 0
}

fn first_ip_layer_index(packet: &Packet) -> Option<usize> {
    packet
        .iter()
        .position(|layer| layer.as_any().is::<Ipv4>() || layer.as_any().is::<Ipv6>())
}

fn udp_options_surplus_offset_in_ip_datagram(ctx: LayerContext<'_>) -> usize {
    let packet = ctx.packet();
    let start = first_ip_layer_index(packet).unwrap_or(0);
    packet
        .iter()
        .enumerate()
        .skip(start)
        .take(ctx.index().saturating_sub(start))
        .map(|(index, layer)| {
            let layer_ctx = LayerContext::new(packet, index);
            layer.encoded_len_with_context(&layer_ctx)
        })
        .sum()
}

fn udp_decoded_surplus_offset_in_ip_datagram(
    packet_before_udp: &Packet,
    udp_length: usize,
) -> usize {
    let start = first_ip_layer_index(packet_before_udp).unwrap_or(0);
    packet_before_udp
        .iter()
        .enumerate()
        .skip(start)
        .map(|(index, layer)| {
            let layer_ctx = LayerContext::new(packet_before_udp, index);
            layer.encoded_len_with_context(&layer_ctx)
        })
        .sum::<usize>()
        + udp_length
}

fn udp_option_inspection_summary(option: &UdpOption) -> String {
    match option {
        UdpOption::EndOfList => "EOL".to_string(),
        UdpOption::NoOperation => "NOP".to_string(),
        UdpOption::AdditionalPayloadChecksum { checksum } => {
            format!("APC(crc32c=0x{:08x})", u32::from_be_bytes(*checksum))
        }
        UdpOption::MaximumDatagramSize { size } => {
            format!("MDS(size={})", u16::from_be_bytes(*size))
        }
        UdpOption::MaximumReassembledDatagramSize {
            size_and_segment_count,
        } => format!(
            "MRDS(size={},segments={})",
            u16::from_be_bytes([size_and_segment_count[0], size_and_segment_count[1]]),
            size_and_segment_count[2]
        ),
        UdpOption::EchoRequest { token } => {
            format!("REQ(token=0x{:08x})", u32::from_be_bytes(*token))
        }
        UdpOption::EchoResponse { token } => {
            format!("RES(token=0x{:08x})", u32::from_be_bytes(*token))
        }
        UdpOption::Timestamp { timestamps } => {
            let tsval =
                u32::from_be_bytes([timestamps[0], timestamps[1], timestamps[2], timestamps[3]]);
            let tsecr =
                u32::from_be_bytes([timestamps[4], timestamps[5], timestamps[6], timestamps[7]]);
            format!("TIME(tsval=0x{tsval:08x},tsecr=0x{tsecr:08x})")
        }
        UdpOption::Experimental { exid_and_data }
        | UdpOption::ExtendedExperimental { exid_and_data } => {
            udp_experiment_inspection_summary("EXP", exid_and_data, "SAFE")
        }
        UdpOption::UnsafeExperimental { exid_and_data }
        | UdpOption::ExtendedUnsafeExperimental { exid_and_data } => {
            udp_experiment_inspection_summary("UEXP", exid_and_data, "UNSAFE")
        }
        UdpOption::Generic { kind, data } => udp_generic_inspection_summary(
            "Generic",
            *kind,
            UDP_OPTION_SHORT_HEADER_LEN + data.len(),
        ),
        UdpOption::ExtendedGeneric { kind, data } => udp_generic_inspection_summary(
            "ExtendedGeneric",
            *kind,
            UDP_OPTION_EXTENDED_HEADER_LEN + data.len(),
        ),
    }
}

fn udp_generic_inspection_summary(label: &str, kind: u8, len: usize) -> String {
    let support = if udp_option_kind_is_unsupported(kind) {
        ",support=unsupported"
    } else {
        ""
    };
    format!(
        "{label}(kind={kind},len={len},class={:?},safety={}{support})",
        udp_option_kind_class(kind),
        udp_option_safety_label(kind)
    )
}

const fn udp_option_safety_label(kind: u8) -> &'static str {
    if udp_option_kind_is_unsafe(kind) {
        "UNSAFE"
    } else {
        "SAFE"
    }
}

fn udp_experiment_inspection_summary(label: &str, exid_and_data: &[u8], safety: &str) -> String {
    let Some((exid, data)) = udp_experiment_parts_from_data(exid_and_data) else {
        return format!(
            "{label}(malformed,data_len={},safety={safety})",
            exid_and_data.len()
        );
    };
    let data = if data.is_empty() {
        "empty".to_string()
    } else {
        hex_bytes(data)
    };
    format!("{label}(exid=0x{exid:04x},data={data},safety={safety})")
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

fn validate_udp_option_len(field: &'static str, actual: usize, expected: usize) -> Result<()> {
    if actual != expected {
        return Err(CrafterError::invalid_field_value(
            field,
            "UDP option has an invalid fixed length",
        ));
    }
    Ok(())
}

fn validate_udp_min_option_len(field: &'static str, actual: usize, minimum: usize) -> Result<()> {
    if actual < minimum {
        return Err(CrafterError::invalid_field_value(
            field,
            "UDP option is shorter than its minimum length",
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
            "UdpOptions(len={}, status={:?}, options={})",
            self.bytes.len(),
            self.status,
            udp_options_inspection_summary(&self.options)
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("len", self.bytes.len().to_string()),
            ("status", format!("{:?}", self.status)),
            (
                "ocs",
                self.option_checksum
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| {
                        if self.bytes.is_empty() {
                            "absent".to_string()
                        } else {
                            "auto".to_string()
                        }
                    }),
            ),
            (
                "alignment",
                self.alignment
                    .as_ref()
                    .map(|bytes| hex_bytes(bytes))
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("option_count", self.options.len().to_string()),
            ("options", udp_options_inspection_summary(&self.options)),
            ("bytes", hex_bytes(&self.bytes)),
        ]
    }

    fn encoded_len(&self) -> usize {
        if let Some(raw_surplus) = &self.raw_surplus {
            return raw_surplus.len();
        }
        if self.bytes.is_empty() && self.option_checksum.is_none() {
            return 0;
        }

        self.alignment.as_ref().map_or(0, Vec::len) + UDP_OPTION_CHECKSUM_LEN + self.bytes.len()
    }

    fn encoded_len_with_context(&self, ctx: &LayerContext<'_>) -> usize {
        if let Some(raw_surplus) = &self.raw_surplus {
            return raw_surplus.len();
        }
        if self.bytes.is_empty() && self.option_checksum.is_none() {
            return 0;
        }

        let alignment_len = self.alignment.as_ref().map_or_else(
            || udp_options_alignment_len(udp_options_surplus_offset_in_ip_datagram(*ctx)),
            Vec::len,
        );
        alignment_len + UDP_OPTION_CHECKSUM_LEN + self.bytes.len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        if let Some(raw_surplus) = &self.raw_surplus {
            out.extend_from_slice(raw_surplus);
            return Ok(());
        }
        if self.bytes.is_empty() && self.option_checksum.is_none() {
            return Ok(());
        }

        let alignment = self.alignment.clone().unwrap_or_else(|| {
            vec![0; udp_options_alignment_len(udp_options_surplus_offset_in_ip_datagram(*ctx))]
        });
        let option_bytes = self.materialized_option_bytes(ctx)?;
        let option_checksum = match self.option_checksum {
            Some(value) => value,
            None => udp_options_generated_ocs(&alignment, &option_bytes)?,
        };

        out.extend_from_slice(&alignment);
        out.extend_from_slice(&option_checksum.to_be_bytes());
        out.extend_from_slice(&option_bytes);
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
    let udp_length = decoded.udp.length_value().unwrap_or(UDP_HEADER_LEN as u16) as usize;
    let udp_checksum = decoded.udp.checksum_value().unwrap_or(0);
    let surplus_offset = udp_decoded_surplus_offset_in_ip_datagram(&packet, udp_length);
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
        packet = packet.push(UdpOptions::from_decoded_surplus(
            decoded.surplus,
            decoded.user_payload,
            surplus_offset,
            udp_checksum,
        ));
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

fn udp_user_payload_bytes_before_options(ctx: LayerContext<'_>) -> Result<Vec<u8>> {
    let mut udp_index = None;
    for (index, layer) in ctx.packet().iter().enumerate().take(ctx.index()) {
        if layer.as_any().is::<Udp>() {
            udp_index = Some(index);
        }
    }

    let Some(udp_index) = udp_index else {
        return Ok(Vec::new());
    };

    let mut payload = Vec::new();
    let mut seen_application_layer = false;

    for (index, layer) in ctx
        .packet()
        .iter()
        .enumerate()
        .take(ctx.index())
        .skip(udp_index + 1)
    {
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
        udp_option_kind_class, udp_option_kind_is_unsafe, udp_option_kind_is_unsupported, Udp,
        UdpChecksumStatus, UdpOption, UdpOptionIter, UdpOptionKindClass, UdpOptionStatus,
        UdpOptions, UDP_HEADER_LEN, UDP_OPTION_APC, UDP_OPTION_APC_LEN, UDP_OPTION_AUTH,
        UDP_OPTION_CHECKSUM_LEN, UDP_OPTION_EOL, UDP_OPTION_EXP, UDP_OPTION_FRAG,
        UDP_OPTION_FRAG_LONG_LEN, UDP_OPTION_FRAG_SHORT_LEN, UDP_OPTION_MDS, UDP_OPTION_MDS_LEN,
        UDP_OPTION_MRDS, UDP_OPTION_MRDS_LEN, UDP_OPTION_NOP, UDP_OPTION_REQ, UDP_OPTION_REQ_LEN,
        UDP_OPTION_RES, UDP_OPTION_RESERVED_SAFE_START, UDP_OPTION_RESERVED_UNSAFE,
        UDP_OPTION_RES_LEN, UDP_OPTION_TIME, UDP_OPTION_TIME_LEN, UDP_OPTION_UCMP, UDP_OPTION_UEXP,
        UDP_OPTION_UNASSIGNED_SAFE_START, UDP_OPTION_UNASSIGNED_UNSAFE_START,
    };
    use crate::checksum::{crc32c, internet_checksum_chunks, ipv4_pseudo_header_checksum};
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

    fn ipv4_total_len(bytes: &[u8]) -> usize {
        u16::from_be_bytes([bytes[2], bytes[3]]) as usize
    }

    fn udp_length(bytes: &[u8]) -> usize {
        u16::from_be_bytes([bytes[24], bytes[25]]) as usize
    }

    fn udp_surplus_start(bytes: &[u8]) -> usize {
        20 + udp_length(bytes)
    }

    fn udp_surplus(bytes: &[u8]) -> &[u8] {
        &bytes[udp_surplus_start(bytes)..ipv4_total_len(bytes)]
    }

    fn udp_surplus_checksum_valid(bytes: &[u8]) -> bool {
        let surplus_start = udp_surplus_start(bytes);
        let surplus = udp_surplus(bytes);
        let alignment_len = surplus_start & 1;
        let len = (surplus.len() as u16).to_be_bytes();
        internet_checksum_chunks([len.as_slice(), &surplus[alignment_len..]]) == 0
    }

    fn apc_checksum_value(udp_options: &UdpOptions) -> u32 {
        udp_options
            .options()
            .iter()
            .find_map(UdpOption::additional_payload_checksum_value)
            .expect("decoded APC option")
    }

    fn assert_udp_option_length_buffer_error(
        bytes: &[u8],
        expected_context: &'static str,
        expected_required: usize,
        expected_available: usize,
    ) {
        let udp_options = UdpOptions::from_bytes(bytes);
        assert_eq!(udp_options.status(), UdpOptionStatus::Malformed);
        assert_eq!(udp_options.as_bytes(), bytes);

        match UdpOption::decode_all(bytes).unwrap_err() {
            crate::CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, expected_context);
                assert_eq!(required, expected_required);
                assert_eq!(available, expected_available);
            }
            other => panic!("expected UDP option length buffer error, got {other:?}"),
        }
    }

    fn assert_udp_option_length_field_error(bytes: &[u8], expected_field: &'static str) {
        let udp_options = UdpOptions::from_bytes(bytes);
        assert_eq!(udp_options.status(), UdpOptionStatus::Malformed);
        assert_eq!(udp_options.as_bytes(), bytes);

        match UdpOption::decode_all(bytes).unwrap_err() {
            crate::CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, expected_field);
            }
            other => panic!("expected UDP option length field error, got {other:?}"),
        }
    }

    fn assert_udp_option_encode_field_error(option: UdpOption, expected_field: &'static str) {
        match option.encode().unwrap_err() {
            crate::CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, expected_field);
            }
            other => panic!("expected UDP option encode field error, got {other:?}"),
        }
    }

    #[test]
    fn udp_options_ocs_absent_is_malformed_and_preserved() {
        let mut datagram = Vec::new();
        datagram.extend_from_slice(&0x1111u16.to_be_bytes());
        datagram.extend_from_slice(&0x2222u16.to_be_bytes());
        datagram.extend_from_slice(&(UDP_HEADER_LEN as u16).to_be_bytes());
        datagram.extend_from_slice(&0u16.to_be_bytes());
        datagram.push(0);
        let bytes = (Ipv4::new()
            .src(src())
            .dst(dst())
            .proto(IpProtocol::Udp)
            .id(0x2210)
            / Raw::from_bytes(datagram))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp_options = decoded.layer::<UdpOptions>().unwrap();
        assert_eq!(udp_options.status(), UdpOptionStatus::Malformed);
        assert_eq!(udp_options.option_checksum_value(), None);
        assert_eq!(udp_options.as_bytes(), &[]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn udp_options_ocs_auto_filled_valid_and_inspectable() {
        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2211)
            / Udp::new().sport(1234).dport(4321)
            / Raw::from_bytes([0xaa, 0xbb])
            / UdpOptions::from_bytes([UDP_OPTION_NOP, UDP_OPTION_EOL]))
        .compile()
        .unwrap();

        let surplus = udp_surplus(bytes.as_bytes());
        assert_eq!(surplus.len(), UDP_OPTION_CHECKSUM_LEN + 2);
        let ocs = u16::from_be_bytes([surplus[0], surplus[1]]);
        assert_ne!(ocs, 0);
        assert!(udp_surplus_checksum_valid(bytes.as_bytes()));

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp_options = decoded.layer::<UdpOptions>().unwrap();
        assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
        assert_eq!(udp_options.option_checksum_value(), Some(ocs));
        assert_eq!(
            udp_options.options(),
            &[UdpOption::NoOperation, UdpOption::EndOfList]
        );
        assert!(udp_options
            .inspection_fields()
            .iter()
            .any(|(name, value)| { *name == "ocs" && value == &format!("0x{ocs:04x}") }));
    }

    #[test]
    fn udp_options_ocs_invalid_is_reported_and_preserved() {
        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2212)
            / Udp::new().sport(1234).dport(4321)
            / Raw::from_bytes([0xaa, 0xbb])
            / UdpOptions::from_bytes([UDP_OPTION_NOP, UDP_OPTION_EOL]))
        .compile()
        .unwrap();
        let mut invalid = bytes.as_bytes().to_vec();
        let surplus_start = udp_surplus_start(&invalid);
        invalid[surplus_start] ^= 0x01;
        assert!(!udp_surplus_checksum_valid(&invalid));

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, &invalid).unwrap();
        let udp_options = decoded.layer::<UdpOptions>().unwrap();
        assert_eq!(udp_options.status(), UdpOptionStatus::OptionChecksumInvalid);
        assert_eq!(decoded.compile().unwrap().as_bytes(), invalid.as_slice());
    }

    #[test]
    fn udp_options_ocs_explicit_override_survives_compile() {
        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2213)
            / Udp::new().sport(1234).dport(4321)
            / Raw::from_bytes([0xaa, 0xbb])
            / UdpOptions::from_bytes([UDP_OPTION_NOP, UDP_OPTION_EOL]).option_checksum(0x1234))
        .compile()
        .unwrap();

        let surplus = udp_surplus(bytes.as_bytes());
        assert_eq!(
            &surplus[..UDP_OPTION_CHECKSUM_LEN],
            &0x1234u16.to_be_bytes()
        );
        assert!(!udp_surplus_checksum_valid(bytes.as_bytes()));

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp_options = decoded.layer::<UdpOptions>().unwrap();
        assert_eq!(udp_options.option_checksum_value(), Some(0x1234));
        assert_eq!(udp_options.status(), UdpOptionStatus::OptionChecksumInvalid);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn udp_options_alignment_even_and_odd_surplus_offsets() {
        let even = (Ipv4::new().src(src()).dst(dst()).id(0x2214)
            / Udp::new().sport(1234).dport(4321)
            / Raw::from_bytes([0xaa, 0xbb])
            / UdpOptions::from_bytes([UDP_OPTION_EOL]))
        .compile()
        .unwrap();
        let even_surplus = udp_surplus(even.as_bytes());
        assert_eq!(even_surplus.len(), UDP_OPTION_CHECKSUM_LEN + 1);
        assert!(udp_surplus_checksum_valid(even.as_bytes()));
        let even_decoded =
            Packet::decode_from_l3(crate::NetworkLayer::Ipv4, even.as_bytes()).unwrap();
        assert_eq!(
            even_decoded
                .layer::<UdpOptions>()
                .unwrap()
                .alignment_bytes(),
            Some([].as_slice())
        );

        let odd = (Ipv4::new().src(src()).dst(dst()).id(0x2215)
            / Udp::new().sport(1234).dport(4321)
            / Raw::from_bytes([0xaa])
            / UdpOptions::from_bytes([UDP_OPTION_EOL]))
        .compile()
        .unwrap();
        let odd_surplus = udp_surplus(odd.as_bytes());
        assert_eq!(odd_surplus.len(), 1 + UDP_OPTION_CHECKSUM_LEN + 1);
        assert_eq!(odd_surplus[0], 0);
        assert!(udp_surplus_checksum_valid(odd.as_bytes()));
        let odd_decoded =
            Packet::decode_from_l3(crate::NetworkLayer::Ipv4, odd.as_bytes()).unwrap();
        let odd_options = odd_decoded.layer::<UdpOptions>().unwrap();
        assert_eq!(odd_options.status(), UdpOptionStatus::Valid);
        assert_eq!(odd_options.alignment_bytes(), Some([0].as_slice()));
    }

    #[test]
    fn udp_options_alignment_nonzero_fill_ignores_options() {
        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2216)
            / Udp::new().sport(1234).dport(4321)
            / Raw::from_bytes([0xaa])
            / UdpOptions::from_bytes([UDP_OPTION_EOL]))
        .compile()
        .unwrap();
        let mut invalid = bytes.as_bytes().to_vec();
        let surplus_start = udp_surplus_start(&invalid);
        invalid[surplus_start] = 0x7f;

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, &invalid).unwrap();
        let udp_options = decoded.layer::<UdpOptions>().unwrap();
        assert_eq!(udp_options.status(), UdpOptionStatus::Ignored);
        assert_eq!(udp_options.alignment_bytes(), Some([0x7f].as_slice()));
        assert_eq!(decoded.compile().unwrap().as_bytes(), invalid.as_slice());
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
        assert_eq!(UDP_OPTION_TIME, 8);
        assert_eq!(UDP_OPTION_EXP, 127);
        assert_eq!(UDP_OPTION_UEXP, 254);

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
                UdpOption::ExtendedExperimental {
                    exid_and_data: vec![0x12, 0x34]
                }
            ]
        );
    }

    #[test]
    fn udp_option_apc_encode_decode_fixed_length() {
        let apc = UdpOption::additional_payload_checksum(0x0102_0304);
        assert_eq!(apc.kind(), UDP_OPTION_APC);
        assert_eq!(apc.data(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(apc.additional_payload_checksum_value(), Some(0x0102_0304));
        assert_eq!(apc.encoded_len(), UDP_OPTION_APC_LEN);
        assert_eq!(
            apc.encode().unwrap(),
            vec![
                UDP_OPTION_APC,
                UDP_OPTION_APC_LEN as u8,
                0x01,
                0x02,
                0x03,
                0x04
            ]
        );

        let decoded =
            UdpOption::decode_all(&[UDP_OPTION_APC, UDP_OPTION_APC_LEN as u8, 1, 2, 3, 4]).unwrap();
        assert_eq!(decoded, vec![apc]);

        let malformed_len = UdpOptions::from_bytes([UDP_OPTION_APC, 5, 1, 2, 3]);
        assert_eq!(
            malformed_len.status(),
            UdpOptionStatus::AdditionalPayloadChecksumInvalid
        );
    }

    #[test]
    fn udp_option_mds_encode_decode_fixed_length_and_display() {
        let mds = UdpOption::maximum_datagram_size(1500);
        assert_eq!(mds, UdpOption::mds(1500));
        assert_eq!(mds.kind(), UDP_OPTION_MDS);
        assert_eq!(mds.data(), &1500u16.to_be_bytes());
        assert_eq!(mds.maximum_datagram_size_value(), Some(1500));
        assert_eq!(mds.maximum_reassembled_datagram_size_values(), None);
        assert!(!mds.uses_extended_length());
        assert_eq!(mds.encoded_len(), UDP_OPTION_MDS_LEN);
        assert_eq!(
            mds.encode().unwrap(),
            vec![UDP_OPTION_MDS, UDP_OPTION_MDS_LEN as u8, 0x05, 0xdc]
        );
        assert_eq!(mds.to_string(), "MDS(size=1500)");

        let decoded =
            UdpOption::decode_all(&[UDP_OPTION_MDS, UDP_OPTION_MDS_LEN as u8, 0x05, 0xdc]).unwrap();
        assert_eq!(decoded, vec![mds.clone()]);

        let udp_options = UdpOptions::from_bytes([UDP_OPTION_MDS, 4, 0x05, 0xdc]);
        assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
        assert_eq!(udp_options.options(), &[mds.clone()]);
        assert!(udp_options
            .inspection_fields()
            .iter()
            .any(|(name, value)| *name == "options" && value == "MDS(size=1500)"));

        let typed = UdpOptions::from_options(vec![mds]).unwrap();
        assert_eq!(typed.as_bytes(), &[UDP_OPTION_MDS, 4, 0x05, 0xdc]);
        assert_eq!(typed.status(), UdpOptionStatus::Valid);
    }

    #[test]
    fn udp_option_mds_malformed_lengths_are_rejected() {
        for bytes in [
            [UDP_OPTION_MDS, 3, 0x05].as_slice(),
            [UDP_OPTION_MDS, 5, 0x05, 0xdc, 0x00].as_slice(),
            [UDP_OPTION_MDS, 255, 0, 4].as_slice(),
        ] {
            assert_udp_option_length_field_error(bytes, "udp.option.mds.length");
        }
    }

    #[test]
    fn udp_option_mrds_encode_decode_fixed_length_and_display() {
        let mrds = UdpOption::maximum_reassembled_datagram_size(9000, 32);
        assert_eq!(mrds, UdpOption::mrds(9000, 32));
        assert_eq!(mrds.kind(), UDP_OPTION_MRDS);
        assert_eq!(mrds.data(), &[0x23, 0x28, 0x20]);
        assert_eq!(
            mrds.maximum_reassembled_datagram_size_values(),
            Some((9000, 32))
        );
        assert_eq!(mrds.maximum_datagram_size_value(), None);
        assert!(!mrds.uses_extended_length());
        assert_eq!(mrds.encoded_len(), UDP_OPTION_MRDS_LEN);
        assert_eq!(
            mrds.encode().unwrap(),
            vec![UDP_OPTION_MRDS, UDP_OPTION_MRDS_LEN as u8, 0x23, 0x28, 0x20]
        );
        assert_eq!(mrds.to_string(), "MRDS(size=9000,segments=32)");

        let decoded =
            UdpOption::decode_all(&[UDP_OPTION_MRDS, UDP_OPTION_MRDS_LEN as u8, 0x23, 0x28, 0x20])
                .unwrap();
        assert_eq!(decoded, vec![mrds.clone()]);

        let udp_options = UdpOptions::from_bytes([UDP_OPTION_MRDS, 5, 0x23, 0x28, 0x20]);
        assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
        assert_eq!(udp_options.options(), &[mrds.clone()]);
        assert!(udp_options
            .inspection_fields()
            .iter()
            .any(|(name, value)| { *name == "options" && value == "MRDS(size=9000,segments=32)" }));

        let typed = UdpOptions::from_options(vec![mrds]).unwrap();
        assert_eq!(typed.as_bytes(), &[UDP_OPTION_MRDS, 5, 0x23, 0x28, 0x20]);
        assert_eq!(typed.status(), UdpOptionStatus::Valid);
    }

    #[test]
    fn udp_option_mrds_malformed_lengths_are_rejected() {
        for bytes in [
            [UDP_OPTION_MRDS, 4, 0x23, 0x28].as_slice(),
            [UDP_OPTION_MRDS, 6, 0x23, 0x28, 0x20, 0x00].as_slice(),
            [UDP_OPTION_MRDS, 255, 0, 5, 0x20].as_slice(),
        ] {
            assert_udp_option_length_field_error(bytes, "udp.option.mrds.length");
        }
    }

    #[test]
    fn udp_option_req_encode_decode_fixed_length_and_display() {
        let req = UdpOption::echo_request(0x0102_0304);
        assert_eq!(req, UdpOption::req(0x0102_0304));
        assert_eq!(req.kind(), UDP_OPTION_REQ);
        assert_eq!(req.data(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(req.echo_request_token(), Some(0x0102_0304));
        assert_eq!(req.echo_response_token(), None);
        assert!(!req.uses_extended_length());
        assert_eq!(req.encoded_len(), UDP_OPTION_REQ_LEN);
        assert_eq!(
            req.encode().unwrap(),
            vec![
                UDP_OPTION_REQ,
                UDP_OPTION_REQ_LEN as u8,
                0x01,
                0x02,
                0x03,
                0x04
            ]
        );
        assert_eq!(req.to_string(), "REQ(token=0x01020304)");

        let decoded =
            UdpOption::decode_all(&[UDP_OPTION_REQ, UDP_OPTION_REQ_LEN as u8, 1, 2, 3, 4]).unwrap();
        assert_eq!(decoded, vec![req.clone()]);

        let udp_options = UdpOptions::from_bytes([UDP_OPTION_REQ, 6, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
        assert_eq!(udp_options.options(), &[req.clone()]);
        assert!(udp_options
            .inspection_fields()
            .iter()
            .any(|(name, value)| *name == "options" && value == "REQ(token=0x01020304)"));

        let typed = UdpOptions::from_options(vec![req]).unwrap();
        assert_eq!(
            typed.as_bytes(),
            &[UDP_OPTION_REQ, 6, 0x01, 0x02, 0x03, 0x04]
        );
        assert_eq!(typed.status(), UdpOptionStatus::Valid);
    }

    #[test]
    fn udp_option_req_malformed_lengths_are_rejected() {
        for bytes in [
            [UDP_OPTION_REQ, 5, 0x01, 0x02, 0x03].as_slice(),
            [UDP_OPTION_REQ, 7, 0x01, 0x02, 0x03, 0x04, 0x05].as_slice(),
            [UDP_OPTION_REQ, 255, 0, 6, 0x01, 0x02].as_slice(),
        ] {
            assert_udp_option_length_field_error(bytes, "udp.option.req.length");
        }
    }

    #[test]
    fn udp_option_res_encode_decode_fixed_length_and_display() {
        let res = UdpOption::echo_response(0x0a0b_0c0d);
        assert_eq!(res, UdpOption::res(0x0a0b_0c0d));
        assert_eq!(res.kind(), UDP_OPTION_RES);
        assert_eq!(res.data(), &[0x0a, 0x0b, 0x0c, 0x0d]);
        assert_eq!(res.echo_response_token(), Some(0x0a0b_0c0d));
        assert_eq!(res.echo_request_token(), None);
        assert!(!res.uses_extended_length());
        assert_eq!(res.encoded_len(), UDP_OPTION_RES_LEN);
        assert_eq!(
            res.encode().unwrap(),
            vec![
                UDP_OPTION_RES,
                UDP_OPTION_RES_LEN as u8,
                0x0a,
                0x0b,
                0x0c,
                0x0d
            ]
        );
        assert_eq!(res.to_string(), "RES(token=0x0a0b0c0d)");

        let decoded =
            UdpOption::decode_all(&[UDP_OPTION_RES, UDP_OPTION_RES_LEN as u8, 10, 11, 12, 13])
                .unwrap();
        assert_eq!(decoded, vec![res.clone()]);

        let udp_options = UdpOptions::from_bytes([UDP_OPTION_RES, 6, 0x0a, 0x0b, 0x0c, 0x0d]);
        assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
        assert_eq!(udp_options.options(), &[res.clone()]);
        assert!(udp_options
            .inspection_fields()
            .iter()
            .any(|(name, value)| *name == "options" && value == "RES(token=0x0a0b0c0d)"));

        let typed = UdpOptions::from_options(vec![res]).unwrap();
        assert_eq!(
            typed.as_bytes(),
            &[UDP_OPTION_RES, 6, 0x0a, 0x0b, 0x0c, 0x0d]
        );
        assert_eq!(typed.status(), UdpOptionStatus::Valid);
    }

    #[test]
    fn udp_option_res_malformed_lengths_are_rejected() {
        for bytes in [
            [UDP_OPTION_RES, 5, 0x0a, 0x0b, 0x0c].as_slice(),
            [UDP_OPTION_RES, 7, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e].as_slice(),
            [UDP_OPTION_RES, 255, 0, 6, 0x0a, 0x0b].as_slice(),
        ] {
            assert_udp_option_length_field_error(bytes, "udp.option.res.length");
        }
    }

    #[test]
    fn udp_option_time_encode_decode_fixed_length_and_display() {
        let time = UdpOption::timestamp(0x0102_0304, 0x0a0b_0c0d);
        assert_eq!(time, UdpOption::time(0x0102_0304, 0x0a0b_0c0d));
        assert_eq!(time.kind(), UDP_OPTION_TIME);
        assert_eq!(
            time.data(),
            &[0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d]
        );
        assert_eq!(time.timestamp_values(), Some((0x0102_0304, 0x0a0b_0c0d)));
        assert_eq!(time.echo_request_token(), None);
        assert_eq!(time.echo_response_token(), None);
        assert!(!time.uses_extended_length());
        assert_eq!(time.encoded_len(), UDP_OPTION_TIME_LEN);
        assert_eq!(
            time.encode().unwrap(),
            vec![
                UDP_OPTION_TIME,
                UDP_OPTION_TIME_LEN as u8,
                0x01,
                0x02,
                0x03,
                0x04,
                0x0a,
                0x0b,
                0x0c,
                0x0d
            ]
        );
        assert_eq!(time.to_string(), "TIME(tsval=0x01020304,tsecr=0x0a0b0c0d)");

        let decoded = UdpOption::decode_all(&[
            UDP_OPTION_TIME,
            UDP_OPTION_TIME_LEN as u8,
            1,
            2,
            3,
            4,
            10,
            11,
            12,
            13,
        ])
        .unwrap();
        assert_eq!(decoded, vec![time.clone()]);

        let udp_options = UdpOptions::from_bytes([
            UDP_OPTION_TIME,
            10,
            0x01,
            0x02,
            0x03,
            0x04,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
        ]);
        assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
        assert_eq!(udp_options.options(), &[time.clone()]);
        assert!(udp_options.inspection_fields().iter().any(|(name, value)| {
            *name == "options" && value == "TIME(tsval=0x01020304,tsecr=0x0a0b0c0d)"
        }));

        let typed = UdpOptions::from_options(vec![time]).unwrap();
        assert_eq!(
            typed.as_bytes(),
            &[
                UDP_OPTION_TIME,
                10,
                0x01,
                0x02,
                0x03,
                0x04,
                0x0a,
                0x0b,
                0x0c,
                0x0d
            ]
        );
        assert_eq!(typed.status(), UdpOptionStatus::Valid);
    }

    #[test]
    fn udp_option_time_zero_values_are_explicitly_preserved() {
        let request = UdpOption::timestamp(0, 0);
        assert_eq!(request.timestamp_values(), Some((0, 0)));
        assert_eq!(
            request.encode().unwrap(),
            vec![
                UDP_OPTION_TIME,
                UDP_OPTION_TIME_LEN as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ]
        );
        assert_eq!(
            request.to_string(),
            "TIME(tsval=0x00000000,tsecr=0x00000000)"
        );
    }

    #[test]
    fn udp_option_time_malformed_lengths_are_rejected() {
        for bytes in [
            [UDP_OPTION_TIME, 9, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c].as_slice(),
            [
                UDP_OPTION_TIME,
                11,
                0x01,
                0x02,
                0x03,
                0x04,
                0x0a,
                0x0b,
                0x0c,
                0x0d,
                0x00,
            ]
            .as_slice(),
            [
                UDP_OPTION_TIME,
                255,
                0,
                10,
                0x01,
                0x02,
                0x03,
                0x04,
                0x0a,
                0x0b,
            ]
            .as_slice(),
        ] {
            assert_udp_option_length_field_error(bytes, "udp.option.time.length");
        }
    }

    #[test]
    fn udp_option_exp_encode_decode_variable_length_and_display() {
        let empty_data: &[u8] = &[];
        let empty = UdpOption::experimental(0x1234, empty_data);
        assert_eq!(empty, UdpOption::exp(0x1234, empty_data));
        assert_eq!(empty.kind(), UDP_OPTION_EXP);
        assert_eq!(empty.data(), &[0x12, 0x34]);
        assert_eq!(empty.experiment_id(), Some(0x1234));
        assert_eq!(empty.experiment_data(), Some(empty_data));
        assert!(!empty.is_unsafe());
        assert!(!empty.uses_extended_length());
        assert_eq!(empty.encoded_len(), 4);
        assert_eq!(empty.encode().unwrap(), vec![UDP_OPTION_EXP, 4, 0x12, 0x34]);
        assert_eq!(empty.to_string(), "EXP(exid=0x1234,data=empty,safety=SAFE)");
        assert_eq!(
            UdpOption::decode_all(&[UDP_OPTION_EXP, 4, 0x12, 0x34]).unwrap(),
            vec![empty.clone()]
        );

        let non_empty = UdpOption::experimental(0xabcd, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(non_empty.data(), &[0xab, 0xcd, 0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(non_empty.experiment_id(), Some(0xabcd));
        assert_eq!(
            non_empty.experiment_data(),
            Some([0xde, 0xad, 0xbe, 0xef].as_slice())
        );
        assert!(!non_empty.is_unsafe());
        assert_eq!(
            non_empty.encode().unwrap(),
            vec![UDP_OPTION_EXP, 8, 0xab, 0xcd, 0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            non_empty.to_string(),
            "EXP(exid=0xabcd,data=de ad be ef,safety=SAFE)"
        );

        let udp_options =
            UdpOptions::from_bytes([UDP_OPTION_EXP, 8, 0xab, 0xcd, 0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
        assert_eq!(udp_options.options(), &[non_empty.clone()]);
        assert!(udp_options.inspection_fields().iter().any(|(name, value)| {
            *name == "options" && value == "EXP(exid=0xabcd,data=de ad be ef,safety=SAFE)"
        }));

        let typed = UdpOptions::from_options(vec![non_empty]).unwrap();
        assert_eq!(
            typed.as_bytes(),
            &[UDP_OPTION_EXP, 8, 0xab, 0xcd, 0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(typed.status(), UdpOptionStatus::Valid);

        let long = UdpOption::experimental(0xbeef, vec![0x5a; 251]);
        assert!(long.uses_extended_length());
        let encoded = long.encode().unwrap();
        assert_eq!(
            &encoded[..6],
            &[UDP_OPTION_EXP, 255, 0x01, 0x01, 0xbe, 0xef]
        );
    }

    #[test]
    fn udp_option_exp_malformed_lengths_are_rejected() {
        for bytes in [
            [UDP_OPTION_EXP, 3, 0x12].as_slice(),
            [UDP_OPTION_EXP, 255, 0, 4].as_slice(),
            [UDP_OPTION_EXP, 255, 0, 5, 0x12].as_slice(),
        ] {
            assert_udp_option_length_field_error(bytes, "udp.option.exp.length");
        }

        let malformed = UdpOption::Experimental {
            exid_and_data: vec![0x12],
        };
        assert_udp_option_encode_field_error(malformed, "udp.option.exp.length");
    }

    #[test]
    fn udp_option_uexp_encode_decode_variable_length_and_safety() {
        let empty_data: &[u8] = &[];
        let empty = UdpOption::unsafe_experimental(0x5678, empty_data);
        assert_eq!(empty, UdpOption::uexp(0x5678, empty_data));
        assert_eq!(empty.kind(), UDP_OPTION_UEXP);
        assert_eq!(empty.data(), &[0x56, 0x78]);
        assert_eq!(empty.experiment_id(), Some(0x5678));
        assert_eq!(empty.experiment_data(), Some(empty_data));
        assert!(empty.is_unsafe());
        assert!(!empty.uses_extended_length());
        assert_eq!(empty.encoded_len(), 4);
        assert_eq!(
            empty.encode().unwrap(),
            vec![UDP_OPTION_UEXP, 4, 0x56, 0x78]
        );
        assert_eq!(
            empty.to_string(),
            "UEXP(exid=0x5678,data=empty,safety=UNSAFE)"
        );
        assert_eq!(
            UdpOption::decode_all(&[UDP_OPTION_UEXP, 4, 0x56, 0x78]).unwrap(),
            vec![empty.clone()]
        );

        let generic_unsafe = UdpOption::generic(UDP_OPTION_UEXP, [0x56, 0x78]);
        assert!(generic_unsafe.is_unsafe());

        let non_empty = UdpOption::unsafe_experimental(0xcafe, [0x01, 0x02, 0x03]);
        assert_eq!(non_empty.data(), &[0xca, 0xfe, 0x01, 0x02, 0x03]);
        assert_eq!(non_empty.experiment_id(), Some(0xcafe));
        assert_eq!(
            non_empty.experiment_data(),
            Some([0x01, 0x02, 0x03].as_slice())
        );
        assert!(non_empty.is_unsafe());
        assert_eq!(
            non_empty.encode().unwrap(),
            vec![UDP_OPTION_UEXP, 7, 0xca, 0xfe, 0x01, 0x02, 0x03]
        );
        assert_eq!(
            non_empty.to_string(),
            "UEXP(exid=0xcafe,data=01 02 03,safety=UNSAFE)"
        );

        let udp_options =
            UdpOptions::from_bytes([UDP_OPTION_UEXP, 7, 0xca, 0xfe, 0x01, 0x02, 0x03]);
        assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
        assert_eq!(udp_options.options(), &[non_empty.clone()]);
        assert!(udp_options.inspection_fields().iter().any(|(name, value)| {
            *name == "options" && value == "UEXP(exid=0xcafe,data=01 02 03,safety=UNSAFE)"
        }));

        let typed = UdpOptions::from_options(vec![non_empty]).unwrap();
        assert_eq!(
            typed.as_bytes(),
            &[UDP_OPTION_UEXP, 7, 0xca, 0xfe, 0x01, 0x02, 0x03]
        );
        assert_eq!(typed.status(), UdpOptionStatus::Valid);

        let long = UdpOption::unsafe_experimental(0xace0, vec![0x77; 251]);
        assert!(long.uses_extended_length());
        let encoded = long.encode().unwrap();
        assert_eq!(
            &encoded[..6],
            &[UDP_OPTION_UEXP, 255, 0x01, 0x01, 0xac, 0xe0]
        );
    }

    #[test]
    fn udp_option_uexp_malformed_lengths_are_rejected() {
        for bytes in [
            [UDP_OPTION_UEXP, 3, 0x56].as_slice(),
            [UDP_OPTION_UEXP, 255, 0, 4].as_slice(),
            [UDP_OPTION_UEXP, 255, 0, 5, 0x56].as_slice(),
        ] {
            assert_udp_option_length_field_error(bytes, "udp.option.uexp.length");
        }

        let malformed = UdpOption::UnsafeExperimental {
            exid_and_data: vec![0x56],
        };
        assert_udp_option_encode_field_error(malformed, "udp.option.uexp.length");
    }

    #[test]
    fn udp_option_unknown_safe_roundtrips_and_reports_metadata() {
        let option = UdpOption::generic(UDP_OPTION_UNASSIGNED_SAFE_START, [0xaa, 0xbb]);
        let encoded = [
            UDP_OPTION_UNASSIGNED_SAFE_START,
            4,
            0xaa,
            0xbb,
            UDP_OPTION_EOL,
        ];

        assert_eq!(option.kind_class(), UdpOptionKindClass::UnassignedSafe);
        assert!(!option.is_unsafe());
        assert!(!option.is_unsupported());
        assert_eq!(
            option.to_string(),
            "Generic(kind=10,len=4,class=UnassignedSafe,safety=SAFE)"
        );

        let udp_options = UdpOptions::from_bytes(encoded);
        assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
        assert_eq!(
            udp_options.options(),
            &[option.clone(), UdpOption::EndOfList]
        );
        assert_eq!(udp_options.as_bytes(), &encoded);
        assert!(udp_options.summary().contains("UnassignedSafe"));
        assert!(udp_options.summary().contains("safety=SAFE"));

        let typed = UdpOptions::from_options(vec![option, UdpOption::EndOfList]).unwrap();
        assert_eq!(typed.as_bytes(), &encoded);
        assert_eq!(typed.status(), UdpOptionStatus::Valid);
    }

    #[test]
    fn udp_option_unknown_unsafe_roundtrips_and_reports_unsupported_metadata() {
        let option = UdpOption::generic(UDP_OPTION_UNASSIGNED_UNSAFE_START, [0xde, 0xad]);
        let encoded = [
            UDP_OPTION_UNASSIGNED_UNSAFE_START,
            4,
            0xde,
            0xad,
            UDP_OPTION_MDS,
            4,
            0x05,
            0xdc,
        ];

        assert_eq!(option.kind_class(), UdpOptionKindClass::UnassignedUnsafe);
        assert!(option.is_unsafe());
        assert!(option.is_unsupported());
        assert_eq!(
            option.to_string(),
            "Generic(kind=194,len=4,class=UnassignedUnsafe,safety=UNSAFE,support=unsupported)"
        );

        let udp_options = UdpOptions::from_bytes(encoded);
        assert_eq!(udp_options.status(), UdpOptionStatus::Unsupported);
        assert_eq!(udp_options.options(), &[option.clone()]);
        assert_eq!(udp_options.as_bytes(), &encoded);
        assert!(udp_options.summary().contains("status=Unsupported"));
        assert!(udp_options.summary().contains("UnassignedUnsafe"));
        assert!(udp_options.summary().contains("safety=UNSAFE"));

        let packet = Ipv4::new().src(src()).dst(dst()).id(0x2246)
            / Udp::new().sport(1234).dport(4321)
            / Raw::from_bytes([0x55])
            / UdpOptions::from_options(vec![option]).unwrap();
        let compiled = packet.compile().unwrap();
        let decoded =
            Packet::decode_from_l3(crate::NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let decoded_options = decoded.layer::<UdpOptions>().unwrap();
        assert_eq!(decoded_options.status(), UdpOptionStatus::Unsupported);
        assert_eq!(
            decoded_options.options(),
            &[UdpOption::generic(
                UDP_OPTION_UNASSIGNED_UNSAFE_START,
                [0xde, 0xad],
            )]
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    #[test]
    fn udp_option_frag_unsupported_preserves_valid_and_malformed_bytes() {
        let frag10 = UdpOption::generic(
            UDP_OPTION_FRAG,
            [0x00, 0x01, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0xdd],
        );
        let frag12 = UdpOption::generic(
            UDP_OPTION_FRAG,
            [0x00, 0x02, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        );

        assert_eq!(frag10.encoded_len(), UDP_OPTION_FRAG_SHORT_LEN);
        assert_eq!(frag12.encoded_len(), UDP_OPTION_FRAG_LONG_LEN);
        assert_eq!(frag10.kind_class(), UdpOptionKindClass::KnownSafe);
        assert!(!frag10.is_unsafe());
        assert!(frag10.is_unsupported());
        assert_eq!(
            frag10.to_string(),
            "Generic(kind=3,len=10,class=KnownSafe,safety=SAFE,support=unsupported)"
        );

        let valid10 = UdpOptions::from_options(vec![frag10.clone()]).unwrap();
        assert_eq!(valid10.status(), UdpOptionStatus::Unsupported);
        assert_eq!(valid10.options(), &[frag10.clone()]);
        assert_eq!(
            valid10.as_bytes(),
            &[
                UDP_OPTION_FRAG,
                UDP_OPTION_FRAG_SHORT_LEN as u8,
                0x00,
                0x01,
                0x00,
                0x03,
                0xaa,
                0xbb,
                0xcc,
                0xdd
            ]
        );

        let valid12 = UdpOptions::from_options(vec![frag12.clone()]).unwrap();
        assert_eq!(valid12.status(), UdpOptionStatus::Unsupported);
        assert_eq!(valid12.options(), &[frag12.clone()]);

        let malformed_short = [UDP_OPTION_FRAG, 9, 0x00, 0x01, 0x00, 0x03, 0xaa, 0xbb, 0xcc];
        let malformed = UdpOptions::from_bytes(malformed_short);
        assert_eq!(malformed.status(), UdpOptionStatus::Malformed);
        assert_eq!(malformed.as_bytes(), &malformed_short);
        assert_eq!(
            malformed.options(),
            &[UdpOption::generic(
                UDP_OPTION_FRAG,
                [0x00, 0x01, 0x00, 0x03, 0xaa, 0xbb, 0xcc],
            )]
        );

        let malformed_extended = [
            UDP_OPTION_FRAG,
            255,
            0,
            10,
            0x00,
            0x01,
            0x00,
            0x03,
            0xaa,
            0xbb,
        ];
        let malformed = UdpOptions::from_bytes(malformed_extended);
        assert_eq!(malformed.status(), UdpOptionStatus::Malformed);
        assert_eq!(malformed.as_bytes(), &malformed_extended);
        assert_eq!(
            malformed.options(),
            &[UdpOption::ExtendedGeneric {
                kind: UDP_OPTION_FRAG,
                data: vec![0x00, 0x01, 0x00, 0x03, 0xaa, 0xbb],
            }]
        );

        let user_payload = [0x55, 0x66];
        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2247)
            / Udp::new().sport(1234).dport(4321)
            / Raw::from_bytes(user_payload)
            / UdpOptions::from_options(vec![frag12.clone()]).unwrap())
        .compile()
        .unwrap();
        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let raw_layers = decoded.layers::<Raw>().collect::<Vec<_>>();
        let decoded_options = decoded.layer::<UdpOptions>().unwrap();

        assert_eq!(raw_layers.len(), 1);
        assert_eq!(raw_layers[0].as_bytes(), user_payload);
        assert_eq!(decoded_options.status(), UdpOptionStatus::Unsupported);
        assert_eq!(decoded_options.options(), &[frag12]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn udp_option_metadata_classifies_registry_ranges() {
        assert_eq!(
            udp_option_kind_class(UDP_OPTION_MDS),
            UdpOptionKindClass::KnownSafe
        );
        assert_eq!(
            udp_option_kind_class(UDP_OPTION_FRAG),
            UdpOptionKindClass::KnownSafe
        );
        assert!(udp_option_kind_is_unsupported(UDP_OPTION_FRAG));

        assert_eq!(
            udp_option_kind_class(UDP_OPTION_AUTH),
            UdpOptionKindClass::ReservedSafe
        );
        assert!(!udp_option_kind_is_unsafe(UDP_OPTION_AUTH));
        assert!(!udp_option_kind_is_unsupported(UDP_OPTION_AUTH));

        assert_eq!(
            udp_option_kind_class(UDP_OPTION_RESERVED_SAFE_START),
            UdpOptionKindClass::ReservedSafe
        );
        assert_eq!(
            udp_option_kind_class(UDP_OPTION_UCMP),
            UdpOptionKindClass::ReservedUnsafe
        );
        assert!(udp_option_kind_is_unsafe(UDP_OPTION_UCMP));
        assert!(udp_option_kind_is_unsupported(UDP_OPTION_UCMP));

        assert_eq!(
            udp_option_kind_class(UDP_OPTION_UNASSIGNED_SAFE_START),
            UdpOptionKindClass::UnassignedSafe
        );
        assert_eq!(
            udp_option_kind_class(UDP_OPTION_UNASSIGNED_UNSAFE_START),
            UdpOptionKindClass::UnassignedUnsafe
        );
        assert!(udp_option_kind_is_unsupported(
            UDP_OPTION_UNASSIGNED_UNSAFE_START
        ));

        assert_eq!(
            udp_option_kind_class(UDP_OPTION_EXP),
            UdpOptionKindClass::ExperimentalSafe
        );
        assert_eq!(
            udp_option_kind_class(UDP_OPTION_UEXP),
            UdpOptionKindClass::ExperimentalUnsafe
        );
        assert!(!udp_option_kind_is_unsupported(UDP_OPTION_UEXP));

        assert_eq!(
            udp_option_kind_class(UDP_OPTION_RESERVED_UNSAFE),
            UdpOptionKindClass::ReservedUnsafe
        );
        assert!(udp_option_kind_is_unsupported(UDP_OPTION_RESERVED_UNSAFE));
    }

    #[test]
    fn udp_options_show_includes_time_option() {
        let packet = Ipv4::new().src(src()).dst(dst()).id(0x2241)
            / Udp::new().sport(1234).dport(4321)
            / Raw::from_bytes([0xde, 0xad])
            / UdpOptions::from_options(vec![UdpOption::timestamp(0x0102_0304, 0)]).unwrap();

        let show = packet.show();
        assert!(show.contains("UdpOptions"));
        assert!(show.contains("options: TIME(tsval=0x01020304,tsecr=0x00000000)"));
    }

    #[test]
    fn udp_option_apc_valid_auto_fill_decodes_valid_status() {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2240)
            / Udp::new().sport(1234).dport(4321)
            / Raw::from_bytes(payload)
            / UdpOptions::new().additional_payload_checksum())
        .compile()
        .unwrap();

        assert!(udp_surplus_checksum_valid(bytes.as_bytes()));

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp_options = decoded.layer::<UdpOptions>().unwrap();
        assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
        assert_eq!(apc_checksum_value(udp_options), crc32c(&payload));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn udp_option_apc_invalid_crc_reports_status() {
        let payload = [0x10, 0x20, 0x30, 0x40];
        let wrong = crc32c(&payload) ^ 0x0000_0001;
        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2241)
            / Udp::new().sport(1234).dport(4321)
            / Raw::from_bytes(payload)
            / UdpOptions::new().additional_payload_checksum_value(wrong))
        .compile()
        .unwrap();

        assert!(udp_surplus_checksum_valid(bytes.as_bytes()));

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp_options = decoded.layer::<UdpOptions>().unwrap();
        assert_eq!(
            udp_options.status(),
            UdpOptionStatus::AdditionalPayloadChecksumInvalid
        );
        assert_eq!(apc_checksum_value(udp_options), wrong);
    }

    #[test]
    fn udp_option_apc_explicit_override_survives_compile() {
        let override_checksum = 0x1234_5678;
        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2242)
            / Udp::new().sport(1234).dport(4321)
            / Raw::from_bytes([0xaa, 0xbb])
            / UdpOptions::new().additional_payload_checksum_value(override_checksum))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp_options = decoded.layer::<UdpOptions>().unwrap();
        assert_eq!(
            &udp_options.as_bytes()[..UDP_OPTION_APC_LEN],
            &[
                UDP_OPTION_APC,
                UDP_OPTION_APC_LEN as u8,
                0x12,
                0x34,
                0x56,
                0x78
            ]
        );
        assert_eq!(apc_checksum_value(udp_options), override_checksum);
        assert_eq!(
            udp_options.status(),
            UdpOptionStatus::AdditionalPayloadChecksumInvalid
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn udp_option_apc_zero_length_user_data() {
        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2243)
            / Udp::new().sport(1234).dport(4321)
            / UdpOptions::new().additional_payload_checksum())
        .compile()
        .unwrap();

        assert_eq!(udp_length(bytes.as_bytes()), UDP_HEADER_LEN);

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp_options = decoded.layer::<UdpOptions>().unwrap();
        assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
        assert_eq!(apc_checksum_value(udp_options), crc32c(&[]));
        assert!(decoded.layers::<Raw>().next().is_none());
    }

    #[test]
    fn udp_option_apc_odd_length_user_data() {
        let payload = [0xaa, 0xbb, 0xcc];
        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2244)
            / Udp::new().sport(1234).dport(4321)
            / Raw::from_bytes(payload)
            / UdpOptions::new().additional_payload_checksum())
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp_options = decoded.layer::<UdpOptions>().unwrap();
        assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
        assert_eq!(udp_options.alignment_bytes(), Some([0].as_slice()));
        assert_eq!(apc_checksum_value(udp_options), crc32c(&payload));
    }

    #[test]
    fn udp_options_apc_payload_boundary_uses_user_data_only() {
        let payload = [0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64];
        let udp_options = UdpOptions::new()
            .additional_payload_checksum()
            .udp_option(UdpOption::NoOperation)
            .unwrap()
            .udp_option(UdpOption::EndOfList)
            .unwrap();
        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2245)
            / Udp::new().sport(1234).dport(4321)
            / Raw::from_bytes(payload)
            / udp_options)
            .compile()
            .unwrap();

        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp_options = decoded.layer::<UdpOptions>().unwrap();
        let apc = apc_checksum_value(udp_options);

        assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
        assert_eq!(
            &bytes.as_bytes()[20 + UDP_HEADER_LEN..udp_surplus_start(bytes.as_bytes())],
            payload.as_slice()
        );
        assert_eq!(apc, crc32c(&payload));

        let mut payload_plus_options = payload.to_vec();
        payload_plus_options.extend_from_slice(udp_options.as_bytes());
        assert_ne!(apc, crc32c(&payload_plus_options));
    }

    #[test]
    fn udp_option_length_parses_one_byte_short_and_extended_envelopes() {
        let decoded = UdpOption::decode_all(&[UDP_OPTION_NOP, UDP_OPTION_EOL, 0, 0]).unwrap();
        assert_eq!(decoded, vec![UdpOption::NoOperation, UdpOption::EndOfList]);

        let decoded = UdpOption::decode_all(&[UDP_OPTION_MDS, 4, 0x05, 0xb4]).unwrap();
        assert_eq!(decoded, vec![UdpOption::maximum_datagram_size(0x05b4)]);

        let decoded = UdpOption::decode_all(&[UDP_OPTION_EXP, 255, 0, 6, 0x12, 0x34]).unwrap();
        assert_eq!(
            decoded,
            vec![UdpOption::ExtendedExperimental {
                exid_and_data: vec![0x12, 0x34]
            }]
        );
    }

    #[test]
    fn udp_option_length_reports_short_envelope_errors() {
        assert_udp_option_length_buffer_error(&[UDP_OPTION_MDS], "udp option length", 2, 1);
        assert_udp_option_length_field_error(&[UDP_OPTION_MDS, 0], "udp.option.length");
        assert_udp_option_length_field_error(&[UDP_OPTION_MDS, 1], "udp.option.length");
        assert_udp_option_length_buffer_error(
            &[UDP_OPTION_MDS, 4, 0xaa],
            "udp option payload",
            4,
            3,
        );
    }

    #[test]
    fn udp_option_length_reports_extended_envelope_errors() {
        assert_udp_option_length_buffer_error(
            &[UDP_OPTION_EXP, 255],
            "udp option extended length",
            4,
            2,
        );
        assert_udp_option_length_buffer_error(
            &[UDP_OPTION_EXP, 255, 0],
            "udp option extended length",
            4,
            3,
        );
        assert_udp_option_length_field_error(
            &[UDP_OPTION_EXP, 255, 0, 0],
            "udp.option.extended_length",
        );
        assert_udp_option_length_field_error(
            &[UDP_OPTION_EXP, 255, 0, 1],
            "udp.option.extended_length",
        );
        assert_udp_option_length_field_error(
            &[UDP_OPTION_EXP, 255, 0, 3],
            "udp.option.extended_length",
        );
        assert_udp_option_length_buffer_error(
            &[UDP_OPTION_EXP, 255, 0, 6, 0xaa],
            "udp option extended payload",
            6,
            5,
        );
    }

    #[test]
    fn udp_option_length_preserves_valid_prefix_before_malformed_envelope() {
        let bytes = [UDP_OPTION_NOP, UDP_OPTION_MDS, 4, 0xaa];
        let udp_options = UdpOptions::from_bytes(bytes);

        assert_eq!(udp_options.status(), UdpOptionStatus::Malformed);
        assert_eq!(udp_options.as_bytes(), &bytes);
        assert_eq!(udp_options.options(), &[UdpOption::NoOperation]);
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
                assert_eq!(context, "udp option extended payload");
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
                UdpOption::ExtendedExperimental {
                    exid_and_data: vec![0x12, 0x34]
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
            &((20 + UDP_HEADER_LEN + dns_len + udp_surplus(bytes.as_bytes()).len()) as u16)
                .to_be_bytes()
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
            &((20 + UDP_HEADER_LEN + dhcp_len + udp_surplus(bytes.as_bytes()).len()) as u16)
                .to_be_bytes()
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
            &((20 + UDP_HEADER_LEN + 3 + udp_surplus(bytes.as_bytes()).len()) as u16).to_be_bytes()
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
        assert_eq!(udp_options.status(), UdpOptionStatus::Ignored);
        assert_eq!(udp_options.alignment_bytes(), Some([0xde].as_slice()));
        assert_eq!(udp_options.option_checksum_value(), Some(0xadbe));
        assert_eq!(udp_options.as_bytes(), &[0xef]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
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
