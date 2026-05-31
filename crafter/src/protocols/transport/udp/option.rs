use core::fmt;

use crate::error::{CrafterError, Result};

use super::super::common::hex_bytes;
use super::constants::*;

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

pub(super) fn encode_udp_options(options: &[UdpOption]) -> Result<Vec<u8>> {
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

pub(super) fn udp_option_is_malformed_apc(option: &UdpOption) -> bool {
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

pub(super) fn udp_option_is_malformed_frag(option: &UdpOption) -> bool {
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

pub(super) fn udp_options_inspection_summary(options: &[UdpOption]) -> String {
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
