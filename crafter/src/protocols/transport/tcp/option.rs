//! TCP option types, encoding, decoding, and classification helpers.

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};

use super::constants::{
    TCP_EDO_HEADER_AND_SEGMENT_LEN, TCP_EDO_HEADER_LEN, TCP_EDO_REQUEST_LEN, TCP_OPTION_EDO,
    TCP_OPTION_EOL, TCP_OPTION_FAST_OPEN, TCP_OPTION_MPTCP, TCP_OPTION_MSS, TCP_OPTION_NOP,
    TCP_OPTION_SACK, TCP_OPTION_SACK_PERMITTED, TCP_OPTION_TIMESTAMP, TCP_OPTION_WINDOW_SCALE,
};

/// One SACK block carried by a TCP SACK option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpSackBlock {
    /// Left edge sequence number.
    pub left_edge: u32,
    /// Right edge sequence number.
    pub right_edge: u32,
}

impl TcpSackBlock {
    /// Create a SACK block.
    pub const fn new(left_edge: u32, right_edge: u32) -> Self {
        Self {
            left_edge,
            right_edge,
        }
    }
}

/// Parsed or constructible TCP Extended Data Offset value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpExtendedDataOffset {
    /// EDO request option with no payload.
    Request,
    /// EDO option carrying the extended TCP header length in 32-bit words.
    HeaderLength {
        /// Extended TCP header length in 32-bit words.
        header_length: u16,
    },
    /// EDO option carrying the extended TCP header length and TCP segment length.
    HeaderAndSegmentLength {
        /// Extended TCP header length in 32-bit words.
        header_length: u16,
        /// TCP segment length in bytes.
        segment_length: u16,
    },
}

impl TcpExtendedDataOffset {
    /// EDO option length byte.
    pub const fn option_len(self) -> u8 {
        match self {
            Self::Request => TCP_EDO_REQUEST_LEN,
            Self::HeaderLength { .. } => TCP_EDO_HEADER_LEN,
            Self::HeaderAndSegmentLength { .. } => TCP_EDO_HEADER_AND_SEGMENT_LEN,
        }
    }
}

/// Parsed or constructible TCP option.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TcpOption {
    /// End of option list.
    EndOfList,
    /// One-byte no-operation padding.
    NoOperation,
    /// Maximum segment size.
    MaximumSegmentSize(u16),
    /// Window scale shift count.
    WindowScale(u8),
    /// SACK permitted.
    SackPermitted,
    /// SACK blocks.
    Sack(Vec<TcpSackBlock>),
    /// TCP timestamp.
    Timestamp {
        /// Timestamp value.
        value: u32,
        /// Timestamp echo reply value.
        echo_reply: u32,
    },
    /// MPTCP option preserving subtype-specific bytes.
    MultipathTcp {
        /// MPTCP subtype nibble.
        subtype: u8,
        /// Bytes after the kind/length header, including the subtype byte.
        data: Vec<u8>,
    },
    /// Extended Data Offset.
    ExtendedDataOffset(TcpExtendedDataOffset),
    /// TCP Fast Open cookie bytes.
    FastOpen(Vec<u8>),
    /// Unknown or caller-defined option with a standard length byte.
    Generic {
        /// Raw option kind byte.
        kind: u8,
        /// Option payload bytes after kind and length.
        data: Vec<u8>,
    },
}

impl TcpOption {
    /// Create an end-of-option-list marker.
    pub const fn end_of_list() -> Self {
        Self::EndOfList
    }

    /// Create a no-operation padding option.
    pub const fn no_operation() -> Self {
        Self::NoOperation
    }

    /// Create an MSS option.
    pub const fn maximum_segment_size(mss: u16) -> Self {
        Self::MaximumSegmentSize(mss)
    }

    /// Compatibility alias for MSS.
    pub const fn mss(mss: u16) -> Self {
        Self::MaximumSegmentSize(mss)
    }

    /// Create a window-scale option.
    pub const fn window_scale(shift: u8) -> Self {
        Self::WindowScale(shift)
    }

    /// Create a SACK-permitted option.
    pub const fn sack_permitted() -> Self {
        Self::SackPermitted
    }

    /// Create a SACK option.
    pub fn sack(blocks: impl Into<Vec<TcpSackBlock>>) -> Self {
        Self::Sack(blocks.into())
    }

    /// Create a timestamp option.
    pub const fn timestamp(value: u32, echo_reply: u32) -> Self {
        Self::Timestamp { value, echo_reply }
    }

    /// Create a generic MPTCP option, preserving subtype-specific bytes.
    pub fn multipath_tcp(subtype: u8, data: impl Into<Vec<u8>>) -> Self {
        Self::MultipathTcp {
            subtype,
            data: data.into(),
        }
    }

    /// Create an EDO request option.
    pub const fn extended_data_offset_request() -> Self {
        Self::ExtendedDataOffset(TcpExtendedDataOffset::Request)
    }

    /// Create an EDO option with an extended header length.
    pub const fn extended_data_offset(header_length: u16) -> Self {
        Self::ExtendedDataOffset(TcpExtendedDataOffset::HeaderLength { header_length })
    }

    /// Create an EDO option with an extended header length and segment length.
    pub const fn extended_data_offset_ext(header_length: u16, segment_length: u16) -> Self {
        Self::ExtendedDataOffset(TcpExtendedDataOffset::HeaderAndSegmentLength {
            header_length,
            segment_length,
        })
    }

    /// Create a TCP Fast Open option.
    pub fn fast_open(cookie: impl Into<Vec<u8>>) -> Self {
        Self::FastOpen(cookie.into())
    }

    /// Create a caller-defined option.
    pub fn generic(kind: u8, data: impl Into<Vec<u8>>) -> Self {
        Self::Generic {
            kind,
            data: data.into(),
        }
    }

    /// Raw option kind byte.
    pub const fn kind(&self) -> u8 {
        match self {
            Self::EndOfList => TCP_OPTION_EOL,
            Self::NoOperation => TCP_OPTION_NOP,
            Self::MaximumSegmentSize(_) => TCP_OPTION_MSS,
            Self::WindowScale(_) => TCP_OPTION_WINDOW_SCALE,
            Self::SackPermitted => TCP_OPTION_SACK_PERMITTED,
            Self::Sack(_) => TCP_OPTION_SACK,
            Self::Timestamp { .. } => TCP_OPTION_TIMESTAMP,
            Self::MultipathTcp { .. } => TCP_OPTION_MPTCP,
            Self::ExtendedDataOffset(_) => TCP_OPTION_EDO,
            Self::FastOpen(_) => TCP_OPTION_FAST_OPEN,
            Self::Generic { kind, .. } => *kind,
        }
    }

    /// Encoded option length in bytes.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::EndOfList | Self::NoOperation => 1,
            Self::MaximumSegmentSize(_) => 4,
            Self::WindowScale(_) => 3,
            Self::SackPermitted => 2,
            Self::Sack(blocks) => 2 + blocks.len() * 8,
            Self::Timestamp { .. } => 10,
            Self::MultipathTcp { data, .. } => 2 + data.len().max(1),
            Self::ExtendedDataOffset(edo) => edo.option_len() as usize,
            Self::FastOpen(cookie) => 2 + cookie.len(),
            Self::Generic { data, .. } => 2 + data.len(),
        }
    }

    /// Encode this option to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let len = self.encoded_len();
        if len > u8::MAX as usize {
            return Err(CrafterError::invalid_field_value(
                "tcp.option.length",
                "TCP option length must fit in one byte",
            ));
        }

        let mut bytes = Vec::with_capacity(len);
        match self {
            Self::EndOfList => bytes.push(TCP_OPTION_EOL),
            Self::NoOperation => bytes.push(TCP_OPTION_NOP),
            Self::MaximumSegmentSize(mss) => {
                bytes.extend_from_slice(&[TCP_OPTION_MSS, 4]);
                bytes.extend_from_slice(&mss.to_be_bytes());
            }
            Self::WindowScale(shift) => {
                bytes.extend_from_slice(&[TCP_OPTION_WINDOW_SCALE, 3, *shift]);
            }
            Self::SackPermitted => {
                bytes.extend_from_slice(&[TCP_OPTION_SACK_PERMITTED, 2]);
            }
            Self::Sack(blocks) => {
                bytes.extend_from_slice(&[TCP_OPTION_SACK, len as u8]);
                for block in blocks {
                    bytes.extend_from_slice(&block.left_edge.to_be_bytes());
                    bytes.extend_from_slice(&block.right_edge.to_be_bytes());
                }
            }
            Self::Timestamp { value, echo_reply } => {
                bytes.extend_from_slice(&[TCP_OPTION_TIMESTAMP, 10]);
                bytes.extend_from_slice(&value.to_be_bytes());
                bytes.extend_from_slice(&echo_reply.to_be_bytes());
            }
            Self::MultipathTcp { subtype, data } => {
                if *subtype > 0x0f {
                    return Err(CrafterError::invalid_field_value(
                        "tcp.option.mptcp.subtype",
                        "MPTCP subtype must fit in four bits",
                    ));
                }
                bytes.extend_from_slice(&[TCP_OPTION_MPTCP, len as u8]);
                if let Some((first, rest)) = data.split_first() {
                    bytes.push((subtype << 4) | (first & 0x0f));
                    bytes.extend_from_slice(rest);
                } else {
                    bytes.push(subtype << 4);
                }
            }
            Self::ExtendedDataOffset(edo) => {
                bytes.extend_from_slice(&[TCP_OPTION_EDO, edo.option_len()]);
                match edo {
                    TcpExtendedDataOffset::Request => {}
                    TcpExtendedDataOffset::HeaderLength { header_length } => {
                        bytes.extend_from_slice(&header_length.to_be_bytes());
                    }
                    TcpExtendedDataOffset::HeaderAndSegmentLength {
                        header_length,
                        segment_length,
                    } => {
                        bytes.extend_from_slice(&header_length.to_be_bytes());
                        bytes.extend_from_slice(&segment_length.to_be_bytes());
                    }
                }
            }
            Self::FastOpen(cookie) => {
                bytes.extend_from_slice(&[TCP_OPTION_FAST_OPEN, len as u8]);
                bytes.extend_from_slice(cookie);
            }
            Self::Generic { kind, data } => {
                if *kind == TCP_OPTION_EOL || *kind == TCP_OPTION_NOP {
                    return Err(CrafterError::invalid_field_value(
                        "tcp.option.kind",
                        "EOL and NOP options do not carry a length byte",
                    ));
                }
                bytes.extend_from_slice(&[*kind, len as u8]);
                bytes.extend_from_slice(data);
            }
        }

        Ok(bytes)
    }

    /// Decode all options from a raw TCP option byte slice.
    pub fn decode_all(bytes: &[u8]) -> Result<Vec<Self>> {
        TcpOptionIter::new(bytes).collect()
    }
}

/// Iterator over encoded TCP options.
#[derive(Debug, Clone)]
pub struct TcpOptionIter<'a> {
    bytes: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> TcpOptionIter<'a> {
    /// Create an iterator over raw TCP option bytes.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            done: false,
        }
    }
}

impl Iterator for TcpOptionIter<'_> {
    type Item = Result<TcpOption>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset >= self.bytes.len() {
            return None;
        }

        let start = self.offset;
        let kind = self.bytes[start];
        match kind {
            TCP_OPTION_EOL => {
                self.done = true;
                self.offset = self.bytes.len();
                Some(Ok(TcpOption::EndOfList))
            }
            TCP_OPTION_NOP => {
                self.offset += 1;
                Some(Ok(TcpOption::NoOperation))
            }
            _ => {
                if start + 2 > self.bytes.len() {
                    self.done = true;
                    return Some(Err(CrafterError::buffer_too_short(
                        "tcp option",
                        start + 2,
                        self.bytes.len(),
                    )));
                }

                let len = self.bytes[start + 1] as usize;
                if len < 2 {
                    self.done = true;
                    return Some(Err(CrafterError::invalid_field_value(
                        "tcp.option.length",
                        "option length must be at least 2 bytes",
                    )));
                }
                if start + len > self.bytes.len() {
                    self.done = true;
                    return Some(Err(CrafterError::buffer_too_short(
                        "tcp option",
                        start + len,
                        self.bytes.len(),
                    )));
                }

                let option_bytes = &self.bytes[start..start + len];
                self.offset += len;
                Some(decode_tcp_option(option_bytes))
            }
        }
    }
}

pub(crate) fn validate_tcp_options(options: &[u8]) -> Result<()> {
    for option in TcpOptionIter::new(options) {
        option?;
    }
    Ok(())
}

fn decode_tcp_option(bytes: &[u8]) -> Result<TcpOption> {
    let kind = bytes[0];
    let data = &bytes[2..];
    match kind {
        TCP_OPTION_MSS => {
            validate_tcp_option_len("tcp.option.mss", bytes.len(), 4)?;
            Ok(TcpOption::MaximumSegmentSize(read_u16_be(data)?))
        }
        TCP_OPTION_WINDOW_SCALE => {
            validate_tcp_option_len("tcp.option.window_scale", bytes.len(), 3)?;
            Ok(TcpOption::WindowScale(data[0]))
        }
        TCP_OPTION_SACK_PERMITTED => {
            validate_tcp_option_len("tcp.option.sack_permitted", bytes.len(), 2)?;
            Ok(TcpOption::SackPermitted)
        }
        TCP_OPTION_SACK => decode_tcp_sack_option(data, bytes.len()),
        TCP_OPTION_TIMESTAMP => {
            validate_tcp_option_len("tcp.option.timestamp", bytes.len(), 10)?;
            Ok(TcpOption::Timestamp {
                value: read_u32_be(&data[0..4])?,
                echo_reply: read_u32_be(&data[4..8])?,
            })
        }
        TCP_OPTION_MPTCP => {
            if data.is_empty() {
                return Err(CrafterError::invalid_field_value(
                    "tcp.option.mptcp",
                    "MPTCP option must include a subtype byte",
                ));
            }
            Ok(TcpOption::MultipathTcp {
                subtype: data[0] >> 4,
                data: data.to_vec(),
            })
        }
        TCP_OPTION_EDO => decode_tcp_edo_option(data, bytes.len()),
        TCP_OPTION_FAST_OPEN => Ok(TcpOption::FastOpen(data.to_vec())),
        _ => Ok(TcpOption::Generic {
            kind,
            data: data.to_vec(),
        }),
    }
}

fn decode_tcp_sack_option(data: &[u8], len: usize) -> Result<TcpOption> {
    if len < 10 || (len - 2) % 8 != 0 {
        return Err(CrafterError::invalid_field_value(
            "tcp.option.sack",
            "SACK option payload must contain one or more 8-byte blocks",
        ));
    }

    let mut blocks = Vec::with_capacity((len - 2) / 8);
    for chunk in data.chunks_exact(8) {
        blocks.push(TcpSackBlock {
            left_edge: read_u32_be(&chunk[0..4])?,
            right_edge: read_u32_be(&chunk[4..8])?,
        });
    }
    Ok(TcpOption::Sack(blocks))
}

fn decode_tcp_edo_option(data: &[u8], len: usize) -> Result<TcpOption> {
    let edo = match len as u8 {
        TCP_EDO_REQUEST_LEN => TcpExtendedDataOffset::Request,
        TCP_EDO_HEADER_LEN => TcpExtendedDataOffset::HeaderLength {
            header_length: read_u16_be(&data[0..2])?,
        },
        TCP_EDO_HEADER_AND_SEGMENT_LEN => TcpExtendedDataOffset::HeaderAndSegmentLength {
            header_length: read_u16_be(&data[0..2])?,
            segment_length: read_u16_be(&data[2..4])?,
        },
        _ => {
            return Err(CrafterError::invalid_field_value(
                "tcp.option.edo.length",
                "EDO length must be 2, 4, or 6 bytes",
            ))
        }
    };
    Ok(TcpOption::ExtendedDataOffset(edo))
}

fn validate_tcp_option_len(field: &'static str, actual: usize, expected: usize) -> Result<()> {
    if actual != expected {
        return Err(CrafterError::invalid_field_value(
            field,
            "TCP option has an invalid fixed length",
        ));
    }
    Ok(())
}
