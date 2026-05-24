//! UDP and TCP protocol implementations.

use core::any::Any;
use core::ops::Div;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet, Raw};
use crate::protocols::dhcp::{DHCP_CLIENT_PORT, DHCP_SERVER_PORT};
use crate::protocols::ip::{IPPROTO_TCP, IPPROTO_UDP};
use crate::registry::ProtocolRegistry;

/// TCP FIN flag.
pub const TCP_FLAG_FIN: u16 = 0x001;
/// TCP SYN flag.
pub const TCP_FLAG_SYN: u16 = 0x002;
/// TCP RST flag.
pub const TCP_FLAG_RST: u16 = 0x004;
/// TCP PSH flag.
pub const TCP_FLAG_PSH: u16 = 0x008;
/// TCP ACK flag.
pub const TCP_FLAG_ACK: u16 = 0x010;
/// TCP URG flag.
pub const TCP_FLAG_URG: u16 = 0x020;
/// TCP ECE flag.
pub const TCP_FLAG_ECE: u16 = 0x040;
/// TCP CWR flag.
pub const TCP_FLAG_CWR: u16 = 0x080;
/// TCP NS flag.
pub const TCP_FLAG_NS: u16 = 0x100;

/// TCP end-of-option-list kind.
pub const TCP_OPTION_EOL: u8 = 0;
/// TCP no-operation option kind.
pub const TCP_OPTION_NOP: u8 = 1;
/// TCP maximum segment size option kind.
pub const TCP_OPTION_MSS: u8 = 2;
/// TCP window scale option kind.
pub const TCP_OPTION_WINDOW_SCALE: u8 = 3;
/// TCP SACK-permitted option kind.
pub const TCP_OPTION_SACK_PERMITTED: u8 = 4;
/// TCP SACK option kind.
pub const TCP_OPTION_SACK: u8 = 5;
/// TCP timestamp option kind.
pub const TCP_OPTION_TIMESTAMP: u8 = 8;
/// TCP MPTCP option kind.
pub const TCP_OPTION_MPTCP: u8 = 30;
/// TCP Fast Open option kind.
pub const TCP_OPTION_FAST_OPEN: u8 = 34;
/// TCP Extended Data Offset option kind.
pub const TCP_OPTION_EDO: u8 = 237;

/// EDO request length byte.
pub const TCP_EDO_REQUEST_LEN: u8 = 2;
/// EDO length byte carrying an extended TCP header length.
pub const TCP_EDO_HEADER_LEN: u8 = 4;
/// EDO length byte carrying an extended TCP header length and segment length.
pub const TCP_EDO_HEADER_AND_SEGMENT_LEN: u8 = 6;

const UDP_HEADER_LEN: usize = 8;
const TCP_MIN_HEADER_LEN: usize = 20;
const TCP_MAX_HEADER_LEN: usize = 60;
const TCP_MAX_DATA_OFFSET: u8 = 15;
const TCP_MAX_RESERVED: u8 = 0x07;
const TCP_MAX_FLAGS: u16 = 0x01ff;

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

    /// Scapy/libcrafter-style alias for MSS.
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

/// User Datagram Protocol header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp {
    source_port: Field<u16>,
    destination_port: Field<u16>,
    length: Field<u16>,
    checksum: Field<u16>,
}

impl Udp {
    /// Create a UDP header with deterministic, Scapy-like defaults.
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

    /// Scapy/libcrafter-style alias for source port.
    pub fn sport(self, source_port: u16) -> Self {
        self.source_port(source_port)
    }

    /// Set the destination port.
    pub fn destination_port(mut self, destination_port: u16) -> Self {
        self.destination_port.set_user(destination_port);
        self
    }

    /// Scapy/libcrafter-style alias for destination port.
    pub fn dport(self, destination_port: u16) -> Self {
        self.destination_port(destination_port)
    }

    /// Set the UDP length field explicitly.
    pub fn length(mut self, length: u16) -> Self {
        self.length.set_user(length);
        self
    }

    /// Scapy-style alias for UDP length.
    pub fn len(self, length: u16) -> Self {
        self.length(length)
    }

    /// Set the UDP checksum explicitly.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum.set_user(checksum);
        self
    }

    /// Scapy-style alias for checksum.
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

/// Transmission Control Protocol header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcp {
    source_port: Field<u16>,
    destination_port: Field<u16>,
    sequence_number: Field<u32>,
    acknowledgment_number: Field<u32>,
    data_offset: Field<u8>,
    reserved: Field<u8>,
    flags: Field<u16>,
    window: Field<u16>,
    checksum: Field<u16>,
    urgent_pointer: Field<u16>,
    options: Vec<u8>,
}

impl Tcp {
    /// Create a TCP header with deterministic, Scapy-like defaults.
    pub fn new() -> Self {
        Self {
            source_port: Field::defaulted(20),
            destination_port: Field::defaulted(80),
            sequence_number: Field::defaulted(0),
            acknowledgment_number: Field::defaulted(0),
            data_offset: Field::unset(),
            reserved: Field::defaulted(0),
            flags: Field::defaulted(TCP_FLAG_SYN),
            window: Field::defaulted(8192),
            checksum: Field::unset(),
            urgent_pointer: Field::defaulted(0),
            options: Vec::new(),
        }
    }

    /// Set the source port.
    pub fn source_port(mut self, source_port: u16) -> Self {
        self.source_port.set_user(source_port);
        self
    }

    /// Scapy/libcrafter-style alias for source port.
    pub fn sport(self, source_port: u16) -> Self {
        self.source_port(source_port)
    }

    /// Set the destination port.
    pub fn destination_port(mut self, destination_port: u16) -> Self {
        self.destination_port.set_user(destination_port);
        self
    }

    /// Scapy/libcrafter-style alias for destination port.
    pub fn dport(self, destination_port: u16) -> Self {
        self.destination_port(destination_port)
    }

    /// Set the sequence number.
    pub fn sequence_number(mut self, sequence_number: u32) -> Self {
        self.sequence_number.set_user(sequence_number);
        self
    }

    /// Scapy/libcrafter-style alias for sequence number.
    pub fn seq(self, sequence_number: u32) -> Self {
        self.sequence_number(sequence_number)
    }

    /// Set the acknowledgment number.
    pub fn acknowledgment_number(mut self, acknowledgment_number: u32) -> Self {
        self.acknowledgment_number.set_user(acknowledgment_number);
        self
    }

    /// Scapy/libcrafter-style alias for acknowledgment number.
    pub fn ack(self, acknowledgment_number: u32) -> Self {
        self.acknowledgment_number(acknowledgment_number)
    }

    /// Set the TCP data offset in 32-bit words.
    pub fn data_offset(mut self, data_offset: u8) -> Self {
        self.data_offset.set_user(data_offset);
        self
    }

    /// Scapy-style alias for data offset.
    pub fn dataofs(self, data_offset: u8) -> Self {
        self.data_offset(data_offset)
    }

    /// Set the reserved TCP bits.
    pub fn reserved(mut self, reserved: u8) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Set the raw TCP flag bits.
    pub fn flags(mut self, flags: u16) -> Self {
        self.flags.set_user(flags);
        self
    }

    /// Set or clear one TCP flag bit.
    pub fn flag(mut self, flag: u16, enabled: bool) -> Self {
        let mut flags = self.flags_value();
        if enabled {
            flags |= flag;
        } else {
            flags &= !flag;
        }
        self.flags.set_user(flags);
        self
    }

    /// Set the FIN flag.
    pub fn fin(self) -> Self {
        self.flag(TCP_FLAG_FIN, true)
    }

    /// Set the SYN flag.
    pub fn syn(self) -> Self {
        self.flag(TCP_FLAG_SYN, true)
    }

    /// Set the RST flag.
    pub fn rst(self) -> Self {
        self.flag(TCP_FLAG_RST, true)
    }

    /// Set the PSH flag.
    pub fn psh(self) -> Self {
        self.flag(TCP_FLAG_PSH, true)
    }

    /// Set the ACK flag.
    pub fn ack_flag(self) -> Self {
        self.flag(TCP_FLAG_ACK, true)
    }

    /// Set the URG flag.
    pub fn urg(self) -> Self {
        self.flag(TCP_FLAG_URG, true)
    }

    /// Set the ECE flag.
    pub fn ece(self) -> Self {
        self.flag(TCP_FLAG_ECE, true)
    }

    /// Set the CWR flag.
    pub fn cwr(self) -> Self {
        self.flag(TCP_FLAG_CWR, true)
    }

    /// Set the NS flag.
    pub fn ns(self) -> Self {
        self.flag(TCP_FLAG_NS, true)
    }

    /// Set the receive window.
    pub fn window(mut self, window: u16) -> Self {
        self.window.set_user(window);
        self
    }

    /// Set the TCP checksum explicitly.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum.set_user(checksum);
        self
    }

    /// Scapy-style alias for checksum.
    pub fn chksum(self, checksum: u16) -> Self {
        self.checksum(checksum)
    }

    /// Set the urgent pointer.
    pub fn urgent_pointer(mut self, urgent_pointer: u16) -> Self {
        self.urgent_pointer.set_user(urgent_pointer);
        self
    }

    /// Scapy-style alias for urgent pointer.
    pub fn urgptr(self, urgent_pointer: u16) -> Self {
        self.urgent_pointer(urgent_pointer)
    }

    /// Append raw TCP option bytes.
    pub fn option(mut self, option: impl AsRef<[u8]>) -> Self {
        self.options.extend_from_slice(option.as_ref());
        self
    }

    /// Append a typed TCP option.
    pub fn tcp_option(mut self, option: TcpOption) -> Result<Self> {
        self.options.extend_from_slice(&option.encode()?);
        Ok(self)
    }

    /// Replace all raw TCP option bytes.
    pub fn options(mut self, options: impl Into<Vec<u8>>) -> Self {
        self.options = options.into();
        self
    }

    /// Remove all TCP option bytes.
    pub fn clear_options(mut self) -> Self {
        self.options.clear();
        self
    }

    /// Source port value.
    pub fn source_port_value(&self) -> u16 {
        value_or_copy(&self.source_port, 20)
    }

    /// Destination port value.
    pub fn destination_port_value(&self) -> u16 {
        value_or_copy(&self.destination_port, 80)
    }

    /// Sequence number.
    pub fn sequence_number_value(&self) -> u32 {
        value_or_copy(&self.sequence_number, 0)
    }

    /// Acknowledgment number.
    pub fn acknowledgment_number_value(&self) -> u32 {
        value_or_copy(&self.acknowledgment_number, 0)
    }

    /// TCP data offset in 32-bit words.
    pub fn data_offset_value(&self) -> u8 {
        self.effective_data_offset()
    }

    /// TCP header length in bytes.
    pub fn header_len(&self) -> usize {
        self.effective_header_len()
    }

    /// Reserved bits value.
    pub fn reserved_value(&self) -> u8 {
        value_or_copy(&self.reserved, 0)
    }

    /// Raw TCP flag bits.
    pub fn flags_value(&self) -> u16 {
        value_or_copy(&self.flags, TCP_FLAG_SYN)
    }

    /// Return true when a TCP flag is set.
    pub fn has_flag(&self, flag: u16) -> bool {
        self.flags_value() & flag != 0
    }

    /// Receive window value.
    pub fn window_value(&self) -> u16 {
        value_or_copy(&self.window, 8192)
    }

    /// Stored checksum value, when explicit or decoded.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    /// Urgent pointer value.
    pub fn urgent_pointer_value(&self) -> u16 {
        value_or_copy(&self.urgent_pointer, 0)
    }

    /// Raw TCP option bytes, including decode-time padding bytes.
    pub fn option_bytes(&self) -> &[u8] {
        &self.options
    }

    /// Iterate over decoded TCP options.
    pub fn option_iter(&self) -> TcpOptionIter<'_> {
        TcpOptionIter::new(&self.options)
    }

    /// Decode TCP options into typed values.
    pub fn parsed_options(&self) -> Result<Vec<TcpOption>> {
        TcpOption::decode_all(&self.options)
    }

    fn effective_data_offset(&self) -> u8 {
        self.data_offset
            .value()
            .copied()
            .unwrap_or((self.effective_header_len() / 4) as u8)
    }

    fn effective_header_len(&self) -> usize {
        if let Some(data_offset) = self.data_offset.value().copied() {
            (data_offset as usize) * 4
        } else {
            TCP_MIN_HEADER_LEN + padded_options_len(self.options.len())
        }
    }

    fn effective_checksum(&self, ctx: LayerContext<'_>, header: &[u8], payload: &[u8]) -> u16 {
        if let Some(checksum) = self.checksum.value().copied() {
            return checksum;
        }

        let mut transport = Vec::with_capacity(header.len() + payload.len());
        transport.extend_from_slice(header);
        transport.extend_from_slice(payload);

        transport_checksum_context(ctx, IPPROTO_TCP)
            .map(|pseudo_header| pseudo_header.checksum(&transport))
            .unwrap_or(0)
    }

    fn validate(&self, payload_len: usize) -> Result<()> {
        if self.effective_data_offset() < 5 {
            return Err(CrafterError::invalid_field_value(
                "tcp.data_offset",
                "TCP data offset must be at least 5 words",
            ));
        }
        if self.effective_data_offset() > TCP_MAX_DATA_OFFSET {
            return Err(CrafterError::invalid_field_value(
                "tcp.data_offset",
                "TCP data offset must be <= 15 words",
            ));
        }
        if self.effective_header_len() < TCP_MIN_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "tcp.data_offset",
                "TCP header must be at least 20 bytes",
            ));
        }
        if self.effective_header_len() > TCP_MAX_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "tcp.data_offset",
                "TCP header must be <= 60 bytes",
            ));
        }
        if self.options.len() > TCP_MAX_HEADER_LEN - TCP_MIN_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "tcp.options",
                "TCP options must fit within the 60-byte maximum header",
            ));
        }
        validate_tcp_options(&self.options)?;
        if self.effective_header_len() < TCP_MIN_HEADER_LEN + self.options.len() {
            return Err(CrafterError::invalid_field_value(
                "tcp.data_offset",
                "TCP data offset is too small for option bytes",
            ));
        }
        if self.reserved_value() > TCP_MAX_RESERVED {
            return Err(CrafterError::invalid_field_value(
                "tcp.reserved",
                "TCP reserved bits must fit in three bits",
            ));
        }
        if self.flags_value() > TCP_MAX_FLAGS {
            return Err(CrafterError::invalid_field_value(
                "tcp.flags",
                "TCP flags must fit in nine bits",
            ));
        }
        if self.effective_header_len() + payload_len > u16::MAX as usize {
            return Err(CrafterError::invalid_field_value(
                "tcp.length",
                "TCP segment exceeds 65535 bytes",
            ));
        }
        Ok(())
    }
}

impl Default for Tcp {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Tcp {
    fn name(&self) -> &'static str {
        "Tcp"
    }

    fn summary(&self) -> String {
        format!(
            "Tcp(sport={}, dport={}, flags={})",
            self.source_port_value(),
            self.destination_port_value(),
            flags_summary(self.flags_value())
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("sport", self.source_port_value().to_string()),
            ("dport", self.destination_port_value().to_string()),
            ("seq", format!("0x{:08x}", self.sequence_number_value())),
            (
                "ack",
                format!("0x{:08x}", self.acknowledgment_number_value()),
            ),
            ("data_offset", self.data_offset_value().to_string()),
            ("reserved", self.reserved_value().to_string()),
            ("flags", flags_summary(self.flags_value())),
            ("window", self.window_value().to_string()),
            (
                "checksum",
                self.checksum_value()
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("urgent_pointer", self.urgent_pointer_value().to_string()),
            ("options", hex_bytes(&self.options)),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.effective_header_len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let payload = payload_bytes_after(*ctx)?;
        self.validate(payload.len())?;

        let header_len = self.effective_header_len();
        let data_offset = (header_len / 4) as u8;
        let flags = self.flags_value();
        let mut header = Vec::with_capacity(header_len);
        header.extend_from_slice(&self.source_port_value().to_be_bytes());
        header.extend_from_slice(&self.destination_port_value().to_be_bytes());
        header.extend_from_slice(&self.sequence_number_value().to_be_bytes());
        header.extend_from_slice(&self.acknowledgment_number_value().to_be_bytes());
        header.push((data_offset << 4) | (self.reserved_value() << 1) | ((flags >> 8) as u8 & 1));
        header.push(flags as u8);
        header.extend_from_slice(&self.window_value().to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes());
        header.extend_from_slice(&self.urgent_pointer_value().to_be_bytes());
        header.extend_from_slice(&self.options);
        header.resize(header_len, 0);

        let checksum = self.effective_checksum(*ctx, &header, &payload);
        header[16..18].copy_from_slice(&checksum.to_be_bytes());
        out.extend_from_slice(&header);
        Ok(())
    }

    impl_layer_object!(Tcp);
}

impl_layer_div!(Tcp);

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

/// Append a decoded TCP segment using an explicit registry.
pub(crate) fn append_tcp_packet_with_registry(
    registry: &ProtocolRegistry,
    mut packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    let (tcp, payload) = decode_tcp_parts(bytes)?;
    let source_port = tcp.source_port_value();
    let destination_port = tcp.destination_port_value();
    packet = packet.push(tcp);
    if !payload.is_empty() {
        packet = registry.decode_tcp_application(packet, source_port, destination_port, payload)?;
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

fn decode_tcp_parts(bytes: &[u8]) -> Result<(Tcp, &[u8])> {
    if bytes.len() < TCP_MIN_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "tcp header",
            TCP_MIN_HEADER_LEN,
            bytes.len(),
        ));
    }

    let data_offset = bytes[12] >> 4;
    if data_offset < 5 {
        return Err(CrafterError::invalid_field_value(
            "tcp.data_offset",
            "TCP data offset must be at least 5 words",
        ));
    }

    let header_len = (data_offset as usize) * 4;
    if bytes.len() < header_len {
        return Err(CrafterError::buffer_too_short(
            "tcp header",
            header_len,
            bytes.len(),
        ));
    }
    validate_tcp_options(&bytes[TCP_MIN_HEADER_LEN..header_len])?;

    let flags = (((bytes[12] & 1) as u16) << 8) | bytes[13] as u16;
    let tcp = Tcp {
        source_port: Field::user(read_u16_be(&bytes[0..2])?),
        destination_port: Field::user(read_u16_be(&bytes[2..4])?),
        sequence_number: Field::user(read_u32_be(&bytes[4..8])?),
        acknowledgment_number: Field::user(read_u32_be(&bytes[8..12])?),
        data_offset: Field::user(data_offset),
        reserved: Field::user((bytes[12] >> 1) & TCP_MAX_RESERVED),
        flags: Field::user(flags),
        window: Field::user(read_u16_be(&bytes[14..16])?),
        checksum: Field::user(read_u16_be(&bytes[16..18])?),
        urgent_pointer: Field::user(read_u16_be(&bytes[18..20])?),
        options: bytes[TCP_MIN_HEADER_LEN..header_len].to_vec(),
    };

    Ok((tcp, &bytes[header_len..]))
}

fn payload_bytes_after(ctx: LayerContext<'_>) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    for (index, layer) in ctx.packet().iter().enumerate().skip(ctx.index() + 1) {
        let layer_ctx = LayerContext::new(ctx.packet(), index);
        layer.compile(&layer_ctx, &mut payload)?;
    }
    Ok(payload)
}

fn transport_checksum_context(
    ctx: LayerContext<'_>,
    transport_protocol: u8,
) -> Option<crate::packet::TransportChecksumContext> {
    (0..ctx.index()).rev().find_map(|index| {
        ctx.packet()
            .get(index)
            .and_then(|layer| layer.transport_checksum_context(transport_protocol))
    })
}

fn validate_tcp_options(options: &[u8]) -> Result<()> {
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

fn padded_options_len(len: usize) -> usize {
    (len + 3) & !3
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn flags_summary(flags: u16) -> String {
    let mut names = Vec::new();
    if flags & TCP_FLAG_NS != 0 {
        names.push("NS");
    }
    if flags & TCP_FLAG_CWR != 0 {
        names.push("CWR");
    }
    if flags & TCP_FLAG_ECE != 0 {
        names.push("ECE");
    }
    if flags & TCP_FLAG_URG != 0 {
        names.push("URG");
    }
    if flags & TCP_FLAG_ACK != 0 {
        names.push("ACK");
    }
    if flags & TCP_FLAG_PSH != 0 {
        names.push("PSH");
    }
    if flags & TCP_FLAG_RST != 0 {
        names.push("RST");
    }
    if flags & TCP_FLAG_SYN != 0 {
        names.push("SYN");
    }
    if flags & TCP_FLAG_FIN != 0 {
        names.push("FIN");
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
mod udp {
    use super::Udp;
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

#[cfg(test)]
mod tcp {
    use super::{Tcp, TCP_FLAG_ACK, TCP_FLAG_SYN};
    use crate::checksum::ipv4_pseudo_header_checksum;
    use crate::{IpProtocol, Ipv4, Packet, Raw, IPPROTO_TCP};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn tcp_autofills_ipv4_checksum_for_odd_payload_and_flags() {
        let packet = Ipv4::new().src(src()).dst(dst()).id(0x2223)
            / Tcp::new()
                .sport(44444)
                .dport(80)
                .seq(0x0102_0304)
                .ack(0x0506_0708)
                .flags(TCP_FLAG_SYN | TCP_FLAG_ACK)
                .window(64240)
            / Raw::from_bytes([0xaa, 0xbb, 0xcc]);
        let bytes = packet.compile().unwrap();

        assert_eq!(&bytes.as_bytes()[2..4], &(43u16).to_be_bytes());
        assert_eq!(&bytes.as_bytes()[20..22], &44444u16.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[22..24], &80u16.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[24..28], &0x0102_0304u32.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[28..32], &0x0506_0708u32.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[32..34], &[0x50, 0x12]);
        let mut tcp = bytes.as_bytes()[20..].to_vec();
        tcp[16] = 0;
        tcp[17] = 0;
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[36], bytes.as_bytes()[37]]),
            ipv4_pseudo_header_checksum(src(), dst(), IPPROTO_TCP, &tcp)
        );
    }

    #[test]
    fn tcp_decode_exposes_header_fields_and_payload() {
        let original = Ipv4::new().src(src()).dst(dst()).id(0x2224)
            / Tcp::new()
                .sport(12345)
                .dport(443)
                .seq(0x1111_2222)
                .ack(0x3333_4444)
                .flags(TCP_FLAG_ACK)
                .window(4096)
                .urgent_pointer(9)
            / Raw::from("GET");
        let bytes = original.compile().unwrap();
        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let tcp = decoded.layer::<Tcp>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(tcp.source_port_value(), 12345);
        assert_eq!(tcp.destination_port_value(), 443);
        assert_eq!(tcp.sequence_number_value(), 0x1111_2222);
        assert_eq!(tcp.acknowledgment_number_value(), 0x3333_4444);
        assert_eq!(tcp.flags_value(), TCP_FLAG_ACK);
        assert_eq!(tcp.window_value(), 4096);
        assert_eq!(tcp.urgent_pointer_value(), 9);
        assert_eq!(raw.as_bytes(), b"GET");
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn explicit_tcp_checksum_is_preserved() {
        let bytes =
            (Ipv4::new().src(src()).dst(dst()) / Tcp::new().checksum(0x1111) / Raw::from("abc"))
                .compile()
                .unwrap();

        assert_eq!(&bytes.as_bytes()[36..38], &[0x11, 0x11]);
    }

    #[test]
    fn tcp_decode_rejects_short_and_malformed_inputs() {
        let short = (Ipv4::new().proto(IpProtocol::Tcp) / Raw::from_bytes([0u8; 19]))
            .compile()
            .unwrap();
        assert!(Packet::decode_from_l3(crate::NetworkLayer::Ipv4, short.as_bytes()).is_err());

        let mut malformed = [0u8; 20];
        malformed[12] = 0x40;
        let bytes = (Ipv4::new().proto(IpProtocol::Tcp) / Raw::from_bytes(malformed))
            .compile()
            .unwrap();
        assert!(Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).is_err());
    }
}

#[cfg(test)]
mod tcp_options {
    use super::{Tcp, TcpExtendedDataOffset, TcpOption, TcpSackBlock, TCP_FLAG_ACK, TCP_FLAG_SYN};
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn tcp_options_encode_decode_common_typed_options() {
        let mut tcp = Tcp::new()
            .sport(44444)
            .dport(443)
            .seq(0x0102_0304)
            .flags(TCP_FLAG_SYN | TCP_FLAG_ACK);
        tcp = tcp.tcp_option(TcpOption::mss(1460)).unwrap();
        tcp = tcp.tcp_option(TcpOption::window_scale(7)).unwrap();
        tcp = tcp
            .tcp_option(TcpOption::timestamp(398_303_815, 12_345))
            .unwrap();
        tcp = tcp.tcp_option(TcpOption::sack_permitted()).unwrap();
        tcp = tcp
            .tcp_option(TcpOption::sack(vec![TcpSackBlock::new(10, 20)]))
            .unwrap();

        let packet = Ipv4::new().src(src()).dst(dst()).id(0x2225) / tcp / Raw::from("payload");
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let tcp = decoded.layer::<Tcp>().unwrap();
        let options = tcp.parsed_options().unwrap();

        assert_eq!(options[0], TcpOption::MaximumSegmentSize(1460));
        assert_eq!(options[1], TcpOption::WindowScale(7));
        assert_eq!(
            options[2],
            TcpOption::Timestamp {
                value: 398_303_815,
                echo_reply: 12_345
            }
        );
        assert_eq!(options[3], TcpOption::SackPermitted);
        assert_eq!(options[4], TcpOption::Sack(vec![TcpSackBlock::new(10, 20)]));
        assert_eq!(options[5], TcpOption::EndOfList);
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn tcp_options_preserve_edo_mptcp_fast_open_and_generic_values() {
        let mut tcp = Tcp::new().sport(12345).dport(80);
        tcp = tcp.tcp_option(TcpOption::extended_data_offset(9)).unwrap();
        tcp = tcp
            .tcp_option(TcpOption::multipath_tcp(1, [0x03, 0xaa, 0xbb]))
            .unwrap();
        tcp = tcp.tcp_option(TcpOption::fast_open([0xca, 0xfe])).unwrap();
        tcp = tcp.tcp_option(TcpOption::generic(76, [0x55])).unwrap();

        let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2226) / tcp)
            .compile()
            .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let options = decoded.layer::<Tcp>().unwrap().parsed_options().unwrap();

        assert_eq!(
            options[0],
            TcpOption::ExtendedDataOffset(TcpExtendedDataOffset::HeaderLength { header_length: 9 })
        );
        assert_eq!(
            options[1],
            TcpOption::MultipathTcp {
                subtype: 1,
                data: vec![0x13, 0xaa, 0xbb]
            }
        );
        assert_eq!(options[2], TcpOption::FastOpen(vec![0xca, 0xfe]));
        assert_eq!(
            options[3],
            TcpOption::Generic {
                kind: 76,
                data: vec![0x55]
            }
        );
    }

    #[test]
    fn tcp_options_reject_malformed_option_lengths_on_decode() {
        let mut tcp = [0u8; 24];
        tcp[12] = 0x60;
        tcp[13] = TCP_FLAG_SYN as u8;
        tcp[20..24].copy_from_slice(&[2, 5, 0x05, 0xb4]);
        let bytes = (Ipv4::new().proto(IpProtocol::Tcp) / Raw::from_bytes(tcp))
            .compile()
            .unwrap();

        let error = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("tcp option"));
    }

    #[test]
    fn tcp_options_iterator_can_be_reused_without_consuming_raw_bytes() {
        let tcp = Tcp::new().option([1, 1, 0]);

        let first = tcp.parsed_options().unwrap();
        let second = tcp.parsed_options().unwrap();

        assert_eq!(
            first,
            vec![
                TcpOption::NoOperation,
                TcpOption::NoOperation,
                TcpOption::EndOfList
            ]
        );
        assert_eq!(second, first);
        assert_eq!(tcp.option_bytes(), &[1, 1, 0]);
    }
}

#[cfg(test)]
mod option_padding {
    use super::{Tcp, TcpOption};
    use crate::{IpProtocol, Ipv4, Ipv4Option, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    #[test]
    fn option_padding_uses_eol_bytes_for_ipv4_and_tcp_alignment() {
        let ip = Ipv4::new()
            .src(src())
            .dst(dst())
            .protocol(0)
            .ip_option(Ipv4Option::generic(8, [1]))
            .unwrap();
        let ip_bytes = (ip / Raw::from("x")).compile().unwrap();
        assert_eq!(ip_bytes.as_bytes()[0], 0x46);
        assert_eq!(&ip_bytes.as_bytes()[20..24], &[8, 3, 1, 0]);

        let decoded_ip = Packet::decode_from_l3(NetworkLayer::Ipv4, ip_bytes.as_bytes()).unwrap();
        assert_eq!(
            decoded_ip
                .layer::<Ipv4>()
                .unwrap()
                .parsed_options()
                .unwrap(),
            vec![Ipv4Option::generic(8, [1]), Ipv4Option::EndOfList]
        );

        let mut tcp = Tcp::new();
        tcp = tcp.tcp_option(TcpOption::mss(1460)).unwrap();
        tcp = tcp.tcp_option(TcpOption::window_scale(7)).unwrap();
        let tcp_bytes = (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Tcp) / tcp)
            .compile()
            .unwrap();
        assert_eq!(tcp_bytes.as_bytes()[32] >> 4, 7);
        assert_eq!(
            &tcp_bytes.as_bytes()[40..48],
            &[2, 4, 0x05, 0xb4, 3, 3, 7, 0]
        );
    }
}

#[cfg(test)]
mod transport_checksums {
    use super::{Tcp, Udp};
    use crate::checksum::ipv6_pseudo_header_checksum;
    use crate::{
        Layer, LayerContext, Packet, Raw, TransportChecksumContext, IPPROTO_TCP, IPPROTO_UDP,
    };
    use core::any::Any;
    use core::net::Ipv6Addr;

    #[derive(Debug, Clone)]
    struct Ipv6PseudoHeader {
        source: Ipv6Addr,
        destination: Ipv6Addr,
    }

    impl Ipv6PseudoHeader {
        fn new() -> Self {
            Self {
                source: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                destination: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            }
        }
    }

    impl Layer for Ipv6PseudoHeader {
        fn name(&self) -> &'static str {
            "Ipv6PseudoHeader"
        }

        fn encoded_len(&self) -> usize {
            0
        }

        fn compile(&self, _ctx: &LayerContext<'_>, _out: &mut Vec<u8>) -> crate::Result<()> {
            Ok(())
        }

        fn transport_checksum_context(
            &self,
            transport_protocol: u8,
        ) -> Option<TransportChecksumContext> {
            Some(TransportChecksumContext::Ipv6 {
                source: self.source,
                destination: self.destination,
                next_header: transport_protocol,
            })
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

    #[test]
    fn udp_uses_ipv6_checksum_context_when_previous_layer_provides_it() {
        let pseudo = Ipv6PseudoHeader::new();
        let source = pseudo.source;
        let destination = pseudo.destination;
        let bytes = (Packet::from_layer(pseudo)
            / Udp::new().sport(1).dport(2)
            / Raw::from_bytes([1, 2, 3]))
        .compile()
        .unwrap();

        let mut udp = bytes.as_bytes().to_vec();
        udp[6] = 0;
        udp[7] = 0;
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[6], bytes.as_bytes()[7]]),
            ipv6_pseudo_header_checksum(source, destination, IPPROTO_UDP, &udp)
        );
    }

    #[test]
    fn tcp_uses_ipv6_checksum_context_when_previous_layer_provides_it() {
        let pseudo = Ipv6PseudoHeader::new();
        let source = pseudo.source;
        let destination = pseudo.destination;
        let bytes = (Packet::from_layer(pseudo)
            / Tcp::new().sport(10).dport(20)
            / Raw::from_bytes([1, 2, 3]))
        .compile()
        .unwrap();

        let mut tcp = bytes.as_bytes().to_vec();
        tcp[16] = 0;
        tcp[17] = 0;
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[16], bytes.as_bytes()[17]]),
            ipv6_pseudo_header_checksum(source, destination, IPPROTO_TCP, &tcp)
        );
    }

    #[test]
    fn transport_checksums_are_zero_without_network_context() {
        let udp = (Udp::new().sport(1).dport(2) / Raw::from("abc"))
            .compile()
            .unwrap();
        let tcp = (Tcp::new().sport(1).dport(2) / Raw::from("abc"))
            .compile()
            .unwrap();

        assert_eq!(&udp.as_bytes()[6..8], &[0, 0]);
        assert_eq!(&tcp.as_bytes()[16..18], &[0, 0]);
    }
}
