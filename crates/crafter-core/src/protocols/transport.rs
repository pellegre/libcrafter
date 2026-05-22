//! UDP and TCP protocol implementations.

use core::any::Any;
use core::ops::Div;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet, Raw};
use crate::protocols::ip::{IPPROTO_TCP, IPPROTO_UDP};

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

/// Append a decoded UDP datagram to an existing packet stack.
pub(crate) fn append_udp_packet(mut packet: Packet, bytes: &[u8]) -> Result<Packet> {
    let (udp, payload, rest) = decode_udp_parts(bytes)?;
    packet = packet.push(udp);
    if !payload.is_empty() {
        packet = packet.push(Raw::from_bytes(payload));
    }
    if !rest.is_empty() {
        packet = packet.push(Raw::from_bytes(rest));
    }
    Ok(packet)
}

/// Append a decoded TCP segment to an existing packet stack.
pub(crate) fn append_tcp_packet(mut packet: Packet, bytes: &[u8]) -> Result<Packet> {
    let (tcp, payload) = decode_tcp_parts(bytes)?;
    packet = packet.push(tcp);
    if !payload.is_empty() {
        packet = packet.push(Raw::from_bytes(payload));
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

    const VLAN_FIXTURE: &[u8] =
        include_bytes!("../../../../tests/fixtures/scapy/vlan-ipv4-udp.bin");

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
