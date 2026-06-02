//! The TCP `Tcp` layer: builders, getters, checksum, validation, and `Layer`.

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::ip::IPPROTO_TCP;

use super::super::common::{
    hex_bytes, impl_layer_div, impl_layer_object, payload_bytes_after, transport_checksum_context,
    value_or_copy,
};
use super::constants::{
    TCP_MAX_DATA_OFFSET, TCP_MAX_FLAGS, TCP_MAX_HEADER_LEN, TCP_MAX_RESERVED, TCP_MIN_HEADER_LEN,
};
use super::flags::{flags_summary, TCP_FLAG_FIN, TCP_FLAG_SYN};
use super::option::{validate_tcp_options, TcpOption, TcpOptionIter};
use super::sizing::{padded_options_len, sequence_space_len};

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
    /// Create a TCP header with deterministic packet-builder defaults.
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

    /// Construct a TCP header from decoded wire fields.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_decoded_parts(
        source_port: u16,
        destination_port: u16,
        sequence_number: u32,
        acknowledgment_number: u32,
        data_offset: u8,
        reserved: u8,
        flags: u16,
        window: u16,
        checksum: u16,
        urgent_pointer: u16,
        options: Vec<u8>,
    ) -> Self {
        Self {
            source_port: Field::user(source_port),
            destination_port: Field::user(destination_port),
            sequence_number: Field::user(sequence_number),
            acknowledgment_number: Field::user(acknowledgment_number),
            data_offset: Field::user(data_offset),
            reserved: Field::user(reserved),
            flags: Field::user(flags),
            window: Field::user(window),
            checksum: Field::user(checksum),
            urgent_pointer: Field::user(urgent_pointer),
            options,
        }
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

    /// Set the sequence number.
    pub fn sequence_number(mut self, sequence_number: u32) -> Self {
        self.sequence_number.set_user(sequence_number);
        self
    }

    /// Compatibility alias for sequence number.
    pub fn seq(self, sequence_number: u32) -> Self {
        self.sequence_number(sequence_number)
    }

    /// Set the acknowledgment number.
    pub fn acknowledgment_number(mut self, acknowledgment_number: u32) -> Self {
        self.acknowledgment_number.set_user(acknowledgment_number);
        self
    }

    /// Compatibility alias for acknowledgment number.
    pub fn ack(self, acknowledgment_number: u32) -> Self {
        self.acknowledgment_number(acknowledgment_number)
    }

    /// Set the TCP data offset in 32-bit words.
    pub fn data_offset(mut self, data_offset: u8) -> Self {
        self.data_offset.set_user(data_offset);
        self
    }

    /// Compatibility alias for data offset.
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
        self.flag(super::flags::TCP_FLAG_FIN, true)
    }

    /// Set the SYN flag.
    pub fn syn(self) -> Self {
        self.flag(TCP_FLAG_SYN, true)
    }

    /// Set the RST flag.
    pub fn rst(self) -> Self {
        self.flag(super::flags::TCP_FLAG_RST, true)
    }

    /// Set the PSH flag.
    pub fn psh(self) -> Self {
        self.flag(super::flags::TCP_FLAG_PSH, true)
    }

    /// Set the ACK flag.
    pub fn ack_flag(self) -> Self {
        self.flag(super::flags::TCP_FLAG_ACK, true)
    }

    /// Set the URG flag.
    pub fn urg(self) -> Self {
        self.flag(super::flags::TCP_FLAG_URG, true)
    }

    /// Set the ECE flag.
    pub fn ece(self) -> Self {
        self.flag(super::flags::TCP_FLAG_ECE, true)
    }

    /// Set the CWR flag.
    pub fn cwr(self) -> Self {
        self.flag(super::flags::TCP_FLAG_CWR, true)
    }

    /// Set the NS flag.
    pub fn ns(self) -> Self {
        self.flag(super::flags::TCP_FLAG_NS, true)
    }

    /// Set or clear the CWR (Congestion Window Reduced) flag.
    ///
    /// Classic ECN control bit per RFC 3168. This is a thin convenience over the
    /// raw [`Tcp::flag`] escape hatch and preserves every other flag bit; it does
    /// not refuse malformed ECN combinations.
    pub fn set_cwr(self, enabled: bool) -> Self {
        self.flag(super::flags::TCP_FLAG_CWR, enabled)
    }

    /// Set or clear the ECE (ECN-Echo) flag.
    ///
    /// Classic ECN control bit per RFC 3168. This is a thin convenience over the
    /// raw [`Tcp::flag`] escape hatch and preserves every other flag bit; it does
    /// not refuse malformed ECN combinations.
    pub fn set_ece(self, enabled: bool) -> Self {
        self.flag(super::flags::TCP_FLAG_ECE, enabled)
    }

    /// Set the AE (Accurate ECN) flag.
    ///
    /// Sets the `0x100` control bit assigned by RFC 9768 to AE (Accurate ECN);
    /// see [`crate::TCP_FLAG_AE`]. This is a thin convenience over the raw
    /// [`Tcp::flag`] escape hatch and preserves every other flag bit.
    pub fn ae(self) -> Self {
        self.flag(super::flags::TCP_FLAG_AE, true)
    }

    /// Set or clear the AE (Accurate ECN) flag.
    ///
    /// Accurate ECN control bit per RFC 9768, occupying the `0x100` position
    /// historically exported as `NS`. This is a thin convenience over the raw
    /// [`Tcp::flag`] escape hatch and preserves every other flag bit; it does not
    /// refuse malformed ECN combinations.
    pub fn set_ae(self, enabled: bool) -> Self {
        self.flag(super::flags::TCP_FLAG_AE, enabled)
    }

    /// Set the classic ECN-setup SYN flag combination (ECE and CWR).
    ///
    /// RFC 3168 §6.1.1 marks an ECN-capable SYN by setting both ECE and CWR.
    /// This sets those two bits and leaves all other flags (including SYN, which
    /// the caller is expected to set) untouched. It does not refuse malformed
    /// combinations.
    pub fn ecn_setup_syn(self) -> Self {
        self.set_ece(true).set_cwr(true)
    }

    /// Set the AccECN-setup feedback bits (AE, CWR, and ECE) on a SYN exchange.
    ///
    /// RFC 9768 carries a three-bit feedback codepoint in AE, CWR, and ECE on
    /// the SYN exchange. This sets all three bits and leaves every other flag
    /// untouched. It does not refuse malformed combinations.
    pub fn accurate_ecn_setup(self) -> Self {
        self.set_ae(true).set_cwr(true).set_ece(true)
    }

    /// Clear the classic and Accurate ECN flags (AE, CWR, and ECE).
    ///
    /// Clears the `0x100` AE bit (RFC 9768) and the classic CWR and ECE bits
    /// (RFC 3168) while preserving every other flag bit. This is a thin
    /// convenience over the raw [`Tcp::flag`] escape hatch.
    pub fn clear_ecn(self) -> Self {
        self.set_ae(false).set_cwr(false).set_ece(false)
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

    /// Compatibility alias for checksum.
    pub fn chksum(self, checksum: u16) -> Self {
        self.checksum(checksum)
    }

    /// Set the urgent pointer.
    pub fn urgent_pointer(mut self, urgent_pointer: u16) -> Self {
        self.urgent_pointer.set_user(urgent_pointer);
        self
    }

    /// Compatibility alias for urgent pointer.
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

    /// True when this segment's SYN control bit is set.
    ///
    /// SYN consumes one octet of TCP sequence space (RFC 9293 section 3.4); see
    /// [`Tcp::sequence_space_len`]. Reads the segment's own flag bits and does
    /// not model any connection state.
    pub fn has_syn(&self) -> bool {
        self.has_flag(TCP_FLAG_SYN)
    }

    /// True when this segment's FIN control bit is set.
    ///
    /// FIN consumes one octet of TCP sequence space (RFC 9293 section 3.4); see
    /// [`Tcp::sequence_space_len`]. Reads the segment's own flag bits and does
    /// not model any connection state.
    pub fn has_fin(&self) -> bool {
        self.has_flag(TCP_FLAG_FIN)
    }

    /// Length of this segment in *sequence space*, in octets.
    ///
    /// Computes `payload_len + (SYN ? 1 : 0) + (FIN ? 1 : 0)` from the segment's
    /// own flag bits (RFC 9293 section 3.4 "Sequence Numbers"): every payload
    /// octet plus a SYN or FIN consumes one sequence number, and a pure ACK
    /// consumes none. The caller supplies `payload_len` because the `Tcp` layer
    /// holds only the header; the payload lives in following layers.
    ///
    /// This is the inspectable form of "how far does this segment advance the
    /// sequence number?", letting a builder compute the acknowledgment number
    /// for a crafted reply without a TCP state machine, retransmission, or
    /// reassembly. Delegates to the free [`sequence_space_len`] helper.
    pub fn sequence_space_len(&self, payload_len: u32) -> u32 {
        sequence_space_len(self.flags_value(), payload_len)
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
