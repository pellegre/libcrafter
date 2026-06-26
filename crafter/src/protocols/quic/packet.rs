//! QUIC packet/datagram layers.
//!
//! [`Quic`] is a raw-preserving datagram layer. It can compile exactly the bytes
//! supplied by the caller or explicit decoder, or concatenate ordered raw
//! [`QuicPacket`] entries for coalesced datagram work in later steps. It does
//! not infer packet type, version, connection IDs, frame boundaries, packet
//! protection, or endpoint behavior.

use crate::field::{Field, FieldState};
use crate::packet::{Layer, LayerContext};
use crate::protocols::transport::common::{hex_bytes, impl_layer_div, impl_layer_object};
use crate::{CrafterError, Result};

use super::constants::{quic_version_label, quic_version_status, QUIC_VERSION_1, QUIC_VERSION_2};
use super::crypto::{
    quic_retry_integrity_tag, quic_verify_retry_integrity_tag, QuicRetryIntegrityStatus,
};
use super::frame::QuicFrame;
use super::header::{
    classify_quic_header, QuicHeaderClassification, QuicLongPacketKind, QUIC_FIXED_BIT_MASK,
    QUIC_HEADER_FORM_MASK, QUIC_SHORT_KEY_PHASE_MASK, QUIC_SHORT_RESERVED_BITS_MASK,
    QUIC_SHORT_SPIN_BIT_MASK,
};
use super::packet_number::{header_bits_for_len, len_from_header_bits, QuicPacketNumber};
use super::varint::{encoded_len_from_prefix, QuicVarInt};
use super::QuicConnectionId;

/// Raw-preserving QUIC UDP payload layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Quic {
    payload: Field<Vec<u8>>,
    packets: Vec<QuicPacket>,
}

impl Quic {
    /// Create an empty QUIC placeholder layer.
    pub fn new() -> Self {
        Self {
            payload: Field::unset(),
            packets: Vec::new(),
        }
    }

    /// Preserve caller-supplied QUIC payload bytes.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self {
            payload: Field::user(bytes.as_ref().to_vec()),
            packets: Vec::new(),
        }
    }

    /// Compatibility constructor for raw QUIC payload bytes.
    pub fn raw(bytes: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(bytes)
    }

    /// Create a QUIC datagram from ordered packet entries.
    pub fn from_packets(packets: impl IntoIterator<Item = QuicPacket>) -> Self {
        Self::new().extend_packets(packets)
    }

    #[allow(dead_code)]
    pub(crate) fn from_decoded_payload(bytes: &[u8]) -> Self {
        Self {
            payload: Field::user(bytes.to_vec()),
            packets: Vec::new(),
        }
    }

    /// Replace payload bytes with a caller-supplied value.
    pub fn payload(mut self, bytes: impl AsRef<[u8]>) -> Self {
        self.payload.set_user(bytes.as_ref().to_vec());
        self.packets.clear();
        self
    }

    /// Append a raw QUIC packet entry to this datagram.
    pub fn packet(mut self, packet: QuicPacket) -> Self {
        if !self.payload.is_unset() {
            self.payload = Field::unset();
        }
        self.packets.push(packet);
        self
    }

    /// Append ordered QUIC packet entries to this datagram.
    pub fn extend_packets(mut self, packets: impl IntoIterator<Item = QuicPacket>) -> Self {
        let mut packets = packets.into_iter();
        if let Some(first) = packets.next() {
            if !self.payload.is_unset() {
                self.payload = Field::unset();
            }
            self.packets.push(first);
            self.packets.extend(packets);
        }
        self
    }

    /// Append raw QUIC packet bytes to this datagram.
    pub fn packet_bytes(self, bytes: impl AsRef<[u8]>) -> Self {
        self.packet(QuicPacket::from_bytes(bytes))
    }

    /// Append multiple raw QUIC packet byte sequences to this datagram.
    pub fn packet_bytes_many<B>(mut self, packets: impl IntoIterator<Item = B>) -> Self
    where
        B: AsRef<[u8]>,
    {
        for bytes in packets {
            self = self.packet_bytes(bytes);
        }
        self
    }

    /// Borrow ordered QUIC packet entries.
    pub fn packets(&self) -> &[QuicPacket] {
        &self.packets
    }

    /// Borrow the effective raw payload bytes.
    pub fn payload_bytes(&self) -> &[u8] {
        self.payload.value().map(Vec::as_slice).unwrap_or(&[])
    }

    /// Return true when the layer has no payload bytes.
    pub fn is_empty(&self) -> bool {
        self.payload_bytes().is_empty() && self.packets.is_empty()
    }

    /// Length of the raw payload.
    pub fn len(&self) -> usize {
        if self.packets.is_empty() {
            self.payload_bytes().len()
        } else {
            self.packets.iter().map(QuicPacket::len).sum()
        }
    }

    /// State of the payload field.
    pub fn payload_state(&self) -> FieldState {
        self.payload.state()
    }

    /// Number of decoded frame entries currently available.
    pub fn frame_count(&self) -> usize {
        0
    }

    /// Number of decoded transport parameter entries currently available.
    pub fn transport_parameter_count(&self) -> usize {
        0
    }

    fn first_packet_bytes_for_inspection(&self) -> &[u8] {
        if let Some(packet) = self.packets.first() {
            packet.as_bytes()
        } else {
            self.payload_bytes()
        }
    }

    fn header_classification_for_inspection(&self) -> Option<Result<QuicHeaderClassification>> {
        let bytes = self.first_packet_bytes_for_inspection();
        if bytes.is_empty() {
            None
        } else {
            Some(classify_quic_header(bytes))
        }
    }

    fn header_summary_for_inspection(&self) -> String {
        match self.header_classification_for_inspection() {
            Some(Ok(classification)) => classification.summary(),
            Some(Err(err)) => format!("header=malformed error={err}"),
            None => "header=empty".to_string(),
        }
    }
}

impl Layer for Quic {
    fn name(&self) -> &'static str {
        "Quic"
    }

    fn summary(&self) -> String {
        format!(
            "Quic(raw_len={}, packets={}, {}, frames={}, transport_parameters={})",
            self.len(),
            self.packets.len(),
            self.header_summary_for_inspection(),
            self.frame_count(),
            self.transport_parameter_count()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("raw_len", self.len().to_string()),
            ("packet_count", self.packets.len().to_string()),
            ("payload_state", format!("{:?}", self.payload_state())),
            ("raw_bytes", hex_bytes(self.payload_bytes())),
            ("frame_count", self.frame_count().to_string()),
            (
                "transport_parameter_count",
                self.transport_parameter_count().to_string(),
            ),
        ];

        match self.header_classification_for_inspection() {
            Some(Ok(classification)) => fields.extend(classification.inspection_fields()),
            Some(Err(err)) => {
                fields.push(("classification", "malformed".to_string()));
                fields.push(("classification_error", err.to_string()));
            }
            None => fields.push(("classification", "empty".to_string())),
        }

        for (index, packet) in self.packets.iter().enumerate() {
            fields.push(("packet", format!("#{index} {}", packet.summary())));
        }

        fields
    }

    fn encoded_len(&self) -> usize {
        self.len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        if self.packets.is_empty() {
            out.extend_from_slice(self.payload_bytes());
        } else {
            for packet in &self.packets {
                out.extend_from_slice(packet.as_bytes());
            }
        }
        Ok(())
    }

    impl_layer_object!(Quic);
}

impl_layer_div!(Quic);

/// Placeholder for an individual QUIC packet within a UDP datagram.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicPacket {
    bytes: Vec<u8>,
    version_negotiation: Option<QuicVersionNegotiationPacket>,
    retry: Option<QuicRetryPacket>,
    long_header: Option<QuicLongHeaderPacket>,
    short_header: Option<QuicShortHeaderPacket>,
}

impl QuicPacket {
    /// Preserve raw packet bytes until typed packet parsing is implemented.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self {
            bytes: bytes.as_ref().to_vec(),
            version_negotiation: None,
            retry: None,
            long_header: None,
            short_header: None,
        }
    }

    /// Preserve a decoded or built Version Negotiation packet entry.
    pub fn from_version_negotiation(packet: QuicVersionNegotiationPacket) -> Self {
        Self {
            bytes: packet.as_bytes().to_vec(),
            version_negotiation: Some(packet),
            retry: None,
            long_header: None,
            short_header: None,
        }
    }

    /// Preserve a decoded or built Retry packet entry.
    pub fn from_retry(packet: QuicRetryPacket) -> Self {
        Self {
            bytes: packet.as_bytes().to_vec(),
            version_negotiation: None,
            retry: Some(packet),
            long_header: None,
            short_header: None,
        }
    }

    /// Preserve a decoded long-header packet that carries a Length field.
    pub fn from_long_header(packet: QuicLongHeaderPacket) -> Self {
        Self {
            bytes: packet.as_bytes().to_vec(),
            version_negotiation: None,
            retry: None,
            long_header: Some(packet),
            short_header: None,
        }
    }

    /// Preserve a decoded short-header packet entry.
    pub fn from_short_header(packet: QuicShortHeaderPacket) -> Self {
        Self {
            bytes: packet.as_bytes().to_vec(),
            version_negotiation: None,
            retry: None,
            long_header: None,
            short_header: Some(packet),
        }
    }

    /// Decode a QUIC packet entry where source-backed typed parsing exists.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        match classify_quic_header(bytes)? {
            QuicHeaderClassification::LongHeader {
                packet_kind: QuicLongPacketKind::VersionNegotiation,
                ..
            } => {
                let version_negotiation = QuicVersionNegotiationPacket::decode(bytes)?;
                Ok(Self {
                    bytes: bytes.to_vec(),
                    version_negotiation: Some(version_negotiation),
                    retry: None,
                    long_header: None,
                    short_header: None,
                })
            }
            QuicHeaderClassification::LongHeader {
                packet_kind: QuicLongPacketKind::Retry,
                ..
            } => {
                let retry = QuicRetryPacket::decode(bytes)?;
                Ok(Self {
                    bytes: bytes.to_vec(),
                    version_negotiation: None,
                    retry: Some(retry),
                    long_header: None,
                    short_header: None,
                })
            }
            QuicHeaderClassification::LongHeader {
                packet_kind:
                    QuicLongPacketKind::Initial
                    | QuicLongPacketKind::ZeroRtt
                    | QuicLongPacketKind::Handshake,
                ..
            } => {
                let long_header = QuicLongHeaderPacket::decode(bytes)?;
                if long_header.len() == bytes.len() {
                    Ok(Self::from_long_header(long_header))
                } else {
                    Ok(Self::from_bytes(bytes))
                }
            }
            _ => Ok(Self::from_bytes(bytes)),
        }
    }

    /// Decode a short-header packet when caller context supplies the DCID length.
    pub fn decode_short_header(
        bytes: impl AsRef<[u8]>,
        destination_connection_id_len: usize,
    ) -> Result<Self> {
        QuicShortHeaderPacket::decode(bytes, destination_connection_id_len)
            .map(Self::from_short_header)
    }

    /// Return the decoded Version Negotiation packet, when this packet is one.
    pub fn version_negotiation(&self) -> Option<&QuicVersionNegotiationPacket> {
        self.version_negotiation.as_ref()
    }

    /// Return true when this packet is a decoded Version Negotiation packet.
    pub fn is_version_negotiation(&self) -> bool {
        self.version_negotiation.is_some()
    }

    /// Return the decoded Retry packet, when this packet is one.
    pub fn retry(&self) -> Option<&QuicRetryPacket> {
        self.retry.as_ref()
    }

    /// Return true when this packet is a decoded Retry packet.
    pub fn is_retry(&self) -> bool {
        self.retry.is_some()
    }

    /// Return the decoded Initial, 0-RTT, or Handshake long-header packet.
    pub fn long_header(&self) -> Option<&QuicLongHeaderPacket> {
        self.long_header.as_ref()
    }

    /// Return true when this packet is a decoded long-header packet with a Length field.
    pub fn is_long_header(&self) -> bool {
        self.long_header.is_some()
    }

    /// Return the decoded short-header packet, when caller context supplied DCID length.
    pub fn short_header(&self) -> Option<&QuicShortHeaderPacket> {
        self.short_header.as_ref()
    }

    /// Return true when this packet is a decoded short-header packet.
    pub fn is_short_header(&self) -> bool {
        self.short_header.is_some()
    }

    /// Borrow the preserved packet bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length of the preserved packet bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when no packet bytes are present.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// One-line packet summary for datagram inspection.
    pub fn summary(&self) -> String {
        if let Some(version_negotiation) = &self.version_negotiation {
            return version_negotiation.summary();
        }
        if let Some(retry) = &self.retry {
            return retry.summary();
        }
        if let Some(long_header) = &self.long_header {
            return long_header.summary();
        }
        if let Some(short_header) = &self.short_header {
            return short_header.summary();
        }
        match classify_quic_header(&self.bytes) {
            Ok(classification) => {
                format!("raw_len={} {}", self.bytes.len(), classification.summary())
            }
            Err(err) => format!("raw_len={} header=malformed error={err}", self.bytes.len()),
        }
    }

    /// Stable field/value pairs for packet inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        if let Some(version_negotiation) = &self.version_negotiation {
            return version_negotiation.inspection_fields();
        }
        if let Some(retry) = &self.retry {
            return retry.inspection_fields();
        }
        if let Some(long_header) = &self.long_header {
            return long_header.inspection_fields();
        }
        if let Some(short_header) = &self.short_header {
            return short_header.inspection_fields();
        }
        let mut fields = vec![
            ("raw_len", self.bytes.len().to_string()),
            ("raw_bytes", hex_bytes(&self.bytes)),
        ];
        match classify_quic_header(&self.bytes) {
            Ok(classification) => fields.extend(classification.inspection_fields()),
            Err(err) => {
                fields.push(("classification", "malformed".to_string()));
                fields.push(("classification_error", err.to_string()));
            }
        }
        fields
    }
}

/// Decoded QUIC short-header packet with caller-supplied DCID length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicShortHeaderPacket {
    first_byte: u8,
    fixed_bit: bool,
    spin_bit: bool,
    reserved_bits: u8,
    key_phase: bool,
    destination_connection_id: QuicConnectionId,
    packet_number: QuicPacketNumber,
    packet_number_bytes: Vec<u8>,
    protected_payload: Vec<u8>,
    raw: Vec<u8>,
}

impl QuicShortHeaderPacket {
    /// Start building a QUIC short-header packet.
    pub fn builder() -> QuicShortHeaderBuilder {
        QuicShortHeaderBuilder::new()
    }

    /// Decode a short-header packet when caller or registry context supplies DCID length.
    pub fn decode(bytes: impl AsRef<[u8]>, destination_connection_id_len: usize) -> Result<Self> {
        let bytes = bytes.as_ref();
        let first_byte = *bytes
            .first()
            .ok_or_else(|| CrafterError::buffer_too_short("quic.short_header", 1, bytes.len()))?;
        if first_byte & QUIC_HEADER_FORM_MASK != 0 {
            return Err(CrafterError::invalid_field_value(
                "quic.short_header",
                "packet is not a short-header packet",
            ));
        }

        let dcid_start = 1usize;
        let dcid_end = dcid_start
            .checked_add(destination_connection_id_len)
            .ok_or_else(|| short_header_length_overflow_error())?;
        if bytes.len() < dcid_end {
            return Err(CrafterError::buffer_too_short(
                "quic.short_header.dcid",
                dcid_end,
                bytes.len(),
            ));
        }

        let packet_number_len = len_from_header_bits(first_byte);
        let packet_number_start = dcid_end;
        let protected_payload_start = packet_number_start
            .checked_add(packet_number_len)
            .ok_or_else(|| short_header_length_overflow_error())?;
        if bytes.len() < protected_payload_start {
            return Err(CrafterError::buffer_too_short(
                "quic.short_header.packet_number",
                protected_payload_start,
                bytes.len(),
            ));
        }
        let (packet_number, consumed) = QuicPacketNumber::decode(
            &bytes[packet_number_start..protected_payload_start],
            packet_number_len,
        )?;
        debug_assert_eq!(consumed, packet_number_len);

        Ok(Self {
            first_byte,
            fixed_bit: first_byte & QUIC_FIXED_BIT_MASK != 0,
            spin_bit: first_byte & QUIC_SHORT_SPIN_BIT_MASK != 0,
            reserved_bits: (first_byte & QUIC_SHORT_RESERVED_BITS_MASK) >> 3,
            key_phase: first_byte & QUIC_SHORT_KEY_PHASE_MASK != 0,
            destination_connection_id: QuicConnectionId::from_bytes(&bytes[dcid_start..dcid_end]),
            packet_number,
            packet_number_bytes: bytes[packet_number_start..protected_payload_start].to_vec(),
            protected_payload: bytes[protected_payload_start..].to_vec(),
            raw: bytes.to_vec(),
        })
    }

    fn from_short_header_parts(parts: QuicShortHeaderBuildParts) -> Result<Self> {
        let packet_number_encoded_len = parts.packet_number.effective_encoded_len()?;
        let mut raw = Vec::with_capacity(
            1 + parts.destination_connection_id.len()
                + packet_number_encoded_len
                + parts.protected_payload.len(),
        );
        raw.push(parts.first_byte);
        raw.extend_from_slice(parts.destination_connection_id.as_bytes());
        let packet_number_start = raw.len();
        parts.packet_number.encode(&mut raw)?;
        let protected_payload_start = raw.len();
        raw.extend_from_slice(&parts.protected_payload);

        Ok(Self {
            first_byte: parts.first_byte,
            fixed_bit: parts.first_byte & QUIC_FIXED_BIT_MASK != 0,
            spin_bit: parts.first_byte & QUIC_SHORT_SPIN_BIT_MASK != 0,
            reserved_bits: (parts.first_byte & QUIC_SHORT_RESERVED_BITS_MASK) >> 3,
            key_phase: parts.first_byte & QUIC_SHORT_KEY_PHASE_MASK != 0,
            destination_connection_id: parts.destination_connection_id,
            packet_number: QuicPacketNumber::new(parts.packet_number.value())
                .with_encoded_len(packet_number_encoded_len),
            packet_number_bytes: raw[packet_number_start..protected_payload_start].to_vec(),
            protected_payload: parts.protected_payload,
            raw,
        })
    }

    /// Raw first byte, including protected packet-type-specific bits.
    pub const fn first_byte(&self) -> u8 {
        self.first_byte
    }

    /// QUIC/fixed bit value.
    pub const fn fixed_bit(&self) -> bool {
        self.fixed_bit
    }

    /// Short-header spin bit value.
    pub const fn spin_bit(&self) -> bool {
        self.spin_bit
    }

    /// Short-header reserved bits.
    pub const fn reserved_bits(&self) -> u8 {
        self.reserved_bits
    }

    /// Short-header key phase bit.
    pub const fn key_phase(&self) -> bool {
        self.key_phase
    }

    /// Borrow the Destination Connection ID.
    pub fn destination_connection_id(&self) -> &QuicConnectionId {
        &self.destination_connection_id
    }

    /// Decoded truncated packet-number value.
    pub const fn packet_number(&self) -> QuicPacketNumber {
        self.packet_number
    }

    /// Borrow the raw packet-number bytes.
    pub fn packet_number_bytes(&self) -> &[u8] {
        &self.packet_number_bytes
    }

    /// Borrow the protected payload bytes after the packet number.
    pub fn protected_payload(&self) -> &[u8] {
        &self.protected_payload
    }

    /// Borrow the preserved packet bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Packet length in bytes.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Return true when no packet bytes are present.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// One-line short-header summary.
    pub fn summary(&self) -> String {
        format!(
            "ShortHeader(raw_len={}, fixed_bit={}, spin_bit={}, reserved_bits={}, key_phase={}, dcid={}, packet_number={}, protected_payload_len={})",
            self.raw.len(),
            self.fixed_bit,
            self.spin_bit,
            self.reserved_bits,
            self.key_phase,
            self.destination_connection_id.summary(),
            self.packet_number.summary(),
            self.protected_payload.len(),
        )
    }

    /// Stable field/value pairs for packet inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("classification", "short_header".to_string()),
            ("header_form", "short".to_string()),
            ("first_byte", format!("0x{:02x}", self.first_byte)),
            ("fixed_bit", self.fixed_bit.to_string()),
            ("spin_bit", self.spin_bit.to_string()),
            ("reserved_bits", self.reserved_bits.to_string()),
            ("key_phase", self.key_phase.to_string()),
            (
                "destination_connection_id_len",
                self.destination_connection_id.len().to_string(),
            ),
            (
                "destination_connection_id",
                self.destination_connection_id.to_spaced_hex(),
            ),
            ("packet_number", self.packet_number.value().to_string()),
            (
                "packet_number_encoded_len",
                self.packet_number
                    .encoded_len_value()
                    .unwrap_or_default()
                    .to_string(),
            ),
            ("packet_number_bytes", hex_bytes(&self.packet_number_bytes)),
            (
                "protected_payload_len",
                self.protected_payload.len().to_string(),
            ),
            ("protected_payload", hex_bytes(&self.protected_payload)),
            ("raw_len", self.raw.len().to_string()),
            ("raw_bytes", hex_bytes(&self.raw)),
        ]
    }
}

fn short_header_length_overflow_error() -> CrafterError {
    CrafterError::invalid_field_value(
        "quic.short_header.length",
        "QUIC short-header length exceeds addressable packet bytes",
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QuicShortHeaderBuildParts {
    first_byte: u8,
    destination_connection_id: QuicConnectionId,
    packet_number: QuicPacketNumber,
    protected_payload: Vec<u8>,
}

/// Builder for QUIC short-header packet emission.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicShortHeaderBuilder {
    first_byte: Field<u8>,
    fixed_bit: Field<bool>,
    spin_bit: Field<bool>,
    reserved_bits: Field<u8>,
    key_phase: Field<bool>,
    destination_connection_id: Field<QuicConnectionId>,
    packet_number: Field<QuicPacketNumber>,
    protected_payload: Field<Vec<u8>>,
}

impl QuicShortHeaderBuilder {
    /// Create a short-header builder with fields left available for defaults.
    pub fn new() -> Self {
        Self {
            first_byte: Field::unset(),
            fixed_bit: Field::unset(),
            spin_bit: Field::unset(),
            reserved_bits: Field::unset(),
            key_phase: Field::unset(),
            destination_connection_id: Field::unset(),
            packet_number: Field::unset(),
            protected_payload: Field::unset(),
        }
    }

    /// Pin byte 0 explicitly, including intentionally malformed values.
    pub fn first_byte(mut self, first_byte: u8) -> Self {
        self.first_byte.set_user(first_byte);
        self
    }

    /// Set the QUIC/fixed bit used when byte 0 is not pinned explicitly.
    pub fn fixed_bit(mut self, fixed_bit: bool) -> Self {
        self.fixed_bit.set_user(fixed_bit);
        self
    }

    /// Set the short-header spin bit used when byte 0 is not pinned explicitly.
    pub fn spin_bit(mut self, spin_bit: bool) -> Self {
        self.spin_bit.set_user(spin_bit);
        self
    }

    /// Set the two reserved bits used when byte 0 is not pinned explicitly.
    pub fn reserved_bits(mut self, reserved_bits: u8) -> Self {
        self.reserved_bits.set_user(reserved_bits);
        self
    }

    /// Set the short-header key phase bit used when byte 0 is not pinned explicitly.
    pub fn key_phase(mut self, key_phase: bool) -> Self {
        self.key_phase.set_user(key_phase);
        self
    }

    /// Set the Destination Connection ID bytes.
    pub fn destination_connection_id(mut self, connection_id: QuicConnectionId) -> Self {
        self.destination_connection_id.set_user(connection_id);
        self
    }

    /// Set the packet number and optional encoded-length override.
    pub fn packet_number(mut self, packet_number: QuicPacketNumber) -> Self {
        self.packet_number.set_user(packet_number);
        self
    }

    /// Set the protected/raw packet payload bytes.
    pub fn protected_payload(mut self, payload: impl AsRef<[u8]>) -> Self {
        self.protected_payload.set_user(payload.as_ref().to_vec());
        self
    }

    /// Compatibility alias for callers treating the packet payload as raw bytes.
    pub fn payload(self, payload: impl AsRef<[u8]>) -> Self {
        self.protected_payload(payload)
    }

    /// Append one raw-preserving frame placeholder to the protected payload.
    pub fn frame(mut self, frame: QuicFrame) -> Self {
        if self.protected_payload.is_unset() {
            self.protected_payload.set_user(Vec::new());
        }
        self.protected_payload
            .value_mut()
            .expect("payload set above")
            .extend_from_slice(frame.as_bytes());
        self
    }

    /// Append raw-preserving frame placeholders to the protected payload.
    pub fn frames(mut self, frames: impl IntoIterator<Item = QuicFrame>) -> Self {
        append_frame_sequence(&mut self.protected_payload, frames);
        self
    }

    /// Build short-header packet bytes without inferring endpoint connection ID state.
    pub fn build(self) -> Result<QuicShortHeaderPacket> {
        let destination_connection_id = self
            .destination_connection_id
            .into_value()
            .unwrap_or_default();
        let protected_payload = self.protected_payload.into_value().unwrap_or_default();
        let packet_number = self
            .packet_number
            .into_value()
            .unwrap_or_else(|| QuicPacketNumber::new(0));
        let packet_number_encoded_len = packet_number.effective_encoded_len()?;
        let first_byte = match self.first_byte.into_value() {
            Some(first_byte) => first_byte,
            None => default_short_header_first_byte(
                packet_number_encoded_len,
                self.fixed_bit.into_value().unwrap_or(true),
                self.spin_bit.into_value().unwrap_or(false),
                self.reserved_bits.into_value().unwrap_or(0),
                self.key_phase.into_value().unwrap_or(false),
            )?,
        };

        QuicShortHeaderPacket::from_short_header_parts(QuicShortHeaderBuildParts {
            first_byte,
            destination_connection_id,
            packet_number,
            protected_payload,
        })
    }
}

fn append_frame_sequence(
    protected_payload: &mut Field<Vec<u8>>,
    frames: impl IntoIterator<Item = QuicFrame>,
) {
    let encoded = QuicFrame::encode_sequence(frames);
    if encoded.is_empty() {
        return;
    }
    if protected_payload.is_unset() {
        protected_payload.set_user(Vec::new());
    }
    protected_payload
        .value_mut()
        .expect("payload set above")
        .extend_from_slice(&encoded);
}

fn default_short_header_first_byte(
    packet_number_encoded_len: usize,
    fixed_bit: bool,
    spin_bit: bool,
    reserved_bits: u8,
    key_phase: bool,
) -> Result<u8> {
    if reserved_bits > 0x03 {
        return Err(CrafterError::invalid_field_value(
            "quic.short_header.reserved_bits",
            "QUIC short-header reserved bits must fit in 2 bits",
        ));
    }

    let mut first_byte = header_bits_for_len(packet_number_encoded_len)?;
    if fixed_bit {
        first_byte |= QUIC_FIXED_BIT_MASK;
    }
    if spin_bit {
        first_byte |= QUIC_SHORT_SPIN_BIT_MASK;
    }
    first_byte |= reserved_bits << 3;
    if key_phase {
        first_byte |= QUIC_SHORT_KEY_PHASE_MASK;
    }
    Ok(first_byte)
}

/// Decoded QUIC Initial, 0-RTT, or Handshake long-header packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicLongHeaderPacket {
    first_byte: u8,
    version: u32,
    packet_kind: QuicLongPacketKind,
    destination_connection_id: QuicConnectionId,
    source_connection_id: QuicConnectionId,
    token_length: Option<QuicVarInt>,
    token_length_encoded_len: Option<usize>,
    token: Vec<u8>,
    length: QuicVarInt,
    length_encoded_len: usize,
    packet_number: QuicPacketNumber,
    packet_number_bytes: Vec<u8>,
    protected_payload: Vec<u8>,
    raw: Vec<u8>,
}

impl QuicLongHeaderPacket {
    /// Start building a QUIC Initial packet.
    pub fn initial_builder() -> QuicInitialBuilder {
        QuicInitialBuilder::new()
    }

    /// Start building a QUIC Handshake packet.
    pub fn handshake_builder() -> QuicHandshakeBuilder {
        QuicHandshakeBuilder::new()
    }

    /// Start building a QUIC 0-RTT packet.
    pub fn zero_rtt_builder() -> QuicZeroRttBuilder {
        QuicZeroRttBuilder::new()
    }

    /// Decode a byte-complete Initial, 0-RTT, or Handshake long-header packet.
    ///
    /// The QUIC Length field covers the packet-number bytes plus the protected
    /// payload. Bytes after that span belong to later coalesced packets and are
    /// not included in this packet's preserved raw bytes.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let classification = classify_quic_header(bytes)?;
        let QuicHeaderClassification::LongHeader {
            first_byte,
            version,
            destination_connection_id,
            source_connection_id,
            invariant_len,
            packet_kind:
                packet_kind @ (QuicLongPacketKind::Initial
                | QuicLongPacketKind::ZeroRtt
                | QuicLongPacketKind::Handshake),
            ..
        } = classification
        else {
            return Err(CrafterError::invalid_field_value(
                "quic.long_header",
                "packet is not an Initial, 0-RTT, or Handshake packet",
            ));
        };

        let (token_length, token_length_encoded_len, token, length_start) =
            if packet_kind == QuicLongPacketKind::Initial {
                let token_length_start = invariant_len;
                let first_token_length_byte =
                    bytes.get(token_length_start).copied().ok_or_else(|| {
                        CrafterError::buffer_too_short(
                            "quic.initial.token_length",
                            token_length_start + 1,
                            bytes.len(),
                        )
                    })?;
                let token_length_encoded_len = encoded_len_from_prefix(first_token_length_byte);
                let token_length_end = token_length_start
                    .checked_add(token_length_encoded_len)
                    .ok_or_else(|| initial_token_length_overflow_error())?;
                if bytes.len() < token_length_end {
                    return Err(CrafterError::buffer_too_short(
                        "quic.initial.token_length",
                        token_length_end,
                        bytes.len(),
                    ));
                }
                let (token_length, consumed) =
                    QuicVarInt::decode(&bytes[token_length_start..token_length_end])?;
                debug_assert_eq!(consumed, token_length_encoded_len);

                let token_len = usize::try_from(token_length.value())
                    .map_err(|_| initial_token_length_overflow_error())?;
                let token_end = token_length_end
                    .checked_add(token_len)
                    .ok_or_else(|| initial_token_length_overflow_error())?;
                if bytes.len() < token_end {
                    return Err(CrafterError::buffer_too_short(
                        "quic.initial.token",
                        token_end,
                        bytes.len(),
                    ));
                }

                (
                    Some(token_length),
                    Some(token_length_encoded_len),
                    bytes[token_length_end..token_end].to_vec(),
                    token_end,
                )
            } else {
                (None, None, Vec::new(), invariant_len)
            };

        let first_length_byte = bytes.get(length_start).copied().ok_or_else(|| {
            CrafterError::buffer_too_short("quic.long_header.length", length_start + 1, bytes.len())
        })?;
        let length_encoded_len = encoded_len_from_prefix(first_length_byte);
        let length_end = length_start
            .checked_add(length_encoded_len)
            .ok_or_else(|| length_overflow_error())?;
        if bytes.len() < length_end {
            return Err(CrafterError::buffer_too_short(
                "quic.long_header.length",
                length_end,
                bytes.len(),
            ));
        }
        let (length, consumed) = QuicVarInt::decode(&bytes[length_start..length_end])?;
        debug_assert_eq!(consumed, length_encoded_len);

        let packet_number_len = len_from_header_bits(first_byte);
        let length_value = usize::try_from(length.value()).map_err(|_| length_overflow_error())?;
        if length_value < packet_number_len {
            return Err(CrafterError::invalid_field_value(
                "quic.long_header.length",
                "QUIC long-header length must cover the packet number",
            ));
        }

        let packet_number_start = length_end;
        let protected_payload_start = packet_number_start
            .checked_add(packet_number_len)
            .ok_or_else(|| length_overflow_error())?;
        if bytes.len() < protected_payload_start {
            return Err(CrafterError::buffer_too_short(
                "quic.long_header.packet_number",
                protected_payload_start,
                bytes.len(),
            ));
        }

        let packet_end = length_end
            .checked_add(length_value)
            .ok_or_else(|| length_overflow_error())?;
        if bytes.len() < packet_end {
            return Err(CrafterError::buffer_too_short(
                "quic.long_header.protected_payload",
                packet_end,
                bytes.len(),
            ));
        }

        let (packet_number, consumed) = QuicPacketNumber::decode(
            &bytes[packet_number_start..protected_payload_start],
            packet_number_len,
        )?;
        debug_assert_eq!(consumed, packet_number_len);

        Ok(Self {
            first_byte,
            version,
            packet_kind,
            destination_connection_id,
            source_connection_id,
            token_length,
            token_length_encoded_len,
            token,
            length,
            length_encoded_len,
            packet_number,
            packet_number_bytes: bytes[packet_number_start..protected_payload_start].to_vec(),
            protected_payload: bytes[protected_payload_start..packet_end].to_vec(),
            raw: bytes[..packet_end].to_vec(),
        })
    }

    /// Raw first byte, including protected packet-type-specific bits.
    pub const fn first_byte(&self) -> u8 {
        self.first_byte
    }

    /// QUIC version field.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Version-specific long-header packet kind.
    pub const fn packet_kind(&self) -> QuicLongPacketKind {
        self.packet_kind
    }

    /// Borrow the Destination Connection ID.
    pub fn destination_connection_id(&self) -> &QuicConnectionId {
        &self.destination_connection_id
    }

    /// Borrow the Source Connection ID.
    pub fn source_connection_id(&self) -> &QuicConnectionId {
        &self.source_connection_id
    }

    /// Decoded Initial Token Length field, when this is an Initial packet.
    pub const fn token_length(&self) -> Option<QuicVarInt> {
        self.token_length
    }

    /// Encoded width of the Initial Token Length field, when present.
    pub const fn token_length_encoded_len(&self) -> Option<usize> {
        self.token_length_encoded_len
    }

    /// Borrow the Initial token bytes. Non-Initial packets return an empty slice.
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// Decoded QUIC Length field value.
    pub const fn length(&self) -> QuicVarInt {
        self.length
    }

    /// Encoded width of the QUIC Length field.
    pub const fn length_encoded_len(&self) -> usize {
        self.length_encoded_len
    }

    /// Decoded truncated packet-number value.
    pub const fn packet_number(&self) -> QuicPacketNumber {
        self.packet_number
    }

    /// Borrow the raw packet-number bytes.
    pub fn packet_number_bytes(&self) -> &[u8] {
        &self.packet_number_bytes
    }

    /// Borrow the protected payload bytes after the packet number.
    pub fn protected_payload(&self) -> &[u8] {
        &self.protected_payload
    }

    /// Borrow the preserved packet bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Packet length in bytes.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Return true when no packet bytes are present.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// One-line long-header summary.
    pub fn summary(&self) -> String {
        format!(
            "{}(raw_len={}, version=0x{:08x}({}), dcid={}, scid={}, token_len={}, length={} length_encoded_len={}, packet_number={}, protected_payload_len={})",
            self.packet_kind.label(),
            self.raw.len(),
            self.version,
            quic_version_label(self.version),
            self.destination_connection_id.summary(),
            self.source_connection_id.summary(),
            self.token.len(),
            self.length.value(),
            self.length_encoded_len,
            self.packet_number.summary(),
            self.protected_payload.len(),
        )
    }

    /// Stable field/value pairs for packet inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("classification", "long_header_packet".to_string()),
            ("packet_kind", self.packet_kind.label().to_string()),
            ("first_byte", format!("0x{:02x}", self.first_byte)),
            (
                "version",
                format!(
                    "0x{:08x} ({})",
                    self.version,
                    quic_version_label(self.version)
                ),
            ),
            (
                "version_status",
                format!("{:?}", quic_version_status(self.version)),
            ),
            (
                "destination_connection_id_len",
                self.destination_connection_id.len().to_string(),
            ),
            (
                "destination_connection_id",
                self.destination_connection_id.to_spaced_hex(),
            ),
            (
                "source_connection_id_len",
                self.source_connection_id.len().to_string(),
            ),
            (
                "source_connection_id",
                self.source_connection_id.to_spaced_hex(),
            ),
            (
                "token_length",
                self.token_length
                    .map(|length| length.value().to_string())
                    .unwrap_or_else(|| "<none>".to_string()),
            ),
            (
                "token_length_encoded_len",
                self.token_length_encoded_len
                    .map(|len| len.to_string())
                    .unwrap_or_else(|| "<none>".to_string()),
            ),
            ("token_len", self.token.len().to_string()),
            ("token", hex_bytes(&self.token)),
            ("length", self.length.value().to_string()),
            ("length_encoded_len", self.length_encoded_len.to_string()),
            ("packet_number", self.packet_number.value().to_string()),
            (
                "packet_number_encoded_len",
                self.packet_number
                    .encoded_len_value()
                    .unwrap_or_default()
                    .to_string(),
            ),
            ("packet_number_bytes", hex_bytes(&self.packet_number_bytes)),
            (
                "protected_payload_len",
                self.protected_payload.len().to_string(),
            ),
            ("protected_payload", hex_bytes(&self.protected_payload)),
            ("raw_len", self.raw.len().to_string()),
            ("raw_bytes", hex_bytes(&self.raw)),
        ]
    }
}

fn length_overflow_error() -> CrafterError {
    CrafterError::invalid_field_value(
        "quic.long_header.length",
        "QUIC long-header length exceeds addressable packet bytes",
    )
}

fn initial_token_length_overflow_error() -> CrafterError {
    CrafterError::invalid_field_value(
        "quic.initial.token_length",
        "QUIC Initial token length exceeds addressable packet bytes",
    )
}

/// Builder for QUIC 0-RTT packet emission.
///
/// This only emits packet bytes. Replay checks, remembered transport parameter
/// validation, and endpoint 0-RTT acceptance policy are intentionally out of
/// scope for this packet primitive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicZeroRttBuilder {
    first_byte: Field<u8>,
    version: Field<u32>,
    destination_connection_id: Field<QuicConnectionId>,
    source_connection_id: Field<QuicConnectionId>,
    length: Field<QuicVarInt>,
    length_encoded_len: Field<usize>,
    packet_number: Field<QuicPacketNumber>,
    protected_payload: Field<Vec<u8>>,
}

impl QuicZeroRttBuilder {
    /// Create a 0-RTT builder with fields left available for defaults.
    pub fn new() -> Self {
        Self {
            first_byte: Field::unset(),
            version: Field::unset(),
            destination_connection_id: Field::unset(),
            source_connection_id: Field::unset(),
            length: Field::unset(),
            length_encoded_len: Field::unset(),
            packet_number: Field::unset(),
            protected_payload: Field::unset(),
        }
    }

    /// Pin byte 0 explicitly, including intentionally malformed values.
    pub fn first_byte(mut self, first_byte: u8) -> Self {
        self.first_byte.set_user(first_byte);
        self
    }

    /// Set the QUIC version field. Defaults to QUIC v1.
    pub fn version(mut self, version: u32) -> Self {
        self.version.set_user(version);
        self
    }

    /// Set the Destination Connection ID bytes.
    pub fn destination_connection_id(mut self, connection_id: QuicConnectionId) -> Self {
        self.destination_connection_id.set_user(connection_id);
        self
    }

    /// Set the Source Connection ID bytes.
    pub fn source_connection_id(mut self, connection_id: QuicConnectionId) -> Self {
        self.source_connection_id.set_user(connection_id);
        self
    }

    /// Pin the QUIC Length field value, including intentionally malformed values.
    pub fn length(mut self, length: QuicVarInt) -> Self {
        self.length.set_user(length);
        self
    }

    /// Pin the encoded width of the QUIC Length varint.
    pub fn length_encoded_len(mut self, encoded_len: usize) -> Self {
        self.length_encoded_len.set_user(encoded_len);
        self
    }

    /// Set the packet number and optional encoded-length override.
    pub fn packet_number(mut self, packet_number: QuicPacketNumber) -> Self {
        self.packet_number.set_user(packet_number);
        self
    }

    /// Set the protected/raw packet payload bytes.
    pub fn protected_payload(mut self, payload: impl AsRef<[u8]>) -> Self {
        self.protected_payload.set_user(payload.as_ref().to_vec());
        self
    }

    /// Compatibility alias for callers treating the packet payload as raw bytes.
    pub fn payload(self, payload: impl AsRef<[u8]>) -> Self {
        self.protected_payload(payload)
    }

    /// Append one raw-preserving frame placeholder to the protected payload.
    pub fn frame(mut self, frame: QuicFrame) -> Self {
        if self.protected_payload.is_unset() {
            self.protected_payload.set_user(Vec::new());
        }
        self.protected_payload
            .value_mut()
            .expect("payload set above")
            .extend_from_slice(frame.as_bytes());
        self
    }

    /// Append raw-preserving frame placeholders to the protected payload.
    pub fn frames(mut self, frames: impl IntoIterator<Item = QuicFrame>) -> Self {
        append_frame_sequence(&mut self.protected_payload, frames);
        self
    }

    /// Build 0-RTT packet bytes without applying endpoint acceptance policy.
    pub fn build(self) -> Result<QuicLongHeaderPacket> {
        let version = self.version.into_value().unwrap_or(QUIC_VERSION_1);
        let destination_connection_id = self
            .destination_connection_id
            .into_value()
            .unwrap_or_default();
        let source_connection_id = self.source_connection_id.into_value().unwrap_or_default();
        let protected_payload = self.protected_payload.into_value().unwrap_or_default();
        let packet_number = self
            .packet_number
            .into_value()
            .unwrap_or_else(|| QuicPacketNumber::new(0));
        let packet_number_encoded_len = packet_number.effective_encoded_len()?;
        let first_byte = match self.first_byte.into_value() {
            Some(first_byte) => first_byte,
            None => default_zero_rtt_first_byte(version, packet_number_encoded_len)?,
        };
        let length = match self.length.into_value() {
            Some(length) => length,
            None => {
                let body_len = packet_number_encoded_len
                    .checked_add(protected_payload.len())
                    .ok_or_else(|| length_overflow_error())?;
                QuicVarInt::new(u64::try_from(body_len).map_err(|_| length_overflow_error())?)?
            }
        };

        QuicLongHeaderPacket::from_long_header_parts(QuicLongHeaderBuildParts {
            packet_kind: QuicLongPacketKind::ZeroRtt,
            first_byte,
            version,
            destination_connection_id,
            source_connection_id,
            token_length: None,
            token_length_encoded_len: None,
            token: Vec::new(),
            length,
            length_encoded_len: self.length_encoded_len.into_value(),
            packet_number,
            protected_payload,
        })
    }
}

/// Builder for QUIC Handshake packet emission.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicHandshakeBuilder {
    first_byte: Field<u8>,
    version: Field<u32>,
    destination_connection_id: Field<QuicConnectionId>,
    source_connection_id: Field<QuicConnectionId>,
    length: Field<QuicVarInt>,
    length_encoded_len: Field<usize>,
    packet_number: Field<QuicPacketNumber>,
    protected_payload: Field<Vec<u8>>,
}

impl QuicHandshakeBuilder {
    /// Create a Handshake builder with fields left available for defaults.
    pub fn new() -> Self {
        Self {
            first_byte: Field::unset(),
            version: Field::unset(),
            destination_connection_id: Field::unset(),
            source_connection_id: Field::unset(),
            length: Field::unset(),
            length_encoded_len: Field::unset(),
            packet_number: Field::unset(),
            protected_payload: Field::unset(),
        }
    }

    /// Pin byte 0 explicitly, including intentionally malformed values.
    pub fn first_byte(mut self, first_byte: u8) -> Self {
        self.first_byte.set_user(first_byte);
        self
    }

    /// Set the QUIC version field. Defaults to QUIC v1.
    pub fn version(mut self, version: u32) -> Self {
        self.version.set_user(version);
        self
    }

    /// Set the Destination Connection ID bytes.
    pub fn destination_connection_id(mut self, connection_id: QuicConnectionId) -> Self {
        self.destination_connection_id.set_user(connection_id);
        self
    }

    /// Set the Source Connection ID bytes.
    pub fn source_connection_id(mut self, connection_id: QuicConnectionId) -> Self {
        self.source_connection_id.set_user(connection_id);
        self
    }

    /// Pin the QUIC Length field value, including intentionally malformed values.
    pub fn length(mut self, length: QuicVarInt) -> Self {
        self.length.set_user(length);
        self
    }

    /// Pin the encoded width of the QUIC Length varint.
    pub fn length_encoded_len(mut self, encoded_len: usize) -> Self {
        self.length_encoded_len.set_user(encoded_len);
        self
    }

    /// Set the packet number and optional encoded-length override.
    pub fn packet_number(mut self, packet_number: QuicPacketNumber) -> Self {
        self.packet_number.set_user(packet_number);
        self
    }

    /// Set the protected/raw packet payload bytes.
    pub fn protected_payload(mut self, payload: impl AsRef<[u8]>) -> Self {
        self.protected_payload.set_user(payload.as_ref().to_vec());
        self
    }

    /// Compatibility alias for callers treating the packet payload as raw bytes.
    pub fn payload(self, payload: impl AsRef<[u8]>) -> Self {
        self.protected_payload(payload)
    }

    /// Append one raw-preserving frame placeholder to the protected payload.
    pub fn frame(mut self, frame: QuicFrame) -> Self {
        if self.protected_payload.is_unset() {
            self.protected_payload.set_user(Vec::new());
        }
        self.protected_payload
            .value_mut()
            .expect("payload set above")
            .extend_from_slice(frame.as_bytes());
        self
    }

    /// Append raw-preserving frame placeholders to the protected payload.
    pub fn frames(mut self, frames: impl IntoIterator<Item = QuicFrame>) -> Self {
        append_frame_sequence(&mut self.protected_payload, frames);
        self
    }

    /// Build Handshake packet bytes.
    pub fn build(self) -> Result<QuicLongHeaderPacket> {
        let version = self.version.into_value().unwrap_or(QUIC_VERSION_1);
        let destination_connection_id = self
            .destination_connection_id
            .into_value()
            .unwrap_or_default();
        let source_connection_id = self.source_connection_id.into_value().unwrap_or_default();
        let protected_payload = self.protected_payload.into_value().unwrap_or_default();
        let packet_number = self
            .packet_number
            .into_value()
            .unwrap_or_else(|| QuicPacketNumber::new(0));
        let packet_number_encoded_len = packet_number.effective_encoded_len()?;
        let first_byte = match self.first_byte.into_value() {
            Some(first_byte) => first_byte,
            None => default_handshake_first_byte(version, packet_number_encoded_len)?,
        };
        let length = match self.length.into_value() {
            Some(length) => length,
            None => {
                let body_len = packet_number_encoded_len
                    .checked_add(protected_payload.len())
                    .ok_or_else(|| length_overflow_error())?;
                QuicVarInt::new(u64::try_from(body_len).map_err(|_| length_overflow_error())?)?
            }
        };

        QuicLongHeaderPacket::from_long_header_parts(QuicLongHeaderBuildParts {
            packet_kind: QuicLongPacketKind::Handshake,
            first_byte,
            version,
            destination_connection_id,
            source_connection_id,
            token_length: None,
            token_length_encoded_len: None,
            token: Vec::new(),
            length,
            length_encoded_len: self.length_encoded_len.into_value(),
            packet_number,
            protected_payload,
        })
    }
}

/// Builder for QUIC Initial packet emission.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicInitialBuilder {
    first_byte: Field<u8>,
    version: Field<u32>,
    destination_connection_id: Field<QuicConnectionId>,
    source_connection_id: Field<QuicConnectionId>,
    token_length: Field<QuicVarInt>,
    token_length_encoded_len: Field<usize>,
    token: Field<Vec<u8>>,
    length: Field<QuicVarInt>,
    length_encoded_len: Field<usize>,
    packet_number: Field<QuicPacketNumber>,
    protected_payload: Field<Vec<u8>>,
}

impl QuicInitialBuilder {
    /// Create an Initial builder with fields left available for defaults.
    pub fn new() -> Self {
        Self {
            first_byte: Field::unset(),
            version: Field::unset(),
            destination_connection_id: Field::unset(),
            source_connection_id: Field::unset(),
            token_length: Field::unset(),
            token_length_encoded_len: Field::unset(),
            token: Field::unset(),
            length: Field::unset(),
            length_encoded_len: Field::unset(),
            packet_number: Field::unset(),
            protected_payload: Field::unset(),
        }
    }

    /// Pin byte 0 explicitly, including intentionally malformed values.
    pub fn first_byte(mut self, first_byte: u8) -> Self {
        self.first_byte.set_user(first_byte);
        self
    }

    /// Set the QUIC version field. Defaults to QUIC v1.
    pub fn version(mut self, version: u32) -> Self {
        self.version.set_user(version);
        self
    }

    /// Set the Destination Connection ID bytes.
    pub fn destination_connection_id(mut self, connection_id: QuicConnectionId) -> Self {
        self.destination_connection_id.set_user(connection_id);
        self
    }

    /// Set the Source Connection ID bytes.
    pub fn source_connection_id(mut self, connection_id: QuicConnectionId) -> Self {
        self.source_connection_id.set_user(connection_id);
        self
    }

    /// Pin the Initial Token Length field value, including malformed mismatches.
    pub fn token_length(mut self, token_length: QuicVarInt) -> Self {
        self.token_length.set_user(token_length);
        self
    }

    /// Pin the encoded width of the Initial Token Length varint.
    pub fn token_length_encoded_len(mut self, encoded_len: usize) -> Self {
        self.token_length_encoded_len.set_user(encoded_len);
        self
    }

    /// Set the Initial token bytes. Defaults to an empty token.
    pub fn token(mut self, token: impl AsRef<[u8]>) -> Self {
        self.token.set_user(token.as_ref().to_vec());
        self
    }

    /// Pin the QUIC Length field value, including intentionally malformed values.
    pub fn length(mut self, length: QuicVarInt) -> Self {
        self.length.set_user(length);
        self
    }

    /// Pin the encoded width of the QUIC Length varint.
    pub fn length_encoded_len(mut self, encoded_len: usize) -> Self {
        self.length_encoded_len.set_user(encoded_len);
        self
    }

    /// Set the packet number and optional encoded-length override.
    pub fn packet_number(mut self, packet_number: QuicPacketNumber) -> Self {
        self.packet_number.set_user(packet_number);
        self
    }

    /// Set the protected/raw packet payload bytes.
    pub fn protected_payload(mut self, payload: impl AsRef<[u8]>) -> Self {
        self.protected_payload.set_user(payload.as_ref().to_vec());
        self
    }

    /// Compatibility alias for callers treating the packet payload as raw bytes.
    pub fn payload(self, payload: impl AsRef<[u8]>) -> Self {
        self.protected_payload(payload)
    }

    /// Append one raw-preserving frame placeholder to the protected payload.
    pub fn frame(mut self, frame: QuicFrame) -> Self {
        if self.protected_payload.is_unset() {
            self.protected_payload.set_user(Vec::new());
        }
        self.protected_payload
            .value_mut()
            .expect("payload set above")
            .extend_from_slice(frame.as_bytes());
        self
    }

    /// Append raw-preserving frame placeholders to the protected payload.
    pub fn frames(mut self, frames: impl IntoIterator<Item = QuicFrame>) -> Self {
        append_frame_sequence(&mut self.protected_payload, frames);
        self
    }

    /// Build Initial packet bytes.
    pub fn build(self) -> Result<QuicLongHeaderPacket> {
        let version = self.version.into_value().unwrap_or(QUIC_VERSION_1);
        let destination_connection_id = self
            .destination_connection_id
            .into_value()
            .unwrap_or_default();
        let source_connection_id = self.source_connection_id.into_value().unwrap_or_default();
        let token = self.token.into_value().unwrap_or_default();
        let protected_payload = self.protected_payload.into_value().unwrap_or_default();
        let packet_number = self
            .packet_number
            .into_value()
            .unwrap_or_else(|| QuicPacketNumber::new(0));
        let packet_number_encoded_len = packet_number.effective_encoded_len()?;
        let first_byte = match self.first_byte.into_value() {
            Some(first_byte) => first_byte,
            None => default_initial_first_byte(version, packet_number_encoded_len)?,
        };

        let token_length = match self.token_length.into_value() {
            Some(token_length) => token_length,
            None => QuicVarInt::new(
                u64::try_from(token.len()).map_err(|_| initial_token_length_overflow_error())?,
            )?,
        };
        let length = match self.length.into_value() {
            Some(length) => length,
            None => {
                let body_len = packet_number_encoded_len
                    .checked_add(protected_payload.len())
                    .ok_or_else(|| length_overflow_error())?;
                QuicVarInt::new(u64::try_from(body_len).map_err(|_| length_overflow_error())?)?
            }
        };

        QuicLongHeaderPacket::from_long_header_parts(QuicLongHeaderBuildParts {
            packet_kind: QuicLongPacketKind::Initial,
            first_byte,
            version,
            destination_connection_id,
            source_connection_id,
            token_length: Some(token_length),
            token_length_encoded_len: self.token_length_encoded_len.into_value(),
            token,
            length,
            length_encoded_len: self.length_encoded_len.into_value(),
            packet_number,
            protected_payload,
        })
    }
}

#[derive(Debug, Clone)]
struct QuicLongHeaderBuildParts {
    packet_kind: QuicLongPacketKind,
    first_byte: u8,
    version: u32,
    destination_connection_id: QuicConnectionId,
    source_connection_id: QuicConnectionId,
    token_length: Option<QuicVarInt>,
    token_length_encoded_len: Option<usize>,
    token: Vec<u8>,
    length: QuicVarInt,
    length_encoded_len: Option<usize>,
    packet_number: QuicPacketNumber,
    protected_payload: Vec<u8>,
}

impl QuicLongHeaderPacket {
    fn from_long_header_parts(parts: QuicLongHeaderBuildParts) -> Result<Self> {
        validate_one_byte_connection_id_len(parts.destination_connection_id.len())?;
        validate_one_byte_connection_id_len(parts.source_connection_id.len())?;

        let mut token_length_bytes = Vec::new();
        let token_length_encoded_len = match parts.token_length {
            Some(token_length) => {
                let encoded_len = match parts.token_length_encoded_len {
                    Some(encoded_len) => {
                        token_length.encode_with_len(encoded_len, &mut token_length_bytes)?;
                        encoded_len
                    }
                    None => token_length.encode(&mut token_length_bytes)?,
                };
                Some(encoded_len)
            }
            None => None,
        };
        let token = if parts.token_length.is_some() {
            parts.token
        } else {
            Vec::new()
        };

        let mut length_bytes = Vec::new();
        let length_encoded_len = match parts.length_encoded_len {
            Some(encoded_len) => {
                parts
                    .length
                    .encode_with_len(encoded_len, &mut length_bytes)?;
                encoded_len
            }
            None => parts.length.encode(&mut length_bytes)?,
        };

        let mut packet_number_bytes = Vec::new();
        parts.packet_number.encode(&mut packet_number_bytes)?;

        let mut raw = Vec::with_capacity(
            1 + 4
                + 1
                + parts.destination_connection_id.len()
                + 1
                + parts.source_connection_id.len()
                + token_length_bytes.len()
                + token.len()
                + length_bytes.len()
                + packet_number_bytes.len()
                + parts.protected_payload.len(),
        );
        raw.push(parts.first_byte);
        raw.extend_from_slice(&parts.version.to_be_bytes());
        raw.push(parts.destination_connection_id.len() as u8);
        raw.extend_from_slice(parts.destination_connection_id.as_bytes());
        raw.push(parts.source_connection_id.len() as u8);
        raw.extend_from_slice(parts.source_connection_id.as_bytes());
        raw.extend_from_slice(&token_length_bytes);
        raw.extend_from_slice(&token);
        raw.extend_from_slice(&length_bytes);
        raw.extend_from_slice(&packet_number_bytes);
        raw.extend_from_slice(&parts.protected_payload);

        Ok(Self {
            first_byte: parts.first_byte,
            version: parts.version,
            packet_kind: parts.packet_kind,
            destination_connection_id: parts.destination_connection_id,
            source_connection_id: parts.source_connection_id,
            token_length: parts.token_length,
            token_length_encoded_len,
            token,
            length: parts.length,
            length_encoded_len,
            packet_number: parts.packet_number,
            packet_number_bytes,
            protected_payload: parts.protected_payload,
            raw,
        })
    }
}

fn default_initial_first_byte(version: u32, packet_number_encoded_len: usize) -> Result<u8> {
    let packet_number_len_bits = header_bits_for_len(packet_number_encoded_len)?;
    match version {
        QUIC_VERSION_1 => Ok(0xc0 | packet_number_len_bits),
        QUIC_VERSION_2 => Ok(0xd0 | packet_number_len_bits),
        _ => Err(CrafterError::invalid_field_value(
            "quic.initial.version",
            "cannot infer Initial packet type bits for unsupported QUIC version",
        )),
    }
}

fn default_handshake_first_byte(version: u32, packet_number_encoded_len: usize) -> Result<u8> {
    let packet_number_len_bits = header_bits_for_len(packet_number_encoded_len)?;
    match version {
        QUIC_VERSION_1 => Ok(0xe0 | packet_number_len_bits),
        QUIC_VERSION_2 => Ok(0xf0 | packet_number_len_bits),
        _ => Err(CrafterError::invalid_field_value(
            "quic.handshake.version",
            "cannot infer Handshake packet type bits for unsupported QUIC version",
        )),
    }
}

fn default_zero_rtt_first_byte(version: u32, packet_number_encoded_len: usize) -> Result<u8> {
    let packet_number_len_bits = header_bits_for_len(packet_number_encoded_len)?;
    match version {
        QUIC_VERSION_1 => Ok(0xd0 | packet_number_len_bits),
        QUIC_VERSION_2 => Ok(0xe0 | packet_number_len_bits),
        _ => Err(CrafterError::invalid_field_value(
            "quic.zero_rtt.version",
            "cannot infer 0-RTT packet type bits for unsupported QUIC version",
        )),
    }
}

/// Decoded QUIC Retry packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicRetryPacket {
    first_byte: u8,
    version: u32,
    destination_connection_id: QuicConnectionId,
    source_connection_id: QuicConnectionId,
    token: Vec<u8>,
    integrity_tag: [u8; QUIC_RETRY_INTEGRITY_TAG_LEN],
    raw: Vec<u8>,
}

/// Retry Integrity Tag length in bytes.
pub const QUIC_RETRY_INTEGRITY_TAG_LEN: usize = 16;

impl QuicRetryPacket {
    /// Start building a Retry packet with explicit token and tag bytes.
    pub fn builder() -> QuicRetryBuilder {
        QuicRetryBuilder::new()
    }

    /// Build a Retry packet from the required fields.
    pub fn new(
        version: u32,
        destination_connection_id: QuicConnectionId,
        source_connection_id: QuicConnectionId,
        token: impl AsRef<[u8]>,
        integrity_tag: [u8; QUIC_RETRY_INTEGRITY_TAG_LEN],
    ) -> Result<Self> {
        Self::builder()
            .version(version)
            .destination_connection_id(destination_connection_id)
            .source_connection_id(source_connection_id)
            .token(token)
            .integrity_tag(integrity_tag)
            .build()
    }

    /// Decode a byte-complete Retry packet without verifying the integrity tag.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let classification = classify_quic_header(bytes)?;
        let QuicHeaderClassification::LongHeader {
            first_byte,
            version,
            destination_connection_id,
            source_connection_id,
            invariant_len,
            remaining_len,
            packet_kind: QuicLongPacketKind::Retry,
            ..
        } = classification
        else {
            return Err(CrafterError::invalid_field_value(
                "quic.retry",
                "packet is not a Retry packet",
            ));
        };

        if remaining_len < QUIC_RETRY_INTEGRITY_TAG_LEN {
            return Err(CrafterError::buffer_too_short(
                "quic.retry.integrity_tag",
                invariant_len + QUIC_RETRY_INTEGRITY_TAG_LEN,
                bytes.len(),
            ));
        }

        let tag_start = bytes.len() - QUIC_RETRY_INTEGRITY_TAG_LEN;
        let mut integrity_tag = [0u8; QUIC_RETRY_INTEGRITY_TAG_LEN];
        integrity_tag.copy_from_slice(&bytes[tag_start..]);

        Ok(Self {
            first_byte,
            version,
            destination_connection_id,
            source_connection_id,
            token: bytes[invariant_len..tag_start].to_vec(),
            integrity_tag,
            raw: bytes.to_vec(),
        })
    }

    fn from_parts(
        first_byte: u8,
        version: u32,
        destination_connection_id: QuicConnectionId,
        source_connection_id: QuicConnectionId,
        token: Vec<u8>,
        integrity_tag: [u8; QUIC_RETRY_INTEGRITY_TAG_LEN],
    ) -> Result<Self> {
        validate_one_byte_connection_id_len(destination_connection_id.len())?;
        validate_one_byte_connection_id_len(source_connection_id.len())?;

        let mut raw = Vec::with_capacity(
            1 + 4
                + 1
                + destination_connection_id.len()
                + 1
                + source_connection_id.len()
                + token.len()
                + QUIC_RETRY_INTEGRITY_TAG_LEN,
        );
        raw.push(first_byte);
        raw.extend_from_slice(&version.to_be_bytes());
        raw.push(destination_connection_id.len() as u8);
        raw.extend_from_slice(destination_connection_id.as_bytes());
        raw.push(source_connection_id.len() as u8);
        raw.extend_from_slice(source_connection_id.as_bytes());
        raw.extend_from_slice(&token);
        raw.extend_from_slice(&integrity_tag);

        Ok(Self {
            first_byte,
            version,
            destination_connection_id,
            source_connection_id,
            token,
            integrity_tag,
            raw,
        })
    }

    /// Raw first byte, including the unused low four bits.
    pub const fn first_byte(&self) -> u8 {
        self.first_byte
    }

    /// QUIC version field.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Borrow the Destination Connection ID.
    pub fn destination_connection_id(&self) -> &QuicConnectionId {
        &self.destination_connection_id
    }

    /// Borrow the Source Connection ID.
    pub fn source_connection_id(&self) -> &QuicConnectionId {
        &self.source_connection_id
    }

    /// Borrow the retry token bytes.
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// Borrow the Retry Integrity Tag bytes.
    pub fn integrity_tag(&self) -> &[u8; QUIC_RETRY_INTEGRITY_TAG_LEN] {
        &self.integrity_tag
    }

    /// Compute the Retry Integrity Tag for this packet and an Original DCID.
    pub fn computed_integrity_tag(
        &self,
        original_destination_connection_id: impl AsRef<[u8]>,
    ) -> Result<[u8; QUIC_RETRY_INTEGRITY_TAG_LEN]> {
        let retry_without_tag = &self.raw[..self.raw.len() - QUIC_RETRY_INTEGRITY_TAG_LEN];
        quic_retry_integrity_tag(
            self.version,
            original_destination_connection_id,
            retry_without_tag,
        )
    }

    /// Verify this packet's Retry Integrity Tag against an Original DCID.
    pub fn integrity_status(
        &self,
        original_destination_connection_id: impl AsRef<[u8]>,
    ) -> Result<QuicRetryIntegrityStatus> {
        quic_verify_retry_integrity_tag(original_destination_connection_id, self)
    }

    /// Borrow the preserved packet bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Packet length in bytes.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Return true when no packet bytes are present.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// One-line Retry summary.
    pub fn summary(&self) -> String {
        format!(
            "Retry(raw_len={}, version=0x{:08x}({}), dcid={}, scid={}, token_len={}, tag={})",
            self.raw.len(),
            self.version,
            quic_version_label(self.version),
            self.destination_connection_id.summary(),
            self.source_connection_id.summary(),
            self.token.len(),
            hex_bytes(&self.integrity_tag),
        )
    }

    /// Stable field/value pairs for packet inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("classification", "retry".to_string()),
            ("first_byte", format!("0x{:02x}", self.first_byte)),
            (
                "version",
                format!(
                    "0x{:08x} ({})",
                    self.version,
                    quic_version_label(self.version)
                ),
            ),
            (
                "version_status",
                format!("{:?}", quic_version_status(self.version)),
            ),
            (
                "destination_connection_id_len",
                self.destination_connection_id.len().to_string(),
            ),
            (
                "destination_connection_id",
                self.destination_connection_id.to_spaced_hex(),
            ),
            (
                "source_connection_id_len",
                self.source_connection_id.len().to_string(),
            ),
            (
                "source_connection_id",
                self.source_connection_id.to_spaced_hex(),
            ),
            ("token_len", self.token.len().to_string()),
            ("token", hex_bytes(&self.token)),
            (
                "retry_integrity_tag_len",
                QUIC_RETRY_INTEGRITY_TAG_LEN.to_string(),
            ),
            ("retry_integrity_tag", hex_bytes(&self.integrity_tag)),
            ("raw_len", self.raw.len().to_string()),
            ("raw_bytes", hex_bytes(&self.raw)),
        ]
    }
}

/// Builder for QUIC Retry packet emission.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicRetryBuilder {
    first_byte: Field<u8>,
    version: Field<u32>,
    destination_connection_id: Field<QuicConnectionId>,
    source_connection_id: Field<QuicConnectionId>,
    token: Field<Vec<u8>>,
    integrity_tag: Field<[u8; QUIC_RETRY_INTEGRITY_TAG_LEN]>,
    computed_integrity_original_destination_connection_id: Field<Vec<u8>>,
}

impl QuicRetryBuilder {
    /// Create an empty Retry builder.
    pub fn new() -> Self {
        Self {
            first_byte: Field::unset(),
            version: Field::unset(),
            destination_connection_id: Field::unset(),
            source_connection_id: Field::unset(),
            token: Field::unset(),
            integrity_tag: Field::unset(),
            computed_integrity_original_destination_connection_id: Field::unset(),
        }
    }

    /// Pin byte 0 explicitly, including intentionally malformed values.
    pub fn first_byte(mut self, first_byte: u8) -> Self {
        self.first_byte.set_user(first_byte);
        self
    }

    /// Set the QUIC version field.
    pub fn version(mut self, version: u32) -> Self {
        self.version.set_user(version);
        self
    }

    /// Set the Destination Connection ID bytes.
    pub fn destination_connection_id(mut self, connection_id: QuicConnectionId) -> Self {
        self.destination_connection_id.set_user(connection_id);
        self
    }

    /// Set the Source Connection ID bytes.
    pub fn source_connection_id(mut self, connection_id: QuicConnectionId) -> Self {
        self.source_connection_id.set_user(connection_id);
        self
    }

    /// Set the retry token bytes, including an explicitly empty token.
    pub fn token(mut self, token: impl AsRef<[u8]>) -> Self {
        self.token.set_user(token.as_ref().to_vec());
        self
    }

    /// Set the Retry Integrity Tag bytes.
    pub fn integrity_tag(mut self, integrity_tag: [u8; QUIC_RETRY_INTEGRITY_TAG_LEN]) -> Self {
        self.integrity_tag.set_user(integrity_tag);
        self
    }

    /// Compute the Retry Integrity Tag from the supplied Original DCID.
    pub fn compute_integrity_tag(
        mut self,
        original_destination_connection_id: impl AsRef<[u8]>,
    ) -> Self {
        self.computed_integrity_original_destination_connection_id
            .set_user(original_destination_connection_id.as_ref().to_vec());
        self
    }

    /// Build the packet bytes.
    pub fn build(self) -> Result<QuicRetryPacket> {
        let version = self.version.into_value().ok_or_else(|| {
            CrafterError::invalid_field_value(
                "quic.retry.version",
                "Retry packet version must be set",
            )
        })?;
        let first_byte = match self.first_byte.into_value() {
            Some(first_byte) => first_byte,
            None => default_retry_first_byte(version)?,
        };
        let destination_connection_id = self
            .destination_connection_id
            .into_value()
            .unwrap_or_default();
        let source_connection_id = self.source_connection_id.into_value().unwrap_or_default();
        let token = self.token.into_value().ok_or_else(|| {
            CrafterError::invalid_field_value("quic.retry.token", "Retry token must be set")
        })?;
        let explicit_integrity_tag = self.integrity_tag.into_value();
        let compute_original_destination_connection_id = self
            .computed_integrity_original_destination_connection_id
            .into_value();
        let integrity_tag = match (
            explicit_integrity_tag,
            compute_original_destination_connection_id,
        ) {
            (Some(integrity_tag), None) => integrity_tag,
            (Some(_), Some(_)) => {
                return Err(CrafterError::invalid_field_value(
                    "quic.retry.integrity_tag",
                    "Retry Integrity Tag cannot be both explicit and computed",
                ))
            }
            (None, Some(original_destination_connection_id)) => {
                let retry_without_tag = retry_without_integrity_tag_bytes(
                    first_byte,
                    version,
                    &destination_connection_id,
                    &source_connection_id,
                    &token,
                )?;
                quic_retry_integrity_tag(
                    version,
                    original_destination_connection_id,
                    retry_without_tag,
                )?
            }
            (None, None) => {
                return Err(CrafterError::invalid_field_value(
                    "quic.retry.integrity_tag",
                    "Retry Integrity Tag must be set",
                ))
            }
        };

        QuicRetryPacket::from_parts(
            first_byte,
            version,
            destination_connection_id,
            source_connection_id,
            token,
            integrity_tag,
        )
    }
}

fn retry_without_integrity_tag_bytes(
    first_byte: u8,
    version: u32,
    destination_connection_id: &QuicConnectionId,
    source_connection_id: &QuicConnectionId,
    token: &[u8],
) -> Result<Vec<u8>> {
    validate_one_byte_connection_id_len(destination_connection_id.len())?;
    validate_one_byte_connection_id_len(source_connection_id.len())?;

    let mut raw = Vec::with_capacity(
        1 + 4 + 1 + destination_connection_id.len() + 1 + source_connection_id.len() + token.len(),
    );
    raw.push(first_byte);
    raw.extend_from_slice(&version.to_be_bytes());
    raw.push(destination_connection_id.len() as u8);
    raw.extend_from_slice(destination_connection_id.as_bytes());
    raw.push(source_connection_id.len() as u8);
    raw.extend_from_slice(source_connection_id.as_bytes());
    raw.extend_from_slice(token);
    Ok(raw)
}

fn default_retry_first_byte(version: u32) -> Result<u8> {
    match version {
        QUIC_VERSION_1 => Ok(0xf0),
        QUIC_VERSION_2 => Ok(0xc0),
        _ => Err(CrafterError::invalid_field_value(
            "quic.retry.version",
            "cannot infer Retry packet type bits for unsupported QUIC version",
        )),
    }
}

/// Decoded QUIC Version Negotiation packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicVersionNegotiationPacket {
    first_byte: u8,
    destination_connection_id: QuicConnectionId,
    source_connection_id: QuicConnectionId,
    supported_versions: Vec<u32>,
    raw: Vec<u8>,
}

impl QuicVersionNegotiationPacket {
    /// Start building a Version Negotiation packet.
    ///
    /// This only emits packet bytes. Endpoint version selection, downgrade
    /// handling, and echo-policy decisions are intentionally out of scope.
    pub fn builder() -> QuicVersionNegotiationBuilder {
        QuicVersionNegotiationBuilder::new()
    }

    /// Build a Version Negotiation packet from connection IDs and versions.
    pub fn new(
        destination_connection_id: QuicConnectionId,
        source_connection_id: QuicConnectionId,
        supported_versions: impl IntoIterator<Item = u32>,
    ) -> Result<Self> {
        Self::builder()
            .destination_connection_id(destination_connection_id)
            .source_connection_id(source_connection_id)
            .supported_versions(supported_versions)
            .build()
    }

    /// Decode a byte-complete Version Negotiation packet.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let classification = classify_quic_header(bytes)?;
        let QuicHeaderClassification::LongHeader {
            first_byte,
            destination_connection_id,
            source_connection_id,
            invariant_len,
            packet_kind: QuicLongPacketKind::VersionNegotiation,
            ..
        } = classification
        else {
            return Err(CrafterError::invalid_field_value(
                "quic.version_negotiation",
                "packet is not a Version Negotiation packet",
            ));
        };

        let version_bytes = &bytes[invariant_len..];
        if version_bytes.is_empty() || version_bytes.len() % 4 != 0 {
            let missing = if version_bytes.is_empty() {
                4
            } else {
                4 - (version_bytes.len() % 4)
            };
            return Err(CrafterError::buffer_too_short(
                "quic.version_negotiation.supported_versions",
                bytes.len() + missing,
                bytes.len(),
            ));
        }

        let supported_versions = version_bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();

        Ok(Self {
            first_byte,
            destination_connection_id,
            source_connection_id,
            supported_versions,
            raw: bytes.to_vec(),
        })
    }

    fn from_parts(
        first_byte: u8,
        destination_connection_id: QuicConnectionId,
        source_connection_id: QuicConnectionId,
        supported_versions: Vec<u32>,
    ) -> Result<Self> {
        if supported_versions.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "quic.version_negotiation.supported_versions",
                "Version Negotiation packets require at least one supported version",
            ));
        }
        validate_one_byte_connection_id_len(destination_connection_id.len())?;
        validate_one_byte_connection_id_len(source_connection_id.len())?;

        let mut raw = Vec::with_capacity(
            1 + 4
                + 1
                + destination_connection_id.len()
                + 1
                + source_connection_id.len()
                + supported_versions.len() * 4,
        );
        raw.push(first_byte);
        raw.extend_from_slice(&0u32.to_be_bytes());
        raw.push(destination_connection_id.len() as u8);
        raw.extend_from_slice(destination_connection_id.as_bytes());
        raw.push(source_connection_id.len() as u8);
        raw.extend_from_slice(source_connection_id.as_bytes());
        for version in &supported_versions {
            raw.extend_from_slice(&version.to_be_bytes());
        }

        Ok(Self {
            first_byte,
            destination_connection_id,
            source_connection_id,
            supported_versions,
            raw,
        })
    }

    /// Raw first byte, including the unused low seven bits.
    pub const fn first_byte(&self) -> u8 {
        self.first_byte
    }

    /// Borrow the Destination Connection ID.
    pub fn destination_connection_id(&self) -> &QuicConnectionId {
        &self.destination_connection_id
    }

    /// Borrow the Source Connection ID.
    pub fn source_connection_id(&self) -> &QuicConnectionId {
        &self.source_connection_id
    }

    /// Borrow the offered supported-version list.
    pub fn supported_versions(&self) -> &[u32] {
        &self.supported_versions
    }

    /// Borrow the preserved packet bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Packet length in bytes.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Return true when the packet has no bytes.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// One-line Version Negotiation summary.
    pub fn summary(&self) -> String {
        format!(
            "VersionNegotiation(raw_len={}, dcid={}, scid={}, supported_versions={})",
            self.raw.len(),
            self.destination_connection_id.summary(),
            self.source_connection_id.summary(),
            version_list_summary(&self.supported_versions)
        )
    }

    /// Stable field/value pairs for packet inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("classification", "version_negotiation".to_string()),
            ("first_byte", format!("0x{:02x}", self.first_byte)),
            (
                "destination_connection_id_len",
                self.destination_connection_id.len().to_string(),
            ),
            (
                "destination_connection_id",
                self.destination_connection_id.to_spaced_hex(),
            ),
            (
                "source_connection_id_len",
                self.source_connection_id.len().to_string(),
            ),
            (
                "source_connection_id",
                self.source_connection_id.to_spaced_hex(),
            ),
            (
                "supported_version_count",
                self.supported_versions.len().to_string(),
            ),
            (
                "supported_versions",
                version_list_summary(&self.supported_versions),
            ),
            (
                "supported_version_statuses",
                self.supported_versions
                    .iter()
                    .map(|version| format!("0x{version:08x}:{:?}", quic_version_status(*version)))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("raw_len", self.raw.len().to_string()),
            ("raw_bytes", hex_bytes(&self.raw)),
        ]
    }
}

/// Builder for QUIC Version Negotiation packet emission.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicVersionNegotiationBuilder {
    first_byte: Field<u8>,
    destination_connection_id: Field<QuicConnectionId>,
    source_connection_id: Field<QuicConnectionId>,
    supported_versions: Vec<u32>,
}

impl QuicVersionNegotiationBuilder {
    /// Create an empty Version Negotiation builder.
    pub fn new() -> Self {
        Self {
            first_byte: Field::unset(),
            destination_connection_id: Field::unset(),
            source_connection_id: Field::unset(),
            supported_versions: Vec::new(),
        }
    }

    /// Pin byte 0 explicitly, including intentionally malformed values.
    pub fn first_byte(mut self, first_byte: u8) -> Self {
        self.first_byte.set_user(first_byte);
        self
    }

    /// Set the Destination Connection ID bytes.
    pub fn destination_connection_id(mut self, connection_id: QuicConnectionId) -> Self {
        self.destination_connection_id.set_user(connection_id);
        self
    }

    /// Set the Source Connection ID bytes.
    pub fn source_connection_id(mut self, connection_id: QuicConnectionId) -> Self {
        self.source_connection_id.set_user(connection_id);
        self
    }

    /// Append one supported-version value.
    pub fn supported_version(mut self, version: u32) -> Self {
        self.supported_versions.push(version);
        self
    }

    /// Replace supported-version values with the supplied list.
    pub fn supported_versions(mut self, versions: impl IntoIterator<Item = u32>) -> Self {
        self.supported_versions = versions.into_iter().collect();
        self
    }

    /// Build the packet bytes.
    pub fn build(self) -> Result<QuicVersionNegotiationPacket> {
        let first_byte = self.first_byte.into_value().unwrap_or(0xc0);
        let destination_connection_id = self
            .destination_connection_id
            .into_value()
            .unwrap_or_default();
        let source_connection_id = self.source_connection_id.into_value().unwrap_or_default();
        QuicVersionNegotiationPacket::from_parts(
            first_byte,
            destination_connection_id,
            source_connection_id,
            self.supported_versions,
        )
    }
}

fn validate_one_byte_connection_id_len(len: usize) -> Result<()> {
    if len <= u8::MAX as usize {
        Ok(())
    } else {
        Err(CrafterError::invalid_field_value(
            "quic.connection_id.length",
            "QUIC connection ID length field must fit in one byte",
        ))
    }
}

fn version_list_summary(versions: &[u32]) -> String {
    versions
        .iter()
        .map(|version| format!("0x{version:08x}({})", quic_version_label(*version)))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use crate::packet::Packet;
    use crate::{Ipv4, Udp};
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn quic_datagram_layer_preserves_raw_unsupported_bytes() {
        let payload = [0xc3, 0x00, 0x00, 0x00, 0x01, 0xaa, 0xbb];
        let quic = Quic::from_bytes(payload);

        assert_eq!(quic.payload_bytes(), payload);
        assert_eq!(quic.encoded_len(), payload.len());
        assert_eq!(quic.len(), payload.len());
        assert!(quic.packets().is_empty());
        assert_eq!(
            quic.summary(),
            "Quic(raw_len=7, packets=0, header=malformed error=quic.header.long.dcid requires 176 bytes, but only 7 bytes are available, frames=0, transport_parameters=0)"
        );
    }

    #[test]
    fn quic_datagram_layer_compiles_raw_payload_through_packet_stack() -> crate::Result<()> {
        let payload = [0xc3, 0x00, 0x00, 0x00, 0x01];
        let compiled = Packet::from_layer(Quic::from_bytes(payload)).compile()?;

        assert_eq!(compiled.as_bytes(), payload);
        Ok(())
    }

    #[test]
    fn quic_datagram_layer_compiles_ordered_raw_packets() -> crate::Result<()> {
        let datagram = Quic::new()
            .packet_bytes([0xc3, 0x00, 0x00])
            .packet(QuicPacket::from_bytes([0xd3, 0x01]));
        let compiled = Packet::from_layer(datagram.clone()).compile()?;

        assert_eq!(datagram.len(), 5);
        assert_eq!(datagram.packets().len(), 2);
        assert_eq!(compiled.as_bytes(), [0xc3, 0x00, 0x00, 0xd3, 0x01]);
        Ok(())
    }

    #[test]
    fn quic_datagram_layer_payload_replaces_packet_entries() -> crate::Result<()> {
        let datagram = Quic::new()
            .packet_bytes([0xc3, 0x00, 0x00])
            .payload([0xaa, 0xbb]);
        let compiled = Packet::from_layer(datagram.clone()).compile()?;

        assert!(datagram.packets().is_empty());
        assert_eq!(datagram.payload_bytes(), [0xaa, 0xbb]);
        assert_eq!(compiled.as_bytes(), [0xaa, 0xbb]);
        Ok(())
    }

    #[test]
    fn quic_coalesced_compile_from_packets_auto_fills_long_lengths() -> crate::Result<()> {
        let initial = QuicLongHeaderPacket::initial_builder()
            .destination_connection_id(QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]))
            .source_connection_id(QuicConnectionId::from_bytes([0xaa]))
            .packet_number(QuicPacketNumber::new(1))
            .payload([0xbe])
            .build()?;
        let handshake = QuicLongHeaderPacket::handshake_builder()
            .destination_connection_id(QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]))
            .source_connection_id(QuicConnectionId::from_bytes([0xaa]))
            .packet_number(QuicPacketNumber::new(2))
            .payload([0xef])
            .build()?;
        let datagram = Quic::from_packets([
            QuicPacket::from_long_header(initial.clone()),
            QuicPacket::from_long_header(handshake.clone()),
        ]);

        assert_eq!(initial.length().value(), 2);
        assert_eq!(handshake.length().value(), 2);
        assert_eq!(datagram.packets().len(), 2);
        assert_eq!(datagram.len(), initial.len() + handshake.len());

        let mut expected = initial.as_bytes().to_vec();
        expected.extend_from_slice(handshake.as_bytes());
        assert_eq!(
            Packet::from_layer(datagram).compile()?.as_bytes(),
            expected.as_slice()
        );
        Ok(())
    }

    #[test]
    fn quic_coalesced_compile_extend_packets_preserves_explicit_lengths() -> crate::Result<()> {
        let initial = QuicLongHeaderPacket::initial_builder()
            .length(QuicVarInt::new(1).unwrap())
            .length_encoded_len(2)
            .packet_number(QuicPacketNumber::new(0x12).with_encoded_len(4))
            .payload([0xcc])
            .build()?;
        let datagram = Quic::from_bytes([0xff])
            .extend_packets([QuicPacket::from_long_header(initial.clone())]);

        assert_eq!(datagram.payload_state(), FieldState::Unset);
        assert_eq!(initial.length().value(), 1);
        assert_eq!(initial.length_encoded_len(), 2);
        assert_eq!(
            Packet::from_layer(datagram).compile()?.as_bytes(),
            initial.as_bytes()
        );
        Ok(())
    }

    #[test]
    fn quic_coalesced_compile_packet_bytes_many_appends_raw_entries() -> crate::Result<()> {
        let datagram = Quic::new().packet_bytes_many([vec![0xc0, 0x00], vec![0xd0, 0x01, 0x02]]);

        assert_eq!(datagram.packets().len(), 2);
        assert_eq!(
            Packet::from_layer(datagram).compile()?.as_bytes(),
            [0xc0, 0x00, 0xd0, 0x01, 0x02]
        );
        Ok(())
    }

    #[test]
    fn quic_coalesced_compile_udp_length_covers_whole_datagram() -> crate::Result<()> {
        let initial = QuicLongHeaderPacket::initial_builder()
            .packet_number(QuicPacketNumber::new(1))
            .payload([0xbe])
            .build()?;
        let handshake = QuicLongHeaderPacket::handshake_builder()
            .packet_number(QuicPacketNumber::new(2))
            .payload([0xef])
            .build()?;
        let datagram = Quic::new()
            .packet(QuicPacket::from_long_header(initial.clone()))
            .packet(QuicPacket::from_long_header(handshake.clone()));
        let datagram_len = datagram.len();
        let compiled = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Udp::new().sport(4433).dport(4433)
            / datagram)
            .compile()?;

        assert_eq!(
            u16::from_be_bytes([compiled.as_bytes()[24], compiled.as_bytes()[25]]),
            (8 + datagram_len) as u16
        );
        assert!(compiled.as_bytes().ends_with(handshake.as_bytes()));
        Ok(())
    }

    #[test]
    fn quic_summary_inspection_datagram_exposes_header_and_counts() {
        let payload = [
            0xc3, 0x00, 0x00, 0x00, 0x01, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0x00,
        ];
        let packet = Packet::from_layer(Quic::from_bytes(payload));

        assert_eq!(
            packet.summary(),
            "Quic(raw_len=13, packets=0, header=long kind=Initial version=0x00000001(QUIC v1) dcid=len=4 value=8394c8f0 scid=len=1 value=aa protected_or_raw_len=1, frames=0, transport_parameters=0)"
        );
        let show = packet.show();
        assert!(show.contains("classification: long_header"), "{show}");
        assert!(show.contains("version: 0x00000001 (QUIC v1)"), "{show}");
        assert!(
            show.contains("destination_connection_id: 83 94 c8 f0"),
            "{show}"
        );
        assert!(show.contains("frame_count: 0"), "{show}");
        assert!(show.contains("transport_parameter_count: 0"), "{show}");
    }

    #[test]
    fn quic_summary_inspection_packet_entry_summary_is_stable() {
        let quic_packet = QuicPacket::from_bytes([0x40, 0x83, 0x94, 0xc8, 0xf0, 0x12, 0x34]);

        assert_eq!(
            quic_packet.summary(),
            "raw_len=7 header=short-ambiguous first_byte=0x40 fixed_bit=true"
        );
        let fields = quic_packet.inspection_fields();
        assert!(fields.contains(&("classification", "short_header_ambiguous".to_string())));
        assert!(fields.contains(&("raw_len", "7".to_string())));
    }

    #[test]
    fn quic_short_header_decode_parses_fields_with_supplied_dcid_length() {
        let bytes = [0x5d, 0x83, 0x94, 0xc8, 0xf0, 0x12, 0x34, 0xbe, 0xef];

        let short = QuicShortHeaderPacket::decode(bytes, 4).unwrap();

        assert_eq!(short.first_byte(), 0x5d);
        assert!(short.fixed_bit());
        assert!(!short.spin_bit());
        assert_eq!(short.reserved_bits(), 3);
        assert!(short.key_phase());
        assert_eq!(
            short.destination_connection_id().as_bytes(),
            [0x83, 0x94, 0xc8, 0xf0]
        );
        assert_eq!(short.packet_number().value(), 0x1234);
        assert_eq!(short.packet_number_bytes(), [0x12, 0x34]);
        assert_eq!(short.protected_payload(), [0xbe, 0xef]);
        assert_eq!(short.as_bytes(), bytes);
        assert_eq!(
            short.summary(),
            "ShortHeader(raw_len=9, fixed_bit=true, spin_bit=false, reserved_bits=3, key_phase=true, dcid=len=4 value=8394c8f0, packet_number=value=4660 encoded_len=2, protected_payload_len=2)"
        );

        let packet = QuicPacket::decode_short_header(bytes, 4).unwrap();
        assert!(packet.is_short_header());
        assert_eq!(
            packet
                .short_header()
                .unwrap()
                .destination_connection_id()
                .as_bytes(),
            [0x83, 0x94, 0xc8, 0xf0]
        );
    }

    #[test]
    fn quic_short_header_decode_preserves_cleared_fixed_bit_when_explicit() {
        let bytes = [0x26, 0x01, 0x02, 0x03, 0xc0, 0xff, 0xee];

        let short = QuicShortHeaderPacket::decode(bytes, 0).unwrap();

        assert_eq!(short.first_byte(), 0x26);
        assert!(!short.fixed_bit());
        assert!(short.spin_bit());
        assert_eq!(short.reserved_bits(), 0);
        assert!(short.key_phase());
        assert_eq!(short.packet_number().value(), 0x01_02_03);
        assert_eq!(short.protected_payload(), [0xc0, 0xff, 0xee]);
    }

    #[test]
    fn quic_short_header_decode_default_packet_decode_preserves_ambiguous_raw() {
        let bytes = [0x40, 0x83, 0x94, 0xc8, 0xf0, 0x12, 0x34];

        let packet = QuicPacket::decode(bytes).unwrap();

        assert!(!packet.is_short_header());
        assert_eq!(packet.as_bytes(), bytes);
        assert_eq!(
            packet.summary(),
            "raw_len=7 header=short-ambiguous first_byte=0x40 fixed_bit=true"
        );
    }

    #[test]
    fn quic_short_header_decode_reports_structured_errors() {
        assert_eq!(
            QuicShortHeaderPacket::decode([], 0).unwrap_err(),
            CrafterError::buffer_too_short("quic.short_header", 1, 0)
        );
        assert_eq!(
            QuicShortHeaderPacket::decode([0xc0, 0x00, 0x00, 0x00, 0x01], 0).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.short_header",
                "packet is not a short-header packet",
            )
        );
        assert_eq!(
            QuicShortHeaderPacket::decode([0x40, 0xaa], 2).unwrap_err(),
            CrafterError::buffer_too_short("quic.short_header.dcid", 3, 2)
        );
        assert_eq!(
            QuicShortHeaderPacket::decode([0x43, 0xaa, 0x01, 0x02], 1).unwrap_err(),
            CrafterError::buffer_too_short("quic.short_header.packet_number", 6, 4)
        );
    }

    #[test]
    fn quic_short_header_build_auto_fills_fixed_bit_and_roundtrips() -> crate::Result<()> {
        let short = QuicShortHeaderPacket::builder()
            .destination_connection_id(QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]))
            .packet_number(QuicPacketNumber::new(0x1234).with_encoded_len(2))
            .payload([0xbe, 0xef])
            .build()?;

        assert_eq!(
            short.as_bytes(),
            [0x41, 0x83, 0x94, 0xc8, 0xf0, 0x12, 0x34, 0xbe, 0xef]
        );
        assert_eq!(short.first_byte(), 0x41);
        assert!(short.fixed_bit());
        assert_eq!(
            short.destination_connection_id().as_bytes(),
            [0x83, 0x94, 0xc8, 0xf0]
        );
        assert_eq!(short.packet_number().value(), 0x1234);
        assert_eq!(short.packet_number_bytes(), [0x12, 0x34]);
        assert_eq!(short.protected_payload(), [0xbe, 0xef]);

        let decoded = QuicShortHeaderPacket::decode(short.as_bytes(), 4)?;
        assert_eq!(decoded.packet_number().value(), 0x1234);
        assert_eq!(decoded.protected_payload(), [0xbe, 0xef]);

        let compiled = Packet::from_layer(Quic::new().packet(QuicPacket::from_short_header(short)))
            .compile()?;
        assert_eq!(
            compiled.as_bytes(),
            [0x41, 0x83, 0x94, 0xc8, 0xf0, 0x12, 0x34, 0xbe, 0xef]
        );
        Ok(())
    }

    #[test]
    fn quic_short_header_build_preserves_selected_bits_and_frames() -> crate::Result<()> {
        let short = QuicShortHeaderPacket::builder()
            .fixed_bit(false)
            .spin_bit(true)
            .reserved_bits(2)
            .key_phase(true)
            .packet_number(QuicPacketNumber::new(0x01_02_03).with_encoded_len(3))
            .frames([QuicFrame::from_bytes([0x00]), QuicFrame::from_bytes([0x01])])
            .build()?;

        assert_eq!(short.as_bytes(), [0x36, 0x01, 0x02, 0x03, 0x00, 0x01]);
        assert!(!short.fixed_bit());
        assert!(short.spin_bit());
        assert_eq!(short.reserved_bits(), 2);
        assert!(short.key_phase());
        assert_eq!(short.packet_number_bytes(), [0x01, 0x02, 0x03]);
        assert_eq!(short.protected_payload(), [0x00, 0x01]);

        let decoded = QuicShortHeaderPacket::decode(short.as_bytes(), 0)?;
        assert_eq!(decoded.first_byte(), 0x36);
        assert!(!decoded.fixed_bit());
        assert_eq!(decoded.packet_number().value(), 0x01_02_03);
        Ok(())
    }

    #[test]
    fn quic_short_header_build_preserves_explicit_malformed_first_byte() -> crate::Result<()> {
        let short = QuicShortHeaderPacket::builder()
            .first_byte(0x40)
            .destination_connection_id(QuicConnectionId::from_bytes([0xaa]))
            .packet_number(QuicPacketNumber::new(0x12).with_encoded_len(4))
            .payload([0xcc])
            .build()?;

        assert_eq!(short.as_bytes(), [0x40, 0xaa, 0x00, 0x00, 0x00, 0x12, 0xcc]);
        assert_eq!(short.first_byte(), 0x40);
        assert_eq!(short.packet_number().encoded_len_value(), Some(4));
        assert_eq!(short.packet_number_bytes(), [0x00, 0x00, 0x00, 0x12]);
        Ok(())
    }

    #[test]
    fn quic_short_header_build_reports_structured_errors() {
        assert_eq!(
            QuicShortHeaderPacket::builder()
                .reserved_bits(4)
                .build()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.short_header.reserved_bits",
                "QUIC short-header reserved bits must fit in 2 bits",
            )
        );
        assert_eq!(
            QuicShortHeaderPacket::builder()
                .packet_number(QuicPacketNumber::new(0x1_0000_0000))
                .build()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.packet_number",
                "QUIC packet number exceeds 32 encoded bits",
            )
        );
    }

    #[test]
    fn quic_long_header_common_decode_parses_v1_initial_fields() {
        let bytes = [
            0xc2, 0x00, 0x00, 0x00, 0x01, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0x02, 0xde,
            0xad, 0x05, 0x01, 0x02, 0x03, 0xbe, 0xef,
        ];

        let packet = QuicLongHeaderPacket::decode(bytes).unwrap();

        assert_eq!(packet.first_byte(), 0xc2);
        assert_eq!(packet.version(), QUIC_VERSION_1);
        assert_eq!(packet.packet_kind(), QuicLongPacketKind::Initial);
        assert_eq!(
            packet.destination_connection_id().as_bytes(),
            [0x83, 0x94, 0xc8, 0xf0]
        );
        assert_eq!(packet.source_connection_id().as_bytes(), [0xaa]);
        assert_eq!(packet.token_length().unwrap().value(), 2);
        assert_eq!(packet.token_length_encoded_len(), Some(1));
        assert_eq!(packet.token(), [0xde, 0xad]);
        assert_eq!(packet.length().value(), 5);
        assert_eq!(packet.length_encoded_len(), 1);
        assert_eq!(packet.packet_number().value(), 0x01_02_03);
        assert_eq!(packet.packet_number_bytes(), [0x01, 0x02, 0x03]);
        assert_eq!(packet.protected_payload(), [0xbe, 0xef]);
        assert_eq!(packet.as_bytes(), bytes);

        let quic_packet = QuicPacket::decode(bytes).unwrap();
        assert!(quic_packet.is_long_header());
        assert_eq!(
            quic_packet.long_header().unwrap().protected_payload(),
            [0xbe, 0xef]
        );
    }

    #[test]
    fn quic_long_header_common_decode_maps_v2_zero_rtt_fields() {
        let bytes = [0xe0, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x00, 0x02, 0x7f, 0xca];

        let packet = QuicLongHeaderPacket::decode(bytes).unwrap();

        assert_eq!(packet.version(), QUIC_VERSION_2);
        assert_eq!(packet.packet_kind(), QuicLongPacketKind::ZeroRtt);
        assert_eq!(packet.destination_connection_id().as_bytes(), []);
        assert_eq!(packet.source_connection_id().as_bytes(), []);
        assert_eq!(packet.length().value(), 2);
        assert_eq!(packet.packet_number().value(), 0x7f);
        assert_eq!(packet.protected_payload(), [0xca]);
    }

    #[test]
    fn quic_long_header_common_decode_preserves_coalesced_remainder_as_raw_packet() {
        let bytes = [
            0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x01, 0xaa, 0xbb, 0xcc,
        ];

        let packet = QuicLongHeaderPacket::decode(bytes).unwrap();
        assert_eq!(packet.as_bytes(), &bytes[..10]);

        let quic_packet = QuicPacket::decode(bytes).unwrap();
        assert!(!quic_packet.is_long_header());
        assert_eq!(quic_packet.as_bytes(), bytes);
    }

    #[test]
    fn quic_long_header_common_decode_reports_structured_length_and_packet_number_errors() {
        assert_eq!(
            QuicLongHeaderPacket::decode([0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("quic.long_header.length", 8, 7)
        );
        assert_eq!(
            QuicLongHeaderPacket::decode([0xe3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03])
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.long_header.length",
                "QUIC long-header length must cover the packet number",
            )
        );
        assert_eq!(
            QuicLongHeaderPacket::decode([0xe1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0xaa,])
                .unwrap_err(),
            CrafterError::buffer_too_short("quic.long_header.packet_number", 10, 9)
        );
        assert_eq!(
            QuicLongHeaderPacket::decode([
                0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0xaa, 0xbb,
            ])
            .unwrap_err(),
            CrafterError::buffer_too_short("quic.long_header.protected_payload", 12, 10)
        );
    }

    #[test]
    fn quic_initial_packet_decode_reports_structured_token_errors() {
        assert_eq!(
            QuicLongHeaderPacket::decode([0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("quic.initial.token_length", 8, 7)
        );
        assert_eq!(
            QuicLongHeaderPacket::decode([0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0xaa,])
                .unwrap_err(),
            CrafterError::buffer_too_short("quic.initial.token", 10, 9)
        );
    }

    #[test]
    fn quic_initial_packet_build_auto_fills_token_length_and_length() -> crate::Result<()> {
        let initial = QuicLongHeaderPacket::initial_builder()
            .destination_connection_id(QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]))
            .source_connection_id(QuicConnectionId::from_bytes([0xaa]))
            .token([0xde, 0xad])
            .packet_number(QuicPacketNumber::new(0x1234).with_encoded_len(2))
            .payload([0xbe, 0xef])
            .build()?;

        assert_eq!(
            initial.as_bytes(),
            [
                0xc1, 0x00, 0x00, 0x00, 0x01, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0x02, 0xde,
                0xad, 0x04, 0x12, 0x34, 0xbe, 0xef,
            ]
        );
        assert_eq!(initial.token_length().unwrap().value(), 2);
        assert_eq!(initial.length().value(), 4);
        assert_eq!(initial.packet_number().value(), 0x1234);

        let decoded = QuicLongHeaderPacket::decode(initial.as_bytes())?;
        assert_eq!(decoded.token(), [0xde, 0xad]);
        assert_eq!(decoded.length().value(), 4);
        assert_eq!(decoded.protected_payload(), [0xbe, 0xef]);

        let compiled =
            Packet::from_layer(Quic::new().packet(QuicPacket::from_long_header(initial)))
                .compile()?;
        assert_eq!(
            compiled.as_bytes(),
            [
                0xc1, 0x00, 0x00, 0x00, 0x01, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0x02, 0xde,
                0xad, 0x04, 0x12, 0x34, 0xbe, 0xef,
            ]
        );
        Ok(())
    }

    #[test]
    fn quic_initial_packet_build_accepts_raw_frame_payload_bytes() -> crate::Result<()> {
        let initial = QuicLongHeaderPacket::initial_builder()
            .frame(QuicFrame::from_bytes([0x00, 0x01]))
            .frame(QuicFrame::from_bytes([0x40, 0xaf]))
            .build()?;

        assert_eq!(initial.protected_payload(), [0x00, 0x01, 0x40, 0xaf]);
        assert_eq!(initial.length().value(), 5);
        assert_eq!(initial.packet_number_bytes(), [0x00]);
        Ok(())
    }

    #[test]
    fn quic_frame_sequence_encode_integrates_with_initial_and_handshake_builders(
    ) -> crate::Result<()> {
        let ping = QuicFrame::ping();
        let crypto = QuicFrame::crypto(QuicVarInt::from_u64_unchecked(0), [0xaa])?;

        let initial = QuicLongHeaderPacket::initial_builder()
            .packet_number(QuicPacketNumber::new(0x1234).with_encoded_len(2))
            .frames([ping.clone(), crypto.clone()])
            .build()?;
        assert_eq!(initial.protected_payload(), [0x01, 0x06, 0x00, 0x01, 0xaa]);
        assert_eq!(initial.length().value(), 7);

        let handshake = QuicLongHeaderPacket::handshake_builder()
            .packet_number(QuicPacketNumber::new(0x12))
            .frames([crypto, ping])
            .build()?;
        assert_eq!(
            handshake.protected_payload(),
            [0x06, 0x00, 0x01, 0xaa, 0x01]
        );
        assert_eq!(handshake.length().value(), 6);
        Ok(())
    }

    #[test]
    fn quic_frame_sequence_encode_preserves_explicit_raw_payload_alternative() -> crate::Result<()>
    {
        let initial = QuicLongHeaderPacket::initial_builder()
            .packet_number(QuicPacketNumber::new(0x12))
            .protected_payload([0xbe, 0xef])
            .build()?;

        assert_eq!(initial.protected_payload(), [0xbe, 0xef]);
        assert_eq!(initial.length().value(), 3);
        Ok(())
    }

    #[test]
    fn quic_initial_packet_build_uses_v2_initial_type_bits() -> crate::Result<()> {
        let initial = QuicLongHeaderPacket::initial_builder()
            .version(QUIC_VERSION_2)
            .packet_number(QuicPacketNumber::new(1))
            .build()?;

        assert_eq!(initial.first_byte(), 0xd0);
        assert_eq!(initial.packet_kind(), QuicLongPacketKind::Initial);
        assert_eq!(initial.as_bytes()[1..5], QUIC_VERSION_2.to_be_bytes());
        Ok(())
    }

    #[test]
    fn quic_initial_packet_build_preserves_explicit_malformed_lengths() -> crate::Result<()> {
        let initial = QuicLongHeaderPacket::initial_builder()
            .token([0xaa, 0xbb])
            .token_length(QuicVarInt::new(1).unwrap())
            .token_length_encoded_len(2)
            .length(QuicVarInt::new(1).unwrap())
            .length_encoded_len(2)
            .packet_number(QuicPacketNumber::new(0x12).with_encoded_len(4))
            .payload([0xcc])
            .build()?;

        assert_eq!(initial.first_byte(), 0xc3);
        assert_eq!(
            initial.as_bytes(),
            [
                0xc3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0xaa, 0xbb, 0x40, 0x01, 0x00,
                0x00, 0x00, 0x12, 0xcc,
            ]
        );
        assert_eq!(initial.token_length().unwrap().value(), 1);
        assert_eq!(initial.token_length_encoded_len(), Some(2));
        assert_eq!(initial.length().value(), 1);
        assert_eq!(initial.length_encoded_len(), 2);
        assert_eq!(initial.packet_number_bytes(), [0x00, 0x00, 0x00, 0x12]);
        Ok(())
    }

    #[test]
    fn quic_initial_packet_build_rejects_unsupported_version_without_first_byte() {
        assert_eq!(
            QuicLongHeaderPacket::initial_builder()
                .version(0xface_feed)
                .build()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.initial.version",
                "cannot infer Initial packet type bits for unsupported QUIC version",
            )
        );

        let initial = QuicLongHeaderPacket::initial_builder()
            .version(0xface_feed)
            .first_byte(0xc0)
            .build()
            .unwrap();
        assert_eq!(initial.version(), 0xface_feed);
        assert_eq!(initial.first_byte(), 0xc0);
    }

    #[test]
    fn quic_handshake_packet_build_auto_fills_length_and_roundtrips() -> crate::Result<()> {
        let handshake = QuicLongHeaderPacket::handshake_builder()
            .destination_connection_id(QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]))
            .source_connection_id(QuicConnectionId::from_bytes([0xaa]))
            .packet_number(QuicPacketNumber::new(0x1234).with_encoded_len(2))
            .payload([0xbe, 0xef])
            .build()?;

        assert_eq!(
            handshake.as_bytes(),
            [
                0xe1, 0x00, 0x00, 0x00, 0x01, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0x04, 0x12,
                0x34, 0xbe, 0xef,
            ]
        );
        assert_eq!(handshake.packet_kind(), QuicLongPacketKind::Handshake);
        assert_eq!(handshake.token(), []);
        assert_eq!(handshake.token_length(), None);
        assert_eq!(handshake.length().value(), 4);

        let decoded = QuicLongHeaderPacket::decode(handshake.as_bytes())?;
        assert_eq!(decoded.packet_kind(), QuicLongPacketKind::Handshake);
        assert_eq!(decoded.packet_number().value(), 0x1234);
        assert_eq!(decoded.protected_payload(), [0xbe, 0xef]);

        let quic_packet = QuicPacket::decode(handshake.as_bytes())?;
        assert!(quic_packet.is_long_header());
        assert_eq!(
            quic_packet.long_header().unwrap().packet_kind(),
            QuicLongPacketKind::Handshake
        );
        Ok(())
    }

    #[test]
    fn quic_handshake_packet_build_accepts_raw_frame_payload_bytes() -> crate::Result<()> {
        let handshake = QuicLongHeaderPacket::handshake_builder()
            .frames([
                QuicFrame::from_bytes([0x06, 0x00, 0x01]),
                QuicFrame::from_bytes([0x01]),
            ])
            .build()?;

        assert_eq!(handshake.first_byte(), 0xe0);
        assert_eq!(handshake.protected_payload(), [0x06, 0x00, 0x01, 0x01]);
        assert_eq!(handshake.length().value(), 5);
        assert_eq!(handshake.packet_number_bytes(), [0x00]);
        Ok(())
    }

    #[test]
    fn quic_handshake_packet_build_uses_v2_handshake_type_bits() -> crate::Result<()> {
        let handshake = QuicLongHeaderPacket::handshake_builder()
            .version(QUIC_VERSION_2)
            .packet_number(QuicPacketNumber::new(1))
            .build()?;

        assert_eq!(handshake.first_byte(), 0xf0);
        assert_eq!(handshake.packet_kind(), QuicLongPacketKind::Handshake);
        assert_eq!(handshake.as_bytes()[1..5], QUIC_VERSION_2.to_be_bytes());
        Ok(())
    }

    #[test]
    fn quic_handshake_packet_build_preserves_explicit_malformed_lengths() -> crate::Result<()> {
        let handshake = QuicLongHeaderPacket::handshake_builder()
            .length(QuicVarInt::new(1).unwrap())
            .length_encoded_len(2)
            .packet_number(QuicPacketNumber::new(0x12).with_encoded_len(4))
            .payload([0xcc])
            .build()?;

        assert_eq!(handshake.first_byte(), 0xe3);
        assert_eq!(
            handshake.as_bytes(),
            [0xe3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x12, 0xcc,]
        );
        assert_eq!(handshake.length().value(), 1);
        assert_eq!(handshake.length_encoded_len(), 2);
        assert_eq!(handshake.packet_number_bytes(), [0x00, 0x00, 0x00, 0x12]);
        Ok(())
    }

    #[test]
    fn quic_handshake_packet_build_rejects_unsupported_version_without_first_byte() {
        assert_eq!(
            QuicLongHeaderPacket::handshake_builder()
                .version(0xface_feed)
                .build()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.handshake.version",
                "cannot infer Handshake packet type bits for unsupported QUIC version",
            )
        );

        let handshake = QuicLongHeaderPacket::handshake_builder()
            .version(0xface_feed)
            .first_byte(0xe0)
            .build()
            .unwrap();
        assert_eq!(handshake.version(), 0xface_feed);
        assert_eq!(handshake.first_byte(), 0xe0);
    }

    #[test]
    fn quic_zero_rtt_packet_build_auto_fills_length_and_roundtrips() -> crate::Result<()> {
        let zero_rtt = QuicLongHeaderPacket::zero_rtt_builder()
            .destination_connection_id(QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]))
            .source_connection_id(QuicConnectionId::from_bytes([0xaa]))
            .packet_number(QuicPacketNumber::new(0x1234).with_encoded_len(2))
            .protected_payload([0xbe, 0xef])
            .build()?;

        assert_eq!(
            zero_rtt.as_bytes(),
            [
                0xd1, 0x00, 0x00, 0x00, 0x01, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0x04, 0x12,
                0x34, 0xbe, 0xef,
            ]
        );
        assert_eq!(zero_rtt.packet_kind(), QuicLongPacketKind::ZeroRtt);
        assert_eq!(zero_rtt.token(), []);
        assert_eq!(zero_rtt.length().value(), 4);

        let decoded = QuicLongHeaderPacket::decode(zero_rtt.as_bytes())?;
        assert_eq!(decoded.packet_kind(), QuicLongPacketKind::ZeroRtt);
        assert_eq!(decoded.packet_number().value(), 0x1234);
        assert_eq!(decoded.protected_payload(), [0xbe, 0xef]);
        Ok(())
    }

    #[test]
    fn quic_zero_rtt_packet_build_preserves_raw_encrypted_payload() -> crate::Result<()> {
        let zero_rtt = QuicLongHeaderPacket::zero_rtt_builder()
            .packet_number(QuicPacketNumber::new(0x05))
            .payload([0xc0, 0xff, 0xee, 0x00])
            .build()?;

        assert_eq!(zero_rtt.first_byte(), 0xd0);
        assert_eq!(zero_rtt.protected_payload(), [0xc0, 0xff, 0xee, 0x00]);
        assert_eq!(zero_rtt.length().value(), 5);
        assert_eq!(zero_rtt.packet_number_bytes(), [0x05]);
        Ok(())
    }

    #[test]
    fn quic_zero_rtt_packet_build_uses_v2_zero_rtt_type_bits() -> crate::Result<()> {
        let zero_rtt = QuicLongHeaderPacket::zero_rtt_builder()
            .version(QUIC_VERSION_2)
            .packet_number(QuicPacketNumber::new(1))
            .build()?;

        assert_eq!(zero_rtt.first_byte(), 0xe0);
        assert_eq!(zero_rtt.packet_kind(), QuicLongPacketKind::ZeroRtt);
        assert_eq!(zero_rtt.as_bytes()[1..5], QUIC_VERSION_2.to_be_bytes());
        Ok(())
    }

    #[test]
    fn quic_zero_rtt_packet_build_preserves_explicit_malformed_lengths() -> crate::Result<()> {
        let zero_rtt = QuicLongHeaderPacket::zero_rtt_builder()
            .length(QuicVarInt::new(1).unwrap())
            .length_encoded_len(2)
            .packet_number(QuicPacketNumber::new(0x12).with_encoded_len(4))
            .payload([0xcc])
            .build()?;

        assert_eq!(zero_rtt.first_byte(), 0xd3);
        assert_eq!(
            zero_rtt.as_bytes(),
            [0xd3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x12, 0xcc,]
        );
        assert_eq!(zero_rtt.length().value(), 1);
        assert_eq!(zero_rtt.length_encoded_len(), 2);
        assert_eq!(zero_rtt.packet_number_bytes(), [0x00, 0x00, 0x00, 0x12]);
        Ok(())
    }

    #[test]
    fn quic_zero_rtt_packet_build_rejects_unsupported_version_without_first_byte() {
        assert_eq!(
            QuicLongHeaderPacket::zero_rtt_builder()
                .version(0xface_feed)
                .build()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.zero_rtt.version",
                "cannot infer 0-RTT packet type bits for unsupported QUIC version",
            )
        );

        let zero_rtt = QuicLongHeaderPacket::zero_rtt_builder()
            .version(0xface_feed)
            .first_byte(0xd0)
            .build()
            .unwrap();
        assert_eq!(zero_rtt.version(), 0xface_feed);
        assert_eq!(zero_rtt.first_byte(), 0xd0);
    }

    #[test]
    fn quic_long_header_common_decode_rejects_packets_without_common_length_fields() {
        assert_eq!(
            QuicLongHeaderPacket::decode([
                0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xde, 0xad, 0xbe, 0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            ])
            .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.long_header",
                "packet is not an Initial, 0-RTT, or Handshake packet",
            )
        );
    }

    #[test]
    fn quic_version_negotiation_decode_preserves_versions_and_bytes() {
        let bytes = [
            0xc0, 0x00, 0x00, 0x00, 0x00, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0x00, 0x00,
            0x00, 0x01, 0x6b, 0x33, 0x43, 0xcf, 0xfa, 0xce, 0xfe, 0xed,
        ];

        let vn = QuicVersionNegotiationPacket::decode(bytes).unwrap();

        assert_eq!(vn.first_byte(), 0xc0);
        assert_eq!(
            vn.destination_connection_id().as_bytes(),
            [0x83, 0x94, 0xc8, 0xf0]
        );
        assert_eq!(vn.source_connection_id().as_bytes(), [0xaa]);
        assert_eq!(
            vn.supported_versions(),
            [0x0000_0001, 0x6b33_43cf, 0xface_feed]
        );
        assert_eq!(vn.as_bytes(), bytes);
        assert_eq!(
            vn.summary(),
            "VersionNegotiation(raw_len=24, dcid=len=4 value=8394c8f0, scid=len=1 value=aa, supported_versions=0x00000001(QUIC v1),0x6b3343cf(QUIC v2),0xfacefeed(unknown version 0xfacefeed))"
        );

        let packet = QuicPacket::decode(bytes).unwrap();
        assert!(packet.is_version_negotiation());
        assert_eq!(packet.as_bytes(), bytes);
        assert_eq!(
            packet.version_negotiation().unwrap().supported_versions(),
            vn.supported_versions()
        );
    }

    #[test]
    fn quic_version_negotiation_decode_inspection_fields_are_stable() {
        let packet = QuicPacket::decode([
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6b, 0x33, 0x43, 0xcf,
        ])
        .unwrap();
        let fields = packet.inspection_fields();

        assert!(fields.contains(&("classification", "version_negotiation".to_string())));
        assert!(fields.contains(&("first_byte", "0x80".to_string())));
        assert!(fields.contains(&("destination_connection_id_len", "0".to_string())));
        assert!(fields.contains(&("source_connection_id_len", "0".to_string())));
        assert!(fields.contains(&("supported_version_count", "1".to_string())));
        assert!(fields.contains(&("supported_versions", "0x6b3343cf(QUIC v2)".to_string(),)));
    }

    #[test]
    fn quic_version_negotiation_decode_reports_missing_or_truncated_versions() {
        assert_eq!(
            QuicVersionNegotiationPacket::decode([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,])
                .unwrap_err(),
            CrafterError::buffer_too_short("quic.version_negotiation.supported_versions", 11, 7,)
        );
        assert_eq!(
            QuicVersionNegotiationPacket::decode([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,])
                .unwrap_err(),
            CrafterError::buffer_too_short("quic.version_negotiation.supported_versions", 11, 8,)
        );
    }

    #[test]
    fn quic_version_negotiation_decode_rejects_non_vn_packets() {
        assert_eq!(
            QuicVersionNegotiationPacket::decode([0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,])
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.version_negotiation",
                "packet is not a Version Negotiation packet",
            )
        );
    }

    #[test]
    fn quic_version_negotiation_build_emits_default_header_and_roundtrips() {
        let vn = QuicVersionNegotiationPacket::builder()
            .destination_connection_id(QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]))
            .source_connection_id(QuicConnectionId::from_bytes([0xaa]))
            .supported_version(0x0000_0001)
            .supported_version(0x6b33_43cf)
            .build()
            .unwrap();

        assert_eq!(
            vn.as_bytes(),
            [
                0xc0, 0x00, 0x00, 0x00, 0x00, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0x00, 0x00,
                0x00, 0x01, 0x6b, 0x33, 0x43, 0xcf,
            ]
        );

        let decoded = QuicVersionNegotiationPacket::decode(vn.as_bytes()).unwrap();
        assert_eq!(decoded, vn);

        let compiled =
            Packet::from_layer(Quic::new().packet(QuicPacket::from_version_negotiation(vn)))
                .compile()
                .unwrap();
        assert_eq!(
            compiled.as_bytes(),
            [
                0xc0, 0x00, 0x00, 0x00, 0x00, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0x00, 0x00,
                0x00, 0x01, 0x6b, 0x33, 0x43, 0xcf,
            ]
        );
    }

    #[test]
    fn quic_version_negotiation_build_preserves_user_overrides() {
        let vn = QuicVersionNegotiationPacket::builder()
            .first_byte(0x81)
            .destination_connection_id(QuicConnectionId::from_bytes([0xde, 0xad]))
            .source_connection_id(QuicConnectionId::from_bytes([0xbe, 0xef]))
            .supported_versions([0xface_feed, 0x0a0a_0a0a])
            .build()
            .unwrap();

        assert_eq!(
            vn.as_bytes(),
            [
                0x81, 0x00, 0x00, 0x00, 0x00, 0x02, 0xde, 0xad, 0x02, 0xbe, 0xef, 0xfa, 0xce, 0xfe,
                0xed, 0x0a, 0x0a, 0x0a, 0x0a,
            ]
        );
        assert_eq!(vn.first_byte(), 0x81);
        assert_eq!(vn.supported_versions(), [0xface_feed, 0x0a0a_0a0a]);
    }

    #[test]
    fn quic_version_negotiation_build_rejects_missing_versions_and_oversized_cids() {
        assert_eq!(
            QuicVersionNegotiationPacket::builder().build().unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.version_negotiation.supported_versions",
                "Version Negotiation packets require at least one supported version",
            )
        );

        assert_eq!(
            QuicVersionNegotiationPacket::builder()
                .destination_connection_id(QuicConnectionId::from_bytes([0xaa; 256]))
                .supported_version(0x0000_0001)
                .build()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.connection_id.length",
                "QUIC connection ID length field must fit in one byte",
            )
        );
    }

    #[test]
    fn quic_retry_decode_preserves_v1_token_tag_and_bytes() {
        let bytes = [
            0xf0, 0x00, 0x00, 0x00, 0x01, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0xde, 0xad,
            0xbe, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f,
        ];

        let retry = QuicRetryPacket::decode(bytes).unwrap();

        assert_eq!(retry.first_byte(), 0xf0);
        assert_eq!(retry.version(), 0x0000_0001);
        assert_eq!(
            retry.destination_connection_id().as_bytes(),
            [0x83, 0x94, 0xc8, 0xf0]
        );
        assert_eq!(retry.source_connection_id().as_bytes(), [0xaa]);
        assert_eq!(retry.token(), [0xde, 0xad, 0xbe]);
        assert_eq!(
            retry.integrity_tag(),
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f
            ]
        );
        assert_eq!(retry.as_bytes(), bytes);

        let packet = QuicPacket::decode(bytes).unwrap();
        assert!(packet.is_retry());
        assert_eq!(packet.retry().unwrap(), &retry);
        assert_eq!(
            retry.summary(),
            "Retry(raw_len=31, version=0x00000001(QUIC v1), dcid=len=4 value=8394c8f0, scid=len=1 value=aa, token_len=3, tag=00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f)"
        );
    }

    #[test]
    fn quic_retry_decode_maps_v2_retry_type_bits() {
        let bytes = [
            0xc0, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x00, 0x42, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        ];

        let retry = QuicRetryPacket::decode(bytes).unwrap();

        assert_eq!(retry.version(), 0x6b33_43cf);
        assert_eq!(retry.token(), [0x42]);
        assert_eq!(retry.integrity_tag(), &[0x55; QUIC_RETRY_INTEGRITY_TAG_LEN]);
        assert_eq!(retry.destination_connection_id().len(), 0);
        assert_eq!(retry.source_connection_id().len(), 0);
    }

    #[test]
    fn quic_retry_integrity_tag_verifies_rfc9001_and_rfc9369_vectors() {
        const ODCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let v1_retry =
            parse_hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
        let v1 = QuicRetryPacket::decode(&v1_retry).unwrap();
        assert_eq!(v1.version(), QUIC_VERSION_1);
        assert_eq!(v1.token(), b"token");
        assert_eq!(
            v1.integrity_status(ODCID).unwrap(),
            QuicRetryIntegrityStatus::Valid
        );
        assert_eq!(
            quic_verify_retry_integrity_tag(ODCID, &v1).unwrap(),
            QuicRetryIntegrityStatus::Valid
        );
        assert_eq!(
            v1.computed_integrity_tag(ODCID).unwrap(),
            *v1.integrity_tag()
        );
        assert_eq!(
            quic_retry_integrity_tag(
                QUIC_VERSION_1,
                ODCID,
                &v1_retry[..v1_retry.len() - QUIC_RETRY_INTEGRITY_TAG_LEN],
            )
            .unwrap(),
            *v1.integrity_tag()
        );

        let pseudo = super::super::crypto::quic_retry_pseudo_packet(
            ODCID,
            &v1_retry[..v1_retry.len() - QUIC_RETRY_INTEGRITY_TAG_LEN],
        )
        .unwrap();
        assert_eq!(
            &pseudo[..1 + ODCID.len()],
            &[0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
        );

        let v2_retry =
            parse_hex("cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6");
        let v2 = QuicRetryPacket::decode(&v2_retry).unwrap();
        assert_eq!(v2.version(), QUIC_VERSION_2);
        assert_eq!(v2.token(), b"token");
        assert_eq!(
            v2.integrity_status(ODCID).unwrap(),
            QuicRetryIntegrityStatus::Valid
        );
        assert_eq!(
            v2.computed_integrity_tag(ODCID).unwrap(),
            *v2.integrity_tag()
        );

        let mut tampered = v1_retry;
        let last = tampered.last_mut().unwrap();
        *last ^= 0x01;
        let tampered_retry = QuicRetryPacket::decode(tampered).unwrap();
        assert_eq!(
            tampered_retry.integrity_status(ODCID).unwrap(),
            QuicRetryIntegrityStatus::Invalid
        );
    }

    #[test]
    fn quic_retry_integrity_tag_builder_computes_only_when_requested() {
        const ODCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let retry = QuicRetryPacket::builder()
            .version(QUIC_VERSION_1)
            .first_byte(0xff)
            .source_connection_id(QuicConnectionId::from_bytes([
                0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5,
            ]))
            .token(b"token")
            .compute_integrity_tag(ODCID)
            .build()
            .unwrap();

        assert_eq!(
            retry.as_bytes(),
            parse_hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba")
        );

        assert_eq!(
            QuicRetryPacket::builder()
                .version(QUIC_VERSION_1)
                .token([])
                .integrity_tag([0xaa; QUIC_RETRY_INTEGRITY_TAG_LEN])
                .compute_integrity_tag(ODCID)
                .build()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.retry.integrity_tag",
                "Retry Integrity Tag cannot be both explicit and computed"
            )
        );

        let unsupported = QuicRetryPacket::builder()
            .version(0xface_feed)
            .first_byte(0xff)
            .token([])
            .integrity_tag([0xaa; QUIC_RETRY_INTEGRITY_TAG_LEN])
            .build()
            .unwrap();
        assert_eq!(
            unsupported.integrity_status(ODCID).unwrap(),
            QuicRetryIntegrityStatus::UnsupportedVersion
        );
        assert_eq!(
            unsupported.computed_integrity_tag(ODCID).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.retry.version",
                "unsupported QUIC Retry integrity version"
            )
        );
    }

    #[test]
    fn quic_retry_decode_inspection_fields_are_stable() {
        let retry = QuicRetryPacket::decode([
            0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xaa, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ])
        .unwrap();
        let fields = retry.inspection_fields();

        assert!(fields.contains(&("classification", "retry".to_string())));
        assert!(fields.contains(&("version", "0x00000001 (QUIC v1)".to_string())));
        assert!(fields.contains(&("token_len", "1".to_string())));
        assert!(fields.contains(&("token", "aa".to_string())));
        assert!(fields.contains(&("retry_integrity_tag_len", "16".to_string())));
    }

    #[test]
    fn quic_retry_decode_reports_truncated_tag_and_non_retry() {
        assert_eq!(
            QuicRetryPacket::decode([
                0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            ])
            .unwrap_err(),
            CrafterError::buffer_too_short("quic.retry.integrity_tag", 23, 22)
        );
        assert_eq!(
            QuicRetryPacket::decode([0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,]).unwrap_err(),
            CrafterError::invalid_field_value("quic.retry", "packet is not a Retry packet")
        );
    }

    #[test]
    fn quic_retry_build_emits_v1_retry_and_roundtrips() {
        let retry = QuicRetryPacket::builder()
            .version(QUIC_VERSION_1)
            .destination_connection_id(QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]))
            .source_connection_id(QuicConnectionId::from_bytes([0xaa]))
            .token([0xde, 0xad, 0xbe])
            .integrity_tag([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ])
            .build()
            .unwrap();

        assert_eq!(
            retry.as_bytes(),
            [
                0xf0, 0x00, 0x00, 0x00, 0x01, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0xde, 0xad,
                0xbe, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f,
            ]
        );
        assert_eq!(QuicRetryPacket::decode(retry.as_bytes()).unwrap(), retry);

        let compiled = Packet::from_layer(Quic::new().packet(QuicPacket::from_retry(retry)))
            .compile()
            .unwrap();
        assert_eq!(
            compiled.as_bytes(),
            [
                0xf0, 0x00, 0x00, 0x00, 0x01, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0xde, 0xad,
                0xbe, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f,
            ]
        );
    }

    #[test]
    fn quic_retry_build_uses_v2_retry_type_bits() {
        let retry = QuicRetryPacket::new(
            QUIC_VERSION_2,
            QuicConnectionId::new(),
            QuicConnectionId::new(),
            [0x42],
            [0x55; QUIC_RETRY_INTEGRITY_TAG_LEN],
        )
        .unwrap();

        assert_eq!(retry.first_byte(), 0xc0);
        assert_eq!(
            retry.as_bytes(),
            [
                0xc0, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x00, 0x42, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            ]
        );
    }

    #[test]
    fn quic_retry_build_preserves_user_first_byte_and_empty_token() {
        let retry = QuicRetryPacket::builder()
            .version(0xface_feed)
            .first_byte(0xff)
            .token([])
            .integrity_tag([0xaa; QUIC_RETRY_INTEGRITY_TAG_LEN])
            .build()
            .unwrap();

        assert_eq!(retry.first_byte(), 0xff);
        assert_eq!(retry.version(), 0xface_feed);
        assert_eq!(retry.token(), []);
        assert_eq!(
            retry.as_bytes(),
            [
                0xff, 0xfa, 0xce, 0xfe, 0xed, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            ]
        );
    }

    #[test]
    fn quic_retry_build_requires_explicit_non_default_fields() {
        assert_eq!(
            QuicRetryPacket::builder().build().unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.retry.version",
                "Retry packet version must be set",
            )
        );
        assert_eq!(
            QuicRetryPacket::builder()
                .version(0xface_feed)
                .token([])
                .integrity_tag([0xaa; QUIC_RETRY_INTEGRITY_TAG_LEN])
                .build()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.retry.version",
                "cannot infer Retry packet type bits for unsupported QUIC version",
            )
        );
        assert_eq!(
            QuicRetryPacket::builder()
                .version(QUIC_VERSION_1)
                .integrity_tag([0xaa; QUIC_RETRY_INTEGRITY_TAG_LEN])
                .build()
                .unwrap_err(),
            CrafterError::invalid_field_value("quic.retry.token", "Retry token must be set")
        );
        assert_eq!(
            QuicRetryPacket::builder()
                .version(QUIC_VERSION_1)
                .token([0x42])
                .build()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.retry.integrity_tag",
                "Retry Integrity Tag must be set",
            )
        );
    }

    fn parse_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "test hex must have even length");
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("valid test hex"))
            .collect()
    }
}
