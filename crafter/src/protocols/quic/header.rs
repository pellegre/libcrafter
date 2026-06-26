//! QUIC header helpers.
//!
//! This module starts with version-independent classification only. It records
//! the invariant long-header fields, preserves the first byte, and avoids
//! guessing short-header connection ID length without caller context.

use crate::error::{CrafterError, Result};
use crate::field::{Field, FieldState};

use super::constants::{
    quic_version_label, quic_version_status, QUIC_VERSION_1, QUIC_VERSION_2,
    QUIC_VERSION_NEGOTIATION,
};
use super::packet_number::{header_bits_for_len, len_from_header_bits};
use super::QuicConnectionId;

/// Header Form bit mask in byte 0.
pub const QUIC_HEADER_FORM_MASK: u8 = 0x80;
/// QUIC fixed-bit mask in byte 0.
pub const QUIC_FIXED_BIT_MASK: u8 = 0x40;
/// QUIC v1/v2 long-header packet-type mask in byte 0.
pub const QUIC_LONG_PACKET_TYPE_MASK: u8 = 0x30;
/// QUIC v1/v2 long-header reserved-bits mask in byte 0.
pub const QUIC_LONG_RESERVED_BITS_MASK: u8 = 0x0c;
/// QUIC v1/v2 short-header spin-bit mask in byte 0.
pub const QUIC_SHORT_SPIN_BIT_MASK: u8 = 0x20;
/// QUIC v1/v2 short-header reserved-bits mask in byte 0.
pub const QUIC_SHORT_RESERVED_BITS_MASK: u8 = 0x18;
/// QUIC v1/v2 short-header key-phase mask in byte 0.
pub const QUIC_SHORT_KEY_PHASE_MASK: u8 = 0x04;
/// QUIC packet-number length mask in byte 0.
pub const QUIC_PACKET_NUMBER_LEN_MASK: u8 = 0x03;

/// RFC 9287 QUIC bit state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicFixedBitStatus {
    /// The QUIC bit is set to the ordinary fixed value.
    Set,
    /// The QUIC bit is cleared as an explicit greasing signal.
    GreasedCleared,
}

impl QuicFixedBitStatus {
    /// Build a status value from the decoded fixed-bit boolean.
    pub const fn from_fixed_bit(fixed_bit: bool) -> Self {
        if fixed_bit {
            Self::Set
        } else {
            Self::GreasedCleared
        }
    }

    /// Stable label for summaries and diagnostics.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::GreasedCleared => "greased_cleared",
        }
    }
}

/// Return the RFC 9287 QUIC bit status for byte 0.
pub const fn quic_fixed_bit_status(first_byte: u8) -> QuicFixedBitStatus {
    QuicFixedBitStatus::from_fixed_bit(first_byte & QUIC_FIXED_BIT_MASK != 0)
}

/// Return a stable RFC 9287 QUIC bit label from a fixed-bit boolean.
pub const fn quic_fixed_bit_label(fixed_bit: bool) -> &'static str {
    QuicFixedBitStatus::from_fixed_bit(fixed_bit).label()
}

/// Set the QUIC bit in byte 0.
pub const fn quic_set_fixed_bit(first_byte: u8) -> u8 {
    first_byte | QUIC_FIXED_BIT_MASK
}

/// Clear the QUIC bit in byte 0 for explicit RFC 9287 greasing.
pub const fn quic_clear_fixed_bit(first_byte: u8) -> u8 {
    first_byte & !QUIC_FIXED_BIT_MASK
}

/// QUIC invariant header form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicHeaderForm {
    /// Long header, carrying a 32-bit version and connection ID lengths.
    Long,
    /// Short header, whose destination connection ID length needs context.
    Short,
}

/// Version-specific long-header packet kind when the version is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicLongPacketKind {
    /// Version Negotiation packet, version field 0.
    VersionNegotiation,
    /// Initial packet.
    Initial,
    /// 0-RTT packet.
    ZeroRtt,
    /// Handshake packet.
    Handshake,
    /// Retry packet.
    Retry,
    /// Nonzero version with no source-backed packet-type mapping yet.
    UnknownVersion,
}

/// Pure version-independent QUIC header classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicHeaderClassification {
    /// Ordinary UDP payload that should not be consumed as QUIC.
    NonQuic,
    /// A short-header-looking payload. Default decode must preserve it raw until
    /// a caller supplies destination connection ID length or endpoint context.
    ShortHeaderAmbiguous {
        /// Raw first byte.
        first_byte: u8,
        /// QUIC/fixed bit value.
        fixed_bit: bool,
    },
    /// Parsed invariant long-header prefix.
    LongHeader {
        /// Raw first byte.
        first_byte: u8,
        /// QUIC/fixed bit value.
        fixed_bit: bool,
        /// 32-bit version field.
        version: u32,
        /// Destination connection ID bytes.
        destination_connection_id: QuicConnectionId,
        /// Source connection ID bytes.
        source_connection_id: QuicConnectionId,
        /// Length of the invariant long-header prefix.
        invariant_len: usize,
        /// Remaining bytes after the invariant long-header prefix.
        remaining_len: usize,
        /// Version-independent or version-specific packet kind.
        packet_kind: QuicLongPacketKind,
    },
}

/// Raw-preserving QUIC header placeholder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicHeader {
    first_byte: Field<u8>,
    raw: Vec<u8>,
}

impl QuicHeader {
    /// Create an empty placeholder header.
    pub fn new() -> Self {
        Self {
            first_byte: Field::unset(),
            raw: Vec::new(),
        }
    }

    /// Preserve raw header bytes recovered from the wire.
    pub fn from_decoded_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let first = *bytes
            .first()
            .ok_or_else(|| CrafterError::buffer_too_short("quic.header", 1, bytes.len()))?;
        Ok(Self {
            first_byte: Field::user(first),
            raw: bytes.to_vec(),
        })
    }

    /// Pin the first header byte explicitly.
    pub fn first_byte(mut self, first_byte: u8) -> Self {
        self.first_byte.set_user(first_byte);
        self
    }

    /// Set the invariant header form bit while preserving every other bit.
    pub fn header_form(mut self, form: QuicHeaderForm) -> Self {
        self.update_first_byte_mask(QUIC_HEADER_FORM_MASK, form.first_byte_bits());
        self
    }

    /// Set the QUIC fixed bit while preserving every other bit.
    pub fn fixed_bit(mut self, fixed: bool) -> Self {
        let value = if fixed { QUIC_FIXED_BIT_MASK } else { 0 };
        self.update_first_byte_mask(QUIC_FIXED_BIT_MASK, value);
        self
    }

    /// Clear the QUIC bit explicitly for RFC 9287 greasing.
    pub fn grease_quic_bit(self) -> Self {
        self.fixed_bit(false)
    }

    /// Set the v1/v2 long-header packet type bits while preserving other bits.
    pub fn long_packet_type_bits(mut self, bits: u8) -> Self {
        self.update_first_byte_mask(QUIC_LONG_PACKET_TYPE_MASK, (bits & 0x03) << 4);
        self
    }

    /// Set the v1/v2 long-header reserved bits while preserving other bits.
    pub fn long_reserved_bits(mut self, bits: u8) -> Self {
        self.update_first_byte_mask(QUIC_LONG_RESERVED_BITS_MASK, (bits & 0x03) << 2);
        self
    }

    /// Set the short-header spin bit while preserving every other bit.
    pub fn short_spin_bit(mut self, spin: bool) -> Self {
        let value = if spin { QUIC_SHORT_SPIN_BIT_MASK } else { 0 };
        self.update_first_byte_mask(QUIC_SHORT_SPIN_BIT_MASK, value);
        self
    }

    /// Set the v1/v2 short-header reserved bits while preserving other bits.
    pub fn short_reserved_bits(mut self, bits: u8) -> Self {
        self.update_first_byte_mask(QUIC_SHORT_RESERVED_BITS_MASK, (bits & 0x03) << 3);
        self
    }

    /// Set the short-header key-phase bit while preserving every other bit.
    pub fn short_key_phase(mut self, key_phase: bool) -> Self {
        let value = if key_phase {
            QUIC_SHORT_KEY_PHASE_MASK
        } else {
            0
        };
        self.update_first_byte_mask(QUIC_SHORT_KEY_PHASE_MASK, value);
        self
    }

    /// Set raw packet-number length bits while preserving every other bit.
    pub fn packet_number_len_bits(mut self, bits: u8) -> Self {
        self.update_first_byte_mask(QUIC_PACKET_NUMBER_LEN_MASK, bits & 0x03);
        self
    }

    /// Set packet-number length bits from a 1, 2, 3, or 4-byte length.
    pub fn packet_number_len(mut self, encoded_len: usize) -> Result<Self> {
        let bits = header_bits_for_len(encoded_len)?;
        self.update_first_byte_mask(QUIC_PACKET_NUMBER_LEN_MASK, bits);
        Ok(self)
    }

    /// Stored first-byte value, if one has been supplied or decoded.
    pub fn first_byte_value(&self) -> Option<u8> {
        self.first_byte.value().copied()
    }

    /// State of the first-byte field.
    pub fn first_byte_state(&self) -> FieldState {
        self.first_byte.state()
    }

    /// Invariant header form, if byte 0 is present.
    pub fn header_form_value(&self) -> Option<QuicHeaderForm> {
        self.first_byte_value().map(QuicHeaderForm::from_first_byte)
    }

    /// Return true when byte 0 identifies a long header.
    pub fn is_long_header(&self) -> Option<bool> {
        self.header_form_value()
            .map(|form| form == QuicHeaderForm::Long)
    }

    /// Return true when byte 0 identifies a short header.
    pub fn is_short_header(&self) -> Option<bool> {
        self.header_form_value()
            .map(|form| form == QuicHeaderForm::Short)
    }

    /// QUIC/fixed bit value, if byte 0 is present.
    pub fn fixed_bit_value(&self) -> Option<bool> {
        self.first_byte_value()
            .map(|first| first & QUIC_FIXED_BIT_MASK != 0)
    }

    /// RFC 9287 QUIC bit status, if byte 0 is present.
    pub fn quic_bit_status_value(&self) -> Option<QuicFixedBitStatus> {
        self.first_byte_value().map(quic_fixed_bit_status)
    }

    /// RFC 9287 QUIC bit label, if byte 0 is present.
    pub fn quic_bit_label_value(&self) -> Option<&'static str> {
        self.quic_bit_status_value().map(QuicFixedBitStatus::label)
    }

    /// Raw v1/v2 long-header packet type bits, if byte 0 is present.
    pub fn long_packet_type_bits_value(&self) -> Option<u8> {
        self.first_byte_value()
            .map(|first| (first & QUIC_LONG_PACKET_TYPE_MASK) >> 4)
    }

    /// Raw v1/v2 long-header reserved bits, if byte 0 is present.
    pub fn long_reserved_bits_value(&self) -> Option<u8> {
        self.first_byte_value()
            .map(|first| (first & QUIC_LONG_RESERVED_BITS_MASK) >> 2)
    }

    /// Short-header spin bit value, if byte 0 is present.
    pub fn short_spin_bit_value(&self) -> Option<bool> {
        self.first_byte_value()
            .map(|first| first & QUIC_SHORT_SPIN_BIT_MASK != 0)
    }

    /// Raw v1/v2 short-header reserved bits, if byte 0 is present.
    pub fn short_reserved_bits_value(&self) -> Option<u8> {
        self.first_byte_value()
            .map(|first| (first & QUIC_SHORT_RESERVED_BITS_MASK) >> 3)
    }

    /// Short-header key-phase bit value, if byte 0 is present.
    pub fn short_key_phase_value(&self) -> Option<bool> {
        self.first_byte_value()
            .map(|first| first & QUIC_SHORT_KEY_PHASE_MASK != 0)
    }

    /// Raw packet-number length bits, if byte 0 is present.
    pub fn packet_number_len_bits_value(&self) -> Option<u8> {
        self.first_byte_value()
            .map(|first| first & QUIC_PACKET_NUMBER_LEN_MASK)
    }

    /// Decoded packet-number length in bytes, if byte 0 is present.
    pub fn packet_number_len_value(&self) -> Option<usize> {
        self.packet_number_len_bits_value()
            .map(len_from_header_bits)
    }

    /// Return whether this header form carries a Destination Connection ID field.
    ///
    /// Long headers encode the field length after the version. Short headers
    /// carry the field immediately after byte 0, but the length is contextual.
    pub fn destination_connection_id_field_present(&self) -> Option<bool> {
        self.header_form_value().map(|_| true)
    }

    /// Borrow the preserved raw header bytes.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn update_first_byte_mask(&mut self, mask: u8, value: u8) {
        let current = self.first_byte_value().unwrap_or(0);
        self.first_byte.set_user((current & !mask) | (value & mask));
    }
}

impl QuicHeaderForm {
    /// Interpret the invariant header form bit from byte 0.
    pub const fn from_first_byte(first_byte: u8) -> Self {
        if first_byte & QUIC_HEADER_FORM_MASK != 0 {
            Self::Long
        } else {
            Self::Short
        }
    }

    const fn first_byte_bits(self) -> u8 {
        match self {
            Self::Long => QUIC_HEADER_FORM_MASK,
            Self::Short => 0,
        }
    }
}

impl QuicLongPacketKind {
    /// Stable packet-kind label for summaries and inspection fields.
    pub const fn label(self) -> &'static str {
        match self {
            Self::VersionNegotiation => "VersionNegotiation",
            Self::Initial => "Initial",
            Self::ZeroRtt => "0-RTT",
            Self::Handshake => "Handshake",
            Self::Retry => "Retry",
            Self::UnknownVersion => "UnknownVersion",
        }
    }
}

impl QuicHeaderClassification {
    /// One-line header classification suitable for packet summaries.
    pub fn summary(&self) -> String {
        match self {
            Self::NonQuic => "header=non-quic".to_string(),
            Self::ShortHeaderAmbiguous {
                first_byte,
                fixed_bit,
            } => format!(
                "header=short-ambiguous first_byte=0x{first_byte:02x} fixed_bit={fixed_bit} quic_bit={}",
                quic_fixed_bit_label(*fixed_bit)
            ),
            Self::LongHeader {
                first_byte,
                fixed_bit,
                version,
                destination_connection_id,
                source_connection_id,
                remaining_len,
                packet_kind,
                ..
            } => format!(
                "header=long kind={} first_byte=0x{first_byte:02x} fixed_bit={fixed_bit} quic_bit={} version=0x{version:08x}({}) dcid={} scid={} protected_or_raw_len={remaining_len}",
                packet_kind.label(),
                quic_fixed_bit_label(*fixed_bit),
                quic_version_label(*version),
                destination_connection_id.summary(),
                source_connection_id.summary(),
            ),
        }
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::NonQuic => vec![("classification", "non_quic".to_string())],
            Self::ShortHeaderAmbiguous {
                first_byte,
                fixed_bit,
            } => vec![
                ("classification", "short_header_ambiguous".to_string()),
                ("header_form", "short".to_string()),
                ("first_byte", format!("0x{first_byte:02x}")),
                ("fixed_bit", fixed_bit.to_string()),
                ("quic_bit", quic_fixed_bit_label(*fixed_bit).to_string()),
                ("destination_connection_id", "contextual".to_string()),
            ],
            Self::LongHeader {
                first_byte,
                fixed_bit,
                version,
                destination_connection_id,
                source_connection_id,
                invariant_len,
                remaining_len,
                packet_kind,
            } => vec![
                ("classification", "long_header".to_string()),
                ("header_form", "long".to_string()),
                ("first_byte", format!("0x{first_byte:02x}")),
                ("fixed_bit", fixed_bit.to_string()),
                ("quic_bit", quic_fixed_bit_label(*fixed_bit).to_string()),
                ("packet_kind", packet_kind.label().to_string()),
                (
                    "version",
                    format!("0x{version:08x} ({})", quic_version_label(*version)),
                ),
                (
                    "version_status",
                    format!("{:?}", quic_version_status(*version)),
                ),
                (
                    "destination_connection_id_len",
                    destination_connection_id.len().to_string(),
                ),
                (
                    "destination_connection_id",
                    destination_connection_id.to_spaced_hex(),
                ),
                (
                    "source_connection_id_len",
                    source_connection_id.len().to_string(),
                ),
                ("source_connection_id", source_connection_id.to_spaced_hex()),
                ("invariant_header_len", invariant_len.to_string()),
                ("protected_or_raw_remainder_len", remaining_len.to_string()),
            ],
        }
    }
}

/// Classify enough QUIC header structure for conservative UDP dispatch.
pub fn classify_quic_header(bytes: &[u8]) -> Result<QuicHeaderClassification> {
    let Some(first_byte) = bytes.first().copied() else {
        return Ok(QuicHeaderClassification::NonQuic);
    };
    let fixed_bit = first_byte & QUIC_FIXED_BIT_MASK != 0;
    if first_byte & QUIC_HEADER_FORM_MASK == 0 {
        return if fixed_bit {
            Ok(QuicHeaderClassification::ShortHeaderAmbiguous {
                first_byte,
                fixed_bit,
            })
        } else {
            Ok(QuicHeaderClassification::NonQuic)
        };
    }

    if bytes.len() < 5 {
        return Err(CrafterError::buffer_too_short(
            "quic.header.long.version",
            5,
            bytes.len(),
        ));
    }
    let version = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    if bytes.len() < 6 {
        return Err(CrafterError::buffer_too_short(
            "quic.header.long.dcid_len",
            6,
            bytes.len(),
        ));
    }
    let dcid_len = bytes[5] as usize;
    let dcid_start = 6;
    let dcid_end = dcid_start + dcid_len;
    if bytes.len() < dcid_end {
        return Err(CrafterError::buffer_too_short(
            "quic.header.long.dcid",
            dcid_end,
            bytes.len(),
        ));
    }
    if bytes.len() < dcid_end + 1 {
        return Err(CrafterError::buffer_too_short(
            "quic.header.long.scid_len",
            dcid_end + 1,
            bytes.len(),
        ));
    }
    let scid_len = bytes[dcid_end] as usize;
    let scid_start = dcid_end + 1;
    let scid_end = scid_start + scid_len;
    if bytes.len() < scid_end {
        return Err(CrafterError::buffer_too_short(
            "quic.header.long.scid",
            scid_end,
            bytes.len(),
        ));
    }
    let remaining_len = bytes.len() - scid_end;
    let packet_kind = classify_long_packet_kind(version, first_byte);
    if packet_kind == QuicLongPacketKind::VersionNegotiation
        && (remaining_len == 0 || remaining_len % 4 != 0)
    {
        let missing = if remaining_len == 0 {
            4
        } else {
            4 - (remaining_len % 4)
        };
        return Err(CrafterError::buffer_too_short(
            "quic.version_negotiation.supported_versions",
            bytes.len() + missing,
            bytes.len(),
        ));
    }

    Ok(QuicHeaderClassification::LongHeader {
        first_byte,
        fixed_bit,
        version,
        destination_connection_id: QuicConnectionId::from_bytes(&bytes[dcid_start..dcid_end]),
        source_connection_id: QuicConnectionId::from_bytes(&bytes[scid_start..scid_end]),
        invariant_len: scid_end,
        remaining_len,
        packet_kind,
    })
}

const fn classify_long_packet_kind(version: u32, first_byte: u8) -> QuicLongPacketKind {
    if version == QUIC_VERSION_NEGOTIATION {
        return QuicLongPacketKind::VersionNegotiation;
    }
    let bits = (first_byte & QUIC_LONG_PACKET_TYPE_MASK) >> 4;
    match version {
        QUIC_VERSION_1 => match bits {
            0 => QuicLongPacketKind::Initial,
            1 => QuicLongPacketKind::ZeroRtt,
            2 => QuicLongPacketKind::Handshake,
            _ => QuicLongPacketKind::Retry,
        },
        QUIC_VERSION_2 => match bits {
            0 => QuicLongPacketKind::Retry,
            1 => QuicLongPacketKind::Initial,
            2 => QuicLongPacketKind::ZeroRtt,
            _ => QuicLongPacketKind::Handshake,
        },
        _ => QuicLongPacketKind::UnknownVersion,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_header_bits_access_decoded_first_byte() {
        let header = QuicHeader::from_decoded_bytes([0x5d, 0xaa, 0xbb]).unwrap();

        assert_eq!(header.first_byte_value(), Some(0x5d));
        assert_eq!(header.first_byte_state(), FieldState::User);
        assert_eq!(header.header_form_value(), Some(QuicHeaderForm::Short));
        assert_eq!(header.is_short_header(), Some(true));
        assert_eq!(header.fixed_bit_value(), Some(true));
        assert_eq!(header.short_spin_bit_value(), Some(false));
        assert_eq!(header.short_reserved_bits_value(), Some(0x03));
        assert_eq!(header.short_key_phase_value(), Some(true));
        assert_eq!(header.packet_number_len_bits_value(), Some(0x01));
        assert_eq!(header.packet_number_len_value(), Some(2));
        assert_eq!(header.destination_connection_id_field_present(), Some(true));
        assert_eq!(header.raw_bytes(), &[0x5d, 0xaa, 0xbb]);
    }

    #[test]
    fn quic_header_bits_build_long_header_first_byte_without_normalizing_reserved_bits() {
        let header = QuicHeader::new()
            .header_form(QuicHeaderForm::Long)
            .fixed_bit(true)
            .long_packet_type_bits(2)
            .long_reserved_bits(3)
            .packet_number_len(4)
            .unwrap();

        assert_eq!(header.first_byte_value(), Some(0xef));
        assert_eq!(header.header_form_value(), Some(QuicHeaderForm::Long));
        assert_eq!(header.is_long_header(), Some(true));
        assert_eq!(header.fixed_bit_value(), Some(true));
        assert_eq!(header.long_packet_type_bits_value(), Some(2));
        assert_eq!(header.long_reserved_bits_value(), Some(3));
        assert_eq!(header.packet_number_len_bits_value(), Some(3));
        assert_eq!(header.packet_number_len_value(), Some(4));
    }

    #[test]
    fn quic_header_bits_build_short_header_preserving_other_raw_bits() {
        let header = QuicHeader::new()
            .first_byte(0xff)
            .header_form(QuicHeaderForm::Short)
            .fixed_bit(false)
            .short_spin_bit(false)
            .short_reserved_bits(1)
            .short_key_phase(false)
            .packet_number_len_bits(2);

        assert_eq!(header.first_byte_value(), Some(0x0a));
        assert_eq!(header.header_form_value(), Some(QuicHeaderForm::Short));
        assert_eq!(header.fixed_bit_value(), Some(false));
        assert_eq!(header.short_spin_bit_value(), Some(false));
        assert_eq!(header.short_reserved_bits_value(), Some(1));
        assert_eq!(header.short_key_phase_value(), Some(false));
        assert_eq!(header.packet_number_len_value(), Some(3));
    }

    #[test]
    fn quic_bit_grease_header_helpers_label_cleared_bit() {
        let header = QuicHeader::new()
            .header_form(QuicHeaderForm::Long)
            .fixed_bit(true)
            .long_packet_type_bits(3)
            .grease_quic_bit();

        assert_eq!(header.first_byte_value(), Some(0xb0));
        assert_eq!(header.fixed_bit_value(), Some(false));
        assert_eq!(
            header.quic_bit_status_value(),
            Some(QuicFixedBitStatus::GreasedCleared)
        );
        assert_eq!(header.quic_bit_label_value(), Some("greased_cleared"));
        assert_eq!(quic_fixed_bit_label(true), "set");
        assert_eq!(quic_fixed_bit_label(false), "greased_cleared");
        assert_eq!(
            quic_fixed_bit_status(0x80),
            QuicFixedBitStatus::GreasedCleared
        );
        assert_eq!(quic_clear_fixed_bit(0xf0), 0xb0);
        assert_eq!(quic_set_fixed_bit(0x80), 0xc0);
    }

    #[test]
    fn quic_header_bits_reject_invalid_packet_number_length_builder() {
        assert_eq!(
            QuicHeader::new().packet_number_len(0).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.packet_number.length",
                "QUIC packet-number length must be 1, 2, 3, or 4 bytes",
            )
        );
        assert_eq!(
            QuicHeader::new().first_byte_value(),
            None,
            "failed builder should not synthesize a byte"
        );
    }

    #[test]
    fn quic_header_classifier_returns_non_match_for_ordinary_udp_payloads() {
        assert_eq!(
            classify_quic_header(&[0x16, 0xfe, 0xfd]).unwrap(),
            QuicHeaderClassification::NonQuic
        );
        assert_eq!(
            classify_quic_header(&[]).unwrap(),
            QuicHeaderClassification::NonQuic
        );
    }

    #[test]
    fn quic_header_classifier_marks_short_headers_ambiguous() {
        assert_eq!(
            classify_quic_header(&[0x43, 0x83, 0x94, 0xc8]).unwrap(),
            QuicHeaderClassification::ShortHeaderAmbiguous {
                first_byte: 0x43,
                fixed_bit: true,
            }
        );
    }

    #[test]
    fn quic_header_classifier_parses_long_header_prefix() {
        let classified = classify_quic_header(&[
            0xc3, 0x00, 0x00, 0x00, 0x01, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0x00,
        ])
        .unwrap();

        match classified {
            QuicHeaderClassification::LongHeader {
                first_byte,
                fixed_bit,
                version,
                destination_connection_id,
                source_connection_id,
                invariant_len,
                remaining_len,
                packet_kind,
            } => {
                assert_eq!(first_byte, 0xc3);
                assert!(fixed_bit);
                assert_eq!(version, QUIC_VERSION_1);
                assert_eq!(
                    destination_connection_id.as_bytes(),
                    [0x83, 0x94, 0xc8, 0xf0]
                );
                assert_eq!(source_connection_id.as_bytes(), [0xaa]);
                assert_eq!(invariant_len, 12);
                assert_eq!(remaining_len, 1);
                assert_eq!(packet_kind, QuicLongPacketKind::Initial);
            }
            other => panic!("unexpected classification: {other:?}"),
        }
    }

    #[test]
    fn quic_summary_inspection_header_classification_is_stable() {
        let classified = classify_quic_header(&[
            0xc3, 0x00, 0x00, 0x00, 0x01, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0x00,
        ])
        .unwrap();

        assert_eq!(
            classified.summary(),
            "header=long kind=Initial first_byte=0xc3 fixed_bit=true quic_bit=set version=0x00000001(QUIC v1) dcid=len=4 value=8394c8f0 scid=len=1 value=aa protected_or_raw_len=1"
        );
        let fields = classified.inspection_fields();
        assert!(fields.contains(&("classification", "long_header".to_string())));
        assert!(fields.contains(&("quic_bit", "set".to_string())));
        assert!(fields.contains(&("version", "0x00000001 (QUIC v1)".to_string())));
        assert!(fields.contains(&("destination_connection_id", "83 94 c8 f0".to_string())));
        assert!(fields.contains(&("protected_or_raw_remainder_len", "1".to_string())));
    }

    #[test]
    fn quic_header_classifier_maps_v2_retry_bits() {
        let classified =
            classify_quic_header(&[0xc0, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x00, 0x00]).unwrap();

        assert!(matches!(
            classified,
            QuicHeaderClassification::LongHeader {
                packet_kind: QuicLongPacketKind::Retry,
                version: QUIC_VERSION_2,
                ..
            }
        ));
    }

    #[test]
    fn quic_header_classifier_classifies_version_negotiation() {
        let classified = classify_quic_header(&[
            0x80, 0x00, 0x00, 0x00, 0x00, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x00, 0x00, 0x00, 0x00,
            0x01,
        ])
        .unwrap();

        assert!(matches!(
            classified,
            QuicHeaderClassification::LongHeader {
                packet_kind: QuicLongPacketKind::VersionNegotiation,
                version: QUIC_VERSION_NEGOTIATION,
                remaining_len: 4,
                ..
            }
        ));
    }

    #[test]
    fn quic_header_classifier_reports_long_header_truncation() {
        assert_eq!(
            classify_quic_header(&[0xc0]).unwrap_err(),
            CrafterError::buffer_too_short("quic.header.long.version", 5, 1)
        );
        assert_eq!(
            classify_quic_header(&[0xc0, 0, 0, 0, 1, 4, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("quic.header.long.dcid", 10, 7)
        );
        assert_eq!(
            classify_quic_header(&[0x80, 0, 0, 0, 0, 0, 0]).unwrap_err(),
            CrafterError::buffer_too_short("quic.version_negotiation.supported_versions", 11, 7)
        );
    }
}
