//! QUIC header helpers.
//!
//! This module starts with version-independent classification only. It records
//! the invariant long-header fields, preserves the first byte, and avoids
//! guessing short-header connection ID length without caller context.

use crate::error::{CrafterError, Result};
use crate::field::{Field, FieldState};

use super::constants::{QUIC_VERSION_1, QUIC_VERSION_2, QUIC_VERSION_NEGOTIATION};
use super::QuicConnectionId;

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

    /// Stored first-byte value, if one has been supplied or decoded.
    pub fn first_byte_value(&self) -> Option<u8> {
        self.first_byte.value().copied()
    }

    /// State of the first-byte field.
    pub fn first_byte_state(&self) -> FieldState {
        self.first_byte.state()
    }

    /// Borrow the preserved raw header bytes.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

/// Classify enough QUIC header structure for conservative UDP dispatch.
pub fn classify_quic_header(bytes: &[u8]) -> Result<QuicHeaderClassification> {
    let Some(first_byte) = bytes.first().copied() else {
        return Ok(QuicHeaderClassification::NonQuic);
    };
    let fixed_bit = first_byte & 0x40 != 0;
    if first_byte & 0x80 == 0 {
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
    let bits = (first_byte & 0x30) >> 4;
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
