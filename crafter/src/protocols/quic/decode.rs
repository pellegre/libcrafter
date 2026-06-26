//! QUIC decode placeholders.
//!
//! These helpers are not registered in UDP dispatch. They give later steps a
//! local integration point while preserving nonempty payload bytes and
//! returning structured errors for malformed empty buffers.

use crate::error::{CrafterError, Result};
use crate::packet::Packet;

use super::header::{classify_quic_header, QuicHeaderClassification, QuicLongPacketKind};
use super::{Quic, QuicLongHeaderPacket, QuicPacket};

/// Explicitly append a raw-preserving QUIC placeholder layer.
pub(crate) fn append_quic_packet(packet: Packet, payload: &[u8]) -> Result<Packet> {
    Ok(packet.push(decode_quic_datagram(payload)?))
}

/// Return true when a UDP payload has enough source-backed QUIC long-header
/// structure to be treated as a QUIC datagram by the conservative registry
/// binding.
///
/// Short headers are intentionally not recognized here: they do not carry a
/// version or connection ID length, so default decode needs caller or endpoint
/// context before claiming the UDP payload as QUIC.
pub(crate) fn looks_like_quic_udp_payload(payload: &[u8]) -> bool {
    match classify_quic_header(payload) {
        Ok(QuicHeaderClassification::LongHeader {
            fixed_bit: true, ..
        }) => true,
        Ok(QuicHeaderClassification::LongHeader {
            packet_kind: QuicLongPacketKind::VersionNegotiation,
            ..
        }) => true,
        _ => false,
    }
}

/// Decode enough of a QUIC datagram to preserve nonempty raw bytes.
pub(crate) fn decode_quic_datagram(payload: &[u8]) -> Result<Quic> {
    if payload.is_empty() {
        return Err(CrafterError::buffer_too_short(
            "quic.datagram",
            1,
            payload.len(),
        ));
    }

    let mut offset = 0usize;
    let mut packets = Vec::new();
    while offset < payload.len() {
        let remaining = &payload[offset..];
        match classify_quic_header(remaining)? {
            QuicHeaderClassification::LongHeader {
                packet_kind:
                    QuicLongPacketKind::Initial
                    | QuicLongPacketKind::ZeroRtt
                    | QuicLongPacketKind::Handshake,
                ..
            } => {
                let long_header = QuicLongHeaderPacket::decode(remaining)?;
                offset = offset
                    .checked_add(long_header.len())
                    .ok_or_else(datagram_length_overflow_error)?;
                packets.push(QuicPacket::from_long_header(long_header));
            }
            QuicHeaderClassification::LongHeader {
                packet_kind: QuicLongPacketKind::VersionNegotiation | QuicLongPacketKind::Retry,
                ..
            } => {
                packets.push(QuicPacket::decode(remaining)?);
                offset = payload.len();
            }
            QuicHeaderClassification::LongHeader {
                packet_kind: QuicLongPacketKind::UnknownVersion,
                ..
            } if packets.is_empty() => {
                return Ok(Quic::from_decoded_payload(payload));
            }
            QuicHeaderClassification::ShortHeaderAmbiguous { .. } if packets.is_empty() => {
                return Ok(Quic::from_decoded_payload(payload));
            }
            QuicHeaderClassification::LongHeader {
                packet_kind: QuicLongPacketKind::UnknownVersion,
                ..
            }
            | QuicHeaderClassification::ShortHeaderAmbiguous { .. } => {
                packets.push(QuicPacket::from_bytes(remaining));
                offset = payload.len();
            }
            QuicHeaderClassification::NonQuic if packets.is_empty() => {
                return Ok(Quic::from_decoded_payload(payload));
            }
            QuicHeaderClassification::NonQuic => {
                return Err(CrafterError::invalid_field_value(
                    "quic.datagram",
                    "coalesced QUIC datagram contains non-QUIC trailing bytes",
                ));
            }
        }
    }

    let mut quic = Quic::new();
    for packet in packets {
        quic = quic.packet(packet);
    }
    Ok(quic)
}

fn datagram_length_overflow_error() -> CrafterError {
    CrafterError::invalid_field_value(
        "quic.datagram.length",
        "QUIC datagram length exceeds addressable packet bytes",
    )
}

#[cfg(test)]
mod tests {
    use crate::packet::{Layer, Packet};
    use crate::protocols::quic::{QuicConnectionId, QuicPacketNumber};

    use super::*;

    #[test]
    fn quic_version_negotiation_decode_enters_typed_packet_layer() -> crate::Result<()> {
        let payload = [
            0xc0, 0x00, 0x00, 0x00, 0x00, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0x00, 0x00,
            0x00, 0x01,
        ];
        let quic = decode_quic_datagram(&payload)?;

        assert_eq!(quic.packets().len(), 1);
        assert!(quic.packets()[0].is_version_negotiation());
        let compiled = Packet::from_layer(quic).compile()?;
        assert_eq!(compiled.as_bytes(), payload);
        Ok(())
    }

    #[test]
    fn quic_retry_decode_enters_typed_packet_layer() -> crate::Result<()> {
        let payload = [
            0xf0, 0x00, 0x00, 0x00, 0x01, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x01, 0xaa, 0xde, 0xad,
            0xbe, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f,
        ];
        let quic = decode_quic_datagram(&payload)?;

        assert_eq!(quic.packets().len(), 1);
        assert!(quic.packets()[0].is_retry());
        let compiled = Packet::from_layer(quic).compile()?;
        assert_eq!(compiled.as_bytes(), payload);
        Ok(())
    }

    #[test]
    fn quic_coalesced_decode_walks_long_header_packet_lengths() -> crate::Result<()> {
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
        let mut payload = initial.as_bytes().to_vec();
        payload.extend_from_slice(handshake.as_bytes());

        let quic = decode_quic_datagram(&payload)?;

        assert_eq!(quic.packets().len(), 2);
        assert!(quic.packets()[0].is_long_header());
        assert!(quic.packets()[1].is_long_header());
        assert_eq!(
            quic.packets()[0].long_header().unwrap().packet_kind(),
            QuicLongPacketKind::Initial
        );
        assert_eq!(
            quic.packets()[1].long_header().unwrap().packet_kind(),
            QuicLongPacketKind::Handshake
        );
        assert!(quic.summary().contains("packets=2"));

        let compiled = Packet::from_layer(quic).compile()?;
        assert_eq!(compiled.as_bytes(), payload);
        Ok(())
    }

    #[test]
    fn quic_coalesced_decode_allows_final_raw_short_header_tail() -> crate::Result<()> {
        let initial = QuicLongHeaderPacket::initial_builder()
            .packet_number(QuicPacketNumber::new(1))
            .payload([0xbe])
            .build()?;
        let short_tail = [0x40, 0x01, 0xaa];
        let mut payload = initial.as_bytes().to_vec();
        payload.extend_from_slice(&short_tail);

        let quic = decode_quic_datagram(&payload)?;

        assert_eq!(quic.packets().len(), 2);
        assert!(quic.packets()[0].is_long_header());
        assert!(!quic.packets()[1].is_short_header());
        assert_eq!(quic.packets()[1].as_bytes(), short_tail);
        assert_eq!(Packet::from_layer(quic).compile()?.as_bytes(), payload);
        Ok(())
    }

    #[test]
    fn quic_coalesced_decode_reports_declared_length_overrun() -> crate::Result<()> {
        let initial = QuicLongHeaderPacket::initial_builder()
            .packet_number(QuicPacketNumber::new(1))
            .payload([0xbe])
            .build()?;
        let malformed_handshake = [0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0x02, 0xef];
        let mut payload = initial.as_bytes().to_vec();
        payload.extend_from_slice(&malformed_handshake);

        assert_eq!(
            decode_quic_datagram(&payload).unwrap_err(),
            CrafterError::buffer_too_short(
                "quic.long_header.protected_payload",
                11,
                malformed_handshake.len(),
            )
        );
        Ok(())
    }

    #[test]
    fn quic_multiplexing_classifier_accepts_source_backed_long_header_shapes() {
        let initial = [
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x00, 0x00, 0x01, 0x00,
        ];
        let version_negotiation = [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x00, 0x00, 0x00, 0x00,
            0x01,
        ];

        assert!(looks_like_quic_udp_payload(&initial));
        assert!(looks_like_quic_udp_payload(&version_negotiation));
    }

    #[test]
    fn quic_multiplexing_classifier_rejects_neighbor_udp_shapes() {
        let cases: &[(&str, &[u8])] = &[
            (
                "dtls_handshake",
                &[0x16, 0xfe, 0xfd, 0x00, 0x00, 0xde, 0xad],
            ),
            (
                "stun_binding",
                &[0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42],
            ),
            ("rtp", &[0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0xde, 0xad]),
            ("zrtp", &[0x10, 0x00, b'Z', b'R', b'T', b'P']),
            ("turn_channel_data", &[0x40, 0x00, 0x00, 0x04, 0xde, 0xad]),
            ("short_header_ambiguous", &[0x43, 0x83, 0x94, 0xc8, 0xf0]),
            ("greased_short_quic_bit", &[0x03, 0x83, 0x94, 0xc8, 0xf0]),
            (
                "greased_non_vn_long_header",
                &[0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00],
            ),
        ];

        for (name, payload) in cases {
            assert!(
                !looks_like_quic_udp_payload(payload),
                "{name} should not be claimed as QUIC"
            );
        }
    }
}
