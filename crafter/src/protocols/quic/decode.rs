//! QUIC decode placeholders.
//!
//! These helpers are not registered in UDP dispatch. They give later steps a
//! local integration point while preserving nonempty payload bytes and
//! returning structured errors for malformed empty buffers.

use crate::error::{CrafterError, Result};
use crate::packet::Packet;

use super::header::{classify_quic_header, QuicHeaderClassification, QuicLongPacketKind};
use super::Quic;

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

    Ok(Quic::from_decoded_payload(payload))
}
