//! QUIC decode placeholders.
//!
//! These helpers are not registered in UDP dispatch. They give later steps a
//! local integration point while preserving nonempty payload bytes and
//! returning structured errors for malformed empty buffers.

use crate::error::{CrafterError, Result};
use crate::packet::Packet;

use super::header::{classify_quic_header, QuicHeaderClassification, QuicLongPacketKind};
use super::{Quic, QuicPacket};

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

    let packet = QuicPacket::decode(payload)?;
    if packet.is_version_negotiation() {
        return Ok(Quic::new().packet(packet));
    }

    Ok(Quic::from_decoded_payload(payload))
}

#[cfg(test)]
mod tests {
    use crate::packet::Packet;

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
}
