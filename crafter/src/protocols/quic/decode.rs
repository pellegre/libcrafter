//! QUIC decode placeholders.
//!
//! These helpers are not registered in UDP dispatch. They give later steps a
//! local integration point while preserving nonempty payload bytes and
//! returning structured errors for malformed empty buffers.

use crate::error::{CrafterError, Result};
use crate::packet::Packet;

use super::{constants::QUIC_VERSION_NEGOTIATION, Quic};

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
    let Some((&first, rest)) = payload.split_first() else {
        return false;
    };
    if first & 0x80 == 0 {
        return false;
    }
    let Some(version_bytes) = rest.get(..4) else {
        return false;
    };
    let version = u32::from_be_bytes([
        version_bytes[0],
        version_bytes[1],
        version_bytes[2],
        version_bytes[3],
    ]);
    let Some((&dcid_len, after_dcid_len)) = rest.get(4..).and_then(|bytes| bytes.split_first())
    else {
        return false;
    };
    let dcid_len = dcid_len as usize;
    let Some(after_dcid) = after_dcid_len.get(dcid_len..) else {
        return false;
    };
    let Some((&scid_len, after_scid_len)) = after_dcid.split_first() else {
        return false;
    };
    let scid_len = scid_len as usize;
    let Some(after_scid) = after_scid_len.get(scid_len..) else {
        return false;
    };

    if version == QUIC_VERSION_NEGOTIATION {
        return !after_scid.is_empty() && after_scid.len() % 4 == 0;
    }

    // RFC 8999's fixed bit must be set for QUIC packets using this
    // version-independent long-header shape. Version-specific body validation
    // lands in the later packet grammar steps.
    first & 0x40 != 0
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
