//! OSPFv2 (RFC 2328) decode entrypoints.
//!
//! OSPF decode follows the crate's structured-error contract: a buffer too short
//! for the 24-octet common header surfaces a typed
//! [`CrafterError::BufferTooShort`] carrying `context`, `required`, and
//! `available` — never a panic and never a half-read field. The shape mirrors the
//! BGP and ICMP decode paths (see `crate::protocols::bgp::decode` and
//! `crate::protocols::icmp::decode`).
//!
//! This block parses only the common header (RFC 2328 §A.3.1). The body bytes
//! that follow are preserved verbatim in [`OspfBody::Unknown`] so an
//! unrecognized (or not-yet-typed) packet type round-trips byte-for-byte; later
//! steps dispatch the body by packet type. Every recovered header field is
//! marked user-set (`Field::user(...)`) so a decoded packet re-compiles to the
//! same bytes. An unknown or invalid Version is honored verbatim — only
//! truncation below the header length is an error here.

use core::net::Ipv4Addr;

use crate::checksum::internet_checksum_chunks;
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::Packet;

use super::constants::{OSPF_AUTH_LEN, OSPF_AUTYPE_CRYPTOGRAPHIC, OSPF_HEADER_LEN};
use super::{OspfBody, OspfChecksumStatus, Ospfv2};

/// Append a decoded OSPFv2 packet to an existing packet stack.
///
/// Delegates to [`append_ospf_packet_with_checksum_validation`] with checksum
/// validation enabled. The validation flag is consumed by a later step; this
/// block parses the common header and preserves the body verbatim.
#[allow(dead_code)]
pub(crate) fn append_ospf_packet(packet: Packet, bytes: &[u8]) -> Result<Packet> {
    append_ospf_packet_with_checksum_validation(packet, bytes, true)
}

/// Parse the OSPFv2 common header (RFC 2328 §A.3.1) and push a typed [`Ospfv2`]
/// layer onto `packet`.
///
/// The 24-octet common header is Version(1), Type(1), Packet Length(2),
/// Router ID(4), Area ID(4), Checksum(2), AuType(2), Authentication(8). A buffer
/// shorter than [`OSPF_HEADER_LEN`] is a structured truncation error
/// (context `"ospf header"`) rather than a panic.
///
/// The body is the octets after the header. The declared Packet Length bounds
/// the body when it is sane (within `[OSPF_HEADER_LEN, bytes.len()]`); otherwise
/// the remaining bytes are used so a malformed length never drops bytes or reads
/// out of bounds. The body is preserved verbatim in
/// [`OspfBody::Unknown`] for now; later steps dispatch it by packet type.
///
/// Every recovered field is marked user-set so the decoded packet re-compiles
/// byte-for-byte. When `validate_checksum` is true and the packet does not use
/// cryptographic authentication (AuType 2, [`OSPF_AUTYPE_CRYPTOGRAPHIC`]), the
/// standard Internet checksum is recomputed over the OSPF packet excluding the
/// 8-octet authentication field (with the checksum field treated as zero) and
/// compared against the stored checksum to record an
/// [`OspfChecksumStatus`]; when `validate_checksum` is false, or the AuType is
/// cryptographic (whose checksum field is zero, RFC 2328 §D.3), the status is
/// [`OspfChecksumStatus::NotChecked`]. This status is decode metadata only and
/// never affects the re-compiled bytes.
#[allow(dead_code)]
pub(crate) fn append_ospf_packet_with_checksum_validation(
    mut packet: Packet,
    bytes: &[u8],
    validate_checksum: bool,
) -> Result<Packet> {
    if bytes.len() < OSPF_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ospf header",
            OSPF_HEADER_LEN,
            bytes.len(),
        ));
    }

    // Common header (RFC 2328 §A.3.1), read from fixed offsets. The length check
    // above guarantees every slice below is in bounds, so this cannot panic.
    let version = bytes[0];
    let packet_type = bytes[1];
    let packet_length = u16::from_be_bytes([bytes[2], bytes[3]]);
    let router_id = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
    let area_id = Ipv4Addr::new(bytes[8], bytes[9], bytes[10], bytes[11]);
    let checksum = u16::from_be_bytes([bytes[12], bytes[13]]);
    let autype = u16::from_be_bytes([bytes[14], bytes[15]]);
    let mut authentication = [0u8; OSPF_AUTH_LEN];
    authentication.copy_from_slice(&bytes[16..OSPF_HEADER_LEN]);

    // The body follows the 24-octet header. Prefer the declared Packet Length
    // when it is within [OSPF_HEADER_LEN, bytes.len()]; otherwise fall back to
    // the remaining bytes so a malformed length neither overruns the buffer nor
    // discards trailing octets.
    let declared = packet_length as usize;
    let body_end = if (OSPF_HEADER_LEN..=bytes.len()).contains(&declared) {
        declared
    } else {
        bytes.len()
    };
    let body = bytes[OSPF_HEADER_LEN..body_end].to_vec();

    // Decode-time checksum validation status (RFC 2328 §A.3.1), gated by the
    // registry's checksum-validation setting. The OSPF checksum is the standard
    // Internet checksum over the whole OSPF packet (the declared/bounded extent
    // `bytes[..body_end]`) EXCLUDING the 8-octet authentication field (octets
    // 16..24), computed with the checksum field itself zeroed. Cryptographic
    // authentication (AuType 2) carries a zero checksum field instead (RFC 2328
    // §D.3), so it is reported as NotChecked rather than compared.
    let checksum_status = if validate_checksum && autype != OSPF_AUTYPE_CRYPTOGRAPHIC {
        // Recompute over the header up to the checksum field, a zeroed checksum
        // field, the AuType, then the body — i.e. octets [0..12], two zero
        // octets for the checksum, octets [14..16] (AuType), and the body. The
        // 8-octet auth field (16..24) is excluded.
        let zero_checksum = [0u8; 2];
        let computed = internet_checksum_chunks([
            &bytes[..12],
            &zero_checksum[..],
            &bytes[14..16],
            &bytes[OSPF_HEADER_LEN..body_end],
        ]);
        if computed == checksum {
            OspfChecksumStatus::Valid
        } else {
            OspfChecksumStatus::Invalid
        }
    } else {
        OspfChecksumStatus::NotChecked
    };

    let ospf = Ospfv2 {
        version: Field::user(version),
        packet_type: Field::user(packet_type),
        packet_length: Field::user(packet_length),
        router_id: Field::user(router_id),
        area_id: Field::user(area_id),
        checksum: Field::user(checksum),
        autype: Field::user(autype),
        authentication: Field::user(authentication),
        checksum_status,
        body: OspfBody::Unknown {
            type_code: packet_type,
            body,
        },
    };

    packet = packet.push(ospf);
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CrafterError;
    use crate::protocols::ospf::constants::{OSPF_TYPE_HELLO, OSPF_VERSION_2};
    use crate::protocols::ospf::Ospfv2;

    /// A buffer one octet short of the 24-octet common header is a structured
    /// truncation error (context `"ospf header"`), never a panic (RFC 2328
    /// §A.3.1).
    #[test]
    fn ospf_decode_short_header_is_truncation_error() {
        let bytes = [0u8; OSPF_HEADER_LEN - 1];
        let err = append_ospf_packet(Packet::new(), &bytes)
            .expect_err("a 23-byte buffer is too short for the OSPF header");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ospf header");
                assert_eq!(required, OSPF_HEADER_LEN);
                assert_eq!(available, bytes.len());
            }
            other => panic!("expected buffer_too_short, got {other:?}"),
        }
    }

    /// A full 24-octet common header (no body) decodes into a typed `Ospfv2`
    /// layer whose fields equal the bytes, and re-compiles byte-for-byte.
    #[test]
    fn ospf_decode_header_only_round_trips() {
        let bytes = Packet::from_layer(
            Ospfv2::new()
                .packet_type(OSPF_TYPE_HELLO)
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0]),
        )
        .compile()
        .expect("header-only OSPF packet compiles");
        assert_eq!(bytes.len(), OSPF_HEADER_LEN);

        let decoded = append_ospf_packet(Packet::new(), bytes.as_bytes())
            .expect("a full common header decodes");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");

        assert_eq!(ospf.version_value(), OSPF_VERSION_2);
        assert_eq!(ospf.packet_type_value(), OSPF_TYPE_HELLO);
        assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

        let recompiled = decoded.compile().expect("decoded OSPF re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }
}
