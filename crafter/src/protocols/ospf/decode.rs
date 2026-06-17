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

use super::constants::{
    OSPF_AUTH_LEN, OSPF_AUTYPE_CRYPTOGRAPHIC, OSPF_HEADER_LEN, OSPF_TYPE_HELLO,
};
use super::packet::OspfHello;
use super::{OspfBody, OspfChecksumStatus, Ospfv2};

/// The fixed (pre-neighbor-list) length of the Hello body, in octets (RFC 2328
/// §A.3.2): Network Mask(4) + HelloInterval(2) + Options(1) + Rtr Pri(1) +
/// RouterDeadInterval(4) + Designated Router(4) + Backup Designated Router(4).
const OSPF_HELLO_FIXED_LEN: usize = 20;

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
    let body_bytes = &bytes[OSPF_HEADER_LEN..body_end];

    // Dispatch the body by packet Type (RFC 2328 §A.3.1), mirroring the BGP
    // message-type dispatch (see `crate::protocols::bgp::decode`). Recognized
    // types parse into a typed `OspfBody`; everything else is preserved verbatim
    // in `OspfBody::Unknown` so it round-trips byte-for-byte (later steps add the
    // remaining typed bodies).
    let body = match packet_type {
        OSPF_TYPE_HELLO => OspfBody::Hello(decode_hello_body(body_bytes)?),
        other => OspfBody::Unknown {
            type_code: other,
            body: body_bytes.to_vec(),
        },
    };

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
        body,
    };

    packet = packet.push(ospf);
    Ok(packet)
}

/// Parse the OSPFv2 Hello body (RFC 2328 §A.3.2) from `body` into an
/// [`OspfHello`].
///
/// The Hello body is a fixed 20 octets — Network Mask(4), HelloInterval(2),
/// Options(1), Rtr Pri(1), RouterDeadInterval(4), Designated Router(4), Backup
/// Designated Router(4) — followed by zero or more 4-octet neighbor Router IDs.
///
/// A buffer shorter than the fixed 20 octets is a structured truncation error
/// (context `"ospf hello"`); a neighbor region whose length is not a multiple of
/// 4 is a structured [`CrafterError::invalid_field_value`]
/// (`"ospf.hello.neighbors"`). Every recovered field is marked user-set (through
/// [`OspfHello::from_decoded_parts`]) so the decoded body re-compiles
/// byte-for-byte.
fn decode_hello_body(body: &[u8]) -> Result<OspfHello> {
    if body.len() < OSPF_HELLO_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ospf hello",
            OSPF_HELLO_FIXED_LEN,
            body.len(),
        ));
    }

    // Fixed 20-octet portion (RFC 2328 §A.3.2), read from fixed offsets. The
    // length check above keeps every slice in bounds, so this cannot panic.
    let network_mask = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
    let hello_interval = u16::from_be_bytes([body[4], body[5]]);
    let options = body[6];
    let router_priority = body[7];
    let router_dead_interval = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
    let designated_router = Ipv4Addr::new(body[12], body[13], body[14], body[15]);
    let backup_designated_router = Ipv4Addr::new(body[16], body[17], body[18], body[19]);

    // The remaining octets are the neighbor list: zero or more 4-octet Router
    // IDs. A region not a multiple of 4 is a malformed body, not a truncation.
    let neighbor_region = &body[OSPF_HELLO_FIXED_LEN..];
    if neighbor_region.len() % 4 != 0 {
        return Err(CrafterError::invalid_field_value(
            "ospf.hello.neighbors",
            "neighbor list length must be a multiple of 4",
        ));
    }
    let neighbors = neighbor_region
        .chunks_exact(4)
        .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
        .collect();

    Ok(OspfHello::from_decoded_parts(
        network_mask,
        hello_interval,
        options,
        router_priority,
        router_dead_interval,
        designated_router,
        backup_designated_router,
        neighbors,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CrafterError;
    use crate::protocols::ospf::constants::{
        OSPF_TYPE_HELLO, OSPF_TYPE_LINK_STATE_ACK, OSPF_VERSION_2,
    };
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
    /// layer whose fields equal the bytes, and re-compiles byte-for-byte. A
    /// body-less packet type (LSAck, which carries an empty body when no LSA
    /// headers are present) is used so the header-only case stays valid now that
    /// type 1 (Hello) dispatches to a typed body that requires a 20-octet body.
    #[test]
    fn ospf_decode_header_only_round_trips() {
        let bytes = Packet::from_layer(
            Ospfv2::new()
                .packet_type(OSPF_TYPE_LINK_STATE_ACK)
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
        assert_eq!(ospf.packet_type_value(), OSPF_TYPE_LINK_STATE_ACK);
        assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

        let recompiled = decoded.compile().expect("decoded OSPF re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// A Hello built with three neighbors and an explicit Designated Router,
    /// once compiled, decodes (type 1) into a typed Hello body that exposes the
    /// three neighbors and the DR, and re-compiles byte-for-byte (RFC 2328
    /// §A.3.2).
    #[test]
    fn ospf_decode_hello_with_three_neighbors_round_trips() {
        use crate::protocols::ospf::OspfBody;

        let dr = Ipv4Addr::new(192, 0, 2, 1);
        let neighbors = [
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(192, 0, 2, 11),
            Ipv4Addr::new(192, 0, 2, 12),
        ];

        let bytes = Packet::from_layer(
            Ospfv2::hello()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0])
                .with_hello(|h| {
                    *h = h
                        .clone()
                        .network_mask(Ipv4Addr::new(255, 255, 255, 0))
                        .options(0x02)
                        .router_priority(1)
                        .designated_router(dr)
                        .backup_designated_router(Ipv4Addr::new(192, 0, 2, 2))
                        .neighbors(neighbors);
                }),
        )
        .compile()
        .expect("a Hello with three neighbors compiles");

        let decoded = append_ospf_packet(Packet::new(), bytes.as_bytes())
            .expect("the Hello decodes");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        assert_eq!(ospf.packet_type_value(), OSPF_TYPE_HELLO);

        let hello = match &ospf.body {
            OspfBody::Hello(hello) => hello,
            other => panic!("expected a typed Hello body, got {other:?}"),
        };
        assert_eq!(hello.neighbors_value(), neighbors.as_slice());
        assert_eq!(hello.designated_router_value(), dr);

        let recompiled = decoded.compile().expect("decoded Hello re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// A Hello body truncated to 19 octets (one short of the fixed 20) is a
    /// structured truncation error (context `"ospf hello"`), never a panic
    /// (RFC 2328 §A.3.2).
    #[test]
    fn ospf_decode_hello_body_truncated_is_truncation_error() {
        let err = decode_hello_body(&[0u8; OSPF_HELLO_FIXED_LEN - 1])
            .expect_err("a 19-octet Hello body is too short for the fixed fields");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ospf hello");
                assert_eq!(required, OSPF_HELLO_FIXED_LEN);
                assert_eq!(available, OSPF_HELLO_FIXED_LEN - 1);
            }
            other => panic!("expected buffer_too_short, got {other:?}"),
        }
    }

    /// A Hello whose neighbor region is 6 trailing bytes (not a multiple of 4)
    /// is a structured invalid-field error (`"ospf.hello.neighbors"`), never a
    /// panic (RFC 2328 §A.3.2).
    #[test]
    fn ospf_decode_hello_misaligned_neighbors_is_invalid_field() {
        // 20 fixed octets plus 6 trailing octets: a malformed neighbor region.
        let body = [0u8; OSPF_HELLO_FIXED_LEN + 6];
        let err = decode_hello_body(&body)
            .expect_err("a 6-octet neighbor region is not a multiple of 4");
        match err {
            CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "ospf.hello.neighbors");
            }
            other => panic!("expected invalid_field_value, got {other:?}"),
        }
    }
}
