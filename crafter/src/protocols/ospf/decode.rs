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
    OSPF_AUTH_LEN, OSPF_AUTYPE_CRYPTOGRAPHIC, OSPF_HEADER_LEN, OSPF_TYPE_DATABASE_DESCRIPTION,
    OSPF_TYPE_HELLO, OSPF_TYPE_LINK_STATE_ACK, OSPF_TYPE_LINK_STATE_REQUEST,
    OSPF_TYPE_LINK_STATE_UPDATE,
};
use super::lsa::{
    decode_lsa_headers, OspfAsExternalLsa, OspfExternalTos, OspfLsa, OspfLsaBody, OspfLsaHeader,
    OspfNetworkLsa, OspfRouterLink, OspfRouterLinkTos, OspfRouterLsa, OspfSummaryLsa,
    OspfSummaryTos, OSPF_AS_EXTERNAL_FLAG_E, OSPF_LSA_AS_EXTERNAL, OSPF_LSA_HEADER_LEN,
    OSPF_LSA_NETWORK, OSPF_LSA_ROUTER, OSPF_LSA_SUMMARY_ASBR, OSPF_LSA_SUMMARY_IP,
};
use super::packet::{
    OspfDatabaseDescription, OspfHello, OspfLinkStateAck, OspfLinkStateRequest,
    OspfLinkStateRequestEntry, OspfLinkStateUpdate,
};
use super::{OspfBody, OspfChecksumStatus, Ospfv2};

/// The fixed (pre-neighbor-list) length of the Hello body, in octets (RFC 2328
/// §A.3.2): Network Mask(4) + HelloInterval(2) + Options(1) + Rtr Pri(1) +
/// RouterDeadInterval(4) + Designated Router(4) + Backup Designated Router(4).
const OSPF_HELLO_FIXED_LEN: usize = 20;

/// The fixed (pre-LSA-header-list) length of the Database Description body, in
/// octets (RFC 2328 §A.3.3): Interface MTU(2) + Options(1) + flags(1) + DD
/// sequence number(4).
const OSPF_DD_FIXED_LEN: usize = 8;

/// The on-wire length of a single Link State Request entry, in octets (RFC 2328
/// §A.3.4): LS type(4) + Link State ID(4) + Advertising Router(4).
const OSPF_LSR_ENTRY_LEN: usize = 12;

/// The on-wire length of the Link State Update `# LSAs` count field, in octets
/// (RFC 2328 §A.3.5).
const OSPF_LSU_COUNT_LEN: usize = 4;

/// The fixed (pre-link-list) length of a Router-LSA body, in octets (RFC 2328
/// §A.4.2): flags(1) + reserved(1) + # links(2).
const OSPF_ROUTER_LSA_FIXED_LEN: usize = 4;

/// The fixed portion of a single Router-LSA link description, in octets
/// (RFC 2328 §A.4.2): Link ID(4) + Link Data(4) + Type(1) + # TOS(1) +
/// metric(2).
const OSPF_ROUTER_LINK_FIXED_LEN: usize = 12;

/// The length of a single Router-LSA per-TOS entry, in octets (RFC 2328
/// §A.4.2): TOS(1) + reserved(1) + TOS metric(2).
const OSPF_ROUTER_LINK_TOS_LEN: usize = 4;

/// The length of the Network-LSA network mask field, in octets (RFC 2328
/// §A.4.3).
const OSPF_NETWORK_LSA_MASK_LEN: usize = 4;

/// The length of a single Network-LSA attached-router entry, in octets: a
/// 4-octet Router ID (RFC 2328 §A.4.3).
const OSPF_NETWORK_LSA_ROUTER_LEN: usize = 4;

/// The length of the Summary-LSA network mask field, in octets (RFC 2328
/// §A.4.4).
const OSPF_SUMMARY_LSA_MASK_LEN: usize = 4;

/// The length of a single Summary-LSA TOS/metric entry, in octets: a 1-octet
/// TOS code plus a 3-octet (24-bit) metric (RFC 2328 §A.4.4).
const OSPF_SUMMARY_LSA_TOS_LEN: usize = 4;

/// The length of the AS-External-LSA network mask field, in octets (RFC 2328
/// §A.4.5).
const OSPF_AS_EXTERNAL_LSA_MASK_LEN: usize = 4;

/// The length of a single AS-External-LSA external metric entry, in octets: a
/// 1-octet combined E/TOS octet, a 3-octet (24-bit) metric, a 4-octet
/// forwarding address, and a 4-octet external route tag (RFC 2328 §A.4.5).
const OSPF_AS_EXTERNAL_LSA_ENTRY_LEN: usize = 12;

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
        OSPF_TYPE_DATABASE_DESCRIPTION => {
            OspfBody::DatabaseDescription(decode_database_description_body(body_bytes)?)
        }
        OSPF_TYPE_LINK_STATE_REQUEST => {
            OspfBody::LinkStateRequest(decode_link_state_request_body(body_bytes)?)
        }
        OSPF_TYPE_LINK_STATE_UPDATE => {
            OspfBody::LinkStateUpdate(decode_link_state_update_body(body_bytes)?)
        }
        OSPF_TYPE_LINK_STATE_ACK => {
            OspfBody::LinkStateAck(decode_link_state_ack_body(body_bytes)?)
        }
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

    // Cryptographic authentication (AuType 2, RFC 2328 §D.3) appends a
    // message-digest trailer after the OSPF packet, inside the IP payload but
    // excluded from the OSPF Packet Length. So when the AuType is cryptographic
    // and the declared Packet Length bounded the body (leaving trailing octets),
    // those `available - packet_length` octets are the digest trailer. The
    // structured 8-octet authentication field carries the trailer's length in its
    // Auth Data Length octet (octet 3); the trailer is captured only when at least
    // that many octets remain, so a short or malformed length never claims bytes
    // it cannot back. The trailer is preserved verbatim so the packet re-compiles
    // byte-for-byte even though the decoder holds no secret key (`crypto_auth` is
    // therefore `None`). Non-cryptographic packets carry no trailer.
    let auth_trailer = if autype == OSPF_AUTYPE_CRYPTOGRAPHIC && body_end < bytes.len() {
        let trailing = &bytes[body_end..];
        let auth_data_len = usize::from(authentication[3]);
        if trailing.len() >= auth_data_len {
            trailing.to_vec()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
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
        // Decoded packets carry no recorded secret key: a cryptographic-auth
        // packet's appended digest trailer is captured verbatim in `auth_trailer`,
        // so `compile()` reproduces it without re-deriving a digest.
        crypto_auth: None,
        auth_trailer,
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

/// Parse the OSPFv2 Database Description body (RFC 2328 §A.3.3) from `body` into
/// an [`OspfDatabaseDescription`].
///
/// The Database Description body is a fixed 8 octets — Interface MTU(2),
/// Options(1), flags(1) (carrying the I/M/MS bits), DD sequence number(4) —
/// followed by a list of zero or more bare 20-octet LSA headers (RFC 2328
/// §A.4.1).
///
/// A buffer shorter than the fixed 8 octets is a structured truncation error
/// (context `"ospf database description"`); the trailing LSA-header list is
/// parsed by [`decode_lsa_headers`], which surfaces a structured
/// truncation error for a partial trailing header. Every recovered field is
/// marked user-set (through [`OspfDatabaseDescription::from_decoded_parts`]) so
/// the decoded body re-compiles byte-for-byte.
fn decode_database_description_body(body: &[u8]) -> Result<OspfDatabaseDescription> {
    if body.len() < OSPF_DD_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ospf database description",
            OSPF_DD_FIXED_LEN,
            body.len(),
        ));
    }

    // Fixed 8-octet portion (RFC 2328 §A.3.3), read from fixed offsets. The
    // length check above keeps every slice in bounds, so this cannot panic.
    let interface_mtu = u16::from_be_bytes([body[0], body[1]]);
    let options = body[2];
    let flags = body[3];
    let dd_sequence_number = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);

    // The remaining octets are the LSA-header list (RFC 2328 §A.4.1): zero or
    // more bare 20-octet headers, parsed by the shared list helper.
    let lsa_headers = decode_lsa_headers(&body[OSPF_DD_FIXED_LEN..])?;

    Ok(OspfDatabaseDescription::from_decoded_parts(
        interface_mtu,
        options,
        flags,
        dd_sequence_number,
        lsa_headers,
    ))
}

/// Parse the OSPFv2 Link State Request body (RFC 2328 §A.3.4) from `body` into
/// an [`OspfLinkStateRequest`].
///
/// The Link State Request body is zero or more 12-octet entries — LS type(4),
/// Link State ID(4), Advertising Router(4) — with no fixed prefix; an empty
/// request list is legal. Unlike the 1-octet LS Type in the LSA header (RFC 2328
/// §A.4.1), the request's LS type is a full 4-octet field.
///
/// A body whose length is not a multiple of 12 is a structured
/// [`CrafterError::invalid_field_value`] (`"ospf.link_state_request.entries"`),
/// never a panic. Every recovered field is marked user-set (through
/// [`OspfLinkStateRequest::from_decoded_parts`]) so the decoded body re-compiles
/// byte-for-byte.
fn decode_link_state_request_body(body: &[u8]) -> Result<OspfLinkStateRequest> {
    // The body is a concatenation of fixed 12-octet entries with no prefix. A
    // remainder is a malformed request list, not a truncation.
    if body.len() % OSPF_LSR_ENTRY_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            "ospf.link_state_request.entries",
            "request list length must be a multiple of 12",
        ));
    }

    // Each 12-octet chunk is LS type(4), Link State ID(4), Advertising Router(4),
    // big-endian. The exact-multiple check above keeps every chunk full, so this
    // cannot panic.
    let entries = body
        .chunks_exact(OSPF_LSR_ENTRY_LEN)
        .map(|chunk| {
            let ls_type = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let link_state_id = Ipv4Addr::new(chunk[4], chunk[5], chunk[6], chunk[7]);
            let advertising_router = Ipv4Addr::new(chunk[8], chunk[9], chunk[10], chunk[11]);
            OspfLinkStateRequestEntry::new(ls_type, link_state_id, advertising_router)
        })
        .collect();

    Ok(OspfLinkStateRequest::from_decoded_parts(entries))
}

/// Parse the OSPFv2 Link State Update body (RFC 2328 §A.3.5) from `body` into an
/// [`OspfLinkStateUpdate`].
///
/// The Link State Update body is a 4-octet `# LSAs` count followed by that many
/// complete LSAs. Each LSA is a 20-octet header (RFC 2328 §A.4.1, decoded by
/// [`OspfLsaHeader::decode`]) plus a body of `length - 20` octets, where
/// `length` is the LSA header's declared length field. Unknown LSA types are
/// preserved verbatim as [`OspfLsaBody::Raw`] (mirroring the BGP decoder's
/// unknown-attribute preservation in `crate::protocols::bgp::decode`) so the
/// update round-trips byte-for-byte; typed LSA bodies arrive in later steps.
///
/// A buffer shorter than the 4-octet count is a structured truncation error
/// (context `"ospf link state update"`). A declared LSA `length` below the
/// 20-octet header minimum is a structured
/// [`CrafterError::invalid_field_value`] (`"ospf.lsa.length"`); a `length`
/// beyond the remaining bytes is a structured truncation error (context
/// `"ospf lsa"`). The loop stops once the byte slice is exhausted (or the
/// declared count is reached), so every body octet is consumed into an LSA and
/// no trailing bytes are dropped. The on-wire `# LSAs` count is recovered and
/// marked user-set (through [`OspfLinkStateUpdate::from_decoded_parts`]) so the
/// update re-compiles byte-for-byte even when the declared count disagrees with
/// the number of parsed LSAs.
fn decode_link_state_update_body(body: &[u8]) -> Result<OspfLinkStateUpdate> {
    if body.len() < OSPF_LSU_COUNT_LEN {
        return Err(CrafterError::buffer_too_short(
            "ospf link state update",
            OSPF_LSU_COUNT_LEN,
            body.len(),
        ));
    }

    // The `# LSAs` count (octets 0..4). The length check above keeps this slice
    // in bounds, so it cannot panic.
    let num_lsas = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);

    // The LSAs follow the count. Parse one LSA per iteration, advancing by each
    // LSA's declared `length` field, until the slice is exhausted or the declared
    // count is reached. Each LSA's body is preserved verbatim as `OspfLsaBody::Raw`
    // (later steps dispatch typed LSA bodies).
    let mut rest = &body[OSPF_LSU_COUNT_LEN..];
    let mut lsas = Vec::with_capacity(num_lsas as usize);
    let mut parsed: u64 = 0;
    while !rest.is_empty() && parsed < u64::from(num_lsas) {
        // Decode the 20-octet header and read its declared LSA length, which
        // spans the header plus the body.
        let (header, length) = OspfLsaHeader::decode(rest)?;

        // The declared length must cover at least the 20-octet header and must
        // not run past the bytes that remain.
        if length < OSPF_LSA_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "ospf.lsa.length",
                "LSA length is below the 20-octet header minimum",
            ));
        }
        if length > rest.len() {
            return Err(CrafterError::buffer_too_short("ospf lsa", length, rest.len()));
        }

        // The LSA body is the `length - 20` octets after the header. Dispatch on
        // the LSA header's LS type: a typed body is parsed for the types this
        // decoder models, and every other type is preserved verbatim as
        // `OspfLsaBody::Raw` so an unknown LSA round-trips byte-for-byte.
        let lsa_body = &rest[OSPF_LSA_HEADER_LEN..length];
        let body = decode_lsa_body(header.ls_type_value(), lsa_body)?;
        lsas.push(OspfLsa::new(header, body));

        rest = &rest[length..];
        parsed += 1;
    }

    Ok(OspfLinkStateUpdate::from_decoded_parts(num_lsas, lsas))
}

/// Dispatch an LSA body by its LS type (RFC 2328 §A.4.1), parsing the typed
/// bodies this decoder models and preserving every other type verbatim.
///
/// `body` is the LSA bytes after the 20-octet header (`length - 20` octets). For
/// a modeled LS type the matching typed [`OspfLsaBody`] variant is parsed (with
/// structured errors on a short body); for any other type the bytes are
/// preserved as [`OspfLsaBody::Raw`] so the LSA round-trips byte-for-byte
/// (mirroring the BGP decoder's unknown-attribute preservation in
/// `crate::protocols::bgp::decode`). Later steps add the remaining typed bodies
/// to the `match` below.
fn decode_lsa_body(ls_type: u8, body: &[u8]) -> Result<OspfLsaBody> {
    match ls_type {
        OSPF_LSA_ROUTER => Ok(OspfLsaBody::Router(decode_router_lsa_body(body)?)),
        OSPF_LSA_NETWORK => Ok(OspfLsaBody::Network(decode_network_lsa_body(body)?)),
        OSPF_LSA_SUMMARY_IP | OSPF_LSA_SUMMARY_ASBR => {
            Ok(OspfLsaBody::Summary(decode_summary_lsa_body(body)?))
        }
        OSPF_LSA_AS_EXTERNAL => Ok(OspfLsaBody::AsExternal(decode_as_external_lsa_body(body)?)),
        _ => Ok(OspfLsaBody::Raw(body.to_vec())),
    }
}

/// Parse the OSPFv2 Router-LSA body (RFC 2328 §A.4.2) from `body` into an
/// [`OspfRouterLsa`].
///
/// `body` is the LSA bytes after the 20-octet header. The body is a 4-octet
/// fixed prefix (the router-description flags, a reserved octet, and the `#
/// links` count) followed by that many link descriptions, each a 12-octet fixed
/// portion (Link ID, Link Data, Type, `# TOS`, metric) plus `# TOS` 4-octet
/// per-TOS entries.
///
/// A body shorter than the 4-octet fixed prefix, or a link region (12 octets
/// plus `# TOS * 4`) that runs past the bytes that remain, is a structured
/// [`CrafterError::buffer_too_short`] (context `"ospf router-lsa link"` for a
/// short link/TOS region) rather than a panic. The flags octet and the on-wire
/// `# links` count are recovered and marked user-set (through
/// [`OspfRouterLsa::from_decoded_parts`]) so the Router-LSA re-compiles
/// byte-for-byte even when the declared count disagrees with the number of
/// parsed links.
fn decode_router_lsa_body(body: &[u8]) -> Result<OspfRouterLsa> {
    if body.len() < OSPF_ROUTER_LSA_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ospf router-lsa",
            OSPF_ROUTER_LSA_FIXED_LEN,
            body.len(),
        ));
    }

    // Fixed prefix: flags(1), a reserved octet (1), then the `# links` count (2).
    let flags = body[0];
    let num_links = u16::from_be_bytes([body[2], body[3]]);

    // Parse `num_links` link descriptions from the bytes after the fixed prefix.
    let mut rest = &body[OSPF_ROUTER_LSA_FIXED_LEN..];
    let mut links = Vec::with_capacity(num_links as usize);
    for _ in 0..num_links {
        // The 12-octet fixed portion must fit, then `# TOS` 4-octet entries.
        if rest.len() < OSPF_ROUTER_LINK_FIXED_LEN {
            return Err(CrafterError::buffer_too_short(
                "ospf router-lsa link",
                OSPF_ROUTER_LINK_FIXED_LEN,
                rest.len(),
            ));
        }

        let link_id = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
        let link_data = Ipv4Addr::new(rest[4], rest[5], rest[6], rest[7]);
        let link_type = rest[8];
        let num_tos = rest[9] as usize;
        let metric = u16::from_be_bytes([rest[10], rest[11]]);

        // The full link spans the 12-octet fixed portion plus `# TOS` 4-octet
        // per-TOS entries; the whole region must be present.
        let link_len = OSPF_ROUTER_LINK_FIXED_LEN + num_tos * OSPF_ROUTER_LINK_TOS_LEN;
        if rest.len() < link_len {
            return Err(CrafterError::buffer_too_short(
                "ospf router-lsa link",
                link_len,
                rest.len(),
            ));
        }

        // Each per-TOS entry is TOS(1), a reserved octet (1), then the TOS
        // metric (2 octets).
        let mut tos_entries = Vec::with_capacity(num_tos);
        let mut tos_bytes = &rest[OSPF_ROUTER_LINK_FIXED_LEN..link_len];
        for _ in 0..num_tos {
            let tos = tos_bytes[0];
            let tos_metric = u16::from_be_bytes([tos_bytes[2], tos_bytes[3]]);
            tos_entries.push(OspfRouterLinkTos::new(tos, tos_metric));
            tos_bytes = &tos_bytes[OSPF_ROUTER_LINK_TOS_LEN..];
        }

        links.push(
            OspfRouterLink::new(link_id, link_data, link_type, metric).tos_entries(tos_entries),
        );

        rest = &rest[link_len..];
    }

    Ok(OspfRouterLsa::from_decoded_parts(flags, num_links, links))
}

/// Parse the OSPFv2 Network-LSA body (RFC 2328 §A.4.3) from `body` into an
/// [`OspfNetworkLsa`].
///
/// `body` is the LSA bytes after the 20-octet header. The body is a 4-octet
/// Network Mask followed by zero or more 4-octet attached Router IDs (the
/// designated router includes its own Router ID).
///
/// A body shorter than the 4-octet network mask is a structured
/// [`CrafterError::buffer_too_short`] (context `"ospf network-lsa"`); an
/// attached-router region whose length is not a multiple of 4 is a structured
/// [`CrafterError::invalid_field_value`]
/// (`"ospf.network_lsa.attached_routers"`), never a panic. The network mask is
/// recovered and marked user-set (through [`OspfNetworkLsa::from_decoded_parts`])
/// so the Network-LSA re-compiles byte-for-byte.
fn decode_network_lsa_body(body: &[u8]) -> Result<OspfNetworkLsa> {
    if body.len() < OSPF_NETWORK_LSA_MASK_LEN {
        return Err(CrafterError::buffer_too_short(
            "ospf network-lsa",
            OSPF_NETWORK_LSA_MASK_LEN,
            body.len(),
        ));
    }

    // Network Mask (octets 0..4). The length check above keeps this slice in
    // bounds, so it cannot panic.
    let network_mask = Ipv4Addr::new(body[0], body[1], body[2], body[3]);

    // The remaining octets are the attached-router list: zero or more 4-octet
    // Router IDs. A region not a multiple of 4 is a malformed list, not a
    // truncation.
    let router_region = &body[OSPF_NETWORK_LSA_MASK_LEN..];
    if router_region.len() % OSPF_NETWORK_LSA_ROUTER_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            "ospf.network_lsa.attached_routers",
            "attached router list length must be a multiple of 4",
        ));
    }
    let attached_routers = router_region
        .chunks_exact(OSPF_NETWORK_LSA_ROUTER_LEN)
        .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
        .collect();

    Ok(OspfNetworkLsa::from_decoded_parts(
        network_mask,
        attached_routers,
    ))
}

/// Parse the OSPFv2 Summary-LSA body (RFC 2328 §A.4.4) from `body` into an
/// [`OspfSummaryLsa`]. Shared by LS type 3 (IP network) and LS type 4 (AS
/// boundary router), which have the identical body layout.
///
/// `body` is the LSA bytes after the 20-octet header. The body is a 4-octet
/// Network Mask followed by one or more 4-octet TOS/metric entries, each a
/// 1-octet TOS code plus a 24-bit (3-octet, big-endian) metric.
///
/// A body shorter than the 4-octet network mask is a structured
/// [`CrafterError::buffer_too_short`] (context `"ospf summary-lsa"`); a
/// TOS/metric region whose length is not a multiple of 4 is a structured
/// [`CrafterError::invalid_field_value`] (`"ospf.summary_lsa.entries"`), never a
/// panic. The network mask is recovered and marked user-set (through
/// [`OspfSummaryLsa::from_decoded_parts`]) so the Summary-LSA re-compiles
/// byte-for-byte.
fn decode_summary_lsa_body(body: &[u8]) -> Result<OspfSummaryLsa> {
    if body.len() < OSPF_SUMMARY_LSA_MASK_LEN {
        return Err(CrafterError::buffer_too_short(
            "ospf summary-lsa",
            OSPF_SUMMARY_LSA_MASK_LEN,
            body.len(),
        ));
    }

    // Network Mask (octets 0..4). The length check above keeps this slice in
    // bounds, so it cannot panic.
    let network_mask = Ipv4Addr::new(body[0], body[1], body[2], body[3]);

    // The remaining octets are the TOS/metric list: one or more 4-octet entries.
    // A region not a multiple of 4 is a malformed list, not a truncation.
    let tos_region = &body[OSPF_SUMMARY_LSA_MASK_LEN..];
    if tos_region.len() % OSPF_SUMMARY_LSA_TOS_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            "ospf.summary_lsa.entries",
            "TOS metric list length must be a multiple of 4",
        ));
    }

    // Each 4-octet entry is a 1-octet TOS code followed by a 24-bit big-endian
    // metric (RFC 2328 §A.4.4). The exact-multiple check above keeps every chunk
    // full, so this cannot panic.
    let entries = tos_region
        .chunks_exact(OSPF_SUMMARY_LSA_TOS_LEN)
        .map(|chunk| {
            let tos = chunk[0];
            let metric =
                (u32::from(chunk[1]) << 16) | (u32::from(chunk[2]) << 8) | u32::from(chunk[3]);
            OspfSummaryTos::new(tos, metric)
        })
        .collect();

    Ok(OspfSummaryLsa::from_decoded_parts(network_mask, entries))
}

/// Parse the OSPFv2 AS-External-LSA body (RFC 2328 §A.4.5) from `body` into an
/// [`OspfAsExternalLsa`].
///
/// `body` is the LSA bytes after the 20-octet header. The body is a 4-octet
/// Network Mask followed by one or more 12-octet external metric entries, each a
/// combined E/TOS octet (the high bit, [`OSPF_AS_EXTERNAL_FLAG_E`], is the E bit
/// and the low 7 bits the TOS code), a 24-bit (3-octet, big-endian) metric, a
/// 4-octet forwarding address, and a 4-octet external route tag.
///
/// A body shorter than the 4-octet network mask is a structured
/// [`CrafterError::buffer_too_short`] (context `"ospf as-external-lsa"`); an
/// external-metric region whose length is not a multiple of 12 is a structured
/// [`CrafterError::invalid_field_value`] (`"ospf.as_external_lsa.entries"`),
/// never a panic. The network mask is recovered and marked user-set (through
/// [`OspfAsExternalLsa::from_decoded_parts`]) so the AS-External-LSA re-compiles
/// byte-for-byte.
fn decode_as_external_lsa_body(body: &[u8]) -> Result<OspfAsExternalLsa> {
    if body.len() < OSPF_AS_EXTERNAL_LSA_MASK_LEN {
        return Err(CrafterError::buffer_too_short(
            "ospf as-external-lsa",
            OSPF_AS_EXTERNAL_LSA_MASK_LEN,
            body.len(),
        ));
    }

    // Network Mask (octets 0..4). The length check above keeps this slice in
    // bounds, so it cannot panic.
    let network_mask = Ipv4Addr::new(body[0], body[1], body[2], body[3]);

    // The remaining octets are the external metric list: one or more 12-octet
    // entries. A region not a multiple of 12 is a malformed list, not a
    // truncation.
    let entry_region = &body[OSPF_AS_EXTERNAL_LSA_MASK_LEN..];
    if entry_region.len() % OSPF_AS_EXTERNAL_LSA_ENTRY_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            "ospf.as_external_lsa.entries",
            "external metric list length must be a multiple of 12",
        ));
    }

    // Each 12-octet entry is a combined E/TOS octet, a 24-bit big-endian metric,
    // a 4-octet forwarding address, and a 4-octet external route tag (RFC 2328
    // §A.4.5). The exact-multiple check above keeps every chunk full, so this
    // cannot panic. The E bit is the high bit of the first octet
    // ([`OSPF_AS_EXTERNAL_FLAG_E`]); the TOS code is its low 7 bits.
    let entries = entry_region
        .chunks_exact(OSPF_AS_EXTERNAL_LSA_ENTRY_LEN)
        .map(|chunk| {
            let e_bit = chunk[0] & OSPF_AS_EXTERNAL_FLAG_E != 0;
            let tos = chunk[0] & 0x7f;
            let metric =
                (u32::from(chunk[1]) << 16) | (u32::from(chunk[2]) << 8) | u32::from(chunk[3]);
            let forwarding_address = Ipv4Addr::new(chunk[4], chunk[5], chunk[6], chunk[7]);
            let external_route_tag =
                u32::from_be_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]);
            OspfExternalTos::new(e_bit, tos, metric, forwarding_address, external_route_tag)
        })
        .collect();

    Ok(OspfAsExternalLsa::from_decoded_parts(network_mask, entries))
}

/// Parse the OSPFv2 Link State Acknowledgment body (RFC 2328 §A.3.6) from `body`
/// into an [`OspfLinkStateAck`].
///
/// Unlike the Database Description body (RFC 2328 §A.3.3) the Link State
/// Acknowledgment has no fixed prefix: the body is just the concatenation of
/// bare 20-octet LSA headers (RFC 2328 §A.4.1), parsed by [`decode_lsa_headers`].
/// An empty list is legal; a partial trailing header surfaces the structured
/// truncation error [`decode_lsa_headers`] returns (context `"ospf lsa header"`)
/// rather than a panic. Every recovered field is marked user-set (through
/// [`OspfLinkStateAck::from_decoded_parts`]) so the decoded body re-compiles
/// byte-for-byte.
fn decode_link_state_ack_body(body: &[u8]) -> Result<OspfLinkStateAck> {
    let lsa_headers = decode_lsa_headers(body)?;
    Ok(OspfLinkStateAck::from_decoded_parts(lsa_headers))
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

    /// A Database Description built with two LSA headers and the I+M+MS flags,
    /// once compiled, decodes (type 2) into a typed Database Description body
    /// that exposes both LSA headers and the flags, and re-compiles
    /// byte-for-byte (RFC 2328 §A.3.3).
    #[test]
    fn ospf_decode_database_description_with_two_lsa_headers_round_trips() {
        use crate::protocols::ospf::lsa::{OspfLsaHeader, OSPF_LSA_NETWORK, OSPF_LSA_ROUTER};
        use crate::protocols::ospf::packet::database_description::{
            OSPF_DD_FLAG_I, OSPF_DD_FLAG_M, OSPF_DD_FLAG_MS,
        };
        use crate::protocols::ospf::OspfBody;
        use crate::protocols::ospf::OSPF_TYPE_DATABASE_DESCRIPTION;

        let bytes = Packet::from_layer(
            Ospfv2::database_description()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0])
                .with_database_description(|d| {
                    *d = d
                        .clone()
                        .interface_mtu(1500)
                        .options(0x02)
                        .dd_sequence_number(0x0000_1a2b)
                        .init(true)
                        .more(true)
                        .master(true)
                        .lsa_header(
                            OspfLsaHeader::new()
                                .ls_type(OSPF_LSA_ROUTER)
                                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                                .ls_sequence_number(0x8000_0001),
                        )
                        .lsa_header(
                            OspfLsaHeader::new()
                                .ls_type(OSPF_LSA_NETWORK)
                                .link_state_id(Ipv4Addr::new(192, 0, 2, 2))
                                .advertising_router(Ipv4Addr::new(198, 51, 100, 7))
                                .ls_sequence_number(0x8000_0002),
                        );
                }),
        )
        .compile()
        .expect("a Database Description with two LSA headers compiles");

        let decoded = append_ospf_packet(Packet::new(), bytes.as_bytes())
            .expect("the Database Description decodes");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        assert_eq!(ospf.packet_type_value(), OSPF_TYPE_DATABASE_DESCRIPTION);

        let dd = match &ospf.body {
            OspfBody::DatabaseDescription(dd) => dd,
            other => panic!("expected a typed Database Description body, got {other:?}"),
        };
        assert_eq!(dd.interface_mtu_value(), 1500);
        assert_eq!(dd.dd_sequence_number_value(), 0x0000_1a2b);
        // The I+M+MS flags survive the round-trip in the low three bits.
        assert_eq!(
            dd.flags_value(),
            OSPF_DD_FLAG_I | OSPF_DD_FLAG_M | OSPF_DD_FLAG_MS
        );
        assert!(dd.init_value());
        assert!(dd.more_value());
        assert!(dd.master_value());

        // Both LSA headers are exposed with their decoded fields.
        let headers = dd.lsa_headers_value();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].ls_type_value(), OSPF_LSA_ROUTER);
        assert_eq!(headers[0].link_state_id_value(), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(
            headers[0].advertising_router_value(),
            Ipv4Addr::new(192, 0, 2, 1)
        );
        assert_eq!(headers[0].ls_sequence_number_value(), 0x8000_0001);
        assert_eq!(headers[1].ls_type_value(), OSPF_LSA_NETWORK);
        assert_eq!(headers[1].link_state_id_value(), Ipv4Addr::new(192, 0, 2, 2));
        assert_eq!(
            headers[1].advertising_router_value(),
            Ipv4Addr::new(198, 51, 100, 7)
        );
        assert_eq!(headers[1].ls_sequence_number_value(), 0x8000_0002);

        let recompiled = decoded
            .compile()
            .expect("decoded Database Description re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// A Database Description body truncated to 7 octets (one short of the fixed
    /// 8) is a structured truncation error (context
    /// `"ospf database description"`), never a panic (RFC 2328 §A.3.3).
    #[test]
    fn ospf_decode_database_description_body_truncated_is_truncation_error() {
        let err = decode_database_description_body(&[0u8; OSPF_DD_FIXED_LEN - 1])
            .expect_err("a 7-octet Database Description body is too short for the fixed fields");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ospf database description");
                assert_eq!(required, OSPF_DD_FIXED_LEN);
                assert_eq!(available, OSPF_DD_FIXED_LEN - 1);
            }
            other => panic!("expected buffer_too_short, got {other:?}"),
        }
    }

    /// A Link State Request built with three entries, once compiled, decodes
    /// (type 3) into a typed Link State Request body that exposes all three
    /// request triples in order, and re-compiles byte-for-byte (RFC 2328
    /// §A.3.4).
    #[test]
    fn ospf_decode_link_state_request_with_three_entries_round_trips() {
        use crate::protocols::ospf::lsa::{OSPF_LSA_NETWORK, OSPF_LSA_ROUTER, OSPF_LSA_SUMMARY_IP};
        use crate::protocols::ospf::OspfBody;
        use crate::protocols::ospf::{OspfLinkStateRequestEntry, OSPF_TYPE_LINK_STATE_REQUEST};

        let entries = [
            OspfLinkStateRequestEntry::new(
                u32::from(OSPF_LSA_ROUTER),
                Ipv4Addr::new(192, 0, 2, 1),
                Ipv4Addr::new(192, 0, 2, 1),
            ),
            OspfLinkStateRequestEntry::new(
                u32::from(OSPF_LSA_NETWORK),
                Ipv4Addr::new(192, 0, 2, 2),
                Ipv4Addr::new(198, 51, 100, 7),
            ),
            OspfLinkStateRequestEntry::new(
                u32::from(OSPF_LSA_SUMMARY_IP),
                Ipv4Addr::new(198, 51, 100, 0),
                Ipv4Addr::new(192, 0, 2, 3),
            ),
        ];

        let bytes = Packet::from_layer(
            Ospfv2::link_state_request()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0])
                .with_link_state_request(|r| {
                    *r = r.clone().requests(entries.iter().cloned());
                }),
        )
        .compile()
        .expect("a Link State Request with three entries compiles");

        let decoded = append_ospf_packet(Packet::new(), bytes.as_bytes())
            .expect("the Link State Request decodes");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        assert_eq!(ospf.packet_type_value(), OSPF_TYPE_LINK_STATE_REQUEST);

        let lsr = match &ospf.body {
            OspfBody::LinkStateRequest(lsr) => lsr,
            other => panic!("expected a typed Link State Request body, got {other:?}"),
        };

        // All three request triples are exposed, in order.
        let decoded_entries = lsr.entries_value();
        assert_eq!(decoded_entries.len(), 3);
        for (decoded_entry, expected) in decoded_entries.iter().zip(entries.iter()) {
            assert_eq!(decoded_entry, expected);
        }

        let recompiled = decoded
            .compile()
            .expect("decoded Link State Request re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// A Link State Request body whose length is 10 trailing octets (not a
    /// multiple of the 12-octet entry size) is a structured invalid-field error
    /// (`"ospf.link_state_request.entries"`), never a panic (RFC 2328 §A.3.4).
    #[test]
    fn ospf_decode_link_state_request_misaligned_entries_is_invalid_field() {
        // 10 trailing octets: not a multiple of the 12-octet entry size.
        let err = decode_link_state_request_body(&[0u8; 10])
            .expect_err("a 10-octet request body is not a multiple of 12");
        match err {
            CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "ospf.link_state_request.entries");
            }
            other => panic!("expected invalid_field_value, got {other:?}"),
        }
    }

    /// A Link State Acknowledgment built with three LSA headers, once compiled,
    /// decodes (type 5) into a typed Link State Acknowledgment body that exposes
    /// all three acknowledged LSA headers in order, and re-compiles
    /// byte-for-byte (RFC 2328 §A.3.6).
    #[test]
    fn ospf_decode_link_state_ack_with_three_lsa_headers_round_trips() {
        use crate::protocols::ospf::lsa::{
            OspfLsaHeader, OSPF_LSA_NETWORK, OSPF_LSA_ROUTER, OSPF_LSA_SUMMARY_IP,
        };
        use crate::protocols::ospf::OspfBody;

        let headers = [
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_ROUTER)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_NETWORK)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 2))
                .advertising_router(Ipv4Addr::new(198, 51, 100, 7))
                .ls_sequence_number(0x8000_0002),
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_SUMMARY_IP)
                .link_state_id(Ipv4Addr::new(198, 51, 100, 0))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 3))
                .ls_sequence_number(0x8000_0003),
        ];

        let bytes = Packet::from_layer(
            Ospfv2::link_state_ack()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0])
                .with_link_state_ack(|a| {
                    *a = a.clone().lsa_headers(headers.iter().cloned());
                }),
        )
        .compile()
        .expect("a Link State Acknowledgment with three LSA headers compiles");

        let decoded = append_ospf_packet(Packet::new(), bytes.as_bytes())
            .expect("the Link State Acknowledgment decodes");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        assert_eq!(ospf.packet_type_value(), OSPF_TYPE_LINK_STATE_ACK);

        let ack = match &ospf.body {
            OspfBody::LinkStateAck(ack) => ack,
            other => panic!("expected a typed Link State Acknowledgment body, got {other:?}"),
        };

        // All three acknowledged headers are exposed, in order, with their
        // decoded fields.
        let decoded_headers = ack.lsa_headers_value();
        assert_eq!(decoded_headers.len(), 3);
        for (decoded_header, expected) in decoded_headers.iter().zip(headers.iter()) {
            assert_eq!(decoded_header.ls_type_value(), expected.ls_type_value());
            assert_eq!(
                decoded_header.link_state_id_value(),
                expected.link_state_id_value()
            );
            assert_eq!(
                decoded_header.advertising_router_value(),
                expected.advertising_router_value()
            );
            assert_eq!(
                decoded_header.ls_sequence_number_value(),
                expected.ls_sequence_number_value()
            );
        }

        let recompiled = decoded
            .compile()
            .expect("decoded Link State Acknowledgment re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// A Link State Acknowledgment body of 30 octets (one full 20-octet LSA
    /// header plus 10 trailing octets) surfaces the structured truncation error
    /// `decode_lsa_headers` returns on the partial trailing header (context
    /// `"ospf lsa header"`), never a panic (RFC 2328 §A.3.6).
    #[test]
    fn ospf_decode_link_state_ack_partial_trailing_header_is_truncation_error() {
        use crate::protocols::ospf::lsa::OSPF_LSA_HEADER_LEN;

        // 30 octets: one full 20-octet header plus a 10-octet partial second.
        let body = [0u8; OSPF_LSA_HEADER_LEN + 10];
        let err = decode_link_state_ack_body(&body)
            .expect_err("a 30-octet ack body has a partial trailing LSA header");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ospf lsa header");
                assert_eq!(required, OSPF_LSA_HEADER_LEN);
                assert_eq!(available, 10);
            }
            other => panic!("expected buffer_too_short, got {other:?}"),
        }
    }

    /// A Link State Update built with two raw-body LSAs (both unmodeled LS
    /// types), once compiled, decodes (type 4) into a typed Link State Update
    /// body that exposes both LSAs with their raw bodies, and re-compiles
    /// byte-for-byte (RFC 2328 §A.3.5).
    #[test]
    fn ospf_decode_link_state_update_with_two_raw_lsas_round_trips() {
        use crate::protocols::ospf::lsa::{OspfLsa, OspfLsaBody, OspfLsaHeader};
        use crate::protocols::ospf::OspfBody;
        use crate::protocols::ospf::OSPF_TYPE_LINK_STATE_UPDATE;

        // Two unmodeled LS types so both bodies are preserved verbatim as `Raw`;
        // the Router-LSA type (1) and Network-LSA type (2) now decode typed and
        // are covered by the dedicated round-trip tests below.
        const OSPF_LSA_UNKNOWN_TYPE_A: u8 = 99;
        const OSPF_LSA_UNKNOWN_TYPE_B: u8 = 98;

        let first_body = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
        let second_body = [0x00, 0x11, 0x22, 0x33];

        let lsas = [
            OspfLsa::new(
                OspfLsaHeader::new()
                    .ls_type(OSPF_LSA_UNKNOWN_TYPE_A)
                    .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                    .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                    .ls_sequence_number(0x8000_0001),
                OspfLsaBody::Raw(first_body.to_vec()),
            ),
            OspfLsa::new(
                OspfLsaHeader::new()
                    .ls_type(OSPF_LSA_UNKNOWN_TYPE_B)
                    .link_state_id(Ipv4Addr::new(192, 0, 2, 2))
                    .advertising_router(Ipv4Addr::new(198, 51, 100, 7))
                    .ls_sequence_number(0x8000_0002),
                OspfLsaBody::Raw(second_body.to_vec()),
            ),
        ];

        let bytes = Packet::from_layer(
            Ospfv2::link_state_update()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0])
                .with_link_state_update(|u| {
                    *u = u.clone().lsas(lsas.iter().cloned());
                }),
        )
        .compile()
        .expect("a Link State Update with two raw LSAs compiles");

        let decoded = append_ospf_packet(Packet::new(), bytes.as_bytes())
            .expect("the Link State Update decodes");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        assert_eq!(ospf.packet_type_value(), OSPF_TYPE_LINK_STATE_UPDATE);

        let lsu = match &ospf.body {
            OspfBody::LinkStateUpdate(lsu) => lsu,
            other => panic!("expected a typed Link State Update body, got {other:?}"),
        };

        // The on-wire count and both LSAs are recovered, in order.
        assert_eq!(lsu.num_lsas_value(), 2);
        let decoded_lsas = lsu.lsas_value();
        assert_eq!(decoded_lsas.len(), 2);
        assert_eq!(decoded_lsas[0].header.ls_type_value(), OSPF_LSA_UNKNOWN_TYPE_A);
        assert_eq!(decoded_lsas[1].header.ls_type_value(), OSPF_LSA_UNKNOWN_TYPE_B);
        match &decoded_lsas[0].body {
            OspfLsaBody::Raw(raw) => assert_eq!(raw.as_slice(), first_body.as_slice()),
            other => panic!("expected a raw LSA body, got {other:?}"),
        }
        match &decoded_lsas[1].body {
            OspfLsaBody::Raw(raw) => assert_eq!(raw.as_slice(), second_body.as_slice()),
            other => panic!("expected a raw LSA body, got {other:?}"),
        }

        let recompiled = decoded
            .compile()
            .expect("decoded Link State Update re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// A Link State Update whose single LSA declares a `length` of 10 (below the
    /// 20-octet header minimum) is a structured invalid-field error
    /// (`"ospf.lsa.length"`), never a panic (RFC 2328 §A.3.5, §A.4.1).
    #[test]
    fn ospf_decode_link_state_update_lsa_length_below_minimum_is_invalid_field() {
        // 4-octet count (1 LSA) followed by a 20-octet header whose declared
        // length field (octets 18..20 of the header) is 10.
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&[0u8; OSPF_LSA_HEADER_LEN]);
        // The declared length sits at octets 18..20 of the LSA header, i.e.
        // octets 22..24 of the body (after the 4-octet count).
        let length_offset = OSPF_LSU_COUNT_LEN + (OSPF_LSA_HEADER_LEN - 2);
        body[length_offset..length_offset + 2].copy_from_slice(&10u16.to_be_bytes());

        let err = decode_link_state_update_body(&body)
            .expect_err("an LSA length of 10 is below the 20-octet header minimum");
        match err {
            CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "ospf.lsa.length");
            }
            other => panic!("expected invalid_field_value, got {other:?}"),
        }
    }

    /// A Link State Update whose single LSA declares a `length` larger than the
    /// bytes that remain is a structured truncation error (context
    /// `"ospf lsa"`), never a panic (RFC 2328 §A.3.5, §A.4.1).
    #[test]
    fn ospf_decode_link_state_update_lsa_length_beyond_buffer_is_truncation_error() {
        // 4-octet count (1 LSA) followed by exactly one 20-octet header (no
        // body) whose declared length field claims a 40-octet LSA. Only 20 LSA
        // octets remain, so the declared length runs past the buffer.
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&[0u8; OSPF_LSA_HEADER_LEN]);
        let length_offset = OSPF_LSU_COUNT_LEN + (OSPF_LSA_HEADER_LEN - 2);
        body[length_offset..length_offset + 2].copy_from_slice(&40u16.to_be_bytes());

        let err = decode_link_state_update_body(&body)
            .expect_err("a declared LSA length of 40 exceeds the 20 remaining octets");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ospf lsa");
                assert_eq!(required, 40);
                assert_eq!(available, OSPF_LSA_HEADER_LEN);
            }
            other => panic!("expected buffer_too_short, got {other:?}"),
        }
    }

    /// A Link State Update carrying a single Router-LSA (LS type 1) with two
    /// links — one of them with a per-TOS entry — once compiled, decodes (type 4)
    /// into a typed [`OspfLsaBody::Router`] body whose flags, `# links`, links,
    /// and per-TOS entries equal the built ones, and re-compiles byte-for-byte
    /// (RFC 2328 §A.3.5, §A.4.2).
    #[test]
    fn ospf_decode_link_state_update_router_lsa_two_links_round_trips() {
        use crate::protocols::ospf::lsa::{
            OspfLsa, OspfLsaBody, OspfLsaHeader, OspfRouterLink, OspfRouterLinkTos, OspfRouterLsa,
            OSPF_LSA_ROUTER, OSPF_ROUTER_LINK_POINT_TO_POINT, OSPF_ROUTER_LINK_STUB,
            OSPF_ROUTER_LSA_FLAG_B,
        };
        use crate::protocols::ospf::OspfBody;
        use crate::protocols::ospf::OSPF_TYPE_LINK_STATE_UPDATE;

        // Router-LSA: B flag set, link 1 point-to-point (no TOS), link 2 stub
        // with one per-TOS entry.
        let router = OspfRouterLsa::new()
            .border()
            .link(OspfRouterLink::new(
                Ipv4Addr::new(192, 0, 2, 2),
                Ipv4Addr::new(198, 51, 100, 1),
                OSPF_ROUTER_LINK_POINT_TO_POINT,
                10,
            ))
            .link(
                OspfRouterLink::new(
                    Ipv4Addr::new(198, 51, 100, 0),
                    Ipv4Addr::new(255, 255, 255, 0),
                    OSPF_ROUTER_LINK_STUB,
                    20,
                )
                .tos(OspfRouterLinkTos::new(2, 30)),
            );

        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_ROUTER)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaBody::Router(router),
        );

        let bytes = Packet::from_layer(
            Ospfv2::link_state_update()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0])
                .with_link_state_update(|u| {
                    *u = u.clone().lsa(lsa.clone());
                }),
        )
        .compile()
        .expect("a Link State Update with a Router-LSA compiles");

        let decoded = append_ospf_packet(Packet::new(), bytes.as_bytes())
            .expect("the Link State Update decodes");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        assert_eq!(ospf.packet_type_value(), OSPF_TYPE_LINK_STATE_UPDATE);

        let lsu = match &ospf.body {
            OspfBody::LinkStateUpdate(lsu) => lsu,
            other => panic!("expected a typed Link State Update body, got {other:?}"),
        };
        let decoded_lsas = lsu.lsas_value();
        assert_eq!(decoded_lsas.len(), 1);
        assert_eq!(decoded_lsas[0].header.ls_type_value(), OSPF_LSA_ROUTER);

        // The Router-LSA body decoded into a typed `Router` variant with both
        // links and the per-TOS entry recovered.
        let router = match &decoded_lsas[0].body {
            OspfLsaBody::Router(router) => router,
            other => panic!("expected a typed Router-LSA body, got {other:?}"),
        };
        assert_eq!(router.flags_value(), OSPF_ROUTER_LSA_FLAG_B);
        assert_eq!(router.num_links_value(), 2);

        let links = router.links_value();
        assert_eq!(links.len(), 2);

        // Link 1: point-to-point, metric 10, no per-TOS entries.
        assert_eq!(links[0].link_id_value(), Ipv4Addr::new(192, 0, 2, 2));
        assert_eq!(links[0].link_data_value(), Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(links[0].link_type_value(), OSPF_ROUTER_LINK_POINT_TO_POINT);
        assert_eq!(links[0].metric_value(), 10);
        assert!(links[0].tos_value().is_empty());

        // Link 2: stub, metric 20, one per-TOS entry (TOS 2, metric 30).
        assert_eq!(links[1].link_id_value(), Ipv4Addr::new(198, 51, 100, 0));
        assert_eq!(links[1].link_data_value(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(links[1].link_type_value(), OSPF_ROUTER_LINK_STUB);
        assert_eq!(links[1].metric_value(), 20);
        assert_eq!(links[1].tos_value().len(), 1);
        assert_eq!(links[1].tos_value()[0].tos_value(), 2);
        assert_eq!(links[1].tos_value()[0].metric_value(), 30);

        // The decoded Router-LSA re-compiles byte-for-byte.
        let recompiled = decoded
            .compile()
            .expect("decoded Link State Update re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// A Router-LSA whose declared `# links` count exceeds the bytes that remain
    /// is a structured truncation error (context `"ospf router-lsa link"`), never
    /// a panic (RFC 2328 §A.4.2).
    #[test]
    fn ospf_decode_link_state_update_router_lsa_too_many_links_is_truncation_error() {
        use crate::protocols::ospf::lsa::{OSPF_LSA_ROUTER, OSPF_ROUTER_LINK_POINT_TO_POINT};

        // Build the Router-LSA body by hand: flags 0, reserved 0, `# links` 2,
        // but only one full 12-octet link description follows.
        let mut router_body = Vec::new();
        router_body.extend_from_slice(&[0x00, 0x00]); // flags, reserved
        router_body.extend_from_slice(&2u16.to_be_bytes()); // # links = 2
        // One complete link: Link ID, Link Data, Type, # TOS 0, metric.
        router_body.extend_from_slice(&[192, 0, 2, 2]); // Link ID
        router_body.extend_from_slice(&[198, 51, 100, 1]); // Link Data
        router_body.push(OSPF_ROUTER_LINK_POINT_TO_POINT); // Type
        router_body.push(0); // # TOS
        router_body.extend_from_slice(&10u16.to_be_bytes()); // metric
        // No second link description, so the declared count of 2 runs past the
        // body.

        // 4-octet count (1 LSA) followed by a 20-octet header whose declared
        // length covers the header plus the Router body.
        let lsa_len = OSPF_LSA_HEADER_LEN + router_body.len();
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes());
        let mut header = vec![0u8; OSPF_LSA_HEADER_LEN];
        header[3] = OSPF_LSA_ROUTER; // LS type (octet 3 of the header)
        header[18..20].copy_from_slice(&(lsa_len as u16).to_be_bytes());
        body.extend_from_slice(&header);
        body.extend_from_slice(&router_body);

        let err = decode_link_state_update_body(&body)
            .expect_err("a Router-LSA declaring 2 links but carrying 1 must error");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ospf router-lsa link");
                assert_eq!(required, OSPF_ROUTER_LINK_FIXED_LEN);
                assert_eq!(available, 0);
            }
            other => panic!("expected buffer_too_short, got {other:?}"),
        }
    }

    /// A Link State Update carrying a single Network-LSA (LS type 2) with a
    /// network mask and two attached routers, once compiled, decodes (type 4)
    /// into a typed [`OspfLsaBody::Network`] body whose mask and attached-router
    /// list equal the built ones, and re-compiles byte-for-byte (RFC 2328
    /// §A.3.5, §A.4.3).
    #[test]
    fn ospf_decode_link_state_update_network_lsa_two_attached_routers_round_trips() {
        use crate::protocols::ospf::lsa::{
            OspfLsa, OspfLsaBody, OspfLsaHeader, OspfNetworkLsa, OSPF_LSA_NETWORK,
        };
        use crate::protocols::ospf::OspfBody;
        use crate::protocols::ospf::OSPF_TYPE_LINK_STATE_UPDATE;

        // Network-LSA: a /24 mask plus two attached Router IDs.
        let network = OspfNetworkLsa::new()
            .network_mask(Ipv4Addr::new(255, 255, 255, 0))
            .attached_router(Ipv4Addr::new(192, 0, 2, 1))
            .attached_router(Ipv4Addr::new(192, 0, 2, 2));

        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_NETWORK)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaBody::Network(network),
        );

        let bytes = Packet::from_layer(
            Ospfv2::link_state_update()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0])
                .with_link_state_update(|u| {
                    *u = u.clone().lsa(lsa.clone());
                }),
        )
        .compile()
        .expect("a Link State Update with a Network-LSA compiles");

        let decoded = append_ospf_packet(Packet::new(), bytes.as_bytes())
            .expect("the Link State Update decodes");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        assert_eq!(ospf.packet_type_value(), OSPF_TYPE_LINK_STATE_UPDATE);

        let lsu = match &ospf.body {
            OspfBody::LinkStateUpdate(lsu) => lsu,
            other => panic!("expected a typed Link State Update body, got {other:?}"),
        };
        let decoded_lsas = lsu.lsas_value();
        assert_eq!(decoded_lsas.len(), 1);
        assert_eq!(decoded_lsas[0].header.ls_type_value(), OSPF_LSA_NETWORK);

        // The Network-LSA body decoded into a typed `Network` variant with the
        // mask and both attached routers recovered, in order.
        let network = match &decoded_lsas[0].body {
            OspfLsaBody::Network(network) => network,
            other => panic!("expected a typed Network-LSA body, got {other:?}"),
        };
        assert_eq!(network.network_mask_value(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(
            network.attached_routers_value(),
            &[Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)]
        );

        // The decoded Network-LSA re-compiles byte-for-byte.
        let recompiled = decoded
            .compile()
            .expect("decoded Link State Update re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// A Network-LSA body of 10 octets — the 4-octet network mask plus a 6-octet
    /// attached-router region (not a multiple of 4) — is a structured
    /// invalid-field error (`"ospf.network_lsa.attached_routers"`), never a panic
    /// (RFC 2328 §A.4.3).
    #[test]
    fn ospf_decode_network_lsa_misaligned_attached_routers_is_invalid_field() {
        // 4 mask octets plus 6 trailing octets: a malformed attached-router list.
        let body = [0u8; OSPF_NETWORK_LSA_MASK_LEN + 6];
        let err = decode_network_lsa_body(&body)
            .expect_err("a 6-octet attached-router region is not a multiple of 4");
        match err {
            CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "ospf.network_lsa.attached_routers");
            }
            other => panic!("expected invalid_field_value, got {other:?}"),
        }
    }

    /// A Link State Update carrying a single type 3 Summary-LSA with a network
    /// mask and two TOS/metric entries, once compiled, decodes (type 4) into a
    /// typed [`OspfLsaBody::Summary`] body whose mask and entries equal the built
    /// ones, and re-compiles byte-for-byte (RFC 2328 §A.3.5, §A.4.4).
    #[test]
    fn ospf_decode_link_state_update_summary_lsa_two_entries_round_trips() {
        use crate::protocols::ospf::lsa::{
            OspfLsa, OspfLsaBody, OspfLsaHeader, OspfSummaryLsa, OSPF_LSA_SUMMARY_IP,
        };
        use crate::protocols::ospf::OspfBody;
        use crate::protocols::ospf::OSPF_TYPE_LINK_STATE_UPDATE;

        // Summary-LSA: a /24 mask, the mandatory TOS 0 metric, plus a second
        // TOS/metric entry. 0x0a0b0c exercises all three metric octets.
        let summary = OspfSummaryLsa::new()
            .network_mask(Ipv4Addr::new(255, 255, 255, 0))
            .metric(10)
            .tos_entry(2, 0x000a_0b0c);

        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_SUMMARY_IP)
                .link_state_id(Ipv4Addr::new(198, 51, 100, 0))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaBody::Summary(summary),
        );

        let bytes = Packet::from_layer(
            Ospfv2::link_state_update()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0])
                .with_link_state_update(|u| {
                    *u = u.clone().lsa(lsa.clone());
                }),
        )
        .compile()
        .expect("a Link State Update with a Summary-LSA compiles");

        let decoded = append_ospf_packet(Packet::new(), bytes.as_bytes())
            .expect("the Link State Update decodes");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        assert_eq!(ospf.packet_type_value(), OSPF_TYPE_LINK_STATE_UPDATE);

        let lsu = match &ospf.body {
            OspfBody::LinkStateUpdate(lsu) => lsu,
            other => panic!("expected a typed Link State Update body, got {other:?}"),
        };
        let decoded_lsas = lsu.lsas_value();
        assert_eq!(decoded_lsas.len(), 1);
        assert_eq!(decoded_lsas[0].header.ls_type_value(), OSPF_LSA_SUMMARY_IP);

        // The Summary-LSA body decoded into a typed `Summary` variant with the
        // mask and both TOS/metric entries recovered, in order, including the
        // 24-bit metric.
        let summary = match &decoded_lsas[0].body {
            OspfLsaBody::Summary(summary) => summary,
            other => panic!("expected a typed Summary-LSA body, got {other:?}"),
        };
        assert_eq!(summary.network_mask_value(), Ipv4Addr::new(255, 255, 255, 0));
        let entries = summary.entries_value();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].tos_value(), 0);
        assert_eq!(entries[0].metric_value(), 10);
        assert_eq!(entries[1].tos_value(), 2);
        assert_eq!(entries[1].metric_value(), 0x000a_0b0c);

        // The decoded Summary-LSA re-compiles byte-for-byte.
        let recompiled = decoded
            .compile()
            .expect("decoded Link State Update re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// A Link State Update carrying a single type 4 Summary-LSA (AS boundary
    /// router) with a zero network mask and a TOS 0 metric, once compiled,
    /// decodes (type 4) into a typed [`OspfLsaBody::Summary`] body and re-compiles
    /// byte-for-byte (RFC 2328 §A.3.5, §A.4.4).
    #[test]
    fn ospf_decode_link_state_update_summary_asbr_lsa_round_trips() {
        use crate::protocols::ospf::lsa::{
            OspfLsa, OspfLsaBody, OspfLsaHeader, OspfSummaryLsa, OSPF_LSA_SUMMARY_ASBR,
        };
        use crate::protocols::ospf::OspfBody;
        use crate::protocols::ospf::OSPF_TYPE_LINK_STATE_UPDATE;

        // A type 4 Summary-LSA: the Network Mask is not meaningful and is zero;
        // the body carries the mandatory TOS 0 metric.
        let summary = OspfSummaryLsa::new()
            .network_mask(Ipv4Addr::UNSPECIFIED)
            .metric(42);

        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_SUMMARY_ASBR)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 9))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaBody::Summary(summary),
        );

        let bytes = Packet::from_layer(
            Ospfv2::link_state_update()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0])
                .with_link_state_update(|u| {
                    *u = u.clone().lsa(lsa.clone());
                }),
        )
        .compile()
        .expect("a Link State Update with a type 4 Summary-LSA compiles");

        let decoded = append_ospf_packet(Packet::new(), bytes.as_bytes())
            .expect("the Link State Update decodes");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        assert_eq!(ospf.packet_type_value(), OSPF_TYPE_LINK_STATE_UPDATE);

        let lsu = match &ospf.body {
            OspfBody::LinkStateUpdate(lsu) => lsu,
            other => panic!("expected a typed Link State Update body, got {other:?}"),
        };
        let decoded_lsas = lsu.lsas_value();
        assert_eq!(decoded_lsas.len(), 1);
        assert_eq!(decoded_lsas[0].header.ls_type_value(), OSPF_LSA_SUMMARY_ASBR);

        let summary = match &decoded_lsas[0].body {
            OspfLsaBody::Summary(summary) => summary,
            other => panic!("expected a typed Summary-LSA body, got {other:?}"),
        };
        assert_eq!(summary.network_mask_value(), Ipv4Addr::UNSPECIFIED);
        let entries = summary.entries_value();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tos_value(), 0);
        assert_eq!(entries[0].metric_value(), 42);

        let recompiled = decoded
            .compile()
            .expect("decoded Link State Update re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// A Summary-LSA body of 10 octets — the 4-octet network mask plus a 6-octet
    /// TOS/metric region (not a multiple of 4, a trailing partial entry) — is a
    /// structured invalid-field error (`"ospf.summary_lsa.entries"`), never a
    /// panic (RFC 2328 §A.4.4).
    #[test]
    fn ospf_decode_summary_lsa_trailing_partial_entry_is_invalid_field() {
        // 4 mask octets plus 6 trailing octets: one full 4-octet TOS/metric entry
        // followed by a 2-octet partial second entry.
        let body = [0u8; OSPF_SUMMARY_LSA_MASK_LEN + 6];
        let err = decode_summary_lsa_body(&body)
            .expect_err("a 6-octet TOS/metric region is not a multiple of 4");
        match err {
            CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "ospf.summary_lsa.entries");
            }
            other => panic!("expected invalid_field_value, got {other:?}"),
        }
    }

    /// A Link State Update carrying a single AS-External-LSA (LS type 5) with a
    /// network mask and one E2 external metric entry (a non-zero forwarding
    /// address and route tag), once compiled, decodes (type 4) into a typed
    /// [`OspfLsaBody::AsExternal`] body whose mask, E bit, metric, forwarding
    /// address, and route tag equal the built ones, and re-compiles byte-for-byte
    /// (RFC 2328 §A.3.5, §A.4.5).
    #[test]
    fn ospf_decode_link_state_update_as_external_lsa_round_trips() {
        use crate::protocols::ospf::lsa::{
            OspfAsExternalLsa, OspfLsa, OspfLsaBody, OspfLsaHeader, OSPF_LSA_AS_EXTERNAL,
        };
        use crate::protocols::ospf::OspfBody;
        use crate::protocols::ospf::OSPF_TYPE_LINK_STATE_UPDATE;

        // AS-External-LSA: a /24 mask. `OspfAsExternalLsa::new()` seeds the
        // mandatory default TOS 0 entry (E1, metric 0, unspecified forwarding
        // address, route tag 0); `external_entry(..)` appends a second E2 entry
        // (0x0a0b0c exercises all three metric octets) with a non-zero forwarding
        // address and external route tag set explicitly. The round-trip exercises
        // the E bit and the forwarding address on the appended entry.
        let external = OspfAsExternalLsa::new()
            .network_mask(Ipv4Addr::new(255, 255, 255, 0))
            .external_entry(
                true,
                5,
                0x000a_0b0c,
                Ipv4Addr::new(192, 0, 2, 9),
                0x1234_5678,
            );

        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_AS_EXTERNAL)
                .link_state_id(Ipv4Addr::new(198, 51, 100, 0))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaBody::AsExternal(external),
        );

        let bytes = Packet::from_layer(
            Ospfv2::link_state_update()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0])
                .with_link_state_update(|u| {
                    *u = u.clone().lsa(lsa.clone());
                }),
        )
        .compile()
        .expect("a Link State Update with an AS-External-LSA compiles");

        let decoded = append_ospf_packet(Packet::new(), bytes.as_bytes())
            .expect("the Link State Update decodes");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        assert_eq!(ospf.packet_type_value(), OSPF_TYPE_LINK_STATE_UPDATE);

        let lsu = match &ospf.body {
            OspfBody::LinkStateUpdate(lsu) => lsu,
            other => panic!("expected a typed Link State Update body, got {other:?}"),
        };
        let decoded_lsas = lsu.lsas_value();
        assert_eq!(decoded_lsas.len(), 1);
        assert_eq!(decoded_lsas[0].header.ls_type_value(), OSPF_LSA_AS_EXTERNAL);

        // The AS-External-LSA body decoded into a typed `AsExternal` variant with
        // the mask and both external metric entries recovered, in order: the
        // mandatory default TOS 0 entry (E1) followed by the appended E2 entry,
        // which exposes the E bit and the forwarding address.
        let external = match &decoded_lsas[0].body {
            OspfLsaBody::AsExternal(external) => external,
            other => panic!("expected a typed AS-External-LSA body, got {other:?}"),
        };
        assert_eq!(external.network_mask_value(), Ipv4Addr::new(255, 255, 255, 0));
        let entries = external.entries_value();
        assert_eq!(entries.len(), 2);
        // The default TOS 0 entry: E1, metric 0, unspecified forwarding address.
        assert!(!entries[0].e_bit_value());
        assert_eq!(entries[0].tos_value(), 0);
        assert_eq!(entries[0].metric_value(), 0);
        assert_eq!(
            entries[0].forwarding_address_value(),
            Ipv4Addr::UNSPECIFIED
        );
        assert_eq!(entries[0].external_route_tag_value(), 0);
        // The appended entry exposes the E bit (E2), TOS, metric, forwarding
        // address, and route tag.
        assert!(entries[1].e_bit_value());
        assert_eq!(entries[1].tos_value(), 5);
        assert_eq!(entries[1].metric_value(), 0x000a_0b0c);
        assert_eq!(
            entries[1].forwarding_address_value(),
            Ipv4Addr::new(192, 0, 2, 9)
        );
        assert_eq!(entries[1].external_route_tag_value(), 0x1234_5678);

        // The decoded AS-External-LSA re-compiles byte-for-byte.
        let recompiled = decoded
            .compile()
            .expect("decoded Link State Update re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// An AS-External-LSA body of 18 octets — the 4-octet network mask plus a
    /// 14-octet external-metric region (not a multiple of 12, a trailing partial
    /// entry) — is a structured invalid-field error
    /// (`"ospf.as_external_lsa.entries"`), never a panic (RFC 2328 §A.4.5).
    #[test]
    fn ospf_decode_as_external_lsa_trailing_partial_entry_is_invalid_field() {
        // 4 mask octets plus 14 trailing octets: one full 12-octet external
        // metric entry followed by a 2-octet partial second entry.
        let body = [0u8; OSPF_AS_EXTERNAL_LSA_MASK_LEN + 14];
        let err = decode_as_external_lsa_body(&body)
            .expect_err("a 14-octet external-metric region is not a multiple of 12");
        match err {
            CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "ospf.as_external_lsa.entries");
            }
            other => panic!("expected invalid_field_value, got {other:?}"),
        }
    }
}
