//! OSPFv3 (RFC 5340) decode entrypoints.
//!
//! OSPFv3 runs directly over IPv6 (next header 89, RFC 5340 §2.5). The decoder
//! mirrors the OSPFv2 path (`crate::protocols::ospf::decode`): a buffer too
//! short for the 16-octet common header surfaces a typed
//! [`CrafterError::BufferTooShort`] carrying `context`, `required`, and
//! `available` — never a panic and never a half-read field.
//!
//! This block parses the 16-octet common header (RFC 5340 §A.3.1) and dispatches
//! the body by packet Type (RFC 5340 §A.3): Hello, Database Description, Link
//! State Request, Link State Update, and Link State Acknowledgment parse into
//! typed [`Ospfv3Body`] variants; everything else is preserved verbatim in
//! [`Ospfv3Body::Unknown`] so it round-trips byte-for-byte. The Link State
//! Update parses each v3 LSA by its 20-octet header (RFC 5340 §A.4.2),
//! dispatching the Router-LSA (LS type function code 1) and Network-LSA (function
//! code 2) bodies and preserving every other LS type as [`Ospfv3LsaBody::Raw`].
//! Every recovered header field is marked user-set (`Field::user(...)`) so a
//! decoded packet re-compiles to the same bytes.
//!
//! The OSPFv3 checksum is the IPv6 upper-layer checksum (RFC 5340 §2.7, the same
//! computation UDP and ICMPv6 use). When `validate_checksum` is enabled and the
//! enclosing IPv6 layer is in scope on the packet stack (so its pseudo-header is
//! recoverable, exactly as the compile-side checksum auto-fill does), the
//! checksum is recomputed over the OSPFv3 packet with the checksum field zeroed
//! and compared to record an [`OspfChecksumStatus`]. When validation is disabled,
//! or no enclosing IPv6 pseudo-header is available at this decode boundary, the
//! status is [`OspfChecksumStatus::NotChecked`]. This status is decode metadata
//! only and never affects the re-compiled bytes.

use core::net::Ipv4Addr;

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::Packet;
use crate::protocols::ip::shared::IPPROTO_OSPF;
use crate::protocols::ospf::OspfChecksumStatus;

use super::constants::{
    OSPFV3_HEADER_LEN, OSPFV3_TYPE_DATABASE_DESCRIPTION, OSPFV3_TYPE_HELLO,
    OSPFV3_TYPE_LINK_STATE_ACK, OSPFV3_TYPE_LINK_STATE_REQUEST, OSPFV3_TYPE_LINK_STATE_UPDATE,
};
use super::hello::Ospfv3Hello;
use super::lsa::{
    decode_ospfv3_lsa_headers, Ospfv3LinkStateUpdate, Ospfv3Lsa, Ospfv3LsaBody, Ospfv3LsaHeader,
    Ospfv3NetworkLsa, Ospfv3RouterInterface, Ospfv3RouterLsa, OSPFV3_LSA_HEADER_LEN,
};
use super::packet::{
    Ospfv3DatabaseDescription, Ospfv3LinkStateAck, Ospfv3LinkStateRequest,
    Ospfv3LinkStateRequestEntry,
};
use super::{Ospfv3, Ospfv3Body};

/// OSPFv3 Router-LSA LS type (RFC 5340 §A.4.2.1 / §A.4.3): function code 1 with
/// the U-bit clear and area scope, i.e. `0x2001`.
const OSPFV3_LSA_ROUTER: u16 = 0x2001;

/// OSPFv3 Network-LSA LS type (RFC 5340 §A.4.2.1 / §A.4.4): function code 2 with
/// the U-bit clear and area scope, i.e. `0x2002`.
const OSPFV3_LSA_NETWORK: u16 = 0x2002;

/// The fixed (pre-neighbor-list) length of the OSPFv3 Hello body, in octets
/// (RFC 5340 §A.3.2): Interface ID(4) + Rtr Priority(1) + Options(3) +
/// HelloInterval(2) + RouterDeadInterval(2) + Designated Router ID(4) + Backup
/// Designated Router ID(4).
const OSPFV3_HELLO_FIXED_LEN: usize = 20;

/// The fixed (pre-LSA-header-list) length of the OSPFv3 Database Description
/// body, in octets (RFC 5340 §A.3.3): Reserved(1) + Options(3) + Interface
/// MTU(2) + Reserved(1) + flags(1) + DD sequence number(4).
const OSPFV3_DD_FIXED_LEN: usize = 12;

/// The on-wire length of a single OSPFv3 Link State Request entry, in octets
/// (RFC 5340 §A.3.4): Reserved(2) + LS type(2) + Link State ID(4) + Advertising
/// Router(4).
const OSPFV3_LSR_ENTRY_LEN: usize = 12;

/// The on-wire length of the OSPFv3 Link State Update `# LSAs` count field, in
/// octets (RFC 5340 §A.3.5).
const OSPFV3_LSU_COUNT_LEN: usize = 4;

/// The fixed (pre-interface-list) length of the OSPFv3 Router-LSA body, in
/// octets (RFC 5340 §A.4.3): flags(1) + Options(3).
const OSPFV3_ROUTER_LSA_FIXED_LEN: usize = 4;

/// The on-wire length of a single OSPFv3 Router-LSA interface description, in
/// octets (RFC 5340 §A.4.3): Type(1) + Reserved(1) + Metric(2) + Interface ID(4)
/// + Neighbor Interface ID(4) + Neighbor Router ID(4).
const OSPFV3_ROUTER_LSA_INTERFACE_LEN: usize = 16;

/// The fixed (pre-router-list) length of the OSPFv3 Network-LSA body, in octets
/// (RFC 5340 §A.4.4): Reserved(1) + Options(3).
const OSPFV3_NETWORK_LSA_FIXED_LEN: usize = 4;

/// The on-wire length of a single OSPFv3 Network-LSA attached Router ID, in
/// octets (RFC 5340 §A.4.4).
const OSPFV3_NETWORK_LSA_ROUTER_LEN: usize = 4;

/// Offset of the OSPFv3 Checksum field within the common header, in octets
/// (RFC 5340 §A.3.1).
const OSPFV3_CHECKSUM_OFFSET: usize = 12;

/// Append a decoded OSPFv3 packet to an existing packet stack.
///
/// Delegates to [`append_ospfv3_packet_with_checksum_validation`] with checksum
/// validation enabled. The registry hands the actual checksum-validation policy;
/// this convenience entrypoint is used by tests and decode helpers.
#[allow(dead_code)]
pub(crate) fn append_ospfv3_packet(packet: Packet, bytes: &[u8]) -> Result<Packet> {
    append_ospfv3_packet_with_checksum_validation(packet, bytes, true)
}

/// Parse the OSPFv3 common header (RFC 5340 §A.3.1) and push a typed [`Ospfv3`]
/// layer onto `packet`, dispatching the body by packet Type.
///
/// The 16-octet common header is Version(1), Type(1), Packet Length(2),
/// Router ID(4), Area ID(4), Checksum(2), Instance ID(1), Reserved(1). A buffer
/// shorter than [`OSPFV3_HEADER_LEN`] is a structured truncation error
/// (context `"ospfv3 header"`) rather than a panic.
///
/// The body is the octets after the header. The declared Packet Length bounds the
/// body when it is sane (within `[OSPFV3_HEADER_LEN, bytes.len()]`); otherwise the
/// remaining bytes are used so a malformed length never drops bytes or reads out
/// of bounds. Recognized packet types parse into a typed [`Ospfv3Body`]; every
/// other type is preserved verbatim in [`Ospfv3Body::Unknown`].
///
/// Every recovered field is marked user-set so the decoded packet re-compiles
/// byte-for-byte. When `validate_checksum` is true and the enclosing IPv6
/// pseudo-header is recoverable from the already-pushed layers (mirroring the
/// compile-side `Ospfv3::checksum_context` and the UDP/ICMPv6 path), the IPv6
/// upper-layer checksum (RFC 5340 §2.7) is recomputed over the OSPFv3 packet with
/// the checksum field zeroed and compared to record an [`OspfChecksumStatus`];
/// otherwise the status is [`OspfChecksumStatus::NotChecked`].
pub(crate) fn append_ospfv3_packet_with_checksum_validation(
    mut packet: Packet,
    bytes: &[u8],
    validate_checksum: bool,
) -> Result<Packet> {
    if bytes.len() < OSPFV3_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ospfv3 header",
            OSPFV3_HEADER_LEN,
            bytes.len(),
        ));
    }

    // Common header (RFC 5340 §A.3.1), read from fixed offsets. The length check
    // above guarantees every slice below is in bounds, so this cannot panic.
    let version = bytes[0];
    let packet_type = bytes[1];
    let packet_length = u16::from_be_bytes([bytes[2], bytes[3]]);
    let router_id = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
    let area_id = Ipv4Addr::new(bytes[8], bytes[9], bytes[10], bytes[11]);
    let checksum = u16::from_be_bytes([bytes[12], bytes[13]]);
    let instance_id = bytes[14];
    let reserved = bytes[15];

    // The body follows the 16-octet header. Prefer the declared Packet Length
    // when it is within [OSPFV3_HEADER_LEN, bytes.len()]; otherwise fall back to
    // the remaining bytes so a malformed length neither overruns the buffer nor
    // discards trailing octets.
    let declared = packet_length as usize;
    let body_end = if (OSPFV3_HEADER_LEN..=bytes.len()).contains(&declared) {
        declared
    } else {
        bytes.len()
    };
    let body_bytes = &bytes[OSPFV3_HEADER_LEN..body_end];

    // Dispatch the body by packet Type (RFC 5340 §A.3), mirroring the OSPFv2
    // decoder. Recognized types parse into a typed `Ospfv3Body`; everything else
    // is preserved verbatim in `Ospfv3Body::Unknown` so it round-trips
    // byte-for-byte.
    let body = match packet_type {
        OSPFV3_TYPE_HELLO => Ospfv3Body::Hello(decode_ospfv3_hello(body_bytes)?),
        OSPFV3_TYPE_DATABASE_DESCRIPTION => {
            Ospfv3Body::DatabaseDescription(decode_ospfv3_database_description(body_bytes)?)
        }
        OSPFV3_TYPE_LINK_STATE_REQUEST => {
            Ospfv3Body::LinkStateRequest(decode_ospfv3_link_state_request(body_bytes)?)
        }
        OSPFV3_TYPE_LINK_STATE_UPDATE => {
            Ospfv3Body::LinkStateUpdate(decode_ospfv3_link_state_update(body_bytes)?)
        }
        OSPFV3_TYPE_LINK_STATE_ACK => {
            Ospfv3Body::LinkStateAck(decode_ospfv3_link_state_ack(body_bytes)?)
        }
        other => Ospfv3Body::Unknown {
            type_code: other,
            body: body_bytes.to_vec(),
        },
    };

    // Decode-time IPv6 upper-layer checksum status (RFC 5340 §2.7). The OSPFv3
    // checksum is the standard IPv6 upper-layer checksum, so validation needs the
    // enclosing IPv6 pseudo-header. The IPv6 layer is already pushed onto `packet`
    // before this next-header dispatch runs, so its pseudo-header is recoverable
    // exactly as the compile-side `Ospfv3::checksum_context` recovers it. When the
    // pseudo-header is available and validation is enabled, recompute over the
    // OSPFv3 packet with the checksum field (octets 12..14) zeroed and compare.
    // Otherwise (validation disabled, or no enclosing IPv6 layer) the status is
    // NotChecked.
    let checksum_status = if validate_checksum {
        match ipv6_pseudo_header(&packet) {
            Some(pseudo_header) => {
                // Recompute over the declared/bounded OSPFv3 extent with the
                // checksum field zeroed, matching how `compile()` forms it.
                let mut zeroed = bytes[..body_end].to_vec();
                zeroed[OSPFV3_CHECKSUM_OFFSET] = 0;
                zeroed[OSPFV3_CHECKSUM_OFFSET + 1] = 0;
                let computed = pseudo_header.checksum(&zeroed);
                if computed == checksum {
                    OspfChecksumStatus::Valid
                } else {
                    OspfChecksumStatus::Invalid
                }
            }
            None => OspfChecksumStatus::NotChecked,
        }
    } else {
        OspfChecksumStatus::NotChecked
    };

    let ospfv3 = Ospfv3 {
        version: Field::user(version),
        packet_type: Field::user(packet_type),
        packet_length: Field::user(packet_length),
        router_id: Field::user(router_id),
        area_id: Field::user(area_id),
        checksum: Field::user(checksum),
        instance_id: Field::user(instance_id),
        reserved: Field::user(reserved),
        body,
        checksum_status,
    };

    packet = packet.push(ospfv3);
    Ok(packet)
}

/// Recover the enclosing IPv6 pseudo-header (next-header 89) for the OSPFv3
/// upper-layer checksum from the already-pushed layers of `packet`, walking from
/// the innermost layer outward toward the network header — the same recovery the
/// compile-side `Ospfv3::checksum_context` and the UDP/ICMPv6 checksum paths use.
///
/// Returns `None` when no enclosing IPv6 layer is present (for example a bare
/// OSPFv3 payload decoded without an IPv6 header), in which case decode-time
/// checksum validation reports [`OspfChecksumStatus::NotChecked`].
fn ipv6_pseudo_header(packet: &Packet) -> Option<crate::packet::TransportChecksumContext> {
    (0..packet.len()).rev().find_map(|index| {
        packet
            .get(index)
            .and_then(|layer| layer.transport_checksum_context(IPPROTO_OSPF))
    })
}

/// Parse the OSPFv3 Hello body (RFC 5340 §A.3.2) from `body` into an
/// [`Ospfv3Hello`].
///
/// The Hello body is a fixed 20 octets — Interface ID(4), Rtr Priority(1),
/// Options(3, a 24-bit field), HelloInterval(2), RouterDeadInterval(2),
/// Designated Router ID(4), Backup Designated Router ID(4) — followed by zero or
/// more 4-octet neighbor Router IDs.
///
/// A buffer shorter than the fixed 20 octets is a structured truncation error
/// (context `"ospfv3 hello"`); a neighbor region whose length is not a multiple of
/// 4 is a structured [`CrafterError::invalid_field_value`]
/// (`"ospfv3.hello.neighbors"`). Every recovered field is marked user-set so the
/// decoded body re-compiles byte-for-byte.
fn decode_ospfv3_hello(body: &[u8]) -> Result<Ospfv3Hello> {
    if body.len() < OSPFV3_HELLO_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ospfv3 hello",
            OSPFV3_HELLO_FIXED_LEN,
            body.len(),
        ));
    }

    let interface_id = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let router_priority = body[4];
    // Options is a 24-bit field carried in three octets after the Router Priority.
    let options = (u32::from(body[5]) << 16) | (u32::from(body[6]) << 8) | u32::from(body[7]);
    let hello_interval = u16::from_be_bytes([body[8], body[9]]);
    let router_dead_interval = u16::from_be_bytes([body[10], body[11]]);
    let designated_router = Ipv4Addr::new(body[12], body[13], body[14], body[15]);
    let backup_designated_router = Ipv4Addr::new(body[16], body[17], body[18], body[19]);

    // The remaining octets are the neighbor list: zero or more 4-octet Router
    // IDs. A region not a multiple of 4 is a malformed body, not a truncation.
    let neighbor_region = &body[OSPFV3_HELLO_FIXED_LEN..];
    if neighbor_region.len() % 4 != 0 {
        return Err(CrafterError::invalid_field_value(
            "ospfv3.hello.neighbors",
            "neighbor list length must be a multiple of 4",
        ));
    }
    let neighbors: Vec<Ipv4Addr> = neighbor_region
        .chunks_exact(4)
        .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
        .collect();

    Ok(Ospfv3Hello::new()
        .interface_id(interface_id)
        .router_priority(router_priority)
        .options(options)
        .hello_interval(hello_interval)
        .router_dead_interval(router_dead_interval)
        .designated_router(designated_router)
        .backup_designated_router(backup_designated_router)
        .neighbors(neighbors))
}

/// Parse the OSPFv3 Database Description body (RFC 5340 §A.3.3) from `body` into
/// an [`Ospfv3DatabaseDescription`].
///
/// The body is a fixed 12 octets — Reserved(1), Options(3), Interface MTU(2),
/// Reserved(1), flags(1), DD sequence number(4) — followed by a list of bare
/// 20-octet [`Ospfv3LsaHeader`] records.
///
/// A buffer shorter than the fixed 12 octets is a structured truncation error
/// (context `"ospfv3 database description"`); the trailing LSA-header list is
/// parsed by [`decode_ospfv3_lsa_headers`], which surfaces a structured truncation
/// error for a partial trailing header. Every recovered field is marked user-set
/// so the decoded body re-compiles byte-for-byte.
fn decode_ospfv3_database_description(body: &[u8]) -> Result<Ospfv3DatabaseDescription> {
    if body.len() < OSPFV3_DD_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ospfv3 database description",
            OSPFV3_DD_FIXED_LEN,
            body.len(),
        ));
    }

    let reserved1 = body[0];
    let options = (u32::from(body[1]) << 16) | (u32::from(body[2]) << 8) | u32::from(body[3]);
    let interface_mtu = u16::from_be_bytes([body[4], body[5]]);
    let reserved2 = body[6];
    let flags = body[7];
    let dd_sequence_number = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);

    // The remaining octets are the LSA-header list (RFC 5340 §A.4.2): zero or
    // more bare 20-octet headers, parsed by the shared list helper.
    let lsa_headers = decode_ospfv3_lsa_headers(&body[OSPFV3_DD_FIXED_LEN..])?;

    Ok(Ospfv3DatabaseDescription::new()
        .reserved1(reserved1)
        .options(options)
        .interface_mtu(interface_mtu)
        .reserved2(reserved2)
        .flags(flags)
        .dd_sequence_number(dd_sequence_number)
        .lsa_headers(lsa_headers))
}

/// Parse the OSPFv3 Link State Request body (RFC 5340 §A.3.4) from `body` into an
/// [`Ospfv3LinkStateRequest`].
///
/// The body is zero or more 12-octet entries — Reserved(2), LS type(2), Link
/// State ID(4), Advertising Router(4) — with no fixed prefix; an empty request
/// list is legal. Unlike the OSPFv2 request entry (RFC 2328 §A.3.4) the LS type is
/// a 16-bit field carried after the 2-octet Reserved field.
///
/// A body whose length is not a multiple of 12 is a structured
/// [`CrafterError::invalid_field_value`] (`"ospfv3.link_state_request.entries"`),
/// never a panic. The decoded entries re-compile byte-for-byte (the 2-octet
/// Reserved field is emitted as zero, matching well-formed requests).
fn decode_ospfv3_link_state_request(body: &[u8]) -> Result<Ospfv3LinkStateRequest> {
    if body.len() % OSPFV3_LSR_ENTRY_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            "ospfv3.link_state_request.entries",
            "request list length must be a multiple of 12",
        ));
    }

    // Each 12-octet chunk is Reserved(2), LS type(2), Link State ID(4),
    // Advertising Router(4), big-endian. The exact-multiple check above keeps
    // every chunk full, so this cannot panic.
    let entries: Vec<Ospfv3LinkStateRequestEntry> = body
        .chunks_exact(OSPFV3_LSR_ENTRY_LEN)
        .map(|chunk| {
            let ls_type = u16::from_be_bytes([chunk[2], chunk[3]]);
            let link_state_id = Ipv4Addr::new(chunk[4], chunk[5], chunk[6], chunk[7]);
            let advertising_router = Ipv4Addr::new(chunk[8], chunk[9], chunk[10], chunk[11]);
            Ospfv3LinkStateRequestEntry::new(ls_type, link_state_id, advertising_router)
        })
        .collect();

    Ok(Ospfv3LinkStateRequest::new().requests(entries))
}

/// Parse the OSPFv3 Link State Acknowledgment body (RFC 5340 §A.3.6) from `body`
/// into an [`Ospfv3LinkStateAck`].
///
/// The body has no fixed prefix: it is just the concatenation of bare 20-octet
/// [`Ospfv3LsaHeader`] records (RFC 5340 §A.4.2), parsed by
/// [`decode_ospfv3_lsa_headers`]. An empty list is legal; a partial trailing
/// header surfaces the structured truncation error that helper returns rather than
/// a panic. Every recovered field is marked user-set so the decoded body
/// re-compiles byte-for-byte.
fn decode_ospfv3_link_state_ack(body: &[u8]) -> Result<Ospfv3LinkStateAck> {
    let lsa_headers = decode_ospfv3_lsa_headers(body)?;
    Ok(Ospfv3LinkStateAck::new().lsa_headers(lsa_headers))
}

/// Parse the OSPFv3 Link State Update body (RFC 5340 §A.3.5) from `body` into an
/// [`Ospfv3LinkStateUpdate`].
///
/// The body is a 4-octet `# LSAs` count followed by that many complete OSPFv3
/// LSAs. Each LSA is a 20-octet header (RFC 5340 §A.4.2, decoded by
/// [`Ospfv3LsaHeader::decode`]) plus a body of `length - 20` octets, where
/// `length` is the LSA header's declared length field. The Router-LSA
/// (`0x2001`) and Network-LSA (`0x2002`) bodies parse into typed
/// [`Ospfv3LsaBody`] variants; every other LS type is preserved verbatim as
/// [`Ospfv3LsaBody::Raw`] so the update round-trips byte-for-byte.
///
/// A buffer shorter than the 4-octet count is a structured truncation error
/// (context `"ospfv3 link state update"`). A declared LSA `length` below the
/// 20-octet header minimum is a structured [`CrafterError::invalid_field_value`]
/// (`"ospfv3.lsa.length"`); a `length` beyond the remaining bytes is a structured
/// truncation error (context `"ospfv3 lsa"`). The on-wire `# LSAs` count is
/// recovered and pinned so the update re-compiles byte-for-byte even when the
/// declared count disagrees with the number of parsed LSAs.
fn decode_ospfv3_link_state_update(body: &[u8]) -> Result<Ospfv3LinkStateUpdate> {
    if body.len() < OSPFV3_LSU_COUNT_LEN {
        return Err(CrafterError::buffer_too_short(
            "ospfv3 link state update",
            OSPFV3_LSU_COUNT_LEN,
            body.len(),
        ));
    }

    // The `# LSAs` count (octets 0..4). The length check above keeps this slice
    // in bounds, so it cannot panic.
    let num_lsas = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);

    // The LSAs follow the count. Parse one LSA per iteration, advancing by each
    // LSA's declared `length` field, until the slice is exhausted or the declared
    // count is reached.
    let mut rest = &body[OSPFV3_LSU_COUNT_LEN..];
    let mut lsas: Vec<Ospfv3Lsa> = Vec::with_capacity(num_lsas as usize);
    let mut parsed: u64 = 0;
    while !rest.is_empty() && parsed < u64::from(num_lsas) {
        // Decode the 20-octet header and read its declared LSA length, which
        // spans the header plus the body.
        let (header, length) = Ospfv3LsaHeader::decode(rest)?;

        // The declared length must cover at least the 20-octet header and must
        // not run past the bytes that remain.
        if length < OSPFV3_LSA_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "ospfv3.lsa.length",
                "LSA length is below the 20-octet header minimum",
            ));
        }
        if length > rest.len() {
            return Err(CrafterError::buffer_too_short(
                "ospfv3 lsa",
                length,
                rest.len(),
            ));
        }

        // The LSA body is the `length - 20` octets after the header. Dispatch on
        // the 16-bit LS type: typed bodies for the types this decoder models, and
        // `Ospfv3LsaBody::Raw` for every other type so an unknown LSA round-trips
        // byte-for-byte.
        let lsa_body = &rest[OSPFV3_LSA_HEADER_LEN..length];
        let decoded_body = decode_ospfv3_lsa_body(header.ls_type_value(), lsa_body)?;
        lsas.push(Ospfv3Lsa::new(header, decoded_body));

        rest = &rest[length..];
        parsed += 1;
    }

    Ok(Ospfv3LinkStateUpdate::new().num_lsas(num_lsas).lsas(lsas))
}

/// Dispatch an OSPFv3 LSA body by its 16-bit LS type (RFC 5340 §A.4.2.1), parsing
/// the typed bodies this decoder models and preserving every other type verbatim.
///
/// `body` is the LSA bytes after the 20-octet header (`length - 20` octets). The
/// Router-LSA (`0x2001`) and Network-LSA (`0x2002`) bodies parse into their typed
/// [`Ospfv3LsaBody`] variants (with structured errors on a short body); any other
/// LS type is preserved as [`Ospfv3LsaBody::Raw`] so the LSA round-trips
/// byte-for-byte.
fn decode_ospfv3_lsa_body(ls_type: u16, body: &[u8]) -> Result<Ospfv3LsaBody> {
    match ls_type {
        OSPFV3_LSA_ROUTER => Ok(Ospfv3LsaBody::Router(decode_ospfv3_router_lsa_body(body)?)),
        OSPFV3_LSA_NETWORK => Ok(Ospfv3LsaBody::Network(decode_ospfv3_network_lsa_body(
            body,
        )?)),
        _ => Ok(Ospfv3LsaBody::Raw(body.to_vec())),
    }
}

/// Parse the OSPFv3 Router-LSA body (RFC 5340 §A.4.3) from `body` into an
/// [`Ospfv3RouterLsa`].
///
/// `body` is the LSA bytes after the 20-octet header. The body is a 4-octet fixed
/// prefix — a router-description flags octet then the 24-bit Options — followed by
/// zero or more 16-octet interface descriptions (Type, Reserved, Metric, Interface
/// ID, Neighbor Interface ID, Neighbor Router ID).
///
/// A body shorter than the 4-octet fixed prefix is a structured
/// [`CrafterError::buffer_too_short`] (context `"ospfv3 router-lsa"`); an
/// interface region whose length is not a multiple of 16 is a structured
/// [`CrafterError::invalid_field_value`] (`"ospfv3.router_lsa.interfaces"`), never
/// a panic. The decoded fields re-compile byte-for-byte.
fn decode_ospfv3_router_lsa_body(body: &[u8]) -> Result<Ospfv3RouterLsa> {
    if body.len() < OSPFV3_ROUTER_LSA_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ospfv3 router-lsa",
            OSPFV3_ROUTER_LSA_FIXED_LEN,
            body.len(),
        ));
    }

    // Fixed prefix: flags(1), then the 24-bit Options as three big-endian octets.
    let flags = body[0];
    let options = (u32::from(body[1]) << 16) | (u32::from(body[2]) << 8) | u32::from(body[3]);

    // The remaining octets are the interface-description list: zero or more
    // 16-octet records. A region not a multiple of 16 is a malformed body, not a
    // truncation.
    let interface_region = &body[OSPFV3_ROUTER_LSA_FIXED_LEN..];
    if interface_region.len() % OSPFV3_ROUTER_LSA_INTERFACE_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            "ospfv3.router_lsa.interfaces",
            "interface description list length must be a multiple of 16",
        ));
    }

    // Each 16-octet record is Type(1), Reserved(1), Metric(2), Interface ID(4),
    // Neighbor Interface ID(4), Neighbor Router ID(4), big-endian. The
    // exact-multiple check above keeps every chunk full, so this cannot panic.
    let interfaces: Vec<Ospfv3RouterInterface> = interface_region
        .chunks_exact(OSPFV3_ROUTER_LSA_INTERFACE_LEN)
        .map(|chunk| {
            let if_type = chunk[0];
            let reserved = chunk[1];
            let metric = u16::from_be_bytes([chunk[2], chunk[3]]);
            let interface_id = u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            let neighbor_interface_id =
                u32::from_be_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]);
            let neighbor_router_id = Ipv4Addr::new(chunk[12], chunk[13], chunk[14], chunk[15]);
            Ospfv3RouterInterface::new(
                if_type,
                metric,
                interface_id,
                neighbor_interface_id,
                neighbor_router_id,
            )
            .reserved(reserved)
        })
        .collect();

    Ok(Ospfv3RouterLsa::new()
        .flags(flags)
        .options(options)
        .interfaces(interfaces))
}

/// Parse the OSPFv3 Network-LSA body (RFC 5340 §A.4.4) from `body` into an
/// [`Ospfv3NetworkLsa`].
///
/// `body` is the LSA bytes after the 20-octet header. The body is a 4-octet fixed
/// prefix — a Reserved octet then the 24-bit Options — followed by zero or more
/// 4-octet attached Router IDs. Unlike the OSPFv2 Network-LSA (RFC 2328 §A.4.3)
/// there is no network-mask field.
///
/// A body shorter than the 4-octet fixed prefix is a structured
/// [`CrafterError::buffer_too_short`] (context `"ospfv3 network-lsa"`); an
/// attached-router region whose length is not a multiple of 4 is a structured
/// [`CrafterError::invalid_field_value`] (`"ospfv3.network_lsa.attached_routers"`),
/// never a panic. The decoded fields re-compile byte-for-byte.
fn decode_ospfv3_network_lsa_body(body: &[u8]) -> Result<Ospfv3NetworkLsa> {
    if body.len() < OSPFV3_NETWORK_LSA_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ospfv3 network-lsa",
            OSPFV3_NETWORK_LSA_FIXED_LEN,
            body.len(),
        ));
    }

    // Fixed prefix: Reserved(1), then the 24-bit Options as three big-endian
    // octets.
    let reserved = body[0];
    let options = (u32::from(body[1]) << 16) | (u32::from(body[2]) << 8) | u32::from(body[3]);

    // The remaining octets are the attached-router list: zero or more 4-octet
    // Router IDs. A region not a multiple of 4 is a malformed body, not a
    // truncation.
    let router_region = &body[OSPFV3_NETWORK_LSA_FIXED_LEN..];
    if router_region.len() % OSPFV3_NETWORK_LSA_ROUTER_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            "ospfv3.network_lsa.attached_routers",
            "attached router list length must be a multiple of 4",
        ));
    }
    let attached_routers: Vec<Ipv4Addr> = router_region
        .chunks_exact(OSPFV3_NETWORK_LSA_ROUTER_LEN)
        .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
        .collect();

    Ok(Ospfv3NetworkLsa::new()
        .reserved(reserved)
        .options(options)
        .attached_routers(attached_routers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{NetworkLayer, Packet};
    use crate::protocols::ip::v6::Ipv6;
    use crate::protocols::ospf::{
        Ospfv3, OSPFV3_HEADER_LEN, OSPFV3_TYPE_DATABASE_DESCRIPTION, OSPFV3_TYPE_HELLO,
        OSPFV3_TYPE_LINK_STATE_ACK, OSPFV3_TYPE_LINK_STATE_REQUEST, OSPFV3_TYPE_LINK_STATE_UPDATE,
        OSPF_VERSION_3,
    };
    use core::net::Ipv6Addr;

    /// Compile an `Ipv6 / Ospfv3` packet over `2001:db8::/32` documentation
    /// addresses, decode it through the default registry, assert the OSPFv3 type
    /// code, assert the typed-body predicate holds, and assert the decoded packet
    /// re-compiles byte-for-byte.
    fn round_trip(ospfv3: Ospfv3, type_code: u8, check_body: impl Fn(&Ospfv3Body)) {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();

        let bytes = (Ipv6::new().src(src).dst(dst) / ospfv3)
            .compile()
            .expect("Ipv6 / Ospfv3 compiles");

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())
            .expect("the default registry decodes the OSPFv3 packet over IPv6");
        let layer = decoded
            .layer::<Ospfv3>()
            .expect("the decoded packet exposes a typed Ospfv3 layer");
        assert_eq!(layer.packet_type_value(), type_code);
        check_body(&layer.body);

        let recompiled = decoded
            .compile()
            .expect("the decoded OSPFv3 packet re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// An OSPFv3 Hello with two neighbors and an explicit DR/BDR decodes (type 1)
    /// into a typed Hello body exposing both neighbors, and re-compiles
    /// byte-for-byte (RFC 5340 §A.3.2).
    #[test]
    fn ospfv3_decode_hello_with_two_neighbors_round_trips() {
        let neighbors = [Ipv4Addr::new(192, 0, 2, 3), Ipv4Addr::new(192, 0, 2, 4)];
        let ospfv3 = Ospfv3::hello()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .with_hello(|h| {
                *h = h
                    .clone()
                    .interface_id(0x0000_0005)
                    .router_priority(1)
                    .options(0x0000_0013)
                    .designated_router(Ipv4Addr::new(192, 0, 2, 1))
                    .backup_designated_router(Ipv4Addr::new(192, 0, 2, 2))
                    .neighbors(neighbors);
            });

        round_trip(ospfv3, OSPFV3_TYPE_HELLO, |body| {
            let hello = match body {
                Ospfv3Body::Hello(hello) => hello,
                other => panic!("expected a typed Hello body, got {other:?}"),
            };
            assert_eq!(hello.neighbors_value(), neighbors.as_slice());
            assert_eq!(hello.designated_router_value(), Ipv4Addr::new(192, 0, 2, 1));
        });
    }

    /// An OSPFv3 Database Description with two LSA headers and the M+MS flags
    /// decodes (type 2) into a typed body exposing both headers and the flags, and
    /// re-compiles byte-for-byte (RFC 5340 §A.3.3).
    #[test]
    fn ospfv3_decode_database_description_with_two_headers_round_trips() {
        let ospfv3 = Ospfv3::database_description()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .with_database_description(|d| {
                *d = d
                    .clone()
                    .interface_mtu(1500)
                    .options(0x0000_0013)
                    .dd_sequence_number(0x0000_1a2b)
                    .more(true)
                    .master(true)
                    .lsa_header(
                        Ospfv3LsaHeader::new()
                            .ls_type(0x2001)
                            .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                            .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                            .ls_sequence_number(0x8000_0001),
                    )
                    .lsa_header(
                        Ospfv3LsaHeader::new()
                            .ls_type(0x2002)
                            .link_state_id(Ipv4Addr::new(192, 0, 2, 2))
                            .advertising_router(Ipv4Addr::new(198, 51, 100, 7))
                            .ls_sequence_number(0x8000_0002),
                    );
            });

        round_trip(ospfv3, OSPFV3_TYPE_DATABASE_DESCRIPTION, |body| {
            let dd = match body {
                Ospfv3Body::DatabaseDescription(dd) => dd,
                other => panic!("expected a typed Database Description body, got {other:?}"),
            };
            assert_eq!(dd.lsa_headers_value().len(), 2);
            assert!(dd.is_more());
            assert!(dd.is_master());
            assert!(!dd.is_init());
            assert_eq!(dd.interface_mtu_value(), 1500);
        });
    }

    /// An OSPFv3 Link State Request with two entries decodes (type 3) into a typed
    /// body exposing both entries, and re-compiles byte-for-byte (RFC 5340 §A.3.4).
    #[test]
    fn ospfv3_decode_link_state_request_with_two_entries_round_trips() {
        let ospfv3 = Ospfv3::link_state_request()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .with_link_state_request(|r| {
                *r = r
                    .clone()
                    .request(Ospfv3LinkStateRequestEntry::new(
                        0x2001,
                        Ipv4Addr::new(192, 0, 2, 1),
                        Ipv4Addr::new(192, 0, 2, 1),
                    ))
                    .request(Ospfv3LinkStateRequestEntry::new(
                        0x2002,
                        Ipv4Addr::new(192, 0, 2, 2),
                        Ipv4Addr::new(198, 51, 100, 7),
                    ));
            });

        round_trip(ospfv3, OSPFV3_TYPE_LINK_STATE_REQUEST, |body| {
            let lsr = match body {
                Ospfv3Body::LinkStateRequest(lsr) => lsr,
                other => panic!("expected a typed Link State Request body, got {other:?}"),
            };
            assert_eq!(lsr.entries_value().len(), 2);
            assert_eq!(lsr.entries_value()[0].ls_type_value(), 0x2001);
            assert_eq!(
                lsr.entries_value()[1].advertising_router_value(),
                Ipv4Addr::new(198, 51, 100, 7)
            );
        });
    }

    /// An OSPFv3 Link State Acknowledgment with two LSA headers decodes (type 5)
    /// into a typed body exposing both headers, and re-compiles byte-for-byte
    /// (RFC 5340 §A.3.6).
    #[test]
    fn ospfv3_decode_link_state_ack_with_two_headers_round_trips() {
        let ospfv3 = Ospfv3::link_state_ack()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .with_link_state_ack(|a| {
                *a = a
                    .clone()
                    .lsa_header(
                        Ospfv3LsaHeader::new()
                            .ls_type(0x2001)
                            .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                            .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                            .ls_sequence_number(0x8000_0001),
                    )
                    .lsa_header(
                        Ospfv3LsaHeader::new()
                            .ls_type(0x2002)
                            .link_state_id(Ipv4Addr::new(192, 0, 2, 2))
                            .advertising_router(Ipv4Addr::new(198, 51, 100, 7))
                            .ls_sequence_number(0x8000_0002),
                    );
            });

        round_trip(ospfv3, OSPFV3_TYPE_LINK_STATE_ACK, |body| {
            let ack = match body {
                Ospfv3Body::LinkStateAck(ack) => ack,
                other => panic!("expected a typed Link State Acknowledgment body, got {other:?}"),
            };
            assert_eq!(ack.lsa_headers_value().len(), 2);
            assert_eq!(ack.lsa_headers_value()[0].ls_type_value(), 0x2001);
        });
    }

    /// An OSPFv3 Link State Update carrying one Router-LSA decodes (type 4) into a
    /// typed body whose single LSA dispatches to a typed Router-LSA body exposing
    /// its interface description, and re-compiles byte-for-byte (RFC 5340 §A.3.5 /
    /// §A.4.3).
    #[test]
    fn ospfv3_decode_link_state_update_with_router_lsa_round_trips() {
        let router_lsa = Ospfv3Lsa::new(
            Ospfv3LsaHeader::new()
                .ls_type(0x2001)
                .link_state_id(Ipv4Addr::new(0, 0, 0, 0))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            Ospfv3LsaBody::Router(Ospfv3RouterLsa::new().options(0x0000_0013).interface(
                Ospfv3RouterInterface::new(
                    1,
                    10,
                    0x0000_0005,
                    0x0000_0006,
                    Ipv4Addr::new(192, 0, 2, 2),
                ),
            )),
        );

        let ospfv3 = Ospfv3::link_state_update()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .with_link_state_update(|u| *u = u.clone().lsa(router_lsa));

        round_trip(ospfv3, OSPFV3_TYPE_LINK_STATE_UPDATE, |body| {
            let lsu = match body {
                Ospfv3Body::LinkStateUpdate(lsu) => lsu,
                other => panic!("expected a typed Link State Update body, got {other:?}"),
            };
            assert_eq!(lsu.lsas_value().len(), 1);
            let lsa = &lsu.lsas_value()[0];
            assert_eq!(lsa.header.ls_type_value(), 0x2001);
            let router = match &lsa.body {
                Ospfv3LsaBody::Router(router) => router,
                other => panic!("expected a typed Router-LSA body, got {other:?}"),
            };
            assert_eq!(router.interfaces_value().len(), 1);
            assert_eq!(
                router.interfaces_value()[0].neighbor_router_id_value(),
                Ipv4Addr::new(192, 0, 2, 2)
            );
        });
    }

    /// A buffer shorter than the 16-octet OSPFv3 common header surfaces a
    /// structured buffer-too-short error (RFC 5340 §A.3.1) rather than a panic.
    #[test]
    fn ospfv3_decode_short_header_is_a_structured_error() {
        let err = append_ospfv3_packet(Packet::new(), &[0u8; 8])
            .expect_err("a short OSPFv3 header is rejected");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ospfv3 header");
                assert_eq!(required, OSPFV3_HEADER_LEN);
                assert_eq!(available, 8);
            }
            other => panic!("expected BufferTooShort, got {other:?}"),
        }
    }

    /// A well-formed `Ipv6 / Ospfv3` Hello decodes with the IPv6 upper-layer
    /// checksum recorded as `Valid` (RFC 5340 §2.7), and decoding the same bytes
    /// through a registry with `checksum_validation(false)` records `NotChecked`;
    /// both re-compile byte-for-byte. Mirrors the OSPFv2 / ICMPv6 checksum-status
    /// tests.
    #[test]
    fn ospfv3_decode_records_checksum_status() {
        use crate::registry::ProtocolRegistry;

        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();

        let bytes = (Ipv6::new().src(src).dst(dst)
            / Ospfv3::hello()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0]))
        .compile()
        .expect("Ipv6 / Ospfv3 Hello compiles");

        // Default registry validates checksums: a well-formed packet is Valid.
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())
            .expect("the default registry decodes the OSPFv3 Hello over IPv6");
        let ospfv3 = decoded
            .layer::<Ospfv3>()
            .expect("the decoded packet exposes a typed Ospfv3 layer");
        assert_eq!(ospfv3.version_value(), OSPF_VERSION_3);
        assert_eq!(ospfv3.checksum_status(), OspfChecksumStatus::Valid);
        assert_eq!(
            decoded.compile().expect("re-compiles").as_bytes(),
            bytes.as_bytes()
        );

        // With checksum validation disabled the status is NotChecked.
        let registry = ProtocolRegistry::with_builtin_bindings().checksum_validation(false);
        let decoded_no_check = registry
            .decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())
            .expect("the no-check registry decodes the OSPFv3 Hello over IPv6");
        let ospfv3_no_check = decoded_no_check
            .layer::<Ospfv3>()
            .expect("the decoded packet exposes a typed Ospfv3 layer");
        assert_eq!(
            ospfv3_no_check.checksum_status(),
            OspfChecksumStatus::NotChecked
        );
        assert_eq!(
            decoded_no_check.compile().expect("re-compiles").as_bytes(),
            bytes.as_bytes()
        );
    }
}
