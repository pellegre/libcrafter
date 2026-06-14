//! ICMPv6 decode path: the `type` byte → typed-body dispatch.
//!
//! Turns wire bytes into a typed [`Icmpv6`] header plus the typed message body
//! the `type` selects, falling back to a single [`Raw`] payload for anything
//! that fails the defensible-parse gate. The entrypoint is
//! [`append_icmpv6_packet`], used by the registry IPv6 next-header 58 binding
//! (`crate::registry`) and reachable through the `icmp` module root; the rest are
//! its private dispatch helpers.
//!
//! This is the ICMPv6 analogue of the ICMPv4 decode in `icmp/decode.rs`: the
//! [`Icmpv6`] header carries the type/code/checksum and the fixed
//! rest-of-header, and the trailing body (NDP option area, MLD records, Node
//! Information data, extended-echo extension structure) is dispatched by the
//! `type` byte. The dispatch covers every ICMPv6 `type` `crafter` implements:
//!
//! - 1–4 / 128 / 129 — RFC 4443 error and echo messages: the type-specific
//!   rest-of-header fields are decoded with the header itself in
//!   [`decode_icmpv6_parts`]; an echo carries a trailing data payload, an error
//!   carries the quoted datagram, both of which fall through to the raw tail.
//! - 130 — RFC 2710 MLDv1 Query *or* RFC 3810/9777 MLDv2 Query, disambiguated by
//!   body length: a body of at least [`MLDV2_QUERY_MIN_BODY_LEN`] (20) bytes is
//!   tried as an MLDv2 Query first; an exactly-16-byte body is an MLDv1 Query.
//! - 131 / 132 — RFC 2710 MLDv1 Report / Done.
//! - 133–137 — RFC 4861 Neighbor Discovery: Router Solicitation, Router
//!   Advertisement, Neighbor Solicitation, Neighbor Advertisement, Redirect.
//! - 139 / 140 — RFC 4620 Node Information Query / Response (experimental).
//! - 143 — RFC 3810/9777 MLDv2 Version 2 Report.
//! - 160 / 161 — RFC 8335 Extended Echo Request / Reply.
//!
//! Any other `type` (for example RFC 2894 Router Renumbering (138), RFC 3122
//! Inverse Neighbor Discovery (141/142), or an IANA-unassigned value such as
//! 200) keeps the decoded [`Icmpv6`] header and preserves the remaining payload
//! as a single [`Raw`] body, per the "unknown next-protocol preserved as Raw"
//! rule in `CLAUDE.md`. A malformed body for a *known* type falls back to the
//! same `Raw` tail (the per-message decoders return an error rather than
//! panicking), so decoding a truncated or over-stated message never panics and
//! never drops bytes.

use super::*;
use crate::endian::read_u16_be;

/// Decode the fixed ICMPv6 header and return it together with the trailing body
/// bytes the `type` dispatch in [`append_icmpv6_packet`] consumes.
///
/// The type-specific rest-of-header fields (echo identifier/sequence, error
/// MTU/pointer, RFC 4884 length, RFC 8335 extended-echo flag byte) are recovered
/// here so the [`Icmpv6`] header surfaces them through its typed accessors; the
/// returned slice is everything after the eight-byte fixed header.
fn decode_icmpv6_parts(bytes: &[u8]) -> Result<(Icmpv6, &[u8])> {
    if bytes.len() < ICMP_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "icmpv6 header",
            ICMP_HEADER_LEN,
            bytes.len(),
        ));
    }

    let rest = copy_array_4(&bytes[4..8]);
    let icmp_type = bytes[0];
    let is_extended_echo = is_extended_echo_v6(icmp_type);
    let icmpv6 = Icmpv6 {
        icmp_type: Field::user(icmp_type),
        code: Field::user(bytes[1]),
        checksum: Field::user(read_u16_be(&bytes[2..4])?),
        rest_of_header: Field::user(rest),
        // RFC 8335 narrows the sequence number to a single octet (byte 2) and
        // adds a flag byte (byte 3), but the identifier is still the 16-bit
        // bytes 0..2, so the identifier field is shared with the echo families.
        identifier: if is_echo_v6(icmp_type) || is_extended_echo {
            Field::user(u16::from_be_bytes([rest[0], rest[1]]))
        } else {
            Field::unset()
        },
        sequence_number: if is_extended_echo {
            // Zero-extend the 8-bit RFC 8335 sequence number into the low octet;
            // the accessor/serialize path treat it as an 8-bit value for these
            // types so the flag byte (byte 3) is never folded in.
            Field::user(u16::from(rest[2]))
        } else {
            field_from_echo(icmp_type, &rest, 2, is_echo_v6)
        },
        length: if icmpv6_type_allows_extensions(icmp_type) {
            Field::user(rest[0])
        } else {
            Field::unset()
        },
        mtu: if icmp_type == ICMPV6_PACKET_TOO_BIG {
            Field::user(u32::from_be_bytes(rest))
        } else {
            Field::unset()
        },
        pointer: if icmp_type == ICMPV6_PARAMETER_PROBLEM {
            Field::user(u32::from_be_bytes(rest))
        } else {
            Field::unset()
        },
        extended_flags: if is_extended_echo {
            Field::user(rest[3])
        } else {
            Field::unset()
        },
    };

    Ok((icmpv6, &bytes[ICMP_HEADER_LEN..]))
}

/// Append a decoded ICMPv6 packet to an existing packet stack.
///
/// Decodes the fixed [`Icmpv6`] header, then dispatches on the `type` byte to the
/// typed message body. Unknown types and malformed known-type bodies preserve the
/// remaining bytes as a single [`Raw`] payload; decoding never panics.
pub(crate) fn append_icmpv6_packet(mut packet: Packet, bytes: &[u8]) -> Result<Packet> {
    let (icmpv6, payload) = decode_icmpv6_parts(bytes)?;
    let icmp_type = icmpv6.icmp_type_value();
    packet = packet.push_icmpv6(icmpv6);

    // RFC 3810/9777 section 5.1 MLDv2 Query: a type-130 message reuses the MLDv1
    // Query type byte but carries a longer body — the 16-byte Multicast Address
    // plus a flags/QRV/QQIC/Number-of-Sources run and a Source Address list. The
    // two versions are disambiguated by body length (the step-27/28 seam): an
    // MLDv2 Query body is at least `MLDV2_QUERY_MIN_BODY_LEN` (20) bytes, while an
    // MLDv1 Query body is *exactly* the 16-byte Multicast Address. Try the
    // MLDv2-query decode first for a type-130 body that is long enough; an
    // exactly-16-byte body skips it and falls to the MLDv1 decoder below. A
    // malformed longer body (e.g. an over-stated Number of Sources) keeps the
    // bytes as a single `Raw` payload (no panic, nothing dropped).
    if icmp_type == ICMPV6_MULTICAST_LISTENER_QUERY && payload.len() >= MLDV2_QUERY_MIN_BODY_LEN {
        if let Ok(query) = decode_mldv2_query(payload) {
            return Ok(packet.push(query));
        }
    }

    // RFC 2710 MLDv1 (types 130-132): the Maximum Response Delay and Reserved
    // fields were decoded with the header above; the trailing body is the 16-byte
    // Multicast Address. The three types share one body shape, so they share a
    // decoder. The MLDv1 Query (130) is disambiguated from the MLDv2 Query
    // (decoded just above) by body length: an MLDv1 body is *exactly* 16 bytes.
    // `decode_multicast_listener_message` enforces the exact-16-byte shape, so a
    // longer (MLDv2) type-130 body never reaches here.
    if icmp_type == ICMPV6_MULTICAST_LISTENER_QUERY
        || icmp_type == ICMPV6_MULTICAST_LISTENER_REPORT
        || icmp_type == ICMPV6_MULTICAST_LISTENER_DONE
    {
        if let Ok(mld) = decode_multicast_listener_message(payload) {
            return Ok(packet.push(mld));
        }
    }

    // RFC 3810/9777 section 5.2 MLDv2 Version 2 Report (type 143): the 16-bit
    // Reserved field and the 16-bit Nr of Mcast Address Records were decoded with
    // the header above; the trailing body is the list of Multicast Address
    // Records. The record walk recovers the records from their own lengths, so a
    // malformed record (a short fixed header, an over-stated Number of Sources, or
    // an over-stated Aux Data Len) keeps the bytes as a single `Raw` payload (no
    // panic, nothing dropped).
    if icmp_type == ICMPV6_MLDV2_REPORT {
        if let Ok(report) = decode_mldv2_report(payload) {
            return Ok(packet.push(report));
        }
    }

    // RFC 4861 Neighbor Discovery messages (types 133-137) carry a typed body
    // after the fixed header. The body is typed whenever the option area parses
    // defensibly — even when the area is empty, so a bare Router Solicitation
    // still exposes its typed body. A malformed option area (a zero-length or
    // overrunning option) keeps the bytes as a single `Raw` payload so nothing is
    // dropped and decoding never panics.
    //
    // RFC 4861 section 4.1 Router Solicitation: the 32-bit Reserved field is the
    // header's rest-of-header (decoded with the header above); the trailing body
    // is the NDP option area.
    if icmp_type == ICMPV6_ROUTER_SOLICITATION {
        if let Ok(rs) = decode_router_solicitation(payload) {
            return Ok(packet.push(rs));
        }
    }

    // RFC 4861 section 4.2 Router Advertisement: the rest-of-header (Cur Hop
    // Limit / M+O flags / Router Lifetime) was decoded with the header above;
    // the trailing body is the Reachable-Time + Retrans-Timer words and the NDP
    // option area. A body too short for the two timer words, or a malformed
    // option area, keeps the bytes as a single `Raw` payload (no panic, nothing
    // dropped).
    if icmp_type == ICMPV6_ROUTER_ADVERTISEMENT {
        if let Ok(ra) = decode_router_advertisement(payload) {
            return Ok(packet.push(ra));
        }
    }

    // RFC 4861 section 4.3 Neighbor Solicitation: the rest-of-header (the 32-bit
    // Reserved field) was decoded with the header above; the trailing body is the
    // 128-bit Target Address followed by the NDP option area. A body too short for
    // the Target Address, or a malformed option area, keeps the bytes as a single
    // `Raw` payload (no panic, nothing dropped).
    if icmp_type == ICMPV6_NEIGHBOR_SOLICITATION {
        if let Ok(ns) = decode_neighbor_solicitation(payload) {
            return Ok(packet.push_neighbor_solicitation(ns));
        }
    }

    // RFC 4861 section 4.4 Neighbor Advertisement: the rest-of-header (the 32-bit
    // R/S/O flags word with its 29 Reserved bits) was decoded with the header
    // above; the trailing body is the 128-bit Target Address followed by the NDP
    // option area. A body too short for the Target Address, or a malformed option
    // area, keeps the bytes as a single `Raw` payload (no panic, nothing dropped).
    if icmp_type == ICMPV6_NEIGHBOR_ADVERTISEMENT {
        if let Ok(na) = decode_neighbor_advertisement(payload) {
            return Ok(packet.push(na));
        }
    }

    // RFC 4861 section 4.5 Redirect: the rest-of-header (the 32-bit Reserved
    // field) was decoded with the header above; the trailing body is the 128-bit
    // Target Address, the 128-bit Destination Address, and the NDP option area
    // (commonly a Target Link-Layer Address and a Redirected Header option). A
    // body too short for both addresses, or a malformed option area, keeps the
    // bytes as a single `Raw` payload (no panic, nothing dropped).
    if icmp_type == ICMPV6_REDIRECT {
        if let Ok(redirect) = decode_redirect(payload) {
            return Ok(packet.push(redirect));
        }
    }

    // RFC 4620 section 4 Node Information Query (139) / Response (140),
    // **experimental**: the Qtype and Flags were decoded with the header above
    // (they are the rest-of-header); the trailing body is the 8-byte Nonce
    // followed by the variable Data field. The two types share one body shape
    // (the `type` byte distinguishes Query from Response), so they share a
    // decoder. A body too short for the fixed Nonce keeps the bytes as a single
    // `Raw` payload (no panic, nothing dropped).
    if icmp_type == ICMPV6_NODE_INFORMATION_QUERY || icmp_type == ICMPV6_NODE_INFORMATION_RESPONSE {
        if let Ok(node_info) = decode_node_information(payload) {
            return Ok(packet.push(node_info));
        }
    }

    // RFC 8335 section 3 Extended Echo Request (160): the identifier / sequence /
    // L-bit live in the rest-of-header (decoded with the header above); the
    // trailing body is an RFC 4884 ICMP Extension Structure carrying a single
    // Interface Identification Object, beginning immediately after the fixed
    // header (no quoted datagram, no original-datagram padding). The structure is
    // version-neutral, so the same decoder ICMPv4 uses (`icmp/decode.rs`) types
    // it here. Anything that does not parse defensibly (bad version, bad
    // checksum, impossible object lengths) stays a single `Raw` payload so the
    // bytes survive and decoding never panics. The reply (161) carries no body of
    // its own, so any trailing bytes on a reply fall through to the raw tail.
    if icmp_type == ICMPV6_EXTENDED_ECHO_REQUEST {
        if let Some(layers) = decode_extended_echo_extension(payload) {
            for layer in layers {
                packet = packet.push_box(layer);
            }
            return Ok(packet);
        }
    }

    // Fallback: any ICMPv6 `type` without a typed body — an IANA-unassigned value,
    // or a standards-track family `crafter` does not model yet (RFC 2894 Router
    // Renumbering (138), RFC 3122 Inverse Neighbor Discovery (141/142)) — keeps
    // the decoded header and preserves the remaining payload as a single `Raw`
    // body. This is also where a malformed *known*-type body lands, because each
    // per-message decoder above returns an error (never a panic) on a bad body and
    // the dispatch falls through to here.
    if !payload.is_empty() {
        packet = packet.push_raw(Raw::from_bytes(payload));
    }
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::append_icmpv6_packet;
    use crate::packet::{Layer, Packet, Raw};
    use crate::protocols::icmp::{
        Icmpv6, Mldv2Report, MulticastListenerMessage, NeighborAdvertisement, NeighborSolicitation,
        NodeInformation, Redirect, RouterAdvertisement, RouterSolicitation,
    };
    use crate::{Ipv6, NetworkLayer};
    use core::net::Ipv6Addr;

    // An ICMPv6 `type` that is never modeled with a typed body. Type 200 is
    // unassigned in the IANA ICMPv6 type registry and is not implemented by any
    // NDP/MLD/extended-echo/node-info step, so it stays a genuine "unknown type"
    // even as more message types are modeled.
    const UNMODELED_ICMPV6_TYPE: u8 = 200;

    fn src() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0x0010)
    }

    fn dst() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 2, 0, 0, 0, 0, 0x0020)
    }

    fn target() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0x00ff)
    }

    fn group() -> Ipv6Addr {
        Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x00fb)
    }

    /// Compile a packet down to the IPv6 layer and decode it back through the
    /// public registry path, returning the rebuilt [`Packet`].
    fn round_trip(packet: Packet) -> Packet {
        let bytes = packet.compile().expect("compile");
        Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).expect("decode_from_l3")
    }

    // Every implemented NDP `type` (133-137) reaches its typed body through the
    // public `decode_from_l3` registry path over an IPv6 packet.
    #[test]
    fn ndp_types_decode_to_typed_bodies() {
        let rs = round_trip(Ipv6::new().src(src()).dst(dst()) / Icmpv6::router_solicitation());
        assert!(rs.layer::<RouterSolicitation>().is_some());

        let ra = round_trip(Ipv6::new().src(src()).dst(dst()) / Icmpv6::router_advertisement());
        assert!(ra.layer::<RouterAdvertisement>().is_some());

        let ns =
            round_trip(Ipv6::new().src(src()).dst(dst()) / Icmpv6::neighbor_solicitation(target()));
        assert!(ns.layer::<NeighborSolicitation>().is_some());

        let na = round_trip(
            Ipv6::new().src(src()).dst(dst()) / Icmpv6::neighbor_advertisement(target()),
        );
        assert!(na.layer::<NeighborAdvertisement>().is_some());

        let redirect =
            round_trip(Ipv6::new().src(src()).dst(dst()) / Icmpv6::redirect(target(), dst()));
        assert!(redirect.layer::<Redirect>().is_some());
    }

    // MLDv1 (130-132), MLDv2 report (143), and node information (139/140) reach
    // their typed bodies through the same registry path.
    #[test]
    fn mld_and_node_info_types_decode_to_typed_bodies() {
        let query =
            round_trip(Ipv6::new().src(src()).dst(dst()) / Icmpv6::mld_query(group(), 1000));
        assert!(query.layer::<MulticastListenerMessage>().is_some());

        let report =
            round_trip(Ipv6::new().src(src()).dst(dst()) / Icmpv6::mldv2_report(Vec::new()));
        assert!(report.layer::<Mldv2Report>().is_some());

        let ni = round_trip(
            Ipv6::new().src(src()).dst(dst())
                / Icmpv6::node_information_query(0, 0, [0u8; 8], Vec::new()),
        );
        assert!(ni.layer::<NodeInformation>().is_some());
    }

    // An unknown ICMPv6 type (200) decodes to the `Icmpv6` header plus a single
    // `Raw` body and round-trips byte-for-byte.
    #[test]
    fn unknown_type_decodes_to_header_plus_raw_and_round_trips() {
        let packet = Ipv6::new().src(src()).dst(dst())
            / Icmpv6::new()
                .icmp_type(UNMODELED_ICMPV6_TYPE)
                .rest_of_header([0xde, 0xad, 0xbe, 0xef])
            / Raw::from_bytes([0x01, 0x02, 0x03, 0x04]);
        let bytes = packet.compile().expect("compile");

        let decoded =
            Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).expect("decode_from_l3");
        let icmpv6 = decoded.layer::<Icmpv6>().expect("Icmpv6 header decodes");
        assert_eq!(icmpv6.icmp_type_value(), UNMODELED_ICMPV6_TYPE);
        let raw = decoded
            .layer::<Raw>()
            .expect("unknown body preserved as Raw");
        assert_eq!(raw.as_bytes(), &[0x01, 0x02, 0x03, 0x04]);

        // No typed NDP/MLD body was synthesized for the unknown type.
        assert!(decoded.layer::<RouterSolicitation>().is_none());
        assert_eq!(
            decoded.compile().expect("recompile").as_bytes(),
            bytes.as_bytes()
        );
    }

    // The standards-track families `crafter` documents as deferred (RFC 2894
    // Router Renumbering (138), RFC 3122 Inverse Neighbor Discovery (141/142))
    // decode to the header plus a `Raw` tail rather than panicking or misparsing.
    #[test]
    fn deferred_families_decode_to_header_plus_raw() {
        for icmp_type in [138u8, 141, 142] {
            let packet = Ipv6::new().src(src()).dst(dst())
                / Icmpv6::new().icmp_type(icmp_type)
                / Raw::from_bytes([0xaa, 0xbb, 0xcc, 0xdd]);
            let decoded = round_trip(packet);
            let icmpv6 = decoded.layer::<Icmpv6>().expect("header decodes");
            assert_eq!(icmpv6.icmp_type_value(), icmp_type);
            assert_eq!(
                decoded
                    .layer::<Raw>()
                    .expect("payload preserved as Raw")
                    .as_bytes(),
                &[0xaa, 0xbb, 0xcc, 0xdd]
            );
        }
    }

    // Decoding a known type whose body is malformed (here an NS whose trailing
    // body is shorter than the 16-byte Target Address) falls back to the header
    // plus a `Raw` tail instead of synthesizing a typed body or panicking.
    #[test]
    fn malformed_known_body_falls_back_to_raw() {
        // Build the ICMPv6 header bytes directly so the truncated body is shorter
        // than a Neighbor Solicitation's required Target Address.
        let mut icmpv6_bytes = vec![
            crate::protocols::icmp::ICMPV6_NEIGHBOR_SOLICITATION,
            0, // code
            0,
            0, // checksum (decode does not validate it)
            0,
            0,
            0,
            0, // reserved rest-of-header
        ];
        icmpv6_bytes.extend_from_slice(&[0xde, 0xad]); // only 2 trailing bytes

        let base = Packet::new();
        let decoded = append_icmpv6_packet(base, &icmpv6_bytes).expect("no panic");
        assert!(decoded.layer::<NeighborSolicitation>().is_none());
        let raw = decoded
            .layer::<Raw>()
            .expect("malformed body preserved as Raw");
        assert_eq!(raw.as_bytes(), &[0xde, 0xad]);
    }

    // A truncated ICMPv6 header (fewer than 8 bytes) surfaces a structured error
    // rather than panicking.
    #[test]
    fn truncated_header_is_structured_error() {
        let base = Packet::new();
        let err = append_icmpv6_packet(base, &[0x80, 0x00, 0x00]).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("icmpv6 header"),
            "unexpected error: {message}"
        );
    }

    // `compile()` auto-fills the ICMPv6 checksum over the IPv6 pseudo-header for
    // every message family, and a user-set checksum survives untouched.
    #[test]
    fn checksum_auto_fills_for_new_families_and_user_value_survives() {
        let cases: Vec<Packet> = vec![
            Ipv6::new().src(src()).dst(dst()) / Icmpv6::router_solicitation(),
            Ipv6::new().src(src()).dst(dst()) / Icmpv6::router_advertisement(),
            Ipv6::new().src(src()).dst(dst()) / Icmpv6::neighbor_solicitation(target()),
            Ipv6::new().src(src()).dst(dst()) / Icmpv6::neighbor_advertisement(target()),
            Ipv6::new().src(src()).dst(dst()) / Icmpv6::redirect(target(), dst()),
            Ipv6::new().src(src()).dst(dst()) / Icmpv6::mld_query(group(), 1000),
            Ipv6::new().src(src()).dst(dst()) / Icmpv6::mldv2_report(Vec::new()),
            Ipv6::new().src(src()).dst(dst()) / Icmpv6::extended_echo_request().id(1).seq(2),
        ];
        for packet in cases {
            let decoded = round_trip(packet);
            let icmpv6 = decoded.layer::<Icmpv6>().expect("Icmpv6 header");
            // A real (non-zero) checksum was auto-filled and round-trips. ICMPv6
            // checksums are never legitimately zero (the pseudo-header always
            // contributes the protocol number and lengths).
            assert_ne!(
                icmpv6.checksum_value(),
                Some(0),
                "checksum should be auto-filled for {}",
                icmpv6.summary()
            );
        }

        // A deliberately wrong, user-set checksum survives compilation untouched.
        // The Neighbor Solicitation builder composes this exact header/body pair;
        // setting `checksum()` on the header is the only difference, so this proves
        // the user value survives the shared `effective_checksum` path every family
        // routes through.
        let forced = Ipv6::new().src(src()).dst(dst())
            / Icmpv6::new()
                .icmp_type(crate::protocols::icmp::ICMPV6_NEIGHBOR_SOLICITATION)
                .code(0)
                .checksum(0xbeef)
            / NeighborSolicitation::new(target());
        let bytes = forced.compile().expect("compile");
        assert_eq!(&bytes.as_bytes()[42..44], &[0xbe, 0xef]);
    }
}
