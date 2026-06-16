//! Malformed/resilience coverage for the RIPng decode entrypoint.
//!
//! The crate's decoders must never panic on truncated or malformed input;
//! instead they return the structured length error
//! ([`CrafterError::BufferTooShort`]) carrying `context`/`required`/`available`
//! so generated tools can inspect exactly what was missing. This test pins that
//! behavior for [`crafter::protocols::rip::ripng::decode`]: a too-short header,
//! a header plus a partial route table entry (RTE), and a header plus a
//! non-multiple-of-20 body each surface a structured error whose context names
//! the RIPng element. Alongside the malformed cases, a valid Response carrying a
//! next-hop RTE (metric `0xFF`) followed by a route RTE decodes successfully and
//! the next hop is classified correctly.
//!
//! All addresses use documentation address space (`2001:db8::/32`). The test
//! binary running to completion is itself the no-panic guarantee.

use std::net::Ipv6Addr;

use crafter::prelude::*;
use crafter::protocols::rip::ripng::decode;

/// A well-formed 20-octet RIPng route RTE body (prefix `2001:db8::/32`,
/// route tag 0, metric 1) used to pad over-length or partial bodies. Mirrors the
/// RFC 2080 §2.1 RTE layout: IPv6 prefix (16), route tag (u16), prefix length
/// (u8), metric (u8).
fn route_rte_bytes() -> [u8; 20] {
    let mut bytes = [0u8; 20];
    let prefix = "2001:db8::"
        .parse::<Ipv6Addr>()
        .expect("valid documentation prefix");
    bytes[0..16].copy_from_slice(&prefix.octets());
    // route tag = 0 (bytes 16..18 already zero)
    bytes[18] = 0x20; // prefix length = 32
    bytes[19] = 0x01; // metric = 1
    bytes
}

/// Assert the error is a structured `BufferTooShort` whose context mentions the
/// RIPng element, and that `required`/`available` are exposed and consistent.
fn assert_ripng_length_error(case: &str, error: CrafterError) {
    match error {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert!(
                context.contains("RIPng"),
                "{case}: error context should mention the RIPng element, got {context:?}"
            );
            assert!(
                available < required,
                "{case}: available ({available}) should be less than required ({required})"
            );
        }
        other => panic!("{case}: expected BufferTooShort, got {other:?}"),
    }
}

#[test]
fn truncated_three_octet_header_returns_structured_error() {
    // Only three octets are present; the 4-octet RIPng header (RFC 2080 §2) is
    // incomplete, so decode must fault on the header rather than panic.
    let bytes = [0x02u8, 0x01, 0x00];
    let error = decode(&bytes).expect_err("a 3-octet truncated header must not decode");
    assert_ripng_length_error("truncated-header", error);
}

#[test]
fn header_plus_partial_rte_returns_structured_error() {
    // A valid 4-octet header (Response, version 1) followed by a 12-octet
    // partial RTE: the trailing run is shorter than a whole 20-octet RTE slot.
    let mut bytes = vec![0x02u8, 0x01, 0x00, 0x00];
    bytes.extend_from_slice(&route_rte_bytes()[..12]);
    let error = decode(&bytes).expect_err("a header plus a 12-octet partial RTE must not decode");
    assert_ripng_length_error("header-plus-partial-rte", error);
}

#[test]
fn header_plus_non_multiple_of_twenty_body_returns_structured_error() {
    // A valid header followed by a 21-octet body (total 25 octets): the trailing
    // run is not a whole multiple of the 20-octet RTE length, so the final
    // partial RTE must surface a structured error.
    let mut bytes = vec![0x02u8, 0x01, 0x00, 0x00];
    bytes.extend_from_slice(&route_rte_bytes());
    bytes.push(0x00); // one extra octet => 21-octet trailing run
    assert_eq!(bytes.len(), 25, "body should be exactly 25 octets");
    let error = decode(&bytes).expect_err("a non-multiple-of-20 body must not decode");
    assert_ripng_length_error("header-plus-25-octet-body", error);
}

#[test]
fn next_hop_rte_followed_by_route_decodes_and_classifies() {
    // A valid Response carrying a next-hop RTE (metric 0xFF, RFC 2080 §2.1.1)
    // followed by a route RTE. Build it through the public packet abstraction and
    // compile it to the wire bytes the decode entrypoint consumes.
    let next_hop = "2001:db8::fe"
        .parse::<Ipv6Addr>()
        .expect("valid documentation next-hop");
    let prefix = "2001:db8:1::"
        .parse::<Ipv6Addr>()
        .expect("valid documentation prefix");

    let ripng = Ripng::response().with_rtes(vec![
        RipngRte::next_hop(next_hop),
        RipngRte::route(prefix, 48, 2),
    ]);
    let bytes = Packet::from_layer(ripng)
        .compile()
        .expect("compiling a next-hop + route RIPng message must succeed");

    let decoded = decode(&bytes).expect("a next-hop RTE followed by a route RTE must decode");
    assert_eq!(
        decoded.command(),
        RipCommand::Response,
        "the decoded command must be Response"
    );
    assert_eq!(
        decoded.rtes().len(),
        2,
        "both RTEs (next-hop and route) must be decoded"
    );

    // The first RTE is the next-hop RTE (metric 0xFF), classified correctly.
    let nh = &decoded.rtes()[0];
    assert!(
        nh.is_next_hop(),
        "the first RTE must classify as a next-hop RTE"
    );
    assert_eq!(
        nh.next_hop_address(),
        Some(next_hop),
        "the next-hop RTE must carry the next-hop address"
    );

    // The second RTE is an ordinary route, not a next hop.
    let route = &decoded.rtes()[1];
    assert!(
        !route.is_next_hop(),
        "the second RTE must not classify as a next-hop RTE"
    );
    assert_eq!(route.prefix_value(), prefix);
    assert_eq!(route.prefix_len_value(), 48);
    assert_eq!(route.metric_value(), 2);
}
