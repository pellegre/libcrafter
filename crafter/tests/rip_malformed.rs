//! Malformed/resilience coverage for the RIP decode entrypoint.
//!
//! The crate's decoders must never panic on truncated or malformed input;
//! instead they return the structured length error
//! ([`CrafterError::BufferTooShort`]) carrying `context`/`required`/`available`
//! so generated tools can inspect exactly what was missing. This test pins that
//! behavior for [`crafter::protocols::rip::decode`]: a too-short header, a
//! header plus a partial entry, and a header plus a non-multiple-of-20 body each
//! surface a structured error whose context names the RIP element. An unknown
//! command still decodes the 4-octet header while preserving the raw command
//! value, and an over-length body (more than the RFC 2453 §4 25-entry guideline)
//! still decodes successfully.
//!
//! The test binary running to completion is itself the no-panic guarantee.

use std::net::Ipv4Addr;

use crafter::prelude::*;
use crafter::protocols::rip::decode;

/// A well-formed 20-octet RIPv2 route entry body (AFI 2, route 192.0.2.0/24,
/// metric 1) used to pad over-length bodies. Mirrors the RFC 2453 entry layout.
fn route_entry_bytes() -> [u8; 20] {
    [
        0x00, 0x02, // address family identifier (IP)
        0x00, 0x00, // route tag
        0xC0, 0x00, 0x02, 0x00, // IPv4 address 192.0.2.0
        0xFF, 0xFF, 0xFF, 0x00, // subnet mask 255.255.255.0
        0x00, 0x00, 0x00, 0x00, // next hop 0.0.0.0
        0x00, 0x00, 0x00, 0x01, // metric 1
    ]
}

/// Assert the error is a structured `BufferTooShort` whose context mentions the
/// RIP element, and that `required`/`available` are exposed and consistent.
fn assert_rip_length_error(case: &str, error: CrafterError) {
    match error {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert!(
                context.contains("RIP"),
                "{case}: error context should mention the RIP element, got {context:?}"
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
fn truncated_two_octet_header_returns_structured_error() {
    // Only the command and version octets are present; the 4-octet header is
    // incomplete, so decode must fault on the header rather than panic.
    let bytes = [0x01u8, 0x02];
    let error = decode(&bytes).expect_err("a 2-octet truncated header must not decode");
    assert_rip_length_error("truncated-header", error);
}

#[test]
fn header_plus_partial_entry_returns_structured_error() {
    // A valid 4-octet header followed by a 10-octet partial route entry: the
    // trailing run is shorter than a whole 20-octet entry slot.
    let mut bytes = vec![0x01u8, 0x02, 0x00, 0x00];
    bytes.extend_from_slice(&route_entry_bytes()[..10]);
    let error = decode(&bytes).expect_err("a header plus a 10-octet partial entry must not decode");
    assert_rip_length_error("header-plus-partial-entry", error);
}

#[test]
fn header_plus_non_multiple_of_twenty_body_returns_structured_error() {
    // A valid header followed by a 21-octet body (total 25 octets): the trailing
    // run is not a whole multiple of the 20-octet entry length, so the final
    // partial entry must surface a structured error.
    let mut bytes = vec![0x01u8, 0x02, 0x00, 0x00];
    bytes.extend_from_slice(&route_entry_bytes());
    bytes.push(0x00); // one extra octet => 21-octet trailing run
    assert_eq!(bytes.len(), 25, "body should be exactly 25 octets");
    let error = decode(&bytes).expect_err("a non-multiple-of-20 body must not decode");
    assert_rip_length_error("header-plus-25-octet-body", error);
}

#[test]
fn unknown_command_decodes_header_and_preserves_raw_value() {
    // An unrecognized command (0xC8 = 200) with no entries must still decode the
    // 4-octet header and preserve the raw command value via RipCommand::Other.
    let bytes = [0xC8u8, 0x02, 0x00, 0x00];
    let rip = decode(&bytes).expect("an unknown command with a complete header must decode");
    assert_eq!(
        rip.command_value(),
        0xC8,
        "the raw command octet must be preserved verbatim"
    );
    assert_eq!(
        rip.command(),
        RipCommand::Other(0xC8),
        "an unknown command must surface as RipCommand::Other(raw)"
    );
    assert!(
        rip.entries().is_empty(),
        "a bare header carries no route entries"
    );
}

#[test]
fn over_length_body_with_more_than_twenty_five_entries_decodes() {
    // The RFC 2453 §4 25-entry limit is a generation guideline, not a decode-time
    // rejection: a body with 30 entries (well over 25) must decode successfully.
    // Build the over-length message through the public packet abstraction
    // (`Packet`/`Rip`/`RipEntry` from the prelude and the rip module) and compile
    // it to the wire bytes the decode entrypoint consumes.
    let entry_count = 30usize;
    let entries: Vec<RipEntry> = (0..entry_count)
        .map(|_| RipEntry::ipv1_route(Ipv4Addr::new(192, 0, 2, 0), 1))
        .collect();
    let rip = Rip::response().with_entries(entries);
    let bytes = Packet::from_layer(rip)
        .compile()
        .expect("compiling an over-length RIP message must succeed");
    assert!(
        bytes.len() > 4 + 25 * 20,
        "the body should carry more than the 25-entry guideline"
    );

    let decoded = decode(&bytes).expect("an over-length body must still decode");
    assert_eq!(
        decoded.entries().len(),
        entry_count,
        "every present entry must be decoded, with no 25-entry cap"
    );
}
