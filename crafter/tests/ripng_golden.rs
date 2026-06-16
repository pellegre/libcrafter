//! Golden byte fixtures pinning current RIPng (RFC 2080) wire behavior.
//!
//! This file is a deliberate *behavior pin*: it builds representative RIPng
//! messages with the current public API, compiles the `Ripng` payload, and
//! asserts the exact emitted bytes against checked-in hex constants derived from
//! the RFC 2080 layout. It also round-trips each case (decode the pinned bytes
//! and compare field values via the public accessors, including the next-hop RTE
//! classification) so a refactor that changes the bytes fails here on purpose.
//!
//! A RIPng message is the 4-octet header (command, version, 2-octet reserved;
//! RFC 2080 §2) followed by zero or more fixed 20-octet route table entries
//! (16-octet IPv6 prefix, 2-octet route tag, 1-octet prefix length, 1-octet
//! metric; RFC 2080 §2.1). A next-hop RTE is marked by a metric of `0xFF`
//! (RFC 2080 §2.1.1) and carries the next-hop address in its prefix field with
//! route tag and prefix length zero.
//!
//! Everything here stays offline and uses documentation address space
//! (`2001:db8::/32`), so there is no live target surface.

use std::net::Ipv6Addr;

use crafter::prelude::*;
use crafter::protocols::rip::ripng::decode;

/// Helper used once to mint the golden constants below. Set
/// `CRAFTER_RIPNG_GOLDEN_DUMP=1` and run with `--nocapture` to print the
/// freshly-compiled hex for every case; paste the values into the `GOLDEN_*`
/// constants. Not part of normal assertions.
fn maybe_dump(name: &str, bytes: &[u8]) {
    if std::env::var_os("CRAFTER_RIPNG_GOLDEN_DUMP").is_some() {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        println!("GOLDEN {name} = \"{hex}\"");
    }
}

/// Parse a compact hex string ("00ff..") into bytes for a golden constant.
fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "golden hex must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Compile the RIPng payload of a built `Ripng` layer to its exact wire bytes.
fn ripng_bytes(ripng: Ripng) -> Vec<u8> {
    Packet::from_layer(ripng)
        .compile()
        .expect("compile RIPng layer")
        .as_bytes()
        .to_vec()
}

/// Parse a documentation-range IPv6 prefix for a golden fixture.
fn prefix(s: &str) -> Ipv6Addr {
    s.parse::<Ipv6Addr>().expect("valid IPv6 prefix")
}

// ---------------------------------------------------------------------------
// RIPng whole-table request (RFC 2080 §2.4.1).
//
// A RIPng Request asking for the peer's complete routing table carries the
// 4-octet header — command 0x01 (Request), version 0x01, reserved 0x0000 —
// followed by a single special RTE whose prefix is `::`, prefix length 0, route
// tag 0, and metric 16 (infinity), the whole-table sentinel.
//
//   header : 01 01 0000
//   rte    : 00000000000000000000000000000000   prefix ::
//            0000                                route tag 0
//            00                                  prefix length 0
//            10                                  metric 16 (infinity)
// ---------------------------------------------------------------------------

const GOLDEN_REQUEST: &str = "010100000000000000000000000000000000000000000010";

fn build_request() -> Ripng {
    Ripng::request().rte(RipngRte::whole_table_request())
}

#[test]
fn ripng_golden_whole_table_request() {
    let bytes = ripng_bytes(build_request());
    maybe_dump("REQUEST", &bytes);
    assert_eq!(bytes, hex(GOLDEN_REQUEST));

    let decoded = decode(&bytes).expect("decode RIPng request golden");
    assert_eq!(decoded.command(), RipCommand::Request);
    assert_eq!(decoded.version_value(), RIPNG_VERSION_1);
    assert_eq!(decoded.reserved_value(), 0);
    assert_eq!(decoded.rtes().len(), 1);
    let rte = &decoded.rtes()[0];
    assert_eq!(rte.prefix_value(), Ipv6Addr::UNSPECIFIED);
    assert_eq!(rte.route_tag_value(), 0);
    assert_eq!(rte.prefix_len_value(), 0);
    assert_eq!(rte.metric_value(), RIPNG_METRIC_INFINITY);
    assert!(rte.is_whole_table_request());
    assert!(!rte.is_next_hop());
}

// ---------------------------------------------------------------------------
// RIPng response with a next-hop RTE followed by two route RTEs (RFC 2080 §2.1
// / §2.1.1).
//
// The leading next-hop RTE (metric 0xFF) names the IPv6 next hop for the route
// RTEs that follow; the two route RTEs then advertise `2001:db8::/32` prefixes
// with their own metrics. A next-hop RTE has route tag 0 and prefix length 0
// (RFC 2080 §2.1.1).
//
//   header   : 02 01 0000                       command Response, version 1
//   next hop : 20010db8000000000000000000000001 prefix 2001:db8::1 (next hop)
//              0000                              route tag 0
//              00                                prefix length 0
//              ff                                metric 0xFF (next-hop marker)
//   route 1  : 20010db8000000000000000000000000 prefix 2001:db8::
//              0000                              route tag 0
//              20                                prefix length 32
//              01                                metric 1
//   route 2  : 20010db8000100000000000000000000 prefix 2001:db8:1::
//              162e                              route tag 0x162e (5678)
//              30                                prefix length 48
//              02                                metric 2
// ---------------------------------------------------------------------------

const GOLDEN_RESPONSE: &str = concat!(
    "02010000",                                 // header: Response, v1, reserved 0
    "20010db8000000000000000000000001000000ff", // next hop 2001:db8::1, m 0xFF
    "20010db800000000000000000000000000002001", // route 2001:db8::/32 m1
    "20010db8000100000000000000000000162e3002", // route 2001:db8:1::/48 tag m2
);

fn build_response() -> Ripng {
    Ripng::response().with_rtes(vec![
        RipngRte::next_hop(prefix("2001:db8::1")),
        RipngRte::route(prefix("2001:db8::"), 32, 1),
        RipngRte::route(prefix("2001:db8:1::"), 48, 2).route_tag(0x162e),
    ])
}

#[test]
fn ripng_golden_response_with_next_hop() {
    let bytes = ripng_bytes(build_response());
    maybe_dump("RESPONSE", &bytes);
    assert_eq!(bytes, hex(GOLDEN_RESPONSE));

    let decoded = decode(&bytes).expect("decode RIPng response golden");
    assert_eq!(decoded.command(), RipCommand::Response);
    assert_eq!(decoded.version_value(), RIPNG_VERSION_1);
    assert_eq!(decoded.reserved_value(), 0);
    assert_eq!(decoded.rtes().len(), 3);

    // The leading RTE is the next-hop RTE (metric 0xFF): it carries the next-hop
    // address in its prefix and classifies as a next-hop RTE.
    let next_hop = &decoded.rtes()[0];
    assert!(next_hop.is_next_hop());
    assert_eq!(next_hop.metric_value(), RIPNG_NEXT_HOP_METRIC);
    assert_eq!(next_hop.next_hop_address(), Some(prefix("2001:db8::1")));
    assert_eq!(next_hop.route_tag_value(), 0);
    assert_eq!(next_hop.prefix_len_value(), 0);

    // The first route RTE: 2001:db8::/32 metric 1, not a next-hop RTE.
    let route1 = &decoded.rtes()[1];
    assert!(!route1.is_next_hop());
    assert_eq!(route1.prefix_value(), prefix("2001:db8::"));
    assert_eq!(route1.prefix_len_value(), 32);
    assert_eq!(route1.metric_value(), 1);
    assert_eq!(route1.route_tag_value(), 0);

    // The second route RTE: 2001:db8:1::/48 metric 2 with a route tag set.
    let route2 = &decoded.rtes()[2];
    assert!(!route2.is_next_hop());
    assert_eq!(route2.prefix_value(), prefix("2001:db8:1::"));
    assert_eq!(route2.prefix_len_value(), 48);
    assert_eq!(route2.metric_value(), 2);
    assert_eq!(route2.route_tag_value(), 0x162e);
}
