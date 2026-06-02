//! Golden byte fixtures pinning current ICMPv4 and ICMPv6 behavior.
//!
//! This file is a deliberate *behavior pin*: it builds representative ICMPv4
//! and ICMPv6 packets with the current public API, compiles them, and asserts
//! the exact emitted bytes against checked-in hex constants. It also decodes
//! each compiled buffer and recompiles it, asserting the round-trip is
//! byte-for-byte identical.
//!
//! The upcoming ICMP restructure (shared/v4/v6 split) and the public-type
//! rename (`Icmp` -> `Icmpv4`, etc.) must not change any of these bytes. Later
//! steps re-run this exact file (`cargo test -p crafter --test icmp_golden`) to
//! detect drift. Keep the test function names stable.
//!
//! Everything here stays offline and uses documentation address space only
//! (`192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`).

use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

const DOC_V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_V4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

const DOC_V6_SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0x0010);
const DOC_V6_DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 2, 0, 0, 0, 0, 0x0020);

fn ipv4() -> Ipv4 {
    // Fixed identification keeps the IPv4 header deterministic across runs so
    // the golden bytes stay stable.
    Ipv4::new().src(DOC_V4_SRC).dst(DOC_V4_DST).id(0x1111)
}

fn ipv6() -> Ipv6 {
    Ipv6::new()
        .src(DOC_V6_SRC)
        .dst(DOC_V6_DST)
        .fl(0x12345)
        .hlim(64)
}

/// Decode an L3 buffer back into typed layers, recompile, and assert the bytes
/// are byte-for-byte identical to the input. This is the round-trip half of the
/// behavior pin.
fn assert_roundtrip(layer: NetworkLayer, golden: &[u8]) {
    let decoded = Packet::decode_from_l3(layer, golden).expect("decode golden bytes");
    let recompiled = decoded.compile().expect("recompile decoded packet");
    assert_eq!(
        recompiled.as_bytes(),
        golden,
        "decode/recompile round-trip changed the bytes"
    );
}

/// Helper used once to mint the golden constants below. Set
/// `CRAFTER_ICMP_GOLDEN_DUMP=1` and run with `--nocapture` to print the
/// freshly-compiled hex for every case; paste the values into the `GOLDEN_*`
/// constants. Not part of normal assertions.
fn maybe_dump(name: &str, bytes: &[u8]) {
    if std::env::var_os("CRAFTER_ICMP_GOLDEN_DUMP").is_some() {
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

// ---------------------------------------------------------------------------
// ICMPv4 golden cases (carried in an IPv4 header).
// ---------------------------------------------------------------------------

const GOLDEN_V4_ECHO_REQUEST: &str =
    "450000201111000040017d7ac000020ac63364140800d6e54242000770696e67";
const GOLDEN_V4_DEST_UNREACH_QUOTED: &str = "4500003d1111000040017d5dc000020ac63364140303e96d00000000450000212222000040116c58c6336414c000020a9c400035000d27247175657279";
const GOLDEN_V4_TIMESTAMP: &str =
    "450000281111000040017d72c000020ac63364140d00f0f100090001000102030000000000000000";
const GOLDEN_V4_ADDRESS_MASK: &str =
    "450000201111000040017d7ac000020ac63364141200eefa00030001ffffff00";
const GOLDEN_V4_ROUTER_ADVERTISEMENT: &str =
    "450000241111000040017d76c000020ac633641409002cea01020708c00002010000000a";
const GOLDEN_V4_RFC4884_MPLS: &str = "450000a81111000040017cf2c000020ac63364140b00e14b002000004500001c3333000040115b4cc6336414c000020a04d2003500080e85000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000d9ce0008010103e80140";

fn build_v4_echo_request() -> Packet {
    ipv4() / Icmpv4::echo_request().id(0x4242).seq(7) / Raw::from("ping")
}

fn build_v4_dest_unreach_quoted() -> Packet {
    let quoted = Ipv4::new().src(DOC_V4_DST).dst(DOC_V4_SRC).id(0x2222)
        / Udp::new().sport(40000).dport(53)
        / Raw::from("query");
    ipv4()
        / Icmpv4::destination_unreachable().code(ICMP_CODE_DU_PORT_UNREACHABLE)
        / IcmpQuotedIpv4::new(quoted)
}

fn build_v4_timestamp() -> Packet {
    ipv4() / Icmpv4::timestamp_request().id(9).seq(1) / IcmpTimestamp::new().originate(0x0001_0203)
}

fn build_v4_address_mask() -> Packet {
    let mask = Ipv4Addr::new(255, 255, 255, 0);
    ipv4() / Icmpv4::address_mask_reply().id(3).seq(1) / IcmpAddressMask::new().mask(mask)
}

fn build_v4_router_advertisement() -> Packet {
    let router = Ipv4Addr::new(192, 0, 2, 1);
    ipv4()
        / Icmpv4::router_advertisement().lifetime(1800)
        / IcmpRouterAdvertisementEntry::new()
            .router_address(router)
            .preference_level(10)
}

fn build_v4_rfc4884_mpls() -> Packet {
    let quoted =
        Ipv4::new().src(DOC_V4_DST).dst(DOC_V4_SRC).id(0x3333) / Udp::new().sport(1234).dport(53);
    ipv4()
        / Icmpv4::time_exceeded().code(ICMP_CODE_TIME_EXCEEDED_TTL)
        / IcmpQuotedIpv4::new(quoted)
        / IcmpExtension::new()
        / IcmpExtensionObject::new()
        / IcmpExtensionMpls::new().label(16000).ttl(64)
}

#[test]
fn icmp_golden_v4_echo_request() {
    let bytes = build_v4_echo_request().compile().expect("compile");
    maybe_dump("V4_ECHO", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_V4_ECHO_REQUEST).as_slice());
    assert_roundtrip(NetworkLayer::Ipv4, bytes.as_bytes());
}

#[test]
fn icmp_golden_v4_destination_unreachable_quoted() {
    let bytes = build_v4_dest_unreach_quoted().compile().expect("compile");
    maybe_dump("V4_DU", bytes.as_bytes());
    assert_eq!(
        bytes.as_bytes(),
        hex(GOLDEN_V4_DEST_UNREACH_QUOTED).as_slice()
    );
    assert_roundtrip(NetworkLayer::Ipv4, bytes.as_bytes());
}

#[test]
fn icmp_golden_v4_timestamp() {
    let bytes = build_v4_timestamp().compile().expect("compile");
    maybe_dump("V4_TS", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_V4_TIMESTAMP).as_slice());
    assert_roundtrip(NetworkLayer::Ipv4, bytes.as_bytes());
}

#[test]
fn icmp_golden_v4_address_mask() {
    let bytes = build_v4_address_mask().compile().expect("compile");
    maybe_dump("V4_MASK", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_V4_ADDRESS_MASK).as_slice());
    assert_roundtrip(NetworkLayer::Ipv4, bytes.as_bytes());
}

#[test]
fn icmp_golden_v4_router_advertisement() {
    let bytes = build_v4_router_advertisement().compile().expect("compile");
    maybe_dump("V4_RA", bytes.as_bytes());
    assert_eq!(
        bytes.as_bytes(),
        hex(GOLDEN_V4_ROUTER_ADVERTISEMENT).as_slice()
    );
    assert_roundtrip(NetworkLayer::Ipv4, bytes.as_bytes());
}

#[test]
fn icmp_golden_v4_rfc4884_mpls_extension() {
    let bytes = build_v4_rfc4884_mpls().compile().expect("compile");
    maybe_dump("V4_EXT", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_V4_RFC4884_MPLS).as_slice());
    assert_roundtrip(NetworkLayer::Ipv4, bytes.as_bytes());
}

// ---------------------------------------------------------------------------
// ICMPv6 golden cases (carried in an IPv6 header so the pseudo-header checksum
// is exercised).
// ---------------------------------------------------------------------------

const GOLDEN_V6_ECHO_REQUEST: &str = "6001234500173a4020010db800010000000000000000001020010db8000200000000000000000020800000d0424200026c6962637261667465722d69707636";
const GOLDEN_V6_DEST_UNREACH: &str = "60012345003d3a4020010db800010000000000000000001020010db800020000000000000000002001042bb00600000060000000000d114020010db800020000000000000000002020010db80001000000000000000000109c400035000db7d17175657279";
const GOLDEN_V6_PACKET_TOO_BIG: &str = "60012345003d3a4020010db800010000000000000000001020010db800020000000000000000002002002bb40000050060000000000d114020010db800020000000000000000002020010db80001000000000000000000109c400035000db7d17175657279";
const GOLDEN_V6_TIME_EXCEEDED: &str = "60012345003d3a4020010db800010000000000000000001020010db8000200000000000000000020030029b40600000060000000000d114020010db800020000000000000000002020010db80001000000000000000000109c400035000db7d17175657279";
const GOLDEN_V6_PARAMETER_PROBLEM: &str = "60012345003d3a4020010db800010000000000000000001020010db800020000000000000000002004002eae0000000660000000000d114020010db800020000000000000000002020010db80001000000000000000000109c400035000db7d17175657279";

/// An IPv6 datagram quoted inside an ICMPv6 error message.
fn v6_quoted() -> Packet {
    Ipv6::new().src(DOC_V6_DST).dst(DOC_V6_SRC).hlim(64)
        / Udp::new().sport(40000).dport(53)
        / Raw::from("query")
}

fn build_v6_echo_request() -> Packet {
    ipv6() / Icmpv6::echo_request().id(0x4242).seq(2) / Raw::from("libcrafter-ipv6")
}

fn build_v6_dest_unreach() -> Packet {
    ipv6() / Icmpv6::destination_unreachable().code(4) / v6_quoted()
}

fn build_v6_packet_too_big() -> Packet {
    ipv6() / Icmpv6::packet_too_big().mtu(1280) / v6_quoted()
}

fn build_v6_time_exceeded() -> Packet {
    ipv6() / Icmpv6::time_exceeded().code(0) / v6_quoted()
}

fn build_v6_parameter_problem() -> Packet {
    ipv6()
        / Icmpv6::new()
            .icmp_type(ICMPV6_PARAMETER_PROBLEM)
            .code(0)
            .pointer(6)
        / v6_quoted()
}

#[test]
fn icmp_golden_v6_echo_request() {
    let bytes = build_v6_echo_request().compile().expect("compile");
    maybe_dump("V6_ECHO", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_V6_ECHO_REQUEST).as_slice());
    assert_roundtrip(NetworkLayer::Ipv6, bytes.as_bytes());
}

#[test]
fn icmp_golden_v6_destination_unreachable() {
    let bytes = build_v6_dest_unreach().compile().expect("compile");
    maybe_dump("V6_DU", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_V6_DEST_UNREACH).as_slice());
    assert_roundtrip(NetworkLayer::Ipv6, bytes.as_bytes());
}

#[test]
fn icmp_golden_v6_packet_too_big() {
    let bytes = build_v6_packet_too_big().compile().expect("compile");
    maybe_dump("V6_PTB", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_V6_PACKET_TOO_BIG).as_slice());
    assert_roundtrip(NetworkLayer::Ipv6, bytes.as_bytes());
}

#[test]
fn icmp_golden_v6_time_exceeded() {
    let bytes = build_v6_time_exceeded().compile().expect("compile");
    maybe_dump("V6_TE", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_V6_TIME_EXCEEDED).as_slice());
    assert_roundtrip(NetworkLayer::Ipv6, bytes.as_bytes());
}

#[test]
fn icmp_golden_v6_parameter_problem() {
    let bytes = build_v6_parameter_problem().compile().expect("compile");
    maybe_dump("V6_PP", bytes.as_bytes());
    assert_eq!(
        bytes.as_bytes(),
        hex(GOLDEN_V6_PARAMETER_PROBLEM).as_slice()
    );
    assert_roundtrip(NetworkLayer::Ipv6, bytes.as_bytes());
}
