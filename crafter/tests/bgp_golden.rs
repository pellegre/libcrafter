//! Golden byte fixtures pinning current BGP-4 (RFC 4271) wire behavior.
//!
//! This file is a deliberate *behavior pin*: it builds representative BGP-4
//! messages with the current public API, compiles them, and asserts the exact
//! emitted bytes against checked-in hex constants. It also round-trips each
//! case (see `assert_roundtrip`) so a refactor that changes the bytes fails
//! here on purpose.
//!
//! KEEPALIVE (RFC 4271 §4.4) is the 16-octet all-ones Marker, a Length field of
//! `0x0013` (19), and a Type of `0x04`, so its golden hex is
//! `ffffffffffffffffffffffffffffffff001304`.
//!
//! Everything here stays offline. BGP messages carry no addresses, so there is
//! no live target surface in this file.

use crafter::prelude::*;
use crafter::protocols::bgp::attribute::{
    BgpAttrValue, BgpPathAttribute, BgpPrefix, BGP_ORIGIN_IGP,
};
use crafter::protocols::bgp::COMMUNITY_NO_EXPORT;
use std::net::Ipv4Addr;

/// Helper used once to mint the golden constants below. Set
/// `CRAFTER_BGP_GOLDEN_DUMP=1` and run with `--nocapture` to print the
/// freshly-compiled hex for every case; paste the values into the `GOLDEN_*`
/// constants. Not part of normal assertions.
fn maybe_dump(name: &str, bytes: &[u8]) {
    if std::env::var_os("CRAFTER_BGP_GOLDEN_DUMP").is_some() {
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

/// Round-trip half of the behavior pin: decode the BGP message from the pinned
/// bytes, recompile it, and assert the bytes are identical.
fn assert_roundtrip(golden: &[u8]) {
    let (decoded, consumed) =
        crafter::protocols::bgp::decode::decode_bgp_message(golden).expect("decode BGP golden");
    assert_eq!(
        consumed,
        golden.len(),
        "decoder must consume one full message"
    );
    let rebuilt = Packet::from_layer(decoded)
        .compile()
        .expect("recompile decoded BGP");
    assert_eq!(
        rebuilt.as_bytes(),
        golden,
        "rebuild/recompile round-trip changed the bytes"
    );
}

// ---------------------------------------------------------------------------
// KEEPALIVE (RFC 4271 §4.4): the 19-octet header alone — all-ones Marker,
// Length 0x0013, Type 0x04.
// ---------------------------------------------------------------------------

const GOLDEN_KEEPALIVE: &str = "ffffffffffffffffffffffffffffffff001304";

#[test]
fn bgp_golden_keepalive() {
    let bytes = Packet::from_layer(Bgp::keepalive())
        .compile()
        .expect("compile");
    maybe_dump("KEEPALIVE", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_KEEPALIVE).as_slice());
    assert_roundtrip(bytes.as_bytes());
}

// ---------------------------------------------------------------------------
// OPEN (RFC 4271 §4.2): version 4, AS 65000, hold time 180, BGP identifier
// 192.0.2.1, and one capabilities optional parameter containing MP-BGP
// IPv4-unicast, 4-octet-ASN(65000), and Route-Refresh.
// ---------------------------------------------------------------------------

const GOLDEN_OPEN: &str =
    "ffffffffffffffffffffffffffffffff002d0104fde800b4c000020110020e01040001000141040000fde80200";

fn build_open() -> Packet {
    Packet::from_layer(
        Bgp::open()
            .version(4)
            .my_as(65000)
            .hold_time(180)
            .bgp_id([192, 0, 2, 1])
            .capabilities([
                BgpCapability::ipv4_unicast(),
                BgpCapability::four_octet_as(65000),
                BgpCapability::route_refresh(),
            ]),
    )
}

#[test]
fn bgp_golden_open() {
    let bytes = build_open().compile().expect("compile");
    maybe_dump("OPEN", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_OPEN).as_slice());
    assert_roundtrip(bytes.as_bytes());
}

// ---------------------------------------------------------------------------
// NOTIFICATION (RFC 4271 §4.5): Cease with subcode 0 and no diagnostic data.
// The body is exactly the error code/subcode pair, so the Length is 21.
// ---------------------------------------------------------------------------

#[test]
fn bgp_golden_notification() {
    let bytes = Packet::from_layer(Bgp::cease()).compile().expect("compile");
    maybe_dump("NOTIFICATION", bytes.as_bytes());
    assert_eq!(
        bytes.as_bytes(),
        hex("ffffffffffffffffffffffffffffffff0015030600").as_slice()
    );
    assert_roundtrip(bytes.as_bytes());

    let with_data = Packet::from_layer(Bgp::cease().data(vec![0xde, 0xad]))
        .compile()
        .expect("compile notification with data");
    assert_eq!(
        with_data.as_bytes(),
        hex("ffffffffffffffffffffffffffffffff0017030600dead").as_slice()
    );
    assert_roundtrip(with_data.as_bytes());
}

// ---------------------------------------------------------------------------
// ROUTE-REFRESH (RFC 2918): IPv4-unicast has AFI 0x0001, a reserved byte of
// 0x00, SAFI 0x01, and total Length 23.
// ---------------------------------------------------------------------------

#[test]
fn bgp_golden_route_refresh() {
    let bytes = Packet::from_layer(Bgp::route_refresh(1, 1))
        .compile()
        .expect("compile");
    maybe_dump("ROUTE_REFRESH", bytes.as_bytes());
    assert_eq!(
        bytes.as_bytes(),
        hex("ffffffffffffffffffffffffffffffff00170500010001").as_slice()
    );
    assert_eq!(
        bytes.as_bytes()[21],
        0,
        "reserved/subtype byte defaults to zero"
    );
    assert_roundtrip(bytes.as_bytes());

    let enhanced = Packet::from_layer(Bgp::route_refresh(1, 1).subtype(1))
        .compile()
        .expect("compile enhanced route refresh");
    assert_eq!(
        enhanced.as_bytes(),
        hex("ffffffffffffffffffffffffffffffff00170500010101").as_slice()
    );
    assert_roundtrip(enhanced.as_bytes());
}

// ---------------------------------------------------------------------------
// UPDATE announcement (RFC 4271 §4.3): no withdrawn routes, ORIGIN=IGP,
// AS_PATH sequence containing AS 65000, NEXT_HOP 192.0.2.1, and NLRI
// 203.0.113.0/24.
// ---------------------------------------------------------------------------

const GOLDEN_UPDATE_ANNOUNCE: &str =
    "ffffffffffffffffffffffffffffffff002d0200000012400101004002040201fde8400304c000020118cb0071";

fn build_update_announce() -> Packet {
    Packet::from_layer(
        Bgp::update()
            .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
            .attribute(BgpPathAttribute::as_sequence(&[65000]))
            .attribute(BgpPathAttribute::next_hop(Ipv4Addr::new(192, 0, 2, 1)))
            .nlri(
                BgpPrefix::from_ipv4(Ipv4Addr::new(203, 0, 113, 0), 24).expect("valid IPv4 prefix"),
            ),
    )
}

#[test]
fn bgp_golden_update_announce() {
    let bytes = build_update_announce().compile().expect("compile");
    maybe_dump("UPDATE_ANNOUNCE", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_UPDATE_ANNOUNCE).as_slice());
    assert_eq!(&bytes.as_bytes()[19..21], &[0x00, 0x00]);
    assert_eq!(&bytes.as_bytes()[21..23], &[0x00, 0x12]);
    assert_eq!(
        &bytes.as_bytes()[bytes.as_bytes().len() - 4..],
        &[0x18, 0xcb, 0x00, 0x71]
    );
    assert_roundtrip(bytes.as_bytes());
}

// ---------------------------------------------------------------------------
// UPDATE announcement with COMMUNITIES (RFC 1997): announces 203.0.113.0/24
// with ORIGIN=IGP, AS_PATH sequence containing AS 65000, NEXT_HOP 192.0.2.1,
// and COMMUNITIES 65000:100 plus NO_EXPORT.
// ---------------------------------------------------------------------------

const GOLDEN_UPDATE_COMMUNITIES: &str =
    "ffffffffffffffffffffffffffffffff0038020000001d400101004002040201fde8400304c0000201c00808fde80064ffffff0118cb0071";

fn build_update_communities() -> Packet {
    Packet::from_layer(
        Bgp::update()
            .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
            .attribute(BgpPathAttribute::as_sequence(&[65000]))
            .attribute(BgpPathAttribute::next_hop(Ipv4Addr::new(192, 0, 2, 1)))
            .attribute(BgpPathAttribute::communities(&[
                0xFDE8_0064,
                COMMUNITY_NO_EXPORT,
            ]))
            .nlri(
                BgpPrefix::from_ipv4(Ipv4Addr::new(203, 0, 113, 0), 24).expect("valid IPv4 prefix"),
            ),
    )
}

#[test]
fn bgp_golden_update_communities() {
    let communities = [0xFDE8_0064, COMMUNITY_NO_EXPORT];
    let bytes = build_update_communities().compile().expect("compile");
    maybe_dump("UPDATE_COMMUNITIES", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_UPDATE_COMMUNITIES).as_slice());

    let body = &bytes.as_bytes()[19..];
    let attr_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let attrs = &body[4..4 + attr_len];
    let communities_offset = attrs.len() - 11;
    let communities_bytes = &attrs[communities_offset..];
    assert_eq!(&communities_bytes[..2], &[0xC0, 0x08]);

    let (decoded, consumed) =
        crafter::protocols::bgp::attribute::decode_attribute(communities_bytes)
            .expect("decode communities attribute");
    assert_eq!(consumed, communities_bytes.len());
    assert_eq!(
        decoded.value,
        BgpAttrValue::Communities(communities.to_vec())
    );
    assert_roundtrip(bytes.as_bytes());
}

// ---------------------------------------------------------------------------
// UPDATE with unknown path attribute: preserves optional/transitive flags,
// unknown type 99, raw value bytes, and NLRI 203.0.113.0/24.
// ---------------------------------------------------------------------------

const GOLDEN_UPDATE_UNKNOWN_ATTR: &str =
    "ffffffffffffffffffffffffffffffff00330200000018400101004002040201fde8400304c0000201c06303aabbcc18cb0071";

fn build_update_unknown_attr() -> Packet {
    Packet::from_layer(
        Bgp::update()
            .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
            .attribute(BgpPathAttribute::as_sequence(&[65000]))
            .attribute(BgpPathAttribute::next_hop(Ipv4Addr::new(192, 0, 2, 1)))
            .attribute(BgpPathAttribute::unknown(99, vec![0xaa, 0xbb, 0xcc]).with_flags(0xc0))
            .nlri(
                BgpPrefix::from_ipv4(Ipv4Addr::new(203, 0, 113, 0), 24).expect("valid IPv4 prefix"),
            ),
    )
}

#[test]
fn bgp_golden_update_unknown_attr() {
    let bytes = build_update_unknown_attr().compile().expect("compile");
    maybe_dump("UPDATE_UNKNOWN_ATTR", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_UPDATE_UNKNOWN_ATTR).as_slice());

    let body = &bytes.as_bytes()[19..];
    let attr_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let attrs = &body[4..4 + attr_len];
    let unknown_offset = attrs.len() - 6;
    let (unknown, consumed) =
        crafter::protocols::bgp::attribute::decode_attribute(&attrs[unknown_offset..])
            .expect("decode unknown attribute");
    assert_eq!(consumed, 6);
    assert_eq!(unknown.flags.value(), Some(&0xc0));
    assert_eq!(unknown.type_code, 99);
    assert_eq!(unknown.value, BgpAttrValue::Unknown(vec![0xaa, 0xbb, 0xcc]));
    assert_roundtrip(bytes.as_bytes());
}

// ---------------------------------------------------------------------------
// UPDATE withdraw (RFC 4271 §4.3): one withdrawn route for 203.0.113.0/24,
// no path attributes, and no NLRI.
// ---------------------------------------------------------------------------

const GOLDEN_UPDATE_WITHDRAW: &str = "ffffffffffffffffffffffffffffffff001b02000418cb00710000";

fn build_update_withdraw() -> Packet {
    Packet::from_layer(Bgp::update().withdraw(
        BgpPrefix::from_ipv4(Ipv4Addr::new(203, 0, 113, 0), 24).expect("valid IPv4 prefix"),
    ))
}

#[test]
fn bgp_golden_update_withdraw() {
    let bytes = build_update_withdraw().compile().expect("compile");
    maybe_dump("UPDATE_WITHDRAW", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_UPDATE_WITHDRAW).as_slice());
    assert_eq!(&bytes.as_bytes()[16..18], &[0x00, 0x1b]);
    assert_eq!(&bytes.as_bytes()[19..21], &[0x00, 0x04]);
    assert_eq!(&bytes.as_bytes()[21..25], &[0x18, 0xcb, 0x00, 0x71]);
    assert_eq!(&bytes.as_bytes()[25..27], &[0x00, 0x00]);
    assert_roundtrip(bytes.as_bytes());
}
