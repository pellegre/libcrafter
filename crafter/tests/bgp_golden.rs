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
    well_known_flags, BgpAttrValue, BgpPathAttribute, BgpPrefix, BGP_ORIGIN_IGP,
};
use crafter::protocols::bgp::{
    AS_TRANS, ATTR_ORIGIN, BGP_HEADER_LEN, BGP_MARKER_LEN, BGP_TYPE_KEEPALIVE, COMMUNITY_NO_EXPORT,
};
use std::net::{Ipv4Addr, Ipv6Addr};

const AS4_ASN: u32 = 4_200_000_000;

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
// OPEN with RFC 6793 4-octet-ASN capability: AS_TRANS (23456) is carried in
// the RFC 4271 two-octet My Autonomous System field while the real 4-octet AS
// value is advertised in the capability block.
// ---------------------------------------------------------------------------

const GOLDEN_OPEN_AS4: &str =
    "ffffffffffffffffffffffffffffffff002d01045ba000b4c000020110020e0104000100014104fa56ea000200";

fn build_open_as4() -> Packet {
    Packet::from_layer(
        Bgp::open()
            .version(4)
            .my_as(AS_TRANS)
            .hold_time(180)
            .bgp_id([192, 0, 2, 1])
            .capabilities([
                BgpCapability::ipv4_unicast(),
                BgpCapability::four_octet_as(AS4_ASN),
                BgpCapability::route_refresh(),
            ]),
    )
}

#[test]
fn bgp_golden_open_as4() {
    let bytes = build_open_as4().compile().expect("compile");
    maybe_dump("OPEN_AS4", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_OPEN_AS4).as_slice());
    assert_eq!(&bytes.as_bytes()[20..22], &AS_TRANS.to_be_bytes());

    let opt_params_len = bytes.as_bytes()[28] as usize;
    assert_eq!(opt_params_len, 16);
    assert_eq!(&bytes.as_bytes()[29..31], &[2, 14]);
    let capabilities =
        crafter::protocols::bgp::capability::decode_capabilities(&bytes.as_bytes()[31..31 + 14])
            .expect("decode OPEN capabilities");
    assert_eq!(capabilities.len(), 3);
    assert_eq!(
        capabilities[1]
            .four_octet_asn()
            .expect("four-octet AS capability parses"),
        AS4_ASN
    );
    assert_eq!(capabilities[2], BgpCapability::route_refresh());
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
// UPDATE announcement with a 4-octet AS_PATH: announces 203.0.113.0/24 with
// ORIGIN=IGP, AS_PATH sequence containing AS 4200000000 as a four-octet AS,
// and NEXT_HOP 192.0.2.1.
// ---------------------------------------------------------------------------

const GOLDEN_UPDATE_AS4_PATH: &str =
    "ffffffffffffffffffffffffffffffff002f0200000014400101004002060201fa56ea00400304c000020118cb0071";

fn build_update_as4_path() -> Packet {
    Packet::from_layer(
        Bgp::update()
            .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
            .attribute(BgpPathAttribute::as_sequence4(&[AS4_ASN]))
            .attribute(BgpPathAttribute::next_hop(Ipv4Addr::new(192, 0, 2, 1)))
            .nlri(
                BgpPrefix::from_ipv4(Ipv4Addr::new(203, 0, 113, 0), 24).expect("valid IPv4 prefix"),
            ),
    )
}

#[test]
fn bgp_golden_update_as4_path() {
    let bytes = build_update_as4_path().compile().expect("compile");
    maybe_dump("UPDATE_AS4_PATH", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_UPDATE_AS4_PATH).as_slice());

    let body = &bytes.as_bytes()[19..];
    assert_eq!(&body[..2], &[0x00, 0x00]);
    let attr_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let attrs = &body[4..4 + attr_len];
    let (_origin, origin_len) =
        crafter::protocols::bgp::attribute::decode_attribute(attrs).expect("decode ORIGIN");
    let as_path_bytes = &attrs[origin_len..origin_len + 9];
    assert_eq!(
        as_path_bytes,
        &[0x40, 0x02, 0x06, 0x02, 0x01, 0xfa, 0x56, 0xea, 0x00]
    );
    assert_eq!(&as_path_bytes[5..9], &AS4_ASN.to_be_bytes());
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
// UPDATE announcement with EXTENDED COMMUNITIES (RFC 4360): announces
// 203.0.113.0/24 with ORIGIN=IGP, AS_PATH sequence containing AS 65000,
// NEXT_HOP 192.0.2.1, and one two-octet-AS Route Target extended community.
// ---------------------------------------------------------------------------

const GOLDEN_UPDATE_EXT_COMMUNITIES: &str =
    "ffffffffffffffffffffffffffffffff0038020000001d400101004002040201fde8400304c0000201c010080002fde80000006418cb0071";

fn build_update_ext_communities() -> Packet {
    let route_target = [0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64];
    Packet::from_layer(
        Bgp::update()
            .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
            .attribute(BgpPathAttribute::as_sequence(&[65000]))
            .attribute(BgpPathAttribute::next_hop(Ipv4Addr::new(192, 0, 2, 1)))
            .attribute(BgpPathAttribute::extended_communities(&[route_target]))
            .nlri(
                BgpPrefix::from_ipv4(Ipv4Addr::new(203, 0, 113, 0), 24).expect("valid IPv4 prefix"),
            ),
    )
}

#[test]
fn bgp_golden_update_ext_communities() {
    let route_target = [0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64];
    let bytes = build_update_ext_communities().compile().expect("compile");
    maybe_dump("UPDATE_EXT_COMMUNITIES", bytes.as_bytes());
    assert_eq!(
        bytes.as_bytes(),
        hex(GOLDEN_UPDATE_EXT_COMMUNITIES).as_slice()
    );

    let body = &bytes.as_bytes()[19..];
    let attr_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let attrs = &body[4..4 + attr_len];
    let ext_communities_offset = attrs.len() - 11;
    let ext_communities_bytes = &attrs[ext_communities_offset..];
    assert_eq!(&ext_communities_bytes[..2], &[0xC0, 0x10]);

    let (decoded, consumed) =
        crafter::protocols::bgp::attribute::decode_attribute(ext_communities_bytes)
            .expect("decode extended communities attribute");
    assert_eq!(consumed, ext_communities_bytes.len());
    assert_eq!(
        decoded.value,
        BgpAttrValue::ExtendedCommunities(vec![route_target])
    );
    assert_roundtrip(bytes.as_bytes());
}

// ---------------------------------------------------------------------------
// UPDATE announcement with LARGE_COMMUNITIES (RFC 8092): announces
// 203.0.113.0/24 with ORIGIN=IGP, AS_PATH sequence containing AS 65000,
// NEXT_HOP 192.0.2.1, and one large community 65000:1:2.
// ---------------------------------------------------------------------------

const GOLDEN_UPDATE_LARGE_COMMUNITIES: &str =
    "ffffffffffffffffffffffffffffffff003c0200000021400101004002040201fde8400304c0000201c0200c0000fde8000000010000000218cb0071";

fn build_update_large_communities() -> Packet {
    Packet::from_layer(
        Bgp::update()
            .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
            .attribute(BgpPathAttribute::as_sequence(&[65000]))
            .attribute(BgpPathAttribute::next_hop(Ipv4Addr::new(192, 0, 2, 1)))
            .attribute(BgpPathAttribute::large_communities(&[[65000, 1, 2]]))
            .nlri(
                BgpPrefix::from_ipv4(Ipv4Addr::new(203, 0, 113, 0), 24).expect("valid IPv4 prefix"),
            ),
    )
}

#[test]
fn bgp_golden_update_large_communities() {
    let large_communities = [[65000, 1, 2]];
    let bytes = build_update_large_communities().compile().expect("compile");
    maybe_dump("UPDATE_LARGE_COMMUNITIES", bytes.as_bytes());
    assert_eq!(
        bytes.as_bytes(),
        hex(GOLDEN_UPDATE_LARGE_COMMUNITIES).as_slice()
    );

    let body = &bytes.as_bytes()[19..];
    let attr_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let attrs = &body[4..4 + attr_len];
    let large_communities_offset = attrs.len() - 15;
    let large_communities_bytes = &attrs[large_communities_offset..];
    assert_eq!(&large_communities_bytes[..2], &[0xC0, 0x20]);

    let (decoded, consumed) =
        crafter::protocols::bgp::attribute::decode_attribute(large_communities_bytes)
            .expect("decode large communities attribute");
    assert_eq!(consumed, large_communities_bytes.len());
    assert_eq!(
        decoded.value,
        BgpAttrValue::LargeCommunities(large_communities.to_vec())
    );
    assert_roundtrip(bytes.as_bytes());
}

// ---------------------------------------------------------------------------
// UPDATE announcement with MP_REACH_NLRI (RFC 4760): carries IPv6-unicast
// reachability for 2001:db8::/32 with next hop 2001:db8::1, alongside ORIGIN
// and AS_PATH, and intentionally no top-level IPv4 NLRI bytes.
// ---------------------------------------------------------------------------

const GOLDEN_UPDATE_MP_REACH: &str =
    "ffffffffffffffffffffffffffffffff003f0200000028400101004002040201fde8800e1a0002011020010db8000000000000000000000001002020010db8";

fn build_update_mp_reach() -> Packet {
    let next_hop = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    let nlri = [
        BgpPrefix::from_ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)
            .expect("valid IPv6 prefix"),
    ];

    Packet::from_layer(
        Bgp::update()
            .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
            .attribute(BgpPathAttribute::as_sequence(&[65000]))
            .attribute(BgpPathAttribute::mp_reach_ipv6(next_hop, &nlri)),
    )
}

#[test]
fn bgp_golden_update_mp_reach() {
    let next_hop = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    let nlri = [
        BgpPrefix::from_ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)
            .expect("valid IPv6 prefix"),
    ];
    let bytes = build_update_mp_reach().compile().expect("compile");
    maybe_dump("UPDATE_MP_REACH", bytes.as_bytes());
    assert_eq!(bytes.as_bytes(), hex(GOLDEN_UPDATE_MP_REACH).as_slice());

    let body = &bytes.as_bytes()[19..];
    assert_eq!(&body[..2], &[0x00, 0x00]);
    let attr_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let attrs = &body[4..4 + attr_len];
    assert_eq!(body.len(), 4 + attr_len, "expected no top-level IPv4 NLRI");

    let (_origin, origin_len) =
        crafter::protocols::bgp::attribute::decode_attribute(attrs).expect("decode ORIGIN");
    let (_as_path, as_path_len) =
        crafter::protocols::bgp::attribute::decode_attribute(&attrs[origin_len..])
            .expect("decode AS_PATH");
    let mp_reach_bytes = &attrs[origin_len + as_path_len..];
    assert_eq!(&mp_reach_bytes[..2], &[0x80, 0x0e]);

    let (decoded, consumed) = crafter::protocols::bgp::attribute::decode_attribute(mp_reach_bytes)
        .expect("decode MP_REACH_NLRI attribute");
    assert_eq!(consumed, mp_reach_bytes.len());
    assert_eq!(
        decoded.value,
        BgpAttrValue::MpReachNlri {
            afi: 2,
            safi: 1,
            next_hop: next_hop.octets().to_vec(),
            nlri: nlri.to_vec(),
        }
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

// ---------------------------------------------------------------------------
// Malformed-on-purpose compile overrides: generated tools sometimes need to
// emit invalid BGP while preserving exactly what the caller asked for. These
// tests assert compile-time preservation only; malformed decode is separate.
// ---------------------------------------------------------------------------

#[test]
fn bgp_compile_preserves_forced_open_message_length() {
    let forced_length = 31u16;
    let bytes = Packet::from_layer(
        Bgp::open()
            .my_as(65000)
            .hold_time(180)
            .bgp_id([192, 0, 2, 1])
            .length(forced_length),
    )
    .compile()
    .expect("compile OPEN with malformed length override");

    assert_eq!(bytes.len(), BGP_HEADER_LEN + 10);
    assert_ne!(forced_length as usize, bytes.len());
    assert_eq!(
        &bytes.as_bytes()[BGP_MARKER_LEN..BGP_MARKER_LEN + 2],
        &forced_length.to_be_bytes()
    );
}

#[test]
fn bgp_compile_preserves_forced_keepalive_marker() {
    let bytes = Packet::from_layer(Bgp::keepalive().marker([0x00; BGP_MARKER_LEN]))
        .compile()
        .expect("compile KEEPALIVE with malformed marker override");

    assert_eq!(&bytes.as_bytes()[..BGP_MARKER_LEN], &[0x00; BGP_MARKER_LEN]);
    assert_eq!(
        &bytes.as_bytes()[BGP_MARKER_LEN..BGP_MARKER_LEN + 2],
        &(BGP_HEADER_LEN as u16).to_be_bytes()
    );
    assert_eq!(bytes.as_bytes()[BGP_MARKER_LEN + 2], BGP_TYPE_KEEPALIVE);
}

#[test]
fn bgp_compile_preserves_forced_update_withdrawn_length() {
    let forced_withdrawn_len = 9u16;
    let bytes = Packet::from_layer(
        Bgp::update()
            .withdraw(
                BgpPrefix::from_ipv4(Ipv4Addr::new(203, 0, 113, 0), 24).expect("valid IPv4 prefix"),
            )
            .withdrawn_len(forced_withdrawn_len),
    )
    .compile()
    .expect("compile UPDATE with malformed withdrawn length override");

    let body = &bytes.as_bytes()[BGP_HEADER_LEN..];
    assert_eq!(&body[..2], &forced_withdrawn_len.to_be_bytes());
    assert_eq!(&body[2..6], &[0x18, 0xcb, 0x00, 0x71]);
    assert_eq!(&body[6..8], &[0x00, 0x00]);
    assert_ne!(forced_withdrawn_len as usize, 4);
}

#[test]
fn bgp_compile_preserves_forced_attribute_flags() {
    let forced_flags = 0x80;
    assert_ne!(forced_flags, well_known_flags(ATTR_ORIGIN));

    let bytes = Packet::from_layer(
        Bgp::update().attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP).with_flags(forced_flags)),
    )
    .compile()
    .expect("compile UPDATE with malformed attribute flags override");

    let body = &bytes.as_bytes()[BGP_HEADER_LEN..];
    let attr_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let attrs = &body[4..4 + attr_len];
    assert_eq!(attrs, &[forced_flags, ATTR_ORIGIN, 1, BGP_ORIGIN_IGP]);
}
