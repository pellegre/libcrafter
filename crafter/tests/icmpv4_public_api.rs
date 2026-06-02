//! Public-surface smoke tests for the ICMPv4 capability set.
//!
//! These tests exercise the same surface that generated tools and the `docs/`
//! guide describe: typed message constructors, body and extension layers, raw
//! escape hatches, auto-fill on `compile()`, `decode_from_l3` round-trips, and
//! `summary()` output. They use documentation address space only and stay fully
//! offline.

use std::net::Ipv4Addr;

use crafter::prelude::*;

const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

fn ipv4() -> Ipv4 {
    Ipv4::new().src(DOC_SRC).dst(DOC_DST)
}

#[test]
fn icmpv4_public_api_echo_request_summary_and_autofill() -> crafter::Result<()> {
    let packet = ipv4() / Icmpv4::echo_request().id(0x4242).seq(7) / Raw::from("ping");

    // compile() fills the ICMP checksum and the IPv4 length/protocol without
    // touching the explicit identifier and sequence number.
    let compiled = packet.compile()?;
    assert!(!compiled.is_empty());

    let summary = packet.summary();
    assert!(
        summary.contains("Icmp(type=echo-request(8), code=0, id=16962, seq=7)"),
        "unexpected summary: {summary}"
    );

    // Round-trip the compiled bytes back into typed layers.
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let icmp = decoded.layer::<Icmpv4>().expect("icmp layer");
    assert_eq!(icmp.identifier_value(), Some(0x4242));
    assert_eq!(icmp.sequence_number_value(), Some(7));
    assert!(icmp.checksum_value().is_some());
    Ok(())
}

#[test]
fn icmpv4_public_api_raw_escape_hatches_survive_compile() -> crafter::Result<()> {
    // Every field has a raw override that compile() must preserve, including
    // values that are deliberately wrong on the wire.
    let icmp = Icmpv4::new()
        .type_(8)
        .code(0)
        .checksum(0xdead)
        .rest_of_header([0x11, 0x22, 0x33, 0x44]);

    let packet = ipv4() / icmp / Raw::from("body");
    let compiled = packet.compile()?;

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let icmp = decoded.layer::<Icmpv4>().expect("icmp layer");
    assert_eq!(icmp.icmp_type_value(), 8);
    assert_eq!(icmp.code_value(), 0);
    // The intentionally invalid checksum is kept verbatim.
    assert_eq!(icmp.checksum_value(), Some(0xdead));
    assert_eq!(icmp.rest_of_header_value(), [0x11, 0x22, 0x33, 0x44]);
    Ok(())
}

#[test]
fn icmpv4_public_api_error_quotes_original_datagram() -> crafter::Result<()> {
    // An ICMPv4 error message carries the offending datagram as a typed quote.
    let quoted = Ipv4::new().src(DOC_DST).dst(DOC_SRC)
        / Udp::new().sport(40000).dport(53)
        / Raw::from("query");

    let packet = ipv4()
        / Icmpv4::destination_unreachable().code(ICMP_CODE_DU_PORT_UNREACHABLE)
        / IcmpQuotedIpv4::new(quoted);
    let compiled = packet.compile()?;

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let icmp = decoded.layer::<Icmpv4>().expect("icmp layer");
    assert_eq!(icmp.icmp_type_value(), ICMP_DESTINATION_UNREACHABLE);
    assert_eq!(icmp.code_value(), ICMP_CODE_DU_PORT_UNREACHABLE);

    let quote = decoded.layer::<IcmpQuotedIpv4>().expect("quoted datagram");
    let quoted_ip = quote.quoted_layer::<Ipv4>().expect("quoted ipv4 header");
    assert_eq!(quoted_ip.source(), DOC_DST);
    Ok(())
}

#[test]
fn icmpv4_public_api_timestamp_body_roundtrip() -> crafter::Result<()> {
    let packet = ipv4()
        / Icmpv4::timestamp_request().id(9).seq(1)
        / IcmpTimestamp::new().originate(0x0001_0203);
    let compiled = packet.compile()?;

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let ts = decoded.layer::<IcmpTimestamp>().expect("timestamp body");
    assert_eq!(ts.originate_value(), 0x0001_0203);
    assert_eq!(ts.receive_value(), 0);
    Ok(())
}

#[test]
fn icmpv4_public_api_address_mask_body_roundtrip() -> crafter::Result<()> {
    let mask = Ipv4Addr::new(255, 255, 255, 0);
    let packet =
        ipv4() / Icmpv4::address_mask_reply().id(3).seq(1) / IcmpAddressMask::new().mask(mask);
    let compiled = packet.compile()?;

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let body = decoded
        .layer::<IcmpAddressMask>()
        .expect("address mask body");
    assert_eq!(body.mask_value(), mask);
    Ok(())
}

#[test]
fn icmpv4_public_api_router_advertisement_entries() -> crafter::Result<()> {
    let router = Ipv4Addr::new(192, 0, 2, 1);
    let packet = ipv4()
        / Icmpv4::router_advertisement().lifetime(1800)
        / IcmpRouterAdvertisementEntry::new()
            .router_address(router)
            .preference_level(10);
    let compiled = packet.compile()?;

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let icmp = decoded.layer::<Icmpv4>().expect("icmp layer");
    assert_eq!(icmp.icmp_type_value(), ICMP_ROUTER_ADVERTISEMENT);
    // Num Addrs is auto-filled from the trailing entry layers.
    assert_eq!(icmp.num_addrs_value(), Some(1));

    let entry = decoded
        .layer::<IcmpRouterAdvertisementEntry>()
        .expect("router entry");
    assert_eq!(entry.router_address_value(), router);
    assert_eq!(entry.preference_level_value(), 10);
    Ok(())
}

#[test]
fn icmpv4_public_api_rfc4884_mpls_extension_roundtrip() -> crafter::Result<()> {
    let quoted = Ipv4::new().src(DOC_DST).dst(DOC_SRC) / Udp::new().sport(1234).dport(53);

    let packet = ipv4()
        / Icmpv4::time_exceeded().code(ICMP_CODE_TIME_EXCEEDED_TTL)
        / IcmpQuotedIpv4::new(quoted)
        / IcmpExtension::new()
        / IcmpExtensionObject::new()
        / IcmpExtensionMpls::new().label(16000).ttl(64);
    let compiled = packet.compile()?;

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let ext = decoded.layer::<IcmpExtension>().expect("extension header");
    // The extension checksum is auto-filled on compile and recovered on decode.
    assert!(ext.checksum_value().is_some());

    let mpls = decoded.layer::<IcmpExtensionMpls>().expect("mpls object");
    assert_eq!(mpls.label_value(), 16000);
    assert_eq!(mpls.ttl_value(), 64);
    // The bottom-of-stack bit is auto-set for the last label in the stack.
    assert_eq!(mpls.bottom_of_stack_value(), Some(true));
    Ok(())
}

#[test]
fn icmpv4_public_api_legacy_type_is_constructible_and_named() -> crafter::Result<()> {
    // Deprecated and experimental types are constructible and keep their
    // assigned identity in summaries; they are never refused.
    let packet = ipv4() / Icmpv4::traceroute() / Raw::from(&[0u8; 4][..]);
    let compiled = packet.compile()?;

    let summary = packet.summary();
    assert!(
        summary.contains("type=traceroute(30)"),
        "unexpected summary: {summary}"
    );

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let icmp = decoded.layer::<Icmpv4>().expect("icmp layer");
    assert_eq!(icmp.icmp_type_value(), ICMP_TRACEROUTE);
    Ok(())
}

#[test]
fn icmpv4_public_api_unknown_type_round_trips_as_raw() -> crafter::Result<()> {
    // A valid-but-unassigned type still compiles and decodes; the body stays a
    // Raw payload and the numeric type is reported without a name.
    let packet = ipv4() / Icmpv4::new().type_(200).code(7) / Raw::from("opaque");
    let compiled = packet.compile()?;

    let summary = packet.summary();
    assert!(
        summary.contains("type=200, code=7"),
        "unexpected summary: {summary}"
    );

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let icmp = decoded.layer::<Icmpv4>().expect("icmp layer");
    assert_eq!(icmp.icmp_type_value(), 200);
    assert!(decoded.layer::<Raw>().is_some());
    Ok(())
}

#[test]
fn icmpv4_public_api_truncated_input_is_a_structured_error() {
    // Genuine ICMP-header truncation surfaces a structured buffer error rather
    // than panicking. An IPv4 header (protocol 1 = ICMP) followed by only three
    // ICMP bytes cannot hold the fixed 8-byte ICMP header.
    let ipv4 = Ipv4::new().src(DOC_SRC).dst(DOC_DST).protocol(IPPROTO_ICMP);
    let header = (ipv4 / Raw::from(&[8u8, 0, 0][..]))
        .compile()
        .expect("compile ipv4 carrier");

    let result = Packet::decode_from_l3(NetworkLayer::Ipv4, header.as_bytes());
    assert!(result.is_err(), "expected a structured decode error");
}
