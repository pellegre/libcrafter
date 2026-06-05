use std::net::Ipv6Addr;

use crafter::prelude::*;

fn doc_src() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 0x0001, 0, 0, 0, 0, 0x0010)
}

fn doc_dst() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 0x0002, 0, 0, 0, 0, 0x0020)
}

fn doc_midpoint() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 0x0003, 0, 0, 0, 0, 0x0030)
}

fn doc_home() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 0x0004, 0, 0, 0, 0, 0x0040)
}

#[test]
fn prelude_builds_ipv6_base_and_current_extension_headers() -> crafter::Result<()> {
    let ipv6: Ipv6 = Ipv6::with_addresses(doc_src(), doc_dst())
        .tc(0x5a)
        .fl(0x12345)
        .hlim(48);
    let routing: Ipv6RoutingHeader = Ipv6RoutingHeader::new()
        .routing_type(253)
        .segleft(0)
        .type_data(vec![0xaa, 0xbb, 0xcc, 0xdd]);
    let fragment: Ipv6FragmentHeader = Ipv6FragmentHeader::new()
        .id(0x0102_0304)
        .frag(0)
        .mflag(false);
    let mobile: Ipv6MobileRoutingHeader =
        Ipv6MobileRoutingHeader::new().home(doc_home()).segleft(1);
    let segment: Ipv6SegmentRoutingHeader = Ipv6SegmentRoutingHeader::new()
        .segment(doc_midpoint())
        .policy(0, doc_src(), IPV6_SEGMENT_POLICY_SOURCE_ADDRESS)?;

    let base_packet = (ipv6 / Raw::from("base")).compile()?;
    let routing_packet =
        (Ipv6::with_addresses(doc_src(), doc_dst()) / routing / Raw::from("routing")).compile()?;
    let fragment_packet = (Ipv6::with_addresses(doc_src(), doc_dst())
        / fragment
        / Udp::new().sport(12345).dport(33434)
        / Raw::from("fragment"))
    .compile()?;
    let mobile_packet =
        (Ipv6::with_addresses(doc_src(), doc_dst()) / mobile / Raw::from("mobile")).compile()?;
    let segment_packet =
        (Ipv6::with_addresses(doc_src(), doc_dst()) / segment.clone() / Raw::from("segment"))
            .compile()?;

    assert_eq!(base_packet.as_bytes()[0] >> 4, 6);
    assert_eq!(base_packet.as_bytes()[6], IPPROTO_IPV6_HOPOPTS);
    assert_eq!(routing_packet.as_bytes()[6], IPPROTO_IPV6_ROUTE);
    assert_eq!(routing_packet.as_bytes()[42], 253);
    assert_eq!(fragment_packet.as_bytes()[6], IPPROTO_IPV6_FRAGMENT);
    assert_eq!(mobile_packet.as_bytes()[6], IPPROTO_IPV6_ROUTE);
    assert_eq!(mobile_packet.as_bytes()[42], IPV6_ROUTING_TYPE_MOBILE);
    assert_eq!(segment_packet.as_bytes()[6], IPPROTO_IPV6_ROUTE);
    assert_eq!(segment_packet.as_bytes()[42], IPV6_ROUTING_TYPE_SEGMENT);
    assert_eq!(
        segment.policy_flags()[0],
        IPV6_SEGMENT_POLICY_SOURCE_ADDRESS
    );

    Ok(())
}

#[test]
fn ipv6_exports_remain_reachable_through_public_paths() {
    let _: Ipv6 = Ipv6::new();
    let _: Ipv6RoutingHeader = Ipv6RoutingHeader::new();
    let _: Ipv6FragmentHeader = Ipv6FragmentHeader::new();
    let _: Ipv6MobileRoutingHeader = Ipv6MobileRoutingHeader::new();
    let _: Ipv6SegmentRoutingHeader = Ipv6SegmentRoutingHeader::new();

    let _: crafter::Ipv6 = crafter::Ipv6::new();
    let _: crafter::Ipv6RoutingHeader = crafter::Ipv6RoutingHeader::new();
    let _: crafter::Ipv6FragmentHeader = crafter::Ipv6FragmentHeader::new();
    let _: crafter::Ipv6MobileRoutingHeader = crafter::Ipv6MobileRoutingHeader::new();
    let _: crafter::Ipv6SegmentRoutingHeader = crafter::Ipv6SegmentRoutingHeader::new();

    let _: crafter::core::Ipv6 = crafter::core::Ipv6::new();
    let _: crafter::core::Ipv6RoutingHeader = crafter::core::Ipv6RoutingHeader::new();
    let _: crafter::core::Ipv6FragmentHeader = crafter::core::Ipv6FragmentHeader::new();
    let _: crafter::core::Ipv6MobileRoutingHeader = crafter::core::Ipv6MobileRoutingHeader::new();
    let _: crafter::core::Ipv6SegmentRoutingHeader = crafter::core::Ipv6SegmentRoutingHeader::new();

    let _: crafter::protocols::Ipv6 = crafter::protocols::Ipv6::new();
    let _: crafter::protocols::Ipv6RoutingHeader = crafter::protocols::Ipv6RoutingHeader::new();
    let _: crafter::protocols::Ipv6FragmentHeader = crafter::protocols::Ipv6FragmentHeader::new();
    let _: crafter::protocols::Ipv6MobileRoutingHeader =
        crafter::protocols::Ipv6MobileRoutingHeader::new();
    let _: crafter::protocols::Ipv6SegmentRoutingHeader =
        crafter::protocols::Ipv6SegmentRoutingHeader::new();

    assert_eq!(IPPROTO_IPV6_HOPOPTS, 0);
    assert_eq!(crafter::IPPROTO_IPV6_ROUTE, 43);
    assert_eq!(crafter::core::IPPROTO_IPV6_FRAGMENT, 44);
    assert_eq!(crafter::protocols::IPPROTO_IPV6_DSTOPTS, 60);
    assert_eq!(IPV6_ROUTING_TYPE_MOBILE, 2);
    assert_eq!(crafter::IPV6_ROUTING_TYPE_SEGMENT, 4);
    assert_eq!(IPV6_SEGMENT_POLICY_UNSET, 0);
    assert_eq!(crafter::core::IPV6_SEGMENT_POLICY_INGRESS, 1);
    assert_eq!(crafter::protocols::IPV6_SEGMENT_POLICY_EGRESS, 2);
    assert_eq!(IPV6_SEGMENT_POLICY_SOURCE_ADDRESS, 3);
}
