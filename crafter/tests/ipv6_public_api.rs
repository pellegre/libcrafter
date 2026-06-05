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

fn base_ipv6(hop_limit: u8) -> Ipv6 {
    Ipv6::with_addresses(doc_src(), doc_dst())
        .tc(0x2a)
        .fl(0x12345)
        .hlim(hop_limit)
}

fn ipv6_payload_length(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[4], bytes[5]])
}

fn ipv6_traffic_class(bytes: &[u8]) -> u8 {
    ((bytes[0] & 0x0f) << 4) | (bytes[1] >> 4)
}

fn u16_field(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn assert_ipv6_wire_base_header(bytes: &[u8], payload_length: u16, next_header: u8, hop_limit: u8) {
    assert_eq!(bytes[0] >> 4, 6);
    assert_eq!(ipv6_payload_length(bytes), payload_length);
    assert_eq!(bytes[6], next_header);
    assert_eq!(bytes[7], hop_limit);
    assert_eq!(bytes.len(), 40 + usize::from(payload_length));
}

fn assert_decoded_ipv6_base_header(
    ipv6: &Ipv6,
    payload_length: u16,
    next_header: u8,
    hop_limit: u8,
) {
    assert_eq!(ipv6.source(), doc_src());
    assert_eq!(ipv6.destination(), doc_dst());
    assert_eq!(ipv6.traffic_class_value(), 0x2a);
    assert_eq!(ipv6.flow_label_value(), 0x12345);
    assert_eq!(ipv6.payload_length_value(), Some(payload_length));
    assert_eq!(ipv6.next_header_value(), next_header);
    assert_eq!(ipv6.hop_limit_value(), hop_limit);
}

fn assert_ipv6_transport_context(ipv6: &Ipv6, next_header: u8) -> TransportChecksumContext {
    let context = ipv6
        .transport_checksum_context(next_header)
        .expect("IPv6 transport checksum context");
    assert_eq!(
        context,
        TransportChecksumContext::Ipv6 {
            source: doc_src(),
            destination: doc_dst(),
            next_header,
        }
    );
    context
}

fn assert_transport_checksum_uses_ipv6_context(
    ipv6: &Ipv6,
    next_header: u8,
    transport: &[u8],
    checksum_offset: usize,
    zero_checksum_transmits_as_ffff: bool,
) {
    let context = assert_ipv6_transport_context(ipv6, next_header);
    let mut zeroed = transport.to_vec();
    zeroed[checksum_offset..checksum_offset + 2].copy_from_slice(&0u16.to_be_bytes());
    let expected = context.checksum(&zeroed);
    let expected_wire = if zero_checksum_transmits_as_ffff && expected == 0 {
        0xffff
    } else {
        expected
    };
    assert_eq!(u16_field(transport, checksum_offset), expected_wire);
}

#[test]
fn ipv6_udp_base_header_roundtrip_autofills_and_checksums() -> crafter::Result<()> {
    let payload = b"udp4";
    let hop_limit = 42;
    let ipv6 = base_ipv6(hop_limit);
    assert_eq!(ipv6.payload_length_value(), None);

    let compiled =
        (ipv6 / Udp::new().sport(0x1234).dport(0x5678) / Raw::from_bytes(payload)).compile()?;
    let bytes = compiled.as_bytes();
    let payload_length = (8 + payload.len()) as u16;

    assert_ipv6_wire_base_header(bytes, payload_length, IPPROTO_UDP, hop_limit);
    assert_eq!(u16_field(&bytes[40..], 4), payload_length);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    let udp = decoded.layer::<Udp>().expect("udp layer");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_decoded_ipv6_base_header(ipv6, payload_length, IPPROTO_UDP, hop_limit);
    assert_eq!(udp.source_port_value(), 0x1234);
    assert_eq!(udp.destination_port_value(), 0x5678);
    assert_eq!(udp.length_value(), Some(payload_length));
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
    assert_eq!(raw.as_bytes(), payload);
    assert_transport_checksum_uses_ipv6_context(ipv6, IPPROTO_UDP, &bytes[40..], 6, true);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn ipv6_tcp_base_header_roundtrip_autofills_and_checksums() -> crafter::Result<()> {
    let payload = b"tcp";
    let hop_limit = 43;
    let ipv6 = base_ipv6(hop_limit);
    assert_eq!(ipv6.payload_length_value(), None);

    let compiled = (ipv6
        / Tcp::new()
            .sport(0x9c40)
            .dport(443)
            .seq(0x0102_0304)
            .ack(0x0506_0708)
            .flags(TCP_FLAG_ACK)
            .window(4096)
        / Raw::from_bytes(payload))
    .compile()?;
    let bytes = compiled.as_bytes();
    let payload_length = (20 + payload.len()) as u16;

    assert_ipv6_wire_base_header(bytes, payload_length, IPPROTO_TCP, hop_limit);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    let tcp = decoded.layer::<Tcp>().expect("tcp layer");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_decoded_ipv6_base_header(ipv6, payload_length, IPPROTO_TCP, hop_limit);
    assert_eq!(tcp.source_port_value(), 0x9c40);
    assert_eq!(tcp.destination_port_value(), 443);
    assert_eq!(tcp.sequence_number_value(), 0x0102_0304);
    assert_eq!(tcp.acknowledgment_number_value(), 0x0506_0708);
    assert_eq!(tcp.data_offset_value(), 5);
    assert_eq!(tcp.flags_value(), TCP_FLAG_ACK);
    assert_eq!(tcp.window_value(), 4096);
    assert_eq!(tcp.checksum_value(), Some(u16_field(&bytes[40..], 16)));
    assert_eq!(raw.as_bytes(), payload);
    assert_transport_checksum_uses_ipv6_context(ipv6, IPPROTO_TCP, &bytes[40..], 16, false);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn ipv6_icmpv6_base_header_roundtrip_autofills_and_checksums() -> crafter::Result<()> {
    let payload = b"icmp";
    let hop_limit = 44;
    let ipv6 = base_ipv6(hop_limit);
    assert_eq!(ipv6.payload_length_value(), None);

    let compiled =
        (ipv6 / Icmpv6::echo_request().id(0x4242).seq(7) / Raw::from_bytes(payload)).compile()?;
    let bytes = compiled.as_bytes();
    let payload_length = (8 + payload.len()) as u16;

    assert_ipv6_wire_base_header(bytes, payload_length, IPPROTO_ICMPV6, hop_limit);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    let icmpv6 = decoded.layer::<Icmpv6>().expect("icmpv6 layer");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_decoded_ipv6_base_header(ipv6, payload_length, IPPROTO_ICMPV6, hop_limit);
    assert_eq!(icmpv6.kind_value(), Some(IcmpKind::EchoRequest));
    assert_eq!(icmpv6.identifier_value(), Some(0x4242));
    assert_eq!(icmpv6.sequence_number_value(), Some(7));
    assert_eq!(icmpv6.checksum_value(), Some(u16_field(&bytes[40..], 2)));
    assert_eq!(raw.as_bytes(), payload);
    assert_transport_checksum_uses_ipv6_context(ipv6, IPPROTO_ICMPV6, &bytes[40..], 2, false);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
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

#[test]
fn traffic_class_api_sets_and_preserves_dscp_ecn_bits() -> crafter::Result<()> {
    let dscp_preserves_ecn = Ipv6::new().tc(0b000000_11).dscp(Dscp::ef());
    assert_eq!(dscp_preserves_ecn.traffic_class_value(), 0b101110_11);
    assert_eq!(dscp_preserves_ecn.dscp_value(), Dscp::ef());
    assert_eq!(dscp_preserves_ecn.ecn_value(), Ecn::ce());

    let ecn_preserves_dscp = dscp_preserves_ecn.ecn(Ecn::capable_0());
    assert_eq!(ecn_preserves_dscp.traffic_class_value(), 0b101110_10);
    assert_eq!(ecn_preserves_dscp.dscp_value(), Dscp::ef());
    assert_eq!(ecn_preserves_dscp.ecn_value(), Ecn::ect0());

    let raw_override = ecn_preserves_dscp.tc(0x15);
    assert_eq!(raw_override.traffic_class_value(), 0x15);
    assert_eq!(raw_override.dscp_value(), Dscp::new(0x05)?);
    assert_eq!(raw_override.ecn_value(), Ecn::ect1());

    let compiled = (Ipv6::with_addresses(doc_src(), doc_dst())
        .dscp(Dscp::ef())
        .ecn(Ecn::capable_0())
        .nh(253)
        / Raw::from("tc"))
    .compile()?;
    let bytes = compiled.as_bytes();
    assert_eq!(ipv6_traffic_class(bytes), 0xba);
    assert_eq!(bytes[6], 253);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    assert_eq!(ipv6.traffic_class_value(), 0xba);
    assert_eq!(ipv6.dscp_value(), Dscp::ef());
    assert_eq!(ipv6.ecn_value(), Ecn::ect0());
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn ipv6_payload_length_override_is_emitted_unchanged() -> crafter::Result<()> {
    let payload = [0xde, 0xad, 0xbe, 0xef];
    let compiled = (base_ipv6(51).plen(2).nh(253) / Raw::from_bytes(payload)).compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(ipv6_payload_length(bytes), 2);
    assert_eq!(bytes[6], 253);
    assert_eq!(bytes[7], 51);
    assert_eq!(&bytes[40..], payload);
    assert_eq!(bytes.len(), 40 + payload.len());

    Ok(())
}

#[test]
fn ipv6_payload_length_short_declaration_splits_trailing_raw_tail() -> crafter::Result<()> {
    let payload = [0xde, 0xad, 0xbe, 0xef];
    let compiled = (base_ipv6(52).plen(2).nh(253) / Raw::from_bytes(payload)).compile()?;
    let bytes = compiled.as_bytes();

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    let raw_layers: Vec<_> = decoded.layers::<Raw>().map(Raw::as_bytes).collect();
    let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();

    assert_decoded_ipv6_base_header(ipv6, 2, 253, 52);
    assert_eq!(raw_layers, vec![&payload[..2], &payload[2..]]);
    assert_eq!(layer_names, vec!["Ipv6", "Raw", "Raw"]);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn ipv6_payload_boundary_autofills_zero_payload_length() -> crafter::Result<()> {
    let compiled = (base_ipv6(53).nh(253) / Raw::new()).compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 0, 253, 53);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    assert_decoded_ipv6_base_header(ipv6, 0, 253, 53);
    assert!(decoded.layer::<Raw>().is_none());
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn ipv6_payload_boundary_autofills_one_octet_payload_length() -> crafter::Result<()> {
    let payload = [0xab];
    let compiled = (base_ipv6(54).nh(253) / Raw::from_bytes(payload)).compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 1, 253, 54);
    assert_eq!(&bytes[40..], payload);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    let raw = decoded.layer::<Raw>().expect("raw payload");
    assert_decoded_ipv6_base_header(ipv6, 1, 253, 54);
    assert_eq!(raw.as_bytes(), payload);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn ipv6_payload_boundary_autofills_max_base_payload_length() -> crafter::Result<()> {
    let payload = vec![0xa5; u16::MAX as usize];
    let compiled = (base_ipv6(55).nh(253) / Raw::from_bytes(&payload)).compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, u16::MAX, 253, 55);
    assert_eq!(&bytes[40..], payload.as_slice());

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    let raw = decoded.layer::<Raw>().expect("raw payload");
    assert_decoded_ipv6_base_header(ipv6, u16::MAX, 253, 55);
    assert_eq!(raw.as_bytes(), payload.as_slice());
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn ipv6_payload_boundary_explicit_zero_payload_length_is_preserved() -> crafter::Result<()> {
    let payload = [0xde, 0xad, 0xbe, 0xef];
    let compiled = (base_ipv6(56).plen(0).nh(253) / Raw::from_bytes(payload)).compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(ipv6_payload_length(bytes), 0);
    assert_eq!(bytes[6], 253);
    assert_eq!(bytes[7], 56);
    assert_eq!(&bytes[40..], payload);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    let raw_layers: Vec<_> = decoded.layers::<Raw>().map(Raw::as_bytes).collect();
    assert_decoded_ipv6_base_header(ipv6, 0, 253, 56);
    assert_eq!(raw_layers, vec![&payload[..]]);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn ipv6_payload_boundary_oversized_payload_returns_structured_error() {
    let payload = vec![0x5a; u16::MAX as usize + 1];
    let err = (base_ipv6(57).nh(253) / Raw::from_bytes(&payload))
        .compile()
        .expect_err("oversized IPv6 base payload must fail");

    match err {
        CrafterError::InvalidFieldValue { field, reason } => {
            assert_eq!(field, "ipv6.payload_length");
            assert!(!reason.is_empty());
        }
        other => panic!("oversized IPv6 base payload expected InvalidFieldValue, got {other:?}"),
    }
}
