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

const IANA_RESERVED_NEXT_HEADER: u8 = 255;

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

fn ipv6_flow_label(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) & 0x000f_ffff
}

#[derive(Debug, Clone, Copy)]
enum ExpectedBaseDecodeError {
    BufferTooShort {
        context: &'static str,
        required: usize,
        available: usize,
    },
    InvalidFieldValue {
        field: &'static str,
        reason: &'static str,
    },
}

fn assert_flow_label_error(err: CrafterError) {
    match err {
        CrafterError::InvalidFieldValue { field, reason } => {
            assert_eq!(field, "ipv6.flow_label");
            assert_eq!(reason, "flow label must fit in 20 bits");
        }
        other => panic!("flow label overflow expected InvalidFieldValue, got {other:?}"),
    }
}

fn assert_base_decode_error(
    label: &str,
    result: crafter::Result<Packet>,
    expected: ExpectedBaseDecodeError,
) {
    let err = result.unwrap_err();
    match (expected, err) {
        (
            ExpectedBaseDecodeError::BufferTooShort {
                context: expected_context,
                required: expected_required,
                available: expected_available,
            },
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            },
        ) => {
            assert_eq!(context, expected_context, "{label}");
            assert_eq!(required, expected_required, "{label}");
            assert_eq!(available, expected_available, "{label}");
        }
        (
            ExpectedBaseDecodeError::InvalidFieldValue {
                field: expected_field,
                reason: expected_reason,
            },
            CrafterError::InvalidFieldValue { field, reason },
        ) => {
            assert_eq!(field, expected_field, "{label}");
            assert_eq!(reason, expected_reason, "{label}");
        }
        (expected, actual) => panic!("{label} expected {expected:?}, got {actual:?}"),
    }
}

fn ethernet_ipv6_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&[0x02, 0x00, 0x5e, 0x00, 0x53, 0x02]);
    frame.extend_from_slice(&[0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
    frame.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn linux_sll_ipv6_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(16 + payload.len());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&6u16.to_be_bytes());
    frame.extend_from_slice(&[0x02, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00]);
    frame.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn assert_ipv6_base_decode_error_entrypoints(bytes: &[u8], expected: ExpectedBaseDecodeError) {
    let registry = ProtocolRegistry::new();
    assert_base_decode_error(
        "Packet::decode_from_l3",
        Packet::decode_from_l3(NetworkLayer::Ipv6, bytes),
        expected,
    );
    assert_base_decode_error(
        "Packet::decode_from_l3_with_registry",
        Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv6, bytes),
        expected,
    );
    assert_base_decode_error(
        "ProtocolRegistry::decode_from_l3",
        registry.decode_from_l3(NetworkLayer::Ipv6, bytes),
        expected,
    );
    assert_base_decode_error(
        "ProtocolRegistry::decode_ipv6",
        registry.decode_ipv6(bytes),
        expected,
    );

    let ethernet = ethernet_ipv6_frame(bytes);
    assert_base_decode_error(
        "Packet::decode_from_link(Ethernet)",
        Packet::decode_from_link(LinkType::Ethernet, &ethernet),
        expected,
    );
    assert_base_decode_error(
        "Packet::decode_from_link_with_registry(Ethernet)",
        Packet::decode_from_link_with_registry(&registry, LinkType::Ethernet, &ethernet),
        expected,
    );
    assert_base_decode_error(
        "ProtocolRegistry::decode_from_link(Ethernet)",
        registry.decode_from_link(LinkType::Ethernet, &ethernet),
        expected,
    );
    assert_base_decode_error(
        "ProtocolRegistry::decode_ethernet",
        registry.decode_ethernet(&ethernet),
        expected,
    );

    let linux_sll = linux_sll_ipv6_frame(bytes);
    assert_base_decode_error(
        "Packet::decode_from_link(LinuxSll)",
        Packet::decode_from_link(LinkType::LinuxSll, &linux_sll),
        expected,
    );
    assert_base_decode_error(
        "Packet::decode_from_link(LinuxCooked)",
        Packet::decode_from_link(LinkType::LinuxCooked, &linux_sll),
        expected,
    );
    assert_base_decode_error(
        "Packet::decode_from_link_with_registry(LinuxSll)",
        Packet::decode_from_link_with_registry(&registry, LinkType::LinuxSll, &linux_sll),
        expected,
    );
    assert_base_decode_error(
        "ProtocolRegistry::decode_from_link(LinuxSll)",
        registry.decode_from_link(LinkType::LinuxSll, &linux_sll),
        expected,
    );
    assert_base_decode_error(
        "ProtocolRegistry::decode_linux_sll",
        registry.decode_linux_sll(&linux_sll),
        expected,
    );
}

fn assert_traffic_class_roundtrip(
    ipv6: Ipv6,
    expected_traffic_class: u8,
    expected_dscp: Dscp,
    expected_ecn: Ecn,
) -> crafter::Result<()> {
    let compiled = (ipv6.nh(253) / Raw::from("tc")).compile()?;
    let bytes = compiled.as_bytes();
    assert_eq!(ipv6_traffic_class(bytes), expected_traffic_class);
    assert_eq!(bytes[0], 0x60 | (expected_traffic_class >> 4));
    assert_eq!(bytes[1], expected_traffic_class << 4);
    assert_eq!(bytes[6], 253);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    assert_eq!(ipv6.traffic_class_value(), expected_traffic_class);
    assert_eq!(ipv6.dscp_value(), expected_dscp);
    assert_eq!(ipv6.ecn_value(), expected_ecn);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
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

#[derive(Debug, Clone, Copy)]
enum Ipv6OptionHeaderKind {
    HopByHop,
    Destination,
}

impl Ipv6OptionHeaderKind {
    const ALL: [Self; 2] = [Self::HopByHop, Self::Destination];

    fn outer_next_header(self) -> u8 {
        match self {
            Self::HopByHop => IPPROTO_IPV6_HOPOPTS,
            Self::Destination => IPPROTO_IPV6_DSTOPTS,
        }
    }

    fn decode_context(self) -> &'static str {
        match self {
            Self::HopByHop => "ipv6 hop-by-hop header",
            Self::Destination => "ipv6 destination options header",
        }
    }

    fn options_error_field(self) -> &'static str {
        match self {
            Self::HopByHop => "ipv6.hop_by_hop.options",
            Self::Destination => "ipv6.destination_options.options",
        }
    }

    fn header_ext_len_field(self) -> &'static str {
        match self {
            Self::HopByHop => "ipv6.hop_by_hop.header_ext_len",
            Self::Destination => "ipv6.destination_options.header_ext_len",
        }
    }
}

fn option_header_packet(
    kind: Ipv6OptionHeaderKind,
    options: Vec<Ipv6Option>,
    header_ext_len: Option<u8>,
    explicit_next_header: Option<u8>,
    with_udp: bool,
) -> Packet {
    match kind {
        Ipv6OptionHeaderKind::HopByHop => {
            let mut header = Ipv6HopByHopOptionsHeader::new().options(options);
            if let Some(header_ext_len) = header_ext_len {
                header = header.header_ext_len(header_ext_len);
            }
            if let Some(next_header) = explicit_next_header {
                header = header.nh(next_header);
            }

            if with_udp {
                base_ipv6(71) / header / Udp::new().sport(1111).dport(2222)
            } else {
                base_ipv6(71) / header / Raw::new()
            }
        }
        Ipv6OptionHeaderKind::Destination => {
            let mut header = Ipv6DestinationOptionsHeader::new().options(options);
            if let Some(header_ext_len) = header_ext_len {
                header = header.header_ext_len(header_ext_len);
            }
            if let Some(next_header) = explicit_next_header {
                header = header.nh(next_header);
            }

            if with_udp {
                base_ipv6(71) / header / Udp::new().sport(1111).dport(2222)
            } else {
                base_ipv6(71) / header / Raw::new()
            }
        }
    }
}

fn assert_decoded_option_header(
    bytes: &[u8],
    kind: Ipv6OptionHeaderKind,
    expected_header_ext_len: u8,
    expected_next_header: u8,
    expected_options: &[Ipv6Option],
) -> crafter::Result<()> {
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;

    match kind {
        Ipv6OptionHeaderKind::HopByHop => {
            let header = decoded
                .layer::<Ipv6HopByHopOptionsHeader>()
                .expect("hop-by-hop options header");
            assert_eq!(header.header_ext_len_value(), Some(expected_header_ext_len));
            assert_eq!(header.next_header_value(), expected_next_header);
            assert_eq!(header.options_value(), expected_options);
        }
        Ipv6OptionHeaderKind::Destination => {
            let header = decoded
                .layer::<Ipv6DestinationOptionsHeader>()
                .expect("destination options header");
            assert_eq!(header.header_ext_len_value(), Some(expected_header_ext_len));
            assert_eq!(header.next_header_value(), expected_next_header);
            assert_eq!(header.options_value(), expected_options);
        }
    }

    assert_eq!(decoded.compile()?.as_bytes(), bytes);
    Ok(())
}

fn unknown_next_header_values() -> [u8; 3] {
    // IANA Protocol Numbers marks 253/254 experimental and 255 reserved.
    [
        IPPROTO_IPV6_EXPERIMENTAL_1,
        IPPROTO_IPV6_EXPERIMENTAL_2,
        IANA_RESERVED_NEXT_HEADER,
    ]
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
fn hop_limit_default_and_aliases_are_stable() -> crafter::Result<()> {
    let default_ipv6 = Ipv6::with_addresses(doc_src(), doc_dst()).nh(253);
    assert_eq!(default_ipv6.hop_limit_value(), 64);

    let default_packet = (default_ipv6 / Raw::from("default-hop")).compile()?;
    let default_bytes = default_packet.as_bytes();
    assert_ipv6_wire_base_header(default_bytes, 11, 253, 64);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, default_bytes)?;
    let decoded_ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    assert_eq!(decoded_ipv6.hop_limit_value(), 64);

    let hop_limit = Ipv6::with_addresses(doc_src(), doc_dst())
        .hop_limit(31)
        .nh(253);
    let hlim = Ipv6::with_addresses(doc_src(), doc_dst()).hlim(31).nh(253);
    assert_eq!(hop_limit.hop_limit_value(), hlim.hop_limit_value());

    let hop_limit_packet = (hop_limit / Raw::from("alias-hop")).compile()?;
    let hlim_packet = (hlim / Raw::from("alias-hop")).compile()?;
    assert_eq!(hop_limit_packet.as_bytes(), hlim_packet.as_bytes());
    assert_ipv6_wire_base_header(hlim_packet.as_bytes(), 9, 253, 31);

    Ok(())
}

#[test]
fn next_header_override_default_auto_and_aliases_are_preserved() -> crafter::Result<()> {
    let default_ipv6 = Ipv6::with_addresses(doc_src(), doc_dst());
    assert_eq!(default_ipv6.next_header_value(), IPPROTO_IPV6_HOPOPTS);

    let default_packet = (default_ipv6 / Raw::from("base")).compile()?;
    assert_ipv6_wire_base_header(default_packet.as_bytes(), 4, IPPROTO_IPV6_HOPOPTS, 64);

    let udp_auto = (Ipv6::with_addresses(doc_src(), doc_dst())
        / Udp::new().sport(0x1111).dport(0x2222)
        / Raw::from("udp"))
    .compile()?;
    assert_ipv6_wire_base_header(udp_auto.as_bytes(), 11, IPPROTO_UDP, 64);

    let next_header_override = (Ipv6::with_addresses(doc_src(), doc_dst()).next_header(253)
        / Udp::new().sport(0x3333).dport(0x4444)
        / Raw::from("next"))
    .compile()?;
    assert_ipv6_wire_base_header(next_header_override.as_bytes(), 12, 253, 64);

    let nh_override = (Ipv6::with_addresses(doc_src(), doc_dst()).nh(IPPROTO_TCP)
        / Udp::new().sport(0x5555).dport(0x6666)
        / Raw::from("alias"))
    .compile()?;
    assert_ipv6_wire_base_header(nh_override.as_bytes(), 13, IPPROTO_TCP, 64);

    Ok(())
}

#[test]
fn next_header_names_are_public_and_used_in_summaries() {
    let cases = [
        (IPPROTO_IPV6_HOPOPTS, "hop-by-hop-options(0)"),
        (IPPROTO_TCP, "tcp(6)"),
        (IPPROTO_UDP, "udp(17)"),
        (IPPROTO_IPV6_ROUTE, "routing(43)"),
        (IPPROTO_IPV6_FRAGMENT, "fragment(44)"),
        (IPPROTO_IPV6_ESP, "esp(50)"),
        (IPPROTO_IPV6_AH, "ah(51)"),
        (IPPROTO_ICMPV6, "icmpv6(58)"),
        (IPPROTO_IPV6_NO_NEXT, "no-next(59)"),
        (IPPROTO_IPV6_DSTOPTS, "destination-options(60)"),
        (IPPROTO_IPV6_MOBILITY, "mobility(135)"),
        (IPPROTO_IPV6_HIP, "hip(139)"),
        (IPPROTO_IPV6_SHIM6, "shim6(140)"),
        (IPPROTO_IPV6_EXPERIMENTAL_1, "experimental-1(253)"),
        (IPPROTO_IPV6_EXPERIMENTAL_2, "experimental-2(254)"),
        (149, "unknown(149)"),
    ];

    for (next_header, label) in cases {
        let packet = Packet::from_layer(base_ipv6(64).nh(next_header));
        let summary = packet.summary();
        let show = packet.show();
        assert!(summary.contains(&format!("next={label}")), "{summary}");
        assert!(show.contains(&format!("next_header: {label}")), "{show}");
    }

    assert_eq!(IPPROTO_IPV6_ESP, 50);
    assert_eq!(crafter::IPPROTO_IPV6_AH, 51);
    assert_eq!(crafter::core::IPPROTO_IPV6_NO_NEXT, 59);
    assert_eq!(crafter::protocols::IPPROTO_IPV6_MOBILITY, 135);
    assert_eq!(IPPROTO_IPV6_HIP, 139);
    assert_eq!(crafter::IPPROTO_IPV6_SHIM6, 140);
    assert_eq!(crafter::core::IPPROTO_IPV6_EXPERIMENTAL_1, 253);
    assert_eq!(crafter::protocols::IPPROTO_IPV6_EXPERIMENTAL_2, 254);
}

#[test]
fn inspection_base_summary_stays_compact_and_show_lists_base_fields() -> crafter::Result<()> {
    let compiled = (Ipv6::with_addresses(doc_src(), doc_dst())
        .dscp(Dscp::ef())
        .ecn(Ecn::ce())
        .fl(0x12345)
        .hlim(37)
        .nh(IPPROTO_IPV6_NO_NEXT)
        / Raw::from("base"))
    .compile()?;

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())?;

    assert_eq!(
        decoded.summary(),
        format!(
            "Ipv6(src={}, dst={}, next=no-next(59)) / Raw(len=4)",
            doc_src(),
            doc_dst()
        )
    );

    let show = decoded.show();
    let expected_src = format!("src: {}", doc_src());
    let expected_dst = format!("dst: {}", doc_dst());
    for expected in [
        "version: 6",
        "traffic_class: 0xbb",
        "dscp: 46",
        "ecn: 3",
        "flow_label: 0x12345",
        "payload_length: 4",
        "next_header: no-next(59)",
        "hop_limit: 37",
        expected_src.as_str(),
        expected_dst.as_str(),
    ] {
        assert!(show.contains(expected), "{show}");
    }

    Ok(())
}

#[test]
fn next_header_names_no_next_header_decodes_empty_payload_without_raw() -> crafter::Result<()> {
    let compiled = (base_ipv6(45).nh(IPPROTO_IPV6_NO_NEXT) / Raw::new()).compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 0, IPPROTO_IPV6_NO_NEXT, 45);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");

    assert_decoded_ipv6_base_header(ipv6, 0, IPPROTO_IPV6_NO_NEXT, 45);
    assert_eq!(decoded.len(), 1);
    assert!(decoded.layer::<Raw>().is_none());
    assert!(decoded.summary().contains("no-next(59)"));
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn next_header_names_no_next_header_preserves_non_empty_payload_as_raw() -> crafter::Result<()> {
    let payload = [0xde, 0xad, 0xbe, 0xef];
    let compiled = (base_ipv6(46).nh(IPPROTO_IPV6_NO_NEXT) / Raw::from_bytes(payload)).compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, payload.len() as u16, IPPROTO_IPV6_NO_NEXT, 46);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_decoded_ipv6_base_header(ipv6, payload.len() as u16, IPPROTO_IPV6_NO_NEXT, 46);
    assert_eq!(raw.as_bytes(), payload);
    assert_eq!(
        decoded.summary(),
        format!(
            "Ipv6(src={}, dst={}, next=no-next(59)) / Raw(len=4)",
            doc_src(),
            doc_dst()
        )
    );
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn unknown_next_header_non_empty_payload_decodes_as_raw_and_roundtrips() -> crafter::Result<()> {
    let payload = [0xca, 0xfe, 0xba, 0xbe, 0x01];

    for (index, next_header) in unknown_next_header_values().into_iter().enumerate() {
        let hop_limit = 58 + index as u8;
        let compiled =
            (base_ipv6(hop_limit).nh(next_header) / Raw::from_bytes(payload)).compile()?;
        let bytes = compiled.as_bytes();

        assert_ipv6_wire_base_header(bytes, payload.len() as u16, next_header, hop_limit);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
        let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
        let raw = decoded.layer::<Raw>().expect("raw payload");

        assert_decoded_ipv6_base_header(ipv6, payload.len() as u16, next_header, hop_limit);
        assert_eq!(raw.as_bytes(), payload);
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded.compile()?.as_bytes(), bytes);
    }

    Ok(())
}

#[test]
fn unknown_next_header_empty_payload_roundtrips_without_raw_layer() -> crafter::Result<()> {
    for (index, next_header) in unknown_next_header_values().into_iter().enumerate() {
        let hop_limit = 61 + index as u8;
        let compiled = (base_ipv6(hop_limit).nh(next_header) / Raw::new()).compile()?;
        let bytes = compiled.as_bytes();

        assert_ipv6_wire_base_header(bytes, 0, next_header, hop_limit);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
        let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");

        assert_decoded_ipv6_base_header(ipv6, 0, next_header, hop_limit);
        assert_eq!(decoded.len(), 1);
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile()?.as_bytes(), bytes);
    }

    Ok(())
}

#[test]
fn base_decode_error_short_headers_through_public_entrypoints() {
    for available in [0, 1, 8, 39] {
        let mut bytes = vec![0; available];
        if let Some(first) = bytes.first_mut() {
            *first = 0x60;
        }

        assert_ipv6_base_decode_error_entrypoints(
            &bytes,
            ExpectedBaseDecodeError::BufferTooShort {
                context: "ipv6 header",
                required: 40,
                available,
            },
        );
    }
}

#[test]
fn base_decode_error_wrong_version_through_public_entrypoints() -> crafter::Result<()> {
    let mut bytes = (base_ipv6(64).nh(253) / Raw::new()).compile()?.into_bytes();
    bytes[0] = 0x40 | (bytes[0] & 0x0f);

    assert_ipv6_base_decode_error_entrypoints(
        &bytes,
        ExpectedBaseDecodeError::InvalidFieldValue {
            field: "ipv6.version",
            reason: "IPv6 packets must have version 6",
        },
    );

    Ok(())
}

#[test]
fn base_decode_error_payload_overrun_through_public_entrypoints() -> crafter::Result<()> {
    let mut bytes = (base_ipv6(64).nh(253) / Raw::new()).compile()?.into_bytes();
    bytes[4..6].copy_from_slice(&4u16.to_be_bytes());

    assert_ipv6_base_decode_error_entrypoints(
        &bytes,
        ExpectedBaseDecodeError::BufferTooShort {
            context: "ipv6 packet",
            required: 44,
            available: 40,
        },
    );

    Ok(())
}

#[test]
fn unknown_next_header_trailing_bytes_after_payload_length_roundtrip() -> crafter::Result<()> {
    let declared_payload_len = 2;
    let payload = [0xde, 0xad, 0xbe, 0xef, 0x5a];

    for (index, next_header) in unknown_next_header_values().into_iter().enumerate() {
        let hop_limit = 64 + index as u8;
        let compiled = (base_ipv6(hop_limit)
            .plen(declared_payload_len)
            .nh(next_header)
            / Raw::from_bytes(payload))
        .compile()?;
        let bytes = compiled.as_bytes();

        assert_eq!(ipv6_payload_length(bytes), declared_payload_len);
        assert_eq!(bytes[6], next_header);
        assert_eq!(bytes[7], hop_limit);
        assert_eq!(bytes.len(), 40 + payload.len());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
        let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
        let raw_layers: Vec<_> = decoded.layers::<Raw>().map(Raw::as_bytes).collect();
        let split_at = usize::from(declared_payload_len);

        assert_decoded_ipv6_base_header(ipv6, declared_payload_len, next_header, hop_limit);
        assert_eq!(raw_layers, vec![&payload[..split_at], &payload[split_at..]]);
        assert_eq!(decoded.compile()?.as_bytes(), bytes);
    }

    Ok(())
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
    let hop_by_hop: Ipv6HopByHopOptionsHeader =
        Ipv6HopByHopOptionsHeader::new().option(Ipv6Option::pad1());
    let destination_options: Ipv6DestinationOptionsHeader =
        Ipv6DestinationOptionsHeader::new().option(Ipv6Option::pad1());
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
    let hop_by_hop_packet = (Ipv6::with_addresses(doc_src(), doc_dst())
        / hop_by_hop
        / Udp::new().sport(12345).dport(33434)
        / Raw::from("hop"))
    .compile()?;
    let destination_options_packet = (Ipv6::with_addresses(doc_src(), doc_dst())
        / destination_options
        / Udp::new().sport(12345).dport(33434)
        / Raw::from("dst"))
    .compile()?;
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
    assert_eq!(hop_by_hop_packet.as_bytes()[6], IPPROTO_IPV6_HOPOPTS);
    assert_eq!(hop_by_hop_packet.as_bytes()[40], IPPROTO_UDP);
    assert_eq!(
        destination_options_packet.as_bytes()[6],
        IPPROTO_IPV6_DSTOPTS
    );
    assert_eq!(destination_options_packet.as_bytes()[40], IPPROTO_UDP);
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
    let _: Ipv6DestinationOptionsHeader = Ipv6DestinationOptionsHeader::new();
    let _: Ipv6HopByHopOptionsHeader = Ipv6HopByHopOptionsHeader::new();
    let _: Ipv6RoutingHeader = Ipv6RoutingHeader::new();
    let _: Ipv6FragmentHeader = Ipv6FragmentHeader::new();
    let _: Ipv6MobileRoutingHeader = Ipv6MobileRoutingHeader::new();
    let _: Ipv6SegmentRoutingHeader = Ipv6SegmentRoutingHeader::new();
    let _: Ipv6Option = Ipv6Option::pad1();
    let _: Ipv6OptionAction = Ipv6OptionAction::Skip;
    let _: Ipv6OptionIter<'_> = Ipv6OptionIter::new(&[IPV6_OPTION_PAD1]);

    let _: crafter::Ipv6 = crafter::Ipv6::new();
    let _: crafter::Ipv6DestinationOptionsHeader = crafter::Ipv6DestinationOptionsHeader::new();
    let _: crafter::Ipv6HopByHopOptionsHeader = crafter::Ipv6HopByHopOptionsHeader::new();
    let _: crafter::Ipv6RoutingHeader = crafter::Ipv6RoutingHeader::new();
    let _: crafter::Ipv6FragmentHeader = crafter::Ipv6FragmentHeader::new();
    let _: crafter::Ipv6MobileRoutingHeader = crafter::Ipv6MobileRoutingHeader::new();
    let _: crafter::Ipv6SegmentRoutingHeader = crafter::Ipv6SegmentRoutingHeader::new();
    let _: crafter::Ipv6Option = crafter::Ipv6Option::pad1();
    let _: crafter::Ipv6OptionAction = crafter::Ipv6OptionAction::Skip;
    let _: crafter::Ipv6OptionIter<'_> = crafter::Ipv6OptionIter::new(&[crafter::IPV6_OPTION_PAD1]);

    let _: crafter::core::Ipv6 = crafter::core::Ipv6::new();
    let _: crafter::core::Ipv6DestinationOptionsHeader =
        crafter::core::Ipv6DestinationOptionsHeader::new();
    let _: crafter::core::Ipv6HopByHopOptionsHeader =
        crafter::core::Ipv6HopByHopOptionsHeader::new();
    let _: crafter::core::Ipv6RoutingHeader = crafter::core::Ipv6RoutingHeader::new();
    let _: crafter::core::Ipv6FragmentHeader = crafter::core::Ipv6FragmentHeader::new();
    let _: crafter::core::Ipv6MobileRoutingHeader = crafter::core::Ipv6MobileRoutingHeader::new();
    let _: crafter::core::Ipv6SegmentRoutingHeader = crafter::core::Ipv6SegmentRoutingHeader::new();
    let _: crafter::core::Ipv6Option = crafter::core::Ipv6Option::pad1();
    let _: crafter::core::Ipv6OptionAction = crafter::core::Ipv6OptionAction::Skip;
    let _: crafter::core::Ipv6OptionIter<'_> =
        crafter::core::Ipv6OptionIter::new(&[crafter::core::IPV6_OPTION_PAD1]);

    let _: crafter::protocols::Ipv6 = crafter::protocols::Ipv6::new();
    let _: crafter::protocols::Ipv6DestinationOptionsHeader =
        crafter::protocols::Ipv6DestinationOptionsHeader::new();
    let _: crafter::protocols::Ipv6HopByHopOptionsHeader =
        crafter::protocols::Ipv6HopByHopOptionsHeader::new();
    let _: crafter::protocols::Ipv6RoutingHeader = crafter::protocols::Ipv6RoutingHeader::new();
    let _: crafter::protocols::Ipv6FragmentHeader = crafter::protocols::Ipv6FragmentHeader::new();
    let _: crafter::protocols::Ipv6MobileRoutingHeader =
        crafter::protocols::Ipv6MobileRoutingHeader::new();
    let _: crafter::protocols::Ipv6SegmentRoutingHeader =
        crafter::protocols::Ipv6SegmentRoutingHeader::new();
    let _: crafter::protocols::Ipv6Option = crafter::protocols::Ipv6Option::pad1();
    let _: crafter::protocols::Ipv6OptionAction = crafter::protocols::Ipv6OptionAction::Skip;
    let _: crafter::protocols::Ipv6OptionIter<'_> =
        crafter::protocols::Ipv6OptionIter::new(&[crafter::protocols::IPV6_OPTION_PAD1]);

    assert_eq!(IPPROTO_IPV6_HOPOPTS, 0);
    assert_eq!(crafter::IPPROTO_IPV6_ROUTE, 43);
    assert_eq!(crafter::core::IPPROTO_IPV6_FRAGMENT, 44);
    assert_eq!(crafter::protocols::IPPROTO_IPV6_DSTOPTS, 60);
    assert_eq!(IPV6_OPTION_PAD1, 0);
    assert_eq!(crafter::IPV6_OPTION_PADN, 1);
    assert_eq!(crafter::IPV6_OPTION_HOME_ADDRESS, 0xc9);
    assert_eq!(IPV6_ROUTING_TYPE_MOBILE, 2);
    assert_eq!(crafter::IPV6_ROUTING_TYPE_SEGMENT, 4);
    assert_eq!(IPV6_SEGMENT_POLICY_UNSET, 0);
    assert_eq!(crafter::core::IPV6_SEGMENT_POLICY_INGRESS, 1);
    assert_eq!(crafter::protocols::IPV6_SEGMENT_POLICY_EGRESS, 2);
    assert_eq!(IPV6_SEGMENT_POLICY_SOURCE_ADDRESS, 3);
}

#[test]
fn hop_by_hop_builder() -> crafter::Result<()> {
    let hop_by_hop = Ipv6HopByHopOptionsHeader::new()
        .option(Ipv6Option::generic(0x1e, [0xaa])?)
        .option(Ipv6Option::pad1())
        .option(Ipv6Option::generic(0x3e, [0xbb, 0xcc])?);
    let packet = base_ipv6(64)
        / hop_by_hop.clone()
        / Udp::new().sport(12345).dport(33434)
        / Raw::from("hbh!");
    let bytes = packet.compile()?;

    assert_eq!(bytes.as_bytes()[6], IPPROTO_IPV6_HOPOPTS);
    assert_eq!(ipv6_payload_length(bytes.as_bytes()), 28);
    assert_eq!(hop_by_hop.encoded_len(), 16);
    assert_eq!(hop_by_hop.header_ext_len_value(), None);
    assert_eq!(
        hop_by_hop.options_value(),
        &[
            Ipv6Option::generic(0x1e, [0xaa])?,
            Ipv6Option::pad1(),
            Ipv6Option::generic(0x3e, [0xbb, 0xcc])?
        ]
    );

    let hbh = &bytes.as_bytes()[40..56];
    assert_eq!(hbh[0], IPPROTO_UDP);
    assert_eq!(hbh[1], 1);
    assert_eq!(
        &hbh[2..10],
        &[0x1e, 1, 0xaa, IPV6_OPTION_PAD1, 0x3e, 2, 0xbb, 0xcc]
    );
    assert_eq!(&hbh[10..16], &[0, 0, 0, 0, 0, 0]);

    let udp = &bytes.as_bytes()[56..64];
    assert_eq!(&udp[0..2], &12345u16.to_be_bytes());
    assert_eq!(&udp[2..4], &33434u16.to_be_bytes());
    assert_eq!(&udp[4..6], &12u16.to_be_bytes());

    let explicit = (base_ipv6(32)
        / Ipv6HopByHopOptionsHeader::new()
            .nh(IPPROTO_IPV6_NO_NEXT)
            .header_ext_len(2)
            .option(Ipv6Option::pad1())
        / Udp::new().sport(1111).dport(2222))
    .compile()?;

    assert_eq!(explicit.as_bytes()[6], IPPROTO_IPV6_HOPOPTS);
    assert_eq!(explicit.as_bytes()[40], IPPROTO_IPV6_NO_NEXT);
    assert_eq!(explicit.as_bytes()[41], 2);
    assert_eq!(ipv6_payload_length(explicit.as_bytes()), 32);

    Ok(())
}

#[test]
fn destination_options_builder() -> crafter::Result<()> {
    let destination_options = Ipv6DestinationOptionsHeader::new()
        .option(Ipv6Option::generic(0x1e, [0xaa])?)
        .option(Ipv6Option::pad1())
        .option(Ipv6Option::generic(0x3e, [0xbb, 0xcc])?);
    let packet = base_ipv6(64)
        / destination_options.clone()
        / Udp::new().sport(12345).dport(33434)
        / Raw::from("dst!");
    let bytes = packet.compile()?;

    assert_eq!(bytes.as_bytes()[6], IPPROTO_IPV6_DSTOPTS);
    assert_eq!(ipv6_payload_length(bytes.as_bytes()), 28);
    assert_eq!(destination_options.encoded_len(), 16);
    assert_eq!(destination_options.header_ext_len_value(), None);
    assert_eq!(
        destination_options.options_value(),
        &[
            Ipv6Option::generic(0x1e, [0xaa])?,
            Ipv6Option::pad1(),
            Ipv6Option::generic(0x3e, [0xbb, 0xcc])?
        ]
    );

    let dstopts = &bytes.as_bytes()[40..56];
    assert_eq!(dstopts[0], IPPROTO_UDP);
    assert_eq!(dstopts[1], 1);
    assert_eq!(
        &dstopts[2..10],
        &[0x1e, 1, 0xaa, IPV6_OPTION_PAD1, 0x3e, 2, 0xbb, 0xcc]
    );
    assert_eq!(&dstopts[10..16], &[0, 0, 0, 0, 0, 0]);

    let udp = &bytes.as_bytes()[56..64];
    assert_eq!(&udp[0..2], &12345u16.to_be_bytes());
    assert_eq!(&udp[2..4], &33434u16.to_be_bytes());
    assert_eq!(&udp[4..6], &12u16.to_be_bytes());

    let chained = (base_ipv6(63)
        / Ipv6HopByHopOptionsHeader::new().option(Ipv6Option::pad1())
        / Ipv6DestinationOptionsHeader::new().option(Ipv6Option::pad1())
        / Udp::new().sport(1111).dport(2222))
    .compile()?;

    assert_eq!(chained.as_bytes()[6], IPPROTO_IPV6_HOPOPTS);
    assert_eq!(chained.as_bytes()[40], IPPROTO_IPV6_DSTOPTS);
    assert_eq!(chained.as_bytes()[48], IPPROTO_UDP);
    assert_eq!(ipv6_payload_length(chained.as_bytes()), 24);

    let explicit = (base_ipv6(32)
        / Ipv6DestinationOptionsHeader::new()
            .nh(IPPROTO_IPV6_NO_NEXT)
            .header_ext_len(2)
            .option(Ipv6Option::pad1())
        / Udp::new().sport(1111).dport(2222))
    .compile()?;

    assert_eq!(explicit.as_bytes()[6], IPPROTO_IPV6_DSTOPTS);
    assert_eq!(explicit.as_bytes()[40], IPPROTO_IPV6_NO_NEXT);
    assert_eq!(explicit.as_bytes()[41], 2);
    assert_eq!(ipv6_payload_length(explicit.as_bytes()), 32);

    Ok(())
}

#[test]
fn destination_options_decode_pre_routing_preserves_order_and_options() -> crafter::Result<()> {
    let options = vec![
        Ipv6Option::generic(0x1e, [0xaa])?,
        Ipv6Option::generic(0x3e, [0xbb])?,
    ];
    let compiled = (base_ipv6(64)
        / Ipv6DestinationOptionsHeader::new()
            .nh(IPPROTO_IPV6_ROUTE)
            .options(options.clone())
        / Ipv6RoutingHeader::new().routing_type(253).segments_left(0)
        / Udp::new().sport(12345).dport(33434)
        / Raw::from("pre!"))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 28, IPPROTO_IPV6_DSTOPTS, 64);
    assert_eq!(bytes[40], IPPROTO_IPV6_ROUTE);
    assert_eq!(bytes[48], IPPROTO_UDP);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();
    let dstopts = decoded
        .layer::<Ipv6DestinationOptionsHeader>()
        .expect("destination options layer");
    let routing = decoded.layer::<Ipv6RoutingHeader>().expect("routing layer");
    let udp = decoded.layer::<Udp>().expect("udp layer");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(
        layer_names,
        vec![
            "Ipv6",
            "Ipv6DestinationOptionsHeader",
            "Ipv6RoutingHeader",
            "Udp",
            "Raw"
        ]
    );
    assert_eq!(dstopts.next_header_value(), IPPROTO_IPV6_ROUTE);
    assert_eq!(dstopts.header_ext_len_value(), Some(0));
    assert_eq!(dstopts.options_value(), options.as_slice());
    assert_eq!(routing.next_header_value(), IPPROTO_UDP);
    assert_eq!(routing.routing_type_value(), 253);
    assert_eq!(udp.destination_port_value(), 33434);
    assert_eq!(raw.as_bytes(), b"pre!");
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn destination_options_decode_after_routing_chains_to_udp() -> crafter::Result<()> {
    let options = vec![
        Ipv6Option::generic(0xde, [0x01, 0x02])?,
        Ipv6Option::padn_data([])?,
    ];
    let compiled = (base_ipv6(65)
        / Ipv6RoutingHeader::new().routing_type(253).segments_left(0)
        / Ipv6DestinationOptionsHeader::new()
            .nh(IPPROTO_UDP)
            .options(options.clone())
        / Udp::new().sport(4444).dport(5555)
        / Raw::from("dst!"))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 28, IPPROTO_IPV6_ROUTE, 65);
    assert_eq!(bytes[40], IPPROTO_IPV6_DSTOPTS);
    assert_eq!(bytes[48], IPPROTO_UDP);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();
    let dstopts = decoded
        .layer::<Ipv6DestinationOptionsHeader>()
        .expect("destination options layer");
    let udp = decoded.layer::<Udp>().expect("udp layer");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(
        layer_names,
        vec![
            "Ipv6",
            "Ipv6RoutingHeader",
            "Ipv6DestinationOptionsHeader",
            "Udp",
            "Raw"
        ]
    );
    assert_eq!(dstopts.next_header_value(), IPPROTO_UDP);
    assert_eq!(dstopts.header_ext_len_value(), Some(0));
    assert_eq!(dstopts.options_value(), options.as_slice());
    assert_eq!(udp.source_port_value(), 4444);
    assert_eq!(udp.destination_port_value(), 5555);
    assert_eq!(raw.as_bytes(), b"dst!");
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn destination_options_decode_terminal_unknown_next_header_as_raw() -> crafter::Result<()> {
    let options = vec![
        Ipv6Option::pad1(),
        Ipv6Option::generic(0x3e, [0xbb, 0xcc])?,
        Ipv6Option::pad1(),
    ];
    let compiled = (base_ipv6(66)
        / Ipv6DestinationOptionsHeader::new()
            .nh(IPPROTO_IPV6_EXPERIMENTAL_1)
            .options(options.clone())
        / Raw::from("tail"))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 12, IPPROTO_IPV6_DSTOPTS, 66);
    assert_eq!(bytes[40], IPPROTO_IPV6_EXPERIMENTAL_1);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();
    let dstopts = decoded
        .layer::<Ipv6DestinationOptionsHeader>()
        .expect("destination options layer");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(
        layer_names,
        vec!["Ipv6", "Ipv6DestinationOptionsHeader", "Raw"]
    );
    assert_eq!(dstopts.next_header_value(), IPPROTO_IPV6_EXPERIMENTAL_1);
    assert_eq!(dstopts.options_value(), options.as_slice());
    assert_eq!(raw.as_bytes(), b"tail");
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn destination_options_decode_no_next_empty_payload_without_raw() -> crafter::Result<()> {
    let compiled = (base_ipv6(67)
        / Ipv6DestinationOptionsHeader::new()
            .nh(IPPROTO_IPV6_NO_NEXT)
            .option(Ipv6Option::padn(6)?)
        / Raw::new())
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 8, IPPROTO_IPV6_DSTOPTS, 67);
    assert_eq!(bytes[40], IPPROTO_IPV6_NO_NEXT);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();
    let dstopts = decoded
        .layer::<Ipv6DestinationOptionsHeader>()
        .expect("destination options layer");

    assert_eq!(layer_names, vec!["Ipv6", "Ipv6DestinationOptionsHeader"]);
    assert_eq!(dstopts.next_header_value(), IPPROTO_IPV6_NO_NEXT);
    assert_eq!(dstopts.header_ext_len_value(), Some(0));
    assert_eq!(dstopts.options_value(), &[Ipv6Option::padn(6)?]);
    assert!(decoded.layer::<Raw>().is_none());
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn destination_options_decode_reports_truncated_header() -> crafter::Result<()> {
    let bytes = (base_ipv6(68).nh(IPPROTO_IPV6_DSTOPTS)
        / Raw::from_bytes([IPPROTO_UDP, 0, IPV6_OPTION_PAD1]))
    .compile()?;

    match Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap_err() {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "ipv6 destination options header");
            assert_eq!(required, 8);
            assert_eq!(available, 3);
        }
        other => {
            panic!("truncated Destination Options header expected BufferTooShort, got {other:?}")
        }
    }

    Ok(())
}

#[test]
fn destination_options_decode_reports_option_length_overrun() -> crafter::Result<()> {
    let bytes = (base_ipv6(69).nh(IPPROTO_IPV6_DSTOPTS)
        / Raw::from_bytes([IPPROTO_UDP, 0, 0x22, 7, 0xaa, 0xbb, 0xcc, 0xdd]))
    .compile()?;

    match Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap_err() {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "ipv6.option.data");
            assert_eq!(required, 9);
            assert_eq!(available, 6);
        }
        other => {
            panic!("overrunning Destination Options option expected BufferTooShort, got {other:?}")
        }
    }

    Ok(())
}

#[test]
fn hop_by_hop_decode_chains_to_udp_and_preserves_options() -> crafter::Result<()> {
    let options = vec![
        Ipv6Option::pad1(),
        Ipv6Option::generic(0x1e, [0xaa])?,
        Ipv6Option::padn_data([0xde, 0xad])?,
        Ipv6Option::generic(0x3e, [])?,
        Ipv6Option::padn_data([0, 0])?,
    ];
    let hop_by_hop = Ipv6HopByHopOptionsHeader::new()
        .nh(IPPROTO_UDP)
        .options(options.clone());
    let compiled =
        (base_ipv6(64) / hop_by_hop / Udp::new().sport(12345).dport(33434) / Raw::from("hbh!"))
            .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 28, IPPROTO_IPV6_HOPOPTS, 64);
    assert_eq!(bytes[40], IPPROTO_UDP);
    assert_eq!(bytes[41], 1);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    let hbh = decoded
        .layer::<Ipv6HopByHopOptionsHeader>()
        .expect("hop-by-hop layer");
    let udp = decoded.layer::<Udp>().expect("udp layer");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(
        layer_names,
        vec!["Ipv6", "Ipv6HopByHopOptionsHeader", "Udp", "Raw"]
    );
    assert_decoded_ipv6_base_header(ipv6, 28, IPPROTO_IPV6_HOPOPTS, 64);
    assert_eq!(hbh.next_header_value(), IPPROTO_UDP);
    assert_eq!(hbh.header_ext_len_value(), Some(1));
    assert_eq!(hbh.options_value(), options.as_slice());
    assert_eq!(udp.source_port_value(), 12345);
    assert_eq!(udp.destination_port_value(), 33434);
    assert_eq!(udp.length_value(), Some(12));
    assert_eq!(raw.as_bytes(), b"hbh!");
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn hop_by_hop_decode_reports_truncated_header() -> crafter::Result<()> {
    let bytes = (base_ipv6(65).nh(IPPROTO_IPV6_HOPOPTS)
        / Raw::from_bytes([IPPROTO_UDP, 0, IPV6_OPTION_PAD1]))
    .compile()?;

    match Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap_err() {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "ipv6 hop-by-hop header");
            assert_eq!(required, 8);
            assert_eq!(available, 3);
        }
        other => panic!("truncated Hop-by-Hop header expected BufferTooShort, got {other:?}"),
    }

    Ok(())
}

#[test]
fn hop_by_hop_decode_reports_option_length_overrun() -> crafter::Result<()> {
    let bytes = (base_ipv6(66).nh(IPPROTO_IPV6_HOPOPTS)
        / Raw::from_bytes([IPPROTO_UDP, 0, 0x22, 7, 0xaa, 0xbb, 0xcc, 0xdd]))
    .compile()?;

    match Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap_err() {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "ipv6.option.data");
            assert_eq!(required, 9);
            assert_eq!(available, 6);
        }
        other => panic!("overrunning Hop-by-Hop option expected BufferTooShort, got {other:?}"),
    }

    Ok(())
}

// RFC 8200 sections 4.2, 4.3, and 4.6 define the shared TLV padding
// rules and 8-octet Hdr Ext Len units for these option-bearing headers.
#[test]
fn option_padding_exact_8_octet_headers_use_deterministic_pad1_bytes() -> crafter::Result<()> {
    for kind in Ipv6OptionHeaderKind::ALL {
        let compiled = option_header_packet(kind, Vec::new(), None, None, true).compile()?;
        let bytes = compiled.as_bytes();

        assert_ipv6_wire_base_header(bytes, 16, kind.outer_next_header(), 71);
        assert_eq!(&bytes[40..48], &[IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&bytes[48..50], &1111u16.to_be_bytes());
        assert_eq!(&bytes[50..52], &2222u16.to_be_bytes());

        let expected_options = vec![Ipv6Option::pad1(); 6];
        assert_decoded_option_header(bytes, kind, 0, IPPROTO_UDP, &expected_options)?;
    }

    Ok(())
}

#[test]
fn option_padding_pad1_only_padding_is_deterministic() -> crafter::Result<()> {
    for kind in Ipv6OptionHeaderKind::ALL {
        let compiled = option_header_packet(
            kind,
            vec![Ipv6Option::pad1()],
            None,
            Some(IPPROTO_IPV6_NO_NEXT),
            false,
        )
        .compile()?;
        let bytes = compiled.as_bytes();

        assert_ipv6_wire_base_header(bytes, 8, kind.outer_next_header(), 71);
        assert_eq!(&bytes[40..48], &[IPPROTO_IPV6_NO_NEXT, 0, 0, 0, 0, 0, 0, 0]);

        let expected_options = vec![Ipv6Option::pad1(); 6];
        assert_decoded_option_header(bytes, kind, 0, IPPROTO_IPV6_NO_NEXT, &expected_options)?;
    }

    Ok(())
}

#[test]
fn option_padding_padn_can_exactly_fill_minimum_header() -> crafter::Result<()> {
    for kind in Ipv6OptionHeaderKind::ALL {
        let padn = Ipv6Option::padn(6)?;
        let compiled = option_header_packet(
            kind,
            vec![padn.clone()],
            None,
            Some(IPPROTO_IPV6_NO_NEXT),
            false,
        )
        .compile()?;
        let bytes = compiled.as_bytes();

        assert_ipv6_wire_base_header(bytes, 8, kind.outer_next_header(), 71);
        assert_eq!(
            &bytes[40..48],
            &[IPPROTO_IPV6_NO_NEXT, 0, IPV6_OPTION_PADN, 4, 0, 0, 0, 0]
        );
        assert_decoded_option_header(bytes, kind, 0, IPPROTO_IPV6_NO_NEXT, &[padn])?;
    }

    Ok(())
}

#[test]
fn option_padding_odd_option_lengths_are_zero_padded_to_8_octets() -> crafter::Result<()> {
    for kind in Ipv6OptionHeaderKind::ALL {
        let odd = Ipv6Option::generic(0x1e, [0xaa, 0xbb, 0xcc])?;
        let compiled = option_header_packet(
            kind,
            vec![odd.clone()],
            None,
            Some(IPPROTO_IPV6_NO_NEXT),
            false,
        )
        .compile()?;
        let bytes = compiled.as_bytes();

        assert_ipv6_wire_base_header(bytes, 8, kind.outer_next_header(), 71);
        assert_eq!(
            &bytes[40..48],
            &[IPPROTO_IPV6_NO_NEXT, 0, 0x1e, 3, 0xaa, 0xbb, 0xcc, 0]
        );
        assert_decoded_option_header(
            bytes,
            kind,
            0,
            IPPROTO_IPV6_NO_NEXT,
            &[odd, Ipv6Option::pad1()],
        )?;
    }

    Ok(())
}

#[test]
fn option_padding_maximum_header_extension_length_is_supported() -> crafter::Result<()> {
    for kind in Ipv6OptionHeaderKind::ALL {
        let compiled = option_header_packet(
            kind,
            vec![Ipv6Option::pad1()],
            Some(u8::MAX),
            Some(IPPROTO_IPV6_NO_NEXT),
            false,
        )
        .compile()?;
        let bytes = compiled.as_bytes();
        let extension = &bytes[40..40 + 2048];

        assert_ipv6_wire_base_header(bytes, 2048, kind.outer_next_header(), 71);
        assert_eq!(extension[0], IPPROTO_IPV6_NO_NEXT);
        assert_eq!(extension[1], u8::MAX);
        assert_eq!(extension[2], IPV6_OPTION_PAD1);
        assert!(extension[3..].iter().all(|byte| *byte == 0));

        let expected_options = vec![Ipv6Option::pad1(); 2046];
        assert_decoded_option_header(
            bytes,
            kind,
            u8::MAX,
            IPPROTO_IPV6_NO_NEXT,
            &expected_options,
        )?;
    }

    Ok(())
}

#[test]
fn option_padding_explicit_too_small_length_reports_structured_error() -> crafter::Result<()> {
    for kind in Ipv6OptionHeaderKind::ALL {
        let packet = option_header_packet(
            kind,
            vec![Ipv6Option::generic(0x1e, [0, 1, 2, 3, 4])?],
            Some(0),
            Some(IPPROTO_IPV6_NO_NEXT),
            false,
        );

        match packet.compile().unwrap_err() {
            CrafterError::InvalidFieldValue { field, reason } => {
                assert_eq!(field, kind.options_error_field());
                assert!(!reason.is_empty());
            }
            other => {
                panic!("too-small option header length expected InvalidFieldValue, got {other:?}")
            }
        }
    }

    Ok(())
}

#[test]
fn option_padding_explicit_larger_length_zero_pads_and_preserves_override() -> crafter::Result<()> {
    for kind in Ipv6OptionHeaderKind::ALL {
        let compiled =
            option_header_packet(kind, vec![Ipv6Option::pad1()], Some(2), None, true).compile()?;
        let bytes = compiled.as_bytes();
        let extension = &bytes[40..64];

        assert_ipv6_wire_base_header(bytes, 32, kind.outer_next_header(), 71);
        assert_eq!(extension[0], IPPROTO_UDP);
        assert_eq!(extension[1], 2);
        assert_eq!(extension[2], IPV6_OPTION_PAD1);
        assert!(extension[3..].iter().all(|byte| *byte == 0));
        assert_eq!(&bytes[64..66], &1111u16.to_be_bytes());
        assert_eq!(&bytes[66..68], &2222u16.to_be_bytes());

        let expected_options = vec![Ipv6Option::pad1(); 22];
        assert_decoded_option_header(bytes, kind, 2, IPPROTO_UDP, &expected_options)?;
    }

    Ok(())
}

#[test]
fn option_padding_impossible_lengths_report_structured_errors() -> crafter::Result<()> {
    for kind in Ipv6OptionHeaderKind::ALL {
        let oversized_option = Ipv6Option::generic(0x1e, vec![0; 255])?;
        let packet = option_header_packet(
            kind,
            vec![oversized_option; 8],
            None,
            Some(IPPROTO_IPV6_NO_NEXT),
            false,
        );

        match packet.compile().unwrap_err() {
            CrafterError::InvalidFieldValue { field, reason } => {
                assert_eq!(field, kind.header_ext_len_field());
                assert!(!reason.is_empty());
            }
            other => panic!("oversized option header expected InvalidFieldValue, got {other:?}"),
        }

        let declared_max = (base_ipv6(72).nh(kind.outer_next_header())
            / Raw::from_bytes([IPPROTO_UDP, u8::MAX, 0, 0, 0, 0, 0, 0]))
        .compile()?;

        match Packet::decode_from_l3(NetworkLayer::Ipv6, declared_max.as_bytes()).unwrap_err() {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, kind.decode_context());
                assert_eq!(required, 2048);
                assert_eq!(available, 8);
            }
            other => panic!(
                "impossible declared option header length expected BufferTooShort, got {other:?}"
            ),
        }
    }

    Ok(())
}

#[test]
fn ipv6_option_model() -> crafter::Result<()> {
    let pad1 = Ipv6Option::pad1();
    let padn = Ipv6Option::padn(4)?;
    let unknown = Ipv6Option::generic(0x63, [0xaa, 0xbb, 0xcc])?;

    assert_eq!(pad1.option_type(), IPV6_OPTION_PAD1);
    assert_eq!(pad1.kind(), IPV6_OPTION_PAD1);
    assert_eq!(pad1.encoded_len(), 1);
    assert_eq!(pad1.data(), &[]);
    assert_eq!(pad1.encode()?, vec![IPV6_OPTION_PAD1]);

    assert_eq!(padn.option_type(), IPV6_OPTION_PADN);
    assert_eq!(padn.encoded_len(), 4);
    assert_eq!(padn.data(), &[0, 0]);
    assert_eq!(padn.encode()?, vec![IPV6_OPTION_PADN, 2, 0, 0]);

    assert_eq!(unknown.option_type(), 0x63);
    assert_eq!(unknown.data(), &[0xaa, 0xbb, 0xcc]);
    assert_eq!(unknown.action_bits(), 1);
    assert_eq!(unknown.action(), Ipv6OptionAction::Discard);
    assert!(unknown.change_en_route());
    assert!(unknown.may_change_en_route());
    assert_eq!(unknown.rest(), 3);
    assert_eq!(unknown.option_number(), 3);
    assert_eq!(unknown.encode()?, vec![0x63, 3, 0xaa, 0xbb, 0xcc]);

    assert_eq!(Ipv6OptionAction::from_bits(0)?, Ipv6OptionAction::Skip);
    assert_eq!(
        Ipv6OptionAction::from_option_type(0xc2),
        Ipv6OptionAction::DiscardSendIcmpIfNotMulticast
    );
    assert_eq!(Ipv6OptionAction::DiscardSendIcmp.bits(), 2);

    let encoded = [
        IPV6_OPTION_PAD1,
        IPV6_OPTION_PADN,
        2,
        0,
        0,
        0x63,
        3,
        0xaa,
        0xbb,
        0xcc,
    ];
    let decoded = Ipv6Option::decode_all(&encoded)?;
    assert_eq!(decoded, vec![pad1.clone(), padn.clone(), unknown.clone()]);
    assert_eq!(
        Ipv6OptionIter::new(&encoded).collect::<crafter::Result<Vec<_>>>()?,
        decoded
    );

    let nonzero_pad = Ipv6Option::decode_all(&[IPV6_OPTION_PADN, 2, 0xde, 0xad])?;
    assert_eq!(nonzero_pad[0].data(), &[0xde, 0xad]);
    assert_eq!(
        nonzero_pad[0].encode()?,
        vec![IPV6_OPTION_PADN, 2, 0xde, 0xad]
    );

    match Ipv6Option::padn(1).unwrap_err() {
        CrafterError::InvalidFieldValue { field, reason } => {
            assert_eq!(field, "ipv6.option.padn.length");
            assert!(!reason.is_empty());
        }
        other => panic!("short PadN expected InvalidFieldValue, got {other:?}"),
    }
    match Ipv6Option::generic(IPV6_OPTION_PAD1, []).unwrap_err() {
        CrafterError::InvalidFieldValue { field, reason } => {
            assert_eq!(field, "ipv6.option.type");
            assert!(!reason.is_empty());
        }
        other => panic!("generic Pad1 expected InvalidFieldValue, got {other:?}"),
    }
    match Ipv6Option::generic(0x22, vec![0; 256]).unwrap_err() {
        CrafterError::InvalidFieldValue { field, reason } => {
            assert_eq!(field, "ipv6.option.length");
            assert!(!reason.is_empty());
        }
        other => panic!("oversized option expected InvalidFieldValue, got {other:?}"),
    }
    match Ipv6Option::decode_all(&[0x22]).unwrap_err() {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "ipv6.option.header");
            assert_eq!(required, 2);
            assert_eq!(available, 1);
        }
        other => panic!("truncated option header expected BufferTooShort, got {other:?}"),
    }
    match Ipv6Option::decode_all(&[0x22, 3, 0xaa]).unwrap_err() {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "ipv6.option.data");
            assert_eq!(required, 5);
            assert_eq!(available, 3);
        }
        other => panic!("overrunning option data expected BufferTooShort, got {other:?}"),
    }

    Ok(())
}

#[test]
fn router_alert_option_values_and_malformed_lengths() -> crafter::Result<()> {
    let rsvp = Ipv6Option::router_alert(IPV6_ROUTER_ALERT_RSVP);

    assert_eq!(IPV6_OPTION_ROUTER_ALERT, 0x05);
    assert_eq!(rsvp.option_type(), IPV6_OPTION_ROUTER_ALERT);
    assert_eq!(rsvp.kind(), IPV6_OPTION_ROUTER_ALERT);
    assert_eq!(rsvp.encoded_len(), 4);
    assert_eq!(rsvp.data(), &[0, 1]);
    assert_eq!(rsvp.router_alert_value(), Some(IPV6_ROUTER_ALERT_RSVP));
    assert_eq!(rsvp.router_alert_value_label(), Some("RSVP"));
    assert_eq!(rsvp.action_bits(), 0);
    assert_eq!(rsvp.action(), Ipv6OptionAction::Skip);
    assert!(!rsvp.change_en_route());
    assert_eq!(rsvp.rest(), 5);
    assert_eq!(
        rsvp.encode()?,
        vec![IPV6_OPTION_ROUTER_ALERT, 2, 0, IPV6_ROUTER_ALERT_RSVP as u8]
    );
    assert_eq!(
        Ipv6Option::decode_all(&[IPV6_OPTION_ROUTER_ALERT, 2, 0, 1])?,
        vec![rsvp.clone()]
    );

    let unassigned = Ipv6Option::router_alert(65502);
    assert_eq!(unassigned.router_alert_value(), Some(65502));
    assert_eq!(unassigned.router_alert_value_label(), Some("Unassigned"));
    assert_eq!(
        unassigned.encode()?,
        vec![IPV6_OPTION_ROUTER_ALERT, 2, 0xff, 0xde]
    );

    assert_eq!(ipv6_router_alert_value_label(IPV6_ROUTER_ALERT_MLD), "MLD");
    assert_eq!(
        ipv6_router_alert_value_label(IPV6_ROUTER_ALERT_ACTIVE_NETWORKS),
        "Active Networks"
    );
    assert_eq!(
        ipv6_router_alert_value_label(IPV6_ROUTER_ALERT_RESERVED),
        "Reserved"
    );
    assert_eq!(
        ipv6_router_alert_value_label(4),
        "Aggregated Reservation Nesting Level"
    );
    assert_eq!(
        ipv6_router_alert_value_label(36),
        "QoS NSLP Aggregation Levels"
    );
    assert_eq!(ipv6_router_alert_value_label(68), "NSIS NATFW NSLP");
    assert_eq!(
        ipv6_router_alert_value_label(IPV6_ROUTER_ALERT_MPLS_OAM),
        "MPLS OAM (DEPRECATED)"
    );
    assert_eq!(ipv6_router_alert_value_label(65503), "Reserved");

    let short = Ipv6Option::decode_all(&[IPV6_OPTION_ROUTER_ALERT, 1, 0xaa])?;
    assert_eq!(
        short,
        vec![Ipv6Option::Generic {
            option_type: IPV6_OPTION_ROUTER_ALERT,
            data: vec![0xaa],
        }]
    );
    assert_eq!(short[0].router_alert_value(), None);
    assert_eq!(short[0].encode()?, vec![IPV6_OPTION_ROUTER_ALERT, 1, 0xaa]);

    let long = Ipv6Option::decode_all(&[IPV6_OPTION_ROUTER_ALERT, 3, 0, 1, 2])?;
    assert_eq!(
        long,
        vec![Ipv6Option::Generic {
            option_type: IPV6_OPTION_ROUTER_ALERT,
            data: vec![0, 1, 2],
        }]
    );
    assert_eq!(long[0].router_alert_value_label(), None);
    assert_eq!(
        long[0].encode()?,
        vec![IPV6_OPTION_ROUTER_ALERT, 3, 0, 1, 2]
    );

    Ok(())
}

#[test]
fn router_alert_hop_by_hop_compile_decode_and_show() -> crafter::Result<()> {
    let router_alert = Ipv6Option::router_alert(IPV6_ROUTER_ALERT_RSVP);
    let packet = base_ipv6(64)
        / Ipv6HopByHopOptionsHeader::new().option(router_alert.clone())
        / Udp::new().sport(12345).dport(33434)
        / Raw::from("ra!");
    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 19, IPPROTO_IPV6_HOPOPTS, 64);
    assert_eq!(&bytes[40..48], &[IPPROTO_UDP, 0, 0x05, 2, 0, 1, 0, 0]);
    assert_eq!(&bytes[48..50], &12345u16.to_be_bytes());
    assert_eq!(&bytes[50..52], &33434u16.to_be_bytes());
    assert_eq!(&bytes[52..54], &11u16.to_be_bytes());

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let hop_by_hop = decoded
        .layer::<Ipv6HopByHopOptionsHeader>()
        .expect("hop-by-hop layer");
    let expected_options = vec![router_alert, Ipv6Option::pad1(), Ipv6Option::pad1()];
    assert_eq!(hop_by_hop.header_ext_len_value(), Some(0));
    assert_eq!(hop_by_hop.options_value(), expected_options.as_slice());

    let show = decoded.show();
    assert!(
        show.contains("options: Router Alert(0x05,value=RSVP(1)),0x00,0x00"),
        "{show}"
    );
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn router_alert_is_not_inserted_by_defaults() -> crafter::Result<()> {
    let compiled =
        (base_ipv6(64) / Ipv6HopByHopOptionsHeader::new() / Udp::new().sport(1111).dport(2222))
            .compile()?;
    let extension = &compiled.as_bytes()[40..48];

    assert_eq!(extension[0], IPPROTO_UDP);
    assert_eq!(extension[1], 0);
    assert!(!extension[2..].contains(&IPV6_OPTION_ROUTER_ALERT));

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())?;
    let hop_by_hop = decoded
        .layer::<Ipv6HopByHopOptionsHeader>()
        .expect("hop-by-hop layer");
    assert!(hop_by_hop
        .options_value()
        .iter()
        .all(|option| *option == Ipv6Option::pad1()));

    Ok(())
}

#[test]
fn router_alert_public_paths_exports_are_reachable() {
    let _: Ipv6Option = Ipv6Option::router_alert(IPV6_ROUTER_ALERT_MLD);
    let root = crafter::Ipv6Option::router_alert(crafter::IPV6_ROUTER_ALERT_RSVP);
    let core =
        crafter::core::Ipv6Option::router_alert(crafter::core::IPV6_ROUTER_ALERT_ACTIVE_NETWORKS);
    let protocols = crafter::protocols::Ipv6Option::router_alert(
        crafter::protocols::IPV6_ROUTER_ALERT_MPLS_OAM,
    );

    assert_eq!(crafter::IPV6_OPTION_ROUTER_ALERT, 0x05);
    assert_eq!(crafter::core::IPV6_OPTION_ROUTER_ALERT, 0x05);
    assert_eq!(crafter::protocols::IPV6_OPTION_ROUTER_ALERT, 0x05);
    assert_eq!(crafter::protocols::ipv6::IPV6_OPTION_ROUTER_ALERT, 0x05);
    assert_eq!(root.router_alert_value_label(), Some("RSVP"));
    assert_eq!(core.router_alert_value_label(), Some("Active Networks"));
    assert_eq!(
        protocols.router_alert_value_label(),
        Some("MPLS OAM (DEPRECATED)")
    );
    assert_eq!(crafter::ipv6_router_alert_value_label(70), "Unassigned");
    assert_eq!(
        crafter::core::ipv6_router_alert_value_label(65535),
        "Reserved"
    );
    assert_eq!(
        crafter::protocols::ipv6_router_alert_value_label(IPV6_ROUTER_ALERT_MLD),
        "MLD"
    );
}

#[test]
fn home_address_option_values_action_bits_and_malformed_lengths() -> crafter::Result<()> {
    let home = doc_home();
    let home_bytes = home.octets();
    let option = Ipv6Option::home_address(home);
    let mut expected = vec![IPV6_OPTION_HOME_ADDRESS, 16];
    expected.extend_from_slice(&home_bytes);

    assert_eq!(IPV6_OPTION_HOME_ADDRESS, 0xc9);
    assert_eq!(option.option_type(), IPV6_OPTION_HOME_ADDRESS);
    assert_eq!(option.kind(), IPV6_OPTION_HOME_ADDRESS);
    assert_eq!(option.encoded_len(), 18);
    assert_eq!(option.data(), home_bytes.as_slice());
    assert_eq!(option.home_address_value(), Some(home));
    assert_eq!(option.router_alert_value(), None);
    assert_eq!(option.jumbo_payload_length(), None);
    assert_eq!(option.action_bits(), 3);
    assert_eq!(
        option.action(),
        Ipv6OptionAction::DiscardSendIcmpIfNotMulticast
    );
    assert!(!option.change_en_route());
    assert!(!option.may_change_en_route());
    assert_eq!(option.rest(), 9);
    assert_eq!(option.option_number(), 9);
    assert_eq!(option.encode()?, expected);
    assert_eq!(Ipv6Option::decode_all(&expected)?, vec![option.clone()]);
    assert_eq!(
        Ipv6Option::home_address_str("2001:db8:4::40")?.home_address_value(),
        Some(home)
    );

    let short_data = home_bytes[..15].to_vec();
    let mut short_encoded = vec![IPV6_OPTION_HOME_ADDRESS, 15];
    short_encoded.extend_from_slice(&short_data);
    let short = Ipv6Option::decode_all(&short_encoded)?;
    assert_eq!(
        short,
        vec![Ipv6Option::Generic {
            option_type: IPV6_OPTION_HOME_ADDRESS,
            data: short_data.clone(),
        }]
    );
    assert_eq!(short[0].home_address_value(), None);
    assert_eq!(short[0].data(), short_data.as_slice());
    assert_eq!(short[0].encode()?, short_encoded);

    let mut long_data = home_bytes.to_vec();
    long_data.push(0xab);
    let mut long_encoded = vec![IPV6_OPTION_HOME_ADDRESS, 17];
    long_encoded.extend_from_slice(&long_data);
    let long = Ipv6Option::decode_all(&long_encoded)?;
    assert_eq!(
        long,
        vec![Ipv6Option::Generic {
            option_type: IPV6_OPTION_HOME_ADDRESS,
            data: long_data.clone(),
        }]
    );
    assert_eq!(long[0].home_address_value(), None);
    assert_eq!(long[0].data(), long_data.as_slice());
    assert_eq!(long[0].encode()?, long_encoded);

    Ok(())
}

#[test]
fn home_address_option_destination_options_compile_decode_show_and_preserve_bytes(
) -> crafter::Result<()> {
    // RFC 6275 Section 6.3 defines the Home Address option as Destination
    // Options option type 0xc9 with a 16-octet IPv6 address data field.
    let home = doc_home();
    let home_bytes = home.octets();
    let home_address = Ipv6Option::home_address(home);
    let packet = base_ipv6(64)
        / Ipv6DestinationOptionsHeader::new().option(home_address.clone())
        / Udp::new().sport(12345).dport(33434)
        / Raw::from("hoa!");
    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 36, IPPROTO_IPV6_DSTOPTS, 64);
    assert_eq!(bytes[40], IPPROTO_UDP);
    assert_eq!(bytes[41], 2);
    assert_eq!(bytes[42], IPV6_OPTION_HOME_ADDRESS);
    assert_eq!(bytes[43], 16);
    assert_eq!(&bytes[44..60], home_bytes.as_slice());
    assert_eq!(&bytes[60..64], &[0, 0, 0, 0]);
    assert_eq!(&bytes[64..66], &12345u16.to_be_bytes());
    assert_eq!(&bytes[66..68], &33434u16.to_be_bytes());
    assert_eq!(&bytes[68..70], &12u16.to_be_bytes());

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let dstopts = decoded
        .layer::<Ipv6DestinationOptionsHeader>()
        .expect("destination options layer");
    let expected_options = vec![
        home_address,
        Ipv6Option::pad1(),
        Ipv6Option::pad1(),
        Ipv6Option::pad1(),
        Ipv6Option::pad1(),
    ];

    assert_eq!(dstopts.next_header_value(), IPPROTO_UDP);
    assert_eq!(dstopts.header_ext_len_value(), Some(2));
    assert_eq!(dstopts.options_value(), expected_options.as_slice());

    let show = decoded.show();
    assert!(
        show.contains("options: Home Address(0xc9,address=2001:db8:4::40),0x00,0x00,0x00,0x00"),
        "{show}"
    );
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn home_address_option_destination_options_preserves_malformed_length_as_generic(
) -> crafter::Result<()> {
    let data = doc_home().octets()[..15].to_vec();
    let malformed = Ipv6Option::generic(IPV6_OPTION_HOME_ADDRESS, data.clone())?;
    let compiled = (base_ipv6(64)
        / Ipv6DestinationOptionsHeader::new()
            .nh(IPPROTO_IPV6_NO_NEXT)
            .option(malformed.clone())
        / Raw::new())
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 24, IPPROTO_IPV6_DSTOPTS, 64);
    assert_eq!(bytes[40], IPPROTO_IPV6_NO_NEXT);
    assert_eq!(bytes[41], 2);
    assert_eq!(bytes[42], IPV6_OPTION_HOME_ADDRESS);
    assert_eq!(bytes[43], 15);
    assert_eq!(&bytes[44..59], data.as_slice());
    assert_eq!(&bytes[59..64], &[0, 0, 0, 0, 0]);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let dstopts = decoded
        .layer::<Ipv6DestinationOptionsHeader>()
        .expect("destination options layer");
    let expected_options = vec![
        malformed,
        Ipv6Option::pad1(),
        Ipv6Option::pad1(),
        Ipv6Option::pad1(),
        Ipv6Option::pad1(),
        Ipv6Option::pad1(),
    ];

    assert_eq!(dstopts.options_value(), expected_options.as_slice());
    assert_eq!(dstopts.options_value()[0].home_address_value(), None);
    assert_eq!(dstopts.options_value()[0].data(), data.as_slice());
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn home_address_option_public_paths_exports_are_reachable() {
    let root = crafter::Ipv6Option::home_address(doc_home());
    let core = crafter::core::Ipv6Option::home_address(doc_home());
    let protocols = crafter::protocols::Ipv6Option::home_address(doc_home());

    assert_eq!(IPV6_OPTION_HOME_ADDRESS, 0xc9);
    assert_eq!(crafter::IPV6_OPTION_HOME_ADDRESS, 0xc9);
    assert_eq!(crafter::core::IPV6_OPTION_HOME_ADDRESS, 0xc9);
    assert_eq!(crafter::protocols::IPV6_OPTION_HOME_ADDRESS, 0xc9);
    assert_eq!(crafter::protocols::ipv6::IPV6_OPTION_HOME_ADDRESS, 0xc9);
    assert_eq!(root.home_address_value(), Some(doc_home()));
    assert_eq!(core.home_address_value(), Some(doc_home()));
    assert_eq!(protocols.home_address_value(), Some(doc_home()));
}

#[test]
fn jumbo_payload_option_values_and_malformed_lengths() -> crafter::Result<()> {
    let jumbo = Ipv6Option::jumbo_payload(65_536);

    assert_eq!(IPV6_OPTION_JUMBO_PAYLOAD, 0xc2);
    assert_eq!(jumbo.option_type(), IPV6_OPTION_JUMBO_PAYLOAD);
    assert_eq!(jumbo.kind(), IPV6_OPTION_JUMBO_PAYLOAD);
    assert_eq!(jumbo.encoded_len(), 6);
    assert_eq!(jumbo.data(), &[0, 1, 0, 0]);
    assert_eq!(jumbo.jumbo_payload_length(), Some(65_536));
    assert_eq!(jumbo.router_alert_value(), None);
    assert_eq!(jumbo.action_bits(), 3);
    assert_eq!(
        jumbo.action(),
        Ipv6OptionAction::DiscardSendIcmpIfNotMulticast
    );
    assert!(!jumbo.change_en_route());
    assert_eq!(jumbo.rest(), 2);
    assert_eq!(
        jumbo.encode()?,
        vec![IPV6_OPTION_JUMBO_PAYLOAD, 4, 0, 1, 0, 0]
    );
    assert_eq!(
        Ipv6Option::decode_all(&[IPV6_OPTION_JUMBO_PAYLOAD, 4, 0, 1, 0, 0])?,
        vec![jumbo.clone()]
    );

    let short = Ipv6Option::decode_all(&[IPV6_OPTION_JUMBO_PAYLOAD, 3, 0, 1, 0])?;
    assert_eq!(
        short,
        vec![Ipv6Option::Generic {
            option_type: IPV6_OPTION_JUMBO_PAYLOAD,
            data: vec![0, 1, 0],
        }]
    );
    assert_eq!(short[0].jumbo_payload_length(), None);
    assert_eq!(
        short[0].encode()?,
        vec![IPV6_OPTION_JUMBO_PAYLOAD, 3, 0, 1, 0]
    );

    let long = Ipv6Option::decode_all(&[IPV6_OPTION_JUMBO_PAYLOAD, 5, 0, 1, 0, 0, 0xab])?;
    assert_eq!(
        long,
        vec![Ipv6Option::Generic {
            option_type: IPV6_OPTION_JUMBO_PAYLOAD,
            data: vec![0, 1, 0, 0, 0xab],
        }]
    );
    assert_eq!(long[0].jumbo_payload_length(), None);
    assert_eq!(
        long[0].encode()?,
        vec![IPV6_OPTION_JUMBO_PAYLOAD, 5, 0, 1, 0, 0, 0xab]
    );

    Ok(())
}

#[test]
fn jumbo_payload_hop_by_hop_compile_decode_and_show() -> crafter::Result<()> {
    let jumbo = Ipv6Option::jumbo_payload(65_536);
    let compiled = (base_ipv6(64)
        / Ipv6HopByHopOptionsHeader::new()
            .nh(IPPROTO_IPV6_NO_NEXT)
            .option(jumbo.clone())
        / Raw::new())
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 8, IPPROTO_IPV6_HOPOPTS, 64);
    assert_eq!(
        &bytes[40..48],
        &[
            IPPROTO_IPV6_NO_NEXT,
            0,
            IPV6_OPTION_JUMBO_PAYLOAD,
            4,
            0,
            1,
            0,
            0
        ]
    );

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    let hop_by_hop = decoded
        .layer::<Ipv6HopByHopOptionsHeader>()
        .expect("hop-by-hop layer");

    assert_eq!(layer_names, vec!["Ipv6", "Ipv6HopByHopOptionsHeader"]);
    assert_decoded_ipv6_base_header(ipv6, 8, IPPROTO_IPV6_HOPOPTS, 64);
    assert_eq!(hop_by_hop.next_header_value(), IPPROTO_IPV6_NO_NEXT);
    assert_eq!(hop_by_hop.header_ext_len_value(), Some(0));
    assert_eq!(hop_by_hop.options_value(), &[jumbo]);

    let show = decoded.show();
    assert!(
        show.contains("options: Jumbo Payload(0xc2,length=65536)"),
        "{show}"
    );
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn jumbo_payload_explicit_ipv6_payload_length_zero_is_preserved_without_large_generation(
) -> crafter::Result<()> {
    // RFC 2675 jumbogram transport behavior, large-payload generation, UDP
    // length-zero handling, and pseudo-header changes are out of scope here.
    let compiled = (base_ipv6(70).plen(0)
        / Ipv6HopByHopOptionsHeader::new()
            .nh(IPPROTO_IPV6_NO_NEXT)
            .option(Ipv6Option::jumbo_payload(65_536))
        / Raw::new())
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(ipv6_payload_length(bytes), 0);
    assert_eq!(bytes[6], IPPROTO_IPV6_HOPOPTS);
    assert_eq!(bytes[7], 70);
    assert_eq!(bytes.len(), 48);
    assert_eq!(
        &bytes[40..48],
        &[
            IPPROTO_IPV6_NO_NEXT,
            0,
            IPV6_OPTION_JUMBO_PAYLOAD,
            4,
            0,
            1,
            0,
            0
        ]
    );

    Ok(())
}

#[test]
fn jumbo_payload_public_paths_exports_are_reachable() {
    let root = crafter::Ipv6Option::jumbo_payload(65_536);
    let core = crafter::core::Ipv6Option::jumbo_payload(65_537);
    let protocols = crafter::protocols::Ipv6Option::jumbo_payload(65_538);

    assert_eq!(crafter::IPV6_OPTION_JUMBO_PAYLOAD, 0xc2);
    assert_eq!(crafter::core::IPV6_OPTION_JUMBO_PAYLOAD, 0xc2);
    assert_eq!(crafter::protocols::IPV6_OPTION_JUMBO_PAYLOAD, 0xc2);
    assert_eq!(crafter::protocols::ipv6::IPV6_OPTION_JUMBO_PAYLOAD, 0xc2);
    assert_eq!(root.jumbo_payload_length(), Some(65_536));
    assert_eq!(core.jumbo_payload_length(), Some(65_537));
    assert_eq!(protocols.jumbo_payload_length(), Some(65_538));
}

#[test]
fn ipv6_option_pad1_encodes_as_one_byte() -> crafter::Result<()> {
    let option = Ipv6Option::pad1();

    assert_eq!(option.option_type(), IPV6_OPTION_PAD1);
    assert_eq!(option.encoded_len(), 1);
    assert_eq!(option.data(), &[]);
    assert_eq!(option.encode()?, vec![IPV6_OPTION_PAD1]);
    assert_eq!(
        Ipv6Option::decode_all(&[IPV6_OPTION_PAD1])?,
        vec![Ipv6Option::Pad1]
    );

    Ok(())
}

#[test]
fn ipv6_option_padn_total_length_and_data_are_preserved() -> crafter::Result<()> {
    let zero_data = Ipv6Option::padn(2)?;
    let zero_filled = Ipv6Option::padn(5)?;
    let explicit_data = Ipv6Option::padn_data([0xde, 0xad, 0xbe])?;

    assert_eq!(zero_data.encoded_len(), 2);
    assert_eq!(zero_data.data(), &[]);
    assert_eq!(zero_data.encode()?, vec![IPV6_OPTION_PADN, 0]);

    assert_eq!(zero_filled.encoded_len(), 5);
    assert_eq!(zero_filled.data(), &[0, 0, 0]);
    assert_eq!(zero_filled.encode()?, vec![IPV6_OPTION_PADN, 3, 0, 0, 0]);

    assert_eq!(explicit_data.encoded_len(), 5);
    assert_eq!(explicit_data.data(), &[0xde, 0xad, 0xbe]);
    assert_eq!(
        explicit_data.encode()?,
        vec![IPV6_OPTION_PADN, 3, 0xde, 0xad, 0xbe]
    );
    assert_eq!(
        Ipv6Option::decode_all(&explicit_data.encode()?)?,
        vec![explicit_data]
    );

    Ok(())
}

#[test]
fn ipv6_option_generic_action_bits_follow_option_type() -> crafter::Result<()> {
    let cases = [
        (0x1e, 0, Ipv6OptionAction::Skip),
        (0x5e, 1, Ipv6OptionAction::Discard),
        (0x9e, 2, Ipv6OptionAction::DiscardSendIcmp),
        (0xde, 3, Ipv6OptionAction::DiscardSendIcmpIfNotMulticast),
    ];

    for (option_type, action_bits, action) in cases {
        let option = Ipv6Option::generic(option_type, [0xaa])?;

        assert_eq!(option.action_bits(), action_bits);
        assert_eq!(option.action(), action);
        assert_eq!(Ipv6OptionAction::from_bits(action_bits)?, action);
        assert_eq!(Ipv6OptionAction::from_option_type(option_type), action);
        assert_eq!(option.rest(), 0x1e);
        assert_eq!(option.option_number(), 0x1e);
        assert!(!option.change_en_route());
    }

    match Ipv6OptionAction::from_bits(4).unwrap_err() {
        CrafterError::InvalidFieldValue { field, reason } => {
            assert_eq!(field, "ipv6.option.action");
            assert!(!reason.is_empty());
        }
        other => panic!("oversized action bits expected InvalidFieldValue, got {other:?}"),
    }

    Ok(())
}

#[test]
fn ipv6_option_change_en_route_bit_is_independent() -> crafter::Result<()> {
    let unchanged = Ipv6Option::generic(0x1e, [0x01])?;
    let may_change = Ipv6Option::generic(0x3e, [0x01])?;
    let discard_and_may_change = Ipv6Option::generic(0x7e, [0x01])?;

    assert!(!unchanged.change_en_route());
    assert!(!unchanged.may_change_en_route());
    assert_eq!(unchanged.action(), Ipv6OptionAction::Skip);
    assert_eq!(unchanged.rest(), 0x1e);

    assert!(may_change.change_en_route());
    assert!(may_change.may_change_en_route());
    assert_eq!(may_change.action(), Ipv6OptionAction::Skip);
    assert_eq!(may_change.rest(), 0x1e);

    assert!(discard_and_may_change.change_en_route());
    assert_eq!(discard_and_may_change.action(), Ipv6OptionAction::Discard);
    assert_eq!(discard_and_may_change.rest(), 0x1e);

    Ok(())
}

#[test]
fn ipv6_option_zero_length_tlvs_roundtrip() -> crafter::Result<()> {
    let generic = Ipv6Option::generic(0x1e, [])?;
    let padn = Ipv6Option::padn_data([])?;

    assert_eq!(generic.encoded_len(), 2);
    assert_eq!(generic.data(), &[]);
    assert_eq!(generic.encode()?, vec![0x1e, 0]);
    assert_eq!(Ipv6Option::decode_all(&[0x1e, 0])?, vec![generic]);

    assert_eq!(padn.encoded_len(), 2);
    assert_eq!(padn.data(), &[]);
    assert_eq!(padn.encode()?, vec![IPV6_OPTION_PADN, 0]);
    assert_eq!(Ipv6Option::decode_all(&[IPV6_OPTION_PADN, 0])?, vec![padn]);

    Ok(())
}

#[test]
fn ipv6_option_decode_reports_malformed_length_overrun() {
    match Ipv6Option::decode_all(&[IPV6_OPTION_PAD1, 0x22, 4, 0xaa]).unwrap_err() {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "ipv6.option.data");
            assert_eq!(required, 7);
            assert_eq!(available, 4);
        }
        other => panic!("overrunning option data expected BufferTooShort, got {other:?}"),
    }

    let mut iter = Ipv6OptionIter::new(&[IPV6_OPTION_PAD1, 0x22, 4, 0xaa]);
    assert_eq!(iter.next().unwrap().unwrap(), Ipv6Option::Pad1);
    match iter.next().unwrap().unwrap_err() {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "ipv6.option.data");
            assert_eq!(required, 7);
            assert_eq!(available, 4);
        }
        other => panic!("overrunning option data expected BufferTooShort, got {other:?}"),
    }
    assert!(iter.next().is_none());
}

#[test]
fn ipv6_option_decode_encode_roundtrip_preserves_bytes() -> crafter::Result<()> {
    let encoded = vec![
        IPV6_OPTION_PAD1,
        IPV6_OPTION_PADN,
        3,
        0xde,
        0xad,
        0xbe,
        0x1e,
        0,
        0x7e,
        2,
        0xaa,
        0xbb,
        IPV6_OPTION_PAD1,
        0xde,
        4,
        0x00,
        0x01,
        0x02,
        0x03,
    ];

    let decoded = Ipv6Option::decode_all(&encoded)?;
    assert_eq!(
        decoded,
        vec![
            Ipv6Option::Pad1,
            Ipv6Option::PadN {
                data: vec![0xde, 0xad, 0xbe]
            },
            Ipv6Option::Generic {
                option_type: 0x1e,
                data: vec![]
            },
            Ipv6Option::Generic {
                option_type: 0x7e,
                data: vec![0xaa, 0xbb]
            },
            Ipv6Option::Pad1,
            Ipv6Option::Generic {
                option_type: 0xde,
                data: vec![0x00, 0x01, 0x02, 0x03]
            },
        ]
    );
    assert_eq!(
        Ipv6OptionIter::new(&encoded).collect::<crafter::Result<Vec<_>>>()?,
        decoded
    );

    let mut roundtrip = Vec::new();
    for option in &decoded {
        roundtrip.extend_from_slice(&option.encode()?);
    }
    assert_eq!(roundtrip, encoded);

    Ok(())
}

#[test]
fn traffic_class_default_and_named_dscp_helpers_roundtrip() -> crafter::Result<()> {
    assert_eq!(Dscp::default(), Dscp::default_forwarding());
    assert_eq!(Dscp::default_forwarding(), Dscp::cs0());
    assert_eq!(Ecn::default(), Ecn::not_ect());

    assert_traffic_class_roundtrip(
        Ipv6::with_addresses(doc_src(), doc_dst()),
        0x00,
        Dscp::default_forwarding(),
        Ecn::not_ect(),
    )?;

    assert_traffic_class_roundtrip(
        Ipv6::with_addresses(doc_src(), doc_dst()).dscp(Dscp::ef()),
        0xb8,
        Dscp::ef(),
        Ecn::not_ect(),
    )?;

    let class_selectors = [
        Dscp::cs0(),
        Dscp::cs1(),
        Dscp::cs2(),
        Dscp::cs3(),
        Dscp::cs4(),
        Dscp::cs5(),
        Dscp::cs6(),
        Dscp::cs7(),
    ];
    for (selector, dscp) in class_selectors.into_iter().enumerate() {
        let selector = selector as u8;
        assert_eq!(dscp.value(), selector << 3);
        assert_eq!(Dscp::class_selector(selector)?, dscp);
        assert_traffic_class_roundtrip(
            Ipv6::with_addresses(doc_src(), doc_dst()).dscp(dscp),
            dscp.value() << 2,
            dscp,
            Ecn::not_ect(),
        )?;
    }

    Ok(())
}

#[test]
fn flow_label_checked_helper_accepts_zero_one_and_maximum() -> crafter::Result<()> {
    for expected_flow_label in [0, 1, 0x000f_ffff] {
        let ipv6 = Ipv6::with_addresses(doc_src(), doc_dst())
            .try_flow_label(expected_flow_label)?
            .nh(253);
        assert_eq!(ipv6.flow_label_value(), expected_flow_label);

        let compiled = (ipv6 / Raw::from("flow")).compile()?;
        let bytes = compiled.as_bytes();
        assert_eq!(ipv6_flow_label(bytes), expected_flow_label);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
        let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
        assert_eq!(ipv6.flow_label_value(), expected_flow_label);
        assert_eq!(decoded.compile()?.as_bytes(), bytes);
    }

    Ok(())
}

#[test]
fn flow_label_checked_helper_rejects_overflow_with_structured_error() {
    let err = Ipv6::new()
        .try_flow_label(0x0010_0000)
        .expect_err("overflowing IPv6 flow label must fail");

    assert_flow_label_error(err);
}

#[test]
fn base_decode_error_flow_label_raw_override_overflow_fails_at_compile_time() {
    let raw_override = Ipv6::new().fl(0x0010_0000);
    assert_eq!(raw_override.flow_label_value(), 0x0010_0000);

    let err = (raw_override.nh(253) / Raw::new())
        .compile()
        .expect_err("raw IPv6 flow label overflow must fail at compile time");

    assert_flow_label_error(err);
}

#[test]
fn traffic_class_ecn_helpers_roundtrip_and_preserve_dscp() -> crafter::Result<()> {
    assert_eq!(Ecn::capable_0(), Ecn::ect0());
    assert_eq!(Ecn::capable_1(), Ecn::ect1());

    let dscp = Dscp::cs5();
    let cases = [
        (Ecn::not_ect(), 0b101000_00),
        (Ecn::ect1(), 0b101000_01),
        (Ecn::ect0(), 0b101000_10),
        (Ecn::ce(), 0b101000_11),
    ];

    for (ecn, expected_traffic_class) in cases {
        assert_traffic_class_roundtrip(
            Ipv6::with_addresses(doc_src(), doc_dst())
                .dscp(dscp)
                .ecn(ecn),
            expected_traffic_class,
            dscp,
            ecn,
        )?;
    }

    Ok(())
}

#[test]
fn traffic_class_api_sets_preserves_and_raw_overrides_bits() -> crafter::Result<()> {
    let dscp_preserves_ecn = Ipv6::new().traffic_class(0b000000_11).dscp(Dscp::ef());
    assert_eq!(dscp_preserves_ecn.traffic_class_value(), 0b101110_11);
    assert_eq!(dscp_preserves_ecn.dscp_value(), Dscp::ef());
    assert_eq!(dscp_preserves_ecn.ecn_value(), Ecn::ce());

    let ecn_preserves_dscp = dscp_preserves_ecn.ecn(Ecn::capable_0());
    assert_eq!(ecn_preserves_dscp.traffic_class_value(), 0b101110_10);
    assert_eq!(ecn_preserves_dscp.dscp_value(), Dscp::ef());
    assert_eq!(ecn_preserves_dscp.ecn_value(), Ecn::ect0());

    let raw_override = ecn_preserves_dscp.traffic_class(0x15);
    assert_eq!(raw_override.traffic_class_value(), 0x15);
    assert_eq!(raw_override.dscp_value(), Dscp::new(0x05)?);
    assert_eq!(raw_override.ecn_value(), Ecn::ect1());
    assert_traffic_class_roundtrip(raw_override, 0x15, Dscp::new(0x05)?, Ecn::ect1())?;

    assert_traffic_class_roundtrip(
        Ipv6::with_addresses(doc_src(), doc_dst())
            .dscp(Dscp::ef())
            .ecn(Ecn::capable_0()),
        0xba,
        Dscp::ef(),
        Ecn::ect0(),
    )?;

    Ok(())
}

#[test]
fn traffic_class_rejects_invalid_dscp_and_accepts_boundaries() -> crafter::Result<()> {
    let max_dscp = Dscp::new(63)?;
    assert_eq!(max_dscp.value(), 63);
    assert!(Dscp::new(64).is_err());
    assert!(Dscp::try_from(64).is_err());
    assert_eq!(Dscp::class_selector(7)?, Dscp::cs7());
    assert!(Dscp::class_selector(8).is_err());

    assert_eq!(Ecn::new(0)?, Ecn::not_ect());
    assert_eq!(Ecn::new(1)?, Ecn::ect1());
    assert_eq!(Ecn::new(2)?, Ecn::ect0());
    assert_eq!(Ecn::new(3)?, Ecn::ce());
    assert!(Ecn::new(4).is_err());

    assert_traffic_class_roundtrip(
        Ipv6::with_addresses(doc_src(), doc_dst())
            .dscp(max_dscp)
            .ecn(Ecn::ce()),
        0xff,
        max_dscp,
        Ecn::ce(),
    )?;

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
