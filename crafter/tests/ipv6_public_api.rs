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

fn assert_buffer_too_short_error(
    label: &str,
    error: CrafterError,
    expected_context: &'static str,
    expected_required: usize,
    expected_available: usize,
) {
    match error {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, expected_context, "{label}");
            assert_eq!(required, expected_required, "{label}");
            assert_eq!(available, expected_available, "{label}");
        }
        other => panic!("{label} expected BufferTooShort, got {other:?}"),
    }
}

fn assert_invalid_field_value_error(
    label: &str,
    error: CrafterError,
    expected_field: &'static str,
) {
    match error {
        CrafterError::InvalidFieldValue { field, reason } => {
            assert_eq!(field, expected_field, "{label}");
            assert!(!reason.is_empty(), "{label}");
        }
        other => panic!("{label} expected InvalidFieldValue, got {other:?}"),
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
    assert_ipv6_decode_error_entrypoints(bytes, expected);
}

fn assert_ipv6_decode_error_entrypoints(bytes: &[u8], expected: ExpectedBaseDecodeError) {
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

fn ipv6_with_routing_payload(payload: &[u8]) -> Vec<u8> {
    (base_ipv6(109).nh(IPPROTO_IPV6_ROUTE) / Raw::from_bytes(payload))
        .compile()
        .expect("malformed routing payload envelope should compile")
        .as_bytes()
        .to_vec()
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

fn raw_option_header_packet_bytes(
    kind: Ipv6OptionHeaderKind,
    raw_header: impl AsRef<[u8]>,
) -> crafter::Result<Vec<u8>> {
    Ok(
        (base_ipv6(73).nh(kind.outer_next_header()) / Raw::from_bytes(raw_header))
            .compile()?
            .into_bytes(),
    )
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

fn assert_decoded_extension_order(
    bytes: &[u8],
    expected_layer_names: &[&str],
) -> crafter::Result<()> {
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();

    assert_eq!(layer_names.as_slice(), expected_layer_names);
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
fn extension_inspection_summary_and_show_list_option_headers() -> crafter::Result<()> {
    let compiled = (base_ipv6(64)
        / Ipv6HopByHopOptionsHeader::new().options([
            Ipv6Option::router_alert(IPV6_ROUTER_ALERT_RSVP),
            Ipv6Option::jumbo_payload(65_536),
            Ipv6Option::unknown(0x13, [])?,
        ])
        / Ipv6DestinationOptionsHeader::new()
            .nh(IPPROTO_IPV6_NO_NEXT)
            .options([Ipv6Option::home_address(doc_home()), Ipv6Option::padn(2)?])
        / Raw::new())
    .compile()?;

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())?;

    let hop_by_hop_options = "Router Alert(0x05,value=RSVP(1)),Jumbo Payload(0xc2,length=65536),Generic(kind=0x13,len=0,act=0,chg=0,rest=0x13,data=empty),0x00,0x00";
    let destination_options = "Home Address(0xc9,address=2001:db8:4::40),0x01,0x00,0x00";

    assert_eq!(
        decoded.summary(),
        format!(
            "Ipv6(src={}, dst={}, next=hop-by-hop-options(0)) / Ipv6HopByHopOptionsHeader(options={hop_by_hop_options}, next=destination-options(60)) / Ipv6DestinationOptionsHeader(options={destination_options}, next=no-next(59))",
            doc_src(),
            doc_dst()
        )
    );

    assert_eq!(
        decoded.show(),
        format!(
            "Packet(len=80, layers=3)\n  [0] Ipv6\n      version: 6\n      traffic_class: 0x2a\n      dscp: 10\n      ecn: 2\n      flow_label: 0x12345\n      payload_length: 40\n      next_header: hop-by-hop-options(0)\n      hop_limit: 64\n      src: {}\n      dst: {}\n  [1] Ipv6HopByHopOptionsHeader\n      next_header: destination-options(60)\n      header_ext_len: 1\n      options: {hop_by_hop_options}\n  [2] Ipv6DestinationOptionsHeader\n      next_header: no-next(59)\n      header_ext_len: 2\n      options: {destination_options}",
            doc_src(),
            doc_dst()
        )
    );

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
    let _: Ipv6FragmentHeaderStatus = Ipv6FragmentHeaderStatus::Atomic;
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
    let _: crafter::Ipv6FragmentHeaderStatus = crafter::Ipv6FragmentHeaderStatus::Initial;
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
    let _: crafter::core::Ipv6FragmentHeaderStatus =
        crafter::core::Ipv6FragmentHeaderStatus::NonInitial;
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
    let _: crafter::protocols::Ipv6FragmentHeaderStatus =
        crafter::protocols::Ipv6FragmentHeaderStatus::Atomic;
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
    assert_eq!(
        ipv6_fragment_header_status_label(Ipv6FragmentHeaderStatus::Atomic),
        "atomic"
    );
    assert_eq!(
        crafter::core::ipv6_fragment_header_status_label(
            crafter::core::Ipv6FragmentHeaderStatus::Initial,
        ),
        "initial"
    );
    assert_eq!(
        crafter::protocols::ipv6_fragment_header_status_label(
            crafter::protocols::Ipv6FragmentHeaderStatus::NonInitial,
        ),
        "non-initial"
    );
}

#[test]
fn fragment_api_exposes_source_backed_field_helpers() -> crafter::Result<()> {
    let fragment = Ipv6FragmentHeader::new()
        .nh(IPPROTO_UDP)
        .reserved(0xab)
        .offset(2)
        .res(0b10)
        .mflag(true)
        .id(0x0102_0304);

    assert_eq!(fragment.next_header_value(), IPPROTO_UDP);
    assert_eq!(fragment.fragment_offset_value(), 2);
    assert_eq!(fragment.offset_value(), 2);
    assert_eq!(fragment.fragment_offset_units(), 2);
    assert_eq!(fragment.fragment_offset_bytes(), 16);
    assert_eq!(fragment.reserved_value(), 0xab);
    assert_eq!(fragment.reserved_byte_value(), 0xab);
    assert_eq!(fragment.res_value(), 0b10);
    assert_eq!(fragment.reserved_bits_value(), 0b10);
    assert!(!fragment.reserved_bits_are_zero());
    assert!(!fragment.reserved_fields_are_zero());
    assert!(fragment.has_more_fragments());
    assert!(fragment.more_fragments_value());
    assert!(fragment.mflag_value());
    assert!(!fragment.is_last_fragment());
    assert_eq!(fragment.identification_value(), 0x0102_0304);
    assert_eq!(fragment.id_value(), 0x0102_0304);
    assert_eq!(
        fragment.fragment_status(),
        Ipv6FragmentHeaderStatus::NonInitial
    );
    assert_eq!(fragment.status(), Ipv6FragmentHeaderStatus::NonInitial);
    assert_eq!(fragment.fragment_status_label(), "non-initial");
    assert!(!fragment.is_atomic_fragment());
    assert!(!fragment.is_initial_fragment());
    assert!(fragment.is_non_initial_fragment());

    let compiled = (base_ipv6(64) / fragment / Raw::from_bytes([1, 2, 3, 4])).compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 12, IPPROTO_IPV6_FRAGMENT, 64);
    assert_eq!(bytes[40], IPPROTO_UDP);
    assert_eq!(bytes[41], 0xab);
    assert_eq!(u16_field(bytes, 42), (2u16 << 3) | (0b10u16 << 1) | 1);
    assert_eq!(&bytes[44..48], &0x0102_0304u32.to_be_bytes());

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let decoded_fragment = decoded
        .layer::<Ipv6FragmentHeader>()
        .expect("fragment layer");
    let raw = decoded.layer::<Raw>().expect("raw fragment payload");

    assert!(decoded.layer::<Udp>().is_none());
    assert_eq!(decoded_fragment.reserved_byte_value(), 0xab);
    assert_eq!(decoded_fragment.reserved_bits_value(), 0b10);
    assert_eq!(
        decoded_fragment.fragment_status(),
        Ipv6FragmentHeaderStatus::NonInitial
    );
    assert_eq!(decoded_fragment.fragment_offset_bytes(), 16);
    assert_eq!(raw.as_bytes(), &[1, 2, 3, 4]);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn fragment_api_classifies_atomic_initial_and_non_initial_status() -> crafter::Result<()> {
    let atomic = Ipv6FragmentHeader::new()
        .nh(IPPROTO_UDP)
        .frag(0)
        .mflag(false)
        .id(0x1122_3344);
    assert_eq!(atomic.fragment_status(), Ipv6FragmentHeaderStatus::Atomic);
    assert_eq!(atomic.fragment_status_label(), "atomic");
    assert!(atomic.fragment_status().is_atomic());
    assert!(atomic.fragment_status().is_initial());
    assert!(!atomic.fragment_status().is_non_initial());
    assert!(atomic.is_atomic_fragment());
    assert!(atomic.is_initial_fragment());
    assert!(!atomic.is_non_initial_fragment());
    assert!(atomic.is_last_fragment());
    assert!(atomic.reserved_fields_are_zero());

    let atomic_packet =
        (base_ipv6(65) / atomic / Udp::new().sport(5300).dport(5301) / Raw::from("atomic"))
            .compile()?;
    let atomic_bytes = atomic_packet.as_bytes();
    let atomic_decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, atomic_bytes)?;
    let atomic_fragment = atomic_decoded
        .layer::<Ipv6FragmentHeader>()
        .expect("fragment layer");

    assert!(atomic_decoded.layer::<Udp>().is_some());
    assert_eq!(
        atomic_fragment.fragment_status(),
        Ipv6FragmentHeaderStatus::Atomic
    );
    assert_eq!(atomic_fragment.fragment_offset_units(), 0);
    assert_eq!(atomic_fragment.fragment_offset_bytes(), 0);
    assert_eq!(atomic_fragment.id_value(), 0x1122_3344);

    let show = atomic_decoded.show();
    assert!(show.contains("fragment_status: atomic"));
    assert!(show.contains("fragment_offset_bytes: 0"));
    assert!(show.contains("reserved_fields_zero: true"));

    let initial = Ipv6FragmentHeader::new().frag(0).mflag(true);
    assert_eq!(initial.fragment_status(), Ipv6FragmentHeaderStatus::Initial);
    assert_eq!(
        ipv6_fragment_header_status_label(initial.fragment_status()),
        "initial"
    );
    assert!(initial.is_initial_fragment());
    assert!(!initial.is_atomic_fragment());
    assert!(!initial.is_last_fragment());

    let non_initial_last = Ipv6FragmentHeader::new().frag(4).mflag(false);
    assert_eq!(
        non_initial_last.fragment_status(),
        Ipv6FragmentHeaderStatus::NonInitial
    );
    assert_eq!(non_initial_last.fragment_status_label(), "non-initial");
    assert_eq!(non_initial_last.fragment_offset_bytes(), 32);
    assert!(!non_initial_last.is_initial_fragment());
    assert!(non_initial_last.is_non_initial_fragment());
    assert!(non_initial_last.is_last_fragment());

    Ok(())
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
fn extension_order_hop_by_hop_before_destination_preserves_user_order() -> crafter::Result<()> {
    // RFC 8200 recommends extension order, but libcrafter preserves the caller's
    // composed packet stack instead of silently reordering extension headers.
    let compiled = (base_ipv6(80)
        / Ipv6HopByHopOptionsHeader::new().option(Ipv6Option::pad1())
        / Ipv6DestinationOptionsHeader::new().option(Ipv6Option::generic(0x1e, [0xaa])?)
        / Udp::new().sport(4100).dport(4101)
        / Raw::from("hbdst"))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(bytes[6], IPPROTO_IPV6_HOPOPTS);
    assert_eq!(bytes[40], IPPROTO_IPV6_DSTOPTS);
    assert_eq!(bytes[48], IPPROTO_UDP);
    assert_decoded_extension_order(
        bytes,
        &[
            "Ipv6",
            "Ipv6HopByHopOptionsHeader",
            "Ipv6DestinationOptionsHeader",
            "Udp",
            "Raw",
        ],
    )
}

#[test]
fn extension_order_destination_before_routing_preserves_user_order() -> crafter::Result<()> {
    let compiled = (base_ipv6(81)
        / Ipv6DestinationOptionsHeader::new().option(Ipv6Option::generic(0x3e, [0xbb])?)
        / Ipv6RoutingHeader::new().routing_type(253).segments_left(0)
        / Udp::new().sport(4200).dport(4201)
        / Raw::from("dst-route"))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(bytes[6], IPPROTO_IPV6_DSTOPTS);
    assert_eq!(bytes[40], IPPROTO_IPV6_ROUTE);
    assert_eq!(bytes[48], IPPROTO_UDP);
    assert_decoded_extension_order(
        bytes,
        &[
            "Ipv6",
            "Ipv6DestinationOptionsHeader",
            "Ipv6RoutingHeader",
            "Udp",
            "Raw",
        ],
    )
}

#[test]
fn extension_order_routing_before_destination_preserves_user_order() -> crafter::Result<()> {
    let compiled = (base_ipv6(82)
        / Ipv6RoutingHeader::new().routing_type(253).segments_left(0)
        / Ipv6DestinationOptionsHeader::new().option(Ipv6Option::generic(0x5e, [0xcc])?)
        / Udp::new().sport(4300).dport(4301)
        / Raw::from("route-dst"))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(bytes[6], IPPROTO_IPV6_ROUTE);
    assert_eq!(bytes[40], IPPROTO_IPV6_DSTOPTS);
    assert_eq!(bytes[48], IPPROTO_UDP);
    assert_decoded_extension_order(
        bytes,
        &[
            "Ipv6",
            "Ipv6RoutingHeader",
            "Ipv6DestinationOptionsHeader",
            "Udp",
            "Raw",
        ],
    )
}

#[test]
fn extension_order_unusual_destination_hop_by_hop_routing_preserves_bytes() -> crafter::Result<()> {
    let compiled = (base_ipv6(83)
        / Ipv6DestinationOptionsHeader::new().option(Ipv6Option::pad1())
        / Ipv6HopByHopOptionsHeader::new().option(Ipv6Option::generic(0x7e, [0xdd])?)
        / Ipv6RoutingHeader::new().routing_type(253).segments_left(0)
        / Udp::new().sport(4400).dport(4401)
        / Raw::from("unusual"))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(bytes[6], IPPROTO_IPV6_DSTOPTS);
    assert_eq!(bytes[40], IPPROTO_IPV6_HOPOPTS);
    assert_eq!(bytes[48], IPPROTO_IPV6_ROUTE);
    assert_eq!(bytes[56], IPPROTO_UDP);
    assert_decoded_extension_order(
        bytes,
        &[
            "Ipv6",
            "Ipv6DestinationOptionsHeader",
            "Ipv6HopByHopOptionsHeader",
            "Ipv6RoutingHeader",
            "Udp",
            "Raw",
        ],
    )
}

#[test]
fn extension_chaining_full_chain_autofills_each_next_header() -> crafter::Result<()> {
    let payload = b"chain";
    let compiled = (base_ipv6(84)
        / Ipv6HopByHopOptionsHeader::new()
        / Ipv6DestinationOptionsHeader::new()
        / Ipv6RoutingHeader::new()
            .routing_type(253)
            .segments_left(0)
            .type_data(vec![0xde, 0xad, 0xbe, 0xef])
        / Ipv6FragmentHeader::new()
            .identification(0xfeed_beef)
            .fragment_offset(0)
            .more_fragments(false)
        / Udp::new().sport(4500).dport(4501)
        / Raw::from_bytes(payload))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 45, IPPROTO_IPV6_HOPOPTS, 84);
    assert_eq!(bytes[40], IPPROTO_IPV6_DSTOPTS);
    assert_eq!(bytes[48], IPPROTO_IPV6_ROUTE);
    assert_eq!(bytes[56], IPPROTO_IPV6_FRAGMENT);
    assert_eq!(bytes[64], IPPROTO_UDP);
    assert_eq!(u16_field(bytes, 76), 13);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    let hop_by_hop = decoded
        .layer::<Ipv6HopByHopOptionsHeader>()
        .expect("hop-by-hop layer");
    let destination_options = decoded
        .layer::<Ipv6DestinationOptionsHeader>()
        .expect("destination options layer");
    let routing = decoded.layer::<Ipv6RoutingHeader>().expect("routing layer");
    let fragment = decoded
        .layer::<Ipv6FragmentHeader>()
        .expect("fragment layer");
    let udp = decoded.layer::<Udp>().expect("udp layer");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(
        layer_names,
        vec![
            "Ipv6",
            "Ipv6HopByHopOptionsHeader",
            "Ipv6DestinationOptionsHeader",
            "Ipv6RoutingHeader",
            "Ipv6FragmentHeader",
            "Udp",
            "Raw",
        ]
    );
    assert_decoded_ipv6_base_header(ipv6, 45, IPPROTO_IPV6_HOPOPTS, 84);
    assert_eq!(hop_by_hop.next_header_value(), IPPROTO_IPV6_DSTOPTS);
    assert_eq!(hop_by_hop.header_ext_len_value(), Some(0));
    assert_eq!(destination_options.next_header_value(), IPPROTO_IPV6_ROUTE);
    assert_eq!(destination_options.header_ext_len_value(), Some(0));
    assert_eq!(routing.next_header_value(), IPPROTO_IPV6_FRAGMENT);
    assert_eq!(routing.header_ext_len_value(), Some(0));
    assert_eq!(routing.routing_type_value(), 253);
    assert_eq!(routing.segments_left_value(), 0);
    assert_eq!(routing.type_data_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(fragment.next_header_value(), IPPROTO_UDP);
    assert_eq!(fragment.fragment_offset_value(), 0);
    assert!(!fragment.has_more_fragments());
    assert_eq!(fragment.identification_value(), 0xfeed_beef);
    assert_eq!(udp.source_port_value(), 4500);
    assert_eq!(udp.destination_port_value(), 4501);
    assert_eq!(udp.length_value(), Some(13));
    assert_eq!(raw.as_bytes(), payload);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn extension_chaining_shorter_chains_autofill_next_headers() -> crafter::Result<()> {
    let option_payload = b"opt";
    let option_chain = (base_ipv6(85)
        / Ipv6HopByHopOptionsHeader::new()
        / Ipv6DestinationOptionsHeader::new()
        / Udp::new().sport(4600).dport(4601)
        / Raw::from_bytes(option_payload))
    .compile()?;
    let option_bytes = option_chain.as_bytes();

    assert_ipv6_wire_base_header(option_bytes, 27, IPPROTO_IPV6_HOPOPTS, 85);
    assert_eq!(option_bytes[40], IPPROTO_IPV6_DSTOPTS);
    assert_eq!(option_bytes[48], IPPROTO_UDP);

    let option_decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, option_bytes)?;
    let option_layer_names: Vec<_> = option_decoded.iter().map(|layer| layer.name()).collect();
    let option_ipv6 = option_decoded.layer::<Ipv6>().expect("ipv6 layer");
    let option_hop_by_hop = option_decoded
        .layer::<Ipv6HopByHopOptionsHeader>()
        .expect("hop-by-hop layer");
    let option_destination = option_decoded
        .layer::<Ipv6DestinationOptionsHeader>()
        .expect("destination options layer");
    let option_udp = option_decoded.layer::<Udp>().expect("udp layer");
    let option_raw = option_decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(
        option_layer_names,
        vec![
            "Ipv6",
            "Ipv6HopByHopOptionsHeader",
            "Ipv6DestinationOptionsHeader",
            "Udp",
            "Raw",
        ]
    );
    assert_decoded_ipv6_base_header(option_ipv6, 27, IPPROTO_IPV6_HOPOPTS, 85);
    assert_eq!(option_hop_by_hop.next_header_value(), IPPROTO_IPV6_DSTOPTS);
    assert_eq!(option_destination.next_header_value(), IPPROTO_UDP);
    assert_eq!(option_udp.source_port_value(), 4600);
    assert_eq!(option_udp.destination_port_value(), 4601);
    assert_eq!(option_udp.length_value(), Some(11));
    assert_eq!(option_raw.as_bytes(), option_payload);
    assert_eq!(option_decoded.compile()?.as_bytes(), option_bytes);

    let fragment_payload = b"rf";
    let route_fragment_chain = (base_ipv6(86)
        / Ipv6RoutingHeader::new()
            .routing_type(253)
            .segments_left(0)
            .type_data(vec![0x10, 0x20, 0x30, 0x40])
        / Ipv6FragmentHeader::new()
            .identification(0x0102_0304)
            .fragment_offset(0)
            .more_fragments(false)
        / Udp::new().sport(4700).dport(4701)
        / Raw::from_bytes(fragment_payload))
    .compile()?;
    let route_fragment_bytes = route_fragment_chain.as_bytes();

    assert_ipv6_wire_base_header(route_fragment_bytes, 26, IPPROTO_IPV6_ROUTE, 86);
    assert_eq!(route_fragment_bytes[40], IPPROTO_IPV6_FRAGMENT);
    assert_eq!(route_fragment_bytes[48], IPPROTO_UDP);

    let route_fragment_decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, route_fragment_bytes)?;
    let route_fragment_layer_names: Vec<_> = route_fragment_decoded
        .iter()
        .map(|layer| layer.name())
        .collect();
    let route_fragment_ipv6 = route_fragment_decoded.layer::<Ipv6>().expect("ipv6 layer");
    let route_fragment_routing = route_fragment_decoded
        .layer::<Ipv6RoutingHeader>()
        .expect("routing layer");
    let route_fragment_fragment = route_fragment_decoded
        .layer::<Ipv6FragmentHeader>()
        .expect("fragment layer");
    let route_fragment_udp = route_fragment_decoded.layer::<Udp>().expect("udp layer");
    let route_fragment_raw = route_fragment_decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(
        route_fragment_layer_names,
        vec![
            "Ipv6",
            "Ipv6RoutingHeader",
            "Ipv6FragmentHeader",
            "Udp",
            "Raw",
        ]
    );
    assert_decoded_ipv6_base_header(route_fragment_ipv6, 26, IPPROTO_IPV6_ROUTE, 86);
    assert_eq!(
        route_fragment_routing.next_header_value(),
        IPPROTO_IPV6_FRAGMENT
    );
    assert_eq!(route_fragment_routing.header_ext_len_value(), Some(0));
    assert_eq!(route_fragment_routing.routing_type_value(), 253);
    assert_eq!(route_fragment_routing.segments_left_value(), 0);
    assert_eq!(
        route_fragment_routing.type_data_bytes(),
        &[0x10, 0x20, 0x30, 0x40]
    );
    assert_eq!(route_fragment_fragment.next_header_value(), IPPROTO_UDP);
    assert_eq!(route_fragment_fragment.fragment_offset_value(), 0);
    assert!(!route_fragment_fragment.has_more_fragments());
    assert_eq!(route_fragment_fragment.identification_value(), 0x0102_0304);
    assert_eq!(route_fragment_udp.source_port_value(), 4700);
    assert_eq!(route_fragment_udp.destination_port_value(), 4701);
    assert_eq!(route_fragment_udp.length_value(), Some(10));
    assert_eq!(route_fragment_raw.as_bytes(), fragment_payload);
    assert_eq!(
        route_fragment_decoded.compile()?.as_bytes(),
        route_fragment_bytes
    );

    Ok(())
}

#[test]
fn extension_chaining_middle_explicit_next_header_override_is_preserved() -> crafter::Result<()> {
    let destination_options = Ipv6DestinationOptionsHeader::new().next_header(IPPROTO_IPV6_NO_NEXT);
    assert_eq!(
        destination_options.next_header_value(),
        IPPROTO_IPV6_NO_NEXT
    );

    let payload = b"override";
    let compiled = (base_ipv6(87)
        / Ipv6HopByHopOptionsHeader::new()
        / destination_options
        / Ipv6RoutingHeader::new().routing_type(253).segments_left(0)
        / Ipv6FragmentHeader::new()
            .identification(0x0a0b_0c0d)
            .fragment_offset(0)
            .more_fragments(false)
        / Udp::new().sport(4800).dport(4801)
        / Raw::from_bytes(payload))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 48, IPPROTO_IPV6_HOPOPTS, 87);
    assert_eq!(bytes[40], IPPROTO_IPV6_DSTOPTS);
    assert_eq!(bytes[48], IPPROTO_IPV6_NO_NEXT);
    assert_eq!(bytes[56], IPPROTO_IPV6_FRAGMENT);
    assert_eq!(bytes[64], IPPROTO_UDP);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    let hop_by_hop = decoded
        .layer::<Ipv6HopByHopOptionsHeader>()
        .expect("hop-by-hop layer");
    let destination_options = decoded
        .layer::<Ipv6DestinationOptionsHeader>()
        .expect("destination options layer");
    let raw_tail = decoded.layer::<Raw>().expect("raw tail");

    assert_eq!(
        layer_names,
        vec![
            "Ipv6",
            "Ipv6HopByHopOptionsHeader",
            "Ipv6DestinationOptionsHeader",
            "Raw",
        ]
    );
    assert_decoded_ipv6_base_header(ipv6, 48, IPPROTO_IPV6_HOPOPTS, 87);
    assert_eq!(hop_by_hop.next_header_value(), IPPROTO_IPV6_DSTOPTS);
    assert_eq!(
        destination_options.next_header_value(),
        IPPROTO_IPV6_NO_NEXT
    );
    assert_eq!(raw_tail.as_bytes(), &bytes[56..]);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn generic_routing_experimental_types_preserve_segments_left_and_padded_type_data(
) -> crafter::Result<()> {
    let payload = [0xa0, 0xb0, 0xc0];

    for (index, routing_type) in [253, 254].into_iter().enumerate() {
        let hop_limit = 88 + index as u8;
        let segments_left = 1 + index as u8;
        let following_next_header = if routing_type == 253 {
            IPPROTO_IPV6_EXPERIMENTAL_2
        } else {
            IPPROTO_IPV6_EXPERIMENTAL_1
        };
        let type_data = vec![routing_type, 0x10, 0x20, 0x30, 0x40];

        let compiled = (base_ipv6(hop_limit)
            / Ipv6RoutingHeader::new()
                .nh(following_next_header)
                .routing_type(routing_type)
                .segments_left(segments_left)
                .type_data(type_data.clone())
            / Raw::from_bytes(payload))
        .compile()?;
        let bytes = compiled.as_bytes();

        assert_ipv6_wire_base_header(bytes, 19, IPPROTO_IPV6_ROUTE, hop_limit);
        assert_eq!(bytes[40], following_next_header);
        assert_eq!(bytes[41], 1);
        assert_eq!(bytes[42], routing_type);
        assert_eq!(bytes[43], segments_left);
        assert_eq!(&bytes[44..49], type_data.as_slice());
        assert!(bytes[49..56].iter().all(|byte| *byte == 0));
        assert_eq!(&bytes[56..], payload);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
        let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();
        let routing = decoded.layer::<Ipv6RoutingHeader>().expect("routing layer");
        let raw = decoded.layer::<Raw>().expect("raw payload");

        let mut expected_type_data = type_data;
        expected_type_data.extend_from_slice(&[0; 7]);

        assert_eq!(layer_names, vec!["Ipv6", "Ipv6RoutingHeader", "Raw"]);
        assert_eq!(routing.next_header_value(), following_next_header);
        assert_eq!(routing.header_ext_len_value(), Some(1));
        assert_eq!(routing.routing_type_value(), routing_type);
        assert_eq!(routing.segments_left_value(), segments_left);
        assert_eq!(routing.type_data_bytes(), expected_type_data.as_slice());
        assert_eq!(raw.as_bytes(), payload);
        assert_eq!(decoded.compile()?.as_bytes(), bytes);
    }

    Ok(())
}

#[test]
fn routing_classification_helpers_and_public_exports_are_source_backed() {
    assert_eq!(IPV6_ROUTING_TYPE_SOURCE_ROUTE, 0);
    assert_eq!(IPV6_ROUTING_TYPE_RH0, IPV6_ROUTING_TYPE_SOURCE_ROUTE);
    assert_eq!(IPV6_ROUTING_TYPE_NIMROD, 1);
    assert_eq!(IPV6_ROUTING_TYPE_MOBILE, 2);
    assert_eq!(IPV6_ROUTING_TYPE_RPL, 3);
    assert_eq!(IPV6_ROUTING_TYPE_SEGMENT, 4);
    assert_eq!(IPV6_ROUTING_TYPE_CRH16, 5);
    assert_eq!(IPV6_ROUTING_TYPE_CRH32, 6);
    assert_eq!(IPV6_ROUTING_TYPE_EXPERIMENTAL_1, 253);
    assert_eq!(IPV6_ROUTING_TYPE_EXPERIMENTAL_2, 254);
    assert_eq!(IPV6_ROUTING_TYPE_RESERVED, 255);

    assert_eq!(
        ipv6_routing_type_label(IPV6_ROUTING_TYPE_RH0),
        "RH0 Source Route"
    );
    assert_eq!(
        ipv6_routing_type_status(IPV6_ROUTING_TYPE_RH0),
        Ipv6RoutingTypeStatus::Deprecated
    );
    assert_eq!(
        ipv6_routing_type_label(IPV6_ROUTING_TYPE_MOBILE),
        "Type 2 Mobile IPv6"
    );
    assert_eq!(
        ipv6_routing_type_status(IPV6_ROUTING_TYPE_MOBILE),
        Ipv6RoutingTypeStatus::Assigned
    );
    assert_eq!(
        ipv6_routing_type_label(IPV6_ROUTING_TYPE_SEGMENT),
        "Segment Routing Header (SRH)"
    );
    assert_eq!(
        ipv6_routing_type_status(IPV6_ROUTING_TYPE_SEGMENT),
        Ipv6RoutingTypeStatus::Assigned
    );
    assert_eq!(
        ipv6_routing_type_status(IPV6_ROUTING_TYPE_EXPERIMENTAL_1),
        Ipv6RoutingTypeStatus::Experimental
    );
    assert_eq!(
        ipv6_routing_type_status(IPV6_ROUTING_TYPE_RESERVED),
        Ipv6RoutingTypeStatus::Reserved
    );
    assert_eq!(ipv6_routing_type_label(99), "Unknown");
    assert_eq!(ipv6_routing_type_status(99), Ipv6RoutingTypeStatus::Unknown);

    assert_eq!(
        crafter::ipv6_routing_type_status(crafter::IPV6_ROUTING_TYPE_RH0),
        crafter::Ipv6RoutingTypeStatus::Deprecated
    );
    assert_eq!(
        crafter::core::ipv6_routing_type_label(crafter::core::IPV6_ROUTING_TYPE_MOBILE),
        "Type 2 Mobile IPv6"
    );
    assert_eq!(
        crafter::protocols::ipv6_routing_type_status(crafter::protocols::IPV6_ROUTING_TYPE_SEGMENT),
        crafter::protocols::Ipv6RoutingTypeStatus::Assigned
    );
}

#[test]
fn routing_classification_rh0_is_deprecated_but_byte_preserving() -> crafter::Result<()> {
    let payload = [0x55, 0x66, 0x77];
    let type_data = [0xaa, 0xbb, 0xcc, 0xdd];
    let compiled = (base_ipv6(94)
        / Ipv6RoutingHeader::new()
            .nh(IPPROTO_IPV6_EXPERIMENTAL_1)
            .routing_type(IPV6_ROUTING_TYPE_RH0)
            .segments_left(1)
            .type_data(type_data)
        / Raw::from_bytes(payload))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 11, IPPROTO_IPV6_ROUTE, 94);
    assert_eq!(bytes[40], IPPROTO_IPV6_EXPERIMENTAL_1);
    assert_eq!(bytes[41], 0);
    assert_eq!(bytes[42], IPV6_ROUTING_TYPE_RH0);
    assert_eq!(bytes[43], 1);
    assert_eq!(&bytes[44..48], &type_data);
    assert_eq!(&bytes[48..], &payload);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();
    let routing = decoded.layer::<Ipv6RoutingHeader>().expect("routing layer");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(layer_names, vec!["Ipv6", "Ipv6RoutingHeader", "Raw"]);
    assert_eq!(routing.routing_type_value(), IPV6_ROUTING_TYPE_RH0);
    assert_eq!(routing.routing_type_label(), "RH0 Source Route");
    assert_eq!(
        routing.routing_type_status(),
        Ipv6RoutingTypeStatus::Deprecated
    );
    assert_eq!(routing.segments_left_value(), 1);
    assert_eq!(routing.type_data_bytes(), type_data.as_slice());
    assert_eq!(raw.as_bytes(), payload);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    let summary = decoded.summary();
    let show = decoded.show();
    assert!(
        summary.contains("RH0 Source Route (deprecated)(0)"),
        "{summary}"
    );
    assert!(
        show.contains("routing_type: RH0 Source Route (deprecated)(0)"),
        "{show}"
    );
    assert!(show.contains("routing_type_status: Deprecated"), "{show}");

    Ok(())
}

#[test]
fn routing_classification_summary_and_show_label_known_and_unknown_types() -> crafter::Result<()> {
    let unknown = Packet::from_layer(Ipv6RoutingHeader::new().routing_type(99));
    let mobile = Packet::from_layer(Ipv6MobileRoutingHeader::new().home(doc_home()));
    let segment = Packet::from_layer(Ipv6SegmentRoutingHeader::new().segment(doc_midpoint()));

    assert!(unknown.summary().contains("type=unknown(99)"));
    assert!(unknown.show().contains("routing_type_status: Unknown"));

    assert_eq!(
        mobile
            .layer::<Ipv6MobileRoutingHeader>()
            .expect("mobile routing header")
            .routing_type_status(),
        Ipv6RoutingTypeStatus::Assigned
    );
    assert!(mobile.summary().contains("Type 2 Mobile IPv6(2)"));
    assert!(mobile
        .show()
        .contains("routing_type: Type 2 Mobile IPv6(2)"));

    assert_eq!(
        segment
            .layer::<Ipv6SegmentRoutingHeader>()
            .expect("segment routing header")
            .routing_type_label(),
        "Segment Routing Header (SRH)"
    );
    assert!(segment
        .summary()
        .contains("Segment Routing Header (SRH)(4)"));
    assert!(segment
        .show()
        .contains("routing_type: Segment Routing Header (SRH)(4)"));

    Ok(())
}

#[test]
fn segment_routing_field_model_is_rfc8754_named_and_byte_preserving() -> crafter::Result<()> {
    let segment_list = [
        Ipv6Addr::new(0x2001, 0x0db8, 0x0009, 0, 0, 0, 0, 0x0090),
        doc_midpoint(),
        Ipv6Addr::new(0x2001, 0x0db8, 0x0008, 0, 0, 0, 0, 0x0080),
    ];
    let trailing_data = [0x05, 0x02, 0xaa, 0xbb];
    let packet = base_ipv6(93)
        / Ipv6SegmentRoutingHeader::new()
            .segments_left(2)
            .last_entry(2)
            .flags(0xa0)
            .tag(0x04d2)
            .segment(segment_list[0])
            .segment(segment_list[1])
            .segment(segment_list[2])
            .raw_trailing_data(trailing_data)
        / Udp::new().sport(12345).dport(33434)
        / Raw::from("srh");

    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();
    assert_ipv6_wire_base_header(bytes, 75, IPPROTO_IPV6_ROUTE, 93);
    assert_eq!(bytes[40], IPPROTO_UDP);
    assert_eq!(bytes[41], 7);
    assert_eq!(bytes[42], IPV6_ROUTING_TYPE_SEGMENT);
    assert_eq!(bytes[43], 2);
    assert_eq!(bytes[44], 2);
    assert_eq!(bytes[45], 0xa0);
    assert_eq!(u16_field(bytes, 46), 0x04d2);
    assert_eq!(&bytes[48..64], segment_list[0].octets().as_slice());
    assert_eq!(&bytes[64..80], segment_list[1].octets().as_slice());
    assert_eq!(&bytes[80..96], segment_list[2].octets().as_slice());
    assert_eq!(&bytes[96..100], trailing_data.as_slice());
    assert_eq!(&bytes[100..104], &[0, 0, 0, 0]);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();
    let segment = decoded
        .layer::<Ipv6SegmentRoutingHeader>()
        .expect("segment routing header");
    let udp = decoded.layer::<Udp>().expect("udp layer");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(
        layer_names,
        vec!["Ipv6", "Ipv6SegmentRoutingHeader", "Udp", "Raw"]
    );
    assert_eq!(segment.routing_type_value(), IPV6_ROUTING_TYPE_SEGMENT);
    assert_eq!(segment.routing_type_label(), "Segment Routing Header (SRH)");
    assert_eq!(segment.segments_left_value(), 2);
    assert_eq!(segment.last_entry_value(), 2);
    assert_eq!(segment.first_segment_value(), 2);
    assert_eq!(segment.flags_value(), 0xa0);
    assert!(segment.c_flag_value());
    assert!(!segment.p_flag_value());
    assert_eq!(segment.reserved_value(), 2);
    assert_eq!(segment.tag_value(), 0x04d2);
    assert_eq!(segment.segment_list(), segment_list.as_slice());
    assert_eq!(segment.segments(), segment.segment_list());
    assert_eq!(
        segment.raw_trailing_data_bytes(),
        &[0x05, 0x02, 0xaa, 0xbb, 0, 0, 0, 0]
    );
    assert_eq!(
        segment.extra_data_bytes(),
        segment.raw_trailing_data_bytes()
    );
    assert_eq!(udp.source_port_value(), 12345);
    assert_eq!(raw.as_bytes(), b"srh");
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    let compatibility_aliases = Ipv6SegmentRoutingHeader::new()
        .segment(doc_midpoint())
        .first_segment(0)
        .c_flag(true)
        .pflag(true)
        .tag(0x1111)
        .extra_data([0xcc]);
    assert_eq!(compatibility_aliases.last_entry_value(), 0);
    assert_eq!(compatibility_aliases.first_segment_value(), 0);
    assert_eq!(compatibility_aliases.flags_value() & 0xc0, 0xc0);
    assert_eq!(compatibility_aliases.tag_value(), 0x1111);
    assert_eq!(compatibility_aliases.raw_trailing_data_bytes(), &[0xcc]);

    let show = decoded.show();
    assert!(show.contains("last_entry: 2"), "{show}");
    assert!(show.contains("flags: 0xa0"), "{show}");
    assert!(show.contains("tag: 0x04d2"), "{show}");
    assert!(
        show.contains("raw_trailing_data: 05 02 aa bb 00 00 00 00"),
        "{show}"
    );

    Ok(())
}

#[test]
fn segment_routing_compat_legacy_aliases_compile_and_inspect() -> crafter::Result<()> {
    let hmac = [0x5a; 32];
    let policy_one = Ipv6Addr::new(0x2001, 0x0db8, 0x0060, 0, 0, 0, 0, 0x0001);
    let policy_two = "2001:db8:60::2";
    let trailing_data = [0x00, 0xee, 0x02, 0xaa, 0xbb];

    let routing = Ipv6SegmentRoutingHeader::new()
        .nh(IPPROTO_UDP)
        .push_ipv6_segment("2001:db8:3::30")?
        .push_segment(doc_home())
        .segleft(1)
        .first_segment(1)
        .c_flag(true)
        .pflag(true)
        .reserved(2)
        .tag(0x1234)
        .policy(0, policy_one, IPV6_SEGMENT_POLICY_INGRESS)?
        .policy_str(1, policy_two, IPV6_SEGMENT_POLICY_EGRESS)?
        .policy_flag(2, IPV6_SEGMENT_POLICY_SOURCE_ADDRESS)?
        .policy_flag4(IPV6_SEGMENT_POLICY_UNSET)
        .hmac_key_id(9)
        .hmac(hmac)
        .extra_data(trailing_data);

    assert_eq!(routing.next_header_value(), IPPROTO_UDP);
    assert_eq!(routing.segments_left_value(), 1);
    assert_eq!(routing.last_entry_value(), 1);
    assert_eq!(routing.first_segment_value(), 1);
    assert_eq!(routing.flags_value(), 0xe0);
    assert!(routing.c_flag_value());
    assert!(routing.p_flag_value());
    assert_eq!(routing.reserved_value(), 2);
    assert_eq!(routing.tag_value(), 0x1234);
    assert_eq!(
        routing.policy_flags(),
        [
            IPV6_SEGMENT_POLICY_INGRESS,
            IPV6_SEGMENT_POLICY_EGRESS,
            IPV6_SEGMENT_POLICY_SOURCE_ADDRESS,
            IPV6_SEGMENT_POLICY_UNSET,
        ]
    );
    assert_eq!(routing.policies()[0], policy_one);
    assert_eq!(
        routing.policies()[1],
        policy_two.parse::<Ipv6Addr>().expect("policy address")
    );
    assert_eq!(routing.hmac_key_id_value(), 9);
    assert_eq!(routing.hmac_bytes(), &hmac);
    assert_eq!(routing.extra_data_bytes(), trailing_data.as_slice());
    assert_eq!(
        routing.raw_trailing_data_bytes(),
        routing.extra_data_bytes()
    );
    assert_eq!(routing.segment_list(), routing.segments());

    let direct_policy_flags = Ipv6SegmentRoutingHeader::new()
        .segment(doc_midpoint())
        .policy_flag1(IPV6_SEGMENT_POLICY_INGRESS)
        .policy_flag2(IPV6_SEGMENT_POLICY_EGRESS)
        .policy_flag3(IPV6_SEGMENT_POLICY_SOURCE_ADDRESS)
        .policy_flag4(IPV6_SEGMENT_POLICY_UNSET);
    assert_eq!(
        direct_policy_flags.policy_flags(),
        [
            IPV6_SEGMENT_POLICY_INGRESS,
            IPV6_SEGMENT_POLICY_EGRESS,
            IPV6_SEGMENT_POLICY_SOURCE_ADDRESS,
            IPV6_SEGMENT_POLICY_UNSET,
        ]
    );
    Packet::from_layer(direct_policy_flags).compile()?;

    let packet =
        base_ipv6(101) / routing / Udp::new().sport(12345).dport(33434) / Raw::from("compat");
    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();
    assert_ipv6_wire_base_header(bytes, 62, IPPROTO_IPV6_ROUTE, 101);
    assert_eq!(bytes[40], IPPROTO_UDP);
    assert_eq!(bytes[41], 5);
    assert_eq!(bytes[42], IPV6_ROUTING_TYPE_SEGMENT);
    assert_eq!(bytes[43], 1);
    assert_eq!(bytes[44], 1);
    assert_eq!(bytes[45], 0xe0);
    assert_eq!(u16_field(bytes, 46), 0x1234);
    assert_eq!(&bytes[80..85], trailing_data.as_slice());
    assert_eq!(&bytes[85..88], &[0, 0, 0]);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let decoded_routing = decoded
        .layer::<Ipv6SegmentRoutingHeader>()
        .expect("segment routing header");
    assert_eq!(decoded_routing.segments_left_value(), 1);
    assert_eq!(decoded_routing.last_entry_value(), 1);
    assert_eq!(decoded_routing.first_segment_value(), 1);
    assert_eq!(decoded_routing.flags_value(), 0xe0);
    assert_eq!(decoded_routing.tag_value(), 0x1234);
    assert_eq!(
        decoded_routing.raw_trailing_data_bytes(),
        &[0x00, 0xee, 0x02, 0xaa, 0xbb, 0, 0, 0]
    );
    assert_eq!(
        decoded_routing.policy_flags(),
        [IPV6_SEGMENT_POLICY_UNSET; 4]
    );
    assert_eq!(decoded_routing.policies(), &[Ipv6Addr::UNSPECIFIED; 4]);
    assert_eq!(decoded_routing.hmac_key_id_value(), 0);
    assert_eq!(decoded_routing.hmac_bytes(), &[0; 32]);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    let show = decoded.show();
    assert!(show.contains("first_segment: 1"), "{show}");
    assert!(
        show.contains("extra_data: 00 ee 02 aa bb 00 00 00"),
        "{show}"
    );

    Ok(())
}

#[test]
fn segment_routing_segments_one_segment_defaults_and_roundtrip() -> crafter::Result<()> {
    let segment = Ipv6Addr::new(0x2001, 0x0db8, 0x0036, 0, 0, 0, 0, 0x0001);
    let payload = b"one";
    let compiled = (base_ipv6(101)
        / Ipv6SegmentRoutingHeader::new().segment(segment)
        / Udp::new().sport(41001).dport(41002)
        / Raw::from_bytes(payload))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 35, IPPROTO_IPV6_ROUTE, 101);
    assert_eq!(bytes[40], IPPROTO_UDP);
    assert_eq!(bytes[41], 2);
    assert_eq!(bytes[42], IPV6_ROUTING_TYPE_SEGMENT);
    assert_eq!(bytes[43], 0);
    assert_eq!(bytes[44], 0);
    assert_eq!(&bytes[48..64], &segment.octets());
    assert_eq!(u16_field(bytes, 64), 41001);
    assert_eq!(u16_field(bytes, 66), 41002);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let segment_header = decoded
        .layer::<Ipv6SegmentRoutingHeader>()
        .expect("segment routing header");
    let udp = decoded.layer::<Udp>().expect("udp layer");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(segment_header.header_ext_len_value(), Some(2));
    assert_eq!(segment_header.segments_left_value(), 0);
    assert_eq!(segment_header.last_entry_value(), 0);
    assert_eq!(segment_header.segment_list(), &[segment]);
    assert!(segment_header.raw_trailing_data_bytes().is_empty());
    assert_eq!(udp.source_port_value(), 41001);
    assert_eq!(udp.destination_port_value(), 41002);
    assert_eq!(raw.as_bytes(), payload);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn segment_routing_segments_multiple_defaults_and_length() -> crafter::Result<()> {
    let segments = [
        Ipv6Addr::new(0x2001, 0x0db8, 0x0036, 0, 0, 0, 0, 0x0010),
        Ipv6Addr::new(0x2001, 0x0db8, 0x0036, 0, 0, 0, 0, 0x0020),
        Ipv6Addr::new(0x2001, 0x0db8, 0x0036, 0, 0, 0, 0, 0x0030),
    ];
    let payload = b"multi";
    let compiled = (base_ipv6(102)
        / Ipv6SegmentRoutingHeader::new()
            .segment(segments[0])
            .segment(segments[1])
            .segment(segments[2])
        / Udp::new().sport(42001).dport(42002)
        / Raw::from_bytes(payload))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 69, IPPROTO_IPV6_ROUTE, 102);
    assert_eq!(bytes[40], IPPROTO_UDP);
    assert_eq!(bytes[41], 6);
    assert_eq!(bytes[42], IPV6_ROUTING_TYPE_SEGMENT);
    assert_eq!(bytes[43], 2);
    assert_eq!(bytes[44], 2);
    assert_eq!(&bytes[48..64], &segments[0].octets());
    assert_eq!(&bytes[64..80], &segments[1].octets());
    assert_eq!(&bytes[80..96], &segments[2].octets());
    assert_eq!(u16_field(bytes, 96), 42001);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let segment_header = decoded
        .layer::<Ipv6SegmentRoutingHeader>()
        .expect("segment routing header");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(segment_header.header_ext_len_value(), Some(6));
    assert_eq!(segment_header.segments_left_value(), 2);
    assert_eq!(segment_header.last_entry_value(), 2);
    assert_eq!(segment_header.segment_list(), segments.as_slice());
    assert!(segment_header.raw_trailing_data_bytes().is_empty());
    assert_eq!(raw.as_bytes(), payload);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn segment_routing_segments_left_and_last_entry_boundaries_are_validated() -> crafter::Result<()> {
    let segments = [
        Ipv6Addr::new(0x2001, 0x0db8, 0x0036, 0, 0, 0, 0, 0x0100),
        Ipv6Addr::new(0x2001, 0x0db8, 0x0036, 0, 0, 0, 0, 0x0200),
        Ipv6Addr::new(0x2001, 0x0db8, 0x0036, 0, 0, 0, 0, 0x0300),
    ];
    let base_segment_header = Ipv6SegmentRoutingHeader::new()
        .segment(segments[0])
        .segment(segments[1])
        .segment(segments[2]);

    Packet::from_layer(base_segment_header.clone().segments_left(0)).compile()?;
    Packet::from_layer(base_segment_header.clone().segments_left(2)).compile()?;

    let segments_left_err = Packet::from_layer(base_segment_header.clone().segments_left(3))
        .compile()
        .expect_err("segments-left equal to the segment count must be rejected");
    assert_invalid_field_value_error(
        "segment routing segments-left out of bounds",
        segments_left_err,
        "ipv6.segment.segments_left",
    );

    let last_entry_err = Packet::from_layer(base_segment_header.last_entry(3))
        .compile()
        .expect_err("last-entry equal to the segment count must be rejected");
    assert_invalid_field_value_error(
        "segment routing last-entry out of bounds",
        last_entry_err,
        "ipv6.segment.last_entry",
    );

    Ok(())
}

#[test]
fn segment_routing_segments_empty_list_is_rejected() {
    let err = Packet::from_layer(Ipv6SegmentRoutingHeader::new())
        .compile()
        .expect_err("RFC 8754 Last Entry requires at least one segment-list entry");

    assert_invalid_field_value_error(
        "segment routing empty segment list",
        err,
        "ipv6.segment.segments",
    );
}

#[test]
fn segment_routing_segments_explicit_header_extension_length_roundtrip() -> crafter::Result<()> {
    let segment = Ipv6Addr::new(0x2001, 0x0db8, 0x0036, 0, 0, 0, 0, 0x0400);
    let payload = b"pad";
    let compiled = (base_ipv6(103)
        / Ipv6SegmentRoutingHeader::new()
            .header_ext_len(4)
            .segment(segment)
        / Udp::new().sport(43001).dport(43002)
        / Raw::from_bytes(payload))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 51, IPPROTO_IPV6_ROUTE, 103);
    assert_eq!(bytes[40], IPPROTO_UDP);
    assert_eq!(bytes[41], 4);
    assert_eq!(bytes[42], IPV6_ROUTING_TYPE_SEGMENT);
    assert_eq!(bytes[43], 0);
    assert_eq!(bytes[44], 0);
    assert_eq!(&bytes[48..64], &segment.octets());
    assert!(bytes[64..80].iter().all(|byte| *byte == 0));
    assert_eq!(u16_field(bytes, 80), 43001);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let segment_header = decoded
        .layer::<Ipv6SegmentRoutingHeader>()
        .expect("segment routing header");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(segment_header.header_ext_len_value(), Some(4));
    assert_eq!(segment_header.segment_list(), &[segment]);
    assert_eq!(segment_header.raw_trailing_data_bytes(), &[0; 16]);
    assert_eq!(raw.as_bytes(), payload);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    let too_small = Packet::from_layer(
        Ipv6SegmentRoutingHeader::new()
            .header_ext_len(1)
            .segment(segment),
    )
    .compile()
    .expect_err("explicit SRH header extension length must fit the segment list");
    assert_invalid_field_value_error(
        "segment routing explicit header extension length too small",
        too_small,
        "ipv6.segment.header_ext_len",
    );

    Ok(())
}

#[test]
fn segment_routing_flags_tag_zero_values_are_encoded_and_inspectable() -> crafter::Result<()> {
    let segment = Ipv6Addr::new(0x2001, 0x0db8, 0x0037, 0, 0, 0, 0, 0x0001);
    let payload = b"zero";
    let compiled = (base_ipv6(104)
        / Ipv6SegmentRoutingHeader::new().segment(segment)
        / Udp::new().sport(44001).dport(44002)
        / Raw::from_bytes(payload))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 36, IPPROTO_IPV6_ROUTE, 104);
    assert_eq!(bytes[40], IPPROTO_UDP);
    assert_eq!(bytes[41], 2);
    assert_eq!(bytes[42], IPV6_ROUTING_TYPE_SEGMENT);
    assert_eq!(bytes[43], 0);
    assert_eq!(bytes[44], 0);
    assert_eq!(bytes[45], 0x00);
    assert_eq!(u16_field(bytes, 46), 0x0000);
    assert_eq!(&bytes[48..64], &segment.octets());
    assert_eq!(u16_field(bytes, 64), 44001);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let segment_header = decoded
        .layer::<Ipv6SegmentRoutingHeader>()
        .expect("segment routing header");

    assert_eq!(segment_header.flags_value(), 0x00);
    assert_eq!(segment_header.tag_value(), 0x0000);
    assert!(!segment_header.c_flag_value());
    assert!(!segment_header.p_flag_value());
    assert_eq!(segment_header.reserved_value(), 0);
    assert_eq!(segment_header.segment_list(), &[segment]);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    let summary = decoded.summary();
    assert!(summary.contains("flags=0x00"), "{summary}");
    assert!(summary.contains("tag=0x0000"), "{summary}");
    let show = decoded.show();
    assert!(show.contains("flags: 0x00"), "{show}");
    assert!(show.contains("tag: 0x0000"), "{show}");

    Ok(())
}

#[test]
fn segment_routing_flags_tag_preserve_unknown_bits_and_maximum_tag() -> crafter::Result<()> {
    let segment = Ipv6Addr::new(0x2001, 0x0db8, 0x0037, 0, 0, 0, 0, 0x0002);
    let payload = [0xde, 0xad, 0xbe, 0xef];
    let compiled = (base_ipv6(105)
        / Ipv6SegmentRoutingHeader::new()
            .next_header(IPPROTO_IPV6_EXPERIMENTAL_1)
            .flags(0xff)
            .tag(u16::MAX)
            .segment(segment)
        / Raw::from_bytes(payload))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 28, IPPROTO_IPV6_ROUTE, 105);
    assert_eq!(bytes[40], IPPROTO_IPV6_EXPERIMENTAL_1);
    assert_eq!(bytes[41], 2);
    assert_eq!(bytes[42], IPV6_ROUTING_TYPE_SEGMENT);
    assert_eq!(bytes[43], 0);
    assert_eq!(bytes[44], 0);
    assert_eq!(bytes[45], 0xff);
    assert_eq!(u16_field(bytes, 46), u16::MAX);
    assert_eq!(&bytes[48..64], &segment.octets());
    assert_eq!(&bytes[64..68], &payload);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let segment_header = decoded
        .layer::<Ipv6SegmentRoutingHeader>()
        .expect("segment routing header");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(segment_header.flags_value(), 0xff);
    assert!(segment_header.c_flag_value());
    assert!(segment_header.p_flag_value());
    assert_eq!(segment_header.reserved_value(), 0x03);
    assert_eq!(segment_header.tag_value(), u16::MAX);
    assert_eq!(raw.as_bytes(), payload.as_slice());
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    let summary = decoded.summary();
    assert!(summary.contains("flags=0xff"), "{summary}");
    assert!(summary.contains("tag=0xffff"), "{summary}");
    let show = decoded.show();
    assert!(show.contains("flags: 0xff"), "{show}");
    assert!(show.contains("tag: 0xffff"), "{show}");

    Ok(())
}

#[test]
fn segment_routing_flags_tag_explicit_override_roundtrip() -> crafter::Result<()> {
    let segment = Ipv6Addr::new(0x2001, 0x0db8, 0x0037, 0, 0, 0, 0, 0x0003);
    let payload = [0xaa, 0xbb, 0xcc];
    let compiled = (base_ipv6(106)
        / Ipv6SegmentRoutingHeader::new()
            .next_header(IPPROTO_IPV6_EXPERIMENTAL_1)
            .flags(0x25)
            .c_flag(true)
            .pflag(true)
            .tag(0x8001)
            .segment(segment)
        / Raw::from_bytes(payload))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 27, IPPROTO_IPV6_ROUTE, 106);
    assert_eq!(bytes[40], IPPROTO_IPV6_EXPERIMENTAL_1);
    assert_eq!(bytes[45], 0xe5);
    assert_eq!(u16_field(bytes, 46), 0x8001);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let segment_header = decoded
        .layer::<Ipv6SegmentRoutingHeader>()
        .expect("segment routing header");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(
        segment_header.next_header_value(),
        IPPROTO_IPV6_EXPERIMENTAL_1
    );
    assert_eq!(segment_header.flags_value(), 0xe5);
    assert_eq!(segment_header.flags_value() & 0x25, 0x25);
    assert_eq!(segment_header.tag_value(), 0x8001);
    assert_eq!(raw.as_bytes(), payload.as_slice());
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn segment_routing_tlv_raw_optional_data_roundtrip() -> crafter::Result<()> {
    let segment = Ipv6Addr::new(0x2001, 0x0db8, 0x0038, 0, 0, 0, 0, 0x0001);
    let optional_data = [
        0x00, // SRH Pad1-shaped byte.
        0x01, 0x02, 0x00, 0x00, // SRH PadN-shaped TLV.
        0xee, 0x03, 0xaa, 0xbb, 0xcc, // Unknown odd-length TLV-shaped data.
    ];
    let expected_trailing_data = [
        0x00, 0x01, 0x02, 0x00, 0x00, 0xee, 0x03, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let payload = b"tlv";
    let compiled = (base_ipv6(107)
        / Ipv6SegmentRoutingHeader::new()
            .segment(segment)
            .raw_trailing_data(optional_data)
        / Udp::new().sport(45001).dport(45002)
        / Raw::from_bytes(payload))
    .compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 51, IPPROTO_IPV6_ROUTE, 107);
    assert_eq!(bytes[40], IPPROTO_UDP);
    assert_eq!(bytes[41], 4);
    assert_eq!(bytes[42], IPV6_ROUTING_TYPE_SEGMENT);
    assert_eq!(bytes[43], 0);
    assert_eq!(bytes[44], 0);
    assert_eq!(&bytes[48..64], &segment.octets());
    assert_eq!(&bytes[64..74], &optional_data);
    assert_eq!(&bytes[74..80], &[0; 6]);
    assert_eq!(u16_field(bytes, 80), 45001);
    assert_eq!(u16_field(bytes, 82), 45002);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let segment_header = decoded
        .layer::<Ipv6SegmentRoutingHeader>()
        .expect("segment routing header");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(segment_header.header_ext_len_value(), Some(4));
    assert_eq!(segment_header.segment_list(), &[segment]);
    assert_eq!(
        segment_header.raw_trailing_data_bytes(),
        expected_trailing_data.as_slice()
    );
    assert_eq!(
        segment_header.extra_data_bytes(),
        segment_header.raw_trailing_data_bytes()
    );
    assert_eq!(raw.as_bytes(), payload);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    let show = decoded.show();
    assert!(
        show.contains("raw_trailing_data: 00 01 02 00 00 ee 03 aa bb cc 00 00 00 00 00 00"),
        "{show}"
    );
    assert!(
        show.contains("extra_data: 00 01 02 00 00 ee 03 aa bb cc 00 00 00 00 00 00"),
        "{show}"
    );

    Ok(())
}

#[test]
fn segment_routing_tlv_explicit_header_length_must_fit_raw_optional_data() {
    let segment = Ipv6Addr::new(0x2001, 0x0db8, 0x0038, 0, 0, 0, 0, 0x0002);
    let err = Packet::from_layer(
        Ipv6SegmentRoutingHeader::new()
            .header_ext_len(3)
            .segment(segment)
            .raw_trailing_data([0xee, 0x03, 0xaa, 0xbb, 0xcc, 0x00, 0x01, 0x02, 0x00]),
    )
    .compile()
    .expect_err("explicit SRH header length must fit raw optional data");

    assert_invalid_field_value_error(
        "segment routing raw optional data too large for explicit length",
        err,
        "ipv6.segment.header_ext_len",
    );
}

#[test]
fn segment_routing_malformed_header_shorter_than_required_is_structured() {
    let bytes = ipv6_with_routing_payload(&[IPPROTO_UDP, 0, IPV6_ROUTING_TYPE_SEGMENT, 0]);

    assert_ipv6_decode_error_entrypoints(
        &bytes,
        ExpectedBaseDecodeError::BufferTooShort {
            context: "ipv6 routing header",
            required: 8,
            available: 4,
        },
    );
}

#[test]
fn segment_routing_malformed_last_entry_requires_available_segment_bytes() {
    let bytes =
        ipv6_with_routing_payload(&[IPPROTO_UDP, 0, IPV6_ROUTING_TYPE_SEGMENT, 0, 1, 0, 0, 0]);

    assert_ipv6_decode_error_entrypoints(
        &bytes,
        ExpectedBaseDecodeError::InvalidFieldValue {
            field: "ipv6.segment.header_ext_len",
            reason: "segment routing data is shorter than its fields require",
        },
    );
}

#[test]
fn segment_routing_malformed_declared_length_shorter_than_fields_is_structured() {
    let mut route_payload = vec![IPPROTO_UDP, 1, IPV6_ROUTING_TYPE_SEGMENT, 0, 0, 0, 0, 0];
    route_payload.extend_from_slice(&[0xaa; 8]);
    let bytes = ipv6_with_routing_payload(&route_payload);

    assert_ipv6_decode_error_entrypoints(
        &bytes,
        ExpectedBaseDecodeError::InvalidFieldValue {
            field: "ipv6.segment.header_ext_len",
            reason: "segment routing data is shorter than its fields require",
        },
    );
}

#[test]
fn segment_routing_malformed_tlv_length_is_structured() {
    let segment = doc_midpoint().octets();
    let mut route_payload = vec![IPPROTO_UDP, 4, IPV6_ROUTING_TYPE_SEGMENT, 0, 0, 0, 0, 0];
    route_payload.extend_from_slice(&segment);
    route_payload.extend_from_slice(&[
        0xee, 0x0f, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a,
    ]);
    let bytes = ipv6_with_routing_payload(&route_payload);

    assert_ipv6_decode_error_entrypoints(
        &bytes,
        ExpectedBaseDecodeError::InvalidFieldValue {
            field: "ipv6.segment.tlv",
            reason: "segment routing TLV length exceeds trailing data",
        },
    );
}

#[test]
fn segment_routing_malformed_invalid_explicit_builder_values_are_structured() {
    let segment = doc_midpoint();

    let empty_err = Packet::from_layer(Ipv6SegmentRoutingHeader::new())
        .compile()
        .expect_err("empty SRH segment list must be rejected");
    assert_invalid_field_value_error(
        "segment routing empty builder segment list",
        empty_err,
        "ipv6.segment.segments",
    );

    let routing_type_err = Packet::from_layer(
        Ipv6SegmentRoutingHeader::new()
            .routing_type(3)
            .segment(segment),
    )
    .compile()
    .expect_err("SRH builder must reject non-SRH routing type");
    assert_invalid_field_value_error(
        "segment routing explicit routing type",
        routing_type_err,
        "ipv6.segment.routing_type",
    );

    let header_len_err = Packet::from_layer(
        Ipv6SegmentRoutingHeader::new()
            .header_ext_len(1)
            .segment(segment),
    )
    .compile()
    .expect_err("explicit SRH header length must fit segment fields");
    assert_invalid_field_value_error(
        "segment routing explicit header length",
        header_len_err,
        "ipv6.segment.header_ext_len",
    );

    let policy_index_err = Ipv6SegmentRoutingHeader::new()
        .policy_flag(4, 1)
        .expect_err("policy flag index must be bounded");
    assert_invalid_field_value_error(
        "segment routing policy index",
        policy_index_err,
        "ipv6.segment.policy",
    );

    let policy_flag_err = Ipv6SegmentRoutingHeader::new()
        .policy_flag(0, 8)
        .expect_err("policy flag must fit three bits");
    assert_invalid_field_value_error(
        "segment routing policy flag",
        policy_flag_err,
        "ipv6.segment.policy_flag",
    );

    let tlv_missing_len_err = Packet::from_layer(
        Ipv6SegmentRoutingHeader::new()
            .segment(segment)
            .raw_trailing_data([0xee]),
    )
    .compile()
    .expect_err("SRH TLV type without length must be rejected");
    assert_invalid_field_value_error(
        "segment routing TLV missing length",
        tlv_missing_len_err,
        "ipv6.segment.tlv",
    );

    let tlv_overrun_err = Packet::from_layer(
        Ipv6SegmentRoutingHeader::new()
            .segment(segment)
            .raw_trailing_data([0xee, 3, 0xaa]),
    )
    .compile()
    .expect_err("SRH TLV length overrun must be rejected");
    assert_invalid_field_value_error(
        "segment routing TLV length overrun",
        tlv_overrun_err,
        "ipv6.segment.tlv",
    );
}

#[test]
fn mobile_routing_api_defaults_status_and_overrides_are_inspectable() -> crafter::Result<()> {
    assert_eq!(IPV6_MOBILE_ROUTING_HEADER_EXT_LEN, 2);
    assert_eq!(IPV6_MOBILE_ROUTING_SEGMENTS_LEFT, 1);
    assert_eq!(IPV6_MOBILE_ROUTING_RESERVED, 0);
    assert_eq!(
        crafter::IPV6_MOBILE_ROUTING_HEADER_EXT_LEN,
        IPV6_MOBILE_ROUTING_HEADER_EXT_LEN
    );
    assert_eq!(
        crafter::core::IPV6_MOBILE_ROUTING_SEGMENTS_LEFT,
        IPV6_MOBILE_ROUTING_SEGMENTS_LEFT
    );
    assert_eq!(
        crafter::protocols::IPV6_MOBILE_ROUTING_RESERVED,
        IPV6_MOBILE_ROUTING_RESERVED
    );

    let header = Ipv6MobileRoutingHeader::new().home_str("2001:db8:4::40")?;

    assert_eq!(header.header_ext_len_value(), None);
    assert_eq!(
        header.effective_header_ext_len_value(),
        IPV6_MOBILE_ROUTING_HEADER_EXT_LEN
    );
    assert_eq!(
        header.header_ext_len_status(),
        Ipv6MobileRoutingHeaderStatus::Valid
    );
    assert_eq!(
        header.segments_left_value(),
        IPV6_MOBILE_ROUTING_SEGMENTS_LEFT
    );
    assert!(header.segments_left_is_defaulted());
    assert_eq!(
        header.segments_left_status(),
        Ipv6MobileRoutingHeaderStatus::Valid
    );
    assert_eq!(header.reserved_value(), IPV6_MOBILE_ROUTING_RESERVED);
    assert!(header.reserved_is_zero());
    assert_eq!(
        header.reserved_status(),
        Ipv6MobileRoutingHeaderStatus::Valid
    );
    assert_eq!(
        header.home_address_value(),
        "2001:db8:4::40".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(
        header.home_address_bytes(),
        header.home_address_value().octets()
    );
    assert_eq!(
        header.validity_status(),
        Ipv6MobileRoutingHeaderStatus::Valid
    );
    assert!(header.validity_status().is_valid());

    let compiled = (base_ipv6(95) / header / Udp::new().sport(12000).dport(12001)).compile()?;
    let bytes = compiled.as_bytes();

    assert_ipv6_wire_base_header(bytes, 32, IPPROTO_IPV6_ROUTE, 95);
    assert_eq!(bytes[40], IPPROTO_UDP);
    assert_eq!(bytes[41], IPV6_MOBILE_ROUTING_HEADER_EXT_LEN);
    assert_eq!(bytes[42], IPV6_ROUTING_TYPE_MOBILE);
    assert_eq!(bytes[43], IPV6_MOBILE_ROUTING_SEGMENTS_LEFT);
    assert_eq!(&bytes[44..48], &IPV6_MOBILE_ROUTING_RESERVED.to_be_bytes());
    assert_eq!(
        &bytes[48..64],
        &"2001:db8:4::40".parse::<Ipv6Addr>().unwrap().octets()
    );

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let mobile = decoded
        .layer::<Ipv6MobileRoutingHeader>()
        .expect("mobile routing header");

    assert_eq!(
        mobile.header_ext_len_value(),
        Some(IPV6_MOBILE_ROUTING_HEADER_EXT_LEN)
    );
    assert_eq!(
        mobile.effective_header_ext_len_value(),
        IPV6_MOBILE_ROUTING_HEADER_EXT_LEN
    );
    assert!(!mobile.segments_left_is_defaulted());
    assert_eq!(
        mobile.validity_status(),
        Ipv6MobileRoutingHeaderStatus::Valid
    );
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    let show = decoded.show();
    assert!(show.contains("validity_status: Valid"), "{show}");
    assert!(show.contains("segments_left_status: Valid"), "{show}");
    assert!(show.contains("reserved_status: Valid"), "{show}");

    let override_header = Ipv6MobileRoutingHeader::new()
        .nh(IPPROTO_IPV6_EXPERIMENTAL_1)
        .header_ext_len(3)
        .routing_type(99)
        .segleft(0)
        .reserved(0x0102_0304)
        .home(doc_home());

    assert_eq!(
        override_header.header_ext_len_status(),
        Ipv6MobileRoutingHeaderStatus::InvalidHeaderExtLen
    );
    assert_eq!(
        override_header.segments_left_status(),
        Ipv6MobileRoutingHeaderStatus::InvalidSegmentsLeft
    );
    assert_eq!(
        override_header.reserved_status(),
        Ipv6MobileRoutingHeaderStatus::NonzeroReserved
    );
    assert_eq!(
        override_header.validity_status(),
        Ipv6MobileRoutingHeaderStatus::InvalidRoutingType
    );
    assert!(!override_header.validity_status().is_valid());

    let override_bytes = (base_ipv6(96) / override_header / Raw::from("override")).compile()?;
    let bytes = override_bytes.as_bytes();

    assert_ipv6_wire_base_header(bytes, 40, IPPROTO_IPV6_ROUTE, 96);
    assert_eq!(bytes[40], IPPROTO_IPV6_EXPERIMENTAL_1);
    assert_eq!(bytes[41], 3);
    assert_eq!(bytes[42], 99);
    assert_eq!(bytes[43], 0);
    assert_eq!(&bytes[44..48], &0x0102_0304u32.to_be_bytes());
    assert_eq!(&bytes[48..64], &doc_home().octets());
    assert!(bytes[64..72].iter().all(|byte| *byte == 0));
    assert_eq!(&bytes[72..], b"override");

    let decoded_override = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let generic = decoded_override
        .layer::<Ipv6RoutingHeader>()
        .expect("non-Type-2 override decodes generically");
    assert_eq!(generic.routing_type_value(), 99);
    assert_eq!(decoded_override.compile()?.as_bytes(), bytes);

    assert_eq!(
        Ipv6MobileRoutingHeader::new()
            .header_ext_len(3)
            .validity_status(),
        Ipv6MobileRoutingHeaderStatus::InvalidHeaderExtLen
    );
    assert_eq!(
        Ipv6MobileRoutingHeader::new().segleft(0).validity_status(),
        Ipv6MobileRoutingHeaderStatus::InvalidSegmentsLeft
    );
    assert_eq!(
        Ipv6MobileRoutingHeader::new().reserved(1).validity_status(),
        Ipv6MobileRoutingHeaderStatus::NonzeroReserved
    );
    assert_eq!(
        crafter::Ipv6MobileRoutingHeaderStatus::Valid,
        crafter::core::Ipv6MobileRoutingHeaderStatus::Valid
    );
    assert_eq!(
        crafter::protocols::Ipv6MobileRoutingHeaderStatus::InvalidSegmentsLeft,
        Ipv6MobileRoutingHeaderStatus::InvalidSegmentsLeft
    );

    Ok(())
}

#[test]
fn mobile_routing_decode_valid_type2_defaults_and_tcp_roundtrip() -> crafter::Result<()> {
    let payload = b"mobile-tcp";
    let hop_limit = 97;
    let mobile_routing_len = 8 + usize::from(IPV6_MOBILE_ROUTING_HEADER_EXT_LEN) * 8;
    let compiled = (base_ipv6(hop_limit)
        / Ipv6MobileRoutingHeader::new().home(doc_home())
        / Tcp::new()
            .sport(4242)
            .dport(443)
            .seq(0x1122_3344)
            .ack(0x5566_7788)
            .flags(TCP_FLAG_ACK)
            .window(2048)
        / Raw::from_bytes(payload))
    .compile()?;
    let bytes = compiled.as_bytes();
    let payload_length = (mobile_routing_len + 20 + payload.len()) as u16;

    assert_ipv6_wire_base_header(bytes, payload_length, IPPROTO_IPV6_ROUTE, hop_limit);
    assert_eq!(bytes[40], IPPROTO_TCP);
    assert_eq!(bytes[41], IPV6_MOBILE_ROUTING_HEADER_EXT_LEN);
    assert_eq!(bytes[42], IPV6_ROUTING_TYPE_MOBILE);
    assert_eq!(bytes[43], IPV6_MOBILE_ROUTING_SEGMENTS_LEFT);
    assert_eq!(&bytes[44..48], &IPV6_MOBILE_ROUTING_RESERVED.to_be_bytes());
    assert_eq!(&bytes[48..64], &doc_home().octets());

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();
    let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
    let mobile = decoded
        .layer::<Ipv6MobileRoutingHeader>()
        .expect("mobile routing header");
    let tcp = decoded.layer::<Tcp>().expect("tcp layer");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(
        layer_names,
        vec!["Ipv6", "Ipv6MobileRoutingHeader", "Tcp", "Raw"]
    );
    assert_decoded_ipv6_base_header(ipv6, payload_length, IPPROTO_IPV6_ROUTE, hop_limit);
    assert_eq!(mobile.next_header_value(), IPPROTO_TCP);
    assert_eq!(
        mobile.header_ext_len_value(),
        Some(IPV6_MOBILE_ROUTING_HEADER_EXT_LEN)
    );
    assert_eq!(
        mobile.effective_header_ext_len_value(),
        IPV6_MOBILE_ROUTING_HEADER_EXT_LEN
    );
    assert_eq!(mobile.routing_type_value(), IPV6_ROUTING_TYPE_MOBILE);
    assert_eq!(mobile.routing_type_label(), "Type 2 Mobile IPv6");
    assert_eq!(
        mobile.routing_type_status(),
        Ipv6RoutingTypeStatus::Assigned
    );
    assert_eq!(
        mobile.segments_left_value(),
        IPV6_MOBILE_ROUTING_SEGMENTS_LEFT
    );
    assert!(!mobile.segments_left_is_defaulted());
    assert_eq!(
        mobile.segments_left_status(),
        Ipv6MobileRoutingHeaderStatus::Valid
    );
    assert_eq!(mobile.reserved_value(), IPV6_MOBILE_ROUTING_RESERVED);
    assert_eq!(
        mobile.reserved_status(),
        Ipv6MobileRoutingHeaderStatus::Valid
    );
    assert_eq!(mobile.home_address_value(), doc_home());
    assert_eq!(
        mobile.validity_status(),
        Ipv6MobileRoutingHeaderStatus::Valid
    );
    assert_eq!(tcp.source_port_value(), 4242);
    assert_eq!(tcp.destination_port_value(), 443);
    assert_eq!(tcp.checksum_value(), Some(u16_field(&bytes[64..], 16)));
    assert_eq!(raw.as_bytes(), payload);
    assert_transport_checksum_uses_ipv6_context(ipv6, IPPROTO_TCP, &bytes[64..], 16, false);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn mobile_routing_decode_reserved_bytes_and_raw_payload_roundtrip() -> crafter::Result<()> {
    let reserved = 0xaabb_ccddu32;
    let payload = b"type2-raw";
    let hop_limit = 98;
    let mobile_routing_len = 8 + usize::from(IPV6_MOBILE_ROUTING_HEADER_EXT_LEN) * 8;
    let compiled = (base_ipv6(hop_limit)
        / Ipv6MobileRoutingHeader::new()
            .nh(IPPROTO_IPV6_EXPERIMENTAL_1)
            .reserved(reserved)
            .home(doc_midpoint())
        / Raw::from_bytes(payload))
    .compile()?;
    let bytes = compiled.as_bytes();
    let payload_length = (mobile_routing_len + payload.len()) as u16;

    assert_ipv6_wire_base_header(bytes, payload_length, IPPROTO_IPV6_ROUTE, hop_limit);
    assert_eq!(bytes[40], IPPROTO_IPV6_EXPERIMENTAL_1);
    assert_eq!(bytes[41], IPV6_MOBILE_ROUTING_HEADER_EXT_LEN);
    assert_eq!(bytes[42], IPV6_ROUTING_TYPE_MOBILE);
    assert_eq!(bytes[43], IPV6_MOBILE_ROUTING_SEGMENTS_LEFT);
    assert_eq!(&bytes[44..48], &reserved.to_be_bytes());
    assert_eq!(&bytes[48..64], &doc_midpoint().octets());
    assert_eq!(&bytes[64..], payload);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
    let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();
    let mobile = decoded
        .layer::<Ipv6MobileRoutingHeader>()
        .expect("mobile routing header");
    let raw = decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(layer_names, vec!["Ipv6", "Ipv6MobileRoutingHeader", "Raw"]);
    assert_eq!(mobile.next_header_value(), IPPROTO_IPV6_EXPERIMENTAL_1);
    assert_eq!(mobile.reserved_value(), reserved);
    assert!(!mobile.reserved_is_zero());
    assert_eq!(
        mobile.reserved_status(),
        Ipv6MobileRoutingHeaderStatus::NonzeroReserved
    );
    assert_eq!(
        mobile.validity_status(),
        Ipv6MobileRoutingHeaderStatus::NonzeroReserved
    );
    assert_eq!(mobile.home_address_value(), doc_midpoint());
    assert_eq!(raw.as_bytes(), payload);
    assert_eq!(decoded.compile()?.as_bytes(), bytes);

    Ok(())
}

#[test]
fn mobile_routing_decode_wrong_length_and_truncation_are_structured() -> crafter::Result<()> {
    let wrong_length = Ipv6MobileRoutingHeader::new()
        .header_ext_len(1)
        .home(doc_home());
    assert_eq!(
        wrong_length.header_ext_len_status(),
        Ipv6MobileRoutingHeaderStatus::InvalidHeaderExtLen
    );
    assert_eq!(
        wrong_length.validity_status(),
        Ipv6MobileRoutingHeaderStatus::InvalidHeaderExtLen
    );

    let compile_err = (base_ipv6(99) / wrong_length / Raw::new())
        .compile()
        .expect_err("too-small explicit Mobile IPv6 routing length must fail");
    assert_invalid_field_value_error(
        "mobile routing explicit length too small",
        compile_err,
        "ipv6.mobile.header_ext_len",
    );

    let wrong_length_wire = [
        IPPROTO_IPV6_NO_NEXT,
        1,
        IPV6_ROUTING_TYPE_MOBILE,
        IPV6_MOBILE_ROUTING_SEGMENTS_LEFT,
        0,
        0,
        0,
        0,
        0x20,
        0x01,
        0x0d,
        0xb8,
        0,
        0,
        0,
        0,
    ];
    let wrong_length_packet =
        (base_ipv6(100).nh(IPPROTO_IPV6_ROUTE) / Raw::from_bytes(&wrong_length_wire)).compile()?;
    let decode_err = Packet::decode_from_l3(NetworkLayer::Ipv6, wrong_length_packet.as_bytes())
        .expect_err("Type 2 routing header length 1 is source-backed invalid");
    assert_invalid_field_value_error(
        "mobile routing decoded length too small",
        decode_err,
        "ipv6.mobile.header_ext_len",
    );

    let mut truncated_wire = vec![
        IPPROTO_TCP,
        IPV6_MOBILE_ROUTING_HEADER_EXT_LEN,
        IPV6_ROUTING_TYPE_MOBILE,
        IPV6_MOBILE_ROUTING_SEGMENTS_LEFT,
        0,
        0,
        0,
        0,
    ];
    truncated_wire.extend_from_slice(&doc_home().octets()[..12]);
    let truncated_packet =
        (base_ipv6(101).nh(IPPROTO_IPV6_ROUTE) / Raw::from_bytes(&truncated_wire)).compile()?;
    let decode_err = Packet::decode_from_l3(NetworkLayer::Ipv6, truncated_packet.as_bytes())
        .expect_err("declared Type 2 routing header must require all 24 bytes");
    assert_buffer_too_short_error(
        "mobile routing truncated header",
        decode_err,
        "ipv6 routing header",
        8 + usize::from(IPV6_MOBILE_ROUTING_HEADER_EXT_LEN) * 8,
        truncated_wire.len(),
    );

    Ok(())
}

#[test]
fn generic_routing_type_data_lengths_pad_to_extension_header_boundary() -> crafter::Result<()> {
    let cases = [
        (vec![0x11], 0, vec![0x11, 0, 0, 0]),
        (
            vec![0x21, 0x22, 0x23, 0x24, 0x25],
            1,
            vec![0x21, 0x22, 0x23, 0x24, 0x25, 0, 0, 0, 0, 0, 0, 0],
        ),
    ];

    for (index, (type_data, expected_header_ext_len, expected_type_data)) in
        cases.into_iter().enumerate()
    {
        let hop_limit = 90 + index as u8;
        let expected_payload_len = 8 + u16::from(expected_header_ext_len) * 8;
        let compiled = (base_ipv6(hop_limit)
            / Ipv6RoutingHeader::new()
                .nh(IPPROTO_IPV6_NO_NEXT)
                .routing_type(253)
                .segments_left(0)
                .type_data(type_data.clone())
            / Raw::new())
        .compile()?;
        let bytes = compiled.as_bytes();

        assert_ipv6_wire_base_header(bytes, expected_payload_len, IPPROTO_IPV6_ROUTE, hop_limit);
        assert_eq!(bytes[40], IPPROTO_IPV6_NO_NEXT);
        assert_eq!(bytes[41], expected_header_ext_len);
        assert_eq!(bytes[42], 253);
        assert_eq!(bytes[43], 0);
        assert_eq!(&bytes[44..44 + type_data.len()], type_data.as_slice());
        assert!(
            bytes[44 + type_data.len()..40 + expected_payload_len as usize]
                .iter()
                .all(|byte| *byte == 0)
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
        let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();
        let routing = decoded.layer::<Ipv6RoutingHeader>().expect("routing layer");

        assert_eq!(layer_names, vec!["Ipv6", "Ipv6RoutingHeader"]);
        assert_eq!(
            routing.header_ext_len_value(),
            Some(expected_header_ext_len)
        );
        assert_eq!(routing.type_data_bytes(), expected_type_data.as_slice());
        assert_eq!(decoded.compile()?.as_bytes(), bytes);
    }

    Ok(())
}

#[test]
fn generic_routing_explicit_header_ext_len_decodes_trailing_type_data_and_roundtrips(
) -> crafter::Result<()> {
    let trailing_type_data = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];
    let mut bytes = (base_ipv6(92)
        / Ipv6RoutingHeader::new()
            .nh(IPPROTO_IPV6_NO_NEXT)
            .header_ext_len(2)
            .routing_type(254)
            .segments_left(3)
            .type_data(vec![0x90, 0x91, 0x92, 0x93])
        / Raw::new())
    .compile()?
    .into_bytes();

    assert_ipv6_wire_base_header(&bytes, 24, IPPROTO_IPV6_ROUTE, 92);
    assert_eq!(
        &bytes[40..48],
        &[IPPROTO_IPV6_NO_NEXT, 2, 254, 3, 0x90, 0x91, 0x92, 0x93]
    );

    bytes[48..64].copy_from_slice(&trailing_type_data);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, &bytes)?;
    let layer_names: Vec<_> = decoded.iter().map(|layer| layer.name()).collect();
    let routing = decoded.layer::<Ipv6RoutingHeader>().expect("routing layer");

    let mut expected_type_data = vec![0x90, 0x91, 0x92, 0x93];
    expected_type_data.extend_from_slice(&trailing_type_data);

    assert_eq!(layer_names, vec!["Ipv6", "Ipv6RoutingHeader"]);
    assert_eq!(routing.next_header_value(), IPPROTO_IPV6_NO_NEXT);
    assert_eq!(routing.header_ext_len_value(), Some(2));
    assert_eq!(routing.routing_type_value(), 254);
    assert_eq!(routing.segments_left_value(), 3);
    assert_eq!(routing.type_data_bytes(), expected_type_data.as_slice());
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());

    Ok(())
}

#[test]
fn generic_routing_explicit_header_ext_len_rejects_type_data_that_does_not_fit() {
    let err = (base_ipv6(93)
        / Ipv6RoutingHeader::new()
            .nh(IPPROTO_IPV6_NO_NEXT)
            .header_ext_len(0)
            .routing_type(253)
            .segments_left(0)
            .type_data(vec![0, 1, 2, 3, 4])
        / Raw::new())
    .compile()
    .expect_err("type-specific data longer than the explicit routing header must fail");

    assert_invalid_field_value_error(
        "generic routing explicit length too short",
        err,
        "ipv6.routing.type_data",
    );
}

#[test]
fn registry_options_builtin_and_custom_decode_after_option_headers() -> crafter::Result<()> {
    let mut registry = ProtocolRegistry::new();
    let custom_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let custom_calls_for_binding = std::sync::Arc::clone(&custom_calls);
    registry.bind_ipv6_next_header(IPPROTO_IPV6_EXPERIMENTAL_1, move |packet, payload| {
        assert_eq!(payload, b"registry-custom");
        custom_calls_for_binding.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(packet.push(Raw::from_bytes(payload)))
    });

    let builtin_compiled = (base_ipv6(88)
        / Ipv6HopByHopOptionsHeader::new().option(Ipv6Option::pad1())
        / Ipv6DestinationOptionsHeader::new().option(Ipv6Option::generic(0x1e, [0xaa])?)
        / Udp::new().sport(4900).dport(4901)
        / Raw::from("registry-builtin"))
    .compile()?;
    let builtin_bytes = builtin_compiled.as_bytes();

    assert_ipv6_wire_base_header(builtin_bytes, 40, IPPROTO_IPV6_HOPOPTS, 88);
    assert_eq!(builtin_bytes[40], IPPROTO_IPV6_DSTOPTS);
    assert_eq!(builtin_bytes[48], IPPROTO_UDP);

    let builtin_decoded = registry.decode_ipv6(builtin_bytes)?;
    let builtin_layer_names: Vec<_> = builtin_decoded.iter().map(|layer| layer.name()).collect();
    let builtin_hop_by_hop = builtin_decoded
        .layer::<Ipv6HopByHopOptionsHeader>()
        .expect("hop-by-hop layer");
    let builtin_destination = builtin_decoded
        .layer::<Ipv6DestinationOptionsHeader>()
        .expect("destination options layer");
    let builtin_udp = builtin_decoded.layer::<Udp>().expect("udp layer");
    let builtin_raw = builtin_decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(
        builtin_layer_names,
        vec![
            "Ipv6",
            "Ipv6HopByHopOptionsHeader",
            "Ipv6DestinationOptionsHeader",
            "Udp",
            "Raw",
        ]
    );
    assert_eq!(builtin_hop_by_hop.next_header_value(), IPPROTO_IPV6_DSTOPTS);
    assert_eq!(builtin_destination.next_header_value(), IPPROTO_UDP);
    assert_eq!(builtin_udp.source_port_value(), 4900);
    assert_eq!(builtin_udp.destination_port_value(), 4901);
    assert_eq!(builtin_raw.as_bytes(), b"registry-builtin");
    assert_eq!(builtin_decoded.compile()?.as_bytes(), builtin_bytes);
    assert_eq!(custom_calls.load(std::sync::atomic::Ordering::SeqCst), 0);

    let custom_compiled = (base_ipv6(89)
        / Ipv6HopByHopOptionsHeader::new().option(Ipv6Option::pad1())
        / Ipv6DestinationOptionsHeader::new()
            .nh(IPPROTO_IPV6_EXPERIMENTAL_1)
            .option(Ipv6Option::generic(0x3e, [0xbb, 0xcc])?)
        / Raw::from("registry-custom"))
    .compile()?;
    let custom_bytes = custom_compiled.as_bytes();

    assert_ipv6_wire_base_header(custom_bytes, 31, IPPROTO_IPV6_HOPOPTS, 89);
    assert_eq!(custom_bytes[40], IPPROTO_IPV6_DSTOPTS);
    assert_eq!(custom_bytes[48], IPPROTO_IPV6_EXPERIMENTAL_1);

    let custom_decoded = registry.decode_ipv6(custom_bytes)?;
    let custom_layer_names: Vec<_> = custom_decoded.iter().map(|layer| layer.name()).collect();
    let custom_hop_by_hop = custom_decoded
        .layer::<Ipv6HopByHopOptionsHeader>()
        .expect("hop-by-hop layer");
    let custom_destination = custom_decoded
        .layer::<Ipv6DestinationOptionsHeader>()
        .expect("destination options layer");
    let custom_raw = custom_decoded.layer::<Raw>().expect("raw payload");

    assert_eq!(
        custom_layer_names,
        vec![
            "Ipv6",
            "Ipv6HopByHopOptionsHeader",
            "Ipv6DestinationOptionsHeader",
            "Raw",
        ]
    );
    assert_eq!(custom_hop_by_hop.next_header_value(), IPPROTO_IPV6_DSTOPTS);
    assert_eq!(
        custom_destination.next_header_value(),
        IPPROTO_IPV6_EXPERIMENTAL_1
    );
    assert_eq!(custom_raw.as_bytes(), b"registry-custom");
    assert_eq!(custom_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(custom_decoded.compile()?.as_bytes(), custom_bytes);

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

#[test]
fn malformed_options_report_structured_errors_for_hop_by_hop_and_destination() -> crafter::Result<()>
{
    assert_buffer_too_short_error(
        "direct truncated PadN option header",
        Ipv6Option::decode_all(&[IPV6_OPTION_PADN]).unwrap_err(),
        "ipv6.option.header",
        2,
        1,
    );
    assert_buffer_too_short_error(
        "direct PadN option data overrun",
        Ipv6Option::decode_all(&[IPV6_OPTION_PADN, 5, 0, 0, 0]).unwrap_err(),
        "ipv6.option.data",
        7,
        5,
    );
    assert_invalid_field_value_error(
        "explicit PadN total length underflow",
        Ipv6Option::padn(1).unwrap_err(),
        "ipv6.option.padn.length",
    );
    assert_invalid_field_value_error(
        "oversized PadN option data",
        Ipv6Option::padn_data(vec![0; 256]).unwrap_err(),
        "ipv6.option.padn.length",
    );
    assert_invalid_field_value_error(
        "oversized generic option data",
        Ipv6Option::generic(0x1e, vec![0; 256]).unwrap_err(),
        "ipv6.option.length",
    );

    for kind in Ipv6OptionHeaderKind::ALL {
        let truncated_header =
            raw_option_header_packet_bytes(kind, [IPPROTO_UDP, 0, IPV6_OPTION_PAD1])?;
        assert_buffer_too_short_error(
            "truncated option-bearing extension header",
            Packet::decode_from_l3(NetworkLayer::Ipv6, &truncated_header).unwrap_err(),
            kind.decode_context(),
            8,
            3,
        );

        let option_overrun = raw_option_header_packet_bytes(
            kind,
            [IPPROTO_UDP, 0, 0x22, 7, 0xaa, 0xbb, 0xcc, 0xdd],
        )?;
        assert_buffer_too_short_error(
            "option length past option header end",
            Packet::decode_from_l3(NetworkLayer::Ipv6, &option_overrun).unwrap_err(),
            "ipv6.option.data",
            9,
            6,
        );

        let padn_overrun = raw_option_header_packet_bytes(
            kind,
            [IPPROTO_UDP, 0, IPV6_OPTION_PADN, 5, 0, 0, 0, 0],
        )?;
        assert_buffer_too_short_error(
            "PadN length past option header end",
            Packet::decode_from_l3(NetworkLayer::Ipv6, &padn_overrun).unwrap_err(),
            "ipv6.option.data",
            7,
            6,
        );

        let declared_too_large =
            raw_option_header_packet_bytes(kind, [IPPROTO_UDP, u8::MAX, 0, 0, 0, 0, 0, 0])?;
        assert_buffer_too_short_error(
            "declared option header length exceeds available payload",
            Packet::decode_from_l3(NetworkLayer::Ipv6, &declared_too_large).unwrap_err(),
            kind.decode_context(),
            2048,
            8,
        );

        let explicit_too_small = option_header_packet(
            kind,
            vec![Ipv6Option::generic(0x1e, [0, 1, 2, 3, 4])?],
            Some(0),
            Some(IPPROTO_IPV6_NO_NEXT),
            false,
        );
        assert_invalid_field_value_error(
            "explicit option header length too small for options",
            explicit_too_small.compile().unwrap_err(),
            kind.options_error_field(),
        );

        let oversized_option = Ipv6Option::generic(0x1e, vec![0; 255])?;
        let oversized_collection = option_header_packet(
            kind,
            vec![oversized_option; 8],
            None,
            Some(IPPROTO_IPV6_NO_NEXT),
            false,
        );
        assert_invalid_field_value_error(
            "option collection exceeds 8-bit extension length field",
            oversized_collection.compile().unwrap_err(),
            kind.header_ext_len_field(),
        );
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
fn unknown_options_hop_by_hop_and_destination_preserve_bytes_and_metadata() -> crafter::Result<()> {
    #[derive(Clone, Copy)]
    struct UnknownOptionCase {
        option_type: u8,
        data: &'static [u8],
        action_bits: u8,
        action: Ipv6OptionAction,
        change_en_route: bool,
        rest: u8,
        summary: &'static str,
    }

    // RFC 8200 Section 4.2 defines the option type high two bits as the
    // unknown-option action, the next bit as the change-en-route bit, and the
    // low five bits as the option-number space named "rest" by IANA.
    let cases = [
        UnknownOptionCase {
            option_type: 0x13,
            data: &[0xde, 0xad],
            action_bits: 0,
            action: Ipv6OptionAction::Skip,
            change_en_route: false,
            rest: 0x13,
            summary: "Generic(kind=0x13,len=2,act=0,chg=0,rest=0x13,data=de ad)",
        },
        UnknownOptionCase {
            option_type: 0x73,
            data: &[0xbe, 0xef, 0x01],
            action_bits: 1,
            action: Ipv6OptionAction::Discard,
            change_en_route: true,
            rest: 0x13,
            summary: "Generic(kind=0x73,len=3,act=1,chg=1,rest=0x13,data=be ef 01)",
        },
        UnknownOptionCase {
            option_type: 0x9e,
            data: &[],
            action_bits: 2,
            action: Ipv6OptionAction::DiscardSendIcmp,
            change_en_route: false,
            rest: 0x1e,
            summary: "Generic(kind=0x9e,len=0,act=2,chg=0,rest=0x1e,data=empty)",
        },
        UnknownOptionCase {
            option_type: 0xfe,
            data: &[0xca, 0xfe, 0x80],
            action_bits: 3,
            action: Ipv6OptionAction::DiscardSendIcmpIfNotMulticast,
            change_en_route: true,
            rest: 0x1e,
            summary: "Generic(kind=0xfe,len=3,act=3,chg=1,rest=0x1e,data=ca fe 80)",
        },
    ];

    let mut raw_options = Vec::new();
    let mut options = Vec::new();
    for case in cases {
        let option = Ipv6Option::unknown(case.option_type, case.data.to_vec())?;
        raw_options.extend_from_slice(&option.encode()?);
        options.push(option);
    }

    for kind in Ipv6OptionHeaderKind::ALL {
        let compiled = option_header_packet(
            kind,
            options.clone(),
            None,
            Some(IPPROTO_IPV6_NO_NEXT),
            false,
        )
        .compile()?;
        let bytes = compiled.as_bytes();

        assert_ipv6_wire_base_header(bytes, 24, kind.outer_next_header(), 71);
        assert_eq!(bytes[40], IPPROTO_IPV6_NO_NEXT);
        assert_eq!(bytes[41], 2);
        assert_eq!(&bytes[42..58], raw_options.as_slice());
        assert_eq!(&bytes[58..64], &[0, 0, 0, 0, 0, 0]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;
        let decoded_options = match kind {
            Ipv6OptionHeaderKind::HopByHop => decoded
                .layer::<Ipv6HopByHopOptionsHeader>()
                .expect("hop-by-hop options header")
                .options_value(),
            Ipv6OptionHeaderKind::Destination => decoded
                .layer::<Ipv6DestinationOptionsHeader>()
                .expect("destination options header")
                .options_value(),
        };

        let mut expected_options = options.clone();
        expected_options.extend(std::iter::repeat_with(Ipv6Option::pad1).take(6));
        assert_eq!(decoded_options, expected_options.as_slice());

        for (option, case) in decoded_options.iter().zip(cases) {
            assert_eq!(option.option_type(), case.option_type);
            assert_eq!(option.kind(), case.option_type);
            assert_eq!(option.data(), case.data);
            assert_eq!(option.action_bits(), case.action_bits);
            assert_eq!(option.action(), case.action);
            assert_eq!(option.change_en_route(), case.change_en_route);
            assert_eq!(option.may_change_en_route(), case.change_en_route);
            assert_eq!(option.rest(), case.rest);
            assert_eq!(option.option_number(), case.rest);
            assert_eq!(
                option.encode()?,
                Ipv6Option::unknown(case.option_type, case.data)?.encode()?
            );
        }

        let summary = decoded.summary();
        let show = decoded.show();
        for case in cases {
            assert!(summary.contains(case.summary), "{summary}");
            assert!(show.contains(case.summary), "{show}");
        }
        assert_eq!(decoded.compile()?.as_bytes(), bytes);
    }

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
