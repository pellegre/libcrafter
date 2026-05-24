#[macro_use]
mod support;

use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::core::{
    decode_dns_name, Arp, CrafterError, Dhcp, DhcpOption, Dns, Ethernet, Icmp, Icmpv6, IpProtocol,
    Ipv4, Ipv4Option, Ipv6, LinkType, LinuxSll, MacAddr, NetworkLayer, NullLoopback, Packet, Raw,
    Tcp, TcpOption, Udp, Vlan, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, DNS_PORT, TCP_FLAG_ACK,
    TCP_FLAG_PSH, TCP_FLAG_SYN,
};
use proptest::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DecodeTarget {
    Ethernet,
    LinuxSll,
    NullLoopback,
    Ipv4,
    Ipv6,
    Ipv4Options,
    TcpOptions,
    Dhcp,
    DhcpOptions,
    DnsName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedErrorKind {
    BufferTooShort,
    InvalidFieldValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExpectedError {
    kind: ExpectedErrorKind,
    context_or_field: &'static str,
}

#[derive(Debug)]
struct MalformedCase {
    name: &'static str,
    target: DecodeTarget,
    expected_error: ExpectedError,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
enum PacketDecodeTarget {
    Link(LinkType),
    L3(NetworkLayer),
}

fn decode_packet(target: PacketDecodeTarget, bytes: &[u8]) -> crafter::core::Result<Packet> {
    match target {
        PacketDecodeTarget::Link(link_type) => Packet::decode_from_link(link_type, bytes),
        PacketDecodeTarget::L3(network_layer) => Packet::decode_from_l3(network_layer, bytes),
    }
}

fn exercise_packet_decode(target: PacketDecodeTarget, bytes: &[u8]) {
    if let Ok(packet) = decode_packet(target, bytes) {
        let _ = packet.summary();
        let _ = packet.show();
        let _ = packet.compile();
    }
}

fn decode_malformed_case(case: &MalformedCase) -> crafter::core::Result<()> {
    match case.target {
        DecodeTarget::Ethernet => {
            decode_packet(PacketDecodeTarget::Link(LinkType::Ethernet), &case.bytes).map(drop)
        }
        DecodeTarget::LinuxSll => {
            decode_packet(PacketDecodeTarget::Link(LinkType::LinuxSll), &case.bytes).map(drop)
        }
        DecodeTarget::NullLoopback => decode_packet(
            PacketDecodeTarget::Link(LinkType::NullLoopback),
            &case.bytes,
        )
        .map(drop),
        DecodeTarget::Ipv4 => {
            decode_packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4), &case.bytes).map(drop)
        }
        DecodeTarget::Ipv6 => {
            decode_packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6), &case.bytes).map(drop)
        }
        DecodeTarget::Ipv4Options => Ipv4Option::decode_all(&case.bytes).map(drop),
        DecodeTarget::TcpOptions => TcpOption::decode_all(&case.bytes).map(drop),
        DecodeTarget::Dhcp => Dhcp::decode(&case.bytes).map(drop),
        DecodeTarget::DhcpOptions => DhcpOption::decode_all(&case.bytes).map(drop),
        DecodeTarget::DnsName => decode_dns_name(&case.bytes, 0).map(drop),
    }
}

fn malformed_cases() -> Vec<MalformedCase> {
    fixture_str!("malformed/core-decode-corpus.hex")
        .lines()
        .enumerate()
        .filter_map(|(line_index, line)| {
            let line_number = line_index + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }

            let mut parts = line.split('|').map(str::trim);
            let name = parts.next().unwrap_or_else(|| {
                panic!("malformed corpus line {line_number} is missing a case name")
            });
            let target = parts.next().unwrap_or_else(|| {
                panic!("malformed corpus case {name} is missing a decode target")
            });
            let expected_kind = parts.next().unwrap_or_else(|| {
                panic!("malformed corpus case {name} is missing an expected error kind")
            });
            let expected_context_or_field = parts.next().unwrap_or_else(|| {
                panic!("malformed corpus case {name} is missing an expected error context or field")
            });
            let hex = parts
                .next()
                .unwrap_or_else(|| panic!("malformed corpus case {name} is missing hex bytes"));
            assert!(
                parts.next().is_none(),
                "malformed corpus case {name} has too many fields"
            );
            assert!(
                !name.is_empty(),
                "malformed corpus line {line_number} has an empty case name"
            );
            assert!(
                !expected_context_or_field.is_empty(),
                "malformed corpus case {name} has an empty expected context or field"
            );

            Some(MalformedCase {
                name,
                target: parse_target(name, target),
                expected_error: ExpectedError {
                    kind: parse_expected_error_kind(name, expected_kind),
                    context_or_field: expected_context_or_field,
                },
                bytes: parse_hex(name, hex),
            })
        })
        .collect()
}

fn parse_target(name: &str, target: &str) -> DecodeTarget {
    match target {
        "ethernet" => DecodeTarget::Ethernet,
        "linux-sll" => DecodeTarget::LinuxSll,
        "null-loopback" => DecodeTarget::NullLoopback,
        "ipv4" => DecodeTarget::Ipv4,
        "ipv6" => DecodeTarget::Ipv6,
        "ipv4-options" => DecodeTarget::Ipv4Options,
        "tcp-options" => DecodeTarget::TcpOptions,
        "dhcp" => DecodeTarget::Dhcp,
        "dhcp-options" => DecodeTarget::DhcpOptions,
        "dns-name" => DecodeTarget::DnsName,
        _ => panic!("malformed corpus case {name} has unknown target {target}"),
    }
}

fn parse_expected_error_kind(name: &str, expected_kind: &str) -> ExpectedErrorKind {
    match expected_kind {
        "buffer-too-short" => ExpectedErrorKind::BufferTooShort,
        "invalid-field-value" => ExpectedErrorKind::InvalidFieldValue,
        _ => panic!("malformed corpus case {name} has unknown expected kind {expected_kind}"),
    }
}

fn parse_hex(name: &str, hex: &str) -> Vec<u8> {
    let hex = hex
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    assert!(
        hex.len() % 2 == 0,
        "malformed corpus case {name} has an odd hex length"
    );

    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = std::str::from_utf8(chunk)
                .unwrap_or_else(|_| panic!("malformed corpus case {name} contains non-UTF8 hex"));
            u8::from_str_radix(byte, 16)
                .unwrap_or_else(|_| panic!("malformed corpus case {name} has invalid hex {byte}"))
        })
        .collect()
}

fn assert_error_matches(case: &MalformedCase, error: CrafterError) {
    match (case.expected_error.kind, error) {
        (ExpectedErrorKind::BufferTooShort, CrafterError::BufferTooShort { context, .. }) => {
            assert_eq!(
                context, case.expected_error.context_or_field,
                "malformed corpus case {} returned an unexpected buffer context",
                case.name
            )
        }
        (ExpectedErrorKind::InvalidFieldValue, CrafterError::InvalidFieldValue { field, .. }) => {
            assert_eq!(
                field, case.expected_error.context_or_field,
                "malformed corpus case {} returned an unexpected invalid field",
                case.name
            )
        }
        (expected, actual) => panic!(
            "malformed corpus case {} expected {expected:?}, got {actual:?}",
            case.name
        ),
    }
}

fn required_malformed_families() -> &'static [&'static str] {
    &[
        "short ethernet",
        "truncated vlan",
        "short arp",
        "short linux sll",
        "short null loopback",
        "short ipv4",
        "bad ipv4 version",
        "bad ipv4 ihl",
        "short ipv4 total length",
        "ipv4 option overrun",
        "short ipv6 base",
        "bad ipv6 version",
        "ipv6 payload length mismatch",
        "truncated ipv6 routing header",
        "truncated ipv6 fragment header",
        "malformed ipv6 segment routing header",
        "short udp header",
        "invalid udp length",
        "short tcp header",
        "tcp data offset underflow",
        "tcp data offset overrun",
        "tcp option overrun",
        "invalid tcp fixed option length",
        "short icmp header",
        "short icmpv6 header",
        "short dns message",
        "truncated dns question",
        "dns pointer cycle",
        "dns pointer out of range",
        "dns label length overrun",
        "short dhcp packet",
        "missing dhcp magic cookie",
        "truncated dhcp option",
        "invalid dhcp fixed option length",
        "invalid dhcp text option",
    ]
}

fn malformed_family(name: &str) -> Option<&'static str> {
    match name {
        "short-ethernet" => Some("short ethernet"),
        "truncated-vlan-header" => Some("truncated vlan"),
        "short-arp-header" | "truncated-arp-addresses" => Some("short arp"),
        "short-linux-sll" => Some("short linux sll"),
        "short-null-loopback" => Some("short null loopback"),
        "short-ipv4-header" => Some("short ipv4"),
        "bad-ipv4-version" => Some("bad ipv4 version"),
        "bad-ipv4-ihl" => Some("bad ipv4 ihl"),
        "ipv4-total-length-shorter-than-header" => Some("short ipv4 total length"),
        "ipv4-option-length-overrun" | "ipv4-option-decoder-overrun" => Some("ipv4 option overrun"),
        "short-ipv6-base-header" => Some("short ipv6 base"),
        "bad-ipv6-version" => Some("bad ipv6 version"),
        "ipv6-payload-length-mismatch" => Some("ipv6 payload length mismatch"),
        "truncated-ipv6-routing-header" => Some("truncated ipv6 routing header"),
        "truncated-ipv6-fragment-header" => Some("truncated ipv6 fragment header"),
        "malformed-ipv6-segment-routing-header" => Some("malformed ipv6 segment routing header"),
        "udp-short-header" => Some("short udp header"),
        "udp-invalid-length" => Some("invalid udp length"),
        "tcp-short-header" => Some("short tcp header"),
        "tcp-data-offset-underflow" => Some("tcp data offset underflow"),
        "tcp-data-offset-overrun" => Some("tcp data offset overrun"),
        "tcp-option-length-overrun" => Some("tcp option overrun"),
        "tcp-option-invalid-fixed-length" => Some("invalid tcp fixed option length"),
        "icmp-short-header" => Some("short icmp header"),
        "icmpv6-short-header" => Some("short icmpv6 header"),
        "dns-short-message" => Some("short dns message"),
        "dns-truncated-question" => Some("truncated dns question"),
        "dns-compression-loop" | "dns-name-pointer-cycle" => Some("dns pointer cycle"),
        "dns-pointer-out-of-range" => Some("dns pointer out of range"),
        "dns-label-length-overrun" => Some("dns label length overrun"),
        "dhcp-short-fixed-header" => Some("short dhcp packet"),
        "dhcp-missing-magic-cookie" => Some("missing dhcp magic cookie"),
        "dhcp-truncated-option" => Some("truncated dhcp option"),
        "dhcp-invalid-fixed-option-length" => Some("invalid dhcp fixed option length"),
        "dhcp-invalid-utf8-text-option" => Some("invalid dhcp text option"),
        _ => None,
    }
}

fn assert_roundtrip(target: PacketDecodeTarget, packet: Packet) {
    let bytes = packet.compile().expect("generated packet should compile");
    let decoded = decode_packet(target, bytes.as_bytes()).expect("generated packet should decode");
    let compiled = decoded
        .compile()
        .expect("decoded generated packet should compile");
    assert_eq!(
        compiled.as_bytes(),
        bytes.as_bytes(),
        "decoded packet changed stable bytes"
    );
}

fn safe_udp_port(seed: u16) -> u16 {
    10_000 + (seed % 50_000)
}

#[test]
fn malformed_corpus_decoder_paths_do_not_panic() {
    let cases = malformed_cases();
    assert!(!cases.is_empty(), "malformed corpus must not be empty");

    for expected in [
        DecodeTarget::Ethernet,
        DecodeTarget::LinuxSll,
        DecodeTarget::NullLoopback,
        DecodeTarget::Ipv4,
        DecodeTarget::Ipv6,
        DecodeTarget::Ipv4Options,
        DecodeTarget::TcpOptions,
        DecodeTarget::Dhcp,
        DecodeTarget::DhcpOptions,
        DecodeTarget::DnsName,
    ] {
        assert!(
            cases.iter().any(|case| case.target == expected),
            "malformed corpus missing {expected:?} coverage"
        );
    }

    let covered = cases
        .iter()
        .filter_map(|case| malformed_family(case.name))
        .collect::<std::collections::HashSet<_>>();
    for expected_name in required_malformed_families() {
        assert!(
            covered.contains(expected_name),
            "malformed corpus missing named coverage for {expected_name}"
        );
    }

    for case in &cases {
        assert!(
            !case.name.is_empty(),
            "malformed corpus case name must be stable"
        );
        let _ = decode_malformed_case(case);
    }
}

#[test]
fn malformed_corpus_reports_structured_errors() {
    let cases = malformed_cases();
    assert!(!cases.is_empty(), "malformed corpus must not be empty");

    for expected in [
        DecodeTarget::Ethernet,
        DecodeTarget::LinuxSll,
        DecodeTarget::NullLoopback,
        DecodeTarget::Ipv4,
        DecodeTarget::Ipv6,
        DecodeTarget::Ipv4Options,
        DecodeTarget::TcpOptions,
        DecodeTarget::Dhcp,
        DecodeTarget::DhcpOptions,
        DecodeTarget::DnsName,
    ] {
        assert!(
            cases.iter().any(|case| case.target == expected),
            "malformed corpus missing {expected:?} coverage"
        );
    }

    let covered = cases
        .iter()
        .filter_map(|case| malformed_family(case.name))
        .collect::<std::collections::HashSet<_>>();
    for required in required_malformed_families() {
        assert!(
            covered.contains(required),
            "malformed corpus missing required coverage for {required}"
        );
    }

    for case in &cases {
        let Err(error) = decode_malformed_case(case) else {
            panic!("malformed corpus case {} unexpectedly decoded", case.name);
        };
        assert_error_matches(case, error);
    }
}

#[test]
fn roundtrip_curated_protocol_families_compile_decode_compile() {
    let client_mac = MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]);
    let server_mac = MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x02]);

    let cases = [
        (
            PacketDecodeTarget::Link(LinkType::Ethernet),
            Ethernet::with_addresses(client_mac, server_mac).ethertype(0x88b5) / Raw::from("raw"),
        ),
        (
            PacketDecodeTarget::Link(LinkType::Ethernet),
            Ethernet::new()
                / Arp::who_has(
                    Ipv4Addr::new(192, 0, 2, 10),
                    Ipv4Addr::new(192, 0, 2, 1),
                    client_mac,
                ),
        ),
        (
            PacketDecodeTarget::Link(LinkType::Ethernet),
            Ethernet::with_addresses(client_mac, server_mac)
                / Vlan::new().vlan_id(42)
                / Ipv4::with_addresses(Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(192, 0, 2, 1))
                / Udp::new().source_port(12_345).destination_port(23_456)
                / Raw::from("vlan-udp"),
        ),
        (
            PacketDecodeTarget::Link(LinkType::LinuxSll),
            LinuxSll::new().source_address(client_mac)
                / Arp::is_at(
                    Ipv4Addr::new(192, 0, 2, 1),
                    client_mac,
                    Ipv4Addr::new(192, 0, 2, 10),
                    server_mac,
                ),
        ),
        (
            PacketDecodeTarget::Link(LinkType::NullLoopback),
            NullLoopback::ipv4()
                / Ipv4::with_addresses(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST)
                / Icmp::echo_request().identifier(7).sequence_number(9)
                / Raw::from("null-icmp"),
        ),
        (
            PacketDecodeTarget::L3(NetworkLayer::Ipv4),
            Ipv4::with_addresses(Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(192, 0, 2, 53))
                / Udp::new().source_port(44_444).destination_port(DNS_PORT)
                / Dns::a_query("example.com").id(0x1234),
        ),
        (
            PacketDecodeTarget::L3(NetworkLayer::Ipv4),
            Ipv4::with_addresses(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST)
                / Udp::new()
                    .source_port(DHCP_CLIENT_PORT)
                    .destination_port(DHCP_SERVER_PORT)
                / Dhcp::discover(client_mac).transaction_id(0x0102_0304),
        ),
        (
            PacketDecodeTarget::L3(NetworkLayer::Ipv6),
            Ipv6::with_addresses(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST)
                / Icmpv6::echo_request().identifier(11).sequence_number(13)
                / Raw::from("icmpv6"),
        ),
    ];

    for (target, packet) in cases {
        assert_roundtrip(target, packet);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn malformed_random_decode_inputs_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        exercise_packet_decode(PacketDecodeTarget::Link(LinkType::Ethernet), &bytes);
        exercise_packet_decode(PacketDecodeTarget::Link(LinkType::LinuxSll), &bytes);
        exercise_packet_decode(PacketDecodeTarget::Link(LinkType::NullLoopback), &bytes);
        exercise_packet_decode(PacketDecodeTarget::L3(NetworkLayer::Ipv4), &bytes);
        exercise_packet_decode(PacketDecodeTarget::L3(NetworkLayer::Ipv6), &bytes);

        let _ = Ipv4Option::decode_all(&bytes);
        let _ = TcpOption::decode_all(&bytes);
        let _ = DhcpOption::decode_all(&bytes);
        let _ = Dhcp::decode(&bytes);
        if !bytes.is_empty() {
            let _ = decode_dns_name(&bytes, 0);
        }
    }

    #[test]
    fn roundtrip_raw_payload_property(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let decoded = Packet::decode_raw(&bytes).expect("raw decode should not fail");
        let compiled = decoded.compile().expect("raw packet should compile");
        prop_assert_eq!(compiled.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn roundtrip_ipv4_udp_property(
        src in any::<[u8; 4]>(),
        dst in any::<[u8; 4]>(),
        sport in any::<u16>(),
        dport in any::<u16>(),
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let packet = Ipv4::with_addresses(Ipv4Addr::from(src), Ipv4Addr::from(dst))
            / Udp::new()
                .source_port(safe_udp_port(sport))
                .destination_port(safe_udp_port(dport))
            / Raw::from(payload);

        let bytes = packet.compile().expect("generated IPv4/UDP packet should compile");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
            .expect("generated IPv4/UDP packet should decode");
        let compiled = decoded.compile().expect("decoded IPv4/UDP packet should compile");
        prop_assert_eq!(compiled.as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn roundtrip_ethernet_ipv4_tcp_property(
        src_mac in any::<[u8; 6]>(),
        dst_mac in any::<[u8; 6]>(),
        src_ip in any::<[u8; 4]>(),
        dst_ip in any::<[u8; 4]>(),
        sport in any::<u16>(),
        dport in any::<u16>(),
        seq in any::<u32>(),
        ack in any::<u32>(),
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let packet = Ethernet::with_addresses(MacAddr::new(src_mac), MacAddr::new(dst_mac))
            / Ipv4::with_addresses(Ipv4Addr::from(src_ip), Ipv4Addr::from(dst_ip))
                .proto(IpProtocol::Tcp)
            / Tcp::new()
                .source_port(safe_udp_port(sport))
                .destination_port(safe_udp_port(dport))
                .sequence_number(seq)
                .acknowledgment_number(ack)
                .flags(TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_PSH)
            / Raw::from(payload);

        let bytes = packet.compile().expect("generated Ethernet/IPv4/TCP packet should compile");
        let decoded = Packet::decode_from_link(LinkType::Ethernet, bytes.as_bytes())
            .expect("generated Ethernet/IPv4/TCP packet should decode");
        let compiled = decoded.compile().expect("decoded Ethernet/IPv4/TCP packet should compile");
        prop_assert_eq!(compiled.as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn roundtrip_ipv6_icmpv6_property(
        src in any::<[u8; 16]>(),
        dst in any::<[u8; 16]>(),
        identifier in any::<u16>(),
        sequence in any::<u16>(),
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let packet = Ipv6::with_addresses(Ipv6Addr::from(src), Ipv6Addr::from(dst))
            / Icmpv6::echo_request()
                .identifier(identifier)
                .sequence_number(sequence)
            / Raw::from(payload);

        let bytes = packet.compile().expect("generated IPv6/ICMPv6 packet should compile");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())
            .expect("generated IPv6/ICMPv6 packet should decode");
        let compiled = decoded.compile().expect("decoded IPv6/ICMPv6 packet should compile");
        prop_assert_eq!(compiled.as_bytes(), bytes.as_bytes());
    }
}
