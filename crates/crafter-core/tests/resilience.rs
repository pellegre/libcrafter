use std::net::{Ipv4Addr, Ipv6Addr};

use crafter_core::{
    decode_dns_name, Arp, Dhcp, DhcpOption, Dns, Ethernet, Icmp, Icmpv6, IpProtocol, Ipv4,
    Ipv4Option, Ipv6, LinkType, LinuxSll, MacAddr, NetworkLayer, NullLoopback, Packet, Raw, Tcp,
    TcpOption, Udp, Vlan, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, DNS_PORT, TCP_FLAG_ACK, TCP_FLAG_PSH,
    TCP_FLAG_SYN,
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

#[derive(Debug)]
struct MalformedCase {
    name: &'static str,
    target: DecodeTarget,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
enum PacketDecodeTarget {
    Link(LinkType),
    L3(NetworkLayer),
}

fn decode_packet(target: PacketDecodeTarget, bytes: &[u8]) -> crafter_core::Result<Packet> {
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

fn decode_malformed_case(case: &MalformedCase) {
    match case.target {
        DecodeTarget::Ethernet => {
            exercise_packet_decode(PacketDecodeTarget::Link(LinkType::Ethernet), &case.bytes)
        }
        DecodeTarget::LinuxSll => {
            exercise_packet_decode(PacketDecodeTarget::Link(LinkType::LinuxSll), &case.bytes)
        }
        DecodeTarget::NullLoopback => exercise_packet_decode(
            PacketDecodeTarget::Link(LinkType::NullLoopback),
            &case.bytes,
        ),
        DecodeTarget::Ipv4 => {
            exercise_packet_decode(PacketDecodeTarget::L3(NetworkLayer::Ipv4), &case.bytes)
        }
        DecodeTarget::Ipv6 => {
            exercise_packet_decode(PacketDecodeTarget::L3(NetworkLayer::Ipv6), &case.bytes)
        }
        DecodeTarget::Ipv4Options => {
            let _ = Ipv4Option::decode_all(&case.bytes);
        }
        DecodeTarget::TcpOptions => {
            let _ = TcpOption::decode_all(&case.bytes);
        }
        DecodeTarget::Dhcp => {
            let _ = Dhcp::decode(&case.bytes);
        }
        DecodeTarget::DhcpOptions => {
            let _ = DhcpOption::decode_all(&case.bytes);
        }
        DecodeTarget::DnsName => {
            let _ = decode_dns_name(&case.bytes, 0);
        }
    }
}

fn malformed_cases() -> Vec<MalformedCase> {
    include_str!("../../../tests/fixtures/malformed/core-decode-corpus.hex")
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }

            let mut parts = line.split('|');
            let name = parts.next().expect("malformed corpus case name");
            let target = parts.next().expect("malformed corpus target");
            let hex = parts.next().expect("malformed corpus hex bytes");
            assert!(
                parts.next().is_none(),
                "malformed corpus case {name} has too many fields"
            );

            Some(MalformedCase {
                name,
                target: parse_target(name, target),
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

    for expected_name in [
        "short-ethernet",
        "short-arp",
        "invalid-vlan-length",
        "bad-linux-sll-length",
        "bad-null-loopback-family-bytes",
        "bad-ipv4-ihl",
        "ipv4-total-length-shorter-than-header",
        "ipv4-option-overrun",
        "truncated-ipv6-base",
        "ipv6-payload-length-mismatch",
        "truncated-ipv6-routing-header",
        "truncated-ipv6-fragment-header",
        "truncated-ipv6-mobile-routing-header",
        "truncated-ipv6-segment-routing-header",
        "udp-length-underflow",
        "tcp-data-offset-underflow",
        "tcp-data-offset-overrun",
        "tcp-option-length-overrun",
        "icmp-short-headers",
        "dns-compression-loop",
        "dns-pointer-out-of-range",
        "dhcp-missing-magic-cookie",
        "dhcp-truncated-option",
    ] {
        assert!(
            cases.iter().any(|case| case.name == expected_name),
            "malformed corpus missing named coverage for {expected_name}"
        );
    }

    for case in &cases {
        assert!(
            !case.name.is_empty(),
            "malformed corpus case name must be stable"
        );
        decode_malformed_case(case);
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
