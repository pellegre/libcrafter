#[macro_use]
mod support;

use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::core::{
    decode_dns_name, scan_dhcp_option_segments, Arp, CrafterError, Dhcp, DhcpOption,
    DhcpOptionArea, Dns, Ethernet, Icmpv4, Icmpv6, Ipv4, Ipv4Option, Ipv4Protocol, Ipv6,
    Ipv6DestinationOptionsHeader, Ipv6FragmentHeader, Ipv6HopByHopOptionsHeader,
    Ipv6MobileRoutingHeader, Ipv6Option, Ipv6RoutingHeader, Ipv6SegmentRoutingHeader, LinkType,
    LinuxSll, LlcSnap, MacAddr, NetworkLayer, NullLoopback, OptionOverload, Packet, Raw, Tcp,
    TcpOption, Udp, UdpOptionStatus, UdpOptions, Vlan, DHCP_CLIENT_PORT, DHCP_SERVER_PORT,
    DNS_PORT,
    IPPROTO_IPV6_AH, IPPROTO_IPV6_ESP, IPPROTO_IPV6_EXPERIMENTAL_1, IPPROTO_IPV6_EXPERIMENTAL_2,
    IPPROTO_IPV6_HIP, IPPROTO_IPV6_MOBILITY, IPPROTO_IPV6_ROUTE, IPPROTO_IPV6_SHIM6, IPPROTO_UDP,
    IPV6_ROUTING_TYPE_EXPERIMENTAL_1, IPV6_ROUTING_TYPE_EXPERIMENTAL_2, IPV6_ROUTING_TYPE_MOBILE,
    IPV6_ROUTING_TYPE_NIMROD, IPV6_ROUTING_TYPE_RH0, TCP_FLAG_ACK, TCP_FLAG_PSH, TCP_FLAG_SYN,
};
use proptest::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DecodeTarget {
    Ethernet,
    Dot11,
    Radiotap,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedOutcome {
    Error(ExpectedError),
    UdpOptionStatus(UdpOptionStatus),
}

#[derive(Debug)]
struct MalformedCase {
    name: &'static str,
    target: DecodeTarget,
    expected_outcome: ExpectedOutcome,
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

fn exercise_ipv4_like_decode(bytes: &[u8]) {
    exercise_packet_decode(PacketDecodeTarget::L3(NetworkLayer::Ipv4), bytes);

    if let Some(options) = ipv4_declared_option_slice(bytes) {
        let _ = Ipv4Option::decode_all(options);
    }
}

fn ipv4_declared_option_slice(bytes: &[u8]) -> Option<&[u8]> {
    let first = *bytes.first()?;
    let header_len = usize::from(first & 0x0f) * 4;
    if header_len > 20 && bytes.len() >= header_len {
        Some(&bytes[20..header_len])
    } else {
        None
    }
}

fn ipv4_like_bytes_strategy() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<u8>(),
        any::<u8>(),
        any::<u16>(),
        any::<u16>(),
        any::<[u8; 2]>(),
        any::<u8>(),
        any::<u8>(),
        prop::collection::vec(any::<u8>(), 0..40),
        prop::collection::vec(any::<u8>(), 0..96),
    )
        .prop_map(
            |(
                version_ihl,
                tos,
                total_length,
                identification,
                flags_offset,
                ttl,
                protocol,
                option_bytes,
                payload_tail,
            )| {
                let ihl_words = usize::from(version_ihl & 0x0f);
                let option_len = ihl_words.saturating_sub(5) * 4;

                let mut bytes = Vec::with_capacity(20 + option_len + payload_tail.len());
                bytes.push(version_ihl);
                bytes.push(tos);
                bytes.extend_from_slice(&total_length.to_be_bytes());
                bytes.extend_from_slice(&identification.to_be_bytes());
                bytes.extend_from_slice(&flags_offset);
                bytes.push(ttl);
                bytes.push(protocol);
                bytes.extend_from_slice(&[0, 0]);
                bytes.extend_from_slice(&[192, 0, 2, 1]);
                bytes.extend_from_slice(&[198, 51, 100, 1]);

                bytes.extend(option_bytes.iter().copied().take(option_len));
                if option_len > option_bytes.len() {
                    bytes.resize(20 + option_len, 0);
                }
                bytes.extend_from_slice(&payload_tail);
                bytes
            },
        )
}

fn decode_malformed_case(case: &MalformedCase) -> crafter::core::Result<()> {
    if expects_decoded_udp_option_status(case) {
        return decode_malformed_packet_case(case).map(drop);
    }

    match case.target {
        DecodeTarget::Ipv4Options => Ipv4Option::decode_all(&case.bytes).map(drop),
        DecodeTarget::TcpOptions => TcpOption::decode_all(&case.bytes).map(drop),
        DecodeTarget::Dhcp => Dhcp::decode(&case.bytes).map(drop),
        DecodeTarget::DhcpOptions => DhcpOption::decode_all(&case.bytes).map(drop),
        DecodeTarget::DnsName => decode_dns_name(&case.bytes, 0).map(drop),
        _ => decode_malformed_packet_case(case).map(drop),
    }
}

fn decode_malformed_packet_case(case: &MalformedCase) -> crafter::core::Result<Packet> {
    match case.target {
        DecodeTarget::Ethernet => {
            decode_packet(PacketDecodeTarget::Link(LinkType::Ethernet), &case.bytes)
        }
        DecodeTarget::Dot11 => {
            decode_packet(PacketDecodeTarget::Link(LinkType::Ieee80211), &case.bytes)
        }
        DecodeTarget::Radiotap => {
            decode_packet(PacketDecodeTarget::Link(LinkType::Radiotap), &case.bytes)
        }
        DecodeTarget::LinuxSll => {
            decode_packet(PacketDecodeTarget::Link(LinkType::LinuxSll), &case.bytes)
        }
        DecodeTarget::NullLoopback => decode_packet(
            PacketDecodeTarget::Link(LinkType::NullLoopback),
            &case.bytes,
        ),
        DecodeTarget::Ipv4 => {
            decode_packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4), &case.bytes)
        }
        DecodeTarget::Ipv6 => {
            decode_packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6), &case.bytes)
        }
        DecodeTarget::Ipv4Options
        | DecodeTarget::TcpOptions
        | DecodeTarget::Dhcp
        | DecodeTarget::DhcpOptions
        | DecodeTarget::DnsName => {
            panic!(
                "malformed corpus case {} cannot use UDP option status with target {:?}",
                case.name, case.target
            )
        }
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
                expected_outcome: parse_expected_outcome(
                    name,
                    expected_kind,
                    expected_context_or_field,
                ),
                bytes: parse_hex(name, hex),
            })
        })
        .collect()
}

fn parse_target(name: &str, target: &str) -> DecodeTarget {
    match target {
        "ethernet" => DecodeTarget::Ethernet,
        "dot11" => DecodeTarget::Dot11,
        "radiotap" => DecodeTarget::Radiotap,
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

fn parse_expected_outcome(
    name: &str,
    expected_kind: &'static str,
    expected_context_or_field: &'static str,
) -> ExpectedOutcome {
    match expected_kind {
        "udp-option-status" => ExpectedOutcome::UdpOptionStatus(parse_udp_option_status(
            name,
            expected_context_or_field,
        )),
        _ => ExpectedOutcome::Error(ExpectedError {
            kind: parse_expected_error_kind(name, expected_kind),
            context_or_field: expected_context_or_field,
        }),
    }
}

fn parse_udp_option_status(name: &str, status: &str) -> UdpOptionStatus {
    match status {
        "additional-payload-checksum-invalid" => UdpOptionStatus::AdditionalPayloadChecksumInvalid,
        "malformed-envelope" => UdpOptionStatus::MalformedEnvelope,
        "nonzero-after-eol" => UdpOptionStatus::NonzeroAfterEndOfList,
        "option-checksum-invalid" => UdpOptionStatus::OptionChecksumInvalid,
        _ => panic!("malformed corpus case {name} has unknown UDP option status {status}"),
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
    let ExpectedOutcome::Error(expected_error) = case.expected_outcome else {
        panic!(
            "malformed corpus case {} expected UDP option status, got structured error {error:?}",
            case.name
        );
    };

    match (expected_error.kind, error) {
        (ExpectedErrorKind::BufferTooShort, CrafterError::BufferTooShort { context, .. }) => {
            assert_eq!(
                context, expected_error.context_or_field,
                "malformed corpus case {} returned an unexpected buffer context",
                case.name
            )
        }
        (ExpectedErrorKind::InvalidFieldValue, CrafterError::InvalidFieldValue { field, .. }) => {
            assert_eq!(
                field, expected_error.context_or_field,
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

fn assert_udp_option_status_matches(case: &MalformedCase, packet: Packet) {
    let ExpectedOutcome::UdpOptionStatus(expected_status) = case.expected_outcome else {
        panic!(
            "malformed corpus case {} unexpectedly decoded successfully",
            case.name
        );
    };
    let udp_options = packet.layer::<UdpOptions>().unwrap_or_else(|| {
        panic!(
            "malformed corpus case {} decoded without a UDP options layer",
            case.name
        )
    });
    assert_eq!(
        udp_options.status(),
        expected_status,
        "malformed corpus case {} returned an unexpected UDP option status",
        case.name
    );
}

fn expects_decoded_udp_option_status(case: &MalformedCase) -> bool {
    matches!(case.expected_outcome, ExpectedOutcome::UdpOptionStatus(_))
}

fn required_malformed_families() -> &'static [&'static str] {
    &[
        "short ethernet",
        "short radiotap header",
        "invalid radiotap length",
        "radiotap length overrun",
        "unterminated radiotap present bitmap",
        "truncated radiotap field",
        "short dot11 frame control",
        "truncated dot11 header",
        "truncated dot11 qos control",
        "truncated dot11 address four",
        "truncated dot11 tagged parameter",
        "truncated dot11 llc snap",
        "truncated dot11 rsn ie",
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
        "truncated ipv6 hop-by-hop options header",
        "truncated ipv6 destination options header",
        "ipv6 option length overrun",
        "ipv6 padn option overrun",
        "ipv6 declared options header overrun",
        "truncated ipv6 routing header",
        "truncated ipv6 fragment header",
        "malformed ipv6 segment routing header",
        "truncated ipv6 unknown extension header",
        "short udp header",
        "invalid udp length",
        "udp length overrun",
        "malformed udp option envelope",
        "invalid udp option fixed length",
        "udp option extended length overrun",
        "udp option nonzero after eol",
        "udp option checksum invalid",
        "udp additional payload checksum invalid",
        "malformed udp frag option",
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
        "dns truncated pointer",
        "dns label length overrun",
        "dns edns option length overrun",
        "dns edns truncated option header",
        "dns nsec bitmap window length",
        "dns nsec3 salt length overrun",
        "dns message trailing bytes",
        "dns a bad rdlength",
        "dns aaaa bad rdlength",
        "dns soa bad fixed tail",
        "dns srv trailing bytes",
        "dns mx exchange overrun",
        "dns txt string overrun",
        "dns ds too short",
        "dns dnskey too short",
        "dns rrsig too short",
        "dns nsec3 hash length overrun",
        "dns nsec bitmap trailing zero",
        "dns svcb param out of order",
        "dns svcb param length overrun",
        "dns name reserved marker",
        "dns name full length overrun",
        "short dhcp packet",
        "missing dhcp magic cookie",
        "truncated dhcp option",
        "invalid dhcp fixed option length",
        "dhcp missing end marker",
        "dhcp non-padding after end",
        "dhcp invalid fixed length",
        "dhcp malformed option overload",
    ]
}

fn malformed_family(name: &str) -> Option<&'static str> {
    match name {
        "short-ethernet" => Some("short ethernet"),
        "short-radiotap-header" => Some("short radiotap header"),
        "invalid-radiotap-length-below-base" => Some("invalid radiotap length"),
        "radiotap-length-overrun" => Some("radiotap length overrun"),
        "unterminated-radiotap-present-bitmap" => Some("unterminated radiotap present bitmap"),
        "truncated-radiotap-channel-field" => Some("truncated radiotap field"),
        "short-dot11-frame-control" => Some("short dot11 frame control"),
        "truncated-dot11-data-header" => Some("truncated dot11 header"),
        "truncated-dot11-qos-control" => Some("truncated dot11 qos control"),
        "truncated-dot11-address-four" => Some("truncated dot11 address four"),
        "truncated-dot11-tagged-parameter" => Some("truncated dot11 tagged parameter"),
        "truncated-dot11-llc-snap" => Some("truncated dot11 llc snap"),
        "truncated-dot11-rsn-ie" => Some("truncated dot11 rsn ie"),
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
        "truncated-ipv6-hop-by-hop-options-header" => {
            Some("truncated ipv6 hop-by-hop options header")
        }
        "truncated-ipv6-destination-options-header" => {
            Some("truncated ipv6 destination options header")
        }
        "ipv6-hop-by-hop-option-length-overrun" | "ipv6-destination-option-length-overrun" => {
            Some("ipv6 option length overrun")
        }
        "ipv6-hop-by-hop-padn-length-overrun" | "ipv6-destination-padn-length-overrun" => {
            Some("ipv6 padn option overrun")
        }
        "ipv6-hop-by-hop-declared-header-overrun" | "ipv6-destination-declared-header-overrun" => {
            Some("ipv6 declared options header overrun")
        }
        "truncated-ipv6-routing-header" => Some("truncated ipv6 routing header"),
        "truncated-ipv6-fragment-header" => Some("truncated ipv6 fragment header"),
        "malformed-ipv6-segment-routing-header"
        | "short-ipv6-segment-routing-header"
        | "ipv6-segment-routing-declared-fields-overrun"
        | "ipv6-segment-routing-tlv-length-overrun" => {
            Some("malformed ipv6 segment routing header")
        }
        "truncated-ipv6-unknown-extension-header" => {
            Some("truncated ipv6 unknown extension header")
        }
        "udp-short-header" => Some("short udp header"),
        "udp-invalid-length" => Some("invalid udp length"),
        "udp-length-overrun" | "udp-ipv6-length-overrun" => Some("udp length overrun"),
        "udp-option-envelope-too-short" => Some("malformed udp option envelope"),
        "udp-option-invalid-fixed-length" => Some("invalid udp option fixed length"),
        "udp-option-extended-length-overrun" => Some("udp option extended length overrun"),
        "udp-option-nonzero-after-eol" => Some("udp option nonzero after eol"),
        "udp-option-invalid-ocs" => Some("udp option checksum invalid"),
        "udp-option-invalid-apc" => Some("udp additional payload checksum invalid"),
        "udp-option-malformed-frag" => Some("malformed udp frag option"),
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
        "dns-truncated-pointer" => Some("dns truncated pointer"),
        "dns-label-length-overrun" => Some("dns label length overrun"),
        "dns-edns-opt-option-length-overrun" => Some("dns edns option length overrun"),
        "dns-edns-opt-truncated-option-header" => Some("dns edns truncated option header"),
        "dns-nsec-bitmap-window-zero-length" => Some("dns nsec bitmap window length"),
        "dns-nsec3-salt-length-overrun" => Some("dns nsec3 salt length overrun"),
        "dns-message-trailing-bytes" => Some("dns message trailing bytes"),
        "dns-a-bad-rdlength" => Some("dns a bad rdlength"),
        "dns-aaaa-bad-rdlength" => Some("dns aaaa bad rdlength"),
        "dns-soa-bad-fixed-tail" => Some("dns soa bad fixed tail"),
        "dns-srv-trailing-bytes" => Some("dns srv trailing bytes"),
        "dns-mx-exchange-overrun" => Some("dns mx exchange overrun"),
        "dns-txt-string-overrun" => Some("dns txt string overrun"),
        "dns-ds-too-short" => Some("dns ds too short"),
        "dns-dnskey-too-short" => Some("dns dnskey too short"),
        "dns-rrsig-too-short" => Some("dns rrsig too short"),
        "dns-nsec3-hash-length-overrun" => Some("dns nsec3 hash length overrun"),
        "dns-nsec-bitmap-trailing-zero" => Some("dns nsec bitmap trailing zero"),
        "dns-svcb-param-out-of-order" => Some("dns svcb param out of order"),
        "dns-svcb-param-length-overrun" => Some("dns svcb param length overrun"),
        "dns-name-reserved-marker" => Some("dns name reserved marker"),
        "dns-name-full-length-overrun" => Some("dns name full length overrun"),
        "dhcp-short-fixed-header" => Some("short dhcp packet"),
        "dhcp-missing-magic-cookie" => Some("missing dhcp magic cookie"),
        "dhcp-truncated-option" | "dhcp-overload-file-truncated-option" => {
            Some("truncated dhcp option")
        }
        "dhcp-invalid-fixed-option-length" => Some("invalid dhcp fixed option length"),
        "dhcp-missing-end-marker" => Some("dhcp missing end marker"),
        "dhcp-non-padding-after-end" => Some("dhcp non-padding after end"),
        "dhcp-invalid-hardware-length" => Some("dhcp invalid fixed length"),
        "dhcp-overload-file-missing-end" => Some("dhcp malformed option overload"),
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

fn ipv4_options_for_selector(selector: u8) -> Vec<Ipv4Option> {
    match selector % 5 {
        0 => Vec::new(),
        1 => vec![Ipv4Option::no_operation()],
        2 => vec![Ipv4Option::router_alert(0)],
        3 => vec![Ipv4Option::timestamp(5, 0, [0x0102_0304])],
        _ => vec![Ipv4Option::generic(30, [0xab, selector])],
    }
}

fn ipv4_with_options(mut ipv4: Ipv4, options: &[Ipv4Option]) -> Ipv4 {
    for option in options {
        ipv4 = ipv4
            .ipv4_option(option.clone())
            .expect("selected IPv4 option should encode");
    }
    ipv4
}

fn encoded_ipv4_options(options: &[Ipv4Option]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for option in options {
        bytes.extend(option.encode().expect("selected IPv4 option should encode"));
    }
    bytes
}

fn deterministic_payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add(index as u8))
        .collect()
}

fn dhcp_client_mac() -> MacAddr {
    MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01])
}

fn segment_routing_malformed_ipv6_packet(route_payload: &[u8]) -> Vec<u8> {
    let ipv6 = Ipv6::with_addresses(
        Ipv6Addr::new(0x2001, 0x0db8, 0x0039, 0, 0, 0, 0, 0x0001),
        Ipv6Addr::new(0x2001, 0x0db8, 0x0039, 0, 0, 0, 0, 0x0002),
    )
    .next_header(43);

    (ipv6 / Raw::from_bytes(route_payload))
        .compile()
        .expect("malformed SRH IPv6 envelope should compile")
        .as_bytes()
        .to_vec()
}

fn segment_routing_malformed_ethernet_frame(ipv6_packet: &[u8]) -> Vec<u8> {
    let ethernet = Ethernet::with_addresses(
        MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x02]),
        MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]),
    )
    .ethertype(0x86dd);

    (ethernet / Raw::from_bytes(ipv6_packet))
        .compile()
        .expect("malformed SRH Ethernet envelope should compile")
        .as_bytes()
        .to_vec()
}

fn segment_routing_malformed_linux_sll_frame(ipv6_packet: &[u8]) -> Vec<u8> {
    (LinuxSll::new()
        .source_address(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
        .protocol(0x86dd)
        / Raw::from_bytes(ipv6_packet))
    .compile()
    .expect("malformed SRH Linux SLL envelope should compile")
    .as_bytes()
    .to_vec()
}

fn doc_ipv6_resilience_addr(subnet: u16, host: u16) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, subnet, 0, 0, 0, 0, host)
}

fn ipv6_resilience_base(hop_limit: u8) -> Ipv6 {
    Ipv6::with_addresses(
        doc_ipv6_resilience_addr(0x0048, 0x0001),
        doc_ipv6_resilience_addr(0x0048, 0x0002),
    )
    .traffic_class(0x2a)
    .flow_label(0x04800)
    .hop_limit(hop_limit)
}

fn ipv6_routing_payload_packet(route_payload: &[u8]) -> Vec<u8> {
    (ipv6_resilience_base(48).next_header(IPPROTO_IPV6_ROUTE) / Raw::from_bytes(route_payload))
        .compile()
        .expect("malformed IPv6 routing envelope should compile")
        .as_bytes()
        .to_vec()
}

fn assert_ipv6_roundtrip_inspectable(label: &str, packet: Packet) -> crafter::core::Result<()> {
    let bytes = packet
        .compile()
        .unwrap_or_else(|err| panic!("{label} should compile: {err}"));
    let decoded = decode_packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6), bytes.as_bytes())
        .unwrap_or_else(|err| panic!("{label} should decode: {err}"));
    assert!(
        !decoded.summary().is_empty(),
        "{label} summary should be inspectable"
    );
    assert!(
        !decoded.show().is_empty(),
        "{label} show output should be inspectable"
    );
    let recompiled = decoded
        .compile()
        .unwrap_or_else(|err| panic!("{label} decoded packet should compile: {err}"));
    assert_eq!(
        recompiled.as_bytes(),
        bytes.as_bytes(),
        "{label} decode/compile changed stable bytes"
    );
    Ok(())
}

#[test]
fn ipv6_curated_resilience_decode_surfaces_are_inspectable() -> crafter::core::Result<()> {
    let segment = doc_ipv6_resilience_addr(0x0048, 0x0030);
    let home = doc_ipv6_resilience_addr(0x0048, 0x0040);

    let cases = vec![
        (
            "base-udp",
            ipv6_resilience_base(49)
                / Udp::new().source_port(49_001).destination_port(49_002)
                / Raw::from("ipv6-base"),
        ),
        (
            "hop-by-hop-and-destination-options",
            ipv6_resilience_base(50)
                / Ipv6HopByHopOptionsHeader::new()
                    .option(Ipv6Option::pad1())
                    .option(Ipv6Option::generic(0x1e, [0xaa, 0xbb])?)
                / Ipv6DestinationOptionsHeader::new()
                    .option(Ipv6Option::home_address(home))
                    .option(Ipv6Option::pad1())
                / Udp::new().source_port(50_001).destination_port(50_002)
                / Raw::from("ipv6-options"),
        ),
        (
            "generic-routing",
            ipv6_resilience_base(51)
                / Ipv6RoutingHeader::new()
                    .next_header(IPPROTO_IPV6_EXPERIMENTAL_1)
                    .routing_type(IPV6_ROUTING_TYPE_EXPERIMENTAL_1)
                    .segments_left(0)
                    .type_data([0xde, 0xad, 0xbe, 0xef])
                / Raw::from("ipv6-generic-routing"),
        ),
        (
            "mobile-routing",
            ipv6_resilience_base(52)
                / Ipv6MobileRoutingHeader::new()
                    .next_header(IPPROTO_IPV6_EXPERIMENTAL_1)
                    .home_address(home)
                / Raw::from("ipv6-mobile-routing"),
        ),
        (
            "segment-routing",
            ipv6_resilience_base(53)
                / Ipv6SegmentRoutingHeader::new()
                    .next_header(IPPROTO_IPV6_EXPERIMENTAL_1)
                    .segment(segment)
                    .flags(0xa0)
                    .tag(0x4801)
                    .raw_trailing_data([0x00, 0x05, 0x02, 0xaa, 0xbb])
                / Raw::from("ipv6-segment-routing"),
        ),
        (
            "atomic-fragment",
            ipv6_resilience_base(54)
                / Ipv6FragmentHeader::new()
                    .next_header(IPPROTO_UDP)
                    .fragment_offset(0)
                    .more_fragments(false)
                    .identification(0x4800_0001)
                / Udp::new().source_port(54_001).destination_port(54_002)
                / Raw::from("ipv6-atomic-fragment"),
        ),
        (
            "non-initial-fragment",
            ipv6_resilience_base(55)
                / Ipv6FragmentHeader::new()
                    .next_header(IPPROTO_UDP)
                    .fragment_offset(3)
                    .more_fragments(true)
                    .identification(0x4800_0002)
                / Raw::from_bytes(&[0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb, 0xcc, 0xdd]),
        ),
        (
            "extension-chain",
            ipv6_resilience_base(56)
                / Ipv6HopByHopOptionsHeader::new().option(Ipv6Option::pad1())
                / Ipv6DestinationOptionsHeader::new().option(Ipv6Option::generic(0x3e, [0xcc])?)
                / Ipv6RoutingHeader::new()
                    .routing_type(IPV6_ROUTING_TYPE_EXPERIMENTAL_2)
                    .segments_left(0)
                    .type_data([0x48, 0x00, 0x00, 0x01])
                / Ipv6SegmentRoutingHeader::new().segment(segment)
                / Ipv6FragmentHeader::new()
                    .fragment_offset(0)
                    .more_fragments(false)
                    .identification(0x4800_0003)
                / Udp::new().source_port(56_001).destination_port(56_002)
                / Raw::from("ipv6-extension-chain"),
        ),
    ];

    for (label, packet) in cases {
        assert_ipv6_roundtrip_inspectable(label, packet)?;
    }

    for (label, next_header) in [
        ("unknown-ah", IPPROTO_IPV6_AH),
        ("unknown-esp", IPPROTO_IPV6_ESP),
        ("unknown-mobility", IPPROTO_IPV6_MOBILITY),
        ("unknown-hip", IPPROTO_IPV6_HIP),
        ("unknown-shim6", IPPROTO_IPV6_SHIM6),
        ("unknown-experimental-1", IPPROTO_IPV6_EXPERIMENTAL_1),
        ("unknown-experimental-2", IPPROTO_IPV6_EXPERIMENTAL_2),
        ("unknown-reserved-255", 255),
    ] {
        assert_ipv6_roundtrip_inspectable(
            label,
            ipv6_resilience_base(57).next_header(next_header)
                / Raw::from(format!("{label}-payload")),
        )?;
    }

    Ok(())
}

#[test]
fn malformed_ipv6_mobile_routing_reports_structured_error() {
    let route_payload = [
        IPPROTO_IPV6_EXPERIMENTAL_1,
        0,
        IPV6_ROUTING_TYPE_MOBILE,
        1,
        0,
        0,
        0,
        0,
    ];
    let bytes = ipv6_routing_payload_packet(&route_payload);
    match decode_packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6), &bytes) {
        Err(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(field, "ipv6.mobile.header_ext_len");
            assert!(
                !reason.is_empty(),
                "mobile routing malformed error should carry a reason"
            );
        }
        other => panic!("malformed IPv6 mobile routing expected structured error, got {other:?}"),
    }
}

/// Malformed DHCP option payloads whose typed views are only decoded lazily
/// through the `Dhcp` accessors (the structural `Dhcp::decode` preserves them
/// as raw `Generic` segments). Each accessor must surface a structured
/// `CrafterError` with a stable `dhcp.option.*` context and never panic, and
/// the raw bytes must remain inspectable on the decoded layer.
#[test]
fn malformed_dhcp_typed_option_views_report_structured_errors() {
    // dhcp relay suboption: option 82 circuit-id suboption declares length 32
    // but only one payload octet is present (RFC 3046 sub-option TLV overrun).
    let relay = Dhcp::discover(dhcp_client_mac())
        .transaction_id(0x0102_0304)
        .option(DhcpOption::generic(82, vec![0x01, 0x20, 0x00]));
    let bytes = relay.malformed().to_bytes();
    let decoded = Dhcp::decode(&bytes).expect("relay frame must decode structurally");
    match decoded.relay_agent_information() {
        Some(Err(CrafterError::BufferTooShort { context, .. })) => {
            assert_eq!(context, "dhcp.option.relay_agent_information");
        }
        other => {
            panic!("malformed dhcp relay suboption expected a structured error, got {other:?}")
        }
    }
    // Raw option 82 bytes remain inspectable on the decoded layer.
    assert!(decoded
        .options_value()
        .iter()
        .any(|o| matches!(o, DhcpOption::Generic { code: 82, .. })));

    // dhcp classless route: option 121 prefix length 24 needs three subnet
    // octets plus a four-octet router, but only a truncated payload is present
    // (RFC 3442 destination-descriptor underrun).
    let route = Dhcp::ack(
        dhcp_client_mac(),
        Ipv4Addr::new(192, 0, 2, 100),
        Ipv4Addr::new(192, 0, 2, 1),
    )
    .option(DhcpOption::generic(121, vec![24, 192, 0]));
    let bytes = route.malformed().to_bytes();
    let decoded = Dhcp::decode(&bytes).expect("classless route frame must decode structurally");
    match decoded.classless_static_routes() {
        Some(Err(CrafterError::BufferTooShort { context, .. })) => {
            assert_eq!(context, "dhcp.option.classless_static_route");
        }
        other => {
            panic!("malformed dhcp classless route expected a structured error, got {other:?}")
        }
    }

    // dhcp domain search: option 119 label length 7 with a truncated label
    // (RFC 1035 label-length overrun read through RFC 3397 concatenation).
    let domain = Dhcp::ack(
        dhcp_client_mac(),
        Ipv4Addr::new(192, 0, 2, 100),
        Ipv4Addr::new(192, 0, 2, 1),
    )
    .option(DhcpOption::generic(119, vec![7, 101, 120]));
    let bytes = domain.malformed().to_bytes();
    let decoded = Dhcp::decode(&bytes).expect("domain search frame must decode structurally");
    match decoded.domain_search() {
        Some(Err(CrafterError::BufferTooShort { context, .. })) => {
            assert_eq!(context, "dhcp.option.domain_search");
        }
        other => panic!("malformed dhcp domain search expected a structured error, got {other:?}"),
    }
}

/// Malformed leasequery option payloads, carried on a DHCPLEASEQUERY frame as
/// raw `Generic` segments, must surface as structured `CrafterError`s through
/// the public leasequery accessors rather than panicking, and the raw option
/// bytes must remain inspectable on the decoded layer.
///
/// The structural `Dhcp::decode` preserves the unknown/short payloads verbatim;
/// the typed views (`client_last_transaction_time`, `associated_ip`,
/// `status_code`, `base_time`, `dhcp_state`, `data_source`) run the
/// source-backed format decoders, which reject the wrong lengths. This exercises
/// the same dimension the relay/route/domain views cover above, but for the RFC
/// 4388 / RFC 6926 leasequery option family.
#[test]
fn malformed_dhcp_leasequery_option_views_report_structured_errors() {
    use crafter::core::{DhcpDataSource, DhcpState, DhcpStatusCode};

    // Codepoints from the IANA BOOTP/DHCP options registry: RFC 4388
    // client-last-transaction-time (91) and associated-ip (92); RFC 6926
    // status-code (151), base-time (152), dhcp-state (156), and data-source
    // (157). Building from a real DHCPLEASEQUERY frame keeps this on the public
    // packet surface.
    const CLIENT_LAST_TRANSACTION_TIME: u8 = 91;
    const ASSOCIATED_IP: u8 = 92;
    const STATUS_CODE: u8 = 151;
    const BASE_TIME: u8 = 152;
    const DHCP_STATE: u8 = 156;
    const DATA_SOURCE: u8 = 157;

    fn decode_lease_query_with(code: u8, payload: Vec<u8>) -> Dhcp {
        let frame = Dhcp::lease_query_by_ip(Ipv4Addr::new(192, 0, 2, 50))
            .transaction_id(0x0102_0304)
            .option(DhcpOption::generic(code, payload));
        let bytes = frame.malformed().to_bytes();
        Dhcp::decode(&bytes).expect("leasequery frame must decode structurally")
    }

    // client-last-transaction-time (91): a 4-octet seconds value; three octets
    // is a fixed-length underrun.
    let decoded = decode_lease_query_with(CLIENT_LAST_TRANSACTION_TIME, vec![0x00, 0x00, 0x0e]);
    match decoded.client_last_transaction_time() {
        Some(Err(CrafterError::InvalidFieldValue { .. })) => {}
        other => panic!(
            "malformed client-last-transaction-time expected a structured error, got {other:?}"
        ),
    }
    // The raw option-91 bytes survive on the decoded layer for inspection.
    assert!(decoded
        .options_value()
        .iter()
        .any(|o| matches!(o, DhcpOption::Generic { code: 91, .. })));

    // associated-ip (92): one or more IPv4 addresses; seven octets is not a
    // non-zero multiple of four.
    let decoded = decode_lease_query_with(ASSOCIATED_IP, vec![192, 0, 2, 10, 198, 51, 100]);
    match decoded.associated_ip() {
        Some(Err(CrafterError::InvalidFieldValue { .. })) => {}
        other => panic!("malformed associated-ip expected a structured error, got {other:?}"),
    }

    // status-code (151): at least the one status octet must be present; an
    // empty payload is a buffer underrun.
    let decoded = decode_lease_query_with(STATUS_CODE, Vec::new());
    match decoded.status_code() {
        Some(Err(CrafterError::BufferTooShort { context, .. })) => {
            assert_eq!(context, "dhcp.option.value");
        }
        other => panic!("malformed status-code expected a structured error, got {other:?}"),
    }

    // base-time (152): a 4-octet absolute time; five octets is a fixed-length
    // overrun.
    let decoded = decode_lease_query_with(BASE_TIME, vec![0x00; 5]);
    match decoded.base_time() {
        Some(Err(CrafterError::InvalidFieldValue { .. })) => {}
        other => panic!("malformed base-time expected a structured error, got {other:?}"),
    }

    // dhcp-state (156): a single State octet; two octets is malformed.
    let decoded = decode_lease_query_with(DHCP_STATE, vec![0x01, 0x02]);
    match decoded.dhcp_state() {
        Some(Err(CrafterError::InvalidFieldValue { .. })) => {}
        other => panic!("malformed dhcp-state expected a structured error, got {other:?}"),
    }

    // data-source (157): a single Flags octet; an empty payload is malformed.
    let decoded = decode_lease_query_with(DATA_SOURCE, Vec::new());
    match decoded.data_source() {
        Some(Err(CrafterError::InvalidFieldValue { .. })) => {}
        other => panic!("malformed data-source expected a structured error, got {other:?}"),
    }

    // A well-formed frame with unassigned (unknown) status and state octets
    // still decodes cleanly through the same accessors, preserving the unknown
    // values verbatim (RFC 6926 leaves most code points Unassigned).
    let good = Dhcp::lease_query_by_ip(Ipv4Addr::new(192, 0, 2, 50))
        .transaction_id(0x0102_0304)
        .option(DhcpOption::generic(STATUS_CODE, vec![0x40, 0xff, 0x00]))
        .option(DhcpOption::generic(DHCP_STATE, vec![0x55]))
        .option(DhcpOption::generic(DATA_SOURCE, vec![0xFE]));
    let bytes = good.malformed().to_bytes();
    let decoded = Dhcp::decode(&bytes).expect("leasequery frame must decode structurally");
    let status = decoded
        .status_code()
        .expect("status present")
        .expect("status decodes");
    assert_eq!(status.status, DhcpStatusCode::Unknown(0x40));
    assert_eq!(status.message, vec![0xff, 0x00]);
    assert_eq!(
        decoded
            .dhcp_state()
            .expect("state present")
            .expect("state decodes"),
        DhcpState::Unknown(0x55),
    );
    let source = decoded
        .data_source()
        .expect("source present")
        .expect("source decodes");
    assert!(
        !source.is_remote(),
        "REMOTE bit clear when only UNA bits set"
    );
    assert_eq!(source, DhcpDataSource::new(0xFE));
}

/// DHCP-family malformed corpus rows: the names whose [`malformed_family`]
/// mapping covers a DHCP decode dimension the step requires (short fixed
/// headers, missing magic cookie, truncated options, invalid fixed option
/// lengths, missing end marker, non-padding after end, invalid hardware
/// lengths, and malformed option overload).
fn is_dhcp_malformed_case(case: &MalformedCase) -> bool {
    matches!(case.target, DecodeTarget::Dhcp | DecodeTarget::DhcpOptions)
}

/// Every malformed DHCP vector must surface a fully structured `CrafterError`,
/// not just the right variant: a `BufferTooShort` must carry the stable
/// `context` plus `required > available` (a buffer underrun, by definition),
/// and an `InvalidFieldValue` must carry the stable `field` plus a non-empty,
/// stable `reason`. This asserts the `context`/`required`/`available` fields the
/// step calls out, on top of the variant/context coverage the corpus runner
/// already checks, and confirms decoding never panics for any DHCP vector.
///
/// It is driven entirely off the existing malformed corpus so no fixture bytes
/// are duplicated; the DHCP rows already cover short fixed headers, missing
/// magic cookie, truncated options, invalid fixed option lengths, missing end
/// marker, non-padding after end, invalid hardware lengths, and malformed
/// option overload.
#[test]
fn malformed_dhcp_corpus_errors_carry_structured_fields() {
    let cases = malformed_cases();
    let dhcp_cases = cases
        .iter()
        .filter(|case| is_dhcp_malformed_case(case))
        .collect::<Vec<_>>();
    assert!(
        !dhcp_cases.is_empty(),
        "malformed corpus must carry DHCP vectors"
    );

    // Every required DHCP decode dimension must be represented among the rows
    // under test so this never silently narrows.
    let dhcp_required_families = [
        "short dhcp packet",
        "missing dhcp magic cookie",
        "truncated dhcp option",
        "invalid dhcp fixed option length",
        "dhcp missing end marker",
        "dhcp non-padding after end",
        "dhcp invalid fixed length",
        "dhcp malformed option overload",
    ];
    let covered = dhcp_cases
        .iter()
        .filter_map(|case| malformed_family(case.name))
        .collect::<std::collections::HashSet<_>>();
    for family in dhcp_required_families {
        assert!(
            covered.contains(family),
            "malformed DHCP corpus missing structured-field coverage for {family}"
        );
    }

    for case in dhcp_cases {
        let Err(error) = decode_malformed_case(case) else {
            panic!(
                "malformed DHCP corpus case {} unexpectedly decoded",
                case.name
            );
        };
        // The variant/context match is shared with the corpus runner; here we
        // additionally assert the structured payload.
        assert_error_matches(case, error.clone());
        let ExpectedOutcome::Error(expected_error) = case.expected_outcome else {
            panic!(
                "malformed DHCP case {} expected structured error outcome",
                case.name
            );
        };
        match error {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(
                    context, expected_error.context_or_field,
                    "malformed DHCP case {} carried an unexpected buffer context",
                    case.name
                );
                assert!(
                    required > available,
                    "malformed DHCP case {} BufferTooShort must require more ({required}) \
                     than is available ({available})",
                    case.name
                );
            }
            CrafterError::InvalidFieldValue { field, reason } => {
                assert_eq!(
                    field, expected_error.context_or_field,
                    "malformed DHCP case {} carried an unexpected invalid field",
                    case.name
                );
                assert!(
                    !reason.is_empty(),
                    "malformed DHCP case {} InvalidFieldValue must carry a non-empty reason",
                    case.name
                );
            }
            other => panic!(
                "malformed DHCP case {} returned an unexpected error {other:?}",
                case.name
            ),
        }
    }
}

/// Malformed DHCP vectors built through the public [`DhcpMalformed`] surface
/// (rather than raw corpus hex) must also decode to structured `CrafterError`s
/// with the `required`/`available`/`reason` fields populated and never panic.
///
/// This exercises the same required dimensions through the typed builder so the
/// malformation knobs themselves stay covered: short fixed header (truncation),
/// missing magic cookie, truncated trailing option, missing end marker,
/// non-padding after the end marker, invalid hardware length, an oversized
/// (length-truncated) option payload, and a malformed option-overload file
/// area.
#[test]
fn malformed_dhcp_builder_vectors_report_structured_errors() {
    use crafter::core::DhcpMalformed;

    let base = || Dhcp::discover(dhcp_client_mac()).transaction_id(0x0102_0304);

    // Short fixed header: a complete DHCP frame truncated below DHCP_MIN_LEN.
    let full = DhcpMalformed::from_valid(base()).to_bytes();
    let short = &full[..8.min(full.len())];
    match Dhcp::decode(short) {
        Err(CrafterError::BufferTooShort {
            context,
            required,
            available,
        }) => {
            assert_eq!(context, "dhcp packet");
            assert!(
                required > available,
                "short fixed header must require more ({required}) than available ({available})"
            );
            assert_eq!(available, short.len());
        }
        other => panic!("short DHCP fixed header expected BufferTooShort, got {other:?}"),
    }

    // Missing magic cookie: a full-length frame whose cookie is corrupted.
    let bytes = DhcpMalformed::from_valid(base())
        .invalid_magic_cookie(0x0000_0000)
        .to_bytes();
    match Dhcp::decode(&bytes) {
        Err(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(field, "dhcp.magic_cookie");
            assert!(!reason.is_empty());
        }
        other => panic!("invalid DHCP magic cookie expected InvalidFieldValue, got {other:?}"),
    }

    // Truncated option: a message-type option declares length 1 but supplies no
    // payload octet.
    let bytes = DhcpMalformed::from_valid(base())
        .option_with_declared_len(53, 1, [])
        .to_bytes();
    match Dhcp::decode(&bytes) {
        Err(CrafterError::BufferTooShort {
            context,
            required,
            available,
        }) => {
            assert_eq!(context, "dhcp option data");
            assert!(required > available);
        }
        other => panic!("truncated DHCP option expected BufferTooShort, got {other:?}"),
    }

    // Invalid fixed option length: message-type (53) declares length 2 but the
    // option is a fixed single octet.
    let bytes = DhcpMalformed::from_valid(base())
        .option_with_declared_len(53, 2, [0x01, 0x00])
        .to_bytes();
    match Dhcp::decode(&bytes) {
        Err(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(field, "dhcp.option.message_type");
            assert!(!reason.is_empty());
        }
        other => {
            panic!("invalid fixed DHCP option length expected InvalidFieldValue, got {other:?}")
        }
    }

    // Missing end marker: a non-empty options area without the trailing end
    // option.
    let bytes = DhcpMalformed::from_valid(base())
        .raw_options([0x35, 0x01, 0x01])
        .to_bytes();
    match Dhcp::decode(&bytes) {
        Err(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(field, "dhcp.options");
            assert!(!reason.is_empty());
        }
        other => panic!("missing DHCP end marker expected InvalidFieldValue, got {other:?}"),
    }

    // Non-padding after end: a complete option segment follows the end option.
    let bytes = DhcpMalformed::from_valid(base())
        .trailing_after_end([0x35, 0x01, 0x01])
        .to_bytes();
    match Dhcp::decode(&bytes) {
        Err(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(field, "dhcp.option.end");
            assert!(!reason.is_empty());
        }
        other => panic!("non-padding after DHCP end expected InvalidFieldValue, got {other:?}"),
    }

    // Invalid hardware length: hlen 32 exceeds the 16-byte chaddr field.
    let bytes = DhcpMalformed::from_valid(base().hardware_len(32)).to_bytes();
    match Dhcp::decode(&bytes) {
        Err(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(field, "dhcp.hlen");
            assert!(!reason.is_empty());
        }
        other => panic!("invalid DHCP hardware length expected InvalidFieldValue, got {other:?}"),
    }

    // Malformed typed option payload via oversized payload: a 300-octet payload
    // with a length-truncated (300 % 256 = 44) length byte overruns the option.
    let bytes = DhcpMalformed::from_valid(base())
        .oversized_option_payload(43, vec![0u8; 300])
        .to_bytes();
    // The decoder must not panic; it may surface a structured error or preserve
    // the bytes as a raw generic segment depending on the truncated length, but
    // it must never panic.
    let _ = Dhcp::decode(&bytes);

    // Malformed option overload: option 52 (in the normal options area) marks
    // the file area overloaded, but the file area carries a truncated option
    // (declared length overruns the 128-byte field) and no end marker.
    let mut file_area = vec![0u8; 128];
    file_area[0] = 0x43; // option 67 (bootfile name)
    file_area[1] = 200; // declared length overruns the 128-byte file area
    let bytes =
        DhcpMalformed::from_valid(base().option(DhcpOption::option_overload(OptionOverload::File)))
            .raw_file(file_area)
            .to_bytes();
    let _ = Dhcp::decode(&bytes); // must not panic; structured error or raw preservation
}

/// ARP malformed corpus rows: every Ethernet-rooted vector whose ARP body is
/// truncated. This covers the short fixed header plus a truncation point inside
/// each of the four variable address fields (sender hardware, sender protocol,
/// target hardware, target protocol).
fn is_arp_malformed_case(case: &MalformedCase) -> bool {
    matches!(case.target, DecodeTarget::Ethernet) && case.name.contains("arp")
}

fn is_ipv6_malformed_case(case: &MalformedCase) -> bool {
    matches!(case.target, DecodeTarget::Ipv6)
}

fn is_ipv6_options_malformed_case(case: &MalformedCase) -> bool {
    matches!(
        malformed_family(case.name),
        Some("truncated ipv6 hop-by-hop options header")
            | Some("truncated ipv6 destination options header")
            | Some("ipv6 option length overrun")
            | Some("ipv6 padn option overrun")
            | Some("ipv6 declared options header overrun")
    )
}

fn is_dot11_or_radiotap_malformed_case(case: &MalformedCase) -> bool {
    matches!(case.target, DecodeTarget::Dot11 | DecodeTarget::Radiotap)
}

#[test]
fn malformed_dot11_and_radiotap_corpus_errors_carry_structured_fields() {
    let cases = malformed_cases();
    let dot11_cases = cases
        .iter()
        .filter(|case| is_dot11_or_radiotap_malformed_case(case))
        .collect::<Vec<_>>();
    assert!(
        !dot11_cases.is_empty(),
        "malformed corpus must carry Dot11/radiotap vectors"
    );

    let exact_counts = [
        ("short-radiotap-header", "radiotap.header", 8, 7),
        (
            "invalid-radiotap-length-below-base",
            "radiotap.header",
            8,
            4,
        ),
        ("radiotap-length-overrun", "radiotap.header", 12, 8),
        (
            "unterminated-radiotap-present-bitmap",
            "radiotap.present",
            8,
            4,
        ),
        ("truncated-radiotap-channel-field", "radiotap.field", 12, 10),
        ("short-dot11-frame-control", "dot11.frame_control", 2, 1),
        ("truncated-dot11-data-header", "dot11.header", 24, 23),
        ("truncated-dot11-qos-control", "dot11.header", 26, 25),
        ("truncated-dot11-address-four", "dot11.header", 30, 29),
        (
            "truncated-dot11-tagged-parameter",
            "dot11.tagged_parameter",
            9,
            4,
        ),
        ("truncated-dot11-llc-snap", "llc_snap.header", 8, 4),
        (
            "truncated-dot11-rsn-ie",
            "dot11.tagged_parameter",
            22,
            8,
        ),
    ];
    let covered = dot11_cases
        .iter()
        .map(|case| case.name)
        .collect::<std::collections::HashSet<_>>();
    for (name, _, _, _) in exact_counts {
        assert!(
            covered.contains(name),
            "malformed Dot11/radiotap corpus missing structured-field coverage for {name}"
        );
    }

    for (name, expected_context, expected_required, expected_available) in exact_counts {
        let case = dot11_cases
            .iter()
            .copied()
            .find(|case| case.name == name)
            .expect("checked coverage above");
        let Err(error) = decode_malformed_case(case) else {
            panic!(
                "malformed Dot11/radiotap corpus case {} unexpectedly decoded",
                case.name
            );
        };
        assert_error_matches(case, error.clone());

        match error {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(
                    context, expected_context,
                    "malformed Dot11/radiotap case {} carried an unexpected buffer context",
                    case.name
                );
                assert_eq!(
                    required, expected_required,
                    "malformed Dot11/radiotap case {} carried an unexpected required length",
                    case.name
                );
                assert_eq!(
                    available, expected_available,
                    "malformed Dot11/radiotap case {} carried an unexpected available length",
                    case.name
                );
                assert!(
                    required > available,
                    "malformed Dot11/radiotap case {} BufferTooShort must require more \
                     ({required}) than is available ({available})",
                    case.name
                );
            }
            other => panic!(
                "malformed Dot11/radiotap case {} returned an unexpected error {other:?}",
                case.name
            ),
        }
    }
}

#[test]
fn malformed_dot11_truncated_eapol_payload_stays_raw_until_typed_decoder_exists() {
    let bytes = parse_hex(
        "truncated-dot11-eapol-raw-boundary",
        "\
        0800000002005e10000102005e10000202005e1000037000\
        aaaa03000000888e0203000501\
        ",
    );

    let packet = Packet::decode_from_link(LinkType::Ieee80211, &bytes)
        .expect("EAPOL EtherType is preserved as Raw until the typed decoder exists");
    let llc = packet
        .layer::<LlcSnap>()
        .expect("complete LLC/SNAP header should decode");
    let raw = packet
        .layer::<Raw>()
        .expect("truncated EAPOL payload should remain inspectable as Raw");

    assert_eq!(llc.ethertype_value(), 0x888e);
    assert_eq!(raw.as_bytes(), &[0x02, 0x03, 0x00, 0x05, 0x01]);
    assert_eq!(
        packet.compile().unwrap().as_bytes(),
        bytes.as_slice(),
        "Raw EAPOL boundary must preserve original bytes"
    );
}

/// Every malformed ARP vector must decode to a fully structured
/// `CrafterError::BufferTooShort`, carrying the `context` that names the failing
/// stage (`arp header` for a short fixed header, `arp addresses` for a truncated
/// address field) plus `required > available` so the expected and available
/// lengths are both observable. Decoding must never panic.
///
/// The cases are driven entirely off the malformed corpus so no fixture bytes
/// are duplicated. The required-dimension guard keeps the row set from silently
/// narrowing below the truncation points the step calls out: the short fixed
/// header and partial sender/target hardware/protocol addresses.
#[test]
fn malformed_arp_corpus_errors_carry_structured_fields() {
    let cases = malformed_cases();
    let arp_cases = cases
        .iter()
        .filter(|case| is_arp_malformed_case(case))
        .collect::<Vec<_>>();
    assert!(
        !arp_cases.is_empty(),
        "malformed corpus must carry ARP vectors"
    );

    // Each truncation point the step requires must be represented by name so
    // this coverage never silently narrows.
    let arp_required_rows = [
        "short-arp-header",
        "truncated-arp-sender-hardware-address",
        "truncated-arp-sender-protocol-address",
        "truncated-arp-target-hardware-address",
        "truncated-arp-target-protocol-address",
    ];
    let covered = arp_cases
        .iter()
        .map(|case| case.name)
        .collect::<std::collections::HashSet<_>>();
    for row in arp_required_rows {
        assert!(
            covered.contains(row),
            "malformed ARP corpus missing structured-field coverage for {row}"
        );
    }

    for case in arp_cases {
        let Err(error) = decode_malformed_case(case) else {
            panic!(
                "malformed ARP corpus case {} unexpectedly decoded",
                case.name
            );
        };
        // The variant/context match is shared with the corpus runner; here we
        // additionally assert the structured payload.
        assert_error_matches(case, error.clone());
        let ExpectedOutcome::Error(expected_error) = case.expected_outcome else {
            panic!(
                "malformed ARP case {} expected structured error outcome",
                case.name
            );
        };
        match error {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(
                    context, expected_error.context_or_field,
                    "malformed ARP case {} carried an unexpected buffer context",
                    case.name
                );
                assert!(
                    required > available,
                    "malformed ARP case {} BufferTooShort must require more ({required}) \
                     than is available ({available})",
                    case.name
                );
            }
            other => panic!(
                "malformed ARP case {} returned an unexpected error {other:?}",
                case.name
            ),
        }
    }
}

#[test]
fn malformed_ipv6_corpus_errors_carry_structured_fields() {
    let cases = malformed_cases();
    let ipv6_cases = cases
        .iter()
        .filter(|case| is_ipv6_malformed_case(case))
        .collect::<Vec<_>>();
    assert!(
        !ipv6_cases.is_empty(),
        "malformed corpus must carry IPv6 vectors"
    );

    let ipv6_required_families = [
        "short ipv6 base",
        "bad ipv6 version",
        "ipv6 payload length mismatch",
        "truncated ipv6 hop-by-hop options header",
        "truncated ipv6 destination options header",
        "ipv6 option length overrun",
        "ipv6 padn option overrun",
        "ipv6 declared options header overrun",
        "truncated ipv6 routing header",
        "truncated ipv6 fragment header",
        "malformed ipv6 segment routing header",
        "truncated ipv6 unknown extension header",
        "udp length overrun",
        "short icmpv6 header",
    ];
    let covered = ipv6_cases
        .iter()
        .filter_map(|case| malformed_family(case.name))
        .collect::<std::collections::HashSet<_>>();
    for family in ipv6_required_families {
        assert!(
            covered.contains(family),
            "malformed IPv6 corpus missing structured-field coverage for {family}"
        );
    }

    for case in ipv6_cases {
        let Err(error) = decode_malformed_case(case) else {
            panic!(
                "malformed IPv6 corpus case {} unexpectedly decoded",
                case.name
            );
        };
        assert_error_matches(case, error.clone());
        let ExpectedOutcome::Error(expected_error) = case.expected_outcome else {
            panic!(
                "malformed IPv6 case {} expected structured error outcome",
                case.name
            );
        };
        match error {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(
                    context, expected_error.context_or_field,
                    "malformed IPv6 case {} carried an unexpected buffer context",
                    case.name
                );
                assert!(
                    required > available,
                    "malformed IPv6 case {} BufferTooShort must require more ({required}) \
                     than is available ({available})",
                    case.name
                );
            }
            CrafterError::InvalidFieldValue { field, reason } => {
                assert_eq!(
                    field, expected_error.context_or_field,
                    "malformed IPv6 case {} carried an unexpected invalid field",
                    case.name
                );
                assert!(
                    !reason.is_empty(),
                    "malformed IPv6 case {} InvalidFieldValue must carry a non-empty reason",
                    case.name
                );
            }
            other => panic!(
                "malformed IPv6 case {} returned an unexpected error {other:?}",
                case.name
            ),
        }
    }
}

#[test]
fn malformed_ipv6_options_corpus_errors_carry_structured_fields() {
    let cases = malformed_cases();
    let ipv6_options_cases = cases
        .iter()
        .filter(|case| is_ipv6_options_malformed_case(case))
        .collect::<Vec<_>>();
    assert!(
        !ipv6_options_cases.is_empty(),
        "malformed corpus must carry IPv6 option-header vectors"
    );

    let ipv6_options_required_families = [
        "truncated ipv6 hop-by-hop options header",
        "truncated ipv6 destination options header",
        "ipv6 option length overrun",
        "ipv6 padn option overrun",
        "ipv6 declared options header overrun",
    ];
    let covered = ipv6_options_cases
        .iter()
        .filter_map(|case| malformed_family(case.name))
        .collect::<std::collections::HashSet<_>>();
    for family in ipv6_options_required_families {
        assert!(
            covered.contains(family),
            "malformed IPv6 options corpus missing structured-field coverage for {family}"
        );
    }

    for case in ipv6_options_cases {
        let Err(error) = decode_malformed_case(case) else {
            panic!(
                "malformed IPv6 options corpus case {} unexpectedly decoded",
                case.name
            );
        };
        assert_error_matches(case, error.clone());
        let ExpectedOutcome::Error(expected_error) = case.expected_outcome else {
            panic!(
                "malformed IPv6 options case {} expected structured error outcome",
                case.name
            );
        };
        match error {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(
                    context, expected_error.context_or_field,
                    "malformed IPv6 options case {} carried an unexpected buffer context",
                    case.name
                );
                assert!(
                    required > available,
                    "malformed IPv6 options case {} BufferTooShort must require more \
                     ({required}) than is available ({available})",
                    case.name
                );
            }
            CrafterError::InvalidFieldValue { field, reason } => {
                assert_eq!(
                    field, expected_error.context_or_field,
                    "malformed IPv6 options case {} carried an unexpected invalid field",
                    case.name
                );
                assert!(
                    !reason.is_empty(),
                    "malformed IPv6 options case {} InvalidFieldValue must carry a \
                     non-empty reason",
                    case.name
                );
            }
            other => panic!(
                "malformed IPv6 options case {} returned an unexpected error {other:?}",
                case.name
            ),
        }
    }
}

#[test]
fn malformed_corpus_decoder_paths_do_not_panic() {
    let cases = malformed_cases();
    assert!(!cases.is_empty(), "malformed corpus must not be empty");

    for expected in [
        DecodeTarget::Ethernet,
        DecodeTarget::Dot11,
        DecodeTarget::Radiotap,
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
        DecodeTarget::Dot11,
        DecodeTarget::Radiotap,
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
        match (
            decode_malformed_case(case),
            expects_decoded_udp_option_status(case),
        ) {
            (Err(error), false) => assert_error_matches(case, error),
            (Ok(()), true) => {
                let packet = decode_malformed_packet_case(case).unwrap_or_else(|err| {
                    panic!(
                        "malformed corpus case {} should decode for status inspection: {err}",
                        case.name
                    )
                });
                assert_udp_option_status_matches(case, packet);
            }
            (Ok(()), false) => {
                panic!("malformed corpus case {} unexpectedly decoded", case.name);
            }
            (Err(error), true) => {
                panic!(
                    "malformed corpus case {} expected UDP option status, got structured error {error:?}",
                    case.name
                );
            }
        }
    }
}

#[test]
fn segment_routing_malformed_decode_entrypoints_report_structured_errors() {
    let segment = Ipv6Addr::new(0x2001, 0x0db8, 0x0039, 0, 0, 0, 0, 0x0003).octets();

    let mut declared_too_short = vec![17, 1, 4, 0, 0, 0, 0, 0];
    declared_too_short.extend_from_slice(&[0xaa; 8]);

    let mut tlv_overrun = vec![17, 4, 4, 0, 0, 0, 0, 0];
    tlv_overrun.extend_from_slice(&segment);
    tlv_overrun.extend_from_slice(&[
        0xee, 0x0f, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a,
    ]);

    let cases = [
        (
            "segment-routing-short-header",
            vec![17, 0, 4, 0],
            ExpectedError {
                kind: ExpectedErrorKind::BufferTooShort,
                context_or_field: "ipv6 routing header",
            },
        ),
        (
            "segment-routing-last-entry-overrun",
            vec![17, 0, 4, 0, 1, 0, 0, 0],
            ExpectedError {
                kind: ExpectedErrorKind::InvalidFieldValue,
                context_or_field: "ipv6.segment.header_ext_len",
            },
        ),
        (
            "segment-routing-declared-length-shorter-than-fields",
            declared_too_short,
            ExpectedError {
                kind: ExpectedErrorKind::InvalidFieldValue,
                context_or_field: "ipv6.segment.header_ext_len",
            },
        ),
        (
            "segment-routing-tlv-length-overrun",
            tlv_overrun,
            ExpectedError {
                kind: ExpectedErrorKind::InvalidFieldValue,
                context_or_field: "ipv6.segment.tlv",
            },
        ),
    ];

    for (name, route_payload, expected_error) in cases {
        let ipv6_packet = segment_routing_malformed_ipv6_packet(&route_payload);
        let ethernet_frame = segment_routing_malformed_ethernet_frame(&ipv6_packet);
        let linux_sll_frame = segment_routing_malformed_linux_sll_frame(&ipv6_packet);

        let expected = MalformedCase {
            name,
            target: DecodeTarget::Ipv6,
            expected_outcome: ExpectedOutcome::Error(expected_error),
            bytes: Vec::new(),
        };

        for (target, bytes) in [
            (PacketDecodeTarget::L3(NetworkLayer::Ipv6), ipv6_packet),
            (PacketDecodeTarget::Link(LinkType::Ethernet), ethernet_frame),
            (
                PacketDecodeTarget::Link(LinkType::LinuxSll),
                linux_sll_frame,
            ),
        ] {
            let error = decode_packet(target, &bytes)
                .err()
                .unwrap_or_else(|| panic!("{name} unexpectedly decoded through {target:?}"));
            assert_error_matches(&expected, error);
        }
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
                / Icmpv4::echo_request().identifier(7).sequence_number(9)
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
    fn malformed_random_decode_inputs_never_panic(
        bytes in prop::collection::vec(any::<u8>(), 0..512),
        ipv4_like_bytes in ipv4_like_bytes_strategy(),
    ) {
        exercise_packet_decode(PacketDecodeTarget::Link(LinkType::Ethernet), &bytes);
        exercise_packet_decode(PacketDecodeTarget::Link(LinkType::Ieee80211), &bytes);
        exercise_packet_decode(PacketDecodeTarget::Link(LinkType::Radiotap), &bytes);
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

        exercise_ipv4_like_decode(&ipv4_like_bytes);
    }

    #[test]
    fn ipv6_random_decode_inputs_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        exercise_packet_decode(PacketDecodeTarget::L3(NetworkLayer::Ipv6), &bytes);
    }

    #[test]
    fn ipv6_unknown_next_header_raw_roundtrip_property(
        next_header in prop::sample::select(vec![
            IPPROTO_IPV6_AH,
            IPPROTO_IPV6_ESP,
            IPPROTO_IPV6_MOBILITY,
            IPPROTO_IPV6_HIP,
            IPPROTO_IPV6_SHIM6,
            IPPROTO_IPV6_EXPERIMENTAL_1,
            IPPROTO_IPV6_EXPERIMENTAL_2,
            255,
        ]),
        traffic_class in any::<u8>(),
        flow_label in 0u32..=0x000f_ffff,
        hop_limit in any::<u8>(),
        payload in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let packet = ipv6_resilience_base(hop_limit)
            .traffic_class(traffic_class)
            .flow_label(flow_label)
            .next_header(next_header)
            / Raw::from(payload);
        let bytes = packet
            .compile()
            .expect("generated IPv6 unknown-next-header packet should compile");

        exercise_packet_decode(PacketDecodeTarget::L3(NetworkLayer::Ipv6), bytes.as_bytes());
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())
            .expect("generated IPv6 unknown-next-header packet should decode");
        let compiled = decoded
            .compile()
            .expect("decoded IPv6 unknown-next-header packet should compile");
        prop_assert_eq!(compiled.as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn ipv6_extension_chain_roundtrip_property(
        traffic_class in any::<u8>(),
        flow_label in 0u32..=0x000f_ffff,
        hop_limit in any::<u8>(),
        hop_option_seed in any::<u8>(),
        hop_option_len in 0usize..=8,
        destination_option_seed in any::<u8>(),
        destination_option_len in 0usize..=8,
        routing_type in prop::sample::select(vec![
            IPV6_ROUTING_TYPE_RH0,
            IPV6_ROUTING_TYPE_NIMROD,
            IPV6_ROUTING_TYPE_EXPERIMENTAL_1,
            IPV6_ROUTING_TYPE_EXPERIMENTAL_2,
        ]),
        routing_data_seed in any::<u8>(),
        routing_data_len in 0usize..=16,
        fragment_offset in 0u16..=16,
        more_fragments in any::<bool>(),
        identification in any::<u32>(),
        payload in prop::collection::vec(any::<u8>(), 0..96),
    ) {
        let generated_bytes = |seed: u8, len: usize| -> Vec<u8> {
            (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
        };
        let hop_option_data = generated_bytes(hop_option_seed, hop_option_len);
        let destination_option_data =
            generated_bytes(destination_option_seed, destination_option_len);
        let routing_data = generated_bytes(routing_data_seed, routing_data_len);

        let packet = ipv6_resilience_base(hop_limit)
            .traffic_class(traffic_class)
            .flow_label(flow_label)
            / Ipv6HopByHopOptionsHeader::new()
                .option(Ipv6Option::pad1())
                .option(
                    Ipv6Option::generic(0x1e, hop_option_data)
                        .expect("bounded Hop-by-Hop option should build"),
                )
            / Ipv6DestinationOptionsHeader::new().option(
                Ipv6Option::generic(0x3e, destination_option_data)
                    .expect("bounded Destination option should build"),
            )
            / Ipv6RoutingHeader::new()
                .routing_type(routing_type)
                .segments_left(0)
                .type_data(routing_data)
            / Ipv6FragmentHeader::new()
                .next_header(IPPROTO_IPV6_EXPERIMENTAL_1)
                .fragment_offset(fragment_offset)
                .more_fragments(more_fragments)
                .identification(identification)
            / Raw::from(payload);

        let bytes = packet
            .compile()
            .expect("generated IPv6 extension chain should compile");
        exercise_packet_decode(PacketDecodeTarget::L3(NetworkLayer::Ipv6), bytes.as_bytes());
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())
            .expect("generated IPv6 extension chain should decode");
        let compiled = decoded
            .compile()
            .expect("decoded IPv6 extension chain should compile");
        prop_assert_eq!(compiled.as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn dhcp_option_scan_decode_encode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        // The raw segment scanner must never panic on arbitrary input across
        // every option area.
        for area in [DhcpOptionArea::Options, DhcpOptionArea::File, DhcpOptionArea::Sname] {
            let _ = scan_dhcp_option_segments(area, &bytes);
        }

        // The logical decoder must never panic, and any options it accepts must
        // re-encode and expose their raw payload without panic.
        if let Ok(options) = DhcpOption::decode_all(&bytes) {
            for option in &options {
                let _ = option.encode();
                let _ = option.payload();
            }
        }
    }

    /// Arbitrary bytes carried through the real `ipv4 / udp / dhcp` decode
    /// boundary must never panic. Unlike [`malformed_random_decode_inputs_never_panic`],
    /// which feeds raw bytes into the L3 entrypoint (where they almost never
    /// satisfy the conservative DHCP dispatch gate), this builds a well-formed
    /// IPv4/UDP frame on the standard DHCP client/server port pair with a valid
    /// BOOTP fixed header and magic cookie, then fuzzes only the option region.
    /// That guarantees the UDP-port-pair + magic-cookie registry gate fires and
    /// the full stack actually routes into the DHCP option decoder, so the
    /// boundary the DHCP live oracle relies on (`decode_from_l3(Ipv4, ..)` ->
    /// UDP 68->67 -> DHCP) is exercised over arbitrary option bytes. The decoder
    /// must surface a structured error or preserve the bytes as raw `Generic`
    /// segments, never panic; whenever it does decode, `summary`/`show`/`compile`
    /// must also stay panic-free.
    #[test]
    fn ipv4_udp_dhcp_boundary_decode_never_panics(
        option_bytes in prop::collection::vec(any::<u8>(), 0..200),
    ) {
        use crafter::core::DhcpMalformed;

        // A valid BOOTP fixed header + magic cookie keeps the registry gate
        // (`is_dhcp_port_pair` && `looks_like_dhcp_payload`) satisfied so the
        // arbitrary option-region bytes reach the DHCP decoder through the real
        // boundary rather than being dropped as non-DHCP UDP traffic.
        let dhcp = DhcpMalformed::from_valid(
            Dhcp::discover(dhcp_client_mac()).transaction_id(0x0102_0304),
        )
        .raw_options(option_bytes);

        let frame = Ipv4::with_addresses(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST)
            / Udp::new()
                .source_port(DHCP_CLIENT_PORT)
                .destination_port(DHCP_SERVER_PORT)
            / dhcp;

        // The fuzzed options never make the fixed header invalid, so the frame
        // always compiles to wire bytes carrying a real DHCP magic cookie.
        let bytes = frame
            .compile()
            .expect("ipv4/udp/dhcp boundary frame should compile");

        // Decoding the whole frame from the IPv4 root must never panic. The DHCP
        // option region may be malformed, so the result is either a structured
        // error or a successful decode that preserves the bytes; both are
        // acceptable as long as nothing panics and the decoded model stays
        // inspectable.
        exercise_packet_decode(PacketDecodeTarget::L3(NetworkLayer::Ipv4), bytes.as_bytes());
    }

    /// Bounded ARP packets with valid length fields and matching address
    /// vectors must round-trip byte-exact through the Ethernet link decode
    /// boundary. The ARP body size is length-derived (HLN + PLN), so the address
    /// vectors are generated to exactly match the sampled lengths, and unusual
    /// hardware/protocol types, unknown numeric opcodes (including reserved and
    /// experimental code points), and nonstandard zero/short/long address lengths
    /// are all exercised. The four address fields are set through the raw byte
    /// setters so no auto-fill rewrites the explicit length fields, and the whole
    /// frame is compiled, decoded, and recompiled with [`assert_roundtrip`] which
    /// asserts the bytes are preserved. Lengths are kept in 0..=12 so the body
    /// stays small and CI stays fast.
    #[test]
    fn arp_roundtrip_variable_length_property(
        hardware_type in any::<u16>(),
        protocol_type in any::<u16>(),
        opcode in any::<u16>(),
        hardware_len in 0u8..=12,
        protocol_len in 0u8..=12,
        sender_hardware_seed in any::<u8>(),
        sender_protocol_seed in any::<u8>(),
        target_hardware_seed in any::<u8>(),
        target_protocol_seed in any::<u8>(),
    ) {
        // Matching address vectors: each field is exactly as long as the length
        // field declares, with deterministic content seeded per field so the
        // bytes are distinguishable but bounded.
        let address = |len: u8, seed: u8| -> Vec<u8> {
            (0..len).map(|i| seed.wrapping_add(i)).collect()
        };

        let arp = Arp::new()
            .hardware_type(hardware_type)
            .protocol_type(protocol_type)
            .hardware_len(hardware_len)
            .protocol_len(protocol_len)
            .opcode(opcode)
            .sender_hardware_bytes(address(hardware_len, sender_hardware_seed))
            .sender_protocol_bytes(address(protocol_len, sender_protocol_seed))
            .target_hardware_bytes(address(hardware_len, target_hardware_seed))
            .target_protocol_bytes(address(protocol_len, target_protocol_seed));

        let packet = Ethernet::new() / arp;
        assert_roundtrip(PacketDecodeTarget::Link(LinkType::Ethernet), packet);
    }

    /// The same bounded ARP packets, but with a small block of trailing bytes
    /// appended after the complete ARP body. The trailing bytes must remain
    /// observable as a raw payload and survive the compile/decode/compile round
    /// trip unchanged. The trailing block is non-empty (so a `Raw` layer is
    /// always produced) and bounded to keep CI fast.
    #[test]
    fn arp_roundtrip_trailing_raw_property(
        hardware_type in any::<u16>(),
        protocol_type in any::<u16>(),
        opcode in any::<u16>(),
        hardware_len in 0u8..=12,
        protocol_len in 0u8..=12,
        sender_hardware_seed in any::<u8>(),
        sender_protocol_seed in any::<u8>(),
        target_hardware_seed in any::<u8>(),
        target_protocol_seed in any::<u8>(),
        trailing in prop::collection::vec(any::<u8>(), 1..16),
    ) {
        let address = |len: u8, seed: u8| -> Vec<u8> {
            (0..len).map(|i| seed.wrapping_add(i)).collect()
        };

        let arp = Arp::new()
            .hardware_type(hardware_type)
            .protocol_type(protocol_type)
            .hardware_len(hardware_len)
            .protocol_len(protocol_len)
            .opcode(opcode)
            .sender_hardware_bytes(address(hardware_len, sender_hardware_seed))
            .sender_protocol_bytes(address(protocol_len, sender_protocol_seed))
            .target_hardware_bytes(address(hardware_len, target_hardware_seed))
            .target_protocol_bytes(address(protocol_len, target_protocol_seed));

        let packet = Ethernet::new() / arp / Raw::from(trailing.clone());

        // Decode the compiled frame and confirm the trailing bytes survive as a
        // raw payload before asserting the full byte-exact round trip.
        let bytes = packet.compile().expect("generated ARP frame should compile");
        let decoded = Packet::decode_from_link(LinkType::Ethernet, bytes.as_bytes())
            .expect("generated ARP frame should decode");
        let recompiled = decoded.compile().expect("decoded ARP frame should compile");
        prop_assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
        // The trailing bytes must be the final bytes on the wire, unchanged.
        prop_assert!(
            bytes.as_bytes().ends_with(&trailing),
            "trailing raw payload must be observable on the wire"
        );
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
    fn roundtrip_ipv4_header_property(
        src_host in 1u8..=254,
        dst_host in 1u8..=254,
        ds_field in prop::sample::select(&[0x00, 0x03, 0x2e, 0xb8, 0xff]),
        flags in prop::sample::select(&[0, 1, 2, 3, 4, 5, 7]),
        fragment_offset in prop::sample::select(&[0, 1, 8, 8191]),
        option_selector in 0u8..5,
        payload_len in prop::sample::select(&[0usize, 1, 7, 8, 31, 128, 512, 1024]),
        payload_seed in any::<u8>(),
    ) {
        let options = ipv4_options_for_selector(option_selector);
        let option_bytes = encoded_ipv4_options(&options);
        let payload = deterministic_payload(payload_len, payload_seed);
        let ipv4 = ipv4_with_options(
            Ipv4::with_addresses(
                Ipv4Addr::new(192, 0, 2, src_host),
                Ipv4Addr::new(198, 51, 100, dst_host),
            )
            .ds_field(ds_field)
            .flags(flags)
            .fragment_offset(fragment_offset)
            .ipv4_protocol(Ipv4Protocol::Experimental1),
            &options,
        );
        let packet = ipv4 / Raw::from(payload.clone());

        let bytes = packet
            .compile()
            .expect("generated IPv4 packet should compile");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
            .expect("generated IPv4 packet should decode");
        let compiled = decoded
            .compile()
            .expect("decoded IPv4 packet should compile");
        prop_assert_eq!(compiled.as_bytes(), bytes.as_bytes());

        let decoded_ipv4 = decoded
            .layer::<Ipv4>()
            .expect("decoded packet should contain an IPv4 layer");
        prop_assert_eq!(decoded_ipv4.ds_field_value(), ds_field);
        prop_assert_eq!(decoded_ipv4.flags_value(), flags);
        prop_assert_eq!(decoded_ipv4.fragment_offset_value(), fragment_offset);
        prop_assert_eq!(decoded_ipv4.header_len(), 20 + ((option_bytes.len() + 3) & !3));
        prop_assert!(decoded_ipv4.option_bytes().starts_with(&option_bytes));
        prop_assert!(decoded_ipv4.option_bytes()[option_bytes.len()..]
            .iter()
            .all(|byte| *byte == 0));

        if !options.is_empty() {
            let parsed_options = decoded_ipv4
                .parsed_options()
                .expect("selected IPv4 options should decode");
            prop_assert_eq!(&parsed_options[..options.len()], options.as_slice());
        }

        if payload.is_empty() {
            prop_assert!(
                decoded.layer::<Raw>().is_none(),
                "empty IPv4 payload should not synthesize a Raw layer"
            );
        } else {
            let decoded_raw = decoded
                .layer::<Raw>()
                .expect("decoded packet should preserve the raw payload");
            prop_assert_eq!(decoded_raw.as_bytes(), payload.as_slice());
        }
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
                .ipv4_protocol(Ipv4Protocol::Tcp)
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

/// Malformed / truncation corpus for the ICMPv6 message families and the NDP
/// option / MLD record parsers (RFC 4861, RFC 3810/9777, RFC 4443).
///
/// `CLAUDE.md` requires that malformed buffers surface as structured
/// [`CrafterError`]s carrying `context`/`required`/`available` (or a stable
/// `field`) and that truncation never panics. The new ICMPv6 risk surface — the
/// NDP option TLV framework (`v6/message/ndp_option.rs`), the MLDv2 records
/// (`v6/message/mld.rs`), and the `type → typed-body` decode dispatch
/// (`v6/decode.rs`) — already returns a structured error or falls back to a
/// `Raw` body on bad input; this module consolidates a corpus that proves it.
///
/// Two complementary surfaces are exercised:
///
/// - The NDP option framework decoders ([`NdpOption::decode_one`] /
///   [`NdpOptions::decode`]) are public, so a zero-length option, an option that
///   overruns the buffer, and a too-short header are asserted to return the exact
///   structured [`CrafterError`] with its `context` / `required` / `available`
///   (for [`CrafterError::BufferTooShort`]) or `field` / `reason` (for
///   [`CrafterError::InvalidFieldValue`]).
/// - The whole-message decoders (NDP messages, MLDv1/MLDv2) are reached through
///   the public [`Packet::decode_from_l3`] IPv6 path. Per the decode dispatch in
///   `v6/decode.rs`, a malformed *known-type* body is swallowed into a `Raw`
///   fallback (so nothing is dropped and decoding never panics) rather than
///   surfacing the per-message error to the caller. These cases therefore assert
///   the clean header-plus-`Raw` fallback and a byte-exact round trip, and — most
///   importantly — that no input panics (the test harness fails on panic).
mod icmpv6_malformed_corpus {
    use core::net::Ipv6Addr;

    use crafter::core::{
        CrafterError, Icmpv6, Ipv6, MacAddr, MulticastAddressRecord, MulticastRecordType,
        NdpOption, NdpOptions, NetworkLayer, Packet, Raw, ICMPV6_MLDV2_REPORT,
        ICMPV6_MULTICAST_LISTENER_QUERY, ICMPV6_NEIGHBOR_ADVERTISEMENT,
    };

    /// A documentation-space source address (`2001:db8::/32`).
    fn src() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0x0010)
    }

    /// A documentation-space destination address (`2001:db8::/32`).
    fn dst() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 2, 0, 0, 0, 0, 0x0020)
    }

    /// A documentation target address being resolved/advertised.
    fn target() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0x00ff)
    }

    /// A documentation multicast group (`ff05::fb`).
    fn group() -> Ipv6Addr {
        Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x00fb)
    }

    /// A documentation MAC (`02:00:5e:00:53:01`).
    fn doc_mac() -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01])
    }

    /// Compile a raw ICMPv6 message (an 8-byte fixed header followed by `body`)
    /// onto an IPv6 header, returning the full wire bytes. The checksum field is
    /// left zero — the decode path under test never validates it.
    fn ipv6_icmpv6_wire(icmp_type: u8, code: u8, rest_of_header: [u8; 4], body: &[u8]) -> Vec<u8> {
        let mut icmpv6 = Vec::with_capacity(8 + body.len());
        icmpv6.push(icmp_type);
        icmpv6.push(code);
        icmpv6.extend_from_slice(&[0, 0]); // checksum (not validated on decode)
        icmpv6.extend_from_slice(&rest_of_header);
        icmpv6.extend_from_slice(body);

        // An IPv6 base header (next-header 58 = ICMPv6) carrying the ICMPv6 bytes.
        let mut ip = Vec::with_capacity(40 + icmpv6.len());
        ip.push(0x60); // version 6, traffic class high nibble
        ip.extend_from_slice(&[0x00, 0x00, 0x00]); // traffic class / flow label
        ip.extend_from_slice(&(icmpv6.len() as u16).to_be_bytes()); // payload length
        ip.push(58); // next header = ICMPv6
        ip.push(255); // hop limit
        ip.extend_from_slice(&src().octets());
        ip.extend_from_slice(&dst().octets());
        ip.extend_from_slice(&icmpv6);
        ip
    }

    /// Decode IPv6 wire bytes through the public registry path. Never panics; the
    /// harness fails the test if the decoder under test does.
    fn decode_ipv6(bytes: &[u8]) -> crafter::core::Result<Packet> {
        Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)
    }

    /// Decode the bytes and assert the message fell back to the `Icmpv6` header
    /// plus a single `Raw` body whose bytes are exactly the original message body
    /// (nothing dropped), and that the decode round-trips byte-for-byte. This is
    /// the contract `v6/decode.rs` documents for a malformed *known-type* body.
    fn assert_header_plus_raw_roundtrip(icmp_type: u8, body: &[u8]) {
        let wire = ipv6_icmpv6_wire(icmp_type, 0, [0, 0, 0, 0], body);
        let decoded =
            decode_ipv6(&wire).expect("malformed known-type body still decodes to a stack");

        let icmpv6 = decoded
            .layer::<Icmpv6>()
            .expect("ICMPv6 header decodes for a malformed body");
        assert_eq!(
            icmpv6.icmp_type_value(),
            icmp_type,
            "ICMPv6 type must survive a malformed body"
        );

        let raw = decoded
            .layer::<Raw>()
            .expect("a malformed known-type body is preserved as Raw");
        assert_eq!(
            raw.as_bytes(),
            body,
            "the Raw fallback must preserve the message body verbatim"
        );

        let recompiled = decoded
            .compile()
            .expect("the header-plus-Raw fallback recompiles");
        assert_eq!(
            recompiled.as_bytes(),
            wire,
            "a header-plus-Raw fallback must round-trip byte-for-byte"
        );
    }

    // --- NDP option framework: structured errors with context/required/available ---

    /// An NDP option whose `Length` field is `0` is invalid (RFC 4861 sec 4.6:
    /// "The value 0 is invalid"). The framework decoder must reject it with a
    /// structured [`CrafterError::InvalidFieldValue`] carrying the stable
    /// `ndp.option.length` field and a non-empty reason — never a panic, and
    /// never an infinite loop (a zero length would otherwise stall the walk).
    #[test]
    fn ndp_option_zero_length_is_structured_error() {
        // Type 1 (Source Link-Layer Address), Length 0, then six value bytes.
        let bytes = [1u8, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        match NdpOption::decode_one(&bytes) {
            Err(CrafterError::InvalidFieldValue { field, reason }) => {
                assert_eq!(field, "ndp.option.length");
                assert!(!reason.is_empty(), "zero-length reason must be populated");
            }
            other => panic!("zero-length NDP option expected InvalidFieldValue, got {other:?}"),
        }

        // The same vector through the whole-area walk surfaces the same error
        // rather than looping forever on a zero-length option.
        match NdpOptions::decode(&bytes) {
            Err(CrafterError::InvalidFieldValue { field, .. }) => {
                assert_eq!(field, "ndp.option.length");
            }
            other => {
                panic!("zero-length NDP option area expected InvalidFieldValue, got {other:?}")
            }
        }
    }

    /// An NDP option whose declared `Length` (in 8-octet units) runs past the end
    /// of the buffer must surface a structured [`CrafterError::BufferTooShort`]
    /// whose `context` is `ndp.option.value` and whose `required > available`
    /// (the declared total exceeds what is present) — never a panic.
    #[test]
    fn ndp_option_length_overrun_is_structured_error() {
        // Type 3 (Prefix Information), Length 4 (declares 32 octets), but only a
        // 10-byte buffer is present.
        let bytes = [3u8, 4, 0, 0, 0, 0, 0, 0, 0, 0];

        for result in [
            NdpOption::decode_one(&bytes).map(|(_, n)| n),
            NdpOptions::decode(&bytes).map(|_| 0),
        ] {
            match result {
                Err(CrafterError::BufferTooShort {
                    context,
                    required,
                    available,
                }) => {
                    assert_eq!(context, "ndp.option.value");
                    assert_eq!(required, 32, "Length 4 declares 32 octets");
                    assert_eq!(available, bytes.len());
                    assert!(
                        required > available,
                        "an overrun must require more ({required}) than is available ({available})"
                    );
                }
                other => panic!("overrunning NDP option expected BufferTooShort, got {other:?}"),
            }
        }
    }

    /// An NDP option area that ends mid-header (a single trailing byte, not the
    /// two-byte Type/Length header) must surface a structured
    /// [`CrafterError::BufferTooShort`] with the `ndp.option.header` context and
    /// `required > available` — never a panic.
    #[test]
    fn ndp_option_truncated_header_is_structured_error() {
        let bytes = [1u8]; // a lone type byte, no length byte

        match NdpOption::decode_one(&bytes) {
            Err(CrafterError::BufferTooShort {
                context,
                required,
                available,
            }) => {
                assert_eq!(context, "ndp.option.header");
                assert_eq!(required, 2);
                assert_eq!(available, 1);
                assert!(required > available);
            }
            other => panic!("truncated NDP option header expected BufferTooShort, got {other:?}"),
        }
    }

    /// An unknown NDP option type is preserved verbatim as
    /// [`NdpOption::Unknown`] and round-trips through encode/decode byte-for-byte
    /// (the spec's unknown-option preservation rule).
    #[test]
    fn unknown_ndp_option_round_trips_verbatim() {
        // Type 253 is unassigned in the IANA NDP option registry; Length 1 means
        // the whole option is one 8-octet unit (six value bytes).
        let wire = [253u8, 1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        let (option, consumed) = NdpOption::decode_one(&wire).expect("unknown option decodes");
        assert_eq!(consumed, 8);
        assert!(
            matches!(option, NdpOption::Unknown { ty: 253, .. }),
            "an unassigned NDP option type is preserved as Unknown, got {option:?}"
        );
        // Re-encoding reproduces the original bytes exactly.
        assert_eq!(
            option.encode().expect("unknown option re-encodes"),
            wire,
            "an unknown NDP option must round-trip verbatim"
        );

        // The same holds across the whole-area walk: a known option followed by an
        // unknown option preserves order and both round-trip.
        let area = NdpOptions::new()
            .push(NdpOption::source_link_layer_address(doc_mac()))
            .push(NdpOption::unknown(
                253,
                vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            ));
        let encoded = area.encode().expect("area encodes");
        let decoded = NdpOptions::decode(&encoded).expect("area decodes");
        assert_eq!(
            decoded.encode().expect("decoded area re-encodes"),
            encoded,
            "an option area with an unknown option must round-trip verbatim"
        );
        assert!(
            matches!(decoded.options()[1], NdpOption::Unknown { ty: 253, .. }),
            "the unknown option keeps its place and type in the ordered list"
        );
    }

    // --- Whole-message decode: malformed bodies fall back to Raw, never panic ---

    /// A Router Advertisement truncated mid-option (a valid two-timer-word body
    /// followed by an NDP option whose declared length overruns the remaining
    /// bytes) must not panic. The decode dispatch swallows the per-option error
    /// and preserves the whole body as `Raw`, round-tripping byte-for-byte.
    #[test]
    fn router_advertisement_truncated_mid_option_falls_back_to_raw() {
        // RA body = Reachable Time(4) + Retrans Timer(4) + option area. The option
        // is type 3 (Prefix Information) declaring Length 4 (32 octets) but only a
        // few option bytes follow — an overrun the option walk rejects.
        let mut body = vec![0u8; 8]; // the two timer words
        body.extend_from_slice(&[3, 4, 0, 0]); // PI option header + 2 value bytes, truncated
        assert_header_plus_raw_roundtrip(crafter::core::ICMPV6_ROUTER_ADVERTISEMENT, &body);
    }

    /// A Router Advertisement whose option area is present but not a multiple of
    /// 8 octets (so the final option's declared length cannot be satisfied) must
    /// not panic and must fall back to a header-plus-`Raw` round trip.
    #[test]
    fn router_advertisement_option_area_not_multiple_of_eight_falls_back_to_raw() {
        let mut body = vec![0u8; 8]; // the two timer words
                                     // A well-formed MTU option (type 5, length 1, 8 octets) followed by three
                                     // stray bytes that cannot form a complete option header+length.
        body.extend_from_slice(&[5, 1, 0, 0, 0, 0, 0x05, 0xdc]);
        body.extend_from_slice(&[1, 9, 0xff]); // type 1, length 9 (72 octets) -> overrun
        assert_header_plus_raw_roundtrip(crafter::core::ICMPV6_ROUTER_ADVERTISEMENT, &body);
    }

    /// A Router Advertisement whose entire option area is zero bytes long (only
    /// the two timer words, no options) decodes cleanly to a typed body — there is
    /// no option to be malformed — proving the empty-option-area boundary is
    /// handled without panic and that the typed body is produced. This is the
    /// positive control for the malformed RA cases above: it confirms those cases
    /// reject genuinely bad input rather than a decoder that always falls back to
    /// Raw.
    #[test]
    fn router_advertisement_zero_length_option_area_decodes_cleanly() {
        // The builder default carries no options, so the body is exactly the two
        // timer words — an empty option area.
        let packet = Ipv6::new().src(src()).dst(dst()).hlim(255) / Icmpv6::router_advertisement();
        let bytes = packet
            .compile()
            .expect("RA with empty option area compiles");

        let decoded = decode_ipv6(bytes.as_bytes()).expect("RA with empty option area decodes");
        assert!(
            decoded
                .layer::<crafter::core::RouterAdvertisement>()
                .is_some(),
            "an RA with an empty option area decodes to a typed body, not Raw"
        );
        assert_eq!(
            decoded.compile().expect("recompiles").as_bytes(),
            bytes.as_bytes(),
            "an RA with an empty option area round-trips byte-for-byte"
        );
    }

    /// A Neighbor Advertisement truncated before its 16-byte Target Address (the
    /// body is shorter than the required target) must not panic and must fall
    /// back to the header-plus-`Raw` round trip.
    #[test]
    fn neighbor_advertisement_truncated_before_target_falls_back_to_raw() {
        // Only two trailing bytes where a 16-byte Target Address is required.
        let body = [0xde, 0xad];
        assert_header_plus_raw_roundtrip(ICMPV6_NEIGHBOR_ADVERTISEMENT, &body);
    }

    /// A Neighbor Advertisement with a valid Target Address but an option area
    /// truncated mid-option must not panic and must fall back to Raw.
    #[test]
    fn neighbor_advertisement_truncated_mid_option_falls_back_to_raw() {
        let mut body = target().octets().to_vec(); // the 16-byte Target Address
                                                   // A Target Link-Layer Address option (type 2) declaring length 1 (8
                                                   // octets) but supplying only three of the six value bytes.
        body.extend_from_slice(&[2, 1, 0x02, 0x00, 0x5e]);
        assert_header_plus_raw_roundtrip(ICMPV6_NEIGHBOR_ADVERTISEMENT, &body);
    }

    /// An MLDv2 Report (type 143) whose first record declares a Number of Sources
    /// that exceeds the buffer must not panic and must fall back to the
    /// header-plus-`Raw` round trip (the record walk rejects the overrun and the
    /// dispatch preserves the body verbatim).
    #[test]
    fn mldv2_report_record_source_count_overrun_falls_back_to_raw() {
        // A single Multicast Address Record fixed header (Record Type 1, Aux Data
        // Len 0, Number of Sources 4) plus the 16-byte multicast address, but no
        // source addresses actually follow — an over-stated source count.
        let mut body = vec![1u8, 0]; // record type 1, aux data len 0
        body.extend_from_slice(&4u16.to_be_bytes()); // number of sources = 4 (none present)
        body.extend_from_slice(&group().octets()); // the 16-byte multicast address
        assert_header_plus_raw_roundtrip(ICMPV6_MLDV2_REPORT, &body);
    }

    /// An MLDv2 Report whose first record declares an Aux Data Len that overruns
    /// the buffer must not panic and must fall back to Raw.
    #[test]
    fn mldv2_report_record_aux_data_len_overrun_falls_back_to_raw() {
        // Record Type 1, Aux Data Len 8 words (32 octets), Number of Sources 0,
        // plus the multicast address, but no aux data follows.
        let mut body = vec![1u8, 8]; // record type 1, aux data len = 8 words
        body.extend_from_slice(&0u16.to_be_bytes()); // number of sources = 0
        body.extend_from_slice(&group().octets());
        assert_header_plus_raw_roundtrip(ICMPV6_MLDV2_REPORT, &body);
    }

    /// An MLDv2 Query (type 130 with a long body) whose Number of Sources exceeds
    /// the buffer must not panic and must fall back to Raw. (A long type-130 body
    /// is routed to the MLDv2-query decoder; an over-stated source count is
    /// rejected and the body is preserved.)
    #[test]
    fn mldv2_query_source_count_overrun_falls_back_to_raw() {
        // The 20-byte MLDv2 Query fixed body (16-byte multicast address + a
        // resv/S/QRV byte + QQIC byte + a 16-bit Number of Sources) with the
        // source count over-stated, plus extra bytes so the body is long enough to
        // be routed to the MLDv2-query decoder rather than the 16-byte MLDv1 path.
        let mut body = group().octets().to_vec(); // 16-byte multicast address
        body.push(0x02); // resv/S/QRV
        body.push(0x00); // QQIC
        body.extend_from_slice(&8u16.to_be_bytes()); // number of sources = 8 (none present)
        body.extend_from_slice(&[0u8; 4]); // four stray bytes (body >= 20 so MLDv2 path)
        assert_header_plus_raw_roundtrip(ICMPV6_MULTICAST_LISTENER_QUERY, &body);
    }

    /// An unknown ICMPv6 `type` (200, IANA-unassigned) with trailing bytes keeps
    /// the `Icmpv6` header and preserves the trailing bytes as a single `Raw`
    /// body, round-tripping byte-for-byte.
    #[test]
    fn unknown_icmpv6_type_with_trailing_bytes_round_trips() {
        const UNKNOWN_TYPE: u8 = 200;
        let body = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let wire = ipv6_icmpv6_wire(UNKNOWN_TYPE, 0, [0xde, 0xad, 0xbe, 0xef], &body);

        let decoded = decode_ipv6(&wire).expect("unknown ICMPv6 type decodes to a stack");
        let icmpv6 = decoded
            .layer::<Icmpv6>()
            .expect("ICMPv6 header decodes for an unknown type");
        assert_eq!(icmpv6.icmp_type_value(), UNKNOWN_TYPE);
        let raw = decoded
            .layer::<Raw>()
            .expect("an unknown ICMPv6 type body is preserved as Raw");
        assert_eq!(raw.as_bytes(), body);
        assert_eq!(
            decoded.compile().expect("recompiles").as_bytes(),
            wire,
            "an unknown ICMPv6 type round-trips byte-for-byte"
        );
    }

    /// A well-formed MLDv2 Report with two records (one carrying sources) still
    /// decodes to a typed body and round-trips — the positive control that proves
    /// the malformed cases above are rejecting genuinely bad input, not a decoder
    /// that always falls back to Raw.
    #[test]
    fn mldv2_report_with_records_decodes_and_round_trips() {
        let records = vec![
            MulticastAddressRecord::new(MulticastRecordType::ModeIsInclude, group())
                .source(src())
                .source(dst()),
            MulticastAddressRecord::new(MulticastRecordType::ChangeToExcludeMode, target()),
        ];
        let packet = Ipv6::new().src(src()).dst(dst()).hlim(255) / Icmpv6::mldv2_report(records);
        let bytes = packet.compile().expect("valid MLDv2 report compiles");
        let decoded = decode_ipv6(bytes.as_bytes()).expect("valid MLDv2 report decodes");
        assert!(
            decoded.layer::<crafter::core::Mldv2Report>().is_some(),
            "a well-formed MLDv2 report decodes to a typed body, not Raw"
        );
        assert_eq!(
            decoded.compile().expect("recompiles").as_bytes(),
            bytes.as_bytes(),
            "a well-formed MLDv2 report round-trips byte-for-byte"
        );
    }
}
