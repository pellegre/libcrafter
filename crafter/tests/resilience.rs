#[macro_use]
mod support;

use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::core::{
    decode_dns_name, scan_dhcp_option_segments, Arp, CrafterError, Dhcp, DhcpOption,
    DhcpOptionArea, Dns, Ethernet, Icmpv4, Icmpv6, Ipv4, Ipv4Option, Ipv4Protocol, Ipv6,
    Ipv6DestinationOptionsHeader, Ipv6FragmentHeader, Ipv6HopByHopOptionsHeader,
    Ipv6MobileRoutingHeader, Ipv6Option, Ipv6RoutingHeader, Ipv6SegmentRoutingHeader, LinkType,
    LinuxSll, MacAddr, NetworkLayer, NullLoopback, Packet, Raw, Tcp, TcpOption, Udp,
    UdpOptionStatus, UdpOptions, Vlan, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, DNS_PORT,
    IPPROTO_IPV6_DSTOPTS, IPPROTO_IPV6_EXPERIMENTAL_1, IPPROTO_IPV6_EXPERIMENTAL_2,
    IPPROTO_IPV6_FRAGMENT, IPPROTO_IPV6_HIP, IPPROTO_IPV6_HOPOPTS, IPPROTO_IPV6_MOBILITY,
    IPPROTO_IPV6_NO_NEXT, IPPROTO_IPV6_ROUTE, IPPROTO_IPV6_SHIM6, IPPROTO_UDP,
    IPV6_OPTION_HOME_ADDRESS, IPV6_OPTION_JUMBO_PAYLOAD, IPV6_OPTION_ROUTER_ALERT,
    IPV6_ROUTING_TYPE_EXPERIMENTAL_1, IPV6_ROUTING_TYPE_EXPERIMENTAL_2, IPV6_ROUTING_TYPE_MOBILE,
    IPV6_ROUTING_TYPE_NIMROD, IPV6_ROUTING_TYPE_RH0, TCP_FLAG_ACK, TCP_FLAG_PSH, TCP_FLAG_SYN,
};
use crafter::protocols::dhcp::{
    DHCP_FIXED_HEADER_LEN, DHCP_MAGIC_COOKIE, DHCP_MIN_LEN, DHCP_OPTION_END,
    DHCP_OPTION_MESSAGE_TYPE,
};
use crafter::wire::backend::pcap::PcapLinkType;
use crafter::wire::{IpDefrag, IpFragment, PacketRecord, WireError};
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

fn compile_dhcp_payload(dhcp: Dhcp) -> Vec<u8> {
    Packet::from_layer(dhcp)
        .compile()
        .expect("DHCP test frame should compile")
        .as_bytes()
        .to_vec()
}

fn dhcp_payload_with_options(options: impl AsRef<[u8]>) -> Vec<u8> {
    let mut bytes = vec![0u8; DHCP_MIN_LEN];
    bytes[0] = 1; // BOOTREQUEST
    bytes[1] = 1; // Ethernet
    bytes[2] = 6; // Ethernet MAC length
    bytes[DHCP_FIXED_HEADER_LEN..DHCP_MIN_LEN].copy_from_slice(&DHCP_MAGIC_COOKIE.to_be_bytes());
    bytes.extend_from_slice(options.as_ref());
    bytes
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
                / Raw::from_bytes([0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb, 0xcc, 0xdd]),
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
        // ESP (next-header 50) and AH (next-header 51) are no longer unknown next
        // headers: the built-in registry now decodes them to typed IPSec layers,
        // each with its own minimum-length contract (ESP needs the 8-octet
        // SPI/Seq header; AH needs the 12-octet fixed header). Their round-trips
        // are covered by the crate-internal ESP/AH registry tests.
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

#[test]
fn malformed_ipv6_jumbo_payload_option_summary_is_inspectable() -> crafter::core::Result<()> {
    let hop_by_hop = [
        IPPROTO_IPV6_NO_NEXT,
        0,
        IPV6_OPTION_JUMBO_PAYLOAD,
        3,
        0x00,
        0x01,
        0x00,
        0,
    ];
    let bytes = (ipv6_resilience_base(58).next_header(IPPROTO_IPV6_HOPOPTS)
        / Raw::from_bytes(hop_by_hop))
    .compile()?;
    let decoded = decode_packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6), bytes.as_bytes())?;

    let summary = decoded.summary();
    assert!(
        summary.contains("Generic(kind=0xc2"),
        "malformed Jumbo Payload option type should remain visible in summary: {summary}"
    );
    let show = decoded.show();
    assert!(
        show.contains("Generic(kind=0xc2"),
        "malformed Jumbo Payload option type should remain visible in show output: {show}"
    );

    Ok(())
}

#[test]
fn malformed_ipv6_router_alert_option_summary_is_inspectable() -> crafter::core::Result<()> {
    let hop_by_hop = [
        IPPROTO_IPV6_NO_NEXT,
        0,
        IPV6_OPTION_ROUTER_ALERT,
        1,
        0xaa,
        0,
        0,
        0,
    ];
    let bytes = (ipv6_resilience_base(58).next_header(IPPROTO_IPV6_HOPOPTS)
        / Raw::from_bytes(hop_by_hop))
    .compile()?;
    let decoded = decode_packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6), bytes.as_bytes())?;

    let summary = decoded.summary();
    assert!(
        summary.contains("Generic(kind=0x05"),
        "malformed Router Alert option type should remain visible in summary: {summary}"
    );
    let show = decoded.show();
    assert!(
        show.contains("Generic(kind=0x05"),
        "malformed Router Alert option type should remain visible in show output: {show}"
    );

    Ok(())
}

#[test]
fn malformed_ipv6_home_address_option_summary_is_inspectable() -> crafter::core::Result<()> {
    let mut destination_options = vec![IPPROTO_IPV6_NO_NEXT, 2, IPV6_OPTION_HOME_ADDRESS, 15];
    destination_options
        .extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    destination_options.extend_from_slice(&[0; 5]);
    let bytes = (ipv6_resilience_base(59).next_header(IPPROTO_IPV6_DSTOPTS)
        / Raw::from_bytes(&destination_options))
    .compile()?;
    let decoded = decode_packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6), bytes.as_bytes())?;

    let summary = decoded.summary();
    assert!(
        summary.contains("Generic(kind=0xc9"),
        "malformed Home Address option type should remain visible in summary: {summary}"
    );
    let show = decoded.show();
    assert!(
        show.contains("Generic(kind=0xc9"),
        "malformed Home Address option type should remain visible in show output: {show}"
    );

    Ok(())
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
    let bytes = compile_dhcp_payload(relay);
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
    let bytes = compile_dhcp_payload(route);
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
    let bytes = compile_dhcp_payload(domain);
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
        let bytes = compile_dhcp_payload(frame);
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
    let bytes = compile_dhcp_payload(good);
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

/// Malformed DHCP vectors built from test-local raw bytes must decode to
/// structured `CrafterError`s with the `required`/`available`/`reason` fields
/// populated and never panic. The public crate intentionally has no
/// DHCP-specific malformed builder; these fixtures keep decoder coverage
/// without exposing a one-off API.
///
/// This exercises short fixed header (truncation), missing magic cookie,
/// truncated trailing option, missing end marker, non-padding after the end
/// marker, invalid hardware length, an oversized (length-truncated) option
/// payload, and a malformed option-overload file area.
#[test]
fn raw_malformed_dhcp_vectors_report_structured_errors() {
    // Short fixed header: a complete DHCP frame truncated below DHCP_MIN_LEN.
    let full = dhcp_payload_with_options([DHCP_OPTION_MESSAGE_TYPE, 1, 1, DHCP_OPTION_END]);
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
    let mut bytes = dhcp_payload_with_options([DHCP_OPTION_MESSAGE_TYPE, 1, 1, DHCP_OPTION_END]);
    bytes[DHCP_FIXED_HEADER_LEN..DHCP_MIN_LEN].copy_from_slice(&0u32.to_be_bytes());
    match Dhcp::decode(&bytes) {
        Err(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(field, "dhcp.magic_cookie");
            assert!(!reason.is_empty());
        }
        other => panic!("invalid DHCP magic cookie expected InvalidFieldValue, got {other:?}"),
    }

    // Truncated option: a message-type option declares length 1 but supplies no
    // payload octet.
    let bytes = dhcp_payload_with_options([DHCP_OPTION_MESSAGE_TYPE, 1]);
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
    let bytes =
        dhcp_payload_with_options([DHCP_OPTION_MESSAGE_TYPE, 2, 0x01, 0x00, DHCP_OPTION_END]);
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
    let bytes = dhcp_payload_with_options([DHCP_OPTION_MESSAGE_TYPE, 0x01, 0x01]);
    match Dhcp::decode(&bytes) {
        Err(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(field, "dhcp.options");
            assert!(!reason.is_empty());
        }
        other => panic!("missing DHCP end marker expected InvalidFieldValue, got {other:?}"),
    }

    // Non-padding after end: a complete option segment follows the end option.
    let bytes = dhcp_payload_with_options([
        DHCP_OPTION_MESSAGE_TYPE,
        0x01,
        0x01,
        DHCP_OPTION_END,
        DHCP_OPTION_MESSAGE_TYPE,
        0x01,
        0x01,
    ]);
    match Dhcp::decode(&bytes) {
        Err(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(field, "dhcp.option.end");
            assert!(!reason.is_empty());
        }
        other => panic!("non-padding after DHCP end expected InvalidFieldValue, got {other:?}"),
    }

    // Invalid hardware length: hlen 32 exceeds the 16-byte chaddr field.
    let mut bytes = dhcp_payload_with_options([DHCP_OPTION_MESSAGE_TYPE, 1, 1, DHCP_OPTION_END]);
    bytes[2] = 32;
    match Dhcp::decode(&bytes) {
        Err(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(field, "dhcp.hlen");
            assert!(!reason.is_empty());
        }
        other => panic!("invalid DHCP hardware length expected InvalidFieldValue, got {other:?}"),
    }

    // Malformed typed option payload via oversized payload: a 300-octet payload
    // with a length-truncated (300 % 256 = 44) length byte overruns the option.
    let mut options = vec![43, 44];
    options.extend(vec![0u8; 300]);
    let bytes = dhcp_payload_with_options(options);
    // The decoder must not panic; it may surface a structured error or preserve
    // the bytes as a raw generic segment depending on the truncated length, but
    // it must never panic.
    let _ = Dhcp::decode(&bytes);

    // Malformed option overload: option 52 (in the normal options area) marks
    // the file area overloaded, but the file area carries a truncated option
    // (declared length overruns the 128-byte field) and no end marker.
    let mut bytes = dhcp_payload_with_options([52, 1, 1, DHCP_OPTION_END]);
    let mut file_area = [0u8; 128];
    file_area[0] = 0x43; // option 67 (bootfile name)
    file_area[1] = 200; // declared length overruns the 128-byte file area
    bytes[108..236].copy_from_slice(&file_area);
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
        ("truncated-dot11-rsn-ie", "dot11.tagged_parameter", 22, 8),
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
fn malformed_dot11_truncated_eapol_payload_returns_structured_error() {
    let bytes = parse_hex(
        "truncated-dot11-eapol-body",
        "\
        0800000002005e10000102005e10000202005e1000037000\
        aaaa03000000888e0203000501\
        ",
    );

    assert_eq!(
        Packet::decode_from_link(LinkType::Ieee80211, &bytes).unwrap_err(),
        CrafterError::buffer_too_short("eapol.body", 9, 5)
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

fn captured_raw_ip_record(bytes: Vec<u8>) -> PacketRecord {
    PacketRecord::new(Raw::from_bytes(&bytes))
        .with_pcap_link_type(PcapLinkType::RawIp)
        .with_captured_bytes(bytes)
}

fn captured_pcap_record(bytes: Vec<u8>, link_type: PcapLinkType) -> PacketRecord {
    PacketRecord::new(Raw::from_bytes(&bytes))
        .with_pcap_link_type(link_type)
        .with_captured_bytes(bytes)
}

fn ipv4_fragment_resilience_bytes(flags_fragment: u16, total_len: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(20 + payload.len());
    bytes.push(0x45);
    bytes.push(0);
    bytes.extend_from_slice(&total_len.to_be_bytes());
    bytes.extend_from_slice(&0x2026u16.to_be_bytes());
    bytes.extend_from_slice(&flags_fragment.to_be_bytes());
    bytes.push(64);
    bytes.push(253);
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&[192, 0, 2, 10]);
    bytes.extend_from_slice(&[198, 51, 100, 20]);
    bytes.extend_from_slice(payload);
    bytes
}

fn ipv6_fragment_resilience_bytes(payload_len: u16, fragment_bytes: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(40 + fragment_bytes.len());
    bytes.extend_from_slice(&[0x60, 0, 0, 0]);
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.push(IPPROTO_IPV6_FRAGMENT);
    bytes.push(64);
    bytes.extend_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ]);
    bytes.extend_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
    ]);
    bytes.extend_from_slice(fragment_bytes);
    bytes
}

fn assert_fragment_buffer_error(error: CrafterError, context: &'static str) {
    match error {
        CrafterError::BufferTooShort {
            context: actual,
            required,
            available,
        } => {
            assert_eq!(actual, context);
            assert!(
                required > available,
                "fragment BufferTooShort must require more bytes than are available"
            );
        }
        other => panic!("expected fragment BufferTooShort for {context}, got {other:?}"),
    }
}

fn assert_fragment_invalid_field(error: CrafterError, field: &'static str) {
    match error {
        CrafterError::InvalidFieldValue {
            field: actual,
            reason,
        } => {
            assert_eq!(actual, field);
            assert!(!reason.is_empty());
        }
        other => panic!("expected fragment InvalidFieldValue for {field}, got {other:?}"),
    }
}

fn wire_packet_error(error: WireError) -> CrafterError {
    match error {
        WireError::Packet(error) => error,
        other => panic!("expected packet error, got {other:?}"),
    }
}

#[test]
fn fragment_malformed_decode_entrypoints_report_structured_errors() {
    let mut truncated_ipv4 = ipv4_fragment_resilience_bytes(0x2000, 20, &[]);
    truncated_ipv4.truncate(19);
    let truncated_ipv6 = ipv6_fragment_resilience_bytes(4, &[IPPROTO_UDP, 0, 0, 1]);
    let ipv4_length_mismatch = ipv4_fragment_resilience_bytes(0x2000, 32, &[0xaa; 8]);
    let ipv6_length_mismatch = ipv6_fragment_resilience_bytes(8, &[IPPROTO_UDP, 0, 0, 1]);

    for (label, target, bytes, context) in [
        (
            "truncated ipv4 fragment header",
            PacketDecodeTarget::L3(NetworkLayer::Ipv4),
            truncated_ipv4,
            "ipv4 header",
        ),
        (
            "truncated ipv6 fragment header",
            PacketDecodeTarget::L3(NetworkLayer::Ipv6),
            truncated_ipv6,
            "ipv6 fragment header",
        ),
        (
            "ipv4 fragment payload length mismatch",
            PacketDecodeTarget::L3(NetworkLayer::Ipv4),
            ipv4_length_mismatch,
            "ipv4 packet",
        ),
        (
            "ipv6 fragment payload length mismatch",
            PacketDecodeTarget::L3(NetworkLayer::Ipv6),
            ipv6_length_mismatch,
            "ipv6 packet",
        ),
    ] {
        let error = decode_packet(target, &bytes)
            .err()
            .unwrap_or_else(|| panic!("{label} unexpectedly decoded"));
        assert_fragment_buffer_error(error, context);
    }
}

#[test]
fn fragment_malformed_transforms_report_structured_errors() {
    let mut truncated_ipv4 = ipv4_fragment_resilience_bytes(0x2000, 20, &[]);
    truncated_ipv4.truncate(19);
    let truncated_ipv6 = ipv6_fragment_resilience_bytes(4, &[IPPROTO_UDP, 0, 0, 1]);

    let mut defrag = IpDefrag::new();
    let error = defrag
        .defrag_record(captured_raw_ip_record(truncated_ipv4))
        .unwrap_err();
    assert_fragment_buffer_error(wire_packet_error(error), "ipv4 header");

    let mut defrag = IpDefrag::new();
    let error = defrag
        .defrag_record(captured_raw_ip_record(truncated_ipv6))
        .unwrap_err();
    assert_fragment_buffer_error(wire_packet_error(error), "ipv6 fragment header");

    let impossible_offset = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        .protocol(253)
        .fragment_offset(0x1fff)
        / Raw::from_bytes([0x5a; 16]);
    let mut fragment = IpFragment::new(28);
    let error = fragment
        .fragment_record(PacketRecord::new(impossible_offset))
        .unwrap_err();
    assert_fragment_invalid_field(wire_packet_error(error), "ipv4.fragment_offset");
}

#[test]
fn fragment_unsupported_wrappers_pass_through_without_panic() {
    let bytes = ipv4_fragment_resilience_bytes(0x2000, 28, &[0xaa; 8]);
    let record = captured_pcap_record(bytes.clone(), PcapLinkType::Ieee80211);

    let mut defrag = IpDefrag::new();
    let output = defrag.defrag_record(record.clone()).unwrap();
    assert_eq!(output.len(), 1);
    assert_eq!(
        output.records()[0].metadata().captured_bytes(),
        Some(bytes.as_slice())
    );

    let mut fragment = IpFragment::new(1280);
    let output = fragment.fragment_record(record).unwrap();
    assert_eq!(output.len(), 1);
    assert_eq!(
        output.records()[0].metadata().captured_bytes(),
        Some(bytes.as_slice())
    );
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
        // ESP (50) and AH (51) are excluded: they are now bound protocols
        // decoding to typed IPSec layers (an opaque `Esp` with an 8-octet
        // minimum, an `Ah` with a 12-octet fixed header), not unknown next
        // headers that always fall back to `Raw`. Their round-trips are covered
        // by the crate-internal ESP/AH registry tests.
        next_header in prop::sample::select(vec![
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
        // A valid BOOTP fixed header + magic cookie keeps the registry gate
        // (`is_dhcp_port_pair` && `looks_like_dhcp_payload`) satisfied so the
        // arbitrary option-region bytes reach the DHCP decoder through the real
        // boundary rather than being dropped as non-DHCP UDP traffic.
        let dhcp_payload = dhcp_payload_with_options(option_bytes);

        let frame = Ipv4::with_addresses(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST)
            / Udp::new()
                .source_port(DHCP_CLIENT_PORT)
                .destination_port(DHCP_SERVER_PORT)
            / Raw::from_bytes(&dhcp_payload);

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

/// Malformed / truncation corpus and property-based fuzzing for the IPSec
/// layers: ESP (RFC 4303), AH (RFC 4302), and IKEv2 (RFC 7296).
///
/// `CLAUDE.md` and the IPSec spec require that every IPSec decode path either
/// produces a typed (or lenient/opaque) result or a structured [`CrafterError`]
/// carrying `context` / `required` / `available` (or a stable `field`), and that
/// it **never panics** — not on truncation, not on a bad pad length, not on a
/// length field that disagrees with the buffer, and not on arbitrary bytes.
///
/// Two complementary surfaces are exercised:
///
/// - A deterministic line-oriented corpus
///   (`fixtures/malformed/ipsec-decode-corpus.hex`) of hand-built malformed ESP /
///   AH / IKEv2 buffers. Each row is reached through a *public* decode entrypoint
///   (`decode_from_l3` for ESP/AH behind IPv4/IPv6, the UDP/500 path for IKE).
///   Rows classified `structured-error` assert the exact `CrafterError`; rows
///   classified `lenient-no-panic` (e.g. a bad ESP pad length or a short ICV that
///   live inside the still-encrypted body the no-SA path cannot inspect) only
///   assert that the decode never panics.
/// - SA-bearing tamper cases that *can* see inside the ciphertext (a bad ESP pad
///   pattern, an ICV shorter than the algorithm requires, and an SK payload with a
///   corrupted ICV), driven through the public SA-registry decode surface, must
///   surface a structured error and never a panic or a silently-wrong plaintext.
/// - Property tests feeding arbitrary bytes to the ESP, AH, and IKE decoders —
///   with and without a registered SA — asserting no input panics (the proptest
///   harness fails the test on any panic).
mod ipsec_malformed_corpus {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crafter::core::{
        CrafterError, EncryptionAlgorithm, Esp, Ipv4, Ipv6, NetworkLayer, Packet, ProtocolRegistry,
        Raw, SecurityAssociation, Udp, IPPROTO_AH, IPPROTO_ESP, IPPROTO_IPV6_AH, IPPROTO_IPV6_ESP,
        IPPROTO_UDP,
    };
    use crafter::protocols::ipsec::ikev2::payload::encrypted::{
        decode_sk_payload_with_sa, IkeEncryptedPayload,
    };
    use proptest::prelude::*;

    /// Documentation addresses (RFC 5737 / RFC 3849) for the carrying envelopes.
    const DOC4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const DOC4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
    const DOC6_SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    const DOC6_DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

    /// IKEv2 well-known UDP port (RFC 7296 §2; IANA "isakmp").
    const IKE_UDP_PORT: u16 = 500;

    /// How a raw IPSec buffer in the corpus is wrapped and reached through a
    /// public decode entrypoint.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum IpsecTarget {
        /// `Ipv4(protocol 50) / <bytes>`, decoded via `decode_from_l3(Ipv4)`.
        Ipv4Esp,
        /// `Ipv6(next-header 50) / <bytes>`, decoded via `decode_from_l3(Ipv6)`.
        Ipv6Esp,
        /// `Ipv4(protocol 51) / <bytes>`, decoded via `decode_from_l3(Ipv4)`.
        Ipv4Ah,
        /// `Ipv6(next-header 51) / <bytes>`, decoded via `decode_from_l3(Ipv6)`.
        Ipv6Ah,
        /// `Ipv4 / Udp(500) / <bytes>`, decoded via `decode_from_l3(Ipv4)`.
        Ikev2,
    }

    /// The decode contract a corpus row asserts.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Classification {
        /// The truncation is detectable from the buffer alone, so the decode must
        /// return a structured error whose `context`/`field` is `context_or_field`.
        StructuredError,
        /// The malformation lives where the opaque (no-SA) decode cannot see it;
        /// the decode may succeed opaquely or error, but must never panic.
        LenientNoPanic,
    }

    #[derive(Debug)]
    struct IpsecCase {
        name: &'static str,
        target: IpsecTarget,
        classification: Classification,
        context_or_field: &'static str,
        bytes: Vec<u8>,
    }

    fn parse_target(name: &str, target: &str) -> IpsecTarget {
        match target {
            "ipv4-esp" => IpsecTarget::Ipv4Esp,
            "ipv6-esp" => IpsecTarget::Ipv6Esp,
            "ipv4-ah" => IpsecTarget::Ipv4Ah,
            "ipv6-ah" => IpsecTarget::Ipv6Ah,
            "ikev2" => IpsecTarget::Ikev2,
            other => panic!("ipsec corpus case {name} has unknown target {other}"),
        }
    }

    fn parse_classification(name: &str, classification: &str) -> Classification {
        match classification {
            "structured-error" => Classification::StructuredError,
            "lenient-no-panic" => Classification::LenientNoPanic,
            other => {
                panic!("ipsec corpus case {name} has unknown classification {other}")
            }
        }
    }

    fn parse_hex(name: &str, hex: &str) -> Vec<u8> {
        let hex = hex
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect::<String>();
        assert!(
            hex.len() % 2 == 0,
            "ipsec corpus case {name} has an odd hex length"
        );
        hex.as_bytes()
            .chunks(2)
            .map(|chunk| {
                let byte = std::str::from_utf8(chunk)
                    .unwrap_or_else(|_| panic!("ipsec corpus case {name} contains non-UTF8 hex"));
                u8::from_str_radix(byte, 16)
                    .unwrap_or_else(|_| panic!("ipsec corpus case {name} has invalid hex {byte}"))
            })
            .collect()
    }

    fn ipsec_cases() -> Vec<IpsecCase> {
        fixture_str!("malformed/ipsec-decode-corpus.hex")
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
                    panic!("ipsec corpus line {line_number} is missing a case name")
                });
                let target = parts.next().unwrap_or_else(|| {
                    panic!("ipsec corpus case {name} is missing a decode target")
                });
                let classification = parts.next().unwrap_or_else(|| {
                    panic!("ipsec corpus case {name} is missing a classification")
                });
                let context_or_field = parts.next().unwrap_or_else(|| {
                    panic!("ipsec corpus case {name} is missing a context-or-field")
                });
                // The hex column may be absent (empty buffer); treat a missing
                // column as the empty buffer rather than a parse error.
                let hex = parts.next().unwrap_or("");
                assert!(
                    parts.next().is_none(),
                    "ipsec corpus case {name} has too many fields"
                );
                assert!(
                    !name.is_empty(),
                    "ipsec corpus line {line_number} has an empty case name"
                );
                assert!(
                    !context_or_field.is_empty(),
                    "ipsec corpus case {name} has an empty context-or-field"
                );

                Some(IpsecCase {
                    name,
                    target: parse_target(name, target),
                    classification: parse_classification(name, classification),
                    context_or_field,
                    bytes: parse_hex(name, hex),
                })
            })
            .collect()
    }

    /// Wrap the raw IPSec buffer in its documented envelope and compile it to wire
    /// bytes, returning the bytes plus the L3 entrypoint to decode them from. The
    /// envelope itself is always well-formed; only the inner IPSec bytes are
    /// malformed, so this compile must always succeed.
    fn wrap_case(case: &IpsecCase) -> (NetworkLayer, Vec<u8>) {
        let raw = Raw::from_bytes(&case.bytes);
        match case.target {
            IpsecTarget::Ipv4Esp => {
                let packet = Ipv4::new()
                    .src(DOC4_SRC)
                    .dst(DOC4_DST)
                    .protocol(IPPROTO_ESP)
                    / raw;
                (NetworkLayer::Ipv4, compile_envelope(case, packet))
            }
            IpsecTarget::Ipv6Esp => {
                let packet = Ipv6::new().src(DOC6_SRC).dst(DOC6_DST).nh(IPPROTO_IPV6_ESP) / raw;
                (NetworkLayer::Ipv6, compile_envelope(case, packet))
            }
            IpsecTarget::Ipv4Ah => {
                let packet = Ipv4::new().src(DOC4_SRC).dst(DOC4_DST).protocol(IPPROTO_AH) / raw;
                (NetworkLayer::Ipv4, compile_envelope(case, packet))
            }
            IpsecTarget::Ipv6Ah => {
                let packet = Ipv6::new().src(DOC6_SRC).dst(DOC6_DST).nh(IPPROTO_IPV6_AH) / raw;
                (NetworkLayer::Ipv6, compile_envelope(case, packet))
            }
            IpsecTarget::Ikev2 => {
                let packet = Ipv4::new()
                    .src(DOC4_SRC)
                    .dst(DOC4_DST)
                    .protocol(IPPROTO_UDP)
                    / Udp::new().sport(IKE_UDP_PORT).dport(IKE_UDP_PORT)
                    / raw;
                (NetworkLayer::Ipv4, compile_envelope(case, packet))
            }
        }
    }

    fn compile_envelope(case: &IpsecCase, packet: Packet) -> Vec<u8> {
        packet
            .compile()
            .unwrap_or_else(|err| {
                panic!(
                    "ipsec corpus envelope for {} should always compile: {err}",
                    case.name
                )
            })
            .as_bytes()
            .to_vec()
    }

    /// Assert a decoded structured error matches the corpus row's expected
    /// `context` (for `BufferTooShort`) or `field` (for `InvalidFieldValue`), with
    /// the `required`/`available`/`reason` payload populated.
    fn assert_structured_error(case: &IpsecCase, error: CrafterError) {
        match error {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(
                    context, case.context_or_field,
                    "ipsec corpus case {} returned an unexpected buffer context",
                    case.name
                );
                assert!(
                    required > available,
                    "ipsec corpus case {} BufferTooShort must require more ({required}) \
                     than is available ({available})",
                    case.name
                );
            }
            CrafterError::InvalidFieldValue { field, reason } => {
                assert_eq!(
                    field, case.context_or_field,
                    "ipsec corpus case {} returned an unexpected invalid field",
                    case.name
                );
                assert!(
                    !reason.is_empty(),
                    "ipsec corpus case {} InvalidFieldValue must carry a non-empty reason",
                    case.name
                );
            }
            other => panic!(
                "ipsec corpus case {} expected a structured error for {}, got {other:?}",
                case.name, case.context_or_field
            ),
        }
    }

    /// Every malformed IPSec corpus row, decoded through a public entrypoint with
    /// the default (SA-less) registry, must honor its classification and never
    /// panic. `structured-error` rows must return the exact error; `lenient-no-panic`
    /// rows may decode opaquely or error, but never panic — and whenever they
    /// decode, the model stays inspectable.
    #[test]
    fn ipsec_malformed_corpus_honors_classification() {
        let cases = ipsec_cases();
        assert!(!cases.is_empty(), "ipsec corpus must not be empty");

        // Every IPSec decode target and both classifications must be represented
        // so this never silently narrows.
        for target in [
            IpsecTarget::Ipv4Esp,
            IpsecTarget::Ipv6Esp,
            IpsecTarget::Ipv4Ah,
            IpsecTarget::Ipv6Ah,
            IpsecTarget::Ikev2,
        ] {
            assert!(
                cases.iter().any(|case| case.target == target),
                "ipsec corpus missing {target:?} coverage"
            );
        }
        for classification in [
            Classification::StructuredError,
            Classification::LenientNoPanic,
        ] {
            assert!(
                cases
                    .iter()
                    .any(|case| case.classification == classification),
                "ipsec corpus missing {classification:?} coverage"
            );
        }

        for case in &cases {
            let (layer, wire) = wrap_case(case);
            let result = Packet::decode_from_l3(layer, &wire);
            match case.classification {
                Classification::StructuredError => {
                    let error = result.err().unwrap_or_else(|| {
                        panic!(
                            "ipsec corpus case {} expected a structured error, but it decoded",
                            case.name
                        )
                    });
                    assert_structured_error(case, error);
                }
                Classification::LenientNoPanic => {
                    // Either outcome is acceptable; the contract is "no panic".
                    // Whenever the lenient case decodes, the model must stay
                    // inspectable (summary/show/compile must not panic either).
                    if let Ok(packet) = result {
                        let _ = packet.summary();
                        let _ = packet.show();
                        let _ = packet.compile();
                    }
                }
            }
        }
    }

    // --- SA-bearing tamper cases (the malformation is inside the ciphertext) ---

    /// Fixed AES-GCM material (documentation-only; never a real key).
    fn gcm_key() -> Vec<u8> {
        vec![0x24u8; 16]
    }
    fn gcm_salt() -> Vec<u8> {
        vec![0xa1, 0xb2, 0xc3, 0xd4]
    }
    fn gcm_iv() -> Vec<u8> {
        vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    }

    /// An ESP datagram whose ICV (AEAD tag) is corrupted must fail integrity with
    /// a structured error — never a panic and never a silently-wrong plaintext.
    /// This is the "bad ESP pad length / short ICV" dimension the opaque corpus
    /// rows cannot reach: only the SA-aware path inspects the trailer and tag.
    #[test]
    fn esp_with_sa_tampered_icv_is_structured_error() {
        let spi = 0x0000_2900;
        let sa = SecurityAssociation::new(spi)
            .encryption(EncryptionAlgorithm::AesGcm16, gcm_key())
            .salt(gcm_salt())
            .transport()
            .extended_sequence(false);

        let packet: Packet = Ipv4::new()
            .src(DOC4_SRC)
            .dst(DOC4_DST)
            .protocol(IPPROTO_ESP)
            / Esp::secured(sa.clone()).spi(spi).sequence(1).iv(gcm_iv())
            / Raw::from("esp-resilience");
        let mut wire = packet
            .compile()
            .expect("ESP envelope compiles")
            .as_bytes()
            .to_vec();
        // Flip the final ICV byte (the AEAD tag sits at the very end).
        *wire.last_mut().unwrap() ^= 0x01;

        let registry = ProtocolRegistry::new().with_security_association(sa);
        let err = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, &wire)
            .expect_err("a corrupted ESP ICV must fail integrity");
        assert!(
            matches!(err, CrafterError::InvalidFieldValue { .. }),
            "expected a structured ICV error, got {err:?}"
        );
    }

    /// An ESP datagram whose ciphertext is one octet shorter than the SA's ICV +
    /// IV + fixed trailer requires must surface a structured `esp datagram`
    /// buffer-too-short — never a panic. The SA can compute exactly how many
    /// octets the algorithm needs, so this truncation is detectable.
    #[test]
    fn esp_with_sa_icv_shorter_than_algorithm_is_structured_error() {
        let spi = 0x0000_2A00;
        let sa = SecurityAssociation::new(spi)
            .encryption(EncryptionAlgorithm::AesGcm16, gcm_key())
            .salt(gcm_salt())
            .transport()
            .extended_sequence(false);

        // SPI(4) || Seq(4) then far too few octets to hold IV(8) + ICV(16) +
        // pad-length + next-header. The on-wire SPI matches the SA so the registry
        // dispatches the SA-aware path; it knows the algorithm's lengths, so it
        // rejects this with a structured buffer-too-short.
        let mut short = spi.to_be_bytes().to_vec();
        short.extend_from_slice(&1u32.to_be_bytes()); // Sequence = 1.
        short.extend_from_slice(&[0xaa, 0xbb, 0xcc]); // far too few body octets.
        let wire = (Ipv4::new()
            .src(DOC4_SRC)
            .dst(DOC4_DST)
            .protocol(IPPROTO_ESP)
            / Raw::from_bytes(&short))
        .compile()
        .expect("short ESP envelope compiles")
        .as_bytes()
        .to_vec();

        let registry = ProtocolRegistry::new().with_security_association(sa);
        let err = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, &wire)
            .expect_err("an ESP body too short for the algorithm's ICV must error");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "esp datagram");
                assert!(required > available);
            }
            other => panic!("expected esp datagram buffer-too-short, got {other:?}"),
        }
    }

    /// Build a real sealed SK payload (generic header + `IV || ciphertext || ICV`)
    /// by compiling a full `Ipv4 / Udp(500) / IkeHeader / SK` message and slicing
    /// off the carrying headers — exactly the bytes `decode_sk_payload_with_sa`
    /// expects (the full SK payload including its 4-octet generic header).
    fn sealed_sk_payload(sk_sa: &SecurityAssociation) -> Vec<u8> {
        use crafter::core::{IkeHeader, IKE_HEADER_LEN};

        let sk = IkeEncryptedPayload::new(sk_sa.clone())
            .iv(gcm_iv())
            .payload(Raw::from("sk-inner"));
        let header = IkeHeader::new()
            .initiator_spi(0x1122_3344_5566_7788)
            .responder_spi(0x99AA_BBCC_DDEE_FF00)
            .initiator();
        let packet: Packet = Ipv4::new()
            .src(DOC4_SRC)
            .dst(DOC4_DST)
            .protocol(IPPROTO_UDP)
            / Udp::new().sport(IKE_UDP_PORT).dport(IKE_UDP_PORT)
            / header
            / sk;
        let wire = packet
            .compile()
            .expect("SK message compiles")
            .as_bytes()
            .to_vec();
        // The UDP payload (the IKE message) starts after the IPv4 + UDP headers;
        // drop the 28-octet IKE header to leave just the SK payload.
        let ihl_words = usize::from(wire[0] & 0x0f);
        let udp_payload_offset = ihl_words * 4 + 8;
        wire[udp_payload_offset + IKE_HEADER_LEN..].to_vec()
    }

    /// An SK (Encrypted) payload whose ICV is corrupted must fail to open with a
    /// structured error — never a panic and never a wrong plaintext.
    #[test]
    fn sk_payload_with_bad_icv_is_structured_error() {
        let sk_sa = SecurityAssociation::new(0x0000_4400)
            .encryption(EncryptionAlgorithm::AesGcm16, gcm_key())
            .salt(gcm_salt());

        // A genuine sealed SK payload, then corrupt its trailing ICV byte.
        let mut payload = sealed_sk_payload(&sk_sa);
        assert!(!payload.is_empty(), "sealed SK payload must be non-empty");
        *payload.last_mut().unwrap() ^= 0x01;

        let err = decode_sk_payload_with_sa(&payload, &sk_sa)
            .expect_err("a corrupted SK ICV must fail to open");
        assert!(
            matches!(err, CrafterError::InvalidFieldValue { .. }),
            "expected a structured SK ICV error, got {err:?}"
        );
    }

    // --- Property-based fuzzing: arbitrary bytes never panic any decoder ---

    /// Decode `bytes` as an ESP/AH datagram behind both IPv4 and IPv6, and as an
    /// IKE message over UDP/500, with the supplied registry. The only contract is
    /// that nothing panics; whenever a decode succeeds, the model stays
    /// inspectable.
    fn exercise_ipsec_decoders(registry: &ProtocolRegistry, bytes: &[u8]) {
        let exercise = |layer: NetworkLayer, wire: &[u8]| {
            if let Ok(packet) = Packet::decode_from_l3_with_registry(registry, layer, wire) {
                let _ = packet.summary();
                let _ = packet.show();
                let _ = packet.compile();
            }
        };

        // ESP / AH behind a well-formed IPv4 header (protocol 50 / 51).
        for protocol in [IPPROTO_ESP, IPPROTO_AH] {
            if let Ok(wire) = (Ipv4::new().src(DOC4_SRC).dst(DOC4_DST).protocol(protocol)
                / Raw::from_bytes(bytes))
            .compile()
            {
                exercise(NetworkLayer::Ipv4, wire.as_bytes());
            }
        }
        // ESP / AH behind a well-formed IPv6 header (next-header 50 / 51).
        for next_header in [IPPROTO_IPV6_ESP, IPPROTO_IPV6_AH] {
            if let Ok(wire) = (Ipv6::new().src(DOC6_SRC).dst(DOC6_DST).nh(next_header)
                / Raw::from_bytes(bytes))
            .compile()
            {
                exercise(NetworkLayer::Ipv6, wire.as_bytes());
            }
        }
        // IKE message over UDP/500.
        if let Ok(wire) = (Ipv4::new()
            .src(DOC4_SRC)
            .dst(DOC4_DST)
            .protocol(IPPROTO_UDP)
            / Udp::new().sport(IKE_UDP_PORT).dport(IKE_UDP_PORT)
            / Raw::from_bytes(bytes))
        .compile()
        {
            exercise(NetworkLayer::Ipv4, wire.as_bytes());
        }

        // The SK payload decoder is reached directly (it is public), so feed the
        // arbitrary bytes to it too under an AEAD SA — it must never panic.
        let _ = decode_sk_payload_with_sa(bytes, &fuzz_sa());
    }

    /// The AEAD SA the with-SA proptest registers (its SPI is matched by the
    /// arbitrary ESP/AH SPI only by chance, which is exactly the path we want to
    /// fuzz — both the matched SA-aware and unmatched opaque branches).
    fn fuzz_sa() -> SecurityAssociation {
        SecurityAssociation::new(0x0000_2900)
            .encryption(EncryptionAlgorithm::AesGcm16, gcm_key())
            .salt(gcm_salt())
            .transport()
            .extended_sequence(false)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// Arbitrary bytes fed to the ESP / AH / IKE decoders through the public
        /// entrypoints with the *default* (SA-less) registry must never panic.
        #[test]
        fn ipsec_random_decode_without_sa_never_panics(
            bytes in prop::collection::vec(any::<u8>(), 0..512),
        ) {
            let registry = ProtocolRegistry::new();
            exercise_ipsec_decoders(&registry, &bytes);
        }

        /// The same arbitrary bytes, but with a registered AES-GCM SA so the
        /// SA-aware ESP/AH decrypt+verify branch (and the SK open path) is fuzzed
        /// too. Whether or not the arbitrary on-wire SPI matches the SA, no input
        /// may panic.
        #[test]
        fn ipsec_random_decode_with_sa_never_panics(
            bytes in prop::collection::vec(any::<u8>(), 0..512),
        ) {
            let registry = ProtocolRegistry::new().with_security_association(fuzz_sa());
            exercise_ipsec_decoders(&registry, &bytes);
        }
    }
}
