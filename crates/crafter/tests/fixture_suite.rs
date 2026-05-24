#[macro_use]
mod support;

use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use crafter::core::{
    Arp, DhcpMessageType, DhcpOption, Dns, Ethernet, Icmp, IcmpKind, Icmpv6, Ipv4, Ipv6, Layer,
    LinkType, MacAddr, NetworkLayer, Packet, Raw, Udp, Vlan, DNS_CLASS_IN,
    DNS_FLAG_RECURSION_DESIRED, DNS_TYPE_A, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_VLAN,
    ICMPV6_ECHO_REQUEST, ICMP_ECHO_REQUEST, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_UDP,
};
use support::fixture_path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketDecodeTarget {
    Raw,
    Link(LinkType),
    L3(NetworkLayer),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureDecodeTarget {
    Packet(PacketDecodeTarget),
    DhcpOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureContents {
    Bytes(&'static [u8]),
    Hex(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedLayer {
    Ethernet,
    Vlan,
    Arp,
    Ipv4,
    Ipv6,
    Icmp,
    Icmpv6,
    Udp,
    Dns,
    Raw,
}

#[derive(Debug, Clone, Copy)]
struct ValidFixtureCase {
    name: &'static str,
    path: &'static str,
    contents: FixtureContents,
    target: FixtureDecodeTarget,
    expected_layers: &'static [ExpectedLayer],
    preserve_exact_bytes: bool,
    summary_path: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MalformedFixtureRow {
    name: String,
    target: String,
    expected_kind: Option<String>,
    expected_context_or_field: Option<String>,
    bytes: Vec<u8>,
}

const VALID_FIXTURES: &[ValidFixtureCase] = &[
    ValidFixtureCase {
        name: "arp-who-has",
        path: "bytes/arp-who-has.bin",
        contents: FixtureContents::Bytes(fixture_bytes!("bytes/arp-who-has.bin")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ethernet)),
        expected_layers: &[ExpectedLayer::Ethernet, ExpectedLayer::Arp],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-offer-options",
        path: "bytes/dhcp-offer-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-offer-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ethernet-experimental-raw",
        path: "bytes/ethernet-experimental-raw.bin",
        contents: FixtureContents::Bytes(fixture_bytes!("bytes/ethernet-experimental-raw.bin")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ethernet)),
        expected_layers: &[ExpectedLayer::Ethernet, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ethernet-vlan-ipv4-udp-raw",
        path: "bytes/ethernet-vlan-ipv4-udp-raw.bin",
        contents: FixtureContents::Bytes(fixture_bytes!("bytes/ethernet-vlan-ipv4-udp-raw.bin")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ethernet)),
        expected_layers: &[
            ExpectedLayer::Ethernet,
            ExpectedLayer::Vlan,
            ExpectedLayer::Ipv4,
            ExpectedLayer::Udp,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-icmp-echo-request",
        path: "bytes/ipv4-icmp-echo-request.bin",
        contents: FixtureContents::Bytes(fixture_bytes!("bytes/ipv4-icmp-echo-request.bin")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Icmp, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-udp-dns-query-example-com",
        path: "bytes/ipv4-udp-dns-query-example-com.bin",
        contents: FixtureContents::Bytes(fixture_bytes!(
            "bytes/ipv4-udp-dns-query-example-com.bin"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Dns],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv6-icmp-echo-request",
        path: "bytes/ipv6-icmp-echo-request.bin",
        contents: FixtureContents::Bytes(fixture_bytes!("bytes/ipv6-icmp-echo-request.bin")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[
            ExpectedLayer::Ipv6,
            ExpectedLayer::Icmpv6,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
];

fn fixture_bytes_for_case(case: &ValidFixtureCase) -> Vec<u8> {
    match case.contents {
        FixtureContents::Bytes(bytes) => bytes.to_vec(),
        FixtureContents::Hex(hex) => decode_hex(case.name, hex),
    }
}

fn decode_hex(label: &str, text: &str) -> Vec<u8> {
    let mut compact = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        for ch in line.chars().filter(|ch| !ch.is_whitespace()) {
            assert!(
                ch.is_ascii_hexdigit(),
                "hex fixture {label} contains non-hex character {ch:?}"
            );
            compact.push(ch);
        }
    }

    assert!(
        compact.len() % 2 == 0,
        "hex fixture {label} has an odd hex length"
    );

    compact
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = std::str::from_utf8(chunk)
                .unwrap_or_else(|_| panic!("hex fixture {label} contains non-UTF8 hex"));
            u8::from_str_radix(byte, 16)
                .unwrap_or_else(|_| panic!("hex fixture {label} has invalid hex byte {byte}"))
        })
        .collect()
}

fn decode_packet(target: PacketDecodeTarget, bytes: &[u8]) -> crafter::core::Result<Packet> {
    match target {
        PacketDecodeTarget::Raw => Packet::decode_raw(bytes),
        PacketDecodeTarget::Link(link_type) => Packet::decode_from_link(link_type, bytes),
        PacketDecodeTarget::L3(network_layer) => Packet::decode_from_l3(network_layer, bytes),
    }
}

fn assert_compile_decode_compile(
    case: &ValidFixtureCase,
    target: PacketDecodeTarget,
    packet: &Packet,
    fixture_bytes: &[u8],
) {
    let compiled = packet
        .compile()
        .unwrap_or_else(|err| panic!("fixture {} should compile: {err}", case.path));

    if case.preserve_exact_bytes {
        assert_eq!(
            compiled.as_bytes(),
            fixture_bytes,
            "fixture {} did not preserve original bytes after decode/compile",
            case.path
        );
    }

    let decoded_again = decode_packet(target, compiled.as_bytes()).unwrap_or_else(|err| {
        panic!(
            "fixture {} should decode after compile/decode/compile setup: {err}",
            case.path
        )
    });
    let recompiled = decoded_again
        .compile()
        .unwrap_or_else(|err| panic!("fixture {} should recompile: {err}", case.path));
    assert_eq!(
        recompiled.as_bytes(),
        compiled.as_bytes(),
        "fixture {} compile/decode/compile bytes changed",
        case.path
    );
}

fn assert_packet_surface(case: &ValidFixtureCase, packet: &Packet) {
    assert_expected_layers(case, packet);

    let summary = packet.summary();
    assert!(
        !summary.is_empty(),
        "fixture {} produced an empty summary",
        case.path
    );

    let show = packet.show();
    assert!(
        show.starts_with("Packet("),
        "fixture {} produced unexpected show output: {show}",
        case.path
    );

    if let Some(summary_path) = case.summary_path {
        let expected = read_summary_fixture(summary_path);
        assert_eq!(
            expected.trim_end(),
            summary.trim_end(),
            "fixture {} summary did not match {}",
            case.path,
            summary_path
        );
    }
}

fn assert_expected_layers(case: &ValidFixtureCase, packet: &Packet) {
    for expected in case.expected_layers {
        match expected {
            ExpectedLayer::Ethernet => {
                let _ = expect_layer::<Ethernet>(case, packet);
            }
            ExpectedLayer::Vlan => {
                let _ = expect_layer::<Vlan>(case, packet);
            }
            ExpectedLayer::Arp => {
                let _ = expect_layer::<Arp>(case, packet);
            }
            ExpectedLayer::Ipv4 => {
                let _ = expect_layer::<Ipv4>(case, packet);
            }
            ExpectedLayer::Ipv6 => {
                let _ = expect_layer::<Ipv6>(case, packet);
            }
            ExpectedLayer::Icmp => {
                let _ = expect_layer::<Icmp>(case, packet);
            }
            ExpectedLayer::Icmpv6 => {
                let _ = expect_layer::<Icmpv6>(case, packet);
            }
            ExpectedLayer::Udp => {
                let _ = expect_layer::<Udp>(case, packet);
            }
            ExpectedLayer::Dns => {
                let _ = expect_layer::<Dns>(case, packet);
            }
            ExpectedLayer::Raw => {
                let _ = expect_layer::<Raw>(case, packet);
            }
        };
    }
}

fn expect_layer<'a, T>(case: &ValidFixtureCase, packet: &'a Packet) -> &'a T
where
    T: Layer,
{
    packet.layer::<T>().unwrap_or_else(|| {
        panic!(
            "fixture {} missing layer {}; actual stack: {}",
            case.path,
            std::any::type_name::<T>(),
            packet.summary()
        )
    })
}

fn assert_fixture_fields(case: &ValidFixtureCase, packet: &Packet) {
    match case.name {
        "arp-who-has" => {
            let ethernet = expect_layer::<Ethernet>(case, packet);
            assert_eq!(ethernet.destination(), Some(MacAddr::BROADCAST));
            assert_eq!(
                ethernet.source(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
            );
            assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_ARP));

            let arp = expect_layer::<Arp>(case, packet);
            assert_eq!(arp.opcode_value(), 1);
            assert_eq!(arp.sender_mac(), ethernet.source());
            assert_eq!(arp.sender_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
            assert_eq!(arp.target_mac(), Some(MacAddr::ZERO));
            assert_eq!(arp.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));
        }
        "ethernet-experimental-raw" => {
            let ethernet = expect_layer::<Ethernet>(case, packet);
            assert_eq!(
                ethernet.destination(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x02]))
            );
            assert_eq!(
                ethernet.source(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
            );
            assert_eq!(ethernet.ethertype_value(), Some(0x9000));
            assert_eq!(
                expect_layer::<Raw>(case, packet).as_bytes(),
                b"libcrafter-ethernet"
            );
        }
        "ethernet-vlan-ipv4-udp-raw" => {
            let ethernet = expect_layer::<Ethernet>(case, packet);
            assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_VLAN));

            let vlan = expect_layer::<Vlan>(case, packet);
            assert_eq!(vlan.pcp_value(), 3);
            assert!(!vlan.dei_value());
            assert_eq!(vlan.vlan_id_value(), 42);
            assert_eq!(vlan.ethertype_value(), ETHERTYPE_IPV4);

            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 20));
            assert_eq!(ipv4.ttl_value(), 58);
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 53_002);
            assert_eq!(udp.destination_port_value(), 9_999);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"vlan-udp");
        }
        "ipv4-icmp-echo-request" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 20));
            assert_eq!(ipv4.identification_value(), 0x1234);
            assert!(ipv4.is_dont_fragment());
            assert_eq!(ipv4.protocol_value(), IPPROTO_ICMP);

            let icmp = expect_layer::<Icmp>(case, packet);
            assert_eq!(icmp.icmp_type_value(), ICMP_ECHO_REQUEST);
            assert_eq!(icmp.kind_value(), Some(IcmpKind::EchoRequest));
            assert_eq!(icmp.identifier_value(), Some(0x4242));
            assert_eq!(icmp.sequence_number_value(), Some(1));
            assert_eq!(
                expect_layer::<Raw>(case, packet).as_bytes(),
                b"libcrafter-icmp"
            );
        }
        "ipv4-udp-dns-query-example-com" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 53));
            assert_eq!(ipv4.ttl_value(), 61);
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 53_001);
            assert_eq!(udp.destination_port_value(), 53);

            let dns = expect_layer::<Dns>(case, packet);
            assert_eq!(dns.id_value(), 0xbeef);
            assert_eq!(dns.flags_value(), DNS_FLAG_RECURSION_DESIRED);
            assert!(!dns.is_response());
            assert_eq!(dns.questions().len(), 1);
            assert_eq!(dns.questions()[0].name(), "example.com.");
            assert_eq!(dns.questions()[0].question_type(), DNS_TYPE_A);
            assert_eq!(dns.questions()[0].question_class(), DNS_CLASS_IN);
        }
        "ipv6-icmp-echo-request" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0001, 0, 0, 0, 0, 0x0010)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0002, 0, 0, 0, 0, 0x0020)
            );
            assert_eq!(ipv6.flow_label_value(), 0x12345);
            assert_eq!(ipv6.next_header_value(), IPPROTO_ICMPV6);
            assert_eq!(ipv6.hop_limit_value(), 64);

            let icmpv6 = expect_layer::<Icmpv6>(case, packet);
            assert_eq!(icmpv6.icmp_type_value(), ICMPV6_ECHO_REQUEST);
            assert_eq!(icmpv6.kind_value(), Some(IcmpKind::EchoRequest));
            assert_eq!(icmpv6.identifier_value(), Some(0x4242));
            assert_eq!(icmpv6.sequence_number_value(), Some(2));
            assert_eq!(
                expect_layer::<Raw>(case, packet).as_bytes(),
                b"libcrafter-ipv6"
            );
        }
        other => panic!("fixture {other} is missing typed field assertions"),
    }
}

fn assert_dhcp_offer_options(case: &ValidFixtureCase, bytes: &[u8]) {
    let options = DhcpOption::decode_all(bytes)
        .unwrap_or_else(|err| panic!("fixture {} should decode DHCP options: {err}", case.path));
    assert_eq!(
        options,
        vec![
            DhcpOption::MessageType(DhcpMessageType::Offer),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 0, 2, 1)),
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::Router(vec![Ipv4Addr::new(192, 0, 2, 1)]),
            DhcpOption::DomainNameServer(vec![
                Ipv4Addr::new(192, 0, 2, 53),
                Ipv4Addr::new(198, 51, 100, 53),
            ]),
            DhcpOption::IpAddressLeaseTime(3_600),
            DhcpOption::End,
        ]
    );

    if case.preserve_exact_bytes {
        let reencoded = encode_dhcp_options(&options);
        assert_eq!(
            reencoded, bytes,
            "fixture {} did not preserve DHCP option bytes",
            case.path
        );
    }
}

fn encode_dhcp_options(options: &[DhcpOption]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for option in options {
        encoded.extend(
            option
                .encode()
                .unwrap_or_else(|err| panic!("DHCP option should re-encode: {err}")),
        );
    }
    encoded
}

fn read_summary_fixture(path: &str) -> String {
    fs::read_to_string(fixture_path(path))
        .unwrap_or_else(|err| panic!("summary fixture {path} should be readable: {err}"))
}

fn parse_malformed_rows(path: &str) -> Vec<MalformedFixtureRow> {
    fixture_str!("malformed/core-decode-corpus.hex")
        .lines()
        .filter_map(|line| parse_malformed_row(path, line))
        .collect()
}

fn parse_malformed_row(path: &str, line: &str) -> Option<MalformedFixtureRow> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let fields = line.split('|').collect::<Vec<_>>();
    let (name, target, expected_kind, expected_context_or_field, hex) = match fields.as_slice() {
        [name, target, hex] => (*name, *target, None, None, *hex),
        [name, target, expected_kind, expected_context_or_field, hex] => (
            *name,
            *target,
            Some((*expected_kind).to_string()),
            Some((*expected_context_or_field).to_string()),
            *hex,
        ),
        _ => panic!(
            "malformed fixture {path} row {line:?} must have either 3 or 5 pipe-separated fields"
        ),
    };

    Some(MalformedFixtureRow {
        name: name.to_string(),
        target: target.to_string(),
        expected_kind,
        expected_context_or_field,
        bytes: decode_hex(name, hex),
    })
}

fn ensure_fixture_exists(path: &str) {
    let full_path = fixture_path(path);
    assert!(
        full_path.is_file(),
        "catalog fixture {path} must exist at {}",
        full_path.display()
    );
}

fn fixture_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();

    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(&path).unwrap_or_else(|err| {
            panic!(
                "fixture directory {} should be readable: {err}",
                path.display()
            )
        }) {
            let entry = entry.unwrap_or_else(|err| {
                panic!(
                    "fixture directory {} contained unreadable entry: {err}",
                    path.display()
                )
            });
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }

    files.sort();
    files
}

fn assert_fixture_filename_convention(relative: &Path) {
    let relative_str = relative
        .to_str()
        .unwrap_or_else(|| panic!("fixture path {relative:?} should be UTF-8"));
    if relative_str == "README.md"
        || relative.file_name().and_then(|name| name.to_str()) == Some(".gitkeep")
    {
        return;
    }

    let category = relative
        .components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
        .unwrap_or_else(|| panic!("fixture path {relative_str} must have a category"));
    let file_name = relative
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_else(|| panic!("fixture path {relative_str} must have a UTF-8 file name"));

    let base_name = match category {
        "bytes" => strip_allowed_suffix(file_name, &[".bin", ".hex"]),
        "malformed" => strip_allowed_suffix(file_name, &[".bin", ".hex"]),
        "pcaps" => strip_allowed_suffix(file_name, &[".pcap", ".pcapng"]),
        "summaries" => strip_allowed_suffix(file_name, &[".summary.txt", ".summary.json"]),
        _ => panic!("fixture path {relative_str} uses unknown category {category}"),
    };

    assert_lower_dash_name(base_name, relative_str);
}

fn strip_allowed_suffix<'a>(file_name: &'a str, suffixes: &[&str]) -> &'a str {
    suffixes
        .iter()
        .find_map(|suffix| file_name.strip_suffix(suffix))
        .unwrap_or_else(|| panic!("fixture file {file_name} uses an unsupported extension"))
}

fn assert_lower_dash_name(name: &str, label: &str) {
    assert!(!name.is_empty(), "fixture {label} has an empty base name");
    assert!(
        !name.starts_with('-') && !name.ends_with('-') && !name.contains("--"),
        "fixture {label} should use dash-separated name segments"
    );
    assert!(
        name.chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-'),
        "fixture {label} should use lowercase dash-separated ASCII names"
    );
}

#[test]
fn valid_fixture_catalog_decodes_current_bytes() {
    for case in VALID_FIXTURES {
        ensure_fixture_exists(case.path);
        let bytes = fixture_bytes_for_case(case);

        match case.target {
            FixtureDecodeTarget::Packet(target) => {
                let packet = decode_packet(target, &bytes)
                    .unwrap_or_else(|err| panic!("fixture {} should decode: {err}", case.path));
                assert_packet_surface(case, &packet);
                assert_fixture_fields(case, &packet);
                assert_compile_decode_compile(case, target, &packet, &bytes);
            }
            FixtureDecodeTarget::DhcpOptions => assert_dhcp_offer_options(case, &bytes),
        }
    }
}

#[test]
fn fixture_tree_hygiene_matches_readme_conventions() {
    let root = fixture_path("");
    let catalog_paths = VALID_FIXTURES
        .iter()
        .map(|case| case.path)
        .collect::<HashSet<_>>();
    let mut bytes_fixture_paths = HashSet::new();

    for file in fixture_files(&root) {
        let relative = file.strip_prefix(&root).unwrap_or_else(|err| {
            panic!(
                "fixture path {} should be under root: {err}",
                file.display()
            )
        });
        assert_fixture_filename_convention(relative);

        let is_gitkeep = relative.file_name().and_then(|name| name.to_str()) == Some(".gitkeep");
        if !is_gitkeep
            && relative
                .components()
                .next()
                .and_then(|component| component.as_os_str().to_str())
                == Some("bytes")
        {
            let path = relative
                .to_str()
                .unwrap_or_else(|| panic!("fixture path {relative:?} should be UTF-8"));
            bytes_fixture_paths.insert(path.to_string());
        }
    }

    for case in VALID_FIXTURES {
        ensure_fixture_exists(case.path);
        assert!(
            bytes_fixture_paths.contains(case.path),
            "catalog entry {} must live under tests/fixtures/bytes",
            case.path
        );
    }

    for path in bytes_fixture_paths {
        assert!(
            catalog_paths.contains(path.as_str()),
            "bytes fixture {path} must be listed in VALID_FIXTURES"
        );
    }
}

#[test]
fn malformed_corpus_rows_are_well_formed() {
    let rows = parse_malformed_rows("malformed/core-decode-corpus.hex");
    assert!(!rows.is_empty(), "malformed corpus must not be empty");

    let valid_targets = HashSet::from([
        "dhcp",
        "dhcp-options",
        "dns-name",
        "ethernet",
        "ipv4",
        "ipv4-options",
        "ipv6",
        "linux-sll",
        "null-loopback",
        "tcp-options",
    ]);

    for row in rows {
        assert_lower_dash_name(&row.name, &row.name);
        assert!(
            valid_targets.contains(row.target.as_str()),
            "malformed fixture {} has unknown target {}",
            row.name,
            row.target
        );
        assert!(
            !row.bytes.is_empty(),
            "malformed fixture {} should carry input bytes",
            row.name
        );
        if let Some(expected_kind) = &row.expected_kind {
            assert_lower_dash_name(expected_kind, &row.name);
        }
    }
}

#[test]
fn summary_fixture_reader_matches_current_summary_fixture() {
    let packet = decode_packet(PacketDecodeTarget::Raw, b"Hello, agents!")
        .expect("raw fixture should decode");
    let expected = read_summary_fixture("summaries/raw-hello-agents.summary.txt");
    let actual = format!(
        "summary:\n{}\n\nshow:\n{}\n\nhexdump:\n{}\n\nraw_string_lossy_debug:\n{:?}\n",
        packet.summary(),
        packet.show(),
        packet.hexdump().expect("raw fixture should hexdump"),
        packet
            .raw_string_lossy()
            .expect("raw fixture should stringify")
    );

    assert_eq!(actual, expected);
}
