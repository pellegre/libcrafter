use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crafter_core::{
    Arp, Dns, Ethernet, Icmp, Icmpv6, Ipv4, Ipv6, Layer, LinkType, LinuxSll, NetworkLayer,
    NullLoopback, Packet, Raw, Tcp, Udp, Vlan, DNS_FLAG_AUTHENTIC_DATA, DNS_FLAG_AUTHORITATIVE,
    DNS_FLAG_CHECKING_DISABLED, DNS_FLAG_QR_RESPONSE, DNS_FLAG_RECURSION_AVAILABLE,
    DNS_FLAG_RECURSION_DESIRED, DNS_FLAG_TRUNCATED, ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST,
    IPV4_FLAG_DONT_FRAGMENT, IPV4_FLAG_MORE_FRAGMENTS, IPV4_FLAG_RESERVED,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct Manifest {
    cases: Vec<ManifestCase>,
}

#[derive(Debug, Deserialize)]
struct ManifestCase {
    name: String,
    direction: String,
    root: String,
    expected_stack: Vec<String>,
    strict_bytes: bool,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FixtureMetadata {
    name: String,
    direction: String,
    root: String,
    root_decoder: String,
    expected_stack: Vec<String>,
    strict_bytes: bool,
    length: usize,
    hex: String,
    relevant_fields: Vec<RelevantFields>,
}

#[derive(Debug, Deserialize)]
struct RelevantFields {
    layer: String,
    fields: BTreeMap<String, Value>,
}

struct CaseContext<'a> {
    name: &'a str,
    root: &'a str,
    direction: &'a str,
    fixture_path: &'a Path,
}

impl fmt::Display for CaseContext<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "case={} root={} direction={} path={}",
            self.name,
            self.root,
            self.direction,
            self.fixture_path.display()
        )
    }
}

struct DecodedLayer<'a> {
    scapy_name: String,
    layer: &'a dyn Layer,
    raw_after: Option<&'a Raw>,
}

#[test]
fn scapy_generated_fixtures_decode_like_manifest() {
    let fixture_dir = fixture_dir();
    let manifest_path = fixture_dir.join("cases.json");
    let manifest: Manifest = read_json(&manifest_path, "Scapy manifest");

    let mut exercised = 0usize;
    for case in &manifest.cases {
        if case.direction != "scapy_to_libcrafter" {
            continue;
        }

        let bin_path = fixture_dir.join(format!("{}.bin", case.name));
        let metadata_path = fixture_dir.join(format!("{}.json", case.name));
        if case.status.as_deref() != Some("implemented")
            && !bin_path.exists()
            && !metadata_path.exists()
        {
            continue;
        }

        exercised += 1;
        exercise_case(case, &bin_path, &metadata_path);
    }

    assert!(
        exercised > 0,
        "Scapy reference tests found no implemented scapy_to_libcrafter fixtures in {}",
        fixture_dir.display()
    );
}

fn exercise_case(case: &ManifestCase, bin_path: &Path, metadata_path: &Path) {
    let ctx = CaseContext {
        name: &case.name,
        root: &case.root,
        direction: &case.direction,
        fixture_path: bin_path,
    };
    let bytes =
        fs::read(bin_path).unwrap_or_else(|err| panic!("{ctx}: failed to read bytes: {err}"));
    let metadata: FixtureMetadata = read_json(metadata_path, "Scapy fixture metadata");

    assert_eq!(
        metadata.name, case.name,
        "{ctx}: metadata case name drifted"
    );
    assert_eq!(
        metadata.direction, case.direction,
        "{ctx}: metadata direction drifted"
    );
    assert_eq!(metadata.root, case.root, "{ctx}: metadata root drifted");
    assert_eq!(
        metadata.root_decoder, case.root,
        "{ctx}: metadata root_decoder drifted"
    );
    assert_eq!(
        metadata.expected_stack, case.expected_stack,
        "{ctx}: metadata expected_stack drifted"
    );
    assert_eq!(
        metadata.strict_bytes, case.strict_bytes,
        "{ctx}: metadata strict_bytes drifted"
    );
    assert_eq!(
        metadata.length,
        bytes.len(),
        "{ctx}: metadata length does not match fixture bytes"
    );
    assert_eq!(
        metadata.hex,
        hex_bytes(&bytes),
        "{ctx}: metadata hex does not match fixture bytes"
    );

    let decoded = decode_for_root(&case.root, &bytes, &ctx);
    assert_eq!(
        decoded.encoded_len(),
        bytes.len(),
        "{ctx}: decoded packet length changed"
    );

    assert_layer_stack(&decoded, &case.expected_stack, &ctx);
    assert_relevant_fields(&decoded, &metadata, &ctx);

    if case.strict_bytes {
        let compiled = decoded
            .compile()
            .unwrap_or_else(|err| panic!("{ctx}: strict_bytes recompile failed: {err}"));
        assert_eq!(
            compiled.as_bytes(),
            bytes.as_slice(),
            "{ctx}: strict_bytes recompile mismatch\nfixture={}\ncompiled={}",
            hex_bytes(&bytes),
            hex_bytes(compiled.as_bytes())
        );
    }
}

fn fixture_dir() -> PathBuf {
    if let Some(path) = env::var_os("LIBCRAFTER_SCAPY_FIXTURE_DIR") {
        return PathBuf::from(path);
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/scapy")
}

fn read_json<T>(path: &Path, label: &str) -> T
where
    T: for<'de> Deserialize<'de>,
{
    let text = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("{label} {} could not be read: {err}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("{label} {} is invalid JSON: {err}", path.display()))
}

fn decode_for_root(root: &str, bytes: &[u8], ctx: &CaseContext<'_>) -> Packet {
    let decoded = match root {
        "link:ethernet" => Packet::decode_from_link(LinkType::Ethernet, bytes),
        "link:linux-cooked" | "link:linux-sll" => {
            Packet::decode_from_link(LinkType::LinuxSll, bytes)
        }
        "link:null-loopback" => Packet::decode_from_link(LinkType::NullLoopback, bytes),
        "link:raw" => Packet::decode_from_link(LinkType::Raw, bytes),
        "l3:ipv4" => Packet::decode_from_l3(NetworkLayer::Ipv4, bytes),
        "l3:ipv6" => Packet::decode_from_l3(NetworkLayer::Ipv6, bytes),
        "l3:raw" => Packet::decode_from_l3(NetworkLayer::Raw, bytes),
        _ => panic!("{ctx}: unsupported manifest root {root}"),
    };

    decoded.unwrap_or_else(|err| panic!("{ctx}: decode failed: {err}"))
}

fn assert_layer_stack(packet: &Packet, expected_stack: &[String], ctx: &CaseContext<'_>) {
    let actual_stack = decoded_layers(packet)
        .iter()
        .map(|layer| layer.scapy_name.clone())
        .collect::<Vec<_>>();
    let comparable_stack = if actual_stack == expected_stack {
        actual_stack.clone()
    } else {
        coalesce_icmpv6_echo_raw_stack(&actual_stack)
    };

    assert_eq!(
        comparable_stack, expected_stack,
        "{ctx}: decoded layer stack disagrees with Scapy metadata; raw Rust stack was {actual_stack:?}"
    );
}

fn coalesce_icmpv6_echo_raw_stack(stack: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(stack.len());
    for name in stack {
        if name == "Raw"
            && out
                .last()
                .is_some_and(|previous: &String| previous.starts_with("ICMPv6Echo"))
        {
            continue;
        }
        out.push(name.clone());
    }
    out
}

fn assert_relevant_fields(packet: &Packet, metadata: &FixtureMetadata, ctx: &CaseContext<'_>) {
    let layers = decoded_layers(packet);
    let mut occurrences = BTreeMap::<String, usize>::new();

    for relevant in &metadata.relevant_fields {
        let occurrence = occurrences.entry(relevant.layer.clone()).or_default();
        let decoded = layers
            .iter()
            .filter(|layer| layer.scapy_name == relevant.layer)
            .nth(*occurrence)
            .unwrap_or_else(|| {
                panic!(
                    "{ctx}: missing decoded layer {} occurrence {} for metadata fields",
                    relevant.layer, occurrence
                )
            });
        *occurrence += 1;

        assert_layer_fields(decoded, &relevant.fields, ctx);
    }
}

fn decoded_layers(packet: &Packet) -> Vec<DecodedLayer<'_>> {
    let layers = packet.iter().collect::<Vec<_>>();
    layers
        .iter()
        .enumerate()
        .map(|(index, layer)| DecodedLayer {
            scapy_name: scapy_layer_name(*layer),
            layer: *layer,
            raw_after: layers
                .get(index + 1)
                .and_then(|next| next.as_any().downcast_ref::<Raw>()),
        })
        .collect()
}

fn scapy_layer_name(layer: &dyn Layer) -> String {
    if layer.as_any().is::<Ethernet>() {
        "Ether".to_string()
    } else if layer.as_any().is::<Arp>() {
        "ARP".to_string()
    } else if layer.as_any().is::<Vlan>() {
        "Dot1Q".to_string()
    } else if layer.as_any().is::<LinuxSll>() {
        "CookedLinux".to_string()
    } else if layer.as_any().is::<NullLoopback>() {
        "Loopback".to_string()
    } else if layer.as_any().is::<Ipv4>() {
        "IP".to_string()
    } else if layer.as_any().is::<Ipv6>() {
        "IPv6".to_string()
    } else if layer.as_any().is::<Udp>() {
        "UDP".to_string()
    } else if layer.as_any().is::<Tcp>() {
        "TCP".to_string()
    } else if layer.as_any().is::<Icmp>() {
        "ICMP".to_string()
    } else if let Some(icmpv6) = layer.as_any().downcast_ref::<Icmpv6>() {
        match icmpv6.icmp_type_value() {
            ICMPV6_ECHO_REQUEST => "ICMPv6EchoRequest".to_string(),
            ICMPV6_ECHO_REPLY => "ICMPv6EchoReply".to_string(),
            _ => "ICMPv6".to_string(),
        }
    } else if layer.as_any().is::<Dns>() {
        "DNS".to_string()
    } else if layer.as_any().is::<Raw>() {
        "Raw".to_string()
    } else {
        layer.name().to_string()
    }
}

fn assert_layer_fields(
    decoded: &DecodedLayer<'_>,
    fields: &BTreeMap<String, Value>,
    ctx: &CaseContext<'_>,
) {
    match decoded.scapy_name.as_str() {
        "Ether" => {
            let layer = typed_layer::<Ethernet>(decoded, ctx);
            for (name, value) in fields {
                match name.as_str() {
                    "dst" => {
                        assert_string(layer.destination().unwrap().to_string(), value, name, ctx)
                    }
                    "src" => assert_string(layer.source().unwrap().to_string(), value, name, ctx),
                    "type" => assert_u64(layer.ethertype_value().unwrap() as u64, value, name, ctx),
                    _ => unsupported_field(decoded, name, ctx),
                }
            }
        }
        "ARP" => {
            let layer = typed_layer::<Arp>(decoded, ctx);
            for (name, value) in fields {
                match name.as_str() {
                    "hwtype" => assert_u64(layer.hardware_type_value() as u64, value, name, ctx),
                    "ptype" => assert_u64(layer.protocol_type_value() as u64, value, name, ctx),
                    "hwlen" => assert_u64(layer.hardware_len_value() as u64, value, name, ctx),
                    "plen" => assert_u64(layer.protocol_len_value() as u64, value, name, ctx),
                    "op" => assert_u64(layer.opcode_value() as u64, value, name, ctx),
                    "hwsrc" => {
                        assert_string(layer.sender_mac().unwrap().to_string(), value, name, ctx)
                    }
                    "hwdst" => {
                        assert_string(layer.target_mac().unwrap().to_string(), value, name, ctx)
                    }
                    "psrc" => {
                        assert_string(layer.sender_ipv4().unwrap().to_string(), value, name, ctx)
                    }
                    "pdst" => {
                        assert_string(layer.target_ipv4().unwrap().to_string(), value, name, ctx)
                    }
                    _ => unsupported_field(decoded, name, ctx),
                }
            }
        }
        "Dot1Q" => {
            let layer = typed_layer::<Vlan>(decoded, ctx);
            for (name, value) in fields {
                match name.as_str() {
                    "prio" => assert_u64(layer.pcp_value() as u64, value, name, ctx),
                    "dei" => assert_u64(u64::from(layer.dei_value()), value, name, ctx),
                    "vlan" => assert_u64(layer.vlan_id_value() as u64, value, name, ctx),
                    "type" => assert_u64(layer.ethertype_value() as u64, value, name, ctx),
                    _ => unsupported_field(decoded, name, ctx),
                }
            }
        }
        "IP" => {
            let layer = typed_layer::<Ipv4>(decoded, ctx);
            for (name, value) in fields {
                match name.as_str() {
                    "version" => assert_u64(layer.version_value() as u64, value, name, ctx),
                    "ihl" => assert_u64(layer.ihl_value() as u64, value, name, ctx),
                    "tos" => assert_u64(layer.tos_value() as u64, value, name, ctx),
                    "len" => {
                        assert_u64(layer.total_length_value().unwrap() as u64, value, name, ctx)
                    }
                    "id" => assert_u64(layer.identification_value() as u64, value, name, ctx),
                    "flags" => {
                        assert_string(scapy_ipv4_flags(layer.flags_value()), value, name, ctx)
                    }
                    "frag" => assert_u64(layer.fragment_offset_value() as u64, value, name, ctx),
                    "ttl" => assert_u64(layer.ttl_value() as u64, value, name, ctx),
                    "proto" => assert_u64(layer.protocol_value() as u64, value, name, ctx),
                    "chksum" => {
                        assert_u64(layer.checksum_value().unwrap() as u64, value, name, ctx)
                    }
                    "src" => assert_string(layer.source().to_string(), value, name, ctx),
                    "dst" => assert_string(layer.destination().to_string(), value, name, ctx),
                    "options" => {
                        assert_empty_array_and_bytes(layer.option_bytes(), value, name, ctx)
                    }
                    _ => unsupported_field(decoded, name, ctx),
                }
            }
        }
        "IPv6" => {
            let layer = typed_layer::<Ipv6>(decoded, ctx);
            for (name, value) in fields {
                match name.as_str() {
                    "version" => assert_u64(layer.version_value() as u64, value, name, ctx),
                    "tc" => assert_u64(layer.traffic_class_value() as u64, value, name, ctx),
                    "fl" => assert_u64(layer.flow_label_value() as u64, value, name, ctx),
                    "plen" => assert_u64(
                        layer.payload_length_value().unwrap() as u64,
                        value,
                        name,
                        ctx,
                    ),
                    "nh" => assert_u64(layer.next_header_value() as u64, value, name, ctx),
                    "hlim" => assert_u64(layer.hop_limit_value() as u64, value, name, ctx),
                    "src" => assert_string(layer.source().to_string(), value, name, ctx),
                    "dst" => assert_string(layer.destination().to_string(), value, name, ctx),
                    _ => unsupported_field(decoded, name, ctx),
                }
            }
        }
        "ICMP" => {
            let layer = typed_layer::<Icmp>(decoded, ctx);
            for (name, value) in fields {
                match name.as_str() {
                    "type" => assert_u64(layer.icmp_type_value() as u64, value, name, ctx),
                    "code" => assert_u64(layer.code_value() as u64, value, name, ctx),
                    "chksum" => {
                        assert_u64(layer.checksum_value().unwrap() as u64, value, name, ctx)
                    }
                    "id" => assert_u64(layer.identifier_value().unwrap() as u64, value, name, ctx),
                    "seq" => assert_u64(
                        layer.sequence_number_value().unwrap() as u64,
                        value,
                        name,
                        ctx,
                    ),
                    "unused" => assert_hex_object_bytes(&[], value, name, ctx),
                    _ => unsupported_field(decoded, name, ctx),
                }
            }
        }
        "ICMPv6EchoRequest" | "ICMPv6EchoReply" => {
            let layer = typed_layer::<Icmpv6>(decoded, ctx);
            for (name, value) in fields {
                match name.as_str() {
                    "type" => assert_u64(layer.icmp_type_value() as u64, value, name, ctx),
                    "code" => assert_u64(layer.code_value() as u64, value, name, ctx),
                    "cksum" => assert_u64(layer.checksum_value().unwrap() as u64, value, name, ctx),
                    "id" => assert_u64(layer.identifier_value().unwrap() as u64, value, name, ctx),
                    "seq" => assert_u64(
                        layer.sequence_number_value().unwrap() as u64,
                        value,
                        name,
                        ctx,
                    ),
                    "data" => {
                        let raw = decoded.raw_after.unwrap_or_else(|| {
                            panic!("{ctx}: ICMPv6 data field had no following Raw payload")
                        });
                        assert_hex_object_bytes(raw.as_bytes(), value, name, ctx);
                    }
                    _ => unsupported_field(decoded, name, ctx),
                }
            }
        }
        "UDP" => {
            let layer = typed_layer::<Udp>(decoded, ctx);
            for (name, value) in fields {
                match name.as_str() {
                    "sport" => assert_u64(layer.source_port_value() as u64, value, name, ctx),
                    "dport" => assert_u64(layer.destination_port_value() as u64, value, name, ctx),
                    "len" => assert_u64(layer.length_value().unwrap() as u64, value, name, ctx),
                    "chksum" => {
                        assert_u64(layer.checksum_value().unwrap() as u64, value, name, ctx)
                    }
                    _ => unsupported_field(decoded, name, ctx),
                }
            }
        }
        "DNS" => {
            let layer = typed_layer::<Dns>(decoded, ctx);
            for (name, value) in fields {
                match name.as_str() {
                    "id" => assert_u64(layer.id_value() as u64, value, name, ctx),
                    "qr" => assert_u64(dns_flag(layer, DNS_FLAG_QR_RESPONSE), value, name, ctx),
                    "opcode" => assert_u64(
                        ((layer.flags_value() >> 11) & 0x0f) as u64,
                        value,
                        name,
                        ctx,
                    ),
                    "aa" => assert_u64(dns_flag(layer, DNS_FLAG_AUTHORITATIVE), value, name, ctx),
                    "tc" => assert_u64(dns_flag(layer, DNS_FLAG_TRUNCATED), value, name, ctx),
                    "rd" => assert_u64(
                        dns_flag(layer, DNS_FLAG_RECURSION_DESIRED),
                        value,
                        name,
                        ctx,
                    ),
                    "ra" => assert_u64(
                        dns_flag(layer, DNS_FLAG_RECURSION_AVAILABLE),
                        value,
                        name,
                        ctx,
                    ),
                    "z" => assert_u64(((layer.flags_value() >> 6) & 0x01) as u64, value, name, ctx),
                    "ad" => assert_u64(dns_flag(layer, DNS_FLAG_AUTHENTIC_DATA), value, name, ctx),
                    "cd" => assert_u64(
                        dns_flag(layer, DNS_FLAG_CHECKING_DISABLED),
                        value,
                        name,
                        ctx,
                    ),
                    "rcode" => assert_u64((layer.flags_value() & 0x0f) as u64, value, name, ctx),
                    "qdcount" => assert_u64(layer.questions().len() as u64, value, name, ctx),
                    "ancount" => assert_u64(layer.answers().len() as u64, value, name, ctx),
                    "nscount" => assert_u64(layer.authorities().len() as u64, value, name, ctx),
                    "arcount" => assert_u64(layer.additionals().len() as u64, value, name, ctx),
                    "qd" => assert_dns_question_markers(layer.questions().len(), value, name, ctx),
                    "an" => assert_empty_array_len(layer.answers().len(), value, name, ctx),
                    "ns" => assert_empty_array_len(layer.authorities().len(), value, name, ctx),
                    "ar" => assert_empty_array_len(layer.additionals().len(), value, name, ctx),
                    _ => unsupported_field(decoded, name, ctx),
                }
            }
        }
        "Raw" => {
            let layer = typed_layer::<Raw>(decoded, ctx);
            for (name, value) in fields {
                match name.as_str() {
                    "load" => assert_hex_object_bytes(layer.as_bytes(), value, name, ctx),
                    _ => unsupported_field(decoded, name, ctx),
                }
            }
        }
        _ => panic!(
            "{ctx}: no Scapy metadata field assertions are implemented for layer {}",
            decoded.scapy_name
        ),
    }
}

fn typed_layer<'a, T>(decoded: &'a DecodedLayer<'_>, ctx: &CaseContext<'_>) -> &'a T
where
    T: Layer,
{
    decoded
        .layer
        .as_any()
        .downcast_ref::<T>()
        .unwrap_or_else(|| {
            panic!(
                "{ctx}: decoded layer {} had unexpected Rust type",
                decoded.scapy_name
            )
        })
}

fn unsupported_field(decoded: &DecodedLayer<'_>, field: &str, ctx: &CaseContext<'_>) -> ! {
    panic!(
        "{ctx}: no assertion implemented for Scapy field {}.{}",
        decoded.scapy_name, field
    );
}

fn assert_string(actual: String, expected: &Value, field: &str, ctx: &CaseContext<'_>) {
    let expected = expected
        .as_str()
        .unwrap_or_else(|| panic!("{ctx}: field {field} expected a string in metadata"));
    assert_eq!(actual, expected, "{ctx}: field {field} mismatch");
}

fn assert_u64(actual: u64, expected: &Value, field: &str, ctx: &CaseContext<'_>) {
    let expected = expected
        .as_u64()
        .unwrap_or_else(|| panic!("{ctx}: field {field} expected an unsigned integer in metadata"));
    assert_eq!(actual, expected, "{ctx}: field {field} mismatch");
}

fn assert_hex_object_bytes(actual: &[u8], expected: &Value, field: &str, ctx: &CaseContext<'_>) {
    let expected_hex = expected
        .get("hex")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{ctx}: field {field} expected a {{hex, ascii}} object"));
    assert_eq!(
        hex_bytes(actual),
        expected_hex,
        "{ctx}: raw payload field {field} mismatch"
    );
}

fn assert_empty_array_and_bytes(
    actual_bytes: &[u8],
    expected: &Value,
    field: &str,
    ctx: &CaseContext<'_>,
) {
    assert_empty_array_len(0, expected, field, ctx);
    assert!(
        actual_bytes.is_empty(),
        "{ctx}: field {field} expected empty option bytes but decoded {}",
        hex_bytes(actual_bytes)
    );
}

fn assert_empty_array_len(actual_len: usize, expected: &Value, field: &str, ctx: &CaseContext<'_>) {
    let expected = expected
        .as_array()
        .unwrap_or_else(|| panic!("{ctx}: field {field} expected an array in metadata"));
    assert!(
        expected.is_empty(),
        "{ctx}: field {field} has non-empty metadata not yet covered by this reference test"
    );
    assert_eq!(actual_len, 0, "{ctx}: field {field} mismatch");
}

fn assert_dns_question_markers(
    actual_len: usize,
    expected: &Value,
    field: &str,
    ctx: &CaseContext<'_>,
) {
    let expected = expected
        .as_array()
        .unwrap_or_else(|| panic!("{ctx}: field {field} expected an array in metadata"));
    assert_eq!(
        actual_len,
        expected.len(),
        "{ctx}: field {field} question count mismatch"
    );
    for item in expected {
        assert_eq!(
            item.as_str(),
            Some("DNSQR"),
            "{ctx}: field {field} contains an unsupported DNS marker"
        );
    }
}

fn scapy_ipv4_flags(flags: u8) -> String {
    let mut names = Vec::new();
    if flags & IPV4_FLAG_RESERVED != 0 {
        names.push("evil");
    }
    if flags & IPV4_FLAG_DONT_FRAGMENT != 0 {
        names.push("DF");
    }
    if flags & IPV4_FLAG_MORE_FRAGMENTS != 0 {
        names.push("MF");
    }
    names.join("+")
}

fn dns_flag(dns: &Dns, flag: u16) -> u64 {
    u64::from(dns.flags_value() & flag != 0)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
