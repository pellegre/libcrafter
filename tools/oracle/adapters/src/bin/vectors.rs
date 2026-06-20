#[path = "vectors/cases.rs"]
mod cases;

use serde_json::{json, Map, Value};
use std::env;
use std::error::Error;
use std::io;

type ExampleResult<T> = std::result::Result<T, Box<dyn Error>>;

const DIRECTION: &str = "libcrafter_to_reference";
const ROUNDTRIP_DIRECTION: &str = "roundtrip";
const GENERATOR: &str = "libcrafter oracle vector emitter";

fn main() -> ExampleResult<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_usage();
        return Ok(());
    }

    let manifest = build_manifest()?;
    if args.iter().any(|arg| arg == "--list") {
        let cases = manifest
            .get("cases")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid_data("oracle manifest cases must be an array"))?;
        for case in cases {
            let object = json_object(case, "oracle case")?;
            println!(
                "{}\t{}\t{}",
                string_field(object, "name")?,
                string_field(object, "root")?,
                string_field(object, "summary").unwrap_or("")
            );
        }
        return Ok(());
    }

    if args.is_empty() || args.iter().any(|arg| arg == "--json") {
        serde_json::to_writer_pretty(io::stdout(), &manifest)?;
        println!();
        return Ok(());
    }

    Err(format!("unknown arguments: {}", args.join(" ")).into())
}

fn print_usage() {
    println!(
        "usage: cargo run -p oracle-adapters --bin vectors -- [--list|--json]\n\nEmit deterministic libcrafter packet vectors for oracle reference validation."
    );
}

fn build_manifest() -> ExampleResult<Value> {
    let case_inputs = cases::build_cases()?;
    let mut cases = Vec::with_capacity(case_inputs.len());
    for case in &case_inputs {
        cases.push(oracle_case(case)?);
    }

    Ok(json!({
        "schema_version": 1,
        "direction": DIRECTION,
        "directions": [DIRECTION, ROUNDTRIP_DIRECTION],
        "generator": GENERATOR,
        "cases": cases,
        "metadata": {
            "case_source": "tools/oracle/adapters/src/bin/vectors/cases.rs"
        }
    }))
}

fn oracle_case(case: &cases::Vector) -> ExampleResult<Value> {
    let raw_hex = case.raw_hex.as_str();
    let expected_stack = normalize_stack(&case.expected_stack);
    let field_assertions = normalize_field_assertions(&case.field_assertions)?;
    let assertion_fields = assertion_fields(&field_assertions)?;
    let feature_tags = case_feature_tags(case, &expected_stack);

    let mut output = Map::new();
    output.insert("name".to_string(), json!(case.name));
    output.insert("family".to_string(), json!(case.family));
    output.insert("feature_tags".to_string(), json!(feature_tags.clone()));
    output.insert("direction".to_string(), json!(DIRECTION));
    output.insert(
        "directions".to_string(),
        json!([DIRECTION, ROUNDTRIP_DIRECTION]),
    );
    output.insert("root".to_string(), json!(case.root));
    output.insert("root_decoder".to_string(), json!(case.root_decoder));
    output.insert(
        "expected_stack".to_string(),
        Value::Array(expected_stack.clone()),
    );
    output.insert("field_assertions".to_string(), field_assertions.clone());
    output.insert("strict_bytes".to_string(), json!(case.strict_bytes));
    output.insert("length".to_string(), json!(case.length));
    output.insert("raw_hex".to_string(), json!(raw_hex));
    output.insert("hex".to_string(), json!(raw_hex));
    output.insert("summary".to_string(), json!(case.summary));
    output.insert(
        "expected_decoded".to_string(),
        json!({
            "backend": "libcrafter",
            "layers": expected_stack,
            "fields": assertion_fields,
            "root": case.root_decoder,
            "source_hex": raw_hex,
            "feature_tags": feature_tags,
            "metadata": {
                "assertions_are_partial": true
            }
        }),
    );
    output.insert(
        "metadata".to_string(),
        json!({
            "case_source": "vectors",
            "assertions_are_partial": true
        }),
    );

    Ok(Value::Object(output))
}

fn case_feature_tags(case: &cases::Vector, expected_stack: &[Value]) -> Vec<String> {
    let mut tags = vec![case.family.to_string()];
    for layer in expected_stack {
        if let Some(layer) = layer.as_str() {
            tags.push(layer.to_string());
        }
    }
    dedupe(tags)
}

fn normalize_stack(stack: &[&str]) -> Vec<Value> {
    stack
        .iter()
        .map(|layer| Value::String(normalize_layer_name(layer)))
        .collect()
}

fn normalize_field_assertions(assertions: &[cases::FieldAssertion]) -> ExampleResult<Value> {
    let mut output = Vec::with_capacity(assertions.len());
    for assertion in assertions {
        let fields = assertion
            .fields
            .as_object()
            .ok_or_else(|| invalid_data("field assertion fields must be an object"))?;
        let normalized_layer = normalize_layer_name(assertion.layer);
        output.push(json!({
            "layer": normalized_layer,
            "fields": normalize_fields(&normalized_layer, fields)?
        }));
    }
    Ok(Value::Array(output))
}

fn normalize_fields(layer: &str, fields: &Map<String, Value>) -> ExampleResult<Value> {
    if layer == "payload" {
        return normalize_payload_fields(fields);
    }

    let mut output = Map::new();
    for (name, value) in fields {
        let normalized_name = normalize_field_name(layer, name);
        output.insert(
            normalized_name.clone(),
            normalize_field_value(layer, &normalized_name, value),
        );
    }
    Ok(Value::Object(output))
}

fn normalize_payload_fields(fields: &Map<String, Value>) -> ExampleResult<Value> {
    let mut output = Map::new();
    if let Some(load) = fields.get("load") {
        if let Some(load_object) = load.as_object() {
            if let Some(hex) = load_object.get("hex").and_then(Value::as_str) {
                output.insert("hex".to_string(), json!(hex));
                output.insert("length".to_string(), json!(hex.len() / 2));
            }
            if let Some(ascii) = load_object.get("ascii").and_then(Value::as_str) {
                output.insert("ascii".to_string(), json!(ascii));
            }
        } else if let Some(hex) = load.as_str() {
            output.insert("hex".to_string(), json!(hex));
            output.insert("length".to_string(), json!(hex.len() / 2));
        }
    }
    Ok(Value::Object(output))
}

fn normalize_layer_name(layer: &str) -> String {
    if layer.starts_with("ICMPv6") {
        return "icmpv6".to_string();
    }

    match layer {
        "ARP" => "arp",
        "BOOTP" | "DHCP" => "dhcp",
        "CookedLinux" => "linux_sll",
        "DNS" => "dns",
        "Dot1Q" => "vlan",
        "Ether" => "ethernet",
        "ICMP" => "icmp",
        "Igmp" => "igmp",
        "IgmpExtension" => "igmp_extension",
        "IgmpQuery" => "igmp_query",
        "IgmpReport" => "igmp_report",
        "IP" => "ipv4",
        "IPv6" => "ipv6",
        "IPv6ExtHdrFragment" => "ipv6_fragment",
        "IPv6ExtHdrRouting" | "IPv6ExtHdrSegmentRouting" => "ipv6_routing",
        "Loopback" => "null_loopback",
        "Raw" => "payload",
        "TCP" => "tcp",
        "UDP" => "udp",
        "UdpOptions" => "UdpOptions",
        _ => return layer.to_ascii_lowercase(),
    }
    .to_string()
}

fn normalize_field_name(layer: &str, field: &str) -> String {
    let layer_name = match (layer, field) {
        ("arp", "hwlen") => "hardware_length",
        ("arp", "hwtype") => "hardware_type",
        ("arp", "plen") => "protocol_length",
        ("dhcp", "ciaddr") => "client_ip",
        ("dhcp", "chaddr") => "client_hardware_address",
        ("dhcp", "giaddr") => "relay_ip",
        ("dhcp", "htype") => "hardware_type",
        ("dhcp", "hlen") => "hardware_length",
        ("dhcp", "siaddr") => "server_ip",
        ("dhcp", "xid") => "transaction_id",
        ("dhcp", "yiaddr") => "your_ip",
        ("dns", "id") => "transaction_id",
        ("dns", "qr") => "is_response",
        ("dns", "rcode") => "response_code",
        ("ethernet", "type") => "ethertype",
        ("icmp", "id") | ("icmpv6", "id") => "identifier",
        ("icmp", "seq") | ("icmpv6", "seq") => "sequence",
        ("icmpv6", "cksum") => "checksum",
        ("ipv4", "id") => "identification",
        ("ipv4", "ihl") => "header_length",
        ("ipv6", "fl") => "flow_label",
        ("ipv6", "plen") => "payload_length",
        ("ipv6", "tc") => "traffic_class",
        ("linux_sll", "lladdrlen") => "address_length",
        ("linux_sll", "lladdrtype") => "address_type",
        ("linux_sll", "pkttype") => "packet_type",
        ("linux_sll", "src") => "source_address",
        ("tcp", "ack") => "acknowledgement",
        ("tcp", "seq") => "sequence",
        ("vlan", "dei") => "drop_eligible",
        ("vlan", "prio") => "priority",
        ("vlan", "type") => "ethertype",
        ("vlan", "vlan") => "vlan_id",
        _ => field,
    };

    match layer_name {
        "chksum" => "checksum",
        "dataofs" => "data_offset",
        "dport" => "dst_port",
        "frag" => "fragment_offset",
        "hlim" => "hop_limit",
        "hwdst" => "target_hardware_address",
        "hwsrc" => "sender_hardware_address",
        "len" => "length",
        "nh" => "next_header",
        "op" => "opcode",
        "pdst" => "target_protocol_address",
        "proto" => "protocol",
        "psrc" => "sender_protocol_address",
        "ptype" => "protocol_type",
        "sport" => "src_port",
        "urgptr" => "urgent_pointer",
        _ => layer_name,
    }
    .to_string()
}

fn normalize_field_value(layer: &str, field: &str, value: &Value) -> Value {
    if field == "flags" {
        return normalize_flags(value);
    }
    if field == "is_response" {
        if let Some(value) = value.as_i64() {
            return json!(value != 0);
        }
    }
    if layer == "linux_sll" && field == "source_address" {
        if let Some(object) = value.as_object() {
            if let Some(hex) = object.get("hex").and_then(Value::as_str) {
                return json!({ "hex": hex });
            }
        }
    }
    value.clone()
}

fn normalize_flags(value: &Value) -> Value {
    if let Some(text) = value.as_str() {
        if text.is_empty() {
            json!("none")
        } else {
            json!(text
                .to_ascii_lowercase()
                .replace('+', "|")
                .replace(' ', "_"))
        }
    } else {
        value.clone()
    }
}

fn assertion_fields(assertions: &Value) -> ExampleResult<Value> {
    let assertions = assertions
        .as_array()
        .ok_or_else(|| invalid_data("field_assertions must be an array"))?;
    let mut fields = Map::new();
    for assertion in assertions {
        let assertion = json_object(assertion, "field assertion")?;
        let layer = string_field(assertion, "layer")?;
        let key = unique_field_key(&fields, layer);
        fields.insert(
            key,
            assertion
                .get("fields")
                .cloned()
                .ok_or_else(|| invalid_data("field assertion is missing fields"))?,
        );
    }
    Ok(Value::Object(fields))
}

fn unique_field_key(existing: &Map<String, Value>, layer: &str) -> String {
    if !existing.contains_key(layer) {
        return layer.to_string();
    }

    let mut index = 2;
    loop {
        let candidate = format!("{layer}#{index}");
        if !existing.contains_key(&candidate) {
            return candidate;
        }
        index += 1;
    }
}

fn dedupe(values: Vec<String>) -> Vec<String> {
    let mut output = Vec::new();
    for value in values {
        if !output.contains(&value) {
            output.push(value);
        }
    }
    output
}

fn json_object<'a>(value: &'a Value, label: &str) -> ExampleResult<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid_data(format!("{label} must be an object")).into())
}

fn string_field<'a>(object: &'a Map<String, Value>, key: &str) -> ExampleResult<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_data(format!("{key} must be a string")).into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod icmpv4_oracle {
    //! Offline validation that the ICMPv4 oracle vectors materialize, decode,
    //! and round-trip byte-for-byte through the same libcrafter surface the
    //! oracle adapters use. These are static, documentation-address-only checks
    //! with no live traffic.

    use super::cases;
    use crafter::prelude::*;

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert!(hex.len() % 2 == 0, "raw_hex must be even length");
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("valid hex"))
            .collect()
    }

    fn icmpv4_vectors() -> Vec<cases::Vector> {
        cases::build_cases()
            .expect("oracle cases build")
            .into_iter()
            .filter(|vector| vector.name.starts_with("crafter-icmpv4-"))
            .collect()
    }

    // Every ICMPv4 message group we emit is decodable from raw L3 bytes and
    // recompiles to the exact same bytes, satisfying the oracle strict_bytes
    // contract for the reference-backend comparison.
    #[test]
    fn icmpv4_oracle_vectors_roundtrip_strict_bytes() {
        let vectors = icmpv4_vectors();
        assert!(
            vectors.len() >= 15,
            "expected the full ICMPv4 message-group coverage, found {}",
            vectors.len()
        );
        for vector in vectors {
            assert_eq!(vector.root_decoder, "l3:ipv4", "{}", vector.name);
            assert!(vector.strict_bytes, "{}", vector.name);
            let bytes = decode_hex(&vector.raw_hex);
            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes)
                .unwrap_or_else(|error| panic!("decode {}: {error}", vector.name));
            let recompiled = decoded
                .compile()
                .unwrap_or_else(|error| panic!("recompile {}: {error}", vector.name));
            assert_eq!(
                recompiled.as_bytes(),
                bytes.as_slice(),
                "byte-for-byte roundtrip failed for {}",
                vector.name
            );
            // The ICMPv4 header is always typed.
            assert!(
                decoded.layer::<Icmpv4>().is_some(),
                "missing typed Icmpv4 layer for {}",
                vector.name
            );
        }
    }

    // The error-family vectors expose a typed quoted IPv4 datagram, so a
    // generated tool can inspect the original packet that triggered the error.
    #[test]
    fn icmpv4_oracle_error_vectors_expose_quoted_datagram() {
        for name in [
            "crafter-icmpv4-destination-unreachable",
            "crafter-icmpv4-time-exceeded",
            "crafter-icmpv4-parameter-problem",
            "crafter-icmpv4-redirect",
            "crafter-icmpv4-frag-needed-next-hop-mtu",
        ] {
            let vector = icmpv4_vectors()
                .into_iter()
                .find(|vector| vector.name == name)
                .unwrap_or_else(|| panic!("missing oracle vector {name}"));
            let bytes = decode_hex(&vector.raw_hex);
            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes).expect("decode error");
            let quoted = decoded
                .layer::<Icmpv4QuotedIp>()
                .unwrap_or_else(|| panic!("missing quoted datagram for {name}"));
            let inner = quoted
                .quoted_layer::<Ipv4>()
                .unwrap_or_else(|| panic!("quoted datagram is not IPv4 for {name}"));
            assert_eq!(
                inner.destination(),
                std::net::Ipv4Addr::new(198, 51, 100, 20)
            );
        }
    }

    // The RFC 4884 / 4950 / 5837 / 8335 extension vectors decode into their
    // typed extension layers; unknown-object fallback is covered by the crate's
    // own tests, so here we assert the typed split the oracle relies on.
    #[test]
    fn icmpv4_oracle_extension_vectors_expose_typed_objects() {
        let vectors = icmpv4_vectors();
        let find = |name: &str| {
            vectors
                .iter()
                .find(|vector| vector.name == name)
                .unwrap_or_else(|| panic!("missing oracle vector {name}"))
        };

        let mpls = find("crafter-icmpv4-extension-mpls");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &decode_hex(&mpls.raw_hex))
            .expect("decode mpls");
        assert!(decoded.layer::<IcmpExtension>().is_some());
        assert!(decoded.layer::<IcmpExtensionMpls>().is_some());

        let info = find("crafter-icmpv4-extension-interface-info");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &decode_hex(&info.raw_hex))
            .expect("decode interface info");
        assert!(decoded.layer::<IcmpExtensionInterfaceInfo>().is_some());

        let extended = find("crafter-icmpv4-extended-echo-request");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &decode_hex(&extended.raw_hex))
            .expect("decode extended echo");
        assert!(decoded.layer::<IcmpExtensionInterfaceId>().is_some());
    }

    // The legacy/deprecated assigned types stay raw-compatible and round-trip
    // without being rejected merely because they are deprecated.
    #[test]
    fn icmpv4_oracle_legacy_vector_is_raw_compatible() {
        let vector = icmpv4_vectors()
            .into_iter()
            .find(|vector| vector.name == "crafter-icmpv4-legacy-traceroute")
            .expect("missing legacy traceroute vector");
        let bytes = decode_hex(&vector.raw_hex);
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes).expect("decode legacy");
        let icmp = decoded.layer::<Icmpv4>().expect("typed icmp header");
        assert_eq!(icmp.icmp_type_value(), ICMP_TRACEROUTE);
        assert_eq!(
            decoded.compile().expect("recompile").as_bytes(),
            bytes.as_slice()
        );
    }
}

#[cfg(test)]
mod igmp_oracle {
    //! Offline validation for the IGMP oracle vectors. The cases stay rooted at
    //! documentation IPv4 addresses and only exercise libcrafter decode and
    //! compile paths; no live traffic is emitted.

    use super::cases;
    use crafter::prelude::*;
    use crafter::protocols::igmp::IgmpExtension;

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert!(hex.len() % 2 == 0, "raw_hex must be even length");
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("valid hex"))
            .collect()
    }

    fn igmp_vectors() -> Vec<cases::Vector> {
        cases::build_cases()
            .expect("oracle cases build")
            .into_iter()
            .filter(|vector| vector.name.starts_with("crafter-igmp-"))
            .collect()
    }

    #[test]
    fn igmp_oracle_vectors_roundtrip_strict_bytes() {
        let vectors = igmp_vectors();
        assert_eq!(vectors.len(), 4, "expected IGMP oracle coverage");
        for vector in vectors {
            assert_eq!(vector.root_decoder, "l3:ipv4", "{}", vector.name);
            assert!(vector.strict_bytes, "{}", vector.name);
            let bytes = decode_hex(&vector.raw_hex);
            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes)
                .unwrap_or_else(|error| panic!("decode {}: {error}", vector.name));
            assert!(
                decoded.layer::<Igmp>().is_some(),
                "missing typed IGMP layer for {}",
                vector.name
            );
            assert_eq!(
                decoded
                    .compile()
                    .unwrap_or_else(|error| panic!("recompile {}: {error}", vector.name))
                    .as_bytes(),
                bytes.as_slice(),
                "byte-for-byte roundtrip failed for {}",
                vector.name
            );
        }
    }

    #[test]
    fn igmp_oracle_vectors_expose_typed_bodies() {
        let vectors = igmp_vectors();
        let find = |name: &str| {
            vectors
                .iter()
                .find(|vector| vector.name == name)
                .unwrap_or_else(|| panic!("missing oracle vector {name}"))
        };

        let query = find("crafter-igmp-v3-query-with-sources");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &decode_hex(&query.raw_hex))
            .expect("decode IGMP query");
        let query = decoded.layer::<IgmpQuery>().expect("typed IGMP query body");
        assert_eq!(query.number_of_sources_value(), 2);

        let report = find("crafter-igmp-v3-report-with-extension");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &decode_hex(&report.raw_hex))
            .expect("decode IGMP report");
        let report = decoded
            .layer::<IgmpReport>()
            .expect("typed IGMP report body");
        assert_eq!(report.number_of_group_records_value(), 1);
        assert!(decoded.layer::<IgmpExtension>().is_some());
    }
}
