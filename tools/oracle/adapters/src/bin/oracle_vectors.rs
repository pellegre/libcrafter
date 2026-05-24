#[path = "oracle_vectors/cases.rs"]
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
        "usage: cargo run -p oracle-adapters --bin oracle_vectors -- [--list|--json]\n\nEmit deterministic libcrafter packet vectors for oracle reference validation."
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
            "case_source": "tools/oracle/adapters/src/bin/oracle_vectors/cases.rs"
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
            "case_source": "oracle_vectors",
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
        "IP" => "ipv4",
        "IPv6" => "ipv6",
        "IPv6ExtHdrFragment" => "ipv6_fragment",
        "IPv6ExtHdrRouting" | "IPv6ExtHdrSegmentRouting" => "ipv6_routing",
        "Loopback" => "null_loopback",
        "Raw" => "payload",
        "TCP" => "tcp",
        "UDP" => "udp",
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
