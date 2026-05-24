use crafter::core::{
    Arp, Dhcp, Dns, Ethernet, Icmp, Icmpv6, Ipv4, Ipv6, Ipv6FragmentHeader,
    Ipv6MobileRoutingHeader, Ipv6RoutingHeader, Ipv6SegmentRoutingHeader, Layer, LinkType,
    LinuxSll, NetworkLayer, NullLoopback, Packet, Raw, Tcp, Udp, Vlan, DNS_FLAG_AUTHENTIC_DATA,
    DNS_FLAG_AUTHORITATIVE, DNS_FLAG_CHECKING_DISABLED, DNS_FLAG_QR_RESPONSE,
    DNS_FLAG_RECURSION_AVAILABLE, DNS_FLAG_RECURSION_DESIRED, DNS_FLAG_TRUNCATED,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

type ExampleResult<T> = std::result::Result<T, Box<dyn Error>>;

const BACKEND_NAME: &str = "libcrafter";

#[derive(Debug)]
struct Args {
    input: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct EncodedVector {
    raw_hex: String,
    root: Option<String>,
    decoder: Option<String>,
    #[serde(default)]
    plan: Option<PacketPlan>,
}

#[derive(Debug, Deserialize, Default)]
struct PacketPlan {
    #[serde(default)]
    feature_tags: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DecodedModel {
    backend: &'static str,
    layers: Vec<String>,
    fields: BTreeMap<String, BTreeMap<String, Value>>,
    root: Option<String>,
    source_hex: String,
    feature_tags: Vec<String>,
    metadata: Value,
}

fn main() -> ExampleResult<()> {
    let args = parse_args()?;
    let input = read_input(args.input)?;
    let document: Value = serde_json::from_str(&input)?;
    let vectors = extract_vectors(&document)?;
    let mut decoded = Vec::with_capacity(vectors.len());

    for vector in vectors {
        decoded.push(decode_vector(&vector)?);
    }

    let report = json!({
        "artifacts": [],
        "artifact_paths": [],
        "backend": BACKEND_NAME,
        "backend_versions": {},
        "count": decoded.len(),
        "failures": [],
        "libcrafter": {
            "version": env!("CARGO_PKG_VERSION")
        },
        "metadata": {
            "decoded": decoded,
            "input_backend": document.get("backend").cloned().unwrap_or(Value::Null),
            "requested_count": document.pointer("/metadata/requested_count").cloned().unwrap_or(Value::Null)
        },
        "mode": document.get("mode").cloned().unwrap_or_else(|| Value::String("offline".to_string())),
        "profile": document.get("profile").cloned().unwrap_or(Value::Null),
        "reproduction_commands": [],
        "results": [],
        "seed": document.get("seed").cloned().unwrap_or(Value::Null),
        "selected_specs": document.get("selected_specs").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "status": "decoded"
    });

    serde_json::to_writer_pretty(io::stdout(), &report)?;
    println!();
    Ok(())
}

fn parse_args() -> ExampleResult<Args> {
    let mut input = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--input" => {
                let value = args.next().ok_or("--input requires a path or -")?;
                input = input_path(value);
            }
            _ if arg.starts_with("--input=") => {
                let value = arg
                    .strip_prefix("--input=")
                    .expect("--input= prefix already matched");
                input = input_path(value.to_string());
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    Ok(Args { input })
}

fn input_path(value: String) -> Option<PathBuf> {
    if value == "-" {
        None
    } else {
        Some(PathBuf::from(value))
    }
}

fn print_usage() {
    println!(
        "usage: cargo run -p oracle-adapters --bin oracle_decode_vectors -- [--input PATH|-]\n\nDecode oracle raw vectors with libcrafter and emit normalized JSON. Reads stdin when --input is omitted or set to -."
    );
}

fn read_input(input: Option<PathBuf>) -> ExampleResult<String> {
    match input {
        Some(path) => Ok(fs::read_to_string(path)?),
        None => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            Ok(buffer)
        }
    }
}

fn extract_vectors(document: &Value) -> ExampleResult<Vec<EncodedVector>> {
    let vectors = if let Some(value) = document.pointer("/metadata/vectors") {
        value
    } else if let Some(value) = document.get("vectors") {
        value
    } else if document.is_array() {
        document
    } else {
        return Err(
            "input JSON must contain metadata.vectors, vectors, or be a vector array".into(),
        );
    };

    Ok(serde_json::from_value(vectors.clone())?)
}

fn decode_vector(vector: &EncodedVector) -> ExampleResult<DecodedModel> {
    let root = vector
        .root
        .as_deref()
        .or(vector.decoder.as_deref())
        .ok_or("vector is missing root decoder metadata")?;
    let bytes = decode_hex(&vector.raw_hex)?;
    let packet = decode_for_root(root, &bytes)?;
    let feature_tags = vector
        .plan
        .as_ref()
        .map(|plan| plan.feature_tags.clone())
        .unwrap_or_default();
    Ok(normalize_packet(
        &packet,
        Some(normalize_root_name(root).to_string()),
        vector.raw_hex.clone(),
        feature_tags,
    ))
}

fn decode_hex(hex: &str) -> ExampleResult<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err("raw_hex must contain an even number of characters".into());
    }

    let mut out = Vec::with_capacity(hex.len() / 2);
    for index in (0..hex.len()).step_by(2) {
        out.push(u8::from_str_radix(&hex[index..index + 2], 16)?);
    }
    Ok(out)
}

fn decode_for_root(root: &str, bytes: &[u8]) -> ExampleResult<Packet> {
    let decoded = match root {
        "Ether" | "link:ethernet" => Packet::decode_from_link(LinkType::Ethernet, bytes),
        "CookedLinux" | "link:linux-cooked" | "link:linux-sll" => {
            Packet::decode_from_link(LinkType::LinuxSll, bytes)
        }
        "Loopback" | "link:null-loopback" => {
            Packet::decode_from_link(LinkType::NullLoopback, bytes)
        }
        "Raw" | "link:raw" => Packet::decode_from_link(LinkType::Raw, bytes),
        "IP" | "l3:ipv4" => Packet::decode_from_l3(NetworkLayer::Ipv4, bytes),
        "IPv6" | "l3:ipv6" => Packet::decode_from_l3(NetworkLayer::Ipv6, bytes),
        "l3:raw" => Packet::decode_from_l3(NetworkLayer::Raw, bytes),
        _ => return Err(format!("unsupported root decoder: {root}").into()),
    };
    Ok(decoded?)
}

fn normalize_packet(
    packet: &Packet,
    root: Option<String>,
    source_hex: String,
    feature_tags: Vec<String>,
) -> DecodedModel {
    let packet_layers = packet.iter().collect::<Vec<_>>();
    let mut layers = Vec::with_capacity(packet_layers.len());
    let mut fields = BTreeMap::new();
    let mut native_layers = Vec::with_capacity(packet_layers.len());

    for layer in packet_layers {
        let layer_name = normalized_layer_name(layer);
        let layer_fields = normalized_layer_fields(layer);
        layers.push(layer_name.clone());
        let key = field_key(&fields, &layer_name);
        fields.insert(key, layer_fields);
        native_layers.push(json!({
            "fields": inspection_fields(layer),
            "name": layer.name(),
            "summary": layer.summary()
        }));
    }

    DecodedModel {
        backend: BACKEND_NAME,
        layers,
        fields,
        root,
        source_hex,
        feature_tags,
        metadata: json!({
            "native": {
                "summary": packet.summary(),
                "layers": native_layers
            }
        }),
    }
}

fn field_key(existing: &BTreeMap<String, BTreeMap<String, Value>>, layer_name: &str) -> String {
    if !existing.contains_key(layer_name) {
        return layer_name.to_string();
    }

    let mut index = 2;
    loop {
        let candidate = format!("{layer_name}#{index}");
        if !existing.contains_key(&candidate) {
            return candidate;
        }
        index += 1;
    }
}

fn normalized_layer_name(layer: &dyn Layer) -> String {
    if layer.as_any().is::<Ethernet>() {
        "ethernet"
    } else if layer.as_any().is::<Arp>() {
        "arp"
    } else if layer.as_any().is::<Vlan>() {
        "vlan"
    } else if layer.as_any().is::<LinuxSll>() {
        "linux_sll"
    } else if layer.as_any().is::<NullLoopback>() {
        "null_loopback"
    } else if layer.as_any().is::<Ipv4>() {
        "ipv4"
    } else if layer.as_any().is::<Ipv6>() {
        "ipv6"
    } else if layer.as_any().is::<Ipv6FragmentHeader>() {
        "ipv6_fragment"
    } else if layer.as_any().is::<Ipv6RoutingHeader>()
        || layer.as_any().is::<Ipv6MobileRoutingHeader>()
        || layer.as_any().is::<Ipv6SegmentRoutingHeader>()
    {
        "ipv6_routing"
    } else if layer.as_any().is::<Udp>() {
        "udp"
    } else if layer.as_any().is::<Tcp>() {
        "tcp"
    } else if layer.as_any().is::<Icmp>() {
        "icmp"
    } else if layer.as_any().is::<Icmpv6>() {
        "icmpv6"
    } else if layer.as_any().is::<Dns>() {
        "dns"
    } else if layer.as_any().is::<Dhcp>() {
        "dhcp"
    } else if layer.as_any().is::<Raw>() {
        "payload"
    } else {
        layer.name()
    }
    .to_string()
}

fn normalize_root_name(root: &str) -> &str {
    match root {
        "CookedLinux" | "link:linux-sll" => "link:linux-cooked",
        "Ether" => "link:ethernet",
        "IP" => "l3:ipv4",
        "IPv6" => "l3:ipv6",
        "Loopback" => "link:null-loopback",
        "Raw" => "link:raw",
        _ => root,
    }
}

fn normalized_layer_fields(layer: &dyn Layer) -> BTreeMap<String, Value> {
    if let Some(layer) = layer.as_any().downcast_ref::<Ethernet>() {
        return ethernet_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Arp>() {
        return arp_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Vlan>() {
        return vlan_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<LinuxSll>() {
        return linux_sll_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<NullLoopback>() {
        return map([("type", json!(layer.family_value()))]);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Ipv4>() {
        return ipv4_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Ipv6>() {
        return ipv6_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Ipv6FragmentHeader>() {
        return ipv6_fragment_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Ipv6RoutingHeader>() {
        return ipv6_routing_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Ipv6MobileRoutingHeader>() {
        return ipv6_mobile_routing_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Ipv6SegmentRoutingHeader>() {
        return ipv6_segment_routing_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Udp>() {
        return udp_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Tcp>() {
        return tcp_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Icmp>() {
        return icmp_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Icmpv6>() {
        return icmpv6_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Dns>() {
        return dns_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Dhcp>() {
        return dhcp_fields(layer);
    }
    if let Some(layer) = layer.as_any().downcast_ref::<Raw>() {
        return payload_fields(layer);
    }
    BTreeMap::new()
}

fn ethernet_fields(layer: &Ethernet) -> BTreeMap<String, Value> {
    let mut fields = BTreeMap::new();
    if let Some(value) = layer.destination() {
        fields.insert("dst".to_string(), json!(value.to_string()));
    }
    if let Some(value) = layer.source() {
        fields.insert("src".to_string(), json!(value.to_string()));
    }
    if let Some(value) = layer.ethertype_value() {
        fields.insert("ethertype".to_string(), json!(value));
    }
    fields
}

fn arp_fields(layer: &Arp) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("hardware_type", json!(layer.hardware_type_value())),
        ("protocol_type", json!(layer.protocol_type_value())),
        ("hardware_length", json!(layer.hardware_len_value())),
        ("protocol_length", json!(layer.protocol_len_value())),
        ("opcode", json!(layer.opcode_value())),
    ]);
    insert_address(
        &mut fields,
        "sender_hardware_address",
        layer.sender_mac().map(|value| value.to_string()),
        layer.sender_hardware_bytes_value(),
    );
    insert_address(
        &mut fields,
        "target_hardware_address",
        layer.target_mac().map(|value| value.to_string()),
        layer.target_hardware_bytes_value(),
    );
    insert_address(
        &mut fields,
        "sender_protocol_address",
        layer.sender_ipv4().map(|value| value.to_string()),
        layer.sender_protocol_bytes_value(),
    );
    insert_address(
        &mut fields,
        "target_protocol_address",
        layer.target_ipv4().map(|value| value.to_string()),
        layer.target_protocol_bytes_value(),
    );
    fields
}

fn vlan_fields(layer: &Vlan) -> BTreeMap<String, Value> {
    map([
        ("priority", json!(layer.pcp_value())),
        ("drop_eligible", json!(layer.dei_value())),
        ("vlan_id", json!(layer.vlan_id_value())),
        ("ethertype", json!(layer.ethertype_value())),
    ])
}

fn linux_sll_fields(layer: &LinuxSll) -> BTreeMap<String, Value> {
    map([
        ("packet_type", json!(layer.packet_type_value())),
        ("address_type", json!(layer.address_type_value())),
        ("address_length", json!(layer.address_len_value())),
        (
            "source_address",
            json!({
                "hex": hex_bytes(&layer.source_address_value())
            }),
        ),
        ("protocol", json!(layer.protocol_value())),
    ])
}

fn ipv4_fields(layer: &Ipv4) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("version", json!(layer.version_value())),
        ("header_length", json!(layer.ihl_value())),
        ("tos", json!(layer.tos_value())),
        ("identification", json!(layer.identification_value())),
        ("flags", json!(ipv4_flags(layer.flags_value()))),
        ("fragment_offset", json!(layer.fragment_offset_value())),
        ("ttl", json!(layer.ttl_value())),
        ("protocol", json!(layer.protocol_value())),
        ("src", json!(layer.source().to_string())),
        ("dst", json!(layer.destination().to_string())),
        ("options", json!(hex_bytes(layer.option_bytes()))),
    ]);
    if let Some(value) = layer.total_length_value() {
        fields.insert("length".to_string(), json!(value));
    }
    if let Some(value) = layer.checksum_value() {
        fields.insert("checksum".to_string(), json!(value));
    }
    fields
}

fn ipv6_fields(layer: &Ipv6) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("version", json!(layer.version_value())),
        ("traffic_class", json!(layer.traffic_class_value())),
        ("flow_label", json!(layer.flow_label_value())),
        ("next_header", json!(layer.next_header_value())),
        ("hop_limit", json!(layer.hop_limit_value())),
        ("src", json!(layer.source().to_string())),
        ("dst", json!(layer.destination().to_string())),
    ]);
    if let Some(value) = layer.payload_length_value() {
        fields.insert("payload_length".to_string(), json!(value));
    }
    fields
}

fn ipv6_fragment_fields(layer: &Ipv6FragmentHeader) -> BTreeMap<String, Value> {
    map([
        ("next_header", json!(layer.next_header_value())),
        ("reserved", json!(layer.reserved_value())),
        ("fragment_offset", json!(layer.fragment_offset_value())),
        ("res", json!(layer.res_value())),
        ("more_fragments", json!(layer.has_more_fragments())),
        ("identification", json!(layer.identification_value())),
    ])
}

fn ipv6_routing_fields(layer: &Ipv6RoutingHeader) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("next_header", json!(layer.next_header_value())),
        ("type", json!(layer.routing_type_value())),
        ("segments_left", json!(layer.segments_left_value())),
        ("reserved", json!(hex_bytes(layer.type_data_bytes()))),
    ]);
    if let Some(value) = layer.header_ext_len_value() {
        fields.insert("length".to_string(), json!(value));
    }
    fields
}

fn ipv6_mobile_routing_fields(layer: &Ipv6MobileRoutingHeader) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("next_header", json!(layer.next_header_value())),
        ("type", json!(layer.routing_type_value())),
        ("segments_left", json!(layer.segments_left_value())),
        ("reserved", json!(layer.reserved_value())),
        ("addresses", json!([layer.home_address_value().to_string()])),
    ]);
    if let Some(value) = layer.header_ext_len_value() {
        fields.insert("length".to_string(), json!(value));
    }
    fields
}

fn ipv6_segment_routing_fields(layer: &Ipv6SegmentRoutingHeader) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("next_header", json!(layer.next_header_value())),
        ("type", json!(layer.routing_type_value())),
        ("segments_left", json!(layer.segments_left_value())),
        ("last_entry", json!(layer.first_segment_value())),
        ("protected", json!(layer.p_flag_value())),
        ("reserved", json!(layer.reserved_value())),
        ("hmac", json!(layer.hmac_key_id_value())),
        (
            "addresses",
            json!(layer
                .segments()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()),
        ),
    ]);
    if let Some(value) = layer.header_ext_len_value() {
        fields.insert("length".to_string(), json!(value));
    }
    fields
}

fn udp_fields(layer: &Udp) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("src_port", json!(layer.source_port_value())),
        ("dst_port", json!(layer.destination_port_value())),
    ]);
    if let Some(value) = layer.length_value() {
        fields.insert("length".to_string(), json!(value));
    }
    if let Some(value) = layer.checksum_value() {
        fields.insert("checksum".to_string(), json!(value));
    }
    fields
}

fn tcp_fields(layer: &Tcp) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("src_port", json!(layer.source_port_value())),
        ("dst_port", json!(layer.destination_port_value())),
        ("sequence", json!(layer.sequence_number_value())),
        (
            "acknowledgement",
            json!(layer.acknowledgment_number_value()),
        ),
        ("data_offset", json!(layer.data_offset_value())),
        ("reserved", json!(layer.reserved_value())),
        ("flags", json!(tcp_flags(layer.flags_value()))),
        ("window", json!(layer.window_value())),
        ("urgent_pointer", json!(layer.urgent_pointer_value())),
        ("options", json!(hex_bytes(layer.option_bytes()))),
    ]);
    if let Some(value) = layer.checksum_value() {
        fields.insert("checksum".to_string(), json!(value));
    }
    fields
}

fn icmp_fields(layer: &Icmp) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("type", json!(layer.icmp_type_value())),
        ("code", json!(layer.code_value())),
        (
            "rest_of_header",
            json!(hex_bytes(&layer.rest_of_header_value())),
        ),
    ]);
    if let Some(value) = layer.checksum_value() {
        fields.insert("checksum".to_string(), json!(value));
    }
    if let Some(value) = layer.identifier_value() {
        fields.insert("identifier".to_string(), json!(value));
    }
    if let Some(value) = layer.sequence_number_value() {
        fields.insert("sequence".to_string(), json!(value));
    }
    if let Some(value) = layer.length_value() {
        fields.insert("length".to_string(), json!(value));
    }
    fields
}

fn icmpv6_fields(layer: &Icmpv6) -> BTreeMap<String, Value> {
    let mut fields = map([
        ("type", json!(layer.icmp_type_value())),
        ("code", json!(layer.code_value())),
        (
            "rest_of_header",
            json!(hex_bytes(&layer.rest_of_header_value())),
        ),
    ]);
    if let Some(value) = layer.checksum_value() {
        fields.insert("checksum".to_string(), json!(value));
    }
    if let Some(value) = layer.identifier_value() {
        fields.insert("identifier".to_string(), json!(value));
    }
    if let Some(value) = layer.sequence_number_value() {
        fields.insert("sequence".to_string(), json!(value));
    }
    if let Some(value) = layer.length_value() {
        fields.insert("length".to_string(), json!(value));
    }
    fields
}

fn dns_fields(layer: &Dns) -> BTreeMap<String, Value> {
    map([
        ("transaction_id", json!(layer.id_value())),
        ("is_response", json!(dns_flag(layer, DNS_FLAG_QR_RESPONSE))),
        ("opcode", json!((layer.flags_value() >> 11) & 0x0f)),
        (
            "authoritative",
            json!(dns_flag(layer, DNS_FLAG_AUTHORITATIVE)),
        ),
        ("truncated", json!(dns_flag(layer, DNS_FLAG_TRUNCATED))),
        (
            "recursion_desired",
            json!(dns_flag(layer, DNS_FLAG_RECURSION_DESIRED)),
        ),
        (
            "recursion_available",
            json!(dns_flag(layer, DNS_FLAG_RECURSION_AVAILABLE)),
        ),
        ("z", json!((layer.flags_value() >> 6) & 0x01)),
        (
            "authenticated_data",
            json!(dns_flag(layer, DNS_FLAG_AUTHENTIC_DATA)),
        ),
        (
            "checking_disabled",
            json!(dns_flag(layer, DNS_FLAG_CHECKING_DISABLED)),
        ),
        ("response_code", json!(layer.flags_value() & 0x0f)),
        ("question_count", json!(layer.questions().len())),
        ("answer_count", json!(layer.answers().len())),
        ("authority_count", json!(layer.authorities().len())),
        ("additional_count", json!(layer.additionals().len())),
    ])
}

fn dhcp_fields(layer: &Dhcp) -> BTreeMap<String, Value> {
    map([
        ("opcode", json!(layer.op_value())),
        ("hardware_type", json!(layer.hardware_type_value())),
        ("hardware_length", json!(layer.hardware_len_value())),
        ("hops", json!(layer.hops_value())),
        ("transaction_id", json!(layer.transaction_id_value())),
        ("seconds", json!(layer.seconds_value())),
        ("flags", json!(layer.flags_value())),
        (
            "client_ip",
            json!(layer.client_ip_address_value().to_string()),
        ),
        ("your_ip", json!(layer.your_ip_address_value().to_string())),
        (
            "server_ip",
            json!(layer.server_ip_address_value().to_string()),
        ),
        (
            "relay_ip",
            json!(layer.gateway_ip_address_value().to_string()),
        ),
        (
            "client_hardware_address",
            json!({"hex": hex_bytes(layer.client_hardware_address_value())}),
        ),
        ("magic_cookie", json!(layer.magic_cookie_value())),
        ("option_count", json!(layer.options_value().len())),
    ])
}

fn payload_fields(layer: &Raw) -> BTreeMap<String, Value> {
    map([
        ("hex", json!(hex_bytes(layer.as_bytes()))),
        ("length", json!(layer.len())),
        (
            "ascii",
            json!(String::from_utf8_lossy(layer.as_bytes()).into_owned()),
        ),
    ])
}

fn inspection_fields(layer: &dyn Layer) -> BTreeMap<String, Value> {
    layer
        .inspection_fields()
        .into_iter()
        .map(|(name, value)| (name.to_string(), json!(value)))
        .collect()
}

fn insert_address(
    fields: &mut BTreeMap<String, Value>,
    name: &str,
    text: Option<String>,
    raw: Vec<u8>,
) {
    fields.insert(
        name.to_string(),
        text.map(Value::String)
            .unwrap_or_else(|| json!({"hex": hex_bytes(&raw)})),
    );
}

fn dns_flag(dns: &Dns, flag: u16) -> bool {
    dns.flags_value() & flag != 0
}

fn map<const N: usize>(items: [(&str, Value); N]) -> BTreeMap<String, Value> {
    items
        .into_iter()
        .map(|(name, value)| (name.to_string(), value))
        .collect()
}

fn ipv4_flags(flags: u8) -> String {
    let mut names = Vec::new();
    if flags & crafter::core::IPV4_FLAG_MORE_FRAGMENTS != 0 {
        names.push("mf");
    }
    if flags & crafter::core::IPV4_FLAG_DONT_FRAGMENT != 0 {
        names.push("df");
    }
    if flags & crafter::core::IPV4_FLAG_RESERVED != 0 {
        names.push("reserved");
    }
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join("|")
    }
}

fn tcp_flags(flags: u16) -> String {
    let mut names = Vec::new();
    for (bit, name) in [
        (crafter::core::TCP_FLAG_FIN, "fin"),
        (crafter::core::TCP_FLAG_SYN, "syn"),
        (crafter::core::TCP_FLAG_RST, "rst"),
        (crafter::core::TCP_FLAG_PSH, "psh"),
        (crafter::core::TCP_FLAG_ACK, "ack"),
        (crafter::core::TCP_FLAG_URG, "urg"),
        (crafter::core::TCP_FLAG_ECE, "ece"),
        (crafter::core::TCP_FLAG_CWR, "cwr"),
        (crafter::core::TCP_FLAG_NS, "ns"),
    ] {
        if flags & bit != 0 {
            names.push(name);
        }
    }
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join("|")
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
