use crafter::prelude::*;
use serde_json::{json, Map, Value};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;

type ExampleResult<T> = std::result::Result<T, Box<dyn Error>>;

const BACKEND_NAME: &str = "libcrafter";

#[derive(Debug)]
struct Args {
    input: Option<PathBuf>,
}

fn main() -> ExampleResult<()> {
    let args = parse_args()?;
    let input = read_input(args.input)?;
    let document: Value = serde_json::from_str(&input)?;
    let plans = extract_plans(&document)?;
    let mut vectors = Vec::with_capacity(plans.len());

    for plan in plans {
        vectors.push(materialize_plan(plan)?);
    }

    let report = json!({
        "artifacts": [],
        "artifact_paths": [],
        "backend": BACKEND_NAME,
        "backend_versions": {},
        "count": vectors.len(),
        "failures": [],
        "libcrafter": {
            "version": env!("CARGO_PKG_VERSION")
        },
        "metadata": {
            "direction": document.pointer("/metadata/direction").cloned().unwrap_or(Value::Null),
            "requested_count": document.pointer("/metadata/requested_count").cloned().unwrap_or(Value::Null),
            "vector_backend": BACKEND_NAME,
            "vectors": vectors
        },
        "mode": document.get("mode").cloned().unwrap_or_else(|| Value::String("offline".to_string())),
        "profile": document.get("profile").cloned().unwrap_or(Value::Null),
        "reproduction_commands": [],
        "results": [],
        "seed": document.get("seed").cloned().unwrap_or(Value::Null),
        "selected_specs": document.get("selected_specs").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "status": "vectors"
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
        "usage: cargo run -p oracle-adapters --bin materialize_plans -- [--input PATH|-]\n\nMaterialize oracle packet plans with libcrafter and emit raw vector JSON. Reads stdin when --input is omitted or set to -."
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

fn extract_plans(document: &Value) -> ExampleResult<&Vec<Value>> {
    let plans = if let Some(value) = document.pointer("/metadata/plans") {
        value
    } else if let Some(value) = document.get("plans") {
        value
    } else if document.is_array() {
        document
    } else {
        return Err("input JSON must contain metadata.plans, plans, or be a plan array".into());
    };
    plans
        .as_array()
        .ok_or_else(|| "plans must be an array".into())
}

fn materialize_plan(plan: &Value) -> ExampleResult<Value> {
    let packet = build_packet(plan)?;
    let compiled = packet.compile()?;
    let raw_hex = hex_bytes(compiled.as_bytes());
    let root = plan_root(plan)?;
    let stack = string_array(plan.get("stack")).unwrap_or_default();
    let feature_tags = string_array(plan.get("feature_tags")).unwrap_or_default();
    let strict_bytes = plan
        .get("strict_bytes")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    Ok(json!({
        "backend": BACKEND_NAME,
        "decoder": root,
        "metadata": {
            "backend": BACKEND_NAME,
            "feature_tags": feature_tags,
            "libcrafter_version": env!("CARGO_PKG_VERSION"),
            "length": compiled.as_bytes().len(),
            "root_decoder": root,
            "stack_tags": feature_tags,
            "strict_bytes": strict_bytes
        },
        "plan": plan,
        "raw_hex": raw_hex,
        "root": root,
        "stack": stack
    }))
}

fn build_packet(plan: &Value) -> ExampleResult<Packet> {
    let stack = string_array(plan.get("stack")).ok_or("packet plan stack must be an array")?;
    let mut packet = Packet::new();

    for raw_layer in stack {
        let layer = canonical_layer(&raw_layer);
        let piece = build_layer(plan, &layer)?;
        packet.push_box_mut(piece);
    }

    Ok(packet)
}

fn build_layer(plan: &Value, layer: &str) -> ExampleResult<Box<dyn Layer>> {
    match layer {
        "payload" | "raw" => Ok(Box::new(Raw::from_bytes(payload_bytes(plan)?))),
        "ethernet" => Ok(Box::new(ethernet_layer(plan)?)),
        "vlan" => Ok(Box::new(vlan_layer(plan)?)),
        "arp" => Ok(Box::new(arp_layer(plan)?)),
        "ipv4" => Ok(Box::new(ipv4_layer(plan)?)),
        "ipv6" => Ok(Box::new(ipv6_layer(plan)?)),
        "ipv6_fragment" => Ok(Box::new(ipv6_fragment_layer(plan)?)),
        "ipv6_routing" => ipv6_routing_layer(plan),
        "udp" => Ok(Box::new(udp_layer(plan)?)),
        "tcp" => Ok(Box::new(tcp_layer(plan)?)),
        "icmp" => Ok(Box::new(icmp_layer(plan)?)),
        "icmpv6" => Ok(Box::new(icmpv6_layer(plan)?)),
        "dns" => Ok(Box::new(dns_layer(plan)?)),
        "dhcp" => Ok(Box::new(dhcp_layer(plan)?)),
        _ => Err(format!("unsupported libcrafter materialization layer: {layer}").into()),
    }
}

fn ethernet_layer(plan: &Value) -> ExampleResult<Ethernet> {
    let fields = layer_fields(plan, "ethernet")?;
    let layer = Ethernet::new()
        .src_str(text_required(fields, &["src"])?)?
        .dst_str(text_required(fields, &["dst"])?)?
        .ethertype(ethertype_value(required(fields, &["ethertype", "type"])?)?);
    Ok(layer)
}

fn vlan_layer(plan: &Value) -> ExampleResult<Vlan> {
    let fields = layer_fields(plan, "vlan")?;
    Ok(Vlan::new()
        .prio(u8_value(required(fields, &["priority", "prio"])?)?)
        .dei(bool_value(required(fields, &["drop_eligible", "dei"])?)?)
        .vlan(u16_value(required(fields, &["vlan_id", "id", "vlan"])?)?)
        .ethertype(ethertype_value(required(fields, &["ethertype", "type"])?)?))
}

fn arp_layer(plan: &Value) -> ExampleResult<Arp> {
    let fields = layer_fields(plan, "arp")?;
    let mut layer = Arp::new()
        .hardware_type(hardware_type_value(required(
            fields,
            &["hardware_type", "hwtype"],
        )?)?)
        .protocol_type(ethertype_value(required(
            fields,
            &["protocol_type", "ptype"],
        )?)?)
        .opcode(arp_opcode(required(
            fields,
            &["opcode", "op", "operation"],
        )?)?);

    // Honor explicit ARP length fields when present. The standard
    // Ethernet/IPv4 generator omits them and lets the standard MAC/IPv4 address
    // setters default them to 6/4; when a plan carries explicit lengths
    // (variable-length or unknown-family ARP), set them through the public
    // `hardware_len`/`protocol_len` setters before the address bytes so the
    // compiled header matches the plan and the Scapy reference exactly.
    if let Some(value) = optional(fields, &["hardware_length", "hwlen"]) {
        layer = layer.hardware_len(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["protocol_length", "plen"]) {
        layer = layer.protocol_len(u8_value(value)?);
    }

    layer = apply_arp_hardware_address(
        layer,
        ArpAddressField::SenderHardware,
        required(fields, &["sender_hardware_address", "hwsrc"])?,
    )?;
    layer = apply_arp_protocol_address(
        layer,
        ArpAddressField::SenderProtocol,
        required(fields, &["sender_protocol_address", "sender_ip", "psrc"])?,
    )?;
    layer = apply_arp_hardware_address(
        layer,
        ArpAddressField::TargetHardware,
        required(fields, &["target_hardware_address", "hwdst"])?,
    )?;
    layer = apply_arp_protocol_address(
        layer,
        ArpAddressField::TargetProtocol,
        required(fields, &["target_protocol_address", "target_ip", "pdst"])?,
    )?;
    Ok(layer)
}

/// Which ARP sender/target address field is being materialized.
#[derive(Debug, Clone, Copy)]
enum ArpAddressField {
    SenderHardware,
    TargetHardware,
    SenderProtocol,
    TargetProtocol,
}

/// Standard Ethernet hardware address width in octets.
const ARP_STANDARD_HARDWARE_OCTETS: usize = 6;
/// Standard IPv4 protocol address width in octets.
const ARP_STANDARD_PROTOCOL_OCTETS: usize = 4;

/// Apply one ARP hardware (sender/target) address to the layer.
///
/// A standard colon-separated MAC string flows through the `hwsrc_str`/
/// `hwdst_str` helpers so the golden Ethernet/IPv4 ARP bytes stay stable. Any
/// raw byte form — a `{"hex": ...}` object, a hex string whose decoded width is
/// not the standard six octets, or an empty string — is set through the raw
/// `sender_hardware_bytes`/`target_hardware_bytes` setters so variable-length
/// and unknown-family hardware addresses materialize byte-for-byte.
fn apply_arp_hardware_address(
    layer: Arp,
    field: ArpAddressField,
    value: &Value,
) -> ExampleResult<Arp> {
    if let Some(text) = value.as_str() {
        if is_standard_mac(text) {
            return Ok(match field {
                ArpAddressField::SenderHardware => layer.hwsrc_str(text)?,
                ArpAddressField::TargetHardware => layer.hwdst_str(text)?,
                _ => unreachable!("hardware address field expected"),
            });
        }
    }
    let raw = arp_address_bytes(value)?;
    Ok(match field {
        ArpAddressField::SenderHardware => layer.sender_hardware_bytes(raw),
        ArpAddressField::TargetHardware => layer.target_hardware_bytes(raw),
        _ => unreachable!("hardware address field expected"),
    })
}

/// Apply one ARP protocol (sender/target) address to the layer.
///
/// A standard dotted-quad IPv4 string flows through the `psrc_str`/`pdst_str`
/// helpers so the golden Ethernet/IPv4 ARP bytes stay stable. Any raw byte
/// form materializes through the raw `sender_protocol_bytes`/
/// `target_protocol_bytes` setters so variable-length and unknown-family
/// protocol addresses materialize byte-for-byte.
fn apply_arp_protocol_address(
    layer: Arp,
    field: ArpAddressField,
    value: &Value,
) -> ExampleResult<Arp> {
    if let Some(text) = value.as_str() {
        if is_standard_ipv4(text) {
            return Ok(match field {
                ArpAddressField::SenderProtocol => layer.psrc_str(text)?,
                ArpAddressField::TargetProtocol => layer.pdst_str(text)?,
                _ => unreachable!("protocol address field expected"),
            });
        }
    }
    let raw = arp_address_bytes(value)?;
    Ok(match field {
        ArpAddressField::SenderProtocol => layer.sender_protocol_bytes(raw),
        ArpAddressField::TargetProtocol => layer.target_protocol_bytes(raw),
        _ => unreachable!("protocol address field expected"),
    })
}

/// Decode an ARP address value into raw octets for the raw byte setters.
///
/// Accepts a `{"hex": ...}` object (the form `decode_vectors` emits for
/// nonstandard addresses), a colon/dash/space-separated or bare hex string, or
/// an empty string (a zero-length HLN/PLN address). This mirrors the Scapy
/// backend's `_arp_address` raw path so both backends materialize the same
/// bytes from the same plan.
fn arp_address_bytes(value: &Value) -> ExampleResult<Vec<u8>> {
    if let Some(object) = value.as_object() {
        if let Some(hex) = object.get("hex").and_then(Value::as_str) {
            return decode_hex(&strip_address_separators(hex));
        }
        return Err(format!("unsupported ARP address object: {value:?}").into());
    }
    if let Some(text) = value.as_str() {
        return decode_hex(&strip_address_separators(text));
    }
    Err(format!("unsupported ARP address value: {value:?}").into())
}

fn strip_address_separators(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !matches!(ch, ':' | '-' | ' '))
        .collect()
}

fn is_standard_mac(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != ARP_STANDARD_HARDWARE_OCTETS {
        return false;
    }
    parts
        .iter()
        .all(|part| part.len() == 2 && u8::from_str_radix(part, 16).is_ok())
}

fn is_standard_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != ARP_STANDARD_PROTOCOL_OCTETS {
        return false;
    }
    parts
        .iter()
        .all(|part| !part.is_empty() && part.parse::<u8>().is_ok())
}

fn ipv4_layer(plan: &Value) -> ExampleResult<Ipv4> {
    let fields = layer_fields(plan, "ipv4")?;
    let mut layer = Ipv4::new()
        .src_str(text_required(fields, &["src"])?)?
        .dst_str(text_required(fields, &["dst"])?)?
        .id(u16_value(required(fields, &["identification", "id"])?)?)
        .ttl(u8_value(required(fields, &["ttl"])?)?)
        .flags(ipv4_flags(required(fields, &["flags"])?)?)
        .protocol(ip_protocol(required(fields, &["protocol", "proto"])?)?);
    if let Some(value) = optional(fields, &["tos"]) {
        layer = layer.tos(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["fragment_offset", "frag"]) {
        layer = layer.frag(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["options"]) {
        layer = layer.options(option_bytes(value)?);
    }
    Ok(layer)
}

fn ipv6_layer(plan: &Value) -> ExampleResult<Ipv6> {
    let fields = layer_fields(plan, "ipv6")?;
    let mut layer = Ipv6::new()
        .src_str(text_required(fields, &["src"])?)?
        .dst_str(text_required(fields, &["dst"])?)?
        .hlim(u8_value(required(fields, &["hop_limit", "hlim"])?)?)
        .nh(ipv6_next_header(required(fields, &["next_header", "nh"])?)?);
    if let Some(value) = optional(fields, &["traffic_class", "tc"]) {
        layer = layer.tc(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["flow_label", "fl"]) {
        layer = layer.fl(u32_value(value)?);
    }
    Ok(layer)
}

fn ipv6_fragment_layer(plan: &Value) -> ExampleResult<Ipv6FragmentHeader> {
    let fields = layer_fields(plan, "ipv6_fragment")?;
    let mut layer = Ipv6FragmentHeader::new()
        .nh(ipv6_next_header(required(fields, &["next_header", "nh"])?)?)
        .id(u32_value(required(fields, &["identification", "id"])?)?)
        .fragment_offset(u16_value(required(
            fields,
            &["fragment_offset", "offset"],
        )?)?)
        .more_fragments(bool_value(required(fields, &["more_fragments", "m"])?)?);
    if let Some(value) = optional(fields, &["reserved"]) {
        layer = layer.reserved(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["res"]) {
        layer = layer.res(u8_value(value)?);
    }
    Ok(layer)
}

fn ipv6_routing_layer(plan: &Value) -> ExampleResult<Box<dyn Layer>> {
    let fields = layer_fields(plan, "ipv6_routing")?;
    let next_header = ipv6_next_header(required(fields, &["next_header", "nh"])?)?;
    let routing_type = u8_value(required(fields, &["type", "routing_type"])?)?;
    let segments_left = u8_value(required(fields, &["segments_left", "segleft"])?)?;
    let mut addresses = string_array(optional(fields, &["addresses"])).unwrap_or_default();

    if routing_type == IPV6_ROUTING_TYPE_MOBILE {
        let home = addresses.first().map(String::as_str).unwrap_or("::1");
        return Ok(Box::new(
            Ipv6MobileRoutingHeader::new()
                .nh(next_header)
                .segments_left(segments_left)
                .home_address_str(home)?,
        ));
    }

    if routing_type == IPV6_ROUTING_TYPE_SEGMENT {
        let mut layer = Ipv6SegmentRoutingHeader::new()
            .nh(next_header)
            .segments_left(segments_left);
        while addresses.len() <= segments_left as usize {
            addresses.push("::".to_string());
        }
        for address in addresses {
            layer = layer.segment_str(&address)?;
        }
        return Ok(Box::new(layer));
    }

    let mut layer = Ipv6RoutingHeader::new()
        .nh(next_header)
        .routing_type(routing_type)
        .segments_left(segments_left);
    if !addresses.is_empty() {
        let mut type_data = vec![0, 0, 0, 0];
        for address in addresses {
            type_data.extend_from_slice(&Ipv6Addr::from_str(&address)?.octets());
        }
        layer = layer.type_data(type_data);
    }
    Ok(Box::new(layer))
}

fn udp_layer(plan: &Value) -> ExampleResult<Udp> {
    let fields = layer_fields(plan, "udp")?;
    let mut layer = Udp::new()
        .sport(u16_value(required(fields, &["src_port", "sport"])?)?)
        .dport(u16_value(required(fields, &["dst_port", "dport"])?)?);
    if let Some(value) = optional(fields, &["checksum", "chksum"]) {
        layer = layer.chksum(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["length", "len"]) {
        layer = layer.len(u16_value(value)?);
    }
    Ok(layer)
}

fn tcp_layer(plan: &Value) -> ExampleResult<Tcp> {
    let fields = layer_fields(plan, "tcp")?;
    let mut layer = Tcp::new()
        .sport(u16_value(required(fields, &["src_port", "sport"])?)?)
        .dport(u16_value(required(fields, &["dst_port", "dport"])?)?)
        .seq(u32_value(required(fields, &["sequence", "seq"])?)?)
        .ack(u32_value(required(fields, &["acknowledgement", "ack"])?)?)
        .reserved(u8_value(required(fields, &["reserved"])?)?)
        .flags(tcp_flags(required(fields, &["flags"])?)?)
        .window(u16_value(required(fields, &["window"])?)?)
        .urgptr(u16_value(required(fields, &["urgent_pointer", "urgptr"])?)?);
    if let Some(value) = optional(fields, &["checksum", "chksum"]) {
        layer = layer.chksum(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["data_offset", "dataofs"]) {
        layer = layer.dataofs(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["options"]) {
        layer = layer.options(option_bytes(value)?);
    }
    Ok(layer)
}

fn icmp_layer(plan: &Value) -> ExampleResult<Icmp> {
    let fields = layer_fields(plan, "icmp")?;
    let mut layer = Icmp::new()
        .type_(icmp_type(required(fields, &["type"])?, false)?)
        .code(u8_value(required(fields, &["code"])?)?);
    if let Some(value) = optional(fields, &["id", "identifier"]) {
        layer = layer.id(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["seq", "sequence"]) {
        layer = layer.seq(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["checksum", "chksum"]) {
        layer = layer.chksum(u16_value(value)?);
    }
    Ok(layer)
}

fn icmpv6_layer(plan: &Value) -> ExampleResult<Icmpv6> {
    let fields = layer_fields(plan, "icmpv6")?;
    let mut layer = Icmpv6::new()
        .type_(icmp_type(required(fields, &["type"])?, true)?)
        .code(u8_value(required(fields, &["code"])?)?);
    if let Some(value) = optional(fields, &["id", "identifier"]) {
        layer = layer.id(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["seq", "sequence"]) {
        layer = layer.seq(u16_value(value)?);
    }
    if let Some(value) = optional(fields, &["checksum", "cksum"]) {
        layer = layer.chksum(u16_value(value)?);
    }
    Ok(layer)
}

fn dns_layer(plan: &Value) -> ExampleResult<Dns> {
    let fields = layer_fields(plan, "dns")?;
    let mut layer = Dns::new()
        .id(u16_value(required(fields, &["transaction_id", "id"])?)?)
        .flags(dns_flags(fields)?)
        .response(bool_value(required(fields, &["is_response"])?)?)
        .rcode(dns_response_code(required(fields, &["response_code"])?)?);

    for question in array_values(required(fields, &["questions"])?)? {
        let qname = if let Some(object) = question.as_object() {
            text_optional(object, &["qname", "name"]).unwrap_or("example.com.")
        } else {
            question.as_str().unwrap_or("example.com.")
        };
        let qtype = if let Some(object) = question.as_object() {
            object
                .get("qtype")
                .or_else(|| object.get("type"))
                .map(dns_record_type)
                .transpose()?
                .unwrap_or(DNS_TYPE_A)
        } else {
            DNS_TYPE_A
        };
        layer = layer.question(DnsQuestion::new(qname, qtype));
    }

    if let Some(answers) = optional(fields, &["answers"]) {
        for answer in array_values(answers)? {
            if let Some(object) = answer.as_object() {
                layer = layer.answer(dns_answer(object)?);
            }
        }
    }

    Ok(layer)
}

fn dhcp_layer(plan: &Value) -> ExampleResult<Dhcp> {
    let fields = layer_fields(plan, "dhcp")?;
    // The fixed BOOTP header fields are optional: a minimal live-friendly DHCP
    // plan emits only op/flags/options and relies on `Dhcp::new()` defaults
    // (BOOTP_REQUEST op, Ethernet htype, hlen 6, xid 0, zero MAC, unspecified
    // addresses) for anything it does not set. Honor every field the plan does
    // provide and leave the rest at their protocol-correct defaults.
    let mut layer = Dhcp::new();
    if let Some(value) = optional(fields, &["op"]) {
        layer = layer.op(dhcp_op(value)?);
    }
    if let Some(value) = optional(fields, &["hardware_type", "htype"]) {
        layer = layer.hardware_type(hardware_type_value(value)? as u8);
    }
    if let Some(value) = optional(fields, &["hardware_length", "hlen"]) {
        layer = layer.hardware_len(u8_value(value)?);
    }
    if let Some(value) = optional(fields, &["transaction_id", "xid"]) {
        layer = layer.xid(u32_value(value)?);
    }
    if let Some(value) = optional(fields, &["flags"]) {
        layer = layer.flags(dhcp_flags(value)?);
    }
    if let Some(value) = optional(fields, &["client_ip", "ciaddr"]) {
        layer = layer.ciaddr(Ipv4Addr::from_str(text_value(value)?)?);
    }
    if let Some(value) = optional(fields, &["your_ip", "yiaddr"]) {
        layer = layer.yiaddr(Ipv4Addr::from_str(text_value(value)?)?);
    }
    if let Some(value) = optional(fields, &["client_hardware_address", "chaddr"]) {
        layer = layer.chaddr(mac_bytes(text_value(value)?)?);
    }
    if let Some(options) = optional(fields, &["options"]) {
        layer = layer.options(dhcp_options(options)?);
    }
    Ok(layer)
}

fn dns_answer(object: &Map<String, Value>) -> ExampleResult<DnsRecord> {
    let rr_type = object
        .get("type")
        .map(dns_record_type)
        .transpose()?
        .unwrap_or(DNS_TYPE_A);
    let name = text_optional(object, &["name", "rrname"]).unwrap_or("example.com.");
    let ttl = object.get("ttl").map(u32_value).transpose()?.unwrap_or(60);
    if rr_type == DNS_TYPE_CNAME {
        return Ok(DnsRecord::cname(
            name,
            text_optional(object, &["target", "rdata"]).unwrap_or("alias.example.com."),
            ttl,
        ));
    }
    if rr_type == DNS_TYPE_AAAA {
        let address = text_optional(object, &["address", "rdata"]).unwrap_or("2001:db8::53");
        return Ok(DnsRecord::aaaa(name, Ipv6Addr::from_str(address)?, ttl));
    }
    let address = text_optional(object, &["address", "rdata"]).unwrap_or("192.0.2.53");
    Ok(DnsRecord::a(name, Ipv4Addr::from_str(address)?, ttl))
}

fn dhcp_options(value: &Value) -> ExampleResult<Vec<DhcpOption>> {
    let mut options = Vec::new();
    for item in array_values(value)? {
        if let Some(text) = item.as_str() {
            if text == "end" {
                options.push(DhcpOption::End);
                continue;
            }
            if text == "pad" {
                options.push(DhcpOption::Pad);
                continue;
            }
            if let Some((name, raw_value)) = text.split_once('=') {
                options.push(dhcp_option_pair(name, raw_value)?);
                continue;
            }
        }
    }
    if !matches!(options.last(), Some(DhcpOption::End)) {
        options.push(DhcpOption::End);
    }
    Ok(options)
}

fn dhcp_option_pair(name: &str, value: &str) -> ExampleResult<DhcpOption> {
    match name.replace('-', "_").as_str() {
        "message_type" => Ok(DhcpOption::message_type(dhcp_message_type(value))),
        "hostname" | "host_name" => Ok(DhcpOption::host_name(value)),
        "domain_name" => Ok(DhcpOption::domain_name(value)),
        "requested_ip" | "requested_ip_address" => {
            Ok(DhcpOption::requested_ip_address(Ipv4Addr::from_str(value)?))
        }
        "server_id" | "server_identifier" => {
            Ok(DhcpOption::server_identifier(Ipv4Addr::from_str(value)?))
        }
        "router" => Ok(DhcpOption::router(parse_ipv4_list(value)?)),
        "dns" | "domain_name_server" => Ok(DhcpOption::domain_name_server(parse_ipv4_list(value)?)),
        "lease_time" => Ok(DhcpOption::lease_time(value.parse::<u32>()?)),
        _ => Ok(DhcpOption::generic(254, value.as_bytes().to_vec())),
    }
}

fn dhcp_message_type(value: &str) -> DhcpMessageType {
    match value.replace('-', "_").as_str() {
        "discover" => DhcpMessageType::Discover,
        "offer" => DhcpMessageType::Offer,
        "request" => DhcpMessageType::Request,
        "decline" => DhcpMessageType::Decline,
        "ack" => DhcpMessageType::Ack,
        "nak" => DhcpMessageType::Nak,
        "release" => DhcpMessageType::Release,
        "inform" => DhcpMessageType::Inform,
        _ => value
            .parse::<u8>()
            .map(DhcpMessageType::Unknown)
            .unwrap_or(DhcpMessageType::Discover),
    }
}

fn parse_ipv4_list(value: &str) -> ExampleResult<Vec<Ipv4Addr>> {
    value
        .split(',')
        .filter(|item| !item.is_empty())
        .map(Ipv4Addr::from_str)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn payload_bytes(plan: &Value) -> ExampleResult<Vec<u8>> {
    let fields = layer_fields(plan, "payload")?;
    if let Some(value) = optional(fields, &["hex", "bytes_hex"]) {
        return decode_hex(text_value(value)?);
    }
    if let Some(value) = optional(fields, &["text", "value"]) {
        return Ok(text_value(value)?.as_bytes().to_vec());
    }
    Err("payload materialization requires bytes in hex, bytes_hex, text, or value".into())
}

fn layer_fields<'a>(plan: &'a Value, layer: &str) -> ExampleResult<&'a Map<String, Value>> {
    let fields = plan
        .get("fields")
        .and_then(Value::as_object)
        .ok_or("packet plan fields must be an object")?;
    if let Some(value) = fields.get(layer) {
        return value
            .as_object()
            .ok_or_else(|| format!("{layer} fields must be an object").into());
    }
    if layer == "ipv4" {
        if let Some(value) = fields.get("ip") {
            return value
                .as_object()
                .ok_or_else(|| "ipv4 fields must be an object".into());
        }
    }
    if layer == "payload" {
        if let Some(value) = fields.get("raw") {
            return value
                .as_object()
                .ok_or_else(|| "payload fields must be an object".into());
        }
    }
    Err(format!("packet plan requires {layer} fields").into())
}

fn required<'a>(fields: &'a Map<String, Value>, names: &[&str]) -> ExampleResult<&'a Value> {
    optional(fields, names)
        .ok_or_else(|| format!("missing required field {}", names.join("/")).into())
}

fn optional<'a>(fields: &'a Map<String, Value>, names: &[&str]) -> Option<&'a Value> {
    for name in names {
        if let Some(value) = fields.get(*name) {
            return Some(value);
        }
    }
    None
}

fn text_required<'a>(fields: &'a Map<String, Value>, names: &[&str]) -> ExampleResult<&'a str> {
    text_value(required(fields, names)?)
}

fn text_optional<'a>(fields: &'a Map<String, Value>, names: &[&str]) -> Option<&'a str> {
    optional(fields, names).and_then(Value::as_str)
}

fn text_value(value: &Value) -> ExampleResult<&str> {
    value
        .as_str()
        .ok_or_else(|| format!("expected string-compatible value, got {value:?}").into())
}

fn string_array(value: Option<&Value>) -> Option<Vec<String>> {
    value.and_then(Value::as_array).map(|items| {
        items
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect()
    })
}

fn array_values(value: &Value) -> ExampleResult<&Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| format!("expected array value, got {value:?}").into())
}

fn canonical_layer(layer: &str) -> String {
    match layer.to_ascii_lowercase().as_str() {
        "dot1q" => "vlan".to_string(),
        "ether" => "ethernet".to_string(),
        "ip" => "ipv4".to_string(),
        "raw" => "payload".to_string(),
        value => value.to_string(),
    }
}

fn plan_root(plan: &Value) -> ExampleResult<&str> {
    plan.pointer("/metadata/root_decoder")
        .or_else(|| plan.pointer("/metadata/root"))
        .and_then(Value::as_str)
        .ok_or_else(|| "packet plan metadata must include root_decoder or root".into())
}

fn ethertype_value(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().as_str() {
            "arp" => Ok(ETHERTYPE_ARP),
            "experimental" | "unknown" => Ok(0x9000),
            "ipv4" | "ip" => Ok(ETHERTYPE_IPV4),
            "ipv6" => Ok(ETHERTYPE_IPV6),
            "vlan" => Ok(ETHERTYPE_VLAN),
            _ => u16_text(text),
        };
    }
    u16_value(value)
}

fn hardware_type_value(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        if matches!(text.to_ascii_lowercase().as_str(), "ether" | "ethernet") {
            return Ok(1);
        }
        return u16_text(text);
    }
    u16_value(value)
}

fn arp_opcode(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "who-has" | "request" => Ok(1),
            "is-at" | "reply" => Ok(2),
            _ => u16_text(text),
        };
    }
    u16_value(value)
}

fn ip_protocol(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().as_str() {
            "icmp" => Ok(IPPROTO_ICMP),
            "tcp" => Ok(IPPROTO_TCP),
            "udp" => Ok(IPPROTO_UDP),
            "unknown" => Ok(253),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn ipv6_next_header(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().as_str() {
            "fragment" => Ok(IPPROTO_IPV6_FRAGMENT),
            "icmpv6" => Ok(IPPROTO_ICMPV6),
            "payload" | "raw" | "unknown" => Ok(253),
            "routing" => Ok(IPPROTO_IPV6_ROUTE),
            "tcp" => Ok(IPPROTO_TCP),
            "udp" => Ok(IPPROTO_UDP),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn ipv4_flags(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "none" | "0" => Ok(0),
            "df" | "dont-fragment" => Ok(IPV4_FLAG_DONT_FRAGMENT),
            "mf" | "more-fragments" => Ok(IPV4_FLAG_MORE_FRAGMENTS),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn tcp_flags(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        if text == "all" {
            return Ok(0x01ff);
        }
        return Ok(flag_text_value(text));
    }
    if let Some(items) = value.as_array() {
        let mut flags = 0;
        for item in items {
            if let Some(text) = item.as_str() {
                if text == "all" {
                    flags |= 0x01ff;
                } else {
                    flags |= flag_text_value(text);
                }
            }
        }
        return Ok(flags);
    }
    u16_value(value)
}

fn flag_text_value(text: &str) -> u16 {
    match text.to_ascii_lowercase().as_str() {
        "fin" => TCP_FLAG_FIN,
        "syn" => TCP_FLAG_SYN,
        "rst" => TCP_FLAG_RST,
        "psh" => TCP_FLAG_PSH,
        "ack" => TCP_FLAG_ACK,
        "urg" => TCP_FLAG_URG,
        "ece" => TCP_FLAG_ECE,
        "cwr" => TCP_FLAG_CWR,
        "ns" => TCP_FLAG_NS,
        other => other
            .chars()
            .fold(0, |flags, item| flags | tcp_flag_char(item)),
    }
}

fn tcp_flag_char(value: char) -> u16 {
    match value {
        'F' | 'f' => TCP_FLAG_FIN,
        'S' | 's' => TCP_FLAG_SYN,
        'R' | 'r' => TCP_FLAG_RST,
        'P' | 'p' => TCP_FLAG_PSH,
        'A' | 'a' => TCP_FLAG_ACK,
        'U' | 'u' => TCP_FLAG_URG,
        'E' | 'e' => TCP_FLAG_ECE,
        'C' | 'c' => TCP_FLAG_CWR,
        'N' | 'n' => TCP_FLAG_NS,
        _ => 0,
    }
}

fn icmp_type(value: &Value, ipv6: bool) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "echo-reply" => Ok(if ipv6 {
                ICMPV6_ECHO_REPLY
            } else {
                ICMP_ECHO_REPLY
            }),
            "echo-request" => Ok(if ipv6 {
                ICMPV6_ECHO_REQUEST
            } else {
                ICMP_ECHO_REQUEST
            }),
            "destination-unreachable" | "dest-unreach" => Ok(if ipv6 {
                ICMPV6_DESTINATION_UNREACHABLE
            } else {
                ICMP_DESTINATION_UNREACHABLE
            }),
            "packet-too-big" if ipv6 => Ok(ICMPV6_PACKET_TOO_BIG),
            "parameter-problem" => Ok(if ipv6 {
                ICMPV6_PARAMETER_PROBLEM
            } else {
                ICMP_PARAMETER_PROBLEM
            }),
            "time-exceeded" => Ok(if ipv6 {
                ICMPV6_TIME_EXCEEDED
            } else {
                ICMP_TIME_EXCEEDED
            }),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn dns_flags(fields: &Map<String, Value>) -> ExampleResult<u16> {
    let mut flags = 0u16;
    if let Some(value) = optional(fields, &["flags"]) {
        for item in value.as_array().into_iter().flatten() {
            if let Some(text) = item.as_str() {
                match text.to_ascii_lowercase().replace('-', "_").as_str() {
                    "authoritative" => flags |= DNS_FLAG_AUTHORITATIVE,
                    "truncated" => flags |= DNS_FLAG_TRUNCATED,
                    "recursion_desired" => flags |= DNS_FLAG_RECURSION_DESIRED,
                    "recursion_available" => flags |= DNS_FLAG_RECURSION_AVAILABLE,
                    "authenticated_data" => flags |= DNS_FLAG_AUTHENTIC_DATA,
                    "checking_disabled" => flags |= DNS_FLAG_CHECKING_DISABLED,
                    _ => {}
                }
            }
        }
    }
    if bool_value(required(fields, &["is_response"])?)? {
        flags |= DNS_FLAG_QR_RESPONSE;
    }
    flags |= dns_response_code(required(fields, &["response_code"])?)? as u16;
    Ok(flags)
}

fn dns_record_type(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_uppercase().as_str() {
            "A" => Ok(DNS_TYPE_A),
            "AAAA" => Ok(DNS_TYPE_AAAA),
            "CNAME" => Ok(DNS_TYPE_CNAME),
            "MX" => Ok(DNS_TYPE_MX),
            "NS" => Ok(DNS_TYPE_NS),
            "PTR" => Ok(DNS_TYPE_PTR),
            "TXT" => Ok(DNS_TYPE_TXT),
            _ => u16_text(text),
        };
    }
    u16_value(value)
}

fn dns_response_code(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('-', "_").as_str() {
            "no_error" => Ok(0),
            "server_failure" => Ok(2),
            "name_error" => Ok(3),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn dhcp_op(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "bootrequest" | "request" => Ok(BOOTP_REQUEST),
            "bootreply" | "reply" => Ok(BOOTP_REPLY),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn dhcp_flags(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "broadcast" | "b" => Ok(0x8000),
            "none" | "0" => Ok(0),
            _ => u16_text(text),
        };
    }
    u16_value(value)
}

fn option_bytes(value: &Value) -> ExampleResult<Vec<u8>> {
    if let Some(text) = value.as_str() {
        return decode_hex(text);
    }
    if let Some(object) = value.as_object() {
        if let Some(hex) = object.get("hex").and_then(Value::as_str) {
            return decode_hex(hex);
        }
    }
    Err(format!("unsupported option bytes value: {value:?}").into())
}

fn bool_value(value: &Value) -> ExampleResult<bool> {
    if let Some(value) = value.as_bool() {
        return Ok(value);
    }
    if let Some(value) = value.as_i64() {
        return Ok(value != 0);
    }
    if let Some(value) = value.as_u64() {
        return Ok(value != 0);
    }
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('_', "-").as_str() {
            "true" | "yes" | "broadcast" | "b" => Ok(true),
            "false" | "no" | "none" | "0" => Ok(false),
            _ => Err(format!("expected bool-compatible value, got {text:?}").into()),
        };
    }
    Err(format!("expected bool-compatible value, got {value:?}").into())
}

fn u8_value(value: &Value) -> ExampleResult<u8> {
    Ok(u8::try_from(u64_value(value)?)?)
}

fn u16_value(value: &Value) -> ExampleResult<u16> {
    Ok(u16::try_from(u64_value(value)?)?)
}

fn u32_value(value: &Value) -> ExampleResult<u32> {
    Ok(u32::try_from(u64_value(value)?)?)
}

fn u64_value(value: &Value) -> ExampleResult<u64> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    if let Some(value) = value.as_i64() {
        return Ok(u64::try_from(value)?);
    }
    if let Some(text) = value.as_str() {
        return u64_text(text);
    }
    Err(format!("expected integer-compatible value, got {value:?}").into())
}

fn u8_text(value: &str) -> ExampleResult<u8> {
    Ok(u8::try_from(u64_text(value)?)?)
}

fn u16_text(value: &str) -> ExampleResult<u16> {
    Ok(u16::try_from(u64_text(value)?)?)
}

fn u64_text(value: &str) -> ExampleResult<u64> {
    let text = value.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return Ok(u64::from_str_radix(hex, 16)?);
    }
    Ok(text.parse::<u64>()?)
}

fn mac_bytes(value: &str) -> ExampleResult<Vec<u8>> {
    Ok(MacAddr::from_str(value)?.octets().to_vec())
}

fn decode_hex(hex: &str) -> ExampleResult<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err("hex strings must contain an even number of characters".into());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for index in (0..hex.len()).step_by(2) {
        out.push(u8::from_str_radix(&hex[index..index + 2], 16)?);
    }
    Ok(out)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// Native DHCPv4 oracle fixtures.
///
/// The seeded Scapy reference backend covers the DHCPv4 cases Scapy can encode
/// byte-for-byte (the message-type matrix plus simple option domains; see
/// `tools/oracle/specs/layers/dhcp.yaml`). Scapy cannot represent option
/// overload (52 across `file`/`sname`), RFC 3396 long-option concatenation,
/// typed relay-agent option 82 sub-options, RFC 4361 node-specific client
/// identifiers, RFC 3118 authentication (90), classless static routes (121),
/// or leasequery status/state options (91/92/151-157) exactly. Those cases are
/// covered here by native libcrafter round-trip fixtures: each builds a packet,
/// compiles it, decodes it back through the registry over UDP, and asserts the
/// recompiled bytes are byte-identical and that the typed accessors recover the
/// constructed value. All addresses are RFC 5737 documentation space and all
/// MACs are RFC 7042 documentation EUI-48 values; nothing here touches a
/// network.
#[cfg(test)]
mod dhcp_oracle_fixtures {
    use crafter::prelude::*;
    use std::net::Ipv4Addr;

    const CLIENT_MAC: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01];
    const RELAY_MAC: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02];

    fn client_mac() -> MacAddr {
        MacAddr::from(CLIENT_MAC)
    }

    fn relay_mac() -> MacAddr {
        MacAddr::from(RELAY_MAC)
    }

    /// Wrap a built `Dhcp` layer in an Ethernet/IPv4/UDP frame on the BOOTP
    /// port pair so the registry decodes it as DHCP, then return the compiled
    /// frame bytes.
    fn frame_bytes(dhcp: Dhcp) -> Vec<u8> {
        let packet = Ethernet::new()
            .src(relay_mac())
            .dst(MacAddr::BROADCAST)
            .ethertype(ETHERTYPE_IPV4)
            / Ipv4::new()
                .src(Ipv4Addr::new(192, 0, 2, 1))
                .dst(Ipv4Addr::new(192, 0, 2, 2))
                .protocol(IPPROTO_UDP)
            / Udp::new().sport(DHCP_SERVER_PORT).dport(DHCP_CLIENT_PORT)
            / dhcp;
        packet
            .compile()
            .expect("documentation DHCP frame must compile")
            .as_bytes()
            .to_vec()
    }

    /// Decode a compiled frame and return the recompiled bytes plus the decoded
    /// DHCP layer, asserting the registry surfaced a DHCP layer over UDP.
    fn decode_roundtrip(bytes: &[u8]) -> (Vec<u8>, Dhcp) {
        let decoded = Packet::decode_from_link(LinkType::Ethernet, bytes)
            .expect("documentation DHCP frame must decode without panic");
        let dhcp = decoded
            .layer::<Dhcp>()
            .expect("decoded frame must expose a DHCP layer over UDP")
            .clone();
        let recompiled = decoded
            .compile()
            .expect("decoded DHCP frame must recompile")
            .as_bytes()
            .to_vec();
        (recompiled, dhcp)
    }

    /// Build, compile, decode, and recompile, asserting a byte-exact round-trip.
    fn assert_byte_roundtrip(dhcp: Dhcp) -> Dhcp {
        let original = frame_bytes(dhcp);
        let (recompiled, decoded) = decode_roundtrip(&original);
        assert_eq!(
            recompiled, original,
            "DHCPv4 fixture must round-trip byte-for-byte through decode and recompile"
        );
        decoded
    }

    #[test]
    fn dhcp_option_overload_file_and_sname() {
        // Option 52 marks both file and sname as overloaded option areas
        // (RFC 2131 section 4.1). Scapy does not model overloaded BOOTP fields.
        let dhcp = Dhcp::discover(client_mac())
            .xid(0x0102_0304)
            .file_option(DhcpOption::bootfile_name(b"boot/pxelinux.0".to_vec()))
            .sname_option(DhcpOption::host_name("oracle-server"));
        let decoded = assert_byte_roundtrip(dhcp);
        assert_eq!(decoded.option_overload(), Some(OptionOverload::Both));
    }

    #[test]
    fn dhcp_rfc3396_long_option_concatenation() {
        // RFC 3396: a value longer than 255 octets is split across repeated
        // instances of the same option code and read back as one logical value.
        let long_domain = format!("{}.example", "a".repeat(300));
        let dhcp = Dhcp::discover(client_mac())
            .xid(0x1111_2222)
            .option(DhcpOption::domain_name(long_domain.clone()));
        let decoded = assert_byte_roundtrip(dhcp);
        let concatenated = decoded
            .concatenated_option(15)
            .expect("rfc3396 domain-name option must be present")
            .expect("rfc3396 concatenation must decode");
        let payload = concatenated
            .payload()
            .expect("concatenated option payload must encode");
        assert_eq!(payload, long_domain.as_bytes());
        assert!(
            payload.len() > 255,
            "rfc3396 fixture must exceed a single 255-octet option instance"
        );
    }

    #[test]
    fn dhcp_relay_agent_option82_suboptions() {
        // RFC 3046 relay-agent option 82 with typed circuit-id and remote-id
        // sub-options. Scapy treats option 82 as opaque bytes.
        let info = DhcpRelayAgentInfo::new(vec![
            DhcpRelaySuboption::circuit_id(b"eth0:vlan100".to_vec()),
            DhcpRelaySuboption::remote_id(RELAY_MAC.to_vec()),
        ]);
        let dhcp = Dhcp::discover(client_mac())
            .xid(0x3333_4444)
            .relay_agent_info(info.clone());
        let decoded = assert_byte_roundtrip(dhcp);
        let recovered = decoded
            .relay_agent_information()
            .expect("relay-agent option 82 must be present")
            .expect("relay-agent option 82 must decode");
        assert_eq!(recovered, info);
    }

    #[test]
    fn dhcp_rfc4361_node_specific_client_identifier() {
        // RFC 4361 type-255 client identifier (IAID + DUID). Scapy carries
        // option 61 only as an opaque string.
        let identifier =
            DhcpClientIdentifier::node_specific(0x0a0b_0c0d, vec![0x00, 0x01, 0x02, 0x03]);
        let dhcp = Dhcp::discover(client_mac())
            .xid(0x5555_6666)
            .option(DhcpOption::client_identifier_value(identifier.clone()));
        let decoded = assert_byte_roundtrip(dhcp);
        let recovered = decoded
            .client_identifier_value()
            .expect("client identifier option 61 must be present")
            .expect("client identifier option 61 must decode");
        assert_eq!(recovered, identifier);
    }

    #[test]
    fn dhcp_rfc3118_authentication_option() {
        // RFC 3118 option 90 delayed authentication with HMAC-MD5. Scapy has no
        // typed authentication option.
        let auth = DhcpAuthentication::new(
            DhcpAuthProtocol::Delayed,
            DhcpAuthAlgorithm::HmacMd5,
            DhcpReplayDetectionMethod::MonotonicCounter,
            0x0000_0001_0000_0002,
            vec![0xab; 16],
        );
        let dhcp = Dhcp::request(
            client_mac(),
            Ipv4Addr::new(192, 0, 2, 100),
            Ipv4Addr::new(192, 0, 2, 1),
        )
        .xid(0x7777_8888)
        .option(DhcpOption::authentication(auth.clone()));
        let decoded = assert_byte_roundtrip(dhcp);
        let recovered = decoded
            .authentication()
            .expect("authentication option 90 must be present")
            .expect("authentication option 90 must decode");
        assert_eq!(recovered, auth);
    }

    #[test]
    fn dhcp_classless_static_routes_option121() {
        // RFC 3442 classless static routes (option 121) with the canonical
        // significant-octet widths.
        let routes = vec![
            DhcpClasslessRoute::new(
                24,
                Ipv4Addr::new(192, 0, 2, 0),
                Ipv4Addr::new(198, 51, 100, 1),
            ),
            DhcpClasslessRoute::new(0, Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(198, 51, 100, 254)),
        ];
        let dhcp = Dhcp::ack(
            client_mac(),
            Ipv4Addr::new(192, 0, 2, 100),
            Ipv4Addr::new(192, 0, 2, 1),
        )
        .xid(0x9999_aaaa)
        .option(DhcpOption::typed(
            DhcpOptionKind::ClasslessStaticRoute,
            DhcpOptionValue::ClasslessRoutes(routes.clone()),
        ));
        let decoded = assert_byte_roundtrip(dhcp);
        let recovered = decoded
            .classless_static_routes()
            .expect("classless static route option 121 must be present")
            .expect("classless static route option 121 must decode");
        assert_eq!(recovered, routes);
    }

    #[test]
    fn dhcp_leasequery_status_and_state() {
        // RFC 4388 leasequery reply carrying a status-code option (151) and a
        // dhcp-state option (153). Scapy has no leasequery option support.
        let status = DhcpStatusCodeOption::new(DhcpStatusCode::Success, b"ok".to_vec());
        let dhcp = Dhcp::lease_query_by_ip(Ipv4Addr::new(192, 0, 2, 100))
            .xid(0xbbbb_cccc)
            .option(DhcpOption::status_code(status.clone()))
            .option(DhcpOption::dhcp_state(DhcpState::Active));
        let decoded = assert_byte_roundtrip(dhcp);
        let recovered = decoded
            .status_code()
            .expect("leasequery status-code option 151 must be present")
            .expect("leasequery status-code option 151 must decode");
        assert_eq!(recovered, status);
        assert_eq!(
            decoded.message_type_value(),
            Some(DhcpMessageType::LeaseQuery)
        );
    }
}

/// Materializer coverage for IPv4-root DHCP plans.
///
/// These tests drive the live offline `libcrafter_to_reference` materialization
/// path directly: they feed an `ipv4 / udp / dhcp` plan (the shape the seeded
/// generator emits for `--case dhcp-discover` rooted at `l3:ipv4`) to
/// [`materialize_plan`], then assert the emitted vector roots at `l3:ipv4`,
/// carries the BOOTP port pair (68 -> 67), and re-decodes through the public
/// `decode_from_l3` entrypoint with a recoverable DHCP message type. Addresses
/// are RFC 5737 documentation space; nothing touches a network.
#[cfg(test)]
mod ipv4_dhcp_materialization {
    use super::{decode_hex, materialize_plan};
    use crafter::prelude::*;
    use serde_json::{json, Value};

    /// A minimal live-friendly `ipv4 / udp / dhcp` plan, matching the seeded
    /// generator output: only the DHCP op/flags/options are set, so the fixed
    /// BOOTP header fields must fall back to `Dhcp::new()` defaults.
    fn ipv4_dhcp_discover_plan() -> Value {
        json!({
            "stack": ["ipv4", "udp", "dhcp"],
            "metadata": {
                "root_decoder": "l3:ipv4",
                "root": "l3:ipv4"
            },
            "feature_tags": ["ipv4", "udp", "dhcp", "dhcp_behavior"],
            "strict_bytes": true,
            "fields": {
                "ipv4": {
                    "src": "192.0.2.1",
                    "dst": "198.51.100.10",
                    "identification": 4242,
                    "ttl": 64,
                    "flags": "none",
                    "protocol": "udp"
                },
                "udp": {
                    "src_port": 68,
                    "dst_port": 67
                },
                "dhcp": {
                    "op": "bootrequest",
                    "flags": "none",
                    "options": ["message-type=discover", "end"]
                }
            }
        })
    }

    #[test]
    fn ipv4_dhcp_plan_materializes_through_public_surface() {
        let plan = ipv4_dhcp_discover_plan();
        let vector = materialize_plan(&plan).expect("ipv4/udp/dhcp plan must materialize");

        // The vector must root at the IPv4 network layer.
        assert_eq!(
            vector.get("root").and_then(Value::as_str),
            Some("l3:ipv4"),
            "materialized vector must root at l3:ipv4"
        );
        assert_eq!(
            vector.get("decoder").and_then(Value::as_str),
            Some("l3:ipv4"),
            "materialized vector decoder must be l3:ipv4"
        );
        let stack: Vec<&str> = vector
            .get("stack")
            .and_then(Value::as_array)
            .expect("vector must carry a stack array")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(stack, ["ipv4", "udp", "dhcp"]);

        let raw_hex = vector
            .get("raw_hex")
            .and_then(Value::as_str)
            .expect("vector must carry raw_hex bytes");
        assert!(!raw_hex.is_empty(), "materialized vector must not be empty");
        let bytes = decode_hex(raw_hex).expect("raw_hex must decode to bytes");

        // Re-decode the produced bytes through the public IPv4 entrypoint.
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes)
            .expect("materialized IPv4 DHCP vector must re-decode from l3");

        decoded
            .layer::<Ipv4>()
            .expect("re-decoded packet must expose an IPv4 layer");

        let udp = decoded
            .layer::<Udp>()
            .expect("re-decoded packet must expose a UDP layer");
        assert_eq!(udp.source_port_value(), 68, "BOOTP client port");
        assert_eq!(udp.destination_port_value(), 67, "BOOTP server port");

        let dhcp = decoded
            .layer::<Dhcp>()
            .expect("re-decoded packet must expose a DHCP layer over UDP");
        assert_eq!(
            dhcp.message_type_value(),
            Some(DhcpMessageType::Discover),
            "DHCP message type must be present and decode to discover"
        );
    }

    #[test]
    fn ipv4_dhcp_plan_defaults_fixed_bootp_fields() {
        // A plan that omits xid/ciaddr/yiaddr/chaddr (as the smoke generator
        // does) must still materialize via Dhcp::new() defaults rather than
        // failing with a missing-required-field error.
        let plan = ipv4_dhcp_discover_plan();
        let vector = materialize_plan(&plan)
            .expect("ipv4/udp/dhcp plan without fixed BOOTP fields must materialize");
        let raw_hex = vector
            .get("raw_hex")
            .and_then(Value::as_str)
            .expect("vector must carry raw_hex bytes");
        let bytes = decode_hex(raw_hex).expect("raw_hex must decode to bytes");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes)
            .expect("default-filled IPv4 DHCP vector must re-decode");
        let dhcp = decoded
            .layer::<Dhcp>()
            .expect("re-decoded packet must expose a DHCP layer");
        // Defaults: BOOTP request op and Ethernet hardware type/len.
        assert_eq!(dhcp.op_value(), BOOTP_REQUEST);
        assert_eq!(dhcp.hardware_type_value(), DHCP_HTYPE_ETHERNET);
        assert_eq!(dhcp.hardware_len_value(), 6);
    }
}
