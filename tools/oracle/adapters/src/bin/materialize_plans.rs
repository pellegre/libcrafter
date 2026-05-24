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
    let layer = Arp::new()
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
        )?)?)
        .hwsrc_str(text_required(
            fields,
            &["sender_hardware_address", "hwsrc"],
        )?)?
        .psrc_str(text_required(
            fields,
            &["sender_protocol_address", "sender_ip", "psrc"],
        )?)?
        .hwdst_str(text_required(
            fields,
            &["target_hardware_address", "hwdst"],
        )?)?
        .pdst_str(text_required(
            fields,
            &["target_protocol_address", "target_ip", "pdst"],
        )?)?;
    Ok(layer)
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
    let mut layer = Dhcp::new()
        .op(dhcp_op(required(fields, &["op"])?)?)
        .hardware_type(hardware_type_value(required(fields, &["hardware_type", "htype"])?)? as u8)
        .hardware_len(u8_value(required(fields, &["hardware_length", "hlen"])?)?)
        .xid(u32_value(required(fields, &["transaction_id", "xid"])?)?)
        .flags(dhcp_flags(required(fields, &["flags"])?)?)
        .ciaddr(Ipv4Addr::from_str(text_required(
            fields,
            &["client_ip", "ciaddr"],
        )?)?)
        .yiaddr(Ipv4Addr::from_str(text_required(
            fields,
            &["your_ip", "yiaddr"],
        )?)?)
        .chaddr(mac_bytes(text_required(
            fields,
            &["client_hardware_address", "chaddr"],
        )?)?);
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
