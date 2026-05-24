use crafter::prelude::*;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

type ExampleResult<T> = std::result::Result<T, Box<dyn Error>>;

const BACKEND_NAME: &str = "libcrafter";

#[derive(Debug)]
struct Args {
    input: Option<PathBuf>,
    out: PathBuf,
    mode: RunMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunMode {
    DryRun,
    Live,
}

impl RunMode {
    const fn is_dry_run(self) -> bool {
        matches!(self, Self::DryRun)
    }
}

#[derive(Debug, Deserialize)]
struct EndpointRequest {
    provider: String,
    backend: String,
    seed: u64,
    profile: String,
    packet_plans: Vec<Value>,
    direction: String,
    endpoint_id: String,
    endpoint_role: String,
    peer_role: String,
    local_addresses: Value,
    peer_addresses: Value,
    interface: String,
    timeout_seconds: u64,
    artifact_paths: Value,
    #[serde(default)]
    metadata: Value,
}

#[derive(Debug, Clone)]
struct PreparedPacket {
    index: usize,
    packet: Packet,
    root: String,
    raw_hex: String,
    feature_tags: Vec<String>,
}

fn main() -> ExampleResult<()> {
    let args = parse_args()?;
    let input = read_input(args.input.clone())?;
    let request: EndpointRequest = serde_json::from_str(&input)?;
    let request_json: Value = serde_json::from_str(&input)?;
    let response = run_endpoint(&request, request_json, &args)?;

    serde_json::to_writer_pretty(io::stdout(), &response)?;
    println!();
    Ok(())
}

fn parse_args() -> ExampleResult<Args> {
    let mut input = None;
    let mut out = PathBuf::from("target/oracle/libcrafter-live-endpoint");
    let mut explicit_mode = None;
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--dry-run" => set_mode(&mut explicit_mode, RunMode::DryRun)?,
            "--live" => set_mode(&mut explicit_mode, RunMode::Live)?,
            "--input" => {
                let value = args.next().ok_or("--input requires a path or -")?;
                input = input_path(value);
            }
            "--out" => {
                out = PathBuf::from(args.next().ok_or("--out requires a directory")?);
            }
            _ if arg.starts_with("--input=") => {
                let value = arg
                    .strip_prefix("--input=")
                    .expect("--input= prefix already matched");
                input = input_path(value.to_string());
            }
            _ if arg.starts_with("--out=") => {
                out = PathBuf::from(
                    arg.strip_prefix("--out=")
                        .expect("--out= prefix already matched"),
                );
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }

    Ok(Args {
        input,
        out,
        mode: explicit_mode.unwrap_or(RunMode::DryRun),
    })
}

fn set_mode(mode: &mut Option<RunMode>, next: RunMode) -> ExampleResult<()> {
    if mode.replace(next).is_some_and(|existing| existing != next) {
        return Err("--dry-run and --live are mutually exclusive".into());
    }
    Ok(())
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
        "usage: cargo run -p crafter --example oracle_live_endpoint -- [--dry-run|--live] --input PATH|- [--out DIR]\n\nRun the libcrafter side of an oracle live endpoint batch. Dry-run is the default and compiles packet plans without sending or capturing traffic."
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

fn run_endpoint(
    request: &EndpointRequest,
    request_json: Value,
    args: &Args,
) -> ExampleResult<Value> {
    if request.endpoint_role != "libcrafter" {
        return Err(format!(
            "oracle_live_endpoint only supports endpoint_role=libcrafter, got {}",
            request.endpoint_role
        )
        .into());
    }

    let phase_role = phase_role(request)?;
    fs::create_dir_all(&args.out)?;
    write_json(
        &artifact_path(
            &args.out,
            &request.artifact_paths,
            "request",
            "request.json",
        ),
        &request_json,
    )?;

    let prepared = prepare_packets(&request.packet_plans)?;
    let response = match phase_role {
        "sender" => run_sender(request, args.mode, &prepared)?,
        "receiver" => run_receiver(request, args.mode, &prepared, &args.out)?,
        value => {
            return Err(format!(
                "unsupported libcrafter live phase_role={value}; expected sender or receiver"
            )
            .into())
        }
    };

    write_json(
        &artifact_path(
            &args.out,
            &request.artifact_paths,
            "response",
            "response.json",
        ),
        &response,
    )?;
    write_json(&args.out.join("response.json"), &response)?;
    Ok(response)
}

fn phase_role(request: &EndpointRequest) -> ExampleResult<&str> {
    if let Some(value) = request.metadata.get("phase_role").and_then(Value::as_str) {
        return Ok(value);
    }

    match request.direction.as_str() {
        "libcrafter_to_reference" if request.endpoint_role == "libcrafter" => Ok("sender"),
        "reference_to_libcrafter" if request.endpoint_role == "libcrafter" => Ok("receiver"),
        other => Err(format!(
            "cannot infer libcrafter endpoint phase for direction={other} endpoint_role={}",
            request.endpoint_role
        )
        .into()),
    }
}

fn prepare_packets(plans: &[Value]) -> ExampleResult<Vec<PreparedPacket>> {
    plans
        .iter()
        .map(|plan| {
            let packet = build_packet(plan)?;
            let compiled = packet.compile()?;
            Ok(PreparedPacket {
                index: packet_index(plan)?,
                packet,
                root: plan_root(plan)?.to_string(),
                raw_hex: hex_bytes(compiled.as_bytes()),
                feature_tags: string_array(plan.get("feature_tags")).unwrap_or_default(),
            })
        })
        .collect()
}

fn run_sender(
    request: &EndpointRequest,
    mode: RunMode,
    prepared: &[PreparedPacket],
) -> ExampleResult<Value> {
    let mut packets = prepared
        .iter()
        .map(|prepared| prepared.packet.clone())
        .collect::<Vec<_>>();
    let ethernet_addresses = live_ethernet_addresses(request)?;
    let send_mode = if let Some((source, destination)) = ethernet_addresses {
        packets = packets
            .into_iter()
            .map(|packet| ethernet_wrap_packet(packet, source, destination))
            .collect();
        SendMode::LinkLayer
    } else {
        common_send_mode(prepared)?
    };
    let mut batch = BatchSend::new()
        .iface(request.interface.clone())
        .concurrency_limit(64)
        .retries(1);
    batch = match send_mode {
        SendMode::Auto | SendMode::NetworkLayer => batch.network_layer(),
        SendMode::LinkLayer => batch.link_layer(),
    };
    batch = if mode.is_dry_run() {
        batch.dry_run()
    } else {
        batch.live()
    };

    let report = batch.send_all(&packets)?;
    let mut statuses = Vec::with_capacity(prepared.len());
    let mut send_reports = Vec::with_capacity(prepared.len());
    let mut live_sent_count = 0usize;

    for (offset, prepared_packet) in prepared.iter().enumerate() {
        let Some(entry) = report.entry(offset) else {
            return Err(format!("missing send report for packet offset {offset}").into());
        };
        let attempts = entry.send_reports();
        let sent = !mode.is_dry_run() && attempts.iter().any(|attempt| attempt.bytes_sent() > 0);
        if sent {
            live_sent_count += 1;
        }
        send_reports.push(json!({
            "index": prepared_packet.index,
            "attempts": entry.attempts(),
            "reports": attempts.iter().map(send_report_json).collect::<Vec<_>>(),
        }));
        statuses.push(index_status(
            request,
            prepared_packet.index,
            if mode.is_dry_run() {
                "dry-run-planned"
            } else {
                "sent"
            },
            sent,
            false,
            0,
            Vec::new(),
            Vec::new(),
            json!({
                "raw_hex": prepared_packet.raw_hex,
                "root": prepared_packet.root,
                "send_reports": send_reports.last().cloned().unwrap_or(Value::Null),
            }),
        ));
    }

    Ok(endpoint_response(
        request,
        mode,
        if mode.is_dry_run() {
            0
        } else {
            live_sent_count
        },
        0,
        Vec::new(),
        Vec::new(),
        statuses,
        Vec::new(),
        json!({
            "phase_role": "sender",
            "send_mode": format!("{send_mode:?}"),
            "send_reports": send_reports,
        }),
    ))
}

fn run_receiver(
    request: &EndpointRequest,
    mode: RunMode,
    prepared: &[PreparedPacket],
    out_dir: &Path,
) -> ExampleResult<Value> {
    let decoded_path = artifact_path(
        out_dir,
        &request.artifact_paths,
        "decoded_models",
        "decoded-models.json",
    );

    if mode.is_dry_run() {
        write_json(&decoded_path, &json!([]))?;
        let statuses = prepared
            .iter()
            .map(|prepared_packet| {
                index_status(
                    request,
                    prepared_packet.index,
                    "dry-run-planned",
                    false,
                    false,
                    0,
                    Vec::new(),
                    Vec::new(),
                    json!({
                        "root": prepared_packet.root,
                        "expected_raw_hex": prepared_packet.raw_hex,
                    }),
                )
            })
            .collect::<Vec<_>>();
        return Ok(endpoint_response(
            request,
            mode,
            0,
            0,
            Vec::new(),
            Vec::new(),
            statuses,
            Vec::new(),
            json!({ "phase_role": "receiver" }),
        ));
    }

    let timeout = Duration::from_secs(request.timeout_seconds.max(1));
    let mut sniffer = Sniffer::interface(request.interface.clone())
        .timeout(timeout)
        .count(prepared.len().max(1));
    if let Some(filter) = live_capture_filter(request) {
        sniffer = sniffer.filter(filter);
    }
    let captured = sniffer.collect()?;

    let mut decoded_models = Vec::with_capacity(captured.len());
    for (offset, captured_packet) in captured.iter().enumerate() {
        let expected = prepared.get(offset);
        let root = expected.map(|packet| packet.root.as_str());
        let observed = packet_for_root(captured_packet.packet(), root)?;
        decoded_models.push(decoded_model(
            &observed,
            root,
            expected
                .map(|packet| packet.feature_tags.clone())
                .unwrap_or_default(),
        )?);
    }
    write_json(&decoded_path, &json!(decoded_models))?;

    let capture_dir = artifact_path(out_dir, &request.artifact_paths, "captures", "captures");
    fs::create_dir_all(&capture_dir)?;
    let capture_summary_path = capture_dir.join("observed.json");
    write_json(
        &capture_summary_path,
        &json!({
            "packet_count": captured.len(),
            "packets": decoded_models,
        }),
    )?;

    let statuses = prepared
        .iter()
        .enumerate()
        .map(|(offset, prepared_packet)| {
            let received = offset < captured.len();
            index_status(
                request,
                prepared_packet.index,
                if received { "received" } else { "timeout" },
                false,
                received,
                usize::from(received),
                if received {
                    vec![capture_summary_path.to_string_lossy().to_string()]
                } else {
                    Vec::new()
                },
                if received {
                    Vec::new()
                } else {
                    vec!["receiver timed out before observing packet".to_string()]
                },
                json!({
                    "root": prepared_packet.root,
                    "expected_raw_hex": prepared_packet.raw_hex,
                }),
            )
        })
        .collect::<Vec<_>>();

    Ok(endpoint_response(
        request,
        mode,
        0,
        captured.len(),
        decoded_models,
        vec![json!({
            "endpoint_role": request.endpoint_role,
            "path": capture_summary_path.to_string_lossy(),
            "link_type": captured.first().map(|packet| format!("{:?}", packet.link_type())),
            "packet_count": captured.len(),
            "metadata": {
                "artifact_kind": "decoded-live-capture-summary"
            }
        })],
        statuses,
        Vec::new(),
        json!({ "phase_role": "receiver" }),
    ))
}

fn common_send_mode(prepared: &[PreparedPacket]) -> ExampleResult<SendMode> {
    let mut mode = None;
    for packet in prepared {
        let next = send_mode_for_root(&packet.root)?;
        if mode.replace(next).is_some_and(|existing| existing != next) {
            return Err(
                "mixed link-layer and network-layer live send roots are unsupported".into(),
            );
        }
    }
    Ok(mode.unwrap_or(SendMode::NetworkLayer))
}

fn send_mode_for_root(root: &str) -> ExampleResult<SendMode> {
    match root {
        "Ether" | "CookedLinux" | "Loopback" | "link:ethernet" | "link:linux-cooked"
        | "link:linux-sll" | "link:null-loopback" => Ok(SendMode::LinkLayer),
        "IP" | "IPv6" | "Raw" | "l3:ipv4" | "l3:ipv6" | "l3:raw" | "link:raw" => {
            Ok(SendMode::NetworkLayer)
        }
        _ => Err(format!("unsupported live send root: {root}").into()),
    }
}

fn send_report_json(report: &SendReport) -> Value {
    json!({
        "bytes_sent": report.bytes_sent(),
        "dry_run": report.is_dry_run(),
        "interface": report.plan().interface(),
        "length": report.plan().len(),
        "raw_hex": hex_bytes(report.plan().bytes()),
        "send_mode": format!("{:?}", report.plan().requested_mode()),
        "target": format!("{:?}", report.plan().target()),
    })
}

fn endpoint_response(
    request: &EndpointRequest,
    mode: RunMode,
    sent_count: usize,
    received_count: usize,
    decoded_models: Vec<Value>,
    captures: Vec<Value>,
    per_index_status: Vec<Value>,
    errors: Vec<String>,
    metadata: Value,
) -> Value {
    json!({
        "provider": request.provider,
        "backend": request.backend,
        "direction": request.direction,
        "endpoint_id": request.endpoint_id,
        "endpoint_role": request.endpoint_role,
        "sent_count": sent_count,
        "received_count": received_count,
        "decoded_models": decoded_models,
        "captures": captures,
        "per_index_status": per_index_status,
        "errors": errors,
        "artifact_paths": request.artifact_paths,
        "metadata": {
            "backend": BACKEND_NAME,
            "dry_run": mode.is_dry_run(),
            "libcrafter_version": env!("CARGO_PKG_VERSION"),
            "live_packet_exchange": !mode.is_dry_run(),
            "local_addresses": request.local_addresses,
            "peer_addresses": request.peer_addresses,
            "peer_role": request.peer_role,
            "profile": request.profile,
            "seed": request.seed,
            "detail": metadata,
        },
    })
}

fn live_capture_filter(request: &EndpointRequest) -> Option<String> {
    let local = request.local_addresses.get("ipv4")?.as_str()?;
    let peer = request.peer_addresses.get("ipv4")?.as_str()?;
    Some(format!(
        "ip and udp and src host {peer} and dst host {local}"
    ))
}

fn live_ethernet_addresses(request: &EndpointRequest) -> ExampleResult<Option<(MacAddr, MacAddr)>> {
    let Some(source) = address_text(&request.local_addresses, "mac") else {
        return Ok(None);
    };
    let Some(destination) = address_text(&request.peer_addresses, "mac") else {
        return Ok(None);
    };
    Ok(Some((
        MacAddr::from_str(source)?,
        MacAddr::from_str(destination)?,
    )))
}

fn address_text<'a>(addresses: &'a Value, key: &str) -> Option<&'a str> {
    addresses
        .get(key)?
        .as_str()
        .filter(|value| !value.is_empty())
}

fn ethernet_wrap_packet(packet: Packet, source: MacAddr, destination: MacAddr) -> Packet {
    Packet::from_layer(
        Ethernet::new()
            .src(source)
            .dst(destination)
            .ethertype(ETHERTYPE_IPV4),
    )
    .concat(packet)
}

#[allow(clippy::too_many_arguments)]
fn index_status(
    request: &EndpointRequest,
    index: usize,
    status: &str,
    sent: bool,
    received: bool,
    decoded_count: usize,
    capture_paths: Vec<String>,
    errors: Vec<String>,
    metadata: Value,
) -> Value {
    json!({
        "index": index,
        "direction": request.direction,
        "status": status,
        "sent": sent,
        "received": received,
        "decoded_count": decoded_count,
        "capture_paths": capture_paths,
        "errors": errors,
        "metadata": metadata,
    })
}

fn write_json(path: &Path, value: &Value) -> ExampleResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn artifact_path(out_dir: &Path, artifact_paths: &Value, key: &str, fallback: &str) -> PathBuf {
    let value = artifact_paths
        .get(key)
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| out_dir.join(fallback));
    if value.is_absolute() {
        value
    } else {
        out_dir.join(value)
    }
}

fn packet_for_root(packet: &Packet, root: Option<&str>) -> ExampleResult<Packet> {
    match root {
        Some("IP" | "IPv4" | "l3:ipv4") => {
            let compiled = packet.compile()?;
            let bytes = compiled.as_bytes();
            let payload = if packet.layer::<Ethernet>().is_some() && bytes.len() >= 14 {
                &bytes[14..]
            } else {
                bytes
            };
            Ok(Packet::decode_from_l3(NetworkLayer::Ipv4, payload)?)
        }
        Some("IPv6" | "l3:ipv6") => {
            let compiled = packet.compile()?;
            let bytes = compiled.as_bytes();
            let payload = if packet.layer::<Ethernet>().is_some() && bytes.len() >= 14 {
                &bytes[14..]
            } else {
                bytes
            };
            Ok(Packet::decode_from_l3(NetworkLayer::Ipv6, payload)?)
        }
        _ => Ok(packet.clone()),
    }
}

fn decoded_model(
    packet: &Packet,
    root: Option<&str>,
    feature_tags: Vec<String>,
) -> ExampleResult<Value> {
    let compiled = packet.compile()?;
    let mut fields = Map::new();
    let mut layers = Vec::new();
    let mut summaries = Vec::new();

    for layer in packet.iter() {
        let name = normalize_layer_name(layer.name());
        layers.push(Value::String(name.to_string()));
        summaries.push(Value::String(layer.summary()));
        let mut layer_fields = Map::new();
        for (field, value) in layer.inspection_fields() {
            if let Some((field_name, field_value)) = normalize_field(name, field, &value)? {
                layer_fields.insert(field_name, field_value);
            }
        }
        fields.insert(name.to_string(), Value::Object(layer_fields));
    }

    Ok(json!({
        "backend": BACKEND_NAME,
        "layers": layers,
        "fields": fields,
        "root": root,
        "source_hex": hex_bytes(compiled.as_bytes()),
        "feature_tags": feature_tags,
        "metadata": {
            "backend": BACKEND_NAME,
            "native_summary": packet.summary(),
            "layer_summaries": summaries,
        },
    }))
}

fn normalize_layer_name(name: &str) -> &str {
    match name {
        "Ethernet" => "ethernet",
        "IPv4" => "ipv4",
        "Ipv4" => "ipv4",
        "IPv6" => "ipv6",
        "Ipv6" => "ipv6",
        "UDP" => "udp",
        "Udp" => "udp",
        "Raw" => "payload",
        value => value,
    }
}

fn normalize_field(
    layer: &str,
    field: &str,
    value: &str,
) -> ExampleResult<Option<(String, Value)>> {
    match (layer, field) {
        ("ipv4", "ihl") => Ok(Some(("header_length".to_string(), json!(u64_text(value)?)))),
        ("ipv4", "total_length") => Ok(Some(("length".to_string(), json!(u64_text(value)?)))),
        ("ipv4", "id") => Ok(Some((
            "identification".to_string(),
            json!(u64_text(value)?),
        ))),
        ("ipv4", "protocol") => Ok(Some((
            "protocol".to_string(),
            json!(protocol_number(value)?),
        ))),
        ("ipv4", "checksum")
        | ("ipv4", "fragment_offset")
        | ("ipv4", "tos")
        | ("ipv4", "ttl")
        | ("ipv4", "version") => Ok(Some((field.to_string(), json!(u64_text(value)?)))),
        ("ipv4", "src") | ("ipv4", "dst") | ("ipv4", "flags") => {
            Ok(Some((field.to_string(), json!(value))))
        }
        ("udp", "sport") => Ok(Some(("src_port".to_string(), json!(u64_text(value)?)))),
        ("udp", "dport") => Ok(Some(("dst_port".to_string(), json!(u64_text(value)?)))),
        ("udp", "checksum") | ("udp", "length") => {
            Ok(Some((field.to_string(), json!(u64_text(value)?))))
        }
        ("payload", "bytes") => Ok(Some((
            "hex".to_string(),
            json!(value
                .split_whitespace()
                .collect::<String>()
                .to_ascii_lowercase()),
        ))),
        ("payload", "len") => Ok(Some(("length".to_string(), json!(u64_text(value)?)))),
        ("payload", "text_lossy") => Ok(None),
        _ => Ok(Some((field.to_string(), json!(value)))),
    }
}

fn protocol_number(value: &str) -> ExampleResult<u64> {
    if let Some(start) = value.find('(') {
        if let Some(end) = value[start + 1..].find(')') {
            return u64_text(&value[start + 1..start + 1 + end]);
        }
    }
    u64_text(value)
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
        "ipv4" => Ok(Box::new(ipv4_layer(plan)?)),
        "ipv6" => Ok(Box::new(ipv6_layer(plan)?)),
        "udp" => Ok(Box::new(udp_layer(plan)?)),
        _ => Err(format!("unsupported libcrafter live materialization layer: {layer}").into()),
    }
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

fn canonical_layer(layer: &str) -> String {
    match layer.to_ascii_lowercase().as_str() {
        "ip" => "ipv4".to_string(),
        "raw" => "payload".to_string(),
        value => value.to_string(),
    }
}

fn plan_root(plan: &Value) -> ExampleResult<&str> {
    plan.pointer("/metadata/root_decoder")
        .or_else(|| plan.pointer("/metadata/root"))
        .or_else(|| plan.get("root"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "packet plan metadata must include root_decoder, metadata.root, or root".into()
        })
}

fn packet_index(plan: &Value) -> ExampleResult<usize> {
    let value = plan
        .get("index")
        .and_then(Value::as_u64)
        .ok_or("packet plan index must be an unsigned integer")?;
    Ok(usize::try_from(value)?)
}

fn ip_protocol(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().as_str() {
            "udp" => Ok(IPPROTO_UDP),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn ipv6_next_header(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().as_str() {
            "payload" | "raw" | "unknown" => Ok(253),
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

fn u8_text(text: &str) -> ExampleResult<u8> {
    Ok(u8::try_from(u64_text(text)?)?)
}

fn u64_text(text: &str) -> ExampleResult<u64> {
    let trimmed = text.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return Ok(u64::from_str_radix(hex, 16)?);
    }
    Ok(trimmed.parse()?)
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
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

#[allow(dead_code)]
fn _parse_ipv4(value: &str) -> ExampleResult<Ipv4Addr> {
    Ok(Ipv4Addr::from_str(value)?)
}

#[allow(dead_code)]
fn _parse_ipv6(value: &str) -> ExampleResult<Ipv6Addr> {
    Ok(Ipv6Addr::from_str(value)?)
}
