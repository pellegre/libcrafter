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
const LIVE_SEND_INTERVAL: Duration = Duration::from_millis(10);

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

#[derive(Debug)]
struct CaptureSlice {
    compare_root: String,
    full_raw: Vec<u8>,
    comparable_raw: Vec<u8>,
    packet: Packet,
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
        "usage: cargo run -p oracle-adapters --bin live_endpoint -- [--dry-run|--live] --input PATH|- [--out DIR]\n\nRun the libcrafter side of an oracle live endpoint batch. Dry-run is the default and compiles packet plans without sending or capturing traffic."
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
            "live_endpoint only supports endpoint_role=libcrafter, got {}",
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
    let wraps_l3_with_ethernet = ethernet_addresses.is_some();
    let send_mode = if let Some((source, destination)) = ethernet_addresses {
        packets = packets
            .into_iter()
            .map(|packet| ethernet_wrap_packet(packet, source, destination))
            .collect();
        SendMode::LinkLayer
    } else {
        common_send_mode(prepared)?
    };
    let mut send_options = SendOptions::new().iface(request.interface.clone());
    send_options = match send_mode {
        SendMode::Auto => send_options,
        SendMode::NetworkLayer => send_options.network_layer(),
        SendMode::LinkLayer => send_options.link_layer(),
    };
    send_options = if mode.is_dry_run() {
        send_options.dry_run()
    } else {
        send_options.live()
    };
    let sender = SocketSender::new(send_options);

    let mut statuses = Vec::with_capacity(prepared.len());
    let mut send_reports = Vec::with_capacity(prepared.len());
    let mut live_sent_count = 0usize;

    for (offset, prepared_packet) in prepared.iter().enumerate() {
        let report = sender.send(&packets[offset])?;
        if !mode.is_dry_run() {
            std::thread::sleep(LIVE_SEND_INTERVAL);
        }
        let attempts = [report];
        let sent = !mode.is_dry_run() && attempts.iter().any(|attempt| attempt.bytes_sent() > 0);
        if sent {
            live_sent_count += 1;
        }
        let sent_raw_hex = hex_bytes(attempts[0].plan().bytes());
        let send_mode_label = send_mode_label(attempts[0].plan().requested_mode());
        let byte_length = attempts[0].plan().len();
        let plan_send_mode = send_mode_for_root(&prepared_packet.root)?;
        let send_root = if wraps_l3_with_ethernet && plan_send_mode == SendMode::NetworkLayer {
            "link:ethernet"
        } else {
            prepared_packet.root.as_str()
        };
        send_reports.push(json!({
            "index": prepared_packet.index,
            "attempts": attempts.len(),
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
                "sent_raw_hex": sent_raw_hex,
                "send_root": send_root,
                "send_mode": send_mode_label,
                "byte_length": byte_length,
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
                let compare_root =
                    compare_root_for_index(request, prepared_packet.index, &prepared_packet.root)?;
                Ok(index_status(
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
                        "capture_root": compare_root,
                        "capture_filter": capture_filter_for_index(request, prepared_packet.index),
                        "capture_match": capture_match_for_index(request, prepared_packet.index),
                    }),
                ))
            })
            .collect::<ExampleResult<Vec<_>>>()?;
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
    let capture_filter = live_capture_filter(request);
    let mut sniffer = Sniffer::interface(request.interface.clone())
        .timeout(timeout)
        .count(prepared.len().max(1));
    if let Some(filter) = capture_filter.clone() {
        sniffer = sniffer.filter(filter);
    }
    let captured = sniffer.collect()?;

    let capture_dir = artifact_path(out_dir, &request.artifact_paths, "captures", "captures");
    fs::create_dir_all(&capture_dir)?;
    let capture_summary_path = capture_dir.join("observed.json");
    let capture_path = capture_summary_path.to_string_lossy().to_string();

    let mut decoded_models = Vec::with_capacity(captured.len());
    let mut observed_packets = Vec::with_capacity(captured.len());
    for (offset, captured_packet) in captured.iter().enumerate() {
        let expected = prepared.get(offset);
        let compare_root = match expected {
            Some(packet) => compare_root_for_index(request, packet.index, &packet.root)?,
            None => "link:ethernet".to_string(),
        };
        let capture_slice = capture_slice_for_root(captured_packet, &compare_root)?;
        let observed_raw_hex = hex_bytes(&capture_slice.comparable_raw);
        let full_capture_raw_hex = hex_bytes(&capture_slice.full_raw);
        let capture_link_type = format!("{:?}", captured_packet.link_type());
        decoded_models.push(decoded_model(
            &capture_slice.packet,
            Some(&capture_slice.compare_root),
            &capture_slice.comparable_raw,
            expected
                .map(|packet| packet.feature_tags.clone())
                .unwrap_or_default(),
        )?);
        observed_packets.push(json!({
            "index": expected.map(|packet| packet.index).unwrap_or(offset),
            "observed_raw_hex": observed_raw_hex.clone(),
            "comparable_raw_hex": observed_raw_hex,
            "full_capture_raw_hex": full_capture_raw_hex,
            "capture_root": capture_slice.compare_root,
            "capture_link_type": capture_link_type,
            "capture_path": capture_path.clone(),
            "byte_length": capture_slice.comparable_raw.len(),
            "comparable_byte_length": capture_slice.comparable_raw.len(),
            "full_capture_byte_length": capture_slice.full_raw.len(),
        }));
    }
    write_json(&decoded_path, &json!(decoded_models))?;

    write_json(
        &capture_summary_path,
        &json!({
            "packet_count": captured.len(),
            "capture_filter": capture_filter,
            "packets": decoded_models,
            "observed_packets": observed_packets,
        }),
    )?;

    let statuses = prepared
        .iter()
        .enumerate()
        .map(|(offset, prepared_packet)| {
            let received = offset < captured.len();
            let observed_packet = observed_packets.get(offset).cloned().unwrap_or(Value::Null);
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
                    "capture_filter": capture_filter_for_index(request, prepared_packet.index),
                    "capture_match": capture_match_for_index(request, prepared_packet.index),
                    "observed_raw_hex": observed_packet
                        .get("observed_raw_hex")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "comparable_raw_hex": observed_packet
                        .get("comparable_raw_hex")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "full_capture_raw_hex": observed_packet
                        .get("full_capture_raw_hex")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "capture_root": observed_packet
                        .get("capture_root")
                        .cloned()
                        .unwrap_or_else(|| json!(prepared_packet.root)),
                    "capture_link_type": observed_packet
                        .get("capture_link_type")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "capture_path": observed_packet
                        .get("capture_path")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "byte_length": observed_packet
                        .get("byte_length")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "comparable_byte_length": observed_packet
                        .get("comparable_byte_length")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "full_capture_byte_length": observed_packet
                        .get("full_capture_byte_length")
                        .cloned()
                        .unwrap_or(Value::Null),
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
                "artifact_kind": "decoded-live-capture-summary",
                "capture_filter": live_capture_filter(request)
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
        "sent_raw_hex": hex_bytes(report.plan().bytes()),
        "byte_length": report.plan().len(),
        "send_mode": format!("{:?}", report.plan().requested_mode()),
        "send_mode_label": send_mode_label(report.plan().requested_mode()),
        "target": format!("{:?}", report.plan().target()),
    })
}

fn send_mode_label(mode: SendMode) -> &'static str {
    match mode {
        SendMode::Auto => "auto",
        SendMode::LinkLayer => "link-layer",
        SendMode::NetworkLayer => "network-layer",
    }
}

#[allow(clippy::too_many_arguments)]
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
    if let Some(filter) = request
        .metadata
        .get("capture_filter")
        .and_then(Value::as_str)
    {
        if !filter.is_empty() {
            return Some(filter.to_string());
        }
    }
    let filters = request
        .metadata
        .get("packets")
        .and_then(Value::as_array)
        .map(|packets| {
            packets
                .iter()
                .filter_map(|packet| packet.get("capture_filter")?.as_str())
                .filter(|filter| !filter.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    combine_capture_filters(filters)
}

fn combine_capture_filters(filters: Vec<String>) -> Option<String> {
    let mut unique = Vec::new();
    for filter in filters {
        if !unique.contains(&filter) {
            unique.push(filter);
        }
    }
    match unique.len() {
        0 => None,
        1 => unique.into_iter().next(),
        _ => Some(
            unique
                .into_iter()
                .map(|filter| format!("({filter})"))
                .collect::<Vec<_>>()
                .join(" or "),
        ),
    }
}

fn capture_filter_for_index(request: &EndpointRequest, index: usize) -> Value {
    packet_metadata_for_index(request, index)
        .and_then(|packet| packet.get("capture_filter"))
        .and_then(Value::as_str)
        .map(|value| json!(value))
        .unwrap_or(Value::Null)
}

fn capture_match_for_index(request: &EndpointRequest, index: usize) -> Value {
    packet_metadata_for_index(request, index)
        .and_then(|packet| packet.get("capture_match"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn packet_metadata_for_index(request: &EndpointRequest, index: usize) -> Option<&Value> {
    request
        .metadata
        .get("packets")
        .and_then(Value::as_array)?
        .iter()
        .find(|packet| {
            packet
                .get("index")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                == Some(index)
        })
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
    let ethertype = if packet.layer::<Ipv6>().is_some() {
        ETHERTYPE_IPV6
    } else {
        ETHERTYPE_IPV4
    };
    Packet::from_layer(
        Ethernet::new()
            .src(source)
            .dst(destination)
            .ethertype(ethertype),
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
        "sent_raw_hex": status_string(&metadata, "sent_raw_hex"),
        "send_root": status_string(&metadata, "send_root"),
        "send_mode": status_string(&metadata, "send_mode"),
        "observed_raw_hex": status_string(&metadata, "observed_raw_hex"),
        "capture_root": status_string(&metadata, "capture_root"),
        "capture_link_type": status_string(&metadata, "capture_link_type"),
        "capture_path": status_string(&metadata, "capture_path"),
        "byte_length": status_usize(&metadata, "byte_length"),
        "capture_paths": capture_paths,
        "errors": errors,
        "metadata": metadata,
    })
}

fn status_string(metadata: &Value, key: &str) -> Value {
    metadata
        .get(key)
        .and_then(Value::as_str)
        .map(|value| json!(value))
        .unwrap_or(Value::Null)
}

fn status_usize(metadata: &Value, key: &str) -> Value {
    metadata
        .get(key)
        .and_then(Value::as_u64)
        .map(|value| json!(value))
        .unwrap_or(Value::Null)
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

fn decoded_model(
    packet: &Packet,
    root: Option<&str>,
    source_bytes: &[u8],
    feature_tags: Vec<String>,
) -> ExampleResult<Value> {
    let mut fields = Map::new();
    let mut layers = Vec::new();
    let mut summaries = Vec::new();

    for layer in packet.iter() {
        let name = normalize_layer_name(layer.name());
        layers.push(Value::String(name.to_string()));
        summaries.push(Value::String(layer.summary()));
        let layer_fields = if let Some(fields) = typed_layer_fields(layer, name) {
            fields
        } else {
            let mut fields = Map::new();
            for (field, value) in layer.inspection_fields() {
                if let Some((field_name, field_value)) = normalize_field(name, field, &value)? {
                    fields.insert(field_name, field_value);
                }
            }
            fields
        };
        fields.insert(name.to_string(), Value::Object(layer_fields));
    }

    Ok(json!({
        "backend": BACKEND_NAME,
        "layers": layers,
        "fields": fields,
        "root": root,
        "source_hex": hex_bytes(source_bytes),
        "feature_tags": feature_tags,
        "metadata": {
            "backend": BACKEND_NAME,
            "native_summary": packet.summary(),
            "layer_summaries": summaries,
        },
    }))
}

fn capture_slice_for_root(
    captured: &PcapPacket,
    compare_root: &str,
) -> ExampleResult<CaptureSlice> {
    let root = canonical_compare_root(compare_root)?;
    let full_raw = captured.data().to_vec();
    match root {
        "l3:ipv4" => {
            let offset = ip_header_offset(&full_raw, 4, ETHERTYPE_IPV4)?;
            let comparable_raw = full_raw[offset..].to_vec();
            let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &comparable_raw)?;
            Ok(CaptureSlice {
                compare_root: root.to_string(),
                full_raw,
                comparable_raw,
                packet,
            })
        }
        "l3:ipv6" => {
            let offset = ip_header_offset(&full_raw, 6, ETHERTYPE_IPV6)?;
            let comparable_raw = full_raw[offset..].to_vec();
            let packet = Packet::decode_from_l3(NetworkLayer::Ipv6, &comparable_raw)?;
            Ok(CaptureSlice {
                compare_root: root.to_string(),
                full_raw,
                comparable_raw,
                packet,
            })
        }
        "link:ethernet" => {
            if captured.packet().layer::<Ethernet>().is_none() {
                return Err(
                    "captured packet has no Ethernet frame for link:ethernet compare root".into(),
                );
            }
            Ok(CaptureSlice {
                compare_root: root.to_string(),
                comparable_raw: full_raw.clone(),
                full_raw,
                packet: captured.packet().clone(),
            })
        }
        _ => Err(format!("wire compare root unavailable for live capture: {compare_root}").into()),
    }
}

fn ip_header_offset(bytes: &[u8], version: u8, ethertype: u16) -> ExampleResult<usize> {
    if bytes.first().is_some_and(|byte| byte >> 4 == version) {
        return Ok(0);
    }
    if bytes.len() >= 14 && u16::from_be_bytes([bytes[12], bytes[13]]) == ethertype {
        return Ok(14);
    }
    if bytes.len() >= 18
        && u16::from_be_bytes([bytes[12], bytes[13]]) == ETHERTYPE_VLAN
        && u16::from_be_bytes([bytes[16], bytes[17]]) == ethertype
    {
        return Ok(18);
    }
    if bytes.len() >= 16 && u16::from_be_bytes([bytes[14], bytes[15]]) == ethertype {
        return Ok(16);
    }
    Err(
        format!("captured packet cannot be sliced at IP header for ethertype 0x{ethertype:04x}")
            .into(),
    )
}

fn compare_root_for_index(
    request: &EndpointRequest,
    index: usize,
    fallback: &str,
) -> ExampleResult<String> {
    let compare_root = request
        .metadata
        .get("packets")
        .and_then(Value::as_array)
        .and_then(|packets| {
            packets.iter().find_map(|packet| {
                let packet_index = packet.get("index")?.as_u64()?;
                if usize::try_from(packet_index).ok()? == index {
                    packet.get("compare_root")?.as_str()
                } else {
                    None
                }
            })
        })
        .unwrap_or(fallback);
    Ok(canonical_compare_root(compare_root)?.to_string())
}

fn canonical_compare_root(root: &str) -> ExampleResult<&'static str> {
    match root {
        "Ether" | "link:ethernet" => Ok("link:ethernet"),
        "IP" | "IPv4" | "l3:ipv4" => Ok("l3:ipv4"),
        "IPv6" | "l3:ipv6" => Ok("l3:ipv6"),
        _ => Err(format!("wire compare root unavailable for live capture: {root}").into()),
    }
}

fn normalize_layer_name(name: &str) -> &str {
    match name {
        "Dns" => "dns",
        "Ethernet" => "ethernet",
        "ICMP" => "icmp",
        "Icmp" => "icmp",
        "ICMPv6" => "icmpv6",
        "ICMPv6EchoRequest" => "icmpv6",
        "Icmpv6" => "icmpv6",
        "IPv4" => "ipv4",
        "Ipv4" => "ipv4",
        "IPv6" => "ipv6",
        "Ipv6" => "ipv6",
        "TCP" => "tcp",
        "Tcp" => "tcp",
        "UDP" => "udp",
        "Udp" => "udp",
        "Raw" => "payload",
        value => value,
    }
}

fn typed_layer_fields(layer: &dyn Layer, name: &str) -> Option<Map<String, Value>> {
    match name {
        "ipv6" => layer.as_any().downcast_ref::<Ipv6>().map(ipv6_fields),
        "tcp" => layer.as_any().downcast_ref::<Tcp>().map(tcp_fields),
        "icmp" => layer.as_any().downcast_ref::<Icmp>().map(icmp_fields),
        "icmpv6" => layer.as_any().downcast_ref::<Icmpv6>().map(icmpv6_fields),
        "dns" => layer.as_any().downcast_ref::<Dns>().map(dns_fields),
        _ => None,
    }
}

fn ipv6_fields(layer: &Ipv6) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("version".to_string(), json!(layer.version_value()));
    fields.insert(
        "traffic_class".to_string(),
        json!(layer.traffic_class_value()),
    );
    fields.insert("flow_label".to_string(), json!(layer.flow_label_value()));
    if let Some(value) = layer.payload_length_value() {
        fields.insert("payload_length".to_string(), json!(value));
    }
    fields.insert("next_header".to_string(), json!(layer.next_header_value()));
    fields.insert("hop_limit".to_string(), json!(layer.hop_limit_value()));
    fields.insert("src".to_string(), json!(layer.source().to_string()));
    fields.insert("dst".to_string(), json!(layer.destination().to_string()));
    fields
}

fn tcp_fields(layer: &Tcp) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("src_port".to_string(), json!(layer.source_port_value()));
    fields.insert(
        "dst_port".to_string(),
        json!(layer.destination_port_value()),
    );
    fields.insert("sequence".to_string(), json!(layer.sequence_number_value()));
    fields.insert(
        "acknowledgement".to_string(),
        json!(layer.acknowledgment_number_value()),
    );
    fields.insert("data_offset".to_string(), json!(layer.data_offset_value()));
    fields.insert("reserved".to_string(), json!(layer.reserved_value()));
    fields.insert(
        "flags".to_string(),
        json!(tcp_flag_names(layer.flags_value())),
    );
    fields.insert("window".to_string(), json!(layer.window_value()));
    fields.insert(
        "urgent_pointer".to_string(),
        json!(layer.urgent_pointer_value()),
    );
    fields.insert(
        "options".to_string(),
        json!(hex_bytes(layer.option_bytes())),
    );
    if let Some(value) = layer.checksum_value() {
        fields.insert("checksum".to_string(), json!(value));
    }
    fields
}

fn icmp_fields(layer: &Icmp) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("type".to_string(), json!(layer.icmp_type_value()));
    fields.insert("code".to_string(), json!(layer.code_value()));
    fields.insert(
        "rest_of_header".to_string(),
        json!(hex_bytes(&layer.rest_of_header_value())),
    );
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

fn icmpv6_fields(layer: &Icmpv6) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("type".to_string(), json!(layer.icmp_type_value()));
    fields.insert("code".to_string(), json!(layer.code_value()));
    fields.insert(
        "rest_of_header".to_string(),
        json!(hex_bytes(&layer.rest_of_header_value())),
    );
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

fn dns_fields(layer: &Dns) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("transaction_id".to_string(), json!(layer.id_value()));
    fields.insert(
        "is_response".to_string(),
        json!(dns_flag_enabled(layer, DNS_FLAG_QR_RESPONSE)),
    );
    fields.insert(
        "opcode".to_string(),
        json!((layer.flags_value() >> 11) & 0x0f),
    );
    fields.insert(
        "authoritative".to_string(),
        json!(dns_flag_enabled(layer, DNS_FLAG_AUTHORITATIVE)),
    );
    fields.insert(
        "truncated".to_string(),
        json!(dns_flag_enabled(layer, DNS_FLAG_TRUNCATED)),
    );
    fields.insert(
        "recursion_desired".to_string(),
        json!(dns_flag_enabled(layer, DNS_FLAG_RECURSION_DESIRED)),
    );
    fields.insert(
        "recursion_available".to_string(),
        json!(dns_flag_enabled(layer, DNS_FLAG_RECURSION_AVAILABLE)),
    );
    fields.insert("z".to_string(), json!((layer.flags_value() >> 6) & 0x01));
    fields.insert(
        "authenticated_data".to_string(),
        json!(dns_flag_enabled(layer, DNS_FLAG_AUTHENTIC_DATA)),
    );
    fields.insert(
        "checking_disabled".to_string(),
        json!(dns_flag_enabled(layer, DNS_FLAG_CHECKING_DISABLED)),
    );
    fields.insert(
        "response_code".to_string(),
        json!(layer.flags_value() & 0x0f),
    );
    fields.insert("question_count".to_string(), json!(layer.questions().len()));
    fields.insert("answer_count".to_string(), json!(layer.answers().len()));
    fields.insert(
        "authority_count".to_string(),
        json!(layer.authorities().len()),
    );
    fields.insert(
        "additional_count".to_string(),
        json!(layer.additionals().len()),
    );
    fields
}

fn dns_flag_enabled(dns: &Dns, flag: u16) -> bool {
    dns.flags_value() & flag != 0
}

fn tcp_flag_names(flags: u16) -> String {
    let mut names = Vec::new();
    for (bit, name) in [
        (TCP_FLAG_FIN, "fin"),
        (TCP_FLAG_SYN, "syn"),
        (TCP_FLAG_RST, "rst"),
        (TCP_FLAG_PSH, "psh"),
        (TCP_FLAG_ACK, "ack"),
        (TCP_FLAG_URG, "urg"),
        (TCP_FLAG_ECE, "ece"),
        (TCP_FLAG_CWR, "cwr"),
        (TCP_FLAG_NS, "ns"),
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
        ("ipv6", "traffic_class") => Ok(Some((field.to_string(), json!(u64_text(value)?)))),
        ("ipv6", "flow_label") => Ok(Some((field.to_string(), json!(u64_text(value)?)))),
        ("ipv6", "payload_length") if value == "auto" => Ok(None),
        ("ipv6", "payload_length") | ("ipv6", "hop_limit") | ("ipv6", "version") => {
            Ok(Some((field.to_string(), json!(u64_text(value)?))))
        }
        ("ipv6", "next_header") => Ok(Some((field.to_string(), json!(protocol_number(value)?)))),
        ("ipv6", "src") | ("ipv6", "dst") => Ok(Some((field.to_string(), json!(value)))),
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
        "tcp" => Ok(Box::new(tcp_layer(plan)?)),
        "icmp" => Ok(Box::new(icmp_layer(plan)?)),
        "icmpv6" => Ok(Box::new(icmpv6_layer(plan)?)),
        "dns" => Ok(Box::new(dns_layer(plan)?)),
        "dhcp" => Ok(Box::new(dhcp_layer(plan)?)),
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
        .urgptr(
            optional(fields, &["urgent_pointer", "urgptr"])
                .map(u16_value)
                .transpose()?
                .unwrap_or(0),
        );
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
        .id(optional(fields, &["transaction_id", "id"])
            .map(u16_value)
            .transpose()?
            .unwrap_or(0))
        .flags(dns_flags(fields)?)
        .response(
            optional(fields, &["is_response"])
                .map(bool_value)
                .transpose()?
                .unwrap_or(false),
        )
        .rcode(
            optional(fields, &["response_code"])
                .map(dns_response_code)
                .transpose()?
                .unwrap_or(0),
        );

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

fn dhcp_layer(plan: &Value) -> ExampleResult<Dhcp> {
    let fields = layer_fields(plan, "dhcp")?;
    // The fixed BOOTP header fields are optional: a minimal live-friendly DHCP
    // plan emits only op/flags/options and relies on `Dhcp::new()` defaults
    // (BOOTP_REQUEST op, Ethernet htype, hlen 6, xid 0, zero MAC, unspecified
    // addresses) for anything it does not set. This mirrors the materialize
    // adapter so DHCP flows through the same generic endpoint batch contract.
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

fn hardware_type_value(value: &Value) -> ExampleResult<u16> {
    if let Some(text) = value.as_str() {
        if matches!(text.to_ascii_lowercase().as_str(), "ether" | "ethernet") {
            return Ok(1);
        }
        return u16_text(text);
    }
    u16_value(value)
}

fn parse_ipv4_list(value: &str) -> ExampleResult<Vec<Ipv4Addr>> {
    value
        .split(',')
        .filter(|item| !item.is_empty())
        .map(Ipv4Addr::from_str)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn mac_bytes(value: &str) -> ExampleResult<Vec<u8>> {
    Ok(MacAddr::from_str(value)?.octets().to_vec())
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
            "icmp" => Ok(IPPROTO_ICMP),
            "tcp" => Ok(IPPROTO_TCP),
            "udp" => Ok(IPPROTO_UDP),
            _ => u8_text(text),
        };
    }
    u8_value(value)
}

fn ipv6_next_header(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().as_str() {
            "icmpv6" => Ok(IPPROTO_ICMPV6),
            "payload" | "raw" | "unknown" => Ok(253),
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
        return Ok(tcp_flag_text_value(text));
    }
    if let Some(items) = value.as_array() {
        let mut flags = 0;
        for item in items {
            if let Some(text) = item.as_str() {
                if text == "all" {
                    flags |= 0x01ff;
                } else {
                    flags |= tcp_flag_text_value(text);
                }
            }
        }
        return Ok(flags);
    }
    u16_value(value)
}

fn tcp_flag_text_value(text: &str) -> u16 {
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
    } else {
        flags |= DNS_FLAG_RECURSION_DESIRED;
    }
    if optional(fields, &["is_response"])
        .map(bool_value)
        .transpose()?
        .unwrap_or(false)
    {
        flags |= DNS_FLAG_QR_RESPONSE;
    }
    if let Some(value) = optional(fields, &["response_code"]) {
        flags |= dns_response_code(value)? as u16;
    }
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

fn array_values(value: &Value) -> ExampleResult<&Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| format!("expected array value, got {value:?}").into())
}

fn u8_value(value: &Value) -> ExampleResult<u8> {
    Ok(u8::try_from(u64_value(value)?)?)
}

fn u16_text(text: &str) -> ExampleResult<u16> {
    Ok(u16::try_from(u64_text(text)?)?)
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

/// Live endpoint batch contract coverage for the IPv4-root `ipv4 / udp / dhcp`
/// stack.
///
/// DHCP flows through the same generic endpoint batch contract every other
/// protocol uses: the libcrafter live endpoint binary must build the
/// `ipv4 / udp / dhcp` packet (no Ethernet frame, no DHCP-specific protocol),
/// compile it, and run the dry-run sender/receiver phases for both oracle
/// directions. The dry-run path sends and captures nothing; all addresses are
/// RFC 5737 documentation space and the run never touches a network.
#[cfg(test)]
mod ipv4_dhcp_live_endpoint {
    use super::*;
    use serde_json::json;

    const ENDPOINT_BACKEND: &str = "libcrafter";

    /// A unique scratch directory under the OS temp dir so the dry-run batch
    /// never writes artifacts into the source tree.
    fn artifact_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "libcrafter-test-ipv4-dhcp-live-endpoint-{}",
            std::process::id()
        ))
    }

    /// A minimal live-friendly `ipv4 / udp / dhcp` plan matching the seeded
    /// generator output: only the DHCP op/flags/options are set so the fixed
    /// BOOTP header falls back to `Dhcp::new()` defaults.
    fn ipv4_dhcp_discover_plan(index: usize) -> Value {
        json!({
            "stack": ["ipv4", "udp", "dhcp"],
            "index": index,
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

    fn artifact_paths(direction: &str, endpoint_role: &str) -> Value {
        let base = artifact_root();
        let root = base
            .join("artifacts")
            .join(direction)
            .join(endpoint_role)
            .to_string_lossy()
            .into_owned();
        json!({
            "root": root,
            "request": format!("{root}/request.json"),
            "response": format!("{root}/response.json"),
            "stdout": format!("{root}/stdout.log"),
            "stderr": format!("{root}/stderr.log"),
            "captures": format!("{root}/captures"),
            "decoded_models": format!("{root}/decoded-models.json"),
        })
    }

    /// Build a libcrafter live endpoint batch request for one direction. The
    /// `phase_role` is left to be inferred from the direction so the binary's
    /// own role-assignment logic is exercised.
    fn dhcp_request(direction: &str) -> EndpointRequest {
        let plans = vec![ipv4_dhcp_discover_plan(11), ipv4_dhcp_discover_plan(12)];
        let artifact_paths = artifact_paths(direction, "libcrafter");
        EndpointRequest {
            provider: "local-dry-run".to_string(),
            backend: ENDPOINT_BACKEND.to_string(),
            seed: 110,
            profile: "smoke".to_string(),
            packet_plans: plans,
            direction: direction.to_string(),
            endpoint_id: "local-dry-run-libcrafter".to_string(),
            endpoint_role: "libcrafter".to_string(),
            peer_role: "reference_backend".to_string(),
            local_addresses: json!({ "ipv4": "192.0.2.10" }),
            peer_addresses: json!({ "ipv4": "192.0.2.20" }),
            interface: "dry-run0".to_string(),
            timeout_seconds: 30,
            artifact_paths,
            metadata: json!({
                "packets": [
                    { "index": 11, "compare_root": "l3:ipv4" },
                    { "index": 12, "compare_root": "l3:ipv4" }
                ]
            }),
        }
    }

    fn run_dry(direction: &str) -> Value {
        let request = dhcp_request(direction);
        let request_json = serde_json::to_value(json!({
            "provider": request.provider,
            "backend": request.backend,
            "seed": request.seed,
            "profile": request.profile,
            "packet_plans": request.packet_plans,
            "direction": request.direction,
            "endpoint_id": request.endpoint_id,
            "endpoint_role": request.endpoint_role,
            "peer_role": request.peer_role,
            "local_addresses": request.local_addresses,
            "peer_addresses": request.peer_addresses,
            "interface": request.interface,
            "timeout_seconds": request.timeout_seconds,
            "artifact_paths": request.artifact_paths,
            "metadata": request.metadata,
        }))
        .expect("request must serialize");
        let args = Args {
            input: None,
            out: artifact_root().join(direction),
            mode: RunMode::DryRun,
        };
        run_endpoint(&request, request_json, &args)
            .expect("ipv4/udp/dhcp dry-run endpoint batch must run")
    }

    fn status_indexes(response: &Value) -> Vec<u64> {
        response
            .get("per_index_status")
            .and_then(Value::as_array)
            .expect("response must carry per_index_status")
            .iter()
            .map(|status| {
                status
                    .get("index")
                    .and_then(Value::as_u64)
                    .expect("status must carry an index")
            })
            .collect()
    }

    #[test]
    fn ipv4_dhcp_plan_builds_through_generic_live_endpoint_contract() {
        // The generic batch contract must materialize the DHCP stack with no
        // DHCP-specific protocol: ipv4 / udp / dhcp, compiled and re-decodable.
        let request = dhcp_request("libcrafter_to_reference");
        let prepared = prepare_packets(&request.packet_plans)
            .expect("ipv4/udp/dhcp plans must prepare through the generic contract");

        assert_eq!(prepared.len(), 2);
        for (offset, prepared_packet) in prepared.iter().enumerate() {
            assert_eq!(prepared_packet.index, 11 + offset);
            assert_eq!(prepared_packet.root, "l3:ipv4");
            assert!(
                !prepared_packet.raw_hex.is_empty(),
                "compiled DHCP packet must carry bytes"
            );

            let bytes = decode_hex(&prepared_packet.raw_hex).expect("raw_hex must decode");
            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes)
                .expect("compiled IPv4 DHCP packet must re-decode from l3");
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
            assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Discover));
        }
    }

    #[test]
    fn ipv4_dhcp_libcrafter_to_reference_assigns_sender_role() {
        let request = dhcp_request("libcrafter_to_reference");
        // libcrafter is the sender when crafting toward the reference backend.
        assert_eq!(
            phase_role(&request).expect("phase role must resolve"),
            "sender"
        );

        let response = run_dry("libcrafter_to_reference");

        assert_eq!(
            response.get("direction").and_then(Value::as_str),
            Some("libcrafter_to_reference")
        );
        assert_eq!(
            response.get("endpoint_role").and_then(Value::as_str),
            Some("libcrafter")
        );
        assert_eq!(
            response.get("provider").and_then(Value::as_str),
            Some("local-dry-run")
        );
        assert_eq!(
            response.get("backend").and_then(Value::as_str),
            Some(ENDPOINT_BACKEND)
        );
        // Packet IDs / indexes round-trip from the request.
        assert_eq!(status_indexes(&response), vec![11, 12]);
        // The dry-run sender plans but sends nothing.
        assert_eq!(response.get("sent_count").and_then(Value::as_u64), Some(0));
        assert_eq!(
            response.get("received_count").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            response
                .get("decoded_models")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0),
            "dry-run sender must not decode models"
        );
        let detail = response.pointer("/metadata/detail/phase_role");
        assert_eq!(detail.and_then(Value::as_str), Some("sender"));
        // Sender status carries the IPv4 send root the plan declared.
        for status in response
            .get("per_index_status")
            .and_then(Value::as_array)
            .expect("statuses")
        {
            assert_eq!(status.get("sent").and_then(Value::as_bool), Some(false));
            assert_eq!(
                status.get("send_root").and_then(Value::as_str),
                Some("l3:ipv4")
            );
            assert_eq!(
                status.get("send_mode").and_then(Value::as_str),
                Some("network-layer")
            );
        }
        // Artifact paths echo the request so the orchestrator can collect them.
        let expected_response_path = artifact_paths("libcrafter_to_reference", "libcrafter")
            .get("response")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .expect("artifact paths must declare a response path");
        assert!(
            expected_response_path
                .ends_with("artifacts/libcrafter_to_reference/libcrafter/response.json"),
            "unexpected response artifact path: {expected_response_path}"
        );
        assert_eq!(
            response
                .pointer("/artifact_paths/response")
                .and_then(Value::as_str),
            Some(expected_response_path.as_str())
        );
    }

    #[test]
    fn ipv4_dhcp_reference_to_libcrafter_assigns_receiver_role() {
        let request = dhcp_request("reference_to_libcrafter");
        // libcrafter is the receiver when the reference backend is the sender.
        assert_eq!(
            phase_role(&request).expect("phase role must resolve"),
            "receiver"
        );

        let response = run_dry("reference_to_libcrafter");

        assert_eq!(
            response.get("direction").and_then(Value::as_str),
            Some("reference_to_libcrafter")
        );
        assert_eq!(status_indexes(&response), vec![11, 12]);
        assert_eq!(
            response.get("received_count").and_then(Value::as_u64),
            Some(0)
        );
        let detail = response.pointer("/metadata/detail/phase_role");
        assert_eq!(detail.and_then(Value::as_str), Some("receiver"));
        // Receiver statuses pin the IPv4 capture (compare) root.
        for status in response
            .get("per_index_status")
            .and_then(Value::as_array)
            .expect("statuses")
        {
            assert_eq!(status.get("received").and_then(Value::as_bool), Some(false));
            assert_eq!(
                status.get("capture_root").and_then(Value::as_str),
                Some("l3:ipv4")
            );
        }
    }
}
