use crafter::prelude::*;
use serde::Deserialize;
use serde_json::{json, Value};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

type ExampleResult<T> = std::result::Result<T, Box<dyn Error>>;

const BACKEND_NAME: &str = "libcrafter";
const FAILURE_TIMEOUT: &str = "timeout";
const FAILURE_WRONG_PEER: &str = "wrong_peer";
const FAILURE_WRONG_PAYLOAD: &str = "wrong_payload";
const FAILURE_DECODE_FAILED: &str = "decode_failed";

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
struct ProbeEndpointRequest {
    provider: String,
    profile: String,
    seed: u64,
    endpoint_role: String,
    interface: String,
    local_ipv4: String,
    peer_ipv4: String,
    timeout_seconds: u64,
    probe_plans: Vec<IcmpEchoPlan>,
    #[serde(default)]
    artifact_paths: Value,
    #[serde(default)]
    metadata: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct IcmpEchoPlan {
    case: String,
    sequence: usize,
    identifier: u16,
    sequence_number: u16,
    payload_hex: String,
    source_ipv4: String,
    destination_ipv4: String,
    expected_reply_source_ipv4: String,
    expected_reply_destination_ipv4: String,
}

#[derive(Debug)]
struct ProbeOutcome {
    result: Value,
    observed_response: Value,
    sent: bool,
    received: bool,
}

#[derive(Debug)]
enum CandidateValidation {
    Ignore,
    Passed(Value),
    WrongPeer(Value),
    WrongPayload(Value),
}

fn main() -> ExampleResult<()> {
    let args = parse_args()?;
    let input = read_input(args.input.clone())?;
    let request: ProbeEndpointRequest = serde_json::from_str(&input)?;
    let request_json: Value = serde_json::from_str(&input)?;
    let response = run_endpoint(&request, request_json, &args)?;

    serde_json::to_writer_pretty(io::stdout(), &response)?;
    println!();
    Ok(())
}

fn parse_args() -> ExampleResult<Args> {
    let mut input = None;
    let mut out = PathBuf::from("target/probe/libcrafter-probe-endpoint");
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
        "usage: cargo run -p crafter --example probe_endpoint -- [--dry-run|--live] --input PATH|- [--out DIR]\n\nRun the libcrafter stimulus endpoint for probe cases. Dry-run is the default and compiles probe packets without sending traffic."
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
    request: &ProbeEndpointRequest,
    request_json: Value,
    args: &Args,
) -> ExampleResult<Value> {
    if request.endpoint_role != "stimulus" {
        return Err(format!(
            "probe_endpoint only supports endpoint_role=stimulus, got {}",
            request.endpoint_role
        )
        .into());
    }

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

    let mut results = Vec::with_capacity(request.probe_plans.len());
    let mut observed_responses = Vec::with_capacity(request.probe_plans.len());
    let mut sent_count = 0usize;
    let mut received_count = 0usize;
    let mut errors = Vec::new();

    for plan in &request.probe_plans {
        if plan.case != "icmp-echo" {
            let message = format!("unsupported probe case: {}", plan.case);
            errors.push(message.clone());
            let outcome = failed_outcome(
                plan,
                FAILURE_DECODE_FAILED,
                vec![message],
                None,
                false,
                false,
            );
            results.push(outcome.result);
            observed_responses.push(outcome.observed_response);
            continue;
        }

        let outcome = if args.mode.is_dry_run() {
            run_icmp_dry_run(request, plan)?
        } else {
            run_icmp_live(request, plan)?
        };
        if outcome.sent {
            sent_count += 1;
        }
        if outcome.received {
            received_count += 1;
        }
        results.push(outcome.result);
        observed_responses.push(outcome.observed_response);
    }

    let response = json!({
        "provider": request.provider,
        "backend": BACKEND_NAME,
        "endpoint_role": request.endpoint_role,
        "profile": request.profile,
        "seed": request.seed,
        "mode": if args.mode.is_dry_run() { "dry-run" } else { "live" },
        "sent_count": sent_count,
        "received_count": received_count,
        "results": results,
        "observed_responses": observed_responses,
        "errors": errors,
        "artifacts": [
            artifact_path(&args.out, &request.artifact_paths, "request", "request.json"),
            artifact_path(&args.out, &request.artifact_paths, "response", "response.json")
        ],
        "artifact_paths": request.artifact_paths,
        "metadata": {
            "backend": BACKEND_NAME,
            "dry_run": args.mode.is_dry_run(),
            "libcrafter_version": env!("CARGO_PKG_VERSION"),
            "interface": request.interface,
            "local_ipv4": request.local_ipv4,
            "peer_ipv4": request.peer_ipv4,
            "request_metadata": request.metadata,
            "failure_reasons": [
                FAILURE_TIMEOUT,
                FAILURE_WRONG_PEER,
                FAILURE_WRONG_PAYLOAD,
                FAILURE_DECODE_FAILED
            ]
        }
    });

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

fn run_icmp_dry_run(
    request: &ProbeEndpointRequest,
    plan: &IcmpEchoPlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = icmp_packet(plan)?;
    let report = SocketSender::new(
        SendOptions::new()
            .iface(request.interface.clone())
            .network_layer()
            .dry_run(),
    )
    .send(&packet)?;
    let sent_raw_hex = hex_bytes(report.plan().bytes());
    let observed = observed_response(
        plan,
        false,
        None,
        json!({}),
        json!({
            "planned_only": true,
            "send_report": send_report_json(&report),
            "sent_raw_hex": sent_raw_hex,
            "capture_filter": capture_filter(plan),
        }),
    );
    let result = json!({
        "case": plan.case,
        "sequence": plan.sequence,
        "status": "planned",
        "endpoint_role": "stimulus",
        "passed": null,
        "observed_response": observed,
        "metadata": {
            "dry_run": true,
            "probe_plan": plan_json(plan),
            "planned_only": true,
            "sent_raw_hex": sent_raw_hex,
            "capture_filter": capture_filter(plan),
        }
    });
    Ok(ProbeOutcome {
        result,
        observed_response: observed,
        sent: false,
        received: false,
    })
}

fn run_icmp_live(
    request: &ProbeEndpointRequest,
    plan: &IcmpEchoPlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = icmp_packet(plan)?;
    let timeout = Duration::from_secs(request.timeout_seconds.max(1));
    let mut sniffer = match Sniffer::interface(request.interface.clone())
        .timeout(timeout)
        .count(32)
        .filter("icmp")
        .open()
    {
        Ok(sniffer) => sniffer,
        Err(err) => {
            return Ok(failed_outcome(
                plan,
                FAILURE_DECODE_FAILED,
                vec![format!("capture open failed: {err}")],
                None,
                false,
                false,
            ));
        }
    };
    let send_report = match SocketSender::new(
        SendOptions::new()
            .iface(request.interface.clone())
            .network_layer()
            .live(),
    )
    .send(&packet)
    {
        Ok(report) => report,
        Err(err) => {
            return Ok(failed_outcome(
                plan,
                FAILURE_DECODE_FAILED,
                vec![format!("send failed: {err}")],
                None,
                false,
                false,
            ));
        }
    };

    let sent = send_report.bytes_sent() > 0;
    let mut wrong_peer = None;
    while let Some(captured) = match sniffer.next_packet() {
        Ok(packet) => packet,
        Err(err) => {
            return Ok(failed_outcome(
                plan,
                FAILURE_DECODE_FAILED,
                vec![format!("capture decode failed: {err}")],
                Some(send_report_json(&send_report)),
                sent,
                false,
            ));
        }
    } {
        match validate_candidate(plan, captured.packet(), captured.data())? {
            CandidateValidation::Ignore => {}
            CandidateValidation::Passed(decoded) => {
                let raw_hex = hex_bytes(captured.data());
                let observed = observed_response(
                    plan,
                    true,
                    Some(raw_hex.clone()),
                    decoded.clone(),
                    json!({
                        "send_report": send_report_json(&send_report),
                        "capture_filter": capture_filter(plan),
                    }),
                );
                let result = json!({
                    "case": plan.case,
                    "sequence": plan.sequence,
                    "status": "passed",
                    "endpoint_role": "stimulus",
                    "passed": true,
                    "observed_response": observed,
                    "metadata": {
                        "dry_run": false,
                        "probe_plan": plan_json(plan),
                        "raw_hex": raw_hex,
                        "decoded": decoded,
                    }
                });
                return Ok(ProbeOutcome {
                    result,
                    observed_response: observed,
                    sent,
                    received: true,
                });
            }
            CandidateValidation::WrongPeer(decoded) => {
                wrong_peer = Some(decoded);
            }
            CandidateValidation::WrongPayload(decoded) => {
                return Ok(failed_outcome(
                    plan,
                    FAILURE_WRONG_PAYLOAD,
                    vec!["ICMP echo reply payload did not match request payload".to_string()],
                    Some(json!({
                        "send_report": send_report_json(&send_report),
                        "decoded": decoded,
                    })),
                    sent,
                    true,
                ));
            }
        }
    }

    if let Some(decoded) = wrong_peer {
        return Ok(failed_outcome(
            plan,
            FAILURE_WRONG_PEER,
            vec!["captured ICMP echo reply did not match expected peer or echo fields".to_string()],
            Some(json!({
                "send_report": send_report_json(&send_report),
                "decoded": decoded,
            })),
            sent,
            true,
        ));
    }

    Ok(failed_outcome(
        plan,
        FAILURE_TIMEOUT,
        vec!["timed out waiting for ICMP echo reply".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter(plan),
        })),
        sent,
        false,
    ))
}

fn failed_outcome(
    plan: &IcmpEchoPlan,
    reason: &str,
    errors: Vec<String>,
    metadata: Option<Value>,
    sent: bool,
    received: bool,
) -> ProbeOutcome {
    let observed_errors = errors.clone();
    let observed = observed_response(
        plan,
        received,
        None,
        json!({}),
        json!({
            "failure_reason": reason,
            "errors": observed_errors,
            "detail": metadata.unwrap_or_else(|| json!({})),
        }),
    );
    let result = json!({
        "case": plan.case,
        "sequence": plan.sequence,
        "status": "failed",
        "endpoint_role": "stimulus",
        "passed": false,
        "observed_response": observed,
        "metadata": {
            "failure_reason": reason,
            "errors": errors,
            "probe_plan": plan_json(plan),
        }
    });
    ProbeOutcome {
        result,
        observed_response: observed,
        sent,
        received,
    }
}

fn validate_candidate(
    plan: &IcmpEchoPlan,
    packet: &Packet,
    raw: &[u8],
) -> ExampleResult<CandidateValidation> {
    let Some(icmp) = packet.layer::<Icmp>() else {
        return Ok(CandidateValidation::Ignore);
    };
    if icmp.icmp_type_value() != ICMP_ECHO_REPLY {
        return Ok(CandidateValidation::Ignore);
    }

    let expected_source: Ipv4Addr = plan.expected_reply_source_ipv4.parse()?;
    let expected_destination: Ipv4Addr = plan.expected_reply_destination_ipv4.parse()?;
    let mut mismatches = Vec::new();

    match packet.layer::<Ipv4>() {
        Some(ipv4) => {
            if ipv4.source() != expected_source {
                mismatches.push(json!({
                    "field": "ipv4.src",
                    "expected": expected_source.to_string(),
                    "actual": ipv4.source().to_string(),
                }));
            }
            if ipv4.destination() != expected_destination {
                mismatches.push(json!({
                    "field": "ipv4.dst",
                    "expected": expected_destination.to_string(),
                    "actual": ipv4.destination().to_string(),
                }));
            }
        }
        None => mismatches.push(json!({
            "field": "ipv4",
            "expected": "present",
            "actual": "missing",
        })),
    }

    if icmp.code_value() != 0 {
        mismatches.push(json!({
            "field": "icmp.code",
            "expected": 0,
            "actual": icmp.code_value(),
        }));
    }
    if icmp.identifier_value() != Some(plan.identifier) {
        mismatches.push(json!({
            "field": "icmp.identifier",
            "expected": plan.identifier,
            "actual": icmp.identifier_value(),
        }));
    }
    if icmp.sequence_number_value() != Some(plan.sequence_number) {
        mismatches.push(json!({
            "field": "icmp.sequence",
            "expected": plan.sequence_number,
            "actual": icmp.sequence_number_value(),
        }));
    }

    let decoded = decoded_packet_json(packet, raw);
    if !mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPeer(json!({
            "packet": decoded,
            "mismatches": mismatches,
        })));
    }

    let expected_payload = decode_hex(&plan.payload_hex)?;
    let actual_payload = raw_payload(packet);
    if actual_payload != expected_payload.as_slice() {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "expected_payload_hex": plan.payload_hex,
            "actual_payload_hex": hex_bytes(actual_payload),
        })));
    }

    Ok(CandidateValidation::Passed(decoded))
}

fn icmp_packet(plan: &IcmpEchoPlan) -> ExampleResult<Packet> {
    let source: Ipv4Addr = plan.source_ipv4.parse()?;
    let destination: Ipv4Addr = plan.destination_ipv4.parse()?;
    let payload = decode_hex(&plan.payload_hex)?;
    Ok(Ipv4::new().src(source).dst(destination)
        / Icmp::echo_request()
            .id(plan.identifier)
            .seq(plan.sequence_number)
        / Raw::from_bytes(payload))
}

fn observed_response(
    plan: &IcmpEchoPlan,
    observed: bool,
    raw_hex: Option<String>,
    decoded: Value,
    metadata: Value,
) -> Value {
    json!({
        "case": plan.case,
        "sequence": plan.sequence,
        "endpoint_role": "stimulus",
        "observed": observed,
        "response_type": "icmp_echo_reply",
        "raw_hex": raw_hex,
        "decoded": decoded,
        "metadata": metadata,
    })
}

fn plan_json(plan: &IcmpEchoPlan) -> Value {
    json!({
        "case": plan.case,
        "sequence": plan.sequence,
        "identifier": plan.identifier,
        "sequence_number": plan.sequence_number,
        "payload_hex": plan.payload_hex,
        "source_ipv4": plan.source_ipv4,
        "destination_ipv4": plan.destination_ipv4,
        "expected_reply_source_ipv4": plan.expected_reply_source_ipv4,
        "expected_reply_destination_ipv4": plan.expected_reply_destination_ipv4,
        "capture_filter": capture_filter(plan),
    })
}

fn decoded_packet_json(packet: &Packet, raw: &[u8]) -> Value {
    let ipv4 = packet.layer::<Ipv4>();
    let icmp = packet.layer::<Icmp>();
    json!({
        "backend": BACKEND_NAME,
        "summary": packet.summary(),
        "raw_hex": hex_bytes(raw),
        "ipv4": ipv4.map(|layer| json!({
            "src": layer.source().to_string(),
            "dst": layer.destination().to_string(),
            "ttl": layer.ttl_value(),
            "protocol": layer.protocol_value(),
        })),
        "icmp": icmp.map(|layer| json!({
            "type": layer.icmp_type_value(),
            "code": layer.code_value(),
            "identifier": layer.identifier_value(),
            "sequence": layer.sequence_number_value(),
        })),
        "payload_hex": hex_bytes(raw_payload(packet)),
    })
}

fn raw_payload(packet: &Packet) -> &[u8] {
    packet.layer::<Raw>().map(Raw::as_bytes).unwrap_or(&[])
}

fn capture_filter(plan: &IcmpEchoPlan) -> String {
    format!(
        "icmp and src host {} and dst host {}",
        plan.expected_reply_source_ipv4, plan.expected_reply_destination_ipv4
    )
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

fn write_json(path: &Path, value: &Value) -> ExampleResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn decode_hex(hex: &str) -> ExampleResult<Vec<u8>> {
    let clean = hex
        .chars()
        .filter(|char| !char.is_whitespace())
        .collect::<String>();
    if clean.len() % 2 != 0 {
        return Err("hex string must contain an even number of digits".into());
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    let mut index = 0usize;
    while index < clean.len() {
        bytes.push(u8::from_str_radix(&clean[index..index + 2], 16)?);
        index += 2;
    }
    Ok(bytes)
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}
