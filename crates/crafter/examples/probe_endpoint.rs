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
const FAILURE_WRONG_FLAGS: &str = "wrong_flags";
const FAILURE_DECODE_FAILED: &str = "decode_failed";
const FAILURE_TARGET_SETUP_FAILED: &str = "target_setup_failed";

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
    probe_plans: Vec<ProbePlan>,
    #[serde(default)]
    artifact_paths: Value,
    #[serde(default)]
    metadata: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct ProbePlan {
    case: String,
    sequence: usize,
    #[serde(default)]
    expected_response: Option<String>,
    #[serde(default)]
    identifier: Option<u16>,
    #[serde(default)]
    sequence_number: Option<u16>,
    #[serde(default)]
    payload_hex: Option<String>,
    #[serde(default)]
    source_ipv4: Option<String>,
    #[serde(default)]
    destination_ipv4: Option<String>,
    #[serde(default)]
    expected_reply_source_ipv4: Option<String>,
    #[serde(default)]
    expected_reply_destination_ipv4: Option<String>,
    #[serde(default)]
    source_port: Option<u16>,
    #[serde(default)]
    destination_port: Option<u16>,
    #[serde(default)]
    tcp_sequence_number: Option<u32>,
    #[serde(default)]
    expected_acknowledgment_number: Option<u32>,
    #[serde(default)]
    window: Option<u16>,
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
        let outcome = match (args.mode, plan.case.as_str()) {
            (RunMode::DryRun, "icmp-echo") => run_icmp_dry_run(request, plan)?,
            (RunMode::Live, "icmp-echo") => run_icmp_live(request, plan)?,
            (RunMode::DryRun, "tcp-syn-open" | "tcp-syn-closed") => run_tcp_dry_run(request, plan)?,
            (RunMode::Live, "tcp-syn-open" | "tcp-syn-closed") => run_tcp_live(request, plan)?,
            _ => {
                let message = format!("unsupported probe case: {}", plan.case);
                errors.push(message.clone());
                failed_outcome(
                    plan,
                    FAILURE_DECODE_FAILED,
                    vec![message],
                    None,
                    false,
                    false,
                )
            }
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
                FAILURE_WRONG_FLAGS,
                FAILURE_DECODE_FAILED,
                FAILURE_TARGET_SETUP_FAILED
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
    plan: &ProbePlan,
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

fn run_icmp_live(request: &ProbeEndpointRequest, plan: &ProbePlan) -> ExampleResult<ProbeOutcome> {
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
        match validate_icmp_candidate(plan, captured.packet(), captured.data())? {
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

fn run_tcp_dry_run(
    request: &ProbeEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = tcp_packet(plan)?;
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
            "target_service": target_service_json(plan),
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
            "target_service": target_service_json(plan),
        }
    });
    Ok(ProbeOutcome {
        result,
        observed_response: observed,
        sent: false,
        received: false,
    })
}

fn run_tcp_live(request: &ProbeEndpointRequest, plan: &ProbePlan) -> ExampleResult<ProbeOutcome> {
    let packet = tcp_packet(plan)?;
    let timeout = Duration::from_secs(request.timeout_seconds.max(1));
    let mut sniffer = match Sniffer::interface(request.interface.clone())
        .timeout(timeout)
        .count(64)
        .filter(&capture_filter(plan))
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
    let mut wrong_flags = None;
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
        match validate_tcp_candidate(plan, captured.packet(), captured.data())? {
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
                wrong_flags = Some(decoded);
            }
        }
    }

    if let Some(decoded) = wrong_flags {
        return Ok(failed_outcome(
            plan,
            FAILURE_WRONG_FLAGS,
            vec!["captured TCP response flags did not match expectation".to_string()],
            Some(json!({
                "send_report": send_report_json(&send_report),
                "decoded": decoded,
            })),
            sent,
            true,
        ));
    }

    if let Some(decoded) = wrong_peer {
        return Ok(failed_outcome(
            plan,
            FAILURE_WRONG_PEER,
            vec!["captured TCP response did not match expected peer or ports".to_string()],
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
        vec![format!("timed out waiting for {}", expected_response(plan))],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter(plan),
        })),
        sent,
        false,
    ))
}

fn failed_outcome(
    plan: &ProbePlan,
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

fn validate_icmp_candidate(
    plan: &ProbePlan,
    packet: &Packet,
    raw: &[u8],
) -> ExampleResult<CandidateValidation> {
    let Some(icmp) = packet.layer::<Icmp>() else {
        return Ok(CandidateValidation::Ignore);
    };
    if icmp.icmp_type_value() != ICMP_ECHO_REPLY {
        return Ok(CandidateValidation::Ignore);
    }

    let expected_source: Ipv4Addr = required_str(
        plan.expected_reply_source_ipv4.as_deref(),
        "expected_reply_source_ipv4",
    )?
    .parse()?;
    let expected_destination: Ipv4Addr = required_str(
        plan.expected_reply_destination_ipv4.as_deref(),
        "expected_reply_destination_ipv4",
    )?
    .parse()?;
    let mut mismatches = Vec::new();
    let identifier = required_u16(plan.identifier, "identifier")?;
    let sequence_number = required_u16(plan.sequence_number, "sequence_number")?;

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
    if icmp.identifier_value() != Some(identifier) {
        mismatches.push(json!({
            "field": "icmp.identifier",
            "expected": identifier,
            "actual": icmp.identifier_value(),
        }));
    }
    if icmp.sequence_number_value() != Some(sequence_number) {
        mismatches.push(json!({
            "field": "icmp.sequence",
            "expected": sequence_number,
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

    let expected_payload = decode_hex(required_str(plan.payload_hex.as_deref(), "payload_hex")?)?;
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

fn validate_tcp_candidate(
    plan: &ProbePlan,
    packet: &Packet,
    raw: &[u8],
) -> ExampleResult<CandidateValidation> {
    let Some(tcp) = packet.layer::<Tcp>() else {
        return Ok(CandidateValidation::Ignore);
    };

    let expected_source: Ipv4Addr = required_str(
        plan.expected_reply_source_ipv4.as_deref(),
        "expected_reply_source_ipv4",
    )?
    .parse()?;
    let expected_destination: Ipv4Addr = required_str(
        plan.expected_reply_destination_ipv4.as_deref(),
        "expected_reply_destination_ipv4",
    )?
    .parse()?;
    let expected_source_port = required_u16(plan.destination_port, "destination_port")?;
    let expected_destination_port = required_u16(plan.source_port, "source_port")?;
    let expected_ack = required_u32(
        plan.expected_acknowledgment_number,
        "expected_acknowledgment_number",
    )?;
    let mut peer_mismatches = Vec::new();

    match packet.layer::<Ipv4>() {
        Some(ipv4) => {
            if ipv4.source() != expected_source {
                peer_mismatches.push(json!({
                    "field": "ipv4.src",
                    "expected": expected_source.to_string(),
                    "actual": ipv4.source().to_string(),
                }));
            }
            if ipv4.destination() != expected_destination {
                peer_mismatches.push(json!({
                    "field": "ipv4.dst",
                    "expected": expected_destination.to_string(),
                    "actual": ipv4.destination().to_string(),
                }));
            }
        }
        None => peer_mismatches.push(json!({
            "field": "ipv4",
            "expected": "present",
            "actual": "missing",
        })),
    }

    if tcp.source_port_value() != expected_source_port {
        peer_mismatches.push(json!({
            "field": "tcp.sport",
            "expected": expected_source_port,
            "actual": tcp.source_port_value(),
        }));
    }
    if tcp.destination_port_value() != expected_destination_port {
        peer_mismatches.push(json!({
            "field": "tcp.dport",
            "expected": expected_destination_port,
            "actual": tcp.destination_port_value(),
        }));
    }

    let decoded = decoded_packet_json(packet, raw);
    if !peer_mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPeer(json!({
            "packet": decoded,
            "mismatches": peer_mismatches,
        })));
    }

    let flags = tcp.flags_value();
    let mut flag_mismatches = Vec::new();
    match plan.case.as_str() {
        "tcp-syn-open" => {
            if flags & TCP_FLAG_SYN == 0 {
                flag_mismatches.push(flag_mismatch("tcp.flags.syn", true, false));
            }
            if flags & TCP_FLAG_ACK == 0 {
                flag_mismatches.push(flag_mismatch("tcp.flags.ack", true, false));
            }
            if flags & TCP_FLAG_RST != 0 {
                flag_mismatches.push(flag_mismatch("tcp.flags.rst", false, true));
            }
            if tcp.acknowledgment_number_value() != expected_ack {
                flag_mismatches.push(json!({
                    "field": "tcp.ack",
                    "expected": expected_ack,
                    "actual": tcp.acknowledgment_number_value(),
                }));
            }
        }
        "tcp-syn-closed" => {
            if flags & TCP_FLAG_RST == 0 {
                flag_mismatches.push(flag_mismatch("tcp.flags.rst", true, false));
            }
            if flags & TCP_FLAG_SYN != 0 {
                flag_mismatches.push(flag_mismatch("tcp.flags.syn", false, true));
            }
            if flags & TCP_FLAG_ACK != 0 && tcp.acknowledgment_number_value() != expected_ack {
                flag_mismatches.push(json!({
                    "field": "tcp.ack",
                    "expected": expected_ack,
                    "actual": tcp.acknowledgment_number_value(),
                }));
            }
        }
        _ => return Ok(CandidateValidation::Ignore),
    }

    if !flag_mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": flag_mismatches,
        })));
    }

    Ok(CandidateValidation::Passed(decoded))
}

fn icmp_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    let payload = decode_hex(required_str(plan.payload_hex.as_deref(), "payload_hex")?)?;
    let identifier = required_u16(plan.identifier, "identifier")?;
    let sequence_number = required_u16(plan.sequence_number, "sequence_number")?;
    Ok(Ipv4::new().src(source).dst(destination)
        / Icmp::echo_request().id(identifier).seq(sequence_number)
        / Raw::from_bytes(payload))
}

fn tcp_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    let source_port = required_u16(plan.source_port, "source_port")?;
    let destination_port = required_u16(plan.destination_port, "destination_port")?;
    let sequence_number = required_u32(plan.tcp_sequence_number, "tcp_sequence_number")?;
    let window = plan.window.unwrap_or(64240);
    Ok(Ipv4::new().src(source).dst(destination)
        / Tcp::new()
            .sport(source_port)
            .dport(destination_port)
            .seq(sequence_number)
            .flags(TCP_FLAG_SYN)
            .window(window))
}

fn observed_response(
    plan: &ProbePlan,
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
        "response_type": expected_response(plan),
        "raw_hex": raw_hex,
        "decoded": decoded,
        "metadata": metadata,
    })
}

fn plan_json(plan: &ProbePlan) -> Value {
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
        "expected_response": plan.expected_response,
        "source_port": plan.source_port,
        "destination_port": plan.destination_port,
        "tcp_sequence_number": plan.tcp_sequence_number,
        "expected_acknowledgment_number": plan.expected_acknowledgment_number,
        "window": plan.window,
        "target_service": target_service_json(plan),
        "capture_filter": capture_filter(plan),
    })
}

fn decoded_packet_json(packet: &Packet, raw: &[u8]) -> Value {
    let ipv4 = packet.layer::<Ipv4>();
    let icmp = packet.layer::<Icmp>();
    let tcp = packet.layer::<Tcp>();
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
        "tcp": tcp.map(|layer| json!({
            "sport": layer.source_port_value(),
            "dport": layer.destination_port_value(),
            "seq": layer.sequence_number_value(),
            "ack": layer.acknowledgment_number_value(),
            "flags": tcp_flag_names(layer.flags_value()),
            "flags_value": layer.flags_value(),
            "window": layer.window_value(),
        })),
        "payload_hex": hex_bytes(raw_payload(packet)),
    })
}

fn raw_payload(packet: &Packet) -> &[u8] {
    packet.layer::<Raw>().map(Raw::as_bytes).unwrap_or(&[])
}

fn capture_filter(plan: &ProbePlan) -> String {
    match plan.case.as_str() {
        "icmp-echo" => format!(
            "icmp and src host {} and dst host {}",
            plan.expected_reply_source_ipv4.as_deref().unwrap_or(""),
            plan.expected_reply_destination_ipv4
                .as_deref()
                .unwrap_or("")
        ),
        "tcp-syn-open" | "tcp-syn-closed" => format!(
            "tcp and src host {} and dst host {} and src port {} and dst port {}",
            plan.expected_reply_source_ipv4.as_deref().unwrap_or(""),
            plan.expected_reply_destination_ipv4
                .as_deref()
                .unwrap_or(""),
            plan.destination_port.unwrap_or(0),
            plan.source_port.unwrap_or(0),
        ),
        _ => String::new(),
    }
}

fn expected_response(plan: &ProbePlan) -> &str {
    plan.expected_response
        .as_deref()
        .unwrap_or(match plan.case.as_str() {
            "icmp-echo" => "icmp_echo_reply",
            "tcp-syn-open" => "tcp_syn_ack",
            "tcp-syn-closed" => "tcp_rst",
            _ => "unknown",
        })
}

fn target_service_json(plan: &ProbePlan) -> Value {
    match plan.case.as_str() {
        "tcp-syn-open" => json!({
            "required": true,
            "kind": "tcp-listener",
            "port": plan.destination_port,
        }),
        "tcp-syn-closed" => json!({
            "required": false,
            "kind": "closed-port",
            "port": plan.destination_port,
        }),
        _ => json!({}),
    }
}

fn flag_mismatch(field: &str, expected: bool, actual: bool) -> Value {
    json!({
        "field": field,
        "expected": expected,
        "actual": actual,
    })
}

fn tcp_flag_names(flags: u16) -> Vec<&'static str> {
    [
        (TCP_FLAG_FIN, "fin"),
        (TCP_FLAG_SYN, "syn"),
        (TCP_FLAG_RST, "rst"),
        (TCP_FLAG_PSH, "psh"),
        (TCP_FLAG_ACK, "ack"),
        (TCP_FLAG_URG, "urg"),
        (TCP_FLAG_ECE, "ece"),
        (TCP_FLAG_CWR, "cwr"),
        (TCP_FLAG_NS, "ns"),
    ]
    .iter()
    .filter_map(|(flag, name)| (flags & *flag != 0).then_some(*name))
    .collect()
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

fn required_str<'a>(value: Option<&'a str>, field: &str) -> ExampleResult<&'a str> {
    value
        .filter(|item| !item.is_empty())
        .ok_or_else(|| format!("probe plan missing required field {field}").into())
}

fn required_u16(value: Option<u16>, field: &str) -> ExampleResult<u16> {
    value.ok_or_else(|| format!("probe plan missing required field {field}").into())
}

fn required_u32(value: Option<u32>, field: &str) -> ExampleResult<u32> {
    value.ok_or_else(|| format!("probe plan missing required field {field}").into())
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
