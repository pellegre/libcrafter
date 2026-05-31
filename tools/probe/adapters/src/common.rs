//! Shared contracts, helpers, and orchestration for the libcrafter probe
//! stimulus endpoint.
//!
//! Case-specific packet construction, capture, and validation live in the
//! per-protocol modules (`icmp`, `tcp`, `dns`, `udp`, `dhcp`, `arp`). This
//! module owns everything those cases share: argument parsing, the JSON
//! request/plan contracts, the dry-run/live dispatch in [`run_endpoint`], and
//! the response/artifact helpers.

use crafter::prelude::*;
use serde::Deserialize;
use serde_json::{json, Value};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::{dns, icmp, tcp};

pub type ExampleResult<T> = std::result::Result<T, Box<dyn Error>>;

pub const BACKEND_NAME: &str = "libcrafter";
pub const FAILURE_TIMEOUT: &str = "timeout";
pub const FAILURE_WRONG_PEER: &str = "wrong_peer";
pub const FAILURE_WRONG_PAYLOAD: &str = "wrong_payload";
pub const FAILURE_WRONG_FLAGS: &str = "wrong_flags";
pub const FAILURE_DECODE_FAILED: &str = "decode_failed";
pub const FAILURE_TARGET_SETUP_FAILED: &str = "target_setup_failed";

#[derive(Debug)]
pub struct Args {
    pub input: Option<PathBuf>,
    pub out: PathBuf,
    pub mode: RunMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    DryRun,
    Live,
}

impl RunMode {
    pub const fn is_dry_run(self) -> bool {
        matches!(self, Self::DryRun)
    }
}

#[derive(Debug, Deserialize)]
pub struct StimulusEndpointRequest {
    pub provider: String,
    pub profile: String,
    pub seed: u64,
    pub endpoint_role: String,
    pub interface: String,
    pub local_ipv4: String,
    pub peer_ipv4: String,
    pub timeout_seconds: u64,
    pub probe_plans: Vec<ProbePlan>,
    #[serde(default)]
    pub artifact_paths: Value,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProbePlan {
    pub case: String,
    pub sequence: usize,
    #[serde(default)]
    pub expected_response: Option<String>,
    #[serde(default)]
    pub identifier: Option<u16>,
    #[serde(default)]
    pub sequence_number: Option<u16>,
    #[serde(default)]
    pub payload_hex: Option<String>,
    #[serde(default)]
    pub source_ipv4: Option<String>,
    #[serde(default)]
    pub destination_ipv4: Option<String>,
    #[serde(default)]
    pub expected_reply_source_ipv4: Option<String>,
    #[serde(default)]
    pub expected_reply_destination_ipv4: Option<String>,
    #[serde(default)]
    pub source_port: Option<u16>,
    #[serde(default)]
    pub destination_port: Option<u16>,
    #[serde(default)]
    pub tcp_sequence_number: Option<u32>,
    #[serde(default)]
    pub expected_acknowledgment_number: Option<u32>,
    #[serde(default)]
    pub window: Option<u16>,
    #[serde(default)]
    pub query_id: Option<u16>,
    #[serde(default)]
    pub query_name: Option<String>,
    #[serde(default)]
    pub query_type: Option<String>,
    #[serde(default)]
    pub query_type_value: Option<u16>,
    #[serde(default)]
    pub query_class_value: Option<u16>,
    #[serde(default)]
    pub expected_answer_name: Option<String>,
    #[serde(default)]
    pub expected_answer_type: Option<String>,
    #[serde(default)]
    pub expected_answer_type_value: Option<u16>,
    #[serde(default)]
    pub expected_answer_data: Option<String>,
    #[serde(default)]
    pub expected_answer_count: Option<usize>,
    #[serde(default)]
    pub original_name: Option<String>,
    #[serde(default)]
    pub absent_name: Option<String>,
    #[serde(default)]
    pub present_name: Option<String>,
    #[serde(default)]
    pub present_type: Option<String>,
    #[serde(default)]
    pub present_type_value: Option<u16>,
    #[serde(default)]
    pub canonical_name: Option<String>,
    #[serde(default)]
    pub terminal_ipv4: Option<String>,
    #[serde(default)]
    pub expected_cname_answer: Option<DnsAnswerExpectation>,
    #[serde(default)]
    pub expected_response_code: Option<u8>,
    #[serde(default)]
    pub answer_ttl: Option<u32>,
    #[serde(default)]
    pub ttl: Option<u8>,
    #[serde(default)]
    pub expected_icmp_type: Option<u8>,
    #[serde(default)]
    pub expected_icmp_code: Option<u8>,
    #[serde(default)]
    pub expected_embedded_prefix_hex: Option<String>,
    #[serde(default)]
    pub expected_embedded_prefix_length: Option<usize>,
}

/// One expected DNS answer record carried in a probe plan.
///
/// Used by multi-answer DNS cases (the CNAME chain) so the stimulus endpoint
/// can confirm an individual non-terminal answer (name/type/class/data) decoded
/// out of the response in addition to the terminal answer the shared
/// single-answer fields already describe.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsAnswerExpectation {
    pub name: String,
    #[serde(default)]
    pub type_value: Option<u16>,
    #[serde(default)]
    pub class_value: Option<u16>,
    pub data: String,
}

#[derive(Debug)]
pub struct ProbeOutcome {
    pub result: Value,
    pub observed_response: Value,
    pub sent: bool,
    pub received: bool,
}

#[derive(Debug)]
pub enum CandidateValidation {
    Ignore,
    Passed(Value),
    WrongPeer(Value),
    WrongPayload(Value),
}

pub fn run() -> ExampleResult<()> {
    let args = parse_args()?;
    let input = read_input(args.input.clone())?;
    let request: StimulusEndpointRequest = serde_json::from_str(&input)?;
    let request_json: Value = serde_json::from_str(&input)?;
    let response = run_endpoint(&request, request_json, &args)?;

    serde_json::to_writer_pretty(io::stdout(), &response)?;
    println!();
    Ok(())
}

pub fn parse_args() -> ExampleResult<Args> {
    let mut input = None;
    let mut out = PathBuf::from("target/probe/libcrafter-stimulus-endpoint");
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
        "usage: cargo run -p probe-adapters --bin stimulus_endpoint -- [--dry-run|--live] --input PATH|- [--out DIR]\n\nRun the libcrafter stimulus endpoint for probe cases. Dry-run is the default and compiles probe packets without sending traffic."
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

pub fn run_endpoint(
    request: &StimulusEndpointRequest,
    request_json: Value,
    args: &Args,
) -> ExampleResult<Value> {
    if request.endpoint_role != "stimulus" {
        return Err(format!(
            "stimulus_endpoint only supports endpoint_role=stimulus, got {}",
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
        let outcome = dispatch_case(request, plan, args.mode, &mut errors)?;
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

/// Route one probe plan to its protocol module for the requested run mode.
fn dispatch_case(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
    mode: RunMode,
    errors: &mut Vec<String>,
) -> ExampleResult<ProbeOutcome> {
    match (mode, plan.case.as_str()) {
        (RunMode::DryRun, "icmp-echo") => icmp::run_icmp_dry_run(request, plan),
        (RunMode::Live, "icmp-echo") => icmp::run_icmp_live(request, plan),
        (RunMode::DryRun, "tcp-syn-open" | "tcp-syn-closed") => tcp::run_tcp_dry_run(request, plan),
        (RunMode::Live, "tcp-syn-open" | "tcp-syn-closed") => tcp::run_tcp_live(request, plan),
        (
            RunMode::DryRun,
            "dns-query" | "dns-a-success" | "dns-aaaa-success" | "dns-cname-chain" | "dns-nxdomain"
            | "dns-nodata",
        ) => dns::run_dns_dry_run(request, plan),
        (
            RunMode::Live,
            "dns-query" | "dns-a-success" | "dns-aaaa-success" | "dns-cname-chain" | "dns-nxdomain"
            | "dns-nodata",
        ) => dns::run_dns_live(request, plan),
        (RunMode::DryRun, "ttl-expired") => icmp::run_ttl_expired_dry_run(request, plan),
        (RunMode::Live, "ttl-expired") => icmp::run_ttl_expired_live(request, plan),
        _ => {
            // DHCP, ARP, and UDP behavioral cases are wired into their modules
            // (`dhcp`, `arp`, `udp`) by later steps; until then they fall
            // through to the same structured `decode_failed` outcome as any
            // other unknown case.
            let message = format!("unsupported probe case: {}", plan.case);
            errors.push(message.clone());
            Ok(failed_outcome(
                plan,
                FAILURE_DECODE_FAILED,
                vec![message],
                None,
                false,
                false,
            ))
        }
    }
}

pub fn failed_outcome(
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

pub fn observed_response(
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

pub fn plan_json(plan: &ProbePlan) -> Value {
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
        "query_id": plan.query_id,
        "query_name": plan.query_name,
        "query_type": plan.query_type,
        "query_type_value": plan.query_type_value,
        "query_class_value": plan.query_class_value,
        "expected_answer_name": plan.expected_answer_name,
        "expected_answer_type": plan.expected_answer_type,
        "expected_answer_type_value": plan.expected_answer_type_value,
        "expected_answer_data": plan.expected_answer_data,
        "expected_answer_count": plan.expected_answer_count,
        "original_name": plan.original_name,
        "absent_name": plan.absent_name,
        "present_name": plan.present_name,
        "present_type": plan.present_type,
        "present_type_value": plan.present_type_value,
        "canonical_name": plan.canonical_name,
        "terminal_ipv4": plan.terminal_ipv4,
        "expected_response_code": plan.expected_response_code,
        "answer_ttl": plan.answer_ttl,
        "ttl": plan.ttl,
        "expected_icmp_type": plan.expected_icmp_type,
        "expected_icmp_code": plan.expected_icmp_code,
        "expected_embedded_prefix_hex": plan.expected_embedded_prefix_hex,
        "expected_embedded_prefix_length": plan.expected_embedded_prefix_length,
        "target_service": target_service_json(plan),
        "capture_filter": capture_filter(plan),
    })
}

pub fn decoded_packet_json(packet: &Packet, raw: &[u8]) -> Value {
    let ipv4 = packet.layer::<Ipv4>();
    let icmp = packet.layer::<Icmp>();
    let tcp = packet.layer::<Tcp>();
    let udp = packet.layer::<Udp>();
    let dns = packet.layer::<Dns>();
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
        "udp": udp.map(|layer| json!({
            "sport": layer.source_port_value(),
            "dport": layer.destination_port_value(),
            "length": layer.length_value(),
            "checksum": layer.checksum_value(),
        })),
        "dns": dns.map(dns::dns_json),
        "payload_hex": hex_bytes(raw_payload(packet)),
    })
}

pub fn raw_payload(packet: &Packet) -> &[u8] {
    packet.layer::<Raw>().map(Raw::as_bytes).unwrap_or(&[])
}

pub fn capture_filter(plan: &ProbePlan) -> String {
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
        "dns-query" | "dns-a-success" | "dns-aaaa-success" | "dns-cname-chain" | "dns-nxdomain"
        | "dns-nodata" => {
            format!(
                "udp and src host {} and dst host {} and src port {} and dst port {}",
                plan.expected_reply_source_ipv4.as_deref().unwrap_or(""),
                plan.expected_reply_destination_ipv4
                    .as_deref()
                    .unwrap_or(""),
                plan.destination_port.unwrap_or(0),
                plan.source_port.unwrap_or(0),
            )
        }
        "ttl-expired" => format!(
            "icmp and src host {} and dst host {}",
            plan.expected_reply_source_ipv4.as_deref().unwrap_or(""),
            plan.expected_reply_destination_ipv4
                .as_deref()
                .unwrap_or("")
        ),
        _ => String::new(),
    }
}

pub fn expected_response(plan: &ProbePlan) -> &str {
    plan.expected_response
        .as_deref()
        .unwrap_or(match plan.case.as_str() {
            "icmp-echo" => "icmp_echo_reply",
            "tcp-syn-open" => "tcp_syn_ack",
            "tcp-syn-closed" => "tcp_rst",
            "dns-query" | "dns-a-success" | "dns-aaaa-success" | "dns-cname-chain"
            | "dns-nxdomain" | "dns-nodata" => "dns_response",
            "ttl-expired" => "icmp_ttl_expired",
            _ => "unknown",
        })
}

pub fn target_service_json(plan: &ProbePlan) -> Value {
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
        "dns-query" | "dns-a-success" | "dns-aaaa-success" => json!({
            "required": true,
            "kind": "udp-dns-responder",
            "port": plan.destination_port,
            "query_name": plan.query_name,
            "query_type": plan.query_type,
            "answer_data": plan.expected_answer_data,
        }),
        "dns-cname-chain" => json!({
            "required": true,
            "kind": "udp-dns-responder",
            "port": plan.destination_port,
            "query_name": plan.query_name,
            "query_type": plan.query_type,
            "answer_data": plan.expected_answer_data,
            "cname_chain": {
                "canonical_name": plan.canonical_name,
                "terminal_ipv4": plan.terminal_ipv4,
                "expected_answer_count": plan.expected_answer_count,
            },
        }),
        "dns-nxdomain" => json!({
            "required": true,
            "kind": "udp-dns-responder",
            "port": plan.destination_port,
            "query_name": plan.query_name,
            "query_type": plan.query_type,
            "absent": true,
            "expected_response_code": plan.expected_response_code,
        }),
        "dns-nodata" => json!({
            "required": true,
            "kind": "udp-dns-responder",
            "port": plan.destination_port,
            "query_name": plan.query_name,
            "query_type": plan.query_type,
            "nodata": true,
            "present_type": plan.present_type,
            "present_type_value": plan.present_type_value,
            "expected_response_code": plan.expected_response_code,
        }),
        _ => json!({}),
    }
}

pub fn flag_mismatch(field: &str, expected: bool, actual: bool) -> Value {
    json!({
        "field": field,
        "expected": expected,
        "actual": actual,
    })
}

pub fn tcp_flag_names(flags: u16) -> Vec<&'static str> {
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

pub fn send_report_json(report: &SendReport) -> Value {
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

pub fn artifact_path(out_dir: &Path, artifact_paths: &Value, key: &str, fallback: &str) -> PathBuf {
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

pub fn write_json(path: &Path, value: &Value) -> ExampleResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

pub fn required_str<'a>(value: Option<&'a str>, field: &str) -> ExampleResult<&'a str> {
    value
        .filter(|item| !item.is_empty())
        .ok_or_else(|| format!("probe plan missing required field {field}").into())
}

pub fn required_u16(value: Option<u16>, field: &str) -> ExampleResult<u16> {
    value.ok_or_else(|| format!("probe plan missing required field {field}").into())
}

pub fn required_u32(value: Option<u32>, field: &str) -> ExampleResult<u32> {
    value.ok_or_else(|| format!("probe plan missing required field {field}").into())
}

pub fn decode_hex(hex: &str) -> ExampleResult<Vec<u8>> {
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

pub fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    #[test]
    fn required_str_rejects_missing_and_empty() {
        assert!(required_str(None, "source_ipv4").is_err());
        assert!(required_str(Some(""), "source_ipv4").is_err());
        assert_eq!(
            required_str(Some("1.2.3.4"), "source_ipv4").unwrap(),
            "1.2.3.4"
        );
    }

    #[test]
    fn required_numeric_helpers_report_field() {
        let err = required_u16(None, "identifier").unwrap_err().to_string();
        assert!(err.contains("identifier"));
        let err = required_u32(None, "tcp_sequence_number")
            .unwrap_err()
            .to_string();
        assert!(err.contains("tcp_sequence_number"));
    }

    #[test]
    fn decode_hex_round_trips() {
        assert_eq!(
            decode_hex("deadBEEF").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(hex_bytes(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn failed_outcome_has_stable_response_shape() {
        let plan = base_plan("icmp-echo");
        let outcome = failed_outcome(
            &plan,
            FAILURE_DECODE_FAILED,
            vec!["boom".to_string()],
            None,
            false,
            false,
        );
        assert_eq!(outcome.result["status"], "failed");
        assert_eq!(outcome.result["passed"], false);
        assert_eq!(
            outcome.result["metadata"]["failure_reason"],
            FAILURE_DECODE_FAILED
        );
        assert_eq!(
            outcome.observed_response["response_type"],
            "icmp_echo_reply"
        );
        assert_eq!(outcome.observed_response["observed"], false);
        assert!(!outcome.sent);
        assert!(!outcome.received);
    }

    #[test]
    fn unsupported_case_dispatches_to_decode_failed() {
        let plan = base_plan("nope");
        let request = StimulusEndpointRequest {
            provider: "qemu".to_string(),
            profile: "smoke".to_string(),
            seed: 1,
            endpoint_role: "stimulus".to_string(),
            interface: "eth0".to_string(),
            local_ipv4: "192.0.2.1".to_string(),
            peer_ipv4: "192.0.2.2".to_string(),
            timeout_seconds: 1,
            probe_plans: vec![plan.clone()],
            artifact_paths: json!({}),
            metadata: json!({}),
        };
        let _ = &request;
        let mut errors = Vec::new();
        let outcome = dispatch_case(&request, &plan, RunMode::DryRun, &mut errors).unwrap();
        assert_eq!(outcome.result["status"], "failed");
        assert_eq!(
            outcome.result["metadata"]["failure_reason"],
            FAILURE_DECODE_FAILED
        );
        assert_eq!(errors, vec!["unsupported probe case: nope".to_string()]);
    }
}
