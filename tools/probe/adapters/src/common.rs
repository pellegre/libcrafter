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

use crate::{arp, dhcp, dns, icmp, tcp, udp};

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
    pub payload_length: Option<usize>,
    #[serde(default)]
    pub expected_payload_hex: Option<String>,
    #[serde(default)]
    pub expected_payload_length: Option<usize>,
    #[serde(default)]
    pub expected_udp_length: Option<u16>,
    #[serde(default)]
    pub expected_udp_checksum_present: Option<bool>,
    #[serde(default)]
    pub expected_udp_checksum_statuses: Option<Vec<String>>,
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
    pub expected_txt_strings: Option<Vec<String>>,
    #[serde(default)]
    pub expected_mx_preference: Option<u16>,
    #[serde(default)]
    pub expected_mx_exchange: Option<String>,
    #[serde(default)]
    pub expected_srv_priority: Option<u16>,
    #[serde(default)]
    pub expected_srv_weight: Option<u16>,
    #[serde(default)]
    pub expected_srv_port: Option<u16>,
    #[serde(default)]
    pub expected_srv_target: Option<String>,
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
    pub edns_udp_payload_size: Option<u16>,
    #[serde(default)]
    pub edns_version: Option<u8>,
    #[serde(default)]
    pub edns_do: Option<bool>,
    #[serde(default)]
    pub edns_request_options: Option<Vec<EdnsOptionExpectation>>,
    #[serde(default)]
    pub expected_edns_udp_payload_size: Option<u16>,
    #[serde(default)]
    pub expected_edns_version: Option<u8>,
    #[serde(default)]
    pub expected_edns_extended_rcode: Option<u8>,
    #[serde(default)]
    pub expected_edns_do: Option<bool>,
    #[serde(default)]
    pub expected_edns_options: Option<Vec<EdnsOptionExpectation>>,
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
    #[serde(default)]
    pub send_count: Option<usize>,
    #[serde(default)]
    pub sends: Option<Vec<DnsSend>>,
    // DHCP/BOOTP behavioral case fields. The stimulus builds a Discover from the
    // client MAC and transaction id; the validation contract names the expected
    // Offer message type, offered address (`yiaddr`), server identifier, and
    // lease timing options decoded out of the response.
    #[serde(default)]
    pub client_mac: Option<String>,
    #[serde(default)]
    pub transaction_id: Option<u32>,
    // The address the client wants to commit in the requested-IP option (50) and
    // the chosen server it names in the server-identifier option (54). Both are
    // set on a DHCP Request stimulus (`dhcp-request-ack`); a Discover leaves them
    // unset.
    #[serde(default)]
    pub requested_ipv4: Option<String>,
    #[serde(default)]
    pub server_identifier: Option<String>,
    // The address a bound client carries in `ciaddr` when it renews its lease.
    // A RENEWING-state renewal Request (`dhcp-renewal-unicast-ack`) is unicast
    // directly to the leasing server: it sets `ciaddr` to the address it already
    // holds, leaves the broadcast flag clear, and omits the requested-IP (50) and
    // server-identifier (54) options. Other DHCP cases leave it unset.
    #[serde(default)]
    pub client_ciaddr: Option<String>,
    // The DHCP client identifier (option 61, RFC 2132 section 9.14), carried as
    // the lowercase hex of the encoded option payload (type octet plus
    // identifier). `client_identifier_hex` is set on the stimulus Discover that
    // identifies with option 61 (`dhcp-client-identifier`);
    // `expected_client_identifier_hex` is the value the responder must echo back
    // in its Offer. A case that relies only on `chaddr` leaves both unset.
    #[serde(default)]
    pub client_identifier_hex: Option<String>,
    #[serde(default)]
    pub expected_client_identifier_hex: Option<String>,
    // The DHCP hostname (option 12, RFC 2132 section 3.14), a string option.
    // `hostname` is set on the stimulus Discover that names itself with option 12
    // (`dhcp-hostname`); `expected_hostname` is the value the responder must echo
    // back in its Offer. A case that does not name a hostname leaves both unset.
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub expected_hostname: Option<String>,
    // The DHCP parameter request list (option 55, RFC 2132 section 9.8): the list
    // of option codes the client asks the server to return. `parameter_request_list`
    // is set on the stimulus Discover that names the wanted options
    // (`dhcp-parameter-request-list`); the responder returns those options and the
    // validator confirms the corresponding values. A case that does not name a
    // parameter request list leaves it unset (the builders inject a default list).
    #[serde(default)]
    pub parameter_request_list: Option<Vec<u8>>,
    #[serde(default)]
    pub expected_message_type_value: Option<u8>,
    #[serde(default)]
    pub expected_yiaddr: Option<String>,
    // RFC 2131 section 4.3.5: a DHCPINFORM Ack allocates no address, so `yiaddr`
    // MUST be 0.0.0.0 and the Ack MUST NOT carry an IP-address-lease-time option
    // (51). `expected_yiaddr_zero` asserts the decoded `yiaddr` is the all-zero
    // address; `expected_no_lease_time` asserts no lease-time (51) option is
    // present. They are set on the Inform Ack case (`dhcp-inform-ack`) and left
    // unset by the lease-granting cases. When `expected_yiaddr_zero` is set, the
    // positive `expected_yiaddr` match is skipped in favor of the zero assertion.
    #[serde(default)]
    pub expected_yiaddr_zero: Option<bool>,
    #[serde(default)]
    pub expected_no_lease_time: Option<bool>,
    #[serde(default)]
    pub expected_server_identifier: Option<String>,
    // RFC 2132 section 9.9: the optional DHCP message option (56), a text status
    // message a server includes in a DHCPNAK (or DHCPDECLINE) to explain the
    // refusal. `expected_message` is the text the responder must return in the Nak
    // (`dhcp-request-nak`); a case that does not name a message leaves it unset and
    // the validator skips the option-56 text check.
    #[serde(default)]
    pub expected_message: Option<String>,
    #[serde(default)]
    pub expected_subnet_mask: Option<String>,
    #[serde(default)]
    pub expected_router_ipv4: Option<String>,
    #[serde(default)]
    pub expected_dns_ipv4: Option<String>,
    #[serde(default)]
    pub expected_lease_time: Option<u32>,
    #[serde(default)]
    pub expected_renewal_time: Option<u32>,
    #[serde(default)]
    pub expected_rebinding_time: Option<u32>,
    // Multi-send DHCP behavioral case fields (`dhcp-rapid-repeat`). The plan
    // carries a `dhcp_sends` array (one entry per Discover->Offer send), each with
    // its own distinct transaction id, client identity (chaddr), and offered
    // address, so the DHCP dispatch can build/send two Discovers and validate two
    // independently-decoded Offers. Single-send DHCP cases leave this unset.
    #[serde(default)]
    pub dhcp_sends: Option<Vec<DhcpSend>>,
    // ARP behavioral case fields. ARP rides Ethernet directly (no IP/UDP), so
    // these are link-layer values: the stimulus builds an Ethernet/ARP who-has
    // from `sender_hardware_addr`/`sender_protocol_addr` for the target it wants
    // to resolve (`target_protocol_addr`), framed from `ethernet_source` to
    // `ethernet_destination` (broadcast for who-has). The validation contract is
    // carried in the typed `validation` object so the endpoint can confirm the
    // decoded is-at operation, sender/target hardware/protocol addresses, and the
    // Ethernet source/destination. Non-ARP cases leave these unset.
    #[serde(default)]
    pub ethertype: Option<u16>,
    #[serde(default)]
    pub hardware_type: Option<u16>,
    #[serde(default)]
    pub protocol_type: Option<u16>,
    #[serde(default)]
    pub operation: Option<u16>,
    #[serde(default)]
    pub sender_hardware_addr: Option<String>,
    #[serde(default)]
    pub sender_protocol_addr: Option<String>,
    #[serde(default)]
    pub target_hardware_addr: Option<String>,
    #[serde(default)]
    pub target_protocol_addr: Option<String>,
    #[serde(default)]
    pub ethernet_source: Option<String>,
    #[serde(default)]
    pub ethernet_destination: Option<String>,
    #[serde(default)]
    pub validation: Option<ArpValidation>,
    // ARP alias behavioral case field (`arp-alias-address-reply`). The target
    // kernel answers ARP for a *configured secondary* IPv4 address (an alias)
    // added to its interface during target setup; the who-has resolves this alias
    // (it is also carried in `target_protocol_addr`). Non-alias cases leave this
    // unset.
    #[serde(default)]
    pub alias_ipv4: Option<String>,
    // Alternate sender protocol address ARP behavioral case field
    // (`arp-spa-variation`). The who-has carries an *alternate* sender protocol
    // address (SPA), distinct from the stimulus endpoint's primary IPv4 (it is
    // also carried in `sender_protocol_addr`). For live execution the target
    // kernel may need this configured as a secondary sender address so it accepts
    // and answers the request. Other ARP cases leave this unset.
    #[serde(default)]
    pub alt_sender_ipv4: Option<String>,
    // Multi-send ARP behavioral case fields (`arp-repeat-two-replies`). The plan
    // carries an `arp_sends` array (one entry per who-has -> is-at send), each
    // with its own sender/target hardware/protocol address, Ethernet framing,
    // capture filter, and is-at validation contract, so the ARP dispatch can
    // build/send two who-has requests for the same target and validate two
    // independently-decoded is-at replies. Single-send ARP cases leave this unset.
    #[serde(default)]
    pub arp_sends: Option<Vec<ArpSend>>,
    // Ethernet-padding ARP behavioral case fields (`arp-padding-reply`). An
    // Ethernet/ARP frame is 42 bytes (14-byte header + 28-byte ARP payload),
    // below the 60-byte (sans FCS) Ethernet minimum; such frames are commonly
    // padded with trailing zero bytes. When `ethernet_min_frame_len` is set, the
    // who-has frame is padded up to that length with trailing zeros (an honored
    // override `compile()` preserves), and the endpoint records the resulting
    // sent frame length (`expected_request_frame_len`). Non-padded ARP cases
    // leave these unset.
    #[serde(default)]
    pub ethernet_min_frame_len: Option<usize>,
    #[serde(default)]
    pub expected_request_frame_len: Option<usize>,
    // Neighbor-cache flush ARP behavioral case fields (`arp-cache-flush-reply`).
    // Provider VMs can carry neighbor state across packets in a session, so the
    // target setup flushes the relevant neighbor entries *before* the stimulus
    // who-has (`neighbor_flush_commands`) and cleanup leaves neighbor state in a
    // normal provider-controlled (flushed) state
    // (`neighbor_flush_cleanup_commands`). `flush_neighbor` marks the case as
    // requiring this explicit pre-stimulus flush. Other ARP cases leave these
    // unset (they still carry the implicit `neighbor_cache_flush` sysctl flush).
    #[serde(default)]
    pub flush_neighbor: Option<bool>,
    #[serde(default)]
    pub neighbor_flush_interface: Option<String>,
    #[serde(default)]
    pub neighbor_flush_commands: Option<Vec<String>>,
    #[serde(default)]
    pub neighbor_flush_cleanup_commands: Option<Vec<String>>,
    // Broadcast-filtered ARP behavioral case fields
    // (`arp-broadcast-filtered-capture`). The capture filter intentionally
    // admits all ARP replies, including an optional setup decoy event; the ARP
    // module ignores replies whose decoded target protocol address is not the
    // planned sender protocol address and only passes on the matching is-at
    // contract.
    #[serde(default)]
    pub ignore_unmatched_arp_replies: Option<bool>,
    #[serde(default)]
    pub decoy_arp_event: Option<Value>,
}

/// Validation contract for the ARP is-at reply (`arp-basic-who-has`).
///
/// The stimulus endpoint decodes the captured Ethernet/ARP reply with
/// libcrafter and asserts the operation (reply = 2), the sender
/// hardware/protocol address (the resolved target MAC/IPv4), the target
/// hardware/protocol address (the original sender), and the Ethernet
/// source/destination of the unicast reply.
#[derive(Debug, Clone, Deserialize)]
pub struct ArpValidation {
    #[serde(default)]
    pub operation: Option<u16>,
    #[serde(default)]
    pub sender_hardware_addr: Option<String>,
    #[serde(default)]
    pub sender_protocol_addr: Option<String>,
    #[serde(default)]
    pub target_hardware_addr: Option<String>,
    #[serde(default)]
    pub target_protocol_addr: Option<String>,
    #[serde(default)]
    pub ethernet_source: Option<String>,
    #[serde(default)]
    pub ethernet_destination: Option<String>,
}

/// One send of a multi-send ARP probe case (`arp-repeat-two-replies`).
///
/// ARP rides Ethernet directly (no IP/UDP), so each send carries link-layer
/// values: the sender/target hardware and protocol addresses, the Ethernet
/// source/destination framing, its own capture filter, and its own typed is-at
/// `validation` contract. The two sends resolve the *same* target address (the
/// case point is that a repeated who-has receives two parseable replies), so the
/// ARP dispatch can build/send each who-has independently and validate every
/// is-at reply against its own send.
#[derive(Debug, Clone, Deserialize)]
pub struct ArpSend {
    #[serde(default)]
    pub index: Option<usize>,
    #[serde(default)]
    pub operation: Option<u16>,
    #[serde(default)]
    pub sender_hardware_addr: Option<String>,
    #[serde(default)]
    pub sender_protocol_addr: Option<String>,
    #[serde(default)]
    pub target_hardware_addr: Option<String>,
    #[serde(default)]
    pub target_protocol_addr: Option<String>,
    #[serde(default)]
    pub ethernet_source: Option<String>,
    #[serde(default)]
    pub ethernet_destination: Option<String>,
    #[serde(default)]
    pub capture_filter: Option<String>,
    #[serde(default)]
    pub validation: Option<ArpValidation>,
}

/// One send of a multi-send DHCP probe case (`dhcp-rapid-repeat`).
///
/// Each send carries its own transaction id (xid), client hardware address
/// (chaddr), source/destination ports, offered address (yiaddr), server
/// identifier, lease timing options, and per-send capture filter/peer
/// expectations so the stimulus endpoint can build/send/capture/decode each
/// Discover independently and match every Offer back to *its* send by the echoed
/// transaction id — never confusing two Offers.
#[derive(Debug, Clone, Deserialize)]
pub struct DhcpSend {
    #[serde(default)]
    pub index: Option<usize>,
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
    pub client_mac: Option<String>,
    #[serde(default)]
    pub transaction_id: Option<u32>,
    #[serde(default)]
    pub expected_message_type_value: Option<u8>,
    #[serde(default)]
    pub expected_yiaddr: Option<String>,
    #[serde(default)]
    pub expected_server_identifier: Option<String>,
    #[serde(default)]
    pub expected_subnet_mask: Option<String>,
    #[serde(default)]
    pub expected_router_ipv4: Option<String>,
    #[serde(default)]
    pub expected_lease_time: Option<u32>,
    #[serde(default)]
    pub expected_renewal_time: Option<u32>,
    #[serde(default)]
    pub expected_rebinding_time: Option<u32>,
    #[serde(default)]
    pub capture_filter: Option<String>,
}

/// One send of a multi-send DNS probe case (`dns-repeat-transaction`).
///
/// Each send carries its own transaction id, source port, query name, expected
/// A answer, and per-send capture filter/peer expectations so the stimulus
/// endpoint can build/send/capture/decode each query independently and match
/// every response back to *its* send by source port and id — never confusing two
/// responses that share the same query name.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsSend {
    #[serde(default)]
    pub index: Option<usize>,
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
    pub expected_response_code: Option<u8>,
    #[serde(default)]
    pub answer_ttl: Option<u32>,
    #[serde(default)]
    pub capture_filter: Option<String>,
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

/// One EDNS(0) option carried in a probe plan (RFC 6891 Section 6.1.2).
///
/// The option code is the IANA EDNS0 Option Code; `data_hex` is the opaque
/// OPTION-DATA bytes in lowercase hex so the JSON contract stays text-only. Used
/// by the EDNS OPT case to describe the option list the stimulus sends and the
/// ordered option list the response's OPT record must decode to.
#[derive(Debug, Clone, Deserialize)]
pub struct EdnsOptionExpectation {
    pub code: u16,
    #[serde(default)]
    pub data_hex: String,
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
            "dns-query"
            | "dns-a-success"
            | "dns-aaaa-success"
            | "dns-cname-chain"
            | "dns-nxdomain"
            | "dns-nodata"
            | "dns-txt-answer"
            | "dns-mx-answer"
            | "dns-srv-answer"
            | "dns-edns-opt"
            | "dns-repeat-transaction",
        ) => dns::run_dns_dry_run(request, plan),
        (
            RunMode::Live,
            "dns-query"
            | "dns-a-success"
            | "dns-aaaa-success"
            | "dns-cname-chain"
            | "dns-nxdomain"
            | "dns-nodata"
            | "dns-txt-answer"
            | "dns-mx-answer"
            | "dns-srv-answer"
            | "dns-edns-opt"
            | "dns-repeat-transaction",
        ) => dns::run_dns_live(request, plan),
        (RunMode::DryRun, "ttl-expired") => icmp::run_ttl_expired_dry_run(request, plan),
        (RunMode::Live, "ttl-expired") => icmp::run_ttl_expired_live(request, plan),
        (
            RunMode::DryRun,
            "dhcp-discover-offer"
            | "dhcp-request-ack"
            | "dhcp-client-identifier"
            | "dhcp-hostname"
            | "dhcp-parameter-request-list"
            | "dhcp-lease-time"
            | "dhcp-renewal-unicast-ack"
            | "dhcp-inform-ack"
            | "dhcp-request-nak"
            | "dhcp-rapid-repeat",
        ) => dhcp::run_dhcp_dry_run(request, plan),
        (
            RunMode::Live,
            "dhcp-discover-offer"
            | "dhcp-request-ack"
            | "dhcp-client-identifier"
            | "dhcp-hostname"
            | "dhcp-parameter-request-list"
            | "dhcp-lease-time"
            | "dhcp-renewal-unicast-ack"
            | "dhcp-inform-ack"
            | "dhcp-request-nak"
            | "dhcp-rapid-repeat",
        ) => dhcp::run_dhcp_live(request, plan),
        (
            RunMode::DryRun,
            "arp-basic-who-has"
            | "arp-repeat-two-replies"
            | "arp-source-address-preserved"
            | "arp-alias-address-reply"
            | "arp-unicast-request-reply"
            | "arp-padding-reply"
            | "arp-cache-flush-reply"
            | "arp-mac-validation"
            | "arp-spa-variation"
            | "arp-broadcast-filtered-capture",
        ) => arp::run_arp_dry_run(request, plan),
        (
            RunMode::Live,
            "arp-basic-who-has"
            | "arp-repeat-two-replies"
            | "arp-source-address-preserved"
            | "arp-alias-address-reply"
            | "arp-unicast-request-reply"
            | "arp-padding-reply"
            | "arp-cache-flush-reply"
            | "arp-mac-validation"
            | "arp-spa-variation"
            | "arp-broadcast-filtered-capture",
        ) => arp::run_arp_live(request, plan),
        (RunMode::DryRun, "udp-echo-empty" | "udp-echo-short" | "udp-echo-binary") => {
            udp::run_udp_dry_run(request, plan)
        }
        (RunMode::Live, "udp-echo-empty" | "udp-echo-short" | "udp-echo-binary") => {
            udp::run_udp_live(request, plan)
        }
        _ => {
            // The remaining ARP and UDP behavioral cases are wired into their
            // modules (`arp`, `udp`) by later steps; until then they fall
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
        "payload_length": plan.payload_length,
        "expected_payload_hex": plan.expected_payload_hex,
        "expected_payload_length": plan.expected_payload_length,
        "expected_udp_length": plan.expected_udp_length,
        "expected_udp_checksum_present": plan.expected_udp_checksum_present,
        "expected_udp_checksum_statuses": plan.expected_udp_checksum_statuses,
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
        "expected_txt_strings": plan.expected_txt_strings,
        "expected_mx_preference": plan.expected_mx_preference,
        "expected_mx_exchange": plan.expected_mx_exchange,
        "expected_srv_priority": plan.expected_srv_priority,
        "expected_srv_weight": plan.expected_srv_weight,
        "expected_srv_port": plan.expected_srv_port,
        "expected_srv_target": plan.expected_srv_target,
        "expected_answer_count": plan.expected_answer_count,
        "original_name": plan.original_name,
        "absent_name": plan.absent_name,
        "present_name": plan.present_name,
        "present_type": plan.present_type,
        "present_type_value": plan.present_type_value,
        "canonical_name": plan.canonical_name,
        "terminal_ipv4": plan.terminal_ipv4,
        "edns_udp_payload_size": plan.edns_udp_payload_size,
        "edns_version": plan.edns_version,
        "edns_do": plan.edns_do,
        "edns_request_options": dns::edns_options_json(plan.edns_request_options.as_deref()),
        "expected_edns_udp_payload_size": plan.expected_edns_udp_payload_size,
        "expected_edns_version": plan.expected_edns_version,
        "expected_edns_extended_rcode": plan.expected_edns_extended_rcode,
        "expected_edns_do": plan.expected_edns_do,
        "expected_edns_options": dns::edns_options_json(plan.expected_edns_options.as_deref()),
        "expected_response_code": plan.expected_response_code,
        "answer_ttl": plan.answer_ttl,
        "ttl": plan.ttl,
        "expected_icmp_type": plan.expected_icmp_type,
        "expected_icmp_code": plan.expected_icmp_code,
        "expected_embedded_prefix_hex": plan.expected_embedded_prefix_hex,
        "expected_embedded_prefix_length": plan.expected_embedded_prefix_length,
        "send_count": plan.send_count,
        "sends": dns::sends_json(plan.sends.as_deref()),
        "dhcp_sends": dhcp::sends_json(plan.dhcp_sends.as_deref()),
        "client_mac": plan.client_mac,
        "transaction_id": plan.transaction_id,
        "requested_ipv4": plan.requested_ipv4,
        "server_identifier": plan.server_identifier,
        "client_ciaddr": plan.client_ciaddr,
        "client_identifier_hex": plan.client_identifier_hex,
        "expected_client_identifier_hex": plan.expected_client_identifier_hex,
        "hostname": plan.hostname,
        "expected_hostname": plan.expected_hostname,
        "parameter_request_list": plan.parameter_request_list,
        "expected_message_type_value": plan.expected_message_type_value,
        "expected_yiaddr": plan.expected_yiaddr,
        "expected_yiaddr_zero": plan.expected_yiaddr_zero,
        "expected_no_lease_time": plan.expected_no_lease_time,
        "expected_server_identifier": plan.expected_server_identifier,
        "expected_message": plan.expected_message,
        "expected_subnet_mask": plan.expected_subnet_mask,
        "expected_router_ipv4": plan.expected_router_ipv4,
        "expected_dns_ipv4": plan.expected_dns_ipv4,
        "expected_lease_time": plan.expected_lease_time,
        "expected_renewal_time": plan.expected_renewal_time,
        "expected_rebinding_time": plan.expected_rebinding_time,
        "ethertype": plan.ethertype,
        "hardware_type": plan.hardware_type,
        "protocol_type": plan.protocol_type,
        "operation": plan.operation,
        "sender_hardware_addr": plan.sender_hardware_addr,
        "sender_protocol_addr": plan.sender_protocol_addr,
        "target_hardware_addr": plan.target_hardware_addr,
        "target_protocol_addr": plan.target_protocol_addr,
        "alias_ipv4": plan.alias_ipv4,
        "alt_sender_ipv4": plan.alt_sender_ipv4,
        "ignore_unmatched_arp_replies": plan.ignore_unmatched_arp_replies,
        "decoy_arp_event": plan.decoy_arp_event,
        "ethernet_source": plan.ethernet_source,
        "ethernet_destination": plan.ethernet_destination,
        "ethernet_min_frame_len": plan.ethernet_min_frame_len,
        "expected_request_frame_len": plan.expected_request_frame_len,
        "arp_sends": arp::sends_json(plan.arp_sends.as_deref()),
        "validation": validation_json(plan),
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
    let dhcp = packet.layer::<Dhcp>();
    let ethernet = packet.layer::<Ethernet>();
    let arp_layer = packet.layer::<Arp>();
    json!({
        "backend": BACKEND_NAME,
        "summary": packet.summary(),
        "raw_hex": hex_bytes(raw),
        "ethernet": ethernet.map(|layer| json!({
            "src": layer.source().map(|mac| mac.to_string()),
            "dst": layer.destination().map(|mac| mac.to_string()),
            "ethertype": layer.ethertype_value(),
        })),
        "arp": arp_layer.map(arp::arp_json),
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
            "checksum_status": udp::checksum_status_name(layer.checksum_status()),
        })),
        "dns": dns.map(dns::dns_json),
        "dhcp": dhcp.map(dhcp::dhcp_json),
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
        "dns-query"
        | "dns-a-success"
        | "dns-aaaa-success"
        | "dns-cname-chain"
        | "dns-nxdomain"
        | "dns-nodata"
        | "dns-txt-answer"
        | "dns-mx-answer"
        | "dns-srv-answer"
        | "dns-edns-opt"
        | "dns-repeat-transaction" => {
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
        "dhcp-discover-offer"
        | "dhcp-request-ack"
        | "dhcp-client-identifier"
        | "dhcp-hostname"
        | "dhcp-parameter-request-list"
        | "dhcp-lease-time"
        | "dhcp-renewal-unicast-ack"
        | "dhcp-inform-ack"
        | "dhcp-request-nak"
        | "dhcp-rapid-repeat" => {
            format!(
                "udp and src host {} and dst host {} and src port {} and dst port {}",
                plan.expected_reply_source_ipv4.as_deref().unwrap_or(""),
                plan.expected_reply_destination_ipv4
                    .as_deref()
                    .unwrap_or(""),
                plan.destination_port.unwrap_or(DHCP_SERVER_PORT),
                plan.source_port.unwrap_or(DHCP_CLIENT_PORT),
            )
        }
        "udp-echo-empty" | "udp-echo-short" | "udp-echo-binary" => {
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
        // ARP rides Ethernet directly and cannot be selected by host/IP BPF, so
        // match on the protocol plus the reply opcode (ARP byte 6:2 == 2).
        "arp-basic-who-has"
        | "arp-repeat-two-replies"
        | "arp-source-address-preserved"
        | "arp-alias-address-reply"
        | "arp-unicast-request-reply"
        | "arp-padding-reply"
        | "arp-cache-flush-reply"
        | "arp-mac-validation"
        | "arp-broadcast-filtered-capture" => "arp and arp[6:2] = 2".to_string(),
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
            "dns-query"
            | "dns-a-success"
            | "dns-aaaa-success"
            | "dns-cname-chain"
            | "dns-nxdomain"
            | "dns-nodata"
            | "dns-txt-answer"
            | "dns-mx-answer"
            | "dns-srv-answer"
            | "dns-edns-opt"
            | "dns-repeat-transaction" => "dns_response",
            "ttl-expired" => "icmp_ttl_expired",
            "dhcp-discover-offer" => "dhcp_offer",
            "dhcp-request-ack" => "dhcp_ack",
            "dhcp-client-identifier" => "dhcp_offer",
            "dhcp-hostname" => "dhcp_offer",
            "dhcp-parameter-request-list" => "dhcp_offer",
            "dhcp-lease-time" => "dhcp_offer",
            "dhcp-renewal-unicast-ack" => "dhcp_ack",
            "dhcp-inform-ack" => "dhcp_ack",
            "dhcp-request-nak" => "dhcp_nak",
            "dhcp-rapid-repeat" => "dhcp_offer",
            "udp-echo-empty" | "udp-echo-short" | "udp-echo-binary" => "udp_response",
            "arp-basic-who-has"
            | "arp-repeat-two-replies"
            | "arp-source-address-preserved"
            | "arp-alias-address-reply"
            | "arp-unicast-request-reply"
            | "arp-padding-reply"
            | "arp-cache-flush-reply"
            | "arp-mac-validation"
            | "arp-broadcast-filtered-capture" => "arp_is_at",
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
        "dns-txt-answer" => json!({
            "required": true,
            "kind": "udp-dns-responder",
            "port": plan.destination_port,
            "query_name": plan.query_name,
            "query_type": plan.query_type,
            "txt_strings": plan.expected_txt_strings,
            "answer_ttl": plan.answer_ttl,
        }),
        "dns-mx-answer" => json!({
            "required": true,
            "kind": "udp-dns-responder",
            "port": plan.destination_port,
            "query_name": plan.query_name,
            "query_type": plan.query_type,
            "mx_preference": plan.expected_mx_preference,
            "mx_exchange": plan.expected_mx_exchange,
            "answer_ttl": plan.answer_ttl,
        }),
        "dns-srv-answer" => json!({
            "required": true,
            "kind": "udp-dns-responder",
            "port": plan.destination_port,
            "query_name": plan.query_name,
            "query_type": plan.query_type,
            "srv_priority": plan.expected_srv_priority,
            "srv_weight": plan.expected_srv_weight,
            "srv_port": plan.expected_srv_port,
            "srv_target": plan.expected_srv_target,
            "answer_ttl": plan.answer_ttl,
        }),
        "dns-edns-opt" => json!({
            "required": true,
            "kind": "udp-dns-responder",
            "port": plan.destination_port,
            "query_name": plan.query_name,
            "query_type": plan.query_type,
            "answer_data": plan.expected_answer_data,
            "answer_ttl": plan.answer_ttl,
            "edns": {
                "udp_payload_size": plan.expected_edns_udp_payload_size,
                "version": plan.expected_edns_version,
                "extended_rcode": plan.expected_edns_extended_rcode,
                "do": plan.expected_edns_do,
                "options": dns::edns_options_json(plan.expected_edns_options.as_deref()),
            },
        }),
        "dns-repeat-transaction" => json!({
            "required": true,
            "kind": "udp-dns-responder",
            "port": plan.destination_port,
            "query_name": plan.query_name,
            "query_type": plan.query_type,
            "answer_data": plan.expected_answer_data,
            "answer_ttl": plan.answer_ttl,
            "repeat_transaction": {
                "query_id": plan.query_id,
                "query_name": plan.query_name,
                "sends": dns::repeat_sends_json(plan.sends.as_deref()),
            },
        }),
        "dhcp-discover-offer" => json!({
            "required": true,
            "kind": "dhcp-responder",
            "port": plan.destination_port,
            "client_port": plan.source_port,
            "client_mac": plan.client_mac,
            "transaction_id": plan.transaction_id,
            "yiaddr": plan.expected_yiaddr,
            "server_identifier": plan.expected_server_identifier,
            "subnet_mask": plan.expected_subnet_mask,
            "router_ipv4": plan.expected_router_ipv4,
            "lease_time": plan.expected_lease_time,
            "renewal_time": plan.expected_renewal_time,
            "rebinding_time": plan.expected_rebinding_time,
        }),
        "dhcp-request-ack" => json!({
            "required": true,
            "kind": "dhcp-responder",
            "port": plan.destination_port,
            "client_port": plan.source_port,
            "client_mac": plan.client_mac,
            "transaction_id": plan.transaction_id,
            "requested_ipv4": plan.requested_ipv4,
            "server_identifier": plan.expected_server_identifier,
            "yiaddr": plan.expected_yiaddr,
            "subnet_mask": plan.expected_subnet_mask,
            "router_ipv4": plan.expected_router_ipv4,
            "dns_ipv4": plan.expected_dns_ipv4,
            "lease_time": plan.expected_lease_time,
            "renewal_time": plan.expected_renewal_time,
            "rebinding_time": plan.expected_rebinding_time,
        }),
        "dhcp-client-identifier" => json!({
            "required": true,
            "kind": "dhcp-responder",
            "port": plan.destination_port,
            "client_port": plan.source_port,
            "client_mac": plan.client_mac,
            "client_identifier_hex": plan.client_identifier_hex,
            "transaction_id": plan.transaction_id,
            "yiaddr": plan.expected_yiaddr,
            "server_identifier": plan.expected_server_identifier,
            "subnet_mask": plan.expected_subnet_mask,
            "router_ipv4": plan.expected_router_ipv4,
            "lease_time": plan.expected_lease_time,
            "renewal_time": plan.expected_renewal_time,
            "rebinding_time": plan.expected_rebinding_time,
        }),
        "dhcp-hostname" => json!({
            "required": true,
            "kind": "dhcp-responder",
            "port": plan.destination_port,
            "client_port": plan.source_port,
            "client_mac": plan.client_mac,
            "hostname": plan.hostname,
            "transaction_id": plan.transaction_id,
            "yiaddr": plan.expected_yiaddr,
            "server_identifier": plan.expected_server_identifier,
            "subnet_mask": plan.expected_subnet_mask,
            "router_ipv4": plan.expected_router_ipv4,
            "lease_time": plan.expected_lease_time,
            "renewal_time": plan.expected_renewal_time,
            "rebinding_time": plan.expected_rebinding_time,
        }),
        "dhcp-parameter-request-list" => json!({
            "required": true,
            "kind": "dhcp-responder",
            "port": plan.destination_port,
            "client_port": plan.source_port,
            "client_mac": plan.client_mac,
            "parameter_request_list": plan.parameter_request_list,
            "transaction_id": plan.transaction_id,
            "yiaddr": plan.expected_yiaddr,
            "server_identifier": plan.expected_server_identifier,
            "subnet_mask": plan.expected_subnet_mask,
            "router_ipv4": plan.expected_router_ipv4,
            "dns_ipv4": plan.expected_dns_ipv4,
            "lease_time": plan.expected_lease_time,
            "renewal_time": plan.expected_renewal_time,
            "rebinding_time": plan.expected_rebinding_time,
        }),
        "dhcp-lease-time" => json!({
            "required": true,
            "kind": "dhcp-responder",
            "port": plan.destination_port,
            "client_port": plan.source_port,
            "client_mac": plan.client_mac,
            "transaction_id": plan.transaction_id,
            "yiaddr": plan.expected_yiaddr,
            "server_identifier": plan.expected_server_identifier,
            "subnet_mask": plan.expected_subnet_mask,
            "router_ipv4": plan.expected_router_ipv4,
            "lease_time": plan.expected_lease_time,
            "renewal_time": plan.expected_renewal_time,
            "rebinding_time": plan.expected_rebinding_time,
        }),
        "dhcp-renewal-unicast-ack" => json!({
            "required": true,
            "kind": "dhcp-responder",
            "port": plan.destination_port,
            "client_port": plan.source_port,
            "client_mac": plan.client_mac,
            "transaction_id": plan.transaction_id,
            // RENEWING-state renewal: the client is already bound to this
            // address (ciaddr) and unicasts the Request directly to the leasing
            // server, which renews the same address in the Ack yiaddr.
            "client_ciaddr": plan.client_ciaddr,
            "renewal_unicast": true,
            "yiaddr": plan.expected_yiaddr,
            "server_identifier": plan.expected_server_identifier,
            "subnet_mask": plan.expected_subnet_mask,
            "router_ipv4": plan.expected_router_ipv4,
            "dns_ipv4": plan.expected_dns_ipv4,
            "lease_time": plan.expected_lease_time,
            "renewal_time": plan.expected_renewal_time,
            "rebinding_time": plan.expected_rebinding_time,
        }),
        "dhcp-inform-ack" => json!({
            "required": true,
            "kind": "dhcp-responder",
            "port": plan.destination_port,
            "client_port": plan.source_port,
            "client_mac": plan.client_mac,
            "transaction_id": plan.transaction_id,
            // INFORM: the client already holds this address (carried in ciaddr)
            // and asks only for configuration parameters. RFC 2131 section 4.3.5:
            // the Ack allocates no address (yiaddr 0.0.0.0) and grants no lease
            // (no option 51).
            "client_ciaddr": plan.client_ciaddr,
            "parameter_request_list": plan.parameter_request_list,
            "inform": true,
            "yiaddr_zero": plan.expected_yiaddr_zero,
            "no_lease_time": plan.expected_no_lease_time,
            "server_identifier": plan.expected_server_identifier,
            "subnet_mask": plan.expected_subnet_mask,
            "router_ipv4": plan.expected_router_ipv4,
            "dns_ipv4": plan.expected_dns_ipv4,
        }),
        "dhcp-request-nak" => json!({
            "required": true,
            "kind": "dhcp-responder",
            "port": plan.destination_port,
            "client_port": plan.source_port,
            "client_mac": plan.client_mac,
            "transaction_id": plan.transaction_id,
            // The client requests an address outside the served pool (option 50),
            // so the responder refuses with a DHCPNAK rather than committing a
            // binding. RFC 2131 section 4.3.2: the Nak allocates no address
            // (yiaddr 0.0.0.0) and grants no lease (no option 51); it names the
            // server in option 54 and MAY carry a message (option 56).
            "requested_ipv4": plan.requested_ipv4,
            "nak": true,
            "yiaddr_zero": plan.expected_yiaddr_zero,
            "no_lease_time": plan.expected_no_lease_time,
            "server_identifier": plan.expected_server_identifier,
            "message": plan.expected_message,
        }),
        "dhcp-rapid-repeat" => json!({
            "required": true,
            "kind": "dhcp-responder",
            "port": plan.destination_port,
            "client_port": plan.source_port,
            "client_mac": plan.client_mac,
            "transaction_id": plan.transaction_id,
            "yiaddr": plan.expected_yiaddr,
            "server_identifier": plan.expected_server_identifier,
            "subnet_mask": plan.expected_subnet_mask,
            "router_ipv4": plan.expected_router_ipv4,
            "lease_time": plan.expected_lease_time,
            "renewal_time": plan.expected_renewal_time,
            "rebinding_time": plan.expected_rebinding_time,
            // The responder answers each repeated Discover with its own Offer
            // keyed by the per-send xid/chaddr, so each decoded Offer is matched
            // back to its Discover and carries its own offered address.
            "rapid_repeat": {
                "sends": dhcp::repeat_sends_json(plan.dhcp_sends.as_deref()),
            },
        }),
        "udp-echo-empty" | "udp-echo-short" | "udp-echo-binary" => json!({
            "required": true,
            "kind": "udp-responder",
            "mode": "echo",
            "port": plan.destination_port,
            "payload_hex": plan.payload_hex,
            "payload_length": plan.payload_length,
            "expected_payload_hex": plan.expected_payload_hex,
            "expected_payload_length": plan.expected_payload_length,
            "expected_udp_length": plan.expected_udp_length,
            "checksum_statuses": plan.expected_udp_checksum_statuses,
        }),
        "arp-basic-who-has"
        | "arp-source-address-preserved"
        | "arp-unicast-request-reply"
        | "arp-padding-reply"
        | "arp-mac-validation" => {
            json!({
                "required": true,
                // ARP relies primarily on the target kernel answering who-has for
                // its own configured address; setup tunes ARP sysctls and flushes
                // the neighbor cache (no listening daemon).
                "kind": "arp-kernel",
                "layer": "link",
                "target_protocol_addr": plan.target_protocol_addr,
                "target_hardware_addr": plan
                    .validation
                    .as_ref()
                    .and_then(|validation| validation.sender_hardware_addr.clone()),
                "arp_sysctls": true,
                "neighbor_cache_flush": true,
            })
        }
        "arp-broadcast-filtered-capture" => json!({
            "required": true,
            // ARP relies primarily on the target kernel answering who-has for its
            // own configured address; setup can also emit unrelated ARP replies.
            // The capture remains broad, and the ARP module ignores decoded decoys
            // that do not target the planned sender protocol address.
            "kind": "arp-kernel",
            "layer": "link",
            "target_protocol_addr": plan.target_protocol_addr,
            "target_hardware_addr": plan
                .validation
                .as_ref()
                .and_then(|validation| validation.sender_hardware_addr.clone()),
            "arp_sysctls": true,
            "neighbor_cache_flush": true,
            "decoy_arp_event": plan.decoy_arp_event,
        }),
        "arp-alias-address-reply" => json!({
            "required": true,
            // Target setup adds (and cleanup removes) a deterministic secondary
            // IPv4 alias on the private interface; the kernel then answers ARP for
            // the alias. Setup also tunes ARP sysctls and flushes the neighbor
            // cache (no listening daemon). The who-has resolves the alias, so the
            // target protocol address is the alias rather than the primary IPv4.
            "kind": "arp-kernel",
            "layer": "link",
            "target_protocol_addr": plan.target_protocol_addr,
            "target_hardware_addr": plan
                .validation
                .as_ref()
                .and_then(|validation| validation.sender_hardware_addr.clone()),
            "alias_address": true,
            "alias_ipv4": plan
                .alias_ipv4
                .clone()
                .or_else(|| plan.target_protocol_addr.clone()),
            "arp_sysctls": true,
            "neighbor_cache_flush": true,
        }),
        "arp-spa-variation" => json!({
            "required": true,
            // ARP relies primarily on the target kernel answering who-has for its
            // own configured address; setup tunes ARP sysctls and flushes the
            // neighbor cache (no listening daemon). The who-has carries an
            // ALTERNATE sender protocol address (SPA); for live execution the
            // kernel may need that SPA configured as a secondary sender address so
            // it accepts/answers the request, so the target service records the
            // alternate SPA (added during setup, removed during cleanup).
            "kind": "arp-kernel",
            "layer": "link",
            "target_protocol_addr": plan.target_protocol_addr,
            "target_hardware_addr": plan
                .validation
                .as_ref()
                .and_then(|validation| validation.sender_hardware_addr.clone()),
            "alt_sender_address": true,
            "alt_sender_ipv4": plan
                .alt_sender_ipv4
                .clone()
                .or_else(|| plan.sender_protocol_addr.clone()),
            "arp_sysctls": true,
            "neighbor_cache_flush": true,
        }),
        "arp-repeat-two-replies" => json!({
            "required": true,
            // ARP relies primarily on the target kernel answering who-has for
            // its own configured address; setup tunes ARP sysctls and flushes
            // the neighbor cache (no listening daemon). The repeated who-has
            // resolves the same target twice, so the kernel answers each send.
            "kind": "arp-kernel",
            "layer": "link",
            "target_protocol_addr": plan.target_protocol_addr,
            "target_hardware_addr": plan
                .validation
                .as_ref()
                .and_then(|validation| validation.sender_hardware_addr.clone()),
            "arp_sysctls": true,
            "neighbor_cache_flush": true,
            // The kernel answers each repeated who-has for the same target with
            // its own is-at, so each decoded reply is validated against its send.
            "repeat": {
                "sends": arp::repeat_sends_json(plan.arp_sends.as_deref()),
            },
        }),
        "arp-cache-flush-reply" => json!({
            "required": true,
            // ARP relies primarily on the target kernel answering who-has for its
            // own configured address; setup tunes ARP sysctls and flushes the
            // neighbor cache (no listening daemon).
            "kind": "arp-kernel",
            "layer": "link",
            "target_protocol_addr": plan.target_protocol_addr,
            "target_hardware_addr": plan
                .validation
                .as_ref()
                .and_then(|validation| validation.sender_hardware_addr.clone()),
            "arp_sysctls": true,
            "neighbor_cache_flush": true,
            // The behavioral distinction: the target setup flushes the relevant
            // neighbor entries BEFORE the stimulus who-has so resolution starts
            // cold, and cleanup leaves neighbor state in the normal,
            // provider-controlled (flushed) state. Surface the explicit flush
            // marker, interface, and setup/cleanup commands so the dry-run target
            // service plan documents the cache-cleanup contract.
            "flush_neighbor": plan.flush_neighbor.unwrap_or(true),
            "neighbor_flush_interface": plan.neighbor_flush_interface,
            "neighbor_flush_commands": plan.neighbor_flush_commands,
            "neighbor_flush_cleanup_commands": plan.neighbor_flush_cleanup_commands,
        }),
        _ => json!({}),
    }
}

pub fn validation_json(plan: &ProbePlan) -> Value {
    match plan.case.as_str() {
        "udp-echo-empty" | "udp-echo-short" | "udp-echo-binary" => json!({
            "source_ipv4": plan.expected_reply_source_ipv4,
            "destination_ipv4": plan.expected_reply_destination_ipv4,
            "source_port": plan.destination_port,
            "destination_port": plan.source_port,
            "payload_hex": plan.expected_payload_hex,
            "payload_length": plan.expected_payload_length,
            "udp_length": plan.expected_udp_length,
            "checksum_present": plan.expected_udp_checksum_present,
            "checksum_statuses": plan.expected_udp_checksum_statuses,
        }),
        _ => {
            // Echo the ARP is-at validation contract so the expected-reply shape
            // (including the source-address preservation contract: the reply's
            // TARGET HW/proto equal the request's SENDER HW/proto) is inspectable
            // from the plan echo. Non-ARP cases leave `validation` unset, so this
            // renders null.
            arp::arp_validation_json(plan.validation.as_ref())
        }
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

pub fn required_u8_list<'a>(value: Option<&'a [u8]>, field: &str) -> ExampleResult<&'a [u8]> {
    value
        .filter(|item| !item.is_empty())
        .ok_or_else(|| format!("probe plan missing required field {field}").into())
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
