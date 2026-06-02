//! ARP behavioral probe cases.
//!
//! `arp-basic-who-has` is the baseline ARP behavioral check: build an
//! Ethernet/ARP who-has request with libcrafter (operation 1, Ethernet
//! destination broadcast), send it at the link layer on a private L2 lab
//! segment, capture the target kernel's unicast is-at reply, decode the
//! Ethernet/ARP response with libcrafter, and validate the operation (reply,
//! 2), the sender hardware/protocol address (the resolved target MAC/IPv4), the
//! target hardware/protocol address (the original sender), and the Ethernet
//! source/destination of the reply.
//!
//! ARP rides Ethernet directly (no IP/UDP), unlike the DNS/DHCP cases: the
//! send/capture path is link-layer (`SendOptions::link_layer`) and the decode
//! entrypoint decodes the Ethernet frame
//! (`Packet::decode_from_link(LinkType::Ethernet, ..)`), not an L3 packet.

use crafter::prelude::*;
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::common::{
    capture_filter, decoded_packet_json, failed_outcome, hex_bytes, observed_response, plan_json,
    required_str, required_u16, send_report_json, target_service_json, ArpSend, ArpValidation,
    CandidateValidation, ExampleResult, ProbeOutcome, ProbePlan, StimulusEndpointRequest,
    FAILURE_DECODE_FAILED, FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD, FAILURE_WRONG_PEER,
};

/// Stable identifier for the ARP case module.
pub const MODULE_NAME: &str = "arp";

/// Ethernet broadcast address: an ARP who-has is broadcast to the segment.
const BROADCAST_MAC: &str = "ff:ff:ff:ff:ff:ff";

pub fn run_arp_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    if let Some(sends) = plan.arp_sends.as_deref() {
        return run_arp_multi_send_dry_run(request, plan, sends);
    }
    let packet = arp_who_has_packet(plan)?;
    // ARP is sent at the link layer (Ethernet), not the network layer: the
    // outgoing frame starts at Ethernet, so the dry-run send plan uses
    // `link_layer()` and compiles the Ethernet/ARP who-has without touching the
    // wire.
    let report = SocketSender::new(
        SendOptions::new()
            .iface(request.interface.clone())
            .link_layer()
            .dry_run(),
    )
    .send(&packet)?;
    let sent_raw_hex = hex_bytes(report.plan().bytes());
    // Record the compiled on-wire frame length so a padded who-has
    // (`arp-padding-reply`) is inspectable: the endpoint reports the sent frame
    // length and how it compares to the plan's expected request frame length.
    let sent_frame_len = report.plan().bytes().len();
    let observed = observed_response(
        plan,
        false,
        None,
        json!({}),
        json!({
            "planned_only": true,
            "send_report": send_report_json(&report),
            "sent_raw_hex": sent_raw_hex,
            "sent_frame_len": sent_frame_len,
            "expected_request_frame_len": plan.expected_request_frame_len,
            "ethernet_min_frame_len": plan.ethernet_min_frame_len,
            "capture_filter": capture_filter(plan),
            "target_service": target_service_json(plan),
            "ignore_unmatched_arp_replies": plan.ignore_unmatched_arp_replies,
            "decoy_arp_event": plan.decoy_arp_event,
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
            "sent_frame_len": sent_frame_len,
            "expected_request_frame_len": plan.expected_request_frame_len,
            "ethernet_min_frame_len": plan.ethernet_min_frame_len,
            "capture_filter": capture_filter(plan),
            "target_service": target_service_json(plan),
            "ignore_unmatched_arp_replies": plan.ignore_unmatched_arp_replies,
            "decoy_arp_event": plan.decoy_arp_event,
        }
    });
    Ok(ProbeOutcome {
        result,
        observed_response: observed,
        sent: false,
        received: false,
    })
}

pub fn run_arp_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    if let Some(sends) = plan.arp_sends.as_deref() {
        return run_arp_multi_send_live(request, plan, sends);
    }
    let packet = arp_who_has_packet(plan)?;
    let timeout = Duration::from_secs(request.timeout_seconds.max(1));
    let mut sniffer = match Sniffer::interface(request.interface.clone())
        .timeout(timeout)
        .count(64)
        .filter(capture_filter(plan))
        .nonblock()
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
            .link_layer()
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
    let mut wrong_payload = None;
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
        match validate_arp_candidate(plan, captured.packet(), captured.data())? {
            CandidateValidation::Ignore => {}
            CandidateValidation::Passed(decoded) => {
                let raw_hex = hex_bytes(captured.data());
                // Record the compiled request frame length so a padded who-has
                // (`arp-padding-reply`) reports the sent frame length alongside
                // the decoded reply.
                let sent_frame_len = send_report.plan().bytes().len();
                let observed = observed_response(
                    plan,
                    true,
                    Some(raw_hex.clone()),
                    decoded.clone(),
                    json!({
                        "send_report": send_report_json(&send_report),
                        "sent_frame_len": sent_frame_len,
                        "expected_request_frame_len": plan.expected_request_frame_len,
                        "ethernet_min_frame_len": plan.ethernet_min_frame_len,
                        "capture_filter": capture_filter(plan),
                        "ignore_unmatched_arp_replies": plan.ignore_unmatched_arp_replies,
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
                        "sent_frame_len": sent_frame_len,
                        "expected_request_frame_len": plan.expected_request_frame_len,
                        "ethernet_min_frame_len": plan.ethernet_min_frame_len,
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
                wrong_payload = Some(decoded);
            }
        }
    }

    if let Some(decoded) = wrong_payload {
        return Ok(failed_outcome(
            plan,
            FAILURE_WRONG_PAYLOAD,
            vec!["captured ARP reply did not match the expected is-at contract".to_string()],
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
            vec!["captured ARP reply did not resolve the expected target address".to_string()],
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
        vec!["timed out waiting for ARP is-at reply".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter(plan),
        })),
        sent,
        false,
    ))
}

/// Derive a single-send `ProbePlan` for one entry of a multi-send ARP case's
/// `arp_sends` array. The derived plan reuses the parent's case and shared fields
/// but overrides the per-send sender/target hardware/protocol addresses, the
/// Ethernet framing, the capture filter, and the typed is-at validation contract
/// so the existing single-send builders (`arp_who_has_packet`,
/// `validate_arp_candidate`) operate on exactly this one who-has and its own
/// expected is-at reply.
fn send_as_plan(parent: &ProbePlan, send: &ArpSend) -> ProbePlan {
    let mut derived = parent.clone();
    // This send is a single, self-contained who-has -> is-at exchange; clear the
    // multi-send marker so the single-send build/validate path runs against just
    // this send.
    derived.arp_sends = None;
    if let Some(value) = send.operation {
        derived.operation = Some(value);
    }
    if let Some(value) = send.sender_hardware_addr.clone() {
        derived.sender_hardware_addr = Some(value);
    }
    if let Some(value) = send.sender_protocol_addr.clone() {
        derived.sender_protocol_addr = Some(value);
    }
    if let Some(value) = send.target_hardware_addr.clone() {
        derived.target_hardware_addr = Some(value);
    }
    if let Some(value) = send.target_protocol_addr.clone() {
        derived.target_protocol_addr = Some(value);
    }
    if let Some(value) = send.ethernet_source.clone() {
        derived.ethernet_source = Some(value);
    }
    if let Some(value) = send.ethernet_destination.clone() {
        derived.ethernet_destination = Some(value);
    }
    if let Some(value) = send.validation.clone() {
        derived.validation = Some(value);
    }
    derived
}

/// Dry-run a multi-send ARP case (`arp-repeat-two-replies`): compile every
/// per-send Ethernet/ARP who-has with libcrafter and emit one planned send and
/// one expected is-at reply per send. No traffic leaves the host. The output
/// carries a `planned_sends` array (one entry per build) and a top-level
/// `send_count` so an inspector sees two planned sends and two expected
/// responses.
fn run_arp_multi_send_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
    sends: &[ArpSend],
) -> ExampleResult<ProbeOutcome> {
    let mut planned_sends = Vec::with_capacity(sends.len());
    for (offset, send) in sends.iter().enumerate() {
        let send_plan = send_as_plan(plan, send);
        let packet = arp_who_has_packet(&send_plan)?;
        let report = SocketSender::new(
            SendOptions::new()
                .iface(request.interface.clone())
                .link_layer()
                .dry_run(),
        )
        .send(&packet)?;
        let sent_raw_hex = hex_bytes(report.plan().bytes());
        planned_sends.push(json!({
            "index": send.index.unwrap_or(offset),
            "operation": send_plan.operation,
            "sender_hardware_addr": send_plan.sender_hardware_addr,
            "sender_protocol_addr": send_plan.sender_protocol_addr,
            "target_protocol_addr": send_plan.target_protocol_addr,
            "ethernet_source": send_plan.ethernet_source,
            "ethernet_destination": send_plan.ethernet_destination,
            "send_report": send_report_json(&report),
            "sent_raw_hex": sent_raw_hex,
            "capture_filter": capture_filter(&send_plan),
            "expected_response": arp_expected_response_json(&send_plan),
        }));
    }
    let expected_responses: Vec<Value> = planned_sends
        .iter()
        .filter_map(|entry| entry.get("expected_response").cloned())
        .collect();
    let observed = observed_response(
        plan,
        false,
        None,
        json!({}),
        json!({
            "planned_only": true,
            "send_count": planned_sends.len(),
            "planned_sends": planned_sends,
            "expected_responses": expected_responses,
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
            "send_count": planned_sends.len(),
            "planned_sends": planned_sends,
            "expected_responses": expected_responses,
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

/// Live multi-send ARP case (`arp-repeat-two-replies`): build and send every
/// per-send libcrafter who-has, capture the is-at replies, decode each, and
/// validate every reply against *its* send's is-at contract (operation, resolved
/// sender hardware/protocol address, target hardware/protocol address, and
/// Ethernet framing). Each send opens its own link-layer capture, so the two
/// replies for the repeated who-has are validated independently — every reply is
/// matched to the who-has that produced it. The case passes only when every send
/// validates, and the report records both responses and their raw hex.
fn run_arp_multi_send_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
    sends: &[ArpSend],
) -> ExampleResult<ProbeOutcome> {
    let mut send_results = Vec::with_capacity(sends.len());
    let mut all_passed = true;
    let mut any_sent = false;
    let mut any_received = false;
    let mut failure_reason: Option<&'static str> = None;
    let mut errors: Vec<String> = Vec::new();

    for (offset, send) in sends.iter().enumerate() {
        let send_plan = send_as_plan(plan, send);
        let outcome = run_arp_live(request, &send_plan)?;
        any_sent |= outcome.sent;
        any_received |= outcome.received;
        let status = outcome
            .result
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("failed");
        if status != "passed" {
            all_passed = false;
            let reason = outcome
                .result
                .get("metadata")
                .and_then(|metadata| metadata.get("failure_reason"))
                .and_then(Value::as_str);
            if let Some(reason) = reason {
                failure_reason.get_or_insert(static_failure_reason(reason));
                errors.push(format!(
                    "send {} (target {:?}) failed: {reason}",
                    send.index.unwrap_or(offset),
                    send_plan.target_protocol_addr,
                ));
            }
        }
        // Record both the per-send raw hex and the decoded reply so the report
        // captures every observed is-at response.
        let raw_hex = outcome
            .observed_response
            .get("raw_hex")
            .cloned()
            .unwrap_or(Value::Null);
        send_results.push(json!({
            "index": send.index.unwrap_or(offset),
            "operation": send_plan.operation,
            "target_protocol_addr": send_plan.target_protocol_addr,
            "status": status,
            "raw_hex": raw_hex,
            "result": outcome.result,
        }));
    }

    let summary = json!({
        "send_count": sends.len(),
        "send_results": send_results,
    });

    if all_passed {
        let observed = observed_response(
            plan,
            true,
            None,
            summary.clone(),
            json!({
                "capture_filter": capture_filter(plan),
                "send_count": sends.len(),
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
                "send_count": sends.len(),
                "send_results": observed["decoded"]["send_results"].clone(),
            }
        });
        return Ok(ProbeOutcome {
            result,
            observed_response: observed,
            sent: any_sent,
            received: any_received,
        });
    }

    Ok(failed_outcome(
        plan,
        failure_reason.unwrap_or(FAILURE_WRONG_PAYLOAD),
        if errors.is_empty() {
            vec!["one or more repeat-two-replies sends failed validation".to_string()]
        } else {
            errors
        },
        Some(summary),
        any_sent,
        any_received,
    ))
}

/// Map a failure-reason string (as it appears in a per-send result) back to the
/// crate's `'static` failure-reason constants so the aggregate failure uses a
/// stable reason.
fn static_failure_reason(reason: &str) -> &'static str {
    match reason {
        FAILURE_TIMEOUT => FAILURE_TIMEOUT,
        FAILURE_WRONG_PEER => FAILURE_WRONG_PEER,
        FAILURE_DECODE_FAILED => FAILURE_DECODE_FAILED,
        _ => FAILURE_WRONG_PAYLOAD,
    }
}

/// JSON view of one send's expected is-at reply (operation, resolved sender
/// hardware/protocol address, target hardware/protocol address, and Ethernet
/// framing) for the dry-run report.
fn arp_expected_response_json(send_plan: &ProbePlan) -> Value {
    let validation = send_plan.validation.as_ref();
    json!({
        "operation": validation.and_then(|v| v.operation),
        "sender_hardware_addr": validation.and_then(|v| v.sender_hardware_addr.clone()),
        "sender_protocol_addr": validation.and_then(|v| v.sender_protocol_addr.clone()),
        "target_hardware_addr": validation.and_then(|v| v.target_hardware_addr.clone()),
        "target_protocol_addr": validation.and_then(|v| v.target_protocol_addr.clone()),
        "ethernet_source": validation.and_then(|v| v.ethernet_source.clone()),
        "ethernet_destination": validation.and_then(|v| v.ethernet_destination.clone()),
        "direction": "target_to_sender",
    })
}

/// JSON view of a plan's `arp_sends` array for the plan echo. `None` renders
/// null.
pub fn sends_json(sends: Option<&[ArpSend]>) -> Value {
    match sends {
        Some(sends) => Value::Array(
            sends
                .iter()
                .map(|send| {
                    json!({
                        "index": send.index,
                        "operation": send.operation,
                        "sender_hardware_addr": send.sender_hardware_addr,
                        "sender_protocol_addr": send.sender_protocol_addr,
                        "target_hardware_addr": send.target_hardware_addr,
                        "target_protocol_addr": send.target_protocol_addr,
                        "ethernet_source": send.ethernet_source,
                        "ethernet_destination": send.ethernet_destination,
                        "capture_filter": send.capture_filter,
                        "validation": arp_validation_json(send.validation.as_ref()),
                    })
                })
                .collect(),
        ),
        None => Value::Null,
    }
}

/// JSON view of a plan's `arp_sends` for the target kernel's `repeat` descriptor:
/// the per-send target protocol address the kernel answers and the resolved
/// sender hardware/protocol address each is-at reply carries.
pub fn repeat_sends_json(sends: Option<&[ArpSend]>) -> Value {
    match sends {
        Some(sends) => Value::Array(
            sends
                .iter()
                .map(|send| {
                    let validation = send.validation.as_ref();
                    json!({
                        "target_protocol_addr": send.target_protocol_addr,
                        "sender_hardware_addr": validation
                            .and_then(|v| v.sender_hardware_addr.clone()),
                        "sender_protocol_addr": validation
                            .and_then(|v| v.sender_protocol_addr.clone()),
                    })
                })
                .collect(),
        ),
        None => Value::Null,
    }
}

/// JSON view of one is-at validation contract for the plan echo.
pub fn arp_validation_json(validation: Option<&ArpValidation>) -> Value {
    match validation {
        Some(validation) => json!({
            "operation": validation.operation,
            "sender_hardware_addr": validation.sender_hardware_addr,
            "sender_protocol_addr": validation.sender_protocol_addr,
            "sender_protocol_addrs": validation.sender_protocol_addrs,
            "target_hardware_addr": validation.target_hardware_addr,
            "target_protocol_addr": validation.target_protocol_addr,
            "ethernet_source": validation.ethernet_source,
            "ethernet_destination": validation.ethernet_destination,
        }),
        None => Value::Null,
    }
}

/// Build the Ethernet/ARP who-has request with libcrafter.
///
/// `compile()` fills the ARP htype/ptype/hlen/plen and the Ethernet ethertype
/// (0x0806) from the layer stack; the caller-set operation, addresses, and
/// Ethernet framing survive untouched. The Ethernet destination defaults to the
/// broadcast address (a who-has is broadcast to the segment) unless the plan
/// overrides it.
///
/// When the plan sets `ethernet_min_frame_len`, the frame is padded with
/// trailing zero bytes up to that length by appending a [`Raw`] layer after the
/// ARP layer (an Ethernet/ARP frame is 42 bytes — 14-byte header + 28-byte ARP
/// payload — below the classic 60-byte sans-FCS minimum). The padding is an
/// honored override: `compile()` preserves it untouched, and the peer's reply
/// decodes the trailing padding back to a `Raw` layer.
pub fn arp_who_has_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let sender_protocol_addr: Ipv4Addr =
        required_str(plan.sender_protocol_addr.as_deref(), "sender_protocol_addr")?.parse()?;
    let target_protocol_addr: Ipv4Addr =
        required_str(plan.target_protocol_addr.as_deref(), "target_protocol_addr")?.parse()?;
    let sender_hardware_addr: MacAddr =
        required_str(plan.sender_hardware_addr.as_deref(), "sender_hardware_addr")?.parse()?;
    let ethernet_source: MacAddr =
        required_str(plan.ethernet_source.as_deref(), "ethernet_source")?.parse()?;
    let ethernet_destination: MacAddr = plan
        .ethernet_destination
        .as_deref()
        .unwrap_or(BROADCAST_MAC)
        .parse()?;

    let arp = Arp::who_has(
        sender_protocol_addr,
        target_protocol_addr,
        sender_hardware_addr,
    );
    let mut packet = Ethernet::with_addresses(ethernet_source, ethernet_destination) / arp;

    if let Some(min_frame_len) = plan.ethernet_min_frame_len {
        // Compile the unpadded frame to learn its on-wire length, then append a
        // deterministic run of trailing zero bytes to reach the minimum. The
        // padding rides as a `Raw` layer after ARP so the agent-set padding is
        // honored and `compile()` leaves it untouched.
        let base_len = packet.compile()?.into_bytes().len();
        if min_frame_len > base_len {
            let pad = vec![0u8; min_frame_len - base_len];
            packet = packet / Raw::from_bytes(&pad);
        }
    }

    Ok(packet)
}

/// Validate one captured candidate against the ARP who-has -> is-at contract.
///
/// A frame whose decoded ARP target protocol address does not match the
/// stimulus sender (the address the reply must be addressed back to) surfaces as
/// `WrongPeer`; a frame addressed back to the sender that fails the is-at
/// contract (operation, resolved addresses, Ethernet framing) surfaces as
/// `WrongPayload`. A fully matching is-at reply surfaces as `Passed`.
pub fn validate_arp_candidate(
    plan: &ProbePlan,
    packet: &Packet,
    raw: &[u8],
) -> ExampleResult<CandidateValidation> {
    let Some(arp) = packet.layer::<Arp>() else {
        return Ok(CandidateValidation::Ignore);
    };
    let validation = plan
        .validation
        .as_ref()
        .ok_or("arp-basic-who-has plan is missing the validation contract")?;

    let decoded = decoded_packet_json(packet, raw);

    // Peer match: the reply's ARP target protocol address must be the original
    // sender's protocol address (the address the kernel resolves the reply back
    // to). A reply for any other querier is for a different exchange.
    let expected_target_protocol: Ipv4Addr = required_str(
        validation.target_protocol_addr.as_deref(),
        "validation.target_protocol_addr",
    )?
    .parse()?;
    let mut peer_mismatches = Vec::new();
    match arp.target_ipv4() {
        Some(actual) => {
            if actual != expected_target_protocol {
                peer_mismatches.push(json!({
                    "field": "arp.target_protocol_addr",
                    "expected": expected_target_protocol.to_string(),
                    "actual": actual.to_string(),
                }));
            }
        }
        None => peer_mismatches.push(json!({
            "field": "arp.target_protocol_addr",
            "expected": expected_target_protocol.to_string(),
            "actual": hex_bytes(&arp.target_protocol_bytes_value()),
        })),
    }
    if !peer_mismatches.is_empty() {
        if plan.ignore_unmatched_arp_replies.unwrap_or(false) {
            return Ok(CandidateValidation::Ignore);
        }
        return Ok(CandidateValidation::WrongPeer(json!({
            "packet": decoded,
            "mismatches": peer_mismatches,
        })));
    }

    let mut mismatches = Vec::new();

    // Operation: an is-at is an ARP reply (operation 2).
    let expected_operation = required_u16(validation.operation, "validation.operation")?;
    if arp.opcode_value() != expected_operation {
        mismatches.push(json!({
            "field": "arp.operation",
            "expected": expected_operation,
            "actual": arp.opcode_value(),
        }));
    }

    // Sender hardware address: the resolved target MAC the kernel answered with.
    let expected_sender_hardware: MacAddr = required_str(
        validation.sender_hardware_addr.as_deref(),
        "validation.sender_hardware_addr",
    )?
    .parse()?;
    match arp.sender_mac() {
        Some(actual) => {
            if actual != expected_sender_hardware {
                mismatches.push(json!({
                    "field": "arp.sender_hardware_addr",
                    "expected": expected_sender_hardware.to_string(),
                    "actual": actual.to_string(),
                }));
            }
        }
        None => mismatches.push(json!({
            "field": "arp.sender_hardware_addr",
            "expected": expected_sender_hardware.to_string(),
            "actual": hex_bytes(&arp.sender_hardware_bytes_value()),
        })),
    }

    // Sender protocol address: usually the resolved target IPv4. Live lab setup
    // can configure secondary IPv4s for sibling ARP cases in one full-suite run;
    // Linux may use one of those local addresses in an is-at reply while still
    // addressing the reply to the planned querier SPA.
    let expected_sender_protocols = expected_sender_protocol_addrs(validation)?;
    match arp.sender_ipv4() {
        Some(actual) => {
            if !expected_sender_protocols
                .iter()
                .any(|expected| actual == *expected)
            {
                mismatches.push(json!({
                    "field": "arp.sender_protocol_addr",
                    "expected": expected_sender_protocols
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                    "actual": actual.to_string(),
                }));
            }
        }
        None => mismatches.push(json!({
            "field": "arp.sender_protocol_addr",
            "expected": expected_sender_protocols
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            "actual": hex_bytes(&arp.sender_protocol_bytes_value()),
        })),
    }

    // Target hardware address: the original sender (the querier's MAC).
    let expected_target_hardware: MacAddr = required_str(
        validation.target_hardware_addr.as_deref(),
        "validation.target_hardware_addr",
    )?
    .parse()?;
    match arp.target_mac() {
        Some(actual) => {
            if actual != expected_target_hardware {
                mismatches.push(json!({
                    "field": "arp.target_hardware_addr",
                    "expected": expected_target_hardware.to_string(),
                    "actual": actual.to_string(),
                }));
            }
        }
        None => mismatches.push(json!({
            "field": "arp.target_hardware_addr",
            "expected": expected_target_hardware.to_string(),
            "actual": hex_bytes(&arp.target_hardware_bytes_value()),
        })),
    }

    // Ethernet framing: the unicast reply is addressed from the resolved target
    // MAC back to the original sender MAC.
    if let Some(ethernet) = packet.layer::<Ethernet>() {
        if let Some(expected_source) = validation.ethernet_source.as_deref() {
            let expected_source: MacAddr = expected_source.parse()?;
            match ethernet.source() {
                Some(actual) if actual == expected_source => {}
                actual => mismatches.push(json!({
                    "field": "ethernet.src",
                    "expected": expected_source.to_string(),
                    "actual": actual.map(|mac| mac.to_string()),
                })),
            }
        }
        if let Some(expected_destination) = validation.ethernet_destination.as_deref() {
            let expected_destination: MacAddr = expected_destination.parse()?;
            match ethernet.destination() {
                Some(actual) if actual == expected_destination => {}
                actual => mismatches.push(json!({
                    "field": "ethernet.dst",
                    "expected": expected_destination.to_string(),
                    "actual": actual.map(|mac| mac.to_string()),
                })),
            }
        }
    } else {
        mismatches.push(json!({
            "field": "ethernet",
            "expected": "present",
            "actual": "missing",
        }));
    }

    if mismatches.is_empty() {
        Ok(CandidateValidation::Passed(decoded))
    } else {
        Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": mismatches,
        })))
    }
}

fn expected_sender_protocol_addrs(validation: &ArpValidation) -> ExampleResult<Vec<Ipv4Addr>> {
    let mut values = Vec::new();
    if let Some(addrs) = validation.sender_protocol_addrs.as_ref() {
        for value in addrs {
            values.push(value.parse()?);
        }
    }
    if values.is_empty() {
        values.push(
            required_str(
                validation.sender_protocol_addr.as_deref(),
                "validation.sender_protocol_addr",
            )?
            .parse()?,
        );
    }
    Ok(values)
}

/// Render a decoded ARP layer to JSON for the observed-response artifact.
pub fn arp_json(arp: &Arp) -> Value {
    json!({
        "hardware_type": arp.hardware_type_value(),
        "protocol_type": arp.protocol_type_value(),
        "hardware_len": arp.hardware_len_value(),
        "protocol_len": arp.protocol_len_value(),
        "operation": arp.opcode_value(),
        "is_reply": arp.opcode_value() == u16::from(ArpOperation::Reply),
        "sender_hardware_addr": arp.sender_mac().map(|mac| mac.to_string()),
        "sender_hardware_bytes": hex_bytes(&arp.sender_hardware_bytes_value()),
        "sender_protocol_addr": arp.sender_ipv4().map(|addr| addr.to_string()),
        "sender_protocol_bytes": hex_bytes(&arp.sender_protocol_bytes_value()),
        "target_hardware_addr": arp.target_mac().map(|mac| mac.to_string()),
        "target_hardware_bytes": hex_bytes(&arp.target_hardware_bytes_value()),
        "target_protocol_addr": arp.target_ipv4().map(|addr| addr.to_string()),
        "target_protocol_bytes": hex_bytes(&arp.target_protocol_bytes_value()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ArpValidation;
    use crate::test_support::base_plan;

    fn who_has_plan() -> ProbePlan {
        let mut plan = base_plan("arp-basic-who-has");
        plan.sender_protocol_addr = Some("10.64.0.10".to_string());
        plan.target_protocol_addr = Some("10.64.0.20".to_string());
        plan.sender_hardware_addr = Some("00:00:5e:00:53:0a".to_string());
        plan.ethernet_source = Some("00:00:5e:00:53:0a".to_string());
        plan.ethernet_destination = Some(BROADCAST_MAC.to_string());
        plan.operation = Some(1);
        plan.validation = Some(ArpValidation {
            operation: Some(2),
            sender_hardware_addr: Some("00:00:5e:00:53:14".to_string()),
            sender_protocol_addr: Some("10.64.0.20".to_string()),
            sender_protocol_addrs: None,
            target_hardware_addr: Some("00:00:5e:00:53:0a".to_string()),
            target_protocol_addr: Some("10.64.0.10".to_string()),
            ethernet_source: Some("00:00:5e:00:53:14".to_string()),
            ethernet_destination: Some("00:00:5e:00:53:0a".to_string()),
        });
        plan
    }

    /// Build the canonical is-at reply the target kernel would unicast back, so
    /// the decode/validate path runs against a real libcrafter-built frame.
    fn is_at_frame(plan: &ProbePlan) -> Vec<u8> {
        let validation = plan.validation.as_ref().unwrap();
        let resolved_mac: MacAddr = validation
            .sender_hardware_addr
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let resolved_ipv4: Ipv4Addr = validation
            .sender_protocol_addr
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let querier_mac: MacAddr = validation
            .target_hardware_addr
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let querier_ipv4: Ipv4Addr = validation
            .target_protocol_addr
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let arp = Arp::is_at(resolved_ipv4, resolved_mac, querier_ipv4, querier_mac);
        let packet = Ethernet::with_addresses(resolved_mac, querier_mac) / arp;
        packet.compile().unwrap().into_bytes()
    }

    #[test]
    fn who_has_builds_ethernet_arp_broadcast_request() {
        let plan = who_has_plan();
        let packet = arp_who_has_packet(&plan).unwrap();

        let ethernet = packet.layer::<Ethernet>().expect("ethernet layer");
        assert_eq!(ethernet.source().unwrap().to_string(), "00:00:5e:00:53:0a");
        assert_eq!(ethernet.destination().unwrap().to_string(), BROADCAST_MAC);
        // compile() fills the ethertype from the ARP layer.
        let bytes = packet.compile().unwrap().into_bytes();
        assert_eq!(&bytes[12..14], &ETHERTYPE_ARP.to_be_bytes());

        let arp = packet.layer::<Arp>().expect("arp layer");
        assert_eq!(arp.opcode_value(), u16::from(ArpOperation::Request));
        assert_eq!(arp.sender_ipv4().unwrap().to_string(), "10.64.0.10");
        assert_eq!(arp.target_ipv4().unwrap().to_string(), "10.64.0.20");
        // who-has leaves the target hardware address unset (all-zero).
        assert_eq!(arp.target_mac().unwrap(), MacAddr::ZERO);
    }

    #[test]
    fn matching_is_at_reply_passes_validation() {
        let plan = who_has_plan();
        let raw = is_at_frame(&plan);
        let packet = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();

        match validate_arp_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed, got {other:?}"),
        }
    }

    #[test]
    fn reply_for_another_querier_is_wrong_peer() {
        let plan = who_has_plan();
        // A reply that resolves the right target but is addressed back to a
        // different querier protocol address is for a different exchange.
        let resolved_mac: MacAddr = "00:00:5e:00:53:14".parse().unwrap();
        let arp = Arp::is_at(
            "10.64.0.20".parse().unwrap(),
            resolved_mac,
            "10.64.0.99".parse().unwrap(),
            "00:00:5e:00:53:63".parse().unwrap(),
        );
        let packet =
            Ethernet::with_addresses(resolved_mac, "00:00:5e:00:53:63".parse().unwrap()) / arp;
        let raw = packet.compile().unwrap().into_bytes();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();

        match validate_arp_candidate(&plan, &decoded, &raw).unwrap() {
            CandidateValidation::WrongPeer(_) => {}
            other => panic!("expected WrongPeer, got {other:?}"),
        }
    }

    #[test]
    fn filtered_capture_ignores_reply_for_another_querier() {
        let mut plan = who_has_plan();
        plan.case = "arp-broadcast-filtered-capture".to_string();
        plan.ignore_unmatched_arp_replies = Some(true);
        // The filtered-capture case may see unrelated ARP is-at replies from
        // target setup. A reply addressed to another protocol address should be
        // ignored, not treated as the matching response.
        let resolved_mac: MacAddr = "00:00:5e:00:53:14".parse().unwrap();
        let arp = Arp::is_at(
            "10.64.0.20".parse().unwrap(),
            resolved_mac,
            "10.64.0.99".parse().unwrap(),
            "00:00:5e:00:53:63".parse().unwrap(),
        );
        let packet =
            Ethernet::with_addresses(resolved_mac, "00:00:5e:00:53:63".parse().unwrap()) / arp;
        let raw = packet.compile().unwrap().into_bytes();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();

        match validate_arp_candidate(&plan, &decoded, &raw).unwrap() {
            CandidateValidation::Ignore => {}
            other => panic!("expected Ignore, got {other:?}"),
        }
    }

    #[test]
    fn request_echoed_back_is_wrong_payload() {
        let plan = who_has_plan();
        // A frame addressed back to the querier but still an ARP request (op 1)
        // with the wrong resolved MAC fails the is-at contract.
        let arp = Arp::new()
            .operation(ArpOperation::Request)
            .sender_hardware_addr("00:00:5e:00:53:ff".parse::<MacAddr>().unwrap())
            .sender_protocol_addr("10.64.0.20".parse().unwrap())
            .target_hardware_addr("00:00:5e:00:53:0a".parse::<MacAddr>().unwrap())
            .target_protocol_addr("10.64.0.10".parse().unwrap());
        let packet = Ethernet::with_addresses(
            "00:00:5e:00:53:ff".parse().unwrap(),
            "00:00:5e:00:53:0a".parse().unwrap(),
        ) / arp;
        let raw = packet.compile().unwrap().into_bytes();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();

        match validate_arp_candidate(&plan, &decoded, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload, got {other:?}"),
        }
    }

    #[test]
    fn reply_with_allowed_secondary_sender_protocol_passes_validation() {
        let mut plan = who_has_plan();
        plan.case = "arp-spa-variation".to_string();
        plan.sender_protocol_addr = Some("10.64.0.17".to_string());
        plan.validation.as_mut().unwrap().target_protocol_addr = Some("10.64.0.17".to_string());
        plan.validation.as_mut().unwrap().sender_protocol_addrs = Some(vec![
            "10.64.0.20".to_string(),
            "10.64.0.27".to_string(),
            "10.64.0.17".to_string(),
        ]);

        let resolved_mac: MacAddr = "00:00:5e:00:53:14".parse().unwrap();
        let querier_mac: MacAddr = "00:00:5e:00:53:0a".parse().unwrap();
        let arp = Arp::is_at(
            "10.64.0.27".parse().unwrap(),
            resolved_mac,
            "10.64.0.17".parse().unwrap(),
            querier_mac,
        );
        let packet = Ethernet::with_addresses(resolved_mac, querier_mac) / arp;
        let raw = packet.compile().unwrap().into_bytes();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();

        match validate_arp_candidate(&plan, &decoded, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed, got {other:?}"),
        }
    }

    #[test]
    fn missing_validation_contract_is_an_error() {
        let mut plan = who_has_plan();
        plan.validation = None;
        let raw = is_at_frame(&who_has_plan());
        let packet = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();
        assert!(validate_arp_candidate(&plan, &packet, &raw).is_err());
    }

    /// Build a two-send `arp-repeat-two-replies` plan resolving the same target
    /// twice, mirroring the planner's per-send shape.
    fn repeat_plan() -> ProbePlan {
        let base = who_has_plan();
        let send = ArpSend {
            index: None,
            operation: Some(1),
            sender_hardware_addr: base.sender_hardware_addr.clone(),
            sender_protocol_addr: base.sender_protocol_addr.clone(),
            target_hardware_addr: Some("00:00:00:00:00:00".to_string()),
            target_protocol_addr: base.target_protocol_addr.clone(),
            ethernet_source: base.ethernet_source.clone(),
            ethernet_destination: Some(BROADCAST_MAC.to_string()),
            capture_filter: Some("arp and arp[6:2] = 2".to_string()),
            validation: base.validation.clone(),
        };
        let mut plan = base_plan("arp-repeat-two-replies");
        plan.arp_sends = Some(vec![
            ArpSend {
                index: Some(0),
                ..send.clone()
            },
            ArpSend {
                index: Some(1),
                ..send
            },
        ]);
        plan
    }

    #[test]
    fn send_as_plan_derives_a_single_send_who_has() {
        let parent = repeat_plan();
        let sends = parent.arp_sends.clone().unwrap();
        let derived = send_as_plan(&parent, &sends[0]);

        // The derived plan is single-send (no nested array) and builds a real
        // Ethernet/ARP broadcast who-has.
        assert!(derived.arp_sends.is_none());
        let packet = arp_who_has_packet(&derived).unwrap();
        let ethernet = packet.layer::<Ethernet>().expect("ethernet layer");
        assert_eq!(ethernet.destination().unwrap().to_string(), BROADCAST_MAC);
        let arp = packet.layer::<Arp>().expect("arp layer");
        assert_eq!(arp.opcode_value(), u16::from(ArpOperation::Request));
        assert_eq!(arp.target_ipv4().unwrap().to_string(), "10.64.0.20");
    }

    /// Build an `arp-alias-address-reply` plan: the who-has resolves a *secondary*
    /// alias address (distinct from the endpoint's primary IPv4) that the target
    /// kernel answers for, and the is-at reply's sender protocol address is the
    /// alias while its sender hardware address is the target endpoint's MAC.
    fn alias_plan() -> ProbePlan {
        let mut plan = base_plan("arp-alias-address-reply");
        plan.sender_protocol_addr = Some("10.64.0.10".to_string());
        // The who-has resolves the configured alias, not the endpoint's primary.
        plan.target_protocol_addr = Some("10.64.0.27".to_string());
        plan.alias_ipv4 = Some("10.64.0.27".to_string());
        plan.sender_hardware_addr = Some("00:00:5e:00:53:0a".to_string());
        plan.ethernet_source = Some("00:00:5e:00:53:0a".to_string());
        plan.ethernet_destination = Some(BROADCAST_MAC.to_string());
        plan.operation = Some(1);
        plan.validation = Some(ArpValidation {
            operation: Some(2),
            // Reply sender HW is the target endpoint MAC; sender proto is the ALIAS.
            sender_hardware_addr: Some("00:00:5e:00:53:14".to_string()),
            sender_protocol_addr: Some("10.64.0.27".to_string()),
            sender_protocol_addrs: None,
            target_hardware_addr: Some("00:00:5e:00:53:0a".to_string()),
            target_protocol_addr: Some("10.64.0.10".to_string()),
            ethernet_source: Some("00:00:5e:00:53:14".to_string()),
            ethernet_destination: Some("00:00:5e:00:53:0a".to_string()),
        });
        plan
    }

    #[test]
    fn alias_who_has_resolves_the_alias_address() {
        let plan = alias_plan();
        let packet = arp_who_has_packet(&plan).unwrap();
        let arp = packet.layer::<Arp>().expect("arp layer");
        assert_eq!(arp.opcode_value(), u16::from(ArpOperation::Request));
        // The who-has target protocol address is the configured alias, distinct
        // from the stimulus sender protocol address.
        assert_eq!(arp.target_ipv4().unwrap().to_string(), "10.64.0.27");
        assert_eq!(arp.sender_ipv4().unwrap().to_string(), "10.64.0.10");
    }

    #[test]
    fn alias_is_at_reply_with_alias_sender_proto_passes_validation() {
        let plan = alias_plan();
        let raw = is_at_frame(&plan);
        let packet = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();
        match validate_arp_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed, got {other:?}"),
        }
    }

    #[test]
    fn alias_reply_for_the_primary_address_is_wrong_payload() {
        // A reply addressed back to the querier but resolving the endpoint's
        // PRIMARY address (not the alias) fails the alias is-at contract.
        let plan = alias_plan();
        let resolved_mac: MacAddr = "00:00:5e:00:53:14".parse().unwrap();
        let arp = Arp::is_at(
            "10.64.0.20".parse().unwrap(),
            resolved_mac,
            "10.64.0.10".parse().unwrap(),
            "00:00:5e:00:53:0a".parse().unwrap(),
        );
        let packet =
            Ethernet::with_addresses(resolved_mac, "00:00:5e:00:53:0a".parse().unwrap()) / arp;
        let raw = packet.compile().unwrap().into_bytes();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();
        match validate_arp_candidate(&plan, &decoded, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload, got {other:?}"),
        }
    }

    /// Build an `arp-unicast-request-reply` plan: an ordinary who-has whose
    /// Ethernet destination is the *known target MAC* rather than the broadcast
    /// address. The target endpoint MAC is the resolved address the is-at reply
    /// also carries (`validation.sender_hardware_addr`).
    fn unicast_plan() -> ProbePlan {
        let mut plan = who_has_plan();
        plan.case = "arp-unicast-request-reply".to_string();
        // The unicast difference: the request is addressed directly to the known
        // target MAC, not broadcast.
        plan.ethernet_destination = Some("00:00:5e:00:53:14".to_string());
        plan
    }

    #[test]
    fn unicast_who_has_targets_the_known_target_mac_not_broadcast() {
        let plan = unicast_plan();
        let packet = arp_who_has_packet(&plan).unwrap();

        let ethernet = packet.layer::<Ethernet>().expect("ethernet layer");
        // The Ethernet destination is the known target MAC, NOT broadcast.
        let target_mac = plan
            .validation
            .as_ref()
            .unwrap()
            .sender_hardware_addr
            .clone()
            .unwrap();
        assert_eq!(ethernet.destination().unwrap().to_string(), target_mac);
        assert_ne!(ethernet.destination().unwrap().to_string(), BROADCAST_MAC);
        assert_eq!(ethernet.source().unwrap().to_string(), "00:00:5e:00:53:0a");

        // compile() still fills the ARP ethertype; the ARP layer is a normal
        // who-has request (operation 1) resolving the target IPv4.
        let bytes = packet.compile().unwrap().into_bytes();
        assert_eq!(&bytes[12..14], &ETHERTYPE_ARP.to_be_bytes());
        let arp = packet.layer::<Arp>().expect("arp layer");
        assert_eq!(arp.opcode_value(), u16::from(ArpOperation::Request));
        assert_eq!(arp.target_ipv4().unwrap().to_string(), "10.64.0.20");
        assert_eq!(arp.target_mac().unwrap(), MacAddr::ZERO);
    }

    #[test]
    fn unicast_is_at_reply_passes_validation() {
        let plan = unicast_plan();
        let raw = is_at_frame(&plan);
        let packet = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();
        match validate_arp_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed, got {other:?}"),
        }
    }

    /// Build an `arp-padding-reply` plan: an ordinary broadcast who-has whose
    /// Ethernet frame is padded up to the 60-byte (sans FCS) minimum with
    /// trailing zero bytes.
    fn padding_plan() -> ProbePlan {
        let mut plan = who_has_plan();
        plan.case = "arp-padding-reply".to_string();
        plan.ethernet_min_frame_len = Some(60);
        plan.expected_request_frame_len = Some(60);
        plan
    }

    #[test]
    fn padding_who_has_is_padded_up_to_the_minimum_frame_length() {
        let plan = padding_plan();
        let packet = arp_who_has_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap().into_bytes();

        // The unpadded Ethernet/ARP frame is 42 bytes; the padded frame reaches
        // the 60-byte minimum the plan requested (the honored override survives
        // compile()).
        assert_eq!(bytes.len(), 60);
        // compile() still fills the ARP ethertype, and the trailing bytes after
        // the 42-byte Ethernet/ARP frame are the zero padding.
        assert_eq!(&bytes[12..14], &ETHERTYPE_ARP.to_be_bytes());
        assert!(bytes[42..].iter().all(|byte| *byte == 0));

        // The padding rides as a trailing Raw layer (an honored payload), and the
        // ARP layer is still an ordinary broadcast who-has.
        let raw = packet.layer::<Raw>().expect("trailing padding Raw layer");
        assert_eq!(raw.as_bytes().len(), 18);
        assert!(raw.as_bytes().iter().all(|byte| *byte == 0));
        let arp = packet.layer::<Arp>().expect("arp layer");
        assert_eq!(arp.opcode_value(), u16::from(ArpOperation::Request));
        assert_eq!(arp.target_ipv4().unwrap().to_string(), "10.64.0.20");
        let ethernet = packet.layer::<Ethernet>().expect("ethernet layer");
        assert_eq!(ethernet.destination().unwrap().to_string(), BROADCAST_MAC);
    }

    #[test]
    fn padded_who_has_decodes_back_with_padding_preserved_as_raw() {
        // A padded request frame round-trips: decoding the compiled padded frame
        // recovers the ARP layer and the trailing zero padding as a Raw layer
        // (decode preserves the set padding bytes, never dropping them).
        let plan = padding_plan();
        let packet = arp_who_has_packet(&plan).unwrap();
        let wire = packet.compile().unwrap().into_bytes();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &wire).unwrap();

        let arp = decoded.layer::<Arp>().expect("decoded arp layer");
        assert_eq!(arp.opcode_value(), u16::from(ArpOperation::Request));
        assert_eq!(arp.sender_ipv4().unwrap().to_string(), "10.64.0.10");
        assert_eq!(arp.target_ipv4().unwrap().to_string(), "10.64.0.20");
        let raw = decoded.layer::<Raw>().expect("decoded padding Raw layer");
        assert_eq!(raw.as_bytes().len(), 18);
        assert!(raw.as_bytes().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn padded_request_still_validates_the_is_at_reply() {
        // The point of the case: even with a padded request, the target's is-at
        // reply decodes and validates against the standard contract.
        let plan = padding_plan();
        let raw = is_at_frame(&plan);
        let packet = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();
        match validate_arp_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed, got {other:?}"),
        }
    }

    #[test]
    fn both_repeated_sends_resolve_the_same_target_and_pass_validation() {
        let parent = repeat_plan();
        let sends = parent.arp_sends.clone().unwrap();
        assert_eq!(sends.len(), 2);

        // Both sends resolve the same target, and the canonical is-at reply each
        // produces validates against its own derived single-send plan.
        let mut resolved_targets = Vec::new();
        for send in &sends {
            let derived = send_as_plan(&parent, send);
            resolved_targets.push(derived.target_protocol_addr.clone());
            let raw = is_at_frame(&derived);
            let packet = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();
            match validate_arp_candidate(&derived, &packet, &raw).unwrap() {
                CandidateValidation::Passed(_) => {}
                other => panic!("expected Passed, got {other:?}"),
            }
        }
        assert_eq!(resolved_targets[0], resolved_targets[1]);
    }
}
