//! UDP behavioral probe cases.
//!
//! `udp-echo-empty`, `udp-echo-short`, `udp-echo-binary`, `udp-echo-large`,
//! `udp-length-boundary-echo`, `udp-source-port-reflection`, and
//! `udp-multi-shot-order` send IPv4/UDP datagrams to a controlled target-side
//! UDP echo responder, then validate the decoded UDP response's peer tuple,
//! length, checksum status, and exact echoed payload. `udp-zero-checksum-ipv4`
//! uses the same echo path but explicitly sets the outgoing IPv4 UDP checksum to
//! zero so compile() override preservation is tested. `udp-options-surplus-echo`
//! appends deterministic UDP surplus/options after the conventional payload
//! length and validates the service still echoes that payload where the provider
//! supports delivery. `udp-closed-port-icmp` sends a UDP datagram to a verified-unbound
//! target port and validates the kernel ICMP destination-unreachable /
//! port-unreachable response plus the embedded original IPv4/UDP prefix.

use crafter::prelude::*;
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::common::{
    capture_filter, decode_hex, decoded_packet_json, failed_outcome, hex_bytes, observed_response,
    plan_json, raw_payload, required_str, required_u16, send_report_json, target_service_json,
    CandidateValidation, ExampleResult, ProbeOutcome, ProbePlan, StimulusEndpointRequest, UdpSend,
    FAILURE_DECODE_FAILED, FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD, FAILURE_WRONG_PEER,
};
use crate::icmp;

pub fn run_udp_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    if plan.case == "udp-closed-port-icmp" {
        return run_udp_closed_port_dry_run(request, plan);
    }
    if let Some(sends) = plan.udp_sends.as_deref() {
        return run_udp_multi_send_dry_run(request, plan, sends);
    }
    let packet = udp_packet(plan)?;
    let report = SocketSender::new(
        SendOptions::new()
            .iface(request.interface.clone())
            .network_layer()
            .dry_run(),
    )
    .send(&packet)?;
    let sent_raw = report.plan().bytes();
    let sent_raw_hex = hex_bytes(sent_raw);
    let sent_packet = Packet::decode_from_l3(NetworkLayer::Ipv4, sent_raw)?;
    let sent_decoded = decoded_packet_json(&sent_packet, sent_raw);
    let sent_udp_options = udp_options_json(sent_packet.layer::<UdpOptions>());
    let sent_udp_surplus_length = sent_udp_options
        .get("surplus_length")
        .cloned()
        .unwrap_or(Value::Null);
    let observed = observed_response(
        plan,
        false,
        None,
        json!({}),
        json!({
            "planned_only": true,
            "send_report": send_report_json(&report),
            "sent_raw_hex": sent_raw_hex,
            "sent_decoded": sent_decoded,
            "sent_udp_surplus_length": sent_udp_surplus_length,
            "sent_udp_options": sent_udp_options,
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
            "sent_decoded": sent_decoded,
            "sent_udp_surplus_length": sent_udp_surplus_length,
            "sent_udp_options": sent_udp_options,
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

pub fn run_udp_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    if plan.case == "udp-closed-port-icmp" {
        return run_udp_closed_port_live(request, plan);
    }
    if let Some(sends) = plan.udp_sends.as_deref() {
        return run_udp_multi_send_live(request, plan, sends);
    }
    let packet = udp_packet(plan)?;
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
        match validate_udp_candidate(plan, captured.packet(), captured.data())? {
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
                wrong_payload = Some(decoded);
            }
        }
    }

    if let Some(decoded) = wrong_payload {
        return Ok(failed_outcome(
            plan,
            FAILURE_WRONG_PAYLOAD,
            vec!["captured UDP echo response did not match expected payload".to_string()],
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
            vec!["captured UDP echo response did not match expected peer or ports".to_string()],
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
        vec!["timed out waiting for UDP echo response".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter(plan),
        })),
        sent,
        false,
    ))
}

fn run_udp_closed_port_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = udp_packet(plan)?;
    let report = SocketSender::new(
        SendOptions::new()
            .iface(request.interface.clone())
            .network_layer()
            .dry_run(),
    )
    .send(&packet)?;
    let sent_raw = report.plan().bytes();
    let sent_raw_hex = hex_bytes(sent_raw);
    let sent_decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, sent_raw)
        .map(|packet| decoded_packet_json(&packet, sent_raw))?;
    let embedded_prefix = expected_closed_port_embedded_prefix(request, plan, sent_raw)?;
    let observed = observed_response(
        plan,
        false,
        None,
        json!({}),
        json!({
            "planned_only": true,
            "send_report": send_report_json(&report),
            "sent_raw_hex": sent_raw_hex,
            "sent_decoded": sent_decoded,
            "capture_filter": capture_filter(plan),
            "target_service": target_service_json(plan),
            "expected_embedded_prefix_hex": hex_bytes(&embedded_prefix),
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
            "sent_decoded": sent_decoded,
            "capture_filter": capture_filter(plan),
            "target_service": target_service_json(plan),
            "expected_embedded_prefix_hex": hex_bytes(&embedded_prefix),
        }
    });
    Ok(ProbeOutcome {
        result,
        observed_response: observed,
        sent: false,
        received: false,
    })
}

fn run_udp_closed_port_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = udp_packet(plan)?;
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
    let embedded_prefix =
        expected_closed_port_embedded_prefix(request, plan, send_report.plan().bytes())?;
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
        match icmp::validate_ttl_expired_candidate(
            plan,
            captured.packet(),
            captured.data(),
            &embedded_prefix,
        )? {
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
                        "expected_embedded_prefix_hex": hex_bytes(&embedded_prefix),
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
                wrong_payload = Some(decoded);
            }
        }
    }

    if let Some(decoded) = wrong_payload {
        return Ok(failed_outcome(
            plan,
            FAILURE_WRONG_PAYLOAD,
            vec![
                "captured ICMP port unreachable did not include the expected embedded UDP packet prefix"
                    .to_string(),
            ],
            Some(json!({
                "send_report": send_report_json(&send_report),
                "decoded": decoded,
                "expected_embedded_prefix_hex": hex_bytes(&embedded_prefix),
            })),
            sent,
            true,
        ));
    }

    if let Some(decoded) = wrong_peer {
        return Ok(failed_outcome(
            plan,
            FAILURE_WRONG_PEER,
            vec![
                "captured ICMP port unreachable did not match expected target or destination"
                    .to_string(),
            ],
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
        vec!["timed out waiting for ICMP port unreachable".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter(plan),
            "expected_embedded_prefix_hex": hex_bytes(&embedded_prefix),
        })),
        sent,
        false,
    ))
}

/// Derive a single-send `ProbePlan` for one entry of `udp_sends`.
///
/// The derived plan keeps the parent's case name but clears the multi-send
/// marker and overrides the per-send tuple, sequence marker, payload, UDP length,
/// and checksum contract. The existing single-send UDP builder and validator can
/// then build, send, decode, and validate exactly this datagram.
fn send_as_plan(parent: &ProbePlan, send: &UdpSend) -> ProbePlan {
    let mut derived = parent.clone();
    derived.udp_sends = None;
    derived.send_count = None;
    if let Some(value) = send.sequence_marker.clone() {
        derived.sequence_marker = Some(value);
    }
    if let Some(value) = send.source_ipv4.clone() {
        derived.source_ipv4 = Some(value);
    }
    if let Some(value) = send.destination_ipv4.clone() {
        derived.destination_ipv4 = Some(value);
    }
    if let Some(value) = send.expected_reply_source_ipv4.clone() {
        derived.expected_reply_source_ipv4 = Some(value);
    }
    if let Some(value) = send.expected_reply_destination_ipv4.clone() {
        derived.expected_reply_destination_ipv4 = Some(value);
    }
    if let Some(value) = send.source_port {
        derived.source_port = Some(value);
    }
    if let Some(value) = send.destination_port {
        derived.destination_port = Some(value);
    }
    if let Some(value) = send.payload_hex.clone() {
        derived.payload_hex = Some(value);
    }
    if let Some(value) = send.payload_length {
        derived.payload_length = Some(value);
    }
    if let Some(value) = send.expected_payload_hex.clone() {
        derived.expected_payload_hex = Some(value);
    }
    if let Some(value) = send.expected_payload_length {
        derived.expected_payload_length = Some(value);
    }
    if let Some(value) = send.expected_udp_length {
        derived.expected_udp_length = Some(value);
    }
    if let Some(value) = send.expected_udp_checksum_present {
        derived.expected_udp_checksum_present = Some(value);
    }
    if let Some(value) = send.expected_udp_checksum_statuses.clone() {
        derived.expected_udp_checksum_statuses = Some(value);
    }
    derived
}

/// Dry-run a multi-shot UDP case: compile every ordered datagram with
/// libcrafter and emit one planned send plus one expected response per marker.
fn run_udp_multi_send_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
    sends: &[UdpSend],
) -> ExampleResult<ProbeOutcome> {
    let mut planned_sends = Vec::with_capacity(sends.len());
    for (offset, send) in sends.iter().enumerate() {
        let send_plan = send_as_plan(plan, send);
        let packet = udp_packet(&send_plan)?;
        let report = SocketSender::new(
            SendOptions::new()
                .iface(request.interface.clone())
                .network_layer()
                .dry_run(),
        )
        .send(&packet)?;
        let sent_raw = report.plan().bytes();
        let sent_raw_hex = hex_bytes(sent_raw);
        let sent_decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, sent_raw)
            .map(|packet| decoded_packet_json(&packet, sent_raw))?;
        planned_sends.push(json!({
            "index": send.index.unwrap_or(offset),
            "sequence_marker": send_plan.sequence_marker,
            "source_port": send_plan.source_port,
            "destination_port": send_plan.destination_port,
            "payload_hex": send_plan.payload_hex,
            "payload_length": send_plan.payload_length,
            "send_report": send_report_json(&report),
            "sent_raw_hex": sent_raw_hex,
            "sent_decoded": sent_decoded,
            "capture_filter": capture_filter(&send_plan),
            "expected_response": udp_expected_response_json(&send_plan),
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

/// Live multi-shot UDP case: send every ordered datagram, capture one echo
/// response per send, decode each response, and validate the peer tuple and
/// payload marker against that send. The aggregate report records every
/// observed response in send order.
fn run_udp_multi_send_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
    sends: &[UdpSend],
) -> ExampleResult<ProbeOutcome> {
    let mut send_results = Vec::with_capacity(sends.len());
    let mut all_passed = true;
    let mut any_sent = false;
    let mut any_received = false;
    let mut failure_reason: Option<&'static str> = None;
    let mut errors: Vec<String> = Vec::new();

    for (offset, send) in sends.iter().enumerate() {
        let send_plan = send_as_plan(plan, send);
        let outcome = run_udp_live(request, &send_plan)?;
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
                    "send {} ({:?}) failed: {reason}",
                    send.index.unwrap_or(offset),
                    send_plan.sequence_marker,
                ));
            }
        }
        let raw_hex = outcome
            .observed_response
            .get("raw_hex")
            .cloned()
            .unwrap_or(Value::Null);
        let decoded = outcome
            .observed_response
            .get("decoded")
            .cloned()
            .unwrap_or_else(|| json!({}));
        send_results.push(json!({
            "index": send.index.unwrap_or(offset),
            "sequence_marker": send_plan.sequence_marker,
            "payload_hex": send_plan.expected_payload_hex,
            "payload_length": send_plan.expected_payload_length,
            "status": status,
            "raw_hex": raw_hex,
            "decoded": decoded,
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
            vec!["one or more UDP multi-shot sends failed validation".to_string()]
        } else {
            errors
        },
        Some(summary),
        any_sent,
        any_received,
    ))
}

fn static_failure_reason(reason: &str) -> &'static str {
    match reason {
        FAILURE_TIMEOUT => FAILURE_TIMEOUT,
        FAILURE_WRONG_PEER => FAILURE_WRONG_PEER,
        FAILURE_DECODE_FAILED => FAILURE_DECODE_FAILED,
        _ => FAILURE_WRONG_PAYLOAD,
    }
}

fn udp_expected_response_json(send_plan: &ProbePlan) -> Value {
    json!({
        "source_ipv4": send_plan.expected_reply_source_ipv4,
        "destination_ipv4": send_plan.expected_reply_destination_ipv4,
        "source_port": send_plan.destination_port,
        "destination_port": send_plan.source_port,
        "sequence_marker": send_plan.sequence_marker,
        "payload_hex": send_plan.expected_payload_hex,
        "payload_length": send_plan.expected_payload_length,
        "udp_length": send_plan.expected_udp_length,
        "checksum_present": send_plan.expected_udp_checksum_present,
        "checksum_statuses": send_plan.expected_udp_checksum_statuses,
    })
}

pub fn sends_json(sends: Option<&[UdpSend]>) -> Value {
    match sends {
        Some(sends) => Value::Array(
            sends
                .iter()
                .map(|send| {
                    json!({
                        "index": send.index,
                        "sequence_marker": send.sequence_marker,
                        "source_ipv4": send.source_ipv4,
                        "destination_ipv4": send.destination_ipv4,
                        "expected_reply_source_ipv4": send.expected_reply_source_ipv4,
                        "expected_reply_destination_ipv4": send.expected_reply_destination_ipv4,
                        "source_port": send.source_port,
                        "destination_port": send.destination_port,
                        "payload_hex": send.payload_hex,
                        "payload_length": send.payload_length,
                        "expected_payload_hex": send.expected_payload_hex,
                        "expected_payload_length": send.expected_payload_length,
                        "expected_udp_length": send.expected_udp_length,
                        "expected_udp_checksum_present": send.expected_udp_checksum_present,
                        "expected_udp_checksum_statuses": send.expected_udp_checksum_statuses,
                        "capture_filter": send.capture_filter,
                        "validation": send.validation,
                    })
                })
                .collect(),
        ),
        None => Value::Null,
    }
}

pub fn ordered_sends_json(sends: Option<&[UdpSend]>) -> Value {
    match sends {
        Some(sends) => Value::Array(
            sends
                .iter()
                .map(|send| {
                    json!({
                        "index": send.index,
                        "sequence_marker": send.sequence_marker,
                        "payload_hex": send.payload_hex,
                        "payload_length": send.payload_length,
                    })
                })
                .collect(),
        ),
        None => Value::Null,
    }
}

pub fn udp_options_json(options: Option<&UdpOptions>) -> Value {
    let Some(options) = options else {
        return Value::Null;
    };
    let alignment = options.alignment_bytes();
    let alignment_length = alignment.map_or(0, |bytes| bytes.len());
    let option_checksum_length = if options.option_checksum_value().is_some() {
        2
    } else {
        0
    };
    let summaries: Vec<String> = options
        .options()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    json!({
        "status": udp_option_status_name(options.status()),
        "surplus_length": alignment_length + option_checksum_length + options.as_bytes().len(),
        "alignment_hex": alignment.map(hex_bytes),
        "alignment_length": alignment_length,
        "option_checksum": options.option_checksum_value(),
        "option_bytes_hex": hex_bytes(options.as_bytes()),
        "option_count": options.options().len(),
        "summary": summaries,
    })
}

pub fn udp_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    let source_port = required_u16(plan.source_port, "source_port")?;
    let destination_port = required_u16(plan.destination_port, "destination_port")?;
    let payload_hex = plan
        .payload_hex
        .as_deref()
        .ok_or_else(|| "probe plan missing required field payload_hex".to_string())?;
    let payload = decode_hex(payload_hex)?;
    let udp = Udp::new()
        .source_port(source_port)
        .destination_port(destination_port);
    let udp = if let Some(checksum) = plan.stimulus_udp_checksum {
        udp.checksum(checksum)
    } else {
        udp
    };
    let mut packet = Ipv4::new().src(source).dst(destination) / udp;
    if !payload.is_empty() {
        packet = packet / Raw::from_bytes(payload);
    }
    if let Some(options_hex) = plan.stimulus_udp_options_hex.as_deref() {
        let options = decode_hex(options_hex)?;
        packet = packet / UdpOptions::from_bytes(options);
    }
    Ok(packet)
}

pub fn validate_udp_candidate(
    plan: &ProbePlan,
    packet: &Packet,
    raw: &[u8],
) -> ExampleResult<CandidateValidation> {
    let Some(udp) = packet.layer::<Udp>() else {
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

    if udp.source_port_value() != expected_source_port {
        peer_mismatches.push(json!({
            "field": "udp.sport",
            "expected": expected_source_port,
            "actual": udp.source_port_value(),
        }));
    }
    if udp.destination_port_value() != expected_destination_port {
        peer_mismatches.push(json!({
            "field": "udp.dport",
            "expected": expected_destination_port,
            "actual": udp.destination_port_value(),
        }));
    }

    let decoded = decoded_packet_json(packet, raw);
    if !peer_mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPeer(json!({
            "packet": decoded,
            "mismatches": peer_mismatches,
        })));
    }

    let expected_payload_hex = plan
        .expected_payload_hex
        .as_deref()
        .or(plan.payload_hex.as_deref())
        .unwrap_or("");
    let expected_payload = decode_hex(expected_payload_hex)?;
    let actual_payload = udp_user_payload(packet, raw);
    let mut mismatches = Vec::new();

    if actual_payload.as_slice() != expected_payload.as_slice() {
        mismatches.push(json!({
            "field": "udp.payload",
            "expected": hex_bytes(&expected_payload),
            "actual": hex_bytes(&actual_payload),
        }));
    }

    let expected_payload_length = plan
        .expected_payload_length
        .unwrap_or(expected_payload.len());
    if actual_payload.len() != expected_payload_length {
        mismatches.push(json!({
            "field": "udp.payload_length",
            "expected": expected_payload_length,
            "actual": actual_payload.len(),
        }));
    }

    if let Some(expected_length) = plan.expected_udp_length {
        if udp.length_value() != Some(expected_length) {
            mismatches.push(json!({
                "field": "udp.length",
                "expected": expected_length,
                "actual": udp.length_value(),
            }));
        }
    }

    if plan.expected_udp_checksum_present.unwrap_or(false) && udp.checksum_value().is_none() {
        mismatches.push(json!({
            "field": "udp.checksum",
            "expected": "present",
            "actual": "missing",
        }));
    }

    let checksum_status = checksum_status_name(udp.checksum_status());
    if let Some(allowed) = plan.expected_udp_checksum_statuses.as_deref() {
        if !allowed.iter().any(|item| item == checksum_status) {
            mismatches.push(json!({
                "field": "udp.checksum_status",
                "expected": allowed,
                "actual": checksum_status,
            }));
        }
    } else if checksum_status == "invalid" {
        mismatches.push(json!({
            "field": "udp.checksum_status",
            "expected": "not invalid",
            "actual": checksum_status,
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

fn udp_user_payload(packet: &Packet, raw: &[u8]) -> Vec<u8> {
    let fallback = || raw_payload(packet).to_vec();
    let l3_offset = if packet.layer::<Ethernet>().is_some() && raw.len() >= 14 {
        14
    } else {
        0
    };
    if raw.len() < l3_offset + 20 {
        return fallback();
    }
    let first = raw[l3_offset];
    let version = first >> 4;
    let header_len = ((first & 0x0f) as usize) * 4;
    if version != 4 || header_len < 20 || raw.len() < l3_offset + header_len {
        return fallback();
    }
    let total_length = u16::from_be_bytes([raw[l3_offset + 2], raw[l3_offset + 3]]) as usize;
    if total_length < header_len || raw.len() < l3_offset + total_length {
        return fallback();
    }
    let udp_offset = l3_offset + header_len;
    let ip_end = l3_offset + total_length;
    if raw.len() < udp_offset + 8 || udp_offset + 8 > ip_end {
        return fallback();
    }
    let udp_length = u16::from_be_bytes([raw[udp_offset + 4], raw[udp_offset + 5]]) as usize;
    if udp_length < 8 || udp_offset + udp_length > ip_end {
        return fallback();
    }
    raw[udp_offset + 8..udp_offset + udp_length].to_vec()
}

pub const fn checksum_status_name(status: UdpChecksumStatus) -> &'static str {
    match status {
        UdpChecksumStatus::NotChecked => "not_checked",
        UdpChecksumStatus::Ipv4NoChecksum => "ipv4_no_checksum",
        UdpChecksumStatus::Valid => "valid",
        UdpChecksumStatus::Invalid => "invalid",
        UdpChecksumStatus::Ipv6ZeroChecksum => "ipv6_zero_checksum",
    }
}

fn expected_closed_port_embedded_prefix(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
    sent_raw: &[u8],
) -> ExampleResult<Vec<u8>> {
    let mut prefix = icmp::expected_embedded_prefix(plan, sent_raw)?;
    if wire_policy_bool(request, "transit_decrements_ipv4_ttl") {
        decrement_ipv4_ttl_and_update_checksum(&mut prefix);
    }
    Ok(prefix)
}

fn wire_policy_bool(request: &StimulusEndpointRequest, key: &str) -> bool {
    request
        .metadata
        .get("wire_policy")
        .and_then(Value::as_object)
        .and_then(|policy| policy.get(key))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn decrement_ipv4_ttl_and_update_checksum(prefix: &mut [u8]) {
    if prefix.len() < 20 {
        return;
    }
    let header_len = ((prefix[0] & 0x0f) as usize) * 4;
    if header_len < 20 || prefix.len() < header_len || prefix[8] == 0 {
        return;
    }
    prefix[8] = prefix[8].saturating_sub(1);
    prefix[10] = 0;
    prefix[11] = 0;
    let checksum = ipv4_header_checksum(&prefix[..header_len]);
    prefix[10] = (checksum >> 8) as u8;
    prefix[11] = checksum as u8;
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub const fn udp_option_status_name(status: UdpOptionStatus) -> &'static str {
    match status {
        UdpOptionStatus::NoSurplus => "no_surplus",
        UdpOptionStatus::NotParsed => "not_parsed",
        UdpOptionStatus::Valid => "valid",
        UdpOptionStatus::Ignored => "ignored",
        UdpOptionStatus::Malformed => "malformed",
        UdpOptionStatus::MalformedEnvelope => "malformed_envelope",
        UdpOptionStatus::NonzeroAfterEndOfList => "nonzero_after_end_of_list",
        UdpOptionStatus::TooManyNoOperations => "too_many_no_operations",
        UdpOptionStatus::Unsupported => "unsupported",
        UdpOptionStatus::UnsupportedFragmentation => "unsupported_fragmentation",
        UdpOptionStatus::UnknownSafe => "unknown_safe",
        UdpOptionStatus::UnknownUnsafe => "unknown_unsafe",
        UdpOptionStatus::OptionChecksumInvalid => "option_checksum_invalid",
        UdpOptionStatus::AdditionalPayloadChecksumInvalid => "additional_payload_checksum_invalid",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    fn echo_plan(case_name: &str, payload: &[u8]) -> ProbePlan {
        let mut plan = base_plan(case_name);
        plan.source_ipv4 = Some("192.0.2.10".to_string());
        plan.destination_ipv4 = Some("192.0.2.20".to_string());
        plan.expected_reply_source_ipv4 = Some("192.0.2.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("192.0.2.10".to_string());
        plan.source_port = Some(46000);
        plan.destination_port = Some(30000);
        plan.payload_hex = Some(hex_bytes(payload));
        plan.payload_length = Some(payload.len());
        plan.expected_payload_hex = Some(hex_bytes(payload));
        plan.expected_payload_length = Some(payload.len());
        plan.expected_udp_length = Some((8 + payload.len()) as u16);
        plan.expected_udp_checksum_present = Some(true);
        plan.expected_udp_checksum_statuses = Some(vec!["valid".to_string()]);
        plan
    }

    fn empty_echo_plan() -> ProbePlan {
        echo_plan("udp-echo-empty", &[])
    }

    fn short_echo_plan() -> ProbePlan {
        echo_plan("udp-echo-short", b"udp-echo:1234abcd")
    }

    fn binary_echo_plan() -> ProbePlan {
        echo_plan(
            "udp-echo-binary",
            &[0x00, 0x42, 0x7f, 0x80, 0xa5, 0xff, 0x01, 0x00, 0xc3, 0xfe],
        )
    }

    fn closed_port_request(metadata: Value) -> StimulusEndpointRequest {
        StimulusEndpointRequest {
            provider: "hetzner".to_string(),
            profile: "behavior".to_string(),
            seed: 1052,
            endpoint_role: "stimulus".to_string(),
            interface: "enp7s0".to_string(),
            local_ipv4: "10.0.25.10".to_string(),
            peer_ipv4: "10.0.25.20".to_string(),
            timeout_seconds: 3,
            probe_plans: Vec::new(),
            artifact_paths: Value::Null,
            metadata,
        }
    }

    #[test]
    fn closed_port_embedded_prefix_is_strict_without_wire_policy() {
        let mut plan = base_plan("udp-closed-port-icmp");
        plan.expected_embedded_prefix_length = Some(28);
        let request = closed_port_request(json!({}));
        let sent = decode_hex("45000052000100004011347d0a00190a0a001914cd3eaed8003ea765").unwrap();

        let prefix = expected_closed_port_embedded_prefix(&request, &plan, &sent).unwrap();

        assert_eq!(prefix, sent);
    }

    #[test]
    fn closed_port_embedded_prefix_honors_transit_ttl_policy() {
        let mut plan = base_plan("udp-closed-port-icmp");
        plan.expected_embedded_prefix_length = Some(28);
        let request = closed_port_request(json!({
            "wire_policy": {
                "transit_decrements_ipv4_ttl": true
            }
        }));
        let sent = decode_hex("45000052000100004011347d0a00190a0a001914cd3eaed8003ea765").unwrap();

        let prefix = expected_closed_port_embedded_prefix(&request, &plan, &sent).unwrap();

        assert_eq!(
            hex_bytes(&prefix),
            "45000052000100003f11357d0a00190a0a001914cd3eaed8003ea765"
        );
    }

    fn large_echo_plan() -> ProbePlan {
        let payload = (0..1200)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        echo_plan("udp-echo-large", &payload)
    }

    fn length_boundary_echo_plan() -> ProbePlan {
        let payload = (0..1371)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut plan = echo_plan("udp-length-boundary-echo", &payload);
        plan.expected_ipv4_total_length = Some(1399);
        plan
    }

    fn source_port_reflection_plan() -> ProbePlan {
        let mut plan = echo_plan("udp-source-port-reflection", b"udp-source-port:1234abcd");
        plan.source_port = Some(62044);
        plan
    }

    fn closed_port_plan() -> ProbePlan {
        let mut plan = echo_plan("udp-closed-port-icmp", b"udp-closed-port-icmp:1234abcd");
        plan.expected_response = Some("icmp_port_unreachable".to_string());
        plan.expected_icmp_type = Some(ICMP_DESTINATION_UNREACHABLE);
        plan.expected_icmp_code = Some(3);
        plan.expected_embedded_prefix_length = Some(28);
        plan
    }

    fn zero_checksum_ipv4_plan() -> ProbePlan {
        let mut plan = echo_plan("udp-zero-checksum-ipv4", b"udp-zero-checksum-ipv4:1234abcd");
        plan.stimulus_udp_checksum = Some(0);
        plan.stimulus_udp_checksum_override = Some(true);
        plan.stimulus_udp_checksum_policy = Some("ipv4_zero_checksum_override".to_string());
        plan.expected_udp_checksum_statuses =
            Some(vec!["valid".to_string(), "ipv4_no_checksum".to_string()]);
        plan
    }

    #[test]
    fn udp_echo_empty_packet_has_no_payload_and_udp_length_eight() {
        let packet = udp_packet(&empty_echo_plan()).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();

        assert_eq!(udp.source_port_value(), 46000);
        assert_eq!(udp.destination_port_value(), 30000);
        assert_eq!(udp.length_value(), Some(8));
        assert!(udp.checksum_value().is_some());
        assert!(decoded.layer::<Raw>().is_none());
    }

    #[test]
    fn validate_udp_candidate_accepts_empty_echo_response() {
        let plan = empty_echo_plan();
        let response = (Ipv4::new()
            .src("192.0.2.20".parse::<Ipv4Addr>().unwrap())
            .dst("192.0.2.10".parse::<Ipv4Addr>().unwrap())
            / Udp::new().source_port(30000).destination_port(46000))
        .compile()
        .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, response.as_bytes()).unwrap();

        let validation = validate_udp_candidate(&plan, &decoded, response.as_bytes()).unwrap();
        assert!(matches!(validation, CandidateValidation::Passed(_)));
    }

    #[test]
    fn validate_udp_candidate_ignores_link_padding_after_empty_echo() {
        let plan = empty_echo_plan();
        let response = (Ethernet::with_addresses(
            "00:00:5e:00:53:14".parse().unwrap(),
            "00:00:5e:00:53:0a".parse().unwrap(),
        ) / Ipv4::new()
            .src("192.0.2.20".parse::<Ipv4Addr>().unwrap())
            .dst("192.0.2.10".parse::<Ipv4Addr>().unwrap())
            / Udp::new().source_port(30000).destination_port(46000))
        .compile()
        .unwrap();
        let mut raw = response.into_bytes();
        raw.extend_from_slice(&[0u8; 18]);
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();

        assert_eq!(decoded.layer::<Udp>().unwrap().length_value(), Some(8));
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[0u8; 18]);
        let validation = validate_udp_candidate(&plan, &decoded, &raw).unwrap();
        assert!(matches!(validation, CandidateValidation::Passed(_)));
    }

    #[test]
    fn udp_echo_short_packet_carries_ascii_payload_and_udp_length() {
        let packet = udp_packet(&short_echo_plan()).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let payload = decoded.layer::<Raw>().unwrap();

        assert_eq!(udp.source_port_value(), 46000);
        assert_eq!(udp.destination_port_value(), 30000);
        assert_eq!(udp.length_value(), Some(25));
        assert!(udp.checksum_value().is_some());
        assert_eq!(payload.as_bytes(), b"udp-echo:1234abcd");
    }

    #[test]
    fn validate_udp_candidate_accepts_short_echo_response() {
        let plan = short_echo_plan();
        let response = (Ipv4::new()
            .src("192.0.2.20".parse::<Ipv4Addr>().unwrap())
            .dst("192.0.2.10".parse::<Ipv4Addr>().unwrap())
            / Udp::new().source_port(30000).destination_port(46000)
            / Raw::from("udp-echo:1234abcd"))
        .compile()
        .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, response.as_bytes()).unwrap();

        let validation = validate_udp_candidate(&plan, &decoded, response.as_bytes()).unwrap();
        assert!(matches!(validation, CandidateValidation::Passed(_)));
    }

    #[test]
    fn udp_echo_binary_packet_carries_zero_and_high_bit_payload() {
        let plan = binary_echo_plan();
        let expected_payload = decode_hex(plan.payload_hex.as_deref().unwrap()).unwrap();
        let packet = udp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let payload = decoded.layer::<Raw>().unwrap();

        assert_eq!(udp.source_port_value(), 46000);
        assert_eq!(udp.destination_port_value(), 30000);
        assert_eq!(
            udp.length_value(),
            Some((8 + expected_payload.len()) as u16)
        );
        assert!(udp.checksum_value().is_some());
        assert_eq!(payload.as_bytes(), expected_payload.as_slice());
        assert!(payload.as_bytes().contains(&0x00));
        assert!(payload.as_bytes().iter().any(|byte| *byte >= 0x80));
    }

    #[test]
    fn validate_udp_candidate_accepts_binary_echo_response() {
        let plan = binary_echo_plan();
        let payload = decode_hex(plan.payload_hex.as_deref().unwrap()).unwrap();
        let response = (Ipv4::new()
            .src("192.0.2.20".parse::<Ipv4Addr>().unwrap())
            .dst("192.0.2.10".parse::<Ipv4Addr>().unwrap())
            / Udp::new().source_port(30000).destination_port(46000)
            / Raw::from_bytes(payload))
        .compile()
        .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, response.as_bytes()).unwrap();

        let validation = validate_udp_candidate(&plan, &decoded, response.as_bytes()).unwrap();
        assert!(matches!(validation, CandidateValidation::Passed(_)));
    }

    #[test]
    fn validate_udp_candidate_rejects_wrong_reflected_destination_port() {
        let plan = source_port_reflection_plan();
        let response = (Ipv4::new()
            .src("192.0.2.20".parse::<Ipv4Addr>().unwrap())
            .dst("192.0.2.10".parse::<Ipv4Addr>().unwrap())
            / Udp::new().source_port(30000).destination_port(46000)
            / Raw::from("udp-source-port:1234abcd"))
        .compile()
        .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, response.as_bytes()).unwrap();

        let validation = validate_udp_candidate(&plan, &decoded, response.as_bytes()).unwrap();
        assert!(matches!(validation, CandidateValidation::WrongPeer(_)));
    }

    #[test]
    fn udp_echo_large_packet_stays_under_private_mtu_safety_limit() {
        let plan = large_echo_plan();
        let expected_payload = decode_hex(plan.payload_hex.as_deref().unwrap()).unwrap();
        let packet = udp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let payload = decoded.layer::<Raw>().unwrap();

        assert_eq!(expected_payload.len(), 1200);
        assert_eq!(bytes.as_bytes().len(), 1228);
        assert!(bytes.as_bytes().len() < 1400);
        assert_eq!(udp.length_value(), Some(1208));
        assert_eq!(payload.as_bytes(), expected_payload.as_slice());
        assert!(udp.checksum_value().is_some());
    }

    #[test]
    fn udp_length_boundary_packet_sets_udp_length_below_safety_limit() {
        let plan = length_boundary_echo_plan();
        let expected_payload = decode_hex(plan.payload_hex.as_deref().unwrap()).unwrap();
        let packet = udp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let payload = decoded.layer::<Raw>().unwrap();

        assert_eq!(expected_payload.len(), 1371);
        assert_eq!(bytes.as_bytes().len(), 1399);
        assert!(bytes.as_bytes().len() < 1400);
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[2], bytes.as_bytes()[3]]),
            1399
        );
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[24], bytes.as_bytes()[25]]),
            1379
        );
        assert_eq!(udp.length_value(), Some(1379));
        assert_eq!(payload.as_bytes(), expected_payload.as_slice());
        assert!(udp.checksum_value().is_some());
    }

    #[test]
    fn validate_udp_candidate_accepts_length_boundary_echo_response() {
        let plan = length_boundary_echo_plan();
        let payload = decode_hex(plan.payload_hex.as_deref().unwrap()).unwrap();
        let response = (Ipv4::new()
            .src("192.0.2.20".parse::<Ipv4Addr>().unwrap())
            .dst("192.0.2.10".parse::<Ipv4Addr>().unwrap())
            / Udp::new().source_port(30000).destination_port(46000)
            / Raw::from_bytes(payload))
        .compile()
        .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, response.as_bytes()).unwrap();

        let validation = validate_udp_candidate(&plan, &decoded, response.as_bytes()).unwrap();
        assert!(matches!(validation, CandidateValidation::Passed(_)));
    }

    #[test]
    fn validate_udp_candidate_rejects_payload_mismatch() {
        let plan = empty_echo_plan();
        let response = (Ipv4::new()
            .src("192.0.2.20".parse::<Ipv4Addr>().unwrap())
            .dst("192.0.2.10".parse::<Ipv4Addr>().unwrap())
            / Udp::new().source_port(30000).destination_port(46000)
            / Raw::from("x"))
        .compile()
        .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, response.as_bytes()).unwrap();

        let validation = validate_udp_candidate(&plan, &decoded, response.as_bytes()).unwrap();
        assert!(matches!(validation, CandidateValidation::WrongPayload(_)));
    }

    #[test]
    fn udp_closed_port_packet_carries_udp_payload_prefix() {
        let plan = closed_port_plan();
        let packet = udp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let payload = decoded.layer::<Raw>().unwrap();

        assert_eq!(udp.source_port_value(), 46000);
        assert_eq!(udp.destination_port_value(), 30000);
        assert_eq!(udp.length_value(), Some(37));
        assert_eq!(payload.as_bytes(), b"udp-closed-port-icmp:1234abcd");
        assert_eq!(
            icmp::expected_embedded_prefix(&plan, bytes.as_bytes()).unwrap(),
            bytes.as_bytes()[..28].to_vec()
        );
    }

    #[test]
    fn udp_closed_port_accepts_icmp_port_unreachable_embedded_prefix() {
        let plan = closed_port_plan();
        let sent = udp_packet(&plan).unwrap().compile().unwrap();
        let embedded_prefix = icmp::expected_embedded_prefix(&plan, sent.as_bytes()).unwrap();
        let response = (Ipv4::new()
            .src("192.0.2.20".parse::<Ipv4Addr>().unwrap())
            .dst("192.0.2.10".parse::<Ipv4Addr>().unwrap())
            / Icmpv4::destination_unreachable().code(3)
            / Raw::from_bytes(embedded_prefix.clone()))
        .compile()
        .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, response.as_bytes()).unwrap();

        let validation = icmp::validate_ttl_expired_candidate(
            &plan,
            &decoded,
            response.as_bytes(),
            &embedded_prefix,
        )
        .unwrap();
        assert!(matches!(validation, CandidateValidation::Passed(_)));
    }

    #[test]
    fn udp_zero_checksum_ipv4_packet_preserves_zero_checksum_override() {
        let packet = udp_packet(&zero_checksum_ipv4_plan()).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let payload = decoded.layer::<Raw>().unwrap();

        assert_eq!(udp.source_port_value(), 46000);
        assert_eq!(udp.destination_port_value(), 30000);
        assert_eq!(udp.length_value(), Some(39));
        assert_eq!(udp.checksum_value(), Some(0));
        assert_eq!(
            checksum_status_name(udp.checksum_status()),
            "ipv4_no_checksum"
        );
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[26], bytes.as_bytes()[27]]),
            0
        );
        assert_eq!(payload.as_bytes(), b"udp-zero-checksum-ipv4:1234abcd");
    }
}
