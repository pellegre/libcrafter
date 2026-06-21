//! DNS probe case `dns-query`: send a DNS query over UDP and validate the
//! decoded UDP/DNS response (peer, ports, transaction id, response flag,
//! response code, question, and answer content).

use crafter::prelude::*;
use serde_json::{json, Value};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::common::{
    capture_filter, captured_data, decode_hex, decoded_packet_json, failed_outcome, hex_bytes,
    observed_response, open_capture_sniffer, plan_json, required_str, required_u16,
    send_report_json, target_service_json, CandidateValidation, DnsSend, EdnsOptionExpectation,
    ExampleResult, ProbeOutcome, ProbePlan, StimulusEndpointRequest, FAILURE_DECODE_FAILED,
    FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD, FAILURE_WRONG_PEER,
};

pub fn run_dns_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    if let Some(sends) = plan.sends.as_deref() {
        return run_dns_multi_send_dry_run(request, plan, sends);
    }
    let packet = dns_packet(plan)?;
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

pub fn run_dns_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    if let Some(sends) = plan.sends.as_deref() {
        return run_dns_multi_send_live(request, plan, sends);
    }
    let packet = dns_packet(plan)?;
    let timeout = Duration::from_secs(request.timeout_seconds.max(1));
    let mut sniffer =
        match open_capture_sniffer(request.interface.clone(), timeout, 64, capture_filter(plan)) {
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
    while let Some(captured) = match sniffer.next_record() {
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
        match validate_dns_candidate(plan, captured.packet(), captured_data(&captured))? {
            CandidateValidation::Ignore => {}
            CandidateValidation::Passed(decoded) => {
                let raw_hex = hex_bytes(captured_data(&captured));
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
            vec!["captured DNS response did not match expected question or answer".to_string()],
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
            vec!["captured DNS response did not match expected peer or ports".to_string()],
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
        vec!["timed out waiting for DNS response".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter(plan),
        })),
        sent,
        false,
    ))
}

/// Derive a single-send `ProbePlan` from a parent multi-send plan and one of its
/// `sends` entries. The derived plan reuses the parent's case and shared fields
/// but overrides the per-send transaction id, source port, query name, peer
/// addresses, expected answer, and capture filter so the existing single-send
/// builders (`dns_packet`, `validate_dns_candidate`) operate on exactly this one
/// send and its own expected response.
fn send_as_plan(parent: &ProbePlan, send: &DnsSend) -> ProbePlan {
    let mut derived = parent.clone();
    // This send is a single, self-contained query; clear the multi-send markers
    // so the single-send build/validate path runs against just this send.
    derived.sends = None;
    derived.send_count = None;
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
    if let Some(value) = send.query_id {
        derived.query_id = Some(value);
    }
    if let Some(value) = send.query_name.clone() {
        derived.query_name = Some(value);
    }
    if let Some(value) = send.query_type.clone() {
        derived.query_type = Some(value);
    }
    if let Some(value) = send.query_type_value {
        derived.query_type_value = Some(value);
    }
    if let Some(value) = send.query_class_value {
        derived.query_class_value = Some(value);
    }
    if let Some(value) = send.expected_answer_name.clone() {
        derived.expected_answer_name = Some(value);
    }
    if let Some(value) = send.expected_answer_type.clone() {
        derived.expected_answer_type = Some(value);
    }
    if let Some(value) = send.expected_answer_type_value {
        derived.expected_answer_type_value = Some(value);
    }
    if let Some(value) = send.expected_answer_data.clone() {
        derived.expected_answer_data = Some(value);
    }
    if let Some(value) = send.expected_answer_count {
        derived.expected_answer_count = Some(value);
    }
    if let Some(value) = send.expected_response_code {
        derived.expected_response_code = Some(value);
    }
    if let Some(value) = send.answer_ttl {
        derived.answer_ttl = Some(value);
    }
    derived
}

/// Dry-run a multi-send DNS case (`dns-repeat-transaction`): compile every
/// per-send stimulus packet with libcrafter and emit one planned send and one
/// expected response per send. No traffic leaves the host. The output carries a
/// `planned_sends` array (one entry per build) and a top-level `send_count` so an
/// inspector sees two planned sends and two expected responses.
fn run_dns_multi_send_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
    sends: &[DnsSend],
) -> ExampleResult<ProbeOutcome> {
    let mut planned_sends = Vec::with_capacity(sends.len());
    for (offset, send) in sends.iter().enumerate() {
        let send_plan = send_as_plan(plan, send);
        let packet = dns_packet(&send_plan)?;
        let report = SocketSender::new(
            SendOptions::new()
                .iface(request.interface.clone())
                .network_layer()
                .dry_run(),
        )
        .send(&packet)?;
        let sent_raw_hex = hex_bytes(report.plan().bytes());
        planned_sends.push(json!({
            "index": send.index.unwrap_or(offset),
            "query_id": send_plan.query_id,
            "source_port": send_plan.source_port,
            "destination_port": send_plan.destination_port,
            "query_name": send_plan.query_name,
            "expected_answer_data": send_plan.expected_answer_data,
            "answer_ttl": send_plan.answer_ttl,
            "send_report": send_report_json(&report),
            "sent_raw_hex": sent_raw_hex,
            "capture_filter": capture_filter(&send_plan),
            "expected_response": dns_expected_response_json(&send_plan),
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

/// Live multi-send DNS case (`dns-repeat-transaction`): build and send every
/// per-send libcrafter query, capture the responses, decode each, and validate
/// every response against *its* send's id, source port, and expected answer.
/// Each send opens its own capture filtered to its source port, so two responses
/// that share a query name are never confused — every response is matched to the
/// send that produced it. The case passes only when every send validates.
fn run_dns_multi_send_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
    sends: &[DnsSend],
) -> ExampleResult<ProbeOutcome> {
    let mut send_results = Vec::with_capacity(sends.len());
    let mut all_passed = true;
    let mut any_sent = false;
    let mut any_received = false;
    let mut failure_reason: Option<&'static str> = None;
    let mut errors: Vec<String> = Vec::new();

    for (offset, send) in sends.iter().enumerate() {
        let send_plan = send_as_plan(plan, send);
        let outcome = run_dns_live(request, &send_plan)?;
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
                    "send {} (source port {:?}) failed: {reason}",
                    send.index.unwrap_or(offset),
                    send_plan.source_port,
                ));
            }
        }
        send_results.push(json!({
            "index": send.index.unwrap_or(offset),
            "query_id": send_plan.query_id,
            "source_port": send_plan.source_port,
            "expected_answer_data": send_plan.expected_answer_data,
            "status": status,
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
            vec!["one or more repeat-transaction sends failed validation".to_string()]
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

/// JSON view of one send's expected response (peer/ports, transaction id, the
/// QR/rcode flags, the question, and the A answer) for the dry-run report.
fn dns_expected_response_json(send_plan: &ProbePlan) -> Value {
    json!({
        "source_ipv4": send_plan.expected_reply_source_ipv4,
        "destination_ipv4": send_plan.expected_reply_destination_ipv4,
        "source_port": send_plan.destination_port,
        "destination_port": send_plan.source_port,
        "query_id": send_plan.query_id,
        "qr": true,
        "response_code": send_plan.expected_response_code.unwrap_or(0),
        "question": {
            "name": send_plan.query_name,
            "type": send_plan.query_type,
            "type_value": send_plan.query_type_value,
        },
        "answer": {
            "name": send_plan.expected_answer_name,
            "type": send_plan.expected_answer_type,
            "data": send_plan.expected_answer_data,
            "ttl": send_plan.answer_ttl,
        },
    })
}

/// JSON view of a plan's `sends` array for the plan echo. `None` renders null.
pub fn sends_json(sends: Option<&[DnsSend]>) -> Value {
    match sends {
        Some(sends) => Value::Array(
            sends
                .iter()
                .map(|send| {
                    json!({
                        "index": send.index,
                        "source_ipv4": send.source_ipv4,
                        "destination_ipv4": send.destination_ipv4,
                        "expected_reply_source_ipv4": send.expected_reply_source_ipv4,
                        "expected_reply_destination_ipv4": send.expected_reply_destination_ipv4,
                        "source_port": send.source_port,
                        "destination_port": send.destination_port,
                        "query_id": send.query_id,
                        "query_name": send.query_name,
                        "query_type": send.query_type,
                        "query_type_value": send.query_type_value,
                        "expected_answer_name": send.expected_answer_name,
                        "expected_answer_type": send.expected_answer_type,
                        "expected_answer_data": send.expected_answer_data,
                        "expected_answer_count": send.expected_answer_count,
                        "expected_response_code": send.expected_response_code,
                        "answer_ttl": send.answer_ttl,
                        "capture_filter": send.capture_filter,
                    })
                })
                .collect(),
        ),
        None => Value::Null,
    }
}

/// JSON view of a plan's `sends` for the responder zone's `repeat_transaction`
/// descriptor: just the per-send source port and the A answer that port expects.
pub fn repeat_sends_json(sends: Option<&[DnsSend]>) -> Value {
    match sends {
        Some(sends) => Value::Array(
            sends
                .iter()
                .map(|send| {
                    json!({
                        "source_port": send.source_port,
                        "answer_data": send.expected_answer_data,
                        "answer_ttl": send.answer_ttl,
                    })
                })
                .collect(),
        ),
        None => Value::Null,
    }
}

pub fn validate_dns_candidate(
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

    let Some(dns) = packet.layer::<Dns>() else {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": [{
                "field": "dns",
                "expected": "present",
                "actual": "missing",
            }],
        })));
    };

    let expected_query_id = required_u16(plan.query_id, "query_id")?;
    let expected_qname =
        canonical_dns_name(required_str(plan.query_name.as_deref(), "query_name")?);
    let expected_qtype = dns_type_value(plan)?;
    let expected_qclass = plan.query_class_value.unwrap_or(DNS_CLASS_IN);
    let expected_rcode = plan.expected_response_code.unwrap_or(0);
    let mut mismatches = Vec::new();

    if dns.id_value() != expected_query_id {
        mismatches.push(json!({
            "field": "dns.id",
            "expected": expected_query_id,
            "actual": dns.id_value(),
        }));
    }
    if !dns.is_response() {
        mismatches.push(json!({
            "field": "dns.qr",
            "expected": true,
            "actual": false,
        }));
    }
    let actual_rcode = (dns.flags_value() & 0x000f) as u8;
    if actual_rcode != expected_rcode {
        mismatches.push(json!({
            "field": "dns.rcode",
            "expected": expected_rcode,
            "actual": actual_rcode,
        }));
    }

    match dns.questions().first() {
        Some(question) => {
            if question.name() != expected_qname {
                mismatches.push(json!({
                    "field": "dns.question.name",
                    "expected": expected_qname,
                    "actual": question.name(),
                }));
            }
            if question.question_type() != expected_qtype {
                mismatches.push(json!({
                    "field": "dns.question.type",
                    "expected": expected_qtype,
                    "actual": question.question_type(),
                }));
            }
            if question.question_class() != expected_qclass {
                mismatches.push(json!({
                    "field": "dns.question.class",
                    "expected": expected_qclass,
                    "actual": question.question_class(),
                }));
            }
        }
        None => mismatches.push(json!({
            "field": "dns.question",
            "expected": "present",
            "actual": "missing",
        })),
    }

    // Negative responses (NXDOMAIN) carry no answer record, so the terminal
    // answer match only runs when an answer is expected. The empty answer
    // section is enforced by `expected_answer_count` (0) below; rcode 3, the QR
    // flag, transaction id, and the preserved question are checked above.
    if let Some(expected_answer_data) = plan.expected_answer_data.as_deref() {
        let expected_answer_name = canonical_dns_name(required_str(
            plan.expected_answer_name.as_deref(),
            "expected_answer_name",
        )?);
        let expected_answer_type = plan.expected_answer_type_value.unwrap_or(expected_qtype);
        let matching_answer = dns.answers().iter().find(|answer| {
            answer.name() == expected_answer_name
                && answer.record_type() == expected_answer_type
                && dns_record_data_matches(answer.data(), expected_answer_data)
        });
        if matching_answer.is_none() {
            mismatches.push(json!({
                "field": "dns.answer",
                "expected": {
                    "name": expected_answer_name,
                    "type": expected_answer_type,
                    "data": expected_answer_data,
                },
                "actual": dns_answers_json(dns),
            }));
        }
    }

    // TXT answers carry variable-length RDATA: a list of DNS character-strings.
    // The contract validates the answer owner name, type (16), class, the full
    // ordered list of decoded character-strings, and the TTL. Comparing the whole
    // list (not just "any string matches") is what exercises the string-length
    // encoding/decoding and preserves ordering.
    if let Some(expected_txt) = plan.expected_txt_strings.as_ref() {
        let expected_answer_name = canonical_dns_name(required_str(
            plan.expected_answer_name.as_deref(),
            "expected_answer_name",
        )?);
        let expected_answer_type = plan.expected_answer_type_value.unwrap_or(DNS_TYPE_TXT);
        let expected_answer_class = plan.query_class_value.unwrap_or(DNS_CLASS_IN);
        let expected_strings: Vec<Vec<u8>> = expected_txt
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        let matching_answer = dns.answers().iter().find(|answer| {
            answer.name() == expected_answer_name
                && answer.record_type() == expected_answer_type
                && answer.class() == expected_answer_class
                && dns_txt_strings(answer.data()).as_deref() == Some(expected_strings.as_slice())
        });
        match matching_answer {
            Some(answer) => {
                if let Some(expected_ttl) = plan.answer_ttl {
                    if answer.ttl() != expected_ttl {
                        mismatches.push(json!({
                            "field": "dns.answer.ttl",
                            "expected": expected_ttl,
                            "actual": answer.ttl(),
                        }));
                    }
                }
            }
            None => mismatches.push(json!({
                "field": "dns.answer",
                "expected": {
                    "name": expected_answer_name,
                    "type": expected_answer_type,
                    "class": expected_answer_class,
                    "txt_strings": expected_txt,
                },
                "actual": dns_answers_json(dns),
            })),
        }
    }

    // MX answers carry composite RDATA: a 16-bit preference followed by the
    // exchange <domain-name>. The contract validates the answer owner name,
    // type (15), class, the decoded structured preference and exchange name, and
    // the TTL. Comparing the decoded preference (a u16) and exchange (a domain
    // name) separately is what exercises the crate's MX RDATA decode rather than
    // a flat byte comparison.
    if let Some(expected_preference) = plan.expected_mx_preference {
        let expected_exchange = canonical_dns_name(required_str(
            plan.expected_mx_exchange.as_deref(),
            "expected_mx_exchange",
        )?);
        let expected_answer_name = canonical_dns_name(required_str(
            plan.expected_answer_name.as_deref(),
            "expected_answer_name",
        )?);
        let expected_answer_type = plan.expected_answer_type_value.unwrap_or(DNS_TYPE_MX);
        let expected_answer_class = plan.query_class_value.unwrap_or(DNS_CLASS_IN);
        let matching_answer = dns.answers().iter().find(|answer| {
            answer.name() == expected_answer_name
                && answer.record_type() == expected_answer_type
                && answer.class() == expected_answer_class
                && dns_mx_fields(answer.data()).is_some_and(|(preference, exchange)| {
                    preference == expected_preference
                        && canonical_dns_name(&exchange) == expected_exchange
                })
        });
        match matching_answer {
            Some(answer) => {
                if let Some(expected_ttl) = plan.answer_ttl {
                    if answer.ttl() != expected_ttl {
                        mismatches.push(json!({
                            "field": "dns.answer.ttl",
                            "expected": expected_ttl,
                            "actual": answer.ttl(),
                        }));
                    }
                }
            }
            None => mismatches.push(json!({
                "field": "dns.answer",
                "expected": {
                    "name": expected_answer_name,
                    "type": expected_answer_type,
                    "class": expected_answer_class,
                    "preference": expected_preference,
                    "exchange": expected_exchange,
                },
                "actual": dns_answers_json(dns),
            })),
        }
    }

    // SRV answers carry composite RDATA: three 16-bit fields (priority, weight,
    // service port) followed by the target <domain-name>. The contract validates
    // the answer owner name, type (33), class, every decoded structured field
    // (priority, weight, port, and target name) separately, and the TTL.
    // Comparing the decoded numeric fields and the target domain name
    // individually is what exercises the crate's SRV RDATA decode rather than a
    // flat byte comparison.
    if let Some(expected_priority) = plan.expected_srv_priority {
        let expected_weight = required_u16(plan.expected_srv_weight, "expected_srv_weight")?;
        let expected_port = required_u16(plan.expected_srv_port, "expected_srv_port")?;
        let expected_target = canonical_dns_name(required_str(
            plan.expected_srv_target.as_deref(),
            "expected_srv_target",
        )?);
        let expected_answer_name = canonical_dns_name(required_str(
            plan.expected_answer_name.as_deref(),
            "expected_answer_name",
        )?);
        let expected_answer_type = plan.expected_answer_type_value.unwrap_or(DNS_TYPE_SRV);
        let expected_answer_class = plan.query_class_value.unwrap_or(DNS_CLASS_IN);
        let matching_answer = dns.answers().iter().find(|answer| {
            answer.name() == expected_answer_name
                && answer.record_type() == expected_answer_type
                && answer.class() == expected_answer_class
                && dns_srv_fields(answer.data()).is_some_and(|(priority, weight, port, target)| {
                    priority == expected_priority
                        && weight == expected_weight
                        && port == expected_port
                        && canonical_dns_name(&target) == expected_target
                })
        });
        match matching_answer {
            Some(answer) => {
                if let Some(expected_ttl) = plan.answer_ttl {
                    if answer.ttl() != expected_ttl {
                        mismatches.push(json!({
                            "field": "dns.answer.ttl",
                            "expected": expected_ttl,
                            "actual": answer.ttl(),
                        }));
                    }
                }
            }
            None => mismatches.push(json!({
                "field": "dns.answer",
                "expected": {
                    "name": expected_answer_name,
                    "type": expected_answer_type,
                    "class": expected_answer_class,
                    "priority": expected_priority,
                    "weight": expected_weight,
                    "port": expected_port,
                    "target": expected_target,
                },
                "actual": dns_answers_json(dns),
            })),
        }
    }

    // Multi-answer chain cases (the CNAME chain) additionally require a specific
    // non-terminal answer (the CNAME whose RDATA is the canonical domain name)
    // and an exact answer count, so a response that decoded the terminal A but
    // dropped or mangled the CNAME RDATA still fails the payload check. The
    // original question is already validated above and stays untouched.
    if let Some(expected_cname) = plan.expected_cname_answer.as_ref() {
        let expected_cname_name = canonical_dns_name(&expected_cname.name);
        let expected_cname_type = expected_cname.type_value.unwrap_or(DNS_TYPE_CNAME);
        let matching_cname = dns.answers().iter().find(|answer| {
            answer.name() == expected_cname_name
                && answer.record_type() == expected_cname_type
                && dns_record_data_matches(answer.data(), &expected_cname.data)
        });
        if matching_cname.is_none() {
            mismatches.push(json!({
                "field": "dns.cname_answer",
                "expected": {
                    "name": expected_cname_name,
                    "type": expected_cname_type,
                    "data": expected_cname.data,
                },
                "actual": dns_answers_json(dns),
            }));
        }
    }

    // EDNS(0) cases require a decoded OPT pseudo-record (RFC 6891) in the
    // response's additional section. The contract validates each EDNS field
    // separately out of the OPT record: the requestor UDP payload size (OPT
    // CLASS), the extended RCODE, EDNS version, and DO flag (packed in the OPT
    // TTL), and the ordered option list (each {code, data} preserved verbatim).
    // Reading these from the typed OPT getters is what exercises the crate's OPT
    // decode rather than treating the additional record as trailing bytes.
    if let Some(expected_payload_size) = plan.expected_edns_udp_payload_size {
        let expected_version = plan.expected_edns_version.unwrap_or(0);
        let expected_extended_rcode = plan.expected_edns_extended_rcode.unwrap_or(0);
        let expected_do = plan.expected_edns_do.unwrap_or(false);
        let expected_options = edns_options_from_plan(plan.expected_edns_options.as_deref())?;
        match dns.additionals().iter().find(|record| record.is_opt()) {
            Some(opt) => {
                if opt.name() != "." {
                    mismatches.push(json!({
                        "field": "dns.opt.name",
                        "expected": ".",
                        "actual": opt.name(),
                    }));
                }
                if opt.edns_udp_payload_size() != expected_payload_size {
                    mismatches.push(json!({
                        "field": "dns.opt.udp_payload_size",
                        "expected": expected_payload_size,
                        "actual": opt.edns_udp_payload_size(),
                    }));
                }
                if opt.edns_version() != expected_version {
                    mismatches.push(json!({
                        "field": "dns.opt.version",
                        "expected": expected_version,
                        "actual": opt.edns_version(),
                    }));
                }
                if opt.edns_extended_rcode() != expected_extended_rcode {
                    mismatches.push(json!({
                        "field": "dns.opt.extended_rcode",
                        "expected": expected_extended_rcode,
                        "actual": opt.edns_extended_rcode(),
                    }));
                }
                if opt.edns_dnssec_ok() != expected_do {
                    mismatches.push(json!({
                        "field": "dns.opt.do",
                        "expected": expected_do,
                        "actual": opt.edns_dnssec_ok(),
                    }));
                }
                let actual_options = opt.edns_options().unwrap_or(&[]);
                let options_match = actual_options.len() == expected_options.len()
                    && actual_options.iter().zip(expected_options.iter()).all(
                        |(actual, expected)| {
                            actual.code() == expected.code() && actual.data() == expected.data()
                        },
                    );
                if !options_match {
                    mismatches.push(json!({
                        "field": "dns.opt.options",
                        "expected": edns_options_json(plan.expected_edns_options.as_deref()),
                        "actual": dns_opt_options_json(actual_options),
                    }));
                }
            }
            None => mismatches.push(json!({
                "field": "dns.opt",
                "expected": "present",
                "actual": "missing",
                "additionals": dns_additionals_json(dns),
            })),
        }
    }

    if let Some(expected_count) = plan.expected_answer_count {
        let actual_count = dns.answers().len();
        if actual_count != expected_count {
            mismatches.push(json!({
                "field": "dns.answer_count",
                "expected": expected_count,
                "actual": actual_count,
            }));
        }
    }

    if !mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": mismatches,
        })));
    }

    Ok(CandidateValidation::Passed(decoded))
}

pub fn dns_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    let source_port = required_u16(plan.source_port, "source_port")?;
    let destination_port = required_u16(plan.destination_port, "destination_port")?;
    let query_id = required_u16(plan.query_id, "query_id")?;
    let query_name = required_str(plan.query_name.as_deref(), "query_name")?;
    let query_type = dns_type_value(plan)?;
    let mut dns = Dns::query(query_name, query_type).id(query_id);
    // EDNS(0) cases carry an OPT pseudo-record in the query's additional section
    // (RFC 6891): the requestor's UDP payload size plus an optional option list.
    if let Some(udp_payload_size) = plan.edns_udp_payload_size {
        let options = edns_options_from_plan(plan.edns_request_options.as_deref())?;
        let version = plan.edns_version.unwrap_or(0);
        let dnssec_ok = plan.edns_do.unwrap_or(false);
        dns = dns.additional(DnsRecord::opt(
            udp_payload_size,
            0,
            version,
            dnssec_ok,
            options,
        ));
    }
    Ok(Ipv4::new().src(source).dst(destination)
        / Udp::new().sport(source_port).dport(destination_port)
        / dns)
}

/// Decode a plan's EDNS option expectations into crate `EdnsOption`s.
///
/// Each entry carries an IANA option code plus opaque OPTION-DATA bytes (hex);
/// the bytes are preserved verbatim per RFC 6891 Section 6.1.2.
pub fn edns_options_from_plan(
    options: Option<&[EdnsOptionExpectation]>,
) -> ExampleResult<Vec<EdnsOption>> {
    let mut decoded = Vec::new();
    for option in options.unwrap_or(&[]) {
        let data = if option.data_hex.is_empty() {
            Vec::new()
        } else {
            decode_hex(&option.data_hex)?
        };
        decoded.push(EdnsOption::new(option.code, data));
    }
    Ok(decoded)
}

/// JSON view of a plan's EDNS option expectations (code plus hex data) for the
/// dry-run report and plan echo. `None` renders as JSON null.
pub fn edns_options_json(options: Option<&[EdnsOptionExpectation]>) -> Value {
    match options {
        Some(options) => Value::Array(
            options
                .iter()
                .map(|option| {
                    json!({
                        "code": option.code,
                        "data_hex": option.data_hex,
                    })
                })
                .collect(),
        ),
        None => Value::Null,
    }
}

pub fn dns_type_value(plan: &ProbePlan) -> ExampleResult<u16> {
    if let Some(value) = plan.query_type_value {
        return Ok(value);
    }
    match plan
        .query_type
        .as_deref()
        .unwrap_or("A")
        .to_ascii_uppercase()
        .as_str()
    {
        "A" => Ok(DNS_TYPE_A),
        "AAAA" => Ok(DNS_TYPE_AAAA),
        "TXT" => Ok(DNS_TYPE_TXT),
        "MX" => Ok(DNS_TYPE_MX),
        "SRV" => Ok(DNS_TYPE_SRV),
        other => Err(format!("unsupported DNS query type: {other}").into()),
    }
}

pub fn canonical_dns_name(name: &str) -> String {
    let trimmed = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        ".".to_string()
    } else {
        format!("{trimmed}.")
    }
}

/// Return the ordered TXT character-strings when `data` is a TXT RDATA, or
/// `None` for any other record data. Used by the TXT answer contract to compare
/// the full decoded character-string list (not just a single string).
pub fn dns_txt_strings(data: &DnsRecordData) -> Option<Vec<Vec<u8>>> {
    match data {
        DnsRecordData::Txt(strings) => Some(strings.clone()),
        _ => None,
    }
}

/// Return the structured MX `(preference, exchange)` when `data` is MX RDATA, or
/// `None` for any other record data. The exchange is the presentation-form
/// domain name. Used by the MX answer contract to compare the decoded numeric
/// preference and exchange name separately (not as a flat byte comparison).
pub fn dns_mx_fields(data: &DnsRecordData) -> Option<(u16, String)> {
    match data {
        DnsRecordData::Mx {
            preference,
            exchange,
        } => Some((*preference, exchange.presentation().to_string())),
        _ => None,
    }
}

/// Return the structured SRV `(priority, weight, port, target)` when `data` is
/// SRV RDATA, or `None` for any other record data. The target is the
/// presentation-form domain name. Used by the SRV answer contract to compare
/// each decoded numeric field and the target name separately (not as a flat byte
/// comparison).
pub fn dns_srv_fields(data: &DnsRecordData) -> Option<(u16, u16, u16, String)> {
    match data {
        DnsRecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => Some((*priority, *weight, *port, target.presentation().to_string())),
        _ => None,
    }
}

pub fn dns_record_data_matches(data: &DnsRecordData, expected: &str) -> bool {
    match data {
        DnsRecordData::A(address) => expected
            .parse::<Ipv4Addr>()
            .is_ok_and(|expected| *address == expected),
        DnsRecordData::Aaaa(address) => expected
            .parse::<Ipv6Addr>()
            .is_ok_and(|expected| *address == expected),
        DnsRecordData::Name(name) => {
            canonical_dns_name(name.presentation()) == canonical_dns_name(expected)
        }
        DnsRecordData::Txt(strings) => strings
            .iter()
            .filter_map(|bytes| std::str::from_utf8(bytes).ok())
            .any(|value| value == expected),
        DnsRecordData::Mx {
            preference,
            exchange,
        } => {
            format!(
                "{preference} {}",
                canonical_dns_name(exchange.presentation())
            ) == expected
        }
        DnsRecordData::Raw(bytes) => hex_bytes(bytes) == expected,
        _ => false,
    }
}

pub fn dns_json(dns: &Dns) -> Value {
    json!({
        "id": dns.id_value(),
        "flags": dns.flags_value(),
        "is_response": dns.is_response(),
        "response_code": dns.flags_value() & 0x000f,
        "questions": dns.questions().iter().map(|question| json!({
            "name": question.name(),
            "type": question.question_type(),
            "class": question.question_class(),
        })).collect::<Vec<_>>(),
        "answers": dns_answers_json(dns),
        "additionals": dns_additionals_json(dns),
    })
}

pub fn dns_answers_json(dns: &Dns) -> Value {
    Value::Array(dns.answers().iter().map(dns_record_json).collect())
}

/// JSON view of the additional-section records, surfacing the decoded EDNS(0)
/// OPT pseudo-record metadata (UDP payload size, version, extended rcode, DO
/// flag, and the ordered option list) so the OPT contract is inspectable from
/// agent code rather than buried in the raw bytes.
pub fn dns_additionals_json(dns: &Dns) -> Value {
    Value::Array(
        dns.additionals()
            .iter()
            .map(|record| {
                if record.is_opt() {
                    json!({
                        "name": record.name(),
                        "type": record.record_type(),
                        "is_opt": true,
                        "udp_payload_size": record.edns_udp_payload_size(),
                        "version": record.edns_version(),
                        "extended_rcode": record.edns_extended_rcode(),
                        "do": record.edns_dnssec_ok(),
                        "flags": record.edns_flags(),
                        "options": dns_opt_options_json(record.edns_options().unwrap_or(&[])),
                    })
                } else {
                    dns_record_json(record)
                }
            })
            .collect(),
    )
}

/// JSON view of a decoded EDNS(0) option list: each option's IANA code, its
/// registry mnemonic when this crate names the code, and its opaque data bytes
/// in hex (preserved verbatim per RFC 6891 Section 6.1.2).
pub fn dns_opt_options_json(options: &[EdnsOption]) -> Value {
    Value::Array(
        options
            .iter()
            .map(|option| {
                json!({
                    "code": option.code(),
                    "name": option.option_code_name(),
                    "data_hex": hex_bytes(option.data()),
                })
            })
            .collect(),
    )
}

fn dns_record_json(record: &DnsRecord) -> Value {
    json!({
        "name": record.name(),
        "type": record.record_type(),
        "class": record.class(),
        "ttl": record.ttl(),
        "data": dns_record_data_json(record.data()),
    })
}

fn dns_record_data_json(data: &DnsRecordData) -> Value {
    match data {
        DnsRecordData::A(address) => json!({
            "kind": "A",
            "value": address.to_string(),
        }),
        DnsRecordData::Aaaa(address) => json!({
            "kind": "AAAA",
            "value": address.to_string(),
        }),
        DnsRecordData::Name(name) => json!({
            "kind": "name",
            "value": name.presentation(),
        }),
        DnsRecordData::Mx {
            preference,
            exchange,
        } => json!({
            "kind": "mx",
            "preference": preference,
            "exchange": exchange.presentation(),
        }),
        DnsRecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => json!({
            "kind": "srv",
            "priority": priority,
            "weight": weight,
            "port": port,
            "target": target.presentation(),
        }),
        DnsRecordData::Txt(strings) => json!({
            "kind": "txt",
            "values": strings
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                .collect::<Vec<_>>(),
        }),
        DnsRecordData::Raw(bytes) => json!({
            "kind": "raw",
            "hex": hex_bytes(bytes),
        }),
        _ => json!({
            "kind": "other",
            "debug": format!("{data:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::DnsAnswerExpectation;
    use crate::test_support::base_plan;

    #[test]
    fn dns_packet_requires_query_name() {
        let mut plan = base_plan("dns-query");
        plan.source_ipv4 = Some("192.0.2.1".to_string());
        plan.destination_ipv4 = Some("192.0.2.2".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(53);
        plan.query_id = Some(0x1234);
        let err = dns_packet(&plan).unwrap_err().to_string();
        assert!(err.contains("query_name"), "got: {err}");
    }

    #[test]
    fn dns_packet_compiles_in_dry_run() {
        let mut plan = base_plan("dns-query");
        plan.source_ipv4 = Some("192.0.2.1".to_string());
        plan.destination_ipv4 = Some("192.0.2.2".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(53);
        plan.query_id = Some(0x1234);
        plan.query_name = Some("example.test".to_string());
        plan.query_type = Some("A".to_string());
        let packet = dns_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        assert!(bytes.len() >= 28, "dns packet too short: {}", bytes.len());
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert_eq!(dns.id_value(), 0x1234);
    }

    #[test]
    fn dns_type_value_maps_names_and_rejects_unknown() {
        let mut plan = base_plan("dns-query");
        plan.query_type = Some("aaaa".to_string());
        assert_eq!(dns_type_value(&plan).unwrap(), DNS_TYPE_AAAA);
        plan.query_type = Some("PTR".to_string());
        assert!(dns_type_value(&plan).is_err());
        plan.query_type = None;
        plan.query_type_value = Some(99);
        assert_eq!(dns_type_value(&plan).unwrap(), 99);
    }

    #[test]
    fn canonical_dns_name_normalizes() {
        assert_eq!(canonical_dns_name("Example.Test."), "example.test.");
        assert_eq!(canonical_dns_name(""), ".");
    }

    /// Build the IPv4/UDP/DNS response a controlled CNAME-chain responder emits:
    /// a CNAME answer owned by the queried name whose RDATA is the canonical
    /// domain name, followed by a terminal A answer owned by that canonical
    /// name. Returns the decoded packet plus the raw bytes for validation.
    fn cname_chain_response_bytes(
        query_name: &str,
        canonical_name: &str,
        terminal: Ipv4Addr,
        query_id: u16,
    ) -> Vec<u8> {
        let dns = Dns::query(query_name, DNS_TYPE_A)
            .id(query_id)
            .response(true)
            .answer(DnsRecord::cname(query_name, canonical_name, 120))
            .answer(DnsRecord::a(canonical_name, terminal, 90));
        (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .expect("cname chain response compiles")
            .as_bytes()
            .to_vec()
    }

    fn cname_chain_plan(query_name: &str, canonical_name: &str, terminal: &str) -> ProbePlan {
        let mut plan = base_plan("dns-cname-chain");
        plan.source_ipv4 = Some("10.77.0.10".to_string());
        plan.destination_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.77.0.10".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(53);
        plan.query_id = Some(0x6642);
        plan.query_name = Some(query_name.to_string());
        plan.query_type = Some("A".to_string());
        plan.query_type_value = Some(DNS_TYPE_A);
        plan.query_class_value = Some(DNS_CLASS_IN);
        plan.expected_answer_name = Some(canonical_name.to_string());
        plan.expected_answer_type = Some("A".to_string());
        plan.expected_answer_type_value = Some(DNS_TYPE_A);
        plan.expected_answer_data = Some(terminal.to_string());
        plan.expected_answer_count = Some(2);
        plan.original_name = Some(query_name.to_string());
        plan.canonical_name = Some(canonical_name.to_string());
        plan.terminal_ipv4 = Some(terminal.to_string());
        plan.expected_cname_answer = Some(DnsAnswerExpectation {
            name: query_name.to_string(),
            type_value: Some(DNS_TYPE_CNAME),
            class_value: Some(DNS_CLASS_IN),
            data: canonical_name.to_string(),
        });
        plan.expected_response_code = Some(0);
        plan
    }

    #[test]
    fn cname_chain_response_validates_both_answers() {
        let query = "probe-1012-0-e6426682f3.behavior.libcrafter.test.";
        let canonical = "canonical-1012-0-03040be178.behavior.libcrafter.test.";
        let terminal = Ipv4Addr::new(203, 0, 113, 244);
        let raw = cname_chain_response_bytes(query, canonical, terminal, 0x6642);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();

        // The crate decodes both answers, including the CNAME domain-name RDATA.
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert_eq!(dns.answers().len(), 2);

        let plan = cname_chain_plan(query, canonical, "203.0.113.244");
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed for cname chain, got {other:?}"),
        }
    }

    #[test]
    fn cname_chain_missing_terminal_answer_fails_payload() {
        let query = "probe-1012-0-e6426682f3.behavior.libcrafter.test.";
        let canonical = "canonical-1012-0-03040be178.behavior.libcrafter.test.";
        // A response that carries only the CNAME (no terminal A) must not pass.
        let dns = Dns::query(query, DNS_TYPE_A)
            .id(0x6642)
            .response(true)
            .answer(DnsRecord::cname(query, canonical, 120));
        let raw = (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = cname_chain_plan(query, canonical, "203.0.113.244");
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for incomplete chain, got {other:?}"),
        }
    }

    /// Build the IPv4/UDP/DNS NXDOMAIN response a controlled responder emits for
    /// an absent name: QR set, rcode 3 (NXDOMAIN), the original question echoed,
    /// and an empty answer section.
    fn nxdomain_response_bytes(query_name: &str, query_id: u16) -> Vec<u8> {
        let dns = Dns::query(query_name, DNS_TYPE_A)
            .id(query_id)
            .response(true)
            .rcode(DNS_RCODE_NXDOMAIN);
        (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .expect("nxdomain response compiles")
            .as_bytes()
            .to_vec()
    }

    fn nxdomain_plan(query_name: &str) -> ProbePlan {
        let mut plan = base_plan("dns-nxdomain");
        plan.source_ipv4 = Some("10.77.0.10".to_string());
        plan.destination_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.77.0.10".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(53);
        plan.query_id = Some(0x4d2a);
        plan.query_name = Some(query_name.to_string());
        plan.query_type = Some("A".to_string());
        plan.query_type_value = Some(DNS_TYPE_A);
        plan.query_class_value = Some(DNS_CLASS_IN);
        plan.absent_name = Some(query_name.to_string());
        plan.expected_answer_count = Some(0);
        plan.expected_response_code = Some(DNS_RCODE_NXDOMAIN);
        plan
    }

    #[test]
    fn nxdomain_response_validates_negative_answer() {
        let query = "probe-1013-0-absent00aa.behavior.libcrafter.test.";
        let raw = nxdomain_response_bytes(query, 0x4d2a);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();

        // The crate decodes the NXDOMAIN response: QR set, rcode 3, no answers,
        // the original question preserved.
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert!(dns.is_response());
        assert_eq!(dns.rcode_value(), DNS_RCODE_NXDOMAIN);
        assert_eq!(dns.answers().len(), 0);
        assert_eq!(dns.questions().first().unwrap().name(), query);

        let plan = nxdomain_plan(query);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed for nxdomain, got {other:?}"),
        }
    }

    #[test]
    fn nxdomain_with_answer_fails_payload() {
        let query = "probe-1013-0-absent00aa.behavior.libcrafter.test.";
        // A responder that wrongly returns an A answer for the absent name (or a
        // NOERROR/rcode-0 answer) must not pass the NXDOMAIN contract: the
        // answer count is non-zero.
        let dns = Dns::query(query, DNS_TYPE_A)
            .id(0x4d2a)
            .response(true)
            .rcode(DNS_RCODE_NXDOMAIN)
            .answer(DnsRecord::a(query, Ipv4Addr::new(203, 0, 113, 5), 60));
        let raw = (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = nxdomain_plan(query);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for nxdomain with answer, got {other:?}"),
        }
    }

    #[test]
    fn wrong_rcode_fails_nxdomain() {
        let query = "probe-1013-0-absent00aa.behavior.libcrafter.test.";
        // A NOERROR (rcode 0) response with no answers is NODATA, not NXDOMAIN;
        // the rcode mismatch must surface.
        let dns = Dns::query(query, DNS_TYPE_A).id(0x4d2a).response(true);
        let raw = (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = nxdomain_plan(query);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong rcode, got {other:?}"),
        }
    }

    /// Build the IPv4/UDP/DNS NODATA response a controlled responder emits when
    /// the name exists but the queried type is absent: QR set, rcode 0
    /// (NOERROR), the original question echoed, and an empty answer section.
    fn nodata_response_bytes(query_name: &str, query_id: u16) -> Vec<u8> {
        let dns = Dns::query(query_name, DNS_TYPE_A)
            .id(query_id)
            .response(true);
        (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .expect("nodata response compiles")
            .as_bytes()
            .to_vec()
    }

    fn nodata_plan(query_name: &str) -> ProbePlan {
        let mut plan = base_plan("dns-nodata");
        plan.source_ipv4 = Some("10.77.0.10".to_string());
        plan.destination_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.77.0.10".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(53);
        plan.query_id = Some(0x73a1);
        plan.query_name = Some(query_name.to_string());
        plan.query_type = Some("A".to_string());
        plan.query_type_value = Some(DNS_TYPE_A);
        plan.query_class_value = Some(DNS_CLASS_IN);
        plan.present_name = Some(query_name.to_string());
        plan.present_type = Some("AAAA".to_string());
        plan.present_type_value = Some(DNS_TYPE_AAAA);
        plan.expected_answer_count = Some(0);
        plan.expected_response_code = Some(0);
        plan
    }

    #[test]
    fn nodata_response_validates_noerror_empty_answer() {
        let query = "probe-1014-0-nodata00bb.behavior.libcrafter.test.";
        let raw = nodata_response_bytes(query, 0x73a1);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();

        // The crate decodes the NODATA response: QR set, rcode 0 (NOERROR), no
        // answers, the original question preserved.
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert!(dns.is_response());
        assert_eq!(dns.rcode_value(), 0);
        assert_eq!(dns.answers().len(), 0);
        assert_eq!(dns.questions().first().unwrap().name(), query);

        let plan = nodata_plan(query);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed for nodata, got {other:?}"),
        }
    }

    #[test]
    fn nodata_with_answer_fails_payload() {
        let query = "probe-1014-0-nodata00bb.behavior.libcrafter.test.";
        // A responder that wrongly returns an A answer for the queried type must
        // not pass the NODATA contract: the answer count is non-zero.
        let dns = Dns::query(query, DNS_TYPE_A)
            .id(0x73a1)
            .response(true)
            .answer(DnsRecord::a(query, Ipv4Addr::new(203, 0, 113, 7), 60));
        let raw = (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = nodata_plan(query);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for nodata with answer, got {other:?}"),
        }
    }

    /// Build the IPv4/UDP/DNS TXT response a controlled responder emits: QR set,
    /// rcode 0, the original question echoed, and a single TXT answer whose RDATA
    /// is the ordered list of DNS character-strings.
    fn txt_response_bytes(query_name: &str, strings: &[&str], ttl: u32, query_id: u16) -> Vec<u8> {
        let txt = DnsRecordData::Txt(strings.iter().map(|s| s.as_bytes().to_vec()).collect());
        let dns = Dns::query(query_name, DNS_TYPE_TXT)
            .id(query_id)
            .response(true)
            .answer(DnsRecord::new(
                query_name,
                DNS_TYPE_TXT,
                DNS_CLASS_IN,
                ttl,
                txt,
            ));
        (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .expect("txt response compiles")
            .as_bytes()
            .to_vec()
    }

    fn txt_plan(query_name: &str, strings: &[&str], ttl: u32) -> ProbePlan {
        let mut plan = base_plan("dns-txt-answer");
        plan.source_ipv4 = Some("10.77.0.10".to_string());
        plan.destination_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.77.0.10".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(53);
        plan.query_id = Some(0x515a);
        plan.query_name = Some(query_name.to_string());
        plan.query_type = Some("TXT".to_string());
        plan.query_type_value = Some(DNS_TYPE_TXT);
        plan.query_class_value = Some(DNS_CLASS_IN);
        plan.expected_answer_name = Some(query_name.to_string());
        plan.expected_answer_type = Some("TXT".to_string());
        plan.expected_answer_type_value = Some(DNS_TYPE_TXT);
        plan.expected_txt_strings = Some(strings.iter().map(|s| s.to_string()).collect());
        plan.answer_ttl = Some(ttl);
        plan.expected_response_code = Some(0);
        plan
    }

    #[test]
    fn txt_response_validates_multi_string_answer() {
        let query = "probe-1015-0-txt000abcd.behavior.libcrafter.test.";
        let strings = [
            "libcrafter-probe-txt=behavior-1015-0",
            "v=libcrafter1 id=deadbeef",
        ];
        let raw = txt_response_bytes(query, &strings, 120, 0x515a);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();

        // The crate decodes the TXT RDATA as an ordered character-string list.
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert_eq!(dns.answers().len(), 1);
        let answer = &dns.answers()[0];
        assert_eq!(answer.record_type(), DNS_TYPE_TXT);
        match answer.data() {
            DnsRecordData::Txt(decoded) => {
                let decoded: Vec<String> = decoded
                    .iter()
                    .map(|bytes| String::from_utf8(bytes.clone()).unwrap())
                    .collect();
                assert_eq!(decoded, strings.to_vec());
            }
            other => panic!("expected TXT rdata, got {other:?}"),
        }

        let plan = txt_plan(query, &strings, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed for txt answer, got {other:?}"),
        }
    }

    #[test]
    fn txt_wrong_string_content_fails_payload() {
        let query = "probe-1015-0-txt000abcd.behavior.libcrafter.test.";
        let strings = ["expected-one", "expected-two"];
        // The responder returns different content than the plan expects.
        let raw = txt_response_bytes(query, &["expected-one", "WRONG-two"], 120, 0x515a);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = txt_plan(query, &strings, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong txt content, got {other:?}"),
        }
    }

    #[test]
    fn txt_wrong_ttl_fails_payload() {
        let query = "probe-1015-0-txt000abcd.behavior.libcrafter.test.";
        let strings = ["one", "two"];
        // Correct strings but a TTL that does not match the contract.
        let raw = txt_response_bytes(query, &strings, 999, 0x515a);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = txt_plan(query, &strings, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong txt ttl, got {other:?}"),
        }
    }

    #[test]
    fn txt_response_dns_packet_builds_txt_query() {
        let query = "probe-1015-0-txt000abcd.behavior.libcrafter.test.";
        let plan = txt_plan(query, &["one", "two"], 120);
        let packet = dns_packet(&plan).unwrap();
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert_eq!(
            dns.questions().first().unwrap().question_type(),
            DNS_TYPE_TXT
        );
        assert_eq!(dns.id_value(), 0x515a);
    }

    /// Build the IPv4/UDP/DNS MX response a controlled responder emits: QR set,
    /// rcode 0, the original question echoed, and a single MX answer whose RDATA
    /// is a 16-bit preference followed by the exchange domain name.
    fn mx_response_bytes(
        query_name: &str,
        preference: u16,
        exchange: &str,
        ttl: u32,
        query_id: u16,
    ) -> Vec<u8> {
        let mx = DnsRecordData::Mx {
            preference,
            exchange: DnsName::parse(exchange).expect("exchange parses"),
        };
        let dns = Dns::query(query_name, DNS_TYPE_MX)
            .id(query_id)
            .response(true)
            .answer(DnsRecord::new(
                query_name,
                DNS_TYPE_MX,
                DNS_CLASS_IN,
                ttl,
                mx,
            ));
        (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .expect("mx response compiles")
            .as_bytes()
            .to_vec()
    }

    fn mx_plan(query_name: &str, preference: u16, exchange: &str, ttl: u32) -> ProbePlan {
        let mut plan = base_plan("dns-mx-answer");
        plan.source_ipv4 = Some("10.77.0.10".to_string());
        plan.destination_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.77.0.10".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(53);
        plan.query_id = Some(0x4d58);
        plan.query_name = Some(query_name.to_string());
        plan.query_type = Some("MX".to_string());
        plan.query_type_value = Some(DNS_TYPE_MX);
        plan.query_class_value = Some(DNS_CLASS_IN);
        plan.expected_answer_name = Some(query_name.to_string());
        plan.expected_answer_type = Some("MX".to_string());
        plan.expected_answer_type_value = Some(DNS_TYPE_MX);
        plan.expected_mx_preference = Some(preference);
        plan.expected_mx_exchange = Some(exchange.to_string());
        plan.answer_ttl = Some(ttl);
        plan.expected_response_code = Some(0);
        plan
    }

    #[test]
    fn mx_response_validates_preference_and_exchange() {
        let query = "probe-1016-0-mx0000abcd.behavior.libcrafter.test.";
        let exchange = "mail-1016-0-mx0000abcd.behavior.libcrafter.test.";
        let raw = mx_response_bytes(query, 10, exchange, 120, 0x4d58);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();

        // The crate decodes the MX RDATA into a structured preference + exchange.
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert_eq!(dns.answers().len(), 1);
        let answer = &dns.answers()[0];
        assert_eq!(answer.record_type(), DNS_TYPE_MX);
        match answer.data() {
            DnsRecordData::Mx {
                preference,
                exchange: decoded,
            } => {
                assert_eq!(*preference, 10);
                assert_eq!(
                    canonical_dns_name(decoded.presentation()),
                    canonical_dns_name(exchange)
                );
            }
            other => panic!("expected MX rdata, got {other:?}"),
        }

        let plan = mx_plan(query, 10, exchange, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed for mx answer, got {other:?}"),
        }
    }

    #[test]
    fn mx_wrong_preference_fails_payload() {
        let query = "probe-1016-0-mx0000abcd.behavior.libcrafter.test.";
        let exchange = "mail-1016-0-mx0000abcd.behavior.libcrafter.test.";
        // Correct exchange but a preference that does not match the contract.
        let raw = mx_response_bytes(query, 99, exchange, 120, 0x4d58);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = mx_plan(query, 10, exchange, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong mx preference, got {other:?}"),
        }
    }

    #[test]
    fn mx_wrong_exchange_fails_payload() {
        let query = "probe-1016-0-mx0000abcd.behavior.libcrafter.test.";
        let exchange = "mail-1016-0-mx0000abcd.behavior.libcrafter.test.";
        // Correct preference but the wrong exchange domain name.
        let raw = mx_response_bytes(
            query,
            10,
            "other-mail.behavior.libcrafter.test.",
            120,
            0x4d58,
        );
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = mx_plan(query, 10, exchange, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong mx exchange, got {other:?}"),
        }
    }

    #[test]
    fn mx_wrong_ttl_fails_payload() {
        let query = "probe-1016-0-mx0000abcd.behavior.libcrafter.test.";
        let exchange = "mail-1016-0-mx0000abcd.behavior.libcrafter.test.";
        // Correct preference and exchange but a TTL that does not match.
        let raw = mx_response_bytes(query, 10, exchange, 999, 0x4d58);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = mx_plan(query, 10, exchange, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong mx ttl, got {other:?}"),
        }
    }

    #[test]
    fn mx_response_dns_packet_builds_mx_query() {
        let query = "probe-1016-0-mx0000abcd.behavior.libcrafter.test.";
        let exchange = "mail-1016-0-mx0000abcd.behavior.libcrafter.test.";
        let plan = mx_plan(query, 10, exchange, 120);
        let packet = dns_packet(&plan).unwrap();
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert_eq!(
            dns.questions().first().unwrap().question_type(),
            DNS_TYPE_MX
        );
        assert_eq!(dns.id_value(), 0x4d58);
    }

    /// Build the IPv4/UDP/DNS SRV response a controlled responder emits: QR set,
    /// rcode 0, the original question echoed, and a single SRV answer whose RDATA
    /// is priority + weight + port + the target domain name.
    fn srv_response_bytes(
        query_name: &str,
        priority: u16,
        weight: u16,
        port: u16,
        target: &str,
        ttl: u32,
        query_id: u16,
    ) -> Vec<u8> {
        let dns = Dns::query(query_name, DNS_TYPE_SRV)
            .id(query_id)
            .response(true)
            .answer(DnsRecord::srv(
                query_name, ttl, priority, weight, port, target,
            ));
        (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .expect("srv response compiles")
            .as_bytes()
            .to_vec()
    }

    #[allow(clippy::too_many_arguments)]
    fn srv_plan(
        query_name: &str,
        priority: u16,
        weight: u16,
        port: u16,
        target: &str,
        ttl: u32,
    ) -> ProbePlan {
        let mut plan = base_plan("dns-srv-answer");
        plan.source_ipv4 = Some("10.77.0.10".to_string());
        plan.destination_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.77.0.10".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(53);
        plan.query_id = Some(0x53a7);
        plan.query_name = Some(query_name.to_string());
        plan.query_type = Some("SRV".to_string());
        plan.query_type_value = Some(DNS_TYPE_SRV);
        plan.query_class_value = Some(DNS_CLASS_IN);
        plan.expected_answer_name = Some(query_name.to_string());
        plan.expected_answer_type = Some("SRV".to_string());
        plan.expected_answer_type_value = Some(DNS_TYPE_SRV);
        plan.expected_srv_priority = Some(priority);
        plan.expected_srv_weight = Some(weight);
        plan.expected_srv_port = Some(port);
        plan.expected_srv_target = Some(target.to_string());
        plan.answer_ttl = Some(ttl);
        plan.expected_response_code = Some(0);
        plan
    }

    #[test]
    fn srv_response_validates_priority_weight_port_and_target() {
        let query = "_sip._tcp.srv-1017-0-srv00abcd.behavior.libcrafter.test.";
        let target = "target-1017-0-srv00abcd.behavior.libcrafter.test.";
        let raw = srv_response_bytes(query, 10, 5, 5060, target, 120, 0x53a7);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();

        // The crate decodes the SRV RDATA into structured priority/weight/port +
        // target name.
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert_eq!(dns.answers().len(), 1);
        let answer = &dns.answers()[0];
        assert_eq!(answer.record_type(), DNS_TYPE_SRV);
        match answer.data() {
            DnsRecordData::Srv {
                priority,
                weight,
                port,
                target: decoded,
            } => {
                assert_eq!((*priority, *weight, *port), (10, 5, 5060));
                assert_eq!(
                    canonical_dns_name(decoded.presentation()),
                    canonical_dns_name(target)
                );
            }
            other => panic!("expected SRV rdata, got {other:?}"),
        }

        let plan = srv_plan(query, 10, 5, 5060, target, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed for srv answer, got {other:?}"),
        }
    }

    #[test]
    fn srv_wrong_priority_fails_payload() {
        let query = "_sip._tcp.srv-1017-0-srv00abcd.behavior.libcrafter.test.";
        let target = "target-1017-0-srv00abcd.behavior.libcrafter.test.";
        // Correct weight/port/target but a priority that does not match.
        let raw = srv_response_bytes(query, 99, 5, 5060, target, 120, 0x53a7);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = srv_plan(query, 10, 5, 5060, target, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong srv priority, got {other:?}"),
        }
    }

    #[test]
    fn srv_wrong_weight_fails_payload() {
        let query = "_sip._tcp.srv-1017-0-srv00abcd.behavior.libcrafter.test.";
        let target = "target-1017-0-srv00abcd.behavior.libcrafter.test.";
        // Correct priority/port/target but a weight that does not match.
        let raw = srv_response_bytes(query, 10, 99, 5060, target, 120, 0x53a7);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = srv_plan(query, 10, 5, 5060, target, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong srv weight, got {other:?}"),
        }
    }

    #[test]
    fn srv_wrong_port_fails_payload() {
        let query = "_sip._tcp.srv-1017-0-srv00abcd.behavior.libcrafter.test.";
        let target = "target-1017-0-srv00abcd.behavior.libcrafter.test.";
        // Correct priority/weight/target but a service port that does not match.
        let raw = srv_response_bytes(query, 10, 5, 9999, target, 120, 0x53a7);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = srv_plan(query, 10, 5, 5060, target, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong srv port, got {other:?}"),
        }
    }

    #[test]
    fn srv_wrong_target_fails_payload() {
        let query = "_sip._tcp.srv-1017-0-srv00abcd.behavior.libcrafter.test.";
        let target = "target-1017-0-srv00abcd.behavior.libcrafter.test.";
        // Correct numeric fields but the wrong target domain name.
        let raw = srv_response_bytes(
            query,
            10,
            5,
            5060,
            "other-target.behavior.libcrafter.test.",
            120,
            0x53a7,
        );
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = srv_plan(query, 10, 5, 5060, target, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong srv target, got {other:?}"),
        }
    }

    #[test]
    fn srv_wrong_ttl_fails_payload() {
        let query = "_sip._tcp.srv-1017-0-srv00abcd.behavior.libcrafter.test.";
        let target = "target-1017-0-srv00abcd.behavior.libcrafter.test.";
        // Correct priority/weight/port/target but a TTL that does not match.
        let raw = srv_response_bytes(query, 10, 5, 5060, target, 999, 0x53a7);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = srv_plan(query, 10, 5, 5060, target, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong srv ttl, got {other:?}"),
        }
    }

    #[test]
    fn srv_response_dns_packet_builds_srv_query() {
        let query = "_sip._tcp.srv-1017-0-srv00abcd.behavior.libcrafter.test.";
        let target = "target-1017-0-srv00abcd.behavior.libcrafter.test.";
        let plan = srv_plan(query, 10, 5, 5060, target, 120);
        let packet = dns_packet(&plan).unwrap();
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert_eq!(
            dns.questions().first().unwrap().question_type(),
            DNS_TYPE_SRV
        );
        assert_eq!(dns.id_value(), 0x53a7);
    }

    #[test]
    fn nxdomain_rcode_fails_nodata() {
        let query = "probe-1014-0-nodata00bb.behavior.libcrafter.test.";
        // NXDOMAIN (rcode 3) is the absent-name case, not NODATA (the name
        // exists). A NODATA plan must reject an rcode-3 response.
        let dns = Dns::query(query, DNS_TYPE_A)
            .id(0x73a1)
            .response(true)
            .rcode(DNS_RCODE_NXDOMAIN);
        let raw = (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = nodata_plan(query);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for nxdomain rcode, got {other:?}"),
        }
    }

    /// Build the IPv4/UDP/DNS EDNS response a controlled responder emits: QR set,
    /// rcode 0, the original A question echoed, an A answer, and an OPT
    /// pseudo-record in the additional section advertising the UDP payload size,
    /// version, DO flag, and the NSID option.
    fn edns_response_bytes(
        query_name: &str,
        answer: Ipv4Addr,
        ttl: u32,
        payload_size: u16,
        version: u8,
        dnssec_ok: bool,
        nsid: &[u8],
    ) -> Vec<u8> {
        let opt = DnsRecord::opt(
            payload_size,
            0,
            version,
            dnssec_ok,
            vec![EdnsOption::nsid(nsid.to_vec())],
        );
        let dns = Dns::query(query_name, DNS_TYPE_A)
            .id(0xed01)
            .response(true)
            .answer(DnsRecord::a(query_name, answer, ttl))
            .additional(opt);
        (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .expect("edns response compiles")
            .as_bytes()
            .to_vec()
    }

    fn edns_plan(
        query_name: &str,
        answer: &str,
        ttl: u32,
        payload_size: u16,
        version: u8,
        dnssec_ok: bool,
        nsid: &[u8],
    ) -> ProbePlan {
        let mut plan = base_plan("dns-edns-opt");
        plan.source_ipv4 = Some("10.77.0.10".to_string());
        plan.destination_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.77.0.10".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(53);
        plan.query_id = Some(0xed01);
        plan.query_name = Some(query_name.to_string());
        plan.query_type = Some("A".to_string());
        plan.query_type_value = Some(DNS_TYPE_A);
        plan.query_class_value = Some(DNS_CLASS_IN);
        plan.expected_answer_name = Some(query_name.to_string());
        plan.expected_answer_type = Some("A".to_string());
        plan.expected_answer_type_value = Some(DNS_TYPE_A);
        plan.expected_answer_data = Some(answer.to_string());
        plan.answer_ttl = Some(ttl);
        plan.expected_response_code = Some(0);
        // The stimulus advertises its own OPT; the responder echoes one back.
        plan.edns_udp_payload_size = Some(1232);
        plan.edns_version = Some(version);
        plan.edns_do = Some(dnssec_ok);
        plan.edns_request_options = Some(vec![EdnsOptionExpectation {
            code: 3,
            data_hex: hex_bytes(b"client"),
        }]);
        plan.expected_edns_udp_payload_size = Some(payload_size);
        plan.expected_edns_version = Some(version);
        plan.expected_edns_extended_rcode = Some(0);
        plan.expected_edns_do = Some(dnssec_ok);
        plan.expected_edns_options = Some(vec![EdnsOptionExpectation {
            code: 3,
            data_hex: hex_bytes(nsid),
        }]);
        plan
    }

    #[test]
    fn edns_query_carries_opt_record() {
        // The stimulus query attaches an OPT pseudo-record advertising the
        // requestor UDP payload size and the NSID option.
        let query = "probe-1018-0-edns0000aa.behavior.libcrafter.test.";
        let plan = edns_plan(query, "203.0.113.7", 120, 4096, 0, true, b"server");
        let packet = dns_packet(&plan).unwrap();
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert_eq!(dns.questions().first().unwrap().question_type(), DNS_TYPE_A);
        let opt = dns
            .additionals()
            .iter()
            .find(|record| record.is_opt())
            .expect("query carries an OPT additional record");
        assert_eq!(opt.edns_udp_payload_size(), 1232);
        assert!(opt.edns_dnssec_ok());
        let options = opt.edns_options().unwrap();
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].code(), DNS_EDNS_OPTION_NSID);
        assert_eq!(options[0].data(), b"client");
    }

    #[test]
    fn edns_response_validates_opt_metadata() {
        let query = "probe-1018-0-edns0000aa.behavior.libcrafter.test.";
        let raw = edns_response_bytes(
            query,
            Ipv4Addr::new(203, 0, 113, 7),
            120,
            4096,
            0,
            true,
            b"server",
        );
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();

        // The crate decodes the additional-section OPT pseudo-record fields.
        let dns = packet.layer::<Dns>().expect("dns layer present");
        let opt = dns
            .additionals()
            .iter()
            .find(|record| record.is_opt())
            .expect("response carries an OPT additional record");
        assert_eq!(opt.name(), ".");
        assert_eq!(opt.edns_udp_payload_size(), 4096);
        assert_eq!(opt.edns_version(), 0);
        assert_eq!(opt.edns_extended_rcode(), 0);
        assert!(opt.edns_dnssec_ok());
        assert_eq!(opt.edns_options().unwrap()[0].data(), b"server");

        let plan = edns_plan(query, "203.0.113.7", 120, 4096, 0, true, b"server");
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed for edns opt answer, got {other:?}"),
        }
    }

    #[test]
    fn edns_missing_opt_fails_payload() {
        let query = "probe-1018-0-edns0000aa.behavior.libcrafter.test.";
        // A response with the correct A answer but no OPT additional record must
        // not pass the EDNS contract.
        let dns = Dns::query(query, DNS_TYPE_A)
            .id(0xed01)
            .response(true)
            .answer(DnsRecord::a(query, Ipv4Addr::new(203, 0, 113, 7), 120));
        let raw = (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = edns_plan(query, "203.0.113.7", 120, 4096, 0, true, b"server");
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for missing OPT, got {other:?}"),
        }
    }

    #[test]
    fn edns_wrong_payload_size_fails_payload() {
        let query = "probe-1018-0-edns0000aa.behavior.libcrafter.test.";
        // Correct option/DO but the OPT advertises a different UDP payload size.
        let raw = edns_response_bytes(
            query,
            Ipv4Addr::new(203, 0, 113, 7),
            120,
            512,
            0,
            true,
            b"server",
        );
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = edns_plan(query, "203.0.113.7", 120, 4096, 0, true, b"server");
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong payload size, got {other:?}"),
        }
    }

    #[test]
    fn edns_wrong_do_flag_fails_payload() {
        let query = "probe-1018-0-edns0000aa.behavior.libcrafter.test.";
        // Correct fields but the DO ("DNSSEC OK") flag is cleared.
        let raw = edns_response_bytes(
            query,
            Ipv4Addr::new(203, 0, 113, 7),
            120,
            4096,
            0,
            false,
            b"server",
        );
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = edns_plan(query, "203.0.113.7", 120, 4096, 0, true, b"server");
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong DO flag, got {other:?}"),
        }
    }

    #[test]
    fn edns_wrong_option_data_fails_payload() {
        let query = "probe-1018-0-edns0000aa.behavior.libcrafter.test.";
        // Correct OPT header fields but the NSID option data differs.
        let raw = edns_response_bytes(
            query,
            Ipv4Addr::new(203, 0, 113, 7),
            120,
            4096,
            0,
            true,
            b"WRONG",
        );
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = edns_plan(query, "203.0.113.7", 120, 4096, 0, true, b"server");
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong option data, got {other:?}"),
        }
    }

    /// Build a `dns-repeat-transaction` plan with two sends reusing one
    /// transaction id and one query name over two distinct source ports, each
    /// with its own A answer.
    fn repeat_transaction_plan() -> ProbePlan {
        let query = "probe-1019-0-rep00000aa.behavior.libcrafter.test.";
        let make_send = |index: usize, source_port: u16, answer: &str, ttl: u32| DnsSend {
            index: Some(index),
            source_ipv4: Some("10.77.0.10".to_string()),
            destination_ipv4: Some("10.77.0.20".to_string()),
            expected_reply_source_ipv4: Some("10.77.0.20".to_string()),
            expected_reply_destination_ipv4: Some("10.77.0.10".to_string()),
            source_port: Some(source_port),
            destination_port: Some(53),
            query_id: Some(0xab12),
            query_name: Some(query.to_string()),
            query_type: Some("A".to_string()),
            query_type_value: Some(DNS_TYPE_A),
            query_class_value: Some(DNS_CLASS_IN),
            expected_answer_name: Some(query.to_string()),
            expected_answer_type: Some("A".to_string()),
            expected_answer_type_value: Some(DNS_TYPE_A),
            expected_answer_data: Some(answer.to_string()),
            expected_answer_count: Some(1),
            expected_response_code: Some(0),
            answer_ttl: Some(ttl),
            capture_filter: None,
        };
        let mut plan = base_plan("dns-repeat-transaction");
        plan.source_ipv4 = Some("10.77.0.10".to_string());
        plan.destination_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.77.0.10".to_string());
        plan.source_port = Some(40100);
        plan.destination_port = Some(53);
        plan.query_id = Some(0xab12);
        plan.query_name = Some(query.to_string());
        plan.query_type = Some("A".to_string());
        plan.query_type_value = Some(DNS_TYPE_A);
        plan.query_class_value = Some(DNS_CLASS_IN);
        plan.expected_answer_data = Some("203.0.113.10".to_string());
        plan.answer_ttl = Some(90);
        plan.send_count = Some(2);
        plan.sends = Some(vec![
            make_send(0, 40100, "203.0.113.10", 90),
            make_send(1, 50200, "203.0.113.20", 120),
        ]);
        plan
    }

    #[test]
    fn send_as_plan_overrides_per_send_fields() {
        let plan = repeat_transaction_plan();
        let sends = plan.sends.clone().unwrap();
        let first = send_as_plan(&plan, &sends[0]);
        let second = send_as_plan(&plan, &sends[1]);
        // Each derived plan is single-send (no nested sends) so the existing
        // build/validate path runs against exactly one query.
        assert!(first.sends.is_none());
        assert!(second.sends.is_none());
        // Shared transaction id and query name; distinct source port and answer.
        assert_eq!(first.query_id, second.query_id);
        assert_eq!(first.query_name, second.query_name);
        assert_ne!(first.source_port, second.source_port);
        assert_eq!(first.source_port, Some(40100));
        assert_eq!(second.source_port, Some(50200));
        assert_eq!(first.expected_answer_data.as_deref(), Some("203.0.113.10"));
        assert_eq!(second.expected_answer_data.as_deref(), Some("203.0.113.20"));
    }

    #[test]
    fn each_send_compiles_its_own_query() {
        let plan = repeat_transaction_plan();
        let sends = plan.sends.clone().unwrap();
        for send in &sends {
            let send_plan = send_as_plan(&plan, send);
            let packet = dns_packet(&send_plan).unwrap();
            let bytes = packet.compile().unwrap();
            assert!(bytes.len() >= 28, "dns packet too short: {}", bytes.len());
            let udp = packet.layer::<Udp>().expect("udp layer present");
            assert_eq!(udp.source_port_value(), send.source_port.unwrap());
            let dns = packet.layer::<Dns>().expect("dns layer present");
            assert_eq!(dns.id_value(), 0xab12);
        }
    }

    #[test]
    fn multi_send_dry_run_emits_two_planned_sends_and_responses() {
        let plan = repeat_transaction_plan();
        let request: StimulusEndpointRequest = serde_json::from_value(serde_json::json!({
            "provider": "qemu",
            "profile": "behavior",
            "seed": 1019,
            "endpoint_role": "stimulus",
            "interface": "eth1",
            "local_ipv4": "10.77.0.10",
            "peer_ipv4": "10.77.0.20",
            "timeout_seconds": 5,
            "probe_plans": [],
        }))
        .expect("request deserializes");
        let outcome = run_dns_dry_run(&request, &plan).expect("dry-run succeeds");
        let metadata = &outcome.result["metadata"];
        assert_eq!(metadata["send_count"], serde_json::json!(2));
        let planned_sends = metadata["planned_sends"].as_array().expect("planned_sends");
        assert_eq!(planned_sends.len(), 2);
        let expected_responses = metadata["expected_responses"]
            .as_array()
            .expect("expected_responses");
        assert_eq!(expected_responses.len(), 2);
        // Each planned send compiled its own stimulus bytes.
        for send in planned_sends {
            assert!(send["sent_raw_hex"]
                .as_str()
                .is_some_and(|hex| !hex.is_empty()));
        }
        // Reused id, separate source ports, distinct answers.
        let ports: Vec<_> = planned_sends
            .iter()
            .map(|send| send["source_port"].clone())
            .collect();
        assert_ne!(ports[0], ports[1]);
        assert_eq!(
            planned_sends[0]["query_id"], planned_sends[1]["query_id"],
            "both sends reuse one transaction id"
        );
        assert_ne!(
            expected_responses[0]["answer"]["data"], expected_responses[1]["answer"]["data"],
            "each expected response carries its own answer"
        );
    }
}
