//! SSDP behavioral probe cases.
//!
//! The adapter materializes live-capable SSDP probe plans as typed libcrafter
//! IPv4/IPv6 + UDP + SSDP packets. It sends search stimuli, captures controlled
//! responses, and handles the notification case as a capture-only observation
//! from the controlled target service.

use crafter::prelude::*;
use serde_json::{json, Value};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::common::{
    captured_data, decode_hex, decoded_packet_json, failed_outcome, hex_bytes, observed_response,
    open_capture_sniffer, plan_json, required_str, required_u16, send_report_json,
    CandidateValidation, ExampleResult, ProbeOutcome, ProbePlan, StimulusEndpointRequest,
    FAILURE_DECODE_FAILED, FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD, FAILURE_WRONG_PEER,
};

const SSDP_IPV4_MULTICAST_TTL: u8 = 2;
const SSDP_IPV6_LINK_LOCAL_HOP_LIMIT: u8 = 1;
const SSDP_IPV6_SITE_LOCAL_HOP_LIMIT: u8 = 5;

pub fn run_ssdp_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = ssdp_packet(plan)?;
    let capture_filter = ssdp_capture_filter(plan)?;
    let report = SocketSender::new(
        SendOptions::new()
            .iface(request.interface.clone())
            .network_layer()
            .dry_run(),
    )
    .send(&packet)?;
    let sent_raw = report.plan().bytes();
    let sent_raw_hex = hex_bytes(sent_raw);
    let sent_packet = Packet::decode_from_l3(network_layer(plan), sent_raw)?;
    let sent_decoded = decoded_ssdp_packet_json(&sent_packet, sent_raw);
    let target_service = ssdp_target_service_json(plan);
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
            "ssdp": ssdp_payload_json(plan)?,
            "expected_ssdp": expected_ssdp_payload_json(plan)?,
            "capture_filter": capture_filter,
            "target_service": target_service,
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
            "ssdp": ssdp_payload_json(plan)?,
            "expected_ssdp": expected_ssdp_payload_json(plan)?,
            "capture_filter": capture_filter,
            "target_service": target_service,
        }
    });
    Ok(ProbeOutcome {
        result,
        observed_response: observed,
        sent: false,
        received: false,
    })
}

pub fn run_ssdp_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    if plan.case == "ssdp-notify-capture" {
        return run_ssdp_capture_live(request, plan);
    }

    let packet = ssdp_packet(plan)?;
    let capture_filter = ssdp_capture_filter(plan)?;
    let timeout = Duration::from_secs(request.timeout_seconds.max(1));
    let mut sniffer = match open_capture_sniffer(
        request.interface.clone(),
        timeout,
        64,
        capture_filter.clone(),
    ) {
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
        match validate_ssdp_candidate(plan, captured.packet(), captured_data(&captured))? {
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
                        "capture_filter": capture_filter,
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
            vec!["captured SSDP response did not match expected payload".to_string()],
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
            vec!["captured SSDP response did not match expected peer or ports".to_string()],
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
        vec!["timed out waiting for SSDP response".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter,
        })),
        sent,
        false,
    ))
}

fn run_ssdp_capture_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let expected_packet = ssdp_packet(plan)?;
    let expected_raw = expected_packet.compile()?;
    let capture_filter = ssdp_capture_filter(plan)?;
    let timeout = Duration::from_secs(request.timeout_seconds.max(1));
    let mut sniffer = match open_capture_sniffer(
        request.interface.clone(),
        timeout,
        64,
        capture_filter.clone(),
    ) {
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

    let mut wrong_peer = None;
    let mut wrong_payload = None;
    while let Some(captured) = match sniffer.next_record() {
        Ok(packet) => packet,
        Err(err) => {
            return Ok(failed_outcome(
                plan,
                FAILURE_DECODE_FAILED,
                vec![format!("capture decode failed: {err}")],
                None,
                false,
                false,
            ));
        }
    } {
        match validate_ssdp_candidate(plan, captured.packet(), captured_data(&captured))? {
            CandidateValidation::Ignore => {}
            CandidateValidation::Passed(decoded) => {
                let raw_hex = hex_bytes(captured_data(&captured));
                let observed = observed_response(
                    plan,
                    true,
                    Some(raw_hex.clone()),
                    decoded.clone(),
                    json!({
                        "capture_filter": capture_filter,
                        "expected_raw_hex": hex_bytes(&expected_raw),
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
                        "expected_raw_hex": hex_bytes(&expected_raw),
                    }
                });
                return Ok(ProbeOutcome {
                    result,
                    observed_response: observed,
                    sent: false,
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
            vec!["captured SSDP notification did not match expected payload".to_string()],
            Some(json!({
                "decoded": decoded,
                "expected_raw_hex": hex_bytes(&expected_raw),
            })),
            false,
            true,
        ));
    }

    if let Some(decoded) = wrong_peer {
        return Ok(failed_outcome(
            plan,
            FAILURE_WRONG_PEER,
            vec!["captured SSDP notification did not match expected peer or ports".to_string()],
            Some(json!({
                "decoded": decoded,
                "expected_raw_hex": hex_bytes(&expected_raw),
            })),
            false,
            true,
        ));
    }

    Ok(failed_outcome(
        plan,
        FAILURE_TIMEOUT,
        vec!["timed out waiting for SSDP notification".to_string()],
        Some(json!({
            "capture_filter": capture_filter,
            "expected_raw_hex": hex_bytes(&expected_raw),
        })),
        false,
        false,
    ))
}

pub fn ssdp_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source_port = required_u16(plan.source_port, "source_port")?;
    let destination_port = required_u16(plan.destination_port, "destination_port")?;
    let udp = Udp::new().sport(source_port).dport(destination_port);
    let message = ssdp_payload(plan)?;

    if plan.source_ipv6.is_some() || plan.destination_ipv6.is_some() {
        let source: Ipv6Addr = required_str(plan.source_ipv6.as_deref(), "source_ipv6")?.parse()?;
        let destination: Ipv6Addr =
            required_str(plan.destination_ipv6.as_deref(), "destination_ipv6")?.parse()?;
        let hop_limit = if destination == SSDP_IPV6_LINK_LOCAL_MULTICAST_ADDR {
            SSDP_IPV6_LINK_LOCAL_HOP_LIMIT
        } else {
            SSDP_IPV6_SITE_LOCAL_HOP_LIMIT
        };
        return Ok(ssdp_ipv6_multicast_packet_with(
            source,
            destination,
            hop_limit,
            udp,
            message,
        ));
    }

    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    Ok(ssdp_ipv4_multicast_packet_with(
        source,
        destination,
        SSDP_IPV4_MULTICAST_TTL,
        udp,
        message,
    ))
}

pub fn validate_ssdp_candidate(
    plan: &ProbePlan,
    packet: &Packet,
    raw: &[u8],
) -> ExampleResult<CandidateValidation> {
    let Some(udp) = packet.layer::<Udp>() else {
        return Ok(CandidateValidation::Ignore);
    };

    let mut peer_mismatches = Vec::new();
    if plan.source_ipv6.is_some() || plan.destination_ipv6.is_some() {
        validate_ipv6_peer(plan, packet, &mut peer_mismatches)?;
    } else {
        validate_ipv4_peer(plan, packet, &mut peer_mismatches)?;
    }

    let expected_source_port = expected_response_source_port(plan)?;
    let expected_destination_port = expected_response_destination_port(plan)?;
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

    let decoded = decoded_ssdp_packet_json(packet, raw);
    if !peer_mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPeer(json!({
            "packet": decoded,
            "mismatches": peer_mismatches,
        })));
    }

    let Some(ssdp) = packet.layer::<Ssdp>() else {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": [{
                "field": "ssdp",
                "expected": "decoded SSDP layer",
                "actual": "missing",
            }],
        })));
    };

    let actual_payload = ssdp.to_bytes();
    let expected_payload = expected_ssdp_payload(plan)?;
    if actual_payload != expected_payload {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "ssdp": ssdp_json(ssdp),
            "mismatches": [{
                "field": "ssdp.payload_hex",
                "expected": hex_bytes(&expected_payload),
                "actual": hex_bytes(&actual_payload),
            }],
        })));
    }

    Ok(CandidateValidation::Passed(decoded))
}

pub fn ssdp_json(ssdp: &Ssdp) -> Value {
    let start_line = ssdp.message().start_line();
    let start_line_json = if let Some(request) = start_line.as_request() {
        json!({
            "kind": "request",
            "method": request.method().as_str(),
            "request_target": request.target().as_str(),
            "version": request.version().as_str(),
            "line": format!(
                "{} {} {}",
                request.method(),
                request.target(),
                request.version()
            ),
        })
    } else if let Some(response) = start_line.as_response() {
        json!({
            "kind": "response",
            "version": response.version().as_str(),
            "status_code": response.code().code(),
            "reason_phrase": response.reason().as_str(),
            "line": format!(
                "{} {} {}",
                response.version(),
                response.code(),
                response.reason()
            ),
        })
    } else {
        json!({})
    };

    json!({
        "summary": ssdp.summary(),
        "start_line": start_line_json,
        "headers": ssdp
            .headers()
            .iter()
            .map(|header| {
                let value = header.value().as_bytes();
                json!({
                    "name": header.name().original(),
                    "canonical_name": header.name().canonical_name(),
                    "value": String::from_utf8_lossy(value),
                    "value_hex": hex_bytes(value),
                })
            })
            .collect::<Vec<_>>(),
        "header_count": ssdp.headers().len(),
        "body_len": ssdp.body().len(),
        "body_hex": hex_bytes(ssdp.body()),
        "payload_hex": hex_bytes(&ssdp.to_bytes()),
    })
}

fn ssdp_payload(plan: &ProbePlan) -> ExampleResult<Ssdp> {
    let payload_hex = required_str(
        plan.payload_hex
            .as_deref()
            .or(plan.udp_payload_hex.as_deref()),
        "payload_hex",
    )?;
    let payload = decode_hex(payload_hex)?;
    Ok(Ssdp::parse(&payload)?)
}

fn expected_ssdp_payload(plan: &ProbePlan) -> ExampleResult<Vec<u8>> {
    let expected_payload_hex = required_str(
        plan.expected_payload_hex
            .as_deref()
            .or(plan.payload_hex.as_deref()),
        "expected_payload_hex",
    )?;
    decode_hex(expected_payload_hex)
}

fn ssdp_payload_json(plan: &ProbePlan) -> ExampleResult<Value> {
    Ok(ssdp_json(&ssdp_payload(plan)?))
}

fn expected_ssdp_payload_json(plan: &ProbePlan) -> ExampleResult<Value> {
    let payload = expected_ssdp_payload(plan)?;
    Ok(ssdp_json(&Ssdp::parse(&payload)?))
}

fn decoded_ssdp_packet_json(packet: &Packet, raw: &[u8]) -> Value {
    let mut decoded = decoded_packet_json(packet, raw);
    if let Value::Object(map) = &mut decoded {
        map.insert(
            "ssdp".into(),
            packet.layer::<Ssdp>().map(ssdp_json).unwrap_or(Value::Null),
        );
    }
    decoded
}

fn ssdp_capture_filter(plan: &ProbePlan) -> ExampleResult<String> {
    if plan.source_ipv6.is_some() || plan.destination_ipv6.is_some() {
        return Ok(format!(
            "ip6 and udp and src host {} and dst host {} and src port {} and dst port {}",
            required_str(
                plan.expected_reply_source_ipv6.as_deref(),
                "expected_reply_source_ipv6"
            )?,
            required_str(
                plan.expected_reply_destination_ipv6.as_deref(),
                "expected_reply_destination_ipv6"
            )?,
            expected_response_source_port(plan)?,
            expected_response_destination_port(plan)?,
        ));
    }

    Ok(format!(
        "udp and src host {} and dst host {} and src port {} and dst port {}",
        expected_response_source_ipv4(plan)?,
        expected_response_destination_ipv4(plan)?,
        expected_response_source_port(plan)?,
        expected_response_destination_port(plan)?,
    ))
}

fn validate_ipv4_peer(
    plan: &ProbePlan,
    packet: &Packet,
    mismatches: &mut Vec<Value>,
) -> ExampleResult<()> {
    let expected_source: Ipv4Addr = expected_response_source_ipv4(plan)?.parse()?;
    let expected_destination: Ipv4Addr = expected_response_destination_ipv4(plan)?.parse()?;
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
    Ok(())
}

fn validate_ipv6_peer(
    plan: &ProbePlan,
    packet: &Packet,
    mismatches: &mut Vec<Value>,
) -> ExampleResult<()> {
    let expected_source: Ipv6Addr = required_str(
        plan.expected_reply_source_ipv6.as_deref(),
        "expected_reply_source_ipv6",
    )?
    .parse()?;
    let expected_destination: Ipv6Addr = required_str(
        plan.expected_reply_destination_ipv6.as_deref(),
        "expected_reply_destination_ipv6",
    )?
    .parse()?;
    match packet.layer::<Ipv6>() {
        Some(ipv6) => {
            if ipv6.source() != expected_source {
                mismatches.push(json!({
                    "field": "ipv6.src",
                    "expected": expected_source.to_string(),
                    "actual": ipv6.source().to_string(),
                }));
            }
            if ipv6.destination() != expected_destination {
                mismatches.push(json!({
                    "field": "ipv6.dst",
                    "expected": expected_destination.to_string(),
                    "actual": ipv6.destination().to_string(),
                }));
            }
        }
        None => mismatches.push(json!({
            "field": "ipv6",
            "expected": "present",
            "actual": "missing",
        })),
    }
    Ok(())
}

fn expected_response_source_ipv4(plan: &ProbePlan) -> ExampleResult<&str> {
    if plan.case == "ssdp-notify-capture" {
        return required_str(plan.source_ipv4.as_deref(), "source_ipv4");
    }
    required_str(
        plan.expected_reply_source_ipv4.as_deref(),
        "expected_reply_source_ipv4",
    )
}

fn expected_response_destination_ipv4(plan: &ProbePlan) -> ExampleResult<&str> {
    if plan.case == "ssdp-notify-capture" {
        return required_str(plan.destination_ipv4.as_deref(), "destination_ipv4");
    }
    required_str(
        plan.expected_reply_destination_ipv4.as_deref(),
        "expected_reply_destination_ipv4",
    )
}

fn expected_response_source_port(plan: &ProbePlan) -> ExampleResult<u16> {
    if plan.case == "ssdp-notify-capture" {
        return required_u16(plan.source_port, "source_port");
    }
    required_u16(plan.destination_port, "destination_port")
}

fn expected_response_destination_port(plan: &ProbePlan) -> ExampleResult<u16> {
    if plan.case == "ssdp-notify-capture" {
        return required_u16(plan.destination_port, "destination_port");
    }
    required_u16(plan.source_port, "source_port")
}

fn network_layer(plan: &ProbePlan) -> NetworkLayer {
    if plan.source_ipv6.is_some() || plan.destination_ipv6.is_some() {
        NetworkLayer::Ipv6
    } else {
        NetworkLayer::Ipv4
    }
}

fn ssdp_target_service_json(plan: &ProbePlan) -> Value {
    plan.target_service.clone().unwrap_or_else(|| json!({}))
}
