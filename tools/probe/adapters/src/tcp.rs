//! TCP probe cases: `tcp-syn-open` (expect SYN/ACK from a listening port) and
//! `tcp-syn-closed` (expect RST from a closed port).

use crafter::prelude::*;
use serde_json::json;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::common::{
    capture_filter, decoded_packet_json, expected_response, failed_outcome, flag_mismatch,
    hex_bytes, observed_response, plan_json, required_str, required_u16, required_u32,
    send_report_json, target_service_json, CandidateValidation, ExampleResult, ProbeOutcome,
    ProbePlan, StimulusEndpointRequest, FAILURE_DECODE_FAILED, FAILURE_TIMEOUT,
    FAILURE_WRONG_FLAGS, FAILURE_WRONG_PEER,
};

pub fn run_tcp_dry_run(
    request: &StimulusEndpointRequest,
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

pub fn run_tcp_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = tcp_packet(plan)?;
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

pub fn validate_tcp_candidate(
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

pub fn tcp_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    #[test]
    fn tcp_packet_requires_sequence_number() {
        let mut plan = base_plan("tcp-syn-open");
        plan.source_ipv4 = Some("192.0.2.1".to_string());
        plan.destination_ipv4 = Some("192.0.2.2".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(80);
        let err = tcp_packet(&plan).unwrap_err().to_string();
        assert!(err.contains("tcp_sequence_number"), "got: {err}");
    }

    #[test]
    fn tcp_packet_compiles_in_dry_run() {
        let mut plan = base_plan("tcp-syn-open");
        plan.source_ipv4 = Some("192.0.2.1".to_string());
        plan.destination_ipv4 = Some("192.0.2.2".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(80);
        plan.tcp_sequence_number = Some(0x1000);
        let packet = tcp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        assert!(bytes.len() >= 40, "tcp packet too short: {}", bytes.len());
        let tcp = packet.layer::<Tcp>().expect("tcp layer present");
        assert_eq!(tcp.flags_value() & TCP_FLAG_SYN, TCP_FLAG_SYN);
    }
}
