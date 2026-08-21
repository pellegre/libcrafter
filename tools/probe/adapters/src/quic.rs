//! QUIC behavioral probe cases.
//!
//! The live-capable QUIC probe sends one IPv4/UDP datagram carrying a
//! raw-preserving [`Quic`] layer to a controlled UDP echo target. More advanced
//! QUIC observations remain planned-only until a stateful QUIC target is
//! available.

use crafter::prelude::*;
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::common::{
    capture_filter, captured_data, decode_hex, decoded_packet_json, failed_outcome, hex_bytes,
    observed_response, open_capture_sniffer, peer_contract_json, plan_json, raw_payload,
    required_str, required_u16, send_report_json, CandidateValidation, ExampleResult, ProbeOutcome,
    ProbePlan, StimulusEndpointRequest, FAILURE_DECODE_FAILED, FAILURE_TIMEOUT,
    FAILURE_WRONG_PAYLOAD, FAILURE_WRONG_PEER,
};

pub fn run_quic_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = quic_packet(plan)?;
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
            "quic_payload_hex": quic_payload_hex(plan)?,
            "capture_filter": capture_filter(plan),
            "peer_contract": peer_contract_json(plan),
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
            "quic_payload_hex": quic_payload_hex(plan)?,
            "capture_filter": capture_filter(plan),
            "peer_contract": peer_contract_json(plan),
        }
    });
    Ok(ProbeOutcome {
        result,
        observed_response: observed,
        sent: false,
        received: false,
    })
}

pub fn run_quic_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = quic_packet(plan)?;
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
            .network_layer(),
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
    let mut wrong_peer = Vec::new();
    let mut wrong_payload = Vec::new();

    while let Some(captured) = match sniffer.next_record() {
        Ok(packet) => packet,
        Err(err) => {
            return Ok(failed_outcome(
                plan,
                FAILURE_DECODE_FAILED,
                vec![format!("capture decode failed: {err}")],
                None,
                true,
                false,
            ));
        }
    } {
        match validate_quic_candidate(plan, captured.packet(), captured_data(&captured))? {
            CandidateValidation::Passed(decoded) => {
                let raw_hex = hex_bytes(captured_data(&captured));
                let observed = observed_response(
                    plan,
                    true,
                    Some(raw_hex.clone()),
                    decoded.clone(),
                    json!({
                        "capture_filter": capture_filter(plan),
                        "peer_contract": peer_contract_json(plan),
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
                        "send_report": send_report_json(&send_report),
                        "capture_filter": capture_filter(plan),
                        "peer_contract": peer_contract_json(plan),
                        "received_raw_hex": raw_hex,
                        "received_decoded": decoded,
                    }
                });
                return Ok(ProbeOutcome {
                    result,
                    observed_response: observed,
                    sent: true,
                    received: true,
                });
            }
            CandidateValidation::WrongPeer(detail) => wrong_peer.push(detail),
            CandidateValidation::WrongPayload(detail) => wrong_payload.push(detail),
            CandidateValidation::Ignore => {}
        }
    }

    let reason = if !wrong_payload.is_empty() {
        FAILURE_WRONG_PAYLOAD
    } else if !wrong_peer.is_empty() {
        FAILURE_WRONG_PEER
    } else {
        FAILURE_TIMEOUT
    };
    Ok(failed_outcome(
        plan,
        reason,
        vec!["captured QUIC/UDP echo response did not match expected peer or payload".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "wrong_peer": wrong_peer,
            "wrong_payload": wrong_payload,
            "capture_filter": capture_filter(plan),
        })),
        true,
        false,
    ))
}

pub fn quic_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    let source_port = required_u16(plan.source_port, "source_port")?;
    let destination_port = required_u16(plan.destination_port, "destination_port")?;
    let payload = decode_hex(quic_payload_hex(plan)?)?;
    Ok(Ipv4::new().src(source).dst(destination)
        / Udp::new()
            .source_port(source_port)
            .destination_port(destination_port)
        / Quic::from_bytes(payload))
}

pub fn quic_json(layer: &Quic) -> Value {
    let bytes = quic_layer_bytes(layer);
    json!({
        "raw_len": layer.len(),
        "packet_count": layer.packets().len(),
        "payload_hex": hex_bytes(&bytes),
        "summary": layer.summary(),
    })
}

fn validate_quic_candidate(
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

    let expected_payload = decode_hex(quic_payload_hex(plan)?)?;
    let actual_payload = packet
        .layer::<Quic>()
        .map(quic_layer_bytes)
        .unwrap_or_else(|| raw_payload(packet).to_vec());
    let mut mismatches = Vec::new();
    if actual_payload.as_slice() != expected_payload.as_slice() {
        mismatches.push(json!({
            "field": "quic.payload",
            "expected": hex_bytes(&expected_payload),
            "actual": hex_bytes(&actual_payload),
        }));
    }
    if let Some(expected_length) = plan
        .quic_payload_length
        .or(plan.udp_payload_length)
        .or(plan.payload_length)
    {
        if actual_payload.len() != expected_length {
            mismatches.push(json!({
                "field": "quic.payload_length",
                "expected": expected_length,
                "actual": actual_payload.len(),
            }));
        }
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

    if mismatches.is_empty() {
        Ok(CandidateValidation::Passed(decoded))
    } else {
        Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": mismatches,
        })))
    }
}

fn quic_payload_hex(plan: &ProbePlan) -> ExampleResult<&str> {
    plan.quic_payload_hex
        .as_deref()
        .or(plan.udp_payload_hex.as_deref())
        .or(plan.payload_hex.as_deref())
        .ok_or_else(|| "probe plan missing required field quic_payload_hex".into())
}

fn quic_layer_bytes(layer: &Quic) -> Vec<u8> {
    if layer.packets().is_empty() {
        layer.payload_bytes().to_vec()
    } else {
        layer
            .packets()
            .iter()
            .flat_map(|packet| packet.as_bytes().iter().copied())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    fn initial_plan() -> ProbePlan {
        let mut plan = base_plan("quic-initial-udp-observation");
        plan.source_ipv4 = Some("192.0.2.10".to_string());
        plan.destination_ipv4 = Some("192.0.2.20".to_string());
        plan.expected_reply_source_ipv4 = Some("192.0.2.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("192.0.2.10".to_string());
        plan.source_port = Some(49152);
        plan.destination_port = Some(4433);
        plan.quic_payload_hex = Some("c000000001048394c8f001aa000301beef".to_string());
        plan.quic_payload_length = Some(17);
        plan.udp_payload_hex = plan.quic_payload_hex.clone();
        plan.udp_payload_length = Some(17);
        plan.expected_udp_length = Some(25);
        plan
    }

    #[test]
    fn quic_packet_builds_ipv4_udp_quic_stack() {
        let packet = quic_packet(&initial_plan()).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        assert!(decoded.layer::<Ipv4>().is_some());
        assert_eq!(
            decoded.layer::<Udp>().unwrap().destination_port_value(),
            4433
        );
        let quic = decoded.layer::<Quic>().expect("QUIC layer");
        assert_eq!(
            quic_layer_bytes(quic),
            decode_hex(quic_payload_hex(&initial_plan()).unwrap()).unwrap()
        );
    }

    #[test]
    fn quic_candidate_validation_accepts_echoed_payload() {
        let plan = initial_plan();
        let payload = decode_hex(quic_payload_hex(&plan).unwrap()).unwrap();
        let response = (Ipv4::new()
            .src("192.0.2.20".parse::<Ipv4Addr>().unwrap())
            .dst("192.0.2.10".parse::<Ipv4Addr>().unwrap())
            / Udp::new().source_port(4433).destination_port(49152)
            / Quic::from_bytes(payload))
        .compile()
        .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, response.as_bytes()).unwrap();
        assert!(matches!(
            validate_quic_candidate(&plan, &decoded, response.as_bytes()).unwrap(),
            CandidateValidation::Passed(_)
        ));
    }
}
