//! UDP behavioral probe cases.
//!
//! `udp-echo-empty`, `udp-echo-short`, `udp-echo-binary`, `udp-echo-large`, and
//! `udp-source-port-reflection` send IPv4/UDP datagrams to a controlled
//! target-side UDP echo responder, then validate the decoded UDP response's peer
//! tuple, length, checksum status, and exact echoed payload.

use crafter::prelude::*;
use serde_json::json;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::common::{
    capture_filter, decode_hex, decoded_packet_json, failed_outcome, hex_bytes, observed_response,
    plan_json, raw_payload, required_str, required_u16, send_report_json, target_service_json,
    CandidateValidation, ExampleResult, ProbeOutcome, ProbePlan, StimulusEndpointRequest,
    FAILURE_DECODE_FAILED, FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD, FAILURE_WRONG_PEER,
};

pub fn run_udp_dry_run(
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
    let packet = Ipv4::new().src(source).dst(destination)
        / Udp::new()
            .source_port(source_port)
            .destination_port(destination_port);
    if payload.is_empty() {
        Ok(packet)
    } else {
        Ok(packet / Raw::from_bytes(payload))
    }
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
    let actual_payload = raw_payload(packet);
    let mut mismatches = Vec::new();

    if actual_payload != expected_payload.as_slice() {
        mismatches.push(json!({
            "field": "udp.payload",
            "expected": hex_bytes(&expected_payload),
            "actual": hex_bytes(actual_payload),
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

pub const fn checksum_status_name(status: UdpChecksumStatus) -> &'static str {
    match status {
        UdpChecksumStatus::NotChecked => "not_checked",
        UdpChecksumStatus::Ipv4NoChecksum => "ipv4_no_checksum",
        UdpChecksumStatus::Valid => "valid",
        UdpChecksumStatus::Invalid => "invalid",
        UdpChecksumStatus::Ipv6ZeroChecksum => "ipv6_zero_checksum",
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

    fn large_echo_plan() -> ProbePlan {
        let payload = (0..1200)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        echo_plan("udp-echo-large", &payload)
    }

    fn source_port_reflection_plan() -> ProbePlan {
        let mut plan = echo_plan("udp-source-port-reflection", b"udp-source-port:1234abcd");
        plan.source_port = Some(62044);
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
}
