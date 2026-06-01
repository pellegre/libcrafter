//! ICMP probe cases: `icmp-echo` (echo request / echo reply) and
//! `ttl-expired` (low-TTL echo request triggering an ICMP time exceeded with
//! the embedded original packet prefix).

use crafter::prelude::*;
use serde_json::json;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::common::{
    capture_filter, decode_hex, decoded_packet_json, failed_outcome, hex_bytes, observed_response,
    plan_json, raw_payload, required_str, required_u16, send_report_json, CandidateValidation,
    ExampleResult, ProbeOutcome, ProbePlan, StimulusEndpointRequest, FAILURE_DECODE_FAILED,
    FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD, FAILURE_WRONG_PEER,
};

pub fn run_icmp_dry_run(
    request: &StimulusEndpointRequest,
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

pub fn run_icmp_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = icmp_packet(plan)?;
    let timeout = Duration::from_secs(request.timeout_seconds.max(1));
    let mut sniffer = match Sniffer::interface(request.interface.clone())
        .timeout(timeout)
        .count(32)
        .filter("icmp")
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

pub fn run_ttl_expired_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = ttl_expired_packet(plan)?;
    let report = SocketSender::new(
        SendOptions::new()
            .iface(request.interface.clone())
            .network_layer()
            .dry_run(),
    )
    .send(&packet)?;
    let sent_raw = report.plan().bytes();
    let sent_raw_hex = hex_bytes(sent_raw);
    let embedded_prefix = expected_embedded_prefix(plan, sent_raw)?;
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
            "capture_filter": capture_filter(plan),
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

pub fn run_ttl_expired_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = ttl_expired_packet(plan)?;
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
    let embedded_prefix = expected_embedded_prefix(plan, send_report.plan().bytes())?;
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
        match validate_ttl_expired_candidate(
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
                "captured ICMP time exceeded did not include the expected embedded packet prefix"
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
                "captured ICMP time exceeded did not match expected router or destination"
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
        vec!["timed out waiting for ICMP time exceeded".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter(plan),
            "expected_embedded_prefix_hex": hex_bytes(&embedded_prefix),
        })),
        sent,
        false,
    ))
}

pub fn validate_icmp_candidate(
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

pub fn validate_ttl_expired_candidate(
    plan: &ProbePlan,
    packet: &Packet,
    raw: &[u8],
    expected_embedded_prefix: &[u8],
) -> ExampleResult<CandidateValidation> {
    let Some(icmp) = packet.layer::<Icmp>() else {
        return Ok(CandidateValidation::Ignore);
    };
    let expected_type = plan.expected_icmp_type.unwrap_or(ICMP_TIME_EXCEEDED);
    if icmp.icmp_type_value() != expected_type {
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
    let expected_code = plan.expected_icmp_code.unwrap_or(0);
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

    let decoded = decoded_packet_json(packet, raw);
    if !peer_mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPeer(json!({
            "packet": decoded,
            "mismatches": peer_mismatches,
        })));
    }

    let mut payload_mismatches = Vec::new();
    if icmp.code_value() != expected_code {
        payload_mismatches.push(json!({
            "field": "icmp.code",
            "expected": expected_code,
            "actual": icmp.code_value(),
        }));
    }

    let embedded = icmp_embedded_payload(packet)?;
    if !embedded.starts_with(expected_embedded_prefix) {
        payload_mismatches.push(json!({
            "field": "icmp.embedded_prefix",
            "expected": hex_bytes(expected_embedded_prefix),
            "actual": hex_bytes(&embedded[..embedded.len().min(expected_embedded_prefix.len())]),
        }));
    }

    if !payload_mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": payload_mismatches,
        })));
    }

    Ok(CandidateValidation::Passed(decoded))
}

fn icmp_embedded_payload(packet: &Packet) -> ExampleResult<Vec<u8>> {
    if let Some(raw) = packet.layer::<Raw>() {
        return Ok(raw.as_bytes().to_vec());
    }
    if let Some(quoted) = packet.layer::<IcmpQuotedIpv4>() {
        let compiled = quoted.datagram().compile()?;
        return Ok(compiled.as_bytes().to_vec());
    }
    Ok(Vec::new())
}

pub fn icmp_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
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

pub fn ttl_expired_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    let payload = decode_hex(required_str(plan.payload_hex.as_deref(), "payload_hex")?)?;
    let identifier = required_u16(plan.identifier, "identifier")?;
    let sequence_number = required_u16(plan.sequence_number, "sequence_number")?;
    Ok(Ipv4::new()
        .src(source)
        .dst(destination)
        .ttl(plan.ttl.unwrap_or(1))
        / Icmp::echo_request().id(identifier).seq(sequence_number)
        / Raw::from_bytes(payload))
}

pub fn expected_embedded_prefix(plan: &ProbePlan, sent_raw: &[u8]) -> ExampleResult<Vec<u8>> {
    if let Some(expected_hex) = plan
        .expected_embedded_prefix_hex
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        return decode_hex(expected_hex);
    }
    let prefix_len = plan
        .expected_embedded_prefix_length
        .unwrap_or(28)
        .min(sent_raw.len());
    Ok(sent_raw[..prefix_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    #[test]
    fn icmp_packet_requires_source() {
        let plan = base_plan("icmp-echo");
        let err = icmp_packet(&plan).unwrap_err().to_string();
        assert!(err.contains("source_ipv4"), "got: {err}");
    }

    #[test]
    fn icmp_packet_compiles_in_dry_run() {
        let mut plan = base_plan("icmp-echo");
        plan.source_ipv4 = Some("192.0.2.1".to_string());
        plan.destination_ipv4 = Some("192.0.2.2".to_string());
        plan.identifier = Some(0x1234);
        plan.sequence_number = Some(1);
        plan.payload_hex = Some("6162".to_string());
        let packet = icmp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        assert!(bytes.len() >= 28, "icmp packet too short: {}", bytes.len());
        assert!(packet.layer::<Icmp>().is_some());
    }

    #[test]
    fn embedded_prefix_defaults_to_first_28_bytes() {
        let plan = base_plan("ttl-expired");
        let sent = (0u8..40).collect::<Vec<_>>();
        let prefix = expected_embedded_prefix(&plan, &sent).unwrap();
        assert_eq!(prefix.len(), 28);
        assert_eq!(prefix, sent[..28]);
    }

    #[test]
    fn embedded_prefix_honors_explicit_hex() {
        let mut plan = base_plan("ttl-expired");
        plan.expected_embedded_prefix_hex = Some("deadbeef".to_string());
        let prefix = expected_embedded_prefix(&plan, &[0u8; 64]).unwrap();
        assert_eq!(prefix, vec![0xde, 0xad, 0xbe, 0xef]);
    }
}
