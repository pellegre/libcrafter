//! RIP probe case `rip-update-v2`: send a RIPv2 whole-table request over
//! UDP/520 to a controlled FRR `ripd` peer and validate the daemon's RIPv2
//! Response (peer tuple, the RIP Response command, and the advertised route
//! entries decoded out of the response).
//!
//! The dry-run path compiles the stimulus request with libcrafter and reports a
//! `planned` outcome without placing any traffic on the wire; the live path is
//! reached only under an explicit `--live` invocation by the probe runner.

use crafter::prelude::*;
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::common::{
    capture_filter, captured_data, decoded_packet_json, failed_outcome, hex_bytes,
    observed_response, open_capture_sniffer, plan_json, required_str, required_u16,
    send_report_json, target_service_json, CandidateValidation, ExampleResult, ProbeOutcome,
    ProbePlan, StimulusEndpointRequest, FAILURE_DECODE_FAILED, FAILURE_TIMEOUT,
    FAILURE_WRONG_PAYLOAD, FAILURE_WRONG_PEER,
};

pub fn run_rip_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = rip_packet(plan)?;
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

pub fn run_rip_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = rip_packet(plan)?;
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
        match validate_rip_candidate(plan, captured.packet(), captured_data(&captured))? {
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
            vec!["captured RIP response was not a RIPv2 Response message".to_string()],
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
            vec!["captured RIP response did not match expected peer or ports".to_string()],
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
        vec!["timed out waiting for RIP response".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter(plan),
        })),
        sent,
        false,
    ))
}

/// Build the IPv4/UDP/RIP stimulus packet for the `rip-update-v2` case: a RIPv2
/// whole-table Request (RFC 2453 §3.9.1) carrying the single AFI-0 / metric-16
/// sentinel entry, sent on UDP/520 from the plan's documentation-range source to
/// the controlled `ripd` peer.
///
/// The convenience builders `rip_v2_whole_table_request` /
/// `rip_v2_multicast_response` target the 224.0.0.9 multicast group; this case
/// drives the daemon directly on its unicast address, so the stack is assembled
/// from the prelude `Rip`/`RipEntry` builders against the plan's peer tuple.
/// Lengths, ports beyond the RIP fields, and checksums are filled by
/// `compile()`.
pub fn rip_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    let source_port = plan.source_port.unwrap_or(RIP_UDP_PORT);
    let destination_port = plan.destination_port.unwrap_or(RIP_UDP_PORT);
    Ok(Ipv4::new().src(source).dst(destination)
        / Udp::new().sport(source_port).dport(destination_port)
        / Rip::request()
            .version(RIP_VERSION_2)
            .entry(RipEntry::whole_table_request()))
}

/// Validate a captured datagram against the `rip-update-v2` contract: the reply
/// must come from the expected peer tuple (`ripd` daemon -> stimulus over
/// UDP/520) and decode to a RIPv2 Response message.
pub fn validate_rip_candidate(
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
    let expected_source_port = plan.destination_port.unwrap_or(RIP_UDP_PORT);
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

    let Some(rip) = packet.layer::<Rip>() else {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": [{
                "field": "rip",
                "expected": "present",
                "actual": "missing",
            }],
        })));
    };

    let mut mismatches = Vec::new();
    if rip.command_value() != RIP_COMMAND_RESPONSE {
        mismatches.push(json!({
            "field": "rip.command",
            "expected": RIP_COMMAND_RESPONSE,
            "actual": rip.command_value(),
        }));
    }
    if rip.version_value() != RIP_VERSION_2 {
        mismatches.push(json!({
            "field": "rip.version",
            "expected": RIP_VERSION_2,
            "actual": rip.version_value(),
        }));
    }

    if !mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": mismatches,
            "rip": rip_json(rip),
        })));
    }

    Ok(CandidateValidation::Passed(json!({
        "packet": decoded,
        "rip": rip_json(rip),
    })))
}

/// JSON view of a decoded RIP layer (command, version, and the per-entry route
/// table) for the observed-response report.
pub fn rip_json(rip: &Rip) -> Value {
    json!({
        "command": rip.command_value(),
        "version": rip.version_value(),
        "entries": rip
            .entries()
            .iter()
            .map(|entry| json!({
                "address_family": entry.address_family_value(),
                "route_tag": entry.route_tag_value(),
                "address": entry.address_value().to_string(),
                "subnet_mask": entry.subnet_mask_value().to_string(),
                "next_hop": entry.next_hop_value().to_string(),
                "metric": entry.metric_value(),
            }))
            .collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    fn rip_plan() -> ProbePlan {
        let mut plan = base_plan("rip-update-v2");
        plan.source_ipv4 = Some("192.0.2.10".to_string());
        plan.destination_ipv4 = Some("192.0.2.20".to_string());
        plan.expected_reply_source_ipv4 = Some("192.0.2.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("192.0.2.10".to_string());
        plan.source_port = Some(42000);
        plan.destination_port = Some(RIP_UDP_PORT);
        plan
    }

    #[test]
    fn rip_packet_requires_source_ipv4() {
        let mut plan = rip_plan();
        plan.source_ipv4 = None;
        let err = rip_packet(&plan).unwrap_err().to_string();
        assert!(err.contains("source_ipv4"), "got: {err}");
    }

    #[test]
    fn rip_packet_builds_v2_whole_table_request() {
        let plan = rip_plan();
        let packet = rip_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();

        let udp = decoded.layer::<Udp>().expect("udp layer present");
        assert_eq!(udp.source_port_value(), 42000);
        assert_eq!(udp.destination_port_value(), RIP_UDP_PORT);

        let rip = decoded.layer::<Rip>().expect("rip layer present");
        assert_eq!(rip.command_value(), RIP_COMMAND_REQUEST);
        assert_eq!(rip.version_value(), RIP_VERSION_2);
        assert_eq!(rip.entries().len(), 1);
        assert_eq!(rip.entries()[0].metric_value(), RIP_METRIC_INFINITY);
    }

    #[test]
    fn validate_rip_candidate_accepts_v2_response() {
        let plan = rip_plan();
        let response = (Ipv4::new()
            .src("192.0.2.20".parse::<Ipv4Addr>().unwrap())
            .dst("192.0.2.10".parse::<Ipv4Addr>().unwrap())
            / Udp::new().sport(RIP_UDP_PORT).dport(42000)
            / Rip::response()
                .version(RIP_VERSION_2)
                .entry(RipEntry::ipv2_route(
                    "198.51.100.0".parse::<Ipv4Addr>().unwrap(),
                    "255.255.255.0".parse::<Ipv4Addr>().unwrap(),
                    1,
                )))
        .compile()
        .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, response.as_bytes()).unwrap();

        let validation = validate_rip_candidate(&plan, &decoded, response.as_bytes()).unwrap();
        assert!(matches!(validation, CandidateValidation::Passed(_)));
    }

    #[test]
    fn validate_rip_candidate_rejects_wrong_peer() {
        let plan = rip_plan();
        let response = (Ipv4::new()
            .src("198.51.100.1".parse::<Ipv4Addr>().unwrap())
            .dst("192.0.2.10".parse::<Ipv4Addr>().unwrap())
            / Udp::new().sport(RIP_UDP_PORT).dport(42000)
            / Rip::response().version(RIP_VERSION_2))
        .compile()
        .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, response.as_bytes()).unwrap();

        let validation = validate_rip_candidate(&plan, &decoded, response.as_bytes()).unwrap();
        assert!(matches!(validation, CandidateValidation::WrongPeer(_)));
    }
}
