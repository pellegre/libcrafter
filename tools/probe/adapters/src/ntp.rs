//! NTP behavioral probe cases.
//!
//! The adapter materializes live-capable NTP probe plans as typed
//! libcrafter IPv4/UDP/NTP packets. It keeps dry-run output byte-inspectable and
//! reserves live sends for provider-backed stimulus endpoint invocations.

use crafter::prelude::*;
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::common::{
    captured_data, decode_hex, decoded_packet_json, failed_outcome, hex_bytes, observed_response,
    open_capture_sniffer, plan_json, required_str, required_u16, send_report_json,
    CandidateValidation, ExampleResult, ProbeOutcome, ProbePlan, StimulusEndpointRequest,
    FAILURE_DECODE_FAILED, FAILURE_TARGET_SETUP_FAILED, FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD,
    FAILURE_WRONG_PEER,
};

const NTP_PORT: u16 = 123;

pub fn is_live_capable_case(case: &str) -> bool {
    matches!(
        case,
        "ntp-client-server-exchange"
            | "ntp-kod-response"
            | "ntp-extension-preservation"
            | "ntp-nts-extension-plan"
    )
}

pub fn is_ntp_case(case: &str) -> bool {
    is_live_capable_case(case) || case == "ntp-malformed-observation"
}

pub fn run_ntp_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = ntp_packet(plan)?;
    let capture_filter = capture_filter(plan);
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
    let sent_decoded = decoded_ntp_packet_json(&sent_packet, sent_raw);
    let ntp = ntp_payload_json(plan)?;
    let expected_ntp = expected_ntp_payload_json(plan)?;
    let target_service = target_service_json(plan);
    let validation = validation_json(plan);
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
            "ntp": ntp,
            "expected_ntp": expected_ntp,
            "capture_filter": capture_filter,
            "target_service": target_service,
            "validation": validation,
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
            "ntp": ntp,
            "expected_ntp": expected_ntp,
            "capture_filter": capture_filter,
            "target_service": target_service,
            "validation": validation,
        }
    });
    Ok(ProbeOutcome {
        result,
        observed_response: observed,
        sent: false,
        received: false,
    })
}

pub fn run_ntp_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    if let Some(outcome) = provider_gate_failure(request, plan) {
        return Ok(outcome);
    }

    let packet = ntp_packet(plan)?;
    let capture_filter = capture_filter(plan);
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
        match validate_ntp_candidate(plan, captured.packet(), captured_data(&captured))? {
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
            vec!["captured NTP response did not match expected payload".to_string()],
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
            vec!["captured NTP response did not match expected peer or ports".to_string()],
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
        vec!["timed out waiting for NTP response".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter,
        })),
        sent,
        false,
    ))
}

pub fn ntp_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    let source_port = required_u16(plan.source_port, "source_port")?;
    let destination_port = required_u16(plan.destination_port, "destination_port")?;
    let ntp = ntp_payload(plan)?;

    Ok(Ipv4::new().src(source).dst(destination)
        / Udp::new().sport(source_port).dport(destination_port)
        / ntp)
}

pub fn validate_ntp_candidate(
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

    let decoded = decoded_ntp_packet_json(packet, raw);
    if !peer_mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPeer(json!({
            "packet": decoded,
            "mismatches": peer_mismatches,
        })));
    }

    let Some(ntp) = packet.layer::<Ntp>() else {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": [{
                "field": "ntp",
                "expected": "decoded NTP layer",
                "actual": "missing",
            }],
        })));
    };

    let expected_payload = expected_ntp_payload(plan)?;
    let actual_payload = ntp_payload_bytes(ntp)?;
    if actual_payload != expected_payload {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "ntp": ntp_json(ntp),
            "mismatches": [{
                "field": "ntp.payload_hex",
                "expected": hex_bytes(&expected_payload),
                "actual": hex_bytes(&actual_payload),
            }],
        })));
    }

    Ok(CandidateValidation::Passed(decoded))
}

pub fn ntp_json(ntp: &Ntp) -> Value {
    let stratum = ntp.stratum_value();
    let reference_id = ntp.reference_id_value();
    json!({
        "summary": ntp.summary(),
        "first_octet": format!("0x{:02x}", ntp.first_octet_value()),
        "leap_indicator": ntp.leap_indicator_value().label(),
        "version": ntp.version_value_effective().label(),
        "version_value": ntp.version_value_effective().value(),
        "mode": ntp.mode_value().label(),
        "mode_value": ntp.mode_value().value(),
        "stratum": stratum.value(),
        "stratum_label": stratum.label(),
        "poll": ntp.poll_value(),
        "precision": ntp.precision_value(),
        "root_delay_raw": ntp.root_delay_value().raw(),
        "root_dispersion_raw": ntp.root_dispersion_value().raw(),
        "reference_id": reference_id.label_for_stratum(stratum),
        "reference_id_ascii": reference_id.ascii_lossy(),
        "reference_id_hex": hex_bytes(&reference_id.bytes()),
        "reference_timestamp": format!("0x{:016x}", ntp.reference_timestamp_value().raw()),
        "origin_timestamp": format!("0x{:016x}", ntp.origin_timestamp_value().raw()),
        "receive_timestamp": format!("0x{:016x}", ntp.receive_timestamp_value().raw()),
        "transmit_timestamp": format!("0x{:016x}", ntp.transmit_timestamp_value().raw()),
        "extension_count": ntp.extension_fields_value().len(),
        "extensions": ntp
            .extension_fields_value()
            .iter()
            .map(extension_json)
            .collect::<Vec<_>>(),
        "legacy_mac": ntp.legacy_mac_value().map(|mac| json!({
            "length": mac.len(),
            "key_id_present": mac.key_id().is_some(),
            "digest_length": mac.digest().len(),
        })),
        "payload_hex": ntp_payload_bytes(ntp).map(|bytes| hex_bytes(&bytes)).unwrap_or_default(),
    })
}

pub fn capture_filter(plan: &ProbePlan) -> String {
    if let Some(filter) = plan
        .capture_filter
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        return filter.to_string();
    }

    format!(
        "udp and src host {} and dst host {} and src port {} and dst port {}",
        plan.expected_reply_source_ipv4.as_deref().unwrap_or(""),
        plan.expected_reply_destination_ipv4
            .as_deref()
            .unwrap_or(""),
        plan.destination_port.unwrap_or(NTP_PORT),
        plan.source_port.unwrap_or(0),
    )
}

pub fn target_service_json(plan: &ProbePlan) -> Value {
    plan.target_service.clone().unwrap_or_else(|| {
        json!({
            "required": true,
            "kind": "ntp-controlled-responder",
            "protocol": "udp",
            "port": plan.destination_port.unwrap_or(NTP_PORT),
            "bind_ipv4": plan.destination_ipv4,
            "source_ipv4": plan.source_ipv4,
            "live_requires_provider": true,
            "controlled_responder": true,
        })
    })
}

pub fn validation_json(plan: &ProbePlan) -> Value {
    json!({
        "expected_decode": if plan.case == "ntp-malformed-observation" {
            "structured_error"
        } else {
            "ntp"
        },
        "source_ipv4": plan.expected_reply_source_ipv4,
        "destination_ipv4": plan.expected_reply_destination_ipv4,
        "source_port": plan.destination_port,
        "destination_port": plan.source_port,
        "planned_only": true,
    })
}

fn ntp_payload(plan: &ProbePlan) -> ExampleResult<Ntp> {
    let payload_hex = required_str(
        plan.payload_hex
            .as_deref()
            .or(plan.udp_payload_hex.as_deref()),
        "payload_hex",
    )?;
    let payload = decode_hex(payload_hex)?;
    Ok(Ntp::decode(&payload)?)
}

fn expected_ntp_payload(plan: &ProbePlan) -> ExampleResult<Vec<u8>> {
    let expected_payload_hex = required_str(
        plan.expected_payload_hex
            .as_deref()
            .or(plan.payload_hex.as_deref()),
        "expected_payload_hex",
    )?;
    decode_hex(expected_payload_hex)
}

fn ntp_payload_json(plan: &ProbePlan) -> ExampleResult<Value> {
    Ok(ntp_json(&ntp_payload(plan)?))
}

fn expected_ntp_payload_json(plan: &ProbePlan) -> ExampleResult<Value> {
    Ok(ntp_json(&Ntp::decode(&expected_ntp_payload(plan)?)?))
}

fn decoded_ntp_packet_json(packet: &Packet, raw: &[u8]) -> Value {
    let mut decoded = decoded_packet_json(packet, raw);
    if let Value::Object(map) = &mut decoded {
        map.insert(
            "ntp".into(),
            packet.layer::<Ntp>().map(ntp_json).unwrap_or(Value::Null),
        );
    }
    decoded
}

fn extension_json(field: &NtpExtensionField) -> Value {
    let extension_type = field.extension_type();
    json!({
        "field_type": field.field_type(),
        "field_type_hex": format!("0x{:04x}", field.field_type()),
        "label": extension_type.label(),
        "category": extension_type.category().label(),
        "declared_length": field.declared_length_value(),
        "value_length": field.value().len(),
        "nts_extension": field.is_nts_extension(),
        "autokey_related": field.is_autokey_related(),
    })
}

fn ntp_payload_bytes(ntp: &Ntp) -> ExampleResult<Vec<u8>> {
    Ok(Packet::from_layer(ntp.clone())
        .compile()?
        .as_bytes()
        .to_vec())
}

fn provider_gate_failure(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> Option<ProbeOutcome> {
    let target_service = target_service_json(plan);
    let requires_provider = target_service
        .get("live_requires_provider")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if !requires_provider || provider_is_live_capable(&request.provider) {
        return None;
    }

    Some(failed_outcome(
        plan,
        FAILURE_TARGET_SETUP_FAILED,
        vec![format!(
            "NTP live stimulus requires provider-backed probe infrastructure; provider={} is not live-capable",
            request.provider
        )],
        Some(json!({
            "target_service": target_service,
            "provider": request.provider,
        })),
        false,
        false,
    ))
}

fn provider_is_live_capable(provider: &str) -> bool {
    !matches!(
        provider,
        "" | "local" | "local-dry-run" | "dry-run" | "offline"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    fn request_payload() -> Vec<u8> {
        Packet::from_layer(Ntp::client().transmit_timestamp(0x0102_0304_0506_0708u64))
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn response_payload() -> Vec<u8> {
        Packet::from_layer(
            Ntp::server()
                .reference_id(*b"GPS\0")
                .origin_timestamp(0x0102_0304_0506_0708u64)
                .receive_timestamp(0x1112_1314_1516_1718u64)
                .transmit_timestamp(0x2122_2324_2526_2728u64),
        )
        .compile()
        .unwrap()
        .as_bytes()
        .to_vec()
    }

    fn ntp_plan() -> ProbePlan {
        let mut plan = base_plan("ntp-client-server-exchange");
        plan.sequence = 4;
        plan.expected_response = Some("ntp_server_response".to_string());
        plan.source_ipv4 = Some("198.51.100.10".to_string());
        plan.destination_ipv4 = Some("198.51.100.130".to_string());
        plan.expected_reply_source_ipv4 = Some("198.51.100.130".to_string());
        plan.expected_reply_destination_ipv4 = Some("198.51.100.10".to_string());
        plan.source_port = Some(49152);
        plan.destination_port = Some(NTP_PORT);
        plan.payload_hex = Some(hex_bytes(&request_payload()));
        plan.expected_payload_hex = Some(hex_bytes(&response_payload()));
        plan.protocol = Some("ntp".to_string());
        plan.capture_filter = Some(
            "udp and src host 198.51.100.130 and dst host 198.51.100.10 and src port 123 and dst port 49152"
                .to_string(),
        );
        plan.target_service = Some(json!({
            "required": true,
            "kind": "ntp-controlled-responder",
            "protocol": "udp",
            "port": NTP_PORT,
            "live_requires_provider": true,
        }));
        plan
    }

    fn stimulus_request(plan: ProbePlan) -> StimulusEndpointRequest {
        StimulusEndpointRequest {
            provider: "local-dry-run".to_string(),
            profile: "ntp-smoke".to_string(),
            seed: 5905,
            endpoint_role: "stimulus".to_string(),
            interface: "lo".to_string(),
            local_ipv4: "198.51.100.10".to_string(),
            peer_ipv4: "198.51.100.130".to_string(),
            timeout_seconds: 1,
            probe_plans: vec![plan],
            artifact_paths: json!({}),
            metadata: json!({}),
        }
    }

    #[test]
    fn ntp_json_plan_deserializes_engine_shape() {
        let payload_hex = hex_bytes(&request_payload());
        let expected_payload_hex = hex_bytes(&response_payload());
        let request: StimulusEndpointRequest = serde_json::from_value(json!({
            "provider": "local-dry-run",
            "profile": "ntp-smoke",
            "seed": 5905,
            "endpoint_role": "stimulus",
            "interface": "lo",
            "local_ipv4": "198.51.100.10",
            "peer_ipv4": "198.51.100.130",
            "timeout_seconds": 1,
            "artifact_paths": {},
            "metadata": {},
            "probe_plans": [{
                "schema_version": 1,
                "case": "ntp-client-server-exchange",
                "sequence": 4,
                "protocol": "ntp",
                "source_ipv4": "198.51.100.10",
                "destination_ipv4": "198.51.100.130",
                "expected_reply_source_ipv4": "198.51.100.130",
                "expected_reply_destination_ipv4": "198.51.100.10",
                "source_port": 49152,
                "destination_port": NTP_PORT,
                "payload_hex": payload_hex,
                "udp_payload_hex": payload_hex,
                "expected_payload_hex": expected_payload_hex,
                "packet": {"stack": ["ipv4", "udp", "ntp"], "ntp": {"mode": "client"}},
                "ntp": {"mode": "client"},
                "expected_ntp": {"mode": "server"},
                "stimulus_driver": {"adapter_module": "tools/probe/adapters/src/ntp.rs"},
                "target_service": {"kind": "ntp-controlled-responder"}
            }]
        }))
        .unwrap();

        let plan = &request.probe_plans[0];
        assert_eq!(plan.case, "ntp-client-server-exchange");
        assert_eq!(plan.protocol.as_deref(), Some("ntp"));
        assert_eq!(plan.packet.as_ref().unwrap()["stack"][2], "ntp");
        assert_eq!(
            plan.target_service.as_ref().unwrap()["kind"],
            "ntp-controlled-responder"
        );
        assert_eq!(ntp_payload(plan).unwrap().mode_value(), NtpMode::Client);
    }

    #[test]
    fn ntp_packet_builds_ipv4_udp_ntp_stack() {
        let plan = ntp_plan();
        let packet = ntp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();

        let ipv4 = decoded.layer::<Ipv4>().expect("ipv4 layer");
        let udp = decoded.layer::<Udp>().expect("udp layer");
        let ntp = decoded.layer::<Ntp>().expect("ntp layer");
        assert_eq!(ipv4.source(), Ipv4Addr::new(198, 51, 100, 10));
        assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 130));
        assert_eq!(udp.source_port_value(), 49152);
        assert_eq!(udp.destination_port_value(), NTP_PORT);
        assert_eq!(ntp.mode_value(), NtpMode::Client);
        assert_eq!(ntp.transmit_timestamp_value().raw(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn ntp_dry_run_reports_decoded_plan() {
        let plan = ntp_plan();
        let request = stimulus_request(plan.clone());
        let outcome = run_ntp_dry_run(&request, &plan).unwrap();

        assert!(!outcome.sent);
        assert!(!outcome.received);
        assert_eq!(outcome.result["status"], "planned");
        assert_eq!(outcome.result["metadata"]["dry_run"], true);
        assert_eq!(
            outcome.result["metadata"]["sent_decoded"]["ntp"]["mode"],
            "client"
        );
        assert_eq!(outcome.result["metadata"]["expected_ntp"]["mode"], "server");
        assert_eq!(
            outcome.result["metadata"]["target_service"]["kind"],
            "ntp-controlled-responder"
        );
    }

    #[test]
    fn ntp_validate_accepts_matching_response() {
        let plan = ntp_plan();
        let response = Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 130))
            .dst(Ipv4Addr::new(198, 51, 100, 10))
            / Udp::new().sport(NTP_PORT).dport(49152)
            / Ntp::decode(&response_payload()).unwrap();
        let raw = response.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, raw.as_bytes()).unwrap();

        match validate_ntp_candidate(&plan, &decoded, raw.as_bytes()).unwrap() {
            CandidateValidation::Passed(decoded) => {
                assert_eq!(decoded["ntp"]["mode"], "server");
            }
            other => panic!("unexpected validation: {other:?}"),
        }
    }

    #[test]
    fn ntp_live_gate_blocks_local_provider_before_send() {
        let plan = ntp_plan();
        let request = stimulus_request(plan.clone());
        let outcome = run_ntp_live(&request, &plan).unwrap();

        assert_eq!(outcome.result["status"], "failed");
        assert_eq!(
            outcome.result["metadata"]["failure_reason"],
            FAILURE_TARGET_SETUP_FAILED
        );
        assert!(!outcome.sent);
    }
}
