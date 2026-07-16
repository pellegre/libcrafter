//! CoAP behavioral probe adapter.
//!
//! The admitted cases materialize the planner's datagram bytes as a typed
//! `Ipv4 / Udp / Coap` packet. Dry runs compile and decode that packet without
//! sending it. Live execution is additionally gated on provider-backed
//! infrastructure and `LIBCRAFTER_COAP_LIVE_CONFIRM=yes`, then captures only a
//! bounded response sequence from the controlled peer.

use crafter::prelude::*;
use serde_json::{json, Value};
use std::env;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::common::{
    captured_data, decode_hex, decoded_packet_json, failed_outcome, hex_bytes, observed_response,
    open_capture_sniffer, plan_json, required_str, required_u16, send_report_json,
    CandidateValidation, ExampleResult, ProbeOutcome, ProbePlan, StimulusEndpointRequest,
    FAILURE_DECODE_FAILED, FAILURE_TARGET_SETUP_FAILED, FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD,
    FAILURE_WRONG_PEER,
};

const COAP_PORT: u16 = 5683;
const COAP_CONFIRMATION_ENV: &str = "LIBCRAFTER_COAP_LIVE_CONFIRM";
const MAX_CAPTURE_RECORDS: usize = 8;
const MAX_TIMEOUT_SECONDS: u64 = 30;

pub fn is_live_capable_case(case: &str) -> bool {
    matches!(
        case,
        "coap-unicast-get-content"
            | "coap-empty-ack-separate-response"
            | "coap-reset"
            | "coap-observe-notification"
            | "coap-block1-transfer"
            | "coap-block2-transfer"
            | "coap-echo-request-tag"
    )
}

pub fn run_coap_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = coap_packet(plan)?;
    let report = SocketSender::new(
        SendOptions::new()
            .iface(request.interface.clone())
            .network_layer()
            .dry_run(),
    )
    .send(&packet)?;
    let sent_raw = report.plan().bytes();
    let sent_packet = Packet::decode_from_l3(NetworkLayer::Ipv4, sent_raw)?;
    let sent_decoded = decoded_coap_packet_json(&sent_packet, sent_raw);
    let request_coap = sent_packet
        .layer::<Coap>()
        .ok_or("compiled CoAP probe did not decode as a typed Coap layer")?;
    let expected = expected_response_payloads(plan)?
        .iter()
        .map(|payload| Coap::decode(payload).map(|message| coap_json(&message)))
        .collect::<crafter::Result<Vec<_>>>()?;
    let capture_filter = capture_filter(plan);
    let target_service = plan.target_service.clone().unwrap_or_else(|| json!({}));
    let observed = observed_response(
        plan,
        false,
        None,
        json!({}),
        json!({
            "dry_run": true,
            "send_report": send_report_json(&report),
            "sent_raw_hex": hex_bytes(sent_raw),
            "sent_decoded": sent_decoded,
            "coap": coap_json(request_coap),
            "expected_coap_responses": expected,
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
            "planned_only": false,
            "probe_plan": plan_json(plan),
            "send_report": send_report_json(&report),
            "sent_raw_hex": hex_bytes(sent_raw),
            "sent_decoded": sent_decoded,
            "coap": coap_json(request_coap),
            "expected_coap_responses": expected,
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

pub fn run_coap_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    if let Some(outcome) = live_gate_failure(request, plan) {
        return Ok(outcome);
    }

    let packet = coap_packet(plan)?;
    let expected_payloads = expected_response_payloads(plan)?;
    if expected_payloads.is_empty() {
        return Ok(failed_outcome(
            plan,
            FAILURE_TARGET_SETUP_FAILED,
            vec!["CoAP live plan has no bounded response payloads".to_string()],
            None,
            false,
            false,
        ));
    }
    let capture_filter = capture_filter(plan);
    let timeout = Duration::from_secs(request.timeout_seconds.clamp(1, MAX_TIMEOUT_SECONDS));
    let mut sniffer = match open_capture_sniffer(
        request.interface.clone(),
        timeout,
        MAX_CAPTURE_RECORDS,
        capture_filter.clone(),
    ) {
        Ok(sniffer) => sniffer,
        Err(err) => {
            return Ok(failed_outcome(
                plan,
                FAILURE_DECODE_FAILED,
                vec![format!("CoAP capture open failed: {err}")],
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
                vec![format!("CoAP send failed: {err}")],
                None,
                false,
                false,
            ));
        }
    };

    let sent = send_report.bytes_sent() > 0;
    let mut response_index = 0usize;
    let mut decoded_responses = Vec::with_capacity(expected_payloads.len());
    let mut raw_responses = Vec::with_capacity(expected_payloads.len());
    let mut wrong_peer = None;
    let mut wrong_payload = None;
    while let Some(captured) = match sniffer.next_record() {
        Ok(record) => record,
        Err(err) => {
            return Ok(failed_outcome(
                plan,
                FAILURE_DECODE_FAILED,
                vec![format!("CoAP capture decode failed: {err}")],
                Some(send_report_json(&send_report)),
                sent,
                false,
            ));
        }
    } {
        let expected = &expected_payloads[response_index];
        match validate_coap_candidate(plan, captured.packet(), captured_data(&captured), expected)?
        {
            CandidateValidation::Ignore => {}
            CandidateValidation::Passed(decoded) => {
                raw_responses.push(hex_bytes(captured_data(&captured)));
                decoded_responses.push(decoded);
                response_index += 1;
                if response_index != expected_payloads.len() {
                    continue;
                }
                let observed = observed_response(
                    plan,
                    true,
                    raw_responses.last().cloned(),
                    json!(decoded_responses),
                    json!({
                        "send_report": send_report_json(&send_report),
                        "capture_filter": capture_filter,
                        "response_count": response_index,
                        "raw_responses": raw_responses,
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
                        "response_count": response_index,
                        "decoded_responses": decoded_responses,
                        "raw_responses": raw_responses,
                    }
                });
                return Ok(ProbeOutcome {
                    result,
                    observed_response: observed,
                    sent,
                    received: true,
                });
            }
            CandidateValidation::WrongPeer(decoded) => wrong_peer = Some(decoded),
            CandidateValidation::WrongPayload(decoded) => wrong_payload = Some(decoded),
        }
    }

    if let Some(decoded) = wrong_payload {
        return Ok(failed_outcome(
            plan,
            FAILURE_WRONG_PAYLOAD,
            vec![format!(
                "captured CoAP response {} did not match its expected typed message",
                response_index + 1
            )],
            Some(json!({
                "send_report": send_report_json(&send_report),
                "decoded": decoded,
                "matched_response_count": response_index,
            })),
            sent,
            true,
        ));
    }
    if let Some(decoded) = wrong_peer {
        return Ok(failed_outcome(
            plan,
            FAILURE_WRONG_PEER,
            vec!["captured CoAP response did not match the controlled peer tuple".to_string()],
            Some(json!({
                "send_report": send_report_json(&send_report),
                "decoded": decoded,
                "matched_response_count": response_index,
            })),
            sent,
            true,
        ));
    }
    Ok(failed_outcome(
        plan,
        FAILURE_TIMEOUT,
        vec![format!(
            "timed out after {response_index}/{} expected CoAP responses",
            expected_payloads.len()
        )],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter,
            "matched_response_count": response_index,
        })),
        sent,
        false,
    ))
}

pub fn coap_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    let source_port = required_u16(plan.source_port, "source_port")?;
    let destination_port = required_u16(plan.destination_port, "destination_port")?;
    let payload = decode_hex(required_str(
        plan.payload_hex
            .as_deref()
            .or(plan.udp_payload_hex.as_deref()),
        "payload_hex",
    )?)?;
    let coap = Coap::decode(&payload)?;
    let compiled = coap_payload_bytes(&coap)?;
    if compiled != payload {
        return Err("typed CoAP request did not preserve the planned datagram bytes".into());
    }
    Ok(Ipv4::new().src(source).dst(destination)
        / Udp::new().sport(source_port).dport(destination_port)
        / coap)
}

pub fn validate_coap_candidate(
    plan: &ProbePlan,
    packet: &Packet,
    raw: &[u8],
    expected_payload: &[u8],
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
    let mut mismatches = Vec::new();
    match packet.layer::<Ipv4>() {
        Some(ipv4) => {
            mismatch(
                &mut mismatches,
                "ipv4.src",
                expected_source.to_string(),
                ipv4.source().to_string(),
            );
            mismatch(
                &mut mismatches,
                "ipv4.dst",
                expected_destination.to_string(),
                ipv4.destination().to_string(),
            );
        }
        None => mismatches.push(json!({
            "field": "ipv4",
            "expected": "present",
            "actual": "missing",
        })),
    }
    mismatch(
        &mut mismatches,
        "udp.sport",
        expected_source_port,
        udp.source_port_value(),
    );
    mismatch(
        &mut mismatches,
        "udp.dport",
        expected_destination_port,
        udp.destination_port_value(),
    );
    let decoded = decoded_coap_packet_json(packet, raw);
    if !mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPeer(json!({
            "packet": decoded,
            "mismatches": mismatches,
        })));
    }

    let Some(actual) = packet.layer::<Coap>() else {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": [{
                "field": "coap",
                "expected": "typed Coap layer",
                "actual": "missing",
            }],
        })));
    };
    let expected = Coap::decode(expected_payload)?;
    let mut field_mismatches = Vec::new();
    mismatch(
        &mut field_mismatches,
        "coap.type",
        expected.message_type_value().label(),
        actual.message_type_value().label(),
    );
    mismatch(
        &mut field_mismatches,
        "coap.code",
        expected.code_value().wire_value(),
        actual.code_value().wire_value(),
    );
    mismatch(
        &mut field_mismatches,
        "coap.message_id",
        expected.message_id_value(),
        actual.message_id_value(),
    );
    mismatch(
        &mut field_mismatches,
        "coap.token",
        expected.token_value().to_hex(),
        actual.token_value().to_hex(),
    );
    mismatch(
        &mut field_mismatches,
        "coap.options",
        options_json(&expected),
        options_json(actual),
    );
    mismatch(
        &mut field_mismatches,
        "coap.payload",
        hex_bytes(expected.payload_value()),
        hex_bytes(actual.payload_value()),
    );
    let actual_payload = coap_payload_bytes(actual)?;
    mismatch(
        &mut field_mismatches,
        "coap.wire",
        hex_bytes(expected_payload),
        hex_bytes(&actual_payload),
    );
    if !field_mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "coap": coap_json(actual),
            "expected_coap": coap_json(&expected),
            "mismatches": field_mismatches,
        })));
    }
    Ok(CandidateValidation::Passed(decoded))
}

pub fn coap_json(coap: &Coap) -> Value {
    let code = coap.code_value();
    json!({
        "summary": coap.summary(),
        "version": coap.version_value().value(),
        "version_label": coap.version_value().label(),
        "type": coap.message_type_value().label(),
        "type_value": coap.message_type_value().value(),
        "code": code.label(),
        "code_value": code.wire_value(),
        "code_name": code.registry_meta().label,
        "message_id": coap.message_id_value(),
        "token_hex": coap.token_value().to_hex(),
        "options": options_json(coap),
        "payload_marker": if coap.payload_marker_value().is_present() { "present" } else { "absent" },
        "payload_hex": hex_bytes(coap.payload_value()),
        "observe": option_values(coap, 6),
        "block2": option_values(coap, 23),
        "block1": option_values(coap, 27),
        "qblock2": option_values(coap, 31),
        "echo": option_values(coap, 252),
        "request_tag": option_values(coap, 292),
    })
}

pub fn capture_filter(plan: &ProbePlan) -> String {
    plan.capture_filter.clone().unwrap_or_else(|| {
        format!(
            "udp and src host {} and dst host {} and src port {} and dst port {}",
            plan.expected_reply_source_ipv4.as_deref().unwrap_or(""),
            plan.expected_reply_destination_ipv4
                .as_deref()
                .unwrap_or(""),
            plan.destination_port.unwrap_or(COAP_PORT),
            plan.source_port.unwrap_or(0),
        )
    })
}

fn expected_response_payloads(plan: &ProbePlan) -> ExampleResult<Vec<Vec<u8>>> {
    let from_service = plan
        .target_service
        .as_ref()
        .and_then(|service| service.get("response_payloads_hex"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .map(|value| {
                    let encoded = value
                        .as_str()
                        .ok_or("target_service.response_payloads_hex entries must be strings")?;
                    decode_hex(encoded)
                })
                .collect::<ExampleResult<Vec<_>>>()
        })
        .transpose()?;
    if let Some(payloads) = from_service.filter(|payloads| !payloads.is_empty()) {
        return Ok(payloads);
    }
    let expected = required_str(plan.expected_payload_hex.as_deref(), "expected_payload_hex")?;
    Ok(vec![decode_hex(expected)?])
}

fn decoded_coap_packet_json(packet: &Packet, raw: &[u8]) -> Value {
    let mut decoded = decoded_packet_json(packet, raw);
    if let Value::Object(map) = &mut decoded {
        map.insert(
            "coap".into(),
            packet.layer::<Coap>().map(coap_json).unwrap_or(Value::Null),
        );
    }
    decoded
}

fn coap_payload_bytes(coap: &Coap) -> ExampleResult<Vec<u8>> {
    Ok(Packet::from_layer(coap.clone())
        .compile()?
        .as_bytes()
        .to_vec())
}

fn options_json(coap: &Coap) -> Value {
    Value::Array(
        coap.options_value()
            .iter()
            .map(|option| {
                json!({
                    "number": option.number().value(),
                    "name": option.registry_meta().label,
                    "value_hex": hex_bytes(option.value()),
                })
            })
            .collect(),
    )
}

fn option_values(coap: &Coap, number: u16) -> Vec<String> {
    coap.options_value()
        .iter()
        .filter(|option| option.number().value() == number)
        .map(|option| hex_bytes(option.value()))
        .collect()
}

fn mismatch<T>(mismatches: &mut Vec<Value>, field: &str, expected: T, actual: T)
where
    T: PartialEq + serde::Serialize,
{
    if expected != actual {
        mismatches.push(json!({
            "field": field,
            "expected": expected,
            "actual": actual,
        }));
    }
}

fn live_gate_failure(request: &StimulusEndpointRequest, plan: &ProbePlan) -> Option<ProbeOutcome> {
    if !provider_is_live_capable(&request.provider) {
        return Some(failed_outcome(
            plan,
            FAILURE_TARGET_SETUP_FAILED,
            vec![format!(
                "CoAP live stimulus requires provider-backed probe infrastructure; provider={} is not live-capable",
                request.provider
            )],
            Some(json!({
                "provider": request.provider,
                "requires_provider": true,
            })),
            false,
            false,
        ));
    }
    if env::var(COAP_CONFIRMATION_ENV).ok().as_deref() != Some("yes") {
        return Some(failed_outcome(
            plan,
            FAILURE_TARGET_SETUP_FAILED,
            vec![format!(
                "CoAP live stimulus requires {COAP_CONFIRMATION_ENV}=yes"
            )],
            Some(json!({
                "confirmation_environment": COAP_CONFIRMATION_ENV,
                "confirmation_value": "yes",
            })),
            false,
            false,
        ));
    }
    None
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

    fn plan(case: &str, request_hex: &str, responses: &[&str]) -> ProbePlan {
        let mut plan = base_plan(case);
        plan.source_ipv4 = Some("192.0.2.10".to_string());
        plan.destination_ipv4 = Some("192.0.2.20".to_string());
        plan.expected_reply_source_ipv4 = Some("192.0.2.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("192.0.2.10".to_string());
        plan.source_port = Some(49152);
        plan.destination_port = Some(COAP_PORT);
        plan.payload_hex = Some(request_hex.to_string());
        plan.expected_payload_hex = responses.last().map(|value| (*value).to_string());
        plan.capture_filter = Some(
            "udp and src host 192.0.2.20 and dst host 192.0.2.10 and src port 5683 and dst port 49152"
                .to_string(),
        );
        plan.target_service = Some(json!({
            "kind": "coap-controlled-responder",
            "response_payloads_hex": responses,
        }));
        plan
    }

    fn request(plan: ProbePlan) -> StimulusEndpointRequest {
        StimulusEndpointRequest {
            provider: "local-dry-run".to_string(),
            profile: "coap-smoke".to_string(),
            seed: 7252,
            endpoint_role: "stimulus".to_string(),
            interface: "eth0".to_string(),
            local_ipv4: "192.0.2.10".to_string(),
            peer_ipv4: "192.0.2.20".to_string(),
            timeout_seconds: 2,
            probe_plans: vec![plan],
            artifact_paths: json!({}),
            metadata: json!({}),
        }
    }

    #[test]
    fn typed_packet_preserves_planned_datagram() {
        let plan = plan(
            "coap-unicast-get-content",
            "42011234aabbb6737461747573",
            &["62451234aabbc0ff636f6e74656e74"],
        );
        let packet = coap_packet(&plan).unwrap();
        let compiled = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let coap = decoded.layer::<Coap>().unwrap();
        assert_eq!(coap.message_id_value(), 0x1234);
        assert_eq!(coap.token_value().as_bytes(), &[0xaa, 0xbb]);
        assert_eq!(coap.options_value()[0].number().value(), 11);
        assert_eq!(coap.options_value()[0].value(), b"status");
    }

    #[test]
    fn dry_run_is_inspectable_and_never_sent() {
        let plan = plan(
            "coap-observe-notification",
            "42011234aabb6056737461747573",
            &["52451234aabb6101b0ff636f6e74656e74"],
        );
        let request = request(plan);
        let outcome = run_coap_dry_run(&request, &request.probe_plans[0]).unwrap();
        assert!(!outcome.sent);
        assert!(!outcome.received);
        assert_eq!(outcome.result["status"], "planned");
        assert_eq!(outcome.result["metadata"]["coap"]["message_id"], 0x1234);
        assert_eq!(outcome.result["metadata"]["coap"]["observe"], json!([""]));
    }

    #[test]
    fn response_validation_checks_peer_and_typed_fields() {
        let plan = plan(
            "coap-unicast-get-content",
            "42011234aabbb6737461747573",
            &["62451234aabbc0ff636f6e74656e74"],
        );
        let response = Ipv4::new()
            .src("192.0.2.20".parse::<Ipv4Addr>().unwrap())
            .dst("192.0.2.10".parse::<Ipv4Addr>().unwrap())
            / Udp::new().sport(COAP_PORT).dport(49152)
            / Coap::decode(&decode_hex("62451234aabbc0ff636f6e74656e74").unwrap()).unwrap();
        let compiled = response.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(matches!(
            validate_coap_candidate(
                &plan,
                &decoded,
                compiled.as_bytes(),
                &decode_hex("62451234aabbc0ff636f6e74656e74").unwrap(),
            )
            .unwrap(),
            CandidateValidation::Passed(_)
        ));
    }

    #[test]
    fn local_live_request_fails_before_capture_or_send() {
        let plan = plan("coap-reset", "42011234aabbb6737461747573", &["70001234"]);
        let request = request(plan);
        let outcome = run_coap_live(&request, &request.probe_plans[0]).unwrap();
        assert!(!outcome.sent);
        assert!(!outcome.received);
        assert_eq!(
            outcome.result["metadata"]["failure_reason"],
            FAILURE_TARGET_SETUP_FAILED
        );
    }
}
