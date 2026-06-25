//! SNMP behavioral probe cases.
//!
//! The adapter materializes plan-level SNMP intent as typed libcrafter SNMP
//! layers over IPv4/UDP. It deliberately stops at packet construction and
//! response decoding: manager sessions, walks, credentials, and retry policy stay
//! outside the probe adapter.

use crafter::prelude::*;
use crafter::protocols::snmp::{
    snmp_security_model_label, SnmpGetBulkPdu, SnmpPdu, SnmpRequestPdu, SnmpScopedPdu,
    SnmpUsmSecurityParameters, SnmpV1TrapPdu, SNMP_SECURITY_MODEL_ANY, SNMP_SECURITY_MODEL_SNMPV1,
    SNMP_SECURITY_MODEL_SNMPV2C, SNMP_SECURITY_MODEL_TSM, SNMP_SECURITY_MODEL_USM,
    SNMP_V3_FLAG_AUTH, SNMP_V3_FLAG_PRIVACY, SNMP_V3_FLAG_REPORTABLE,
};
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::common::{
    capture_filter, captured_data, decode_hex, decoded_packet_json, failed_outcome, hex_bytes,
    observed_response, open_capture_sniffer, plan_json, required_str, required_u16,
    send_report_json, target_service_json, CandidateValidation, ExampleResult, ProbeOutcome,
    ProbePlan, StimulusEndpointRequest, FAILURE_DECODE_FAILED, FAILURE_TIMEOUT,
    FAILURE_WRONG_PAYLOAD, FAILURE_WRONG_PEER,
};

const SNMP_SYS_UPTIME_OID: &str = "1.3.6.1.2.1.1.3.0";
const SNMP_TRAP_OID_BINDING: &str = "1.3.6.1.6.3.1.1.4.1.0";
const DEFAULT_SNMP_V3_MAX_SIZE: i64 = 1500;

#[derive(Debug, Clone)]
struct DecodedSnmpPdu {
    tag_label: String,
    tag_number: u8,
    request_id: Option<i64>,
    error_status: Option<i64>,
    error_index: Option<i64>,
    non_repeaters: Option<i64>,
    max_repetitions: Option<i64>,
    varbinds: Vec<SnmpVarBind>,
}

pub fn run_snmp_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = snmp_packet(plan)?;
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
            "capture_filter": capture_filter(plan),
            "target_service": target_service_json(plan),
            "snmp_request": plan.snmp_request,
            "expected_snmp_response": expected_snmp_response_json(plan),
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
            "snmp_request": plan.snmp_request,
            "expected_snmp_response": expected_snmp_response_json(plan),
        }
    });
    Ok(ProbeOutcome {
        result,
        observed_response: observed,
        sent: false,
        received: false,
    })
}

pub fn run_snmp_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = snmp_packet(plan)?;
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
        match validate_snmp_candidate(plan, captured.packet(), captured_data(&captured))? {
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
            vec!["captured SNMP message did not match expected response fields".to_string()],
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
            vec!["captured SNMP response did not match expected peer or ports".to_string()],
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
        vec!["timed out waiting for SNMP response".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter(plan),
        })),
        sent,
        false,
    ))
}

pub fn snmp_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    let source_port = required_u16(plan.source_port, "source_port")?;
    let destination_port = required_u16(plan.destination_port, "destination_port")?;
    let message = snmp_message(plan)?;

    Ok(Ipv4::new().src(source).dst(destination)
        / Udp::new().sport(source_port).dport(destination_port)
        / message)
}

pub fn validate_snmp_candidate(
    plan: &ProbePlan,
    packet: &Packet,
    raw: &[u8],
) -> ExampleResult<CandidateValidation> {
    let Some(snmp) = packet.layer::<Snmp>() else {
        return Ok(CandidateValidation::Ignore);
    };
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

    let mut mismatches = Vec::new();
    match decoded_snmp_pdu(snmp)? {
        Some(pdu) => validate_expected_snmp_pdu(plan, snmp, &pdu, &mut mismatches)?,
        None => mismatches.push(json!({
            "field": "snmp.pdu",
            "expected": "present",
            "actual": "missing",
        })),
    }

    if !mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "snmp": snmp_json(snmp),
            "mismatches": mismatches,
        })));
    }

    Ok(CandidateValidation::Passed(decoded))
}

pub fn snmp_json(snmp: &Snmp) -> Value {
    let mut value = json!({
        "version": snmp.version_label(),
        "version_value": snmp.version_value(),
        "summary": snmp.summary(),
        "message_len": snmp.encoded_len(),
        "community_len": if snmp.as_v3().is_some() {
            Value::Null
        } else {
            json!(snmp.community().len())
        },
    });

    if let Value::Object(map) = &mut value {
        match decoded_snmp_pdu(snmp) {
            Ok(Some(pdu)) => {
                map.insert("pdu".into(), pdu.to_json());
            }
            Ok(None) => {}
            Err(err) => {
                map.insert("pdu_decode_error".into(), json!(err.to_string()));
            }
        }

        if let Some(v3) = snmp.as_v3() {
            let mut v3_json = json!({
                "msg_id": v3.msg_id(),
                "max_size": v3.max_size(),
                "flags_hex": hex_bytes(v3.flags()),
                "flags_label": v3.flags_value().label(),
                "security_model": v3.security_model(),
                "security_model_label": snmp_security_model_label(v3.security_model()),
                "security_parameters_len": v3.security_parameters().len(),
                "scoped_data_kind": v3.scoped_data_kind(),
                "scoped_data_len": v3.scoped_data().len(),
            });
            if let Value::Object(v3_map) = &mut v3_json {
                match v3.scoped_pdu() {
                    Ok(Some(scoped)) => {
                        v3_map.insert(
                            "scoped_pdu".into(),
                            json!({
                                "context_engine_id_len": scoped.context_engine_id().len(),
                                "context_name_len": scoped.context_name().len(),
                            }),
                        );
                    }
                    Ok(None) => {}
                    Err(err) => {
                        v3_map.insert("scoped_pdu_decode_error".into(), json!(err.to_string()));
                    }
                }
            }
            map.insert("v3".into(), v3_json);
        }
    }

    value
}

fn snmp_message(plan: &ProbePlan) -> ExampleResult<Snmp> {
    let request = plan
        .snmp_request
        .as_ref()
        .ok_or_else(|| "probe plan missing required field snmp_request".to_string())?;
    let version = json_str(request, "version")?;
    match version {
        "v1" => community_message(request, SnmpVersion::V1),
        "v2c" => community_message(request, SnmpVersion::V2c),
        "v3" => v3_message(request),
        other => Err(format!("unsupported SNMP version in snmp_request.version: {other}").into()),
    }
}

fn community_message(request: &Value, version: SnmpVersion) -> ExampleResult<Snmp> {
    let community = json_str(request, "community")?.as_bytes().to_vec();
    let request_id = json_i64(request, "request_id")?;
    let pdu_kind = normalized_pdu_kind(json_str(request, "pdu")?);
    let varbinds = request_varbinds(request)?;

    let message = match (version, pdu_kind.as_str()) {
        (SnmpVersion::V1, "get-request") => Snmp::v1_get_request(community, request_id, varbinds)?,
        (SnmpVersion::V1, "get-next-request") => {
            Snmp::v1_get_next_request(community, request_id, varbinds)?
        }
        (SnmpVersion::V1, "set-request") => Snmp::v1_set_request(community, request_id, varbinds)?,
        (SnmpVersion::V1, "response") => Snmp::v1_response(community, request_id, varbinds)?,
        (SnmpVersion::V2c, "get-request") => {
            Snmp::v2c_get_request(community, request_id, varbinds)?
        }
        (SnmpVersion::V2c, "get-next-request") => {
            Snmp::v2c_get_next_request(community, request_id, varbinds)?
        }
        (SnmpVersion::V2c, "set-request") => {
            Snmp::v2c_set_request(community, request_id, varbinds)?
        }
        (SnmpVersion::V2c, "response") => Snmp::v2c_response(community, request_id, varbinds)?,
        (SnmpVersion::V2c, "get-bulk-request") => {
            let non_repeaters = json_i64(request, "non_repeaters")?;
            let max_repetitions = json_i64(request, "max_repetitions")?;
            Snmp::v2c_get_bulk_request(
                community,
                request_id,
                non_repeaters,
                max_repetitions,
                varbinds,
            )?
        }
        (SnmpVersion::V2c, "inform-request") => {
            Snmp::v2c_inform_request(community, request_id, varbinds)?
        }
        (SnmpVersion::V2c, "snmpv2-trap") => {
            Snmp::v2c_snmpv2_trap(community, request_id, trap_varbinds(request)?)?
        }
        (SnmpVersion::V2c, "report") => Snmp::v2c_report(community, request_id, varbinds)?,
        (_, other) => return Err(format!("unsupported SNMP community PDU: {other}").into()),
    };
    Ok(message)
}

fn v3_message(request: &Value) -> ExampleResult<Snmp> {
    let request_id = json_i64(request, "request_id")?;
    let msg_id = optional_i64(request, "msg_id")?.unwrap_or(request_id);
    let max_size = optional_i64(request, "max_size")?.unwrap_or(DEFAULT_SNMP_V3_MAX_SIZE);
    let flags = v3_flags(request)?;
    let security_model = security_model_value(request.get("security_model"))?;
    let engine_id = hex_object_bytes(request, "engine_id")?;
    let user_name = request
        .get("user_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .as_bytes()
        .to_vec();
    let pdu = v3_scoped_pdu(request)?;
    let scoped_pdu = SnmpScopedPdu::new(engine_id.clone(), Vec::new(), pdu);
    let security_parameters = if security_model == SNMP_SECURITY_MODEL_USM {
        SnmpUsmSecurityParameters::new(engine_id, 0, 0, user_name, Vec::new(), Vec::new())
            .compile()?
    } else {
        hex_object_bytes(request, "security_parameters")?
    };

    Ok(Snmp::v3_plaintext(
        msg_id,
        max_size,
        flags,
        security_model,
        security_parameters,
        scoped_pdu,
    )?)
}

fn v3_scoped_pdu(request: &Value) -> ExampleResult<SnmpPdu> {
    let request_id = json_i64(request, "request_id")?;
    let pdu_kind = normalized_pdu_kind(json_str(request, "pdu")?);
    let varbinds = request_varbinds(request)?;
    match pdu_kind.as_str() {
        "get-request" => Ok(SnmpPdu::get_request(request_id, varbinds)?),
        "get-next-request" => Ok(SnmpPdu::get_next_request(request_id, varbinds)?),
        "set-request" => Ok(SnmpPdu::set_request(request_id, varbinds)?),
        "response" => Ok(SnmpPdu::response(request_id, varbinds)?),
        "get-bulk-request" => Ok(SnmpPdu::get_bulk_request(
            request_id,
            json_i64(request, "non_repeaters")?,
            json_i64(request, "max_repetitions")?,
            varbinds,
        )?),
        "inform-request" => Ok(SnmpPdu::inform_request(request_id, varbinds)?),
        "snmpv2-trap" => Ok(SnmpPdu::snmpv2_trap(request_id, trap_varbinds(request)?)?),
        "report" => Ok(SnmpPdu::report(request_id, varbinds)?),
        other => Err(format!("unsupported SNMPv3 scoped PDU: {other}").into()),
    }
}

fn request_varbinds(request: &Value) -> ExampleResult<SnmpVarBindList> {
    let oid = SnmpOid::from_dotted(json_str(request, "oid")?)?;
    Ok(SnmpVarBindList::new(vec![SnmpVarBind::null(oid)]))
}

fn trap_varbinds(request: &Value) -> ExampleResult<SnmpVarBindList> {
    let trap_oid = SnmpOid::from_dotted(json_str(request, "oid")?)?;
    let uptime_oid = SnmpOid::from_dotted(SNMP_SYS_UPTIME_OID)?;
    let trap_oid_binding = SnmpOid::from_dotted(SNMP_TRAP_OID_BINDING)?;
    let uptime = optional_u32(request, "uptime_ticks")?.unwrap_or(0);
    Ok(SnmpVarBindList::new(vec![
        SnmpVarBind::time_ticks(uptime_oid, uptime),
        SnmpVarBind::object_identifier(trap_oid_binding, trap_oid),
    ]))
}

fn validate_expected_snmp_pdu(
    plan: &ProbePlan,
    snmp: &Snmp,
    pdu: &DecodedSnmpPdu,
    mismatches: &mut Vec<Value>,
) -> ExampleResult<()> {
    let Some(expected) = plan.expected_snmp_response.as_ref() else {
        return Ok(());
    };

    if let Some(expected_version) = expected.get("version").and_then(Value::as_str) {
        if snmp.version_label() != expected_version {
            mismatches.push(json!({
                "field": "snmp.version",
                "expected": expected_version,
                "actual": snmp.version_label(),
            }));
        }
    }

    if let Some(expected_pdu) = expected.get("pdu").and_then(Value::as_str) {
        let expected_label = canonical_response_pdu_label(expected_pdu);
        if pdu.tag_label != expected_label {
            mismatches.push(json!({
                "field": "snmp.pdu",
                "expected": expected_label,
                "actual": pdu.tag_label,
            }));
        }
    }

    if let Some(expected_request_id) = optional_i64(expected, "request_id")? {
        if pdu.request_id != Some(expected_request_id) {
            mismatches.push(json!({
                "field": "snmp.request_id",
                "expected": expected_request_id,
                "actual": pdu.request_id,
            }));
        }
    }

    if let Some(expected_oid) = expected.get("oid").and_then(Value::as_str) {
        let oid_seen = pdu
            .varbinds
            .iter()
            .any(|varbind| varbind.name().to_string() == expected_oid)
            || pdu.varbinds.iter().any(|varbind| {
                varbind
                    .as_object_identifier()
                    .map(|oid| oid.to_string() == expected_oid)
                    .unwrap_or(false)
            });
        if !oid_seen {
            mismatches.push(json!({
                "field": "snmp.varbind.oid",
                "expected": expected_oid,
                "actual": pdu.varbinds.iter().map(|varbind| varbind.summary()).collect::<Vec<_>>(),
            }));
        }
    }

    if let Some(expected_value) = expected.get("value") {
        let matched = pdu
            .varbinds
            .iter()
            .any(|varbind| expected_value_matches(varbind, expected_value).unwrap_or(false));
        if !matched {
            mismatches.push(json!({
                "field": "snmp.varbind.value",
                "expected": expected_value,
                "actual": varbinds_json(&pdu.varbinds),
            }));
        }
    }

    Ok(())
}

fn expected_snmp_response_json(plan: &ProbePlan) -> Value {
    plan.expected_snmp_response
        .clone()
        .unwrap_or_else(|| json!({}))
}

fn decoded_snmp_pdu(snmp: &Snmp) -> ExampleResult<Option<DecodedSnmpPdu>> {
    if let Some(pdu) = snmp.pdu_opt() {
        return decoded_pdu(pdu).map(Some);
    }
    if let Some(v3) = snmp.as_v3() {
        if let Some(scoped) = v3.scoped_pdu()? {
            return decoded_pdu(scoped.pdu()).map(Some);
        }
    }
    Ok(None)
}

fn decoded_pdu(pdu: &SnmpPdu) -> ExampleResult<DecodedSnmpPdu> {
    let tag_label = pdu.tag_label();
    let tag_number = pdu.tag_number();
    if let Some(fields) = pdu.as_get_request()? {
        return Ok(decoded_request_pdu(tag_label, tag_number, fields));
    }
    if let Some(fields) = pdu.as_get_next_request()? {
        return Ok(decoded_request_pdu(tag_label, tag_number, fields));
    }
    if let Some(fields) = pdu.as_response()? {
        return Ok(decoded_request_pdu(tag_label, tag_number, fields));
    }
    if let Some(fields) = pdu.as_set_request()? {
        return Ok(decoded_request_pdu(tag_label, tag_number, fields));
    }
    if let Some(fields) = pdu.as_inform_request()? {
        return Ok(decoded_request_pdu(tag_label, tag_number, fields));
    }
    if let Some(fields) = pdu.as_snmpv2_trap()? {
        return Ok(decoded_request_pdu(tag_label, tag_number, fields));
    }
    if let Some(fields) = pdu.as_report()? {
        return Ok(decoded_request_pdu(tag_label, tag_number, fields));
    }
    if let Some(fields) = pdu.as_get_bulk_request()? {
        return Ok(decoded_bulk_pdu(tag_label, tag_number, fields));
    }
    if let Some(fields) = pdu.as_v1_trap()? {
        return Ok(decoded_v1_trap_pdu(tag_label, tag_number, fields));
    }
    Ok(DecodedSnmpPdu {
        tag_label,
        tag_number,
        request_id: None,
        error_status: None,
        error_index: None,
        non_repeaters: None,
        max_repetitions: None,
        varbinds: Vec::new(),
    })
}

fn decoded_request_pdu(
    tag_label: String,
    tag_number: u8,
    fields: SnmpRequestPdu,
) -> DecodedSnmpPdu {
    DecodedSnmpPdu {
        tag_label,
        tag_number,
        request_id: Some(fields.request_id()),
        error_status: Some(fields.error_status()),
        error_index: Some(fields.error_index()),
        non_repeaters: None,
        max_repetitions: None,
        varbinds: fields.varbinds().as_slice().to_vec(),
    }
}

fn decoded_bulk_pdu(tag_label: String, tag_number: u8, fields: SnmpGetBulkPdu) -> DecodedSnmpPdu {
    DecodedSnmpPdu {
        tag_label,
        tag_number,
        request_id: Some(fields.request_id()),
        error_status: None,
        error_index: None,
        non_repeaters: Some(fields.non_repeaters()),
        max_repetitions: Some(fields.max_repetitions()),
        varbinds: fields.varbinds().as_slice().to_vec(),
    }
}

fn decoded_v1_trap_pdu(tag_label: String, tag_number: u8, fields: SnmpV1TrapPdu) -> DecodedSnmpPdu {
    DecodedSnmpPdu {
        tag_label,
        tag_number,
        request_id: None,
        error_status: None,
        error_index: None,
        non_repeaters: None,
        max_repetitions: None,
        varbinds: fields.varbinds().as_slice().to_vec(),
    }
}

impl DecodedSnmpPdu {
    fn to_json(&self) -> Value {
        json!({
            "type": self.tag_label,
            "tag": self.tag_number,
            "request_id": self.request_id,
            "error_status": self.error_status,
            "error_index": self.error_index,
            "non_repeaters": self.non_repeaters,
            "max_repetitions": self.max_repetitions,
            "varbind_count": self.varbinds.len(),
            "varbinds": varbinds_json(&self.varbinds),
        })
    }
}

fn varbinds_json(varbinds: &[SnmpVarBind]) -> Value {
    Value::Array(varbinds.iter().map(varbind_json).collect())
}

fn varbind_json(varbind: &SnmpVarBind) -> Value {
    json!({
        "name": varbind.name().to_string(),
        "summary": varbind.summary(),
        "value": varbind_value_json(varbind),
    })
}

fn varbind_value_json(varbind: &SnmpVarBind) -> Value {
    if varbind.is_null_value() {
        return json!({"kind": "null"});
    }
    if let Some(value) = varbind.as_integer() {
        return json!({"kind": "integer", "value": value});
    }
    if let Some(value) = varbind.as_octets() {
        let mut rendered = json!({"kind": "octet_string", "hex": hex_bytes(value)});
        if let Ok(text) = std::str::from_utf8(value) {
            if let Value::Object(map) = &mut rendered {
                map.insert("text".into(), json!(text));
            }
        }
        return rendered;
    }
    if let Some(value) = varbind.as_object_identifier() {
        return json!({"kind": "object_identifier", "oid": value.to_string()});
    }
    if let Some(value) = varbind.as_ip_address() {
        return json!({"kind": "ip_address", "address": Ipv4Addr::from(value).to_string()});
    }
    if let Some(value) = varbind.as_counter32() {
        return json!({"kind": "counter32", "value": value});
    }
    if let Some(value) = varbind.as_gauge32_or_unsigned32() {
        return json!({"kind": "gauge32_or_unsigned32", "value": value});
    }
    if let Some(value) = varbind.as_time_ticks() {
        return json!({"kind": "time_ticks", "ticks": value});
    }
    if let Some(value) = varbind.as_opaque() {
        return json!({"kind": "opaque", "hex": hex_bytes(value)});
    }
    if let Some(value) = varbind.as_counter64() {
        return json!({"kind": "counter64", "value": value});
    }
    if varbind.is_no_such_object() {
        return json!({"kind": "no_such_object"});
    }
    if varbind.is_no_such_instance() {
        return json!({"kind": "no_such_instance"});
    }
    if varbind.is_end_of_mib_view() {
        return json!({"kind": "end_of_mib_view"});
    }
    if let Some(value) = varbind.raw_value_tlv_bytes() {
        return json!({"kind": "raw_tlv", "hex": hex_bytes(value)});
    }
    json!({"kind": varbind.value_summary()})
}

fn expected_value_matches(varbind: &SnmpVarBind, expected: &Value) -> ExampleResult<bool> {
    let kind = json_str(expected, "kind")?;
    match kind {
        "null" => Ok(varbind.is_null_value()),
        "integer" => Ok(varbind.as_integer() == Some(json_i64(expected, "value")?)),
        "octet_string" => {
            let Some(actual) = varbind.as_octets() else {
                return Ok(false);
            };
            if let Some(text) = expected.get("text").and_then(Value::as_str) {
                return Ok(actual == text.as_bytes());
            }
            if let Some(hex) = expected.get("hex").and_then(Value::as_str) {
                return Ok(actual == decode_hex(hex)?.as_slice());
            }
            Ok(false)
        }
        "object_identifier" => Ok(varbind
            .as_object_identifier()
            .map(|oid| oid.to_string() == json_str(expected, "oid").unwrap_or_default())
            .unwrap_or(false)),
        "ip_address" => Ok(varbind
            .as_ip_address()
            .map(|octets| {
                Ipv4Addr::from(octets).to_string()
                    == json_str(expected, "address").unwrap_or_default()
            })
            .unwrap_or(false)),
        "counter32" => Ok(varbind.as_counter32() == Some(json_u32(expected, "value")?)),
        "gauge32" | "unsigned32" | "gauge32_or_unsigned32" => {
            Ok(varbind.as_gauge32_or_unsigned32() == Some(json_u32(expected, "value")?))
        }
        "time_ticks" => Ok(varbind.as_time_ticks() == Some(json_u32(expected, "ticks")?)),
        "opaque" => Ok(varbind
            .as_opaque()
            .map(|actual| {
                expected
                    .get("hex")
                    .and_then(Value::as_str)
                    .map(|hex| decode_hex(hex).map(|expected| actual == expected.as_slice()))
                    .transpose()
                    .map(|value| value.unwrap_or(false))
            })
            .transpose()?
            .unwrap_or(false)),
        "counter64" => Ok(varbind.as_counter64() == Some(json_u64(expected, "value")?)),
        "no_such_object" => Ok(varbind.is_no_such_object()),
        "no_such_instance" => Ok(varbind.is_no_such_instance()),
        "end_of_mib_view" => Ok(varbind.is_end_of_mib_view()),
        other => Err(format!("unsupported expected SNMP value kind: {other}").into()),
    }
}

fn json_str<'a>(value: &'a Value, key: &str) -> ExampleResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|item| !item.is_empty())
        .ok_or_else(|| format!("SNMP plan missing required string field {key}").into())
}

fn json_i64(value: &Value, key: &str) -> ExampleResult<i64> {
    optional_i64(value, key)?
        .ok_or_else(|| format!("SNMP plan missing required integer field {key}").into())
}

fn optional_i64(value: &Value, key: &str) -> ExampleResult<Option<i64>> {
    let Some(raw) = value.get(key) else {
        return Ok(None);
    };
    if let Some(signed) = raw.as_i64() {
        return Ok(Some(signed));
    }
    if let Some(unsigned) = raw.as_u64() {
        let signed = i64::try_from(unsigned)
            .map_err(|_| format!("SNMP integer field {key} exceeds i64::MAX"))?;
        return Ok(Some(signed));
    }
    Err(format!("SNMP field {key} must be an integer").into())
}

fn json_u32(value: &Value, key: &str) -> ExampleResult<u32> {
    optional_u32(value, key)?
        .ok_or_else(|| format!("SNMP plan missing required u32 field {key}").into())
}

fn optional_u32(value: &Value, key: &str) -> ExampleResult<Option<u32>> {
    let Some(raw) = value.get(key) else {
        return Ok(None);
    };
    let unsigned = raw
        .as_u64()
        .ok_or_else(|| format!("SNMP field {key} must be an unsigned integer"))?;
    let value =
        u32::try_from(unsigned).map_err(|_| format!("SNMP field {key} exceeds u32::MAX"))?;
    Ok(Some(value))
}

fn json_u64(value: &Value, key: &str) -> ExampleResult<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("SNMP plan missing required u64 field {key}").into())
}

fn hex_object_bytes(value: &Value, key: &str) -> ExampleResult<Vec<u8>> {
    let Some(raw) = value.get(key) else {
        return Ok(Vec::new());
    };
    if let Some(hex) = raw.as_str() {
        return decode_hex(hex);
    }
    if let Some(hex) = raw.get("hex").and_then(Value::as_str) {
        return decode_hex(hex);
    }
    Err(format!("SNMP field {key} must be a hex string or object with hex").into())
}

fn v3_flags(request: &Value) -> ExampleResult<Vec<u8>> {
    let Some(raw) = request.get("msg_flags") else {
        return Ok(vec![0]);
    };
    if let Some(bits) = raw.as_u64() {
        let bits =
            u8::try_from(bits).map_err(|_| "SNMP msg_flags integer exceeds u8::MAX".to_string())?;
        return Ok(vec![bits]);
    }
    if let Some(hex) = raw.as_str().and_then(|item| item.strip_prefix("0x")) {
        let bits = u8::from_str_radix(hex, 16)?;
        return Ok(vec![bits]);
    }
    let flags = raw
        .as_array()
        .ok_or_else(|| "SNMP msg_flags must be an array, integer, or 0xNN string".to_string())?;
    let mut bits = 0u8;
    for flag in flags {
        match flag.as_str().unwrap_or_default() {
            "auth" | "authFlag" => bits |= SNMP_V3_FLAG_AUTH,
            "privacy" | "priv" | "privFlag" => bits |= SNMP_V3_FLAG_PRIVACY,
            "reportable" | "reportableFlag" => bits |= SNMP_V3_FLAG_REPORTABLE,
            other => return Err(format!("unsupported SNMPv3 msgFlag: {other}").into()),
        }
    }
    Ok(vec![bits])
}

fn security_model_value(value: Option<&Value>) -> ExampleResult<i64> {
    let Some(value) = value else {
        return Ok(SNMP_SECURITY_MODEL_USM);
    };
    if let Some(raw) = value.as_i64() {
        return Ok(raw);
    }
    match value.as_str().unwrap_or_default() {
        "any" => Ok(SNMP_SECURITY_MODEL_ANY),
        "snmpv1" | "v1" => Ok(SNMP_SECURITY_MODEL_SNMPV1),
        "snmpv2c" | "v2c" => Ok(SNMP_SECURITY_MODEL_SNMPV2C),
        "usm" => Ok(SNMP_SECURITY_MODEL_USM),
        "tsm" => Ok(SNMP_SECURITY_MODEL_TSM),
        other => Err(format!("unsupported SNMP security_model: {other}").into()),
    }
}

fn normalized_pdu_kind(value: &str) -> String {
    value.replace('_', "-").to_ascii_lowercase()
}

fn canonical_response_pdu_label(value: &str) -> String {
    match normalized_pdu_kind(value).as_str() {
        "notification-observed" => "snmpv2-trap".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    fn get_plan() -> ProbePlan {
        let mut plan = base_plan("snmp-get-response");
        plan.source_ipv4 = Some("198.51.100.10".to_string());
        plan.destination_ipv4 = Some("198.51.100.130".to_string());
        plan.expected_reply_source_ipv4 = Some("198.51.100.130".to_string());
        plan.expected_reply_destination_ipv4 = Some("198.51.100.10".to_string());
        plan.source_port = Some(42161);
        plan.destination_port = Some(SNMP_PORT);
        plan.expected_response = Some("snmp_response".to_string());
        plan.snmp_request = Some(json!({
            "version": "v2c",
            "community": "doc-community",
            "pdu": "get_request",
            "request_id": 77,
            "oid": "1.3.6.1.2.1.1.1.0",
        }));
        plan.expected_snmp_response = Some(json!({
            "version": "v2c",
            "community": "doc-community",
            "pdu": "response",
            "request_id": 77,
            "oid": "1.3.6.1.2.1.1.1.0",
            "value": {"kind": "octet_string", "text": "doc-system"},
        }));
        plan
    }

    fn stimulus_request(plan: ProbePlan) -> StimulusEndpointRequest {
        StimulusEndpointRequest {
            provider: "local-dry-run".to_string(),
            profile: "snmp-smoke".to_string(),
            seed: 1,
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
    fn snmp_packet_compiles_and_decodes_as_snmp_layer() {
        let plan = get_plan();
        let packet = snmp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes).unwrap();
        let snmp = decoded.layer::<Snmp>().expect("snmp layer");
        assert_eq!(snmp.version_label(), "v2c");
        assert_eq!(snmp.pdu().tag_label(), "get-request");
    }

    #[test]
    fn dry_run_emits_decoded_snmp_metadata() {
        let plan = get_plan();
        let request = stimulus_request(plan.clone());
        let outcome = run_snmp_dry_run(&request, &plan).unwrap();
        assert_eq!(outcome.result["status"], "planned");
        assert_eq!(
            outcome.result["metadata"]["sent_decoded"]["snmp"]["pdu"]["type"],
            "get-request"
        );
        assert_eq!(
            outcome.result["metadata"]["target_service"]["kind"],
            "snmp-controlled-peer"
        );
    }

    #[test]
    fn validate_snmp_candidate_accepts_matching_response() {
        let plan = get_plan();
        let response = Ipv4::new()
            .src_str("198.51.100.130")
            .unwrap()
            .dst_str("198.51.100.10")
            .unwrap()
            / Udp::new().sport(SNMP_PORT).dport(42161)
            / Snmp::v2c_response(
                b"doc-community".to_vec(),
                77,
                SnmpVarBindList::new(vec![SnmpVarBind::octet_string(
                    SnmpOid::from_dotted("1.3.6.1.2.1.1.1.0").unwrap(),
                    b"doc-system".to_vec(),
                )]),
            )
            .unwrap();
        let raw = response.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();

        match validate_snmp_candidate(&plan, &decoded, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected pass, got {other:?}"),
        }
    }
}
