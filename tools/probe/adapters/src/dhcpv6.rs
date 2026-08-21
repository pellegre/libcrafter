//! DHCPv6 behavioral probe cases.
//!
//! The DHCPv6 probe planner carries a source-backed JSON contract for client,
//! server, relay, IA_NA, IA_PD, Reconfigure, and Leasequery behavior. This
//! adapter materializes that contract with libcrafter's typed DHCPv6 packet
//! layer, compiles the packet in dry-run mode, and validates live replies by
//! decoding IPv6/UDP/DHCPv6 responses back through libcrafter.

use crafter::prelude::*;
use serde_json::{json, Map, Value};
use std::net::Ipv6Addr;
use std::time::Duration;

use crate::common::{
    captured_data, decode_hex, decoded_packet_json, failed_outcome, hex_bytes, observed_response,
    open_capture_sniffer, peer_contract_json, plan_json, required_str, required_u16,
    send_report_json, CandidateValidation, ExampleResult, ProbeOutcome, ProbePlan,
    StimulusEndpointRequest, FAILURE_DECODE_FAILED, FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD,
    FAILURE_WRONG_PEER,
};

const DHCPV6_CLIENT_PORT: u16 = 546;
const DHCPV6_SERVER_PORT: u16 = 547;
const DHCPV6_RELAY_FORW: u8 = 12;
const DHCPV6_RELAY_REPL: u8 = 13;

/// Run one DHCPv6 probe plan without sending traffic.
pub fn run_dhcpv6_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = dhcpv6_packet(plan)?;
    let report = SocketSender::new(
        SendOptions::new()
            .iface(request.interface.clone())
            .network_layer()
            .dry_run(),
    )
    .send(&packet)?;
    let sent_raw = report.plan().bytes();
    let sent_raw_hex = hex_bytes(sent_raw);
    let sent_packet = Packet::decode_from_l3(NetworkLayer::Ipv6, sent_raw)?;
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

/// Run one DHCPv6 probe plan against a supplied interface.
pub fn run_dhcpv6_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = dhcpv6_packet(plan)?;
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
        match validate_dhcpv6_candidate(plan, captured.packet(), captured_data(&captured))? {
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
            vec!["captured DHCPv6 response did not match the expected contract".to_string()],
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
            vec!["captured DHCPv6 response did not match expected peer or ports".to_string()],
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
        vec!["timed out waiting for DHCPv6 response".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter(plan),
        })),
        sent,
        false,
    ))
}

/// Return the BPF capture filter for a DHCPv6 plan.
pub fn capture_filter(plan: &ProbePlan) -> String {
    let expected_src = plan.expected_reply_source_ipv6.as_deref().unwrap_or("");
    let expected_dst = plan
        .expected_reply_destination_ipv6
        .as_deref()
        .unwrap_or("");
    if expected_src.is_empty() || expected_dst.is_empty() {
        return "udp and (port 546 or port 547)".to_string();
    }
    format!(
        "udp and src host {expected_src} and dst host {expected_dst} and src port {} and dst port {}",
        expected_reply_source_port(plan),
        expected_reply_destination_port(plan),
    )
}

fn dhcpv6_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source_ipv6 =
        required_str(plan.source_ipv6.as_deref(), "source_ipv6")?.parse::<Ipv6Addr>()?;
    let destination_ipv6 =
        required_str(plan.destination_ipv6.as_deref(), "destination_ipv6")?.parse::<Ipv6Addr>()?;
    let source_port = required_u16(plan.source_port, "source_port")?;
    let destination_port = required_u16(plan.destination_port, "destination_port")?;
    let udp = Udp::new()
        .source_port(source_port)
        .destination_port(destination_port);
    Ok(Ipv6::with_addresses(source_ipv6, destination_ipv6) / udp / dhcpv6_message(plan)?)
}

fn dhcpv6_message(plan: &ProbePlan) -> ExampleResult<Dhcpv6> {
    let spec = dhcpv6_contract(plan)?;
    let message_type_code =
        required_json_u8(spec, "message_type_code", "dhcpv6.message_type_code")?;
    let transaction_id = required_json_u32(spec, "transaction_id", "dhcpv6.transaction_id")?;
    let mut message =
        if message_type_code == DHCPV6_RELAY_FORW || message_type_code == DHCPV6_RELAY_REPL {
            relay_message_from_contract(spec, message_type_code)?
        } else {
            Dhcpv6::new()
                .message_type_code(message_type_code)
                .transaction_id(transaction_id)
        };
    if let Some(options) = spec.get("options").and_then(Value::as_array) {
        for option in options {
            message = message.option(option_from_plan_row(option, spec)?);
        }
    }
    Ok(message)
}

fn relay_message_from_contract(
    spec: &Map<String, Value>,
    message_type_code: u8,
) -> ExampleResult<Dhcpv6> {
    let relay = required_object(spec.get("relay"), "dhcpv6.relay")?;
    let link_address = required_json_str(relay, "link_address", "dhcpv6.relay.link_address")?
        .parse::<Ipv6Addr>()?;
    let peer_address = required_json_str(relay, "peer_address", "dhcpv6.relay.peer_address")?
        .parse::<Ipv6Addr>()?;
    let hop_count = relay.get("hop_count").and_then(json_u8).unwrap_or(0);
    let message = match message_type_code {
        DHCPV6_RELAY_FORW => Dhcpv6::relay_forward(link_address, peer_address),
        DHCPV6_RELAY_REPL => Dhcpv6::relay_reply(link_address, peer_address),
        _ => unreachable!("relay_message_from_contract is called only for relay messages"),
    };
    Ok(message.hop_count(hop_count))
}

fn option_from_plan_row(row: &Value, spec: &Map<String, Value>) -> ExampleResult<Dhcpv6Option> {
    let object = required_object(Some(row), "dhcpv6.options[]")?;
    let code = required_json_u16(object, "code", "dhcpv6.options[].code")?;
    let name = object.get("name").and_then(Value::as_str).unwrap_or("");
    Ok(match name {
        "client_identifier" | "query_client_identifier" => {
            Dhcpv6Option::client_id(required_hex_field(object, "duid_hex")?)
        }
        "server_identifier" => Dhcpv6Option::server_id(required_hex_field(object, "duid_hex")?),
        "option_request" => Dhcpv6Option::oro(json_u16_array(object.get("requested"))?),
        "elapsed_time" => Dhcpv6Option::elapsed_time(required_json_u16(
            object,
            "centiseconds",
            "elapsed_time.centiseconds",
        )?),
        "ia_na" => ia_na_option(object)?,
        "ia_pd" => ia_pd_option(object)?,
        "rapid_commit" => Dhcpv6Option::rapid_commit(),
        "interface_id" => Dhcpv6Option::interface_id(required_hex_field(object, "hex")?),
        "relay_message" => Dhcpv6Option::relay_msg(relay_message_payload(object, spec)?),
        "reconfigure_message" => {
            let code = message_type_code_from_name(required_json_str(
                object,
                "message_type",
                "reconfigure_message.message_type",
            )?)?;
            Dhcpv6Option::reconfigure_message(Dhcpv6MessageType::from_code(code))
        }
        "reconfigure_accept" => Dhcpv6Option::reconfigure_accept(),
        "authentication" => Dhcpv6Option::raw(code, authentication_payload(object)?),
        "lq_query" => leasequery_option(object)?,
        "relay_id" => Dhcpv6Option::relay_id(required_hex_field(object, "data_hex")?),
        "lq_start_time" => Dhcpv6Option::leasequery_start_time(required_seconds(object)?),
        "lq_base_time" => Dhcpv6Option::leasequery_base_time(required_seconds(object)?),
        "clt_time" => Dhcpv6Option::client_time(required_seconds(object)?),
        "status_code" => status_option(object)?,
        "unknown" => Dhcpv6Option::raw(code, required_hex_field(object, "data_hex")?),
        _ => {
            if let Some(hex) = object.get("data_hex").and_then(Value::as_str) {
                Dhcpv6Option::raw(code, decode_hex(hex)?)
            } else if let Some(hex) = object.get("hex").and_then(Value::as_str) {
                Dhcpv6Option::raw(code, decode_hex(hex)?)
            } else {
                Dhcpv6Option::empty(code)
            }
        }
    })
}

fn ia_na_option(object: &Map<String, Value>) -> ExampleResult<Dhcpv6Option> {
    let mut ia_na = Dhcpv6IaNa::new(
        required_json_u32(object, "iaid", "ia_na.iaid")?,
        required_json_u32(object, "t1", "ia_na.t1")?,
        required_json_u32(object, "t2", "ia_na.t2")?,
    );
    for address in object
        .get("addresses")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let row = required_object(Some(address), "ia_na.addresses[]")?;
        let ia_addr = Dhcpv6IaAddr::new(
            required_json_str(row, "ipv6", "ia_na.addresses[].ipv6")?.parse::<Ipv6Addr>()?,
            required_json_u32(
                row,
                "preferred_lifetime",
                "ia_na.addresses[].preferred_lifetime",
            )?,
            required_json_u32(row, "valid_lifetime", "ia_na.addresses[].valid_lifetime")?,
        );
        ia_na = ia_na.ia_addr(ia_addr)?;
    }
    Ok(Dhcpv6Option::ia_na(ia_na)?)
}

fn ia_pd_option(object: &Map<String, Value>) -> ExampleResult<Dhcpv6Option> {
    let mut ia_pd = Dhcpv6IaPd::new(
        required_json_u32(object, "iaid", "ia_pd.iaid")?,
        required_json_u32(object, "t1", "ia_pd.t1")?,
        required_json_u32(object, "t2", "ia_pd.t2")?,
    );
    for prefix in object
        .get("prefixes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let row = required_object(Some(prefix), "ia_pd.prefixes[]")?;
        let ia_prefix = Dhcpv6IaPrefix::new(
            required_json_u32(
                row,
                "preferred_lifetime",
                "ia_pd.prefixes[].preferred_lifetime",
            )?,
            required_json_u32(row, "valid_lifetime", "ia_pd.prefixes[].valid_lifetime")?,
            required_json_u8(row, "prefix_length", "ia_pd.prefixes[].prefix_length")?,
            required_json_str(row, "prefix", "ia_pd.prefixes[].prefix")?.parse::<Ipv6Addr>()?,
        );
        ia_pd = ia_pd.ia_prefix(ia_prefix)?;
    }
    Ok(Dhcpv6Option::ia_pd(ia_pd)?)
}

fn relay_message_payload(
    row: &Map<String, Value>,
    spec: &Map<String, Value>,
) -> ExampleResult<Vec<u8>> {
    let relay = required_object(spec.get("relay"), "dhcpv6.relay")?;
    let nested = required_object(relay.get("relay_message"), "dhcpv6.relay.relay_message")?;
    let message_type_code = nested
        .get("message_type_code")
        .and_then(json_u8)
        .or_else(|| {
            row.get("message_type")
                .and_then(Value::as_str)
                .and_then(|name| message_type_code_from_name(name).ok())
        })
        .ok_or("relay message is missing message_type_code")?;
    let transaction_id = nested
        .get("transaction_id")
        .and_then(json_u32)
        .or_else(|| spec.get("transaction_id").and_then(json_u32))
        .ok_or("relay message is missing transaction_id")?;
    let mut inner = Dhcpv6::new()
        .message_type_code(message_type_code)
        .transaction_id(transaction_id);
    if let Some(duid_hex) = spec.get("client_duid_hex").and_then(Value::as_str) {
        inner = inner.client_id(decode_hex(duid_hex)?);
    }
    if message_type_code != 1 {
        if let Some(duid_hex) = spec.get("server_duid_hex").and_then(Value::as_str) {
            inner = inner.server_id(decode_hex(duid_hex)?);
        }
    }
    let bytes = Packet::from_layer(inner).compile()?;
    Ok(bytes.as_bytes().to_vec())
}

fn leasequery_option(object: &Map<String, Value>) -> ExampleResult<Dhcpv6Option> {
    let query_type = object
        .get("query_type_code")
        .and_then(json_u8)
        .or_else(|| {
            object
                .get("query_type")
                .and_then(Value::as_str)
                .map(leasequery_type_code_from_name)
        })
        .unwrap_or(1);
    let address = required_json_str(object, "address", "lq_query.address")?.parse::<Ipv6Addr>()?;
    Ok(Dhcpv6Option::leasequery(Dhcpv6Leasequery::new(
        Dhcpv6LeasequeryType::from_code(query_type),
        address,
    ))?)
}

fn status_option(object: &Map<String, Value>) -> ExampleResult<Dhcpv6Option> {
    let status_code = required_json_u16(object, "status_code", "status_code.status_code")?;
    Ok(Dhcpv6Option::status_code(Dhcpv6StatusCodeOption::new(
        Dhcpv6StatusCode::from_code(status_code),
    )))
}

fn authentication_payload(object: &Map<String, Value>) -> ExampleResult<Vec<u8>> {
    if let Some(hex) = object.get("data_hex").and_then(Value::as_str) {
        return decode_hex(hex);
    }
    let protocol = match object.get("protocol").and_then(Value::as_str) {
        Some("delayed") => 1,
        Some("configuration-token") => 0,
        Some("reconfigure-key") => 3,
        _ => object.get("protocol_code").and_then(json_u8).unwrap_or(1),
    };
    let algorithm = object.get("algorithm").and_then(json_u8).unwrap_or(1);
    let rdm = object.get("rdm").and_then(json_u8).unwrap_or(0);
    let replay_detection = object
        .get("replay_detection")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mut payload = Vec::with_capacity(11);
    payload.push(protocol);
    payload.push(algorithm);
    payload.push(rdm);
    payload.extend_from_slice(&replay_detection.to_be_bytes());
    Ok(payload)
}

/// Decode a DHCPv6 layer into stable JSON for probe reports.
pub fn dhcpv6_json(layer: &Dhcpv6) -> Value {
    json!({
        "message_type": message_type_label(layer.message_type_code_value()),
        "message_type_code": layer.message_type_code_value(),
        "transaction_id": layer.transaction_id_value(),
        "relay": layer.relay().map(|relay| json!({
            "hop_count": relay.hop_count_value(),
            "link_address": relay.link_address_value().to_string(),
            "peer_address": relay.peer_address_value().to_string(),
        })),
        "options": layer.options_ref().iter().map(option_json).collect::<Vec<_>>(),
        "option_count": layer.options_ref().len(),
    })
}

fn option_json(option: &Dhcpv6Option) -> Value {
    let mut value = json!({
        "code": option.codepoint(),
        "name": dhcpv6_option_name(option.codepoint()),
        "length": option.payload_len(),
        "payload_hex": hex_bytes(option.payload()),
    });
    if let Value::Object(map) = &mut value {
        if let Some(duid) = option.client_id_value() {
            map.insert("client_duid_hex".into(), json!(hex_bytes(duid)));
        }
        if let Some(duid) = option.server_id_value() {
            map.insert("server_duid_hex".into(), json!(hex_bytes(duid)));
        }
        if let Ok(Some(codes)) = option.oro_value() {
            map.insert(
                "requested".into(),
                json!(codes.iter().map(|code| code.code()).collect::<Vec<_>>()),
            );
        }
        if let Ok(Some(status)) = option.status_code_value() {
            map.insert("status_code".into(), json!(status.status().code()));
            map.insert("status".into(), json!(status.status().to_string()));
            if let Some(message) = status.message_text() {
                map.insert("status_message".into(), json!(message));
            }
        }
        if let Some(relay_msg) = option.relay_msg_value() {
            map.insert("relay_message_hex".into(), json!(hex_bytes(relay_msg)));
            if let Ok(nested) = Dhcpv6::decode(relay_msg) {
                map.insert("relay_message".into(), dhcpv6_json(&nested));
            }
        }
    }
    value
}

/// Validate one captured DHCPv6 candidate against the plan contract.
pub fn validate_dhcpv6_candidate(
    plan: &ProbePlan,
    packet: &Packet,
    raw: &[u8],
) -> ExampleResult<CandidateValidation> {
    let Some(dhcpv6) = packet.layer::<Dhcpv6>() else {
        return Ok(CandidateValidation::Ignore);
    };
    let decoded = decoded_packet_json(packet, raw);
    let peer_mismatches = dhcpv6_peer_mismatches(plan, packet);
    if !peer_mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPeer(json!({
            "packet": decoded,
            "mismatches": peer_mismatches,
        })));
    }

    let mut mismatches = Vec::new();
    let expected_type = expected_message_type_code(plan)?;
    if dhcpv6.message_type_code_value() != expected_type {
        mismatches.push(json!({
            "field": "dhcpv6.message_type_code",
            "expected": expected_type,
            "actual": dhcpv6.message_type_code_value(),
        }));
    }

    validate_transaction_id(plan, dhcpv6, &mut mismatches)?;
    validate_expected_options(plan, dhcpv6, &mut mismatches)?;
    validate_relay_reply(plan, dhcpv6, &mut mismatches)?;

    if mismatches.is_empty() {
        Ok(CandidateValidation::Passed(decoded))
    } else {
        Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": mismatches,
        })))
    }
}

fn dhcpv6_peer_mismatches(plan: &ProbePlan, packet: &Packet) -> Vec<Value> {
    let mut mismatches = Vec::new();
    if let Some(ipv6) = packet.layer::<Ipv6>() {
        if let Some(expected) = parse_optional_ipv6(plan.expected_reply_source_ipv6.as_deref()) {
            if ipv6.source() != expected {
                mismatches.push(json!({
                    "field": "ipv6.source",
                    "expected": expected.to_string(),
                    "actual": ipv6.source().to_string(),
                }));
            }
        }
        if let Some(expected) = parse_optional_ipv6(plan.expected_reply_destination_ipv6.as_deref())
        {
            if ipv6.destination() != expected {
                mismatches.push(json!({
                    "field": "ipv6.destination",
                    "expected": expected.to_string(),
                    "actual": ipv6.destination().to_string(),
                }));
            }
        }
    } else {
        mismatches.push(json!({
            "field": "ipv6",
            "expected": "present",
            "actual": "missing",
        }));
    }

    if let Some(udp) = packet.layer::<Udp>() {
        let expected_source_port = expected_reply_source_port(plan);
        let expected_destination_port = expected_reply_destination_port(plan);
        if udp.source_port_value() != expected_source_port {
            mismatches.push(json!({
                "field": "udp.sport",
                "expected": expected_source_port,
                "actual": udp.source_port_value(),
            }));
        }
        if udp.destination_port_value() != expected_destination_port {
            mismatches.push(json!({
                "field": "udp.dport",
                "expected": expected_destination_port,
                "actual": udp.destination_port_value(),
            }));
        }
    } else {
        mismatches.push(json!({
            "field": "udp",
            "expected": "present",
            "actual": "missing",
        }));
    }
    mismatches
}

fn validate_transaction_id(
    plan: &ProbePlan,
    dhcpv6: &Dhcpv6,
    mismatches: &mut Vec<Value>,
) -> ExampleResult<()> {
    let expected_transaction_id = expected_transaction_id(plan)?;
    if dhcpv6.message_type_code_value() == DHCPV6_RELAY_REPL {
        match dhcpv6.relayed_message_value()? {
            Some(inner) if inner.transaction_id_value() == expected_transaction_id => {}
            Some(inner) => mismatches.push(json!({
                "field": "dhcpv6.relay_message.transaction_id",
                "expected": expected_transaction_id,
                "actual": inner.transaction_id_value(),
            })),
            None => mismatches.push(json!({
                "field": "dhcpv6.relay_message",
                "expected": "present",
                "actual": "missing",
            })),
        }
    } else if dhcpv6.transaction_id_value() != expected_transaction_id {
        mismatches.push(json!({
            "field": "dhcpv6.transaction_id",
            "expected": expected_transaction_id,
            "actual": dhcpv6.transaction_id_value(),
        }));
    }
    Ok(())
}

fn validate_expected_options(
    plan: &ProbePlan,
    dhcpv6: &Dhcpv6,
    mismatches: &mut Vec<Value>,
) -> ExampleResult<()> {
    let spec = dhcpv6_contract(plan)?;
    let Some(expected_options) = spec.get("expected_options").and_then(Value::as_array) else {
        return Ok(());
    };
    for expected in expected_options {
        let row = required_object(Some(expected), "dhcpv6.expected_options[]")?;
        let code = required_json_u16(row, "code", "dhcpv6.expected_options[].code")?;
        let candidates = dhcpv6
            .options_ref()
            .iter()
            .filter(|option| option.codepoint() == code)
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            mismatches.push(json!({
                "field": "dhcpv6.options",
                "expected_code": code,
                "actual": "missing",
            }));
            continue;
        }
        if let Some(expected_duid) = row.get("duid_hex").and_then(Value::as_str) {
            let expected_bytes = decode_hex(expected_duid)?;
            if !candidates
                .iter()
                .any(|option| option.payload() == expected_bytes.as_slice())
            {
                mismatches.push(json!({
                    "field": format!("dhcpv6.option.{code}.duid"),
                    "expected": expected_duid,
                    "actual": candidates.iter().map(|option| hex_bytes(option.payload())).collect::<Vec<_>>(),
                }));
            }
        }
        if let Some(expected_hex) = row.get("data_hex").and_then(Value::as_str) {
            let expected_bytes = decode_hex(expected_hex)?;
            if !candidates
                .iter()
                .any(|option| option.payload() == expected_bytes.as_slice())
            {
                mismatches.push(json!({
                    "field": format!("dhcpv6.option.{code}.payload"),
                    "expected": expected_hex,
                    "actual": candidates.iter().map(|option| hex_bytes(option.payload())).collect::<Vec<_>>(),
                }));
            }
        }
        if let Some(expected_status) = row.get("status_code").and_then(json_u16) {
            let mut found = false;
            for option in &candidates {
                if let Some(status) = option.status_code_value()? {
                    found |= status.status().code() == expected_status;
                }
            }
            if !found {
                mismatches.push(json!({
                    "field": format!("dhcpv6.option.{code}.status_code"),
                    "expected": expected_status,
                    "actual": candidates.iter().map(|option| hex_bytes(option.payload())).collect::<Vec<_>>(),
                }));
            }
        }
    }
    Ok(())
}

fn validate_relay_reply(
    plan: &ProbePlan,
    dhcpv6: &Dhcpv6,
    mismatches: &mut Vec<Value>,
) -> ExampleResult<()> {
    if plan.case != "dhcpv6-relay-forward-reply" {
        return Ok(());
    }
    let spec = dhcpv6_contract(plan)?;
    let relay = required_object(spec.get("relay"), "dhcpv6.relay")?;
    if let Some(expected_interface_id) = relay.get("interface_id_hex").and_then(Value::as_str) {
        let expected = decode_hex(expected_interface_id)?;
        match dhcpv6.interface_id_value() {
            Some(actual) if actual == expected.as_slice() => {}
            Some(actual) => mismatches.push(json!({
                "field": "dhcpv6.interface_id",
                "expected": expected_interface_id,
                "actual": hex_bytes(actual),
            })),
            None => mismatches.push(json!({
                "field": "dhcpv6.interface_id",
                "expected": expected_interface_id,
                "actual": "missing",
            })),
        }
    }
    if let Some(expected_inner) = relay
        .get("expected_relay_message")
        .and_then(Value::as_object)
        .and_then(|object| object.get("message_type_code"))
        .and_then(json_u8)
    {
        match dhcpv6.relayed_message_value()? {
            Some(inner) if inner.message_type_code_value() == expected_inner => {}
            Some(inner) => mismatches.push(json!({
                "field": "dhcpv6.relay_message.message_type_code",
                "expected": expected_inner,
                "actual": inner.message_type_code_value(),
            })),
            None => mismatches.push(json!({
                "field": "dhcpv6.relay_message",
                "expected": "present",
                "actual": "missing",
            })),
        }
    }
    Ok(())
}

fn expected_message_type_code(plan: &ProbePlan) -> ExampleResult<u8> {
    let spec = dhcpv6_contract(plan)?;
    spec.get("expected_message_type_code")
        .and_then(json_u8)
        .ok_or_else(|| "DHCPv6 plan missing expected_message_type_code".into())
}

fn expected_transaction_id(plan: &ProbePlan) -> ExampleResult<u32> {
    let spec = dhcpv6_contract(plan)?;
    spec.get("transaction_id")
        .and_then(json_u32)
        .ok_or_else(|| "DHCPv6 plan missing transaction_id".into())
}

pub fn validation_json(plan: &ProbePlan) -> Value {
    let Some(spec) = plan.dhcpv6.as_ref() else {
        return json!({});
    };
    json!({
        "source_ipv6": plan.expected_reply_source_ipv6,
        "destination_ipv6": plan.expected_reply_destination_ipv6,
        "source_port": expected_reply_source_port(plan),
        "destination_port": expected_reply_destination_port(plan),
        "expected_message_type_code": spec.get("expected_message_type_code"),
        "transaction_id": spec.get("transaction_id"),
        "expected_options": spec.get("expected_options"),
        "relay": spec.get("relay"),
    })
}

fn dhcpv6_contract(plan: &ProbePlan) -> ExampleResult<&Map<String, Value>> {
    plan.dhcpv6
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| "DHCPv6 plan is missing the dhcpv6 contract".into())
}

fn expected_reply_source_port(plan: &ProbePlan) -> u16 {
    if plan.source_port == Some(DHCPV6_SERVER_PORT)
        && plan.destination_port == Some(DHCPV6_SERVER_PORT)
    {
        DHCPV6_SERVER_PORT
    } else {
        plan.destination_port.unwrap_or(DHCPV6_SERVER_PORT)
    }
}

fn expected_reply_destination_port(plan: &ProbePlan) -> u16 {
    plan.source_port.unwrap_or(DHCPV6_CLIENT_PORT)
}

fn required_object<'a>(
    value: Option<&'a Value>,
    field: &str,
) -> ExampleResult<&'a Map<String, Value>> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{field} must be an object").into())
}

fn required_json_str<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    field: &str,
) -> ExampleResult<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("probe plan missing required field {field}").into())
}

fn required_json_u8(object: &Map<String, Value>, key: &str, field: &str) -> ExampleResult<u8> {
    object
        .get(key)
        .and_then(json_u8)
        .ok_or_else(|| format!("probe plan missing required field {field}").into())
}

fn required_json_u16(object: &Map<String, Value>, key: &str, field: &str) -> ExampleResult<u16> {
    object
        .get(key)
        .and_then(json_u16)
        .ok_or_else(|| format!("probe plan missing required field {field}").into())
}

fn required_json_u32(object: &Map<String, Value>, key: &str, field: &str) -> ExampleResult<u32> {
    object
        .get(key)
        .and_then(json_u32)
        .ok_or_else(|| format!("probe plan missing required field {field}").into())
}

fn required_hex_field(object: &Map<String, Value>, key: &str) -> ExampleResult<Vec<u8>> {
    decode_hex(required_json_str(object, key, key)?)
}

fn required_seconds(object: &Map<String, Value>) -> ExampleResult<u32> {
    required_json_u32(object, "seconds", "seconds")
}

fn json_u8(value: &Value) -> Option<u8> {
    value.as_u64().and_then(|value| u8::try_from(value).ok())
}

fn json_u16(value: &Value) -> Option<u16> {
    value.as_u64().and_then(|value| u16::try_from(value).ok())
}

fn json_u32(value: &Value) -> Option<u32> {
    value.as_u64().and_then(|value| u32::try_from(value).ok())
}

fn json_u16_array(value: Option<&Value>) -> ExampleResult<Vec<u16>> {
    let Some(array) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    array
        .iter()
        .map(|item| json_u16(item).ok_or_else(|| "expected a DHCPv6 option codepoint".into()))
        .collect()
}

fn parse_optional_ipv6(value: Option<&str>) -> Option<Ipv6Addr> {
    value.and_then(|value| value.parse::<Ipv6Addr>().ok())
}

fn message_type_code_from_name(name: &str) -> ExampleResult<u8> {
    let code = match name {
        "solicit" => 1,
        "advertise" => 2,
        "request" => 3,
        "confirm" => 4,
        "renew" => 5,
        "rebind" => 6,
        "reply" => 7,
        "release" => 8,
        "decline" => 9,
        "reconfigure" => 10,
        "information-request" => 11,
        "relay-forward" => 12,
        "relay-reply" => 13,
        "leasequery" => 14,
        "leasequery-reply" => 15,
        "leasequery-done" => 16,
        "leasequery-data" => 17,
        "activeleasequery" => 22,
        other => return Err(format!("unsupported DHCPv6 message type {other:?}").into()),
    };
    Ok(code)
}

fn message_type_label(code: u8) -> String {
    match code {
        1 => "solicit".to_string(),
        2 => "advertise".to_string(),
        3 => "request".to_string(),
        4 => "confirm".to_string(),
        5 => "renew".to_string(),
        6 => "rebind".to_string(),
        7 => "reply".to_string(),
        8 => "release".to_string(),
        9 => "decline".to_string(),
        10 => "reconfigure".to_string(),
        11 => "information-request".to_string(),
        12 => "relay-forward".to_string(),
        13 => "relay-reply".to_string(),
        14 => "leasequery".to_string(),
        15 => "leasequery-reply".to_string(),
        16 => "leasequery-done".to_string(),
        17 => "leasequery-data".to_string(),
        22 => "activeleasequery".to_string(),
        other => format!("unknown({other})"),
    }
}

fn leasequery_type_code_from_name(name: &str) -> u8 {
    match name {
        "by_client_id" => 2,
        "by_relay_id" => 3,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    fn request(plan: ProbePlan) -> StimulusEndpointRequest {
        StimulusEndpointRequest {
            profile: "dhcpv6-smoke".to_string(),
            seed: 9925,
            endpoint_role: "stimulus".to_string(),
            interface: "eth0".to_string(),
            local_ipv4: "10.0.0.10".to_string(),
            peer_ipv4: "10.0.0.20".to_string(),
            timeout_seconds: 1,
            probe_plans: vec![plan],
            artifact_paths: json!({}),
            metadata: json!({}),
        }
    }

    fn information_request_plan() -> ProbePlan {
        let mut plan = base_plan("dhcpv6-information-request-reply");
        plan.sequence = 7;
        plan.expected_response = Some("dhcpv6_reply".to_string());
        plan.source_ipv6 = Some("2001:db8::10".to_string());
        plan.destination_ipv6 = Some("ff02::1:2".to_string());
        plan.target_ipv6 = Some("2001:db8::20".to_string());
        plan.expected_reply_source_ipv6 = Some("2001:db8::20".to_string());
        plan.expected_reply_destination_ipv6 = Some("2001:db8::10".to_string());
        plan.source_port = Some(DHCPV6_CLIENT_PORT);
        plan.destination_port = Some(DHCPV6_SERVER_PORT);
        plan.protocol = Some("dhcpv6".to_string());
        plan.planned_only = Some(true);
        plan.dhcpv6 = Some(json!({
            "message_type": "information-request",
            "message_type_code": 11,
            "expected_message_type": "reply",
            "expected_message_type_code": 7,
            "transaction_id": 0x0a0b0c,
            "client_duid_hex": "0003000100005e005301",
            "server_duid_hex": "0003000100005e005302",
            "options": [
                {"name": "client_identifier", "code": 1, "duid_hex": "0003000100005e005301"},
                {"name": "option_request", "code": 6, "requested": [23, 24]}
            ],
            "expected_options": [
                {"name": "server_identifier", "code": 2, "duid_hex": "0003000100005e005302"},
                {"name": "client_identifier", "code": 1, "duid_hex": "0003000100005e005301"}
            ],
            "relay": {"enabled": false}
        }));
        plan
    }

    #[test]
    fn dry_run_builds_and_decodes_information_request() {
        let plan = information_request_plan();
        let outcome = run_dhcpv6_dry_run(&request(plan.clone()), &plan).unwrap();
        assert!(!outcome.sent);
        assert!(!outcome.received);
        assert_eq!(outcome.result["status"], "planned");
        assert_eq!(
            outcome.result["metadata"]["sent_decoded"]["dhcpv6"]["message_type_code"],
            11
        );
        assert_eq!(
            outcome.result["metadata"]["sent_decoded"]["udp"]["sport"],
            DHCPV6_CLIENT_PORT
        );
    }

    #[test]
    fn validates_matching_reply_candidate() {
        let plan = information_request_plan();
        let response = Ipv6::with_addresses(
            "2001:db8::20".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        ) / Udp::dhcpv6_server()
            / Dhcpv6::reply(0x0a0b0c)
                .server_id(decode_hex("0003000100005e005302").unwrap())
                .client_id(decode_hex("0003000100005e005301").unwrap());
        let compiled = response.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes()).unwrap();

        match validate_dhcpv6_candidate(&plan, &decoded, compiled.as_bytes()).unwrap() {
            CandidateValidation::Passed(decoded) => {
                assert_eq!(decoded["dhcpv6"]["message_type_code"], 7);
            }
            other => panic!("expected passed candidate, got {other:?}"),
        }
    }

    #[test]
    fn validates_wrong_transaction_as_payload_mismatch() {
        let plan = information_request_plan();
        let response = Ipv6::with_addresses(
            "2001:db8::20".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        ) / Udp::dhcpv6_server()
            / Dhcpv6::reply(0x010203)
                .server_id(decode_hex("0003000100005e005302").unwrap())
                .client_id(decode_hex("0003000100005e005301").unwrap());
        let compiled = response.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes()).unwrap();

        match validate_dhcpv6_candidate(&plan, &decoded, compiled.as_bytes()).unwrap() {
            CandidateValidation::WrongPayload(decoded) => {
                assert_eq!(decoded["mismatches"][0]["field"], "dhcpv6.transaction_id");
            }
            other => panic!("expected payload mismatch, got {other:?}"),
        }
    }
}
