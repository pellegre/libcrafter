//! mDNS behavioral probe cases.
//!
//! The adapter materializes probe-engine mDNS contracts as typed libcrafter
//! IPv4/IPv6 + UDP/5353 + DNS packets. Dry-run compiles the stimulus packet by
//! default; live runs send query-shaped cases, capture target-emitted
//! announcement/goodbye cases, and treat known-answer suppression as an
//! expected absence.

use crafter::prelude::*;
use crafter::protocols::dns::mdns as dns_mdns;
use serde_json::{json, Value};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::common::{
    captured_data, decoded_packet_json, failed_outcome, hex_bytes, observed_response,
    open_capture_sniffer, plan_json, required_str, required_u16, send_report_json,
    target_service_json, CandidateValidation, ExampleResult, ProbeOutcome, ProbePlan,
    StimulusEndpointRequest, FAILURE_DECODE_FAILED, FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD,
    FAILURE_WRONG_PEER,
};

const DNS_QTYPE_ANY_VALUE: u16 = 255;

pub fn run_mdns_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = mdns_packet(plan)?;
    let filter = capture_filter(plan);
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
    let sent_decoded = decoded_mdns_packet_json(&sent_packet, sent_raw);
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
            "mdns": mdns_json_from_plan(plan)?,
            "expected_mdns": expected_mdns_json(plan),
            "capture_filter": filter,
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
            "mdns": mdns_json_from_plan(plan)?,
            "expected_mdns": expected_mdns_json(plan),
            "capture_filter": filter,
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

pub fn run_mdns_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    if is_capture_only_case(plan) {
        return run_mdns_capture_live(request, plan);
    }

    let packet = mdns_packet(plan)?;
    let filter = capture_filter(plan);
    let timeout = Duration::from_secs(request.timeout_seconds.max(1));
    let mut sniffer =
        match open_capture_sniffer(request.interface.clone(), timeout, 64, filter.clone()) {
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
        match validate_mdns_candidate(plan, captured.packet(), captured_data(&captured))? {
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
                        "capture_filter": filter,
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

    if expected_absence(plan) {
        return Ok(passed_absence_outcome(
            plan,
            json!({
                "send_report": send_report_json(&send_report),
                "capture_filter": filter,
                "expected_packet_count": 0,
            }),
            sent,
        ));
    }

    if let Some(decoded) = wrong_payload {
        return Ok(failed_outcome(
            plan,
            FAILURE_WRONG_PAYLOAD,
            vec!["captured mDNS response did not match expected DNS-SD records".to_string()],
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
            vec!["captured mDNS response did not match expected peer or UDP ports".to_string()],
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
        vec!["timed out waiting for mDNS response".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": filter,
        })),
        sent,
        false,
    ))
}

fn run_mdns_capture_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let expected_packet = mdns_packet(plan)?;
    let expected_raw = expected_packet.compile()?;
    let filter = capture_filter(plan);
    let timeout = Duration::from_secs(request.timeout_seconds.max(1));
    let mut sniffer =
        match open_capture_sniffer(request.interface.clone(), timeout, 64, filter.clone()) {
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
        match validate_mdns_candidate(plan, captured.packet(), captured_data(&captured))? {
            CandidateValidation::Ignore => {}
            CandidateValidation::Passed(decoded) => {
                let raw_hex = hex_bytes(captured_data(&captured));
                let observed = observed_response(
                    plan,
                    true,
                    Some(raw_hex.clone()),
                    decoded.clone(),
                    json!({
                        "capture_filter": filter,
                        "expected_raw_hex": hex_bytes(expected_raw.as_bytes()),
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
                        "expected_raw_hex": hex_bytes(expected_raw.as_bytes()),
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
            vec!["captured mDNS announcement did not match expected DNS-SD records".to_string()],
            Some(json!({
                "decoded": decoded,
                "expected_raw_hex": hex_bytes(expected_raw.as_bytes()),
            })),
            false,
            true,
        ));
    }

    if let Some(decoded) = wrong_peer {
        return Ok(failed_outcome(
            plan,
            FAILURE_WRONG_PEER,
            vec!["captured mDNS announcement did not match expected peer or UDP ports".to_string()],
            Some(json!({
                "decoded": decoded,
                "expected_raw_hex": hex_bytes(expected_raw.as_bytes()),
            })),
            false,
            true,
        ));
    }

    Ok(failed_outcome(
        plan,
        FAILURE_TIMEOUT,
        vec!["timed out waiting for mDNS announcement".to_string()],
        Some(json!({
            "capture_filter": filter,
            "expected_raw_hex": hex_bytes(expected_raw.as_bytes()),
        })),
        false,
        false,
    ))
}

pub fn mdns_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let message = required_value(plan.mdns.as_ref(), "mdns")?;
    let dns = mdns_message_from_json(message)?;
    let source_port = required_u16(plan.source_port, "source_port")?;
    let destination_port = required_u16(plan.destination_port, "destination_port")?;
    let udp = Udp::new().sport(source_port).dport(destination_port);

    if is_ipv6_plan(plan) {
        let source: Ipv6Addr = required_str(plan.source_ipv6.as_deref(), "source_ipv6")?.parse()?;
        let destination: Ipv6Addr =
            required_str(plan.destination_ipv6.as_deref(), "destination_ipv6")?.parse()?;
        return Ok(Ipv6::new()
            .src(source)
            .dst(destination)
            .hop_limit(dns_mdns::MDNS_RESPONSE_HOP_LIMIT)
            / udp
            / dns);
    }

    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    Ok(Ipv4::new()
        .src(source)
        .dst(destination)
        .ttl(dns_mdns::MDNS_RESPONSE_TTL)
        / udp
        / dns)
}

pub fn validate_mdns_candidate(
    plan: &ProbePlan,
    packet: &Packet,
    raw: &[u8],
) -> ExampleResult<CandidateValidation> {
    let Some(udp) = packet.layer::<Udp>() else {
        return Ok(CandidateValidation::Ignore);
    };

    let mut peer_mismatches = Vec::new();
    if is_ipv6_plan(plan) {
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

    let decoded = decoded_mdns_packet_json(packet, raw);
    if !peer_mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPeer(json!({
            "packet": decoded,
            "mismatches": peer_mismatches,
        })));
    }

    let Some(dns) = packet.layer::<Dns>() else {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": [{
                "field": "dns",
                "expected": "decoded mDNS/DNS layer",
                "actual": "missing",
            }],
        })));
    };

    if expected_absence(plan) {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": [{
                "field": "mdns.response",
                "expected": "absent",
                "actual": "present",
            }],
        })));
    }

    let expected = expected_mdns_value(plan)?;
    let mut mismatches = Vec::new();
    validate_mdns_header(expected, dns, &mut mismatches);
    validate_mdns_questions(expected, dns, &mut mismatches)?;
    validate_mdns_records(expected, dns, &mut mismatches)?;

    if !mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": mismatches,
        })));
    }

    Ok(CandidateValidation::Passed(decoded))
}

pub fn capture_filter(plan: &ProbePlan) -> String {
    if let Some(filter) = plan.capture_filter.as_deref() {
        return filter.to_string();
    }

    if is_ipv6_plan(plan) {
        return format!(
            "ip6 and udp and src host {} and dst host {} and src port {} and dst port {}",
            plan.expected_reply_source_ipv6.as_deref().unwrap_or(""),
            plan.expected_reply_destination_ipv6
                .as_deref()
                .unwrap_or(""),
            plan.destination_port.unwrap_or(dns_mdns::MDNS_PORT),
            expected_response_destination_port(plan).unwrap_or(0),
        );
    }

    if expected_absence(plan) {
        return format!(
            "udp and src host {} and port {}",
            plan.expected_reply_source_ipv4.as_deref().unwrap_or(""),
            plan.destination_port.unwrap_or(dns_mdns::MDNS_PORT),
        );
    }

    format!(
        "udp and src host {} and dst host {} and src port {} and dst port {}",
        plan.expected_reply_source_ipv4.as_deref().unwrap_or(""),
        plan.expected_reply_destination_ipv4
            .as_deref()
            .unwrap_or(""),
        plan.destination_port.unwrap_or(dns_mdns::MDNS_PORT),
        expected_response_destination_port(plan).unwrap_or(0),
    )
}

pub fn validation_json(plan: &ProbePlan) -> Value {
    json!({
        "expected_decode": if expected_absence(plan) { "no_mdns_response" } else { "mdns" },
        "transport": "udp",
        "source_port": plan.source_port,
        "destination_port": plan.destination_port,
        "source_ipv4": plan.expected_reply_source_ipv4,
        "destination_ipv4": plan.expected_reply_destination_ipv4,
        "source_ipv6": plan.expected_reply_source_ipv6,
        "destination_ipv6": plan.expected_reply_destination_ipv6,
        "expected_packet_count": expected_packet_count(plan),
        "mdns": plan.mdns,
        "expected_mdns": plan.expected_mdns,
    })
}

pub fn mdns_json(dns: &Dns) -> Value {
    json!({
        "id": dns.id_value(),
        "flags": dns.flags_value(),
        "is_response": dns.is_response(),
        "authoritative_answer": dns.flags_value() & DNS_FLAG_AUTHORITATIVE != 0,
        "response_code": dns.flags_value() & 0x000f,
        "questions": dns.questions().iter().map(mdns_question_json).collect::<Vec<_>>(),
        "answers": dns.answers().iter().map(mdns_record_json).collect::<Vec<_>>(),
        "authorities": dns.authorities().iter().map(mdns_record_json).collect::<Vec<_>>(),
        "additionals": dns.additionals().iter().map(mdns_record_json).collect::<Vec<_>>(),
    })
}

fn mdns_message_from_json(message: &Value) -> ExampleResult<Dns> {
    if value_str(message.get("message_kind")).unwrap_or_default() == "suppressed" {
        return Err("cannot build packet for suppressed mDNS response".into());
    }

    let response = value_bool(message.get("response")).unwrap_or_else(|| {
        value_str(message.get("message_kind"))
            .is_some_and(|kind| kind == "response" || kind == "announcement" || kind == "goodbye")
    });
    let transaction_id = value_u16(message.get("transaction_id"))?.unwrap_or(0);
    let questions = question_vec(message.get("questions"))?;
    let answers = record_vec(message.get("answers"))?;
    let authorities = record_vec(message.get("authority"))?;
    let additionals = record_vec(message.get("additional"))?;

    let mut dns = if response {
        let mut dns = if value_bool(message.get("goodbye")).unwrap_or(false) {
            dns_mdns::goodbye_response(answers)
        } else {
            dns_mdns::response_with_answers(answers)
        };
        if !value_bool(message.get("authoritative_answer")).unwrap_or(true) {
            dns = dns.authoritative(false);
        }
        dns
    } else {
        let mut questions = questions.into_iter();
        let first_question = questions
            .next()
            .ok_or("mdns.questions requires at least one item")?;
        let mut dns = dns_mdns::query(first_question);
        for question in questions {
            dns = dns.question(question);
        }
        for answer in answers {
            dns = dns.mdns_known_answer(answer);
        }
        dns
    };

    for authority in authorities {
        dns = dns.authority(authority);
    }
    for additional in additionals {
        dns = dns.additional(additional);
    }

    Ok(dns.id(transaction_id))
}

fn question_vec(value: Option<&Value>) -> ExampleResult<Vec<DnsQuestion>> {
    let mut questions = Vec::new();
    for (index, item) in value_array(value).iter().enumerate() {
        questions.push(question_from_json(item, index)?);
    }
    Ok(questions)
}

fn question_from_json(value: &Value, index: usize) -> ExampleResult<DnsQuestion> {
    let field = format!("mdns.questions[{index}]");
    let name = required_json_str(value.get("name"), &format!("{field}.name"))?;
    let record_type = record_type_value(value, &field)?;
    let class = class_value(value.get("class"))?.unwrap_or(DNS_CLASS_IN);
    let mut question = DnsQuestion::new(name, record_type).qclass(class);
    if value_bool(value.get("unicast_response")).unwrap_or(false) {
        question = question.mdns_qu(true);
    }
    Ok(question)
}

fn record_vec(value: Option<&Value>) -> ExampleResult<Vec<DnsRecord>> {
    let mut records = Vec::new();
    for (index, item) in value_array(value).iter().enumerate() {
        records.push(record_from_json(item, index)?);
    }
    Ok(records)
}

fn record_from_json(value: &Value, index: usize) -> ExampleResult<DnsRecord> {
    let field = format!("mdns.records[{index}]");
    let name = required_json_str(value.get("name"), &format!("{field}.name"))?;
    let record_type = record_type_value(value, &field)?;
    let class = class_value(value.get("class"))?.unwrap_or(DNS_CLASS_IN);
    let ttl = value_u32(value.get("ttl"))?.unwrap_or(dns_mdns::MDNS_RESPONSE_TTL as u32);
    let data = match record_type {
        DNS_TYPE_PTR => {
            let target = required_json_str(value.get("target"), &format!("{field}.target"))?;
            DnsRecordData::name(target)
        }
        DNS_TYPE_SRV => {
            let target = required_json_str(value.get("target"), &format!("{field}.target"))?;
            DnsRecordData::Srv {
                priority: value_u16(value.get("priority"))?.unwrap_or(0),
                weight: value_u16(value.get("weight"))?.unwrap_or(0),
                port: required_json_u16(value.get("port"), &format!("{field}.port"))?,
                target: target.into(),
            }
        }
        DNS_TYPE_TXT => DnsRecordData::Txt(txt_string_bytes(value.get("strings"))?),
        DNS_TYPE_A => DnsRecordData::A(
            required_json_str(value.get("address"), &format!("{field}.address"))?.parse()?,
        ),
        DNS_TYPE_AAAA => DnsRecordData::Aaaa(
            required_json_str(value.get("address"), &format!("{field}.address"))?.parse()?,
        ),
        other => return Err(format!("unsupported mDNS record type: {other}").into()),
    };
    let mut record = DnsRecord::new(name, record_type, class, ttl, data);
    if let Some(cache_flush) = value_bool(value.get("cache_flush")) {
        record = record.mdns_cache_flush(cache_flush);
    }
    Ok(record)
}

fn validate_ipv4_peer(
    plan: &ProbePlan,
    packet: &Packet,
    mismatches: &mut Vec<Value>,
) -> ExampleResult<()> {
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

fn validate_mdns_header(expected: &Value, dns: &Dns, mismatches: &mut Vec<Value>) {
    let expected_id = value_u16(expected.get("transaction_id"))
        .ok()
        .flatten()
        .unwrap_or(0);
    if dns.id_value() != expected_id {
        mismatches.push(json!({
            "field": "dns.id",
            "expected": expected_id,
            "actual": dns.id_value(),
        }));
    }

    let expected_response = value_bool(expected.get("response")).unwrap_or(true);
    if dns.is_response() != expected_response {
        mismatches.push(json!({
            "field": "dns.qr",
            "expected": expected_response,
            "actual": dns.is_response(),
        }));
    }

    if let Some(authoritative) = value_bool(expected.get("authoritative_answer")) {
        let actual = dns.flags_value() & DNS_FLAG_AUTHORITATIVE != 0;
        if actual != authoritative {
            mismatches.push(json!({
                "field": "dns.aa",
                "expected": authoritative,
                "actual": actual,
            }));
        }
    }

    let actual_rcode = (dns.flags_value() & 0x000f) as u8;
    if actual_rcode != 0 {
        mismatches.push(json!({
            "field": "dns.rcode",
            "expected": 0,
            "actual": actual_rcode,
        }));
    }
}

fn validate_mdns_questions(
    expected: &Value,
    dns: &Dns,
    mismatches: &mut Vec<Value>,
) -> ExampleResult<()> {
    let expected_questions = value_array(expected.get("questions"));
    if expected_questions.len() != dns.questions().len() {
        mismatches.push(json!({
            "field": "dns.question_count",
            "expected": expected_questions.len(),
            "actual": dns.questions().len(),
        }));
        return Ok(());
    }

    for (index, expected_question) in expected_questions.iter().enumerate() {
        let actual = &dns.questions()[index];
        let name = canonical_dns_name(required_json_str(
            expected_question.get("name"),
            &format!("expected_mdns.questions[{index}].name"),
        )?);
        let qtype = record_type_value(expected_question, "expected_mdns.question")?;
        let base_class = class_value(expected_question.get("class"))?.unwrap_or(DNS_CLASS_IN);
        let qu = value_bool(expected_question.get("unicast_response")).unwrap_or(false);
        if !actual.name().eq_ignore_ascii_case(&name) {
            mismatches.push(json!({
                "field": format!("dns.questions[{index}].name"),
                "expected": name,
                "actual": actual.name(),
            }));
        }
        if actual.question_type() != qtype {
            mismatches.push(json!({
                "field": format!("dns.questions[{index}].type"),
                "expected": qtype,
                "actual": actual.question_type(),
            }));
        }
        if actual.mdns_base_question_class() != base_class {
            mismatches.push(json!({
                "field": format!("dns.questions[{index}].class"),
                "expected": base_class,
                "actual": actual.mdns_base_question_class(),
            }));
        }
        if actual.mdns_unicast_response_preferred_value() != qu {
            mismatches.push(json!({
                "field": format!("dns.questions[{index}].qu"),
                "expected": qu,
                "actual": actual.mdns_unicast_response_preferred_value(),
            }));
        }
    }
    Ok(())
}

fn validate_mdns_records(
    expected: &Value,
    dns: &Dns,
    mismatches: &mut Vec<Value>,
) -> ExampleResult<()> {
    let expected_answers = value_array(expected.get("answers"));
    if expected_answers.len() != dns.answers().len() {
        mismatches.push(json!({
            "field": "dns.answer_count",
            "expected": expected_answers.len(),
            "actual": dns.answers().len(),
        }));
    }

    for (index, expected_record) in expected_answers.iter().enumerate() {
        if !dns
            .answers()
            .iter()
            .any(|actual| mdns_record_matches(actual, expected_record).unwrap_or(false))
        {
            mismatches.push(json!({
                "field": format!("dns.answers[{index}]"),
                "expected": expected_record,
                "actual": dns.answers().iter().map(mdns_record_json).collect::<Vec<_>>(),
            }));
        }
    }

    if value_bool(expected.get("cache_flush_required")).unwrap_or(false)
        && !dns.answers().iter().any(DnsRecord::mdns_cache_flush_value)
    {
        mismatches.push(json!({
            "field": "dns.answers.cache_flush",
            "expected": "at least one cache-flush answer",
            "actual": dns.answers().iter().map(mdns_record_json).collect::<Vec<_>>(),
        }));
    }

    if value_bool(expected.get("goodbye")).unwrap_or(false)
        && dns.answers().iter().any(|record| record.ttl() != 0)
    {
        mismatches.push(json!({
            "field": "dns.answers.ttl",
            "expected": 0,
            "actual": dns.answers().iter().map(mdns_record_json).collect::<Vec<_>>(),
        }));
    }

    if let Some(keys) = txt_keys(expected.get("bonjour_txt_keys")) {
        let actual_keys = dns
            .answers()
            .iter()
            .filter(|record| record.record_type() == DNS_TYPE_TXT)
            .flat_map(|record| txt_keys_from_record(record).unwrap_or_default())
            .collect::<Vec<_>>();
        for key in keys {
            if !actual_keys.iter().any(|actual| actual == &key) {
                mismatches.push(json!({
                    "field": "dns.answers.txt.keys",
                    "expected_key": key,
                    "actual_keys": actual_keys,
                }));
            }
        }
    }

    Ok(())
}

fn mdns_record_matches(record: &DnsRecord, expected: &Value) -> ExampleResult<bool> {
    let name = canonical_dns_name(required_json_str(expected.get("name"), "record.name")?);
    let record_type = record_type_value(expected, "record")?;
    let base_class = class_value(expected.get("class"))?.unwrap_or(DNS_CLASS_IN);
    if !record.name().eq_ignore_ascii_case(&name)
        || record.record_type() != record_type
        || record.mdns_base_class() != base_class
    {
        return Ok(false);
    }
    if let Some(ttl) = value_u32(expected.get("ttl"))? {
        if record.ttl() != ttl {
            return Ok(false);
        }
    }
    if let Some(cache_flush) = value_bool(expected.get("cache_flush")) {
        if record.mdns_cache_flush_value() != cache_flush {
            return Ok(false);
        }
    }

    Ok(match (record_type, record.data()) {
        (DNS_TYPE_PTR, DnsRecordData::Name(target)) => {
            target
                .presentation()
                .eq_ignore_ascii_case(&canonical_dns_name(required_json_str(
                    expected.get("target"),
                    "record.target",
                )?))
        }
        (DNS_TYPE_A, DnsRecordData::A(address)) => expected
            .get("address")
            .and_then(Value::as_str)
            .is_some_and(|expected| {
                expected
                    .parse::<Ipv4Addr>()
                    .is_ok_and(|value| value == *address)
            }),
        (DNS_TYPE_AAAA, DnsRecordData::Aaaa(address)) => expected
            .get("address")
            .and_then(Value::as_str)
            .is_some_and(|expected| {
                expected
                    .parse::<Ipv6Addr>()
                    .is_ok_and(|value| value == *address)
            }),
        (
            DNS_TYPE_SRV,
            DnsRecordData::Srv {
                priority,
                weight,
                port,
                target,
            },
        ) => {
            *priority == value_u16(expected.get("priority"))?.unwrap_or(0)
                && *weight == value_u16(expected.get("weight"))?.unwrap_or(0)
                && *port == required_json_u16(expected.get("port"), "record.port")?
                && target
                    .presentation()
                    .eq_ignore_ascii_case(&canonical_dns_name(required_json_str(
                        expected.get("target"),
                        "record.target",
                    )?))
        }
        (DNS_TYPE_TXT, DnsRecordData::Txt(strings)) => {
            *strings == txt_string_bytes(expected.get("strings"))?
        }
        _ => false,
    })
}

fn expected_response_source_port(plan: &ProbePlan) -> ExampleResult<u16> {
    required_u16(plan.destination_port, "destination_port")
}

fn expected_response_destination_port(plan: &ProbePlan) -> ExampleResult<u16> {
    if is_capture_only_case(plan) {
        return required_u16(plan.destination_port, "destination_port");
    }
    required_u16(plan.source_port, "source_port")
}

fn expected_packet_count(plan: &ProbePlan) -> usize {
    plan.expected_mdns
        .as_ref()
        .and_then(|value| value.get("expected_packet_count"))
        .and_then(Value::as_u64)
        .unwrap_or(1) as usize
}

fn expected_absence(plan: &ProbePlan) -> bool {
    expected_packet_count(plan) == 0
        || plan
            .expected_mdns
            .as_ref()
            .and_then(|value| value.get("message_kind"))
            .and_then(Value::as_str)
            == Some("suppressed")
}

fn is_capture_only_case(plan: &ProbePlan) -> bool {
    matches!(plan.case.as_str(), "mdns-announcement" | "mdns-goodbye")
}

fn is_ipv6_plan(plan: &ProbePlan) -> bool {
    plan.address_family.as_deref() == Some("ipv6")
        || plan.source_ipv6.is_some()
        || plan.destination_ipv6.is_some()
}

fn network_layer(plan: &ProbePlan) -> NetworkLayer {
    if is_ipv6_plan(plan) {
        NetworkLayer::Ipv6
    } else {
        NetworkLayer::Ipv4
    }
}

fn decoded_mdns_packet_json(packet: &Packet, raw: &[u8]) -> Value {
    let mut decoded = decoded_packet_json(packet, raw);
    if let Value::Object(map) = &mut decoded {
        map.insert(
            "mdns".into(),
            packet.layer::<Dns>().map(mdns_json).unwrap_or(Value::Null),
        );
    }
    decoded
}

fn passed_absence_outcome(plan: &ProbePlan, metadata: Value, sent: bool) -> ProbeOutcome {
    let observed = observed_response(
        plan,
        false,
        None,
        json!({
            "expected_packet_count": 0,
            "response": "absent",
        }),
        metadata.clone(),
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
            "expected_absence": true,
            "detail": metadata,
        }
    });
    ProbeOutcome {
        result,
        observed_response: observed,
        sent,
        received: false,
    }
}

fn mdns_json_from_plan(plan: &ProbePlan) -> ExampleResult<Value> {
    match plan.mdns.as_ref() {
        Some(message) => Ok(mdns_json(&mdns_message_from_json(message)?)),
        None => Ok(Value::Null),
    }
}

fn expected_mdns_json(plan: &ProbePlan) -> Value {
    plan.expected_mdns.clone().unwrap_or(Value::Null)
}

fn expected_mdns_value(plan: &ProbePlan) -> ExampleResult<&Value> {
    required_value(plan.expected_mdns.as_ref(), "expected_mdns")
}

fn required_value<'a>(value: Option<&'a Value>, field: &str) -> ExampleResult<&'a Value> {
    value.ok_or_else(|| format!("{field} is required").into())
}

fn required_json_str<'a>(value: Option<&'a Value>, field: &str) -> ExampleResult<&'a str> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{field} is required").into())
}

fn required_json_u16(value: Option<&Value>, field: &str) -> ExampleResult<u16> {
    value_u16(value)?.ok_or_else(|| format!("{field} is required").into())
}

fn value_array(value: Option<&Value>) -> Vec<&Value> {
    value
        .and_then(Value::as_array)
        .map(|array| array.iter().collect())
        .unwrap_or_default()
}

fn value_str(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

fn value_bool(value: Option<&Value>) -> Option<bool> {
    value.and_then(Value::as_bool)
}

fn value_u16(value: Option<&Value>) -> ExampleResult<Option<u16>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let number = value
        .as_u64()
        .ok_or_else(|| format!("expected unsigned integer, got {value}"))?;
    u16::try_from(number)
        .map(Some)
        .map_err(|_| format!("value does not fit in u16: {number}").into())
}

fn value_u32(value: Option<&Value>) -> ExampleResult<Option<u32>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let number = value
        .as_u64()
        .ok_or_else(|| format!("expected unsigned integer, got {value}"))?;
    u32::try_from(number)
        .map(Some)
        .map_err(|_| format!("value does not fit in u32: {number}").into())
}

fn class_value(value: Option<&Value>) -> ExampleResult<Option<u16>> {
    match value {
        None => Ok(None),
        Some(Value::Number(_)) => value_u16(value),
        Some(Value::String(label)) if label.eq_ignore_ascii_case("IN") => Ok(Some(DNS_CLASS_IN)),
        Some(Value::String(label)) if label.eq_ignore_ascii_case("ANY") => Ok(Some(DNS_CLASS_ANY)),
        Some(other) => Err(format!("unsupported DNS class: {other}").into()),
    }
}

fn record_type_value(value: &Value, field: &str) -> ExampleResult<u16> {
    if let Some(number) = value_u16(value.get("record_type_value"))? {
        return Ok(number);
    }
    let label = required_json_str(value.get("record_type"), &format!("{field}.record_type"))?;
    match label.to_ascii_uppercase().as_str() {
        "A" => Ok(DNS_TYPE_A),
        "AAAA" => Ok(DNS_TYPE_AAAA),
        "PTR" => Ok(DNS_TYPE_PTR),
        "SRV" => Ok(DNS_TYPE_SRV),
        "TXT" => Ok(DNS_TYPE_TXT),
        "ANY" => Ok(DNS_QTYPE_ANY_VALUE),
        other => Err(format!("unsupported mDNS record type: {other}").into()),
    }
}

fn txt_string_bytes(value: Option<&Value>) -> ExampleResult<Vec<Vec<u8>>> {
    let Some(values) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut strings = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        strings.push(
            required_json_str(Some(value), &format!("strings[{index}]"))?
                .as_bytes()
                .to_vec(),
        );
    }
    Ok(strings)
}

fn txt_keys(value: Option<&Value>) -> Option<Vec<String>> {
    let keys = value?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();
    Some(keys)
}

fn txt_keys_from_record(record: &DnsRecord) -> Option<Vec<String>> {
    let DnsRecordData::Txt(strings) = record.data() else {
        return None;
    };
    Some(
        strings
            .iter()
            .filter_map(|bytes| std::str::from_utf8(bytes).ok())
            .filter_map(|value| value.split_once('=').map(|(key, _)| key.to_string()))
            .collect(),
    )
}

fn canonical_dns_name(name: &str) -> String {
    let dns_name: DnsName = name.into();
    dns_name.presentation().to_ascii_lowercase()
}

fn mdns_question_json(question: &DnsQuestion) -> Value {
    json!({
        "name": question.name(),
        "type": question.question_type(),
        "class": question.question_class(),
        "base_class": question.mdns_base_question_class(),
        "unicast_response": question.mdns_unicast_response_preferred_value(),
    })
}

fn mdns_record_json(record: &DnsRecord) -> Value {
    json!({
        "name": record.name(),
        "type": record.record_type(),
        "class": record.class(),
        "base_class": record.mdns_base_class(),
        "cache_flush": record.mdns_cache_flush_value(),
        "ttl": record.ttl(),
        "data": mdns_record_data_json(record.data()),
    })
}

fn mdns_record_data_json(data: &DnsRecordData) -> Value {
    match data {
        DnsRecordData::A(address) => json!({
            "kind": "A",
            "value": address.to_string(),
        }),
        DnsRecordData::Aaaa(address) => json!({
            "kind": "AAAA",
            "value": address.to_string(),
        }),
        DnsRecordData::Name(name) => json!({
            "kind": "name",
            "value": name.presentation(),
        }),
        DnsRecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => json!({
            "kind": "srv",
            "priority": priority,
            "weight": weight,
            "port": port,
            "target": target.presentation(),
        }),
        DnsRecordData::Txt(strings) => json!({
            "kind": "txt",
            "values": strings
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                .collect::<Vec<_>>(),
            "values_hex": strings.iter().map(|bytes| hex_bytes(bytes)).collect::<Vec<_>>(),
        }),
        DnsRecordData::Raw(bytes) => json!({
            "kind": "raw",
            "hex": hex_bytes(bytes),
        }),
        _ => json!({
            "kind": "other",
            "debug": format!("{data:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    fn browse_plan(case: &str) -> ProbePlan {
        let mut plan = base_plan(case);
        plan.protocol = Some("mdns".to_string());
        plan.address_family = Some("ipv4".to_string());
        plan.source_ipv4 = Some("192.0.2.10".to_string());
        plan.destination_ipv4 = Some("224.0.0.251".to_string());
        plan.target_ipv4 = Some("198.51.100.20".to_string());
        plan.expected_reply_source_ipv4 = Some("198.51.100.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("224.0.0.251".to_string());
        plan.source_port = Some(dns_mdns::MDNS_PORT);
        plan.destination_port = Some(dns_mdns::MDNS_PORT);
        plan.service_port = Some(dns_mdns::MDNS_PORT);
        plan.multicast_group = Some("224.0.0.251".to_string());
        plan.mdns = Some(json!({
            "transaction_id": 0,
            "message_kind": "query",
            "response": false,
            "questions": [{
                "name": "_ipp._tcp.local.",
                "record_type": "PTR",
                "class": "IN",
                "unicast_response": case == "mdns-qu-unicast-response",
            }],
            "answers": [],
            "authority": [],
            "additional": [],
        }));
        plan.expected_mdns = Some(expected_response());
        plan
    }

    fn expected_response() -> Value {
        json!({
            "transaction_id": 0,
            "message_kind": "response",
            "response": true,
            "authoritative_answer": true,
            "questions": [],
            "answers": [
                {
                    "name": "_ipp._tcp.local.",
                    "record_type": "PTR",
                    "class": "IN",
                    "ttl": 120,
                    "target": "Crafter Printer 1._ipp._tcp.local.",
                    "cache_flush": false,
                },
                {
                    "name": "Crafter Printer 1._ipp._tcp.local.",
                    "record_type": "SRV",
                    "class": "IN",
                    "ttl": 120,
                    "priority": 0,
                    "weight": 0,
                    "port": 631,
                    "target": "printer.local.",
                    "cache_flush": true,
                },
                {
                    "name": "Crafter Printer 1._ipp._tcp.local.",
                    "record_type": "TXT",
                    "class": "IN",
                    "ttl": 120,
                    "strings": ["txtvers=1", "qtotal=1"],
                    "cache_flush": true,
                },
                {
                    "name": "printer.local.",
                    "record_type": "A",
                    "class": "IN",
                    "ttl": 120,
                    "address": "198.51.100.20",
                    "cache_flush": true,
                }
            ],
            "authority": [],
            "additional": [],
        })
    }

    fn response_packet_bytes() -> Vec<u8> {
        let dns = dns_mdns::response_with_answers([
            dns_mdns::service_ptr(
                "_ipp._tcp.local.",
                "Crafter Printer 1._ipp._tcp.local.",
                120,
            ),
            dns_mdns::srv(
                "Crafter Printer 1._ipp._tcp.local.",
                "printer.local.",
                631,
                120,
            )
            .mdns_cache_flush(true),
            dns_mdns::txt(
                "Crafter Printer 1._ipp._tcp.local.",
                [b"txtvers=1".as_slice(), b"qtotal=1".as_slice()],
                120,
            )
            .mdns_cache_flush(true),
            dns_mdns::a("printer.local.", Ipv4Addr::new(198, 51, 100, 20), 120)
                .mdns_cache_flush(true),
        ]);
        (Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 20))
            .dst(dns_mdns::MDNS_IPV4_MULTICAST)
            .ttl(dns_mdns::MDNS_RESPONSE_TTL)
            / Udp::new()
                .sport(dns_mdns::MDNS_PORT)
                .dport(dns_mdns::MDNS_PORT)
            / dns)
            .compile()
            .expect("mDNS response compiles")
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn mdns_query_packet_compiles_with_qu_bit() {
        let mut plan = browse_plan("mdns-qu-unicast-response");
        plan.source_port = Some(55_000);
        plan.expected_reply_destination_ipv4 = Some("192.0.2.10".to_string());
        if let Some(Value::Object(message)) = &mut plan.mdns {
            if let Some(Value::Array(questions)) = message.get_mut("questions") {
                questions[0]["unicast_response"] = json!(true);
            }
        }

        let packet = mdns_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        assert!(bytes.len() >= 40, "mDNS packet too short: {}", bytes.len());
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert_eq!(dns.id_value(), 0);
        assert!(!dns.is_response());
        assert!(dns.questions()[0].mdns_unicast_response_preferred_value());
    }

    #[test]
    fn mdns_response_validation_checks_service_records() {
        let raw = response_packet_bytes();
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = browse_plan("mdns-ipv4-multicast-browse");

        match validate_mdns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(decoded) => {
                assert_eq!(decoded["mdns"]["answers"].as_array().unwrap().len(), 4);
            }
            other => panic!("expected mDNS candidate to pass, got {other:?}"),
        }
    }

    #[test]
    fn mdns_unsolicited_response_preserves_record_cache_flush_bits() {
        let mut message = expected_response();
        message["unsolicited"] = json!(true);

        let dns = mdns_message_from_json(&message).unwrap();

        assert!(!dns.answers()[0].mdns_cache_flush_value());
        assert!(dns.answers()[1].mdns_cache_flush_value());
    }

    #[test]
    fn mdns_engine_plan_deserializes_and_dry_run_reports_decoded_packet() {
        let plan_json = json!({
            "case": "mdns-ipv4-multicast-browse",
            "sequence": 0,
            "protocol": "mdns",
            "address_family": "ipv4",
            "source_ipv4": "192.0.2.10",
            "destination_ipv4": "224.0.0.251",
            "target_ipv4": "198.51.100.20",
            "expected_reply_source_ipv4": "198.51.100.20",
            "expected_reply_destination_ipv4": "224.0.0.251",
            "source_port": 5353,
            "destination_port": 5353,
            "service_port": 5353,
            "multicast_group": "224.0.0.251",
            "planned_only": true,
            "mdns": {
                "transaction_id": 0,
                "message_kind": "query",
                "response": false,
                "questions": [{
                    "name": "_ipp._tcp.local.",
                    "record_type": "PTR",
                    "class": "IN",
                    "unicast_response": false
                }],
                "answers": [],
                "authority": [],
                "additional": []
            },
            "expected_mdns": expected_response(),
            "target_service": {
                "required": true,
                "kind": "mdns-controlled-responder",
                "protocol": "udp",
                "port": 5353
            },
            "capture_filter": concat!(
                "udp and src host 198.51.100.20 and dst host 224.0.0.251 ",
                "and src port 5353 and dst port 5353"
            )
        });
        let plan: ProbePlan = serde_json::from_value(plan_json).unwrap();
        let request = StimulusEndpointRequest {
            provider: "local-dry-run".to_string(),
            profile: "mdns-smoke".to_string(),
            seed: 5353,
            endpoint_role: "stimulus".to_string(),
            interface: "dry-run0".to_string(),
            local_ipv4: "192.0.2.10".to_string(),
            peer_ipv4: "198.51.100.20".to_string(),
            timeout_seconds: 1,
            probe_plans: vec![plan.clone()],
            artifact_paths: json!({}),
            metadata: json!({}),
        };

        let outcome = run_mdns_dry_run(&request, &plan).unwrap();

        assert_eq!(outcome.result["status"], "planned");
        assert_eq!(
            outcome.result["metadata"]["sent_decoded"]["mdns"]["questions"][0]["name"],
            "_ipp._tcp.local."
        );
        assert_eq!(
            outcome.result["metadata"]["target_service"]["kind"],
            "mdns-controlled-responder"
        );
    }

    #[test]
    fn mdns_known_answer_suppression_rejects_unexpected_response() {
        let mut plan = browse_plan("mdns-known-answer-suppression");
        plan.expected_mdns = Some(json!({
            "transaction_id": 0,
            "message_kind": "suppressed",
            "expected_packet_count": 0,
            "reason": "known_answer_ttl_at_least_half_original",
        }));
        let raw = response_packet_bytes();
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();

        match validate_mdns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(decoded) => {
                assert_eq!(decoded["mismatches"][0]["field"], "mdns.response");
            }
            other => panic!("expected unexpected response to fail suppression, got {other:?}"),
        }
    }
}
