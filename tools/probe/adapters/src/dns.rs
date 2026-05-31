//! DNS probe case `dns-query`: send a DNS query over UDP and validate the
//! decoded UDP/DNS response (peer, ports, transaction id, response flag,
//! response code, question, and answer content).

use crafter::prelude::*;
use serde_json::{json, Value};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::common::{
    capture_filter, decoded_packet_json, failed_outcome, hex_bytes, observed_response, plan_json,
    required_str, required_u16, send_report_json, target_service_json, CandidateValidation,
    ExampleResult, ProbeOutcome, ProbePlan, StimulusEndpointRequest, FAILURE_DECODE_FAILED,
    FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD, FAILURE_WRONG_PEER,
};

pub fn run_dns_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = dns_packet(plan)?;
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

pub fn run_dns_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = dns_packet(plan)?;
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
        match validate_dns_candidate(plan, captured.packet(), captured.data())? {
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
            vec!["captured DNS response did not match expected question or answer".to_string()],
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
            vec!["captured DNS response did not match expected peer or ports".to_string()],
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
        vec!["timed out waiting for DNS response".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter(plan),
        })),
        sent,
        false,
    ))
}

pub fn validate_dns_candidate(
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

    let Some(dns) = packet.layer::<Dns>() else {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": [{
                "field": "dns",
                "expected": "present",
                "actual": "missing",
            }],
        })));
    };

    let expected_query_id = required_u16(plan.query_id, "query_id")?;
    let expected_qname =
        canonical_dns_name(required_str(plan.query_name.as_deref(), "query_name")?);
    let expected_qtype = dns_type_value(plan)?;
    let expected_qclass = plan.query_class_value.unwrap_or(DNS_CLASS_IN);
    let expected_answer_name = canonical_dns_name(required_str(
        plan.expected_answer_name.as_deref(),
        "expected_answer_name",
    )?);
    let expected_answer_type = plan.expected_answer_type_value.unwrap_or(expected_qtype);
    let expected_answer_data =
        required_str(plan.expected_answer_data.as_deref(), "expected_answer_data")?;
    let expected_rcode = plan.expected_response_code.unwrap_or(0);
    let mut mismatches = Vec::new();

    if dns.id_value() != expected_query_id {
        mismatches.push(json!({
            "field": "dns.id",
            "expected": expected_query_id,
            "actual": dns.id_value(),
        }));
    }
    if !dns.is_response() {
        mismatches.push(json!({
            "field": "dns.qr",
            "expected": true,
            "actual": false,
        }));
    }
    let actual_rcode = (dns.flags_value() & 0x000f) as u8;
    if actual_rcode != expected_rcode {
        mismatches.push(json!({
            "field": "dns.rcode",
            "expected": expected_rcode,
            "actual": actual_rcode,
        }));
    }

    match dns.questions().first() {
        Some(question) => {
            if question.name() != expected_qname {
                mismatches.push(json!({
                    "field": "dns.question.name",
                    "expected": expected_qname,
                    "actual": question.name(),
                }));
            }
            if question.question_type() != expected_qtype {
                mismatches.push(json!({
                    "field": "dns.question.type",
                    "expected": expected_qtype,
                    "actual": question.question_type(),
                }));
            }
            if question.question_class() != expected_qclass {
                mismatches.push(json!({
                    "field": "dns.question.class",
                    "expected": expected_qclass,
                    "actual": question.question_class(),
                }));
            }
        }
        None => mismatches.push(json!({
            "field": "dns.question",
            "expected": "present",
            "actual": "missing",
        })),
    }

    let matching_answer = dns.answers().iter().find(|answer| {
        answer.name() == expected_answer_name
            && answer.record_type() == expected_answer_type
            && dns_record_data_matches(answer.data(), expected_answer_data)
    });
    if matching_answer.is_none() {
        mismatches.push(json!({
            "field": "dns.answer",
            "expected": {
                "name": expected_answer_name,
                "type": expected_answer_type,
                "data": expected_answer_data,
            },
            "actual": dns_answers_json(dns),
        }));
    }

    if !mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": mismatches,
        })));
    }

    Ok(CandidateValidation::Passed(decoded))
}

pub fn dns_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    let source_port = required_u16(plan.source_port, "source_port")?;
    let destination_port = required_u16(plan.destination_port, "destination_port")?;
    let query_id = required_u16(plan.query_id, "query_id")?;
    let query_name = required_str(plan.query_name.as_deref(), "query_name")?;
    let query_type = dns_type_value(plan)?;
    Ok(Ipv4::new().src(source).dst(destination)
        / Udp::new().sport(source_port).dport(destination_port)
        / Dns::query(query_name, query_type).id(query_id))
}

pub fn dns_type_value(plan: &ProbePlan) -> ExampleResult<u16> {
    if let Some(value) = plan.query_type_value {
        return Ok(value);
    }
    match plan
        .query_type
        .as_deref()
        .unwrap_or("A")
        .to_ascii_uppercase()
        .as_str()
    {
        "A" => Ok(DNS_TYPE_A),
        "AAAA" => Ok(DNS_TYPE_AAAA),
        other => Err(format!("unsupported DNS query type: {other}").into()),
    }
}

pub fn canonical_dns_name(name: &str) -> String {
    let trimmed = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        ".".to_string()
    } else {
        format!("{trimmed}.")
    }
}

pub fn dns_record_data_matches(data: &DnsRecordData, expected: &str) -> bool {
    match data {
        DnsRecordData::A(address) => expected
            .parse::<Ipv4Addr>()
            .is_ok_and(|expected| *address == expected),
        DnsRecordData::Aaaa(address) => expected
            .parse::<Ipv6Addr>()
            .is_ok_and(|expected| *address == expected),
        DnsRecordData::Name(name) => {
            canonical_dns_name(name.presentation()) == canonical_dns_name(expected)
        }
        DnsRecordData::Txt(strings) => strings
            .iter()
            .filter_map(|bytes| std::str::from_utf8(bytes).ok())
            .any(|value| value == expected),
        DnsRecordData::Mx {
            preference,
            exchange,
        } => {
            format!(
                "{preference} {}",
                canonical_dns_name(exchange.presentation())
            ) == expected
        }
        DnsRecordData::Raw(bytes) => hex_bytes(bytes) == expected,
        _ => false,
    }
}

pub fn dns_json(dns: &Dns) -> Value {
    json!({
        "id": dns.id_value(),
        "flags": dns.flags_value(),
        "is_response": dns.is_response(),
        "response_code": dns.flags_value() & 0x000f,
        "questions": dns.questions().iter().map(|question| json!({
            "name": question.name(),
            "type": question.question_type(),
            "class": question.question_class(),
        })).collect::<Vec<_>>(),
        "answers": dns_answers_json(dns),
    })
}

pub fn dns_answers_json(dns: &Dns) -> Value {
    Value::Array(dns.answers().iter().map(dns_record_json).collect())
}

fn dns_record_json(record: &DnsRecord) -> Value {
    json!({
        "name": record.name(),
        "type": record.record_type(),
        "class": record.class(),
        "ttl": record.ttl(),
        "data": dns_record_data_json(record.data()),
    })
}

fn dns_record_data_json(data: &DnsRecordData) -> Value {
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
        DnsRecordData::Mx {
            preference,
            exchange,
        } => json!({
            "kind": "mx",
            "preference": preference,
            "exchange": exchange.presentation(),
        }),
        DnsRecordData::Txt(strings) => json!({
            "kind": "txt",
            "values": strings
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                .collect::<Vec<_>>(),
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

    #[test]
    fn dns_packet_requires_query_name() {
        let mut plan = base_plan("dns-query");
        plan.source_ipv4 = Some("192.0.2.1".to_string());
        plan.destination_ipv4 = Some("192.0.2.2".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(53);
        plan.query_id = Some(0x1234);
        let err = dns_packet(&plan).unwrap_err().to_string();
        assert!(err.contains("query_name"), "got: {err}");
    }

    #[test]
    fn dns_packet_compiles_in_dry_run() {
        let mut plan = base_plan("dns-query");
        plan.source_ipv4 = Some("192.0.2.1".to_string());
        plan.destination_ipv4 = Some("192.0.2.2".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(53);
        plan.query_id = Some(0x1234);
        plan.query_name = Some("example.test".to_string());
        plan.query_type = Some("A".to_string());
        let packet = dns_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        assert!(bytes.len() >= 28, "dns packet too short: {}", bytes.len());
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert_eq!(dns.id_value(), 0x1234);
    }

    #[test]
    fn dns_type_value_maps_names_and_rejects_unknown() {
        let mut plan = base_plan("dns-query");
        plan.query_type = Some("aaaa".to_string());
        assert_eq!(dns_type_value(&plan).unwrap(), DNS_TYPE_AAAA);
        plan.query_type = Some("PTR".to_string());
        assert!(dns_type_value(&plan).is_err());
        plan.query_type = None;
        plan.query_type_value = Some(99);
        assert_eq!(dns_type_value(&plan).unwrap(), 99);
    }

    #[test]
    fn canonical_dns_name_normalizes() {
        assert_eq!(canonical_dns_name("Example.Test."), "example.test.");
        assert_eq!(canonical_dns_name(""), ".");
    }
}
