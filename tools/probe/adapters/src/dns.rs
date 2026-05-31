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

    // Negative responses (NXDOMAIN) carry no answer record, so the terminal
    // answer match only runs when an answer is expected. The empty answer
    // section is enforced by `expected_answer_count` (0) below; rcode 3, the QR
    // flag, transaction id, and the preserved question are checked above.
    if let Some(expected_answer_data) = plan.expected_answer_data.as_deref() {
        let expected_answer_name = canonical_dns_name(required_str(
            plan.expected_answer_name.as_deref(),
            "expected_answer_name",
        )?);
        let expected_answer_type = plan.expected_answer_type_value.unwrap_or(expected_qtype);
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
    }

    // TXT answers carry variable-length RDATA: a list of DNS character-strings.
    // The contract validates the answer owner name, type (16), class, the full
    // ordered list of decoded character-strings, and the TTL. Comparing the whole
    // list (not just "any string matches") is what exercises the string-length
    // encoding/decoding and preserves ordering.
    if let Some(expected_txt) = plan.expected_txt_strings.as_ref() {
        let expected_answer_name = canonical_dns_name(required_str(
            plan.expected_answer_name.as_deref(),
            "expected_answer_name",
        )?);
        let expected_answer_type = plan.expected_answer_type_value.unwrap_or(DNS_TYPE_TXT);
        let expected_answer_class = plan.query_class_value.unwrap_or(DNS_CLASS_IN);
        let expected_strings: Vec<Vec<u8>> = expected_txt
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        let matching_answer = dns.answers().iter().find(|answer| {
            answer.name() == expected_answer_name
                && answer.record_type() == expected_answer_type
                && answer.class() == expected_answer_class
                && dns_txt_strings(answer.data()).as_deref() == Some(expected_strings.as_slice())
        });
        match matching_answer {
            Some(answer) => {
                if let Some(expected_ttl) = plan.answer_ttl {
                    if answer.ttl() != expected_ttl {
                        mismatches.push(json!({
                            "field": "dns.answer.ttl",
                            "expected": expected_ttl,
                            "actual": answer.ttl(),
                        }));
                    }
                }
            }
            None => mismatches.push(json!({
                "field": "dns.answer",
                "expected": {
                    "name": expected_answer_name,
                    "type": expected_answer_type,
                    "class": expected_answer_class,
                    "txt_strings": expected_txt,
                },
                "actual": dns_answers_json(dns),
            })),
        }
    }

    // Multi-answer chain cases (the CNAME chain) additionally require a specific
    // non-terminal answer (the CNAME whose RDATA is the canonical domain name)
    // and an exact answer count, so a response that decoded the terminal A but
    // dropped or mangled the CNAME RDATA still fails the payload check. The
    // original question is already validated above and stays untouched.
    if let Some(expected_cname) = plan.expected_cname_answer.as_ref() {
        let expected_cname_name = canonical_dns_name(&expected_cname.name);
        let expected_cname_type = expected_cname.type_value.unwrap_or(DNS_TYPE_CNAME);
        let matching_cname = dns.answers().iter().find(|answer| {
            answer.name() == expected_cname_name
                && answer.record_type() == expected_cname_type
                && dns_record_data_matches(answer.data(), &expected_cname.data)
        });
        if matching_cname.is_none() {
            mismatches.push(json!({
                "field": "dns.cname_answer",
                "expected": {
                    "name": expected_cname_name,
                    "type": expected_cname_type,
                    "data": expected_cname.data,
                },
                "actual": dns_answers_json(dns),
            }));
        }
    }

    if let Some(expected_count) = plan.expected_answer_count {
        let actual_count = dns.answers().len();
        if actual_count != expected_count {
            mismatches.push(json!({
                "field": "dns.answer_count",
                "expected": expected_count,
                "actual": actual_count,
            }));
        }
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
        "TXT" => Ok(DNS_TYPE_TXT),
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

/// Return the ordered TXT character-strings when `data` is a TXT RDATA, or
/// `None` for any other record data. Used by the TXT answer contract to compare
/// the full decoded character-string list (not just a single string).
pub fn dns_txt_strings(data: &DnsRecordData) -> Option<Vec<Vec<u8>>> {
    match data {
        DnsRecordData::Txt(strings) => Some(strings.clone()),
        _ => None,
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
    use crate::common::DnsAnswerExpectation;
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

    /// Build the IPv4/UDP/DNS response a controlled CNAME-chain responder emits:
    /// a CNAME answer owned by the queried name whose RDATA is the canonical
    /// domain name, followed by a terminal A answer owned by that canonical
    /// name. Returns the decoded packet plus the raw bytes for validation.
    fn cname_chain_response_bytes(
        query_name: &str,
        canonical_name: &str,
        terminal: Ipv4Addr,
        query_id: u16,
    ) -> Vec<u8> {
        let dns = Dns::query(query_name, DNS_TYPE_A)
            .id(query_id)
            .response(true)
            .answer(DnsRecord::cname(query_name, canonical_name, 120))
            .answer(DnsRecord::a(canonical_name, terminal, 90));
        (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .expect("cname chain response compiles")
            .as_bytes()
            .to_vec()
    }

    fn cname_chain_plan(query_name: &str, canonical_name: &str, terminal: &str) -> ProbePlan {
        let mut plan = base_plan("dns-cname-chain");
        plan.source_ipv4 = Some("10.77.0.10".to_string());
        plan.destination_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.77.0.10".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(53);
        plan.query_id = Some(0x6642);
        plan.query_name = Some(query_name.to_string());
        plan.query_type = Some("A".to_string());
        plan.query_type_value = Some(DNS_TYPE_A);
        plan.query_class_value = Some(DNS_CLASS_IN);
        plan.expected_answer_name = Some(canonical_name.to_string());
        plan.expected_answer_type = Some("A".to_string());
        plan.expected_answer_type_value = Some(DNS_TYPE_A);
        plan.expected_answer_data = Some(terminal.to_string());
        plan.expected_answer_count = Some(2);
        plan.original_name = Some(query_name.to_string());
        plan.canonical_name = Some(canonical_name.to_string());
        plan.terminal_ipv4 = Some(terminal.to_string());
        plan.expected_cname_answer = Some(DnsAnswerExpectation {
            name: query_name.to_string(),
            type_value: Some(DNS_TYPE_CNAME),
            class_value: Some(DNS_CLASS_IN),
            data: canonical_name.to_string(),
        });
        plan.expected_response_code = Some(0);
        plan
    }

    #[test]
    fn cname_chain_response_validates_both_answers() {
        let query = "probe-1012-0-e6426682f3.behavior.libcrafter.test.";
        let canonical = "canonical-1012-0-03040be178.behavior.libcrafter.test.";
        let terminal = Ipv4Addr::new(203, 0, 113, 244);
        let raw = cname_chain_response_bytes(query, canonical, terminal, 0x6642);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();

        // The crate decodes both answers, including the CNAME domain-name RDATA.
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert_eq!(dns.answers().len(), 2);

        let plan = cname_chain_plan(query, canonical, "203.0.113.244");
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed for cname chain, got {other:?}"),
        }
    }

    #[test]
    fn cname_chain_missing_terminal_answer_fails_payload() {
        let query = "probe-1012-0-e6426682f3.behavior.libcrafter.test.";
        let canonical = "canonical-1012-0-03040be178.behavior.libcrafter.test.";
        // A response that carries only the CNAME (no terminal A) must not pass.
        let dns = Dns::query(query, DNS_TYPE_A)
            .id(0x6642)
            .response(true)
            .answer(DnsRecord::cname(query, canonical, 120));
        let raw = (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = cname_chain_plan(query, canonical, "203.0.113.244");
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for incomplete chain, got {other:?}"),
        }
    }

    /// Build the IPv4/UDP/DNS NXDOMAIN response a controlled responder emits for
    /// an absent name: QR set, rcode 3 (NXDOMAIN), the original question echoed,
    /// and an empty answer section.
    fn nxdomain_response_bytes(query_name: &str, query_id: u16) -> Vec<u8> {
        let dns = Dns::query(query_name, DNS_TYPE_A)
            .id(query_id)
            .response(true)
            .rcode(DNS_RCODE_NXDOMAIN);
        (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .expect("nxdomain response compiles")
            .as_bytes()
            .to_vec()
    }

    fn nxdomain_plan(query_name: &str) -> ProbePlan {
        let mut plan = base_plan("dns-nxdomain");
        plan.source_ipv4 = Some("10.77.0.10".to_string());
        plan.destination_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.77.0.10".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(53);
        plan.query_id = Some(0x4d2a);
        plan.query_name = Some(query_name.to_string());
        plan.query_type = Some("A".to_string());
        plan.query_type_value = Some(DNS_TYPE_A);
        plan.query_class_value = Some(DNS_CLASS_IN);
        plan.absent_name = Some(query_name.to_string());
        plan.expected_answer_count = Some(0);
        plan.expected_response_code = Some(DNS_RCODE_NXDOMAIN);
        plan
    }

    #[test]
    fn nxdomain_response_validates_negative_answer() {
        let query = "probe-1013-0-absent00aa.behavior.libcrafter.test.";
        let raw = nxdomain_response_bytes(query, 0x4d2a);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();

        // The crate decodes the NXDOMAIN response: QR set, rcode 3, no answers,
        // the original question preserved.
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert!(dns.is_response());
        assert_eq!(dns.rcode_value(), DNS_RCODE_NXDOMAIN);
        assert_eq!(dns.answers().len(), 0);
        assert_eq!(dns.questions().first().unwrap().name(), query);

        let plan = nxdomain_plan(query);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed for nxdomain, got {other:?}"),
        }
    }

    #[test]
    fn nxdomain_with_answer_fails_payload() {
        let query = "probe-1013-0-absent00aa.behavior.libcrafter.test.";
        // A responder that wrongly returns an A answer for the absent name (or a
        // NOERROR/rcode-0 answer) must not pass the NXDOMAIN contract: the
        // answer count is non-zero.
        let dns = Dns::query(query, DNS_TYPE_A)
            .id(0x4d2a)
            .response(true)
            .rcode(DNS_RCODE_NXDOMAIN)
            .answer(DnsRecord::a(query, Ipv4Addr::new(203, 0, 113, 5), 60));
        let raw = (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = nxdomain_plan(query);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for nxdomain with answer, got {other:?}"),
        }
    }

    #[test]
    fn wrong_rcode_fails_nxdomain() {
        let query = "probe-1013-0-absent00aa.behavior.libcrafter.test.";
        // A NOERROR (rcode 0) response with no answers is NODATA, not NXDOMAIN;
        // the rcode mismatch must surface.
        let dns = Dns::query(query, DNS_TYPE_A).id(0x4d2a).response(true);
        let raw = (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = nxdomain_plan(query);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong rcode, got {other:?}"),
        }
    }

    /// Build the IPv4/UDP/DNS NODATA response a controlled responder emits when
    /// the name exists but the queried type is absent: QR set, rcode 0
    /// (NOERROR), the original question echoed, and an empty answer section.
    fn nodata_response_bytes(query_name: &str, query_id: u16) -> Vec<u8> {
        let dns = Dns::query(query_name, DNS_TYPE_A)
            .id(query_id)
            .response(true);
        (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .expect("nodata response compiles")
            .as_bytes()
            .to_vec()
    }

    fn nodata_plan(query_name: &str) -> ProbePlan {
        let mut plan = base_plan("dns-nodata");
        plan.source_ipv4 = Some("10.77.0.10".to_string());
        plan.destination_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.77.0.10".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(53);
        plan.query_id = Some(0x73a1);
        plan.query_name = Some(query_name.to_string());
        plan.query_type = Some("A".to_string());
        plan.query_type_value = Some(DNS_TYPE_A);
        plan.query_class_value = Some(DNS_CLASS_IN);
        plan.present_name = Some(query_name.to_string());
        plan.present_type = Some("AAAA".to_string());
        plan.present_type_value = Some(DNS_TYPE_AAAA);
        plan.expected_answer_count = Some(0);
        plan.expected_response_code = Some(0);
        plan
    }

    #[test]
    fn nodata_response_validates_noerror_empty_answer() {
        let query = "probe-1014-0-nodata00bb.behavior.libcrafter.test.";
        let raw = nodata_response_bytes(query, 0x73a1);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();

        // The crate decodes the NODATA response: QR set, rcode 0 (NOERROR), no
        // answers, the original question preserved.
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert!(dns.is_response());
        assert_eq!(dns.rcode_value(), 0);
        assert_eq!(dns.answers().len(), 0);
        assert_eq!(dns.questions().first().unwrap().name(), query);

        let plan = nodata_plan(query);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed for nodata, got {other:?}"),
        }
    }

    #[test]
    fn nodata_with_answer_fails_payload() {
        let query = "probe-1014-0-nodata00bb.behavior.libcrafter.test.";
        // A responder that wrongly returns an A answer for the queried type must
        // not pass the NODATA contract: the answer count is non-zero.
        let dns = Dns::query(query, DNS_TYPE_A)
            .id(0x73a1)
            .response(true)
            .answer(DnsRecord::a(query, Ipv4Addr::new(203, 0, 113, 7), 60));
        let raw = (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = nodata_plan(query);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for nodata with answer, got {other:?}"),
        }
    }

    /// Build the IPv4/UDP/DNS TXT response a controlled responder emits: QR set,
    /// rcode 0, the original question echoed, and a single TXT answer whose RDATA
    /// is the ordered list of DNS character-strings.
    fn txt_response_bytes(query_name: &str, strings: &[&str], ttl: u32, query_id: u16) -> Vec<u8> {
        let txt = DnsRecordData::Txt(strings.iter().map(|s| s.as_bytes().to_vec()).collect());
        let dns = Dns::query(query_name, DNS_TYPE_TXT)
            .id(query_id)
            .response(true)
            .answer(DnsRecord::new(
                query_name,
                DNS_TYPE_TXT,
                DNS_CLASS_IN,
                ttl,
                txt,
            ));
        (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .expect("txt response compiles")
            .as_bytes()
            .to_vec()
    }

    fn txt_plan(query_name: &str, strings: &[&str], ttl: u32) -> ProbePlan {
        let mut plan = base_plan("dns-txt-answer");
        plan.source_ipv4 = Some("10.77.0.10".to_string());
        plan.destination_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.77.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.77.0.10".to_string());
        plan.source_port = Some(40000);
        plan.destination_port = Some(53);
        plan.query_id = Some(0x515a);
        plan.query_name = Some(query_name.to_string());
        plan.query_type = Some("TXT".to_string());
        plan.query_type_value = Some(DNS_TYPE_TXT);
        plan.query_class_value = Some(DNS_CLASS_IN);
        plan.expected_answer_name = Some(query_name.to_string());
        plan.expected_answer_type = Some("TXT".to_string());
        plan.expected_answer_type_value = Some(DNS_TYPE_TXT);
        plan.expected_txt_strings = Some(strings.iter().map(|s| s.to_string()).collect());
        plan.answer_ttl = Some(ttl);
        plan.expected_response_code = Some(0);
        plan
    }

    #[test]
    fn txt_response_validates_multi_string_answer() {
        let query = "probe-1015-0-txt000abcd.behavior.libcrafter.test.";
        let strings = [
            "libcrafter-probe-txt=behavior-1015-0",
            "v=libcrafter1 id=deadbeef",
        ];
        let raw = txt_response_bytes(query, &strings, 120, 0x515a);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();

        // The crate decodes the TXT RDATA as an ordered character-string list.
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert_eq!(dns.answers().len(), 1);
        let answer = &dns.answers()[0];
        assert_eq!(answer.record_type(), DNS_TYPE_TXT);
        match answer.data() {
            DnsRecordData::Txt(decoded) => {
                let decoded: Vec<String> = decoded
                    .iter()
                    .map(|bytes| String::from_utf8(bytes.clone()).unwrap())
                    .collect();
                assert_eq!(decoded, strings.to_vec());
            }
            other => panic!("expected TXT rdata, got {other:?}"),
        }

        let plan = txt_plan(query, &strings, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed for txt answer, got {other:?}"),
        }
    }

    #[test]
    fn txt_wrong_string_content_fails_payload() {
        let query = "probe-1015-0-txt000abcd.behavior.libcrafter.test.";
        let strings = ["expected-one", "expected-two"];
        // The responder returns different content than the plan expects.
        let raw = txt_response_bytes(query, &["expected-one", "WRONG-two"], 120, 0x515a);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = txt_plan(query, &strings, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong txt content, got {other:?}"),
        }
    }

    #[test]
    fn txt_wrong_ttl_fails_payload() {
        let query = "probe-1015-0-txt000abcd.behavior.libcrafter.test.";
        let strings = ["one", "two"];
        // Correct strings but a TTL that does not match the contract.
        let raw = txt_response_bytes(query, &strings, 999, 0x515a);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = txt_plan(query, &strings, 120);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for wrong txt ttl, got {other:?}"),
        }
    }

    #[test]
    fn txt_response_dns_packet_builds_txt_query() {
        let query = "probe-1015-0-txt000abcd.behavior.libcrafter.test.";
        let plan = txt_plan(query, &["one", "two"], 120);
        let packet = dns_packet(&plan).unwrap();
        let dns = packet.layer::<Dns>().expect("dns layer present");
        assert_eq!(
            dns.questions().first().unwrap().question_type(),
            DNS_TYPE_TXT
        );
        assert_eq!(dns.id_value(), 0x515a);
    }

    #[test]
    fn nxdomain_rcode_fails_nodata() {
        let query = "probe-1014-0-nodata00bb.behavior.libcrafter.test.";
        // NXDOMAIN (rcode 3) is the absent-name case, not NODATA (the name
        // exists). A NODATA plan must reject an rcode-3 response.
        let dns = Dns::query(query, DNS_TYPE_A)
            .id(0x73a1)
            .response(true)
            .rcode(DNS_RCODE_NXDOMAIN);
        let raw = (Ipv4::new()
            .src(Ipv4Addr::new(10, 77, 0, 20))
            .dst(Ipv4Addr::new(10, 77, 0, 10))
            / Udp::new().sport(53).dport(40000)
            / dns)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw).unwrap();
        let plan = nodata_plan(query);
        match validate_dns_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload for nxdomain rcode, got {other:?}"),
        }
    }
}
