//! SSDP behavioral probe cases.
//!
//! The adapter materializes live-capable SSDP probe plans as typed libcrafter
//! IPv4/IPv6 + UDP + SSDP packets. It sends search stimuli, captures controlled
//! responses, and handles the notification case as a capture-only observation
//! from the controlled target service.

use crafter::prelude::*;
use serde_json::{json, Value};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::common::{
    captured_data, decode_hex, decoded_packet_json, failed_outcome, hex_bytes, observed_response,
    open_capture_sniffer, plan_json, required_str, required_u16, send_report_json,
    CandidateValidation, ExampleResult, ProbeOutcome, ProbePlan, StimulusEndpointRequest,
    FAILURE_DECODE_FAILED, FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD, FAILURE_WRONG_PEER,
};

const SSDP_IPV4_MULTICAST_TTL: u8 = 2;
const SSDP_IPV6_LINK_LOCAL_HOP_LIMIT: u8 = 1;
const SSDP_IPV6_SITE_LOCAL_HOP_LIMIT: u8 = 5;

pub fn run_ssdp_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = ssdp_packet(plan)?;
    let capture_filter = ssdp_capture_filter(plan)?;
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
    let sent_decoded = decoded_ssdp_packet_json(&sent_packet, sent_raw);
    let target_service = ssdp_target_service_json(plan);
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
            "ssdp": ssdp_payload_json(plan)?,
            "expected_ssdp": expected_ssdp_payload_json(plan)?,
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
            "probe_plan": plan_json(plan),
            "planned_only": true,
            "sent_raw_hex": sent_raw_hex,
            "sent_decoded": sent_decoded,
            "ssdp": ssdp_payload_json(plan)?,
            "expected_ssdp": expected_ssdp_payload_json(plan)?,
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

pub fn run_ssdp_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    if plan.case == "ssdp-notify-capture" {
        return run_ssdp_capture_live(request, plan);
    }

    let packet = ssdp_packet(plan)?;
    let capture_filter = ssdp_capture_filter(plan)?;
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
        match validate_ssdp_candidate(plan, captured.packet(), captured_data(&captured))? {
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
            vec!["captured SSDP response did not match expected payload".to_string()],
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
            vec!["captured SSDP response did not match expected peer or ports".to_string()],
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
        vec!["timed out waiting for SSDP response".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter,
        })),
        sent,
        false,
    ))
}

fn run_ssdp_capture_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let expected_packet = ssdp_packet(plan)?;
    let expected_raw = expected_packet.compile()?;
    let capture_filter = ssdp_capture_filter(plan)?;
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
        match validate_ssdp_candidate(plan, captured.packet(), captured_data(&captured))? {
            CandidateValidation::Ignore => {}
            CandidateValidation::Passed(decoded) => {
                let raw_hex = hex_bytes(captured_data(&captured));
                let observed = observed_response(
                    plan,
                    true,
                    Some(raw_hex.clone()),
                    decoded.clone(),
                    json!({
                        "capture_filter": capture_filter,
                        "expected_raw_hex": hex_bytes(&expected_raw),
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
                        "expected_raw_hex": hex_bytes(&expected_raw),
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
            vec!["captured SSDP notification did not match expected payload".to_string()],
            Some(json!({
                "decoded": decoded,
                "expected_raw_hex": hex_bytes(&expected_raw),
            })),
            false,
            true,
        ));
    }

    if let Some(decoded) = wrong_peer {
        return Ok(failed_outcome(
            plan,
            FAILURE_WRONG_PEER,
            vec!["captured SSDP notification did not match expected peer or ports".to_string()],
            Some(json!({
                "decoded": decoded,
                "expected_raw_hex": hex_bytes(&expected_raw),
            })),
            false,
            true,
        ));
    }

    Ok(failed_outcome(
        plan,
        FAILURE_TIMEOUT,
        vec!["timed out waiting for SSDP notification".to_string()],
        Some(json!({
            "capture_filter": capture_filter,
            "expected_raw_hex": hex_bytes(&expected_raw),
        })),
        false,
        false,
    ))
}

pub fn ssdp_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source_port = required_u16(plan.source_port, "source_port")?;
    let destination_port = required_u16(plan.destination_port, "destination_port")?;
    let udp = Udp::new().sport(source_port).dport(destination_port);
    let message = ssdp_payload(plan)?;

    if plan.source_ipv6.is_some() || plan.destination_ipv6.is_some() {
        let source: Ipv6Addr = required_str(plan.source_ipv6.as_deref(), "source_ipv6")?.parse()?;
        let destination: Ipv6Addr =
            required_str(plan.destination_ipv6.as_deref(), "destination_ipv6")?.parse()?;
        let hop_limit = if destination == SSDP_IPV6_LINK_LOCAL_MULTICAST_ADDR {
            SSDP_IPV6_LINK_LOCAL_HOP_LIMIT
        } else {
            SSDP_IPV6_SITE_LOCAL_HOP_LIMIT
        };
        return Ok(ssdp_ipv6_multicast_packet_with(
            source,
            destination,
            hop_limit,
            udp,
            message,
        ));
    }

    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    Ok(ssdp_ipv4_multicast_packet_with(
        source,
        destination,
        SSDP_IPV4_MULTICAST_TTL,
        udp,
        message,
    ))
}

pub fn validate_ssdp_candidate(
    plan: &ProbePlan,
    packet: &Packet,
    raw: &[u8],
) -> ExampleResult<CandidateValidation> {
    let Some(udp) = packet.layer::<Udp>() else {
        return Ok(CandidateValidation::Ignore);
    };

    let mut peer_mismatches = Vec::new();
    if plan.source_ipv6.is_some() || plan.destination_ipv6.is_some() {
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

    let decoded = decoded_ssdp_packet_json(packet, raw);
    if !peer_mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPeer(json!({
            "packet": decoded,
            "mismatches": peer_mismatches,
        })));
    }

    let Some(ssdp) = packet.layer::<Ssdp>() else {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": [{
                "field": "ssdp",
                "expected": "decoded SSDP layer",
                "actual": "missing",
            }],
        })));
    };

    let actual_payload = ssdp.to_bytes();
    let expected_payload = expected_ssdp_payload(plan)?;
    if actual_payload != expected_payload {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "ssdp": ssdp_json(ssdp),
            "mismatches": [{
                "field": "ssdp.payload_hex",
                "expected": hex_bytes(&expected_payload),
                "actual": hex_bytes(&actual_payload),
            }],
        })));
    }

    Ok(CandidateValidation::Passed(decoded))
}

pub fn ssdp_json(ssdp: &Ssdp) -> Value {
    let start_line = ssdp.message().start_line();
    let start_line_json = if let Some(request) = start_line.as_request() {
        json!({
            "kind": "request",
            "method": request.method().as_str(),
            "request_target": request.target().as_str(),
            "version": request.version().as_str(),
            "line": format!(
                "{} {} {}",
                request.method(),
                request.target(),
                request.version()
            ),
        })
    } else if let Some(response) = start_line.as_response() {
        json!({
            "kind": "response",
            "version": response.version().as_str(),
            "status_code": response.code().code(),
            "reason_phrase": response.reason().as_str(),
            "line": format!(
                "{} {} {}",
                response.version(),
                response.code(),
                response.reason()
            ),
        })
    } else {
        json!({})
    };

    json!({
        "summary": ssdp.summary(),
        "start_line": start_line_json,
        "headers": ssdp
            .headers()
            .iter()
            .map(|header| {
                let value = header.value().as_bytes();
                json!({
                    "name": header.name().original(),
                    "canonical_name": header.name().canonical_name(),
                    "value": String::from_utf8_lossy(value),
                    "value_hex": hex_bytes(value),
                })
            })
            .collect::<Vec<_>>(),
        "header_count": ssdp.headers().len(),
        "body_len": ssdp.body().len(),
        "body_hex": hex_bytes(ssdp.body()),
        "payload_hex": hex_bytes(&ssdp.to_bytes()),
    })
}

fn ssdp_payload(plan: &ProbePlan) -> ExampleResult<Ssdp> {
    let payload_hex = required_str(
        plan.payload_hex
            .as_deref()
            .or(plan.udp_payload_hex.as_deref()),
        "payload_hex",
    )?;
    let payload = decode_hex(payload_hex)?;
    Ok(Ssdp::parse(&payload)?)
}

fn expected_ssdp_payload(plan: &ProbePlan) -> ExampleResult<Vec<u8>> {
    let expected_payload_hex = required_str(
        plan.expected_payload_hex
            .as_deref()
            .or(plan.payload_hex.as_deref()),
        "expected_payload_hex",
    )?;
    decode_hex(expected_payload_hex)
}

fn ssdp_payload_json(plan: &ProbePlan) -> ExampleResult<Value> {
    Ok(ssdp_json(&ssdp_payload(plan)?))
}

fn expected_ssdp_payload_json(plan: &ProbePlan) -> ExampleResult<Value> {
    let payload = expected_ssdp_payload(plan)?;
    Ok(ssdp_json(&Ssdp::parse(&payload)?))
}

fn decoded_ssdp_packet_json(packet: &Packet, raw: &[u8]) -> Value {
    let mut decoded = decoded_packet_json(packet, raw);
    if let Value::Object(map) = &mut decoded {
        map.insert(
            "ssdp".into(),
            packet.layer::<Ssdp>().map(ssdp_json).unwrap_or(Value::Null),
        );
    }
    decoded
}

fn ssdp_capture_filter(plan: &ProbePlan) -> ExampleResult<String> {
    if plan.source_ipv6.is_some() || plan.destination_ipv6.is_some() {
        return Ok(format!(
            "ip6 and udp and src host {} and dst host {} and src port {} and dst port {}",
            required_str(
                plan.expected_reply_source_ipv6.as_deref(),
                "expected_reply_source_ipv6"
            )?,
            required_str(
                plan.expected_reply_destination_ipv6.as_deref(),
                "expected_reply_destination_ipv6"
            )?,
            expected_response_source_port(plan)?,
            expected_response_destination_port(plan)?,
        ));
    }

    Ok(format!(
        "udp and src host {} and dst host {} and src port {} and dst port {}",
        expected_response_source_ipv4(plan)?,
        expected_response_destination_ipv4(plan)?,
        expected_response_source_port(plan)?,
        expected_response_destination_port(plan)?,
    ))
}

fn validate_ipv4_peer(
    plan: &ProbePlan,
    packet: &Packet,
    mismatches: &mut Vec<Value>,
) -> ExampleResult<()> {
    let expected_source: Ipv4Addr = expected_response_source_ipv4(plan)?.parse()?;
    let expected_destination: Ipv4Addr = expected_response_destination_ipv4(plan)?.parse()?;
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

fn expected_response_source_ipv4(plan: &ProbePlan) -> ExampleResult<&str> {
    if plan.case == "ssdp-notify-capture" {
        return required_str(plan.source_ipv4.as_deref(), "source_ipv4");
    }
    required_str(
        plan.expected_reply_source_ipv4.as_deref(),
        "expected_reply_source_ipv4",
    )
}

fn expected_response_destination_ipv4(plan: &ProbePlan) -> ExampleResult<&str> {
    if plan.case == "ssdp-notify-capture" {
        return required_str(plan.destination_ipv4.as_deref(), "destination_ipv4");
    }
    required_str(
        plan.expected_reply_destination_ipv4.as_deref(),
        "expected_reply_destination_ipv4",
    )
}

fn expected_response_source_port(plan: &ProbePlan) -> ExampleResult<u16> {
    if plan.case == "ssdp-notify-capture" {
        return required_u16(plan.source_port, "source_port");
    }
    required_u16(plan.destination_port, "destination_port")
}

fn expected_response_destination_port(plan: &ProbePlan) -> ExampleResult<u16> {
    if plan.case == "ssdp-notify-capture" {
        return required_u16(plan.destination_port, "destination_port");
    }
    required_u16(plan.source_port, "source_port")
}

fn network_layer(plan: &ProbePlan) -> NetworkLayer {
    if plan.source_ipv6.is_some() || plan.destination_ipv6.is_some() {
        NetworkLayer::Ipv6
    } else {
        NetworkLayer::Ipv4
    }
}

fn ssdp_target_service_json(plan: &ProbePlan) -> Value {
    plan.target_service.clone().unwrap_or_else(|| json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    const SSDP_PORT: u16 = 1900;

    fn search_payload() -> &'static [u8] {
        b"M-SEARCH * HTTP/1.1\r\n\
          HOST: 239.255.255.250:1900\r\n\
          MAN: \"ssdp:discover\"\r\n\
          MX: 1\r\n\
          ST: ssdp:all\r\n\
          USER-AGENT: libcrafter-probe/0.1 UPnP/2.0 ssdp-probe/0.1\r\n\
          \r\n"
    }

    fn response_payload() -> &'static [u8] {
        b"HTTP/1.1 200 OK\r\n\
          CACHE-CONTROL: max-age=1800\r\n\
          EXT:\r\n\
          LOCATION: http://198.51.100.130:8000/root.xml\r\n\
          SERVER: unix/5.10 UPnP/2.0 libcrafter-probe/0.1\r\n\
          ST: upnp:rootdevice\r\n\
          USN: uuid:00000000-0000-4000-8000-000000000053::upnp:rootdevice\r\n\
          BOOTID.UPNP.ORG: 1\r\n\
          CONFIGID.UPNP.ORG: 1\r\n\
          \r\n"
    }

    fn ipv4_search_plan() -> ProbePlan {
        let mut plan = base_plan("ssdp-ipv4-search-exchange");
        plan.sequence = 7;
        plan.expected_response = Some("ssdp_search_response".to_string());
        plan.source_ipv4 = Some("198.51.100.10".to_string());
        plan.destination_ipv4 = Some("239.255.255.250".to_string());
        plan.expected_reply_source_ipv4 = Some("198.51.100.130".to_string());
        plan.expected_reply_destination_ipv4 = Some("198.51.100.10".to_string());
        plan.source_port = Some(49152);
        plan.destination_port = Some(SSDP_PORT);
        plan.payload_hex = Some(hex_bytes(search_payload()));
        plan.expected_payload_hex = Some(hex_bytes(response_payload()));
        plan.protocol = Some("ssdp".to_string());
        plan.target_service = Some(json!({
            "required": true,
            "kind": "ssdp-controlled-responder",
            "protocol": "udp",
            "port": SSDP_PORT,
            "behavior": "search_response",
        }));
        plan
    }

    fn ipv6_search_plan() -> ProbePlan {
        let mut plan = ipv4_search_plan();
        plan.case = "ssdp-ipv6-search-exchange".to_string();
        plan.source_ipv4 = None;
        plan.destination_ipv4 = None;
        plan.expected_reply_source_ipv4 = None;
        plan.expected_reply_destination_ipv4 = None;
        plan.source_ipv6 = Some("2001:db8::10".to_string());
        plan.destination_ipv6 = Some("ff02::c".to_string());
        plan.expected_reply_source_ipv6 = Some("2001:db8::130".to_string());
        plan.expected_reply_destination_ipv6 = Some("2001:db8::10".to_string());
        plan.payload_hex = Some(hex_bytes(
            b"M-SEARCH * HTTP/1.1\r\n\
              HOST: [ff02::c]:1900\r\n\
              MAN: \"ssdp:discover\"\r\n\
              MX: 1\r\n\
              ST: ssdp:all\r\n\
              \r\n",
        ));
        plan
    }

    fn stimulus_request(plan: ProbePlan) -> StimulusEndpointRequest {
        StimulusEndpointRequest {
            provider: "local-dry-run".to_string(),
            profile: "ssdp-smoke".to_string(),
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
    fn json_decodes_ssdp_probe_plan_with_engine_metadata() {
        let request: StimulusEndpointRequest = serde_json::from_value(json!({
            "provider": "local-dry-run",
            "profile": "ssdp-smoke",
            "seed": 11,
            "endpoint_role": "stimulus",
            "interface": "lo",
            "local_ipv4": "198.51.100.10",
            "peer_ipv4": "198.51.100.130",
            "timeout_seconds": 1,
            "artifact_paths": {},
            "metadata": {},
            "probe_plans": [{
                "schema_version": 1,
                "case": "ssdp-ipv4-search-exchange",
                "sequence": 3,
                "protocol": "ssdp",
                "source_ipv4": "198.51.100.10",
                "destination_ipv4": "239.255.255.250",
                "expected_reply_source_ipv4": "198.51.100.130",
                "expected_reply_destination_ipv4": "198.51.100.10",
                "source_port": 49152,
                "destination_port": SSDP_PORT,
                "udp_payload_hex": hex_bytes(search_payload()),
                "expected_payload_hex": hex_bytes(response_payload()),
                "ssdp": {"message_kind": "m_search"},
                "expected_ssdp": {"message_kind": "response"},
                "stimulus_driver": {"adapter_module": "tools/probe/adapters/src/ssdp.rs"},
                "target_service": {"kind": "ssdp-controlled-responder"}
            }]
        }))
        .unwrap();

        let plan = &request.probe_plans[0];
        assert_eq!(plan.case, "ssdp-ipv4-search-exchange");
        assert_eq!(plan.sequence, 3);
        assert_eq!(plan.protocol.as_deref(), Some("ssdp"));
        assert_eq!(plan.payload_hex, None);
        assert_eq!(
            plan.udp_payload_hex.as_deref(),
            Some(hex_bytes(search_payload()).as_str())
        );
        assert_eq!(
            plan.target_service.as_ref().unwrap()["kind"],
            "ssdp-controlled-responder"
        );
        assert_eq!(ssdp_payload(plan).unwrap().headers().len(), 5);
    }

    #[test]
    fn ssdp_packet_builds_ipv4_udp_ssdp_stack() {
        let plan = ipv4_search_plan();
        let packet = ssdp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes).unwrap();

        let ipv4 = decoded.layer::<Ipv4>().expect("ipv4 layer");
        let udp = decoded.layer::<Udp>().expect("udp layer");
        let ssdp = decoded.layer::<Ssdp>().expect("ssdp layer");
        assert_eq!(ipv4.source(), Ipv4Addr::new(198, 51, 100, 10));
        assert_eq!(ipv4.destination(), Ipv4Addr::new(239, 255, 255, 250));
        assert_eq!(ipv4.ttl_value(), SSDP_IPV4_MULTICAST_TTL);
        assert_eq!(udp.source_port_value(), 49152);
        assert_eq!(udp.destination_port_value(), SSDP_PORT);
        assert_eq!(ssdp.to_bytes(), search_payload());
    }

    #[test]
    fn ssdp_packet_builds_ipv6_link_local_multicast_stack() {
        let plan = ipv6_search_plan();
        let packet = ssdp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, &bytes).unwrap();

        let ipv6 = decoded.layer::<Ipv6>().expect("ipv6 layer");
        let udp = decoded.layer::<Udp>().expect("udp layer");
        assert_eq!(ipv6.source(), "2001:db8::10".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ipv6.destination(), SSDP_IPV6_LINK_LOCAL_MULTICAST_ADDR);
        assert_eq!(ipv6.hop_limit_value(), SSDP_IPV6_LINK_LOCAL_HOP_LIMIT);
        assert_eq!(udp.source_port_value(), 49152);
        assert_eq!(udp.destination_port_value(), SSDP_PORT);
        assert!(decoded.layer::<Ssdp>().is_some());
    }

    #[test]
    fn dry_run_output_reports_decoded_ssdp_plan() {
        let plan = ipv4_search_plan();
        let request = stimulus_request(plan.clone());
        let outcome = run_ssdp_dry_run(&request, &plan).unwrap();

        assert!(!outcome.sent);
        assert!(!outcome.received);
        assert_eq!(outcome.result["status"], "planned");
        assert_eq!(outcome.result["metadata"]["dry_run"], true);
        assert_eq!(
            outcome.result["metadata"]["sent_decoded"]["ssdp"]["start_line"]["method"],
            "M-SEARCH"
        );
        assert_eq!(
            outcome.result["metadata"]["expected_ssdp"]["start_line"]["status_code"],
            200
        );
        assert_eq!(
            outcome.result["metadata"]["target_service"]["kind"],
            "ssdp-controlled-responder"
        );
        assert_eq!(
            outcome.result["metadata"]["capture_filter"],
            "udp and src host 198.51.100.130 and dst host 198.51.100.10 and src port 1900 and dst port 49152"
        );
    }

    #[test]
    fn malformed_ssdp_plans_fail_before_send_materialization() {
        let mut missing_port = ipv4_search_plan();
        missing_port.source_port = None;
        let err = ssdp_packet(&missing_port).unwrap_err().to_string();
        assert!(err.contains("source_port"), "{err}");

        let mut malformed_payload = ipv4_search_plan();
        malformed_payload.payload_hex = Some(hex_bytes(
            b"M-SEARCH * HTTP/1.1\r\nHOST 239.255.255.250:1900\r\n\r\n",
        ));
        let err = ssdp_packet(&malformed_payload).unwrap_err().to_string();
        assert!(err.contains("invalid SSDP header"), "{err}");
    }

    #[test]
    fn optional_fields_support_legacy_payload_and_target_service_shapes() {
        let mut plan = ipv4_search_plan();
        let payload_hex = plan.payload_hex.take().unwrap();
        plan.udp_payload_hex = Some(payload_hex.clone());
        plan.target_service = None;

        let ssdp = ssdp_payload(&plan).unwrap();
        assert_eq!(ssdp.to_bytes(), search_payload());
        assert_eq!(ssdp_target_service_json(&plan), json!({}));

        let mut expected_fallback_plan = ipv4_search_plan();
        expected_fallback_plan.expected_payload_hex = None;
        assert_eq!(
            expected_ssdp_payload(&expected_fallback_plan).unwrap(),
            search_payload()
        );
    }
}
