//! ARP behavioral probe cases.
//!
//! `arp-basic-who-has` is the baseline ARP behavioral check: build an
//! Ethernet/ARP who-has request with libcrafter (operation 1, Ethernet
//! destination broadcast), send it at the link layer on a private L2 lab
//! segment, capture the target kernel's unicast is-at reply, decode the
//! Ethernet/ARP response with libcrafter, and validate the operation (reply,
//! 2), the sender hardware/protocol address (the resolved target MAC/IPv4), the
//! target hardware/protocol address (the original sender), and the Ethernet
//! source/destination of the reply.
//!
//! ARP rides Ethernet directly (no IP/UDP), unlike the DNS/DHCP cases: the
//! send/capture path is link-layer (`SendOptions::link_layer`) and the decode
//! entrypoint decodes the Ethernet frame
//! (`Packet::decode_from_link(LinkType::Ethernet, ..)`), not an L3 packet.

use crafter::prelude::*;
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::common::{
    capture_filter, decoded_packet_json, failed_outcome, hex_bytes, observed_response, plan_json,
    required_str, required_u16, send_report_json, target_service_json, CandidateValidation,
    ExampleResult, ProbeOutcome, ProbePlan, StimulusEndpointRequest, FAILURE_DECODE_FAILED,
    FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD, FAILURE_WRONG_PEER,
};

/// Stable identifier for the ARP case module.
pub const MODULE_NAME: &str = "arp";

/// Ethernet broadcast address: an ARP who-has is broadcast to the segment.
const BROADCAST_MAC: &str = "ff:ff:ff:ff:ff:ff";

pub fn run_arp_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = arp_who_has_packet(plan)?;
    // ARP is sent at the link layer (Ethernet), not the network layer: the
    // outgoing frame starts at Ethernet, so the dry-run send plan uses
    // `link_layer()` and compiles the Ethernet/ARP who-has without touching the
    // wire.
    let report = SocketSender::new(
        SendOptions::new()
            .iface(request.interface.clone())
            .link_layer()
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

pub fn run_arp_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = arp_who_has_packet(plan)?;
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
            .link_layer()
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
        match validate_arp_candidate(plan, captured.packet(), captured.data())? {
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
            vec!["captured ARP reply did not match the expected is-at contract".to_string()],
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
            vec!["captured ARP reply did not resolve the expected target address".to_string()],
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
        vec!["timed out waiting for ARP is-at reply".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter(plan),
        })),
        sent,
        false,
    ))
}

/// Build the Ethernet/ARP who-has request with libcrafter.
///
/// `compile()` fills the ARP htype/ptype/hlen/plen and the Ethernet ethertype
/// (0x0806) from the layer stack; the caller-set operation, addresses, and
/// Ethernet framing survive untouched. The Ethernet destination defaults to the
/// broadcast address (a who-has is broadcast to the segment) unless the plan
/// overrides it.
pub fn arp_who_has_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let sender_protocol_addr: Ipv4Addr =
        required_str(plan.sender_protocol_addr.as_deref(), "sender_protocol_addr")?.parse()?;
    let target_protocol_addr: Ipv4Addr =
        required_str(plan.target_protocol_addr.as_deref(), "target_protocol_addr")?.parse()?;
    let sender_hardware_addr: MacAddr =
        required_str(plan.sender_hardware_addr.as_deref(), "sender_hardware_addr")?.parse()?;
    let ethernet_source: MacAddr =
        required_str(plan.ethernet_source.as_deref(), "ethernet_source")?.parse()?;
    let ethernet_destination: MacAddr = plan
        .ethernet_destination
        .as_deref()
        .unwrap_or(BROADCAST_MAC)
        .parse()?;

    let arp = Arp::who_has(
        sender_protocol_addr,
        target_protocol_addr,
        sender_hardware_addr,
    );
    Ok(Ethernet::with_addresses(ethernet_source, ethernet_destination) / arp)
}

/// Validate one captured candidate against the ARP who-has -> is-at contract.
///
/// A frame whose decoded ARP target protocol address does not match the
/// stimulus sender (the address the reply must be addressed back to) surfaces as
/// `WrongPeer`; a frame addressed back to the sender that fails the is-at
/// contract (operation, resolved addresses, Ethernet framing) surfaces as
/// `WrongPayload`. A fully matching is-at reply surfaces as `Passed`.
pub fn validate_arp_candidate(
    plan: &ProbePlan,
    packet: &Packet,
    raw: &[u8],
) -> ExampleResult<CandidateValidation> {
    let Some(arp) = packet.layer::<Arp>() else {
        return Ok(CandidateValidation::Ignore);
    };
    let validation = plan
        .validation
        .as_ref()
        .ok_or("arp-basic-who-has plan is missing the validation contract")?;

    let decoded = decoded_packet_json(packet, raw);

    // Peer match: the reply's ARP target protocol address must be the original
    // sender's protocol address (the address the kernel resolves the reply back
    // to). A reply for any other querier is for a different exchange.
    let expected_target_protocol: Ipv4Addr = required_str(
        validation.target_protocol_addr.as_deref(),
        "validation.target_protocol_addr",
    )?
    .parse()?;
    let mut peer_mismatches = Vec::new();
    match arp.target_ipv4() {
        Some(actual) => {
            if actual != expected_target_protocol {
                peer_mismatches.push(json!({
                    "field": "arp.target_protocol_addr",
                    "expected": expected_target_protocol.to_string(),
                    "actual": actual.to_string(),
                }));
            }
        }
        None => peer_mismatches.push(json!({
            "field": "arp.target_protocol_addr",
            "expected": expected_target_protocol.to_string(),
            "actual": hex_bytes(&arp.target_protocol_bytes_value()),
        })),
    }
    if !peer_mismatches.is_empty() {
        return Ok(CandidateValidation::WrongPeer(json!({
            "packet": decoded,
            "mismatches": peer_mismatches,
        })));
    }

    let mut mismatches = Vec::new();

    // Operation: an is-at is an ARP reply (operation 2).
    let expected_operation = required_u16(validation.operation, "validation.operation")?;
    if arp.opcode_value() != expected_operation {
        mismatches.push(json!({
            "field": "arp.operation",
            "expected": expected_operation,
            "actual": arp.opcode_value(),
        }));
    }

    // Sender hardware address: the resolved target MAC the kernel answered with.
    let expected_sender_hardware: MacAddr = required_str(
        validation.sender_hardware_addr.as_deref(),
        "validation.sender_hardware_addr",
    )?
    .parse()?;
    match arp.sender_mac() {
        Some(actual) => {
            if actual != expected_sender_hardware {
                mismatches.push(json!({
                    "field": "arp.sender_hardware_addr",
                    "expected": expected_sender_hardware.to_string(),
                    "actual": actual.to_string(),
                }));
            }
        }
        None => mismatches.push(json!({
            "field": "arp.sender_hardware_addr",
            "expected": expected_sender_hardware.to_string(),
            "actual": hex_bytes(&arp.sender_hardware_bytes_value()),
        })),
    }

    // Sender protocol address: the resolved target IPv4.
    let expected_sender_protocol: Ipv4Addr = required_str(
        validation.sender_protocol_addr.as_deref(),
        "validation.sender_protocol_addr",
    )?
    .parse()?;
    match arp.sender_ipv4() {
        Some(actual) => {
            if actual != expected_sender_protocol {
                mismatches.push(json!({
                    "field": "arp.sender_protocol_addr",
                    "expected": expected_sender_protocol.to_string(),
                    "actual": actual.to_string(),
                }));
            }
        }
        None => mismatches.push(json!({
            "field": "arp.sender_protocol_addr",
            "expected": expected_sender_protocol.to_string(),
            "actual": hex_bytes(&arp.sender_protocol_bytes_value()),
        })),
    }

    // Target hardware address: the original sender (the querier's MAC).
    let expected_target_hardware: MacAddr = required_str(
        validation.target_hardware_addr.as_deref(),
        "validation.target_hardware_addr",
    )?
    .parse()?;
    match arp.target_mac() {
        Some(actual) => {
            if actual != expected_target_hardware {
                mismatches.push(json!({
                    "field": "arp.target_hardware_addr",
                    "expected": expected_target_hardware.to_string(),
                    "actual": actual.to_string(),
                }));
            }
        }
        None => mismatches.push(json!({
            "field": "arp.target_hardware_addr",
            "expected": expected_target_hardware.to_string(),
            "actual": hex_bytes(&arp.target_hardware_bytes_value()),
        })),
    }

    // Ethernet framing: the unicast reply is addressed from the resolved target
    // MAC back to the original sender MAC.
    if let Some(ethernet) = packet.layer::<Ethernet>() {
        if let Some(expected_source) = validation.ethernet_source.as_deref() {
            let expected_source: MacAddr = expected_source.parse()?;
            match ethernet.source() {
                Some(actual) if actual == expected_source => {}
                actual => mismatches.push(json!({
                    "field": "ethernet.src",
                    "expected": expected_source.to_string(),
                    "actual": actual.map(|mac| mac.to_string()),
                })),
            }
        }
        if let Some(expected_destination) = validation.ethernet_destination.as_deref() {
            let expected_destination: MacAddr = expected_destination.parse()?;
            match ethernet.destination() {
                Some(actual) if actual == expected_destination => {}
                actual => mismatches.push(json!({
                    "field": "ethernet.dst",
                    "expected": expected_destination.to_string(),
                    "actual": actual.map(|mac| mac.to_string()),
                })),
            }
        }
    } else {
        mismatches.push(json!({
            "field": "ethernet",
            "expected": "present",
            "actual": "missing",
        }));
    }

    if mismatches.is_empty() {
        Ok(CandidateValidation::Passed(decoded))
    } else {
        Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": mismatches,
        })))
    }
}

/// Render a decoded ARP layer to JSON for the observed-response artifact.
pub fn arp_json(arp: &Arp) -> Value {
    json!({
        "hardware_type": arp.hardware_type_value(),
        "protocol_type": arp.protocol_type_value(),
        "hardware_len": arp.hardware_len_value(),
        "protocol_len": arp.protocol_len_value(),
        "operation": arp.opcode_value(),
        "is_reply": arp.opcode_value() == u16::from(ArpOperation::Reply),
        "sender_hardware_addr": arp.sender_mac().map(|mac| mac.to_string()),
        "sender_hardware_bytes": hex_bytes(&arp.sender_hardware_bytes_value()),
        "sender_protocol_addr": arp.sender_ipv4().map(|addr| addr.to_string()),
        "sender_protocol_bytes": hex_bytes(&arp.sender_protocol_bytes_value()),
        "target_hardware_addr": arp.target_mac().map(|mac| mac.to_string()),
        "target_hardware_bytes": hex_bytes(&arp.target_hardware_bytes_value()),
        "target_protocol_addr": arp.target_ipv4().map(|addr| addr.to_string()),
        "target_protocol_bytes": hex_bytes(&arp.target_protocol_bytes_value()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ArpValidation;
    use crate::test_support::base_plan;

    fn who_has_plan() -> ProbePlan {
        let mut plan = base_plan("arp-basic-who-has");
        plan.sender_protocol_addr = Some("10.64.0.10".to_string());
        plan.target_protocol_addr = Some("10.64.0.20".to_string());
        plan.sender_hardware_addr = Some("00:00:5e:00:53:0a".to_string());
        plan.ethernet_source = Some("00:00:5e:00:53:0a".to_string());
        plan.ethernet_destination = Some(BROADCAST_MAC.to_string());
        plan.operation = Some(1);
        plan.validation = Some(ArpValidation {
            operation: Some(2),
            sender_hardware_addr: Some("00:00:5e:00:53:14".to_string()),
            sender_protocol_addr: Some("10.64.0.20".to_string()),
            target_hardware_addr: Some("00:00:5e:00:53:0a".to_string()),
            target_protocol_addr: Some("10.64.0.10".to_string()),
            ethernet_source: Some("00:00:5e:00:53:14".to_string()),
            ethernet_destination: Some("00:00:5e:00:53:0a".to_string()),
        });
        plan
    }

    /// Build the canonical is-at reply the target kernel would unicast back, so
    /// the decode/validate path runs against a real libcrafter-built frame.
    fn is_at_frame(plan: &ProbePlan) -> Vec<u8> {
        let validation = plan.validation.as_ref().unwrap();
        let resolved_mac: MacAddr = validation
            .sender_hardware_addr
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let resolved_ipv4: Ipv4Addr = validation
            .sender_protocol_addr
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let querier_mac: MacAddr = validation
            .target_hardware_addr
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let querier_ipv4: Ipv4Addr = validation
            .target_protocol_addr
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let arp = Arp::is_at(resolved_ipv4, resolved_mac, querier_ipv4, querier_mac);
        let packet = Ethernet::with_addresses(resolved_mac, querier_mac) / arp;
        packet.compile().unwrap().into_bytes()
    }

    #[test]
    fn who_has_builds_ethernet_arp_broadcast_request() {
        let plan = who_has_plan();
        let packet = arp_who_has_packet(&plan).unwrap();

        let ethernet = packet.layer::<Ethernet>().expect("ethernet layer");
        assert_eq!(ethernet.source().unwrap().to_string(), "00:00:5e:00:53:0a");
        assert_eq!(ethernet.destination().unwrap().to_string(), BROADCAST_MAC);
        // compile() fills the ethertype from the ARP layer.
        let bytes = packet.compile().unwrap().into_bytes();
        assert_eq!(&bytes[12..14], &ETHERTYPE_ARP.to_be_bytes());

        let arp = packet.layer::<Arp>().expect("arp layer");
        assert_eq!(arp.opcode_value(), u16::from(ArpOperation::Request));
        assert_eq!(arp.sender_ipv4().unwrap().to_string(), "10.64.0.10");
        assert_eq!(arp.target_ipv4().unwrap().to_string(), "10.64.0.20");
        // who-has leaves the target hardware address unset (all-zero).
        assert_eq!(arp.target_mac().unwrap(), MacAddr::ZERO);
    }

    #[test]
    fn matching_is_at_reply_passes_validation() {
        let plan = who_has_plan();
        let raw = is_at_frame(&plan);
        let packet = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();

        match validate_arp_candidate(&plan, &packet, &raw).unwrap() {
            CandidateValidation::Passed(_) => {}
            other => panic!("expected Passed, got {other:?}"),
        }
    }

    #[test]
    fn reply_for_another_querier_is_wrong_peer() {
        let plan = who_has_plan();
        // A reply that resolves the right target but is addressed back to a
        // different querier protocol address is for a different exchange.
        let resolved_mac: MacAddr = "00:00:5e:00:53:14".parse().unwrap();
        let arp = Arp::is_at(
            "10.64.0.20".parse().unwrap(),
            resolved_mac,
            "10.64.0.99".parse().unwrap(),
            "00:00:5e:00:53:63".parse().unwrap(),
        );
        let packet =
            Ethernet::with_addresses(resolved_mac, "00:00:5e:00:53:63".parse().unwrap()) / arp;
        let raw = packet.compile().unwrap().into_bytes();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();

        match validate_arp_candidate(&plan, &decoded, &raw).unwrap() {
            CandidateValidation::WrongPeer(_) => {}
            other => panic!("expected WrongPeer, got {other:?}"),
        }
    }

    #[test]
    fn request_echoed_back_is_wrong_payload() {
        let plan = who_has_plan();
        // A frame addressed back to the querier but still an ARP request (op 1)
        // with the wrong resolved MAC fails the is-at contract.
        let arp = Arp::new()
            .operation(ArpOperation::Request)
            .sender_hardware_addr("00:00:5e:00:53:ff".parse::<MacAddr>().unwrap())
            .sender_protocol_addr("10.64.0.20".parse().unwrap())
            .target_hardware_addr("00:00:5e:00:53:0a".parse::<MacAddr>().unwrap())
            .target_protocol_addr("10.64.0.10".parse().unwrap());
        let packet = Ethernet::with_addresses(
            "00:00:5e:00:53:ff".parse().unwrap(),
            "00:00:5e:00:53:0a".parse().unwrap(),
        ) / arp;
        let raw = packet.compile().unwrap().into_bytes();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();

        match validate_arp_candidate(&plan, &decoded, &raw).unwrap() {
            CandidateValidation::WrongPayload(_) => {}
            other => panic!("expected WrongPayload, got {other:?}"),
        }
    }

    #[test]
    fn missing_validation_contract_is_an_error() {
        let mut plan = who_has_plan();
        plan.validation = None;
        let raw = is_at_frame(&who_has_plan());
        let packet = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();
        assert!(validate_arp_candidate(&plan, &packet, &raw).is_err());
    }
}
