//! DHCP behavioral probe cases.
//!
//! `dhcp-discover-offer` is the baseline DHCP behavioral check: build a
//! BOOTP/DHCP Discover with libcrafter, send it from the client port (68) to
//! the server port (67) against a controlled DHCP responder on a private L2
//! lab segment, capture the Offer, decode the IPv4/UDP/BOOTP/DHCP response with
//! libcrafter, and validate the BOOTP opcode (reply), the message type (Offer,
//! option 53), the echoed transaction id (xid), the client hardware address
//! (chaddr), the offered address (yiaddr), the server identifier (option 54),
//! the lease timing options (51/58/59), and the response direction
//! (server -> client, ports 67 -> 68).

use crafter::prelude::*;
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::common::{
    capture_filter, decoded_packet_json, failed_outcome, hex_bytes, observed_response, plan_json,
    required_str, required_u32, send_report_json, target_service_json, CandidateValidation,
    ExampleResult, ProbeOutcome, ProbePlan, StimulusEndpointRequest, FAILURE_DECODE_FAILED,
    FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD, FAILURE_WRONG_PEER,
};

/// Stable identifier for the DHCP case module.
pub const MODULE_NAME: &str = "dhcp";

pub fn run_dhcp_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = dhcp_packet(plan)?;
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

pub fn run_dhcp_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = dhcp_packet(plan)?;
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
        match validate_dhcp_candidate(plan, captured.packet(), captured.data())? {
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
            vec!["captured DHCP response did not match the expected Offer contract".to_string()],
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
            vec!["captured DHCP response did not match expected peer or ports".to_string()],
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
        vec!["timed out waiting for DHCP Offer".to_string()],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "capture_filter": capture_filter(plan),
        })),
        sent,
        false,
    ))
}

/// Build the IPv4/UDP/BOOTP/DHCP stimulus packet with libcrafter.
///
/// `dhcp-discover-offer` builds a Discover (message type 1); `dhcp-request-ack`
/// builds a Request (message type 3) carrying the requested-IP option (50) and
/// the chosen server-identifier option (54). The stimulus is sent from the DHCP
/// client port (68) to the server port (67). `compile()` fills the BOOTP
/// op/htype/hlen, magic cookie, lengths, and the UDP/IPv4 checksums; the
/// caller-set client MAC, transaction id, requested IP, and server identifier
/// survive untouched.
pub fn dhcp_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    let source_port = plan.source_port.unwrap_or(DHCP_CLIENT_PORT);
    let destination_port = plan.destination_port.unwrap_or(DHCP_SERVER_PORT);
    let client_mac: MacAddr = required_str(plan.client_mac.as_deref(), "client_mac")?.parse()?;
    let transaction_id = required_u32(plan.transaction_id, "transaction_id")?;

    let dhcp = if plan.case == "dhcp-request-ack" {
        // RFC 2131 section 4.3.2: a DHCPREQUEST in response to a DHCPOFFER names
        // the address it wants to commit in the requested-IP option (50) and the
        // chosen server in the server-identifier option (54), echoing the xid.
        let requested_ip: Ipv4Addr =
            required_str(plan.requested_ipv4.as_deref(), "requested_ipv4")?.parse()?;
        let server_identifier: Ipv4Addr =
            required_str(plan.server_identifier.as_deref(), "server_identifier")?.parse()?;
        Dhcp::request(client_mac, requested_ip, server_identifier).transaction_id(transaction_id)
    } else {
        // RFC 2131 section 4.1: a client that cannot receive unicast before its
        // address is configured sets the broadcast flag. The lab transport
        // unicasts the Offer back over the private segment, so the responder uses
        // the recorded source address; the flag stays a faithful Discover shape.
        Dhcp::discover(client_mac).transaction_id(transaction_id)
    };

    Ok(Ipv4::new().src(source).dst(destination)
        / Udp::new().sport(source_port).dport(destination_port)
        / dhcp)
}

/// Validate one captured candidate against the DHCP Discover->Offer contract.
///
/// Peer/port mismatches surface as `WrongPeer`; a packet that reaches the right
/// peer but fails the BOOTP/DHCP contract (opcode, message type, transaction
/// id, chaddr, yiaddr, server identifier, lease options, direction) surfaces as
/// `WrongPayload`. A fully matching Offer surfaces as `Passed`.
pub fn validate_dhcp_candidate(
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
    let expected_source_port = plan.destination_port.unwrap_or(DHCP_SERVER_PORT);
    let expected_destination_port = plan.source_port.unwrap_or(DHCP_CLIENT_PORT);
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

    let Some(dhcp) = packet.layer::<Dhcp>() else {
        return Ok(CandidateValidation::WrongPayload(json!({
            "packet": decoded,
            "mismatches": [{
                "field": "dhcp",
                "expected": "present",
                "actual": "missing",
            }],
        })));
    };

    let mut mismatches = Vec::new();

    // Response direction: a DHCP Offer is a BOOTP reply (op 2). Combined with the
    // ports checked above (server 67 -> client 68), this confirms the
    // server -> client direction.
    if dhcp.op_value() != BOOTP_REPLY {
        mismatches.push(json!({
            "field": "dhcp.op",
            "expected": BOOTP_REPLY,
            "actual": dhcp.op_value(),
        }));
    }

    // Message type (option 53): Offer.
    let expected_message_type = plan.expected_message_type_value.unwrap_or(DHCP_OFFER);
    let actual_message_type = dhcp.message_type_value().map(DhcpMessageType::code);
    if actual_message_type != Some(expected_message_type) {
        mismatches.push(json!({
            "field": "dhcp.message_type",
            "expected": expected_message_type,
            "actual": actual_message_type,
        }));
    }

    // Transaction id (xid) echoed from the Discover.
    let expected_xid = required_u32(plan.transaction_id, "transaction_id")?;
    if dhcp.transaction_id_value() != expected_xid {
        mismatches.push(json!({
            "field": "dhcp.xid",
            "expected": expected_xid,
            "actual": dhcp.transaction_id_value(),
        }));
    }

    // Client hardware address (chaddr) echoed from the Discover.
    let expected_chaddr: MacAddr =
        required_str(plan.client_mac.as_deref(), "client_mac")?.parse()?;
    match dhcp.client_mac_value() {
        Some(actual_chaddr) => {
            if actual_chaddr != expected_chaddr {
                mismatches.push(json!({
                    "field": "dhcp.chaddr",
                    "expected": expected_chaddr.to_string(),
                    "actual": actual_chaddr.to_string(),
                }));
            }
        }
        None => mismatches.push(json!({
            "field": "dhcp.chaddr",
            "expected": expected_chaddr.to_string(),
            "actual": hex_bytes(dhcp.client_hardware_address_value()),
        })),
    }

    // Offered address (yiaddr).
    let expected_yiaddr: Ipv4Addr =
        required_str(plan.expected_yiaddr.as_deref(), "expected_yiaddr")?.parse()?;
    match dhcp.offered_ip_address() {
        Some(actual_yiaddr) => {
            if actual_yiaddr != expected_yiaddr {
                mismatches.push(json!({
                    "field": "dhcp.yiaddr",
                    "expected": expected_yiaddr.to_string(),
                    "actual": actual_yiaddr.to_string(),
                }));
            }
        }
        None => mismatches.push(json!({
            "field": "dhcp.yiaddr",
            "expected": expected_yiaddr.to_string(),
            "actual": dhcp.your_ip_address_value().to_string(),
        })),
    }

    // Server identifier (option 54).
    let expected_server_identifier: Ipv4Addr = required_str(
        plan.expected_server_identifier.as_deref(),
        "expected_server_identifier",
    )?
    .parse()?;
    match dhcp.server_identifier_value() {
        Some(actual_server_identifier) => {
            if actual_server_identifier != expected_server_identifier {
                mismatches.push(json!({
                    "field": "dhcp.server_identifier",
                    "expected": expected_server_identifier.to_string(),
                    "actual": actual_server_identifier.to_string(),
                }));
            }
        }
        None => mismatches.push(json!({
            "field": "dhcp.server_identifier",
            "expected": expected_server_identifier.to_string(),
            "actual": Value::Null,
        })),
    }

    // Lease time option (51); renewal (58) and rebinding (59) when planned.
    if let Some(expected_lease_time) = plan.expected_lease_time {
        match dhcp.lease_time_value() {
            Some(actual) if actual == expected_lease_time => {}
            actual => mismatches.push(json!({
                "field": "dhcp.lease_time",
                "expected": expected_lease_time,
                "actual": actual,
            })),
        }
    }
    if let Some(expected_renewal_time) = plan.expected_renewal_time {
        match dhcp.renewal_time_value() {
            Some(actual) if actual == expected_renewal_time => {}
            actual => mismatches.push(json!({
                "field": "dhcp.renewal_time",
                "expected": expected_renewal_time,
                "actual": actual,
            })),
        }
    }
    if let Some(expected_rebinding_time) = plan.expected_rebinding_time {
        match dhcp.rebinding_time_value() {
            Some(actual) if actual == expected_rebinding_time => {}
            actual => mismatches.push(json!({
                "field": "dhcp.rebinding_time",
                "expected": expected_rebinding_time,
                "actual": actual,
            })),
        }
    }

    // Configuration options committed by the Ack: subnet mask (1), router (3),
    // and DNS server (6) when the plan names them.
    if let Some(expected_subnet_mask) = plan.expected_subnet_mask.as_deref() {
        let expected: Ipv4Addr = expected_subnet_mask.parse()?;
        match dhcp.subnet_mask_value() {
            Some(actual) if actual == expected => {}
            actual => mismatches.push(json!({
                "field": "dhcp.subnet_mask",
                "expected": expected.to_string(),
                "actual": actual.map(|address| address.to_string()),
            })),
        }
    }
    if let Some(expected_router) = plan.expected_router_ipv4.as_deref() {
        let expected: Ipv4Addr = expected_router.parse()?;
        let routers = dhcp.routers();
        if !routers.contains(&expected) {
            mismatches.push(json!({
                "field": "dhcp.router",
                "expected": expected.to_string(),
                "actual": routers
                    .iter()
                    .map(|address| address.to_string())
                    .collect::<Vec<_>>(),
            }));
        }
    }
    if let Some(expected_dns) = plan.expected_dns_ipv4.as_deref() {
        let expected: Ipv4Addr = expected_dns.parse()?;
        let dns_servers = dhcp.domain_name_servers();
        if !dns_servers.contains(&expected) {
            mismatches.push(json!({
                "field": "dhcp.domain_name_server",
                "expected": expected.to_string(),
                "actual": dns_servers
                    .iter()
                    .map(|address| address.to_string())
                    .collect::<Vec<_>>(),
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

/// JSON view of a decoded DHCP layer for the observed-response artifact.
pub fn dhcp_json(dhcp: &Dhcp) -> Value {
    json!({
        "op": dhcp.op_value(),
        "is_reply": dhcp.op_value() == BOOTP_REPLY,
        "hardware_type": dhcp.hardware_type_value(),
        "hardware_len": dhcp.hardware_len_value(),
        "transaction_id": dhcp.transaction_id_value(),
        "flags": dhcp.flags_value(),
        "client_ip_address": dhcp.client_ip_address_value().to_string(),
        "your_ip_address": dhcp.your_ip_address_value().to_string(),
        "server_ip_address": dhcp.server_ip_address_value().to_string(),
        "gateway_ip_address": dhcp.gateway_ip_address_value().to_string(),
        "client_hardware_address": hex_bytes(dhcp.client_hardware_address_value()),
        "client_mac": dhcp.client_mac_value().map(|mac| mac.to_string()),
        "message_type": dhcp.message_type_value().map(DhcpMessageType::code),
        "server_identifier": dhcp
            .server_identifier_value()
            .map(|address| address.to_string()),
        "subnet_mask": dhcp.subnet_mask_value().map(|address| address.to_string()),
        "routers": dhcp
            .routers()
            .iter()
            .map(|address| address.to_string())
            .collect::<Vec<_>>(),
        "lease_time": dhcp.lease_time_value(),
        "renewal_time": dhcp.renewal_time_value(),
        "rebinding_time": dhcp.rebinding_time_value(),
        "options": dhcp
            .options_value()
            .iter()
            .map(|option| json!({ "code": option.code() }))
            .collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    fn discover_plan() -> ProbePlan {
        let mut plan = base_plan("dhcp-discover-offer");
        plan.source_ipv4 = Some("10.64.0.10".to_string());
        plan.destination_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.64.0.10".to_string());
        plan.source_port = Some(DHCP_CLIENT_PORT);
        plan.destination_port = Some(DHCP_SERVER_PORT);
        plan.client_mac = Some("00:00:5e:00:53:2a".to_string());
        plan.transaction_id = Some(0x3903_f326);
        plan.expected_message_type_value = Some(DHCP_OFFER);
        plan.expected_yiaddr = Some("198.51.100.42".to_string());
        plan.expected_server_identifier = Some("10.64.0.20".to_string());
        plan.expected_lease_time = Some(3600);
        plan.expected_renewal_time = Some(1800);
        plan.expected_rebinding_time = Some(3150);
        plan
    }

    /// Build the canonical Offer the controlled responder would unicast back, so
    /// the decode/validate path runs against a real libcrafter-built packet.
    fn offer_packet(plan: &ProbePlan) -> Packet {
        let client_mac: MacAddr = plan.client_mac.as_deref().unwrap().parse().unwrap();
        let server_identifier: Ipv4Addr = plan
            .expected_server_identifier
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let offered: Ipv4Addr = plan.expected_yiaddr.as_deref().unwrap().parse().unwrap();
        let dhcp = Dhcp::offer(client_mac, offered, server_identifier)
            .transaction_id(plan.transaction_id.unwrap())
            .lease_time(plan.expected_lease_time.unwrap())
            .renewal_time(plan.expected_renewal_time.unwrap())
            .rebinding_time(plan.expected_rebinding_time.unwrap())
            .subnet_mask("255.255.255.0".parse().unwrap());
        Ipv4::new()
            .src(
                plan.expected_reply_source_ipv4
                    .as_deref()
                    .unwrap()
                    .parse::<Ipv4Addr>()
                    .unwrap(),
            )
            .dst(
                plan.expected_reply_destination_ipv4
                    .as_deref()
                    .unwrap()
                    .parse::<Ipv4Addr>()
                    .unwrap(),
            )
            / Udp::new().sport(DHCP_SERVER_PORT).dport(DHCP_CLIENT_PORT)
            / dhcp
    }

    fn request_plan() -> ProbePlan {
        let mut plan = base_plan("dhcp-request-ack");
        plan.source_ipv4 = Some("10.64.0.10".to_string());
        plan.destination_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.64.0.10".to_string());
        plan.source_port = Some(DHCP_CLIENT_PORT);
        plan.destination_port = Some(DHCP_SERVER_PORT);
        plan.client_mac = Some("00:00:5e:00:53:2a".to_string());
        plan.transaction_id = Some(0x3903_f326);
        plan.requested_ipv4 = Some("198.51.100.42".to_string());
        plan.server_identifier = Some("10.64.0.20".to_string());
        plan.expected_message_type_value = Some(DHCP_ACK);
        plan.expected_yiaddr = Some("198.51.100.42".to_string());
        plan.expected_server_identifier = Some("10.64.0.20".to_string());
        plan.expected_subnet_mask = Some("255.255.255.0".to_string());
        plan.expected_router_ipv4 = Some("10.64.0.1".to_string());
        plan.expected_dns_ipv4 = Some("198.51.100.53".to_string());
        plan.expected_lease_time = Some(3600);
        plan.expected_renewal_time = Some(1800);
        plan.expected_rebinding_time = Some(3150);
        plan
    }

    /// Build the canonical Ack the controlled responder would unicast back, so
    /// the decode/validate path runs against a real libcrafter-built packet.
    fn ack_packet(plan: &ProbePlan) -> Packet {
        let client_mac: MacAddr = plan.client_mac.as_deref().unwrap().parse().unwrap();
        let server_identifier: Ipv4Addr = plan
            .expected_server_identifier
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let assigned: Ipv4Addr = plan.expected_yiaddr.as_deref().unwrap().parse().unwrap();
        let subnet_mask: Ipv4Addr = plan.expected_subnet_mask.as_deref().unwrap().parse().unwrap();
        let router: Ipv4Addr = plan.expected_router_ipv4.as_deref().unwrap().parse().unwrap();
        let dns: Ipv4Addr = plan.expected_dns_ipv4.as_deref().unwrap().parse().unwrap();
        let dhcp = Dhcp::ack(client_mac, assigned, server_identifier)
            .transaction_id(plan.transaction_id.unwrap())
            .lease_time(plan.expected_lease_time.unwrap())
            .renewal_time(plan.expected_renewal_time.unwrap())
            .rebinding_time(plan.expected_rebinding_time.unwrap())
            .subnet_mask(subnet_mask)
            .router(vec![router])
            .domain_name_server(vec![dns]);
        Ipv4::new()
            .src(
                plan.expected_reply_source_ipv4
                    .as_deref()
                    .unwrap()
                    .parse::<Ipv4Addr>()
                    .unwrap(),
            )
            .dst(
                plan.expected_reply_destination_ipv4
                    .as_deref()
                    .unwrap()
                    .parse::<Ipv4Addr>()
                    .unwrap(),
            )
            / Udp::new().sport(DHCP_SERVER_PORT).dport(DHCP_CLIENT_PORT)
            / dhcp
    }

    #[test]
    fn dhcp_request_compiles_with_requested_ip_and_server_identifier() {
        let plan = request_plan();
        let packet = dhcp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap().as_bytes().to_vec();

        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let dhcp = decoded.layer::<Dhcp>().unwrap();

        // Client 68 -> server 67.
        assert_eq!(udp.source_port_value(), DHCP_CLIENT_PORT);
        assert_eq!(udp.destination_port_value(), DHCP_SERVER_PORT);
        // BOOTP request carrying a Request with the caller's xid, requested IP
        // (option 50), and server identifier (option 54).
        assert_eq!(dhcp.op_value(), BOOTP_REQUEST);
        assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Request));
        assert_eq!(dhcp.transaction_id_value(), 0x3903_f326);
        assert_eq!(
            dhcp.requested_ip_address_value(),
            Some("198.51.100.42".parse().unwrap())
        );
        assert_eq!(
            dhcp.server_identifier_value(),
            Some("10.64.0.20".parse().unwrap())
        );
        assert_eq!(dhcp.magic_cookie_value(), DHCP_MAGIC_COOKIE);
    }

    #[test]
    fn dhcp_request_requires_requested_ip() {
        let mut plan = request_plan();
        plan.requested_ipv4 = None;
        assert!(dhcp_packet(&plan).is_err());
    }

    #[test]
    fn dhcp_request_requires_server_identifier() {
        let mut plan = request_plan();
        plan.server_identifier = None;
        assert!(dhcp_packet(&plan).is_err());
    }

    #[test]
    fn matching_ack_passes_validation() {
        let plan = request_plan();
        let bytes = ack_packet(&plan).compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(
            matches!(validation, CandidateValidation::Passed(_)),
            "expected Passed, got {validation:?}"
        );
    }

    #[test]
    fn ack_with_wrong_message_type_is_wrong_payload() {
        let plan = request_plan();
        // A Nak (message type 6) reaches the right peer but fails the Ack contract.
        let client_mac: MacAddr = plan.client_mac.as_deref().unwrap().parse().unwrap();
        let server_identifier: Ipv4Addr = plan
            .expected_server_identifier
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let dhcp =
            Dhcp::nak(client_mac, server_identifier).transaction_id(plan.transaction_id.unwrap());
        let packet = Ipv4::new()
            .src("10.64.0.20".parse::<Ipv4Addr>().unwrap())
            .dst("10.64.0.10".parse::<Ipv4Addr>().unwrap())
            / Udp::new().sport(DHCP_SERVER_PORT).dport(DHCP_CLIENT_PORT)
            / dhcp;
        let bytes = packet.compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(matches!(validation, CandidateValidation::WrongPayload(_)));
    }

    #[test]
    fn ack_missing_dns_option_is_wrong_payload() {
        let plan = request_plan();
        let client_mac: MacAddr = plan.client_mac.as_deref().unwrap().parse().unwrap();
        let server_identifier: Ipv4Addr = plan
            .expected_server_identifier
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let assigned: Ipv4Addr = plan.expected_yiaddr.as_deref().unwrap().parse().unwrap();
        // Same Ack but without the DNS server option (6) the plan requires.
        let dhcp = Dhcp::ack(client_mac, assigned, server_identifier)
            .transaction_id(plan.transaction_id.unwrap())
            .lease_time(plan.expected_lease_time.unwrap())
            .renewal_time(plan.expected_renewal_time.unwrap())
            .rebinding_time(plan.expected_rebinding_time.unwrap())
            .subnet_mask(plan.expected_subnet_mask.as_deref().unwrap().parse().unwrap())
            .router(vec![plan.expected_router_ipv4.as_deref().unwrap().parse().unwrap()]);
        let packet = Ipv4::new()
            .src("10.64.0.20".parse::<Ipv4Addr>().unwrap())
            .dst("10.64.0.10".parse::<Ipv4Addr>().unwrap())
            / Udp::new().sport(DHCP_SERVER_PORT).dport(DHCP_CLIENT_PORT)
            / dhcp;
        let bytes = packet.compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(matches!(validation, CandidateValidation::WrongPayload(_)));
    }

    #[test]
    fn dhcp_packet_requires_client_mac() {
        let mut plan = discover_plan();
        plan.client_mac = None;
        assert!(dhcp_packet(&plan).is_err());
    }

    #[test]
    fn dhcp_packet_requires_transaction_id() {
        let mut plan = discover_plan();
        plan.transaction_id = None;
        assert!(dhcp_packet(&plan).is_err());
    }

    #[test]
    fn dhcp_discover_compiles_with_client_ports_and_message_type() {
        let plan = discover_plan();
        let packet = dhcp_packet(&plan).unwrap();
        let compiled = packet.compile().unwrap();
        let bytes = compiled.as_bytes().to_vec();

        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let dhcp = decoded.layer::<Dhcp>().unwrap();

        // Client 68 -> server 67.
        assert_eq!(udp.source_port_value(), DHCP_CLIENT_PORT);
        assert_eq!(udp.destination_port_value(), DHCP_SERVER_PORT);
        // BOOTP request carrying a Discover with the caller's xid and chaddr.
        assert_eq!(dhcp.op_value(), BOOTP_REQUEST);
        assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Discover));
        assert_eq!(dhcp.transaction_id_value(), 0x3903_f326);
        assert_eq!(
            dhcp.client_mac_value(),
            Some("00:00:5e:00:53:2a".parse().unwrap())
        );
        // compile() filled the magic cookie.
        assert_eq!(dhcp.magic_cookie_value(), DHCP_MAGIC_COOKIE);
    }

    #[test]
    fn matching_offer_passes_validation() {
        let plan = discover_plan();
        let bytes = offer_packet(&plan).compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(
            matches!(validation, CandidateValidation::Passed(_)),
            "expected Passed, got {validation:?}"
        );
    }

    #[test]
    fn wrong_yiaddr_is_wrong_payload() {
        let mut plan = discover_plan();
        let bytes = offer_packet(&plan).compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        plan.expected_yiaddr = Some("198.51.100.99".to_string());
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(matches!(validation, CandidateValidation::WrongPayload(_)));
    }

    #[test]
    fn wrong_transaction_id_is_wrong_payload() {
        let mut plan = discover_plan();
        let bytes = offer_packet(&plan).compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        plan.transaction_id = Some(0x0102_0304);
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(matches!(validation, CandidateValidation::WrongPayload(_)));
    }

    #[test]
    fn wrong_peer_ports_are_wrong_peer() {
        let plan = discover_plan();
        // An Offer that arrives on the wrong ports (e.g. 67 -> 67) is a peer
        // mismatch, not a payload mismatch.
        let client_mac: MacAddr = plan.client_mac.as_deref().unwrap().parse().unwrap();
        let server_identifier: Ipv4Addr = plan
            .expected_server_identifier
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let offered: Ipv4Addr = plan.expected_yiaddr.as_deref().unwrap().parse().unwrap();
        let dhcp = Dhcp::offer(client_mac, offered, server_identifier)
            .transaction_id(plan.transaction_id.unwrap());
        let packet = Ipv4::new()
            .src("10.64.0.20".parse::<Ipv4Addr>().unwrap())
            .dst("10.64.0.10".parse::<Ipv4Addr>().unwrap())
            / Udp::new().sport(DHCP_SERVER_PORT).dport(DHCP_SERVER_PORT)
            / dhcp;
        let bytes = packet.compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(matches!(validation, CandidateValidation::WrongPeer(_)));
    }
}
