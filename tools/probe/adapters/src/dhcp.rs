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
    capture_filter, captured_data, decode_hex, decoded_packet_json, failed_outcome, hex_bytes,
    observed_response, open_capture_sniffer, plan_json, required_str, required_u32,
    required_u8_list, send_report_json, target_service_json, CandidateValidation, DhcpSend,
    ExampleResult, ProbeOutcome, ProbePlan, StimulusEndpointRequest, FAILURE_DECODE_FAILED,
    FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD, FAILURE_WRONG_PEER,
};

/// Stable identifier for the DHCP case module.
pub const MODULE_NAME: &str = "dhcp";

pub fn run_dhcp_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    if let Some(sends) = plan.dhcp_sends.as_deref() {
        return run_dhcp_multi_send_dry_run(request, plan, sends);
    }
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
    if let Some(sends) = plan.dhcp_sends.as_deref() {
        return run_dhcp_multi_send_live(request, plan, sends);
    }
    let packet = dhcp_packet(plan)?;
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
        match validate_dhcp_candidate(plan, captured.packet(), captured_data(&captured))? {
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

/// Derive a single-send `ProbePlan` for one entry of a multi-send DHCP case's
/// `dhcp_sends` array. The derived plan reuses the parent's case and shared
/// fields but overrides the per-send transaction id, client identity (chaddr),
/// source/destination ports, peer addresses, offered address, server identifier,
/// lease timing options, and capture filter so the existing single-send builders
/// (`dhcp_packet`, `validate_dhcp_candidate`) operate on exactly this one
/// Discover and its own expected Offer.
fn send_as_plan(parent: &ProbePlan, send: &DhcpSend) -> ProbePlan {
    let mut derived = parent.clone();
    // This send is a single, self-contained Discover->Offer exchange; clear the
    // multi-send markers so the single-send build/validate path runs against just
    // this send.
    derived.dhcp_sends = None;
    derived.send_count = None;
    if let Some(value) = send.source_ipv4.clone() {
        derived.source_ipv4 = Some(value);
    }
    if let Some(value) = send.destination_ipv4.clone() {
        derived.destination_ipv4 = Some(value);
    }
    if let Some(value) = send.expected_reply_source_ipv4.clone() {
        derived.expected_reply_source_ipv4 = Some(value);
    }
    if let Some(value) = send.expected_reply_destination_ipv4.clone() {
        derived.expected_reply_destination_ipv4 = Some(value);
    }
    if let Some(value) = send.source_port {
        derived.source_port = Some(value);
    }
    if let Some(value) = send.destination_port {
        derived.destination_port = Some(value);
    }
    if let Some(value) = send.client_mac.clone() {
        derived.client_mac = Some(value);
    }
    if let Some(value) = send.transaction_id {
        derived.transaction_id = Some(value);
    }
    if let Some(value) = send.expected_message_type_value {
        derived.expected_message_type_value = Some(value);
    }
    if let Some(value) = send.expected_yiaddr.clone() {
        derived.expected_yiaddr = Some(value);
    }
    if let Some(value) = send.expected_server_identifier.clone() {
        derived.expected_server_identifier = Some(value);
    }
    if let Some(value) = send.expected_subnet_mask.clone() {
        derived.expected_subnet_mask = Some(value);
    }
    if let Some(value) = send.expected_router_ipv4.clone() {
        derived.expected_router_ipv4 = Some(value);
    }
    if let Some(value) = send.expected_lease_time {
        derived.expected_lease_time = Some(value);
    }
    if let Some(value) = send.expected_renewal_time {
        derived.expected_renewal_time = Some(value);
    }
    if let Some(value) = send.expected_rebinding_time {
        derived.expected_rebinding_time = Some(value);
    }
    derived
}

/// Dry-run a multi-send DHCP case (`dhcp-rapid-repeat`): compile every per-send
/// Discover with libcrafter and emit one planned send and one expected Offer per
/// send. No traffic leaves the host. The output carries a `planned_sends` array
/// (one entry per build) and a top-level `send_count` so an inspector sees two
/// planned sends and two expected responses.
fn run_dhcp_multi_send_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
    sends: &[DhcpSend],
) -> ExampleResult<ProbeOutcome> {
    let mut planned_sends = Vec::with_capacity(sends.len());
    for (offset, send) in sends.iter().enumerate() {
        let send_plan = send_as_plan(plan, send);
        let packet = dhcp_packet(&send_plan)?;
        let report = SocketSender::new(
            SendOptions::new()
                .iface(request.interface.clone())
                .network_layer()
                .dry_run(),
        )
        .send(&packet)?;
        let sent_raw_hex = hex_bytes(report.plan().bytes());
        planned_sends.push(json!({
            "index": send.index.unwrap_or(offset),
            "transaction_id": send_plan.transaction_id,
            "client_mac": send_plan.client_mac,
            "source_port": send_plan.source_port,
            "destination_port": send_plan.destination_port,
            "expected_yiaddr": send_plan.expected_yiaddr,
            "send_report": send_report_json(&report),
            "sent_raw_hex": sent_raw_hex,
            "capture_filter": capture_filter(&send_plan),
            "expected_response": dhcp_expected_response_json(&send_plan),
        }));
    }
    let expected_responses: Vec<Value> = planned_sends
        .iter()
        .filter_map(|entry| entry.get("expected_response").cloned())
        .collect();
    let observed = observed_response(
        plan,
        false,
        None,
        json!({}),
        json!({
            "planned_only": true,
            "send_count": planned_sends.len(),
            "planned_sends": planned_sends,
            "expected_responses": expected_responses,
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
            "send_count": planned_sends.len(),
            "planned_sends": planned_sends,
            "expected_responses": expected_responses,
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

/// Live multi-send DHCP case (`dhcp-rapid-repeat`): build and send every per-send
/// libcrafter Discover, capture the Offers, decode each, and validate every Offer
/// against *its* send's transaction id (xid), client identity (chaddr), and
/// offered address. Each send opens its own capture filtered to the client port,
/// so two Offers that share the lab transport are never confused — every Offer is
/// matched to the Discover that produced it by the echoed xid. The case passes
/// only when every send validates.
fn run_dhcp_multi_send_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
    sends: &[DhcpSend],
) -> ExampleResult<ProbeOutcome> {
    let mut send_results = Vec::with_capacity(sends.len());
    let mut all_passed = true;
    let mut any_sent = false;
    let mut any_received = false;
    let mut failure_reason: Option<&'static str> = None;
    let mut errors: Vec<String> = Vec::new();

    for (offset, send) in sends.iter().enumerate() {
        let send_plan = send_as_plan(plan, send);
        let outcome = run_dhcp_live(request, &send_plan)?;
        any_sent |= outcome.sent;
        any_received |= outcome.received;
        let status = outcome
            .result
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("failed");
        if status != "passed" {
            all_passed = false;
            let reason = outcome
                .result
                .get("metadata")
                .and_then(|metadata| metadata.get("failure_reason"))
                .and_then(Value::as_str);
            if let Some(reason) = reason {
                failure_reason.get_or_insert(static_failure_reason(reason));
                errors.push(format!(
                    "send {} (xid {:?}) failed: {reason}",
                    send.index.unwrap_or(offset),
                    send_plan.transaction_id,
                ));
            }
        }
        send_results.push(json!({
            "index": send.index.unwrap_or(offset),
            "transaction_id": send_plan.transaction_id,
            "client_mac": send_plan.client_mac,
            "expected_yiaddr": send_plan.expected_yiaddr,
            "status": status,
            "result": outcome.result,
        }));
    }

    let summary = json!({
        "send_count": sends.len(),
        "send_results": send_results,
    });

    if all_passed {
        let observed = observed_response(
            plan,
            true,
            None,
            summary.clone(),
            json!({
                "capture_filter": capture_filter(plan),
                "send_count": sends.len(),
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
                "send_count": sends.len(),
                "send_results": observed["decoded"]["send_results"].clone(),
            }
        });
        return Ok(ProbeOutcome {
            result,
            observed_response: observed,
            sent: any_sent,
            received: any_received,
        });
    }

    Ok(failed_outcome(
        plan,
        failure_reason.unwrap_or(FAILURE_WRONG_PAYLOAD),
        if errors.is_empty() {
            vec!["one or more rapid-repeat sends failed validation".to_string()]
        } else {
            errors
        },
        Some(summary),
        any_sent,
        any_received,
    ))
}

/// Map a failure-reason string (as it appears in a per-send result) back to the
/// crate's `'static` failure-reason constants so the aggregate failure uses a
/// stable reason.
fn static_failure_reason(reason: &str) -> &'static str {
    match reason {
        FAILURE_TIMEOUT => FAILURE_TIMEOUT,
        FAILURE_WRONG_PEER => FAILURE_WRONG_PEER,
        FAILURE_DECODE_FAILED => FAILURE_DECODE_FAILED,
        _ => FAILURE_WRONG_PAYLOAD,
    }
}

/// JSON view of one send's expected Offer (peer/ports, transaction id, message
/// type, offered address, server identifier, and lease options) for the dry-run
/// report.
fn dhcp_expected_response_json(send_plan: &ProbePlan) -> Value {
    json!({
        "source_ipv4": send_plan.expected_reply_source_ipv4,
        "destination_ipv4": send_plan.expected_reply_destination_ipv4,
        "source_port": send_plan.destination_port,
        "destination_port": send_plan.source_port,
        "op_value": 2,
        "message_type_value": send_plan.expected_message_type_value.unwrap_or(DHCP_OFFER),
        "transaction_id": send_plan.transaction_id,
        "client_hardware_address": send_plan.client_mac,
        "yiaddr": send_plan.expected_yiaddr,
        "server_identifier": send_plan.expected_server_identifier,
        "lease_time": send_plan.expected_lease_time,
        "renewal_time": send_plan.expected_renewal_time,
        "rebinding_time": send_plan.expected_rebinding_time,
        "direction": "server_to_client",
    })
}

/// JSON view of a plan's `dhcp_sends` array for the plan echo. `None` renders
/// null.
pub fn sends_json(sends: Option<&[DhcpSend]>) -> Value {
    match sends {
        Some(sends) => Value::Array(
            sends
                .iter()
                .map(|send| {
                    json!({
                        "index": send.index,
                        "source_ipv4": send.source_ipv4,
                        "destination_ipv4": send.destination_ipv4,
                        "expected_reply_source_ipv4": send.expected_reply_source_ipv4,
                        "expected_reply_destination_ipv4": send.expected_reply_destination_ipv4,
                        "source_port": send.source_port,
                        "destination_port": send.destination_port,
                        "client_mac": send.client_mac,
                        "transaction_id": send.transaction_id,
                        "expected_message_type_value": send.expected_message_type_value,
                        "expected_yiaddr": send.expected_yiaddr,
                        "expected_server_identifier": send.expected_server_identifier,
                        "expected_subnet_mask": send.expected_subnet_mask,
                        "expected_router_ipv4": send.expected_router_ipv4,
                        "expected_lease_time": send.expected_lease_time,
                        "expected_renewal_time": send.expected_renewal_time,
                        "expected_rebinding_time": send.expected_rebinding_time,
                        "capture_filter": send.capture_filter,
                    })
                })
                .collect(),
        ),
        None => Value::Null,
    }
}

/// JSON view of a plan's `dhcp_sends` for the responder's `rapid_repeat`
/// descriptor: the per-send transaction id, client MAC, and offered address the
/// responder keys each Offer to.
pub fn repeat_sends_json(sends: Option<&[DhcpSend]>) -> Value {
    match sends {
        Some(sends) => Value::Array(
            sends
                .iter()
                .map(|send| {
                    json!({
                        "transaction_id": send.transaction_id,
                        "client_mac": send.client_mac,
                        "yiaddr": send.expected_yiaddr,
                    })
                })
                .collect(),
        ),
        None => Value::Null,
    }
}

/// Build the IPv4/UDP/BOOTP/DHCP stimulus packet with libcrafter.
///
/// `dhcp-discover-offer` builds a Discover (message type 1); `dhcp-request-ack`
/// builds a SELECTING-state Request (message type 3) carrying the requested-IP
/// option (50) and the chosen server-identifier option (54);
/// `dhcp-renewal-unicast-ack` builds a RENEWING-state Request (message type 3)
/// that is unicast directly to the leasing server, setting `ciaddr` to the
/// bound address and omitting options 50/54. The stimulus is sent from the DHCP
/// client port (68) to the server port (67). `compile()` fills the BOOTP
/// op/htype/hlen, magic cookie, lengths, and the UDP/IPv4 checksums; the
/// caller-set client MAC, transaction id, ciaddr, requested IP, and server
/// identifier survive untouched.
pub fn dhcp_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    let source_port = plan.source_port.unwrap_or(DHCP_CLIENT_PORT);
    let destination_port = plan.destination_port.unwrap_or(DHCP_SERVER_PORT);
    let client_mac: MacAddr = required_str(plan.client_mac.as_deref(), "client_mac")?.parse()?;
    let transaction_id = required_u32(plan.transaction_id, "transaction_id")?;

    let dhcp = if plan.case == "dhcp-request-ack" || plan.case == "dhcp-request-nak" {
        // RFC 2131 section 4.3.2: a DHCPREQUEST in response to a DHCPOFFER names
        // the address it wants to commit in the requested-IP option (50) and the
        // chosen server in the server-identifier option (54), echoing the xid. The
        // `dhcp-request-nak` stimulus is the same SELECTING/INIT-REBOOT-style
        // Request shape, except the requested-IP names an address outside the
        // responder's served pool, which the server refuses with a DHCPNAK.
        let requested_ip: Ipv4Addr =
            required_str(plan.requested_ipv4.as_deref(), "requested_ipv4")?.parse()?;
        let server_identifier: Ipv4Addr =
            required_str(plan.server_identifier.as_deref(), "server_identifier")?.parse()?;
        Dhcp::request(client_mac, requested_ip, server_identifier).transaction_id(transaction_id)
    } else if plan.case == "dhcp-renewal-unicast-ack" {
        // RFC 2131 section 4.3.6 (table 4) and section 4.4.5: a client in the
        // RENEWING state unicasts its DHCPREQUEST directly to the server that
        // leased its address. It fills `ciaddr` with the address it is already
        // bound to, leaves the broadcast flag clear, and MUST NOT set the
        // server-identifier option (54) or the requested-IP option (50) — the
        // request is addressed to the one server, not broadcast to all servers.
        // Build the Request shape directly (rather than `Dhcp::request`, which
        // injects options 50/54) and set only the renewal-state fields: the
        // bound `ciaddr` and the parameter request list (option 55) naming the
        // configuration/lease options the unicast Ack confirms. `compile()`
        // fills the BOOTP op/htype/hlen, magic cookie, and lengths; the
        // caller-set ciaddr, client MAC, transaction id, and request list
        // survive untouched.
        let client_ciaddr: Ipv4Addr =
            required_str(plan.client_ciaddr.as_deref(), "client_ciaddr")?.parse()?;
        let requests = required_u8_list(
            plan.parameter_request_list.as_deref(),
            "parameter_request_list",
        )?
        .to_vec();
        Dhcp::new()
            .client_mac(client_mac)
            .message_type(DhcpMessageType::Request)
            .ciaddr(client_ciaddr)
            .transaction_id(transaction_id)
            .parameter_request_list(requests)
    } else if plan.case == "dhcp-inform-ack" {
        // RFC 2131 section 3.4 and section 4.4.3: a client that already has an
        // externally configured IP address uses a DHCPINFORM to ask only for
        // local configuration parameters. It fills `ciaddr` with the address it
        // is already using and names the wanted options in the parameter request
        // list (option 55), but it does NOT request a lease, so it omits the
        // requested-IP option (50). Build the Inform shape directly (rather than
        // `Dhcp::inform`, which injects a default request list) so the stimulus
        // carries exactly the caller's configuration-only request list (no lease
        // options). `compile()` fills the BOOTP op/htype/hlen, magic cookie, and
        // lengths; the caller-set ciaddr, client MAC, transaction id, and request
        // list survive untouched.
        let client_ciaddr: Ipv4Addr =
            required_str(plan.client_ciaddr.as_deref(), "client_ciaddr")?.parse()?;
        let requests = required_u8_list(
            plan.parameter_request_list.as_deref(),
            "parameter_request_list",
        )?
        .to_vec();
        Dhcp::new()
            .client_mac(client_mac)
            .message_type(DhcpMessageType::Inform)
            .ciaddr(client_ciaddr)
            .transaction_id(transaction_id)
            .parameter_request_list(requests)
    } else if plan.case == "dhcp-client-identifier" {
        // RFC 2132 section 9.14: a client may identify itself with the client
        // identifier option (61) in addition to chaddr. The encoded option-61
        // payload (the type octet plus identifier) is carried verbatim in the
        // plan; `compile()` fills the option code/length and the magic cookie.
        let client_identifier = decode_hex(required_str(
            plan.client_identifier_hex.as_deref(),
            "client_identifier_hex",
        )?)?;
        Dhcp::discover(client_mac)
            .transaction_id(transaction_id)
            .client_id(client_identifier)
    } else if plan.case == "dhcp-hostname" {
        // RFC 2132 section 3.14: a client may name itself with the hostname
        // option (12), a string option, in addition to chaddr. The hostname is
        // carried verbatim in the plan; `compile()` fills the option
        // code/length and the magic cookie. The caller-set string survives.
        let hostname = required_str(plan.hostname.as_deref(), "hostname")?;
        Dhcp::discover(client_mac)
            .transaction_id(transaction_id)
            .hostname(hostname)
    } else if plan.case == "dhcp-parameter-request-list" {
        // RFC 2132 section 9.8: the client names the option codes it wants the
        // server to return in the parameter request list (option 55). The plan
        // carries an explicit deterministic list, so build the Discover shape
        // directly (rather than `Dhcp::discover`, which injects a default list)
        // and set exactly the caller's codes. `compile()` fills the BOOTP
        // op/htype/hlen, magic cookie, and lengths; the caller-set request list,
        // client MAC, and transaction id survive untouched.
        let requests = required_u8_list(
            plan.parameter_request_list.as_deref(),
            "parameter_request_list",
        )?
        .to_vec();
        Dhcp::new()
            .client_mac(client_mac)
            .message_type(DhcpMessageType::Discover)
            .transaction_id(transaction_id)
            .parameter_request_list(requests)
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

    // Offered/assigned address (yiaddr). RFC 2131 section 4.3.5: a DHCPINFORM Ack
    // allocates no address, so for the Inform case the plan asserts `yiaddr` is
    // the all-zero address instead of naming a concrete `expected_yiaddr`.
    if plan.expected_yiaddr_zero.unwrap_or(false) {
        let actual_yiaddr = dhcp.your_ip_address_value();
        if actual_yiaddr != Ipv4Addr::UNSPECIFIED {
            mismatches.push(json!({
                "field": "dhcp.yiaddr",
                "expected": Ipv4Addr::UNSPECIFIED.to_string(),
                "actual": actual_yiaddr.to_string(),
            }));
        }
    } else {
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

    // DHCP message (option 56) returned by the responder when the plan names it
    // (RFC 2132 section 9.9). A DHCPNAK MAY carry a text message explaining the
    // refusal; the decoded string option must match the planned message exactly so
    // the option-56 text round-trips through libcrafter encode and decode.
    if let Some(expected_message) = plan.expected_message.as_deref() {
        match dhcp.message_value() {
            Some(actual) if actual == expected_message => {}
            actual => mismatches.push(json!({
                "field": "dhcp.message",
                "expected": expected_message,
                "actual": actual,
            })),
        }
    }

    // Client identifier (option 61) echoed by the responder when the plan names
    // it (RFC 2132 section 9.14; RFC 6842 makes echoing a MUST). Compare the
    // re-encoded decoded identifier against the planned option-61 payload so the
    // typed decode (LegacyHardware / NodeSpecific / Raw) round-trips to the same
    // bytes the stimulus carried.
    if let Some(expected_client_identifier_hex) = plan.expected_client_identifier_hex.as_deref() {
        let expected = decode_hex(expected_client_identifier_hex)?;
        match dhcp.client_identifier_value() {
            Some(Ok(identifier)) => {
                let actual = identifier.encode();
                if actual != expected {
                    mismatches.push(json!({
                        "field": "dhcp.client_identifier",
                        "expected": hex_bytes(&expected),
                        "actual": hex_bytes(&actual),
                    }));
                }
            }
            Some(Err(err)) => mismatches.push(json!({
                "field": "dhcp.client_identifier",
                "expected": hex_bytes(&expected),
                "actual": format!("decode error: {err}"),
            })),
            None => mismatches.push(json!({
                "field": "dhcp.client_identifier",
                "expected": hex_bytes(&expected),
                "actual": Value::Null,
            })),
        }
    }

    // Hostname (option 12, a string option) echoed by the responder when the
    // plan names it (RFC 2132 section 3.14). The decoded string option must
    // match the planned hostname exactly so the string option round-trips
    // through libcrafter encode and decode.
    if let Some(expected_hostname) = plan.expected_hostname.as_deref() {
        match dhcp.host_name_value() {
            Some(actual) if actual == expected_hostname => {}
            actual => mismatches.push(json!({
                "field": "dhcp.host_name",
                "expected": expected_hostname,
                "actual": actual,
            })),
        }
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
    // RFC 2131 section 4.3.5: a DHCPINFORM Ack grants no lease, so it MUST NOT
    // carry an IP-address-lease-time option (51). When the plan asserts this
    // negative invariant, any lease-time option present is a payload mismatch.
    if plan.expected_no_lease_time.unwrap_or(false) {
        if let Some(actual) = dhcp.lease_time_value() {
            mismatches.push(json!({
                "field": "dhcp.lease_time",
                "expected": Value::Null,
                "actual": actual,
            }));
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
        "client_identifier_hex": dhcp
            .client_identifier_value()
            .and_then(|identifier| identifier.ok())
            .map(|identifier| hex_bytes(&identifier.encode())),
        "host_name": dhcp.host_name_value(),
        "message": dhcp.message_value(),
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
        let subnet_mask: Ipv4Addr = plan
            .expected_subnet_mask
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let router: Ipv4Addr = plan
            .expected_router_ipv4
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
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
            .subnet_mask(
                plan.expected_subnet_mask
                    .as_deref()
                    .unwrap()
                    .parse()
                    .unwrap(),
            )
            .router(vec![plan
                .expected_router_ipv4
                .as_deref()
                .unwrap()
                .parse()
                .unwrap()]);
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

    fn client_identifier_plan() -> ProbePlan {
        // RFC 4361 node-specific client identifier: type 0xff, a 4-octet IAID
        // (11223344), then a DUID-LL (type 3, hardware type 1, MAC 00:00:5e:00:53:99).
        let client_identifier_hex = "ff112233440003000100005e005399".to_string();
        let mut plan = base_plan("dhcp-client-identifier");
        plan.source_ipv4 = Some("10.64.0.10".to_string());
        plan.destination_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.64.0.10".to_string());
        plan.source_port = Some(DHCP_CLIENT_PORT);
        plan.destination_port = Some(DHCP_SERVER_PORT);
        plan.client_mac = Some("00:00:5e:00:53:2a".to_string());
        plan.client_identifier_hex = Some(client_identifier_hex.clone());
        plan.transaction_id = Some(0x3903_f326);
        plan.expected_message_type_value = Some(DHCP_OFFER);
        plan.expected_yiaddr = Some("198.51.100.42".to_string());
        plan.expected_server_identifier = Some("10.64.0.20".to_string());
        plan.expected_client_identifier_hex = Some(client_identifier_hex);
        plan.expected_lease_time = Some(3600);
        plan.expected_renewal_time = Some(1800);
        plan.expected_rebinding_time = Some(3150);
        plan
    }

    /// Build the canonical Offer the controlled responder would unicast back,
    /// echoing the client identifier (option 61) the Discover carried.
    fn offer_with_client_identifier_packet(plan: &ProbePlan) -> Packet {
        let client_mac: MacAddr = plan.client_mac.as_deref().unwrap().parse().unwrap();
        let server_identifier: Ipv4Addr = plan
            .expected_server_identifier
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let offered: Ipv4Addr = plan.expected_yiaddr.as_deref().unwrap().parse().unwrap();
        let client_identifier =
            decode_hex(plan.expected_client_identifier_hex.as_deref().unwrap()).unwrap();
        let dhcp = Dhcp::offer(client_mac, offered, server_identifier)
            .transaction_id(plan.transaction_id.unwrap())
            .lease_time(plan.expected_lease_time.unwrap())
            .renewal_time(plan.expected_renewal_time.unwrap())
            .rebinding_time(plan.expected_rebinding_time.unwrap())
            .subnet_mask("255.255.255.0".parse().unwrap())
            .client_id(client_identifier);
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
    fn dhcp_discover_compiles_with_client_identifier_option() {
        let plan = client_identifier_plan();
        let packet = dhcp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap().as_bytes().to_vec();

        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let dhcp = decoded.layer::<Dhcp>().unwrap();

        // Client 68 -> server 67; a Discover carrying chaddr plus option 61.
        assert_eq!(udp.source_port_value(), DHCP_CLIENT_PORT);
        assert_eq!(udp.destination_port_value(), DHCP_SERVER_PORT);
        assert_eq!(dhcp.op_value(), BOOTP_REQUEST);
        assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Discover));
        assert_eq!(dhcp.transaction_id_value(), 0x3903_f326);
        // The decoded client identifier (option 61) re-encodes to the bytes the
        // plan carried.
        let expected = decode_hex(plan.expected_client_identifier_hex.as_deref().unwrap()).unwrap();
        let actual = dhcp.client_identifier_value().unwrap().unwrap().encode();
        assert_eq!(actual, expected);
        assert_eq!(dhcp.magic_cookie_value(), DHCP_MAGIC_COOKIE);
    }

    #[test]
    fn dhcp_client_identifier_requires_client_identifier_hex() {
        let mut plan = client_identifier_plan();
        plan.client_identifier_hex = None;
        assert!(dhcp_packet(&plan).is_err());
    }

    #[test]
    fn matching_offer_with_client_identifier_passes_validation() {
        let plan = client_identifier_plan();
        let bytes = offer_with_client_identifier_packet(&plan)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(
            matches!(validation, CandidateValidation::Passed(_)),
            "expected Passed, got {validation:?}"
        );
    }

    #[test]
    fn offer_missing_client_identifier_is_wrong_payload() {
        let plan = client_identifier_plan();
        // An otherwise-correct Offer that omits the client identifier (option 61)
        // reaches the right peer but fails the contract.
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
    fn offer_with_wrong_client_identifier_is_wrong_payload() {
        let mut plan = client_identifier_plan();
        let bytes = offer_with_client_identifier_packet(&plan)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        // The responder echoed the Discover's identifier, but the plan now expects
        // a different one: a payload mismatch on option 61.
        plan.expected_client_identifier_hex = Some("ff99887766".to_string());
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(matches!(validation, CandidateValidation::WrongPayload(_)));
    }

    fn hostname_plan() -> ProbePlan {
        let hostname = "probe-qemu-1023-0".to_string();
        let mut plan = base_plan("dhcp-hostname");
        plan.source_ipv4 = Some("10.64.0.10".to_string());
        plan.destination_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.64.0.10".to_string());
        plan.source_port = Some(DHCP_CLIENT_PORT);
        plan.destination_port = Some(DHCP_SERVER_PORT);
        plan.client_mac = Some("00:00:5e:00:53:2a".to_string());
        plan.hostname = Some(hostname.clone());
        plan.transaction_id = Some(0x3903_f326);
        plan.expected_message_type_value = Some(DHCP_OFFER);
        plan.expected_yiaddr = Some("198.51.100.42".to_string());
        plan.expected_server_identifier = Some("10.64.0.20".to_string());
        plan.expected_hostname = Some(hostname);
        plan.expected_lease_time = Some(3600);
        plan.expected_renewal_time = Some(1800);
        plan.expected_rebinding_time = Some(3150);
        plan
    }

    /// Build the canonical Offer the controlled responder would unicast back,
    /// echoing the hostname (option 12) the Discover carried.
    fn offer_with_hostname_packet(plan: &ProbePlan) -> Packet {
        let client_mac: MacAddr = plan.client_mac.as_deref().unwrap().parse().unwrap();
        let server_identifier: Ipv4Addr = plan
            .expected_server_identifier
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let offered: Ipv4Addr = plan.expected_yiaddr.as_deref().unwrap().parse().unwrap();
        let hostname = plan.expected_hostname.as_deref().unwrap().to_string();
        let dhcp = Dhcp::offer(client_mac, offered, server_identifier)
            .transaction_id(plan.transaction_id.unwrap())
            .lease_time(plan.expected_lease_time.unwrap())
            .renewal_time(plan.expected_renewal_time.unwrap())
            .rebinding_time(plan.expected_rebinding_time.unwrap())
            .subnet_mask("255.255.255.0".parse().unwrap())
            .hostname(hostname);
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
    fn dhcp_discover_compiles_with_hostname_option() {
        let plan = hostname_plan();
        let packet = dhcp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap().as_bytes().to_vec();

        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let dhcp = decoded.layer::<Dhcp>().unwrap();

        // Client 68 -> server 67; a Discover carrying chaddr plus option 12.
        assert_eq!(udp.source_port_value(), DHCP_CLIENT_PORT);
        assert_eq!(udp.destination_port_value(), DHCP_SERVER_PORT);
        assert_eq!(dhcp.op_value(), BOOTP_REQUEST);
        assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Discover));
        assert_eq!(dhcp.transaction_id_value(), 0x3903_f326);
        // The decoded hostname (option 12) round-trips to the planned string.
        assert_eq!(dhcp.host_name_value(), plan.hostname.as_deref());
        assert_eq!(dhcp.magic_cookie_value(), DHCP_MAGIC_COOKIE);
    }

    #[test]
    fn dhcp_hostname_requires_hostname() {
        let mut plan = hostname_plan();
        plan.hostname = None;
        assert!(dhcp_packet(&plan).is_err());
    }

    #[test]
    fn matching_offer_with_hostname_passes_validation() {
        let plan = hostname_plan();
        let bytes = offer_with_hostname_packet(&plan)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(
            matches!(validation, CandidateValidation::Passed(_)),
            "expected Passed, got {validation:?}"
        );
    }

    #[test]
    fn offer_missing_hostname_is_wrong_payload() {
        let plan = hostname_plan();
        // An otherwise-correct Offer that omits the hostname (option 12) reaches
        // the right peer but fails the contract.
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
    fn offer_with_wrong_hostname_is_wrong_payload() {
        let mut plan = hostname_plan();
        let bytes = offer_with_hostname_packet(&plan)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        // The responder echoed the Discover's hostname, but the plan now expects
        // a different one: a payload mismatch on option 12.
        plan.expected_hostname = Some("other-host".to_string());
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(matches!(validation, CandidateValidation::WrongPayload(_)));
    }

    fn lease_time_plan() -> ProbePlan {
        // RFC 2132: the responder returns the IP address lease time (option 51),
        // the renewal T1 time value (option 58), and the rebinding T2 time value
        // (option 59) as 32-bit second counts; T1 < T2 < lease.
        let mut plan = base_plan("dhcp-lease-time");
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

    /// Build the canonical Offer the controlled responder would unicast back,
    /// carrying the three DHCP timing options (lease 51, renewal 58, rebinding 59).
    fn offer_with_timing_options_packet(plan: &ProbePlan) -> Packet {
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

    #[test]
    fn offer_timing_options_decode_to_planned_second_counts() {
        let plan = lease_time_plan();
        let bytes = offer_with_timing_options_packet(&plan)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let dhcp = decoded.layer::<Dhcp>().unwrap();
        // Each timing option decodes to the planned 32-bit second count.
        assert_eq!(dhcp.lease_time_value(), Some(3600));
        assert_eq!(dhcp.renewal_time_value(), Some(1800));
        assert_eq!(dhcp.rebinding_time_value(), Some(3150));
    }

    #[test]
    fn matching_offer_with_timing_options_passes_validation() {
        let plan = lease_time_plan();
        let bytes = offer_with_timing_options_packet(&plan)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(
            matches!(validation, CandidateValidation::Passed(_)),
            "expected Passed, got {validation:?}"
        );
    }

    #[test]
    fn offer_with_wrong_renewal_time_is_wrong_payload() {
        let mut plan = lease_time_plan();
        let bytes = offer_with_timing_options_packet(&plan)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        // The responder returned T1 = 1800, but the plan now expects a different
        // renewal time: a payload mismatch on option 58.
        plan.expected_renewal_time = Some(900);
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(matches!(validation, CandidateValidation::WrongPayload(_)));
    }

    #[test]
    fn offer_missing_rebinding_time_is_wrong_payload() {
        let plan = lease_time_plan();
        // An otherwise-correct Offer that omits the rebinding (T2) option (59) the
        // plan requires reaches the right peer but fails the contract.
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
            .subnet_mask("255.255.255.0".parse().unwrap());
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

    fn parameter_request_list_plan() -> ProbePlan {
        // RFC 2132 section 9.8 parameter request list (option 55): subnet mask (1),
        // router (3), DNS server (6), lease time (51), renewal T1 (58), and
        // rebinding T2 (59). The responder returns those requested options and the
        // validator confirms the corresponding values.
        let mut plan = base_plan("dhcp-parameter-request-list");
        plan.source_ipv4 = Some("10.64.0.10".to_string());
        plan.destination_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.64.0.10".to_string());
        plan.source_port = Some(DHCP_CLIENT_PORT);
        plan.destination_port = Some(DHCP_SERVER_PORT);
        plan.client_mac = Some("00:00:5e:00:53:2a".to_string());
        plan.parameter_request_list = Some(vec![1, 3, 6, 51, 58, 59]);
        plan.transaction_id = Some(0x3903_f326);
        plan.expected_message_type_value = Some(DHCP_OFFER);
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

    /// Build the canonical Offer the controlled responder would unicast back,
    /// returning exactly the options the parameter request list (option 55) named.
    fn offer_with_requested_options_packet(plan: &ProbePlan) -> Packet {
        let client_mac: MacAddr = plan.client_mac.as_deref().unwrap().parse().unwrap();
        let server_identifier: Ipv4Addr = plan
            .expected_server_identifier
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let offered: Ipv4Addr = plan.expected_yiaddr.as_deref().unwrap().parse().unwrap();
        let subnet_mask: Ipv4Addr = plan
            .expected_subnet_mask
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let router: Ipv4Addr = plan
            .expected_router_ipv4
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let dns: Ipv4Addr = plan.expected_dns_ipv4.as_deref().unwrap().parse().unwrap();
        let dhcp = Dhcp::offer(client_mac, offered, server_identifier)
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
    fn dhcp_discover_compiles_with_parameter_request_list() {
        let plan = parameter_request_list_plan();
        let packet = dhcp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap().as_bytes().to_vec();

        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let dhcp = decoded.layer::<Dhcp>().unwrap();

        // Client 68 -> server 67; a Discover carrying chaddr plus option 55.
        assert_eq!(udp.source_port_value(), DHCP_CLIENT_PORT);
        assert_eq!(udp.destination_port_value(), DHCP_SERVER_PORT);
        assert_eq!(dhcp.op_value(), BOOTP_REQUEST);
        assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Discover));
        assert_eq!(dhcp.transaction_id_value(), 0x3903_f326);
        // The decoded parameter request list (option 55) is exactly the codes the
        // plan named; the default list the discover builder injects is overridden.
        assert_eq!(
            dhcp.parameter_request_list_value(),
            Some([1u8, 3, 6, 51, 58, 59].as_slice())
        );
        assert_eq!(dhcp.magic_cookie_value(), DHCP_MAGIC_COOKIE);
    }

    #[test]
    fn dhcp_parameter_request_list_requires_the_list() {
        let mut plan = parameter_request_list_plan();
        plan.parameter_request_list = None;
        assert!(dhcp_packet(&plan).is_err());
    }

    #[test]
    fn matching_offer_with_requested_options_passes_validation() {
        let plan = parameter_request_list_plan();
        let bytes = offer_with_requested_options_packet(&plan)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(
            matches!(validation, CandidateValidation::Passed(_)),
            "expected Passed, got {validation:?}"
        );
    }

    #[test]
    fn offer_missing_a_requested_option_is_wrong_payload() {
        let plan = parameter_request_list_plan();
        // An otherwise-correct Offer that omits the requested DNS server option (6)
        // reaches the right peer but fails the contract.
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
            .subnet_mask(
                plan.expected_subnet_mask
                    .as_deref()
                    .unwrap()
                    .parse()
                    .unwrap(),
            )
            .router(vec![plan
                .expected_router_ipv4
                .as_deref()
                .unwrap()
                .parse()
                .unwrap()]);
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

    fn renewal_plan() -> ProbePlan {
        // RFC 2131 RENEWING state: the client is already bound to this address and
        // unicasts its Request directly to the leasing server. It sets ciaddr,
        // leaves the broadcast flag clear, and omits the requested-IP (50) and
        // server-identifier (54) options. The server renews the same address.
        let mut plan = base_plan("dhcp-renewal-unicast-ack");
        plan.source_ipv4 = Some("10.64.0.10".to_string());
        plan.destination_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.64.0.10".to_string());
        plan.source_port = Some(DHCP_CLIENT_PORT);
        plan.destination_port = Some(DHCP_SERVER_PORT);
        plan.client_mac = Some("00:00:5e:00:53:2a".to_string());
        plan.transaction_id = Some(0x3903_f326);
        plan.client_ciaddr = Some("198.51.100.42".to_string());
        plan.parameter_request_list = Some(vec![1, 3, 6, 51, 58, 59]);
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

    #[test]
    fn dhcp_renewal_compiles_with_ciaddr_and_no_request_or_server_options() {
        let plan = renewal_plan();
        let packet = dhcp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap().as_bytes().to_vec();

        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let dhcp = decoded.layer::<Dhcp>().unwrap();

        // Client 68 -> server 67; a RENEWING-state Request.
        assert_eq!(udp.source_port_value(), DHCP_CLIENT_PORT);
        assert_eq!(udp.destination_port_value(), DHCP_SERVER_PORT);
        assert_eq!(dhcp.op_value(), BOOTP_REQUEST);
        assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Request));
        assert_eq!(dhcp.transaction_id_value(), 0x3903_f326);
        // The bound address is carried in ciaddr.
        assert_eq!(
            dhcp.client_ip_address_value(),
            "198.51.100.42".parse::<Ipv4Addr>().unwrap()
        );
        // RFC 2131 section 4.3.6: RENEWING omits the requested-IP (50) and
        // server-identifier (54) options; the request is addressed to the one
        // server directly, not broadcast to all servers.
        assert_eq!(dhcp.requested_ip_address_value(), None);
        assert_eq!(dhcp.server_identifier_value(), None);
        // The broadcast flag stays clear (unicast renewal).
        assert_eq!(dhcp.flags_value() & 0x8000, 0);
        // The parameter request list (option 55) names the options the Ack confirms.
        assert_eq!(
            dhcp.parameter_request_list_value(),
            Some([1u8, 3, 6, 51, 58, 59].as_slice())
        );
        assert_eq!(dhcp.magic_cookie_value(), DHCP_MAGIC_COOKIE);
    }

    #[test]
    fn dhcp_renewal_requires_client_ciaddr() {
        let mut plan = renewal_plan();
        plan.client_ciaddr = None;
        assert!(dhcp_packet(&plan).is_err());
    }

    #[test]
    fn matching_renewal_ack_passes_validation() {
        let plan = renewal_plan();
        // The server renews the same address with a unicast Ack; reuse the
        // request-ack Ack builder shape (yiaddr == bound address, opt 54, lease
        // and configuration options).
        let bytes = ack_packet(&plan).compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(
            matches!(validation, CandidateValidation::Passed(_)),
            "expected Passed, got {validation:?}"
        );
    }

    #[test]
    fn renewal_ack_with_wrong_yiaddr_is_wrong_payload() {
        let mut plan = renewal_plan();
        let bytes = ack_packet(&plan).compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        // The server renewed 198.51.100.42, but the plan now expects a different
        // address: a payload mismatch on the renewed yiaddr.
        plan.expected_yiaddr = Some("198.51.100.99".to_string());
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(matches!(validation, CandidateValidation::WrongPayload(_)));
    }

    fn inform_plan() -> ProbePlan {
        // RFC 2131 section 3.4: a client that already has an externally configured
        // address sends a DHCPINFORM carrying its address in ciaddr and a
        // configuration-only parameter request list (subnet 1, router 3, DNS 6).
        // The server replies with an Ack that returns those options but allocates
        // no address (yiaddr 0.0.0.0) and grants no lease (no option 51).
        let mut plan = base_plan("dhcp-inform-ack");
        plan.source_ipv4 = Some("10.64.0.10".to_string());
        plan.destination_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.64.0.10".to_string());
        plan.source_port = Some(DHCP_CLIENT_PORT);
        plan.destination_port = Some(DHCP_SERVER_PORT);
        plan.client_mac = Some("00:00:5e:00:53:2a".to_string());
        plan.transaction_id = Some(0x3903_f326);
        plan.client_ciaddr = Some("198.51.100.42".to_string());
        plan.parameter_request_list = Some(vec![1, 3, 6]);
        plan.expected_message_type_value = Some(DHCP_ACK);
        plan.expected_yiaddr_zero = Some(true);
        plan.expected_no_lease_time = Some(true);
        plan.expected_server_identifier = Some("10.64.0.20".to_string());
        plan.expected_subnet_mask = Some("255.255.255.0".to_string());
        plan.expected_router_ipv4 = Some("10.64.0.1".to_string());
        plan.expected_dns_ipv4 = Some("198.51.100.53".to_string());
        plan
    }

    /// Build the canonical Inform Ack the controlled responder would unicast back:
    /// the configuration options (subnet 1, router 3, DNS 6) and the server
    /// identifier (54), but no allocated address (yiaddr 0.0.0.0) and no lease
    /// (no option 51) — RFC 2131 section 4.3.5.
    fn inform_ack_packet(plan: &ProbePlan) -> Packet {
        let client_mac: MacAddr = plan.client_mac.as_deref().unwrap().parse().unwrap();
        let server_identifier: Ipv4Addr = plan
            .expected_server_identifier
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let subnet_mask: Ipv4Addr = plan
            .expected_subnet_mask
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let router: Ipv4Addr = plan
            .expected_router_ipv4
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let dns: Ipv4Addr = plan.expected_dns_ipv4.as_deref().unwrap().parse().unwrap();
        // An Ack in response to an Inform commits no binding: yiaddr is left as the
        // all-zero address (Dhcp::ack with the unspecified address) and no lease
        // timing options are set.
        let dhcp = Dhcp::ack(client_mac, Ipv4Addr::UNSPECIFIED, server_identifier)
            .transaction_id(plan.transaction_id.unwrap())
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
    fn dhcp_inform_compiles_with_ciaddr_and_config_only_request_list() {
        let plan = inform_plan();
        let packet = dhcp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap().as_bytes().to_vec();

        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let dhcp = decoded.layer::<Dhcp>().unwrap();

        // Client 68 -> server 67; a BOOTP request carrying an Inform (type 8).
        assert_eq!(udp.source_port_value(), DHCP_CLIENT_PORT);
        assert_eq!(udp.destination_port_value(), DHCP_SERVER_PORT);
        assert_eq!(dhcp.op_value(), BOOTP_REQUEST);
        assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Inform));
        assert_eq!(dhcp.transaction_id_value(), 0x3903_f326);
        // The externally-configured address is carried in ciaddr.
        assert_eq!(
            dhcp.client_ip_address_value(),
            "198.51.100.42".parse::<Ipv4Addr>().unwrap()
        );
        // RFC 2131 section 3.4: an Inform asks for no lease, so it omits the
        // requested-IP option (50); the request list names configuration options
        // only (no lease options 51/58/59).
        assert_eq!(dhcp.requested_ip_address_value(), None);
        assert_eq!(
            dhcp.parameter_request_list_value(),
            Some([1u8, 3, 6].as_slice())
        );
        assert_eq!(dhcp.magic_cookie_value(), DHCP_MAGIC_COOKIE);
    }

    #[test]
    fn dhcp_inform_requires_client_ciaddr() {
        let mut plan = inform_plan();
        plan.client_ciaddr = None;
        assert!(dhcp_packet(&plan).is_err());
    }

    #[test]
    fn dhcp_inform_requires_parameter_request_list() {
        let mut plan = inform_plan();
        plan.parameter_request_list = None;
        assert!(dhcp_packet(&plan).is_err());
    }

    #[test]
    fn matching_inform_ack_passes_validation() {
        let plan = inform_plan();
        let bytes = inform_ack_packet(&plan)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        // The Inform Ack carries config options, no allocated address, and no lease.
        let dhcp = decoded.layer::<Dhcp>().unwrap();
        assert_eq!(dhcp.your_ip_address_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(dhcp.lease_time_value(), None);
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(
            matches!(validation, CandidateValidation::Passed(_)),
            "expected Passed, got {validation:?}"
        );
    }

    #[test]
    fn inform_ack_that_allocates_an_address_is_wrong_payload() {
        let plan = inform_plan();
        // A server that wrongly allocates an address (non-zero yiaddr) in response
        // to an Inform reaches the right peer but violates RFC 2131 section 4.3.5.
        let client_mac: MacAddr = plan.client_mac.as_deref().unwrap().parse().unwrap();
        let server_identifier: Ipv4Addr = plan
            .expected_server_identifier
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let dhcp = Dhcp::ack(
            client_mac,
            "198.51.100.42".parse().unwrap(),
            server_identifier,
        )
        .transaction_id(plan.transaction_id.unwrap())
        .subnet_mask("255.255.255.0".parse().unwrap())
        .router(vec!["10.64.0.1".parse().unwrap()])
        .domain_name_server(vec!["198.51.100.53".parse().unwrap()]);
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
    fn inform_ack_with_a_lease_time_is_wrong_payload() {
        let plan = inform_plan();
        // A server that wrongly grants a lease (option 51) in response to an Inform
        // reaches the right peer but violates RFC 2131 section 4.3.5.
        let client_mac: MacAddr = plan.client_mac.as_deref().unwrap().parse().unwrap();
        let server_identifier: Ipv4Addr = plan
            .expected_server_identifier
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let dhcp = Dhcp::ack(client_mac, Ipv4Addr::UNSPECIFIED, server_identifier)
            .transaction_id(plan.transaction_id.unwrap())
            .lease_time(3600)
            .subnet_mask("255.255.255.0".parse().unwrap())
            .router(vec!["10.64.0.1".parse().unwrap()])
            .domain_name_server(vec!["198.51.100.53".parse().unwrap()]);
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
    fn inform_ack_missing_a_config_option_is_wrong_payload() {
        let plan = inform_plan();
        // An Inform Ack that omits the requested DNS server option (6) reaches the
        // right peer but fails the configuration contract.
        let client_mac: MacAddr = plan.client_mac.as_deref().unwrap().parse().unwrap();
        let server_identifier: Ipv4Addr = plan
            .expected_server_identifier
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let dhcp = Dhcp::ack(client_mac, Ipv4Addr::UNSPECIFIED, server_identifier)
            .transaction_id(plan.transaction_id.unwrap())
            .subnet_mask("255.255.255.0".parse().unwrap())
            .router(vec!["10.64.0.1".parse().unwrap()]);
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

    fn nak_plan() -> ProbePlan {
        // RFC 2131 section 4.3.2: the client asks (option 50) for an address the
        // server cannot grant (here a 192.0.2.0/24 address outside the served
        // 198.51.100.0/24 pool) and names the chosen server (option 54). The server
        // refuses with a DHCPNAK (type 6) that carries no allocation (yiaddr
        // 0.0.0.0), no lease (no option 51), the server identifier (54), and an
        // optional message (option 56) per RFC 2132 section 9.9.
        let mut plan = base_plan("dhcp-request-nak");
        plan.source_ipv4 = Some("10.64.0.10".to_string());
        plan.destination_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.64.0.10".to_string());
        plan.source_port = Some(DHCP_CLIENT_PORT);
        plan.destination_port = Some(DHCP_SERVER_PORT);
        plan.client_mac = Some("00:00:5e:00:53:2a".to_string());
        plan.transaction_id = Some(0x3903_f326);
        plan.requested_ipv4 = Some("192.0.2.42".to_string());
        plan.server_identifier = Some("10.64.0.20".to_string());
        plan.expected_message_type_value = Some(DHCP_NAK);
        plan.expected_yiaddr_zero = Some(true);
        plan.expected_no_lease_time = Some(true);
        plan.expected_server_identifier = Some("10.64.0.20".to_string());
        plan.expected_message =
            Some("requested address 192.0.2.42 is not on this network".to_string());
        plan
    }

    /// Build the canonical Nak the controlled responder would unicast back: a
    /// BOOTP reply refusing the request, with no allocated address (yiaddr
    /// 0.0.0.0), no lease, the server identifier (54), and the message (56).
    fn nak_packet(plan: &ProbePlan) -> Packet {
        let client_mac: MacAddr = plan.client_mac.as_deref().unwrap().parse().unwrap();
        let server_identifier: Ipv4Addr = plan
            .expected_server_identifier
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let dhcp = Dhcp::nak(client_mac, server_identifier)
            .transaction_id(plan.transaction_id.unwrap())
            .message(plan.expected_message.as_deref().unwrap().to_string());
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
    fn dhcp_request_nak_stimulus_compiles_with_invalid_requested_ip() {
        let plan = nak_plan();
        let packet = dhcp_packet(&plan).unwrap();
        let bytes = packet.compile().unwrap().as_bytes().to_vec();

        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let dhcp = decoded.layer::<Dhcp>().unwrap();

        // Client 68 -> server 67; a SELECTING-style Request carrying the invalid
        // requested IP (option 50) and the chosen server (option 54).
        assert_eq!(udp.source_port_value(), DHCP_CLIENT_PORT);
        assert_eq!(udp.destination_port_value(), DHCP_SERVER_PORT);
        assert_eq!(dhcp.op_value(), BOOTP_REQUEST);
        assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Request));
        assert_eq!(dhcp.transaction_id_value(), 0x3903_f326);
        assert_eq!(
            dhcp.requested_ip_address_value(),
            Some("192.0.2.42".parse().unwrap())
        );
        assert_eq!(
            dhcp.server_identifier_value(),
            Some("10.64.0.20".parse().unwrap())
        );
        assert_eq!(dhcp.magic_cookie_value(), DHCP_MAGIC_COOKIE);
    }

    #[test]
    fn matching_nak_passes_validation() {
        let plan = nak_plan();
        let bytes = nak_packet(&plan).compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        // The Nak refuses the request: message type 6, no allocation, no lease, the
        // server identifier (54), and the message (56) decode as planned.
        let dhcp = decoded.layer::<Dhcp>().unwrap();
        assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Nak));
        assert_eq!(dhcp.your_ip_address_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(dhcp.lease_time_value(), None);
        assert_eq!(
            dhcp.message_value(),
            Some("requested address 192.0.2.42 is not on this network")
        );
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(
            matches!(validation, CandidateValidation::Passed(_)),
            "expected Passed, got {validation:?}"
        );
    }

    #[test]
    fn ack_instead_of_nak_is_wrong_payload() {
        let plan = nak_plan();
        // A server that wrongly grants the (invalid) request with an Ack reaches the
        // right peer but fails the Nak contract (wrong message type, allocates an
        // address, grants a lease).
        let client_mac: MacAddr = plan.client_mac.as_deref().unwrap().parse().unwrap();
        let server_identifier: Ipv4Addr = plan
            .expected_server_identifier
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let dhcp = Dhcp::ack(client_mac, "192.0.2.42".parse().unwrap(), server_identifier)
            .transaction_id(plan.transaction_id.unwrap())
            .lease_time(3600);
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
    fn nak_missing_message_is_wrong_payload() {
        let plan = nak_plan();
        // A Nak that omits the message option (56) the plan requires reaches the
        // right peer but fails the contract.
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
    fn nak_with_wrong_message_is_wrong_payload() {
        let mut plan = nak_plan();
        let bytes = nak_packet(&plan).compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        // The responder returned its message, but the plan now expects different
        // text: a payload mismatch on option 56.
        plan.expected_message = Some("some other reason".to_string());
        let validation = validate_dhcp_candidate(&plan, &decoded, &bytes).unwrap();
        assert!(matches!(validation, CandidateValidation::WrongPayload(_)));
    }

    #[test]
    fn nak_that_allocates_an_address_is_wrong_payload() {
        let plan = nak_plan();
        // RFC 2131 section 4.3.2: a DHCPNAK allocates no address. A Nak with a
        // non-zero yiaddr reaches the right peer but violates the invariant.
        let client_mac: MacAddr = plan.client_mac.as_deref().unwrap().parse().unwrap();
        let server_identifier: Ipv4Addr = plan
            .expected_server_identifier
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        let dhcp = Dhcp::nak(client_mac, server_identifier)
            .transaction_id(plan.transaction_id.unwrap())
            .yiaddr("192.0.2.42".parse().unwrap())
            .message(plan.expected_message.as_deref().unwrap().to_string());
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

    /// Build one `DhcpSend` for a `dhcp-rapid-repeat` plan with a distinct
    /// transaction id, client identity (chaddr), and offered address.
    fn rapid_repeat_send(
        index: usize,
        transaction_id: u32,
        client_mac: &str,
        offered: &str,
    ) -> DhcpSend {
        DhcpSend {
            index: Some(index),
            source_ipv4: Some("10.64.0.10".to_string()),
            destination_ipv4: Some("10.64.0.20".to_string()),
            expected_reply_source_ipv4: Some("10.64.0.20".to_string()),
            expected_reply_destination_ipv4: Some("10.64.0.10".to_string()),
            source_port: Some(DHCP_CLIENT_PORT),
            destination_port: Some(DHCP_SERVER_PORT),
            client_mac: Some(client_mac.to_string()),
            transaction_id: Some(transaction_id),
            expected_message_type_value: Some(DHCP_OFFER),
            expected_yiaddr: Some(offered.to_string()),
            expected_server_identifier: Some("10.64.0.20".to_string()),
            expected_subnet_mask: Some("255.255.255.0".to_string()),
            expected_router_ipv4: None,
            expected_lease_time: Some(3600),
            expected_renewal_time: Some(1800),
            expected_rebinding_time: Some(3150),
            capture_filter: Some(
                "udp and src host 10.64.0.20 and dst host 10.64.0.10 \
                 and src port 67 and dst port 68"
                    .to_string(),
            ),
        }
    }

    /// A `dhcp-rapid-repeat` plan carrying two Discover->Offer sends with
    /// distinct xids, client identities, and offered addresses.
    fn rapid_repeat_plan() -> ProbePlan {
        let sends = vec![
            rapid_repeat_send(0, 0x3903_f326, "00:00:5e:00:53:2a", "198.51.100.42"),
            rapid_repeat_send(1, 0x7c4e_1b09, "00:00:5e:00:53:7f", "198.51.100.77"),
        ];
        let mut plan = base_plan("dhcp-rapid-repeat");
        // Top-level fields mirror the first send so single-send consumers keep
        // working; the dispatch detects `dhcp_sends` and drives both sends.
        plan.source_ipv4 = Some("10.64.0.10".to_string());
        plan.destination_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_source_ipv4 = Some("10.64.0.20".to_string());
        plan.expected_reply_destination_ipv4 = Some("10.64.0.10".to_string());
        plan.source_port = Some(DHCP_CLIENT_PORT);
        plan.destination_port = Some(DHCP_SERVER_PORT);
        plan.client_mac = sends[0].client_mac.clone();
        plan.transaction_id = sends[0].transaction_id;
        plan.expected_message_type_value = Some(DHCP_OFFER);
        plan.expected_yiaddr = sends[0].expected_yiaddr.clone();
        plan.expected_server_identifier = Some("10.64.0.20".to_string());
        plan.expected_subnet_mask = Some("255.255.255.0".to_string());
        plan.expected_lease_time = Some(3600);
        plan.expected_renewal_time = Some(1800);
        plan.expected_rebinding_time = Some(3150);
        plan.send_count = Some(sends.len());
        plan.dhcp_sends = Some(sends);
        plan
    }

    #[test]
    fn rapid_repeat_sends_build_distinct_discovers() {
        let plan = rapid_repeat_plan();
        let sends = plan.dhcp_sends.clone().unwrap();
        assert_eq!(sends.len(), 2);

        let first = send_as_plan(&plan, &sends[0]);
        let second = send_as_plan(&plan, &sends[1]);
        // The two derived single-send plans carry distinct identities (the case
        // point: two independently identifiable Discovers).
        assert_ne!(first.transaction_id, second.transaction_id);
        assert_ne!(first.client_mac, second.client_mac);
        assert_ne!(first.expected_yiaddr, second.expected_yiaddr);
        // Each derived plan compiles into a real Discover with its own xid/chaddr.
        let first_packet = dhcp_packet(&first).unwrap();
        let second_packet = dhcp_packet(&second).unwrap();
        let first_dhcp = first_packet.layer::<Dhcp>().unwrap();
        let second_dhcp = second_packet.layer::<Dhcp>().unwrap();
        assert_eq!(first_dhcp.transaction_id_value(), 0x3903_f326);
        assert_eq!(second_dhcp.transaction_id_value(), 0x7c4e_1b09);
        assert_eq!(
            first_dhcp.message_type_value().map(DhcpMessageType::code),
            Some(1)
        );
        assert_eq!(
            second_dhcp.message_type_value().map(DhcpMessageType::code),
            Some(1)
        );
    }

    #[test]
    fn rapid_repeat_each_offer_validates_against_its_own_send() {
        let plan = rapid_repeat_plan();
        let sends = plan.dhcp_sends.clone().unwrap();
        for send in &sends {
            let send_plan = send_as_plan(&plan, send);
            // The responder's Offer for this Discover, keyed to its xid/chaddr.
            let bytes = offer_packet(&send_plan)
                .compile()
                .unwrap()
                .as_bytes()
                .to_vec();
            let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
            let validation = validate_dhcp_candidate(&send_plan, &decoded, &bytes).unwrap();
            assert!(
                matches!(validation, CandidateValidation::Passed(_)),
                "expected Passed for send {:?}, got {validation:?}",
                send.index
            );
        }
    }

    #[test]
    fn rapid_repeat_offer_for_wrong_send_is_wrong_payload() {
        let plan = rapid_repeat_plan();
        let sends = plan.dhcp_sends.clone().unwrap();
        // The second send's Offer (its xid/chaddr/yiaddr) must NOT validate
        // against the first send's contract: the two Offers are never confused.
        let second_plan = send_as_plan(&plan, &sends[1]);
        let bytes = offer_packet(&second_plan)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let decoded = Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, &bytes).unwrap();
        let first_plan = send_as_plan(&plan, &sends[0]);
        let validation = validate_dhcp_candidate(&first_plan, &decoded, &bytes).unwrap();
        assert!(
            matches!(validation, CandidateValidation::WrongPayload(_)),
            "expected WrongPayload matching the second Offer against the first send, got {validation:?}"
        );
    }
}
