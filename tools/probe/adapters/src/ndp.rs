//! NDP (IPv6 Neighbor Discovery, RFC 4861) behavioral probe cases.
//!
//! NDP is the IPv6 analog of ARP: `ndp-neighbor-solicitation` is the baseline
//! check (the direct analog of ARP who-has/is-at). The stimulus builds a
//! Neighbor Solicitation (ICMPv6 type 135) resolving the target endpoint's
//! link-local address, carrying a Source Link-Layer Address option and addressed
//! to the target's solicited-node multicast group (RFC 4291 section 2.7.1). The
//! target kernel auto-answers a solicited Neighbor Advertisement (type 136, the
//! is-at analog) with the R/S/O flags and a Target Link-Layer Address option.
//! `ndp-router-solicitation` solicits a Router Advertisement (type 134, needs an
//! RA-emitting router target), and `ndp-duplicate-address-detection` sends a
//! DAD probe from the unspecified source (`::`) and validates the defending
//! Neighbor Advertisement.
//!
//! Unlike ARP (which rides Ethernet directly), NDP rides ICMPv6 over IPv6 (next
//! header 58): the stimulus builds an `Ethernet / Ipv6 / Icmpv6 / <ndp-body>`
//! stack with libcrafter and sends it at the link layer
//! (`SendOptions::link_layer`), because the destination is a multicast group and
//! the outgoing frame must carry the IPv6 multicast Ethernet destination
//! (`33:33:...`, RFC 2464). The captured reply decodes through
//! `Packet::decode_from_link(LinkType::Ethernet, ..)` and the validation
//! inspects the decoded `Icmpv6` header (type, code, the NA R/S/O flags through
//! `Icmpv6::body()`), the resolved Target Address, and the link-layer option.

use crafter::prelude::*;
use serde_json::{json, Value};
use std::net::Ipv6Addr;
use std::time::Duration;

use crate::common::{
    capture_filter, decoded_packet_json, failed_outcome, hex_bytes, observed_response, plan_json,
    required_str, send_report_json, target_service_json, CandidateValidation, ExampleResult,
    NdpValidation, ProbeOutcome, ProbePlan, StimulusEndpointRequest, FAILURE_DECODE_FAILED,
    FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD, FAILURE_WRONG_PEER,
};

/// Stable identifier for the NDP case module.
pub const MODULE_NAME: &str = "ndp";

/// ICMPv6 NDP message type codepoints (RFC 4861 section 4 / IANA
/// icmpv6-parameters), mirroring the crafter `ICMPV6_*` constants.
const NDP_ROUTER_SOLICITATION_TYPE: u8 = 133;
const NDP_ROUTER_ADVERTISEMENT_TYPE: u8 = 134;
const NDP_NEIGHBOR_SOLICITATION_TYPE: u8 = 135;
const NDP_NEIGHBOR_ADVERTISEMENT_TYPE: u8 = 136;

pub fn run_ndp_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = ndp_stimulus_packet(plan)?;
    // NDP rides ICMPv6 over IPv6 but the destination is a multicast group, so the
    // stimulus is sent at the link layer with an explicit IPv6-multicast Ethernet
    // destination (RFC 2464 33:33 mapping). The dry-run send plan compiles the
    // full Ethernet/IPv6/ICMPv6 stack without touching the wire.
    let report = SocketSender::new(
        SendOptions::new()
            .iface(request.interface.clone())
            .link_layer()
            .dry_run(),
    )
    .send(&packet)?;
    let sent_raw_hex = hex_bytes(report.plan().bytes());
    let sent_frame_len = report.plan().bytes().len();
    let observed = observed_response(
        plan,
        false,
        None,
        json!({}),
        json!({
            "planned_only": true,
            "send_report": send_report_json(&report),
            "sent_raw_hex": sent_raw_hex,
            "sent_frame_len": sent_frame_len,
            "capture_filter": capture_filter(plan),
            "target_service": target_service_json(plan),
            "requires_router_target": plan.requires_router_target,
            "dad": plan.dad,
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
            "sent_frame_len": sent_frame_len,
            "capture_filter": capture_filter(plan),
            "target_service": target_service_json(plan),
            "requires_router_target": plan.requires_router_target,
            "dad": plan.dad,
        }
    });
    Ok(ProbeOutcome {
        result,
        observed_response: observed,
        sent: false,
        received: false,
    })
}

pub fn run_ndp_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = ndp_stimulus_packet(plan)?;
    let timeout = Duration::from_secs(request.timeout_seconds.max(1));
    let mut sniffer = match Sniffer::interface(request.interface.clone())
        .timeout(timeout)
        .count(32)
        .filter("icmp6")
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
        match validate_ndp_candidate(plan, captured.packet(), captured.data())? {
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
                        "capture_filter": capture_filter(plan),
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
                return Ok(failed_outcome(
                    plan,
                    FAILURE_WRONG_PAYLOAD,
                    vec![
                        "captured ICMPv6 reply did not match the expected advertisement contract"
                            .to_string(),
                    ],
                    Some(json!({
                        "send_report": send_report_json(&send_report),
                        "candidate": decoded,
                    })),
                    sent,
                    true,
                ));
            }
        }
    }

    let reason = if wrong_peer.is_some() {
        FAILURE_WRONG_PEER
    } else {
        FAILURE_TIMEOUT
    };
    Ok(failed_outcome(
        plan,
        reason,
        vec![match reason {
            FAILURE_WRONG_PEER => {
                "captured ICMPv6 replies were for a different exchange".to_string()
            }
            _ => "no matching NDP advertisement captured before timeout".to_string(),
        }],
        Some(json!({
            "send_report": send_report_json(&send_report),
            "wrong_peer": wrong_peer,
        })),
        sent,
        false,
    ))
}

/// Map an IPv6 multicast address to its Ethernet multicast destination MAC.
///
/// RFC 2464 section 7: an IPv6 multicast address maps to the Ethernet
/// destination `33:33:` followed by the low four octets of the IPv6 address. The
/// solicited-node and all-routers/all-nodes groups all map this way, so the
/// link-layer frame reaches every node that has joined the group.
fn ipv6_multicast_ethernet_destination(multicast: Ipv6Addr) -> ExampleResult<MacAddr> {
    let octets = multicast.octets();
    let mac = format!(
        "33:33:{:02x}:{:02x}:{:02x}:{:02x}",
        octets[12], octets[13], octets[14], octets[15]
    );
    Ok(mac.parse()?)
}

/// Build the Ethernet / IPv6 / ICMPv6 NDP stimulus stack with libcrafter.
///
/// The body is a Router Solicitation, a Neighbor Solicitation (with a Source
/// Link-Layer Address option unless the DAD case omits it), built from the
/// crafter NDP builders. `compile()` fills the IPv6 payload length / next-header
/// and the ICMPv6 checksum over the IPv6 pseudo-header; the caller-set addresses
/// and Ethernet framing survive untouched. The Ethernet destination is the
/// IPv6-multicast mapping (RFC 2464) of the IPv6 destination so the frame is
/// delivered at the link layer to the solicited-node / all-routers group.
pub fn ndp_stimulus_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source_ipv6: Ipv6Addr =
        required_str(plan.source_ipv6.as_deref(), "source_ipv6")?.parse()?;
    let destination_ipv6: Ipv6Addr =
        required_str(plan.destination_ipv6.as_deref(), "destination_ipv6")?.parse()?;
    let ethernet_source: MacAddr =
        required_str(plan.ethernet_source.as_deref(), "ethernet_source")?.parse()?;
    let ethernet_destination = ipv6_multicast_ethernet_destination(destination_ipv6)?;

    // The trailing ICMPv6 NDP message: a full `Icmpv6 / <ndp-body>` packet from
    // the crafter builders. The DAD case omits the Source Link-Layer Address
    // option (RFC 4861 section 4.3 forbids it when the source is unspecified).
    let icmpv6_packet = match plan.icmpv6_type {
        Some(NDP_ROUTER_SOLICITATION_TYPE) => match plan.source_link_layer_addr.as_deref() {
            Some(mac) => Icmpv6::router_solicitation_with_source_link_layer(mac.parse()?),
            None => Icmpv6::router_solicitation(),
        },
        Some(NDP_NEIGHBOR_SOLICITATION_TYPE) | None => {
            let target: Ipv6Addr =
                required_str(plan.target_ipv6.as_deref(), "target_ipv6")?.parse()?;
            let omit_slla = plan.omit_source_link_layer_addr.unwrap_or(false);
            match (omit_slla, plan.source_link_layer_addr.as_deref()) {
                (false, Some(mac)) => {
                    Icmpv6::neighbor_solicitation_with_source_link_layer(target, mac.parse()?)
                }
                _ => Icmpv6::neighbor_solicitation(target),
            }
        }
        Some(other) => {
            return Err(format!("unsupported NDP stimulus ICMPv6 type {other}").into());
        }
    };

    // The crafter NDP builders return a `Packet` whose top layer is `Icmpv6`;
    // compose the IPv6 and Ethernet headers under it. Composing an `Ipv6` layer
    // with the ICMPv6 packet places ICMPv6 (next header 58) over IPv6, and the
    // Ethernet header carries the IPv6-multicast destination MAC.
    let ipv6 = Ipv6::with_addresses(source_ipv6, destination_ipv6);
    let packet =
        Ethernet::with_addresses(ethernet_source, ethernet_destination) / ipv6 / icmpv6_packet;
    Ok(packet)
}

/// Validate one captured candidate against the NDP advertisement contract.
///
/// A frame whose decoded ICMPv6 type is not the expected advertisement, or whose
/// resolved Target Address is not the address the solicitation asked for, surfaces
/// as `WrongPeer`; a frame for the right exchange that fails the flags / option
/// contract surfaces as `WrongPayload`; a fully matching advertisement surfaces
/// as `Passed`.
pub fn validate_ndp_candidate(
    plan: &ProbePlan,
    packet: &Packet,
    raw: &[u8],
) -> ExampleResult<CandidateValidation> {
    let Some(icmpv6) = packet.layer::<Icmpv6>() else {
        return Ok(CandidateValidation::Ignore);
    };
    let validation = plan
        .ndp_validation
        .as_ref()
        .ok_or("NDP plan is missing the validation contract")?;

    let decoded = decoded_packet_json(packet, raw);

    let expected_type = validation
        .icmpv6_type
        .unwrap_or(NDP_NEIGHBOR_ADVERTISEMENT_TYPE);
    if icmpv6.icmp_type_value() != expected_type {
        // A different ICMPv6 type (e.g. an unrelated NS/RS on the segment) is for
        // a different exchange, not a payload failure.
        return Ok(CandidateValidation::WrongPeer(json!({
            "packet": decoded,
            "mismatches": [json!({
                "field": "icmpv6.type",
                "expected": expected_type,
                "actual": icmpv6.icmp_type_value(),
            })],
        })));
    }

    let mut mismatches = Vec::new();

    if let Some(expected_code) = validation.icmpv6_code {
        if icmpv6.code_value() != expected_code {
            mismatches.push(json!({
                "field": "icmpv6.code",
                "expected": expected_code,
                "actual": icmpv6.code_value(),
            }));
        }
    }

    // Resolve the advertisement body. A Neighbor Advertisement carries the R/S/O
    // flags (read from the typed body view) and a Target Address; a Router
    // Advertisement carries the router flags.
    match expected_type {
        NDP_NEIGHBOR_ADVERTISEMENT_TYPE => {
            validate_neighbor_advertisement(packet, &icmpv6, validation, &mut mismatches);
        }
        NDP_ROUTER_ADVERTISEMENT_TYPE => {
            validate_router_advertisement(packet, validation, &mut mismatches);
        }
        _ => {}
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

/// Validate a Neighbor Advertisement body against the contract: the R/S/O flags
/// (from `Icmpv6::body()`), the resolved Target Address, and the Target
/// Link-Layer Address option MAC.
fn validate_neighbor_advertisement(
    packet: &Packet,
    icmpv6: &Icmpv6,
    validation: &NdpValidation,
    mismatches: &mut Vec<Value>,
) {
    if let Icmpv6Body::NeighborAdvertisement {
        router,
        solicited,
        override_flag,
        ..
    } = icmpv6.body()
    {
        check_flag("ndp.na.router", validation.router_flag, router, mismatches);
        check_flag(
            "ndp.na.solicited",
            validation.solicited_flag,
            solicited,
            mismatches,
        );
        check_flag(
            "ndp.na.override",
            validation.override_flag,
            override_flag,
            mismatches,
        );
    } else {
        mismatches.push(json!({
            "field": "ndp.na.body",
            "expected": "neighbor-advertisement",
            "actual": format!("{:?}", icmpv6.body()),
        }));
    }

    if let Some(advertisement) = packet.layer::<NeighborAdvertisement>() {
        if let Some(expected_target) = validation.target_ipv6.as_deref() {
            match expected_target.parse::<Ipv6Addr>() {
                Ok(expected) if advertisement.target_address_value() != expected => {
                    mismatches.push(json!({
                        "field": "ndp.na.target_address",
                        "expected": expected.to_string(),
                        "actual": advertisement.target_address_value().to_string(),
                    }));
                }
                Ok(_) => {}
                Err(err) => mismatches.push(json!({
                    "field": "ndp.na.target_address",
                    "error": format!("invalid expected target {expected_target}: {err}"),
                })),
            }
        }
        if let Some(expected_mac) = validation.target_link_layer_addr.as_deref() {
            let observed = advertisement
                .options_ref()
                .iter()
                .find_map(|option| option.link_layer_address());
            match observed {
                Some(mac) if mac.to_string() == expected_mac.to_lowercase() => {}
                Some(mac) => mismatches.push(json!({
                    "field": "ndp.na.target_link_layer_addr",
                    "expected": expected_mac,
                    "actual": mac.to_string(),
                })),
                None => mismatches.push(json!({
                    "field": "ndp.na.target_link_layer_addr",
                    "expected": expected_mac,
                    "actual": null,
                })),
            }
        }
    } else {
        mismatches.push(json!({
            "field": "ndp.na.layer",
            "expected": "NeighborAdvertisement",
            "actual": null,
        }));
    }
}

/// Validate a Router Advertisement body against the contract: the Managed (M) and
/// Other (O) flags read from `Icmpv6::body()`.
fn validate_router_advertisement(
    packet: &Packet,
    validation: &NdpValidation,
    mismatches: &mut Vec<Value>,
) {
    if let Some(icmpv6) = packet.layer::<Icmpv6>() {
        if let Icmpv6Body::RouterAdvertisement { managed, other, .. } = icmpv6.body() {
            check_flag("ndp.ra.managed", validation.managed_flag, managed, mismatches);
            check_flag("ndp.ra.other", validation.other_flag, other, mismatches);
        } else {
            mismatches.push(json!({
                "field": "ndp.ra.body",
                "expected": "router-advertisement",
                "actual": format!("{:?}", icmpv6.body()),
            }));
        }
    }
}

/// Push a flag mismatch when the expected flag is set in the contract and the
/// decoded value differs. A `None` expectation does not constrain the flag.
fn check_flag(field: &str, expected: Option<bool>, actual: bool, mismatches: &mut Vec<Value>) {
    if let Some(expected) = expected {
        if expected != actual {
            mismatches.push(json!({
                "field": field,
                "expected": expected,
                "actual": actual,
            }));
        }
    }
}

/// JSON view of an NDP validation contract for the plan echo. `None` renders
/// `null` (non-NDP cases leave the contract unset).
pub fn ndp_validation_json(validation: Option<&NdpValidation>) -> Value {
    match validation {
        Some(validation) => json!({
            "icmpv6_type": validation.icmpv6_type,
            "icmpv6_code": validation.icmpv6_code,
            "response_label": validation.response_label,
            "router_flag": validation.router_flag,
            "solicited_flag": validation.solicited_flag,
            "override_flag": validation.override_flag,
            "managed_flag": validation.managed_flag,
            "other_flag": validation.other_flag,
            "target_ipv6": validation.target_ipv6,
            "target_link_layer_addr": validation.target_link_layer_addr,
            "router_link_layer_addr": validation.router_link_layer_addr,
            "source_ipv6": validation.source_ipv6,
            "destination_ipv6": validation.destination_ipv6,
        }),
        None => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    fn ndp_validation(target: &str, mac: &str) -> NdpValidation {
        NdpValidation {
            icmpv6_type: Some(NDP_NEIGHBOR_ADVERTISEMENT_TYPE),
            icmpv6_code: Some(0),
            response_label: Some("neighbor-advertisement".to_string()),
            router_flag: Some(false),
            solicited_flag: Some(true),
            override_flag: Some(true),
            managed_flag: None,
            other_flag: None,
            target_ipv6: Some(target.to_string()),
            target_link_layer_addr: Some(mac.to_string()),
            router_link_layer_addr: None,
            source_ipv6: Some(target.to_string()),
            destination_ipv6: Some("fe80::1".to_string()),
        }
    }

    fn neighbor_solicitation_plan() -> ProbePlan {
        let mut plan = base_plan("ndp-neighbor-solicitation");
        plan.icmpv6_type = Some(NDP_NEIGHBOR_SOLICITATION_TYPE);
        plan.icmpv6_code = Some(0);
        plan.source_ipv6 = Some("fe80::1".to_string());
        plan.destination_ipv6 = Some("ff02::1:ff00:2".to_string());
        plan.target_ipv6 = Some("fe80::2".to_string());
        plan.source_link_layer_addr = Some("00:00:5e:00:53:01".to_string());
        plan.ethernet_source = Some("00:00:5e:00:53:01".to_string());
        plan
    }

    #[test]
    fn ipv6_multicast_maps_to_3333_ethernet() {
        let mac = ipv6_multicast_ethernet_destination("ff02::1:ff95:d57f".parse().unwrap()).unwrap();
        // RFC 2464: 33:33 plus the low four octets of the IPv6 multicast address.
        assert_eq!(mac.to_string(), "33:33:ff:95:d5:7f");
    }

    #[test]
    fn neighbor_solicitation_stack_compiles() {
        let plan = neighbor_solicitation_plan();
        let packet = ndp_stimulus_packet(&plan).unwrap();
        let raw = packet.compile().unwrap().into_bytes();
        // The compiled frame is an Ethernet/IPv6/ICMPv6 stack: the ethertype is
        // IPv6 (0x86dd), the IPv6 next header is ICMPv6 (58), and the ICMPv6 type
        // byte (offset 40 of an IPv6 packet with no extension headers, i.e. byte
        // 54 of the Ethernet frame) is the Neighbor Solicitation type.
        assert_eq!(&raw[12..14], &(0x86ddu16).to_be_bytes());
        assert_eq!(raw[14 + 6], 58, "ipv6 next header is icmpv6");
        assert_eq!(raw[14 + 40], NDP_NEIGHBOR_SOLICITATION_TYPE);
        // The Ethernet destination is the solicited-node multicast 33:33 mapping.
        assert_eq!(&raw[0..2], &[0x33, 0x33]);
    }

    #[test]
    fn dad_solicitation_omits_source_link_layer() {
        let mut plan = neighbor_solicitation_plan();
        plan.case = "ndp-duplicate-address-detection".to_string();
        plan.source_ipv6 = Some("::".to_string());
        plan.omit_source_link_layer_addr = Some(true);
        plan.dad = Some(true);
        let packet = ndp_stimulus_packet(&plan).unwrap();
        let raw = packet.compile().unwrap().into_bytes();
        // The DAD solicitation is still a Neighbor Solicitation but the IPv6
        // source is unspecified (::) and the body carries no SLLA option, so the
        // ICMPv6 payload is exactly the 4-byte reserved word + 16-byte target.
        assert_eq!(raw[14 + 40], NDP_NEIGHBOR_SOLICITATION_TYPE);
        let icmpv6_payload_len = raw.len() - (14 + 40);
        assert_eq!(
            icmpv6_payload_len, 24,
            "DAD NS body is 4-byte ICMPv6 header rest + 4 reserved + 16 target with no options"
        );
    }

    #[test]
    fn validate_accepts_matching_neighbor_advertisement() {
        let mut plan = neighbor_solicitation_plan();
        let target = "fe80::2";
        let target_mac = "00:00:5e:00:53:02";
        plan.ndp_validation = Some(ndp_validation(target, target_mac));

        // Build the reply the target kernel would send: a solicited Neighbor
        // Advertisement (R=0, S=1, O=1) with a Target Link-Layer Address option.
        let advertisement = Icmpv6::neighbor_advertisement_with_target_link_layer(
            target.parse().unwrap(),
            target_mac.parse().unwrap(),
            false,
            true,
            true,
        );
        let ipv6 = Ipv6::with_addresses(target.parse().unwrap(), "fe80::1".parse().unwrap());
        let reply = Ethernet::with_addresses(
            target_mac.parse().unwrap(),
            "00:00:5e:00:53:01".parse().unwrap(),
        ) / ipv6
            / advertisement;
        let raw = reply.compile().unwrap().into_bytes();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();

        let outcome = validate_ndp_candidate(&plan, &decoded, &raw).unwrap();
        assert!(
            matches!(outcome, CandidateValidation::Passed(_)),
            "expected a matching neighbor advertisement to pass, got {outcome:?}"
        );
    }

    #[test]
    fn validate_rejects_wrong_flags() {
        let mut plan = neighbor_solicitation_plan();
        let target = "fe80::2";
        let target_mac = "00:00:5e:00:53:02";
        plan.ndp_validation = Some(ndp_validation(target, target_mac));

        // A Neighbor Advertisement with the Solicited flag clear violates the
        // contract (the contract expects S=1 for a solicited reply).
        let advertisement = Icmpv6::neighbor_advertisement_with_target_link_layer(
            target.parse().unwrap(),
            target_mac.parse().unwrap(),
            false,
            false,
            true,
        );
        let ipv6 = Ipv6::with_addresses(target.parse().unwrap(), "fe80::1".parse().unwrap());
        let reply = Ethernet::with_addresses(
            target_mac.parse().unwrap(),
            "00:00:5e:00:53:01".parse().unwrap(),
        ) / ipv6
            / advertisement;
        let raw = reply.compile().unwrap().into_bytes();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &raw).unwrap();

        let outcome = validate_ndp_candidate(&plan, &decoded, &raw).unwrap();
        assert!(
            matches!(outcome, CandidateValidation::WrongPayload(_)),
            "expected a wrong-flags advertisement to fail, got {outcome:?}"
        );
    }
}
