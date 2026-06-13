//! IPv6 summary and inspection formatting helpers.

use core::net::Ipv6Addr;

use crate::protocols::ip::shared::ipv6_next_header_summary as shared_next_header_summary;

use super::constants::{
    IPV6_ROUTING_TYPE_CRH16, IPV6_ROUTING_TYPE_CRH32, IPV6_ROUTING_TYPE_EXPERIMENTAL_1,
    IPV6_ROUTING_TYPE_EXPERIMENTAL_2, IPV6_ROUTING_TYPE_MOBILE, IPV6_ROUTING_TYPE_NIMROD,
    IPV6_ROUTING_TYPE_RESERVED, IPV6_ROUTING_TYPE_RH0, IPV6_ROUTING_TYPE_RPL,
    IPV6_ROUTING_TYPE_SEGMENT,
};
use super::header::Ipv6;
use super::options::{ipv6_router_alert_value_label, Ipv6Option};
use super::{Ipv6FragmentHeaderStatus, Ipv6RoutingTypeStatus};

pub(super) fn summary(ipv6: &Ipv6) -> String {
    format!(
        "Ipv6(src={}, dst={}, next={})",
        ipv6.source(),
        ipv6.destination(),
        next_header_summary(ipv6.next_header_value())
    )
}

pub(super) fn inspection_fields(ipv6: &Ipv6) -> Vec<(&'static str, String)> {
    vec![
        ("version", ipv6.version_value().to_string()),
        (
            "traffic_class",
            format!("0x{:02x}", ipv6.traffic_class_value()),
        ),
        ("dscp", ipv6.dscp_value().value().to_string()),
        ("ecn", ipv6.ecn_value().value().to_string()),
        ("flow_label", format!("0x{:05x}", ipv6.flow_label_value())),
        (
            "payload_length",
            ipv6.payload_length_value()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "auto".to_string()),
        ),
        ("next_header", next_header_summary(ipv6.next_header_value())),
        ("hop_limit", ipv6.hop_limit_value().to_string()),
        ("src", ipv6.source().to_string()),
        ("dst", ipv6.destination().to_string()),
    ]
}

pub(super) fn next_header_summary(next_header: u8) -> String {
    shared_next_header_summary(next_header)
}

/// Source-backed label for an IPv6 Fragment Header status.
pub const fn ipv6_fragment_header_status_label(status: Ipv6FragmentHeaderStatus) -> &'static str {
    match status {
        Ipv6FragmentHeaderStatus::Atomic => "atomic",
        Ipv6FragmentHeaderStatus::Initial => "initial",
        Ipv6FragmentHeaderStatus::NonInitial => "non-initial",
    }
}

/// Source-backed label for an IPv6 Routing Header type.
pub const fn ipv6_routing_type_label(routing_type: u8) -> &'static str {
    match routing_type {
        IPV6_ROUTING_TYPE_RH0 => "RH0 Source Route",
        IPV6_ROUTING_TYPE_NIMROD => "Nimrod",
        IPV6_ROUTING_TYPE_MOBILE => "Type 2 Mobile IPv6",
        IPV6_ROUTING_TYPE_RPL => "RPL Source Route Header",
        IPV6_ROUTING_TYPE_SEGMENT => "Segment Routing Header (SRH)",
        IPV6_ROUTING_TYPE_CRH16 => "CRH-16",
        IPV6_ROUTING_TYPE_CRH32 => "CRH-32",
        IPV6_ROUTING_TYPE_EXPERIMENTAL_1 => "RFC3692 experiment 1",
        IPV6_ROUTING_TYPE_EXPERIMENTAL_2 => "RFC3692 experiment 2",
        IPV6_ROUTING_TYPE_RESERVED => "Reserved",
        _ => "Unknown",
    }
}

/// Source-backed status for an IPv6 Routing Header type.
pub const fn ipv6_routing_type_status(routing_type: u8) -> Ipv6RoutingTypeStatus {
    match routing_type {
        IPV6_ROUTING_TYPE_RH0 | IPV6_ROUTING_TYPE_NIMROD => Ipv6RoutingTypeStatus::Deprecated,
        IPV6_ROUTING_TYPE_MOBILE
        | IPV6_ROUTING_TYPE_RPL
        | IPV6_ROUTING_TYPE_SEGMENT
        | IPV6_ROUTING_TYPE_CRH16
        | IPV6_ROUTING_TYPE_CRH32 => Ipv6RoutingTypeStatus::Assigned,
        IPV6_ROUTING_TYPE_EXPERIMENTAL_1 | IPV6_ROUTING_TYPE_EXPERIMENTAL_2 => {
            Ipv6RoutingTypeStatus::Experimental
        }
        IPV6_ROUTING_TYPE_RESERVED => Ipv6RoutingTypeStatus::Reserved,
        _ => Ipv6RoutingTypeStatus::Unknown,
    }
}

pub(super) fn routing_type_summary(routing_type: u8) -> String {
    match ipv6_routing_type_status(routing_type) {
        Ipv6RoutingTypeStatus::Assigned => {
            format!("{}({routing_type})", ipv6_routing_type_label(routing_type))
        }
        Ipv6RoutingTypeStatus::Deprecated => {
            format!(
                "{} (deprecated)({routing_type})",
                ipv6_routing_type_label(routing_type)
            )
        }
        Ipv6RoutingTypeStatus::Experimental => match routing_type {
            IPV6_ROUTING_TYPE_EXPERIMENTAL_1 => "experimental-1(253)".to_string(),
            IPV6_ROUTING_TYPE_EXPERIMENTAL_2 => "experimental-2(254)".to_string(),
            value => format!("experimental({value})"),
        },
        Ipv6RoutingTypeStatus::Reserved => format!("reserved({routing_type})"),
        Ipv6RoutingTypeStatus::Unknown => format!("unknown({routing_type})"),
    }
}

pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();

    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(&format!("{byte:02x}"));
    }

    output
}

pub(super) fn ipv6_list_summary(addresses: &[Ipv6Addr]) -> String {
    addresses
        .iter()
        .map(Ipv6Addr::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

pub(super) fn ipv6_options_summary(options: &[Ipv6Option]) -> String {
    if options.is_empty() {
        return "none".to_string();
    }

    options
        .iter()
        .map(ipv6_option_summary)
        .collect::<Vec<_>>()
        .join(",")
}

fn ipv6_option_summary(option: &Ipv6Option) -> String {
    match option {
        Ipv6Option::JumboPayload { .. } => match option.jumbo_payload_length() {
            Some(length) => {
                format!(
                    "Jumbo Payload(0x{:02x},length={length})",
                    option.option_type()
                )
            }
            None => format!(
                "Jumbo Payload(0x{:02x},malformed_length={})",
                option.option_type(),
                option.data().len()
            ),
        },
        Ipv6Option::RouterAlert { .. } => match option.router_alert_value() {
            Some(value) => {
                format!(
                    "Router Alert(0x{:02x},value={})",
                    option.option_type(),
                    ipv6_router_alert_value_summary(value)
                )
            }
            None => format!(
                "Router Alert(0x{:02x},malformed_length={})",
                option.option_type(),
                option.data().len()
            ),
        },
        Ipv6Option::HomeAddress { .. } => match option.home_address_value() {
            Some(address) => {
                format!(
                    "Home Address(0x{:02x},address={address})",
                    option.option_type()
                )
            }
            None => format!(
                "Home Address(0x{:02x},malformed_length={})",
                option.option_type(),
                option.data().len()
            ),
        },
        Ipv6Option::Generic { option_type, data } => {
            let data_summary = if data.is_empty() {
                "empty".to_string()
            } else {
                hex_bytes(data)
            };

            format!(
                "Generic(kind=0x{option_type:02x},len={},act={},chg={},rest=0x{:02x},data={data_summary})",
                data.len(),
                option.action_bits(),
                u8::from(option.change_en_route()),
                option.rest(),
            )
        }
        _ => format!("0x{:02x}", option.option_type()),
    }
}

fn ipv6_router_alert_value_summary(value: u16) -> String {
    format!("{}({value})", ipv6_router_alert_value_label(value))
}
