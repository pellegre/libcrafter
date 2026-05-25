use crate::{
    Arp, ArpOperation, Dhcp, Dns, Icmp, Icmpv6, Ipv4, Ipv6, Packet, Tcp, Udp, BOOTP_REPLY,
    DHCP_CLIENT_PORT, DHCP_SERVER_PORT, DNS_PORT, ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST,
    ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST,
};

pub struct ReplyMatcher {
    request: Packet,
}

impl ReplyMatcher {
    /// Create a matcher from a request packet.
    pub fn from_packet(request: &Packet) -> Self {
        Self {
            request: request.clone(),
        }
    }

    /// Derived BPF-style filter for likely replies.
    pub fn reply_filter(&self) -> Option<String> {
        request_reply_filter(&self.request)
    }

    /// Return true when `candidate` is a typed reply to the request.
    pub fn matches(&self, candidate: &Packet) -> bool {
        reply_matches(&self.request, candidate)
    }
}

/// Derive a BPF-style reply filter for one packet.
pub fn reply_filter(packet: &Packet) -> Option<String> {
    ReplyMatcher::from_packet(packet).reply_filter()
}

/// Return true when `candidate` is a typed reply to `request`.
pub fn reply_matches(request: &Packet, candidate: &Packet) -> bool {
    if request.layer::<Dns>().is_some() {
        return dns_reply_matches(request, candidate);
    }
    if request.layer::<Dhcp>().is_some() {
        return dhcp_reply_matches(request, candidate);
    }

    arp_reply_matches(request, candidate)
        || icmp_reply_matches(request, candidate)
        || icmpv6_reply_matches(request, candidate)
        || tcp_reply_matches(request, candidate)
        || udp_reply_matches(request, candidate)
}

fn request_reply_filter(packet: &Packet) -> Option<String> {
    if packet.layer::<Dhcp>().is_some() {
        return Some(dhcp_filter());
    }
    if packet.layer::<Dns>().is_some() {
        return Some(transport_filter("udp", packet, Some(DNS_PORT), None));
    }
    if let Some(arp) = packet.layer::<Arp>() {
        return Some(arp_filter(arp));
    }
    if packet.layer::<Icmp>().is_some() {
        return Some(protocol_filter("icmp", packet));
    }
    if packet.layer::<Icmpv6>().is_some() {
        return Some(protocol_filter("icmp6", packet));
    }
    if let Some(tcp) = packet.layer::<Tcp>() {
        return Some(transport_filter(
            "tcp",
            packet,
            Some(tcp.destination_port_value()),
            Some(tcp.source_port_value()),
        ));
    }
    if let Some(udp) = packet.layer::<Udp>() {
        return Some(transport_filter(
            "udp",
            packet,
            Some(udp.destination_port_value()),
            Some(udp.source_port_value()),
        ));
    }

    None
}

pub(crate) fn combine_filters(derived: Option<String>, user: Option<&str>) -> Option<String> {
    let user = user.map(str::trim).filter(|filter| !filter.is_empty());
    match (derived, user) {
        (Some(derived), Some(user)) => Some(format!("({derived}) and ({user})")),
        (Some(derived), None) => Some(derived),
        (None, Some(user)) => Some(user.to_string()),
        (None, None) => None,
    }
}

pub(crate) fn batch_reply_filter(packets: &[Packet]) -> Option<String> {
    let mut filters = Vec::new();
    for packet in packets {
        let Some(filter) = ReplyMatcher::from_packet(packet).reply_filter() else {
            continue;
        };
        if !filters.iter().any(|existing| existing == &filter) {
            filters.push(filter);
        }
    }

    match filters.len() {
        0 => None,
        1 => filters.pop(),
        _ => Some(
            filters
                .into_iter()
                .map(|filter| format!("({filter})"))
                .collect::<Vec<_>>()
                .join(" or "),
        ),
    }
}

fn dhcp_filter() -> String {
    format!("udp and src port {DHCP_SERVER_PORT} and dst port {DHCP_CLIENT_PORT}")
}

fn arp_filter(arp: &Arp) -> String {
    let mut terms = vec!["arp".to_string()];
    if let Some(target) = arp.target_ipv4() {
        terms.push(format!("src host {target}"));
    }
    if let Some(sender) = arp.sender_ipv4() {
        terms.push(format!("dst host {sender}"));
    }
    terms.join(" and ")
}

fn protocol_filter(protocol: &str, packet: &Packet) -> String {
    let mut terms = vec![protocol.to_string()];
    if let Some(hosts) = reversed_host_terms(packet) {
        terms.extend(hosts);
    }
    terms.join(" and ")
}

fn transport_filter(
    protocol: &str,
    packet: &Packet,
    source_port: Option<u16>,
    destination_port: Option<u16>,
) -> String {
    let mut terms = vec![protocol.to_string()];
    if let Some(hosts) = reversed_host_terms(packet) {
        terms.extend(hosts);
    }
    if let Some(source_port) = source_port {
        terms.push(format!("src port {source_port}"));
    }
    if let Some(destination_port) = destination_port {
        terms.push(format!("dst port {destination_port}"));
    }
    terms.join(" and ")
}

fn reversed_host_terms(packet: &Packet) -> Option<Vec<String>> {
    if let Some(ipv4) = packet.layer::<Ipv4>() {
        Some(vec![
            format!("src host {}", ipv4.destination()),
            format!("dst host {}", ipv4.source()),
        ])
    } else {
        packet.layer::<Ipv6>().map(|ipv6| {
            vec![
                format!("src host {}", ipv6.destination()),
                format!("dst host {}", ipv6.source()),
            ]
        })
    }
}

fn arp_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    let Some(request_arp) = request.layer::<Arp>() else {
        return false;
    };
    let Some(candidate_arp) = candidate.layer::<Arp>() else {
        return false;
    };

    request_arp.opcode_value() == u16::from(ArpOperation::Request)
        && candidate_arp.opcode_value() == u16::from(ArpOperation::Reply)
        && candidate_arp.sender_protocol_bytes_value() == request_arp.target_protocol_bytes_value()
        && candidate_arp.target_protocol_bytes_value() == request_arp.sender_protocol_bytes_value()
        && candidate_arp.target_hardware_bytes_value() == request_arp.sender_hardware_bytes_value()
}

fn icmp_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    let Some(request_icmp) = request.layer::<Icmp>() else {
        return false;
    };
    let Some(candidate_icmp) = candidate.layer::<Icmp>() else {
        return false;
    };

    request_icmp.icmp_type_value() == ICMP_ECHO_REQUEST
        && candidate_icmp.icmp_type_value() == ICMP_ECHO_REPLY
        && request_icmp.identifier_value() == candidate_icmp.identifier_value()
        && request_icmp.sequence_number_value() == candidate_icmp.sequence_number_value()
        && ip_addresses_are_reversed(request, candidate)
}

fn icmpv6_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    let Some(request_icmp) = request.layer::<Icmpv6>() else {
        return false;
    };
    let Some(candidate_icmp) = candidate.layer::<Icmpv6>() else {
        return false;
    };

    request_icmp.icmp_type_value() == ICMPV6_ECHO_REQUEST
        && candidate_icmp.icmp_type_value() == ICMPV6_ECHO_REPLY
        && request_icmp.identifier_value() == candidate_icmp.identifier_value()
        && request_icmp.sequence_number_value() == candidate_icmp.sequence_number_value()
        && ip_addresses_are_reversed(request, candidate)
}

fn tcp_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    let Some(request_tcp) = request.layer::<Tcp>() else {
        return false;
    };
    let Some(candidate_tcp) = candidate.layer::<Tcp>() else {
        return false;
    };

    candidate_tcp.source_port_value() == request_tcp.destination_port_value()
        && candidate_tcp.destination_port_value() == request_tcp.source_port_value()
        && ip_addresses_are_reversed(request, candidate)
}

fn udp_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    let Some(request_udp) = request.layer::<Udp>() else {
        return false;
    };
    let Some(candidate_udp) = candidate.layer::<Udp>() else {
        return false;
    };

    candidate_udp.source_port_value() == request_udp.destination_port_value()
        && candidate_udp.destination_port_value() == request_udp.source_port_value()
        && ip_addresses_are_reversed(request, candidate)
}

fn dns_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    let Some(request_dns) = request.layer::<Dns>() else {
        return false;
    };
    let Some(candidate_dns) = candidate.layer::<Dns>() else {
        return false;
    };

    !request_dns.is_response()
        && candidate_dns.is_response()
        && request_dns.id_value() == candidate_dns.id_value()
        && udp_optional_reply_matches(request, candidate)
}

fn dhcp_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    let Some(request_dhcp) = request.layer::<Dhcp>() else {
        return false;
    };
    let Some(candidate_dhcp) = candidate.layer::<Dhcp>() else {
        return false;
    };

    candidate_dhcp.op_value() == BOOTP_REPLY
        && request_dhcp.transaction_id_value() == candidate_dhcp.transaction_id_value()
        && request_dhcp.client_hardware_address_value()
            == candidate_dhcp.client_hardware_address_value()
        && dhcp_transport_reply_matches(request, candidate)
}

fn dhcp_transport_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    match (request.layer::<Udp>(), candidate.layer::<Udp>()) {
        (Some(request_udp), Some(candidate_udp)) => {
            request_udp.source_port_value() == DHCP_CLIENT_PORT
                && request_udp.destination_port_value() == DHCP_SERVER_PORT
                && candidate_udp.source_port_value() == DHCP_SERVER_PORT
                && candidate_udp.destination_port_value() == DHCP_CLIENT_PORT
        }
        (None, None) => true,
        _ => false,
    }
}

fn udp_optional_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    match (request.layer::<Udp>(), candidate.layer::<Udp>()) {
        (Some(_), Some(_)) => udp_reply_matches(request, candidate),
        (None, None) => ip_addresses_are_reversed(request, candidate),
        _ => false,
    }
}

fn ip_addresses_are_reversed(request: &Packet, candidate: &Packet) -> bool {
    ipv4_addresses_are_reversed(request, candidate)
        && ipv6_addresses_are_reversed(request, candidate)
}

fn ipv4_addresses_are_reversed(request: &Packet, candidate: &Packet) -> bool {
    match (request.layer::<Ipv4>(), candidate.layer::<Ipv4>()) {
        (Some(request_ip), Some(candidate_ip)) => {
            candidate_ip.source() == request_ip.destination()
                && candidate_ip.destination() == request_ip.source()
        }
        (None, None) => true,
        _ => false,
    }
}

fn ipv6_addresses_are_reversed(request: &Packet, candidate: &Packet) -> bool {
    match (request.layer::<Ipv6>(), candidate.layer::<Ipv6>()) {
        (Some(request_ip), Some(candidate_ip)) => {
            candidate_ip.source() == request_ip.destination()
                && candidate_ip.destination() == request_ip.source()
        }
        (None, None) => true,
        _ => false,
    }
}
