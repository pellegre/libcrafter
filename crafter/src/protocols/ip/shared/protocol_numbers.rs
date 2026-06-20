//! Shared IP protocol-number constants and display helpers.
//!
//! IPv4 `Protocol` and IPv6 `Next Header` fields use the same IANA protocol
//! number space. Version modules re-export the legacy public names from here.

/// IP protocol number for IPv6 Hop-by-Hop Options.
pub const IPPROTO_HOPOPTS: u8 = 0;
/// IP protocol number for ICMP.
pub const IPPROTO_ICMP: u8 = 1;
/// IANA Assigned Internet Protocol number for IGMP.
pub const IPPROTO_IGMP: u8 = 2;
/// IP protocol number for TCP.
pub const IPPROTO_TCP: u8 = 6;
/// IP protocol number for UDP.
pub const IPPROTO_UDP: u8 = 17;
/// IP protocol number for IPv6 encapsulation.
pub const IPPROTO_IPV6: u8 = 41;
/// IP protocol number for IPv6 Routing Header.
pub const IPPROTO_ROUTE: u8 = 43;
/// IP protocol number for IPv6 Fragment Header.
pub const IPPROTO_FRAGMENT: u8 = 44;
/// IP protocol number for Generic Routing Encapsulation.
pub const IPPROTO_GRE: u8 = 47;
/// IP protocol number for Encapsulating Security Payload.
pub const IPPROTO_ESP: u8 = 50;
/// IP protocol number for Authentication Header.
pub const IPPROTO_AH: u8 = 51;
/// IP protocol number for ICMPv6.
pub const IPPROTO_ICMPV6: u8 = 58;
/// IP protocol number for No Next Header.
pub const IPPROTO_NO_NEXT: u8 = 59;
/// IP protocol number for IPv6 Destination Options.
pub const IPPROTO_DSTOPTS: u8 = 60;
/// IP protocol number for Open Shortest Path First IGP.
pub const IPPROTO_OSPF: u8 = 89;
/// IP protocol number for Stream Control Transmission Protocol.
pub const IPPROTO_SCTP: u8 = 132;
/// IP protocol number for IPv6 Mobility Header.
pub const IPPROTO_MOBILITY: u8 = 135;
/// IP protocol number for Host Identity Protocol.
pub const IPPROTO_HIP: u8 = 139;
/// IP protocol number for Shim6 Protocol.
pub const IPPROTO_SHIM6: u8 = 140;
/// IP protocol number reserved for experimentation and testing.
pub const IPPROTO_EXPERIMENTAL_1: u8 = 253;
/// IP protocol number reserved for experimentation and testing.
pub const IPPROTO_EXPERIMENTAL_2: u8 = 254;

/// IPv6 Hop-by-Hop Options next-header compatibility alias.
pub const IPPROTO_IPV6_HOPOPTS: u8 = IPPROTO_HOPOPTS;
/// IPv6 Routing Header next-header compatibility alias.
pub const IPPROTO_IPV6_ROUTE: u8 = IPPROTO_ROUTE;
/// IPv6 Fragment Header next-header compatibility alias.
pub const IPPROTO_IPV6_FRAGMENT: u8 = IPPROTO_FRAGMENT;
/// IPv6 Encapsulating Security Payload next-header compatibility alias.
pub const IPPROTO_IPV6_ESP: u8 = IPPROTO_ESP;
/// IPv6 Authentication Header next-header compatibility alias.
pub const IPPROTO_IPV6_AH: u8 = IPPROTO_AH;
/// IPv6 No Next Header next-header compatibility alias.
pub const IPPROTO_IPV6_NO_NEXT: u8 = IPPROTO_NO_NEXT;
/// IPv6 Destination Options next-header compatibility alias.
pub const IPPROTO_IPV6_DSTOPTS: u8 = IPPROTO_DSTOPTS;
/// IPv6 Mobility Header next-header compatibility alias.
pub const IPPROTO_IPV6_MOBILITY: u8 = IPPROTO_MOBILITY;
/// IPv6 Host Identity Protocol next-header compatibility alias.
pub const IPPROTO_IPV6_HIP: u8 = IPPROTO_HIP;
/// IPv6 Shim6 Protocol next-header compatibility alias.
pub const IPPROTO_IPV6_SHIM6: u8 = IPPROTO_SHIM6;
/// IPv6 experimental/testing next-header compatibility alias 1.
pub const IPPROTO_IPV6_EXPERIMENTAL_1: u8 = IPPROTO_EXPERIMENTAL_1;
/// IPv6 experimental/testing next-header compatibility alias 2.
pub const IPPROTO_IPV6_EXPERIMENTAL_2: u8 = IPPROTO_EXPERIMENTAL_2;

pub(crate) const fn ip_protocol_label(protocol: u8) -> Option<&'static str> {
    match protocol {
        IPPROTO_HOPOPTS => Some("hopopt"),
        IPPROTO_ICMP => Some("icmp"),
        IPPROTO_IGMP => Some("igmp"),
        IPPROTO_TCP => Some("tcp"),
        IPPROTO_UDP => Some("udp"),
        IPPROTO_IPV6 => Some("ipv6"),
        IPPROTO_GRE => Some("gre"),
        IPPROTO_ESP => Some("esp"),
        IPPROTO_AH => Some("ah"),
        IPPROTO_ICMPV6 => Some("icmpv6"),
        IPPROTO_OSPF => Some("ospf"),
        IPPROTO_SCTP => Some("sctp"),
        IPPROTO_EXPERIMENTAL_1 | IPPROTO_EXPERIMENTAL_2 => Some("experimental"),
        _ => None,
    }
}

pub(crate) fn ip_protocol_summary(protocol: u8) -> String {
    match ip_protocol_label(protocol) {
        Some(label) => format!("{label}({protocol})"),
        None => protocol.to_string(),
    }
}

pub(crate) const fn ipv6_next_header_label(next_header: u8) -> Option<&'static str> {
    match next_header {
        IPPROTO_IPV6_HOPOPTS => Some("hop-by-hop-options"),
        IPPROTO_TCP => Some("tcp"),
        IPPROTO_UDP => Some("udp"),
        IPPROTO_IPV6_ROUTE => Some("routing"),
        IPPROTO_IPV6_FRAGMENT => Some("fragment"),
        IPPROTO_IPV6_ESP => Some("esp"),
        IPPROTO_IPV6_AH => Some("ah"),
        IPPROTO_ICMPV6 => Some("icmpv6"),
        IPPROTO_IPV6_NO_NEXT => Some("no-next"),
        IPPROTO_IPV6_DSTOPTS => Some("destination-options"),
        IPPROTO_IPV6_MOBILITY => Some("mobility"),
        IPPROTO_IPV6_HIP => Some("hip"),
        IPPROTO_IPV6_SHIM6 => Some("shim6"),
        IPPROTO_IPV6_EXPERIMENTAL_1 => Some("experimental-1"),
        IPPROTO_IPV6_EXPERIMENTAL_2 => Some("experimental-2"),
        255 => Some("reserved"),
        _ => None,
    }
}

pub(crate) fn ipv6_next_header_summary(next_header: u8) -> String {
    match ipv6_next_header_label(next_header) {
        Some(label) => format!("{label}({next_header})"),
        None => format!("unknown({next_header})"),
    }
}
