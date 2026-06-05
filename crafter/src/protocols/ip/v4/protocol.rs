//! IPv4 protocol field wrappers and display helpers.

use crate::protocols::ip::shared::{
    ip_protocol_summary, IPPROTO_AH, IPPROTO_ESP, IPPROTO_EXPERIMENTAL_1, IPPROTO_EXPERIMENTAL_2,
    IPPROTO_GRE, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IPV6, IPPROTO_OSPF, IPPROTO_SCTP,
    IPPROTO_TCP, IPPROTO_UDP,
};

/// Common IPv4 protocol numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Ipv4Protocol {
    /// IPv6 hop-by-hop option.
    HopByHop = 0,
    /// Internet Control Message Protocol for IPv4.
    Icmpv4 = IPPROTO_ICMP,
    /// Transmission Control Protocol.
    Tcp = IPPROTO_TCP,
    /// User Datagram Protocol.
    Udp = IPPROTO_UDP,
    /// IPv6 encapsulation.
    Ipv6 = IPPROTO_IPV6,
    /// Generic Routing Encapsulation.
    Gre = IPPROTO_GRE,
    /// Encapsulating Security Payload.
    Esp = IPPROTO_ESP,
    /// Authentication Header.
    Ah = IPPROTO_AH,
    /// ICMPv6.
    Icmpv6 = IPPROTO_ICMPV6,
    /// Open Shortest Path First IGP.
    Ospf = IPPROTO_OSPF,
    /// Stream Control Transmission Protocol.
    Sctp = IPPROTO_SCTP,
    /// Experimentation and testing value 1.
    Experimental1 = IPPROTO_EXPERIMENTAL_1,
    /// Experimentation and testing value 2.
    Experimental2 = IPPROTO_EXPERIMENTAL_2,
}

impl From<Ipv4Protocol> for u8 {
    fn from(value: Ipv4Protocol) -> Self {
        value as u8
    }
}

pub(crate) fn protocol_summary(protocol: u8) -> String {
    ip_protocol_summary(protocol)
}
