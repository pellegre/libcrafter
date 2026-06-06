//! IPv4 protocol implementation.

mod constants;
mod decode;
mod display;
mod fragment;
mod header;
mod options;
mod protocol;

#[cfg(test)]
mod tests;

pub use crate::protocols::ip::shared::{
    Dscp, Ecn, IPPROTO_AH, IPPROTO_ESP, IPPROTO_EXPERIMENTAL_1, IPPROTO_EXPERIMENTAL_2,
    IPPROTO_GRE, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IPV6, IPPROTO_OSPF, IPPROTO_SCTP,
    IPPROTO_TCP, IPPROTO_UDP,
};
pub use constants::{
    IPV4_FLAG_DONT_FRAGMENT, IPV4_FLAG_MORE_FRAGMENTS, IPV4_FLAG_RESERVED, IPV4_OPTION_EOL,
    IPV4_OPTION_EXPERIMENTAL_1, IPV4_OPTION_EXPERIMENTAL_2, IPV4_OPTION_EXPERIMENTAL_3,
    IPV4_OPTION_EXPERIMENTAL_4, IPV4_OPTION_LOOSE_SOURCE_ROUTE, IPV4_OPTION_NOP,
    IPV4_OPTION_RECORD_ROUTE, IPV4_OPTION_ROUTER_ALERT, IPV4_OPTION_STRICT_SOURCE_ROUTE,
    IPV4_OPTION_TIMESTAMP, IPV4_OPTION_TRACEROUTE,
};
pub(crate) use decode::{append_ipv4_packet_with_registry, decode_quoted_ipv4};
pub use fragment::Ipv4FragmentInfo;
pub use header::{Ipv4, Ipv4ChecksumStatus};
pub use options::{Ipv4Option, Ipv4OptionIter, Ipv4OptionKind, Ipv4RouteOptionKind};
pub use protocol::Ipv4Protocol;
