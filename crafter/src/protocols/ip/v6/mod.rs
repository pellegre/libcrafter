//! IPv6 base header and IPv6 extension header implementations.

mod constants;
mod decode;
mod display;
mod extension;
mod header;
mod options;

#[cfg(test)]
mod tests;

use core::net::Ipv6Addr;
use core::str::FromStr;

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::icmp::Icmpv6;
use crate::protocols::ip::shared::{IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};
use crate::protocols::transport::{Tcp, Udp};

pub use constants::{
    IPPROTO_IPV6_AH, IPPROTO_IPV6_DSTOPTS, IPPROTO_IPV6_ESP, IPPROTO_IPV6_EXPERIMENTAL_1,
    IPPROTO_IPV6_EXPERIMENTAL_2, IPPROTO_IPV6_FRAGMENT, IPPROTO_IPV6_HIP, IPPROTO_IPV6_HOPOPTS,
    IPPROTO_IPV6_MOBILITY, IPPROTO_IPV6_NO_NEXT, IPPROTO_IPV6_ROUTE, IPPROTO_IPV6_SHIM6,
    IPV6_MOBILE_ROUTING_HEADER_EXT_LEN, IPV6_MOBILE_ROUTING_RESERVED,
    IPV6_MOBILE_ROUTING_SEGMENTS_LEFT, IPV6_OPTION_HOME_ADDRESS, IPV6_OPTION_JUMBO_PAYLOAD,
    IPV6_OPTION_PAD1, IPV6_OPTION_PADN, IPV6_OPTION_ROUTER_ALERT,
    IPV6_ROUTER_ALERT_ACTIVE_NETWORKS, IPV6_ROUTER_ALERT_MLD, IPV6_ROUTER_ALERT_MPLS_OAM,
    IPV6_ROUTER_ALERT_RESERVED, IPV6_ROUTER_ALERT_RSVP, IPV6_ROUTING_TYPE_CRH16,
    IPV6_ROUTING_TYPE_CRH32, IPV6_ROUTING_TYPE_EXPERIMENTAL_1, IPV6_ROUTING_TYPE_EXPERIMENTAL_2,
    IPV6_ROUTING_TYPE_MOBILE, IPV6_ROUTING_TYPE_NIMROD, IPV6_ROUTING_TYPE_RESERVED,
    IPV6_ROUTING_TYPE_RH0, IPV6_ROUTING_TYPE_RPL, IPV6_ROUTING_TYPE_SEGMENT,
    IPV6_ROUTING_TYPE_SOURCE_ROUTE, IPV6_SEGMENT_POLICY_EGRESS, IPV6_SEGMENT_POLICY_INGRESS,
    IPV6_SEGMENT_POLICY_SOURCE_ADDRESS, IPV6_SEGMENT_POLICY_UNSET,
};
pub(crate) use decode::append_ipv6_packet_with_registry;
pub use display::{
    ipv6_fragment_header_status_label, ipv6_routing_type_label, ipv6_routing_type_status,
};
pub use extension::{
    Ipv6DestinationOptionsHeader, Ipv6FragmentHeader, Ipv6FragmentHeaderStatus,
    Ipv6HopByHopOptionsHeader, Ipv6MobileRoutingHeader, Ipv6MobileRoutingHeaderStatus,
    Ipv6RoutingHeader, Ipv6RoutingTypeStatus, Ipv6SegmentRoutingHeader,
};
pub use header::Ipv6;
pub use options::{ipv6_router_alert_value_label, Ipv6Option, Ipv6OptionAction, Ipv6OptionIter};

fn payload_len_after(ctx: LayerContext<'_>) -> usize {
    ctx.packet().encoded_len_after(ctx.index())
}

fn layer_ipv6_next_header(layer: &dyn Layer) -> Option<u8> {
    if layer.as_any().is::<Ipv6HopByHopOptionsHeader>() {
        Some(IPPROTO_IPV6_HOPOPTS)
    } else if layer.as_any().is::<Ipv6DestinationOptionsHeader>() {
        Some(IPPROTO_IPV6_DSTOPTS)
    } else if layer.as_any().is::<Ipv6RoutingHeader>()
        || layer.as_any().is::<Ipv6MobileRoutingHeader>()
        || layer.as_any().is::<Ipv6SegmentRoutingHeader>()
    {
        Some(IPPROTO_IPV6_ROUTE)
    } else if layer.as_any().is::<Ipv6FragmentHeader>() {
        Some(IPPROTO_IPV6_FRAGMENT)
    } else if layer.as_any().is::<Tcp>() {
        Some(IPPROTO_TCP)
    } else if layer.as_any().is::<Udp>() {
        Some(IPPROTO_UDP)
    } else if layer.as_any().is::<Icmpv6>() {
        Some(IPPROTO_ICMPV6)
    } else {
        None
    }
}

fn parse_ipv6(input: &str) -> Result<Ipv6Addr> {
    Ipv6Addr::from_str(input).map_err(|_| {
        CrafterError::invalid_field_value("ipv6_address", "expected textual IPv6 address")
    })
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn copy_array_16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[..16]);
    out
}
