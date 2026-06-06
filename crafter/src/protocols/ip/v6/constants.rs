//! IPv6-specific constants.

pub use crate::protocols::ip::shared::{
    IPPROTO_IPV6_AH, IPPROTO_IPV6_DSTOPTS, IPPROTO_IPV6_ESP, IPPROTO_IPV6_EXPERIMENTAL_1,
    IPPROTO_IPV6_EXPERIMENTAL_2, IPPROTO_IPV6_FRAGMENT, IPPROTO_IPV6_HIP, IPPROTO_IPV6_HOPOPTS,
    IPPROTO_IPV6_MOBILITY, IPPROTO_IPV6_NO_NEXT, IPPROTO_IPV6_ROUTE, IPPROTO_IPV6_SHIM6,
};

/// IPv6 Pad1 option type shared by Hop-by-Hop and Destination Options headers.
pub const IPV6_OPTION_PAD1: u8 = 0x00;
/// IPv6 PadN option type shared by Hop-by-Hop and Destination Options headers.
pub const IPV6_OPTION_PADN: u8 = 0x01;
/// IPv6 Jumbo Payload option type, defined by RFC 2675 for Hop-by-Hop Options.
pub const IPV6_OPTION_JUMBO_PAYLOAD: u8 = 0xc2;
/// IPv6 Router Alert option type. Deprecated by IANA for new protocols.
pub const IPV6_OPTION_ROUTER_ALERT: u8 = 0x05;
/// IPv6 Home Address option type, defined by RFC 6275 for Destination Options.
pub const IPV6_OPTION_HOME_ADDRESS: u8 = 0xc9;

/// IPv6 Router Alert value: Multicast Listener Discovery.
pub const IPV6_ROUTER_ALERT_MLD: u16 = 0;
/// IPv6 Router Alert value: Resource Reservation Protocol.
pub const IPV6_ROUTER_ALERT_RSVP: u16 = 1;
/// IPv6 Router Alert value: Active Networks.
pub const IPV6_ROUTER_ALERT_ACTIVE_NETWORKS: u16 = 2;
/// IPv6 Router Alert value: reserved.
pub const IPV6_ROUTER_ALERT_RESERVED: u16 = 3;
/// IPv6 Router Alert value: MPLS OAM, deprecated in the IANA registry.
pub const IPV6_ROUTER_ALERT_MPLS_OAM: u16 = 69;

/// IPv6 Routing Header Type 0 source route, also called RH0. Deprecated by RFC 5095.
pub const IPV6_ROUTING_TYPE_SOURCE_ROUTE: u8 = 0;
/// Compatibility alias for the deprecated Type 0 Routing Header.
pub const IPV6_ROUTING_TYPE_RH0: u8 = IPV6_ROUTING_TYPE_SOURCE_ROUTE;
/// IPv6 Routing Header type for Nimrod, deprecated in the IANA registry.
pub const IPV6_ROUTING_TYPE_NIMROD: u8 = 1;
/// IPv6 Routing Header type for mobile IPv6 home-address routing.
pub const IPV6_ROUTING_TYPE_MOBILE: u8 = 2;
/// IPv6 Routing Header type for RPL source routing.
pub const IPV6_ROUTING_TYPE_RPL: u8 = 3;
/// IPv6 Routing Header type for segment routing.
pub const IPV6_ROUTING_TYPE_SEGMENT: u8 = 4;
/// IPv6 Routing Header type for CRH-16.
pub const IPV6_ROUTING_TYPE_CRH16: u8 = 5;
/// IPv6 Routing Header type for CRH-32.
pub const IPV6_ROUTING_TYPE_CRH32: u8 = 6;
/// IPv6 Routing Header type for RFC3692-style experiment 1.
pub const IPV6_ROUTING_TYPE_EXPERIMENTAL_1: u8 = 253;
/// IPv6 Routing Header type for RFC3692-style experiment 2.
pub const IPV6_ROUTING_TYPE_EXPERIMENTAL_2: u8 = 254;
/// IPv6 Routing Header type reserved by IANA.
pub const IPV6_ROUTING_TYPE_RESERVED: u8 = 255;

/// RFC 6275 Type 2 Routing Header `Hdr Ext Len` value.
pub const IPV6_MOBILE_ROUTING_HEADER_EXT_LEN: u8 = 2;
/// RFC 6275 Type 2 Routing Header `Segments Left` value on the wire.
pub const IPV6_MOBILE_ROUTING_SEGMENTS_LEFT: u8 = 1;
/// RFC 6275 Type 2 Routing Header reserved field value sent by compliant senders.
pub const IPV6_MOBILE_ROUTING_RESERVED: u32 = 0;

/// Segment-routing policy flag: unset.
pub const IPV6_SEGMENT_POLICY_UNSET: u8 = 0;
/// Segment-routing policy flag: ingress router.
pub const IPV6_SEGMENT_POLICY_INGRESS: u8 = 1;
/// Segment-routing policy flag: egress router.
pub const IPV6_SEGMENT_POLICY_EGRESS: u8 = 2;
/// Segment-routing policy flag: original source address.
pub const IPV6_SEGMENT_POLICY_SOURCE_ADDRESS: u8 = 3;

pub(super) const IPV6_HEADER_LEN: usize = 40;
pub(super) const IPV6_EXTENSION_MIN_LEN: usize = 8;
pub(super) const IPV6_FRAGMENT_HEADER_LEN: usize = 8;
pub(super) const IPV6_MOBILE_ROUTING_LEN: usize = 24;
pub(super) const IPV6_SEGMENT_BASE_LEN: usize = 8;
pub(super) const IPV6_MAX_FLOW_LABEL: u32 = 0x000f_ffff;
pub(super) const IPV6_MAX_HEADER_EXT_LEN: usize = 8 + u8::MAX as usize * 8;
pub(super) const IPV6_MAX_FRAGMENT_OFFSET: u16 = 0x1fff;
pub(super) const IPV6_SEGMENT_HMAC_LEN: usize = 32;
pub(super) const IPV6_OPTION_DATA_MAX_LEN: usize = u8::MAX as usize;
pub(super) const IPV6_OPTION_HEADER_LEN: usize = 2;
pub(super) const IPV6_JUMBO_PAYLOAD_DATA_LEN: usize = 4;
pub(super) const IPV6_ROUTER_ALERT_DATA_LEN: usize = 2;
pub(super) const IPV6_HOME_ADDRESS_DATA_LEN: usize = 16;
pub(super) const IPV6_OPTION_ACTION_SHIFT: u8 = 6;
pub(super) const IPV6_OPTION_CHANGE_EN_ROUTE_MASK: u8 = 0x20;
pub(super) const IPV6_OPTION_NUMBER_MASK: u8 = 0x1f;
