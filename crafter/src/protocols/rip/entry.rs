//! RIP route table entry (RTE) model.
//!
//! A RIP route entry is the fixed 20-octet record that follows the 4-octet RIP
//! header (RFC 1058 §3.1, RFC 2453 §4). It carries:
//!
//! - Address Family Identifier (2 octets).
//! - Route Tag (2 octets; RIPv2 only, zero in RIPv1).
//! - IPv4 Address (4 octets).
//! - Subnet Mask (4 octets; RIPv2 only, zero in RIPv1).
//! - Next Hop (4 octets; RIPv2 only, zero in RIPv1).
//! - Metric (4 octets).
//!
//! This module defines the [`RipEntry`] type and its chainable builders. The
//! values are held in [`Field`] wrappers so a later `compile()` step can fill
//! defaults only when the caller left a field unset and leave caller-set values
//! untouched. Compile/decode behavior is added in later steps.

use std::net::Ipv4Addr;

use crate::error::{CrafterError, Result};
use crate::field::Field;

use super::constants::{RIP_AFI_IP, RIP_ENTRY_LEN, RIP_METRIC_INFINITY};
use super::registry::is_rip_auth_marker;

/// A single 20-octet RIP route table entry (RFC 1058 §3.1, RFC 2453 §4).
///
/// Every field is held in a [`Field`] wrapper so that the builders mark values
/// the caller set explicitly (`set_user`), while `new()` installs library
/// defaults. The `*_value()` accessors return the effective value regardless of
/// whether it was caller-set or defaulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RipEntry {
    /// Address Family Identifier (RFC 2453 §4.1; IANA Address Family Numbers).
    pub address_family: Field<u16>,
    /// Route Tag (RFC 2453 §4; zero in RIPv1).
    pub route_tag: Field<u16>,
    /// IPv4 destination address.
    pub address: Field<Ipv4Addr>,
    /// Subnet mask (RFC 2453 §4; zero in RIPv1).
    pub subnet_mask: Field<Ipv4Addr>,
    /// Next hop (RFC 2453 §4; zero in RIPv1).
    pub next_hop: Field<Ipv4Addr>,
    /// Metric (RFC 1058 §3.1).
    pub metric: Field<u32>,
}

impl RipEntry {
    /// Create a route entry with library defaults.
    ///
    /// The address family defaults to [`RIP_AFI_IP`], addresses to `0.0.0.0`,
    /// and route tag and metric to `0`. None of these defaults are marked as
    /// caller-set, so a later `compile()` step may overwrite them.
    pub fn new() -> Self {
        Self {
            address_family: Field::defaulted(RIP_AFI_IP),
            route_tag: Field::defaulted(0),
            address: Field::defaulted(Ipv4Addr::UNSPECIFIED),
            subnet_mask: Field::defaulted(Ipv4Addr::UNSPECIFIED),
            next_hop: Field::defaulted(Ipv4Addr::UNSPECIFIED),
            metric: Field::defaulted(0),
        }
    }

    /// Build a RIPv1 route entry (RFC 1058 §3.1).
    ///
    /// Sets the address family to [`RIP_AFI_IP`], the destination `address`, and
    /// the `metric`. The route tag, subnet mask, and next hop are left at their
    /// zero defaults, matching the RIPv1 entry layout where those fields must be
    /// zero.
    pub fn ipv1_route(address: Ipv4Addr, metric: u32) -> Self {
        Self::new()
            .address_family(RIP_AFI_IP)
            .address(address)
            .metric(metric)
    }

    /// Build a RIPv2 route entry (RFC 2453 §4).
    ///
    /// Sets the address family to [`RIP_AFI_IP`], the destination `address`, the
    /// subnet `mask`, and the `metric`. The next hop defaults to `0.0.0.0`
    /// (RFC 2453 §4: a next hop of 0.0.0.0 means the originator of the route).
    pub fn ipv2_route(address: Ipv4Addr, mask: Ipv4Addr, metric: u32) -> Self {
        Self::new()
            .address_family(RIP_AFI_IP)
            .address(address)
            .subnet_mask(mask)
            .metric(metric)
    }

    /// Set the address family identifier (caller-set).
    pub fn address_family(mut self, value: u16) -> Self {
        self.address_family.set_user(value);
        self
    }

    /// Set the route tag (caller-set).
    pub fn route_tag(mut self, value: u16) -> Self {
        self.route_tag.set_user(value);
        self
    }

    /// Set the route tag (caller-set), fluent v2 alias of [`route_tag`].
    ///
    /// The Route Tag (RFC 2453 §3.1) is a 2-octet field in each RIPv2 entry
    /// used to carry information — for example, an autonomous-system number —
    /// that is opaque to RIP itself and must be preserved unchanged. It
    /// occupies the two octets after the address family that are reserved/zero
    /// in RIPv1. This is an explicit, discoverable alias of [`route_tag`] for
    /// fluent RIPv2 entry construction.
    ///
    /// [`route_tag`]: RipEntry::route_tag
    pub fn with_route_tag(mut self, tag: u16) -> RipEntry {
        self.route_tag.set_user(tag);
        self
    }

    /// Set the IPv4 destination address (caller-set).
    pub fn address(mut self, value: Ipv4Addr) -> Self {
        self.address.set_user(value);
        self
    }

    /// Set the subnet mask (caller-set).
    pub fn subnet_mask(mut self, value: Ipv4Addr) -> Self {
        self.subnet_mask.set_user(value);
        self
    }

    /// Set the subnet mask (caller-set) to the contiguous mask for `len`.
    ///
    /// `len` is a CIDR prefix length (`0..=32`); `len` values greater than 32
    /// are clamped to 32. The resulting mask is the contiguous big-endian mask
    /// with `len` leading one-bits (for example, `with_prefix_len(24)` sets
    /// `255.255.255.0` and `with_prefix_len(0)` sets `0.0.0.0`). This is a
    /// convenience over [`subnet_mask`] for the common contiguous case; callers
    /// that need a non-contiguous (deliberately malformed) mask set it directly
    /// via [`subnet_mask`].
    ///
    /// [`subnet_mask`]: RipEntry::subnet_mask
    pub fn with_prefix_len(mut self, len: u8) -> RipEntry {
        let len = len.min(32);
        let mask_bits: u32 = if len == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(len))
        };
        self.subnet_mask.set_user(Ipv4Addr::from(mask_bits));
        self
    }

    /// Set the next hop (caller-set).
    pub fn next_hop(mut self, value: Ipv4Addr) -> Self {
        self.next_hop.set_user(value);
        self
    }

    /// Set the next hop (caller-set), fluent v2 alias of [`next_hop`].
    ///
    /// The Next Hop (RFC 2453 §4.4) is the 4-octet immediate next-hop IP
    /// address to which packets for the entry should be forwarded. A value of
    /// `0.0.0.0` is the default and means "use the originator of this
    /// advertisement" as the next hop. It occupies the four octets after the
    /// subnet mask that are reserved/zero in RIPv1. This is an explicit,
    /// discoverable alias of [`next_hop`] for fluent RIPv2 entry construction.
    ///
    /// [`next_hop`]: RipEntry::next_hop
    pub fn with_next_hop(mut self, next_hop: Ipv4Addr) -> RipEntry {
        self.next_hop.set_user(next_hop);
        self
    }

    /// Whether this entry's next hop is the RFC 2453 §4.4 default (`0.0.0.0`).
    ///
    /// Returns `true` when [`next_hop_value`] equals [`Ipv4Addr::UNSPECIFIED`]
    /// (`0.0.0.0`), which RFC 2453 §4.4 defines as meaning the originator of the
    /// advertisement is the next hop.
    ///
    /// [`next_hop_value`]: RipEntry::next_hop_value
    pub fn next_hop_is_default(&self) -> bool {
        self.next_hop_value() == Ipv4Addr::UNSPECIFIED
    }

    /// Set the metric (caller-set).
    pub fn metric(mut self, value: u32) -> Self {
        self.metric.set_user(value);
        self
    }

    /// Effective address family identifier (caller-set or default).
    pub fn address_family_value(&self) -> u16 {
        self.address_family.value().copied().unwrap_or(RIP_AFI_IP)
    }

    /// Effective route tag (caller-set or default).
    pub fn route_tag_value(&self) -> u16 {
        self.route_tag.value().copied().unwrap_or(0)
    }

    /// Effective IPv4 destination address (caller-set or default).
    pub fn address_value(&self) -> Ipv4Addr {
        self.address
            .value()
            .copied()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// Effective subnet mask (caller-set or default).
    pub fn subnet_mask_value(&self) -> Ipv4Addr {
        self.subnet_mask
            .value()
            .copied()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// Best-effort CIDR prefix length derived from the effective subnet mask.
    ///
    /// Returns the number of one-bits in [`subnet_mask_value`] read as a
    /// big-endian 32-bit integer. This is purely derived and does **not** assume
    /// the mask is contiguous: a non-contiguous mask (for example `255.0.255.0`,
    /// which a generated tool may set on purpose) still returns its raw set-bit
    /// count, so the value is a best-effort length rather than a validated CIDR
    /// prefix. For a contiguous mask the result is the conventional prefix length
    /// (`255.255.255.0` yields `24`, `0.0.0.0` yields `0`).
    ///
    /// [`subnet_mask_value`]: RipEntry::subnet_mask_value
    pub fn prefix_len(&self) -> u8 {
        u32::from(self.subnet_mask_value()).count_ones() as u8
    }

    /// Effective next hop (caller-set or default).
    pub fn next_hop_value(&self) -> Ipv4Addr {
        self.next_hop
            .value()
            .copied()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// Effective metric (caller-set or default).
    pub fn metric_value(&self) -> u32 {
        self.metric.value().copied().unwrap_or(0)
    }

    /// Whether this entry's metric marks the destination as unreachable.
    ///
    /// A metric of [`RIP_METRIC_INFINITY`] (16) or greater means the
    /// destination is unreachable (RFC 1058 §3.1).
    pub fn is_unreachable(&self) -> bool {
        self.metric_value() >= RIP_METRIC_INFINITY
    }

    /// Whether this entry is a RIPv2 authentication marker entry.
    ///
    /// Returns `true` when the address family is the AFI 0xFFFF authentication
    /// marker (RFC 2453 §4.1).
    pub fn is_auth_marker(&self) -> bool {
        is_rip_auth_marker(self.address_family_value())
    }

    /// Build the request-whole-table sentinel entry (RFC 1058 §3.4.1,
    /// RFC 2453 §3.9.1).
    ///
    /// A RIP Request that asks for the entire routing table is encoded as a
    /// single route entry whose Address Family Identifier is `0` and whose
    /// Metric is [`RIP_METRIC_INFINITY`] (16), with all addresses `0.0.0.0`.
    /// This is the sole-entry sentinel for a complete-table request, not an
    /// ordinary route. The address family is marked caller-set so the
    /// distinguished `0` survives `compile()` instead of being defaulted to
    /// [`RIP_AFI_IP`].
    pub fn whole_table_request() -> Self {
        let mut entry = Self::new();
        entry.address_family.set_user(0);
        entry.metric.set_user(RIP_METRIC_INFINITY);
        entry
    }

    /// Whether this entry is the request-whole-table sentinel (RFC 1058
    /// §3.4.1, RFC 2453 §3.9.1).
    ///
    /// Returns `true` when the address family is `0` and the metric is
    /// [`RIP_METRIC_INFINITY`] (16), the distinguished encoding of a
    /// complete-table request carried as the sole route entry.
    pub fn is_whole_table_request(&self) -> bool {
        self.address_family_value() == 0 && self.metric_value() == RIP_METRIC_INFINITY
    }

    /// Serialize this route entry to its 20-octet big-endian wire form.
    ///
    /// Appends, in RFC 2453 §4 order: Address Family (u16), Route Tag (u16),
    /// IPv4 Address (4 octets), Subnet Mask (4 octets), Next Hop (4 octets),
    /// Metric (u32). Effective values are used as-is, so caller-set overrides
    /// (including deliberately wrong ones) serialize exactly as set.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.address_family_value().to_be_bytes());
        out.extend_from_slice(&self.route_tag_value().to_be_bytes());
        out.extend_from_slice(&self.address_value().octets());
        out.extend_from_slice(&self.subnet_mask_value().octets());
        out.extend_from_slice(&self.next_hop_value().octets());
        out.extend_from_slice(&self.metric_value().to_be_bytes());
    }

    /// Encoded length of a route entry, in octets. Always [`RIP_ENTRY_LEN`].
    pub const fn encoded_len(&self) -> usize {
        RIP_ENTRY_LEN
    }

    /// Parse a 20-octet route entry from the front of `bytes`.
    ///
    /// Reads the six fields in RFC 2453 §4 order (big-endian): Address Family
    /// (u16), Route Tag (u16), IPv4 Address (4 octets), Subnet Mask (4 octets),
    /// Next Hop (4 octets), Metric (u32). Every field is marked caller-set via
    /// `set_user`, so a decoded entry re-`encode`s byte-for-byte.
    ///
    /// A buffer shorter than [`RIP_ENTRY_LEN`] yields the crate's structured
    /// [`CrafterError::buffer_too_short`] (context `"RIP route entry"`,
    /// `required = RIP_ENTRY_LEN`, `available = bytes.len()`) rather than
    /// panicking.
    #[allow(dead_code)]
    pub(crate) fn decode(bytes: &[u8]) -> Result<RipEntry> {
        if bytes.len() < RIP_ENTRY_LEN {
            return Err(CrafterError::buffer_too_short(
                "RIP route entry",
                RIP_ENTRY_LEN,
                bytes.len(),
            ));
        }

        let address_family = u16::from_be_bytes([bytes[0], bytes[1]]);
        let route_tag = u16::from_be_bytes([bytes[2], bytes[3]]);
        let address = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
        let subnet_mask = Ipv4Addr::new(bytes[8], bytes[9], bytes[10], bytes[11]);
        let next_hop = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        let metric = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);

        let mut entry = RipEntry::new();
        entry.address_family.set_user(address_family);
        entry.route_tag.set_user(route_tag);
        entry.address.set_user(address);
        entry.subnet_mask.set_user(subnet_mask);
        entry.next_hop.set_user(next_hop);
        entry.metric.set_user(metric);
        Ok(entry)
    }
}

impl Default for RipEntry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod rip_entry_builder_sets_fields {
    use super::*;

    #[test]
    fn builders_set_and_read_back_each_field() {
        let address = Ipv4Addr::new(192, 0, 2, 1);
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let next_hop = Ipv4Addr::new(192, 0, 2, 254);

        let entry = RipEntry::new()
            .address_family(RIP_AFI_IP)
            .route_tag(0xABCD)
            .address(address)
            .subnet_mask(mask)
            .next_hop(next_hop)
            .metric(7);

        assert_eq!(entry.address_family_value(), RIP_AFI_IP);
        assert_eq!(entry.route_tag_value(), 0xABCD);
        assert_eq!(entry.address_value(), address);
        assert_eq!(entry.subnet_mask_value(), mask);
        assert_eq!(entry.next_hop_value(), next_hop);
        assert_eq!(entry.metric_value(), 7);

        // Builders mark every touched field as caller-set.
        assert!(entry.address_family.is_user_set());
        assert!(entry.route_tag.is_user_set());
        assert!(entry.address.is_user_set());
        assert!(entry.subnet_mask.is_user_set());
        assert!(entry.next_hop.is_user_set());
        assert!(entry.metric.is_user_set());
    }

    #[test]
    fn defaults_are_present_but_not_user_set() {
        let entry = RipEntry::new();

        assert_eq!(entry.address_family_value(), RIP_AFI_IP);
        assert_eq!(entry.route_tag_value(), 0);
        assert_eq!(entry.address_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(entry.subnet_mask_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(entry.next_hop_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(entry.metric_value(), 0);

        assert!(entry.address_family.is_defaulted());
        assert!(entry.route_tag.is_defaulted());
        assert!(entry.address.is_defaulted());
        assert!(entry.subnet_mask.is_defaulted());
        assert!(entry.next_hop.is_defaulted());
        assert!(entry.metric.is_defaulted());
    }
}

#[cfg(test)]
mod rip_entry_encodes_20_octets_be {
    use super::*;

    #[test]
    fn encodes_fields_in_big_endian_order() {
        let entry = RipEntry::new()
            .address_family(2)
            .route_tag(0x1234)
            .address(Ipv4Addr::new(192, 0, 2, 1))
            .subnet_mask(Ipv4Addr::new(255, 255, 255, 0))
            .next_hop(Ipv4Addr::new(192, 0, 2, 254))
            .metric(3);

        let mut out = Vec::new();
        entry.encode(&mut out);

        let expected: [u8; 20] = [
            0x00, 0x02, // address family = 2
            0x12, 0x34, // route tag = 0x1234
            192, 0, 2, 1, // address = 192.0.2.1
            255, 255, 255, 0, // subnet mask = 255.255.255.0
            192, 0, 2, 254, // next hop = 192.0.2.254
            0x00, 0x00, 0x00, 0x03, // metric = 3
        ];

        assert_eq!(out, expected);
        assert_eq!(out.len(), RIP_ENTRY_LEN);
        assert_eq!(entry.encoded_len(), RIP_ENTRY_LEN);
    }
}

#[cfg(test)]
mod rip_entry_preserves_user_values {
    use super::*;

    #[test]
    fn out_of_range_metric_serializes_exactly() {
        let entry = RipEntry::new().metric(0xDEAD_BEEF);

        let mut out = Vec::new();
        entry.encode(&mut out);

        // Metric occupies the final 4 octets of the 20-octet entry.
        assert_eq!(&out[16..20], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(out.len(), RIP_ENTRY_LEN);
    }
}

#[cfg(test)]
mod rip_entry_decode_roundtrip {
    use super::*;

    #[test]
    fn decode_reproduces_fields_and_reencodes_identically() {
        let entry = RipEntry::new()
            .address_family(2)
            .route_tag(0x1234)
            .address(Ipv4Addr::new(192, 0, 2, 1))
            .subnet_mask(Ipv4Addr::new(255, 255, 255, 0))
            .next_hop(Ipv4Addr::new(192, 0, 2, 254))
            .metric(3);

        let mut bytes = Vec::new();
        entry.encode(&mut bytes);

        let decoded = RipEntry::decode(&bytes).expect("20 octets decode");

        assert_eq!(decoded.address_family_value(), entry.address_family_value());
        assert_eq!(decoded.route_tag_value(), entry.route_tag_value());
        assert_eq!(decoded.address_value(), entry.address_value());
        assert_eq!(decoded.subnet_mask_value(), entry.subnet_mask_value());
        assert_eq!(decoded.next_hop_value(), entry.next_hop_value());
        assert_eq!(decoded.metric_value(), entry.metric_value());

        // Every decoded field is marked caller-set, so re-encoding is exact.
        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, bytes);
    }
}

#[cfg(test)]
mod rip_entry_decode_truncated_is_error {
    use super::*;

    #[test]
    fn short_slice_returns_structured_error_without_panic() {
        let short = [0u8; 10];

        let err = RipEntry::decode(&short).expect_err("10 octets is too short");

        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert!(
                    context.contains("entry"),
                    "context should mention the entry, got {context:?}"
                );
                assert_eq!(required, RIP_ENTRY_LEN);
                assert_eq!(available, short.len());
            }
            other => panic!("expected BufferTooShort, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod rip_entry_v1_v2_constructors {
    use super::*;

    #[test]
    fn ipv1_route_leaves_mask_and_next_hop_zero() {
        let address = Ipv4Addr::new(192, 0, 2, 1);
        let entry = RipEntry::ipv1_route(address, 5);

        assert_eq!(entry.address_family_value(), RIP_AFI_IP);
        assert_eq!(entry.address_value(), address);
        assert_eq!(entry.metric_value(), 5);
        // RIPv1 leaves route tag, subnet mask, and next hop at zero.
        assert_eq!(entry.route_tag_value(), 0);
        assert_eq!(entry.subnet_mask_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(entry.next_hop_value(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn ipv2_route_sets_mask_and_defaults_next_hop() {
        let address = Ipv4Addr::new(192, 0, 2, 1);
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let entry = RipEntry::ipv2_route(address, mask, 7);

        assert_eq!(entry.address_family_value(), RIP_AFI_IP);
        assert_eq!(entry.address_value(), address);
        assert_eq!(entry.subnet_mask_value(), mask);
        assert_eq!(entry.metric_value(), 7);
        // Next hop defaults to 0.0.0.0 (the route originator).
        assert_eq!(entry.next_hop_value(), Ipv4Addr::UNSPECIFIED);
    }
}

#[cfg(test)]
mod rip_entry_reachability {
    use super::*;

    #[test]
    fn is_unreachable_at_infinity_metric() {
        let address = Ipv4Addr::new(192, 0, 2, 1);

        let reachable = RipEntry::ipv1_route(address, RIP_METRIC_INFINITY - 1);
        assert!(!reachable.is_unreachable());

        let unreachable = RipEntry::ipv1_route(address, RIP_METRIC_INFINITY);
        assert!(unreachable.is_unreachable());
    }
}

#[cfg(test)]
mod rip_entry_whole_table_request {
    use super::*;

    #[test]
    fn sentinel_round_trips_and_is_recognized() {
        let sentinel = RipEntry::whole_table_request();

        // RFC 1058 §3.4.1 / RFC 2453 §3.9.1: AFI 0, metric 16, addresses 0.
        assert_eq!(sentinel.address_family_value(), 0);
        assert_eq!(sentinel.metric_value(), RIP_METRIC_INFINITY);
        assert_eq!(sentinel.address_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(sentinel.subnet_mask_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(sentinel.next_hop_value(), Ipv4Addr::UNSPECIFIED);

        // The predicate recognizes the sentinel.
        assert!(sentinel.is_whole_table_request());

        // Round-trips byte-for-byte through encode/decode and stays recognized.
        let mut bytes = Vec::new();
        sentinel.encode(&mut bytes);
        assert_eq!(bytes.len(), RIP_ENTRY_LEN);

        let decoded = RipEntry::decode(&bytes).expect("20 octets decode");
        assert_eq!(decoded.address_family_value(), 0);
        assert_eq!(decoded.metric_value(), RIP_METRIC_INFINITY);
        assert!(decoded.is_whole_table_request());

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, bytes);
    }

    #[test]
    fn normal_route_is_not_a_whole_table_request() {
        let route = RipEntry::ipv2_route(
            Ipv4Addr::new(192, 0, 2, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            3,
        );

        assert!(!route.is_whole_table_request());
    }
}

#[cfg(test)]
mod rip_entry_route_tag_roundtrips {
    use super::*;

    #[test]
    fn nonzero_tag_round_trips_through_encode_decode() {
        // RFC 2453 §3.1: the 2-octet route tag is opaque to RIP and must be
        // carried unchanged. Build a RIPv2 route and set a distinctive tag.
        let entry = RipEntry::ipv2_route(
            Ipv4Addr::new(192, 0, 2, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            3,
        )
        .with_route_tag(0xABCD);

        assert_eq!(entry.route_tag_value(), 0xABCD);

        let mut bytes = Vec::new();
        entry.encode(&mut bytes);

        // Route tag occupies the two octets after the address family
        // (RFC 2453 §4): bytes 2..4 of the 20-octet entry.
        assert_eq!(&bytes[2..4], &[0xAB, 0xCD]);

        let decoded = RipEntry::decode(&bytes).expect("20 octets decode");
        assert_eq!(decoded.route_tag_value(), 0xABCD);
    }
}

#[cfg(test)]
mod rip_entry_v1_route_tag_zero {
    use super::*;

    #[test]
    fn ipv1_route_encodes_zero_route_tag() {
        // RFC 1058: RIPv1 entries leave the route-tag octets zero.
        let entry = RipEntry::ipv1_route(Ipv4Addr::new(192, 0, 2, 1), 5);

        assert_eq!(entry.route_tag_value(), 0);

        let mut bytes = Vec::new();
        entry.encode(&mut bytes);

        // Bytes 2..4 (the route-tag field) must be zero in RIPv1.
        assert_eq!(&bytes[2..4], &[0x00, 0x00]);
    }
}

#[cfg(test)]
mod rip_entry_prefix_len_helpers {
    use super::*;

    #[test]
    fn with_prefix_len_and_prefix_len_round_trip_contiguous_masks() {
        // RFC 2453 §4: a /24 is the contiguous mask 255.255.255.0.
        let slash24 = RipEntry::new().with_prefix_len(24);
        assert_eq!(slash24.subnet_mask_value(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(slash24.prefix_len(), 24);
        assert!(slash24.subnet_mask.is_user_set());

        // A /0 is the all-zero mask 0.0.0.0.
        let slash0 = RipEntry::new().with_prefix_len(0);
        assert_eq!(slash0.subnet_mask_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(slash0.prefix_len(), 0);

        // A /32 is the all-ones mask 255.255.255.255.
        let slash32 = RipEntry::new().with_prefix_len(32);
        assert_eq!(
            slash32.subnet_mask_value(),
            Ipv4Addr::new(255, 255, 255, 255)
        );
        assert_eq!(slash32.prefix_len(), 32);
    }
}

#[cfg(test)]
mod rip_entry_noncontiguous_mask_preserved {
    use super::*;

    #[test]
    fn noncontiguous_mask_octets_serialize_exactly() {
        // A deliberately non-contiguous mask (honored override for malformed
        // packets) must serialize byte-for-byte as set, not be normalized.
        let mask = Ipv4Addr::new(255, 0, 255, 0);
        let entry = RipEntry::new().subnet_mask(mask);

        assert_eq!(entry.subnet_mask_value(), mask);

        let mut bytes = Vec::new();
        entry.encode(&mut bytes);

        // Subnet mask occupies bytes 8..12 of the 20-octet entry (RFC 2453 §4).
        assert_eq!(&bytes[8..12], &[255, 0, 255, 0]);
    }
}

#[cfg(test)]
mod rip_entry_next_hop_roundtrips {
    use super::*;

    #[test]
    fn next_hop_octets_round_trip_through_encode_decode() {
        // RFC 2453 §4.4: the 4-octet next hop carries the immediate next-hop IP.
        let next_hop = Ipv4Addr::new(192, 0, 2, 254);
        let entry = RipEntry::ipv2_route(
            Ipv4Addr::new(192, 0, 2, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            3,
        )
        .with_next_hop(next_hop);

        assert_eq!(entry.next_hop_value(), next_hop);
        assert!(!entry.next_hop_is_default());

        let mut bytes = Vec::new();
        entry.encode(&mut bytes);

        // Next hop occupies bytes 12..16 of the 20-octet entry (RFC 2453 §4).
        assert_eq!(&bytes[12..16], &[192, 0, 2, 254]);

        let decoded = RipEntry::decode(&bytes).expect("20 octets decode");
        assert_eq!(decoded.next_hop_value(), next_hop);
        assert!(!decoded.next_hop_is_default());
    }
}

#[cfg(test)]
mod rip_entry_next_hop_default {
    use super::*;

    #[test]
    fn fresh_ipv2_route_reports_default_next_hop() {
        // RFC 2453 §4.4: a next hop of 0.0.0.0 is the default (route originator).
        let entry = RipEntry::ipv2_route(
            Ipv4Addr::new(192, 0, 2, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            3,
        );

        assert_eq!(entry.next_hop_value(), Ipv4Addr::UNSPECIFIED);
        assert!(entry.next_hop_is_default());
    }
}
