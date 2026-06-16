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

use super::constants::{RIP_AFI_IP, RIP_ENTRY_LEN};

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

    /// Set the next hop (caller-set).
    pub fn next_hop(mut self, value: Ipv4Addr) -> Self {
        self.next_hop.set_user(value);
        self
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
        self.address.value().copied().unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// Effective subnet mask (caller-set or default).
    pub fn subnet_mask_value(&self) -> Ipv4Addr {
        self.subnet_mask
            .value()
            .copied()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
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
