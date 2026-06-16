//! RIPng route table entry (RTE) model (RFC 2080 §2.1).
//!
//! A RIPng RTE is the fixed 20-octet record that follows the 4-octet RIPng
//! header. It carries:
//!
//! - IPv6 prefix (16 octets).
//! - Route Tag (2 octets).
//! - Prefix Length (1 octet).
//! - Metric (1 octet).
//!
//! This module defines the [`RipngRte`] type and its chainable builders. The
//! values are held in [`Field`] wrappers so a later `compile()` step can fill
//! defaults only when the caller left a field unset and leave caller-set values
//! untouched. Compile/decode behavior and the next-hop RTE follow in later
//! steps.

use std::net::Ipv6Addr;

use crate::error::{CrafterError, Result};
use crate::field::Field;

use super::constants::RIPNG_RTE_LEN;

/// A single 20-octet RIPng route table entry (RFC 2080 §2.1).
///
/// Every field is held in a [`Field`] wrapper so that the builders mark values
/// the caller set explicitly (`set_user`), while `new()` installs library
/// defaults. The `*_value()` accessors return the effective value regardless of
/// whether it was caller-set or defaulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RipngRte {
    /// IPv6 destination prefix (RFC 2080 §2.1).
    pub prefix: Field<Ipv6Addr>,
    /// Route Tag (RFC 2080 §2.1).
    pub route_tag: Field<u16>,
    /// Prefix Length (RFC 2080 §2.1; significant bits of the prefix).
    pub prefix_len: Field<u8>,
    /// Metric (RFC 2080 §2.1; `0xFF` marks a next-hop RTE).
    pub metric: Field<u8>,
}

impl RipngRte {
    /// Create a RIPng RTE with library defaults.
    ///
    /// The prefix defaults to `::`, and the route tag, prefix length, and
    /// metric to `0`. None of these defaults are marked as caller-set, so a
    /// later `compile()` step may overwrite them.
    pub fn new() -> Self {
        Self {
            prefix: Field::defaulted(Ipv6Addr::UNSPECIFIED),
            route_tag: Field::defaulted(0),
            prefix_len: Field::defaulted(0),
            metric: Field::defaulted(0),
        }
    }

    /// Build a RIPng route RTE (RFC 2080 §2.1).
    ///
    /// Sets the IPv6 `prefix`, the `prefix_len`, and the `metric`, all as
    /// caller-set values. The route tag is left at its zero default.
    pub fn route(prefix: Ipv6Addr, prefix_len: u8, metric: u8) -> Self {
        let mut rte = Self::new();
        rte.prefix.set_user(prefix);
        rte.prefix_len.set_user(prefix_len);
        rte.metric.set_user(metric);
        rte
    }

    /// Set the IPv6 prefix (caller-set).
    pub fn prefix(mut self, value: Ipv6Addr) -> Self {
        self.prefix.set_user(value);
        self
    }

    /// Set the route tag (caller-set).
    pub fn route_tag(mut self, value: u16) -> Self {
        self.route_tag.set_user(value);
        self
    }

    /// Set the prefix length (caller-set).
    pub fn prefix_len(mut self, value: u8) -> Self {
        self.prefix_len.set_user(value);
        self
    }

    /// Set the metric (caller-set).
    pub fn metric(mut self, value: u8) -> Self {
        self.metric.set_user(value);
        self
    }

    /// Effective IPv6 prefix (caller-set or default).
    pub fn prefix_value(&self) -> Ipv6Addr {
        self.prefix.value().copied().unwrap_or(Ipv6Addr::UNSPECIFIED)
    }

    /// Effective route tag (caller-set or default).
    pub fn route_tag_value(&self) -> u16 {
        self.route_tag.value().copied().unwrap_or(0)
    }

    /// Effective prefix length (caller-set or default).
    pub fn prefix_len_value(&self) -> u8 {
        self.prefix_len.value().copied().unwrap_or(0)
    }

    /// Effective metric (caller-set or default).
    pub fn metric_value(&self) -> u8 {
        self.metric.value().copied().unwrap_or(0)
    }

    /// Serialize this RTE to its 20-octet big-endian wire form (RFC 2080 §2.1).
    ///
    /// Appends, in order: the IPv6 prefix (16 octets), Route Tag (u16), Prefix
    /// Length (u8), Metric (u8). Effective values are used as-is, so caller-set
    /// overrides (including deliberately wrong prefix lengths) serialize exactly
    /// as set.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.prefix_value().octets());
        out.extend_from_slice(&self.route_tag_value().to_be_bytes());
        out.push(self.prefix_len_value());
        out.push(self.metric_value());
    }

    /// Encoded length of a RIPng RTE, in octets. Always [`RIPNG_RTE_LEN`].
    pub const fn encoded_len(&self) -> usize {
        RIPNG_RTE_LEN
    }

    /// Parse a 20-octet RIPng RTE from the front of `bytes` (RFC 2080 §2.1).
    ///
    /// Reads the four fields in RFC 2080 §2.1 order (big-endian): IPv6 prefix
    /// (16 octets), Route Tag (u16), Prefix Length (u8), Metric (u8). Every
    /// field is marked caller-set via `set_user`, so a decoded RTE re-`encode`s
    /// byte-for-byte.
    ///
    /// A buffer shorter than [`RIPNG_RTE_LEN`] yields the crate's structured
    /// [`CrafterError::buffer_too_short`] (context `"RIPng route table entry"`,
    /// `required = RIPNG_RTE_LEN`, `available = bytes.len()`) rather than
    /// panicking.
    #[allow(dead_code)]
    pub(crate) fn decode(bytes: &[u8]) -> Result<RipngRte> {
        if bytes.len() < RIPNG_RTE_LEN {
            return Err(CrafterError::buffer_too_short(
                "RIPng route table entry",
                RIPNG_RTE_LEN,
                bytes.len(),
            ));
        }

        let mut prefix_octets = [0u8; 16];
        prefix_octets.copy_from_slice(&bytes[0..16]);
        let prefix = Ipv6Addr::from(prefix_octets);
        let route_tag = u16::from_be_bytes([bytes[16], bytes[17]]);
        let prefix_len = bytes[18];
        let metric = bytes[19];

        let mut rte = RipngRte::new();
        rte.prefix.set_user(prefix);
        rte.route_tag.set_user(route_tag);
        rte.prefix_len.set_user(prefix_len);
        rte.metric.set_user(metric);
        Ok(rte)
    }
}

impl Default for RipngRte {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod ripng_rte_builder_sets_fields {
    use super::*;

    #[test]
    fn builders_set_and_read_back_each_field() {
        let prefix = "2001:db8::".parse::<Ipv6Addr>().expect("valid prefix");

        let rte = RipngRte::new()
            .prefix(prefix)
            .route_tag(0xABCD)
            .prefix_len(64)
            .metric(7);

        assert_eq!(rte.prefix_value(), prefix);
        assert_eq!(rte.route_tag_value(), 0xABCD);
        assert_eq!(rte.prefix_len_value(), 64);
        assert_eq!(rte.metric_value(), 7);

        // Builders mark every touched field as caller-set.
        assert!(rte.prefix.is_user_set());
        assert!(rte.route_tag.is_user_set());
        assert!(rte.prefix_len.is_user_set());
        assert!(rte.metric.is_user_set());
    }

    #[test]
    fn defaults_are_present_but_not_user_set() {
        let rte = RipngRte::new();

        assert_eq!(rte.prefix_value(), Ipv6Addr::UNSPECIFIED);
        assert_eq!(rte.route_tag_value(), 0);
        assert_eq!(rte.prefix_len_value(), 0);
        assert_eq!(rte.metric_value(), 0);

        assert!(rte.prefix.is_defaulted());
        assert!(rte.route_tag.is_defaulted());
        assert!(rte.prefix_len.is_defaulted());
        assert!(rte.metric.is_defaulted());
    }

    #[test]
    fn route_constructor_sets_prefix_len_metric_user() {
        let prefix = "2001:db8:1::".parse::<Ipv6Addr>().expect("valid prefix");

        let rte = RipngRte::route(prefix, 48, 3);

        assert_eq!(rte.prefix_value(), prefix);
        assert_eq!(rte.prefix_len_value(), 48);
        assert_eq!(rte.metric_value(), 3);
        assert_eq!(rte.route_tag_value(), 0);

        assert!(rte.prefix.is_user_set());
        assert!(rte.prefix_len.is_user_set());
        assert!(rte.metric.is_user_set());
        // Route tag is left at its zero default by the route() constructor.
        assert!(rte.route_tag.is_defaulted());
    }
}

#[cfg(test)]
mod ripng_rte_encodes_20_octets_be {
    use super::*;

    #[test]
    fn encodes_fields_in_big_endian_order() {
        let prefix = "2001:db8::".parse::<Ipv6Addr>().expect("valid prefix");

        let rte = RipngRte::route(prefix, 32, 3).route_tag(0x1234);

        let mut out = Vec::new();
        rte.encode(&mut out);

        // RFC 2080 §2.1: IPv6 prefix (16), Route Tag (u16 be), Prefix Length
        // (u8), Metric (u8).
        let mut expected = Vec::new();
        expected.extend_from_slice(&prefix.octets()); // 16 prefix octets
        expected.extend_from_slice(&[0x12, 0x34]); // route tag = 0x1234
        expected.push(0x20); // prefix length = 32
        expected.push(0x03); // metric = 3

        assert_eq!(out, expected);
        assert_eq!(out.len(), RIPNG_RTE_LEN);
        assert_eq!(rte.encoded_len(), RIPNG_RTE_LEN);
    }
}

#[cfg(test)]
mod ripng_rte_preserves_user_values {
    use super::*;

    #[test]
    fn out_of_range_prefix_len_serializes_exactly() {
        // A prefix length of 200 is invalid but caller-set; the serializer must
        // honor the override and emit it byte-for-byte (0xC8), not clamp it.
        let prefix = "2001:db8::".parse::<Ipv6Addr>().expect("valid prefix");
        let rte = RipngRte::route(prefix, 200, 3);

        let mut out = Vec::new();
        rte.encode(&mut out);

        // Prefix length occupies octet 18 of the 20-octet RTE (RFC 2080 §2.1).
        assert_eq!(out[18], 0xC8);
        assert_eq!(out.len(), RIPNG_RTE_LEN);
    }
}

#[cfg(test)]
mod ripng_rte_decode_roundtrip {
    use super::*;

    #[test]
    fn decode_reproduces_fields_and_reencodes_identically() {
        let prefix = "2001:db8::".parse::<Ipv6Addr>().expect("valid prefix");

        let rte = RipngRte::route(prefix, 32, 3).route_tag(0x1234);

        let mut bytes = Vec::new();
        rte.encode(&mut bytes);

        let decoded = RipngRte::decode(&bytes).expect("20 octets decode");

        assert_eq!(decoded.prefix_value(), rte.prefix_value());
        assert_eq!(decoded.route_tag_value(), rte.route_tag_value());
        assert_eq!(decoded.prefix_len_value(), rte.prefix_len_value());
        assert_eq!(decoded.metric_value(), rte.metric_value());

        // Every decoded field is marked caller-set, so re-encoding is exact.
        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, bytes);
    }
}

#[cfg(test)]
mod ripng_rte_decode_truncated_is_error {
    use super::*;

    #[test]
    fn short_slice_returns_structured_error_without_panic() {
        // 12 octets is fewer than the fixed 20-octet RTE (RFC 2080 §2.1).
        let short = [0u8; 12];

        let err = RipngRte::decode(&short).expect_err("12 octets is too short");

        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert!(
                    context.contains("RIPng"),
                    "context should mention the RIPng RTE, got {context:?}"
                );
                assert_eq!(required, RIPNG_RTE_LEN);
                assert_eq!(available, short.len());
            }
            other => panic!("expected BufferTooShort, got {other:?}"),
        }
    }
}
