//! Ordered, lossless CoAP option primitives.

use super::registry::{
    coap_option_is_critical, coap_option_is_no_cache_key, coap_option_is_safe_to_forward,
    coap_option_is_unsafe, coap_option_meta, CoapRegistryMeta,
};

/// Lossless CoAP datagram Option Number.
///
/// The wrapper is open over the complete 16-bit option-number space. Registry
/// assignment is inspection metadata only: reserved, unassigned,
/// experimental, and future values remain representable without truncation or
/// normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CoapOptionNumber(u16);

impl CoapOptionNumber {
    /// Build an option number from its complete decoded wire value.
    pub const fn from_wire(value: u16) -> Self {
        Self(value)
    }

    /// Return the preserved 16-bit option number.
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Return source-backed registry metadata without gating this value.
    pub fn registry_meta(self) -> CoapRegistryMeta {
        coap_option_meta(self.value())
    }

    /// Return whether this option is critical (option-number bit zero set).
    ///
    /// A false result means the option is elective.
    pub const fn is_critical(self) -> bool {
        coap_option_is_critical(self.value())
    }

    /// Return whether this option is unsafe to forward (bit one set).
    pub const fn is_unsafe(self) -> bool {
        coap_option_is_unsafe(self.value())
    }

    /// Return whether this option is safe to forward (bit one clear).
    pub const fn is_safe_to_forward(self) -> bool {
        coap_option_is_safe_to_forward(self.value())
    }

    /// Return whether this safe-to-forward option is excluded from cache keys.
    ///
    /// RFC 7252 derives this property from bits one through four. It therefore
    /// remains meaningful for unassigned and future option numbers.
    pub const fn is_no_cache_key(self) -> bool {
        coap_option_is_no_cache_key(self.value())
    }
}

impl From<u16> for CoapOptionNumber {
    fn from(value: u16) -> Self {
        Self::from_wire(value)
    }
}

impl From<CoapOptionNumber> for u16 {
    fn from(number: CoapOptionNumber) -> Self {
        number.value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::coap::constants::*;
    use crate::protocols::coap::registry::CoapRegistryStatus;

    #[test]
    fn admitted_option_constants_match_the_reviewed_registry() {
        let cases = [
            (COAP_OPTION_IF_MATCH, 1, "If-Match"),
            (COAP_OPTION_URI_HOST, 3, "Uri-Host"),
            (COAP_OPTION_ETAG, 4, "ETag"),
            (COAP_OPTION_IF_NONE_MATCH, 5, "If-None-Match"),
            (COAP_OPTION_OBSERVE, 6, "Observe"),
            (COAP_OPTION_URI_PORT, 7, "Uri-Port"),
            (COAP_OPTION_LOCATION_PATH, 8, "Location-Path"),
            (COAP_OPTION_OSCORE, 9, "OSCORE"),
            (COAP_OPTION_URI_PATH, 11, "Uri-Path"),
            (COAP_OPTION_CONTENT_FORMAT, 12, "Content-Format"),
            (COAP_OPTION_MAX_AGE, 14, "Max-Age"),
            (COAP_OPTION_URI_QUERY, 15, "Uri-Query"),
            (COAP_OPTION_HOP_LIMIT, 16, "Hop-Limit"),
            (COAP_OPTION_ACCEPT, 17, "Accept"),
            (COAP_OPTION_Q_BLOCK1, 19, "Q-Block1"),
            (COAP_OPTION_LOCATION_QUERY, 20, "Location-Query"),
            (COAP_OPTION_BLOCK2, 23, "Block2"),
            (COAP_OPTION_BLOCK1, 27, "Block1"),
            (COAP_OPTION_SIZE2, 28, "Size2"),
            (COAP_OPTION_Q_BLOCK2, 31, "Q-Block2"),
            (COAP_OPTION_PROXY_URI, 35, "Proxy-Uri"),
            (COAP_OPTION_PROXY_SCHEME, 39, "Proxy-Scheme"),
            (COAP_OPTION_SIZE1, 60, "Size1"),
            (COAP_OPTION_ECHO, 252, "Echo"),
            (COAP_OPTION_NO_RESPONSE, 258, "No-Response"),
            (COAP_OPTION_REQUEST_TAG, 292, "Request-Tag"),
        ];

        for (constant, expected, label) in cases {
            let number = CoapOptionNumber::from_wire(constant);
            assert_eq!(constant, expected);
            assert_eq!(number.value(), expected);
            assert_eq!(number.registry_meta().label, label);
            assert_eq!(number.registry_meta().status, CoapRegistryStatus::Assigned);
        }
    }

    #[test]
    fn option_number_preserves_boundaries_and_future_values() {
        for value in [0, 1, 292, 64999, 65000, u16::MAX] {
            let number = CoapOptionNumber::from(value);
            assert_eq!(number.value(), value);
            assert_eq!(u16::from(number), value);
        }

        let cases = [
            (0, "option-0", CoapRegistryStatus::Reserved),
            (2, "option-2", CoapRegistryStatus::Unassigned),
            (64999, "option-64999", CoapRegistryStatus::Unassigned),
            (65000, "option-65000", CoapRegistryStatus::Experimental),
            (u16::MAX, "option-65535", CoapRegistryStatus::Experimental),
        ];

        for (value, label, status) in cases {
            let metadata = CoapOptionNumber::from_wire(value).registry_meta();
            assert_eq!(metadata.value, u64::from(value));
            assert_eq!(metadata.label, label);
            assert_eq!(metadata.status, status);
        }
    }

    #[test]
    fn option_properties_are_derived_from_bits_across_the_full_domain() {
        for value in u16::MIN..=u16::MAX {
            let number = CoapOptionNumber::from_wire(value);

            assert_eq!(number.is_critical(), value & 1 != 0);
            assert_eq!(number.is_unsafe(), value & 2 != 0);
            assert_eq!(number.is_safe_to_forward(), value & 2 == 0);
            assert_eq!(number.is_no_cache_key(), value & 0x1e == 0x1c);
            assert_ne!(number.is_unsafe(), number.is_safe_to_forward());
        }

        let future = CoapOptionNumber::from_wire(65021);
        assert!(future.is_critical());
        assert!(!future.is_unsafe());
        assert!(future.is_safe_to_forward());
        assert!(future.is_no_cache_key());
        assert_eq!(
            future.registry_meta().status,
            CoapRegistryStatus::Experimental
        );
    }
}
