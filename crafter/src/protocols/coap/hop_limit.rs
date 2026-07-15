//! RFC 8768 Hop-Limit option values and safe decrement semantics.
//!
//! This module models only the packet-local option value. It never forwards a
//! request, chooses a proxy, or emits a Hop Limit Reached response.

use core::fmt;

use crate::error::{CrafterError, Result};

use super::constants::COAP_OPTION_HOP_LIMIT;
use super::option::CoapOption;
use super::registry::{coap_option_meta, CoapRegistryMeta};

/// One raw-preserving RFC 8768 Hop-Limit option value.
///
/// Hop-Limit is encoded in exactly one octet and its source-conformant range
/// is 1 through 255. [`Self::new`] deliberately retains zero as an explicit
/// malformed one-byte value for packet crafting. Use [`Self::try_new`] or
/// [`Self::validate`] when a source-conformant value is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoapHopLimit {
    remaining: u8,
}

/// Typed result returned when decrementing would produce or retain zero.
///
/// This result is packet-local metadata. It does not forward a request or
/// construct a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoapHopLimitExhausted;

impl CoapHopLimit {
    /// RFC 8768's default initial Hop-Limit value.
    pub const DEFAULT_INITIAL: u8 = 16;
    /// Smallest source-conformant Hop-Limit value.
    pub const MIN: u8 = 1;
    /// Largest source-conformant Hop-Limit value.
    pub const MAX: u8 = u8::MAX;

    /// Build an exact one-byte Hop-Limit value.
    ///
    /// Zero remains representable as an intentional malformed value. Call
    /// [`Self::validate`] to reject it.
    pub const fn new(remaining: u8) -> Self {
        Self { remaining }
    }

    /// Build a Hop-Limit after checking the RFC 8768 range.
    pub fn try_new(remaining: u8) -> Result<Self> {
        let value = Self::new(remaining);
        value.validate()?;
        Ok(value)
    }

    /// Build RFC 8768's default initial value of 16.
    pub const fn initial() -> Self {
        Self::new(Self::DEFAULT_INITIAL)
    }

    /// Return the exact remaining-hop octet.
    pub const fn remaining(&self) -> u8 {
        self.remaining
    }

    /// Borrow the exact one-byte option value.
    pub fn as_bytes(&self) -> &[u8] {
        core::slice::from_ref(&self.remaining)
    }

    /// Consume the wrapper and return the exact one-byte option value.
    pub fn into_bytes(self) -> Vec<u8> {
        vec![self.remaining]
    }

    /// Return current source-backed registry metadata for Hop-Limit.
    pub fn registry_meta(&self) -> CoapRegistryMeta {
        coap_option_meta(COAP_OPTION_HOP_LIMIT)
    }

    /// Check the RFC 8768 semantic range of 1 through 255.
    pub fn validate(&self) -> Result<()> {
        if self.remaining == 0 {
            return Err(CrafterError::invalid_field_value(
                "coap.hop-limit",
                "Hop-Limit must be between 1 and 255",
            ));
        }
        Ok(())
    }

    /// Decrement before a prospective forwarding operation.
    ///
    /// A remaining value of one would become zero and therefore returns the
    /// typed exhausted result. An explicitly malformed zero is also exhausted
    /// rather than wrapping to 255. This method performs no forwarding or I/O.
    pub const fn decrement(&self) -> core::result::Result<Self, CoapHopLimitExhausted> {
        if self.remaining <= Self::MIN {
            Err(CoapHopLimitExhausted)
        } else {
            Ok(Self::new(self.remaining - 1))
        }
    }
}

impl Default for CoapHopLimit {
    fn default() -> Self {
        Self::initial()
    }
}

impl From<u8> for CoapHopLimit {
    fn from(remaining: u8) -> Self {
        Self::new(remaining)
    }
}

impl From<CoapHopLimit> for CoapOption {
    fn from(value: CoapHopLimit) -> Self {
        CoapOption::new(COAP_OPTION_HOP_LIMIT, value.into_bytes())
    }
}

impl TryFrom<&CoapOption> for CoapHopLimit {
    type Error = CrafterError;

    fn try_from(option: &CoapOption) -> Result<Self> {
        if option.number().value() != COAP_OPTION_HOP_LIMIT {
            return Err(CrafterError::invalid_field_value(
                "coap.hop-limit",
                "option number is not Hop-Limit",
            ));
        }
        if option.value().len() != 1 {
            return Err(CrafterError::invalid_field_value(
                "coap.hop-limit",
                "Hop-Limit value must contain exactly one byte",
            ));
        }

        Ok(Self::new(option.value()[0]))
    }
}

impl fmt::Display for CoapHopLimitExhausted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CoAP Hop-Limit is exhausted")
    }
}

impl std::error::Error for CoapHopLimitExhausted {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;
    use crate::protocols::coap::{Coap, CoapRegistryStatus};

    fn compiled(value: impl Into<CoapOption>) -> Vec<u8> {
        Packet::from_layer(Coap::get().message_id(0x1234).option(value))
            .compile()
            .expect("Hop-Limit packet compiles")
            .into_bytes()
    }

    #[test]
    fn default_and_registry_metadata_are_source_backed() {
        let hop_limit = CoapHopLimit::default();
        assert_eq!(hop_limit.remaining(), 16);
        assert_eq!(hop_limit.as_bytes(), &[16]);
        assert_eq!(
            compiled(hop_limit),
            [0x40, 0x01, 0x12, 0x34, 0xd1, 0x03, 0x10]
        );

        let metadata = hop_limit.registry_meta();
        assert_eq!(metadata.value, 16);
        assert_eq!(metadata.label, "Hop-Limit");
        assert_eq!(metadata.status, CoapRegistryStatus::Assigned);
        assert_eq!(metadata.reference, Some("RFC 8768"));
    }

    #[test]
    fn zero_is_preserved_but_checked_construction_rejects_it() {
        let zero = CoapHopLimit::new(0);
        assert_eq!(zero.remaining(), 0);
        assert_eq!(zero.as_bytes(), &[0]);
        assert!(zero.validate().is_err());
        assert!(CoapHopLimit::try_new(0).is_err());
        assert_eq!(zero.decrement(), Err(CoapHopLimitExhausted));
        assert_eq!(compiled(zero), [0x40, 0x01, 0x12, 0x34, 0xd1, 0x03, 0x00]);

        let raw = CoapOption::new(COAP_OPTION_HOP_LIMIT, [0]);
        let decoded = CoapHopLimit::try_from(&raw).expect("one byte stays typed");
        assert_eq!(decoded.remaining(), 0);
        assert_eq!(CoapOption::from(decoded).value(), &[0]);
    }

    #[test]
    fn one_is_valid_but_decrement_reports_typed_exhaustion() {
        let one = CoapHopLimit::try_new(1).expect("one is in range");
        assert_eq!(one.decrement(), Err(CoapHopLimitExhausted));
        assert_eq!(compiled(one), [0x40, 0x01, 0x12, 0x34, 0xd1, 0x03, 0x01]);
    }

    #[test]
    fn maximum_and_intermediate_values_decrement_without_side_effects() {
        let maximum = CoapHopLimit::try_new(CoapHopLimit::MAX).unwrap();
        assert_eq!(maximum.remaining(), 255);
        assert_eq!(maximum.decrement().unwrap().remaining(), 254);
        assert_eq!(
            compiled(maximum),
            [0x40, 0x01, 0x12, 0x34, 0xd1, 0x03, 0xff]
        );

        let initial = CoapHopLimit::initial();
        let decremented = initial.decrement().unwrap();
        assert_eq!(initial.remaining(), 16);
        assert_eq!(decremented.remaining(), 15);
    }

    #[test]
    fn malformed_lengths_remain_raw_and_are_reported_by_message_validation() {
        let empty = CoapOption::new(COAP_OPTION_HOP_LIMIT, Vec::new());
        assert!(CoapHopLimit::try_from(&empty).is_err());
        assert_eq!(
            compiled(empty.clone()),
            [0x40, 0x01, 0x12, 0x34, 0xd0, 0x03]
        );

        let overlong = CoapOption::new(COAP_OPTION_HOP_LIMIT, [0, 2]);
        assert!(CoapHopLimit::try_from(&overlong).is_err());
        assert_eq!(
            compiled(overlong.clone()),
            [0x40, 0x01, 0x12, 0x34, 0xd2, 0x03, 0x00, 0x02]
        );

        for option in [empty, overlong] {
            let message = Coap::get().option(option);
            let validation = message.validate();
            assert!(validation.issues().iter().any(|issue| {
                issue.field() == "coap.options[0].value" && issue.reason().contains("exactly 1")
            }));
        }
    }

    #[test]
    fn message_helpers_and_prelude_export_preserve_exact_values() {
        let request = Coap::get().hop_limit(CoapHopLimit::initial());
        assert_eq!(request.hop_limit_value().unwrap().unwrap().remaining(), 16);

        let _: crate::prelude::CoapHopLimit = crate::prelude::CoapHopLimit::initial();
        let _: crate::prelude::CoapHopLimitExhausted = CoapHopLimitExhausted;
    }
}
