//! RFC 7641 Observe option values and stateless serial ordering.
//!
//! Observe registration state, notification scheduling, and refresh timers
//! belong to callers. This module only models exact option bytes and the
//! packet-local comparisons defined by RFC 7641 Sections 2, 3.4, and 4.4.

use core::time::Duration;

use crate::error::{CrafterError, Result};

use super::constants::COAP_OPTION_OBSERVE;
use super::option::CoapOption;

const OBSERVE_SERIAL_MODULUS: u32 = 1 << 24;
const OBSERVE_SERIAL_HALF_RANGE: u32 = 1 << 23;
const OBSERVE_REORDERING_TIMEOUT: Duration = Duration::from_secs(128);

/// One RFC 7641 Observe option value with its exact `uint` representation.
///
/// [`Self::new`] deliberately permits values above the 24-bit Observe range
/// so generated tools can construct malformed packets. Use [`Self::try_new`]
/// or [`Self::validate`] when a source-conformant value is required. Typed
/// conversion from a decoded [`CoapOption`] retains noncanonical zero-prefixed
/// integer bytes for exact re-encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoapObserve {
    value: u32,
    wire_value: Vec<u8>,
}

/// Stateless RFC 7641 ordering of an incoming Observe value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoapObserveOrdering {
    /// The incoming value is newer in 24-bit serial arithmetic.
    Newer,
    /// The incoming value is older in 24-bit serial arithmetic.
    Older,
    /// Both values are identical.
    Duplicate,
    /// The values are exactly half the serial space apart or are invalid.
    Ambiguous,
}

impl CoapObserveOrdering {
    /// Return whether the incoming value is newer.
    pub const fn is_newer(self) -> bool {
        matches!(self, Self::Newer)
    }

    /// Return whether the incoming value duplicates the freshest value.
    pub const fn is_duplicate(self) -> bool {
        matches!(self, Self::Duplicate)
    }
}

impl CoapObserve {
    /// Largest source-conformant Observe sequence value (`2^24 - 1`).
    pub const MAX_VALUE: u32 = OBSERVE_SERIAL_MODULUS - 1;

    /// Build an Observe value using the shortest CoAP `uint` encoding.
    ///
    /// Values above [`Self::MAX_VALUE`] are retained as explicit malformed
    /// four-byte values. Call [`Self::validate`] to check the 24-bit bound.
    pub fn new(value: u32) -> Self {
        Self {
            value,
            wire_value: encode_observe_uint(value),
        }
    }

    /// Build an Observe value after checking the RFC 7641 24-bit bound.
    pub fn try_new(value: u32) -> Result<Self> {
        let value = Self::new(value);
        value.validate()?;
        Ok(value)
    }

    /// Build the empty `Observe: 0` registration value.
    pub fn register() -> Self {
        Self::new(0)
    }

    /// Alias for [`Self::register`] using request-oriented terminology.
    pub fn registration() -> Self {
        Self::register()
    }

    /// Build the one-byte `Observe: 1` deregistration value.
    pub fn deregister() -> Self {
        Self::new(1)
    }

    /// Alias for [`Self::deregister`] using request-oriented terminology.
    pub fn deregistration() -> Self {
        Self::deregister()
    }

    /// Build a checked 24-bit notification sequence value.
    pub fn notification(value: u32) -> Result<Self> {
        Self::try_new(value)
    }

    /// Return the decoded unsigned integer.
    pub const fn value(&self) -> u32 {
        self.value
    }

    /// Borrow the exact canonical or decoded option value bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire_value
    }

    /// Consume this wrapper and return the exact option value bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.wire_value
    }

    /// Check the RFC 7641 24-bit value and zero-to-three-byte wire bounds.
    pub fn validate(&self) -> Result<()> {
        if self.value > Self::MAX_VALUE || self.wire_value.len() > 3 {
            return Err(CrafterError::invalid_field_value(
                "coap.observe",
                "Observe value must fit in 24 bits and at most 3 bytes",
            ));
        }
        Ok(())
    }

    /// Return whether this is the registration value zero.
    pub const fn is_registration(&self) -> bool {
        self.value == 0
    }

    /// Return whether this is the deregistration value one.
    pub const fn is_deregistration(&self) -> bool {
        self.value == 1
    }

    /// Compare this incoming value with the freshest value in 24-bit serial
    /// arithmetic.
    ///
    /// Equality is [`CoapObserveOrdering::Duplicate`]. Values exactly `2^23`
    /// apart have no defined serial order and return
    /// [`CoapObserveOrdering::Ambiguous`]. Invalid unchecked values also
    /// return `Ambiguous` rather than being silently truncated.
    pub fn is_newer_than(&self, freshest: &Self) -> CoapObserveOrdering {
        if self.validate().is_err() || freshest.validate().is_err() {
            return CoapObserveOrdering::Ambiguous;
        }

        let delta = self.value.wrapping_sub(freshest.value) & Self::MAX_VALUE;
        match delta {
            0 => CoapObserveOrdering::Duplicate,
            OBSERVE_SERIAL_HALF_RANGE => CoapObserveOrdering::Ambiguous,
            1..OBSERVE_SERIAL_HALF_RANGE => CoapObserveOrdering::Newer,
            _ => CoapObserveOrdering::Older,
        }
    }

    /// Apply the complete RFC 7641 freshness comparison including elapsed
    /// client-local time.
    ///
    /// Once more than 128 seconds have elapsed, an otherwise valid incoming
    /// value is newer regardless of serial ordering. This method stores no
    /// timestamp; callers provide the already-computed elapsed duration.
    pub fn is_newer_than_after(&self, freshest: &Self, elapsed: Duration) -> CoapObserveOrdering {
        if self.validate().is_err() || freshest.validate().is_err() {
            return CoapObserveOrdering::Ambiguous;
        }
        if elapsed > OBSERVE_REORDERING_TIMEOUT {
            CoapObserveOrdering::Newer
        } else {
            self.is_newer_than(freshest)
        }
    }
}

impl From<u32> for CoapObserve {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<CoapObserve> for CoapOption {
    fn from(value: CoapObserve) -> Self {
        CoapOption::new(COAP_OPTION_OBSERVE, value.into_bytes())
    }
}

impl TryFrom<&CoapOption> for CoapObserve {
    type Error = CrafterError;

    fn try_from(option: &CoapOption) -> Result<Self> {
        if option.number().value() != COAP_OPTION_OBSERVE {
            return Err(CrafterError::invalid_field_value(
                "coap.observe",
                "option number is not Observe",
            ));
        }
        if option.value().len() > 3 {
            return Err(CrafterError::invalid_field_value(
                "coap.observe",
                "Observe value must fit in 24 bits and at most 3 bytes",
            ));
        }

        Ok(Self {
            value: option
                .value()
                .iter()
                .fold(0u32, |value, byte| (value << 8) | u32::from(*byte)),
            wire_value: option.value().to_vec(),
        })
    }
}

fn encode_observe_uint(value: u32) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }

    let encoded = value.to_be_bytes();
    let first = encoded
        .iter()
        .position(|byte| *byte != 0)
        .expect("a nonzero integer contains a nonzero byte");
    encoded[first..].to_vec()
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::*;
    use crate::packet::Packet;
    use crate::protocols::coap::{Coap, CoapCode};

    #[test]
    fn registration_deregistration_and_notification_values_are_source_backed() {
        let registration = CoapObserve::register();
        assert_eq!(registration.value(), 0);
        assert_eq!(registration.as_bytes(), b"");
        assert!(registration.is_registration());

        let deregistration = CoapObserve::deregister();
        assert_eq!(deregistration.value(), 1);
        assert_eq!(deregistration.as_bytes(), &[1]);
        assert!(deregistration.is_deregistration());

        let notification = CoapObserve::notification(CoapObserve::MAX_VALUE).unwrap();
        assert_eq!(notification.as_bytes(), &[0xff, 0xff, 0xff]);
    }

    #[test]
    fn decoded_noncanonical_bytes_round_trip_exactly() {
        let option = CoapOption::new(COAP_OPTION_OBSERVE, vec![0, 0, 1]);
        let observe = CoapObserve::try_from(&option).unwrap();
        assert_eq!(observe.value(), 1);
        assert_eq!(observe.as_bytes(), &[0, 0, 1]);
        assert_eq!(CoapOption::from(observe).value(), &[0, 0, 1]);
    }

    #[test]
    fn checked_bounds_reject_unknown_size_without_losing_raw_option() {
        let unchecked = CoapObserve::new(1 << 24);
        assert_eq!(unchecked.as_bytes(), &[1, 0, 0, 0]);
        assert!(unchecked.validate().is_err());
        assert!(CoapObserve::try_new(1 << 24).is_err());

        let raw = CoapOption::new(COAP_OPTION_OBSERVE, vec![0, 0, 0, 1]);
        assert!(CoapObserve::try_from(&raw).is_err());
        assert_eq!(raw.value(), &[0, 0, 0, 1]);
    }

    #[test]
    fn serial_ordering_handles_wraparound_duplicates_and_half_range() {
        let zero = CoapObserve::new(0);
        let one = CoapObserve::new(1);
        let maximum = CoapObserve::new(CoapObserve::MAX_VALUE);
        let half = CoapObserve::new(OBSERVE_SERIAL_HALF_RANGE);

        assert_eq!(one.is_newer_than(&zero), CoapObserveOrdering::Newer);
        assert_eq!(zero.is_newer_than(&one), CoapObserveOrdering::Older);
        assert_eq!(zero.is_newer_than(&maximum), CoapObserveOrdering::Newer);
        assert_eq!(maximum.is_newer_than(&zero), CoapObserveOrdering::Older);
        assert_eq!(one.is_newer_than(&one), CoapObserveOrdering::Duplicate);
        assert_eq!(half.is_newer_than(&zero), CoapObserveOrdering::Ambiguous);

        assert_eq!(
            zero.is_newer_than_after(&one, Duration::from_secs(128)),
            CoapObserveOrdering::Older
        );
        assert_eq!(
            zero.is_newer_than_after(&one, Duration::from_secs(129)),
            CoapObserveOrdering::Newer
        );
    }

    #[test]
    fn request_and_notification_helpers_use_code_and_option_presence() {
        let registration = Coap::observe_registration().message_id(0x1234);
        assert!(registration.has_observe());
        assert!(registration.is_observe_request());
        assert!(registration.is_observe_registration());
        assert!(!registration.is_observe_deregistration());
        assert_eq!(registration.observe_value().unwrap().unwrap().value(), 0);
        assert_eq!(
            Packet::from_layer(registration)
                .compile()
                .unwrap()
                .as_bytes(),
            [0x40, 0x01, 0x12, 0x34, 0x60]
        );

        let deregistration = Coap::observe_deregistration();
        assert!(deregistration.is_observe_deregistration());

        let notification = Coap::response(CoapCode::content())
            .observe(CoapObserve::new(7))
            .message_id(0x2345);
        assert!(notification.is_observe_notification());
        assert_eq!(
            notification
                .observe_notification()
                .unwrap()
                .unwrap()
                .value(),
            7
        );
        assert_eq!(
            Packet::from_layer(notification)
                .compile()
                .unwrap()
                .as_bytes(),
            [0x40, 0x45, 0x23, 0x45, 0x61, 0x07]
        );

        assert!(!Coap::post()
            .observe(CoapObserve::register())
            .is_observe_request());
        assert!(!Coap::bad_request()
            .observe(CoapObserve::new(7))
            .is_observe_notification());
    }

    #[test]
    fn malformed_observe_request_remains_classifiable_and_inspectable() {
        let raw = Coap::get().option(CoapOption::new(COAP_OPTION_OBSERVE, vec![0, 0, 0, 2]));
        assert!(raw.is_observe_request());
        assert!(raw.observe_value().unwrap().is_err());
        assert_eq!(raw.options_value()[0].value(), &[0, 0, 0, 2]);
    }
}
