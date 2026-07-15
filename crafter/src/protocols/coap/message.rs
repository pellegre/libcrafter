//! CoAP datagram message layers.

use core::fmt;

use super::constants::{COAP_DEFAULT_TYPE, COAP_DEFAULT_VERSION, COAP_VERSION_1};

const COAP_TWO_BIT_VALUE_MASK: u8 = 0x03;
const COAP_TYPE_CONFIRMABLE: u8 = 0;
const COAP_TYPE_NON_CONFIRMABLE: u8 = 1;
const COAP_TYPE_ACKNOWLEDGEMENT: u8 = 2;
const COAP_TYPE_RESET: u8 = 3;

/// Source-backed CoAP datagram version field value.
///
/// RFC 7252 currently defines version 1. Other values remain inspectable, and
/// caller-supplied values outside the two-bit field are retained until the
/// value is explicitly requested for wire serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CoapVersion(u8);

impl CoapVersion {
    /// Build a version from an already-extracted wire integer or an explicit
    /// caller-supplied boundary value.
    pub const fn from_wire(value: u8) -> Self {
        Self(value)
    }

    /// Current source-backed default CoAP version.
    pub const fn current() -> Self {
        Self(COAP_VERSION_1)
    }

    /// Return the preserved caller-supplied value without masking.
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Return the value encoded in the two-bit datagram Version field.
    pub const fn wire_value(self) -> u8 {
        self.value() & COAP_TWO_BIT_VALUE_MASK
    }

    /// Stable summary and inspection label.
    pub fn label(self) -> String {
        match self.value() {
            COAP_VERSION_1 => "coap-v1".to_string(),
            value => format!("version-{value}"),
        }
    }

    /// Stable summary-safe label.
    pub fn summary_label(self) -> String {
        self.label()
    }

    /// Return true for the current source-backed CoAP version.
    pub const fn is_current(self) -> bool {
        self.value() == COAP_VERSION_1
    }
}

impl Default for CoapVersion {
    fn default() -> Self {
        Self::from_wire(COAP_DEFAULT_VERSION)
    }
}

impl From<u8> for CoapVersion {
    fn from(value: u8) -> Self {
        Self::from_wire(value)
    }
}

impl From<CoapVersion> for u8 {
    fn from(value: CoapVersion) -> Self {
        value.value()
    }
}

impl fmt::Display for CoapVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Source-backed CoAP datagram message Type field value.
///
/// RFC 7252 defines every two-bit wire value. `Unknown` retains explicit
/// caller-supplied values outside that extracted field space for boundary
/// packet construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CoapMessageType {
    /// Confirmable message (CON).
    Confirmable,
    /// Non-confirmable message (NON).
    NonConfirmable,
    /// Acknowledgement message (ACK).
    Acknowledgement,
    /// Reset message (RST).
    Reset,
    /// Caller-supplied value outside the source-backed two-bit Type space.
    Unknown(u8),
}

impl CoapMessageType {
    /// Build a message type from an already-extracted wire integer or an
    /// explicit caller-supplied boundary value.
    pub const fn from_wire(value: u8) -> Self {
        match value {
            COAP_TYPE_CONFIRMABLE => Self::Confirmable,
            COAP_TYPE_NON_CONFIRMABLE => Self::NonConfirmable,
            COAP_TYPE_ACKNOWLEDGEMENT => Self::Acknowledgement,
            COAP_TYPE_RESET => Self::Reset,
            value => Self::Unknown(value),
        }
    }

    /// Return the preserved caller-supplied value without masking.
    pub const fn value(self) -> u8 {
        match self {
            Self::Confirmable => COAP_TYPE_CONFIRMABLE,
            Self::NonConfirmable => COAP_TYPE_NON_CONFIRMABLE,
            Self::Acknowledgement => COAP_TYPE_ACKNOWLEDGEMENT,
            Self::Reset => COAP_TYPE_RESET,
            Self::Unknown(value) => value,
        }
    }

    /// Return the value encoded in the two-bit datagram Type field.
    pub const fn wire_value(self) -> u8 {
        self.value() & COAP_TWO_BIT_VALUE_MASK
    }

    /// Stable summary and inspection label.
    pub fn label(self) -> String {
        match self {
            Self::Confirmable => "confirmable".to_string(),
            Self::NonConfirmable => "non-confirmable".to_string(),
            Self::Acknowledgement => "acknowledgement".to_string(),
            Self::Reset => "reset".to_string(),
            Self::Unknown(value) => format!("message-type-{value}"),
        }
    }

    /// Stable summary-safe label.
    pub fn summary_label(self) -> String {
        self.label()
    }

    /// Return true for a Confirmable (CON) message.
    pub const fn is_confirmable(self) -> bool {
        matches!(self, Self::Confirmable)
    }

    /// Return true for a Non-confirmable (NON) message.
    pub const fn is_non_confirmable(self) -> bool {
        matches!(self, Self::NonConfirmable)
    }

    /// Return true for an Acknowledgement (ACK) message.
    pub const fn is_acknowledgement(self) -> bool {
        matches!(self, Self::Acknowledgement)
    }

    /// Return true for a Reset (RST) message.
    pub const fn is_reset(self) -> bool {
        matches!(self, Self::Reset)
    }

    /// Return true for a caller-supplied value outside the two-bit Type space.
    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown(_))
    }
}

impl Default for CoapMessageType {
    fn default() -> Self {
        Self::from_wire(COAP_DEFAULT_TYPE)
    }
}

impl From<u8> for CoapMessageType {
    fn from(value: u8) -> Self {
        Self::from_wire(value)
    }
}

impl From<CoapMessageType> for u8 {
    fn from(value: CoapMessageType) -> Self {
        value.value()
    }
}

impl fmt::Display for CoapMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_preserves_every_wire_value() {
        for value in 0..=COAP_TWO_BIT_VALUE_MASK {
            let version = CoapVersion::from_wire(value);
            assert_eq!(version.value(), value);
            assert_eq!(version.wire_value(), value);
            assert_eq!(u8::from(version), value);
        }

        assert_eq!(CoapVersion::default(), CoapVersion::current());
        assert_eq!(CoapVersion::default().value(), COAP_VERSION_1);
        assert!(CoapVersion::current().is_current());
        assert!(!CoapVersion::from_wire(0).is_current());
        assert_eq!(CoapVersion::current().label(), "coap-v1");
        assert_eq!(CoapVersion::current().summary_label(), "coap-v1");
        assert_eq!(CoapVersion::current().to_string(), "coap-v1");
    }

    #[test]
    fn version_masks_only_when_requested_for_wire_serialization() {
        let version = CoapVersion::from(0xfd);

        assert_eq!(version.value(), 0xfd);
        assert_eq!(u8::from(version), 0xfd);
        assert_eq!(version.wire_value(), 1);
        assert_eq!(version.label(), "version-253");
        assert_eq!(version.summary_label(), "version-253");
        assert_eq!(version.to_string(), "version-253");
    }

    #[test]
    fn message_type_models_every_wire_value() {
        let cases = [
            (0, CoapMessageType::Confirmable, "confirmable"),
            (1, CoapMessageType::NonConfirmable, "non-confirmable"),
            (2, CoapMessageType::Acknowledgement, "acknowledgement"),
            (3, CoapMessageType::Reset, "reset"),
        ];

        for (value, message_type, label) in cases {
            assert_eq!(CoapMessageType::from_wire(value), message_type);
            assert_eq!(message_type.value(), value);
            assert_eq!(message_type.wire_value(), value);
            assert_eq!(u8::from(message_type), value);
            assert_eq!(message_type.label(), label);
            assert_eq!(message_type.summary_label(), label);
            assert_eq!(message_type.to_string(), label);
            assert!(!message_type.is_unknown());
        }

        assert_eq!(CoapMessageType::default(), CoapMessageType::Confirmable);
        assert!(CoapMessageType::Confirmable.is_confirmable());
        assert!(CoapMessageType::NonConfirmable.is_non_confirmable());
        assert!(CoapMessageType::Acknowledgement.is_acknowledgement());
        assert!(CoapMessageType::Reset.is_reset());
    }

    #[test]
    fn message_type_preserves_out_of_range_caller_values() {
        let message_type = CoapMessageType::from(0xfe);

        assert_eq!(message_type, CoapMessageType::Unknown(0xfe));
        assert_eq!(message_type.value(), 0xfe);
        assert_eq!(u8::from(message_type), 0xfe);
        assert_eq!(message_type.wire_value(), COAP_TYPE_ACKNOWLEDGEMENT);
        assert_eq!(message_type.label(), "message-type-254");
        assert_eq!(message_type.summary_label(), "message-type-254");
        assert_eq!(message_type.to_string(), "message-type-254");
        assert!(message_type.is_unknown());
        assert!(!message_type.is_confirmable());
        assert!(!message_type.is_non_confirmable());
        assert!(!message_type.is_acknowledgement());
        assert!(!message_type.is_reset());
    }
}
