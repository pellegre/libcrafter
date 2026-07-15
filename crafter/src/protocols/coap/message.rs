//! CoAP datagram message layers.

use core::fmt;

use super::constants::*;
use super::registry::{coap_code_meta, coap_signaling_code_meta, CoapRegistryMeta};

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

/// Lossless CoAP Code field value.
///
/// The one-octet Code field packs a three-bit class and a five-bit detail.
/// This newtype intentionally remains open over every byte so unassigned,
/// reserved, role-inappropriate, and future values survive decode and
/// re-serialization unchanged. Named constructors cover only assignments in
/// the reviewed IANA snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CoapCode(u8);

impl CoapCode {
    /// Build a code from an exact wire byte without registry validation.
    pub const fn from_wire(value: u8) -> Self {
        Self(value)
    }

    /// Pack a code from class and detail values.
    ///
    /// Only the low three class bits and low five detail bits belong to the
    /// Code octet. Use [`Self::from_wire`] when preserving an existing raw
    /// byte rather than composing its two wire fields.
    pub const fn from_parts(class: u8, detail: u8) -> Self {
        Self(
            ((class << COAP_CODE_CLASS_SHIFT) & COAP_CODE_CLASS_MASK)
                | (detail & COAP_CODE_DETAIL_MASK),
        )
    }

    /// Return the exact one-octet Code value.
    pub const fn wire_value(self) -> u8 {
        self.0
    }

    /// Return the three-bit code class.
    pub const fn class(self) -> u8 {
        (self.wire_value() & COAP_CODE_CLASS_MASK) >> COAP_CODE_CLASS_SHIFT
    }

    /// Return the five-bit code detail.
    pub const fn detail(self) -> u8 {
        self.wire_value() & COAP_CODE_DETAIL_MASK
    }

    /// Return the customary `C.DD` numeric label.
    pub fn label(self) -> String {
        format!("{}.{:02}", self.class(), self.detail())
    }

    /// Return source-backed metadata for this code value.
    ///
    /// Class 7 uses the reliable-transport signaling registry. Datagram code
    /// validation remains contextual and may still report class 7 as reserved.
    pub fn registry_meta(self) -> CoapRegistryMeta {
        if self.is_signaling() {
            coap_signaling_code_meta(self.wire_value())
        } else {
            coap_code_meta(self.wire_value())
        }
    }

    /// Return true for the Empty `0.00` code.
    pub const fn is_empty(self) -> bool {
        self.wire_value() == COAP_CODE_EMPTY
    }

    /// Return true for a non-empty class-0 request code.
    ///
    /// This is deliberately class-based so future assigned methods remain
    /// requests without requiring a library update.
    pub const fn is_request(self) -> bool {
        self.class() == 0 && self.detail() != 0
    }

    /// Return true for the class-2 through class-5 response space.
    ///
    /// Class 3 is currently reserved, but remains inside the response code
    /// range so a future assignment does not require a classification change.
    pub const fn is_response(self) -> bool {
        self.class() >= 2 && self.class() <= 5
    }

    /// Return true for a reliable-transport signaling class value.
    ///
    /// This includes unassigned class-7 details so they remain classifiable
    /// and lossless. A datagram layer must still treat class 7 as reserved.
    pub const fn is_signaling(self) -> bool {
        self.class() == 7
    }

    /// Empty (`0.00`).
    pub const fn empty() -> Self {
        Self::from_wire(COAP_CODE_EMPTY)
    }

    /// GET (`0.01`).
    pub const fn get() -> Self {
        Self::from_wire(COAP_CODE_GET)
    }

    /// POST (`0.02`).
    pub const fn post() -> Self {
        Self::from_wire(COAP_CODE_POST)
    }

    /// PUT (`0.03`).
    pub const fn put() -> Self {
        Self::from_wire(COAP_CODE_PUT)
    }

    /// DELETE (`0.04`).
    pub const fn delete() -> Self {
        Self::from_wire(COAP_CODE_DELETE)
    }

    /// FETCH (`0.05`, RFC 8132).
    pub const fn fetch() -> Self {
        Self::from_wire(COAP_CODE_FETCH)
    }

    /// PATCH (`0.06`, RFC 8132).
    pub const fn patch() -> Self {
        Self::from_wire(COAP_CODE_PATCH)
    }

    /// iPATCH (`0.07`, RFC 8132).
    pub const fn ipatch() -> Self {
        Self::from_wire(COAP_CODE_IPATCH)
    }

    /// Created (`2.01`).
    pub const fn created() -> Self {
        Self::from_wire(COAP_CODE_CREATED)
    }

    /// Deleted (`2.02`).
    pub const fn deleted() -> Self {
        Self::from_wire(COAP_CODE_DELETED)
    }

    /// Valid (`2.03`).
    pub const fn valid() -> Self {
        Self::from_wire(COAP_CODE_VALID)
    }

    /// Changed (`2.04`).
    pub const fn changed() -> Self {
        Self::from_wire(COAP_CODE_CHANGED)
    }

    /// Content (`2.05`).
    pub const fn content() -> Self {
        Self::from_wire(COAP_CODE_CONTENT)
    }

    /// Continue (`2.31`).
    pub const fn continue_() -> Self {
        Self::from_wire(COAP_CODE_CONTINUE)
    }

    /// Bad Request (`4.00`).
    pub const fn bad_request() -> Self {
        Self::from_wire(COAP_CODE_BAD_REQUEST)
    }

    /// Unauthorized (`4.01`).
    pub const fn unauthorized() -> Self {
        Self::from_wire(COAP_CODE_UNAUTHORIZED)
    }

    /// Bad Option (`4.02`).
    pub const fn bad_option() -> Self {
        Self::from_wire(COAP_CODE_BAD_OPTION)
    }

    /// Forbidden (`4.03`).
    pub const fn forbidden() -> Self {
        Self::from_wire(COAP_CODE_FORBIDDEN)
    }

    /// Not Found (`4.04`).
    pub const fn not_found() -> Self {
        Self::from_wire(COAP_CODE_NOT_FOUND)
    }

    /// Method Not Allowed (`4.05`).
    pub const fn method_not_allowed() -> Self {
        Self::from_wire(COAP_CODE_METHOD_NOT_ALLOWED)
    }

    /// Not Acceptable (`4.06`).
    pub const fn not_acceptable() -> Self {
        Self::from_wire(COAP_CODE_NOT_ACCEPTABLE)
    }

    /// Request Entity Incomplete (`4.08`).
    pub const fn request_entity_incomplete() -> Self {
        Self::from_wire(COAP_CODE_REQUEST_ENTITY_INCOMPLETE)
    }

    /// Conflict (`4.09`).
    pub const fn conflict() -> Self {
        Self::from_wire(COAP_CODE_CONFLICT)
    }

    /// Precondition Failed (`4.12`).
    pub const fn precondition_failed() -> Self {
        Self::from_wire(COAP_CODE_PRECONDITION_FAILED)
    }

    /// Request Entity Too Large (`4.13`).
    pub const fn request_entity_too_large() -> Self {
        Self::from_wire(COAP_CODE_REQUEST_ENTITY_TOO_LARGE)
    }

    /// Unsupported Content-Format (`4.15`).
    pub const fn unsupported_content_format() -> Self {
        Self::from_wire(COAP_CODE_UNSUPPORTED_CONTENT_FORMAT)
    }

    /// Unprocessable Entity (`4.22`).
    pub const fn unprocessable_entity() -> Self {
        Self::from_wire(COAP_CODE_UNPROCESSABLE_ENTITY)
    }

    /// Too Many Requests (`4.29`).
    pub const fn too_many_requests() -> Self {
        Self::from_wire(COAP_CODE_TOO_MANY_REQUESTS)
    }

    /// Internal Server Error (`5.00`).
    pub const fn internal_server_error() -> Self {
        Self::from_wire(COAP_CODE_INTERNAL_SERVER_ERROR)
    }

    /// Not Implemented (`5.01`).
    pub const fn not_implemented() -> Self {
        Self::from_wire(COAP_CODE_NOT_IMPLEMENTED)
    }

    /// Bad Gateway (`5.02`).
    pub const fn bad_gateway() -> Self {
        Self::from_wire(COAP_CODE_BAD_GATEWAY)
    }

    /// Service Unavailable (`5.03`).
    pub const fn service_unavailable() -> Self {
        Self::from_wire(COAP_CODE_SERVICE_UNAVAILABLE)
    }

    /// Gateway Timeout (`5.04`).
    pub const fn gateway_timeout() -> Self {
        Self::from_wire(COAP_CODE_GATEWAY_TIMEOUT)
    }

    /// Proxying Not Supported (`5.05`).
    pub const fn proxying_not_supported() -> Self {
        Self::from_wire(COAP_CODE_PROXYING_NOT_SUPPORTED)
    }

    /// Hop Limit Reached (`5.08`).
    pub const fn hop_limit_reached() -> Self {
        Self::from_wire(COAP_CODE_HOP_LIMIT_REACHED)
    }

    /// Capabilities and Settings Message (`7.01`).
    pub const fn csm() -> Self {
        Self::from_wire(COAP_CODE_CSM)
    }

    /// Ping (`7.02`).
    pub const fn ping() -> Self {
        Self::from_wire(COAP_CODE_PING)
    }

    /// Pong (`7.03`).
    pub const fn pong() -> Self {
        Self::from_wire(COAP_CODE_PONG)
    }

    /// Release (`7.04`).
    pub const fn release() -> Self {
        Self::from_wire(COAP_CODE_RELEASE)
    }

    /// Abort (`7.05`).
    pub const fn abort() -> Self {
        Self::from_wire(COAP_CODE_ABORT)
    }
}

impl From<u8> for CoapCode {
    fn from(value: u8) -> Self {
        Self::from_wire(value)
    }
}

impl From<CoapCode> for u8 {
    fn from(value: CoapCode) -> Self {
        value.wire_value()
    }
}

impl fmt::Display for CoapCode {
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

    #[test]
    fn code_packs_and_extracts_class_detail_boundaries() {
        let cases = [
            (0, 0, 0x00, "0.00"),
            (0, 31, 0x1f, "0.31"),
            (2, 1, 0x41, "2.01"),
            (4, 29, 0x9d, "4.29"),
            (5, 31, 0xbf, "5.31"),
            (7, 31, 0xff, "7.31"),
        ];

        for (class, detail, wire, label) in cases {
            let code = CoapCode::from_parts(class, detail);
            assert_eq!(code.wire_value(), wire);
            assert_eq!(code.class(), class);
            assert_eq!(code.detail(), detail);
            assert_eq!(code.label(), label);
            assert_eq!(code.to_string(), label);
            assert_eq!(u8::from(code), wire);
        }

        assert_eq!(CoapCode::from_parts(0xff, 0xff), CoapCode::from_wire(0xff));
        assert_eq!(CoapCode::default(), CoapCode::empty());
    }

    #[test]
    fn code_named_constructors_match_current_assignments() {
        let cases = [
            (CoapCode::empty(), 0x00, "Empty"),
            (CoapCode::get(), 0x01, "GET"),
            (CoapCode::post(), 0x02, "POST"),
            (CoapCode::put(), 0x03, "PUT"),
            (CoapCode::delete(), 0x04, "DELETE"),
            (CoapCode::fetch(), 0x05, "FETCH"),
            (CoapCode::patch(), 0x06, "PATCH"),
            (CoapCode::ipatch(), 0x07, "iPATCH"),
            (CoapCode::created(), 0x41, "Created"),
            (CoapCode::deleted(), 0x42, "Deleted"),
            (CoapCode::valid(), 0x43, "Valid"),
            (CoapCode::changed(), 0x44, "Changed"),
            (CoapCode::content(), 0x45, "Content"),
            (CoapCode::continue_(), 0x5f, "Continue"),
            (CoapCode::bad_request(), 0x80, "Bad Request"),
            (CoapCode::unauthorized(), 0x81, "Unauthorized"),
            (CoapCode::bad_option(), 0x82, "Bad Option"),
            (CoapCode::forbidden(), 0x83, "Forbidden"),
            (CoapCode::not_found(), 0x84, "Not Found"),
            (CoapCode::method_not_allowed(), 0x85, "Method Not Allowed"),
            (CoapCode::not_acceptable(), 0x86, "Not Acceptable"),
            (
                CoapCode::request_entity_incomplete(),
                0x88,
                "Request Entity Incomplete",
            ),
            (CoapCode::conflict(), 0x89, "Conflict"),
            (CoapCode::precondition_failed(), 0x8c, "Precondition Failed"),
            (
                CoapCode::request_entity_too_large(),
                0x8d,
                "Request Entity Too Large",
            ),
            (
                CoapCode::unsupported_content_format(),
                0x8f,
                "Unsupported Content-Format",
            ),
            (
                CoapCode::unprocessable_entity(),
                0x96,
                "Unprocessable Entity",
            ),
            (CoapCode::too_many_requests(), 0x9d, "Too Many Requests"),
            (
                CoapCode::internal_server_error(),
                0xa0,
                "Internal Server Error",
            ),
            (CoapCode::not_implemented(), 0xa1, "Not Implemented"),
            (CoapCode::bad_gateway(), 0xa2, "Bad Gateway"),
            (CoapCode::service_unavailable(), 0xa3, "Service Unavailable"),
            (CoapCode::gateway_timeout(), 0xa4, "Gateway Timeout"),
            (
                CoapCode::proxying_not_supported(),
                0xa5,
                "Proxying Not Supported",
            ),
            (CoapCode::hop_limit_reached(), 0xa8, "Hop Limit Reached"),
            (CoapCode::csm(), 0xe1, "CSM"),
            (CoapCode::ping(), 0xe2, "Ping"),
            (CoapCode::pong(), 0xe3, "Pong"),
            (CoapCode::release(), 0xe4, "Release"),
            (CoapCode::abort(), 0xe5, "Abort"),
        ];

        for (code, wire, registry_label) in cases {
            assert_eq!(code.wire_value(), wire);
            assert_eq!(code.registry_meta().value, u64::from(wire));
            assert_eq!(code.registry_meta().label, registry_label);
            assert!(code.registry_meta().status.is_assigned());
        }
    }

    #[test]
    fn code_classification_is_lossless_and_class_based() {
        assert!(CoapCode::empty().is_empty());
        assert!(!CoapCode::empty().is_request());
        assert!(CoapCode::get().is_request());
        assert!(CoapCode::from_parts(0, 31).is_request());
        assert!(CoapCode::created().is_response());
        assert!(CoapCode::bad_request().is_response());
        assert!(CoapCode::internal_server_error().is_response());
        assert!(CoapCode::from_parts(3, 0).is_response());
        assert!(!CoapCode::from_parts(6, 0).is_response());
        assert!(CoapCode::csm().is_signaling());
        assert!(CoapCode::from_parts(7, 31).is_signaling());
        assert!(!CoapCode::from_parts(6, 31).is_signaling());
    }

    #[test]
    fn code_preserves_every_unknown_and_reserved_wire_byte() {
        for wire in u8::MIN..=u8::MAX {
            let code = CoapCode::from(wire);
            assert_eq!(code.wire_value(), wire);
            assert_eq!(u8::from(code), wire);
            assert_eq!(
                CoapCode::from_parts(code.class(), code.detail()).wire_value(),
                wire
            );
        }

        let unknown_method = CoapCode::from_wire(0x08);
        assert_eq!(unknown_method.label(), "0.08");
        assert_eq!(unknown_method.registry_meta().label, "code-0.08");
        assert!(unknown_method.is_request());

        let reserved = CoapCode::from_wire(0x20);
        assert_eq!(reserved.label(), "1.00");
        assert_eq!(reserved.registry_meta().label, "code-1.00");
        assert!(!reserved.is_empty());
        assert!(!reserved.is_request());
        assert!(!reserved.is_response());
        assert!(!reserved.is_signaling());

        let unknown_signaling = CoapCode::from_wire(0xff);
        assert_eq!(unknown_signaling.label(), "7.31");
        assert_eq!(unknown_signaling.registry_meta().label, "signaling-7.31");
        assert!(unknown_signaling.is_signaling());
    }
}
