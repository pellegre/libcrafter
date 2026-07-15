//! RFC 7967 No-Response option masks and response-class inspection.
//!
//! This module only records a request's response-class preferences. It does
//! not suppress responses, retire tokens, wait for responses, or otherwise
//! change endpoint or transport behavior.

use crate::error::{CrafterError, Result};

use super::constants::COAP_OPTION_NO_RESPONSE;
use super::message::CoapCode;
use super::option::CoapOption;

const SUPPRESS_SUCCESS_BIT: u8 = 0x02;
const SUPPRESS_CLIENT_ERROR_BIT: u8 = 0x08;
const SUPPRESS_SERVER_ERROR_BIT: u8 = 0x10;
const KNOWN_SUPPRESSION_MASK: u8 =
    SUPPRESS_SUCCESS_BIT | SUPPRESS_CLIENT_ERROR_BIT | SUPPRESS_SERVER_ERROR_BIT;

/// One raw-preserving RFC 7967 No-Response suppression mask.
///
/// The option uses an empty value for mask zero and one octet for nonzero
/// masks. [`Self::new`] deliberately preserves unknown bits so generated
/// tools can construct future or malformed values. Use [`Self::try_new`] or
/// [`Self::validate`] when only the response classes defined by RFC 7967 are
/// desired. Typed conversion from a decoded [`CoapOption`] retains an explicit
/// one-byte zero for exact re-encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoapNoResponse {
    mask: u8,
    wire_value: Vec<u8>,
}

impl CoapNoResponse {
    /// Mask bit suppressing 2.xx success responses.
    pub const SUPPRESS_SUCCESS: u8 = SUPPRESS_SUCCESS_BIT;
    /// Mask bit suppressing 4.xx client-error responses.
    pub const SUPPRESS_CLIENT_ERROR: u8 = SUPPRESS_CLIENT_ERROR_BIT;
    /// Mask bit suppressing 5.xx server-error responses.
    pub const SUPPRESS_SERVER_ERROR: u8 = SUPPRESS_SERVER_ERROR_BIT;
    /// All response-class suppression bits defined by RFC 7967.
    pub const SUPPRESS_ALL: u8 = KNOWN_SUPPRESSION_MASK;

    /// Build a mask using the canonical empty-or-one-byte CoAP `uint` form.
    ///
    /// Unknown bits remain unchanged. Call [`Self::validate`] to reject them.
    pub fn new(mask: u8) -> Self {
        Self {
            mask,
            wire_value: if mask == 0 { Vec::new() } else { vec![mask] },
        }
    }

    /// Build a mask after checking that no reserved bits are set.
    pub fn try_new(mask: u8) -> Result<Self> {
        let value = Self::new(mask);
        value.validate()?;
        Ok(value)
    }

    /// Build the empty mask, expressing interest in every response class.
    pub fn interested_in_all() -> Self {
        Self::new(0)
    }

    /// Build a mask suppressing 2.xx success responses.
    pub fn suppress_success() -> Self {
        Self::new(Self::SUPPRESS_SUCCESS)
    }

    /// Build a mask suppressing 4.xx client-error responses.
    pub fn suppress_client_error() -> Self {
        Self::new(Self::SUPPRESS_CLIENT_ERROR)
    }

    /// Build a mask suppressing 5.xx server-error responses.
    pub fn suppress_server_error() -> Self {
        Self::new(Self::SUPPRESS_SERVER_ERROR)
    }

    /// Build a mask suppressing all response classes defined by RFC 7252.
    pub fn suppress_all() -> Self {
        Self::new(Self::SUPPRESS_ALL)
    }

    /// Return the exact decoded mask octet, or zero for an empty option.
    pub const fn mask(&self) -> u8 {
        self.mask
    }

    /// Borrow the exact canonical or decoded option value bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire_value
    }

    /// Consume this wrapper and return the exact option value bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.wire_value
    }

    /// Return mask bits not assigned to RFC 7967 response classes.
    pub const fn reserved_bits(&self) -> u8 {
        self.mask & !KNOWN_SUPPRESSION_MASK
    }

    /// Return whether any reserved mask bits are set.
    pub const fn has_reserved_bits(&self) -> bool {
        self.reserved_bits() != 0
    }

    /// Check that the mask contains only RFC 7967 response-class bits.
    pub fn validate(&self) -> Result<()> {
        if self.has_reserved_bits() {
            return Err(CrafterError::invalid_field_value(
                "coap.no-response",
                "No-Response mask contains reserved bits",
            ));
        }
        Ok(())
    }

    /// Return whether 2.xx success responses are suppressed.
    pub const fn suppresses_success(&self) -> bool {
        self.mask & Self::SUPPRESS_SUCCESS != 0
    }

    /// Return whether 4.xx client-error responses are suppressed.
    pub const fn suppresses_client_error(&self) -> bool {
        self.mask & Self::SUPPRESS_CLIENT_ERROR != 0
    }

    /// Return whether 5.xx server-error responses are suppressed.
    pub const fn suppresses_server_error(&self) -> bool {
        self.mask & Self::SUPPRESS_SERVER_ERROR != 0
    }

    /// Test one CoAP Code against the response-class suppression mask.
    ///
    /// Request, Empty, signaling, reserved class-3, and class-6 codes are not
    /// suppressed because RFC 7967 assigns mask bits only for classes 2, 4,
    /// and 5.
    pub const fn suppresses(&self, code: CoapCode) -> bool {
        match code.class() {
            2 => self.suppresses_success(),
            4 => self.suppresses_client_error(),
            5 => self.suppresses_server_error(),
            _ => false,
        }
    }
}

impl From<u8> for CoapNoResponse {
    fn from(mask: u8) -> Self {
        Self::new(mask)
    }
}

impl From<CoapNoResponse> for CoapOption {
    fn from(value: CoapNoResponse) -> Self {
        CoapOption::new(COAP_OPTION_NO_RESPONSE, value.into_bytes())
    }
}

impl TryFrom<&CoapOption> for CoapNoResponse {
    type Error = CrafterError;

    fn try_from(option: &CoapOption) -> Result<Self> {
        if option.number().value() != COAP_OPTION_NO_RESPONSE {
            return Err(CrafterError::invalid_field_value(
                "coap.no-response",
                "option number is not No-Response",
            ));
        }
        if option.value().len() > 1 {
            return Err(CrafterError::invalid_field_value(
                "coap.no-response",
                "No-Response value must contain at most one byte",
            ));
        }

        Ok(Self {
            mask: option.value().first().copied().unwrap_or(0),
            wire_value: option.value().to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;
    use crate::protocols::coap::{Coap, CoapMessageType};

    #[test]
    fn canonical_masks_cover_each_rfc_7967_response_class() {
        let success = CoapNoResponse::suppress_success();
        assert_eq!(success.mask(), 2);
        assert_eq!(success.as_bytes(), &[2]);
        assert!(success.suppresses_success());
        assert!(!success.suppresses_client_error());
        assert!(!success.suppresses_server_error());

        let client_error = CoapNoResponse::suppress_client_error();
        assert_eq!(client_error.mask(), 8);
        assert!(client_error.suppresses_client_error());

        let server_error = CoapNoResponse::suppress_server_error();
        assert_eq!(server_error.mask(), 16);
        assert!(server_error.suppresses_server_error());

        let interested = CoapNoResponse::interested_in_all();
        assert_eq!(interested.mask(), 0);
        assert_eq!(interested.as_bytes(), b"");
    }

    #[test]
    fn combination_masks_test_response_codes_by_class() {
        let success_and_server = CoapNoResponse::try_new(
            CoapNoResponse::SUPPRESS_SUCCESS | CoapNoResponse::SUPPRESS_SERVER_ERROR,
        )
        .unwrap();
        assert_eq!(success_and_server.mask(), 18);
        assert!(success_and_server.suppresses(CoapCode::content()));
        assert!(!success_and_server.suppresses(CoapCode::bad_request()));
        assert!(success_and_server.suppresses(CoapCode::internal_server_error()));

        let all = CoapNoResponse::suppress_all();
        assert_eq!(all.mask(), 26);
        assert!(all.suppresses(CoapCode::from_parts(2, 31)));
        assert!(all.suppresses(CoapCode::from_parts(4, 29)));
        assert!(all.suppresses(CoapCode::from_parts(5, 3)));
        assert!(!all.suppresses(CoapCode::from_parts(3, 1)));
        assert!(!all.suppresses(CoapCode::get()));
    }

    #[test]
    fn unknown_bits_and_noncanonical_zero_remain_raw_and_validated_separately() {
        let unknown = CoapNoResponse::new(0x81);
        assert_eq!(unknown.mask(), 0x81);
        assert_eq!(unknown.reserved_bits(), 0x81);
        assert_eq!(unknown.as_bytes(), &[0x81]);
        assert!(unknown.validate().is_err());
        assert!(CoapNoResponse::try_new(0x81).is_err());

        let raw = CoapOption::new(COAP_OPTION_NO_RESPONSE, vec![0x81]);
        let decoded = CoapNoResponse::try_from(&raw).unwrap();
        assert_eq!(decoded.mask(), 0x81);
        assert_eq!(CoapOption::from(decoded).value(), &[0x81]);

        let explicit_zero = CoapOption::new(COAP_OPTION_NO_RESPONSE, vec![0]);
        let decoded_zero = CoapNoResponse::try_from(&explicit_zero).unwrap();
        assert_eq!(decoded_zero.mask(), 0);
        assert_eq!(decoded_zero.as_bytes(), &[0]);
        assert_eq!(CoapOption::from(decoded_zero).value(), &[0]);

        let overlong = CoapOption::new(COAP_OPTION_NO_RESPONSE, vec![0, 2]);
        assert!(CoapNoResponse::try_from(&overlong).is_err());
        assert_eq!(overlong.value(), &[0, 2]);
    }

    #[test]
    fn request_builder_appends_exact_bytes_without_changing_message_behavior() {
        let request = Coap::put()
            .message_type(CoapMessageType::NonConfirmable)
            .message_id(0x7d38)
            .no_response(CoapNoResponse::suppress_all());

        assert_eq!(request.code_value(), CoapCode::put());
        assert_eq!(
            request.message_type_value(),
            CoapMessageType::NonConfirmable
        );
        assert_eq!(request.message_id_value(), 0x7d38);
        assert_eq!(request.no_response_value().unwrap().unwrap().mask(), 26);
        assert_eq!(
            Packet::from_layer(request).compile().unwrap().as_bytes(),
            [0x50, 0x03, 0x7d, 0x38, 0xd1, 0xf5, 0x1a]
        );
    }
}
