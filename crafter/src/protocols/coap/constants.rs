//! CoAP wire constants.
//!
//! The datagram layout and defaults are frozen in
//! `.agents/docs/coap-wire-grammar.md`; service assignments are frozen in
//! `.agents/docs/coap-codepoints.md`. These values describe packet bytes and
//! transport registrations only. They do not authorize live traffic.

/// Length of the fixed CoAP datagram header in octets (RFC 7252 Section 3).
pub const COAP_HEADER_LEN: usize = 4;

/// Wire mask for the Version field in the first octet (RFC 7252 Section 3).
pub const COAP_VERSION_MASK: u8 = 0b1100_0000;
/// Shift for the Version field in the first octet (RFC 7252 Section 3).
pub const COAP_VERSION_SHIFT: u8 = 6;
/// Wire mask for the Type field in the first octet (RFC 7252 Section 3).
pub const COAP_TYPE_MASK: u8 = 0b0011_0000;
/// Shift for the Type field in the first octet (RFC 7252 Section 3).
pub const COAP_TYPE_SHIFT: u8 = 4;
/// Wire mask for the Token Length field in the first octet (RFC 7252 Section 3).
pub const COAP_TKL_MASK: u8 = 0b0000_1111;
/// Shift for the Token Length field in the first octet (RFC 7252 Section 3).
pub const COAP_TKL_SHIFT: u8 = 0;

/// Wire mask for the code class in the Code octet (RFC 7252 Section 3).
pub const COAP_CODE_CLASS_MASK: u8 = 0b1110_0000;
/// Shift for the code class in the Code octet (RFC 7252 Section 3).
pub const COAP_CODE_CLASS_SHIFT: u8 = 5;
/// Wire mask for the code detail in the Code octet (RFC 7252 Section 3).
pub const COAP_CODE_DETAIL_MASK: u8 = 0b0001_1111;

/// Payload marker separating options from payload (RFC 7252 Sections 3 and 3.1).
pub const COAP_PAYLOAD_MARKER: u8 = 0xff;

/// Maximum base CoAP token length in octets (RFC 7252 Section 3).
///
/// RFC 8974 Section 2.1 defines the extended token-length forms implemented by
/// the later extended-token codec; this constant intentionally names the base
/// RFC 7252 limit.
pub const COAP_MAX_TOKEN_LEN: usize = 8;

/// CoAP version defined by RFC 7252 Section 3.
pub const COAP_VERSION_1: u8 = 1;

/// Unset Version compile default from the CoAP wire grammar defaults table.
pub const COAP_DEFAULT_VERSION: u8 = COAP_VERSION_1;
/// Unset Type compile default: Confirmable (RFC 7252 Sections 3 and 4.2).
pub const COAP_DEFAULT_TYPE: u8 = 0;
/// Unset Token Length compile default for an empty token (RFC 7252 Section 3).
pub const COAP_DEFAULT_TKL: u8 = 0;
/// Unset Code compile default: Empty `0.00` (RFC 7252 Sections 3 and 4.1).
pub const COAP_DEFAULT_CODE: u8 = 0;
/// Deterministic unset Message ID compile default from the CoAP wire grammar.
pub const COAP_DEFAULT_MESSAGE_ID: u16 = 0;

/// Assigned cleartext CoAP service port (IANA coap rows; RFC 7252 Section 12).
pub const COAP_PORT: u16 = 5683;
/// Assigned secure CoAP service port (IANA coaps rows; RFC 7252 Section 12).
pub const COAPS_PORT: u16 = 5684;

/// Explicit UDP alias for the assigned cleartext CoAP service port.
pub const COAP_UDP_PORT: u16 = COAP_PORT;
/// Explicit UDP alias for the assigned DTLS-secured CoAP service port.
pub const COAPS_UDP_PORT: u16 = COAPS_PORT;
/// Explicit TCP alias for the reliable CoAP service port (RFC 8323 Section 11).
pub const COAP_TCP_PORT: u16 = COAP_PORT;
/// Explicit TCP alias for the reliable secure CoAP service port (RFC 8323 Section 11).
pub const COAPS_TCP_PORT: u16 = COAPS_PORT;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_source_backed_lengths_and_marker() {
        assert_eq!(COAP_HEADER_LEN, 4);
        assert_eq!(COAP_MAX_TOKEN_LEN, 8);
        assert_eq!(COAP_PAYLOAD_MARKER, 0xff);
    }

    #[test]
    fn first_octet_masks_and_shifts_match_the_wire_layout() {
        assert_eq!(COAP_VERSION_MASK, 0xc0);
        assert_eq!(COAP_VERSION_SHIFT, 6);
        assert_eq!(COAP_TYPE_MASK, 0x30);
        assert_eq!(COAP_TYPE_SHIFT, 4);
        assert_eq!(COAP_TKL_MASK, 0x0f);
        assert_eq!(COAP_TKL_SHIFT, 0);

        assert_eq!(COAP_VERSION_MASK | COAP_TYPE_MASK | COAP_TKL_MASK, 0xff);
        assert_eq!(COAP_VERSION_MASK & COAP_TYPE_MASK, 0);
        assert_eq!(COAP_VERSION_MASK & COAP_TKL_MASK, 0);
        assert_eq!(COAP_TYPE_MASK & COAP_TKL_MASK, 0);

        let first = (COAP_VERSION_1 << COAP_VERSION_SHIFT) | (2 << COAP_TYPE_SHIFT) | 8;
        assert_eq!((first & COAP_VERSION_MASK) >> COAP_VERSION_SHIFT, 1);
        assert_eq!((first & COAP_TYPE_MASK) >> COAP_TYPE_SHIFT, 2);
        assert_eq!((first & COAP_TKL_MASK) >> COAP_TKL_SHIFT, 8);
    }

    #[test]
    fn code_masks_and_shift_match_the_wire_layout() {
        assert_eq!(COAP_CODE_CLASS_MASK, 0xe0);
        assert_eq!(COAP_CODE_CLASS_SHIFT, 5);
        assert_eq!(COAP_CODE_DETAIL_MASK, 0x1f);
        assert_eq!(COAP_CODE_CLASS_MASK | COAP_CODE_DETAIL_MASK, 0xff);
        assert_eq!(COAP_CODE_CLASS_MASK & COAP_CODE_DETAIL_MASK, 0);

        let code = (4 << COAP_CODE_CLASS_SHIFT) | 4;
        assert_eq!((code & COAP_CODE_CLASS_MASK) >> COAP_CODE_CLASS_SHIFT, 4);
        assert_eq!(code & COAP_CODE_DETAIL_MASK, 4);
    }

    #[test]
    fn defaults_match_the_frozen_unset_message_shape() {
        assert_eq!(COAP_DEFAULT_VERSION, COAP_VERSION_1);
        assert_eq!(COAP_DEFAULT_TYPE, 0);
        assert_eq!(COAP_DEFAULT_TKL, 0);
        assert_eq!(COAP_DEFAULT_CODE, 0);
        assert_eq!(COAP_DEFAULT_MESSAGE_ID, 0);

        let first = (COAP_DEFAULT_VERSION << COAP_VERSION_SHIFT)
            | (COAP_DEFAULT_TYPE << COAP_TYPE_SHIFT)
            | (COAP_DEFAULT_TKL << COAP_TKL_SHIFT);
        assert_eq!(first, 0x40);
    }

    #[test]
    fn service_port_aliases_match_the_iana_rows() {
        assert_eq!(COAP_PORT, 5683);
        assert_eq!(COAPS_PORT, 5684);
        assert_eq!(COAP_UDP_PORT, COAP_PORT);
        assert_eq!(COAPS_UDP_PORT, COAPS_PORT);
        assert_eq!(COAP_TCP_PORT, COAP_PORT);
        assert_eq!(COAPS_TCP_PORT, COAPS_PORT);
    }
}
