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

// CoAP Code values remain associated constructors on `CoapCode` rather than
// duplicate public constants. These crate-private values are frozen by the
// reviewed IANA snapshot in `.agents/docs/coap-codepoints.md`.
pub(crate) const COAP_CODE_EMPTY: u8 = 0x00;
pub(crate) const COAP_CODE_GET: u8 = 0x01;
pub(crate) const COAP_CODE_POST: u8 = 0x02;
pub(crate) const COAP_CODE_PUT: u8 = 0x03;
pub(crate) const COAP_CODE_DELETE: u8 = 0x04;
pub(crate) const COAP_CODE_FETCH: u8 = 0x05;
pub(crate) const COAP_CODE_PATCH: u8 = 0x06;
pub(crate) const COAP_CODE_IPATCH: u8 = 0x07;

pub(crate) const COAP_CODE_CREATED: u8 = 0x41;
pub(crate) const COAP_CODE_DELETED: u8 = 0x42;
pub(crate) const COAP_CODE_VALID: u8 = 0x43;
pub(crate) const COAP_CODE_CHANGED: u8 = 0x44;
pub(crate) const COAP_CODE_CONTENT: u8 = 0x45;
pub(crate) const COAP_CODE_CONTINUE: u8 = 0x5f;

pub(crate) const COAP_CODE_BAD_REQUEST: u8 = 0x80;
pub(crate) const COAP_CODE_UNAUTHORIZED: u8 = 0x81;
pub(crate) const COAP_CODE_BAD_OPTION: u8 = 0x82;
pub(crate) const COAP_CODE_FORBIDDEN: u8 = 0x83;
pub(crate) const COAP_CODE_NOT_FOUND: u8 = 0x84;
pub(crate) const COAP_CODE_METHOD_NOT_ALLOWED: u8 = 0x85;
pub(crate) const COAP_CODE_NOT_ACCEPTABLE: u8 = 0x86;
pub(crate) const COAP_CODE_REQUEST_ENTITY_INCOMPLETE: u8 = 0x88;
pub(crate) const COAP_CODE_CONFLICT: u8 = 0x89;
pub(crate) const COAP_CODE_PRECONDITION_FAILED: u8 = 0x8c;
pub(crate) const COAP_CODE_REQUEST_ENTITY_TOO_LARGE: u8 = 0x8d;
pub(crate) const COAP_CODE_UNSUPPORTED_CONTENT_FORMAT: u8 = 0x8f;
pub(crate) const COAP_CODE_UNPROCESSABLE_ENTITY: u8 = 0x96;
pub(crate) const COAP_CODE_TOO_MANY_REQUESTS: u8 = 0x9d;

pub(crate) const COAP_CODE_INTERNAL_SERVER_ERROR: u8 = 0xa0;
pub(crate) const COAP_CODE_NOT_IMPLEMENTED: u8 = 0xa1;
pub(crate) const COAP_CODE_BAD_GATEWAY: u8 = 0xa2;
pub(crate) const COAP_CODE_SERVICE_UNAVAILABLE: u8 = 0xa3;
pub(crate) const COAP_CODE_GATEWAY_TIMEOUT: u8 = 0xa4;
pub(crate) const COAP_CODE_PROXYING_NOT_SUPPORTED: u8 = 0xa5;
pub(crate) const COAP_CODE_HOP_LIMIT_REACHED: u8 = 0xa8;

pub(crate) const COAP_CODE_CSM: u8 = 0xe1;
pub(crate) const COAP_CODE_PING: u8 = 0xe2;
pub(crate) const COAP_CODE_PONG: u8 = 0xe3;
pub(crate) const COAP_CODE_RELEASE: u8 = 0xe4;
pub(crate) const COAP_CODE_ABORT: u8 = 0xe5;

// Datagram CoAP Option Numbers admitted by the reviewed packet API. Registry
// rows whose semantics are draft-backed, external, or explicitly outside the
// project scope remain available through `coap_option_meta` without receiving
// a stable builder constant here.
/// If-Match option number (RFC 7252).
pub const COAP_OPTION_IF_MATCH: u16 = 1;
/// Uri-Host option number (RFC 7252).
pub const COAP_OPTION_URI_HOST: u16 = 3;
/// ETag option number (RFC 7252).
pub const COAP_OPTION_ETAG: u16 = 4;
/// If-None-Match option number (RFC 7252).
pub const COAP_OPTION_IF_NONE_MATCH: u16 = 5;
/// Observe option number (RFC 7641).
pub const COAP_OPTION_OBSERVE: u16 = 6;
/// Uri-Port option number (RFC 7252).
pub const COAP_OPTION_URI_PORT: u16 = 7;
/// Location-Path option number (RFC 7252).
pub const COAP_OPTION_LOCATION_PATH: u16 = 8;
/// OSCORE option number (RFC 8613).
pub const COAP_OPTION_OSCORE: u16 = 9;
/// Uri-Path option number (RFC 7252).
pub const COAP_OPTION_URI_PATH: u16 = 11;
/// Content-Format option number (RFC 7252).
pub const COAP_OPTION_CONTENT_FORMAT: u16 = 12;
/// Max-Age option number (RFC 7252).
pub const COAP_OPTION_MAX_AGE: u16 = 14;
/// Uri-Query option number (RFC 7252).
pub const COAP_OPTION_URI_QUERY: u16 = 15;
/// Hop-Limit option number (RFC 8768).
pub const COAP_OPTION_HOP_LIMIT: u16 = 16;
/// Accept option number (RFC 7252).
pub const COAP_OPTION_ACCEPT: u16 = 17;
/// Q-Block1 option number (RFC 9177).
pub const COAP_OPTION_Q_BLOCK1: u16 = 19;
/// Location-Query option number (RFC 7252).
pub const COAP_OPTION_LOCATION_QUERY: u16 = 20;
/// Block2 option number (RFC 7959).
pub const COAP_OPTION_BLOCK2: u16 = 23;
/// Block1 option number (RFC 7959).
pub const COAP_OPTION_BLOCK1: u16 = 27;
/// Size2 option number (RFC 7959).
pub const COAP_OPTION_SIZE2: u16 = 28;
/// Q-Block2 option number (RFC 9177).
pub const COAP_OPTION_Q_BLOCK2: u16 = 31;
/// Proxy-Uri option number (RFC 7252).
pub const COAP_OPTION_PROXY_URI: u16 = 35;
/// Proxy-Scheme option number (RFC 7252).
pub const COAP_OPTION_PROXY_SCHEME: u16 = 39;
/// Size1 option number (RFC 7252).
pub const COAP_OPTION_SIZE1: u16 = 60;
/// Echo option number (RFC 9175).
pub const COAP_OPTION_ECHO: u16 = 252;
/// No-Response option number (RFC 7967).
pub const COAP_OPTION_NO_RESPONSE: u16 = 258;
/// Request-Tag option number (RFC 9175).
pub const COAP_OPTION_REQUEST_TAG: u16 = 292;

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
