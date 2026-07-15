//! CoAP datagram message layers.
//!
//! Header, default, and override behavior follows
//! `.agents/docs/coap-wire-grammar.md` and RFC 7252 Sections 3 and 4.1.
//! Extended token-length metadata follows RFC 8974 Section 2.1; canonical
//! extended-token emission remains assigned to the later extended-token
//! codec.

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{CrafterError, Result};
use crate::field::{Field, FieldState};
use crate::packet::{hexdump, Layer, LayerContext, Packet};
use crate::protocols::ip::{v4::Ipv4, v6::Ipv6};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::protocols::transport::Udp;

use super::constants::*;
use super::option::{
    encode_option_sequence, CoapAccept, CoapContentFormat, CoapEtag, CoapIfMatch, CoapIfNoneMatch,
    CoapOption, CoapOptions, CoapUriHost, CoapUriPath, CoapUriPort, CoapUriQuery,
};
use super::registry::{coap_code_meta, coap_signaling_code_meta, CoapRegistryMeta};

const COAP_TWO_BIT_VALUE_MASK: u8 = 0x03;
const COAP_TYPE_CONFIRMABLE: u8 = 0;
const COAP_TYPE_NON_CONFIRMABLE: u8 = 1;
const COAP_TYPE_ACKNOWLEDGEMENT: u8 = 2;
const COAP_TYPE_RESET: u8 = 3;
const COAP_INSPECTION_HEX_LIMIT: usize = 16;

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

/// Owned, byte-preserving CoAP token.
///
/// Token bytes are opaque and are deliberately modeled separately from the
/// header Token Length field. This permits callers to preserve extended
/// tokens and intentionally malformed token-length overrides without changing
/// the owned bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CoapToken(Vec<u8>);

impl CoapToken {
    /// Build a token whose length is canonical for base RFC 7252 datagrams.
    ///
    /// Extended-token header encoding is added separately. Until then, use
    /// [`Self::from_bytes`] to preserve extended or intentionally malformed
    /// token values.
    pub fn new(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        validate_base_token_len(bytes.len())?;
        Ok(Self(bytes.to_vec()))
    }

    /// Preserve token bytes without applying the base-token length policy.
    ///
    /// This constructor never truncates or normalizes its input. It is the
    /// explicit path for extended-token construction, decoded bytes, and
    /// intentionally malformed test packets.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(bytes.as_ref().to_vec())
    }

    /// Borrow the preserved token bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the token and return its owned bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Return the number of preserved token bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return true when the token contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return the token as lowercase hexadecimal without interpreting it as
    /// text.
    pub fn to_hex(&self) -> String {
        let mut output = String::with_capacity(self.len() * 2);
        for byte in self.as_bytes() {
            output.push_str(&format!("{byte:02x}"));
        }
        output
    }

    /// Return the token using the crate's stable binary hex-dump format.
    pub fn hexdump(&self) -> String {
        hexdump(self.as_bytes())
    }
}

impl AsRef<[u8]> for CoapToken {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for CoapToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Lossless CoAP datagram Token Length metadata.
///
/// The discriminator, extension bytes, and logical declared length remain
/// independent so decoded noncanonical forms and intentionally malformed
/// caller overrides can be retained without changing the owned token bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoapTokenLength {
    nibble: u8,
    extension_bytes: Vec<u8>,
    declared_len: usize,
}

impl CoapTokenLength {
    /// Build the shortest RFC 8974 token-length representation for `len`.
    pub fn canonical_for_len(len: usize) -> Result<Self> {
        match len {
            0..=12 => Ok(Self::explicit(len as u8, Vec::new(), len)),
            13..=268 => Ok(Self::explicit(13, vec![(len - 13) as u8], len)),
            269..=65_804 => Ok(Self::explicit(
                14,
                ((len - 269) as u16).to_be_bytes().to_vec(),
                len,
            )),
            _ => Err(CrafterError::invalid_field_value(
                "coap.token-length",
                "token length exceeds the RFC 8974 encoding range",
            )),
        }
    }

    /// Preserve explicit token-length metadata without requiring its parts to
    /// agree with one another or with the owned token bytes.
    pub fn explicit(nibble: u8, extension_bytes: impl Into<Vec<u8>>, declared_len: usize) -> Self {
        Self {
            nibble,
            extension_bytes: extension_bytes.into(),
            declared_len,
        }
    }

    /// Return the preserved Token Length discriminator without masking.
    pub const fn nibble(&self) -> u8 {
        self.nibble
    }

    /// Borrow the exact token-length extension bytes.
    pub fn extension_bytes(&self) -> &[u8] {
        &self.extension_bytes
    }

    /// Return the preserved logical declared token length.
    pub const fn declared_len(&self) -> usize {
        self.declared_len
    }
}

impl Default for CoapTokenLength {
    fn default() -> Self {
        Self::explicit(COAP_DEFAULT_TKL, Vec::new(), 0)
    }
}

/// Explicit CoAP payload-marker choice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum CoapPayloadMarker {
    /// Do not place a payload marker before the owned payload bytes.
    #[default]
    Absent,
    /// Place the `0xff` payload marker before the owned payload bytes.
    Present,
}

impl CoapPayloadMarker {
    /// Return true when the payload marker is selected.
    pub const fn is_present(self) -> bool {
        matches!(self, Self::Present)
    }
}

/// Ordering policy used when compiling CoAP options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum CoapOptionOrder {
    /// Stably sort options by number before encoding them.
    #[default]
    Canonical,
    /// Encode options in caller-provided order, including explicit malformed
    /// delta/header overrides.
    Wire,
}

static EMPTY_COAP_TOKEN: CoapToken = CoapToken(Vec::new());

/// One owned CoAP datagram message.
///
/// Header fields, token bytes, marker state, and payload bytes remain
/// independent so callers can construct malformed packets deliberately.
/// Compilation fills only unset fields in later wire-encoding steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coap {
    version: Field<CoapVersion>,
    message_type: Field<CoapMessageType>,
    token_length: Field<CoapTokenLength>,
    code: Field<CoapCode>,
    message_id: Field<u16>,
    token: Field<CoapToken>,
    options: Vec<CoapOption>,
    option_order: CoapOptionOrder,
    payload_marker: Field<CoapPayloadMarker>,
    payload: Vec<u8>,
}

impl Coap {
    /// Create an empty CoAP datagram layer whose compile-time fields are unset.
    pub fn new() -> Self {
        Self {
            version: Field::unset(),
            message_type: Field::unset(),
            token_length: Field::unset(),
            code: Field::unset(),
            message_id: Field::unset(),
            token: Field::unset(),
            options: Vec::new(),
            option_order: CoapOptionOrder::Canonical,
            payload_marker: Field::unset(),
            payload: Vec::new(),
        }
    }

    /// Build an Empty (`0.00`) message without pinning dependent fields.
    pub fn empty() -> Self {
        Self::new().code(CoapCode::empty())
    }

    /// Build a request with an explicit code.
    ///
    /// The code is not semantically restricted here so malformed and future
    /// values remain constructible. Validation is an explicit later step.
    pub fn request(code: CoapCode) -> Self {
        Self::new().code(code)
    }

    /// Build a response with an explicit code and no inferred message type.
    ///
    /// Whether a response is Confirmable, Non-confirmable, or piggybacked in
    /// an Acknowledgement depends on caller transaction context.
    pub fn response(code: CoapCode) -> Self {
        Self::new().code(code)
    }

    /// Build a GET (`0.01`) request.
    pub fn get() -> Self {
        Self::request(CoapCode::get())
    }

    /// Build a POST (`0.02`) request.
    pub fn post() -> Self {
        Self::request(CoapCode::post())
    }

    /// Build a PUT (`0.03`) request.
    pub fn put() -> Self {
        Self::request(CoapCode::put())
    }

    /// Build a DELETE (`0.04`) request.
    pub fn delete() -> Self {
        Self::request(CoapCode::delete())
    }

    /// Set the preserved Version value explicitly.
    pub fn version(mut self, value: impl Into<CoapVersion>) -> Self {
        self.version.set_user(value.into());
        self
    }

    /// Set the preserved datagram message Type explicitly.
    pub fn message_type(mut self, value: CoapMessageType) -> Self {
        self.message_type.set_user(value);
        self
    }

    /// Set explicit token-length metadata independently from the token bytes.
    pub fn token_length(mut self, value: CoapTokenLength) -> Self {
        self.token_length.set_user(value);
        self
    }

    /// Set the preserved Code byte explicitly.
    pub fn code(mut self, value: impl Into<CoapCode>) -> Self {
        self.code.set_user(value.into());
        self
    }

    /// Set the Message ID explicitly.
    pub fn message_id(mut self, value: u16) -> Self {
        self.message_id.set_user(value);
        self
    }

    /// Set owned token bytes independently from token-length metadata.
    pub fn token(mut self, value: impl Into<CoapToken>) -> Self {
        self.token.set_user(value.into());
        self
    }

    /// Append one option while preserving insertion order.
    pub fn option(mut self, value: impl Into<CoapOption>) -> Self {
        self.options.push(value.into());
        self
    }

    /// Append one Uri-Host option without replacing an existing occurrence.
    pub fn uri_host(self, value: impl Into<CoapUriHost>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one Uri-Port option without replacing an existing occurrence.
    pub fn uri_port(self, value: impl Into<CoapUriPort>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one Uri-Path segment without replacing existing segments.
    pub fn uri_path(self, value: impl Into<CoapUriPath>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one Uri-Query argument without replacing existing arguments.
    pub fn uri_query(self, value: impl Into<CoapUriQuery>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one If-Match value without replacing existing occurrences.
    pub fn if_match(self, value: impl Into<CoapIfMatch>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append the empty If-None-Match option.
    pub fn if_none_match(self) -> Self {
        self.option(CoapOption::from(CoapIfNoneMatch::new()))
    }

    /// Append one ETag value without replacing existing occurrences.
    pub fn etag(self, value: impl Into<CoapEtag>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one Content-Format value without replacing an existing occurrence.
    pub fn content_format(self, value: impl Into<CoapContentFormat>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one Accept value without replacing an existing occurrence.
    pub fn accept(self, value: impl Into<CoapAccept>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Replace the ordered option sequence.
    pub fn options(mut self, values: impl IntoIterator<Item = CoapOption>) -> Self {
        self.options = values.into_iter().collect();
        self
    }

    /// Select how option occurrences are ordered during compilation.
    ///
    /// Canonical ordering is the default. Wire order is explicit so callers
    /// can retain deliberately malformed order and header overrides.
    pub fn option_order(mut self, value: CoapOptionOrder) -> Self {
        self.option_order = value;
        self
    }

    /// Set an explicit payload-marker choice independently from payload bytes.
    pub fn payload_marker(mut self, value: CoapPayloadMarker) -> Self {
        self.payload_marker.set_user(value);
        self
    }

    /// Set the owned binary payload independently from marker state.
    pub fn payload(mut self, value: impl Into<Vec<u8>>) -> Self {
        self.payload = value.into();
        self
    }

    /// Select a Confirmable message type.
    pub fn confirmable(self) -> Self {
        self.message_type(CoapMessageType::Confirmable)
    }

    /// Select a Non-confirmable message type.
    pub fn non_confirmable(self) -> Self {
        self.message_type(CoapMessageType::NonConfirmable)
    }

    /// Select an Acknowledgement message type.
    pub fn acknowledgement(self) -> Self {
        self.message_type(CoapMessageType::Acknowledgement)
    }

    /// Select a Reset message type.
    pub fn reset(self) -> Self {
        self.message_type(CoapMessageType::Reset)
    }

    /// Return the Version field state.
    pub const fn version_state(&self) -> FieldState {
        self.version.state()
    }

    /// Return the explicit Version or the current compile-time default.
    pub fn version_value(&self) -> CoapVersion {
        self.version.value().copied().unwrap_or_default()
    }

    /// Return the message Type field state.
    pub const fn message_type_state(&self) -> FieldState {
        self.message_type.state()
    }

    /// Return the explicit message Type or the Confirmable default.
    pub fn message_type_value(&self) -> CoapMessageType {
        self.message_type.value().copied().unwrap_or_default()
    }

    /// Return the token-length metadata field state.
    pub const fn token_length_state(&self) -> FieldState {
        self.token_length.state()
    }

    /// Return explicit token-length metadata or derive the canonical value.
    pub fn token_length_value(&self) -> Result<CoapTokenLength> {
        match self.token_length.value() {
            Some(value) => Ok(value.clone()),
            None => {
                let token_len = self.token_value().len();
                validate_base_token_len(token_len)?;
                CoapTokenLength::canonical_for_len(token_len)
            }
        }
    }

    /// Return the Code field state.
    pub const fn code_state(&self) -> FieldState {
        self.code.state()
    }

    /// Return the explicit Code or the Empty compile-time default.
    pub fn code_value(&self) -> CoapCode {
        self.code.value().copied().unwrap_or_default()
    }

    /// Return the Message ID field state.
    pub const fn message_id_state(&self) -> FieldState {
        self.message_id.state()
    }

    /// Return the explicit Message ID or the deterministic zero default.
    pub fn message_id_value(&self) -> u16 {
        self.message_id
            .value()
            .copied()
            .unwrap_or(COAP_DEFAULT_MESSAGE_ID)
    }

    /// Return the token field state.
    pub const fn token_state(&self) -> FieldState {
        self.token.state()
    }

    /// Borrow explicit token bytes or the effective empty token.
    pub fn token_value(&self) -> &CoapToken {
        self.token.value().unwrap_or(&EMPTY_COAP_TOKEN)
    }

    /// Borrow option occurrences in their preserved order.
    pub fn options_value(&self) -> &[CoapOption] {
        &self.options
    }

    /// Return the selected option compilation order.
    pub const fn option_order_value(&self) -> CoapOptionOrder {
        self.option_order
    }

    /// Return the payload-marker field state.
    pub const fn payload_marker_state(&self) -> FieldState {
        self.payload_marker.state()
    }

    /// Return the explicit marker choice or derive it from payload presence.
    pub fn payload_marker_value(&self) -> CoapPayloadMarker {
        self.payload_marker.value().copied().unwrap_or_else(|| {
            if self.payload.is_empty() {
                CoapPayloadMarker::Absent
            } else {
                CoapPayloadMarker::Present
            }
        })
    }

    /// Borrow the exact owned payload bytes.
    pub fn payload_value(&self) -> &[u8] {
        &self.payload
    }

    fn first_octet_value(&self) -> Result<u8> {
        let version = self.version_value().wire_value() << COAP_VERSION_SHIFT;
        let message_type = self.message_type_value().wire_value() << COAP_TYPE_SHIFT;
        let token_length = self.token_length_value()?.nibble() << COAP_TKL_SHIFT;

        Ok((version & COAP_VERSION_MASK)
            | (message_type & COAP_TYPE_MASK)
            | (token_length & COAP_TKL_MASK))
    }

    fn encoded_options(&self) -> Result<Vec<u8>> {
        let mut options = CoapOptions::from_options(self.options.iter().cloned());
        if self.option_order == CoapOptionOrder::Canonical {
            options.sort_canonical();
        }

        let mut encoded = Vec::new();
        encode_option_sequence(&options, &mut encoded)?;
        Ok(encoded)
    }

    fn version_inspection_label(&self) -> String {
        let version = self.version_value();
        if self.version_state() == FieldState::User && !version.is_current() {
            format!("{} [explicit-noncurrent]", version.value())
        } else {
            version.value().to_string()
        }
    }

    fn message_type_inspection_label(&self) -> String {
        let message_type = self.message_type_value();
        if self.message_type_state() == FieldState::User && message_type.is_unknown() {
            format!("{} [explicit-out-of-range]", message_type.label())
        } else {
            message_type.label()
        }
    }

    fn code_inspection_label(&self) -> String {
        let code = self.code_value();
        // `CoapCode` is shared with reliable framing, where class 7 selects
        // signaling metadata. This layer is specifically an RFC 7252
        // datagram, whose classes 6 and 7 remain reserved.
        let metadata = coap_code_meta(code.wire_value());
        let mut label = format!("{}({})", code.label(), metadata.label);

        if self.code_state() == FieldState::User && matches!(code.class(), 1 | 3 | 6 | 7) {
            label.push_str(" [explicit-reserved]");
        }
        if code.is_empty()
            && (!self.token_value().is_empty()
                || !self.options.is_empty()
                || self.payload_marker_value().is_present()
                || !self.payload.is_empty())
        {
            label.push_str(" [empty-message-mismatch]");
        }

        label
    }

    fn token_length_inspection_label(&self) -> String {
        let actual_len = self.token_value().len();
        let Ok(token_length) = self.token_length_value() else {
            return format!("{actual_len} [unset-invalid]");
        };

        if self.token_length_state() == FieldState::User
            && !token_length_matches_bytes(&token_length, actual_len)
        {
            format!(
                "{} [explicit-mismatch:nibble={},actual={actual_len}]",
                token_length.declared_len(),
                token_length.nibble()
            )
        } else {
            token_length.declared_len().to_string()
        }
    }

    fn token_inspection_label(&self) -> String {
        let token = self.token_value();
        format!("len={} hex={}", token.len(), bounded_hex(token.as_bytes()))
    }

    fn option_malformed_overrides(&self) -> Vec<bool> {
        let mut indices = (0..self.options.len()).collect::<Vec<_>>();
        if self.option_order == CoapOptionOrder::Canonical {
            indices.sort_by_key(|index| self.options[*index].number());
        }

        let mut malformed = vec![false; self.options.len()];
        let mut previous_number = 0u16;
        for index in indices {
            let option = &self.options[index];
            let number = option.number().value();
            let out_of_order =
                self.option_order == CoapOptionOrder::Wire && number < previous_number;
            let expected_delta = u32::from(number.saturating_sub(previous_number));
            previous_number = number;

            malformed[index] = out_of_order || option_encoding_mismatch(option, expected_delta);
        }

        malformed
    }

    fn options_have_malformed_overrides(&self) -> bool {
        self.option_malformed_overrides()
            .into_iter()
            .any(|value| value)
    }

    fn options_inspection_label(&self) -> String {
        if self.options.is_empty() {
            return "0 []".to_string();
        }

        let malformed = self.option_malformed_overrides();
        let labels = self
            .options
            .iter()
            .enumerate()
            .map(|(index, option)| {
                let number = option.number().value();
                let metadata = option.registry_meta();

                let value = if number == COAP_OPTION_OSCORE {
                    "<redacted>".to_string()
                } else {
                    bounded_hex(option.value())
                };
                let mut label = format!(
                    "{}({},len={},hex={value})",
                    metadata.label,
                    number,
                    option.value().len()
                );

                if malformed[index] {
                    label.push_str(" [malformed-override]");
                }
                label
            })
            .collect::<Vec<_>>()
            .join(", ");

        format!("{} [{labels}]", self.options.len())
    }

    fn payload_marker_inspection_label(&self) -> String {
        let marker = self.payload_marker_value();
        let label = if marker.is_present() {
            "present"
        } else {
            "absent"
        };
        let mismatch = self.payload_marker_state() == FieldState::User
            && marker.is_present() != !self.payload.is_empty();

        if mismatch {
            format!("{label} [explicit-mismatch]")
        } else {
            label.to_string()
        }
    }
}

impl Default for Coap {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Coap {
    fn name(&self) -> &'static str {
        "Coap"
    }

    fn summary(&self) -> String {
        let options = if self.options_have_malformed_overrides() {
            format!("{} [malformed-override]", self.options.len())
        } else {
            self.options.len().to_string()
        };

        format!(
            "Coap(version={}, type={}, code={}, mid=0x{:04x}, token_len={}, options={}, marker={}, payload={} bytes)",
            self.version_inspection_label(),
            self.message_type_inspection_label(),
            self.code_inspection_label(),
            self.message_id_value(),
            self.token_length_inspection_label(),
            options,
            self.payload_marker_inspection_label(),
            self.payload.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("version", self.version_inspection_label()),
            ("type", self.message_type_inspection_label()),
            ("token_length", self.token_length_inspection_label()),
            ("code", self.code_inspection_label()),
            ("message_id", format!("0x{:04x}", self.message_id_value())),
            ("token", self.token_inspection_label()),
            ("options", self.options_inspection_label()),
            ("payload_marker", self.payload_marker_inspection_label()),
            ("payload_length", self.payload.len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        let option_len = self
            .encoded_options()
            .map(|options| options.len())
            .unwrap_or_default();
        let marker_len = usize::from(self.payload_marker_value().is_present());

        COAP_HEADER_LEN
            .saturating_add(self.token_value().len())
            .saturating_add(option_len)
            .saturating_add(marker_len)
            .saturating_add(self.payload.len())
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let first_octet = self.first_octet_value()?;
        let options = self.encoded_options()?;
        let mut encoded = Vec::with_capacity(self.encoded_len());

        encoded.push(first_octet);
        encoded.push(self.code_value().wire_value());
        encoded.extend_from_slice(&self.message_id_value().to_be_bytes());
        encoded.extend_from_slice(self.token_value().as_bytes());
        encoded.extend_from_slice(&options);
        if self.payload_marker_value().is_present() {
            encoded.push(COAP_PAYLOAD_MARKER);
        }
        encoded.extend_from_slice(&self.payload);
        out.extend_from_slice(&encoded);
        Ok(())
    }

    impl_layer_object!(Coap);
}

impl_layer_div!(Coap);

/// Build a UDP header for a cleartext CoAP client request.
///
/// Only the assigned cleartext destination port is pinned. Callers may
/// override either UDP port after construction.
pub fn coap_request_udp() -> Udp {
    Udp::new().destination_port(COAP_UDP_PORT)
}

/// Build a UDP header for a cleartext CoAP server response.
///
/// Only the assigned cleartext source port is pinned. Callers may override
/// either UDP port after construction.
pub fn coap_response_udp() -> Udp {
    Udp::new().source_port(COAP_UDP_PORT)
}

/// Build an IPv4/UDP/CoAP request packet without sending it.
///
/// Documentation-safe examples can use `192.0.2.10` as `source` and
/// `198.51.100.20` as `destination`; this helper never selects an interface or
/// performs network I/O.
pub fn coap_ipv4_request(source: Ipv4Addr, destination: Ipv4Addr, message: Coap) -> Packet {
    Ipv4::with_addresses(source, destination) / coap_request_udp() / message
}

/// Build an IPv4/UDP/CoAP response packet without sending it.
///
/// Documentation-safe examples can use `198.51.100.20` as `source` and
/// `192.0.2.10` as `destination`; this helper never selects an interface or
/// performs network I/O.
pub fn coap_ipv4_response(source: Ipv4Addr, destination: Ipv4Addr, message: Coap) -> Packet {
    Ipv4::with_addresses(source, destination) / coap_response_udp() / message
}

/// Build an IPv6/UDP/CoAP request packet without sending it.
///
/// Documentation-safe examples can use `2001:db8::10` as `source` and
/// `2001:db8::20` as `destination`; this helper never selects an interface or
/// performs network I/O.
pub fn coap_ipv6_request(source: Ipv6Addr, destination: Ipv6Addr, message: Coap) -> Packet {
    Ipv6::with_addresses(source, destination) / coap_request_udp() / message
}

/// Build an IPv6/UDP/CoAP response packet without sending it.
///
/// Documentation-safe examples can use `2001:db8::20` as `source` and
/// `2001:db8::10` as `destination`; this helper never selects an interface or
/// performs network I/O.
pub fn coap_ipv6_response(source: Ipv6Addr, destination: Ipv6Addr, message: Coap) -> Packet {
    Ipv6::with_addresses(source, destination) / coap_response_udp() / message
}

fn bounded_hex(bytes: &[u8]) -> String {
    let shown = bytes.len().min(COAP_INSPECTION_HEX_LIMIT);
    let mut output = String::with_capacity(shown.saturating_mul(2).saturating_add(24));
    for byte in &bytes[..shown] {
        output.push_str(&format!("{byte:02x}"));
    }
    if bytes.len() > shown {
        output.push_str(&format!("...(+{} bytes)", bytes.len() - shown));
    }
    output
}

fn token_length_matches_bytes(token_length: &CoapTokenLength, actual_len: usize) -> bool {
    if token_length.declared_len() != actual_len {
        return false;
    }

    match token_length.nibble() {
        0..=12 => {
            token_length.extension_bytes().is_empty()
                && token_length.declared_len() == usize::from(token_length.nibble())
        }
        13 => {
            let extension = token_length.extension_bytes();
            extension.len() == 1
                && token_length.declared_len() == 13usize.saturating_add(usize::from(extension[0]))
        }
        14 => {
            let extension = token_length.extension_bytes();
            extension.len() == 2
                && token_length.declared_len()
                    == 269usize.saturating_add(usize::from(u16::from_be_bytes([
                        extension[0],
                        extension[1],
                    ])))
        }
        _ => false,
    }
}

fn option_encoding_mismatch(option: &CoapOption, expected_delta: u32) -> bool {
    let Some(encoding) = option.encoding() else {
        return false;
    };

    encoding
        .wire_delta()
        .is_some_and(|wire_delta| wire_delta != expected_delta)
        || encoding
            .wire_length()
            .is_some_and(|wire_length| wire_length != option.value().len())
        || (encoding.raw_bytes().is_some()
            && encoding.wire_delta().is_none()
            && encoding.wire_length().is_none())
}

fn validate_base_token_len(len: usize) -> Result<()> {
    if len <= COAP_MAX_TOKEN_LEN {
        Ok(())
    } else {
        Err(CrafterError::invalid_field_value(
            "coap.token-length",
            "base CoAP tokens must be at most 8 bytes",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::IntoPacket;
    use crate::protocols::transport::UDP_HEADER_LEN;

    #[test]
    fn coap_packet_storage_supports_conversion_typed_access_mutation_and_clone() {
        let message = Coap::post()
            .message_id(0x1234)
            .token(CoapToken::from_bytes([0xaa, 0xbb]));
        let converted = message.clone().into_packet();
        let mut packet = Packet::from_layer(message.clone());

        assert_eq!(converted.layer::<Coap>(), Some(&message));
        assert_eq!(packet.layer::<Coap>(), Some(&message));
        assert_eq!(packet.get(0).expect("CoAP layer").name(), "Coap");

        let stored = packet.layer_mut::<Coap>().expect("mutable CoAP layer");
        *stored = stored.clone().message_id(0xabcd).payload(b"ok".to_vec());

        let cloned = packet.clone();
        let cloned_coap = cloned.layer::<Coap>().expect("cloned CoAP layer");
        assert_eq!(cloned_coap.message_id_value(), 0xabcd);
        assert_eq!(cloned_coap.payload_value(), b"ok");
        assert_eq!(cloned.compile().unwrap(), packet.compile().unwrap());
        assert_eq!(
            packet.summary(),
            "Coap(version=1, type=confirmable, code=0.02(POST), mid=0xabcd, token_len=2, options=0, marker=present, payload=2 bytes)"
        );

        let show = packet.show();
        assert!(show.contains("Packet(len=9, layers=1)"), "{show}");
        assert!(show.contains("[0] Coap"), "{show}");
        assert!(show.contains("message_id: 0xabcd"), "{show}");
        assert!(show.contains("payload_length: 2"), "{show}");
    }

    #[test]
    fn coap_slash_composition_builds_ipv4_and_ipv6_udp_stacks() {
        let message = Coap::get()
            .message_id(0x1234)
            .token(CoapToken::from_bytes([0xaa]))
            .payload(b"ok".to_vec());
        let coap_bytes = Packet::from_layer(message.clone()).compile().unwrap();

        let ipv4_packet = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Udp::new().sport(49_152).dport(COAP_UDP_PORT)
            / message.clone();
        assert_eq!(ipv4_packet.len(), 3);
        assert!(ipv4_packet.layer::<Ipv4>().is_some());
        assert!(ipv4_packet.layer::<Udp>().is_some());
        assert_eq!(ipv4_packet.layer::<Coap>(), Some(&message));

        let ipv4_bytes = ipv4_packet.compile().expect("IPv4/UDP/CoAP compiles");
        assert_eq!(ipv4_bytes.len(), 20 + UDP_HEADER_LEN + coap_bytes.len());
        assert_eq!(&ipv4_bytes[20 + UDP_HEADER_LEN..], coap_bytes.as_bytes());
        assert!(ipv4_packet.summary().contains(" / Coap("));
        assert!(ipv4_packet.show().contains("[2] Coap"));

        let ipv6_packet = Ipv6::new()
            .src(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10))
            .dst(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 20))
            / Udp::new().sport(49_152).dport(COAP_UDP_PORT)
            / message.clone();
        assert_eq!(ipv6_packet.len(), 3);
        assert!(ipv6_packet.layer::<Ipv6>().is_some());
        assert!(ipv6_packet.layer::<Udp>().is_some());
        assert_eq!(ipv6_packet.layer::<Coap>(), Some(&message));

        let ipv6_bytes = ipv6_packet.compile().expect("IPv6/UDP/CoAP compiles");
        assert_eq!(ipv6_bytes.len(), 40 + UDP_HEADER_LEN + coap_bytes.len());
        assert_eq!(&ipv6_bytes[40 + UDP_HEADER_LEN..], coap_bytes.as_bytes());
        assert!(ipv6_packet.summary().contains(" / Coap("));
        assert!(ipv6_packet.show().contains("[2] Coap"));
    }

    #[test]
    fn coap_udp_helpers_pin_only_the_cleartext_service_side_port() {
        let request = coap_request_udp();
        assert_eq!(request.destination_port_value(), COAP_UDP_PORT);
        assert_eq!(request.source_port_value(), Udp::new().source_port_value());

        let response = coap_response_udp();
        assert_eq!(response.source_port_value(), COAP_UDP_PORT);
        assert_eq!(
            response.destination_port_value(),
            Udp::new().destination_port_value()
        );

        let request_overrides = coap_request_udp()
            .source_port(49_152)
            .destination_port(12_345);
        assert_eq!(request_overrides.source_port_value(), 49_152);
        assert_eq!(request_overrides.destination_port_value(), 12_345);

        let response_overrides = coap_response_udp()
            .source_port(12_345)
            .destination_port(49_152);
        assert_eq!(response_overrides.source_port_value(), 12_345);
        assert_eq!(response_overrides.destination_port_value(), 49_152);
    }

    #[test]
    fn coap_ip_helpers_compile_typed_documentation_address_stacks() {
        let ipv4_client = Ipv4Addr::new(192, 0, 2, 10);
        let ipv4_server = Ipv4Addr::new(198, 51, 100, 20);
        let ipv6_client = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let ipv6_server = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 20);
        let request = Coap::get().message_id(0x1234);
        let response = Coap::response(CoapCode::content())
            .message_id(0x1234)
            .payload(b"ok".to_vec());

        let packets = [
            coap_ipv4_request(ipv4_client, ipv4_server, request.clone()),
            coap_ipv4_response(ipv4_server, ipv4_client, response.clone()),
            coap_ipv6_request(ipv6_client, ipv6_server, request),
            coap_ipv6_response(ipv6_server, ipv6_client, response),
        ];

        for packet in packets {
            assert!(packet.layer::<Udp>().is_some());
            assert!(packet.layer::<Coap>().is_some());
            assert!(packet.layer::<Ipv4>().is_some() || packet.layer::<Ipv6>().is_some());
            packet
                .compile()
                .expect("documentation-address stack compiles");
        }
    }

    #[test]
    fn empty_default_fixed_header_matches_golden_bytes() {
        let message = Coap::new();

        assert_eq!(message.encoded_len(), COAP_HEADER_LEN);
        assert_eq!(
            Packet::from_layer(message).compile().unwrap().as_bytes(),
            &[0x40, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn explicit_malformed_fixed_header_matches_golden_bytes() {
        let message = Coap::new()
            .version(3u8)
            .message_type(CoapMessageType::Reset)
            .token_length(CoapTokenLength::explicit(15, Vec::new(), 0))
            .code(0xffu8)
            .message_id(0xabcd);

        assert_eq!(message.encoded_len(), COAP_HEADER_LEN);
        assert_eq!(
            Packet::from_layer(message).compile().unwrap().as_bytes(),
            &[0xff, 0xff, 0xab, 0xcd]
        );
    }

    #[test]
    fn coap_new_keeps_fields_unset_and_exposes_effective_defaults() {
        let message = Coap::new();

        assert_eq!(message.version_state(), FieldState::Unset);
        assert_eq!(message.version_value(), CoapVersion::current());
        assert_eq!(message.message_type_state(), FieldState::Unset);
        assert_eq!(message.message_type_value(), CoapMessageType::Confirmable);
        assert_eq!(message.token_length_state(), FieldState::Unset);
        assert_eq!(
            message.token_length_value().unwrap(),
            CoapTokenLength::default()
        );
        assert_eq!(message.code_state(), FieldState::Unset);
        assert_eq!(message.code_value(), CoapCode::empty());
        assert_eq!(message.message_id_state(), FieldState::Unset);
        assert_eq!(message.message_id_value(), COAP_DEFAULT_MESSAGE_ID);
        assert_eq!(message.token_state(), FieldState::Unset);
        assert!(message.token_value().is_empty());
        assert!(message.options_value().is_empty());
        assert_eq!(message.option_order_value(), CoapOptionOrder::Canonical);
        assert_eq!(message.payload_marker_state(), FieldState::Unset);
        assert_eq!(message.payload_marker_value(), CoapPayloadMarker::Absent);
        assert!(message.payload_value().is_empty());
        assert_eq!(message, Coap::default());
    }

    #[test]
    fn coap_named_constructors_pin_only_unambiguous_values() {
        let cases = [
            (Coap::empty(), CoapCode::empty()),
            (Coap::get(), CoapCode::get()),
            (Coap::post(), CoapCode::post()),
            (Coap::put(), CoapCode::put()),
            (Coap::delete(), CoapCode::delete()),
            (
                Coap::request(CoapCode::from_wire(0x1f)),
                CoapCode::from_wire(0x1f),
            ),
            (Coap::response(CoapCode::content()), CoapCode::content()),
        ];

        for (message, code) in cases {
            assert_eq!(message.code_state(), FieldState::User);
            assert_eq!(message.code_value(), code);
            assert_eq!(message.version_state(), FieldState::Unset);
            assert_eq!(message.message_type_state(), FieldState::Unset);
            assert_eq!(message.message_id_state(), FieldState::Unset);
            assert_eq!(message.token_state(), FieldState::Unset);
            assert_eq!(message.token_length_state(), FieldState::Unset);
            assert_eq!(message.payload_marker_state(), FieldState::Unset);
        }

        assert_eq!(
            Coap::new().acknowledgement().message_type_value(),
            CoapMessageType::Acknowledgement
        );
        assert_eq!(
            Coap::new().reset().message_type_value(),
            CoapMessageType::Reset
        );
        assert_eq!(
            Coap::new().confirmable().message_type_value(),
            CoapMessageType::Confirmable
        );
        assert_eq!(
            Coap::new().non_confirmable().message_type_value(),
            CoapMessageType::NonConfirmable
        );
    }

    #[test]
    fn coap_setters_preserve_independent_explicit_state() {
        let token_length = CoapTokenLength::explicit(0xfe, vec![0xaa, 0xbb], 999);
        let first = CoapOption::new(11u16, b"a".to_vec());
        let second = CoapOption::new(11u16, b"b".to_vec());
        let message = Coap::new()
            .version(0xfdu8)
            .message_type(CoapMessageType::Unknown(0xfc))
            .token_length(token_length.clone())
            .code(0xffu8)
            .message_id(0xabcd)
            .token(CoapToken::from_bytes([1, 2, 3]))
            .option(first.clone())
            .option(second.clone())
            .payload_marker(CoapPayloadMarker::Absent)
            .payload(vec![0xff, 0x00]);

        assert_eq!(message.version_state(), FieldState::User);
        assert_eq!(message.version_value().value(), 0xfd);
        assert_eq!(message.message_type_state(), FieldState::User);
        assert_eq!(message.message_type_value(), CoapMessageType::Unknown(0xfc));
        assert_eq!(message.token_length_state(), FieldState::User);
        assert_eq!(message.token_length_value().unwrap(), token_length);
        assert_eq!(message.code_state(), FieldState::User);
        assert_eq!(message.code_value(), CoapCode::from_wire(0xff));
        assert_eq!(message.message_id_state(), FieldState::User);
        assert_eq!(message.message_id_value(), 0xabcd);
        assert_eq!(message.token_state(), FieldState::User);
        assert_eq!(message.token_value().as_bytes(), &[1, 2, 3]);
        assert_eq!(message.options_value(), &[first, second]);
        assert_eq!(message.payload_marker_state(), FieldState::User);
        assert_eq!(message.payload_marker_value(), CoapPayloadMarker::Absent);
        assert_eq!(message.payload_value(), &[0xff, 0x00]);
    }

    #[test]
    fn coap_unset_dependent_fields_follow_base_owned_bytes_without_changing_state() {
        let message = Coap::new()
            .token(CoapToken::from_bytes([0u8; COAP_MAX_TOKEN_LEN]))
            .payload(vec![1, 2, 3]);

        let token_length = message.token_length_value().unwrap();
        assert_eq!(token_length.nibble(), COAP_MAX_TOKEN_LEN as u8);
        assert!(token_length.extension_bytes().is_empty());
        assert_eq!(token_length.declared_len(), COAP_MAX_TOKEN_LEN);
        assert_eq!(message.token_length_state(), FieldState::Unset);
        assert_eq!(message.payload_marker_value(), CoapPayloadMarker::Present);
        assert_eq!(message.payload_marker_state(), FieldState::Unset);
    }

    #[test]
    fn compile_autofills_only_unset_base_token_length() {
        let token = CoapToken::from_bytes([0xaa, 0xbb, 0xcc]);
        let automatic = Coap::response(CoapCode::content())
            .message_type(CoapMessageType::Reset)
            .message_id(0xabcd)
            .token(token.clone());
        let explicit_matching =
            automatic
                .clone()
                .token_length(CoapTokenLength::explicit(3, Vec::new(), 3));
        let explicit_mismatching =
            automatic
                .clone()
                .token_length(CoapTokenLength::explicit(1, Vec::new(), 999));

        let automatic_bytes = Packet::from_layer(automatic).compile().unwrap();
        let matching_bytes = Packet::from_layer(explicit_matching).compile().unwrap();
        let mismatching_bytes = Packet::from_layer(explicit_mismatching).compile().unwrap();

        assert_eq!(
            automatic_bytes.as_bytes(),
            &[0x73, 0x45, 0xab, 0xcd, 0xaa, 0xbb, 0xcc]
        );
        assert_eq!(matching_bytes, automatic_bytes);
        assert_eq!(
            mismatching_bytes.as_bytes(),
            &[0x71, 0x45, 0xab, 0xcd, 0xaa, 0xbb, 0xcc]
        );
    }

    #[test]
    fn compile_preserves_explicit_mismatch_for_empty_message_with_token() {
        let message = Coap::empty()
            .token(CoapToken::from_bytes([0xaa, 0xbb, 0xcc]))
            .token_length(CoapTokenLength::explicit(1, vec![0xfe], 999));

        assert_eq!(
            Packet::from_layer(message).compile().unwrap().as_bytes(),
            &[0x41, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc]
        );
    }

    #[test]
    fn compile_rejects_unset_token_length_requiring_extended_support() {
        let message = Coap::new().token(CoapToken::from_bytes([0u8; COAP_MAX_TOKEN_LEN + 1]));

        assert_eq!(
            Packet::from_layer(message).compile().unwrap_err(),
            CrafterError::invalid_field_value(
                "coap.token-length",
                "base CoAP tokens must be at most 8 bytes"
            )
        );
    }

    #[test]
    fn coap_options_setter_replaces_and_preserves_order() {
        let replaced = CoapOption::new(12u16, vec![0]);
        let first = CoapOption::new(15u16, b"a=1".to_vec());
        let second = CoapOption::new(11u16, b"status".to_vec());
        let message = Coap::new()
            .option(replaced)
            .options([first.clone(), second.clone()]);

        assert_eq!(message.options_value(), &[first, second]);
    }

    #[test]
    fn compile_options_only_uses_stable_canonical_order() {
        let first_repeated = CoapOption::new(11u16, b"a".to_vec());
        let lower = CoapOption::new(3u16, b"h".to_vec());
        let second_repeated = CoapOption::new(11u16, b"b".to_vec());
        let message = Coap::new().options([first_repeated, lower, second_repeated]);

        assert_eq!(message.encoded_len(), 10);
        assert!(!message.summary().contains("malformed-override"));
        assert_eq!(
            Packet::from_layer(message).compile().unwrap().as_bytes(),
            &[0x40, 0x00, 0x00, 0x00, 0x31, b'h', 0x81, b'a', 0x01, b'b']
        );
    }

    #[test]
    fn compile_explicit_wire_order_preserves_malformed_sequence() {
        let message = Coap::new()
            .options([
                CoapOption::new(11u16, b"a".to_vec()),
                CoapOption::new(3u16, b"h".to_vec()).with_wire_delta(0),
                CoapOption::new(11u16, b"b".to_vec()),
            ])
            .option_order(CoapOptionOrder::Wire);

        assert_eq!(message.option_order_value(), CoapOptionOrder::Wire);
        assert_eq!(message.encoded_len(), 10);
        assert!(message.summary().contains("malformed-override"));
        assert_eq!(
            Packet::from_layer(message).compile().unwrap().as_bytes(),
            &[0x40, 0x00, 0x00, 0x00, 0xb1, b'a', 0x01, b'h', 0x81, b'b']
        );
    }

    #[test]
    fn compile_payload_only_autofills_marker() {
        let message = Coap::new().payload(vec![0xde, 0xad]);

        assert_eq!(message.payload_marker_state(), FieldState::Unset);
        assert_eq!(message.encoded_len(), 7);
        assert_eq!(
            Packet::from_layer(message).compile().unwrap().as_bytes(),
            &[0x40, 0x00, 0x00, 0x00, 0xff, 0xde, 0xad]
        );
    }

    #[test]
    fn compile_honors_explicit_payload_marker_mismatches() {
        let marker_without_payload = Coap::new().payload_marker(CoapPayloadMarker::Present);
        let payload_without_marker = Coap::new()
            .payload_marker(CoapPayloadMarker::Absent)
            .payload(vec![0xde, 0xad]);

        assert_eq!(marker_without_payload.encoded_len(), 5);
        assert_eq!(
            Packet::from_layer(marker_without_payload)
                .compile()
                .unwrap()
                .as_bytes(),
            &[0x40, 0x00, 0x00, 0x00, 0xff]
        );
        assert_eq!(payload_without_marker.encoded_len(), 6);
        assert_eq!(
            Packet::from_layer(payload_without_marker)
                .compile()
                .unwrap()
                .as_bytes(),
            &[0x40, 0x00, 0x00, 0x00, 0xde, 0xad]
        );
    }

    #[test]
    fn token_length_model_preserves_explicit_and_canonical_forms() {
        let explicit = CoapTokenLength::explicit(0xff, vec![1, 2, 3], usize::MAX);
        assert_eq!(explicit.nibble(), 0xff);
        assert_eq!(explicit.extension_bytes(), &[1, 2, 3]);
        assert_eq!(explicit.declared_len(), usize::MAX);

        let direct = CoapTokenLength::canonical_for_len(12).unwrap();
        assert_eq!(direct.nibble(), 12);
        assert!(direct.extension_bytes().is_empty());
        assert_eq!(direct.declared_len(), 12);

        let extended8 = CoapTokenLength::canonical_for_len(268).unwrap();
        assert_eq!(extended8.nibble(), 13);
        assert_eq!(extended8.extension_bytes(), &[0xff]);
        assert_eq!(extended8.declared_len(), 268);

        let extended16 = CoapTokenLength::canonical_for_len(65_804).unwrap();
        assert_eq!(extended16.nibble(), 14);
        assert_eq!(extended16.extension_bytes(), &[0xff, 0xff]);
        assert_eq!(extended16.declared_len(), 65_804);

        assert!(CoapTokenLength::canonical_for_len(65_805).is_err());
    }

    #[test]
    fn payload_marker_reports_presence() {
        assert!(!CoapPayloadMarker::Absent.is_present());
        assert!(CoapPayloadMarker::Present.is_present());
        assert_eq!(CoapPayloadMarker::default(), CoapPayloadMarker::Absent);
    }

    #[test]
    fn request_summary_and_show_are_exact_and_deterministic() {
        let packet = Packet::from_layer(
            Coap::get()
                .confirmable()
                .message_id(0x1234)
                .token(CoapToken::from_bytes([0xaa, 0xbb]))
                .option(CoapOption::from_string(COAP_OPTION_URI_PATH, "status")),
        );

        assert_eq!(
            packet.summary(),
            "Coap(version=1, type=confirmable, code=0.01(GET), mid=0x1234, token_len=2, options=1, marker=absent, payload=0 bytes)"
        );
        assert_eq!(
            packet.show(),
            "Packet(len=13, layers=1)\n  [0] Coap\n      version: 1\n      type: confirmable\n      token_length: 2\n      code: 0.01(GET)\n      message_id: 0x1234\n      token: len=2 hex=aabb\n      options: 1 [Uri-Path(11,len=6,hex=737461747573)]\n      payload_marker: absent\n      payload_length: 0"
        );
    }

    #[test]
    fn response_summary_and_show_are_exact_and_deterministic() {
        let packet = Packet::from_layer(
            Coap::response(CoapCode::content())
                .non_confirmable()
                .message_id(0x0102)
                .token(CoapToken::from_bytes([0x01]))
                .option(CoapOption::from_uint(COAP_OPTION_CONTENT_FORMAT, 0))
                .payload(b"ok".to_vec()),
        );

        assert_eq!(
            packet.summary(),
            "Coap(version=1, type=non-confirmable, code=2.05(Content), mid=0x0102, token_len=1, options=1, marker=present, payload=2 bytes)"
        );
        assert_eq!(
            packet.show(),
            "Packet(len=9, layers=1)\n  [0] Coap\n      version: 1\n      type: non-confirmable\n      token_length: 1\n      code: 2.05(Content)\n      message_id: 0x0102\n      token: len=1 hex=01\n      options: 1 [Content-Format(12,len=0,hex=)]\n      payload_marker: present\n      payload_length: 2"
        );
    }

    #[test]
    fn empty_ack_summary_and_show_are_exact_and_deterministic() {
        let packet = Packet::from_layer(Coap::empty().acknowledgement().message_id(0xabcd));

        assert_eq!(
            packet.summary(),
            "Coap(version=1, type=acknowledgement, code=0.00(Empty), mid=0xabcd, token_len=0, options=0, marker=absent, payload=0 bytes)"
        );
        assert_eq!(
            packet.show(),
            "Packet(len=4, layers=1)\n  [0] Coap\n      version: 1\n      type: acknowledgement\n      token_length: 0\n      code: 0.00(Empty)\n      message_id: 0xabcd\n      token: len=0 hex=\n      options: 0 []\n      payload_marker: absent\n      payload_length: 0"
        );
    }

    #[test]
    fn unknown_option_summary_and_show_use_stable_numeric_labels() {
        let packet = Packet::from_layer(
            Coap::get()
                .message_id(0x0001)
                .option(CoapOption::new(65_001u16, vec![0xde, 0xad])),
        );

        assert_eq!(
            packet.summary(),
            "Coap(version=1, type=confirmable, code=0.01(GET), mid=0x0001, token_len=0, options=1, marker=absent, payload=0 bytes)"
        );
        assert_eq!(
            packet.show(),
            "Packet(len=9, layers=1)\n  [0] Coap\n      version: 1\n      type: confirmable\n      token_length: 0\n      code: 0.01(GET)\n      message_id: 0x0001\n      token: len=0 hex=\n      options: 1 [option-65001(65001,len=2,hex=dead)]\n      payload_marker: absent\n      payload_length: 0"
        );
    }

    #[test]
    fn payload_summary_and_show_report_length_without_dumping_bytes() {
        let packet = Packet::from_layer(
            Coap::post()
                .message_id(0x0007)
                .payload(vec![0x00, 0xff, 0x10]),
        );

        assert_eq!(
            packet.summary(),
            "Coap(version=1, type=confirmable, code=0.02(POST), mid=0x0007, token_len=0, options=0, marker=present, payload=3 bytes)"
        );
        assert_eq!(
            packet.show(),
            "Packet(len=8, layers=1)\n  [0] Coap\n      version: 1\n      type: confirmable\n      token_length: 0\n      code: 0.02(POST)\n      message_id: 0x0007\n      token: len=0 hex=\n      options: 0 []\n      payload_marker: present\n      payload_length: 3"
        );
    }

    #[test]
    fn explicit_malformed_overrides_are_visible_without_payload_disclosure() {
        let packet = Packet::from_layer(
            Coap::new()
                .version(3u8)
                .message_type(CoapMessageType::Unknown(4))
                .token_length(CoapTokenLength::explicit(1, Vec::new(), 1))
                .code(CoapCode::from_parts(1, 0))
                .token(CoapToken::from_bytes([0xaa, 0xbb]))
                .option(CoapOption::new(11u16, vec![0xcc]).with_wire_length(2))
                .payload_marker(CoapPayloadMarker::Absent)
                .payload(vec![0xde]),
        );

        assert_eq!(
            packet.summary(),
            "Coap(version=3 [explicit-noncurrent], type=message-type-4 [explicit-out-of-range], code=1.00(code-1.00) [explicit-reserved], mid=0x0000, token_len=1 [explicit-mismatch:nibble=1,actual=2], options=1 [malformed-override], marker=absent [explicit-mismatch], payload=1 bytes)"
        );
        assert!(!packet.show().contains("hex=de"));
        assert!(packet.show().contains("[malformed-override]"));
    }

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

    #[test]
    fn token_checked_constructor_accepts_empty_one_and_eight_byte_values() {
        let empty = CoapToken::new([]).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.as_bytes(), []);
        assert_eq!(empty.to_hex(), "");
        assert_eq!(empty.hexdump(), "");
        assert_eq!(empty.to_string(), "");

        let one = CoapToken::new([0xa5]).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one.as_bytes(), [0xa5]);
        assert_eq!(one.as_ref(), [0xa5]);
        assert_eq!(one.to_hex(), "a5");
        assert_eq!(one.hexdump(), "0000: a5");
        assert_eq!(one.to_string(), "a5");

        let eight = CoapToken::new([0x00, 0x10, 0x80, 0xff, 0x01, 0x02, 0x03, 0x04]).unwrap();
        assert_eq!(eight.len(), COAP_MAX_TOKEN_LEN);
        assert_eq!(eight.to_hex(), "001080ff01020304");
        assert_eq!(eight.to_string(), "001080ff01020304");
        assert_eq!(
            eight.into_bytes(),
            vec![0x00, 0x10, 0x80, 0xff, 0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn token_raw_constructor_preserves_extended_and_oversized_inputs() {
        let extended_bytes = vec![0x7e; COAP_MAX_TOKEN_LEN + 1];
        let extended = CoapToken::from_bytes(&extended_bytes);
        assert_eq!(extended.len(), COAP_MAX_TOKEN_LEN + 1);
        assert_eq!(extended.as_bytes(), extended_bytes);

        let oversized_bytes = vec![0x5a; 65_805];
        let oversized = CoapToken::from_bytes(&oversized_bytes);
        assert_eq!(oversized.len(), 65_805);
        assert_eq!(oversized.as_bytes(), oversized_bytes);
        assert_eq!(oversized.into_bytes(), oversized_bytes);
    }

    #[test]
    fn token_checked_constructor_rejects_non_base_lengths_without_truncation() {
        let bytes = [0x5a; COAP_MAX_TOKEN_LEN + 1];

        assert_eq!(
            CoapToken::new(bytes).unwrap_err(),
            CrafterError::invalid_field_value(
                "coap.token-length",
                "base CoAP tokens must be at most 8 bytes"
            )
        );
        assert_eq!(CoapToken::from_bytes(bytes).as_bytes(), bytes);
    }
}
