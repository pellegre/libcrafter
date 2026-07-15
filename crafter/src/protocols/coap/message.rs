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
use crate::protocols::transport::{Udp, UDP_HEADER_LEN};

use super::block::{CoapBlock, CoapBlockKind, CoapBlockTransport, CoapBlockValidation};
use super::constants::*;
use super::hop_limit::CoapHopLimit;
use super::no_response::CoapNoResponse;
use super::observe::CoapObserve;
use super::option::{
    encode_option_sequence, validate_coap_proxy_options, CoapAccept, CoapContentFormat, CoapEcho,
    CoapEtag, CoapIfMatch, CoapIfNoneMatch, CoapLocationPath, CoapLocationQuery, CoapOption,
    CoapOptions, CoapProxyScheme, CoapProxyUri, CoapRequestTag, CoapSize1, CoapSize2, CoapUriHost,
    CoapUriPath, CoapUriPort, CoapUriQuery,
};
use super::registry::{coap_code_meta, coap_signaling_code_meta, CoapRegistryMeta};

const COAP_TWO_BIT_VALUE_MASK: u8 = 0x03;
const COAP_TYPE_CONFIRMABLE: u8 = 0;
const COAP_TYPE_NON_CONFIRMABLE: u8 = 1;
const COAP_TYPE_ACKNOWLEDGEMENT: u8 = 2;
const COAP_TYPE_RESET: u8 = 3;
const COAP_INSPECTION_HEX_LIMIT: usize = 16;
const COAP_MAX_UDP_PAYLOAD_LEN: usize = u16::MAX as usize - UDP_HEADER_LEN;

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

/// Source-backed RFC 8974 Token Length encoding form.
///
/// The form is selected by the four-bit TKL discriminator. Reserved or
/// out-of-range discriminators remain preserved by [`CoapTokenLength`], but
/// do not map to an encoding form and are reported through a structured
/// error by [`CoapTokenLength::encoding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoapTokenLengthEncoding {
    /// TKL 0 through 12 carries the token length directly.
    Direct,
    /// TKL 13 uses one extension byte and represents lengths 13 through 268.
    Extended8,
    /// TKL 14 uses two extension bytes and represents lengths 269 through
    /// 65804.
    Extended16,
}

impl CoapTokenLengthEncoding {
    /// Return the number of extension bytes used by this encoding form.
    pub const fn extension_len(self) -> usize {
        match self {
            Self::Direct => 0,
            Self::Extended8 => 1,
            Self::Extended16 => 2,
        }
    }

    /// Return the smallest token length represented by this encoding form.
    pub const fn min_len(self) -> usize {
        match self {
            Self::Direct => CoapTokenLength::DIRECT_MIN_LEN,
            Self::Extended8 => CoapTokenLength::EXTENDED8_MIN_LEN,
            Self::Extended16 => CoapTokenLength::EXTENDED16_MIN_LEN,
        }
    }

    /// Return the largest token length represented by this encoding form.
    pub const fn max_len(self) -> usize {
        match self {
            Self::Direct => CoapTokenLength::DIRECT_MAX_LEN,
            Self::Extended8 => CoapTokenLength::EXTENDED8_MAX_LEN,
            Self::Extended16 => CoapTokenLength::EXTENDED16_MAX_LEN,
        }
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
    /// Minimum length represented directly by TKL (RFC 8974 Section 2.1).
    pub const DIRECT_MIN_LEN: usize = 0;
    /// Maximum length represented directly by TKL (RFC 8974 Section 2.1).
    pub const DIRECT_MAX_LEN: usize = 12;
    /// Minimum length represented by the one-byte extension form.
    pub const EXTENDED8_MIN_LEN: usize = 13;
    /// Maximum length represented by the one-byte extension form.
    pub const EXTENDED8_MAX_LEN: usize = 268;
    /// Minimum length represented by the two-byte extension form.
    pub const EXTENDED16_MIN_LEN: usize = 269;
    /// Maximum length represented by the two-byte extension form.
    pub const EXTENDED16_MAX_LEN: usize = 65_804;
    /// Maximum token length representable by RFC 8974 TKL metadata.
    pub const MAX_LEN: usize = Self::EXTENDED16_MAX_LEN;

    /// Build the shortest RFC 8974 token-length representation for `len`.
    pub fn canonical_for_len(len: usize) -> Result<Self> {
        match len {
            Self::DIRECT_MIN_LEN..=Self::DIRECT_MAX_LEN => {
                Ok(Self::explicit(len as u8, Vec::new(), len))
            }
            Self::EXTENDED8_MIN_LEN..=Self::EXTENDED8_MAX_LEN => Ok(Self::explicit(
                13,
                vec![(len - Self::EXTENDED8_MIN_LEN) as u8],
                len,
            )),
            Self::EXTENDED16_MIN_LEN..=Self::EXTENDED16_MAX_LEN => Ok(Self::explicit(
                14,
                ((len - Self::EXTENDED16_MIN_LEN) as u16)
                    .to_be_bytes()
                    .to_vec(),
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

    /// Return the RFC 8974 encoding form selected by the preserved TKL.
    ///
    /// TKL 15 remains a message-format error. Values above 15 can exist only
    /// as caller overrides and are rejected here instead of being masked.
    pub fn encoding(&self) -> Result<CoapTokenLengthEncoding> {
        match self.nibble {
            0..=12 => Ok(CoapTokenLengthEncoding::Direct),
            13 => Ok(CoapTokenLengthEncoding::Extended8),
            14 => Ok(CoapTokenLengthEncoding::Extended16),
            15 => Err(CrafterError::invalid_field_value(
                "coap.token-length",
                "reserved TKL encoding 15",
            )),
            _ => Err(CrafterError::invalid_field_value(
                "coap.token-length",
                "token-length discriminator exceeds four bits",
            )),
        }
    }

    /// Decode the logical token length represented by the TKL and extension.
    ///
    /// This value is derived from preserved wire metadata and is intentionally
    /// separate from [`Self::declared_len`], which may be a caller override.
    pub fn wire_len(&self) -> Result<usize> {
        match self.encoding()? {
            CoapTokenLengthEncoding::Direct if self.extension_bytes.is_empty() => {
                Ok(usize::from(self.nibble))
            }
            CoapTokenLengthEncoding::Extended8 if self.extension_bytes.len() == 1 => {
                Ok(Self::EXTENDED8_MIN_LEN + usize::from(self.extension_bytes[0]))
            }
            CoapTokenLengthEncoding::Extended16 if self.extension_bytes.len() == 2 => {
                Ok(Self::EXTENDED16_MIN_LEN
                    + usize::from(u16::from_be_bytes([
                        self.extension_bytes[0],
                        self.extension_bytes[1],
                    ])))
            }
            CoapTokenLengthEncoding::Direct => Err(CrafterError::invalid_field_value(
                "coap.token-length",
                "direct TKL encoding must not contain extension bytes",
            )),
            CoapTokenLengthEncoding::Extended8 => Err(CrafterError::invalid_field_value(
                "coap.token-length",
                "TKL 13 encoding requires exactly one extension byte",
            )),
            CoapTokenLengthEncoding::Extended16 => Err(CrafterError::invalid_field_value(
                "coap.token-length",
                "TKL 14 encoding requires exactly two extension bytes",
            )),
        }
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

/// Severity assigned to one opt-in CoAP semantic validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CoapValidationSeverity {
    /// The message is structurally representable, but uses a noncanonical or
    /// suspicious value that callers may still choose to send deliberately.
    Warning,
    /// The message violates a source-backed CoAP semantic requirement.
    Error,
}

/// Stable category assigned to one CoAP semantic validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CoapValidationCategory {
    /// Version, Type, or Code role and combination rules.
    Header,
    /// Empty-message rules from RFC 7252 Section 4.1.
    EmptyMessage,
    /// Token Length metadata and owned token byte agreement.
    TokenLength,
    /// Payload marker and owned payload byte agreement.
    PayloadMarker,
    /// Option number order or explicit option-header metadata.
    OptionOrdering,
    /// Explicit option-header delta, length, or raw bytes disagree with the
    /// typed occurrence they encode.
    OptionEncoding,
    /// A non-repeatable option occurred more than once.
    OptionRepeatability,
    /// An option value violates its source-backed semantic length.
    OptionLength,
    /// An option value has a valid structural length but violates its
    /// source-backed semantic range.
    OptionValue,
    /// Two individually valid options cannot be combined.
    OptionInteraction,
    /// An option is not applicable to the message's request/response role.
    OptionApplicability,
    /// A method-specific request shape is semantically incomplete.
    MethodSemantics,
}

/// One inspectable CoAP semantic validation finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapValidationIssue {
    field: String,
    severity: CoapValidationSeverity,
    category: CoapValidationCategory,
    reason: String,
}

impl CoapValidationIssue {
    fn new(
        field: impl Into<String>,
        severity: CoapValidationSeverity,
        category: CoapValidationCategory,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            severity,
            category,
            reason: reason.into(),
        }
    }

    /// Return the stable dotted field path for this finding.
    pub fn field(&self) -> &str {
        &self.field
    }

    /// Return the finding severity.
    pub const fn severity(&self) -> CoapValidationSeverity {
        self.severity
    }

    /// Return the source-backed validation category.
    pub const fn category(&self) -> CoapValidationCategory {
        self.category
    }

    /// Return the stable human-readable reason.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Aggregate opt-in semantic validation report for one CoAP datagram.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoapValidation {
    issues: Vec<CoapValidationIssue>,
}

impl CoapValidation {
    /// Borrow findings in deterministic validation order.
    pub fn issues(&self) -> &[CoapValidationIssue] {
        &self.issues
    }

    /// Consume the report and return its findings.
    pub fn into_issues(self) -> Vec<CoapValidationIssue> {
        self.issues
    }

    /// Return true when validation found no semantic inconsistencies.
    pub fn is_clean(&self) -> bool {
        self.issues.is_empty()
    }

    /// Return true when at least one error-severity finding is present.
    pub fn has_errors(&self) -> bool {
        self.issues
            .iter()
            .any(|issue| issue.severity == CoapValidationSeverity::Error)
    }

    /// Return the number of findings.
    pub fn len(&self) -> usize {
        self.issues.len()
    }

    /// Return true when no findings are present.
    pub fn is_empty(&self) -> bool {
        self.issues.is_empty()
    }

    fn push(
        &mut self,
        field: impl Into<String>,
        severity: CoapValidationSeverity,
        category: CoapValidationCategory,
        reason: impl Into<String>,
    ) {
        self.issues
            .push(CoapValidationIssue::new(field, severity, category, reason));
    }
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

    /// Build an Empty Acknowledgement (ACK) for `message_id`.
    ///
    /// RFC 7252 Sections 4.4 and 5.2.2 require the Message ID of an
    /// Acknowledgement to echo the correlated message. The type, Empty code,
    /// and Message ID are ordinary explicit fields: later builder calls may
    /// deliberately override any of them for malformed-packet construction.
    pub fn empty_acknowledgement(message_id: u16) -> Self {
        Self::empty().acknowledgement().message_id(message_id)
    }

    /// Build an Empty Reset (RST) for `message_id`.
    ///
    /// RFC 7252 Section 4.4 requires a Reset to echo the Message ID of the
    /// correlated message. The type, Empty code, and Message ID remain
    /// explicit caller values and may be deliberately overridden afterward.
    pub fn empty_reset(message_id: u16) -> Self {
        Self::empty().reset().message_id(message_id)
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

    /// Build a FETCH (`0.05`) request (RFC 8132).
    pub fn fetch() -> Self {
        Self::request(CoapCode::fetch())
    }

    /// Build a PATCH (`0.06`) request (RFC 8132).
    pub fn patch() -> Self {
        Self::request(CoapCode::patch())
    }

    /// Build an iPATCH (`0.07`) request (RFC 8132).
    pub fn ipatch() -> Self {
        Self::request(CoapCode::ipatch())
    }

    /// Build a PATCH request carrying an opaque patch document.
    ///
    /// RFC 8132 identifies the patch document through Content-Format. The
    /// bytes remain uninterpreted, and unknown or future formats are accepted.
    pub fn patch_document(
        content_format: impl Into<CoapContentFormat>,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self::patch()
            .content_format(content_format)
            .payload(payload)
    }

    /// Build an idempotent iPATCH request carrying an opaque patch document.
    ///
    /// This records the caller's idempotence assertion but does not inspect or
    /// apply the patch document.
    pub fn ipatch_document(
        content_format: impl Into<CoapContentFormat>,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self::ipatch()
            .content_format(content_format)
            .payload(payload)
    }

    /// Build a `2.01 Created` response to a PATCH or iPATCH request.
    pub fn patch_created_response() -> Self {
        Self::response(CoapCode::created())
    }

    /// Build a `2.04 Changed` response to a PATCH or iPATCH request.
    pub fn patch_changed_response() -> Self {
        Self::response(CoapCode::changed())
    }

    /// Build a `4.09 Conflict` PATCH or iPATCH error response.
    pub fn patch_conflict_response() -> Self {
        Self::response(CoapCode::conflict())
    }

    /// Build a `4.15 Unsupported Content-Format` PATCH or iPATCH error response.
    pub fn patch_unsupported_content_format_response() -> Self {
        Self::response(CoapCode::unsupported_content_format())
    }

    /// Build a `4.22 Unprocessable Entity` PATCH or iPATCH error response.
    pub fn patch_unprocessable_entity_response() -> Self {
        Self::response(CoapCode::unprocessable_entity())
    }

    /// Build a Content (`2.05`) response without inferring transaction fields.
    pub fn content() -> Self {
        Self::response(CoapCode::content())
    }

    /// Build a Bad Request (`4.00`) response without inferring transaction fields.
    pub fn bad_request() -> Self {
        Self::response(CoapCode::bad_request())
    }

    /// Build an Internal Server Error (`5.00`) response without inferring transaction fields.
    pub fn internal_server_error() -> Self {
        Self::response(CoapCode::internal_server_error())
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

    /// Append one Observe option without replacing an existing occurrence.
    pub fn observe(self, value: impl Into<CoapObserve>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one RFC 7967 No-Response request option.
    ///
    /// This records response-class preferences without changing the Code,
    /// message Type, transport, or any endpoint send/receive behavior.
    /// Repetition and request applicability remain opt-in validation concerns.
    pub fn no_response(self, value: impl Into<CoapNoResponse>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one raw-preserving RFC 8768 Hop-Limit request option.
    ///
    /// This only records packet metadata. Use [`CoapHopLimit::decrement`] to
    /// obtain a safe stateless result before any caller-controlled forwarding.
    pub fn hop_limit(self, value: impl Into<CoapHopLimit>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one raw-preserving RFC 9175 Echo challenge or response value.
    ///
    /// This only records exact packet bytes. It does not generate a challenge,
    /// assess freshness, retry a request, or retain replay state.
    pub fn echo(self, value: impl Into<CoapEcho>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one raw-preserving RFC 9175 Request-Tag occurrence.
    ///
    /// Repeated occurrences are retained in insertion order. Tag allocation,
    /// reuse policy, and blockwise transfer state remain caller concerns.
    pub fn request_tag(self, value: impl Into<CoapRequestTag>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one raw-preserving RFC 7959 Block1 option.
    pub fn block1(self, value: CoapBlock) -> Self {
        self.block(CoapBlockKind::Block1, value)
    }

    /// Append one raw-preserving RFC 7959 Block2 option.
    pub fn block2(self, value: CoapBlock) -> Self {
        self.block(CoapBlockKind::Block2, value)
    }

    /// Append one raw-preserving Block or Q-Block option of `kind`.
    ///
    /// The explicit kind selects only the option number. Exact value bytes,
    /// including malformed and noncanonical encodings, remain authoritative.
    pub fn block(self, kind: CoapBlockKind, value: CoapBlock) -> Self {
        self.option(value.into_option(kind))
    }

    /// Append one raw-preserving RFC 9177 Q-Block1 option.
    pub fn qblock1(self, value: CoapBlock) -> Self {
        self.block(CoapBlockKind::QBlock1, value)
    }

    /// Append one raw-preserving RFC 9177 Q-Block2 option.
    ///
    /// Repeated occurrences remain ordered so missing-block request metadata
    /// can be inspected and validated without scheduling retransmissions.
    pub fn qblock2(self, value: CoapBlock) -> Self {
        self.block(CoapBlockKind::QBlock2, value)
    }

    /// Attach one Block2 request selection without changing the request Code.
    ///
    /// The M bit, size, and option encoding remain caller-controlled and are
    /// checked only by [`Self::block2_validation`].
    pub fn block2_request_selection(self, value: CoapBlock) -> Self {
        self.block2(value)
    }

    /// Attach a Block2 selection and request a Size2 estimate.
    ///
    /// RFC 7959 Section 4 represents a Size2 request with the canonical empty
    /// uint value zero. A server may omit the estimate.
    pub fn block2_request_selection_with_size2(self, value: CoapBlock) -> Self {
        self.block2_request_selection(value)
            .size2(CoapSize2::new(0))
    }

    /// Attach one descriptive Block2 value and its exact response payload.
    ///
    /// The existing response Code, token, transaction fields, and
    /// representation metadata remain caller-controlled. Fragment semantics
    /// are checked only by [`Self::block2_validation`].
    pub fn block2_response_fragment(self, value: CoapBlock, payload: impl Into<Vec<u8>>) -> Self {
        self.block2(value).payload(payload)
    }

    /// Attach a Block2 response fragment with ETag and total Size2 metadata.
    ///
    /// Both metadata values describe the complete representation rather than
    /// only this fragment. This helper retains no cache or reassembly state.
    pub fn block2_response_fragment_with_metadata(
        self,
        value: CoapBlock,
        payload: impl Into<Vec<u8>>,
        etag: impl Into<CoapEtag>,
        total_size: impl Into<CoapSize2>,
    ) -> Self {
        self.block2_response_fragment(value, payload)
            .etag(etag)
            .size2(total_size)
    }

    /// Attach one descriptive Block1 value and its exact request payload.
    ///
    /// The existing code, URI options, token, and transaction fields remain
    /// caller-controlled. Payload length and M-bit consistency are checked
    /// only by [`Self::block1_validation`], never while building or compiling.
    pub fn block1_request_fragment(self, value: CoapBlock, payload: impl Into<Vec<u8>>) -> Self {
        self.block1(value).payload(payload)
    }

    /// Attach a Block1 request fragment and total request-body Size1 metadata.
    pub fn block1_request_fragment_with_size1(
        self,
        value: CoapBlock,
        payload: impl Into<Vec<u8>>,
        total_size: impl Into<CoapSize1>,
    ) -> Self {
        self.block1_request_fragment(value, payload)
            .size1(total_size)
    }

    /// Build a provisional RFC 7959 `2.31 Continue` Block1 response.
    ///
    /// The supplied control value is emitted exactly, allowing a server to
    /// acknowledge a block and select a smaller SZX for subsequent requests.
    pub fn block1_continue(value: CoapBlock) -> Self {
        Self::response(CoapCode::continue_()).block1(value)
    }

    /// Build an RFC 7959 `4.08 Request Entity Incomplete` Block1 response.
    pub fn block1_request_entity_incomplete(value: CoapBlock) -> Self {
        Self::response(CoapCode::request_entity_incomplete()).block1(value)
    }

    /// Build an RFC 7959 `4.13 Request Entity Too Large` Block1 response.
    ///
    /// Size1 carries the server's maximum accepted request-body size, while
    /// the exact Block1 value may advertise a smaller preferred SZX.
    pub fn block1_request_entity_too_large(
        value: CoapBlock,
        maximum_size: impl Into<CoapSize1>,
    ) -> Self {
        Self::response(CoapCode::request_entity_too_large())
            .block1(value)
            .size1(maximum_size)
    }

    /// Attach one RFC 9177 Q-Block1 request payload with required metadata.
    ///
    /// Request-Tag and Size1 are required for every payload of the request
    /// body. This helper only records their exact values; uniqueness, stable
    /// cross-message values, and transmission order remain caller concerns.
    pub fn qblock1_request_fragment(
        self,
        value: CoapBlock,
        payload: impl Into<Vec<u8>>,
        request_tag: impl Into<CoapRequestTag>,
        total_size: impl Into<CoapSize1>,
    ) -> Self {
        self.qblock1(value)
            .request_tag(request_tag)
            .size1(total_size)
            .payload(payload)
    }

    /// Build an RFC 9177 `2.31 Continue` Q-Block1 response.
    ///
    /// The supplied value identifies the highest acknowledged block in the
    /// latest MAX_PAYLOADS_SET. Token selection remains caller-controlled.
    pub fn qblock1_continue(value: CoapBlock) -> Self {
        Self::response(CoapCode::continue_()).qblock1(value)
    }

    /// Attach one Q-Block2 request selector without changing the request Code.
    pub fn qblock2_request_selection(self, value: CoapBlock) -> Self {
        self.qblock2(value)
    }

    /// Attach one RFC 9177 Q-Block2 response payload with required metadata.
    ///
    /// ETag and Size2 describe the complete body. This helper retains no
    /// cache, response sequence, retransmission, or reassembly state.
    pub fn qblock2_response_fragment(
        self,
        value: CoapBlock,
        payload: impl Into<Vec<u8>>,
        etag: impl Into<CoapEtag>,
        total_size: impl Into<CoapSize2>,
    ) -> Self {
        self.qblock2(value)
            .etag(etag)
            .size2(total_size)
            .payload(payload)
    }

    /// Build an RFC 7641 GET registration request with `Observe: 0`.
    ///
    /// Token, URI, transport, and transaction fields remain caller-controlled.
    pub fn observe_registration() -> Self {
        Self::get().observe(CoapObserve::register())
    }

    /// Build an RFC 7641 GET deregistration request with `Observe: 1`.
    ///
    /// The caller is responsible for reusing the observation token and
    /// request options required by RFC 7641 Section 3.6.
    pub fn observe_deregistration() -> Self {
        Self::get().observe(CoapObserve::deregister())
    }

    /// Append one Location-Path segment without replacing existing segments.
    ///
    /// This response-oriented helper records packet metadata only; it does not
    /// create or resolve a resource.
    pub fn location_path(self, value: impl Into<CoapLocationPath>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one Location-Query argument without replacing existing arguments.
    pub fn location_query(self, value: impl Into<CoapLocationQuery>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one Size1 value without replacing an existing occurrence.
    pub fn size1(self, value: impl Into<CoapSize1>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one Size2 value without replacing an existing occurrence.
    pub fn size2(self, value: impl Into<CoapSize2>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one Proxy-Uri value without resolving or forwarding it.
    pub fn proxy_uri(self, value: impl Into<CoapProxyUri>) -> Self {
        self.option(CoapOption::from(value.into()))
    }

    /// Append one Proxy-Scheme value without composing or forwarding a URI.
    pub fn proxy_scheme(self, value: impl Into<CoapProxyScheme>) -> Self {
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
            None => self.canonical_token_length_value(),
        }
    }

    /// Derive canonical RFC 8974 metadata from the owned token bytes.
    ///
    /// This accessor deliberately ignores an explicit [`Self::token_length`]
    /// override, allowing callers to compare the canonical representation of
    /// the lossless token bytes with the wire metadata selected for compile.
    pub fn canonical_token_length_value(&self) -> Result<CoapTokenLength> {
        CoapTokenLength::canonical_for_len(self.token_value().len())
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

    /// Iterate over typed, raw-preserving Content-Format occurrences.
    pub fn content_format_values(&self) -> impl Iterator<Item = Result<CoapContentFormat>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_CONTENT_FORMAT)
            .map(CoapContentFormat::try_from)
    }

    /// Return the first typed, raw-preserving Content-Format occurrence.
    pub fn content_format_value(&self) -> Option<Result<CoapContentFormat>> {
        self.content_format_values().next()
    }

    /// Iterate over typed, raw-preserving Accept occurrences.
    pub fn accept_values(&self) -> impl Iterator<Item = Result<CoapAccept>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_ACCEPT)
            .map(CoapAccept::try_from)
    }

    /// Return the first typed, raw-preserving Accept occurrence.
    pub fn accept_value(&self) -> Option<Result<CoapAccept>> {
        self.accept_values().next()
    }

    /// Return whether at least one Observe option is present.
    ///
    /// Repeatability and value validity remain available through typed access
    /// and opt-in semantic validation.
    pub fn has_observe(&self) -> bool {
        self.options
            .iter()
            .any(|option| option.number().value() == COAP_OPTION_OBSERVE)
    }

    /// Iterate over typed Observe occurrences in insertion or wire order.
    pub fn observe_values(&self) -> impl Iterator<Item = Result<CoapObserve>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_OBSERVE)
            .map(CoapObserve::try_from)
    }

    /// Return the first Observe occurrence as a checked, raw-preserving view.
    pub fn observe_value(&self) -> Option<Result<CoapObserve>> {
        self.observe_values().next()
    }

    /// Iterate over typed No-Response occurrences in insertion or wire order.
    pub fn no_response_values(&self) -> impl Iterator<Item = Result<CoapNoResponse>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_NO_RESPONSE)
            .map(CoapNoResponse::try_from)
    }

    /// Return the first raw-preserving No-Response mask.
    pub fn no_response_value(&self) -> Option<Result<CoapNoResponse>> {
        self.no_response_values().next()
    }

    /// Iterate over typed, raw-preserving Hop-Limit occurrences.
    pub fn hop_limit_values(&self) -> impl Iterator<Item = Result<CoapHopLimit>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_HOP_LIMIT)
            .map(CoapHopLimit::try_from)
    }

    /// Return the first Hop-Limit occurrence as a typed value.
    pub fn hop_limit_value(&self) -> Option<Result<CoapHopLimit>> {
        self.hop_limit_values().next()
    }

    /// Iterate over typed, raw-preserving Echo occurrences.
    pub fn echo_values(&self) -> impl Iterator<Item = Result<CoapEcho>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_ECHO)
            .map(CoapEcho::try_from)
    }

    /// Return the first Echo occurrence as a checked typed value.
    pub fn echo_value(&self) -> Option<Result<CoapEcho>> {
        self.echo_values().next()
    }

    /// Iterate over typed, raw-preserving Request-Tag occurrences.
    pub fn request_tag_values(&self) -> impl Iterator<Item = Result<CoapRequestTag>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_REQUEST_TAG)
            .map(CoapRequestTag::try_from)
    }

    /// Return the first Request-Tag occurrence as a checked typed value.
    pub fn request_tag_value(&self) -> Option<Result<CoapRequestTag>> {
        self.request_tag_values().next()
    }

    /// Compare Request-Tag occurrences in two messages using exact bytes.
    ///
    /// Empty occurrences match each other, while absence does not match
    /// presence. The comparison intentionally remains independent of semantic
    /// validation so explicitly malformed raw values remain inspectable. It
    /// retains no transfer state and does not decide when a tag may be reused.
    pub fn request_tag_matches(&self, other: &Self) -> bool {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_REQUEST_TAG)
            .any(|tag| {
                other.options.iter().any(|other_tag| {
                    other_tag.number().value() == COAP_OPTION_REQUEST_TAG
                        && tag.value() == other_tag.value()
                })
            })
    }

    /// Iterate over typed, raw-preserving Block1 occurrences.
    pub fn block1_values(&self) -> impl Iterator<Item = Result<CoapBlock>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_BLOCK1)
            .map(CoapBlock::try_from)
    }

    /// Return the first Block1 occurrence as a typed, raw-preserving value.
    pub fn block1_value(&self) -> Option<Result<CoapBlock>> {
        self.block1_values().next()
    }

    /// Return an explicit source-backed report for the first Block1 option.
    ///
    /// Block1 in a request is descriptive, so its M bit and selected size are
    /// checked against the request payload. Block1 in a response is control
    /// metadata, so the response payload is deliberately ignored. Repeated
    /// occurrences remain available through [`Self::block1_values`] and are
    /// reported separately by [`Self::validate`].
    pub fn block1_validation(
        &self,
        transport: CoapBlockTransport,
    ) -> Option<Result<CoapBlockValidation>> {
        self.block1_value().map(|value| {
            value.map(|value| {
                if self.is_request() {
                    value.validate_block1(transport, self.payload.len())
                } else {
                    value.validate_control(CoapBlockKind::Block1, transport)
                }
            })
        })
    }

    /// Iterate over typed, raw-preserving Block2 occurrences.
    pub fn block2_values(&self) -> impl Iterator<Item = Result<CoapBlock>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_BLOCK2)
            .map(CoapBlock::try_from)
    }

    /// Return the first Block2 occurrence as a typed, raw-preserving value.
    pub fn block2_value(&self) -> Option<Result<CoapBlock>> {
        self.block2_values().next()
    }

    /// Return the byte offset selected or described by the first Block2 value.
    pub fn block2_offset(&self) -> Option<Result<u64>> {
        self.block2_value()
            .map(|value| value.and_then(|value| value.offset()))
    }

    /// Return an explicit source-backed report for the first Block2 option.
    ///
    /// A request Block2 is control metadata whose M bit must be zero. A
    /// response Block2 describes this message's payload and may be compared
    /// with the request selection to validate returned size and offset.
    /// Repeated occurrences remain inspectable and are reported separately by
    /// [`Self::validate`].
    pub fn block2_validation(
        &self,
        transport: CoapBlockTransport,
        requested: Option<&CoapBlock>,
    ) -> Option<Result<CoapBlockValidation>> {
        self.block2_value().map(|value| {
            value.map(|value| {
                if self.is_request() {
                    value.validate_block2_request(transport)
                } else {
                    value.validate_block2_response(transport, self.payload.len(), requested)
                }
            })
        })
    }

    /// Iterate over typed, raw-preserving Q-Block1 occurrences.
    pub fn qblock1_values(&self) -> impl Iterator<Item = Result<CoapBlock>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_Q_BLOCK1)
            .map(CoapBlock::try_from)
    }

    /// Return the first Q-Block1 occurrence.
    pub fn qblock1_value(&self) -> Option<Result<CoapBlock>> {
        self.qblock1_values().next()
    }

    /// Return packet-local Q-Block1 value and payload validation.
    pub fn qblock1_validation(
        &self,
        transport: CoapBlockTransport,
    ) -> Option<Result<CoapBlockValidation>> {
        self.qblock1_value().map(|value| {
            value.map(|value| {
                if self.is_request() {
                    value.validate_qblock1_request(transport, self.payload.len())
                } else {
                    value.validate_qblock1_response(transport)
                }
            })
        })
    }

    /// Iterate over typed, raw-preserving Q-Block2 occurrences.
    pub fn qblock2_values(&self) -> impl Iterator<Item = Result<CoapBlock>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_Q_BLOCK2)
            .map(CoapBlock::try_from)
    }

    /// Return the first Q-Block2 occurrence.
    pub fn qblock2_value(&self) -> Option<Result<CoapBlock>> {
        self.qblock2_values().next()
    }

    /// Return the first Q-Block2 byte offset.
    pub fn qblock2_offset(&self) -> Option<Result<u64>> {
        self.qblock2_value()
            .map(|value| value.and_then(|value| value.offset()))
    }

    /// Return packet-local Q-Block2 request or response validation.
    pub fn qblock2_validation(
        &self,
        transport: CoapBlockTransport,
        requested: Option<&CoapBlock>,
        max_payloads: u64,
    ) -> Option<Result<CoapBlockValidation>> {
        self.qblock2_value().map(|value| {
            value.map(|value| {
                if self.is_request() {
                    value.validate_qblock2_request(transport, max_payloads)
                } else {
                    value.validate_qblock2_response(
                        transport,
                        self.payload.len(),
                        requested,
                        max_payloads,
                    )
                }
            })
        })
    }

    /// Return the Observe value when this is a 2.xx notification shape.
    pub fn observe_notification(&self) -> Option<Result<CoapObserve>> {
        self.is_observe_notification()
            .then(|| self.observe_value())
            .flatten()
    }

    /// Iterate over typed Location-Path occurrences in insertion or wire order.
    ///
    /// Empty components remain present. A malformed occurrence is reported at
    /// its exact position without changing the underlying opaque option.
    pub fn location_paths(&self) -> impl Iterator<Item = Result<CoapLocationPath>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_LOCATION_PATH)
            .map(CoapLocationPath::try_from)
    }

    /// Iterate over typed Location-Query occurrences in insertion or wire order.
    pub fn location_queries(&self) -> impl Iterator<Item = Result<CoapLocationQuery>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_LOCATION_QUERY)
            .map(CoapLocationQuery::try_from)
    }

    /// Iterate over typed, raw-preserving Size1 occurrences.
    pub fn size1_values(&self) -> impl Iterator<Item = Result<CoapSize1>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_SIZE1)
            .map(CoapSize1::try_from)
    }

    /// Return the first Size1 occurrence as a typed, raw-preserving value.
    pub fn size1_value(&self) -> Option<Result<CoapSize1>> {
        self.size1_values().next()
    }

    /// Iterate over typed, raw-preserving ETag occurrences.
    pub fn etag_values(&self) -> impl Iterator<Item = Result<CoapEtag>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_ETAG)
            .map(CoapEtag::try_from)
    }

    /// Return the first ETag occurrence as a typed, raw-preserving value.
    pub fn etag_value(&self) -> Option<Result<CoapEtag>> {
        self.etag_values().next()
    }

    /// Iterate over typed, raw-preserving Size2 occurrences.
    pub fn size2_values(&self) -> impl Iterator<Item = Result<CoapSize2>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_SIZE2)
            .map(CoapSize2::try_from)
    }

    /// Return the first Size2 occurrence as a typed, raw-preserving value.
    pub fn size2_value(&self) -> Option<Result<CoapSize2>> {
        self.size2_values().next()
    }

    /// Iterate over typed Proxy-Uri occurrences in insertion or wire order.
    pub fn proxy_uris(&self) -> impl Iterator<Item = Result<CoapProxyUri>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_PROXY_URI)
            .map(CoapProxyUri::try_from)
    }

    /// Iterate over typed Proxy-Scheme occurrences in insertion or wire order.
    pub fn proxy_schemes(&self) -> impl Iterator<Item = Result<CoapProxyScheme>> + '_ {
        self.options
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_PROXY_SCHEME)
            .map(CoapProxyScheme::try_from)
    }

    /// Check Proxy-Uri mutual exclusion without changing or compiling options.
    pub fn validate_proxy_options(&self) -> Result<()> {
        validate_coap_proxy_options(&self.options)
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

    /// Inspect all source-backed CoAP datagram semantic inconsistencies.
    ///
    /// Validation is deliberately opt-in and aggregate: it neither mutates
    /// the layer nor participates in [`Layer::compile`]. Unknown option
    /// numbers remain lossless and receive no guessed semantic rules.
    pub fn validate(&self) -> CoapValidation {
        let mut validation = CoapValidation::default();

        validate_header_semantics(self, &mut validation);
        validate_token_semantics(self, &mut validation);
        validate_payload_semantics(self, &mut validation);
        validate_empty_message_semantics(self, &mut validation);
        validate_patch_semantics(self, &mut validation);
        validate_option_semantics(self, &mut validation);
        validate_qblock_semantics(self, &mut validation);

        validation
    }

    /// Return true when this datagram carries the Empty (`0.00`) code.
    ///
    /// This is a field classification, not semantic validation: an explicitly
    /// malformed Empty message with a token, options, or payload remains
    /// classified as Empty so its caller-supplied fields stay inspectable.
    pub fn is_empty(&self) -> bool {
        self.code_value().is_empty()
    }

    /// Return true when this datagram carries a non-empty class-0 code.
    ///
    /// Classification is intentionally open to future method assignments and
    /// does not validate whether the datagram message type is suitable for a
    /// request.
    pub fn is_request(&self) -> bool {
        self.code_value().is_request()
    }

    /// Return true when this datagram carries a class-2 through class-5 code.
    ///
    /// This preserves the open response-code space and does not validate the
    /// response's datagram message type.
    pub fn is_response(&self) -> bool {
        self.code_value().is_response()
    }

    /// Return true for a GET carrying an Observe option.
    ///
    /// This packet-local predicate deliberately classifies malformed or
    /// unknown-size values by code and option presence; callers can inspect
    /// [`Self::observe_value`] or [`Self::validate`] separately.
    pub fn is_observe_request(&self) -> bool {
        self.code_value() == CoapCode::get() && self.has_observe()
    }

    /// Return true for a GET registration request carrying `Observe: 0`.
    pub fn is_observe_registration(&self) -> bool {
        self.code_value() == CoapCode::get()
            && self
                .observe_values()
                .any(|value| value.is_ok_and(|value| value.is_registration()))
    }

    /// Return true for a GET deregistration request carrying `Observe: 1`.
    pub fn is_observe_deregistration(&self) -> bool {
        self.code_value() == CoapCode::get()
            && self
                .observe_values()
                .any(|value| value.is_ok_and(|value| value.is_deregistration()))
    }

    /// Return true for a 2.xx response carrying an Observe option.
    ///
    /// RFC 7641 defines only 2.xx responses with Observe as continuing
    /// notifications; terminal non-2.xx responses omit the option.
    pub fn is_observe_notification(&self) -> bool {
        self.code_value().class() == 2 && self.has_observe()
    }

    /// Return true when this datagram has the Confirmable (CON) message type.
    pub fn is_confirmable(&self) -> bool {
        self.message_type_value().is_confirmable()
    }

    /// Return true when this datagram has the Acknowledgement (ACK) type.
    pub fn is_acknowledgement(&self) -> bool {
        self.message_type_value().is_acknowledgement()
    }

    /// Return true when this datagram has the Reset (RST) message type.
    pub fn is_reset(&self) -> bool {
        self.message_type_value().is_reset()
    }

    /// Return true for the Empty ACK shape used before or after a separate
    /// Confirmable response.
    ///
    /// This predicate does not establish that a response will follow or that
    /// retained transaction state accepts this acknowledgement.
    pub fn is_empty_acknowledgement(&self) -> bool {
        self.is_acknowledgement() && self.is_empty()
    }

    /// Return true for a response carried in an Acknowledgement message.
    ///
    /// RFC 7252 Section 5.2.1 defines this ACK-plus-response-code shape as a
    /// piggybacked response. Use [`Self::matches_request`] to also compare the
    /// request Token and Message ID.
    pub fn is_piggybacked_response(&self) -> bool {
        self.is_acknowledgement() && self.is_response()
    }

    /// Return true for the datagram shape of a separate response.
    ///
    /// RFC 7252 Sections 5.2.2 and 5.2.3 carry separate responses in a new
    /// Confirmable or Non-confirmable message, not in an Acknowledgement.
    /// This predicate does not require or retain the preceding Empty ACK.
    pub fn is_separate_response(&self) -> bool {
        self.is_response()
            && (self.is_confirmable() || self.message_type_value().is_non_confirmable())
    }

    /// Compare the opaque Token bytes of two datagrams.
    ///
    /// RFC 7252 Section 5.3 uses the Token, together with endpoint information,
    /// to correlate a response with a request. This packet-local predicate
    /// compares only the typed token bytes and is not a transaction lookup.
    pub fn token_matches(&self, other: &Self) -> bool {
        self.token_value() == other.token_value()
    }

    /// Compare the Message ID fields of two datagrams.
    ///
    /// RFC 7252 Section 4.4 also requires endpoint information when matching
    /// an ACK or RST. This packet-local predicate compares only Message IDs.
    pub fn message_id_matches(&self, other: &Self) -> bool {
        self.message_id_value() == other.message_id_value()
    }

    /// Test the packet-local RFC 7252 shape and correlation fields for this
    /// response against `request`.
    ///
    /// A piggybacked response requires matching Token and Message ID. A
    /// separate CON or NON response requires only a matching Token. The
    /// caller remains responsible for endpoint identity, outstanding-request
    /// state, timing, security association, and duplicate handling; this is
    /// deliberately not a transaction engine.
    pub fn matches_request(&self, request: &Self) -> bool {
        let request_has_valid_shape = request.is_request()
            && (request.is_confirmable() || request.message_type_value().is_non_confirmable());

        if !request_has_valid_shape || !self.is_response() || !self.token_matches(request) {
            return false;
        }

        if self.is_piggybacked_response() {
            request.is_confirmable() && self.message_id_matches(request)
        } else {
            self.is_separate_response()
        }
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
        // The model accepts complete RFC 8974 metadata, while canonical
        // extension-byte emission remains a separate codec concern. Retain
        // the established base-only automatic compile boundary until then.
        if self.token_length_state() == FieldState::Unset {
            validate_base_token_len(self.token_value().len())?;
        }
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

/// Build the RFC 6690 `/.well-known/core` resource-discovery GET request.
///
/// The request contains the two Uri-Path segments and selects
/// `application/link-format` through Accept. It remains an ordinary typed
/// packet layer: callers provide transaction fields and choose a transport,
/// and this helper performs no network discovery or I/O.
pub fn coap_discovery_request() -> Coap {
    Coap::get()
        .uri_path(CoapUriPath::new(".well-known"))
        .uri_path(CoapUriPath::new("core"))
        .accept(CoapAccept::new(COAP_CONTENT_FORMAT_LINK_FORMAT))
}

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

#[derive(Clone, Copy)]
enum CoapOptionApplicability {
    Both,
    Request,
    Response,
}

#[derive(Clone, Copy)]
struct CoapOptionValidationRule {
    label: &'static str,
    min_len: Option<usize>,
    max_len: Option<usize>,
    repeatable: bool,
    applicability: CoapOptionApplicability,
}

impl CoapOptionValidationRule {
    const fn new(
        label: &'static str,
        min_len: usize,
        max_len: usize,
        repeatable: bool,
        applicability: CoapOptionApplicability,
    ) -> Self {
        Self {
            label,
            min_len: Some(min_len),
            max_len: Some(max_len),
            repeatable,
            applicability,
        }
    }

    const fn without_length(
        label: &'static str,
        repeatable: bool,
        applicability: CoapOptionApplicability,
    ) -> Self {
        Self {
            label,
            min_len: None,
            max_len: None,
            repeatable,
            applicability,
        }
    }
}

fn validate_header_semantics(message: &Coap, validation: &mut CoapValidation) {
    if !message.version_value().is_current() {
        validation.push(
            "coap.version",
            CoapValidationSeverity::Error,
            CoapValidationCategory::Header,
            "datagram CoAP version must be 1",
        );
    }

    if message.message_type_value().is_unknown() {
        validation.push(
            "coap.type",
            CoapValidationSeverity::Error,
            CoapValidationCategory::Header,
            "datagram CoAP type must fit the two-bit message type field",
        );
    }

    let code = message.code_value();
    if matches!(code.class(), 1 | 3 | 6 | 7) {
        validation.push(
            "coap.code",
            CoapValidationSeverity::Error,
            CoapValidationCategory::Header,
            "code class is reserved for datagram CoAP",
        );
    }

    let message_type = message.message_type_value();
    if message.is_request() && !(message_type.is_confirmable() || message_type.is_non_confirmable())
    {
        validation.push(
            "coap.type",
            CoapValidationSeverity::Error,
            CoapValidationCategory::Header,
            "requests must use Confirmable or Non-confirmable message type",
        );
    }

    if !message.is_empty() && message_type.is_reset() {
        validation.push(
            "coap.code",
            CoapValidationSeverity::Error,
            CoapValidationCategory::Header,
            "Reset messages must carry the Empty code",
        );
    }

    if message.is_empty() && message_type.is_non_confirmable() {
        validation.push(
            "coap.type",
            CoapValidationSeverity::Error,
            CoapValidationCategory::EmptyMessage,
            "Non-confirmable messages must not be Empty",
        );
    }
}

fn validate_token_semantics(message: &Coap, validation: &mut CoapValidation) {
    let actual_len = message.token_value().len();
    match message.token_length_value() {
        Ok(token_length) => match token_length.wire_len() {
            Ok(wire_len)
                if wire_len == token_length.declared_len() && wire_len == actual_len => {}
            Ok(wire_len) => validation.push(
                "coap.token-length",
                CoapValidationSeverity::Error,
                CoapValidationCategory::TokenLength,
                format!(
                    "wire token length {wire_len} and declared length {} do not describe {actual_len} token bytes",
                    token_length.declared_len()
                ),
            ),
            Err(error) => validation.push(
                "coap.token-length",
                CoapValidationSeverity::Error,
                CoapValidationCategory::TokenLength,
                error.to_string(),
            ),
        }
        Err(error) => validation.push(
            "coap.token-length",
            CoapValidationSeverity::Error,
            CoapValidationCategory::TokenLength,
            error.to_string(),
        ),
    }

    match message.canonical_token_length_value() {
        Ok(canonical) => {
            let minimum_datagram_len = COAP_HEADER_LEN
                .saturating_add(canonical.encoding().map_or(0, |form| form.extension_len()))
                .saturating_add(actual_len);
            if minimum_datagram_len > COAP_MAX_UDP_PAYLOAD_LEN {
                validation.push(
                    "coap.token-length",
                    CoapValidationSeverity::Error,
                    CoapValidationCategory::TokenLength,
                    format!(
                        "token length {actual_len} cannot fit with the CoAP header and TKL extension in a standard UDP datagram"
                    ),
                );
            }
        }
        Err(error) => {
            if message.token_length_value().is_ok() {
                validation.push(
                    "coap.token-length",
                    CoapValidationSeverity::Error,
                    CoapValidationCategory::TokenLength,
                    error.to_string(),
                );
            }
        }
    }
}

fn validate_payload_semantics(message: &Coap, validation: &mut CoapValidation) {
    let marker_present = message.payload_marker_value().is_present();
    let payload_present = !message.payload_value().is_empty();
    if marker_present == payload_present {
        return;
    }

    let reason = if marker_present {
        "payload marker must be followed by a non-empty payload"
    } else {
        "a non-empty payload requires a payload marker"
    };
    validation.push(
        "coap.payload-marker",
        CoapValidationSeverity::Error,
        CoapValidationCategory::PayloadMarker,
        reason,
    );
}

fn validate_empty_message_semantics(message: &Coap, validation: &mut CoapValidation) {
    if !message.is_empty() {
        return;
    }

    if !message.token_value().is_empty() {
        validation.push(
            "coap.token",
            CoapValidationSeverity::Error,
            CoapValidationCategory::EmptyMessage,
            "Empty messages must not contain a token",
        );
    }
    if !message.options_value().is_empty() {
        validation.push(
            "coap.options",
            CoapValidationSeverity::Error,
            CoapValidationCategory::EmptyMessage,
            "Empty messages must not contain options",
        );
    }
    if !message.payload_value().is_empty() {
        validation.push(
            "coap.payload",
            CoapValidationSeverity::Error,
            CoapValidationCategory::EmptyMessage,
            "Empty messages must not contain a payload",
        );
    }
}

fn validate_patch_semantics(message: &Coap, validation: &mut CoapValidation) {
    if !matches!(message.code_value(), code if code == CoapCode::patch() || code == CoapCode::ipatch())
    {
        return;
    }

    if message.content_format_value().is_none() {
        validation.push(
            "coap.options",
            CoapValidationSeverity::Error,
            CoapValidationCategory::MethodSemantics,
            "PATCH and iPATCH requests require a Content-Format for the patch document",
        );
    }

    if message.payload_value().is_empty() {
        validation.push(
            "coap.payload",
            CoapValidationSeverity::Error,
            CoapValidationCategory::MethodSemantics,
            "PATCH and iPATCH requests require a non-empty patch document payload",
        );
    }
}

fn validate_option_semantics(message: &Coap, validation: &mut CoapValidation) {
    validate_option_order_and_encoding(message, validation);

    let mut seen = Vec::<u16>::new();
    for (index, option) in message.options_value().iter().enumerate() {
        let number = option.number().value();
        let Some(rule) = coap_option_validation_rule(number) else {
            continue;
        };

        if !rule.repeatable && seen.contains(&number) {
            validation.push(
                format!("coap.options[{index}]"),
                CoapValidationSeverity::Error,
                CoapValidationCategory::OptionRepeatability,
                format!("{} option must not be repeated", rule.label),
            );
        }
        seen.push(number);

        if let (Some(min_len), Some(max_len)) = (rule.min_len, rule.max_len) {
            let actual_len = option.value().len();
            if actual_len < min_len || actual_len > max_len {
                let expected = if min_len == max_len {
                    format!("exactly {min_len}")
                } else {
                    format!("between {min_len} and {max_len}")
                };
                validation.push(
                    format!("coap.options[{index}].value"),
                    CoapValidationSeverity::Error,
                    CoapValidationCategory::OptionLength,
                    format!(
                        "{} option value must contain {expected} bytes, found {actual_len}",
                        rule.label
                    ),
                );
            }
        }

        let applicable = match rule.applicability {
            CoapOptionApplicability::Both => true,
            CoapOptionApplicability::Request => message.is_request(),
            CoapOptionApplicability::Response => message.is_response(),
        };
        if !applicable {
            let required_role = match rule.applicability {
                CoapOptionApplicability::Request => "request",
                CoapOptionApplicability::Response => "response",
                CoapOptionApplicability::Both => unreachable!("both roles are always applicable"),
            };
            validation.push(
                format!("coap.options[{index}].number"),
                CoapValidationSeverity::Error,
                CoapValidationCategory::OptionApplicability,
                format!("{} is a {required_role} option", rule.label),
            );
        }

        if number == COAP_OPTION_SIZE2 && message.is_request() {
            match CoapSize2::try_from(option) {
                Ok(size2) if size2.value() != 0 => validation.push(
                    format!("coap.options[{index}].value"),
                    CoapValidationSeverity::Error,
                    CoapValidationCategory::OptionApplicability,
                    "Size2 in a request must use the size-request value zero",
                ),
                _ => {}
            }
        }

        if number == COAP_OPTION_HOP_LIMIT && option.value() == [0] {
            validation.push(
                format!("coap.options[{index}].value"),
                CoapValidationSeverity::Error,
                CoapValidationCategory::OptionValue,
                "Hop-Limit must be between 1 and 255",
            );
        }
    }

    let has_proxy_uri = message
        .options_value()
        .iter()
        .any(|option| option.number().value() == COAP_OPTION_PROXY_URI);
    if has_proxy_uri {
        for (index, option) in message.options_value().iter().enumerate() {
            if matches!(
                option.number().value(),
                COAP_OPTION_URI_HOST
                    | COAP_OPTION_URI_PORT
                    | COAP_OPTION_URI_PATH
                    | COAP_OPTION_URI_QUERY
                    | COAP_OPTION_PROXY_SCHEME
            ) {
                validation.push(
                    format!("coap.options[{index}].number"),
                    CoapValidationSeverity::Error,
                    CoapValidationCategory::OptionInteraction,
                    "Proxy-Uri must not be combined with Uri-* or Proxy-Scheme options",
                );
            }
        }
    }
}

fn validate_qblock_semantics(message: &Coap, validation: &mut CoapValidation) {
    let has_block = message.options_value().iter().any(|option| {
        matches!(
            option.number().value(),
            COAP_OPTION_BLOCK1 | COAP_OPTION_BLOCK2
        )
    });
    let has_qblock = message.options_value().iter().any(|option| {
        matches!(
            option.number().value(),
            COAP_OPTION_Q_BLOCK1 | COAP_OPTION_Q_BLOCK2
        )
    });
    if has_block && has_qblock {
        validation.push(
            "coap.options",
            CoapValidationSeverity::Error,
            CoapValidationCategory::OptionInteraction,
            "Block and Q-Block options must not be mixed at the same protection level",
        );
    }

    let has_qblock1 = message
        .options_value()
        .iter()
        .any(|option| option.number().value() == COAP_OPTION_Q_BLOCK1);
    if message.is_request() && has_qblock1 {
        if message.request_tag_value().is_none() {
            validation.push(
                "coap.options",
                CoapValidationSeverity::Error,
                CoapValidationCategory::OptionInteraction,
                "Q-Block1 requests require a Request-Tag option",
            );
        }
        if message.size1_value().is_none() {
            validation.push(
                "coap.options",
                CoapValidationSeverity::Error,
                CoapValidationCategory::OptionInteraction,
                "Q-Block1 requests require a Size1 option",
            );
        }
    }

    let qblock2_indices = message
        .options_value()
        .iter()
        .enumerate()
        .filter(|(_, option)| option.number().value() == COAP_OPTION_Q_BLOCK2)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();

    if message.is_response() && !qblock2_indices.is_empty() {
        if message.etag_value().is_none() {
            validation.push(
                "coap.options",
                CoapValidationSeverity::Error,
                CoapValidationCategory::OptionInteraction,
                "Q-Block2 responses require an ETag option",
            );
        }
        if message.size2_value().is_none() {
            validation.push(
                "coap.options",
                CoapValidationSeverity::Error,
                CoapValidationCategory::OptionInteraction,
                "Q-Block2 responses require a Size2 option",
            );
        }
    }

    if qblock2_indices.len() > 1 && !message.is_request() {
        for index in qblock2_indices.iter().skip(1) {
            validation.push(
                format!("coap.options[{index}]"),
                CoapValidationSeverity::Error,
                CoapValidationCategory::OptionRepeatability,
                "Q-Block2 may be repeated only in a request for missing blocks",
            );
        }
    }

    let mut previous: Option<CoapBlock> = None;
    for index in qblock2_indices {
        let Ok(value) = CoapBlock::try_from(&message.options_value()[index]) else {
            continue;
        };
        if let Some(previous) = previous {
            if !previous.qblock_precedes(&value) {
                validation.push(
                    format!("coap.options[{index}].value"),
                    CoapValidationSeverity::Error,
                    CoapValidationCategory::OptionOrdering,
                    "repeated Q-Block2 request numbers must be strictly increasing",
                );
            }
        }
        previous = Some(value);
    }
}

fn validate_option_order_and_encoding(message: &Coap, validation: &mut CoapValidation) {
    let mut indices = (0..message.options_value().len()).collect::<Vec<_>>();
    if message.option_order_value() == CoapOptionOrder::Canonical {
        indices.sort_by_key(|index| message.options_value()[*index].number());
    }

    let mut previous_number = 0u16;
    for index in indices {
        let option = &message.options_value()[index];
        let number = option.number().value();
        if message.option_order_value() == CoapOptionOrder::Wire && number < previous_number {
            validation.push(
                format!("coap.options[{index}].number"),
                CoapValidationSeverity::Error,
                CoapValidationCategory::OptionOrdering,
                "wire-order option numbers must be nondecreasing",
            );
        }

        let expected_delta = u32::from(number.saturating_sub(previous_number));
        if let Some(encoding) = option.encoding() {
            if encoding
                .wire_delta()
                .is_some_and(|wire_delta| wire_delta != expected_delta)
            {
                validation.push(
                    format!("coap.options[{index}].encoding.delta"),
                    CoapValidationSeverity::Error,
                    CoapValidationCategory::OptionEncoding,
                    format!("explicit option delta does not match expected delta {expected_delta}"),
                );
            }
            if encoding
                .wire_length()
                .is_some_and(|wire_length| wire_length != option.value().len())
            {
                validation.push(
                    format!("coap.options[{index}].encoding.length"),
                    CoapValidationSeverity::Error,
                    CoapValidationCategory::OptionEncoding,
                    format!(
                        "explicit option length does not match {} value bytes",
                        option.value().len()
                    ),
                );
            }
            if encoding.raw_bytes().is_some()
                && encoding.wire_delta().is_none()
                && encoding.wire_length().is_none()
            {
                validation.push(
                    format!("coap.options[{index}].encoding.header"),
                    CoapValidationSeverity::Warning,
                    CoapValidationCategory::OptionEncoding,
                    "raw option header cannot be checked without logical delta and length metadata",
                );
            }
        }

        previous_number = number;
    }
}

fn coap_option_validation_rule(number: u16) -> Option<CoapOptionValidationRule> {
    use CoapOptionApplicability::{Both, Request, Response};

    let rule = match number {
        COAP_OPTION_IF_MATCH => CoapOptionValidationRule::new("If-Match", 0, 8, true, Request),
        COAP_OPTION_URI_HOST => CoapOptionValidationRule::new("Uri-Host", 1, 255, false, Request),
        COAP_OPTION_ETAG => CoapOptionValidationRule::new("ETag", 1, 8, true, Both),
        COAP_OPTION_IF_NONE_MATCH => {
            CoapOptionValidationRule::new("If-None-Match", 0, 0, false, Request)
        }
        COAP_OPTION_OBSERVE => CoapOptionValidationRule::new("Observe", 0, 3, false, Both),
        COAP_OPTION_URI_PORT => CoapOptionValidationRule::new("Uri-Port", 0, 2, false, Request),
        COAP_OPTION_LOCATION_PATH => {
            CoapOptionValidationRule::new("Location-Path", 0, 255, true, Response)
        }
        COAP_OPTION_OSCORE => CoapOptionValidationRule::without_length("OSCORE", false, Both),
        COAP_OPTION_URI_PATH => CoapOptionValidationRule::new("Uri-Path", 0, 255, true, Request),
        COAP_OPTION_CONTENT_FORMAT => {
            CoapOptionValidationRule::new("Content-Format", 0, 2, false, Both)
        }
        COAP_OPTION_MAX_AGE => CoapOptionValidationRule::new("Max-Age", 0, 4, false, Response),
        COAP_OPTION_URI_QUERY => CoapOptionValidationRule::new("Uri-Query", 0, 255, true, Request),
        COAP_OPTION_HOP_LIMIT => CoapOptionValidationRule::new("Hop-Limit", 1, 1, false, Request),
        COAP_OPTION_ACCEPT => CoapOptionValidationRule::new("Accept", 0, 2, false, Request),
        COAP_OPTION_Q_BLOCK1 => CoapOptionValidationRule::new("Q-Block1", 0, 3, false, Both),
        COAP_OPTION_LOCATION_QUERY => {
            CoapOptionValidationRule::new("Location-Query", 0, 255, true, Response)
        }
        COAP_OPTION_BLOCK2 => CoapOptionValidationRule::new("Block2", 0, 3, false, Both),
        COAP_OPTION_BLOCK1 => CoapOptionValidationRule::new("Block1", 0, 3, false, Both),
        COAP_OPTION_SIZE2 => CoapOptionValidationRule::new("Size2", 0, 4, false, Both),
        COAP_OPTION_Q_BLOCK2 => CoapOptionValidationRule::new("Q-Block2", 0, 3, true, Both),
        COAP_OPTION_PROXY_URI => {
            CoapOptionValidationRule::new("Proxy-Uri", 1, 1034, false, Request)
        }
        COAP_OPTION_PROXY_SCHEME => {
            CoapOptionValidationRule::new("Proxy-Scheme", 1, 255, false, Request)
        }
        COAP_OPTION_SIZE1 => CoapOptionValidationRule::new("Size1", 0, 4, false, Both),
        COAP_OPTION_ECHO => CoapOptionValidationRule::new("Echo", 1, 40, false, Both),
        COAP_OPTION_NO_RESPONSE => {
            CoapOptionValidationRule::new("No-Response", 0, 1, false, Request)
        }
        COAP_OPTION_REQUEST_TAG => {
            CoapOptionValidationRule::new("Request-Tag", 0, 8, true, Request)
        }
        _ => return None,
    };
    Some(rule)
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
    token_length
        .wire_len()
        .is_ok_and(|wire_len| wire_len == token_length.declared_len() && wire_len == actual_len)
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
    use crate::protocols::coap::CoapOptionEncoding;

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
            (
                Coap::get(),
                CoapCode::get(),
                0x01,
                "Coap(version=1, type=confirmable, code=0.01(GET), mid=0x0000, token_len=0, options=0, marker=absent, payload=0 bytes)",
            ),
            (
                Coap::post(),
                CoapCode::post(),
                0x02,
                "Coap(version=1, type=confirmable, code=0.02(POST), mid=0x0000, token_len=0, options=0, marker=absent, payload=0 bytes)",
            ),
            (
                Coap::put(),
                CoapCode::put(),
                0x03,
                "Coap(version=1, type=confirmable, code=0.03(PUT), mid=0x0000, token_len=0, options=0, marker=absent, payload=0 bytes)",
            ),
            (
                Coap::delete(),
                CoapCode::delete(),
                0x04,
                "Coap(version=1, type=confirmable, code=0.04(DELETE), mid=0x0000, token_len=0, options=0, marker=absent, payload=0 bytes)",
            ),
            (
                Coap::fetch(),
                CoapCode::fetch(),
                0x05,
                "Coap(version=1, type=confirmable, code=0.05(FETCH), mid=0x0000, token_len=0, options=0, marker=absent, payload=0 bytes)",
            ),
            (
                Coap::patch(),
                CoapCode::patch(),
                0x06,
                "Coap(version=1, type=confirmable, code=0.06(PATCH), mid=0x0000, token_len=0, options=0, marker=absent, payload=0 bytes)",
            ),
            (
                Coap::ipatch(),
                CoapCode::ipatch(),
                0x07,
                "Coap(version=1, type=confirmable, code=0.07(iPATCH), mid=0x0000, token_len=0, options=0, marker=absent, payload=0 bytes)",
            ),
            (
                Coap::content(),
                CoapCode::content(),
                0x45,
                "Coap(version=1, type=confirmable, code=2.05(Content), mid=0x0000, token_len=0, options=0, marker=absent, payload=0 bytes)",
            ),
            (
                Coap::bad_request(),
                CoapCode::bad_request(),
                0x80,
                "Coap(version=1, type=confirmable, code=4.00(Bad Request), mid=0x0000, token_len=0, options=0, marker=absent, payload=0 bytes)",
            ),
            (
                Coap::internal_server_error(),
                CoapCode::internal_server_error(),
                0xa0,
                "Coap(version=1, type=confirmable, code=5.00(Internal Server Error), mid=0x0000, token_len=0, options=0, marker=absent, payload=0 bytes)",
            ),
        ];

        for (message, code, code_byte, summary) in cases {
            assert_eq!(message.code_state(), FieldState::User);
            assert_eq!(message.code_value(), code);
            assert_eq!(message.version_state(), FieldState::Unset);
            assert_eq!(message.message_type_state(), FieldState::Unset);
            assert_eq!(message.message_id_state(), FieldState::Unset);
            assert_eq!(message.token_state(), FieldState::Unset);
            assert_eq!(message.token_length_state(), FieldState::Unset);
            assert!(message.options_value().is_empty());
            assert_eq!(message.payload_marker_state(), FieldState::Unset);
            assert!(message.payload_value().is_empty());
            assert_eq!(message.summary(), summary);
            assert_eq!(
                Packet::from_layer(message).compile().unwrap().as_bytes(),
                &[0x40, code_byte, 0x00, 0x00]
            );
        }

        let generic_cases = [
            (Coap::empty(), CoapCode::empty()),
            (
                Coap::request(CoapCode::from_wire(0x1f)),
                CoapCode::from_wire(0x1f),
            ),
            (
                Coap::response(CoapCode::from_wire(0xbe)),
                CoapCode::from_wire(0xbe),
            ),
        ];

        for (message, code) in generic_cases {
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
        assert_eq!(
            explicit.encoding().unwrap_err(),
            CrafterError::invalid_field_value(
                "coap.token-length",
                "token-length discriminator exceeds four bits"
            )
        );

        let direct = CoapTokenLength::canonical_for_len(12).unwrap();
        assert_eq!(direct.nibble(), 12);
        assert!(direct.extension_bytes().is_empty());
        assert_eq!(direct.declared_len(), 12);
        assert_eq!(direct.wire_len().unwrap(), 12);
        assert_eq!(direct.encoding().unwrap(), CoapTokenLengthEncoding::Direct);

        let extended8 = CoapTokenLength::canonical_for_len(268).unwrap();
        assert_eq!(extended8.nibble(), 13);
        assert_eq!(extended8.extension_bytes(), &[0xff]);
        assert_eq!(extended8.declared_len(), 268);
        assert_eq!(extended8.wire_len().unwrap(), 268);
        assert_eq!(
            extended8.encoding().unwrap(),
            CoapTokenLengthEncoding::Extended8
        );

        let extended16 = CoapTokenLength::canonical_for_len(CoapTokenLength::MAX_LEN).unwrap();
        assert_eq!(extended16.nibble(), 14);
        assert_eq!(extended16.extension_bytes(), &[0xff, 0xff]);
        assert_eq!(extended16.declared_len(), CoapTokenLength::MAX_LEN);
        assert_eq!(extended16.wire_len().unwrap(), CoapTokenLength::MAX_LEN);
        assert_eq!(
            extended16.encoding().unwrap(),
            CoapTokenLengthEncoding::Extended16
        );

        assert!(CoapTokenLength::canonical_for_len(CoapTokenLength::MAX_LEN + 1).is_err());
    }

    #[test]
    fn token_length_encoding_metadata_exposes_source_backed_form_bounds() {
        assert_eq!(CoapTokenLengthEncoding::Direct.extension_len(), 0);
        assert_eq!(CoapTokenLengthEncoding::Direct.min_len(), 0);
        assert_eq!(CoapTokenLengthEncoding::Direct.max_len(), 12);
        assert_eq!(CoapTokenLengthEncoding::Extended8.extension_len(), 1);
        assert_eq!(CoapTokenLengthEncoding::Extended8.min_len(), 13);
        assert_eq!(CoapTokenLengthEncoding::Extended8.max_len(), 268);
        assert_eq!(CoapTokenLengthEncoding::Extended16.extension_len(), 2);
        assert_eq!(CoapTokenLengthEncoding::Extended16.min_len(), 269);
        assert_eq!(CoapTokenLengthEncoding::Extended16.max_len(), 65_804);

        assert_eq!(CoapTokenLength::DIRECT_MAX_LEN, 12);
        assert_eq!(CoapTokenLength::EXTENDED8_MAX_LEN, 268);
        assert_eq!(CoapTokenLength::EXTENDED16_MAX_LEN, 65_804);
    }

    #[test]
    fn canonical_token_length_remains_distinct_from_explicit_wire_override() {
        let message = Coap::get()
            .token(CoapToken::from_bytes([0xa5; 13]))
            .token_length(CoapTokenLength::explicit(1, Vec::new(), 1));

        let canonical = message.canonical_token_length_value().unwrap();
        assert_eq!(
            canonical.encoding().unwrap(),
            CoapTokenLengthEncoding::Extended8
        );
        assert_eq!(canonical.extension_bytes(), [0]);
        assert_eq!(canonical.declared_len(), 13);
        assert_eq!(
            message.token_length_value().unwrap(),
            CoapTokenLength::explicit(1, Vec::new(), 1)
        );

        let validation = message.validate();
        assert_eq!(validation.len(), 1);
        assert_eq!(validation.issues()[0].field(), "coap.token-length");
        assert!(validation.issues()[0]
            .reason()
            .contains("do not describe 13 token bytes"));
    }

    #[test]
    fn token_validation_reports_standard_udp_length_incompatibility() {
        let largest_token_that_fits = COAP_MAX_UDP_PAYLOAD_LEN
            - COAP_HEADER_LEN
            - CoapTokenLengthEncoding::Extended16.extension_len();
        let message = Coap::get().token(CoapToken::from_bytes(vec![
            0x7e;
            largest_token_that_fits + 1
        ]));

        let validation = message.validate();
        assert_eq!(validation.len(), 1);
        assert_eq!(validation.issues()[0].field(), "coap.token-length");
        assert_eq!(
            validation.issues()[0].reason(),
            format!(
                "token length {} cannot fit with the CoAP header and TKL extension in a standard UDP datagram",
                largest_token_that_fits + 1
            )
        );
    }

    #[test]
    fn reserved_token_length_remains_a_structured_direct_decode_error() {
        assert_eq!(
            Coap::decode(&[0x4f, 0x01, 0x00, 0x01]),
            Err(CrafterError::invalid_field_value(
                "coap.token-length",
                "reserved TKL encoding 15"
            ))
        );
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
    fn message_classification_covers_piggybacked_separate_and_malformed_shapes() {
        let request = Coap::get().confirmable();
        assert!(request.is_request());
        assert!(request.is_confirmable());
        assert!(!request.is_empty());
        assert!(!request.is_response());
        assert!(!request.is_acknowledgement());
        assert!(!request.is_reset());
        assert!(!request.is_piggybacked_response());
        assert!(!request.is_separate_response());

        let piggybacked = Coap::content().acknowledgement();
        assert!(piggybacked.is_response());
        assert!(piggybacked.is_acknowledgement());
        assert!(piggybacked.is_piggybacked_response());
        assert!(!piggybacked.is_empty_acknowledgement());
        assert!(!piggybacked.is_separate_response());

        let separate_confirmable = Coap::content().confirmable();
        let separate_non_confirmable = Coap::response(CoapCode::from_wire(0x5d)).non_confirmable();
        for response in [&separate_confirmable, &separate_non_confirmable] {
            assert!(response.is_response());
            assert!(response.is_separate_response());
            assert!(!response.is_piggybacked_response());
        }
        assert!(separate_confirmable.is_confirmable());
        assert!(!separate_non_confirmable.is_confirmable());

        let empty_ack = Coap::empty_acknowledgement(0x1234);
        assert!(empty_ack.is_empty());
        assert!(empty_ack.is_acknowledgement());
        assert!(empty_ack.is_empty_acknowledgement());
        assert!(!empty_ack.is_response());

        let reset = Coap::empty_reset(0x1234);
        assert!(reset.is_empty());
        assert!(reset.is_reset());
        assert!(!reset.is_empty_acknowledgement());

        let malformed_ack_request = Coap::get().acknowledgement();
        assert!(malformed_ack_request.is_request());
        assert!(malformed_ack_request.is_acknowledgement());
        assert!(!malformed_ack_request.is_piggybacked_response());
        assert!(!malformed_ack_request.is_separate_response());

        let malformed_reset_response = Coap::response(CoapCode::from_wire(0x5d)).reset();
        assert!(malformed_reset_response.is_response());
        assert!(malformed_reset_response.is_reset());
        assert!(!malformed_reset_response.is_piggybacked_response());
        assert!(!malformed_reset_response.is_separate_response());

        let reserved = Coap::new().code(CoapCode::from_wire(0x20));
        assert!(!reserved.is_empty());
        assert!(!reserved.is_request());
        assert!(!reserved.is_response());
    }

    #[test]
    fn token_and_message_id_predicates_follow_rfc7252_matching_fields() {
        let request = Coap::get()
            .confirmable()
            .message_id(0x1234)
            .token(CoapToken::from_bytes([0xaa, 0xbb]));
        let piggybacked = Coap::content()
            .acknowledgement()
            .message_id(0x1234)
            .token(CoapToken::from_bytes([0xaa, 0xbb]));

        assert!(piggybacked.token_matches(&request));
        assert!(piggybacked.message_id_matches(&request));
        assert!(piggybacked.matches_request(&request));

        let wrong_piggybacked_token = piggybacked
            .clone()
            .token(CoapToken::from_bytes([0xcc, 0xdd]));
        assert!(!wrong_piggybacked_token.token_matches(&request));
        assert!(!wrong_piggybacked_token.matches_request(&request));

        let wrong_piggybacked_message_id = piggybacked.clone().message_id(0x5678);
        assert!(wrong_piggybacked_message_id.token_matches(&request));
        assert!(!wrong_piggybacked_message_id.message_id_matches(&request));
        assert!(!wrong_piggybacked_message_id.matches_request(&request));

        let separate = Coap::response(CoapCode::from_wire(0x5d))
            .confirmable()
            .message_id(0x5678)
            .token(CoapToken::from_bytes([0xaa, 0xbb]));
        assert!(separate.token_matches(&request));
        assert!(!separate.message_id_matches(&request));
        assert!(separate.matches_request(&request));

        let wrong_separate_token = separate.token(CoapToken::from_bytes([0x00]));
        assert!(!wrong_separate_token.matches_request(&request));

        let malformed_request = request.clone().acknowledgement();
        assert!(!piggybacked.matches_request(&malformed_request));

        let reset_with_response_code = Coap::response(CoapCode::from_wire(0x5d))
            .reset()
            .message_id(0x1234)
            .token(CoapToken::from_bytes([0xaa, 0xbb]));
        assert!(!reset_with_response_code.matches_request(&request));
    }

    #[test]
    fn empty_acknowledgement_and_reset_constructors_keep_explicit_overrides() {
        let acknowledgement = Coap::empty_acknowledgement(0x1234);
        assert_eq!(acknowledgement.code_state(), FieldState::User);
        assert_eq!(acknowledgement.code_value(), CoapCode::empty());
        assert_eq!(acknowledgement.message_type_state(), FieldState::User);
        assert_eq!(
            acknowledgement.message_type_value(),
            CoapMessageType::Acknowledgement
        );
        assert_eq!(acknowledgement.message_id_state(), FieldState::User);
        assert_eq!(acknowledgement.message_id_value(), 0x1234);
        assert_eq!(
            Packet::from_layer(acknowledgement)
                .compile()
                .unwrap()
                .as_bytes(),
            &[0x60, 0x00, 0x12, 0x34]
        );

        let reset = Coap::empty_reset(0xabcd);
        assert_eq!(reset.code_state(), FieldState::User);
        assert_eq!(reset.code_value(), CoapCode::empty());
        assert_eq!(reset.message_type_state(), FieldState::User);
        assert_eq!(reset.message_type_value(), CoapMessageType::Reset);
        assert_eq!(reset.message_id_state(), FieldState::User);
        assert_eq!(reset.message_id_value(), 0xabcd);
        assert_eq!(
            Packet::from_layer(reset).compile().unwrap().as_bytes(),
            &[0x70, 0x00, 0xab, 0xcd]
        );

        let overridden = Coap::empty_acknowledgement(0x1111)
            .version(3u8)
            .message_type(CoapMessageType::Unknown(6))
            .code(CoapCode::from_wire(0x5d))
            .message_id(0x2222)
            .token(CoapToken::from_bytes([0xaa]));
        let compiled = Packet::from_layer(overridden.clone()).compile().unwrap();

        assert_eq!(overridden.version_value(), CoapVersion::from_wire(3));
        assert_eq!(overridden.message_type_value(), CoapMessageType::Unknown(6));
        assert_eq!(overridden.code_value(), CoapCode::from_wire(0x5d));
        assert_eq!(overridden.message_id_value(), 0x2222);
        assert_eq!(overridden.token_value().as_bytes(), [0xaa]);
        assert_eq!(compiled.as_bytes(), &[0xe1, 0x5d, 0x22, 0x22, 0xaa]);
    }

    #[test]
    fn canonical_coap_builders_validate_without_findings() {
        let messages = [
            Coap::new(),
            Coap::empty_acknowledgement(0x1234),
            Coap::empty_reset(0x1234),
            Coap::get()
                .uri_host(CoapUriHost::new("example.com"))
                .uri_path(CoapUriPath::new("status"))
                .accept(CoapAccept::new(50)),
            Coap::content()
                .content_format(CoapContentFormat::new(50))
                .location_path(CoapLocationPath::new("created"))
                .payload(b"ok".to_vec()),
        ];

        for message in messages {
            let validation = message.validate();
            assert!(validation.is_clean(), "{:#?}", validation.issues());
            assert!(validation.is_empty());
            assert!(!validation.has_errors());
            assert_eq!(validation.len(), 0);
            assert!(validation.into_issues().is_empty());
        }
    }

    #[test]
    fn malformed_coap_compiles_and_reports_all_semantic_categories() {
        let malformed = Coap::empty()
            .version(2u8)
            .non_confirmable()
            .token_length(CoapTokenLength::explicit(2, Vec::new(), 2))
            .token(CoapToken::from_bytes([0xaa]))
            .options([
                CoapOption::new(COAP_OPTION_PROXY_URI, Vec::new())
                    .with_encoding(CoapOptionEncoding::explicit(35, 0)),
                CoapOption::new(COAP_OPTION_URI_HOST, Vec::new())
                    .with_encoding(CoapOptionEncoding::explicit(0, 1)),
                CoapOption::new(COAP_OPTION_URI_HOST, b"example.com".to_vec())
                    .with_encoding(CoapOptionEncoding::explicit(0, 11)),
            ])
            .option_order(CoapOptionOrder::Wire)
            .payload_marker(CoapPayloadMarker::Absent)
            .payload(vec![0xff]);

        let compiled = Packet::from_layer(malformed.clone())
            .compile()
            .expect("opt-in validation must not participate in compilation");
        assert!(!compiled.as_bytes().is_empty());

        let validation = malformed.validate();
        assert!(!validation.is_clean());
        assert!(validation.has_errors());

        let categories = validation
            .issues()
            .iter()
            .map(CoapValidationIssue::category)
            .collect::<Vec<_>>();
        for category in [
            CoapValidationCategory::Header,
            CoapValidationCategory::EmptyMessage,
            CoapValidationCategory::TokenLength,
            CoapValidationCategory::PayloadMarker,
            CoapValidationCategory::OptionOrdering,
            CoapValidationCategory::OptionEncoding,
            CoapValidationCategory::OptionRepeatability,
            CoapValidationCategory::OptionLength,
            CoapValidationCategory::OptionInteraction,
            CoapValidationCategory::OptionApplicability,
        ] {
            assert!(categories.contains(&category), "missing {category:?}");
        }

        let fields = validation
            .issues()
            .iter()
            .map(CoapValidationIssue::field)
            .collect::<Vec<_>>();
        assert!(fields.contains(&"coap.version"));
        assert!(fields.contains(&"coap.token-length"));
        assert!(fields.contains(&"coap.payload-marker"));
        assert!(fields.contains(&"coap.options[1].number"));
        assert!(fields.contains(&"coap.options[1].encoding.length"));
        assert!(fields.contains(&"coap.options[2]"));
        assert!(validation
            .issues()
            .iter()
            .all(|issue| !issue.reason().is_empty()));
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
