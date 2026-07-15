//! Ordered, lossless CoAP option primitives.
//!
//! The delta/length grammar and preservation rules are frozen in
//! `.agents/docs/coap-wire-grammar.md` from RFC 7252 Sections 3.1, 3.2, and
//! 5.4.6. Registry labels remain the separate concern of the reviewed
//! `.agents/docs/coap-codepoints.md` snapshot.

use core::str;

use crate::error::{CrafterError, Result};
use crate::field::{Field, FieldState};

use super::constants::{
    COAP_OPTION_ACCEPT, COAP_OPTION_CONTENT_FORMAT, COAP_OPTION_ETAG, COAP_OPTION_IF_MATCH,
    COAP_OPTION_IF_NONE_MATCH, COAP_OPTION_LOCATION_PATH, COAP_OPTION_LOCATION_QUERY,
    COAP_OPTION_MAX_AGE, COAP_OPTION_SIZE1, COAP_OPTION_SIZE2, COAP_OPTION_URI_HOST,
    COAP_OPTION_URI_PATH, COAP_OPTION_URI_PORT, COAP_OPTION_URI_QUERY, COAP_PAYLOAD_MARKER,
};
use super::registry::{
    coap_content_format_meta, coap_option_is_critical, coap_option_is_no_cache_key,
    coap_option_is_safe_to_forward, coap_option_is_unsafe, coap_option_meta, CoapRegistryMeta,
};

const COAP_OPTION_DIRECT_MAX: u64 = 12;
const COAP_OPTION_EXTENDED8_BASE: u64 = 13;
const COAP_OPTION_EXTENDED8_MAX: u64 = 268;
const COAP_OPTION_EXTENDED16_BASE: u64 = 269;
const COAP_OPTION_EXTENDED16_MAX: u64 = 65_804;

const COAP_OPTION_EXTENDED8_NIBBLE: u8 = 13;
const COAP_OPTION_EXTENDED16_NIBBLE: u8 = 14;
const COAP_OPTION_RESERVED_NIBBLE: u8 = 15;

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

/// Semantic wire format associated with a source-backed CoAP option.
///
/// This metadata never constrains the opaque option envelope. In particular,
/// an unknown option or a known option carrying a malformed value remains a
/// lossless [`CoapOption`] and may still be inspected through any of its
/// fallible value views.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoapOptionFormat {
    /// The option is represented by an empty value.
    Empty,
    /// The option value is an uninterpreted byte string.
    Opaque,
    /// The option value is an unsigned integer in network byte order.
    Uint,
    /// The option value is a UTF-8 string.
    String,
    /// The local source snapshot does not assign a value format.
    Unknown,
}

/// Explicit logical delta and length values for an option wire header.
///
/// The option header codec uses these values only when the caller asks for an
/// override. Keeping them independent permits intentionally noncanonical or
/// internally inconsistent packets without changing the option number or
/// owned value bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoapOptionEncoding {
    wire_delta: Option<u32>,
    wire_length: Option<usize>,
    raw_header: Option<Vec<u8>>,
}

impl CoapOptionEncoding {
    /// Create encoding metadata with no explicit overrides.
    pub const fn new() -> Self {
        Self {
            wire_delta: None,
            wire_length: None,
            raw_header: None,
        }
    }

    /// Create encoding metadata with both logical wire values pinned.
    pub const fn explicit(wire_delta: u32, wire_length: usize) -> Self {
        Self {
            wire_delta: Some(wire_delta),
            wire_length: Some(wire_length),
            raw_header: None,
        }
    }

    /// Preserve exact option header and extension bytes.
    ///
    /// Raw bytes take precedence over logical delta and length overrides when
    /// the option header is compiled. They are deliberately not validated so
    /// callers and decoded packets can retain noncanonical, truncated, or
    /// reserved encodings byte-for-byte.
    pub fn from_raw_bytes(raw_header: impl Into<Vec<u8>>) -> Self {
        Self {
            wire_delta: None,
            wire_length: None,
            raw_header: Some(raw_header.into()),
        }
    }

    /// Pin the logical delta emitted by the option header codec.
    pub const fn with_wire_delta(mut self, wire_delta: u32) -> Self {
        self.wire_delta = Some(wire_delta);
        self
    }

    /// Pin the logical length emitted by the option header codec.
    pub const fn with_wire_length(mut self, wire_length: usize) -> Self {
        self.wire_length = Some(wire_length);
        self
    }

    /// Pin exact option header and extension bytes.
    ///
    /// The raw representation wins over any logical overrides already stored
    /// in this metadata.
    pub fn with_raw_bytes(mut self, raw_header: impl Into<Vec<u8>>) -> Self {
        self.raw_header = Some(raw_header.into());
        self
    }

    /// Return the caller-supplied wire delta, if present.
    pub const fn wire_delta(&self) -> Option<u32> {
        self.wire_delta
    }

    /// Return the caller-supplied wire length, if present.
    pub const fn wire_length(&self) -> Option<usize> {
        self.wire_length
    }

    /// Borrow exact caller-supplied or decoded option header bytes.
    pub fn raw_bytes(&self) -> Option<&[u8]> {
        self.raw_header.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DecodedOptionHeader {
    pub(super) delta: u32,
    pub(super) length: usize,
    pub(super) consumed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EncodedOptionComponent {
    nibble: u8,
    extension: [u8; 2],
    extension_len: usize,
}

impl EncodedOptionComponent {
    fn direct(nibble: u8) -> Self {
        Self {
            nibble,
            extension: [0; 2],
            extension_len: 0,
        }
    }

    fn extended8(extension: u8) -> Self {
        Self {
            nibble: COAP_OPTION_EXTENDED8_NIBBLE,
            extension: [extension, 0],
            extension_len: 1,
        }
    }

    fn extended16(extension: u16) -> Self {
        Self {
            nibble: COAP_OPTION_EXTENDED16_NIBBLE,
            extension: extension.to_be_bytes(),
            extension_len: 2,
        }
    }

    fn extension(&self) -> &[u8] {
        &self.extension[..self.extension_len]
    }
}

/// Append one option header and return its encoded byte count.
///
/// Canonical values use their shortest direct or extended representation.
/// Logical values in `encoding` override the derived delta and length. Exact
/// raw bytes, when present, take precedence and are emitted without validation
/// so deliberately malformed packets remain constructible.
pub(super) fn encode_option_header(
    delta: u32,
    length: usize,
    encoding: Option<&CoapOptionEncoding>,
    out: &mut Vec<u8>,
) -> Result<usize> {
    if let Some(raw_header) = encoding.and_then(CoapOptionEncoding::raw_bytes) {
        out.extend_from_slice(raw_header);
        return Ok(raw_header.len());
    }

    let delta = encoding
        .and_then(CoapOptionEncoding::wire_delta)
        .unwrap_or(delta);
    let length = encoding
        .and_then(CoapOptionEncoding::wire_length)
        .unwrap_or(length);

    let encoded_delta = encode_option_component(
        u64::from(delta),
        "coap.option.delta",
        "option delta exceeds 65804",
    )?;
    let length = u64::try_from(length).map_err(|_| {
        CrafterError::invalid_field_value("coap.option.length", "option length exceeds 65804")
    })?;
    let encoded_length =
        encode_option_component(length, "coap.option.length", "option length exceeds 65804")?;

    let encoded_len = 1usize
        .checked_add(encoded_delta.extension_len)
        .and_then(|len| len.checked_add(encoded_length.extension_len))
        .ok_or_else(|| {
            CrafterError::invalid_field_value("coap.option.header", "option header length overflow")
        })?;

    out.reserve(encoded_len);
    out.push((encoded_delta.nibble << 4) | encoded_length.nibble);
    out.extend_from_slice(encoded_delta.extension());
    out.extend_from_slice(encoded_length.extension());
    Ok(encoded_len)
}

/// Decode one option header and return logical values plus bytes consumed.
pub(super) fn decode_option_header(bytes: &[u8]) -> Result<DecodedOptionHeader> {
    let header = *bytes
        .first()
        .ok_or_else(|| CrafterError::buffer_too_short("coap.option.header", 1, bytes.len()))?;
    let delta_nibble = header >> 4;
    let length_nibble = header & 0x0f;

    if delta_nibble == COAP_OPTION_RESERVED_NIBBLE {
        let reason = if header == 0xff {
            "payload marker is not an option header"
        } else {
            "reserved delta nibble 15 is not a payload marker"
        };
        return Err(CrafterError::invalid_field_value(
            "coap.option.delta",
            reason,
        ));
    }
    if length_nibble == COAP_OPTION_RESERVED_NIBBLE {
        return Err(CrafterError::invalid_field_value(
            "coap.option.length",
            "reserved option length nibble 15",
        ));
    }

    let mut cursor = 1usize;
    let delta = decode_option_component(
        delta_nibble,
        bytes,
        &mut cursor,
        "coap.option.delta.extended8",
        "coap.option.delta.extended16",
        "coap.option.delta",
    )?;
    let length = decode_option_component(
        length_nibble,
        bytes,
        &mut cursor,
        "coap.option.length.extended8",
        "coap.option.length.extended16",
        "coap.option.length",
    )?;
    let length = usize::try_from(length).map_err(|_| {
        CrafterError::invalid_field_value("coap.option.length", "decoded option length overflow")
    })?;

    Ok(DecodedOptionHeader {
        delta,
        length,
        consumed: cursor,
    })
}

fn encode_option_component(
    value: u64,
    field: &'static str,
    overflow_reason: &'static str,
) -> Result<EncodedOptionComponent> {
    match value {
        0..=COAP_OPTION_DIRECT_MAX => Ok(EncodedOptionComponent::direct(value as u8)),
        COAP_OPTION_EXTENDED8_BASE..=COAP_OPTION_EXTENDED8_MAX => {
            let extension = value
                .checked_sub(COAP_OPTION_EXTENDED8_BASE)
                .and_then(|extension| u8::try_from(extension).ok())
                .ok_or_else(|| CrafterError::invalid_field_value(field, overflow_reason))?;
            Ok(EncodedOptionComponent::extended8(extension))
        }
        COAP_OPTION_EXTENDED16_BASE..=COAP_OPTION_EXTENDED16_MAX => {
            let extension = value
                .checked_sub(COAP_OPTION_EXTENDED16_BASE)
                .and_then(|extension| u16::try_from(extension).ok())
                .ok_or_else(|| CrafterError::invalid_field_value(field, overflow_reason))?;
            Ok(EncodedOptionComponent::extended16(extension))
        }
        _ => Err(CrafterError::invalid_field_value(field, overflow_reason)),
    }
}

fn decode_option_component(
    nibble: u8,
    bytes: &[u8],
    cursor: &mut usize,
    extended8_context: &'static str,
    extended16_context: &'static str,
    field: &'static str,
) -> Result<u32> {
    match nibble {
        0..=12 => Ok(u32::from(nibble)),
        COAP_OPTION_EXTENDED8_NIBBLE => {
            let remaining = bytes.get(*cursor..).unwrap_or_default();
            let extension = *remaining.first().ok_or_else(|| {
                CrafterError::buffer_too_short(extended8_context, 1, remaining.len())
            })?;
            *cursor = cursor.checked_add(1).ok_or_else(|| {
                CrafterError::invalid_field_value(field, "option header cursor overflow")
            })?;
            u32::from(extension)
                .checked_add(COAP_OPTION_EXTENDED8_BASE as u32)
                .ok_or_else(|| {
                    CrafterError::invalid_field_value(field, "decoded option value overflow")
                })
        }
        COAP_OPTION_EXTENDED16_NIBBLE => {
            let remaining = bytes.get(*cursor..).unwrap_or_default();
            let extension = remaining.get(..2).ok_or_else(|| {
                CrafterError::buffer_too_short(extended16_context, 2, remaining.len())
            })?;
            let extension = u16::from_be_bytes([extension[0], extension[1]]);
            *cursor = cursor.checked_add(2).ok_or_else(|| {
                CrafterError::invalid_field_value(field, "option header cursor overflow")
            })?;
            u32::from(extension)
                .checked_add(COAP_OPTION_EXTENDED16_BASE as u32)
                .ok_or_else(|| {
                    CrafterError::invalid_field_value(field, "decoded option value overflow")
                })
        }
        _ => Err(CrafterError::invalid_field_value(
            field,
            "reserved option header nibble",
        )),
    }
}

/// One ordered, lossless CoAP option occurrence.
///
/// The value is always retained as owned opaque bytes. Typed views borrow that
/// same storage, so failed UTF-8 or integer interpretation never discards or
/// normalizes the wire representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapOption {
    number: CoapOptionNumber,
    value: Vec<u8>,
    encoding: Field<CoapOptionEncoding>,
}

fn encode_coap_uint(value: u64) -> Vec<u8> {
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

fn decode_coap_uint(
    bytes: &[u8],
    max_length: usize,
    field: &'static str,
    length_error: &'static str,
) -> Result<u64> {
    if bytes.len() > max_length {
        return Err(CrafterError::invalid_field_value(field, length_error));
    }

    Ok(bytes
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)))
}

impl CoapOption {
    /// Build an opaque option occurrence from its number and exact value bytes.
    pub fn new(number: impl Into<CoapOptionNumber>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            number: number.into(),
            value: value.into(),
            encoding: Field::unset(),
        }
    }

    /// Build an opaque option occurrence without assigning a semantic format.
    pub fn from_opaque(number: impl Into<CoapOptionNumber>, value: impl Into<Vec<u8>>) -> Self {
        Self::new(number, value)
    }

    /// Build an option with the canonical shortest unsigned-integer value.
    ///
    /// Zero is represented by an empty value, as required by the CoAP `uint`
    /// format. Decoded or deliberately noncanonical integers should use
    /// [`Self::new`] so their original bytes remain intact.
    pub fn from_uint(number: impl Into<CoapOptionNumber>, value: u64) -> Self {
        Self::new(number, encode_coap_uint(value))
    }

    /// Build an option from UTF-8 text while retaining its exact encoded bytes.
    pub fn from_string(number: impl Into<CoapOptionNumber>, value: impl AsRef<str>) -> Self {
        Self::new(number, value.as_ref().as_bytes().to_vec())
    }

    /// Attach explicit option-header encoding metadata.
    pub fn with_encoding(mut self, encoding: CoapOptionEncoding) -> Self {
        self.encoding.set_user(encoding);
        self
    }

    /// Pin only the logical wire delta while retaining any length override.
    pub fn with_wire_delta(mut self, wire_delta: u32) -> Self {
        let encoding = self
            .encoding
            .value()
            .cloned()
            .unwrap_or_default()
            .with_wire_delta(wire_delta);
        self.encoding.set_user(encoding);
        self
    }

    /// Pin only the logical wire length while retaining any delta override.
    pub fn with_wire_length(mut self, wire_length: usize) -> Self {
        let encoding = self
            .encoding
            .value()
            .cloned()
            .unwrap_or_default()
            .with_wire_length(wire_length);
        self.encoding.set_user(encoding);
        self
    }

    /// Return this occurrence's complete option number.
    pub const fn number(&self) -> CoapOptionNumber {
        self.number
    }

    /// Borrow the exact, unmodified option value bytes.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Borrow the exact, unmodified option value bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.value()
    }

    /// Consume this occurrence and return its exact value bytes.
    pub fn into_value(self) -> Vec<u8> {
        self.value
    }

    /// Consume this occurrence and return its exact value bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.into_value()
    }

    /// Return the state of the optional explicit encoding metadata.
    pub const fn encoding_state(&self) -> FieldState {
        self.encoding.state()
    }

    /// Borrow explicit or decoded encoding metadata, if present.
    pub const fn encoding(&self) -> Option<&CoapOptionEncoding> {
        self.encoding.value()
    }

    /// Return source-backed registry metadata for this option number.
    pub fn registry_meta(&self) -> CoapRegistryMeta {
        self.number.registry_meta()
    }

    /// Return source-backed value-format metadata for this option number.
    pub const fn format(&self) -> CoapOptionFormat {
        match self.number.value() {
            5 => CoapOptionFormat::Empty,
            1 | 4 | 9 | 252 | 292 => CoapOptionFormat::Opaque,
            6 | 7 | 12 | 14 | 16 | 17 | 19 | 23 | 27 | 28 | 31 | 60 | 258 => CoapOptionFormat::Uint,
            3 | 8 | 11 | 15 | 20 | 35 | 39 => CoapOptionFormat::String,
            _ => CoapOptionFormat::Unknown,
        }
    }

    /// Interpret the value as an unsigned network-byte-order integer.
    ///
    /// Empty values represent zero. Values wider than `u64` return a
    /// structured error, and the original bytes remain available unchanged.
    pub fn as_uint(&self) -> Result<u64> {
        decode_coap_uint(
            &self.value,
            size_of::<u64>(),
            "coap.option.uint",
            "unsigned option value exceeds 64 bits",
        )
    }

    /// Interpret the exact value bytes as UTF-8 text.
    pub fn as_str(&self) -> Result<&str> {
        str::from_utf8(&self.value).map_err(|_| {
            CrafterError::invalid_field_value(
                "coap.option.string",
                "option value is not valid UTF-8",
            )
        })
    }

    /// Borrow the value through the fallible opaque-view interface.
    ///
    /// Opaque bytes have no structural restrictions, so this currently always
    /// succeeds. Returning [`Result`] keeps typed option-view call sites
    /// uniform without copying or changing the stored value.
    pub fn as_opaque(&self) -> Result<&[u8]> {
        Ok(self.value())
    }
}

macro_rules! define_uint_option {
    (
        $(#[$meta:meta])*
        $name:ident,
        integer = $integer:ty,
        number = $number:expr,
        field = $field:literal,
        wrong_number = $wrong_number:literal,
        max_length = $max_length:expr,
        length_error = $length_error:literal
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name {
            value: $integer,
            wire_value: Vec<u8>,
        }

        impl $name {
            /// Build a value using the canonical shortest CoAP `uint` encoding.
            pub fn new(value: $integer) -> Self {
                Self {
                    value,
                    wire_value: encode_coap_uint(u64::from(value)),
                }
            }

            /// Return the decoded unsigned integer.
            pub const fn value(&self) -> $integer {
                self.value
            }

            /// Borrow the exact canonical or decoded option value bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.wire_value
            }

            /// Consume the wrapper and return the exact option value bytes.
            pub fn into_bytes(self) -> Vec<u8> {
                self.wire_value
            }
        }

        impl From<$integer> for $name {
            fn from(value: $integer) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for CoapOption {
            fn from(value: $name) -> Self {
                CoapOption::new($number, value.into_bytes())
            }
        }

        impl TryFrom<&CoapOption> for $name {
            type Error = CrafterError;

            fn try_from(option: &CoapOption) -> Result<Self> {
                if option.number().value() != $number {
                    return Err(CrafterError::invalid_field_value($field, $wrong_number));
                }

                let value = decode_coap_uint(
                    option.value(),
                    $max_length,
                    $field,
                    $length_error,
                )? as $integer;
                Ok(Self {
                    value,
                    wire_value: option.value().to_vec(),
                })
            }
        }
    };
}

define_uint_option! {
    /// One RFC 7252 Content-Format option with an open IANA identifier.
    ///
    /// The numeric value is never restricted to the currently assigned set.
    /// Checked conversion retains zero-prefixed noncanonical bytes so the
    /// option can be converted back without changing its wire representation.
    CoapContentFormat,
    integer = u16,
    number = COAP_OPTION_CONTENT_FORMAT,
    field = "coap.content-format",
    wrong_number = "option number is not Content-Format",
    max_length = 2,
    length_error = "Content-Format length must not exceed 2 bytes"
}

impl CoapContentFormat {
    /// Return current source-backed registry metadata for this open value.
    pub fn registry_meta(&self) -> CoapRegistryMeta {
        coap_content_format_meta(u64::from(self.value))
    }
}

define_uint_option! {
    /// One RFC 7252 Accept option with an open IANA Content-Format identifier.
    ///
    /// Unknown, experimental, and future identifiers remain representable and
    /// inspectable through [`Self::registry_meta`].
    CoapAccept,
    integer = u16,
    number = COAP_OPTION_ACCEPT,
    field = "coap.accept",
    wrong_number = "option number is not Accept",
    max_length = 2,
    length_error = "Accept length must not exceed 2 bytes"
}

impl CoapAccept {
    /// Return current source-backed Content-Format metadata for this value.
    pub fn registry_meta(&self) -> CoapRegistryMeta {
        coap_content_format_meta(u64::from(self.value))
    }
}

define_uint_option! {
    /// One RFC 7252 Max-Age response freshness lifetime in seconds.
    CoapMaxAge,
    integer = u32,
    number = COAP_OPTION_MAX_AGE,
    field = "coap.max-age",
    wrong_number = "option number is not Max-Age",
    max_length = 4,
    length_error = "Max-Age length must not exceed 4 bytes"
}

impl CoapMaxAge {
    /// RFC 7252's freshness lifetime when a response omits Max-Age.
    pub const RESPONSE_DEFAULT_SECONDS: u32 = 60;

    /// Return the RFC 7252 response interpretation without inserting an option.
    pub const fn effective_response_seconds(value: Option<&Self>) -> u32 {
        match value {
            Some(value) => value.value,
            None => Self::RESPONSE_DEFAULT_SECONDS,
        }
    }
}

define_uint_option! {
    /// One RFC 7252 Size1 request-body size metadata value.
    CoapSize1,
    integer = u32,
    number = COAP_OPTION_SIZE1,
    field = "coap.size1",
    wrong_number = "option number is not Size1",
    max_length = 4,
    length_error = "Size1 length must not exceed 4 bytes"
}

define_uint_option! {
    /// One RFC 7959 Size2 response-body size metadata value.
    CoapSize2,
    integer = u32,
    number = COAP_OPTION_SIZE2,
    field = "coap.size2",
    wrong_number = "option number is not Size2",
    max_length = 4,
    length_error = "Size2 length must not exceed 4 bytes"
}

macro_rules! impl_size_platform_conversions {
    ($name:ident, field = $field:literal, label = $label:literal) => {
        impl $name {
            /// Build a size value from the platform's collection length type.
            pub fn try_from_usize(value: usize) -> Result<Self> {
                let value = u32::try_from(value).map_err(|_| {
                    CrafterError::invalid_field_value(
                        $field,
                        concat!($label, " value exceeds the four-byte CoAP uint range"),
                    )
                })?;
                Ok(Self::new(value))
            }

            /// Convert the decoded size to the platform's collection length type.
            pub fn try_to_usize(&self) -> Result<usize> {
                usize::try_from(self.value()).map_err(|_| {
                    CrafterError::invalid_field_value(
                        $field,
                        concat!($label, " value exceeds the platform usize range"),
                    )
                })
            }
        }

        impl TryFrom<usize> for $name {
            type Error = CrafterError;

            fn try_from(value: usize) -> Result<Self> {
                Self::try_from_usize(value)
            }
        }

        impl TryFrom<&$name> for usize {
            type Error = CrafterError;

            fn try_from(value: &$name) -> Result<Self> {
                value.try_to_usize()
            }
        }
    };
}

impl_size_platform_conversions!(CoapSize1, field = "coap.size1", label = "Size1");
impl_size_platform_conversions!(CoapSize2, field = "coap.size2", label = "Size2");

macro_rules! define_checked_opaque_option {
    (
        $(#[$meta:meta])*
        $name:ident,
        number = $number:expr,
        field = $field:literal,
        wrong_number = $wrong_number:literal,
        min_length = $min_length:expr,
        max_length = $max_length:expr,
        length_error = $length_error:literal
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name {
            value: Vec<u8>,
        }

        impl $name {
            /// Build one lossless occurrence from exact option value bytes.
            ///
            /// This constructor deliberately accepts semantically malformed
            /// lengths for packet crafting. Use [`Self::try_new`] or
            /// [`Self::validate`] when a checked value is required.
            pub fn new(value: impl AsRef<[u8]>) -> Self {
                Self {
                    value: value.as_ref().to_vec(),
                }
            }

            /// Build one occurrence after checking its RFC 7252 length.
            pub fn try_new(value: impl AsRef<[u8]>) -> Result<Self> {
                let value = Self::new(value);
                value.validate()?;
                Ok(value)
            }

            /// Check this occurrence's RFC 7252 semantic length.
            pub fn validate(&self) -> Result<()> {
                if !($min_length..=$max_length).contains(&self.value.len()) {
                    return Err(CrafterError::invalid_field_value($field, $length_error));
                }
                Ok(())
            }

            /// Borrow the exact option value bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.value
            }

            /// Consume the wrapper and return the exact option value bytes.
            pub fn into_bytes(self) -> Vec<u8> {
                self.value
            }

            /// Compare the exact opaque value with caller-provided bytes.
            ///
            /// This is byte equality only. It does not apply cache or server
            /// precondition semantics.
            pub fn matches_bytes(&self, other: impl AsRef<[u8]>) -> bool {
                self.as_bytes() == other.as_ref()
            }
        }

        impl From<Vec<u8>> for $name {
            fn from(value: Vec<u8>) -> Self {
                Self { value }
            }
        }

        impl From<$name> for CoapOption {
            fn from(value: $name) -> Self {
                CoapOption::new($number, value.into_bytes())
            }
        }

        impl TryFrom<&CoapOption> for $name {
            type Error = CrafterError;

            fn try_from(option: &CoapOption) -> Result<Self> {
                if option.number().value() != $number {
                    return Err(CrafterError::invalid_field_value($field, $wrong_number));
                }

                Self::try_new(option.value())
            }
        }
    };
}

define_checked_opaque_option! {
    /// One repeatable RFC 7252 If-Match request precondition value.
    ///
    /// Values are opaque and at most eight bytes. The empty value is the
    /// source-defined wildcard form represented by [`Self::any`].
    CoapIfMatch,
    number = COAP_OPTION_IF_MATCH,
    field = "coap.if-match",
    wrong_number = "option number is not If-Match",
    min_length = 0,
    max_length = 8,
    length_error = "If-Match length must not exceed 8 bytes"
}

impl CoapIfMatch {
    /// Build the empty wildcard form that matches any current representation.
    pub fn any() -> Self {
        Self::new([])
    }

    /// Return whether this value is the empty wildcard form.
    pub fn is_any(&self) -> bool {
        self.as_bytes().is_empty()
    }

    /// Compare this value with one ETag using exact byte equality.
    ///
    /// The wildcard form is reported separately by [`Self::is_any`] and is
    /// not expanded into server-side precondition behavior here.
    pub fn matches_etag(&self, etag: &CoapEtag) -> bool {
        self.matches_bytes(etag.as_bytes())
    }
}

define_checked_opaque_option! {
    /// One repeatable RFC 7252 Entity-Tag option value.
    ///
    /// ETags are opaque byte strings between one and eight bytes inclusive.
    CoapEtag,
    number = COAP_OPTION_ETAG,
    field = "coap.etag",
    wrong_number = "option number is not ETag",
    min_length = 1,
    max_length = 8,
    length_error = "ETag length must be between 1 and 8 bytes"
}

impl CoapEtag {
    /// Compare this ETag with one If-Match value using exact byte equality.
    ///
    /// Call [`CoapIfMatch::is_any`] separately for the empty wildcard form.
    pub fn matches_if_match(&self, if_match: &CoapIfMatch) -> bool {
        self.matches_bytes(if_match.as_bytes())
    }
}

/// The empty RFC 7252 If-None-Match request precondition option.
///
/// Presence is the complete typed value. A nonempty raw [`CoapOption`] stays
/// constructible and lossless but fails the checked `TryFrom` view.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct CoapIfNoneMatch;

impl CoapIfNoneMatch {
    /// Build the empty If-None-Match value.
    pub const fn new() -> Self {
        Self
    }

    /// Borrow the empty wire value.
    pub const fn as_bytes(&self) -> &'static [u8] {
        &[]
    }

    /// Return the empty wire value as owned bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        Vec::new()
    }
}

impl From<CoapIfNoneMatch> for CoapOption {
    fn from(value: CoapIfNoneMatch) -> Self {
        CoapOption::new(COAP_OPTION_IF_NONE_MATCH, value.into_bytes())
    }
}

impl TryFrom<&CoapOption> for CoapIfNoneMatch {
    type Error = CrafterError;

    fn try_from(option: &CoapOption) -> Result<Self> {
        if option.number().value() != COAP_OPTION_IF_NONE_MATCH {
            return Err(CrafterError::invalid_field_value(
                "coap.if-none-match",
                "option number is not If-None-Match",
            ));
        }
        if !option.value().is_empty() {
            return Err(CrafterError::invalid_field_value(
                "coap.if-none-match",
                "If-None-Match value must be empty",
            ));
        }

        Ok(Self)
    }
}

macro_rules! define_uri_string_option {
    (
        $(#[$meta:meta])*
        $name:ident,
        number = $number:expr,
        field = $field:literal,
        wrong_number = $wrong_number:literal,
        min_length = $min_length:expr,
        length_error = $length_error:literal
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name {
            value: Vec<u8>,
        }

        impl $name {
            /// Build one typed occurrence from exact option value bytes.
            ///
            /// Construction is intentionally lossless and does not enforce
            /// semantic length or UTF-8 validity. Use `TryFrom<&CoapOption>`
            /// and [`Self::as_str`] when a checked typed view is required.
            pub fn new(value: impl AsRef<[u8]>) -> Self {
                Self {
                    value: value.as_ref().to_vec(),
                }
            }

            /// Borrow the exact option value bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.value
            }

            /// Consume the wrapper and return the exact option value bytes.
            pub fn into_bytes(self) -> Vec<u8> {
                self.value
            }

            /// Interpret the exact option value as UTF-8 without normalization.
            pub fn as_str(&self) -> Result<&str> {
                str::from_utf8(&self.value).map_err(|_| {
                    CrafterError::invalid_field_value(
                        $field,
                        "option value is not valid UTF-8",
                    )
                })
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::new(value)
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self::new(value)
            }
        }

        impl From<Vec<u8>> for $name {
            fn from(value: Vec<u8>) -> Self {
                Self { value }
            }
        }

        impl From<$name> for CoapOption {
            fn from(value: $name) -> Self {
                CoapOption::new($number, value.into_bytes())
            }
        }

        impl TryFrom<&CoapOption> for $name {
            type Error = CrafterError;

            fn try_from(option: &CoapOption) -> Result<Self> {
                if option.number().value() != $number {
                    return Err(CrafterError::invalid_field_value($field, $wrong_number));
                }

                if !($min_length..=255).contains(&option.value().len()) {
                    return Err(CrafterError::invalid_field_value($field, $length_error));
                }

                Ok(Self::new(option.value()))
            }
        }
    };
}

define_uri_string_option! {
    /// One RFC 7252 Uri-Host option value.
    ///
    /// The wrapper owns the exact wire bytes. It does not resolve names,
    /// lowercase a host, or otherwise perform URI processing.
    CoapUriHost,
    number = COAP_OPTION_URI_HOST,
    field = "coap.uri-host",
    wrong_number = "option number is not Uri-Host",
    min_length = 1,
    length_error = "Uri-Host length must be between 1 and 255 bytes"
}

define_uri_string_option! {
    /// One repeatable RFC 7252 Uri-Path segment.
    ///
    /// Empty segments are valid wire values. Dot-segment resolution and the
    /// semantic prohibition on `.` and `..` remain separate from this
    /// lossless packet wrapper.
    CoapUriPath,
    number = COAP_OPTION_URI_PATH,
    field = "coap.uri-path",
    wrong_number = "option number is not Uri-Path",
    min_length = 0,
    length_error = "Uri-Path length must not exceed 255 bytes"
}

define_uri_string_option! {
    /// One repeatable RFC 7252 Uri-Query argument.
    ///
    /// Empty arguments and exact UTF-8 or non-UTF-8 bytes remain owned and
    /// inspectable without treating the value as a form-encoded string.
    CoapUriQuery,
    number = COAP_OPTION_URI_QUERY,
    field = "coap.uri-query",
    wrong_number = "option number is not Uri-Query",
    min_length = 0,
    length_error = "Uri-Query length must not exceed 255 bytes"
}

define_uri_string_option! {
    /// One repeatable RFC 7252 Location-Path segment.
    ///
    /// Empty segments and exact binary bytes remain distinct occurrences.
    /// Resource storage and relative-reference resolution are caller concerns.
    CoapLocationPath,
    number = COAP_OPTION_LOCATION_PATH,
    field = "coap.location-path",
    wrong_number = "option number is not Location-Path",
    min_length = 0,
    length_error = "Location-Path length must not exceed 255 bytes"
}

define_uri_string_option! {
    /// One repeatable RFC 7252 Location-Query argument.
    ///
    /// Empty arguments and insertion order are preserved without parsing the
    /// returned resource location as a complete URI.
    CoapLocationQuery,
    number = COAP_OPTION_LOCATION_QUERY,
    field = "coap.location-query",
    wrong_number = "option number is not Location-Query",
    min_length = 0,
    length_error = "Location-Query length must not exceed 255 bytes"
}

/// One RFC 7252 Uri-Port option value with its exact uint representation.
///
/// Checked construction emits the canonical shortest network-byte-order
/// representation. A typed view of a decoded noncanonical zero-prefixed
/// value retains those original bytes for an exact conversion back to
/// [`CoapOption`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoapUriPort {
    value: u16,
    wire_value: Vec<u8>,
}

impl CoapUriPort {
    /// Build a Uri-Port value using the canonical shortest `uint` encoding.
    pub fn new(value: u16) -> Self {
        Self {
            value,
            wire_value: encode_coap_uint(u64::from(value)),
        }
    }

    /// Return the decoded transport-layer port number.
    pub const fn value(&self) -> u16 {
        self.value
    }

    /// Borrow the exact canonical or decoded option value bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire_value
    }

    /// Consume the wrapper and return the exact option value bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.wire_value
    }
}

impl From<u16> for CoapUriPort {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<CoapUriPort> for CoapOption {
    fn from(value: CoapUriPort) -> Self {
        CoapOption::new(COAP_OPTION_URI_PORT, value.into_bytes())
    }
}

impl TryFrom<&CoapOption> for CoapUriPort {
    type Error = CrafterError;

    fn try_from(option: &CoapOption) -> Result<Self> {
        if option.number().value() != COAP_OPTION_URI_PORT {
            return Err(CrafterError::invalid_field_value(
                "coap.uri-port",
                "option number is not Uri-Port",
            ));
        }
        let value = decode_coap_uint(
            option.value(),
            size_of::<u16>(),
            "coap.uri-port",
            "Uri-Port length must not exceed 2 bytes",
        )? as u16;
        Ok(Self {
            value,
            wire_value: option.value().to_vec(),
        })
    }
}

impl CoapUriPath {
    /// Split an already-resolved URI path into ordered Uri-Path occurrences.
    ///
    /// RFC 7252 Section 6.4 splits before resolving percent-encodings, so an
    /// encoded slash remains inside its segment. An empty path and `/` yield
    /// no occurrences; other empty segments, including a trailing segment,
    /// are preserved. This helper accepts an optional leading slash but does
    /// not parse a complete URI or resolve dot segments.
    pub fn split(path: impl AsRef<[u8]>) -> Result<Vec<Self>> {
        let path = path.as_ref();
        if path.is_empty() || path == b"/" {
            return Ok(Vec::new());
        }

        let segments = path.strip_prefix(b"/").unwrap_or(path);
        segments
            .split(|byte| *byte == b'/')
            .map(|segment| {
                decode_percent_encoded_uri_component(segment, "coap.uri-path.percent-encoding")
                    .map(Self::from)
            })
            .collect()
    }
}

impl CoapUriQuery {
    /// Split a URI query component into ordered Uri-Query occurrences.
    ///
    /// RFC 7252 Section 6.4 splits on `&` before resolving percent-encodings,
    /// preserving encoded ampersands within an argument. A leading `?` is
    /// accepted for convenience. Empty arguments are retained and `+` is not
    /// treated as form-encoded whitespace.
    pub fn split(query: impl AsRef<[u8]>) -> Result<Vec<Self>> {
        let query = query.as_ref();
        let arguments = query.strip_prefix(b"?").unwrap_or(query);
        arguments
            .split(|byte| *byte == b'&')
            .map(|argument| {
                decode_percent_encoded_uri_component(argument, "coap.uri-query.percent-encoding")
                    .map(Self::from)
            })
            .collect()
    }
}

fn decode_percent_encoded_uri_component(input: &[u8], field: &'static str) -> Result<Vec<u8>> {
    let mut decoded = Vec::with_capacity(input.len());
    let mut cursor = 0;

    while cursor < input.len() {
        if input[cursor] != b'%' {
            decoded.push(input[cursor]);
            cursor += 1;
            continue;
        }

        let encoded = input.get(cursor + 1..cursor + 3).ok_or_else(|| {
            CrafterError::invalid_field_value(field, "incomplete percent-encoding")
        })?;
        let high = decode_hex_digit(encoded[0]).ok_or_else(|| {
            CrafterError::invalid_field_value(
                field,
                "percent-encoding contains a non-hexadecimal digit",
            )
        })?;
        let low = decode_hex_digit(encoded[1]).ok_or_else(|| {
            CrafterError::invalid_field_value(
                field,
                "percent-encoding contains a non-hexadecimal digit",
            )
        })?;
        decoded.push((high << 4) | low);
        cursor += 3;
    }

    Ok(decoded)
}

const fn decode_hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

/// An ordered collection of CoAP option occurrences.
///
/// Insertion and decoded wire order are preserved, including duplicates and
/// out-of-order numbers. Canonical numeric ordering happens only through an
/// explicit sorting method.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoapOptions {
    options: Vec<CoapOption>,
}

impl CoapOptions {
    /// Create an empty ordered option collection.
    pub const fn new() -> Self {
        Self {
            options: Vec::new(),
        }
    }

    /// Build a collection from occurrences in caller-provided order.
    pub fn from_options(options: impl IntoIterator<Item = CoapOption>) -> Self {
        options.into_iter().collect()
    }

    /// Append an occurrence and return the collection for builder chaining.
    pub fn push(mut self, option: CoapOption) -> Self {
        self.options.push(option);
        self
    }

    /// Append an occurrence in place.
    pub fn add(&mut self, option: CoapOption) {
        self.options.push(option);
    }

    /// Borrow all occurrences in their current order.
    pub fn options(&self) -> &[CoapOption] {
        &self.options
    }

    /// Borrow all occurrences in their current order.
    pub fn as_slice(&self) -> &[CoapOption] {
        self.options()
    }

    /// Consume the collection and return occurrences in their current order.
    pub fn into_options(self) -> Vec<CoapOption> {
        self.options
    }

    /// Consume the collection and return occurrences in their current order.
    pub fn into_vec(self) -> Vec<CoapOption> {
        self.into_options()
    }

    /// Return the number of option occurrences, including duplicates.
    pub fn len(&self) -> usize {
        self.options.len()
    }

    /// Return true when no option occurrences are present.
    pub fn is_empty(&self) -> bool {
        self.options.is_empty()
    }

    /// Iterate over occurrences in their current order.
    pub fn iter(&self) -> core::slice::Iter<'_, CoapOption> {
        self.options.iter()
    }

    /// Iterate mutably over occurrences in their current order.
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, CoapOption> {
        self.options.iter_mut()
    }

    /// Stably sort occurrences by option number for requested canonical order.
    ///
    /// Stable sorting preserves the relative order of repeated options.
    pub fn sort_canonical(&mut self) {
        self.options.sort_by_key(CoapOption::number);
    }

    /// Consume the collection and return it in stable canonical number order.
    pub fn into_canonical_order(mut self) -> Self {
        self.sort_canonical();
        self
    }
}

impl From<Vec<CoapOption>> for CoapOptions {
    fn from(options: Vec<CoapOption>) -> Self {
        Self { options }
    }
}

impl From<CoapOptions> for Vec<CoapOption> {
    fn from(options: CoapOptions) -> Self {
        options.into_options()
    }
}

impl FromIterator<CoapOption> for CoapOptions {
    fn from_iter<I: IntoIterator<Item = CoapOption>>(iter: I) -> Self {
        Self {
            options: iter.into_iter().collect(),
        }
    }
}

impl Extend<CoapOption> for CoapOptions {
    fn extend<I: IntoIterator<Item = CoapOption>>(&mut self, iter: I) {
        self.options.extend(iter);
    }
}

impl IntoIterator for CoapOptions {
    type Item = CoapOption;
    type IntoIter = std::vec::IntoIter<CoapOption>;

    fn into_iter(self) -> Self::IntoIter {
        self.options.into_iter()
    }
}

impl<'a> IntoIterator for &'a CoapOptions {
    type Item = &'a CoapOption;
    type IntoIter = core::slice::Iter<'a, CoapOption>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut CoapOptions {
    type Item = &'a mut CoapOption;
    type IntoIter = core::slice::IterMut<'a, CoapOption>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

/// One decoded option sequence and its boundary within the input slice.
///
/// `consumed` counts only option bytes. When `payload_marker` is true, the
/// marker is the next byte in the original input and remains available to the
/// enclosing message decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DecodedOptionSequence {
    pub(super) options: CoapOptions,
    pub(super) consumed: usize,
    pub(super) payload_marker: bool,
}

/// Append an ordered option sequence and return its encoded byte count.
///
/// Unset encodings derive canonical deltas from the caller's typed order.
/// Explicit logical delta or exact-header overrides remain authoritative,
/// even when they deliberately describe a different or malformed wire
/// sequence. The output is changed only after the entire sequence encodes.
pub(super) fn encode_option_sequence(options: &CoapOptions, out: &mut Vec<u8>) -> Result<usize> {
    let mut encoded = Vec::new();
    let mut previous_number = 0u16;

    for option in options {
        let number = option.number().value();
        let encoding = option.encoding();
        let has_delta_override = encoding.is_some_and(|encoding| {
            encoding.raw_bytes().is_some() || encoding.wire_delta().is_some()
        });

        let delta = match number.checked_sub(previous_number) {
            Some(delta) => u32::from(delta),
            None if has_delta_override => 0,
            None => {
                return Err(CrafterError::invalid_field_value(
                    "coap.option-order",
                    "canonical option numbers must be nondecreasing",
                ));
            }
        };

        if !has_delta_override {
            let cumulative = u32::from(previous_number)
                .checked_add(delta)
                .and_then(|value| u16::try_from(value).ok())
                .ok_or_else(|| {
                    CrafterError::invalid_field_value(
                        "coap.option-number",
                        "cumulative option number exceeds 65535",
                    )
                })?;
            if cumulative != number {
                return Err(CrafterError::invalid_field_value(
                    "coap.option-order",
                    "canonical option numbers must be nondecreasing",
                ));
            }
        }

        encode_option_header(delta, option.value().len(), encoding, &mut encoded)?;
        encoded.extend_from_slice(option.value());
        previous_number = number;
    }

    let encoded_len = encoded.len();
    out.extend_from_slice(&encoded);
    Ok(encoded_len)
}

/// Decode options until input exhaustion or a payload marker boundary.
///
/// Unknown numbers, repeated occurrences, raw header bytes, and opaque values
/// are preserved exactly. A marker is recognized only where the next option
/// header would begin; marker-valued extension or option bytes are never
/// searched for or treated specially.
pub(super) fn decode_option_sequence(bytes: &[u8]) -> Result<DecodedOptionSequence> {
    let mut options = CoapOptions::new();
    let mut cursor = 0usize;
    let mut previous_number = 0u16;

    while cursor < bytes.len() {
        let remaining = bytes.get(cursor..).unwrap_or_default();
        if remaining.first() == Some(&COAP_PAYLOAD_MARKER) {
            return Ok(DecodedOptionSequence {
                options,
                consumed: cursor,
                payload_marker: true,
            });
        }

        let header = decode_option_header(remaining)?;
        let number = u32::from(previous_number)
            .checked_add(header.delta)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "coap.option-number",
                    "cumulative option number exceeds 65535",
                )
            })?;

        let value_bytes = remaining.get(header.consumed..).unwrap_or_default();
        let value = value_bytes.get(..header.length).ok_or_else(|| {
            CrafterError::buffer_too_short("coap.option.value", header.length, value_bytes.len())
        })?;
        let option_len = header.consumed.checked_add(header.length).ok_or_else(|| {
            CrafterError::invalid_field_value(
                "coap.option.length",
                "option sequence cursor overflow",
            )
        })?;
        let raw_header = remaining
            .get(..header.consumed)
            .ok_or_else(|| {
                CrafterError::buffer_too_short(
                    "coap.option.header",
                    header.consumed,
                    remaining.len(),
                )
            })?
            .to_vec();

        let encoding =
            CoapOptionEncoding::explicit(header.delta, header.length).with_raw_bytes(raw_header);
        options.add(CoapOption::new(number, value.to_vec()).with_encoding(encoding));
        cursor = cursor.checked_add(option_len).ok_or_else(|| {
            CrafterError::invalid_field_value(
                "coap.option.length",
                "option sequence cursor overflow",
            )
        })?;
        previous_number = number;
    }

    Ok(DecodedOptionSequence {
        options,
        consumed: cursor,
        payload_marker: false,
    })
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

    #[test]
    fn option_occurrences_preserve_duplicates_empty_values_and_order() {
        let options = CoapOptions::new()
            .push(CoapOption::new(COAP_OPTION_URI_PATH, b"sensors".to_vec()))
            .push(CoapOption::new(COAP_OPTION_IF_NONE_MATCH, Vec::new()))
            .push(CoapOption::new(
                COAP_OPTION_URI_PATH,
                b"temperature".to_vec(),
            ))
            .push(CoapOption::new(65001u16, vec![0xde, 0xad]));

        let numbers: Vec<_> = options
            .iter()
            .map(|option| option.number().value())
            .collect();
        assert_eq!(numbers, vec![11, 5, 11, 65001]);
        assert_eq!(options.len(), 4);
        assert_eq!(options.options()[1].value(), b"");
        assert_eq!(options.options()[1].format(), CoapOptionFormat::Empty);
        assert_eq!(options.options()[3].value(), [0xde, 0xad]);
        assert_eq!(
            options.options()[3].registry_meta().status,
            CoapRegistryStatus::Experimental
        );
    }

    #[test]
    fn canonical_sort_is_explicit_stable_and_ownership_preserving() {
        let options = CoapOptions::from_options([
            CoapOption::new(11u16, b"first".to_vec()),
            CoapOption::new(5u16, Vec::new()),
            CoapOption::new(11u16, b"second".to_vec()),
        ]);

        assert_eq!(options.options()[0].value(), b"first");

        let sorted = options.into_canonical_order().into_options();
        assert_eq!(sorted[0].number().value(), 5);
        assert_eq!(sorted[1].value(), b"first");
        assert_eq!(sorted[2].value(), b"second");
    }

    #[test]
    fn typed_views_do_not_change_opaque_bytes() {
        let empty = CoapOption::new(COAP_OPTION_MAX_AGE, Vec::new());
        assert_eq!(empty.as_uint(), Ok(0));
        assert_eq!(empty.value(), b"");

        let noncanonical = CoapOption::new(COAP_OPTION_MAX_AGE, vec![0, 1]);
        assert_eq!(noncanonical.as_uint(), Ok(1));
        assert_eq!(noncanonical.value(), [0, 1]);

        let text = CoapOption::from_string(COAP_OPTION_URI_PATH, "temperatura");
        assert_eq!(text.as_str(), Ok("temperatura"));
        assert_eq!(text.as_opaque(), Ok("temperatura".as_bytes()));

        let binary = CoapOption::new(COAP_OPTION_ETAG, vec![0xff, 0x00]);
        assert_eq!(
            binary.as_str(),
            Err(CrafterError::InvalidFieldValue {
                field: "coap.option.string",
                reason: "option value is not valid UTF-8",
            })
        );
        assert_eq!(binary.value(), [0xff, 0x00]);

        let too_wide = CoapOption::new(65002u16, vec![0; 9]);
        assert_eq!(
            too_wide.as_uint(),
            Err(CrafterError::InvalidFieldValue {
                field: "coap.option.uint",
                reason: "unsigned option value exceeds 64 bits",
            })
        );
        assert_eq!(too_wide.into_bytes(), vec![0; 9]);
    }

    #[test]
    fn representation_uint_wrappers_cover_zero_and_multibyte_boundaries() {
        let content_format_cases = [
            (0, Vec::new()),
            (u8::MAX as u16, vec![0xff]),
            (u8::MAX as u16 + 1, vec![0x01, 0x00]),
            (u16::MAX, vec![0xff, 0xff]),
        ];
        for (value, expected) in content_format_cases {
            let content_format = CoapContentFormat::new(value);
            assert_eq!(content_format.value(), value);
            assert_eq!(content_format.as_bytes(), expected);

            let option = CoapOption::from(content_format);
            assert_eq!(option.number().value(), COAP_OPTION_CONTENT_FORMAT);
            assert_eq!(option.value(), expected);
            assert_eq!(CoapContentFormat::try_from(&option).unwrap().value(), value);
        }

        let wide_cases = [
            (0, Vec::new()),
            (u8::MAX as u32, vec![0xff]),
            (u8::MAX as u32 + 1, vec![0x01, 0x00]),
            (u16::MAX as u32 + 1, vec![0x01, 0x00, 0x00]),
            (u32::MAX, vec![0xff, 0xff, 0xff, 0xff]),
        ];
        for (value, expected) in wide_cases {
            assert_eq!(CoapMaxAge::new(value).as_bytes(), expected);
            assert_eq!(CoapSize1::new(value).as_bytes(), expected);
            assert_eq!(CoapSize2::new(value).as_bytes(), expected);
        }
    }

    #[test]
    fn content_format_wrappers_keep_open_registry_metadata() {
        let assigned = CoapContentFormat::new(0).registry_meta();
        assert_eq!(assigned.label, "text/plain; charset=utf-8");
        assert_eq!(assigned.status, CoapRegistryStatus::Assigned);

        let unknown = CoapContentFormat::new(1).registry_meta();
        assert_eq!(unknown.value, 1);
        assert_eq!(unknown.label, "content-format-1");
        assert_eq!(unknown.status, CoapRegistryStatus::Unassigned);

        let accepted = CoapAccept::new(65_535);
        assert_eq!(accepted.value(), 65_535);
        assert_eq!(
            accepted.registry_meta().status,
            CoapRegistryStatus::Experimental
        );
    }

    #[test]
    fn representation_wrappers_preserve_noncanonical_raw_values() {
        let content_option = CoapOption::new(COAP_OPTION_CONTENT_FORMAT, [0x00, 0x2a]);
        let content_format = CoapContentFormat::try_from(&content_option).unwrap();
        assert_eq!(content_format.value(), 42);
        assert_eq!(content_format.as_bytes(), [0x00, 0x2a]);
        assert_eq!(CoapOption::from(content_format).value(), [0x00, 0x2a]);

        let accept_option = CoapOption::new(COAP_OPTION_ACCEPT, [0x00, 0x01]);
        let accept = CoapAccept::try_from(&accept_option).unwrap();
        assert_eq!(accept.value(), 1);
        assert_eq!(CoapOption::from(accept).value(), [0x00, 0x01]);

        let max_age_option = CoapOption::new(COAP_OPTION_MAX_AGE, [0, 0, 0, 60]);
        let max_age = CoapMaxAge::try_from(&max_age_option).unwrap();
        assert_eq!(max_age.value(), 60);
        assert_eq!(CoapOption::from(max_age).value(), [0, 0, 0, 60]);

        for option in [
            CoapOption::new(COAP_OPTION_SIZE1, [0, 0, 1, 0]),
            CoapOption::new(COAP_OPTION_SIZE2, [0, 0, 1, 0]),
        ] {
            let rebuilt = if option.number().value() == COAP_OPTION_SIZE1 {
                CoapOption::from(CoapSize1::try_from(&option).unwrap())
            } else {
                CoapOption::from(CoapSize2::try_from(&option).unwrap())
            };
            assert_eq!(rebuilt.value(), option.value());
        }
    }

    #[test]
    fn max_age_default_is_an_explicit_interpretation_helper() {
        assert_eq!(CoapMaxAge::effective_response_seconds(None), 60);

        let explicit = CoapMaxAge::new(0);
        assert_eq!(CoapMaxAge::effective_response_seconds(Some(&explicit)), 0);

        let message =
            crate::protocols::coap::Coap::response(crate::protocols::coap::CoapCode::content());
        assert!(message.options_value().is_empty());
    }

    #[test]
    fn representation_message_helpers_append_exact_typed_options() {
        let message =
            crate::protocols::coap::Coap::request(crate::protocols::coap::CoapCode::get())
                .content_format(CoapContentFormat::new(50))
                .accept(CoapAccept::new(60))
                .content_format(CoapContentFormat::new(42));

        assert_eq!(message.options_value().len(), 3);
        assert_eq!(message.options_value()[0].number().value(), 12);
        assert_eq!(message.options_value()[0].value(), [50]);
        assert_eq!(message.options_value()[1].number().value(), 17);
        assert_eq!(message.options_value()[1].value(), [60]);
        assert_eq!(message.options_value()[2].number().value(), 12);
        assert_eq!(message.options_value()[2].value(), [42]);
    }

    #[test]
    fn location_wrappers_preserve_empty_binary_and_malformed_occurrences() {
        let empty_path = CoapLocationPath::new("");
        let empty_option = CoapOption::from(empty_path.clone());
        assert_eq!(empty_option.number().value(), COAP_OPTION_LOCATION_PATH);
        assert_eq!(empty_option.value(), b"");
        assert_eq!(CoapLocationPath::try_from(&empty_option), Ok(empty_path));

        let binary_query = CoapOption::new(COAP_OPTION_LOCATION_QUERY, [0xff, 0x00]);
        let query = CoapLocationQuery::try_from(&binary_query).unwrap();
        assert_eq!(query.as_bytes(), [0xff, 0x00]);
        assert_eq!(
            query.as_str(),
            Err(CrafterError::invalid_field_value(
                "coap.location-query",
                "option value is not valid UTF-8",
            ))
        );
        assert_eq!(binary_query.value(), [0xff, 0x00]);

        let oversized = CoapOption::new(COAP_OPTION_LOCATION_PATH, vec![b'x'; 256]);
        assert_eq!(
            CoapLocationPath::try_from(&oversized),
            Err(CrafterError::invalid_field_value(
                "coap.location-path",
                "Location-Path length must not exceed 255 bytes",
            ))
        );
        assert_eq!(oversized.value().len(), 256);
    }

    #[test]
    fn location_and_size_helpers_preserve_number_order_and_components() {
        let response =
            crate::protocols::coap::Coap::response(crate::protocols::coap::CoapCode::created())
                .location_path("jobs")
                .location_path("")
                .location_path("42")
                .location_query("view=full")
                .location_query("")
                .size2(CoapSize2::new(0))
                .size1(CoapSize1::new(u32::MAX));

        let options = response.options_value();
        assert_eq!(
            options
                .iter()
                .map(|option| option.number().value())
                .collect::<Vec<_>>(),
            vec![8, 8, 8, 20, 20, 28, 60]
        );
        assert_eq!(
            response
                .location_paths()
                .map(|value| value.unwrap().into_bytes())
                .collect::<Vec<_>>(),
            vec![b"jobs".to_vec(), Vec::new(), b"42".to_vec()]
        );
        assert_eq!(
            response
                .location_queries()
                .map(|value| value.unwrap().into_bytes())
                .collect::<Vec<_>>(),
            vec![b"view=full".to_vec(), Vec::new()]
        );
        assert_eq!(options[5].value(), b"");
        assert_eq!(options[6].value(), [0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn size_helpers_check_platform_values_and_preserve_malformed_raw_bytes() {
        let payload_len = 65_536usize;
        let size1 = CoapSize1::try_from(payload_len).unwrap();
        let size2 = CoapSize2::try_from_usize(payload_len).unwrap();
        assert_eq!(size1.value(), 65_536);
        assert_eq!(size1.as_bytes(), [0x01, 0x00, 0x00]);
        assert_eq!(size1.try_to_usize(), Ok(payload_len));
        assert_eq!(usize::try_from(&size2), Ok(payload_len));

        #[cfg(target_pointer_width = "64")]
        {
            let oversized = u32::MAX as usize + 1;
            assert_eq!(
                CoapSize1::try_from_usize(oversized),
                Err(CrafterError::invalid_field_value(
                    "coap.size1",
                    "Size1 value exceeds the four-byte CoAP uint range",
                ))
            );
            assert_eq!(
                CoapSize2::try_from(oversized),
                Err(CrafterError::invalid_field_value(
                    "coap.size2",
                    "Size2 value exceeds the four-byte CoAP uint range",
                ))
            );
        }

        for (number, field, reason) in [
            (
                COAP_OPTION_SIZE1,
                "coap.size1",
                "Size1 length must not exceed 4 bytes",
            ),
            (
                COAP_OPTION_SIZE2,
                "coap.size2",
                "Size2 length must not exceed 4 bytes",
            ),
        ] {
            let malformed = CoapOption::new(number, [0, 0, 0, 0, 1]);
            let error = if number == COAP_OPTION_SIZE1 {
                CoapSize1::try_from(&malformed).unwrap_err()
            } else {
                CoapSize2::try_from(&malformed).unwrap_err()
            };
            assert_eq!(error, CrafterError::invalid_field_value(field, reason));
            assert_eq!(malformed.value(), [0, 0, 0, 0, 1]);
        }
    }

    #[test]
    fn uri_wrappers_construct_and_inspect_exact_option_values() {
        let host = CoapUriHost::new("münchen.example");
        let host_option = CoapOption::from(host.clone());
        assert_eq!(host_option.number().value(), COAP_OPTION_URI_HOST);
        assert_eq!(host_option.value(), "münchen.example".as_bytes());
        assert_eq!(CoapUriHost::try_from(&host_option), Ok(host));

        let empty_path = CoapUriPath::new(b"");
        let empty_path_option = CoapOption::from(empty_path.clone());
        assert_eq!(empty_path_option.number().value(), COAP_OPTION_URI_PATH);
        assert_eq!(empty_path_option.value(), b"");
        assert_eq!(CoapUriPath::try_from(&empty_path_option), Ok(empty_path));

        let query = CoapUriQuery::new("city=Zürich");
        let query_option = CoapOption::from(query.clone());
        assert_eq!(query_option.number().value(), COAP_OPTION_URI_QUERY);
        assert_eq!(query_option.value(), "city=Zürich".as_bytes());
        assert_eq!(CoapUriQuery::try_from(&query_option), Ok(query));

        let port_cases = [
            (0, Vec::new()),
            (u8::MAX as u16, vec![u8::MAX]),
            (u8::MAX as u16 + 1, vec![1, 0]),
            (u16::MAX, vec![u8::MAX, u8::MAX]),
        ];
        for (value, expected_bytes) in port_cases {
            let port = CoapUriPort::new(value);
            assert_eq!(port.value(), value);
            assert_eq!(port.as_bytes(), expected_bytes);

            let option = CoapOption::from(port);
            assert_eq!(option.number().value(), COAP_OPTION_URI_PORT);
            assert_eq!(option.value(), expected_bytes);
            assert_eq!(CoapUriPort::try_from(&option).unwrap().value(), value);
        }

        let noncanonical_port = CoapOption::new(COAP_OPTION_URI_PORT, [0, 1]);
        let port = CoapUriPort::try_from(&noncanonical_port).unwrap();
        assert_eq!(port.value(), 1);
        assert_eq!(port.as_bytes(), [0, 1]);
        assert_eq!(CoapOption::from(port).value(), [0, 1]);
    }

    #[test]
    fn uri_typed_view_failures_leave_opaque_options_unchanged() {
        let invalid_utf8 = CoapOption::new(COAP_OPTION_URI_PATH, [0xff, 0x00]);
        let typed = CoapUriPath::try_from(&invalid_utf8).unwrap();
        assert_eq!(typed.as_bytes(), [0xff, 0x00]);
        assert_eq!(
            typed.as_str(),
            Err(CrafterError::invalid_field_value(
                "coap.uri-path",
                "option value is not valid UTF-8",
            ))
        );
        assert_eq!(invalid_utf8.value(), [0xff, 0x00]);

        let wrong_number = CoapOption::new(COAP_OPTION_URI_QUERY, b"host".to_vec());
        assert_eq!(
            CoapUriHost::try_from(&wrong_number),
            Err(CrafterError::invalid_field_value(
                "coap.uri-host",
                "option number is not Uri-Host",
            ))
        );
        assert_eq!(wrong_number.value(), b"host");

        let empty_host = CoapOption::new(COAP_OPTION_URI_HOST, Vec::new());
        assert_eq!(
            CoapUriHost::try_from(&empty_host),
            Err(CrafterError::invalid_field_value(
                "coap.uri-host",
                "Uri-Host length must be between 1 and 255 bytes",
            ))
        );
        assert_eq!(empty_host.value(), b"");

        let oversized_path = CoapOption::new(COAP_OPTION_URI_PATH, vec![b'x'; 256]);
        assert_eq!(
            CoapUriPath::try_from(&oversized_path),
            Err(CrafterError::invalid_field_value(
                "coap.uri-path",
                "Uri-Path length must not exceed 255 bytes",
            ))
        );
        assert_eq!(oversized_path.value().len(), 256);

        let oversized_port = CoapOption::new(COAP_OPTION_URI_PORT, [0, 1, 2]);
        assert_eq!(
            CoapUriPort::try_from(&oversized_port),
            Err(CrafterError::invalid_field_value(
                "coap.uri-port",
                "Uri-Port length must not exceed 2 bytes",
            ))
        );
        assert_eq!(oversized_port.value(), [0, 1, 2]);
    }

    #[test]
    fn uri_path_split_preserves_empty_unicode_and_encoded_segments() {
        let path = CoapUriPath::split("/sensors//caf%C3%A9/%2F/").unwrap();
        let values: Vec<_> = path.iter().map(CoapUriPath::as_bytes).collect();
        assert_eq!(
            values,
            vec![
                b"sensors".as_slice(),
                b"".as_slice(),
                "café".as_bytes(),
                b"/".as_slice(),
                b"".as_slice(),
            ]
        );
        assert!(CoapUriPath::split("").unwrap().is_empty());
        assert!(CoapUriPath::split("/").unwrap().is_empty());

        let unresolved = CoapUriPath::split("/./../status").unwrap();
        assert_eq!(unresolved[0].as_bytes(), b".");
        assert_eq!(unresolved[1].as_bytes(), b"..");
        assert_eq!(unresolved[2].as_bytes(), b"status");

        assert_eq!(
            CoapUriPath::split("/bad/%2"),
            Err(CrafterError::invalid_field_value(
                "coap.uri-path.percent-encoding",
                "incomplete percent-encoding",
            ))
        );
    }

    #[test]
    fn uri_query_split_preserves_empty_arguments_and_decodes_after_splitting() {
        let query = CoapUriQuery::split("?a=1&&city=Z%C3%BCrich&literal=%26&plus=a+b").unwrap();
        let values: Vec<_> = query.iter().map(CoapUriQuery::as_bytes).collect();
        assert_eq!(
            values,
            vec![
                b"a=1".as_slice(),
                b"".as_slice(),
                "city=Zürich".as_bytes(),
                b"literal=&".as_slice(),
                b"plus=a+b".as_slice(),
            ]
        );
        assert_eq!(
            CoapUriQuery::split("").unwrap()[0].as_bytes(),
            b"".as_slice()
        );

        let binary = CoapUriQuery::split("raw=%FF").unwrap();
        assert_eq!(binary[0].as_bytes(), [b'r', b'a', b'w', b'=', 0xff]);
        assert!(binary[0].as_str().is_err());

        assert_eq!(
            CoapUriQuery::split("bad=%GG"),
            Err(CrafterError::invalid_field_value(
                "coap.uri-query.percent-encoding",
                "percent-encoding contains a non-hexadecimal digit",
            ))
        );
    }

    #[test]
    fn uri_options_keep_repeat_order_and_round_trip_exactly() {
        let options = CoapOptions::from_options([
            CoapOption::from(CoapUriHost::new("example.com")),
            CoapOption::from(CoapUriPort::new(5683)),
            CoapOption::from(CoapUriPath::new("sensors")),
            CoapOption::from(CoapUriPath::new("")),
            CoapOption::from(CoapUriQuery::new("units=c")),
            CoapOption::from(CoapUriQuery::new("raw=&")),
        ]);

        let mut encoded = Vec::new();
        encode_option_sequence(&options, &mut encoded).unwrap();
        let expected = [
            0x3b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x42, 0x16,
            0x33, 0x47, b's', b'e', b'n', b's', b'o', b'r', b's', 0x00, 0x47, b'u', b'n', b'i',
            b't', b's', b'=', b'c', 0x05, b'r', b'a', b'w', b'=', b'&',
        ];
        assert_eq!(encoded, expected);

        let decoded = decode_option_sequence(&encoded).unwrap();
        let decoded_options = decoded.options.options();
        assert_eq!(
            CoapUriHost::try_from(&decoded_options[0]).unwrap().as_str(),
            Ok("example.com")
        );
        assert_eq!(
            CoapUriPort::try_from(&decoded_options[1]).unwrap().value(),
            5683
        );
        assert_eq!(
            CoapUriPath::try_from(&decoded_options[2]).unwrap().as_str(),
            Ok("sensors")
        );
        assert_eq!(
            CoapUriPath::try_from(&decoded_options[3]).unwrap().as_str(),
            Ok("")
        );
        assert_eq!(
            CoapUriQuery::try_from(&decoded_options[4])
                .unwrap()
                .as_str(),
            Ok("units=c")
        );
        assert_eq!(
            CoapUriQuery::try_from(&decoded_options[5])
                .unwrap()
                .as_str(),
            Ok("raw=&")
        );

        let rebuilt = CoapOptions::from_options([
            CoapOption::from(CoapUriHost::try_from(&decoded_options[0]).unwrap()),
            CoapOption::from(CoapUriPort::try_from(&decoded_options[1]).unwrap()),
            CoapOption::from(CoapUriPath::try_from(&decoded_options[2]).unwrap()),
            CoapOption::from(CoapUriPath::try_from(&decoded_options[3]).unwrap()),
            CoapOption::from(CoapUriQuery::try_from(&decoded_options[4]).unwrap()),
            CoapOption::from(CoapUriQuery::try_from(&decoded_options[5]).unwrap()),
        ]);
        let mut reencoded = Vec::new();
        encode_option_sequence(&rebuilt, &mut reencoded).unwrap();
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn coap_uri_builder_methods_append_typed_occurrences() {
        let message = crate::protocols::coap::Coap::get()
            .uri_host("example.com")
            .uri_port(5683)
            .uri_path("sensors")
            .uri_path("")
            .uri_query("units=c")
            .uri_query("format=json");

        let options = message.options_value();
        assert_eq!(options.len(), 6);
        assert_eq!(options[0].number().value(), COAP_OPTION_URI_HOST);
        assert_eq!(options[1].number().value(), COAP_OPTION_URI_PORT);
        assert_eq!(options[2].number().value(), COAP_OPTION_URI_PATH);
        assert_eq!(options[3].number().value(), COAP_OPTION_URI_PATH);
        assert_eq!(options[4].number().value(), COAP_OPTION_URI_QUERY);
        assert_eq!(options[5].number().value(), COAP_OPTION_URI_QUERY);
    }

    #[test]
    fn conditional_wrappers_check_boundaries_and_preserve_binary_values() {
        let wildcard = CoapIfMatch::any();
        assert!(wildcard.is_any());
        assert_eq!(wildcard.validate(), Ok(()));
        assert_eq!(wildcard.as_bytes(), b"");

        let if_match = CoapIfMatch::try_new([0x00, 0xff, 0x80, 1, 2, 3, 4, 5]).unwrap();
        assert!(!if_match.is_any());
        assert_eq!(if_match.as_bytes(), [0x00, 0xff, 0x80, 1, 2, 3, 4, 5]);
        assert_eq!(
            CoapIfMatch::try_new([0u8; 9]),
            Err(CrafterError::invalid_field_value(
                "coap.if-match",
                "If-Match length must not exceed 8 bytes",
            ))
        );

        for value in [vec![0xff], vec![0x00, 1, 2, 3, 4, 5, 6, 0xff]] {
            let etag = CoapEtag::try_new(&value).unwrap();
            assert_eq!(etag.as_bytes(), value);
        }
        assert_eq!(
            CoapEtag::try_new([]),
            Err(CrafterError::invalid_field_value(
                "coap.etag",
                "ETag length must be between 1 and 8 bytes",
            ))
        );
        assert_eq!(
            CoapEtag::try_new([0u8; 9]),
            Err(CrafterError::invalid_field_value(
                "coap.etag",
                "ETag length must be between 1 and 8 bytes",
            ))
        );

        let if_none_match = CoapIfNoneMatch::new();
        assert_eq!(if_none_match.as_bytes(), b"");
        let option = CoapOption::from(if_none_match);
        assert_eq!(option.number().value(), COAP_OPTION_IF_NONE_MATCH);
        assert_eq!(option.value(), b"");
        assert_eq!(CoapIfNoneMatch::try_from(&option), Ok(if_none_match));
    }

    #[test]
    fn conditional_comparisons_are_exact_byte_equality_only() {
        let etag = CoapEtag::try_new([0xde, 0xad]).unwrap();
        let same = CoapIfMatch::try_new([0xde, 0xad]).unwrap();
        let different = CoapIfMatch::try_new([0xde, 0xae]).unwrap();
        let wildcard = CoapIfMatch::any();

        assert!(etag.matches_bytes([0xde, 0xad]));
        assert!(etag.matches_if_match(&same));
        assert!(same.matches_etag(&etag));
        assert!(!different.matches_etag(&etag));
        assert!(wildcard.is_any());
        assert!(!wildcard.matches_etag(&etag));
    }

    #[test]
    fn conditional_options_and_builders_preserve_repeated_occurrences() {
        let message = crate::protocols::coap::Coap::get()
            .etag(vec![0x01])
            .etag(vec![0x02, 0x03])
            .if_match(vec![0x01])
            .if_match(CoapIfMatch::any())
            .if_none_match();

        let options = message.options_value();
        let numbers: Vec<_> = options
            .iter()
            .map(|option| option.number().value())
            .collect();
        assert_eq!(
            numbers,
            [
                COAP_OPTION_ETAG,
                COAP_OPTION_ETAG,
                COAP_OPTION_IF_MATCH,
                COAP_OPTION_IF_MATCH,
                COAP_OPTION_IF_NONE_MATCH,
            ]
        );
        assert_eq!(options[0].value(), [0x01]);
        assert_eq!(options[1].value(), [0x02, 0x03]);
        assert_eq!(options[2].value(), [0x01]);
        assert_eq!(options[3].value(), b"");
        assert_eq!(options[4].value(), b"");
    }

    #[test]
    fn malformed_conditional_raw_options_remain_lossless_and_encodable() {
        let oversized_if_match = CoapOption::new(COAP_OPTION_IF_MATCH, vec![0x80; 9]);
        assert_eq!(
            CoapIfMatch::try_from(&oversized_if_match),
            Err(CrafterError::invalid_field_value(
                "coap.if-match",
                "If-Match length must not exceed 8 bytes",
            ))
        );
        assert_eq!(oversized_if_match.value(), [0x80; 9]);

        let empty_etag = CoapOption::new(COAP_OPTION_ETAG, Vec::new());
        assert_eq!(
            CoapEtag::try_from(&empty_etag),
            Err(CrafterError::invalid_field_value(
                "coap.etag",
                "ETag length must be between 1 and 8 bytes",
            ))
        );
        assert_eq!(empty_etag.value(), b"");

        let nonempty_if_none_match =
            CoapOption::new(COAP_OPTION_IF_NONE_MATCH, [0xff]).with_wire_length(0);
        assert_eq!(
            CoapIfNoneMatch::try_from(&nonempty_if_none_match),
            Err(CrafterError::invalid_field_value(
                "coap.if-none-match",
                "If-None-Match value must be empty",
            ))
        );
        assert_eq!(nonempty_if_none_match.value(), [0xff]);
        assert_eq!(
            nonempty_if_none_match
                .encoding()
                .and_then(CoapOptionEncoding::wire_length),
            Some(0)
        );

        let malformed =
            CoapOptions::from_options([oversized_if_match, empty_etag, nonempty_if_none_match]);
        let mut encoded = Vec::new();
        encode_option_sequence(&malformed, &mut encoded).unwrap();
        assert_eq!(
            encoded,
            [0x19, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x30, 0x10, 0xff,]
        );
    }

    #[test]
    fn explicit_wire_overrides_are_independent_from_semantic_values() {
        let option = CoapOption::new(COAP_OPTION_URI_PATH, b"status".to_vec())
            .with_wire_delta(65804)
            .with_wire_length(1);

        assert_eq!(option.number().value(), COAP_OPTION_URI_PATH);
        assert_eq!(option.value(), b"status");
        assert_eq!(option.encoding_state(), FieldState::User);
        let encoding = option.encoding().expect("explicit encoding metadata");
        assert_eq!(encoding.wire_delta(), Some(65804));
        assert_eq!(encoding.wire_length(), Some(1));
    }

    #[test]
    fn option_header_codec_covers_every_direct_value_and_extension_boundary() {
        for value in 0u32..=12 {
            let mut encoded = Vec::new();
            let consumed = encode_option_header(value, 0, None, &mut encoded).unwrap();
            assert_eq!(encoded, [((value as u8) << 4)]);
            assert_eq!(consumed, 1);
            assert_eq!(
                decode_option_header(&encoded).unwrap(),
                DecodedOptionHeader {
                    delta: value,
                    length: 0,
                    consumed: 1,
                }
            );
        }

        for value in 0usize..=12 {
            let mut encoded = Vec::new();
            let consumed = encode_option_header(0, value, None, &mut encoded).unwrap();
            assert_eq!(encoded, [value as u8]);
            assert_eq!(consumed, 1);
            assert_eq!(
                decode_option_header(&encoded).unwrap(),
                DecodedOptionHeader {
                    delta: 0,
                    length: value,
                    consumed: 1,
                }
            );
        }

        let delta_cases: &[(u32, &[u8])] = &[
            (13, &[0xd0, 0x00]),
            (268, &[0xd0, 0xff]),
            (269, &[0xe0, 0x00, 0x00]),
            (65_804, &[0xe0, 0xff, 0xff]),
        ];
        for &(delta, expected) in delta_cases {
            let mut encoded = Vec::new();
            let consumed = encode_option_header(delta, 0, None, &mut encoded).unwrap();
            assert_eq!(encoded, expected);
            assert_eq!(consumed, expected.len());
            assert_eq!(
                decode_option_header(&encoded).unwrap(),
                DecodedOptionHeader {
                    delta,
                    length: 0,
                    consumed: expected.len(),
                }
            );
        }

        let length_cases: &[(usize, &[u8])] = &[
            (13, &[0x0d, 0x00]),
            (268, &[0x0d, 0xff]),
            (269, &[0x0e, 0x00, 0x00]),
            (65_804, &[0x0e, 0xff, 0xff]),
        ];
        for &(length, expected) in length_cases {
            let mut encoded = Vec::new();
            let consumed = encode_option_header(0, length, None, &mut encoded).unwrap();
            assert_eq!(encoded, expected);
            assert_eq!(consumed, expected.len());
            assert_eq!(
                decode_option_header(&encoded).unwrap(),
                DecodedOptionHeader {
                    delta: 0,
                    length,
                    consumed: expected.len(),
                }
            );
        }
    }

    #[test]
    fn option_header_codec_orders_extensions_and_reports_only_header_consumption() {
        let mut encoded = Vec::new();
        assert_eq!(encode_option_header(269, 268, None, &mut encoded), Ok(4));
        assert_eq!(encoded, [0xed, 0x00, 0x00, 0xff]);

        encoded.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(
            decode_option_header(&encoded),
            Ok(DecodedOptionHeader {
                delta: 269,
                length: 268,
                consumed: 4,
            })
        );
    }

    #[test]
    fn option_header_codec_honors_logical_and_exact_raw_overrides() {
        let logical = CoapOptionEncoding::explicit(269, 268);
        let mut encoded = Vec::new();
        assert_eq!(
            encode_option_header(1, 2, Some(&logical), &mut encoded),
            Ok(4)
        );
        assert_eq!(encoded, [0xed, 0x00, 0x00, 0xff]);

        let raw = logical.with_raw_bytes([0xfe, 0xaa, 0xbb]);
        assert_eq!(raw.wire_delta(), Some(269));
        assert_eq!(raw.wire_length(), Some(268));
        assert_eq!(raw.raw_bytes(), Some([0xfe, 0xaa, 0xbb].as_slice()));

        encoded.clear();
        assert_eq!(encode_option_header(1, 2, Some(&raw), &mut encoded), Ok(3));
        assert_eq!(encoded, [0xfe, 0xaa, 0xbb]);

        let decoded = CoapOptionEncoding::from_raw_bytes([0xd0, 0x00]);
        assert_eq!(decoded.raw_bytes(), Some([0xd0, 0x00].as_slice()));
        assert_eq!(decoded.wire_delta(), None);
        assert_eq!(decoded.wire_length(), None);
    }

    #[test]
    fn option_header_codec_rejects_unencodable_logical_values() {
        let mut encoded = Vec::new();
        assert_eq!(
            encode_option_header(65_805, 0, None, &mut encoded),
            Err(CrafterError::invalid_field_value(
                "coap.option.delta",
                "option delta exceeds 65804",
            ))
        );
        assert!(encoded.is_empty());

        assert_eq!(
            encode_option_header(0, 65_805, None, &mut encoded),
            Err(CrafterError::invalid_field_value(
                "coap.option.length",
                "option length exceeds 65804",
            ))
        );
        assert!(encoded.is_empty());

        let invalid_override = CoapOptionEncoding::new().with_wire_delta(u32::MAX);
        assert_eq!(
            encode_option_header(0, 0, Some(&invalid_override), &mut encoded),
            Err(CrafterError::invalid_field_value(
                "coap.option.delta",
                "option delta exceeds 65804",
            ))
        );
        assert!(encoded.is_empty());
    }

    #[test]
    fn option_header_codec_reports_stable_truncation_boundaries() {
        let cases: &[(&[u8], &str, usize, usize)] = &[
            (&[], "coap.option.header", 1, 0),
            (&[0xd0], "coap.option.delta.extended8", 1, 0),
            (&[0xe0], "coap.option.delta.extended16", 2, 0),
            (&[0xe0, 0x00], "coap.option.delta.extended16", 2, 1),
            (&[0x0d], "coap.option.length.extended8", 1, 0),
            (&[0x0e], "coap.option.length.extended16", 2, 0),
            (&[0x0e, 0x00], "coap.option.length.extended16", 2, 1),
            (&[0xdd, 0x00], "coap.option.length.extended8", 1, 0),
            (&[0xed, 0x00, 0x00], "coap.option.length.extended8", 1, 0),
            (&[0xee, 0x00, 0x00], "coap.option.length.extended16", 2, 0),
            (
                &[0xee, 0x00, 0x00, 0x00],
                "coap.option.length.extended16",
                2,
                1,
            ),
        ];

        for &(bytes, context, required, available) in cases {
            assert_eq!(
                decode_option_header(bytes),
                Err(CrafterError::BufferTooShort {
                    context,
                    required,
                    available,
                }),
                "bytes: {bytes:02x?}"
            );
        }
    }

    #[test]
    fn option_header_codec_rejects_every_reserved_nibble_position() {
        for length_nibble in 0u8..=14 {
            let header = 0xf0 | length_nibble;
            assert_eq!(
                decode_option_header(&[header]),
                Err(CrafterError::invalid_field_value(
                    "coap.option.delta",
                    "reserved delta nibble 15 is not a payload marker",
                ))
            );
        }

        for delta_nibble in 0u8..=14 {
            let header = (delta_nibble << 4) | 0x0f;
            assert_eq!(
                decode_option_header(&[header]),
                Err(CrafterError::invalid_field_value(
                    "coap.option.length",
                    "reserved option length nibble 15",
                ))
            );
        }

        assert_eq!(
            decode_option_header(&[0xff]),
            Err(CrafterError::invalid_field_value(
                "coap.option.delta",
                "payload marker is not an option header",
            ))
        );
    }

    #[test]
    fn option_sequence_round_trips_empty_and_payload_marker_boundaries() {
        let mut encoded = vec![0xaa];
        assert_eq!(
            encode_option_sequence(&CoapOptions::new(), &mut encoded),
            Ok(0)
        );
        assert_eq!(encoded, [0xaa]);

        let decoded = decode_option_sequence(&[]).unwrap();
        assert!(decoded.options.is_empty());
        assert_eq!(decoded.consumed, 0);
        assert!(!decoded.payload_marker);

        let decoded = decode_option_sequence(&[COAP_PAYLOAD_MARKER, 0x01, 0xff]).unwrap();
        assert!(decoded.options.is_empty());
        assert_eq!(decoded.consumed, 0);
        assert!(decoded.payload_marker);
    }

    #[test]
    fn option_sequence_round_trips_repeats_extensions_and_unknown_values() {
        let options = CoapOptions::from_options([
            CoapOption::new(13u16, Vec::new()),
            CoapOption::new(13u16, b"repeat".to_vec()),
            CoapOption::new(282u16, vec![0xff, 0x00]),
            CoapOption::new(283u16, vec![0xab; 269]),
            CoapOption::new(65_000u16, vec![0xde, 0xad, 0xbe, 0xef]),
        ]);

        let mut encoded = Vec::new();
        let encoded_len = encode_option_sequence(&options, &mut encoded).unwrap();
        assert_eq!(encoded_len, encoded.len());
        assert_eq!(&encoded[..2], [0xd0, 0x00]);
        assert_eq!(encoded[2], 0x06);

        let mut framed = encoded.clone();
        framed.extend_from_slice(&[COAP_PAYLOAD_MARKER, 0x10, 0xff]);
        let decoded = decode_option_sequence(&framed).unwrap();
        assert_eq!(decoded.consumed, encoded.len());
        assert!(decoded.payload_marker);

        let decoded_numbers: Vec<_> = decoded
            .options
            .iter()
            .map(|option| option.number().value())
            .collect();
        assert_eq!(decoded_numbers, [13, 13, 282, 283, 65_000]);
        for (actual, expected) in decoded.options.iter().zip(options.iter()) {
            assert_eq!(actual.value(), expected.value());
            let encoding = actual.encoding().expect("decoded encoding metadata");
            assert!(encoding.raw_bytes().is_some());
            assert!(encoding.wire_delta().is_some());
            assert_eq!(encoding.wire_length(), Some(actual.value().len()));
        }

        let mut reencoded = Vec::new();
        encode_option_sequence(&decoded.options, &mut reencoded).unwrap();
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn option_sequence_honors_explicit_headers_and_rejects_only_impossible_ones() {
        let options = CoapOptions::from_options([
            CoapOption::new(11u16, b"a".to_vec()),
            CoapOption::new(5u16, b"bc".to_vec())
                .with_encoding(CoapOptionEncoding::from_raw_bytes([0xf1])),
            CoapOption::new(4u16, b"d".to_vec()).with_wire_delta(13),
        ]);
        let mut encoded = Vec::new();
        encode_option_sequence(&options, &mut encoded).unwrap();
        assert_eq!(encoded, [0xb1, b'a', 0xf1, b'b', b'c', 0xd1, 0x00, b'd']);

        let decreasing = CoapOptions::from_options([
            CoapOption::new(11u16, Vec::new()),
            CoapOption::new(5u16, Vec::new()),
        ]);
        let mut untouched = vec![0xaa];
        assert_eq!(
            encode_option_sequence(&decreasing, &mut untouched),
            Err(CrafterError::invalid_field_value(
                "coap.option-order",
                "canonical option numbers must be nondecreasing",
            ))
        );
        assert_eq!(untouched, [0xaa]);

        let impossible =
            CoapOptions::from_options(
                [CoapOption::new(1u16, Vec::new()).with_wire_delta(u32::MAX)],
            );
        assert_eq!(
            encode_option_sequence(&impossible, &mut untouched),
            Err(CrafterError::invalid_field_value(
                "coap.option.delta",
                "option delta exceeds 65804",
            ))
        );
        assert_eq!(untouched, [0xaa]);
    }

    #[test]
    fn option_sequence_reports_value_truncation_and_cumulative_overflow() {
        assert_eq!(
            decode_option_sequence(&[0x03, 0xaa]),
            Err(CrafterError::BufferTooShort {
                context: "coap.option.value",
                required: 3,
                available: 1,
            })
        );

        assert_eq!(
            decode_option_sequence(&[0xe0, 0xff, 0xff]),
            Err(CrafterError::invalid_field_value(
                "coap.option-number",
                "cumulative option number exceeds 65535",
            ))
        );
    }

    #[test]
    fn uint_builder_uses_the_shortest_network_order_value() {
        assert_eq!(CoapOption::from_uint(12u16, 0).value(), b"");
        assert_eq!(CoapOption::from_uint(12u16, 0xff).value(), [0xff]);
        assert_eq!(CoapOption::from_uint(12u16, 0x0100).value(), [1, 0]);
    }
}
