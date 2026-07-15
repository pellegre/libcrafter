//! Ordered, lossless CoAP option primitives.

use core::str;

use crate::error::{CrafterError, Result};
use crate::field::{Field, FieldState};

use super::registry::{
    coap_option_is_critical, coap_option_is_no_cache_key, coap_option_is_safe_to_forward,
    coap_option_is_unsafe, coap_option_meta, CoapRegistryMeta,
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
        if value == 0 {
            return Self::new(number, Vec::new());
        }

        let encoded = value.to_be_bytes();
        let first = encoded
            .iter()
            .position(|byte| *byte != 0)
            .expect("a nonzero integer contains a nonzero byte");
        Self::new(number, encoded[first..].to_vec())
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
        if self.value.len() > size_of::<u64>() {
            return Err(CrafterError::invalid_field_value(
                "coap.option.uint",
                "unsigned option value exceeds 64 bits",
            ));
        }

        Ok(self
            .value
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)))
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
        assert!(binary.as_str().is_err());
        assert_eq!(binary.value(), [0xff, 0x00]);

        let too_wide = CoapOption::new(65002u16, vec![0; 9]);
        assert!(too_wide.as_uint().is_err());
        assert_eq!(too_wide.into_bytes(), vec![0; 9]);
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
    fn uint_builder_uses_the_shortest_network_order_value() {
        assert_eq!(CoapOption::from_uint(12u16, 0).value(), b"");
        assert_eq!(CoapOption::from_uint(12u16, 0xff).value(), [0xff]);
        assert_eq!(CoapOption::from_uint(12u16, 0x0100).value(), [1, 0]);
    }
}
