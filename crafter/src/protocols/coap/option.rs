//! Ordered, lossless CoAP option primitives.

use core::str;

use crate::error::{CrafterError, Result};
use crate::field::{Field, FieldState};

use super::registry::{
    coap_option_is_critical, coap_option_is_no_cache_key, coap_option_is_safe_to_forward,
    coap_option_is_unsafe, coap_option_meta, CoapRegistryMeta,
};

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
}

impl CoapOptionEncoding {
    /// Create encoding metadata with no explicit overrides.
    pub const fn new() -> Self {
        Self {
            wire_delta: None,
            wire_length: None,
        }
    }

    /// Create encoding metadata with both logical wire values pinned.
    pub const fn explicit(wire_delta: u32, wire_length: usize) -> Self {
        Self {
            wire_delta: Some(wire_delta),
            wire_length: Some(wire_length),
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

    /// Return the caller-supplied wire delta, if present.
    pub const fn wire_delta(&self) -> Option<u32> {
        self.wire_delta
    }

    /// Return the caller-supplied wire length, if present.
    pub const fn wire_length(&self) -> Option<usize> {
        self.wire_length
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
    fn uint_builder_uses_the_shortest_network_order_value() {
        assert_eq!(CoapOption::from_uint(12u16, 0).value(), b"");
        assert_eq!(CoapOption::from_uint(12u16, 0xff).value(), [0xff]);
        assert_eq!(CoapOption::from_uint(12u16, 0x0100).value(), [1, 0]);
    }
}
