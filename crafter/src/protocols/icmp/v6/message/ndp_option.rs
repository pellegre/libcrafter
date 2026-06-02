//! IPv6 Neighbor Discovery (NDP) option TLV framework.
//!
//! RFC 4861 section 4.6 defines a single, uniform option layout shared by every
//! Neighbor Discovery message (Router Solicitation, Router Advertisement,
//! Neighbor Solicitation, Neighbor Advertisement, Redirect):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Type      |    Length     |              ...              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-                               -
//! ~                              ...                              ~
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! - `Type` is a one-byte option type codepoint.
//! - `Length` is a one-byte field expressed **in units of 8 octets** and counts
//!   the **whole** option, including the two-byte Type/Length header. RFC 4861
//!   section 4.6: "The length of the option (including the type and length
//!   fields) in units of 8 octets. The value 0 is invalid. Nodes MUST silently
//!   discard an ND packet that contains an option with length zero."
//! - The remaining bytes are the option value.
//!
//! Options form an **ordered list** that round-trips in order. Each message
//! carries zero or more of them.
//!
//! This module is the shared framework only: it models a recognized option's
//! raw value bytes plus an [`NdpOption::Unknown`] variant that preserves an
//! unrecognized option's bytes verbatim, auto-fills the length field (whole
//! option padded to the 8-octet boundary) when the agent did not set it,
//! preserves an explicitly-set length even when it is wrong, and decodes into a
//! structured [`CrafterError`] (never a panic) on a zero length or a buffer
//! overrun. Typed accessors/constructors for individual options (Source/Target
//! Link-Layer Address, Prefix Information, MTU, ...) are layered on top of this
//! framework in later steps.
//!
//! Codepoints below are grounded against the IANA "IPv6 Neighbor Discovery
//! Option Formats" registry
//! (<https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-5>)
//! and the defining RFC is cited per constant. (The local `rfc-protocol-spec`
//! manifest cache is sparse for NDP, so the values were grounded directly
//! against the live IANA registry plus RFC 4861 section 4.6.)

use core::fmt;

use crate::error::{CrafterError, Result};

// --- NDP option type codepoints (IANA "IPv6 Neighbor Discovery Option
// Formats" registry) -------------------------------------------------------

/// Source Link-Layer Address option (RFC 4861 section 4.6.1).
pub const NDP_OPT_SOURCE_LINK_LAYER_ADDR: u8 = 1;

/// Target Link-Layer Address option (RFC 4861 section 4.6.1).
pub const NDP_OPT_TARGET_LINK_LAYER_ADDR: u8 = 2;

/// Prefix Information option (RFC 4861 section 4.6.2).
pub const NDP_OPT_PREFIX_INFORMATION: u8 = 3;

/// Redirected Header option (RFC 4861 section 4.6.3).
pub const NDP_OPT_REDIRECTED_HEADER: u8 = 4;

/// MTU option (RFC 4861 section 4.6.4).
pub const NDP_OPT_MTU: u8 = 5;

/// Nonce option (RFC 3971 section 5.3.2; used for SEND and RFC 7527 DAD).
pub const NDP_OPT_NONCE: u8 = 14;

/// Route Information option (RFC 4191 section 2.3).
pub const NDP_OPT_ROUTE_INFORMATION: u8 = 24;

/// Recursive DNS Server (RDNSS) option (RFC 8106 section 5.1; originally
/// RFC 5006, obsoleted by RFC 8106).
pub const NDP_OPT_RDNSS: u8 = 25;

/// RA Flags Extension option (RFC 5175 section 4).
pub const NDP_OPT_RA_FLAGS_EXTENSION: u8 = 26;

/// DNS Search List (DNSSL) option (RFC 8106 section 5.2).
pub const NDP_OPT_DNSSL: u8 = 31;

/// Captive Portal option (RFC 8910 section 2; IANA name "DHCP Captive-Portal").
pub const NDP_OPT_CAPTIVE_PORTAL: u8 = 37;

/// PREF64 option (RFC 8781 section 4).
pub const NDP_OPT_PREF64: u8 = 38;

/// The unit, in octets, of the NDP option `Length` field (RFC 4861 sec 4.6:
/// "in units of 8 octets").
pub const NDP_OPTION_LENGTH_UNIT: usize = 8;

/// Width, in octets, of the Type/Length header that precedes every NDP option
/// value (RFC 4861 sec 4.6).
pub const NDP_OPTION_HEADER_LEN: usize = 2;

/// Return the human-readable name for a recognized NDP option type, or `None`
/// for an unassigned/unrecognized type.
///
/// Names match the IANA "IPv6 Neighbor Discovery Option Formats" registry
/// descriptions.
pub const fn ndp_option_type_name(ty: u8) -> Option<&'static str> {
    match ty {
        NDP_OPT_SOURCE_LINK_LAYER_ADDR => Some("Source Link-Layer Address"),
        NDP_OPT_TARGET_LINK_LAYER_ADDR => Some("Target Link-Layer Address"),
        NDP_OPT_PREFIX_INFORMATION => Some("Prefix Information"),
        NDP_OPT_REDIRECTED_HEADER => Some("Redirected Header"),
        NDP_OPT_MTU => Some("MTU"),
        NDP_OPT_NONCE => Some("Nonce"),
        NDP_OPT_ROUTE_INFORMATION => Some("Route Information"),
        NDP_OPT_RDNSS => Some("Recursive DNS Server"),
        NDP_OPT_RA_FLAGS_EXTENSION => Some("RA Flags Extension"),
        NDP_OPT_DNSSL => Some("DNS Search List"),
        NDP_OPT_CAPTIVE_PORTAL => Some("Captive Portal"),
        NDP_OPT_PREF64 => Some("PREF64"),
        _ => None,
    }
}

/// Return true when `ty` is an NDP option type `crafter` recognizes by name.
pub const fn ndp_option_type_is_known(ty: u8) -> bool {
    ndp_option_type_name(ty).is_some()
}

/// A single Neighbor Discovery option (RFC 4861 section 4.6).
///
/// This is the framework-level representation: a `{type, value-bytes}` option
/// with the length field auto-filled (or preserved verbatim when set on
/// purpose). [`Self::Generic`] holds a recognized option type with its raw
/// value bytes, and [`Self::Unknown`] preserves an unrecognized option's value
/// bytes byte-for-byte so they round-trip. Both carry an optional explicit
/// `length` override so a deliberately-wrong length survives `encode()`.
///
/// Typed option views and constructors (Source/Target Link-Layer Address,
/// Prefix Information, MTU, ...) build on top of this representation in later
/// steps; this enum is `#[non_exhaustive]` so those variants can be added
/// without breaking the framework's callers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NdpOption {
    /// A recognized option type carried as raw value bytes (the bytes after the
    /// two-byte Type/Length header), with the length field auto-filled unless
    /// `length` is set.
    Generic {
        /// Option type codepoint (a recognized [`ndp_option_type_is_known`]
        /// value).
        ty: u8,
        /// Option value bytes (everything after the Type/Length header).
        value: Vec<u8>,
        /// Explicit `Length` field (in units of 8 octets) when the agent set it
        /// on purpose. `None` means auto-fill on encode. An explicitly-set
        /// value is preserved even when it disagrees with `value` — the
        /// honored-overrides rule.
        length: Option<u8>,
    },
    /// An unrecognized option type, preserved verbatim so its bytes round-trip
    /// unchanged.
    Unknown {
        /// Option type codepoint (an unrecognized value).
        ty: u8,
        /// Option value bytes (everything after the Type/Length header),
        /// preserved exactly as decoded.
        bytes: Vec<u8>,
        /// Explicit `Length` field (in units of 8 octets) when set; `None`
        /// auto-fills on encode.
        length: Option<u8>,
    },
}

impl NdpOption {
    /// Build a recognized-type option from its type codepoint and raw value
    /// bytes, with the length field auto-filled on encode.
    pub fn generic(ty: u8, value: impl Into<Vec<u8>>) -> Self {
        Self::Generic {
            ty,
            value: value.into(),
            length: None,
        }
    }

    /// Build an unrecognized-type option whose bytes are preserved verbatim,
    /// with the length field auto-filled on encode.
    pub fn unknown(ty: u8, bytes: impl Into<Vec<u8>>) -> Self {
        Self::Unknown {
            ty,
            bytes: bytes.into(),
            length: None,
        }
    }

    /// Pin the `Length` field (in units of 8 octets) to an explicit value.
    ///
    /// The pinned value is emitted verbatim by [`Self::encode`], even when it
    /// disagrees with the value bytes — generated tools often need a malformed
    /// option to exercise a peer's parser (the honored-overrides rule). Pass a
    /// fresh option through [`Self::generic`]/[`Self::unknown`] (or
    /// [`Self::clear_length`]) to return to auto-fill.
    pub fn length(mut self, length: u8) -> Self {
        match &mut self {
            Self::Generic { length: l, .. } | Self::Unknown { length: l, .. } => {
                *l = Some(length);
            }
        }
        self
    }

    /// Drop any explicit `Length` override so the field auto-fills on encode.
    pub fn clear_length(mut self) -> Self {
        match &mut self {
            Self::Generic { length: l, .. } | Self::Unknown { length: l, .. } => {
                *l = None;
            }
        }
        self
    }

    /// Option type codepoint.
    pub const fn option_type(&self) -> u8 {
        match self {
            Self::Generic { ty, .. } | Self::Unknown { ty, .. } => *ty,
        }
    }

    /// Option value bytes (everything after the two-byte Type/Length header).
    pub fn value(&self) -> &[u8] {
        match self {
            Self::Generic { value, .. } => value,
            Self::Unknown { bytes, .. } => bytes,
        }
    }

    /// Explicit `Length` field (in units of 8 octets) when one is pinned, else
    /// `None` (auto-fill on encode).
    pub const fn explicit_length(&self) -> Option<u8> {
        match self {
            Self::Generic { length, .. } | Self::Unknown { length, .. } => *length,
        }
    }

    /// True when this option's type is recognized by name.
    pub const fn is_known(&self) -> bool {
        ndp_option_type_is_known(self.option_type())
    }

    /// The `Length` field (in units of 8 octets) that [`Self::encode`] will
    /// emit: the pinned value when set, otherwise the auto-filled length that
    /// rounds the whole option up to the next 8-octet boundary.
    ///
    /// Returns an error only when the auto-filled length would exceed the
    /// one-byte field's range (a value longer than `255 * 8 - 2` bytes); a
    /// pinned length is always returned as-is.
    pub fn effective_length(&self) -> Result<u8> {
        if let Some(length) = self.explicit_length() {
            return Ok(length);
        }
        auto_fill_length(self.value().len())
    }

    /// Total encoded length of this option in bytes, including the Type/Length
    /// header and any zero padding implied by the (auto-filled or pinned)
    /// length field.
    ///
    /// A pinned length drives the encoded size (the honored-overrides rule), so
    /// a deliberately-wrong length yields a deliberately-wrong size.
    pub fn encoded_len(&self) -> Result<usize> {
        Ok(self.effective_length()? as usize * NDP_OPTION_LENGTH_UNIT)
    }

    /// Encode this single option to bytes (RFC 4861 section 4.6 layout).
    ///
    /// The `Length` field is auto-filled to round the whole option (header plus
    /// value) up to the next 8-octet boundary, zero-padding the value, unless
    /// the agent pinned a length via [`Self::length`] — in which case the
    /// pinned length is emitted verbatim and the value is padded (or, for a too
    /// small pinned length, truncated) to match, so the wrong value survives.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let length = self.effective_length()?;
        let ty = self.option_type();
        let value = self.value();

        let total = length as usize * NDP_OPTION_LENGTH_UNIT;
        let mut bytes = Vec::with_capacity(total.max(NDP_OPTION_HEADER_LEN));
        bytes.push(ty);
        bytes.push(length);

        // The value occupies whatever space the (header + value) leaves inside
        // the length-declared total, padded with zeros to the boundary. When a
        // pinned length is too small to hold the value, the value is truncated
        // to the declared size — the pinned length, not the value, is the
        // source of truth (honored overrides).
        let value_capacity = total.saturating_sub(NDP_OPTION_HEADER_LEN);
        if value.len() >= value_capacity {
            bytes.extend_from_slice(&value[..value_capacity]);
        } else {
            bytes.extend_from_slice(value);
            bytes.resize(total, 0);
        }

        Ok(bytes)
    }

    /// Decode a single option from the front of `bytes`, returning the option
    /// and the number of bytes it consumed.
    ///
    /// Returns a structured [`CrafterError`] (never a panic) when fewer than two
    /// bytes are available, when the `Length` field is zero (RFC 4861 sec 4.6:
    /// "The value 0 is invalid"), or when the declared length runs past the end
    /// of `bytes`.
    ///
    /// The whole declared option (header plus value, including any padding) is
    /// captured as the option's value bytes so it round-trips verbatim, and the
    /// decoded length is pinned on the returned option so re-encoding reproduces
    /// the original bytes.
    pub fn decode_one(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < NDP_OPTION_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "ndp.option.header",
                NDP_OPTION_HEADER_LEN,
                bytes.len(),
            ));
        }

        let ty = bytes[0];
        let length = bytes[1];
        if length == 0 {
            // RFC 4861 sec 4.6: a length of 0 is invalid.
            return Err(CrafterError::invalid_field_value(
                "ndp.option.length",
                "NDP option length field must not be zero",
            ));
        }

        let total = length as usize * NDP_OPTION_LENGTH_UNIT;
        if total > bytes.len() {
            return Err(CrafterError::buffer_too_short(
                "ndp.option.value",
                total,
                bytes.len(),
            ));
        }

        let value = bytes[NDP_OPTION_HEADER_LEN..total].to_vec();
        let option = if ndp_option_type_is_known(ty) {
            Self::Generic {
                ty,
                value,
                length: Some(length),
            }
        } else {
            Self::Unknown {
                ty,
                bytes: value,
                length: Some(length),
            }
        };
        Ok((option, total))
    }
}

impl fmt::Display for NdpOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ty = self.option_type();
        let name = ndp_option_type_name(ty).unwrap_or("Unknown");
        let length = match self.explicit_length() {
            Some(length) => length.to_string(),
            None => "auto".to_string(),
        };
        write!(
            f,
            "{name}(type={ty}, len={length}, value_len={})",
            self.value().len()
        )
    }
}

/// An ordered list of Neighbor Discovery options (RFC 4861 section 4.6).
///
/// NDP options are an ordered sequence; this container preserves insertion /
/// decode order so a re-encode reproduces the original ordering. Decoding walks
/// the option area option-by-option and never panics: it surfaces the first
/// malformed option as a structured [`CrafterError`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NdpOptions {
    options: Vec<NdpOption>,
}

impl NdpOptions {
    /// Create an empty option list.
    pub const fn new() -> Self {
        Self {
            options: Vec::new(),
        }
    }

    /// Append an option, preserving order.
    pub fn push(mut self, option: NdpOption) -> Self {
        self.options.push(option);
        self
    }

    /// Append an option in place, preserving order.
    pub fn add(&mut self, option: NdpOption) {
        self.options.push(option);
    }

    /// The options in order.
    pub fn options(&self) -> &[NdpOption] {
        &self.options
    }

    /// Number of options.
    pub fn len(&self) -> usize {
        self.options.len()
    }

    /// True when there are no options.
    pub fn is_empty(&self) -> bool {
        self.options.is_empty()
    }

    /// Iterate over the options in order.
    pub fn iter(&self) -> core::slice::Iter<'_, NdpOption> {
        self.options.iter()
    }

    /// Total encoded length, in bytes, of all options.
    pub fn encoded_len(&self) -> Result<usize> {
        let mut total = 0usize;
        for option in &self.options {
            total += option.encoded_len()?;
        }
        Ok(total)
    }

    /// Encode every option in order into a single option-area byte buffer.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for option in &self.options {
            bytes.extend_from_slice(&option.encode()?);
        }
        Ok(bytes)
    }

    /// Decode an entire NDP option area into an ordered list.
    ///
    /// Walks `bytes` option-by-option. Returns a structured [`CrafterError`]
    /// (never a panic) on the first option with a zero length or one that runs
    /// past the end of the buffer. Order is preserved and unrecognized options
    /// are kept verbatim as [`NdpOption::Unknown`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut options = Vec::new();
        let mut offset = 0usize;
        while offset < bytes.len() {
            let (option, consumed) = NdpOption::decode_one(&bytes[offset..])?;
            // `decode_one` rejects a zero length, so `consumed` is always > 0;
            // the loop therefore always makes progress and terminates.
            offset += consumed;
            options.push(option);
        }
        Ok(Self { options })
    }
}

impl FromIterator<NdpOption> for NdpOptions {
    fn from_iter<I: IntoIterator<Item = NdpOption>>(iter: I) -> Self {
        Self {
            options: iter.into_iter().collect(),
        }
    }
}

impl<'a> IntoIterator for &'a NdpOptions {
    type Item = &'a NdpOption;
    type IntoIter = core::slice::Iter<'a, NdpOption>;

    fn into_iter(self) -> Self::IntoIter {
        self.options.iter()
    }
}

/// Compute the auto-filled `Length` field (in units of 8 octets) for an option
/// whose value is `value_len` bytes long: round the whole option (the two-byte
/// header plus the value) up to the next 8-octet boundary (RFC 4861 sec 4.6).
///
/// Returns an error when the rounded length would exceed the one-byte field's
/// range.
fn auto_fill_length(value_len: usize) -> Result<u8> {
    let total = NDP_OPTION_HEADER_LEN + value_len;
    // Round up to the next multiple of 8 octets, then convert to units.
    let units = total.div_ceil(NDP_OPTION_LENGTH_UNIT);
    // A well-formed option is at least one 8-octet unit even when empty.
    let units = units.max(1);
    u8::try_from(units).map_err(|_| {
        CrafterError::invalid_field_value(
            "ndp.option.length",
            "NDP option length in 8-octet units does not fit in one byte",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The named codepoints match the IANA "IPv6 Neighbor Discovery Option
    // Formats" registry. Hard-coded literals are the independent oracle.
    #[test]
    fn ndp_option_codepoints_match_iana_registry() {
        assert_eq!(NDP_OPT_SOURCE_LINK_LAYER_ADDR, 1);
        assert_eq!(NDP_OPT_TARGET_LINK_LAYER_ADDR, 2);
        assert_eq!(NDP_OPT_PREFIX_INFORMATION, 3);
        assert_eq!(NDP_OPT_REDIRECTED_HEADER, 4);
        assert_eq!(NDP_OPT_MTU, 5);
        assert_eq!(NDP_OPT_NONCE, 14);
        assert_eq!(NDP_OPT_ROUTE_INFORMATION, 24);
        assert_eq!(NDP_OPT_RDNSS, 25);
        assert_eq!(NDP_OPT_RA_FLAGS_EXTENSION, 26);
        assert_eq!(NDP_OPT_DNSSL, 31);
        assert_eq!(NDP_OPT_CAPTIVE_PORTAL, 37);
        assert_eq!(NDP_OPT_PREF64, 38);
    }

    #[test]
    fn known_vs_unknown_type_classification() {
        assert!(ndp_option_type_is_known(NDP_OPT_MTU));
        assert_eq!(ndp_option_type_name(NDP_OPT_MTU), Some("MTU"));
        // 99 is unassigned in the NDP option registry.
        assert!(!ndp_option_type_is_known(99));
        assert_eq!(ndp_option_type_name(99), None);
    }

    // A known-type generic option and an unknown option round-trip in order,
    // preserving both the ordering and the exact value bytes.
    #[test]
    fn ordered_known_and_unknown_round_trip() {
        // MTU option (type 5): the RFC 4861 sec 4.6.4 layout is type/length +
        // 2 reserved bytes + 4-byte MTU = 8 bytes total (length unit 1).
        let mtu = NdpOption::generic(NDP_OPT_MTU, [0x00, 0x00, 0x00, 0x00, 0x05, 0xdc]);
        // An unrecognized option type carrying arbitrary 6-byte value, which
        // pads to one 8-octet unit.
        let unknown = NdpOption::unknown(0x99, [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02]);

        let options = NdpOptions::new().push(mtu.clone()).push(unknown.clone());

        let encoded = options.encode().unwrap();
        // Two options, each exactly one 8-octet unit.
        assert_eq!(encoded.len(), 16);
        // First option header.
        assert_eq!(&encoded[0..2], &[NDP_OPT_MTU, 1]);
        // Second option header.
        assert_eq!(&encoded[8..10], &[0x99, 1]);

        let decoded = NdpOptions::decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);

        // Order preserved: MTU first, unknown second.
        assert_eq!(decoded.options()[0].option_type(), NDP_OPT_MTU);
        assert!(decoded.options()[0].is_known());
        assert!(matches!(decoded.options()[0], NdpOption::Generic { .. }));

        assert_eq!(decoded.options()[1].option_type(), 0x99);
        assert!(!decoded.options()[1].is_known());
        // Unknown bytes preserved verbatim (incl. the trailing zero padding the
        // encoder added to reach the 8-octet boundary).
        match &decoded.options()[1] {
            NdpOption::Unknown { bytes, .. } => {
                assert_eq!(bytes, &[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02]);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }

        // Re-encode reproduces the original bytes exactly.
        assert_eq!(decoded.encode().unwrap(), encoded);
    }

    // The length field auto-fills to the next 8-octet boundary, zero-padding
    // the value (RFC 4861 sec 4.6).
    #[test]
    fn length_auto_fills_to_eight_octet_boundary() {
        // 6-byte value + 2-byte header = 8 bytes -> exactly 1 unit, no padding.
        let exact = NdpOption::generic(NDP_OPT_SOURCE_LINK_LAYER_ADDR, [1, 2, 3, 4, 5, 6]);
        assert_eq!(exact.effective_length().unwrap(), 1);
        let exact_bytes = exact.encode().unwrap();
        assert_eq!(exact_bytes.len(), 8);
        assert_eq!(exact_bytes[1], 1);
        assert_eq!(&exact_bytes[2..8], &[1, 2, 3, 4, 5, 6]);

        // 7-byte value + 2-byte header = 9 bytes -> rounds up to 2 units (16
        // bytes), padding the last 7 bytes with zeros.
        let padded = NdpOption::generic(NDP_OPT_PREFIX_INFORMATION, [9; 7]);
        assert_eq!(padded.effective_length().unwrap(), 2);
        let padded_bytes = padded.encode().unwrap();
        assert_eq!(padded_bytes.len(), 16);
        assert_eq!(padded_bytes[1], 2);
        assert_eq!(&padded_bytes[2..9], &[9; 7]);
        assert_eq!(&padded_bytes[9..16], &[0; 7]);

        // An empty-value option still occupies one 8-octet unit.
        let empty = NdpOption::generic(NDP_OPT_NONCE, []);
        assert_eq!(empty.effective_length().unwrap(), 1);
        assert_eq!(
            empty.encode().unwrap(),
            [NDP_OPT_NONCE, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    // A deliberately-wrong explicit length is emitted verbatim (honored
    // overrides): generated tools need malformed options to exercise a parser.
    #[test]
    fn explicit_wrong_length_is_preserved() {
        // The value is one unit's worth, but the agent pins length=4 (claims 32
        // bytes). The encoder must emit length=4 untouched.
        let wrong = NdpOption::generic(NDP_OPT_MTU, [0, 0, 0, 0, 5, 0xdc]).length(4);
        assert_eq!(wrong.explicit_length(), Some(4));
        assert_eq!(wrong.effective_length().unwrap(), 4);
        let bytes = wrong.encode().unwrap();
        assert_eq!(bytes[1], 4, "pinned length survives untouched");
        assert_eq!(bytes.len(), 32, "pinned length drives the encoded size");
        // The real value bytes are still present at the front, zero-padded out.
        assert_eq!(&bytes[2..8], &[0, 0, 0, 0, 5, 0xdc]);
        assert_eq!(&bytes[8..32], &[0; 24]);

        // A pinned length smaller than the value truncates to the declared size
        // rather than silently growing it — the length stays the source of
        // truth.
        let tiny = NdpOption::unknown(0x99, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).length(1);
        let tiny_bytes = tiny.encode().unwrap();
        assert_eq!(tiny_bytes.len(), 8);
        assert_eq!(tiny_bytes[1], 1);
        assert_eq!(&tiny_bytes[2..8], &[1, 2, 3, 4, 5, 6]);

        // clear_length returns to auto-fill.
        let restored = wrong.clear_length();
        assert_eq!(restored.explicit_length(), None);
        assert_eq!(restored.effective_length().unwrap(), 1);
    }

    // A zero length field is invalid (RFC 4861 sec 4.6) and decodes to a
    // structured error, never a panic.
    #[test]
    fn zero_length_is_a_structured_error() {
        let bytes = [NDP_OPT_MTU, 0, 0, 0, 0, 0, 0, 0];
        let err = NdpOption::decode_one(&bytes).unwrap_err();
        assert_eq!(
            err,
            CrafterError::invalid_field_value(
                "ndp.option.length",
                "NDP option length field must not be zero",
            )
        );

        // The same error surfaces when walking a full option area.
        assert_eq!(NdpOptions::decode(&bytes).unwrap_err(), err);
    }

    // A length that runs past the end of the buffer (truncation/overrun)
    // decodes to a structured BufferTooShort error, never a panic.
    #[test]
    fn truncated_option_is_a_structured_error() {
        // Declares length=2 (16 bytes) but only 8 bytes are present.
        let bytes = [NDP_OPT_PREFIX_INFORMATION, 2, 0, 0, 0, 0, 0, 0];
        let err = NdpOption::decode_one(&bytes).unwrap_err();
        assert_eq!(
            err,
            CrafterError::buffer_too_short("ndp.option.value", 16, 8)
        );

        // A header that is itself truncated (one byte) is also a structured
        // error, not a panic.
        let stub = [NDP_OPT_MTU];
        let header_err = NdpOption::decode_one(&stub).unwrap_err();
        assert_eq!(
            header_err,
            CrafterError::buffer_too_short("ndp.option.header", 2, 1)
        );

        // And it surfaces through the option-area walk too.
        assert_eq!(NdpOptions::decode(&bytes).unwrap_err(), err);
    }

    // A trailing malformed option after a valid one still surfaces as an error,
    // and the walk made progress (did not loop or panic).
    #[test]
    fn malformed_trailing_option_after_valid_one_errors() {
        let mut area = Vec::new();
        area.extend_from_slice(
            &NdpOption::generic(NDP_OPT_MTU, [0, 0, 0, 0, 5, 0xdc])
                .encode()
                .unwrap(),
        );
        // Append a second option that overruns.
        area.extend_from_slice(&[NDP_OPT_RDNSS, 5, 0, 0]);
        let err = NdpOptions::decode(&area).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }
}
