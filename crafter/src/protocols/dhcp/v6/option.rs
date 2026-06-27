//! DHCPv6 generic option model.
//!
//! DHCPv6 options are 16-bit code, 16-bit length, variable payload TLVs. This
//! module starts with the raw-preserving data model; the serial codec and IANA
//! registry classification live in later modules.

/// DHCPv6 option codepoint.
///
/// Every 16-bit value is representable so packets can preserve registered,
/// obsolete, unassigned, private, or future codepoints without requiring typed
/// support in the crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dhcpv6OptionCode(u16);

impl Dhcpv6OptionCode {
    /// Create an option codepoint from its raw wire value.
    pub const fn from_code(code: u16) -> Self {
        Self(code)
    }

    /// Raw wire codepoint.
    pub const fn code(self) -> u16 {
        self.0
    }
}

impl From<u16> for Dhcpv6OptionCode {
    fn from(code: u16) -> Self {
        Self::from_code(code)
    }
}

impl From<Dhcpv6OptionCode> for u16 {
    fn from(code: Dhcpv6OptionCode) -> Self {
        code.code()
    }
}

/// Reusable DHCPv6 option payload format family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6OptionFormat {
    /// Zero-length payload.
    Empty,
    /// Opaque payload bytes preserved verbatim.
    Raw,
}

/// Raw-preserving DHCPv6 option payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Dhcpv6OptionValue {
    /// Zero-length payload.
    Empty,
    /// Opaque payload bytes preserved verbatim.
    Raw(Vec<u8>),
}

impl Dhcpv6OptionValue {
    /// View this option value as payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Raw(bytes) => bytes,
        }
    }

    /// Consume this value into payload bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Empty => Vec::new(),
            Self::Raw(bytes) => bytes,
        }
    }

    /// Payload length in bytes.
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// True when the payload has zero bytes.
    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }

    /// Payload format family.
    pub const fn format(&self) -> Dhcpv6OptionFormat {
        match self {
            Self::Empty => Dhcpv6OptionFormat::Empty,
            Self::Raw(_) => Dhcpv6OptionFormat::Raw,
        }
    }
}

impl From<Vec<u8>> for Dhcpv6OptionValue {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Raw(bytes)
    }
}

impl From<&[u8]> for Dhcpv6OptionValue {
    fn from(bytes: &[u8]) -> Self {
        Self::Raw(bytes.to_vec())
    }
}

/// DHCPv6 option TLV.
///
/// The payload is kept as a [`Dhcpv6OptionValue`] so unknown and unsupported
/// options can round-trip through later codecs without losing bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6Option {
    code: Dhcpv6OptionCode,
    value: Dhcpv6OptionValue,
}

impl Dhcpv6Option {
    /// Create an option from a codepoint and raw payload bytes.
    pub fn raw(code: impl Into<Dhcpv6OptionCode>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            code: code.into(),
            value: Dhcpv6OptionValue::Raw(payload.into()),
        }
    }

    /// Create a zero-length option.
    pub fn empty(code: impl Into<Dhcpv6OptionCode>) -> Self {
        Self {
            code: code.into(),
            value: Dhcpv6OptionValue::Empty,
        }
    }

    /// Create an option from a codepoint and typed payload value.
    pub fn typed(code: impl Into<Dhcpv6OptionCode>, value: Dhcpv6OptionValue) -> Self {
        Self {
            code: code.into(),
            value,
        }
    }

    /// Option codepoint.
    pub const fn code(&self) -> Dhcpv6OptionCode {
        self.code
    }

    /// Raw option codepoint.
    pub const fn codepoint(&self) -> u16 {
        self.code.code()
    }

    /// Option payload value.
    pub const fn value(&self) -> &Dhcpv6OptionValue {
        &self.value
    }

    /// Mutable option payload value.
    pub fn value_mut(&mut self) -> &mut Dhcpv6OptionValue {
        &mut self.value
    }

    /// View this option's payload bytes.
    pub fn payload(&self) -> &[u8] {
        self.value.as_bytes()
    }

    /// Alias for [`Dhcpv6Option::payload`].
    pub fn as_bytes(&self) -> &[u8] {
        self.payload()
    }

    /// Payload length in bytes.
    pub fn payload_len(&self) -> usize {
        self.value.len()
    }

    /// True when the payload has zero bytes.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Payload format family.
    pub const fn format(&self) -> Dhcpv6OptionFormat {
        self.value.format()
    }

    /// Consume this option into its codepoint and payload value.
    pub fn into_parts(self) -> (Dhcpv6OptionCode, Dhcpv6OptionValue) {
        (self.code, self.value)
    }
}

#[cfg(test)]
mod dhcpv6_option_model_tests {
    use super::{Dhcpv6Option, Dhcpv6OptionCode, Dhcpv6OptionFormat, Dhcpv6OptionValue};

    #[test]
    fn dhcpv6_option_model_raw_option_preserves_code_and_payload() {
        let option = Dhcpv6Option::raw(23u16, vec![0xde, 0xad, 0xbe, 0xef]);

        assert_eq!(option.code(), Dhcpv6OptionCode::from_code(23));
        assert_eq!(option.codepoint(), 23);
        assert_eq!(option.payload(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(option.as_bytes(), option.payload());
        assert_eq!(option.payload_len(), 4);
        assert_eq!(option.format(), Dhcpv6OptionFormat::Raw);
        assert!(!option.is_empty());
    }

    #[test]
    fn dhcpv6_option_model_empty_option_has_empty_payload() {
        let option = Dhcpv6Option::empty(14u16);

        assert_eq!(option.codepoint(), 14);
        assert_eq!(option.payload(), &[]);
        assert_eq!(option.payload_len(), 0);
        assert_eq!(option.format(), Dhcpv6OptionFormat::Empty);
        assert!(option.is_empty());
    }

    #[test]
    fn dhcpv6_option_model_unknown_codes_are_ordinary_codepoints() {
        let code = Dhcpv6OptionCode::from_code(65_000);
        let option = Dhcpv6Option::raw(code, [1, 2, 3].as_slice());

        assert_eq!(u16::from(option.code()), 65_000);
        assert_eq!(option.payload(), &[1, 2, 3]);
    }

    #[test]
    fn dhcpv6_option_model_value_bytes_are_lossless() {
        let mut option =
            Dhcpv6Option::typed(1u16, Dhcpv6OptionValue::Raw(vec![0x00, 0xff, 0x7e, 0x80]));
        assert_eq!(option.value().as_bytes(), &[0x00, 0xff, 0x7e, 0x80]);

        *option.value_mut() = Dhcpv6OptionValue::Empty;
        let (code, value) = option.into_parts();
        assert_eq!(code.code(), 1);
        assert_eq!(value.into_bytes(), Vec::<u8>::new());
    }
}
