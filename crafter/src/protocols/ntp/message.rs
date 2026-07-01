//! NTP fixed-header message field helpers.
//!
//! Source-gated by `.agents/docs/ntp-wire-grammar.md` and
//! `.agents/docs/ntp-codepoints.md`. This module only models packet field
//! values; it does not add synchronization or peer workflow behavior.

use core::fmt;

use super::constants::*;
use super::registry::{ntp_mode_meta, NtpRegistryMeta};

/// Source-backed NTP version field value.
///
/// The version number is the middle three bits of the first NTP fixed-header
/// octet. Unknown or future three-bit values are valid packet data and are
/// preserved for inspection and round-trip construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NtpVersion(u8);

impl NtpVersion {
    /// Build a version value from an already-extracted wire integer.
    pub const fn from_wire(value: u8) -> Self {
        Self(value)
    }

    /// Current source-backed default NTP version.
    pub const fn current() -> Self {
        Self(NTP_VERSION_CURRENT)
    }

    /// Raw version value.
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Raw version value for serialization.
    pub const fn wire_value(self) -> u8 {
        self.value()
    }

    /// Value masked to the three version bits used in the first NTP octet.
    pub const fn first_octet_bits(self) -> u8 {
        self.value() & NTP_VERSION_VALUE_MASK
    }

    /// Stable summary and inspection label.
    pub fn label(self) -> String {
        match self.value() {
            NTP_VERSION_1 => "ntp-v1".to_string(),
            NTP_VERSION_2 => "ntp-v2".to_string(),
            NTP_VERSION_3 => "ntp-v3".to_string(),
            NTP_VERSION_4 => "ntp-v4".to_string(),
            value => format!("version-{value}"),
        }
    }

    /// Stable summary-safe label.
    pub fn summary_label(self) -> String {
        self.label()
    }

    /// Return true for the current default NTP version.
    pub const fn is_current(self) -> bool {
        self.value() == NTP_VERSION_CURRENT
    }
}

impl Default for NtpVersion {
    fn default() -> Self {
        Self::current()
    }
}

impl From<u8> for NtpVersion {
    fn from(value: u8) -> Self {
        Self::from_wire(value)
    }
}

impl From<NtpVersion> for u8 {
    fn from(value: NtpVersion) -> Self {
        value.wire_value()
    }
}

impl fmt::Display for NtpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Source-backed NTP mode field value.
///
/// RFC 5905 defines the complete three-bit mode space. The `Unknown` variant
/// preserves caller-supplied values outside that extracted field space for
/// boundary-packet construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NtpMode {
    /// Reserved mode value 0.
    Reserved,
    /// Symmetric active mode value 1.
    SymmetricActive,
    /// Symmetric passive mode value 2.
    SymmetricPassive,
    /// Client mode value 3.
    Client,
    /// Server mode value 4.
    Server,
    /// Broadcast mode value 5.
    Broadcast,
    /// Control mode value 6.
    Control,
    /// Private-use mode value 7.
    PrivateUse,
    /// Caller-supplied value outside the source-backed three-bit mode space.
    Unknown(u8),
}

impl NtpMode {
    /// Build a mode from an already-extracted wire integer.
    pub const fn from_wire(value: u8) -> Self {
        match value {
            NTP_MODE_RESERVED => Self::Reserved,
            NTP_MODE_SYMMETRIC_ACTIVE => Self::SymmetricActive,
            NTP_MODE_SYMMETRIC_PASSIVE => Self::SymmetricPassive,
            NTP_MODE_CLIENT => Self::Client,
            NTP_MODE_SERVER => Self::Server,
            NTP_MODE_BROADCAST => Self::Broadcast,
            NTP_MODE_CONTROL => Self::Control,
            NTP_MODE_PRIVATE => Self::PrivateUse,
            value => Self::Unknown(value),
        }
    }

    /// Raw mode value.
    pub const fn value(self) -> u8 {
        match self {
            Self::Reserved => NTP_MODE_RESERVED,
            Self::SymmetricActive => NTP_MODE_SYMMETRIC_ACTIVE,
            Self::SymmetricPassive => NTP_MODE_SYMMETRIC_PASSIVE,
            Self::Client => NTP_MODE_CLIENT,
            Self::Server => NTP_MODE_SERVER,
            Self::Broadcast => NTP_MODE_BROADCAST,
            Self::Control => NTP_MODE_CONTROL,
            Self::PrivateUse => NTP_MODE_PRIVATE,
            Self::Unknown(value) => value,
        }
    }

    /// Raw mode value for serialization.
    pub const fn wire_value(self) -> u8 {
        self.value()
    }

    /// Value masked to the three mode bits used in the first NTP octet.
    pub const fn first_octet_bits(self) -> u8 {
        self.value() & NTP_MODE_VALUE_MASK
    }

    /// Source-backed registry metadata for this mode value.
    pub fn registry_meta(self) -> NtpRegistryMeta {
        ntp_mode_meta(self.value())
    }

    /// Stable summary and inspection label.
    pub fn label(self) -> String {
        self.registry_meta().label
    }

    /// Stable summary-safe label.
    pub fn summary_label(self) -> String {
        self.label()
    }
}

impl Default for NtpMode {
    fn default() -> Self {
        Self::Client
    }
}

impl From<u8> for NtpMode {
    fn from(value: u8) -> Self {
        Self::from_wire(value)
    }
}

impl From<NtpMode> for u8 {
    fn from(value: NtpMode) -> Self {
        value.wire_value()
    }
}

impl fmt::Display for NtpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::ntp::NtpRegistryStatus;

    #[test]
    fn ntp_version_mode_version_values_and_labels_preserve_wire_values() {
        let cases = [
            (0, "version-0"),
            (1, "ntp-v1"),
            (2, "ntp-v2"),
            (3, "ntp-v3"),
            (4, "ntp-v4"),
            (5, "version-5"),
            (6, "version-6"),
            (7, "version-7"),
        ];

        for (value, label) in cases {
            let version = NtpVersion::from_wire(value);
            assert_eq!(version.value(), value);
            assert_eq!(version.wire_value(), value);
            assert_eq!(version.first_octet_bits(), value);
            assert_eq!(u8::from(version), value);
            assert_eq!(version.label(), label);
            assert_eq!(version.summary_label(), label);
            assert_eq!(version.to_string(), label);
        }

        assert_eq!(NtpVersion::default(), NtpVersion::current());
        assert!(NtpVersion::current().is_current());
    }

    #[test]
    fn ntp_version_mode_modes_match_source_backed_codepoints() {
        let cases = [
            (NtpMode::Reserved, 0, "reserved", NtpRegistryStatus::Reserved),
            (
                NtpMode::SymmetricActive,
                1,
                "symmetric-active",
                NtpRegistryStatus::Assigned,
            ),
            (
                NtpMode::SymmetricPassive,
                2,
                "symmetric-passive",
                NtpRegistryStatus::Assigned,
            ),
            (NtpMode::Client, 3, "client", NtpRegistryStatus::Assigned),
            (NtpMode::Server, 4, "server", NtpRegistryStatus::Assigned),
            (
                NtpMode::Broadcast,
                5,
                "broadcast",
                NtpRegistryStatus::Assigned,
            ),
            (NtpMode::Control, 6, "control", NtpRegistryStatus::Assigned),
            (
                NtpMode::PrivateUse,
                7,
                "private-use",
                NtpRegistryStatus::PrivateOrExperimental,
            ),
        ];

        for (mode, value, label, status) in cases {
            assert_eq!(NtpMode::from_wire(value), mode);
            assert_eq!(mode.value(), value);
            assert_eq!(mode.wire_value(), value);
            assert_eq!(mode.first_octet_bits(), value);
            assert_eq!(u8::from(mode), value);
            assert_eq!(mode.label(), label);
            assert_eq!(mode.summary_label(), label);
            assert_eq!(mode.to_string(), label);

            let meta = mode.registry_meta();
            assert_eq!(meta.value, u32::from(value));
            assert_eq!(meta.label, label);
            assert_eq!(meta.status, status);
        }

        assert_eq!(NtpMode::default(), NtpMode::Client);
    }

    #[test]
    fn ntp_version_mode_unknown_or_future_values_are_summary_safe() {
        let future_version = NtpVersion::from_wire(7);
        assert_eq!(future_version.value(), 7);
        assert_eq!(future_version.label(), "version-7");
        assert!(!future_version.to_string().chars().any(char::is_whitespace));

        let caller_mode = NtpMode::Unknown(0x2a);
        assert_eq!(caller_mode.value(), 0x2a);
        assert_eq!(caller_mode.wire_value(), 0x2a);
        assert_eq!(caller_mode.first_octet_bits(), 0x2a & NTP_MODE_VALUE_MASK);
        assert_eq!(u8::from(caller_mode), 0x2a);
        assert_eq!(caller_mode.label(), "mode-42");
        assert_eq!(caller_mode.summary_label(), "mode-42");
        assert!(!caller_mode.to_string().chars().any(char::is_whitespace));
    }
}
