//! TLS alert helpers.
//!
//! Alert levels and descriptions are raw one-octet values. The typed helpers
//! delegate names and status labels to the source-backed constants table while
//! preserving every caller-supplied or decoded value for malformed packet work.

use core::fmt;

use super::constants::{self, TlsCodepointStatus};
use crate::{CrafterError, Result};

/// TLS alert message length in bytes: `AlertLevel | AlertDescription`.
pub const TLS_ALERT_LEN: usize = 2;

/// A raw-preserving TLS `AlertLevel` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsAlertLevel {
    raw: u8,
}

impl TlsAlertLevel {
    /// TLS `warning` alert level.
    pub const WARNING: Self = Self::new(constants::TLS_ALERT_LEVEL_WARNING);
    /// TLS `fatal` alert level.
    pub const FATAL: Self = Self::new(constants::TLS_ALERT_LEVEL_FATAL);

    /// Preserve a caller-supplied raw one-octet alert level.
    pub const fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied raw one-octet alert level.
    pub const fn from_u8(raw: u8) -> Self {
        Self::new(raw)
    }

    /// TLS `warning` constructor.
    pub const fn warning() -> Self {
        Self::WARNING
    }

    /// TLS `fatal` constructor.
    pub const fn fatal() -> Self {
        Self::FATAL
    }

    /// Return the preserved raw one-octet wire value.
    pub const fn raw(self) -> u8 {
        self.raw
    }

    /// Return the preserved raw one-octet wire value.
    pub const fn as_u8(self) -> u8 {
        self.raw
    }

    /// Return the one-byte wire encoding.
    pub const fn to_byte(self) -> u8 {
        self.raw
    }

    /// Return the source-backed alert level name, when selected.
    pub const fn name(self) -> Option<&'static str> {
        constants::tls_alert_level_name(self.raw)
    }

    /// Return the source-backed assignment status.
    pub const fn status(self) -> TlsCodepointStatus {
        constants::tls_alert_level_status(self.raw)
    }

    /// Return true when this level has a selected source-backed name.
    pub const fn is_known(self) -> bool {
        self.name().is_some()
    }

    /// Human-readable label preserving unknown values numerically.
    pub fn label(self) -> String {
        constants::tls_alert_level_label(self.raw)
    }

    /// Stable one-line summary with raw value and source-backed status.
    pub fn summary(self) -> String {
        format!(
            "{} raw=0x{:02x} status={}",
            self.label(),
            self.raw,
            self.status().label()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("alert_level", self.label()),
            ("alert_level_raw", format!("0x{:02x}", self.raw)),
            ("alert_level_status", self.status().label().to_string()),
        ]
    }
}

impl From<u8> for TlsAlertLevel {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<TlsAlertLevel> for u8 {
    fn from(value: TlsAlertLevel) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsAlertLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// A raw-preserving TLS `AlertDescription` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsAlertDescription {
    raw: u8,
}

impl TlsAlertDescription {
    /// TLS `close_notify` alert description.
    pub const CLOSE_NOTIFY: Self = Self::new(constants::TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY);
    /// TLS `unexpected_message` alert description.
    pub const UNEXPECTED_MESSAGE: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_UNEXPECTED_MESSAGE);
    /// TLS `bad_record_mac` alert description.
    pub const BAD_RECORD_MAC: Self = Self::new(constants::TLS_ALERT_DESCRIPTION_BAD_RECORD_MAC);
    /// TLS `decryption_failed_RESERVED` alert description.
    pub const DECRYPTION_FAILED_RESERVED: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_DECRYPTION_FAILED_RESERVED);
    /// TLS `record_overflow` alert description.
    pub const RECORD_OVERFLOW: Self = Self::new(constants::TLS_ALERT_DESCRIPTION_RECORD_OVERFLOW);
    /// TLS `decompression_failure_RESERVED` alert description.
    pub const DECOMPRESSION_FAILURE_RESERVED: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_DECOMPRESSION_FAILURE_RESERVED);
    /// TLS `handshake_failure` alert description.
    pub const HANDSHAKE_FAILURE: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_HANDSHAKE_FAILURE);
    /// TLS `no_certificate_RESERVED` alert description.
    pub const NO_CERTIFICATE_RESERVED: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_NO_CERTIFICATE_RESERVED);
    /// TLS `bad_certificate` alert description.
    pub const BAD_CERTIFICATE: Self = Self::new(constants::TLS_ALERT_DESCRIPTION_BAD_CERTIFICATE);
    /// TLS `unsupported_certificate` alert description.
    pub const UNSUPPORTED_CERTIFICATE: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_UNSUPPORTED_CERTIFICATE);
    /// TLS `certificate_revoked` alert description.
    pub const CERTIFICATE_REVOKED: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_CERTIFICATE_REVOKED);
    /// TLS `certificate_expired` alert description.
    pub const CERTIFICATE_EXPIRED: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_CERTIFICATE_EXPIRED);
    /// TLS `certificate_unknown` alert description.
    pub const CERTIFICATE_UNKNOWN: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_CERTIFICATE_UNKNOWN);
    /// TLS `illegal_parameter` alert description.
    pub const ILLEGAL_PARAMETER: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_ILLEGAL_PARAMETER);
    /// TLS `unknown_ca` alert description.
    pub const UNKNOWN_CA: Self = Self::new(constants::TLS_ALERT_DESCRIPTION_UNKNOWN_CA);
    /// TLS `access_denied` alert description.
    pub const ACCESS_DENIED: Self = Self::new(constants::TLS_ALERT_DESCRIPTION_ACCESS_DENIED);
    /// TLS `decode_error` alert description.
    pub const DECODE_ERROR: Self = Self::new(constants::TLS_ALERT_DESCRIPTION_DECODE_ERROR);
    /// TLS `decrypt_error` alert description.
    pub const DECRYPT_ERROR: Self = Self::new(constants::TLS_ALERT_DESCRIPTION_DECRYPT_ERROR);
    /// TLS `too_many_cids_requested` alert description.
    pub const TOO_MANY_CIDS_REQUESTED: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_TOO_MANY_CIDS_REQUESTED);
    /// TLS `export_restriction_RESERVED` alert description.
    pub const EXPORT_RESTRICTION_RESERVED: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_EXPORT_RESTRICTION_RESERVED);
    /// TLS `protocol_version` alert description.
    pub const PROTOCOL_VERSION: Self = Self::new(constants::TLS_ALERT_DESCRIPTION_PROTOCOL_VERSION);
    /// TLS `insufficient_security` alert description.
    pub const INSUFFICIENT_SECURITY: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_INSUFFICIENT_SECURITY);
    /// TLS `internal_error` alert description.
    pub const INTERNAL_ERROR: Self = Self::new(constants::TLS_ALERT_DESCRIPTION_INTERNAL_ERROR);
    /// TLS `inappropriate_fallback` alert description.
    pub const INAPPROPRIATE_FALLBACK: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_INAPPROPRIATE_FALLBACK);
    /// TLS `user_canceled` alert description.
    pub const USER_CANCELED: Self = Self::new(constants::TLS_ALERT_DESCRIPTION_USER_CANCELED);
    /// TLS `no_renegotiation_RESERVED` alert description.
    pub const NO_RENEGOTIATION_RESERVED: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_NO_RENEGOTIATION_RESERVED);
    /// TLS `missing_extension` alert description.
    pub const MISSING_EXTENSION: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_MISSING_EXTENSION);
    /// TLS `unsupported_extension` alert description.
    pub const UNSUPPORTED_EXTENSION: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_UNSUPPORTED_EXTENSION);
    /// TLS `certificate_unobtainable_RESERVED` alert description.
    pub const CERTIFICATE_UNOBTAINABLE_RESERVED: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_CERTIFICATE_UNOBTAINABLE_RESERVED);
    /// TLS `unrecognized_name` alert description.
    pub const UNRECOGNIZED_NAME: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_UNRECOGNIZED_NAME);
    /// TLS `bad_certificate_status_response` alert description.
    pub const BAD_CERTIFICATE_STATUS_RESPONSE: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_BAD_CERTIFICATE_STATUS_RESPONSE);
    /// TLS `bad_certificate_hash_value_RESERVED` alert description.
    pub const BAD_CERTIFICATE_HASH_VALUE_RESERVED: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_BAD_CERTIFICATE_HASH_VALUE_RESERVED);
    /// TLS `unknown_psk_identity` alert description.
    pub const UNKNOWN_PSK_IDENTITY: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_UNKNOWN_PSK_IDENTITY);
    /// TLS `certificate_required` alert description.
    pub const CERTIFICATE_REQUIRED: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_CERTIFICATE_REQUIRED);
    /// TLS `general_error` alert description.
    pub const GENERAL_ERROR: Self = Self::new(constants::TLS_ALERT_DESCRIPTION_GENERAL_ERROR);
    /// TLS `no_application_protocol` alert description.
    pub const NO_APPLICATION_PROTOCOL: Self =
        Self::new(constants::TLS_ALERT_DESCRIPTION_NO_APPLICATION_PROTOCOL);
    /// TLS `ech_required` alert description.
    pub const ECH_REQUIRED: Self = Self::new(constants::TLS_ALERT_DESCRIPTION_ECH_REQUIRED);

    /// Preserve a caller-supplied raw one-octet alert description.
    pub const fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied raw one-octet alert description.
    pub const fn from_u8(raw: u8) -> Self {
        Self::new(raw)
    }

    /// TLS `close_notify` constructor.
    pub const fn close_notify() -> Self {
        Self::CLOSE_NOTIFY
    }

    /// TLS `unexpected_message` constructor.
    pub const fn unexpected_message() -> Self {
        Self::UNEXPECTED_MESSAGE
    }

    /// TLS `bad_record_mac` constructor.
    pub const fn bad_record_mac() -> Self {
        Self::BAD_RECORD_MAC
    }

    /// TLS `record_overflow` constructor.
    pub const fn record_overflow() -> Self {
        Self::RECORD_OVERFLOW
    }

    /// TLS `handshake_failure` constructor.
    pub const fn handshake_failure() -> Self {
        Self::HANDSHAKE_FAILURE
    }

    /// TLS `decode_error` constructor.
    pub const fn decode_error() -> Self {
        Self::DECODE_ERROR
    }

    /// TLS `decrypt_error` constructor.
    pub const fn decrypt_error() -> Self {
        Self::DECRYPT_ERROR
    }

    /// TLS `internal_error` constructor.
    pub const fn internal_error() -> Self {
        Self::INTERNAL_ERROR
    }

    /// TLS `protocol_version` constructor.
    pub const fn protocol_version() -> Self {
        Self::PROTOCOL_VERSION
    }

    /// TLS `unknown_ca` constructor.
    pub const fn unknown_ca() -> Self {
        Self::UNKNOWN_CA
    }

    /// TLS `no_application_protocol` constructor.
    pub const fn no_application_protocol() -> Self {
        Self::NO_APPLICATION_PROTOCOL
    }

    /// Return the preserved raw one-octet wire value.
    pub const fn raw(self) -> u8 {
        self.raw
    }

    /// Return the preserved raw one-octet wire value.
    pub const fn as_u8(self) -> u8 {
        self.raw
    }

    /// Return the one-byte wire encoding.
    pub const fn to_byte(self) -> u8 {
        self.raw
    }

    /// Return the source-backed alert description name, when selected.
    pub const fn name(self) -> Option<&'static str> {
        constants::tls_alert_description_name(self.raw)
    }

    /// Return the source-backed assignment status.
    pub const fn status(self) -> TlsCodepointStatus {
        constants::tls_alert_description_status(self.raw)
    }

    /// Return true when this description has a selected source-backed name.
    pub const fn is_known(self) -> bool {
        self.name().is_some()
    }

    /// Human-readable label preserving unknown values numerically.
    pub fn label(self) -> String {
        constants::tls_alert_description_label(self.raw)
    }

    /// Stable one-line summary with raw value and source-backed status.
    pub fn summary(self) -> String {
        format!(
            "{} raw=0x{:02x} status={}",
            self.label(),
            self.raw,
            self.status().label()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("alert_description", self.label()),
            ("alert_description_raw", format!("0x{:02x}", self.raw)),
            (
                "alert_description_status",
                self.status().label().to_string(),
            ),
        ]
    }
}

impl From<u8> for TlsAlertDescription {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<TlsAlertDescription> for u8 {
    fn from(value: TlsAlertDescription) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsAlertDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// TLS alert message (`AlertLevel | AlertDescription`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsAlert {
    level: TlsAlertLevel,
    description: TlsAlertDescription,
}

impl TlsAlert {
    /// Create an alert from raw-preserving level and description values.
    pub const fn new(level: TlsAlertLevel, description: TlsAlertDescription) -> Self {
        Self { level, description }
    }

    /// Preserve caller-supplied raw level and description bytes.
    pub const fn from_raw(level: u8, description: u8) -> Self {
        Self::new(
            TlsAlertLevel::new(level),
            TlsAlertDescription::new(description),
        )
    }

    /// Create a warning alert with the supplied description.
    pub const fn warning(description: TlsAlertDescription) -> Self {
        Self::new(TlsAlertLevel::WARNING, description)
    }

    /// Create a fatal alert with the supplied description.
    pub const fn fatal(description: TlsAlertDescription) -> Self {
        Self::new(TlsAlertLevel::FATAL, description)
    }

    /// Common `warning close_notify` alert.
    pub const fn close_notify() -> Self {
        Self::warning(TlsAlertDescription::CLOSE_NOTIFY)
    }

    /// Common `fatal unexpected_message` alert.
    pub const fn unexpected_message() -> Self {
        Self::fatal(TlsAlertDescription::UNEXPECTED_MESSAGE)
    }

    /// Common `fatal bad_record_mac` alert.
    pub const fn bad_record_mac() -> Self {
        Self::fatal(TlsAlertDescription::BAD_RECORD_MAC)
    }

    /// Common `fatal record_overflow` alert.
    pub const fn record_overflow() -> Self {
        Self::fatal(TlsAlertDescription::RECORD_OVERFLOW)
    }

    /// Common `fatal handshake_failure` alert.
    pub const fn handshake_failure() -> Self {
        Self::fatal(TlsAlertDescription::HANDSHAKE_FAILURE)
    }

    /// Common `fatal decode_error` alert.
    pub const fn decode_error() -> Self {
        Self::fatal(TlsAlertDescription::DECODE_ERROR)
    }

    /// Common `fatal decrypt_error` alert.
    pub const fn decrypt_error() -> Self {
        Self::fatal(TlsAlertDescription::DECRYPT_ERROR)
    }

    /// Common `fatal internal_error` alert.
    pub const fn internal_error() -> Self {
        Self::fatal(TlsAlertDescription::INTERNAL_ERROR)
    }

    /// Common `fatal protocol_version` alert.
    pub const fn protocol_version() -> Self {
        Self::fatal(TlsAlertDescription::PROTOCOL_VERSION)
    }

    /// Common `fatal unknown_ca` alert.
    pub const fn unknown_ca() -> Self {
        Self::fatal(TlsAlertDescription::UNKNOWN_CA)
    }

    /// Common `fatal no_application_protocol` alert.
    pub const fn no_application_protocol() -> Self {
        Self::fatal(TlsAlertDescription::NO_APPLICATION_PROTOCOL)
    }

    /// Return the raw-preserving alert level.
    pub const fn level(self) -> TlsAlertLevel {
        self.level
    }

    /// Return the raw-preserving alert description.
    pub const fn description(self) -> TlsAlertDescription {
        self.description
    }

    /// Return the preserved raw level byte.
    pub const fn level_raw(self) -> u8 {
        self.level.raw()
    }

    /// Return the preserved raw description byte.
    pub const fn description_raw(self) -> u8 {
        self.description.raw()
    }

    /// Return the fixed two-byte wire encoding.
    pub const fn to_bytes(self) -> [u8; TLS_ALERT_LEN] {
        [self.level.raw(), self.description.raw()]
    }

    /// Append the fixed two-byte wire encoding to `out`.
    pub fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_bytes());
    }

    /// Return the fixed two-byte wire encoding as a vector.
    pub fn encode_to_vec(self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    /// Decode a TLS alert from the first two bytes of `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (alert, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(alert)
    }

    /// Decode a TLS alert from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_ALERT_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.alert",
                TLS_ALERT_LEN,
                bytes.len(),
            ));
        }

        Ok((Self::from_raw(bytes[0], bytes[1]), &bytes[TLS_ALERT_LEN..]))
    }

    /// Stable one-line summary preserving raw labels.
    pub fn summary(self) -> String {
        format!(
            "alert level={} description={}",
            self.level.label(),
            self.description.label()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("alert_level", self.level.label()),
            ("alert_level_raw", format!("0x{:02x}", self.level.raw())),
            (
                "alert_level_status",
                self.level.status().label().to_string(),
            ),
            ("alert_description", self.description.label()),
            (
                "alert_description_raw",
                format!("0x{:02x}", self.description.raw()),
            ),
            (
                "alert_description_status",
                self.description.status().label().to_string(),
            ),
            (
                "alert_wire",
                format!("{:02x} {:02x}", self.level.raw(), self.description.raw()),
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_alert_warning_and_fatal_builders_round_trip() {
        let close_notify = TlsAlert::close_notify();
        assert_eq!(close_notify.level(), TlsAlertLevel::WARNING);
        assert_eq!(
            close_notify.description(),
            TlsAlertDescription::CLOSE_NOTIFY
        );
        assert_eq!(close_notify.to_bytes(), [0x01, 0x00]);
        assert_eq!(close_notify.encode_to_vec(), vec![0x01, 0x00]);
        assert_eq!(
            close_notify.summary(),
            "alert level=warning description=close_notify"
        );

        let decode_error = TlsAlert::decode_error();
        let mut encoded = Vec::new();
        decode_error.encode(&mut encoded);
        assert_eq!(encoded, [0x02, 0x32]);
        assert_eq!(TlsAlert::decode(&encoded).unwrap(), decode_error);
        assert_eq!(
            TlsAlert::decode_prefix(&[0x02, 0x32, 0xaa]).unwrap(),
            (decode_error, &[0xaa][..])
        );
        assert_eq!(
            decode_error.summary(),
            "alert level=fatal description=decode_error"
        );

        let fields = decode_error.inspection_fields();
        assert!(fields.contains(&("alert_level", "fatal".to_string())));
        assert!(fields.contains(&("alert_level_raw", "0x02".to_string())));
        assert!(fields.contains(&("alert_level_status", "default-eligible".to_string())));
        assert!(fields.contains(&("alert_description", "decode_error".to_string())));
        assert!(fields.contains(&("alert_description_raw", "0x32".to_string())));
        assert!(fields.contains(&("alert_description_status", "label-eligible".to_string())));
        assert!(fields.contains(&("alert_wire", "02 32".to_string())));
    }

    #[test]
    fn tls_alert_unknown_description_and_invalid_combinations_are_preserved() {
        let unknown_description = TlsAlert::from_raw(0x02, 0xfe);
        assert_eq!(unknown_description.level_raw(), 0x02);
        assert_eq!(unknown_description.description_raw(), 0xfe);
        assert_eq!(unknown_description.description().name(), None);
        assert_eq!(
            unknown_description.description().label(),
            "unassigned alert description 0xfe"
        );
        assert_eq!(
            unknown_description.summary(),
            "alert level=fatal description=unassigned alert description 0xfe"
        );
        assert_eq!(unknown_description.to_bytes(), [0x02, 0xfe]);

        let invalid_level = TlsAlert::from_raw(0x7f, 0x00);
        assert_eq!(invalid_level.level().name(), None);
        assert_eq!(
            invalid_level.level().status(),
            TlsCodepointStatus::Unassigned
        );
        assert_eq!(invalid_level.to_bytes(), [0x7f, 0x00]);
        assert_eq!(
            invalid_level.summary(),
            "alert level=unassigned alert level 0x7f description=close_notify"
        );

        let intentionally_odd = TlsAlert::fatal(TlsAlertDescription::CLOSE_NOTIFY);
        assert_eq!(intentionally_odd.to_bytes(), [0x02, 0x00]);
        assert_eq!(
            intentionally_odd.summary(),
            "alert level=fatal description=close_notify"
        );
    }

    #[test]
    fn tls_alert_level_and_description_helpers_reuse_constants() {
        assert_eq!(
            TlsAlertLevel::warning().raw(),
            constants::TLS_ALERT_LEVEL_WARNING
        );
        assert_eq!(
            TlsAlertLevel::fatal().raw(),
            constants::TLS_ALERT_LEVEL_FATAL
        );
        assert_eq!(TlsAlertLevel::FATAL.name(), Some("fatal"));
        assert_eq!(
            TlsAlertLevel::FATAL.status(),
            TlsCodepointStatus::DefaultEligible
        );
        assert_eq!(
            TlsAlertLevel::from_u8(0x09).summary(),
            "unassigned alert level 0x09 raw=0x09 status=unassigned"
        );

        assert_eq!(
            TlsAlertDescription::decode_error().raw(),
            constants::TLS_ALERT_DESCRIPTION_DECODE_ERROR
        );
        assert_eq!(
            TlsAlertDescription::DECODE_ERROR.name(),
            Some("decode_error")
        );
        assert_eq!(
            TlsAlertDescription::DECRYPTION_FAILED_RESERVED.status(),
            TlsCodepointStatus::PreserveOnly
        );
        assert_eq!(
            TlsAlertDescription::from_u8(0x07).summary(),
            "unassigned alert description 0x07 raw=0x07 status=unassigned"
        );
    }

    #[test]
    fn tls_alert_decode_short_buffer_is_structured_error() {
        assert_eq!(
            TlsAlert::decode([0x02]).unwrap_err(),
            CrafterError::buffer_too_short("tls.alert", TLS_ALERT_LEN, 1)
        );
    }
}
