//! TLS protocol version helpers.
//!
//! TLS version fields are raw 16-bit wire values. TLS 1.3 keeps legacy
//! `0x0303` values in record and hello fields while negotiating `0x0304`
//! through `supported_versions`, so the helper exposes both contextual
//! constructors without rewriting caller-supplied values.

use core::fmt;

use super::constants::{
    is_tls_grease_u16, tls_protocol_version_label, tls_protocol_version_name,
    tls_protocol_version_status, TlsCodepointStatus, TLS_CURRENT_VERSION, TLS_LEGACY_VERSION,
    TLS_VERSION_1_0, TLS_VERSION_1_1, TLS_VERSION_1_2, TLS_VERSION_1_3, TLS_VERSION_SSL_3_0,
};

/// A raw-preserving TLS `ProtocolVersion` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsVersion {
    raw: u16,
}

impl TlsVersion {
    /// Historical SSL 3.0 version value, preserved by value only.
    pub const SSL_3_0: Self = Self::new(TLS_VERSION_SSL_3_0);
    /// TLS 1.0 protocol version value.
    pub const TLS_1_0: Self = Self::new(TLS_VERSION_1_0);
    /// TLS 1.1 protocol version value.
    pub const TLS_1_1: Self = Self::new(TLS_VERSION_1_1);
    /// TLS 1.2 protocol version value.
    pub const TLS_1_2: Self = Self::new(TLS_VERSION_1_2);
    /// TLS 1.3 `supported_versions` value.
    pub const TLS_1_3: Self = Self::new(TLS_VERSION_1_3);
    /// TLS 1.3-compatible legacy record/hello version value.
    pub const LEGACY_RECORD: Self = Self::new(TLS_LEGACY_VERSION);
    /// TLS 1.3 negotiated version value carried by `supported_versions`.
    pub const NEGOTIATED_TLS_1_3: Self = Self::new(TLS_CURRENT_VERSION);

    /// Preserve a caller-supplied raw 16-bit version value.
    pub const fn new(raw: u16) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied raw 16-bit version value.
    pub const fn from_u16(raw: u16) -> Self {
        Self::new(raw)
    }

    /// Decode a big-endian TLS version value from exactly two bytes.
    pub const fn from_be_bytes(bytes: [u8; 2]) -> Self {
        Self::new(u16::from_be_bytes(bytes))
    }

    /// Historical SSL 3.0 version constructor.
    pub const fn ssl_3_0() -> Self {
        Self::SSL_3_0
    }

    /// TLS 1.0 version constructor.
    pub const fn tls_1_0() -> Self {
        Self::TLS_1_0
    }

    /// TLS 1.1 version constructor.
    pub const fn tls_1_1() -> Self {
        Self::TLS_1_1
    }

    /// TLS 1.2 version constructor.
    pub const fn tls_1_2() -> Self {
        Self::TLS_1_2
    }

    /// TLS 1.3 negotiated-version constructor for `supported_versions`.
    pub const fn tls_1_3() -> Self {
        Self::TLS_1_3
    }

    /// TLS record legacy-version constructor.
    ///
    /// This returns `0x0303`, which is the TLS 1.2 protocol value and the TLS
    /// 1.3 legacy record value. It does not imply TLS 1.3 negotiation.
    pub const fn legacy_record() -> Self {
        Self::LEGACY_RECORD
    }

    /// TLS hello legacy-version constructor.
    ///
    /// ClientHello and ServerHello legacy fields use `0x0303` for TLS 1.3
    /// compatibility; negotiated TLS 1.3 is represented by
    /// [`Self::supported_versions_tls_1_3`].
    pub const fn legacy_hello() -> Self {
        Self::LEGACY_RECORD
    }

    /// TLS 1.3 constructor for the `supported_versions` extension.
    pub const fn supported_versions_tls_1_3() -> Self {
        Self::NEGOTIATED_TLS_1_3
    }

    /// Return the preserved raw 16-bit wire value.
    pub const fn raw(self) -> u16 {
        self.raw
    }

    /// Return the preserved raw 16-bit wire value.
    pub const fn as_u16(self) -> u16 {
        self.raw
    }

    /// Return the big-endian two-byte wire encoding.
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.raw.to_be_bytes()
    }

    /// Return the source-backed version name, when selected.
    pub const fn name(self) -> Option<&'static str> {
        tls_protocol_version_name(self.raw)
    }

    /// Return the source-backed assignment status.
    pub const fn status(self) -> TlsCodepointStatus {
        tls_protocol_version_status(self.raw)
    }

    /// Return true for RFC 8701 sparse GREASE version values.
    pub const fn is_grease(self) -> bool {
        is_tls_grease_u16(self.raw)
    }

    /// Return true when this value is the TLS 1.3 legacy record/hello value.
    pub const fn is_legacy_compatibility_value(self) -> bool {
        self.raw == TLS_LEGACY_VERSION
    }

    /// Return true when this value is the TLS 1.3 `supported_versions` value.
    pub const fn is_supported_versions_tls_1_3(self) -> bool {
        self.raw == TLS_VERSION_1_3
    }

    /// Human-readable label preserving unknown values numerically.
    pub fn label(self) -> String {
        tls_protocol_version_label(self.raw)
    }

    /// Stable inspection summary with raw value and source-backed status.
    pub fn inspection_label(self) -> String {
        format!(
            "{} raw=0x{:04x} status={}",
            self.label(),
            self.raw,
            self.status().label()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        self.inspection_fields_for(TlsVersionField::ProtocolVersion)
    }

    /// Stable field/value pairs for contextual packet inspection output.
    pub fn inspection_fields_for(self, field: TlsVersionField) -> Vec<(&'static str, String)> {
        vec![
            ("field", field.label().to_string()),
            ("role", field.role().to_string()),
            ("version", self.label()),
            ("raw", format!("0x{:04x}", self.raw)),
            ("status", self.status().label().to_string()),
        ]
    }
}

impl From<u16> for TlsVersion {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<TlsVersion> for u16 {
    fn from(value: TlsVersion) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Context for inspecting a TLS version-bearing field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersionField {
    /// Generic TLS `ProtocolVersion` value.
    ProtocolVersion,
    /// TLS record header legacy record-version field.
    LegacyRecordVersion,
    /// ClientHello or ServerHello legacy-version field.
    LegacyHelloVersion,
    /// TLS `supported_versions` extension value.
    SupportedVersions,
}

impl TlsVersionField {
    /// Stable field label for summaries and inspection output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::ProtocolVersion => "protocol_version",
            Self::LegacyRecordVersion => "legacy_record_version",
            Self::LegacyHelloVersion => "legacy_version",
            Self::SupportedVersions => "supported_versions",
        }
    }

    /// Stable semantic role label for summaries and inspection output.
    pub const fn role(self) -> &'static str {
        match self {
            Self::ProtocolVersion => "protocol version",
            Self::LegacyRecordVersion => "record compatibility field",
            Self::LegacyHelloVersion => "hello compatibility field",
            Self::SupportedVersions => "negotiated version extension value",
        }
    }
}

impl fmt::Display for TlsVersionField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_version_known_constructors_expose_raw_values() {
        assert_eq!(TlsVersion::ssl_3_0().raw(), TLS_VERSION_SSL_3_0);
        assert_eq!(TlsVersion::tls_1_0().raw(), TLS_VERSION_1_0);
        assert_eq!(TlsVersion::tls_1_1().raw(), TLS_VERSION_1_1);
        assert_eq!(TlsVersion::tls_1_2().raw(), TLS_VERSION_1_2);
        assert_eq!(TlsVersion::tls_1_3().raw(), TLS_VERSION_1_3);
        assert_eq!(TlsVersion::from_be_bytes([0x03, 0x04]), TlsVersion::TLS_1_3);
        assert_eq!(TlsVersion::TLS_1_3.to_be_bytes(), [0x03, 0x04]);
    }

    #[test]
    fn tls_version_distinguishes_legacy_record_from_supported_versions() {
        let record_legacy = TlsVersion::legacy_record();
        let hello_legacy = TlsVersion::legacy_hello();
        let negotiated = TlsVersion::supported_versions_tls_1_3();

        assert_eq!(record_legacy.raw(), TLS_LEGACY_VERSION);
        assert_eq!(hello_legacy.raw(), TLS_VERSION_1_2);
        assert_eq!(negotiated.raw(), TLS_CURRENT_VERSION);
        assert_ne!(record_legacy, negotiated);
        assert!(record_legacy.is_legacy_compatibility_value());
        assert!(!record_legacy.is_supported_versions_tls_1_3());
        assert!(negotiated.is_supported_versions_tls_1_3());
    }

    #[test]
    fn tls_version_labels_and_statuses_reuse_constants() {
        let tls12 = TlsVersion::TLS_1_2;
        let grease = TlsVersion::from_u16(0x7a7a);
        let unknown = TlsVersion::from_u16(0x4242);

        assert_eq!(tls12.name(), Some("TLS 1.2"));
        assert_eq!(tls12.status(), TlsCodepointStatus::DefaultEligible);
        assert_eq!(tls12.label(), "TLS 1.2");
        assert_eq!(tls12.to_string(), "TLS 1.2");
        assert!(grease.is_grease());
        assert_eq!(grease.status(), TlsCodepointStatus::ReservedGrease);
        assert_eq!(grease.label(), "reserved grease protocol version 0x7a7a");
        assert_eq!(unknown.status(), TlsCodepointStatus::Unknown);
        assert_eq!(unknown.label(), "unknown protocol version 0x4242");
    }

    #[test]
    fn tls_version_inspection_output_includes_context_and_raw_value() {
        let legacy_fields =
            TlsVersion::legacy_record().inspection_fields_for(TlsVersionField::LegacyRecordVersion);
        assert!(legacy_fields.contains(&("field", "legacy_record_version".to_string())));
        assert!(legacy_fields.contains(&("role", "record compatibility field".to_string())));
        assert!(legacy_fields.contains(&("version", "TLS 1.2".to_string())));
        assert!(legacy_fields.contains(&("raw", "0x0303".to_string())));
        assert!(legacy_fields.contains(&("status", "default-eligible".to_string())));

        let supported_fields = TlsVersion::supported_versions_tls_1_3()
            .inspection_fields_for(TlsVersionField::SupportedVersions);
        assert!(supported_fields.contains(&("field", "supported_versions".to_string())));
        assert!(
            supported_fields.contains(&("role", "negotiated version extension value".to_string()))
        );
        assert!(supported_fields.contains(&("version", "TLS 1.3".to_string())));
        assert!(supported_fields.contains(&("raw", "0x0304".to_string())));

        assert_eq!(
            TlsVersion::from_u16(0x4242).inspection_label(),
            "unknown protocol version 0x4242 raw=0x4242 status=unknown"
        );
    }
}
