//! TLS record content type helpers.
//!
//! TLS `ContentType` is a raw one-octet record-header value. The model keeps
//! every observed or caller-supplied value intact so unsupported or future
//! content types can still be represented as opaque record fragments.

use core::fmt;

use super::constants::{
    tls_content_type_label, tls_content_type_name, tls_content_type_status, TlsCodepointStatus,
    TLS_CONTENT_TYPE_ACK, TLS_CONTENT_TYPE_ALERT, TLS_CONTENT_TYPE_APPLICATION_DATA,
    TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC, TLS_CONTENT_TYPE_HANDSHAKE, TLS_CONTENT_TYPE_HEARTBEAT,
    TLS_CONTENT_TYPE_RETURN_ROUTABILITY_CHECK, TLS_CONTENT_TYPE_TLS12_CID,
};

/// A raw-preserving TLS record `ContentType` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsContentType {
    raw: u8,
}

impl TlsContentType {
    /// TLS record `change_cipher_spec` content type.
    pub const CHANGE_CIPHER_SPEC: Self = Self::new(TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC);
    /// TLS record `alert` content type.
    pub const ALERT: Self = Self::new(TLS_CONTENT_TYPE_ALERT);
    /// TLS record `handshake` content type.
    pub const HANDSHAKE: Self = Self::new(TLS_CONTENT_TYPE_HANDSHAKE);
    /// TLS record `application_data` content type.
    pub const APPLICATION_DATA: Self = Self::new(TLS_CONTENT_TYPE_APPLICATION_DATA);
    /// TLS record `heartbeat` content type, selected for packet-only modeling.
    pub const HEARTBEAT: Self = Self::new(TLS_CONTENT_TYPE_HEARTBEAT);
    /// TLS record `tls12_cid` content type, preserved for explicit values.
    pub const TLS12_CID: Self = Self::new(TLS_CONTENT_TYPE_TLS12_CID);
    /// DTLS ACK content type, preserved by value when observed in a TLS record.
    pub const ACK: Self = Self::new(TLS_CONTENT_TYPE_ACK);
    /// DTLS return_routability_check content type, preserved by value when observed.
    pub const RETURN_ROUTABILITY_CHECK: Self = Self::new(TLS_CONTENT_TYPE_RETURN_ROUTABILITY_CHECK);

    /// Preserve a caller-supplied raw one-octet content type.
    pub const fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied raw one-octet content type.
    pub const fn from_u8(raw: u8) -> Self {
        Self::new(raw)
    }

    /// TLS record `change_cipher_spec` constructor.
    pub const fn change_cipher_spec() -> Self {
        Self::CHANGE_CIPHER_SPEC
    }

    /// TLS record `alert` constructor.
    pub const fn alert() -> Self {
        Self::ALERT
    }

    /// TLS record `handshake` constructor.
    pub const fn handshake() -> Self {
        Self::HANDSHAKE
    }

    /// TLS record `application_data` constructor.
    pub const fn application_data() -> Self {
        Self::APPLICATION_DATA
    }

    /// TLS record `heartbeat` constructor.
    pub const fn heartbeat() -> Self {
        Self::HEARTBEAT
    }

    /// TLS record `tls12_cid` constructor.
    pub const fn tls12_cid() -> Self {
        Self::TLS12_CID
    }

    /// DTLS ACK constructor for raw preservation.
    pub const fn ack() -> Self {
        Self::ACK
    }

    /// DTLS return_routability_check constructor for raw preservation.
    pub const fn return_routability_check() -> Self {
        Self::RETURN_ROUTABILITY_CHECK
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

    /// Return the source-backed content type name, when selected.
    pub const fn name(self) -> Option<&'static str> {
        tls_content_type_name(self.raw)
    }

    /// Return the source-backed assignment status.
    pub const fn status(self) -> TlsCodepointStatus {
        tls_content_type_status(self.raw)
    }

    /// Return true when this content type has a selected source-backed name.
    pub const fn is_known(self) -> bool {
        self.name().is_some()
    }

    /// Return true for content types selected for default TLS-over-TCP behavior.
    pub const fn is_default_eligible(self) -> bool {
        matches!(self.status(), TlsCodepointStatus::DefaultEligible)
    }

    /// Return true when an enclosing valid TLS record may preserve the fragment as opaque bytes.
    ///
    /// TLS record validity is determined by the enclosing record header and
    /// length. The content type model never rejects unknown, reserved,
    /// deferred, or DTLS-only values by itself.
    pub const fn allows_opaque_fragment(self) -> bool {
        true
    }

    /// Human-readable label preserving unknown values numerically.
    pub fn label(self) -> String {
        tls_content_type_label(self.raw)
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
            ("content_type", self.label()),
            ("raw", format!("0x{:02x}", self.raw)),
            ("status", self.status().label().to_string()),
            ("opaque_fragment", self.allows_opaque_fragment().to_string()),
        ]
    }
}

impl From<u8> for TlsContentType {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<TlsContentType> for u8 {
    fn from(value: TlsContentType) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_content_type_known_constructors_expose_raw_values() {
        assert_eq!(
            TlsContentType::change_cipher_spec().raw(),
            TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC
        );
        assert_eq!(TlsContentType::alert().raw(), TLS_CONTENT_TYPE_ALERT);
        assert_eq!(
            TlsContentType::handshake().raw(),
            TLS_CONTENT_TYPE_HANDSHAKE
        );
        assert_eq!(
            TlsContentType::application_data().raw(),
            TLS_CONTENT_TYPE_APPLICATION_DATA
        );
        assert_eq!(
            TlsContentType::heartbeat().raw(),
            TLS_CONTENT_TYPE_HEARTBEAT
        );
        assert_eq!(
            TlsContentType::tls12_cid().raw(),
            TLS_CONTENT_TYPE_TLS12_CID
        );
        assert_eq!(TlsContentType::ack().raw(), TLS_CONTENT_TYPE_ACK);
        assert_eq!(
            TlsContentType::return_routability_check().raw(),
            TLS_CONTENT_TYPE_RETURN_ROUTABILITY_CHECK
        );
        assert_eq!(TlsContentType::from_u8(0x16), TlsContentType::HANDSHAKE);
        assert_eq!(TlsContentType::HANDSHAKE.to_byte(), 0x16);
    }

    #[test]
    fn tls_content_type_labels_and_statuses_reuse_constants() {
        let handshake = TlsContentType::HANDSHAKE;
        let heartbeat = TlsContentType::HEARTBEAT;
        let ack = TlsContentType::ACK;
        let reserved = TlsContentType::from_u8(0x30);
        let unassigned = TlsContentType::from_u8(0x7f);

        assert_eq!(handshake.name(), Some("handshake"));
        assert_eq!(handshake.status(), TlsCodepointStatus::DefaultEligible);
        assert_eq!(handshake.label(), "handshake");
        assert_eq!(handshake.to_string(), "handshake");
        assert!(handshake.is_known());
        assert!(handshake.is_default_eligible());

        assert_eq!(heartbeat.status(), TlsCodepointStatus::LabelEligible);
        assert_eq!(heartbeat.label(), "heartbeat");
        assert!(!heartbeat.is_default_eligible());

        assert_eq!(ack.status(), TlsCodepointStatus::DtlsOnly);
        assert_eq!(ack.label(), "ACK");

        assert_eq!(reserved.name(), None);
        assert_eq!(reserved.status(), TlsCodepointStatus::Reserved);
        assert_eq!(reserved.label(), "reserved content type 0x30");

        assert_eq!(unassigned.status(), TlsCodepointStatus::Unassigned);
        assert_eq!(unassigned.label(), "unassigned content type 0x7f");
    }

    #[test]
    fn tls_content_type_unknown_values_are_preserved_without_rejection() {
        for raw in [0x00, 0x18, 0x19, 0x1a, 0x30, 0x7f, 0xff] {
            let content_type = TlsContentType::from_u8(raw);

            assert_eq!(content_type.raw(), raw);
            assert_eq!(content_type.as_u8(), raw);
            assert_eq!(u8::from(content_type), raw);
            assert!(content_type.allows_opaque_fragment());
        }
    }

    #[test]
    fn tls_content_type_summary_and_inspection_include_raw_and_status() {
        let handshake = TlsContentType::HANDSHAKE;
        assert_eq!(
            handshake.summary(),
            "handshake raw=0x16 status=default-eligible"
        );
        assert_eq!(
            handshake.inspection_fields(),
            vec![
                ("content_type", "handshake".to_string()),
                ("raw", "0x16".to_string()),
                ("status", "default-eligible".to_string()),
                ("opaque_fragment", "true".to_string()),
            ]
        );

        let unknown = TlsContentType::from_u8(0xff);
        assert_eq!(
            unknown.summary(),
            "unassigned content type 0xff raw=0xff status=unassigned"
        );
        assert!(unknown
            .inspection_fields()
            .contains(&("content_type", "unassigned content type 0xff".to_string(),)));
    }
}
