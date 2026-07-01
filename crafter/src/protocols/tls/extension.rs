//! TLS extension type helpers.
//!
//! TLS extensions are length-prefixed entries keyed by a raw two-octet
//! `ExtensionType`. This module models the codepoint and a single raw
//! extension entry so unknown or deferred extension bodies stay round-trippable.
//! Full extension-list parsing and typed bodies are added in later
//! source-backed steps.

use core::fmt;

use super::constants::{self, TlsCodepointStatus};
use crate::{CrafterError, Result};

/// TLS ExtensionType codepoint width in bytes.
pub const TLS_EXTENSION_TYPE_LEN: usize = 2;
/// TLS extension body length field width in bytes.
pub const TLS_EXTENSION_LENGTH_LEN: usize = 2;
/// TLS extension entry header width in bytes.
pub const TLS_EXTENSION_HEADER_LEN: usize = TLS_EXTENSION_TYPE_LEN + TLS_EXTENSION_LENGTH_LEN;

/// A raw-preserving TLS `ExtensionType` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsExtensionType {
    raw: u16,
}

impl TlsExtensionType {
    /// TLS ExtensionType `server_name`.
    pub const SERVER_NAME: Self = Self::new(constants::TLS_EXTENSION_SERVER_NAME);
    /// TLS ExtensionType `max_fragment_length`.
    pub const MAX_FRAGMENT_LENGTH: Self = Self::new(constants::TLS_EXTENSION_MAX_FRAGMENT_LENGTH);
    /// TLS ExtensionType `status_request`.
    pub const STATUS_REQUEST: Self = Self::new(constants::TLS_EXTENSION_STATUS_REQUEST);
    /// TLS ExtensionType `supported_groups`.
    pub const SUPPORTED_GROUPS: Self = Self::new(constants::TLS_EXTENSION_SUPPORTED_GROUPS);
    /// TLS ExtensionType `ec_point_formats`.
    pub const EC_POINT_FORMATS: Self = Self::new(constants::TLS_EXTENSION_EC_POINT_FORMATS);
    /// TLS ExtensionType `signature_algorithms`.
    pub const SIGNATURE_ALGORITHMS: Self = Self::new(constants::TLS_EXTENSION_SIGNATURE_ALGORITHMS);
    /// TLS ExtensionType `heartbeat`.
    pub const HEARTBEAT: Self = Self::new(constants::TLS_EXTENSION_HEARTBEAT);
    /// TLS ExtensionType `application_layer_protocol_negotiation`.
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: Self =
        Self::new(constants::TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
    /// TLS ExtensionType `padding`.
    pub const PADDING: Self = Self::new(constants::TLS_EXTENSION_PADDING);
    /// TLS ExtensionType `compress_certificate`.
    pub const COMPRESS_CERTIFICATE: Self = Self::new(constants::TLS_EXTENSION_COMPRESS_CERTIFICATE);
    /// TLS ExtensionType `record_size_limit`.
    pub const RECORD_SIZE_LIMIT: Self = Self::new(constants::TLS_EXTENSION_RECORD_SIZE_LIMIT);
    /// Reserved TLS ExtensionType 40.
    pub const RESERVED_40: Self = Self::new(constants::TLS_EXTENSION_RESERVED_40);
    /// TLS ExtensionType `pre_shared_key`.
    pub const PRE_SHARED_KEY: Self = Self::new(constants::TLS_EXTENSION_PRE_SHARED_KEY);
    /// TLS ExtensionType `early_data`.
    pub const EARLY_DATA: Self = Self::new(constants::TLS_EXTENSION_EARLY_DATA);
    /// TLS ExtensionType `supported_versions`.
    pub const SUPPORTED_VERSIONS: Self = Self::new(constants::TLS_EXTENSION_SUPPORTED_VERSIONS);
    /// TLS ExtensionType `cookie`.
    pub const COOKIE: Self = Self::new(constants::TLS_EXTENSION_COOKIE);
    /// TLS ExtensionType `psk_key_exchange_modes`.
    pub const PSK_KEY_EXCHANGE_MODES: Self =
        Self::new(constants::TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES);
    /// Reserved TLS ExtensionType 46.
    pub const RESERVED_46: Self = Self::new(constants::TLS_EXTENSION_RESERVED_46);
    /// TLS ExtensionType `certificate_authorities`.
    pub const CERTIFICATE_AUTHORITIES: Self =
        Self::new(constants::TLS_EXTENSION_CERTIFICATE_AUTHORITIES);
    /// TLS ExtensionType `oid_filters`.
    pub const OID_FILTERS: Self = Self::new(constants::TLS_EXTENSION_OID_FILTERS);
    /// TLS ExtensionType `post_handshake_auth`.
    pub const POST_HANDSHAKE_AUTH: Self = Self::new(constants::TLS_EXTENSION_POST_HANDSHAKE_AUTH);
    /// TLS ExtensionType `signature_algorithms_cert`.
    pub const SIGNATURE_ALGORITHMS_CERT: Self =
        Self::new(constants::TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT);
    /// TLS ExtensionType `key_share`.
    pub const KEY_SHARE: Self = Self::new(constants::TLS_EXTENSION_KEY_SHARE);
    /// TLS ExtensionType `quic_transport_parameters`, preserved outside TLS-over-TCP.
    pub const QUIC_TRANSPORT_PARAMETERS: Self =
        Self::new(constants::TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS);
    /// TLS ExtensionType `ech_outer_extensions`, ECH deferred.
    pub const ECH_OUTER_EXTENSIONS: Self = Self::new(constants::TLS_EXTENSION_ECH_OUTER_EXTENSIONS);
    /// TLS ExtensionType `encrypted_client_hello`, ECH deferred.
    pub const ENCRYPTED_CLIENT_HELLO: Self =
        Self::new(constants::TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO);
    /// TLS ExtensionType `renegotiation_info`.
    pub const RENEGOTIATION_INFO: Self = Self::new(constants::TLS_EXTENSION_RENEGOTIATION_INFO);

    /// Preserve a caller-supplied raw two-octet extension type value.
    pub const fn new(raw: u16) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied raw two-octet extension type value.
    pub const fn from_u16(raw: u16) -> Self {
        Self::new(raw)
    }

    /// Decode a big-endian TLS extension type value from exactly two bytes.
    pub const fn from_be_bytes(bytes: [u8; TLS_EXTENSION_TYPE_LEN]) -> Self {
        Self::new(u16::from_be_bytes(bytes))
    }

    /// TLS ExtensionType `server_name` constructor.
    pub const fn server_name() -> Self {
        Self::SERVER_NAME
    }

    /// TLS ExtensionType `supported_groups` constructor.
    pub const fn supported_groups() -> Self {
        Self::SUPPORTED_GROUPS
    }

    /// TLS ExtensionType `signature_algorithms` constructor.
    pub const fn signature_algorithms() -> Self {
        Self::SIGNATURE_ALGORITHMS
    }

    /// TLS ExtensionType `application_layer_protocol_negotiation` constructor.
    pub const fn application_layer_protocol_negotiation() -> Self {
        Self::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
    }

    /// TLS ExtensionType `supported_versions` constructor.
    pub const fn supported_versions() -> Self {
        Self::SUPPORTED_VERSIONS
    }

    /// TLS ExtensionType `key_share` constructor.
    pub const fn key_share() -> Self {
        Self::KEY_SHARE
    }

    /// Return the preserved raw two-octet wire value.
    pub const fn raw(self) -> u16 {
        self.raw
    }

    /// Return the preserved raw two-octet wire value.
    pub const fn as_u16(self) -> u16 {
        self.raw
    }

    /// Return the big-endian two-byte wire encoding.
    pub const fn to_be_bytes(self) -> [u8; TLS_EXTENSION_TYPE_LEN] {
        self.raw.to_be_bytes()
    }

    /// Append the two-byte wire encoding to `out`.
    pub fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }

    /// Return the two-byte wire encoding as a vector.
    pub fn encode_to_vec(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    /// Decode a TLS extension type from the first two bytes of `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (extension_type, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(extension_type)
    }

    /// Decode a TLS extension type from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_EXTENSION_TYPE_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.extension.type",
                TLS_EXTENSION_TYPE_LEN,
                bytes.len(),
            ));
        }

        Ok((
            Self::from_be_bytes([bytes[0], bytes[1]]),
            &bytes[TLS_EXTENSION_TYPE_LEN..],
        ))
    }

    /// Return the source-backed extension type name, when selected.
    pub const fn name(self) -> Option<&'static str> {
        constants::tls_extension_name(self.raw)
    }

    /// Return the source-backed assignment status.
    pub const fn status(self) -> TlsCodepointStatus {
        constants::tls_extension_status(self.raw)
    }

    /// Return true when this extension type has a selected source-backed name.
    pub const fn is_known(self) -> bool {
        self.name().is_some()
    }

    /// Return true for extension types selected for default TLS builders.
    pub const fn is_default_eligible(self) -> bool {
        matches!(self.status(), TlsCodepointStatus::DefaultEligible)
    }

    /// Return true for RFC 8701 sparse GREASE extension type values.
    pub const fn is_grease(self) -> bool {
        constants::is_tls_grease_u16(self.raw)
    }

    /// Return true for IANA private-use extension type values.
    pub const fn is_private_use(self) -> bool {
        matches!(self.raw, 0xff00 | 0xff02..=0xffff)
    }

    /// Return true for ECH extension types selected as preserve-only in the codepoint notes.
    pub const fn is_ech(self) -> bool {
        matches!(
            self.raw,
            constants::TLS_EXTENSION_ECH_OUTER_EXTENSIONS
                | constants::TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO
        )
    }

    /// Human-readable label preserving unknown values numerically.
    pub fn label(self) -> String {
        constants::tls_extension_label(self.raw)
    }

    /// Stable one-line summary with raw value and source-backed status.
    pub fn summary(self) -> String {
        format!(
            "{} raw=0x{:04x} status={}",
            self.label(),
            self.raw,
            self.status().label()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("extension_type", self.label()),
            ("extension_type_raw", format!("0x{:04x}", self.raw)),
            ("extension_type_status", self.status().label().to_string()),
            ("grease", self.is_grease().to_string()),
            ("private_use", self.is_private_use().to_string()),
            ("ech", self.is_ech().to_string()),
        ]
    }
}

impl From<u16> for TlsExtensionType {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<TlsExtensionType> for u16 {
    fn from(value: TlsExtensionType) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsExtensionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// A raw-preserving single TLS extension entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsRawExtension {
    extension_type: TlsExtensionType,
    body: Vec<u8>,
}

impl TlsRawExtension {
    /// Create a raw extension entry from an extension type and body bytes.
    pub fn new(extension_type: impl Into<TlsExtensionType>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            extension_type: extension_type.into(),
            body: body.into(),
        }
    }

    /// Create a raw extension entry from a raw two-octet extension type value.
    pub fn from_raw(extension_type: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::new(TlsExtensionType::from_u16(extension_type), body)
    }

    /// Return the preserved extension type.
    pub const fn extension_type(&self) -> TlsExtensionType {
        self.extension_type
    }

    /// Return the preserved raw extension type value.
    pub const fn raw_type(&self) -> u16 {
        self.extension_type.raw()
    }

    /// Borrow the preserved extension body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consume the raw extension and return the body bytes.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Number of bytes in the extension body.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Number of bytes in the complete encoded extension entry.
    pub fn encoded_len(&self) -> Result<usize> {
        TLS_EXTENSION_HEADER_LEN
            .checked_add(self.body.len())
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.extension.length", "length overflow")
            })
    }

    /// Append the extension entry with uint16 body length to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let body_len = u16::try_from(self.body.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.extension.length",
                "length must fit in two bytes",
            )
        })?;

        self.extension_type.encode(out);
        out.extend_from_slice(&body_len.to_be_bytes());
        out.extend_from_slice(&self.body);
        Ok(())
    }

    /// Return the encoded extension entry.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode one TLS extension entry from `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (extension, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(extension)
    }

    /// Decode one TLS extension entry from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_EXTENSION_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.extension",
                TLS_EXTENSION_HEADER_LEN,
                bytes.len(),
            ));
        }

        let extension_type = TlsExtensionType::from_be_bytes([bytes[0], bytes[1]]);
        let body_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let required = TLS_EXTENSION_HEADER_LEN + body_len;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.extension.body",
                required,
                bytes.len(),
            ));
        }

        let body = bytes[TLS_EXTENSION_HEADER_LEN..required].to_vec();
        Ok((Self::new(extension_type, body), &bytes[required..]))
    }

    /// Stable one-line summary preserving the type and body size.
    pub fn summary(&self) -> String {
        format!(
            "extension type={} raw=0x{:04x} body_bytes={}",
            self.extension_type.label(),
            self.extension_type.raw(),
            self.body.len()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("extension_type", self.extension_type.label()),
            (
                "extension_type_raw",
                format!("0x{:04x}", self.extension_type.raw()),
            ),
            (
                "extension_type_status",
                self.extension_type.status().label().to_string(),
            ),
            ("extension_body_bytes", self.body.len().to_string()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_extension_type_known_constructors_expose_raw_values() {
        assert_eq!(
            TlsExtensionType::server_name().raw(),
            constants::TLS_EXTENSION_SERVER_NAME
        );
        assert_eq!(
            TlsExtensionType::supported_groups().raw(),
            constants::TLS_EXTENSION_SUPPORTED_GROUPS
        );
        assert_eq!(
            TlsExtensionType::signature_algorithms().raw(),
            constants::TLS_EXTENSION_SIGNATURE_ALGORITHMS
        );
        assert_eq!(
            TlsExtensionType::application_layer_protocol_negotiation().raw(),
            constants::TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION
        );
        assert_eq!(
            TlsExtensionType::supported_versions().raw(),
            constants::TLS_EXTENSION_SUPPORTED_VERSIONS
        );
        assert_eq!(
            TlsExtensionType::key_share().raw(),
            constants::TLS_EXTENSION_KEY_SHARE
        );
        assert_eq!(
            TlsExtensionType::from_be_bytes([0x00, 0x2b]),
            TlsExtensionType::SUPPORTED_VERSIONS
        );
        assert_eq!(
            TlsExtensionType::SUPPORTED_VERSIONS.to_be_bytes(),
            [0x00, 0x2b]
        );
    }

    #[test]
    fn tls_extension_type_labels_statuses_and_ranges_reuse_constants() {
        let sni = TlsExtensionType::SERVER_NAME;
        let legacy = TlsExtensionType::MAX_FRAGMENT_LENGTH;
        let deferred = TlsExtensionType::HEARTBEAT;
        let reserved = TlsExtensionType::RESERVED_46;
        let grease = TlsExtensionType::from_u16(0x0a0a);
        let private = TlsExtensionType::from_u16(0xff10);
        let renegotiation = TlsExtensionType::RENEGOTIATION_INFO;
        let ech = TlsExtensionType::ENCRYPTED_CLIENT_HELLO;
        let unknown = TlsExtensionType::from_u16(0xbeef);

        assert_eq!(sni.name(), Some("server_name"));
        assert_eq!(sni.status(), TlsCodepointStatus::DefaultEligible);
        assert_eq!(sni.label(), "server_name");
        assert_eq!(sni.to_string(), "server_name");
        assert!(sni.is_known());
        assert!(sni.is_default_eligible());

        assert_eq!(legacy.status(), TlsCodepointStatus::PreserveOnly);
        assert_eq!(legacy.label(), "max_fragment_length");
        assert!(!legacy.is_default_eligible());

        assert_eq!(deferred.status(), TlsCodepointStatus::Deferred);
        assert_eq!(deferred.label(), "heartbeat");

        assert_eq!(reserved.status(), TlsCodepointStatus::Reserved);
        assert_eq!(reserved.label(), "Reserved");

        assert_eq!(grease.name(), None);
        assert_eq!(grease.status(), TlsCodepointStatus::ReservedGrease);
        assert_eq!(grease.label(), "reserved grease extension 0x0a0a");
        assert!(grease.is_grease());

        assert_eq!(private.status(), TlsCodepointStatus::PrivateUse);
        assert_eq!(private.label(), "private-use extension 0xff10");
        assert!(private.is_private_use());

        assert_eq!(renegotiation.status(), TlsCodepointStatus::PreserveOnly);
        assert!(!renegotiation.is_private_use());

        assert_eq!(ech.status(), TlsCodepointStatus::PreserveOnly);
        assert!(ech.is_ech());

        assert_eq!(unknown.status(), TlsCodepointStatus::Unknown);
        assert_eq!(unknown.label(), "unknown extension 0xbeef");
        assert!(!unknown.is_known());
    }

    #[test]
    fn tls_extension_type_encode_decode_preserves_raw_values_and_tail() {
        let extension_type = TlsExtensionType::from_u16(0xbeef);
        let mut encoded = Vec::new();
        extension_type.encode(&mut encoded);

        assert_eq!(encoded, [0xbe, 0xef]);
        assert_eq!(extension_type.encode_to_vec(), vec![0xbe, 0xef]);
        assert_eq!(TlsExtensionType::decode(&encoded).unwrap(), extension_type);
        assert_eq!(
            TlsExtensionType::decode_prefix(&[0xbe, 0xef, 0xaa]).unwrap(),
            (extension_type, &[0xaa][..])
        );
        assert_eq!(u16::from(extension_type), 0xbeef);
        assert_eq!(TlsExtensionType::from(0xbeef).as_u16(), 0xbeef);
    }

    #[test]
    fn tls_extension_type_inspection_includes_raw_status_and_ranges() {
        let grease = TlsExtensionType::from_u16(0x1a1a);

        assert_eq!(
            grease.summary(),
            "reserved grease extension 0x1a1a raw=0x1a1a status=reserved-grease"
        );

        let fields = grease.inspection_fields();
        assert!(fields.contains(&(
            "extension_type",
            "reserved grease extension 0x1a1a".to_string()
        )));
        assert!(fields.contains(&("extension_type_raw", "0x1a1a".to_string())));
        assert!(fields.contains(&("extension_type_status", "reserved-grease".to_string())));
        assert!(fields.contains(&("grease", "true".to_string())));
        assert!(fields.contains(&("private_use", "false".to_string())));
        assert!(fields.contains(&("ech", "false".to_string())));
    }

    #[test]
    fn tls_extension_type_raw_extension_preserves_unknown_type_and_body_bytes() {
        let extension = TlsRawExtension::from_raw(0xbeef, [0xde, 0xad, 0xfa, 0xce]);
        let encoded = extension.encode_to_vec().unwrap();

        assert_eq!(encoded, [0xbe, 0xef, 0x00, 0x04, 0xde, 0xad, 0xfa, 0xce]);
        assert_eq!(extension.body_len(), 4);
        assert_eq!(
            extension.encoded_len().unwrap(),
            TLS_EXTENSION_HEADER_LEN + 4
        );

        let encoded_with_tail = [encoded.as_slice(), &[0xaa][..]].concat();
        let (decoded, tail) = TlsRawExtension::decode_prefix(&encoded_with_tail).unwrap();
        assert_eq!(tail, &[0xaa]);
        assert_eq!(decoded.extension_type(), TlsExtensionType::from_u16(0xbeef));
        assert_eq!(decoded.raw_type(), 0xbeef);
        assert_eq!(decoded.body(), &[0xde, 0xad, 0xfa, 0xce]);
        assert_eq!(decoded.encode_to_vec().unwrap(), encoded);
        assert_eq!(
            decoded.summary(),
            "extension type=unknown extension 0xbeef raw=0xbeef body_bytes=4"
        );

        let fields = decoded.inspection_fields();
        assert!(fields.contains(&("extension_type", "unknown extension 0xbeef".to_string())));
        assert!(fields.contains(&("extension_type_raw", "0xbeef".to_string())));
        assert!(fields.contains(&("extension_type_status", "unknown".to_string())));
        assert!(fields.contains(&("extension_body_bytes", "4".to_string())));
        assert_eq!(decoded.into_body(), vec![0xde, 0xad, 0xfa, 0xce]);
    }

    #[test]
    fn tls_extension_type_raw_extension_supports_known_and_empty_bodies() {
        let extension =
            TlsRawExtension::new(TlsExtensionType::SUPPORTED_VERSIONS, Vec::<u8>::new());

        assert_eq!(extension.body(), &[]);
        assert_eq!(extension.encode_to_vec().unwrap(), [0x00, 0x2b, 0x00, 0x00]);
        assert_eq!(
            TlsRawExtension::decode([0x00, 0x2b, 0x00, 0x00]).unwrap(),
            extension
        );
    }

    #[test]
    fn tls_extension_type_decode_reports_structured_errors() {
        assert_eq!(
            TlsExtensionType::decode([0xbe]).unwrap_err(),
            CrafterError::buffer_too_short("tls.extension.type", TLS_EXTENSION_TYPE_LEN, 1)
        );
        assert_eq!(
            TlsRawExtension::decode([0xbe, 0xef, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.extension", TLS_EXTENSION_HEADER_LEN, 3)
        );
        assert_eq!(
            TlsRawExtension::decode([0xbe, 0xef, 0x00, 0x04, 0xde]).unwrap_err(),
            CrafterError::buffer_too_short("tls.extension.body", 8, 5)
        );
    }

    #[test]
    fn tls_extension_type_encode_rejects_oversized_raw_body() {
        let extension = TlsRawExtension::from_raw(0xbeef, vec![0; u16::MAX as usize + 1]);

        assert_eq!(
            extension.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.length",
                "length must fit in two bytes"
            )
        );
    }
}
