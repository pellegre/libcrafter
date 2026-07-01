//! TLS signature scheme helpers.
//!
//! TLS `SignatureScheme` values are raw two-octet registry codepoints used by
//! signature_algorithms and signature_algorithms_cert. The model keeps every
//! caller-supplied or decoded value intact, including unknown, GREASE,
//! private-use, and legacy schemes.

use core::fmt;

use super::constants::{self, TlsCodepointStatus};
use crate::{CrafterError, Result};

/// TLS SignatureScheme codepoint width in bytes.
pub const TLS_SIGNATURE_SCHEME_LEN: usize = 2;
/// TLS signature_algorithms vector length-prefix width in bytes.
pub const TLS_SIGNATURE_SCHEME_LIST_PREFIX_LEN: usize = 2;

/// A raw-preserving TLS `SignatureScheme` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsSignatureScheme {
    raw: u16,
}

impl TlsSignatureScheme {
    /// TLS SignatureScheme `rsa_pkcs1_sha1`.
    pub const RSA_PKCS1_SHA1: Self = Self::new(constants::TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA1);
    /// TLS SignatureScheme `ecdsa_sha1`.
    pub const ECDSA_SHA1: Self = Self::new(constants::TLS_SIGNATURE_SCHEME_ECDSA_SHA1);
    /// TLS SignatureScheme `rsa_pkcs1_sha256`.
    pub const RSA_PKCS1_SHA256: Self = Self::new(constants::TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA256);
    /// TLS SignatureScheme `ecdsa_secp256r1_sha256`.
    pub const ECDSA_SECP256R1_SHA256: Self =
        Self::new(constants::TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256);
    /// TLS SignatureScheme `rsa_pkcs1_sha384`.
    pub const RSA_PKCS1_SHA384: Self = Self::new(constants::TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA384);
    /// TLS SignatureScheme `ecdsa_secp384r1_sha384`.
    pub const ECDSA_SECP384R1_SHA384: Self =
        Self::new(constants::TLS_SIGNATURE_SCHEME_ECDSA_SECP384R1_SHA384);
    /// TLS SignatureScheme `rsa_pkcs1_sha512`.
    pub const RSA_PKCS1_SHA512: Self = Self::new(constants::TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA512);
    /// TLS SignatureScheme `ecdsa_secp521r1_sha512`.
    pub const ECDSA_SECP521R1_SHA512: Self =
        Self::new(constants::TLS_SIGNATURE_SCHEME_ECDSA_SECP521R1_SHA512);
    /// TLS SignatureScheme `rsa_pss_rsae_sha256`.
    pub const RSA_PSS_RSAE_SHA256: Self =
        Self::new(constants::TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256);
    /// TLS SignatureScheme `rsa_pss_rsae_sha384`.
    pub const RSA_PSS_RSAE_SHA384: Self =
        Self::new(constants::TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA384);
    /// TLS SignatureScheme `rsa_pss_rsae_sha512`.
    pub const RSA_PSS_RSAE_SHA512: Self =
        Self::new(constants::TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA512);
    /// TLS SignatureScheme `ed25519`.
    pub const ED25519: Self = Self::new(constants::TLS_SIGNATURE_SCHEME_ED25519);
    /// TLS SignatureScheme `ed448`.
    pub const ED448: Self = Self::new(constants::TLS_SIGNATURE_SCHEME_ED448);
    /// TLS SignatureScheme `rsa_pss_pss_sha256`.
    pub const RSA_PSS_PSS_SHA256: Self =
        Self::new(constants::TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA256);
    /// TLS SignatureScheme `rsa_pss_pss_sha384`.
    pub const RSA_PSS_PSS_SHA384: Self =
        Self::new(constants::TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA384);
    /// TLS SignatureScheme `rsa_pss_pss_sha512`.
    pub const RSA_PSS_PSS_SHA512: Self =
        Self::new(constants::TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA512);

    /// Preserve a caller-supplied raw two-octet signature scheme value.
    pub const fn new(raw: u16) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied raw two-octet signature scheme value.
    pub const fn from_u16(raw: u16) -> Self {
        Self::new(raw)
    }

    /// Decode a big-endian TLS signature scheme value from exactly two bytes.
    pub const fn from_be_bytes(bytes: [u8; TLS_SIGNATURE_SCHEME_LEN]) -> Self {
        Self::new(u16::from_be_bytes(bytes))
    }

    /// TLS SignatureScheme `rsa_pkcs1_sha256` constructor.
    pub const fn rsa_pkcs1_sha256() -> Self {
        Self::RSA_PKCS1_SHA256
    }

    /// TLS SignatureScheme `ecdsa_secp256r1_sha256` constructor.
    pub const fn ecdsa_secp256r1_sha256() -> Self {
        Self::ECDSA_SECP256R1_SHA256
    }

    /// TLS SignatureScheme `rsa_pss_rsae_sha256` constructor.
    pub const fn rsa_pss_rsae_sha256() -> Self {
        Self::RSA_PSS_RSAE_SHA256
    }

    /// TLS SignatureScheme `ed25519` constructor.
    pub const fn ed25519() -> Self {
        Self::ED25519
    }

    /// TLS SignatureScheme `rsa_pkcs1_sha1` constructor.
    pub const fn rsa_pkcs1_sha1() -> Self {
        Self::RSA_PKCS1_SHA1
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
    pub const fn to_be_bytes(self) -> [u8; TLS_SIGNATURE_SCHEME_LEN] {
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

    /// Decode a TLS signature scheme from the first two bytes of `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (scheme, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(scheme)
    }

    /// Decode a TLS signature scheme from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_SIGNATURE_SCHEME_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.signature_scheme",
                TLS_SIGNATURE_SCHEME_LEN,
                bytes.len(),
            ));
        }

        Ok((
            Self::from_be_bytes([bytes[0], bytes[1]]),
            &bytes[TLS_SIGNATURE_SCHEME_LEN..],
        ))
    }

    /// Return the source-backed signature scheme name, when selected.
    pub const fn name(self) -> Option<&'static str> {
        constants::tls_signature_scheme_name(self.raw)
    }

    /// Return the source-backed assignment status.
    pub const fn status(self) -> TlsCodepointStatus {
        constants::tls_signature_scheme_status(self.raw)
    }

    /// Return true when this scheme has a selected source-backed name.
    pub const fn is_known(self) -> bool {
        self.name().is_some()
    }

    /// Return true for schemes selected for default TLS builders.
    pub const fn is_default_eligible(self) -> bool {
        matches!(self.status(), TlsCodepointStatus::DefaultEligible)
    }

    /// Return true for RFC 8701 sparse GREASE signature scheme values.
    pub const fn is_grease(self) -> bool {
        constants::is_tls_grease_u16(self.raw)
    }

    /// Return true for IANA private-use signature scheme values.
    pub const fn is_private_use(self) -> bool {
        matches!(self.raw, 0xfe00..=0xffff)
    }

    /// Return true for legacy SHA-1 schemes selected in the codepoint notes.
    pub const fn is_legacy_sha1(self) -> bool {
        matches!(
            self.raw,
            constants::TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA1
                | constants::TLS_SIGNATURE_SCHEME_ECDSA_SHA1
        )
    }

    /// Human-readable label preserving unknown values numerically.
    pub fn label(self) -> String {
        constants::tls_signature_scheme_label(self.raw)
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
            ("signature_scheme", self.label()),
            ("signature_scheme_raw", format!("0x{:04x}", self.raw)),
            ("signature_scheme_status", self.status().label().to_string()),
            ("grease", self.is_grease().to_string()),
            ("private_use", self.is_private_use().to_string()),
            ("legacy_sha1", self.is_legacy_sha1().to_string()),
        ]
    }
}

impl From<u16> for TlsSignatureScheme {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<TlsSignatureScheme> for u16 {
    fn from(value: TlsSignatureScheme) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsSignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Ordered TLS signature_algorithms vector.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsSignatureSchemeList {
    schemes: Vec<TlsSignatureScheme>,
}

impl TlsSignatureSchemeList {
    /// Create an ordered signature scheme list.
    pub fn new(schemes: impl Into<Vec<TlsSignatureScheme>>) -> Self {
        Self {
            schemes: schemes.into(),
        }
    }

    /// Create an empty ordered signature scheme list.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create an ordered list from raw two-octet values.
    pub fn from_raws(raws: impl IntoIterator<Item = u16>) -> Self {
        Self::new(
            raws.into_iter()
                .map(TlsSignatureScheme::from_u16)
                .collect::<Vec<_>>(),
        )
    }

    /// Borrow the ordered signature scheme values.
    pub fn schemes(&self) -> &[TlsSignatureScheme] {
        &self.schemes
    }

    /// Return the ordered raw signature scheme values.
    pub fn raw_values(&self) -> Vec<u16> {
        self.schemes.iter().map(|scheme| scheme.raw()).collect()
    }

    /// Return labels in wire order.
    pub fn labels(&self) -> Vec<String> {
        self.schemes.iter().map(|scheme| scheme.label()).collect()
    }

    /// Consume the list and return the ordered values.
    pub fn into_vec(self) -> Vec<TlsSignatureScheme> {
        self.schemes
    }

    /// Append a scheme to the ordered list.
    pub fn push(&mut self, scheme: TlsSignatureScheme) {
        self.schemes.push(scheme);
    }

    /// Number of signature scheme values in the list.
    pub fn len(&self) -> usize {
        self.schemes.len()
    }

    /// Return true when the list carries no signature scheme values.
    pub fn is_empty(&self) -> bool {
        self.schemes.is_empty()
    }

    /// Number of bytes occupied by the vector body, excluding the length prefix.
    pub fn byte_len(&self) -> Result<usize> {
        self.schemes
            .len()
            .checked_mul(TLS_SIGNATURE_SCHEME_LEN)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.signature_schemes.length", "length overflow")
            })
    }

    /// Number of bytes occupied by the complete encoded vector.
    pub fn encoded_len(&self) -> Result<usize> {
        self.byte_len()?
            .checked_add(TLS_SIGNATURE_SCHEME_LIST_PREFIX_LEN)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.signature_schemes.length", "length overflow")
            })
    }

    /// Append the uint16 length-prefixed signature_algorithms vector.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let byte_len = self.byte_len()?;
        let encoded_len = u16::try_from(byte_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.signature_schemes.length",
                "length must fit in two bytes",
            )
        })?;

        out.extend_from_slice(&encoded_len.to_be_bytes());
        for scheme in &self.schemes {
            scheme.encode(out);
        }
        Ok(())
    }

    /// Return the uint16 length-prefixed signature_algorithms vector.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode a uint16 length-prefixed signature_algorithms vector.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (list, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(list)
    }

    /// Decode a uint16 length-prefixed signature_algorithms vector from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_SIGNATURE_SCHEME_LIST_PREFIX_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.signature_schemes.length",
                TLS_SIGNATURE_SCHEME_LIST_PREFIX_LEN,
                bytes.len(),
            ));
        }

        let byte_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        let required = TLS_SIGNATURE_SCHEME_LIST_PREFIX_LEN + byte_len;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.signature_schemes",
                required,
                bytes.len(),
            ));
        }

        if byte_len % TLS_SIGNATURE_SCHEME_LEN != 0 {
            return Err(CrafterError::invalid_field_value(
                "tls.signature_schemes.length",
                "signature scheme vector length must be even",
            ));
        }

        let body = &bytes[TLS_SIGNATURE_SCHEME_LIST_PREFIX_LEN..required];
        let schemes = body
            .chunks_exact(TLS_SIGNATURE_SCHEME_LEN)
            .map(|chunk| TlsSignatureScheme::from_be_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();

        Ok((Self::new(schemes), &bytes[required..]))
    }

    /// Stable one-line summary preserving order.
    pub fn summary(&self) -> String {
        let values = self.labels().join(",");
        format!(
            "signature_schemes count={} bytes={} values={}",
            self.len(),
            self.schemes.len() * TLS_SIGNATURE_SCHEME_LEN,
            values
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("signature_schemes_count", self.len().to_string()),
            (
                "signature_schemes_bytes",
                (self.schemes.len() * TLS_SIGNATURE_SCHEME_LEN).to_string(),
            ),
            ("signature_schemes", self.labels().join(",")),
        ]
    }
}

impl From<Vec<TlsSignatureScheme>> for TlsSignatureSchemeList {
    fn from(schemes: Vec<TlsSignatureScheme>) -> Self {
        Self::new(schemes)
    }
}

impl<const N: usize> From<[TlsSignatureScheme; N]> for TlsSignatureSchemeList {
    fn from(schemes: [TlsSignatureScheme; N]) -> Self {
        Self::new(Vec::from(schemes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_groups_signatures_signature_scheme_known_constructors_expose_raw_values() {
        assert_eq!(
            TlsSignatureScheme::rsa_pkcs1_sha256().raw(),
            constants::TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA256
        );
        assert_eq!(
            TlsSignatureScheme::ecdsa_secp256r1_sha256().raw(),
            constants::TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256
        );
        assert_eq!(
            TlsSignatureScheme::rsa_pss_rsae_sha256().raw(),
            constants::TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256
        );
        assert_eq!(
            TlsSignatureScheme::ed25519().raw(),
            constants::TLS_SIGNATURE_SCHEME_ED25519
        );
        assert_eq!(
            TlsSignatureScheme::rsa_pkcs1_sha1().raw(),
            constants::TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA1
        );
        assert_eq!(
            TlsSignatureScheme::from_be_bytes([0x08, 0x07]),
            TlsSignatureScheme::ED25519
        );
        assert_eq!(TlsSignatureScheme::ED25519.to_be_bytes(), [0x08, 0x07]);
    }

    #[test]
    fn tls_groups_signatures_signature_scheme_labels_statuses_and_ranges_reuse_constants() {
        let ed25519 = TlsSignatureScheme::ED25519;
        let legacy = TlsSignatureScheme::RSA_PKCS1_SHA1;
        let grease = TlsSignatureScheme::from_u16(0x2a2a);
        let private = TlsSignatureScheme::from_u16(0xfe00);
        let unknown = TlsSignatureScheme::from_u16(0xbeef);

        assert_eq!(ed25519.name(), Some("ed25519"));
        assert_eq!(ed25519.status(), TlsCodepointStatus::DefaultEligible);
        assert_eq!(ed25519.label(), "ed25519");
        assert_eq!(ed25519.to_string(), "ed25519");
        assert!(ed25519.is_known());
        assert!(ed25519.is_default_eligible());

        assert_eq!(legacy.status(), TlsCodepointStatus::PreserveOnly);
        assert_eq!(legacy.label(), "rsa_pkcs1_sha1");
        assert!(legacy.is_legacy_sha1());
        assert!(!legacy.is_default_eligible());

        assert_eq!(grease.name(), None);
        assert_eq!(grease.status(), TlsCodepointStatus::ReservedGrease);
        assert_eq!(grease.label(), "reserved grease signature scheme 0x2a2a");
        assert!(grease.is_grease());

        assert_eq!(private.status(), TlsCodepointStatus::PrivateUse);
        assert_eq!(private.label(), "private-use signature scheme 0xfe00");
        assert!(private.is_private_use());

        assert_eq!(unknown.status(), TlsCodepointStatus::Unknown);
        assert_eq!(unknown.label(), "unknown signature scheme 0xbeef");
        assert!(!unknown.is_known());
    }

    #[test]
    fn tls_groups_signatures_signature_scheme_encode_decode_preserves_raw_values_and_tail() {
        let scheme = TlsSignatureScheme::from_u16(0xbeef);
        let mut encoded = Vec::new();
        scheme.encode(&mut encoded);

        assert_eq!(encoded, [0xbe, 0xef]);
        assert_eq!(scheme.encode_to_vec(), vec![0xbe, 0xef]);
        assert_eq!(TlsSignatureScheme::decode(&encoded).unwrap(), scheme);
        assert_eq!(
            TlsSignatureScheme::decode_prefix(&[0xbe, 0xef, 0xaa]).unwrap(),
            (scheme, &[0xaa][..])
        );
        assert_eq!(u16::from(scheme), 0xbeef);
        assert_eq!(TlsSignatureScheme::from(0xbeef).as_u16(), 0xbeef);
    }

    #[test]
    fn tls_groups_signatures_signature_scheme_inspection_includes_raw_status_and_ranges() {
        let grease = TlsSignatureScheme::from_u16(0x1a1a);

        assert_eq!(
            grease.summary(),
            "reserved grease signature scheme 0x1a1a raw=0x1a1a status=reserved-grease"
        );

        let fields = grease.inspection_fields();
        assert!(fields.contains(&(
            "signature_scheme",
            "reserved grease signature scheme 0x1a1a".to_string()
        )));
        assert!(fields.contains(&("signature_scheme_raw", "0x1a1a".to_string())));
        assert!(fields.contains(&("signature_scheme_status", "reserved-grease".to_string())));
        assert!(fields.contains(&("grease", "true".to_string())));
        assert!(fields.contains(&("private_use", "false".to_string())));
        assert!(fields.contains(&("legacy_sha1", "false".to_string())));
    }

    #[test]
    fn tls_groups_signatures_signature_scheme_list_encodes_decodes_and_preserves_order() {
        let list = TlsSignatureSchemeList::new(vec![
            TlsSignatureScheme::ED25519,
            TlsSignatureScheme::from_u16(0x2a2a),
            TlsSignatureScheme::RSA_PKCS1_SHA1,
            TlsSignatureScheme::from_u16(0xfe00),
            TlsSignatureScheme::from_u16(0xbeef),
        ]);

        let encoded = list.encode_to_vec().unwrap();
        assert_eq!(
            encoded,
            [0x00, 0x0a, 0x08, 0x07, 0x2a, 0x2a, 0x02, 0x01, 0xfe, 0x00, 0xbe, 0xef]
        );

        let encoded_with_tail = [encoded.as_slice(), &[0xaa][..]].concat();
        let (decoded, tail) = TlsSignatureSchemeList::decode_prefix(&encoded_with_tail).unwrap();
        assert_eq!(tail, &[0xaa]);
        assert_eq!(decoded, list);
        assert_eq!(
            decoded.raw_values(),
            vec![0x0807, 0x2a2a, 0x0201, 0xfe00, 0xbeef]
        );
        assert_eq!(
            decoded.labels(),
            vec![
                "ed25519".to_string(),
                "reserved grease signature scheme 0x2a2a".to_string(),
                "rsa_pkcs1_sha1".to_string(),
                "private-use signature scheme 0xfe00".to_string(),
                "unknown signature scheme 0xbeef".to_string(),
            ]
        );
        assert_eq!(
            decoded.summary(),
            "signature_schemes count=5 bytes=10 values=ed25519,reserved grease signature scheme 0x2a2a,rsa_pkcs1_sha1,private-use signature scheme 0xfe00,unknown signature scheme 0xbeef"
        );

        let fields = decoded.inspection_fields();
        assert!(fields.contains(&("signature_schemes_count", "5".to_string())));
        assert!(fields.contains(&("signature_schemes_bytes", "10".to_string())));
    }

    #[test]
    fn tls_groups_signatures_signature_scheme_list_supports_empty_and_incremental_building() {
        let mut list = TlsSignatureSchemeList::empty();
        assert!(list.is_empty());
        assert_eq!(list.encode_to_vec().unwrap(), [0x00, 0x00]);
        assert_eq!(
            TlsSignatureSchemeList::decode([0x00, 0x00])
                .unwrap()
                .schemes(),
            &[]
        );

        list.push(TlsSignatureScheme::RSA_PSS_RSAE_SHA256);
        assert_eq!(list.len(), 1);
        assert_eq!(list.byte_len().unwrap(), 2);
        assert_eq!(list.encoded_len().unwrap(), 4);
        assert_eq!(list.encode_to_vec().unwrap(), [0x00, 0x02, 0x08, 0x04]);

        let from_raws = TlsSignatureSchemeList::from_raws([0x0807, 0xfe00]);
        assert_eq!(from_raws.raw_values(), vec![0x0807, 0xfe00]);
        assert_eq!(
            TlsSignatureSchemeList::from([TlsSignatureScheme::ED25519]).raw_values(),
            vec![0x0807]
        );
    }

    #[test]
    fn tls_groups_signatures_signature_scheme_list_reports_structured_decode_errors() {
        assert_eq!(
            TlsSignatureScheme::decode([0x08]).unwrap_err(),
            CrafterError::buffer_too_short("tls.signature_scheme", TLS_SIGNATURE_SCHEME_LEN, 1)
        );
        assert_eq!(
            TlsSignatureSchemeList::decode([0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.signature_schemes.length",
                TLS_SIGNATURE_SCHEME_LIST_PREFIX_LEN,
                1,
            )
        );
        assert_eq!(
            TlsSignatureSchemeList::decode([0x00, 0x04, 0x08, 0x07]).unwrap_err(),
            CrafterError::buffer_too_short("tls.signature_schemes", 6, 4)
        );
        assert_eq!(
            TlsSignatureSchemeList::decode([0x00, 0x03, 0x08, 0x07, 0xaa]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.signature_schemes.length",
                "signature scheme vector length must be even"
            )
        );
    }

    #[test]
    fn tls_groups_signatures_signature_scheme_list_rejects_encoded_body_too_large_for_u16_prefix() {
        let schemes = vec![TlsSignatureScheme::ED25519; 32768];
        let list = TlsSignatureSchemeList::new(schemes);

        assert_eq!(list.byte_len().unwrap(), 65536);
        assert_eq!(
            list.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.signature_schemes.length",
                "length must fit in two bytes"
            )
        );
    }
}
