//! TLS cipher suite helpers.
//!
//! Cipher suites are raw two-octet values. ClientHello carries an ordered
//! uint16 length-prefixed list of these values, while ServerHello carries one
//! selected value. The model keeps every caller-supplied or decoded value
//! intact, including unknown, GREASE, private-use, and signaling values.

use core::fmt;

use super::constants::{self, TlsCodepointStatus};
use crate::{CrafterError, Result};

/// TLS cipher suite codepoint width in bytes.
pub const TLS_CIPHER_SUITE_LEN: usize = 2;
/// TLS ClientHello cipher suite vector length-prefix width in bytes.
pub const TLS_CIPHER_SUITE_LIST_PREFIX_LEN: usize = 2;

/// A raw-preserving TLS `CipherSuite` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsCipherSuite {
    raw: u16,
}

impl TlsCipherSuite {
    /// TLS 1.3 `TLS_AES_128_GCM_SHA256`.
    pub const AES_128_GCM_SHA256: Self = Self::new(constants::TLS_CIPHER_SUITE_AES_128_GCM_SHA256);
    /// TLS 1.3 `TLS_AES_256_GCM_SHA384`.
    pub const AES_256_GCM_SHA384: Self = Self::new(constants::TLS_CIPHER_SUITE_AES_256_GCM_SHA384);
    /// TLS 1.3 `TLS_CHACHA20_POLY1305_SHA256`.
    pub const CHACHA20_POLY1305_SHA256: Self =
        Self::new(constants::TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256);
    /// TLS 1.3 `TLS_AES_128_CCM_SHA256`.
    pub const AES_128_CCM_SHA256: Self = Self::new(constants::TLS_CIPHER_SUITE_AES_128_CCM_SHA256);
    /// TLS 1.3 `TLS_AES_128_CCM_8_SHA256`.
    pub const AES_128_CCM_8_SHA256: Self =
        Self::new(constants::TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256);
    /// TLS 1.2 `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.
    pub const ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: Self =
        Self::new(constants::TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    /// TLS 1.2 `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`.
    pub const ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: Self =
        Self::new(constants::TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
    /// TLS 1.2 `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
    pub const ECDHE_RSA_WITH_AES_128_GCM_SHA256: Self =
        Self::new(constants::TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    /// TLS 1.2 `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.
    pub const ECDHE_RSA_WITH_AES_256_GCM_SHA384: Self =
        Self::new(constants::TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    /// TLS 1.2 `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`.
    pub const ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: Self =
        Self::new(constants::TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
    /// TLS 1.2 `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`.
    pub const ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: Self =
        Self::new(constants::TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
    /// TLS 1.2 `TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256`.
    pub const ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256: Self =
        Self::new(constants::TLS_CIPHER_SUITE_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256);
    /// TLS 1.2 `TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256`.
    pub const ECDHE_PSK_WITH_AES_128_GCM_SHA256: Self =
        Self::new(constants::TLS_CIPHER_SUITE_ECDHE_PSK_WITH_AES_128_GCM_SHA256);
    /// TLS 1.2 `TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384`.
    pub const ECDHE_PSK_WITH_AES_256_GCM_SHA384: Self =
        Self::new(constants::TLS_CIPHER_SUITE_ECDHE_PSK_WITH_AES_256_GCM_SHA384);
    /// TLS 1.2 `TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256`.
    pub const ECDHE_PSK_WITH_AES_128_CCM_SHA256: Self =
        Self::new(constants::TLS_CIPHER_SUITE_ECDHE_PSK_WITH_AES_128_CCM_SHA256);
    /// TLS signaling cipher suite value `TLS_EMPTY_RENEGOTIATION_INFO_SCSV`.
    pub const EMPTY_RENEGOTIATION_INFO_SCSV: Self =
        Self::new(constants::TLS_CIPHER_SUITE_EMPTY_RENEGOTIATION_INFO_SCSV);
    /// TLS signaling cipher suite value `TLS_FALLBACK_SCSV`.
    pub const FALLBACK_SCSV: Self = Self::new(constants::TLS_CIPHER_SUITE_FALLBACK_SCSV);

    /// Preserve a caller-supplied raw two-octet cipher suite value.
    pub const fn new(raw: u16) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied raw two-octet cipher suite value.
    pub const fn from_u16(raw: u16) -> Self {
        Self::new(raw)
    }

    /// Decode a big-endian TLS cipher suite value from exactly two bytes.
    pub const fn from_be_bytes(bytes: [u8; TLS_CIPHER_SUITE_LEN]) -> Self {
        Self::new(u16::from_be_bytes(bytes))
    }

    /// TLS 1.3 `TLS_AES_128_GCM_SHA256` constructor.
    pub const fn aes_128_gcm_sha256() -> Self {
        Self::AES_128_GCM_SHA256
    }

    /// TLS 1.3 `TLS_AES_256_GCM_SHA384` constructor.
    pub const fn aes_256_gcm_sha384() -> Self {
        Self::AES_256_GCM_SHA384
    }

    /// TLS 1.3 `TLS_CHACHA20_POLY1305_SHA256` constructor.
    pub const fn chacha20_poly1305_sha256() -> Self {
        Self::CHACHA20_POLY1305_SHA256
    }

    /// TLS 1.3 `TLS_AES_128_CCM_SHA256` constructor.
    pub const fn aes_128_ccm_sha256() -> Self {
        Self::AES_128_CCM_SHA256
    }

    /// TLS 1.3 `TLS_AES_128_CCM_8_SHA256` constructor.
    pub const fn aes_128_ccm_8_sha256() -> Self {
        Self::AES_128_CCM_8_SHA256
    }

    /// TLS signaling cipher suite value `TLS_EMPTY_RENEGOTIATION_INFO_SCSV`.
    pub const fn empty_renegotiation_info_scsv() -> Self {
        Self::EMPTY_RENEGOTIATION_INFO_SCSV
    }

    /// TLS signaling cipher suite value `TLS_FALLBACK_SCSV`.
    pub const fn fallback_scsv() -> Self {
        Self::FALLBACK_SCSV
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
    pub const fn to_be_bytes(self) -> [u8; TLS_CIPHER_SUITE_LEN] {
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

    /// Decode a TLS cipher suite from the first two bytes of `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (suite, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(suite)
    }

    /// Decode a TLS cipher suite from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_CIPHER_SUITE_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.cipher_suite",
                TLS_CIPHER_SUITE_LEN,
                bytes.len(),
            ));
        }

        Ok((
            Self::from_be_bytes([bytes[0], bytes[1]]),
            &bytes[TLS_CIPHER_SUITE_LEN..],
        ))
    }

    /// Return the source-backed cipher suite name, when selected.
    pub const fn name(self) -> Option<&'static str> {
        constants::tls_cipher_suite_name(self.raw)
    }

    /// Return the source-backed assignment status.
    pub const fn status(self) -> TlsCodepointStatus {
        constants::tls_cipher_suite_status(self.raw)
    }

    /// Return true when this suite has a selected source-backed name.
    pub const fn is_known(self) -> bool {
        self.name().is_some()
    }

    /// Return true for cipher suites selected for default TLS builders.
    pub const fn is_default_eligible(self) -> bool {
        matches!(self.status(), TlsCodepointStatus::DefaultEligible)
    }

    /// Return true for RFC 8701 sparse GREASE cipher suite values.
    pub const fn is_grease(self) -> bool {
        constants::is_tls_grease_u16(self.raw)
    }

    /// Return true for IANA private-use cipher suite values.
    pub const fn is_private_use(self) -> bool {
        matches!(self.raw, 0xff00..=0xffff)
    }

    /// Return true for signaling cipher suite values selected in the codepoint notes.
    pub const fn is_signaling(self) -> bool {
        matches!(
            self.raw,
            constants::TLS_CIPHER_SUITE_EMPTY_RENEGOTIATION_INFO_SCSV
                | constants::TLS_CIPHER_SUITE_FALLBACK_SCSV
        )
    }

    /// Human-readable label preserving unknown values numerically.
    pub fn label(self) -> String {
        constants::tls_cipher_suite_label(self.raw)
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
            ("cipher_suite", self.label()),
            ("cipher_suite_raw", format!("0x{:04x}", self.raw)),
            ("cipher_suite_status", self.status().label().to_string()),
            ("grease", self.is_grease().to_string()),
            ("private_use", self.is_private_use().to_string()),
            ("signaling", self.is_signaling().to_string()),
        ]
    }
}

impl From<u16> for TlsCipherSuite {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<TlsCipherSuite> for u16 {
    fn from(value: TlsCipherSuite) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsCipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Ordered TLS ClientHello cipher suite vector.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsCipherSuiteList {
    suites: Vec<TlsCipherSuite>,
}

impl TlsCipherSuiteList {
    /// Create an ordered cipher suite list.
    pub fn new(suites: impl Into<Vec<TlsCipherSuite>>) -> Self {
        Self {
            suites: suites.into(),
        }
    }

    /// Create an empty ordered cipher suite list.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create an ordered list from raw two-octet values.
    pub fn from_raws(raws: impl IntoIterator<Item = u16>) -> Self {
        Self::new(
            raws.into_iter()
                .map(TlsCipherSuite::from_u16)
                .collect::<Vec<_>>(),
        )
    }

    /// Borrow the ordered cipher suite values.
    pub fn suites(&self) -> &[TlsCipherSuite] {
        &self.suites
    }

    /// Return the ordered raw cipher suite values.
    pub fn raw_values(&self) -> Vec<u16> {
        self.suites.iter().map(|suite| suite.raw()).collect()
    }

    /// Return labels in wire order.
    pub fn labels(&self) -> Vec<String> {
        self.suites.iter().map(|suite| suite.label()).collect()
    }

    /// Consume the list and return the ordered values.
    pub fn into_vec(self) -> Vec<TlsCipherSuite> {
        self.suites
    }

    /// Append a suite to the ordered list.
    pub fn push(&mut self, suite: TlsCipherSuite) {
        self.suites.push(suite);
    }

    /// Number of cipher suite values in the list.
    pub fn len(&self) -> usize {
        self.suites.len()
    }

    /// Return true when the list carries no cipher suite values.
    pub fn is_empty(&self) -> bool {
        self.suites.is_empty()
    }

    /// Number of bytes occupied by the vector body, excluding the length prefix.
    pub fn byte_len(&self) -> Result<usize> {
        self.suites
            .len()
            .checked_mul(TLS_CIPHER_SUITE_LEN)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.cipher_suites.length", "length overflow")
            })
    }

    /// Number of bytes occupied by the complete encoded vector.
    pub fn encoded_len(&self) -> Result<usize> {
        self.byte_len()?
            .checked_add(TLS_CIPHER_SUITE_LIST_PREFIX_LEN)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.cipher_suites.length", "length overflow")
            })
    }

    /// Append the uint16 length-prefixed ClientHello cipher suite vector.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let byte_len = self.byte_len()?;
        let encoded_len = u16::try_from(byte_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.cipher_suites.length",
                "length must fit in two bytes",
            )
        })?;

        out.extend_from_slice(&encoded_len.to_be_bytes());
        for suite in &self.suites {
            suite.encode(out);
        }
        Ok(())
    }

    /// Return the uint16 length-prefixed ClientHello cipher suite vector.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode a uint16 length-prefixed ClientHello cipher suite vector.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (list, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(list)
    }

    /// Decode a uint16 length-prefixed ClientHello cipher suite vector from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_CIPHER_SUITE_LIST_PREFIX_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.cipher_suites.length",
                TLS_CIPHER_SUITE_LIST_PREFIX_LEN,
                bytes.len(),
            ));
        }

        let byte_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        let required = TLS_CIPHER_SUITE_LIST_PREFIX_LEN + byte_len;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.cipher_suites",
                required,
                bytes.len(),
            ));
        }

        if byte_len % TLS_CIPHER_SUITE_LEN != 0 {
            return Err(CrafterError::invalid_field_value(
                "tls.cipher_suites.length",
                "cipher suite vector length must be even",
            ));
        }

        let body = &bytes[TLS_CIPHER_SUITE_LIST_PREFIX_LEN..required];
        let suites = body
            .chunks_exact(TLS_CIPHER_SUITE_LEN)
            .map(|chunk| TlsCipherSuite::from_be_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();

        Ok((Self::new(suites), &bytes[required..]))
    }

    /// Stable one-line summary preserving order.
    pub fn summary(&self) -> String {
        let values = self.labels().join(",");
        format!(
            "cipher_suites count={} bytes={} values={}",
            self.len(),
            self.suites.len() * TLS_CIPHER_SUITE_LEN,
            values
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("cipher_suites_count", self.len().to_string()),
            (
                "cipher_suites_bytes",
                (self.suites.len() * TLS_CIPHER_SUITE_LEN).to_string(),
            ),
            ("cipher_suites", self.labels().join(",")),
        ]
    }
}

impl From<Vec<TlsCipherSuite>> for TlsCipherSuiteList {
    fn from(suites: Vec<TlsCipherSuite>) -> Self {
        Self::new(suites)
    }
}

impl<const N: usize> From<[TlsCipherSuite; N]> for TlsCipherSuiteList {
    fn from(suites: [TlsCipherSuite; N]) -> Self {
        Self::new(Vec::from(suites))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_cipher_suite_known_constructors_expose_raw_values() {
        assert_eq!(
            TlsCipherSuite::aes_128_gcm_sha256().raw(),
            constants::TLS_CIPHER_SUITE_AES_128_GCM_SHA256
        );
        assert_eq!(
            TlsCipherSuite::aes_256_gcm_sha384().raw(),
            constants::TLS_CIPHER_SUITE_AES_256_GCM_SHA384
        );
        assert_eq!(
            TlsCipherSuite::chacha20_poly1305_sha256().raw(),
            constants::TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256
        );
        assert_eq!(
            TlsCipherSuite::aes_128_ccm_sha256().raw(),
            constants::TLS_CIPHER_SUITE_AES_128_CCM_SHA256
        );
        assert_eq!(
            TlsCipherSuite::aes_128_ccm_8_sha256().raw(),
            constants::TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256
        );
        assert_eq!(
            TlsCipherSuite::empty_renegotiation_info_scsv().raw(),
            constants::TLS_CIPHER_SUITE_EMPTY_RENEGOTIATION_INFO_SCSV
        );
        assert_eq!(
            TlsCipherSuite::fallback_scsv().raw(),
            constants::TLS_CIPHER_SUITE_FALLBACK_SCSV
        );
        assert_eq!(
            TlsCipherSuite::from_be_bytes([0x13, 0x01]),
            TlsCipherSuite::AES_128_GCM_SHA256
        );
        assert_eq!(
            TlsCipherSuite::AES_128_GCM_SHA256.to_be_bytes(),
            [0x13, 0x01]
        );
    }

    #[test]
    fn tls_cipher_suite_labels_statuses_and_ranges_reuse_constants() {
        let tls13 = TlsCipherSuite::AES_128_GCM_SHA256;
        let tls12 = TlsCipherSuite::ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        let scsv = TlsCipherSuite::FALLBACK_SCSV;
        let grease = TlsCipherSuite::from_u16(0x0a0a);
        let private = TlsCipherSuite::from_u16(0xff01);
        let unknown = TlsCipherSuite::from_u16(0x1234);

        assert_eq!(tls13.name(), Some("TLS_AES_128_GCM_SHA256"));
        assert_eq!(tls13.status(), TlsCodepointStatus::DefaultEligible);
        assert_eq!(tls13.label(), "TLS_AES_128_GCM_SHA256");
        assert_eq!(tls13.to_string(), "TLS_AES_128_GCM_SHA256");
        assert!(tls13.is_known());
        assert!(tls13.is_default_eligible());

        assert_eq!(tls12.status(), TlsCodepointStatus::LabelEligible);
        assert_eq!(tls12.label(), "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        assert!(!tls12.is_default_eligible());

        assert_eq!(scsv.status(), TlsCodepointStatus::PreserveOnly);
        assert!(scsv.is_signaling());

        assert_eq!(grease.name(), None);
        assert_eq!(grease.status(), TlsCodepointStatus::ReservedGrease);
        assert_eq!(grease.label(), "reserved grease cipher suite 0x0a0a");
        assert!(grease.is_grease());

        assert_eq!(private.status(), TlsCodepointStatus::PrivateUse);
        assert_eq!(private.label(), "private-use cipher suite 0xff01");
        assert!(private.is_private_use());

        assert_eq!(unknown.status(), TlsCodepointStatus::Unknown);
        assert_eq!(unknown.label(), "unknown cipher suite 0x1234");
        assert!(!unknown.is_known());
    }

    #[test]
    fn tls_cipher_suite_encode_decode_preserves_raw_values_and_tail() {
        let suite = TlsCipherSuite::from_u16(0xbeef);
        let mut encoded = Vec::new();
        suite.encode(&mut encoded);

        assert_eq!(encoded, [0xbe, 0xef]);
        assert_eq!(suite.encode_to_vec(), vec![0xbe, 0xef]);
        assert_eq!(TlsCipherSuite::decode(&encoded).unwrap(), suite);
        assert_eq!(
            TlsCipherSuite::decode_prefix(&[0xbe, 0xef, 0xaa]).unwrap(),
            (suite, &[0xaa][..])
        );
        assert_eq!(u16::from(suite), 0xbeef);
        assert_eq!(TlsCipherSuite::from(0xbeef).as_u16(), 0xbeef);
    }

    #[test]
    fn tls_cipher_suite_inspection_includes_raw_status_and_registry_range() {
        let grease = TlsCipherSuite::from_u16(0x1a1a);

        assert_eq!(
            grease.summary(),
            "reserved grease cipher suite 0x1a1a raw=0x1a1a status=reserved-grease"
        );

        let fields = grease.inspection_fields();
        assert!(fields.contains(&(
            "cipher_suite",
            "reserved grease cipher suite 0x1a1a".to_string()
        )));
        assert!(fields.contains(&("cipher_suite_raw", "0x1a1a".to_string())));
        assert!(fields.contains(&("cipher_suite_status", "reserved-grease".to_string())));
        assert!(fields.contains(&("grease", "true".to_string())));
        assert!(fields.contains(&("private_use", "false".to_string())));
        assert!(fields.contains(&("signaling", "false".to_string())));
    }

    #[test]
    fn tls_cipher_suite_list_encodes_decodes_and_preserves_order() {
        let list = TlsCipherSuiteList::new(vec![
            TlsCipherSuite::AES_128_GCM_SHA256,
            TlsCipherSuite::from_u16(0x0a0a),
            TlsCipherSuite::ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TlsCipherSuite::from_u16(0xbeef),
        ]);

        let encoded = list.encode_to_vec().unwrap();
        assert_eq!(
            encoded,
            [0x00, 0x08, 0x13, 0x01, 0x0a, 0x0a, 0xc0, 0x2f, 0xbe, 0xef]
        );

        let encoded_with_tail = [encoded.as_slice(), &[0xaa][..]].concat();
        let (decoded, tail) = TlsCipherSuiteList::decode_prefix(&encoded_with_tail).unwrap();
        assert_eq!(tail, &[0xaa]);
        assert_eq!(decoded, list);
        assert_eq!(decoded.raw_values(), vec![0x1301, 0x0a0a, 0xc02f, 0xbeef]);
        assert_eq!(
            decoded.labels(),
            vec![
                "TLS_AES_128_GCM_SHA256".to_string(),
                "reserved grease cipher suite 0x0a0a".to_string(),
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
                "unknown cipher suite 0xbeef".to_string(),
            ]
        );
        assert_eq!(
            decoded.summary(),
            "cipher_suites count=4 bytes=8 values=TLS_AES_128_GCM_SHA256,reserved grease cipher suite 0x0a0a,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,unknown cipher suite 0xbeef"
        );

        let fields = decoded.inspection_fields();
        assert!(fields.contains(&("cipher_suites_count", "4".to_string())));
        assert!(fields.contains(&("cipher_suites_bytes", "8".to_string())));
    }

    #[test]
    fn tls_cipher_suite_list_supports_empty_and_incremental_building() {
        let mut list = TlsCipherSuiteList::empty();
        assert!(list.is_empty());
        assert_eq!(list.encode_to_vec().unwrap(), [0x00, 0x00]);
        assert_eq!(
            TlsCipherSuiteList::decode([0x00, 0x00]).unwrap().suites(),
            &[]
        );

        list.push(TlsCipherSuite::AES_256_GCM_SHA384);
        assert_eq!(list.len(), 1);
        assert_eq!(list.byte_len().unwrap(), 2);
        assert_eq!(list.encoded_len().unwrap(), 4);
        assert_eq!(list.encode_to_vec().unwrap(), [0x00, 0x02, 0x13, 0x02]);

        let from_raws = TlsCipherSuiteList::from_raws([0x1301, 0xff00]);
        assert_eq!(from_raws.raw_values(), vec![0x1301, 0xff00]);
        assert_eq!(
            TlsCipherSuiteList::from([TlsCipherSuite::AES_128_GCM_SHA256]).raw_values(),
            vec![0x1301]
        );
    }

    #[test]
    fn tls_cipher_suite_list_reports_structured_decode_errors() {
        assert_eq!(
            TlsCipherSuite::decode([0x13]).unwrap_err(),
            CrafterError::buffer_too_short("tls.cipher_suite", TLS_CIPHER_SUITE_LEN, 1)
        );
        assert_eq!(
            TlsCipherSuiteList::decode([0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.cipher_suites.length",
                TLS_CIPHER_SUITE_LIST_PREFIX_LEN,
                1,
            )
        );
        assert_eq!(
            TlsCipherSuiteList::decode([0x00, 0x04, 0x13, 0x01]).unwrap_err(),
            CrafterError::buffer_too_short("tls.cipher_suites", 6, 4)
        );
        assert_eq!(
            TlsCipherSuiteList::decode([0x00, 0x03, 0x13, 0x01, 0xaa]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.cipher_suites.length",
                "cipher suite vector length must be even"
            )
        );
    }

    #[test]
    fn tls_cipher_suite_list_rejects_encoded_body_too_large_for_u16_prefix() {
        let suites = vec![TlsCipherSuite::AES_128_GCM_SHA256; 32768];
        let list = TlsCipherSuiteList::new(suites);

        assert_eq!(list.byte_len().unwrap(), 65536);
        assert_eq!(
            list.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.cipher_suites.length",
                "length must fit in two bytes"
            )
        );
    }
}
