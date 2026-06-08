//! IPSec Security Association.
//!
//! A lightweight per-packet crypto context carrying the SPI, mode,
//! encryption/integrity algorithms, keys, salt, and ESN flag that drive
//! ESP/AH and IKEv2 SK crypto. It is not a policy database (SAD/SPD).
//! The seal/open crypto driver is added by later steps; the
//! algorithm-identifier enums live in `algorithms`.

mod algorithms;

pub use algorithms::{
    EncryptionAlgorithm, IntegrityAlgorithm, AUTH_AES_128_GMAC, AUTH_AES_XCBC_96,
    AUTH_HMAC_SHA1_96, AUTH_HMAC_SHA2_256_128, AUTH_HMAC_SHA2_384_192, AUTH_HMAC_SHA2_512_256,
    AUTH_NONE, ENCR_AES_CBC, ENCR_AES_CCM_8, ENCR_AES_CTR, ENCR_AES_GCM_16, ENCR_CHACHA20_POLY1305,
    ENCR_NULL,
};

use crate::{CrafterError, Result};

/// IPSec processing mode: how the protected data is encapsulated.
///
/// Transport mode protects the upper-layer payload of a single IP datagram;
/// tunnel mode protects an entire inner IP datagram (RFC 4301 §3.2). The SA
/// carries the mode so ESP/AH `compile()`/decode know whether the protected
/// next header is an upper-layer protocol or an inner IP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpsecMode {
    /// Transport mode: protects the upper-layer payload in place.
    #[default]
    Transport,
    /// Tunnel mode: protects an entire encapsulated inner IP datagram.
    Tunnel,
}

impl IpsecMode {
    /// Stable lowercase label for inspection summaries (`transport`/`tunnel`).
    pub const fn label(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Tunnel => "tunnel",
        }
    }
}

/// Per-packet IPSec crypto context driving ESP/AH and IKEv2 SK seal/open.
///
/// A `SecurityAssociation` carries exactly the values one packet needs to
/// seal or open: the SPI, the [`IpsecMode`], the encryption and integrity
/// algorithms (Step 07) with their key material and (AEAD/CTR) salt, and the
/// extended-sequence-number flag. It is intentionally **not** a SAD/SPD entry:
/// there is no policy lookup, no anti-replay window, and no key management.
///
/// Build one with the fluent builder:
///
/// ```
/// use crafter::protocols::ipsec::sa::{EncryptionAlgorithm, SecurityAssociation};
///
/// let sa = SecurityAssociation::new(0x0000_2000)
///     .encryption(EncryptionAlgorithm::AesGcm16, vec![0u8; 16])
///     .salt(vec![0u8; 4])
///     .tunnel()
///     .extended_sequence(true);
/// assert!(sa.validate().is_ok());
/// ```
///
/// Keys are caller-supplied and never logged: the [`Debug`] impl and
/// [`SecurityAssociation::summary`] redact all key and salt bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct SecurityAssociation {
    /// Security Parameters Index identifying this SA on the wire.
    pub spi: u32,
    /// Processing mode (transport or tunnel).
    pub mode: IpsecMode,
    /// Encryption / AEAD algorithm (Step 07).
    pub enc: EncryptionAlgorithm,
    /// Encryption key material (excludes the per-SA salt).
    pub enc_key: Vec<u8>,
    /// Separate integrity algorithm (`None` for AEAD suites).
    pub integ: IntegrityAlgorithm,
    /// Integrity key material (empty for `None`/AEAD).
    pub integ_key: Vec<u8>,
    /// Per-SA salt (implicit nonce prefix) for AEAD/CTR suites.
    pub salt: Vec<u8>,
    /// Whether 64-bit Extended Sequence Numbers are in use (RFC 4304).
    pub esn: bool,
}

impl SecurityAssociation {
    /// Start building an SA for the given SPI.
    ///
    /// Defaults: transport mode, `ENCR_NULL` encryption with no key,
    /// `NONE` integrity with no key, empty salt, ESN disabled. Use the fluent
    /// setters to fill in the algorithms and key material.
    pub const fn new(spi: u32) -> Self {
        Self {
            spi,
            mode: IpsecMode::Transport,
            enc: EncryptionAlgorithm::Null,
            enc_key: Vec::new(),
            integ: IntegrityAlgorithm::None,
            integ_key: Vec::new(),
            salt: Vec::new(),
            esn: false,
        }
    }

    /// Set the encryption algorithm and its key (consuming builder step).
    #[must_use]
    pub fn encryption(mut self, alg: EncryptionAlgorithm, key: impl Into<Vec<u8>>) -> Self {
        self.enc = alg;
        self.enc_key = key.into();
        self
    }

    /// Set the separate integrity algorithm and its key (consuming builder step).
    #[must_use]
    pub fn integrity(mut self, alg: IntegrityAlgorithm, key: impl Into<Vec<u8>>) -> Self {
        self.integ = alg;
        self.integ_key = key.into();
        self
    }

    /// Set the per-SA salt (implicit nonce prefix) for AEAD/CTR suites.
    #[must_use]
    pub fn salt(mut self, salt: impl Into<Vec<u8>>) -> Self {
        self.salt = salt.into();
        self
    }

    /// Select tunnel mode.
    #[must_use]
    pub fn tunnel(mut self) -> Self {
        self.mode = IpsecMode::Tunnel;
        self
    }

    /// Select transport mode (the default).
    #[must_use]
    pub fn transport(mut self) -> Self {
        self.mode = IpsecMode::Transport;
        self
    }

    /// Enable or disable 64-bit Extended Sequence Numbers (RFC 4304).
    #[must_use]
    pub fn extended_sequence(mut self, esn: bool) -> Self {
        self.esn = esn;
        self
    }

    /// Validate that the supplied key and salt lengths match the algorithm
    /// metadata (Step 07).
    ///
    /// Returns a structured [`CrafterError::InvalidFieldValue`] when a key or
    /// salt length disagrees with the algorithm's required length. This never
    /// mutates the caller's values — a deliberately wrong key is reported, not
    /// silently corrected, so malformed packets remain buildable by going
    /// around `validate()`.
    ///
    /// `Unknown` algorithms carry no length metadata and are accepted as-is,
    /// preserving the malformed-input round-trip contract.
    pub fn validate(&self) -> Result<()> {
        // Encryption key length, when the algorithm specifies one.
        if let Some(expected) = self.enc.key_len() {
            if self.enc_key.len() != expected {
                return Err(CrafterError::invalid_field_value(
                    "ipsec.sa.enc_key",
                    "encryption key length does not match algorithm",
                ));
            }
        }

        // Salt length must match the algorithm's salt requirement.
        if self.salt.len() != self.enc.salt_len() {
            return Err(CrafterError::invalid_field_value(
                "ipsec.sa.salt",
                "salt length does not match algorithm",
            ));
        }

        // Integrity key: AES-based integrity uses a 16-octet AES key; HMAC
        // accepts any length but an empty key is almost certainly an error.
        match self.integ {
            IntegrityAlgorithm::None => {}
            IntegrityAlgorithm::AesXcbc96 | IntegrityAlgorithm::AesGmac => {
                if self.integ_key.len() != 16 {
                    return Err(CrafterError::invalid_field_value(
                        "ipsec.sa.integ_key",
                        "integrity key length does not match algorithm",
                    ));
                }
            }
            _ => {
                if self.integ_key.is_empty() {
                    return Err(CrafterError::invalid_field_value(
                        "ipsec.sa.integ_key",
                        "integrity algorithm requires a non-empty key",
                    ));
                }
            }
        }

        Ok(())
    }

    /// One-line inspection summary that never prints key or salt bytes.
    ///
    /// Example: `SA(spi=0x00002000, mode=transport, enc=AES_GCM_16, integ=NONE, esn=false)`.
    pub fn summary(&self) -> String {
        format!(
            "SA(spi=0x{:08x}, mode={}, enc={}, integ={}, esn={})",
            self.spi,
            self.mode.label(),
            encryption_label(self.enc),
            integrity_label(self.integ),
            self.esn,
        )
    }
}

impl std::fmt::Debug for SecurityAssociation {
    /// Redacted debug view: key and salt bytes are replaced by their lengths so
    /// caller key material never lands in a log or panic message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityAssociation")
            .field("spi", &format_args!("0x{:08x}", self.spi))
            .field("mode", &self.mode)
            .field("enc", &self.enc)
            .field("enc_key", &format_args!("<{} bytes redacted>", self.enc_key.len()))
            .field("integ", &self.integ)
            .field(
                "integ_key",
                &format_args!("<{} bytes redacted>", self.integ_key.len()),
            )
            .field("salt", &format_args!("<{} bytes redacted>", self.salt.len()))
            .field("esn", &self.esn)
            .finish()
    }
}

/// Stable IANA-style label for an encryption algorithm (for summaries).
fn encryption_label(alg: EncryptionAlgorithm) -> String {
    match alg {
        EncryptionAlgorithm::Null => "NULL".to_string(),
        EncryptionAlgorithm::AesCbc => "AES_CBC".to_string(),
        EncryptionAlgorithm::AesCtr => "AES_CTR".to_string(),
        EncryptionAlgorithm::AesCcm8 => "AES_CCM_8".to_string(),
        EncryptionAlgorithm::AesGcm16 => "AES_GCM_16".to_string(),
        EncryptionAlgorithm::ChaCha20Poly1305 => "CHACHA20_POLY1305".to_string(),
        EncryptionAlgorithm::Unknown(id) => format!("UNKNOWN({id})"),
    }
}

/// Stable IANA-style label for an integrity algorithm (for summaries).
fn integrity_label(alg: IntegrityAlgorithm) -> String {
    match alg {
        IntegrityAlgorithm::None => "NONE".to_string(),
        IntegrityAlgorithm::HmacSha1_96 => "HMAC_SHA1_96".to_string(),
        IntegrityAlgorithm::AesXcbc96 => "AES_XCBC_96".to_string(),
        IntegrityAlgorithm::AesGmac => "AES_128_GMAC".to_string(),
        IntegrityAlgorithm::HmacSha2_256_128 => "HMAC_SHA2_256_128".to_string(),
        IntegrityAlgorithm::HmacSha2_384_192 => "HMAC_SHA2_384_192".to_string(),
        IntegrityAlgorithm::HmacSha2_512_256 => "HMAC_SHA2_512_256".to_string(),
        IntegrityAlgorithm::Unknown(id) => format!("UNKNOWN({id})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_round_trips_all_fields() {
        let sa = SecurityAssociation::new(0x0000_2000)
            .encryption(EncryptionAlgorithm::AesGcm16, vec![0xAAu8; 16])
            .integrity(IntegrityAlgorithm::None, Vec::new())
            .salt(vec![0x01, 0x02, 0x03, 0x04])
            .tunnel()
            .extended_sequence(true);

        assert_eq!(sa.spi, 0x0000_2000);
        assert_eq!(sa.mode, IpsecMode::Tunnel);
        assert_eq!(sa.enc, EncryptionAlgorithm::AesGcm16);
        assert_eq!(sa.enc_key, vec![0xAAu8; 16]);
        assert_eq!(sa.integ, IntegrityAlgorithm::None);
        assert!(sa.integ_key.is_empty());
        assert_eq!(sa.salt, vec![0x01, 0x02, 0x03, 0x04]);
        assert!(sa.esn);

        // transport() flips the mode back; ESN toggles off.
        let sa = sa.transport().extended_sequence(false);
        assert_eq!(sa.mode, IpsecMode::Transport);
        assert!(!sa.esn);
    }

    #[test]
    fn new_defaults_are_transport_null_none() {
        let sa = SecurityAssociation::new(1);
        assert_eq!(sa.spi, 1);
        assert_eq!(sa.mode, IpsecMode::Transport);
        assert_eq!(sa.enc, EncryptionAlgorithm::Null);
        assert_eq!(sa.integ, IntegrityAlgorithm::None);
        assert!(sa.enc_key.is_empty());
        assert!(sa.integ_key.is_empty());
        assert!(sa.salt.is_empty());
        assert!(!sa.esn);
    }

    #[test]
    fn validate_accepts_a_correct_aead_sa() {
        let sa = SecurityAssociation::new(0x10)
            .encryption(EncryptionAlgorithm::AesGcm16, vec![0u8; 16])
            .salt(vec![0u8; 4]);
        assert!(sa.validate().is_ok());
    }

    #[test]
    fn validate_accepts_a_correct_cbc_hmac_sa() {
        let sa = SecurityAssociation::new(0x10)
            .encryption(EncryptionAlgorithm::AesCbc, vec![0u8; 16])
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0u8; 32]);
        assert!(sa.validate().is_ok());
    }

    #[test]
    fn validate_rejects_wrong_length_encryption_key() {
        let sa = SecurityAssociation::new(0x10)
            .encryption(EncryptionAlgorithm::AesGcm16, vec![0u8; 8]) // should be 16
            .salt(vec![0u8; 4]);
        let err = sa.validate().unwrap_err();
        assert_eq!(
            err,
            CrafterError::invalid_field_value(
                "ipsec.sa.enc_key",
                "encryption key length does not match algorithm",
            )
        );
        // The caller's wrong key is preserved untouched (never silently fixed).
        assert_eq!(sa.enc_key.len(), 8);
    }

    #[test]
    fn validate_rejects_wrong_length_salt() {
        let sa = SecurityAssociation::new(0x10)
            .encryption(EncryptionAlgorithm::AesGcm16, vec![0u8; 16])
            .salt(vec![0u8; 3]); // GCM salt is 4
        assert!(sa.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_hmac_key() {
        let sa = SecurityAssociation::new(0x10)
            .encryption(EncryptionAlgorithm::AesCbc, vec![0u8; 16])
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, Vec::new());
        assert!(sa.validate().is_err());
    }

    #[test]
    fn validate_accepts_unknown_algorithm() {
        // Unknown carries no length metadata: validate must not reject it.
        let sa = SecurityAssociation::new(0x10)
            .encryption(EncryptionAlgorithm::Unknown(99), vec![0u8; 7]);
        assert!(sa.validate().is_ok());
    }

    #[test]
    fn summary_omits_key_material() {
        let sa = SecurityAssociation::new(0x0000_2000)
            .encryption(EncryptionAlgorithm::AesGcm16, vec![0xDEu8; 16])
            .salt(vec![0xBEu8; 4]);
        let summary = sa.summary();
        assert_eq!(
            summary,
            "SA(spi=0x00002000, mode=transport, enc=AES_GCM_16, integ=NONE, esn=false)"
        );
        // No run of repeated key/salt bytes may appear in the summary (the
        // single substrings "de"/"be" occur naturally in words like "mode").
        assert!(!summary.contains("dede"));
        assert!(!summary.contains("bebe"));
        assert!(!summary.to_lowercase().contains("dede"));
        assert!(!summary.to_lowercase().contains("bebe"));
    }

    #[test]
    fn debug_redacts_key_material() {
        let sa = SecurityAssociation::new(0x10)
            .encryption(EncryptionAlgorithm::AesCbc, vec![0xABu8; 16])
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0xCDu8; 32])
            .salt(vec![0xEFu8; 0]);
        let rendered = format!("{sa:?}");
        assert!(rendered.contains("redacted"));
        // Raw key bytes must not be present (no byte arrays, no hex of keys).
        assert!(!rendered.contains("171")); // 0xAB as decimal
        assert!(!rendered.contains("ab, ab"));
        assert!(!rendered.contains("cd, cd"));
    }
}
