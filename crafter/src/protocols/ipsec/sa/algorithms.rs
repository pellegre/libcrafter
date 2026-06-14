//! IPSec algorithm identifiers and metadata.
//!
//! [`EncryptionAlgorithm`] and [`IntegrityAlgorithm`] map the IANA IKEv2
//! transform IDs (Transform Type 1 = ENCR, Transform Type 3 = INTEG) to the
//! crypto primitives in [`super::super::crypto`] and carry the key/IV/ICV/block
//! metadata the SA (Step 08) and the IKEv2 SA payload (Step 35) need to drive
//! ESP/AH/SK crypto.
//!
//! The numeric IDs come from the IANA "Internet Key Exchange Version 2 (IKEv2)
//! Parameters" registry as recorded in `docs/internal/manifests/ipsec-rfc-manifest.md` (Step 01):
//!
//! Encryption (Transform Type 1):
//! - `ENCR_NULL` = 11 (RFC 2410)
//! - `ENCR_AES_CBC` = 12 (RFC 3602)
//! - `ENCR_AES_CTR` = 13 (RFC 3686)
//! - `ENCR_AES_CCM_8` = 14 (RFC 4309)
//! - `ENCR_AES_GCM_16` = 20 (RFC 4106)
//! - `ENCR_CHACHA20_POLY1305` = 28 (RFC 7634)
//!
//! Integrity (Transform Type 3):
//! - `NONE` = 0
//! - `AUTH_HMAC_SHA1_96` = 2 (RFC 2404)
//! - `AUTH_AES_XCBC_96` = 5 (RFC 3566)
//! - `AUTH_AES_128_GMAC` = 9 (RFC 4543)
//! - `AUTH_HMAC_SHA2_256_128` = 12 (RFC 4868)
//! - `AUTH_HMAC_SHA2_384_192` = 13 (RFC 4868)
//! - `AUTH_HMAC_SHA2_512_256` = 14 (RFC 4868)
//!
//! An unrecognized transform ID is preserved as an `Unknown(u16)` variant rather
//! than rejected, honoring the malformed-input contract: a decoded SA proposal
//! carrying an unknown algorithm round-trips its codepoint instead of erroring.

use super::super::crypto::{AeadTransform, CipherTransform, IntegrityTransform};
use crate::{CrafterError, Result};

// --- Encryption (Transform Type 1) transform IDs ----------------------------

/// `ENCR_NULL` IKEv2 transform ID (RFC 2410).
pub const ENCR_NULL: u16 = 11;
/// `ENCR_AES_CBC` IKEv2 transform ID (RFC 3602).
pub const ENCR_AES_CBC: u16 = 12;
/// `ENCR_AES_CTR` IKEv2 transform ID (RFC 3686).
pub const ENCR_AES_CTR: u16 = 13;
/// `ENCR_AES_CCM_8` IKEv2 transform ID (RFC 4309).
pub const ENCR_AES_CCM_8: u16 = 14;
/// `ENCR_AES_GCM_16` IKEv2 transform ID (RFC 4106).
pub const ENCR_AES_GCM_16: u16 = 20;
/// `ENCR_CHACHA20_POLY1305` IKEv2 transform ID (RFC 7634).
pub const ENCR_CHACHA20_POLY1305: u16 = 28;

// --- Integrity (Transform Type 3) transform IDs -----------------------------

/// `NONE` integrity transform ID (no integrity / integrity supplied by AEAD).
pub const AUTH_NONE: u16 = 0;
/// `AUTH_HMAC_SHA1_96` IKEv2 transform ID (RFC 2404).
pub const AUTH_HMAC_SHA1_96: u16 = 2;
/// `AUTH_AES_XCBC_96` IKEv2 transform ID (RFC 3566).
pub const AUTH_AES_XCBC_96: u16 = 5;
/// `AUTH_AES_128_GMAC` IKEv2 transform ID (RFC 4543).
pub const AUTH_AES_128_GMAC: u16 = 9;
/// `AUTH_HMAC_SHA2_256_128` IKEv2 transform ID (RFC 4868).
pub const AUTH_HMAC_SHA2_256_128: u16 = 12;
/// `AUTH_HMAC_SHA2_384_192` IKEv2 transform ID (RFC 4868).
pub const AUTH_HMAC_SHA2_384_192: u16 = 13;
/// `AUTH_HMAC_SHA2_512_256` IKEv2 transform ID (RFC 4868).
pub const AUTH_HMAC_SHA2_512_256: u16 = 14;

/// IPSec encryption / AEAD algorithm, identified by its IKEv2 ENCR transform ID.
///
/// Each known variant bridges a wire codepoint to either a non-AEAD
/// [`CipherTransform`] (with a separate [`IntegrityAlgorithm`]) or an
/// [`AeadTransform`] (combined confidentiality + integrity). `Unknown` preserves
/// an unrecognized transform ID so a decoded SA proposal round-trips it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// `ENCR_NULL` (RFC 2410): no confidentiality.
    Null,
    /// `ENCR_AES_CBC` (RFC 3602): AES-128-CBC, separate integrity.
    AesCbc,
    /// `ENCR_AES_CTR` (RFC 3686): AES-128-CTR, separate integrity.
    AesCtr,
    /// `ENCR_AES_CCM_8` (RFC 4309): AEAD, 8-octet ICV.
    AesCcm8,
    /// `ENCR_AES_GCM_16` (RFC 4106): AEAD, 16-octet ICV.
    AesGcm16,
    /// `ENCR_CHACHA20_POLY1305` (RFC 7634): AEAD, 16-octet ICV.
    ChaCha20Poly1305,
    /// An IKEv2 ENCR transform ID `crafter` does not model, preserved verbatim.
    Unknown(u16),
}

impl EncryptionAlgorithm {
    /// IANA IKEv2 ENCR transform ID for this algorithm.
    pub const fn transform_id(self) -> u16 {
        match self {
            Self::Null => ENCR_NULL,
            Self::AesCbc => ENCR_AES_CBC,
            Self::AesCtr => ENCR_AES_CTR,
            Self::AesCcm8 => ENCR_AES_CCM_8,
            Self::AesGcm16 => ENCR_AES_GCM_16,
            Self::ChaCha20Poly1305 => ENCR_CHACHA20_POLY1305,
            Self::Unknown(id) => id,
        }
    }

    /// Whether this algorithm is an AEAD (combined confidentiality + integrity).
    ///
    /// AEAD suites carry their own ICV and pair with [`IntegrityAlgorithm::None`];
    /// non-AEAD ciphers require a separate [`IntegrityAlgorithm`]. `Unknown` is
    /// treated as non-AEAD (conservative; it carries no AEAD parameters).
    pub const fn is_aead(self) -> bool {
        matches!(
            self,
            Self::AesCcm8 | Self::AesGcm16 | Self::ChaCha20Poly1305
        )
    }

    /// Cipher key length in octets (excludes the per-SA salt), or `None` when the
    /// transform takes no key (`NULL`) or is `Unknown`.
    ///
    /// AES variants use the AES-128 key the underlying transforms implement
    /// (16 octets); ChaCha20-Poly1305 uses a 256-bit key (32 octets). Larger AES
    /// key sizes (192/256) are out of scope for the current transforms.
    pub const fn key_len(self) -> Option<usize> {
        match self {
            Self::Null => None,
            Self::AesCbc | Self::AesCtr | Self::AesCcm8 | Self::AesGcm16 => Some(16),
            Self::ChaCha20Poly1305 => Some(32),
            Self::Unknown(_) => None,
        }
    }

    /// Explicit per-packet IV length in octets carried on the wire.
    ///
    /// `NULL` has no IV. CBC uses a 16-octet IV (RFC 3602); CTR and all AEAD
    /// suites use an 8-octet IV (RFC 3686 / RFC 4106 / RFC 4309 / RFC 7634).
    pub const fn iv_len(self) -> usize {
        match self {
            Self::Null => 0,
            Self::AesCbc => 16,
            Self::AesCtr | Self::AesCcm8 | Self::AesGcm16 | Self::ChaCha20Poly1305 => 8,
            Self::Unknown(_) => 0,
        }
    }

    /// Per-SA salt length in octets (the implicit, fixed nonce prefix).
    ///
    /// Only AEAD suites and CTR-style ciphers carry a salt. AES-GCM and
    /// ChaCha20-Poly1305 use a 4-octet salt; AES-CCM-8 uses a 3-octet salt
    /// (RFC 4309 §4); AES-CTR uses a 4-octet salt (RFC 3686). CBC, NULL, and
    /// `Unknown` carry no salt.
    pub const fn salt_len(self) -> usize {
        match self {
            Self::AesCtr | Self::AesGcm16 | Self::ChaCha20Poly1305 => 4,
            Self::AesCcm8 => 3,
            Self::Null | Self::AesCbc | Self::Unknown(_) => 0,
        }
    }

    /// Cipher block size in octets used for ESP padding (RFC 4303 §2.4).
    ///
    /// AES-CBC pads to its 16-octet block. Keystream / AEAD modes (CTR, GCM,
    /// CCM, ChaCha20) and NULL impose no block alignment (block size 1).
    /// `Unknown` defaults to 1 (no forced padding).
    pub const fn block_size(self) -> usize {
        match self {
            Self::AesCbc => 16,
            Self::Null
            | Self::AesCtr
            | Self::AesCcm8
            | Self::AesGcm16
            | Self::ChaCha20Poly1305
            | Self::Unknown(_) => 1,
        }
    }

    /// ICV (authentication tag) length in octets for AEAD suites, or `None` for
    /// non-AEAD ciphers (whose integrity comes from a separate
    /// [`IntegrityAlgorithm`]) and `Unknown`.
    pub const fn icv_len(self) -> Option<usize> {
        match self {
            Self::AesGcm16 | Self::ChaCha20Poly1305 => Some(16),
            Self::AesCcm8 => Some(8),
            Self::Null | Self::AesCbc | Self::AesCtr | Self::Unknown(_) => None,
        }
    }

    /// Resolve the matching non-AEAD [`CipherTransform`] (Steps 05).
    ///
    /// Returns a structured error for AEAD algorithms (use [`Self::aead_transform`])
    /// and for `Unknown` codepoints.
    pub fn cipher_transform(self) -> Result<CipherTransform> {
        match self {
            Self::Null => Ok(CipherTransform::Null),
            Self::AesCbc => Ok(CipherTransform::AesCbc),
            Self::AesCtr => Ok(CipherTransform::AesCtr),
            Self::AesCcm8 | Self::AesGcm16 | Self::ChaCha20Poly1305 => {
                Err(CrafterError::invalid_field_value(
                    "ipsec.sa.encryption",
                    "AEAD algorithm has no separate cipher transform",
                ))
            }
            Self::Unknown(_) => Err(CrafterError::invalid_field_value(
                "ipsec.sa.encryption",
                "unknown encryption transform ID has no cipher transform",
            )),
        }
    }

    /// Resolve the matching [`AeadTransform`] (Step 06).
    ///
    /// Returns a structured error for non-AEAD algorithms (use
    /// [`Self::cipher_transform`]) and for `Unknown` codepoints.
    pub fn aead_transform(self) -> Result<AeadTransform> {
        match self {
            Self::AesGcm16 => Ok(AeadTransform::AesGcm16),
            Self::AesCcm8 => Ok(AeadTransform::AesCcm8),
            Self::ChaCha20Poly1305 => Ok(AeadTransform::ChaCha20Poly1305),
            Self::Null | Self::AesCbc | Self::AesCtr => Err(CrafterError::invalid_field_value(
                "ipsec.sa.encryption",
                "non-AEAD algorithm has no AEAD transform",
            )),
            Self::Unknown(_) => Err(CrafterError::invalid_field_value(
                "ipsec.sa.encryption",
                "unknown encryption transform ID has no AEAD transform",
            )),
        }
    }
}

impl From<u16> for EncryptionAlgorithm {
    /// Map an IKEv2 ENCR transform ID to an [`EncryptionAlgorithm`], preserving
    /// an unrecognized ID as `Unknown` (never erroring).
    fn from(id: u16) -> Self {
        match id {
            ENCR_NULL => Self::Null,
            ENCR_AES_CBC => Self::AesCbc,
            ENCR_AES_CTR => Self::AesCtr,
            ENCR_AES_CCM_8 => Self::AesCcm8,
            ENCR_AES_GCM_16 => Self::AesGcm16,
            ENCR_CHACHA20_POLY1305 => Self::ChaCha20Poly1305,
            other => Self::Unknown(other),
        }
    }
}

// `TryFrom<u16>` is provided automatically by the blanket
// `impl<T, U: Into<T>> TryFrom<U> for T` (`Error = Infallible`): unknown IDs are
// preserved as `Unknown` rather than rejected, so the conversion never fails.

impl From<EncryptionAlgorithm> for u16 {
    fn from(algorithm: EncryptionAlgorithm) -> Self {
        algorithm.transform_id()
    }
}

/// IPSec integrity algorithm, identified by its IKEv2 INTEG transform ID.
///
/// Each known variant bridges a wire codepoint to an [`IntegrityTransform`].
/// `None` selects no separate integrity (used with AEAD encryption). `Unknown`
/// preserves an unrecognized transform ID so a decoded SA proposal round-trips
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityAlgorithm {
    /// `NONE` (transform ID 0): no separate integrity (AEAD supplies its own).
    None,
    /// `AUTH_HMAC_SHA1_96` (RFC 2404): 96-bit ICV.
    HmacSha1_96,
    /// `AUTH_AES_XCBC_96` (RFC 3566): 96-bit ICV.
    AesXcbc96,
    /// `AUTH_AES_128_GMAC` (RFC 4543): 128-bit ICV.
    AesGmac,
    /// `AUTH_HMAC_SHA2_256_128` (RFC 4868): 128-bit ICV.
    HmacSha2_256_128,
    /// `AUTH_HMAC_SHA2_384_192` (RFC 4868): 192-bit ICV.
    HmacSha2_384_192,
    /// `AUTH_HMAC_SHA2_512_256` (RFC 4868): 256-bit ICV.
    HmacSha2_512_256,
    /// An IKEv2 INTEG transform ID `crafter` does not model, preserved verbatim.
    Unknown(u16),
}

impl IntegrityAlgorithm {
    /// IANA IKEv2 INTEG transform ID for this algorithm.
    pub const fn transform_id(self) -> u16 {
        match self {
            Self::None => AUTH_NONE,
            Self::HmacSha1_96 => AUTH_HMAC_SHA1_96,
            Self::AesXcbc96 => AUTH_AES_XCBC_96,
            Self::AesGmac => AUTH_AES_128_GMAC,
            Self::HmacSha2_256_128 => AUTH_HMAC_SHA2_256_128,
            Self::HmacSha2_384_192 => AUTH_HMAC_SHA2_384_192,
            Self::HmacSha2_512_256 => AUTH_HMAC_SHA2_512_256,
            Self::Unknown(id) => id,
        }
    }

    /// ICV length in octets, or `None` for `NONE` and `Unknown` (no integrity
    /// output is produced).
    pub const fn icv_len(self) -> Option<usize> {
        match self {
            Self::None => None,
            Self::HmacSha1_96 => Some(12),      // RFC 2404: 96 bits
            Self::AesXcbc96 => Some(12),        // RFC 3566: 96 bits
            Self::AesGmac => Some(16),          // RFC 4543: 128 bits
            Self::HmacSha2_256_128 => Some(16), // RFC 4868: 128 bits
            Self::HmacSha2_384_192 => Some(24), // RFC 4868: 192 bits
            Self::HmacSha2_512_256 => Some(32), // RFC 4868: 256 bits
            Self::Unknown(_) => None,
        }
    }

    /// Resolve the matching [`IntegrityTransform`] (Step 04).
    ///
    /// Returns a structured error for `None` (no integrity transform exists) and
    /// for `Unknown` codepoints.
    pub fn integrity_transform(self) -> Result<IntegrityTransform> {
        match self {
            Self::HmacSha1_96 => Ok(IntegrityTransform::HmacSha1_96),
            Self::AesXcbc96 => Ok(IntegrityTransform::AesXcbcMac96),
            Self::AesGmac => Ok(IntegrityTransform::AesGmac),
            Self::HmacSha2_256_128 => Ok(IntegrityTransform::HmacSha2_256_128),
            Self::HmacSha2_384_192 => Ok(IntegrityTransform::HmacSha2_384_192),
            Self::HmacSha2_512_256 => Ok(IntegrityTransform::HmacSha2_512_256),
            Self::None => Err(CrafterError::invalid_field_value(
                "ipsec.sa.integrity",
                "NONE integrity has no transform",
            )),
            Self::Unknown(_) => Err(CrafterError::invalid_field_value(
                "ipsec.sa.integrity",
                "unknown integrity transform ID has no transform",
            )),
        }
    }
}

impl From<u16> for IntegrityAlgorithm {
    /// Map an IKEv2 INTEG transform ID to an [`IntegrityAlgorithm`], preserving
    /// an unrecognized ID as `Unknown` (never erroring).
    fn from(id: u16) -> Self {
        match id {
            AUTH_NONE => Self::None,
            AUTH_HMAC_SHA1_96 => Self::HmacSha1_96,
            AUTH_AES_XCBC_96 => Self::AesXcbc96,
            AUTH_AES_128_GMAC => Self::AesGmac,
            AUTH_HMAC_SHA2_256_128 => Self::HmacSha2_256_128,
            AUTH_HMAC_SHA2_384_192 => Self::HmacSha2_384_192,
            AUTH_HMAC_SHA2_512_256 => Self::HmacSha2_512_256,
            other => Self::Unknown(other),
        }
    }
}

// `TryFrom<u16>` is provided automatically by the blanket
// `impl<T, U: Into<T>> TryFrom<U> for T` (`Error = Infallible`): unknown IDs are
// preserved as `Unknown` rather than rejected, so the conversion never fails.

impl From<IntegrityAlgorithm> for u16 {
    fn from(algorithm: IntegrityAlgorithm) -> Self {
        algorithm.transform_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Encryption transform IDs (IANA / docs/internal/manifests/ipsec-rfc-manifest.md) -------

    #[test]
    fn encryption_transform_ids_match_iana() {
        assert_eq!(EncryptionAlgorithm::Null.transform_id(), 11);
        assert_eq!(EncryptionAlgorithm::AesCbc.transform_id(), 12);
        assert_eq!(EncryptionAlgorithm::AesCtr.transform_id(), 13);
        assert_eq!(EncryptionAlgorithm::AesCcm8.transform_id(), 14);
        assert_eq!(EncryptionAlgorithm::AesGcm16.transform_id(), 20);
        assert_eq!(EncryptionAlgorithm::ChaCha20Poly1305.transform_id(), 28);
    }

    #[test]
    fn encryption_id_constants_match_manifest() {
        assert_eq!(ENCR_NULL, 11);
        assert_eq!(ENCR_AES_CBC, 12);
        assert_eq!(ENCR_AES_CTR, 13);
        assert_eq!(ENCR_AES_CCM_8, 14);
        assert_eq!(ENCR_AES_GCM_16, 20);
        assert_eq!(ENCR_CHACHA20_POLY1305, 28);
    }

    // Exercise the `TryFrom<u16>` surface explicitly. The blanket
    // `TryFrom` (from `From<u16>`) is infallible, so clippy flags the
    // `.unwrap()`; that is exactly the point — the conversion never fails.
    #[allow(clippy::unnecessary_fallible_conversions)]
    #[test]
    fn encryption_from_u16_round_trips() {
        for algo in [
            EncryptionAlgorithm::Null,
            EncryptionAlgorithm::AesCbc,
            EncryptionAlgorithm::AesCtr,
            EncryptionAlgorithm::AesCcm8,
            EncryptionAlgorithm::AesGcm16,
            EncryptionAlgorithm::ChaCha20Poly1305,
        ] {
            let id = algo.transform_id();
            assert_eq!(EncryptionAlgorithm::from(id), algo);
            assert_eq!(u16::from(algo), id);
            assert_eq!(EncryptionAlgorithm::try_from(id).unwrap(), algo);
        }
    }

    #[test]
    fn encryption_unknown_id_is_preserved() {
        // 99 is not an assigned ENCR transform ID; it must round-trip verbatim.
        let algo = EncryptionAlgorithm::from(99);
        assert_eq!(algo, EncryptionAlgorithm::Unknown(99));
        assert_eq!(algo.transform_id(), 99);
        assert_eq!(u16::from(algo), 99);
        assert!(algo.cipher_transform().is_err());
        assert!(algo.aead_transform().is_err());
    }

    #[test]
    fn encryption_aead_classification() {
        assert!(!EncryptionAlgorithm::Null.is_aead());
        assert!(!EncryptionAlgorithm::AesCbc.is_aead());
        assert!(!EncryptionAlgorithm::AesCtr.is_aead());
        assert!(EncryptionAlgorithm::AesCcm8.is_aead());
        assert!(EncryptionAlgorithm::AesGcm16.is_aead());
        assert!(EncryptionAlgorithm::ChaCha20Poly1305.is_aead());
        assert!(!EncryptionAlgorithm::Unknown(99).is_aead());
    }

    #[test]
    fn encryption_metadata_matches_rfcs() {
        // NULL (RFC 2410): no key/IV/salt, block size 1, no ICV.
        let null = EncryptionAlgorithm::Null;
        assert_eq!(null.key_len(), None);
        assert_eq!(null.iv_len(), 0);
        assert_eq!(null.salt_len(), 0);
        assert_eq!(null.block_size(), 1);
        assert_eq!(null.icv_len(), None);

        // AES-CBC (RFC 3602): 16-octet key/IV, 16-octet block, no salt/ICV.
        let cbc = EncryptionAlgorithm::AesCbc;
        assert_eq!(cbc.key_len(), Some(16));
        assert_eq!(cbc.iv_len(), 16);
        assert_eq!(cbc.salt_len(), 0);
        assert_eq!(cbc.block_size(), 16);
        assert_eq!(cbc.icv_len(), None);

        // AES-CTR (RFC 3686): 16-octet key, 8-octet IV, 4-octet salt, block 1.
        let ctr = EncryptionAlgorithm::AesCtr;
        assert_eq!(ctr.key_len(), Some(16));
        assert_eq!(ctr.iv_len(), 8);
        assert_eq!(ctr.salt_len(), 4);
        assert_eq!(ctr.block_size(), 1);
        assert_eq!(ctr.icv_len(), None);

        // AES-CCM-8 (RFC 4309): 16-octet key, 8-octet IV, 3-octet salt, 8 ICV.
        let ccm = EncryptionAlgorithm::AesCcm8;
        assert_eq!(ccm.key_len(), Some(16));
        assert_eq!(ccm.iv_len(), 8);
        assert_eq!(ccm.salt_len(), 3);
        assert_eq!(ccm.block_size(), 1);
        assert_eq!(ccm.icv_len(), Some(8));

        // AES-GCM-16 (RFC 4106): 16-octet key, 8-octet IV, 4-octet salt, 16 ICV.
        let gcm = EncryptionAlgorithm::AesGcm16;
        assert_eq!(gcm.key_len(), Some(16));
        assert_eq!(gcm.iv_len(), 8);
        assert_eq!(gcm.salt_len(), 4);
        assert_eq!(gcm.block_size(), 1);
        assert_eq!(gcm.icv_len(), Some(16));

        // ChaCha20-Poly1305 (RFC 7634): 32-octet key, 8 IV, 4 salt, 16 ICV.
        let cc = EncryptionAlgorithm::ChaCha20Poly1305;
        assert_eq!(cc.key_len(), Some(32));
        assert_eq!(cc.iv_len(), 8);
        assert_eq!(cc.salt_len(), 4);
        assert_eq!(cc.block_size(), 1);
        assert_eq!(cc.icv_len(), Some(16));
    }

    #[test]
    fn encryption_transform_resolution_matches_crypto_primitives() {
        assert_eq!(
            EncryptionAlgorithm::Null.cipher_transform().unwrap(),
            CipherTransform::Null
        );
        assert_eq!(
            EncryptionAlgorithm::AesCbc.cipher_transform().unwrap(),
            CipherTransform::AesCbc
        );
        assert_eq!(
            EncryptionAlgorithm::AesCtr.cipher_transform().unwrap(),
            CipherTransform::AesCtr
        );
        assert_eq!(
            EncryptionAlgorithm::AesGcm16.aead_transform().unwrap(),
            AeadTransform::AesGcm16
        );
        assert_eq!(
            EncryptionAlgorithm::AesCcm8.aead_transform().unwrap(),
            AeadTransform::AesCcm8
        );
        assert_eq!(
            EncryptionAlgorithm::ChaCha20Poly1305
                .aead_transform()
                .unwrap(),
            AeadTransform::ChaCha20Poly1305
        );

        // Cross errors: AEAD has no cipher transform, cipher has no AEAD.
        assert!(EncryptionAlgorithm::AesGcm16.cipher_transform().is_err());
        assert!(EncryptionAlgorithm::AesCbc.aead_transform().is_err());

        // The metadata must agree with the resolved AEAD transform.
        for algo in [
            EncryptionAlgorithm::AesGcm16,
            EncryptionAlgorithm::AesCcm8,
            EncryptionAlgorithm::ChaCha20Poly1305,
        ] {
            let aead = algo.aead_transform().unwrap();
            assert_eq!(algo.icv_len(), Some(aead.icv_len()));
            assert_eq!(algo.key_len(), Some(aead.key_len()));
            assert_eq!(algo.iv_len(), aead.iv_len());
            assert_eq!(algo.salt_len(), aead.salt_len());
        }

        // Non-AEAD ciphers agree with the resolved cipher transform.
        for algo in [
            EncryptionAlgorithm::AesCbc,
            EncryptionAlgorithm::AesCtr,
            EncryptionAlgorithm::Null,
        ] {
            let cipher = algo.cipher_transform().unwrap();
            assert_eq!(algo.iv_len(), cipher.iv_len());
            assert_eq!(algo.block_size(), cipher.block_size());
        }
    }

    // --- Integrity transform IDs (IANA / docs/internal/manifests/ipsec-rfc-manifest.md) --------

    #[test]
    fn integrity_transform_ids_match_iana() {
        assert_eq!(IntegrityAlgorithm::None.transform_id(), 0);
        assert_eq!(IntegrityAlgorithm::HmacSha1_96.transform_id(), 2);
        assert_eq!(IntegrityAlgorithm::AesXcbc96.transform_id(), 5);
        assert_eq!(IntegrityAlgorithm::AesGmac.transform_id(), 9);
        assert_eq!(IntegrityAlgorithm::HmacSha2_256_128.transform_id(), 12);
        assert_eq!(IntegrityAlgorithm::HmacSha2_384_192.transform_id(), 13);
        assert_eq!(IntegrityAlgorithm::HmacSha2_512_256.transform_id(), 14);
    }

    #[test]
    fn integrity_id_constants_match_manifest() {
        assert_eq!(AUTH_NONE, 0);
        assert_eq!(AUTH_HMAC_SHA1_96, 2);
        assert_eq!(AUTH_AES_XCBC_96, 5);
        assert_eq!(AUTH_AES_128_GMAC, 9);
        assert_eq!(AUTH_HMAC_SHA2_256_128, 12);
        assert_eq!(AUTH_HMAC_SHA2_384_192, 13);
        assert_eq!(AUTH_HMAC_SHA2_512_256, 14);
    }

    // See `encryption_from_u16_round_trips`: the `TryFrom` is infallible, so the
    // `.unwrap()` is intentional and clippy's fallible-conversion lint is muted.
    #[allow(clippy::unnecessary_fallible_conversions)]
    #[test]
    fn integrity_from_u16_round_trips() {
        for algo in [
            IntegrityAlgorithm::None,
            IntegrityAlgorithm::HmacSha1_96,
            IntegrityAlgorithm::AesXcbc96,
            IntegrityAlgorithm::AesGmac,
            IntegrityAlgorithm::HmacSha2_256_128,
            IntegrityAlgorithm::HmacSha2_384_192,
            IntegrityAlgorithm::HmacSha2_512_256,
        ] {
            let id = algo.transform_id();
            assert_eq!(IntegrityAlgorithm::from(id), algo);
            assert_eq!(u16::from(algo), id);
            assert_eq!(IntegrityAlgorithm::try_from(id).unwrap(), algo);
        }
    }

    #[test]
    fn integrity_unknown_id_is_preserved() {
        // 200 is not an assigned INTEG transform ID; it must round-trip verbatim.
        let algo = IntegrityAlgorithm::from(200);
        assert_eq!(algo, IntegrityAlgorithm::Unknown(200));
        assert_eq!(algo.transform_id(), 200);
        assert_eq!(u16::from(algo), 200);
        assert_eq!(algo.icv_len(), None);
        assert!(algo.integrity_transform().is_err());
    }

    #[test]
    fn integrity_icv_lengths_match_rfcs() {
        assert_eq!(IntegrityAlgorithm::None.icv_len(), None);
        assert_eq!(IntegrityAlgorithm::HmacSha1_96.icv_len(), Some(12));
        assert_eq!(IntegrityAlgorithm::AesXcbc96.icv_len(), Some(12));
        assert_eq!(IntegrityAlgorithm::AesGmac.icv_len(), Some(16));
        assert_eq!(IntegrityAlgorithm::HmacSha2_256_128.icv_len(), Some(16));
        assert_eq!(IntegrityAlgorithm::HmacSha2_384_192.icv_len(), Some(24));
        assert_eq!(IntegrityAlgorithm::HmacSha2_512_256.icv_len(), Some(32));
    }

    #[test]
    fn integrity_transform_resolution_and_icv_agree() {
        let cases = [
            (
                IntegrityAlgorithm::HmacSha1_96,
                IntegrityTransform::HmacSha1_96,
            ),
            (
                IntegrityAlgorithm::AesXcbc96,
                IntegrityTransform::AesXcbcMac96,
            ),
            (IntegrityAlgorithm::AesGmac, IntegrityTransform::AesGmac),
            (
                IntegrityAlgorithm::HmacSha2_256_128,
                IntegrityTransform::HmacSha2_256_128,
            ),
            (
                IntegrityAlgorithm::HmacSha2_384_192,
                IntegrityTransform::HmacSha2_384_192,
            ),
            (
                IntegrityAlgorithm::HmacSha2_512_256,
                IntegrityTransform::HmacSha2_512_256,
            ),
        ];
        for (algo, transform) in cases {
            assert_eq!(algo.integrity_transform().unwrap(), transform);
            assert_eq!(algo.icv_len(), Some(transform.icv_len()));
        }
        assert!(IntegrityAlgorithm::None.integrity_transform().is_err());
    }
}
