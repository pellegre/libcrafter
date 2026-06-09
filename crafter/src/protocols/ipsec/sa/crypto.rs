//! IPSec seal/open crypto driver.
//!
//! This module centralizes the crypto routing that ESP (RFC 4303), AH
//! (RFC 4302), and the IKEv2 SK payload (RFC 7296) all share. Instead of each
//! protocol re-deriving how a [`SecurityAssociation`] maps to the underlying
//! transforms — and how the AEAD vs. cipher-plus-integrity suites differ — they
//! call [`seal`] and [`open`] here.
//!
//! Two suite families are handled:
//!
//! - **AEAD** (`ENCR_AES_GCM_16`, `ENCR_AES_CCM_8`, `ENCR_CHACHA20_POLY1305`):
//!   a single combined operation. The nonce is `salt || iv` (RFC 4106 §4 /
//!   RFC 4309 §4 / RFC 7634 §2), the AAD is passed through verbatim (ESP uses
//!   `SPI||Seq` plus the ESN high-order bits), and the authentication tag is
//!   returned as the ICV. [`open`] verifies the tag and decrypts in one step,
//!   never returning unauthenticated plaintext.
//!
//! - **Cipher + separate integrity** (`ENCR_AES_CBC`, `ENCR_AES_CTR`,
//!   `ENCR_NULL` paired with an [`IntegrityAlgorithm`]): "encrypt-then-MAC".
//!   [`seal`] encrypts with the cipher, then computes the ICV over
//!   `aad || iv || ciphertext` (the ESP integrity input: ESP header + explicit
//!   IV + ciphertext, RFC 4303 §3.3.2 / §3.4.4.1). [`open`] verifies that ICV
//!   in constant time **first** and only decrypts when it matches; an integrity
//!   failure returns a structured error and never yields plaintext.
//!
//! The driver does not assemble the ESP/AH/SK wire bytes (that is the layer's
//! job); it operates purely on `(sa, iv, aad, plaintext/ciphertext, icv)` and
//! returns the cryptographic pieces those layers need.

use super::algorithms::IntegrityAlgorithm;
use super::SecurityAssociation;
use crate::{CrafterError, Result};

/// The cryptographic output of a [`seal`] operation.
///
/// Carries the ciphertext and the Integrity Check Value (ICV / authentication
/// tag) the protecting layer writes to the wire. For AEAD suites the ICV is the
/// AEAD tag; for cipher+integrity suites it is the separate MAC computed over
/// the integrity input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealOutput {
    /// The encrypted payload (same length as the plaintext for all current
    /// transforms; CBC requires a block-aligned plaintext from the caller).
    pub ciphertext: Vec<u8>,
    /// The Integrity Check Value appended after the ciphertext on the wire.
    pub icv: Vec<u8>,
}

/// Whether a suite requires an explicit per-packet IV and how long it is.
///
/// Callers use this to supply a deterministic IV (for oracle byte-parity) or to
/// know they must generate one. `NULL` encryption carries no IV
/// (`iv_required == false`, `iv_len == 0`); CBC/CTR and the AEAD suites require
/// an explicit IV of [`IvRequirement::iv_len`] octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IvRequirement {
    /// Length in octets of the explicit IV the suite expects on the wire.
    pub iv_len: usize,
    /// Whether an explicit IV must be supplied (`false` only for `NULL`).
    pub iv_required: bool,
}

/// Describe the explicit-IV requirement for `sa`'s encryption algorithm.
///
/// This lets a caller pin a deterministic IV for reproducible bytes, or learn
/// that it must generate `iv_len` random octets, without reaching into the
/// algorithm metadata directly. The IV length comes from
/// [`super::EncryptionAlgorithm::iv_len`]; a zero length means no IV (`NULL`).
pub fn iv_requirement(sa: &SecurityAssociation) -> IvRequirement {
    let iv_len = sa.enc.iv_len();
    IvRequirement {
        iv_len,
        iv_required: iv_len != 0,
    }
}

/// Seal `plaintext` under `sa`, returning the ciphertext and ICV.
///
/// - `iv` is the explicit per-packet IV (empty for `NULL`); see
///   [`iv_requirement`].
/// - `aad` is the additional authenticated data — for ESP this is the integrity
///   prefix `SPI||Seq` (plus the ESN high-order bits when enabled).
///
/// For AEAD suites the nonce is `sa.salt || iv`, the AAD is authenticated by the
/// AEAD, and the returned ICV is the AEAD tag. For cipher+integrity suites the
/// plaintext is encrypted with the cipher and the ICV is computed over
/// `aad || iv || ciphertext`. A suite with neither encryption nor integrity
/// (NULL + NONE) seals to a copy of the plaintext with an empty ICV.
pub fn seal(
    sa: &SecurityAssociation,
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SealOutput> {
    if sa.enc.is_aead() {
        let transform = sa.enc.aead_transform()?;
        let nonce = aead_nonce(sa, iv);
        let (ciphertext, icv) = transform.seal(&sa.enc_key, &nonce, aad, plaintext)?;
        Ok(SealOutput { ciphertext, icv })
    } else {
        let cipher = sa.enc.cipher_transform()?;
        let cipher_key = cipher_key(sa);
        let ciphertext = cipher.encrypt(&cipher_key, iv, plaintext)?;
        let icv = compute_integrity(sa, iv, aad, &ciphertext)?;
        Ok(SealOutput { ciphertext, icv })
    }
}

/// Open `ciphertext` under `sa`, verifying its `icv` and returning the plaintext.
///
/// The `iv` and `aad` conventions match [`seal`]. Integrity is checked **before**
/// any decryption:
///
/// - AEAD suites verify the tag and decrypt in one constant-time operation; a
///   mismatch returns a structured error and never plaintext.
/// - Cipher+integrity suites recompute the ICV over `aad || iv || ciphertext`,
///   compare it to `icv` in constant time, and only decrypt on a match.
///
/// On any integrity failure this returns a [`CrafterError::InvalidFieldValue`]
/// (field `ipsec.sa.icv`) and never the unauthenticated plaintext.
pub fn open(
    sa: &SecurityAssociation,
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    icv: &[u8],
) -> Result<Vec<u8>> {
    if sa.enc.is_aead() {
        let transform = sa.enc.aead_transform()?;
        let nonce = aead_nonce(sa, iv);
        // The AEAD verifies the tag and decrypts atomically; a bad tag yields a
        // structured error, never plaintext.
        transform.open(&sa.enc_key, &nonce, aad, ciphertext, icv)
    } else {
        // Encrypt-then-MAC: verify the ICV in constant time FIRST, then decrypt.
        verify_integrity(sa, iv, aad, ciphertext, icv)?;
        let cipher = sa.enc.cipher_transform()?;
        let cipher_key = cipher_key(sa);
        cipher.decrypt(&cipher_key, iv, ciphertext)
    }
}

/// Assemble the AEAD nonce `salt || iv` for `sa` (RFC 4106/4309/7634).
fn aead_nonce(sa: &SecurityAssociation, iv: &[u8]) -> Vec<u8> {
    let mut nonce = Vec::with_capacity(sa.salt.len() + iv.len());
    nonce.extend_from_slice(&sa.salt);
    nonce.extend_from_slice(iv);
    nonce
}

/// Build the cipher key for a non-AEAD suite.
///
/// AES-CTR keys are `aes_key(16) || salt(4)` (RFC 3686 §4); CBC and NULL use the
/// encryption key as-is (no salt).
fn cipher_key(sa: &SecurityAssociation) -> Vec<u8> {
    if matches!(sa.enc, super::EncryptionAlgorithm::AesCtr) {
        let mut key = Vec::with_capacity(sa.enc_key.len() + sa.salt.len());
        key.extend_from_slice(&sa.enc_key);
        key.extend_from_slice(&sa.salt);
        key
    } else {
        sa.enc_key.clone()
    }
}

/// Build the integrity input `aad || iv || ciphertext` for cipher+integrity
/// suites (the ESP integrity input: ESP header + explicit IV + ciphertext).
fn integrity_input(iv: &[u8], aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(aad.len() + iv.len() + ciphertext.len());
    input.extend_from_slice(aad);
    input.extend_from_slice(iv);
    input.extend_from_slice(ciphertext);
    input
}

/// Build the integrity key for `sa`'s integrity algorithm.
///
/// HMAC and AES-XCBC-MAC use the integrity key verbatim. AES-GMAC (RFC 4543)
/// authenticates with AES-GCM and needs `aes_key || salt(4) || iv(8)` as its
/// transform key (see [`super::super::crypto::IntegrityTransform::compute`]).
fn integrity_key(sa: &SecurityAssociation, iv: &[u8]) -> Vec<u8> {
    if matches!(sa.integ, IntegrityAlgorithm::AesGmac) {
        let mut key = Vec::with_capacity(sa.integ_key.len() + sa.salt.len() + iv.len());
        key.extend_from_slice(&sa.integ_key);
        key.extend_from_slice(&sa.salt);
        key.extend_from_slice(iv);
        key
    } else {
        sa.integ_key.clone()
    }
}

/// Compute the separate ICV over `aad || iv || ciphertext` for cipher+integrity
/// suites, or an empty ICV when the SA carries no integrity algorithm.
fn compute_integrity(
    sa: &SecurityAssociation,
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    match sa.integ {
        IntegrityAlgorithm::None => Ok(Vec::new()),
        _ => {
            let transform = sa.integ.integrity_transform()?;
            let key = integrity_key(sa, iv);
            let input = integrity_input(iv, aad, ciphertext);
            transform.compute(&key, &input)
        }
    }
}

/// Verify the separate ICV for cipher+integrity suites in constant time.
///
/// Returns `Ok(())` on a verified match; otherwise a structured integrity error.
/// An SA with no integrity algorithm accepts only an empty ICV.
fn verify_integrity(
    sa: &SecurityAssociation,
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    icv: &[u8],
) -> Result<()> {
    match sa.integ {
        IntegrityAlgorithm::None => {
            if icv.is_empty() {
                Ok(())
            } else {
                Err(icv_mismatch())
            }
        }
        _ => {
            let transform = sa.integ.integrity_transform()?;
            let key = integrity_key(sa, iv);
            let input = integrity_input(iv, aad, ciphertext);
            // `verify` recomputes the MAC and compares in constant time.
            if transform.verify(&key, &input, icv)? {
                Ok(())
            } else {
                Err(icv_mismatch())
            }
        }
    }
}

/// Structured integrity (ICV mismatch) error for the cipher+integrity path.
const fn icv_mismatch() -> CrafterError {
    CrafterError::invalid_field_value("ipsec.sa.icv", "integrity check failed: ICV did not verify")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::ipsec::sa::{EncryptionAlgorithm, IntegrityAlgorithm};

    /// A 16-octet AES-128 key filled with a repeating byte.
    fn aes_key() -> Vec<u8> {
        vec![0x11u8; 16]
    }

    /// A 32-octet ChaCha20 key filled with a repeating byte.
    fn chacha_key() -> Vec<u8> {
        vec![0x22u8; 32]
    }

    /// An 8-octet deterministic IV (the explicit IV CBC/CTR/AEAD carry).
    fn iv8() -> Vec<u8> {
        vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    }

    /// A 16-octet deterministic IV for AES-CBC.
    fn iv16() -> Vec<u8> {
        (0u8..16).collect()
    }

    /// The ESP-style AAD `SPI||Seq`.
    fn aad() -> Vec<u8> {
        vec![0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x07]
    }

    /// Round-trip helper: seal then open must recover the plaintext, and a
    /// one-bit ICV tamper must make `open` fail closed.
    fn round_trip_and_tamper(sa: &SecurityAssociation, iv: &[u8], plaintext: &[u8]) {
        let sealed = seal(sa, iv, &aad(), plaintext).unwrap();
        let opened = open(sa, iv, &aad(), &sealed.ciphertext, &sealed.icv).unwrap();
        assert_eq!(opened, plaintext, "seal/open must round-trip the plaintext");

        // A one-bit tamper of the ICV must make open() fail, never return
        // plaintext. (Empty ICVs — NULL+NONE — have nothing to tamper.)
        if !sealed.icv.is_empty() {
            let mut bad_icv = sealed.icv.clone();
            bad_icv[0] ^= 0x01;
            assert!(
                open(sa, iv, &aad(), &sealed.ciphertext, &bad_icv).is_err(),
                "a tampered ICV must make open() error"
            );
        }

        // Tampering the ciphertext must also fail closed.
        if !sealed.ciphertext.is_empty() {
            let mut bad_ct = sealed.ciphertext.clone();
            bad_ct[0] ^= 0x01;
            assert!(
                open(sa, iv, &aad(), &bad_ct, &sealed.icv).is_err(),
                "a tampered ciphertext must make open() error"
            );
        }
    }

    #[test]
    fn aes_gcm_round_trip_and_tamper() {
        let sa = SecurityAssociation::new(0x0102_0304)
            .encryption(EncryptionAlgorithm::AesGcm16, aes_key())
            .salt(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(sa.validate().is_ok());
        round_trip_and_tamper(&sa, &iv8(), b"AES-GCM-16 ESP plaintext payload!");
    }

    #[test]
    fn chacha20_poly1305_round_trip_and_tamper() {
        let sa = SecurityAssociation::new(0x0102_0304)
            .encryption(EncryptionAlgorithm::ChaCha20Poly1305, chacha_key())
            .salt(vec![0xA0, 0xA1, 0xA2, 0xA3]);
        assert!(sa.validate().is_ok());
        round_trip_and_tamper(&sa, &iv8(), b"ChaCha20-Poly1305 ESP plaintext!");
    }

    #[test]
    fn aes_ccm_round_trip_and_tamper() {
        let sa = SecurityAssociation::new(0x0102_0304)
            .encryption(EncryptionAlgorithm::AesCcm8, aes_key())
            .salt(vec![0xA0, 0xA1, 0xA2]); // CCM salt is 3 octets
        assert!(sa.validate().is_ok());
        round_trip_and_tamper(&sa, &iv8(), b"AES-CCM-8 ESP plaintext payload!");
    }

    #[test]
    fn aes_cbc_hmac_sha256_round_trip_and_tamper() {
        let sa = SecurityAssociation::new(0x0102_0304)
            .encryption(EncryptionAlgorithm::AesCbc, aes_key())
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0x33u8; 32]);
        assert!(sa.validate().is_ok());
        // CBC requires a block-aligned plaintext (ESP pads before sealing).
        let plaintext = vec![0x5Au8; 32];
        round_trip_and_tamper(&sa, &iv16(), &plaintext);
    }

    #[test]
    fn aes_ctr_hmac_sha256_round_trip_and_tamper() {
        let sa = SecurityAssociation::new(0x0102_0304)
            .encryption(EncryptionAlgorithm::AesCtr, aes_key())
            .salt(vec![0x00, 0x00, 0x00, 0x30]) // CTR salt is 4 octets
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0x44u8; 32]);
        assert!(sa.validate().is_ok());
        round_trip_and_tamper(&sa, &iv8(), b"AES-CTR ESP plaintext, any length");
    }

    #[test]
    fn null_hmac_sha256_round_trip_and_tamper() {
        let sa = SecurityAssociation::new(0x0102_0304)
            .encryption(EncryptionAlgorithm::Null, Vec::new())
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0x55u8; 32]);
        assert!(sa.validate().is_ok());
        // NULL carries no IV.
        round_trip_and_tamper(&sa, &[], b"NULL cipher with HMAC integrity!");
    }

    #[test]
    fn aes_gmac_integrity_round_trip_and_tamper() {
        // AES-GMAC integrity (RFC 4543) needs salt+IV folded into its key; the
        // driver builds that key from sa.salt and the explicit IV.
        let sa = SecurityAssociation::new(0x0102_0304)
            .encryption(EncryptionAlgorithm::AesCtr, aes_key())
            .salt(vec![0x00, 0x00, 0x00, 0x30])
            .integrity(IntegrityAlgorithm::AesGmac, vec![0x66u8; 16]);
        assert!(sa.validate().is_ok());
        round_trip_and_tamper(&sa, &iv8(), b"AES-CTR + AES-GMAC integrity!!!!");
    }

    #[test]
    fn iv_requirement_reports_lengths() {
        let gcm = SecurityAssociation::new(1)
            .encryption(EncryptionAlgorithm::AesGcm16, aes_key())
            .salt(vec![0u8; 4]);
        assert_eq!(
            iv_requirement(&gcm),
            IvRequirement {
                iv_len: 8,
                iv_required: true
            }
        );

        let cbc = SecurityAssociation::new(1)
            .encryption(EncryptionAlgorithm::AesCbc, aes_key())
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0u8; 32]);
        assert_eq!(
            iv_requirement(&cbc),
            IvRequirement {
                iv_len: 16,
                iv_required: true
            }
        );

        let null = SecurityAssociation::new(1);
        assert_eq!(
            iv_requirement(&null),
            IvRequirement {
                iv_len: 0,
                iv_required: false
            }
        );
    }

    #[test]
    fn icv_mismatch_is_structured_error() {
        let sa = SecurityAssociation::new(0x10)
            .encryption(EncryptionAlgorithm::AesCbc, aes_key())
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0x33u8; 32]);
        let plaintext = vec![0u8; 16];
        let sealed = seal(&sa, &iv16(), &aad(), &plaintext).unwrap();
        let mut bad_icv = sealed.icv.clone();
        bad_icv[0] ^= 0x01;
        let err = open(&sa, &iv16(), &aad(), &sealed.ciphertext, &bad_icv).unwrap_err();
        match err {
            CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "ipsec.sa.icv");
            }
            other => panic!("expected structured ICV error, got {other:?}"),
        }
    }

    #[test]
    fn tampered_aad_fails_open() {
        // The AAD (SPI||Seq) is authenticated; changing it must fail open for
        // both AEAD and cipher+integrity suites.
        let gcm = SecurityAssociation::new(0x0102_0304)
            .encryption(EncryptionAlgorithm::AesGcm16, aes_key())
            .salt(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let sealed = seal(&gcm, &iv8(), &aad(), b"payload").unwrap();
        let mut bad_aad = aad();
        bad_aad[0] ^= 0x01;
        assert!(open(&gcm, &iv8(), &bad_aad, &sealed.ciphertext, &sealed.icv).is_err());

        let cbc = SecurityAssociation::new(0x0102_0304)
            .encryption(EncryptionAlgorithm::AesCbc, aes_key())
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0x33u8; 32]);
        let sealed = seal(&cbc, &iv16(), &aad(), &[0u8; 16]).unwrap();
        let mut bad_aad = aad();
        bad_aad[0] ^= 0x01;
        assert!(open(&cbc, &iv16(), &bad_aad, &sealed.ciphertext, &sealed.icv).is_err());
    }
}
