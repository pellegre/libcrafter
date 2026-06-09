//! IPSec AEAD (combined-mode) transforms.
//!
//! AEAD suites perform confidentiality and integrity in a single operation: the
//! cipher encrypts the plaintext and produces an authentication tag (the ESP
//! ICV) bound to the additional authenticated data (AAD = `SPI||Seq`, plus the
//! high-order ESN bits when ESN is enabled). The nonce is the per-SA salt
//! concatenated with the per-packet IV. SA wiring and the ESP trailer are
//! layered on in later steps; here each transform stays primitive and is
//! individually KAT-verified against its defining RFC.
//!
//! Coverage (plan.md "Algorithm coverage" / "ESP wire rules"):
//! - `ENCR_AES_GCM_16` (RFC 4106) — AEAD, 4-octet salt + 8-octet IV =
//!   12-octet nonce, 16-octet ICV. **MUST** per RFC 8221.
//! - `ENCR_AES_CCM_8` (RFC 4309) — AEAD, 3-octet salt + 8-octet IV =
//!   11-octet nonce (L = 4), 8-octet ICV.
//! - `ENCR_CHACHA20_POLY1305` (RFC 7634) — AEAD, 4-octet salt + 8-octet IV =
//!   12-octet nonce, 16-octet ICV. **SHOULD** per RFC 8221.
//!
//! ## Nonce composition
//! For all three transforms the nonce passed to [`AeadTransform::seal`] /
//! [`AeadTransform::open`] is already assembled as `salt || IV`. RFC 4106 §4
//! and RFC 7634 §2 build a 12-octet nonce from a 4-octet salt and an 8-octet
//! IV. RFC 4309 §4 builds an 11-octet nonce from a 3-octet salt and an 8-octet
//! IV (the CCM `L` parameter is 4, so the nonce is `15 - L = 11` octets).
//!
//! ## Tag handling
//! `seal` returns the ciphertext and the detached tag separately; ESP writes
//! the tag as the trailing ICV. `open` recomputes and verifies the tag with the
//! AEAD's own constant-time comparison and returns a structured integrity error
//! on mismatch — it never panics and never returns unauthenticated plaintext.

use aes::Aes128;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::Aes128Gcm;
use ccm::consts::{U11, U8};
use ccm::Ccm;
use chacha20poly1305::ChaCha20Poly1305;
use cipher::generic_array::GenericArray;
use cipher::KeyInit;

use crate::{CrafterError, Result};

/// AES-128 key length in octets (RFC 4106 / RFC 4309).
const AES128_KEY_LEN: usize = 16;
/// ChaCha20 key length in octets (RFC 7634).
const CHACHA20_KEY_LEN: usize = 32;

/// Salt length in octets for AES-GCM / ChaCha20-Poly1305 (RFC 4106 / RFC 7634).
const SALT_LEN_4: usize = 4;
/// Salt length in octets for AES-CCM (RFC 4309 §4).
const SALT_LEN_3: usize = 3;
/// Explicit per-packet IV length in octets, shared by all three AEAD suites.
const IV_LEN: usize = 8;

/// 12-octet AEAD nonce length (AES-GCM / ChaCha20-Poly1305).
const NONCE_LEN_12: usize = SALT_LEN_4 + IV_LEN;
/// 11-octet AEAD nonce length (AES-CCM, RFC 4309 §4: `15 - L` with `L = 4`).
const NONCE_LEN_11: usize = SALT_LEN_3 + IV_LEN;

/// 16-octet ICV length (AES-GCM-16 / ChaCha20-Poly1305).
const ICV_LEN_16: usize = 16;
/// 8-octet ICV length (AES-CCM-8).
const ICV_LEN_8: usize = 8;

/// AES-128-CCM with an 8-octet tag and an 11-octet nonce (RFC 4309: `L = 4`).
type AesCcm8 = Ccm<Aes128, U8, U11>;

/// IPSec AEAD transforms, identified by their IKEv2 transform names.
///
/// Each variant combines encryption and integrity. The transforms here are the
/// AEAD suites; the non-AEAD ciphers (AES-CBC/CTR/NULL) and standalone
/// integrity MACs live in the sibling [`super::cipher`] and [`super::integrity`]
/// modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadTransform {
    /// AES-GCM-16 (RFC 4106): AES-128-GCM, 12-octet nonce, 16-octet ICV.
    AesGcm16,
    /// AES-CCM-8 (RFC 4309): AES-128-CCM, 11-octet nonce, 8-octet ICV.
    AesCcm8,
    /// ChaCha20-Poly1305 (RFC 7634): 12-octet nonce, 16-octet ICV.
    ChaCha20Poly1305,
}

impl AeadTransform {
    /// Cipher key length in octets (excludes the per-SA salt).
    pub const fn key_len(self) -> usize {
        match self {
            Self::AesGcm16 => AES128_KEY_LEN,           // RFC 4106: AES-128 key
            Self::AesCcm8 => AES128_KEY_LEN,            // RFC 4309: AES-128 key
            Self::ChaCha20Poly1305 => CHACHA20_KEY_LEN, // RFC 7634: 256-bit key
        }
    }

    /// Per-SA salt length in octets (the implicit, fixed nonce prefix).
    pub const fn salt_len(self) -> usize {
        match self {
            Self::AesGcm16 => SALT_LEN_4,         // RFC 4106 §4: 4-octet salt
            Self::AesCcm8 => SALT_LEN_3,          // RFC 4309 §4: 3-octet salt
            Self::ChaCha20Poly1305 => SALT_LEN_4, // RFC 7634 §2: 4-octet salt
        }
    }

    /// Explicit per-packet IV length in octets carried on the wire.
    ///
    /// All three AEAD suites use an 8-octet explicit IV (RFC 4106 §3, RFC 4309
    /// §3, RFC 7634 §2).
    pub const fn iv_len(self) -> usize {
        IV_LEN
    }

    /// Assembled nonce length in octets (`salt_len() + iv_len()`).
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::AesGcm16 => NONCE_LEN_12,
            Self::AesCcm8 => NONCE_LEN_11,
            Self::ChaCha20Poly1305 => NONCE_LEN_12,
        }
    }

    /// ICV (authentication tag) length in octets.
    pub const fn icv_len(self) -> usize {
        match self {
            Self::AesGcm16 => ICV_LEN_16,         // RFC 4106: 16-octet ICV
            Self::AesCcm8 => ICV_LEN_8,           // RFC 4309: 8-octet ICV
            Self::ChaCha20Poly1305 => ICV_LEN_16, // RFC 7634: 16-octet ICV
        }
    }

    /// Encrypt `plaintext` and compute the authentication tag.
    ///
    /// - `key` is the cipher key ([`AeadTransform::key_len`] octets); it does
    ///   **not** include the salt.
    /// - `nonce` is the already-assembled `salt || IV`
    ///   ([`AeadTransform::nonce_len`] octets).
    /// - `aad` is the additional authenticated data (ESP `SPI||Seq`, plus the
    ///   ESN high-order bits when enabled); it is authenticated but not
    ///   encrypted.
    ///
    /// Returns `(ciphertext, tag)`. The ciphertext has the same length as the
    /// plaintext; the tag is [`AeadTransform::icv_len`] octets. Key/nonce shape
    /// mismatches surface as structured errors rather than panics.
    pub fn seal(
        self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        self.check_shapes(key, nonce)?;
        match self {
            Self::AesGcm16 => {
                let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| Self::key_err(self))?;
                let mut buf = plaintext.to_vec();
                let tag = cipher
                    .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, &mut buf)
                    .map_err(|_| Self::seal_err(self))?;
                Ok((buf, tag.to_vec()))
            }
            Self::AesCcm8 => {
                let cipher = AesCcm8::new_from_slice(key).map_err(|_| Self::key_err(self))?;
                let mut buf = plaintext.to_vec();
                let tag = cipher
                    .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, &mut buf)
                    .map_err(|_| Self::seal_err(self))?;
                Ok((buf, tag.to_vec()))
            }
            Self::ChaCha20Poly1305 => {
                let cipher =
                    ChaCha20Poly1305::new_from_slice(key).map_err(|_| Self::key_err(self))?;
                let mut buf = plaintext.to_vec();
                let tag = cipher
                    .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, &mut buf)
                    .map_err(|_| Self::seal_err(self))?;
                Ok((buf, tag.to_vec()))
            }
        }
    }

    /// Verify the tag and decrypt `ciphertext`.
    ///
    /// The `key`, `nonce`, and `aad` conventions match [`AeadTransform::seal`].
    /// On success the recovered plaintext is returned. If the tag does not match
    /// — a tampered ciphertext, AAD, nonce, or tag — this returns a structured
    /// integrity error and never the (unauthenticated) plaintext. The tag
    /// comparison is the AEAD's own constant-time check.
    pub fn open(
        self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>> {
        self.check_shapes(key, nonce)?;
        if tag.len() != self.icv_len() {
            return Err(Self::tag_len_err(self));
        }
        match self {
            Self::AesGcm16 => {
                let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| Self::key_err(self))?;
                let mut buf = ciphertext.to_vec();
                cipher
                    .decrypt_in_place_detached(
                        GenericArray::from_slice(nonce),
                        aad,
                        &mut buf,
                        GenericArray::from_slice(tag),
                    )
                    .map_err(|_| Self::integrity_err(self))?;
                Ok(buf)
            }
            Self::AesCcm8 => {
                let cipher = AesCcm8::new_from_slice(key).map_err(|_| Self::key_err(self))?;
                let mut buf = ciphertext.to_vec();
                cipher
                    .decrypt_in_place_detached(
                        GenericArray::from_slice(nonce),
                        aad,
                        &mut buf,
                        GenericArray::from_slice(tag),
                    )
                    .map_err(|_| Self::integrity_err(self))?;
                Ok(buf)
            }
            Self::ChaCha20Poly1305 => {
                let cipher =
                    ChaCha20Poly1305::new_from_slice(key).map_err(|_| Self::key_err(self))?;
                let mut buf = ciphertext.to_vec();
                cipher
                    .decrypt_in_place_detached(
                        GenericArray::from_slice(nonce),
                        aad,
                        &mut buf,
                        GenericArray::from_slice(tag),
                    )
                    .map_err(|_| Self::integrity_err(self))?;
                Ok(buf)
            }
        }
    }

    /// Validate the key and nonce lengths for this transform.
    fn check_shapes(self, key: &[u8], nonce: &[u8]) -> Result<()> {
        if key.len() != self.key_len() {
            return Err(Self::key_err(self));
        }
        if nonce.len() != self.nonce_len() {
            return Err(Self::nonce_err(self));
        }
        Ok(())
    }

    /// Structured error for an invalid key length.
    const fn key_err(self) -> CrafterError {
        CrafterError::invalid_field_value(
            "ipsec.aead.key",
            "AEAD key length does not match the transform",
        )
    }

    /// Structured error for an invalid nonce length.
    const fn nonce_err(self) -> CrafterError {
        CrafterError::invalid_field_value(
            "ipsec.aead.nonce",
            "AEAD nonce length does not match salt||IV for the transform",
        )
    }

    /// Structured error for an invalid tag length on `open`.
    const fn tag_len_err(self) -> CrafterError {
        CrafterError::invalid_field_value(
            "ipsec.aead.tag",
            "AEAD tag length does not match the transform ICV",
        )
    }

    /// Structured error for a seal (encryption) failure.
    const fn seal_err(self) -> CrafterError {
        CrafterError::invalid_field_value("ipsec.aead.seal", "AEAD encryption failed")
    }

    /// Structured integrity error for a tag-verification failure on `open`.
    const fn integrity_err(self) -> CrafterError {
        CrafterError::invalid_field_value(
            "ipsec.aead.icv",
            "AEAD integrity check failed: tag did not verify",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a hex string (whitespace ignored) into a byte vector for KATs.
    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(s.len() % 2 == 0, "hex string must have even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    // --- AES-GCM-16: McGrew & Viega GCM Appendix B (RFC 4106 reference) ------
    //
    // RFC 4106 §9 does not print inline test vectors; it defers to "Appendix B
    // of [GCM]" (McGrew & Viega, "The Galois/Counter Mode of Operation"), the
    // same authoritative AES-GCM vectors NIST adopts. AES-GCM-16 in ESP is
    // exactly AES-128-GCM with a 12-octet nonce (salt(4)||IV(8)) and a 16-octet
    // tag, with AAD = SPI||Seq; these vectors pin the seal/open path with bytes
    // published in the GCM specification.

    /// GCM Appendix B, Test Case 3 (AES-128, empty AAD).
    ///   K  = feffe9928665731c6d6a8f9467308308
    ///   IV = cafebabefacedbaddecaf888         (12-octet nonce)
    ///   P  = 64 octets
    ///   C  = 42831ec2...473f5985
    ///   T  = 4d5c2af327cd64a62cf35abd2ba6fab4
    /// The 12-octet IV maps to ESP's salt(4)||IV(8) nonce construction.
    #[test]
    fn aes_gcm16_gcm_appendix_b_case3_no_aad() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = hex("cafebabefacedbaddecaf888"); // salt(4)||IV(8)
        let plaintext = hex("d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b391aafd255");
        let expected_ct = hex("42831ec2217774244b7221b784d0d49c\
             e3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa05\
             1ba30b396a0aac973d58e091473f5985");
        let expected_tag = hex("4d5c2af327cd64a62cf35abd2ba6fab4");

        let t = AeadTransform::AesGcm16;
        assert_eq!(t.key_len(), 16);
        assert_eq!(t.salt_len(), 4);
        assert_eq!(t.iv_len(), 8);
        assert_eq!(t.nonce_len(), 12);
        assert_eq!(t.icv_len(), 16);

        let (ct, tag) = t.seal(&key, &nonce, &[], &plaintext).unwrap();
        assert_eq!(ct, expected_ct);
        assert_eq!(tag, expected_tag);

        let pt = t.open(&key, &nonce, &[], &ct, &tag).unwrap();
        assert_eq!(pt, plaintext);
    }

    /// GCM Appendix B, Test Case 4 (AES-128, with AAD).
    ///   K   = feffe9928665731c6d6a8f9467308308
    ///   IV  = cafebabefacedbaddecaf888
    ///   A   = feedfacedeadbeeffeedfacedeadbeefabaddad2  (the ESP AAD shape)
    ///   P   = 60 octets
    ///   C   = 42831ec2...3d58e091
    ///   T   = 5bc94fbc3221a5db94fae95ae7121a47
    /// AAD authentication is the ESP SPI||Seq path; tampering it must fail open.
    #[test]
    fn aes_gcm16_gcm_appendix_b_case4_with_aad() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = hex("cafebabefacedbaddecaf888");
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = hex("d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b39");
        let expected_ct = hex("42831ec2217774244b7221b784d0d49c\
             e3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa05\
             1ba30b396a0aac973d58e091");
        let expected_tag = hex("5bc94fbc3221a5db94fae95ae7121a47");

        let t = AeadTransform::AesGcm16;
        let (ct, tag) = t.seal(&key, &nonce, &aad, &plaintext).unwrap();
        assert_eq!(ct, expected_ct);
        assert_eq!(tag, expected_tag);

        let pt = t.open(&key, &nonce, &aad, &ct, &tag).unwrap();
        assert_eq!(pt, plaintext);

        // Tamper: flip one AAD bit -> open must error, not return plaintext.
        let mut bad_aad = aad.clone();
        bad_aad[0] ^= 0x01;
        assert!(t.open(&key, &nonce, &bad_aad, &ct, &tag).is_err());
    }

    /// AES-GCM-16 tamper detection: flipping one bit of the tag fails open.
    #[test]
    fn aes_gcm16_tag_tamper_fails_open() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = hex("cafebabefacedbaddecaf888");
        let plaintext = b"ESP AEAD plaintext block";

        let t = AeadTransform::AesGcm16;
        let (ct, mut tag) = t.seal(&key, &nonce, &[], plaintext).unwrap();
        assert!(t.open(&key, &nonce, &[], &ct, &tag).is_ok());

        tag[0] ^= 0x01;
        let err = t.open(&key, &nonce, &[], &ct, &tag).unwrap_err();
        match err {
            CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "ipsec.aead.icv");
            }
            other => panic!("expected integrity error, got {other:?}"),
        }
    }

    // --- ChaCha20-Poly1305: RFC 7634 Appendix A -----------------------------
    //
    // RFC 7634 Appendix A prints a complete ESP example: SK_e, salt, explicit
    // IV, SPI, Sequence Number, the AAD (SPI||Seq), the plaintext (inner packet
    // with ESP pad/pad-length/next-header), the ciphertext, and the 16-octet
    // Poly1305 tag. The 96-bit nonce is salt(4)||IV(8). This is the canonical
    // KAT for ENCR_CHACHA20_POLY1305.

    /// RFC 7634 Appendix A: assert exact ciphertext + Poly1305 tag, then verify
    /// open() recovers the plaintext and rejects a tampered tag.
    #[test]
    fn chacha20poly1305_rfc7634_appendix_a() {
        let key = hex("808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f");
        let salt = hex("a0a1a2a3");
        let iv = hex("1011121314151617");
        let mut nonce = salt.clone();
        nonce.extend_from_slice(&iv); // salt(4)||IV(8) = 12 octets

        // AAD = SPI(01020304) || Seq(00000005).
        let aad = hex("0102030400000005");

        // Plaintext = inner IPv4 packet + ESP pad/pad-length/next-header
        // (RFC 7634 Appendix A), 88 octets total.
        let plaintext = hex("45000054a6f2000040 01e778c63364 05c0000205 08005b7a\
             3a0800005 53bec1000073627\
             08090a0b0c0d0e0f1011121314151617\
             18191a1b1c1d1e1f2021222324252627\
             28292a2b2c2d2e2f3031323334353637\
             0102020 4");
        let expected_ct = hex("2403942 8b97f417e3c13753a4f05087b\
             67c352e6a7fab1b982d466ef407ae5c6\
             14ee8099d52844eb61aa95dfab4c02f7\
             2aa71e7c4c4f64c9befe2facc638e8f3\
             cbec163fac469b502773f6fb94e664da\
             9165b82829f641e0");
        let expected_tag = hex("76aaa8266b7fb0f7b11b369907e1ad43");

        let t = AeadTransform::ChaCha20Poly1305;
        assert_eq!(t.key_len(), 32);
        assert_eq!(t.salt_len(), 4);
        assert_eq!(t.iv_len(), 8);
        assert_eq!(t.nonce_len(), 12);
        assert_eq!(t.icv_len(), 16);
        assert_eq!(nonce.len(), 12);
        assert_eq!(plaintext.len(), 88);

        let (ct, tag) = t.seal(&key, &nonce, &aad, &plaintext).unwrap();
        assert_eq!(ct, expected_ct);
        assert_eq!(tag, expected_tag);

        let pt = t.open(&key, &nonce, &aad, &ct, &tag).unwrap();
        assert_eq!(pt, plaintext);

        // Tamper: flip one tag bit -> open must error.
        let mut bad_tag = tag.clone();
        bad_tag[15] ^= 0x80;
        assert!(t.open(&key, &nonce, &aad, &ct, &bad_tag).is_err());
        // Tamper: flip one ciphertext bit -> open must error.
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0x01;
        assert!(t.open(&key, &nonce, &aad, &bad_ct, &tag).is_err());
    }

    // --- AES-CCM-8: RFC 3610 Packet Vector #1 (CCM-crate validation) --------
    //
    // RFC 4309 §3 mandates the CCM IPsec nonce of 11 octets (salt(3)||IV(8),
    // L = 4) and an 8-octet ICV for ENCR_AES_CCM_8, but publishes no inline
    // ICV/ciphertext bytes. The defining CCM KATs live in RFC 3610 §8, which
    // uses L = 2 (a 13-octet nonce) and M = 8 (an 8-octet tag). Because the
    // CCM `L` value — and therefore the nonce length — is a fixed type
    // parameter of the `ccm` crate, the RFC 3610 vectors cannot be replayed
    // through the production 11-octet (L = 4) instantiation. We therefore pin
    // the `ccm` crate's seal/open against RFC 3610 Packet Vector #1 with a
    // local L = 2 instantiation (proving our use of the AEAD API is correct),
    // and separately exercise the RFC 4309 11-octet-nonce production transform
    // with a round-trip + tamper test.

    /// RFC 3610 §8 Packet Vector #1 (M = 8, L = 2):
    ///   Key   = c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
    ///   Nonce = 00000003020100a0a1a2a3a4a5        (13 octets)
    ///   AAD   = 0001020304050607                  (8 octets)
    ///   P     = 08090a0b0c0d0e0f1011121314151617 18191a1b1c1d1e  (23 octets)
    ///   CCM output (ciphertext||tag) =
    ///     588c979a61c663d2f066d0c2c0f98980 6d5f6b61dac384  (ciphertext, 23)
    ///     17e8d12cfdf926e0                              (tag, 8)
    /// This validates the `ccm` crate (the same code path the production
    /// transform calls) against published CCM bytes.
    #[test]
    fn aes_ccm8_rfc3610_packet_vector1_via_ccm_crate() {
        use ccm::aead::AeadInPlace as CcmAeadInPlace;
        use ccm::consts::{U13, U8 as CcmU8};
        use ccm::{Ccm, KeyInit as CcmKeyInit};

        // L = 2 -> 13-octet nonce, matching RFC 3610's printed vectors.
        type AesCcm8L2 = Ccm<Aes128, CcmU8, U13>;

        let key = hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        let nonce = hex("00000003020100a0a1a2a3a4a5");
        let aad = hex("0001020304050607");
        let plaintext = hex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
        let expected_ct = hex("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384");
        let expected_tag = hex("17e8d12cfdf926e0");

        let cipher = <AesCcm8L2 as CcmKeyInit>::new_from_slice(&key).unwrap();
        let mut buf = plaintext.clone();
        let tag = cipher
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, &mut buf)
            .unwrap();
        assert_eq!(buf, expected_ct);
        assert_eq!(tag.to_vec(), expected_tag);

        // Decrypt round-trips and verifies the tag.
        let mut dec = expected_ct.clone();
        cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                &aad,
                &mut dec,
                GenericArray::from_slice(&expected_tag),
            )
            .unwrap();
        assert_eq!(dec, plaintext);
    }

    /// AES-CCM-8 production transform (RFC 4309, 11-octet salt(3)||IV(8)
    /// nonce, L = 4): seal/open round-trip and tamper detection. The
    /// nonce-length contract is asserted against RFC 4309 §4.
    #[test]
    fn aes_ccm8_rfc4309_roundtrip_and_tamper() {
        let t = AeadTransform::AesCcm8;
        assert_eq!(t.key_len(), 16);
        assert_eq!(t.salt_len(), 3); // RFC 4309 §4: 3-octet salt
        assert_eq!(t.iv_len(), 8);
        assert_eq!(t.nonce_len(), 11); // RFC 4309 §4: 15 - L = 11 (L = 4)
        assert_eq!(t.icv_len(), 8); // ENCR_AES_CCM_8

        let key = hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        // salt(3)||IV(8) = 11 octets.
        let nonce = hex("a0a1a20011223344556677");
        assert_eq!(nonce.len(), t.nonce_len());
        let aad = hex("0102030400000007"); // ESP SPI||Seq shape
        let plaintext = b"ESP AES-CCM-8 payload, RFC 4309";

        let (ct, tag) = t.seal(&key, &nonce, &aad, plaintext).unwrap();
        assert_eq!(tag.len(), 8);
        assert_eq!(ct.len(), plaintext.len());

        let pt = t.open(&key, &nonce, &aad, &ct, &tag).unwrap();
        assert_eq!(pt, plaintext);

        // Tamper: flip one tag bit -> open must error with a structured
        // integrity error, never plaintext.
        let mut bad_tag = tag.clone();
        bad_tag[0] ^= 0x01;
        let err = t.open(&key, &nonce, &aad, &ct, &bad_tag).unwrap_err();
        match err {
            CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "ipsec.aead.icv");
            }
            other => panic!("expected integrity error, got {other:?}"),
        }
        // Tamper: flip one ciphertext bit -> open must error.
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0x01;
        assert!(t.open(&key, &nonce, &aad, &bad_ct, &tag).is_err());
    }

    /// Key/nonce/tag shape guards return structured errors, not panics.
    #[test]
    fn aead_shape_guards() {
        let t = AeadTransform::AesGcm16;
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = hex("cafebabefacedbaddecaf888");

        // Wrong key length.
        assert!(t.seal(&hex("0011223344"), &nonce, &[], b"x").is_err());
        // Wrong nonce length.
        assert!(t.seal(&key, &hex("00112233"), &[], b"x").is_err());
        // open() with a wrong tag length.
        let (ct, _tag) = t.seal(&key, &nonce, &[], b"x").unwrap();
        assert!(t.open(&key, &nonce, &[], &ct, &hex("0011")).is_err());
    }
}
