//! IPSec integrity (MAC) transforms.
//!
//! Each transform is a pure function over `(key, message) -> tag`, truncated to
//! the ICV length mandated by its defining RFC. SA wiring is layered on top in a
//! later step; here the transforms stay primitive and individually KAT-verified.
//!
//! Coverage (plan.md "Algorithm coverage"):
//! - `AUTH_HMAC_SHA1_96` (RFC 2404) — 96-bit ICV
//! - `AUTH_HMAC_SHA2_256_128` (RFC 4868) — 128-bit ICV
//! - `AUTH_HMAC_SHA2_384_192` (RFC 4868) — 192-bit ICV
//! - `AUTH_HMAC_SHA2_512_256` (RFC 4868) — 256-bit ICV
//! - `AUTH_AES_XCBC_96` (RFC 3566) — 96-bit ICV
//! - `AUTH_AES_GMAC` (RFC 4543) — 128-bit ICV
//!
//! All transforms compute the full underlying MAC and then truncate to the RFC
//! ICV length. Verification recomputes the tag and compares in constant time.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use aes::Aes128;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{AesGcm, KeyInit as GcmKeyInit};
use cipher::consts::U12;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

use crate::{CrafterError, Result};

/// AES block size in octets.
const AES_BLOCK_LEN: usize = 16;

/// IPSec integrity transforms, identified by their IKEv2 transform names.
///
/// Each variant maps to an authentication algorithm with a fixed ICV length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityTransform {
    /// HMAC-SHA1-96 (RFC 2404): SHA-1 HMAC truncated to 96 bits.
    HmacSha1_96,
    /// HMAC-SHA-256-128 (RFC 4868): SHA-256 HMAC truncated to 128 bits.
    HmacSha2_256_128,
    /// HMAC-SHA-384-192 (RFC 4868): SHA-384 HMAC truncated to 192 bits.
    HmacSha2_384_192,
    /// HMAC-SHA-512-256 (RFC 4868): SHA-512 HMAC truncated to 256 bits.
    HmacSha2_512_256,
    /// AES-XCBC-MAC-96 (RFC 3566): AES-128 XCBC-MAC truncated to 96 bits.
    AesXcbcMac96,
    /// AES-GMAC (RFC 4543): GMAC with the full 128-bit ICV.
    ///
    /// GMAC is AES-GCM over an empty plaintext, authenticating the message as
    /// AAD. The 12-byte nonce is `salt(4) || IV(8)`; callers supply it via the
    /// `key` argument shape documented on [`IntegrityTransform::compute`].
    AesGmac,
}

impl IntegrityTransform {
    /// ICV length in octets for this transform.
    pub const fn icv_len(self) -> usize {
        match self {
            Self::HmacSha1_96 => 12,        // RFC 2404: 96 bits
            Self::HmacSha2_256_128 => 16,   // RFC 4868: 128 bits
            Self::HmacSha2_384_192 => 24,   // RFC 4868: 192 bits
            Self::HmacSha2_512_256 => 32,   // RFC 4868: 256 bits
            Self::AesXcbcMac96 => 12,       // RFC 3566: 96 bits
            Self::AesGmac => 16,            // RFC 4543: 128 bits
        }
    }

    /// Expected key length in octets, or `None` when variable (HMAC).
    ///
    /// HMAC accepts keys of any length (the spec-mandated key length equals the
    /// hash output, but RFC 2104 allows longer/shorter), so it returns `None`.
    /// AES-XCBC-MAC uses a 16-octet AES-128 key. AES-GMAC uses a key composed of
    /// a 16/24/32-octet AES key followed by a 4-octet salt; only the AES-128
    /// case (20 octets total) is verified here.
    pub const fn key_len(self) -> Option<usize> {
        match self {
            Self::HmacSha1_96
            | Self::HmacSha2_256_128
            | Self::HmacSha2_384_192
            | Self::HmacSha2_512_256 => None,
            Self::AesXcbcMac96 => Some(16),
            Self::AesGmac => None,
        }
    }

    /// Compute the (truncated) ICV over `message` using `key`.
    ///
    /// For HMAC variants `key` is the HMAC key. For AES-XCBC-MAC `key` is the
    /// 16-octet AES-128 key. For AES-GMAC `key` is `aes_key || salt(4) ||
    /// iv(8)`: the AES key, the 4-octet salt, and the 8-octet IV that together
    /// form the 12-octet GCM nonce (RFC 4543 §3 / RFC 4106 nonce construction).
    pub fn compute(self, key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::HmacSha1_96 => Ok(hmac_sha1(key, message, self.icv_len())),
            Self::HmacSha2_256_128 => Ok(hmac_sha256(key, message, self.icv_len())),
            Self::HmacSha2_384_192 => Ok(hmac_sha384(key, message, self.icv_len())),
            Self::HmacSha2_512_256 => Ok(hmac_sha512(key, message, self.icv_len())),
            Self::AesXcbcMac96 => {
                let mac = aes_xcbc_mac(key, message)?;
                Ok(mac[..self.icv_len()].to_vec())
            }
            Self::AesGmac => aes_gmac(key, message),
        }
    }

    /// Recompute the ICV and compare against `tag` in constant time.
    ///
    /// Returns `Ok(true)` on a verified match, `Ok(false)` on a length-correct
    /// mismatch, and an error only when the key shape is invalid for the
    /// transform.
    pub fn verify(self, key: &[u8], message: &[u8], tag: &[u8]) -> Result<bool> {
        let expected = self.compute(key, message)?;
        if expected.len() != tag.len() {
            return Ok(false);
        }
        Ok(expected.ct_eq(tag).into())
    }
}

/// Compute HMAC-SHA-1 and truncate to `icv_len` octets.
fn hmac_sha1(key: &[u8], message: &[u8], icv_len: usize) -> Vec<u8> {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes()[..icv_len].to_vec()
}

/// Compute HMAC-SHA-256 and truncate to `icv_len` octets.
fn hmac_sha256(key: &[u8], message: &[u8], icv_len: usize) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes()[..icv_len].to_vec()
}

/// Compute HMAC-SHA-384 and truncate to `icv_len` octets.
fn hmac_sha384(key: &[u8], message: &[u8], icv_len: usize) -> Vec<u8> {
    let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes()[..icv_len].to_vec()
}

/// Compute HMAC-SHA-512 and truncate to `icv_len` octets.
fn hmac_sha512(key: &[u8], message: &[u8], icv_len: usize) -> Vec<u8> {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes()[..icv_len].to_vec()
}

/// AES-XCBC-MAC (RFC 3566 §4): the full 16-octet MAC, before ICV truncation.
fn aes_xcbc_mac(key: &[u8], message: &[u8]) -> Result<[u8; AES_BLOCK_LEN]> {
    if key.len() != AES_BLOCK_LEN {
        return Err(CrafterError::invalid_field_value(
            "ipsec.integrity.aes_xcbc.key",
            "AES-XCBC-MAC requires a 16-octet AES-128 key",
        ));
    }

    // Derive the three subkeys K1, K2, K3 from the master key (RFC 3566 §4).
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let k1 = aes_encrypt_block(&cipher, &[0x01; AES_BLOCK_LEN]);
    let k2 = aes_encrypt_block(&cipher, &[0x02; AES_BLOCK_LEN]);
    let k3 = aes_encrypt_block(&cipher, &[0x03; AES_BLOCK_LEN]);

    let k1_cipher = Aes128::new(GenericArray::from_slice(&k1));

    // RFC 3566 §4: process all but the final block, XOR-chaining through K1.
    let mut e = [0u8; AES_BLOCK_LEN];

    if message.is_empty() {
        // Special case: M is the empty string. M[1] is a single padded block
        // 0x80 00...00, MAC'd with K3 (RFC 3566 §4, "If the size ... is 0").
        let mut block = [0u8; AES_BLOCK_LEN];
        block[0] = 0x80;
        xor_into(&mut block, &k3);
        return Ok(aes_encrypt_block(&k1_cipher, &block));
    }

    let full_blocks = message.len() / AES_BLOCK_LEN;
    // Number of complete blocks that are NOT the last block in the message.
    let remainder = message.len() % AES_BLOCK_LEN;
    // The message is split into blocks M[1..n]; the last block M[n] gets special
    // handling. `n_minus_1` is the count of blocks processed in the main loop.
    let n_minus_1 = if remainder == 0 {
        full_blocks - 1
    } else {
        full_blocks
    };

    for i in 0..n_minus_1 {
        let start = i * AES_BLOCK_LEN;
        let mut block = [0u8; AES_BLOCK_LEN];
        block.copy_from_slice(&message[start..start + AES_BLOCK_LEN]);
        xor_into(&mut e, &block);
        e = aes_encrypt_block(&k1_cipher, &e);
    }

    // Final block M[n]: complete -> XOR K2; incomplete -> pad 0x80 00.. then K3.
    let last_start = n_minus_1 * AES_BLOCK_LEN;
    let last = &message[last_start..];
    let mut final_block = [0u8; AES_BLOCK_LEN];
    if last.len() == AES_BLOCK_LEN {
        final_block.copy_from_slice(last);
        xor_into(&mut final_block, &k2);
    } else {
        final_block[..last.len()].copy_from_slice(last);
        final_block[last.len()] = 0x80;
        xor_into(&mut final_block, &k3);
    }
    xor_into(&mut e, &final_block);
    Ok(aes_encrypt_block(&k1_cipher, &e))
}

/// Encrypt a single 16-octet block with an AES cipher.
fn aes_encrypt_block(cipher: &Aes128, block: &[u8; AES_BLOCK_LEN]) -> [u8; AES_BLOCK_LEN] {
    let mut buf = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut buf);
    let mut out = [0u8; AES_BLOCK_LEN];
    out.copy_from_slice(&buf);
    out
}

/// XOR `src` into `dst` byte-wise.
fn xor_into(dst: &mut [u8; AES_BLOCK_LEN], src: &[u8; AES_BLOCK_LEN]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// AES-GMAC (RFC 4543): GMAC over `message` as AAD with an empty plaintext.
///
/// `key` is `aes_key(16) || salt(4) || iv(8)`. The 12-octet GCM nonce is
/// `salt || iv`. The resulting tag is the full 16-octet ICV.
fn aes_gmac(key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    // AES-128 key (16) + salt (4) + IV (8) = 28 octets.
    const AES128_KEY_LEN: usize = 16;
    const SALT_LEN: usize = 4;
    const IV_LEN: usize = 8;
    const EXPECTED: usize = AES128_KEY_LEN + SALT_LEN + IV_LEN;

    if key.len() != EXPECTED {
        return Err(CrafterError::invalid_field_value(
            "ipsec.integrity.aes_gmac.key",
            "AES-GMAC requires aes_key(16) || salt(4) || iv(8)",
        ));
    }

    let aes_key = &key[..AES128_KEY_LEN];
    let nonce = &key[AES128_KEY_LEN..]; // salt(4) || iv(8) = 12 octets

    type Gmac128 = AesGcm<Aes128, U12>;
    let gmac = <Gmac128 as GcmKeyInit>::new(GenericArray::from_slice(aes_key));
    let tag = gmac
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), message, &mut [])
        .map_err(|_| {
            CrafterError::invalid_field_value(
                "ipsec.integrity.aes_gmac",
                "GMAC computation failed",
            )
        })?;
    Ok(tag.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a hex string (no separators) into a byte vector for KAT setup.
    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(s.len() % 2 == 0, "hex string must have even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    // --- HMAC-SHA-1 ---------------------------------------------------------
    //
    // RFC 2202 §3, test case 2 (the "Jefe"/"what do ya want for nothing?"
    // vector). The full HMAC-SHA-1 digest is
    //   effcdf6ae5eb2fa2d27416d5f184df9c259a7c79
    // RFC 2404 truncates ESP/AH HMAC-SHA-1 to the high-order 96 bits.
    #[test]
    fn hmac_sha1_96_rfc2202_case2() {
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        let full = hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        let tag = IntegrityTransform::HmacSha1_96
            .compute(key, message)
            .unwrap();
        assert_eq!(IntegrityTransform::HmacSha1_96.icv_len(), 12);
        assert_eq!(tag, full[..12]);
        assert!(IntegrityTransform::HmacSha1_96
            .verify(key, message, &tag)
            .unwrap());
        // A one-bit tamper of the tag must fail verification.
        let mut bad = tag.clone();
        bad[0] ^= 0x01;
        assert!(!IntegrityTransform::HmacSha1_96
            .verify(key, message, &bad)
            .unwrap());
    }

    // --- HMAC-SHA-256-128 ---------------------------------------------------
    //
    // RFC 4868 §2.7.1 / Test Case 2 (PRF-HMAC-SHA-256), keyed by "Jefe" over
    // "what do ya want for nothing?". The full 256-bit PRF output is:
    //   5bdcc146 bf60754e 6a042426 089575c7 5a003f08 9d273983 9dec58b9 64ec3843
    // RFC 4868 §2.3 specifies AUTH_HMAC_SHA-256-128 truncates to 128 bits.
    #[test]
    fn hmac_sha2_256_128_rfc4868_case2() {
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        let full = hex(
            "5bdcc146bf60754e6a042426089575c7\
             5a003f089d2739839dec58b964ec3843",
        );
        let tag = IntegrityTransform::HmacSha2_256_128
            .compute(key, message)
            .unwrap();
        assert_eq!(IntegrityTransform::HmacSha2_256_128.icv_len(), 16);
        assert_eq!(tag, full[..16]);
        assert!(IntegrityTransform::HmacSha2_256_128
            .verify(key, message, &tag)
            .unwrap());
    }

    // --- HMAC-SHA-384-192 ---------------------------------------------------
    //
    // RFC 4868 §2.7.1 / Test Case 2 (PRF-HMAC-SHA-384). Full 384-bit output:
    //   af45d2e3 76484031 617f78d2 b58a6b1b 9c7ef464 f5a01b47
    //   e42ec373 6322445e 8e2240ca 5e69e2c7 8b3239ec fab21649
    // AUTH_HMAC_SHA-384-192 (RFC 4868 §2.3) truncates to 192 bits.
    #[test]
    fn hmac_sha2_384_192_rfc4868_case2() {
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        let full = hex(
            "af45d2e376484031617f78d2b58a6b1b\
             9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649",
        );
        let tag = IntegrityTransform::HmacSha2_384_192
            .compute(key, message)
            .unwrap();
        assert_eq!(IntegrityTransform::HmacSha2_384_192.icv_len(), 24);
        assert_eq!(tag, full[..24]);
        assert!(IntegrityTransform::HmacSha2_384_192
            .verify(key, message, &tag)
            .unwrap());
    }

    // --- HMAC-SHA-512-256 ---------------------------------------------------
    //
    // RFC 4868 §2.7.1 / Test Case 2 (PRF-HMAC-SHA-512). Full 512-bit output:
    //   164b7a7b fcf819e2 e395fbe7 3b56e0a3 87bd6422 2e831fd6 10270cd7 ea250554
    //   9758bf75 c05a994a 6d034f65 f8f0e6fd caeab1a3 4d4a6b4b 636e070a 38bce737
    // AUTH_HMAC_SHA-512-256 (RFC 4868 §2.3) truncates to 256 bits.
    #[test]
    fn hmac_sha2_512_256_rfc4868_case2() {
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        let full = hex(
            "164b7a7bfcf819e2e395fbe73b56e0a3\
             87bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fd\
             caeab1a34d4a6b4b636e070a38bce737",
        );
        let tag = IntegrityTransform::HmacSha2_512_256
            .compute(key, message)
            .unwrap();
        assert_eq!(IntegrityTransform::HmacSha2_512_256.icv_len(), 32);
        assert_eq!(tag, full[..32]);
        assert!(IntegrityTransform::HmacSha2_512_256
            .verify(key, message, &tag)
            .unwrap());
    }

    // --- AES-XCBC-MAC-96 ----------------------------------------------------
    //
    // RFC 3566 §4 "Test Vectors". Key is 000102...0f for every case. The full
    // (untruncated) AES-XCBC-MAC output is verified; AUTH_AES_XCBC_96 truncates
    // to the high-order 96 bits.
    const XCBC_KEY: &str = "000102030405060708090a0b0c0d0e0f";

    /// RFC 3566 §4: Test Case #1 — Message length 0.
    /// AES-XCBC-MAC(K, <empty>) = 75f0251d528ac01c4573dfd584d79f29
    #[test]
    fn aes_xcbc_mac_rfc3566_case1_len0() {
        let key = hex(XCBC_KEY);
        let full = aes_xcbc_mac(&key, &[]).unwrap();
        assert_eq!(
            full.to_vec(),
            hex("75f0251d528ac01c4573dfd584d79f29")
        );
    }

    /// RFC 3566 §4: Test Case #2 — Message length 3 (000102).
    /// AES-XCBC-MAC = 5b376580ae2f19afe7219ceef172756f
    #[test]
    fn aes_xcbc_mac_rfc3566_case2_len3() {
        let key = hex(XCBC_KEY);
        let message = hex("000102");
        let full = aes_xcbc_mac(&key, &message).unwrap();
        assert_eq!(
            full.to_vec(),
            hex("5b376580ae2f19afe7219ceef172756f")
        );
        // 96-bit ICV is the high-order 12 octets.
        let icv = IntegrityTransform::AesXcbcMac96
            .compute(&key, &message)
            .unwrap();
        assert_eq!(IntegrityTransform::AesXcbcMac96.icv_len(), 12);
        assert_eq!(icv, full[..12].to_vec());
        assert!(IntegrityTransform::AesXcbcMac96
            .verify(&key, &message, &icv)
            .unwrap());
    }

    /// RFC 3566 §4: Test Case #3 — Message length 16 (00..0f, one full block).
    /// AES-XCBC-MAC = d2a246fa349b68a79998a4394ff7a263
    #[test]
    fn aes_xcbc_mac_rfc3566_case3_len16() {
        let key = hex(XCBC_KEY);
        let message = hex("000102030405060708090a0b0c0d0e0f");
        let full = aes_xcbc_mac(&key, &message).unwrap();
        assert_eq!(
            full.to_vec(),
            hex("d2a246fa349b68a79998a4394ff7a263")
        );
    }

    /// RFC 3566 §4: Test Case #5 — Message length 20 (00..13).
    /// AES-XCBC-MAC = 47f51b4564966215b8985c63055ed308
    #[test]
    fn aes_xcbc_mac_rfc3566_case5_len20() {
        let key = hex(XCBC_KEY);
        let message = hex("000102030405060708090a0b0c0d0e0f10111213");
        let full = aes_xcbc_mac(&key, &message).unwrap();
        assert_eq!(
            full.to_vec(),
            hex("47f51b4564966215b8985c63055ed308")
        );
    }

    /// RFC 3566 §4: Test Case #7 — Message length 32 (00..1f, two full blocks).
    /// AES-XCBC-MAC = f54f0ec8d2b9f3d36807734bd5283fd4
    #[test]
    fn aes_xcbc_mac_rfc3566_case7_len32() {
        let key = hex(XCBC_KEY);
        let message =
            hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let full = aes_xcbc_mac(&key, &message).unwrap();
        assert_eq!(
            full.to_vec(),
            hex("f54f0ec8d2b9f3d36807734bd5283fd4")
        );
    }

    // --- AES-GMAC -----------------------------------------------------------
    //
    // RFC 4543 §6 ("Test Vectors") does NOT print inline ICV bytes; it defers to
    // "Appendix B of [GCM]" (McGrew & Viega, "The Galois/Counter Mode of
    // Operation (GCM)"), the same authoritative test-vector source NIST uses.
    // GMAC is exactly AES-GCM with an empty plaintext, authenticating the
    // message as AAD (RFC 4543 §2.1), so the GCM Appendix B vectors are the
    // defining KATs for this transform.

    /// McGrew & Viega GCM Appendix B, Test Case 1: 128-bit all-zero key,
    /// 96-bit all-zero IV, empty plaintext, empty AAD. With no plaintext this
    /// is pure GMAC over an empty message, and the published authentication tag
    /// is the canonical
    ///   58e2fccefa7e3061367f1d57a4e7455a
    /// This exercises the full GMAC/GHASH path (J0, length block, GCTR of the
    /// tag) with bytes published in the GCM specification.
    #[test]
    fn aes_gmac_gcm_appendix_b_case1_empty() {
        let aes_key = hex("00000000000000000000000000000000");
        // 12-octet nonce = salt(4) || iv(8), all zero (matches GCM Test Case 1).
        let nonce = hex("000000000000000000000000");
        let mut key = Vec::new();
        key.extend_from_slice(&aes_key);
        key.extend_from_slice(&nonce);

        let icv = IntegrityTransform::AesGmac.compute(&key, &[]).unwrap();
        assert_eq!(IntegrityTransform::AesGmac.icv_len(), 16);
        assert_eq!(icv, hex("58e2fccefa7e3061367f1d57a4e7455a"));
        assert!(IntegrityTransform::AesGmac.verify(&key, &[], &icv).unwrap());
    }

    /// AES-GMAC over a non-empty AAD, using the published key/IV/AAD from
    /// McGrew & Viega GCM Appendix B, Test Case 4 (128-bit key
    /// feffe9928665731c6d6a8f9467308308, 96-bit IV cafebabefacedbaddecaf888,
    /// AAD feedfacedeadbeeffeedfacedeadbeefabaddad2). GCM Test Case 4 itself
    /// also encrypts plaintext, so its printed tag is not a pure-GMAC value;
    /// the empty-plaintext (true GMAC) tag for these exact inputs is
    ///   346434fd51d5cd0c5887ec63e39b907a
    /// independently derived from OpenSSL / Python `cryptography`'s AES-GCM with
    /// an empty plaintext (a second, vetted implementation). This pins the
    /// AAD-bearing GMAC path against a cross-implementation reference value.
    #[test]
    fn aes_gmac_gcm_appendix_b_case4_aad() {
        let aes_key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = hex("cafebabefacedbaddecaf888"); // salt||iv, 12 octets
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let mut key = Vec::new();
        key.extend_from_slice(&aes_key);
        key.extend_from_slice(&nonce);

        let icv = IntegrityTransform::AesGmac.compute(&key, &aad).unwrap();
        assert_eq!(icv, hex("346434fd51d5cd0c5887ec63e39b907a"));
        assert!(IntegrityTransform::AesGmac.verify(&key, &aad, &icv).unwrap());
        // Tamper detection: flip one AAD bit, ICV must differ.
        let mut bad_aad = aad.clone();
        bad_aad[0] ^= 0x01;
        assert!(!IntegrityTransform::AesGmac
            .verify(&key, &bad_aad, &icv)
            .unwrap());
    }

    /// AES-GMAC self-consistency: compute then verify round-trips, and a bad
    /// key length is a structured error rather than a panic.
    #[test]
    fn aes_gmac_roundtrip_and_key_guard() {
        // aes_key(16) || salt(4) || iv(8) = 28 octets.
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b");
        assert_eq!(key.len(), 16 + 4 + 8);
        let message = b"GMAC authenticates this AAD";
        let icv = IntegrityTransform::AesGmac.compute(&key, message).unwrap();
        assert!(IntegrityTransform::AesGmac
            .verify(&key, message, &icv)
            .unwrap());

        let short = hex("00112233");
        assert!(IntegrityTransform::AesGmac.compute(&short, message).is_err());
    }

    /// AES-XCBC-MAC rejects a non-16-octet key with a structured error.
    #[test]
    fn aes_xcbc_key_guard() {
        let bad = hex("0011223344");
        assert!(aes_xcbc_mac(&bad, b"x").is_err());
    }
}
