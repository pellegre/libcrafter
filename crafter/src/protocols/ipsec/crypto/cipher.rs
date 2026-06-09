//! IPSec confidentiality (cipher) transforms.
//!
//! These are the non-AEAD ESP ciphers: each pairs with a separate integrity
//! transform from [`super::integrity`] under the ESP "encrypt-then-MAC" suites.
//! Every transform is a pure function over `(key, iv, buffer)` and is
//! individually KAT-verified against its defining RFC. SA wiring and the ESP
//! padding/trailer are layered on in later steps; here the ciphers stay
//! primitive.
//!
//! Coverage (plan.md "Algorithm coverage" / "ESP wire rules"):
//! - `ENCR_AES_CBC` (RFC 3602) — AES-128 in CBC mode, 16-octet block and IV.
//! - `ENCR_AES_CTR` (RFC 3686) — AES-128 in CTR mode, 8-octet IV plus a
//!   4-octet nonce/salt and a 4-octet block counter starting at 1.
//! - `ENCR_NULL` (RFC 2410) — the identity transform, 1-octet "block", no IV.
//!
//! ## Padding
//! The CBC transform operates on an **already block-aligned** buffer: ESP adds
//! its pad / pad-length / next-header trailer in a later step, not here. CBC
//! therefore uses no cipher-level padding. CTR is a keystream cipher and needs
//! no alignment. NULL copies its input verbatim.

use aes::Aes128;
use cipher::block_padding::NoPadding;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher};

use crate::{CrafterError, Result};

/// AES block size in octets (RFC 3602 / RFC 3686).
const AES_BLOCK_LEN: usize = 16;
/// AES-128 key length in octets.
const AES128_KEY_LEN: usize = 16;
/// Explicit IV length for AES-CTR (RFC 3686 §4): the 64-bit per-packet IV.
const CTR_IV_LEN: usize = 8;
/// Nonce/salt length for AES-CTR (RFC 3686 §4): the 32-bit per-SA value.
const CTR_NONCE_LEN: usize = 4;

/// AES-128 in CBC mode (RFC 3602), no cipher-level padding.
type AesCbcEnc = cbc::Encryptor<Aes128>;
/// AES-128 CBC decryptor (RFC 3602), no cipher-level padding.
type AesCbcDec = cbc::Decryptor<Aes128>;
/// AES-128 in CTR mode with a big-endian 128-bit counter (RFC 3686).
type AesCtr = ctr::Ctr128BE<Aes128>;

/// IPSec confidentiality transforms, identified by their IKEv2 transform names.
///
/// Each variant maps to an ESP encryption algorithm. The transforms here are
/// the non-AEAD ciphers; AEAD suites (AES-GCM/CCM, ChaCha20-Poly1305) live in
/// the sibling `aead` module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherTransform {
    /// AES-128-CBC (RFC 3602): explicit 16-octet IV, 16-octet block.
    AesCbc,
    /// AES-128-CTR (RFC 3686): 8-octet IV, 4-octet salt-prefixed counter block.
    AesCtr,
    /// NULL (RFC 2410): the identity transform, no key/IV semantics.
    Null,
}

impl CipherTransform {
    /// Cipher block size in octets.
    ///
    /// CBC operates on multiples of this length. NULL has no real block
    /// structure; RFC 2410 §2.1 defines its blocksize as 1 octet so that ESP
    /// never adds padding for it.
    pub const fn block_size(self) -> usize {
        match self {
            Self::AesCbc => AES_BLOCK_LEN, // RFC 3602 §3: 16-octet block
            Self::AesCtr => 1,             // RFC 3686 §2: keystream, no block padding
            Self::Null => 1,               // RFC 2410 §2.1: blocksize of 1
        }
    }

    /// Length in octets of the explicit per-packet IV carried on the wire.
    ///
    /// For CBC this is the 16-octet IV (RFC 3602 §3). For CTR this is the
    /// 8-octet IV (RFC 3686 §4); the 4-octet salt is part of the key material,
    /// not the wire IV. NULL has no IV.
    pub const fn iv_len(self) -> usize {
        match self {
            Self::AesCbc => AES_BLOCK_LEN, // RFC 3602: 16-octet IV
            Self::AesCtr => CTR_IV_LEN,    // RFC 3686: 8-octet IV
            Self::Null => 0,               // RFC 2410: no IV
        }
    }

    /// Encrypt `plaintext` under `key`/`iv`.
    ///
    /// - **AES-CBC**: `iv` is the 16-octet IV and `plaintext` MUST already be a
    ///   whole number of 16-octet blocks (ESP supplies the padding). `key` is a
    ///   16-octet AES-128 key.
    /// - **AES-CTR**: `key` is `aes_key(16) || salt(4)` and `iv` is the 8-octet
    ///   explicit IV. The 128-bit counter block is `salt || iv || 0x00000001`
    ///   (RFC 3686 §4). Encryption and decryption are identical.
    /// - **NULL**: returns a copy of `plaintext`.
    ///
    /// Returns an error only when the key/IV/length shape is invalid for the
    /// transform; the cipher math itself is infallible here.
    pub fn encrypt(self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::AesCbc => aes_cbc_encrypt(key, iv, plaintext),
            Self::AesCtr => aes_ctr_apply(key, iv, plaintext),
            Self::Null => Ok(plaintext.to_vec()),
        }
    }

    /// Decrypt `ciphertext` under `key`/`iv`.
    ///
    /// The key/IV conventions match [`CipherTransform::encrypt`]. For CBC the
    /// `ciphertext` MUST be a whole number of 16-octet blocks; ESP padding is
    /// stripped by the ESP layer after decryption, not here. CTR and NULL are
    /// symmetric with encryption.
    pub fn decrypt(self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::AesCbc => aes_cbc_decrypt(key, iv, ciphertext),
            Self::AesCtr => aes_ctr_apply(key, iv, ciphertext),
            Self::Null => Ok(ciphertext.to_vec()),
        }
    }
}

/// Validate the AES-128 CBC key and IV shapes.
fn cbc_key_iv(key: &[u8], iv: &[u8]) -> Result<()> {
    if key.len() != AES128_KEY_LEN {
        return Err(CrafterError::invalid_field_value(
            "ipsec.cipher.aes_cbc.key",
            "AES-CBC requires a 16-octet AES-128 key",
        ));
    }
    if iv.len() != AES_BLOCK_LEN {
        return Err(CrafterError::invalid_field_value(
            "ipsec.cipher.aes_cbc.iv",
            "AES-CBC requires a 16-octet IV",
        ));
    }
    Ok(())
}

/// AES-128-CBC encrypt over an already block-aligned buffer (RFC 3602 §3).
fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    cbc_key_iv(key, iv)?;
    if plaintext.len() % AES_BLOCK_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            "ipsec.cipher.aes_cbc.plaintext",
            "AES-CBC plaintext must be a multiple of the 16-octet block size",
        ));
    }
    let mut buf = plaintext.to_vec();
    let len = buf.len();
    // NoPadding over an exact-block buffer is infallible; the only error paths
    // (unpadded length / undersized buffer) are guarded above.
    let ct = AesCbcEnc::new(key.into(), iv.into())
        .encrypt_padded_mut::<NoPadding>(&mut buf, len)
        .map_err(|_| {
            CrafterError::invalid_field_value("ipsec.cipher.aes_cbc", "AES-CBC encryption failed")
        })?;
    Ok(ct.to_vec())
}

/// AES-128-CBC decrypt over a block-aligned ciphertext (RFC 3602 §3).
fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    cbc_key_iv(key, iv)?;
    if ciphertext.len() % AES_BLOCK_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            "ipsec.cipher.aes_cbc.ciphertext",
            "AES-CBC ciphertext must be a multiple of the 16-octet block size",
        ));
    }
    let mut buf = ciphertext.to_vec();
    // NoPadding decrypt does not strip anything; ESP trailer removal is the ESP
    // layer's job. This yields the raw block-aligned plaintext.
    let pt = AesCbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| {
            CrafterError::invalid_field_value("ipsec.cipher.aes_cbc", "AES-CBC decryption failed")
        })?;
    Ok(pt.to_vec())
}

/// AES-128-CTR keystream application (RFC 3686 §4).
///
/// `key` is `aes_key(16) || salt(4)` and `iv` is the 8-octet explicit IV. The
/// 128-bit initial counter block is `salt(4) || iv(8) || 0x00000001`; the
/// 32-bit block counter increments per 16-octet keystream block. Because CTR is
/// a keystream cipher, this single routine serves both encryption and
/// decryption.
fn aes_ctr_apply(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if key.len() != AES128_KEY_LEN + CTR_NONCE_LEN {
        return Err(CrafterError::invalid_field_value(
            "ipsec.cipher.aes_ctr.key",
            "AES-CTR requires aes_key(16) || salt(4)",
        ));
    }
    if iv.len() != CTR_IV_LEN {
        return Err(CrafterError::invalid_field_value(
            "ipsec.cipher.aes_ctr.iv",
            "AES-CTR requires an 8-octet IV",
        ));
    }

    let aes_key = &key[..AES128_KEY_LEN];
    let salt = &key[AES128_KEY_LEN..]; // 4-octet nonce/salt

    // Counter block (RFC 3686 §4): salt(4) || iv(8) || block-counter(4 = 1).
    let mut counter = [0u8; AES_BLOCK_LEN];
    counter[..CTR_NONCE_LEN].copy_from_slice(salt);
    counter[CTR_NONCE_LEN..CTR_NONCE_LEN + CTR_IV_LEN].copy_from_slice(iv);
    counter[AES_BLOCK_LEN - 4..].copy_from_slice(&1u32.to_be_bytes());

    let mut buf = data.to_vec();
    let mut ctr = AesCtr::new(aes_key.into(), (&counter).into());
    ctr.apply_keystream(&mut buf);
    Ok(buf)
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

    // --- AES-CBC: RFC 3602 §4 "Test Vectors" --------------------------------
    //
    // RFC 3602 §4 publishes AES-CBC test vectors with explicit Key / IV /
    // Plaintext / Ciphertext. The plaintext is block-aligned in each printed
    // case, which is exactly the contract of this transform (ESP supplies any
    // padding before calling it). We assert the exact ciphertext, then confirm
    // decrypt round-trips back to the plaintext.

    /// RFC 3602 §4 Case #2: 16-octet (one block) plaintext.
    ///   Key:        c286696d887c9aa0611bbb3e2025a45a
    ///   IV:         562e17996d093d28ddb3ba695a2e6f58
    ///   Plaintext:  000102030405060708090a0b0c0d0e0f
    ///   Ciphertext: d296cd94c2cccf8a3a863028b5e1dc0a7586602d253cfff91b8266bea6d61ab1
    #[test]
    fn aes_cbc_rfc3602_case2() {
        let key = hex("c286696d887c9aa0611bbb3e2025a45a");
        let iv = hex("562e17996d093d28ddb3ba695a2e6f58");
        let plaintext = hex("000102030405060708090a0b0c0d0e0f");
        let expected = hex("d296cd94c2cccf8a3a863028b5e1dc0a");

        assert_eq!(CipherTransform::AesCbc.block_size(), 16);
        assert_eq!(CipherTransform::AesCbc.iv_len(), 16);

        let ct = CipherTransform::AesCbc
            .encrypt(&key, &iv, &plaintext)
            .unwrap();
        assert_eq!(ct, expected);

        let pt = CipherTransform::AesCbc.decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    /// RFC 3602 §4 Case #4: 32-octet (two block) plaintext.
    ///   Key:        56e47a38c5598974bc46903dba290349
    ///   IV:         8ce82eefbea0da3c44699ed7db51b7d9
    ///   Plaintext:  a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
    ///               b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
    ///   Ciphertext: c30e32ffedc0774e6aff6af0869f71aa
    ///               0f3af07a9a31a9c684db207eb0ef8e4e
    #[test]
    fn aes_cbc_rfc3602_case4() {
        let key = hex("56e47a38c5598974bc46903dba290349");
        let iv = hex("8ce82eefbea0da3c44699ed7db51b7d9");
        let plaintext = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
             b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
        let expected = hex("c30e32ffedc0774e6aff6af0869f71aa\
             0f3af07a9a31a9c684db207eb0ef8e4e");

        let ct = CipherTransform::AesCbc
            .encrypt(&key, &iv, &plaintext)
            .unwrap();
        assert_eq!(ct, expected);

        let pt = CipherTransform::AesCbc.decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    /// A non-block-aligned CBC input is a structured error, not a panic. ESP is
    /// responsible for padding before it calls the cipher.
    #[test]
    fn aes_cbc_rejects_unaligned_and_bad_key() {
        let key = hex("c286696d887c9aa0611bbb3e2025a45a");
        let iv = hex("562e17996d093d28ddb3ba695a2e6f58");
        // 15 octets: not a whole block.
        assert!(CipherTransform::AesCbc
            .encrypt(&key, &iv, &[0u8; 15])
            .is_err());
        // Wrong key length.
        assert!(CipherTransform::AesCbc
            .encrypt(&hex("0011223344"), &iv, &[0u8; 16])
            .is_err());
        // Wrong IV length.
        assert!(CipherTransform::AesCbc
            .encrypt(&key, &hex("00112233"), &[0u8; 16])
            .is_err());
    }

    // --- AES-CTR: RFC 3686 §6 "Test Vectors" --------------------------------
    //
    // RFC 3686 §6 publishes AES-CTR test vectors as Key (AES key || nonce),
    // IV, Plaintext, and Ciphertext. In this transform the 4-octet nonce/salt
    // is appended to the AES key (key = aes_key || nonce) and the IV is the
    // 8-octet explicit IV; the block counter starts at 1 per RFC 3686 §4. We
    // assert the exact ciphertext and confirm CTR is its own inverse.

    /// RFC 3686 §6 Test Vector #1: 16-octet plaintext, 128-bit key.
    ///   Key:        ae6852f8121067cc4bf7a5765577f39e  (AES key)
    ///   Nonce:      00000030                          (salt)
    ///   IV:         0000000000000000
    ///   Plaintext:  53696e676c6520626c6f636b206d7367   ("Single block msg")
    ///   Ciphertext: e4095d4fb7a7b3792d6175a3261311b8
    #[test]
    fn aes_ctr_rfc3686_vector1() {
        let aes_key = hex("ae6852f8121067cc4bf7a5765577f39e");
        let nonce = hex("00000030");
        let iv = hex("0000000000000000");
        let plaintext = hex("53696e676c6520626c6f636b206d7367");
        let expected = hex("e4095d4fb7a7b3792d6175a3261311b8");

        assert_eq!(CipherTransform::AesCtr.block_size(), 1);
        assert_eq!(CipherTransform::AesCtr.iv_len(), 8);

        let mut key = aes_key.clone();
        key.extend_from_slice(&nonce); // key = aes_key(16) || salt(4)

        let ct = CipherTransform::AesCtr
            .encrypt(&key, &iv, &plaintext)
            .unwrap();
        assert_eq!(ct, expected);

        // CTR is symmetric: decrypt recovers the plaintext.
        let pt = CipherTransform::AesCtr.decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    /// RFC 3686 §6 Test Vector #2: 32-octet plaintext, 128-bit key.
    ///   Key:        7e24067817fae0d743d6ce1f32539163
    ///   Nonce:      006cb6db
    ///   IV:         c0543b59da48d90b
    ///   Plaintext:  000102030405060708090a0b0c0d0e0f
    ///               101112131415161718191a1b1c1d1e1f
    ///   Ciphertext: 5104a106168a72d9790d41ee8edad388
    ///               eb2e1efc46da57c8fce630df9141be28
    #[test]
    fn aes_ctr_rfc3686_vector2() {
        let aes_key = hex("7e24067817fae0d743d6ce1f32539163");
        let nonce = hex("006cb6db");
        let iv = hex("c0543b59da48d90b");
        let plaintext = hex("000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f");
        let expected = hex("5104a106168a72d9790d41ee8edad388\
             eb2e1efc46da57c8fce630df9141be28");

        let mut key = aes_key.clone();
        key.extend_from_slice(&nonce);

        let ct = CipherTransform::AesCtr
            .encrypt(&key, &iv, &plaintext)
            .unwrap();
        assert_eq!(ct, expected);

        let pt = CipherTransform::AesCtr.decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    /// RFC 3686 §6 Test Vector #3: 36-octet plaintext, 128-bit key.
    ///   Key:        7691be035e5020a8ac6e618529f9a0dc
    ///   Nonce:      00e0017b
    ///   IV:         27777f3f4a1786f0
    ///   Plaintext:  000102...0102030405060708090a0b0c0d0e0f
    ///               202122232425262728292a2b2c2d2e2f
    ///               30313233
    ///   Ciphertext: c1cf48a89f2ffdd9cf4652e9efdb72d7
    ///               4540a42bde6d7836d59a5ceaaef31053
    ///               25b2072f
    #[test]
    fn aes_ctr_rfc3686_vector3() {
        let aes_key = hex("7691be035e5020a8ac6e618529f9a0dc");
        let nonce = hex("00e0017b");
        let iv = hex("27777f3f4a1786f0");
        let plaintext = hex("000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f\
             20212223");
        let expected = hex("c1cf48a89f2ffdd9cf4652e9efdb72d7\
             4540a42bde6d7836d59a5ceaaef31053\
             25b2072f");

        let mut key = aes_key.clone();
        key.extend_from_slice(&nonce);

        let ct = CipherTransform::AesCtr
            .encrypt(&key, &iv, &plaintext)
            .unwrap();
        assert_eq!(ct, expected);

        let pt = CipherTransform::AesCtr.decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    /// AES-CTR guards its key/IV shapes with structured errors.
    #[test]
    fn aes_ctr_key_iv_guards() {
        let key = hex("ae6852f8121067cc4bf7a5765577f39e00000030"); // 20 octets
                                                                   // Wrong IV length.
        assert!(CipherTransform::AesCtr
            .encrypt(&key, &hex("0000"), &[0u8; 4])
            .is_err());
        // Wrong key length (missing salt).
        assert!(CipherTransform::AesCtr
            .encrypt(
                &hex("ae6852f8121067cc4bf7a5765577f39e"),
                &hex("0000000000000000"),
                &[0u8; 4]
            )
            .is_err());
    }

    // --- NULL: RFC 2410 -----------------------------------------------------
    //
    // RFC 2410 defines the NULL cipher as the identity transform with a
    // blocksize of one octet and no IV. Encryption and decryption are copies.
    #[test]
    fn null_is_identity() {
        assert_eq!(CipherTransform::Null.block_size(), 1);
        assert_eq!(CipherTransform::Null.iv_len(), 0);

        let data = hex("deadbeef0011223344");
        let ct = CipherTransform::Null.encrypt(&[], &[], &data).unwrap();
        assert_eq!(ct, data);
        let pt = CipherTransform::Null.decrypt(&[], &[], &ct).unwrap();
        assert_eq!(pt, data);

        // Empty input round-trips too.
        assert_eq!(
            CipherTransform::Null.encrypt(&[], &[], &[]).unwrap(),
            Vec::<u8>::new()
        );
    }
}
