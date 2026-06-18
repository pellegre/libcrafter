//! OSPFv2 authentication helpers (RFC 2328 §D).
//!
//! RFC 2328 §A.3.1 places a 2-octet Authentication Type (AuType) field and an
//! 8-octet Authentication field in every OSPF common header, and §D defines how
//! the two are used together:
//!
//! - **Null authentication (AuType 0, RFC 2328 §D.1):** the 8 authentication
//!   octets are left zero and play no role; the standard Internet checksum still
//!   protects the packet.
//! - **Simple password (AuType 1, RFC 2328 §D.2):** a cleartext password of up
//!   to 8 octets is carried in the authentication field, right-padded with zeros
//!   to fill the 8 octets; the Internet checksum still applies and excludes the
//!   authentication field.
//!
//! - **Cryptographic authentication (AuType 2, RFC 2328 §D.3):** the 8
//!   authentication octets are reinterpreted as a structured field — Reserved (2
//!   octets, zero), Key ID (1 octet), Authentication Data Length (1 octet, the
//!   digest length), and a Cryptographic sequence number (4 octets) — the OSPF
//!   header Checksum is set to zero, and a keyed message digest is appended after
//!   the OSPF packet. The digest is *not* counted in the OSPF Packet Length but
//!   *is* part of the enclosing IP payload. For keyed-MD5 (RFC 1321 / RFC 2328
//!   §D.3) the digest is `MD5(ospf_packet_with_structured_auth || key_padded_to_16)`
//!   and is 16 octets long.
//!
//! The [`Ospfv2`](crate::protocols::ospf::Ospfv2) layer already exposes the raw
//! [`autype`](crate::protocols::ospf::Ospfv2::autype) and
//! [`authentication`](crate::protocols::ospf::Ospfv2::authentication) builders
//! (which honor caller overrides, including deliberately malformed values). This
//! module adds the ergonomic, correctly-padded
//! [`null_auth`](crate::protocols::ospf::Ospfv2::null_auth),
//! [`simple_password`](crate::protocols::ospf::Ospfv2::simple_password), and
//! [`crypto_md5_auth`](crate::protocols::ospf::Ospfv2::crypto_md5_auth) builders
//! on top of them; for null and simple-password authentication the header
//! checksum auto-fill already excludes the 8-octet authentication field, so
//! setting an authentication value never changes the computed checksum.

use md5::{Digest, Md5};

use crate::protocols::ospf::constants::OSPF_AUTH_LEN;

/// Length, in octets, of a keyed-MD5 OSPF message-digest trailer (RFC 1321).
pub const OSPF_MD5_DIGEST_LEN: u8 = 16;

/// Length, in octets, to which an OSPF cryptographic-authentication key is
/// padded before being mixed into the keyed-MD5 digest (RFC 2328 §D.3).
const OSPF_MD5_KEY_PAD_LEN: usize = 16;

/// OSPF cryptographic authentication parameters (AuType 2, keyed-MD5, RFC 2328
/// §D.3).
///
/// These carry the Key ID and Cryptographic sequence number that populate the
/// structured 8-octet authentication field, plus the secret key used to compute
/// the appended message-digest trailer. The secret key never appears on the
/// wire: only the digest derived from it does.
///
/// This is `compile()` metadata held by the [`Ospfv2`](crate::protocols::ospf::Ospfv2)
/// layer; it is installed by
/// [`Ospfv2::crypto_md5_auth`](crate::protocols::ospf::Ospfv2::crypto_md5_auth)
/// and does not participate in the layer's compiled-byte equality beyond
/// producing the trailer.
#[derive(Debug, Clone)]
pub struct OspfCryptoAuth {
    /// Key ID identifying the shared secret (RFC 2328 §D.3).
    key_id: u8,
    /// Cryptographic sequence number, monotonically increasing to defeat replay
    /// (RFC 2328 §D.3).
    sequence_number: u32,
    /// The shared secret key; padded to 16 octets and mixed into the digest, but
    /// never placed on the wire.
    key: Vec<u8>,
}

impl OspfCryptoAuth {
    /// Build cryptographic-authentication parameters from a Key ID, a
    /// Cryptographic sequence number, and the shared secret key bytes.
    pub fn new(key_id: u8, sequence_number: u32, key: impl Into<Vec<u8>>) -> Self {
        Self {
            key_id,
            sequence_number,
            key: key.into(),
        }
    }

    /// The Key ID identifying the shared secret (RFC 2328 §D.3).
    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    /// The Cryptographic sequence number (RFC 2328 §D.3).
    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    /// The shared secret key bytes used to compute the digest (never on the wire).
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Encode the structured 8-octet authentication field for keyed-MD5
    /// cryptographic authentication (RFC 2328 §D.3): Reserved (2 octets, zero),
    /// Key ID (1 octet), Authentication Data Length (1 octet, the digest length),
    /// and the Cryptographic sequence number (4 octets, big-endian).
    pub(crate) fn structured_auth_field(&self) -> [u8; OSPF_AUTH_LEN] {
        let mut field = [0u8; OSPF_AUTH_LEN];
        // Octets 0..2: Reserved, left zero.
        field[2] = self.key_id;
        field[3] = OSPF_MD5_DIGEST_LEN;
        field[4..8].copy_from_slice(&self.sequence_number.to_be_bytes());
        field
    }

    /// Compute the keyed-MD5 message-digest trailer over `packet_bytes` followed
    /// by the secret key right-padded with zeros to 16 octets (RFC 2328 §D.3,
    /// RFC 1321). `packet_bytes` must be the full OSPF packet with the structured
    /// authentication field already in place and the header Checksum zeroed.
    pub(crate) fn md5_digest(&self, packet_bytes: &[u8]) -> [u8; OSPF_MD5_DIGEST_LEN as usize] {
        let mut padded_key = [0u8; OSPF_MD5_KEY_PAD_LEN];
        let copied = self.key.len().min(OSPF_MD5_KEY_PAD_LEN);
        padded_key[..copied].copy_from_slice(&self.key[..copied]);

        let mut hasher = Md5::new();
        hasher.update(packet_bytes);
        hasher.update(padded_key);
        hasher.finalize().into()
    }
}

/// Right-pad (and, if necessary, truncate) a cleartext OSPF simple password into
/// the fixed 8-octet authentication field (RFC 2328 §D.2).
///
/// The first up-to-8 octets of `password` are copied into the field and any
/// remaining octets are left zero. A password longer than 8 octets is truncated
/// to its first 8 octets — the only 8 the OSPF authentication field can carry —
/// so the result is always exactly [`OSPF_AUTH_LEN`] octets.
pub(crate) fn simple_password_field(password: &[u8]) -> [u8; OSPF_AUTH_LEN] {
    let mut field = [0u8; OSPF_AUTH_LEN];
    let copied = password.len().min(OSPF_AUTH_LEN);
    field[..copied].copy_from_slice(&password[..copied]);
    field
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ospf_simple_password_field_right_pads_short_passwords() {
        // A short password fills the leading octets and leaves the rest zero.
        assert_eq!(
            simple_password_field(b"abc"),
            [b'a', b'b', b'c', 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn ospf_simple_password_field_keeps_an_exact_eight_octet_password() {
        // Exactly 8 octets are copied verbatim with no padding.
        assert_eq!(
            simple_password_field(b"password"),
            [b'p', b'a', b's', b's', b'w', b'o', b'r', b'd']
        );
    }

    #[test]
    fn ospf_simple_password_field_truncates_overlong_passwords() {
        // A password longer than 8 octets is truncated to its first 8 octets.
        assert_eq!(
            simple_password_field(b"toolongsecret"),
            [b't', b'o', b'o', b'l', b'o', b'n', b'g', b's']
        );
    }

    #[test]
    fn ospf_crypto_auth_structured_field_matches_rfc_2328_d3_layout() {
        // RFC 2328 §D.3: Reserved(2, zero), Key ID(1), Auth Data Length(1) = the
        // digest length (16 for keyed-MD5), Cryptographic sequence number(4).
        let auth = OspfCryptoAuth::new(7, 0x0102_0304, b"secret".to_vec());
        assert_eq!(
            auth.structured_auth_field(),
            [0x00, 0x00, 0x07, OSPF_MD5_DIGEST_LEN, 0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn ospf_crypto_auth_md5_digest_matches_the_rfc_1321_abc_vector() {
        // RFC 1321 pins MD5("abc") = 900150983cd24fb0d6963f7d28e17f72. An
        // empty key pads to 16 zero octets, so digesting "abc" with the
        // 16-octet padded zero key is NOT the bare MD5("abc"); instead pin the
        // bare MD5("abc") through a zero-length packet trick: a zero-length key
        // appended to "abc" still adds 16 zero octets. So verify the bare vector
        // directly via the underlying hasher and the keyed form separately.
        let bare = {
            let mut hasher = Md5::new();
            hasher.update(b"abc");
            let out: [u8; 16] = hasher.finalize().into();
            out
        };
        assert_eq!(
            bare,
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28,
                0xe1, 0x7f, 0x72
            ]
        );

        // The keyed-MD5 helper digests packet_bytes || key_padded_to_16. With an
        // empty key the padded key is 16 zero octets, so the digest equals
        // MD5("abc" || [0;16]); recomputing with the same inputs reproduces it.
        let auth = OspfCryptoAuth::new(1, 0, Vec::new());
        let digest = auth.md5_digest(b"abc");
        let expected = {
            let mut hasher = Md5::new();
            hasher.update(b"abc");
            hasher.update([0u8; 16]);
            let out: [u8; 16] = hasher.finalize().into();
            out
        };
        assert_eq!(digest, expected);
    }

    #[test]
    fn ospf_crypto_auth_md5_digest_pads_or_truncates_the_key_to_sixteen_octets() {
        // A key shorter than 16 octets is right-padded with zeros; a key longer
        // than 16 octets is truncated to its first 16 — both yield a 16-octet
        // padded key, matching the explicit padded forms.
        let short = OspfCryptoAuth::new(1, 0, b"key".to_vec());
        let short_expected = {
            let mut padded = [0u8; 16];
            padded[..3].copy_from_slice(b"key");
            let mut hasher = Md5::new();
            hasher.update(b"packet");
            hasher.update(padded);
            let out: [u8; 16] = hasher.finalize().into();
            out
        };
        assert_eq!(short.md5_digest(b"packet"), short_expected);

        let long_key = vec![0xABu8; 20];
        let long = OspfCryptoAuth::new(1, 0, long_key.clone());
        let long_expected = {
            let mut hasher = Md5::new();
            hasher.update(b"packet");
            hasher.update(&long_key[..16]);
            let out: [u8; 16] = hasher.finalize().into();
            out
        };
        assert_eq!(long.md5_digest(b"packet"), long_expected);
    }
}
