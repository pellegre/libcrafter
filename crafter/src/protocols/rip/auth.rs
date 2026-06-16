//! RIPv2 authentication entry model (AFI 0xFFFF).
//!
//! RIPv2 authentication (RFC 2453 §4.1, RFC 4822 §3) replaces the first route
//! entry of a message with a special authentication entry whose Address Family
//! Identifier is the marker [`RIP_AFI_AUTH`] (0xFFFF). The two octets that would
//! be a route entry's Route Tag instead carry the Authentication Type:
//!
//! - type 2 — simple password (RFC 2453 §4.1): the remaining 16 octets carry a
//!   plaintext password, right-padded with zeros.
//! - type 3 — keyed message digest (RFC 2082, obsoleted by RFC 4822 §3): the
//!   remaining octets carry the trailing-entry header (packet length to digest
//!   offset, key id, authentication-data length, sequence number, and two
//!   reserved words), with the digest itself carried in a trailing entry.
//!
//! This module defines the auth *entry model* and its builders only:
//! [`RipAuth`] holds the authentication type and a [`RipAuthPayload`], and
//! [`RipAuth::as_entry`] renders the entry into a [`RipEntry`] carrying AFI
//! 0xFFFF and the type in the tag octets so it can sit in a [`Rip`] message's
//! entry list. The full simple-password and keyed-digest wire encodings (and
//! the RFC 2082/4822 digest computation) are added in later steps.
//!
//! [`Rip`]: super::Rip

use std::net::Ipv4Addr;

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::field::Field;

use super::constants::{RIP_AFI_AUTH, RIP_ENTRY_LEN, RIP_HEADER_LEN};
use super::entry::RipEntry;
use super::registry::{
    is_rip_auth_marker, rip_auth_type, rip_auth_type_code, RipAuthType,
    RIP_AUTH_TYPE_KEYED_DIGEST, RIP_AUTH_TYPE_SIMPLE,
};

/// Simple-password authentication carries up to 16 octets of plaintext password.
/// RFC 2453 §4.1.
pub const RIP_SIMPLE_PASSWORD_LEN: usize = 16;

/// Authentication Type carried in the trailing keyed-digest authentication
/// block (RFC 4822 §3.1, originally RFC 2082): the trailer entry that follows
/// the last route entry uses the marker AFI 0xFFFF and this `0x0001` trailer
/// type, then carries the raw digest octets.
pub const RIP_AUTH_TRAILER_MARKER: u16 = 0x0001;

/// The keyed-message-digest algorithm used by a RIPv2 keyed authentication
/// entry (RFC 2082 / RFC 4822 §3).
///
/// RFC 2082 defined Keyed-MD5; RFC 4822 §3 generalized RIPv2 cryptographic
/// authentication to the HMAC-SHA family while keeping the same trailing-entry
/// framing. The selected algorithm fixes the length of the trailing digest
/// (see [`RipDigestAlgorithm::digest_len`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RipDigestAlgorithm {
    /// RFC 2082 §3.2.1 Keyed-MD5 (16-octet digest).
    KeyedMd5,
    /// RFC 4822 §3 HMAC-SHA-1 (20-octet digest).
    HmacSha1,
    /// RFC 4822 §3 HMAC-SHA-256 (32-octet digest).
    HmacSha256,
}

impl RipDigestAlgorithm {
    /// Length, in octets, of this algorithm's trailing authentication digest
    /// (RFC 2082 §3.2.1, RFC 4822 §3): 16 for Keyed-MD5, 20 for HMAC-SHA-1, 32
    /// for HMAC-SHA-256.
    pub fn digest_len(self) -> usize {
        match self {
            RipDigestAlgorithm::KeyedMd5 => 16,
            RipDigestAlgorithm::HmacSha1 => 20,
            RipDigestAlgorithm::HmacSha256 => 32,
        }
    }
}

impl Default for RipDigestAlgorithm {
    fn default() -> Self {
        RipDigestAlgorithm::KeyedMd5
    }
}

/// A RIPv2 authentication entry (AFI 0xFFFF; RFC 2453 §4.1, RFC 4822 §3).
///
/// The `auth_type` field is held in a [`Field`] wrapper so a later `compile()`
/// step can fill it only when the caller left it unset and leave caller-set
/// values — including deliberately wrong ones — untouched. The `payload`
/// distinguishes the two RIPv2 authentication forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RipAuth {
    /// Authentication Type, the 2-octet field in the auth entry's tag octets
    /// (RFC 2453 §4.1): 2 simple password, 3 keyed message digest.
    pub auth_type: Field<u16>,
    /// The authentication payload, selecting the simple-password or
    /// keyed-digest form.
    pub payload: RipAuthPayload,
}

/// The RIPv2 authentication payload, one variant per authentication type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RipAuthPayload {
    /// Simple password (RFC 2453 §4.1): 16 octets of plaintext password,
    /// right-padded with zeros.
    SimplePassword([u8; RIP_SIMPLE_PASSWORD_LEN]),
    /// Keyed message digest (RFC 2082 / RFC 4822 §3): the trailing-entry header
    /// that precedes the digest in the trailing entry.
    KeyedDigest(RipKeyedDigestHeader),
}

/// The RFC 4822 §3.1 keyed-message-digest trailing-entry header.
///
/// This header occupies the keyed-digest authentication entry (the entry whose
/// AFI is 0xFFFF and whose Authentication Type is 3); the digest itself is
/// carried in a separate trailing entry. Every field is held in a [`Field`]
/// wrapper so a later `compile()` step can fill values (notably the offset and
/// authentication-data length) only when the caller left them unset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RipKeyedDigestHeader {
    /// Keyed-message-digest algorithm (RFC 2082 / RFC 4822 §3), defaulting to
    /// [`RipDigestAlgorithm::KeyedMd5`]. It fixes the trailing digest length and
    /// selects the hash used when `compile()` auto-computes the digest.
    pub algorithm: RipDigestAlgorithm,
    /// Offset, in octets from the start of the RIP message, to the trailing
    /// digest entry (the "RIP packet length" / offset field; RFC 4822 §3.1).
    pub offset: Field<u16>,
    /// Key Identifier (RFC 4822 §3.1): identifies the key/algorithm in use.
    pub key_id: Field<u8>,
    /// Authentication Data Length (RFC 4822 §3.1): length, in octets, of the
    /// trailing digest.
    pub auth_data_len: Field<u8>,
    /// Sequence Number (RFC 4822 §3.1): a monotonically increasing,
    /// non-decreasing per-message counter.
    pub sequence: Field<u32>,
    /// First reserved 4-octet word, must be zero (RFC 4822 §3.1).
    pub reserved1: Field<u32>,
    /// Second reserved 4-octet word, must be zero (RFC 4822 §3.1).
    pub reserved2: Field<u32>,
    /// Caller-pinned trailing digest, if any (RFC 2082 §3.2.1).
    ///
    /// When `Some`, this is the exact 16-octet Keyed-MD5 digest the caller wants
    /// emitted; `compile()` honors it untouched, so a caller may deliberately pin
    /// a wrong digest to exercise a verifier. When `None`, `compile()` computes
    /// the digest with [`compute_md5_digest`] over the message and key. The
    /// digest itself rides in the trailing authentication block, not in this
    /// header entry's octets.
    pub digest: Option<[u8; 16]>,
}

impl RipKeyedDigestHeader {
    /// Create a keyed-digest header with library defaults (all zero), none of
    /// which are marked caller-set.
    pub fn new() -> Self {
        Self {
            algorithm: RipDigestAlgorithm::default(),
            offset: Field::defaulted(0),
            key_id: Field::defaulted(0),
            auth_data_len: Field::defaulted(0),
            sequence: Field::defaulted(0),
            reserved1: Field::defaulted(0),
            reserved2: Field::defaulted(0),
            digest: None,
        }
    }

    /// Effective offset to the trailing digest entry (caller-set or default).
    pub fn offset_value(&self) -> u16 {
        self.offset.value().copied().unwrap_or(0)
    }

    /// Effective Key Identifier (caller-set or default).
    pub fn key_id_value(&self) -> u8 {
        self.key_id.value().copied().unwrap_or(0)
    }

    /// Effective Authentication Data Length (caller-set or, when unset, the
    /// trailing digest length implied by [`Self::algorithm`]).
    ///
    /// When the caller pinned an explicit length it survives untouched
    /// (including deliberately wrong values); otherwise this reflects the
    /// selected algorithm's digest length (16 Keyed-MD5, 20 HMAC-SHA-1, 32
    /// HMAC-SHA-256) per RFC 2082 §3.2.1 / RFC 4822 §3.
    pub fn auth_data_len_value(&self) -> u8 {
        if self.auth_data_len.is_user_set() {
            self.auth_data_len.value().copied().unwrap_or(0)
        } else {
            self.algorithm.digest_len() as u8
        }
    }

    /// Effective Sequence Number (caller-set or default).
    pub fn sequence_value(&self) -> u32 {
        self.sequence.value().copied().unwrap_or(0)
    }
}

impl Default for RipKeyedDigestHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl RipAuth {
    /// Build a simple-password authentication entry (RFC 2453 §4.1).
    ///
    /// The password is right-padded with zero octets, or truncated, to exactly
    /// [`RIP_SIMPLE_PASSWORD_LEN`] (16) octets. The authentication type is set
    /// (caller-set) to [`RIP_AUTH_TYPE_SIMPLE`] (2).
    pub fn simple_password(password: &[u8]) -> Self {
        let mut bytes = [0u8; RIP_SIMPLE_PASSWORD_LEN];
        let take = password.len().min(RIP_SIMPLE_PASSWORD_LEN);
        bytes[..take].copy_from_slice(&password[..take]);
        Self {
            auth_type: Field::user(RIP_AUTH_TYPE_SIMPLE),
            payload: RipAuthPayload::SimplePassword(bytes),
        }
    }

    /// Build a keyed message-digest authentication entry (RFC 2082 / RFC 4822
    /// §3).
    ///
    /// Sets the authentication type (caller-set) to
    /// [`RIP_AUTH_TYPE_KEYED_DIGEST`] (3) and seeds the trailing-entry header
    /// with the given Key Identifier and Authentication Data Length; the offset,
    /// sequence, and reserved words default to zero and are filled in later
    /// encoding/compile steps.
    pub fn keyed_digest(key_id: u8, auth_data_len: u8) -> Self {
        let mut header = RipKeyedDigestHeader::new();
        header.key_id.set_user(key_id);
        header.auth_data_len.set_user(auth_data_len);
        Self {
            auth_type: Field::user(RIP_AUTH_TYPE_KEYED_DIGEST),
            payload: RipAuthPayload::KeyedDigest(header),
        }
    }

    /// Build a keyed message-digest authentication entry for a specific digest
    /// algorithm (RFC 2082 Keyed-MD5 / RFC 4822 §3 HMAC-SHA).
    ///
    /// Sets the authentication type (caller-set) to
    /// [`RIP_AUTH_TYPE_KEYED_DIGEST`] (3), records `alg` on the trailing-entry
    /// header, and seeds the Key Identifier. The Authentication Data Length is
    /// left unset so it reflects `alg`'s digest length (16 Keyed-MD5, 20
    /// HMAC-SHA-1, 32 HMAC-SHA-256) until a caller overrides it; the offset,
    /// sequence, and reserved words default to zero.
    pub fn keyed_digest_with(alg: RipDigestAlgorithm, key_id: u8) -> Self {
        let mut header = RipKeyedDigestHeader::new();
        header.algorithm = alg;
        header.key_id.set_user(key_id);
        Self {
            auth_type: Field::user(RIP_AUTH_TYPE_KEYED_DIGEST),
            payload: RipAuthPayload::KeyedDigest(header),
        }
    }

    /// Effective authentication type wire code (caller-set or default).
    pub fn auth_type_value(&self) -> u16 {
        self.auth_type.value().copied().unwrap_or(RIP_AUTH_TYPE_SIMPLE)
    }

    /// Effective authentication type as a typed [`RipAuthType`] (caller-set or
    /// default).
    pub fn auth_type(&self) -> RipAuthType {
        rip_auth_type(self.auth_type_value())
    }

    /// Effective Authentication Data Length, in octets (RFC 4822 §3.1).
    ///
    /// For the keyed-digest form this is the configured length of the trailing
    /// digest (for example, 16 for Keyed-MD5 or 20 for HMAC-SHA-1); for the
    /// simple-password form, which carries no digest, this is `0`.
    pub fn auth_data_len(&self) -> u8 {
        match &self.payload {
            RipAuthPayload::KeyedDigest(header) => header.auth_data_len_value(),
            RipAuthPayload::SimplePassword(_) => 0,
        }
    }

    /// Render the keyed-digest leading authentication entry as a [`RipEntry`]
    /// (RFC 4822 §3.1, originally RFC 2082).
    ///
    /// The returned 20-octet entry carries, in wire order: the authentication
    /// marker AFI [`RIP_AFI_AUTH`] (0xFFFF) in its address-family octets, the
    /// keyed-message-digest authentication type
    /// [`RIP_AUTH_TYPE_KEYED_DIGEST`] (3) in its route-tag octets, then the
    /// 16-octet keyed-digest header laid into the entry's remaining slots: the
    /// offset to the trailing digest (u16), the Key Identifier (u8), the
    /// Authentication Data Length (u8), the 32-bit Sequence Number, and 8
    /// reserved octets (RFC 4822 §3.1's two reserved words).
    ///
    /// These follow the same slot-mapping technique as the simple-password form
    /// in [`RipAuth::as_entry`]: the header octets are laid verbatim, big-endian,
    /// into the address (offset/key id/auth data length), subnet-mask (sequence),
    /// next-hop (first reserved word), and metric (second reserved word) slots
    /// via the caller-set builders, so the existing [`RipEntry::encode`] emits
    /// them byte-for-byte. The digest itself is not part of this entry; it is
    /// framed separately by [`RipAuth::trailing_digest_block`]. For a
    /// simple-password payload this falls back to [`RipAuth::as_entry`].
    pub fn keyed_digest_header_entry(&self) -> RipEntry {
        let header = match &self.payload {
            RipAuthPayload::KeyedDigest(header) => header,
            RipAuthPayload::SimplePassword(_) => return self.as_entry(),
        };

        let offset = header.offset_value().to_be_bytes();
        let sequence = header.sequence_value();

        // Lay the 16-octet keyed-digest header into the entry's four 4-octet
        // slots that follow the AFI and type octets (RFC 4822 §3.1):
        //   address    (bytes 4..8):  offset hi, offset lo, key id, auth data len
        //   subnet mask(bytes 8..12): 32-bit sequence number
        //   next hop   (bytes 12..16): first reserved word (zero)
        //   metric     (bytes 16..20): second reserved word (zero)
        let address = Ipv4Addr::new(
            offset[0],
            offset[1],
            header.key_id_value(),
            header.auth_data_len_value(),
        );

        RipEntry::new()
            .address_family(RIP_AFI_AUTH)
            .route_tag(RIP_AUTH_TYPE_KEYED_DIGEST)
            .address(address)
            .subnet_mask(Ipv4Addr::from(sequence))
            .next_hop(Ipv4Addr::UNSPECIFIED)
            .metric(0)
    }

    /// Frame the trailing keyed-digest authentication block (RFC 4822 §3.1,
    /// originally RFC 2082).
    ///
    /// The digest is carried after the last route entry in a trailing
    /// authentication block introduced by the marker AFI [`RIP_AFI_AUTH`]
    /// (0xFFFF) and the trailer type `0x0001`, immediately followed by the raw
    /// `digest` octets. The caller supplies the digest verbatim here;
    /// auto-computation of the RFC 2082 Keyed-MD5 / RFC 4822 HMAC-SHA digest is
    /// added in later steps. The returned `Vec` is `4 + digest.len()` octets:
    /// two octets of AFI, two of trailer type, then the digest.
    pub fn trailing_digest_block(digest: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + digest.len());
        out.extend_from_slice(&RIP_AFI_AUTH.to_be_bytes());
        out.extend_from_slice(&RIP_AUTH_TRAILER_MARKER.to_be_bytes());
        out.extend_from_slice(digest);
        out
    }

    /// Render this authentication entry as a [`RipEntry`] (RFC 2453 §4.1).
    ///
    /// The returned entry carries the authentication marker AFI
    /// [`RIP_AFI_AUTH`] (0xFFFF) in its address-family octets and the
    /// authentication type in the route-tag octets, so it can sit in a [`Rip`]
    /// message's entry list.
    ///
    /// For the simple-password form (RFC 2453 §4.1) the 16-octet plaintext
    /// password is laid into the entry's remaining 16 octets — the address,
    /// subnet-mask, next-hop, and metric slots — so the entry's existing
    /// [`RipEntry::encode`] emits the password right-padded with zeros after the
    /// AFI and type octets. The remaining payload octets for the keyed-digest
    /// form are filled by the keyed-digest wire encoding added in a later step.
    ///
    /// [`Rip`]: super::Rip
    pub fn as_entry(&self) -> RipEntry {
        let entry = RipEntry::new()
            .address_family(RIP_AFI_AUTH)
            .route_tag(rip_auth_type_code(self.auth_type()));

        match &self.payload {
            RipAuthPayload::SimplePassword(password) => {
                // The 16-octet password occupies the four 4-octet slots that
                // follow the AFI and type octets: address (0..4), subnet mask
                // (4..8), next hop (8..12), metric (12..16). Lay the octets in
                // verbatim, big-endian, via the caller-set builders so the
                // entry re-encodes byte-for-byte (RFC 2453 §4.1).
                let address =
                    Ipv4Addr::new(password[0], password[1], password[2], password[3]);
                let subnet_mask =
                    Ipv4Addr::new(password[4], password[5], password[6], password[7]);
                let next_hop =
                    Ipv4Addr::new(password[8], password[9], password[10], password[11]);
                let metric = u32::from_be_bytes([
                    password[12],
                    password[13],
                    password[14],
                    password[15],
                ]);
                entry
                    .address(address)
                    .subnet_mask(subnet_mask)
                    .next_hop(next_hop)
                    .metric(metric)
            }
            RipAuthPayload::KeyedDigest(_) => entry,
        }
    }
}

/// Decode a RIPv2 authentication entry into a [`RipAuth`] (RFC 2453 §4.1).
///
/// Returns `Some` only when `entry` is an authentication marker entry (AFI
/// [`RIP_AFI_AUTH`], 0xFFFF) whose authentication type — carried in the
/// route-tag octets — is the simple-password type
/// [`RIP_AUTH_TYPE_SIMPLE`] (2). The 16-octet plaintext password is
/// reconstructed verbatim from the entry's address, subnet-mask, next-hop, and
/// metric slots, the inverse of [`RipAuth::as_entry`]. Any other AFI or
/// authentication type yields `None` (keyed-digest decode lands in a later
/// step).
pub fn decode_auth_entry(entry: &RipEntry) -> Option<RipAuth> {
    if !is_rip_auth_marker(entry.address_family_value()) {
        return None;
    }
    if entry.route_tag_value() != RIP_AUTH_TYPE_SIMPLE {
        return None;
    }

    let mut password = [0u8; RIP_SIMPLE_PASSWORD_LEN];
    password[0..4].copy_from_slice(&entry.address_value().octets());
    password[4..8].copy_from_slice(&entry.subnet_mask_value().octets());
    password[8..12].copy_from_slice(&entry.next_hop_value().octets());
    password[12..16].copy_from_slice(&entry.metric_value().to_be_bytes());

    Some(RipAuth::simple_password(&password))
}

/// Length, in octets, of an RFC 2082 Keyed-MD5 digest.
pub const RIP_MD5_DIGEST_LEN: usize = 16;

/// Compute the RFC 2082 §3.2.1 Keyed-MD5 authentication digest.
///
/// `message_with_key_region` is the complete RIP message to authenticate —
/// header, route entries, the leading keyed-digest authentication entry, and the
/// 4-octet trailing authentication block introduction (AFI 0xFFFF, trailer type
/// 0x0001) — followed by a trailing 16-octet region reserved for the digest.
/// Per RFC 2082 §3.2.1, that trailing region is filled with the authentication
/// `key` (right-padded with zeros, or truncated, to 16 octets) before MD5 is
/// computed over the whole buffer; the resulting 16-octet digest then replaces
/// the key region on the wire.
///
/// The returned `[u8; 16]` is the digest to place in the trailing block via
/// [`RipAuth::trailing_digest_block`]. The input is not mutated; the key is laid
/// into a working copy. If `message_with_key_region` is shorter than 16 octets
/// the whole buffer is treated as the key region.
pub(crate) fn compute_md5_digest(
    message_with_key_region: &[u8],
    key: &[u8],
) -> [u8; RIP_MD5_DIGEST_LEN] {
    // RFC 2082 §3.2.1: the trailing 16-octet digest region is overwritten with
    // the authentication key (zero-padded / truncated to 16 octets) before
    // hashing.
    let mut buf = message_with_key_region.to_vec();
    let region_start = buf.len().saturating_sub(RIP_MD5_DIGEST_LEN);
    let region = &mut buf[region_start..];
    let key_take = key.len().min(region.len());
    for byte in region.iter_mut() {
        *byte = 0;
    }
    region[..key_take].copy_from_slice(&key[..key_take]);

    let mut hasher = Md5::new();
    hasher.update(&buf);
    let out = hasher.finalize();
    let mut digest = [0u8; RIP_MD5_DIGEST_LEN];
    digest.copy_from_slice(&out);
    digest
}

/// Compute the RFC 4822 §3 cryptographic authentication digest for `alg` over
/// `message` keyed by `key`.
///
/// RFC 4822 §3 replaces the RFC 2082 Keyed-MD5 construction with the standard
/// HMAC of the selected SHA algorithm (HMAC-SHA-1, HMAC-SHA-256, …) computed
/// over the full RIP message (header, route entries, the leading keyed-digest
/// authentication entry, and the 4-octet trailing authentication block
/// introduction), returning the full-length MAC. The returned `Vec` is the
/// digest to place in the trailing block via [`RipAuth::trailing_digest_block`];
/// its length is `alg.digest_len()` (20 for HMAC-SHA-1, 32 for HMAC-SHA-256).
///
/// For [`RipDigestAlgorithm::KeyedMd5`] this delegates to [`compute_md5_digest`]
/// over a `message` that already carries the 16-octet trailing key region, so a
/// single call site can compute either family from the same algorithm selector.
pub(crate) fn compute_hmac_digest(
    alg: RipDigestAlgorithm,
    message: &[u8],
    key: &[u8],
) -> Vec<u8> {
    match alg {
        RipDigestAlgorithm::KeyedMd5 => compute_md5_digest(message, key).to_vec(),
        RipDigestAlgorithm::HmacSha1 => {
            // hmac 0.12 / sha1 0.10: keyed HMAC-SHA-1 (RFC 2104 / RFC 4822 §3).
            // `new_from_slice` accepts any key length, so this never fails.
            let mut mac = Hmac::<Sha1>::new_from_slice(key)
                .expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        RipDigestAlgorithm::HmacSha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key)
                .expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// Outcome of verifying a RIPv2 authenticated message against a key
/// (RFC 2453 §4.1, RFC 4822 §4).
///
/// The variants distinguish the two authentication forms and, within each, a
/// match from a mismatch. `Unauthenticated` is returned when the message's
/// leading entry is not a RIPv2 authentication entry (its Address Family
/// Identifier is not the AFI 0xFFFF marker), so there is nothing to verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RipAuthVerification {
    /// The leading entry is not an authentication entry (AFI != 0xFFFF), so the
    /// message carries no authentication to verify.
    Unauthenticated,
    /// Simple-password authentication (RFC 2453 §4.1) whose 16-octet password
    /// matches the supplied key (right-padded with zeros to 16 octets).
    SimplePasswordOk,
    /// Simple-password authentication whose 16-octet password does not match the
    /// supplied key.
    SimplePasswordMismatch,
    /// Keyed message-digest authentication (RFC 2082 / RFC 4822 §3) whose
    /// recomputed digest matches the trailing digest on the wire.
    DigestOk,
    /// Keyed message-digest authentication whose recomputed digest does not match
    /// the trailing digest on the wire.
    DigestMismatch,
}

/// Verify a RIPv2 authenticated message against a key (RFC 2453 §4.1,
/// RFC 4822 §4).
///
/// `message_bytes` is the complete RIP message as it appears on the wire: the
/// 4-octet header, the leading authentication entry, any route entries, and —
/// for keyed message digest — the trailing authentication block (AFI 0xFFFF,
/// trailer type 0x0001, then the digest octets). `key` is the authentication
/// key shared with the sender.
///
/// The function inspects the leading entry that follows the header:
///
/// - If its Address Family Identifier is not the AFI 0xFFFF authentication
///   marker, the message is not authenticated and [`RipAuthVerification::
///   Unauthenticated`] is returned.
/// - For Authentication Type 2 (simple password, RFC 2453 §4.1) the 16-octet
///   password carried in the entry is compared, in constant time, to `key`
///   right-padded with zeros (or truncated) to 16 octets, yielding
///   [`RipAuthVerification::SimplePasswordOk`] or
///   [`RipAuthVerification::SimplePasswordMismatch`].
/// - For Authentication Type 3 (keyed message digest, RFC 2082 / RFC 4822 §3)
///   the digest is recomputed over the message with the trailing digest region
///   replaced by the key, exactly as on `compile()`, using the algorithm implied
///   by the Authentication Data Length carried in the header entry (16 octets
///   Keyed-MD5, 20 HMAC-SHA-1, 32 HMAC-SHA-256). The recomputed digest is
///   compared, in constant time, to the trailing digest on the wire, yielding
///   [`RipAuthVerification::DigestOk`] or [`RipAuthVerification::DigestMismatch`].
///
/// A truncated or structurally invalid message (too short to hold the header and
/// a leading authentication entry, an unrecognized authentication type, or a
/// trailing digest block that does not fit) verifies as a mismatch for its
/// implied form rather than panicking; an entirely absent authentication entry
/// reads as [`RipAuthVerification::Unauthenticated`].
pub fn verify(message_bytes: &[u8], key: &[u8]) -> RipAuthVerification {
    // The leading authentication entry follows the 4-octet header. Without a
    // full header plus one 20-octet entry there is nothing to inspect.
    if message_bytes.len() < RIP_HEADER_LEN + RIP_ENTRY_LEN {
        return RipAuthVerification::Unauthenticated;
    }
    let entry = &message_bytes[RIP_HEADER_LEN..RIP_HEADER_LEN + RIP_ENTRY_LEN];

    // AFI (entry bytes 0..2) must be the 0xFFFF authentication marker.
    let afi = u16::from_be_bytes([entry[0], entry[1]]);
    if !is_rip_auth_marker(afi) {
        return RipAuthVerification::Unauthenticated;
    }

    // Authentication Type rides in the entry's route-tag octets (bytes 2..4).
    let auth_type = u16::from_be_bytes([entry[2], entry[3]]);
    match rip_auth_type(auth_type) {
        RipAuthType::SimplePassword => {
            // The 16-octet plaintext password occupies the entry's remaining
            // octets (bytes 4..20). Compare it, in constant time, to the key
            // right-padded with zeros / truncated to 16 octets (RFC 2453 §4.1).
            let mut expected = [0u8; RIP_SIMPLE_PASSWORD_LEN];
            let take = key.len().min(RIP_SIMPLE_PASSWORD_LEN);
            expected[..take].copy_from_slice(&key[..take]);
            let matches: bool = entry[4..RIP_ENTRY_LEN].ct_eq(&expected).into();
            if matches {
                RipAuthVerification::SimplePasswordOk
            } else {
                RipAuthVerification::SimplePasswordMismatch
            }
        }
        RipAuthType::KeyedMessageDigest => {
            // The keyed-digest header entry carries the Authentication Data
            // Length (entry byte 7), which fixes the trailing digest length and,
            // here, the algorithm (RFC 2082 / RFC 4822 §3).
            let auth_data_len = entry[7] as usize;
            let alg = match auth_data_len {
                20 => RipDigestAlgorithm::HmacSha1,
                32 => RipDigestAlgorithm::HmacSha256,
                // Keyed-MD5 is the RFC 2082 default; any other length falls back
                // to its 16-octet construction.
                _ => RipDigestAlgorithm::KeyedMd5,
            };

            // The trailing digest sits at the tail of the message after the
            // 4-octet trailing-block introduction (AFI 0xFFFF + trailer 0x0001).
            // It must fit; otherwise the message is malformed and cannot match.
            if message_bytes.len() < auth_data_len {
                return RipAuthVerification::DigestMismatch;
            }
            let digest_start = message_bytes.len() - auth_data_len;
            let transmitted = &message_bytes[digest_start..];

            // Recompute the digest the same way `compile()` does: the trailing
            // digest region is replaced by the key before hashing (RFC 2082
            // §3.2.1) for Keyed-MD5, or HMAC keyed by `key` over the message up
            // to the digest region (RFC 4822 §3) for the HMAC-SHA family.
            let recomputed = match alg {
                RipDigestAlgorithm::KeyedMd5 => {
                    compute_md5_digest(message_bytes, key).to_vec()
                }
                RipDigestAlgorithm::HmacSha1 | RipDigestAlgorithm::HmacSha256 => {
                    compute_hmac_digest(alg, &message_bytes[..digest_start], key)
                }
            };

            let matches: bool = recomputed.as_slice().ct_eq(transmitted).into();
            if matches {
                RipAuthVerification::DigestOk
            } else {
                RipAuthVerification::DigestMismatch
            }
        }
        RipAuthType::Other(_) => RipAuthVerification::DigestMismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rip_auth_builders_set_type() {
        // Simple password (RFC 2453 §4.1) is authentication type 2.
        let simple = RipAuth::simple_password(b"secret");
        assert_eq!(simple.auth_type_value(), RIP_AUTH_TYPE_SIMPLE);
        assert_eq!(simple.auth_type_value(), 2);
        assert_eq!(simple.auth_type(), RipAuthType::SimplePassword);
        assert!(matches!(
            simple.payload,
            RipAuthPayload::SimplePassword(_)
        ));

        // Keyed message digest (RFC 2082 / RFC 4822 §3) is authentication type 3.
        let keyed = RipAuth::keyed_digest(1, 16);
        assert_eq!(keyed.auth_type_value(), RIP_AUTH_TYPE_KEYED_DIGEST);
        assert_eq!(keyed.auth_type_value(), 3);
        assert_eq!(keyed.auth_type(), RipAuthType::KeyedMessageDigest);
        match &keyed.payload {
            RipAuthPayload::KeyedDigest(header) => {
                assert_eq!(header.key_id_value(), 1);
                assert_eq!(header.auth_data_len_value(), 16);
            }
            other => panic!("expected KeyedDigest payload, got {other:?}"),
        }

        // as_entry() renders the auth marker AFI 0xFFFF and carries the type in
        // the route-tag octets (RFC 2453 §4.1).
        let simple_entry = simple.as_entry();
        assert_eq!(simple_entry.address_family_value(), RIP_AFI_AUTH);
        assert_eq!(simple_entry.address_family_value(), 0xFFFF);
        assert_eq!(simple_entry.route_tag_value(), RIP_AUTH_TYPE_SIMPLE);
        assert!(simple_entry.is_auth_marker());

        let keyed_entry = keyed.as_entry();
        assert_eq!(keyed_entry.address_family_value(), RIP_AFI_AUTH);
        assert_eq!(keyed_entry.route_tag_value(), RIP_AUTH_TYPE_KEYED_DIGEST);
        assert!(keyed_entry.is_auth_marker());
    }

    #[test]
    fn simple_password_pads_and_truncates_to_16_octets() {
        // A short password is right-padded with zeros.
        let short = RipAuth::simple_password(b"pw");
        match short.payload {
            RipAuthPayload::SimplePassword(bytes) => {
                assert_eq!(&bytes[..2], b"pw");
                assert!(bytes[2..].iter().all(|&b| b == 0));
            }
            other => panic!("expected SimplePassword payload, got {other:?}"),
        }

        // An over-long password is truncated to 16 octets.
        let long = RipAuth::simple_password(b"0123456789ABCDEF_overflow");
        match long.payload {
            RipAuthPayload::SimplePassword(bytes) => {
                assert_eq!(&bytes, b"0123456789ABCDEF");
            }
            other => panic!("expected SimplePassword payload, got {other:?}"),
        }
    }

    #[test]
    fn rip_auth_simple_password_roundtrips() {
        // RFC 2453 §4.1: a simple-password auth entry is AFI 0xFFFF, type 2,
        // then 16 octets of plaintext password right-padded with zeros.
        let auth = RipAuth::simple_password(b"secret");
        let entry = auth.as_entry();

        let mut bytes = Vec::new();
        entry.encode(&mut bytes);
        assert_eq!(bytes.len(), 20);

        // AFI 0xFFFF (bytes 0..2) and Authentication Type 2 (bytes 2..4).
        assert_eq!(&bytes[0..2], &[0xFF, 0xFF]);
        assert_eq!(&bytes[2..4], &[0x00, 0x02]);

        // The remaining 16 octets are "secret" followed by zero padding.
        let mut expected_password = [0u8; RIP_SIMPLE_PASSWORD_LEN];
        expected_password[..b"secret".len()].copy_from_slice(b"secret");
        assert_eq!(&bytes[4..20], &expected_password);

        // decode_auth_entry recovers the password from the rendered entry.
        let recovered = decode_auth_entry(&entry).expect("simple-password auth entry decodes");
        assert_eq!(recovered.auth_type_value(), RIP_AUTH_TYPE_SIMPLE);
        match recovered.payload {
            RipAuthPayload::SimplePassword(bytes) => {
                assert_eq!(&bytes, &expected_password);
            }
            other => panic!("expected SimplePassword payload, got {other:?}"),
        }
    }

    #[test]
    fn rip_auth_keyed_digest_layout() {
        // RFC 4822 §3.1 (originally RFC 2082): the keyed-digest leading entry is
        // AFI 0xFFFF, type 3, then offset (u16), key id (u8), auth data length
        // (u8), sequence (u32), and two reserved words (8 octets). The digest
        // itself follows the last route entry as a trailing block introduced by
        // AFI 0xFFFF and the 0x0001 trailer marker.
        let mut auth = RipAuth::keyed_digest(7, 16);
        match &mut auth.payload {
            RipAuthPayload::KeyedDigest(header) => {
                header.sequence.set_user(42);
            }
            other => panic!("expected KeyedDigest payload, got {other:?}"),
        }

        assert_eq!(auth.auth_data_len(), 16);

        // The leading header entry encodes to 20 octets in RFC 4822 §3.1 order.
        let header_entry = auth.keyed_digest_header_entry();
        let mut header_bytes = Vec::new();
        header_entry.encode(&mut header_bytes);
        assert_eq!(header_bytes.len(), RIP_ENTRY_LEN);

        // AFI 0xFFFF (bytes 0..2) and Authentication Type 3 (bytes 2..4).
        assert_eq!(&header_bytes[0..2], &[0xFF, 0xFF]);
        assert_eq!(&header_bytes[2..4], &[0x00, 0x03]);

        // Offset (bytes 4..6), Key ID (byte 6), Auth Data Length (byte 7).
        assert_eq!(&header_bytes[4..6], &[0x00, 0x00]);
        assert_eq!(header_bytes[6], 0x07);
        assert_eq!(header_bytes[7], 16);

        // Sequence number occupies bytes 8..12 (RFC 4822 §3.1).
        assert_eq!(&header_bytes[8..12], &42u32.to_be_bytes());

        // The two reserved words (bytes 12..20) are zero.
        assert!(header_bytes[12..20].iter().all(|&b| b == 0));

        // The trailing digest block is AFI 0xFFFF, trailer marker 0x0001, then
        // the 16 supplied digest octets.
        let digest = [0xAB_u8; 16];
        let block = RipAuth::trailing_digest_block(&digest);
        assert_eq!(block.len(), 4 + digest.len());
        assert_eq!(&block[0..2], &[0xFF, 0xFF]);
        assert_eq!(&block[2..4], &[0x00, 0x01]);
        assert_eq!(&block[4..], &digest);
    }

    #[test]
    fn rip_auth_md5_known_vector() {
        // RFC 2082 §3.2.1 Keyed-MD5: the trailing 16-octet digest region is
        // filled with the authentication key (zero-padded to 16 octets) and MD5
        // is computed over the whole message. Fixed message: a 4-octet RIP
        // header (command 2, version 2, reserved 0) followed by the 16-octet
        // digest region. The expected digest was computed once with this exact
        // construction and pinned here as a self-consistent golden constant.
        let message_with_key_region: Vec<u8> = {
            let mut m = vec![0x02, 0x02, 0x00, 0x00];
            m.extend_from_slice(&[0u8; RIP_MD5_DIGEST_LEN]);
            m
        };
        let key = b"rip-md5-key";

        // Golden digest: MD5 over the header plus the key (zero-padded to 16
        // octets) in the trailing region.
        let expected: [u8; RIP_MD5_DIGEST_LEN] = [
            0x81, 0xe1, 0xbb, 0x86, 0xc7, 0x27, 0x6e, 0x81, 0xfa, 0x30, 0xdf, 0x78, 0x48, 0xe0,
            0x00, 0x97,
        ];

        let digest = compute_md5_digest(&message_with_key_region, key);
        assert_eq!(digest, expected);

        // The construction is deterministic.
        assert_eq!(
            compute_md5_digest(&message_with_key_region, key),
            expected
        );

        // A different key yields a different digest.
        assert_ne!(
            compute_md5_digest(&message_with_key_region, b"other-key"),
            expected
        );
    }

    #[test]
    fn rip_auth_hmac_sha_lengths() {
        // RFC 4822 §3: HMAC-SHA digests are the full MAC length of the chosen
        // hash — 20 octets for HMAC-SHA-1, 32 for HMAC-SHA-256. The selected
        // algorithm fixes both the trailing digest length and the auth-data
        // length reported by the keyed-digest header.
        let message = b"\x02\x02\x00\x00rip-hmac-sample-message";
        let key = b"rip-hmac-key";

        let sha1 = compute_hmac_digest(RipDigestAlgorithm::HmacSha1, message, key);
        assert_eq!(sha1.len(), 20);
        assert_eq!(sha1.len(), RipDigestAlgorithm::HmacSha1.digest_len());

        let sha256 = compute_hmac_digest(RipDigestAlgorithm::HmacSha256, message, key);
        assert_eq!(sha256.len(), 32);
        assert_eq!(sha256.len(), RipDigestAlgorithm::HmacSha256.digest_len());

        // Keyed-MD5 stays 16 octets via the same selector.
        let md5 = compute_hmac_digest(RipDigestAlgorithm::KeyedMd5, message, key);
        assert_eq!(md5.len(), 16);
        assert_eq!(md5.len(), RipDigestAlgorithm::KeyedMd5.digest_len());

        // keyed_digest_with leaves the auth-data length unset so it reflects the
        // selected algorithm's digest length until a caller overrides it.
        let auth = RipAuth::keyed_digest_with(RipDigestAlgorithm::HmacSha1, 5);
        assert_eq!(auth.auth_data_len(), 20);
        match &auth.payload {
            RipAuthPayload::KeyedDigest(header) => {
                assert_eq!(header.algorithm, RipDigestAlgorithm::HmacSha1);
                assert_eq!(header.key_id_value(), 5);
            }
            other => panic!("expected KeyedDigest payload, got {other:?}"),
        }

        let auth256 = RipAuth::keyed_digest_with(RipDigestAlgorithm::HmacSha256, 9);
        assert_eq!(auth256.auth_data_len(), 32);

        // The default keyed-digest builder stays Keyed-MD5 (16 octets).
        let md5_auth = RipAuth::keyed_digest(1, 16);
        assert_eq!(md5_auth.auth_data_len(), 16);
        match &md5_auth.payload {
            RipAuthPayload::KeyedDigest(header) => {
                assert_eq!(header.algorithm, RipDigestAlgorithm::KeyedMd5);
            }
            other => panic!("expected KeyedDigest payload, got {other:?}"),
        }
    }

    #[test]
    fn rip_auth_hmac_sha1_known_vector() {
        // RFC 4822 §3 HMAC-SHA-1: a deterministic, self-consistent golden vector.
        // Fixed message: a 4-octet RIP header (command 2, version 2, reserved 0)
        // followed by a short ASCII tail; fixed key. The expected MAC was
        // computed once with this exact construction and pinned here.
        let message = b"\x02\x02\x00\x00rip-hmac-sha1-known-vector";
        let key = b"rip-sha1-key";

        let expected: [u8; 20] = [
            0x05, 0x36, 0x0e, 0x18, 0xb1, 0x19, 0x7f, 0xbe, 0xa6, 0x00, 0x00, 0xd1, 0x66, 0x52,
            0x6c, 0x8d, 0xd7, 0x77, 0x15, 0x8d,
        ];

        let digest = compute_hmac_digest(RipDigestAlgorithm::HmacSha1, message, key);
        assert_eq!(digest.len(), 20);
        assert_eq!(digest.as_slice(), &expected);

        // The construction is deterministic.
        assert_eq!(
            compute_hmac_digest(RipDigestAlgorithm::HmacSha1, message, key),
            digest
        );

        // A different key yields a different MAC.
        assert_ne!(
            compute_hmac_digest(RipDigestAlgorithm::HmacSha1, message, b"other-key"),
            digest
        );
    }

    #[test]
    fn rip_auth_verify_simple_password() {
        // RFC 2453 §4.1: a simple-password authenticated message is the 4-octet
        // header followed by the AFI 0xFFFF / type 2 authentication entry whose
        // remaining 16 octets carry the password. Build that message and verify it.
        let key = b"rip-pass";
        let auth = RipAuth::simple_password(key);

        let mut message = vec![
            crate::protocols::rip::constants::RIP_COMMAND_RESPONSE,
            crate::protocols::rip::constants::RIP_VERSION_2,
            0x00,
            0x00,
        ];
        auth.as_entry().encode(&mut message);

        // The correct key (padded to 16 octets) verifies as a match.
        assert_eq!(verify(&message, key), RipAuthVerification::SimplePasswordOk);

        // A wrong key is reported as a mismatch, not a panic.
        assert_eq!(
            verify(&message, b"wrong-pass"),
            RipAuthVerification::SimplePasswordMismatch
        );

        // A message whose leading entry is an ordinary IP route (AFI 2) is not
        // authenticated, so there is nothing to verify.
        let mut unauthenticated = vec![
            crate::protocols::rip::constants::RIP_COMMAND_RESPONSE,
            crate::protocols::rip::constants::RIP_VERSION_2,
            0x00,
            0x00,
        ];
        RipEntry::ipv2_route(
            std::net::Ipv4Addr::new(192, 0, 2, 0),
            std::net::Ipv4Addr::new(255, 255, 255, 0),
            1,
        )
        .encode(&mut unauthenticated);
        assert_eq!(
            verify(&unauthenticated, key),
            RipAuthVerification::Unauthenticated
        );
    }

    #[test]
    fn rip_auth_verify_keyed_md5() {
        // RFC 2082 §3.2.1 Keyed-MD5: build the authenticated message directly
        // from the auth layout helpers (the Rip-compile auto-fill integration is
        // a later step). The on-wire message is:
        //   header(4) | keyed-digest header entry(20) | route entry(20)
        //            | trailing block intro(4: AFI 0xFFFF, trailer 0x0001) | digest(16)
        // The digest is MD5 over the same message with the trailing 16-octet
        // region replaced by the key (zero-padded to 16 octets).
        let key = b"rip-md5-key";
        let auth = RipAuth::keyed_digest(1, RIP_MD5_DIGEST_LEN as u8);

        // Header (Response, v2, reserved 0) + leading keyed-digest header entry.
        let mut message: Vec<u8> = vec![
            crate::protocols::rip::constants::RIP_COMMAND_RESPONSE,
            crate::protocols::rip::constants::RIP_VERSION_2,
            0x00,
            0x00,
        ];
        auth.keyed_digest_header_entry().encode(&mut message);

        // One ordinary RIPv2 route entry.
        RipEntry::ipv2_route(
            std::net::Ipv4Addr::new(192, 0, 2, 0),
            std::net::Ipv4Addr::new(255, 255, 255, 0),
            1,
        )
        .encode(&mut message);

        // Trailing authentication block introduction (AFI 0xFFFF, trailer 0x0001),
        // then the 16-octet digest region.
        message.extend_from_slice(&RIP_AFI_AUTH.to_be_bytes());
        message.extend_from_slice(&RIP_AUTH_TRAILER_MARKER.to_be_bytes());

        // Build the message-with-key-region (the digest region starts as zeros)
        // and compute the RFC 2082 Keyed-MD5 digest over it.
        let mut message_with_key_region = message.clone();
        message_with_key_region.extend_from_slice(&[0u8; RIP_MD5_DIGEST_LEN]);
        let digest = compute_md5_digest(&message_with_key_region, key);

        // Place the computed digest on the wire after the trailing block intro.
        message.extend_from_slice(&digest);

        // The correct key recomputes the same digest and verifies as a match.
        assert_eq!(verify(&message, key), RipAuthVerification::DigestOk);

        // A wrong key recomputes a different digest and is a mismatch.
        assert_eq!(
            verify(&message, b"other-key"),
            RipAuthVerification::DigestMismatch
        );
    }
}
