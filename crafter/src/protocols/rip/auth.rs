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

use crate::field::Field;

use super::constants::RIP_AFI_AUTH;
use super::entry::RipEntry;
use super::registry::{
    rip_auth_type, rip_auth_type_code, RipAuthType, RIP_AUTH_TYPE_KEYED_DIGEST,
    RIP_AUTH_TYPE_SIMPLE,
};

/// Simple-password authentication carries up to 16 octets of plaintext password.
/// RFC 2453 §4.1.
pub const RIP_SIMPLE_PASSWORD_LEN: usize = 16;

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
}

impl RipKeyedDigestHeader {
    /// Create a keyed-digest header with library defaults (all zero), none of
    /// which are marked caller-set.
    pub fn new() -> Self {
        Self {
            offset: Field::defaulted(0),
            key_id: Field::defaulted(0),
            auth_data_len: Field::defaulted(0),
            sequence: Field::defaulted(0),
            reserved1: Field::defaulted(0),
            reserved2: Field::defaulted(0),
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

    /// Effective Authentication Data Length (caller-set or default).
    pub fn auth_data_len_value(&self) -> u8 {
        self.auth_data_len.value().copied().unwrap_or(0)
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

    /// Effective authentication type wire code (caller-set or default).
    pub fn auth_type_value(&self) -> u16 {
        self.auth_type.value().copied().unwrap_or(RIP_AUTH_TYPE_SIMPLE)
    }

    /// Effective authentication type as a typed [`RipAuthType`] (caller-set or
    /// default).
    pub fn auth_type(&self) -> RipAuthType {
        rip_auth_type(self.auth_type_value())
    }

    /// Render this authentication entry as a [`RipEntry`] (RFC 2453 §4.1).
    ///
    /// The returned entry carries the authentication marker AFI
    /// [`RIP_AFI_AUTH`] (0xFFFF) in its address-family octets and the
    /// authentication type in the route-tag octets, so it can sit in a [`Rip`]
    /// message's entry list. The remaining payload octets (the password or the
    /// keyed-digest header) are filled by the full simple-password and
    /// keyed-digest wire encodings added in later steps.
    ///
    /// [`Rip`]: super::Rip
    pub fn as_entry(&self) -> RipEntry {
        RipEntry::new()
            .address_family(RIP_AFI_AUTH)
            .route_tag(rip_auth_type_code(self.auth_type()))
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
}
