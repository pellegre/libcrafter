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
//! Cryptographic authentication (AuType 2, RFC 2328 §D.3) instead uses the two
//! authentication octets as a Key ID / Auth Data Length / Crypto Sequence Number
//! triple and appends a message-digest trailer; it is handled in a later block.
//!
//! The [`Ospfv2`](crate::protocols::ospf::Ospfv2) layer already exposes the raw
//! [`autype`](crate::protocols::ospf::Ospfv2::autype) and
//! [`authentication`](crate::protocols::ospf::Ospfv2::authentication) builders
//! (which honor caller overrides, including deliberately malformed values). This
//! module adds the ergonomic, correctly-padded
//! [`null_auth`](crate::protocols::ospf::Ospfv2::null_auth) and
//! [`simple_password`](crate::protocols::ospf::Ospfv2::simple_password) builders
//! on top of them; the header checksum auto-fill already excludes the 8-octet
//! authentication field, so setting an authentication value never changes the
//! computed checksum.

use crate::protocols::ospf::constants::OSPF_AUTH_LEN;

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
}
