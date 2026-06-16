//! Source-backed RIP command-codepoint metadata.
//!
//! Source: RFC 1058 §3.1 (1 Request, 2 Response) and its appendix
//! (3 Traceon, 4 Traceoff, 5 reserved for Sun Microsystems), reconciled with
//! RFC 2091 §3.2 (9 Update Request, 10 Update Response, 11 Update Acknowledge)
//! for demand/triggered RIP. Each entry records a short name and an assignment
//! status so decoders can classify every command value without panicking and
//! preserve unknown commands as raw/typed data instead of pretending every code
//! has a single authoritative interpretation.
//!
//! This table is intentionally metadata only: it names codepoints. The
//! wire-format codec for RIP messages lives elsewhere in this module.

use super::constants::{RIP_AFI_AUTH, RIP_AFI_IP};

/// Assignment status for a RIP command codepoint.
///
/// Source: RFC 1058 §3.1 / appendix and RFC 2091 §3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RipCommandStatus {
    /// Assigned to a single command in active use (RFC 1058 / RFC 2091).
    Assigned,
    /// Defined historically but no longer used (RFC 1058 Traceon/Traceoff).
    Obsolete,
    /// Reserved (Sun Microsystems code 5; RFC 2091 historical codes 6-8).
    Reserved,
    /// Not assigned by any governing RFC.
    Unassigned,
}

/// One source-backed RIP command-codepoint registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RipCommandMeta {
    /// Wire codepoint.
    pub code: u8,
    /// Short name, or a status label for unassigned codes.
    pub name: &'static str,
    /// Assignment status.
    pub status: RipCommandStatus,
}

/// Return the registry metadata for a RIP command code.
///
/// Unknown codes fall through to an `Unassigned` entry named "Unassigned" so
/// callers always receive a non-empty diagnostic without panicking.
///
/// Source: RFC 1058 §3.1 / appendix and RFC 2091 §3.2.
pub const fn rip_command_meta(code: u8) -> RipCommandMeta {
    let (name, status) = match code {
        1 => ("Request", RipCommandStatus::Assigned),
        2 => ("Response", RipCommandStatus::Assigned),
        3 => ("Traceon", RipCommandStatus::Obsolete),
        4 => ("Traceoff", RipCommandStatus::Obsolete),
        5 => ("Sun reserved", RipCommandStatus::Reserved),
        6 => ("Triggered Request", RipCommandStatus::Reserved),
        7 => ("Triggered Response", RipCommandStatus::Reserved),
        8 => ("Triggered Acknowledgement", RipCommandStatus::Reserved),
        9 => ("Update Request", RipCommandStatus::Assigned),
        10 => ("Update Response", RipCommandStatus::Assigned),
        11 => ("Update Acknowledge", RipCommandStatus::Assigned),
        _ => ("Unassigned", RipCommandStatus::Unassigned),
    };
    RipCommandMeta { code, name, status }
}

/// Short name for a RIP command code, when it is not unassigned.
///
/// Returns `None` for codes the governing RFCs do not name.
pub const fn rip_command_name(code: u8) -> Option<&'static str> {
    let meta = rip_command_meta(code);
    match meta.status {
        RipCommandStatus::Unassigned => None,
        _ => Some(meta.name),
    }
}

// ---------------------------------------------------------------------------
// Address Family Identifier classification
// (IANA Address Family Numbers; RFC 2453 §4.1)
// ---------------------------------------------------------------------------

/// Classification of the 2-octet Address Family Identifier (AFI) that begins a
/// RIP route entry.
///
/// RIP routes only the IP family; the 0xFFFF marker introduces a RIPv2
/// authentication entry. Every other AFI is preserved as `Other(afi)` rather
/// than rejected, mirroring the command registry's preserve-don't-reject
/// policy so decoders never panic on or silently rewrite an unknown family.
///
/// Source: IANA Address Family Numbers (IP = 2) and RFC 2453 §4.1 (0xFFFF
/// authentication marker).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RipAddressFamily {
    /// IP (IPv4) — the only routeable family RIP carries.
    /// Source: IANA Address Family Numbers (IP = 2).
    Ip,
    /// RIPv2 authentication-entry marker (AFI 0xFFFF).
    /// Source: RFC 2453 §4.1.
    AuthMarker,
    /// Any other Address Family Identifier, preserved verbatim.
    Other(u16),
}

/// Classify a RIP route-entry Address Family Identifier.
///
/// Maps `2 => Ip` (IANA Address Family Numbers, IP = 2),
/// `0xFFFF => AuthMarker` (RFC 2453 §4.1), and every other value to
/// `Other(afi)` so unknown families round-trip instead of being rejected.
pub const fn rip_address_family(afi: u16) -> RipAddressFamily {
    match afi {
        RIP_AFI_IP => RipAddressFamily::Ip,
        RIP_AFI_AUTH => RipAddressFamily::AuthMarker,
        other => RipAddressFamily::Other(other),
    }
}

/// Whether an Address Family Identifier marks a RIPv2 authentication entry.
///
/// Returns `true` for AFI 0xFFFF (RFC 2453 §4.1), `false` otherwise.
pub const fn is_rip_auth_marker(afi: u16) -> bool {
    afi == RIP_AFI_AUTH
}

// ---------------------------------------------------------------------------
// Authentication Type classification
// (RFC 2453 §4.1 simple password; RFC 2082 / RFC 4822 §3 keyed message digest)
// ---------------------------------------------------------------------------

/// RIPv2 authentication-entry Authentication Type, the 2-octet field that
/// follows the AFI 0xFFFF marker (RFC 2453 §4.1).
///
/// Type 2 is simple password authentication (RFC 2453 §4.1); type 3 is keyed
/// message-digest authentication (RFC 2082, obsoleted by RFC 4822 §3). Type 1
/// historically marked the entry as carrying an IP route and is kept reserved,
/// so it (and every other value) is preserved as `Other(value)` rather than
/// rejected, mirroring the command/address-family registries' preserve-don't-
/// reject policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RipAuthType {
    /// Simple password authentication (RFC 2453 §4.1).
    SimplePassword,
    /// Keyed message-digest authentication (RFC 2082 / RFC 4822 §3).
    KeyedMessageDigest,
    /// Any other Authentication Type, preserved verbatim.
    Other(u16),
}

/// Authentication Type 2: simple password (RFC 2453 §4.1).
pub const RIP_AUTH_TYPE_SIMPLE: u16 = 2;
/// Authentication Type 3: keyed message digest (RFC 2082 / RFC 4822 §3).
pub const RIP_AUTH_TYPE_KEYED_DIGEST: u16 = 3;

/// Classify a RIPv2 authentication-entry Authentication Type.
///
/// Maps `2 => SimplePassword` (RFC 2453 §4.1),
/// `3 => KeyedMessageDigest` (RFC 2082 / RFC 4822 §3), and every other value to
/// `Other(value)` so unknown auth types round-trip instead of being rejected.
pub const fn rip_auth_type(value: u16) -> RipAuthType {
    match value {
        RIP_AUTH_TYPE_SIMPLE => RipAuthType::SimplePassword,
        RIP_AUTH_TYPE_KEYED_DIGEST => RipAuthType::KeyedMessageDigest,
        other => RipAuthType::Other(other),
    }
}

/// Wire codepoint for a RIPv2 Authentication Type.
///
/// Reverse of [`rip_auth_type`]: `SimplePassword => 2` (RFC 2453 §4.1),
/// `KeyedMessageDigest => 3` (RFC 2082 / RFC 4822 §3), and `Other(value)`
/// back to its preserved `value`.
pub const fn rip_auth_type_code(kind: RipAuthType) -> u16 {
    match kind {
        RipAuthType::SimplePassword => RIP_AUTH_TYPE_SIMPLE,
        RipAuthType::KeyedMessageDigest => RIP_AUTH_TYPE_KEYED_DIGEST,
        RipAuthType::Other(value) => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rip_command_registry_classifies_codes() {
        // RFC 1058 §3.1 core commands.
        assert_eq!(rip_command_meta(1).status, RipCommandStatus::Assigned);
        assert_eq!(rip_command_name(1), Some("Request"));
        assert_eq!(rip_command_meta(2).status, RipCommandStatus::Assigned);
        assert_eq!(rip_command_name(2), Some("Response"));

        // RFC 2091 §3.2 demand/triggered RIP commands.
        assert_eq!(rip_command_meta(9).status, RipCommandStatus::Assigned);
        assert_eq!(rip_command_name(9), Some("Update Request"));
        assert_eq!(rip_command_meta(10).status, RipCommandStatus::Assigned);
        assert_eq!(rip_command_name(10), Some("Update Response"));
        assert_eq!(rip_command_meta(11).status, RipCommandStatus::Assigned);
        assert_eq!(rip_command_name(11), Some("Update Acknowledge"));

        // An arbitrary unassigned code preserves rather than rejects.
        assert_eq!(rip_command_meta(200).status, RipCommandStatus::Unassigned);
        assert_eq!(rip_command_name(200), None);
    }

    #[test]
    fn rip_command_registry_covers_every_code_without_panic() {
        for code in 0u8..=255 {
            let meta = rip_command_meta(code);
            assert_eq!(meta.code, code);
            // Every code yields a non-empty name.
            assert!(!meta.name.is_empty());
            // name lookup agrees with the metadata status.
            match meta.status {
                RipCommandStatus::Unassigned => assert_eq!(rip_command_name(code), None),
                _ => assert_eq!(rip_command_name(code), Some(meta.name)),
            }
        }
    }

    #[test]
    fn rip_address_family_classifies_ip_and_auth() {
        // IP family (IANA Address Family Numbers, IP = 2).
        assert_eq!(rip_address_family(2), RipAddressFamily::Ip);
        // RIPv2 authentication marker (RFC 2453 §4.1).
        assert_eq!(rip_address_family(0xFFFF), RipAddressFamily::AuthMarker);
        // An unknown AFI is preserved, not rejected.
        assert_eq!(rip_address_family(7), RipAddressFamily::Other(7));
        // The auth-marker predicate recognizes AFI 0xFFFF.
        assert!(is_rip_auth_marker(0xFFFF));
    }

    #[test]
    fn rip_auth_type_roundtrips() {
        // Simple password (RFC 2453 §4.1) round-trips through value 2.
        assert_eq!(
            rip_auth_type(RIP_AUTH_TYPE_SIMPLE),
            RipAuthType::SimplePassword
        );
        assert_eq!(
            rip_auth_type_code(RipAuthType::SimplePassword),
            RIP_AUTH_TYPE_SIMPLE
        );
        assert_eq!(rip_auth_type_code(rip_auth_type(2)), 2);

        // Keyed message digest (RFC 2082 / RFC 4822 §3) round-trips through 3.
        assert_eq!(
            rip_auth_type(RIP_AUTH_TYPE_KEYED_DIGEST),
            RipAuthType::KeyedMessageDigest
        );
        assert_eq!(
            rip_auth_type_code(RipAuthType::KeyedMessageDigest),
            RIP_AUTH_TYPE_KEYED_DIGEST
        );
        assert_eq!(rip_auth_type_code(rip_auth_type(3)), 3);

        // An unknown auth type is preserved as Other and round-trips verbatim.
        assert_eq!(rip_auth_type(42), RipAuthType::Other(42));
        assert_eq!(rip_auth_type_code(RipAuthType::Other(42)), 42);
        assert_eq!(rip_auth_type_code(rip_auth_type(42)), 42);
    }
}
