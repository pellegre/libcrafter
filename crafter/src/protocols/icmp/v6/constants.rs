//! ICMPv6 (`ICMPV6_*`) codepoint constants.
//!
//! Moved verbatim out of `icmp/constants.rs` into the `icmp/v6/` subtree so the
//! ICMPv6 codepoints sit beside the [`Icmpv6`](super::Icmpv6) header that uses
//! them, mirroring the `icmp/v4/` layout. Nothing here changes wire behavior,
//! defaults, or the public API surface: these are re-exported back through
//! `icmp/constants.rs` (and, via `icmp/mod.rs`, the crate root and prelude), so
//! every existing path — `crate::protocols::icmp::ICMPV6_*`, the
//! `protocols::mod.rs` re-exports, and the prelude — keeps resolving to the same
//! names.
//!
//! The codepoints below are the `Type` field assignments from the IANA
//! "Internet Control Message Protocol version 6 (ICMPv6) Parameters" registry,
//! <https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml>.
//! The defining RFC is cited per constant. (The local `rfc-protocol-spec`
//! manifest cache is sparse for ICMPv6, so these values were grounded directly
//! against the live IANA Type registry.)

/// ICMPv6 destination unreachable type.
pub const ICMPV6_DESTINATION_UNREACHABLE: u8 = 1;

/// ICMPv6 packet-too-big type.
pub const ICMPV6_PACKET_TOO_BIG: u8 = 2;

/// ICMPv6 time exceeded type.
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;

/// ICMPv6 parameter problem type.
pub const ICMPV6_PARAMETER_PROBLEM: u8 = 4;

/// ICMPv6 echo request type.
pub const ICMPV6_ECHO_REQUEST: u8 = 128;

/// ICMPv6 echo reply type.
pub const ICMPV6_ECHO_REPLY: u8 = 129;

// Multicast Listener Discovery, version 1 (RFC 2710, types 130–132).

/// ICMPv6 Multicast Listener Query type (MLDv1, RFC 2710).
pub const ICMPV6_MULTICAST_LISTENER_QUERY: u8 = 130;

/// ICMPv6 Multicast Listener Report type (MLDv1, RFC 2710).
pub const ICMPV6_MULTICAST_LISTENER_REPORT: u8 = 131;

/// ICMPv6 Multicast Listener Done type (MLDv1, RFC 2710).
pub const ICMPV6_MULTICAST_LISTENER_DONE: u8 = 132;

// IPv6 Neighbor Discovery (RFC 4861, types 133–137).

/// ICMPv6 Router Solicitation type (NDP, RFC 4861).
pub const ICMPV6_ROUTER_SOLICITATION: u8 = 133;

/// ICMPv6 Router Advertisement type (NDP, RFC 4861).
pub const ICMPV6_ROUTER_ADVERTISEMENT: u8 = 134;

/// ICMPv6 Neighbor Solicitation type (NDP, RFC 4861).
pub const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;

/// ICMPv6 Neighbor Advertisement type (NDP, RFC 4861).
pub const ICMPV6_NEIGHBOR_ADVERTISEMENT: u8 = 136;

/// ICMPv6 Redirect type (NDP, RFC 4861).
pub const ICMPV6_REDIRECT: u8 = 137;

/// ICMPv6 Router Renumbering type (RFC 2894).
pub const ICMPV6_ROUTER_RENUMBERING: u8 = 138;

/// ICMPv6 Node Information Query type (experimental, RFC 4620).
pub const ICMPV6_NODE_INFORMATION_QUERY: u8 = 139;

/// ICMPv6 Node Information Response type (experimental, RFC 4620).
pub const ICMPV6_NODE_INFORMATION_RESPONSE: u8 = 140;

/// ICMPv6 Inverse Neighbor Discovery Solicitation type (RFC 3122).
pub const ICMPV6_INVERSE_ND_SOLICITATION: u8 = 141;

/// ICMPv6 Inverse Neighbor Discovery Advertisement type (RFC 3122).
pub const ICMPV6_INVERSE_ND_ADVERTISEMENT: u8 = 142;

/// ICMPv6 Version 2 Multicast Listener Report type (MLDv2, RFC 3810; the IANA
/// registry now cites RFC 9777, which obsoletes RFC 3810).
pub const ICMPV6_MLDV2_REPORT: u8 = 143;

// Extended Echo (RFC 8335, types 160/161); mirrors the ICMPv4 extended-echo
// support.

/// ICMPv6 Extended Echo Request type (RFC 8335).
pub const ICMPV6_EXTENDED_ECHO_REQUEST: u8 = 160;

/// ICMPv6 Extended Echo Reply type (RFC 8335).
pub const ICMPV6_EXTENDED_ECHO_REPLY: u8 = 161;

#[cfg(test)]
mod tests {
    use super::*;

    // Asserts each ICMPv6 `Type` codepoint matches its value in the IANA
    // "ICMPv6 Parameters" Type registry. Hard-coded literals here are the
    // independent oracle: the test fails if a constant is ever edited away
    // from its registry assignment.
    #[test]
    fn icmpv6_type_codepoints_match_iana_registry() {
        // Pre-existing RFC 4443 types (regression guard).
        assert_eq!(ICMPV6_DESTINATION_UNREACHABLE, 1);
        assert_eq!(ICMPV6_PACKET_TOO_BIG, 2);
        assert_eq!(ICMPV6_TIME_EXCEEDED, 3);
        assert_eq!(ICMPV6_PARAMETER_PROBLEM, 4);
        assert_eq!(ICMPV6_ECHO_REQUEST, 128);
        assert_eq!(ICMPV6_ECHO_REPLY, 129);

        // MLDv1 (RFC 2710).
        assert_eq!(ICMPV6_MULTICAST_LISTENER_QUERY, 130);
        assert_eq!(ICMPV6_MULTICAST_LISTENER_REPORT, 131);
        assert_eq!(ICMPV6_MULTICAST_LISTENER_DONE, 132);

        // Neighbor Discovery (RFC 4861).
        assert_eq!(ICMPV6_ROUTER_SOLICITATION, 133);
        assert_eq!(ICMPV6_ROUTER_ADVERTISEMENT, 134);
        assert_eq!(ICMPV6_NEIGHBOR_SOLICITATION, 135);
        assert_eq!(ICMPV6_NEIGHBOR_ADVERTISEMENT, 136);
        assert_eq!(ICMPV6_REDIRECT, 137);

        // Router Renumbering / Node Information / Inverse ND.
        assert_eq!(ICMPV6_ROUTER_RENUMBERING, 138);
        assert_eq!(ICMPV6_NODE_INFORMATION_QUERY, 139);
        assert_eq!(ICMPV6_NODE_INFORMATION_RESPONSE, 140);
        assert_eq!(ICMPV6_INVERSE_ND_SOLICITATION, 141);
        assert_eq!(ICMPV6_INVERSE_ND_ADVERTISEMENT, 142);

        // MLDv2 (RFC 3810 / RFC 9777).
        assert_eq!(ICMPV6_MLDV2_REPORT, 143);

        // Extended Echo (RFC 8335).
        assert_eq!(ICMPV6_EXTENDED_ECHO_REQUEST, 160);
        assert_eq!(ICMPV6_EXTENDED_ECHO_REPLY, 161);
    }
}
