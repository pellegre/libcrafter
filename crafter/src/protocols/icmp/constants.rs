//! The pure naming, summary, and predicate helpers that operate on ICMP
//! codepoints.
//!
//! Originally extracted verbatim from `icmp.rs`; nothing here changes wire
//! behavior, defaults, or the public API surface. The ICMPv4 (`ICMP_*`) and
//! ICMPv6 (`ICMPV6_*`) codepoint constants now live in `icmp/v4/constants.rs`
//! and `icmp/v6/constants.rs` respectively and are imported back here for the
//! shared helpers below.

// Re-export the ICMPv4 (`ICMP_*`) and ICMPv6 (`ICMPV6_*`) codepoints from the v4
// and v6 subtrees so the shared helpers below resolve them and every module that
// globs `super::constants::*` (and, through `icmp/mod.rs`, the crate root and
// prelude) keeps seeing the same names after the internal move.
pub use super::v4::constants::*;
pub use super::v6::constants::*;

pub(crate) fn is_echo_v4(icmp_type: u8) -> bool {
    matches!(icmp_type, ICMP_ECHO_REQUEST | ICMP_ECHO_REPLY)
}

/// True for the RFC 792 / RFC 950 query families that carry an identifier and
/// sequence number in the rest-of-header: echo, timestamp, information, and
/// address mask messages.
///
/// This is broader than [`is_echo_v4`] on purpose: echo-only matching used by
/// ping-style tools still flows through [`IcmpKind`], so timestamp,
/// information, and address mask messages surface id/seq without being mistaken
/// for echoes.
pub(crate) fn is_query_v4(icmp_type: u8) -> bool {
    is_echo_v4(icmp_type)
        || matches!(
            icmp_type,
            ICMP_TIMESTAMP
                | ICMP_TIMESTAMP_REPLY
                | ICMP_INFORMATION_REQUEST
                | ICMP_INFORMATION_REPLY
                | ICMP_ADDRESS_MASK_REQUEST
                | ICMP_ADDRESS_MASK_REPLY
        )
}

pub(crate) fn is_echo_v6(icmp_type: u8) -> bool {
    matches!(icmp_type, ICMPV6_ECHO_REQUEST | ICMPV6_ECHO_REPLY)
}

/// True for the RFC 8335 extended echo request/reply types, which carry a 16-bit
/// identifier, an 8-bit sequence number, and a flag byte in the rest-of-header.
pub(crate) fn is_extended_echo_v4(icmp_type: u8) -> bool {
    matches!(
        icmp_type,
        ICMP_EXTENDED_ECHO_REQUEST | ICMP_EXTENDED_ECHO_REPLY
    )
}

pub(crate) fn icmpv4_type_allows_extensions(icmp_type: u8) -> bool {
    matches!(
        icmp_type,
        ICMP_DESTINATION_UNREACHABLE | ICMP_TIME_EXCEEDED | ICMP_PARAMETER_PROBLEM
    )
}

/// Human-readable RFC 5837 interface role, keeping the raw numeric value visible
/// for unknown role codes (the field is only two bits, so all values are
/// assigned, but the formatting is kept defensive).
pub(crate) fn interface_role_summary(role: u8) -> String {
    match role {
        ICMP_INTERFACE_ROLE_INCOMING => "incoming".to_string(),
        ICMP_INTERFACE_ROLE_SUB_IP_INCOMING => "sub-ip-incoming".to_string(),
        ICMP_INTERFACE_ROLE_OUTGOING => "outgoing".to_string(),
        ICMP_INTERFACE_ROLE_NEXT_HOP => "next-hop".to_string(),
        other => format!("role({other})"),
    }
}

/// True for the RFC 792 error-family ICMPv4 types that quote the original
/// datagram after the fixed header: destination unreachable, source quench,
/// redirect, time exceeded, and parameter problem.
///
/// Source quench (RFC 6633) is deprecated but still follows the error shape, so
/// it is decoded with a quoted datagram like the others.
pub(crate) fn icmpv4_type_is_error(icmp_type: u8) -> bool {
    matches!(
        icmp_type,
        ICMP_DESTINATION_UNREACHABLE
            | ICMP_SOURCE_QUENCH
            | ICMP_REDIRECT
            | ICMP_TIME_EXCEEDED
            | ICMP_PARAMETER_PROBLEM
    )
}

pub(crate) fn icmpv6_type_allows_extensions(icmp_type: u8) -> bool {
    matches!(
        icmp_type,
        ICMPV6_DESTINATION_UNREACHABLE | ICMPV6_TIME_EXCEEDED
    )
}

pub(crate) fn icmpv4_type_summary(icmp_type: u8) -> String {
    match icmpv4_type_name(icmp_type) {
        Some(name) => format!("{name}({icmp_type})"),
        None => icmp_type.to_string(),
    }
}

/// Stable IANA-registry name for a known ICMPv4 type, or `None` when the value
/// is unassigned and should remain numeric.
///
/// Names are sourced from the IANA ICMP Parameters registry. Deprecated and
/// reserved values still return a name so summaries report their assigned
/// identity rather than hiding it.
pub(crate) fn icmpv4_type_name(icmp_type: u8) -> Option<&'static str> {
    let name = match icmp_type {
        ICMP_ECHO_REPLY => "echo-reply",
        ICMP_DESTINATION_UNREACHABLE => "destination-unreachable",
        ICMP_SOURCE_QUENCH => "source-quench",
        ICMP_REDIRECT => "redirect",
        ICMP_ALTERNATE_HOST_ADDRESS => "alternate-host-address",
        ICMP_ECHO_REQUEST => "echo-request",
        ICMP_ROUTER_ADVERTISEMENT => "router-advertisement",
        ICMP_ROUTER_SOLICITATION => "router-solicitation",
        ICMP_TIME_EXCEEDED => "time-exceeded",
        ICMP_PARAMETER_PROBLEM => "parameter-problem",
        ICMP_TIMESTAMP => "timestamp",
        ICMP_TIMESTAMP_REPLY => "timestamp-reply",
        ICMP_INFORMATION_REQUEST => "information-request",
        ICMP_INFORMATION_REPLY => "information-reply",
        ICMP_ADDRESS_MASK_REQUEST => "address-mask-request",
        ICMP_ADDRESS_MASK_REPLY => "address-mask-reply",
        ICMP_RESERVED_SECURITY => "reserved-security",
        ICMP_RESERVED_ROBUSTNESS_EXPERIMENT_FIRST..=ICMP_RESERVED_ROBUSTNESS_EXPERIMENT_LAST => {
            "reserved-robustness-experiment"
        }
        ICMP_TRACEROUTE => "traceroute",
        ICMP_DATAGRAM_CONVERSION_ERROR => "datagram-conversion-error",
        ICMP_MOBILE_HOST_REDIRECT => "mobile-host-redirect",
        ICMP_IPV6_WHERE_ARE_YOU => "ipv6-where-are-you",
        ICMP_IPV6_I_AM_HERE => "ipv6-i-am-here",
        ICMP_MOBILE_REGISTRATION_REQUEST => "mobile-registration-request",
        ICMP_MOBILE_REGISTRATION_REPLY => "mobile-registration-reply",
        ICMP_DOMAIN_NAME_REQUEST => "domain-name-request",
        ICMP_DOMAIN_NAME_REPLY => "domain-name-reply",
        ICMP_SKIP => "skip",
        ICMP_PHOTURIS => "photuris",
        ICMP_SEAMOBY_EXPERIMENTAL => "seamoby-experimental",
        ICMP_EXTENDED_ECHO_REQUEST => "extended-echo-request",
        ICMP_EXTENDED_ECHO_REPLY => "extended-echo-reply",
        ICMP_EXPERIMENTAL_253 => "experiment-1",
        ICMP_EXPERIMENTAL_254 => "experiment-2",
        ICMP_RESERVED_255 => "reserved",
        _ => return None,
    };
    Some(name)
}

/// True when the ICMPv4 type is marked deprecated or obsolete in the IANA
/// registry (RFC 6633 source quench, plus the RFC 6918 legacy deprecations).
///
/// Deprecated values are still constructible and decodable; this only reports
/// their registry status.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn icmpv4_type_is_deprecated(icmp_type: u8) -> bool {
    matches!(
        icmp_type,
        ICMP_SOURCE_QUENCH
            | ICMP_ALTERNATE_HOST_ADDRESS
            | ICMP_INFORMATION_REQUEST
            | ICMP_INFORMATION_REPLY
            | ICMP_ADDRESS_MASK_REQUEST
            | ICMP_ADDRESS_MASK_REPLY
            | ICMP_TRACEROUTE
            | ICMP_DATAGRAM_CONVERSION_ERROR
            | ICMP_MOBILE_HOST_REDIRECT
            | ICMP_IPV6_WHERE_ARE_YOU
            | ICMP_IPV6_I_AM_HERE
            | ICMP_MOBILE_REGISTRATION_REQUEST
            | ICMP_MOBILE_REGISTRATION_REPLY
            | ICMP_DOMAIN_NAME_REQUEST
            | ICMP_DOMAIN_NAME_REPLY
            | ICMP_SKIP
    )
}

/// Stable IANA-registry name for a known ICMPv4 (type, code) pair, or `None`
/// when the code has no registered meaning for that type and should remain
/// numeric. Only types with IANA code registries are covered.
pub(crate) fn icmpv4_code_name(icmp_type: u8, code: u8) -> Option<&'static str> {
    let name = match (icmp_type, code) {
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_NET_UNREACHABLE) => "net-unreachable",
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_HOST_UNREACHABLE) => "host-unreachable",
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_PROTOCOL_UNREACHABLE) => "protocol-unreachable",
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_PORT_UNREACHABLE) => "port-unreachable",
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_FRAGMENTATION_NEEDED) => "fragmentation-needed",
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_SOURCE_ROUTE_FAILED) => "source-route-failed",
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_DEST_NETWORK_UNKNOWN) => "dest-network-unknown",
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_DEST_HOST_UNKNOWN) => "dest-host-unknown",
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_SOURCE_HOST_ISOLATED) => "source-host-isolated",
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_NETWORK_ADMIN_PROHIBITED) => {
            "network-admin-prohibited"
        }
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_HOST_ADMIN_PROHIBITED) => {
            "host-admin-prohibited"
        }
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_NETWORK_UNREACHABLE_TOS) => {
            "network-unreachable-tos"
        }
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_HOST_UNREACHABLE_TOS) => "host-unreachable-tos",
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_COMM_ADMIN_PROHIBITED) => {
            "comm-admin-prohibited"
        }
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_HOST_PRECEDENCE_VIOLATION) => {
            "host-precedence-violation"
        }
        (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_PRECEDENCE_CUTOFF) => "precedence-cutoff",
        (ICMP_REDIRECT, ICMP_CODE_REDIRECT_NETWORK) => "redirect-network",
        (ICMP_REDIRECT, ICMP_CODE_REDIRECT_HOST) => "redirect-host",
        (ICMP_REDIRECT, ICMP_CODE_REDIRECT_TOS_NETWORK) => "redirect-tos-network",
        (ICMP_REDIRECT, ICMP_CODE_REDIRECT_TOS_HOST) => "redirect-tos-host",
        (ICMP_ROUTER_ADVERTISEMENT, ICMP_CODE_ROUTER_ADVERTISEMENT_NORMAL) => "normal",
        (ICMP_ROUTER_ADVERTISEMENT, ICMP_CODE_ROUTER_ADVERTISEMENT_NO_COMMON_TRAFFIC) => {
            "no-common-traffic"
        }
        (ICMP_TIME_EXCEEDED, ICMP_CODE_TIME_EXCEEDED_TTL) => "ttl-exceeded",
        (ICMP_TIME_EXCEEDED, ICMP_CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY) => {
            "fragment-reassembly-time-exceeded"
        }
        (ICMP_PARAMETER_PROBLEM, ICMP_CODE_PARAMETER_PROBLEM_POINTER) => "pointer",
        (ICMP_PARAMETER_PROBLEM, ICMP_CODE_PARAMETER_PROBLEM_MISSING_OPTION) => "missing-option",
        (ICMP_PARAMETER_PROBLEM, ICMP_CODE_PARAMETER_PROBLEM_BAD_LENGTH) => "bad-length",
        (ICMP_PHOTURIS, ICMP_CODE_PHOTURIS_BAD_SPI) => "bad-spi",
        (ICMP_PHOTURIS, ICMP_CODE_PHOTURIS_AUTHENTICATION_FAILED) => "authentication-failed",
        (ICMP_PHOTURIS, ICMP_CODE_PHOTURIS_DECOMPRESSION_FAILED) => "decompression-failed",
        (ICMP_PHOTURIS, ICMP_CODE_PHOTURIS_DECRYPTION_FAILED) => "decryption-failed",
        (ICMP_PHOTURIS, ICMP_CODE_PHOTURIS_NEED_AUTHENTICATION) => "need-authentication",
        (ICMP_PHOTURIS, ICMP_CODE_PHOTURIS_NEED_AUTHORIZATION) => "need-authorization",
        (ICMP_EXTENDED_ECHO_REPLY, ICMP_CODE_EXTENDED_ECHO_REPLY_NO_ERROR) => "no-error",
        (ICMP_EXTENDED_ECHO_REPLY, ICMP_CODE_EXTENDED_ECHO_REPLY_MALFORMED_QUERY) => {
            "malformed-query"
        }
        (ICMP_EXTENDED_ECHO_REPLY, ICMP_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_INTERFACE) => {
            "no-such-interface"
        }
        (ICMP_EXTENDED_ECHO_REPLY, ICMP_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_TABLE_ENTRY) => {
            "no-such-table-entry"
        }
        (ICMP_EXTENDED_ECHO_REPLY, ICMP_CODE_EXTENDED_ECHO_REPLY_MULTIPLE_INTERFACES) => {
            "multiple-interfaces"
        }
        _ => return None,
    };
    Some(name)
}

/// Summary string for an ICMPv4 (type, code) pair: a stable name with its
/// numeric value when known, otherwise the bare number.
pub(crate) fn icmpv4_code_summary(icmp_type: u8, code: u8) -> String {
    match icmpv4_code_name(icmp_type, code) {
        Some(name) => format!("{name}({code})"),
        None => code.to_string(),
    }
}

pub(crate) fn icmpv6_type_summary(icmp_type: u8) -> String {
    match icmp_type {
        ICMPV6_DESTINATION_UNREACHABLE => "destination-unreachable(1)".to_string(),
        ICMPV6_PACKET_TOO_BIG => "packet-too-big(2)".to_string(),
        ICMPV6_TIME_EXCEEDED => "time-exceeded(3)".to_string(),
        ICMPV6_PARAMETER_PROBLEM => "parameter-problem(4)".to_string(),
        ICMPV6_ECHO_REQUEST => "echo-request(128)".to_string(),
        ICMPV6_ECHO_REPLY => "echo-reply(129)".to_string(),
        value => value.to_string(),
    }
}

#[cfg(test)]
mod icmpv4_codepoints {
    use super::{
        icmpv4_code_summary, icmpv4_type_is_deprecated, icmpv4_type_name, icmpv4_type_summary,
        ICMP_ADDRESS_MASK_REPLY, ICMP_ADDRESS_MASK_REQUEST, ICMP_ALTERNATE_HOST_ADDRESS,
        ICMP_CODE_DU_FRAGMENTATION_NEEDED, ICMP_CODE_DU_NET_UNREACHABLE,
        ICMP_CODE_EXTENDED_ECHO_REPLY_MULTIPLE_INTERFACES, ICMP_CODE_PHOTURIS_NEED_AUTHORIZATION,
        ICMP_CODE_REDIRECT_HOST, ICMP_CODE_ROUTER_ADVERTISEMENT_NO_COMMON_TRAFFIC,
        ICMP_DESTINATION_UNREACHABLE, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST, ICMP_EXPERIMENTAL_253,
        ICMP_EXPERIMENTAL_254, ICMP_EXTENDED_ECHO_REPLY, ICMP_EXTENDED_ECHO_REQUEST,
        ICMP_INFORMATION_REPLY, ICMP_PHOTURIS, ICMP_REDIRECT, ICMP_RESERVED_255,
        ICMP_RESERVED_ROBUSTNESS_EXPERIMENT_FIRST, ICMP_RESERVED_ROBUSTNESS_EXPERIMENT_LAST,
        ICMP_RESERVED_SECURITY, ICMP_ROUTER_ADVERTISEMENT, ICMP_ROUTER_SOLICITATION,
        ICMP_SEAMOBY_EXPERIMENTAL, ICMP_SOURCE_QUENCH, ICMP_TIMESTAMP, ICMP_TIMESTAMP_REPLY,
    };

    // Representative type numbers from the IANA ICMP Parameters registry. These
    // pin the assigned values rather than the source order, so a later edit that
    // renumbers a constant fails loudly.
    #[test]
    fn icmpv4_codepoints_representative_type_constants_have_iana_values() {
        assert_eq!(ICMP_ECHO_REPLY, 0);
        assert_eq!(ICMP_DESTINATION_UNREACHABLE, 3);
        assert_eq!(ICMP_SOURCE_QUENCH, 4);
        assert_eq!(ICMP_REDIRECT, 5);
        assert_eq!(ICMP_ECHO_REQUEST, 8);
        assert_eq!(ICMP_ROUTER_ADVERTISEMENT, 9);
        assert_eq!(ICMP_ROUTER_SOLICITATION, 10);
        assert_eq!(ICMP_TIMESTAMP, 13);
        assert_eq!(ICMP_TIMESTAMP_REPLY, 14);
        assert_eq!(ICMP_PHOTURIS, 40);
        assert_eq!(ICMP_SEAMOBY_EXPERIMENTAL, 41);
        assert_eq!(ICMP_EXTENDED_ECHO_REQUEST, 42);
        assert_eq!(ICMP_EXTENDED_ECHO_REPLY, 43);
        assert_eq!(ICMP_EXPERIMENTAL_253, 253);
        assert_eq!(ICMP_EXPERIMENTAL_254, 254);
        assert_eq!(ICMP_RESERVED_255, 255);
        assert_eq!(ICMP_RESERVED_SECURITY, 19);
        assert_eq!(ICMP_RESERVED_ROBUSTNESS_EXPERIMENT_FIRST, 20);
        assert_eq!(ICMP_RESERVED_ROBUSTNESS_EXPERIMENT_LAST, 29);
    }

    // Representative code-field values for the types that carry IANA code
    // registries.
    #[test]
    fn icmpv4_codepoints_representative_code_constants_have_iana_values() {
        assert_eq!(ICMP_CODE_DU_NET_UNREACHABLE, 0);
        assert_eq!(ICMP_CODE_DU_FRAGMENTATION_NEEDED, 4);
        assert_eq!(ICMP_CODE_REDIRECT_HOST, 1);
        assert_eq!(ICMP_CODE_ROUTER_ADVERTISEMENT_NO_COMMON_TRAFFIC, 16);
        assert_eq!(ICMP_CODE_PHOTURIS_NEED_AUTHORIZATION, 5);
        assert_eq!(ICMP_CODE_EXTENDED_ECHO_REPLY_MULTIPLE_INTERFACES, 4);
    }

    // The constants and summary helpers must be reachable from the crate root so
    // generated tools can name codepoints without reaching into the module.
    #[test]
    fn icmpv4_codepoints_constants_are_publicly_exported() {
        assert_eq!(crate::ICMP_TIMESTAMP, ICMP_TIMESTAMP);
        assert_eq!(crate::ICMP_ROUTER_ADVERTISEMENT, ICMP_ROUTER_ADVERTISEMENT);
        assert_eq!(
            crate::ICMP_EXTENDED_ECHO_REQUEST,
            ICMP_EXTENDED_ECHO_REQUEST
        );
        assert_eq!(crate::ICMP_EXPERIMENTAL_253, ICMP_EXPERIMENTAL_253);
        assert_eq!(
            crate::ICMP_ALTERNATE_HOST_ADDRESS,
            ICMP_ALTERNATE_HOST_ADDRESS
        );
        assert_eq!(crate::ICMP_ADDRESS_MASK_REQUEST, ICMP_ADDRESS_MASK_REQUEST);
        // The same names must also surface through the `core` prelude re-export.
        assert_eq!(crate::core::ICMP_PHOTURIS, ICMP_PHOTURIS);
        assert_eq!(
            crate::core::ICMP_CODE_ROUTER_ADVERTISEMENT_NO_COMMON_TRAFFIC,
            ICMP_CODE_ROUTER_ADVERTISEMENT_NO_COMMON_TRAFFIC
        );
    }

    // Known types render their stable registry name with the numeric value kept
    // visible.
    #[test]
    fn icmpv4_codepoints_known_type_summaries_use_stable_names() {
        assert_eq!(icmpv4_type_summary(ICMP_ECHO_REPLY), "echo-reply(0)");
        assert_eq!(
            icmpv4_type_summary(ICMP_DESTINATION_UNREACHABLE),
            "destination-unreachable(3)"
        );
        assert_eq!(icmpv4_type_summary(ICMP_TIMESTAMP), "timestamp(13)");
        assert_eq!(
            icmpv4_type_summary(ICMP_EXTENDED_ECHO_REQUEST),
            "extended-echo-request(42)"
        );
        assert_eq!(
            icmpv4_type_summary(ICMP_EXPERIMENTAL_253),
            "experiment-1(253)"
        );
        // Every value across the robustness-experiment reserved range names the
        // shared registry meaning rather than only the endpoints.
        assert_eq!(
            icmpv4_type_summary(25),
            "reserved-robustness-experiment(25)"
        );
        assert_eq!(icmpv4_type_name(ICMP_RESERVED_255), Some("reserved"));
    }

    // Known (type, code) pairs render their stable registry name; the numeric
    // code stays visible.
    #[test]
    fn icmpv4_codepoints_known_code_summaries_use_stable_names() {
        assert_eq!(
            icmpv4_code_summary(
                ICMP_DESTINATION_UNREACHABLE,
                ICMP_CODE_DU_FRAGMENTATION_NEEDED
            ),
            "fragmentation-needed(4)"
        );
        assert_eq!(
            icmpv4_code_summary(ICMP_REDIRECT, ICMP_CODE_REDIRECT_HOST),
            "redirect-host(1)"
        );
        assert_eq!(
            icmpv4_code_summary(
                ICMP_ROUTER_ADVERTISEMENT,
                ICMP_CODE_ROUTER_ADVERTISEMENT_NO_COMMON_TRAFFIC
            ),
            "no-common-traffic(16)"
        );
        assert_eq!(
            icmpv4_code_summary(ICMP_PHOTURIS, ICMP_CODE_PHOTURIS_NEED_AUTHORIZATION),
            "need-authorization(5)"
        );
        assert_eq!(
            icmpv4_code_summary(
                ICMP_EXTENDED_ECHO_REPLY,
                ICMP_CODE_EXTENDED_ECHO_REPLY_MULTIPLE_INTERFACES
            ),
            "multiple-interfaces(4)"
        );
    }

    // Deprecated and obsolete types keep their registry identity in both the
    // name lookup and the deprecation predicate. Naming a value never doubles as
    // refusing it.
    #[test]
    fn icmpv4_codepoints_deprecated_types_retain_names_and_report_status() {
        assert_eq!(icmpv4_type_summary(ICMP_SOURCE_QUENCH), "source-quench(4)");
        assert_eq!(
            icmpv4_type_summary(ICMP_ALTERNATE_HOST_ADDRESS),
            "alternate-host-address(6)"
        );
        assert_eq!(
            icmpv4_type_summary(ICMP_ADDRESS_MASK_REPLY),
            "address-mask-reply(18)"
        );

        // RFC 6633 (source quench) and the RFC 6918 bulk deprecations are
        // reported as deprecated.
        assert!(icmpv4_type_is_deprecated(ICMP_SOURCE_QUENCH));
        assert!(icmpv4_type_is_deprecated(ICMP_ALTERNATE_HOST_ADDRESS));
        assert!(icmpv4_type_is_deprecated(ICMP_INFORMATION_REPLY));
        assert!(icmpv4_type_is_deprecated(ICMP_ADDRESS_MASK_REQUEST));

        // Active and reserved-but-not-deprecated types are not flagged.
        assert!(!icmpv4_type_is_deprecated(ICMP_ECHO_REQUEST));
        assert!(!icmpv4_type_is_deprecated(ICMP_SEAMOBY_EXPERIMENTAL));
        assert!(!icmpv4_type_is_deprecated(ICMP_EXTENDED_ECHO_REQUEST));
        assert!(!icmpv4_type_is_deprecated(ICMP_RESERVED_255));
    }

    // Unassigned type numbers have no registry name and fall back to the bare
    // number in summaries.
    #[test]
    fn icmpv4_codepoints_unknown_type_falls_back_to_number() {
        // Types 1, 2, 7 are Unassigned in the IANA registry.
        assert_eq!(icmpv4_type_name(1), None);
        assert_eq!(icmpv4_type_name(2), None);
        assert_eq!(icmpv4_type_name(7), None);
        assert_eq!(icmpv4_type_summary(1), "1");
        assert_eq!(icmpv4_type_summary(7), "7");
    }

    // Codes with no registered meaning for their type fall back to the bare
    // number, including codes on a type that has no code registry at all.
    #[test]
    fn icmpv4_codepoints_unknown_code_falls_back_to_number() {
        // Type 3 has a code registry, but code 99 is not assigned.
        assert_eq!(icmpv4_code_summary(ICMP_DESTINATION_UNREACHABLE, 99), "99");
        // Type 11 (time exceeded) has only codes 0 and 1.
        assert_eq!(icmpv4_code_summary(super::ICMP_TIME_EXCEEDED, 200), "200");
        // Echo request carries no code registry, so any code is numeric.
        assert_eq!(icmpv4_code_summary(ICMP_ECHO_REQUEST, 0), "0");
        assert_eq!(icmpv4_code_summary(ICMP_ECHO_REQUEST, 5), "5");
    }
}
