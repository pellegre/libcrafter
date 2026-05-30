//! ICMP and ICMPv6 codepoint constants and the pure naming, summary, and
//! predicate helpers that operate on those codepoints.
//!
//! Extracted verbatim from the original `icmp.rs`; nothing here changes wire
//! behavior, defaults, or the public API surface.

/// ICMPv4 echo reply type (RFC 792).
pub const ICMP_ECHO_REPLY: u8 = 0;

/// ICMPv4 destination unreachable type (RFC 792).
pub const ICMP_DESTINATION_UNREACHABLE: u8 = 3;

/// ICMPv4 source quench type (RFC 792).
///
/// Deprecated by RFC 6633: hosts and routers must not generate or react to it.
/// `crafter` still constructs and decodes it on request.
pub const ICMP_SOURCE_QUENCH: u8 = 4;

/// ICMPv4 redirect type (RFC 792).
pub const ICMP_REDIRECT: u8 = 5;

/// ICMPv4 alternate host address type (RFC 6918).
///
/// Deprecated by RFC 6918.
pub const ICMP_ALTERNATE_HOST_ADDRESS: u8 = 6;

/// ICMPv4 echo request type (RFC 792).
pub const ICMP_ECHO_REQUEST: u8 = 8;

/// ICMPv4 router advertisement type (RFC 1256).
pub const ICMP_ROUTER_ADVERTISEMENT: u8 = 9;

/// ICMPv4 router solicitation type (RFC 1256).
pub const ICMP_ROUTER_SOLICITATION: u8 = 10;

/// ICMPv4 time exceeded type (RFC 792).
pub const ICMP_TIME_EXCEEDED: u8 = 11;

/// ICMPv4 parameter problem type (RFC 792).
pub const ICMP_PARAMETER_PROBLEM: u8 = 12;

/// ICMPv4 timestamp request type (RFC 792).
pub const ICMP_TIMESTAMP: u8 = 13;

/// ICMPv4 timestamp reply type (RFC 792).
pub const ICMP_TIMESTAMP_REPLY: u8 = 14;

/// ICMPv4 information request type (RFC 792).
///
/// Deprecated by RFC 6918.
pub const ICMP_INFORMATION_REQUEST: u8 = 15;

/// ICMPv4 information reply type (RFC 792).
///
/// Deprecated by RFC 6918.
pub const ICMP_INFORMATION_REPLY: u8 = 16;

/// ICMPv4 address mask request type (RFC 950).
///
/// Deprecated by RFC 6918.
pub const ICMP_ADDRESS_MASK_REQUEST: u8 = 17;

/// ICMPv4 address mask reply type (RFC 950).
///
/// Deprecated by RFC 6918.
pub const ICMP_ADDRESS_MASK_REPLY: u8 = 18;

/// ICMPv4 type 19, reserved (for Security) in the IANA registry.
pub const ICMP_RESERVED_SECURITY: u8 = 19;

/// First ICMPv4 type reserved for the Robustness Experiment (types 20-29).
pub const ICMP_RESERVED_ROBUSTNESS_EXPERIMENT_FIRST: u8 = 20;

/// Last ICMPv4 type reserved for the Robustness Experiment (types 20-29).
pub const ICMP_RESERVED_ROBUSTNESS_EXPERIMENT_LAST: u8 = 29;

/// ICMPv4 traceroute type (RFC 1393).
///
/// Deprecated by RFC 6918.
pub const ICMP_TRACEROUTE: u8 = 30;

/// ICMPv4 datagram conversion error type (RFC 1475).
///
/// Deprecated by RFC 6918.
pub const ICMP_DATAGRAM_CONVERSION_ERROR: u8 = 31;

/// ICMPv4 mobile host redirect type.
///
/// Deprecated by RFC 6918.
pub const ICMP_MOBILE_HOST_REDIRECT: u8 = 32;

/// ICMPv4 IPv6 where-are-you type.
///
/// Deprecated by RFC 6918.
pub const ICMP_IPV6_WHERE_ARE_YOU: u8 = 33;

/// ICMPv4 IPv6 I-am-here type.
///
/// Deprecated by RFC 6918.
pub const ICMP_IPV6_I_AM_HERE: u8 = 34;

/// ICMPv4 mobile registration request type.
///
/// Deprecated by RFC 6918.
pub const ICMP_MOBILE_REGISTRATION_REQUEST: u8 = 35;

/// ICMPv4 mobile registration reply type.
///
/// Deprecated by RFC 6918.
pub const ICMP_MOBILE_REGISTRATION_REPLY: u8 = 36;

/// ICMPv4 domain name request type (RFC 1788).
///
/// Deprecated by RFC 6918.
pub const ICMP_DOMAIN_NAME_REQUEST: u8 = 37;

/// ICMPv4 domain name reply type (RFC 1788).
///
/// Deprecated by RFC 6918.
pub const ICMP_DOMAIN_NAME_REPLY: u8 = 38;

/// ICMPv4 SKIP type.
///
/// Deprecated by RFC 6918.
pub const ICMP_SKIP: u8 = 39;

/// ICMPv4 Photuris security failures type (RFC 2521).
pub const ICMP_PHOTURIS: u8 = 40;

/// ICMPv4 Seamoby experimental mobility type (RFC 4065).
pub const ICMP_SEAMOBY_EXPERIMENTAL: u8 = 41;

/// ICMPv4 extended echo request type (RFC 8335).
pub const ICMP_EXTENDED_ECHO_REQUEST: u8 = 42;

/// ICMPv4 extended echo reply type (RFC 8335).
pub const ICMP_EXTENDED_ECHO_REPLY: u8 = 43;

/// ICMPv4 type 253, RFC 3692-style experiment 1 (RFC 4727).
pub const ICMP_EXPERIMENTAL_253: u8 = 253;

/// ICMPv4 type 254, RFC 3692-style experiment 2 (RFC 4727).
pub const ICMP_EXPERIMENTAL_254: u8 = 254;

/// ICMPv4 type 255, reserved in the IANA registry.
pub const ICMP_RESERVED_255: u8 = 255;

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

/// Destination unreachable code: net unreachable (RFC 792).
pub const ICMP_CODE_DU_NET_UNREACHABLE: u8 = 0;

/// Destination unreachable code: host unreachable (RFC 792).
pub const ICMP_CODE_DU_HOST_UNREACHABLE: u8 = 1;

/// Destination unreachable code: protocol unreachable (RFC 792).
pub const ICMP_CODE_DU_PROTOCOL_UNREACHABLE: u8 = 2;

/// Destination unreachable code: port unreachable (RFC 792).
pub const ICMP_CODE_DU_PORT_UNREACHABLE: u8 = 3;

/// Destination unreachable code: fragmentation needed and DF set (RFC 792).
pub const ICMP_CODE_DU_FRAGMENTATION_NEEDED: u8 = 4;

/// Destination unreachable code: source route failed (RFC 792).
pub const ICMP_CODE_DU_SOURCE_ROUTE_FAILED: u8 = 5;

/// Destination unreachable code: destination network unknown (RFC 1122).
pub const ICMP_CODE_DU_DEST_NETWORK_UNKNOWN: u8 = 6;

/// Destination unreachable code: destination host unknown (RFC 1122).
pub const ICMP_CODE_DU_DEST_HOST_UNKNOWN: u8 = 7;

/// Destination unreachable code: source host isolated (RFC 1122).
pub const ICMP_CODE_DU_SOURCE_HOST_ISOLATED: u8 = 8;

/// Destination unreachable code: network administratively prohibited (RFC 1122).
pub const ICMP_CODE_DU_NETWORK_ADMIN_PROHIBITED: u8 = 9;

/// Destination unreachable code: host administratively prohibited (RFC 1122).
pub const ICMP_CODE_DU_HOST_ADMIN_PROHIBITED: u8 = 10;

/// Destination unreachable code: network unreachable for ToS (RFC 1122).
pub const ICMP_CODE_DU_NETWORK_UNREACHABLE_TOS: u8 = 11;

/// Destination unreachable code: host unreachable for ToS (RFC 1122).
pub const ICMP_CODE_DU_HOST_UNREACHABLE_TOS: u8 = 12;

/// Destination unreachable code: communication administratively prohibited (RFC 1812).
pub const ICMP_CODE_DU_COMM_ADMIN_PROHIBITED: u8 = 13;

/// Destination unreachable code: host precedence violation (RFC 1812).
pub const ICMP_CODE_DU_HOST_PRECEDENCE_VIOLATION: u8 = 14;

/// Destination unreachable code: precedence cutoff in effect (RFC 1812).
pub const ICMP_CODE_DU_PRECEDENCE_CUTOFF: u8 = 15;

/// Redirect code: redirect datagram for the network or subnet (RFC 792).
pub const ICMP_CODE_REDIRECT_NETWORK: u8 = 0;

/// Redirect code: redirect datagram for the host (RFC 792).
pub const ICMP_CODE_REDIRECT_HOST: u8 = 1;

/// Redirect code: redirect datagram for the ToS and network (RFC 792).
pub const ICMP_CODE_REDIRECT_TOS_NETWORK: u8 = 2;

/// Redirect code: redirect datagram for the ToS and host (RFC 792).
pub const ICMP_CODE_REDIRECT_TOS_HOST: u8 = 3;

/// Router advertisement code: normal router advertisement (RFC 3344).
pub const ICMP_CODE_ROUTER_ADVERTISEMENT_NORMAL: u8 = 0;

/// Router advertisement code: does not route common traffic (RFC 3344).
pub const ICMP_CODE_ROUTER_ADVERTISEMENT_NO_COMMON_TRAFFIC: u8 = 16;

/// Time exceeded code: TTL exceeded in transit (RFC 792).
pub const ICMP_CODE_TIME_EXCEEDED_TTL: u8 = 0;

/// Time exceeded code: fragment reassembly time exceeded (RFC 792).
pub const ICMP_CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY: u8 = 1;

/// Parameter problem code: pointer indicates the error (RFC 792).
pub const ICMP_CODE_PARAMETER_PROBLEM_POINTER: u8 = 0;

/// Parameter problem code: missing a required option (RFC 1108).
pub const ICMP_CODE_PARAMETER_PROBLEM_MISSING_OPTION: u8 = 1;

/// Parameter problem code: bad length (RFC 792).
pub const ICMP_CODE_PARAMETER_PROBLEM_BAD_LENGTH: u8 = 2;

/// Photuris code: bad SPI (RFC 2521).
pub const ICMP_CODE_PHOTURIS_BAD_SPI: u8 = 0;

/// Photuris code: authentication failed (RFC 2521).
pub const ICMP_CODE_PHOTURIS_AUTHENTICATION_FAILED: u8 = 1;

/// Photuris code: decompression failed (RFC 2521).
pub const ICMP_CODE_PHOTURIS_DECOMPRESSION_FAILED: u8 = 2;

/// Photuris code: decryption failed (RFC 2521).
pub const ICMP_CODE_PHOTURIS_DECRYPTION_FAILED: u8 = 3;

/// Photuris code: need authentication (RFC 2521).
pub const ICMP_CODE_PHOTURIS_NEED_AUTHENTICATION: u8 = 4;

/// Photuris code: need authorization (RFC 2521).
pub const ICMP_CODE_PHOTURIS_NEED_AUTHORIZATION: u8 = 5;

/// Extended echo reply code: no error (RFC 8335).
pub const ICMP_CODE_EXTENDED_ECHO_REPLY_NO_ERROR: u8 = 0;

/// Extended echo reply code: malformed query (RFC 8335).
pub const ICMP_CODE_EXTENDED_ECHO_REPLY_MALFORMED_QUERY: u8 = 1;

/// Extended echo reply code: no such interface (RFC 8335).
pub const ICMP_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_INTERFACE: u8 = 2;

/// Extended echo reply code: no such table entry (RFC 8335).
pub const ICMP_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_TABLE_ENTRY: u8 = 3;

/// Extended echo reply code: multiple interfaces satisfy query (RFC 8335).
pub const ICMP_CODE_EXTENDED_ECHO_REPLY_MULTIPLE_INTERFACES: u8 = 4;

/// RFC 1256 standard router advertisement entry size, measured in 32-bit words.
///
/// The entry size counts 32-bit words per advertised router; the standard
/// format is a 4-byte router address plus a 4-byte preference level, so the
/// value is two words (8 bytes per entry).
pub const ICMP_ROUTER_ADVERTISEMENT_ENTRY_WORDS: u8 = 2;

/// ICMP extension object class for MPLS labels.
pub const ICMP_EXTENSION_CLASS_MPLS: u8 = 1;

/// ICMP extension object C-Type for an incoming MPLS label stack.
pub const ICMP_EXTENSION_CTYPE_MPLS_INCOMING: u8 = 1;

/// RFC 5837 ICMP extension object class for interface information.
pub const ICMP_EXTENSION_CLASS_INTERFACE_INFO: u8 = 2;

/// RFC 5837 interface role: incoming IP interface.
pub const ICMP_INTERFACE_ROLE_INCOMING: u8 = 0;

/// RFC 5837 interface role: sub-IP component of the incoming IP interface.
pub const ICMP_INTERFACE_ROLE_SUB_IP_INCOMING: u8 = 1;

/// RFC 5837 interface role: outgoing IP interface.
pub const ICMP_INTERFACE_ROLE_OUTGOING: u8 = 2;

/// RFC 5837 interface role: IP next hop.
pub const ICMP_INTERFACE_ROLE_NEXT_HOP: u8 = 3;

/// RFC 5837 C-Type bit 4 (ifIndex sub-object present).
pub const ICMP_INTERFACE_CTYPE_IFINDEX: u8 = 0x08;

/// RFC 5837 C-Type bit 5 (IP Address sub-object present).
pub const ICMP_INTERFACE_CTYPE_IP_ADDRESS: u8 = 0x04;

/// RFC 5837 C-Type bit 6 (Interface Name sub-object present).
pub const ICMP_INTERFACE_CTYPE_NAME: u8 = 0x02;

/// RFC 5837 C-Type bit 7 (MTU sub-object present).
pub const ICMP_INTERFACE_CTYPE_MTU: u8 = 0x01;

/// RFC 5837 IP Address sub-object Address Family Identifier for IPv4.
pub const ICMP_INTERFACE_AFI_IPV4: u16 = 1;

/// RFC 5837 IP Address sub-object Address Family Identifier for IPv6.
pub const ICMP_INTERFACE_AFI_IPV6: u16 = 2;

/// RFC 8335 ICMP extension object class for the Interface Identification Object.
pub const ICMP_EXTENSION_CLASS_INTERFACE_ID: u8 = 3;

/// RFC 8335 Interface Identification Object C-Type: identifies the interface by
/// name (RFC 7223 name padded with zeros to a 32-bit boundary).
pub const ICMP_INTERFACE_ID_CTYPE_NAME: u8 = 1;

/// RFC 8335 Interface Identification Object C-Type: identifies the interface by
/// a 32-bit ifIndex.
pub const ICMP_INTERFACE_ID_CTYPE_INDEX: u8 = 2;

/// RFC 8335 Interface Identification Object C-Type: identifies the interface by
/// address (AFI, address length, reserved, then the address padded to a 32-bit
/// boundary).
pub const ICMP_INTERFACE_ID_CTYPE_ADDRESS: u8 = 3;

/// RFC 8335 extended echo request L-bit mask (local bit, the rightmost bit of
/// the request flag byte).
pub const ICMP_EXTENDED_ECHO_REQUEST_L_BIT: u8 = 0x01;

/// RFC 8335 extended echo reply Active (A) flag mask in the reply flag byte.
pub const ICMP_EXTENDED_ECHO_REPLY_ACTIVE: u8 = 0x04;

/// RFC 8335 extended echo reply IPv4 (4) flag mask in the reply flag byte.
pub const ICMP_EXTENDED_ECHO_REPLY_IPV4: u8 = 0x02;

/// RFC 8335 extended echo reply IPv6 (6) flag mask in the reply flag byte.
pub const ICMP_EXTENDED_ECHO_REPLY_IPV6: u8 = 0x01;

/// RFC 8335 extended echo reply state value: reserved (0).
pub const ICMP_EXTENDED_ECHO_REPLY_STATE_RESERVED: u8 = 0;

/// RFC 8335 extended echo reply state value: incomplete (1).
pub const ICMP_EXTENDED_ECHO_REPLY_STATE_INCOMPLETE: u8 = 1;

/// RFC 8335 extended echo reply state value: reachable (2).
pub const ICMP_EXTENDED_ECHO_REPLY_STATE_REACHABLE: u8 = 2;

/// RFC 8335 extended echo reply state value: stale (3).
pub const ICMP_EXTENDED_ECHO_REPLY_STATE_STALE: u8 = 3;

/// RFC 8335 extended echo reply state value: delay (4).
pub const ICMP_EXTENDED_ECHO_REPLY_STATE_DELAY: u8 = 4;

/// RFC 8335 extended echo reply state value: probe (5).
pub const ICMP_EXTENDED_ECHO_REPLY_STATE_PROBE: u8 = 5;

/// RFC 8335 extended echo reply state value: failed (6).
pub const ICMP_EXTENDED_ECHO_REPLY_STATE_FAILED: u8 = 6;

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
