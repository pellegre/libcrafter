//! ICMPv4 (`ICMP_*`) codepoint constants.
//!
//! Moved verbatim out of `icmp/constants.rs` into the `icmp/v4/` subtree;
//! nothing here changes wire behavior, defaults, or the public API surface.
//! These are re-exported at the `icmp` module root (via `v4/mod.rs` and
//! `icmp/mod.rs`), so every existing path — `crate::protocols::icmp::ICMP_*`,
//! the `protocols::mod.rs` re-exports, and the prelude — keeps resolving to the
//! same names. The version-specific `ICMPV6_*` constants stay in
//! `icmp/constants.rs`.

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
