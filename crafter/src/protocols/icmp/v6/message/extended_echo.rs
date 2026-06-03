//! ICMPv6 Extended Echo Request / Reply (RFC 8335, types 160 / 161).
//!
//! RFC 8335 defines an "Extended Echo" probe that, unlike the RFC 4443 echo,
//! queries the reachability of a *named interface* on the target rather than the
//! target's own data path. It assigns one type pair per IP version: ICMPv4 types
//! 42 / 43 (already implemented in `icmp/v4/` and `icmp/shared/extensions.rs`)
//! and the ICMPv6 types 160 / 161 implemented here. The two versions share the
//! exact same fixed-header layout and the same RFC 4884 ICMP Extension Structure;
//! the only wire differences are the type numbers and that the ICMPv6 checksum
//! folds in the IPv6 pseudo-header (which the [`Icmpv6`] header's `compile()`
//! already handles). This module therefore mirrors the ICMPv4 extended-echo
//! idiom rather than inventing a parallel one.
//!
//! ## Wire layout (RFC 8335 section 3, grounded against the authoritative RFC)
//!
//! Extended Echo Request (type 160, code 0):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Type      |     Code      |          Checksum             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Identifier          |Sequence Number|   Reserved  |L|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  ICMP Extension Structure                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The Identifier (16 bits), Sequence Number (8 bits), 7 Reserved bits, and the
//! L (Local) bit make up the four-byte rest-of-header carried on the [`Icmpv6`]
//! header — the same split this crate uses for ICMPv4 and for the NDP messages.
//! The body is an RFC 4884 ICMP Extension Structure carrying exactly one
//! Interface Identification Object (extension object class 3) identifying the
//! probed interface by ifIndex, name, or address. It is built and decoded with
//! the version-neutral [`IcmpExtension`] / [`IcmpExtensionObject`] /
//! [`IcmpExtensionInterfaceId`] framework in `icmp/shared/extensions.rs`,
//! composed under the header with `/` exactly like the ICMPv4 request.
//!
//! Extended Echo Reply (type 161):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Type      |     Code      |          Checksum             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Identifier          |Sequence Number|State|Res|A|4|6|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The reply echoes the Identifier and Sequence Number; its `Code` reports the
//! query result (0 No Error, 1 Malformed Query, 2 No Such Interface, 3 No Such
//! Table Entry, 4 Multiple Interfaces Satisfy Query — RFC 8335 section 8) and the
//! flag byte packs the State (top 3 bits), 2 Reserved bits, and the A (Active),
//! 4 (IPv4), and 6 (IPv6) status bits. The reply carries **no** extension
//! structure — it is a status response.
//!
//! The rest-of-header packing and the per-flag accessors live on the [`Icmpv6`]
//! header (see `icmp/v6/mod.rs`), so the builders here only set the type/code and
//! return a header ready to compose with the extension structure (request) or to
//! compile on its own (reply). This keeps the body model consistent with the NDP
//! builders, which also return a header / [`Packet`] from an `impl Icmpv6`.

use super::super::*;

// --- RFC 8335 ICMPv6 extended echo codepoints -----------------------------
//
// The flag-byte masks, reply codes, and State values are identical in value to
// the ICMPv4 extended-echo constants (RFC 8335 defines one shared format for
// both versions). They are re-declared here under `ICMPV6_*` names so an agent
// working with ICMPv6 finds version-explicit constants next to the ICMPv6
// builders, mirroring how the ICMPv4 side exposes the `ICMP_*` spellings. Each
// is grounded against RFC 8335 section 3 (flags) and section 8 (reply codes).

/// RFC 8335 extended echo request L-bit mask (Local bit, the rightmost bit of
/// the request flag byte): the probed interface resides on a proxy node.
pub const ICMPV6_EXTENDED_ECHO_REQUEST_L_BIT: u8 = 0x01;

/// RFC 8335 extended echo reply Active (A) flag mask in the reply flag byte.
pub const ICMPV6_EXTENDED_ECHO_REPLY_ACTIVE: u8 = 0x04;

/// RFC 8335 extended echo reply IPv4 (4) flag mask in the reply flag byte.
pub const ICMPV6_EXTENDED_ECHO_REPLY_IPV4: u8 = 0x02;

/// RFC 8335 extended echo reply IPv6 (6) flag mask in the reply flag byte.
pub const ICMPV6_EXTENDED_ECHO_REPLY_IPV6: u8 = 0x01;

/// RFC 8335 extended echo reply Code: No Error (section 8).
pub const ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_ERROR: u8 = 0;

/// RFC 8335 extended echo reply Code: Malformed Query (section 8).
pub const ICMPV6_CODE_EXTENDED_ECHO_REPLY_MALFORMED_QUERY: u8 = 1;

/// RFC 8335 extended echo reply Code: No Such Interface (section 8).
pub const ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_INTERFACE: u8 = 2;

/// RFC 8335 extended echo reply Code: No Such Table Entry (section 8).
pub const ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_TABLE_ENTRY: u8 = 3;

/// RFC 8335 extended echo reply Code: Multiple Interfaces Satisfy Query
/// (section 8).
pub const ICMPV6_CODE_EXTENDED_ECHO_REPLY_MULTIPLE_INTERFACES: u8 = 4;

/// RFC 8335 extended echo reply State value: Reserved (0).
pub const ICMPV6_EXTENDED_ECHO_REPLY_STATE_RESERVED: u8 = 0;

/// RFC 8335 extended echo reply State value: Incomplete (1).
pub const ICMPV6_EXTENDED_ECHO_REPLY_STATE_INCOMPLETE: u8 = 1;

/// RFC 8335 extended echo reply State value: Reachable (2).
pub const ICMPV6_EXTENDED_ECHO_REPLY_STATE_REACHABLE: u8 = 2;

/// RFC 8335 extended echo reply State value: Stale (3).
pub const ICMPV6_EXTENDED_ECHO_REPLY_STATE_STALE: u8 = 3;

/// RFC 8335 extended echo reply State value: Delay (4).
pub const ICMPV6_EXTENDED_ECHO_REPLY_STATE_DELAY: u8 = 4;

/// RFC 8335 extended echo reply State value: Probe (5).
pub const ICMPV6_EXTENDED_ECHO_REPLY_STATE_PROBE: u8 = 5;

/// RFC 8335 extended echo reply State value: Failed (6).
pub const ICMPV6_EXTENDED_ECHO_REPLY_STATE_FAILED: u8 = 6;

impl Icmpv6 {
    /// Build an ICMPv6 Extended Echo Request header (RFC 8335, type 160, code 0).
    ///
    /// The returned [`Icmpv6`] header carries a 16-bit identifier, an 8-bit
    /// sequence number, and a flag byte whose rightmost bit is the L-bit (the
    /// probed interface resides on a proxy node), set with [`Icmpv6::id`],
    /// [`Icmpv6::seq`], and [`Icmpv6::extended_l_bit`]. Compose the RFC 4884 ICMP
    /// Extension Structure — a single Interface Identification Object naming the
    /// probed interface — after the header with `/`, exactly like the ICMPv4
    /// request:
    ///
    /// ```
    /// use crafter::prelude::*;
    ///
    /// let request = Ipv6::new()
    ///     .src("2001:db8::10".parse().unwrap())
    ///     .dst("2001:db8::20".parse().unwrap())
    ///     / Icmpv6::extended_echo_request().id(0x1234).seq(7)
    ///     / IcmpExtension::new()
    ///     / IcmpExtensionObject::new()
    ///     / IcmpExtensionInterfaceId::by_index(42);
    /// let _bytes = request.compile().unwrap();
    /// ```
    ///
    /// `compile()` auto-fills the ICMPv6 checksum over the IPv6 pseudo-header,
    /// covering the extension structure.
    pub fn extended_echo_request() -> Self {
        Self::new().icmp_type(ICMPV6_EXTENDED_ECHO_REQUEST)
    }

    /// Build an ICMPv6 Extended Echo Reply header (RFC 8335, type 161).
    ///
    /// The reply echoes the identifier and sequence number; its `Code` reports the
    /// query result (0-4, see the `ICMPV6_CODE_EXTENDED_ECHO_REPLY_*` constants)
    /// and the flag byte carries the State, Active, IPv4, and IPv6 status bits,
    /// set with [`Icmpv6::extended_state`], [`Icmpv6::extended_active`],
    /// [`Icmpv6::extended_ipv4`], and [`Icmpv6::extended_ipv6`]. The reply carries
    /// no body of its own.
    pub fn extended_echo_reply() -> Self {
        Self::new().icmp_type(ICMPV6_EXTENDED_ECHO_REPLY)
    }
}

#[cfg(test)]
mod tests {
    use crate::protocols::icmp::{
        IcmpExtension, IcmpExtensionInterfaceId, IcmpExtensionObject, Icmpv6,
        ICMPV6_EXTENDED_ECHO_REPLY, ICMPV6_EXTENDED_ECHO_REQUEST,
        ICMP_EXTENSION_CLASS_INTERFACE_ID, ICMP_INTERFACE_ID_CTYPE_INDEX,
    };
    use crate::protocols::icmp::{
        ICMPV6_CODE_EXTENDED_ECHO_REPLY_MALFORMED_QUERY,
        ICMPV6_CODE_EXTENDED_ECHO_REPLY_MULTIPLE_INTERFACES,
        ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_ERROR,
        ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_INTERFACE,
        ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_TABLE_ENTRY,
        ICMPV6_EXTENDED_ECHO_REPLY_STATE_REACHABLE,
    };
    use crate::{Ipv6, NetworkLayer, Packet};
    use core::net::Ipv6Addr;

    fn src() -> Ipv6Addr {
        // RFC 3849 documentation prefix 2001:db8::/32.
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010)
    }

    fn dst() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0020)
    }

    // An Extended Echo Request carries its 16-bit identifier, 8-bit sequence
    // number, and flag byte in the fixed header, then an RFC 4884 extension
    // structure with a single Interface Identification Object (by ifIndex)
    // directly after the header. The whole packet round-trips and the typed
    // object surfaces the ifIndex. Mirrors the ICMPv4 extended-echo test idiom in
    // `icmp/shared/extensions.rs`.
    #[test]
    fn icmpv6_rfc8335_extended_echo_request_by_index_round_trips() {
        let compiled = (Ipv6::new().src(src()).dst(dst())
            / Icmpv6::extended_echo_request().id(0x1234).seq(7)
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_index(42))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // Fixed ICMPv6 header at offset 40 (after the 40-byte IPv6 header):
        // type 160, code 0.
        assert_eq!(bytes[40], ICMPV6_EXTENDED_ECHO_REQUEST);
        assert_eq!(bytes[41], 0);
        // Identifier (bytes 44-45), 8-bit sequence (byte 46), flag byte (byte 47).
        assert_eq!(&bytes[44..46], &0x1234u16.to_be_bytes());
        assert_eq!(bytes[46], 7);
        assert_eq!(bytes[47], 0);
        // The extension header begins immediately after the fixed header (no
        // quote, no padding): version 2.
        assert_eq!(bytes[48] >> 4, 2);
        // The object header auto-fills class 3 (Interface Identification) and
        // C-Type 2 (by index). Object header at offset 48 + 4 = 52.
        assert_eq!(bytes[54], ICMP_EXTENSION_CLASS_INTERFACE_ID);
        assert_eq!(bytes[55], ICMP_INTERFACE_ID_CTYPE_INDEX);
        // Object length: 4-byte header + 4-byte ifIndex = 8.
        assert_eq!(u16::from_be_bytes([bytes[52], bytes[53]]), 8);
        // ifIndex value.
        assert_eq!(
            u32::from_be_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]),
            42
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert_eq!(icmpv6.icmp_type_value(), ICMPV6_EXTENDED_ECHO_REQUEST);
        assert_eq!(icmpv6.identifier_value(), Some(0x1234));
        assert_eq!(icmpv6.sequence_number_value(), Some(7));
        assert_eq!(icmpv6.extended_l_bit_value(), Some(false));
        assert!(decoded.layer::<IcmpExtension>().is_some());
        let id = decoded.layer::<IcmpExtensionInterfaceId>().unwrap();
        assert_eq!(id.index_value(), Some(42));
        assert_eq!(id.c_type(), ICMP_INTERFACE_ID_CTYPE_INDEX);
        // Byte-stable re-compile.
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // The Interface Identification Object can identify by interface name (C-Type
    // 1), zero padded to a 32-bit boundary; it round-trips under the ICMPv6
    // request the same way it does under the ICMPv4 request.
    #[test]
    fn icmpv6_rfc8335_extended_echo_request_by_name_round_trips() {
        let compiled = (Ipv6::new().src(src()).dst(dst())
            / Icmpv6::extended_echo_request().id(1).seq(1)
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_name("eth0"))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let id = decoded.layer::<IcmpExtensionInterfaceId>().unwrap();
        assert_eq!(id.name_value(), Some(&b"eth0"[..]));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // The request L-bit is the rightmost bit of the flag byte and round-trips.
    #[test]
    fn icmpv6_rfc8335_extended_echo_request_l_bit_round_trips() {
        let compiled = (Ipv6::new().src(src()).dst(dst())
            / Icmpv6::extended_echo_request()
                .id(9)
                .seq(3)
                .extended_l_bit(true)
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_index(1))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // Flag byte (offset 47): only the rightmost (L) bit set.
        assert_eq!(bytes[47], 0x01);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert_eq!(icmpv6.extended_l_bit_value(), Some(true));
        // Reply-only accessors are not meaningful on a request.
        assert_eq!(icmpv6.extended_state_value(), None);
        assert_eq!(icmpv6.extended_active_value(), None);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // Every reply code (0-4) compiles and decodes, keeping its numeric code;
    // replies carry no body of their own.
    #[test]
    fn icmpv6_rfc8335_extended_echo_reply_all_codes_round_trip() {
        let codes = [
            ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_ERROR,
            ICMPV6_CODE_EXTENDED_ECHO_REPLY_MALFORMED_QUERY,
            ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_INTERFACE,
            ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_TABLE_ENTRY,
            ICMPV6_CODE_EXTENDED_ECHO_REPLY_MULTIPLE_INTERFACES,
        ];
        for code in codes {
            let compiled = (Ipv6::new().src(src()).dst(dst())
                / Icmpv6::extended_echo_reply().id(0xabcd).seq(5).code(code))
            .compile()
            .unwrap();

            let bytes = compiled.as_bytes();
            assert_eq!(bytes[40], ICMPV6_EXTENDED_ECHO_REPLY);
            assert_eq!(bytes[41], code);

            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
            let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
            assert_eq!(icmpv6.code_value(), code);
            assert_eq!(icmpv6.identifier_value(), Some(0xabcd));
            assert_eq!(icmpv6.sequence_number_value(), Some(5));
            assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
        }
    }

    // The reply flag byte packs State (3 bits), 2 Reserved bits, and the A/4/6
    // status bits; each typed accessor surfaces its field and the byte
    // round-trips. Here: State Reachable, Active, IPv6 reachable (IPv4 not).
    #[test]
    fn icmpv6_rfc8335_extended_echo_reply_state_and_flags_round_trip() {
        let compiled = (Ipv6::new().src(src()).dst(dst())
            / Icmpv6::extended_echo_reply()
                .code(ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_ERROR)
                .extended_state(ICMPV6_EXTENDED_ECHO_REPLY_STATE_REACHABLE)
                .extended_active(true)
                .extended_ipv4(false)
                .extended_ipv6(true))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // State 2 in bits 5-7 (0b010 << 5 = 0x40), A bit (0x04), 6 bit (0x01).
        assert_eq!(bytes[47], 0x40 | 0x04 | 0x01);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        assert_eq!(
            icmpv6.extended_state_value(),
            Some(ICMPV6_EXTENDED_ECHO_REPLY_STATE_REACHABLE)
        );
        assert_eq!(icmpv6.extended_active_value(), Some(true));
        assert_eq!(icmpv6.extended_ipv4_value(), Some(false));
        assert_eq!(icmpv6.extended_ipv6_value(), Some(true));
        // Request-only accessor is not meaningful on a reply.
        assert_eq!(icmpv6.extended_l_bit_value(), None);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // An explicit raw flag byte survives compilation untouched, including
    // Reserved bits the typed setters do not expose (honored-overrides rule).
    #[test]
    fn icmpv6_rfc8335_extended_echo_explicit_flag_byte_preserved() {
        let compiled = (Ipv6::new().src(src()).dst(dst())
            / Icmpv6::extended_echo_request()
                .id(1)
                .seq(1)
                .extended_flags(0xa5)
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_index(7))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        assert_eq!(bytes[47], 0xa5);
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes).unwrap();
        assert_eq!(
            decoded.layer::<Icmpv6>().unwrap().extended_flags_value(),
            Some(0xa5)
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }
}
