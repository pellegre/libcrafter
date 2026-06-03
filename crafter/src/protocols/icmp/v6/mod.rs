//! ICMPv6 layer implementation.
//!
//! Moved out of `icmp/icmpv6.rs` into the `icmp/v6/` subtree so ICMPv6 sits as a
//! sibling of the ICMPv4 code in `icmp/v4/` under the shared core. This holds the
//! [`Icmpv6`] header struct and its builder/decode/compile impls plus the ICMPv6
//! (`ICMPV6_*`) codepoint constants (in `v6/constants.rs`). Shared compile/
//! auto-fill helpers, the version-neutral [`IcmpKind`]/[`IcmpLayer`] contract,
//! and the codepoint naming/predicate helpers are reached through the `icmp`
//! module root (`use super::*;`), one level above which this file now lives.
//! This is a pure internal move:
//! `crate::protocols::icmp::Icmpv6`, the `protocols::mod.rs` re-exports, the
//! registry IPv6 next-header 58 binding, and the prelude all keep resolving to
//! the same names.

use super::*;
use crate::endian::read_u16_be;

// The ICMPv6 (`ICMPV6_*`) codepoint constants used below live in
// `v6/constants.rs`. They are reached through the `use super::*;` glob above:
// `icmp/mod.rs` re-exports them at the root (`pub use self::constants::*;`),
// which in turn re-exports `super::v6::constants::*`.
pub(crate) mod constants;

// The typed ICMPv6 message-body model ([`Icmpv6Body`] / [`Icmpv6ErrorBody`]),
// dispatched by the `type` byte the way ICMPv4 dispatches its bodies. The
// `Icmpv6` header below routes through it for classification, `summary()`, and
// `show()`. Re-exported at the `icmp` root so it surfaces through
// `protocols::mod.rs` and the prelude like the other ICMPv6 types.
mod body;
pub use self::body::{Icmpv6Body, Icmpv6ErrorBody};

// ICMPv6-specific message bodies (Neighbor Discovery, MLD, node information,
// extended echo) live under `v6/message/`. This step adds the shared Neighbor
// Discovery option TLV framework ([`NdpOption`] / [`NdpOptions`] and the
// `NDP_OPT_*` codepoints) per RFC 4861 section 4.6; later steps grow the
// concrete message bodies. Re-exported at the `icmp` root (and onward through
// `protocols::mod.rs` and the prelude) like the other ICMPv6 types.
mod message;
// RFC 8335 ICMPv6 extended echo (types 160/161). The builders live in
// `message/extended_echo.rs` (an `impl Icmpv6` that sets the type/code, like the
// NDP builders); the flag-byte masks, reply codes, and State values are
// re-exported here so the header's own rest-of-header packing and the typed
// flag accessors in this file resolve them, and so the `icmp` root surfaces them
// like the other ICMPv6 codepoints.
pub use self::message::extended_echo::{
    ICMPV6_CODE_EXTENDED_ECHO_REPLY_MALFORMED_QUERY,
    ICMPV6_CODE_EXTENDED_ECHO_REPLY_MULTIPLE_INTERFACES, ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_ERROR,
    ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_INTERFACE,
    ICMPV6_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_TABLE_ENTRY, ICMPV6_EXTENDED_ECHO_REPLY_ACTIVE,
    ICMPV6_EXTENDED_ECHO_REPLY_IPV4, ICMPV6_EXTENDED_ECHO_REPLY_IPV6,
    ICMPV6_EXTENDED_ECHO_REPLY_STATE_DELAY, ICMPV6_EXTENDED_ECHO_REPLY_STATE_FAILED,
    ICMPV6_EXTENDED_ECHO_REPLY_STATE_INCOMPLETE, ICMPV6_EXTENDED_ECHO_REPLY_STATE_PROBE,
    ICMPV6_EXTENDED_ECHO_REPLY_STATE_REACHABLE, ICMPV6_EXTENDED_ECHO_REPLY_STATE_RESERVED,
    ICMPV6_EXTENDED_ECHO_REPLY_STATE_STALE, ICMPV6_EXTENDED_ECHO_REQUEST_L_BIT,
};
// MLDv1 (RFC 2710, types 130-132): one body type reused across Query / Report /
// Done, distinguished by the header `type`. The builders live in
// `message/mld.rs` (an `impl Icmpv6`, like the NDP builders); re-export the body
// type and its decoder so the `icmp` root surfaces it and the decode dispatch
// below reaches it.
pub(crate) use self::message::mld::decode_multicast_listener_message;
pub use self::message::mld::MulticastListenerMessage;
pub(crate) use self::message::ndp::{
    decode_neighbor_advertisement, decode_neighbor_solicitation, decode_redirect,
    decode_router_advertisement, decode_router_solicitation,
};
pub use self::message::ndp::{
    NeighborAdvertisement, NeighborSolicitation, Redirect, RouterAdvertisement, RouterSolicitation,
    ICMPV6_NA_FLAGS_RESERVED, ICMPV6_NA_FLAG_OVERRIDE, ICMPV6_NA_FLAG_ROUTER,
    ICMPV6_NA_FLAG_SOLICITED, ICMPV6_RA_DEFAULT_CUR_HOP_LIMIT, ICMPV6_RA_DEFAULT_ROUTER_LIFETIME,
    ICMPV6_RA_FLAGS_RESERVED, ICMPV6_RA_FLAG_MANAGED, ICMPV6_RA_FLAG_OTHER,
};
pub use self::message::ndp_option::{
    ndp_option_type_is_known, ndp_option_type_name, ndp_rdnss_length_units, NdpOption, NdpOptions,
    Pref64Plc, Prf, NDP_DNS_LIFETIME_INFINITY, NDP_DNS_RESERVED_LEN,
    NDP_LINK_LAYER_ADDR_ETHERNET_LEN, NDP_MTU_OPTION_LEN, NDP_MTU_OPTION_UNITS, NDP_NONCE_MIN_LEN,
    NDP_OPTION_HEADER_LEN, NDP_OPTION_LENGTH_UNIT, NDP_OPT_CAPTIVE_PORTAL, NDP_OPT_DNSSL,
    NDP_OPT_MTU, NDP_OPT_NONCE, NDP_OPT_PREF64, NDP_OPT_PREFIX_INFORMATION,
    NDP_OPT_RA_FLAGS_EXTENSION, NDP_OPT_RDNSS, NDP_OPT_REDIRECTED_HEADER,
    NDP_OPT_ROUTE_INFORMATION, NDP_OPT_SOURCE_LINK_LAYER_ADDR, NDP_OPT_TARGET_LINK_LAYER_ADDR,
    NDP_PREF64_LEN, NDP_PREF64_PLC_MASK, NDP_PREF64_PREFIX_LEN, NDP_PREF64_SCALED_LIFETIME_MAX,
    NDP_PREF64_SCALED_LIFETIME_SHIFT, NDP_PREF64_UNITS, NDP_PREFIX_FLAGS_RESERVED,
    NDP_PREFIX_FLAG_AUTONOMOUS, NDP_PREFIX_FLAG_ON_LINK, NDP_PREFIX_INFORMATION_LEN,
    NDP_PREFIX_INFORMATION_UNITS, NDP_PREFIX_LIFETIME_INFINITY, NDP_PRF_MASK, NDP_PRF_SHIFT,
    NDP_RA_FLAGS_EXTENSION_BITS_LEN, NDP_RA_FLAGS_EXTENSION_LEN, NDP_RA_FLAGS_EXTENSION_UNITS,
    NDP_RDNSS_ADDRESS_LEN, NDP_REDIRECTED_HEADER_RESERVED_LEN,
    NDP_ROUTE_INFORMATION_LEN_FULL_PREFIX, NDP_ROUTE_INFORMATION_LEN_HALF_PREFIX,
    NDP_ROUTE_INFORMATION_LEN_NO_PREFIX, NDP_ROUTE_LIFETIME_INFINITY,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv6 {
    icmp_type: Field<u8>,
    code: Field<u8>,
    checksum: Field<u16>,
    rest_of_header: Field<[u8; 4]>,
    identifier: Field<u16>,
    sequence_number: Field<u16>,
    length: Field<u8>,
    mtu: Field<u32>,
    pointer: Field<u32>,
    // RFC 8335 extended echo flag byte (the fourth byte of the rest-of-header):
    // the L-bit for an Extended Echo Request and the State/A/4/6 status bits for
    // an Extended Echo Reply. Carried on the header (like the identifier and
    // sequence number) because it lives in the fixed rest-of-header; the typed
    // builders/accessors live in `message/extended_echo.rs`.
    extended_flags: Field<u8>,
}

impl Icmpv6 {
    /// Create an ICMPv6 echo-request header with deterministic defaults.
    pub fn new() -> Self {
        Self {
            icmp_type: Field::defaulted(ICMPV6_ECHO_REQUEST),
            code: Field::defaulted(0),
            checksum: Field::unset(),
            rest_of_header: Field::defaulted([0; 4]),
            identifier: Field::defaulted(0),
            sequence_number: Field::defaulted(0),
            length: Field::unset(),
            mtu: Field::unset(),
            pointer: Field::unset(),
            extended_flags: Field::unset(),
        }
    }

    /// Create an echo request.
    pub fn echo_request() -> Self {
        Self::new().kind(IcmpKind::EchoRequest)
    }

    /// Create an echo reply.
    pub fn echo_reply() -> Self {
        Self::new().kind(IcmpKind::EchoReply)
    }

    /// Create a time-exceeded message.
    pub fn time_exceeded() -> Self {
        Self::new().kind(IcmpKind::TimeExceeded)
    }

    /// Create a destination-unreachable message.
    pub fn destination_unreachable() -> Self {
        Self::new().kind(IcmpKind::DestinationUnreachable)
    }

    /// Create a packet-too-big message.
    pub fn packet_too_big() -> Self {
        Self::new().icmp_type(ICMPV6_PACKET_TOO_BIG)
    }

    /// Set the ICMPv6 type from a common kind.
    pub fn kind(mut self, kind: IcmpKind) -> Self {
        self.icmp_type.set_user(kind.ipv6_type());
        self
    }

    /// Set the raw ICMPv6 type.
    pub fn icmp_type(mut self, icmp_type: u8) -> Self {
        self.icmp_type.set_user(icmp_type);
        self
    }

    /// Alias for generated code that wants the protocol field name.
    pub fn type_(self, icmp_type: u8) -> Self {
        self.icmp_type(icmp_type)
    }

    /// Set the ICMPv6 code.
    pub fn code(mut self, code: u8) -> Self {
        self.code.set_user(code);
        self
    }

    /// Set the checksum explicitly.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum.set_user(checksum);
        self
    }

    /// Compatibility alias for checksum.
    pub fn chksum(self, checksum: u16) -> Self {
        self.checksum(checksum)
    }

    /// Set the raw four-byte rest-of-header field.
    pub fn rest_of_header(mut self, rest_of_header: [u8; 4]) -> Self {
        self.rest_of_header.set_user(rest_of_header);
        self
    }

    /// Set the echo identifier.
    pub fn identifier(mut self, identifier: u16) -> Self {
        self.identifier.set_user(identifier);
        self
    }

    /// Compatibility alias for identifier.
    pub fn id(self, identifier: u16) -> Self {
        self.identifier(identifier)
    }

    /// Set the echo sequence number.
    pub fn sequence_number(mut self, sequence_number: u16) -> Self {
        self.sequence_number.set_user(sequence_number);
        self
    }

    /// Compatibility alias for sequence number.
    pub fn seq(self, sequence_number: u16) -> Self {
        self.sequence_number(sequence_number)
    }

    /// Set the RFC 4884 original datagram length field explicitly.
    pub fn length(mut self, length: u8) -> Self {
        self.length.set_user(length);
        self
    }

    /// Compatibility alias for RFC 4884 length.
    pub fn len(self, length: u8) -> Self {
        self.length(length)
    }

    /// Set the packet-too-big MTU field.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu.set_user(mtu);
        self
    }

    /// Set the parameter-problem pointer field.
    pub fn pointer(mut self, pointer: u32) -> Self {
        self.pointer.set_user(pointer);
        self
    }

    /// Set the raw RFC 8335 extended echo flag byte (the fourth byte of the
    /// rest-of-header) explicitly.
    ///
    /// This is the escape hatch for crafting reserved bits and flag combinations
    /// the typed builders do not expose; an explicit byte survives compilation
    /// untouched. The typed setters ([`Icmpv6::extended_l_bit`],
    /// [`Icmpv6::extended_state`], [`Icmpv6::extended_active`],
    /// [`Icmpv6::extended_ipv4`], [`Icmpv6::extended_ipv6`]) build on it.
    pub fn extended_flags(mut self, extended_flags: u8) -> Self {
        self.extended_flags.set_user(extended_flags);
        self
    }

    /// Set the RFC 8335 extended echo request L-bit (the probed interface is on
    /// a proxy node).
    ///
    /// The L-bit is the rightmost bit of the request flag byte (RFC 8335 section
    /// 3); the other seven Reserved bits are left untouched (use
    /// [`Icmpv6::extended_flags`] to set Reserved bits deliberately).
    pub fn extended_l_bit(mut self, set: bool) -> Self {
        let base = self.extended_flags.value().copied().unwrap_or(0);
        let value = if set {
            base | ICMPV6_EXTENDED_ECHO_REQUEST_L_BIT
        } else {
            base & !ICMPV6_EXTENDED_ECHO_REQUEST_L_BIT
        };
        self.extended_flags.set_user(value);
        self
    }

    /// Set the RFC 8335 extended echo reply State field (3 bits, occupying the
    /// top of the reply flag byte).
    pub fn extended_state(mut self, state: u8) -> Self {
        let base = self.extended_flags.value().copied().unwrap_or(0);
        let value = (base & 0x1f) | ((state & 0x07) << 5);
        self.extended_flags.set_user(value);
        self
    }

    /// Set the RFC 8335 extended echo reply Active (A) flag.
    pub fn extended_active(mut self, set: bool) -> Self {
        let base = self.extended_flags.value().copied().unwrap_or(0);
        let value = if set {
            base | ICMPV6_EXTENDED_ECHO_REPLY_ACTIVE
        } else {
            base & !ICMPV6_EXTENDED_ECHO_REPLY_ACTIVE
        };
        self.extended_flags.set_user(value);
        self
    }

    /// Set the RFC 8335 extended echo reply IPv4 (4) flag.
    pub fn extended_ipv4(mut self, set: bool) -> Self {
        let base = self.extended_flags.value().copied().unwrap_or(0);
        let value = if set {
            base | ICMPV6_EXTENDED_ECHO_REPLY_IPV4
        } else {
            base & !ICMPV6_EXTENDED_ECHO_REPLY_IPV4
        };
        self.extended_flags.set_user(value);
        self
    }

    /// Set the RFC 8335 extended echo reply IPv6 (6) flag.
    pub fn extended_ipv6(mut self, set: bool) -> Self {
        let base = self.extended_flags.value().copied().unwrap_or(0);
        let value = if set {
            base | ICMPV6_EXTENDED_ECHO_REPLY_IPV6
        } else {
            base & !ICMPV6_EXTENDED_ECHO_REPLY_IPV6
        };
        self.extended_flags.set_user(value);
        self
    }

    /// Raw ICMPv6 type value.
    pub fn icmp_type_value(&self) -> u8 {
        value_or_copy(&self.icmp_type, ICMPV6_ECHO_REQUEST)
    }

    /// ICMPv6 code value.
    pub fn code_value(&self) -> u8 {
        value_or_copy(&self.code, 0)
    }

    /// Stored checksum value, when explicit or decoded.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    /// Identifier value when meaningful for the current type.
    ///
    /// Surfaced for the RFC 4443 echo messages and for the RFC 8335 extended echo
    /// messages, both of which carry a 16-bit identifier in the first half of the
    /// rest-of-header.
    pub fn identifier_value(&self) -> Option<u16> {
        let icmp_type = self.icmp_type_value();
        if is_echo_v6(icmp_type) || is_extended_echo_v6(icmp_type) {
            Some(value_or_u16_from_rest(
                &self.identifier,
                &self.rest_of_header,
                0,
            ))
        } else {
            None
        }
    }

    /// Sequence number when meaningful for the current type.
    ///
    /// Surfaced for the RFC 4443 echo messages as a 16-bit value, and for the
    /// RFC 8335 extended echo messages as an 8-bit value (the third byte of the
    /// rest-of-header, zero-extended here; the fourth byte is the flag byte).
    pub fn sequence_number_value(&self) -> Option<u16> {
        let icmp_type = self.icmp_type_value();
        if is_extended_echo_v6(icmp_type) {
            Some(u16::from(value_or_u8_from_rest(
                &self.extended_sequence_number_byte(),
                &self.rest_of_header,
                2,
            )))
        } else if is_echo_v6(icmp_type) {
            Some(value_or_u16_from_rest(
                &self.sequence_number,
                &self.rest_of_header,
                2,
            ))
        } else {
            None
        }
    }

    /// Raw four-byte rest-of-header value after applying typed fields.
    pub fn rest_of_header_value(&self) -> [u8; 4] {
        self.effective_rest_of_header(None, 8).unwrap_or([0; 4])
    }

    /// RFC 4884 length field when explicit or decoded.
    pub fn length_value(&self) -> Option<u8> {
        self.length.value().copied()
    }

    /// RFC 8335 extended echo flag byte (the fourth byte of the rest-of-header)
    /// when the type is an extended echo request or reply.
    ///
    /// The byte is surfaced verbatim so Reserved bits stay inspectable; the typed
    /// accessors below interpret the individual flags.
    pub fn extended_flags_value(&self) -> Option<u8> {
        if is_extended_echo_v6(self.icmp_type_value()) {
            Some(value_or_u8_from_rest(
                &self.extended_flags,
                &self.rest_of_header,
                3,
            ))
        } else {
            None
        }
    }

    /// RFC 8335 extended echo request L-bit when the type is an extended echo
    /// request.
    pub fn extended_l_bit_value(&self) -> Option<bool> {
        if self.icmp_type_value() == ICMPV6_EXTENDED_ECHO_REQUEST {
            self.extended_flags_value()
                .map(|flags| flags & ICMPV6_EXTENDED_ECHO_REQUEST_L_BIT != 0)
        } else {
            None
        }
    }

    /// RFC 8335 extended echo reply State field (3 bits) when the type is an
    /// extended echo reply.
    pub fn extended_state_value(&self) -> Option<u8> {
        if self.icmp_type_value() == ICMPV6_EXTENDED_ECHO_REPLY {
            self.extended_flags_value().map(|flags| (flags >> 5) & 0x07)
        } else {
            None
        }
    }

    /// RFC 8335 extended echo reply Active (A) flag when the type is an extended
    /// echo reply.
    pub fn extended_active_value(&self) -> Option<bool> {
        if self.icmp_type_value() == ICMPV6_EXTENDED_ECHO_REPLY {
            self.extended_flags_value()
                .map(|flags| flags & ICMPV6_EXTENDED_ECHO_REPLY_ACTIVE != 0)
        } else {
            None
        }
    }

    /// RFC 8335 extended echo reply IPv4 (4) flag when the type is an extended
    /// echo reply.
    pub fn extended_ipv4_value(&self) -> Option<bool> {
        if self.icmp_type_value() == ICMPV6_EXTENDED_ECHO_REPLY {
            self.extended_flags_value()
                .map(|flags| flags & ICMPV6_EXTENDED_ECHO_REPLY_IPV4 != 0)
        } else {
            None
        }
    }

    /// RFC 8335 extended echo reply IPv6 (6) flag when the type is an extended
    /// echo reply.
    pub fn extended_ipv6_value(&self) -> Option<bool> {
        if self.icmp_type_value() == ICMPV6_EXTENDED_ECHO_REPLY {
            self.extended_flags_value()
                .map(|flags| flags & ICMPV6_EXTENDED_ECHO_REPLY_IPV6 != 0)
        } else {
            None
        }
    }

    /// Common ICMP kind, when the type is version-independent.
    pub fn kind_value(&self) -> Option<IcmpKind> {
        match self.icmp_type_value() {
            ICMPV6_DESTINATION_UNREACHABLE => Some(IcmpKind::DestinationUnreachable),
            ICMPV6_TIME_EXCEEDED => Some(IcmpKind::TimeExceeded),
            ICMPV6_PARAMETER_PROBLEM => Some(IcmpKind::ParameterProblem),
            ICMPV6_ECHO_REQUEST => Some(IcmpKind::EchoRequest),
            ICMPV6_ECHO_REPLY => Some(IcmpKind::EchoReply),
            _ => None,
        }
    }

    /// The typed message body this header carries, dispatched by the ICMPv6
    /// `type`.
    ///
    /// This is the ICMPv6 analogue of the ICMPv4 type-dispatched body model: it
    /// classifies the message (echo / error / unknown) and surfaces the
    /// type-specific rest-of-header fields as a typed [`Icmpv6Body`]. The body is
    /// a view derived from the header's fields, so reading it never changes the
    /// bytes the header emits; later steps grow it with the NDP, MLD,
    /// node-information, and extended-echo families.
    pub fn body(&self) -> Icmpv6Body {
        Icmpv6Body::from_header(self)
    }

    fn effective_rest_of_header(
        &self,
        ctx: Option<LayerContext<'_>>,
        extension_unit: usize,
    ) -> Result<[u8; 4]> {
        // Same precedence rule as ICMPv4: an explicit raw rest-of-header is the
        // base, and auto-filled typed values never overwrite it.
        let raw_is_user = self.rest_of_header.is_user_set();
        let mut rest = value_or_copy(&self.rest_of_header, [0; 4]);

        match self.icmp_type_value() {
            ICMPV6_ECHO_REQUEST | ICMPV6_ECHO_REPLY => {
                if self.identifier.is_user_set() || !raw_is_user {
                    let identifier =
                        value_or_u16_from_rest(&self.identifier, &self.rest_of_header, 0);
                    rest[..2].copy_from_slice(&identifier.to_be_bytes());
                }
                if self.sequence_number.is_user_set() || !raw_is_user {
                    let sequence =
                        value_or_u16_from_rest(&self.sequence_number, &self.rest_of_header, 2);
                    rest[2..4].copy_from_slice(&sequence.to_be_bytes());
                }
            }
            ICMPV6_DESTINATION_UNREACHABLE | ICMPV6_TIME_EXCEEDED => {
                if let Some(length) =
                    self.overriding_extension_length(ctx, extension_unit, raw_is_user)?
                {
                    rest[0] = length;
                }
            }
            ICMPV6_PACKET_TOO_BIG => {
                if self.mtu.is_user_set() || !raw_is_user {
                    if let Some(mtu) = self.mtu.value().copied() {
                        rest.copy_from_slice(&mtu.to_be_bytes());
                    }
                }
            }
            ICMPV6_PARAMETER_PROBLEM => {
                if self.pointer.is_user_set() || !raw_is_user {
                    if let Some(pointer) = self.pointer.value().copied() {
                        rest.copy_from_slice(&pointer.to_be_bytes());
                    }
                }
            }
            ICMPV6_EXTENDED_ECHO_REQUEST | ICMPV6_EXTENDED_ECHO_REPLY => {
                // RFC 8335 section 3: identifier (bytes 0-1), an 8-bit sequence
                // number (byte 2), and a flag byte (byte 3). The flag byte holds
                // the L-bit for requests and State/A/4/6 for replies; the typed
                // builders pre-pack it into `extended_flags`. This mirrors the
                // ICMPv4 extended-echo rest-of-header layout exactly (the only
                // wire difference is the type number and the IPv6-pseudo-header
                // checksum, which `compile()` already handles).
                if self.identifier.is_user_set() || !raw_is_user {
                    let identifier =
                        value_or_u16_from_rest(&self.identifier, &self.rest_of_header, 0);
                    rest[..2].copy_from_slice(&identifier.to_be_bytes());
                }
                if self.sequence_number.is_user_set() || !raw_is_user {
                    let sequence = value_or_u8_from_rest(
                        &self.extended_sequence_number_byte(),
                        &self.rest_of_header,
                        2,
                    );
                    rest[2] = sequence;
                }
                if self.extended_flags.is_user_set() || !raw_is_user {
                    if let Some(flags) = self.extended_flags.value().copied() {
                        rest[3] = flags;
                    }
                }
            }
            _ => {}
        }

        Ok(rest)
    }

    /// The RFC 8335 8-bit sequence number as a `Field<u8>` derived from the
    /// 16-bit `sequence_number` field: a user-set sequence number contributes its
    /// low octet, otherwise the field stays unset so the rest-of-header supplies
    /// the byte. Mirrors the ICMPv4 `sequence_number_byte` helper.
    fn extended_sequence_number_byte(&self) -> Field<u8> {
        match self.sequence_number.value().copied() {
            Some(value) => Field::user(value as u8),
            None => Field::unset(),
        }
    }

    /// RFC 4884 length byte that should override the raw rest-of-header.
    fn overriding_extension_length(
        &self,
        ctx: Option<LayerContext<'_>>,
        extension_unit: usize,
        raw_is_user: bool,
    ) -> Result<Option<u8>> {
        if self.length.is_user_set() {
            return Ok(self.length.value().copied());
        }
        if raw_is_user {
            return Ok(None);
        }
        self.effective_extension_length(ctx, extension_unit)
    }

    fn effective_extension_length(
        &self,
        ctx: Option<LayerContext<'_>>,
        unit: usize,
    ) -> Result<Option<u8>> {
        if let Some(length) = self.length.value().copied() {
            return Ok(Some(length));
        }
        let Some(ctx) = ctx else {
            return Ok(None);
        };
        if !icmpv6_type_allows_extensions(self.icmp_type_value()) {
            return Ok(None);
        }

        let len = encoded_len_until_extension(ctx);
        u8::try_from(len / unit).map(Some).map_err(|_| {
            CrafterError::invalid_field_value(
                "icmpv6.length",
                "ICMPv6 original datagram length does not fit in one byte",
            )
        })
    }

    fn effective_checksum(&self, ctx: LayerContext<'_>, header: &[u8], payload: &[u8]) -> u16 {
        if let Some(checksum) = self.checksum.value().copied() {
            return checksum;
        }

        let mut segment = Vec::with_capacity(header.len() + payload.len());
        segment.extend_from_slice(header);
        segment.extend_from_slice(payload);
        checksum_context(ctx, IPPROTO_ICMPV6)
            .map(|pseudo_header| pseudo_header.checksum(&segment))
            .unwrap_or(0)
    }
}

impl Default for Icmpv6 {
    fn default() -> Self {
        Self::new()
    }
}

impl IcmpLayer for Icmpv6 {
    fn icmp_type_value(&self) -> u8 {
        Icmpv6::icmp_type_value(self)
    }

    fn code_value(&self) -> u8 {
        Icmpv6::code_value(self)
    }

    fn checksum_value(&self) -> Option<u16> {
        Icmpv6::checksum_value(self)
    }

    fn identifier_value(&self) -> Option<u16> {
        Icmpv6::identifier_value(self)
    }

    fn sequence_number_value(&self) -> Option<u16> {
        Icmpv6::sequence_number_value(self)
    }

    fn kind(&self) -> Option<IcmpKind> {
        self.kind_value()
    }
}

impl Layer for Icmpv6 {
    fn name(&self) -> &'static str {
        "Icmpv6"
    }

    fn summary(&self) -> String {
        format!(
            "Icmpv6(type={}, code={}, id={}, seq={})",
            icmpv6_type_summary(self.icmp_type_value()),
            self.code_value(),
            self.identifier_value()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.sequence_number_value()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string())
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let body = self.body();
        vec![
            ("type", icmpv6_type_summary(self.icmp_type_value())),
            ("code", self.code_value().to_string()),
            ("body", body.detail()),
            (
                "checksum",
                self.checksum_value()
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("rest_of_header", hex_bytes(&self.rest_of_header_value())),
            (
                "identifier",
                self.identifier_value()
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "sequence_number",
                self.sequence_number_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "length",
                self.length_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_HEADER_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let payload = payload_bytes_after(*ctx)?;
        let mut header = Vec::with_capacity(ICMP_HEADER_LEN);
        header.push(self.icmp_type_value());
        header.push(self.code_value());
        header.extend_from_slice(&0u16.to_be_bytes());
        header.extend_from_slice(&self.effective_rest_of_header(Some(*ctx), 8)?);

        let checksum = self.effective_checksum(*ctx, &header, &payload);
        header[2..4].copy_from_slice(&checksum.to_be_bytes());
        out.extend_from_slice(&header);
        Ok(())
    }

    impl_layer_object!(Icmpv6);
}

impl_layer_div!(Icmpv6);

fn decode_icmpv6_parts(bytes: &[u8]) -> Result<(Icmpv6, &[u8])> {
    if bytes.len() < ICMP_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "icmpv6 header",
            ICMP_HEADER_LEN,
            bytes.len(),
        ));
    }

    let rest = copy_array_4(&bytes[4..8]);
    let icmp_type = bytes[0];
    let is_extended_echo = is_extended_echo_v6(icmp_type);
    let icmpv6 = Icmpv6 {
        icmp_type: Field::user(icmp_type),
        code: Field::user(bytes[1]),
        checksum: Field::user(read_u16_be(&bytes[2..4])?),
        rest_of_header: Field::user(rest),
        // RFC 8335 narrows the sequence number to a single octet (byte 2) and
        // adds a flag byte (byte 3), but the identifier is still the 16-bit
        // bytes 0..2, so the identifier field is shared with the echo families.
        identifier: if is_echo_v6(icmp_type) || is_extended_echo {
            Field::user(u16::from_be_bytes([rest[0], rest[1]]))
        } else {
            Field::unset()
        },
        sequence_number: if is_extended_echo {
            // Zero-extend the 8-bit RFC 8335 sequence number into the low octet;
            // the accessor/serialize path treat it as an 8-bit value for these
            // types so the flag byte (byte 3) is never folded in.
            Field::user(u16::from(rest[2]))
        } else {
            field_from_echo(icmp_type, &rest, 2, is_echo_v6)
        },
        length: if icmpv6_type_allows_extensions(icmp_type) {
            Field::user(rest[0])
        } else {
            Field::unset()
        },
        mtu: if icmp_type == ICMPV6_PACKET_TOO_BIG {
            Field::user(u32::from_be_bytes(rest))
        } else {
            Field::unset()
        },
        pointer: if icmp_type == ICMPV6_PARAMETER_PROBLEM {
            Field::user(u32::from_be_bytes(rest))
        } else {
            Field::unset()
        },
        extended_flags: if is_extended_echo {
            Field::user(rest[3])
        } else {
            Field::unset()
        },
    };

    Ok((icmpv6, &bytes[ICMP_HEADER_LEN..]))
}

/// Append a decoded ICMPv6 packet to an existing packet stack.
pub(crate) fn append_icmpv6_packet(mut packet: Packet, bytes: &[u8]) -> Result<Packet> {
    let (icmpv6, payload) = decode_icmpv6_parts(bytes)?;
    let icmp_type = icmpv6.icmp_type_value();
    packet = packet.push(icmpv6);

    // RFC 4861 Neighbor Discovery messages carry a typed body after the fixed
    // header (for a Router Solicitation: the NDP option area; the 32-bit
    // Reserved field is the header's rest-of-header, decoded with the header).
    // Type the body whenever the header is a recognized NDP message and the
    // option area parses defensibly — even when the area is empty, so a bare
    // Router Solicitation still exposes its typed body. A malformed option area
    // (a zero-length or overrunning option) keeps the bytes as a single `Raw`
    // payload so nothing is dropped and decoding never panics. Later steps add
    // the remaining NDP/MLD/extended-echo bodies here in lockstep with the
    // `Icmpv6Body` classifier in `body.rs`.
    // RFC 2710 MLDv1 (types 130-132): the Maximum Response Delay and Reserved
    // fields were decoded with the header above; the trailing body is the 16-byte
    // Multicast Address. The three types share one body shape, so they share a
    // decoder. The MLDv1 Query (130) is disambiguated from the MLDv2 Query (added
    // in step 28) by body length: an MLDv1 body is *exactly* 16 bytes, while an
    // MLDv2 query body is longer. `decode_multicast_listener_message` enforces the
    // exact-16-byte shape, so a longer (MLDv2) type-130 body falls through to the
    // `Raw` tail here for now; step 28 inserts the longer-body MLDv2-query branch.
    if icmp_type == ICMPV6_MULTICAST_LISTENER_QUERY
        || icmp_type == ICMPV6_MULTICAST_LISTENER_REPORT
        || icmp_type == ICMPV6_MULTICAST_LISTENER_DONE
    {
        if let Ok(mld) = decode_multicast_listener_message(payload) {
            return Ok(packet.push(mld));
        }
    }

    if icmp_type == ICMPV6_ROUTER_SOLICITATION {
        if let Ok(rs) = decode_router_solicitation(payload) {
            return Ok(packet.push(rs));
        }
    }

    // RFC 4861 section 4.2 Router Advertisement: the rest-of-header (Cur Hop
    // Limit / M+O flags / Router Lifetime) was decoded with the header above;
    // the trailing body is the Reachable-Time + Retrans-Timer words and the NDP
    // option area. A body too short for the two timer words, or a malformed
    // option area, keeps the bytes as a single `Raw` payload (no panic, nothing
    // dropped).
    if icmp_type == ICMPV6_ROUTER_ADVERTISEMENT {
        if let Ok(ra) = decode_router_advertisement(payload) {
            return Ok(packet.push(ra));
        }
    }

    // RFC 4861 section 4.3 Neighbor Solicitation: the rest-of-header (the 32-bit
    // Reserved field) was decoded with the header above; the trailing body is the
    // 128-bit Target Address followed by the NDP option area. A body too short for
    // the Target Address, or a malformed option area, keeps the bytes as a single
    // `Raw` payload (no panic, nothing dropped).
    if icmp_type == ICMPV6_NEIGHBOR_SOLICITATION {
        if let Ok(ns) = decode_neighbor_solicitation(payload) {
            return Ok(packet.push(ns));
        }
    }

    // RFC 4861 section 4.4 Neighbor Advertisement: the rest-of-header (the 32-bit
    // R/S/O flags word with its 29 Reserved bits) was decoded with the header
    // above; the trailing body is the 128-bit Target Address followed by the NDP
    // option area. A body too short for the Target Address, or a malformed option
    // area, keeps the bytes as a single `Raw` payload (no panic, nothing dropped).
    if icmp_type == ICMPV6_NEIGHBOR_ADVERTISEMENT {
        if let Ok(na) = decode_neighbor_advertisement(payload) {
            return Ok(packet.push(na));
        }
    }

    // RFC 4861 section 4.5 Redirect: the rest-of-header (the 32-bit Reserved
    // field) was decoded with the header above; the trailing body is the 128-bit
    // Target Address, the 128-bit Destination Address, and the NDP option area
    // (commonly a Target Link-Layer Address and a Redirected Header option). A
    // body too short for both addresses, or a malformed option area, keeps the
    // bytes as a single `Raw` payload (no panic, nothing dropped).
    if icmp_type == ICMPV6_REDIRECT {
        if let Ok(redirect) = decode_redirect(payload) {
            return Ok(packet.push(redirect));
        }
    }

    // RFC 8335 section 3 Extended Echo Request (160): the identifier / sequence /
    // L-bit live in the rest-of-header (decoded with the header above); the
    // trailing body is an RFC 4884 ICMP Extension Structure carrying a single
    // Interface Identification Object, beginning immediately after the fixed
    // header (no quoted datagram, no original-datagram padding). The structure is
    // version-neutral, so the same decoder ICMPv4 uses (`icmp/decode.rs`) types
    // it here. Anything that does not parse defensibly (bad version, bad
    // checksum, impossible object lengths) stays a single `Raw` payload so the
    // bytes survive and decoding never panics. The reply (161) carries no body of
    // its own, so any trailing bytes on a reply fall through to the raw tail.
    if icmp_type == ICMPV6_EXTENDED_ECHO_REQUEST {
        if let Some(layers) = decode_extended_echo_extension(payload) {
            for layer in layers {
                packet = packet.push_box(layer);
            }
            return Ok(packet);
        }
    }

    if !payload.is_empty() {
        packet = packet.push(Raw::from_bytes(payload));
    }
    Ok(packet)
}

#[cfg(test)]
mod icmpv6 {
    use super::{IcmpKind, Icmpv6, Icmpv6Body, Icmpv6ErrorBody};
    use crate::packet::Layer;
    use crate::protocols::icmp::{
        ICMPV6_ECHO_REQUEST, ICMPV6_PACKET_TOO_BIG, ICMPV6_PARAMETER_PROBLEM,
    };

    // An ICMPv6 `type` that is never modeled with a typed body — used as the
    // stand-in "unknown type" in `icmpv6_body_preserves_unknown_type`. Type 200
    // is unassigned in the IANA ICMPv6 type registry and is not implemented by
    // any NDP/MLD/extended-echo step, so it stays a genuine Unknown-classification
    // test even as more message types are modeled.
    const UNMODELED_ICMPV6_TYPE: u8 = 200;
    use crate::{Ipv6, NetworkLayer, Packet, Raw};
    use core::net::Ipv6Addr;

    const IPV6_ICMP_FIXTURE: &[u8] = fixture_bytes!("bytes/ipv6-icmp-echo-request.bin");

    fn src() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0x0010)
    }

    fn dst() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 2, 0, 0, 0, 0, 0x0020)
    }

    #[test]
    fn icmpv6_echo_request_matches_golden_bytes() {
        let packet = Ipv6::new().src(src()).dst(dst()).fl(0x12345).hlim(64)
            / Icmpv6::echo_request().id(0x4242).seq(2)
            / Raw::from("libcrafter-ipv6");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes(), IPV6_ICMP_FIXTURE);
        assert_eq!(&bytes.as_bytes()[40..42], &[ICMPV6_ECHO_REQUEST, 0]);
        assert_eq!(&bytes.as_bytes()[42..44], &0x00d0u16.to_be_bytes());
    }

    #[test]
    fn icmpv6_decode_from_ipv6_exposes_echo_fields_and_payload() {
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, IPV6_ICMP_FIXTURE).unwrap();
        let ipv6 = decoded.layer::<Ipv6>().unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(ipv6.source(), src());
        assert_eq!(ipv6.destination(), dst());
        assert_eq!(ipv6.flow_label_value(), 0x12345);
        assert_eq!(ipv6.payload_length_value(), Some(23));
        assert_eq!(icmpv6.kind_value(), Some(IcmpKind::EchoRequest));
        assert_eq!(icmpv6.checksum_value(), Some(0x00d0));
        assert_eq!(icmpv6.identifier_value(), Some(0x4242));
        assert_eq!(icmpv6.sequence_number_value(), Some(2));
        assert_eq!(raw.as_bytes(), b"libcrafter-ipv6");
        assert_eq!(decoded.compile().unwrap().as_bytes(), IPV6_ICMP_FIXTURE);
    }

    #[test]
    fn icmpv6_explicit_checksum_is_preserved() {
        let bytes = (Ipv6::new().src(src()).dst(dst())
            / Icmpv6::echo_request().id(7).seq(8).checksum(0x2222)
            / Raw::from("abc"))
        .compile()
        .unwrap();

        assert_eq!(&bytes.as_bytes()[42..44], &[0x22, 0x22]);
    }

    #[test]
    fn icmpv6_decode_rejects_short_inputs() {
        let short = (Ipv6::new().nh(crate::IPPROTO_ICMPV6) / Raw::from_bytes([0u8; 7]))
            .compile()
            .unwrap();
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv6, short.as_bytes()).is_err());
    }

    // The typed-body model classifies echo / error / unknown messages by type,
    // surfacing the type-specific rest-of-header fields per variant.
    #[test]
    fn icmpv6_body_classifies_echo() {
        let body = Icmpv6::echo_request().id(0x4242).seq(2).body();
        assert_eq!(
            body,
            Icmpv6Body::Echo {
                identifier: 0x4242,
                sequence_number: 2,
            }
        );
        assert_eq!(body.label(), "echo");
    }

    #[test]
    fn icmpv6_body_classifies_errors() {
        let du = Icmpv6::destination_unreachable().code(4).body();
        assert_eq!(
            du,
            Icmpv6Body::Error(Icmpv6ErrorBody::DestinationUnreachable)
        );
        assert_eq!(du.label(), "error");
        assert_eq!(
            Icmpv6::packet_too_big().mtu(1280).body(),
            Icmpv6Body::Error(Icmpv6ErrorBody::PacketTooBig { mtu: 1280 })
        );
        assert_eq!(
            Icmpv6::time_exceeded().body(),
            Icmpv6Body::Error(Icmpv6ErrorBody::TimeExceeded)
        );
        assert_eq!(
            Icmpv6::new()
                .icmp_type(ICMPV6_PARAMETER_PROBLEM)
                .pointer(6)
                .body(),
            Icmpv6Body::Error(Icmpv6ErrorBody::ParameterProblem { pointer: 6 })
        );
    }

    // RFC 8335 extended echo request/reply bodies classify by type, surfacing the
    // identifier / 8-bit sequence / flag-byte fields per variant.
    #[test]
    fn icmpv6_body_classifies_extended_echo() {
        let request = Icmpv6::extended_echo_request()
            .id(0x1234)
            .seq(7)
            .extended_l_bit(true)
            .body();
        assert_eq!(
            request,
            Icmpv6Body::ExtendedEchoRequest {
                identifier: 0x1234,
                sequence_number: 7,
                local: true,
                reserved_flags: 0,
            }
        );
        assert_eq!(request.label(), "extended-echo-request");

        let reply = Icmpv6::extended_echo_reply()
            .id(0xabcd)
            .seq(5)
            .extended_state(2)
            .extended_active(true)
            .extended_ipv6(true)
            .body();
        assert_eq!(
            reply,
            Icmpv6Body::ExtendedEchoReply {
                identifier: 0xabcd,
                sequence_number: 5,
                state: 2,
                active: true,
                ipv4: false,
                ipv6: true,
            }
        );
        assert_eq!(reply.label(), "extended-echo-reply");
    }

    // An unrecognized type (here type 200, which the IANA ICMPv6 registry leaves
    // unassigned and no message step models) falls through to the extensible
    // `Unknown` variant with its raw rest-of-header preserved.
    #[test]
    fn icmpv6_body_preserves_unknown_type() {
        let icmpv6 = Icmpv6::new()
            .icmp_type(UNMODELED_ICMPV6_TYPE)
            .rest_of_header([0xde, 0xad, 0xbe, 0xef]);
        let body = icmpv6.body();
        assert_eq!(
            body,
            Icmpv6Body::Unknown {
                icmp_type: UNMODELED_ICMPV6_TYPE,
                rest_of_header: [0xde, 0xad, 0xbe, 0xef],
            }
        );
        assert_eq!(body.label(), "unknown");
    }

    // The body model is a view over the header: it does not change the existing
    // echo/error summary string (other tests and the oracle bind to it), and the
    // body variant is surfaced through `show()`/inspection fields instead.
    #[test]
    fn icmpv6_summary_is_stable_and_show_reports_body() {
        let echo = Icmpv6::echo_request().id(0x4242).seq(2);
        assert_eq!(
            echo.summary(),
            "Icmpv6(type=echo-request(128), code=0, id=16962, seq=2)"
        );
        let echo_body = echo
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "body")
            .map(|(_, value)| value)
            .expect("show() exposes a body field");
        assert_eq!(echo_body, "echo(id=0x4242, seq=2)");

        let ptb = Icmpv6::packet_too_big().mtu(1280);
        assert_eq!(
            ptb.summary(),
            "Icmpv6(type=packet-too-big(2), code=0, id=-, seq=-)"
        );
        let ptb_body = ptb
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "body")
            .map(|(_, value)| value)
            .expect("show() exposes a body field");
        assert_eq!(ptb_body, "error(packet-too-big, mtu=1280)");

        let unknown = Icmpv6::new().icmp_type(ICMPV6_PACKET_TOO_BIG ^ 0xff);
        let unknown_body = unknown
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "body")
            .map(|(_, value)| value)
            .expect("show() exposes a body field");
        assert!(unknown_body.starts_with("unknown(type="));
    }
}
