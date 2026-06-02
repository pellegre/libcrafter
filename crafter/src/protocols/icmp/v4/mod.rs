//! ICMPv4 layer implementation.
//!
//! Moved out of `icmp/mod.rs` into the `icmp/v4/` subtree so ICMPv4 and ICMPv6
//! sit as siblings under the shared core. This holds the [`Icmp`] header struct
//! and its builder/decode/compile impls plus the ICMPv4 (`ICMP_*`) codepoint
//! constants. Shared compile/auto-fill helpers, the version-neutral
//! [`IcmpKind`]/[`IcmpLayer`] contract, the typed body layers, and the RFC 4884
//! extension framework are reached through `use super::*;`. This is a pure
//! internal move: `crate::protocols::icmp::Icmp`, the `protocols::mod.rs`
//! re-exports, and the prelude all keep resolving to the same names. [`Icmp`] is
//! renamed to `Icmpv4` in a later step; this step only relocates the code.

use super::*;

pub(crate) mod constants;
pub use self::constants::*;

mod bodies;
pub use self::bodies::*;

/// Internet Control Message Protocol for IPv4.
///
/// Fields are `pub(crate)` so the ICMPv4 decode path in `icmp/decode.rs` (which
/// stays at the module root for now) can construct the header from wire bytes.
/// They remain invisible to downstream crates, so the public API is unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp {
    pub(crate) icmp_type: Field<u8>,
    pub(crate) code: Field<u8>,
    pub(crate) checksum: Field<u16>,
    pub(crate) rest_of_header: Field<[u8; 4]>,
    pub(crate) identifier: Field<u16>,
    pub(crate) sequence_number: Field<u16>,
    pub(crate) pointer: Field<u8>,
    pub(crate) gateway: Field<Ipv4Addr>,
    pub(crate) length: Field<u8>,
    pub(crate) mtu_next_hop: Field<u16>,
    pub(crate) num_addrs: Field<u8>,
    pub(crate) addr_entry_size: Field<u8>,
    pub(crate) lifetime: Field<u16>,
    pub(crate) extended_flags: Field<u8>,
}

impl Icmp {
    /// Create an ICMP echo-request header with deterministic defaults.
    pub fn new() -> Self {
        Self {
            icmp_type: Field::defaulted(ICMP_ECHO_REQUEST),
            code: Field::defaulted(0),
            checksum: Field::unset(),
            rest_of_header: Field::defaulted([0; 4]),
            identifier: Field::defaulted(0),
            sequence_number: Field::defaulted(0),
            pointer: Field::unset(),
            gateway: Field::unset(),
            length: Field::unset(),
            mtu_next_hop: Field::unset(),
            num_addrs: Field::unset(),
            addr_entry_size: Field::unset(),
            lifetime: Field::unset(),
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

    /// Create a timestamp request (RFC 792, type 13).
    ///
    /// The fixed header carries the identifier and sequence number; the three
    /// 32-bit timestamps live in a separate [`IcmpTimestamp`] body layer.
    pub fn timestamp_request() -> Self {
        Self::new().icmp_type(ICMP_TIMESTAMP)
    }

    /// Create a timestamp reply (RFC 792, type 14).
    pub fn timestamp_reply() -> Self {
        Self::new().icmp_type(ICMP_TIMESTAMP_REPLY)
    }

    /// Create an information request (RFC 792, type 15).
    ///
    /// Deprecated by RFC 6918, but still constructible. Information messages
    /// carry only the identifier and sequence number with no body beyond the
    /// fixed header.
    pub fn information_request() -> Self {
        Self::new().icmp_type(ICMP_INFORMATION_REQUEST)
    }

    /// Create an information reply (RFC 792, type 16).
    ///
    /// Deprecated by RFC 6918, but still constructible.
    pub fn information_reply() -> Self {
        Self::new().icmp_type(ICMP_INFORMATION_REPLY)
    }

    /// Create an address mask request (RFC 950, type 17).
    ///
    /// Deprecated by RFC 6918, but still constructible. The fixed header carries
    /// the identifier and sequence number; the 32-bit address mask lives in a
    /// separate [`IcmpAddressMask`] body layer (RFC 950 sets it to zero in a
    /// request).
    pub fn address_mask_request() -> Self {
        Self::new().icmp_type(ICMP_ADDRESS_MASK_REQUEST)
    }

    /// Create an address mask reply (RFC 950, type 18).
    ///
    /// Deprecated by RFC 6918, but still constructible. The replying gateway
    /// sets the [`IcmpAddressMask`] body to the subnet/network mask.
    pub fn address_mask_reply() -> Self {
        Self::new().icmp_type(ICMP_ADDRESS_MASK_REPLY)
    }

    /// Create a router advertisement (RFC 1256, type 9).
    ///
    /// The fixed header's rest-of-header carries Num Addrs (byte 0), Addr Entry
    /// Size (byte 1), and Lifetime (bytes 2-3); the advertised router addresses
    /// and preference levels live in following [`IcmpRouterAdvertisementEntry`]
    /// layers. Num Addrs and Addr Entry Size are auto-filled from those entries
    /// at compile time unless the caller pins them.
    pub fn router_advertisement() -> Self {
        Self::new().icmp_type(ICMP_ROUTER_ADVERTISEMENT)
    }

    /// Create a router solicitation (RFC 1256, type 10).
    ///
    /// The rest-of-header is a single 32-bit reserved field that RFC 1256 sends
    /// as zero and receivers ignore; it has no body beyond the fixed header.
    pub fn router_solicitation() -> Self {
        Self::new().icmp_type(ICMP_ROUTER_SOLICITATION)
    }

    /// Create an extended echo request (RFC 8335, type 42).
    ///
    /// The fixed header carries a 16-bit identifier, an 8-bit sequence number,
    /// and a flag byte whose rightmost bit is the L-bit (the probed interface
    /// resides on a proxy node). An RFC 4884 extension structure carrying a
    /// single [`IcmpExtensionInterfaceId`] object follows the header directly
    /// (no quoted datagram, no RFC 4884 original-datagram padding).
    pub fn extended_echo_request() -> Self {
        Self::new().icmp_type(ICMP_EXTENDED_ECHO_REQUEST)
    }

    /// Create an extended echo reply (RFC 8335, type 43).
    ///
    /// The reply echoes the identifier and sequence number; its `Code` reports
    /// the query result (0-4) and the flag byte carries the State, Active, IPv4,
    /// and IPv6 flags. The reply has no body of its own.
    pub fn extended_echo_reply() -> Self {
        Self::new().icmp_type(ICMP_EXTENDED_ECHO_REPLY)
    }

    /// Create a traceroute message (RFC 1393, type 30).
    ///
    /// Deprecated by RFC 6918, but still constructible. RFC 1393 defines a
    /// rest-of-header layout (ID Number, plus outbound/return hop counts and
    /// link speed/MTU words in the body); `crafter` does not type that body, so
    /// set the rest-of-header and any body bytes with [`rest_of_header`] and a
    /// trailing [`Raw`] layer.
    ///
    /// [`rest_of_header`]: Self::rest_of_header
    /// [`Raw`]: crate::Raw
    pub fn traceroute() -> Self {
        Self::new().icmp_type(ICMP_TRACEROUTE)
    }

    /// Create a datagram conversion error message (RFC 1475, type 31).
    ///
    /// Deprecated by RFC 6918, but still constructible. RFC 1475 places a
    /// 32-bit pointer in the rest-of-header and quotes the offending datagram in
    /// the body; `crafter` keeps both raw-compatible (set the rest-of-header and
    /// append the quoted bytes as a trailing layer).
    pub fn datagram_conversion_error() -> Self {
        Self::new().icmp_type(ICMP_DATAGRAM_CONVERSION_ERROR)
    }

    /// Create a mobile host redirect message (type 32).
    ///
    /// Deprecated by RFC 6918, but still constructible. The message body is not
    /// typed; use [`rest_of_header`] and a trailing [`Raw`] layer for any
    /// payload.
    ///
    /// [`rest_of_header`]: Self::rest_of_header
    /// [`Raw`]: crate::Raw
    pub fn mobile_host_redirect() -> Self {
        Self::new().icmp_type(ICMP_MOBILE_HOST_REDIRECT)
    }

    /// Create an "IPv6 Where-Are-You" message (type 33).
    ///
    /// Deprecated by RFC 6918, but still constructible. The message body is not
    /// typed and stays raw-compatible.
    pub fn ipv6_where_are_you() -> Self {
        Self::new().icmp_type(ICMP_IPV6_WHERE_ARE_YOU)
    }

    /// Create an "IPv6 I-Am-Here" message (type 34).
    ///
    /// Deprecated by RFC 6918, but still constructible. The message body is not
    /// typed and stays raw-compatible.
    pub fn ipv6_i_am_here() -> Self {
        Self::new().icmp_type(ICMP_IPV6_I_AM_HERE)
    }

    /// Create a mobile registration request message (type 35).
    ///
    /// Deprecated by RFC 6918, but still constructible. The message body is not
    /// typed and stays raw-compatible.
    pub fn mobile_registration_request() -> Self {
        Self::new().icmp_type(ICMP_MOBILE_REGISTRATION_REQUEST)
    }

    /// Create a mobile registration reply message (type 36).
    ///
    /// Deprecated by RFC 6918, but still constructible. The message body is not
    /// typed and stays raw-compatible.
    pub fn mobile_registration_reply() -> Self {
        Self::new().icmp_type(ICMP_MOBILE_REGISTRATION_REPLY)
    }

    /// Create a domain name request message (RFC 1788, type 37).
    ///
    /// Deprecated by RFC 6918, but still constructible. RFC 1788 carries the
    /// identifier and sequence number in the rest-of-header (like the RFC 792
    /// query families) and an optional name body; `crafter` does not type the
    /// body, so append it with a trailing [`Raw`] layer.
    ///
    /// [`Raw`]: crate::Raw
    pub fn domain_name_request() -> Self {
        Self::new().icmp_type(ICMP_DOMAIN_NAME_REQUEST)
    }

    /// Create a domain name reply message (RFC 1788, type 38).
    ///
    /// Deprecated by RFC 6918, but still constructible. The TTL and name list
    /// body is not typed; append it with a trailing [`Raw`] layer.
    ///
    /// [`Raw`]: crate::Raw
    pub fn domain_name_reply() -> Self {
        Self::new().icmp_type(ICMP_DOMAIN_NAME_REPLY)
    }

    /// Create a SKIP message (type 39).
    ///
    /// Deprecated by RFC 6918, but still constructible. The message body is not
    /// typed and stays raw-compatible.
    pub fn skip() -> Self {
        Self::new().icmp_type(ICMP_SKIP)
    }

    /// Create a Photuris security-failures message (RFC 2521, type 40).
    ///
    /// The `Code` carries the security failure (0 bad-SPI through 5
    /// need-authorization); the rest-of-header and quoted datagram body are not
    /// typed, so set them with [`rest_of_header`] and a trailing layer.
    ///
    /// [`rest_of_header`]: Self::rest_of_header
    pub fn photuris() -> Self {
        Self::new().icmp_type(ICMP_PHOTURIS)
    }

    /// Create an experimental mobility message (RFC 4065, type 41).
    ///
    /// Experimental: assigned to messages utilized by experimental mobility
    /// protocols such as Seamoby. The body is not typed and stays
    /// raw-compatible.
    pub fn seamoby_experimental() -> Self {
        Self::new().icmp_type(ICMP_SEAMOBY_EXPERIMENTAL)
    }

    /// Create an RFC 3692-style experiment 1 message (RFC 4727, type 253).
    ///
    /// Experimental: reserved for protocol experiments. The body is not typed
    /// and stays raw-compatible.
    pub fn experiment_1() -> Self {
        Self::new().icmp_type(ICMP_EXPERIMENTAL_253)
    }

    /// Create an RFC 3692-style experiment 2 message (RFC 4727, type 254).
    ///
    /// Experimental: reserved for protocol experiments. The body is not typed
    /// and stays raw-compatible.
    pub fn experiment_2() -> Self {
        Self::new().icmp_type(ICMP_EXPERIMENTAL_254)
    }

    /// Set the ICMP type from a common kind.
    pub fn kind(mut self, kind: IcmpKind) -> Self {
        self.icmp_type.set_user(kind.ipv4_type());
        self
    }

    /// Set the raw ICMP type.
    pub fn icmp_type(mut self, icmp_type: u8) -> Self {
        self.icmp_type.set_user(icmp_type);
        self
    }

    /// Alias for generated code that wants the protocol field name.
    pub fn type_(self, icmp_type: u8) -> Self {
        self.icmp_type(icmp_type)
    }

    /// Set the ICMP code.
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

    /// Set the parameter-problem pointer byte.
    pub fn pointer(mut self, pointer: u8) -> Self {
        self.pointer.set_user(pointer);
        self
    }

    /// Set the redirect gateway address.
    pub fn gateway(mut self, gateway: Ipv4Addr) -> Self {
        self.gateway.set_user(gateway);
        self
    }

    /// Set the redirect gateway address from dotted-quad text.
    pub fn gateway_str(self, gateway: &str) -> Result<Self> {
        Ok(self.gateway(parse_ipv4(gateway)?))
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

    /// Set the next-hop MTU field used by destination-unreachable messages.
    pub fn mtu_next_hop(mut self, mtu_next_hop: u16) -> Self {
        self.mtu_next_hop.set_user(mtu_next_hop);
        self
    }

    /// Compatibility alias for next-hop MTU.
    pub fn mtu(self, mtu_next_hop: u16) -> Self {
        self.mtu_next_hop(mtu_next_hop)
    }

    /// Set the RFC 1256 router advertisement Num Addrs field explicitly.
    ///
    /// When unset, compilation counts the following
    /// [`IcmpRouterAdvertisementEntry`] layers.
    pub fn num_addrs(mut self, num_addrs: u8) -> Self {
        self.num_addrs.set_user(num_addrs);
        self
    }

    /// Set the RFC 1256 router advertisement Addr Entry Size field explicitly,
    /// measured in 32-bit words.
    ///
    /// When unset, compilation defaults it to
    /// [`ICMP_ROUTER_ADVERTISEMENT_ENTRY_WORDS`] for the standard entry format.
    pub fn addr_entry_size(mut self, addr_entry_size: u8) -> Self {
        self.addr_entry_size.set_user(addr_entry_size);
        self
    }

    /// Set the RFC 1256 router advertisement Lifetime field (seconds).
    pub fn lifetime(mut self, lifetime: u16) -> Self {
        self.lifetime.set_user(lifetime);
        self
    }

    /// Set the raw RFC 8335 extended echo flag byte (the fourth byte of the
    /// rest-of-header) explicitly.
    ///
    /// This is the escape hatch for crafting reserved bits and flag combinations
    /// the typed builders do not expose; an explicit byte survives compilation
    /// untouched.
    pub fn extended_flags(mut self, extended_flags: u8) -> Self {
        self.extended_flags.set_user(extended_flags);
        self
    }

    /// Set the RFC 8335 extended echo request L-bit (the probed interface is on
    /// a proxy node).
    ///
    /// The L-bit is the rightmost bit of the request flag byte; the other seven
    /// reserved bits are left untouched (use [`Icmp::extended_flags`] to set
    /// reserved bits deliberately).
    pub fn extended_l_bit(mut self, set: bool) -> Self {
        let base = self.extended_flags.value().copied().unwrap_or(0);
        let value = if set {
            base | ICMP_EXTENDED_ECHO_REQUEST_L_BIT
        } else {
            base & !ICMP_EXTENDED_ECHO_REQUEST_L_BIT
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
            base | ICMP_EXTENDED_ECHO_REPLY_ACTIVE
        } else {
            base & !ICMP_EXTENDED_ECHO_REPLY_ACTIVE
        };
        self.extended_flags.set_user(value);
        self
    }

    /// Set the RFC 8335 extended echo reply IPv4 (4) flag.
    pub fn extended_ipv4(mut self, set: bool) -> Self {
        let base = self.extended_flags.value().copied().unwrap_or(0);
        let value = if set {
            base | ICMP_EXTENDED_ECHO_REPLY_IPV4
        } else {
            base & !ICMP_EXTENDED_ECHO_REPLY_IPV4
        };
        self.extended_flags.set_user(value);
        self
    }

    /// Set the RFC 8335 extended echo reply IPv6 (6) flag.
    pub fn extended_ipv6(mut self, set: bool) -> Self {
        let base = self.extended_flags.value().copied().unwrap_or(0);
        let value = if set {
            base | ICMP_EXTENDED_ECHO_REPLY_IPV6
        } else {
            base & !ICMP_EXTENDED_ECHO_REPLY_IPV6
        };
        self.extended_flags.set_user(value);
        self
    }

    /// Raw ICMP type value.
    pub fn icmp_type_value(&self) -> u8 {
        value_or_copy(&self.icmp_type, ICMP_ECHO_REQUEST)
    }

    /// ICMP code value.
    pub fn code_value(&self) -> u8 {
        value_or_copy(&self.code, 0)
    }

    /// Stored checksum value, when explicit or decoded.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    /// Identifier value when meaningful for the current type.
    ///
    /// Echo, timestamp, and information messages (RFC 792) and the RFC 8335
    /// extended echo messages all carry a 16-bit identifier in the first half of
    /// the rest-of-header; this accessor surfaces it for each of those families.
    pub fn identifier_value(&self) -> Option<u16> {
        let icmp_type = self.icmp_type_value();
        if is_query_v4(icmp_type) || is_extended_echo_v4(icmp_type) {
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
    /// Surfaced for echo, timestamp, and information messages (RFC 792) as a
    /// 16-bit value, and for the RFC 8335 extended echo messages as an 8-bit
    /// value (the third byte of the rest-of-header), zero-extended here.
    pub fn sequence_number_value(&self) -> Option<u16> {
        let icmp_type = self.icmp_type_value();
        if is_extended_echo_v4(icmp_type) {
            // RFC 8335 narrows the sequence number to a single octet (byte 2);
            // the fourth byte is the flag byte, not part of the sequence.
            Some(u16::from(value_or_u8_from_rest(
                &self.sequence_number_byte(),
                &self.rest_of_header,
                2,
            )))
        } else if is_query_v4(icmp_type) {
            Some(value_or_u16_from_rest(
                &self.sequence_number,
                &self.rest_of_header,
                2,
            ))
        } else {
            None
        }
    }

    /// The RFC 8335 8-bit sequence number as a `Field<u8>` derived from the
    /// 16-bit `sequence_number` field: a user-set sequence number contributes its
    /// low octet, otherwise the field stays unset so the rest-of-header supplies
    /// the byte.
    fn sequence_number_byte(&self) -> Field<u8> {
        match self.sequence_number.value().copied() {
            Some(value) => Field::user(value as u8),
            None => Field::unset(),
        }
    }

    /// Raw four-byte rest-of-header value after applying typed fields.
    pub fn rest_of_header_value(&self) -> [u8; 4] {
        self.effective_rest_of_header(None, 4).unwrap_or([0; 4])
    }

    /// RFC 4884 length field when explicit or decoded.
    pub fn length_value(&self) -> Option<u8> {
        self.length.value().copied()
    }

    /// Parameter-problem pointer byte when explicit or decoded.
    pub fn pointer_value(&self) -> Option<u8> {
        self.pointer.value().copied()
    }

    /// Redirect gateway address when explicit or decoded.
    pub fn gateway_value(&self) -> Option<Ipv4Addr> {
        self.gateway.value().copied()
    }

    /// Next-hop MTU field when explicit or decoded.
    pub fn mtu_next_hop_value(&self) -> Option<u16> {
        self.mtu_next_hop.value().copied()
    }

    /// RFC 1256 router advertisement Num Addrs field when explicit or decoded.
    pub fn num_addrs_value(&self) -> Option<u8> {
        self.num_addrs.value().copied()
    }

    /// RFC 1256 router advertisement Addr Entry Size field (32-bit words) when
    /// explicit or decoded.
    pub fn addr_entry_size_value(&self) -> Option<u8> {
        self.addr_entry_size.value().copied()
    }

    /// RFC 1256 router advertisement Lifetime field when explicit or decoded.
    pub fn lifetime_value(&self) -> Option<u16> {
        self.lifetime.value().copied()
    }

    /// RFC 8335 extended echo flag byte (the fourth byte of the rest-of-header)
    /// when the type is an extended echo request or reply.
    ///
    /// The byte is surfaced verbatim so reserved bits stay inspectable; the
    /// typed accessors below interpret the individual flags.
    pub fn extended_flags_value(&self) -> Option<u8> {
        if is_extended_echo_v4(self.icmp_type_value()) {
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
        if self.icmp_type_value() == ICMP_EXTENDED_ECHO_REQUEST {
            self.extended_flags_value()
                .map(|flags| flags & ICMP_EXTENDED_ECHO_REQUEST_L_BIT != 0)
        } else {
            None
        }
    }

    /// RFC 8335 extended echo reply State field (3 bits) when the type is an
    /// extended echo reply.
    pub fn extended_state_value(&self) -> Option<u8> {
        if self.icmp_type_value() == ICMP_EXTENDED_ECHO_REPLY {
            self.extended_flags_value().map(|flags| (flags >> 5) & 0x07)
        } else {
            None
        }
    }

    /// RFC 8335 extended echo reply Active (A) flag when the type is an extended
    /// echo reply.
    pub fn extended_active_value(&self) -> Option<bool> {
        if self.icmp_type_value() == ICMP_EXTENDED_ECHO_REPLY {
            self.extended_flags_value()
                .map(|flags| flags & ICMP_EXTENDED_ECHO_REPLY_ACTIVE != 0)
        } else {
            None
        }
    }

    /// RFC 8335 extended echo reply IPv4 (4) flag when the type is an extended
    /// echo reply.
    pub fn extended_ipv4_value(&self) -> Option<bool> {
        if self.icmp_type_value() == ICMP_EXTENDED_ECHO_REPLY {
            self.extended_flags_value()
                .map(|flags| flags & ICMP_EXTENDED_ECHO_REPLY_IPV4 != 0)
        } else {
            None
        }
    }

    /// RFC 8335 extended echo reply IPv6 (6) flag when the type is an extended
    /// echo reply.
    pub fn extended_ipv6_value(&self) -> Option<bool> {
        if self.icmp_type_value() == ICMP_EXTENDED_ECHO_REPLY {
            self.extended_flags_value()
                .map(|flags| flags & ICMP_EXTENDED_ECHO_REPLY_IPV6 != 0)
        } else {
            None
        }
    }

    /// Common ICMP kind, when the type is version-independent.
    pub fn kind_value(&self) -> Option<IcmpKind> {
        match self.icmp_type_value() {
            ICMP_DESTINATION_UNREACHABLE => Some(IcmpKind::DestinationUnreachable),
            ICMP_TIME_EXCEEDED => Some(IcmpKind::TimeExceeded),
            ICMP_PARAMETER_PROBLEM => Some(IcmpKind::ParameterProblem),
            ICMP_ECHO_REQUEST => Some(IcmpKind::EchoRequest),
            ICMP_ECHO_REPLY => Some(IcmpKind::EchoReply),
            _ => None,
        }
    }

    fn effective_rest_of_header(
        &self,
        ctx: Option<LayerContext<'_>>,
        extension_unit: usize,
    ) -> Result<[u8; 4]> {
        // The four bytes after the checksum (RFC 792) carry a type-specific
        // interpretation. An explicit raw `rest_of_header` is the base and must
        // survive compilation untouched unless a *user-set* typed field
        // deliberately overrides part of it. Auto-filled (unset/defaulted)
        // typed values never clobber raw bytes the caller supplied on purpose.
        let raw_is_user = self.rest_of_header.is_user_set();
        let mut rest = value_or_copy(&self.rest_of_header, [0; 4]);

        match self.icmp_type_value() {
            ICMP_ECHO_REQUEST
            | ICMP_ECHO_REPLY
            | ICMP_TIMESTAMP
            | ICMP_TIMESTAMP_REPLY
            | ICMP_INFORMATION_REQUEST
            | ICMP_INFORMATION_REPLY
            | ICMP_ADDRESS_MASK_REQUEST
            | ICMP_ADDRESS_MASK_REPLY => {
                // RFC 792 / RFC 950 query families: identifier (2) + sequence
                // (2). When the raw rest is user-set, only a user-set id/seq
                // overrides those bytes; otherwise the typed defaults seed them
                // from the raw value.
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
            ICMP_DESTINATION_UNREACHABLE => {
                // Bytes 0 unused, byte 1 RFC 4884 length, bytes 2-3 RFC 1191
                // next-hop MTU (destination-unreachable code 4).
                if let Some(length) =
                    self.overriding_extension_length(ctx, extension_unit, raw_is_user)?
                {
                    rest[1] = length;
                }
                if self.mtu_next_hop.is_user_set() || !raw_is_user {
                    if let Some(mtu) = self.mtu_next_hop.value().copied() {
                        rest[2..4].copy_from_slice(&mtu.to_be_bytes());
                    }
                }
            }
            ICMP_REDIRECT => {
                // The whole rest is the gateway address.
                if self.gateway.is_user_set() || !raw_is_user {
                    if let Some(gateway) = self.gateway.value().copied() {
                        rest = gateway.octets();
                    }
                }
            }
            ICMP_TIME_EXCEEDED => {
                // Byte 1 carries the RFC 4884 length.
                if let Some(length) =
                    self.overriding_extension_length(ctx, extension_unit, raw_is_user)?
                {
                    rest[1] = length;
                }
            }
            ICMP_PARAMETER_PROBLEM => {
                // Byte 0 is the pointer, byte 1 the RFC 4884 length.
                if self.pointer.is_user_set() || !raw_is_user {
                    if let Some(pointer) = self.pointer.value().copied() {
                        rest[0] = pointer;
                    }
                }
                if let Some(length) =
                    self.overriding_extension_length(ctx, extension_unit, raw_is_user)?
                {
                    rest[1] = length;
                }
            }
            ICMP_ROUTER_ADVERTISEMENT => {
                // RFC 1256: byte 0 Num Addrs, byte 1 Addr Entry Size (32-bit
                // words), bytes 2-3 Lifetime. Num Addrs is auto-filled from the
                // following entry layers and Addr Entry Size defaults to the
                // standard format unless the caller pinned the raw rest or the
                // typed field. A user-set typed field always wins over the raw
                // base.
                if let Some(num_addrs) = self.overriding_num_addrs(ctx, raw_is_user) {
                    rest[0] = num_addrs;
                }
                if self.addr_entry_size.is_user_set() {
                    rest[1] = self.addr_entry_size_value().unwrap_or(0);
                } else if !raw_is_user {
                    rest[1] = ICMP_ROUTER_ADVERTISEMENT_ENTRY_WORDS;
                }
                if self.lifetime.is_user_set() || !raw_is_user {
                    if let Some(lifetime) = self.lifetime.value().copied() {
                        rest[2..4].copy_from_slice(&lifetime.to_be_bytes());
                    }
                }
            }
            ICMP_EXTENDED_ECHO_REQUEST | ICMP_EXTENDED_ECHO_REPLY => {
                // RFC 8335: identifier (bytes 0-1), an 8-bit sequence number
                // (byte 2), and a flag byte (byte 3). The flag byte holds the
                // L-bit for requests and State/A/4/6 for replies; the typed
                // builders pre-pack it into `extended_flags`.
                if self.identifier.is_user_set() || !raw_is_user {
                    let identifier =
                        value_or_u16_from_rest(&self.identifier, &self.rest_of_header, 0);
                    rest[..2].copy_from_slice(&identifier.to_be_bytes());
                }
                if self.sequence_number.is_user_set() || !raw_is_user {
                    let sequence = value_or_u8_from_rest(
                        &self.sequence_number_byte(),
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

    /// RFC 1256 Num Addrs byte that should override the raw rest-of-header.
    ///
    /// A user-set Num Addrs always wins. An auto-counted value (from the
    /// following entry layers) only applies when the caller did not pin the raw
    /// rest-of-header, so a deliberate raw count survives compilation.
    fn overriding_num_addrs(&self, ctx: Option<LayerContext<'_>>, raw_is_user: bool) -> Option<u8> {
        if let Some(num_addrs) = self.num_addrs.value().copied() {
            return Some(num_addrs);
        }
        if raw_is_user {
            return None;
        }
        let ctx = ctx?;
        u8::try_from(router_advertisement_entry_count(ctx)).ok()
    }

    /// RFC 4884 length byte that should override the raw rest-of-header.
    ///
    /// A user-set length always wins. An auto-computed length only applies when
    /// the caller did not pin the raw rest-of-header, so deliberate raw bytes
    /// survive compilation.
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

    // Reached by the RFC 4884 original-datagram padding helpers in the parent
    // `icmp` module (which compute extension offsets from a preceding `Icmp`
    // header), so it is crate-visible rather than private. Not part of the
    // public API.
    pub(crate) fn effective_extension_length(
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
        if !icmpv4_type_allows_extensions(self.icmp_type_value()) {
            return Ok(None);
        }

        // RFC 4884: the length attribute counts 32-bit words of the *padded*
        // original datagram and is meaningful only when an extension structure
        // is appended. When no `IcmpExtension` follows, the field stays zero so
        // a compliant receiver reads "no extensions present".
        if !following_extension_present(ctx) {
            return Ok(Some(0));
        }

        let raw_len = encoded_len_until_extension(ctx);
        let padded = rfc4884_padded_original_len(raw_len, unit);
        u8::try_from(padded / unit).map(Some).map_err(|_| {
            CrafterError::invalid_field_value(
                "icmp.length",
                "ICMP original datagram length does not fit in one byte",
            )
        })
    }

    fn effective_checksum(&self, header: &[u8], payload: &[u8]) -> u16 {
        if let Some(checksum) = self.checksum.value().copied() {
            return checksum;
        }

        let mut segment = Vec::with_capacity(header.len() + payload.len());
        segment.extend_from_slice(header);
        segment.extend_from_slice(payload);
        internet_checksum(&segment)
    }
}

impl Default for Icmp {
    fn default() -> Self {
        Self::new()
    }
}

impl IcmpLayer for Icmp {
    fn icmp_type_value(&self) -> u8 {
        Icmp::icmp_type_value(self)
    }

    fn code_value(&self) -> u8 {
        Icmp::code_value(self)
    }

    fn checksum_value(&self) -> Option<u16> {
        Icmp::checksum_value(self)
    }

    fn identifier_value(&self) -> Option<u16> {
        Icmp::identifier_value(self)
    }

    fn sequence_number_value(&self) -> Option<u16> {
        Icmp::sequence_number_value(self)
    }

    fn kind(&self) -> Option<IcmpKind> {
        self.kind_value()
    }
}

impl Layer for Icmp {
    fn name(&self) -> &'static str {
        "Icmp"
    }

    fn summary(&self) -> String {
        format!(
            "Icmp(type={}, code={}, id={}, seq={})",
            icmpv4_type_summary(self.icmp_type_value()),
            icmpv4_code_summary(self.icmp_type_value(), self.code_value()),
            self.identifier_value()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.sequence_number_value()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string())
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("type", icmpv4_type_summary(self.icmp_type_value())),
            (
                "code",
                icmpv4_code_summary(self.icmp_type_value(), self.code_value()),
            ),
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
            (
                "num_addrs",
                self.num_addrs_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            (
                "addr_entry_size",
                self.addr_entry_size_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            (
                "lifetime",
                self.lifetime_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "extended_flags",
                self.extended_flags_value()
                    .map(|value| format!("0x{value:02x}"))
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "extended_l_bit",
                self.extended_l_bit_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "extended_state",
                self.extended_state_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "extended_active",
                self.extended_active_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "extended_ipv4",
                self.extended_ipv4_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "extended_ipv6",
                self.extended_ipv6_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
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
        header.extend_from_slice(&self.effective_rest_of_header(Some(*ctx), 4)?);

        let checksum = self.effective_checksum(&header, &payload);
        header[2..4].copy_from_slice(&checksum.to_be_bytes());
        out.extend_from_slice(&header);
        Ok(())
    }

    impl_layer_object!(Icmp);
}

impl_layer_div!(Icmp);

#[cfg(test)]
mod icmpv4_header_model {
    use super::{Icmp, IcmpKind, ICMP_ECHO_REQUEST, ICMP_REDIRECT, ICMP_TIME_EXCEEDED};
    use crate::packet::Layer;
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw, Udp};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // The header model exposes the raw rest-of-header escape hatch unchanged.
    // An explicit four-byte rest-of-header on a non-typed body survives
    // compilation byte-for-byte.
    #[test]
    fn icmpv4_header_model_raw_rest_of_header_is_preserved() {
        let raw = [0xde, 0xad, 0xbe, 0xef];
        let bytes = (Ipv4::new().src(src()).dst(dst())
            / Icmp::new().icmp_type(99).code(7).rest_of_header(raw)
            / Raw::from("body"))
        .compile()
        .unwrap();

        // Type/code at the start of the ICMP header (after the 20-byte IPv4 hdr).
        assert_eq!(&bytes.as_bytes()[20..22], &[99, 7]);
        // Bytes 4..8 of the ICMP header are the untouched rest-of-header.
        assert_eq!(&bytes.as_bytes()[24..28], &raw);
    }

    // An explicit raw rest-of-header survives even when it is inconsistent with
    // the typed message constructor: a time-exceeded message that would
    // normally auto-fill the RFC 4884 length byte keeps the caller's raw bytes
    // when they pinned the whole rest-of-header on purpose.
    #[test]
    fn icmpv4_header_model_raw_rest_survives_typed_constructor() {
        let raw = [0xaa, 0xbb, 0xcc, 0xdd];
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded().rest_of_header(raw)
            / (Ipv4::new()
                .src(Ipv4Addr::new(192, 0, 2, 1))
                .dst(Ipv4Addr::new(198, 51, 100, 1))
                .proto(IpProtocol::Udp)
                / Udp::new().sport(53).dport(1111)
                / Raw::from("quoted"));
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[20], ICMP_TIME_EXCEEDED);
        // The whole rest-of-header is exactly what the caller pinned; the RFC
        // 4884 length auto-fill must not clobber byte index 25.
        assert_eq!(&bytes.as_bytes()[24..28], &raw);
    }

    // A user-set typed field still overrides the matching slice of an explicit
    // raw rest-of-header, because it is a more specific caller intent.
    #[test]
    fn icmpv4_header_model_user_typed_field_overrides_raw_rest() {
        let raw = [0x00, 0x00, 0x00, 0x00];
        let bytes = (Ipv4::new().src(src()).dst(dst())
            / Icmp::echo_request()
                .rest_of_header(raw)
                .id(0x1234)
                .seq(0x5678)
            / Raw::from("x"))
        .compile()
        .unwrap();

        // id/seq the caller set explicitly win over the zeroed raw rest.
        assert_eq!(&bytes.as_bytes()[24..26], &0x1234u16.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[26..28], &0x5678u16.to_be_bytes());
    }

    // The explicit checksum escape hatch is honored verbatim, even when it is
    // an intentionally wrong value.
    #[test]
    fn icmpv4_header_model_explicit_checksum_is_preserved() {
        let bytes = (Ipv4::new().src(src()).dst(dst())
            / Icmp::echo_request().id(7).seq(8).checksum(0xbeef)
            / Raw::from("abc"))
        .compile()
        .unwrap();

        assert_eq!(&bytes.as_bytes()[22..24], &0xbeefu16.to_be_bytes());
    }

    // An unknown/unassigned ICMPv4 type with raw rest-of-header bytes round-trips
    // through compile and decode: the header is inspectable as typed fields and
    // the trailing bytes remain a Raw payload.
    #[test]
    fn icmpv4_header_model_unknown_type_roundtrip() {
        let raw = [0x01, 0x02, 0x03, 0x04];
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::new().icmp_type(200).code(13).rest_of_header(raw)
            / Raw::from("payload");
        let compiled = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.icmp_type_value(), 200);
        assert_eq!(icmp.code_value(), 13);
        assert_eq!(icmp.rest_of_header_value(), raw);
        // An unknown type maps to no common kind and carries no echo fields.
        assert_eq!(icmp.kind_value(), None);
        assert_eq!(icmp.identifier_value(), None);
        assert_eq!(icmp.sequence_number_value(), None);
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), b"payload");
        // Recompiling reproduces the original bytes exactly.
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // Summaries stay stable across the typed bodies: known types report their
    // registry name with the numeric value kept visible, and echo bodies surface
    // their identifier and sequence number.
    #[test]
    fn icmpv4_header_model_summary_is_stable() {
        assert_eq!(
            Icmp::echo_request().id(0x4242).seq(1).summary(),
            "Icmp(type=echo-request(8), code=0, id=16962, seq=1)"
        );
        assert_eq!(
            Icmp::new().icmp_type(ICMP_REDIRECT).code(1).summary(),
            "Icmp(type=redirect(5), code=redirect-host(1), id=-, seq=-)"
        );
        // Unknown type falls back to the bare number and reports no echo fields.
        assert_eq!(
            Icmp::new().icmp_type(200).code(13).summary(),
            "Icmp(type=200, code=13, id=-, seq=-)"
        );
    }

    // Echo construction still matches the documented golden behavior: the typed
    // id/seq accessors and common kind are intact after the model refactor.
    #[test]
    fn icmpv4_header_model_echo_compatibility_is_intact() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::echo_request().id(0x4242).seq(1)
            / Raw::from("libcrafter-icmp");
        let compiled = packet.compile().unwrap();

        assert_eq!(&compiled.as_bytes()[20..22], &[ICMP_ECHO_REQUEST, 0]);
        assert_eq!(&compiled.as_bytes()[24..26], &0x4242u16.to_be_bytes());
        assert_eq!(&compiled.as_bytes()[26..28], &1u16.to_be_bytes());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.kind_value(), Some(IcmpKind::EchoRequest));
        assert_eq!(icmp.identifier_value(), Some(0x4242));
        assert_eq!(icmp.sequence_number_value(), Some(1));
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // The redirect gateway escape hatch fills the whole rest-of-header when the
    // caller sets a gateway and did not pin raw bytes.
    #[test]
    fn icmpv4_header_model_redirect_gateway_fills_rest() {
        let gateway = Ipv4Addr::new(192, 0, 2, 254);
        let icmp = Icmp::new().icmp_type(ICMP_REDIRECT).gateway(gateway);
        assert_eq!(icmp.gateway_value(), Some(gateway));
        assert_eq!(icmp.rest_of_header_value(), gateway.octets());
    }
}

#[cfg(test)]
mod icmpv4_legacy_assigned_types {
    use super::{
        icmpv4_code_summary, icmpv4_type_is_deprecated, icmpv4_type_summary, Icmp,
        ICMP_CODE_PHOTURIS_BAD_SPI, ICMP_CODE_PHOTURIS_NEED_AUTHORIZATION,
        ICMP_DATAGRAM_CONVERSION_ERROR, ICMP_DOMAIN_NAME_REPLY, ICMP_DOMAIN_NAME_REQUEST,
        ICMP_EXPERIMENTAL_253, ICMP_EXPERIMENTAL_254, ICMP_IPV6_I_AM_HERE, ICMP_IPV6_WHERE_ARE_YOU,
        ICMP_MOBILE_HOST_REDIRECT, ICMP_MOBILE_REGISTRATION_REPLY,
        ICMP_MOBILE_REGISTRATION_REQUEST, ICMP_PHOTURIS, ICMP_RESERVED_255,
        ICMP_SEAMOBY_EXPERIMENTAL, ICMP_SKIP, ICMP_TRACEROUTE,
    };
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // Representative legacy constructors set the assigned IANA type without
    // refusing it merely because it is deprecated or experimental, and a
    // trailing raw body survives compilation untouched.
    #[test]
    fn icmpv4_legacy_assigned_types_constructors_set_assigned_types() {
        let cases: &[(Icmp, u8)] = &[
            (Icmp::traceroute(), ICMP_TRACEROUTE),
            (
                Icmp::datagram_conversion_error(),
                ICMP_DATAGRAM_CONVERSION_ERROR,
            ),
            (Icmp::mobile_host_redirect(), ICMP_MOBILE_HOST_REDIRECT),
            (Icmp::ipv6_where_are_you(), ICMP_IPV6_WHERE_ARE_YOU),
            (Icmp::ipv6_i_am_here(), ICMP_IPV6_I_AM_HERE),
            (
                Icmp::mobile_registration_request(),
                ICMP_MOBILE_REGISTRATION_REQUEST,
            ),
            (
                Icmp::mobile_registration_reply(),
                ICMP_MOBILE_REGISTRATION_REPLY,
            ),
            (Icmp::domain_name_request(), ICMP_DOMAIN_NAME_REQUEST),
            (Icmp::domain_name_reply(), ICMP_DOMAIN_NAME_REPLY),
            (Icmp::skip(), ICMP_SKIP),
            (Icmp::photuris(), ICMP_PHOTURIS),
            (Icmp::seamoby_experimental(), ICMP_SEAMOBY_EXPERIMENTAL),
            (Icmp::experiment_1(), ICMP_EXPERIMENTAL_253),
            (Icmp::experiment_2(), ICMP_EXPERIMENTAL_254),
        ];

        for (icmp, expected_type) in cases {
            assert_eq!(
                icmp.icmp_type_value(),
                *expected_type,
                "constructor for type {expected_type} set the wrong type"
            );
            let bytes = (Ipv4::new().src(src()).dst(dst())
                / icmp.clone().rest_of_header([0xde, 0xad, 0xbe, 0xef])
                / Raw::from("legacy-body"))
            .compile()
            .unwrap();
            assert_eq!(bytes.as_bytes()[20], *expected_type);
            // The user-set rest-of-header survives compilation untouched.
            assert_eq!(&bytes.as_bytes()[24..28], &[0xde, 0xad, 0xbe, 0xef]);
            // The trailing raw body is emitted verbatim after the 8-byte header.
            assert_eq!(&bytes.as_bytes()[28..], b"legacy-body");
        }
    }

    // RFC 2521 Photuris defines codes 0-5; the constructor honors an explicit
    // code and the summary names it without hiding the numeric value.
    #[test]
    fn icmpv4_legacy_assigned_types_photuris_codes_summarize() {
        assert_eq!(ICMP_CODE_PHOTURIS_BAD_SPI, 0);
        assert_eq!(ICMP_CODE_PHOTURIS_NEED_AUTHORIZATION, 5);

        let icmp = Icmp::photuris().code(ICMP_CODE_PHOTURIS_NEED_AUTHORIZATION);
        assert_eq!(icmp.icmp_type_value(), ICMP_PHOTURIS);
        assert_eq!(icmp.code_value(), ICMP_CODE_PHOTURIS_NEED_AUTHORIZATION);
        assert_eq!(icmpv4_type_summary(ICMP_PHOTURIS), "photuris(40)");
        assert_eq!(
            icmpv4_code_summary(ICMP_PHOTURIS, ICMP_CODE_PHOTURIS_BAD_SPI),
            "bad-spi(0)"
        );
        assert_eq!(
            icmpv4_code_summary(ICMP_PHOTURIS, ICMP_CODE_PHOTURIS_NEED_AUTHORIZATION),
            "need-authorization(5)"
        );
    }

    // RFC 4727 experiment types 253/254 and the reserved type 255 must construct,
    // decode, and recompile byte-for-byte while reporting their assigned identity.
    #[test]
    fn icmpv4_legacy_assigned_types_experiment_and_reserved_roundtrip() {
        for (icmp, expected_type, name) in [
            (
                Icmp::experiment_1(),
                ICMP_EXPERIMENTAL_253,
                "experiment-1(253)",
            ),
            (
                Icmp::experiment_2(),
                ICMP_EXPERIMENTAL_254,
                "experiment-2(254)",
            ),
            (
                Icmp::new().icmp_type(ICMP_RESERVED_255),
                ICMP_RESERVED_255,
                "reserved(255)",
            ),
        ] {
            assert_eq!(icmp.icmp_type_value(), expected_type);
            assert_eq!(icmpv4_type_summary(expected_type), name);
            let compiled = (Ipv4::new().src(src()).dst(dst()) / icmp / Raw::from("xprmnt"))
                .compile()
                .unwrap();
            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
            let icmp = decoded.layer::<Icmp>().unwrap();
            assert_eq!(icmp.icmp_type_value(), expected_type);
            let raw = decoded.layer::<Raw>().unwrap();
            assert_eq!(raw.as_bytes(), b"xprmnt");
            assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
        }
    }

    // An unknown, unassigned type with an unknown code still decodes through the
    // generic header path and recompiles byte-for-byte, with both values left
    // numeric in the summary.
    #[test]
    fn icmpv4_legacy_assigned_types_unknown_type_falls_back_and_roundtrips() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::new()
                .icmp_type(200)
                .code(77)
                .rest_of_header([0x11, 0x22, 0x33, 0x44])
            / Raw::from("unknown"))
        .compile()
        .unwrap();

        assert_eq!(compiled.as_bytes()[20], 200);
        assert_eq!(compiled.as_bytes()[21], 77);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.icmp_type_value(), 200);
        assert_eq!(icmp.code_value(), 77);
        assert_eq!(icmp.rest_of_header_value(), [0x11, 0x22, 0x33, 0x44]);
        let raw = decoded.layer::<Raw>().unwrap();
        assert_eq!(raw.as_bytes(), b"unknown");

        // Unknown type and code remain bare numbers in the summary.
        assert_eq!(icmpv4_type_summary(200), "200");
        assert_eq!(icmpv4_code_summary(200, 77), "77");

        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // Deprecated legacy types keep their registry status reported while remaining
    // fully constructible and named in summaries.
    #[test]
    fn icmpv4_legacy_assigned_types_deprecated_status_is_visible() {
        assert!(icmpv4_type_is_deprecated(ICMP_TRACEROUTE));
        assert!(icmpv4_type_is_deprecated(ICMP_SKIP));
        assert!(icmpv4_type_is_deprecated(ICMP_MOBILE_HOST_REDIRECT));
        // Photuris and the experiment types are assigned but not flagged
        // deprecated; they still construct and decode.
        assert!(!icmpv4_type_is_deprecated(ICMP_PHOTURIS));
        assert!(!icmpv4_type_is_deprecated(ICMP_EXPERIMENTAL_253));

        assert_eq!(icmpv4_type_summary(ICMP_TRACEROUTE), "traceroute(30)");
        assert_eq!(
            icmpv4_type_summary(ICMP_DOMAIN_NAME_REQUEST),
            "domain-name-request(37)"
        );
        assert_eq!(icmpv4_type_summary(ICMP_SKIP), "skip(39)");
    }

    // A deprecated legacy type with a quoted body decodes and recompiles
    // byte-for-byte; the body stays raw-compatible because these types are not
    // typed beyond the fixed header.
    #[test]
    fn icmpv4_legacy_assigned_types_byte_for_byte_decode_compile_preservation() {
        let compiled = (Ipv4::new().src(src()).dst(dst()).proto(IpProtocol::Icmp)
            / Icmp::datagram_conversion_error()
                .code(1)
                .rest_of_header([0x00, 0x00, 0x00, 0x18])
            / Raw::from_bytes([0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.icmp_type_value(), ICMP_DATAGRAM_CONVERSION_ERROR);
        assert_eq!(icmp.code_value(), 1);
        let raw = decoded.layer::<Raw>().unwrap();
        assert_eq!(
            raw.as_bytes(),
            &[0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04]
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }
}
