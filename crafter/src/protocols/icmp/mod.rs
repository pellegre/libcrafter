//! ICMP, ICMPv6, and ICMP extension implementations.
//!
//! # ICMPv4 surface
//!
//! [`Icmp`] is the fixed 8-byte ICMPv4 header and the front of every ICMPv4
//! packet. Typed constructors cover the IANA registry: the RFC 792 echo, error,
//! timestamp, and information families; RFC 950 address mask; RFC 1256 router
//! discovery; RFC 8335 extended echo; and by-name constructors for the
//! deprecated and experimental legacy types. Data that follows the fixed header
//! is modeled as its own typed body or extension layer composed with `/`:
//!
//! - [`IcmpQuotedIpv4`] — the quoted original datagram in an ICMPv4 error.
//! - [`IcmpTimestamp`] — RFC 792 originate/receive/transmit timestamps.
//! - [`IcmpAddressMask`] — the RFC 950 address mask.
//! - [`IcmpRouterAdvertisementEntry`] — one RFC 1256 advertised router entry.
//! - [`IcmpExtension`] + [`IcmpExtensionObject`] — RFC 4884 multi-part framing
//!   and a generic extension object, with typed object bodies for RFC 4950 MPLS
//!   ([`IcmpExtensionMpls`]), RFC 5837 interface information
//!   ([`IcmpExtensionInterfaceInfo`]), and RFC 8335 interface identification
//!   ([`IcmpExtensionInterfaceId`]).
//!
//! `compile()` fills protocol-correct defaults the caller left unset — the ICMP
//! checksum, RFC 4884 length and zero padding, extension checksums, router
//! advertisement counts and entry size, and type-specific default codes — while
//! any value set explicitly survives untouched, including intentionally invalid
//! ones. The raw escape hatches [`Icmp::type_`], [`Icmp::code`],
//! [`Icmp::checksum`], and [`Icmp::rest_of_header`] (plus a [`Raw`] body) build
//! malformed or not-yet-typed messages.
//!
//! `decode_from_l3` (see [`crate::core::Packet::decode_from_l3`]) types the
//! header and any body it can parse defensibly; ambiguous, unknown, or
//! truncated trailing bytes stay a [`Raw`] payload, and genuine header
//! truncation returns a structured buffer error rather than panicking.
//! [`Packet::summary`](crate::core::Packet::summary) names known types and codes
//! while still printing raw numeric values, and
//! [`show`](crate::core::Packet::show) lists every typed field.
//!
//! ```rust
//! use crafter::prelude::*;
//! use std::net::Ipv4Addr;
//!
//! # fn main() -> crafter::Result<()> {
//! // A port-unreachable error quoting the datagram that triggered it.
//! let offending = Ipv4::new()
//!     .src(Ipv4Addr::new(198, 51, 100, 20))
//!     .dst(Ipv4Addr::new(192, 0, 2, 10))
//!     / Udp::new().sport(40000).dport(53)
//!     / Raw::from("query");
//!
//! let packet = Ipv4::new()
//!     .src(Ipv4Addr::new(192, 0, 2, 10))
//!     .dst(Ipv4Addr::new(198, 51, 100, 20))
//!     / Icmp::destination_unreachable().code(ICMP_CODE_DU_PORT_UNREACHABLE)
//!     / IcmpQuotedIpv4::new(offending);
//!
//! // compile() auto-fills the ICMP checksum and IPv4 length/protocol.
//! let bytes = packet.compile()?;
//!
//! // decode_from_l3 recovers the typed header and quoted datagram.
//! let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
//! let icmp = decoded.layer::<Icmp>().expect("icmp header");
//! assert_eq!(icmp.icmp_type_value(), ICMP_DESTINATION_UNREACHABLE);
//! let quote = decoded.layer::<IcmpQuotedIpv4>().expect("quoted datagram");
//! assert!(quote.quoted_layer::<Ipv4>().is_some());
//! # Ok(())
//! # }
//! ```

use core::any::Any;
use core::net::Ipv4Addr;
use core::ops::Div;
use core::str::FromStr;

use crate::checksum::internet_checksum;
use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet, Raw, TransportChecksumContext};
use crate::protocols::ip::{decode_quoted_ipv4, IPPROTO_ICMPV6};

mod constants;
pub use self::constants::*;

// ICMPv4 type numbers from the IANA ICMP Parameters registry
// (<https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml>).
// Status annotations follow the registry: Deprecated values are marked in their
// doc comments per RFC 6633 (Source Quench) and RFC 6918 (the bulk legacy
// deprecations). Deprecated and reserved values remain constructible and
// decodable; this step only names them and never refuses them.

// ICMPv4 code-field registries from the IANA ICMP Parameters registry.

const ICMP_HEADER_LEN: usize = 8;
/// RFC 792 timestamp body: originate, receive, and transmit timestamps, each a
/// 32-bit value (12 bytes total) following the fixed ICMP header.
const ICMP_TIMESTAMP_BODY_LEN: usize = 12;
/// RFC 950 address mask body: a single 32-bit address mask (4 bytes) following
/// the fixed ICMP header.
const ICMP_ADDRESS_MASK_BODY_LEN: usize = 4;
/// RFC 1256 router advertisement entry: a 32-bit router address plus a 32-bit
/// preference level (8 bytes total).
const ICMP_ROUTER_ADVERTISEMENT_ENTRY_LEN: usize = 8;
const ICMP_EXTENSION_HEADER_LEN: usize = 4;
const ICMP_EXTENSION_OBJECT_LEN: usize = 4;
const ICMP_EXTENSION_MPLS_LEN: usize = 4;
/// RFC 5837 ifIndex sub-object: a single 32-bit interface index.
const ICMP_INTERFACE_IFINDEX_LEN: usize = 4;
/// RFC 5837 IP Address sub-object fixed prefix: 16-bit AFI plus 16-bit reserved.
const ICMP_INTERFACE_IP_ADDRESS_PREFIX_LEN: usize = 4;
/// RFC 5837 MTU sub-object: a single 32-bit MTU value.
const ICMP_INTERFACE_MTU_LEN: usize = 4;
/// RFC 5837 maximum interface-name octets (the length octet plus up to 63 name
/// octets, capped at 64 total).
const ICMP_INTERFACE_NAME_MAX: usize = 63;
/// RFC 8335 Interface Identification Object ifIndex body: a single 32-bit index.
const ICMP_INTERFACE_ID_INDEX_LEN: usize = 4;
/// RFC 8335 Interface Identification Object address body fixed prefix: 16-bit
/// AFI, 8-bit address length, and 8-bit reserved.
const ICMP_INTERFACE_ID_ADDRESS_PREFIX_LEN: usize = 4;
/// RFC 4884 expected extension header version for ICMP multi-part messages.
const ICMP_EXTENSION_VERSION: u8 = 2;
/// RFC 4884 minimum "original datagram" size, in octets, when an ICMPv4 message
/// carries an appended extension structure. Shorter quoted datagrams are zero
/// padded up to this length before the extension header.
const ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM: usize = 128;
const MPLS_MAX_LABEL: u32 = 0x000f_ffff;
const MPLS_MAX_EXP: u8 = 0x07;

macro_rules! impl_layer_object {
    ($type:ty) => {
        fn clone_layer(&self) -> Box<dyn Layer> {
            Box::new(self.clone())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }

        fn into_any(self: Box<Self>) -> Box<dyn Any> {
            self
        }
    };
}

macro_rules! impl_layer_div {
    ($type:ty) => {
        impl<R> Div<R> for $type
        where
            R: IntoPacket,
        {
            type Output = Packet;

            fn div(self, rhs: R) -> Self::Output {
                Packet::from_layer(self).concat(rhs)
            }
        }
    };
}
mod icmpv6;
pub use self::icmpv6::Icmpv6;
pub(crate) use self::icmpv6::append_icmpv6_packet;

mod extensions;
pub use self::extensions::*;

/// ICMP message kind shared by IPv4 and IPv6 builders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IcmpKind {
    /// Destination unreachable.
    DestinationUnreachable,
    /// Time exceeded.
    TimeExceeded,
    /// Parameter problem.
    ParameterProblem,
    /// Echo request.
    EchoRequest,
    /// Echo reply.
    EchoReply,
}

impl IcmpKind {
    /// ICMPv4 type value for this common kind.
    pub const fn ipv4_type(self) -> u8 {
        match self {
            Self::DestinationUnreachable => ICMP_DESTINATION_UNREACHABLE,
            Self::TimeExceeded => ICMP_TIME_EXCEEDED,
            Self::ParameterProblem => ICMP_PARAMETER_PROBLEM,
            Self::EchoRequest => ICMP_ECHO_REQUEST,
            Self::EchoReply => ICMP_ECHO_REPLY,
        }
    }

    /// ICMPv6 type value for this common kind.
    pub const fn ipv6_type(self) -> u8 {
        match self {
            Self::DestinationUnreachable => ICMPV6_DESTINATION_UNREACHABLE,
            Self::TimeExceeded => ICMPV6_TIME_EXCEEDED,
            Self::ParameterProblem => ICMPV6_PARAMETER_PROBLEM,
            Self::EchoRequest => ICMPV6_ECHO_REQUEST,
            Self::EchoReply => ICMPV6_ECHO_REPLY,
        }
    }
}

/// Version-independent ICMP behavior used by ping-style tools.
pub trait IcmpLayer: Layer {
    /// Raw ICMP type value.
    fn icmp_type_value(&self) -> u8;

    /// Raw ICMP code value.
    fn code_value(&self) -> u8;

    /// Stored checksum value, when explicit or decoded.
    fn checksum_value(&self) -> Option<u16>;

    /// Echo identifier when this layer carries one.
    fn identifier_value(&self) -> Option<u16>;

    /// Echo sequence number when this layer carries one.
    fn sequence_number_value(&self) -> Option<u16>;

    /// Common message kind, when the type maps cleanly across ICMP versions.
    fn kind(&self) -> Option<IcmpKind>;

    /// Return true for echo requests.
    fn is_echo_request(&self) -> bool {
        self.kind() == Some(IcmpKind::EchoRequest)
    }

    /// Return true for echo replies.
    fn is_echo_reply(&self) -> bool {
        self.kind() == Some(IcmpKind::EchoReply)
    }
}

/// Internet Control Message Protocol for IPv4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp {
    icmp_type: Field<u8>,
    code: Field<u8>,
    checksum: Field<u16>,
    rest_of_header: Field<[u8; 4]>,
    identifier: Field<u16>,
    sequence_number: Field<u16>,
    pointer: Field<u8>,
    gateway: Field<Ipv4Addr>,
    length: Field<u8>,
    mtu_next_hop: Field<u16>,
    num_addrs: Field<u8>,
    addr_entry_size: Field<u8>,
    lifetime: Field<u16>,
    extended_flags: Field<u8>,
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

/// Quoted original IPv4 datagram carried by an ICMPv4 error message.
///
/// RFC 792 error messages (destination unreachable, source quench, redirect,
/// time exceeded, parameter problem) append the IPv4 header plus at least the
/// first 64 bits of the offending datagram so the originator can match the
/// error to the packet it sent. This layer holds that quoted datagram as a
/// nested [`Packet`] of typed layers, keeping the packet abstraction intact:
/// the quoted IPv4 header, transport header, and payload are inspectable just
/// like any other layer stack.
///
/// On decode the quote is parsed leniently: a valid IPv4 prefix is typed,
/// unknown quoted next protocols and truncated quotes remain raw-compatible,
/// and a non-IPv4 quote leaves the bytes as a plain `Raw` payload instead of
/// producing this layer.
#[derive(Debug, Clone)]
pub struct IcmpQuotedIpv4 {
    datagram: Packet,
}

impl IcmpQuotedIpv4 {
    /// Wrap a quoted original datagram built from typed packet layers.
    pub fn new(datagram: impl IntoPacket) -> Self {
        Self {
            datagram: datagram.into_packet(),
        }
    }

    /// Borrow the quoted datagram as a typed packet stack.
    pub fn datagram(&self) -> &Packet {
        &self.datagram
    }

    /// Mutably borrow the quoted datagram.
    pub fn datagram_mut(&mut self) -> &mut Packet {
        &mut self.datagram
    }

    /// First quoted layer of type `T`, when the quote was typed on decode.
    pub fn quoted_layer<T>(&self) -> Option<&T>
    where
        T: Layer,
    {
        self.datagram.layer::<T>()
    }
}

impl PartialEq for IcmpQuotedIpv4 {
    fn eq(&self, other: &Self) -> bool {
        // Layers are not directly comparable through trait objects, so compare
        // the compiled byte image. Quoted datagrams decode every field as
        // user-set, so this is a faithful structural comparison.
        match (self.datagram.compile(), other.datagram.compile()) {
            (Ok(left), Ok(right)) => left.as_bytes() == right.as_bytes(),
            _ => false,
        }
    }
}

impl Layer for IcmpQuotedIpv4 {
    fn name(&self) -> &'static str {
        "IcmpQuotedIpv4"
    }

    fn summary(&self) -> String {
        format!("IcmpQuotedIpv4({})", self.datagram.summary())
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("quoted_len", self.datagram.encoded_len().to_string()),
            ("quoted", self.datagram.summary()),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.datagram.encoded_len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.datagram.compile_into(out)
    }

    impl_layer_object!(IcmpQuotedIpv4);
}

impl_layer_div!(IcmpQuotedIpv4);

/// RFC 792 timestamp message body.
///
/// Timestamp request (type 13) and timestamp reply (type 14) append three
/// 32-bit timestamps after the fixed ICMP header: the originate timestamp set
/// by the requester, the receive timestamp set when the responder received the
/// request, and the transmit timestamp set when the responder sent the reply.
/// RFC 792 defines each as milliseconds since midnight UT; a sender that cannot
/// supply a standard value may set the high-order bit, so the raw 32-bit values
/// are exposed verbatim rather than reinterpreted.
///
/// This layer always encodes exactly 12 bytes. Malformed timestamp lengths
/// (a short or oversized trailing region) are not forced into this layer on
/// decode; they remain a [`Raw`] payload so the bytes are never lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpTimestamp {
    originate: Field<u32>,
    receive: Field<u32>,
    transmit: Field<u32>,
}

impl IcmpTimestamp {
    /// Create a timestamp body with all three timestamps defaulted to zero.
    pub fn new() -> Self {
        Self {
            originate: Field::defaulted(0),
            receive: Field::defaulted(0),
            transmit: Field::defaulted(0),
        }
    }

    /// Set the originate timestamp.
    pub fn originate(mut self, originate: u32) -> Self {
        self.originate.set_user(originate);
        self
    }

    /// Set the receive timestamp.
    pub fn receive(mut self, receive: u32) -> Self {
        self.receive.set_user(receive);
        self
    }

    /// Set the transmit timestamp.
    pub fn transmit(mut self, transmit: u32) -> Self {
        self.transmit.set_user(transmit);
        self
    }

    /// Originate timestamp value.
    pub fn originate_value(&self) -> u32 {
        value_or_copy(&self.originate, 0)
    }

    /// Receive timestamp value.
    pub fn receive_value(&self) -> u32 {
        value_or_copy(&self.receive, 0)
    }

    /// Transmit timestamp value.
    pub fn transmit_value(&self) -> u32 {
        value_or_copy(&self.transmit, 0)
    }
}

impl Default for IcmpTimestamp {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpTimestamp {
    fn name(&self) -> &'static str {
        "IcmpTimestamp"
    }

    fn summary(&self) -> String {
        format!(
            "IcmpTimestamp(originate={}, receive={}, transmit={})",
            self.originate_value(),
            self.receive_value(),
            self.transmit_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("originate", self.originate_value().to_string()),
            ("receive", self.receive_value().to_string()),
            ("transmit", self.transmit_value().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_TIMESTAMP_BODY_LEN
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.originate_value().to_be_bytes());
        out.extend_from_slice(&self.receive_value().to_be_bytes());
        out.extend_from_slice(&self.transmit_value().to_be_bytes());
        Ok(())
    }

    impl_layer_object!(IcmpTimestamp);
}

impl_layer_div!(IcmpTimestamp);

/// RFC 950 address mask message body.
///
/// Address mask request (type 17) and address mask reply (type 18) append a
/// single 32-bit address mask after the fixed ICMP header. RFC 950 has the
/// requesting host set the mask to zero and the responding gateway return the
/// 32-bit subnet/network mask. The identifier and sequence number live in the
/// fixed header's rest-of-header, like an echo.
///
/// Both messages are deprecated by RFC 6918 but remain constructible and
/// decodable. The mask is modeled as an [`Ipv4Addr`] for convenience while the
/// raw four bytes stay inspectable through [`IcmpAddressMask::mask_octets`].
///
/// This layer always encodes exactly four bytes. A trailing region that is not
/// exactly four bytes is not forced into this layer on decode; it stays a
/// [`Raw`] payload so the bytes are never lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpAddressMask {
    mask: Field<Ipv4Addr>,
}

impl IcmpAddressMask {
    /// Create an address mask body defaulting to the all-zero mask RFC 950
    /// specifies for a request.
    pub fn new() -> Self {
        Self {
            mask: Field::defaulted(Ipv4Addr::UNSPECIFIED),
        }
    }

    /// Set the 32-bit address mask.
    pub fn mask(mut self, mask: Ipv4Addr) -> Self {
        self.mask.set_user(mask);
        self
    }

    /// Set the address mask from dotted-quad text.
    pub fn mask_str(self, mask: &str) -> Result<Self> {
        Ok(self.mask(parse_ipv4(mask)?))
    }

    /// Set the address mask from a raw 32-bit value.
    pub fn mask_bits(self, mask: u32) -> Self {
        self.mask(Ipv4Addr::from(mask))
    }

    /// Address mask value as an [`Ipv4Addr`].
    pub fn mask_value(&self) -> Ipv4Addr {
        value_or_copy(&self.mask, Ipv4Addr::UNSPECIFIED)
    }

    /// Address mask as its raw four bytes.
    pub fn mask_octets(&self) -> [u8; 4] {
        self.mask_value().octets()
    }
}

impl Default for IcmpAddressMask {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpAddressMask {
    fn name(&self) -> &'static str {
        "IcmpAddressMask"
    }

    fn summary(&self) -> String {
        format!("IcmpAddressMask(mask={})", self.mask_value())
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("mask", self.mask_value().to_string()),
            ("mask_bytes", hex_bytes(&self.mask_octets())),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_ADDRESS_MASK_BODY_LEN
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.mask_octets());
        Ok(())
    }

    impl_layer_object!(IcmpAddressMask);
}

impl_layer_div!(IcmpAddressMask);

/// RFC 1256 router advertisement entry.
///
/// A router advertisement (type 9) lists one entry per advertised router after
/// the fixed ICMP header. The standard entry format (Addr Entry Size of two
/// 32-bit words) is a 4-byte router address followed by a 4-byte signed
/// preference level: higher preference levels are preferred, and the reserved
/// value 0x8000_0000 means the address must not be used as a default router.
///
/// This layer always encodes exactly eight bytes. The router address is modeled
/// as an [`Ipv4Addr`] for convenience while the raw four address bytes stay
/// inspectable through [`IcmpRouterAdvertisementEntry::router_address_octets`].
/// The preference level is exposed as a raw `i32` so the full signed range,
/// including the reserved "do not use" value, survives untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpRouterAdvertisementEntry {
    router_address: Field<Ipv4Addr>,
    preference_level: Field<i32>,
}

impl IcmpRouterAdvertisementEntry {
    /// Create a router advertisement entry defaulting to the unspecified
    /// address and a zero preference level.
    pub fn new() -> Self {
        Self {
            router_address: Field::defaulted(Ipv4Addr::UNSPECIFIED),
            preference_level: Field::defaulted(0),
        }
    }

    /// Set the advertised router address.
    pub fn router_address(mut self, router_address: Ipv4Addr) -> Self {
        self.router_address.set_user(router_address);
        self
    }

    /// Set the advertised router address from dotted-quad text.
    pub fn router_address_str(self, router_address: &str) -> Result<Self> {
        Ok(self.router_address(parse_ipv4(router_address)?))
    }

    /// Set the signed preference level.
    pub fn preference_level(mut self, preference_level: i32) -> Self {
        self.preference_level.set_user(preference_level);
        self
    }

    /// Router address value as an [`Ipv4Addr`].
    pub fn router_address_value(&self) -> Ipv4Addr {
        value_or_copy(&self.router_address, Ipv4Addr::UNSPECIFIED)
    }

    /// Router address as its raw four bytes.
    pub fn router_address_octets(&self) -> [u8; 4] {
        self.router_address_value().octets()
    }

    /// Signed preference level value.
    pub fn preference_level_value(&self) -> i32 {
        value_or_copy(&self.preference_level, 0)
    }
}

impl Default for IcmpRouterAdvertisementEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpRouterAdvertisementEntry {
    fn name(&self) -> &'static str {
        "IcmpRouterAdvertisementEntry"
    }

    fn summary(&self) -> String {
        format!(
            "IcmpRouterAdvertisementEntry(router={}, preference={})",
            self.router_address_value(),
            self.preference_level_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("router_address", self.router_address_value().to_string()),
            (
                "router_address_bytes",
                hex_bytes(&self.router_address_octets()),
            ),
            (
                "preference_level",
                self.preference_level_value().to_string(),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_ROUTER_ADVERTISEMENT_ENTRY_LEN
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.router_address_octets());
        out.extend_from_slice(&self.preference_level_value().to_be_bytes());
        Ok(())
    }

    impl_layer_object!(IcmpRouterAdvertisementEntry);
}

impl_layer_div!(IcmpRouterAdvertisementEntry);

/// Append a decoded ICMP packet to an existing packet stack.
pub(crate) fn append_icmp_packet(mut packet: Packet, bytes: &[u8]) -> Result<Packet> {
    let (icmp, payload) = decode_icmp_parts(bytes)?;
    let icmp_type = icmp.icmp_type_value();
    // RFC 1256 router advertisement fields are read from the fixed header before
    // it is pushed (and moved) so the entry parser below can use them.
    let ra_num_addrs = icmp.num_addrs_value().unwrap_or(0) as usize;
    let ra_entry_words = icmp.addr_entry_size_value().unwrap_or(0) as usize;
    // RFC 4884 length field (32-bit words of the padded original datagram) for
    // the extension-capable error types; read before the header is moved.
    let rfc4884_length_words = if icmpv4_type_allows_extensions(icmp_type) {
        icmp.length_value().unwrap_or(0) as usize
    } else {
        0
    };
    packet = packet.push(icmp);

    if payload.is_empty() {
        return Ok(packet);
    }

    // RFC 792 error messages quote the original datagram after the fixed
    // header. Type it as an `IcmpQuotedIpv4` layer when the quote begins with a
    // parseable IPv4 header; anything left over (or an unparseable quote)
    // stays raw-compatible so the bytes are never dropped.
    if icmpv4_type_is_error(icmp_type) {
        if let Some((quoted, consumed)) = decode_quoted_ipv4(payload) {
            packet = packet.push(IcmpQuotedIpv4 { datagram: quoted });
            let trailing = &payload[consumed..];
            if trailing.is_empty() {
                return Ok(packet);
            }
            // RFC 4884: when the length field claims a padded original datagram
            // and a valid extension structure follows, split the trailing bytes
            // into the extension header and its objects. Anything that does not
            // parse defensibly (bad version, bad checksum, non-canonical
            // padding, impossible object lengths) stays a single `Raw` tail.
            match decode_icmp_extensions(payload, consumed, rfc4884_length_words) {
                Some(layers) => {
                    for layer in layers {
                        packet = packet.push_box(layer);
                    }
                }
                None => {
                    packet = packet.push(Raw::from_bytes(trailing));
                }
            }
            return Ok(packet);
        }
    }

    // RFC 8335 extended echo request carries an RFC 4884 extension structure
    // (extension header plus a single Interface Identification Object) directly
    // after the fixed header — no quoted datagram and no original-datagram
    // padding. Type it when the structure parses defensibly; anything else
    // (bad version, bad checksum, impossible object lengths) stays raw so the
    // bytes survive and decoding never panics. The reply has no body, so any
    // trailing bytes on a reply fall through to the raw tail below.
    if icmp_type == ICMP_EXTENDED_ECHO_REQUEST {
        if let Some(layers) = decode_extended_echo_extension(payload) {
            for layer in layers {
                packet = packet.push_box(layer);
            }
            return Ok(packet);
        }
    }

    // RFC 792 timestamp messages carry exactly three 32-bit timestamps after
    // the fixed header. Type the body only when its length is exactly right;
    // a short or oversized region is a malformed timestamp and stays raw so the
    // bytes survive and decoding never panics.
    if matches!(icmp_type, ICMP_TIMESTAMP | ICMP_TIMESTAMP_REPLY)
        && payload.len() == ICMP_TIMESTAMP_BODY_LEN
    {
        let originate = read_u32_be(&payload[0..4])?;
        let receive = read_u32_be(&payload[4..8])?;
        let transmit = read_u32_be(&payload[8..12])?;
        packet = packet.push(IcmpTimestamp {
            originate: Field::user(originate),
            receive: Field::user(receive),
            transmit: Field::user(transmit),
        });
        return Ok(packet);
    }

    // RFC 950 address mask messages carry exactly one 32-bit mask after the
    // fixed header. Type the body only when its length is exactly right; any
    // other length is malformed and stays raw so the bytes survive and decoding
    // never panics.
    if matches!(
        icmp_type,
        ICMP_ADDRESS_MASK_REQUEST | ICMP_ADDRESS_MASK_REPLY
    ) && payload.len() == ICMP_ADDRESS_MASK_BODY_LEN
    {
        let mask = Ipv4Addr::from(copy_array_4(&payload[0..4]));
        packet = packet.push(IcmpAddressMask {
            mask: Field::user(mask),
        });
        return Ok(packet);
    }

    // RFC 1256 router advertisement entries follow the fixed header. Type them
    // only when the message uses the standard entry size (two 32-bit words) and
    // the body length is exactly Num Addrs entries; any other shape (a
    // non-standard Addr Entry Size, a count/length mismatch, or trailing data)
    // is left raw so unusual or malformed bodies survive and decoding never
    // panics.
    if icmp_type == ICMP_ROUTER_ADVERTISEMENT
        && ra_entry_words == ICMP_ROUTER_ADVERTISEMENT_ENTRY_WORDS as usize
        && payload.len() == ra_num_addrs * ICMP_ROUTER_ADVERTISEMENT_ENTRY_LEN
        && ra_num_addrs > 0
    {
        for chunk in payload.chunks_exact(ICMP_ROUTER_ADVERTISEMENT_ENTRY_LEN) {
            let router_address = Ipv4Addr::from(copy_array_4(&chunk[0..4]));
            let preference_level = read_u32_be(&chunk[4..8])? as i32;
            packet = packet.push(IcmpRouterAdvertisementEntry {
                router_address: Field::user(router_address),
                preference_level: Field::user(preference_level),
            });
        }
        return Ok(packet);
    }

    packet = packet.push(Raw::from_bytes(payload));
    Ok(packet)
}

/// Decode the RFC 4884 extension structure that follows a quoted original
/// datagram, returning the typed [`IcmpExtension`] and [`IcmpExtensionObject`]
/// layers (plus a `Raw` body per object) when the parse is defensible.
///
/// `payload` is the ICMP body after the fixed header, `quoted_len` is the
/// number of bytes consumed by the quoted datagram, and `length_words` is the
/// RFC 4884 length field (32-bit words of the padded original datagram).
///
/// Returns `None` — so the caller keeps the trailing bytes as a single `Raw`
/// tail — whenever the length field claims no extensions, the claimed offset is
/// out of range, the padding is non-canonical (so a typed round-trip would not
/// reproduce the bytes), the extension version is not 2, the extension checksum
/// does not verify, or an object length is impossible. The quoted datagram is
/// never dropped, so an ambiguous structure stays inspectable as raw bytes.
fn decode_icmp_extensions(
    payload: &[u8],
    quoted_len: usize,
    length_words: usize,
) -> Option<Vec<Box<dyn Layer>>> {
    // A zero length field means "no extensions" per RFC 4884.
    if length_words == 0 {
        return None;
    }

    let ext_start = length_words * ICMP_EXTENSION_OBJECT_LEN;
    // The claimed original datagram region must contain the quote and leave room
    // for at least the extension header.
    if ext_start < quoted_len || ext_start + ICMP_EXTENSION_HEADER_LEN > payload.len() {
        return None;
    }

    // The padding between the quote and the extension header is part of the
    // original datagram. Only a canonical (zero) padding round-trips, because
    // the encoder regenerates it from the length field; anything else is left
    // raw so the bytes survive unchanged.
    if payload[quoted_len..ext_start].iter().any(|&byte| byte != 0) {
        return None;
    }

    let extension = &payload[ext_start..];
    let version = extension[0] >> 4;
    if version != ICMP_EXTENSION_VERSION {
        return None;
    }
    let reserved = u16::from_be_bytes([extension[0], extension[1]]) & 0x0fff;
    let stored_checksum = u16::from_be_bytes([extension[2], extension[3]]);

    // RFC 4884: a zero checksum means none was transmitted; otherwise the one's
    // complement sum over the whole extension structure must verify. A bad
    // checksum is treated as "not really an extension" and the bytes stay raw.
    if stored_checksum != 0 && internet_checksum(extension) != 0 {
        return None;
    }

    let objects = decode_icmp_extension_objects(&extension[ICMP_EXTENSION_HEADER_LEN..])?;

    let mut layers: Vec<Box<dyn Layer>> = Vec::with_capacity(1 + objects.len());
    layers.push(Box::new(
        IcmpExtension::new()
            .version(version)
            .reserved(reserved)
            .checksum(stored_checksum),
    ));
    layers.extend(objects);
    Some(layers)
}

/// Decode the RFC 4884 extension structure carried by an RFC 8335 extended echo
/// request, which begins immediately after the fixed ICMP header (no quoted
/// original datagram and no original-datagram padding).
///
/// Returns the typed [`IcmpExtension`] header and its objects (an
/// [`IcmpExtensionInterfaceId`] for the standard single Interface Identification
/// Object, or generic objects otherwise) when the structure parses defensibly.
/// Returns `None` — so the caller keeps the payload as a single `Raw` body —
/// when the payload is too short for the extension header, the version is not 2,
/// the extension checksum does not verify, or an object length is impossible.
fn decode_extended_echo_extension(payload: &[u8]) -> Option<Vec<Box<dyn Layer>>> {
    if payload.len() < ICMP_EXTENSION_HEADER_LEN {
        return None;
    }

    let version = payload[0] >> 4;
    if version != ICMP_EXTENSION_VERSION {
        return None;
    }
    let reserved = u16::from_be_bytes([payload[0], payload[1]]) & 0x0fff;
    let stored_checksum = u16::from_be_bytes([payload[2], payload[3]]);

    // RFC 4884: a zero checksum means none was transmitted; otherwise the one's
    // complement sum over the whole extension structure must verify.
    if stored_checksum != 0 && internet_checksum(payload) != 0 {
        return None;
    }

    let objects = decode_icmp_extension_objects(&payload[ICMP_EXTENSION_HEADER_LEN..])?;

    let mut layers: Vec<Box<dyn Layer>> = Vec::with_capacity(1 + objects.len());
    layers.push(Box::new(
        IcmpExtension::new()
            .version(version)
            .reserved(reserved)
            .checksum(stored_checksum),
    ));
    layers.extend(objects);
    Some(layers)
}

/// Decode the object stream that follows an RFC 4884 extension header into
/// [`IcmpExtensionObject`] layers, each followed by the object body.
///
/// RFC 4950 MPLS label stack objects (class 1, C-Type 1) whose body is a whole
/// number of 4-octet entries decode into typed [`IcmpExtensionMpls`] layers,
/// preserving the label, experimental/traffic-class bits, bottom-of-stack bit,
/// and TTL of each entry. RFC 5837 interface information objects (class 2)
/// whose body parses cleanly per the C-Type presence bits decode into a typed
/// [`IcmpExtensionInterfaceInfo`] layer. Every other object — and any object
/// whose body does not parse defensibly — keeps its body as a single `Raw`
/// payload so unknown classes/sub-types and malformed bodies round-trip
/// byte-for-byte.
///
/// Returns `None` when an object header is truncated or claims a length that
/// does not fit the remaining bytes, so the caller can keep the whole region
/// raw rather than fabricating a structure.
fn decode_icmp_extension_objects(mut bytes: &[u8]) -> Option<Vec<Box<dyn Layer>>> {
    let mut objects: Vec<Box<dyn Layer>> = Vec::new();

    while !bytes.is_empty() {
        if bytes.len() < ICMP_EXTENSION_OBJECT_LEN {
            return None;
        }
        let length = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        // The length covers the 4-byte object header plus its payload and must
        // fit in the remaining bytes; anything else is an impossible object.
        if length < ICMP_EXTENSION_OBJECT_LEN || length > bytes.len() {
            return None;
        }
        let class_num = bytes[2];
        let c_type = bytes[3];
        objects.push(Box::new(
            IcmpExtensionObject::new()
                .length(length as u16)
                .class_num(class_num)
                .c_type(c_type),
        ));
        let body = &bytes[ICMP_EXTENSION_OBJECT_LEN..length];
        if !body.is_empty() {
            // RFC 4950: a MPLS label stack object carries one or more 4-octet
            // label stack entries. Type them only when the body is a whole
            // number of entries; a partial entry is a malformed body and stays
            // raw so the bytes survive and decoding never panics.
            if class_num == ICMP_EXTENSION_CLASS_MPLS
                && c_type == ICMP_EXTENSION_CTYPE_MPLS_INCOMING
                && body.len() % ICMP_EXTENSION_MPLS_LEN == 0
            {
                for chunk in body.chunks_exact(ICMP_EXTENSION_MPLS_LEN) {
                    objects.push(Box::new(decode_mpls_entry(chunk)));
                }
            } else if class_num == ICMP_EXTENSION_CLASS_INTERFACE_INFO {
                // RFC 5837: type the body per the C-Type presence bits, but only
                // when the sub-objects consume the whole body exactly (so a
                // re-compile reproduces the bytes). Anything else stays raw.
                match decode_interface_info(c_type, body) {
                    Some(info) => objects.push(Box::new(info)),
                    None => objects.push(Box::new(Raw::from_bytes(body))),
                }
            } else if class_num == ICMP_EXTENSION_CLASS_INTERFACE_ID {
                // RFC 8335: type the Interface Identification Object body per its
                // C-Type (name/index/address) when it parses defensibly with
                // canonical zero padding; anything else stays raw so the bytes
                // round-trip unchanged.
                match decode_interface_id(c_type, body) {
                    Some(id) => objects.push(Box::new(id)),
                    None => objects.push(Box::new(Raw::from_bytes(body))),
                }
            } else {
                objects.push(Box::new(Raw::from_bytes(body)));
            }
        }
        bytes = &bytes[length..];
    }

    Some(objects)
}

fn decode_icmp_parts(bytes: &[u8]) -> Result<(Icmp, &[u8])> {
    if bytes.len() < ICMP_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "icmp header",
            ICMP_HEADER_LEN,
            bytes.len(),
        ));
    }

    let rest = copy_array_4(&bytes[4..8]);
    let icmp_type = bytes[0];
    // RFC 8335 extended echo: identifier (bytes 0-1), an 8-bit sequence number
    // (byte 2, zero-extended into the u16 sequence field), and a flag byte
    // (byte 3). RFC 792/RFC 950 query families keep their 16-bit sequence.
    let extended = is_extended_echo_v4(icmp_type);
    let identifier = if extended {
        Field::user(u16::from_be_bytes([rest[0], rest[1]]))
    } else {
        field_from_echo(icmp_type, &rest, 0, is_query_v4)
    };
    let sequence_number = if extended {
        Field::user(u16::from(rest[2]))
    } else {
        field_from_echo(icmp_type, &rest, 2, is_query_v4)
    };
    let icmp = Icmp {
        icmp_type: Field::user(icmp_type),
        code: Field::user(bytes[1]),
        checksum: Field::user(read_u16_be(&bytes[2..4])?),
        rest_of_header: Field::user(rest),
        identifier,
        sequence_number,
        pointer: if icmp_type == ICMP_PARAMETER_PROBLEM {
            Field::user(rest[0])
        } else {
            Field::unset()
        },
        gateway: if icmp_type == ICMP_REDIRECT {
            Field::user(Ipv4Addr::from(rest))
        } else {
            Field::unset()
        },
        length: if icmpv4_type_allows_extensions(icmp_type) {
            Field::user(rest[1])
        } else {
            Field::unset()
        },
        mtu_next_hop: if icmp_type == ICMP_DESTINATION_UNREACHABLE {
            Field::user(u16::from_be_bytes([rest[2], rest[3]]))
        } else {
            Field::unset()
        },
        num_addrs: if icmp_type == ICMP_ROUTER_ADVERTISEMENT {
            Field::user(rest[0])
        } else {
            Field::unset()
        },
        addr_entry_size: if icmp_type == ICMP_ROUTER_ADVERTISEMENT {
            Field::user(rest[1])
        } else {
            Field::unset()
        },
        lifetime: if icmp_type == ICMP_ROUTER_ADVERTISEMENT {
            Field::user(u16::from_be_bytes([rest[2], rest[3]]))
        } else {
            Field::unset()
        },
        extended_flags: if extended {
            Field::user(rest[3])
        } else {
            Field::unset()
        },
    };

    Ok((icmp, &bytes[ICMP_HEADER_LEN..]))
}

fn payload_bytes_after(ctx: LayerContext<'_>) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    for (index, layer) in ctx.packet().iter().enumerate().skip(ctx.index() + 1) {
        let layer_ctx = LayerContext::new(ctx.packet(), index);
        layer.compile(&layer_ctx, &mut payload)?;
    }
    Ok(payload)
}

fn router_advertisement_entry_count(ctx: LayerContext<'_>) -> usize {
    ctx.packet()
        .iter()
        .skip(ctx.index() + 1)
        .take_while(|layer| layer.as_any().is::<IcmpRouterAdvertisementEntry>())
        .count()
}

fn encoded_len_until_extension(ctx: LayerContext<'_>) -> usize {
    ctx.packet()
        .iter()
        .skip(ctx.index() + 1)
        .take_while(|layer| !layer.as_any().is::<IcmpExtension>())
        .map(Layer::encoded_len)
        .sum()
}

/// True when an [`IcmpExtension`] header follows the layer at `ctx` (looking
/// past the quoted original datagram). RFC 4884 length, padding, and the
/// minimum original datagram size only apply when an extension structure is
/// actually appended.
fn following_extension_present(ctx: LayerContext<'_>) -> bool {
    ctx.packet()
        .iter()
        .skip(ctx.index() + 1)
        .any(|layer| layer.as_any().is::<IcmpExtension>())
}

/// RFC 4884 padded "original datagram" length, in octets.
///
/// The quoted datagram is zero padded to the nearest 32-bit (`unit`-byte)
/// boundary and to at least [`ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM`] octets, so
/// the appended extension structure starts at a predictable offset that a
/// compliant receiver can locate from the length field.
fn rfc4884_padded_original_len(raw_len: usize, unit: usize) -> usize {
    let unit = unit.max(1);
    let rounded = raw_len.div_ceil(unit) * unit;
    rounded.max(ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM)
}

/// Zero-padding inserted between the quoted original datagram and the
/// [`IcmpExtension`] at `ctx`, so the original datagram field reaches its RFC
/// 4884 padded length.
///
/// The padding target is driven by the preceding [`Icmp`] length field: an
/// explicit (or decoded) length is honored verbatim so deliberately malformed
/// or non-canonical packets round-trip, while an unset length falls back to the
/// auto-computed minimum/word-rounded size. This keeps the byte the length
/// field claims and the bytes actually emitted consistent.
fn extension_original_datagram_padding(ctx: LayerContext<'_>) -> usize {
    // RFC 4884 original-datagram padding is scoped to ICMPv4 here: when no
    // ICMPv4 `Icmp` header precedes the extension (for example an ICMPv6 stack,
    // whose RFC 4884 framing is not in scope), nothing is padded so the layer's
    // size stays its bare header length.
    let Some(target) = preceding_icmp_original_datagram_len(ctx) else {
        return 0;
    };
    let raw_len = original_datagram_len_before_extension(ctx);
    target.saturating_sub(raw_len)
}

/// Sum of encoded lengths of the layers strictly between the nearest preceding
/// [`Icmp`] header and the [`IcmpExtension`] at `ctx` — i.e. the unpadded
/// quoted original datagram bytes.
fn original_datagram_len_before_extension(ctx: LayerContext<'_>) -> usize {
    let Some(icmp_index) = preceding_icmp_index(ctx) else {
        return 0;
    };
    ((icmp_index + 1)..ctx.index())
        .filter_map(|index| ctx.packet().get(index))
        .map(Layer::encoded_len)
        .sum()
}

/// Padded original datagram length, in octets, claimed by the nearest preceding
/// [`Icmp`] header's RFC 4884 length field. Returns `None` when there is no
/// preceding ICMPv4 header or it carries no length field.
fn preceding_icmp_original_datagram_len(ctx: LayerContext<'_>) -> Option<usize> {
    let icmp_index = preceding_icmp_index(ctx)?;
    let icmp = ctx
        .packet()
        .get(icmp_index)?
        .as_any()
        .downcast_ref::<Icmp>()?;
    let icmp_ctx = LayerContext::new(ctx.packet(), icmp_index);
    let words = icmp
        .effective_extension_length(Some(icmp_ctx), ICMP_EXTENSION_OBJECT_LEN)
        .ok()??;
    Some(words as usize * ICMP_EXTENSION_OBJECT_LEN)
}

/// Index of the nearest [`Icmp`] layer preceding `ctx`, if any.
fn preceding_icmp_index(ctx: LayerContext<'_>) -> Option<usize> {
    (0..ctx.index()).rev().find(|&index| {
        ctx.packet()
            .get(index)
            .is_some_and(|layer| layer.as_any().is::<Icmp>())
    })
}

fn extension_object_payload_len(ctx: LayerContext<'_>) -> usize {
    ctx.packet()
        .iter()
        .skip(ctx.index() + 1)
        .take_while(|layer| {
            !layer.as_any().is::<IcmpExtensionObject>() && !layer.as_any().is::<IcmpExtension>()
        })
        .map(Layer::encoded_len)
        .sum()
}

fn checksum_context(
    ctx: LayerContext<'_>,
    transport_protocol: u8,
) -> Option<TransportChecksumContext> {
    (0..ctx.index()).rev().find_map(|index| {
        ctx.packet()
            .get(index)
            .and_then(|layer| layer.transport_checksum_context(transport_protocol))
    })
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn value_or_u16_from_rest(field: &Field<u16>, rest: &Field<[u8; 4]>, offset: usize) -> u16 {
    field.value().copied().unwrap_or_else(|| {
        let rest = rest.value().copied().unwrap_or([0; 4]);
        u16::from_be_bytes([rest[offset], rest[offset + 1]])
    })
}

fn value_or_u8_from_rest(field: &Field<u8>, rest: &Field<[u8; 4]>, offset: usize) -> u8 {
    field.value().copied().unwrap_or_else(|| {
        let rest = rest.value().copied().unwrap_or([0; 4]);
        rest[offset]
    })
}

fn field_from_echo(
    icmp_type: u8,
    rest: &[u8; 4],
    offset: usize,
    is_echo: fn(u8) -> bool,
) -> Field<u16> {
    if is_echo(icmp_type) {
        Field::user(u16::from_be_bytes([rest[offset], rest[offset + 1]]))
    } else {
        Field::unset()
    }
}

fn parse_ipv4(input: &str) -> Result<Ipv4Addr> {
    Ipv4Addr::from_str(input).map_err(|_| {
        CrafterError::invalid_field_value("ipv4_address", "expected dotted-quad IPv4 address")
    })
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();

    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(&format!("{byte:02x}"));
    }

    output
}

fn copy_array_4(bytes: &[u8]) -> [u8; 4] {
    let mut out = [0u8; 4];
    out.copy_from_slice(&bytes[..4]);
    out
}

#[cfg(test)]
mod icmp_tests {
    use super::{
        Icmp, IcmpExtension, IcmpExtensionMpls, IcmpExtensionObject, IcmpKind, ICMP_ECHO_REQUEST,
        ICMP_TIME_EXCEEDED,
    };
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw, Udp};
    use core::net::Ipv4Addr;

    const IPV4_ICMP_FIXTURE: &[u8] = fixture_bytes!("bytes/ipv4-icmp-echo-request.bin");

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn icmp_echo_request_matches_golden_bytes() {
        let packet = Ipv4::new()
            .src(src())
            .dst(dst())
            .id(0x1234)
            .dont_fragment(true)
            / Icmp::echo_request().id(0x4242).seq(1)
            / Raw::from("libcrafter-icmp");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes(), IPV4_ICMP_FIXTURE);
        assert_eq!(&bytes.as_bytes()[20..22], &[ICMP_ECHO_REQUEST, 0]);
        assert_eq!(&bytes.as_bytes()[22..24], &0xa7d0u16.to_be_bytes());
    }

    #[test]
    fn icmp_decode_from_ipv4_exposes_echo_fields_and_payload() {
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, IPV4_ICMP_FIXTURE).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(icmp.kind_value(), Some(IcmpKind::EchoRequest));
        assert_eq!(icmp.code_value(), 0);
        assert_eq!(icmp.checksum_value(), Some(0xa7d0));
        assert_eq!(icmp.identifier_value(), Some(0x4242));
        assert_eq!(icmp.sequence_number_value(), Some(1));
        assert_eq!(raw.as_bytes(), b"libcrafter-icmp");
        assert_eq!(decoded.compile().unwrap().as_bytes(), IPV4_ICMP_FIXTURE);
    }

    #[test]
    fn icmp_explicit_checksum_is_preserved() {
        let bytes = (Ipv4::new().src(src()).dst(dst())
            / Icmp::echo_request().id(7).seq(8).checksum(0x1111)
            / Raw::from("abc"))
        .compile()
        .unwrap();

        assert_eq!(&bytes.as_bytes()[22..24], &[0x11, 0x11]);
    }

    #[test]
    fn icmp_time_exceeded_autofills_length_and_extension_objects() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded().code(0)
            / (Ipv4::new()
                .src(Ipv4Addr::new(5, 6, 7, 8))
                .dst(Ipv4Addr::new(10, 11, 12, 13))
                .proto(IpProtocol::Udp)
                / Udp::new().sport(53).dport(1111)
                / Raw::from("data"))
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(1234).ttl(100)
            / IcmpExtensionMpls::new()
                .label(2345)
                .experimental(6)
                .ttl(150);
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[20], ICMP_TIME_EXCEEDED);
        // RFC 4884: the 32-byte quoted datagram is zero padded up to the 128
        // octet minimum, so the length field reports 32 words and the extension
        // structure starts 96 padding bytes after the 32-byte quote.
        assert_eq!(bytes.as_bytes()[25], 32);
        assert!(bytes.as_bytes()[60..156].iter().all(|&byte| byte == 0));
        // Extension header (version 2, reserved 0) at the padded boundary.
        assert_eq!(&bytes.as_bytes()[156..158], &[0x20, 0x00]);
        // Extension object: length 12 (4-byte header + two MPLS words), class 1
        // (MPLS), C-Type 1 (incoming label stack).
        assert_eq!(&bytes.as_bytes()[160..164], &[0x00, 0x0c, 0x01, 0x01]);
        assert_eq!(bytes.as_bytes()[166] & 0x01, 0);
        assert_eq!(bytes.as_bytes()[170] & 0x01, 1);
    }

    #[test]
    fn icmp_decode_rejects_short_inputs() {
        let short = (Ipv4::new().proto(IpProtocol::Icmp) / Raw::from_bytes([0u8; 7]))
            .compile()
            .unwrap();
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv4, short.as_bytes()).is_err());
    }
}

#[cfg(test)]
mod ping_roundtrip {
    use super::{Icmp, IcmpKind, IcmpLayer, Icmpv6};
    use crate::{Ipv4, Ipv6, NetworkLayer, Packet, Raw};
    use core::net::{Ipv4Addr, Ipv6Addr};

    fn echo_reply_matches(request: &dyn IcmpLayer, reply: &dyn IcmpLayer) -> bool {
        request.kind() == Some(IcmpKind::EchoRequest)
            && reply.kind() == Some(IcmpKind::EchoReply)
            && request.identifier_value() == reply.identifier_value()
            && request.sequence_number_value() == reply.sequence_number_value()
    }

    #[test]
    fn ping_roundtrip_matches_ipv4_echo_reply_by_id_and_sequence() {
        let src = Ipv4Addr::new(192, 0, 2, 10);
        let dst = Ipv4Addr::new(198, 51, 100, 20);
        let request = Ipv4::new().src(src).dst(dst)
            / Icmp::echo_request().id(0x7777).seq(9)
            / Raw::from("ping");
        let reply = Ipv4::new().src(dst).dst(src)
            / Icmp::echo_reply().id(0x7777).seq(9)
            / Raw::from("ping");

        let decoded_request =
            Packet::decode_from_l3(NetworkLayer::Ipv4, request.compile().unwrap()).unwrap();
        let decoded_reply =
            Packet::decode_from_l3(NetworkLayer::Ipv4, reply.compile().unwrap()).unwrap();

        assert!(echo_reply_matches(
            decoded_request.layer::<Icmp>().unwrap(),
            decoded_reply.layer::<Icmp>().unwrap()
        ));
    }

    #[test]
    fn ping_roundtrip_matches_ipv6_echo_reply_by_id_and_sequence() {
        let src = Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0x0db8, 2, 0, 0, 0, 0, 2);
        let request = Ipv6::new().src(src).dst(dst)
            / Icmpv6::echo_request().id(0x8888).seq(10)
            / Raw::from("ping6");
        let reply = Ipv6::new().src(dst).dst(src)
            / Icmpv6::echo_reply().id(0x8888).seq(10)
            / Raw::from("ping6");

        let decoded_request =
            Packet::decode_from_l3(NetworkLayer::Ipv6, request.compile().unwrap()).unwrap();
        let decoded_reply =
            Packet::decode_from_l3(NetworkLayer::Ipv6, reply.compile().unwrap()).unwrap();

        assert!(echo_reply_matches(
            decoded_request.layer::<Icmpv6>().unwrap(),
            decoded_reply.layer::<Icmpv6>().unwrap()
        ));
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
mod icmpv4_rfc792_errors {
    use super::{
        icmpv4_code_summary, icmpv4_type_is_deprecated, Icmp, IcmpQuotedIpv4,
        ICMP_CODE_DU_FRAGMENTATION_NEEDED, ICMP_CODE_DU_PORT_UNREACHABLE,
        ICMP_CODE_PARAMETER_PROBLEM_POINTER, ICMP_CODE_REDIRECT_HOST,
        ICMP_CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY, ICMP_DESTINATION_UNREACHABLE,
        ICMP_PARAMETER_PROBLEM, ICMP_REDIRECT, ICMP_SOURCE_QUENCH, ICMP_TIME_EXCEEDED,
    };
    use crate::packet::Layer;
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw, Udp};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // A complete quoted original datagram (IPv4 + UDP + payload) that an agent
    // would construct for an error message.
    fn quoted_udp() -> Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 1))
            .proto(IpProtocol::Udp)
            / Udp::new().sport(40000).dport(53)
            / Raw::from("query")
    }

    // Each RFC 792 error type compiles with the type/code the caller chose and
    // carries its quoted datagram. The quoted IPv4 source/destination survive a
    // full decode round-trip as typed layers.
    #[test]
    fn icmpv4_rfc792_errors_each_type_quotes_original_datagram() {
        for (icmp_type, code) in [
            (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_PORT_UNREACHABLE),
            (ICMP_SOURCE_QUENCH, 0),
            (
                ICMP_TIME_EXCEEDED,
                ICMP_CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY,
            ),
            (ICMP_PARAMETER_PROBLEM, ICMP_CODE_PARAMETER_PROBLEM_POINTER),
        ] {
            let packet = Ipv4::new().src(src()).dst(dst())
                / Icmp::new().icmp_type(icmp_type).code(code)
                / IcmpQuotedIpv4::new(quoted_udp());
            let compiled = packet.compile().unwrap();
            assert_eq!(compiled.as_bytes()[20], icmp_type);
            assert_eq!(compiled.as_bytes()[21], code);

            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
            let icmp = decoded.layer::<Icmp>().unwrap();
            assert_eq!(icmp.icmp_type_value(), icmp_type);
            assert_eq!(icmp.code_value(), code);

            let quoted = decoded.layer::<IcmpQuotedIpv4>().unwrap();
            let inner = quoted.quoted_layer::<Ipv4>().unwrap();
            assert_eq!(inner.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(inner.destination(), Ipv4Addr::new(198, 51, 100, 1));
            let inner_udp = quoted.quoted_layer::<Udp>().unwrap();
            assert_eq!(inner_udp.destination_port_value(), 53);
            assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
        }
    }

    // Representative codes for the error types that carry an IANA code registry
    // render their stable names while keeping the numeric value visible.
    #[test]
    fn icmpv4_rfc792_errors_representative_codes_summarize() {
        assert_eq!(
            icmpv4_code_summary(ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_PORT_UNREACHABLE),
            "port-unreachable(3)"
        );
        assert_eq!(
            icmpv4_code_summary(
                ICMP_TIME_EXCEEDED,
                ICMP_CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY
            ),
            "fragment-reassembly-time-exceeded(1)"
        );
        assert_eq!(
            icmpv4_code_summary(ICMP_PARAMETER_PROBLEM, ICMP_CODE_PARAMETER_PROBLEM_POINTER),
            "pointer(0)"
        );
    }

    // Redirect carries the gateway address in the rest-of-header; the typed
    // gateway accessor survives a decode round-trip and the quoted datagram is
    // typed alongside it.
    #[test]
    fn icmpv4_rfc792_errors_redirect_gateway_and_quote_roundtrip() {
        let gateway = Ipv4Addr::new(192, 0, 2, 254);
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::new()
                .icmp_type(ICMP_REDIRECT)
                .code(ICMP_CODE_REDIRECT_HOST)
                .gateway(gateway)
            / IcmpQuotedIpv4::new(quoted_udp());
        let compiled = packet.compile().unwrap();
        // Rest-of-header (ICMP bytes 4..8) holds the gateway address.
        assert_eq!(&compiled.as_bytes()[24..28], &gateway.octets());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.gateway_value(), Some(gateway));
        assert_eq!(icmp.code_value(), ICMP_CODE_REDIRECT_HOST);
        assert!(decoded.layer::<IcmpQuotedIpv4>().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // Parameter problem carries the pointer byte at rest-of-header[0]; it
    // survives a decode round-trip.
    #[test]
    fn icmpv4_rfc792_errors_parameter_problem_pointer_roundtrip() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::new().icmp_type(ICMP_PARAMETER_PROBLEM).pointer(12)
            / IcmpQuotedIpv4::new(quoted_udp());
        let compiled = packet.compile().unwrap();
        assert_eq!(compiled.as_bytes()[24], 12);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert_eq!(decoded.layer::<Icmp>().unwrap().pointer_value(), Some(12));
    }

    // Source quench (type 4) is deprecated by RFC 6633 but still constructible
    // and decodable as an error message with a quoted datagram.
    #[test]
    fn icmpv4_rfc792_errors_source_quench_is_deprecated_but_usable() {
        assert!(icmpv4_type_is_deprecated(ICMP_SOURCE_QUENCH));

        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::new().icmp_type(ICMP_SOURCE_QUENCH)
            / IcmpQuotedIpv4::new(quoted_udp());
        let compiled = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert_eq!(
            decoded.layer::<Icmp>().unwrap().icmp_type_value(),
            ICMP_SOURCE_QUENCH
        );
        assert!(decoded.layer::<IcmpQuotedIpv4>().is_some());
    }

    // RFC 1191: destination unreachable code 4 (fragmentation needed) carries an
    // unused high-order 16 bits and a 16-bit next-hop MTU in the second word.
    #[test]
    fn icmpv4_rfc792_errors_rfc1191_next_hop_mtu_roundtrips() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::new()
                .icmp_type(ICMP_DESTINATION_UNREACHABLE)
                .code(ICMP_CODE_DU_FRAGMENTATION_NEEDED)
                .mtu_next_hop(1492)
            / IcmpQuotedIpv4::new(quoted_udp());
        let compiled = packet.compile().unwrap();
        // ICMP rest-of-header: bytes 4..6 unused (RFC 4884 length byte aside),
        // bytes 6..8 are the next-hop MTU. Byte index 24 is rest-of-header[0].
        assert_eq!(&compiled.as_bytes()[26..28], &1492u16.to_be_bytes());
        // The high-order unused word must stay zero.
        assert_eq!(compiled.as_bytes()[24], 0);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert_eq!(
            decoded.layer::<Icmp>().unwrap().mtu_next_hop_value(),
            Some(1492)
        );
    }

    // A quoted datagram that is only the IPv4 header plus the first 8 bytes of
    // the original payload (the RFC 792 minimum) is the common truncated case:
    // the IPv4 header is typed, the truncated payload stays raw-compatible, and
    // nothing panics.
    #[test]
    fn icmpv4_rfc792_errors_truncated_quote_does_not_panic() {
        // Build a full datagram, then keep only header + 8 payload bytes so the
        // quoted IPv4 total_length deliberately overshoots the present bytes.
        let original = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 1))
            .proto(IpProtocol::Udp)
            / Udp::new().sport(40000).dport(53)
            / Raw::from("a-long-original-payload"))
        .compile()
        .unwrap();
        let mut quote = original.as_bytes().to_vec();
        quote.truncate(20 + 8); // IPv4 header (20) + 64 bits of original data.

        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::new().icmp_type(ICMP_TIME_EXCEEDED)
            / Raw::from_bytes(&quote);
        let compiled = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let quoted = decoded.layer::<IcmpQuotedIpv4>().unwrap();
        let inner = quoted.quoted_layer::<Ipv4>().unwrap();
        assert_eq!(inner.source(), Ipv4Addr::new(192, 0, 2, 1));
        // The truncated UDP header could not be fully decoded, so it stays raw.
        assert!(quoted.quoted_layer::<Udp>().is_none());
        assert!(quoted.datagram().layer::<Raw>().is_some());
        // The whole message still round-trips byte-for-byte.
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // A quoted next protocol crafter does not decode (here protocol 254) keeps
    // the quoted IPv4 header typed and the rest of the quote raw-compatible.
    #[test]
    fn icmpv4_rfc792_errors_unknown_quoted_protocol_falls_back_to_raw() {
        let quoted = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 1))
            .protocol(254)
            / Raw::from("opaque-upper-layer");
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::new().icmp_type(ICMP_DESTINATION_UNREACHABLE)
            / IcmpQuotedIpv4::new(quoted);
        let compiled = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let quoted = decoded.layer::<IcmpQuotedIpv4>().unwrap();
        let inner = quoted.quoted_layer::<Ipv4>().unwrap();
        assert_eq!(inner.protocol_value(), 254);
        assert_eq!(
            quoted.datagram().layer::<Raw>().unwrap().as_bytes(),
            b"opaque-upper-layer"
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // A non-IPv4 quote (the bytes do not start with a valid IPv4 header) is not
    // forced into the typed quoted layer; it remains a plain Raw payload so no
    // bytes are lost.
    #[test]
    fn icmpv4_rfc792_errors_non_ipv4_quote_stays_raw() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::new().icmp_type(ICMP_DESTINATION_UNREACHABLE)
            / Raw::from_bytes([0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let compiled = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpQuotedIpv4>().is_none());
        assert_eq!(
            decoded.layer::<Raw>().unwrap().as_bytes(),
            &[0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        );
    }

    // Explicit malformed overrides on an error message survive compilation: a
    // deliberately wrong checksum and a pinned raw rest-of-header are emitted
    // verbatim even though the type would otherwise auto-fill them.
    #[test]
    fn icmpv4_rfc792_errors_explicit_malformed_overrides_are_preserved() {
        let raw_rest = [0xde, 0xad, 0xbe, 0xef];
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::new()
                .icmp_type(ICMP_TIME_EXCEEDED)
                .code(0)
                .checksum(0xbeef)
                .rest_of_header(raw_rest)
            / IcmpQuotedIpv4::new(quoted_udp());
        let compiled = packet.compile().unwrap();

        // The intentionally wrong checksum is honored verbatim.
        assert_eq!(&compiled.as_bytes()[22..24], &0xbeefu16.to_be_bytes());
        // The pinned rest-of-header survives the RFC 4884 length auto-fill.
        assert_eq!(&compiled.as_bytes()[24..28], &raw_rest);
    }

    // The quoted layer summary keeps the nested datagram inspectable.
    #[test]
    fn icmpv4_rfc792_errors_quoted_layer_summary_is_inspectable() {
        let quoted = IcmpQuotedIpv4::new(quoted_udp());
        let summary = quoted.summary();
        assert!(summary.starts_with("IcmpQuotedIpv4("));
        assert!(summary.contains("Ipv4"));
    }
}

#[cfg(test)]
mod icmpv4_rfc792_queries {
    use super::{
        icmpv4_type_is_deprecated, icmpv4_type_summary, Icmp, IcmpTimestamp,
        ICMP_INFORMATION_REPLY, ICMP_INFORMATION_REQUEST, ICMP_TIMESTAMP, ICMP_TIMESTAMP_REPLY,
    };
    use crate::checksum::internet_checksum;
    use crate::packet::Layer;
    use crate::{Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // A timestamp request compiles its fixed header (with identifier and
    // sequence) plus the three 32-bit timestamps, and the typed body survives a
    // full decode round-trip with its values intact.
    #[test]
    fn icmpv4_rfc792_queries_timestamp_compile_decode_roundtrip() {
        for icmp_type in [ICMP_TIMESTAMP, ICMP_TIMESTAMP_REPLY] {
            let packet = Ipv4::new().src(src()).dst(dst())
                / Icmp::new().icmp_type(icmp_type).id(0x1234).seq(7)
                / IcmpTimestamp::new()
                    .originate(0x0a0b_0c0d)
                    .receive(0x11223344)
                    .transmit(0x55667788);
            let compiled = packet.compile().unwrap();

            // ICMP header begins at byte 20 (20-byte IPv4 header, no options).
            assert_eq!(compiled.as_bytes()[20], icmp_type);
            assert_eq!(compiled.as_bytes()[21], 0); // code
                                                    // Identifier (bytes 24..26) and sequence (bytes 26..28).
            assert_eq!(&compiled.as_bytes()[24..26], &0x1234u16.to_be_bytes());
            assert_eq!(&compiled.as_bytes()[26..28], &7u16.to_be_bytes());
            // Timestamp body (bytes 28..40): originate, receive, transmit.
            assert_eq!(&compiled.as_bytes()[28..32], &0x0a0b_0c0du32.to_be_bytes());
            assert_eq!(&compiled.as_bytes()[32..36], &0x11223344u32.to_be_bytes());
            assert_eq!(&compiled.as_bytes()[36..40], &0x55667788u32.to_be_bytes());

            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
            let icmp = decoded.layer::<Icmp>().unwrap();
            assert_eq!(icmp.icmp_type_value(), icmp_type);
            // Identifier and sequence are inspectable for the timestamp family.
            assert_eq!(icmp.identifier_value(), Some(0x1234));
            assert_eq!(icmp.sequence_number_value(), Some(7));
            // Timestamp is not an echo, so it maps to no common ping kind.
            assert_eq!(icmp.kind_value(), None);

            let ts = decoded.layer::<IcmpTimestamp>().unwrap();
            assert_eq!(ts.originate_value(), 0x0a0b_0c0d);
            assert_eq!(ts.receive_value(), 0x11223344);
            assert_eq!(ts.transmit_value(), 0x55667788);
            // No leftover raw bytes when the body length is exactly 12.
            assert!(decoded.layer::<Raw>().is_none());
            assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
        }
    }

    // The timestamp constructors set the right types and default the body to
    // zero timestamps.
    #[test]
    fn icmpv4_rfc792_queries_timestamp_constructors_set_types() {
        assert_eq!(Icmp::timestamp_request().icmp_type_value(), ICMP_TIMESTAMP);
        assert_eq!(
            Icmp::timestamp_reply().icmp_type_value(),
            ICMP_TIMESTAMP_REPLY
        );
        let ts = IcmpTimestamp::new();
        assert_eq!(ts.originate_value(), 0);
        assert_eq!(ts.receive_value(), 0);
        assert_eq!(ts.transmit_value(), 0);
    }

    // The ICMP checksum is auto-filled over the header plus the timestamp body
    // when the caller leaves it unset.
    #[test]
    fn icmpv4_rfc792_queries_timestamp_checksum_autofill() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::timestamp_request().id(0x4242).seq(3)
            / IcmpTimestamp::new().originate(1).receive(2).transmit(3);
        let compiled = packet.compile().unwrap();

        // Recompute the expected checksum over the full ICMP message (header +
        // 12-byte timestamp body) with the checksum field zeroed.
        let icmp_message = &compiled.as_bytes()[20..];
        let mut zeroed = icmp_message.to_vec();
        zeroed[2] = 0;
        zeroed[3] = 0;
        let expected = internet_checksum(&zeroed);
        assert_ne!(expected, 0);
        assert_eq!(
            &compiled.as_bytes()[22..24],
            &expected.to_be_bytes(),
            "auto-filled checksum must cover the timestamp body"
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert_eq!(
            decoded.layer::<Icmp>().unwrap().checksum_value(),
            Some(expected)
        );
    }

    // An explicit (deliberately wrong) checksum on a timestamp message is
    // emitted verbatim instead of being recomputed over the body.
    #[test]
    fn icmpv4_rfc792_queries_timestamp_explicit_checksum_override() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::timestamp_request().id(1).seq(1).checksum(0xbeef)
            / IcmpTimestamp::new().originate(9).receive(9).transmit(9);
        let compiled = packet.compile().unwrap();

        assert_eq!(&compiled.as_bytes()[22..24], &0xbeefu16.to_be_bytes());
    }

    // Information request and reply are constructible (RFC 792) and carry only
    // the identifier and sequence number with no body beyond the fixed header.
    #[test]
    fn icmpv4_rfc792_queries_information_request_reply_construction() {
        for icmp_type in [ICMP_INFORMATION_REQUEST, ICMP_INFORMATION_REPLY] {
            let packet = Ipv4::new().src(src()).dst(dst())
                / Icmp::new().icmp_type(icmp_type).id(0x0a0b).seq(0x0c0d);
            let compiled = packet.compile().unwrap();

            assert_eq!(compiled.as_bytes()[20], icmp_type);
            assert_eq!(compiled.as_bytes()[21], 0);
            assert_eq!(&compiled.as_bytes()[24..26], &0x0a0bu16.to_be_bytes());
            assert_eq!(&compiled.as_bytes()[26..28], &0x0c0du16.to_be_bytes());
            // No body bytes follow the fixed 8-byte ICMP header.
            assert_eq!(compiled.as_bytes().len(), 20 + 8);

            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
            let icmp = decoded.layer::<Icmp>().unwrap();
            assert_eq!(icmp.icmp_type_value(), icmp_type);
            assert_eq!(icmp.identifier_value(), Some(0x0a0b));
            assert_eq!(icmp.sequence_number_value(), Some(0x0c0d));
            // Information messages are not echoes, so they carry no ping kind.
            assert_eq!(icmp.kind_value(), None);
            assert!(decoded.layer::<Raw>().is_none());
            assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
        }

        // The dedicated constructors set the same types.
        assert_eq!(
            Icmp::information_request().icmp_type_value(),
            ICMP_INFORMATION_REQUEST
        );
        assert_eq!(
            Icmp::information_reply().icmp_type_value(),
            ICMP_INFORMATION_REPLY
        );
    }

    // Information messages are deprecated by RFC 6918 but keep their registry
    // identity in summaries and are flagged as deprecated. Naming them never
    // doubles as refusing them (construction above succeeds).
    #[test]
    fn icmpv4_rfc792_queries_deprecated_information_summaries() {
        assert_eq!(
            icmpv4_type_summary(ICMP_INFORMATION_REQUEST),
            "information-request(15)"
        );
        assert_eq!(
            icmpv4_type_summary(ICMP_INFORMATION_REPLY),
            "information-reply(16)"
        );
        assert!(icmpv4_type_is_deprecated(ICMP_INFORMATION_REQUEST));
        assert!(icmpv4_type_is_deprecated(ICMP_INFORMATION_REPLY));

        // Timestamp messages are active (not deprecated) and keep their names.
        assert_eq!(icmpv4_type_summary(ICMP_TIMESTAMP), "timestamp(13)");
        assert_eq!(
            icmpv4_type_summary(ICMP_TIMESTAMP_REPLY),
            "timestamp-reply(14)"
        );
        assert!(!icmpv4_type_is_deprecated(ICMP_TIMESTAMP));

        // The body summary exposes the three typed timestamps.
        let summary = IcmpTimestamp::new()
            .originate(1)
            .receive(2)
            .transmit(3)
            .summary();
        assert_eq!(summary, "IcmpTimestamp(originate=1, receive=2, transmit=3)");
    }

    // A timestamp message whose trailing region is the wrong length (not exactly
    // 12 bytes) is malformed: the typed body parser declines it, the bytes
    // remain a Raw payload, decoding does not panic, and the message still
    // round-trips byte-for-byte.
    #[test]
    fn icmpv4_rfc792_queries_malformed_timestamp_stays_raw() {
        // Short body: only 8 of the 12 timestamp bytes are present.
        let short = Ipv4::new().src(src()).dst(dst())
            / Icmp::timestamp_request().id(1).seq(1)
            / Raw::from_bytes([0xaa; 8]);
        let compiled = short.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpTimestamp>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[0xaa; 8]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());

        // Oversized body: 12 timestamp bytes plus trailing unknown data.
        let mut body = vec![0u8; 12];
        body.extend_from_slice(b"trailing");
        let long = Ipv4::new().src(src()).dst(dst())
            / Icmp::timestamp_reply().id(2).seq(2)
            / Raw::from_bytes(&body);
        let compiled = long.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpTimestamp>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &body[..]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // True buffer truncation (fewer than 8 bytes of ICMP header) returns a
    // structured buffer error rather than panicking.
    #[test]
    fn icmpv4_rfc792_queries_truncated_header_is_structured_error() {
        let short = (Ipv4::new().proto(crate::IpProtocol::Icmp)
            / Raw::from_bytes([ICMP_TIMESTAMP; 5]))
        .compile()
        .unwrap();
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv4, short.as_bytes()).is_err());
    }
}

#[cfg(test)]
mod icmpv4_address_mask {
    use super::{
        icmpv4_type_is_deprecated, icmpv4_type_summary, Icmp, IcmpAddressMask,
        ICMP_ADDRESS_MASK_REPLY, ICMP_ADDRESS_MASK_REQUEST,
    };
    use crate::checksum::internet_checksum;
    use crate::packet::Layer;
    use crate::{Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // An address mask request (RFC 950) compiles its fixed header (with
    // identifier and sequence) plus the 32-bit mask, with the mask defaulting to
    // all zeros per RFC 950, and round-trips through decode with its fields
    // intact.
    #[test]
    fn icmpv4_address_mask_request_compile_decode_roundtrip() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::address_mask_request().id(0x1234).seq(7)
            / IcmpAddressMask::new();
        let compiled = packet.compile().unwrap();

        // ICMP header begins at byte 20 (20-byte IPv4 header, no options).
        assert_eq!(compiled.as_bytes()[20], ICMP_ADDRESS_MASK_REQUEST);
        assert_eq!(compiled.as_bytes()[21], 0); // code
                                                // Identifier (bytes 24..26) and sequence (bytes 26..28).
        assert_eq!(&compiled.as_bytes()[24..26], &0x1234u16.to_be_bytes());
        assert_eq!(&compiled.as_bytes()[26..28], &7u16.to_be_bytes());
        // RFC 950 request: the address mask body (bytes 28..32) is all zeros.
        assert_eq!(&compiled.as_bytes()[28..32], &[0, 0, 0, 0]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.icmp_type_value(), ICMP_ADDRESS_MASK_REQUEST);
        // Identifier and sequence are inspectable for the address mask family.
        assert_eq!(icmp.identifier_value(), Some(0x1234));
        assert_eq!(icmp.sequence_number_value(), Some(7));
        // Address mask is not an echo, so it maps to no common ping kind.
        assert_eq!(icmp.kind_value(), None);

        let mask = decoded.layer::<IcmpAddressMask>().unwrap();
        assert_eq!(mask.mask_value(), Ipv4Addr::UNSPECIFIED);
        // No leftover raw bytes when the body length is exactly 4.
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // An address mask reply carries the gateway's subnet/network mask, exposed
    // through both the typed Ipv4Addr accessor and the raw octets, and survives
    // a full decode round-trip.
    #[test]
    fn icmpv4_address_mask_reply_compile_decode_roundtrip_and_accessors() {
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::address_mask_reply().id(0xabcd).seq(9)
            / IcmpAddressMask::new().mask(mask);
        let compiled = packet.compile().unwrap();

        assert_eq!(compiled.as_bytes()[20], ICMP_ADDRESS_MASK_REPLY);
        // The 32-bit mask body holds the subnet mask verbatim.
        assert_eq!(&compiled.as_bytes()[28..32], &mask.octets());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let body = decoded.layer::<IcmpAddressMask>().unwrap();
        assert_eq!(body.mask_value(), mask);
        assert_eq!(body.mask_octets(), [255, 255, 255, 0]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());

        // The mask escape hatches agree with the typed accessor.
        assert_eq!(
            IcmpAddressMask::new().mask_bits(0xffff_ff00).mask_value(),
            mask
        );
        assert_eq!(
            IcmpAddressMask::new()
                .mask_str("255.255.255.0")
                .unwrap()
                .mask_value(),
            mask
        );
    }

    // The address mask constructors set the right types and default the body to
    // the all-zero mask.
    #[test]
    fn icmpv4_address_mask_constructors_set_types() {
        assert_eq!(
            Icmp::address_mask_request().icmp_type_value(),
            ICMP_ADDRESS_MASK_REQUEST
        );
        assert_eq!(
            Icmp::address_mask_reply().icmp_type_value(),
            ICMP_ADDRESS_MASK_REPLY
        );
        assert_eq!(IcmpAddressMask::new().mask_value(), Ipv4Addr::UNSPECIFIED);
    }

    // The ICMP checksum is auto-filled over the header plus the address mask
    // body when the caller leaves it unset.
    #[test]
    fn icmpv4_address_mask_checksum_autofill() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::address_mask_reply().id(0x4242).seq(3)
            / IcmpAddressMask::new().mask(Ipv4Addr::new(255, 255, 0, 0));
        let compiled = packet.compile().unwrap();

        // Recompute the expected checksum over the full ICMP message (header +
        // 4-byte mask body) with the checksum field zeroed.
        let icmp_message = &compiled.as_bytes()[20..];
        let mut zeroed = icmp_message.to_vec();
        zeroed[2] = 0;
        zeroed[3] = 0;
        let expected = internet_checksum(&zeroed);
        assert_ne!(expected, 0);
        assert_eq!(
            &compiled.as_bytes()[22..24],
            &expected.to_be_bytes(),
            "auto-filled checksum must cover the address mask body"
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert_eq!(
            decoded.layer::<Icmp>().unwrap().checksum_value(),
            Some(expected)
        );
    }

    // An explicit (deliberately wrong) checksum on an address mask message is
    // emitted verbatim instead of being recomputed over the body.
    #[test]
    fn icmpv4_address_mask_explicit_checksum_override() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::address_mask_request().id(1).seq(1).checksum(0xbeef)
            / IcmpAddressMask::new();
        let compiled = packet.compile().unwrap();

        assert_eq!(&compiled.as_bytes()[22..24], &0xbeefu16.to_be_bytes());
    }

    // Both address mask types are deprecated by RFC 6918 but keep their registry
    // identity in summaries and are flagged as deprecated. Naming them never
    // doubles as refusing them (construction above succeeds).
    #[test]
    fn icmpv4_address_mask_deprecated_summaries() {
        assert_eq!(
            icmpv4_type_summary(ICMP_ADDRESS_MASK_REQUEST),
            "address-mask-request(17)"
        );
        assert_eq!(
            icmpv4_type_summary(ICMP_ADDRESS_MASK_REPLY),
            "address-mask-reply(18)"
        );
        assert!(icmpv4_type_is_deprecated(ICMP_ADDRESS_MASK_REQUEST));
        assert!(icmpv4_type_is_deprecated(ICMP_ADDRESS_MASK_REPLY));

        // The body summary exposes the typed mask.
        assert_eq!(
            IcmpAddressMask::new()
                .mask(Ipv4Addr::new(255, 255, 255, 0))
                .summary(),
            "IcmpAddressMask(mask=255.255.255.0)"
        );
    }

    // An address mask message whose trailing region is the wrong length (not
    // exactly 4 bytes) is malformed: the typed body parser declines it, the
    // bytes remain a Raw payload, decoding does not panic, and the message still
    // round-trips byte-for-byte.
    #[test]
    fn icmpv4_address_mask_malformed_body_stays_raw() {
        // Short body: only 3 of the 4 mask bytes are present.
        let short = Ipv4::new().src(src()).dst(dst())
            / Icmp::address_mask_request().id(1).seq(1)
            / Raw::from_bytes([0xaa; 3]);
        let compiled = short.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpAddressMask>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[0xaa; 3]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());

        // Oversized body: 4 mask bytes plus trailing unknown data.
        let mut body = vec![0xffu8; 4];
        body.extend_from_slice(b"trailing");
        let long = Ipv4::new().src(src()).dst(dst())
            / Icmp::address_mask_reply().id(2).seq(2)
            / Raw::from_bytes(&body);
        let compiled = long.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpAddressMask>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &body[..]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }
}

#[cfg(test)]
mod icmpv4_router_discovery {
    use super::{
        icmpv4_type_summary, Icmp, IcmpRouterAdvertisementEntry,
        ICMP_CODE_ROUTER_ADVERTISEMENT_NORMAL, ICMP_ROUTER_ADVERTISEMENT,
        ICMP_ROUTER_ADVERTISEMENT_ENTRY_WORDS, ICMP_ROUTER_SOLICITATION,
    };
    use crate::checksum::internet_checksum;
    use crate::packet::Layer;
    use crate::{Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // A router solicitation (RFC 1256, type 10) is the fixed 8-byte header with a
    // 32-bit reserved field that is sent as zero. It carries no body and round-
    // trips through decode with the reserved word intact.
    #[test]
    fn icmpv4_router_discovery_solicitation_compile_decode_roundtrip() {
        let packet = Ipv4::new().src(src()).dst(dst()) / Icmp::router_solicitation();
        let compiled = packet.compile().unwrap();

        // ICMP header begins at byte 20 (20-byte IPv4 header, no options).
        assert_eq!(compiled.as_bytes()[20], ICMP_ROUTER_SOLICITATION);
        assert_eq!(compiled.as_bytes()[21], 0); // code
                                                // The reserved 32-bit field (bytes 24..28) is sent as zero.
        assert_eq!(&compiled.as_bytes()[24..28], &[0, 0, 0, 0]);
        // No body follows the fixed 8-byte ICMP header.
        assert_eq!(compiled.as_bytes().len(), 20 + 8);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.icmp_type_value(), ICMP_ROUTER_SOLICITATION);
        assert_eq!(icmp.rest_of_header_value(), [0, 0, 0, 0]);
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(
            Icmp::router_solicitation().icmp_type_value(),
            ICMP_ROUTER_SOLICITATION
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // A one-entry router advertisement compiles its fixed header (Num Addrs,
    // Addr Entry Size, Lifetime) plus a single router-address/preference entry,
    // and round-trips through decode with the typed entry intact.
    #[test]
    fn icmpv4_router_discovery_advertisement_one_entry_roundtrip() {
        let router = Ipv4Addr::new(192, 0, 2, 1);
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::router_advertisement().lifetime(1800)
            / IcmpRouterAdvertisementEntry::new()
                .router_address(router)
                .preference_level(5);
        let compiled = packet.compile().unwrap();

        assert_eq!(compiled.as_bytes()[20], ICMP_ROUTER_ADVERTISEMENT);
        assert_eq!(compiled.as_bytes()[21], 0); // code
                                                // Rest-of-header: Num Addrs (byte 24), Addr Entry Size (byte 25),
                                                // Lifetime (bytes 26..28).
        assert_eq!(compiled.as_bytes()[24], 1);
        assert_eq!(
            compiled.as_bytes()[25],
            ICMP_ROUTER_ADVERTISEMENT_ENTRY_WORDS
        );
        assert_eq!(&compiled.as_bytes()[26..28], &1800u16.to_be_bytes());
        // Entry: router address (bytes 28..32) then signed preference (32..36).
        assert_eq!(&compiled.as_bytes()[28..32], &router.octets());
        assert_eq!(&compiled.as_bytes()[32..36], &5i32.to_be_bytes());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.num_addrs_value(), Some(1));
        assert_eq!(
            icmp.addr_entry_size_value(),
            Some(ICMP_ROUTER_ADVERTISEMENT_ENTRY_WORDS)
        );
        assert_eq!(icmp.lifetime_value(), Some(1800));

        let entry = decoded.layer::<IcmpRouterAdvertisementEntry>().unwrap();
        assert_eq!(entry.router_address_value(), router);
        assert_eq!(entry.preference_level_value(), 5);
        // No leftover raw bytes when the body length matches Num Addrs entries.
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // A multi-entry advertisement preserves every entry in order, including a
    // negative (signed) preference level, and round-trips through decode.
    #[test]
    fn icmpv4_router_discovery_advertisement_multi_entry_roundtrip() {
        let entries = [
            (Ipv4Addr::new(192, 0, 2, 1), 100i32),
            (Ipv4Addr::new(192, 0, 2, 2), -50i32),
            (Ipv4Addr::new(192, 0, 2, 3), 0i32),
        ];
        let mut packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::router_advertisement()
                .code(ICMP_CODE_ROUTER_ADVERTISEMENT_NORMAL)
                .lifetime(600);
        for (router, preference) in entries {
            packet = packet
                / IcmpRouterAdvertisementEntry::new()
                    .router_address(router)
                    .preference_level(preference);
        }
        let compiled = packet.compile().unwrap();

        // Num Addrs is auto-filled to the entry count.
        assert_eq!(compiled.as_bytes()[24], entries.len() as u8);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let decoded_entries: Vec<&IcmpRouterAdvertisementEntry> =
            decoded.layers::<IcmpRouterAdvertisementEntry>().collect();
        assert_eq!(decoded_entries.len(), entries.len());
        for (decoded_entry, (router, preference)) in decoded_entries.iter().zip(entries) {
            assert_eq!(decoded_entry.router_address_value(), router);
            assert_eq!(decoded_entry.preference_level_value(), preference);
        }
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // Compilation auto-fills Num Addrs from the following entry layers and
    // defaults Addr Entry Size to the standard format when the caller leaves
    // them unset, and the auto-filled ICMP checksum covers the whole message.
    #[test]
    fn icmpv4_router_discovery_advertisement_autofills_counts_and_checksum() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::router_advertisement().lifetime(900)
            / IcmpRouterAdvertisementEntry::new().router_address(Ipv4Addr::new(192, 0, 2, 1))
            / IcmpRouterAdvertisementEntry::new().router_address(Ipv4Addr::new(192, 0, 2, 2));
        let compiled = packet.compile().unwrap();

        // Num Addrs counts the two entries; Addr Entry Size defaults to 2 words.
        assert_eq!(compiled.as_bytes()[24], 2);
        assert_eq!(
            compiled.as_bytes()[25],
            ICMP_ROUTER_ADVERTISEMENT_ENTRY_WORDS
        );

        // The auto-filled checksum covers the header plus both entries.
        let icmp_message = &compiled.as_bytes()[20..];
        let mut zeroed = icmp_message.to_vec();
        zeroed[2] = 0;
        zeroed[3] = 0;
        let expected = internet_checksum(&zeroed);
        assert_ne!(expected, 0);
        assert_eq!(&compiled.as_bytes()[22..24], &expected.to_be_bytes());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert_eq!(
            decoded.layer::<Icmp>().unwrap().checksum_value(),
            Some(expected)
        );
    }

    // Explicit Num Addrs, Addr Entry Size, Lifetime, and checksum overrides are
    // preserved verbatim even when they are deliberately inconsistent with the
    // following entries. A mismatched Num Addrs / non-standard Addr Entry Size
    // means decode cannot defensibly type the entries, so the body stays Raw and
    // the message still round-trips byte-for-byte.
    #[test]
    fn icmpv4_router_discovery_advertisement_explicit_malformed_overrides() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::router_advertisement()
                .num_addrs(7) // deliberately wrong: only one entry follows
                .addr_entry_size(3) // non-standard entry size
                .lifetime(0xbeef)
                .checksum(0xdead)
            / IcmpRouterAdvertisementEntry::new().router_address(Ipv4Addr::new(192, 0, 2, 9));
        let compiled = packet.compile().unwrap();

        // Every pinned field is emitted verbatim.
        assert_eq!(compiled.as_bytes()[24], 7);
        assert_eq!(compiled.as_bytes()[25], 3);
        assert_eq!(&compiled.as_bytes()[26..28], &0xbeefu16.to_be_bytes());
        assert_eq!(&compiled.as_bytes()[22..24], &0xdeadu16.to_be_bytes());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.num_addrs_value(), Some(7));
        assert_eq!(icmp.addr_entry_size_value(), Some(3));
        assert_eq!(icmp.lifetime_value(), Some(0xbeef));
        // The inconsistent header means the body cannot be typed as entries; the
        // bytes survive as Raw and nothing panics.
        assert!(decoded.layer::<IcmpRouterAdvertisementEntry>().is_none());
        assert!(decoded.layer::<Raw>().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // A router advertisement whose body length does not match Num Addrs * entry
    // size is malformed: the entry parser declines it, the bytes remain Raw,
    // decoding does not panic, and the message still round-trips byte-for-byte.
    #[test]
    fn icmpv4_router_discovery_advertisement_length_mismatch_stays_raw() {
        // Standard entry size and Num Addrs of 1, but only 5 trailing bytes.
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::router_advertisement()
                .num_addrs(1)
                .addr_entry_size(ICMP_ROUTER_ADVERTISEMENT_ENTRY_WORDS)
            / Raw::from_bytes([0xaa; 5]);
        let compiled = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpRouterAdvertisementEntry>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[0xaa; 5]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // Summaries identify the router discovery types and the typed entry fields
    // while keeping numeric values visible.
    #[test]
    fn icmpv4_router_discovery_summary_output() {
        assert_eq!(
            icmpv4_type_summary(ICMP_ROUTER_ADVERTISEMENT),
            "router-advertisement(9)"
        );
        assert_eq!(
            icmpv4_type_summary(ICMP_ROUTER_SOLICITATION),
            "router-solicitation(10)"
        );
        assert_eq!(
            Icmp::router_advertisement().code(0).summary(),
            "Icmp(type=router-advertisement(9), code=normal(0), id=-, seq=-)"
        );
        assert_eq!(
            IcmpRouterAdvertisementEntry::new()
                .router_address(Ipv4Addr::new(192, 0, 2, 1))
                .preference_level(-7)
                .summary(),
            "IcmpRouterAdvertisementEntry(router=192.0.2.1, preference=-7)"
        );
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
