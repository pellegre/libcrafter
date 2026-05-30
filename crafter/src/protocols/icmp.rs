//! ICMP, ICMPv6, and ICMP extension implementations.

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

// ICMPv4 type numbers from the IANA ICMP Parameters registry
// (<https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml>).
// Status annotations follow the registry: Deprecated values are marked in their
// doc comments per RFC 6633 (Source Quench) and RFC 6918 (the bulk legacy
// deprecations). Deprecated and reserved values remain constructible and
// decodable; this step only names them and never refuses them.

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

// ICMPv4 code-field registries from the IANA ICMP Parameters registry.

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

/// Internet Control Message Protocol for IPv6.
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

    /// Echo identifier value when meaningful for the current type.
    pub fn identifier_value(&self) -> Option<u16> {
        if is_echo_v6(self.icmp_type_value()) {
            Some(value_or_u16_from_rest(
                &self.identifier,
                &self.rest_of_header,
                0,
            ))
        } else {
            None
        }
    }

    /// Echo sequence number when meaningful for the current type.
    pub fn sequence_number_value(&self) -> Option<u16> {
        if is_echo_v6(self.icmp_type_value()) {
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
            _ => {}
        }

        Ok(rest)
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
        vec![
            ("type", icmpv6_type_summary(self.icmp_type_value())),
            ("code", self.code_value().to_string()),
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

/// RFC 4884 ICMP extension header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpExtension {
    version: Field<u8>,
    reserved: Field<u16>,
    checksum: Field<u16>,
}

impl IcmpExtension {
    /// Create an ICMP extension header.
    pub fn new() -> Self {
        Self {
            version: Field::defaulted(2),
            reserved: Field::defaulted(0),
            checksum: Field::unset(),
        }
    }

    /// Set the extension version.
    pub fn version(mut self, version: u8) -> Self {
        self.version.set_user(version);
        self
    }

    /// Set the 12-bit reserved field.
    pub fn reserved(mut self, reserved: u16) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Set the extension checksum explicitly.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum.set_user(checksum);
        self
    }

    /// Version value.
    pub fn version_value(&self) -> u8 {
        value_or_copy(&self.version, 2)
    }

    /// Reserved field value.
    pub fn reserved_value(&self) -> u16 {
        value_or_copy(&self.reserved, 0)
    }

    /// Stored checksum when explicit or decoded.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    fn validate(&self) -> Result<()> {
        if self.version_value() > 0x0f {
            return Err(CrafterError::invalid_field_value(
                "icmp_extension.version",
                "version must fit in four bits",
            ));
        }
        if self.reserved_value() > 0x0fff {
            return Err(CrafterError::invalid_field_value(
                "icmp_extension.reserved",
                "reserved field must fit in 12 bits",
            ));
        }
        Ok(())
    }
}

impl Default for IcmpExtension {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpExtension {
    fn name(&self) -> &'static str {
        "IcmpExtension"
    }

    fn summary(&self) -> String {
        format!("IcmpExtension(version={})", self.version_value())
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("version", self.version_value().to_string()),
            ("reserved", format!("0x{:03x}", self.reserved_value())),
            (
                "checksum",
                self.checksum_value()
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| "auto".to_string()),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_EXTENSION_HEADER_LEN
    }

    fn encoded_len_with_context(&self, ctx: &LayerContext<'_>) -> usize {
        // The RFC 4884 zero padding emitted before the extension header is part
        // of this layer's on-wire size, so enclosing length fields (the outer
        // IPv4 total length, for one) count it.
        ICMP_EXTENSION_HEADER_LEN + extension_original_datagram_padding(*ctx)
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;

        // RFC 4884: the preceding "original datagram" field is zero padded so
        // the extension structure starts at the offset the length field claims.
        // The padding belongs to the original datagram (it is not covered by the
        // extension checksum), so emit it before the extension header.
        let padding = extension_original_datagram_padding(*ctx);
        out.resize(out.len() + padding, 0);

        let mut header = Vec::with_capacity(ICMP_EXTENSION_HEADER_LEN);
        let version_reserved =
            ((self.version_value() as u16) << 12) | (self.reserved_value() & 0x0fff);
        header.extend_from_slice(&version_reserved.to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes());
        let payload = payload_bytes_after(*ctx)?;
        let checksum = self.checksum.value().copied().unwrap_or_else(|| {
            let mut bytes = Vec::with_capacity(header.len() + payload.len());
            bytes.extend_from_slice(&header);
            bytes.extend_from_slice(&payload);
            internet_checksum(&bytes)
        });
        header[2..4].copy_from_slice(&checksum.to_be_bytes());
        out.extend_from_slice(&header);
        Ok(())
    }

    impl_layer_object!(IcmpExtension);
}

impl_layer_div!(IcmpExtension);

/// RFC 4884 ICMP extension object header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpExtensionObject {
    length: Field<u16>,
    class_num: Field<u8>,
    c_type: Field<u8>,
}

impl IcmpExtensionObject {
    /// Create an extension object header.
    pub fn new() -> Self {
        Self {
            length: Field::unset(),
            class_num: Field::defaulted(0),
            c_type: Field::defaulted(0),
        }
    }

    /// Set the object length explicitly.
    pub fn length(mut self, length: u16) -> Self {
        self.length.set_user(length);
        self
    }

    /// Set the object class number.
    pub fn class_num(mut self, class_num: u8) -> Self {
        self.class_num.set_user(class_num);
        self
    }

    /// Set the object C-Type.
    pub fn c_type(mut self, c_type: u8) -> Self {
        self.c_type.set_user(c_type);
        self
    }

    /// Object length when explicit or decoded.
    pub fn length_value(&self) -> Option<u16> {
        self.length.value().copied()
    }

    /// Object class number.
    pub fn class_num_value(&self) -> u8 {
        value_or_copy(&self.class_num, 0)
    }

    /// Object C-Type.
    pub fn c_type_value(&self) -> u8 {
        value_or_copy(&self.c_type, 0)
    }

    fn effective_length(&self, ctx: LayerContext<'_>) -> Result<u16> {
        if let Some(length) = self.length.value().copied() {
            return Ok(length);
        }

        u16::try_from(ICMP_EXTENSION_OBJECT_LEN + extension_object_payload_len(ctx)).map_err(|_| {
            CrafterError::invalid_field_value(
                "icmp_extension_object.length",
                "extension object length exceeds 65535 bytes",
            )
        })
    }

    fn effective_class_num(&self, next: Option<&dyn Layer>) -> u8 {
        if self.class_num.is_user_set() {
            return self.class_num_value();
        }
        if next
            .map(|layer| layer.as_any().is::<IcmpExtensionMpls>())
            .unwrap_or(false)
        {
            ICMP_EXTENSION_CLASS_MPLS
        } else if next
            .map(|layer| layer.as_any().is::<IcmpExtensionInterfaceInfo>())
            .unwrap_or(false)
        {
            ICMP_EXTENSION_CLASS_INTERFACE_INFO
        } else if next
            .map(|layer| layer.as_any().is::<IcmpExtensionInterfaceId>())
            .unwrap_or(false)
        {
            ICMP_EXTENSION_CLASS_INTERFACE_ID
        } else {
            self.class_num_value()
        }
    }

    fn effective_c_type(&self, next: Option<&dyn Layer>) -> u8 {
        if self.c_type.is_user_set() {
            return self.c_type_value();
        }
        if next
            .map(|layer| layer.as_any().is::<IcmpExtensionMpls>())
            .unwrap_or(false)
        {
            ICMP_EXTENSION_CTYPE_MPLS_INCOMING
        } else if let Some(info) =
            next.and_then(|layer| layer.as_any().downcast_ref::<IcmpExtensionInterfaceInfo>())
        {
            info.c_type_byte()
        } else if let Some(id) =
            next.and_then(|layer| layer.as_any().downcast_ref::<IcmpExtensionInterfaceId>())
        {
            id.c_type()
        } else {
            self.c_type_value()
        }
    }
}

impl Default for IcmpExtensionObject {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpExtensionObject {
    fn name(&self) -> &'static str {
        "IcmpExtensionObject"
    }

    fn summary(&self) -> String {
        format!(
            "IcmpExtensionObject(class={}, ctype={})",
            self.class_num_value(),
            self.c_type_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "length",
                self.length_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("class_num", self.class_num_value().to_string()),
            ("c_type", self.c_type_value().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_EXTENSION_OBJECT_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.effective_length(*ctx)?.to_be_bytes());
        out.push(self.effective_class_num(ctx.next()));
        out.push(self.effective_c_type(ctx.next()));
        Ok(())
    }

    impl_layer_object!(IcmpExtensionObject);
}

impl_layer_div!(IcmpExtensionObject);

/// MPLS label stack entry for ICMP extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpExtensionMpls {
    label: Field<u32>,
    experimental: Field<u8>,
    bottom_of_stack: Field<bool>,
    ttl: Field<u8>,
}

impl IcmpExtensionMpls {
    /// Create an MPLS extension entry.
    pub fn new() -> Self {
        Self {
            label: Field::defaulted(0),
            experimental: Field::defaulted(0),
            bottom_of_stack: Field::unset(),
            ttl: Field::defaulted(0),
        }
    }

    /// Set the MPLS label.
    pub fn label(mut self, label: u32) -> Self {
        self.label.set_user(label);
        self
    }

    /// Set the experimental bits.
    pub fn experimental(mut self, experimental: u8) -> Self {
        self.experimental.set_user(experimental);
        self
    }

    /// Alias for the experimental bits.
    pub fn exp(self, experimental: u8) -> Self {
        self.experimental(experimental)
    }

    /// Set the bottom-of-stack bit explicitly.
    pub fn bottom_of_stack(mut self, bottom_of_stack: bool) -> Self {
        self.bottom_of_stack.set_user(bottom_of_stack);
        self
    }

    /// Set the MPLS TTL.
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl.set_user(ttl);
        self
    }

    /// MPLS label value.
    pub fn label_value(&self) -> u32 {
        value_or_copy(&self.label, 0)
    }

    /// Experimental bits value.
    pub fn experimental_value(&self) -> u8 {
        value_or_copy(&self.experimental, 0)
    }

    /// Stored bottom-of-stack bit when explicit or decoded.
    pub fn bottom_of_stack_value(&self) -> Option<bool> {
        self.bottom_of_stack.value().copied()
    }

    /// MPLS TTL value.
    pub fn ttl_value(&self) -> u8 {
        value_or_copy(&self.ttl, 0)
    }

    fn effective_bottom_of_stack(&self, next: Option<&dyn Layer>) -> bool {
        self.bottom_of_stack.value().copied().unwrap_or_else(|| {
            !next
                .map(|layer| layer.as_any().is::<IcmpExtensionMpls>())
                .unwrap_or(false)
        })
    }

    fn validate(&self) -> Result<()> {
        if self.label_value() > MPLS_MAX_LABEL {
            return Err(CrafterError::invalid_field_value(
                "icmp_extension_mpls.label",
                "MPLS label must fit in 20 bits",
            ));
        }
        if self.experimental_value() > MPLS_MAX_EXP {
            return Err(CrafterError::invalid_field_value(
                "icmp_extension_mpls.experimental",
                "MPLS experimental field must fit in three bits",
            ));
        }
        Ok(())
    }
}

impl Default for IcmpExtensionMpls {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpExtensionMpls {
    fn name(&self) -> &'static str {
        "IcmpExtensionMpls"
    }

    fn summary(&self) -> String {
        format!(
            "IcmpExtensionMpls(label={}, ttl={})",
            self.label_value(),
            self.ttl_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("label", self.label_value().to_string()),
            ("experimental", self.experimental_value().to_string()),
            (
                "bottom_of_stack",
                self.bottom_of_stack_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("ttl", self.ttl_value().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_EXTENSION_MPLS_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;

        let word = (self.label_value() << 12)
            | ((self.experimental_value() as u32) << 9)
            | ((self.effective_bottom_of_stack(ctx.next()) as u32) << 8)
            | self.ttl_value() as u32;
        out.extend_from_slice(&word.to_be_bytes());
        Ok(())
    }

    impl_layer_object!(IcmpExtensionMpls);
}

impl_layer_div!(IcmpExtensionMpls);

/// RFC 5837 IP Address sub-object carried inside an interface information
/// object: a 16-bit Address Family Identifier, a 16-bit reserved field, and the
/// address bytes (4 for IPv4, 16 for IPv6). The address is kept as raw bytes so
/// unknown AFIs and non-canonical reserved values round-trip byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpInterfaceIpAddress {
    afi: Field<u16>,
    reserved: Field<u16>,
    address: Vec<u8>,
}

impl IcmpInterfaceIpAddress {
    /// Build an IPv4 IP Address sub-object.
    pub fn ipv4(address: Ipv4Addr) -> Self {
        Self {
            afi: Field::user(ICMP_INTERFACE_AFI_IPV4),
            reserved: Field::defaulted(0),
            address: address.octets().to_vec(),
        }
    }

    /// Build an IPv6 IP Address sub-object.
    pub fn ipv6(address: core::net::Ipv6Addr) -> Self {
        Self {
            afi: Field::user(ICMP_INTERFACE_AFI_IPV6),
            reserved: Field::defaulted(0),
            address: address.octets().to_vec(),
        }
    }

    /// Build an IP Address sub-object from a raw AFI and address bytes, the
    /// escape hatch for unknown or malformed address families.
    pub fn raw(afi: u16, address: impl Into<Vec<u8>>) -> Self {
        Self {
            afi: Field::user(afi),
            reserved: Field::defaulted(0),
            address: address.into(),
        }
    }

    /// Set the 16-bit reserved field explicitly.
    pub fn reserved(mut self, reserved: u16) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Address Family Identifier value.
    pub fn afi_value(&self) -> u16 {
        value_or_copy(&self.afi, 0)
    }

    /// Reserved field value.
    pub fn reserved_value(&self) -> u16 {
        value_or_copy(&self.reserved, 0)
    }

    /// Raw address bytes.
    pub fn address_bytes(&self) -> &[u8] {
        &self.address
    }

    /// Address as an [`Ipv4Addr`] when the AFI is IPv4 and four bytes follow.
    pub fn ipv4_value(&self) -> Option<Ipv4Addr> {
        if self.afi_value() == ICMP_INTERFACE_AFI_IPV4 && self.address.len() == 4 {
            Some(Ipv4Addr::new(
                self.address[0],
                self.address[1],
                self.address[2],
                self.address[3],
            ))
        } else {
            None
        }
    }

    /// Address as an [`Ipv6Addr`](core::net::Ipv6Addr) when the AFI is IPv6 and
    /// sixteen bytes follow.
    pub fn ipv6_value(&self) -> Option<core::net::Ipv6Addr> {
        if self.afi_value() == ICMP_INTERFACE_AFI_IPV6 && self.address.len() == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&self.address);
            Some(core::net::Ipv6Addr::from(octets))
        } else {
            None
        }
    }

    fn encoded_len(&self) -> usize {
        ICMP_INTERFACE_IP_ADDRESS_PREFIX_LEN + self.address.len()
    }

    fn compile(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.afi_value().to_be_bytes());
        out.extend_from_slice(&self.reserved_value().to_be_bytes());
        out.extend_from_slice(&self.address);
    }
}

/// RFC 5837 ICMP extension object carrying interface information.
///
/// The single object holds an interface role (RFC 5837 figure 1, C-Type bits
/// 0-1), a two-bit reserved field (bits 2-3), and up to four optional
/// sub-objects in their mandatory order: a 32-bit `ifIndex`, an
/// [`IcmpInterfaceIpAddress`], an interface name, and a 32-bit MTU. The C-Type
/// presence bits (4-7) are derived from which sub-objects are present, so the
/// preceding [`IcmpExtensionObject`] auto-fills class 2 and the matching C-Type
/// byte. Unknown or malformed bodies stay raw through the generic object path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpExtensionInterfaceInfo {
    role: Field<u8>,
    reserved: Field<u8>,
    if_index: Option<u32>,
    ip_address: Option<IcmpInterfaceIpAddress>,
    name: Option<Vec<u8>>,
    mtu: Option<u32>,
}

impl IcmpExtensionInterfaceInfo {
    /// Create an interface information object with the incoming-interface role
    /// and no sub-objects.
    pub fn new() -> Self {
        Self {
            role: Field::defaulted(ICMP_INTERFACE_ROLE_INCOMING),
            reserved: Field::defaulted(0),
            if_index: None,
            ip_address: None,
            name: None,
            mtu: None,
        }
    }

    /// Set the two-bit interface role (RFC 5837 C-Type bits 0-1).
    pub fn role(mut self, role: u8) -> Self {
        self.role.set_user(role);
        self
    }

    /// Set the two-bit reserved field (RFC 5837 C-Type bits 2-3).
    pub fn reserved(mut self, reserved: u8) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Include the 32-bit ifIndex sub-object.
    pub fn if_index(mut self, if_index: u32) -> Self {
        self.if_index = Some(if_index);
        self
    }

    /// Include the IP Address sub-object.
    pub fn ip_address(mut self, ip_address: IcmpInterfaceIpAddress) -> Self {
        self.ip_address = Some(ip_address);
        self
    }

    /// Include the Interface Name sub-object from raw name octets (UTF-8 per
    /// RFC 5837, but bytes are preserved verbatim and zero padded on the wire).
    pub fn name_bytes(mut self, name: impl Into<Vec<u8>>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Include the Interface Name sub-object from a string.
    pub fn name(self, name: &str) -> Self {
        self.name_bytes(name.as_bytes().to_vec())
    }

    /// Include the 32-bit MTU sub-object.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Interface role value (C-Type bits 0-1).
    pub fn role_value(&self) -> u8 {
        value_or_copy(&self.role, ICMP_INTERFACE_ROLE_INCOMING)
    }

    /// Reserved field value (C-Type bits 2-3).
    pub fn reserved_value(&self) -> u8 {
        value_or_copy(&self.reserved, 0)
    }

    /// ifIndex sub-object value, if present.
    pub fn if_index_value(&self) -> Option<u32> {
        self.if_index
    }

    /// IP Address sub-object, if present.
    pub fn ip_address_value(&self) -> Option<&IcmpInterfaceIpAddress> {
        self.ip_address.as_ref()
    }

    /// Interface name octets, if present.
    pub fn name_value(&self) -> Option<&[u8]> {
        self.name.as_deref()
    }

    /// MTU sub-object value, if present.
    pub fn mtu_value(&self) -> Option<u32> {
        self.mtu
    }

    /// RFC 5837 C-Type byte: role in bits 0-1, reserved in bits 2-3, and one
    /// presence bit per included sub-object in bits 4-7.
    pub fn c_type_byte(&self) -> u8 {
        let mut byte = ((self.role_value() & 0x03) << 6) | ((self.reserved_value() & 0x03) << 4);
        if self.if_index.is_some() {
            byte |= ICMP_INTERFACE_CTYPE_IFINDEX;
        }
        if self.ip_address.is_some() {
            byte |= ICMP_INTERFACE_CTYPE_IP_ADDRESS;
        }
        if self.name.is_some() {
            byte |= ICMP_INTERFACE_CTYPE_NAME;
        }
        if self.mtu.is_some() {
            byte |= ICMP_INTERFACE_CTYPE_MTU;
        }
        byte
    }

    /// On-wire length of the interface name sub-object (length octet plus name
    /// octets, zero padded to a 4-octet boundary), when a name is present.
    fn name_encoded_len(&self) -> usize {
        self.name
            .as_ref()
            .map(|name| {
                let raw = 1 + name.len();
                raw.div_ceil(4) * 4
            })
            .unwrap_or(0)
    }

    fn validate(&self) -> Result<()> {
        if self.role_value() > 0x03 {
            return Err(CrafterError::invalid_field_value(
                "icmp_interface_info.role",
                "interface role must fit in two bits",
            ));
        }
        if self.reserved_value() > 0x03 {
            return Err(CrafterError::invalid_field_value(
                "icmp_interface_info.reserved",
                "interface reserved field must fit in two bits",
            ));
        }
        if let Some(name) = &self.name {
            if name.len() > ICMP_INTERFACE_NAME_MAX {
                return Err(CrafterError::invalid_field_value(
                    "icmp_interface_info.name",
                    "interface name must not exceed 63 octets",
                ));
            }
        }
        Ok(())
    }
}

impl Default for IcmpExtensionInterfaceInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpExtensionInterfaceInfo {
    fn name(&self) -> &'static str {
        "IcmpExtensionInterfaceInfo"
    }

    fn summary(&self) -> String {
        let mut parts = vec![format!(
            "role={}",
            interface_role_summary(self.role_value())
        )];
        if let Some(if_index) = self.if_index {
            parts.push(format!("ifindex={if_index}"));
        }
        if let Some(ip) = &self.ip_address {
            let rendered = ip
                .ipv4_value()
                .map(|addr| addr.to_string())
                .or_else(|| ip.ipv6_value().map(|addr| addr.to_string()))
                .unwrap_or_else(|| {
                    format!("afi={} {}", ip.afi_value(), hex_bytes(ip.address_bytes()))
                });
            parts.push(format!("ip={rendered}"));
        }
        if let Some(name) = &self.name {
            parts.push(format!("name={}", String::from_utf8_lossy(name)));
        }
        if let Some(mtu) = self.mtu {
            parts.push(format!("mtu={mtu}"));
        }
        format!("IcmpExtensionInterfaceInfo({})", parts.join(", "))
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("role", interface_role_summary(self.role_value())),
            ("reserved", self.reserved_value().to_string()),
            ("c_type", format!("0x{:02x}", self.c_type_byte())),
            (
                "if_index",
                self.if_index
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "ip_address",
                self.ip_address
                    .as_ref()
                    .map(|ip| {
                        ip.ipv4_value()
                            .map(|addr| addr.to_string())
                            .or_else(|| ip.ipv6_value().map(|addr| addr.to_string()))
                            .unwrap_or_else(|| {
                                format!("afi={} {}", ip.afi_value(), hex_bytes(ip.address_bytes()))
                            })
                    })
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "name",
                self.name
                    .as_ref()
                    .map(|name| String::from_utf8_lossy(name).into_owned())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "mtu",
                self.mtu
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        let mut len = 0;
        if self.if_index.is_some() {
            len += ICMP_INTERFACE_IFINDEX_LEN;
        }
        if let Some(ip) = &self.ip_address {
            len += ip.encoded_len();
        }
        len += self.name_encoded_len();
        if self.mtu.is_some() {
            len += ICMP_INTERFACE_MTU_LEN;
        }
        len
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;
        if let Some(if_index) = self.if_index {
            out.extend_from_slice(&if_index.to_be_bytes());
        }
        if let Some(ip) = &self.ip_address {
            ip.compile(out);
        }
        if let Some(name) = &self.name {
            // RFC 5837: a one-octet length (covering itself plus the name) leads
            // the name, which is then zero padded to a 4-octet boundary.
            let padded = self.name_encoded_len();
            out.push((1 + name.len()) as u8);
            out.extend_from_slice(name);
            out.resize(out.len() + (padded - 1 - name.len()), 0);
        }
        if let Some(mtu) = self.mtu {
            out.extend_from_slice(&mtu.to_be_bytes());
        }
        Ok(())
    }

    impl_layer_object!(IcmpExtensionInterfaceInfo);
}

impl_layer_div!(IcmpExtensionInterfaceInfo);

/// RFC 8335 Interface Identification Object body (extension object class 3).
///
/// The object identifies the probed interface in exactly one of three ways,
/// selected by the C-Type of the preceding [`IcmpExtensionObject`]:
///
/// - C-Type 1 (by name): the interface name (RFC 7223) zero padded to a 32-bit
///   boundary.
/// - C-Type 2 (by index): a 32-bit ifIndex.
/// - C-Type 3 (by address): a 16-bit AFI, an 8-bit address length, an 8-bit
///   reserved field, and the address bytes zero padded to a 32-bit boundary.
///
/// The form is kept as a typed body so the object's C-Type auto-fills from which
/// constructor was used, and so decode can surface each form's fields. A `raw`
/// escape hatch carries an explicit C-Type and arbitrary body bytes for crafting
/// objects the typed forms do not cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpExtensionInterfaceId {
    body: InterfaceIdBody,
}

/// The selected RFC 8335 Interface Identification Object form.
#[derive(Debug, Clone, PartialEq, Eq)]
enum InterfaceIdBody {
    /// C-Type 1: interface name, zero padded to a 32-bit boundary on the wire.
    Name(Vec<u8>),
    /// C-Type 2: a 32-bit ifIndex.
    Index(u32),
    /// C-Type 3: AFI, an explicit address length, reserved byte, and address.
    Address {
        afi: u16,
        address_length: u8,
        reserved: u8,
        address: Vec<u8>,
    },
    /// An explicit C-Type plus raw body bytes (escape hatch). The bytes are
    /// emitted verbatim without padding so deliberately malformed objects survive.
    Raw { c_type: u8, bytes: Vec<u8> },
}

impl IcmpExtensionInterfaceId {
    /// Identify the interface by name (RFC 8335 C-Type 1).
    pub fn by_name(name: &str) -> Self {
        Self::by_name_bytes(name.as_bytes().to_vec())
    }

    /// Identify the interface by raw name octets (RFC 8335 C-Type 1). The octets
    /// are zero padded to a 32-bit boundary on the wire.
    pub fn by_name_bytes(name: impl Into<Vec<u8>>) -> Self {
        Self {
            body: InterfaceIdBody::Name(name.into()),
        }
    }

    /// Identify the interface by a 32-bit ifIndex (RFC 8335 C-Type 2).
    pub fn by_index(if_index: u32) -> Self {
        Self {
            body: InterfaceIdBody::Index(if_index),
        }
    }

    /// Identify the interface by IPv4 address (RFC 8335 C-Type 3).
    pub fn by_ipv4(address: Ipv4Addr) -> Self {
        Self::by_address(ICMP_INTERFACE_AFI_IPV4, address.octets())
    }

    /// Identify the interface by IPv6 address (RFC 8335 C-Type 3).
    pub fn by_ipv6(address: core::net::Ipv6Addr) -> Self {
        Self::by_address(ICMP_INTERFACE_AFI_IPV6, address.octets())
    }

    /// Identify the interface by a raw AFI and address bytes (RFC 8335 C-Type 3).
    ///
    /// The address length defaults to the number of address bytes; the address
    /// is zero padded to a 32-bit boundary on the wire.
    pub fn by_address(afi: u16, address: impl Into<Vec<u8>>) -> Self {
        let address = address.into();
        let address_length = address.len() as u8;
        Self {
            body: InterfaceIdBody::Address {
                afi,
                address_length,
                reserved: 0,
                address,
            },
        }
    }

    /// Build an object with an explicit C-Type and raw body bytes, the escape
    /// hatch for crafting objects the typed forms do not cover. The bytes are
    /// emitted verbatim (no padding).
    pub fn raw(c_type: u8, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            body: InterfaceIdBody::Raw {
                c_type,
                bytes: bytes.into(),
            },
        }
    }

    /// Override the C-Type 3 address length field (the count of significant
    /// address bytes) explicitly, the escape hatch for deliberately mismatched
    /// lengths. Has no effect on the other forms.
    pub fn address_length(mut self, address_length: u8) -> Self {
        if let InterfaceIdBody::Address {
            address_length: slot,
            ..
        } = &mut self.body
        {
            *slot = address_length;
        }
        self
    }

    /// Override the C-Type 3 reserved byte explicitly. Has no effect on the other
    /// forms.
    pub fn reserved(mut self, reserved: u8) -> Self {
        if let InterfaceIdBody::Address { reserved: slot, .. } = &mut self.body {
            *slot = reserved;
        }
        self
    }

    /// RFC 8335 C-Type for the selected form.
    pub fn c_type(&self) -> u8 {
        match &self.body {
            InterfaceIdBody::Name(_) => ICMP_INTERFACE_ID_CTYPE_NAME,
            InterfaceIdBody::Index(_) => ICMP_INTERFACE_ID_CTYPE_INDEX,
            InterfaceIdBody::Address { .. } => ICMP_INTERFACE_ID_CTYPE_ADDRESS,
            InterfaceIdBody::Raw { c_type, .. } => *c_type,
        }
    }

    /// Interface name octets (C-Type 1), if this is a name object.
    pub fn name_value(&self) -> Option<&[u8]> {
        match &self.body {
            InterfaceIdBody::Name(name) => Some(name),
            _ => None,
        }
    }

    /// ifIndex (C-Type 2), if this is an index object.
    pub fn index_value(&self) -> Option<u32> {
        match &self.body {
            InterfaceIdBody::Index(index) => Some(*index),
            _ => None,
        }
    }

    /// Address Family Identifier (C-Type 3), if this is an address object.
    pub fn afi_value(&self) -> Option<u16> {
        match &self.body {
            InterfaceIdBody::Address { afi, .. } => Some(*afi),
            _ => None,
        }
    }

    /// Address bytes (C-Type 3), if this is an address object.
    pub fn address_bytes(&self) -> Option<&[u8]> {
        match &self.body {
            InterfaceIdBody::Address { address, .. } => Some(address),
            _ => None,
        }
    }

    /// Address length field (C-Type 3), if this is an address object.
    pub fn address_length_value(&self) -> Option<u8> {
        match &self.body {
            InterfaceIdBody::Address { address_length, .. } => Some(*address_length),
            _ => None,
        }
    }

    /// Address as an [`Ipv4Addr`] when this is an IPv4 address object.
    pub fn ipv4_value(&self) -> Option<Ipv4Addr> {
        match &self.body {
            InterfaceIdBody::Address { afi, address, .. }
                if *afi == ICMP_INTERFACE_AFI_IPV4 && address.len() == 4 =>
            {
                Some(Ipv4Addr::new(
                    address[0], address[1], address[2], address[3],
                ))
            }
            _ => None,
        }
    }

    /// Address as an [`Ipv6Addr`](core::net::Ipv6Addr) when this is an IPv6
    /// address object.
    pub fn ipv6_value(&self) -> Option<core::net::Ipv6Addr> {
        match &self.body {
            InterfaceIdBody::Address { afi, address, .. }
                if *afi == ICMP_INTERFACE_AFI_IPV6 && address.len() == 16 =>
            {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(address);
                Some(core::net::Ipv6Addr::from(octets))
            }
            _ => None,
        }
    }

    /// Raw escape-hatch body bytes, if this object was built with [`Self::raw`].
    pub fn raw_bytes(&self) -> Option<&[u8]> {
        match &self.body {
            InterfaceIdBody::Raw { bytes, .. } => Some(bytes),
            _ => None,
        }
    }
}

impl Layer for IcmpExtensionInterfaceId {
    fn name(&self) -> &'static str {
        "IcmpExtensionInterfaceId"
    }

    fn summary(&self) -> String {
        let detail = match &self.body {
            InterfaceIdBody::Name(name) => {
                format!("name={}", String::from_utf8_lossy(name))
            }
            InterfaceIdBody::Index(index) => format!("ifindex={index}"),
            InterfaceIdBody::Address { afi, address, .. } => {
                if let Some(addr) = self.ipv4_value() {
                    format!("address={addr}")
                } else if let Some(addr) = self.ipv6_value() {
                    format!("address={addr}")
                } else {
                    format!("address=afi={afi} {}", hex_bytes(address))
                }
            }
            InterfaceIdBody::Raw { c_type, bytes } => {
                format!("ctype={c_type} raw={}", hex_bytes(bytes))
            }
        };
        format!("IcmpExtensionInterfaceId({detail})")
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("c_type", self.c_type().to_string()),
            (
                "name",
                self.name_value()
                    .map(|name| String::from_utf8_lossy(name).into_owned())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "index",
                self.index_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "afi",
                self.afi_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "address",
                self.address_bytes()
                    .map(hex_bytes)
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        match &self.body {
            InterfaceIdBody::Name(name) => name.len().div_ceil(4) * 4,
            InterfaceIdBody::Index(_) => ICMP_INTERFACE_ID_INDEX_LEN,
            InterfaceIdBody::Address { address, .. } => {
                ICMP_INTERFACE_ID_ADDRESS_PREFIX_LEN + address.len().div_ceil(4) * 4
            }
            InterfaceIdBody::Raw { bytes, .. } => bytes.len(),
        }
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        match &self.body {
            InterfaceIdBody::Name(name) => {
                let padded = name.len().div_ceil(4) * 4;
                out.extend_from_slice(name);
                out.resize(out.len() + (padded - name.len()), 0);
            }
            InterfaceIdBody::Index(index) => {
                out.extend_from_slice(&index.to_be_bytes());
            }
            InterfaceIdBody::Address {
                afi,
                address_length,
                reserved,
                address,
            } => {
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(*address_length);
                out.push(*reserved);
                let padded = address.len().div_ceil(4) * 4;
                out.extend_from_slice(address);
                out.resize(out.len() + (padded - address.len()), 0);
            }
            InterfaceIdBody::Raw { bytes, .. } => {
                out.extend_from_slice(bytes);
            }
        }
        Ok(())
    }

    impl_layer_object!(IcmpExtensionInterfaceId);
}

impl_layer_div!(IcmpExtensionInterfaceId);

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

/// Decode a single RFC 4950 MPLS label stack entry (4 octets) into a typed
/// [`IcmpExtensionMpls`] layer.
///
/// The 32-bit word packs a 20-bit label, a 3-bit experimental/traffic-class
/// field, a 1-bit bottom-of-stack flag, and an 8-bit TTL. Every field is set as
/// a user value — including the bottom-of-stack bit — so a re-compile reproduces
/// the exact bits even when the decoded stack is non-canonical (for example a
/// set bottom-of-stack bit that is not on the final entry).
fn decode_mpls_entry(chunk: &[u8]) -> IcmpExtensionMpls {
    let word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    let label = word >> 12;
    let experimental = ((word >> 9) & 0x07) as u8;
    let bottom_of_stack = (word >> 8) & 0x01 == 1;
    let ttl = (word & 0xff) as u8;
    IcmpExtensionMpls {
        label: Field::user(label),
        experimental: Field::user(experimental),
        bottom_of_stack: Field::user(bottom_of_stack),
        ttl: Field::user(ttl),
    }
}

/// Decode an RFC 5837 interface information object body into a typed
/// [`IcmpExtensionInterfaceInfo`] layer.
///
/// The C-Type byte drives which sub-objects are present (bits 0-1 role, bits
/// 2-3 reserved, bits 4-7 ifIndex/IP-address/name/MTU). Sub-objects are parsed
/// in their mandatory order and must consume the body exactly, with canonical
/// (zero) name padding, so a re-compile reproduces the bytes. Any short,
/// trailing, or non-canonical body returns `None` so the caller keeps the
/// region as raw bytes and decoding never panics.
fn decode_interface_info(c_type: u8, mut body: &[u8]) -> Option<IcmpExtensionInterfaceInfo> {
    let role = (c_type >> 6) & 0x03;
    let reserved = (c_type >> 4) & 0x03;
    let mut info = IcmpExtensionInterfaceInfo {
        role: Field::user(role),
        reserved: Field::user(reserved),
        if_index: None,
        ip_address: None,
        name: None,
        mtu: None,
    };

    if c_type & ICMP_INTERFACE_CTYPE_IFINDEX != 0 {
        if body.len() < ICMP_INTERFACE_IFINDEX_LEN {
            return None;
        }
        info.if_index = Some(u32::from_be_bytes(copy_array_4(
            &body[..ICMP_INTERFACE_IFINDEX_LEN],
        )));
        body = &body[ICMP_INTERFACE_IFINDEX_LEN..];
    }

    if c_type & ICMP_INTERFACE_CTYPE_IP_ADDRESS != 0 {
        if body.len() < ICMP_INTERFACE_IP_ADDRESS_PREFIX_LEN {
            return None;
        }
        let afi = u16::from_be_bytes([body[0], body[1]]);
        let reserved16 = u16::from_be_bytes([body[2], body[3]]);
        // Only AFIs with a fixed address width can be split unambiguously from
        // any following name/MTU sub-objects; unknown AFIs stay raw.
        let addr_len = match afi {
            ICMP_INTERFACE_AFI_IPV4 => 4,
            ICMP_INTERFACE_AFI_IPV6 => 16,
            _ => return None,
        };
        let total = ICMP_INTERFACE_IP_ADDRESS_PREFIX_LEN + addr_len;
        if body.len() < total {
            return None;
        }
        info.ip_address = Some(IcmpInterfaceIpAddress {
            afi: Field::user(afi),
            reserved: Field::user(reserved16),
            address: body[ICMP_INTERFACE_IP_ADDRESS_PREFIX_LEN..total].to_vec(),
        });
        body = &body[total..];
    }

    if c_type & ICMP_INTERFACE_CTYPE_NAME != 0 {
        if body.is_empty() {
            return None;
        }
        let length = body[0] as usize;
        // The length octet covers itself plus the name; the name is then padded
        // to a 4-octet boundary. Reject lengths that do not fit or exceed the
        // 64-octet ceiling.
        if length < 1 || length > body.len() {
            return None;
        }
        let name_len = length - 1;
        if name_len > ICMP_INTERFACE_NAME_MAX {
            return None;
        }
        let padded = length.div_ceil(4) * 4;
        if padded > body.len() {
            return None;
        }
        // Only canonical zero padding round-trips through compile.
        if body[length..padded].iter().any(|&byte| byte != 0) {
            return None;
        }
        info.name = Some(body[1..length].to_vec());
        body = &body[padded..];
    }

    if c_type & ICMP_INTERFACE_CTYPE_MTU != 0 {
        if body.len() < ICMP_INTERFACE_MTU_LEN {
            return None;
        }
        info.mtu = Some(u32::from_be_bytes(copy_array_4(
            &body[..ICMP_INTERFACE_MTU_LEN],
        )));
        body = &body[ICMP_INTERFACE_MTU_LEN..];
    }

    // Sub-objects must consume the body exactly so the typed layer round-trips.
    if !body.is_empty() {
        return None;
    }

    Some(info)
}

/// Decode an RFC 8335 Interface Identification Object body into a typed
/// [`IcmpExtensionInterfaceId`] layer.
///
/// The object's C-Type selects the form: name (1), index (2), or address (3).
/// Each form must consume the whole body exactly with canonical (zero) padding
/// so a re-compile reproduces the bytes; anything else — an unknown C-Type, a
/// mismatched length, non-canonical padding, or an unknown-width address AFI —
/// returns `None` so the caller keeps the body as raw bytes and decoding never
/// panics.
fn decode_interface_id(c_type: u8, body: &[u8]) -> Option<IcmpExtensionInterfaceId> {
    match c_type {
        ICMP_INTERFACE_ID_CTYPE_NAME => {
            // The name is zero padded to a 32-bit boundary; reject a body whose
            // length is not a whole number of words or whose padding is not zero.
            if body.is_empty() || body.len() % 4 != 0 {
                return None;
            }
            // RFC 7223 names are NUL-padded; the name is the leading non-NUL run,
            // and every trailing byte after the first NUL must be NUL so the
            // padded form round-trips through compile.
            let name_len = body
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(body.len());
            if body[name_len..].iter().any(|&byte| byte != 0) {
                return None;
            }
            // Reject names whose unpadded length would re-pad to a different size
            // (only canonical minimal padding round-trips).
            if name_len.div_ceil(4) * 4 != body.len() {
                return None;
            }
            Some(IcmpExtensionInterfaceId::by_name_bytes(
                body[..name_len].to_vec(),
            ))
        }
        ICMP_INTERFACE_ID_CTYPE_INDEX => {
            if body.len() != ICMP_INTERFACE_ID_INDEX_LEN {
                return None;
            }
            Some(IcmpExtensionInterfaceId::by_index(u32::from_be_bytes(
                copy_array_4(body),
            )))
        }
        ICMP_INTERFACE_ID_CTYPE_ADDRESS => {
            if body.len() < ICMP_INTERFACE_ID_ADDRESS_PREFIX_LEN {
                return None;
            }
            let afi = u16::from_be_bytes([body[0], body[1]]);
            let address_length = body[2];
            let reserved = body[3];
            let address = &body[ICMP_INTERFACE_ID_ADDRESS_PREFIX_LEN..];
            // The significant address length must fit the padded address region
            // and re-pad to exactly the body length so a re-compile reproduces it.
            let significant = address_length as usize;
            if significant > address.len() || significant.div_ceil(4) * 4 != address.len() {
                return None;
            }
            // Only canonical zero padding past the significant address bytes
            // round-trips through compile.
            if address[significant..].iter().any(|&byte| byte != 0) {
                return None;
            }
            Some(
                IcmpExtensionInterfaceId::by_address(afi, address[..significant].to_vec())
                    .reserved(reserved),
            )
        }
        _ => None,
    }
}

/// Append a decoded ICMPv6 packet to an existing packet stack.
pub(crate) fn append_icmpv6_packet(mut packet: Packet, bytes: &[u8]) -> Result<Packet> {
    let (icmpv6, payload) = decode_icmpv6_parts(bytes)?;
    packet = packet.push(icmpv6);
    if !payload.is_empty() {
        packet = packet.push(Raw::from_bytes(payload));
    }
    Ok(packet)
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
    let icmpv6 = Icmpv6 {
        icmp_type: Field::user(icmp_type),
        code: Field::user(bytes[1]),
        checksum: Field::user(read_u16_be(&bytes[2..4])?),
        rest_of_header: Field::user(rest),
        identifier: field_from_echo(icmp_type, &rest, 0, is_echo_v6),
        sequence_number: field_from_echo(icmp_type, &rest, 2, is_echo_v6),
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
    };

    Ok((icmpv6, &bytes[ICMP_HEADER_LEN..]))
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

fn is_echo_v4(icmp_type: u8) -> bool {
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
fn is_query_v4(icmp_type: u8) -> bool {
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

fn is_echo_v6(icmp_type: u8) -> bool {
    matches!(icmp_type, ICMPV6_ECHO_REQUEST | ICMPV6_ECHO_REPLY)
}

/// True for the RFC 8335 extended echo request/reply types, which carry a 16-bit
/// identifier, an 8-bit sequence number, and a flag byte in the rest-of-header.
fn is_extended_echo_v4(icmp_type: u8) -> bool {
    matches!(
        icmp_type,
        ICMP_EXTENDED_ECHO_REQUEST | ICMP_EXTENDED_ECHO_REPLY
    )
}

fn icmpv4_type_allows_extensions(icmp_type: u8) -> bool {
    matches!(
        icmp_type,
        ICMP_DESTINATION_UNREACHABLE | ICMP_TIME_EXCEEDED | ICMP_PARAMETER_PROBLEM
    )
}

/// Human-readable RFC 5837 interface role, keeping the raw numeric value visible
/// for unknown role codes (the field is only two bits, so all values are
/// assigned, but the formatting is kept defensive).
fn interface_role_summary(role: u8) -> String {
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
fn icmpv4_type_is_error(icmp_type: u8) -> bool {
    matches!(
        icmp_type,
        ICMP_DESTINATION_UNREACHABLE
            | ICMP_SOURCE_QUENCH
            | ICMP_REDIRECT
            | ICMP_TIME_EXCEEDED
            | ICMP_PARAMETER_PROBLEM
    )
}

fn icmpv6_type_allows_extensions(icmp_type: u8) -> bool {
    matches!(
        icmp_type,
        ICMPV6_DESTINATION_UNREACHABLE | ICMPV6_TIME_EXCEEDED
    )
}

fn parse_ipv4(input: &str) -> Result<Ipv4Addr> {
    Ipv4Addr::from_str(input).map_err(|_| {
        CrafterError::invalid_field_value("ipv4_address", "expected dotted-quad IPv4 address")
    })
}

fn icmpv4_type_summary(icmp_type: u8) -> String {
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
fn icmpv4_type_name(icmp_type: u8) -> Option<&'static str> {
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
fn icmpv4_type_is_deprecated(icmp_type: u8) -> bool {
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
fn icmpv4_code_name(icmp_type: u8, code: u8) -> Option<&'static str> {
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
fn icmpv4_code_summary(icmp_type: u8, code: u8) -> String {
    match icmpv4_code_name(icmp_type, code) {
        Some(name) => format!("{name}({code})"),
        None => code.to_string(),
    }
}

fn icmpv6_type_summary(icmp_type: u8) -> String {
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
mod icmpv6 {
    use super::{IcmpKind, Icmpv6, ICMPV6_ECHO_REQUEST};
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
mod icmpv4_rfc4884_extensions {
    use super::{
        Icmp, IcmpExtension, IcmpExtensionMpls, IcmpExtensionObject, IcmpQuotedIpv4,
        ICMP_EXTENSION_HEADER_LEN, ICMP_PARAMETER_PROBLEM, ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM,
    };
    use crate::checksum::verify_internet_checksum;
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw, Udp};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // The standard 32-byte quoted datagram (IPv4 + UDP + payload) an agent would
    // attach to an error message.
    fn quoted_udp() -> Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 1))
            .proto(IpProtocol::Udp)
            / Udp::new().sport(40000).dport(53)
            / Raw::from("query")
    }

    // The first byte of the ICMP body after the 20-byte IPv4 header sits at
    // offset 28; the RFC 4884 length field is the ICMP rest-of-header byte 1.
    const ICMP_BODY_START: usize = 28;
    const RFC4884_LENGTH_BYTE: usize = 25;

    // A time-exceeded message that quotes a short datagram and appends an
    // extension structure auto-fills the RFC 4884 length field, measured in
    // 32-bit words of the *padded* original datagram (128 octets minimum here).
    #[test]
    fn icmpv4_rfc4884_extensions_autofills_length_field() {
        let bytes = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(1234).ttl(64))
        .compile()
        .unwrap();

        // 128 octets / 4 = 32 words.
        assert_eq!(bytes.as_bytes()[RFC4884_LENGTH_BYTE], 32);
    }

    // A plain error message with no extension structure leaves the length field
    // zero, so a compliant receiver reads "no extensions present".
    #[test]
    fn icmpv4_rfc4884_extensions_length_is_zero_without_extensions() {
        let bytes = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp()))
        .compile()
        .unwrap();

        assert_eq!(bytes.as_bytes()[RFC4884_LENGTH_BYTE], 0);
    }

    // The original datagram is zero padded up to the RFC 4884 minimum of 128
    // octets before the extension header when the quote is shorter, and a quote
    // longer than the minimum is only padded up to the next 32-bit boundary.
    #[test]
    fn icmpv4_rfc4884_extensions_pads_minimum_original_datagram() {
        // A short quote (well under 128 octets) is padded up to the 128-octet
        // minimum.
        let quote_len = quoted_udp().encoded_len();
        assert!(quote_len < ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM);
        let short = (Ipv4::new().src(src()).dst(dst())
            / Icmp::destination_unreachable()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new())
        .compile()
        .unwrap();
        let ext_start = ICMP_BODY_START + ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM;
        // Everything past the quote and before the extension header is zero
        // padding making up the rest of the 128-octet original datagram.
        assert!(short.as_bytes()[ICMP_BODY_START + quote_len..ext_start]
            .iter()
            .all(|&byte| byte == 0));
        // The extension header (version 2) starts exactly at the padded boundary.
        assert_eq!(short.as_bytes()[ext_start] >> 4, 2);
        assert_eq!(short.as_bytes()[RFC4884_LENGTH_BYTE], 32);

        // A quote longer than 128 octets but not word-aligned (133 bytes) is
        // padded only up to the next 32-bit boundary (136 octets / 4 = 34 words),
        // never back down to the minimum.
        let long_quote = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 1))
            .proto(IpProtocol::Udp)
            / Udp::new().sport(40000).dport(53)
            / Raw::from_bytes(vec![0xab; 105]); // 20 + 8 + 105 = 133 bytes
        let long = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(long_quote)
            / IcmpExtension::new())
        .compile()
        .unwrap();
        assert_eq!(long.as_bytes()[RFC4884_LENGTH_BYTE], 34);
        // The three padding octets that round 133 up to 136 are zero.
        let long_ext_start = ICMP_BODY_START + 136;
        assert!(long.as_bytes()[ICMP_BODY_START + 133..long_ext_start]
            .iter()
            .all(|&byte| byte == 0));
        assert_eq!(long.as_bytes()[long_ext_start] >> 4, 2);
    }

    // The extension header checksum is auto-filled over the whole extension
    // structure (header plus objects), so the structure verifies on the wire.
    #[test]
    fn icmpv4_rfc4884_extensions_autofills_extension_checksum() {
        let bytes = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(99).ttl(10))
        .compile()
        .unwrap();

        let ext_start = ICMP_BODY_START + ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM;
        // The one's-complement sum over the extension structure is zero.
        assert!(verify_internet_checksum(&bytes.as_bytes()[ext_start..]));
        // A non-zero checksum was actually emitted (not left at zero).
        assert_ne!(&bytes.as_bytes()[ext_start + 2..ext_start + 4], &[0, 0]);
    }

    // An explicit extension checksum is honored verbatim, even when it is
    // intentionally wrong, and it survives a decode round-trip.
    #[test]
    fn icmpv4_rfc4884_extensions_explicit_malformed_checksum_is_preserved() {
        let bytes = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new().checksum(0xdead)
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(7).ttl(5))
        .compile()
        .unwrap();

        let ext_start = ICMP_BODY_START + ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM;
        assert_eq!(
            &bytes.as_bytes()[ext_start + 2..ext_start + 4],
            &0xdeadu16.to_be_bytes()
        );

        // A non-zero but wrong checksum is treated as "not a real extension" on
        // decode, so the trailing bytes stay raw rather than being typed.
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpExtension>().is_none());
        assert!(decoded.layer::<Raw>().is_some());
        // The bytes round-trip unchanged regardless.
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }

    // A generic, unrecognized extension object retains its length, class,
    // sub-type, and raw payload across a compile/decode round-trip.
    #[test]
    fn icmpv4_rfc4884_extensions_generic_unknown_object_roundtrip() {
        let payload = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::new().icmp_type(ICMP_PARAMETER_PROBLEM)
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new().class_num(200).c_type(7)
            / Raw::from_bytes(payload);
        let compiled = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let object = decoded.layer::<IcmpExtensionObject>().unwrap();
        // Length covers the 4-byte object header plus the 8-byte payload.
        assert_eq!(object.length_value(), Some(12));
        assert_eq!(object.class_num_value(), 200);
        assert_eq!(object.c_type_value(), 7);
        // The unknown object payload survives as raw bytes.
        let raw = decoded.layer::<Raw>().unwrap();
        assert_eq!(raw.as_bytes(), &payload);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // A complete RFC 4884 packet decodes into typed Icmp, quoted datagram,
    // extension header, and extension object layers.
    #[test]
    fn icmpv4_rfc4884_extensions_decode_splits_typed_layers() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(1234).ttl(100)
            / IcmpExtensionMpls::new().label(2345).ttl(50))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();

        // The ICMP header and quoted datagram are typed.
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.length_value(), Some(32));
        let quoted = decoded.layer::<IcmpQuotedIpv4>().unwrap();
        assert_eq!(
            quoted.quoted_layer::<Ipv4>().unwrap().source(),
            Ipv4Addr::new(192, 0, 2, 1)
        );

        // The extension header and object are typed.
        let extension = decoded.layer::<IcmpExtension>().unwrap();
        assert_eq!(extension.version_value(), 2);
        assert_eq!(extension.checksum_value().map(|_| true), Some(true));
        let object = decoded.layer::<IcmpExtensionObject>().unwrap();
        // Object length covers the 4-byte object header plus the two 4-byte MPLS
        // label stack words.
        assert_eq!(object.length_value(), Some(12));
        assert_eq!(object.class_num_value(), 1);
        assert_eq!(object.c_type_value(), 1);

        // The whole structure round-trips byte-for-byte.
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // When the length field claims an extension structure but the bytes that
    // follow are not a valid one (here a corrupted version nibble), decoding
    // keeps the trailing bytes as a single Raw tail instead of fabricating typed
    // layers or panicking, and the buffer still round-trips unchanged.
    #[test]
    fn icmpv4_rfc4884_extensions_ambiguous_data_stays_raw() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(1).ttl(1))
        .compile()
        .unwrap();

        // Corrupt the extension version nibble (set it to 0xf instead of 2).
        let mut corrupt = compiled.as_bytes().to_vec();
        let ext_start = ICMP_BODY_START + ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM;
        corrupt[ext_start] = 0xf0 | (corrupt[ext_start] & 0x0f);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &corrupt).unwrap();
        // No typed extension layers were produced.
        assert!(decoded.layer::<IcmpExtension>().is_none());
        assert!(decoded.layer::<IcmpExtensionObject>().is_none());
        // The quoted datagram is still typed and the ambiguous tail is raw.
        assert!(decoded.layer::<IcmpQuotedIpv4>().is_some());
        let raw = decoded.layer::<Raw>().unwrap();
        // The raw tail is the padding plus the unparsed extension bytes.
        assert!(raw.as_bytes().len() >= ICMP_EXTENSION_HEADER_LEN);
        // The corrupted buffer round-trips unchanged.
        assert_eq!(decoded.compile().unwrap().as_bytes(), &corrupt[..]);
    }
}

#[cfg(test)]
mod icmpv4_rfc4950_mpls {
    use super::{
        Icmp, IcmpExtension, IcmpExtensionMpls, IcmpExtensionObject, IcmpQuotedIpv4,
        ICMP_EXTENSION_CLASS_MPLS, ICMP_EXTENSION_CTYPE_MPLS_INCOMING,
        ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM,
    };
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw, Udp};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // The standard short quoted datagram (IPv4 + UDP + payload) attached to an
    // error message before the extension structure.
    fn quoted_udp() -> Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 1))
            .proto(IpProtocol::Udp)
            / Udp::new().sport(40000).dport(53)
            / Raw::from("query")
    }

    // The ICMP body begins at offset 28 (20-byte IPv4 header + 8-byte ICMP
    // header). The quote is padded up to the 128-octet RFC 4884 minimum, so the
    // extension header sits at offset 28 + 128 and the first object header four
    // bytes later.
    const EXT_HEADER_START: usize = 28 + ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM;
    const OBJECT_HEADER_START: usize = EXT_HEADER_START + 4;
    const FIRST_ENTRY_START: usize = OBJECT_HEADER_START + 4;

    // A single MPLS label stack entry encodes its label, experimental bits,
    // bottom-of-stack flag, and TTL into one 4-octet word, and decodes back into
    // a typed IcmpExtensionMpls layer.
    #[test]
    fn icmpv4_rfc4950_mpls_single_label_encode_decode() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(0xabcde).exp(5).ttl(64))
        .compile()
        .unwrap();

        // Object header: length 8 (4-byte object header + one 4-byte entry),
        // class 1 (MPLS), C-Type 1 (incoming label stack).
        assert_eq!(
            &compiled.as_bytes()[OBJECT_HEADER_START..OBJECT_HEADER_START + 4],
            &[
                0x00,
                0x08,
                ICMP_EXTENSION_CLASS_MPLS,
                ICMP_EXTENSION_CTYPE_MPLS_INCOMING
            ]
        );
        // The 32-bit entry word packs label (20 bits) | exp (3) | S (1) | TTL.
        let expected = (0xabcdeu32 << 12) | (5u32 << 9) | (1u32 << 8) | 64u32;
        assert_eq!(
            &compiled.as_bytes()[FIRST_ENTRY_START..FIRST_ENTRY_START + 4],
            &expected.to_be_bytes()
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let mpls = decoded.layer::<IcmpExtensionMpls>().unwrap();
        assert_eq!(mpls.label_value(), 0xabcde);
        assert_eq!(mpls.experimental_value(), 5);
        assert_eq!(mpls.ttl_value(), 64);
        // A single entry is the bottom of the stack.
        assert_eq!(mpls.bottom_of_stack_value(), Some(true));
        // The typed object header is also exposed.
        let object = decoded.layer::<IcmpExtensionObject>().unwrap();
        assert_eq!(object.length_value(), Some(8));
        assert_eq!(object.class_num_value(), ICMP_EXTENSION_CLASS_MPLS);
        assert_eq!(object.c_type_value(), ICMP_EXTENSION_CTYPE_MPLS_INCOMING);
    }

    // A multi-label stack encodes each entry as its own 4-octet word, and decode
    // exposes every entry as a separate typed layer in order, preserving each
    // entry's label, experimental bits, and TTL.
    #[test]
    fn icmpv4_rfc4950_mpls_multi_label_encode_decode() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(100).exp(1).ttl(10)
            / IcmpExtensionMpls::new().label(200).exp(2).ttl(20)
            / IcmpExtensionMpls::new().label(300).exp(3).ttl(30))
        .compile()
        .unwrap();

        // Object length covers the 4-byte header plus three 4-byte entries.
        let object = {
            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
            decoded
                .layer::<IcmpExtensionObject>()
                .unwrap()
                .length_value()
        };
        assert_eq!(object, Some(16));

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let entries: Vec<&IcmpExtensionMpls> = decoded.layers::<IcmpExtensionMpls>().collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].label_value(), 100);
        assert_eq!(entries[0].experimental_value(), 1);
        assert_eq!(entries[0].ttl_value(), 10);
        assert_eq!(entries[1].label_value(), 200);
        assert_eq!(entries[2].label_value(), 300);
        // Only the final entry carries the bottom-of-stack bit.
        assert_eq!(entries[0].bottom_of_stack_value(), Some(false));
        assert_eq!(entries[1].bottom_of_stack_value(), Some(false));
        assert_eq!(entries[2].bottom_of_stack_value(), Some(true));
    }

    // With the bottom-of-stack bit left unset, compile auto-fills it: only the
    // final entry in a stack is the bottom of stack.
    #[test]
    fn icmpv4_rfc4950_mpls_bottom_of_stack_autofill() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(1).ttl(1)
            / IcmpExtensionMpls::new().label(2).ttl(2))
        .compile()
        .unwrap();

        // The bottom-of-stack S bit is bit 8 of the 32-bit entry word, which in
        // big-endian layout is the LSB of the entry's third octet (offset +2).
        // First entry: S bit clear (not the bottom of the stack).
        assert_eq!(compiled.as_bytes()[FIRST_ENTRY_START + 2] & 0x01, 0);
        // Second entry (four octets later): S bit set (bottom of the stack).
        assert_eq!(compiled.as_bytes()[FIRST_ENTRY_START + 6] & 0x01, 1);
    }

    // An explicit bottom-of-stack override is honored verbatim, even when it
    // contradicts the auto-fill rule (here a set bit on a non-final entry and a
    // clear bit on the final entry), and survives a decode round-trip.
    #[test]
    fn icmpv4_rfc4950_mpls_explicit_bottom_of_stack_override() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new()
                .label(1)
                .ttl(1)
                .bottom_of_stack(true)
            / IcmpExtensionMpls::new()
                .label(2)
                .ttl(2)
                .bottom_of_stack(false))
        .compile()
        .unwrap();

        // The S bit lives in the LSB of each entry's third octet (offset +2).
        // First entry forced to bottom-of-stack despite a following entry.
        assert_eq!(compiled.as_bytes()[FIRST_ENTRY_START + 2] & 0x01, 1);
        // Final entry forced to not-bottom-of-stack despite being last.
        assert_eq!(compiled.as_bytes()[FIRST_ENTRY_START + 6] & 0x01, 0);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let entries: Vec<&IcmpExtensionMpls> = decoded.layers::<IcmpExtensionMpls>().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].bottom_of_stack_value(), Some(true));
        assert_eq!(entries[1].bottom_of_stack_value(), Some(false));
    }

    // A label that does not fit in 20 bits, and experimental bits that do not fit
    // in 3 bits, are rejected at compile time per the existing invalid-field
    // policy.
    #[test]
    fn icmpv4_rfc4950_mpls_invalid_field_bounds() {
        let too_large_label = Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(0x10_0000).ttl(1);
        assert!(too_large_label.compile().is_err());

        let too_large_exp = Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(1).exp(8).ttl(1);
        assert!(too_large_exp.compile().is_err());
    }

    // A complete MPLS-bearing error message round-trips byte-for-byte through
    // Packet::decode_from_l3 even when the entries carry maximal field values.
    #[test]
    fn icmpv4_rfc4950_mpls_byte_for_byte_roundtrip() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::destination_unreachable()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(0xfffff).exp(7).ttl(255)
            / IcmpExtensionMpls::new().label(0).exp(0).ttl(0))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        // The typed MPLS entries are present.
        assert_eq!(decoded.layers::<IcmpExtensionMpls>().count(), 2);
        // And the whole packet reproduces the original bytes exactly.
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // An MPLS object whose body is not a whole number of 4-octet entries is
    // malformed; decode keeps the body as a single Raw payload (never panicking)
    // and the buffer still round-trips unchanged.
    #[test]
    fn icmpv4_rfc4950_mpls_partial_entry_stays_raw() {
        // Build a valid two-entry MPLS object, then truncate the object so its
        // body holds one full entry plus two stray octets (a partial entry).
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(7).ttl(7)
            / IcmpExtensionMpls::new().label(8).ttl(8))
        .compile()
        .unwrap();

        let mut bytes = compiled.as_bytes().to_vec();
        // Drop the final two octets so the trailing object body is 6 bytes (one
        // 4-octet entry + a 2-octet partial entry), shrinking the object length
        // and the IPv4 total length to keep the buffer self-consistent.
        bytes.truncate(bytes.len() - 2);
        // Object length field (big-endian u16) drops from 12 to 10.
        bytes[OBJECT_HEADER_START] = 0x00;
        bytes[OBJECT_HEADER_START + 1] = 0x0a;
        // IPv4 total length (offset 2..4) drops by two as well.
        let total = u16::from_be_bytes([bytes[2], bytes[3]]) - 2;
        bytes[2..4].copy_from_slice(&total.to_be_bytes());
        // Recompute the IPv4 header checksum over the patched header.
        bytes[10] = 0;
        bytes[11] = 0;
        let mut sum = 0u32;
        for pair in bytes[0..20].chunks(2) {
            sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let csum = !(sum as u16);
        bytes[10..12].copy_from_slice(&csum.to_be_bytes());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes).unwrap();
        // The malformed MPLS body is not typed into entries.
        assert_eq!(decoded.layers::<IcmpExtensionMpls>().count(), 0);
        // It survives as a raw body and the buffer round-trips unchanged.
        assert!(decoded.layer::<Raw>().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), &bytes[..]);
    }
}

#[cfg(test)]
mod icmpv4_rfc5837_interface_info {
    use super::{
        Icmp, IcmpExtension, IcmpExtensionInterfaceInfo, IcmpExtensionObject,
        IcmpInterfaceIpAddress, IcmpQuotedIpv4, ICMP_EXTENSION_CLASS_INTERFACE_INFO,
        ICMP_INTERFACE_CTYPE_IFINDEX, ICMP_INTERFACE_CTYPE_IP_ADDRESS, ICMP_INTERFACE_CTYPE_MTU,
        ICMP_INTERFACE_CTYPE_NAME, ICMP_INTERFACE_ROLE_NEXT_HOP, ICMP_INTERFACE_ROLE_OUTGOING,
        ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM,
    };
    use crate::checksum::verify_internet_checksum;
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw, Udp};
    use core::net::{Ipv4Addr, Ipv6Addr};

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    fn quoted_udp() -> Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 1))
            .proto(IpProtocol::Udp)
            / Udp::new().sport(40000).dport(53)
            / Raw::from("query")
    }

    // The ICMP body begins at offset 28; the quote is padded up to the 128-octet
    // RFC 4884 minimum, so the extension header sits at offset 28 + 128 and the
    // first object header four bytes later.
    const EXT_HEADER_START: usize = 28 + ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM;
    const OBJECT_HEADER_START: usize = EXT_HEADER_START + 4;
    const OBJECT_BODY_START: usize = OBJECT_HEADER_START + 4;

    // A full interface information object carrying every RFC 5837 sub-object
    // (ifIndex, IPv4 address, name, MTU) encodes its C-Type presence bits and
    // decodes back into a typed layer that exposes each field.
    #[test]
    fn icmpv4_rfc5837_interface_info_all_subobjects_encode_decode() {
        let info = IcmpExtensionInterfaceInfo::new()
            .role(ICMP_INTERFACE_ROLE_OUTGOING)
            .if_index(7)
            .ip_address(IcmpInterfaceIpAddress::ipv4(Ipv4Addr::new(192, 0, 2, 99)))
            .name("eth0")
            .mtu(1500);
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / info)
            .compile()
            .unwrap();

        // The object header auto-fills class 2 and a C-Type with role=2 and all
        // four presence bits set.
        let expected_ctype = (ICMP_INTERFACE_ROLE_OUTGOING << 6)
            | ICMP_INTERFACE_CTYPE_IFINDEX
            | ICMP_INTERFACE_CTYPE_IP_ADDRESS
            | ICMP_INTERFACE_CTYPE_NAME
            | ICMP_INTERFACE_CTYPE_MTU;
        assert_eq!(
            compiled.as_bytes()[OBJECT_HEADER_START + 2],
            ICMP_EXTENSION_CLASS_INTERFACE_INFO
        );
        assert_eq!(compiled.as_bytes()[OBJECT_HEADER_START + 3], expected_ctype);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let info = decoded.layer::<IcmpExtensionInterfaceInfo>().unwrap();
        assert_eq!(info.role_value(), ICMP_INTERFACE_ROLE_OUTGOING);
        assert_eq!(info.if_index_value(), Some(7));
        assert_eq!(
            info.ip_address_value().unwrap().ipv4_value(),
            Some(Ipv4Addr::new(192, 0, 2, 99))
        );
        assert_eq!(info.name_value(), Some(&b"eth0"[..]));
        assert_eq!(info.mtu_value(), Some(1500));
        // The whole packet reproduces its bytes exactly.
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // Each sub-object can stand alone; an ifIndex-only object sets just the
    // ifIndex presence bit and round-trips.
    #[test]
    fn icmpv4_rfc5837_interface_info_ifindex_only() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceInfo::new().if_index(0xdead_beef))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let info = decoded.layer::<IcmpExtensionInterfaceInfo>().unwrap();
        assert_eq!(info.if_index_value(), Some(0xdead_beef));
        assert_eq!(info.ip_address_value(), None);
        assert_eq!(info.name_value(), None);
        assert_eq!(info.mtu_value(), None);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // An IPv6 IP Address sub-object carries a 16-byte address and is recognized
    // on decode by its AFI.
    #[test]
    fn icmpv4_rfc5837_interface_info_ipv6_address_subobject() {
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x1234);
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceInfo::new()
                .role(ICMP_INTERFACE_ROLE_NEXT_HOP)
                .ip_address(IcmpInterfaceIpAddress::ipv6(addr)))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let info = decoded.layer::<IcmpExtensionInterfaceInfo>().unwrap();
        assert_eq!(info.role_value(), ICMP_INTERFACE_ROLE_NEXT_HOP);
        assert_eq!(info.ip_address_value().unwrap().ipv6_value(), Some(addr));
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // The interface name sub-object emits a leading length octet covering itself
    // plus the name, then zero pads to a 4-octet boundary; decode strips both.
    #[test]
    fn icmpv4_rfc5837_interface_info_name_padding() {
        // "eth0" is 4 octets; with the length octet the sub-object is 5 octets,
        // padded up to 8.
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceInfo::new().name("eth0"))
        .compile()
        .unwrap();

        // Length octet: 1 (itself) + 4 (name) = 5.
        assert_eq!(compiled.as_bytes()[OBJECT_BODY_START], 5);
        assert_eq!(
            &compiled.as_bytes()[OBJECT_BODY_START + 1..OBJECT_BODY_START + 5],
            b"eth0"
        );
        // Three zero pad octets bring the sub-object to an 8-octet boundary.
        assert_eq!(
            &compiled.as_bytes()[OBJECT_BODY_START + 5..OBJECT_BODY_START + 8],
            &[0, 0, 0]
        );
        // Object length covers the 4-byte header plus the 8-byte name sub-object.
        let object = compiled.as_bytes()[OBJECT_HEADER_START + 1];
        assert_eq!(object, 12);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let info = decoded.layer::<IcmpExtensionInterfaceInfo>().unwrap();
        assert_eq!(info.name_value(), Some(&b"eth0"[..]));
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // The object length field auto-fills to the 4-byte object header plus the
    // sub-object body length when left unset.
    #[test]
    fn icmpv4_rfc5837_interface_info_length_autofill() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceInfo::new().if_index(1).mtu(9000))
        .compile()
        .unwrap();

        // Body: 4-byte ifIndex + 4-byte MTU = 8; object length = 4 + 8 = 12.
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let object = decoded.layer::<IcmpExtensionObject>().unwrap();
        assert_eq!(object.length_value(), Some(12));
        assert_eq!(
            object.class_num_value(),
            ICMP_EXTENSION_CLASS_INTERFACE_INFO
        );
    }

    // An explicit object length override is honored verbatim even when it does
    // not match the auto-computed body length.
    #[test]
    fn icmpv4_rfc5837_interface_info_explicit_length_override() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new().length(99)
            / IcmpExtensionInterfaceInfo::new().if_index(1))
        .compile()
        .unwrap();

        // The big-endian length field carries the override, not the computed 8.
        assert_eq!(
            u16::from_be_bytes([
                compiled.as_bytes()[OBJECT_HEADER_START],
                compiled.as_bytes()[OBJECT_HEADER_START + 1],
            ]),
            99
        );
    }

    // The RFC 4884 extension checksum is computed over the whole extension
    // structure including the interface information object and verifies on
    // decode.
    #[test]
    fn icmpv4_rfc5837_interface_info_extension_checksum() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceInfo::new()
                .if_index(5)
                .name("wlan0")
                .mtu(1280))
        .compile()
        .unwrap();

        // The extension structure (from the version/reserved/checksum header to
        // the end) carries a one's-complement checksum that verifies.
        assert!(verify_internet_checksum(
            &compiled.as_bytes()[EXT_HEADER_START..]
        ));

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        // The decoded extension header preserves the transmitted checksum.
        let extension = decoded.layer::<IcmpExtension>().unwrap();
        assert!(extension.checksum_value().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // An unknown extension object class is not an interface information object;
    // it falls back to the generic IcmpExtensionObject + Raw body and is not
    // mistakenly typed as RFC 5837.
    #[test]
    fn icmpv4_rfc5837_interface_info_unknown_class_stays_raw() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new().class_num(200).c_type(0x0f)
            / Raw::from_bytes([1, 2, 3, 4]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpExtensionInterfaceInfo>().is_none());
        let object = decoded.layer::<IcmpExtensionObject>().unwrap();
        assert_eq!(object.class_num_value(), 200);
        assert!(decoded.layer::<Raw>().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // An interface information object whose body is too short for the sub-objects
    // its C-Type claims cannot be parsed defensibly; decode keeps the body raw
    // and never panics, and the buffer round-trips unchanged.
    #[test]
    fn icmpv4_rfc5837_interface_info_truncated_subobject_stays_raw() {
        // Class 2, C-Type with the MTU presence bit set, but only two body octets
        // (an MTU needs four). The object is otherwise well-formed.
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
                .class_num(ICMP_EXTENSION_CLASS_INTERFACE_INFO)
                .c_type(ICMP_INTERFACE_CTYPE_MTU)
            / Raw::from_bytes([0xaa, 0xbb]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        // The under-length body is not typed as an interface information object.
        assert!(decoded.layer::<IcmpExtensionInterfaceInfo>().is_none());
        assert!(decoded.layer::<Raw>().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // The summary names the interface role and surfaces each present sub-object's
    // value without hiding the raw numbers.
    #[test]
    fn icmpv4_rfc5837_interface_info_summary() {
        let info = IcmpExtensionInterfaceInfo::new()
            .role(ICMP_INTERFACE_ROLE_OUTGOING)
            .if_index(42)
            .ip_address(IcmpInterfaceIpAddress::ipv4(Ipv4Addr::new(192, 0, 2, 1)))
            .name("eth1")
            .mtu(1500);
        let summary = crate::packet::Layer::summary(&info);
        assert!(summary.contains("outgoing"), "summary was {summary}");
        assert!(summary.contains("ifindex=42"), "summary was {summary}");
        assert!(summary.contains("192.0.2.1"), "summary was {summary}");
        assert!(summary.contains("name=eth1"), "summary was {summary}");
        assert!(summary.contains("mtu=1500"), "summary was {summary}");
    }
}

#[cfg(test)]
mod icmpv4_rfc8335_extended_echo {
    use super::{
        Icmp, IcmpExtension, IcmpExtensionInterfaceId, IcmpExtensionObject,
        ICMP_CODE_EXTENDED_ECHO_REPLY_MALFORMED_QUERY,
        ICMP_CODE_EXTENDED_ECHO_REPLY_MULTIPLE_INTERFACES, ICMP_CODE_EXTENDED_ECHO_REPLY_NO_ERROR,
        ICMP_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_INTERFACE,
        ICMP_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_TABLE_ENTRY, ICMP_EXTENDED_ECHO_REPLY,
        ICMP_EXTENDED_ECHO_REQUEST, ICMP_EXTENSION_CLASS_INTERFACE_ID,
        ICMP_INTERFACE_ID_CTYPE_ADDRESS, ICMP_INTERFACE_ID_CTYPE_INDEX,
        ICMP_INTERFACE_ID_CTYPE_NAME,
    };
    use crate::checksum::verify_internet_checksum;
    use crate::{Ipv4, NetworkLayer, Packet, Raw};
    use core::net::{Ipv4Addr, Ipv6Addr};

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // An extended echo request carries its 16-bit identifier, 8-bit sequence
    // number, and flag byte in the fixed header, then an RFC 4884 extension
    // structure with a single Interface Identification Object directly after the
    // header (no quoted datagram, no original-datagram padding). The whole packet
    // round-trips and the typed object surfaces the ifIndex.
    #[test]
    fn icmpv4_rfc8335_extended_echo_request_compile_decode() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::extended_echo_request().id(0x1234).seq(7)
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_index(42))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // Fixed ICMP header at offset 20: type 42, code 0.
        assert_eq!(bytes[20], ICMP_EXTENDED_ECHO_REQUEST);
        assert_eq!(bytes[21], 0);
        // Identifier (bytes 24-25), 8-bit sequence (byte 26), flag byte (byte 27).
        assert_eq!(&bytes[24..26], &0x1234u16.to_be_bytes());
        assert_eq!(bytes[26], 7);
        assert_eq!(bytes[27], 0);
        // The extension header begins immediately after the fixed header (no
        // quote, no padding): version 2.
        assert_eq!(bytes[28] >> 4, 2);
        // The object header auto-fills class 3 and C-Type 2 (by index).
        assert_eq!(bytes[34], ICMP_EXTENSION_CLASS_INTERFACE_ID);
        assert_eq!(bytes[35], ICMP_INTERFACE_ID_CTYPE_INDEX);
        // Object length: 4-byte header + 4-byte ifIndex = 8.
        assert_eq!(u16::from_be_bytes([bytes[32], bytes[33]]), 8);
        // ifIndex value.
        assert_eq!(
            u32::from_be_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]),
            42
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.icmp_type_value(), ICMP_EXTENDED_ECHO_REQUEST);
        assert_eq!(icmp.identifier_value(), Some(0x1234));
        assert_eq!(icmp.sequence_number_value(), Some(7));
        assert_eq!(icmp.extended_l_bit_value(), Some(false));
        assert!(decoded.layer::<IcmpExtension>().is_some());
        let id = decoded.layer::<IcmpExtensionInterfaceId>().unwrap();
        assert_eq!(id.index_value(), Some(42));
        assert_eq!(id.c_type(), ICMP_INTERFACE_ID_CTYPE_INDEX);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // The Interface Identification Object can identify by name (C-Type 1), with
    // the name zero padded to a 32-bit boundary.
    #[test]
    fn icmpv4_rfc8335_extended_echo_request_by_name() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::extended_echo_request().id(1).seq(1)
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_name("eth0"))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        assert_eq!(bytes[35], ICMP_INTERFACE_ID_CTYPE_NAME);
        // "eth0" is 4 octets, already on a 32-bit boundary; object length 4 + 4.
        assert_eq!(u16::from_be_bytes([bytes[32], bytes[33]]), 8);
        assert_eq!(&bytes[36..40], b"eth0");

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let id = decoded.layer::<IcmpExtensionInterfaceId>().unwrap();
        assert_eq!(id.name_value(), Some(&b"eth0"[..]));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // A short name is zero padded to a 32-bit boundary on the wire and the
    // padding is stripped on decode.
    #[test]
    fn icmpv4_rfc8335_extended_echo_request_by_name_padding() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::extended_echo_request()
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_name("e0"))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // "e0" (2 octets) pads to 4; object length 4 + 4 = 8.
        assert_eq!(u16::from_be_bytes([bytes[32], bytes[33]]), 8);
        assert_eq!(&bytes[36..38], b"e0");
        assert_eq!(&bytes[38..40], &[0, 0]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let id = decoded.layer::<IcmpExtensionInterfaceId>().unwrap();
        assert_eq!(id.name_value(), Some(&b"e0"[..]));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // The Interface Identification Object can identify by IPv4 address (C-Type 3):
    // AFI, address length, reserved, then the address padded to a 32-bit boundary.
    #[test]
    fn icmpv4_rfc8335_extended_echo_request_by_ipv4_address() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::extended_echo_request()
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_ipv4(Ipv4Addr::new(192, 0, 2, 99)))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        assert_eq!(bytes[35], ICMP_INTERFACE_ID_CTYPE_ADDRESS);
        // AFI 1 (IPv4), address length 4, reserved 0, then the 4 address octets.
        assert_eq!(u16::from_be_bytes([bytes[36], bytes[37]]), 1);
        assert_eq!(bytes[38], 4);
        assert_eq!(bytes[39], 0);
        assert_eq!(&bytes[40..44], &[192, 0, 2, 99]);
        // Object length: 4-byte header + 4-byte prefix + 4-byte address = 12.
        assert_eq!(u16::from_be_bytes([bytes[32], bytes[33]]), 12);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let id = decoded.layer::<IcmpExtensionInterfaceId>().unwrap();
        assert_eq!(id.ipv4_value(), Some(Ipv4Addr::new(192, 0, 2, 99)));
        assert_eq!(id.address_length_value(), Some(4));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // An IPv6 address object carries a 16-byte address (already 32-bit aligned).
    #[test]
    fn icmpv4_rfc8335_extended_echo_request_by_ipv6_address() {
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x99);
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::extended_echo_request()
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_ipv6(addr))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // AFI 2 (IPv6), address length 16. Object length 4 + 4 + 16 = 24.
        assert_eq!(u16::from_be_bytes([bytes[36], bytes[37]]), 2);
        assert_eq!(bytes[38], 16);
        assert_eq!(u16::from_be_bytes([bytes[32], bytes[33]]), 24);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let id = decoded.layer::<IcmpExtensionInterfaceId>().unwrap();
        assert_eq!(id.ipv6_value(), Some(addr));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // The request L-bit is the rightmost bit of the flag byte and round-trips.
    #[test]
    fn icmpv4_rfc8335_extended_echo_request_l_bit() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::extended_echo_request()
                .id(9)
                .seq(3)
                .extended_l_bit(true)
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_index(1))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // Flag byte (offset 27): only the rightmost (L) bit set.
        assert_eq!(bytes[27], 0x01);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.extended_l_bit_value(), Some(true));
        // Reply-only accessors are not meaningful on a request.
        assert_eq!(icmp.extended_state_value(), None);
        assert_eq!(icmp.extended_active_value(), None);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // Every reply code (0-4) compiles and decodes, keeping its numeric code and a
    // stable summary name; replies carry no body of their own.
    #[test]
    fn icmpv4_rfc8335_extended_echo_reply_all_codes() {
        let codes = [
            (ICMP_CODE_EXTENDED_ECHO_REPLY_NO_ERROR, "no-error"),
            (
                ICMP_CODE_EXTENDED_ECHO_REPLY_MALFORMED_QUERY,
                "malformed-query",
            ),
            (
                ICMP_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_INTERFACE,
                "no-such-interface",
            ),
            (
                ICMP_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_TABLE_ENTRY,
                "no-such-table-entry",
            ),
            (
                ICMP_CODE_EXTENDED_ECHO_REPLY_MULTIPLE_INTERFACES,
                "multiple-interfaces",
            ),
        ];
        for (code, name) in codes {
            let compiled = (Ipv4::new().src(src()).dst(dst())
                / Icmp::extended_echo_reply().id(0xabcd).seq(5).code(code))
            .compile()
            .unwrap();

            let bytes = compiled.as_bytes();
            assert_eq!(bytes[20], ICMP_EXTENDED_ECHO_REPLY);
            assert_eq!(bytes[21], code);

            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
            let icmp = decoded.layer::<Icmp>().unwrap();
            assert_eq!(icmp.code_value(), code);
            assert_eq!(icmp.identifier_value(), Some(0xabcd));
            assert_eq!(icmp.sequence_number_value(), Some(5));
            assert!(
                crate::packet::Layer::summary(icmp).contains(name),
                "summary missing {name}"
            );
            assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
        }
    }

    // The reply flag byte packs State (3 bits), reserved (2 bits), and the A/4/6
    // flags; each typed accessor surfaces its field and the byte round-trips.
    #[test]
    fn icmpv4_rfc8335_extended_echo_reply_flags() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::extended_echo_reply()
                .code(ICMP_CODE_EXTENDED_ECHO_REPLY_NO_ERROR)
                .extended_state(super::ICMP_EXTENDED_ECHO_REPLY_STATE_REACHABLE)
                .extended_active(true)
                .extended_ipv4(true)
                .extended_ipv6(false))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // State 2 in bits 5-7 (0b010 << 5 = 0x40), A bit (0x04), 4 bit (0x02).
        assert_eq!(bytes[27], 0x40 | 0x04 | 0x02);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(
            icmp.extended_state_value(),
            Some(super::ICMP_EXTENDED_ECHO_REPLY_STATE_REACHABLE)
        );
        assert_eq!(icmp.extended_active_value(), Some(true));
        assert_eq!(icmp.extended_ipv4_value(), Some(true));
        assert_eq!(icmp.extended_ipv6_value(), Some(false));
        // The L-bit accessor is request-only and not meaningful on a reply.
        assert_eq!(icmp.extended_l_bit_value(), None);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // A reply with an unexpected trailing payload keeps it as a Raw layer rather
    // than typing it; the buffer round-trips unchanged.
    #[test]
    fn icmpv4_rfc8335_extended_echo_reply_trailing_payload_stays_raw() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::extended_echo_reply().code(ICMP_CODE_EXTENDED_ECHO_REPLY_NO_ERROR)
            / Raw::from_bytes([0xde, 0xad, 0xbe, 0xef]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let raw = decoded.layer::<Raw>().unwrap();
        assert_eq!(raw.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        assert!(decoded.layer::<IcmpExtension>().is_none());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // The default request carries exactly one Interface Identification Object and
    // its object length covers just that object.
    #[test]
    fn icmpv4_rfc8335_extended_echo_exactly_one_object_default() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::extended_echo_request()
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_index(3))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let object_count = decoded
            .iter()
            .filter(|layer| layer.as_any().is::<IcmpExtensionObject>())
            .count();
        assert_eq!(object_count, 1);
        let id_count = decoded
            .iter()
            .filter(|layer| layer.as_any().is::<IcmpExtensionInterfaceId>())
            .count();
        assert_eq!(id_count, 1);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // A deliberately malformed object count (two objects in a single request) is
    // preserved on compile and decode; the crate does not refuse to emit it.
    #[test]
    fn icmpv4_rfc8335_extended_echo_malformed_object_count_preserved() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::extended_echo_request()
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_index(1)
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_index(2))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        // Both Interface Identification Objects survive (RFC 8335 expects exactly
        // one, but malformed multi-object requests must still round-trip).
        let ids: Vec<_> = decoded
            .iter()
            .filter_map(|layer| layer.as_any().downcast_ref::<IcmpExtensionInterfaceId>())
            .map(|id| id.index_value())
            .collect();
        assert_eq!(ids, vec![Some(1), Some(2)]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // An unknown Interface Identification Object C-Type is not typed; it falls
    // back to the generic IcmpExtensionObject + Raw body and round-trips.
    #[test]
    fn icmpv4_rfc8335_extended_echo_unknown_object_falls_back_to_raw() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::extended_echo_request()
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
                .class_num(ICMP_EXTENSION_CLASS_INTERFACE_ID)
                .c_type(0x7f)
            / Raw::from_bytes([1, 2, 3, 4]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpExtensionInterfaceId>().is_none());
        let object = decoded.layer::<IcmpExtensionObject>().unwrap();
        assert_eq!(object.class_num_value(), ICMP_EXTENSION_CLASS_INTERFACE_ID);
        assert_eq!(object.c_type_value(), 0x7f);
        assert!(decoded.layer::<Raw>().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // The RFC 4884 extension checksum covers the whole extension structure and
    // verifies on decode; an extended echo request round-trips byte-for-byte.
    #[test]
    fn icmpv4_rfc8335_extended_echo_checksum_roundtrip() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::extended_echo_request().id(0x55aa).seq(2)
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_name("wlan0"))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // The extension structure starts at offset 28 (right after the 8-byte
        // ICMP header, no quote or padding) and carries a verifying checksum.
        assert!(verify_internet_checksum(&bytes[28..]));
        // The outer ICMP checksum also verifies (covers the ICMP header + body).
        assert!(verify_internet_checksum(&bytes[20..]));

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let extension = decoded.layer::<IcmpExtension>().unwrap();
        assert!(extension.checksum_value().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // An explicit raw flag byte survives compilation untouched, the escape hatch
    // for crafting reserved bits the typed builders do not expose.
    #[test]
    fn icmpv4_rfc8335_extended_echo_explicit_flag_byte_preserved() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmp::extended_echo_request()
                .id(1)
                .seq(1)
                .extended_flags(0xfe)
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_index(1))
        .compile()
        .unwrap();

        // The raw flag byte (including the reserved bits) is emitted verbatim.
        assert_eq!(compiled.as_bytes()[27], 0xfe);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.extended_flags_value(), Some(0xfe));
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }
}

#[cfg(test)]
mod icmpv4_legacy_assigned_types {
    use super::{
        icmpv4_code_summary, icmpv4_type_is_deprecated, icmpv4_type_summary, Icmp,
        ICMP_CODE_PHOTURIS_BAD_SPI, ICMP_CODE_PHOTURIS_NEED_AUTHORIZATION,
        ICMP_DATAGRAM_CONVERSION_ERROR, ICMP_DOMAIN_NAME_REPLY, ICMP_DOMAIN_NAME_REQUEST,
        ICMP_EXPERIMENTAL_253, ICMP_EXPERIMENTAL_254, ICMP_IPV6_I_AM_HERE, ICMP_IPV6_WHERE_ARE_YOU,
        ICMP_MOBILE_HOST_REDIRECT, ICMP_MOBILE_REGISTRATION_REPLY, ICMP_MOBILE_REGISTRATION_REQUEST,
        ICMP_PHOTURIS, ICMP_RESERVED_255, ICMP_SEAMOBY_EXPERIMENTAL, ICMP_SKIP, ICMP_TRACEROUTE,
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
            let decoded =
                Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
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
