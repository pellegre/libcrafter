//! DHCP option types and the option-area codec.

use core::net::Ipv4Addr;
use core::str;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};

use super::constants::{
    DHCP_OPTION_ALL_SUBNETS_LOCAL, DHCP_OPTION_ARP_CACHE_TIMEOUT, DHCP_OPTION_BOOT_FILE_SIZE,
    DHCP_OPTION_BROADCAST_ADDRESS, DHCP_OPTION_CLASSLESS_STATIC_ROUTE,
    DHCP_OPTION_CLIENT_IDENTIFIER, DHCP_OPTION_COOKIE_SERVER, DHCP_OPTION_DEFAULT_IP_TTL,
    DHCP_OPTION_DOMAIN_NAME, DHCP_OPTION_DOMAIN_NAME_SERVER, DHCP_OPTION_DOMAIN_SEARCH,
    DHCP_OPTION_END, DHCP_OPTION_ETHERNET_ENCAPSULATION, DHCP_OPTION_EXTENSIONS_PATH,
    DHCP_OPTION_HOST_NAME, DHCP_OPTION_IMPRESS_SERVER, DHCP_OPTION_INTERFACE_MTU,
    DHCP_OPTION_IP_ADDRESS_LEASE_TIME, DHCP_OPTION_IP_FORWARDING, DHCP_OPTION_LOG_SERVER,
    DHCP_OPTION_LPR_SERVER, DHCP_OPTION_MASK_SUPPLIER, DHCP_OPTION_MAX_DATAGRAM_REASSEMBLY,
    DHCP_OPTION_MAX_MESSAGE_SIZE, DHCP_OPTION_MERIT_DUMP_FILE, DHCP_OPTION_MESSAGE,
    DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_NAME_SERVER, DHCP_OPTION_NETBIOS_DATAGRAM_SERVER,
    DHCP_OPTION_NETBIOS_NAME_SERVER, DHCP_OPTION_NETBIOS_NODE_TYPE, DHCP_OPTION_NETBIOS_SCOPE,
    DHCP_OPTION_NIS_DOMAIN, DHCP_OPTION_NIS_SERVERS, DHCP_OPTION_NON_LOCAL_SOURCE_ROUTING,
    DHCP_OPTION_NTP_SERVERS, DHCP_OPTION_OVERLOAD, DHCP_OPTION_PAD,
    DHCP_OPTION_PARAMETER_REQUEST_LIST, DHCP_OPTION_PATH_MTU_AGING_TIMEOUT,
    DHCP_OPTION_PATH_MTU_PLATEAU_TABLE, DHCP_OPTION_PERFORM_MASK_DISCOVERY,
    DHCP_OPTION_PERFORM_ROUTER_DISCOVERY, DHCP_OPTION_POLICY_FILTER, DHCP_OPTION_REBINDING_TIME,
    DHCP_OPTION_RENEWAL_TIME, DHCP_OPTION_REQUESTED_IP_ADDRESS,
    DHCP_OPTION_RESOURCE_LOCATION_SERVER, DHCP_OPTION_ROOT_PATH, DHCP_OPTION_ROUTER,
    DHCP_OPTION_ROUTER_SOLICITATION_ADDRESS, DHCP_OPTION_SERVER_IDENTIFIER,
    DHCP_OPTION_SIP_SERVERS, DHCP_OPTION_STATIC_ROUTE, DHCP_OPTION_SUBNET_MASK,
    DHCP_OPTION_SWAP_SERVER, DHCP_OPTION_TCP_DEFAULT_TTL, DHCP_OPTION_TCP_KEEPALIVE_GARBAGE,
    DHCP_OPTION_TCP_KEEPALIVE_INTERVAL, DHCP_OPTION_TIME_OFFSET, DHCP_OPTION_TIME_SERVER,
    DHCP_OPTION_TRAILER_ENCAPSULATION, DHCP_OPTION_VENDOR_CLASS_IDENTIFIER,
    DHCP_OPTION_VENDOR_SPECIFIC, DHCP_OPTION_X_WINDOW_DISPLAY_MANAGER,
    DHCP_OPTION_X_WINDOW_FONT_SERVER, DHCP_OVERLOAD_BOTH, DHCP_OVERLOAD_FILE, DHCP_OVERLOAD_SNAME,
};
use super::message::DhcpMessageType;
use super::registry::{option_name, option_status, DhcpOptionStatus};

/// Source area a DHCPv4 option segment was decoded from.
///
/// Source: RFC 2131 section 4.1 (BOOTP `sname`/`file` fields) and option 52
/// "Option Overload" (RFC 2132 section 9.3), which lets the `file` and `sname`
/// fixed fields carry additional options. The normal options area always
/// follows the magic cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhcpOptionArea {
    /// The normal options area following the magic cookie.
    Options,
    /// The overloaded BOOTP `file` (boot file name) field.
    File,
    /// The overloaded BOOTP `sname` (server host name) field.
    Sname,
}

impl DhcpOptionArea {
    /// Stable lowercase label for summaries and diagnostics.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Options => "options",
            Self::File => "file",
            Self::Sname => "sname",
        }
    }
}

/// Typed value of the DHCPv4 "Option Overload" option (option 52).
///
/// Source: RFC 2132 section 9.3. Option 52 is a single octet whose value tells a
/// parser to interpret the BOOTP `file` field, the `sname` field, or both as
/// additional option areas: value `1` overloads `file`, value `2` overloads
/// `sname`, and value `3` overloads both. Any other value is unspecified by the
/// registry, so it is preserved verbatim as [`OptionOverload::Unknown`] rather
/// than silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptionOverload {
    /// Value 1: the `file` field is overloaded with options.
    File,
    /// Value 2: the `sname` field is overloaded with options.
    Sname,
    /// Value 3: both the `file` and `sname` fields are overloaded with options.
    Both,
    /// An unspecified overload value, preserved verbatim.
    Unknown(u8),
}

impl OptionOverload {
    /// Classify a raw overload octet (RFC 2132 section 9.3).
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCP_OVERLOAD_FILE => Self::File,
            DHCP_OVERLOAD_SNAME => Self::Sname,
            DHCP_OVERLOAD_BOTH => Self::Both,
            other => Self::Unknown(other),
        }
    }

    /// Wire octet value for this overload.
    pub const fn code(self) -> u8 {
        match self {
            Self::File => DHCP_OVERLOAD_FILE,
            Self::Sname => DHCP_OVERLOAD_SNAME,
            Self::Both => DHCP_OVERLOAD_BOTH,
            Self::Unknown(code) => code,
        }
    }

    /// True when the `file` field is overloaded with options.
    pub const fn overloads_file(self) -> bool {
        matches!(self, Self::File | Self::Both)
    }

    /// True when the `sname` field is overloaded with options.
    pub const fn overloads_sname(self) -> bool {
        matches!(self, Self::Sname | Self::Both)
    }

    /// True when the given area is overloaded with options.
    pub const fn overloads(self, area: DhcpOptionArea) -> bool {
        match area {
            DhcpOptionArea::Options => true,
            DhcpOptionArea::File => self.overloads_file(),
            DhcpOptionArea::Sname => self.overloads_sname(),
        }
    }
}

/// A classic RFC 2132 static route entry (option 33).
///
/// Source: RFC 2132 section 5.8. Option 33 carries a list of IPv4 address
/// pairs; the first address of each pair is the route destination and the
/// second is the router for that destination. Each entry is exactly eight
/// octets on the wire (two 4-octet addresses), so the option length must be a
/// non-zero multiple of eight. The default route `0.0.0.0` is an illegal
/// destination per the RFC, but the codec preserves caller-supplied values
/// verbatim so intentionally malformed packets can still be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DhcpStaticRoute {
    /// Route destination address.
    pub destination: Ipv4Addr,
    /// Router address used to reach the destination.
    pub router: Ipv4Addr,
}

impl DhcpStaticRoute {
    /// Create a static route from a destination and router address.
    pub const fn new(destination: Ipv4Addr, router: Ipv4Addr) -> Self {
        Self {
            destination,
            router,
        }
    }
}

/// A RFC 3442 classless static route entry (option 121).
///
/// Source: RFC 3442. Each route in option 121 is a destination descriptor
/// followed by a 4-octet router address. The destination descriptor is one
/// octet giving the subnet-mask width (number of one bits, 0-32), followed by
/// only the significant octets of the subnet number: `ceil(width / 8)` octets.
/// Insignificant trailing octets are omitted on the wire, so a `/24` route
/// carries three subnet octets and a `/0` default route carries none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DhcpClasslessRoute {
    /// Subnet-mask width in bits (number of one bits, 0-32).
    pub prefix_length: u8,
    /// Subnet (destination network) number. Only the significant octets, as
    /// determined by `prefix_length`, are placed on the wire.
    pub destination: Ipv4Addr,
    /// Router address used to reach the destination.
    pub router: Ipv4Addr,
}

impl DhcpClasslessRoute {
    /// Create a classless static route from a prefix length, destination
    /// network, and router address.
    pub const fn new(prefix_length: u8, destination: Ipv4Addr, router: Ipv4Addr) -> Self {
        Self {
            prefix_length,
            destination,
            router,
        }
    }

    /// Number of significant subnet-number octets on the wire for this route's
    /// prefix length: `ceil(prefix_length / 8)` (RFC 3442). A prefix length of
    /// zero (the default route) carries no subnet octets.
    pub const fn significant_octets(prefix_length: u8) -> usize {
        (prefix_length as usize).div_ceil(8)
    }
}

/// The encoding selector of the RFC 3361 SIP Servers option (option 120).
///
/// Source: RFC 3361 section 3. The first payload octet after the length is the
/// `enc` byte: `0` selects an RFC 1035 domain-name list, `1` selects an IPv4
/// address list. A server MUST NOT mix the two encodings. Any other `enc`
/// value is preserved verbatim as [`SipServers::Unknown`] so the raw bytes are
/// never lost.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SipServers {
    /// `enc = 0`: an RFC 1035 label-encoded list of SIP server domain names.
    DomainNames(Vec<String>),
    /// `enc = 1`: a list of SIP server IPv4 addresses.
    Addresses(Vec<Ipv4Addr>),
    /// An unspecified `enc` value with its raw payload (excluding `enc`).
    Unknown {
        /// The raw `enc` selector octet.
        encoding: u8,
        /// The remaining payload bytes after the `enc` octet.
        data: Vec<u8>,
    },
}

/// A DHCPv4 option codepoint with source-backed registry awareness.
///
/// Source: IANA "BOOTP Vendor Extensions and DHCP Options" registry (updated
/// 2026-02-02). Every wire codepoint maps to a `DhcpOptionCode`; the variant
/// distinguishes assigned codes from ambiguous, private-use, removed, and
/// unassigned ranges so unknown payloads can always be preserved as raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhcpOptionCode {
    /// Pad option (code 0), a single octet with no length or payload.
    Pad,
    /// End option (code 255), a single octet marking the end of options.
    End,
    /// A registered codepoint assigned to a single option by an RFC.
    Assigned(u8),
    /// A registered codepoint with multiple historical or vendor meanings.
    Ambiguous(u8),
    /// A codepoint in the private-use range (224-254).
    PrivateUse(u8),
    /// A codepoint removed or left unassigned by the registry.
    RemovedOrUnassigned(u8),
}

impl DhcpOptionCode {
    /// Classify a wire codepoint using the source-backed registry.
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCP_OPTION_PAD => Self::Pad,
            DHCP_OPTION_END => Self::End,
            _ => match option_status(code) {
                DhcpOptionStatus::Assigned => Self::Assigned(code),
                DhcpOptionStatus::Ambiguous => Self::Ambiguous(code),
                DhcpOptionStatus::PrivateUse => Self::PrivateUse(code),
                DhcpOptionStatus::RemovedOrUnassigned | DhcpOptionStatus::Unknown => {
                    Self::RemovedOrUnassigned(code)
                }
            },
        }
    }

    /// Wire codepoint value.
    pub const fn code(self) -> u8 {
        match self {
            Self::Pad => DHCP_OPTION_PAD,
            Self::End => DHCP_OPTION_END,
            Self::Assigned(code)
            | Self::Ambiguous(code)
            | Self::PrivateUse(code)
            | Self::RemovedOrUnassigned(code) => code,
        }
    }

    /// Registered short name when the registry assigns one.
    pub fn name(self) -> Option<&'static str> {
        option_name(self.code())
    }

    /// True when the codepoint is a single-octet option (pad or end).
    pub const fn is_single_octet(self) -> bool {
        matches!(self, Self::Pad | Self::End)
    }
}

impl From<u8> for DhcpOptionCode {
    fn from(code: u8) -> Self {
        Self::from_code(code)
    }
}

impl From<DhcpOptionCode> for u8 {
    fn from(code: DhcpOptionCode) -> Self {
        code.code()
    }
}

/// A reusable DHCPv4 option wire-format value family.
///
/// Source: RFC 2132 option formats and the IANA registry length column. This
/// is the logical decoded view of an option payload. Families that the codec
/// does not yet decode into a richer structure are preserved verbatim as
/// [`DhcpOptionValue::Opaque`] so no bytes are lost.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DhcpOptionValue {
    /// No payload (length zero), used by flag-style options.
    Empty,
    /// A single unsigned byte.
    U8(u8),
    /// A 16-bit big-endian unsigned integer.
    U16(u16),
    /// A 32-bit big-endian unsigned integer.
    U32(u32),
    /// A 32-bit big-endian signed integer (for example option 2, time offset).
    I32(i32),
    /// A boolean flag carried in a single octet (`0` or `1`). Out-of-range
    /// values are preserved through the raw bytes rather than coerced.
    Bool(bool),
    /// A single IPv4 address.
    Ipv4(Ipv4Addr),
    /// A list of IPv4 addresses.
    Ipv4List(Vec<Ipv4Addr>),
    /// A list of IPv4 address pairs (for example option 21 policy filters and
    /// option 33 static routes), each pair being two 4-octet addresses.
    Ipv4Pairs(Vec<(Ipv4Addr, Ipv4Addr)>),
    /// A list of 16-bit big-endian unsigned integers (for example option 25,
    /// the path MTU plateau table).
    U16List(Vec<u16>),
    /// Text-like bytes. Not guaranteed to be UTF-8; raw bytes are preserved.
    Text(Vec<u8>),
    /// A DHCP message type (option 53).
    MessageType(DhcpMessageType),
    /// An option overload value (option 52).
    OptionOverload(OptionOverload),
    /// A parameter request list (option 55): a sequence of option codes.
    ParameterRequestList(Vec<u8>),
    /// A list of RFC 2132 static routes (option 33), each a destination and
    /// router IPv4 address pair.
    StaticRoutes(Vec<DhcpStaticRoute>),
    /// A list of RFC 3442 classless static routes (option 121).
    ClasslessRoutes(Vec<DhcpClasslessRoute>),
    /// An RFC 3397 / RFC 1035 domain-search list (option 119), decoded to its
    /// logical fully-qualified domain names.
    DomainSearch(Vec<String>),
    /// An RFC 3361 SIP Servers value (option 120): a domain-name list, an IPv4
    /// address list, or an unspecified encoding preserved verbatim.
    SipServers(SipServers),
    /// Opaque bytes preserved verbatim for options without a richer decode yet.
    Opaque(Vec<u8>),
}

impl DhcpOptionValue {
    /// View the value as raw payload bytes when it is byte-like.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Text(bytes) | Self::ParameterRequestList(bytes) | Self::Opaque(bytes) => {
                Some(bytes)
            }
            _ => None,
        }
    }

    /// Lossy UTF-8 view for text-like values, preserving the raw bytes.
    pub fn as_text_lossy(&self) -> Option<String> {
        match self {
            Self::Text(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
            _ => None,
        }
    }

    /// Encode this logical value to its option payload bytes (without the
    /// option code or length byte). The byte layout follows the RFC 2132
    /// option formats: integers are big-endian, booleans are a single `0`/`1`
    /// octet, and address pairs concatenate two 4-octet addresses each.
    pub fn encode_payload(&self) -> Vec<u8> {
        match self {
            Self::Empty => Vec::new(),
            Self::U8(value) => vec![*value],
            Self::U16(value) => value.to_be_bytes().to_vec(),
            Self::U32(value) => value.to_be_bytes().to_vec(),
            Self::I32(value) => value.to_be_bytes().to_vec(),
            Self::Bool(value) => vec![u8::from(*value)],
            Self::Ipv4(address) => address.octets().to_vec(),
            Self::Ipv4List(addresses) => encode_ipv4_list(addresses),
            Self::Ipv4Pairs(pairs) => {
                let mut bytes = Vec::with_capacity(pairs.len() * 8);
                for (first, second) in pairs {
                    bytes.extend_from_slice(&first.octets());
                    bytes.extend_from_slice(&second.octets());
                }
                bytes
            }
            Self::U16List(values) => {
                let mut bytes = Vec::with_capacity(values.len() * 2);
                for value in values {
                    bytes.extend_from_slice(&value.to_be_bytes());
                }
                bytes
            }
            Self::MessageType(message_type) => vec![message_type.code()],
            Self::OptionOverload(overload) => vec![overload.code()],
            Self::StaticRoutes(routes) => encode_static_routes(routes),
            Self::ClasslessRoutes(routes) => encode_classless_routes(routes),
            Self::DomainSearch(names) => encode_domain_name_list(names),
            Self::SipServers(servers) => encode_sip_servers(servers),
            Self::Text(bytes) | Self::ParameterRequestList(bytes) | Self::Opaque(bytes) => {
                bytes.clone()
            }
        }
    }
}

/// Wire-format family of a registered DHCPv4 option.
///
/// Source: RFC 2132 option formats and the IANA registry length column. This
/// names the reusable byte layout each base option uses so a single typed codec
/// can serve every option that shares a shape, instead of one bespoke decoder
/// per code. Options whose contents are only opaque bytes, vendor data, or text
/// keep the corresponding raw-preserving format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhcpOptionFormat {
    /// A single IPv4 address (4 octets).
    Ipv4,
    /// One or more IPv4 addresses (length a non-zero multiple of 4).
    Ipv4List,
    /// One or more IPv4 address pairs (length a non-zero multiple of 8), used by
    /// the policy filter and static route options.
    Ipv4Pairs,
    /// A single octet interpreted as a boolean flag (`0`/`1`).
    Bool,
    /// A single unsigned octet.
    U8,
    /// A 16-bit big-endian unsigned integer (2 octets).
    U16,
    /// One or more 16-bit big-endian unsigned integers (length a non-zero
    /// multiple of 2), used by the path MTU plateau table.
    U16List,
    /// A 32-bit big-endian signed integer (4 octets).
    I32,
    /// A 32-bit big-endian unsigned integer (4 octets).
    U32,
    /// NVT ASCII / text-like bytes; not guaranteed UTF-8, raw bytes preserved.
    Text,
    /// A list of option codes (parameter request list, option 55).
    ParameterRequestList,
    /// The DHCP message type single octet (option 53).
    MessageType,
    /// The option overload single octet (option 52).
    OptionOverload,
    /// RFC 2132 static routes (option 33): destination/router IPv4 pairs.
    StaticRoutes,
    /// RFC 3442 classless static routes (option 121).
    ClasslessRoutes,
    /// RFC 3397 domain-search list (option 119): RFC 1035 label encoding.
    DomainSearch,
    /// RFC 3361 SIP servers (option 120): enc byte plus domain or address list.
    SipServers,
    /// Opaque bytes preserved verbatim (vendor-specific, client/vendor id).
    Opaque,
}

/// A registered DHCPv4 option with a source-backed wire format.
///
/// Source: RFC 2132 and the IANA "BOOTP Vendor Extensions and DHCP Options"
/// registry (updated 2026-02-02). Each kind maps to its wire codepoint and its
/// [`DhcpOptionFormat`], giving callers a source-backed, format-aware view of
/// the option without forcing a bespoke decoder per code. This covers the RFC
/// 2132 base options (codes 1-61) plus later route, domain, and
/// service-discovery options whose wire formats are specified by their own RFC
/// (for example option 119 domain search, option 120 SIP servers, and option
/// 121 classless static routes). Codepoints outside this set are still
/// preserved as raw segments and classified by the option-code registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum DhcpOptionKind {
    SubnetMask,
    TimeOffset,
    Router,
    TimeServer,
    NameServer,
    DomainNameServer,
    LogServer,
    CookieServer,
    LprServer,
    ImpressServer,
    ResourceLocationServer,
    HostName,
    BootFileSize,
    MeritDumpFile,
    DomainName,
    SwapServer,
    RootPath,
    ExtensionsPath,
    IpForwarding,
    NonLocalSourceRouting,
    PolicyFilter,
    MaxDatagramReassembly,
    DefaultIpTtl,
    PathMtuAgingTimeout,
    PathMtuPlateauTable,
    InterfaceMtu,
    AllSubnetsLocal,
    BroadcastAddress,
    PerformMaskDiscovery,
    MaskSupplier,
    PerformRouterDiscovery,
    RouterSolicitationAddress,
    StaticRoute,
    TrailerEncapsulation,
    ArpCacheTimeout,
    EthernetEncapsulation,
    TcpDefaultTtl,
    TcpKeepaliveInterval,
    TcpKeepaliveGarbage,
    NisDomain,
    NisServers,
    NtpServers,
    VendorSpecificInformation,
    NetbiosNameServer,
    NetbiosDatagramServer,
    NetbiosNodeType,
    NetbiosScope,
    XWindowFontServer,
    XWindowDisplayManager,
    RequestedIpAddress,
    IpAddressLeaseTime,
    OptionOverload,
    DhcpMessageType,
    ServerIdentifier,
    ParameterRequestList,
    DhcpMessage,
    MaximumDhcpMessageSize,
    RenewalTime,
    RebindingTime,
    VendorClassIdentifier,
    ClientIdentifier,
    DomainSearch,
    SipServers,
    ClasslessStaticRoute,
}

impl DhcpOptionKind {
    /// Registered option kind for a wire codepoint, when one has a typed format.
    pub const fn from_code(code: u8) -> Option<Self> {
        let kind = match code {
            DHCP_OPTION_SUBNET_MASK => Self::SubnetMask,
            DHCP_OPTION_TIME_OFFSET => Self::TimeOffset,
            DHCP_OPTION_ROUTER => Self::Router,
            DHCP_OPTION_TIME_SERVER => Self::TimeServer,
            DHCP_OPTION_NAME_SERVER => Self::NameServer,
            DHCP_OPTION_DOMAIN_NAME_SERVER => Self::DomainNameServer,
            DHCP_OPTION_LOG_SERVER => Self::LogServer,
            DHCP_OPTION_COOKIE_SERVER => Self::CookieServer,
            DHCP_OPTION_LPR_SERVER => Self::LprServer,
            DHCP_OPTION_IMPRESS_SERVER => Self::ImpressServer,
            DHCP_OPTION_RESOURCE_LOCATION_SERVER => Self::ResourceLocationServer,
            DHCP_OPTION_HOST_NAME => Self::HostName,
            DHCP_OPTION_BOOT_FILE_SIZE => Self::BootFileSize,
            DHCP_OPTION_MERIT_DUMP_FILE => Self::MeritDumpFile,
            DHCP_OPTION_DOMAIN_NAME => Self::DomainName,
            DHCP_OPTION_SWAP_SERVER => Self::SwapServer,
            DHCP_OPTION_ROOT_PATH => Self::RootPath,
            DHCP_OPTION_EXTENSIONS_PATH => Self::ExtensionsPath,
            DHCP_OPTION_IP_FORWARDING => Self::IpForwarding,
            DHCP_OPTION_NON_LOCAL_SOURCE_ROUTING => Self::NonLocalSourceRouting,
            DHCP_OPTION_POLICY_FILTER => Self::PolicyFilter,
            DHCP_OPTION_MAX_DATAGRAM_REASSEMBLY => Self::MaxDatagramReassembly,
            DHCP_OPTION_DEFAULT_IP_TTL => Self::DefaultIpTtl,
            DHCP_OPTION_PATH_MTU_AGING_TIMEOUT => Self::PathMtuAgingTimeout,
            DHCP_OPTION_PATH_MTU_PLATEAU_TABLE => Self::PathMtuPlateauTable,
            DHCP_OPTION_INTERFACE_MTU => Self::InterfaceMtu,
            DHCP_OPTION_ALL_SUBNETS_LOCAL => Self::AllSubnetsLocal,
            DHCP_OPTION_BROADCAST_ADDRESS => Self::BroadcastAddress,
            DHCP_OPTION_PERFORM_MASK_DISCOVERY => Self::PerformMaskDiscovery,
            DHCP_OPTION_MASK_SUPPLIER => Self::MaskSupplier,
            DHCP_OPTION_PERFORM_ROUTER_DISCOVERY => Self::PerformRouterDiscovery,
            DHCP_OPTION_ROUTER_SOLICITATION_ADDRESS => Self::RouterSolicitationAddress,
            DHCP_OPTION_STATIC_ROUTE => Self::StaticRoute,
            DHCP_OPTION_TRAILER_ENCAPSULATION => Self::TrailerEncapsulation,
            DHCP_OPTION_ARP_CACHE_TIMEOUT => Self::ArpCacheTimeout,
            DHCP_OPTION_ETHERNET_ENCAPSULATION => Self::EthernetEncapsulation,
            DHCP_OPTION_TCP_DEFAULT_TTL => Self::TcpDefaultTtl,
            DHCP_OPTION_TCP_KEEPALIVE_INTERVAL => Self::TcpKeepaliveInterval,
            DHCP_OPTION_TCP_KEEPALIVE_GARBAGE => Self::TcpKeepaliveGarbage,
            DHCP_OPTION_NIS_DOMAIN => Self::NisDomain,
            DHCP_OPTION_NIS_SERVERS => Self::NisServers,
            DHCP_OPTION_NTP_SERVERS => Self::NtpServers,
            DHCP_OPTION_VENDOR_SPECIFIC => Self::VendorSpecificInformation,
            DHCP_OPTION_NETBIOS_NAME_SERVER => Self::NetbiosNameServer,
            DHCP_OPTION_NETBIOS_DATAGRAM_SERVER => Self::NetbiosDatagramServer,
            DHCP_OPTION_NETBIOS_NODE_TYPE => Self::NetbiosNodeType,
            DHCP_OPTION_NETBIOS_SCOPE => Self::NetbiosScope,
            DHCP_OPTION_X_WINDOW_FONT_SERVER => Self::XWindowFontServer,
            DHCP_OPTION_X_WINDOW_DISPLAY_MANAGER => Self::XWindowDisplayManager,
            DHCP_OPTION_REQUESTED_IP_ADDRESS => Self::RequestedIpAddress,
            DHCP_OPTION_IP_ADDRESS_LEASE_TIME => Self::IpAddressLeaseTime,
            DHCP_OPTION_OVERLOAD => Self::OptionOverload,
            DHCP_OPTION_MESSAGE_TYPE => Self::DhcpMessageType,
            DHCP_OPTION_SERVER_IDENTIFIER => Self::ServerIdentifier,
            DHCP_OPTION_PARAMETER_REQUEST_LIST => Self::ParameterRequestList,
            DHCP_OPTION_MESSAGE => Self::DhcpMessage,
            DHCP_OPTION_MAX_MESSAGE_SIZE => Self::MaximumDhcpMessageSize,
            DHCP_OPTION_RENEWAL_TIME => Self::RenewalTime,
            DHCP_OPTION_REBINDING_TIME => Self::RebindingTime,
            DHCP_OPTION_VENDOR_CLASS_IDENTIFIER => Self::VendorClassIdentifier,
            DHCP_OPTION_CLIENT_IDENTIFIER => Self::ClientIdentifier,
            DHCP_OPTION_DOMAIN_SEARCH => Self::DomainSearch,
            DHCP_OPTION_SIP_SERVERS => Self::SipServers,
            DHCP_OPTION_CLASSLESS_STATIC_ROUTE => Self::ClasslessStaticRoute,
            _ => return None,
        };
        Some(kind)
    }

    /// Wire codepoint for this option.
    pub const fn code(self) -> u8 {
        match self {
            Self::SubnetMask => DHCP_OPTION_SUBNET_MASK,
            Self::TimeOffset => DHCP_OPTION_TIME_OFFSET,
            Self::Router => DHCP_OPTION_ROUTER,
            Self::TimeServer => DHCP_OPTION_TIME_SERVER,
            Self::NameServer => DHCP_OPTION_NAME_SERVER,
            Self::DomainNameServer => DHCP_OPTION_DOMAIN_NAME_SERVER,
            Self::LogServer => DHCP_OPTION_LOG_SERVER,
            Self::CookieServer => DHCP_OPTION_COOKIE_SERVER,
            Self::LprServer => DHCP_OPTION_LPR_SERVER,
            Self::ImpressServer => DHCP_OPTION_IMPRESS_SERVER,
            Self::ResourceLocationServer => DHCP_OPTION_RESOURCE_LOCATION_SERVER,
            Self::HostName => DHCP_OPTION_HOST_NAME,
            Self::BootFileSize => DHCP_OPTION_BOOT_FILE_SIZE,
            Self::MeritDumpFile => DHCP_OPTION_MERIT_DUMP_FILE,
            Self::DomainName => DHCP_OPTION_DOMAIN_NAME,
            Self::SwapServer => DHCP_OPTION_SWAP_SERVER,
            Self::RootPath => DHCP_OPTION_ROOT_PATH,
            Self::ExtensionsPath => DHCP_OPTION_EXTENSIONS_PATH,
            Self::IpForwarding => DHCP_OPTION_IP_FORWARDING,
            Self::NonLocalSourceRouting => DHCP_OPTION_NON_LOCAL_SOURCE_ROUTING,
            Self::PolicyFilter => DHCP_OPTION_POLICY_FILTER,
            Self::MaxDatagramReassembly => DHCP_OPTION_MAX_DATAGRAM_REASSEMBLY,
            Self::DefaultIpTtl => DHCP_OPTION_DEFAULT_IP_TTL,
            Self::PathMtuAgingTimeout => DHCP_OPTION_PATH_MTU_AGING_TIMEOUT,
            Self::PathMtuPlateauTable => DHCP_OPTION_PATH_MTU_PLATEAU_TABLE,
            Self::InterfaceMtu => DHCP_OPTION_INTERFACE_MTU,
            Self::AllSubnetsLocal => DHCP_OPTION_ALL_SUBNETS_LOCAL,
            Self::BroadcastAddress => DHCP_OPTION_BROADCAST_ADDRESS,
            Self::PerformMaskDiscovery => DHCP_OPTION_PERFORM_MASK_DISCOVERY,
            Self::MaskSupplier => DHCP_OPTION_MASK_SUPPLIER,
            Self::PerformRouterDiscovery => DHCP_OPTION_PERFORM_ROUTER_DISCOVERY,
            Self::RouterSolicitationAddress => DHCP_OPTION_ROUTER_SOLICITATION_ADDRESS,
            Self::StaticRoute => DHCP_OPTION_STATIC_ROUTE,
            Self::TrailerEncapsulation => DHCP_OPTION_TRAILER_ENCAPSULATION,
            Self::ArpCacheTimeout => DHCP_OPTION_ARP_CACHE_TIMEOUT,
            Self::EthernetEncapsulation => DHCP_OPTION_ETHERNET_ENCAPSULATION,
            Self::TcpDefaultTtl => DHCP_OPTION_TCP_DEFAULT_TTL,
            Self::TcpKeepaliveInterval => DHCP_OPTION_TCP_KEEPALIVE_INTERVAL,
            Self::TcpKeepaliveGarbage => DHCP_OPTION_TCP_KEEPALIVE_GARBAGE,
            Self::NisDomain => DHCP_OPTION_NIS_DOMAIN,
            Self::NisServers => DHCP_OPTION_NIS_SERVERS,
            Self::NtpServers => DHCP_OPTION_NTP_SERVERS,
            Self::VendorSpecificInformation => DHCP_OPTION_VENDOR_SPECIFIC,
            Self::NetbiosNameServer => DHCP_OPTION_NETBIOS_NAME_SERVER,
            Self::NetbiosDatagramServer => DHCP_OPTION_NETBIOS_DATAGRAM_SERVER,
            Self::NetbiosNodeType => DHCP_OPTION_NETBIOS_NODE_TYPE,
            Self::NetbiosScope => DHCP_OPTION_NETBIOS_SCOPE,
            Self::XWindowFontServer => DHCP_OPTION_X_WINDOW_FONT_SERVER,
            Self::XWindowDisplayManager => DHCP_OPTION_X_WINDOW_DISPLAY_MANAGER,
            Self::RequestedIpAddress => DHCP_OPTION_REQUESTED_IP_ADDRESS,
            Self::IpAddressLeaseTime => DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
            Self::OptionOverload => DHCP_OPTION_OVERLOAD,
            Self::DhcpMessageType => DHCP_OPTION_MESSAGE_TYPE,
            Self::ServerIdentifier => DHCP_OPTION_SERVER_IDENTIFIER,
            Self::ParameterRequestList => DHCP_OPTION_PARAMETER_REQUEST_LIST,
            Self::DhcpMessage => DHCP_OPTION_MESSAGE,
            Self::MaximumDhcpMessageSize => DHCP_OPTION_MAX_MESSAGE_SIZE,
            Self::RenewalTime => DHCP_OPTION_RENEWAL_TIME,
            Self::RebindingTime => DHCP_OPTION_REBINDING_TIME,
            Self::VendorClassIdentifier => DHCP_OPTION_VENDOR_CLASS_IDENTIFIER,
            Self::ClientIdentifier => DHCP_OPTION_CLIENT_IDENTIFIER,
            Self::DomainSearch => DHCP_OPTION_DOMAIN_SEARCH,
            Self::SipServers => DHCP_OPTION_SIP_SERVERS,
            Self::ClasslessStaticRoute => DHCP_OPTION_CLASSLESS_STATIC_ROUTE,
        }
    }

    /// Wire-format family for this option (RFC 2132 option formats).
    pub const fn format(self) -> DhcpOptionFormat {
        use DhcpOptionFormat as F;
        match self {
            // Single IPv4 address.
            Self::SubnetMask
            | Self::SwapServer
            | Self::BroadcastAddress
            | Self::RouterSolicitationAddress
            | Self::RequestedIpAddress
            | Self::ServerIdentifier => F::Ipv4,
            // IPv4 address lists.
            Self::Router
            | Self::TimeServer
            | Self::NameServer
            | Self::DomainNameServer
            | Self::LogServer
            | Self::CookieServer
            | Self::LprServer
            | Self::ImpressServer
            | Self::ResourceLocationServer
            | Self::NisServers
            | Self::NtpServers
            | Self::NetbiosNameServer
            | Self::NetbiosDatagramServer
            | Self::XWindowFontServer
            | Self::XWindowDisplayManager => F::Ipv4List,
            // IPv4 address pairs.
            Self::PolicyFilter => F::Ipv4Pairs,
            // Static routes are destination/router IPv4 pairs, surfaced as typed
            // route structs (RFC 2132 section 5.8).
            Self::StaticRoute => F::StaticRoutes,
            // Classless static routes (RFC 3442).
            Self::ClasslessStaticRoute => F::ClasslessRoutes,
            // Domain-search list (RFC 3397).
            Self::DomainSearch => F::DomainSearch,
            // SIP servers (RFC 3361).
            Self::SipServers => F::SipServers,
            // Boolean flag byte.
            Self::IpForwarding
            | Self::NonLocalSourceRouting
            | Self::AllSubnetsLocal
            | Self::PerformMaskDiscovery
            | Self::MaskSupplier
            | Self::PerformRouterDiscovery
            | Self::TrailerEncapsulation
            | Self::EthernetEncapsulation
            | Self::TcpKeepaliveGarbage => F::Bool,
            // Single octet unsigned.
            Self::DefaultIpTtl | Self::TcpDefaultTtl | Self::NetbiosNodeType => F::U8,
            // 16-bit unsigned.
            Self::BootFileSize
            | Self::MaxDatagramReassembly
            | Self::InterfaceMtu
            | Self::MaximumDhcpMessageSize => F::U16,
            // 16-bit unsigned list.
            Self::PathMtuPlateauTable => F::U16List,
            // 32-bit signed.
            Self::TimeOffset => F::I32,
            // 32-bit unsigned.
            Self::PathMtuAgingTimeout
            | Self::ArpCacheTimeout
            | Self::TcpKeepaliveInterval
            | Self::IpAddressLeaseTime
            | Self::RenewalTime
            | Self::RebindingTime => F::U32,
            // NVT ASCII / text-like.
            Self::HostName
            | Self::MeritDumpFile
            | Self::DomainName
            | Self::RootPath
            | Self::ExtensionsPath
            | Self::NisDomain
            | Self::NetbiosScope
            | Self::DhcpMessage => F::Text,
            // Special single-octet codecs and lists.
            Self::ParameterRequestList => F::ParameterRequestList,
            Self::DhcpMessageType => F::MessageType,
            Self::OptionOverload => F::OptionOverload,
            // Opaque/vendor data preserved verbatim.
            Self::VendorSpecificInformation
            | Self::VendorClassIdentifier
            | Self::ClientIdentifier => F::Opaque,
        }
    }
}

/// Decode an option payload into its logical [`DhcpOptionValue`] using the
/// source-backed format table, when the code is a registered RFC 2132 base
/// option. Returns `Ok(None)` for codes outside that set so callers fall back
/// to preserving raw bytes. Length and format violations surface as structured
/// [`CrafterError`] values rather than panics.
pub fn typed_option_value(code: u8, data: &[u8]) -> Result<Option<DhcpOptionValue>> {
    let Some(kind) = DhcpOptionKind::from_code(code) else {
        return Ok(None);
    };
    let field = "dhcp.option.value";
    let value = match kind.format() {
        DhcpOptionFormat::Ipv4 => DhcpOptionValue::Ipv4(decode_ipv4_option(field, data)?),
        DhcpOptionFormat::Ipv4List => DhcpOptionValue::Ipv4List(decode_ipv4_list(field, data)?),
        DhcpOptionFormat::Ipv4Pairs => DhcpOptionValue::Ipv4Pairs(decode_ipv4_pairs(field, data)?),
        DhcpOptionFormat::Bool => DhcpOptionValue::Bool(decode_bool_option(field, data)?),
        DhcpOptionFormat::U8 => {
            validate_fixed_len(field, data.len(), 1)?;
            DhcpOptionValue::U8(data[0])
        }
        DhcpOptionFormat::U16 => DhcpOptionValue::U16(decode_u16_option(field, data)?),
        DhcpOptionFormat::U16List => DhcpOptionValue::U16List(decode_u16_list(field, data)?),
        DhcpOptionFormat::I32 => {
            validate_fixed_len(field, data.len(), 4)?;
            DhcpOptionValue::I32(i32::from_be_bytes([data[0], data[1], data[2], data[3]]))
        }
        DhcpOptionFormat::U32 => DhcpOptionValue::U32(decode_u32_option(field, data)?),
        DhcpOptionFormat::Text => DhcpOptionValue::Text(data.to_vec()),
        DhcpOptionFormat::ParameterRequestList => {
            DhcpOptionValue::ParameterRequestList(data.to_vec())
        }
        DhcpOptionFormat::MessageType => {
            validate_fixed_len(field, data.len(), 1)?;
            DhcpOptionValue::MessageType(DhcpMessageType::from_code(data[0]))
        }
        DhcpOptionFormat::OptionOverload => {
            validate_fixed_len(field, data.len(), 1)?;
            DhcpOptionValue::OptionOverload(OptionOverload::from_code(data[0]))
        }
        DhcpOptionFormat::StaticRoutes => {
            DhcpOptionValue::StaticRoutes(decode_static_routes(data)?)
        }
        DhcpOptionFormat::ClasslessRoutes => {
            DhcpOptionValue::ClasslessRoutes(decode_classless_routes(data)?)
        }
        DhcpOptionFormat::DomainSearch => DhcpOptionValue::DomainSearch(decode_domain_name_list(
            "dhcp.option.domain_search",
            data,
        )?),
        DhcpOptionFormat::SipServers => DhcpOptionValue::SipServers(decode_sip_servers(data)?),
        DhcpOptionFormat::Opaque => {
            if data.is_empty() {
                DhcpOptionValue::Empty
            } else {
                DhcpOptionValue::Opaque(data.to_vec())
            }
        }
    };
    Ok(Some(value))
}

/// A raw decoded DHCPv4 option segment with full inspection metadata.
///
/// A segment is one on-the-wire option instance before any RFC 3396 logical
/// concatenation. It records the source area, codepoint, declared length byte,
/// data bytes, and the byte offset within its area so callers can inspect or
/// re-encode the exact wire bytes even for unknown or malformed options.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhcpOptionSegment {
    /// Source area this segment was decoded from.
    pub area: DhcpOptionArea,
    /// Option codepoint with registry classification.
    pub code: DhcpOptionCode,
    /// Declared length byte. `None` for the single-octet pad/end options.
    pub declared_len: Option<u8>,
    /// Byte offset of the option code within its source area.
    pub offset: usize,
    /// Option payload bytes (after code and length), empty for pad/end.
    pub data: Vec<u8>,
}

impl DhcpOptionSegment {
    /// Wire codepoint of this segment.
    pub const fn code_value(&self) -> u8 {
        self.code.code()
    }

    /// True when this segment is a pad or end single-octet option.
    pub const fn is_single_octet(&self) -> bool {
        self.code.is_single_octet()
    }
}

/// Scan a DHCPv4 option area into raw segments with inspection metadata.
///
/// This is the low-level segment scanner described by the plan: it understands
/// pad and end single-octet options and surfaces declared lengths, offsets, and
/// data bytes without applying option overload or RFC 3396 concatenation. It is
/// purely structural and does not enforce option-stream policy such as
/// requiring an end marker; the logical decoder layered on top owns that. The
/// scanner records every option instance in declaration order, including pad
/// and end markers and any bytes that follow an end marker, so callers can
/// inspect and re-encode the exact wire bytes even for malformed streams.
/// Truncated code/length/data are reported as structured [`CrafterError`]
/// values rather than panics.
pub fn scan_dhcp_option_segments(
    area: DhcpOptionArea,
    bytes: &[u8],
) -> Result<Vec<DhcpOptionSegment>> {
    let mut segments = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        let code = bytes[offset];
        let code_offset = offset;
        offset += 1;

        match code {
            DHCP_OPTION_PAD => segments.push(DhcpOptionSegment {
                area,
                code: DhcpOptionCode::Pad,
                declared_len: None,
                offset: code_offset,
                data: Vec::new(),
            }),
            DHCP_OPTION_END => segments.push(DhcpOptionSegment {
                area,
                code: DhcpOptionCode::End,
                declared_len: None,
                offset: code_offset,
                data: Vec::new(),
            }),
            _ => {
                if offset >= bytes.len() {
                    return Err(CrafterError::buffer_too_short(
                        "dhcp option length",
                        offset + 1,
                        bytes.len(),
                    ));
                }
                let len = bytes[offset] as usize;
                offset += 1;
                let end = offset + len;
                if end > bytes.len() {
                    return Err(CrafterError::buffer_too_short(
                        "dhcp option data",
                        end,
                        bytes.len(),
                    ));
                }
                segments.push(DhcpOptionSegment {
                    area,
                    code: DhcpOptionCode::from_code(code),
                    declared_len: Some(len as u8),
                    offset: code_offset,
                    data: bytes[offset..end].to_vec(),
                });
                offset = end;
            }
        }
    }

    Ok(segments)
}

/// Parsed or constructible DHCP option.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DhcpOption {
    /// Padding byte.
    Pad,
    /// End marker.
    End,
    /// DHCP message type.
    MessageType(DhcpMessageType),
    /// Option overload (option 52): which fixed fields carry options.
    OptionOverload(OptionOverload),
    /// Subnet mask.
    SubnetMask(Ipv4Addr),
    /// Router list.
    Router(Vec<Ipv4Addr>),
    /// DNS server list.
    DomainNameServer(Vec<Ipv4Addr>),
    /// Host name.
    HostName(String),
    /// Domain name.
    DomainName(String),
    /// Broadcast address.
    BroadcastAddress(Ipv4Addr),
    /// Requested IP address.
    RequestedIpAddress(Ipv4Addr),
    /// Lease time in seconds.
    IpAddressLeaseTime(u32),
    /// Server identifier.
    ServerIdentifier(Ipv4Addr),
    /// Parameter request list.
    ParameterRequestList(Vec<u8>),
    /// Renewal time in seconds.
    RenewalTime(u32),
    /// Rebinding time in seconds.
    RebindingTime(u32),
    /// Client identifier bytes.
    ClientIdentifier(Vec<u8>),
    /// Unknown or caller-defined DHCP option.
    Generic {
        /// Raw DHCP option code.
        code: u8,
        /// Option payload bytes after code and length.
        data: Vec<u8>,
    },
}

impl DhcpOption {
    /// Create a DHCP message type option.
    pub const fn message_type(message_type: DhcpMessageType) -> Self {
        Self::MessageType(message_type)
    }

    /// Create an option overload option (option 52).
    pub const fn option_overload(overload: OptionOverload) -> Self {
        Self::OptionOverload(overload)
    }

    /// Create a subnet mask option.
    pub const fn subnet_mask(mask: Ipv4Addr) -> Self {
        Self::SubnetMask(mask)
    }

    /// Create a router list option.
    pub fn router(routers: impl Into<Vec<Ipv4Addr>>) -> Self {
        Self::Router(routers.into())
    }

    /// Create a DNS server list option.
    pub fn domain_name_server(servers: impl Into<Vec<Ipv4Addr>>) -> Self {
        Self::DomainNameServer(servers.into())
    }

    /// Create a host name option.
    pub fn host_name(host_name: impl Into<String>) -> Self {
        Self::HostName(host_name.into())
    }

    /// Create a domain name option.
    pub fn domain_name(domain_name: impl Into<String>) -> Self {
        Self::DomainName(domain_name.into())
    }

    /// Create a requested IP address option.
    pub const fn requested_ip_address(address: Ipv4Addr) -> Self {
        Self::RequestedIpAddress(address)
    }

    /// Create a lease time option.
    pub const fn lease_time(seconds: u32) -> Self {
        Self::IpAddressLeaseTime(seconds)
    }

    /// Create a server identifier option.
    pub const fn server_identifier(address: Ipv4Addr) -> Self {
        Self::ServerIdentifier(address)
    }

    /// Create a parameter request list option.
    pub fn parameter_request_list(requests: impl Into<Vec<u8>>) -> Self {
        Self::ParameterRequestList(requests.into())
    }

    /// Create a client identifier option.
    pub fn client_identifier(identifier: impl Into<Vec<u8>>) -> Self {
        Self::ClientIdentifier(identifier.into())
    }

    /// Create a caller-defined option.
    pub fn generic(code: u8, data: impl Into<Vec<u8>>) -> Self {
        Self::Generic {
            code,
            data: data.into(),
        }
    }

    /// Create a registered RFC 2132 base option from a typed value.
    ///
    /// The value is serialized to its RFC 2132 wire layout (big-endian integers,
    /// single-octet booleans, concatenated address pairs) and carried under the
    /// option's codepoint. The result re-decodes through [`DhcpOption::kind`] and
    /// [`DhcpOption::typed_value`], and round-trips byte-for-byte through the
    /// codec. Constructing a value family that does not match the option's
    /// registered format still encodes the bytes the caller supplied, leaving
    /// intentional malformation to the explicit malformed surface.
    pub fn typed(kind: DhcpOptionKind, value: DhcpOptionValue) -> Self {
        Self::Generic {
            code: kind.code(),
            data: value.encode_payload(),
        }
    }

    /// Raw DHCP option code.
    pub const fn code(&self) -> u8 {
        match self {
            Self::Pad => DHCP_OPTION_PAD,
            Self::End => DHCP_OPTION_END,
            Self::MessageType(_) => DHCP_OPTION_MESSAGE_TYPE,
            Self::OptionOverload(_) => DHCP_OPTION_OVERLOAD,
            Self::SubnetMask(_) => DHCP_OPTION_SUBNET_MASK,
            Self::Router(_) => DHCP_OPTION_ROUTER,
            Self::DomainNameServer(_) => DHCP_OPTION_DOMAIN_NAME_SERVER,
            Self::HostName(_) => DHCP_OPTION_HOST_NAME,
            Self::DomainName(_) => DHCP_OPTION_DOMAIN_NAME,
            Self::BroadcastAddress(_) => DHCP_OPTION_BROADCAST_ADDRESS,
            Self::RequestedIpAddress(_) => DHCP_OPTION_REQUESTED_IP_ADDRESS,
            Self::IpAddressLeaseTime(_) => DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
            Self::ServerIdentifier(_) => DHCP_OPTION_SERVER_IDENTIFIER,
            Self::ParameterRequestList(_) => DHCP_OPTION_PARAMETER_REQUEST_LIST,
            Self::RenewalTime(_) => DHCP_OPTION_RENEWAL_TIME,
            Self::RebindingTime(_) => DHCP_OPTION_REBINDING_TIME,
            Self::ClientIdentifier(_) => DHCP_OPTION_CLIENT_IDENTIFIER,
            Self::Generic { code, .. } => *code,
        }
    }

    /// Registry-classified codepoint for this option.
    pub fn option_code(&self) -> DhcpOptionCode {
        DhcpOptionCode::from_code(self.code())
    }

    /// Source-backed registry name for this option, when assigned.
    pub fn registry_name(&self) -> Option<&'static str> {
        option_name(self.code())
    }

    /// Logical wire-format value family for this option.
    ///
    /// Maps the typed enum onto the reusable [`DhcpOptionValue`] families so
    /// callers can reason about option payloads uniformly. Pad and end have no
    /// value family and return `None`.
    pub fn logical_value(&self) -> Option<DhcpOptionValue> {
        let value = match self {
            Self::Pad | Self::End => return None,
            Self::MessageType(message_type) => DhcpOptionValue::MessageType(*message_type),
            Self::OptionOverload(overload) => DhcpOptionValue::OptionOverload(*overload),
            Self::SubnetMask(address)
            | Self::BroadcastAddress(address)
            | Self::RequestedIpAddress(address)
            | Self::ServerIdentifier(address) => DhcpOptionValue::Ipv4(*address),
            Self::Router(addresses) | Self::DomainNameServer(addresses) => {
                DhcpOptionValue::Ipv4List(addresses.clone())
            }
            Self::HostName(text) | Self::DomainName(text) => {
                DhcpOptionValue::Text(text.as_bytes().to_vec())
            }
            Self::IpAddressLeaseTime(seconds)
            | Self::RenewalTime(seconds)
            | Self::RebindingTime(seconds) => DhcpOptionValue::U32(*seconds),
            Self::ParameterRequestList(requests) => {
                DhcpOptionValue::ParameterRequestList(requests.clone())
            }
            Self::ClientIdentifier(data) | Self::Generic { data, .. } => {
                if data.is_empty() {
                    DhcpOptionValue::Empty
                } else {
                    DhcpOptionValue::Opaque(data.clone())
                }
            }
        };
        Some(value)
    }

    /// Registered RFC 2132 base option kind for this option, when its codepoint
    /// is one (codes 1-61).
    pub fn kind(&self) -> Option<DhcpOptionKind> {
        DhcpOptionKind::from_code(self.code())
    }

    /// Format-aware decode of this option's logical payload, driven by the
    /// source-backed RFC 2132 format table.
    ///
    /// Unlike [`DhcpOption::logical_value`], which mirrors the legacy typed enum
    /// shape, this reinterprets the reassembled payload bytes through the wire
    /// format registered for the option code. For example option 2 (time
    /// offset) decodes to [`DhcpOptionValue::I32`], boolean flag options decode
    /// to [`DhcpOptionValue::Bool`], and the path MTU plateau table decodes to
    /// [`DhcpOptionValue::U16List`]. Codes outside the RFC 2132 base set return
    /// `Ok(None)`, and length or format violations surface as structured
    /// errors. Pad and end options have no payload and return `Ok(None)`.
    pub fn typed_value(&self) -> Result<Option<DhcpOptionValue>> {
        if matches!(self, Self::Pad | Self::End) {
            return Ok(None);
        }
        typed_option_value(self.code(), &self.payload_bytes()?)
    }

    /// Encoded option length in bytes.
    ///
    /// Accounts for RFC 3396 splitting: a logical payload longer than 255 bytes
    /// is emitted as several same-code segments, each carrying its own code and
    /// length byte, so the encoded length includes per-segment overhead.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Pad | Self::End => 1,
            Self::MessageType(_) | Self::OptionOverload(_) => 3,
            Self::SubnetMask(_)
            | Self::BroadcastAddress(_)
            | Self::RequestedIpAddress(_)
            | Self::ServerIdentifier(_) => 6,
            Self::Router(addresses) | Self::DomainNameServer(addresses) => {
                split_option_encoded_len(addresses.len() * 4)
            }
            Self::HostName(name) | Self::DomainName(name) => split_option_encoded_len(name.len()),
            Self::IpAddressLeaseTime(_) | Self::RenewalTime(_) | Self::RebindingTime(_) => 6,
            Self::ParameterRequestList(requests)
            | Self::ClientIdentifier(requests)
            | Self::Generic { data: requests, .. } => split_option_encoded_len(requests.len()),
        }
    }

    /// Encode this option to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut bytes)?;
        Ok(bytes)
    }

    /// Logical option payload bytes, without the option code or length byte(s).
    ///
    /// This is the full reassembled value (RFC 3396): for a long option that the
    /// codec concatenated across several wire segments, this returns the joined
    /// payload. Pad and end options have no payload and return an empty vector.
    pub fn payload(&self) -> Result<Vec<u8>> {
        self.payload_bytes()
    }

    /// Decode all DHCP options from a byte slice.
    pub fn decode_all(bytes: &[u8]) -> Result<Vec<Self>> {
        decode_dhcp_options(bytes)
    }

    pub(super) fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Pad => {
                out.push(DHCP_OPTION_PAD);
                Ok(())
            }
            Self::End => {
                out.push(DHCP_OPTION_END);
                Ok(())
            }
            _ => {
                if matches!(self.code(), DHCP_OPTION_PAD | DHCP_OPTION_END) {
                    return Err(CrafterError::invalid_field_value(
                        "dhcp.option.code",
                        "pad and end options do not carry a length byte",
                    ));
                }
                let data = self.payload_bytes()?;
                // RFC 3396: the option length field is a single octet, so a
                // logical value longer than 255 bytes is encoded as repeated
                // instances of the same option code, split into <=255-byte
                // segments in order. Empty payloads still emit one segment.
                encode_split_option(self.code(), &data, out);
                Ok(())
            }
        }
    }

    fn payload_bytes(&self) -> Result<Vec<u8>> {
        let bytes = match self {
            Self::Pad | Self::End => Vec::new(),
            Self::MessageType(message_type) => vec![message_type.code()],
            Self::OptionOverload(overload) => vec![overload.code()],
            Self::SubnetMask(address)
            | Self::BroadcastAddress(address)
            | Self::RequestedIpAddress(address)
            | Self::ServerIdentifier(address) => address.octets().to_vec(),
            Self::Router(addresses) | Self::DomainNameServer(addresses) => {
                encode_ipv4_list(addresses)
            }
            Self::HostName(host_name) | Self::DomainName(host_name) => {
                host_name.as_bytes().to_vec()
            }
            Self::IpAddressLeaseTime(seconds)
            | Self::RenewalTime(seconds)
            | Self::RebindingTime(seconds) => seconds.to_be_bytes().to_vec(),
            Self::ParameterRequestList(requests) | Self::ClientIdentifier(requests) => {
                requests.clone()
            }
            Self::Generic { code, data } => {
                if matches!(*code, DHCP_OPTION_PAD | DHCP_OPTION_END) {
                    return Err(CrafterError::invalid_field_value(
                        "dhcp.option.code",
                        "generic option code cannot be pad or end",
                    ));
                }
                data.clone()
            }
        };
        Ok(bytes)
    }
}

pub(super) fn decode_dhcp_options(bytes: &[u8]) -> Result<Vec<DhcpOption>> {
    decode_segments_to_options(&scan_dhcp_option_segments(DhcpOptionArea::Options, bytes)?)
}

/// Find the option-overload value (option 52) carried in a normal-area option
/// list, when present (RFC 2132 section 9.3).
pub(super) fn find_option_overload(options: &[DhcpOption]) -> Option<OptionOverload> {
    options.iter().find_map(|option| match option {
        DhcpOption::OptionOverload(overload) => Some(*overload),
        _ => None,
    })
}

/// Decode the options carried in an overloaded `file` or `sname` field.
///
/// Source: RFC 2131 section 4.1. An overloaded field begins at its first octet,
/// terminates with an `end` option, and is followed by padding to fill the
/// remainder of the fixed-width field. This decoder applies that layout: it
/// scans typed options until the `end` marker, after which only padding (zero
/// bytes / pad options) may appear. A missing end marker or non-padding data
/// after the end marker is reported as a structured error with a field name
/// scoped to the source area; truncation never panics.
pub(super) fn decode_overload_area_options(
    area: DhcpOptionArea,
    bytes: &[u8],
) -> Result<Vec<DhcpOption>> {
    let segments = scan_dhcp_option_segments(area, bytes)?;
    let mut order = SegmentOrder::new();
    let mut saw_end = false;

    for segment in &segments {
        match segment.code {
            DhcpOptionCode::Pad => {
                // Pad both before and after the end marker is allowed; the
                // remainder of the fixed-width field is zero-padded.
                if !saw_end {
                    order.push_pad();
                }
            }
            DhcpOptionCode::End if !saw_end => {
                order.push_end();
                saw_end = true;
            }
            _ => {
                if saw_end {
                    return Err(CrafterError::invalid_field_value(
                        overload_end_field(area),
                        "non-padding data follows the DHCP end option in an overloaded field",
                    ));
                }
                order.push_content(segment.code_value(), &segment.data);
            }
        }
    }

    // Decode (and RFC 3396 reassemble) the collected options first so a per-option
    // structural error surfaces ahead of the missing-end-marker check, matching the
    // ordering callers and the malformed corpus expect.
    let options = order.into_options()?;

    if !saw_end {
        return Err(CrafterError::invalid_field_value(
            overload_field(area),
            "overloaded DHCP field is missing an end marker",
        ));
    }

    Ok(options)
}

const fn overload_field(area: DhcpOptionArea) -> &'static str {
    match area {
        DhcpOptionArea::Options => "dhcp.options",
        DhcpOptionArea::File => "dhcp.file.options",
        DhcpOptionArea::Sname => "dhcp.sname.options",
    }
}

const fn overload_end_field(area: DhcpOptionArea) -> &'static str {
    match area {
        DhcpOptionArea::Options => "dhcp.option.end",
        DhcpOptionArea::File => "dhcp.file.option.end",
        DhcpOptionArea::Sname => "dhcp.sname.option.end",
    }
}

/// Encode an option list into a fixed-width overloaded field area.
///
/// Source: RFC 2131 section 4.1. The options are encoded starting at the first
/// octet, an `end` marker is appended when the caller did not supply one, and
/// the field is zero-padded to its fixed width. Returns an error when the
/// encoded options do not fit within the field.
pub(super) fn encode_overload_area_options(
    field: &'static str,
    options: &[DhcpOption],
    width: usize,
) -> Result<Vec<u8>> {
    let mut bytes = encode_dhcp_options(options)?;
    if bytes.len() > width {
        return Err(CrafterError::invalid_field_value(
            field,
            "overloaded DHCP field options exceed the fixed field width",
        ));
    }
    bytes.resize(width, 0);
    Ok(bytes)
}

/// Decode raw option segments into logical typed options.
///
/// This is the logical decoder layered on top of the raw segment scanner. It
/// enforces the structural policy for the normal options area: options must be
/// terminated by an end marker, and only padding may follow it. RFC 3396 long
/// option concatenation is applied here: repeated instances of the same option
/// code are reassembled, in declaration order, into one logical option whose
/// payload is the concatenation of every instance's data. The raw per-instance
/// segments stay inspectable through [`scan_dhcp_option_segments`].
fn decode_segments_to_options(segments: &[DhcpOptionSegment]) -> Result<Vec<DhcpOption>> {
    let mut order = SegmentOrder::new();
    let mut saw_end = false;

    for segment in segments {
        match segment.code {
            DhcpOptionCode::Pad => order.push_pad(),
            DhcpOptionCode::End if !saw_end => {
                order.push_end();
                saw_end = true;
            }
            _ => {
                if saw_end {
                    return Err(CrafterError::invalid_field_value(
                        "dhcp.option.end",
                        "non-padding data follows DHCP end option",
                    ));
                }
                order.push_content(segment.code_value(), &segment.data);
            }
        }
    }

    // Decode (and RFC 3396 reassemble) the collected options first so a per-option
    // structural error surfaces ahead of the missing-end-marker check, matching the
    // prior decode ordering and the malformed corpus expectations.
    let options = order.into_options()?;

    if !saw_end {
        return Err(CrafterError::invalid_field_value(
            "dhcp.options",
            "DHCP options are missing an end marker",
        ));
    }

    Ok(options)
}

/// Ordered accumulator that applies RFC 3396 concatenation while preserving the
/// declaration order of pad, end, and content options within one area.
///
/// Content segments sharing an option code are reassembled into a single logical
/// option positioned where the first portion appeared (RFC 3396 section 7), with
/// later portions' data appended in order. Pad and end markers are never
/// concatenated and keep their relative position.
struct SegmentOrder {
    slots: Vec<Slot>,
    content_index: std::collections::HashMap<u8, usize>,
}

enum Slot {
    Pad,
    End,
    Content { code: u8, data: Vec<u8> },
}

impl SegmentOrder {
    fn new() -> Self {
        Self {
            slots: Vec::new(),
            content_index: std::collections::HashMap::new(),
        }
    }

    fn push_pad(&mut self) {
        self.slots.push(Slot::Pad);
    }

    fn push_end(&mut self) {
        self.slots.push(Slot::End);
    }

    fn push_content(&mut self, code: u8, data: &[u8]) {
        if let Some(&index) = self.content_index.get(&code) {
            if let Slot::Content { data: existing, .. } = &mut self.slots[index] {
                existing.extend_from_slice(data);
                return;
            }
        }
        let index = self.slots.len();
        self.content_index.insert(code, index);
        self.slots.push(Slot::Content {
            code,
            data: data.to_vec(),
        });
    }

    fn into_options(self) -> Result<Vec<DhcpOption>> {
        let mut options = Vec::with_capacity(self.slots.len());
        for slot in self.slots {
            match slot {
                Slot::Pad => options.push(DhcpOption::Pad),
                Slot::End => options.push(DhcpOption::End),
                Slot::Content { code, data } => options.push(decode_dhcp_option(code, &data)?),
            }
        }
        Ok(options)
    }
}

pub(super) fn decode_dhcp_option(code: u8, data: &[u8]) -> Result<DhcpOption> {
    match code {
        DHCP_OPTION_MESSAGE_TYPE => {
            validate_fixed_len("dhcp.option.message_type", data.len(), 1)?;
            Ok(DhcpOption::MessageType(DhcpMessageType::from_code(data[0])))
        }
        DHCP_OPTION_OVERLOAD => {
            validate_fixed_len("dhcp.option.overload", data.len(), 1)?;
            let overload = OptionOverload::from_code(data[0]);
            Ok(DhcpOption::OptionOverload(overload))
        }
        DHCP_OPTION_SUBNET_MASK => Ok(DhcpOption::SubnetMask(decode_ipv4_option(
            "dhcp.option.subnet_mask",
            data,
        )?)),
        DHCP_OPTION_ROUTER => Ok(DhcpOption::Router(decode_ipv4_list(
            "dhcp.option.router",
            data,
        )?)),
        DHCP_OPTION_DOMAIN_NAME_SERVER => Ok(DhcpOption::DomainNameServer(decode_ipv4_list(
            "dhcp.option.domain_name_server",
            data,
        )?)),
        // RFC 2132 host/domain names are NVT ASCII, not guaranteed UTF-8. When
        // the bytes decode as UTF-8 the convenience String variant is used;
        // otherwise the raw bytes are preserved verbatim through the generic
        // variant so no data is lost. The format-aware `typed_value()` view
        // still surfaces these as `DhcpOptionValue::Text` in both cases.
        DHCP_OPTION_HOST_NAME => Ok(match decode_optional_text(data) {
            Some(text) => DhcpOption::HostName(text),
            None => DhcpOption::Generic {
                code,
                data: data.to_vec(),
            },
        }),
        DHCP_OPTION_DOMAIN_NAME => Ok(match decode_optional_text(data) {
            Some(text) => DhcpOption::DomainName(text),
            None => DhcpOption::Generic {
                code,
                data: data.to_vec(),
            },
        }),
        DHCP_OPTION_BROADCAST_ADDRESS => Ok(DhcpOption::BroadcastAddress(decode_ipv4_option(
            "dhcp.option.broadcast_address",
            data,
        )?)),
        DHCP_OPTION_REQUESTED_IP_ADDRESS => Ok(DhcpOption::RequestedIpAddress(decode_ipv4_option(
            "dhcp.option.requested_ip_address",
            data,
        )?)),
        DHCP_OPTION_IP_ADDRESS_LEASE_TIME => Ok(DhcpOption::IpAddressLeaseTime(decode_u32_option(
            "dhcp.option.lease_time",
            data,
        )?)),
        DHCP_OPTION_SERVER_IDENTIFIER => Ok(DhcpOption::ServerIdentifier(decode_ipv4_option(
            "dhcp.option.server_identifier",
            data,
        )?)),
        DHCP_OPTION_PARAMETER_REQUEST_LIST => Ok(DhcpOption::ParameterRequestList(data.to_vec())),
        DHCP_OPTION_RENEWAL_TIME => Ok(DhcpOption::RenewalTime(decode_u32_option(
            "dhcp.option.renewal_time",
            data,
        )?)),
        DHCP_OPTION_REBINDING_TIME => Ok(DhcpOption::RebindingTime(decode_u32_option(
            "dhcp.option.rebinding_time",
            data,
        )?)),
        DHCP_OPTION_CLIENT_IDENTIFIER => Ok(DhcpOption::ClientIdentifier(data.to_vec())),
        _ => Ok(DhcpOption::Generic {
            code,
            data: data.to_vec(),
        }),
    }
}

pub(super) fn encode_dhcp_options(options: &[DhcpOption]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(encoded_options_len_lossy(options));
    let mut saw_end = false;

    for option in options {
        if saw_end && !matches!(option, DhcpOption::Pad) {
            return Err(CrafterError::invalid_field_value(
                "dhcp.options",
                "only padding may follow the DHCP end option",
            ));
        }
        if matches!(option, DhcpOption::End) {
            saw_end = true;
        }
        option.encode_into(&mut out)?;
    }

    if !saw_end {
        out.push(DHCP_OPTION_END);
    }
    Ok(out)
}

pub(super) fn encoded_options_len_lossy(options: &[DhcpOption]) -> usize {
    let len = options.iter().map(DhcpOption::encoded_len).sum::<usize>();
    if options
        .iter()
        .any(|option| matches!(option, DhcpOption::End))
    {
        len
    } else {
        len + 1
    }
}

fn validate_fixed_len(field: &'static str, actual: usize, expected: usize) -> Result<()> {
    if actual != expected {
        return Err(CrafterError::invalid_field_value(
            field,
            "DHCP option has an invalid fixed length",
        ));
    }
    Ok(())
}

/// Decode an NVT ASCII / text-like option payload into a convenience `String`
/// when, and only when, the bytes are valid UTF-8. RFC 2132 text options are
/// not guaranteed UTF-8, so a non-UTF-8 payload yields `None`, leaving the
/// caller to preserve the raw bytes rather than forcing a lossy conversion.
fn decode_optional_text(data: &[u8]) -> Option<String> {
    str::from_utf8(data).map(str::to_string).ok()
}

fn decode_ipv4_option(field: &'static str, data: &[u8]) -> Result<Ipv4Addr> {
    validate_fixed_len(field, data.len(), 4)?;
    Ok(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
}

fn decode_ipv4_list(field: &'static str, data: &[u8]) -> Result<Vec<Ipv4Addr>> {
    if data.len() % 4 != 0 {
        return Err(CrafterError::invalid_field_value(
            field,
            "IPv4 address list option length must be a multiple of four",
        ));
    }
    Ok(data
        .chunks_exact(4)
        .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
        .collect())
}

fn decode_u32_option(field: &'static str, data: &[u8]) -> Result<u32> {
    validate_fixed_len(field, data.len(), 4)?;
    read_u32_be(data)
}

fn decode_u16_option(field: &'static str, data: &[u8]) -> Result<u16> {
    validate_fixed_len(field, data.len(), 2)?;
    read_u16_be(data)
}

fn decode_u16_list(field: &'static str, data: &[u8]) -> Result<Vec<u16>> {
    if data.is_empty() || data.len() % 2 != 0 {
        return Err(CrafterError::invalid_field_value(
            field,
            "16-bit list option length must be a non-zero multiple of two",
        ));
    }
    data.chunks_exact(2).map(read_u16_be).collect()
}

fn decode_bool_option(field: &'static str, data: &[u8]) -> Result<bool> {
    validate_fixed_len(field, data.len(), 1)?;
    // RFC 2132 defines these flags as a single octet whose value is 0 or 1.
    // Any other value is malformed for the typed view; the raw segment bytes
    // remain inspectable for callers that need the verbatim octet.
    match data[0] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(CrafterError::invalid_field_value(
            field,
            "boolean option octet must be 0 or 1",
        )),
    }
}

fn decode_ipv4_pairs(field: &'static str, data: &[u8]) -> Result<Vec<(Ipv4Addr, Ipv4Addr)>> {
    if data.is_empty() || data.len() % 8 != 0 {
        return Err(CrafterError::invalid_field_value(
            field,
            "IPv4 address pair option length must be a non-zero multiple of eight",
        ));
    }
    Ok(data
        .chunks_exact(8)
        .map(|chunk| {
            (
                Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]),
                Ipv4Addr::new(chunk[4], chunk[5], chunk[6], chunk[7]),
            )
        })
        .collect())
}

fn encode_ipv4_list(addresses: &[Ipv4Addr]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(addresses.len() * 4);
    for address in addresses {
        bytes.extend_from_slice(&address.octets());
    }
    bytes
}

/// Octet length of one RFC 2132 static route entry on the wire (option 33).
const DHCP_STATIC_ROUTE_ENTRY_LEN: usize = 8;
/// Octet length of the router address in an RFC 3442 classless route.
const DHCP_CLASSLESS_ROUTER_LEN: usize = 4;
/// Maximum subnet-mask width for an RFC 3442 classless route prefix.
const DHCP_CLASSLESS_MAX_PREFIX: u8 = 32;
/// Maximum length of a single RFC 1035 label (six-bit length field).
const DHCP_DNS_LABEL_MAX_LEN: usize = 63;
/// Two high bits set on a length octet mark an RFC 1035 compression pointer.
const DHCP_DNS_POINTER_MASK: u8 = 0xC0;
/// RFC 3361 SIP servers encoding: RFC 1035 domain-name list.
const DHCP_SIP_ENC_DOMAIN: u8 = 0;
/// RFC 3361 SIP servers encoding: IPv4 address list.
const DHCP_SIP_ENC_ADDRESS: u8 = 1;

/// Decode an RFC 2132 static route list (option 33).
///
/// Source: RFC 2132 section 5.8. The payload is a sequence of 8-octet entries,
/// each a destination IPv4 address followed by the router IPv4 address. The
/// length must be a non-zero multiple of eight; anything else is a structured
/// error rather than a panic.
fn decode_static_routes(data: &[u8]) -> Result<Vec<DhcpStaticRoute>> {
    let field = "dhcp.option.static_route";
    if data.is_empty() || data.len() % DHCP_STATIC_ROUTE_ENTRY_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            field,
            "static route option length must be a non-zero multiple of eight",
        ));
    }
    Ok(data
        .chunks_exact(DHCP_STATIC_ROUTE_ENTRY_LEN)
        .map(|chunk| {
            DhcpStaticRoute::new(
                Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]),
                Ipv4Addr::new(chunk[4], chunk[5], chunk[6], chunk[7]),
            )
        })
        .collect())
}

/// Encode an RFC 2132 static route list (option 33).
fn encode_static_routes(routes: &[DhcpStaticRoute]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(routes.len() * DHCP_STATIC_ROUTE_ENTRY_LEN);
    for route in routes {
        bytes.extend_from_slice(&route.destination.octets());
        bytes.extend_from_slice(&route.router.octets());
    }
    bytes
}

/// Decode an RFC 3442 classless static route list (option 121).
///
/// Source: RFC 3442. Each route is a destination descriptor (one mask-width
/// octet plus `ceil(width / 8)` significant subnet octets) followed by a
/// 4-octet router address. Prefix lengths above 32, truncated descriptors, and
/// truncated router addresses all surface as structured errors; the function
/// never panics on short input.
fn decode_classless_routes(data: &[u8]) -> Result<Vec<DhcpClasslessRoute>> {
    let field = "dhcp.option.classless_static_route";
    let mut routes = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let prefix_length = data[offset];
        offset += 1;
        if prefix_length > DHCP_CLASSLESS_MAX_PREFIX {
            return Err(CrafterError::invalid_field_value(
                field,
                "classless route prefix length exceeds 32 bits",
            ));
        }
        let significant = DhcpClasslessRoute::significant_octets(prefix_length);
        if offset + significant + DHCP_CLASSLESS_ROUTER_LEN > data.len() {
            return Err(CrafterError::buffer_too_short(
                field,
                offset + significant + DHCP_CLASSLESS_ROUTER_LEN,
                data.len(),
            ));
        }
        let mut subnet = [0u8; 4];
        subnet[..significant].copy_from_slice(&data[offset..offset + significant]);
        offset += significant;
        let router = Ipv4Addr::new(
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        );
        offset += DHCP_CLASSLESS_ROUTER_LEN;
        routes.push(DhcpClasslessRoute::new(
            prefix_length,
            Ipv4Addr::from(subnet),
            router,
        ));
    }

    Ok(routes)
}

/// Encode an RFC 3442 classless static route list (option 121).
///
/// Only the `ceil(prefix_length / 8)` significant subnet octets are emitted, in
/// order, before each route's 4-octet router address (RFC 3442).
fn encode_classless_routes(routes: &[DhcpClasslessRoute]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for route in routes {
        let significant = DhcpClasslessRoute::significant_octets(route.prefix_length).min(4);
        bytes.push(route.prefix_length);
        bytes.extend_from_slice(&route.destination.octets()[..significant]);
        bytes.extend_from_slice(&route.router.octets());
    }
    bytes
}

/// Decode an RFC 1035 / RFC 3397 domain-name list (option 119 and the option
/// 120 domain encoding).
///
/// Source: RFC 3397 section 2 and RFC 1035 section 4.1.4. Names are sequences
/// of length-prefixed labels terminated by a zero-length root label, and a
/// label length whose two high bits are set is a two-octet compression pointer
/// into the aggregate option data. Truncated labels or pointers, oversized
/// labels, and forward/self pointer loops surface as structured errors rather
/// than panics.
fn decode_domain_name_list(field: &'static str, data: &[u8]) -> Result<Vec<String>> {
    let mut names = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let (name, next) = decode_domain_name(field, data, offset)?;
        names.push(name);
        offset = next;
    }

    Ok(names)
}

/// Decode one RFC 1035 domain name starting at `start`, returning the assembled
/// name and the offset of the first octet after the name in the linear stream
/// (the byte after the terminating root label or compression pointer).
fn decode_domain_name(field: &'static str, data: &[u8], start: usize) -> Result<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut cursor = start;
    // The offset just past the name in the linear stream, fixed at the first
    // compression pointer encountered (RFC 1035 section 4.1.4).
    let mut linear_end: Option<usize> = None;
    // Bound the jump count by the data length to reject pointer loops.
    let mut jumps = 0usize;

    loop {
        if cursor >= data.len() {
            return Err(CrafterError::buffer_too_short(
                field,
                cursor + 1,
                data.len(),
            ));
        }
        let length = data[cursor];

        if length == 0 {
            cursor += 1;
            let end = linear_end.unwrap_or(cursor);
            return Ok((labels.join("."), end));
        }

        if length & DHCP_DNS_POINTER_MASK == DHCP_DNS_POINTER_MASK {
            if cursor + 2 > data.len() {
                return Err(CrafterError::buffer_too_short(
                    field,
                    cursor + 2,
                    data.len(),
                ));
            }
            let pointer =
                (usize::from(length & !DHCP_DNS_POINTER_MASK) << 8) | usize::from(data[cursor + 1]);
            if linear_end.is_none() {
                linear_end = Some(cursor + 2);
            }
            if pointer >= data.len() {
                return Err(CrafterError::invalid_field_value(
                    field,
                    "domain-name compression pointer points outside the option data",
                ));
            }
            jumps += 1;
            if jumps > data.len() {
                return Err(CrafterError::invalid_field_value(
                    field,
                    "domain-name compression pointers form a loop",
                ));
            }
            cursor = pointer;
            continue;
        }

        if length & DHCP_DNS_POINTER_MASK != 0 {
            return Err(CrafterError::invalid_field_value(
                field,
                "domain-name label length has reserved high bits set",
            ));
        }

        let label_len = usize::from(length);
        if label_len > DHCP_DNS_LABEL_MAX_LEN {
            return Err(CrafterError::invalid_field_value(
                field,
                "domain-name label exceeds 63 octets",
            ));
        }
        let label_start = cursor + 1;
        let label_end = label_start + label_len;
        if label_end > data.len() {
            return Err(CrafterError::buffer_too_short(field, label_end, data.len()));
        }
        // RFC 1035 labels are not guaranteed UTF-8; preserve the bytes lossily
        // for the convenience string view. Raw bytes remain inspectable through
        // the option segments and the option's `payload()`.
        labels.push(String::from_utf8_lossy(&data[label_start..label_end]).into_owned());
        cursor = label_end;
    }
}

/// Encode an RFC 1035 / RFC 3397 domain-name list without compression.
///
/// Each name is split on `.` into labels, every label is emitted as a
/// length-prefixed run, and the name is terminated by a zero root label. Empty
/// labels (leading, trailing, or doubled dots) are dropped so a trailing dot in
/// a fully-qualified name does not produce an invalid zero-length label mid
/// name. This emitter never uses compression pointers, which is always a valid
/// RFC 1035 encoding; the decoder still resolves pointers produced elsewhere.
fn encode_domain_name_list(names: &[String]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for name in names {
        for label in name.split('.').filter(|label| !label.is_empty()) {
            let label_bytes = label.as_bytes();
            let len = label_bytes.len().min(DHCP_DNS_LABEL_MAX_LEN);
            bytes.push(len as u8);
            bytes.extend_from_slice(&label_bytes[..len]);
        }
        bytes.push(0);
    }
    bytes
}

/// Decode an RFC 3361 SIP servers option (option 120).
///
/// Source: RFC 3361 section 3. The first payload octet is the `enc` selector:
/// `0` introduces an RFC 1035 domain-name list, `1` introduces an IPv4 address
/// list (length a non-zero multiple of four after the `enc` byte). Any other
/// `enc` value is preserved verbatim. An empty payload (no `enc` byte) is a
/// structured error.
fn decode_sip_servers(data: &[u8]) -> Result<SipServers> {
    let field = "dhcp.option.sip_servers";
    let Some((&encoding, rest)) = data.split_first() else {
        return Err(CrafterError::buffer_too_short(field, 1, 0));
    };
    match encoding {
        DHCP_SIP_ENC_DOMAIN => Ok(SipServers::DomainNames(decode_domain_name_list(
            field, rest,
        )?)),
        DHCP_SIP_ENC_ADDRESS => {
            if rest.is_empty() || rest.len() % 4 != 0 {
                return Err(CrafterError::invalid_field_value(
                    field,
                    "SIP server address list length must be a non-zero multiple of four",
                ));
            }
            Ok(SipServers::Addresses(decode_ipv4_list(field, rest)?))
        }
        other => Ok(SipServers::Unknown {
            encoding: other,
            data: rest.to_vec(),
        }),
    }
}

/// Encode an RFC 3361 SIP servers option (option 120).
fn encode_sip_servers(servers: &SipServers) -> Vec<u8> {
    match servers {
        SipServers::DomainNames(names) => {
            let mut bytes = vec![DHCP_SIP_ENC_DOMAIN];
            bytes.extend(encode_domain_name_list(names));
            bytes
        }
        SipServers::Addresses(addresses) => {
            let mut bytes = vec![DHCP_SIP_ENC_ADDRESS];
            bytes.extend(encode_ipv4_list(addresses));
            bytes
        }
        SipServers::Unknown { encoding, data } => {
            let mut bytes = Vec::with_capacity(1 + data.len());
            bytes.push(*encoding);
            bytes.extend_from_slice(data);
            bytes
        }
    }
}

/// Maximum payload an option length byte can describe (RFC 2132 section 2).
pub(super) const DHCP_MAX_OPTION_DATA_LEN: usize = u8::MAX as usize;

/// Encode a logical option payload as one or more on-the-wire segments.
///
/// RFC 3396: because the DHCP option length is a single octet, a logical value
/// longer than 255 octets is split into repeated instances of the same option
/// code. The split portions are emitted in sequential order, each at most 255
/// bytes; the first portion comes first. Payloads of 255 bytes or fewer emit a
/// single segment, and an empty payload emits one zero-length segment.
pub(super) fn encode_split_option(code: u8, data: &[u8], out: &mut Vec<u8>) {
    if data.is_empty() {
        out.push(code);
        out.push(0);
        return;
    }
    for chunk in data.chunks(DHCP_MAX_OPTION_DATA_LEN) {
        out.push(code);
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
}

/// Encoded byte length of a payload after RFC 3396 splitting, including the
/// per-segment code and length overhead.
pub(super) fn split_option_encoded_len(data_len: usize) -> usize {
    if data_len == 0 {
        return 2;
    }
    let segments = data_len.div_ceil(DHCP_MAX_OPTION_DATA_LEN);
    segments * 2 + data_len
}

#[cfg(test)]
mod dhcp_options {
    use super::super::{
        scan_dhcp_option_segments, Dhcp, DhcpMessageType, DhcpOption, DhcpOptionArea,
        DhcpOptionCode, DhcpOptionSegment, DhcpOptionStatus, DhcpOptionValue,
    };
    use crate::error::CrafterError;
    use core::net::Ipv4Addr;

    const OFFER_OPTIONS: &str = fixture_str!("bytes/dhcp-offer-options.hex");

    #[test]
    fn option_fixture_decodes_common_offer_values() {
        let options = DhcpOption::decode_all(&hex_fixture(OFFER_OPTIONS)).unwrap();
        let dhcp = Dhcp::new().options(options);

        assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Offer));
        assert_eq!(
            dhcp.server_identifier_value(),
            Some(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(
            dhcp.subnet_mask_value(),
            Some(Ipv4Addr::new(255, 255, 255, 0))
        );
        assert_eq!(dhcp.routers(), vec![Ipv4Addr::new(192, 0, 2, 1)]);
        assert_eq!(
            dhcp.domain_name_servers(),
            vec![
                Ipv4Addr::new(192, 0, 2, 53),
                Ipv4Addr::new(198, 51, 100, 53)
            ]
        );
        assert_eq!(dhcp.lease_time_value(), Some(3600));
    }

    #[test]
    fn typed_options_roundtrip_and_preserve_unknown_options() {
        let options = vec![
            DhcpOption::Pad,
            DhcpOption::message_type(DhcpMessageType::Ack),
            DhcpOption::host_name("agent-host"),
            DhcpOption::generic(224, [0xde, 0xad, 0xbe, 0xef]),
            DhcpOption::End,
            DhcpOption::Pad,
        ];

        let encoded = Dhcp::new()
            .options(options.clone())
            .encoded_options()
            .unwrap();
        let decoded = DhcpOption::decode_all(&encoded).unwrap();

        assert_eq!(decoded, options);
    }

    #[test]
    fn builder_appends_end_marker_deterministically() {
        let encoded = Dhcp::new()
            .message_type(DhcpMessageType::Discover)
            .encoded_options()
            .unwrap();

        assert_eq!(encoded.last(), Some(&super::DHCP_OPTION_END));
    }

    #[test]
    fn dhcp_offer_options_decode_through_new_model() {
        let bytes = hex_fixture(OFFER_OPTIONS);

        // The raw segment scanner surfaces each on-the-wire option instance
        // with source-area, codepoint, declared length, offset, and bytes.
        let segments = scan_dhcp_option_segments(DhcpOptionArea::Options, &bytes).unwrap();

        let codes: Vec<u8> = segments.iter().map(|s| s.code_value()).collect();
        assert_eq!(codes, vec![53, 54, 1, 3, 6, 51, 255]);

        // Every segment reports the area it came from.
        assert!(segments.iter().all(|s| s.area == DhcpOptionArea::Options));

        // Declared length and offsets are inspectable for non-single-octet
        // options; pad/end carry no declared length.
        let message_type = &segments[0];
        assert_eq!(message_type.code, DhcpOptionCode::Assigned(53));
        assert_eq!(message_type.declared_len, Some(1));
        assert_eq!(message_type.offset, 0);
        assert_eq!(message_type.data, vec![DhcpMessageType::Offer.code()]);

        let server_id = &segments[1];
        assert_eq!(server_id.declared_len, Some(4));
        assert_eq!(server_id.offset, 3);
        assert_eq!(server_id.data, vec![192, 0, 2, 1]);

        let end = segments.last().unwrap();
        assert_eq!(end.code, DhcpOptionCode::End);
        assert!(end.is_single_octet());
        assert_eq!(end.declared_len, None);

        // The logical typed decode bridges onto reusable value families.
        let options = DhcpOption::decode_all(&bytes).unwrap();
        let logical: Vec<Option<DhcpOptionValue>> =
            options.iter().map(DhcpOption::logical_value).collect();
        assert_eq!(
            logical[0],
            Some(DhcpOptionValue::MessageType(DhcpMessageType::Offer))
        );
        assert_eq!(
            logical[2],
            Some(DhcpOptionValue::Ipv4(Ipv4Addr::new(255, 255, 255, 0)))
        );
        assert_eq!(
            logical[4],
            Some(DhcpOptionValue::Ipv4List(vec![
                Ipv4Addr::new(192, 0, 2, 53),
                Ipv4Addr::new(198, 51, 100, 53),
            ]))
        );
        assert_eq!(logical[5], Some(DhcpOptionValue::U32(3_600)));
        // The end marker has no value family.
        assert_eq!(options.last().unwrap().logical_value(), None);

        // Registry names are source-backed for assigned codes.
        assert_eq!(options[0].registry_name(), Some("DHCP Msg Type"));
        assert_eq!(options[1].registry_name(), Some("DHCP Server Id"));
    }

    #[test]
    fn dhcp_option_model_preserves_unknown_private_bytes() {
        // Private-use code 224 and an unassigned/removed code 84 must both be
        // preserved as raw bytes with full segment metadata and classified by
        // the source-backed registry.
        let private_payload = [0xde, 0xad, 0xbe, 0xef];
        let removed_payload = [0x01, 0x02];

        let options = vec![
            DhcpOption::message_type(DhcpMessageType::Ack),
            DhcpOption::generic(224, private_payload),
            DhcpOption::generic(84, removed_payload),
            DhcpOption::End,
        ];

        let encoded = Dhcp::new()
            .options(options.clone())
            .encoded_options()
            .unwrap();

        // Round-trip through the typed decoder preserves the unknown bytes.
        let decoded = DhcpOption::decode_all(&encoded).unwrap();
        assert_eq!(decoded, options);

        // Codepoint classification is source-backed.
        assert_eq!(decoded[1].option_code(), DhcpOptionCode::PrivateUse(224));
        assert_eq!(
            decoded[2].option_code(),
            DhcpOptionCode::RemovedOrUnassigned(84)
        );
        assert_eq!(decoded[1].registry_name(), None);
        assert_eq!(decoded[2].registry_name(), Some("REMOVED/Unassigned"));

        // The logical value preserves opaque bytes verbatim.
        assert_eq!(
            decoded[1].logical_value(),
            Some(DhcpOptionValue::Opaque(private_payload.to_vec()))
        );
        assert_eq!(
            decoded[1]
                .logical_value()
                .and_then(|v| v.as_bytes().map(<[u8]>::to_vec)),
            Some(private_payload.to_vec())
        );

        // The raw segment scanner exposes declared length, offset, and bytes
        // for the unknown/private options without losing data.
        let segments = scan_dhcp_option_segments(DhcpOptionArea::Options, &encoded).unwrap();
        let private = segments
            .iter()
            .find(|s| s.code_value() == 224)
            .expect("private-use segment present");
        assert_eq!(private.code, DhcpOptionCode::PrivateUse(224));
        assert_eq!(private.declared_len, Some(private_payload.len() as u8));
        assert_eq!(private.data, private_payload);

        let removed = segments
            .iter()
            .find(|s| s.code_value() == 84)
            .expect("removed segment present");
        assert_eq!(removed.code, DhcpOptionCode::RemovedOrUnassigned(84));
        assert_eq!(removed.data, removed_payload);

        // Codepoint status is classified directly as well.
        assert_eq!(
            DhcpOptionCode::from_code(224),
            DhcpOptionCode::PrivateUse(224)
        );
        assert_eq!(
            super::option_status(84),
            DhcpOptionStatus::RemovedOrUnassigned
        );
    }

    #[test]
    fn dhcp_option_codec_preserves_raw_segments() {
        // A mixed stream with leading pad, several typed options, an unknown
        // private-use option, an end marker, and a trailing pad. The logical
        // decoder routes through the raw scanner, so the segment view and the
        // typed view must agree, and an exact byte round-trip must hold.
        let options = vec![
            DhcpOption::Pad,
            DhcpOption::message_type(DhcpMessageType::Ack),
            DhcpOption::subnet_mask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::generic(224, [0xde, 0xad, 0xbe, 0xef]),
            DhcpOption::End,
            DhcpOption::Pad,
        ];

        let encoded = Dhcp::new()
            .options(options.clone())
            .encoded_options()
            .unwrap();

        // Raw scanner records every on-the-wire instance in order, including
        // the leading and trailing pad and the end marker.
        let segments = scan_dhcp_option_segments(DhcpOptionArea::Options, &encoded).unwrap();
        let codes: Vec<u8> = segments.iter().map(DhcpOptionSegment::code_value).collect();
        assert_eq!(codes, vec![0, 53, 1, 224, 255, 0]);
        assert!(segments.iter().all(|s| s.area == DhcpOptionArea::Options));

        // The unknown private-use option keeps its declared length and bytes.
        let private = &segments[3];
        assert_eq!(private.code, DhcpOptionCode::PrivateUse(224));
        assert_eq!(private.declared_len, Some(4));
        assert_eq!(private.data, vec![0xde, 0xad, 0xbe, 0xef]);

        // The end marker is a single-octet option with no declared length, and
        // a pad segment may legally follow it.
        let end = &segments[4];
        assert_eq!(end.code, DhcpOptionCode::End);
        assert!(end.is_single_octet());
        assert_eq!(end.declared_len, None);
        assert_eq!(segments[5].code, DhcpOptionCode::Pad);

        // The logical decode matches the original options exactly, and a second
        // encode reproduces the original bytes (exact round-trip).
        let decoded = DhcpOption::decode_all(&encoded).unwrap();
        assert_eq!(decoded, options);
        let re_encoded = Dhcp::new().options(decoded).encoded_options().unwrap();
        assert_eq!(re_encoded, encoded);
    }

    #[test]
    fn dhcp_option_codec_rejects_non_padding_after_end() {
        // An end marker immediately followed by non-padding data is a structured
        // decode error, not a panic or a silently truncated decode.
        let bytes = [
            super::DHCP_OPTION_END,
            super::DHCP_OPTION_MESSAGE_TYPE,
            1,
            1,
        ];

        let error = DhcpOption::decode_all(&bytes).unwrap_err();
        assert!(matches!(
            error,
            CrafterError::InvalidFieldValue { field, .. } if field == "dhcp.option.end"
        ));

        // The raw scanner itself stays permissive and records the trailing
        // option as a segment so callers can still inspect the malformed bytes.
        let segments = scan_dhcp_option_segments(DhcpOptionArea::Options, &bytes).unwrap();
        let codes: Vec<u8> = segments.iter().map(DhcpOptionSegment::code_value).collect();
        assert_eq!(codes, vec![255, 53]);
    }

    #[test]
    fn dhcp_option_codec_rejects_missing_end_marker() {
        // A well-formed option with no terminating end marker is rejected by the
        // logical decoder with a stable field name.
        let bytes = [super::DHCP_OPTION_MESSAGE_TYPE, 1, 1];

        let error = DhcpOption::decode_all(&bytes).unwrap_err();
        assert!(matches!(
            error,
            CrafterError::InvalidFieldValue { field, .. } if field == "dhcp.options"
        ));
    }

    #[test]
    fn dhcp_option_codec_reports_truncated_segments() {
        // Truncated length and truncated data surface as buffer-too-short
        // errors from the raw scanner rather than panicking.
        let truncated_length = [super::DHCP_OPTION_MESSAGE_TYPE];
        let truncated_data = [super::DHCP_OPTION_MESSAGE_TYPE, 4, 0x01];

        for bytes in [truncated_length.as_slice(), truncated_data.as_slice()] {
            let error = scan_dhcp_option_segments(DhcpOptionArea::Options, bytes).unwrap_err();
            assert!(matches!(error, CrafterError::BufferTooShort { .. }));
            // The logical decoder propagates the same structured error.
            assert!(matches!(
                DhcpOption::decode_all(bytes),
                Err(CrafterError::BufferTooShort { .. })
            ));
        }
    }

    #[test]
    fn dhcp_option_codec_preserves_pad_and_unknown_options() {
        // Padding before and after content, plus an unknown removed/unassigned
        // codepoint, round-trip exactly and stay classified by the registry.
        let options = vec![
            DhcpOption::Pad,
            DhcpOption::Pad,
            DhcpOption::message_type(DhcpMessageType::Discover),
            DhcpOption::generic(84, [0x01, 0x02]),
            DhcpOption::End,
        ];

        let encoded = Dhcp::new()
            .options(options.clone())
            .encoded_options()
            .unwrap();
        let decoded = DhcpOption::decode_all(&encoded).unwrap();
        assert_eq!(decoded, options);

        assert_eq!(
            decoded[3].option_code(),
            DhcpOptionCode::RemovedOrUnassigned(84)
        );
        assert_eq!(
            decoded[3].logical_value(),
            Some(DhcpOptionValue::Opaque(vec![0x01, 0x02]))
        );
    }

    fn hex_fixture(input: &str) -> Vec<u8> {
        input
            .split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect()
    }
}

#[cfg(test)]
mod dhcp_rfc3396 {
    use super::super::{
        scan_dhcp_option_segments, Dhcp, DhcpMessageType, DhcpOption, DhcpOptionArea,
    };
    use super::{encode_split_option, split_option_encoded_len, DHCP_MAX_OPTION_DATA_LEN};
    use core::net::Ipv4Addr;

    // Codes used by the long-payload style options exercised below.
    const HOST_NAME: u8 = super::super::DHCP_OPTION_HOST_NAME;
    const DOMAIN_SEARCH: u8 = 119; // RFC 3397, decoded as opaque/generic here.
    const VENDOR_CLASS: u8 = 60; // Vendor class identifier, generic opaque.

    fn build_options(payload_options: Vec<DhcpOption>) -> Vec<u8> {
        Dhcp::new()
            .options(payload_options)
            .encoded_options()
            .unwrap()
    }

    #[test]
    fn dhcp_rfc3396_concatenates_repeated_option_segments() {
        // Build a wire stream by hand with one logical option (a long host name)
        // split into two same-code segments, exactly as RFC 3396 prescribes. The
        // logical decoder must reassemble them into one option whose value is the
        // concatenation, while the raw segment scanner still exposes both
        // on-the-wire portions for inspection.
        let part_one = vec![b'a'; DHCP_MAX_OPTION_DATA_LEN]; // 255 bytes
        let part_two = vec![b'b'; 40];
        let mut full = part_one.clone();
        full.extend_from_slice(&part_two);

        let mut wire = Vec::new();
        wire.push(HOST_NAME);
        wire.push(part_one.len() as u8);
        wire.extend_from_slice(&part_one);
        wire.push(HOST_NAME);
        wire.push(part_two.len() as u8);
        wire.extend_from_slice(&part_two);
        wire.push(super::super::DHCP_OPTION_END);

        // Raw segments: two separate host-name instances remain inspectable.
        let segments = scan_dhcp_option_segments(DhcpOptionArea::Options, &wire).unwrap();
        let host_segments: Vec<&super::DhcpOptionSegment> = segments
            .iter()
            .filter(|s| s.code_value() == HOST_NAME)
            .collect();
        assert_eq!(host_segments.len(), 2);
        assert_eq!(host_segments[0].data, part_one);
        assert_eq!(host_segments[1].data, part_two);

        // Logical decode: exactly one host-name option, value concatenated.
        let decoded = DhcpOption::decode_all(&wire).unwrap();
        let host_options: Vec<&DhcpOption> =
            decoded.iter().filter(|o| o.code() == HOST_NAME).collect();
        assert_eq!(host_options.len(), 1);
        match host_options[0] {
            DhcpOption::HostName(name) => {
                assert_eq!(name.as_bytes(), full.as_slice());
                assert_eq!(name.len(), DHCP_MAX_OPTION_DATA_LEN + 40);
            }
            other => panic!("expected concatenated host name, got {other:?}"),
        }
    }

    #[test]
    fn dhcp_rfc3396_encoder_splits_long_payloads() {
        // A typed option with a payload longer than 255 bytes must be encoded as
        // multiple same-code segments, each at most 255 bytes, in order.
        let long_name = "x".repeat(600);
        let encoded = build_options(vec![
            DhcpOption::host_name(long_name.clone()),
            DhcpOption::End,
        ]);

        let segments = scan_dhcp_option_segments(DhcpOptionArea::Options, &encoded).unwrap();
        let host_segments: Vec<&super::DhcpOptionSegment> = segments
            .iter()
            .filter(|s| s.code_value() == HOST_NAME)
            .collect();
        // 600 bytes -> 255 + 255 + 90 -> three segments.
        assert_eq!(host_segments.len(), 3);
        assert_eq!(host_segments[0].data.len(), DHCP_MAX_OPTION_DATA_LEN);
        assert_eq!(host_segments[1].data.len(), DHCP_MAX_OPTION_DATA_LEN);
        assert_eq!(host_segments[2].data.len(), 90);
        // Every emitted segment respects the one-byte length limit.
        assert!(host_segments
            .iter()
            .all(|s| s.declared_len.unwrap() as usize <= DHCP_MAX_OPTION_DATA_LEN));

        // Decoding the split bytes reassembles the original logical value, and a
        // re-encode reproduces the same wire bytes (the splits are canonical).
        let decoded = DhcpOption::decode_all(&encoded).unwrap();
        let host = decoded
            .iter()
            .find(|o| o.code() == HOST_NAME)
            .expect("host name present");
        assert_eq!(host, &DhcpOption::host_name(long_name));
        let re_encoded = Dhcp::new().options(decoded).encoded_options().unwrap();
        assert_eq!(re_encoded, encoded);
    }

    #[test]
    fn dhcp_rfc3396_exact_255_boundary_is_a_single_segment() {
        // A payload of exactly 255 bytes fits one segment; 256 needs two.
        let exactly_255 = vec![0xABu8; DHCP_MAX_OPTION_DATA_LEN];
        let mut out = Vec::new();
        encode_split_option(VENDOR_CLASS, &exactly_255, &mut out);
        // One segment: code + len(255) + 255 data bytes.
        assert_eq!(out.len(), 2 + DHCP_MAX_OPTION_DATA_LEN);
        assert_eq!(out[0], VENDOR_CLASS);
        assert_eq!(out[1], 255);

        let just_over = vec![0xCDu8; DHCP_MAX_OPTION_DATA_LEN + 1];
        let mut out = Vec::new();
        encode_split_option(VENDOR_CLASS, &just_over, &mut out);
        // Two segments: 255 + 1.
        let segments = scan_dhcp_option_segments(DhcpOptionArea::Options, &out).unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].data.len(), DHCP_MAX_OPTION_DATA_LEN);
        assert_eq!(segments[1].data.len(), 1);

        // Reported encoded length matches the encoder for both boundaries.
        assert_eq!(
            split_option_encoded_len(DHCP_MAX_OPTION_DATA_LEN),
            2 + DHCP_MAX_OPTION_DATA_LEN
        );
        assert_eq!(
            split_option_encoded_len(DHCP_MAX_OPTION_DATA_LEN + 1),
            2 + DHCP_MAX_OPTION_DATA_LEN + 2 + 1
        );
        assert_eq!(split_option_encoded_len(0), 2);
    }

    #[test]
    fn dhcp_rfc3396_multi_segment_roundtrip_for_long_vendor_and_message_payloads() {
        // A generic (vendor/message style) option with a 700-byte opaque payload
        // round-trips through encode -> decode -> encode. The encoded length the
        // option reports must match the actual encoded bytes so the layer length
        // accounting stays correct.
        let payload = (0u16..700).map(|n| n as u8).collect::<Vec<u8>>();
        let option = DhcpOption::generic(VENDOR_CLASS, payload.clone());
        assert_eq!(option.encode().unwrap().len(), option.encoded_len());

        let encoded = build_options(vec![option.clone(), DhcpOption::End]);
        let decoded = DhcpOption::decode_all(&encoded).unwrap();
        let vendor = decoded
            .iter()
            .find(|o| o.code() == VENDOR_CLASS)
            .expect("vendor option present");
        // Concatenated payload survives without data loss.
        assert_eq!(vendor.payload().unwrap(), payload);
        // Exact wire round-trip for canonical 255-byte splits.
        let re_encoded = Dhcp::new().options(decoded).encoded_options().unwrap();
        assert_eq!(re_encoded, encoded);
    }

    #[test]
    fn dhcp_rfc3396_concatenates_across_overloaded_areas() {
        // RFC 3396 section 5: the aggregate buffer is options, then file, then
        // sname. A domain-search style option split across all three areas must
        // reassemble into one logical value in aggregate order, while each area's
        // raw options stay separately inspectable.
        let dhcp = Dhcp::new()
            .message_type(DhcpMessageType::Ack)
            .server_identifier(Ipv4Addr::new(192, 0, 2, 1))
            .option(DhcpOption::generic(DOMAIN_SEARCH, b"aaa".to_vec()))
            .file_option(DhcpOption::generic(DOMAIN_SEARCH, b"bbb".to_vec()))
            .file_option(DhcpOption::End)
            .sname_option(DhcpOption::generic(DOMAIN_SEARCH, b"ccc".to_vec()))
            .sname_option(DhcpOption::End);

        let bytes = crate::Packet::from_layer(dhcp)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let parsed = Dhcp::decode(&bytes).unwrap();

        // Per-area raw options remain inspectable.
        assert!(parsed
            .options_value()
            .iter()
            .any(|o| o.code() == DOMAIN_SEARCH));
        assert!(parsed
            .file_options_value()
            .iter()
            .any(|o| o.code() == DOMAIN_SEARCH));
        assert!(parsed
            .sname_options_value()
            .iter()
            .any(|o| o.code() == DOMAIN_SEARCH));

        // The cross-area reassembly joins options, then file, then sname.
        let joined = parsed
            .concatenated_option(DOMAIN_SEARCH)
            .expect("option present in some area")
            .expect("decodes cleanly");
        assert_eq!(joined.payload().unwrap(), b"aaabbbccc".to_vec());

        // A code that appears in no area yields None.
        assert!(parsed.concatenated_option(200).is_none());
    }
}

#[cfg(test)]
mod dhcp_rfc2132_base_options {
    use super::super::{
        Dhcp, DhcpMessageType, DhcpOption, DhcpOptionCode, DhcpOptionFormat, DhcpOptionKind,
        DhcpOptionValue, OptionOverload,
    };
    use super::typed_option_value;
    use crate::error::CrafterError;
    use core::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    // One representative option per RFC 2132 base format family, chosen to cover
    // both the historical typed subset and codes that were previously decoded
    // only as Generic opaque bytes. Each tuple is (code, logical value).
    fn family_samples() -> Vec<(u8, DhcpOptionValue)> {
        vec![
            // IPv4 single address (option 1, subnet mask).
            (1, DhcpOptionValue::Ipv4(ip(255, 255, 255, 0))),
            // IPv4 single address that was NOT in the old typed subset
            // (option 16, swap server; option 32, router solicitation).
            (16, DhcpOptionValue::Ipv4(ip(192, 0, 2, 9))),
            (32, DhcpOptionValue::Ipv4(ip(192, 0, 2, 7))),
            // IPv4 list (option 6, DNS) and a previously-Generic list
            // (option 42, NTP servers; option 44, NetBIOS name server).
            (
                6,
                DhcpOptionValue::Ipv4List(vec![ip(192, 0, 2, 53), ip(198, 51, 100, 53)]),
            ),
            (42, DhcpOptionValue::Ipv4List(vec![ip(192, 0, 2, 123)])),
            (
                44,
                DhcpOptionValue::Ipv4List(vec![ip(192, 0, 2, 200), ip(192, 0, 2, 201)]),
            ),
            // IPv4 address pairs (option 21 policy filter).
            (
                21,
                DhcpOptionValue::Ipv4Pairs(vec![(ip(192, 0, 2, 0), ip(255, 255, 255, 0))]),
            ),
            // Static routes (option 33) decode to typed destination/router
            // pairs (RFC 2132 section 5.8).
            (
                33,
                DhcpOptionValue::StaticRoutes(vec![
                    super::DhcpStaticRoute::new(ip(198, 51, 100, 0), ip(192, 0, 2, 1)),
                    super::DhcpStaticRoute::new(ip(203, 0, 113, 0), ip(192, 0, 2, 2)),
                ]),
            ),
            // Boolean flag bytes (option 19 IP forwarding, option 27 all subnets
            // local, option 39 TCP keepalive garbage) - a new format family.
            (19, DhcpOptionValue::Bool(true)),
            (27, DhcpOptionValue::Bool(false)),
            (39, DhcpOptionValue::Bool(true)),
            // Single unsigned octet (option 23 default IP TTL, option 46 NetBIOS
            // node type).
            (23, DhcpOptionValue::U8(64)),
            (46, DhcpOptionValue::U8(8)),
            // 16-bit unsigned (option 13 boot file size, option 22 max datagram
            // reassembly, option 26 interface MTU, option 57 max message size).
            (13, DhcpOptionValue::U16(1024)),
            (22, DhcpOptionValue::U16(576)),
            (26, DhcpOptionValue::U16(1500)),
            (57, DhcpOptionValue::U16(1400)),
            // 16-bit unsigned list (option 25 path MTU plateau table) - a new
            // format family.
            (25, DhcpOptionValue::U16List(vec![68, 296, 1500])),
            // 32-bit signed (option 2 time offset) - a new format family.
            (2, DhcpOptionValue::I32(-18_000)),
            // 32-bit unsigned (option 24 MTU aging, option 35 ARP timeout,
            // option 51 lease time).
            (24, DhcpOptionValue::U32(1_200)),
            (35, DhcpOptionValue::U32(60)),
            (51, DhcpOptionValue::U32(86_400)),
            // Text / NVT ASCII (option 12 host name, option 40 NIS domain,
            // option 56 message) - bytes preserved, never lossy.
            (12, DhcpOptionValue::Text(b"agent-host".to_vec())),
            (40, DhcpOptionValue::Text(b"corp.example".to_vec())),
            (56, DhcpOptionValue::Text(b"lease denied".to_vec())),
            // Parameter request list (option 55).
            (
                55,
                DhcpOptionValue::ParameterRequestList(vec![1, 3, 6, 15, 51, 54]),
            ),
            // Message type (option 53) and option overload (option 52).
            (53, DhcpOptionValue::MessageType(DhcpMessageType::Discover)),
            (52, DhcpOptionValue::OptionOverload(OptionOverload::Both)),
            // Opaque (option 60 vendor class id, option 61 client id, option 43
            // vendor specific) - raw bytes preserved.
            (60, DhcpOptionValue::Opaque(b"MSFT 5.0".to_vec())),
            (
                61,
                DhcpOptionValue::Opaque(vec![0x01, 0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]),
            ),
            (43, DhcpOptionValue::Opaque(vec![0xde, 0xad, 0xbe, 0xef])),
        ]
    }

    #[test]
    fn dhcp_rfc2132_base_options_cover_format_families() {
        // Every RFC 2132 base format family is represented, and every sample
        // decodes back to the exact logical value through the source-backed
        // format table - including options that were previously only opaque
        // Generic bytes.
        let samples = family_samples();

        // Prove the sample set spans every DhcpOptionFormat variant so no
        // family is left untested.
        use std::collections::HashSet;
        let covered: HashSet<DhcpOptionFormat> = samples
            .iter()
            .map(|(code, _)| {
                DhcpOptionKind::from_code(*code)
                    .expect("sample code is a registered base option")
                    .format()
            })
            .collect();
        let all_families = [
            DhcpOptionFormat::Ipv4,
            DhcpOptionFormat::Ipv4List,
            DhcpOptionFormat::Ipv4Pairs,
            DhcpOptionFormat::Bool,
            DhcpOptionFormat::U8,
            DhcpOptionFormat::U16,
            DhcpOptionFormat::U16List,
            DhcpOptionFormat::I32,
            DhcpOptionFormat::U32,
            DhcpOptionFormat::Text,
            DhcpOptionFormat::ParameterRequestList,
            DhcpOptionFormat::MessageType,
            DhcpOptionFormat::OptionOverload,
            DhcpOptionFormat::Opaque,
        ];
        for family in all_families {
            assert!(
                covered.contains(&family),
                "format family {family:?} is not exercised by the sample set",
            );
        }

        for (code, value) in samples {
            // The free typed-decode function and the option accessor agree.
            let payload = value.encode_payload();
            let decoded = typed_option_value(code, &payload)
                .unwrap()
                .unwrap_or_else(|| panic!("code {code} has no typed value"));
            assert_eq!(decoded, value, "typed decode mismatch for code {code}");

            // Constructed through the kind+value builder, the option re-decodes
            // to the same logical value and reports its registered kind.
            let kind = DhcpOptionKind::from_code(code).unwrap();
            assert_eq!(kind.code(), code);
            let option = DhcpOption::typed(kind, value.clone());
            assert_eq!(option.code(), code);
            assert_eq!(option.kind(), Some(kind));
            assert_eq!(option.typed_value().unwrap(), Some(value.clone()));

            // The codepoint is registry-classified, never RemovedOrUnassigned
            // for a base option.
            assert!(matches!(
                DhcpOptionCode::from_code(code),
                DhcpOptionCode::Assigned(_)
            ));
        }
    }

    #[test]
    fn dhcp_rfc2132_base_options_roundtrip() {
        // Every sample option survives a full compile -> decode -> compile cycle
        // inside a real DHCP packet without data loss, and the typed value is
        // recoverable from the decoded option in each area position.
        let samples = family_samples();
        let mut options: Vec<DhcpOption> = samples
            .iter()
            // Skip the overload sample here: option 52 changes how the sname/file
            // fields are interpreted, which is exercised by the overload tests.
            .filter(|(code, _)| *code != 52)
            .map(|(code, value)| {
                DhcpOption::typed(DhcpOptionKind::from_code(*code).unwrap(), value.clone())
            })
            .collect();
        options.push(DhcpOption::End);

        let dhcp = Dhcp::new()
            .op(super::super::BOOTP_REPLY)
            .options(options.clone());

        let bytes = crate::Packet::from_layer(dhcp)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let parsed = Dhcp::decode(&bytes).unwrap();

        // Exact byte round-trip: re-compiling the decoded packet reproduces the
        // wire bytes.
        let recompiled = crate::Packet::from_layer(parsed.clone())
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        assert_eq!(recompiled, bytes);

        // Each sample's typed value is recoverable from the decoded options.
        for (code, value) in samples.iter().filter(|(code, _)| *code != 52) {
            let option = parsed
                .options_value()
                .iter()
                .find(|o| o.code() == *code)
                .unwrap_or_else(|| panic!("option {code} present after decode"));
            assert_eq!(
                option.typed_value().unwrap(),
                Some(value.clone()),
                "typed value lost for code {code} after round-trip",
            );
        }

        // Text options preserve raw bytes and never force lossy UTF-8: a non-UTF-8
        // host name survives byte-for-byte.
        let raw_text = DhcpOption::typed(
            DhcpOptionKind::HostName,
            DhcpOptionValue::Text(vec![0xff, 0xfe, b'x']),
        );
        let dhcp = Dhcp::new().options([raw_text, DhcpOption::End]);
        let bytes = crate::Packet::from_layer(dhcp)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let parsed = Dhcp::decode(&bytes).unwrap();
        let host = parsed
            .options_value()
            .iter()
            .find(|o| o.code() == 12)
            .unwrap();
        assert_eq!(
            host.typed_value().unwrap(),
            Some(DhcpOptionValue::Text(vec![0xff, 0xfe, b'x'])),
        );
    }

    #[test]
    fn dhcp_rfc2132_base_options_reject_malformed_lengths() {
        // Format violations are structured errors, not panics: a boolean with a
        // bad octet, a too-short u32, an odd-length address list, and a non-pair
        // route length all surface as InvalidFieldValue.
        for (code, bad) in [
            (19u8, vec![2u8]),        // boolean octet must be 0/1
            (51, vec![0, 0, 1]),      // lease time must be 4 octets
            (6, vec![192, 0, 2]),     // address list must be a multiple of 4
            (33, vec![192, 0, 2, 1]), // static route must be a multiple of 8
            (25, vec![0]),            // u16 list must be a multiple of 2
        ] {
            let error = typed_option_value(code, &bad).unwrap_err();
            assert!(
                matches!(error, CrafterError::InvalidFieldValue { .. }),
                "code {code} should yield a structured field error",
            );
        }

        // Codes outside the RFC 2132 base set return Ok(None) so callers fall
        // back to raw-byte preservation.
        assert!(typed_option_value(224, &[0xde, 0xad]).unwrap().is_none());
        assert!(typed_option_value(82, &[0x01, 0x00]).unwrap().is_none());
    }
}

#[cfg(test)]
mod dhcp_route_domain_service {
    use super::super::{
        Dhcp, DhcpClasslessRoute, DhcpMessageType, DhcpOption, DhcpOptionKind, DhcpOptionValue,
        DhcpStaticRoute, SipServers,
    };
    use super::{
        decode_classless_routes, decode_domain_name_list, decode_static_routes,
        encode_classless_routes, encode_domain_name_list, encode_static_routes, typed_option_value,
    };
    use crate::error::CrafterError;
    use core::net::Ipv4Addr;

    const STATIC_ROUTE: u8 = super::super::DHCP_OPTION_STATIC_ROUTE; // 33
    const DOMAIN_SEARCH: u8 = super::super::DHCP_OPTION_DOMAIN_SEARCH; // 119
    const SIP_SERVERS: u8 = super::super::DHCP_OPTION_SIP_SERVERS; // 120
    const CLASSLESS_ROUTE: u8 = super::super::DHCP_OPTION_CLASSLESS_STATIC_ROUTE; // 121

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn build_and_decode(option: DhcpOption) -> Dhcp {
        let dhcp = Dhcp::new()
            .op(super::super::BOOTP_REPLY)
            .message_type(DhcpMessageType::Ack)
            .options([option, DhcpOption::End]);
        let bytes = crate::Packet::from_layer(dhcp)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        Dhcp::decode(&bytes).unwrap()
    }

    #[test]
    fn dhcp_classless_routes_roundtrip() {
        // RFC 3442: a /24 route carries three significant subnet octets, a /0
        // default route carries none, and a /32 host route carries four. Each
        // route is followed by a 4-octet router address.
        let routes = vec![
            DhcpClasslessRoute::new(24, ip(198, 51, 100, 0), ip(192, 0, 2, 1)),
            DhcpClasslessRoute::new(0, ip(0, 0, 0, 0), ip(192, 0, 2, 254)),
            DhcpClasslessRoute::new(32, ip(203, 0, 113, 7), ip(192, 0, 2, 9)),
            DhcpClasslessRoute::new(16, ip(172, 16, 0, 0), ip(192, 0, 2, 8)),
        ];
        let value = DhcpOptionValue::ClasslessRoutes(routes.clone());

        // Wire layout matches the RFC 3442 destination-descriptor encoding:
        // significant octets = ceil(prefix / 8).
        let payload = value.encode_payload();
        let expected: Vec<u8> = vec![
            24, 198, 51, 100, /* router */ 192, 0, 2, 1, // /24
            0, /* no subnet octets, router */ 192, 0, 2, 254, // /0
            32, 203, 0, 113, 7, /* router */ 192, 0, 2, 9, // /32
            16, 172, 16, /* router */ 192, 0, 2, 8, // /16
        ];
        assert_eq!(payload, expected);

        // typed decode reproduces the exact routes.
        let decoded = typed_option_value(CLASSLESS_ROUTE, &payload)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, value);
        assert_eq!(
            DhcpClasslessRoute::significant_octets(24),
            3,
            "ceil(24/8) significant octets",
        );

        // Full packet round-trip through the typed builder and the accessor.
        let option = DhcpOption::typed(DhcpOptionKind::ClasslessStaticRoute, value.clone());
        assert_eq!(option.code(), CLASSLESS_ROUTE);
        let parsed = build_and_decode(option);
        assert_eq!(parsed.classless_static_routes().unwrap().unwrap(), routes);

        // Re-compiling the decoded packet reproduces the wire bytes.
        let bytes = crate::Packet::from_layer(parsed.clone())
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let recompiled = crate::Packet::from_layer(Dhcp::decode(&bytes).unwrap())
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        assert_eq!(recompiled, bytes);

        // The raw decode/encode helpers round-trip directly as well.
        assert_eq!(decode_classless_routes(&payload).unwrap(), routes);
        assert_eq!(encode_classless_routes(&routes), payload);
    }

    #[test]
    fn dhcp_static_routes_roundtrip() {
        // RFC 2132 section 5.8: option 33 is destination/router IPv4 pairs.
        let routes = vec![
            DhcpStaticRoute::new(ip(198, 51, 100, 0), ip(192, 0, 2, 1)),
            DhcpStaticRoute::new(ip(203, 0, 113, 0), ip(192, 0, 2, 2)),
        ];
        let value = DhcpOptionValue::StaticRoutes(routes.clone());
        let payload = value.encode_payload();
        assert_eq!(payload.len(), routes.len() * 8);

        let decoded = typed_option_value(STATIC_ROUTE, &payload).unwrap().unwrap();
        assert_eq!(decoded, value);

        let option = DhcpOption::typed(DhcpOptionKind::StaticRoute, value);
        let parsed = build_and_decode(option);
        assert_eq!(parsed.static_routes().unwrap().unwrap(), routes);

        assert_eq!(decode_static_routes(&payload).unwrap(), routes);
        assert_eq!(encode_static_routes(&routes), payload);
    }

    #[test]
    fn dhcp_domain_search_roundtrip() {
        // RFC 3397 / RFC 1035: a domain-search list is label-encoded names, each
        // terminated by a zero root label.
        let names = vec!["eng.example.com".to_string(), "example.net".to_string()];
        let value = DhcpOptionValue::DomainSearch(names.clone());

        // The uncompressed encoding is a sequence of length-prefixed labels.
        let payload = value.encode_payload();
        let expected: Vec<u8> = {
            let mut bytes = Vec::new();
            for name in &names {
                for label in name.split('.') {
                    bytes.push(label.len() as u8);
                    bytes.extend_from_slice(label.as_bytes());
                }
                bytes.push(0);
            }
            bytes
        };
        assert_eq!(payload, expected);

        // typed decode reproduces the logical names.
        let decoded = typed_option_value(DOMAIN_SEARCH, &payload)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, value);

        // Full packet round-trip and accessor.
        let option = DhcpOption::typed(DhcpOptionKind::DomainSearch, value);
        let parsed = build_and_decode(option);
        assert_eq!(parsed.domain_search().unwrap().unwrap(), names);

        // The decoder resolves RFC 1035 compression pointers within the
        // aggregate data: "marketing.example.com" pointing back to "example.com"
        // from the first name (the RFC 3397 worked example shape).
        let mut compressed = Vec::new();
        compressed.extend_from_slice(&[3, b'e', b'n', b'g']); // offset 0: eng
        compressed.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']); // offset 4
        compressed.extend_from_slice(&[3, b'c', b'o', b'm', 0]); // offset 12
        let pointer_to_example = compressed.len(); // start of the second name
        compressed.extend_from_slice(&[9, b'm', b'a', b'r', b'k', b'e', b't', b'i', b'n', b'g']);
        // Compression pointer to offset 4 ("example.com").
        compressed.push(0xC0);
        compressed.push(4);
        let _ = pointer_to_example;
        let resolved = decode_domain_name_list("dhcp.option.domain_search", &compressed).unwrap();
        assert_eq!(
            resolved,
            vec![
                "eng.example.com".to_string(),
                "marketing.example.com".to_string(),
            ],
        );

        // Encoding names with a trailing dot (fully-qualified form) does not emit
        // a stray zero-length label.
        let fqdn = encode_domain_name_list(&["host.example.com.".to_string()]);
        assert_eq!(
            decode_domain_name_list("dhcp.option.domain_search", &fqdn).unwrap(),
            vec!["host.example.com".to_string()],
        );
    }

    #[test]
    fn dhcp_sip_servers_roundtrip_both_encodings() {
        // RFC 3361: enc=0 is a domain-name list, enc=1 is an IPv4 address list.
        let domains = SipServers::DomainNames(vec![
            "sip.example.com".to_string(),
            "sip.example.net".to_string(),
        ]);
        let domain_payload = DhcpOptionValue::SipServers(domains.clone()).encode_payload();
        assert_eq!(domain_payload[0], 0, "enc byte selects domain names");
        let decoded = typed_option_value(SIP_SERVERS, &domain_payload)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, DhcpOptionValue::SipServers(domains.clone()));

        let addresses = SipServers::Addresses(vec![ip(192, 0, 2, 10), ip(198, 51, 100, 10)]);
        let address_payload = DhcpOptionValue::SipServers(addresses.clone()).encode_payload();
        assert_eq!(address_payload[0], 1, "enc byte selects addresses");
        let decoded = typed_option_value(SIP_SERVERS, &address_payload)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, DhcpOptionValue::SipServers(addresses.clone()));

        // An unspecified enc value is preserved verbatim, not coerced.
        let unknown = typed_option_value(SIP_SERVERS, &[0x09, 0xde, 0xad])
            .unwrap()
            .unwrap();
        assert_eq!(
            unknown,
            DhcpOptionValue::SipServers(SipServers::Unknown {
                encoding: 0x09,
                data: vec![0xde, 0xad],
            }),
        );

        // Accessor surfaces the address-list encoding from a full packet.
        let option = DhcpOption::typed(
            DhcpOptionKind::SipServers,
            DhcpOptionValue::SipServers(addresses.clone()),
        );
        let parsed = build_and_decode(option);
        assert_eq!(parsed.sip_servers().unwrap().unwrap(), addresses);
    }

    #[test]
    fn dhcp_route_domain_service_malformed_inputs() {
        // Every malformed case is a structured error, never a panic.

        // RFC 3442 classless route: prefix length above 32 is invalid.
        let bad_prefix = [33u8, 10, 0, 0, 192, 0, 2, 1];
        assert!(matches!(
            decode_classless_routes(&bad_prefix),
            Err(CrafterError::InvalidFieldValue { field, .. }) if field == "dhcp.option.classless_static_route",
        ));

        // RFC 3442 classless route: a route truncated before its router address.
        // /24 needs 3 subnet octets + 4 router octets after the descriptor.
        let truncated_route = [24u8, 10, 0, 0, 192, 0]; // missing two router octets
        assert!(matches!(
            decode_classless_routes(&truncated_route),
            Err(CrafterError::BufferTooShort { .. }),
        ));
        // The same surfaces through typed_option_value without panicking.
        assert!(typed_option_value(CLASSLESS_ROUTE, &truncated_route).is_err());

        // RFC 2132 static route: length not a multiple of eight.
        assert!(matches!(
            decode_static_routes(&[192, 0, 2, 1, 192, 0, 2]),
            Err(CrafterError::InvalidFieldValue { field, .. }) if field == "dhcp.option.static_route",
        ));

        // RFC 3397 domain search: a label that runs past the end of the data.
        let truncated_label = [5u8, b'a', b'b']; // claims 5 bytes, only 2 follow
        assert!(matches!(
            decode_domain_name_list("dhcp.option.domain_search", &truncated_label),
            Err(CrafterError::BufferTooShort { .. }),
        ));

        // RFC 3397 domain search: a compression pointer past the end of the data.
        let bad_pointer = [0xC0u8, 0x40];
        assert!(matches!(
            decode_domain_name_list("dhcp.option.domain_search", &bad_pointer),
            Err(CrafterError::InvalidFieldValue { .. }),
        ));

        // RFC 3397 domain search: a self-referential pointer loop is rejected
        // rather than looping forever.
        let pointer_loop = [0xC0u8, 0x00];
        assert!(matches!(
            decode_domain_name_list("dhcp.option.domain_search", &pointer_loop),
            Err(CrafterError::InvalidFieldValue { .. }),
        ));

        // RFC 3361 SIP servers: empty payload (no enc byte).
        assert!(matches!(
            typed_option_value(SIP_SERVERS, &[]),
            Err(CrafterError::BufferTooShort { .. }),
        ));

        // RFC 3361 SIP servers: address encoding with a length that is not a
        // multiple of four after the enc byte.
        assert!(matches!(
            typed_option_value(SIP_SERVERS, &[1, 192, 0, 2]),
            Err(CrafterError::InvalidFieldValue { .. }),
        ));
    }
}
