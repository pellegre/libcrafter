//! DHCP option types and the option-area codec.

use core::net::Ipv4Addr;
use core::str;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};

use super::constants::{
    DHCP_AUTH_ALGORITHM_HMAC_MD5, DHCP_AUTH_HEADER_LEN, DHCP_AUTH_PROTOCOL_CONFIGURATION_TOKEN,
    DHCP_AUTH_PROTOCOL_DELAYED, DHCP_AUTH_PROTOCOL_RECONFIGURE_KEY,
    DHCP_AUTH_RDM_MONOTONIC_COUNTER, DHCP_AUTH_REPLAY_DETECTION_LEN, DHCP_CLIENT_ID_TYPE_NONE,
    DHCP_CLIENT_ID_TYPE_RFC4361, DHCP_CLIENT_MACHINE_UUID_TYPE, DHCP_CLIENT_NDI_TYPE_UNDI,
    DHCP_DATA_SOURCE_FLAG_REMOTE, DHCP_HTYPE_ETHERNET, DHCP_IAID_LEN,
    DHCP_OPTION_ALL_SUBNETS_LOCAL, DHCP_OPTION_ARP_CACHE_TIMEOUT, DHCP_OPTION_ASSOCIATED_IP,
    DHCP_OPTION_AUTHENTICATION, DHCP_OPTION_BASE_TIME, DHCP_OPTION_BOOTFILE_NAME,
    DHCP_OPTION_BOOT_FILE_SIZE, DHCP_OPTION_BROADCAST_ADDRESS, DHCP_OPTION_CAPTIVE_PORTAL,
    DHCP_OPTION_CLASSLESS_STATIC_ROUTE, DHCP_OPTION_CLIENT_IDENTIFIER,
    DHCP_OPTION_CLIENT_LAST_TRANSACTION_TIME, DHCP_OPTION_CLIENT_MACHINE_IDENTIFIER,
    DHCP_OPTION_CLIENT_NDI, DHCP_OPTION_CLIENT_SYSTEM_ARCHITECTURE, DHCP_OPTION_COOKIE_SERVER,
    DHCP_OPTION_DATA_SOURCE, DHCP_OPTION_DEFAULT_IP_TTL, DHCP_OPTION_DHCP_STATE,
    DHCP_OPTION_DOMAIN_NAME, DHCP_OPTION_DOMAIN_NAME_SERVER, DHCP_OPTION_DOMAIN_SEARCH,
    DHCP_OPTION_END, DHCP_OPTION_ETHERNET_ENCAPSULATION, DHCP_OPTION_EXTENSIONS_PATH,
    DHCP_OPTION_FORCERENEW_NONCE_CAPABLE, DHCP_OPTION_HOST_NAME, DHCP_OPTION_IMPRESS_SERVER,
    DHCP_OPTION_INTERFACE_MTU, DHCP_OPTION_IPV6_ONLY_PREFERRED, DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
    DHCP_OPTION_IP_FORWARDING, DHCP_OPTION_LOG_SERVER, DHCP_OPTION_LPR_SERVER,
    DHCP_OPTION_MASK_SUPPLIER, DHCP_OPTION_MAX_DATAGRAM_REASSEMBLY, DHCP_OPTION_MAX_MESSAGE_SIZE,
    DHCP_OPTION_MERIT_DUMP_FILE, DHCP_OPTION_MESSAGE, DHCP_OPTION_MESSAGE_TYPE,
    DHCP_OPTION_MUD_URL_V4, DHCP_OPTION_NAME_SERVER, DHCP_OPTION_NETBIOS_DATAGRAM_SERVER,
    DHCP_OPTION_NETBIOS_NAME_SERVER, DHCP_OPTION_NETBIOS_NODE_TYPE, DHCP_OPTION_NETBIOS_SCOPE,
    DHCP_OPTION_NIS_DOMAIN, DHCP_OPTION_NIS_SERVERS, DHCP_OPTION_NON_LOCAL_SOURCE_ROUTING,
    DHCP_OPTION_NTP_SERVERS, DHCP_OPTION_OVERLOAD, DHCP_OPTION_PAD,
    DHCP_OPTION_PARAMETER_REQUEST_LIST, DHCP_OPTION_PATH_MTU_AGING_TIMEOUT,
    DHCP_OPTION_PATH_MTU_PLATEAU_TABLE, DHCP_OPTION_PERFORM_MASK_DISCOVERY,
    DHCP_OPTION_PERFORM_ROUTER_DISCOVERY, DHCP_OPTION_POLICY_FILTER,
    DHCP_OPTION_PXELINUX_CONFIGFILE, DHCP_OPTION_PXELINUX_MAGIC, DHCP_OPTION_PXELINUX_PATHPREFIX,
    DHCP_OPTION_PXELINUX_REBOOTTIME, DHCP_OPTION_QUERY_END_TIME, DHCP_OPTION_QUERY_START_TIME,
    DHCP_OPTION_REBINDING_TIME, DHCP_OPTION_RELAY_AGENT_INFORMATION, DHCP_OPTION_RENEWAL_TIME,
    DHCP_OPTION_REQUESTED_IP_ADDRESS, DHCP_OPTION_RESOURCE_LOCATION_SERVER, DHCP_OPTION_ROOT_PATH,
    DHCP_OPTION_ROUTER, DHCP_OPTION_ROUTER_SOLICITATION_ADDRESS, DHCP_OPTION_SERVER_IDENTIFIER,
    DHCP_OPTION_SIP_SERVERS, DHCP_OPTION_START_TIME_OF_STATE, DHCP_OPTION_STATIC_ROUTE,
    DHCP_OPTION_STATUS_CODE, DHCP_OPTION_SUBNET_MASK, DHCP_OPTION_SWAP_SERVER,
    DHCP_OPTION_TCP_DEFAULT_TTL, DHCP_OPTION_TCP_KEEPALIVE_GARBAGE,
    DHCP_OPTION_TCP_KEEPALIVE_INTERVAL, DHCP_OPTION_TFTP_SERVER_ADDRESS,
    DHCP_OPTION_TFTP_SERVER_NAME, DHCP_OPTION_TIME_OFFSET, DHCP_OPTION_TIME_SERVER,
    DHCP_OPTION_TRAILER_ENCAPSULATION, DHCP_OPTION_USER_CLASS, DHCP_OPTION_VENDOR_CLASS_IDENTIFIER,
    DHCP_OPTION_VENDOR_SPECIFIC, DHCP_OPTION_VI_VENDOR_CLASS, DHCP_OPTION_VI_VENDOR_SPECIFIC,
    DHCP_OPTION_X_WINDOW_DISPLAY_MANAGER, DHCP_OPTION_X_WINDOW_FONT_SERVER, DHCP_OVERLOAD_BOTH,
    DHCP_OVERLOAD_FILE, DHCP_OVERLOAD_SNAME, DHCP_PXELINUX_MAGIC_VALUE,
    DHCP_RELAY_SUBOPTION_AUTHENTICATION, DHCP_RELAY_SUBOPTION_CIRCUIT_ID,
    DHCP_RELAY_SUBOPTION_DOCSIS_DEVICE_CLASS, DHCP_RELAY_SUBOPTION_LINK_SELECTION,
    DHCP_RELAY_SUBOPTION_RADIUS_ATTRIBUTES, DHCP_RELAY_SUBOPTION_RELAY_AGENT_ID,
    DHCP_RELAY_SUBOPTION_RELAY_FLAGS, DHCP_RELAY_SUBOPTION_RELAY_SOURCE_PORT,
    DHCP_RELAY_SUBOPTION_REMOTE_ID, DHCP_RELAY_SUBOPTION_SERVER_ID_OVERRIDE,
    DHCP_RELAY_SUBOPTION_SUBSCRIBER_ID, DHCP_RELAY_SUBOPTION_VENDOR_SPECIFIC,
    DHCP_RELAY_SUBOPTION_VSS, DHCP_RELAY_SUBOPTION_VSS_CONTROL, DHCP_STATE_ABANDONED,
    DHCP_STATE_ACTIVE, DHCP_STATE_AVAILABLE, DHCP_STATE_EXPIRED, DHCP_STATE_RELEASED,
    DHCP_STATE_REMOTE, DHCP_STATE_RESERVED, DHCP_STATE_RESET, DHCP_STATE_TRANSITIONING,
    DHCP_STATUS_CATCH_UP_COMPLETE, DHCP_STATUS_CONNECTION_ACTIVE, DHCP_STATUS_DATA_MISSING,
    DHCP_STATUS_MALFORMED_QUERY, DHCP_STATUS_NOT_ALLOWED, DHCP_STATUS_QUERY_TERMINATED,
    DHCP_STATUS_SUCCESS, DHCP_STATUS_TLS_CONNECTION_REFUSED, DHCP_STATUS_UNSPEC_FAIL,
    DHCP_VSS_TYPE_GLOBAL_DEFAULT, DHCP_VSS_TYPE_NVT_ASCII, DHCP_VSS_TYPE_VPN_ID,
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

/// An RFC 3004 User Class Data instance (option 77).
///
/// Source: RFC 3004 (errata-corrected). Option 77 carries one or more
/// length-prefixed opaque class values: each instance is a single `UC_Len`
/// octet (the number of data octets, which MUST be non-zero) followed by that
/// many opaque data octets. The data bytes are not interpreted by the codec, so
/// any vendor-defined contents are preserved verbatim. This type holds the raw
/// opaque class values; the length-prefix framing is applied on encode.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhcpUserClass {
    /// The opaque user-class data instances, in wire order. Each is preserved
    /// verbatim; the codec adds and removes the per-instance length octet.
    pub classes: Vec<Vec<u8>>,
}

impl DhcpUserClass {
    /// Create a user-class value from a list of opaque class instances.
    pub fn new(classes: impl Into<Vec<Vec<u8>>>) -> Self {
        Self {
            classes: classes.into(),
        }
    }
}

/// One RFC 4578 client system architecture type identifier (option 93).
///
/// Source: RFC 4578 section 2.1. Option 93 carries one or more 16-bit
/// big-endian architecture type values from the IANA "Processor Architecture
/// Types" registry (for example `0` Intel x86PC, `6` EFI IA32, `7` EFI BC,
/// `9` EFI x86-64). Unknown values are preserved verbatim as the raw `u16`, so
/// architectures not in the crate's snapshot still round-trip.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientSystemArchitecture {
    /// The 16-bit architecture type values in wire order.
    pub architectures: Vec<u16>,
}

impl ClientSystemArchitecture {
    /// Create a client-system-architecture value from a list of type values.
    pub fn new(architectures: impl Into<Vec<u16>>) -> Self {
        Self {
            architectures: architectures.into(),
        }
    }
}

/// An RFC 4578 client network device interface value (option 94).
///
/// Source: RFC 4578 section 2.2. Option 94 is exactly three octets: a `type`
/// octet (only value `1`, UNDI, is defined) followed by the interface's major
/// and minor revision octets. Unknown `type` values are preserved verbatim
/// rather than rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientNetworkDeviceInterface {
    /// Interface type octet (`1` = UNDI per RFC 4578).
    pub interface_type: u8,
    /// Major revision octet of the interface.
    pub major: u8,
    /// Minor revision octet of the interface.
    pub minor: u8,
}

impl ClientNetworkDeviceInterface {
    /// Create a client network device interface value.
    pub const fn new(interface_type: u8, major: u8, minor: u8) -> Self {
        Self {
            interface_type,
            major,
            minor,
        }
    }

    /// Create a UNDI (type `1`) interface value from major/minor revisions
    /// (RFC 4578 section 2.2).
    pub const fn undi(major: u8, minor: u8) -> Self {
        Self::new(DHCP_CLIENT_NDI_TYPE_UNDI, major, minor)
    }
}

/// A DHCPv4 Client-identifier option value (option 61).
///
/// Source: RFC 2132 section 9.14, RFC 4361 section 6.1, and RFC 6842. The
/// option is a one-octet `type` field followed by the client identifier. This
/// type models the three forms that appear on the wire without ever losing the
/// raw bytes:
///
/// - [`DhcpClientIdentifier::LegacyHardware`]: the RFC 2132 form, a hardware
///   type (an ARP hardware type per STD 2, for example `1` for Ethernet)
///   followed by a hardware address. With type `1` and a 6-octet address this
///   is the common Ethernet MAC client identifier.
/// - [`DhcpClientIdentifier::NodeSpecific`]: the RFC 4361 form, type `255`
///   followed by a 4-octet IAID and a variable-length DUID, giving a node a
///   stable identity across interfaces and across DHCPv4/DHCPv6.
/// - [`DhcpClientIdentifier::Raw`]: any other form (including type `0`
///   non-hardware identifiers such as a fully-qualified domain name, or
///   identifiers whose internal structure the codec does not interpret),
///   preserved verbatim including the type octet.
///
/// RFC 6842 requires a server to echo the option unaltered in its replies; the
/// crate models the option as packet data so a reply can carry exactly what the
/// client sent. This is a packet-field model, not lease policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DhcpClientIdentifier {
    /// RFC 2132 hardware-type identifier: an ARP hardware type octet followed by
    /// a hardware address (for example type `1` plus a 6-octet Ethernet MAC).
    LegacyHardware {
        /// ARP hardware type (STD 2), for example `1` for Ethernet.
        hardware_type: u8,
        /// The hardware address bytes, preserved verbatim.
        address: Vec<u8>,
    },
    /// RFC 4361 node-specific identifier: type `255`, a 4-octet IAID, and a DUID.
    NodeSpecific {
        /// The opaque 32-bit Identity Association Identifier (IAID).
        iaid: u32,
        /// The DHCP Unique Identifier (DUID) bytes, preserved verbatim.
        duid: Vec<u8>,
    },
    /// Any other identifier form, preserved verbatim including the type octet.
    Raw(Vec<u8>),
}

impl DhcpClientIdentifier {
    /// Create an RFC 2132 hardware-type identifier from a hardware type octet and
    /// hardware address bytes.
    pub fn legacy_hardware(hardware_type: u8, address: impl Into<Vec<u8>>) -> Self {
        Self::LegacyHardware {
            hardware_type,
            address: address.into(),
        }
    }

    /// Create an Ethernet (hardware type `1`) MAC client identifier from six
    /// address octets (RFC 2132 section 9.14).
    pub fn ethernet_mac(mac: [u8; 6]) -> Self {
        Self::LegacyHardware {
            hardware_type: DHCP_HTYPE_ETHERNET,
            address: mac.to_vec(),
        }
    }

    /// Create an RFC 4361 node-specific identifier from an IAID and DUID.
    ///
    /// Source: RFC 4361 section 6.1. The encoded option is the type octet `255`,
    /// the 4-octet IAID, then the DUID.
    pub fn node_specific(iaid: u32, duid: impl Into<Vec<u8>>) -> Self {
        Self::NodeSpecific {
            iaid,
            duid: duid.into(),
        }
    }

    /// Create a raw identifier preserved verbatim (including its type octet).
    pub fn raw(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Raw(bytes.into())
    }

    /// The option `type` octet this identifier encodes with (RFC 2132 / RFC
    /// 4361). Returns `None` for an empty [`DhcpClientIdentifier::Raw`], which
    /// carries no type octet.
    pub fn type_octet(&self) -> Option<u8> {
        match self {
            Self::LegacyHardware { hardware_type, .. } => Some(*hardware_type),
            Self::NodeSpecific { .. } => Some(DHCP_CLIENT_ID_TYPE_RFC4361),
            Self::Raw(bytes) => bytes.first().copied(),
        }
    }

    /// Encode this identifier to its option 61 payload bytes (the `type` octet
    /// and identifier, without the option code or length).
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::LegacyHardware {
                hardware_type,
                address,
            } => {
                let mut bytes = Vec::with_capacity(1 + address.len());
                bytes.push(*hardware_type);
                bytes.extend_from_slice(address);
                bytes
            }
            Self::NodeSpecific { iaid, duid } => {
                let mut bytes = Vec::with_capacity(1 + DHCP_IAID_LEN + duid.len());
                bytes.push(DHCP_CLIENT_ID_TYPE_RFC4361);
                bytes.extend_from_slice(&iaid.to_be_bytes());
                bytes.extend_from_slice(duid);
                bytes
            }
            Self::Raw(bytes) => bytes.clone(),
        }
    }
}

/// The RFC 3118 authentication Protocol field (option 90, first octet).
///
/// Source: RFC 3118 section 2 and the IANA "DHCP Authentication Protocols"
/// sub-registry. The Protocol field selects how the variable Authentication
/// Information is interpreted. Registered values are surfaced as named variants;
/// any unassigned or reserved value is preserved verbatim through
/// [`DhcpAuthProtocol::Unknown`] so no information is lost. This is a packet
/// field only: the crate never selects or runs an authentication protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhcpAuthProtocol {
    /// Configuration token protocol (value `0`, RFC 3118 section 4): the
    /// authentication information is an opaque shared token.
    ConfigurationToken,
    /// Delayed authentication protocol (value `1`, RFC 3118 section 5): the
    /// authentication information is a Secret ID plus a keyed hash.
    Delayed,
    /// Reconfigure Key protocol (value `3`), reused by RFC 6704 Forcerenew Nonce
    /// Authentication to carry a forcerenew nonce or its HMAC-MD5 digest.
    ReconfigureKey,
    /// Any other Protocol value, preserved verbatim.
    Unknown(u8),
}

impl DhcpAuthProtocol {
    /// Classify a raw Protocol octet (RFC 3118 section 2).
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCP_AUTH_PROTOCOL_CONFIGURATION_TOKEN => Self::ConfigurationToken,
            DHCP_AUTH_PROTOCOL_DELAYED => Self::Delayed,
            DHCP_AUTH_PROTOCOL_RECONFIGURE_KEY => Self::ReconfigureKey,
            other => Self::Unknown(other),
        }
    }

    /// Wire octet value for this Protocol.
    pub const fn code(self) -> u8 {
        match self {
            Self::ConfigurationToken => DHCP_AUTH_PROTOCOL_CONFIGURATION_TOKEN,
            Self::Delayed => DHCP_AUTH_PROTOCOL_DELAYED,
            Self::ReconfigureKey => DHCP_AUTH_PROTOCOL_RECONFIGURE_KEY,
            Self::Unknown(code) => code,
        }
    }
}

/// The RFC 3118 authentication Algorithm field (option 90, second octet).
///
/// Source: RFC 3118 sections 4 and 5.1 and the IANA "DHCP Authentication
/// Algorithm" sub-registry. The Algorithm value is interpreted relative to the
/// Protocol. The well-known value is HMAC-MD5 (`1`), used by the Delayed
/// Authentication protocol and by RFC 6704. Other values are preserved
/// verbatim through [`DhcpAuthAlgorithm::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhcpAuthAlgorithm {
    /// HMAC-MD5 generating function (value `1`, RFC 3118 section 5.1).
    HmacMd5,
    /// Any other Algorithm value, preserved verbatim (including the Protocol-0
    /// value `0`).
    Unknown(u8),
}

impl DhcpAuthAlgorithm {
    /// Classify a raw Algorithm octet (RFC 3118 section 5.1).
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCP_AUTH_ALGORITHM_HMAC_MD5 => Self::HmacMd5,
            other => Self::Unknown(other),
        }
    }

    /// Wire octet value for this Algorithm.
    pub const fn code(self) -> u8 {
        match self {
            Self::HmacMd5 => DHCP_AUTH_ALGORITHM_HMAC_MD5,
            Self::Unknown(code) => code,
        }
    }
}

/// The RFC 3118 authentication Replay Detection Method (RDM) field (option 90,
/// third octet).
///
/// Source: RFC 3118 section 2. The RDM names how the 64-bit Replay Detection
/// field is interpreted. RFC 3118 defines value `0`, a monotonically increasing
/// counter (NTP timestamps are recommended). Other values are preserved
/// verbatim through [`DhcpReplayDetectionMethod::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhcpReplayDetectionMethod {
    /// Monotonically increasing counter (value `0`, RFC 3118 section 2).
    MonotonicCounter,
    /// Any other RDM value, preserved verbatim.
    Unknown(u8),
}

impl DhcpReplayDetectionMethod {
    /// Classify a raw RDM octet (RFC 3118 section 2).
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCP_AUTH_RDM_MONOTONIC_COUNTER => Self::MonotonicCounter,
            other => Self::Unknown(other),
        }
    }

    /// Wire octet value for this RDM.
    pub const fn code(self) -> u8 {
        match self {
            Self::MonotonicCounter => DHCP_AUTH_RDM_MONOTONIC_COUNTER,
            Self::Unknown(code) => code,
        }
    }
}

/// An RFC 3118 DHCP Authentication option value (option 90).
///
/// Source: RFC 3118 section 2. The option is a fixed 11-octet header followed by
/// variable Authentication Information:
///
/// ```text
/// Code | Length | Protocol | Algorithm | RDM | Replay Detection (8) | Auth Info...
/// ```
///
/// This type models each header field as a typed value and preserves the
/// Authentication Information as raw bytes, because its structure depends on the
/// Protocol (for the Delayed Authentication protocol it is a 4-octet Secret ID
/// plus a keyed hash; for RFC 6704 it is a Type octet plus a 128-bit value).
/// The crate models these as packet data only: it never derives, signs,
/// verifies, or looks up keys or secrets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhcpAuthentication {
    /// Authentication Protocol (RFC 3118 section 2, first octet).
    pub protocol: DhcpAuthProtocol,
    /// Authentication Algorithm (RFC 3118 section 2, second octet).
    pub algorithm: DhcpAuthAlgorithm,
    /// Replay Detection Method (RFC 3118 section 2, third octet).
    pub rdm: DhcpReplayDetectionMethod,
    /// The 64-bit Replay Detection field (RFC 3118 section 2). For RDM `0` this
    /// is a monotonically increasing counter value.
    pub replay_detection: u64,
    /// Authentication Information bytes, preserved verbatim. The internal layout
    /// depends on the Protocol and is not interpreted by the codec.
    pub authentication_information: Vec<u8>,
}

impl DhcpAuthentication {
    /// Create an authentication option value from its typed header fields and the
    /// raw authentication information bytes.
    pub fn new(
        protocol: DhcpAuthProtocol,
        algorithm: DhcpAuthAlgorithm,
        rdm: DhcpReplayDetectionMethod,
        replay_detection: u64,
        authentication_information: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            protocol,
            algorithm,
            rdm,
            replay_detection,
            authentication_information: authentication_information.into(),
        }
    }

    /// Encode this authentication option to its option 90 payload bytes (the
    /// header fields followed by the authentication information, without the
    /// option code or length byte).
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(DHCP_AUTH_HEADER_LEN + self.authentication_information.len());
        bytes.push(self.protocol.code());
        bytes.push(self.algorithm.code());
        bytes.push(self.rdm.code());
        bytes.extend_from_slice(&self.replay_detection.to_be_bytes());
        bytes.extend_from_slice(&self.authentication_information);
        bytes
    }
}

/// An RFC 6704 FORCERENEW_NONCE_CAPABLE option value (option 145).
///
/// Source: RFC 6704 section 4. The option carries the list of authentication
/// algorithms a client supports for Forcerenew Nonce Authentication, one
/// algorithm per octet:
///
/// ```text
/// Code (145) | Len (n) | A1 | A2 | A3 | ...
/// ```
///
/// The algorithm octets are preserved verbatim so unspecified values still
/// round-trip. This is packet data only; the crate does not negotiate or run an
/// algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct DhcpForcerenewNonceCapable {
    /// The supported authentication algorithm identifiers, one per octet
    /// (RFC 6704 section 4). HMAC-MD5 is value `1`.
    pub algorithms: Vec<u8>,
}

impl DhcpForcerenewNonceCapable {
    /// Create a FORCERENEW_NONCE_CAPABLE value from a list of algorithm octets.
    pub fn new(algorithms: impl Into<Vec<u8>>) -> Self {
        Self {
            algorithms: algorithms.into(),
        }
    }

    /// Create a FORCERENEW_NONCE_CAPABLE value advertising HMAC-MD5 (algorithm
    /// `1`, RFC 6704 section 4).
    pub fn hmac_md5() -> Self {
        Self {
            algorithms: vec![DHCP_AUTH_ALGORITHM_HMAC_MD5],
        }
    }

    /// Encode this value to its option 145 payload bytes (the algorithm octets,
    /// without the option code or length byte).
    pub fn encode(&self) -> Vec<u8> {
        self.algorithms.clone()
    }
}

/// A DHCP leasequery status code (option 151, first octet).
///
/// Source: RFC 6926 section 6.2.2 and the IANA "DHCP Status Code Type 151
/// Values" sub-registry (XML retrieved 2026-05-29). The status octet conveys
/// the result of a (bulk) leasequery. Registered values are surfaced as named
/// variants; any unassigned value is preserved verbatim through
/// [`DhcpStatusCode::Unknown`] so no information is lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhcpStatusCode {
    /// Success (value `0`, RFC 6926).
    Success,
    /// UnspecFail (value `1`, RFC 6926).
    UnspecFail,
    /// QueryTerminated (value `2`, RFC 6926).
    QueryTerminated,
    /// MalformedQuery (value `3`, RFC 6926).
    MalformedQuery,
    /// NotAllowed (value `4`, RFC 6926).
    NotAllowed,
    /// DataMissing (value `5`, RFC 7724).
    DataMissing,
    /// ConnectionActive (value `6`, RFC 7724).
    ConnectionActive,
    /// CatchUpComplete (value `7`, RFC 7724).
    CatchUpComplete,
    /// TLSConnectionRefused (value `8`, RFC 7724).
    TlsConnectionRefused,
    /// Any other status value, preserved verbatim.
    Unknown(u8),
}

impl DhcpStatusCode {
    /// Classify a raw status octet (RFC 6926 section 6.2.2).
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCP_STATUS_SUCCESS => Self::Success,
            DHCP_STATUS_UNSPEC_FAIL => Self::UnspecFail,
            DHCP_STATUS_QUERY_TERMINATED => Self::QueryTerminated,
            DHCP_STATUS_MALFORMED_QUERY => Self::MalformedQuery,
            DHCP_STATUS_NOT_ALLOWED => Self::NotAllowed,
            DHCP_STATUS_DATA_MISSING => Self::DataMissing,
            DHCP_STATUS_CONNECTION_ACTIVE => Self::ConnectionActive,
            DHCP_STATUS_CATCH_UP_COMPLETE => Self::CatchUpComplete,
            DHCP_STATUS_TLS_CONNECTION_REFUSED => Self::TlsConnectionRefused,
            other => Self::Unknown(other),
        }
    }

    /// Wire octet value for this status code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => DHCP_STATUS_SUCCESS,
            Self::UnspecFail => DHCP_STATUS_UNSPEC_FAIL,
            Self::QueryTerminated => DHCP_STATUS_QUERY_TERMINATED,
            Self::MalformedQuery => DHCP_STATUS_MALFORMED_QUERY,
            Self::NotAllowed => DHCP_STATUS_NOT_ALLOWED,
            Self::DataMissing => DHCP_STATUS_DATA_MISSING,
            Self::ConnectionActive => DHCP_STATUS_CONNECTION_ACTIVE,
            Self::CatchUpComplete => DHCP_STATUS_CATCH_UP_COMPLETE,
            Self::TlsConnectionRefused => DHCP_STATUS_TLS_CONNECTION_REFUSED,
            Self::Unknown(code) => code,
        }
    }
}

/// A DHCP status-code option value (option 151).
///
/// Source: RFC 6926 section 6.2.2. The option is a one-octet status code
/// followed by an optional UTF-8-encoded status message with no termination or
/// null characters:
///
/// ```text
/// Code (151) | Len (n+1) | status | s1 | s2 | ... | sn
/// ```
///
/// The status octet is decoded into a typed [`DhcpStatusCode`] (unknown values
/// preserved verbatim) and the message bytes are kept raw, because the text is
/// not guaranteed to be valid UTF-8 in arbitrary captures. Use
/// [`DhcpStatusCodeOption::message_lossy`] for a convenience string view.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhcpStatusCodeOption {
    /// The leasequery status code (RFC 6926 section 6.2.2, first octet).
    pub status: DhcpStatusCode,
    /// The optional status message bytes, preserved verbatim (RFC 6926 says the
    /// message is UTF-8 with no termination or null characters, but captured
    /// bytes are kept raw rather than forced through a lossy decode).
    pub message: Vec<u8>,
}

impl DhcpStatusCodeOption {
    /// Create a status-code value from a typed status and raw message bytes.
    pub fn new(status: DhcpStatusCode, message: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    /// Lossy UTF-8 view of the status message, preserving the raw bytes.
    pub fn message_lossy(&self) -> String {
        String::from_utf8_lossy(&self.message).into_owned()
    }

    /// Encode this value to its option 151 payload bytes (the status octet
    /// followed by the message, without the option code or length byte).
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.message.len());
        bytes.push(self.status.code());
        bytes.extend_from_slice(&self.message);
        bytes
    }
}

/// A DHCP IP-address binding state (option 156, State octet).
///
/// Source: RFC 6926 section 6.2.7 and the IANA "DHCP State Type 156 Values"
/// sub-registry (XML retrieved 2026-05-29). Registered values are surfaced as
/// named variants; any unassigned value is preserved verbatim through
/// [`DhcpState::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhcpState {
    /// Reserved (value `0`, RFC 6926).
    Reserved,
    /// AVAILABLE (value `1`, RFC 6926).
    Available,
    /// ACTIVE (value `2`, RFC 6926).
    Active,
    /// EXPIRED (value `3`, RFC 6926).
    Expired,
    /// RELEASED (value `4`, RFC 6926).
    Released,
    /// ABANDONED (value `5`, RFC 6926).
    Abandoned,
    /// RESET (value `6`, RFC 6926).
    Reset,
    /// REMOTE (value `7`, RFC 6926).
    Remote,
    /// TRANSITIONING (value `8`, RFC 6926).
    Transitioning,
    /// Any other state value, preserved verbatim.
    Unknown(u8),
}

impl DhcpState {
    /// Classify a raw State octet (RFC 6926 section 6.2.7).
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCP_STATE_RESERVED => Self::Reserved,
            DHCP_STATE_AVAILABLE => Self::Available,
            DHCP_STATE_ACTIVE => Self::Active,
            DHCP_STATE_EXPIRED => Self::Expired,
            DHCP_STATE_RELEASED => Self::Released,
            DHCP_STATE_ABANDONED => Self::Abandoned,
            DHCP_STATE_RESET => Self::Reset,
            DHCP_STATE_REMOTE => Self::Remote,
            DHCP_STATE_TRANSITIONING => Self::Transitioning,
            other => Self::Unknown(other),
        }
    }

    /// Wire octet value for this state.
    pub const fn code(self) -> u8 {
        match self {
            Self::Reserved => DHCP_STATE_RESERVED,
            Self::Available => DHCP_STATE_AVAILABLE,
            Self::Active => DHCP_STATE_ACTIVE,
            Self::Expired => DHCP_STATE_EXPIRED,
            Self::Released => DHCP_STATE_RELEASED,
            Self::Abandoned => DHCP_STATE_ABANDONED,
            Self::Reset => DHCP_STATE_RESET,
            Self::Remote => DHCP_STATE_REMOTE,
            Self::Transitioning => DHCP_STATE_TRANSITIONING,
            Self::Unknown(code) => code,
        }
    }
}

/// A DHCP data-source option value (option 157, Flags octet).
///
/// Source: RFC 6926 section 6.2.8. The option is a single Flags octet whose
/// least-significant bit is the REMOTE flag (`R`): set means the binding data
/// came from a remote server, clear means it came from the local server. The
/// remaining bits (the `UNA` field) are unassigned and MUST be ignored, but
/// they are preserved verbatim here so the octet round-trips exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DhcpDataSource {
    /// The raw Flags octet (RFC 6926 section 6.2.8), preserved verbatim.
    pub flags: u8,
}

impl DhcpDataSource {
    /// Create a data-source value from a raw Flags octet.
    pub const fn new(flags: u8) -> Self {
        Self { flags }
    }

    /// Create a data-source value with only the REMOTE (`R`) flag set or clear.
    pub const fn from_remote(remote: bool) -> Self {
        Self {
            flags: if remote {
                DHCP_DATA_SOURCE_FLAG_REMOTE
            } else {
                0
            },
        }
    }

    /// Whether the REMOTE (`R`) flag is set: the data came from a remote server
    /// (RFC 6926 section 6.2.8). A clear flag means the local server.
    pub const fn is_remote(self) -> bool {
        self.flags & DHCP_DATA_SOURCE_FLAG_REMOTE != 0
    }

    /// Encode this value to its option 157 payload byte (the Flags octet,
    /// without the option code or length byte).
    pub fn encode(self) -> Vec<u8> {
        vec![self.flags]
    }
}

/// An RFC 4578 UUID/GUID-based client machine identifier (option 97).
///
/// Source: RFC 4578 section 2.3. Option 97 is a `type` octet followed by the
/// machine identifier. The only defined type is `0`, which introduces a
/// 16-octet GUID (total option length 17). The `type` octet and identifier
/// bytes are preserved verbatim so non-zero types and non-16-octet identifiers
/// still round-trip.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhcpClientUuid {
    /// Identifier type octet (`0` = GUID per RFC 4578).
    pub identifier_type: u8,
    /// The machine identifier bytes (a 16-octet GUID for type `0`).
    pub identifier: Vec<u8>,
}

impl DhcpClientUuid {
    /// Create a client machine identifier value from a type and identifier.
    pub fn new(identifier_type: u8, identifier: impl Into<Vec<u8>>) -> Self {
        Self {
            identifier_type,
            identifier: identifier.into(),
        }
    }

    /// Create a type-`0` GUID client identifier from a 16-octet GUID.
    pub fn guid(guid: impl Into<Vec<u8>>) -> Self {
        Self::new(DHCP_CLIENT_MACHINE_UUID_TYPE, guid)
    }
}

/// One RFC 3925 V-I Vendor Class data instance (option 124).
///
/// Source: RFC 3925 section 3. Option 124 carries one or more vendor instances,
/// each a 4-octet IANA Enterprise Number, a one-octet `data-len`, and that many
/// opaque vendor-class-data octets. The data bytes are vendor-defined and are
/// preserved verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhcpVendorClassData {
    /// The vendor's 32-bit IANA Enterprise Number.
    pub enterprise_number: u32,
    /// Opaque vendor-class data, preserved verbatim.
    pub data: Vec<u8>,
}

impl DhcpVendorClassData {
    /// Create a V-I vendor-class instance from an enterprise number and data.
    pub fn new(enterprise_number: u32, data: impl Into<Vec<u8>>) -> Self {
        Self {
            enterprise_number,
            data: data.into(),
        }
    }
}

/// One RFC 3925 V-I Vendor-Specific suboption inside option 125's option-data.
///
/// Source: RFC 3925 section 4. Within a vendor instance's `option-data`, the
/// vendor-specific information is a sequence of suboptions, each a one-octet
/// `subopt-code`, a one-octet `subopt-len`, and that many opaque data octets.
/// The suboption code space is vendor-defined, so the data is opaque to the
/// codec and preserved verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhcpVendorSuboption {
    /// Vendor-defined suboption code.
    pub code: u8,
    /// Opaque suboption data, preserved verbatim.
    pub data: Vec<u8>,
}

impl DhcpVendorSuboption {
    /// Create a vendor suboption from a code and opaque data.
    pub fn new(code: u8, data: impl Into<Vec<u8>>) -> Self {
        Self {
            code,
            data: data.into(),
        }
    }
}

/// One RFC 3925 V-I Vendor-Specific Information instance (option 125).
///
/// Source: RFC 3925 section 4. Option 125 carries one or more vendor instances,
/// each a 4-octet IANA Enterprise Number, a one-octet `data-len`, and that many
/// octets of `option-data`. The option-data is itself a sequence of
/// [`DhcpVendorSuboption`] code/length/value triples (nested TLVs). Because the
/// suboption code space is vendor-defined and known only by the vendor class,
/// the suboption payloads stay opaque.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhcpVendorIdentifyingOption {
    /// The vendor's 32-bit IANA Enterprise Number.
    pub enterprise_number: u32,
    /// The vendor-defined nested suboptions carried in this instance.
    pub suboptions: Vec<DhcpVendorSuboption>,
}

impl DhcpVendorIdentifyingOption {
    /// Create a V-I vendor-specific instance from an enterprise number and
    /// nested suboptions.
    pub fn new(enterprise_number: u32, suboptions: impl Into<Vec<DhcpVendorSuboption>>) -> Self {
        Self {
            enterprise_number,
            suboptions: suboptions.into(),
        }
    }
}

/// One vendor tuple inside the RFC 4243 relay-agent Vendor-Specific Information
/// sub-option (relay sub-option 9).
///
/// Source: RFC 4243 section 4. The sub-option carries one or more tuples, each a
/// 4-octet IANA Enterprise Number, a one-octet data length, and that many opaque
/// vendor-defined octets. The data bytes are vendor-defined and preserved
/// verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhcpRelayVendorSpecific {
    /// The vendor's 32-bit IANA Enterprise Number.
    pub enterprise_number: u32,
    /// Opaque vendor-defined data, preserved verbatim.
    pub data: Vec<u8>,
}

impl DhcpRelayVendorSpecific {
    /// Create a relay vendor-specific tuple from an enterprise number and data.
    pub fn new(enterprise_number: u32, data: impl Into<Vec<u8>>) -> Self {
        Self {
            enterprise_number,
            data: data.into(),
        }
    }
}

/// An RFC 6607 Virtual Subnet Selection (VSS) value carried by relay
/// sub-option 151 (and reused by DHCP VSS options).
///
/// Source: RFC 6607 section 4. The value is a one-octet `Type` followed by
/// type-specific VSS Information: type `0` is an NVT ASCII VPN identifier, type
/// `1` is a 7-octet RFC 2685 VPN-ID, and type `255` selects the global default
/// VPN with no following information. The `type` octet and the information bytes
/// are preserved verbatim so unspecified types still round-trip.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhcpVssInfo {
    /// VSS type octet (`0` NVT ASCII, `1` RFC 2685 VPN-ID, `255` global default).
    pub vss_type: u8,
    /// Type-specific VSS information bytes, preserved verbatim.
    pub information: Vec<u8>,
}

impl DhcpVssInfo {
    /// Create a VSS value from a type octet and information bytes.
    pub fn new(vss_type: u8, information: impl Into<Vec<u8>>) -> Self {
        Self {
            vss_type,
            information: information.into(),
        }
    }

    /// Create a type-`0` NVT ASCII VPN identifier VSS value.
    pub fn nvt_ascii(identifier: impl Into<Vec<u8>>) -> Self {
        Self::new(DHCP_VSS_TYPE_NVT_ASCII, identifier)
    }

    /// Create a type-`1` RFC 2685 VPN-ID VSS value (7 octets).
    pub fn vpn_id(vpn_id: impl Into<Vec<u8>>) -> Self {
        Self::new(DHCP_VSS_TYPE_VPN_ID, vpn_id)
    }

    /// Create a type-`255` global default VSS value with no information.
    pub fn global_default() -> Self {
        Self::new(DHCP_VSS_TYPE_GLOBAL_DEFAULT, Vec::new())
    }
}

/// One sub-option of the RFC 3046 Relay Agent Information option (option 82).
///
/// Source: RFC 3046 section 2 and the IANA "DHCP Relay Agent Sub-Option Codes"
/// registry (last updated 2026-05-29). Each sub-option is a code/length/value
/// triple. Registered sub-options whose wire format is specified are decoded
/// into typed variants; codes without a single authoritative typed format, and
/// unknown or reserved codes, are preserved verbatim through
/// [`DhcpRelaySuboption::Other`] so no bytes are lost.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DhcpRelaySuboption {
    /// Agent Circuit ID (sub-option 1, RFC 3046): opaque relay-defined bytes.
    CircuitId(Vec<u8>),
    /// Agent Remote ID (sub-option 2, RFC 3046): opaque relay-defined bytes.
    RemoteId(Vec<u8>),
    /// DOCSIS Device Class (sub-option 4, RFC 3256): a 32-bit class bitfield.
    DocsisDeviceClass(u32),
    /// Link Selection (sub-option 5, RFC 3527): a 4-octet subnet IPv4 address.
    LinkSelection(Ipv4Addr),
    /// Subscriber-ID (sub-option 6, RFC 3993): opaque NVT ASCII bytes.
    SubscriberId(Vec<u8>),
    /// RADIUS Attributes (sub-option 7, RFC 4014): concatenated RADIUS
    /// attributes, preserved verbatim because their format is RADIUS-defined.
    RadiusAttributes(Vec<u8>),
    /// Authentication (sub-option 8, RFC 4030): an RFC 3118-style authentication
    /// payload, preserved verbatim.
    Authentication(Vec<u8>),
    /// Vendor-Specific Information (sub-option 9, RFC 4243): one or more
    /// enterprise-number plus opaque-data tuples.
    VendorSpecific(Vec<DhcpRelayVendorSpecific>),
    /// Relay Agent Flags (sub-option 10, RFC 5010): a one-octet flags field
    /// (bit 0 / `0x80` is the Unicast flag).
    RelayFlags(u8),
    /// Server Identifier Override (sub-option 11, RFC 5107): a 4-octet IPv4
    /// address overriding the server identifier.
    ServerIdOverride(Ipv4Addr),
    /// Relay Agent Identifier (sub-option 12, RFC 6925): opaque relay-defined
    /// bytes.
    RelayAgentId(Vec<u8>),
    /// DHCPv4 Relay Source Port (sub-option 19, RFC 8357): a zero-length flag
    /// signalling the relay uses a non-`67` UDP source port. The actual port is
    /// learned from the UDP header, so this sub-option carries no value.
    RelaySourcePort,
    /// Virtual Subnet Selection (sub-option 151, RFC 6607): a type octet plus
    /// VSS information.
    Vss(DhcpVssInfo),
    /// Virtual Subnet Selection Control (sub-option 152, RFC 6607): a
    /// zero-length control sub-option.
    VssControl,
    /// Any sub-option without a single authoritative typed format, or an
    /// unknown/reserved code, preserved as raw code and data bytes.
    Other {
        /// Sub-option code.
        code: u8,
        /// Sub-option data bytes (after code and length), preserved verbatim.
        data: Vec<u8>,
    },
}

impl DhcpRelaySuboption {
    /// Create an Agent Circuit ID sub-option (sub-option 1, RFC 3046).
    pub fn circuit_id(data: impl Into<Vec<u8>>) -> Self {
        Self::CircuitId(data.into())
    }

    /// Create an Agent Remote ID sub-option (sub-option 2, RFC 3046).
    pub fn remote_id(data: impl Into<Vec<u8>>) -> Self {
        Self::RemoteId(data.into())
    }

    /// Create a Subscriber-ID sub-option (sub-option 6, RFC 3993).
    pub fn subscriber_id(data: impl Into<Vec<u8>>) -> Self {
        Self::SubscriberId(data.into())
    }

    /// Create a Relay Agent Identifier sub-option (sub-option 12, RFC 6925).
    pub fn relay_agent_id(data: impl Into<Vec<u8>>) -> Self {
        Self::RelayAgentId(data.into())
    }

    /// Create a sub-option from a raw code and data bytes, preserving the code
    /// and payload verbatim.
    pub fn other(code: u8, data: impl Into<Vec<u8>>) -> Self {
        Self::Other {
            code,
            data: data.into(),
        }
    }

    /// Wire codepoint of this sub-option.
    pub const fn code(&self) -> u8 {
        match self {
            Self::CircuitId(_) => DHCP_RELAY_SUBOPTION_CIRCUIT_ID,
            Self::RemoteId(_) => DHCP_RELAY_SUBOPTION_REMOTE_ID,
            Self::DocsisDeviceClass(_) => DHCP_RELAY_SUBOPTION_DOCSIS_DEVICE_CLASS,
            Self::LinkSelection(_) => DHCP_RELAY_SUBOPTION_LINK_SELECTION,
            Self::SubscriberId(_) => DHCP_RELAY_SUBOPTION_SUBSCRIBER_ID,
            Self::RadiusAttributes(_) => DHCP_RELAY_SUBOPTION_RADIUS_ATTRIBUTES,
            Self::Authentication(_) => DHCP_RELAY_SUBOPTION_AUTHENTICATION,
            Self::VendorSpecific(_) => DHCP_RELAY_SUBOPTION_VENDOR_SPECIFIC,
            Self::RelayFlags(_) => DHCP_RELAY_SUBOPTION_RELAY_FLAGS,
            Self::ServerIdOverride(_) => DHCP_RELAY_SUBOPTION_SERVER_ID_OVERRIDE,
            Self::RelayAgentId(_) => DHCP_RELAY_SUBOPTION_RELAY_AGENT_ID,
            Self::RelaySourcePort => DHCP_RELAY_SUBOPTION_RELAY_SOURCE_PORT,
            Self::Vss(_) => DHCP_RELAY_SUBOPTION_VSS,
            Self::VssControl => DHCP_RELAY_SUBOPTION_VSS_CONTROL,
            Self::Other { code, .. } => *code,
        }
    }

    /// Encode this sub-option's value bytes (after the code and length octets).
    fn encode_value(&self) -> Vec<u8> {
        match self {
            Self::CircuitId(data)
            | Self::RemoteId(data)
            | Self::SubscriberId(data)
            | Self::RadiusAttributes(data)
            | Self::Authentication(data)
            | Self::RelayAgentId(data)
            | Self::Other { data, .. } => data.clone(),
            Self::DocsisDeviceClass(value) => value.to_be_bytes().to_vec(),
            Self::LinkSelection(address) | Self::ServerIdOverride(address) => {
                address.octets().to_vec()
            }
            Self::VendorSpecific(tuples) => encode_relay_vendor_specific(tuples),
            Self::RelayFlags(flags) => vec![*flags],
            Self::RelaySourcePort | Self::VssControl => Vec::new(),
            Self::Vss(vss) => {
                let mut bytes = Vec::with_capacity(1 + vss.information.len());
                bytes.push(vss.vss_type);
                bytes.extend_from_slice(&vss.information);
                bytes
            }
        }
    }
}

/// The RFC 3046 Relay Agent Information option (option 82).
///
/// Source: RFC 3046 section 2. The option is a container for a sequence of
/// relay-agent sub-options. There is no pad sub-option and the field is not
/// terminated with an end marker; the option length bounds the sub-options.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct DhcpRelayAgentInfo {
    /// The relay-agent sub-options carried in this option, in wire order.
    pub suboptions: Vec<DhcpRelaySuboption>,
}

impl DhcpRelayAgentInfo {
    /// Create a relay agent information value from a list of sub-options.
    pub fn new(suboptions: impl Into<Vec<DhcpRelaySuboption>>) -> Self {
        Self {
            suboptions: suboptions.into(),
        }
    }

    /// Append a sub-option and return the updated value (builder style).
    pub fn with(mut self, suboption: DhcpRelaySuboption) -> Self {
        self.suboptions.push(suboption);
        self
    }

    /// First sub-option with the given code, when present.
    pub fn suboption(&self, code: u8) -> Option<&DhcpRelaySuboption> {
        self.suboptions.iter().find(|sub| sub.code() == code)
    }
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
    /// An RFC 3004 user-class value (option 77): one or more length-prefixed
    /// opaque class instances.
    UserClass(DhcpUserClass),
    /// An RFC 4578 client system architecture list (option 93): 16-bit type
    /// values.
    ClientSystemArchitecture(ClientSystemArchitecture),
    /// An RFC 4578 client network device interface value (option 94).
    ClientNetworkDeviceInterface(ClientNetworkDeviceInterface),
    /// An RFC 4578 UUID/GUID-based client machine identifier (option 97).
    ClientUuid(DhcpClientUuid),
    /// An RFC 3925 V-I Vendor Class value (option 124): one or more
    /// enterprise-number plus opaque vendor-class-data instances.
    ViVendorClass(Vec<DhcpVendorClassData>),
    /// An RFC 3925 V-I Vendor-Specific Information value (option 125): one or
    /// more enterprise-number instances each carrying nested suboptions.
    ViVendorSpecific(Vec<DhcpVendorIdentifyingOption>),
    /// An RFC 3046 Relay Agent Information value (option 82): a sequence of
    /// relay-agent sub-options.
    RelayAgentInformation(DhcpRelayAgentInfo),
    /// A DHCPv4 Client-identifier value (option 61): an RFC 2132 hardware-type
    /// identifier, an RFC 4361 IAID+DUID identifier, or a raw identifier.
    ClientIdentifier(DhcpClientIdentifier),
    /// An RFC 3118 Authentication value (option 90): typed Protocol, Algorithm,
    /// RDM, and Replay Detection header fields plus raw authentication
    /// information.
    Authentication(DhcpAuthentication),
    /// An RFC 6704 FORCERENEW_NONCE_CAPABLE value (option 145): the list of
    /// supported authentication algorithm octets.
    ForcerenewNonceCapable(DhcpForcerenewNonceCapable),
    /// An RFC 6926 leasequery status-code value (option 151): a typed status
    /// octet plus an optional raw status message.
    StatusCode(DhcpStatusCodeOption),
    /// An RFC 6926 dhcp-state value (option 156): a typed IP-address binding
    /// state octet.
    DhcpState(DhcpState),
    /// An RFC 6926 data-source value (option 157): the Flags octet, including
    /// the REMOTE (`R`) flag.
    DataSource(DhcpDataSource),
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
            Self::UserClass(user_class) => encode_user_class(user_class),
            Self::ClientSystemArchitecture(arch) => encode_client_system_architecture(arch),
            Self::ClientNetworkDeviceInterface(ndi) => {
                vec![ndi.interface_type, ndi.major, ndi.minor]
            }
            Self::ClientUuid(uuid) => encode_client_uuid(uuid),
            Self::ViVendorClass(instances) => encode_vi_vendor_class(instances),
            Self::ViVendorSpecific(instances) => encode_vi_vendor_specific(instances),
            Self::RelayAgentInformation(info) => encode_relay_agent_information(info),
            Self::ClientIdentifier(identifier) => identifier.encode(),
            Self::Authentication(auth) => auth.encode(),
            Self::ForcerenewNonceCapable(value) => value.encode(),
            Self::StatusCode(status) => status.encode(),
            Self::DhcpState(state) => vec![state.code()],
            Self::DataSource(source) => source.encode(),
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
    /// RFC 3004 user class (option 77): length-prefixed opaque class instances.
    UserClass,
    /// RFC 4578 client system architecture (option 93): 16-bit type list.
    ClientSystemArchitecture,
    /// RFC 4578 client network device interface (option 94): type/major/minor.
    ClientNetworkDeviceInterface,
    /// RFC 4578 UUID/GUID client identifier (option 97): type octet plus GUID.
    ClientUuid,
    /// RFC 3925 V-I Vendor Class (option 124): enterprise-number instances.
    ViVendorClass,
    /// RFC 3925 V-I Vendor-Specific Information (option 125): enterprise-number
    /// instances carrying nested suboptions.
    ViVendorSpecific,
    /// RFC 3046 Relay Agent Information (option 82): a sequence of relay-agent
    /// sub-options.
    RelayAgentInformation,
    /// DHCPv4 Client-identifier (option 61): a type octet plus an RFC 2132
    /// hardware identifier, RFC 4361 IAID+DUID identifier, or raw identifier.
    ClientIdentifier,
    /// RFC 3118 Authentication (option 90): an 11-octet header (Protocol,
    /// Algorithm, RDM, 64-bit Replay Detection) plus raw authentication info.
    Authentication,
    /// RFC 6704 FORCERENEW_NONCE_CAPABLE (option 145): a list of algorithm
    /// octets.
    ForcerenewNonceCapable,
    /// RFC 6926 leasequery status-code (option 151): a status octet plus an
    /// optional text message.
    StatusCode,
    /// RFC 6926 dhcp-state (option 156): a single IP-address binding state octet.
    DhcpState,
    /// RFC 6926 data-source (option 157): a single Flags octet.
    DataSource,
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
    TftpServerName,
    BootfileName,
    UserClass,
    ClientSystemArchitecture,
    ClientNetworkDeviceInterface,
    ClientMachineIdentifier,
    ViVendorClass,
    ViVendorSpecificInformation,
    RelayAgentInformation,
    Authentication,
    ForcerenewNonceCapable,
    ClientLastTransactionTime,
    AssociatedIp,
    StatusCode,
    BaseTime,
    StartTimeOfState,
    QueryStartTime,
    QueryEndTime,
    DhcpState,
    DataSource,
    PxelinuxMagic,
    PxelinuxConfigFile,
    PxelinuxPathPrefix,
    PxelinuxRebootTime,
    Ipv6OnlyPreferred,
    CaptivePortal,
    MudUrl,
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
            DHCP_OPTION_TFTP_SERVER_NAME => Self::TftpServerName,
            DHCP_OPTION_BOOTFILE_NAME => Self::BootfileName,
            DHCP_OPTION_USER_CLASS => Self::UserClass,
            DHCP_OPTION_CLIENT_SYSTEM_ARCHITECTURE => Self::ClientSystemArchitecture,
            DHCP_OPTION_CLIENT_NDI => Self::ClientNetworkDeviceInterface,
            DHCP_OPTION_CLIENT_MACHINE_IDENTIFIER => Self::ClientMachineIdentifier,
            DHCP_OPTION_VI_VENDOR_CLASS => Self::ViVendorClass,
            DHCP_OPTION_VI_VENDOR_SPECIFIC => Self::ViVendorSpecificInformation,
            DHCP_OPTION_RELAY_AGENT_INFORMATION => Self::RelayAgentInformation,
            DHCP_OPTION_AUTHENTICATION => Self::Authentication,
            DHCP_OPTION_FORCERENEW_NONCE_CAPABLE => Self::ForcerenewNonceCapable,
            DHCP_OPTION_CLIENT_LAST_TRANSACTION_TIME => Self::ClientLastTransactionTime,
            DHCP_OPTION_ASSOCIATED_IP => Self::AssociatedIp,
            DHCP_OPTION_STATUS_CODE => Self::StatusCode,
            DHCP_OPTION_BASE_TIME => Self::BaseTime,
            DHCP_OPTION_START_TIME_OF_STATE => Self::StartTimeOfState,
            DHCP_OPTION_QUERY_START_TIME => Self::QueryStartTime,
            DHCP_OPTION_QUERY_END_TIME => Self::QueryEndTime,
            DHCP_OPTION_DHCP_STATE => Self::DhcpState,
            DHCP_OPTION_DATA_SOURCE => Self::DataSource,
            DHCP_OPTION_PXELINUX_MAGIC => Self::PxelinuxMagic,
            DHCP_OPTION_PXELINUX_CONFIGFILE => Self::PxelinuxConfigFile,
            DHCP_OPTION_PXELINUX_PATHPREFIX => Self::PxelinuxPathPrefix,
            DHCP_OPTION_PXELINUX_REBOOTTIME => Self::PxelinuxRebootTime,
            DHCP_OPTION_IPV6_ONLY_PREFERRED => Self::Ipv6OnlyPreferred,
            DHCP_OPTION_CAPTIVE_PORTAL => Self::CaptivePortal,
            DHCP_OPTION_MUD_URL_V4 => Self::MudUrl,
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
            Self::TftpServerName => DHCP_OPTION_TFTP_SERVER_NAME,
            Self::BootfileName => DHCP_OPTION_BOOTFILE_NAME,
            Self::UserClass => DHCP_OPTION_USER_CLASS,
            Self::ClientSystemArchitecture => DHCP_OPTION_CLIENT_SYSTEM_ARCHITECTURE,
            Self::ClientNetworkDeviceInterface => DHCP_OPTION_CLIENT_NDI,
            Self::ClientMachineIdentifier => DHCP_OPTION_CLIENT_MACHINE_IDENTIFIER,
            Self::ViVendorClass => DHCP_OPTION_VI_VENDOR_CLASS,
            Self::ViVendorSpecificInformation => DHCP_OPTION_VI_VENDOR_SPECIFIC,
            Self::RelayAgentInformation => DHCP_OPTION_RELAY_AGENT_INFORMATION,
            Self::Authentication => DHCP_OPTION_AUTHENTICATION,
            Self::ForcerenewNonceCapable => DHCP_OPTION_FORCERENEW_NONCE_CAPABLE,
            Self::ClientLastTransactionTime => DHCP_OPTION_CLIENT_LAST_TRANSACTION_TIME,
            Self::AssociatedIp => DHCP_OPTION_ASSOCIATED_IP,
            Self::StatusCode => DHCP_OPTION_STATUS_CODE,
            Self::BaseTime => DHCP_OPTION_BASE_TIME,
            Self::StartTimeOfState => DHCP_OPTION_START_TIME_OF_STATE,
            Self::QueryStartTime => DHCP_OPTION_QUERY_START_TIME,
            Self::QueryEndTime => DHCP_OPTION_QUERY_END_TIME,
            Self::DhcpState => DHCP_OPTION_DHCP_STATE,
            Self::DataSource => DHCP_OPTION_DATA_SOURCE,
            Self::PxelinuxMagic => DHCP_OPTION_PXELINUX_MAGIC,
            Self::PxelinuxConfigFile => DHCP_OPTION_PXELINUX_CONFIGFILE,
            Self::PxelinuxPathPrefix => DHCP_OPTION_PXELINUX_PATHPREFIX,
            Self::PxelinuxRebootTime => DHCP_OPTION_PXELINUX_REBOOTTIME,
            Self::Ipv6OnlyPreferred => DHCP_OPTION_IPV6_ONLY_PREFERRED,
            Self::CaptivePortal => DHCP_OPTION_CAPTIVE_PORTAL,
            Self::MudUrl => DHCP_OPTION_MUD_URL_V4,
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
            | Self::XWindowDisplayManager
            // RFC 4388 associated-ip (option 92): one or more IPv4 addresses.
            | Self::AssociatedIp => F::Ipv4List,
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
            // 32-bit unsigned. The leasequery time options (RFC 4388 client
            // last transaction time option 91 and RFC 6926 base-time 152,
            // start-time-of-state 153, query-start-time 154, query-end-time 155)
            // are all 4-octet unsigned seconds values; some are absolute time and
            // some are seconds-in-the-past, but the wire format is identical.
            Self::PathMtuAgingTimeout
            | Self::ArpCacheTimeout
            | Self::TcpKeepaliveInterval
            | Self::IpAddressLeaseTime
            | Self::RenewalTime
            | Self::RebindingTime
            | Self::ClientLastTransactionTime
            | Self::BaseTime
            | Self::StartTimeOfState
            | Self::QueryStartTime
            | Self::QueryEndTime
            // RFC 8925 IPv6-Only Preferred (option 108) is a 4-octet V6ONLY_WAIT
            // seconds value.
            | Self::Ipv6OnlyPreferred => F::U32,
            // NVT ASCII / text-like.
            Self::HostName
            | Self::MeritDumpFile
            | Self::DomainName
            | Self::RootPath
            | Self::ExtensionsPath
            | Self::NisDomain
            | Self::NetbiosScope
            | Self::DhcpMessage
            | Self::TftpServerName
            | Self::BootfileName
            | Self::PxelinuxConfigFile
            | Self::PxelinuxPathPrefix
            // RFC 8910 Captive-Portal (option 114) carries a URI and RFC 8520
            // MUD URL (option 161) carries an HTTPS URL, both as text-like bytes
            // with no terminator.
            | Self::CaptivePortal
            | Self::MudUrl => F::Text,
            // RFC 5071 PXELINUX reboot time is a 32-bit seconds value.
            Self::PxelinuxRebootTime => F::U32,
            // Special single-octet codecs and lists.
            Self::ParameterRequestList => F::ParameterRequestList,
            Self::DhcpMessageType => F::MessageType,
            Self::OptionOverload => F::OptionOverload,
            // Vendor/user-class/PXE structured formats.
            Self::UserClass => F::UserClass,
            Self::ClientSystemArchitecture => F::ClientSystemArchitecture,
            Self::ClientNetworkDeviceInterface => F::ClientNetworkDeviceInterface,
            Self::ClientMachineIdentifier => F::ClientUuid,
            Self::ViVendorClass => F::ViVendorClass,
            Self::ViVendorSpecificInformation => F::ViVendorSpecific,
            // RFC 3046 relay agent information (option 82): nested sub-options.
            Self::RelayAgentInformation => F::RelayAgentInformation,
            // RFC 2132 / RFC 4361 client identifier (option 61): a type octet
            // plus a hardware identifier, an IAID+DUID, or a raw identifier.
            Self::ClientIdentifier => F::ClientIdentifier,
            // RFC 3118 authentication (option 90): typed header fields plus raw
            // authentication information.
            Self::Authentication => F::Authentication,
            // RFC 6704 FORCERENEW_NONCE_CAPABLE (option 145): algorithm octets.
            Self::ForcerenewNonceCapable => F::ForcerenewNonceCapable,
            // RFC 6926 leasequery status-code (option 151): status octet + text.
            Self::StatusCode => F::StatusCode,
            // RFC 6926 dhcp-state (option 156): a single binding-state octet.
            Self::DhcpState => F::DhcpState,
            // RFC 6926 data-source (option 157): a single Flags octet.
            Self::DataSource => F::DataSource,
            // Opaque/vendor data preserved verbatim. The PXELINUX magic is a
            // fixed 4-octet value whose meaning is positional, so it is kept
            // opaque rather than reinterpreted.
            Self::VendorSpecificInformation | Self::VendorClassIdentifier | Self::PxelinuxMagic => {
                F::Opaque
            }
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
        DhcpOptionFormat::UserClass => DhcpOptionValue::UserClass(decode_user_class(data)?),
        DhcpOptionFormat::ClientSystemArchitecture => {
            DhcpOptionValue::ClientSystemArchitecture(decode_client_system_architecture(data)?)
        }
        DhcpOptionFormat::ClientNetworkDeviceInterface => {
            DhcpOptionValue::ClientNetworkDeviceInterface(decode_client_ndi(data)?)
        }
        DhcpOptionFormat::ClientUuid => DhcpOptionValue::ClientUuid(decode_client_uuid(data)?),
        DhcpOptionFormat::ViVendorClass => {
            DhcpOptionValue::ViVendorClass(decode_vi_vendor_class(data)?)
        }
        DhcpOptionFormat::ViVendorSpecific => {
            DhcpOptionValue::ViVendorSpecific(decode_vi_vendor_specific(data)?)
        }
        DhcpOptionFormat::RelayAgentInformation => {
            DhcpOptionValue::RelayAgentInformation(decode_relay_agent_information(data)?)
        }
        DhcpOptionFormat::ClientIdentifier => {
            DhcpOptionValue::ClientIdentifier(decode_client_identifier(data)?)
        }
        DhcpOptionFormat::Authentication => {
            DhcpOptionValue::Authentication(decode_authentication(data)?)
        }
        DhcpOptionFormat::ForcerenewNonceCapable => {
            DhcpOptionValue::ForcerenewNonceCapable(DhcpForcerenewNonceCapable::new(data.to_vec()))
        }
        DhcpOptionFormat::StatusCode => {
            DhcpOptionValue::StatusCode(decode_status_code(field, data)?)
        }
        DhcpOptionFormat::DhcpState => {
            validate_fixed_len(field, data.len(), 1)?;
            DhcpOptionValue::DhcpState(DhcpState::from_code(data[0]))
        }
        DhcpOptionFormat::DataSource => {
            validate_fixed_len(field, data.len(), 1)?;
            DhcpOptionValue::DataSource(DhcpDataSource::new(data[0]))
        }
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

/// Decode the RFC 5859 TFTP Server Address option (option 150) into its IPv4
/// address list.
///
/// Source: RFC 5859. The payload is one or more IPv4 addresses (length a
/// non-zero multiple of four). Code 150 is marked ambiguous by the IANA
/// registry (it is also used by Etherboot and GRUB), so the default option
/// decoder preserves code 150 as raw bytes; this is an explicit opt-in to the
/// RFC 5859 interpretation. A length that is not a non-zero multiple of four
/// surfaces as a structured error rather than a panic.
pub fn decode_tftp_server_addresses(data: &[u8]) -> Result<Vec<Ipv4Addr>> {
    let field = "dhcp.option.tftp_server_address";
    if data.is_empty() || data.len() % 4 != 0 {
        return Err(CrafterError::invalid_field_value(
            field,
            "TFTP server address option length must be a non-zero multiple of four",
        ));
    }
    decode_ipv4_list(field, data)
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

    /// Create a client identifier option from raw payload bytes (the `type`
    /// octet plus identifier).
    pub fn client_identifier(identifier: impl Into<Vec<u8>>) -> Self {
        Self::ClientIdentifier(identifier.into())
    }

    /// Create a typed client identifier option (option 61) from a
    /// [`DhcpClientIdentifier`].
    ///
    /// Source: RFC 2132 section 9.14 and RFC 4361 section 6.1. The value is
    /// serialized to its option 61 wire layout and re-decodes through
    /// [`DhcpOption::typed_value`] into a [`DhcpOptionValue::ClientIdentifier`].
    /// Use [`DhcpClientIdentifier::ethernet_mac`] for a legacy Ethernet MAC
    /// identifier or [`DhcpClientIdentifier::node_specific`] for an RFC 4361
    /// IAID+DUID identifier.
    pub fn client_identifier_value(identifier: DhcpClientIdentifier) -> Self {
        Self::ClientIdentifier(identifier.encode())
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

    /// Create a vendor-specific information option (option 43, RFC 2132).
    ///
    /// The payload is opaque vendor data whose internal format is defined by the
    /// vendor (option 60); it is carried verbatim.
    pub fn vendor_specific(data: impl Into<Vec<u8>>) -> Self {
        Self::generic(DHCP_OPTION_VENDOR_SPECIFIC, data)
    }

    /// Create a vendor class identifier option (option 60, RFC 2132).
    pub fn vendor_class_identifier(data: impl Into<Vec<u8>>) -> Self {
        Self::generic(DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, data)
    }

    /// Create a TFTP server name option (option 66, RFC 2132 section 9.4).
    pub fn tftp_server_name(name: impl Into<Vec<u8>>) -> Self {
        Self::generic(DHCP_OPTION_TFTP_SERVER_NAME, name)
    }

    /// Create a bootfile name option (option 67, RFC 2132 section 9.5).
    pub fn bootfile_name(name: impl Into<Vec<u8>>) -> Self {
        Self::generic(DHCP_OPTION_BOOTFILE_NAME, name)
    }

    /// Create an RFC 3004 user-class option (option 77).
    pub fn user_class(user_class: DhcpUserClass) -> Self {
        Self::typed(
            DhcpOptionKind::UserClass,
            DhcpOptionValue::UserClass(user_class),
        )
    }

    /// Create an RFC 4578 client system architecture option (option 93).
    pub fn client_system_architecture(arch: ClientSystemArchitecture) -> Self {
        Self::typed(
            DhcpOptionKind::ClientSystemArchitecture,
            DhcpOptionValue::ClientSystemArchitecture(arch),
        )
    }

    /// Create an RFC 4578 client network device interface option (option 94).
    pub fn client_network_device_interface(ndi: ClientNetworkDeviceInterface) -> Self {
        Self::typed(
            DhcpOptionKind::ClientNetworkDeviceInterface,
            DhcpOptionValue::ClientNetworkDeviceInterface(ndi),
        )
    }

    /// Create an RFC 4578 UUID/GUID client machine identifier option (option 97).
    pub fn client_uuid(uuid: DhcpClientUuid) -> Self {
        Self::typed(
            DhcpOptionKind::ClientMachineIdentifier,
            DhcpOptionValue::ClientUuid(uuid),
        )
    }

    /// Create an RFC 3925 V-I Vendor Class option (option 124).
    pub fn vi_vendor_class(instances: impl Into<Vec<DhcpVendorClassData>>) -> Self {
        Self::typed(
            DhcpOptionKind::ViVendorClass,
            DhcpOptionValue::ViVendorClass(instances.into()),
        )
    }

    /// Create an RFC 3925 V-I Vendor-Specific Information option (option 125).
    pub fn vi_vendor_specific(instances: impl Into<Vec<DhcpVendorIdentifyingOption>>) -> Self {
        Self::typed(
            DhcpOptionKind::ViVendorSpecificInformation,
            DhcpOptionValue::ViVendorSpecific(instances.into()),
        )
    }

    /// Create an RFC 3046 Relay Agent Information option (option 82).
    ///
    /// The sub-options are serialized to their RFC 3046 sub-option layout
    /// (code/length/value triples, no pad, no end marker) and re-decode through
    /// [`DhcpOption::typed_value`] into a
    /// [`DhcpOptionValue::RelayAgentInformation`].
    pub fn relay_agent_information(info: DhcpRelayAgentInfo) -> Self {
        Self::typed(
            DhcpOptionKind::RelayAgentInformation,
            DhcpOptionValue::RelayAgentInformation(info),
        )
    }

    /// Create an RFC 3118 Authentication option (option 90).
    ///
    /// The header fields (Protocol, Algorithm, RDM, Replay Detection) and the
    /// raw authentication information are serialized to the RFC 3118 layout and
    /// re-decode through [`DhcpOption::typed_value`] into a
    /// [`DhcpOptionValue::Authentication`]. This is packet data only: the crate
    /// does not derive, sign, or verify the authentication information.
    pub fn authentication(auth: DhcpAuthentication) -> Self {
        Self::typed(
            DhcpOptionKind::Authentication,
            DhcpOptionValue::Authentication(auth),
        )
    }

    /// Create an RFC 6704 FORCERENEW_NONCE_CAPABLE option (option 145).
    ///
    /// The supported authentication algorithm octets are carried verbatim and
    /// re-decode through [`DhcpOption::typed_value`] into a
    /// [`DhcpOptionValue::ForcerenewNonceCapable`].
    pub fn forcerenew_nonce_capable(value: DhcpForcerenewNonceCapable) -> Self {
        Self::typed(
            DhcpOptionKind::ForcerenewNonceCapable,
            DhcpOptionValue::ForcerenewNonceCapable(value),
        )
    }

    /// Create an RFC 4388 client-last-transaction-time option (option 91).
    ///
    /// The value is the unsigned number of seconds in the past from when the
    /// DHCPLEASEACTIVE message is sent that the client last dealt with the
    /// server about this IP address (RFC 4388 section 6.1).
    pub fn client_last_transaction_time(seconds: u32) -> Self {
        Self::typed(
            DhcpOptionKind::ClientLastTransactionTime,
            DhcpOptionValue::U32(seconds),
        )
    }

    /// Create an RFC 4388 associated-ip option (option 92).
    ///
    /// The payload is one or more IPv4 addresses associated with the queried
    /// client (RFC 4388 section 6.1).
    pub fn associated_ip(addresses: impl Into<Vec<Ipv4Addr>>) -> Self {
        Self::typed(
            DhcpOptionKind::AssociatedIp,
            DhcpOptionValue::Ipv4List(addresses.into()),
        )
    }

    /// Create an RFC 6926 status-code option (option 151).
    ///
    /// The status octet and optional message re-decode through
    /// [`DhcpOption::typed_value`] into a [`DhcpOptionValue::StatusCode`].
    pub fn status_code(status: DhcpStatusCodeOption) -> Self {
        Self::typed(
            DhcpOptionKind::StatusCode,
            DhcpOptionValue::StatusCode(status),
        )
    }

    /// Create an RFC 6926 base-time option (option 152).
    ///
    /// The value is the absolute time (seconds since Jan 1, 1970) the message
    /// was created (RFC 6926 section 6.2.3).
    pub fn base_time(seconds: u32) -> Self {
        Self::typed(DhcpOptionKind::BaseTime, DhcpOptionValue::U32(seconds))
    }

    /// Create an RFC 6926 start-time-of-state option (option 153).
    ///
    /// The value is the number of seconds in the past from base-time when the
    /// IP address entered its current state (RFC 6926 section 6.2.4).
    pub fn start_time_of_state(seconds: u32) -> Self {
        Self::typed(
            DhcpOptionKind::StartTimeOfState,
            DhcpOptionValue::U32(seconds),
        )
    }

    /// Create an RFC 6926 query-start-time option (option 154).
    ///
    /// The value is the absolute start time (seconds since Jan 1, 1970) of the
    /// query (RFC 6926 section 6.2.5).
    pub fn query_start_time(seconds: u32) -> Self {
        Self::typed(
            DhcpOptionKind::QueryStartTime,
            DhcpOptionValue::U32(seconds),
        )
    }

    /// Create an RFC 6926 query-end-time option (option 155).
    ///
    /// The value is the absolute end time (seconds since Jan 1, 1970) of the
    /// query (RFC 6926 section 6.2.6).
    pub fn query_end_time(seconds: u32) -> Self {
        Self::typed(DhcpOptionKind::QueryEndTime, DhcpOptionValue::U32(seconds))
    }

    /// Create an RFC 6926 dhcp-state option (option 156).
    ///
    /// The state octet re-decodes through [`DhcpOption::typed_value`] into a
    /// [`DhcpOptionValue::DhcpState`] (RFC 6926 section 6.2.7).
    pub fn dhcp_state(state: DhcpState) -> Self {
        Self::typed(DhcpOptionKind::DhcpState, DhcpOptionValue::DhcpState(state))
    }

    /// Create an RFC 6926 data-source option (option 157).
    ///
    /// The Flags octet (including the REMOTE flag) re-decodes through
    /// [`DhcpOption::typed_value`] into a [`DhcpOptionValue::DataSource`] (RFC
    /// 6926 section 6.2.8).
    pub fn data_source(source: DhcpDataSource) -> Self {
        Self::typed(
            DhcpOptionKind::DataSource,
            DhcpOptionValue::DataSource(source),
        )
    }

    /// Create an RFC 5859 TFTP server address option (option 150).
    ///
    /// The payload is a list of IPv4 addresses (length a multiple of four). Note
    /// that the IANA registry marks code 150 as ambiguous (TFTP server /
    /// Etherboot / GRUB); this constructor encodes the RFC 5859 interpretation,
    /// while decoding leaves code 150 as raw bytes by default. Use
    /// [`super::Dhcp::tftp_server_addresses`] to apply the RFC 5859 decode.
    pub fn tftp_server_addresses(addresses: impl Into<Vec<Ipv4Addr>>) -> Self {
        Self::generic(
            DHCP_OPTION_TFTP_SERVER_ADDRESS,
            encode_ipv4_list(&addresses.into()),
        )
    }

    /// Create an RFC 5071 PXELINUX magic option (option 208).
    ///
    /// The payload is the fixed magic value `F1:00:74:7E`.
    pub fn pxelinux_magic() -> Self {
        Self::generic(
            DHCP_OPTION_PXELINUX_MAGIC,
            DHCP_PXELINUX_MAGIC_VALUE.to_vec(),
        )
    }

    /// Create an RFC 5071 PXELINUX configuration file option (option 209).
    pub fn pxelinux_config_file(path: impl Into<Vec<u8>>) -> Self {
        Self::generic(DHCP_OPTION_PXELINUX_CONFIGFILE, path)
    }

    /// Create an RFC 5071 PXELINUX path prefix option (option 210).
    pub fn pxelinux_path_prefix(path: impl Into<Vec<u8>>) -> Self {
        Self::generic(DHCP_OPTION_PXELINUX_PATHPREFIX, path)
    }

    /// Create an RFC 5071 PXELINUX reboot time option (option 211), in seconds.
    pub fn pxelinux_reboot_time(seconds: u32) -> Self {
        Self::typed(
            DhcpOptionKind::PxelinuxRebootTime,
            DhcpOptionValue::U32(seconds),
        )
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

/// Octet length of an RFC 3925 IANA Enterprise Number (options 124 and 125).
const DHCP_ENTERPRISE_NUMBER_LEN: usize = 4;

/// Decode an RFC 3004 user-class option (option 77).
///
/// Source: RFC 3004 (errata-corrected). The payload is one or more instances,
/// each a one-octet length followed by that many opaque data octets. A
/// zero-length instance is malformed per the RFC, and a length that runs past
/// the end of the data is a structured error rather than a panic.
fn decode_user_class(data: &[u8]) -> Result<DhcpUserClass> {
    let field = "dhcp.option.user_class";
    let mut classes = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let len = data[offset] as usize;
        offset += 1;
        if len == 0 {
            return Err(CrafterError::invalid_field_value(
                field,
                "user class data instance length must be non-zero",
            ));
        }
        let end = offset + len;
        if end > data.len() {
            return Err(CrafterError::buffer_too_short(field, end, data.len()));
        }
        classes.push(data[offset..end].to_vec());
        offset = end;
    }

    Ok(DhcpUserClass::new(classes))
}

/// Encode an RFC 3004 user-class option (option 77).
///
/// Each opaque class instance is emitted as a one-octet length prefix followed
/// by its data bytes, in order. Instance lengths are bounded to the 255-octet
/// length field; longer instances are truncated to the field width.
fn encode_user_class(user_class: &DhcpUserClass) -> Vec<u8> {
    let mut bytes = Vec::new();
    for class in &user_class.classes {
        let len = class.len().min(DHCP_MAX_OPTION_DATA_LEN);
        bytes.push(len as u8);
        bytes.extend_from_slice(&class[..len]);
    }
    bytes
}

/// Decode an RFC 4578 client system architecture option (option 93).
///
/// Source: RFC 4578 section 2.1. The payload is one or more 16-bit big-endian
/// architecture type values, so the length must be a non-zero multiple of two.
fn decode_client_system_architecture(data: &[u8]) -> Result<ClientSystemArchitecture> {
    let field = "dhcp.option.client_system_architecture";
    Ok(ClientSystemArchitecture::new(decode_u16_list(field, data)?))
}

/// Encode an RFC 4578 client system architecture option (option 93).
fn encode_client_system_architecture(arch: &ClientSystemArchitecture) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(arch.architectures.len() * 2);
    for value in &arch.architectures {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes
}

/// Decode an RFC 4578 client network device interface option (option 94).
///
/// Source: RFC 4578 section 2.2. The payload is exactly three octets: an
/// interface type octet followed by major and minor revision octets. Any other
/// length is a structured error.
fn decode_client_ndi(data: &[u8]) -> Result<ClientNetworkDeviceInterface> {
    let field = "dhcp.option.client_ndi";
    validate_fixed_len(field, data.len(), 3)?;
    Ok(ClientNetworkDeviceInterface::new(data[0], data[1], data[2]))
}

/// Decode an RFC 4578 UUID/GUID client machine identifier (option 97).
///
/// Source: RFC 4578 section 2.3. The payload is a type octet followed by the
/// machine identifier. At least the type octet must be present; the identifier
/// bytes (a 16-octet GUID for type `0`) are preserved verbatim, so non-standard
/// type values and identifier lengths still round-trip.
fn decode_client_uuid(data: &[u8]) -> Result<DhcpClientUuid> {
    let field = "dhcp.option.client_uuid";
    let Some((&identifier_type, rest)) = data.split_first() else {
        return Err(CrafterError::buffer_too_short(field, 1, 0));
    };
    Ok(DhcpClientUuid::new(identifier_type, rest.to_vec()))
}

/// Decode a DHCPv4 Client-identifier option (option 61).
///
/// Source: RFC 2132 section 9.14 and RFC 4361 section 6.1. The payload is a
/// one-octet `type` field followed by the identifier. A type of `255` (RFC
/// 4361) introduces a 4-octet IAID and a variable-length DUID; any other
/// non-empty type is the RFC 2132 hardware-type form (hardware type plus
/// hardware address). An empty payload carries no type octet and is preserved
/// as an empty raw identifier rather than treated as a panic-worthy buffer. A
/// type-`255` identifier with fewer than four IAID octets surfaces as a
/// structured error rather than a panic.
fn decode_client_identifier(data: &[u8]) -> Result<DhcpClientIdentifier> {
    let field = "dhcp.option.client_identifier";
    let Some((&type_octet, rest)) = data.split_first() else {
        // No type octet present: preserve the empty payload verbatim.
        return Ok(DhcpClientIdentifier::Raw(Vec::new()));
    };
    if type_octet == DHCP_CLIENT_ID_TYPE_RFC4361 {
        if rest.len() < DHCP_IAID_LEN {
            return Err(CrafterError::buffer_too_short(
                field,
                1 + DHCP_IAID_LEN,
                data.len(),
            ));
        }
        let iaid = read_u32_be(&rest[..DHCP_IAID_LEN])?;
        let duid = rest[DHCP_IAID_LEN..].to_vec();
        return Ok(DhcpClientIdentifier::NodeSpecific { iaid, duid });
    }
    if type_octet == DHCP_CLIENT_ID_TYPE_NONE {
        // RFC 2132: a type of 0 is a non-hardware identifier (for example a
        // fully-qualified domain name). The structure beyond the type octet is
        // not specified, so the whole payload is preserved verbatim.
        return Ok(DhcpClientIdentifier::Raw(data.to_vec()));
    }
    Ok(DhcpClientIdentifier::LegacyHardware {
        hardware_type: type_octet,
        address: rest.to_vec(),
    })
}

/// Decode an RFC 3118 DHCP Authentication option (option 90).
///
/// Source: RFC 3118 section 2. The payload is a fixed 11-octet header (a
/// one-octet Protocol, a one-octet Algorithm, a one-octet RDM, and an 8-octet
/// Replay Detection field) followed by variable Authentication Information. A
/// payload shorter than the 11-octet header surfaces as a structured
/// [`CrafterError`] rather than a panic. The Authentication Information is
/// preserved verbatim because its structure depends on the Protocol; the codec
/// never interprets, signs, or verifies it.
fn decode_authentication(data: &[u8]) -> Result<DhcpAuthentication> {
    let field = "dhcp.option.authentication";
    if data.len() < DHCP_AUTH_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            field,
            DHCP_AUTH_HEADER_LEN,
            data.len(),
        ));
    }
    let protocol = DhcpAuthProtocol::from_code(data[0]);
    let algorithm = DhcpAuthAlgorithm::from_code(data[1]);
    let rdm = DhcpReplayDetectionMethod::from_code(data[2]);
    let replay_end = 3 + DHCP_AUTH_REPLAY_DETECTION_LEN;
    // The length check above guarantees at least DHCP_AUTH_HEADER_LEN (11)
    // octets, so this 8-octet slice is always present.
    let mut replay_bytes = [0u8; DHCP_AUTH_REPLAY_DETECTION_LEN];
    replay_bytes.copy_from_slice(&data[3..replay_end]);
    let replay_detection = u64::from_be_bytes(replay_bytes);
    Ok(DhcpAuthentication {
        protocol,
        algorithm,
        rdm,
        replay_detection,
        authentication_information: data[replay_end..].to_vec(),
    })
}

/// Decode an RFC 6926 leasequery status-code option (option 151).
///
/// Source: RFC 6926 section 6.2.2. The payload is a one-octet status code
/// followed by an optional status message of zero or more octets (the RFC
/// describes the message as UTF-8 with no termination or null characters, but
/// the bytes are preserved verbatim). At least the status octet must be present;
/// an empty payload surfaces as a structured [`CrafterError`] rather than a
/// panic.
fn decode_status_code(field: &'static str, data: &[u8]) -> Result<DhcpStatusCodeOption> {
    let Some((&status, message)) = data.split_first() else {
        return Err(CrafterError::buffer_too_short(field, 1, 0));
    };
    Ok(DhcpStatusCodeOption::new(
        DhcpStatusCode::from_code(status),
        message.to_vec(),
    ))
}

/// Encode an RFC 4578 UUID/GUID client machine identifier (option 97).
fn encode_client_uuid(uuid: &DhcpClientUuid) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + uuid.identifier.len());
    bytes.push(uuid.identifier_type);
    bytes.extend_from_slice(&uuid.identifier);
    bytes
}

/// Decode an RFC 3925 V-I Vendor Class option (option 124).
///
/// Source: RFC 3925 section 3. The payload is one or more instances, each a
/// 4-octet enterprise number, a one-octet `data-len`, and that many opaque
/// vendor-class-data octets. A truncated enterprise number, missing data-len,
/// or a data-len that runs past the end of the option surfaces as a structured
/// error rather than a panic.
fn decode_vi_vendor_class(data: &[u8]) -> Result<Vec<DhcpVendorClassData>> {
    let field = "dhcp.option.vi_vendor_class";
    let mut instances = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let enterprise_number = read_enterprise_number(field, data, offset)?;
        offset += DHCP_ENTERPRISE_NUMBER_LEN;
        if offset >= data.len() {
            return Err(CrafterError::buffer_too_short(
                field,
                offset + 1,
                data.len(),
            ));
        }
        let len = data[offset] as usize;
        offset += 1;
        let end = offset + len;
        if end > data.len() {
            return Err(CrafterError::buffer_too_short(field, end, data.len()));
        }
        instances.push(DhcpVendorClassData::new(
            enterprise_number,
            data[offset..end].to_vec(),
        ));
        offset = end;
    }

    Ok(instances)
}

/// Encode an RFC 3925 V-I Vendor Class option (option 124).
fn encode_vi_vendor_class(instances: &[DhcpVendorClassData]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for instance in instances {
        bytes.extend_from_slice(&instance.enterprise_number.to_be_bytes());
        let len = instance.data.len().min(DHCP_MAX_OPTION_DATA_LEN);
        bytes.push(len as u8);
        bytes.extend_from_slice(&instance.data[..len]);
    }
    bytes
}

/// Decode an RFC 3925 V-I Vendor-Specific Information option (option 125).
///
/// Source: RFC 3925 section 4. The payload is one or more instances, each a
/// 4-octet enterprise number, a one-octet `data-len`, and that many octets of
/// option-data; the option-data is itself a sequence of `subopt-code` /
/// `subopt-len` / value triples. Truncated headers, suboption lengths that run
/// past the instance, and truncated suboption data all surface as structured
/// errors. The suboption data stays opaque because its code space is
/// vendor-defined.
fn decode_vi_vendor_specific(data: &[u8]) -> Result<Vec<DhcpVendorIdentifyingOption>> {
    let field = "dhcp.option.vi_vendor_specific";
    let mut instances = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let enterprise_number = read_enterprise_number(field, data, offset)?;
        offset += DHCP_ENTERPRISE_NUMBER_LEN;
        if offset >= data.len() {
            return Err(CrafterError::buffer_too_short(
                field,
                offset + 1,
                data.len(),
            ));
        }
        let len = data[offset] as usize;
        offset += 1;
        let end = offset + len;
        if end > data.len() {
            return Err(CrafterError::buffer_too_short(field, end, data.len()));
        }
        let suboptions = decode_vendor_suboptions(field, &data[offset..end])?;
        instances.push(DhcpVendorIdentifyingOption::new(
            enterprise_number,
            suboptions,
        ));
        offset = end;
    }

    Ok(instances)
}

/// Decode the nested RFC 3925 suboptions inside one option-125 instance.
fn decode_vendor_suboptions(field: &'static str, data: &[u8]) -> Result<Vec<DhcpVendorSuboption>> {
    let mut suboptions = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let code = data[offset];
        offset += 1;
        if offset >= data.len() {
            return Err(CrafterError::buffer_too_short(
                field,
                offset + 1,
                data.len(),
            ));
        }
        let len = data[offset] as usize;
        offset += 1;
        let end = offset + len;
        if end > data.len() {
            return Err(CrafterError::buffer_too_short(field, end, data.len()));
        }
        suboptions.push(DhcpVendorSuboption::new(code, data[offset..end].to_vec()));
        offset = end;
    }

    Ok(suboptions)
}

/// Encode an RFC 3925 V-I Vendor-Specific Information option (option 125).
fn encode_vi_vendor_specific(instances: &[DhcpVendorIdentifyingOption]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for instance in instances {
        bytes.extend_from_slice(&instance.enterprise_number.to_be_bytes());
        let option_data = encode_vendor_suboptions(&instance.suboptions);
        let len = option_data.len().min(DHCP_MAX_OPTION_DATA_LEN);
        bytes.push(len as u8);
        bytes.extend_from_slice(&option_data[..len]);
    }
    bytes
}

/// Encode the nested RFC 3925 suboptions of one option-125 instance.
fn encode_vendor_suboptions(suboptions: &[DhcpVendorSuboption]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for suboption in suboptions {
        bytes.push(suboption.code);
        let len = suboption.data.len().min(DHCP_MAX_OPTION_DATA_LEN);
        bytes.push(len as u8);
        bytes.extend_from_slice(&suboption.data[..len]);
    }
    bytes
}

/// Read a 4-octet big-endian IANA Enterprise Number at `offset` (RFC 3925).
fn read_enterprise_number(field: &'static str, data: &[u8], offset: usize) -> Result<u32> {
    let end = offset + DHCP_ENTERPRISE_NUMBER_LEN;
    if end > data.len() {
        return Err(CrafterError::buffer_too_short(field, end, data.len()));
    }
    read_u32_be(&data[offset..end])
}

/// Decode an RFC 3046 Relay Agent Information option (option 82).
///
/// Source: RFC 3046 section 2 and the IANA "DHCP Relay Agent Sub-Option Codes"
/// registry. The payload is a sequence of code/length/value sub-options with no
/// pad and no end marker. Registered sub-options whose wire format is specified
/// decode into typed variants; codes without a single authoritative typed format
/// and unknown or reserved codes are preserved verbatim. A truncated sub-option
/// header or a length that runs past the end of the option surfaces as a
/// structured error rather than a panic.
fn decode_relay_agent_information(data: &[u8]) -> Result<DhcpRelayAgentInfo> {
    let field = "dhcp.option.relay_agent_information";
    let mut suboptions = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let code = data[offset];
        offset += 1;
        if offset >= data.len() {
            return Err(CrafterError::buffer_too_short(
                field,
                offset + 1,
                data.len(),
            ));
        }
        let len = data[offset] as usize;
        offset += 1;
        let end = offset + len;
        if end > data.len() {
            return Err(CrafterError::buffer_too_short(field, end, data.len()));
        }
        let value = &data[offset..end];
        suboptions.push(decode_relay_suboption(field, code, value)?);
        offset = end;
    }

    Ok(DhcpRelayAgentInfo::new(suboptions))
}

/// Decode one relay-agent sub-option from its code and value bytes.
fn decode_relay_suboption(
    field: &'static str,
    code: u8,
    value: &[u8],
) -> Result<DhcpRelaySuboption> {
    let suboption = match code {
        DHCP_RELAY_SUBOPTION_CIRCUIT_ID => DhcpRelaySuboption::CircuitId(value.to_vec()),
        DHCP_RELAY_SUBOPTION_REMOTE_ID => DhcpRelaySuboption::RemoteId(value.to_vec()),
        DHCP_RELAY_SUBOPTION_DOCSIS_DEVICE_CLASS => {
            validate_fixed_len(field, value.len(), 4)?;
            DhcpRelaySuboption::DocsisDeviceClass(read_u32_be(value)?)
        }
        DHCP_RELAY_SUBOPTION_LINK_SELECTION => {
            DhcpRelaySuboption::LinkSelection(decode_ipv4_option(field, value)?)
        }
        DHCP_RELAY_SUBOPTION_SUBSCRIBER_ID => DhcpRelaySuboption::SubscriberId(value.to_vec()),
        DHCP_RELAY_SUBOPTION_RADIUS_ATTRIBUTES => {
            DhcpRelaySuboption::RadiusAttributes(value.to_vec())
        }
        DHCP_RELAY_SUBOPTION_AUTHENTICATION => DhcpRelaySuboption::Authentication(value.to_vec()),
        DHCP_RELAY_SUBOPTION_VENDOR_SPECIFIC => {
            DhcpRelaySuboption::VendorSpecific(decode_relay_vendor_specific(field, value)?)
        }
        DHCP_RELAY_SUBOPTION_RELAY_FLAGS => {
            validate_fixed_len(field, value.len(), 1)?;
            DhcpRelaySuboption::RelayFlags(value[0])
        }
        DHCP_RELAY_SUBOPTION_SERVER_ID_OVERRIDE => {
            DhcpRelaySuboption::ServerIdOverride(decode_ipv4_option(field, value)?)
        }
        DHCP_RELAY_SUBOPTION_RELAY_AGENT_ID => DhcpRelaySuboption::RelayAgentId(value.to_vec()),
        DHCP_RELAY_SUBOPTION_RELAY_SOURCE_PORT => {
            // RFC 8357: the relay source port sub-option carries no value; the
            // length must be zero and the actual port is learned from the UDP
            // header. A non-zero length is malformed for the typed view.
            validate_fixed_len(field, value.len(), 0)?;
            DhcpRelaySuboption::RelaySourcePort
        }
        DHCP_RELAY_SUBOPTION_VSS => {
            // RFC 6607: a one-octet Type followed by type-specific VSS Info.
            if value.is_empty() {
                return Err(CrafterError::buffer_too_short(field, 1, value.len()));
            }
            DhcpRelaySuboption::Vss(DhcpVssInfo::new(value[0], value[1..].to_vec()))
        }
        DHCP_RELAY_SUBOPTION_VSS_CONTROL => {
            validate_fixed_len(field, value.len(), 0)?;
            DhcpRelaySuboption::VssControl
        }
        _ => DhcpRelaySuboption::Other {
            code,
            data: value.to_vec(),
        },
    };
    Ok(suboption)
}

/// Decode the RFC 4243 relay Vendor-Specific Information sub-option (relay
/// sub-option 9) into its enterprise-number plus opaque-data tuples.
///
/// Source: RFC 4243 section 4. The value is one or more tuples, each a 4-octet
/// enterprise number, a one-octet data length, and that many opaque octets. A
/// truncated enterprise number, missing data-len, or a data-len that runs past
/// the end surfaces as a structured error rather than a panic.
fn decode_relay_vendor_specific(
    field: &'static str,
    data: &[u8],
) -> Result<Vec<DhcpRelayVendorSpecific>> {
    let mut tuples = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let enterprise_number = read_enterprise_number(field, data, offset)?;
        offset += DHCP_ENTERPRISE_NUMBER_LEN;
        if offset >= data.len() {
            return Err(CrafterError::buffer_too_short(
                field,
                offset + 1,
                data.len(),
            ));
        }
        let len = data[offset] as usize;
        offset += 1;
        let end = offset + len;
        if end > data.len() {
            return Err(CrafterError::buffer_too_short(field, end, data.len()));
        }
        tuples.push(DhcpRelayVendorSpecific::new(
            enterprise_number,
            data[offset..end].to_vec(),
        ));
        offset = end;
    }

    Ok(tuples)
}

/// Encode an RFC 3046 Relay Agent Information option (option 82) value to its
/// option payload bytes (without the option code or length byte).
fn encode_relay_agent_information(info: &DhcpRelayAgentInfo) -> Vec<u8> {
    let mut bytes = Vec::new();
    for suboption in &info.suboptions {
        let value = suboption.encode_value();
        let len = value.len().min(DHCP_MAX_OPTION_DATA_LEN);
        bytes.push(suboption.code());
        bytes.push(len as u8);
        bytes.extend_from_slice(&value[..len]);
    }
    bytes
}

/// Encode the RFC 4243 relay Vendor-Specific Information tuples (relay
/// sub-option 9) into their sub-option value bytes.
fn encode_relay_vendor_specific(tuples: &[DhcpRelayVendorSpecific]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for tuple in tuples {
        bytes.extend_from_slice(&tuple.enterprise_number.to_be_bytes());
        let len = tuple.data.len().min(DHCP_MAX_OPTION_DATA_LEN);
        bytes.push(len as u8);
        bytes.extend_from_slice(&tuple.data[..len]);
    }
    bytes
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
        Dhcp, DhcpClientIdentifier, DhcpMessageType, DhcpOption, DhcpOptionCode, DhcpOptionFormat,
        DhcpOptionKind, DhcpOptionValue, OptionOverload,
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
            // Opaque (option 60 vendor class id, option 43 vendor specific) -
            // raw bytes preserved.
            (60, DhcpOptionValue::Opaque(b"MSFT 5.0".to_vec())),
            // Client identifier (option 61): the legacy RFC 2132 Ethernet
            // hardware-type form (type 1 plus a 6-octet MAC).
            (
                61,
                DhcpOptionValue::ClientIdentifier(DhcpClientIdentifier::ethernet_mac([
                    0x02, 0x00, 0x5e, 0x10, 0x00, 0x01,
                ])),
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
            DhcpOptionFormat::ClientIdentifier,
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

        // Codes outside the typed-format set return Ok(None) so callers fall
        // back to raw-byte preservation. Code 100 (RFC 4833 PCode) has no
        // single authoritative typed format here and stays raw.
        assert!(typed_option_value(224, &[0xde, 0xad]).unwrap().is_none());
        assert!(typed_option_value(100, &[0x01, 0x00]).unwrap().is_none());
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

#[cfg(test)]
mod dhcp_vendor_user_pxe {
    use super::super::{
        decode_tftp_server_addresses, ClientNetworkDeviceInterface, ClientSystemArchitecture, Dhcp,
        DhcpClientUuid, DhcpMessageType, DhcpOption, DhcpUserClass, DhcpVendorClassData,
        DhcpVendorIdentifyingOption, DhcpVendorSuboption,
    };
    use super::{
        decode_client_ndi, decode_client_system_architecture, decode_client_uuid,
        decode_user_class, decode_vi_vendor_class, decode_vi_vendor_specific, typed_option_value,
        DhcpOptionValue,
    };
    use crate::error::CrafterError;
    use core::net::Ipv4Addr;

    const VENDOR_SPECIFIC: u8 = super::super::DHCP_OPTION_VENDOR_SPECIFIC; // 43
    const VENDOR_CLASS_ID: u8 = super::super::DHCP_OPTION_VENDOR_CLASS_IDENTIFIER; // 60
    const TFTP_SERVER_NAME: u8 = super::super::DHCP_OPTION_TFTP_SERVER_NAME; // 66
    const BOOTFILE_NAME: u8 = super::super::DHCP_OPTION_BOOTFILE_NAME; // 67
    const USER_CLASS: u8 = super::super::DHCP_OPTION_USER_CLASS; // 77
    const CLIENT_ARCH: u8 = super::super::DHCP_OPTION_CLIENT_SYSTEM_ARCHITECTURE; // 93
    const CLIENT_NDI: u8 = super::super::DHCP_OPTION_CLIENT_NDI; // 94
    const CLIENT_UUID: u8 = super::super::DHCP_OPTION_CLIENT_MACHINE_IDENTIFIER; // 97
    const VI_VENDOR_CLASS: u8 = super::super::DHCP_OPTION_VI_VENDOR_CLASS; // 124
    const VI_VENDOR_SPECIFIC: u8 = super::super::DHCP_OPTION_VI_VENDOR_SPECIFIC; // 125
    const TFTP_SERVER_ADDRESS: u8 = super::super::DHCP_OPTION_TFTP_SERVER_ADDRESS; // 150

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn build_and_decode(options: Vec<DhcpOption>) -> Dhcp {
        let dhcp = Dhcp::new()
            .op(super::super::BOOTP_REQUEST)
            .message_type(DhcpMessageType::Discover)
            .options(options);
        let bytes = crate::Packet::from_layer(dhcp)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        Dhcp::decode(&bytes).unwrap()
    }

    fn recompile_is_stable(parsed: &Dhcp) {
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
    }

    #[test]
    fn dhcp_vendor_identifying_options_roundtrip() {
        // RFC 3925 option 124 (V-I Vendor Class): one or more instances of a
        // 4-octet enterprise number, a data-len octet, and opaque
        // vendor-class-data.
        let vivco = vec![
            DhcpVendorClassData::new(3561, b"PXEClient:Arch:00009".to_vec()),
            DhcpVendorClassData::new(311, vec![0xde, 0xad, 0xbe, 0xef]),
        ];
        let vivco_value = DhcpOptionValue::ViVendorClass(vivco.clone());
        let payload = vivco_value.encode_payload();
        // Wire layout: enterprise(4) + data-len(1) + data, repeated.
        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(&3561u32.to_be_bytes());
        expected.push(20);
        expected.extend_from_slice(b"PXEClient:Arch:00009");
        expected.extend_from_slice(&311u32.to_be_bytes());
        expected.push(4);
        expected.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(payload, expected);
        assert_eq!(
            typed_option_value(VI_VENDOR_CLASS, &payload)
                .unwrap()
                .unwrap(),
            vivco_value,
        );
        assert_eq!(decode_vi_vendor_class(&payload).unwrap(), vivco);

        // RFC 3925 option 125 (V-I Vendor-Specific Information): enterprise
        // number, data-len, then nested code/length/value suboptions.
        let vivso = vec![DhcpVendorIdentifyingOption::new(
            3561,
            vec![
                DhcpVendorSuboption::new(1, vec![0x01, 0x02, 0x03]),
                DhcpVendorSuboption::new(2, b"opaque".to_vec()),
            ],
        )];
        let vivso_value = DhcpOptionValue::ViVendorSpecific(vivso.clone());
        let payload = vivso_value.encode_payload();
        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(&3561u32.to_be_bytes());
        // option-data: subopt1 (code 1, len 3, data) + subopt2 (code 2, len 6,
        // "opaque") = 5 + 8 = 13 octets.
        expected.push(13);
        expected.extend_from_slice(&[1, 3, 0x01, 0x02, 0x03]);
        expected.push(2);
        expected.push(6);
        expected.extend_from_slice(b"opaque");
        assert_eq!(payload, expected);
        assert_eq!(
            typed_option_value(VI_VENDOR_SPECIFIC, &payload)
                .unwrap()
                .unwrap(),
            vivso_value,
        );
        assert_eq!(decode_vi_vendor_specific(&payload).unwrap(), vivso);

        // Full packet round-trip through the typed builders and accessors.
        let parsed = build_and_decode(vec![
            DhcpOption::vi_vendor_class(vivco.clone()),
            DhcpOption::vi_vendor_specific(vivso.clone()),
            DhcpOption::End,
        ]);
        assert_eq!(parsed.vi_vendor_class().unwrap().unwrap(), vivco);
        assert_eq!(parsed.vi_vendor_specific().unwrap().unwrap(), vivso);
        recompile_is_stable(&parsed);

        // Vendor-specific (43) and vendor class id (60) stay opaque, preserving
        // the exact bytes the caller supplied.
        let opaque = vec![0x01, 0xff, 0x00, 0xab];
        let parsed = build_and_decode(vec![
            DhcpOption::vendor_specific(opaque.clone()),
            DhcpOption::vendor_class_identifier(b"MSFT 5.0".to_vec()),
            DhcpOption::End,
        ]);
        assert_eq!(parsed.vendor_specific_information().unwrap(), opaque);
        assert_eq!(
            parsed.vendor_class_identifier().unwrap(),
            b"MSFT 5.0".to_vec(),
        );

        // Truncated and malformed V-I payloads are structured errors, not
        // panics.
        // Enterprise number present but no data-len octet.
        assert!(matches!(
            typed_option_value(VI_VENDOR_CLASS, &3561u32.to_be_bytes()),
            Err(CrafterError::BufferTooShort { .. }),
        ));
        // data-len claims more bytes than remain.
        let bad = {
            let mut bytes = 3561u32.to_be_bytes().to_vec();
            bytes.push(5);
            bytes.extend_from_slice(&[1, 2]);
            bytes
        };
        assert!(matches!(
            decode_vi_vendor_class(&bad),
            Err(CrafterError::BufferTooShort { .. }),
        ));
        // Nested suboption length runs past the instance.
        let bad_subopt = {
            let mut bytes = 3561u32.to_be_bytes().to_vec();
            bytes.push(3); // option-data len
            bytes.extend_from_slice(&[7, 9, 0xaa]); // subopt code 7, len 9, only 1 byte
            bytes
        };
        assert!(matches!(
            decode_vi_vendor_specific(&bad_subopt),
            Err(CrafterError::BufferTooShort { .. }),
        ));
    }

    #[test]
    fn dhcp_pxe_architecture_options_roundtrip() {
        // RFC 4578 option 93 (Client System Architecture): a list of 16-bit
        // architecture type values. 0 = Intel x86PC, 7 = EFI BC, 9 = EFI x86-64.
        let arch = ClientSystemArchitecture::new(vec![0u16, 7, 9]);
        let arch_value = DhcpOptionValue::ClientSystemArchitecture(arch.clone());
        let payload = arch_value.encode_payload();
        assert_eq!(payload, vec![0, 0, 0, 7, 0, 9]);
        assert_eq!(
            typed_option_value(CLIENT_ARCH, &payload).unwrap().unwrap(),
            arch_value,
        );
        assert_eq!(decode_client_system_architecture(&payload).unwrap(), arch);
        // Odd length is rejected as a structured error (must be a multiple of 2).
        assert!(matches!(
            typed_option_value(CLIENT_ARCH, &[0, 7, 9]),
            Err(CrafterError::InvalidFieldValue { .. }),
        ));

        // RFC 4578 option 94 (Client Network Device Interface): type/major/minor.
        let ndi = ClientNetworkDeviceInterface::undi(2, 1);
        let ndi_value = DhcpOptionValue::ClientNetworkDeviceInterface(ndi);
        let payload = ndi_value.encode_payload();
        assert_eq!(payload, vec![1, 2, 1]);
        assert_eq!(
            typed_option_value(CLIENT_NDI, &payload).unwrap().unwrap(),
            ndi_value,
        );
        assert_eq!(decode_client_ndi(&payload).unwrap(), ndi);
        // Any length other than three is a structured error.
        assert!(matches!(
            typed_option_value(CLIENT_NDI, &[1, 2]),
            Err(CrafterError::InvalidFieldValue { .. }),
        ));

        // RFC 4578 option 97 (UUID/GUID client identifier): type 0 + 16-octet
        // GUID.
        let guid: Vec<u8> = (0u8..16).collect();
        let uuid = DhcpClientUuid::guid(guid.clone());
        let uuid_value = DhcpOptionValue::ClientUuid(uuid.clone());
        let payload = uuid_value.encode_payload();
        assert_eq!(payload.len(), 17);
        assert_eq!(payload[0], 0);
        assert_eq!(&payload[1..], guid.as_slice());
        assert_eq!(
            typed_option_value(CLIENT_UUID, &payload).unwrap().unwrap(),
            uuid_value,
        );
        assert_eq!(decode_client_uuid(&payload).unwrap(), uuid);
        // Empty payload (no type octet) is a structured error.
        assert!(matches!(
            typed_option_value(CLIENT_UUID, &[]),
            Err(CrafterError::BufferTooShort { .. }),
        ));

        // Full packet round-trip through builders and accessors.
        let parsed = build_and_decode(vec![
            DhcpOption::client_system_architecture(arch.clone()),
            DhcpOption::client_network_device_interface(ndi),
            DhcpOption::client_uuid(uuid.clone()),
            DhcpOption::pxelinux_magic(),
            DhcpOption::pxelinux_config_file(b"pxelinux.cfg/default".to_vec()),
            DhcpOption::pxelinux_path_prefix(b"tftp://192.0.2.1/".to_vec()),
            DhcpOption::pxelinux_reboot_time(30),
            DhcpOption::End,
        ]);
        assert_eq!(parsed.client_system_architecture().unwrap().unwrap(), arch,);
        assert_eq!(
            parsed.client_network_device_interface().unwrap().unwrap(),
            ndi,
        );
        assert_eq!(parsed.client_uuid().unwrap().unwrap(), uuid);

        // RFC 5071 PXELINUX options 208-211.
        assert_eq!(
            parsed.pxelinux_magic().unwrap(),
            vec![0xF1, 0x00, 0x74, 0x7E]
        );
        assert_eq!(
            parsed.pxelinux_config_file().unwrap(),
            b"pxelinux.cfg/default".to_vec(),
        );
        assert_eq!(
            parsed.pxelinux_path_prefix().unwrap(),
            b"tftp://192.0.2.1/".to_vec(),
        );
        assert_eq!(parsed.pxelinux_reboot_time().unwrap().unwrap(), 30);
        recompile_is_stable(&parsed);
    }

    #[test]
    fn dhcp_user_class_roundtrip() {
        // RFC 3004 option 77: one or more length-prefixed opaque class
        // instances.
        let user_class = DhcpUserClass::new(vec![b"iPXE".to_vec(), b"linux-install".to_vec()]);
        let value = DhcpOptionValue::UserClass(user_class.clone());
        let payload = value.encode_payload();
        let mut expected = vec![4u8];
        expected.extend_from_slice(b"iPXE");
        expected.push(13);
        expected.extend_from_slice(b"linux-install");
        assert_eq!(payload, expected);
        assert_eq!(
            typed_option_value(USER_CLASS, &payload).unwrap().unwrap(),
            value,
        );
        assert_eq!(decode_user_class(&payload).unwrap(), user_class);

        // Full packet round-trip and accessor.
        let parsed = build_and_decode(vec![
            DhcpOption::user_class(user_class.clone()),
            DhcpOption::End,
        ]);
        assert_eq!(parsed.user_class().unwrap().unwrap(), user_class);
        recompile_is_stable(&parsed);

        // A zero-length instance is malformed per RFC 3004 (errata) and surfaces
        // as a structured error rather than a panic.
        assert!(matches!(
            decode_user_class(&[0]),
            Err(CrafterError::InvalidFieldValue { .. }),
        ));
        // An instance length that runs past the data is a structured error.
        assert!(matches!(
            decode_user_class(&[5, b'a', b'b']),
            Err(CrafterError::BufferTooShort { .. }),
        ));
    }

    #[test]
    fn dhcp_tftp_and_bootfile_options_roundtrip() {
        // RFC 2132 options 66/67 are NVT ASCII strings carried as raw bytes.
        let parsed = build_and_decode(vec![
            DhcpOption::tftp_server_name(b"tftp.example.com".to_vec()),
            DhcpOption::bootfile_name(b"undionly.kpxe".to_vec()),
            DhcpOption::End,
        ]);
        assert_eq!(
            parsed.tftp_server_name().unwrap(),
            b"tftp.example.com".to_vec(),
        );
        assert_eq!(parsed.bootfile_name().unwrap(), b"undionly.kpxe".to_vec());
        recompile_is_stable(&parsed);

        // RFC 5859 option 150 (TFTP server address) is an IPv4 address list.
        // Code 150 is ambiguous in the registry, so the default decode leaves it
        // raw; the explicit accessor applies the RFC 5859 interpretation.
        let addresses = vec![ip(192, 0, 2, 10), ip(198, 51, 100, 10)];
        let parsed = build_and_decode(vec![
            DhcpOption::tftp_server_addresses(addresses.clone()),
            DhcpOption::End,
        ]);
        assert_eq!(parsed.tftp_server_addresses().unwrap().unwrap(), addresses);
        // The same option stays opaque to the default typed decoder.
        assert!(typed_option_value(TFTP_SERVER_ADDRESS, &[192, 0, 2, 10])
            .unwrap()
            .is_none());
        recompile_is_stable(&parsed);

        // A length not a multiple of four is a structured error, never a panic.
        assert!(matches!(
            decode_tftp_server_addresses(&[192, 0, 2]),
            Err(CrafterError::InvalidFieldValue { .. }),
        ));
        assert!(matches!(
            decode_tftp_server_addresses(&[]),
            Err(CrafterError::InvalidFieldValue { .. }),
        ));

        // Options 43 and 60 codepoints are referenced in this module's tests; the
        // constants are pinned to their IANA values here for clarity.
        assert_eq!(VENDOR_SPECIFIC, 43);
        assert_eq!(VENDOR_CLASS_ID, 60);
        assert_eq!(TFTP_SERVER_NAME, 66);
        assert_eq!(BOOTFILE_NAME, 67);
    }
}

#[cfg(test)]
mod dhcp_relay_agent {
    use super::super::{
        scan_dhcp_option_segments, Dhcp, DhcpMessageType, DhcpOption, DhcpOptionArea,
        DhcpRelayAgentInfo, DhcpRelaySuboption, DhcpRelayVendorSpecific, DhcpVssInfo,
    };
    use super::{decode_relay_agent_information, typed_option_value, DhcpOptionValue};
    use crate::error::CrafterError;
    use core::net::Ipv4Addr;

    const RELAY_AGENT_INFORMATION: u8 = super::super::DHCP_OPTION_RELAY_AGENT_INFORMATION; // 82

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn build_and_decode(options: Vec<DhcpOption>) -> Dhcp {
        let dhcp = Dhcp::new()
            .op(super::super::BOOTP_REPLY)
            .message_type(DhcpMessageType::Ack)
            .options(options);
        let bytes = crate::Packet::from_layer(dhcp)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        Dhcp::decode(&bytes).unwrap()
    }

    fn recompile_is_stable(parsed: &Dhcp) {
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
    }

    #[test]
    fn dhcp_relay_agent_option82_roundtrips_suboptions() {
        // RFC 3046 option 82 is a container for relay-agent sub-options, each a
        // code/length/value triple with no pad and no end marker. Every
        // registered sub-option whose wire format is specified by the IANA
        // "DHCP Relay Agent Sub-Option Codes" registry is exercised here, plus an
        // unknown sub-option that must be preserved verbatim.
        let info = DhcpRelayAgentInfo::new(vec![
            // Sub-option 1 / 2 (RFC 3046): opaque relay-defined bytes.
            DhcpRelaySuboption::circuit_id(b"eth0:vlan100".to_vec()),
            DhcpRelaySuboption::remote_id(vec![0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef]),
            // Sub-option 4 (RFC 3256): 32-bit DOCSIS device class bitfield.
            DhcpRelaySuboption::DocsisDeviceClass(0x0000_0001),
            // Sub-option 5 (RFC 3527): subnet IPv4 link selection address.
            DhcpRelaySuboption::LinkSelection(ip(192, 0, 2, 0)),
            // Sub-option 6 (RFC 3993): opaque NVT ASCII subscriber id.
            DhcpRelaySuboption::subscriber_id(b"sub-42".to_vec()),
            // Sub-option 7 (RFC 4014): opaque RADIUS attributes.
            DhcpRelaySuboption::RadiusAttributes(vec![0x01, 0x06, 0x00, 0x00, 0x00, 0x2a]),
            // Sub-option 8 (RFC 4030): opaque authentication payload.
            DhcpRelaySuboption::Authentication(vec![0x01, 0x00, 0x00, 0x00]),
            // Sub-option 9 (RFC 4243): enterprise-number plus opaque-data tuples.
            DhcpRelaySuboption::VendorSpecific(vec![
                DhcpRelayVendorSpecific::new(3561, vec![0xde, 0xad]),
                DhcpRelayVendorSpecific::new(311, b"v".to_vec()),
            ]),
            // Sub-option 10 (RFC 5010): one-octet flags (Unicast bit set).
            DhcpRelaySuboption::RelayFlags(super::super::DHCP_RELAY_FLAG_UNICAST),
            // Sub-option 11 (RFC 5107): 4-octet server-id override address.
            DhcpRelaySuboption::ServerIdOverride(ip(192, 0, 2, 1)),
            // Sub-option 12 (RFC 6925): opaque relay agent identifier.
            DhcpRelaySuboption::relay_agent_id(vec![0xab, 0xcd]),
            // Sub-option 19 (RFC 8357): zero-length relay source port flag.
            DhcpRelaySuboption::RelaySourcePort,
            // Sub-option 151 (RFC 6607): VSS type octet plus VSS information.
            DhcpRelaySuboption::Vss(DhcpVssInfo::nvt_ascii(b"vpn-blue".to_vec())),
            // Sub-option 152 (RFC 6607): zero-length VSS control.
            DhcpRelaySuboption::VssControl,
            // An unknown/reserved sub-option is preserved verbatim.
            DhcpRelaySuboption::other(200, vec![0x01, 0x02, 0x03]),
        ]);

        // The typed value encodes to RFC 3046 sub-option layout and decodes back
        // losslessly.
        let value = DhcpOptionValue::RelayAgentInformation(info.clone());
        let payload = value.encode_payload();
        assert_eq!(
            decode_relay_agent_information(&payload).unwrap(),
            info,
            "relay agent information must round-trip through the codec",
        );
        assert_eq!(
            typed_option_value(RELAY_AGENT_INFORMATION, &payload)
                .unwrap()
                .unwrap(),
            value,
        );

        // The relay source port and VSS control sub-options are zero-length.
        let relay_port = info.suboption(19).unwrap().encode_value();
        assert!(relay_port.is_empty(), "relay source port carries no value");

        // Full packet round-trip through the typed builder and accessor.
        let parsed = build_and_decode(vec![
            DhcpOption::relay_agent_information(info.clone()),
            DhcpOption::End,
        ]);
        let decoded = parsed.relay_agent_information().unwrap().unwrap();
        assert_eq!(decoded, info);
        // The unknown sub-option is preserved with its exact code and data.
        assert_eq!(
            decoded.suboption(200),
            Some(&DhcpRelaySuboption::other(200, vec![0x01, 0x02, 0x03])),
        );
        recompile_is_stable(&parsed);
    }

    #[test]
    fn dhcp_relay_agent_option82_rejects_truncated_suboption() {
        // A sub-option length that runs past the end of the option is a
        // structured error, never a panic. Code 1 (circuit id), declared length
        // 5, but only two value octets present.
        let truncated = [1u8, 5, 0xaa, 0xbb];
        assert!(matches!(
            decode_relay_agent_information(&truncated),
            Err(CrafterError::BufferTooShort { .. }),
        ));
        // The same surfaces through typed_option_value without panicking.
        assert!(typed_option_value(RELAY_AGENT_INFORMATION, &truncated).is_err());

        // A sub-option header missing its length octet is also rejected.
        let no_len = [1u8];
        assert!(matches!(
            decode_relay_agent_information(&no_len),
            Err(CrafterError::BufferTooShort { .. }),
        ));

        // Fixed-width sub-options reject wrong lengths: link selection (code 5)
        // must be exactly four octets, and relay source port (code 19) must be
        // zero-length.
        assert!(matches!(
            decode_relay_agent_information(&[5, 3, 192, 0, 2]),
            Err(CrafterError::InvalidFieldValue { .. }),
        ));
        assert!(matches!(
            decode_relay_agent_information(&[19, 2, 0x00, 0x43]),
            Err(CrafterError::InvalidFieldValue { .. }),
        ));
    }

    #[test]
    fn dhcp_relay_agent_option82_unknown_suboptions_preserved() {
        // Unknown and reserved relay sub-option codes (here code 3, which RFC
        // 3046 reserves, and code 99, unassigned) are preserved as raw code and
        // data so no bytes are lost and the option re-encodes byte-exactly.
        let info = DhcpRelayAgentInfo::new(vec![
            DhcpRelaySuboption::other(3, vec![0xca, 0xfe]),
            DhcpRelaySuboption::other(99, b"private".to_vec()),
        ]);
        let payload = DhcpOptionValue::RelayAgentInformation(info.clone()).encode_payload();
        // Wire layout: code, len, data per sub-option.
        assert_eq!(
            payload,
            vec![3, 2, 0xca, 0xfe, 99, 7, b'p', b'r', b'i', b'v', b'a', b't', b'e'],
        );
        assert_eq!(decode_relay_agent_information(&payload).unwrap(), info);

        let parsed = build_and_decode(vec![
            DhcpOption::relay_agent_information(info.clone()),
            DhcpOption::End,
        ]);
        assert_eq!(parsed.relay_agent_information().unwrap().unwrap(), info);
        recompile_is_stable(&parsed);
    }

    #[test]
    fn dhcp_relay_agent_option82_overload_and_long_options() {
        // Option 52 overload: option 82 carried in the overloaded `file` field
        // must surface through the cross-area accessor and re-encode consistently.
        let info = DhcpRelayAgentInfo::new(vec![
            DhcpRelaySuboption::circuit_id(b"port-7".to_vec()),
            DhcpRelaySuboption::ServerIdOverride(ip(198, 51, 100, 1)),
        ]);
        let dhcp = Dhcp::new()
            .op(super::super::BOOTP_REPLY)
            .message_type(DhcpMessageType::Ack)
            .file_options(vec![DhcpOption::relay_agent_information(info.clone())]);
        let bytes = crate::Packet::from_layer(dhcp)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let parsed = Dhcp::decode(&bytes).unwrap();
        assert_eq!(parsed.relay_agent_information().unwrap().unwrap(), info);
        recompile_is_stable(&parsed);

        // RFC 3396 long-option splitting: a relay option whose payload exceeds
        // 255 octets is split across repeated option-82 segments and reassembled
        // into one logical value. The option-82 length is the single octet that
        // overflows, so several sub-options (each <=255 octets) are combined to
        // push the total option payload past one segment.
        let big_info = DhcpRelayAgentInfo::new(vec![
            DhcpRelaySuboption::circuit_id(vec![0x5au8; 200]),
            DhcpRelaySuboption::remote_id(vec![0xa5u8; 200]),
        ]);
        let payload = DhcpOptionValue::RelayAgentInformation(big_info.clone()).encode_payload();
        assert!(payload.len() > 255, "payload must exceed one segment");
        let parsed = build_and_decode(vec![
            DhcpOption::relay_agent_information(big_info.clone()),
            DhcpOption::End,
        ]);
        // The raw wire form is split into more than one option-82 segment, while
        // decode (RFC 3396) concatenates them into one logical option.
        let encoded = parsed.encoded_options().unwrap();
        let segments = scan_dhcp_option_segments(DhcpOptionArea::Options, &encoded)
            .unwrap()
            .into_iter()
            .filter(|seg| seg.code_value() == RELAY_AGENT_INFORMATION)
            .count();
        assert!(
            segments >= 2,
            "an over-long relay option must split into multiple wire segments",
        );
        // The cross-area accessor reassembles the segments into one logical value.
        assert_eq!(parsed.relay_agent_information().unwrap().unwrap(), big_info);
        recompile_is_stable(&parsed);

        // The codepoint is pinned to its IANA value for clarity.
        assert_eq!(RELAY_AGENT_INFORMATION, 82);
    }
}

#[cfg(test)]
mod dhcp_client_identifier {
    use super::super::{Dhcp, DhcpClientIdentifier, DhcpMessageType, DhcpOption, DhcpOptionValue};
    use super::{decode_client_identifier, typed_option_value};
    use crate::error::CrafterError;

    const CLIENT_IDENTIFIER: u8 = super::super::DHCP_OPTION_CLIENT_IDENTIFIER; // 61

    fn build_and_decode(option: DhcpOption) -> Dhcp {
        let dhcp = Dhcp::new()
            .op(super::super::BOOTP_REQUEST)
            .message_type(DhcpMessageType::Request)
            .options(vec![option, DhcpOption::End]);
        let bytes = crate::Packet::from_layer(dhcp)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        Dhcp::decode(&bytes).unwrap()
    }

    fn recompile_is_stable(parsed: &Dhcp) {
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
    }

    #[test]
    fn dhcp_client_identifier_legacy_mac_roundtrip() {
        // RFC 2132 section 9.14: the common client identifier is a hardware type
        // (1 = Ethernet) followed by a 6-octet MAC address.
        let mac = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01];
        let identifier = DhcpClientIdentifier::ethernet_mac(mac);
        assert_eq!(identifier.type_octet(), Some(1));

        // The typed value encodes to the option-61 wire layout (type octet plus
        // address) and decodes back losslessly.
        let value = DhcpOptionValue::ClientIdentifier(identifier.clone());
        let payload = value.encode_payload();
        assert_eq!(payload, vec![0x01, 0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]);
        assert_eq!(decode_client_identifier(&payload).unwrap(), identifier);
        assert_eq!(
            typed_option_value(CLIENT_IDENTIFIER, &payload)
                .unwrap()
                .unwrap(),
            value,
        );

        // Full packet round-trip through the typed builder and the accessor,
        // which surfaces the identifier independently from chaddr.
        let parsed = build_and_decode(DhcpOption::client_identifier_value(identifier.clone()));
        assert_eq!(
            parsed.client_identifier_value().unwrap().unwrap(),
            identifier,
        );
        recompile_is_stable(&parsed);

        // The legacy raw-byte constructor produces the same wire bytes.
        let raw = build_and_decode(DhcpOption::client_identifier(payload.clone()));
        assert_eq!(raw.client_identifier_value().unwrap().unwrap(), identifier);
    }

    #[test]
    fn dhcp_client_identifier_rfc4361_roundtrip() {
        // RFC 4361 section 6.1: type 255, a 4-octet IAID, then a DUID. The DUID
        // here is a DUID-LLT (type 1) carrying a hardware type, a 4-octet time,
        // and a 6-octet link-layer address, but the codec preserves it verbatim.
        let iaid = 0x0102_0304u32;
        let duid = vec![
            0x00, 0x01, // DUID type 1 (DUID-LLT)
            0x00, 0x01, // hardware type 1 (Ethernet)
            0x12, 0x34, 0x56, 0x78, // DUID time
            0x02, 0x00, 0x5e, 0x10, 0x00, 0x01, // link-layer address
        ];
        let identifier = DhcpClientIdentifier::node_specific(iaid, duid.clone());
        assert_eq!(identifier.type_octet(), Some(255));

        // The encoded payload is type 255 + IAID + DUID.
        let value = DhcpOptionValue::ClientIdentifier(identifier.clone());
        let payload = value.encode_payload();
        assert_eq!(payload[0], 255, "RFC 4361 identifier uses type 255");
        assert_eq!(&payload[1..5], &iaid.to_be_bytes(), "IAID is 4 octets");
        assert_eq!(&payload[5..], duid.as_slice(), "DUID follows the IAID");

        assert_eq!(decode_client_identifier(&payload).unwrap(), identifier);
        assert_eq!(
            typed_option_value(CLIENT_IDENTIFIER, &payload)
                .unwrap()
                .unwrap(),
            value,
        );

        // Full packet round-trip through the typed builder and accessor.
        let parsed = build_and_decode(DhcpOption::client_identifier_value(identifier.clone()));
        assert_eq!(
            parsed.client_identifier_value().unwrap().unwrap(),
            identifier,
        );
        recompile_is_stable(&parsed);
    }

    #[test]
    fn dhcp_client_identifier_raw_unknown_forms_preserved() {
        // A type-0 (non-hardware) identifier per RFC 2132 (for example a
        // fully-qualified domain name) has no specified internal structure, so
        // the whole payload is preserved verbatim including the type octet.
        let fqdn_payload = {
            let mut bytes = vec![0u8];
            bytes.extend_from_slice(b"host.example.com");
            bytes
        };
        let decoded = decode_client_identifier(&fqdn_payload).unwrap();
        assert_eq!(decoded, DhcpClientIdentifier::Raw(fqdn_payload.clone()));
        let parsed = build_and_decode(DhcpOption::client_identifier(fqdn_payload.clone()));
        assert_eq!(
            parsed.client_identifier_value().unwrap().unwrap(),
            DhcpClientIdentifier::Raw(fqdn_payload),
        );

        // An empty payload carries no type octet and round-trips as empty raw.
        assert_eq!(
            decode_client_identifier(&[]).unwrap(),
            DhcpClientIdentifier::Raw(Vec::new()),
        );

        // The Raw constructor encodes its bytes verbatim (no synthesized type).
        let raw = DhcpClientIdentifier::raw(vec![0x07, 0xaa, 0xbb]);
        assert_eq!(raw.encode(), vec![0x07, 0xaa, 0xbb]);
        assert_eq!(raw.type_octet(), Some(0x07));

        // A type-255 RFC 4361 identifier with fewer than four IAID octets is a
        // structured error, never a panic.
        let truncated = [255u8, 0x01, 0x02, 0x03];
        assert!(matches!(
            decode_client_identifier(&truncated),
            Err(CrafterError::BufferTooShort { .. }),
        ));
    }

    #[test]
    fn dhcp_client_identifier_server_reply_echo() {
        // RFC 6842: a server MUST return the client identifier option, unaltered,
        // in its reply. The crate models this as packet data, so a reply (op =
        // BOOTREPLY, message type ACK) can carry exactly what the client sent.
        let identifier =
            DhcpClientIdentifier::node_specific(0xdead_beef, vec![0x00, 0x03, 0x00, 0x01, 0x11]);
        let request_payload =
            DhcpOptionValue::ClientIdentifier(identifier.clone()).encode_payload();

        let reply = Dhcp::new()
            .op(super::super::BOOTP_REPLY)
            .message_type(DhcpMessageType::Ack)
            .options(vec![
                DhcpOption::client_identifier_value(identifier.clone()),
                DhcpOption::End,
            ]);
        let bytes = crate::Packet::from_layer(reply)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let parsed = Dhcp::decode(&bytes).unwrap();

        // The server reply echoes the identifier unaltered.
        let echoed = parsed.client_identifier_value().unwrap().unwrap();
        assert_eq!(echoed, identifier);
        assert_eq!(echoed.encode(), request_payload);
        recompile_is_stable(&parsed);

        // The codepoint is pinned to its IANA value for clarity.
        assert_eq!(CLIENT_IDENTIFIER, 61);
    }
}

#[cfg(test)]
mod dhcp_authentication {
    use super::super::{
        Dhcp, DhcpAuthAlgorithm, DhcpAuthProtocol, DhcpAuthentication, DhcpForcerenewNonceCapable,
        DhcpMessageType, DhcpOption, DhcpOptionValue, DhcpReplayDetectionMethod,
    };
    use super::{decode_authentication, typed_option_value};
    use crate::error::CrafterError;

    const AUTHENTICATION: u8 = super::super::DHCP_OPTION_AUTHENTICATION; // 90
    const FORCERENEW_NONCE_CAPABLE: u8 = super::super::DHCP_OPTION_FORCERENEW_NONCE_CAPABLE; // 145

    fn build_and_decode(options: Vec<DhcpOption>) -> Dhcp {
        let dhcp = Dhcp::new()
            .op(super::super::BOOTP_REQUEST)
            .message_type(DhcpMessageType::Request)
            .options(options);
        let bytes = crate::Packet::from_layer(dhcp)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        Dhcp::decode(&bytes).unwrap()
    }

    fn recompile_is_stable(parsed: &Dhcp) {
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
    }

    #[test]
    fn dhcp_authentication_option_roundtrip() {
        // RFC 3118 section 2: the delayed-authentication option carries a typed
        // 11-octet header (Protocol 1, Algorithm 1 = HMAC-MD5, RDM 0 =
        // monotonic counter, an 8-octet Replay Detection value) followed by the
        // Authentication Information (here a 4-octet Secret ID plus a 16-octet
        // HMAC-MD5 digest). The crate models these as packet fields only; the
        // digest bytes below are arbitrary documentation values, not a real MAC.
        let secret_id = [0x00, 0x00, 0x00, 0x2a];
        let digest = [0xABu8; 16];
        let mut auth_info = Vec::new();
        auth_info.extend_from_slice(&secret_id);
        auth_info.extend_from_slice(&digest);
        let auth = DhcpAuthentication::new(
            DhcpAuthProtocol::Delayed,
            DhcpAuthAlgorithm::HmacMd5,
            DhcpReplayDetectionMethod::MonotonicCounter,
            0x0102_0304_0506_0708,
            auth_info.clone(),
        );

        // The typed value encodes to the RFC 3118 wire layout and decodes back
        // losslessly.
        let value = DhcpOptionValue::Authentication(auth.clone());
        let payload = value.encode_payload();
        let mut expected = vec![1u8, 1, 0]; // Protocol, Algorithm, RDM
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        expected.extend_from_slice(&auth_info);
        assert_eq!(payload, expected);
        assert_eq!(decode_authentication(&payload).unwrap(), auth);
        assert_eq!(
            typed_option_value(AUTHENTICATION, &payload)
                .unwrap()
                .unwrap(),
            value,
        );

        // Full packet round-trip through the typed builder and the cross-area
        // accessor.
        let parsed = build_and_decode(vec![
            DhcpOption::authentication(auth.clone()),
            DhcpOption::End,
        ]);
        let decoded = parsed.authentication().unwrap().unwrap();
        assert_eq!(decoded, auth);
        assert_eq!(decoded.authentication_information, auth_info);
        recompile_is_stable(&parsed);

        // The codepoint is pinned to its IANA value for clarity.
        assert_eq!(AUTHENTICATION, 90);
    }

    #[test]
    fn dhcp_authentication_unknown_codes_preserved() {
        // RFC 3118 leaves most Protocol, Algorithm, and RDM values unassigned.
        // Unknown values in any of those fields are preserved verbatim rather
        // than coerced, and the authentication information stays raw.
        let auth = DhcpAuthentication::new(
            DhcpAuthProtocol::Unknown(0x7f),
            DhcpAuthAlgorithm::Unknown(0x42),
            DhcpReplayDetectionMethod::Unknown(0x99),
            0,
            vec![0xde, 0xad, 0xbe, 0xef],
        );
        let payload = DhcpOptionValue::Authentication(auth.clone()).encode_payload();
        assert_eq!(payload[0], 0x7f, "unknown Protocol preserved");
        assert_eq!(payload[1], 0x42, "unknown Algorithm preserved");
        assert_eq!(payload[2], 0x99, "unknown RDM preserved");

        let decoded = decode_authentication(&payload).unwrap();
        assert_eq!(decoded, auth);
        // The unknown octets re-classify back to their numeric value.
        assert_eq!(decoded.protocol.code(), 0x7f);
        assert_eq!(decoded.algorithm.code(), 0x42);
        assert_eq!(decoded.rdm.code(), 0x99);

        let parsed = build_and_decode(vec![
            DhcpOption::authentication(auth.clone()),
            DhcpOption::End,
        ]);
        assert_eq!(parsed.authentication().unwrap().unwrap(), auth);
        recompile_is_stable(&parsed);
    }

    #[test]
    fn dhcp_authentication_malformed_lengths_are_structured() {
        // RFC 3118 section 2: the option must carry at least the 11-octet header
        // (Protocol, Algorithm, RDM, and the 8-octet Replay Detection field). A
        // payload shorter than that is a structured BufferTooShort error, never
        // a panic, on both the decode helper and the typed dispatch.
        for len in 0..super::super::DHCP_AUTH_HEADER_LEN {
            let short = vec![0u8; len];
            assert!(
                matches!(
                    decode_authentication(&short),
                    Err(CrafterError::BufferTooShort { .. }),
                ),
                "len {len} must be rejected",
            );
            assert!(typed_option_value(AUTHENTICATION, &short).is_err());
        }

        // A payload of exactly the header length is valid with empty auth info.
        let header_only = vec![1u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let decoded = decode_authentication(&header_only).unwrap();
        assert!(decoded.authentication_information.is_empty());
        assert_eq!(decoded.encode(), header_only);
    }

    #[test]
    fn dhcp_forcerenew_nonce_capable_option_parsing() {
        // RFC 6704 section 4: the FORCERENEW_NONCE_CAPABLE option (145) carries
        // the list of supported authentication algorithm octets. HMAC-MD5 is
        // algorithm 1.
        let value = DhcpForcerenewNonceCapable::hmac_md5();
        assert_eq!(value.algorithms, vec![1]);
        let payload = DhcpOptionValue::ForcerenewNonceCapable(value.clone()).encode_payload();
        assert_eq!(payload, vec![1]);
        assert_eq!(
            typed_option_value(FORCERENEW_NONCE_CAPABLE, &payload)
                .unwrap()
                .unwrap(),
            DhcpOptionValue::ForcerenewNonceCapable(value.clone()),
        );

        // Multiple algorithm octets (including unspecified values) round-trip.
        let multi = DhcpForcerenewNonceCapable::new(vec![1, 2, 0xff]);
        let parsed = build_and_decode(vec![
            DhcpOption::forcerenew_nonce_capable(multi.clone()),
            DhcpOption::End,
        ]);
        assert_eq!(parsed.forcerenew_nonce_capable().unwrap().unwrap(), multi);
        recompile_is_stable(&parsed);

        // An empty algorithm list (zero-length option) is valid and parses to an
        // empty list rather than panicking.
        assert_eq!(
            typed_option_value(FORCERENEW_NONCE_CAPABLE, &[])
                .unwrap()
                .unwrap(),
            DhcpOptionValue::ForcerenewNonceCapable(DhcpForcerenewNonceCapable::default()),
        );

        // The codepoint is pinned to its IANA value for clarity.
        assert_eq!(FORCERENEW_NONCE_CAPABLE, 145);
    }
}

#[cfg(test)]
mod dhcp_leasequery {
    use super::super::{
        Dhcp, DhcpDataSource, DhcpMessageType, DhcpOption, DhcpOptionValue, DhcpState,
        DhcpStatusCode, DhcpStatusCodeOption,
    };
    use super::typed_option_value;
    use crate::error::CrafterError;
    use core::net::Ipv4Addr;

    const CLIENT_LAST_TRANSACTION_TIME: u8 = super::super::DHCP_OPTION_CLIENT_LAST_TRANSACTION_TIME; // 91
    const ASSOCIATED_IP: u8 = super::super::DHCP_OPTION_ASSOCIATED_IP; // 92
    const STATUS_CODE: u8 = super::super::DHCP_OPTION_STATUS_CODE; // 151
    const BASE_TIME: u8 = super::super::DHCP_OPTION_BASE_TIME; // 152
    const START_TIME_OF_STATE: u8 = super::super::DHCP_OPTION_START_TIME_OF_STATE; // 153
    const QUERY_START_TIME: u8 = super::super::DHCP_OPTION_QUERY_START_TIME; // 154
    const QUERY_END_TIME: u8 = super::super::DHCP_OPTION_QUERY_END_TIME; // 155
    const DHCP_STATE: u8 = super::super::DHCP_OPTION_DHCP_STATE; // 156
    const DATA_SOURCE: u8 = super::super::DHCP_OPTION_DATA_SOURCE; // 157

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn build_and_decode(options: Vec<DhcpOption>) -> Dhcp {
        let dhcp = Dhcp::new()
            .op(super::super::BOOTP_REPLY)
            .message_type(DhcpMessageType::LeaseActive)
            .options(options);
        let bytes = crate::Packet::from_layer(dhcp)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        Dhcp::decode(&bytes).unwrap()
    }

    fn recompile_is_stable(parsed: &Dhcp) {
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
    }

    #[test]
    fn dhcp_leasequery_options_roundtrip() {
        // Every leasequery option carries its source-backed wire format without
        // data loss: the RFC 4388 client-last-transaction-time (91) and
        // associated-ip (92); the RFC 6926 status-code (151), base-time (152),
        // start-time-of-state (153), query-start-time (154), query-end-time
        // (155), dhcp-state (156), and data-source (157). Documentation IPv4
        // addresses and arbitrary times are used; no live traffic is involved.
        let status = DhcpStatusCodeOption::new(DhcpStatusCode::Success, b"ok".to_vec());

        // Each typed value encodes to the expected wire layout and decodes back
        // losslessly through the source-backed format dispatch.
        let cases: Vec<(u8, DhcpOptionValue, Vec<u8>)> = vec![
            (
                CLIENT_LAST_TRANSACTION_TIME,
                DhcpOptionValue::U32(3600),
                3600u32.to_be_bytes().to_vec(),
            ),
            (
                ASSOCIATED_IP,
                DhcpOptionValue::Ipv4List(vec![ip(192, 0, 2, 10), ip(198, 51, 100, 20)]),
                vec![192, 0, 2, 10, 198, 51, 100, 20],
            ),
            (
                STATUS_CODE,
                DhcpOptionValue::StatusCode(status.clone()),
                vec![0, b'o', b'k'],
            ),
            (
                BASE_TIME,
                DhcpOptionValue::U32(1_700_000_000),
                1_700_000_000u32.to_be_bytes().to_vec(),
            ),
            (
                START_TIME_OF_STATE,
                DhcpOptionValue::U32(120),
                120u32.to_be_bytes().to_vec(),
            ),
            (
                QUERY_START_TIME,
                DhcpOptionValue::U32(1_699_999_000),
                1_699_999_000u32.to_be_bytes().to_vec(),
            ),
            (
                QUERY_END_TIME,
                DhcpOptionValue::U32(1_700_000_500),
                1_700_000_500u32.to_be_bytes().to_vec(),
            ),
            (
                DHCP_STATE,
                DhcpOptionValue::DhcpState(DhcpState::Active),
                vec![2],
            ),
            (
                DATA_SOURCE,
                DhcpOptionValue::DataSource(DhcpDataSource::from_remote(true)),
                vec![1],
            ),
        ];
        for (code, value, expected) in &cases {
            let payload = value.encode_payload();
            assert_eq!(&payload, expected, "wire payload for code {code}");
            assert_eq!(
                typed_option_value(*code, &payload).unwrap().unwrap(),
                *value,
                "typed decode mismatch for code {code}",
            );
        }

        // Full packet round-trip through the typed builders and the cross-area
        // accessors, with no loss across compile -> decode -> compile.
        let parsed = build_and_decode(vec![
            DhcpOption::client_last_transaction_time(3600),
            DhcpOption::associated_ip(vec![ip(192, 0, 2, 10), ip(198, 51, 100, 20)]),
            DhcpOption::status_code(status.clone()),
            DhcpOption::base_time(1_700_000_000),
            DhcpOption::start_time_of_state(120),
            DhcpOption::query_start_time(1_699_999_000),
            DhcpOption::query_end_time(1_700_000_500),
            DhcpOption::dhcp_state(DhcpState::Active),
            DhcpOption::data_source(DhcpDataSource::from_remote(true)),
            DhcpOption::End,
        ]);
        assert_eq!(
            parsed.client_last_transaction_time().unwrap().unwrap(),
            3600
        );
        assert_eq!(
            parsed.associated_ip().unwrap().unwrap(),
            vec![ip(192, 0, 2, 10), ip(198, 51, 100, 20)],
        );
        let decoded_status = parsed.status_code().unwrap().unwrap();
        assert_eq!(decoded_status.status, DhcpStatusCode::Success);
        assert_eq!(decoded_status.message, b"ok");
        assert_eq!(decoded_status.message_lossy(), "ok");
        assert_eq!(parsed.base_time().unwrap().unwrap(), 1_700_000_000);
        assert_eq!(parsed.start_time_of_state().unwrap().unwrap(), 120);
        assert_eq!(parsed.query_start_time().unwrap().unwrap(), 1_699_999_000);
        assert_eq!(parsed.query_end_time().unwrap().unwrap(), 1_700_000_500);
        assert_eq!(parsed.dhcp_state().unwrap().unwrap(), DhcpState::Active);
        let source = parsed.data_source().unwrap().unwrap();
        assert!(source.is_remote());
        recompile_is_stable(&parsed);

        // The codepoints are pinned to their IANA values for clarity.
        assert_eq!(CLIENT_LAST_TRANSACTION_TIME, 91);
        assert_eq!(ASSOCIATED_IP, 92);
        assert_eq!(STATUS_CODE, 151);
        assert_eq!(BASE_TIME, 152);
        assert_eq!(START_TIME_OF_STATE, 153);
        assert_eq!(QUERY_START_TIME, 154);
        assert_eq!(QUERY_END_TIME, 155);
        assert_eq!(DHCP_STATE, 156);
        assert_eq!(DATA_SOURCE, 157);
    }

    #[test]
    fn dhcp_leasequery_unknown_status_and_state_preserved() {
        // RFC 6926 / RFC 7724 leave most status and state values unassigned; the
        // IANA sub-registries mark 9-255 Unassigned. Unknown values are preserved
        // verbatim through the Unknown variants rather than coerced.
        assert_eq!(DhcpStatusCode::from_code(200), DhcpStatusCode::Unknown(200));
        assert_eq!(DhcpStatusCode::Unknown(200).code(), 200);
        assert_eq!(DhcpState::from_code(99), DhcpState::Unknown(99));
        assert_eq!(DhcpState::Unknown(99).code(), 99);

        // A status-code option with an unassigned status and non-UTF-8 message
        // bytes round-trips with the raw message preserved.
        let status =
            DhcpStatusCodeOption::new(DhcpStatusCode::Unknown(0x40), vec![0xff, 0xfe, 0x00]);
        let payload = DhcpOptionValue::StatusCode(status.clone()).encode_payload();
        assert_eq!(payload, vec![0x40, 0xff, 0xfe, 0x00]);
        assert_eq!(
            typed_option_value(STATUS_CODE, &payload).unwrap().unwrap(),
            DhcpOptionValue::StatusCode(status.clone()),
        );
        let parsed = build_and_decode(vec![
            DhcpOption::status_code(status.clone()),
            DhcpOption::End,
        ]);
        assert_eq!(parsed.status_code().unwrap().unwrap(), status);
        recompile_is_stable(&parsed);

        // An unassigned dhcp-state octet round-trips through the typed value.
        let parsed_state = build_and_decode(vec![
            DhcpOption::dhcp_state(DhcpState::Unknown(0x55)),
            DhcpOption::End,
        ]);
        assert_eq!(
            parsed_state.dhcp_state().unwrap().unwrap(),
            DhcpState::Unknown(0x55),
        );

        // The data-source UNA bits (RFC 6926 section 6.2.8, "MUST be ignored")
        // are preserved verbatim so the octet round-trips exactly, while the
        // typed REMOTE flag is still readable.
        let source = DhcpDataSource::new(0xFE);
        assert!(
            !source.is_remote(),
            "REMOTE bit clear when only UNA bits set"
        );
        assert_eq!(source.encode(), vec![0xFE]);
        let source_remote = DhcpDataSource::new(0xFF);
        assert!(source_remote.is_remote());
        assert_eq!(
            typed_option_value(DATA_SOURCE, &[0xFE]).unwrap().unwrap(),
            DhcpOptionValue::DataSource(DhcpDataSource::new(0xFE)),
        );
    }

    #[test]
    fn dhcp_leasequery_malformed_lengths_are_structured() {
        // Fixed-length leasequery options reject wrong lengths with structured
        // errors rather than panicking. The 4-octet time options (91, 152-155)
        // reject any length other than four; the single-octet state (156) and
        // data-source (157) reject any length other than one; associated-ip (92)
        // requires a non-zero multiple of four; status-code (151) requires at
        // least the one status octet.
        for code in [
            CLIENT_LAST_TRANSACTION_TIME,
            BASE_TIME,
            START_TIME_OF_STATE,
            QUERY_START_TIME,
            QUERY_END_TIME,
        ] {
            for len in [0usize, 1, 2, 3, 5, 8] {
                assert!(
                    typed_option_value(code, &vec![0u8; len]).is_err(),
                    "code {code} len {len} must be rejected",
                );
            }
        }
        for code in [DHCP_STATE, DATA_SOURCE] {
            for len in [0usize, 2, 3] {
                assert!(
                    typed_option_value(code, &vec![0u8; len]).is_err(),
                    "code {code} len {len} must be rejected",
                );
            }
        }
        // associated-ip: a length that is not a non-zero multiple of four.
        for len in [1usize, 2, 3, 5, 7] {
            assert!(typed_option_value(ASSOCIATED_IP, &vec![0u8; len]).is_err());
        }
        // status-code: an empty payload has no status octet.
        assert!(matches!(
            typed_option_value(STATUS_CODE, &[]),
            Err(CrafterError::BufferTooShort { .. }),
        ));
        // status-code: a bare status octet with no message is valid (empty msg).
        let bare = typed_option_value(STATUS_CODE, &[3]).unwrap().unwrap();
        assert_eq!(
            bare,
            DhcpOptionValue::StatusCode(DhcpStatusCodeOption::new(
                DhcpStatusCode::MalformedQuery,
                Vec::new(),
            )),
        );
    }
}

#[cfg(test)]
mod dhcp_remaining_registry {
    use super::super::{
        Dhcp, DhcpMessageType, DhcpOption, DhcpOptionCode, DhcpOptionKind, DhcpOptionStatus,
        DhcpOptionValue,
    };
    use super::typed_option_value;
    use crate::protocols::dhcp::constants::DHCP_IPV6_ONLY_PREFERRED_LEN;

    // Modern registered options with a clear, safely supported wire format.
    const IPV6_ONLY_PREFERRED: u8 = super::super::DHCP_OPTION_IPV6_ONLY_PREFERRED; // 108
    const CAPTIVE_PORTAL: u8 = super::super::DHCP_OPTION_CAPTIVE_PORTAL; // 114
    const MUD_URL: u8 = super::super::DHCP_OPTION_MUD_URL_V4; // 161

    // Modern registered options whose formats are nested/complex and are
    // intentionally preserved as raw bytes for now (PcpServer is a list of
    // length-prefixed address lists, Dnr and SixRd are nested TLV/prefix
    // structures). Their codepoints are still known to the library.
    const PCP_SERVER: u8 = super::super::DHCP_OPTION_V4_PCP_SERVER; // 158 (PcpServer)
    const DNR: u8 = super::super::DHCP_OPTION_V4_DNR; // 162 (Dnr)
    const SIX_RD: u8 = super::super::DHCP_OPTION_6RD; // 212 (SixRd)

    fn build_and_decode(options: Vec<DhcpOption>) -> Dhcp {
        let dhcp = Dhcp::new()
            .op(super::super::BOOTP_REPLY)
            .message_type(DhcpMessageType::Ack)
            .options(options);
        let bytes = crate::Packet::from_layer(dhcp)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        Dhcp::decode(&bytes).unwrap()
    }

    /// Reassembled payload bytes for an option code in a decoded packet.
    fn option_payload(parsed: &Dhcp, code: u8) -> Vec<u8> {
        parsed
            .concatenated_option(code)
            .expect("option present")
            .expect("option decodes")
            .payload()
            .expect("payload bytes")
            .to_vec()
    }

    #[test]
    fn dhcp_modern_registry_options_decode_typed() {
        // RFC 8925 IPv6-Only Preferred (108): a 4-octet V6ONLY_WAIT seconds
        // value decodes to U32 and re-encodes to the exact wire bytes.
        let wait = 1800u32;
        let payload = wait.to_be_bytes().to_vec();
        assert_eq!(payload.len(), DHCP_IPV6_ONLY_PREFERRED_LEN);
        let value = typed_option_value(IPV6_ONLY_PREFERRED, &payload)
            .unwrap()
            .expect("option 108 has a typed value");
        assert_eq!(value, DhcpOptionValue::U32(wait));
        assert_eq!(value.encode_payload(), payload);
        assert_eq!(
            DhcpOptionKind::from_code(IPV6_ONLY_PREFERRED),
            Some(DhcpOptionKind::Ipv6OnlyPreferred),
        );
        // A length other than 4 octets is a structured error, never a panic.
        assert!(typed_option_value(IPV6_ONLY_PREFERRED, &[0u8; 3]).is_err());

        // RFC 8910 Captive-Portal (114) and RFC 8520 MUD URL (161): URI/URL
        // text-like bytes preserved verbatim (not coerced to UTF-8).
        let portal = b"https://portal.example.com/captive".to_vec();
        let captive = typed_option_value(CAPTIVE_PORTAL, &portal)
            .unwrap()
            .expect("option 114 has a typed value");
        assert_eq!(captive, DhcpOptionValue::Text(portal.clone()));
        assert_eq!(captive.encode_payload(), portal);
        assert_eq!(
            DhcpOptionKind::from_code(CAPTIVE_PORTAL),
            Some(DhcpOptionKind::CaptivePortal),
        );

        let mud = b"https://mud.example.com/device.json".to_vec();
        let mud_url = typed_option_value(MUD_URL, &mud)
            .unwrap()
            .expect("option 161 has a typed value");
        assert_eq!(mud_url, DhcpOptionValue::Text(mud.clone()));
        assert_eq!(
            DhcpOptionKind::from_code(MUD_URL),
            Some(DhcpOptionKind::MudUrl),
        );

        // Non-UTF-8 bytes in a text-like modern option are still preserved.
        let raw_text = vec![0xff, 0x00, 0x80, 0x41];
        let preserved = typed_option_value(CAPTIVE_PORTAL, &raw_text)
            .unwrap()
            .unwrap();
        assert_eq!(preserved, DhcpOptionValue::Text(raw_text));

        // Each newly typed option round-trips inside a full DHCP packet.
        let parsed = build_and_decode(vec![
            DhcpOption::message_type(DhcpMessageType::Ack),
            DhcpOption::generic(IPV6_ONLY_PREFERRED, payload.clone()),
            DhcpOption::generic(CAPTIVE_PORTAL, portal.clone()),
            DhcpOption::generic(MUD_URL, mud.clone()),
            DhcpOption::End,
        ]);
        assert_eq!(option_payload(&parsed, IPV6_ONLY_PREFERRED), payload);
        assert_eq!(option_payload(&parsed, CAPTIVE_PORTAL), portal);
        assert_eq!(option_payload(&parsed, MUD_URL), mud);
    }

    #[test]
    fn dhcp_remaining_registry_options_preserve_raw_payloads() {
        // The remaining registry codepoints fall into two raw-preserving groups:
        // modern assigned options with nested/complex formats (PcpServer 158,
        // Dnr 162, SixRd 212), and unknown/private/removed/ambiguous codes. For
        // all of them the option code and payload bytes must survive a full
        // compile -> decode cycle, and the typed-format dispatch must decline to
        // reinterpret them (returning Ok(None)) so the raw bytes are preserved.
        //
        // Documentation-style opaque payloads only; no live traffic.
        let raw_cases: &[(u8, Vec<u8>)] = &[
            // OPTION_V4_PCP_SERVER (158): a list-length octet plus a PCP server
            // IPv4 address; kept opaque rather than mistyped as a flat list.
            (PCP_SERVER, vec![0x04, 192, 0, 2, 1]),
            // OPTION_V4_DNR (162): a nested Service Priority / ADN / addrs / svc
            // params structure, preserved verbatim.
            (DNR, vec![0x00, 0x01, 0x03, b'd', b'n', b's']),
            // OPTION_6RD (212): IPv4MaskLen, 6rdPrefixLen, 6rd prefix, BR addrs.
            (
                SIX_RD,
                vec![
                    0x10, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0,
                    2, 1,
                ],
            ),
            // Unassigned/removed code (RFC 3679 range).
            (110, vec![0xde, 0xad]),
            // Ambiguous historical PXE code (128-135).
            (130, vec![0x01, 0x02, 0x03]),
            // Private-use code (224-254).
            (240, vec![0xbe, 0xef]),
        ];

        for (code, payload) in raw_cases {
            let code = *code;
            // The typed-format dispatch declines to reinterpret these codes, so
            // the raw bytes are preserved instead of being parsed.
            assert!(
                typed_option_value(code, payload).unwrap().is_none(),
                "code {code} must stay raw (Ok(None) from the typed dispatch)",
            );

            // Built as a raw option and round-tripped through a full packet, the
            // codepoint and payload bytes survive without loss.
            let parsed = build_and_decode(vec![
                DhcpOption::message_type(DhcpMessageType::Ack),
                DhcpOption::generic(code, payload.clone()),
                DhcpOption::End,
            ]);
            assert_eq!(
                option_payload(&parsed, code),
                *payload,
                "code {code} payload must round-trip through a full packet",
            );

            // The decoded raw option preserves the bytes and the codepoint
            // classification, and its logical value is opaque bytes.
            let option = DhcpOption::generic(code, payload.clone());
            assert_eq!(option.code(), code);
            assert_eq!(
                option.logical_value(),
                Some(DhcpOptionValue::Opaque(payload.clone())),
            );
            assert_eq!(option.typed_value().unwrap(), None);
        }

        // The modern assigned codes are still classified as Assigned by the
        // source-backed registry even though they decode raw, while the
        // unknown/private/removed codes carry their range classifications.
        for code in [PCP_SERVER, DNR, SIX_RD] {
            assert_eq!(
                super::super::option_status(code),
                DhcpOptionStatus::Assigned
            );
            assert!(matches!(
                DhcpOptionCode::from_code(code),
                DhcpOptionCode::Assigned(_)
            ));
        }
        assert_eq!(
            super::super::option_status(130),
            DhcpOptionStatus::Ambiguous
        );
        assert_eq!(
            DhcpOptionCode::from_code(110),
            DhcpOptionCode::RemovedOrUnassigned(110),
        );
        assert_eq!(
            DhcpOptionCode::from_code(240),
            DhcpOptionCode::PrivateUse(240)
        );
    }
}
