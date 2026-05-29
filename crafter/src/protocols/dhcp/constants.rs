//! BOOTP/DHCP wire-level constants and codepoints.

/// BOOTP/DHCP fixed header length in bytes, before the magic cookie.
pub const DHCP_FIXED_HEADER_LEN: usize = 236;
/// DHCP magic cookie length in bytes.
pub const DHCP_MAGIC_COOKIE_LEN: usize = 4;
/// Minimum DHCP message length including the fixed header and magic cookie.
pub const DHCP_MIN_LEN: usize = DHCP_FIXED_HEADER_LEN + DHCP_MAGIC_COOKIE_LEN;
/// DHCP client UDP port.
pub const DHCP_CLIENT_PORT: u16 = 68;
/// DHCP server UDP port.
pub const DHCP_SERVER_PORT: u16 = 67;
/// RFC 2131 DHCP magic cookie.
pub const DHCP_MAGIC_COOKIE: u32 = 0x6382_5363;

/// BOOTP request opcode.
pub const BOOTP_REQUEST: u8 = 1;
/// BOOTP reply opcode.
pub const BOOTP_REPLY: u8 = 2;
/// Ethernet hardware type used by DHCP over Ethernet.
pub const DHCP_HTYPE_ETHERNET: u8 = 1;

/// DHCP pad option code.
pub const DHCP_OPTION_PAD: u8 = 0;
/// DHCP subnet mask option code.
pub const DHCP_OPTION_SUBNET_MASK: u8 = 1;
/// DHCP router option code.
pub const DHCP_OPTION_ROUTER: u8 = 3;
/// DHCP DNS server option code.
pub const DHCP_OPTION_DOMAIN_NAME_SERVER: u8 = 6;
/// DHCP host name option code.
pub const DHCP_OPTION_HOST_NAME: u8 = 12;
/// DHCP domain name option code.
pub const DHCP_OPTION_DOMAIN_NAME: u8 = 15;
/// DHCP broadcast address option code.
pub const DHCP_OPTION_BROADCAST_ADDRESS: u8 = 28;
/// DHCP requested IP address option code.
pub const DHCP_OPTION_REQUESTED_IP_ADDRESS: u8 = 50;
/// DHCP lease time option code.
pub const DHCP_OPTION_IP_ADDRESS_LEASE_TIME: u8 = 51;
/// DHCP option overload option code (RFC 2132 section 9.3).
pub const DHCP_OPTION_OVERLOAD: u8 = 52;
/// DHCP message type option code.
pub const DHCP_OPTION_MESSAGE_TYPE: u8 = 53;
/// DHCP server identifier option code.
pub const DHCP_OPTION_SERVER_IDENTIFIER: u8 = 54;
/// DHCP parameter request list option code.
pub const DHCP_OPTION_PARAMETER_REQUEST_LIST: u8 = 55;
/// DHCP renewal time option code.
pub const DHCP_OPTION_RENEWAL_TIME: u8 = 58;
/// DHCP rebinding time option code.
pub const DHCP_OPTION_REBINDING_TIME: u8 = 59;
/// DHCP client identifier option code.
pub const DHCP_OPTION_CLIENT_IDENTIFIER: u8 = 61;
/// DHCP end option code.
pub const DHCP_OPTION_END: u8 = 255;

/// Option overload value: the `file` field holds options (RFC 2132 section 9.3).
pub const DHCP_OVERLOAD_FILE: u8 = 1;
/// Option overload value: the `sname` field holds options (RFC 2132 section 9.3).
pub const DHCP_OVERLOAD_SNAME: u8 = 2;
/// Option overload value: both `file` and `sname` hold options (RFC 2132 section 9.3).
pub const DHCP_OVERLOAD_BOTH: u8 = 3;

/// DHCP Discover message type value.
pub const DHCP_DISCOVER: u8 = 1;
/// DHCP Offer message type value.
pub const DHCP_OFFER: u8 = 2;
/// DHCP Request message type value.
pub const DHCP_REQUEST: u8 = 3;
/// DHCP Decline message type value.
pub const DHCP_DECLINE: u8 = 4;
/// DHCP ACK message type value.
pub const DHCP_ACK: u8 = 5;
/// DHCP NAK message type value.
pub const DHCP_NAK: u8 = 6;
/// DHCP Release message type value.
pub const DHCP_RELEASE: u8 = 7;
/// DHCP Inform message type value.
pub const DHCP_INFORM: u8 = 8;
/// DHCP FORCERENEW message type value (RFC 3203).
pub const DHCP_FORCE_RENEW: u8 = 9;
/// DHCP LEASEQUERY message type value (RFC 4388).
pub const DHCP_LEASE_QUERY: u8 = 10;
/// DHCP LEASEUNASSIGNED message type value (RFC 4388).
pub const DHCP_LEASE_UNASSIGNED: u8 = 11;
/// DHCP LEASEUNKNOWN message type value (RFC 4388).
pub const DHCP_LEASE_UNKNOWN: u8 = 12;
/// DHCP LEASEACTIVE message type value (RFC 4388).
pub const DHCP_LEASE_ACTIVE: u8 = 13;
/// DHCP BULKLEASEQUERY message type value (RFC 6926).
pub const DHCP_BULK_LEASE_QUERY: u8 = 14;
/// DHCP LEASEQUERYDONE message type value (RFC 6926).
pub const DHCP_LEASE_QUERY_DONE: u8 = 15;
/// DHCP ACTIVELEASEQUERY message type value (RFC 7724).
pub const DHCP_ACTIVE_LEASE_QUERY: u8 = 16;
/// DHCP LEASEQUERYSTATUS message type value (RFC 7724).
pub const DHCP_LEASE_QUERY_STATUS: u8 = 17;
/// DHCP TLS message type value (RFC 7724).
pub const DHCP_TLS: u8 = 18;

/// BOOTP fixed client hardware address field length in bytes.
pub(crate) const DHCP_CHADDR_LEN: usize = 16;
/// BOOTP fixed server name field length in bytes.
pub(crate) const DHCP_SNAME_LEN: usize = 64;
/// BOOTP fixed boot file name field length in bytes.
pub(crate) const DHCP_FILE_LEN: usize = 128;
/// Default parameter request list used by client message builders.
pub(crate) const DHCP_DEFAULT_PARAMETER_REQUESTS: [u8; 6] = [
    DHCP_OPTION_SUBNET_MASK,
    DHCP_OPTION_ROUTER,
    DHCP_OPTION_DOMAIN_NAME_SERVER,
    DHCP_OPTION_DOMAIN_NAME,
    DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
    DHCP_OPTION_SERVER_IDENTIFIER,
];
