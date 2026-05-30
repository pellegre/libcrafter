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

// RFC 2132 BOOTP vendor extension and DHCP option codes (codes 1-61). Each
// constant is the wire codepoint from the IANA "BOOTP Vendor Extensions and
// DHCP Options" registry (updated 2026-02-02), reconciled with RFC 2132.

/// DHCP pad option code (RFC 2132 section 3.1).
pub const DHCP_OPTION_PAD: u8 = 0;
/// DHCP subnet mask option code (RFC 2132 section 3.3).
pub const DHCP_OPTION_SUBNET_MASK: u8 = 1;
/// DHCP time offset option code (RFC 2132 section 3.4).
pub const DHCP_OPTION_TIME_OFFSET: u8 = 2;
/// DHCP router option code (RFC 2132 section 3.5).
pub const DHCP_OPTION_ROUTER: u8 = 3;
/// DHCP time server option code (RFC 2132 section 3.6).
pub const DHCP_OPTION_TIME_SERVER: u8 = 4;
/// DHCP name server (IEN 116) option code (RFC 2132 section 3.7).
pub const DHCP_OPTION_NAME_SERVER: u8 = 5;
/// DHCP DNS server option code (RFC 2132 section 3.8).
pub const DHCP_OPTION_DOMAIN_NAME_SERVER: u8 = 6;
/// DHCP log server option code (RFC 2132 section 3.9).
pub const DHCP_OPTION_LOG_SERVER: u8 = 7;
/// DHCP cookie/quote server option code (RFC 2132 section 3.10).
pub const DHCP_OPTION_COOKIE_SERVER: u8 = 8;
/// DHCP LPR server option code (RFC 2132 section 3.11).
pub const DHCP_OPTION_LPR_SERVER: u8 = 9;
/// DHCP Impress server option code (RFC 2132 section 3.12).
pub const DHCP_OPTION_IMPRESS_SERVER: u8 = 10;
/// DHCP resource location (RLP) server option code (RFC 2132 section 3.13).
pub const DHCP_OPTION_RESOURCE_LOCATION_SERVER: u8 = 11;
/// DHCP host name option code (RFC 2132 section 3.14).
pub const DHCP_OPTION_HOST_NAME: u8 = 12;
/// DHCP boot file size option code (RFC 2132 section 3.15).
pub const DHCP_OPTION_BOOT_FILE_SIZE: u8 = 13;
/// DHCP merit dump file option code (RFC 2132 section 3.16).
pub const DHCP_OPTION_MERIT_DUMP_FILE: u8 = 14;
/// DHCP domain name option code (RFC 2132 section 3.17).
pub const DHCP_OPTION_DOMAIN_NAME: u8 = 15;
/// DHCP swap server option code (RFC 2132 section 3.18).
pub const DHCP_OPTION_SWAP_SERVER: u8 = 16;
/// DHCP root path option code (RFC 2132 section 3.19).
pub const DHCP_OPTION_ROOT_PATH: u8 = 17;
/// DHCP extensions path option code (RFC 2132 section 3.20).
pub const DHCP_OPTION_EXTENSIONS_PATH: u8 = 18;
/// DHCP IP forwarding enable/disable option code (RFC 2132 section 4.1).
pub const DHCP_OPTION_IP_FORWARDING: u8 = 19;
/// DHCP non-local source routing option code (RFC 2132 section 4.2).
pub const DHCP_OPTION_NON_LOCAL_SOURCE_ROUTING: u8 = 20;
/// DHCP policy filter option code (RFC 2132 section 4.3).
pub const DHCP_OPTION_POLICY_FILTER: u8 = 21;
/// DHCP maximum datagram reassembly size option code (RFC 2132 section 4.4).
pub const DHCP_OPTION_MAX_DATAGRAM_REASSEMBLY: u8 = 22;
/// DHCP default IP time-to-live option code (RFC 2132 section 4.5).
pub const DHCP_OPTION_DEFAULT_IP_TTL: u8 = 23;
/// DHCP path MTU aging timeout option code (RFC 2132 section 4.6).
pub const DHCP_OPTION_PATH_MTU_AGING_TIMEOUT: u8 = 24;
/// DHCP path MTU plateau table option code (RFC 2132 section 4.7).
pub const DHCP_OPTION_PATH_MTU_PLATEAU_TABLE: u8 = 25;
/// DHCP interface MTU option code (RFC 2132 section 5.1).
pub const DHCP_OPTION_INTERFACE_MTU: u8 = 26;
/// DHCP all subnets are local option code (RFC 2132 section 5.2).
pub const DHCP_OPTION_ALL_SUBNETS_LOCAL: u8 = 27;
/// DHCP broadcast address option code (RFC 2132 section 5.3).
pub const DHCP_OPTION_BROADCAST_ADDRESS: u8 = 28;
/// DHCP perform mask discovery option code (RFC 2132 section 5.4).
pub const DHCP_OPTION_PERFORM_MASK_DISCOVERY: u8 = 29;
/// DHCP mask supplier option code (RFC 2132 section 5.5).
pub const DHCP_OPTION_MASK_SUPPLIER: u8 = 30;
/// DHCP perform router discovery option code (RFC 2132 section 5.6).
pub const DHCP_OPTION_PERFORM_ROUTER_DISCOVERY: u8 = 31;
/// DHCP router solicitation address option code (RFC 2132 section 5.7).
pub const DHCP_OPTION_ROUTER_SOLICITATION_ADDRESS: u8 = 32;
/// DHCP static route option code (RFC 2132 section 5.8).
pub const DHCP_OPTION_STATIC_ROUTE: u8 = 33;
/// DHCP trailer encapsulation option code (RFC 2132 section 6.1).
pub const DHCP_OPTION_TRAILER_ENCAPSULATION: u8 = 34;
/// DHCP ARP cache timeout option code (RFC 2132 section 6.2).
pub const DHCP_OPTION_ARP_CACHE_TIMEOUT: u8 = 35;
/// DHCP Ethernet encapsulation option code (RFC 2132 section 6.3).
pub const DHCP_OPTION_ETHERNET_ENCAPSULATION: u8 = 36;
/// DHCP TCP default TTL option code (RFC 2132 section 7.1).
pub const DHCP_OPTION_TCP_DEFAULT_TTL: u8 = 37;
/// DHCP TCP keepalive interval option code (RFC 2132 section 7.2).
pub const DHCP_OPTION_TCP_KEEPALIVE_INTERVAL: u8 = 38;
/// DHCP TCP keepalive garbage option code (RFC 2132 section 7.3).
pub const DHCP_OPTION_TCP_KEEPALIVE_GARBAGE: u8 = 39;
/// DHCP NIS domain name option code (RFC 2132 section 8.1).
pub const DHCP_OPTION_NIS_DOMAIN: u8 = 40;
/// DHCP NIS servers option code (RFC 2132 section 8.2).
pub const DHCP_OPTION_NIS_SERVERS: u8 = 41;
/// DHCP NTP servers option code (RFC 2132 section 8.3).
pub const DHCP_OPTION_NTP_SERVERS: u8 = 42;
/// DHCP vendor-specific information option code (RFC 2132 section 8.4).
pub const DHCP_OPTION_VENDOR_SPECIFIC: u8 = 43;
/// DHCP NetBIOS over TCP/IP name server option code (RFC 2132 section 8.5).
pub const DHCP_OPTION_NETBIOS_NAME_SERVER: u8 = 44;
/// DHCP NetBIOS datagram distribution server option code (RFC 2132 section 8.6).
pub const DHCP_OPTION_NETBIOS_DATAGRAM_SERVER: u8 = 45;
/// DHCP NetBIOS node type option code (RFC 2132 section 8.7).
pub const DHCP_OPTION_NETBIOS_NODE_TYPE: u8 = 46;
/// DHCP NetBIOS scope option code (RFC 2132 section 8.8).
pub const DHCP_OPTION_NETBIOS_SCOPE: u8 = 47;
/// DHCP X Window System font server option code (RFC 2132 section 8.9).
pub const DHCP_OPTION_X_WINDOW_FONT_SERVER: u8 = 48;
/// DHCP X Window System display manager option code (RFC 2132 section 8.10).
pub const DHCP_OPTION_X_WINDOW_DISPLAY_MANAGER: u8 = 49;
/// DHCP requested IP address option code (RFC 2132 section 9.1).
pub const DHCP_OPTION_REQUESTED_IP_ADDRESS: u8 = 50;
/// DHCP lease time option code (RFC 2132 section 9.2).
pub const DHCP_OPTION_IP_ADDRESS_LEASE_TIME: u8 = 51;
/// DHCP option overload option code (RFC 2132 section 9.3).
pub const DHCP_OPTION_OVERLOAD: u8 = 52;
/// DHCP message type option code (RFC 2132 section 9.6).
pub const DHCP_OPTION_MESSAGE_TYPE: u8 = 53;
/// DHCP server identifier option code (RFC 2132 section 9.7).
pub const DHCP_OPTION_SERVER_IDENTIFIER: u8 = 54;
/// DHCP parameter request list option code (RFC 2132 section 9.8).
pub const DHCP_OPTION_PARAMETER_REQUEST_LIST: u8 = 55;
/// DHCP message (error text) option code (RFC 2132 section 9.9).
pub const DHCP_OPTION_MESSAGE: u8 = 56;
/// DHCP maximum DHCP message size option code (RFC 2132 section 9.10).
pub const DHCP_OPTION_MAX_MESSAGE_SIZE: u8 = 57;
/// DHCP renewal (T1) time option code (RFC 2132 section 9.11).
pub const DHCP_OPTION_RENEWAL_TIME: u8 = 58;
/// DHCP rebinding (T2) time option code (RFC 2132 section 9.12).
pub const DHCP_OPTION_REBINDING_TIME: u8 = 59;
/// DHCP vendor class identifier option code (RFC 2132 section 9.13).
pub const DHCP_OPTION_VENDOR_CLASS_IDENTIFIER: u8 = 60;
/// DHCP client identifier option code (RFC 2132 section 9.14).
pub const DHCP_OPTION_CLIENT_IDENTIFIER: u8 = 61;
/// DHCP end option code (RFC 2132 section 3.2).
pub const DHCP_OPTION_END: u8 = 255;

// Route, domain, and service-discovery option codes beyond the RFC 2132 base
// subset. Codepoints come from the IANA "BOOTP Vendor Extensions and DHCP
// Options" registry (updated 2026-02-02); each wire format is defined by the
// RFC cited inline.

/// DHCP BCMCS Controller Domain Name list option code (RFC 4280).
pub const DHCP_OPTION_BCMCS_DOMAIN_LIST: u8 = 88;
/// DHCP BCMCS Controller IPv4 address option code (RFC 4280).
pub const DHCP_OPTION_BCMCS_IPV4_LIST: u8 = 89;
/// DHCP GEOCONF_CIVIC civic location option code (RFC 4776).
pub const DHCP_OPTION_GEOCONF_CIVIC: u8 = 99;
/// DHCP PCode (POSIX timezone string) option code (RFC 4833).
pub const DHCP_OPTION_PCODE: u8 = 100;
/// DHCP TCode (timezone database name) option code (RFC 4833).
pub const DHCP_OPTION_TCODE: u8 = 101;
/// DHCP Name Service Search option code (RFC 2937).
pub const DHCP_OPTION_NAME_SERVICE_SEARCH: u8 = 117;
/// DHCP Domain Search option code (RFC 3397).
pub const DHCP_OPTION_DOMAIN_SEARCH: u8 = 119;
/// DHCP SIP Servers option code (RFC 3361).
pub const DHCP_OPTION_SIP_SERVERS: u8 = 120;
/// DHCP Classless Static Route option code (RFC 3442).
pub const DHCP_OPTION_CLASSLESS_STATIC_ROUTE: u8 = 121;
/// DHCP GeoConf (GeoLoc binary) option code (RFC 6225).
pub const DHCP_OPTION_GEOCONF: u8 = 123;
/// DHCP SIP UA Configuration Service Domains option code (RFC 6011).
pub const DHCP_OPTION_SIP_UA_CONFIG_DOMAINS: u8 = 141;
/// DHCP GeoLoc option code (RFC 6225).
pub const DHCP_OPTION_GEOLOC: u8 = 144;
/// DHCP RDNSS Selection option code (RFC 6731).
pub const DHCP_OPTION_RDNSS_SELECTION: u8 = 146;
/// DHCP OPTION_V4_DOTS_RI (DOTS reference identifier) option code (RFC 8973).
pub const DHCP_OPTION_V4_DOTS_RI: u8 = 147;
/// DHCP OPTION_V4_DOTS_ADDRESS option code (RFC 8973).
pub const DHCP_OPTION_V4_DOTS_ADDRESS: u8 = 148;
/// DHCP OPTION_V4_PCP_SERVER option code (RFC 7291).
pub const DHCP_OPTION_V4_PCP_SERVER: u8 = 158;
/// DHCP OPTION_MUD_URL_V4 option code (RFC 8520).
pub const DHCP_OPTION_MUD_URL_V4: u8 = 161;
/// DHCP OPTION_V4_DNR (Discovery of Network-designated Resolvers) option code
/// (RFC 9463).
pub const DHCP_OPTION_V4_DNR: u8 = 162;
/// DHCP OPTION_6RD (IPv6 Rapid Deployment) option code (RFC 5969).
pub const DHCP_OPTION_6RD: u8 = 212;

// Authentication and FORCERENEW option codes and field constants. Codepoints
// come from the IANA "BOOTP Vendor Extensions and DHCP Options" registry
// (updated 2026-02-02) and the authentication sub-registries; each wire format
// is defined by the RFC cited inline.

/// DHCP Authentication option code (RFC 3118 section 2).
pub const DHCP_OPTION_AUTHENTICATION: u8 = 90;
/// DHCP FORCERENEW_NONCE_CAPABLE option code (RFC 6704 section 4).
pub const DHCP_OPTION_FORCERENEW_NONCE_CAPABLE: u8 = 145;

/// Fixed length in octets of the RFC 3118 authentication option header that
/// precedes the variable authentication information: a one-octet Protocol, a
/// one-octet Algorithm, a one-octet RDM, and an 8-octet Replay Detection field.
///
/// Source: RFC 3118 section 2.
pub const DHCP_AUTH_HEADER_LEN: usize = 11;
/// Length in octets of the RFC 3118 authentication option Replay Detection
/// field (a 64-bit value).
///
/// Source: RFC 3118 section 2.
pub const DHCP_AUTH_REPLAY_DETECTION_LEN: usize = 8;

/// RFC 3118 authentication Protocol value for the Configuration Token protocol.
///
/// Source: RFC 3118 section 4 and the IANA "DHCP Authentication Protocols"
/// sub-registry (value `0`).
pub const DHCP_AUTH_PROTOCOL_CONFIGURATION_TOKEN: u8 = 0;
/// RFC 3118 authentication Protocol value for the Delayed Authentication
/// protocol.
///
/// Source: RFC 3118 section 5 and the IANA "DHCP Authentication Protocols"
/// sub-registry (value `1`).
pub const DHCP_AUTH_PROTOCOL_DELAYED: u8 = 1;
/// RFC 6704 authentication Protocol value used by Forcerenew Nonce
/// Authentication. RFC 6704 reuses the RFC 3118 Reconfigure Key protocol value
/// `3` to carry the forcerenew nonce.
///
/// Source: RFC 6704 section 5.
pub const DHCP_AUTH_PROTOCOL_RECONFIGURE_KEY: u8 = 3;

/// RFC 3118 authentication Algorithm value for the HMAC-MD5 generating function
/// used by the Delayed Authentication protocol and by RFC 6704.
///
/// Source: RFC 3118 section 5.1 and RFC 6704 section 5 (Algorithm `1`).
pub const DHCP_AUTH_ALGORITHM_HMAC_MD5: u8 = 1;

/// RFC 3118 authentication Replay Detection Method (RDM) value for a
/// monotonically increasing counter.
///
/// Source: RFC 3118 section 2 (RDM `0`).
pub const DHCP_AUTH_RDM_MONOTONIC_COUNTER: u8 = 0;

/// RFC 6704 Forcerenew nonce authentication-information Type value carrying the
/// 128-bit forcerenew nonce (server to client).
///
/// Source: RFC 6704 section 5.
pub const DHCP_FORCERENEW_NONCE_TYPE_NONCE: u8 = 1;
/// RFC 6704 Forcerenew nonce authentication-information Type value carrying the
/// 128-bit HMAC-MD5 digest (in the authenticated FORCERENEW message).
///
/// Source: RFC 6704 section 5.
pub const DHCP_FORCERENEW_NONCE_TYPE_HMAC_MD5: u8 = 2;

// Leasequery, bulk leasequery, and active leasequery option codes and field
// constants. Codepoints come from the IANA "BOOTP Vendor Extensions and DHCP
// Options" registry (updated 2026-02-02) and its DHCP Status Code (type 151)
// and DHCP State (type 156) sub-registries (XML retrieved 2026-05-29); each
// wire format is defined by the RFC cited inline.

/// DHCP client-last-transaction-time option code (RFC 4388 section 6.1).
pub const DHCP_OPTION_CLIENT_LAST_TRANSACTION_TIME: u8 = 91;
/// DHCP associated-ip option code (RFC 4388 section 6.1).
pub const DHCP_OPTION_ASSOCIATED_IP: u8 = 92;
/// DHCP status-code option code (RFC 6926 section 6.2.2).
pub const DHCP_OPTION_STATUS_CODE: u8 = 151;
/// DHCP base-time option code (RFC 6926 section 6.2.3).
pub const DHCP_OPTION_BASE_TIME: u8 = 152;
/// DHCP start-time-of-state option code (RFC 6926 section 6.2.4).
pub const DHCP_OPTION_START_TIME_OF_STATE: u8 = 153;
/// DHCP query-start-time option code (RFC 6926 section 6.2.5).
pub const DHCP_OPTION_QUERY_START_TIME: u8 = 154;
/// DHCP query-end-time option code (RFC 6926 section 6.2.6).
pub const DHCP_OPTION_QUERY_END_TIME: u8 = 155;
/// DHCP dhcp-state option code (RFC 6926 section 6.2.7).
pub const DHCP_OPTION_DHCP_STATE: u8 = 156;
/// DHCP data-source option code (RFC 6926 section 6.2.8).
pub const DHCP_OPTION_DATA_SOURCE: u8 = 157;

/// DHCP status-code value Success (`0`).
///
/// Source: RFC 6926 section 6.2.2 and the IANA "DHCP Status Code Type 151
/// Values" sub-registry.
pub const DHCP_STATUS_SUCCESS: u8 = 0;
/// DHCP status-code value UnspecFail (`1`). Source: RFC 6926, IANA type-151.
pub const DHCP_STATUS_UNSPEC_FAIL: u8 = 1;
/// DHCP status-code value QueryTerminated (`2`). Source: RFC 6926, IANA type-151.
pub const DHCP_STATUS_QUERY_TERMINATED: u8 = 2;
/// DHCP status-code value MalformedQuery (`3`). Source: RFC 6926, IANA type-151.
pub const DHCP_STATUS_MALFORMED_QUERY: u8 = 3;
/// DHCP status-code value NotAllowed (`4`). Source: RFC 6926, IANA type-151.
pub const DHCP_STATUS_NOT_ALLOWED: u8 = 4;
/// DHCP status-code value DataMissing (`5`). Source: RFC 7724, IANA type-151.
pub const DHCP_STATUS_DATA_MISSING: u8 = 5;
/// DHCP status-code value ConnectionActive (`6`). Source: RFC 7724, IANA type-151.
pub const DHCP_STATUS_CONNECTION_ACTIVE: u8 = 6;
/// DHCP status-code value CatchUpComplete (`7`). Source: RFC 7724, IANA type-151.
pub const DHCP_STATUS_CATCH_UP_COMPLETE: u8 = 7;
/// DHCP status-code value TLSConnectionRefused (`8`). Source: RFC 7724, IANA type-151.
pub const DHCP_STATUS_TLS_CONNECTION_REFUSED: u8 = 8;

/// DHCP dhcp-state value Reserved (`0`).
///
/// Source: RFC 6926 section 6.2.7 and the IANA "DHCP State Type 156 Values"
/// sub-registry.
pub const DHCP_STATE_RESERVED: u8 = 0;
/// DHCP dhcp-state value AVAILABLE (`1`). Source: RFC 6926, IANA type-156.
pub const DHCP_STATE_AVAILABLE: u8 = 1;
/// DHCP dhcp-state value ACTIVE (`2`). Source: RFC 6926, IANA type-156.
pub const DHCP_STATE_ACTIVE: u8 = 2;
/// DHCP dhcp-state value EXPIRED (`3`). Source: RFC 6926, IANA type-156.
pub const DHCP_STATE_EXPIRED: u8 = 3;
/// DHCP dhcp-state value RELEASED (`4`). Source: RFC 6926, IANA type-156.
pub const DHCP_STATE_RELEASED: u8 = 4;
/// DHCP dhcp-state value ABANDONED (`5`). Source: RFC 6926, IANA type-156.
pub const DHCP_STATE_ABANDONED: u8 = 5;
/// DHCP dhcp-state value RESET (`6`). Source: RFC 6926, IANA type-156.
pub const DHCP_STATE_RESET: u8 = 6;
/// DHCP dhcp-state value REMOTE (`7`). Source: RFC 6926, IANA type-156.
pub const DHCP_STATE_REMOTE: u8 = 7;
/// DHCP dhcp-state value TRANSITIONING (`8`). Source: RFC 6926, IANA type-156.
pub const DHCP_STATE_TRANSITIONING: u8 = 8;

/// RFC 6926 data-source option (option 157) Flags REMOTE bit (`R`, `0x01`).
///
/// Source: RFC 6926 section 6.2.8. The Flags octet's least-significant bit is
/// the REMOTE flag: set (`1`) means the data came from a remote server, clear
/// (`0`) means it came from the local server. The remaining bits (UNA) are
/// unassigned and MUST be ignored.
pub const DHCP_DATA_SOURCE_FLAG_REMOTE: u8 = 0x01;

// Vendor, user-class, PXE, and vendor-identifying option codes. Codepoints come
// from the IANA "BOOTP Vendor Extensions and DHCP Options" registry (updated
// 2026-02-02); each wire format is defined by the RFC cited inline.

/// DHCP TFTP server name option code (RFC 2132 section 9.4).
pub const DHCP_OPTION_TFTP_SERVER_NAME: u8 = 66;
/// DHCP bootfile name option code (RFC 2132 section 9.5).
pub const DHCP_OPTION_BOOTFILE_NAME: u8 = 67;
/// DHCP user class option code (RFC 3004).
pub const DHCP_OPTION_USER_CLASS: u8 = 77;
/// DHCP client system architecture type option code (RFC 4578).
pub const DHCP_OPTION_CLIENT_SYSTEM_ARCHITECTURE: u8 = 93;
/// DHCP client network device interface option code (RFC 4578).
pub const DHCP_OPTION_CLIENT_NDI: u8 = 94;
/// DHCP UUID/GUID-based client identifier option code (RFC 4578).
pub const DHCP_OPTION_CLIENT_MACHINE_IDENTIFIER: u8 = 97;
/// DHCP V-I Vendor Class option code (RFC 3925).
pub const DHCP_OPTION_VI_VENDOR_CLASS: u8 = 124;
/// DHCP V-I Vendor-Specific Information option code (RFC 3925).
pub const DHCP_OPTION_VI_VENDOR_SPECIFIC: u8 = 125;
/// DHCP Relay Agent Information option code (RFC 3046).
pub const DHCP_OPTION_RELAY_AGENT_INFORMATION: u8 = 82;
/// DHCP TFTP server address option code (RFC 5859).
pub const DHCP_OPTION_TFTP_SERVER_ADDRESS: u8 = 150;
/// DHCP PXELINUX magic option code (RFC 5071 / RFC 5494).
pub const DHCP_OPTION_PXELINUX_MAGIC: u8 = 208;
/// DHCP PXELINUX configuration file option code (RFC 5071).
pub const DHCP_OPTION_PXELINUX_CONFIGFILE: u8 = 209;
/// DHCP PXELINUX path prefix option code (RFC 5071).
pub const DHCP_OPTION_PXELINUX_PATHPREFIX: u8 = 210;
/// DHCP PXELINUX reboot time option code (RFC 5071).
pub const DHCP_OPTION_PXELINUX_REBOOTTIME: u8 = 211;

// Relay Agent Information sub-option codes (option 82). Codepoints come from the
// IANA "DHCP Relay Agent Sub-Option Codes" registry (last updated 2026-05-29);
// each wire format is defined by the RFC cited inline.

/// Relay agent Agent Circuit ID sub-option code (RFC 3046).
pub const DHCP_RELAY_SUBOPTION_CIRCUIT_ID: u8 = 1;
/// Relay agent Agent Remote ID sub-option code (RFC 3046).
pub const DHCP_RELAY_SUBOPTION_REMOTE_ID: u8 = 2;
/// Relay agent DOCSIS Device Class sub-option code (RFC 3256).
pub const DHCP_RELAY_SUBOPTION_DOCSIS_DEVICE_CLASS: u8 = 4;
/// Relay agent Link Selection sub-option code (RFC 3527).
pub const DHCP_RELAY_SUBOPTION_LINK_SELECTION: u8 = 5;
/// Relay agent Subscriber-ID sub-option code (RFC 3993).
pub const DHCP_RELAY_SUBOPTION_SUBSCRIBER_ID: u8 = 6;
/// Relay agent RADIUS Attributes sub-option code (RFC 4014).
pub const DHCP_RELAY_SUBOPTION_RADIUS_ATTRIBUTES: u8 = 7;
/// Relay agent Authentication sub-option code (RFC 4030).
pub const DHCP_RELAY_SUBOPTION_AUTHENTICATION: u8 = 8;
/// Relay agent Vendor-Specific Information sub-option code (RFC 4243).
pub const DHCP_RELAY_SUBOPTION_VENDOR_SPECIFIC: u8 = 9;
/// Relay agent Relay Agent Flags sub-option code (RFC 5010).
pub const DHCP_RELAY_SUBOPTION_RELAY_FLAGS: u8 = 10;
/// Relay agent Server Identifier Override sub-option code (RFC 5107).
pub const DHCP_RELAY_SUBOPTION_SERVER_ID_OVERRIDE: u8 = 11;
/// Relay agent Relay Agent Identifier sub-option code (RFC 6925).
pub const DHCP_RELAY_SUBOPTION_RELAY_AGENT_ID: u8 = 12;
/// Relay agent Access-Technology-Type sub-option code (RFC 7839).
pub const DHCP_RELAY_SUBOPTION_ACCESS_TECHNOLOGY_TYPE: u8 = 13;
/// Relay agent Access-Network-Name sub-option code (RFC 7839).
pub const DHCP_RELAY_SUBOPTION_ACCESS_NETWORK_NAME: u8 = 14;
/// Relay agent Access-Point-Name sub-option code (RFC 7839).
pub const DHCP_RELAY_SUBOPTION_ACCESS_POINT_NAME: u8 = 15;
/// Relay agent Access-Point-BSSID sub-option code (RFC 7839).
pub const DHCP_RELAY_SUBOPTION_ACCESS_POINT_BSSID: u8 = 16;
/// Relay agent Operator-Identifier sub-option code (RFC 7839).
pub const DHCP_RELAY_SUBOPTION_OPERATOR_IDENTIFIER: u8 = 17;
/// Relay agent Operator-Realm sub-option code (RFC 7839).
pub const DHCP_RELAY_SUBOPTION_OPERATOR_REALM: u8 = 18;
/// Relay agent DHCPv4 Relay Source Port sub-option code (RFC 8357).
pub const DHCP_RELAY_SUBOPTION_RELAY_SOURCE_PORT: u8 = 19;
/// Relay agent DHCPv4 Virtual Subnet Selection (VSS) sub-option code (RFC 6607).
pub const DHCP_RELAY_SUBOPTION_VSS: u8 = 151;
/// Relay agent DHCPv4 Virtual Subnet Selection Control sub-option code (RFC 6607).
pub const DHCP_RELAY_SUBOPTION_VSS_CONTROL: u8 = 152;

/// RFC 5010 Relay Agent Flags sub-option Unicast flag bit (`U`, bit 0 / `0x80`).
pub const DHCP_RELAY_FLAG_UNICAST: u8 = 0x80;
/// RFC 6607 VSS Type octet for an NVT ASCII VPN identifier.
pub const DHCP_VSS_TYPE_NVT_ASCII: u8 = 0;
/// RFC 6607 VSS Type octet for an RFC 2685 VPN-ID (7 octets).
pub const DHCP_VSS_TYPE_VPN_ID: u8 = 1;
/// RFC 6607 VSS Type octet selecting the global, default VPN (no VSS info).
pub const DHCP_VSS_TYPE_GLOBAL_DEFAULT: u8 = 255;

/// RFC 5071 PXELINUX magic option payload `0xF1 0x00 0x74 0x7E` (option 208).
pub const DHCP_PXELINUX_MAGIC_VALUE: [u8; 4] = [0xF1, 0x00, 0x74, 0x7E];
/// RFC 4578 client machine identifier type octet for a 16-octet GUID (option 97).
pub const DHCP_CLIENT_MACHINE_UUID_TYPE: u8 = 0;
/// RFC 4578 client network device interface type octet for UNDI (option 94).
pub const DHCP_CLIENT_NDI_TYPE_UNDI: u8 = 1;

/// RFC 2132 section 9.14 client identifier type octet for an identifier that is
/// not a hardware address (for example a DUID-bearing or domain-name based id).
pub const DHCP_CLIENT_ID_TYPE_NONE: u8 = 0;
/// RFC 4361 client identifier type octet (`255`) introducing an IAID and DUID.
///
/// Source: RFC 4361 section 6.1. When the option 61 type field is `255`, the
/// next four octets are an IAID and the remaining octets are a DUID.
pub const DHCP_CLIENT_ID_TYPE_RFC4361: u8 = 255;
/// RFC 4361 Identity Association Identifier (IAID) length in octets.
///
/// Source: RFC 4361 section 6.1. The IAID is an opaque 32-bit (4-octet) quantity
/// following the type-`255` octet.
pub const DHCP_IAID_LEN: usize = 4;

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
