//! DHCPv6 wire-level constants and registry metadata.
//!
//! Source: RFC 9915 for the base message, relay, option, UDP, and relay-hop
//! wire facts; IANA "Dynamic Host Configuration Protocol for IPv6 (DHCPv6)
//! Parameters" registries for message types, status codes, and DUID types.

/// DHCPv6 client/server fixed header length in bytes.
///
/// RFC 9915 section 8 defines a 1-octet `msg-type` field followed by a
/// 3-octet `transaction-id` field.
pub const DHCPV6_CLIENT_SERVER_HEADER_LEN: usize = 4;
/// DHCPv6 relay fixed header length in bytes.
///
/// RFC 9915 section 9 defines 1-octet `msg-type`, 1-octet `hop-count`,
/// 16-octet `link-address`, and 16-octet `peer-address` fields.
pub const DHCPV6_RELAY_HEADER_LEN: usize = 34;
/// DHCPv6 option header length in bytes.
///
/// RFC 9915 section 21 defines 2-octet `option-code` and 2-octet `option-len`
/// fields before the option payload.
pub const DHCPV6_OPTION_HEADER_LEN: usize = 4;
/// DHCPv6 transaction ID length in bytes.
pub const DHCPV6_TRANSACTION_ID_LEN: usize = 3;
/// Mask for the 24-bit DHCPv6 transaction ID field.
pub const DHCPV6_TRANSACTION_ID_MASK: u32 = 0x00ff_ffff;
/// Largest value encodable in the 24-bit DHCPv6 transaction ID field.
pub const DHCPV6_TRANSACTION_ID_MAX: u32 = DHCPV6_TRANSACTION_ID_MASK;
/// RFC 9915 relay hop-count limit.
pub const DHCPV6_HOP_COUNT_LIMIT: u8 = 8;
/// DHCPv6 client UDP port.
pub const DHCPV6_CLIENT_PORT: u16 = 546;
/// DHCPv6 server and relay-agent UDP port.
pub const DHCPV6_SERVER_PORT: u16 = 547;

/// DHCPv6 OPTION_CLIENTID option code.
pub const DHCPV6_OPTION_CLIENTID: u16 = 1;
/// DHCPv6 OPTION_SERVERID option code.
pub const DHCPV6_OPTION_SERVERID: u16 = 2;
/// DHCPv6 OPTION_IA_NA option code.
pub const DHCPV6_OPTION_IA_NA: u16 = 3;
/// DHCPv6 OPTION_IAADDR option code.
pub const DHCPV6_OPTION_IAADDR: u16 = 5;
/// DHCPv6 OPTION_ORO option code.
pub const DHCPV6_OPTION_ORO: u16 = 6;
/// DHCPv6 OPTION_PREFERENCE option code.
pub const DHCPV6_OPTION_PREFERENCE: u16 = 7;
/// DHCPv6 OPTION_ELAPSED_TIME option code.
pub const DHCPV6_OPTION_ELAPSED_TIME: u16 = 8;
/// DHCPv6 OPTION_AUTH option code.
pub const DHCPV6_OPTION_AUTH: u16 = 11;
/// DHCPv6 OPTION_STATUS_CODE option code.
pub const DHCPV6_OPTION_STATUS_CODE: u16 = 13;
/// DHCPv6 OPTION_RAPID_COMMIT option code.
pub const DHCPV6_OPTION_RAPID_COMMIT: u16 = 14;
/// DHCPv6 OPTION_USER_CLASS option code.
pub const DHCPV6_OPTION_USER_CLASS: u16 = 15;
/// DHCPv6 OPTION_VENDOR_CLASS option code.
pub const DHCPV6_OPTION_VENDOR_CLASS: u16 = 16;
/// DHCPv6 OPTION_VENDOR_OPTS option code.
pub const DHCPV6_OPTION_VENDOR_OPTS: u16 = 17;
/// DHCPv6 OPTION_RECONF_MSG option code.
pub const DHCPV6_OPTION_RECONF_MSG: u16 = 19;
/// DHCPv6 OPTION_RECONF_ACCEPT option code.
pub const DHCPV6_OPTION_RECONF_ACCEPT: u16 = 20;
/// DHCPv6 OPTION_IA_PD option code.
pub const DHCPV6_OPTION_IA_PD: u16 = 25;
/// DHCPv6 OPTION_IAPREFIX option code.
pub const DHCPV6_OPTION_IAPREFIX: u16 = 26;

/// Fixed length in octets of the DHCPv6 Authentication option payload header.
pub const DHCPV6_AUTH_HEADER_LEN: usize = 11;
/// Length in octets of the DHCPv6 Authentication Replay Detection field.
pub const DHCPV6_AUTH_REPLAY_DETECTION_LEN: usize = 8;
/// Authentication Protocol value for the configuration token protocol.
pub const DHCPV6_AUTH_PROTOCOL_CONFIGURATION_TOKEN: u8 = 0;
/// Authentication Protocol value for delayed authentication.
pub const DHCPV6_AUTH_PROTOCOL_DELAYED: u8 = 1;
/// Authentication Protocol value for obsolete DHCPv6 delayed authentication.
pub const DHCPV6_AUTH_PROTOCOL_DHCPV6_DELAYED_OBSOLETE: u8 = 2;
/// Authentication Protocol value for DHCPv6 Reconfigure Key.
pub const DHCPV6_AUTH_PROTOCOL_RECONFIGURE_KEY: u8 = 3;
/// Authentication Protocol value for split-horizon DNS.
pub const DHCPV6_AUTH_PROTOCOL_SPLIT_HORIZON_DNS: u8 = 4;
/// Authentication Algorithm value for configuration token.
pub const DHCPV6_AUTH_ALGORITHM_CONFIGURATION_TOKEN: u8 = 0;
/// Authentication Algorithm value for HMAC-MD5.
pub const DHCPV6_AUTH_ALGORITHM_HMAC_MD5: u8 = 1;
/// Replay Detection Method value for a monotonically increasing value.
pub const DHCPV6_AUTH_RDM_MONOTONIC_COUNTER: u8 = 0;

/// DHCPv6 SOLICIT message type.
pub const DHCPV6_SOLICIT: u8 = 1;
/// DHCPv6 ADVERTISE message type.
pub const DHCPV6_ADVERTISE: u8 = 2;
/// DHCPv6 REQUEST message type.
pub const DHCPV6_REQUEST: u8 = 3;
/// DHCPv6 CONFIRM message type.
pub const DHCPV6_CONFIRM: u8 = 4;
/// DHCPv6 RENEW message type.
pub const DHCPV6_RENEW: u8 = 5;
/// DHCPv6 REBIND message type.
pub const DHCPV6_REBIND: u8 = 6;
/// DHCPv6 REPLY message type.
pub const DHCPV6_REPLY: u8 = 7;
/// DHCPv6 RELEASE message type.
pub const DHCPV6_RELEASE: u8 = 8;
/// DHCPv6 DECLINE message type.
pub const DHCPV6_DECLINE: u8 = 9;
/// DHCPv6 RECONFIGURE message type.
pub const DHCPV6_RECONFIGURE: u8 = 10;
/// DHCPv6 INFORMATION-REQUEST message type.
pub const DHCPV6_INFORMATION_REQUEST: u8 = 11;
/// DHCPv6 RELAY-FORW message type.
pub const DHCPV6_RELAY_FORW: u8 = 12;
/// DHCPv6 RELAY-REPL message type.
pub const DHCPV6_RELAY_REPL: u8 = 13;
/// DHCPv6 LEASEQUERY message type.
pub const DHCPV6_LEASEQUERY: u8 = 14;
/// DHCPv6 LEASEQUERY-REPLY message type.
pub const DHCPV6_LEASEQUERY_REPLY: u8 = 15;
/// DHCPv6 LEASEQUERY-DONE message type.
pub const DHCPV6_LEASEQUERY_DONE: u8 = 16;
/// DHCPv6 LEASEQUERY-DATA message type.
pub const DHCPV6_LEASEQUERY_DATA: u8 = 17;
/// DHCPv6 RECONFIGURE-REQUEST message type.
pub const DHCPV6_RECONFIGURE_REQUEST: u8 = 18;
/// DHCPv6 RECONFIGURE-REPLY message type.
pub const DHCPV6_RECONFIGURE_REPLY: u8 = 19;
/// DHCPV4-QUERY message type carried by DHCPv6.
pub const DHCPV6_DHCPV4_QUERY: u8 = 20;
/// DHCPV4-RESPONSE message type carried by DHCPv6.
pub const DHCPV6_DHCPV4_RESPONSE: u8 = 21;
/// DHCPv6 ACTIVELEASEQUERY message type.
pub const DHCPV6_ACTIVE_LEASEQUERY: u8 = 22;
/// DHCPv6 STARTTLS message type.
pub const DHCPV6_STARTTLS: u8 = 23;
/// DHCPv6 BNDUPD failover message type.
pub const DHCPV6_BNDUPD: u8 = 24;
/// DHCPv6 BNDREPLY failover message type.
pub const DHCPV6_BNDREPLY: u8 = 25;
/// DHCPv6 POOLREQ failover message type.
pub const DHCPV6_POOLREQ: u8 = 26;
/// DHCPv6 POOLRESP failover message type.
pub const DHCPV6_POOLRESP: u8 = 27;
/// DHCPv6 UPDREQ failover message type.
pub const DHCPV6_UPDREQ: u8 = 28;
/// DHCPv6 UPDREQALL failover message type.
pub const DHCPV6_UPDREQALL: u8 = 29;
/// DHCPv6 UPDDONE failover message type.
pub const DHCPV6_UPDDONE: u8 = 30;
/// DHCPv6 CONNECT failover message type.
pub const DHCPV6_CONNECT: u8 = 31;
/// DHCPv6 CONNECTREPLY failover message type.
pub const DHCPV6_CONNECTREPLY: u8 = 32;
/// DHCPv6 DISCONNECT failover message type.
pub const DHCPV6_DISCONNECT: u8 = 33;
/// DHCPv6 STATE failover message type.
pub const DHCPV6_STATE: u8 = 34;
/// DHCPv6 CONTACT failover message type.
pub const DHCPV6_CONTACT: u8 = 35;
/// DHCPv6 ADDR-REG-INFORM address-registration message type.
pub const DHCPV6_ADDR_REG_INFORM: u8 = 36;
/// DHCPv6 ADDR-REG-REPLY address-registration message type.
pub const DHCPV6_ADDR_REG_REPLY: u8 = 37;

/// Reserved DHCPv6 message type codepoint.
pub const DHCPV6_MESSAGE_TYPE_RESERVED: u8 = 0;
/// Lowest currently unassigned DHCPv6 message type codepoint.
pub const DHCPV6_MESSAGE_TYPE_UNASSIGNED_START: u8 = 38;
/// Highest currently unassigned DHCPv6 message type codepoint.
pub const DHCPV6_MESSAGE_TYPE_UNASSIGNED_END: u8 = u8::MAX;

/// Registry assignment status for a DHCPv6 message type codepoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6MessageTypeStatus {
    /// Codepoint is reserved by the registry.
    Reserved,
    /// Codepoint has a registry assignment. The crate may still treat the
    /// corresponding message family as packet data until a later layer adds
    /// typed behavior.
    Registered,
    /// Codepoint is unassigned by the registry.
    Unassigned,
}

/// One DHCPv6 message-type registry row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dhcpv6MessageTypeMeta {
    /// Wire codepoint.
    pub code: u8,
    /// Registered message name or range label.
    pub name: &'static str,
    /// Registry assignment status.
    pub status: Dhcpv6MessageTypeStatus,
}

/// Return registry metadata for any DHCPv6 message type codepoint.
pub const fn dhcpv6_message_type_meta(code: u8) -> Dhcpv6MessageTypeMeta {
    match code {
        DHCPV6_MESSAGE_TYPE_RESERVED => {
            dhcpv6_message_type_entry(code, "Reserved", Dhcpv6MessageTypeStatus::Reserved)
        }
        DHCPV6_SOLICIT => {
            dhcpv6_message_type_entry(code, "SOLICIT", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_ADVERTISE => {
            dhcpv6_message_type_entry(code, "ADVERTISE", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_REQUEST => {
            dhcpv6_message_type_entry(code, "REQUEST", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_CONFIRM => {
            dhcpv6_message_type_entry(code, "CONFIRM", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_RENEW => {
            dhcpv6_message_type_entry(code, "RENEW", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_REBIND => {
            dhcpv6_message_type_entry(code, "REBIND", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_REPLY => {
            dhcpv6_message_type_entry(code, "REPLY", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_RELEASE => {
            dhcpv6_message_type_entry(code, "RELEASE", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_DECLINE => {
            dhcpv6_message_type_entry(code, "DECLINE", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_RECONFIGURE => {
            dhcpv6_message_type_entry(code, "RECONFIGURE", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_INFORMATION_REQUEST => dhcpv6_message_type_entry(
            code,
            "INFORMATION-REQUEST",
            Dhcpv6MessageTypeStatus::Registered,
        ),
        DHCPV6_RELAY_FORW => {
            dhcpv6_message_type_entry(code, "RELAY-FORW", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_RELAY_REPL => {
            dhcpv6_message_type_entry(code, "RELAY-REPL", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_LEASEQUERY => {
            dhcpv6_message_type_entry(code, "LEASEQUERY", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_LEASEQUERY_REPLY => dhcpv6_message_type_entry(
            code,
            "LEASEQUERY-REPLY",
            Dhcpv6MessageTypeStatus::Registered,
        ),
        DHCPV6_LEASEQUERY_DONE => {
            dhcpv6_message_type_entry(code, "LEASEQUERY-DONE", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_LEASEQUERY_DATA => {
            dhcpv6_message_type_entry(code, "LEASEQUERY-DATA", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_RECONFIGURE_REQUEST => dhcpv6_message_type_entry(
            code,
            "RECONFIGURE-REQUEST",
            Dhcpv6MessageTypeStatus::Registered,
        ),
        DHCPV6_RECONFIGURE_REPLY => dhcpv6_message_type_entry(
            code,
            "RECONFIGURE-REPLY",
            Dhcpv6MessageTypeStatus::Registered,
        ),
        DHCPV6_DHCPV4_QUERY => {
            dhcpv6_message_type_entry(code, "DHCPV4-QUERY", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_DHCPV4_RESPONSE => {
            dhcpv6_message_type_entry(code, "DHCPV4-RESPONSE", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_ACTIVE_LEASEQUERY => dhcpv6_message_type_entry(
            code,
            "ACTIVELEASEQUERY",
            Dhcpv6MessageTypeStatus::Registered,
        ),
        DHCPV6_STARTTLS => {
            dhcpv6_message_type_entry(code, "STARTTLS", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_BNDUPD => {
            dhcpv6_message_type_entry(code, "BNDUPD", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_BNDREPLY => {
            dhcpv6_message_type_entry(code, "BNDREPLY", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_POOLREQ => {
            dhcpv6_message_type_entry(code, "POOLREQ", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_POOLRESP => {
            dhcpv6_message_type_entry(code, "POOLRESP", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_UPDREQ => {
            dhcpv6_message_type_entry(code, "UPDREQ", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_UPDREQALL => {
            dhcpv6_message_type_entry(code, "UPDREQALL", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_UPDDONE => {
            dhcpv6_message_type_entry(code, "UPDDONE", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_CONNECT => {
            dhcpv6_message_type_entry(code, "CONNECT", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_CONNECTREPLY => {
            dhcpv6_message_type_entry(code, "CONNECTREPLY", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_DISCONNECT => {
            dhcpv6_message_type_entry(code, "DISCONNECT", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_STATE => {
            dhcpv6_message_type_entry(code, "STATE", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_CONTACT => {
            dhcpv6_message_type_entry(code, "CONTACT", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_ADDR_REG_INFORM => {
            dhcpv6_message_type_entry(code, "ADDR-REG-INFORM", Dhcpv6MessageTypeStatus::Registered)
        }
        DHCPV6_ADDR_REG_REPLY => {
            dhcpv6_message_type_entry(code, "ADDR-REG-REPLY", Dhcpv6MessageTypeStatus::Registered)
        }
        _ => dhcpv6_message_type_entry(code, "Unassigned", Dhcpv6MessageTypeStatus::Unassigned),
    }
}

/// Registry status for a DHCPv6 message type codepoint.
pub const fn dhcpv6_message_type_status(code: u8) -> Dhcpv6MessageTypeStatus {
    dhcpv6_message_type_meta(code).status
}

/// Registered DHCPv6 message name for a codepoint.
pub const fn dhcpv6_message_type_name(code: u8) -> Option<&'static str> {
    match dhcpv6_message_type_meta(code).status {
        Dhcpv6MessageTypeStatus::Registered => Some(dhcpv6_message_type_meta(code).name),
        _ => None,
    }
}

const fn dhcpv6_message_type_entry(
    code: u8,
    name: &'static str,
    status: Dhcpv6MessageTypeStatus,
) -> Dhcpv6MessageTypeMeta {
    Dhcpv6MessageTypeMeta { code, name, status }
}

/// DHCPv6 Status Code: Success.
pub const DHCPV6_STATUS_SUCCESS: u16 = 0;
/// DHCPv6 Status Code: UnspecFail.
pub const DHCPV6_STATUS_UNSPEC_FAIL: u16 = 1;
/// DHCPv6 Status Code: NoAddrsAvail.
pub const DHCPV6_STATUS_NO_ADDRS_AVAIL: u16 = 2;
/// DHCPv6 Status Code: NoBinding.
pub const DHCPV6_STATUS_NO_BINDING: u16 = 3;
/// DHCPv6 Status Code: NotOnLink.
pub const DHCPV6_STATUS_NOT_ON_LINK: u16 = 4;
/// DHCPv6 Status Code: UseMulticast (obsolete).
pub const DHCPV6_STATUS_USE_MULTICAST: u16 = 5;
/// DHCPv6 Status Code: NoPrefixAvail.
pub const DHCPV6_STATUS_NO_PREFIX_AVAIL: u16 = 6;
/// DHCPv6 Status Code: UnknownQueryType.
pub const DHCPV6_STATUS_UNKNOWN_QUERY_TYPE: u16 = 7;
/// DHCPv6 Status Code: MalformedQuery.
pub const DHCPV6_STATUS_MALFORMED_QUERY: u16 = 8;
/// DHCPv6 Status Code: NotConfigured.
pub const DHCPV6_STATUS_NOT_CONFIGURED: u16 = 9;
/// DHCPv6 Status Code: NotAllowed.
pub const DHCPV6_STATUS_NOT_ALLOWED: u16 = 10;
/// DHCPv6 Status Code: QueryTerminated.
pub const DHCPV6_STATUS_QUERY_TERMINATED: u16 = 11;
/// DHCPv6 Status Code: DataMissing.
pub const DHCPV6_STATUS_DATA_MISSING: u16 = 12;
/// DHCPv6 Status Code: CatchUpComplete.
pub const DHCPV6_STATUS_CATCH_UP_COMPLETE: u16 = 13;
/// DHCPv6 Status Code: NotSupported.
pub const DHCPV6_STATUS_NOT_SUPPORTED: u16 = 14;
/// DHCPv6 Status Code: TLSConnectionRefused.
pub const DHCPV6_STATUS_TLS_CONNECTION_REFUSED: u16 = 15;
/// DHCPv6 Status Code: AddressInUse.
pub const DHCPV6_STATUS_ADDRESS_IN_USE: u16 = 16;
/// DHCPv6 Status Code: ConfigurationConflict.
pub const DHCPV6_STATUS_CONFIGURATION_CONFLICT: u16 = 17;
/// DHCPv6 Status Code: MissingBindingInformation.
pub const DHCPV6_STATUS_MISSING_BINDING_INFORMATION: u16 = 18;
/// DHCPv6 Status Code: OutdatedBindingInformation.
pub const DHCPV6_STATUS_OUTDATED_BINDING_INFORMATION: u16 = 19;
/// DHCPv6 Status Code: ServerShuttingDown.
pub const DHCPV6_STATUS_SERVER_SHUTTING_DOWN: u16 = 20;
/// DHCPv6 Status Code: DNSUpdateNotSupported.
pub const DHCPV6_STATUS_DNS_UPDATE_NOT_SUPPORTED: u16 = 21;
/// DHCPv6 Status Code: ExcessiveTimeSkew.
pub const DHCPV6_STATUS_EXCESSIVE_TIME_SKEW: u16 = 22;
/// DHCPv6 Status Code: NoSRv6LocatorAvail.
pub const DHCPV6_STATUS_NO_SRV6_LOCATOR_AVAIL: u16 = 23;

/// Lowest currently unassigned DHCPv6 status code.
pub const DHCPV6_STATUS_UNASSIGNED_START: u16 = 24;
/// Highest currently unassigned DHCPv6 status code.
pub const DHCPV6_STATUS_UNASSIGNED_END: u16 = u16::MAX;

/// Registry assignment status for a DHCPv6 status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6StatusCodeStatus {
    /// Codepoint has a registry assignment.
    Registered,
    /// Codepoint is still registered but marked obsolete.
    Obsolete,
    /// Codepoint is unassigned by the registry.
    Unassigned,
}

/// One DHCPv6 status-code registry row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dhcpv6StatusCodeMeta {
    /// Wire codepoint.
    pub code: u16,
    /// Registered status name or range label.
    pub name: &'static str,
    /// Registry assignment status.
    pub status: Dhcpv6StatusCodeStatus,
}

/// Return registry metadata for any DHCPv6 status code.
pub const fn dhcpv6_status_code_meta(code: u16) -> Dhcpv6StatusCodeMeta {
    match code {
        DHCPV6_STATUS_SUCCESS => {
            dhcpv6_status_code_entry(code, "Success", Dhcpv6StatusCodeStatus::Registered)
        }
        DHCPV6_STATUS_UNSPEC_FAIL => {
            dhcpv6_status_code_entry(code, "UnspecFail", Dhcpv6StatusCodeStatus::Registered)
        }
        DHCPV6_STATUS_NO_ADDRS_AVAIL => {
            dhcpv6_status_code_entry(code, "NoAddrsAvail", Dhcpv6StatusCodeStatus::Registered)
        }
        DHCPV6_STATUS_NO_BINDING => {
            dhcpv6_status_code_entry(code, "NoBinding", Dhcpv6StatusCodeStatus::Registered)
        }
        DHCPV6_STATUS_NOT_ON_LINK => {
            dhcpv6_status_code_entry(code, "NotOnLink", Dhcpv6StatusCodeStatus::Registered)
        }
        DHCPV6_STATUS_USE_MULTICAST => {
            dhcpv6_status_code_entry(code, "UseMulticast", Dhcpv6StatusCodeStatus::Obsolete)
        }
        DHCPV6_STATUS_NO_PREFIX_AVAIL => {
            dhcpv6_status_code_entry(code, "NoPrefixAvail", Dhcpv6StatusCodeStatus::Registered)
        }
        DHCPV6_STATUS_UNKNOWN_QUERY_TYPE => {
            dhcpv6_status_code_entry(code, "UnknownQueryType", Dhcpv6StatusCodeStatus::Registered)
        }
        DHCPV6_STATUS_MALFORMED_QUERY => {
            dhcpv6_status_code_entry(code, "MalformedQuery", Dhcpv6StatusCodeStatus::Registered)
        }
        DHCPV6_STATUS_NOT_CONFIGURED => {
            dhcpv6_status_code_entry(code, "NotConfigured", Dhcpv6StatusCodeStatus::Registered)
        }
        DHCPV6_STATUS_NOT_ALLOWED => {
            dhcpv6_status_code_entry(code, "NotAllowed", Dhcpv6StatusCodeStatus::Registered)
        }
        DHCPV6_STATUS_QUERY_TERMINATED => {
            dhcpv6_status_code_entry(code, "QueryTerminated", Dhcpv6StatusCodeStatus::Registered)
        }
        DHCPV6_STATUS_DATA_MISSING => {
            dhcpv6_status_code_entry(code, "DataMissing", Dhcpv6StatusCodeStatus::Registered)
        }
        DHCPV6_STATUS_CATCH_UP_COMPLETE => {
            dhcpv6_status_code_entry(code, "CatchUpComplete", Dhcpv6StatusCodeStatus::Registered)
        }
        DHCPV6_STATUS_NOT_SUPPORTED => {
            dhcpv6_status_code_entry(code, "NotSupported", Dhcpv6StatusCodeStatus::Registered)
        }
        DHCPV6_STATUS_TLS_CONNECTION_REFUSED => dhcpv6_status_code_entry(
            code,
            "TLSConnectionRefused",
            Dhcpv6StatusCodeStatus::Registered,
        ),
        DHCPV6_STATUS_ADDRESS_IN_USE => {
            dhcpv6_status_code_entry(code, "AddressInUse", Dhcpv6StatusCodeStatus::Registered)
        }
        DHCPV6_STATUS_CONFIGURATION_CONFLICT => dhcpv6_status_code_entry(
            code,
            "ConfigurationConflict",
            Dhcpv6StatusCodeStatus::Registered,
        ),
        DHCPV6_STATUS_MISSING_BINDING_INFORMATION => dhcpv6_status_code_entry(
            code,
            "MissingBindingInformation",
            Dhcpv6StatusCodeStatus::Registered,
        ),
        DHCPV6_STATUS_OUTDATED_BINDING_INFORMATION => dhcpv6_status_code_entry(
            code,
            "OutdatedBindingInformation",
            Dhcpv6StatusCodeStatus::Registered,
        ),
        DHCPV6_STATUS_SERVER_SHUTTING_DOWN => dhcpv6_status_code_entry(
            code,
            "ServerShuttingDown",
            Dhcpv6StatusCodeStatus::Registered,
        ),
        DHCPV6_STATUS_DNS_UPDATE_NOT_SUPPORTED => dhcpv6_status_code_entry(
            code,
            "DNSUpdateNotSupported",
            Dhcpv6StatusCodeStatus::Registered,
        ),
        DHCPV6_STATUS_EXCESSIVE_TIME_SKEW => dhcpv6_status_code_entry(
            code,
            "ExcessiveTimeSkew",
            Dhcpv6StatusCodeStatus::Registered,
        ),
        DHCPV6_STATUS_NO_SRV6_LOCATOR_AVAIL => dhcpv6_status_code_entry(
            code,
            "NoSRv6LocatorAvail",
            Dhcpv6StatusCodeStatus::Registered,
        ),
        _ => dhcpv6_status_code_entry(code, "Unassigned", Dhcpv6StatusCodeStatus::Unassigned),
    }
}

/// Registry status for a DHCPv6 status code.
pub const fn dhcpv6_status_code_status(code: u16) -> Dhcpv6StatusCodeStatus {
    dhcpv6_status_code_meta(code).status
}

/// Registered DHCPv6 status-code name for a codepoint.
pub const fn dhcpv6_status_code_name(code: u16) -> Option<&'static str> {
    match dhcpv6_status_code_meta(code).status {
        Dhcpv6StatusCodeStatus::Registered | Dhcpv6StatusCodeStatus::Obsolete => {
            Some(dhcpv6_status_code_meta(code).name)
        }
        Dhcpv6StatusCodeStatus::Unassigned => None,
    }
}

const fn dhcpv6_status_code_entry(
    code: u16,
    name: &'static str,
    status: Dhcpv6StatusCodeStatus,
) -> Dhcpv6StatusCodeMeta {
    Dhcpv6StatusCodeMeta { code, name, status }
}

/// DHCPv6 DUID-LLT type.
pub const DHCPV6_DUID_LLT: u16 = 1;
/// DHCPv6 DUID-EN type.
pub const DHCPV6_DUID_EN: u16 = 2;
/// DHCPv6 DUID-LL type.
pub const DHCPV6_DUID_LL: u16 = 3;
/// DHCPv6 DUID-UUID type.
pub const DHCPV6_DUID_UUID: u16 = 4;
/// Lowest currently unassigned DHCPv6 DUID type.
pub const DHCPV6_DUID_UNASSIGNED_START: u16 = 5;
/// Highest currently unassigned DHCPv6 DUID type.
pub const DHCPV6_DUID_UNASSIGNED_END: u16 = u16::MAX;

#[cfg(test)]
mod dhcpv6_constants_tests {
    use super::*;

    #[test]
    fn dhcpv6_wire_lengths_and_ports_match_rfc9915() {
        assert_eq!(DHCPV6_CLIENT_SERVER_HEADER_LEN, 4);
        assert_eq!(DHCPV6_RELAY_HEADER_LEN, 34);
        assert_eq!(DHCPV6_OPTION_HEADER_LEN, 4);
        assert_eq!(DHCPV6_TRANSACTION_ID_LEN, 3);
        assert_eq!(DHCPV6_TRANSACTION_ID_MASK, 0x00ff_ffff);
        assert_eq!(DHCPV6_TRANSACTION_ID_MAX, 0x00ff_ffff);
        assert_eq!(DHCPV6_HOP_COUNT_LIMIT, 8);
        assert_eq!(DHCPV6_CLIENT_PORT, 546);
        assert_eq!(DHCPV6_SERVER_PORT, 547);
    }

    #[test]
    fn dhcpv6_message_registry_metadata_preserves_registered_and_unassigned() {
        for code in 1..=37 {
            let meta = dhcpv6_message_type_meta(code);
            assert_eq!(meta.code, code);
            assert_eq!(
                meta.status,
                Dhcpv6MessageTypeStatus::Registered,
                "message type {code} should be registered",
            );
            assert_eq!(dhcpv6_message_type_name(code), Some(meta.name));
        }

        let reserved = dhcpv6_message_type_meta(DHCPV6_MESSAGE_TYPE_RESERVED);
        assert_eq!(reserved.name, "Reserved");
        assert_eq!(reserved.status, Dhcpv6MessageTypeStatus::Reserved);
        assert_eq!(dhcpv6_message_type_name(DHCPV6_MESSAGE_TYPE_RESERVED), None);

        let unassigned = dhcpv6_message_type_meta(DHCPV6_MESSAGE_TYPE_UNASSIGNED_START);
        assert_eq!(unassigned.name, "Unassigned");
        assert_eq!(unassigned.status, Dhcpv6MessageTypeStatus::Unassigned);
        assert_eq!(
            dhcpv6_message_type_name(DHCPV6_MESSAGE_TYPE_UNASSIGNED_END),
            None
        );
    }

    #[test]
    fn dhcpv6_status_registry_metadata_preserves_obsolete_and_unassigned() {
        for code in 0..=23 {
            let meta = dhcpv6_status_code_meta(code);
            assert_eq!(meta.code, code);
            assert!(
                matches!(
                    meta.status,
                    Dhcpv6StatusCodeStatus::Registered | Dhcpv6StatusCodeStatus::Obsolete
                ),
                "status code {code} should be known",
            );
            assert_eq!(dhcpv6_status_code_name(code), Some(meta.name));
        }

        let obsolete = dhcpv6_status_code_meta(DHCPV6_STATUS_USE_MULTICAST);
        assert_eq!(obsolete.name, "UseMulticast");
        assert_eq!(obsolete.status, Dhcpv6StatusCodeStatus::Obsolete);

        let unassigned = dhcpv6_status_code_meta(DHCPV6_STATUS_UNASSIGNED_START);
        assert_eq!(unassigned.name, "Unassigned");
        assert_eq!(unassigned.status, Dhcpv6StatusCodeStatus::Unassigned);
        assert_eq!(dhcpv6_status_code_name(DHCPV6_STATUS_UNASSIGNED_END), None);
    }

    #[test]
    fn dhcpv6_core_codepoint_constants_match_registries() {
        assert_eq!(DHCPV6_SOLICIT, 1);
        assert_eq!(DHCPV6_RELAY_FORW, 12);
        assert_eq!(DHCPV6_ADDR_REG_REPLY, 37);
        assert_eq!(DHCPV6_STATUS_SUCCESS, 0);
        assert_eq!(DHCPV6_STATUS_NO_SRV6_LOCATOR_AVAIL, 23);
        assert_eq!(DHCPV6_DUID_LLT, 1);
        assert_eq!(DHCPV6_DUID_EN, 2);
        assert_eq!(DHCPV6_DUID_LL, 3);
        assert_eq!(DHCPV6_DUID_UUID, 4);
    }
}
