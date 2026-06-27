//! Source-backed DHCPv6 option-code metadata.
//!
//! Source: IANA "Dynamic Host Configuration Protocol for IPv6 (DHCPv6)
//! Parameters" registry, sub-registry "Option Codes" (updated 2026-03-10).
//! The table records the registered name plus the Client ORO and singleton
//! columns where IANA publishes them. The wire-format codec remains raw-first:
//! metadata classifies codepoints but does not require typed payload support.

/// Registry assignment status for a DHCPv6 option codepoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6OptionStatus {
    /// Codepoint is reserved by the registry.
    Reserved,
    /// Codepoint is assigned by the registry.
    Assigned,
    /// Codepoint is assigned but marked obsolete by the registry.
    Obsolete,
    /// Codepoint is unassigned by the registry.
    Unassigned,
    /// Codepoint is not covered by the registry table bundled with this crate.
    Unknown,
}

/// IANA Client ORO column for a DHCPv6 option codepoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6ClientOro {
    /// The option is not requested through the Client Option Request option.
    No,
    /// The option may be requested through the Client Option Request option.
    Yes,
    /// The option may optionally appear in the Client Option Request option.
    Optional,
    /// Required for Information-request messages.
    RequiredForInformationRequest,
    /// Required for Solicit messages.
    RequiredForSolicit,
}

/// IANA singleton column for a DHCPv6 option codepoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6OptionSingleton {
    /// At most one instance is expected in the enclosing option scope.
    Yes,
    /// Multiple instances may be present in the enclosing option scope.
    No,
}

impl Dhcpv6OptionSingleton {
    /// True when the registry marks the option as singleton.
    pub const fn is_singleton(self) -> bool {
        matches!(self, Self::Yes)
    }
}

/// One source-backed DHCPv6 option-code registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dhcpv6OptionMeta {
    /// Wire codepoint.
    pub code: u16,
    /// Registered option name, or a range/status label for non-assigned codes.
    pub name: &'static str,
    /// Registry assignment status.
    pub status: Dhcpv6OptionStatus,
    /// IANA Client ORO column, when published for the row.
    pub client_oro: Option<Dhcpv6ClientOro>,
    /// IANA singleton column, when published for the row.
    pub singleton: Option<Dhcpv6OptionSingleton>,
}

/// Last explicit DHCPv6 option-code row included from IANA.
pub const DHCPV6_OPTION_REGISTRY_EXPLICIT_END: u16 = 150;
/// Lowest currently unassigned DHCPv6 option codepoint in the trailing range.
pub const DHCPV6_OPTION_UNASSIGNED_START: u16 = 151;
/// Highest DHCPv6 option codepoint in the trailing unassigned range.
pub const DHCPV6_OPTION_UNASSIGNED_END: u16 = u16::MAX;

/// Return registry metadata for any DHCPv6 option codepoint.
pub const fn dhcpv6_option_meta(code: u16) -> Dhcpv6OptionMeta {
    if code <= DHCPV6_OPTION_REGISTRY_EXPLICIT_END {
        return DHCPV6_OPTION_META[code as usize];
    }
    if code >= DHCPV6_OPTION_UNASSIGNED_START {
        return entry(code, "Unassigned", UNASSIGNED, None, None);
    }
    entry(code, "Unknown", UNKNOWN, None, None)
}

/// Registry status for a DHCPv6 option codepoint.
pub const fn dhcpv6_option_status(code: u16) -> Dhcpv6OptionStatus {
    dhcpv6_option_meta(code).status
}

/// Registered option name for a DHCPv6 option codepoint, when assigned.
pub const fn dhcpv6_option_name(code: u16) -> Option<&'static str> {
    match dhcpv6_option_meta(code).status {
        Dhcpv6OptionStatus::Assigned | Dhcpv6OptionStatus::Obsolete => {
            Some(dhcpv6_option_meta(code).name)
        }
        Dhcpv6OptionStatus::Reserved
        | Dhcpv6OptionStatus::Unassigned
        | Dhcpv6OptionStatus::Unknown => None,
    }
}

const fn entry(
    code: u16,
    name: &'static str,
    status: Dhcpv6OptionStatus,
    client_oro: Option<Dhcpv6ClientOro>,
    singleton: Option<Dhcpv6OptionSingleton>,
) -> Dhcpv6OptionMeta {
    Dhcpv6OptionMeta {
        code,
        name,
        status,
        client_oro,
        singleton,
    }
}

type Oro = Dhcpv6ClientOro;
type Singleton = Dhcpv6OptionSingleton;

const RESERVED: Dhcpv6OptionStatus = Dhcpv6OptionStatus::Reserved;
const ASSIGNED: Dhcpv6OptionStatus = Dhcpv6OptionStatus::Assigned;
const OBSOLETE: Dhcpv6OptionStatus = Dhcpv6OptionStatus::Obsolete;
const UNASSIGNED: Dhcpv6OptionStatus = Dhcpv6OptionStatus::Unassigned;
const UNKNOWN: Dhcpv6OptionStatus = Dhcpv6OptionStatus::Unknown;

const DHCPV6_OPTION_META: [Dhcpv6OptionMeta; 151] = [
    entry(0, "Reserved", RESERVED, None, None),
    entry(
        1,
        "OPTION_CLIENTID",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        2,
        "OPTION_SERVERID",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        3,
        "OPTION_IA_NA",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::No),
    ),
    entry(
        4,
        "OPTION_IA_TA",
        OBSOLETE,
        Some(Oro::No),
        Some(Singleton::No),
    ),
    entry(
        5,
        "OPTION_IAADDR",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::No),
    ),
    entry(
        6,
        "OPTION_ORO",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        7,
        "OPTION_PREFERENCE",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        8,
        "OPTION_ELAPSED_TIME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        9,
        "OPTION_RELAY_MSG",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        10,
        "Unassigned",
        UNASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        11,
        "OPTION_AUTH",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        12,
        "OPTION_UNICAST",
        OBSOLETE,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        13,
        "OPTION_STATUS_CODE",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        14,
        "OPTION_RAPID_COMMIT",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        15,
        "OPTION_USER_CLASS",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        16,
        "OPTION_VENDOR_CLASS",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::No),
    ),
    entry(
        17,
        "OPTION_VENDOR_OPTS",
        ASSIGNED,
        Some(Oro::Optional),
        Some(Singleton::No),
    ),
    entry(
        18,
        "OPTION_INTERFACE_ID",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        19,
        "OPTION_RECONF_MSG",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        20,
        "OPTION_RECONF_ACCEPT",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        21,
        "OPTION_SIP_SERVER_D",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        22,
        "OPTION_SIP_SERVER_A",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        23,
        "OPTION_DNS_SERVERS",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        24,
        "OPTION_DOMAIN_LIST",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        25,
        "OPTION_IA_PD",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::No),
    ),
    entry(
        26,
        "OPTION_IAPREFIX",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::No),
    ),
    entry(
        27,
        "OPTION_NIS_SERVERS",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        28,
        "OPTION_NISP_SERVERS",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        29,
        "OPTION_NIS_DOMAIN_NAME",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        30,
        "OPTION_NISP_DOMAIN_NAME",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        31,
        "OPTION_SNTP_SERVERS",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        32,
        "OPTION_INFORMATION_REFRESH_TIME",
        ASSIGNED,
        Some(Oro::RequiredForInformationRequest),
        Some(Singleton::Yes),
    ),
    entry(
        33,
        "OPTION_BCMCS_SERVER_D",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        34,
        "OPTION_BCMCS_SERVER_A",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        35,
        "Unassigned",
        UNASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        36,
        "OPTION_GEOCONF_CIVIC",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        37,
        "OPTION_REMOTE_ID",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        38,
        "OPTION_SUBSCRIBER_ID",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        39,
        "OPTION_CLIENT_FQDN",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        40,
        "OPTION_PANA_AGENT",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        41,
        "OPTION_NEW_POSIX_TIMEZONE",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        42,
        "OPTION_NEW_TZDB_TIMEZONE",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        43,
        "OPTION_ERO",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        44,
        "OPTION_LQ_QUERY",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        45,
        "OPTION_CLIENT_DATA",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        46,
        "OPTION_CLT_TIME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        47,
        "OPTION_LQ_RELAY_DATA",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        48,
        "OPTION_LQ_CLIENT_LINK",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        49,
        "OPTION_MIP6_HNIDF",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        50,
        "OPTION_MIP6_VDINF",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        51,
        "OPTION_V6_LOST",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        52,
        "OPTION_CAPWAP_AC_V6",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        53,
        "OPTION_RELAY_ID",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        54,
        "OPTION-IPv6_Address-MoS",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        55,
        "OPTION-IPv6_FQDN-MoS",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        56,
        "OPTION_NTP_SERVER",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        57,
        "OPTION_V6_ACCESS_DOMAIN",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        58,
        "OPTION_SIP_UA_CS_LIST",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        59,
        "OPT_BOOTFILE_URL",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        60,
        "OPT_BOOTFILE_PARAM",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        61,
        "OPTION_CLIENT_ARCH_TYPE",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        62,
        "OPTION_NII",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        63,
        "OPTION_GEOLOCATION",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        64,
        "OPTION_AFTR_NAME",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        65,
        "OPTION_ERP_LOCAL_DOMAIN_NAME",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        66,
        "OPTION_RSOO",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        67,
        "OPTION_PD_EXCLUDE",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        68,
        "OPTION_VSS",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        69,
        "OPTION_MIP6_IDINF",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        70,
        "OPTION_MIP6_UDINF",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        71,
        "OPTION_MIP6_HNP",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        72,
        "OPTION_MIP6_HAA",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        73,
        "OPTION_MIP6_HAF",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        74,
        "OPTION_RDNSS_SELECTION",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        75,
        "OPTION_KRB_PRINCIPAL_NAME",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        76,
        "OPTION_KRB_REALM_NAME",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        77,
        "OPTION_KRB_DEFAULT_REALM_NAME",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        78,
        "OPTION_KRB_KDC",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        79,
        "OPTION_CLIENT_LINKLAYER_ADDR",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        80,
        "OPTION_LINK_ADDRESS",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        81,
        "OPTION_RADIUS",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        82,
        "OPTION_SOL_MAX_RT",
        ASSIGNED,
        Some(Oro::RequiredForSolicit),
        Some(Singleton::Yes),
    ),
    entry(
        83,
        "OPTION_INF_MAX_RT",
        ASSIGNED,
        Some(Oro::RequiredForInformationRequest),
        Some(Singleton::Yes),
    ),
    entry(
        84,
        "OPTION_ADDRSEL",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        85,
        "OPTION_ADDRSEL_TABLE",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        86,
        "OPTION_V6_PCP_SERVER",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::No),
    ),
    entry(
        87,
        "OPTION_DHCPV4_MSG",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        88,
        "OPTION_DHCP4_O_DHCP6_SERVER",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        89,
        "OPTION_S46_RULE",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::No),
    ),
    entry(
        90,
        "OPTION_S46_BR",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::No),
    ),
    entry(
        91,
        "OPTION_S46_DMR",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        92,
        "OPTION_S46_V4V6BIND",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        93,
        "OPTION_S46_PORTPARAMS",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        94,
        "OPTION_S46_CONT_MAPE",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::No),
    ),
    entry(
        95,
        "OPTION_S46_CONT_MAPT",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        96,
        "OPTION_S46_CONT_LW",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        97,
        "OPTION_4RD",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        98,
        "OPTION_4RD_MAP_RULE",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        99,
        "OPTION_4RD_NON_MAP_RULE",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        100,
        "OPTION_LQ_BASE_TIME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        101,
        "OPTION_LQ_START_TIME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        102,
        "OPTION_LQ_END_TIME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        103,
        "DHCP Captive-Portal",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        104,
        "OPTION_MPL_PARAMETERS",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::No),
    ),
    entry(
        105,
        "OPTION_ANI_ATT",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        106,
        "OPTION_ANI_NETWORK_NAME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        107,
        "OPTION_ANI_AP_NAME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        108,
        "OPTION_ANI_AP_BSSID",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        109,
        "OPTION_ANI_OPERATOR_ID",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        110,
        "OPTION_ANI_OPERATOR_REALM",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        111,
        "OPTION_S46_PRIORITY",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        112,
        "OPTION_MUD_URL_V6",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        113,
        "OPTION_V6_PREFIX64",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::No),
    ),
    entry(
        114,
        "OPTION_F_BINDING_STATUS",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        115,
        "OPTION_F_CONNECT_FLAGS",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        116,
        "OPTION_F_DNS_REMOVAL_INFO",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        117,
        "OPTION_F_DNS_HOST_NAME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        118,
        "OPTION_F_DNS_ZONE_NAME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        119,
        "OPTION_F_DNS_FLAGS",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        120,
        "OPTION_F_EXPIRATION_TIME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        121,
        "OPTION_F_MAX_UNACKED_BNDUPD",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        122,
        "OPTION_F_MCLT",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        123,
        "OPTION_F_PARTNER_LIFETIME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        124,
        "OPTION_F_PARTNER_LIFETIME_SENT",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        125,
        "OPTION_F_PARTNER_DOWN_TIME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        126,
        "OPTION_F_PARTNER_RAW_CLT_TIME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        127,
        "OPTION_F_PROTOCOL_VERSION",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        128,
        "OPTION_F_KEEPALIVE_TIME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        129,
        "OPTION_F_RECONFIGURE_DATA",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        130,
        "OPTION_F_RELATIONSHIP_NAME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        131,
        "OPTION_F_SERVER_FLAGS",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        132,
        "OPTION_F_SERVER_STATE",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        133,
        "OPTION_F_START_TIME_OF_STATE",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        134,
        "OPTION_F_STATE_EXPIRATION_TIME",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        135,
        "OPTION_RELAY_PORT",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        136,
        "OPTION_V6_SZTP_REDIRECT",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        137,
        "OPTION_S46_BIND_IPV6_PREFIX",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        138,
        "OPTION_IA_LL",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::No),
    ),
    entry(
        139,
        "OPTION_LLADDR",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::No),
    ),
    entry(
        140,
        "OPTION_SLAP_QUAD",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::Yes),
    ),
    entry(
        141,
        "OPTION_V6_DOTS_RI",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        142,
        "OPTION_V6_DOTS_ADDRESS",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        143,
        "OPTION-IPv6_Address-ANDSF",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        144,
        "OPTION_V6_DNR",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::No),
    ),
    entry(
        145,
        "OPTION_REGISTERED_DOMAIN",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::No),
    ),
    entry(
        146,
        "OPTION_FORWARD_DIST_MANAGER",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        147,
        "OPTION_REVERSE_DIST_MANAGER",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        148,
        "OPTION_ADDR_REG_ENABLE",
        ASSIGNED,
        Some(Oro::Yes),
        Some(Singleton::Yes),
    ),
    entry(
        149,
        "OPTION_IA_SRV6_LOCATOR",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::No),
    ),
    entry(
        150,
        "OPTION_IALOCATOR",
        ASSIGNED,
        Some(Oro::No),
        Some(Singleton::No),
    ),
];

#[cfg(test)]
mod dhcpv6_option_registry_tests {
    use super::{
        dhcpv6_option_meta, dhcpv6_option_name, dhcpv6_option_status, Dhcpv6ClientOro,
        Dhcpv6OptionSingleton, Dhcpv6OptionStatus, DHCPV6_OPTION_REGISTRY_EXPLICIT_END,
        DHCPV6_OPTION_UNASSIGNED_END, DHCPV6_OPTION_UNASSIGNED_START,
    };

    #[test]
    fn dhcpv6_option_registry_core_rows_include_oro_and_singleton() {
        let clientid = dhcpv6_option_meta(1);
        assert_eq!(clientid.name, "OPTION_CLIENTID");
        assert_eq!(clientid.status, Dhcpv6OptionStatus::Assigned);
        assert_eq!(clientid.client_oro, Some(Dhcpv6ClientOro::No));
        assert_eq!(clientid.singleton, Some(Dhcpv6OptionSingleton::Yes));

        let vendor_opts = dhcpv6_option_meta(17);
        assert_eq!(vendor_opts.client_oro, Some(Dhcpv6ClientOro::Optional));
        assert_eq!(vendor_opts.singleton, Some(Dhcpv6OptionSingleton::No));

        let information_refresh = dhcpv6_option_meta(32);
        assert_eq!(
            information_refresh.client_oro,
            Some(Dhcpv6ClientOro::RequiredForInformationRequest),
        );

        let sol_max_rt = dhcpv6_option_meta(82);
        assert_eq!(
            sol_max_rt.client_oro,
            Some(Dhcpv6ClientOro::RequiredForSolicit)
        );

        let v6_dnr = dhcpv6_option_meta(144);
        assert_eq!(v6_dnr.name, "OPTION_V6_DNR");
        assert_eq!(v6_dnr.singleton, Some(Dhcpv6OptionSingleton::No));
    }

    #[test]
    fn dhcpv6_option_registry_obsolete_reserved_and_unassigned_are_distinct() {
        assert_eq!(dhcpv6_option_status(0), Dhcpv6OptionStatus::Reserved);
        assert_eq!(dhcpv6_option_name(0), None);

        assert_eq!(dhcpv6_option_status(4), Dhcpv6OptionStatus::Obsolete);
        assert_eq!(dhcpv6_option_name(4), Some("OPTION_IA_TA"));
        assert_eq!(dhcpv6_option_status(12), Dhcpv6OptionStatus::Obsolete);

        assert_eq!(dhcpv6_option_status(10), Dhcpv6OptionStatus::Unassigned);
        assert_eq!(dhcpv6_option_name(10), None);
        assert_eq!(dhcpv6_option_status(35), Dhcpv6OptionStatus::Unassigned);

        let trailing = dhcpv6_option_meta(DHCPV6_OPTION_UNASSIGNED_START);
        assert_eq!(trailing.name, "Unassigned");
        assert_eq!(trailing.status, Dhcpv6OptionStatus::Unassigned);
        assert_eq!(trailing.client_oro, None);
        assert_eq!(trailing.singleton, None);
        assert_eq!(
            dhcpv6_option_status(DHCPV6_OPTION_UNASSIGNED_END),
            Dhcpv6OptionStatus::Unassigned,
        );
    }

    #[test]
    fn dhcpv6_option_registry_explicit_rows_are_indexed_by_code() {
        let mut assigned = 0usize;
        let mut obsolete = 0usize;
        let mut unassigned = 0usize;
        let mut reserved = 0usize;

        for code in 0..=DHCPV6_OPTION_REGISTRY_EXPLICIT_END {
            let meta = dhcpv6_option_meta(code);
            assert_eq!(meta.code, code);
            assert_ne!(meta.status, Dhcpv6OptionStatus::Unknown);
            match meta.status {
                Dhcpv6OptionStatus::Assigned => assigned += 1,
                Dhcpv6OptionStatus::Obsolete => obsolete += 1,
                Dhcpv6OptionStatus::Unassigned => unassigned += 1,
                Dhcpv6OptionStatus::Reserved => reserved += 1,
                Dhcpv6OptionStatus::Unknown => unreachable!(),
            }
        }

        assert_eq!(assigned, 146);
        assert_eq!(obsolete, 2);
        assert_eq!(unassigned, 2);
        assert_eq!(reserved, 1);
    }

    #[test]
    fn dhcpv6_option_registry_name_only_reports_assigned_rows() {
        assert_eq!(dhcpv6_option_name(1), Some("OPTION_CLIENTID"));
        assert_eq!(dhcpv6_option_name(4), Some("OPTION_IA_TA"));
        assert_eq!(dhcpv6_option_name(10), None);
        assert_eq!(dhcpv6_option_name(0), None);
        assert_eq!(dhcpv6_option_name(151), None);
    }
}
