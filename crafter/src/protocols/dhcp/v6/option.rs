//! DHCPv6 generic option model.
//!
//! DHCPv6 options are 16-bit code, 16-bit length, variable payload TLVs. This
//! module starts with the raw-preserving data model; the serial codec and IANA
//! registry classification live in later modules.

use core::net::Ipv6Addr;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::protocols::dhcp::v4::Dhcpv4;
use crate::protocols::dns::{decode_dns_name_typed, DnsName};

use super::constants::{
    DHCPV6_AUTH_ALGORITHM_CONFIGURATION_TOKEN, DHCPV6_AUTH_ALGORITHM_HMAC_MD5,
    DHCPV6_AUTH_HEADER_LEN, DHCPV6_AUTH_PROTOCOL_CONFIGURATION_TOKEN, DHCPV6_AUTH_PROTOCOL_DELAYED,
    DHCPV6_AUTH_PROTOCOL_DHCPV6_DELAYED_OBSOLETE, DHCPV6_AUTH_PROTOCOL_RECONFIGURE_KEY,
    DHCPV6_AUTH_PROTOCOL_SPLIT_HORIZON_DNS, DHCPV6_AUTH_RDM_MONOTONIC_COUNTER,
    DHCPV6_AUTH_REPLAY_DETECTION_LEN, DHCPV6_OPTION_4RD, DHCPV6_OPTION_4RD_MAP_RULE,
    DHCPV6_OPTION_4RD_NON_MAP_RULE, DHCPV6_OPTION_ADDR_REG_ENABLE, DHCPV6_OPTION_AUTH,
    DHCPV6_OPTION_BOOTFILE_PARAM, DHCPV6_OPTION_BOOTFILE_URL, DHCPV6_OPTION_CAPTIVE_PORTAL,
    DHCPV6_OPTION_CLIENTID, DHCPV6_OPTION_CLIENT_ARCH_TYPE, DHCPV6_OPTION_CLIENT_DATA,
    DHCPV6_OPTION_CLIENT_FQDN, DHCPV6_OPTION_CLIENT_LINKLAYER_ADDR, DHCPV6_OPTION_CLT_TIME,
    DHCPV6_OPTION_DHCPV4_MSG, DHCPV6_OPTION_DNS_SERVERS, DHCPV6_OPTION_DOMAIN_LIST,
    DHCPV6_OPTION_ELAPSED_TIME, DHCPV6_OPTION_F_BINDING_STATUS,
    DHCPV6_OPTION_F_STATE_EXPIRATION_TIME, DHCPV6_OPTION_HEADER_LEN, DHCPV6_OPTION_IAADDR,
    DHCPV6_OPTION_IAPREFIX, DHCPV6_OPTION_IA_NA, DHCPV6_OPTION_IA_PD,
    DHCPV6_OPTION_INFORMATION_REFRESH_TIME, DHCPV6_OPTION_INF_MAX_RT, DHCPV6_OPTION_INTERFACE_ID,
    DHCPV6_OPTION_LQ_BASE_TIME, DHCPV6_OPTION_LQ_CLIENT_LINK, DHCPV6_OPTION_LQ_END_TIME,
    DHCPV6_OPTION_LQ_QUERY, DHCPV6_OPTION_LQ_RELAY_DATA, DHCPV6_OPTION_LQ_START_TIME,
    DHCPV6_OPTION_MUD_URL_V6, DHCPV6_OPTION_NEW_POSIX_TIMEZONE, DHCPV6_OPTION_NEW_TZDB_TIMEZONE,
    DHCPV6_OPTION_NII, DHCPV6_OPTION_NTP_SERVER, DHCPV6_OPTION_ORO, DHCPV6_OPTION_PD_EXCLUDE,
    DHCPV6_OPTION_PREFERENCE, DHCPV6_OPTION_RAPID_COMMIT, DHCPV6_OPTION_RECONF_ACCEPT,
    DHCPV6_OPTION_RECONF_MSG, DHCPV6_OPTION_RELAY_ID, DHCPV6_OPTION_RELAY_MSG,
    DHCPV6_OPTION_REMOTE_ID, DHCPV6_OPTION_RSOO, DHCPV6_OPTION_S46_BIND_IPV6_PREFIX,
    DHCPV6_OPTION_S46_BR, DHCPV6_OPTION_S46_CONT_LW, DHCPV6_OPTION_S46_CONT_MAPE,
    DHCPV6_OPTION_S46_CONT_MAPT, DHCPV6_OPTION_S46_DMR, DHCPV6_OPTION_S46_PORTPARAMS,
    DHCPV6_OPTION_S46_PRIORITY, DHCPV6_OPTION_S46_RULE, DHCPV6_OPTION_S46_V4V6BIND,
    DHCPV6_OPTION_SERVERID, DHCPV6_OPTION_SIP_SERVER_A, DHCPV6_OPTION_SIP_SERVER_D,
    DHCPV6_OPTION_SIP_UA_CS_LIST, DHCPV6_OPTION_SNTP_SERVERS, DHCPV6_OPTION_SOL_MAX_RT,
    DHCPV6_OPTION_STATUS_CODE, DHCPV6_OPTION_SUBSCRIBER_ID, DHCPV6_OPTION_USER_CLASS,
    DHCPV6_OPTION_V6_DNR, DHCPV6_OPTION_V6_PREFIX64, DHCPV6_OPTION_VENDOR_CLASS,
    DHCPV6_OPTION_VENDOR_OPTS, DHCPV6_TIME_INFINITY,
};
use super::duid::Dhcpv6Duid;
use super::message::{dhcpv6_message_type_summary, Dhcpv6MessageType};
use super::registry::dhcpv6_option_name;
use super::status::Dhcpv6StatusCode;

const DHCPV6_IAADDR_HEADER_LEN: usize = 24;
const DHCPV6_IA_NA_HEADER_LEN: usize = 12;
const DHCPV6_IA_PD_HEADER_LEN: usize = 12;
const DHCPV6_IAPREFIX_HEADER_LEN: usize = 25;
const DHCPV6_PREFIX_LEN_MAX: u8 = 128;
const DHCPV6_PD_EXCLUDE_PAYLOAD_MIN_LEN: usize = 2;
const DHCPV6_PD_EXCLUDE_PAYLOAD_MAX_LEN: usize = 17;
const DHCPV6_PD_EXCLUDE_SUBNET_ID_MIN_LEN: usize = 1;
const DHCPV6_PD_EXCLUDE_SUBNET_ID_MAX_LEN: usize = 16;
const DHCPV6_LQ_QUERY_HEADER_LEN: usize = 17;

/// DHCPv6 option codepoint.
///
/// Every 16-bit value is representable so packets can preserve registered,
/// obsolete, unassigned, private, or future codepoints without requiring typed
/// support in the crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dhcpv6OptionCode(u16);

impl Dhcpv6OptionCode {
    /// Create an option codepoint from its raw wire value.
    pub const fn from_code(code: u16) -> Self {
        Self(code)
    }

    /// Raw wire codepoint.
    pub const fn code(self) -> u16 {
        self.0
    }
}

impl From<u16> for Dhcpv6OptionCode {
    fn from(code: u16) -> Self {
        Self::from_code(code)
    }
}

impl From<Dhcpv6OptionCode> for u16 {
    fn from(code: Dhcpv6OptionCode) -> Self {
        code.code()
    }
}

/// Reusable DHCPv6 option payload format family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6OptionFormat {
    /// Zero-length payload.
    Empty,
    /// Opaque payload bytes preserved verbatim.
    Raw,
}

/// Raw-preserving DHCPv6 option payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Dhcpv6OptionValue {
    /// Zero-length payload.
    Empty,
    /// Opaque payload bytes preserved verbatim.
    Raw(Vec<u8>),
}

impl Dhcpv6OptionValue {
    /// View this option value as payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Raw(bytes) => bytes,
        }
    }

    /// Consume this value into payload bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Empty => Vec::new(),
            Self::Raw(bytes) => bytes,
        }
    }

    /// Payload length in bytes.
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// True when the payload has zero bytes.
    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }

    /// Payload format family.
    pub const fn format(&self) -> Dhcpv6OptionFormat {
        match self {
            Self::Empty => Dhcpv6OptionFormat::Empty,
            Self::Raw(_) => Dhcpv6OptionFormat::Raw,
        }
    }
}

impl From<Vec<u8>> for Dhcpv6OptionValue {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Raw(bytes)
    }
}

impl From<&[u8]> for Dhcpv6OptionValue {
    fn from(bytes: &[u8]) -> Self {
        Self::Raw(bytes.to_vec())
    }
}

/// DHCPv6 option TLV.
///
/// The payload is kept as a [`Dhcpv6OptionValue`] so unknown and unsupported
/// options can round-trip through later codecs without losing bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6Option {
    code: Dhcpv6OptionCode,
    value: Dhcpv6OptionValue,
}

/// DHCPv6 Authentication Protocol field.
///
/// Values come from the IANA DHCP Authentication Option protocol namespace.
/// Unknown values are preserved, and the crate never runs an authentication
/// protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6AuthProtocol {
    /// Configuration token protocol.
    ConfigurationToken,
    /// Delayed authentication protocol.
    Delayed,
    /// DHCPv6 delayed authentication protocol, now obsolete.
    Dhcpv6DelayedObsolete,
    /// DHCPv6 Reconfigure Key Authentication Protocol.
    ReconfigureKey,
    /// Split-horizon DNS authentication protocol.
    SplitHorizonDns,
    /// Any other protocol value, preserved verbatim.
    Unknown(u8),
}

/// DHCPv6 Authentication Algorithm field.
///
/// Algorithm values are interpreted by the selected protocol. This enum names
/// registered byte values only and does not compute or verify authentication
/// material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6AuthAlgorithm {
    /// Configuration token algorithm value.
    ConfigurationToken,
    /// HMAC-MD5 keyed hash algorithm value.
    HmacMd5,
    /// Any other algorithm value, preserved verbatim.
    Unknown(u8),
}

/// DHCPv6 Authentication Replay Detection Method field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6ReplayDetectionMethod {
    /// A monotonically increasing 64-bit replay detection value.
    MonotonicCounter,
    /// Any other RDM value, preserved verbatim.
    Unknown(u8),
}

/// DHCPv6 OPTION_AUTH payload.
///
/// This type models the fixed Authentication option fields and preserves the
/// variable authentication information bytes. It is packet data only: the crate
/// never derives keys, signs messages, verifies MACs, or interprets secrets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6Authentication {
    /// Authentication Protocol field.
    pub protocol: Dhcpv6AuthProtocol,
    /// Authentication Algorithm field.
    pub algorithm: Dhcpv6AuthAlgorithm,
    /// Replay Detection Method field.
    pub rdm: Dhcpv6ReplayDetectionMethod,
    /// 64-bit Replay Detection field.
    pub replay_detection: u64,
    /// Authentication Information bytes, preserved verbatim.
    pub authentication_information: Vec<u8>,
}

/// DHCPv6 OPTION_USER_CLASS payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6UserClass {
    class_data: Vec<Vec<u8>>,
}

/// DHCPv6 OPTION_VENDOR_CLASS payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6VendorClass {
    enterprise_number: u32,
    class_data: Vec<Vec<u8>>,
}

/// DHCPv6 enterprise-scoped Vendor Options suboption.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6VendorOption {
    code: Dhcpv6OptionCode,
    payload: Vec<u8>,
}

/// DHCPv6 OPTION_VENDOR_OPTS payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6VendorOptions {
    enterprise_number: u32,
    options: Vec<Dhcpv6VendorOption>,
}

/// DHCPv6 OPTION_REMOTE_ID payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6RemoteId {
    enterprise_number: u32,
    remote_id: Vec<u8>,
}

/// DHCPv6 OPTION_CLIENT_LINKLAYER_ADDR payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6ClientLinkLayerAddress {
    hardware_type: u16,
    link_layer_address: Vec<u8>,
}

/// DHCPv6 OPTION_RSOO payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6RelaySuppliedOptions {
    options: Vec<Dhcpv6Option>,
}

/// DHCPv6 OPTION_DOMAIN_LIST payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6DomainList {
    names: Vec<DnsName>,
}

/// DHCPv6 OPT_BOOTFILE_PARAM payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6BootfileParam {
    parameters: Vec<Vec<u8>>,
}

/// DHCPv6 OPTION_CLIENT_ARCH_TYPE payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6ClientArchitecture {
    architectures: Vec<u16>,
}

/// DHCPv6 OPTION_NII payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dhcpv6NetworkInterfaceIdentifier {
    /// Interface type octet.
    pub interface_type: u8,
    /// Major revision octet.
    pub major: u8,
    /// Minor revision octet.
    pub minor: u8,
}

/// DHCPv6 OPTION_NTP_SERVER suboption.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6NtpSuboption {
    code: Dhcpv6OptionCode,
    payload: Vec<u8>,
}

/// DHCPv6 OPTION_NTP_SERVER payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6NtpServer {
    suboptions: Vec<Dhcpv6NtpSuboption>,
}

/// DHCPv6 OPTION_CLIENT_FQDN payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6ClientFqdn {
    flags: u8,
    domain_name: DnsName,
}

/// DHCPv6 OPTION_STATUS_CODE payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6StatusCodeOption {
    status: Dhcpv6StatusCode,
    message: Vec<u8>,
}

/// DHCPv6 OPTION_IA_NA identity association.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6IaNa {
    iaid: u32,
    t1: u32,
    t2: u32,
    options: Vec<Dhcpv6Option>,
}

/// DHCPv6 OPTION_IA_PD identity association for prefix delegation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6IaPd {
    iaid: u32,
    t1: u32,
    t2: u32,
    options: Vec<Dhcpv6Option>,
}

/// DHCPv6 OPTION_IAPREFIX delegated prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6IaPrefix {
    preferred_lifetime: u32,
    valid_lifetime: u32,
    prefix_length: u8,
    prefix: Ipv6Addr,
    options: Vec<Dhcpv6Option>,
}

/// DHCPv6 OPTION_PD_EXCLUDE payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6PdExclude {
    prefix_length: u8,
    subnet_id: Vec<u8>,
}

/// DHCPv6 S46 container option kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6S46ContainerKind {
    /// OPTION_S46_CONT_MAPE.
    MapE,
    /// OPTION_S46_CONT_MAPT.
    MapT,
    /// OPTION_S46_CONT_LW.
    Lightweight4Over6,
}

/// DHCPv6 S46 container payload with nested DHCPv6 options.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6S46Container {
    kind: Dhcpv6S46ContainerKind,
    options: Vec<Dhcpv6Option>,
}

/// DHCPv6 OPTION_S46_PRIORITY payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6S46Priority {
    option_codes: Vec<u16>,
}

/// DHCPv6 OPTION_V6_DNR SvcParam tuple.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6DnrSvcParam {
    key: u16,
    value: Vec<u8>,
}

/// DHCPv6 OPTION_V6_DNR resolver instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6Dnr {
    service_priority: u16,
    adn: DnsName,
    addresses: Vec<Ipv6Addr>,
    svc_params: Vec<Dhcpv6DnrSvcParam>,
}

/// DHCPv6 Leasequery query type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6LeasequeryType {
    /// Query by IPv6 address.
    ByAddress,
    /// Query by client identifier.
    ByClientId,
    /// Query by relay identifier.
    ByRelayId,
    /// Query type unknown to this crate.
    Unknown(u8),
}

/// DHCPv6 OPTION_LQ_QUERY payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6Leasequery {
    query_type: Dhcpv6LeasequeryType,
    link_address: Ipv6Addr,
    options: Vec<Dhcpv6Option>,
}

/// DHCPv6 OPTION_CLIENT_DATA payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Dhcpv6ClientData {
    options: Vec<Dhcpv6Option>,
}

/// DHCPv6 OPTION_IAADDR address binding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6IaAddr {
    address: Ipv6Addr,
    preferred_lifetime: u32,
    valid_lifetime: u32,
    options: Vec<Dhcpv6Option>,
}

impl Dhcpv6IaAddr {
    /// Create an IA Address option body.
    pub fn new(address: Ipv6Addr, preferred_lifetime: u32, valid_lifetime: u32) -> Self {
        Self {
            address,
            preferred_lifetime,
            valid_lifetime,
            options: Vec::new(),
        }
    }

    /// Decode an IA Address option payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < DHCPV6_IAADDR_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "dhcpv6.option.iaaddr",
                DHCPV6_IAADDR_HEADER_LEN,
                bytes.len(),
            ));
        }

        Ok(Self {
            address: Ipv6Addr::from(copy_array_16(&bytes[0..16])),
            preferred_lifetime: read_u32_be(&bytes[16..20])?,
            valid_lifetime: read_u32_be(&bytes[20..24])?,
            options: Dhcpv6Option::decode_all(&bytes[DHCPV6_IAADDR_HEADER_LEN..])?,
        })
    }

    /// Encode this IA Address option payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(
            DHCPV6_IAADDR_HEADER_LEN
                + self
                    .options
                    .iter()
                    .map(|option| DHCPV6_OPTION_HEADER_LEN + option.payload_len())
                    .sum::<usize>(),
        );
        out.extend_from_slice(&self.address.octets());
        out.extend_from_slice(&self.preferred_lifetime.to_be_bytes());
        out.extend_from_slice(&self.valid_lifetime.to_be_bytes());
        out.extend_from_slice(&Dhcpv6Option::encode_all(&self.options)?);
        Ok(out)
    }

    /// IPv6 address value.
    pub const fn address(&self) -> Ipv6Addr {
        self.address
    }

    /// Preferred lifetime value.
    pub const fn preferred_lifetime(&self) -> u32 {
        self.preferred_lifetime
    }

    /// True when the preferred lifetime uses the DHCPv6 infinity sentinel.
    pub const fn preferred_lifetime_is_infinite(&self) -> bool {
        self.preferred_lifetime == DHCPV6_TIME_INFINITY
    }

    /// Valid lifetime value.
    pub const fn valid_lifetime(&self) -> u32 {
        self.valid_lifetime
    }

    /// True when the valid lifetime uses the DHCPv6 infinity sentinel.
    pub const fn valid_lifetime_is_infinite(&self) -> bool {
        self.valid_lifetime == DHCPV6_TIME_INFINITY
    }

    /// Append a nested option.
    pub fn option(mut self, option: Dhcpv6Option) -> Self {
        self.options.push(option);
        self
    }

    /// Append a nested OPTION_STATUS_CODE option.
    pub fn status_code(self, status: Dhcpv6StatusCodeOption) -> Self {
        self.option(Dhcpv6Option::status_code(status))
    }

    /// Replace the nested option list.
    pub fn options(mut self, options: impl Into<Vec<Dhcpv6Option>>) -> Self {
        self.options = options.into();
        self
    }

    /// Borrow nested options.
    pub fn options_ref(&self) -> &[Dhcpv6Option] {
        &self.options
    }

    /// Mutably borrow nested options.
    pub fn options_mut(&mut self) -> &mut Vec<Dhcpv6Option> {
        &mut self.options
    }
}

impl Dhcpv6IaPd {
    /// Create an IA_PD container.
    pub fn new(iaid: u32, t1: u32, t2: u32) -> Self {
        Self {
            iaid,
            t1,
            t2,
            options: Vec::new(),
        }
    }

    /// Decode an IA_PD option payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < DHCPV6_IA_PD_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "dhcpv6.option.ia_pd",
                DHCPV6_IA_PD_HEADER_LEN,
                bytes.len(),
            ));
        }

        Ok(Self {
            iaid: read_u32_be(&bytes[0..4])?,
            t1: read_u32_be(&bytes[4..8])?,
            t2: read_u32_be(&bytes[8..12])?,
            options: Dhcpv6Option::decode_all(&bytes[DHCPV6_IA_PD_HEADER_LEN..])?,
        })
    }

    /// Encode this IA_PD option payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(
            DHCPV6_IA_PD_HEADER_LEN
                + self
                    .options
                    .iter()
                    .map(|option| DHCPV6_OPTION_HEADER_LEN + option.payload_len())
                    .sum::<usize>(),
        );
        out.extend_from_slice(&self.iaid.to_be_bytes());
        out.extend_from_slice(&self.t1.to_be_bytes());
        out.extend_from_slice(&self.t2.to_be_bytes());
        out.extend_from_slice(&Dhcpv6Option::encode_all(&self.options)?);
        Ok(out)
    }

    /// IAID value.
    pub const fn iaid(&self) -> u32 {
        self.iaid
    }

    /// T1 value.
    pub const fn t1(&self) -> u32 {
        self.t1
    }

    /// T2 value.
    pub const fn t2(&self) -> u32 {
        self.t2
    }

    /// T1 and T2 timer values.
    pub const fn timers(&self) -> (u32, u32) {
        (self.t1, self.t2)
    }

    /// Append a nested option.
    pub fn option(mut self, option: Dhcpv6Option) -> Self {
        self.options.push(option);
        self
    }

    /// Append a nested OPTION_STATUS_CODE option.
    pub fn status_code(self, status: Dhcpv6StatusCodeOption) -> Self {
        self.option(Dhcpv6Option::status_code(status))
    }

    /// Append a nested IA Prefix option.
    pub fn ia_prefix(self, ia_prefix: Dhcpv6IaPrefix) -> Result<Self> {
        Ok(self.option(Dhcpv6Option::ia_prefix(ia_prefix)?))
    }

    /// Replace the nested option list.
    pub fn options(mut self, options: impl Into<Vec<Dhcpv6Option>>) -> Self {
        self.options = options.into();
        self
    }

    /// Borrow nested options.
    pub fn options_ref(&self) -> &[Dhcpv6Option] {
        &self.options
    }

    /// Mutably borrow nested options.
    pub fn options_mut(&mut self) -> &mut Vec<Dhcpv6Option> {
        &mut self.options
    }
}

impl Dhcpv6IaNa {
    /// Create an IA_NA container.
    pub fn new(iaid: u32, t1: u32, t2: u32) -> Self {
        Self {
            iaid,
            t1,
            t2,
            options: Vec::new(),
        }
    }

    /// Decode an IA_NA option payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < DHCPV6_IA_NA_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "dhcpv6.option.ia_na",
                DHCPV6_IA_NA_HEADER_LEN,
                bytes.len(),
            ));
        }

        Ok(Self {
            iaid: read_u32_be(&bytes[0..4])?,
            t1: read_u32_be(&bytes[4..8])?,
            t2: read_u32_be(&bytes[8..12])?,
            options: Dhcpv6Option::decode_all(&bytes[DHCPV6_IA_NA_HEADER_LEN..])?,
        })
    }

    /// Encode this IA_NA option payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(
            DHCPV6_IA_NA_HEADER_LEN
                + self
                    .options
                    .iter()
                    .map(|option| DHCPV6_OPTION_HEADER_LEN + option.payload_len())
                    .sum::<usize>(),
        );
        out.extend_from_slice(&self.iaid.to_be_bytes());
        out.extend_from_slice(&self.t1.to_be_bytes());
        out.extend_from_slice(&self.t2.to_be_bytes());
        out.extend_from_slice(&Dhcpv6Option::encode_all(&self.options)?);
        Ok(out)
    }

    /// IAID value.
    pub const fn iaid(&self) -> u32 {
        self.iaid
    }

    /// T1 value.
    pub const fn t1(&self) -> u32 {
        self.t1
    }

    /// T2 value.
    pub const fn t2(&self) -> u32 {
        self.t2
    }

    /// T1 and T2 timer values.
    pub const fn timers(&self) -> (u32, u32) {
        (self.t1, self.t2)
    }

    /// Append a nested option.
    pub fn option(mut self, option: Dhcpv6Option) -> Self {
        self.options.push(option);
        self
    }

    /// Append a nested OPTION_STATUS_CODE option.
    pub fn status_code(self, status: Dhcpv6StatusCodeOption) -> Self {
        self.option(Dhcpv6Option::status_code(status))
    }

    /// Append a nested IA Address option.
    pub fn ia_addr(self, ia_addr: Dhcpv6IaAddr) -> Result<Self> {
        Ok(self.option(Dhcpv6Option::ia_addr(ia_addr)?))
    }

    /// Replace the nested option list.
    pub fn options(mut self, options: impl Into<Vec<Dhcpv6Option>>) -> Self {
        self.options = options.into();
        self
    }

    /// Borrow nested options.
    pub fn options_ref(&self) -> &[Dhcpv6Option] {
        &self.options
    }

    /// Mutably borrow nested options.
    pub fn options_mut(&mut self) -> &mut Vec<Dhcpv6Option> {
        &mut self.options
    }
}

impl Dhcpv6IaPrefix {
    /// Create an IA Prefix option body.
    pub fn new(
        preferred_lifetime: u32,
        valid_lifetime: u32,
        prefix_length: u8,
        prefix: Ipv6Addr,
    ) -> Self {
        Self {
            preferred_lifetime,
            valid_lifetime,
            prefix_length,
            prefix,
            options: Vec::new(),
        }
    }

    /// Decode an IA Prefix option payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < DHCPV6_IAPREFIX_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "dhcpv6.option.iaprefix",
                DHCPV6_IAPREFIX_HEADER_LEN,
                bytes.len(),
            ));
        }

        let prefix_length = bytes[8];
        validate_prefix_length(prefix_length)?;
        Ok(Self {
            preferred_lifetime: read_u32_be(&bytes[0..4])?,
            valid_lifetime: read_u32_be(&bytes[4..8])?,
            prefix_length,
            prefix: Ipv6Addr::from(copy_array_16(&bytes[9..25])),
            options: Dhcpv6Option::decode_all(&bytes[DHCPV6_IAPREFIX_HEADER_LEN..])?,
        })
    }

    /// Encode this IA Prefix option payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_prefix_length(self.prefix_length)?;
        let mut out = Vec::with_capacity(
            DHCPV6_IAPREFIX_HEADER_LEN
                + self
                    .options
                    .iter()
                    .map(|option| DHCPV6_OPTION_HEADER_LEN + option.payload_len())
                    .sum::<usize>(),
        );
        out.extend_from_slice(&self.preferred_lifetime.to_be_bytes());
        out.extend_from_slice(&self.valid_lifetime.to_be_bytes());
        out.push(self.prefix_length);
        out.extend_from_slice(&self.prefix.octets());
        out.extend_from_slice(&Dhcpv6Option::encode_all(&self.options)?);
        Ok(out)
    }

    /// Preferred lifetime value.
    pub const fn preferred_lifetime(&self) -> u32 {
        self.preferred_lifetime
    }

    /// True when the preferred lifetime uses the DHCPv6 infinity sentinel.
    pub const fn preferred_lifetime_is_infinite(&self) -> bool {
        self.preferred_lifetime == DHCPV6_TIME_INFINITY
    }

    /// Valid lifetime value.
    pub const fn valid_lifetime(&self) -> u32 {
        self.valid_lifetime
    }

    /// True when the valid lifetime uses the DHCPv6 infinity sentinel.
    pub const fn valid_lifetime_is_infinite(&self) -> bool {
        self.valid_lifetime == DHCPV6_TIME_INFINITY
    }

    /// Prefix length.
    pub const fn prefix_length(&self) -> u8 {
        self.prefix_length
    }

    /// Prefix address bytes.
    pub const fn prefix(&self) -> Ipv6Addr {
        self.prefix
    }

    /// Append a nested option.
    pub fn option(mut self, option: Dhcpv6Option) -> Self {
        self.options.push(option);
        self
    }

    /// Append a nested OPTION_STATUS_CODE option.
    pub fn status_code(self, status: Dhcpv6StatusCodeOption) -> Self {
        self.option(Dhcpv6Option::status_code(status))
    }

    /// Append a nested OPTION_PD_EXCLUDE option.
    pub fn pd_exclude(self, pd_exclude: Dhcpv6PdExclude) -> Result<Self> {
        Ok(self.option(Dhcpv6Option::pd_exclude(pd_exclude)?))
    }

    /// Decode the first nested OPTION_PD_EXCLUDE option, if present.
    pub fn pd_exclude_value(&self) -> Result<Option<Dhcpv6PdExclude>> {
        for option in &self.options {
            if let Some(pd_exclude) = option.pd_exclude_value()? {
                return Ok(Some(pd_exclude));
            }
        }
        Ok(None)
    }

    /// Replace the nested option list.
    pub fn options(mut self, options: impl Into<Vec<Dhcpv6Option>>) -> Self {
        self.options = options.into();
        self
    }

    /// Borrow nested options.
    pub fn options_ref(&self) -> &[Dhcpv6Option] {
        &self.options
    }

    /// Mutably borrow nested options.
    pub fn options_mut(&mut self) -> &mut Vec<Dhcpv6Option> {
        &mut self.options
    }
}

impl Dhcpv6PdExclude {
    /// Create an OPTION_PD_EXCLUDE payload.
    pub fn new(prefix_length: u8, subnet_id: impl Into<Vec<u8>>) -> Result<Self> {
        validate_prefix_length_for("dhcpv6.option.pd_exclude.prefix_length", prefix_length)?;
        let subnet_id = subnet_id.into();
        validate_pd_exclude_subnet_id_len(subnet_id.len())?;
        Ok(Self {
            prefix_length,
            subnet_id,
        })
    }

    /// Decode an OPTION_PD_EXCLUDE payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < DHCPV6_PD_EXCLUDE_PAYLOAD_MIN_LEN {
            return Err(CrafterError::buffer_too_short(
                "dhcpv6.option.pd_exclude",
                DHCPV6_PD_EXCLUDE_PAYLOAD_MIN_LEN,
                bytes.len(),
            ));
        }
        validate_pd_exclude_payload_len(bytes.len())?;
        Self::new(bytes[0], bytes[1..].to_vec())
    }

    /// Encode this OPTION_PD_EXCLUDE payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_prefix_length_for("dhcpv6.option.pd_exclude.prefix_length", self.prefix_length)?;
        validate_pd_exclude_subnet_id_len(self.subnet_id.len())?;
        let mut out = Vec::with_capacity(1 + self.subnet_id.len());
        out.push(self.prefix_length);
        out.extend_from_slice(&self.subnet_id);
        Ok(out)
    }

    /// Excluded prefix length.
    pub const fn prefix_length(&self) -> u8 {
        self.prefix_length
    }

    /// Subnet-ID bytes that identify the excluded prefix under the enclosing prefix.
    pub fn subnet_id(&self) -> &[u8] {
        &self.subnet_id
    }
}

impl Dhcpv6S46ContainerKind {
    /// Create a S46 container kind from its DHCPv6 option code.
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            DHCPV6_OPTION_S46_CONT_MAPE => Some(Self::MapE),
            DHCPV6_OPTION_S46_CONT_MAPT => Some(Self::MapT),
            DHCPV6_OPTION_S46_CONT_LW => Some(Self::Lightweight4Over6),
            _ => None,
        }
    }

    /// DHCPv6 option code for this container.
    pub const fn code(self) -> u16 {
        match self {
            Self::MapE => DHCPV6_OPTION_S46_CONT_MAPE,
            Self::MapT => DHCPV6_OPTION_S46_CONT_MAPT,
            Self::Lightweight4Over6 => DHCPV6_OPTION_S46_CONT_LW,
        }
    }
}

impl Dhcpv6S46Container {
    /// Create an empty S46 container payload.
    pub fn new(kind: Dhcpv6S46ContainerKind) -> Self {
        Self {
            kind,
            options: Vec::new(),
        }
    }

    /// Decode an S46 container payload.
    pub fn decode(kind: Dhcpv6S46ContainerKind, bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            kind,
            options: Dhcpv6Option::decode_all(bytes)?,
        })
    }

    /// Encode this S46 container payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        Dhcpv6Option::encode_all(&self.options)
    }

    /// Container kind.
    pub const fn kind(&self) -> Dhcpv6S46ContainerKind {
        self.kind
    }

    /// DHCPv6 option code for this container.
    pub const fn codepoint(&self) -> u16 {
        self.kind.code()
    }

    /// Append a nested S46 option.
    pub fn option(mut self, option: Dhcpv6Option) -> Self {
        self.options.push(option);
        self
    }

    /// Replace the nested option list.
    pub fn options(mut self, options: impl Into<Vec<Dhcpv6Option>>) -> Self {
        self.options = options.into();
        self
    }

    /// Borrow nested options.
    pub fn options_ref(&self) -> &[Dhcpv6Option] {
        &self.options
    }

    /// Mutably borrow nested options.
    pub fn options_mut(&mut self) -> &mut Vec<Dhcpv6Option> {
        &mut self.options
    }
}

impl Dhcpv6S46Priority {
    /// Create an OPTION_S46_PRIORITY payload from ordered option codes.
    pub fn new(option_codes: impl Into<Vec<u16>>) -> Self {
        Self {
            option_codes: option_codes.into(),
        }
    }

    /// Decode an OPTION_S46_PRIORITY payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() % 2 != 0 {
            return Err(CrafterError::invalid_field_value(
                "dhcpv6.option.s46_priority",
                "payload length must be a multiple of 2 bytes",
            ));
        }

        let mut option_codes = Vec::with_capacity(bytes.len() / 2);
        for chunk in bytes.chunks_exact(2) {
            option_codes.push(read_u16_be(chunk)?);
        }
        Ok(Self { option_codes })
    }

    /// Encode this OPTION_S46_PRIORITY payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.option_codes.len() * 2);
        for code in &self.option_codes {
            append_u16_be(&mut out, *code);
        }
        out
    }

    /// Ordered option codes in priority order.
    pub fn option_codes(&self) -> &[u16] {
        &self.option_codes
    }
}

impl Dhcpv6DnrSvcParam {
    /// Create a DNR resolver parameter from an explicit SvcParamKey and value bytes.
    pub fn new(key: u16, value: impl Into<Vec<u8>>) -> Self {
        Self {
            key,
            value: value.into(),
        }
    }

    /// SvcParamKey value.
    pub const fn key(&self) -> u16 {
        self.key
    }

    /// SvcParamValue bytes, preserved verbatim.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl Dhcpv6Dnr {
    /// Create an OPTION_V6_DNR resolver instance.
    pub fn new(service_priority: u16, adn: DnsName) -> Self {
        Self {
            service_priority,
            adn,
            addresses: Vec::new(),
            svc_params: Vec::new(),
        }
    }

    /// Decode an OPTION_V6_DNR payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure_available(bytes, 4, "dhcpv6.option.v6_dnr")?;
        let service_priority = read_u16_be(&bytes[0..2])?;
        let adn_len = read_u16_be(&bytes[2..4])? as usize;
        let adn_start = 4;
        let adn_end = adn_start + adn_len;
        ensure_available(bytes, adn_end, "dhcpv6.option.v6_dnr.adn")?;
        let (adn, consumed) =
            decode_uncompressed_dns_name(bytes, adn_start, "dhcpv6.option.v6_dnr.adn")?;
        if consumed != adn_len {
            return Err(CrafterError::invalid_field_value(
                "dhcpv6.option.v6_dnr.adn",
                "ADN length does not match encoded DNS name",
            ));
        }

        let mut offset = adn_end;
        let mut addresses = Vec::new();
        let svc_params = if offset == bytes.len() {
            Vec::new()
        } else {
            ensure_available(bytes, offset + 2, "dhcpv6.option.v6_dnr.address_len")?;
            let address_len = read_u16_be(&bytes[offset..offset + 2])? as usize;
            offset += 2;
            if address_len % 16 != 0 {
                return Err(CrafterError::invalid_field_value(
                    "dhcpv6.option.v6_dnr.addresses",
                    "address hint length must be a multiple of 16 bytes",
                ));
            }
            let address_end = offset + address_len;
            ensure_available(bytes, address_end, "dhcpv6.option.v6_dnr.addresses")?;
            for chunk in bytes[offset..address_end].chunks_exact(16) {
                addresses.push(Ipv6Addr::from(copy_array_16(chunk)));
            }
            offset = address_end;
            decode_dnr_svc_params(&bytes[offset..])?
        };

        Ok(Self {
            service_priority,
            adn,
            addresses,
            svc_params,
        })
    }

    /// Encode this OPTION_V6_DNR payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_dnr_svc_params(&self.svc_params)?;
        let adn = self.adn.encode_uncompressed()?;
        let adn_len = u16::try_from(adn.len()).map_err(|_| {
            CrafterError::invalid_field_value("dhcpv6.option.v6_dnr.adn", "ADN exceeds 65535 bytes")
        })?;
        let address_len = self
            .addresses
            .len()
            .checked_mul(16)
            .and_then(|len| u16::try_from(len).ok())
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "dhcpv6.option.v6_dnr.addresses",
                    "address hint list exceeds 65535 bytes",
                )
            })?;

        let mut out = Vec::new();
        append_u16_be(&mut out, self.service_priority);
        append_u16_be(&mut out, adn_len);
        out.extend_from_slice(&adn);
        if !self.addresses.is_empty() || !self.svc_params.is_empty() {
            append_u16_be(&mut out, address_len);
            for address in &self.addresses {
                out.extend_from_slice(&address.octets());
            }
            encode_dnr_svc_params(&self.svc_params, &mut out)?;
        }
        Ok(out)
    }

    /// Service priority value.
    pub const fn service_priority(&self) -> u16 {
        self.service_priority
    }

    /// Authentication Domain Name.
    pub const fn adn(&self) -> &DnsName {
        &self.adn
    }

    /// IPv6 address hints.
    pub fn addresses(&self) -> &[Ipv6Addr] {
        &self.addresses
    }

    /// Resolver parameters.
    pub fn svc_params(&self) -> &[Dhcpv6DnrSvcParam] {
        &self.svc_params
    }

    /// Replace IPv6 address hints.
    pub fn addresses_from<I>(mut self, addresses: I) -> Self
    where
        I: IntoIterator<Item = Ipv6Addr>,
    {
        self.addresses = addresses.into_iter().collect();
        self
    }

    /// Append one resolver parameter.
    pub fn svc_param(mut self, param: Dhcpv6DnrSvcParam) -> Self {
        self.svc_params.push(param);
        self
    }

    /// Replace resolver parameters.
    pub fn svc_params_from(mut self, params: impl Into<Vec<Dhcpv6DnrSvcParam>>) -> Self {
        self.svc_params = params.into();
        self
    }
}

impl Dhcpv6LeasequeryType {
    /// Create a Leasequery query type from its raw wire octet.
    pub const fn from_code(code: u8) -> Self {
        match code {
            1 => Self::ByAddress,
            2 => Self::ByClientId,
            3 => Self::ByRelayId,
            other => Self::Unknown(other),
        }
    }

    /// Raw wire octet.
    pub const fn code(self) -> u8 {
        match self {
            Self::ByAddress => 1,
            Self::ByClientId => 2,
            Self::ByRelayId => 3,
            Self::Unknown(code) => code,
        }
    }
}

impl Dhcpv6Leasequery {
    /// Create an OPTION_LQ_QUERY payload.
    pub fn new(query_type: Dhcpv6LeasequeryType, link_address: Ipv6Addr) -> Self {
        Self {
            query_type,
            link_address,
            options: Vec::new(),
        }
    }

    /// Decode an OPTION_LQ_QUERY payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < DHCPV6_LQ_QUERY_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "dhcpv6.option.lq_query",
                DHCPV6_LQ_QUERY_HEADER_LEN,
                bytes.len(),
            ));
        }
        Ok(Self {
            query_type: Dhcpv6LeasequeryType::from_code(bytes[0]),
            link_address: Ipv6Addr::from(copy_array_16(&bytes[1..17])),
            options: Dhcpv6Option::decode_all(&bytes[DHCPV6_LQ_QUERY_HEADER_LEN..])?,
        })
    }

    /// Encode this OPTION_LQ_QUERY payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(
            DHCPV6_LQ_QUERY_HEADER_LEN
                + self
                    .options
                    .iter()
                    .map(|option| DHCPV6_OPTION_HEADER_LEN + option.payload_len())
                    .sum::<usize>(),
        );
        out.push(self.query_type.code());
        out.extend_from_slice(&self.link_address.octets());
        out.extend_from_slice(&Dhcpv6Option::encode_all(&self.options)?);
        Ok(out)
    }

    /// Query type.
    pub const fn query_type(&self) -> Dhcpv6LeasequeryType {
        self.query_type
    }

    /// Link address used for the query.
    pub const fn link_address(&self) -> Ipv6Addr {
        self.link_address
    }

    /// Append a nested query option.
    pub fn option(mut self, option: Dhcpv6Option) -> Self {
        self.options.push(option);
        self
    }

    /// Replace nested query options.
    pub fn options(mut self, options: impl Into<Vec<Dhcpv6Option>>) -> Self {
        self.options = options.into();
        self
    }

    /// Borrow nested query options.
    pub fn options_ref(&self) -> &[Dhcpv6Option] {
        &self.options
    }
}

impl Dhcpv6ClientData {
    /// Create an empty OPTION_CLIENT_DATA payload.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode an OPTION_CLIENT_DATA payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            options: Dhcpv6Option::decode_all(bytes)?,
        })
    }

    /// Encode this OPTION_CLIENT_DATA payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        Dhcpv6Option::encode_all(&self.options)
    }

    /// Append a nested client-data option.
    pub fn option(mut self, option: Dhcpv6Option) -> Self {
        self.options.push(option);
        self
    }

    /// Replace nested client-data options.
    pub fn options(mut self, options: impl Into<Vec<Dhcpv6Option>>) -> Self {
        self.options = options.into();
        self
    }

    /// Borrow nested client-data options.
    pub fn options_ref(&self) -> &[Dhcpv6Option] {
        &self.options
    }
}

impl Dhcpv6AuthProtocol {
    /// Create an authentication protocol value from a raw octet.
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCPV6_AUTH_PROTOCOL_CONFIGURATION_TOKEN => Self::ConfigurationToken,
            DHCPV6_AUTH_PROTOCOL_DELAYED => Self::Delayed,
            DHCPV6_AUTH_PROTOCOL_DHCPV6_DELAYED_OBSOLETE => Self::Dhcpv6DelayedObsolete,
            DHCPV6_AUTH_PROTOCOL_RECONFIGURE_KEY => Self::ReconfigureKey,
            DHCPV6_AUTH_PROTOCOL_SPLIT_HORIZON_DNS => Self::SplitHorizonDns,
            other => Self::Unknown(other),
        }
    }

    /// Wire octet value.
    pub const fn code(self) -> u8 {
        match self {
            Self::ConfigurationToken => DHCPV6_AUTH_PROTOCOL_CONFIGURATION_TOKEN,
            Self::Delayed => DHCPV6_AUTH_PROTOCOL_DELAYED,
            Self::Dhcpv6DelayedObsolete => DHCPV6_AUTH_PROTOCOL_DHCPV6_DELAYED_OBSOLETE,
            Self::ReconfigureKey => DHCPV6_AUTH_PROTOCOL_RECONFIGURE_KEY,
            Self::SplitHorizonDns => DHCPV6_AUTH_PROTOCOL_SPLIT_HORIZON_DNS,
            Self::Unknown(code) => code,
        }
    }
}

impl Dhcpv6AuthAlgorithm {
    /// Create an authentication algorithm value from a raw octet.
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCPV6_AUTH_ALGORITHM_CONFIGURATION_TOKEN => Self::ConfigurationToken,
            DHCPV6_AUTH_ALGORITHM_HMAC_MD5 => Self::HmacMd5,
            other => Self::Unknown(other),
        }
    }

    /// Wire octet value.
    pub const fn code(self) -> u8 {
        match self {
            Self::ConfigurationToken => DHCPV6_AUTH_ALGORITHM_CONFIGURATION_TOKEN,
            Self::HmacMd5 => DHCPV6_AUTH_ALGORITHM_HMAC_MD5,
            Self::Unknown(code) => code,
        }
    }
}

impl Dhcpv6ReplayDetectionMethod {
    /// Create a replay detection method value from a raw octet.
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCPV6_AUTH_RDM_MONOTONIC_COUNTER => Self::MonotonicCounter,
            other => Self::Unknown(other),
        }
    }

    /// Wire octet value.
    pub const fn code(self) -> u8 {
        match self {
            Self::MonotonicCounter => DHCPV6_AUTH_RDM_MONOTONIC_COUNTER,
            Self::Unknown(code) => code,
        }
    }
}

impl Dhcpv6Authentication {
    /// Create an Authentication option payload from typed header fields and raw
    /// authentication information bytes.
    pub fn new(
        protocol: Dhcpv6AuthProtocol,
        algorithm: Dhcpv6AuthAlgorithm,
        rdm: Dhcpv6ReplayDetectionMethod,
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

    /// Decode an Authentication option payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < DHCPV6_AUTH_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "dhcpv6.option.authentication",
                DHCPV6_AUTH_HEADER_LEN,
                bytes.len(),
            ));
        }

        let replay_end = 3 + DHCPV6_AUTH_REPLAY_DETECTION_LEN;
        let mut replay_detection = [0u8; DHCPV6_AUTH_REPLAY_DETECTION_LEN];
        replay_detection.copy_from_slice(&bytes[3..replay_end]);

        Ok(Self {
            protocol: Dhcpv6AuthProtocol::from_code(bytes[0]),
            algorithm: Dhcpv6AuthAlgorithm::from_code(bytes[1]),
            rdm: Dhcpv6ReplayDetectionMethod::from_code(bytes[2]),
            replay_detection: u64::from_be_bytes(replay_detection),
            authentication_information: bytes[replay_end..].to_vec(),
        })
    }

    /// Encode this Authentication option payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(DHCPV6_AUTH_HEADER_LEN + self.authentication_information.len());
        out.push(self.protocol.code());
        out.push(self.algorithm.code());
        out.push(self.rdm.code());
        out.extend_from_slice(&self.replay_detection.to_be_bytes());
        out.extend_from_slice(&self.authentication_information);
        out
    }
}

impl Dhcpv6UserClass {
    /// Create a User Class payload from opaque class-data entries.
    pub fn new<C, D>(class_data: C) -> Self
    where
        C: IntoIterator<Item = D>,
        D: Into<Vec<u8>>,
    {
        Self {
            class_data: class_data.into_iter().map(Into::into).collect(),
        }
    }

    /// Decode a User Class payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            class_data: decode_class_data_list(bytes, "dhcpv6.option.user_class")?,
        })
    }

    /// Encode this User Class payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_class_data_list(&self.class_data, "dhcpv6.option.user_class")
    }

    /// Borrow class-data entries.
    pub fn class_data(&self) -> &[Vec<u8>] {
        &self.class_data
    }

    /// Consume this value into class-data entries.
    pub fn into_class_data(self) -> Vec<Vec<u8>> {
        self.class_data
    }
}

impl Dhcpv6VendorClass {
    /// Create a Vendor Class payload scoped to an enterprise number.
    pub fn new<C, D>(enterprise_number: u32, class_data: C) -> Self
    where
        C: IntoIterator<Item = D>,
        D: Into<Vec<u8>>,
    {
        Self {
            enterprise_number,
            class_data: class_data.into_iter().map(Into::into).collect(),
        }
    }

    /// Decode a Vendor Class payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(CrafterError::buffer_too_short(
                "dhcpv6.option.vendor_class.enterprise_number",
                4,
                bytes.len(),
            ));
        }

        Ok(Self {
            enterprise_number: read_u32_be(&bytes[0..4])?,
            class_data: decode_class_data_list(&bytes[4..], "dhcpv6.option.vendor_class")?,
        })
    }

    /// Encode this Vendor Class payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(4 + encoded_class_data_len(&self.class_data));
        out.extend_from_slice(&self.enterprise_number.to_be_bytes());
        out.extend_from_slice(&encode_class_data_list(
            &self.class_data,
            "dhcpv6.option.vendor_class",
        )?);
        Ok(out)
    }

    /// Enterprise number.
    pub const fn enterprise_number(&self) -> u32 {
        self.enterprise_number
    }

    /// Borrow vendor class-data entries.
    pub fn class_data(&self) -> &[Vec<u8>] {
        &self.class_data
    }

    /// Consume this value into its enterprise number and class-data entries.
    pub fn into_parts(self) -> (u32, Vec<Vec<u8>>) {
        (self.enterprise_number, self.class_data)
    }
}

impl Dhcpv6VendorOption {
    /// Create an enterprise-scoped Vendor Options suboption.
    pub fn new(code: impl Into<Dhcpv6OptionCode>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            code: code.into(),
            payload: payload.into(),
        }
    }

    /// Suboption codepoint.
    pub const fn code(&self) -> Dhcpv6OptionCode {
        self.code
    }

    /// Raw suboption codepoint.
    pub const fn codepoint(&self) -> u16 {
        self.code.code()
    }

    /// Suboption payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Suboption payload length.
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        let payload_len = u16::try_from(self.payload.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "dhcpv6.option.vendor_opts.option_length",
                "payload exceeds 65535 bytes",
            )
        })?;
        append_u16_be(out, self.codepoint());
        append_u16_be(out, payload_len);
        out.extend_from_slice(&self.payload);
        Ok(())
    }
}

impl Dhcpv6VendorOptions {
    /// Create a Vendor Options payload scoped to an enterprise number.
    pub fn new<I>(enterprise_number: u32, options: I) -> Self
    where
        I: IntoIterator<Item = Dhcpv6VendorOption>,
    {
        Self {
            enterprise_number,
            options: options.into_iter().collect(),
        }
    }

    /// Decode a Vendor Options payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(CrafterError::buffer_too_short(
                "dhcpv6.option.vendor_opts.enterprise_number",
                4,
                bytes.len(),
            ));
        }

        let mut options = Vec::new();
        let mut offset = 4usize;
        while offset < bytes.len() {
            ensure_available(bytes, offset + 2, "dhcpv6.option.vendor_opts.option_code")?;
            let code = read_u16_be(&bytes[offset..offset + 2])?;
            ensure_available(bytes, offset + 4, "dhcpv6.option.vendor_opts.option_length")?;
            let payload_len = read_u16_be(&bytes[offset + 2..offset + 4])? as usize;
            let payload_start = offset + 4;
            let payload_end = payload_start + payload_len;
            ensure_available(
                bytes,
                payload_end,
                "dhcpv6.option.vendor_opts.option_payload",
            )?;
            options.push(Dhcpv6VendorOption::new(
                code,
                bytes[payload_start..payload_end].to_vec(),
            ));
            offset = payload_end;
        }

        Ok(Self {
            enterprise_number: read_u32_be(&bytes[0..4])?,
            options,
        })
    }

    /// Encode this Vendor Options payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let total_len = 4 + self
            .options
            .iter()
            .map(|option| DHCPV6_OPTION_HEADER_LEN + option.payload_len())
            .sum::<usize>();
        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&self.enterprise_number.to_be_bytes());
        for option in &self.options {
            option.encode_into(&mut out)?;
        }
        Ok(out)
    }

    /// Enterprise number.
    pub const fn enterprise_number(&self) -> u32 {
        self.enterprise_number
    }

    /// Borrow vendor suboptions.
    pub fn options(&self) -> &[Dhcpv6VendorOption] {
        &self.options
    }

    /// Append a vendor suboption.
    pub fn option(mut self, option: Dhcpv6VendorOption) -> Self {
        self.options.push(option);
        self
    }

    /// Consume this value into its enterprise number and suboptions.
    pub fn into_parts(self) -> (u32, Vec<Dhcpv6VendorOption>) {
        (self.enterprise_number, self.options)
    }
}

impl Dhcpv6RemoteId {
    /// Create a Remote-ID payload.
    pub fn new(enterprise_number: u32, remote_id: impl Into<Vec<u8>>) -> Self {
        Self {
            enterprise_number,
            remote_id: remote_id.into(),
        }
    }

    /// Decode a Remote-ID payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(CrafterError::buffer_too_short(
                "dhcpv6.option.remote_id.enterprise_number",
                4,
                bytes.len(),
            ));
        }
        Ok(Self {
            enterprise_number: read_u32_be(&bytes[0..4])?,
            remote_id: bytes[4..].to_vec(),
        })
    }

    /// Encode this Remote-ID payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.remote_id.len());
        out.extend_from_slice(&self.enterprise_number.to_be_bytes());
        out.extend_from_slice(&self.remote_id);
        out
    }

    /// Enterprise number.
    pub const fn enterprise_number(&self) -> u32 {
        self.enterprise_number
    }

    /// Remote-ID bytes.
    pub fn remote_id(&self) -> &[u8] {
        &self.remote_id
    }
}

impl Dhcpv6ClientLinkLayerAddress {
    /// Create a Client Link-Layer Address payload.
    pub fn new(hardware_type: u16, link_layer_address: impl Into<Vec<u8>>) -> Self {
        Self {
            hardware_type,
            link_layer_address: link_layer_address.into(),
        }
    }

    /// Create a Client Link-Layer Address payload for Ethernet.
    pub fn ethernet(link_layer_address: [u8; 6]) -> Self {
        Self::new(1, link_layer_address)
    }

    /// Decode a Client Link-Layer Address payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(CrafterError::buffer_too_short(
                "dhcpv6.option.client_linklayer_addr.hardware_type",
                2,
                bytes.len(),
            ));
        }
        Ok(Self {
            hardware_type: read_u16_be(&bytes[0..2])?,
            link_layer_address: bytes[2..].to_vec(),
        })
    }

    /// Encode this Client Link-Layer Address payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.link_layer_address.len());
        append_u16_be(&mut out, self.hardware_type);
        out.extend_from_slice(&self.link_layer_address);
        out
    }

    /// Hardware type from the ARP hardware type namespace.
    pub const fn hardware_type(&self) -> u16 {
        self.hardware_type
    }

    /// Link-layer address bytes.
    pub fn link_layer_address(&self) -> &[u8] {
        &self.link_layer_address
    }
}

impl Dhcpv6RelaySuppliedOptions {
    /// Create a Relay-Supplied Options payload.
    pub fn new<I>(options: I) -> Self
    where
        I: IntoIterator<Item = Dhcpv6Option>,
    {
        Self {
            options: options.into_iter().collect(),
        }
    }

    /// Decode a Relay-Supplied Options payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            options: Dhcpv6Option::decode_all(bytes)?,
        })
    }

    /// Encode this Relay-Supplied Options payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        Dhcpv6Option::encode_all(&self.options)
    }

    /// Borrow relay-supplied options.
    pub fn options(&self) -> &[Dhcpv6Option] {
        &self.options
    }

    /// Append a relay-supplied option.
    pub fn option(mut self, option: Dhcpv6Option) -> Self {
        self.options.push(option);
        self
    }
}

impl Dhcpv6DomainList {
    /// Create a Domain List payload from typed DNS names.
    pub fn new<I>(names: I) -> Self
    where
        I: IntoIterator<Item = DnsName>,
    {
        Self {
            names: names.into_iter().collect(),
        }
    }

    /// Parse presentation-form domain names into a Domain List payload.
    pub fn parse<I, S>(names: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut parsed = Vec::new();
        for name in names {
            parsed.push(DnsName::parse(name.as_ref())?);
        }
        Ok(Self::new(parsed))
    }

    /// Decode a Domain List payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut names = Vec::new();
        let mut offset = 0usize;
        while offset < bytes.len() {
            let (name, consumed) = decode_dns_name_typed(bytes, offset)?;
            names.push(name);
            offset += consumed;
        }
        Ok(Self { names })
    }

    /// Encode this Domain List payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for name in &self.names {
            out.extend_from_slice(&name.encode_uncompressed()?);
        }
        Ok(out)
    }

    /// Borrow domain names.
    pub fn names(&self) -> &[DnsName] {
        &self.names
    }

    /// Domain names as canonical presentation strings.
    pub fn presentations(&self) -> Vec<&str> {
        self.names.iter().map(DnsName::presentation).collect()
    }
}

impl Dhcpv6BootfileParam {
    /// Create a Bootfile Param payload from opaque parameter strings.
    pub fn new<P, D>(parameters: P) -> Self
    where
        P: IntoIterator<Item = D>,
        D: Into<Vec<u8>>,
    {
        Self {
            parameters: parameters.into_iter().map(Into::into).collect(),
        }
    }

    /// Decode a Bootfile Param payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            parameters: decode_class_data_list(bytes, "dhcpv6.option.bootfile_param")?,
        })
    }

    /// Encode this Bootfile Param payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_class_data_list(&self.parameters, "dhcpv6.option.bootfile_param")
    }

    /// Borrow bootfile parameters.
    pub fn parameters(&self) -> &[Vec<u8>] {
        &self.parameters
    }
}

impl Dhcpv6ClientArchitecture {
    /// Create a Client Architecture payload from processor architecture values.
    pub fn new(architectures: impl Into<Vec<u16>>) -> Self {
        Self {
            architectures: architectures.into(),
        }
    }

    /// Decode a Client Architecture payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() % 2 != 0 {
            return Err(CrafterError::invalid_field_value(
                "dhcpv6.option.client_arch_type",
                "payload length must be a non-zero multiple of 2 bytes",
            ));
        }

        let mut architectures = Vec::with_capacity(bytes.len() / 2);
        for chunk in bytes.chunks_exact(2) {
            architectures.push(read_u16_be(chunk)?);
        }
        Ok(Self { architectures })
    }

    /// Encode this Client Architecture payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.architectures.len() * 2);
        for architecture in &self.architectures {
            append_u16_be(&mut out, *architecture);
        }
        out
    }

    /// Borrow architecture values.
    pub fn architectures(&self) -> &[u16] {
        &self.architectures
    }
}

impl Dhcpv6NetworkInterfaceIdentifier {
    /// Create a Network Interface Identifier payload.
    pub const fn new(interface_type: u8, major: u8, minor: u8) -> Self {
        Self {
            interface_type,
            major,
            minor,
        }
    }

    /// Create a UNDI Network Interface Identifier payload.
    pub const fn undi(major: u8, minor: u8) -> Self {
        Self::new(1, major, minor)
    }

    /// Decode a Network Interface Identifier payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 3 {
            return Err(CrafterError::invalid_field_value(
                "dhcpv6.option.nii",
                "payload length does not match option format",
            ));
        }
        Ok(Self::new(bytes[0], bytes[1], bytes[2]))
    }

    /// Encode this Network Interface Identifier payload.
    pub const fn encode(self) -> [u8; 3] {
        [self.interface_type, self.major, self.minor]
    }
}

impl Dhcpv6NtpSuboption {
    /// Create an NTP Server suboption.
    pub fn new(code: impl Into<Dhcpv6OptionCode>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            code: code.into(),
            payload: payload.into(),
        }
    }

    /// Create an NTP server address suboption.
    pub fn server_address(address: Ipv6Addr) -> Self {
        Self::new(1u16, address.octets())
    }

    /// Create an NTP server FQDN suboption.
    pub fn server_fqdn(name: DnsName) -> Result<Self> {
        Ok(Self::new(2u16, name.encode_uncompressed()?))
    }

    /// Suboption code.
    pub const fn code(&self) -> Dhcpv6OptionCode {
        self.code
    }

    /// Raw suboption codepoint.
    pub const fn codepoint(&self) -> u16 {
        self.code.code()
    }

    /// Suboption payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        let payload_len = u16::try_from(self.payload.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "dhcpv6.option.ntp_server.suboption_length",
                "payload exceeds 65535 bytes",
            )
        })?;
        append_u16_be(out, self.codepoint());
        append_u16_be(out, payload_len);
        out.extend_from_slice(&self.payload);
        Ok(())
    }
}

impl Dhcpv6NtpServer {
    /// Create an NTP Server payload.
    pub fn new<I>(suboptions: I) -> Self
    where
        I: IntoIterator<Item = Dhcpv6NtpSuboption>,
    {
        Self {
            suboptions: suboptions.into_iter().collect(),
        }
    }

    /// Decode an NTP Server payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut suboptions = Vec::new();
        let mut offset = 0usize;
        while offset < bytes.len() {
            ensure_available(bytes, offset + 2, "dhcpv6.option.ntp_server.suboption_code")?;
            let code = read_u16_be(&bytes[offset..offset + 2])?;
            ensure_available(
                bytes,
                offset + 4,
                "dhcpv6.option.ntp_server.suboption_length",
            )?;
            let payload_len = read_u16_be(&bytes[offset + 2..offset + 4])? as usize;
            let payload_start = offset + 4;
            let payload_end = payload_start + payload_len;
            ensure_available(
                bytes,
                payload_end,
                "dhcpv6.option.ntp_server.suboption_payload",
            )?;
            suboptions.push(Dhcpv6NtpSuboption::new(
                code,
                bytes[payload_start..payload_end].to_vec(),
            ));
            offset = payload_end;
        }
        Ok(Self { suboptions })
    }

    /// Encode this NTP Server payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for suboption in &self.suboptions {
            suboption.encode_into(&mut out)?;
        }
        Ok(out)
    }

    /// Borrow NTP suboptions.
    pub fn suboptions(&self) -> &[Dhcpv6NtpSuboption] {
        &self.suboptions
    }
}

impl Dhcpv6ClientFqdn {
    /// Create a Client FQDN payload.
    pub const fn new(flags: u8, domain_name: DnsName) -> Self {
        Self { flags, domain_name }
    }

    /// Decode a Client FQDN payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(CrafterError::buffer_too_short(
                "dhcpv6.option.client_fqdn.flags",
                1,
                0,
            ));
        }
        let (domain_name, consumed) =
            decode_uncompressed_dns_name(bytes, 1, "dhcpv6.option.client_fqdn.name")?;
        if consumed + 1 != bytes.len() {
            return Err(CrafterError::invalid_field_value(
                "dhcpv6.option.client_fqdn.name",
                "trailing bytes after domain name",
            ));
        }
        Ok(Self {
            flags: bytes[0],
            domain_name,
        })
    }

    /// Encode this Client FQDN payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(1);
        out.push(self.flags);
        out.extend_from_slice(&self.domain_name.encode_uncompressed()?);
        Ok(out)
    }

    /// Raw FQDN flags octet.
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Domain name.
    pub const fn domain_name(&self) -> &DnsName {
        &self.domain_name
    }
}

impl Dhcpv6StatusCodeOption {
    /// Create a Status Code option payload with no status message bytes.
    pub fn new(status: Dhcpv6StatusCode) -> Self {
        Self {
            status,
            message: Vec::new(),
        }
    }

    /// Create a Status Code option payload with status message bytes.
    pub fn with_message(status: Dhcpv6StatusCode, message: impl AsRef<[u8]>) -> Self {
        Self {
            status,
            message: message.as_ref().to_vec(),
        }
    }

    /// Decode a Status Code option payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(CrafterError::buffer_too_short(
                "dhcpv6.option.status_code",
                2,
                bytes.len(),
            ));
        }

        Ok(Self {
            status: Dhcpv6StatusCode::from_code(read_u16_be(&bytes[0..2])?),
            message: bytes[2..].to_vec(),
        })
    }

    /// Encode this Status Code option payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.message.len());
        append_u16_be(&mut out, self.status.code());
        out.extend_from_slice(&self.message);
        out
    }

    /// Status code value.
    pub const fn status(&self) -> Dhcpv6StatusCode {
        self.status
    }

    /// Status message bytes.
    pub fn message_bytes(&self) -> &[u8] {
        &self.message
    }

    /// Status message as UTF-8, when the bytes are valid UTF-8.
    pub fn message_text(&self) -> Option<&str> {
        core::str::from_utf8(&self.message).ok()
    }
}

impl Dhcpv6Option {
    /// Create an option from a codepoint and raw payload bytes.
    pub fn raw(code: impl Into<Dhcpv6OptionCode>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            code: code.into(),
            value: Dhcpv6OptionValue::Raw(payload.into()),
        }
    }

    /// Create a zero-length option.
    pub fn empty(code: impl Into<Dhcpv6OptionCode>) -> Self {
        Self {
            code: code.into(),
            value: Dhcpv6OptionValue::Empty,
        }
    }

    /// Create an option from a codepoint and typed payload value.
    pub fn typed(code: impl Into<Dhcpv6OptionCode>, value: Dhcpv6OptionValue) -> Self {
        Self {
            code: code.into(),
            value,
        }
    }

    /// Create an OPTION_CLIENTID option carrying DUID bytes.
    pub fn client_id(duid: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_CLIENTID, duid)
    }

    /// Create an OPTION_SERVERID option carrying DUID bytes.
    pub fn server_id(duid: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_SERVERID, duid)
    }

    /// Create an OPTION_CLIENTID option from a typed DUID.
    pub fn client_duid(duid: Dhcpv6Duid) -> Self {
        Self::client_id(duid)
    }

    /// Create an OPTION_SERVERID option from a typed DUID.
    pub fn server_duid(duid: Dhcpv6Duid) -> Self {
        Self::server_id(duid)
    }

    /// Create an OPTION_ORO option from requested option codepoints.
    pub fn oro<I, C>(codes: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<Dhcpv6OptionCode>,
    {
        let mut payload = Vec::new();
        for code in codes {
            append_u16_be(&mut payload, code.into().code());
        }
        Self::raw(DHCPV6_OPTION_ORO, payload)
    }

    /// Create an OPTION_PREFERENCE option.
    pub fn preference(preference: u8) -> Self {
        Self::raw(DHCPV6_OPTION_PREFERENCE, vec![preference])
    }

    /// Create an OPTION_ELAPSED_TIME option in hundredths of a second.
    pub fn elapsed_time(centiseconds: u16) -> Self {
        Self::raw(
            DHCPV6_OPTION_ELAPSED_TIME,
            centiseconds.to_be_bytes().to_vec(),
        )
    }

    /// Create an OPTION_RELAY_MSG option from raw relayed DHCPv6 bytes.
    pub fn relay_msg(payload: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_RELAY_MSG, payload)
    }

    /// Create an OPTION_RAPID_COMMIT option.
    pub fn rapid_commit() -> Self {
        Self::empty(DHCPV6_OPTION_RAPID_COMMIT)
    }

    /// Create an OPTION_ADDR_REG_ENABLE option.
    pub fn addr_reg_enable() -> Self {
        Self::empty(DHCPV6_OPTION_ADDR_REG_ENABLE)
    }

    /// Create an OPTION_AUTH option.
    ///
    /// This serializes the supplied packet fields only; it does not derive,
    /// sign, or verify authentication material.
    pub fn authentication(authentication: Dhcpv6Authentication) -> Self {
        Self::raw(DHCPV6_OPTION_AUTH, authentication.encode())
    }

    /// Create an OPTION_USER_CLASS option.
    pub fn user_class(user_class: Dhcpv6UserClass) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_USER_CLASS, user_class.encode()?))
    }

    /// Create an OPTION_VENDOR_CLASS option.
    pub fn vendor_class(vendor_class: Dhcpv6VendorClass) -> Result<Self> {
        Ok(Self::raw(
            DHCPV6_OPTION_VENDOR_CLASS,
            vendor_class.encode()?,
        ))
    }

    /// Create an OPTION_VENDOR_OPTS option.
    pub fn vendor_opts(vendor_opts: Dhcpv6VendorOptions) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_VENDOR_OPTS, vendor_opts.encode()?))
    }

    /// Create an OPTION_INTERFACE_ID option.
    pub fn interface_id(interface_id: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_INTERFACE_ID, interface_id)
    }

    /// Create an OPTION_RECONF_MSG option.
    pub fn reconfigure_message(message_type: Dhcpv6MessageType) -> Self {
        Self::raw(DHCPV6_OPTION_RECONF_MSG, vec![message_type.code()])
    }

    /// Create an OPTION_RECONF_ACCEPT option.
    pub fn reconfigure_accept() -> Self {
        Self::empty(DHCPV6_OPTION_RECONF_ACCEPT)
    }

    /// Create an OPTION_DNS_SERVERS option.
    pub fn dns_servers<I>(servers: I) -> Self
    where
        I: IntoIterator<Item = Ipv6Addr>,
    {
        Self::raw(DHCPV6_OPTION_DNS_SERVERS, encode_ipv6_addr_list(servers))
    }

    /// Create an OPTION_SIP_SERVER_D option.
    pub fn sip_server_domains(domain_list: Dhcpv6DomainList) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_SIP_SERVER_D, domain_list.encode()?))
    }

    /// Create an OPTION_SIP_SERVER_A option.
    pub fn sip_server_addresses<I>(addresses: I) -> Self
    where
        I: IntoIterator<Item = Ipv6Addr>,
    {
        Self::raw(DHCPV6_OPTION_SIP_SERVER_A, encode_ipv6_addr_list(addresses))
    }

    /// Create an OPTION_DOMAIN_LIST option.
    pub fn domain_list(domain_list: Dhcpv6DomainList) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_DOMAIN_LIST, domain_list.encode()?))
    }

    /// Create an OPTION_SNTP_SERVERS option.
    pub fn sntp_servers<I>(servers: I) -> Self
    where
        I: IntoIterator<Item = Ipv6Addr>,
    {
        Self::raw(DHCPV6_OPTION_SNTP_SERVERS, encode_ipv6_addr_list(servers))
    }

    /// Create an OPTION_INFORMATION_REFRESH_TIME option.
    pub fn information_refresh_time(seconds: u32) -> Self {
        Self::raw(
            DHCPV6_OPTION_INFORMATION_REFRESH_TIME,
            seconds.to_be_bytes().to_vec(),
        )
    }

    /// Create an OPTION_SOL_MAX_RT option.
    pub fn sol_max_rt(seconds: u32) -> Self {
        Self::raw(DHCPV6_OPTION_SOL_MAX_RT, seconds.to_be_bytes().to_vec())
    }

    /// Create an OPTION_INF_MAX_RT option.
    pub fn inf_max_rt(seconds: u32) -> Self {
        Self::raw(DHCPV6_OPTION_INF_MAX_RT, seconds.to_be_bytes().to_vec())
    }

    /// Create an OPTION_STATUS_CODE option.
    pub fn status_code(status: Dhcpv6StatusCodeOption) -> Self {
        Self::raw(DHCPV6_OPTION_STATUS_CODE, status.encode())
    }

    /// Create an OPTION_STATUS_CODE option with no status message bytes.
    pub fn status(status: Dhcpv6StatusCode) -> Self {
        Self::status_code(Dhcpv6StatusCodeOption::new(status))
    }

    /// Create an OPTION_STATUS_CODE option with status message bytes.
    pub fn status_message(status: Dhcpv6StatusCode, message: impl AsRef<[u8]>) -> Self {
        Self::status_code(Dhcpv6StatusCodeOption::with_message(status, message))
    }

    /// Create an OPTION_IA_NA option.
    pub fn ia_na(ia_na: Dhcpv6IaNa) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_IA_NA, ia_na.encode()?))
    }

    /// Create an OPTION_IA_PD option.
    pub fn ia_pd(ia_pd: Dhcpv6IaPd) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_IA_PD, ia_pd.encode()?))
    }

    /// Create an OPTION_IAPREFIX option.
    pub fn ia_prefix(ia_prefix: Dhcpv6IaPrefix) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_IAPREFIX, ia_prefix.encode()?))
    }

    /// Create an OPTION_PD_EXCLUDE option.
    pub fn pd_exclude(pd_exclude: Dhcpv6PdExclude) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_PD_EXCLUDE, pd_exclude.encode()?))
    }

    /// Create an OPTION_S46_RULE option with raw payload bytes.
    pub fn s46_rule(payload: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_S46_RULE, payload)
    }

    /// Create an OPTION_S46_BR option with raw payload bytes.
    pub fn s46_br(payload: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_S46_BR, payload)
    }

    /// Create an OPTION_S46_DMR option with raw payload bytes.
    pub fn s46_dmr(payload: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_S46_DMR, payload)
    }

    /// Create an OPTION_S46_V4V6BIND option with raw payload bytes.
    pub fn s46_v4v6bind(payload: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_S46_V4V6BIND, payload)
    }

    /// Create an OPTION_S46_PORTPARAMS option with raw payload bytes.
    pub fn s46_portparams(payload: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_S46_PORTPARAMS, payload)
    }

    /// Create an S46 container option.
    pub fn s46_container(container: Dhcpv6S46Container) -> Result<Self> {
        Ok(Self::raw(container.codepoint(), container.encode()?))
    }

    /// Create an OPTION_S46_CONT_MAPE option from nested options.
    pub fn s46_cont_mape(options: impl Into<Vec<Dhcpv6Option>>) -> Result<Self> {
        Self::s46_container(Dhcpv6S46Container::new(Dhcpv6S46ContainerKind::MapE).options(options))
    }

    /// Create an OPTION_S46_CONT_MAPT option from nested options.
    pub fn s46_cont_mapt(options: impl Into<Vec<Dhcpv6Option>>) -> Result<Self> {
        Self::s46_container(Dhcpv6S46Container::new(Dhcpv6S46ContainerKind::MapT).options(options))
    }

    /// Create an OPTION_S46_CONT_LW option from nested options.
    pub fn s46_cont_lw(options: impl Into<Vec<Dhcpv6Option>>) -> Result<Self> {
        Self::s46_container(
            Dhcpv6S46Container::new(Dhcpv6S46ContainerKind::Lightweight4Over6).options(options),
        )
    }

    /// Create an OPTION_4RD option with raw payload bytes.
    pub fn four_rd(payload: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_4RD, payload)
    }

    /// Create an OPTION_4RD_MAP_RULE option with raw payload bytes.
    pub fn four_rd_map_rule(payload: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_4RD_MAP_RULE, payload)
    }

    /// Create an OPTION_4RD_NON_MAP_RULE option with raw payload bytes.
    pub fn four_rd_non_map_rule(payload: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_4RD_NON_MAP_RULE, payload)
    }

    /// Create an OPTION_S46_PRIORITY option.
    pub fn s46_priority(priority: Dhcpv6S46Priority) -> Self {
        Self::raw(DHCPV6_OPTION_S46_PRIORITY, priority.encode())
    }

    /// Create an OPTION_S46_BIND_IPV6_PREFIX option with raw payload bytes.
    pub fn s46_bind_ipv6_prefix(payload: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_S46_BIND_IPV6_PREFIX, payload)
    }

    /// Create the DHCPv6 Captive-Portal URI option.
    pub fn captive_portal_uri(uri: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_CAPTIVE_PORTAL, uri)
    }

    /// Create an OPTION_MUD_URL_V6 option.
    pub fn mud_url_v6(uri: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_MUD_URL_V6, uri)
    }

    /// Create an OPTION_V6_PREFIX64 option with raw payload bytes.
    pub fn v6_prefix64(payload: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_V6_PREFIX64, payload)
    }

    /// Create an OPTION_V6_DNR option.
    pub fn v6_dnr(dnr: Dhcpv6Dnr) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_V6_DNR, dnr.encode()?))
    }

    /// Create an OPTION_LQ_QUERY option.
    pub fn leasequery(query: Dhcpv6Leasequery) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_LQ_QUERY, query.encode()?))
    }

    /// Create an OPTION_CLIENT_DATA option.
    pub fn client_data(client_data: Dhcpv6ClientData) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_CLIENT_DATA, client_data.encode()?))
    }

    /// Create an OPTION_CLT_TIME option.
    pub fn client_time(seconds: u32) -> Self {
        Self::raw(DHCPV6_OPTION_CLT_TIME, seconds.to_be_bytes().to_vec())
    }

    /// Create an OPTION_LQ_RELAY_DATA option.
    pub fn leasequery_relay_data(payload: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_LQ_RELAY_DATA, payload)
    }

    /// Create an OPTION_LQ_CLIENT_LINK option.
    pub fn leasequery_client_link<I>(addresses: I) -> Self
    where
        I: IntoIterator<Item = Ipv6Addr>,
    {
        Self::raw(
            DHCPV6_OPTION_LQ_CLIENT_LINK,
            encode_ipv6_addr_list(addresses),
        )
    }

    /// Create an OPTION_LQ_BASE_TIME option.
    pub fn leasequery_base_time(seconds: u32) -> Self {
        Self::raw(DHCPV6_OPTION_LQ_BASE_TIME, seconds.to_be_bytes().to_vec())
    }

    /// Create an OPTION_LQ_START_TIME option.
    pub fn leasequery_start_time(seconds: u32) -> Self {
        Self::raw(DHCPV6_OPTION_LQ_START_TIME, seconds.to_be_bytes().to_vec())
    }

    /// Create an OPTION_LQ_END_TIME option.
    pub fn leasequery_end_time(seconds: u32) -> Self {
        Self::raw(DHCPV6_OPTION_LQ_END_TIME, seconds.to_be_bytes().to_vec())
    }

    /// Create an OPTION_DHCPV4_MSG option from embedded DHCPv4 bytes.
    pub fn dhcpv4_msg(payload: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_DHCPV4_MSG, payload)
    }

    /// Create an OPTION_DHCPV4_MSG option from a typed DHCPv4 layer.
    pub fn dhcpv4_message(message: Dhcpv4) -> Result<Self> {
        let bytes = crate::packet::Packet::from_layer(message).compile()?;
        Ok(Self::dhcpv4_msg(bytes.as_bytes()))
    }

    /// Create a raw DHCPv6 failover option from the registered F_* option range.
    pub fn failover_option(code: u16, payload: impl Into<Vec<u8>>) -> Result<Self> {
        if !dhcpv6_failover_option_code(code) {
            return Err(CrafterError::invalid_field_value(
                "dhcpv6.option.failover.code",
                "option code is not in the DHCPv6 failover option range",
            ));
        }
        Ok(Self::raw(code, payload))
    }

    /// Create an OPTION_REMOTE_ID option.
    pub fn remote_id(remote_id: Dhcpv6RemoteId) -> Self {
        Self::raw(DHCPV6_OPTION_REMOTE_ID, remote_id.encode())
    }

    /// Create an OPTION_SUBSCRIBER_ID option.
    pub fn subscriber_id(subscriber_id: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_SUBSCRIBER_ID, subscriber_id)
    }

    /// Create an OPTION_RELAY_ID option.
    pub fn relay_id(relay_id: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_RELAY_ID, relay_id)
    }

    /// Create an OPTION_NTP_SERVER option.
    pub fn ntp_server(ntp: Dhcpv6NtpServer) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_NTP_SERVER, ntp.encode()?))
    }

    /// Create an OPTION_SIP_UA_CS_LIST option.
    pub fn sip_ua_cs_list(domain_list: Dhcpv6DomainList) -> Result<Self> {
        Ok(Self::raw(
            DHCPV6_OPTION_SIP_UA_CS_LIST,
            domain_list.encode()?,
        ))
    }

    /// Create an OPT_BOOTFILE_URL option.
    pub fn bootfile_url(url: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_BOOTFILE_URL, url)
    }

    /// Create an OPT_BOOTFILE_PARAM option.
    pub fn bootfile_param(params: Dhcpv6BootfileParam) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_BOOTFILE_PARAM, params.encode()?))
    }

    /// Create an OPTION_CLIENT_ARCH_TYPE option.
    pub fn client_arch_type(arch: Dhcpv6ClientArchitecture) -> Self {
        Self::raw(DHCPV6_OPTION_CLIENT_ARCH_TYPE, arch.encode())
    }

    /// Create an OPTION_NII option.
    pub fn network_interface_identifier(nii: Dhcpv6NetworkInterfaceIdentifier) -> Self {
        Self::raw(DHCPV6_OPTION_NII, nii.encode())
    }

    /// Create an OPTION_CLIENT_FQDN option.
    pub fn client_fqdn(fqdn: Dhcpv6ClientFqdn) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_CLIENT_FQDN, fqdn.encode()?))
    }

    /// Create an OPTION_RSOO option.
    pub fn relay_supplied_options(rsoo: Dhcpv6RelaySuppliedOptions) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_RSOO, rsoo.encode()?))
    }

    /// Create an OPTION_CLIENT_LINKLAYER_ADDR option.
    pub fn client_link_layer_addr(client: Dhcpv6ClientLinkLayerAddress) -> Self {
        Self::raw(DHCPV6_OPTION_CLIENT_LINKLAYER_ADDR, client.encode())
    }

    /// Create an OPTION_NEW_POSIX_TIMEZONE option.
    pub fn posix_timezone(value: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_NEW_POSIX_TIMEZONE, value)
    }

    /// Create an OPTION_NEW_TZDB_TIMEZONE option.
    pub fn tzdb_timezone(value: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_NEW_TZDB_TIMEZONE, value)
    }

    /// Create an OPTION_IAADDR option.
    pub fn ia_addr(ia_addr: Dhcpv6IaAddr) -> Result<Self> {
        Ok(Self::raw(DHCPV6_OPTION_IAADDR, ia_addr.encode()?))
    }

    /// Option codepoint.
    pub const fn code(&self) -> Dhcpv6OptionCode {
        self.code
    }

    /// Raw option codepoint.
    pub const fn codepoint(&self) -> u16 {
        self.code.code()
    }

    /// Option payload value.
    pub const fn value(&self) -> &Dhcpv6OptionValue {
        &self.value
    }

    /// Mutable option payload value.
    pub fn value_mut(&mut self) -> &mut Dhcpv6OptionValue {
        &mut self.value
    }

    /// View this option's payload bytes.
    pub fn payload(&self) -> &[u8] {
        self.value.as_bytes()
    }

    /// Alias for [`Dhcpv6Option::payload`].
    pub fn as_bytes(&self) -> &[u8] {
        self.payload()
    }

    /// Payload length in bytes.
    pub fn payload_len(&self) -> usize {
        self.value.len()
    }

    /// Registered option name, when this codepoint is assigned.
    pub fn registered_name(&self) -> Option<&'static str> {
        dhcpv6_option_name(self.codepoint())
    }

    /// One-line option summary for layer inspection output.
    pub fn summary(&self) -> String {
        let code = self.codepoint();
        let name = self
            .registered_name()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("code{}", code));
        let mut parts = vec![
            format!("code={code}"),
            format!("len={}", self.payload_len()),
        ];

        match code {
            DHCPV6_OPTION_CLIENTID | DHCPV6_OPTION_SERVERID => {
                parts.push(format!("duid_len={}", self.payload_len()));
            }
            DHCPV6_OPTION_ORO => match self.oro_value() {
                Ok(Some(codes)) => parts.push(format!("requested={}", codes.len())),
                Err(_) => parts.push("requested=malformed".to_string()),
                Ok(None) => {}
            },
            DHCPV6_OPTION_PREFERENCE => match self.preference_value() {
                Ok(Some(value)) => parts.push(format!("preference={value}")),
                Err(_) => parts.push("preference=malformed".to_string()),
                Ok(None) => {}
            },
            DHCPV6_OPTION_ELAPSED_TIME => match self.elapsed_time_value() {
                Ok(Some(value)) => parts.push(format!("elapsed_cs={value}")),
                Err(_) => parts.push("elapsed_cs=malformed".to_string()),
                Ok(None) => {}
            },
            DHCPV6_OPTION_RECONF_MSG => match self.reconfigure_message_value() {
                Ok(Some(message)) => {
                    parts.push(format!("message={}", dhcpv6_message_type_summary(message)));
                }
                Err(_) => parts.push("message=malformed".to_string()),
                Ok(None) => {}
            },
            DHCPV6_OPTION_STATUS_CODE => match self.status_code_value() {
                Ok(Some(status)) => {
                    parts.push(format!("status={}", status.status()));
                    if !status.message_bytes().is_empty() {
                        parts.push(format!("message_len={}", status.message_bytes().len()));
                    }
                }
                Err(_) => parts.push("status=malformed".to_string()),
                Ok(None) => {}
            },
            DHCPV6_OPTION_IA_NA => match self.ia_na_value() {
                Ok(Some(ia)) => {
                    parts.push(format!("iaid=0x{:08x}", ia.iaid()));
                    parts.push(format!("t1={}", ia.t1()));
                    parts.push(format!("t2={}", ia.t2()));
                    parts.push(format!("nested={}", ia.options_ref().len()));
                }
                Err(_) => parts.push("ia_na=malformed".to_string()),
                Ok(None) => {}
            },
            DHCPV6_OPTION_IA_PD => match self.ia_pd_value() {
                Ok(Some(ia)) => {
                    parts.push(format!("iaid=0x{:08x}", ia.iaid()));
                    parts.push(format!("t1={}", ia.t1()));
                    parts.push(format!("t2={}", ia.t2()));
                    parts.push(format!("nested={}", ia.options_ref().len()));
                }
                Err(_) => parts.push("ia_pd=malformed".to_string()),
                Ok(None) => {}
            },
            DHCPV6_OPTION_IAADDR => match self.ia_addr_value() {
                Ok(Some(iaaddr)) => {
                    parts.push(format!("address={}", iaaddr.address()));
                    parts.push(format!("preferred={}", iaaddr.preferred_lifetime()));
                    parts.push(format!("valid={}", iaaddr.valid_lifetime()));
                    parts.push(format!("nested={}", iaaddr.options_ref().len()));
                }
                Err(_) => parts.push("iaaddr=malformed".to_string()),
                Ok(None) => {}
            },
            DHCPV6_OPTION_IAPREFIX => match self.ia_prefix_value() {
                Ok(Some(prefix)) => {
                    parts.push(format!("{}/{}", prefix.prefix(), prefix.prefix_length()));
                    parts.push(format!("preferred={}", prefix.preferred_lifetime()));
                    parts.push(format!("valid={}", prefix.valid_lifetime()));
                    parts.push(format!("nested={}", prefix.options_ref().len()));
                }
                Err(_) => parts.push("iaprefix=malformed".to_string()),
                Ok(None) => {}
            },
            DHCPV6_OPTION_DNS_SERVERS => match self.dns_servers_value() {
                Ok(Some(addresses)) => parts.push(format!("addresses={}", addresses.len())),
                Err(_) => parts.push("addresses=malformed".to_string()),
                Ok(None) => {}
            },
            DHCPV6_OPTION_DOMAIN_LIST => match self.domain_list_value() {
                Ok(Some(domains)) => parts.push(format!("domains={}", domains.names().len())),
                Err(_) => parts.push("domains=malformed".to_string()),
                Ok(None) => {}
            },
            DHCPV6_OPTION_SNTP_SERVERS | DHCPV6_OPTION_SIP_SERVER_A => {
                let addresses = if code == DHCPV6_OPTION_SNTP_SERVERS {
                    self.sntp_servers_value()
                } else {
                    self.sip_server_addresses_value()
                };
                match addresses {
                    Ok(Some(addresses)) => parts.push(format!("addresses={}", addresses.len())),
                    Err(_) => parts.push("addresses=malformed".to_string()),
                    Ok(None) => {}
                }
            }
            DHCPV6_OPTION_SIP_SERVER_D | DHCPV6_OPTION_SIP_UA_CS_LIST => {
                let domains = if code == DHCPV6_OPTION_SIP_SERVER_D {
                    self.sip_server_domains_value()
                } else {
                    self.sip_ua_cs_list_value()
                };
                match domains {
                    Ok(Some(domains)) => parts.push(format!("domains={}", domains.names().len())),
                    Err(_) => parts.push("domains=malformed".to_string()),
                    Ok(None) => {}
                }
            }
            DHCPV6_OPTION_RELAY_MSG | DHCPV6_OPTION_DHCPV4_MSG | DHCPV6_OPTION_LQ_RELAY_DATA => {
                parts.push(format!("message_len={}", self.payload_len()));
            }
            _ => {}
        }

        format!("{name}({})", parts.join(","))
    }

    /// True when the payload has zero bytes.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Payload format family.
    pub const fn format(&self) -> Dhcpv6OptionFormat {
        self.value.format()
    }

    /// Consume this option into its codepoint and payload value.
    pub fn into_parts(self) -> (Dhcpv6OptionCode, Dhcpv6OptionValue) {
        (self.code, self.value)
    }

    /// Return OPTION_CLIENTID DUID bytes when this option is Client ID.
    pub fn client_id_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_CLIENTID)
    }

    /// Return OPTION_SERVERID DUID bytes when this option is Server ID.
    pub fn server_id_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_SERVERID)
    }

    /// Decode OPTION_CLIENTID as a DUID.
    pub fn client_duid_value(&self) -> Result<Option<Dhcpv6Duid>> {
        match self.client_id_value() {
            Some(payload) => Dhcpv6Duid::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_SERVERID as a DUID.
    pub fn server_duid_value(&self) -> Result<Option<Dhcpv6Duid>> {
        match self.server_id_value() {
            Some(payload) => Dhcpv6Duid::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_ORO requested option codepoints.
    pub fn oro_value(&self) -> Result<Option<Vec<Dhcpv6OptionCode>>> {
        let Some(payload) = self.payload_if_code(DHCPV6_OPTION_ORO) else {
            return Ok(None);
        };
        if payload.len() % 2 != 0 {
            return Err(CrafterError::invalid_field_value(
                "dhcpv6.option.oro",
                "payload length must be a multiple of 2 bytes",
            ));
        }

        let mut codes = Vec::with_capacity(payload.len() / 2);
        for chunk in payload.chunks_exact(2) {
            codes.push(Dhcpv6OptionCode::from_code(read_u16_be(chunk)?));
        }
        Ok(Some(codes))
    }

    /// Decode OPTION_PREFERENCE.
    pub fn preference_value(&self) -> Result<Option<u8>> {
        Ok(self
            .exact_payload_if_code(DHCPV6_OPTION_PREFERENCE, 1, "dhcpv6.option.preference")?
            .map(|payload| payload[0]))
    }

    /// Decode OPTION_ELAPSED_TIME.
    pub fn elapsed_time_value(&self) -> Result<Option<u16>> {
        Ok(self
            .exact_payload_if_code(DHCPV6_OPTION_ELAPSED_TIME, 2, "dhcpv6.option.elapsed_time")?
            .map(|payload| u16::from_be_bytes([payload[0], payload[1]])))
    }

    /// Return OPTION_RELAY_MSG payload bytes.
    pub fn relay_msg_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_RELAY_MSG)
    }

    /// Return true when this is a valid zero-length OPTION_RAPID_COMMIT.
    pub fn rapid_commit_present(&self) -> Result<bool> {
        Ok(self
            .exact_payload_if_code(DHCPV6_OPTION_RAPID_COMMIT, 0, "dhcpv6.option.rapid_commit")?
            .is_some())
    }

    /// Return true when this is a valid zero-length OPTION_ADDR_REG_ENABLE.
    pub fn addr_reg_enable_present(&self) -> Result<bool> {
        Ok(self
            .exact_payload_if_code(
                DHCPV6_OPTION_ADDR_REG_ENABLE,
                0,
                "dhcpv6.option.addr_reg_enable",
            )?
            .is_some())
    }

    /// Decode OPTION_AUTH.
    pub fn authentication_value(&self) -> Result<Option<Dhcpv6Authentication>> {
        match self.payload_if_code(DHCPV6_OPTION_AUTH) {
            Some(payload) => Dhcpv6Authentication::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_USER_CLASS.
    pub fn user_class_value(&self) -> Result<Option<Dhcpv6UserClass>> {
        match self.payload_if_code(DHCPV6_OPTION_USER_CLASS) {
            Some(payload) => Dhcpv6UserClass::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_VENDOR_CLASS.
    pub fn vendor_class_value(&self) -> Result<Option<Dhcpv6VendorClass>> {
        match self.payload_if_code(DHCPV6_OPTION_VENDOR_CLASS) {
            Some(payload) => Dhcpv6VendorClass::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_VENDOR_OPTS.
    pub fn vendor_opts_value(&self) -> Result<Option<Dhcpv6VendorOptions>> {
        match self.payload_if_code(DHCPV6_OPTION_VENDOR_OPTS) {
            Some(payload) => Dhcpv6VendorOptions::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Return OPTION_INTERFACE_ID payload bytes.
    pub fn interface_id_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_INTERFACE_ID)
    }

    /// Decode OPTION_RECONF_MSG.
    pub fn reconfigure_message_value(&self) -> Result<Option<Dhcpv6MessageType>> {
        Ok(self
            .exact_payload_if_code(DHCPV6_OPTION_RECONF_MSG, 1, "dhcpv6.option.reconf_msg")?
            .map(|payload| Dhcpv6MessageType::from_code(payload[0])))
    }

    /// Return true when this is a valid zero-length OPTION_RECONF_ACCEPT.
    pub fn reconfigure_accept_present(&self) -> Result<bool> {
        Ok(self
            .exact_payload_if_code(
                DHCPV6_OPTION_RECONF_ACCEPT,
                0,
                "dhcpv6.option.reconf_accept",
            )?
            .is_some())
    }

    /// Decode OPTION_DNS_SERVERS.
    pub fn dns_servers_value(&self) -> Result<Option<Vec<Ipv6Addr>>> {
        self.ipv6_addr_list_if_code(DHCPV6_OPTION_DNS_SERVERS, "dhcpv6.option.dns_servers")
    }

    /// Decode OPTION_SIP_SERVER_D.
    pub fn sip_server_domains_value(&self) -> Result<Option<Dhcpv6DomainList>> {
        match self.payload_if_code(DHCPV6_OPTION_SIP_SERVER_D) {
            Some(payload) => Dhcpv6DomainList::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_SIP_SERVER_A.
    pub fn sip_server_addresses_value(&self) -> Result<Option<Vec<Ipv6Addr>>> {
        self.ipv6_addr_list_if_code(DHCPV6_OPTION_SIP_SERVER_A, "dhcpv6.option.sip_server_a")
    }

    /// Decode OPTION_DOMAIN_LIST.
    pub fn domain_list_value(&self) -> Result<Option<Dhcpv6DomainList>> {
        match self.payload_if_code(DHCPV6_OPTION_DOMAIN_LIST) {
            Some(payload) => Dhcpv6DomainList::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_SNTP_SERVERS.
    pub fn sntp_servers_value(&self) -> Result<Option<Vec<Ipv6Addr>>> {
        self.ipv6_addr_list_if_code(DHCPV6_OPTION_SNTP_SERVERS, "dhcpv6.option.sntp_servers")
    }

    /// Decode OPTION_INFORMATION_REFRESH_TIME.
    pub fn information_refresh_time_value(&self) -> Result<Option<u32>> {
        self.fixed_u32_if_code(
            DHCPV6_OPTION_INFORMATION_REFRESH_TIME,
            "dhcpv6.option.information_refresh_time",
        )
    }

    /// Decode OPTION_SOL_MAX_RT.
    pub fn sol_max_rt_value(&self) -> Result<Option<u32>> {
        self.fixed_u32_if_code(DHCPV6_OPTION_SOL_MAX_RT, "dhcpv6.option.sol_max_rt")
    }

    /// Decode OPTION_INF_MAX_RT.
    pub fn inf_max_rt_value(&self) -> Result<Option<u32>> {
        self.fixed_u32_if_code(DHCPV6_OPTION_INF_MAX_RT, "dhcpv6.option.inf_max_rt")
    }

    /// Decode OPTION_STATUS_CODE.
    pub fn status_code_value(&self) -> Result<Option<Dhcpv6StatusCodeOption>> {
        match self.payload_if_code(DHCPV6_OPTION_STATUS_CODE) {
            Some(payload) => Dhcpv6StatusCodeOption::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_IA_NA.
    pub fn ia_na_value(&self) -> Result<Option<Dhcpv6IaNa>> {
        match self.payload_if_code(DHCPV6_OPTION_IA_NA) {
            Some(payload) => Dhcpv6IaNa::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_IA_PD.
    pub fn ia_pd_value(&self) -> Result<Option<Dhcpv6IaPd>> {
        match self.payload_if_code(DHCPV6_OPTION_IA_PD) {
            Some(payload) => Dhcpv6IaPd::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_IAPREFIX.
    pub fn ia_prefix_value(&self) -> Result<Option<Dhcpv6IaPrefix>> {
        match self.payload_if_code(DHCPV6_OPTION_IAPREFIX) {
            Some(payload) => Dhcpv6IaPrefix::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_PD_EXCLUDE.
    pub fn pd_exclude_value(&self) -> Result<Option<Dhcpv6PdExclude>> {
        match self.payload_if_code(DHCPV6_OPTION_PD_EXCLUDE) {
            Some(payload) => Dhcpv6PdExclude::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_S46_CONT_MAPE, OPTION_S46_CONT_MAPT, or OPTION_S46_CONT_LW.
    pub fn s46_container_value(&self) -> Result<Option<Dhcpv6S46Container>> {
        match Dhcpv6S46ContainerKind::from_code(self.codepoint()) {
            Some(kind) => Dhcpv6S46Container::decode(kind, self.payload()).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_S46_PRIORITY.
    pub fn s46_priority_value(&self) -> Result<Option<Dhcpv6S46Priority>> {
        match self.payload_if_code(DHCPV6_OPTION_S46_PRIORITY) {
            Some(payload) => Dhcpv6S46Priority::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Return Captive-Portal URI bytes.
    pub fn captive_portal_uri_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_CAPTIVE_PORTAL)
    }

    /// Return Captive-Portal URI as UTF-8 text when valid.
    pub fn captive_portal_uri_text(&self) -> Option<&str> {
        core::str::from_utf8(self.captive_portal_uri_value()?).ok()
    }

    /// Return OPTION_MUD_URL_V6 URI bytes.
    pub fn mud_url_v6_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_MUD_URL_V6)
    }

    /// Return OPTION_MUD_URL_V6 URI as UTF-8 text when valid.
    pub fn mud_url_v6_text(&self) -> Option<&str> {
        core::str::from_utf8(self.mud_url_v6_value()?).ok()
    }

    /// Return OPTION_V6_PREFIX64 payload bytes.
    pub fn v6_prefix64_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_V6_PREFIX64)
    }

    /// Decode OPTION_V6_DNR.
    pub fn v6_dnr_value(&self) -> Result<Option<Dhcpv6Dnr>> {
        match self.payload_if_code(DHCPV6_OPTION_V6_DNR) {
            Some(payload) => Dhcpv6Dnr::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_LQ_QUERY.
    pub fn leasequery_value(&self) -> Result<Option<Dhcpv6Leasequery>> {
        match self.payload_if_code(DHCPV6_OPTION_LQ_QUERY) {
            Some(payload) => Dhcpv6Leasequery::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_CLIENT_DATA.
    pub fn client_data_value(&self) -> Result<Option<Dhcpv6ClientData>> {
        match self.payload_if_code(DHCPV6_OPTION_CLIENT_DATA) {
            Some(payload) => Dhcpv6ClientData::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_CLT_TIME.
    pub fn client_time_value(&self) -> Result<Option<u32>> {
        self.fixed_u32_if_code(DHCPV6_OPTION_CLT_TIME, "dhcpv6.option.clt_time")
    }

    /// Return OPTION_LQ_RELAY_DATA payload bytes.
    pub fn leasequery_relay_data_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_LQ_RELAY_DATA)
    }

    /// Decode OPTION_LQ_CLIENT_LINK.
    pub fn leasequery_client_link_value(&self) -> Result<Option<Vec<Ipv6Addr>>> {
        self.ipv6_addr_list_if_code(DHCPV6_OPTION_LQ_CLIENT_LINK, "dhcpv6.option.lq_client_link")
    }

    /// Decode OPTION_LQ_BASE_TIME.
    pub fn leasequery_base_time_value(&self) -> Result<Option<u32>> {
        self.fixed_u32_if_code(DHCPV6_OPTION_LQ_BASE_TIME, "dhcpv6.option.lq_base_time")
    }

    /// Decode OPTION_LQ_START_TIME.
    pub fn leasequery_start_time_value(&self) -> Result<Option<u32>> {
        self.fixed_u32_if_code(DHCPV6_OPTION_LQ_START_TIME, "dhcpv6.option.lq_start_time")
    }

    /// Decode OPTION_LQ_END_TIME.
    pub fn leasequery_end_time_value(&self) -> Result<Option<u32>> {
        self.fixed_u32_if_code(DHCPV6_OPTION_LQ_END_TIME, "dhcpv6.option.lq_end_time")
    }

    /// Return OPTION_DHCPV4_MSG payload bytes.
    pub fn dhcpv4_msg_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_DHCPV4_MSG)
    }

    /// Decode OPTION_DHCPV4_MSG as a typed DHCPv4 layer.
    pub fn dhcpv4_message_value(&self) -> Result<Option<Dhcpv4>> {
        match self.dhcpv4_msg_value() {
            Some(payload) => Dhcpv4::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Return raw payload bytes for registered DHCPv6 failover options.
    pub fn failover_option_value(&self) -> Option<&[u8]> {
        dhcpv6_failover_option_code(self.codepoint()).then(|| self.payload())
    }

    /// Decode OPTION_REMOTE_ID.
    pub fn remote_id_value(&self) -> Result<Option<Dhcpv6RemoteId>> {
        match self.payload_if_code(DHCPV6_OPTION_REMOTE_ID) {
            Some(payload) => Dhcpv6RemoteId::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Return OPTION_SUBSCRIBER_ID payload bytes.
    pub fn subscriber_id_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_SUBSCRIBER_ID)
    }

    /// Return OPTION_RELAY_ID payload bytes.
    pub fn relay_id_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_RELAY_ID)
    }

    /// Decode OPTION_NTP_SERVER.
    pub fn ntp_server_value(&self) -> Result<Option<Dhcpv6NtpServer>> {
        match self.payload_if_code(DHCPV6_OPTION_NTP_SERVER) {
            Some(payload) => Dhcpv6NtpServer::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_SIP_UA_CS_LIST.
    pub fn sip_ua_cs_list_value(&self) -> Result<Option<Dhcpv6DomainList>> {
        match self.payload_if_code(DHCPV6_OPTION_SIP_UA_CS_LIST) {
            Some(payload) => Dhcpv6DomainList::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Return OPT_BOOTFILE_URL payload bytes.
    pub fn bootfile_url_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_BOOTFILE_URL)
    }

    /// Return OPT_BOOTFILE_URL as UTF-8 text when valid.
    pub fn bootfile_url_text(&self) -> Option<&str> {
        self.bootfile_url_value()
            .and_then(|payload| core::str::from_utf8(payload).ok())
    }

    /// Decode OPT_BOOTFILE_PARAM.
    pub fn bootfile_param_value(&self) -> Result<Option<Dhcpv6BootfileParam>> {
        match self.payload_if_code(DHCPV6_OPTION_BOOTFILE_PARAM) {
            Some(payload) => Dhcpv6BootfileParam::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_CLIENT_ARCH_TYPE.
    pub fn client_arch_type_value(&self) -> Result<Option<Dhcpv6ClientArchitecture>> {
        match self.payload_if_code(DHCPV6_OPTION_CLIENT_ARCH_TYPE) {
            Some(payload) => Dhcpv6ClientArchitecture::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_NII.
    pub fn network_interface_identifier_value(
        &self,
    ) -> Result<Option<Dhcpv6NetworkInterfaceIdentifier>> {
        match self.payload_if_code(DHCPV6_OPTION_NII) {
            Some(payload) => Dhcpv6NetworkInterfaceIdentifier::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_CLIENT_FQDN.
    pub fn client_fqdn_value(&self) -> Result<Option<Dhcpv6ClientFqdn>> {
        match self.payload_if_code(DHCPV6_OPTION_CLIENT_FQDN) {
            Some(payload) => Dhcpv6ClientFqdn::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_RELAY_ID as a DUID.
    pub fn relay_duid_value(&self) -> Result<Option<Dhcpv6Duid>> {
        match self.relay_id_value() {
            Some(payload) => Dhcpv6Duid::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_RSOO.
    pub fn relay_supplied_options_value(&self) -> Result<Option<Dhcpv6RelaySuppliedOptions>> {
        match self.payload_if_code(DHCPV6_OPTION_RSOO) {
            Some(payload) => Dhcpv6RelaySuppliedOptions::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Decode OPTION_CLIENT_LINKLAYER_ADDR.
    pub fn client_link_layer_addr_value(&self) -> Result<Option<Dhcpv6ClientLinkLayerAddress>> {
        match self.payload_if_code(DHCPV6_OPTION_CLIENT_LINKLAYER_ADDR) {
            Some(payload) => Dhcpv6ClientLinkLayerAddress::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Return OPTION_NEW_POSIX_TIMEZONE bytes.
    pub fn posix_timezone_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_NEW_POSIX_TIMEZONE)
    }

    /// Return OPTION_NEW_POSIX_TIMEZONE as UTF-8 text when valid.
    pub fn posix_timezone_text(&self) -> Option<&str> {
        self.posix_timezone_value()
            .and_then(|payload| core::str::from_utf8(payload).ok())
    }

    /// Return OPTION_NEW_TZDB_TIMEZONE bytes.
    pub fn tzdb_timezone_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_NEW_TZDB_TIMEZONE)
    }

    /// Return OPTION_NEW_TZDB_TIMEZONE as UTF-8 text when valid.
    pub fn tzdb_timezone_text(&self) -> Option<&str> {
        self.tzdb_timezone_value()
            .and_then(|payload| core::str::from_utf8(payload).ok())
    }

    /// Decode OPTION_IAADDR.
    pub fn ia_addr_value(&self) -> Result<Option<Dhcpv6IaAddr>> {
        match self.payload_if_code(DHCPV6_OPTION_IAADDR) {
            Some(payload) => Dhcpv6IaAddr::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Encode this option to its DHCPv6 TLV wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(DHCPV6_OPTION_HEADER_LEN + self.payload_len());
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Append this option's DHCPv6 TLV wire bytes to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        let payload_len = u16::try_from(self.payload_len()).map_err(|_| {
            CrafterError::invalid_field_value("dhcpv6.option.length", "payload exceeds 65535 bytes")
        })?;

        append_u16_be(out, self.codepoint());
        append_u16_be(out, payload_len);
        out.extend_from_slice(self.payload());
        Ok(())
    }

    /// Encode a serial list of DHCPv6 options.
    pub fn encode_all(options: &[Self]) -> Result<Vec<u8>> {
        let total_len = options
            .iter()
            .map(|option| DHCPV6_OPTION_HEADER_LEN + option.payload_len())
            .sum();
        let mut out = Vec::with_capacity(total_len);
        for option in options {
            option.encode_into(&mut out)?;
        }
        Ok(out)
    }

    /// Decode a serial DHCPv6 option list.
    pub fn decode_all(bytes: &[u8]) -> Result<Vec<Self>> {
        let mut options = Vec::new();
        let mut offset = 0usize;

        while offset < bytes.len() {
            let code = read_option_code(bytes, offset)?;
            let payload_len = read_option_len(bytes, offset)? as usize;
            let payload_start = offset + DHCPV6_OPTION_HEADER_LEN;
            let payload_end = payload_start + payload_len;
            ensure_available(bytes, payload_end, "dhcpv6.option.payload")?;

            let payload = &bytes[payload_start..payload_end];
            let value = if payload.is_empty() {
                Dhcpv6OptionValue::Empty
            } else {
                Dhcpv6OptionValue::Raw(payload.to_vec())
            };
            options.push(Self::typed(code, value));
            offset = payload_end;
        }

        Ok(options)
    }

    fn payload_if_code(&self, code: u16) -> Option<&[u8]> {
        (self.codepoint() == code).then(|| self.payload())
    }

    fn exact_payload_if_code(
        &self,
        code: u16,
        expected_len: usize,
        context: &'static str,
    ) -> Result<Option<&[u8]>> {
        let Some(payload) = self.payload_if_code(code) else {
            return Ok(None);
        };
        if payload.len() != expected_len {
            return Err(CrafterError::invalid_field_value(
                context,
                "payload length does not match option format",
            ));
        }
        Ok(Some(payload))
    }

    fn fixed_u32_if_code(&self, code: u16, context: &'static str) -> Result<Option<u32>> {
        Ok(self
            .exact_payload_if_code(code, 4, context)?
            .map(|payload| u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])))
    }

    fn ipv6_addr_list_if_code(
        &self,
        code: u16,
        context: &'static str,
    ) -> Result<Option<Vec<Ipv6Addr>>> {
        let Some(payload) = self.payload_if_code(code) else {
            return Ok(None);
        };
        decode_ipv6_addr_list(payload, context).map(Some)
    }
}

fn encode_ipv6_addr_list<I>(addresses: I) -> Vec<u8>
where
    I: IntoIterator<Item = Ipv6Addr>,
{
    let mut out = Vec::new();
    for address in addresses {
        out.extend_from_slice(&address.octets());
    }
    out
}

fn decode_ipv6_addr_list(bytes: &[u8], context: &'static str) -> Result<Vec<Ipv6Addr>> {
    if bytes.len() % 16 != 0 {
        return Err(CrafterError::invalid_field_value(
            context,
            "payload length must be a multiple of 16 bytes",
        ));
    }

    let mut addresses = Vec::with_capacity(bytes.len() / 16);
    for chunk in bytes.chunks_exact(16) {
        addresses.push(Ipv6Addr::from(copy_array_16(chunk)));
    }
    Ok(addresses)
}

fn encode_dnr_svc_params(params: &[Dhcpv6DnrSvcParam], out: &mut Vec<u8>) -> Result<()> {
    validate_dnr_svc_params(params)?;
    for param in params {
        let value_len = u16::try_from(param.value.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "dhcpv6.option.v6_dnr.svc_params",
                "SvcParamValue exceeds 65535 bytes",
            )
        })?;
        append_u16_be(out, param.key);
        append_u16_be(out, value_len);
        out.extend_from_slice(&param.value);
    }
    Ok(())
}

fn decode_dnr_svc_params(bytes: &[u8]) -> Result<Vec<Dhcpv6DnrSvcParam>> {
    let mut params = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        ensure_available(bytes, offset + 4, "dhcpv6.option.v6_dnr.svc_params")?;
        let key = read_u16_be(&bytes[offset..offset + 2])?;
        let value_len = read_u16_be(&bytes[offset + 2..offset + 4])? as usize;
        let value_start = offset + 4;
        let value_end = value_start + value_len;
        ensure_available(bytes, value_end, "dhcpv6.option.v6_dnr.svc_params")?;
        params.push(Dhcpv6DnrSvcParam::new(
            key,
            bytes[value_start..value_end].to_vec(),
        ));
        offset = value_end;
    }
    validate_dnr_svc_params(&params)?;
    Ok(params)
}

fn validate_dnr_svc_params(params: &[Dhcpv6DnrSvcParam]) -> Result<()> {
    for pair in params.windows(2) {
        if pair[0].key >= pair[1].key {
            return Err(CrafterError::invalid_field_value(
                "dhcpv6.option.v6_dnr.svc_params",
                "SvcParamKeys must be in strictly increasing order",
            ));
        }
    }
    Ok(())
}

fn decode_uncompressed_dns_name(
    bytes: &[u8],
    offset: usize,
    context: &'static str,
) -> Result<(DnsName, usize)> {
    let mut labels = Vec::new();
    let mut cursor = offset;
    loop {
        ensure_available(bytes, cursor + 1, context)?;
        let label_len = bytes[cursor];
        if label_len & 0xc0 != 0 {
            return Err(CrafterError::invalid_field_value(
                context,
                "compressed or reserved DNS label markers are not valid here",
            ));
        }
        cursor += 1;
        if label_len == 0 {
            let used = cursor - offset;
            return Ok((DnsName::from_labels(labels)?, used));
        }
        let label_end = cursor + label_len as usize;
        ensure_available(bytes, label_end, context)?;
        labels.push(bytes[cursor..label_end].to_vec());
        cursor = label_end;
    }
}

fn decode_class_data_list(bytes: &[u8], context: &'static str) -> Result<Vec<Vec<u8>>> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        ensure_available(bytes, offset + 2, context)?;
        let data_len = read_u16_be(&bytes[offset..offset + 2])? as usize;
        let data_start = offset + 2;
        let data_end = data_start + data_len;
        ensure_available(bytes, data_end, context)?;
        entries.push(bytes[data_start..data_end].to_vec());
        offset = data_end;
    }
    Ok(entries)
}

fn encoded_class_data_len(entries: &[Vec<u8>]) -> usize {
    entries.iter().map(|entry| 2 + entry.len()).sum()
}

fn encode_class_data_list(entries: &[Vec<u8>], context: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(encoded_class_data_len(entries));
    for entry in entries {
        let entry_len = u16::try_from(entry.len())
            .map_err(|_| CrafterError::invalid_field_value(context, "entry exceeds 65535 bytes"))?;
        append_u16_be(&mut out, entry_len);
        out.extend_from_slice(entry);
    }
    Ok(out)
}

fn append_u16_be(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn copy_array_16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    out
}

fn validate_prefix_length(prefix_length: u8) -> Result<()> {
    validate_prefix_length_for("dhcpv6.option.iaprefix.prefix_length", prefix_length)
}

fn dhcpv6_failover_option_code(code: u16) -> bool {
    (DHCPV6_OPTION_F_BINDING_STATUS..=DHCPV6_OPTION_F_STATE_EXPIRATION_TIME).contains(&code)
}

fn validate_prefix_length_for(context: &'static str, prefix_length: u8) -> Result<()> {
    if prefix_length > DHCPV6_PREFIX_LEN_MAX {
        return Err(CrafterError::invalid_field_value(
            context,
            "prefix length must be at most 128",
        ));
    }
    Ok(())
}

fn validate_pd_exclude_payload_len(len: usize) -> Result<()> {
    if !(DHCPV6_PD_EXCLUDE_PAYLOAD_MIN_LEN..=DHCPV6_PD_EXCLUDE_PAYLOAD_MAX_LEN).contains(&len) {
        return Err(CrafterError::invalid_field_value(
            "dhcpv6.option.pd_exclude",
            "payload length must be between 2 and 17 bytes",
        ));
    }
    Ok(())
}

fn validate_pd_exclude_subnet_id_len(len: usize) -> Result<()> {
    if !(DHCPV6_PD_EXCLUDE_SUBNET_ID_MIN_LEN..=DHCPV6_PD_EXCLUDE_SUBNET_ID_MAX_LEN).contains(&len) {
        return Err(CrafterError::invalid_field_value(
            "dhcpv6.option.pd_exclude.subnet_id",
            "subnet id length must be between 1 and 16 bytes",
        ));
    }
    Ok(())
}

fn read_option_code(bytes: &[u8], offset: usize) -> Result<u16> {
    ensure_available(bytes, offset + 2, "dhcpv6.option.code")?;
    read_u16_be(&bytes[offset..offset + 2])
}

fn read_option_len(bytes: &[u8], offset: usize) -> Result<u16> {
    ensure_available(
        bytes,
        offset + DHCPV6_OPTION_HEADER_LEN,
        "dhcpv6.option.length",
    )?;
    read_u16_be(&bytes[offset + 2..offset + DHCPV6_OPTION_HEADER_LEN])
}

fn ensure_available(bytes: &[u8], required: usize, context: &'static str) -> Result<()> {
    if bytes.len() < required {
        Err(CrafterError::buffer_too_short(
            context,
            required,
            bytes.len(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod dhcpv6_option_model_tests {
    use super::{Dhcpv6Option, Dhcpv6OptionCode, Dhcpv6OptionFormat, Dhcpv6OptionValue};

    #[test]
    fn dhcpv6_option_model_raw_option_preserves_code_and_payload() {
        let option = Dhcpv6Option::raw(23u16, vec![0xde, 0xad, 0xbe, 0xef]);

        assert_eq!(option.code(), Dhcpv6OptionCode::from_code(23));
        assert_eq!(option.codepoint(), 23);
        assert_eq!(option.payload(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(option.as_bytes(), option.payload());
        assert_eq!(option.payload_len(), 4);
        assert_eq!(option.format(), Dhcpv6OptionFormat::Raw);
        assert!(!option.is_empty());
    }

    #[test]
    fn dhcpv6_option_model_empty_option_has_empty_payload() {
        let option = Dhcpv6Option::empty(14u16);

        assert_eq!(option.codepoint(), 14);
        assert_eq!(option.payload(), &[]);
        assert_eq!(option.payload_len(), 0);
        assert_eq!(option.format(), Dhcpv6OptionFormat::Empty);
        assert!(option.is_empty());
    }

    #[test]
    fn dhcpv6_option_model_unknown_codes_are_ordinary_codepoints() {
        let code = Dhcpv6OptionCode::from_code(65_000);
        let option = Dhcpv6Option::raw(code, [1, 2, 3].as_slice());

        assert_eq!(u16::from(option.code()), 65_000);
        assert_eq!(option.payload(), &[1, 2, 3]);
    }

    #[test]
    fn dhcpv6_option_model_value_bytes_are_lossless() {
        let mut option =
            Dhcpv6Option::typed(1u16, Dhcpv6OptionValue::Raw(vec![0x00, 0xff, 0x7e, 0x80]));
        assert_eq!(option.value().as_bytes(), &[0x00, 0xff, 0x7e, 0x80]);

        *option.value_mut() = Dhcpv6OptionValue::Empty;
        let (code, value) = option.into_parts();
        assert_eq!(code.code(), 1);
        assert_eq!(value.into_bytes(), Vec::<u8>::new());
    }
}

#[cfg(test)]
mod dhcpv6_option_codec_tests {
    use super::Dhcpv6Option;
    use crate::error::CrafterError;

    #[test]
    fn dhcpv6_option_codec_encodes_zero_length_options() {
        let option = Dhcpv6Option::empty(14u16);

        assert_eq!(option.encode().unwrap(), vec![0x00, 0x0e, 0x00, 0x00]);
        let decoded = Dhcpv6Option::decode_all(&[0x00, 0x0e, 0x00, 0x00]).unwrap();
        assert_eq!(decoded, vec![option]);
        assert!(decoded[0].is_empty());
    }

    #[test]
    fn dhcpv6_option_codec_decodes_multiple_options() {
        let bytes = [0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb, 0x00, 0x17, 0x00, 0x00];
        let decoded = Dhcpv6Option::decode_all(&bytes).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].codepoint(), 1);
        assert_eq!(decoded[0].payload(), &[0xaa, 0xbb]);
        assert_eq!(decoded[1].codepoint(), 23);
        assert_eq!(decoded[1].payload(), &[]);
        assert_eq!(Dhcpv6Option::encode_all(&decoded).unwrap(), bytes);
    }

    #[test]
    fn dhcpv6_option_codec_unknown_options_roundtrip() {
        let option = Dhcpv6Option::raw(65_000u16, [0xde, 0xad, 0xbe, 0xef].as_slice());
        let encoded = option.encode().unwrap();

        assert_eq!(
            encoded,
            vec![0xfd, 0xe8, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(Dhcpv6Option::decode_all(&encoded).unwrap(), vec![option]);
    }

    #[test]
    fn dhcpv6_option_codec_truncated_code_length_and_payload_are_structured() {
        assert_eq!(
            Dhcpv6Option::decode_all(&[0x00]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.code", 2, 1),
        );

        assert_eq!(
            Dhcpv6Option::decode_all(&[0x00, 0x01, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.length", 4, 3),
        );

        assert_eq!(
            Dhcpv6Option::decode_all(&[0x00, 0x01, 0x00, 0x04, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.payload", 8, 5),
        );
    }
}

#[cfg(test)]
mod dhcpv6_basic_options_tests {
    use super::{Dhcpv6Option, Dhcpv6OptionCode};
    use crate::error::CrafterError;
    use crate::protocols::dhcp::v6::{
        DHCPV6_OPTION_CLIENTID, DHCPV6_OPTION_ELAPSED_TIME, DHCPV6_OPTION_ORO,
        DHCPV6_OPTION_PREFERENCE, DHCPV6_OPTION_RAPID_COMMIT, DHCPV6_OPTION_SERVERID,
    };

    #[test]
    fn dhcpv6_basic_options_constructors_encode_core_tlvs() {
        let client_id = Dhcpv6Option::client_id([0x00, 0x03, 0xaa, 0xbb]);
        let server_id = Dhcpv6Option::server_id([0x00, 0x01, 0xcc, 0xdd]);
        let oro = Dhcpv6Option::oro([23u16, 24u16]);
        let preference = Dhcpv6Option::preference(200);
        let elapsed_time = Dhcpv6Option::elapsed_time(37);
        let rapid_commit = Dhcpv6Option::rapid_commit();

        assert_eq!(client_id.codepoint(), DHCPV6_OPTION_CLIENTID);
        assert_eq!(
            client_id.client_id_value(),
            Some(&[0x00, 0x03, 0xaa, 0xbb][..])
        );
        assert_eq!(server_id.codepoint(), DHCPV6_OPTION_SERVERID);
        assert_eq!(
            server_id.server_id_value(),
            Some(&[0x00, 0x01, 0xcc, 0xdd][..])
        );
        assert_eq!(oro.codepoint(), DHCPV6_OPTION_ORO);
        assert_eq!(
            oro.oro_value().unwrap(),
            Some(vec![
                Dhcpv6OptionCode::from_code(23),
                Dhcpv6OptionCode::from_code(24),
            ]),
        );
        assert_eq!(preference.codepoint(), DHCPV6_OPTION_PREFERENCE);
        assert_eq!(preference.preference_value().unwrap(), Some(200));
        assert_eq!(elapsed_time.codepoint(), DHCPV6_OPTION_ELAPSED_TIME);
        assert_eq!(elapsed_time.elapsed_time_value().unwrap(), Some(37));
        assert_eq!(rapid_commit.codepoint(), DHCPV6_OPTION_RAPID_COMMIT);
        assert!(rapid_commit.rapid_commit_present().unwrap());

        assert_eq!(
            Dhcpv6Option::encode_all(&[
                client_id,
                server_id,
                oro,
                preference,
                elapsed_time,
                rapid_commit,
            ])
            .unwrap(),
            vec![
                0x00, 0x01, 0x00, 0x04, 0x00, 0x03, 0xaa, 0xbb, 0x00, 0x02, 0x00, 0x04, 0x00, 0x01,
                0xcc, 0xdd, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18, 0x00, 0x07, 0x00, 0x01,
                200, 0x00, 0x08, 0x00, 0x02, 0x00, 37, 0x00, 0x0e, 0x00, 0x00,
            ],
        );
    }

    #[test]
    fn dhcpv6_basic_options_value_decoders_validate_fixed_lengths() {
        let decoded = Dhcpv6Option::decode_all(&[
            0x00, 0x07, 0x00, 0x02, 0xaa, 0xbb, 0x00, 0x08, 0x00, 0x01, 0xcc, 0x00, 0x0e, 0x00,
            0x01, 0xdd, 0x00, 0x06, 0x00, 0x03, 0x00, 0x17, 0xff,
        ])
        .unwrap();

        assert_eq!(
            decoded[0].preference_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.preference",
                "payload length does not match option format",
            ),
        );
        assert_eq!(decoded[0].payload(), &[0xaa, 0xbb]);

        assert_eq!(
            decoded[1].elapsed_time_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.elapsed_time",
                "payload length does not match option format",
            ),
        );
        assert_eq!(decoded[1].payload(), &[0xcc]);

        assert_eq!(
            decoded[2].rapid_commit_present().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.rapid_commit",
                "payload length does not match option format",
            ),
        );
        assert_eq!(decoded[2].payload(), &[0xdd]);

        assert_eq!(
            decoded[3].oro_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.oro",
                "payload length must be a multiple of 2 bytes",
            ),
        );
        assert_eq!(decoded[3].payload(), &[0x00, 0x17, 0xff]);
    }
}

#[cfg(test)]
mod dhcpv6_ia_na_tests {
    use super::{Dhcpv6IaNa, Dhcpv6Option};
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{Dhcpv6, DHCPV6_OPTION_IAADDR, DHCPV6_OPTION_IA_NA};

    #[test]
    fn dhcpv6_ia_na_empty_container_encodes_and_decodes() {
        let ia_na = Dhcpv6IaNa::new(0x01020304, 300, 600);
        let option = Dhcpv6Option::ia_na(ia_na.clone()).unwrap();

        assert_eq!(option.codepoint(), DHCPV6_OPTION_IA_NA);
        assert_eq!(
            option.encode().unwrap(),
            vec![
                0x00, 0x03, 0x00, 0x0c, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x00,
                0x02, 0x58,
            ],
        );

        let decoded = option.ia_na_value().unwrap().unwrap();
        assert_eq!(decoded, ia_na);
        assert_eq!(decoded.iaid(), 0x01020304);
        assert_eq!(decoded.t1(), 300);
        assert_eq!(decoded.t2(), 600);
        assert!(decoded.options_ref().is_empty());
    }

    #[test]
    fn dhcpv6_ia_na_preserves_nested_iaaddr_and_unknown_option_order() {
        let iaaddr = Dhcpv6Option::raw(DHCPV6_OPTION_IAADDR, vec![0xaa; 24]);
        let unknown = Dhcpv6Option::raw(65_000u16, [0xde, 0xad].as_slice());
        let ia_na = Dhcpv6IaNa::new(7, 0, 0)
            .option(iaaddr.clone())
            .option(unknown.clone());
        let option = Dhcpv6Option::ia_na(ia_na).unwrap();

        let decoded = option.ia_na_value().unwrap().unwrap();
        assert_eq!(decoded.iaid(), 7);
        assert_eq!(decoded.options_ref(), &[iaaddr, unknown]);
    }

    #[test]
    fn dhcpv6_ia_na_short_payload_is_structured_error_and_payload_survives() {
        let option = Dhcpv6Option::raw(DHCPV6_OPTION_IA_NA, vec![0; 11]);

        assert_eq!(
            option.ia_na_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.ia_na", 12, 11),
        );
        assert_eq!(option.payload(), &[0; 11]);
    }

    #[test]
    fn dhcpv6_ia_na_layer_helpers_roundtrip() {
        let nested = Dhcpv6Option::raw(DHCPV6_OPTION_IAADDR, vec![0xbb; 24]);
        let ia_na = Dhcpv6IaNa::new(0x11223344, 10, 20).option(nested.clone());
        let message = Dhcpv6::reply(0x010203).ia_na(ia_na.clone()).unwrap();

        assert_eq!(message.ia_na_value().unwrap(), Some(ia_na.clone()));
        assert_eq!(message.ia_na_values().unwrap(), vec![ia_na.clone()]);

        let bytes = Packet::from_layer(message).compile().unwrap();
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();
        let decoded_ia_na = decoded.ia_na_value().unwrap().unwrap();

        assert_eq!(decoded_ia_na.iaid(), 0x11223344);
        assert_eq!(decoded_ia_na.t1(), 10);
        assert_eq!(decoded_ia_na.t2(), 20);
        assert_eq!(decoded_ia_na.options_ref(), &[nested]);
    }
}

#[cfg(test)]
mod dhcpv6_iaaddr_tests {
    use core::net::Ipv6Addr;

    use super::{Dhcpv6IaAddr, Dhcpv6IaNa, Dhcpv6Option};
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{Dhcpv6, DHCPV6_OPTION_IAADDR, DHCPV6_OPTION_IA_NA};

    fn address() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)
    }

    #[test]
    fn dhcpv6_iaaddr_encodes_and_decodes_basic_address_fields() {
        let ia_addr = Dhcpv6IaAddr::new(address(), 3600, 7200);
        let option = Dhcpv6Option::ia_addr(ia_addr.clone()).unwrap();

        assert_eq!(option.codepoint(), DHCPV6_OPTION_IAADDR);
        assert_eq!(option.payload_len(), 24);

        let decoded = option.ia_addr_value().unwrap().unwrap();
        assert_eq!(decoded, ia_addr);
        assert_eq!(decoded.address(), address());
        assert_eq!(decoded.preferred_lifetime(), 3600);
        assert_eq!(decoded.valid_lifetime(), 7200);
        assert!(decoded.options_ref().is_empty());
    }

    #[test]
    fn dhcpv6_iaaddr_preserves_nested_unknown_options() {
        let unknown = Dhcpv6Option::raw(65_000u16, [0xde, 0xad, 0xbe, 0xef].as_slice());
        let ia_addr = Dhcpv6IaAddr::new(address(), 1, 2).option(unknown.clone());
        let decoded = Dhcpv6Option::ia_addr(ia_addr)
            .unwrap()
            .ia_addr_value()
            .unwrap()
            .unwrap();

        assert_eq!(decoded.options_ref(), &[unknown]);
    }

    #[test]
    fn dhcpv6_iaaddr_short_payload_is_structured_error() {
        let option = Dhcpv6Option::raw(DHCPV6_OPTION_IAADDR, vec![0; 23]);

        assert_eq!(
            option.ia_addr_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.iaaddr", 24, 23),
        );
        assert_eq!(option.payload(), &[0; 23]);
    }

    #[test]
    fn dhcpv6_iaaddr_roundtrips_under_ia_na() {
        let unknown = Dhcpv6Option::raw(65_001u16, [0xaa, 0xbb].as_slice());
        let ia_addr = Dhcpv6IaAddr::new(address(), 60, 120).option(unknown.clone());
        let ia_na = Dhcpv6IaNa::new(0x01020304, 30, 90)
            .ia_addr(ia_addr.clone())
            .unwrap();
        let message = Dhcpv6::reply(0x0a0b0c).ia_na(ia_na).unwrap();
        let bytes = Packet::from_layer(message).compile().unwrap();
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();

        let decoded_ia_na = decoded.ia_na_value().unwrap().unwrap();
        assert_eq!(decoded_ia_na.options_ref().len(), 1);
        assert_eq!(
            decoded_ia_na.options_ref()[0].codepoint(),
            DHCPV6_OPTION_IAADDR
        );

        let decoded_ia_addr = decoded_ia_na.options_ref()[0]
            .ia_addr_value()
            .unwrap()
            .unwrap();
        assert_eq!(decoded_ia_addr, ia_addr);
        assert_eq!(decoded_ia_addr.options_ref(), &[unknown]);

        let encoded_ia_na = Dhcpv6Option::ia_na(decoded_ia_na).unwrap();
        assert_eq!(encoded_ia_na.codepoint(), DHCPV6_OPTION_IA_NA);
    }
}

#[cfg(test)]
mod dhcpv6_ia_pd_tests {
    use super::{Dhcpv6IaPd, Dhcpv6Option};
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{Dhcpv6, DHCPV6_OPTION_IAPREFIX, DHCPV6_OPTION_IA_PD};

    #[test]
    fn dhcpv6_ia_pd_empty_container_encodes_and_decodes() {
        let ia_pd = Dhcpv6IaPd::new(0x01020304, 300, 600);
        let option = Dhcpv6Option::ia_pd(ia_pd.clone()).unwrap();

        assert_eq!(option.codepoint(), DHCPV6_OPTION_IA_PD);
        assert_eq!(
            option.encode().unwrap(),
            vec![
                0x00, 0x19, 0x00, 0x0c, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x00,
                0x02, 0x58,
            ],
        );

        let decoded = option.ia_pd_value().unwrap().unwrap();
        assert_eq!(decoded, ia_pd);
        assert_eq!(decoded.iaid(), 0x01020304);
        assert_eq!(decoded.t1(), 300);
        assert_eq!(decoded.t2(), 600);
        assert!(decoded.options_ref().is_empty());
    }

    #[test]
    fn dhcpv6_ia_pd_preserves_iaprefix_and_unknown_nested_order() {
        let iaprefix = Dhcpv6Option::raw(DHCPV6_OPTION_IAPREFIX, vec![0xaa; 25]);
        let unknown = Dhcpv6Option::raw(65_000u16, [0xde, 0xad].as_slice());
        let ia_pd = Dhcpv6IaPd::new(7, 0, 0)
            .option(iaprefix.clone())
            .option(unknown.clone());
        let option = Dhcpv6Option::ia_pd(ia_pd).unwrap();

        let decoded = option.ia_pd_value().unwrap().unwrap();
        assert_eq!(decoded.iaid(), 7);
        assert_eq!(decoded.options_ref(), &[iaprefix, unknown]);
    }

    #[test]
    fn dhcpv6_ia_pd_short_payload_is_structured_error() {
        let option = Dhcpv6Option::raw(DHCPV6_OPTION_IA_PD, vec![0; 11]);

        assert_eq!(
            option.ia_pd_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.ia_pd", 12, 11),
        );
        assert_eq!(option.payload(), &[0; 11]);
    }

    #[test]
    fn dhcpv6_ia_pd_layer_helpers_roundtrip() {
        let nested = Dhcpv6Option::raw(DHCPV6_OPTION_IAPREFIX, vec![0xbb; 25]);
        let ia_pd = Dhcpv6IaPd::new(0x11223344, 10, 20).option(nested.clone());
        let message = Dhcpv6::reply(0x010203).ia_pd(ia_pd.clone()).unwrap();

        assert_eq!(message.ia_pd_value().unwrap(), Some(ia_pd.clone()));
        assert_eq!(message.ia_pd_values().unwrap(), vec![ia_pd.clone()]);

        let bytes = Packet::from_layer(message).compile().unwrap();
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();
        let decoded_ia_pd = decoded.ia_pd_value().unwrap().unwrap();

        assert_eq!(decoded_ia_pd.iaid(), 0x11223344);
        assert_eq!(decoded_ia_pd.t1(), 10);
        assert_eq!(decoded_ia_pd.t2(), 20);
        assert_eq!(decoded_ia_pd.options_ref(), &[nested]);
    }
}

#[cfg(test)]
mod dhcpv6_iaprefix_tests {
    use core::net::Ipv6Addr;

    use super::{Dhcpv6IaPd, Dhcpv6IaPrefix, Dhcpv6Option};
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{Dhcpv6, DHCPV6_OPTION_IAPREFIX};

    fn prefix() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)
    }

    #[test]
    fn dhcpv6_iaprefix_encodes_and_decodes_documentation_prefix() {
        let ia_prefix = Dhcpv6IaPrefix::new(3600, 7200, 32, prefix());
        let option = Dhcpv6Option::ia_prefix(ia_prefix.clone()).unwrap();

        assert_eq!(option.codepoint(), DHCPV6_OPTION_IAPREFIX);
        assert_eq!(option.payload_len(), 25);

        let decoded = option.ia_prefix_value().unwrap().unwrap();
        assert_eq!(decoded, ia_prefix);
        assert_eq!(decoded.preferred_lifetime(), 3600);
        assert_eq!(decoded.valid_lifetime(), 7200);
        assert_eq!(decoded.prefix_length(), 32);
        assert_eq!(decoded.prefix(), prefix());
        assert!(decoded.options_ref().is_empty());
    }

    #[test]
    fn dhcpv6_iaprefix_preserves_nested_unknown_options() {
        let unknown = Dhcpv6Option::raw(65_000u16, [0xde, 0xad].as_slice());
        let ia_prefix = Dhcpv6IaPrefix::new(1, 2, 48, prefix()).option(unknown.clone());
        let decoded = Dhcpv6Option::ia_prefix(ia_prefix)
            .unwrap()
            .ia_prefix_value()
            .unwrap()
            .unwrap();

        assert_eq!(decoded.options_ref(), &[unknown]);
    }

    #[test]
    fn dhcpv6_iaprefix_rejects_short_payload_and_bad_prefix_length() {
        let short = Dhcpv6Option::raw(DHCPV6_OPTION_IAPREFIX, vec![0; 24]);
        assert_eq!(
            short.ia_prefix_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.iaprefix", 25, 24),
        );

        let invalid = Dhcpv6IaPrefix::new(1, 2, 129, prefix());
        assert_eq!(
            invalid.encode().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.iaprefix.prefix_length",
                "prefix length must be at most 128",
            ),
        );

        let mut payload = vec![0; 25];
        payload[8] = 129;
        let invalid_wire = Dhcpv6Option::raw(DHCPV6_OPTION_IAPREFIX, payload.clone());
        assert_eq!(
            invalid_wire.ia_prefix_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.iaprefix.prefix_length",
                "prefix length must be at most 128",
            ),
        );
        assert_eq!(invalid_wire.payload(), payload.as_slice());
    }

    #[test]
    fn dhcpv6_iaprefix_roundtrips_under_ia_pd() {
        let nested = Dhcpv6Option::raw(65_001u16, [0xaa, 0xbb].as_slice());
        let ia_prefix = Dhcpv6IaPrefix::new(60, 120, 32, prefix()).option(nested.clone());
        let ia_pd = Dhcpv6IaPd::new(0x01020304, 30, 90)
            .ia_prefix(ia_prefix.clone())
            .unwrap();
        let message = Dhcpv6::reply(0x0a0b0c).ia_pd(ia_pd).unwrap();
        let bytes = Packet::from_layer(message).compile().unwrap();
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();

        let decoded_ia_pd = decoded.ia_pd_value().unwrap().unwrap();
        assert_eq!(decoded_ia_pd.options_ref().len(), 1);
        assert_eq!(
            decoded_ia_pd.options_ref()[0].codepoint(),
            DHCPV6_OPTION_IAPREFIX
        );

        let decoded_prefix = decoded_ia_pd.options_ref()[0]
            .ia_prefix_value()
            .unwrap()
            .unwrap();
        assert_eq!(decoded_prefix, ia_prefix);
        assert_eq!(decoded_prefix.options_ref(), &[nested]);
    }
}

#[cfg(test)]
mod dhcpv6_prefix_extensions_tests {
    use core::net::Ipv6Addr;

    use super::{Dhcpv6IaPd, Dhcpv6IaPrefix, Dhcpv6Option, Dhcpv6PdExclude};
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{Dhcpv6, DHCPV6_OPTION_IAPREFIX, DHCPV6_OPTION_PD_EXCLUDE};

    fn prefix() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 0x5100, 0, 0, 0, 0, 0)
    }

    #[test]
    fn dhcpv6_prefix_extensions_encode_pd_exclude_boundaries() {
        let min = Dhcpv6PdExclude::new(0, [0x00]).unwrap();
        let max = Dhcpv6PdExclude::new(128, [0xff; 16]).unwrap();
        let min_option = Dhcpv6Option::pd_exclude(min.clone()).unwrap();
        let max_option = Dhcpv6Option::pd_exclude(max.clone()).unwrap();

        assert_eq!(min_option.codepoint(), DHCPV6_OPTION_PD_EXCLUDE);
        assert_eq!(min_option.payload(), &[0, 0]);
        assert_eq!(min_option.pd_exclude_value().unwrap(), Some(min));

        assert_eq!(max_option.payload_len(), 17);
        assert_eq!(max_option.payload()[0], 128);
        assert_eq!(max_option.pd_exclude_value().unwrap(), Some(max.clone()));
        assert_eq!(max.prefix_length(), 128);
        assert_eq!(max.subnet_id(), &[0xff; 16]);
    }

    #[test]
    fn dhcpv6_prefix_extensions_roundtrip_under_iaprefix_and_preserve_unknown() {
        let exclude = Dhcpv6PdExclude::new(56, [0x2a]).unwrap();
        let unknown = Dhcpv6Option::raw(65_002u16, [0xaa, 0xbb, 0xcc]);
        let ia_prefix = Dhcpv6IaPrefix::new(600, 1_200, 48, prefix())
            .pd_exclude(exclude.clone())
            .unwrap()
            .option(unknown.clone());
        let ia_pd = Dhcpv6IaPd::new(0x01020304, 300, 600)
            .ia_prefix(ia_prefix.clone())
            .unwrap();
        let message = Dhcpv6::reply(0x112233).ia_pd(ia_pd).unwrap();
        let decoded =
            Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes()).unwrap();

        let decoded_ia_pd = decoded.ia_pd_value().unwrap().unwrap();
        assert_eq!(
            decoded_ia_pd.options_ref()[0].codepoint(),
            DHCPV6_OPTION_IAPREFIX,
        );
        let decoded_prefix = decoded_ia_pd.options_ref()[0]
            .ia_prefix_value()
            .unwrap()
            .unwrap();

        assert_eq!(decoded_prefix.pd_exclude_value().unwrap(), Some(exclude));
        assert_eq!(decoded_prefix.options_ref()[1], unknown);
        assert_eq!(decoded_prefix, ia_prefix);
    }

    #[test]
    fn dhcpv6_prefix_extensions_reject_malformed_pd_exclude_payloads() {
        assert_eq!(
            Dhcpv6PdExclude::new(129, [0]).unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.pd_exclude.prefix_length",
                "prefix length must be at most 128",
            ),
        );
        assert_eq!(
            Dhcpv6PdExclude::new(64, []).unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.pd_exclude.subnet_id",
                "subnet id length must be between 1 and 16 bytes",
            ),
        );

        let short = Dhcpv6Option::raw(DHCPV6_OPTION_PD_EXCLUDE, [64]);
        assert_eq!(
            short.pd_exclude_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.pd_exclude", 2, 1),
        );

        let long = Dhcpv6Option::raw(DHCPV6_OPTION_PD_EXCLUDE, [64; 18]);
        assert_eq!(
            long.pd_exclude_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.pd_exclude",
                "payload length must be between 2 and 17 bytes",
            ),
        );
    }
}

#[cfg(test)]
mod dhcpv6_softwire_tests {
    use super::{Dhcpv6Option, Dhcpv6S46ContainerKind, Dhcpv6S46Priority};
    use crate::error::CrafterError;
    use crate::protocols::dhcp::v6::{
        dhcpv6_option_meta, dhcpv6_s46_priority_option_permitted, Dhcpv6ClientOro,
        Dhcpv6OptionSingleton, DHCPV6_OPTION_4RD, DHCPV6_OPTION_4RD_MAP_RULE,
        DHCPV6_OPTION_4RD_NON_MAP_RULE, DHCPV6_OPTION_S46_BIND_IPV6_PREFIX, DHCPV6_OPTION_S46_BR,
        DHCPV6_OPTION_S46_CONT_LW, DHCPV6_OPTION_S46_CONT_MAPE, DHCPV6_OPTION_S46_CONT_MAPT,
        DHCPV6_OPTION_S46_PRIORITY, DHCPV6_OPTION_S46_RULE, DHCPV6_OPTION_S46_V4V6BIND,
    };

    #[test]
    fn dhcpv6_softwire_containers_preserve_nested_options() {
        let rule = Dhcpv6Option::s46_rule([0x20, 0x08, 0xc0, 0x00, 0x02]);
        let unknown = Dhcpv6Option::raw(65_003u16, [0xaa, 0xbb]);
        let container = Dhcpv6Option::s46_cont_mape(vec![rule.clone(), unknown.clone()]).unwrap();

        assert_eq!(container.codepoint(), DHCPV6_OPTION_S46_CONT_MAPE);
        let decoded = container.s46_container_value().unwrap().unwrap();
        assert_eq!(decoded.kind(), Dhcpv6S46ContainerKind::MapE);
        assert_eq!(decoded.codepoint(), DHCPV6_OPTION_S46_CONT_MAPE);
        assert_eq!(decoded.options_ref(), &[rule, unknown]);

        let mapt = Dhcpv6Option::s46_cont_mapt(vec![Dhcpv6Option::s46_dmr([0x40, 0x20])]).unwrap();
        assert_eq!(
            mapt.s46_container_value().unwrap().unwrap().kind(),
            Dhcpv6S46ContainerKind::MapT,
        );
        let lw =
            Dhcpv6Option::s46_cont_lw(vec![Dhcpv6Option::s46_portparams([0, 8, 0, 1])]).unwrap();
        assert_eq!(
            lw.s46_container_value().unwrap().unwrap().kind(),
            Dhcpv6S46ContainerKind::Lightweight4Over6,
        );
    }

    #[test]
    fn dhcpv6_softwire_raw_fields_and_priority_roundtrip() {
        for (option, code, payload) in [
            (
                Dhcpv6Option::s46_br([0x20, 0x01]),
                DHCPV6_OPTION_S46_BR,
                vec![0x20, 0x01],
            ),
            (
                Dhcpv6Option::s46_v4v6bind([0xc0, 0x00, 0x02, 0x01]),
                DHCPV6_OPTION_S46_V4V6BIND,
                vec![0xc0, 0x00, 0x02, 0x01],
            ),
            (Dhcpv6Option::four_rd([0x01]), DHCPV6_OPTION_4RD, vec![0x01]),
            (
                Dhcpv6Option::four_rd_map_rule([0x02]),
                DHCPV6_OPTION_4RD_MAP_RULE,
                vec![0x02],
            ),
            (
                Dhcpv6Option::four_rd_non_map_rule([0x03]),
                DHCPV6_OPTION_4RD_NON_MAP_RULE,
                vec![0x03],
            ),
            (
                Dhcpv6Option::s46_bind_ipv6_prefix([0x40, 0x20, 0x01]),
                DHCPV6_OPTION_S46_BIND_IPV6_PREFIX,
                vec![0x40, 0x20, 0x01],
            ),
        ] {
            assert_eq!(option.codepoint(), code);
            assert_eq!(option.payload(), payload.as_slice());
        }

        let priority = Dhcpv6S46Priority::new(vec![
            DHCPV6_OPTION_S46_CONT_MAPE,
            DHCPV6_OPTION_S46_CONT_MAPT,
            DHCPV6_OPTION_S46_CONT_LW,
        ]);
        let option = Dhcpv6Option::s46_priority(priority.clone());

        assert_eq!(option.codepoint(), DHCPV6_OPTION_S46_PRIORITY);
        assert_eq!(option.s46_priority_value().unwrap(), Some(priority.clone()));
        assert_eq!(
            priority.option_codes(),
            &[
                DHCPV6_OPTION_S46_CONT_MAPE,
                DHCPV6_OPTION_S46_CONT_MAPT,
                DHCPV6_OPTION_S46_CONT_LW,
            ],
        );
    }

    #[test]
    fn dhcpv6_softwire_registry_metadata_and_malformed_lengths() {
        let meta = dhcpv6_option_meta(DHCPV6_OPTION_S46_CONT_MAPE);
        assert_eq!(meta.name, "OPTION_S46_CONT_MAPE");
        assert_eq!(meta.client_oro, Some(Dhcpv6ClientOro::Yes));
        assert_eq!(meta.singleton, Some(Dhcpv6OptionSingleton::No));

        assert!(dhcpv6_s46_priority_option_permitted(
            DHCPV6_OPTION_S46_CONT_MAPE
        ));
        assert!(dhcpv6_s46_priority_option_permitted(
            DHCPV6_OPTION_S46_CONT_MAPT
        ));
        assert!(dhcpv6_s46_priority_option_permitted(
            DHCPV6_OPTION_S46_CONT_LW
        ));
        assert!(!dhcpv6_s46_priority_option_permitted(
            DHCPV6_OPTION_S46_RULE
        ));

        let malformed =
            Dhcpv6Option::raw(DHCPV6_OPTION_S46_CONT_MAPE, [0x00, 0x59, 0x00, 0x02, 0xaa]);
        assert_eq!(
            malformed.s46_container_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.payload", 6, 5),
        );

        let odd_priority = Dhcpv6Option::raw(DHCPV6_OPTION_S46_PRIORITY, [0x00]);
        assert_eq!(
            odd_priority.s46_priority_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.s46_priority",
                "payload length must be a multiple of 2 bytes",
            ),
        );
    }
}

#[cfg(test)]
mod dhcpv6_modern_options_tests {
    use core::net::Ipv6Addr;

    use super::{Dhcpv6Dnr, Dhcpv6DnrSvcParam, Dhcpv6Option};
    use crate::error::CrafterError;
    use crate::protocols::dhcp::v6::{
        dhcpv6_option_meta, DHCPV6_OPTION_CAPTIVE_PORTAL, DHCPV6_OPTION_MUD_URL_V6,
        DHCPV6_OPTION_V6_DNR, DHCPV6_OPTION_V6_PREFIX64,
    };
    use crate::protocols::dns::DnsName;

    #[test]
    fn dhcpv6_modern_options_preserve_uri_payloads_and_registry_metadata() {
        let captive = Dhcpv6Option::captive_portal_uri(b"https://cp.example.net/api".as_slice());
        let mud = Dhcpv6Option::mud_url_v6(b"https://mud.example.net/model.json".as_slice());
        let prefix64 = Dhcpv6Option::v6_prefix64([0x40, 0x00, 0x64, 0xff, 0x9b]);

        assert_eq!(captive.codepoint(), DHCPV6_OPTION_CAPTIVE_PORTAL);
        assert_eq!(
            captive.captive_portal_uri_text(),
            Some("https://cp.example.net/api")
        );
        assert_eq!(mud.codepoint(), DHCPV6_OPTION_MUD_URL_V6);
        assert_eq!(
            mud.mud_url_v6_text(),
            Some("https://mud.example.net/model.json"),
        );
        assert_eq!(prefix64.codepoint(), DHCPV6_OPTION_V6_PREFIX64);
        assert_eq!(
            prefix64.v6_prefix64_value(),
            Some(&[0x40, 0x00, 0x64, 0xff, 0x9b][..])
        );

        assert_eq!(
            dhcpv6_option_meta(DHCPV6_OPTION_CAPTIVE_PORTAL).name,
            "DHCP Captive-Portal",
        );
        assert_eq!(
            dhcpv6_option_meta(DHCPV6_OPTION_MUD_URL_V6).name,
            "OPTION_MUD_URL_V6",
        );
        assert_eq!(
            dhcpv6_option_meta(DHCPV6_OPTION_V6_DNR).name,
            "OPTION_V6_DNR",
        );
    }

    #[test]
    fn dhcpv6_modern_options_dnr_roundtrips_addresses_and_unknown_params() {
        let addr_a = Ipv6Addr::new(0x2001, 0x0db8, 53, 0, 0, 0, 0, 1);
        let addr_b = Ipv6Addr::new(0x2001, 0x0db8, 53, 0, 0, 0, 0, 2);
        let alpn = Dhcpv6DnrSvcParam::new(1, b"\x02h2".to_vec());
        let unknown = Dhcpv6DnrSvcParam::new(65_000, [0xde, 0xad, 0xbe, 0xef]);
        let dnr = Dhcpv6Dnr::new(10, DnsName::parse("resolver.example.").unwrap())
            .addresses_from([addr_a, addr_b])
            .svc_params_from(vec![alpn.clone(), unknown.clone()]);
        let option = Dhcpv6Option::v6_dnr(dnr.clone()).unwrap();

        assert_eq!(option.codepoint(), DHCPV6_OPTION_V6_DNR);
        let decoded = option.v6_dnr_value().unwrap().unwrap();
        assert_eq!(decoded, dnr);
        assert_eq!(decoded.service_priority(), 10);
        assert_eq!(decoded.adn().presentation(), "resolver.example.");
        assert_eq!(decoded.addresses(), &[addr_a, addr_b]);
        assert_eq!(decoded.svc_params(), &[alpn, unknown]);
        assert_eq!(decoded.svc_params()[1].key(), 65_000);
        assert_eq!(decoded.svc_params()[1].value(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn dhcpv6_modern_options_reject_malformed_dnr_payloads() {
        let short = Dhcpv6Option::raw(DHCPV6_OPTION_V6_DNR, [0, 1, 0]);
        assert_eq!(
            short.v6_dnr_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.v6_dnr", 4, 3),
        );

        let compressed_adn = Dhcpv6Option::raw(DHCPV6_OPTION_V6_DNR, [0, 1, 0, 2, 0xc0, 0x00]);
        assert_eq!(
            compressed_adn.v6_dnr_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.v6_dnr.adn",
                "compressed or reserved DNS label markers are not valid here",
            ),
        );

        let bad_addr_len = Dhcpv6Option::raw(DHCPV6_OPTION_V6_DNR, [0, 1, 0, 1, 0, 0, 1, 0xff]);
        assert_eq!(
            bad_addr_len.v6_dnr_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.v6_dnr.addresses",
                "address hint length must be a multiple of 16 bytes",
            ),
        );

        let out_of_order = Dhcpv6Dnr::new(1, DnsName::root()).svc_params_from(vec![
            Dhcpv6DnrSvcParam::new(5, []),
            Dhcpv6DnrSvcParam::new(4, []),
        ]);
        assert_eq!(
            out_of_order.encode().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.v6_dnr.svc_params",
                "SvcParamKeys must be in strictly increasing order",
            ),
        );
    }
}

#[cfg(test)]
mod dhcpv6_status_option_tests {
    use core::net::Ipv6Addr;

    use super::{
        Dhcpv6IaAddr, Dhcpv6IaNa, Dhcpv6IaPd, Dhcpv6IaPrefix, Dhcpv6Option, Dhcpv6StatusCodeOption,
    };
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{Dhcpv6, Dhcpv6StatusCode, DHCPV6_OPTION_STATUS_CODE};

    fn address() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)
    }

    fn prefix() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)
    }

    #[test]
    fn dhcpv6_status_option_encodes_success_with_empty_message() {
        let status = Dhcpv6StatusCodeOption::new(Dhcpv6StatusCode::Success);
        let option = Dhcpv6Option::status_code(status.clone());

        assert_eq!(option.codepoint(), DHCPV6_OPTION_STATUS_CODE);
        assert_eq!(option.payload(), &[0x00, 0x00]);
        assert_eq!(option.status_code_value().unwrap(), Some(status.clone()));
        assert_eq!(status.status(), Dhcpv6StatusCode::Success);
        assert_eq!(status.message_bytes(), &[]);
        assert_eq!(status.message_text(), Some(""));
    }

    #[test]
    fn dhcpv6_status_option_preserves_no_addrs_message_text() {
        let option = Dhcpv6Option::status_message(Dhcpv6StatusCode::NoAddrsAvail, b"no addresses");
        let decoded = option.status_code_value().unwrap().unwrap();

        assert_eq!(decoded.status(), Dhcpv6StatusCode::NoAddrsAvail);
        assert_eq!(decoded.message_bytes(), b"no addresses");
        assert_eq!(decoded.message_text(), Some("no addresses"));
        assert_eq!(
            option.encode().unwrap(),
            [
                0x00, 0x0d, 0x00, 0x0e, 0x00, 0x02, b'n', b'o', b' ', b'a', b'd', b'd', b'r', b'e',
                b's', b's', b'e', b's',
            ],
        );
    }

    #[test]
    fn dhcpv6_status_option_preserves_no_prefix_message_text() {
        let status =
            Dhcpv6StatusCodeOption::with_message(Dhcpv6StatusCode::NoPrefixAvail, "no prefix");
        let decoded = Dhcpv6StatusCodeOption::decode(&status.encode()).unwrap();

        assert_eq!(decoded.status(), Dhcpv6StatusCode::NoPrefixAvail);
        assert_eq!(decoded.message_text(), Some("no prefix"));
    }

    #[test]
    fn dhcpv6_status_option_preserves_unknown_status_codes() {
        let option = Dhcpv6Option::raw(DHCPV6_OPTION_STATUS_CODE, [0xfd, 0xe8, b'o', b'k']);
        let decoded = option.status_code_value().unwrap().unwrap();

        assert_eq!(decoded.status(), Dhcpv6StatusCode::Unknown(65_000));
        assert_eq!(decoded.message_text(), Some("ok"));
        assert_eq!(
            Dhcpv6Option::status_code(decoded).payload(),
            option.payload()
        );
    }

    #[test]
    fn dhcpv6_status_option_preserves_non_utf8_message_bytes() {
        let option = Dhcpv6Option::raw(DHCPV6_OPTION_STATUS_CODE, [0x00, 0x01, 0xff, 0xfe]);
        let decoded = option.status_code_value().unwrap().unwrap();

        assert_eq!(decoded.status(), Dhcpv6StatusCode::UnspecFail);
        assert_eq!(decoded.message_bytes(), &[0xff, 0xfe]);
        assert_eq!(decoded.message_text(), None);
    }

    #[test]
    fn dhcpv6_status_option_rejects_short_payload_without_losing_bytes() {
        let option = Dhcpv6Option::raw(DHCPV6_OPTION_STATUS_CODE, [0xaa]);

        assert_eq!(
            option.status_code_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.status_code", 2, 1),
        );
        assert_eq!(option.payload(), &[0xaa]);
    }

    #[test]
    fn dhcpv6_status_option_helpers_work_top_level_and_nested() {
        let top = Dhcpv6StatusCodeOption::new(Dhcpv6StatusCode::Success);
        let no_addrs =
            Dhcpv6StatusCodeOption::with_message(Dhcpv6StatusCode::NoAddrsAvail, "no address");
        let no_prefix =
            Dhcpv6StatusCodeOption::with_message(Dhcpv6StatusCode::NoPrefixAvail, "no prefix");

        let ia_addr = Dhcpv6IaAddr::new(address(), 60, 120).status_code(no_addrs.clone());
        let ia_na = Dhcpv6IaNa::new(0x01020304, 30, 90)
            .status_code(no_addrs.clone())
            .ia_addr(ia_addr)
            .unwrap();
        let ia_prefix = Dhcpv6IaPrefix::new(60, 120, 32, prefix()).status_code(no_prefix.clone());
        let ia_pd = Dhcpv6IaPd::new(0x11223344, 300, 600)
            .status_code(no_prefix.clone())
            .ia_prefix(ia_prefix)
            .unwrap();
        let message = Dhcpv6::reply(0x0a0b0c)
            .status_code(top.clone())
            .ia_na(ia_na)
            .unwrap()
            .ia_pd(ia_pd)
            .unwrap();

        assert_eq!(message.status_code_value().unwrap(), Some(top.clone()));
        assert_eq!(message.status_code_values().unwrap(), vec![top.clone()]);

        let bytes = Packet::from_layer(message).compile().unwrap();
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();
        let decoded_ia_na = decoded.ia_na_value().unwrap().unwrap();
        let decoded_ia_pd = decoded.ia_pd_value().unwrap().unwrap();

        assert_eq!(decoded.status_code_value().unwrap(), Some(top));
        assert_eq!(
            decoded_ia_na.options_ref()[0]
                .status_code_value()
                .unwrap()
                .unwrap(),
            no_addrs,
        );
        assert_eq!(
            decoded_ia_pd.options_ref()[0]
                .status_code_value()
                .unwrap()
                .unwrap(),
            no_prefix,
        );
    }
}

#[cfg(test)]
mod dhcpv6_authentication_tests {
    use super::{
        Dhcpv6AuthAlgorithm, Dhcpv6AuthProtocol, Dhcpv6Authentication, Dhcpv6Option,
        Dhcpv6ReplayDetectionMethod,
    };
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{
        Dhcpv6, Dhcpv6MessageType, DHCPV6_AUTH_HEADER_LEN, DHCPV6_OPTION_AUTH,
    };

    fn build_and_decode(authentication: Dhcpv6Authentication) -> Dhcpv6 {
        let bytes = Packet::from_layer(Dhcpv6::request(0x010203).authentication(authentication))
            .compile()
            .unwrap();
        Dhcpv6::decode(bytes.as_bytes()).unwrap()
    }

    #[test]
    fn dhcpv6_authentication_option_roundtrips_packet_fields_only() {
        // The authentication information bytes are arbitrary documentation data,
        // not a generated MAC. The crate encodes and decodes the packet fields
        // only; it does not derive, sign, or verify authentication material.
        let mut auth_info = Vec::new();
        auth_info.extend_from_slice(&[0x00, 0x00, 0x00, 0x2a]);
        auth_info.extend_from_slice(&[0xabu8; 16]);
        let authentication = Dhcpv6Authentication::new(
            Dhcpv6AuthProtocol::Delayed,
            Dhcpv6AuthAlgorithm::HmacMd5,
            Dhcpv6ReplayDetectionMethod::MonotonicCounter,
            0x0102_0304_0506_0708,
            auth_info.clone(),
        );

        let payload = authentication.encode();
        let mut expected = vec![1u8, 1, 0];
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        expected.extend_from_slice(&auth_info);
        assert_eq!(payload, expected);
        assert_eq!(
            Dhcpv6Authentication::decode(&payload).unwrap(),
            authentication
        );

        let option = Dhcpv6Option::authentication(authentication.clone());
        assert_eq!(option.codepoint(), DHCPV6_OPTION_AUTH);
        assert_eq!(
            option.authentication_value().unwrap(),
            Some(authentication.clone()),
        );

        let parsed = build_and_decode(authentication.clone());
        assert_eq!(parsed.message_type_value(), Dhcpv6MessageType::Request);
        assert_eq!(parsed.authentication_value().unwrap(), Some(authentication));
        assert_eq!(
            parsed
                .authentication_value()
                .unwrap()
                .unwrap()
                .authentication_information,
            auth_info
        );
    }

    #[test]
    fn dhcpv6_authentication_unknown_field_codes_are_preserved() {
        let authentication = Dhcpv6Authentication::new(
            Dhcpv6AuthProtocol::Unknown(0x7f),
            Dhcpv6AuthAlgorithm::Unknown(0x42),
            Dhcpv6ReplayDetectionMethod::Unknown(0x99),
            0,
            vec![0xde, 0xad, 0xbe, 0xef],
        );
        let payload = authentication.encode();

        assert_eq!(payload[0], 0x7f);
        assert_eq!(payload[1], 0x42);
        assert_eq!(payload[2], 0x99);

        let decoded = Dhcpv6Authentication::decode(&payload).unwrap();
        assert_eq!(decoded, authentication);
        assert_eq!(decoded.protocol.code(), 0x7f);
        assert_eq!(decoded.algorithm.code(), 0x42);
        assert_eq!(decoded.rdm.code(), 0x99);
        assert_eq!(
            build_and_decode(authentication.clone())
                .authentication_value()
                .unwrap(),
            Some(authentication),
        );
    }

    #[test]
    fn dhcpv6_authentication_registered_code_values_are_named() {
        assert_eq!(Dhcpv6AuthProtocol::ConfigurationToken.code(), 0);
        assert_eq!(Dhcpv6AuthProtocol::Delayed.code(), 1);
        assert_eq!(Dhcpv6AuthProtocol::Dhcpv6DelayedObsolete.code(), 2);
        assert_eq!(Dhcpv6AuthProtocol::ReconfigureKey.code(), 3);
        assert_eq!(Dhcpv6AuthProtocol::SplitHorizonDns.code(), 4);
        assert_eq!(
            Dhcpv6AuthProtocol::from_code(2),
            Dhcpv6AuthProtocol::Dhcpv6DelayedObsolete,
        );
        assert_eq!(
            Dhcpv6AuthAlgorithm::from_code(0),
            Dhcpv6AuthAlgorithm::ConfigurationToken,
        );
        assert_eq!(
            Dhcpv6AuthAlgorithm::from_code(1),
            Dhcpv6AuthAlgorithm::HmacMd5,
        );
        assert_eq!(
            Dhcpv6ReplayDetectionMethod::from_code(0),
            Dhcpv6ReplayDetectionMethod::MonotonicCounter,
        );
    }

    #[test]
    fn dhcpv6_authentication_malformed_lengths_are_structured() {
        for len in 0..DHCPV6_AUTH_HEADER_LEN {
            let short = vec![0u8; len];
            assert_eq!(
                Dhcpv6Authentication::decode(&short).unwrap_err(),
                CrafterError::buffer_too_short(
                    "dhcpv6.option.authentication",
                    DHCPV6_AUTH_HEADER_LEN,
                    len,
                ),
            );

            let option = Dhcpv6Option::raw(DHCPV6_OPTION_AUTH, short);
            assert!(matches!(
                option.authentication_value(),
                Err(CrafterError::BufferTooShort { .. }),
            ));
        }

        let header_only = vec![1u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let decoded = Dhcpv6Authentication::decode(&header_only).unwrap();
        assert!(decoded.authentication_information.is_empty());
        assert_eq!(decoded.encode(), header_only);
    }
}

#[cfg(test)]
mod dhcpv6_vendor_class_tests {
    use super::{
        Dhcpv6Option, Dhcpv6UserClass, Dhcpv6VendorClass, Dhcpv6VendorOption, Dhcpv6VendorOptions,
    };
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{
        Dhcpv6, DHCPV6_OPTION_USER_CLASS, DHCPV6_OPTION_VENDOR_CLASS, DHCPV6_OPTION_VENDOR_OPTS,
    };

    #[test]
    fn dhcpv6_vendor_class_user_class_preserves_multiple_entries() {
        let user_class =
            Dhcpv6UserClass::new(vec![b"alpha-client".to_vec(), b"install-profile".to_vec()]);
        let option = Dhcpv6Option::user_class(user_class.clone()).unwrap();

        assert_eq!(option.codepoint(), DHCPV6_OPTION_USER_CLASS);
        assert_eq!(
            option.payload(),
            &[
                0x00, 0x0c, b'a', b'l', b'p', b'h', b'a', b'-', b'c', b'l', b'i', b'e', b'n', b't',
                0x00, 0x0f, b'i', b'n', b's', b't', b'a', b'l', b'l', b'-', b'p', b'r', b'o', b'f',
                b'i', b'l', b'e',
            ],
        );
        assert_eq!(option.user_class_value().unwrap(), Some(user_class.clone()));

        let message = Dhcpv6::request(0x010203)
            .user_class(user_class.clone())
            .unwrap();
        let bytes = Packet::from_layer(message).compile().unwrap();
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();
        assert_eq!(decoded.user_class_value().unwrap(), Some(user_class));
    }

    #[test]
    fn dhcpv6_vendor_class_preserves_enterprise_and_multiple_entries() {
        let vendor_class = Dhcpv6VendorClass::new(
            3561,
            vec![
                b"PXEClient:Arch:00009".to_vec(),
                vec![0xde, 0xad, 0xbe, 0xef],
            ],
        );
        let option = Dhcpv6Option::vendor_class(vendor_class.clone()).unwrap();

        assert_eq!(option.codepoint(), DHCPV6_OPTION_VENDOR_CLASS);
        assert_eq!(&option.payload()[0..4], &3561u32.to_be_bytes());
        assert_eq!(
            option.vendor_class_value().unwrap(),
            Some(vendor_class.clone()),
        );
        assert_eq!(vendor_class.enterprise_number(), 3561);
        assert_eq!(vendor_class.class_data()[1], vec![0xde, 0xad, 0xbe, 0xef]);

        let message = Dhcpv6::request(0x010203)
            .vendor_class(vendor_class.clone())
            .unwrap();
        let decoded =
            Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes()).unwrap();
        assert_eq!(
            decoded.vendor_class_value().unwrap(),
            Some(vendor_class.clone())
        );
        assert_eq!(decoded.vendor_class_values().unwrap(), vec![vendor_class]);
    }

    #[test]
    fn dhcpv6_vendor_class_vendor_opts_preserve_unknown_suboptions() {
        let unknown = Dhcpv6VendorOption::new(65_000u16, vec![0xde, 0xad, 0xbe, 0xef]);
        let empty = Dhcpv6VendorOption::new(7u16, Vec::<u8>::new());
        let vendor_opts = Dhcpv6VendorOptions::new(32_473, vec![unknown.clone(), empty.clone()]);
        let option = Dhcpv6Option::vendor_opts(vendor_opts.clone()).unwrap();

        assert_eq!(option.codepoint(), DHCPV6_OPTION_VENDOR_OPTS);
        assert_eq!(
            option.payload(),
            &[
                0x00, 0x00, 0x7e, 0xd9, 0xfd, 0xe8, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x07,
                0x00, 0x00,
            ],
        );

        let decoded = option.vendor_opts_value().unwrap().unwrap();
        assert_eq!(decoded.enterprise_number(), 32_473);
        assert_eq!(decoded.options(), &[unknown.clone(), empty.clone()]);
        assert_eq!(decoded.options()[0].codepoint(), 65_000);
        assert_eq!(decoded.options()[0].payload(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decoded.options()[1].payload(), &[]);

        let second = Dhcpv6VendorOptions::new(311, vec![Dhcpv6VendorOption::new(1u16, [0xaa])]);
        let message = Dhcpv6::request(0x010203)
            .vendor_opts(vendor_opts.clone())
            .unwrap()
            .vendor_opts(second.clone())
            .unwrap();
        let decoded_message =
            Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes()).unwrap();
        assert_eq!(
            decoded_message.vendor_opts_value().unwrap(),
            Some(vendor_opts.clone()),
        );
        assert_eq!(
            decoded_message.vendor_opts_values().unwrap(),
            vec![vendor_opts, second],
        );
    }

    #[test]
    fn dhcpv6_vendor_class_malformed_lengths_are_structured() {
        let short_user = Dhcpv6Option::raw(DHCPV6_OPTION_USER_CLASS, [0x00, 0x04, 0xaa]);
        assert_eq!(
            short_user.user_class_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.user_class", 6, 3),
        );

        let short_vendor_class = Dhcpv6Option::raw(DHCPV6_OPTION_VENDOR_CLASS, [0x00, 0x00, 0x00]);
        assert_eq!(
            short_vendor_class.vendor_class_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.vendor_class.enterprise_number", 4, 3,),
        );

        let short_vendor_class_entry = Dhcpv6Option::raw(
            DHCPV6_OPTION_VENDOR_CLASS,
            [0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0xaa],
        );
        assert_eq!(
            short_vendor_class_entry.vendor_class_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.vendor_class", 6, 3),
        );

        let short_vendor_code =
            Dhcpv6Option::raw(DHCPV6_OPTION_VENDOR_OPTS, [0x00, 0x00, 0x00, 0x01, 0xfd]);
        assert_eq!(
            short_vendor_code.vendor_opts_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.vendor_opts.option_code", 6, 5),
        );

        let short_vendor_payload = Dhcpv6Option::raw(
            DHCPV6_OPTION_VENDOR_OPTS,
            [0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x00, 0x04, 0xaa],
        );
        assert_eq!(
            short_vendor_payload.vendor_opts_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.vendor_opts.option_payload", 12, 9),
        );
    }
}

#[cfg(test)]
mod dhcpv6_dns_domain_tests {
    use core::net::Ipv6Addr;

    use super::{Dhcpv6DomainList, Dhcpv6Option, Dhcpv6OptionCode};
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{
        Dhcpv6, DHCPV6_OPTION_DNS_SERVERS, DHCPV6_OPTION_DOMAIN_LIST,
    };

    fn dns_server(index: u16) -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, index)
    }

    #[test]
    fn dhcpv6_dns_domain_servers_preserve_multiple_ipv6_addresses() {
        let servers = vec![dns_server(53), dns_server(54)];
        let option = Dhcpv6Option::dns_servers(servers.clone());

        assert_eq!(option.codepoint(), DHCPV6_OPTION_DNS_SERVERS);
        assert_eq!(option.payload_len(), 32);
        assert_eq!(option.dns_servers_value().unwrap(), Some(servers.clone()));
        assert_eq!(&option.payload()[0..16], &dns_server(53).octets());
        assert_eq!(&option.payload()[16..32], &dns_server(54).octets());

        let message = Dhcpv6::reply(0x010203).dns_servers(servers.clone());
        let decoded =
            Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes()).unwrap();
        assert_eq!(decoded.dns_servers_value().unwrap(), Some(servers));
    }

    #[test]
    fn dhcpv6_dns_domain_list_uses_dns_name_wire_format() {
        let domain_list = Dhcpv6DomainList::parse(["example.com", "lab.example."]).unwrap();
        let option = Dhcpv6Option::domain_list(domain_list.clone()).unwrap();

        assert_eq!(option.codepoint(), DHCPV6_OPTION_DOMAIN_LIST);
        assert_eq!(
            option.payload(),
            &[
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 3, b'l', b'a',
                b'b', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
            ],
        );

        let decoded = option.domain_list_value().unwrap().unwrap();
        assert_eq!(decoded, domain_list);
        assert_eq!(
            decoded.presentations(),
            vec!["example.com.", "lab.example."]
        );
        assert_eq!(decoded.names()[0].presentation(), "example.com.");
    }

    #[test]
    fn dhcpv6_dns_domain_list_reports_truncated_domain_names() {
        let option = Dhcpv6Option::raw(DHCPV6_OPTION_DOMAIN_LIST, [7, b'e', b'x']);

        assert_eq!(
            option.domain_list_value().unwrap_err(),
            CrafterError::buffer_too_short("dns.name.label", 8, 3),
        );
    }

    #[test]
    fn dhcpv6_dns_domain_oro_request_and_response_roundtrip() {
        let request = Dhcpv6::information_request(0x0a0b0c)
            .oro([DHCPV6_OPTION_DNS_SERVERS, DHCPV6_OPTION_DOMAIN_LIST]);
        assert_eq!(
            request.oro_value().unwrap(),
            Some(vec![
                Dhcpv6OptionCode::from_code(DHCPV6_OPTION_DNS_SERVERS),
                Dhcpv6OptionCode::from_code(DHCPV6_OPTION_DOMAIN_LIST),
            ]),
        );

        let domains = Dhcpv6DomainList::parse(["example.com.", "ops.example.com."]).unwrap();
        let response = Dhcpv6::reply(0x0a0b0c)
            .dns_servers([dns_server(53), dns_server(54)])
            .domain_list(domains.clone())
            .unwrap();
        let decoded =
            Dhcpv6::decode(Packet::from_layer(response).compile().unwrap().as_bytes()).unwrap();

        assert_eq!(
            decoded.dns_servers_value().unwrap(),
            Some(vec![dns_server(53), dns_server(54)]),
        );
        assert_eq!(decoded.domain_list_value().unwrap(), Some(domains));
    }

    #[test]
    fn dhcpv6_dns_domain_servers_reject_truncated_address_list() {
        let option = Dhcpv6Option::raw(DHCPV6_OPTION_DNS_SERVERS, vec![0; 15]);

        assert_eq!(
            option.dns_servers_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.dns_servers",
                "payload length must be a multiple of 16 bytes",
            ),
        );
    }
}

#[cfg(test)]
mod dhcpv6_information_refresh_tests {
    use core::net::Ipv6Addr;

    use super::{Dhcpv6IaAddr, Dhcpv6IaNa, Dhcpv6IaPd, Dhcpv6IaPrefix, Dhcpv6Option};
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{
        Dhcpv6, DHCPV6_OPTION_INFORMATION_REFRESH_TIME, DHCPV6_OPTION_INF_MAX_RT,
        DHCPV6_OPTION_SOL_MAX_RT, DHCPV6_TIME_INFINITY,
    };

    fn address() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 46, 0, 0, 0, 0, 1)
    }

    fn prefix() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 46, 0, 0, 0, 0, 0)
    }

    #[test]
    fn dhcpv6_information_refresh_encodes_valid_32_bit_values() {
        let information_refresh = Dhcpv6Option::information_refresh_time(86_400);
        let sol_max_rt = Dhcpv6Option::sol_max_rt(3_600);
        let inf_max_rt = Dhcpv6Option::inf_max_rt(DHCPV6_TIME_INFINITY);

        assert_eq!(
            information_refresh.codepoint(),
            DHCPV6_OPTION_INFORMATION_REFRESH_TIME,
        );
        assert_eq!(information_refresh.payload(), &86_400u32.to_be_bytes());
        assert_eq!(
            information_refresh
                .information_refresh_time_value()
                .unwrap(),
            Some(86_400),
        );
        assert_eq!(sol_max_rt.codepoint(), DHCPV6_OPTION_SOL_MAX_RT);
        assert_eq!(sol_max_rt.sol_max_rt_value().unwrap(), Some(3_600));
        assert_eq!(inf_max_rt.codepoint(), DHCPV6_OPTION_INF_MAX_RT);
        assert_eq!(
            inf_max_rt.inf_max_rt_value().unwrap(),
            Some(DHCPV6_TIME_INFINITY),
        );
    }

    #[test]
    fn dhcpv6_information_refresh_layer_roundtrips_timers() {
        let message = Dhcpv6::reply(0x010203)
            .information_refresh_time(600)
            .sol_max_rt(3_600)
            .inf_max_rt(7_200);
        let decoded =
            Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes()).unwrap();

        assert_eq!(decoded.information_refresh_time_value().unwrap(), Some(600));
        assert_eq!(decoded.sol_max_rt_value().unwrap(), Some(3_600));
        assert_eq!(decoded.inf_max_rt_value().unwrap(), Some(7_200));
    }

    #[test]
    fn dhcpv6_information_refresh_ia_timer_and_infinity_helpers() {
        let ia_na = Dhcpv6IaNa::new(0x01020304, 300, 600);
        let ia_pd = Dhcpv6IaPd::new(0x11223344, 900, 1_800);
        let ia_addr = Dhcpv6IaAddr::new(address(), DHCPV6_TIME_INFINITY, DHCPV6_TIME_INFINITY);
        let ia_prefix =
            Dhcpv6IaPrefix::new(DHCPV6_TIME_INFINITY, DHCPV6_TIME_INFINITY, 48, prefix());

        assert_eq!(ia_na.timers(), (300, 600));
        assert_eq!(ia_pd.timers(), (900, 1_800));
        assert!(ia_addr.preferred_lifetime_is_infinite());
        assert!(ia_addr.valid_lifetime_is_infinite());
        assert!(ia_prefix.preferred_lifetime_is_infinite());
        assert!(ia_prefix.valid_lifetime_is_infinite());
    }

    #[test]
    fn dhcpv6_information_refresh_rejects_malformed_fixed_length_payloads() {
        for (option, field) in [
            (
                Dhcpv6Option::raw(DHCPV6_OPTION_INFORMATION_REFRESH_TIME, [0, 0, 0]),
                "dhcpv6.option.information_refresh_time",
            ),
            (
                Dhcpv6Option::raw(DHCPV6_OPTION_SOL_MAX_RT, [0, 0, 0]),
                "dhcpv6.option.sol_max_rt",
            ),
            (
                Dhcpv6Option::raw(DHCPV6_OPTION_INF_MAX_RT, [0, 0, 0]),
                "dhcpv6.option.inf_max_rt",
            ),
        ] {
            let error = match option.codepoint() {
                DHCPV6_OPTION_INFORMATION_REFRESH_TIME => {
                    option.information_refresh_time_value().unwrap_err()
                }
                DHCPV6_OPTION_SOL_MAX_RT => option.sol_max_rt_value().unwrap_err(),
                DHCPV6_OPTION_INF_MAX_RT => option.inf_max_rt_value().unwrap_err(),
                _ => unreachable!(),
            };
            assert_eq!(
                error,
                CrafterError::invalid_field_value(
                    field,
                    "payload length does not match option format",
                ),
            );
        }
    }
}

#[cfg(test)]
mod dhcpv6_max_rt_tests {
    use super::Dhcpv6Option;
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{
        Dhcpv6, DHCPV6_OPTION_INF_MAX_RT, DHCPV6_OPTION_SOL_MAX_RT, DHCPV6_TIME_INFINITY,
    };

    #[test]
    fn dhcpv6_max_rt_encodes_normal_and_boundary_values() {
        let sol_zero = Dhcpv6Option::sol_max_rt(0);
        let sol_normal = Dhcpv6Option::sol_max_rt(3_600);
        let inf_infinity = Dhcpv6Option::inf_max_rt(DHCPV6_TIME_INFINITY);

        assert_eq!(sol_zero.codepoint(), DHCPV6_OPTION_SOL_MAX_RT);
        assert_eq!(sol_zero.payload(), &0u32.to_be_bytes());
        assert_eq!(sol_zero.sol_max_rt_value().unwrap(), Some(0));
        assert_eq!(sol_normal.sol_max_rt_value().unwrap(), Some(3_600));

        assert_eq!(inf_infinity.codepoint(), DHCPV6_OPTION_INF_MAX_RT);
        assert_eq!(inf_infinity.payload(), &DHCPV6_TIME_INFINITY.to_be_bytes());
        assert_eq!(
            inf_infinity.inf_max_rt_value().unwrap(),
            Some(DHCPV6_TIME_INFINITY),
        );
    }

    #[test]
    fn dhcpv6_max_rt_layer_roundtrips_values() {
        let message = Dhcpv6::reply(0x010203).sol_max_rt(3_600).inf_max_rt(7_200);
        let decoded =
            Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes()).unwrap();

        assert_eq!(decoded.sol_max_rt_value().unwrap(), Some(3_600));
        assert_eq!(decoded.inf_max_rt_value().unwrap(), Some(7_200));
    }

    #[test]
    fn dhcpv6_max_rt_rejects_wrong_length_payloads() {
        for (option, expected) in [
            (
                Dhcpv6Option::raw(DHCPV6_OPTION_SOL_MAX_RT, []),
                "dhcpv6.option.sol_max_rt",
            ),
            (
                Dhcpv6Option::raw(DHCPV6_OPTION_SOL_MAX_RT, [0, 0, 0]),
                "dhcpv6.option.sol_max_rt",
            ),
            (
                Dhcpv6Option::raw(DHCPV6_OPTION_INF_MAX_RT, [0, 0, 0, 0, 0]),
                "dhcpv6.option.inf_max_rt",
            ),
        ] {
            let error = match option.codepoint() {
                DHCPV6_OPTION_SOL_MAX_RT => option.sol_max_rt_value().unwrap_err(),
                DHCPV6_OPTION_INF_MAX_RT => option.inf_max_rt_value().unwrap_err(),
                _ => unreachable!(),
            };
            assert_eq!(
                error,
                CrafterError::invalid_field_value(
                    expected,
                    "payload length does not match option format",
                ),
            );
        }
    }
}

#[cfg(test)]
mod dhcpv6_boot_options_tests {
    use super::{
        Dhcpv6BootfileParam, Dhcpv6ClientArchitecture, Dhcpv6NetworkInterfaceIdentifier,
        Dhcpv6Option,
    };
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{
        Dhcpv6, DHCPV6_OPTION_BOOTFILE_PARAM, DHCPV6_OPTION_BOOTFILE_URL,
        DHCPV6_OPTION_CLIENT_ARCH_TYPE, DHCPV6_OPTION_NII,
    };

    #[test]
    fn dhcpv6_boot_options_preserve_url_and_multiple_parameters() {
        let url = b"tftp://[2001:db8::1]/bootx64.efi".as_slice();
        let params = Dhcpv6BootfileParam::new(vec![
            b"root-path=/srv/netboot".to_vec(),
            b"console=ttyS0".to_vec(),
        ]);
        let param_option = Dhcpv6Option::bootfile_param(params.clone()).unwrap();

        assert_eq!(
            Dhcpv6Option::bootfile_url(url).codepoint(),
            DHCPV6_OPTION_BOOTFILE_URL,
        );
        assert_eq!(
            Dhcpv6Option::bootfile_url(url).bootfile_url_text(),
            Some("tftp://[2001:db8::1]/bootx64.efi")
        );
        assert_eq!(param_option.codepoint(), DHCPV6_OPTION_BOOTFILE_PARAM);
        assert_eq!(
            param_option.payload(),
            &[
                0x00, 0x16, b'r', b'o', b'o', b't', b'-', b'p', b'a', b't', b'h', b'=', b'/', b's',
                b'r', b'v', b'/', b'n', b'e', b't', b'b', b'o', b'o', b't', 0x00, 0x0d, b'c', b'o',
                b'n', b's', b'o', b'l', b'e', b'=', b't', b't', b'y', b'S', b'0',
            ],
        );

        let message = Dhcpv6::reply(0x010203)
            .bootfile_url(url)
            .bootfile_param(params.clone())
            .unwrap();
        let decoded =
            Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes()).unwrap();
        assert_eq!(decoded.bootfile_url_value(), Some(url));
        assert_eq!(
            decoded.bootfile_url_text(),
            Some("tftp://[2001:db8::1]/bootx64.efi")
        );
        assert_eq!(decoded.bootfile_param_value().unwrap(), Some(params));
    }

    #[test]
    fn dhcpv6_boot_options_preserve_unknown_architecture_values() {
        let arch = Dhcpv6ClientArchitecture::new(vec![0, 7, 9, 0xffff]);
        let option = Dhcpv6Option::client_arch_type(arch.clone());

        assert_eq!(option.codepoint(), DHCPV6_OPTION_CLIENT_ARCH_TYPE);
        assert_eq!(
            option.payload(),
            &[0x00, 0x00, 0x00, 0x07, 0x00, 0x09, 0xff, 0xff]
        );
        assert_eq!(option.client_arch_type_value().unwrap(), Some(arch.clone()));
        assert_eq!(arch.architectures(), &[0, 7, 9, 0xffff]);

        let decoded = Dhcpv6::decode(
            Packet::from_layer(Dhcpv6::reply(0x010203).client_arch_type(arch.clone()))
                .compile()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(decoded.client_arch_type_value().unwrap(), Some(arch));
    }

    #[test]
    fn dhcpv6_boot_options_nii_roundtrips_and_rejects_bad_lengths() {
        let nii = Dhcpv6NetworkInterfaceIdentifier::undi(2, 1);
        let option = Dhcpv6Option::network_interface_identifier(nii);

        assert_eq!(option.codepoint(), DHCPV6_OPTION_NII);
        assert_eq!(option.payload(), &[1, 2, 1]);
        assert_eq!(
            option.network_interface_identifier_value().unwrap(),
            Some(nii)
        );

        let decoded = Dhcpv6::decode(
            Packet::from_layer(Dhcpv6::reply(0x010203).network_interface_identifier(nii))
                .compile()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            decoded.network_interface_identifier_value().unwrap(),
            Some(nii)
        );

        let malformed = Dhcpv6Option::raw(DHCPV6_OPTION_NII, [1, 2]);
        assert_eq!(
            malformed.network_interface_identifier_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.nii",
                "payload length does not match option format",
            ),
        );
    }

    #[test]
    fn dhcpv6_boot_options_reject_malformed_parameter_and_arch_lengths() {
        let malformed_param = Dhcpv6Option::raw(DHCPV6_OPTION_BOOTFILE_PARAM, [0x00, 0x04, b'a']);
        assert_eq!(
            malformed_param.bootfile_param_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.bootfile_param", 6, 3),
        );

        let malformed_arch = Dhcpv6Option::raw(DHCPV6_OPTION_CLIENT_ARCH_TYPE, [0x00]);
        assert_eq!(
            malformed_arch.client_arch_type_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.client_arch_type",
                "payload length must be a non-zero multiple of 2 bytes",
            ),
        );
    }
}

#[cfg(test)]
mod dhcpv6_service_options_tests {
    use core::net::Ipv6Addr;

    use super::{Dhcpv6DomainList, Dhcpv6NtpServer, Dhcpv6NtpSuboption, Dhcpv6Option};
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{
        Dhcpv6, DHCPV6_OPTION_NEW_POSIX_TIMEZONE, DHCPV6_OPTION_NEW_TZDB_TIMEZONE,
        DHCPV6_OPTION_NTP_SERVER, DHCPV6_OPTION_SIP_SERVER_A, DHCPV6_OPTION_SIP_SERVER_D,
        DHCPV6_OPTION_SIP_UA_CS_LIST, DHCPV6_OPTION_SNTP_SERVERS,
    };
    use crate::protocols::dns::DnsName;

    fn addr(index: u16) -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 48, 0, 0, 0, 0, index)
    }

    #[test]
    fn dhcpv6_service_options_sip_and_sntp_address_lists_roundtrip() {
        let sip = Dhcpv6Option::sip_server_addresses([addr(10), addr(11)]);
        let sntp = Dhcpv6Option::sntp_servers([addr(20), addr(21)]);

        assert_eq!(sip.codepoint(), DHCPV6_OPTION_SIP_SERVER_A);
        assert_eq!(
            sip.sip_server_addresses_value().unwrap(),
            Some(vec![addr(10), addr(11)]),
        );
        assert_eq!(sntp.codepoint(), DHCPV6_OPTION_SNTP_SERVERS);
        assert_eq!(
            sntp.sntp_servers_value().unwrap(),
            Some(vec![addr(20), addr(21)]),
        );

        let decoded = Dhcpv6::decode(
            Packet::from_layer(
                Dhcpv6::reply(0x010203)
                    .option(sip.clone())
                    .option(sntp.clone()),
            )
            .compile()
            .unwrap()
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            decoded.options_ref()[0]
                .sip_server_addresses_value()
                .unwrap(),
            Some(vec![addr(10), addr(11)]),
        );
        assert_eq!(
            decoded.options_ref()[1].sntp_servers_value().unwrap(),
            Some(vec![addr(20), addr(21)]),
        );
    }

    #[test]
    fn dhcpv6_service_options_sip_domain_lists_use_dns_wire_format() {
        let domains = Dhcpv6DomainList::parse(["sip.example.com.", "backup.example.com."]).unwrap();
        let sip_domains = Dhcpv6Option::sip_server_domains(domains.clone()).unwrap();
        let ua_domains = Dhcpv6Option::sip_ua_cs_list(domains.clone()).unwrap();

        assert_eq!(sip_domains.codepoint(), DHCPV6_OPTION_SIP_SERVER_D);
        assert_eq!(ua_domains.codepoint(), DHCPV6_OPTION_SIP_UA_CS_LIST);
        assert_eq!(
            sip_domains.sip_server_domains_value().unwrap(),
            Some(domains.clone()),
        );
        assert_eq!(ua_domains.sip_ua_cs_list_value().unwrap(), Some(domains));
    }

    #[test]
    fn dhcpv6_service_options_ntp_suboptions_preserve_unknown_payloads() {
        let ntp = Dhcpv6NtpServer::new(vec![
            Dhcpv6NtpSuboption::server_address(addr(123)),
            Dhcpv6NtpSuboption::server_fqdn(DnsName::parse("time.example.com.").unwrap()).unwrap(),
            Dhcpv6NtpSuboption::new(65_000u16, [0xde, 0xad, 0xbe, 0xef]),
        ]);
        let option = Dhcpv6Option::ntp_server(ntp.clone()).unwrap();

        assert_eq!(option.codepoint(), DHCPV6_OPTION_NTP_SERVER);
        let decoded = option.ntp_server_value().unwrap().unwrap();
        assert_eq!(decoded, ntp);
        assert_eq!(decoded.suboptions()[0].codepoint(), 1);
        assert_eq!(decoded.suboptions()[0].payload(), &addr(123).octets());
        assert_eq!(decoded.suboptions()[2].codepoint(), 65_000);
        assert_eq!(decoded.suboptions()[2].payload(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn dhcpv6_service_options_timezone_bytes_have_text_views() {
        let posix = Dhcpv6Option::posix_timezone(b"EST5EDT,M3.2.0/2,M11.1.0/2".as_slice());
        let tzdb = Dhcpv6Option::tzdb_timezone(b"America/New_York".as_slice());

        assert_eq!(posix.codepoint(), DHCPV6_OPTION_NEW_POSIX_TIMEZONE);
        assert_eq!(
            posix.posix_timezone_text(),
            Some("EST5EDT,M3.2.0/2,M11.1.0/2")
        );
        assert_eq!(tzdb.codepoint(), DHCPV6_OPTION_NEW_TZDB_TIMEZONE);
        assert_eq!(tzdb.tzdb_timezone_text(), Some("America/New_York"));
    }

    #[test]
    fn dhcpv6_service_options_malformed_payloads_are_structured() {
        let bad_sip = Dhcpv6Option::raw(DHCPV6_OPTION_SIP_SERVER_A, vec![0; 15]);
        assert_eq!(
            bad_sip.sip_server_addresses_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.sip_server_a",
                "payload length must be a multiple of 16 bytes",
            ),
        );

        let bad_ntp = Dhcpv6Option::raw(DHCPV6_OPTION_NTP_SERVER, [0x00, 0x01, 0x00, 0x04, 0xaa]);
        assert_eq!(
            bad_ntp.ntp_server_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.ntp_server.suboption_payload", 8, 5),
        );
    }
}

#[cfg(test)]
mod dhcpv6_fqdn_tests {
    use super::{Dhcpv6ClientFqdn, Dhcpv6Option};
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{Dhcpv6, DHCPV6_OPTION_CLIENT_FQDN};
    use crate::protocols::dns::DnsName;

    #[test]
    fn dhcpv6_fqdn_encodes_fully_qualified_name() {
        let fqdn = Dhcpv6ClientFqdn::new(0x01, DnsName::parse("host.example.com.").unwrap());
        let option = Dhcpv6Option::client_fqdn(fqdn.clone()).unwrap();

        assert_eq!(option.codepoint(), DHCPV6_OPTION_CLIENT_FQDN);
        assert_eq!(
            option.payload(),
            &[
                0x01, 4, b'h', b'o', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
                b'c', b'o', b'm', 0,
            ],
        );
        assert_eq!(option.client_fqdn_value().unwrap(), Some(fqdn.clone()));

        let decoded = Dhcpv6::decode(
            Packet::from_layer(Dhcpv6::reply(0x010203).option(option))
                .compile()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            decoded.options_ref()[0].client_fqdn_value().unwrap(),
            Some(fqdn)
        );
    }

    #[test]
    fn dhcpv6_fqdn_preserves_root_name_and_unknown_flags() {
        let root = Dhcpv6ClientFqdn::new(0xf8, DnsName::root());
        let decoded = Dhcpv6Option::client_fqdn(root.clone())
            .unwrap()
            .client_fqdn_value()
            .unwrap()
            .unwrap();

        assert_eq!(decoded.flags(), 0xf8);
        assert_eq!(decoded.domain_name().presentation(), ".");
        assert_eq!(decoded, root);
    }

    #[test]
    fn dhcpv6_fqdn_rejects_compressed_or_truncated_names() {
        let compressed = Dhcpv6Option::raw(DHCPV6_OPTION_CLIENT_FQDN, [0x00, 0xc0, 0x00]);
        assert_eq!(
            compressed.client_fqdn_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.client_fqdn.name",
                "compressed or reserved DNS label markers are not valid here",
            ),
        );

        let truncated = Dhcpv6Option::raw(DHCPV6_OPTION_CLIENT_FQDN, [0x00, 7, b'e', b'x']);
        assert_eq!(
            truncated.client_fqdn_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.client_fqdn.name", 9, 4),
        );
    }
}
