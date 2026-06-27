//! DHCPv6 generic option model.
//!
//! DHCPv6 options are 16-bit code, 16-bit length, variable payload TLVs. This
//! module starts with the raw-preserving data model; the serial codec and IANA
//! registry classification live in later modules.

use core::net::Ipv6Addr;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};

use super::constants::{
    DHCPV6_AUTH_ALGORITHM_CONFIGURATION_TOKEN, DHCPV6_AUTH_ALGORITHM_HMAC_MD5,
    DHCPV6_AUTH_HEADER_LEN, DHCPV6_AUTH_PROTOCOL_CONFIGURATION_TOKEN, DHCPV6_AUTH_PROTOCOL_DELAYED,
    DHCPV6_AUTH_PROTOCOL_DHCPV6_DELAYED_OBSOLETE, DHCPV6_AUTH_PROTOCOL_RECONFIGURE_KEY,
    DHCPV6_AUTH_PROTOCOL_SPLIT_HORIZON_DNS, DHCPV6_AUTH_RDM_MONOTONIC_COUNTER,
    DHCPV6_AUTH_REPLAY_DETECTION_LEN, DHCPV6_OPTION_AUTH, DHCPV6_OPTION_CLIENTID,
    DHCPV6_OPTION_ELAPSED_TIME, DHCPV6_OPTION_HEADER_LEN, DHCPV6_OPTION_IAADDR,
    DHCPV6_OPTION_IAPREFIX, DHCPV6_OPTION_IA_NA, DHCPV6_OPTION_IA_PD, DHCPV6_OPTION_ORO,
    DHCPV6_OPTION_PREFERENCE, DHCPV6_OPTION_RAPID_COMMIT, DHCPV6_OPTION_RECONF_ACCEPT,
    DHCPV6_OPTION_RECONF_MSG, DHCPV6_OPTION_SERVERID, DHCPV6_OPTION_STATUS_CODE,
};
use super::duid::Dhcpv6Duid;
use super::message::Dhcpv6MessageType;
use super::status::Dhcpv6StatusCode;

const DHCPV6_IAADDR_HEADER_LEN: usize = 24;
const DHCPV6_IA_NA_HEADER_LEN: usize = 12;
const DHCPV6_IA_PD_HEADER_LEN: usize = 12;
const DHCPV6_IAPREFIX_HEADER_LEN: usize = 25;
const DHCPV6_PREFIX_LEN_MAX: u8 = 128;

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

    /// Valid lifetime value.
    pub const fn valid_lifetime(&self) -> u32 {
        self.valid_lifetime
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

    /// Valid lifetime value.
    pub const fn valid_lifetime(&self) -> u32 {
        self.valid_lifetime
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

    /// Create an OPTION_RAPID_COMMIT option.
    pub fn rapid_commit() -> Self {
        Self::empty(DHCPV6_OPTION_RAPID_COMMIT)
    }

    /// Create an OPTION_AUTH option.
    ///
    /// This serializes the supplied packet fields only; it does not derive,
    /// sign, or verify authentication material.
    pub fn authentication(authentication: Dhcpv6Authentication) -> Self {
        Self::raw(DHCPV6_OPTION_AUTH, authentication.encode())
    }

    /// Create an OPTION_RECONF_MSG option.
    pub fn reconfigure_message(message_type: Dhcpv6MessageType) -> Self {
        Self::raw(DHCPV6_OPTION_RECONF_MSG, vec![message_type.code()])
    }

    /// Create an OPTION_RECONF_ACCEPT option.
    pub fn reconfigure_accept() -> Self {
        Self::empty(DHCPV6_OPTION_RECONF_ACCEPT)
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

    /// Return true when this is a valid zero-length OPTION_RAPID_COMMIT.
    pub fn rapid_commit_present(&self) -> Result<bool> {
        Ok(self
            .exact_payload_if_code(DHCPV6_OPTION_RAPID_COMMIT, 0, "dhcpv6.option.rapid_commit")?
            .is_some())
    }

    /// Decode OPTION_AUTH.
    pub fn authentication_value(&self) -> Result<Option<Dhcpv6Authentication>> {
        match self.payload_if_code(DHCPV6_OPTION_AUTH) {
            Some(payload) => Dhcpv6Authentication::decode(payload).map(Some),
            None => Ok(None),
        }
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
    if prefix_length > DHCPV6_PREFIX_LEN_MAX {
        return Err(CrafterError::invalid_field_value(
            "dhcpv6.option.iaprefix.prefix_length",
            "prefix length must be at most 128",
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
