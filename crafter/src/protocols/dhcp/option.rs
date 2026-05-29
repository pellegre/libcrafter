//! DHCP option types and the option-area codec.

use core::net::Ipv4Addr;
use core::str;

use crate::endian::read_u32_be;
use crate::error::{CrafterError, Result};

use super::constants::{
    DHCP_OPTION_BROADCAST_ADDRESS, DHCP_OPTION_CLIENT_IDENTIFIER, DHCP_OPTION_DOMAIN_NAME,
    DHCP_OPTION_DOMAIN_NAME_SERVER, DHCP_OPTION_END, DHCP_OPTION_HOST_NAME,
    DHCP_OPTION_IP_ADDRESS_LEASE_TIME, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_PAD,
    DHCP_OPTION_PARAMETER_REQUEST_LIST, DHCP_OPTION_REBINDING_TIME, DHCP_OPTION_RENEWAL_TIME,
    DHCP_OPTION_REQUESTED_IP_ADDRESS, DHCP_OPTION_ROUTER, DHCP_OPTION_SERVER_IDENTIFIER,
    DHCP_OPTION_SUBNET_MASK,
};
use super::message::DhcpMessageType;

/// Parsed or constructible DHCP option.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DhcpOption {
    /// Padding byte.
    Pad,
    /// End marker.
    End,
    /// DHCP message type.
    MessageType(DhcpMessageType),
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

    /// Raw DHCP option code.
    pub const fn code(&self) -> u8 {
        match self {
            Self::Pad => DHCP_OPTION_PAD,
            Self::End => DHCP_OPTION_END,
            Self::MessageType(_) => DHCP_OPTION_MESSAGE_TYPE,
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

    /// Encoded option length in bytes.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Pad | Self::End => 1,
            Self::MessageType(_) => 3,
            Self::SubnetMask(_)
            | Self::BroadcastAddress(_)
            | Self::RequestedIpAddress(_)
            | Self::ServerIdentifier(_) => 6,
            Self::Router(addresses) | Self::DomainNameServer(addresses) => 2 + addresses.len() * 4,
            Self::HostName(name) | Self::DomainName(name) => 2 + name.len(),
            Self::IpAddressLeaseTime(_) | Self::RenewalTime(_) | Self::RebindingTime(_) => 6,
            Self::ParameterRequestList(requests)
            | Self::ClientIdentifier(requests)
            | Self::Generic { data: requests, .. } => 2 + requests.len(),
        }
    }

    /// Encode this option to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut bytes)?;
        Ok(bytes)
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
                let data = self.payload_bytes()?;
                if data.len() > u8::MAX as usize {
                    return Err(CrafterError::invalid_field_value(
                        "dhcp.option.length",
                        "DHCP option payload must fit in one byte",
                    ));
                }
                if matches!(self.code(), DHCP_OPTION_PAD | DHCP_OPTION_END) {
                    return Err(CrafterError::invalid_field_value(
                        "dhcp.option.code",
                        "pad and end options do not carry a length byte",
                    ));
                }
                out.push(self.code());
                out.push(data.len() as u8);
                out.extend_from_slice(&data);
                Ok(())
            }
        }
    }

    fn payload_bytes(&self) -> Result<Vec<u8>> {
        let bytes = match self {
            Self::Pad | Self::End => Vec::new(),
            Self::MessageType(message_type) => vec![message_type.code()],
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
    let mut options = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        let code = bytes[offset];
        offset += 1;

        match code {
            DHCP_OPTION_PAD => options.push(DhcpOption::Pad),
            DHCP_OPTION_END => {
                options.push(DhcpOption::End);
                while offset < bytes.len() {
                    if bytes[offset] != DHCP_OPTION_PAD {
                        return Err(CrafterError::invalid_field_value(
                            "dhcp.option.end",
                            "non-padding data follows DHCP end option",
                        ));
                    }
                    options.push(DhcpOption::Pad);
                    offset += 1;
                }
                return Ok(options);
            }
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
                options.push(decode_dhcp_option(code, &bytes[offset..end])?);
                offset = end;
            }
        }
    }

    Err(CrafterError::invalid_field_value(
        "dhcp.options",
        "DHCP options are missing an end marker",
    ))
}

fn decode_dhcp_option(code: u8, data: &[u8]) -> Result<DhcpOption> {
    match code {
        DHCP_OPTION_MESSAGE_TYPE => {
            validate_fixed_len("dhcp.option.message_type", data.len(), 1)?;
            Ok(DhcpOption::MessageType(DhcpMessageType::from_code(data[0])))
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
        DHCP_OPTION_HOST_NAME => Ok(DhcpOption::HostName(decode_text_option(
            "dhcp.option.host_name",
            data,
        )?)),
        DHCP_OPTION_DOMAIN_NAME => Ok(DhcpOption::DomainName(decode_text_option(
            "dhcp.option.domain_name",
            data,
        )?)),
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

fn decode_text_option(field: &'static str, data: &[u8]) -> Result<String> {
    str::from_utf8(data)
        .map(str::to_string)
        .map_err(|_| CrafterError::invalid_field_value(field, "option text is not valid UTF-8"))
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

fn encode_ipv4_list(addresses: &[Ipv4Addr]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(addresses.len() * 4);
    for address in addresses {
        bytes.extend_from_slice(&address.octets());
    }
    bytes
}

#[cfg(test)]
mod dhcp_options {
    use super::super::{Dhcp, DhcpMessageType, DhcpOption};
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

    fn hex_fixture(input: &str) -> Vec<u8> {
        input
            .split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect()
    }
}
