//! Dynamic Host Configuration Protocol implementation.

use core::any::Any;
use core::net::Ipv4Addr;
use core::ops::Div;
use core::str;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::mac::MacAddr;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

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

const DHCP_CHADDR_LEN: usize = 16;
const DHCP_SNAME_LEN: usize = 64;
const DHCP_FILE_LEN: usize = 128;
const DHCP_DEFAULT_PARAMETER_REQUESTS: [u8; 6] = [
    DHCP_OPTION_SUBNET_MASK,
    DHCP_OPTION_ROUTER,
    DHCP_OPTION_DOMAIN_NAME_SERVER,
    DHCP_OPTION_DOMAIN_NAME,
    DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
    DHCP_OPTION_SERVER_IDENTIFIER,
];

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

/// DHCP message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhcpMessageType {
    /// Discover.
    Discover,
    /// Offer.
    Offer,
    /// Request.
    Request,
    /// Decline.
    Decline,
    /// ACK.
    Ack,
    /// NAK.
    Nak,
    /// Release.
    Release,
    /// Inform.
    Inform,
    /// Unknown message type value preserved from decode.
    Unknown(u8),
}

impl DhcpMessageType {
    /// Create a DHCP message type from its wire value.
    pub const fn from_code(code: u8) -> Self {
        match code {
            DHCP_DISCOVER => Self::Discover,
            DHCP_OFFER => Self::Offer,
            DHCP_REQUEST => Self::Request,
            DHCP_DECLINE => Self::Decline,
            DHCP_ACK => Self::Ack,
            DHCP_NAK => Self::Nak,
            DHCP_RELEASE => Self::Release,
            DHCP_INFORM => Self::Inform,
            value => Self::Unknown(value),
        }
    }

    /// Wire value.
    pub const fn code(self) -> u8 {
        match self {
            Self::Discover => DHCP_DISCOVER,
            Self::Offer => DHCP_OFFER,
            Self::Request => DHCP_REQUEST,
            Self::Decline => DHCP_DECLINE,
            Self::Ack => DHCP_ACK,
            Self::Nak => DHCP_NAK,
            Self::Release => DHCP_RELEASE,
            Self::Inform => DHCP_INFORM,
            Self::Unknown(value) => value,
        }
    }
}

impl From<DhcpMessageType> for u8 {
    fn from(value: DhcpMessageType) -> Self {
        value.code()
    }
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

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
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

/// DHCP packet layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcp {
    op: Field<u8>,
    hardware_type: Field<u8>,
    hardware_len: Field<u8>,
    hops: Field<u8>,
    transaction_id: Field<u32>,
    seconds: Field<u16>,
    flags: Field<u16>,
    client_ip_address: Field<Ipv4Addr>,
    your_ip_address: Field<Ipv4Addr>,
    server_ip_address: Field<Ipv4Addr>,
    gateway_ip_address: Field<Ipv4Addr>,
    client_hardware_address: Vec<u8>,
    server_name: Vec<u8>,
    boot_file_name: Vec<u8>,
    magic_cookie: Field<u32>,
    options: Vec<DhcpOption>,
}

impl Dhcp {
    /// Create an empty DHCP/BOOTP request with deterministic Ethernet defaults.
    pub fn new() -> Self {
        Self {
            op: Field::defaulted(BOOTP_REQUEST),
            hardware_type: Field::defaulted(DHCP_HTYPE_ETHERNET),
            hardware_len: Field::defaulted(6),
            hops: Field::defaulted(0),
            transaction_id: Field::defaulted(0),
            seconds: Field::defaulted(0),
            flags: Field::defaulted(0),
            client_ip_address: Field::defaulted(Ipv4Addr::UNSPECIFIED),
            your_ip_address: Field::defaulted(Ipv4Addr::UNSPECIFIED),
            server_ip_address: Field::defaulted(Ipv4Addr::UNSPECIFIED),
            gateway_ip_address: Field::defaulted(Ipv4Addr::UNSPECIFIED),
            client_hardware_address: MacAddr::ZERO.octets().to_vec(),
            server_name: Vec::new(),
            boot_file_name: Vec::new(),
            magic_cookie: Field::defaulted(DHCP_MAGIC_COOKIE),
            options: Vec::new(),
        }
    }

    /// Create a DHCP discover message for an Ethernet client.
    pub fn discover(client_mac: MacAddr) -> Self {
        Self::new()
            .client_mac(client_mac)
            .message_type(DhcpMessageType::Discover)
            .parameter_request_list(DHCP_DEFAULT_PARAMETER_REQUESTS)
    }

    /// Create a DHCP request message for an Ethernet client.
    pub fn request(
        client_mac: MacAddr,
        requested_ip: Ipv4Addr,
        server_identifier: Ipv4Addr,
    ) -> Self {
        Self::new()
            .client_mac(client_mac)
            .message_type(DhcpMessageType::Request)
            .requested_ip_address(requested_ip)
            .server_identifier(server_identifier)
            .parameter_request_list(DHCP_DEFAULT_PARAMETER_REQUESTS)
    }

    /// Create a DHCP offer message.
    pub fn offer(client_mac: MacAddr, offered_ip: Ipv4Addr, server_identifier: Ipv4Addr) -> Self {
        Self::new()
            .op(BOOTP_REPLY)
            .client_mac(client_mac)
            .yiaddr(offered_ip)
            .message_type(DhcpMessageType::Offer)
            .server_identifier(server_identifier)
    }

    /// Decode a DHCP packet payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_dhcp(bytes)
    }

    /// Set the BOOTP opcode.
    pub fn op(mut self, op: u8) -> Self {
        self.op.set_user(op);
        self
    }

    /// Set the hardware type.
    pub fn hardware_type(mut self, hardware_type: u8) -> Self {
        self.hardware_type.set_user(hardware_type);
        self
    }

    /// Compatibility alias for hardware type.
    pub fn htype(self, hardware_type: u8) -> Self {
        self.hardware_type(hardware_type)
    }

    /// Set the hardware address length.
    pub fn hardware_len(mut self, hardware_len: u8) -> Self {
        self.hardware_len.set_user(hardware_len);
        self
    }

    /// Compatibility alias for hardware address length.
    pub fn hlen(self, hardware_len: u8) -> Self {
        self.hardware_len(hardware_len)
    }

    /// Set relay-agent hops.
    pub fn hops(mut self, hops: u8) -> Self {
        self.hops.set_user(hops);
        self
    }

    /// Set the DHCP transaction ID.
    pub fn transaction_id(mut self, transaction_id: u32) -> Self {
        self.transaction_id.set_user(transaction_id);
        self
    }

    /// Compatibility alias for transaction ID.
    pub fn xid(self, transaction_id: u32) -> Self {
        self.transaction_id(transaction_id)
    }

    /// Set elapsed seconds.
    pub fn seconds(mut self, seconds: u16) -> Self {
        self.seconds.set_user(seconds);
        self
    }

    /// Compatibility alias for elapsed seconds.
    pub fn secs(self, seconds: u16) -> Self {
        self.seconds(seconds)
    }

    /// Set the raw DHCP flags field.
    pub fn flags(mut self, flags: u16) -> Self {
        self.flags.set_user(flags);
        self
    }

    /// Set the client IP address field.
    pub fn client_ip_address(mut self, address: Ipv4Addr) -> Self {
        self.client_ip_address.set_user(address);
        self
    }

    /// Compatibility alias for client IP address.
    pub fn ciaddr(self, address: Ipv4Addr) -> Self {
        self.client_ip_address(address)
    }

    /// Set the your/client IP address field.
    pub fn your_ip_address(mut self, address: Ipv4Addr) -> Self {
        self.your_ip_address.set_user(address);
        self
    }

    /// Compatibility alias for your/client IP address.
    pub fn yiaddr(self, address: Ipv4Addr) -> Self {
        self.your_ip_address(address)
    }

    /// Set the server IP address field.
    pub fn server_ip_address(mut self, address: Ipv4Addr) -> Self {
        self.server_ip_address.set_user(address);
        self
    }

    /// Compatibility alias for server IP address.
    pub fn siaddr(self, address: Ipv4Addr) -> Self {
        self.server_ip_address(address)
    }

    /// Set the gateway IP address field.
    pub fn gateway_ip_address(mut self, address: Ipv4Addr) -> Self {
        self.gateway_ip_address.set_user(address);
        self
    }

    /// Compatibility alias for gateway IP address.
    pub fn giaddr(self, address: Ipv4Addr) -> Self {
        self.gateway_ip_address(address)
    }

    /// Set the fixed client hardware address field.
    pub fn chaddr(mut self, address: impl AsRef<[u8]>) -> Self {
        let address = address.as_ref();
        self.client_hardware_address = address.to_vec();
        if !self.hardware_len.is_user_set() {
            self.hardware_len = Field::defaulted(address.len().min(DHCP_CHADDR_LEN) as u8);
        }
        self
    }

    /// Set the client Ethernet MAC address.
    pub fn client_mac(self, address: MacAddr) -> Self {
        self.chaddr(address.octets())
    }

    /// Set the server host name fixed field bytes.
    pub fn sname(mut self, server_name: impl AsRef<[u8]>) -> Self {
        self.server_name = server_name.as_ref().to_vec();
        self
    }

    /// Set the boot file name fixed field bytes.
    pub fn file(mut self, boot_file_name: impl AsRef<[u8]>) -> Self {
        self.boot_file_name = boot_file_name.as_ref().to_vec();
        self
    }

    /// Set the DHCP magic cookie explicitly.
    pub fn magic_cookie(mut self, magic_cookie: u32) -> Self {
        self.magic_cookie.set_user(magic_cookie);
        self
    }

    /// Append a DHCP option.
    pub fn option(mut self, option: DhcpOption) -> Self {
        self.options.push(option);
        self
    }

    /// Replace all DHCP options.
    pub fn options(mut self, options: impl Into<Vec<DhcpOption>>) -> Self {
        self.options = options.into();
        self
    }

    /// Remove all DHCP options.
    pub fn clear_options(mut self) -> Self {
        self.options.clear();
        self
    }

    /// Append a DHCP message type option.
    pub fn message_type(self, message_type: DhcpMessageType) -> Self {
        self.option(DhcpOption::message_type(message_type))
    }

    /// Append a requested IP address option.
    pub fn requested_ip_address(self, address: Ipv4Addr) -> Self {
        self.option(DhcpOption::requested_ip_address(address))
    }

    /// Append a server identifier option.
    pub fn server_identifier(self, address: Ipv4Addr) -> Self {
        self.option(DhcpOption::server_identifier(address))
    }

    /// Append a parameter request list option.
    pub fn parameter_request_list(self, requests: impl Into<Vec<u8>>) -> Self {
        self.option(DhcpOption::parameter_request_list(requests))
    }

    /// Append a host name option.
    pub fn host_name(self, host_name: impl Into<String>) -> Self {
        self.option(DhcpOption::host_name(host_name))
    }

    /// Alias for host name.
    pub fn hostname(self, host_name: impl Into<String>) -> Self {
        self.host_name(host_name)
    }

    /// Append a subnet mask option.
    pub fn subnet_mask(self, mask: Ipv4Addr) -> Self {
        self.option(DhcpOption::subnet_mask(mask))
    }

    /// Append a router option.
    pub fn router(self, routers: impl Into<Vec<Ipv4Addr>>) -> Self {
        self.option(DhcpOption::router(routers))
    }

    /// Append a DNS server option.
    pub fn domain_name_server(self, servers: impl Into<Vec<Ipv4Addr>>) -> Self {
        self.option(DhcpOption::domain_name_server(servers))
    }

    /// Append a lease time option.
    pub fn lease_time(self, seconds: u32) -> Self {
        self.option(DhcpOption::lease_time(seconds))
    }

    /// BOOTP opcode value.
    pub fn op_value(&self) -> u8 {
        value_or_copy(&self.op, BOOTP_REQUEST)
    }

    /// Hardware type value.
    pub fn hardware_type_value(&self) -> u8 {
        value_or_copy(&self.hardware_type, DHCP_HTYPE_ETHERNET)
    }

    /// Hardware address length value.
    pub fn hardware_len_value(&self) -> u8 {
        value_or_copy(
            &self.hardware_len,
            self.client_hardware_address.len().min(255) as u8,
        )
    }

    /// Relay-agent hops value.
    pub fn hops_value(&self) -> u8 {
        value_or_copy(&self.hops, 0)
    }

    /// Transaction ID value.
    pub fn transaction_id_value(&self) -> u32 {
        value_or_copy(&self.transaction_id, 0)
    }

    /// Elapsed seconds value.
    pub fn seconds_value(&self) -> u16 {
        value_or_copy(&self.seconds, 0)
    }

    /// Raw flags field value.
    pub fn flags_value(&self) -> u16 {
        value_or_copy(&self.flags, 0)
    }

    /// Client IP address field value.
    pub fn client_ip_address_value(&self) -> Ipv4Addr {
        value_or_copy(&self.client_ip_address, Ipv4Addr::UNSPECIFIED)
    }

    /// Your/client IP address field value.
    pub fn your_ip_address_value(&self) -> Ipv4Addr {
        value_or_copy(&self.your_ip_address, Ipv4Addr::UNSPECIFIED)
    }

    /// Server IP address field value.
    pub fn server_ip_address_value(&self) -> Ipv4Addr {
        value_or_copy(&self.server_ip_address, Ipv4Addr::UNSPECIFIED)
    }

    /// Gateway IP address field value.
    pub fn gateway_ip_address_value(&self) -> Ipv4Addr {
        value_or_copy(&self.gateway_ip_address, Ipv4Addr::UNSPECIFIED)
    }

    /// Client hardware address bytes according to the hardware length field.
    pub fn client_hardware_address_value(&self) -> &[u8] {
        let len = (self.hardware_len_value() as usize).min(self.client_hardware_address.len());
        &self.client_hardware_address[..len]
    }

    /// Client Ethernet MAC address, when the hardware address contains at least six bytes.
    pub fn client_mac_value(&self) -> Option<MacAddr> {
        let bytes = self.client_hardware_address_value();
        if bytes.len() < 6 {
            return None;
        }
        Some(MacAddr::new(
            <[u8; 6]>::try_from(&bytes[..6]).expect("slice length already checked"),
        ))
    }

    /// Raw fixed client hardware address field bytes.
    pub fn chaddr_bytes(&self) -> &[u8] {
        &self.client_hardware_address
    }

    /// Raw server name field bytes.
    pub fn sname_bytes(&self) -> &[u8] {
        trim_fixed_bytes(&self.server_name)
    }

    /// Raw boot file name field bytes.
    pub fn file_bytes(&self) -> &[u8] {
        trim_fixed_bytes(&self.boot_file_name)
    }

    /// Magic cookie value.
    pub fn magic_cookie_value(&self) -> u32 {
        value_or_copy(&self.magic_cookie, DHCP_MAGIC_COOKIE)
    }

    /// DHCP options.
    pub fn options_value(&self) -> &[DhcpOption] {
        &self.options
    }

    /// DHCP message type option, when present.
    pub fn message_type_value(&self) -> Option<DhcpMessageType> {
        self.options.iter().find_map(|option| match option {
            DhcpOption::MessageType(message_type) => Some(*message_type),
            _ => None,
        })
    }

    /// Offered IP address from `yiaddr`, when present.
    pub fn offered_ip_address(&self) -> Option<Ipv4Addr> {
        let address = self.your_ip_address_value();
        (address != Ipv4Addr::UNSPECIFIED).then_some(address)
    }

    /// Requested IP address option, when present.
    pub fn requested_ip_address_value(&self) -> Option<Ipv4Addr> {
        self.options.iter().find_map(|option| match option {
            DhcpOption::RequestedIpAddress(address) => Some(*address),
            _ => None,
        })
    }

    /// Server identifier option, when present.
    pub fn server_identifier_value(&self) -> Option<Ipv4Addr> {
        self.options.iter().find_map(|option| match option {
            DhcpOption::ServerIdentifier(address) => Some(*address),
            _ => None,
        })
    }

    /// Subnet mask option, when present.
    pub fn subnet_mask_value(&self) -> Option<Ipv4Addr> {
        self.options.iter().find_map(|option| match option {
            DhcpOption::SubnetMask(address) => Some(*address),
            _ => None,
        })
    }

    /// Router addresses from all router options.
    pub fn routers(&self) -> Vec<Ipv4Addr> {
        self.options
            .iter()
            .filter_map(|option| match option {
                DhcpOption::Router(addresses) => Some(addresses.as_slice()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect()
    }

    /// DNS server addresses from all DNS server options.
    pub fn domain_name_servers(&self) -> Vec<Ipv4Addr> {
        self.options
            .iter()
            .filter_map(|option| match option {
                DhcpOption::DomainNameServer(addresses) => Some(addresses.as_slice()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect()
    }

    /// Host name option, when present.
    pub fn host_name_value(&self) -> Option<&str> {
        self.options.iter().find_map(|option| match option {
            DhcpOption::HostName(host_name) => Some(host_name.as_str()),
            _ => None,
        })
    }

    /// Lease time option, when present.
    pub fn lease_time_value(&self) -> Option<u32> {
        self.options.iter().find_map(|option| match option {
            DhcpOption::IpAddressLeaseTime(seconds) => Some(*seconds),
            _ => None,
        })
    }

    /// Encode DHCP options, appending an end marker when needed.
    pub fn encoded_options(&self) -> Result<Vec<u8>> {
        encode_dhcp_options(&self.options)
    }

    fn validate(&self) -> Result<()> {
        if self.hardware_len_value() as usize > DHCP_CHADDR_LEN {
            return Err(CrafterError::invalid_field_value(
                "dhcp.hlen",
                "hardware address length must fit in the 16-byte chaddr field",
            ));
        }
        if self.client_hardware_address.len() > DHCP_CHADDR_LEN {
            return Err(CrafterError::invalid_field_value(
                "dhcp.chaddr",
                "client hardware address field must be at most 16 bytes",
            ));
        }
        if self.server_name.len() > DHCP_SNAME_LEN {
            return Err(CrafterError::invalid_field_value(
                "dhcp.sname",
                "server name field must be at most 64 bytes",
            ));
        }
        if self.boot_file_name.len() > DHCP_FILE_LEN {
            return Err(CrafterError::invalid_field_value(
                "dhcp.file",
                "boot file name field must be at most 128 bytes",
            ));
        }
        self.encoded_options()?;
        Ok(())
    }

    fn encoded_dhcp_len(&self) -> usize {
        DHCP_MIN_LEN + encoded_options_len_lossy(&self.options)
    }
}

impl Default for Dhcp {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Dhcp {
    fn name(&self) -> &'static str {
        "Dhcp"
    }

    fn summary(&self) -> String {
        format!(
            "Dhcp(type={}, xid=0x{:08x}, yiaddr={})",
            self.message_type_value()
                .map(message_type_summary)
                .unwrap_or_else(|| "unknown".to_string()),
            self.transaction_id_value(),
            self.your_ip_address_value(),
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("op", self.op_value().to_string()),
            ("htype", self.hardware_type_value().to_string()),
            ("hlen", self.hardware_len_value().to_string()),
            ("xid", format!("0x{:08x}", self.transaction_id_value())),
            ("flags", format!("0x{:04x}", self.flags_value())),
            ("ciaddr", self.client_ip_address_value().to_string()),
            ("yiaddr", self.your_ip_address_value().to_string()),
            ("siaddr", self.server_ip_address_value().to_string()),
            ("giaddr", self.gateway_ip_address_value().to_string()),
            ("chaddr", hex_bytes(self.client_hardware_address_value())),
            (
                "message_type",
                self.message_type_value()
                    .map(message_type_summary)
                    .unwrap_or_else(|| "none".to_string()),
            ),
            ("options", self.options.len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.encoded_dhcp_len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;

        out.reserve(self.encoded_dhcp_len());
        out.push(self.op_value());
        out.push(self.hardware_type_value());
        out.push(self.hardware_len_value());
        out.push(self.hops_value());
        out.extend_from_slice(&self.transaction_id_value().to_be_bytes());
        out.extend_from_slice(&self.seconds_value().to_be_bytes());
        out.extend_from_slice(&self.flags_value().to_be_bytes());
        out.extend_from_slice(&self.client_ip_address_value().octets());
        out.extend_from_slice(&self.your_ip_address_value().octets());
        out.extend_from_slice(&self.server_ip_address_value().octets());
        out.extend_from_slice(&self.gateway_ip_address_value().octets());
        append_fixed_field(out, &self.client_hardware_address, DHCP_CHADDR_LEN);
        append_fixed_field(out, &self.server_name, DHCP_SNAME_LEN);
        append_fixed_field(out, &self.boot_file_name, DHCP_FILE_LEN);
        out.extend_from_slice(&self.magic_cookie_value().to_be_bytes());
        out.extend_from_slice(&self.encoded_options()?);
        Ok(())
    }

    impl_layer_object!(Dhcp);
}

impl_layer_div!(Dhcp);

/// Append a decoded DHCP message to an existing packet stack.
pub(crate) fn append_dhcp_packet(packet: Packet, bytes: &[u8]) -> Result<Packet> {
    Ok(packet.push(decode_dhcp(bytes)?))
}

/// Return true when bytes have enough structure to decode as DHCP.
pub(crate) fn looks_like_dhcp_payload(bytes: &[u8]) -> bool {
    bytes.len() >= DHCP_MIN_LEN
        && bytes[DHCP_FIXED_HEADER_LEN..DHCP_MIN_LEN] == DHCP_MAGIC_COOKIE.to_be_bytes()
}

/// Return true when the UDP source/destination pair is a DHCP client/server pair.
pub(crate) const fn is_dhcp_port_pair(source_port: u16, destination_port: u16) -> bool {
    matches!(source_port, DHCP_CLIENT_PORT | DHCP_SERVER_PORT)
        && matches!(destination_port, DHCP_CLIENT_PORT | DHCP_SERVER_PORT)
}

fn decode_dhcp(bytes: &[u8]) -> Result<Dhcp> {
    if bytes.len() < DHCP_MIN_LEN {
        return Err(CrafterError::buffer_too_short(
            "dhcp packet",
            DHCP_MIN_LEN,
            bytes.len(),
        ));
    }

    let hardware_len = bytes[2];
    if hardware_len as usize > DHCP_CHADDR_LEN {
        return Err(CrafterError::invalid_field_value(
            "dhcp.hlen",
            "hardware address length must fit in the 16-byte chaddr field",
        ));
    }

    let magic_cookie = read_u32_be(&bytes[DHCP_FIXED_HEADER_LEN..DHCP_MIN_LEN])?;
    if magic_cookie != DHCP_MAGIC_COOKIE {
        return Err(CrafterError::invalid_field_value(
            "dhcp.magic_cookie",
            "DHCP magic cookie is missing or invalid",
        ));
    }

    Ok(Dhcp {
        op: Field::user(bytes[0]),
        hardware_type: Field::user(bytes[1]),
        hardware_len: Field::user(hardware_len),
        hops: Field::user(bytes[3]),
        transaction_id: Field::user(read_u32_be(&bytes[4..8])?),
        seconds: Field::user(read_u16_be(&bytes[8..10])?),
        flags: Field::user(read_u16_be(&bytes[10..12])?),
        client_ip_address: Field::user(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
        your_ip_address: Field::user(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
        server_ip_address: Field::user(Ipv4Addr::new(bytes[20], bytes[21], bytes[22], bytes[23])),
        gateway_ip_address: Field::user(Ipv4Addr::new(bytes[24], bytes[25], bytes[26], bytes[27])),
        client_hardware_address: bytes[28..44].to_vec(),
        server_name: bytes[44..108].to_vec(),
        boot_file_name: bytes[108..236].to_vec(),
        magic_cookie: Field::user(magic_cookie),
        options: decode_dhcp_options(&bytes[DHCP_MIN_LEN..])?,
    })
}

fn decode_dhcp_options(bytes: &[u8]) -> Result<Vec<DhcpOption>> {
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

fn encode_dhcp_options(options: &[DhcpOption]) -> Result<Vec<u8>> {
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

fn encoded_options_len_lossy(options: &[DhcpOption]) -> usize {
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

fn append_fixed_field(out: &mut Vec<u8>, bytes: &[u8], len: usize) {
    let copy_len = bytes.len().min(len);
    out.extend_from_slice(&bytes[..copy_len]);
    out.resize(out.len() + (len - copy_len), 0);
}

fn trim_fixed_bytes(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|byte| *byte == 0) {
        Some(index) => &bytes[..index],
        None => bytes,
    }
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn message_type_summary(message_type: DhcpMessageType) -> String {
    match message_type {
        DhcpMessageType::Discover => "discover".to_string(),
        DhcpMessageType::Offer => "offer".to_string(),
        DhcpMessageType::Request => "request".to_string(),
        DhcpMessageType::Decline => "decline".to_string(),
        DhcpMessageType::Ack => "ack".to_string(),
        DhcpMessageType::Nak => "nak".to_string(),
        DhcpMessageType::Release => "release".to_string(),
        DhcpMessageType::Inform => "inform".to_string(),
        DhcpMessageType::Unknown(value) => format!("unknown({value})"),
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

#[cfg(test)]
mod dhcp_tests {
    use super::{
        Dhcp, DhcpMessageType, BOOTP_REPLY, DHCP_CLIENT_PORT, DHCP_MAGIC_COOKIE, DHCP_SERVER_PORT,
    };
    use crate::{Ipv4, MacAddr, NetworkLayer, Packet, Udp};
    use core::net::Ipv4Addr;

    fn mac() -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01])
    }

    #[test]
    fn discover_encodes_and_decodes_over_udp() {
        let bytes = (Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
            .id(0x4444)
            / Udp::dhcp_client()
            / Dhcp::discover(mac())
                .xid(0x3903_f326)
                .flags(0x8000)
                .hostname("agent"))
        .compile()
        .unwrap();

        assert_eq!(&bytes.as_bytes()[20..22], &DHCP_CLIENT_PORT.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[22..24], &DHCP_SERVER_PORT.to_be_bytes());
        let dhcp_start = 20 + 8;
        assert_eq!(
            &bytes.as_bytes()[dhcp_start + 236..dhcp_start + 240],
            &DHCP_MAGIC_COOKIE.to_be_bytes()
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let dhcp = decoded.layer::<Dhcp>().unwrap();

        assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Discover));
        assert_eq!(dhcp.client_mac_value(), Some(mac()));
        assert_eq!(dhcp.transaction_id_value(), 0x3903_f326);
        assert_eq!(dhcp.host_name_value(), Some("agent"));
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn response_helpers_extract_common_offer_fields() {
        let offered = Ipv4Addr::new(192, 0, 2, 42);
        let server = Ipv4Addr::new(192, 0, 2, 1);
        let router = Ipv4Addr::new(192, 0, 2, 254);
        let dns = Ipv4Addr::new(198, 51, 100, 53);

        let bytes = (Ipv4::new().src(server).dst(Ipv4Addr::BROADCAST)
            / Udp::dhcp_server()
            / Dhcp::offer(mac(), offered, server)
                .subnet_mask(Ipv4Addr::new(255, 255, 255, 0))
                .router([router])
                .domain_name_server([dns])
                .lease_time(3600))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let dhcp = decoded.layer::<Dhcp>().unwrap();

        assert_eq!(dhcp.op_value(), BOOTP_REPLY);
        assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Offer));
        assert_eq!(dhcp.offered_ip_address(), Some(offered));
        assert_eq!(dhcp.server_identifier_value(), Some(server));
        assert_eq!(
            dhcp.subnet_mask_value(),
            Some(Ipv4Addr::new(255, 255, 255, 0))
        );
        assert_eq!(dhcp.routers(), vec![router]);
        assert_eq!(dhcp.domain_name_servers(), vec![dns]);
        assert_eq!(dhcp.lease_time_value(), Some(3600));
    }

    #[test]
    fn request_builder_sets_requested_ip_and_server_identifier() {
        let requested = Ipv4Addr::new(192, 0, 2, 42);
        let server = Ipv4Addr::new(192, 0, 2, 1);
        let dhcp = Dhcp::request(mac(), requested, server).xid(7);

        assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Request));
        assert_eq!(dhcp.requested_ip_address_value(), Some(requested));
        assert_eq!(dhcp.server_identifier_value(), Some(server));
        assert_eq!(dhcp.transaction_id_value(), 7);
    }
}

#[cfg(test)]
mod dhcp_options {
    use super::{Dhcp, DhcpMessageType, DhcpOption};
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

#[cfg(test)]
mod dhcp_malformed {
    use super::{
        Dhcp, DhcpOption, DHCP_FIXED_HEADER_LEN, DHCP_MAGIC_COOKIE, DHCP_MIN_LEN, DHCP_OPTION_END,
        DHCP_OPTION_MESSAGE_TYPE,
    };
    use crate::{Ipv4, NetworkLayer, Packet, Raw, Udp};
    use core::net::Ipv4Addr;

    fn valid_minimal_payload(options: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; DHCP_MIN_LEN];
        bytes[0] = super::BOOTP_REQUEST;
        bytes[1] = super::DHCP_HTYPE_ETHERNET;
        bytes[2] = 6;
        bytes[DHCP_FIXED_HEADER_LEN..DHCP_MIN_LEN]
            .copy_from_slice(&DHCP_MAGIC_COOKIE.to_be_bytes());
        bytes.extend_from_slice(options);
        bytes
    }

    #[test]
    fn malformed_option_lengths_are_rejected() {
        let payload = valid_minimal_payload(&[DHCP_OPTION_MESSAGE_TYPE, 2, 1, DHCP_OPTION_END]);

        assert!(Dhcp::decode(&payload).is_err());
    }

    #[test]
    fn missing_end_marker_is_rejected() {
        let payload = valid_minimal_payload(&[DHCP_OPTION_MESSAGE_TYPE, 1, 1]);

        assert!(Dhcp::decode(&payload).is_err());
    }

    #[test]
    fn non_padding_after_end_is_rejected() {
        let payload = valid_minimal_payload(&[DHCP_OPTION_END, 1]);

        assert!(Dhcp::decode(&payload).is_err());
    }

    #[test]
    fn non_dhcp_udp_on_dhcp_ports_stays_raw() {
        let bytes = (Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
            / Udp::dhcp_client()
            / Raw::from("not a dhcp packet"))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();

        assert!(decoded.layer::<Dhcp>().is_none());
        assert_eq!(
            decoded.layer::<Raw>().unwrap().as_bytes(),
            b"not a dhcp packet"
        );
    }

    #[test]
    fn invalid_builder_lengths_are_rejected() {
        assert!(Packet::from_layer(Dhcp::new().hlen(17)).compile().is_err());
        assert!(Packet::from_layer(Dhcp::new().chaddr([0u8; 17]))
            .compile()
            .is_err());
        assert!(DhcpOption::generic(super::DHCP_OPTION_PAD, [])
            .encode()
            .is_err());
    }
}
