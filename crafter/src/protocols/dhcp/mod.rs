//! Dynamic Host Configuration Protocol implementation.

mod constants;
mod malformed;
mod message;
mod option;
mod registry;

use core::any::Any;
use core::net::Ipv4Addr;
use core::ops::Div;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::mac::MacAddr;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

pub use constants::{
    BOOTP_REPLY, BOOTP_REQUEST, DHCP_ACK, DHCP_CLIENT_PORT, DHCP_DECLINE, DHCP_DISCOVER,
    DHCP_FIXED_HEADER_LEN, DHCP_HTYPE_ETHERNET, DHCP_INFORM, DHCP_MAGIC_COOKIE,
    DHCP_MAGIC_COOKIE_LEN, DHCP_MIN_LEN, DHCP_NAK, DHCP_OFFER, DHCP_OPTION_BROADCAST_ADDRESS,
    DHCP_OPTION_CLIENT_IDENTIFIER, DHCP_OPTION_DOMAIN_NAME, DHCP_OPTION_DOMAIN_NAME_SERVER,
    DHCP_OPTION_END, DHCP_OPTION_HOST_NAME, DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
    DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_PAD, DHCP_OPTION_PARAMETER_REQUEST_LIST,
    DHCP_OPTION_REBINDING_TIME, DHCP_OPTION_RENEWAL_TIME, DHCP_OPTION_REQUESTED_IP_ADDRESS,
    DHCP_OPTION_ROUTER, DHCP_OPTION_SERVER_IDENTIFIER, DHCP_OPTION_SUBNET_MASK, DHCP_RELEASE,
    DHCP_REQUEST, DHCP_SERVER_PORT,
};
pub use malformed::DhcpMalformed;
pub use message::DhcpMessageType;
pub use option::{
    scan_dhcp_option_segments, DhcpOption, DhcpOptionArea, DhcpOptionCode, DhcpOptionSegment,
    DhcpOptionValue,
};
pub use registry::{
    option_meta, option_name, option_status, DhcpOptionMeta, DhcpOptionStatus,
    DHCP_OPTION_PRIVATE_USE_END, DHCP_OPTION_PRIVATE_USE_START,
};

use constants::{DHCP_CHADDR_LEN, DHCP_DEFAULT_PARAMETER_REQUESTS, DHCP_FILE_LEN, DHCP_SNAME_LEN};
use message::message_type_summary;
use option::{encode_dhcp_options, encoded_options_len_lossy};

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

    /// Begin building an intentionally malformed DHCP packet from this one.
    ///
    /// The returned [`DhcpMalformed`] builder emits raw bytes and skips the
    /// structural validation [`Dhcp::compile`] enforces, so it can craft
    /// invalid packets (bad magic cookie, oversized fields, malformed option
    /// lengths, missing end markers) on purpose. The typed `Dhcp` builder stays
    /// valid by default; malformation is opt-in only through this surface.
    pub fn malformed(self) -> DhcpMalformed {
        DhcpMalformed::from_valid(self)
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

    /// Full stored client hardware address fixed-field bytes.
    ///
    /// This is the raw `chaddr` field as stored: on decode it is the full
    /// 16-octet BOOTP field (RFC 2131 section 2); on a builder it is whatever
    /// the caller supplied. Use [`Dhcp::client_hardware_address_value`] for the
    /// `hlen`-bounded logical address.
    pub fn chaddr_bytes(&self) -> &[u8] {
        &self.client_hardware_address
    }

    /// Full stored server name fixed-field bytes, before any trimming.
    ///
    /// On decode this is the complete 64-octet `sname` field (RFC 2131 section
    /// 2), including trailing NUL padding; on a builder it is the bytes the
    /// caller supplied. Use [`Dhcp::sname_bytes`] for the trimmed string-like
    /// view.
    pub fn sname_raw(&self) -> &[u8] {
        &self.server_name
    }

    /// Full stored boot file name fixed-field bytes, before any trimming.
    ///
    /// On decode this is the complete 128-octet `file` field (RFC 2131 section
    /// 2), including trailing NUL padding; on a builder it is the bytes the
    /// caller supplied. Use [`Dhcp::file_bytes`] for the trimmed string-like
    /// view.
    pub fn file_raw(&self) -> &[u8] {
        &self.boot_file_name
    }

    /// Server name field as a trimmed string-like view (bytes up to the first
    /// NUL).
    ///
    /// Use [`Dhcp::sname_raw`] for the untrimmed fixed-field bytes.
    pub fn sname_bytes(&self) -> &[u8] {
        trim_fixed_bytes(&self.server_name)
    }

    /// Boot file name field as a trimmed string-like view (bytes up to the
    /// first NUL).
    ///
    /// Use [`Dhcp::file_raw`] for the untrimmed fixed-field bytes.
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
        options: DhcpOption::decode_all(&bytes[DHCP_MIN_LEN..])?,
    })
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

#[cfg(test)]
mod dhcp_fixed_header {
    use super::{
        Dhcp, DhcpMalformed, DhcpMessageType, BOOTP_REPLY, DHCP_FIXED_HEADER_LEN,
        DHCP_MAGIC_COOKIE, DHCP_MIN_LEN, DHCP_OPTION_MESSAGE_TYPE,
    };
    use crate::error::CrafterError;
    use crate::{MacAddr, Packet};
    use core::net::Ipv4Addr;

    fn mac() -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x02])
    }

    #[test]
    fn dhcp_fixed_header_roundtrips_exact_bytes() {
        // Build a packet that exercises every fixed BOOTP field (RFC 2131
        // section 2) with deliberately odd-but-valid values, then prove the
        // exact wire bytes survive compile -> decode -> compile unchanged and
        // that each typed accessor reports the value that was set.
        let chaddr = [0x02u8, 0x00, 0x5e, 0x10, 0x00, 0x02];
        let dhcp = Dhcp::new()
            .op(BOOTP_REPLY)
            .htype(6)
            .hlen(6)
            .hops(3)
            .xid(0x1234_5678)
            .secs(0x0102)
            .flags(0x8000)
            .ciaddr(Ipv4Addr::new(192, 0, 2, 10))
            .yiaddr(Ipv4Addr::new(192, 0, 2, 20))
            .siaddr(Ipv4Addr::new(192, 0, 2, 30))
            .giaddr(Ipv4Addr::new(192, 0, 2, 40))
            .chaddr(chaddr)
            .sname("boot-server")
            .file("pxelinux.0")
            .message_type(DhcpMessageType::Ack);

        let compiled = Packet::from_layer(dhcp.clone()).compile().unwrap();
        let bytes = compiled.as_bytes();

        // The fixed header occupies the first 236 bytes; the magic cookie
        // immediately follows it.
        assert_eq!(bytes[0], BOOTP_REPLY);
        assert_eq!(bytes[1], 6);
        assert_eq!(bytes[2], 6);
        assert_eq!(bytes[3], 3);
        assert_eq!(&bytes[4..8], &0x1234_5678u32.to_be_bytes());
        assert_eq!(&bytes[8..10], &0x0102u16.to_be_bytes());
        assert_eq!(&bytes[10..12], &0x8000u16.to_be_bytes());
        assert_eq!(&bytes[12..16], &Ipv4Addr::new(192, 0, 2, 10).octets());
        assert_eq!(&bytes[16..20], &Ipv4Addr::new(192, 0, 2, 20).octets());
        assert_eq!(&bytes[20..24], &Ipv4Addr::new(192, 0, 2, 30).octets());
        assert_eq!(&bytes[24..28], &Ipv4Addr::new(192, 0, 2, 40).octets());
        assert_eq!(&bytes[28..34], &chaddr);
        // chaddr is zero-padded to its 16-octet fixed width.
        assert_eq!(&bytes[34..44], &[0u8; 10]);
        assert_eq!(&bytes[44..55], b"boot-server");
        assert_eq!(&bytes[108..118], b"pxelinux.0");
        assert_eq!(
            &bytes[DHCP_FIXED_HEADER_LEN..DHCP_MIN_LEN],
            &DHCP_MAGIC_COOKIE.to_be_bytes()
        );

        // Decode and re-compile: the wire bytes must be reproduced exactly.
        let parsed = Dhcp::decode(bytes).unwrap();
        assert_eq!(parsed.op_value(), BOOTP_REPLY);
        assert_eq!(parsed.hardware_type_value(), 6);
        assert_eq!(parsed.hardware_len_value(), 6);
        assert_eq!(parsed.hops_value(), 3);
        assert_eq!(parsed.transaction_id_value(), 0x1234_5678);
        assert_eq!(parsed.seconds_value(), 0x0102);
        assert_eq!(parsed.flags_value(), 0x8000);
        assert_eq!(
            parsed.client_ip_address_value(),
            Ipv4Addr::new(192, 0, 2, 10)
        );
        assert_eq!(parsed.your_ip_address_value(), Ipv4Addr::new(192, 0, 2, 20));
        assert_eq!(
            parsed.server_ip_address_value(),
            Ipv4Addr::new(192, 0, 2, 30)
        );
        assert_eq!(
            parsed.gateway_ip_address_value(),
            Ipv4Addr::new(192, 0, 2, 40)
        );

        // Raw fixed-field accessors expose the full padded field bytes; the
        // trimmed string-like views stop at the first NUL.
        assert_eq!(parsed.sname_raw().len(), 64);
        assert_eq!(parsed.file_raw().len(), 128);
        assert_eq!(parsed.sname_bytes(), b"boot-server");
        assert_eq!(parsed.file_bytes(), b"pxelinux.0");
        assert_eq!(parsed.client_mac_value(), Some(mac()));

        let recompiled = Packet::from_layer(parsed).compile().unwrap();
        assert_eq!(recompiled.as_bytes(), bytes);
    }

    #[test]
    fn explicit_fixed_field_overrides_survive_compile() {
        // Values the caller set explicitly must survive compile untouched, even
        // when they are unusual: a BOOTP reply opcode on a request-style packet,
        // a non-Ethernet hardware type, and a zero hlen with a populated chaddr.
        let dhcp = Dhcp::new()
            .op(0x42)
            .htype(0xfe)
            .hlen(0)
            .chaddr([0xaa, 0xbb, 0xcc])
            .message_type(DhcpMessageType::Discover);

        let bytes = Packet::from_layer(dhcp).compile().unwrap();
        let parsed = Dhcp::decode(bytes.as_bytes()).unwrap();

        assert_eq!(parsed.op_value(), 0x42);
        assert_eq!(parsed.hardware_type_value(), 0xfe);
        assert_eq!(parsed.hardware_len_value(), 0);
        // The full chaddr field is preserved even though hlen is zero.
        assert_eq!(&parsed.chaddr_bytes()[..3], &[0xaa, 0xbb, 0xcc]);
        // The hlen-bounded logical address is empty when hlen is zero.
        assert_eq!(parsed.client_hardware_address_value(), &[] as &[u8]);
    }

    #[test]
    fn hardware_length_validation_stays_structured() {
        // An hlen beyond the 16-octet chaddr field is a structured field error,
        // not a panic, on both compile and decode.
        let error = Packet::from_layer(Dhcp::new().hlen(17))
            .compile()
            .unwrap_err();
        assert!(matches!(
            error,
            CrafterError::InvalidFieldValue { field, .. } if field == "dhcp.hlen"
        ));

        let mut bytes = vec![0u8; DHCP_MIN_LEN];
        bytes[2] = 17;
        bytes[DHCP_FIXED_HEADER_LEN..DHCP_MIN_LEN]
            .copy_from_slice(&DHCP_MAGIC_COOKIE.to_be_bytes());
        let decode_error = Dhcp::decode(&bytes).unwrap_err();
        assert!(matches!(
            decode_error,
            CrafterError::InvalidFieldValue { field, .. } if field == "dhcp.hlen"
        ));
    }

    #[test]
    fn dhcp_malformed_builder_can_emit_invalid_magic_cookie() {
        // The normal builder is valid by default and decodes cleanly.
        let valid = Dhcp::new()
            .client_mac(mac())
            .message_type(DhcpMessageType::Discover);
        let valid_bytes = Packet::from_layer(valid.clone()).compile().unwrap();
        assert!(Dhcp::decode(valid_bytes.as_bytes()).is_ok());

        // The visibly-named malformed builder overrides the magic cookie with a
        // value RFC 2131 forbids. Construction is opt-in and emits the bad
        // bytes verbatim.
        let bogus_cookie = 0xdead_beef;
        let malformed = valid.clone().malformed().invalid_magic_cookie(bogus_cookie);
        let bytes = malformed.to_bytes();

        // The cookie is written at the documented offset and is the bad value.
        assert_eq!(
            &bytes[DHCP_FIXED_HEADER_LEN..DHCP_MIN_LEN],
            &bogus_cookie.to_be_bytes()
        );

        // The normal decoder rejects it as a structured magic-cookie error and
        // never panics.
        let error = Dhcp::decode(&bytes).unwrap_err();
        assert!(matches!(
            error,
            CrafterError::InvalidFieldValue { field, .. } if field == "dhcp.magic_cookie"
        ));

        // The malformed builder also composes as a layer through `/`.
        let layered = DhcpMalformed::from_valid(valid)
            .invalid_magic_cookie(bogus_cookie)
            .to_bytes();
        assert_eq!(layered, bytes);
    }

    #[test]
    fn dhcp_malformed_builder_emits_structural_violations() {
        let base = Dhcp::new().message_type(DhcpMessageType::Discover);

        // Oversized option payload: the length byte cannot describe more than
        // 255 octets, so the segment is unrecoverable and decode fails.
        let oversized = base
            .clone()
            .malformed()
            .oversized_option_payload(DHCP_OPTION_MESSAGE_TYPE, vec![0u8; 300])
            .to_bytes();
        assert!(Dhcp::decode(&oversized).is_err());

        // Malformed option length: a declared length that overruns the data.
        let bad_len = base
            .clone()
            .malformed()
            .option_with_declared_len(DHCP_OPTION_MESSAGE_TYPE, 5, [0x01])
            .to_bytes();
        assert!(Dhcp::decode(&bad_len).is_err());

        // Missing end marker.
        let no_end = base
            .clone()
            .malformed()
            .raw_options([DHCP_OPTION_MESSAGE_TYPE, 1, 1])
            .to_bytes();
        let no_end_error = Dhcp::decode(&no_end).unwrap_err();
        assert!(matches!(
            no_end_error,
            CrafterError::InvalidFieldValue { field, .. } if field == "dhcp.options"
        ));

        // Non-padding bytes after the end marker.
        let trailing = base
            .clone()
            .malformed()
            .trailing_after_end([DHCP_OPTION_MESSAGE_TYPE, 1, 1])
            .to_bytes();
        let trailing_error = Dhcp::decode(&trailing).unwrap_err();
        assert!(matches!(
            trailing_error,
            CrafterError::InvalidFieldValue { field, .. } if field == "dhcp.option.end"
        ));

        // Oversized fixed field: a chaddr longer than the 16-octet field is
        // only reachable through the raw malformed hook, never the typed
        // builder.
        let oversized_chaddr = base.malformed().raw_chaddr(vec![0xffu8; 20]).to_bytes();
        // The packet is longer than a minimal DHCP packet because the field
        // overflowed, and the raw bytes are preserved verbatim.
        assert!(oversized_chaddr.len() > DHCP_MIN_LEN);
        assert_eq!(&oversized_chaddr[28..48], &[0xffu8; 20]);
    }
}
