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
    DHCP_MAGIC_COOKIE_LEN, DHCP_MIN_LEN, DHCP_NAK, DHCP_OFFER, DHCP_OPTION_6RD,
    DHCP_OPTION_BCMCS_DOMAIN_LIST, DHCP_OPTION_BCMCS_IPV4_LIST, DHCP_OPTION_BOOTFILE_NAME,
    DHCP_OPTION_BROADCAST_ADDRESS, DHCP_OPTION_CLASSLESS_STATIC_ROUTE,
    DHCP_OPTION_CLIENT_IDENTIFIER, DHCP_OPTION_CLIENT_MACHINE_IDENTIFIER, DHCP_OPTION_CLIENT_NDI,
    DHCP_OPTION_CLIENT_SYSTEM_ARCHITECTURE, DHCP_OPTION_DOMAIN_NAME,
    DHCP_OPTION_DOMAIN_NAME_SERVER, DHCP_OPTION_DOMAIN_SEARCH, DHCP_OPTION_END,
    DHCP_OPTION_GEOCONF, DHCP_OPTION_GEOCONF_CIVIC, DHCP_OPTION_GEOLOC, DHCP_OPTION_HOST_NAME,
    DHCP_OPTION_IP_ADDRESS_LEASE_TIME, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MUD_URL_V4,
    DHCP_OPTION_NAME_SERVICE_SEARCH, DHCP_OPTION_OVERLOAD, DHCP_OPTION_PAD,
    DHCP_OPTION_PARAMETER_REQUEST_LIST, DHCP_OPTION_PCODE, DHCP_OPTION_PXELINUX_CONFIGFILE,
    DHCP_OPTION_PXELINUX_MAGIC, DHCP_OPTION_PXELINUX_PATHPREFIX, DHCP_OPTION_PXELINUX_REBOOTTIME,
    DHCP_OPTION_RDNSS_SELECTION, DHCP_OPTION_REBINDING_TIME, DHCP_OPTION_RENEWAL_TIME,
    DHCP_OPTION_REQUESTED_IP_ADDRESS, DHCP_OPTION_ROUTER, DHCP_OPTION_SERVER_IDENTIFIER,
    DHCP_OPTION_SIP_SERVERS, DHCP_OPTION_SIP_UA_CONFIG_DOMAINS, DHCP_OPTION_STATIC_ROUTE,
    DHCP_OPTION_SUBNET_MASK, DHCP_OPTION_TCODE, DHCP_OPTION_TFTP_SERVER_ADDRESS,
    DHCP_OPTION_TFTP_SERVER_NAME, DHCP_OPTION_USER_CLASS, DHCP_OPTION_V4_DNR,
    DHCP_OPTION_V4_DOTS_ADDRESS, DHCP_OPTION_V4_DOTS_RI, DHCP_OPTION_V4_PCP_SERVER,
    DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, DHCP_OPTION_VENDOR_SPECIFIC, DHCP_OPTION_VI_VENDOR_CLASS,
    DHCP_OPTION_VI_VENDOR_SPECIFIC, DHCP_OVERLOAD_BOTH, DHCP_OVERLOAD_FILE, DHCP_OVERLOAD_SNAME,
    DHCP_RELEASE, DHCP_REQUEST, DHCP_SERVER_PORT,
};
pub use malformed::DhcpMalformed;
pub use message::DhcpMessageType;
pub use option::{
    decode_tftp_server_addresses, scan_dhcp_option_segments, typed_option_value,
    ClientNetworkDeviceInterface, ClientSystemArchitecture, DhcpClasslessRoute, DhcpClientUuid,
    DhcpOption, DhcpOptionArea, DhcpOptionCode, DhcpOptionFormat, DhcpOptionKind,
    DhcpOptionSegment, DhcpOptionValue, DhcpStaticRoute, DhcpUserClass, DhcpVendorClassData,
    DhcpVendorIdentifyingOption, DhcpVendorSuboption, OptionOverload, SipServers,
};
pub use registry::{
    option_meta, option_name, option_status, DhcpOptionMeta, DhcpOptionStatus,
    DHCP_OPTION_PRIVATE_USE_END, DHCP_OPTION_PRIVATE_USE_START,
};

use constants::{DHCP_CHADDR_LEN, DHCP_DEFAULT_PARAMETER_REQUESTS, DHCP_FILE_LEN, DHCP_SNAME_LEN};
use message::message_type_summary;
use option::{
    decode_dhcp_option, decode_overload_area_options, encode_dhcp_options,
    encode_overload_area_options, encoded_options_len_lossy, find_option_overload,
};

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
    /// Options carried in the overloaded `file` field (RFC 2132 section 9.3).
    file_options: Vec<DhcpOption>,
    /// Options carried in the overloaded `sname` field (RFC 2132 section 9.3).
    sname_options: Vec<DhcpOption>,
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
            file_options: Vec::new(),
            sname_options: Vec::new(),
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

    /// Append a DHCP option to the overloaded `file` field area.
    ///
    /// Placing any option in the `file` area overloads it (RFC 2132 section
    /// 9.3); [`Dhcp::compile`] adds the matching option-overload option (52) to
    /// the normal options area when the caller did not set one explicitly. The
    /// `file` fixed field can no longer be used as a boot file name string while
    /// it carries options.
    pub fn file_option(mut self, option: DhcpOption) -> Self {
        self.file_options.push(option);
        self
    }

    /// Replace all options in the overloaded `file` field area.
    pub fn file_options(mut self, options: impl Into<Vec<DhcpOption>>) -> Self {
        self.file_options = options.into();
        self
    }

    /// Append a DHCP option to the overloaded `sname` field area.
    ///
    /// Placing any option in the `sname` area overloads it (RFC 2132 section
    /// 9.3); [`Dhcp::compile`] adds the matching option-overload option (52) to
    /// the normal options area when the caller did not set one explicitly. The
    /// `sname` fixed field can no longer be used as a server host name string
    /// while it carries options.
    pub fn sname_option(mut self, option: DhcpOption) -> Self {
        self.sname_options.push(option);
        self
    }

    /// Replace all options in the overloaded `sname` field area.
    pub fn sname_options(mut self, options: impl Into<Vec<DhcpOption>>) -> Self {
        self.sname_options = options.into();
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

    /// DHCP options in the normal options area.
    pub fn options_value(&self) -> &[DhcpOption] {
        &self.options
    }

    /// Options carried in the overloaded `file` field, when any (RFC 2132
    /// section 9.3).
    pub fn file_options_value(&self) -> &[DhcpOption] {
        &self.file_options
    }

    /// Options carried in the overloaded `sname` field, when any (RFC 2132
    /// section 9.3).
    pub fn sname_options_value(&self) -> &[DhcpOption] {
        &self.sname_options
    }

    /// Reassemble the logical value of an option that may be split across areas.
    ///
    /// RFC 3396 section 5 defines the aggregate option buffer as the normal
    /// options field, then the overloaded `file` field, then the overloaded
    /// `sname` field, in that order. Within each area the per-area decoder has
    /// already concatenated repeated instances of a code; this accessor joins
    /// those per-area payloads across the three areas in aggregate order and
    /// decodes the result once, so an option split across area boundaries is
    /// surfaced as a single logical option. Returns `None` when no area carries
    /// the code. The per-area raw options remain inspectable through
    /// [`Dhcp::options_value`], [`Dhcp::file_options_value`], and
    /// [`Dhcp::sname_options_value`].
    pub fn concatenated_option(&self, code: u8) -> Option<Result<DhcpOption>> {
        let mut payload: Option<Vec<u8>> = None;
        // Aggregate order: options field, then file field, then sname field.
        for area in [&self.options, &self.file_options, &self.sname_options] {
            for option in area {
                if option.code() != code {
                    continue;
                }
                match option.payload() {
                    Ok(bytes) => payload
                        .get_or_insert_with(Vec::new)
                        .extend_from_slice(&bytes),
                    Err(error) => return Some(Err(error)),
                }
            }
        }
        payload.map(|bytes| decode_dhcp_option(code, &bytes))
    }

    /// Resolve which fixed fields are overloaded with options (RFC 2132 section
    /// 9.3).
    ///
    /// When the caller placed options in the `file` or `sname` areas, that is
    /// reflected here even before [`Dhcp::compile`] inserts the matching option
    /// 52. An explicit option 52 in the normal options area is honored when no
    /// area options were placed, so a decoded packet reports the overload value
    /// from the wire.
    pub fn option_overload(&self) -> Option<OptionOverload> {
        match (self.file_options.is_empty(), self.sname_options.is_empty()) {
            (false, false) => Some(OptionOverload::Both),
            (false, true) => Some(OptionOverload::File),
            (true, false) => Some(OptionOverload::Sname),
            (true, true) => find_option_overload(&self.options),
        }
    }

    /// True when the `file` field is overloaded with options.
    pub fn file_is_overloaded(&self) -> bool {
        self.option_overload()
            .is_some_and(OptionOverload::overloads_file)
    }

    /// True when the `sname` field is overloaded with options.
    pub fn sname_is_overloaded(&self) -> bool {
        self.option_overload()
            .is_some_and(OptionOverload::overloads_sname)
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

    /// RFC 2132 static routes (option 33), concatenated across areas.
    ///
    /// Source: RFC 2132 section 5.8. Reassembles the logical option payload from
    /// the normal, `file`, and `sname` areas (RFC 3396), then decodes it into
    /// typed destination/router pairs. Returns `None` when no area carries the
    /// option; a malformed payload surfaces as a structured error.
    pub fn static_routes(&self) -> Option<Result<Vec<DhcpStaticRoute>>> {
        self.typed_value_in_areas(DHCP_OPTION_STATIC_ROUTE)
            .map(|result| {
                result.map(|value| match value {
                    DhcpOptionValue::StaticRoutes(routes) => routes,
                    _ => Vec::new(),
                })
            })
    }

    /// RFC 3442 classless static routes (option 121), concatenated across areas.
    ///
    /// Source: RFC 3442. Reassembles the logical option payload (RFC 3396) and
    /// decodes it into typed prefix/destination/router routes. Returns `None`
    /// when no area carries the option; an invalid prefix length or truncated
    /// route surfaces as a structured error.
    pub fn classless_static_routes(&self) -> Option<Result<Vec<DhcpClasslessRoute>>> {
        self.typed_value_in_areas(DHCP_OPTION_CLASSLESS_STATIC_ROUTE)
            .map(|result| {
                result.map(|value| match value {
                    DhcpOptionValue::ClasslessRoutes(routes) => routes,
                    _ => Vec::new(),
                })
            })
    }

    /// RFC 3397 domain-search list (option 119), concatenated across areas.
    ///
    /// Source: RFC 3397 / RFC 1035. Reassembles the logical option payload
    /// (RFC 3396) and decodes the RFC 1035 label encoding, resolving compression
    /// pointers within the aggregate data, into fully-qualified domain names.
    /// Returns `None` when no area carries the option; a malformed encoding
    /// surfaces as a structured error.
    pub fn domain_search(&self) -> Option<Result<Vec<String>>> {
        self.typed_value_in_areas(DHCP_OPTION_DOMAIN_SEARCH)
            .map(|result| {
                result.map(|value| match value {
                    DhcpOptionValue::DomainSearch(names) => names,
                    _ => Vec::new(),
                })
            })
    }

    /// RFC 3361 SIP servers (option 120), concatenated across areas.
    ///
    /// Source: RFC 3361. Reassembles the logical option payload (RFC 3396) and
    /// decodes the `enc` selector into either a domain-name list or an IPv4
    /// address list, preserving any unspecified encoding verbatim. Returns
    /// `None` when no area carries the option; a malformed payload surfaces as a
    /// structured error.
    pub fn sip_servers(&self) -> Option<Result<SipServers>> {
        self.typed_value_in_areas(DHCP_OPTION_SIP_SERVERS)
            .map(|result| {
                result.map(|value| match value {
                    DhcpOptionValue::SipServers(servers) => servers,
                    _ => SipServers::Addresses(Vec::new()),
                })
            })
    }

    /// RFC 2132 vendor-specific information (option 43), concatenated across
    /// areas.
    ///
    /// Source: RFC 2132 section 8.4. The payload is opaque vendor data whose
    /// internal format is defined by the vendor (option 60); it is returned
    /// verbatim. Returns `None` when no area carries the option.
    pub fn vendor_specific_information(&self) -> Option<Vec<u8>> {
        self.concatenated_payload(DHCP_OPTION_VENDOR_SPECIFIC)
    }

    /// RFC 2132 vendor class identifier (option 60), concatenated across areas.
    ///
    /// Source: RFC 2132 section 9.13. The payload is an opaque string of octets
    /// interpreted by servers; it is returned verbatim. Returns `None` when no
    /// area carries the option.
    pub fn vendor_class_identifier(&self) -> Option<Vec<u8>> {
        self.concatenated_payload(DHCP_OPTION_VENDOR_CLASS_IDENTIFIER)
    }

    /// RFC 2132 TFTP server name (option 66), concatenated across areas.
    ///
    /// Source: RFC 2132 section 9.4. The payload is an NVT ASCII string. The raw
    /// bytes are returned because the value is not guaranteed UTF-8. Returns
    /// `None` when no area carries the option.
    pub fn tftp_server_name(&self) -> Option<Vec<u8>> {
        self.concatenated_payload(DHCP_OPTION_TFTP_SERVER_NAME)
    }

    /// RFC 2132 bootfile name (option 67), concatenated across areas.
    ///
    /// Source: RFC 2132 section 9.5. The payload is an NVT ASCII string returned
    /// as raw bytes. Returns `None` when no area carries the option.
    pub fn bootfile_name(&self) -> Option<Vec<u8>> {
        self.concatenated_payload(DHCP_OPTION_BOOTFILE_NAME)
    }

    /// RFC 3004 user class (option 77), concatenated across areas.
    ///
    /// Source: RFC 3004. Reassembles the logical payload (RFC 3396) and decodes
    /// the length-prefixed opaque class instances. Returns `None` when no area
    /// carries the option; a malformed instance length surfaces as a structured
    /// error.
    pub fn user_class(&self) -> Option<Result<DhcpUserClass>> {
        self.typed_value_in_areas(DHCP_OPTION_USER_CLASS)
            .map(|result| {
                result.map(|value| match value {
                    DhcpOptionValue::UserClass(user_class) => user_class,
                    _ => DhcpUserClass::new(Vec::new()),
                })
            })
    }

    /// RFC 4578 client system architecture types (option 93), concatenated
    /// across areas.
    ///
    /// Source: RFC 4578 section 2.1. Reassembles the logical payload (RFC 3396)
    /// and decodes the 16-bit architecture type list. Returns `None` when no
    /// area carries the option; a length that is not a non-zero multiple of two
    /// surfaces as a structured error.
    pub fn client_system_architecture(&self) -> Option<Result<ClientSystemArchitecture>> {
        self.typed_value_in_areas(DHCP_OPTION_CLIENT_SYSTEM_ARCHITECTURE)
            .map(|result| {
                result.map(|value| match value {
                    DhcpOptionValue::ClientSystemArchitecture(arch) => arch,
                    _ => ClientSystemArchitecture::new(Vec::new()),
                })
            })
    }

    /// RFC 4578 client network device interface (option 94), concatenated across
    /// areas.
    ///
    /// Source: RFC 4578 section 2.2. Decodes the type/major/minor triple.
    /// Returns `None` when no area carries the option; a length other than three
    /// surfaces as a structured error.
    pub fn client_network_device_interface(&self) -> Option<Result<ClientNetworkDeviceInterface>> {
        self.typed_value_in_areas(DHCP_OPTION_CLIENT_NDI)
            .map(|result| {
                result.map(|value| match value {
                    DhcpOptionValue::ClientNetworkDeviceInterface(ndi) => ndi,
                    _ => ClientNetworkDeviceInterface::new(0, 0, 0),
                })
            })
    }

    /// RFC 4578 UUID/GUID client machine identifier (option 97), concatenated
    /// across areas.
    ///
    /// Source: RFC 4578 section 2.3. Decodes the type octet plus identifier
    /// (a 16-octet GUID for type `0`). Returns `None` when no area carries the
    /// option; an empty payload surfaces as a structured error.
    pub fn client_uuid(&self) -> Option<Result<DhcpClientUuid>> {
        self.typed_value_in_areas(DHCP_OPTION_CLIENT_MACHINE_IDENTIFIER)
            .map(|result| {
                result.map(|value| match value {
                    DhcpOptionValue::ClientUuid(uuid) => uuid,
                    _ => DhcpClientUuid::new(0, Vec::new()),
                })
            })
    }

    /// RFC 3925 V-I Vendor Class instances (option 124), concatenated across
    /// areas.
    ///
    /// Source: RFC 3925 section 3. Decodes the enterprise-number plus opaque
    /// vendor-class-data instances. Returns `None` when no area carries the
    /// option; a truncated instance surfaces as a structured error.
    pub fn vi_vendor_class(&self) -> Option<Result<Vec<DhcpVendorClassData>>> {
        self.typed_value_in_areas(DHCP_OPTION_VI_VENDOR_CLASS)
            .map(|result| {
                result.map(|value| match value {
                    DhcpOptionValue::ViVendorClass(instances) => instances,
                    _ => Vec::new(),
                })
            })
    }

    /// RFC 3925 V-I Vendor-Specific Information instances (option 125),
    /// concatenated across areas.
    ///
    /// Source: RFC 3925 section 4. Decodes the enterprise-number instances and
    /// their nested suboptions. Returns `None` when no area carries the option;
    /// a truncated instance or suboption surfaces as a structured error.
    pub fn vi_vendor_specific(&self) -> Option<Result<Vec<DhcpVendorIdentifyingOption>>> {
        self.typed_value_in_areas(DHCP_OPTION_VI_VENDOR_SPECIFIC)
            .map(|result| {
                result.map(|value| match value {
                    DhcpOptionValue::ViVendorSpecific(instances) => instances,
                    _ => Vec::new(),
                })
            })
    }

    /// RFC 5859 TFTP server addresses (option 150), concatenated across areas.
    ///
    /// Source: RFC 5859. Code 150 is marked ambiguous by the IANA registry
    /// (TFTP server / Etherboot / GRUB), so it is preserved as raw bytes by the
    /// default option decoder. This accessor is an explicit opt-in to the RFC
    /// 5859 IPv4-address-list interpretation: it reassembles the logical payload
    /// (RFC 3396) and decodes the address list. Returns `None` when no area
    /// carries the option; a length that is not a non-zero multiple of four
    /// surfaces as a structured error.
    pub fn tftp_server_addresses(&self) -> Option<Result<Vec<Ipv4Addr>>> {
        let payload = self.concatenated_payload(DHCP_OPTION_TFTP_SERVER_ADDRESS)?;
        Some(decode_tftp_server_addresses(&payload))
    }

    /// RFC 5071 PXELINUX magic value (option 208), concatenated across areas.
    ///
    /// Source: RFC 5071. The payload is the fixed 4-octet magic value; it is
    /// returned verbatim. Returns `None` when no area carries the option.
    pub fn pxelinux_magic(&self) -> Option<Vec<u8>> {
        self.concatenated_payload(DHCP_OPTION_PXELINUX_MAGIC)
    }

    /// RFC 5071 PXELINUX configuration file path (option 209), concatenated
    /// across areas.
    ///
    /// Source: RFC 5071. The payload is an NVT ASCII string returned as raw
    /// bytes. Returns `None` when no area carries the option.
    pub fn pxelinux_config_file(&self) -> Option<Vec<u8>> {
        self.concatenated_payload(DHCP_OPTION_PXELINUX_CONFIGFILE)
    }

    /// RFC 5071 PXELINUX path prefix (option 210), concatenated across areas.
    ///
    /// Source: RFC 5071. The payload is an NVT ASCII string returned as raw
    /// bytes. Returns `None` when no area carries the option.
    pub fn pxelinux_path_prefix(&self) -> Option<Vec<u8>> {
        self.concatenated_payload(DHCP_OPTION_PXELINUX_PATHPREFIX)
    }

    /// RFC 5071 PXELINUX reboot time in seconds (option 211), concatenated
    /// across areas.
    ///
    /// Source: RFC 5071. The payload is a 32-bit big-endian seconds value.
    /// Returns `None` when no area carries the option; a length other than four
    /// surfaces as a structured error.
    pub fn pxelinux_reboot_time(&self) -> Option<Result<u32>> {
        self.typed_value_in_areas(DHCP_OPTION_PXELINUX_REBOOTTIME)
            .map(|result| {
                result.map(|value| match value {
                    DhcpOptionValue::U32(seconds) => seconds,
                    _ => 0,
                })
            })
    }

    /// Reassemble the raw logical payload bytes of an option across all areas.
    ///
    /// Joins the option payload across the normal, `file`, and `sname` areas in
    /// RFC 3396 aggregate order and returns the raw bytes. Returns `None` when
    /// no area carries the code. Used for options whose payloads stay opaque
    /// (vendor data, NVT ASCII strings, the PXELINUX magic).
    fn concatenated_payload(&self, code: u8) -> Option<Vec<u8>> {
        match self.concatenated_option(code)? {
            Ok(option) => option.payload().ok(),
            Err(_) => None,
        }
    }

    /// Decode the typed value of an option, reassembled across all areas.
    ///
    /// Joins the option payload across the normal, `file`, and `sname` areas in
    /// RFC 3396 aggregate order and runs the source-backed format decoder.
    /// Returns `None` when no area carries the code.
    fn typed_value_in_areas(&self, code: u8) -> Option<Result<DhcpOptionValue>> {
        let joined = self.concatenated_option(code)?;
        Some(joined.and_then(|option| {
            option
                .typed_value()
                .and_then(|value| value.ok_or_else(|| missing_typed_value(code)))
        }))
    }

    /// Encode the normal-area DHCP options, appending an end marker when needed.
    ///
    /// When the `file` or `sname` areas carry options and the caller did not
    /// set an explicit option-overload option (52), one is inserted here so the
    /// emitted normal options describe the overloaded fields (RFC 2132 section
    /// 9.3).
    pub fn encoded_options(&self) -> Result<Vec<u8>> {
        encode_dhcp_options(&self.effective_normal_options())
    }

    /// Normal-area options with an auto-inserted option-overload option (52)
    /// when overloaded fields carry options and the caller did not set one.
    fn effective_normal_options(&self) -> Vec<DhcpOption> {
        let Some(overload) = self.option_overload() else {
            return self.options.clone();
        };
        if find_option_overload(&self.options).is_some() {
            // The caller set option 52 explicitly; honor it untouched.
            return self.options.clone();
        }

        let mut options = self.options.clone();
        let overload_option = DhcpOption::option_overload(overload);
        match options.iter().position(|o| matches!(o, DhcpOption::End)) {
            Some(end) => options.insert(end, overload_option),
            None => options.push(overload_option),
        }
        options
    }

    /// Render the `file` fixed-field bytes for the wire (RFC 2131 section 2).
    ///
    /// When the field is overloaded it carries its option list, terminated by an
    /// end marker and zero-padded to 128 octets; otherwise the boot file name
    /// string bytes are used (truncated/padded by the fixed-field writer).
    fn encoded_file_field(&self) -> Result<Option<Vec<u8>>> {
        if self.file_options.is_empty() {
            return Ok(None);
        }
        Ok(Some(encode_overload_area_options(
            "dhcp.file.options",
            &self.file_options,
            DHCP_FILE_LEN,
        )?))
    }

    /// Render the `sname` fixed-field bytes for the wire (RFC 2131 section 2).
    fn encoded_sname_field(&self) -> Result<Option<Vec<u8>>> {
        if self.sname_options.is_empty() {
            return Ok(None);
        }
        Ok(Some(encode_overload_area_options(
            "dhcp.sname.options",
            &self.sname_options,
            DHCP_SNAME_LEN,
        )?))
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
        // A field cannot be both a normal string and an overloaded option area.
        if !self.file_options.is_empty() && !self.boot_file_name.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "dhcp.file",
                "boot file name string and overloaded file options are mutually exclusive",
            ));
        }
        if !self.sname_options.is_empty() && !self.server_name.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "dhcp.sname",
                "server name string and overloaded sname options are mutually exclusive",
            ));
        }
        self.encoded_options()?;
        self.encoded_file_field()?;
        self.encoded_sname_field()?;
        Ok(())
    }

    fn encoded_dhcp_len(&self) -> usize {
        DHCP_MIN_LEN + encoded_options_len_lossy(&self.effective_normal_options())
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
            (
                "overload",
                match self.option_overload() {
                    Some(OptionOverload::File) => "file".to_string(),
                    Some(OptionOverload::Sname) => "sname".to_string(),
                    Some(OptionOverload::Both) => "file+sname".to_string(),
                    Some(OptionOverload::Unknown(value)) => format!("unknown({value})"),
                    None => "none".to_string(),
                },
            ),
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
        // RFC 2131 section 4.1: when overloaded, `sname`/`file` carry their
        // option list (already padded to the fixed width); otherwise they hold
        // the host name / boot file name string.
        match self.encoded_sname_field()? {
            Some(bytes) => out.extend_from_slice(&bytes),
            None => append_fixed_field(out, &self.server_name, DHCP_SNAME_LEN),
        }
        match self.encoded_file_field()? {
            Some(bytes) => out.extend_from_slice(&bytes),
            None => append_fixed_field(out, &self.boot_file_name, DHCP_FILE_LEN),
        }
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

    // RFC 2131 section 4.1: interpret the normal options area first so any
    // option-overload option (52) is available before the `sname`/`file`
    // fields are examined.
    let options = DhcpOption::decode_all(&bytes[DHCP_MIN_LEN..])?;
    let overload = find_option_overload(&options);

    let mut server_name = bytes[44..108].to_vec();
    let mut boot_file_name = bytes[108..236].to_vec();
    let mut sname_options = Vec::new();
    let mut file_options = Vec::new();

    if let Some(overload) = overload {
        // The `file` field MUST be interpreted before `sname` per RFC 2131
        // section 4.1, but each is decoded from its own fixed-width field.
        if overload.overloads_file() {
            file_options = decode_overload_area_options(DhcpOptionArea::File, &boot_file_name)?;
            boot_file_name.clear();
        }
        if overload.overloads_sname() {
            sname_options = decode_overload_area_options(DhcpOptionArea::Sname, &server_name)?;
            server_name.clear();
        }
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
        server_name,
        boot_file_name,
        magic_cookie: Field::user(magic_cookie),
        options,
        file_options,
        sname_options,
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

/// Structured error for the unexpected case where a registered route/domain/
/// service option code yields no typed value. The route, domain, and SIP
/// formats always produce a typed value when their code decodes, so this only
/// guards against an internal mapping regression rather than wire data.
fn missing_typed_value(code: u8) -> CrafterError {
    CrafterError::invalid_field_value(
        "dhcp.option.value",
        match code {
            DHCP_OPTION_STATIC_ROUTE => "static route option has no typed value",
            DHCP_OPTION_CLASSLESS_STATIC_ROUTE => {
                "classless static route option has no typed value"
            }
            DHCP_OPTION_DOMAIN_SEARCH => "domain search option has no typed value",
            DHCP_OPTION_SIP_SERVERS => "SIP servers option has no typed value",
            _ => "DHCP option has no typed value",
        },
    )
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

#[cfg(test)]
mod dhcp_option_overload {
    use super::{
        Dhcp, DhcpMessageType, DhcpOption, DhcpOptionArea, OptionOverload, DHCP_FILE_LEN,
        DHCP_MIN_LEN, DHCP_OPTION_OVERLOAD, DHCP_SNAME_LEN,
    };
    use crate::error::CrafterError;
    use crate::Packet;
    use core::net::Ipv4Addr;

    // Fixed-field byte ranges within the DHCP message (RFC 2131 section 2):
    // sname[64] starts at offset 44, file[128] starts at offset 108.
    const SNAME_START: usize = 44;
    const SNAME_END: usize = SNAME_START + DHCP_SNAME_LEN;
    const FILE_START: usize = 108;
    const FILE_END: usize = FILE_START + DHCP_FILE_LEN;

    fn compiled_bytes(dhcp: Dhcp) -> Vec<u8> {
        Packet::from_layer(dhcp)
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn dhcp_option_overload_normal_only_keeps_string_fields() {
        // Without any overloaded options, `sname`/`file` stay plain strings and
        // no option 52 is emitted.
        let dhcp = Dhcp::new()
            .message_type(DhcpMessageType::Discover)
            .sname("boot-server")
            .file("pxelinux.0");

        assert_eq!(dhcp.option_overload(), None);
        assert!(!dhcp.file_is_overloaded());
        assert!(!dhcp.sname_is_overloaded());

        let bytes = compiled_bytes(dhcp);
        assert_eq!(&bytes[SNAME_START..SNAME_START + 11], b"boot-server");
        assert_eq!(&bytes[FILE_START..FILE_START + 10], b"pxelinux.0");

        let parsed = Dhcp::decode(&bytes).unwrap();
        assert_eq!(parsed.option_overload(), None);
        assert_eq!(parsed.sname_bytes(), b"boot-server");
        assert_eq!(parsed.file_bytes(), b"pxelinux.0");
        assert!(parsed.file_options_value().is_empty());
        assert!(parsed.sname_options_value().is_empty());
        // No option 52 appears in the normal options area.
        assert!(parsed
            .options_value()
            .iter()
            .all(|o| o.code() != DHCP_OPTION_OVERLOAD));
        assert_eq!(
            Packet::from_layer(parsed).compile().unwrap().as_bytes(),
            bytes
        );
    }

    #[test]
    fn dhcp_option_overload_file_only() {
        // Placing options in the `file` area overloads only `file`; option 52 is
        // auto-inserted with value 1.
        let dhcp = Dhcp::new()
            .message_type(DhcpMessageType::Ack)
            .sname("boot-server")
            .file_option(DhcpOption::host_name("from-file"))
            .file_option(DhcpOption::End);

        assert_eq!(dhcp.option_overload(), Some(OptionOverload::File));
        assert!(dhcp.file_is_overloaded());
        assert!(!dhcp.sname_is_overloaded());

        let bytes = compiled_bytes(dhcp);
        // The normal options area carries the auto-inserted overload option.
        let parsed = Dhcp::decode(&bytes).unwrap();
        assert_eq!(parsed.option_overload(), Some(OptionOverload::File));
        // `sname` stays a string; `file` carries options.
        assert_eq!(parsed.sname_bytes(), b"boot-server");
        assert_eq!(parsed.file_bytes(), b"");
        assert!(parsed.sname_options_value().is_empty());
        assert_eq!(
            parsed.file_options_value(),
            &[DhcpOption::host_name("from-file"), DhcpOption::End]
        );
        // Re-encode reproduces the exact wire bytes.
        assert_eq!(
            Packet::from_layer(parsed).compile().unwrap().as_bytes(),
            bytes
        );
    }

    #[test]
    fn dhcp_option_overload_sname_only() {
        let dhcp = Dhcp::new()
            .message_type(DhcpMessageType::Ack)
            .file("pxelinux.0")
            .sname_option(DhcpOption::host_name("from-sname"))
            .sname_option(DhcpOption::End);

        assert_eq!(dhcp.option_overload(), Some(OptionOverload::Sname));

        let bytes = compiled_bytes(dhcp);
        let parsed = Dhcp::decode(&bytes).unwrap();
        assert_eq!(parsed.option_overload(), Some(OptionOverload::Sname));
        assert!(parsed.sname_is_overloaded());
        assert!(!parsed.file_is_overloaded());
        assert_eq!(parsed.file_bytes(), b"pxelinux.0");
        assert_eq!(parsed.sname_bytes(), b"");
        assert_eq!(
            parsed.sname_options_value(),
            &[DhcpOption::host_name("from-sname"), DhcpOption::End]
        );
        assert!(parsed.file_options_value().is_empty());
        assert_eq!(
            Packet::from_layer(parsed).compile().unwrap().as_bytes(),
            bytes
        );
    }

    #[test]
    fn dhcp_option_overload_decodes_file_and_sname_areas() {
        // Both fields overloaded: option 52 value 3, with distinct options in
        // each area plus the normal area. Decode must surface each option with
        // exact source-area metadata and re-encode consistently.
        let dhcp = Dhcp::new()
            .message_type(DhcpMessageType::Ack)
            .server_identifier(Ipv4Addr::new(192, 0, 2, 1))
            .file_option(DhcpOption::subnet_mask(Ipv4Addr::new(255, 255, 255, 0)))
            .file_option(DhcpOption::End)
            .sname_option(DhcpOption::router([Ipv4Addr::new(192, 0, 2, 254)]))
            .sname_option(DhcpOption::End);

        assert_eq!(dhcp.option_overload(), Some(OptionOverload::Both));

        let bytes = compiled_bytes(dhcp.clone());

        // Fixed fields are exactly their fixed widths even when overloaded.
        assert_eq!(
            bytes.len(),
            DHCP_MIN_LEN + dhcp.encoded_options().unwrap().len()
        );

        let parsed = Dhcp::decode(&bytes).unwrap();
        assert_eq!(parsed.option_overload(), Some(OptionOverload::Both));
        assert!(parsed.file_is_overloaded());
        assert!(parsed.sname_is_overloaded());

        // The normal area carries the message type, server id, and option 52.
        assert_eq!(parsed.message_type_value(), Some(DhcpMessageType::Ack));
        assert_eq!(
            parsed.server_identifier_value(),
            Some(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert!(parsed
            .options_value()
            .iter()
            .any(|o| matches!(o, DhcpOption::OptionOverload(OptionOverload::Both))));

        // The file and sname areas carry their own options.
        assert_eq!(
            parsed.file_options_value(),
            &[
                DhcpOption::subnet_mask(Ipv4Addr::new(255, 255, 255, 0)),
                DhcpOption::End
            ]
        );
        assert_eq!(
            parsed.sname_options_value(),
            &[
                DhcpOption::router([Ipv4Addr::new(192, 0, 2, 254)]),
                DhcpOption::End
            ]
        );

        // Source-area metadata is exact: scanning each fixed field reports the
        // matching area for every segment.
        let file_segments =
            super::scan_dhcp_option_segments(DhcpOptionArea::File, &bytes[FILE_START..FILE_END])
                .unwrap();
        assert!(file_segments.iter().all(|s| s.area == DhcpOptionArea::File));
        assert_eq!(
            file_segments[0].code_value(),
            super::DHCP_OPTION_SUBNET_MASK
        );

        let sname_segments =
            super::scan_dhcp_option_segments(DhcpOptionArea::Sname, &bytes[SNAME_START..SNAME_END])
                .unwrap();
        assert!(sname_segments
            .iter()
            .all(|s| s.area == DhcpOptionArea::Sname));
        assert_eq!(sname_segments[0].code_value(), super::DHCP_OPTION_ROUTER);

        // Re-encode reproduces the exact wire bytes.
        assert_eq!(
            Packet::from_layer(parsed).compile().unwrap().as_bytes(),
            bytes
        );
    }

    #[test]
    fn dhcp_option_overload_honors_explicit_option_52() {
        // When the caller sets option 52 explicitly, it is honored untouched and
        // not duplicated by the auto-insert path.
        let dhcp = Dhcp::new()
            .message_type(DhcpMessageType::Ack)
            .option(DhcpOption::option_overload(OptionOverload::File))
            .file_option(DhcpOption::host_name("from-file"))
            .file_option(DhcpOption::End);

        let bytes = compiled_bytes(dhcp);
        let parsed = Dhcp::decode(&bytes).unwrap();
        // Exactly one option 52 survives the round-trip.
        let count = parsed
            .options_value()
            .iter()
            .filter(|o| o.code() == DHCP_OPTION_OVERLOAD)
            .count();
        assert_eq!(count, 1);
        assert_eq!(parsed.option_overload(), Some(OptionOverload::File));
        assert_eq!(
            parsed.file_options_value(),
            &[DhcpOption::host_name("from-file"), DhcpOption::End]
        );
        assert_eq!(
            Packet::from_layer(parsed).compile().unwrap().as_bytes(),
            bytes
        );
    }

    #[test]
    fn dhcp_option_overload_rejects_string_and_options_in_same_field() {
        // A field cannot be both a string and an overloaded option area.
        let file_conflict = Dhcp::new()
            .message_type(DhcpMessageType::Ack)
            .file("pxelinux.0")
            .file_option(DhcpOption::host_name("x"))
            .file_option(DhcpOption::End);
        let error = Packet::from_layer(file_conflict).compile().unwrap_err();
        assert!(matches!(
            error,
            CrafterError::InvalidFieldValue { field, .. } if field == "dhcp.file"
        ));

        let sname_conflict = Dhcp::new()
            .message_type(DhcpMessageType::Ack)
            .sname("boot-server")
            .sname_option(DhcpOption::host_name("x"))
            .sname_option(DhcpOption::End);
        let error = Packet::from_layer(sname_conflict).compile().unwrap_err();
        assert!(matches!(
            error,
            CrafterError::InvalidFieldValue { field, .. } if field == "dhcp.sname"
        ));
    }

    #[test]
    fn dhcp_option_overload_rejects_options_exceeding_field_width() {
        // Overloaded option data that does not fit the fixed field width is a
        // structured error, not a panic.
        let too_big = Dhcp::new()
            .message_type(DhcpMessageType::Ack)
            .sname_option(DhcpOption::generic(60, vec![0u8; 200]))
            .sname_option(DhcpOption::End);
        let error = Packet::from_layer(too_big).compile().unwrap_err();
        assert!(matches!(
            error,
            CrafterError::InvalidFieldValue { field, .. } if field == "dhcp.sname.options"
        ));
    }

    #[test]
    fn dhcp_option_overload_missing_end_marker_in_field_is_structured() {
        // Build a valid overloaded packet, then corrupt the overloaded `file`
        // field so it lacks an end marker. Decode must report a structured
        // error scoped to the file area and never panic.
        let dhcp = Dhcp::new()
            .message_type(DhcpMessageType::Ack)
            .option(DhcpOption::option_overload(OptionOverload::File))
            .file_option(DhcpOption::host_name("from-file"))
            .file_option(DhcpOption::End);
        let mut bytes = compiled_bytes(dhcp);
        // Overwrite the entire overloaded `file` field with pad bytes so it
        // contains options-area data but no terminating end marker (255).
        for byte in &mut bytes[FILE_START..FILE_END] {
            *byte = super::DHCP_OPTION_PAD;
        }
        let error = Dhcp::decode(&bytes).unwrap_err();
        assert!(matches!(
            error,
            CrafterError::InvalidFieldValue { field, .. } if field == "dhcp.file.options"
        ));
    }
}
