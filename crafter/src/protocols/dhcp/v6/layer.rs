//! DHCPv6 packet layer.

use core::any::Any;
use core::net::Ipv6Addr;
use core::ops::Div;

use crate::error::{CrafterError, Result};
use crate::field::{Field, FieldState};
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

use super::constants::{
    DHCPV6_CLIENT_PORT, DHCPV6_CLIENT_SERVER_HEADER_LEN, DHCPV6_LEASEQUERY,
    DHCPV6_LEASEQUERY_REPLY, DHCPV6_RELAY_FORW, DHCPV6_RELAY_HEADER_LEN, DHCPV6_RELAY_REPL,
    DHCPV6_SERVER_PORT, DHCPV6_TRANSACTION_ID_MAX,
};
use super::duid::Dhcpv6Duid;
use super::message::{dhcpv6_message_type_summary, Dhcpv6MessageType};
use super::option::{
    Dhcpv6Authentication, Dhcpv6BootfileParam, Dhcpv6ClientArchitecture, Dhcpv6ClientData,
    Dhcpv6ClientLinkLayerAddress, Dhcpv6DomainList, Dhcpv6IaNa, Dhcpv6IaPd, Dhcpv6Leasequery,
    Dhcpv6NetworkInterfaceIdentifier, Dhcpv6Option, Dhcpv6OptionCode, Dhcpv6RelaySuppliedOptions,
    Dhcpv6RemoteId, Dhcpv6StatusCodeOption, Dhcpv6UserClass, Dhcpv6VendorClass,
    Dhcpv6VendorOptions,
};
use super::registry::{dhcpv6_option_meta, dhcpv6_option_name, Dhcpv6OptionSingleton};
use super::status::Dhcpv6StatusCode;
use crate::protocols::dhcp::v4::Dhcpv4;

/// DHCPv6 packet layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcpv6 {
    message_type: Field<Dhcpv6MessageType>,
    transaction_id: Field<u32>,
    relay: Option<Dhcpv6RelayHeader>,
    options: Vec<Dhcpv6Option>,
}

/// DHCPv6 relay fixed-header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcpv6RelayHeader {
    hop_count: Field<u8>,
    link_address: Field<Ipv6Addr>,
    peer_address: Field<Ipv6Addr>,
}

/// Report for repeated DHCPv6 options in one option list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcpv6OptionRepetitionReport {
    entries: Vec<Dhcpv6OptionRepetition>,
}

/// Repetition metadata for one DHCPv6 option codepoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcpv6OptionRepetition {
    /// Wire option codepoint.
    pub code: u16,
    /// Number of occurrences in the inspected option list.
    pub count: usize,
    /// IANA singleton column for the option codepoint, when known.
    pub singleton: Option<Dhcpv6OptionSingleton>,
}

impl Dhcpv6OptionRepetitionReport {
    /// Ordered repetition entries, keyed by first occurrence in the option list.
    pub fn entries(&self) -> &[Dhcpv6OptionRepetition] {
        &self.entries
    }

    /// Return the repetition entry for an option codepoint.
    pub fn for_code(&self, code: u16) -> Option<&Dhcpv6OptionRepetition> {
        self.entries.iter().find(|entry| entry.code == code)
    }

    /// True when any singleton option appears more than once.
    pub fn has_duplicate_singletons(&self) -> bool {
        self.entries
            .iter()
            .any(Dhcpv6OptionRepetition::is_duplicate_singleton)
    }

    /// Iterate over duplicate singleton entries.
    pub fn duplicate_singletons(&self) -> impl Iterator<Item = &Dhcpv6OptionRepetition> {
        self.entries
            .iter()
            .filter(|entry| entry.is_duplicate_singleton())
    }
}

impl Dhcpv6OptionRepetition {
    /// True when this option is registry-marked singleton and appears more than once.
    pub fn is_duplicate_singleton(&self) -> bool {
        self.count > 1 && self.singleton == Some(Dhcpv6OptionSingleton::Yes)
    }
}

impl Dhcpv6RelayHeader {
    /// Create a relay header with deterministic hop-count default.
    pub fn new(link_address: Ipv6Addr, peer_address: Ipv6Addr) -> Self {
        Self {
            hop_count: Field::defaulted(0),
            link_address: Field::user(link_address),
            peer_address: Field::user(peer_address),
        }
    }

    /// Set the relay hop count.
    pub fn hop_count(mut self, hop_count: u8) -> Self {
        self.hop_count.set_user(hop_count);
        self
    }

    /// Set the relay link-address field.
    pub fn link_address(mut self, link_address: Ipv6Addr) -> Self {
        self.link_address.set_user(link_address);
        self
    }

    /// Set the relay peer-address field.
    pub fn peer_address(mut self, peer_address: Ipv6Addr) -> Self {
        self.peer_address.set_user(peer_address);
        self
    }

    /// Relay hop-count value.
    pub fn hop_count_value(&self) -> u8 {
        self.hop_count.value().copied().unwrap_or(0)
    }

    /// State of the relay hop-count field.
    pub const fn hop_count_state(&self) -> FieldState {
        self.hop_count.state()
    }

    /// Relay link-address value.
    pub fn link_address_value(&self) -> Ipv6Addr {
        self.link_address
            .value()
            .copied()
            .unwrap_or(Ipv6Addr::UNSPECIFIED)
    }

    /// State of the relay link-address field.
    pub const fn link_address_state(&self) -> FieldState {
        self.link_address.state()
    }

    /// Relay peer-address value.
    pub fn peer_address_value(&self) -> Ipv6Addr {
        self.peer_address
            .value()
            .copied()
            .unwrap_or(Ipv6Addr::UNSPECIFIED)
    }

    /// State of the relay peer-address field.
    pub const fn peer_address_state(&self) -> FieldState {
        self.peer_address.state()
    }
}

impl Dhcpv6 {
    /// Create an empty DHCPv6 client/server message with deterministic defaults.
    pub fn new() -> Self {
        Self {
            message_type: Field::defaulted(Dhcpv6MessageType::Solicit),
            transaction_id: Field::defaulted(0),
            relay: None,
            options: Vec::new(),
        }
    }

    /// Create a DHCPv6 Solicit message with the supplied transaction ID.
    pub fn solicit(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Solicit, transaction_id)
    }

    /// Create a DHCPv6 Advertise message with the supplied transaction ID.
    pub fn advertise(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Advertise, transaction_id)
    }

    /// Create a DHCPv6 Request message with the supplied transaction ID.
    pub fn request(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Request, transaction_id)
    }

    /// Create a DHCPv6 Confirm message with the supplied transaction ID.
    pub fn confirm(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Confirm, transaction_id)
    }

    /// Create a DHCPv6 Renew message with the supplied transaction ID.
    pub fn renew(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Renew, transaction_id)
    }

    /// Create a DHCPv6 Rebind message with the supplied transaction ID.
    pub fn rebind(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Rebind, transaction_id)
    }

    /// Create a DHCPv6 Reply message with the supplied transaction ID.
    pub fn reply(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Reply, transaction_id)
    }

    /// Create a DHCPv6 Release message with the supplied transaction ID.
    pub fn release(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Release, transaction_id)
    }

    /// Create a DHCPv6 Decline message with the supplied transaction ID.
    pub fn decline(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Decline, transaction_id)
    }

    /// Create a DHCPv6 Reconfigure message with the supplied transaction ID.
    pub fn reconfigure(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Reconfigure, transaction_id)
    }

    /// Create a DHCPv6 Reconfigure message carrying OPTION_RECONF_MSG.
    pub fn reconfigure_with_message(
        transaction_id: u32,
        requested_message_type: Dhcpv6MessageType,
    ) -> Self {
        Self::reconfigure(transaction_id).reconfigure_message(requested_message_type)
    }

    /// Create a DHCPv6 Information-request message with the supplied transaction ID.
    pub fn information_request(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::InformationRequest, transaction_id)
    }

    /// Create a DHCPv6 LEASEQUERY message with the supplied transaction ID.
    pub fn leasequery(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::LeaseQuery, transaction_id)
    }

    /// Create a DHCPv6 LEASEQUERY-REPLY message with the supplied transaction ID.
    pub fn leasequery_reply(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::LeaseQueryReply, transaction_id)
    }

    /// Create a DHCPv6 LEASEQUERY-DONE message with the supplied transaction ID.
    pub fn leasequery_done(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::LeaseQueryDone, transaction_id)
    }

    /// Create a DHCPv6 LEASEQUERY-DATA message with the supplied transaction ID.
    pub fn leasequery_data(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::LeaseQueryData, transaction_id)
    }

    /// Create a DHCPv6 ACTIVELEASEQUERY message with the supplied transaction ID.
    pub fn active_leasequery(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::ActiveLeaseQuery, transaction_id)
    }

    /// Create a DHCPv6 STARTTLS message with the supplied transaction ID.
    pub fn starttls(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::StartTls, transaction_id)
    }

    /// Create a DHCPv6 DHCPV4-QUERY message with the supplied transaction ID.
    pub fn dhcpv4_query(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Dhcpv4Query, transaction_id)
    }

    /// Create a DHCPv6 DHCPV4-RESPONSE message with the supplied transaction ID.
    pub fn dhcpv4_response(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Dhcpv4Response, transaction_id)
    }

    /// Create a DHCPv6 BNDUPD failover message.
    pub fn bndupd(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::BndUpd, transaction_id)
    }

    /// Create a DHCPv6 BNDREPLY failover message.
    pub fn bndreply(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::BndReply, transaction_id)
    }

    /// Create a DHCPv6 POOLREQ failover message.
    pub fn poolreq(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::PoolReq, transaction_id)
    }

    /// Create a DHCPv6 POOLRESP failover message.
    pub fn poolresp(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::PoolResp, transaction_id)
    }

    /// Create a DHCPv6 UPDREQ failover message.
    pub fn updreq(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::UpdReq, transaction_id)
    }

    /// Create a DHCPv6 UPDREQALL failover message.
    pub fn updreqall(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::UpdReqAll, transaction_id)
    }

    /// Create a DHCPv6 UPDDONE failover message.
    pub fn upddone(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::UpdDone, transaction_id)
    }

    /// Create a DHCPv6 CONNECT failover message.
    pub fn connect(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Connect, transaction_id)
    }

    /// Create a DHCPv6 CONNECTREPLY failover message.
    pub fn connect_reply(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::ConnectReply, transaction_id)
    }

    /// Create a DHCPv6 DISCONNECT failover message.
    pub fn disconnect(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Disconnect, transaction_id)
    }

    /// Create a DHCPv6 STATE failover message.
    pub fn state(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::State, transaction_id)
    }

    /// Create a DHCPv6 CONTACT failover message.
    pub fn contact(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::Contact, transaction_id)
    }

    /// Create a DHCPv6 ADDR-REG-INFORM message with the supplied transaction ID.
    pub fn addr_reg_inform(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::AddrRegInform, transaction_id)
    }

    /// Create a DHCPv6 ADDR-REG-REPLY message with the supplied transaction ID.
    pub fn addr_reg_reply(transaction_id: u32) -> Self {
        Self::client_server_message(Dhcpv6MessageType::AddrRegReply, transaction_id)
    }

    /// Create a DHCPv6 Relay-forward message body.
    pub fn relay_forward(link_address: Ipv6Addr, peer_address: Ipv6Addr) -> Self {
        Self::new()
            .message_type(Dhcpv6MessageType::RelayForw)
            .relay_header(Dhcpv6RelayHeader::new(link_address, peer_address))
    }

    /// Create a DHCPv6 Relay-reply message body.
    pub fn relay_reply(link_address: Ipv6Addr, peer_address: Ipv6Addr) -> Self {
        Self::new()
            .message_type(Dhcpv6MessageType::RelayRepl)
            .relay_header(Dhcpv6RelayHeader::new(link_address, peer_address))
    }

    /// Decode a DHCPv6 message.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_dhcpv6(bytes)
    }

    fn client_server_message(message_type: Dhcpv6MessageType, transaction_id: u32) -> Self {
        Self::new()
            .message_type(message_type)
            .transaction_id(transaction_id)
    }

    /// Set the DHCPv6 message type.
    pub fn message_type(mut self, message_type: Dhcpv6MessageType) -> Self {
        self.message_type.set_user(message_type);
        self
    }

    /// Set the DHCPv6 message type from a raw codepoint.
    pub fn message_type_code(self, code: u8) -> Self {
        self.message_type(Dhcpv6MessageType::from_code(code))
    }

    /// Current message type value.
    pub fn message_type_value(&self) -> Dhcpv6MessageType {
        self.message_type
            .value()
            .copied()
            .unwrap_or(Dhcpv6MessageType::Solicit)
    }

    /// Current raw message type codepoint.
    pub fn message_type_code_value(&self) -> u8 {
        self.message_type_value().code()
    }

    /// State of the message type field.
    pub const fn message_type_state(&self) -> FieldState {
        self.message_type.state()
    }

    /// Set the 24-bit DHCPv6 transaction ID.
    pub fn transaction_id(mut self, transaction_id: u32) -> Self {
        self.transaction_id.set_user(transaction_id);
        self
    }

    /// Try to set the 24-bit DHCPv6 transaction ID.
    pub fn try_transaction_id(mut self, transaction_id: u32) -> Result<Self> {
        validate_transaction_id(transaction_id)?;
        self.transaction_id.set_user(transaction_id);
        Ok(self)
    }

    /// Current transaction ID value.
    pub fn transaction_id_value(&self) -> u32 {
        self.transaction_id.value().copied().unwrap_or(0)
    }

    /// State of the transaction ID field.
    pub const fn transaction_id_state(&self) -> FieldState {
        self.transaction_id.state()
    }

    /// Set relay fixed-header fields.
    pub fn relay_header(mut self, relay: Dhcpv6RelayHeader) -> Self {
        self.relay = Some(relay);
        self
    }

    /// Set relay hop count when this message carries a relay header.
    pub fn hop_count(mut self, hop_count: u8) -> Self {
        if let Some(relay) = self.relay.take() {
            self.relay = Some(relay.hop_count(hop_count));
        }
        self
    }

    /// Set relay link-address when this message carries a relay header.
    pub fn link_address(mut self, link_address: Ipv6Addr) -> Self {
        if let Some(relay) = self.relay.take() {
            self.relay = Some(relay.link_address(link_address));
        }
        self
    }

    /// Set relay peer-address when this message carries a relay header.
    pub fn peer_address(mut self, peer_address: Ipv6Addr) -> Self {
        if let Some(relay) = self.relay.take() {
            self.relay = Some(relay.peer_address(peer_address));
        }
        self
    }

    /// Borrow relay fixed-header fields, when present.
    pub fn relay(&self) -> Option<&Dhcpv6RelayHeader> {
        self.relay.as_ref()
    }

    /// Mutably borrow relay fixed-header fields, when present.
    pub fn relay_mut(&mut self) -> Option<&mut Dhcpv6RelayHeader> {
        self.relay.as_mut()
    }

    /// Append an option and return the updated layer.
    pub fn option(mut self, option: Dhcpv6Option) -> Self {
        self.options.push(option);
        self
    }

    /// Append a raw option by codepoint and payload bytes.
    pub fn raw_option(
        self,
        code: impl Into<Dhcpv6OptionCode>,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        self.option(Dhcpv6Option::raw(code, payload))
    }

    /// Append a zero-length option by codepoint.
    pub fn empty_option(self, code: impl Into<Dhcpv6OptionCode>) -> Self {
        self.option(Dhcpv6Option::empty(code))
    }

    /// Append an OPTION_CLIENTID option.
    pub fn client_id(self, duid: impl Into<Vec<u8>>) -> Self {
        self.option(Dhcpv6Option::client_id(duid))
    }

    /// Append an OPTION_SERVERID option.
    pub fn server_id(self, duid: impl Into<Vec<u8>>) -> Self {
        self.option(Dhcpv6Option::server_id(duid))
    }

    /// Append an OPTION_CLIENTID option from a typed DUID.
    pub fn client_duid(self, duid: Dhcpv6Duid) -> Self {
        self.client_id(duid)
    }

    /// Append an OPTION_SERVERID option from a typed DUID.
    pub fn server_duid(self, duid: Dhcpv6Duid) -> Self {
        self.server_id(duid)
    }

    /// Append an OPTION_ORO option.
    pub fn oro<I, C>(self, codes: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<Dhcpv6OptionCode>,
    {
        self.option(Dhcpv6Option::oro(codes))
    }

    /// Append an OPTION_PREFERENCE option.
    pub fn preference(self, preference: u8) -> Self {
        self.option(Dhcpv6Option::preference(preference))
    }

    /// Append an OPTION_ELAPSED_TIME option in hundredths of a second.
    pub fn elapsed_time(self, centiseconds: u16) -> Self {
        self.option(Dhcpv6Option::elapsed_time(centiseconds))
    }

    /// Append an OPTION_RELAY_MSG option from raw relayed DHCPv6 bytes.
    pub fn relay_msg(self, payload: impl Into<Vec<u8>>) -> Self {
        self.option(Dhcpv6Option::relay_msg(payload))
    }

    /// Append an OPTION_RELAY_MSG option from a typed DHCPv6 message.
    pub fn relay_message(self, message: Dhcpv6) -> Result<Self> {
        let bytes = Packet::from_layer(message).compile()?;
        Ok(self.relay_msg(bytes.as_bytes()))
    }

    /// Append an OPTION_RAPID_COMMIT option.
    pub fn rapid_commit(self) -> Self {
        self.option(Dhcpv6Option::rapid_commit())
    }

    /// Append an OPTION_ADDR_REG_ENABLE option.
    pub fn addr_reg_enable(self) -> Self {
        self.option(Dhcpv6Option::addr_reg_enable())
    }

    /// Append an OPTION_LQ_QUERY option.
    pub fn leasequery_option(self, query: Dhcpv6Leasequery) -> Result<Self> {
        Ok(self.option(Dhcpv6Option::leasequery(query)?))
    }

    /// Append an OPTION_CLIENT_DATA option.
    pub fn client_data(self, client_data: Dhcpv6ClientData) -> Result<Self> {
        Ok(self.option(Dhcpv6Option::client_data(client_data)?))
    }

    /// Append an OPTION_CLT_TIME option.
    pub fn client_time(self, seconds: u32) -> Self {
        self.option(Dhcpv6Option::client_time(seconds))
    }

    /// Append an OPTION_LQ_RELAY_DATA option.
    pub fn leasequery_relay_data(self, payload: impl Into<Vec<u8>>) -> Self {
        self.option(Dhcpv6Option::leasequery_relay_data(payload))
    }

    /// Append an OPTION_LQ_CLIENT_LINK option.
    pub fn leasequery_client_link<I>(self, addresses: I) -> Self
    where
        I: IntoIterator<Item = Ipv6Addr>,
    {
        self.option(Dhcpv6Option::leasequery_client_link(addresses))
    }

    /// Append an OPTION_LQ_BASE_TIME option.
    pub fn leasequery_base_time(self, seconds: u32) -> Self {
        self.option(Dhcpv6Option::leasequery_base_time(seconds))
    }

    /// Append an OPTION_LQ_START_TIME option.
    pub fn leasequery_start_time(self, seconds: u32) -> Self {
        self.option(Dhcpv6Option::leasequery_start_time(seconds))
    }

    /// Append an OPTION_LQ_END_TIME option.
    pub fn leasequery_end_time(self, seconds: u32) -> Self {
        self.option(Dhcpv6Option::leasequery_end_time(seconds))
    }

    /// Append an OPTION_DHCPV4_MSG option from embedded DHCPv4 bytes.
    pub fn dhcpv4_msg(self, payload: impl Into<Vec<u8>>) -> Self {
        self.option(Dhcpv6Option::dhcpv4_msg(payload))
    }

    /// Append an OPTION_DHCPV4_MSG option from a typed DHCPv4 layer.
    pub fn dhcpv4_message(self, message: Dhcpv4) -> Result<Self> {
        Ok(self.option(Dhcpv6Option::dhcpv4_message(message)?))
    }

    /// Append a raw DHCPv6 failover option from the registered F_* option range.
    pub fn failover_option(self, code: u16, payload: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(self.option(Dhcpv6Option::failover_option(code, payload)?))
    }

    /// Append an OPTION_AUTH option.
    pub fn authentication(self, authentication: Dhcpv6Authentication) -> Self {
        self.option(Dhcpv6Option::authentication(authentication))
    }

    /// Append an OPTION_USER_CLASS option.
    pub fn user_class(self, user_class: Dhcpv6UserClass) -> Result<Self> {
        Ok(self.option(Dhcpv6Option::user_class(user_class)?))
    }

    /// Append an OPTION_VENDOR_CLASS option.
    pub fn vendor_class(self, vendor_class: Dhcpv6VendorClass) -> Result<Self> {
        Ok(self.option(Dhcpv6Option::vendor_class(vendor_class)?))
    }

    /// Append an OPTION_VENDOR_OPTS option.
    pub fn vendor_opts(self, vendor_opts: Dhcpv6VendorOptions) -> Result<Self> {
        Ok(self.option(Dhcpv6Option::vendor_opts(vendor_opts)?))
    }

    /// Append an OPTION_INTERFACE_ID option.
    pub fn interface_id(self, interface_id: impl Into<Vec<u8>>) -> Self {
        self.option(Dhcpv6Option::interface_id(interface_id))
    }

    /// Append an OPTION_RECONF_MSG option.
    pub fn reconfigure_message(self, message_type: Dhcpv6MessageType) -> Self {
        self.option(Dhcpv6Option::reconfigure_message(message_type))
    }

    /// Append an OPTION_RECONF_ACCEPT option.
    pub fn reconfigure_accept(self) -> Self {
        self.option(Dhcpv6Option::reconfigure_accept())
    }

    /// Append an OPTION_DNS_SERVERS option.
    pub fn dns_servers<I>(self, servers: I) -> Self
    where
        I: IntoIterator<Item = Ipv6Addr>,
    {
        self.option(Dhcpv6Option::dns_servers(servers))
    }

    /// Append an OPTION_DOMAIN_LIST option.
    pub fn domain_list(self, domain_list: Dhcpv6DomainList) -> Result<Self> {
        Ok(self.option(Dhcpv6Option::domain_list(domain_list)?))
    }

    /// Append an OPTION_INFORMATION_REFRESH_TIME option.
    pub fn information_refresh_time(self, seconds: u32) -> Self {
        self.option(Dhcpv6Option::information_refresh_time(seconds))
    }

    /// Append an OPTION_SOL_MAX_RT option.
    pub fn sol_max_rt(self, seconds: u32) -> Self {
        self.option(Dhcpv6Option::sol_max_rt(seconds))
    }

    /// Append an OPTION_INF_MAX_RT option.
    pub fn inf_max_rt(self, seconds: u32) -> Self {
        self.option(Dhcpv6Option::inf_max_rt(seconds))
    }

    /// Append an OPTION_STATUS_CODE option.
    pub fn status_code(self, status: Dhcpv6StatusCodeOption) -> Self {
        self.option(Dhcpv6Option::status_code(status))
    }

    /// Append an OPTION_STATUS_CODE option with no status message bytes.
    pub fn status(self, status: Dhcpv6StatusCode) -> Self {
        self.option(Dhcpv6Option::status(status))
    }

    /// Append an OPTION_STATUS_CODE option with status message bytes.
    pub fn status_message(self, status: Dhcpv6StatusCode, message: impl AsRef<[u8]>) -> Self {
        self.option(Dhcpv6Option::status_message(status, message))
    }

    /// Append an OPTION_IA_NA option.
    pub fn ia_na(self, ia_na: Dhcpv6IaNa) -> Result<Self> {
        Ok(self.option(Dhcpv6Option::ia_na(ia_na)?))
    }

    /// Append an OPTION_IA_PD option.
    pub fn ia_pd(self, ia_pd: Dhcpv6IaPd) -> Result<Self> {
        Ok(self.option(Dhcpv6Option::ia_pd(ia_pd)?))
    }

    /// Append an OPTION_REMOTE_ID option.
    pub fn remote_id(self, remote_id: Dhcpv6RemoteId) -> Self {
        self.option(Dhcpv6Option::remote_id(remote_id))
    }

    /// Append an OPTION_SUBSCRIBER_ID option.
    pub fn subscriber_id(self, subscriber_id: impl Into<Vec<u8>>) -> Self {
        self.option(Dhcpv6Option::subscriber_id(subscriber_id))
    }

    /// Append an OPTION_RELAY_ID option.
    pub fn relay_id(self, relay_id: impl Into<Vec<u8>>) -> Self {
        self.option(Dhcpv6Option::relay_id(relay_id))
    }

    /// Append an OPT_BOOTFILE_URL option.
    pub fn bootfile_url(self, url: impl Into<Vec<u8>>) -> Self {
        self.option(Dhcpv6Option::bootfile_url(url))
    }

    /// Append an OPT_BOOTFILE_PARAM option.
    pub fn bootfile_param(self, params: Dhcpv6BootfileParam) -> Result<Self> {
        Ok(self.option(Dhcpv6Option::bootfile_param(params)?))
    }

    /// Append an OPTION_CLIENT_ARCH_TYPE option.
    pub fn client_arch_type(self, arch: Dhcpv6ClientArchitecture) -> Self {
        self.option(Dhcpv6Option::client_arch_type(arch))
    }

    /// Append an OPTION_NII option.
    pub fn network_interface_identifier(self, nii: Dhcpv6NetworkInterfaceIdentifier) -> Self {
        self.option(Dhcpv6Option::network_interface_identifier(nii))
    }

    /// Append an OPTION_RSOO option.
    pub fn relay_supplied_options(self, rsoo: Dhcpv6RelaySuppliedOptions) -> Result<Self> {
        Ok(self.option(Dhcpv6Option::relay_supplied_options(rsoo)?))
    }

    /// Append an OPTION_CLIENT_LINKLAYER_ADDR option.
    pub fn client_link_layer_addr(self, client: Dhcpv6ClientLinkLayerAddress) -> Self {
        self.option(Dhcpv6Option::client_link_layer_addr(client))
    }

    /// Replace the option list.
    pub fn options(mut self, options: impl Into<Vec<Dhcpv6Option>>) -> Self {
        self.options = options.into();
        self
    }

    /// Borrow the option list.
    pub fn options_ref(&self) -> &[Dhcpv6Option] {
        &self.options
    }

    /// Mutably borrow the option list.
    pub fn options_mut(&mut self) -> &mut Vec<Dhcpv6Option> {
        &mut self.options
    }

    /// Report repeated top-level options without rejecting malformed packets.
    pub fn option_repetition_report(&self) -> Dhcpv6OptionRepetitionReport {
        option_repetition_report_for(&self.options)
    }

    /// Return OPTION_CLIENTID DUID bytes from the first Client ID option.
    pub fn client_id_value(&self) -> Option<&[u8]> {
        self.first_option(super::constants::DHCPV6_OPTION_CLIENTID)
            .and_then(Dhcpv6Option::client_id_value)
    }

    /// Return OPTION_SERVERID DUID bytes from the first Server ID option.
    pub fn server_id_value(&self) -> Option<&[u8]> {
        self.first_option(super::constants::DHCPV6_OPTION_SERVERID)
            .and_then(Dhcpv6Option::server_id_value)
    }

    /// Decode the first Client ID option as a DUID.
    pub fn client_duid_value(&self) -> Result<Option<Dhcpv6Duid>> {
        match self.first_option(super::constants::DHCPV6_OPTION_CLIENTID) {
            Some(option) => option.client_duid_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Server ID option as a DUID.
    pub fn server_duid_value(&self) -> Result<Option<Dhcpv6Duid>> {
        match self.first_option(super::constants::DHCPV6_OPTION_SERVERID) {
            Some(option) => option.server_duid_value(),
            None => Ok(None),
        }
    }

    /// Decode requested option codepoints from the first ORO option.
    pub fn oro_value(&self) -> Result<Option<Vec<Dhcpv6OptionCode>>> {
        match self.first_option(super::constants::DHCPV6_OPTION_ORO) {
            Some(option) => option.oro_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Preference option.
    pub fn preference_value(&self) -> Result<Option<u8>> {
        match self.first_option(super::constants::DHCPV6_OPTION_PREFERENCE) {
            Some(option) => option.preference_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Elapsed Time option.
    pub fn elapsed_time_value(&self) -> Result<Option<u16>> {
        match self.first_option(super::constants::DHCPV6_OPTION_ELAPSED_TIME) {
            Some(option) => option.elapsed_time_value(),
            None => Ok(None),
        }
    }

    /// Return OPTION_RELAY_MSG payload bytes from the first Relay Message option.
    pub fn relay_msg_value(&self) -> Option<&[u8]> {
        self.first_option(super::constants::DHCPV6_OPTION_RELAY_MSG)
            .and_then(Dhcpv6Option::relay_msg_value)
    }

    /// Decode the first Relay Message option as a DHCPv6 message.
    pub fn relayed_message_value(&self) -> Result<Option<Dhcpv6>> {
        match self.relay_msg_value() {
            Some(payload) => Dhcpv6::decode(payload).map(Some),
            None => Ok(None),
        }
    }

    /// Return true when a valid Rapid Commit option is present.
    pub fn rapid_commit_present(&self) -> Result<bool> {
        match self.first_option(super::constants::DHCPV6_OPTION_RAPID_COMMIT) {
            Some(option) => option.rapid_commit_present(),
            None => Ok(false),
        }
    }

    /// Return true when a valid Address Registration Enable option is present.
    pub fn addr_reg_enable_present(&self) -> Result<bool> {
        match self.first_option(super::constants::DHCPV6_OPTION_ADDR_REG_ENABLE) {
            Some(option) => option.addr_reg_enable_present(),
            None => Ok(false),
        }
    }

    /// Decode the first Leasequery option.
    pub fn leasequery_value(&self) -> Result<Option<Dhcpv6Leasequery>> {
        match self.first_option(super::constants::DHCPV6_OPTION_LQ_QUERY) {
            Some(option) => option.leasequery_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Client Data option.
    pub fn client_data_value(&self) -> Result<Option<Dhcpv6ClientData>> {
        match self.first_option(super::constants::DHCPV6_OPTION_CLIENT_DATA) {
            Some(option) => option.client_data_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Client Last Transaction Time option.
    pub fn client_time_value(&self) -> Result<Option<u32>> {
        match self.first_option(super::constants::DHCPV6_OPTION_CLT_TIME) {
            Some(option) => option.client_time_value(),
            None => Ok(None),
        }
    }

    /// Return OPTION_LQ_RELAY_DATA payload bytes.
    pub fn leasequery_relay_data_value(&self) -> Option<&[u8]> {
        self.first_option(super::constants::DHCPV6_OPTION_LQ_RELAY_DATA)
            .and_then(Dhcpv6Option::leasequery_relay_data_value)
    }

    /// Decode the first Leasequery Client Link option.
    pub fn leasequery_client_link_value(&self) -> Result<Option<Vec<Ipv6Addr>>> {
        match self.first_option(super::constants::DHCPV6_OPTION_LQ_CLIENT_LINK) {
            Some(option) => option.leasequery_client_link_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Leasequery Base Time option.
    pub fn leasequery_base_time_value(&self) -> Result<Option<u32>> {
        match self.first_option(super::constants::DHCPV6_OPTION_LQ_BASE_TIME) {
            Some(option) => option.leasequery_base_time_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Leasequery Start Time option.
    pub fn leasequery_start_time_value(&self) -> Result<Option<u32>> {
        match self.first_option(super::constants::DHCPV6_OPTION_LQ_START_TIME) {
            Some(option) => option.leasequery_start_time_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Leasequery End Time option.
    pub fn leasequery_end_time_value(&self) -> Result<Option<u32>> {
        match self.first_option(super::constants::DHCPV6_OPTION_LQ_END_TIME) {
            Some(option) => option.leasequery_end_time_value(),
            None => Ok(None),
        }
    }

    /// Return OPTION_DHCPV4_MSG payload bytes.
    pub fn dhcpv4_msg_value(&self) -> Option<&[u8]> {
        self.first_option(super::constants::DHCPV6_OPTION_DHCPV4_MSG)
            .and_then(Dhcpv6Option::dhcpv4_msg_value)
    }

    /// Decode the first OPTION_DHCPV4_MSG as a typed DHCPv4 layer.
    pub fn dhcpv4_message_value(&self) -> Result<Option<Dhcpv4>> {
        match self.first_option(super::constants::DHCPV6_OPTION_DHCPV4_MSG) {
            Some(option) => option.dhcpv4_message_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Authentication option.
    pub fn authentication_value(&self) -> Result<Option<Dhcpv6Authentication>> {
        match self.first_option(super::constants::DHCPV6_OPTION_AUTH) {
            Some(option) => option.authentication_value(),
            None => Ok(None),
        }
    }

    /// Decode the first User Class option.
    pub fn user_class_value(&self) -> Result<Option<Dhcpv6UserClass>> {
        match self.first_option(super::constants::DHCPV6_OPTION_USER_CLASS) {
            Some(option) => option.user_class_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Vendor Class option.
    pub fn vendor_class_value(&self) -> Result<Option<Dhcpv6VendorClass>> {
        match self.first_option(super::constants::DHCPV6_OPTION_VENDOR_CLASS) {
            Some(option) => option.vendor_class_value(),
            None => Ok(None),
        }
    }

    /// Decode all Vendor Class options in packet order.
    pub fn vendor_class_values(&self) -> Result<Vec<Dhcpv6VendorClass>> {
        let mut values = Vec::new();
        for option in &self.options {
            if let Some(vendor_class) = option.vendor_class_value()? {
                values.push(vendor_class);
            }
        }
        Ok(values)
    }

    /// Decode the first Vendor Options option.
    pub fn vendor_opts_value(&self) -> Result<Option<Dhcpv6VendorOptions>> {
        match self.first_option(super::constants::DHCPV6_OPTION_VENDOR_OPTS) {
            Some(option) => option.vendor_opts_value(),
            None => Ok(None),
        }
    }

    /// Decode all Vendor Options options in packet order.
    pub fn vendor_opts_values(&self) -> Result<Vec<Dhcpv6VendorOptions>> {
        let mut values = Vec::new();
        for option in &self.options {
            if let Some(vendor_opts) = option.vendor_opts_value()? {
                values.push(vendor_opts);
            }
        }
        Ok(values)
    }

    /// Return OPTION_INTERFACE_ID payload bytes from the first Interface-Id option.
    pub fn interface_id_value(&self) -> Option<&[u8]> {
        self.first_option(super::constants::DHCPV6_OPTION_INTERFACE_ID)
            .and_then(Dhcpv6Option::interface_id_value)
    }

    /// Decode the first Reconfigure Message option.
    pub fn reconfigure_message_value(&self) -> Result<Option<Dhcpv6MessageType>> {
        match self.first_option(super::constants::DHCPV6_OPTION_RECONF_MSG) {
            Some(option) => option.reconfigure_message_value(),
            None => Ok(None),
        }
    }

    /// Return true when a valid Reconfigure Accept option is present.
    pub fn reconfigure_accept_present(&self) -> Result<bool> {
        match self.first_option(super::constants::DHCPV6_OPTION_RECONF_ACCEPT) {
            Some(option) => option.reconfigure_accept_present(),
            None => Ok(false),
        }
    }

    /// Decode the first DNS Servers option.
    pub fn dns_servers_value(&self) -> Result<Option<Vec<Ipv6Addr>>> {
        match self.first_option(super::constants::DHCPV6_OPTION_DNS_SERVERS) {
            Some(option) => option.dns_servers_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Domain List option.
    pub fn domain_list_value(&self) -> Result<Option<Dhcpv6DomainList>> {
        match self.first_option(super::constants::DHCPV6_OPTION_DOMAIN_LIST) {
            Some(option) => option.domain_list_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Information Refresh Time option.
    pub fn information_refresh_time_value(&self) -> Result<Option<u32>> {
        match self.first_option(super::constants::DHCPV6_OPTION_INFORMATION_REFRESH_TIME) {
            Some(option) => option.information_refresh_time_value(),
            None => Ok(None),
        }
    }

    /// Decode the first SOL_MAX_RT option.
    pub fn sol_max_rt_value(&self) -> Result<Option<u32>> {
        match self.first_option(super::constants::DHCPV6_OPTION_SOL_MAX_RT) {
            Some(option) => option.sol_max_rt_value(),
            None => Ok(None),
        }
    }

    /// Decode the first INF_MAX_RT option.
    pub fn inf_max_rt_value(&self) -> Result<Option<u32>> {
        match self.first_option(super::constants::DHCPV6_OPTION_INF_MAX_RT) {
            Some(option) => option.inf_max_rt_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Status Code option.
    pub fn status_code_value(&self) -> Result<Option<Dhcpv6StatusCodeOption>> {
        match self.first_option(super::constants::DHCPV6_OPTION_STATUS_CODE) {
            Some(option) => option.status_code_value(),
            None => Ok(None),
        }
    }

    /// Decode all Status Code options in packet order.
    pub fn status_code_values(&self) -> Result<Vec<Dhcpv6StatusCodeOption>> {
        let mut values = Vec::new();
        for option in &self.options {
            if let Some(status) = option.status_code_value()? {
                values.push(status);
            }
        }
        Ok(values)
    }

    /// Decode the first IA_NA option.
    pub fn ia_na_value(&self) -> Result<Option<Dhcpv6IaNa>> {
        match self.first_option(super::constants::DHCPV6_OPTION_IA_NA) {
            Some(option) => option.ia_na_value(),
            None => Ok(None),
        }
    }

    /// Decode all IA_NA options in packet order.
    pub fn ia_na_values(&self) -> Result<Vec<Dhcpv6IaNa>> {
        let mut values = Vec::new();
        for option in &self.options {
            if let Some(ia_na) = option.ia_na_value()? {
                values.push(ia_na);
            }
        }
        Ok(values)
    }

    /// Decode the first IA_PD option.
    pub fn ia_pd_value(&self) -> Result<Option<Dhcpv6IaPd>> {
        match self.first_option(super::constants::DHCPV6_OPTION_IA_PD) {
            Some(option) => option.ia_pd_value(),
            None => Ok(None),
        }
    }

    /// Decode all IA_PD options in packet order.
    pub fn ia_pd_values(&self) -> Result<Vec<Dhcpv6IaPd>> {
        let mut values = Vec::new();
        for option in &self.options {
            if let Some(ia_pd) = option.ia_pd_value()? {
                values.push(ia_pd);
            }
        }
        Ok(values)
    }

    /// Decode the first Remote-ID option.
    pub fn remote_id_value(&self) -> Result<Option<Dhcpv6RemoteId>> {
        match self.first_option(super::constants::DHCPV6_OPTION_REMOTE_ID) {
            Some(option) => option.remote_id_value(),
            None => Ok(None),
        }
    }

    /// Return OPTION_SUBSCRIBER_ID payload bytes from the first Subscriber-ID option.
    pub fn subscriber_id_value(&self) -> Option<&[u8]> {
        self.first_option(super::constants::DHCPV6_OPTION_SUBSCRIBER_ID)
            .and_then(Dhcpv6Option::subscriber_id_value)
    }

    /// Return OPTION_RELAY_ID payload bytes from the first Relay-ID option.
    pub fn relay_id_value(&self) -> Option<&[u8]> {
        self.first_option(super::constants::DHCPV6_OPTION_RELAY_ID)
            .and_then(Dhcpv6Option::relay_id_value)
    }

    /// Return OPT_BOOTFILE_URL payload bytes.
    pub fn bootfile_url_value(&self) -> Option<&[u8]> {
        self.first_option(super::constants::DHCPV6_OPTION_BOOTFILE_URL)
            .and_then(Dhcpv6Option::bootfile_url_value)
    }

    /// Return OPT_BOOTFILE_URL as UTF-8 text when valid.
    pub fn bootfile_url_text(&self) -> Option<&str> {
        self.first_option(super::constants::DHCPV6_OPTION_BOOTFILE_URL)
            .and_then(Dhcpv6Option::bootfile_url_text)
    }

    /// Decode the first Bootfile Param option.
    pub fn bootfile_param_value(&self) -> Result<Option<Dhcpv6BootfileParam>> {
        match self.first_option(super::constants::DHCPV6_OPTION_BOOTFILE_PARAM) {
            Some(option) => option.bootfile_param_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Client Architecture option.
    pub fn client_arch_type_value(&self) -> Result<Option<Dhcpv6ClientArchitecture>> {
        match self.first_option(super::constants::DHCPV6_OPTION_CLIENT_ARCH_TYPE) {
            Some(option) => option.client_arch_type_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Network Interface Identifier option.
    pub fn network_interface_identifier_value(
        &self,
    ) -> Result<Option<Dhcpv6NetworkInterfaceIdentifier>> {
        match self.first_option(super::constants::DHCPV6_OPTION_NII) {
            Some(option) => option.network_interface_identifier_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Relay-ID option as a DUID.
    pub fn relay_duid_value(&self) -> Result<Option<Dhcpv6Duid>> {
        match self.first_option(super::constants::DHCPV6_OPTION_RELAY_ID) {
            Some(option) => option.relay_duid_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Relay-Supplied Options option.
    pub fn relay_supplied_options_value(&self) -> Result<Option<Dhcpv6RelaySuppliedOptions>> {
        match self.first_option(super::constants::DHCPV6_OPTION_RSOO) {
            Some(option) => option.relay_supplied_options_value(),
            None => Ok(None),
        }
    }

    /// Decode the first Client Link-Layer Address option.
    pub fn client_link_layer_addr_value(&self) -> Result<Option<Dhcpv6ClientLinkLayerAddress>> {
        match self.first_option(super::constants::DHCPV6_OPTION_CLIENT_LINKLAYER_ADDR) {
            Some(option) => option.client_link_layer_addr_value(),
            None => Ok(None),
        }
    }

    /// Encoded DHCPv6 client/server message length.
    pub fn encoded_dhcpv6_len(&self) -> usize {
        let header_len = if self.relay.is_some() {
            DHCPV6_RELAY_HEADER_LEN
        } else {
            DHCPV6_CLIENT_SERVER_HEADER_LEN
        };
        header_len
            + self
                .options
                .iter()
                .map(|option| super::constants::DHCPV6_OPTION_HEADER_LEN + option.payload_len())
                .sum::<usize>()
    }

    fn first_option(&self, code: u16) -> Option<&Dhcpv6Option> {
        self.options
            .iter()
            .find(|option| option.codepoint() == code)
    }
}

impl Default for Dhcpv6 {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Dhcpv6 {
    fn name(&self) -> &'static str {
        "Dhcpv6"
    }

    fn summary(&self) -> String {
        let option_summary = dhcpv6_option_summary_suffix(&self.options);
        if let Some(relay) = &self.relay {
            return format!(
                "Dhcpv6(type={}, hop_count={}, link_address={}, peer_address={}, options={}{})",
                dhcpv6_message_type_summary(self.message_type_value()),
                relay.hop_count_value(),
                relay.link_address_value(),
                relay.peer_address_value(),
                self.options.len(),
                option_summary,
            );
        }
        format!(
            "Dhcpv6(type={}, xid=0x{:06x}, options={}{})",
            dhcpv6_message_type_summary(self.message_type_value()),
            self.transaction_id_value(),
            self.options.len(),
            option_summary,
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            (
                "message_type",
                dhcpv6_message_type_summary(self.message_type_value()),
            ),
            (
                "transaction_id",
                format!("0x{:06x}", self.transaction_id_value()),
            ),
            ("options", self.options.len().to_string()),
        ];
        if let Some(relay) = &self.relay {
            fields.push(("hop_count", relay.hop_count_value().to_string()));
            fields.push(("link_address", relay.link_address_value().to_string()));
            fields.push(("peer_address", relay.peer_address_value().to_string()));
        }
        if !self.options.is_empty() {
            fields.push(("option_names", dhcpv6_option_name_list(&self.options)));
            for (index, option) in self.options.iter().enumerate() {
                fields.push(("option", format!("[{index}] {}", option.summary())));
            }
        }
        let repetition = self.option_repetition_report();
        for entry in repetition.duplicate_singletons() {
            fields.push((
                "duplicate_singleton",
                format!(
                    "{} count={}",
                    dhcpv6_option_code_label(entry.code),
                    entry.count
                ),
            ));
        }
        fields
    }

    fn encoded_len(&self) -> usize {
        self.encoded_dhcpv6_len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        if let Some(relay) = &self.relay {
            out.reserve(self.encoded_dhcpv6_len());
            out.push(self.message_type_value().code());
            out.push(relay.hop_count_value());
            out.extend_from_slice(&relay.link_address_value().octets());
            out.extend_from_slice(&relay.peer_address_value().octets());
            for option in &self.options {
                option.encode_into(out)?;
            }
            return Ok(());
        }

        let transaction_id = self.transaction_id_value();
        validate_transaction_id(transaction_id)?;

        out.reserve(self.encoded_dhcpv6_len());
        out.push(self.message_type_value().code());
        out.push(((transaction_id >> 16) & 0xff) as u8);
        out.push(((transaction_id >> 8) & 0xff) as u8);
        out.push((transaction_id & 0xff) as u8);
        for option in &self.options {
            option.encode_into(out)?;
        }
        Ok(())
    }

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
}

impl<R> Div<R> for Dhcpv6
where
    R: IntoPacket,
{
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        Packet::from_layer(self).concat(rhs)
    }
}

/// Append a decoded DHCPv6 message to an existing packet stack.
pub(crate) fn append_dhcpv6_packet(packet: Packet, bytes: &[u8]) -> Result<Packet> {
    Ok(packet.push(decode_dhcpv6(bytes)?))
}

/// Return true when a UDP source/destination pair is a DHCPv6 client/server pair.
pub(crate) const fn is_dhcpv6_port_pair(source_port: u16, destination_port: u16) -> bool {
    matches!(
        (source_port, destination_port),
        (DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT) | (DHCPV6_SERVER_PORT, DHCPV6_CLIENT_PORT)
    )
}

/// Return true when a UDP source/destination pair is a DHCPv6 relay/server pair.
pub(crate) const fn is_dhcpv6_relay_port_pair(source_port: u16, destination_port: u16) -> bool {
    matches!(
        (source_port, destination_port),
        (DHCPV6_SERVER_PORT, DHCPV6_SERVER_PORT)
    )
}

/// Return true when bytes have enough shape to decode as a DHCPv6 client/server message.
pub(crate) fn looks_like_dhcpv6_client_payload(bytes: &[u8]) -> bool {
    bytes.len() >= DHCPV6_CLIENT_SERVER_HEADER_LEN
        && !matches!(bytes[0], DHCPV6_RELAY_FORW | DHCPV6_RELAY_REPL)
}

/// Return true when bytes have enough shape to decode as a DHCPv6 relay message.
pub(crate) fn looks_like_dhcpv6_relay_payload(bytes: &[u8]) -> bool {
    bytes.len() >= DHCPV6_RELAY_HEADER_LEN
        && matches!(bytes[0], DHCPV6_RELAY_FORW | DHCPV6_RELAY_REPL)
}

/// Return true when bytes have enough shape to decode as DHCPv6 server-port data.
pub(crate) fn looks_like_dhcpv6_server_port_payload(bytes: &[u8]) -> bool {
    bytes.len() >= DHCPV6_CLIENT_SERVER_HEADER_LEN
        && matches!(bytes[0], DHCPV6_LEASEQUERY | DHCPV6_LEASEQUERY_REPLY)
}

/// Return true when the UDP port pair and payload shape plausibly carry DHCPv6.
pub(crate) fn looks_like_dhcpv6_payload(
    source_port: u16,
    destination_port: u16,
    bytes: &[u8],
) -> bool {
    if is_dhcpv6_port_pair(source_port, destination_port) {
        return looks_like_dhcpv6_client_payload(bytes);
    }

    is_dhcpv6_relay_port_pair(source_port, destination_port)
        && (looks_like_dhcpv6_relay_payload(bytes) || looks_like_dhcpv6_server_port_payload(bytes))
}

fn decode_dhcpv6(bytes: &[u8]) -> Result<Dhcpv6> {
    match bytes.first().copied() {
        Some(DHCPV6_RELAY_FORW | DHCPV6_RELAY_REPL) => decode_dhcpv6_relay(bytes),
        _ => decode_dhcpv6_client_server(bytes),
    }
}

fn decode_dhcpv6_client_server(bytes: &[u8]) -> Result<Dhcpv6> {
    if bytes.len() < DHCPV6_CLIENT_SERVER_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "dhcpv6.client_server_header",
            DHCPV6_CLIENT_SERVER_HEADER_LEN,
            bytes.len(),
        ));
    }

    let transaction_id = ((bytes[1] as u32) << 16) | ((bytes[2] as u32) << 8) | bytes[3] as u32;
    Ok(Dhcpv6 {
        message_type: Field::user(Dhcpv6MessageType::from_code(bytes[0])),
        transaction_id: Field::user(transaction_id),
        relay: None,
        options: Dhcpv6Option::decode_all(&bytes[DHCPV6_CLIENT_SERVER_HEADER_LEN..])?,
    })
}

fn decode_dhcpv6_relay(bytes: &[u8]) -> Result<Dhcpv6> {
    if bytes.len() < DHCPV6_RELAY_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "dhcpv6.relay_header",
            DHCPV6_RELAY_HEADER_LEN,
            bytes.len(),
        ));
    }

    Ok(Dhcpv6 {
        message_type: Field::user(Dhcpv6MessageType::from_code(bytes[0])),
        transaction_id: Field::defaulted(0),
        relay: Some(Dhcpv6RelayHeader {
            hop_count: Field::user(bytes[1]),
            link_address: Field::user(Ipv6Addr::from(copy_array_16(&bytes[2..18]))),
            peer_address: Field::user(Ipv6Addr::from(copy_array_16(&bytes[18..34]))),
        }),
        options: Dhcpv6Option::decode_all(&bytes[DHCPV6_RELAY_HEADER_LEN..])?,
    })
}

fn validate_transaction_id(transaction_id: u32) -> Result<()> {
    if transaction_id > DHCPV6_TRANSACTION_ID_MAX {
        return Err(CrafterError::invalid_field_value(
            "dhcpv6.transaction_id",
            "value exceeds 24 bits",
        ));
    }
    Ok(())
}

fn option_repetition_report_for(options: &[Dhcpv6Option]) -> Dhcpv6OptionRepetitionReport {
    let mut entries = Vec::<Dhcpv6OptionRepetition>::new();

    for option in options {
        let code = option.codepoint();
        match entries.iter_mut().find(|entry| entry.code == code) {
            Some(entry) => entry.count += 1,
            None => entries.push(Dhcpv6OptionRepetition {
                code,
                count: 1,
                singleton: dhcpv6_option_meta(code).singleton,
            }),
        }
    }

    Dhcpv6OptionRepetitionReport { entries }
}

fn dhcpv6_option_summary_suffix(options: &[Dhcpv6Option]) -> String {
    if options.is_empty() {
        String::new()
    } else {
        format!(" [{}]", dhcpv6_option_name_list(options))
    }
}

fn dhcpv6_option_name_list(options: &[Dhcpv6Option]) -> String {
    const MAX_OPTION_LABELS: usize = 5;

    let mut labels = options
        .iter()
        .take(MAX_OPTION_LABELS)
        .map(|option| dhcpv6_option_code_label(option.codepoint()))
        .collect::<Vec<_>>();
    if options.len() > MAX_OPTION_LABELS {
        labels.push(format!("+{} more", options.len() - MAX_OPTION_LABELS));
    }
    labels.join(",")
}

fn dhcpv6_option_code_label(code: u16) -> String {
    dhcpv6_option_name(code)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("code{}", code))
}

fn copy_array_16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    out
}

#[cfg(test)]
mod dhcpv6_client_header_tests {
    use super::Dhcpv6;
    use crate::error::CrafterError;
    use crate::field::FieldState;
    use crate::packet::{Layer, Packet};
    use crate::protocols::dhcp::v6::{Dhcpv6MessageType, Dhcpv6Option};

    #[test]
    fn dhcpv6_client_header_default_compiles() {
        let bytes = Packet::from_layer(Dhcpv6::default()).compile().unwrap();

        assert_eq!(bytes.as_bytes(), &[1, 0, 0, 0]);
    }

    #[test]
    fn dhcpv6_client_header_compile_includes_options() {
        let dhcpv6 = Dhcpv6::new()
            .message_type(Dhcpv6MessageType::Request)
            .transaction_id(0x00ab_cdef)
            .option(Dhcpv6Option::raw(
                23u16,
                [0x20, 0x01, 0x0d, 0xb8].as_slice(),
            ));
        let bytes = Packet::from_layer(dhcpv6.clone()).compile().unwrap();

        assert_eq!(
            bytes.as_bytes(),
            &[3, 0xab, 0xcd, 0xef, 0x00, 0x17, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8],
        );
        assert_eq!(dhcpv6.encoded_len(), bytes.as_bytes().len());
    }

    #[test]
    fn dhcpv6_client_header_decode_marks_wire_fields_user_set() {
        let decoded = Dhcpv6::decode(&[7, 0x01, 0x02, 0x03, 0x00, 0x0e, 0x00, 0x00]).unwrap();

        assert_eq!(decoded.message_type_value(), Dhcpv6MessageType::Reply);
        assert_eq!(decoded.message_type_state(), FieldState::User);
        assert_eq!(decoded.transaction_id_value(), 0x010203);
        assert_eq!(decoded.transaction_id_state(), FieldState::User);
        assert_eq!(decoded.options_ref().len(), 1);
        assert_eq!(decoded.options_ref()[0].codepoint(), 14);

        let recompiled = Packet::from_layer(decoded).compile().unwrap();
        assert_eq!(
            recompiled.as_bytes(),
            &[7, 0x01, 0x02, 0x03, 0x00, 0x0e, 0x00, 0x00]
        );
    }

    #[test]
    fn dhcpv6_client_header_preserves_unknown_message_type() {
        let decoded = Dhcpv6::decode(&[200, 0, 0, 1]).unwrap();

        assert_eq!(
            decoded.message_type_value(),
            Dhcpv6MessageType::Unknown(200)
        );
        assert_eq!(
            Packet::from_layer(decoded).compile().unwrap().as_bytes(),
            &[200, 0, 0, 1]
        );
    }

    #[test]
    fn dhcpv6_client_header_rejects_truncated_header_and_oversized_xid() {
        assert_eq!(
            Dhcpv6::decode(&[1, 2, 3]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.client_server_header", 4, 3),
        );

        let error = Packet::from_layer(Dhcpv6::new().transaction_id(0x0100_0000))
            .compile()
            .unwrap_err();
        assert_eq!(
            error,
            CrafterError::invalid_field_value("dhcpv6.transaction_id", "value exceeds 24 bits",),
        );
    }
}

#[cfg(test)]
mod dhcpv6_singleton_tests {
    use super::Dhcpv6;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{
        Dhcpv6Option, Dhcpv6OptionSingleton, DHCPV6_OPTION_CLIENTID, DHCPV6_OPTION_IA_NA,
        DHCPV6_OPTION_VENDOR_OPTS,
    };

    #[test]
    fn dhcpv6_singleton_reports_duplicate_client_id_without_blocking_compile() {
        let dhcpv6 = Dhcpv6::solicit(0x010203)
            .client_id([0x00, 0x01])
            .client_id([0x00, 0x02]);
        let report = dhcpv6.option_repetition_report();
        let client_id = report.for_code(DHCPV6_OPTION_CLIENTID).unwrap();

        assert_eq!(client_id.code, DHCPV6_OPTION_CLIENTID);
        assert_eq!(client_id.count, 2);
        assert_eq!(client_id.singleton, Some(Dhcpv6OptionSingleton::Yes));
        assert!(client_id.is_duplicate_singleton());
        assert!(report.has_duplicate_singletons());
        assert_eq!(report.duplicate_singletons().count(), 1);
        assert!(Packet::from_layer(dhcpv6).compile().is_ok());
    }

    #[test]
    fn dhcpv6_singleton_allows_repeated_ia_na() {
        let ia_na = Dhcpv6Option::raw(DHCPV6_OPTION_IA_NA, [0; 12]);
        let dhcpv6 = Dhcpv6::reply(0x010203).option(ia_na.clone()).option(ia_na);
        let report = dhcpv6.option_repetition_report();
        let ia_na_entry = report.for_code(DHCPV6_OPTION_IA_NA).unwrap();

        assert_eq!(ia_na_entry.count, 2);
        assert_eq!(ia_na_entry.singleton, Some(Dhcpv6OptionSingleton::No));
        assert!(!ia_na_entry.is_duplicate_singleton());
        assert!(!report.has_duplicate_singletons());
        assert!(Packet::from_layer(dhcpv6).compile().is_ok());
    }

    #[test]
    fn dhcpv6_singleton_allows_repeated_vendor_options() {
        let vendor = Dhcpv6Option::raw(DHCPV6_OPTION_VENDOR_OPTS, [0x00, 0x00, 0x00, 0x01]);
        let dhcpv6 = Dhcpv6::reply(0x010203)
            .option(vendor.clone())
            .option(vendor);
        let report = dhcpv6.option_repetition_report();
        let vendor_entry = report.for_code(DHCPV6_OPTION_VENDOR_OPTS).unwrap();

        assert_eq!(vendor_entry.count, 2);
        assert_eq!(vendor_entry.singleton, Some(Dhcpv6OptionSingleton::No));
        assert!(!vendor_entry.is_duplicate_singleton());
        assert!(!report.has_duplicate_singletons());
    }

    #[test]
    fn dhcpv6_singleton_preserves_unknown_repetitions_without_flagging() {
        let unknown = Dhcpv6Option::raw(65_000u16, [0xde, 0xad]);
        let dhcpv6 = Dhcpv6::reply(0x010203)
            .option(unknown.clone())
            .option(unknown);
        let report = dhcpv6.option_repetition_report();
        let unknown_entry = report.for_code(65_000).unwrap();

        assert_eq!(unknown_entry.code, 65_000);
        assert_eq!(unknown_entry.count, 2);
        assert_eq!(unknown_entry.singleton, None);
        assert!(!unknown_entry.is_duplicate_singleton());
        assert_eq!(report.entries().len(), 1);
    }
}

#[cfg(test)]
mod dhcpv6_raw_escape_tests {
    use super::Dhcpv6;
    use core::net::Ipv6Addr;

    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{
        Dhcpv6IaNa, Dhcpv6MessageType, Dhcpv6Option, DHCPV6_OPTION_IAADDR, DHCPV6_OPTION_IA_NA,
        DHCPV6_OPTION_STATUS_CODE,
    };

    #[test]
    fn dhcpv6_raw_escape_compiles_unknown_message_type_and_options() {
        let message = Dhcpv6::new()
            .message_type_code(250)
            .transaction_id(0x00ff_00ff)
            .raw_option(65_000u16, [0xaa, 0xbb, 0xcc])
            .empty_option(65_001u16);
        let bytes = Packet::from_layer(message).compile().unwrap();

        assert_eq!(
            bytes.as_bytes(),
            &[
                250, 0xff, 0x00, 0xff, 0xfd, 0xe8, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0xfd, 0xe9, 0x00,
                0x00,
            ],
        );

        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();
        assert_eq!(
            decoded.message_type_value(),
            Dhcpv6MessageType::Unknown(250)
        );
        assert_eq!(decoded.message_type_code_value(), 250);
        assert_eq!(decoded.transaction_id_value(), 0x00ff_00ff);
        assert_eq!(decoded.options_ref()[0].codepoint(), 65_000);
        assert_eq!(decoded.options_ref()[0].payload(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(decoded.options_ref()[1].codepoint(), 65_001);
        assert!(decoded.options_ref()[1].is_empty());
    }

    #[test]
    fn dhcpv6_raw_escape_preserves_explicit_relay_hop_count_and_raw_option() {
        let link = Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 1);
        let peer = Ipv6Addr::new(0x2001, 0x0db8, 2, 0, 0, 0, 0, 2);
        let relay = Dhcpv6::relay_forward(link, peer)
            .hop_count(255)
            .raw_option(65_002u16, [0x01, 0x02]);
        let decoded = Dhcpv6::decode(Packet::from_layer(relay).compile().unwrap().as_bytes())
            .expect("valid relay envelope should decode");

        let relay_header = decoded.relay().unwrap();
        assert_eq!(relay_header.hop_count_value(), 255);
        assert_eq!(relay_header.link_address_value(), link);
        assert_eq!(relay_header.peer_address_value(), peer);
        assert_eq!(decoded.options_ref()[0].codepoint(), 65_002);
        assert_eq!(decoded.options_ref()[0].payload(), &[0x01, 0x02]);
    }

    #[test]
    fn dhcpv6_raw_escape_keeps_malformed_nested_options_inspectable() {
        let ia_na = Dhcpv6IaNa::new(0x0102_0304, 60, 120)
            .raw_option(DHCPV6_OPTION_IAADDR, [0xaa])
            .raw_option(65_003u16, [0xde, 0xad]);
        let message = Dhcpv6::reply(0x010203)
            .option(Dhcpv6Option::ia_na(ia_na).unwrap())
            .raw_option(65_004u16, [0xbe, 0xef]);
        let decoded = Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes())
            .expect("valid DHCPv6 envelope should decode");
        let decoded_ia_na = decoded.options_ref()[0].ia_na_value().unwrap().unwrap();

        assert_eq!(decoded.options_ref()[0].codepoint(), DHCPV6_OPTION_IA_NA);
        assert_eq!(
            decoded_ia_na.options_ref()[0].codepoint(),
            DHCPV6_OPTION_IAADDR
        );
        assert_eq!(decoded_ia_na.options_ref()[0].payload(), &[0xaa]);
        assert!(decoded_ia_na.options_ref()[0].ia_addr_value().is_err());
        assert_eq!(decoded_ia_na.options_ref()[1].codepoint(), 65_003);
        assert_eq!(decoded_ia_na.options_ref()[1].payload(), &[0xde, 0xad]);
        assert_eq!(decoded.options_ref()[1].codepoint(), 65_004);
    }

    #[test]
    fn dhcpv6_raw_escape_decodes_valid_header_with_malformed_typed_option() {
        let decoded = Dhcpv6::decode(&[7, 0x01, 0x02, 0x03, 0x00, 0x0d, 0x00, 0x01, 0xff]).unwrap();
        let option = &decoded.options_ref()[0];

        assert_eq!(decoded.message_type_value(), Dhcpv6MessageType::Reply);
        assert_eq!(option.codepoint(), DHCPV6_OPTION_STATUS_CODE);
        assert_eq!(option.payload(), &[0xff]);
        assert!(option.status_code_value().is_err());
        assert!(option.summary().contains("status=malformed"));
    }
}

#[cfg(test)]
mod dhcpv6_transaction_id_tests {
    use super::Dhcpv6;
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::Dhcpv6MessageType;

    #[test]
    fn dhcpv6_transaction_id_default_is_deterministic() {
        let first = Packet::from_layer(Dhcpv6::new()).compile().unwrap();
        let second = Packet::from_layer(Dhcpv6::default()).compile().unwrap();

        assert_eq!(first.as_bytes(), &[1, 0, 0, 0]);
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn dhcpv6_transaction_id_explicit_value_roundtrips() {
        let packet = Dhcpv6::new()
            .message_type(Dhcpv6MessageType::InformationRequest)
            .transaction_id(0x0012_3456);
        let bytes = Packet::from_layer(packet).compile().unwrap();

        assert_eq!(bytes.as_bytes(), &[11, 0x12, 0x34, 0x56]);
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();
        assert_eq!(decoded.transaction_id_value(), 0x0012_3456);
        assert_eq!(
            Packet::from_layer(decoded).compile().unwrap().as_bytes(),
            bytes.as_bytes(),
        );
    }

    #[test]
    fn dhcpv6_transaction_id_maximum_value_works() {
        let packet = Dhcpv6::new().try_transaction_id(0x00ff_ffff).unwrap();
        let bytes = Packet::from_layer(packet).compile().unwrap();

        assert_eq!(bytes.as_bytes(), &[1, 0xff, 0xff, 0xff]);
        assert_eq!(
            Dhcpv6::decode(bytes.as_bytes())
                .unwrap()
                .transaction_id_value(),
            0x00ff_ffff
        );
    }

    #[test]
    fn dhcpv6_transaction_id_invalid_typed_values_are_structured_errors() {
        let expected =
            CrafterError::invalid_field_value("dhcpv6.transaction_id", "value exceeds 24 bits");

        assert_eq!(
            Dhcpv6::new().try_transaction_id(0x0100_0000).unwrap_err(),
            expected,
        );
        assert_eq!(
            Packet::from_layer(Dhcpv6::new().transaction_id(0x0100_0000))
                .compile()
                .unwrap_err(),
            expected,
        );
    }
}

#[cfg(test)]
mod dhcpv6_client_decode_tests {
    use super::{
        append_dhcpv6_packet, is_dhcpv6_port_pair, looks_like_dhcpv6_client_payload, Dhcpv6,
    };
    use crate::error::CrafterError;
    use crate::packet::{NetworkLayer, Packet, Raw};
    use crate::protocols::dhcp::v6::{Dhcpv6MessageType, Dhcpv6Option};
    use crate::protocols::ip::v6::Ipv6;
    use crate::protocols::transport::Udp;

    #[test]
    fn dhcpv6_client_decode_append_packet_preserves_unknown_message_type() {
        let packet = append_dhcpv6_packet(Packet::new(), &[200, 0x01, 0x02, 0x03]).unwrap();
        let dhcpv6 = packet.layer::<Dhcpv6>().unwrap();

        assert_eq!(dhcpv6.message_type_value(), Dhcpv6MessageType::Unknown(200));
        assert_eq!(dhcpv6.transaction_id_value(), 0x010203);
    }

    #[test]
    fn dhcpv6_client_decode_reports_short_header_and_truncated_options() {
        assert_eq!(
            Dhcpv6::decode(&[1, 2, 3]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.client_server_header", 4, 3),
        );
        assert_eq!(
            Dhcpv6::decode(&[1, 0, 0, 0, 0, 23, 0, 4, 1]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.payload", 8, 5),
        );
    }

    #[test]
    fn dhcpv6_client_decode_port_and_payload_gate_is_conservative() {
        assert!(is_dhcpv6_port_pair(546, 547));
        assert!(is_dhcpv6_port_pair(547, 546));
        assert!(!is_dhcpv6_port_pair(547, 547));
        assert!(looks_like_dhcpv6_client_payload(&[1, 0, 0, 0]));
        assert!(looks_like_dhcpv6_client_payload(&[250, 0, 0, 0]));
        assert!(!looks_like_dhcpv6_client_payload(&[12, 0, 0, 0]));
        assert!(!looks_like_dhcpv6_client_payload(&[1, 0, 0]));
    }

    #[test]
    fn dhcpv6_client_decode_udp_registry_decodes_client_server_payload() {
        let packet = Ipv6::new()
            / Udp::dhcpv6_client()
            / Dhcpv6::new()
                .message_type(Dhcpv6MessageType::Request)
                .transaction_id(0x00010203)
                .option(Dhcpv6Option::empty(14u16));
        let bytes = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let dhcpv6 = decoded.layer::<Dhcpv6>().unwrap();
        assert_eq!(dhcpv6.message_type_value(), Dhcpv6MessageType::Request);
        assert_eq!(dhcpv6.transaction_id_value(), 0x010203);
        assert_eq!(dhcpv6.options_ref().len(), 1);
        assert!(decoded.layer::<Raw>().is_none());
    }
}

#[cfg(test)]
mod dhcpv6_relay_header_tests {
    use core::net::Ipv6Addr;

    use super::{Dhcpv6, Dhcpv6RelayHeader};
    use crate::field::FieldState;
    use crate::packet::{Layer, Packet};
    use crate::protocols::dhcp::v6::Dhcpv6MessageType;

    fn link() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 1)
    }

    fn peer() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 2, 0, 0, 0, 0, 2)
    }

    #[test]
    fn dhcpv6_relay_header_relay_forward_builder_sets_packet_data() {
        let relay = Dhcpv6::relay_forward(link(), peer());
        let header = relay.relay().unwrap();

        assert_eq!(relay.message_type_value(), Dhcpv6MessageType::RelayForw);
        assert_eq!(header.hop_count_value(), 0);
        assert_eq!(header.hop_count_state(), FieldState::Defaulted);
        assert_eq!(header.link_address_value(), link());
        assert_eq!(header.link_address_state(), FieldState::User);
        assert_eq!(header.peer_address_value(), peer());
        assert_eq!(header.peer_address_state(), FieldState::User);
        assert_eq!(relay.encoded_len(), 34);
    }

    #[test]
    fn dhcpv6_relay_header_relay_reply_builder_sets_packet_data() {
        let relay = Dhcpv6::relay_reply(link(), peer()).hop_count(2);
        let header = relay.relay().unwrap();

        assert_eq!(relay.message_type_value(), Dhcpv6MessageType::RelayRepl);
        assert_eq!(header.hop_count_value(), 2);
        assert_eq!(header.hop_count_state(), FieldState::User);
    }

    #[test]
    fn dhcpv6_relay_header_peer_address_setter_updates_packet_data() {
        let new_peer = Ipv6Addr::new(0x2001, 0x0db8, 3, 0, 0, 0, 0, 3);
        let relay = Dhcpv6::relay_forward(link(), peer()).peer_address(new_peer);

        assert_eq!(relay.relay().unwrap().peer_address_value(), new_peer);
    }

    #[test]
    fn dhcpv6_relay_header_summary_and_inspection_include_peer_address() {
        let relay = Dhcpv6::relay_forward(link(), peer()).hop_count(1);

        let summary = relay.summary();
        assert!(summary.contains("relay-forw"));
        assert!(summary.contains("hop_count=1"));
        assert!(summary.contains("peer_address=2001:db8:2::2"));
        assert!(relay
            .inspection_fields()
            .iter()
            .any(|(name, value)| *name == "peer_address" && value == "2001:db8:2::2"));
    }

    #[test]
    fn dhcpv6_relay_header_compile_emits_fixed_header() {
        let bytes = Packet::from_layer(Dhcpv6::relay_forward(link(), peer()))
            .compile()
            .unwrap();

        assert_eq!(bytes.as_bytes()[0], 12);
        assert_eq!(bytes.as_bytes()[1], 0);
        assert_eq!(&bytes.as_bytes()[2..18], &link().octets());
        assert_eq!(&bytes.as_bytes()[18..34], &peer().octets());
        assert_eq!(bytes.as_bytes().len(), 34);
    }

    #[test]
    fn dhcpv6_relay_header_standalone_header_builder_tracks_fields() {
        let header = Dhcpv6RelayHeader::new(link(), peer()).hop_count(3);

        assert_eq!(header.hop_count_value(), 3);
        assert_eq!(header.link_address_value(), link());
        assert_eq!(header.peer_address_value(), peer());
    }
}

#[cfg(test)]
mod dhcpv6_relay_codec_tests {
    use core::net::Ipv6Addr;

    use super::{
        append_dhcpv6_packet, is_dhcpv6_relay_port_pair, looks_like_dhcpv6_relay_payload, Dhcpv6,
    };
    use crate::error::CrafterError;
    use crate::packet::{NetworkLayer, Packet, Raw};
    use crate::protocols::dhcp::v6::{Dhcpv6MessageType, Dhcpv6Option};
    use crate::protocols::ip::v6::Ipv6;
    use crate::protocols::transport::Udp;

    const RELAY_MESSAGE_OPTION: u16 = 9;

    fn link(segment: u16) -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, segment, 0, 0, 0, 0, 1)
    }

    fn peer(segment: u16) -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, segment, 0, 0, 0, 0, 2)
    }

    #[test]
    fn dhcpv6_relay_codec_encodes_and_decodes_relay_message_option() {
        let client_bytes =
            Packet::from_layer(Dhcpv6::solicit(0x010203).option(Dhcpv6Option::empty(14u16)))
                .compile()
                .unwrap();
        let relay = Dhcpv6::relay_forward(link(1), peer(1))
            .hop_count(1)
            .option(Dhcpv6Option::raw(
                RELAY_MESSAGE_OPTION,
                client_bytes.as_bytes(),
            ));
        let relay_bytes = Packet::from_layer(relay).compile().unwrap();

        assert_eq!(relay_bytes.as_bytes()[0], 12);
        assert_eq!(relay_bytes.as_bytes()[1], 1);
        assert_eq!(&relay_bytes.as_bytes()[2..18], &link(1).octets());
        assert_eq!(&relay_bytes.as_bytes()[18..34], &peer(1).octets());

        let decoded = append_dhcpv6_packet(Packet::new(), relay_bytes.as_bytes()).unwrap();
        let relay = decoded.layer::<Dhcpv6>().unwrap();
        let relay_header = relay.relay().unwrap();
        assert_eq!(relay.message_type_value(), Dhcpv6MessageType::RelayForw);
        assert_eq!(relay_header.hop_count_value(), 1);
        assert_eq!(relay_header.link_address_value(), link(1));
        assert_eq!(relay_header.peer_address_value(), peer(1));
        assert_eq!(relay.options_ref().len(), 1);

        let nested_option = &relay.options_ref()[0];
        assert_eq!(nested_option.codepoint(), RELAY_MESSAGE_OPTION);
        let nested = Dhcpv6::decode(nested_option.payload()).unwrap();
        assert_eq!(nested.message_type_value(), Dhcpv6MessageType::Solicit);
        assert_eq!(nested.transaction_id_value(), 0x010203);
        assert_eq!(nested.options_ref()[0].codepoint(), 14);
    }

    #[test]
    fn dhcpv6_relay_codec_preserves_multiple_encapsulation_levels() {
        let client_bytes = Packet::from_layer(
            Dhcpv6::new()
                .message_type(Dhcpv6MessageType::Request)
                .transaction_id(0x040506),
        )
        .compile()
        .unwrap();
        let inner_relay_bytes =
            Packet::from_layer(Dhcpv6::relay_forward(link(1), peer(1)).hop_count(2).option(
                Dhcpv6Option::raw(RELAY_MESSAGE_OPTION, client_bytes.as_bytes()),
            ))
            .compile()
            .unwrap();
        let outer_relay_bytes =
            Packet::from_layer(Dhcpv6::relay_forward(link(2), peer(2)).hop_count(3).option(
                Dhcpv6Option::raw(RELAY_MESSAGE_OPTION, inner_relay_bytes.as_bytes()),
            ))
            .compile()
            .unwrap();

        let outer = Dhcpv6::decode(outer_relay_bytes.as_bytes()).unwrap();
        assert_eq!(outer.relay().unwrap().hop_count_value(), 3);
        assert_eq!(outer.relay().unwrap().link_address_value(), link(2));

        let inner = Dhcpv6::decode(outer.options_ref()[0].payload()).unwrap();
        assert_eq!(inner.message_type_value(), Dhcpv6MessageType::RelayForw);
        assert_eq!(inner.relay().unwrap().hop_count_value(), 2);
        assert_eq!(inner.relay().unwrap().link_address_value(), link(1));

        let client = Dhcpv6::decode(inner.options_ref()[0].payload()).unwrap();
        assert_eq!(client.message_type_value(), Dhcpv6MessageType::Request);
        assert_eq!(client.transaction_id_value(), 0x040506);
    }

    #[test]
    fn dhcpv6_relay_codec_hop_count_roundtrips() {
        let relay = Dhcpv6::relay_reply(link(4), peer(4)).hop_count(31);
        let bytes = Packet::from_layer(relay).compile().unwrap();
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();

        assert_eq!(decoded.message_type_value(), Dhcpv6MessageType::RelayRepl);
        assert_eq!(decoded.relay().unwrap().hop_count_value(), 31);
        assert_eq!(
            Packet::from_layer(decoded).compile().unwrap().as_bytes(),
            bytes.as_bytes(),
        );
    }

    #[test]
    fn dhcpv6_relay_codec_reports_truncated_relay_header() {
        let mut bytes = vec![12, 0];
        bytes.resize(33, 0);

        assert_eq!(
            Dhcpv6::decode(&bytes).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.relay_header", 34, 33),
        );
    }

    #[test]
    fn dhcpv6_relay_codec_udp_registry_decodes_server_relay_payload() {
        assert!(is_dhcpv6_relay_port_pair(547, 547));

        let payload = Packet::from_layer(Dhcpv6::relay_reply(link(5), peer(5)))
            .compile()
            .unwrap();
        assert!(looks_like_dhcpv6_relay_payload(payload.as_bytes()));
        assert!(!looks_like_dhcpv6_relay_payload(&payload.as_bytes()[..33]));

        let packet = Ipv6::new()
            / Udp::new().source_port(547).destination_port(547)
            / Dhcpv6::relay_reply(link(5), peer(5)).hop_count(4);
        let bytes = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let dhcpv6 = decoded.layer::<Dhcpv6>().unwrap();
        assert_eq!(dhcpv6.message_type_value(), Dhcpv6MessageType::RelayRepl);
        assert_eq!(dhcpv6.relay().unwrap().hop_count_value(), 4);
        assert_eq!(dhcpv6.relay().unwrap().peer_address_value(), peer(5));
        assert!(decoded.layer::<Raw>().is_none());
    }
}

#[cfg(test)]
mod dhcpv6_udp_binding_tests {
    use core::net::Ipv6Addr;

    use super::{
        is_dhcpv6_port_pair, is_dhcpv6_relay_port_pair, looks_like_dhcpv6_payload, Dhcpv6,
    };
    use crate::packet::{NetworkLayer, Packet, Raw};
    use crate::protocols::dhcp::v6::{
        Dhcpv6Leasequery, Dhcpv6LeasequeryType, Dhcpv6MessageType, Dhcpv6Option,
    };
    use crate::protocols::ip::v6::Ipv6;
    use crate::protocols::transport::Udp;

    fn link() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 6, 0, 0, 0, 0, 1)
    }

    fn peer() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 6, 0, 0, 0, 0, 2)
    }

    #[test]
    fn dhcpv6_udp_binding_payload_gate_is_port_and_message_type_aware() {
        let mut relay = vec![12, 0];
        relay.resize(34, 0);

        assert!(is_dhcpv6_port_pair(546, 547));
        assert!(is_dhcpv6_port_pair(547, 546));
        assert!(is_dhcpv6_relay_port_pair(547, 547));
        assert!(!is_dhcpv6_port_pair(546, 546));
        assert!(!is_dhcpv6_relay_port_pair(546, 547));

        assert!(looks_like_dhcpv6_payload(546, 547, &[1, 0, 0, 0]));
        assert!(looks_like_dhcpv6_payload(547, 546, &[7, 0, 0, 1]));
        assert!(!looks_like_dhcpv6_payload(546, 547, &[12, 0, 0, 0]));
        assert!(!looks_like_dhcpv6_payload(546, 547, &[1, 0, 0]));

        assert!(looks_like_dhcpv6_payload(547, 547, &relay));
        assert!(looks_like_dhcpv6_payload(547, 547, &[14, 0, 0, 2]));
        assert!(looks_like_dhcpv6_payload(547, 547, &[15, 0, 0, 3]));
        assert!(!looks_like_dhcpv6_payload(547, 547, &[12, 0, 0, 0]));
        assert!(!looks_like_dhcpv6_payload(547, 547, &[1, 0, 0, 0]));
        assert!(!looks_like_dhcpv6_payload(547, 547, &[22, 0, 0, 4]));
        assert!(!looks_like_dhcpv6_payload(547, 547, &[200, 0, 0, 5]));
        assert!(!looks_like_dhcpv6_payload(546, 546, &[1, 0, 0, 0]));
    }

    #[test]
    fn dhcpv6_udp_binding_decodes_client_server_payload() {
        let packet = Ipv6::new() / Udp::dhcpv6_client() / Dhcpv6::solicit(0x010203);
        let bytes = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let dhcpv6 = decoded.layer::<Dhcpv6>().unwrap();
        assert_eq!(dhcpv6.message_type_value(), Dhcpv6MessageType::Solicit);
        assert_eq!(dhcpv6.transaction_id_value(), 0x010203);
        assert!(decoded.layer::<Raw>().is_none());
    }

    #[test]
    fn dhcpv6_udp_binding_decodes_relay_payload() {
        let packet = Ipv6::new() / Udp::dhcpv6_relay() / Dhcpv6::relay_forward(link(), peer());
        let bytes = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let dhcpv6 = decoded.layer::<Dhcpv6>().unwrap();
        assert_eq!(dhcpv6.message_type_value(), Dhcpv6MessageType::RelayForw);
        assert_eq!(dhcpv6.relay().unwrap().link_address_value(), link());
        assert_eq!(dhcpv6.relay().unwrap().peer_address_value(), peer());
        assert!(decoded.layer::<Raw>().is_none());
    }

    #[test]
    fn dhcpv6_udp_binding_decodes_base_leasequery_on_server_ports() {
        let query = Dhcpv6Leasequery::new(Dhcpv6LeasequeryType::ByAddress, link())
            .option(Dhcpv6Option::client_id([0, 3, 0, 1, 0xaa, 0xbb]));
        let packet = Ipv6::new()
            / Udp::dhcpv6_relay()
            / Dhcpv6::leasequery(0x010203)
                .leasequery_option(query.clone())
                .unwrap();
        let bytes = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let dhcpv6 = decoded.layer::<Dhcpv6>().unwrap();
        assert_eq!(dhcpv6.message_type_value(), Dhcpv6MessageType::LeaseQuery);
        assert_eq!(dhcpv6.transaction_id_value(), 0x010203);
        assert_eq!(dhcpv6.leasequery_value().unwrap(), Some(query));
        assert!(decoded.layer::<Raw>().is_none());
    }

    #[test]
    fn dhcpv6_udp_binding_leaves_unrelated_payload_raw() {
        let packet = Ipv6::new() / Udp::dhcpv6_client() / Raw::from_bytes([12, 0, 0, 0]);
        let bytes = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        assert!(decoded.layer::<Dhcpv6>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[12, 0, 0, 0],);
    }

    #[test]
    fn dhcpv6_udp_binding_leaves_non_udp_server_port_payload_raw() {
        let packet = Ipv6::new() / Udp::dhcpv6_relay() / Raw::from_bytes([22, 0, 0, 4]);
        let bytes = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        assert!(decoded.layer::<Dhcpv6>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[22, 0, 0, 4],);
    }
}

#[cfg(test)]
mod dhcpv6_relay_options_tests {
    use core::net::Ipv6Addr;

    use super::Dhcpv6;
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{
        dhcpv6_rsoo_option_permission, dhcpv6_rsoo_option_permitted, Dhcpv6ClientLinkLayerAddress,
        Dhcpv6Duid, Dhcpv6MessageType, Dhcpv6Option, Dhcpv6RelaySuppliedOptions, Dhcpv6RemoteId,
        Dhcpv6RsooOptionPermission, DHCPV6_OPTION_CLIENT_LINKLAYER_ADDR,
        DHCPV6_OPTION_ERP_LOCAL_DOMAIN_NAME, DHCPV6_OPTION_INTERFACE_ID, DHCPV6_OPTION_RELAY_MSG,
        DHCPV6_OPTION_RSOO,
    };

    fn link() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 44, 0, 0, 0, 0, 1)
    }

    fn peer() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 44, 0, 0, 0, 0, 2)
    }

    #[test]
    fn dhcpv6_relay_options_encapsulate_relay_message() {
        let inner = Dhcpv6::solicit(0x010203).client_id([0x00, 0x03, 0xaa, 0xbb]);
        let inner_bytes = Packet::from_layer(inner.clone()).compile().unwrap();
        let relay = Dhcpv6::relay_forward(link(), peer())
            .interface_id(b"access-loop-7".as_slice())
            .relay_message(inner)
            .unwrap();

        let bytes = Packet::from_layer(relay).compile().unwrap();
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();

        assert_eq!(decoded.message_type_value(), Dhcpv6MessageType::RelayForw);
        assert_eq!(decoded.interface_id_value(), Some(&b"access-loop-7"[..]));
        assert_eq!(decoded.relay_msg_value(), Some(inner_bytes.as_bytes()));

        let relayed = decoded.relayed_message_value().unwrap().unwrap();
        assert_eq!(relayed.message_type_value(), Dhcpv6MessageType::Solicit);
        assert_eq!(relayed.transaction_id_value(), 0x010203);
        assert_eq!(
            decoded.options_ref()[1].codepoint(),
            DHCPV6_OPTION_RELAY_MSG
        );
    }

    #[test]
    fn dhcpv6_relay_options_preserve_interface_and_identifier_bytes() {
        let remote_id = Dhcpv6RemoteId::new(3561, b"slot/1/port/2".as_slice());
        let relay_duid = Dhcpv6Duid::ll(1, [0x02, 0x00, 0x5e, 0x44, 0x00, 0x01]);
        let relay = Dhcpv6::relay_forward(link(), peer())
            .interface_id([0xde, 0xad, 0xbe, 0xef])
            .remote_id(remote_id.clone())
            .subscriber_id(b"subscriber-123".as_slice())
            .relay_id(relay_duid.clone());

        assert_eq!(
            relay.interface_id_value(),
            Some(&[0xde, 0xad, 0xbe, 0xef][..])
        );
        assert_eq!(relay.remote_id_value().unwrap(), Some(remote_id.clone()));
        assert_eq!(remote_id.enterprise_number(), 3561);
        assert_eq!(remote_id.remote_id(), b"slot/1/port/2");
        assert_eq!(relay.subscriber_id_value(), Some(&b"subscriber-123"[..]));
        assert_eq!(relay.relay_duid_value().unwrap(), Some(relay_duid.clone()));

        let bytes = Packet::from_layer(relay).compile().unwrap();
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();
        assert_eq!(
            decoded.interface_id_value(),
            Some(&[0xde, 0xad, 0xbe, 0xef][..])
        );
        assert_eq!(decoded.remote_id_value().unwrap(), Some(remote_id));
        assert_eq!(decoded.relay_duid_value().unwrap(), Some(relay_duid));
        assert_eq!(
            decoded.options_ref()[0].codepoint(),
            DHCPV6_OPTION_INTERFACE_ID
        );
    }

    #[test]
    fn dhcpv6_relay_options_client_link_layer_address_roundtrips() {
        let client = Dhcpv6ClientLinkLayerAddress::ethernet([0x02, 0x00, 0x5e, 0x44, 0x00, 0x02]);
        let option = Dhcpv6Option::client_link_layer_addr(client.clone());

        assert_eq!(option.codepoint(), DHCPV6_OPTION_CLIENT_LINKLAYER_ADDR);
        assert_eq!(
            option.payload(),
            &[0x00, 0x01, 0x02, 0x00, 0x5e, 0x44, 0x00, 0x02],
        );
        assert_eq!(
            option.client_link_layer_addr_value().unwrap(),
            Some(client.clone()),
        );
        assert_eq!(client.hardware_type(), 1);
        assert_eq!(
            client.link_layer_address(),
            &[0x02, 0x00, 0x5e, 0x44, 0x00, 0x02],
        );

        let relay = Dhcpv6::relay_forward(link(), peer()).client_link_layer_addr(client.clone());
        let decoded =
            Dhcpv6::decode(Packet::from_layer(relay).compile().unwrap().as_bytes()).unwrap();
        assert_eq!(
            decoded.client_link_layer_addr_value().unwrap(),
            Some(client),
        );
    }

    #[test]
    fn dhcpv6_relay_options_rsoo_preserves_unknown_options_and_permission_metadata() {
        let permitted = Dhcpv6Option::raw(DHCPV6_OPTION_ERP_LOCAL_DOMAIN_NAME, b"example.test");
        let unknown = Dhcpv6Option::raw(65_000u16, [0xde, 0xad, 0xbe, 0xef]);
        let rsoo = Dhcpv6RelaySuppliedOptions::new(vec![permitted.clone(), unknown.clone()]);
        let option = Dhcpv6Option::relay_supplied_options(rsoo.clone()).unwrap();

        assert_eq!(option.codepoint(), DHCPV6_OPTION_RSOO);
        assert_eq!(
            option.relay_supplied_options_value().unwrap(),
            Some(rsoo.clone()),
        );
        assert_eq!(rsoo.options(), &[permitted.clone(), unknown.clone()]);
        assert!(dhcpv6_rsoo_option_permitted(
            DHCPV6_OPTION_ERP_LOCAL_DOMAIN_NAME
        ));
        assert!(!dhcpv6_rsoo_option_permitted(65_000));
        assert_eq!(
            dhcpv6_rsoo_option_permission(65_000),
            Dhcpv6RsooOptionPermission::NotPermitted,
        );

        let relay = Dhcpv6::relay_forward(link(), peer())
            .relay_supplied_options(rsoo.clone())
            .unwrap();
        let decoded =
            Dhcpv6::decode(Packet::from_layer(relay).compile().unwrap().as_bytes()).unwrap();
        assert_eq!(decoded.relay_supplied_options_value().unwrap(), Some(rsoo));
        assert_eq!(
            dhcpv6_rsoo_option_permission(DHCPV6_OPTION_ERP_LOCAL_DOMAIN_NAME),
            Dhcpv6RsooOptionPermission::Permitted,
        );
    }

    #[test]
    fn dhcpv6_relay_options_malformed_lengths_are_structured() {
        assert_eq!(
            Dhcpv6RemoteId::decode(&[0x00, 0x00, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.remote_id.enterprise_number", 4, 3),
        );
        assert_eq!(
            Dhcpv6ClientLinkLayerAddress::decode(&[0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "dhcpv6.option.client_linklayer_addr.hardware_type",
                2,
                1,
            ),
        );

        let malformed_rsoo = Dhcpv6Option::raw(DHCPV6_OPTION_RSOO, [0x00, 0x01, 0x00, 0x04, 0xaa]);
        assert_eq!(
            malformed_rsoo.relay_supplied_options_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.payload", 8, 5),
        );
    }
}

#[cfg(test)]
mod dhcpv6_basic_options_layer_tests {
    use super::Dhcpv6;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{Dhcpv6MessageType, Dhcpv6OptionCode};

    #[test]
    fn dhcpv6_basic_options_layer_helpers_append_query_and_roundtrip() {
        let message = Dhcpv6::solicit(0x010203)
            .client_id([0x00, 0x03, 0xaa, 0xbb])
            .server_id([0x00, 0x01, 0xcc, 0xdd])
            .oro([23u16, 24u16])
            .preference(99)
            .elapsed_time(123)
            .rapid_commit();

        assert_eq!(
            message.client_id_value(),
            Some(&[0x00, 0x03, 0xaa, 0xbb][..])
        );
        assert_eq!(
            message.server_id_value(),
            Some(&[0x00, 0x01, 0xcc, 0xdd][..])
        );
        assert_eq!(
            message.oro_value().unwrap(),
            Some(vec![
                Dhcpv6OptionCode::from_code(23),
                Dhcpv6OptionCode::from_code(24),
            ]),
        );
        assert_eq!(message.preference_value().unwrap(), Some(99));
        assert_eq!(message.elapsed_time_value().unwrap(), Some(123));
        assert!(message.rapid_commit_present().unwrap());

        let bytes = Packet::from_layer(message).compile().unwrap();
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();

        assert_eq!(decoded.message_type_value(), Dhcpv6MessageType::Solicit);
        assert_eq!(decoded.transaction_id_value(), 0x010203);
        assert_eq!(
            decoded.client_id_value(),
            Some(&[0x00, 0x03, 0xaa, 0xbb][..])
        );
        assert_eq!(
            decoded.oro_value().unwrap(),
            Some(vec![
                Dhcpv6OptionCode::from_code(23),
                Dhcpv6OptionCode::from_code(24),
            ]),
        );
        assert_eq!(decoded.preference_value().unwrap(), Some(99));
        assert_eq!(decoded.elapsed_time_value().unwrap(), Some(123));
        assert!(decoded.rapid_commit_present().unwrap());
    }
}

#[cfg(test)]
mod dhcpv6_reconfigure_tests {
    use super::Dhcpv6;
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{
        Dhcpv6MessageType, Dhcpv6Option, Dhcpv6StatusCode, DHCPV6_ADDR_REG_INFORM,
        DHCPV6_ADDR_REG_REPLY, DHCPV6_OPTION_ADDR_REG_ENABLE, DHCPV6_OPTION_RECONF_ACCEPT,
        DHCPV6_OPTION_RECONF_MSG,
    };

    #[test]
    fn dhcpv6_reconfigure_message_option_accepts_registered_target_values() {
        let renew = Dhcpv6Option::reconfigure_message(Dhcpv6MessageType::Renew);
        let information_request =
            Dhcpv6Option::reconfigure_message(Dhcpv6MessageType::InformationRequest);

        assert_eq!(renew.codepoint(), DHCPV6_OPTION_RECONF_MSG);
        assert_eq!(renew.payload(), &[Dhcpv6MessageType::Renew.code()]);
        assert_eq!(
            renew.reconfigure_message_value().unwrap(),
            Some(Dhcpv6MessageType::Renew),
        );
        assert_eq!(
            information_request.reconfigure_message_value().unwrap(),
            Some(Dhcpv6MessageType::InformationRequest),
        );
    }

    #[test]
    fn dhcpv6_reconfigure_message_option_preserves_unknown_values() {
        let option = Dhcpv6Option::reconfigure_message(Dhcpv6MessageType::Unknown(250));

        assert_eq!(option.payload(), &[250]);
        assert_eq!(
            option.reconfigure_message_value().unwrap(),
            Some(Dhcpv6MessageType::Unknown(250)),
        );
    }

    #[test]
    fn dhcpv6_reconfigure_accept_option_is_zero_length() {
        let option = Dhcpv6Option::reconfigure_accept();

        assert_eq!(option.codepoint(), DHCPV6_OPTION_RECONF_ACCEPT);
        assert_eq!(option.payload(), &[]);
        assert!(option.reconfigure_accept_present().unwrap());
        assert_eq!(option.encode().unwrap(), vec![0x00, 0x14, 0x00, 0x00],);
    }

    #[test]
    fn dhcpv6_reconfigure_options_reject_bad_lengths() {
        let empty_reconfigure = Dhcpv6Option::empty(DHCPV6_OPTION_RECONF_MSG);
        let long_reconfigure = Dhcpv6Option::raw(DHCPV6_OPTION_RECONF_MSG, [5, 11]);
        let bad_accept = Dhcpv6Option::raw(DHCPV6_OPTION_RECONF_ACCEPT, [1]);

        assert_eq!(
            empty_reconfigure.reconfigure_message_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.reconf_msg",
                "payload length does not match option format",
            ),
        );
        assert_eq!(
            long_reconfigure.reconfigure_message_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.reconf_msg",
                "payload length does not match option format",
            ),
        );
        assert_eq!(
            bad_accept.reconfigure_accept_present().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.reconf_accept",
                "payload length does not match option format",
            ),
        );
        assert_eq!(long_reconfigure.payload(), &[5, 11]);
        assert_eq!(bad_accept.payload(), &[1]);
    }

    #[test]
    fn dhcpv6_reconfigure_packet_builder_roundtrips_message_option() {
        let message = Dhcpv6::reconfigure_with_message(0x010203, Dhcpv6MessageType::Renew)
            .reconfigure_accept();

        assert_eq!(message.message_type_value(), Dhcpv6MessageType::Reconfigure);
        assert_eq!(
            message.reconfigure_message_value().unwrap(),
            Some(Dhcpv6MessageType::Renew),
        );
        assert!(message.reconfigure_accept_present().unwrap());

        let bytes = Packet::from_layer(message).compile().unwrap();
        assert_eq!(
            bytes.as_bytes(),
            &[10, 0x01, 0x02, 0x03, 0x00, 0x13, 0x00, 0x01, 0x05, 0x00, 0x14, 0x00, 0x00,],
        );

        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();
        assert_eq!(decoded.message_type_value(), Dhcpv6MessageType::Reconfigure);
        assert_eq!(
            decoded.reconfigure_message_value().unwrap(),
            Some(Dhcpv6MessageType::Renew),
        );
        assert!(decoded.reconfigure_accept_present().unwrap());
    }

    #[test]
    fn dhcpv6_reconfigure_packet_decodes_unknown_message_option() {
        let bytes = [10, 0xaa, 0xbb, 0xcc, 0x00, 0x13, 0x00, 0x01, 250];
        let decoded = Dhcpv6::decode(&bytes).unwrap();

        assert_eq!(decoded.transaction_id_value(), 0xaabbcc);
        assert_eq!(
            decoded.reconfigure_message_value().unwrap(),
            Some(Dhcpv6MessageType::Unknown(250)),
        );
    }

    #[test]
    fn dhcpv6_address_registration_message_codepoints_and_enable_option() {
        let enable = Dhcpv6Option::addr_reg_enable();

        assert_eq!(
            Dhcpv6MessageType::AddrRegInform.code(),
            DHCPV6_ADDR_REG_INFORM
        );
        assert_eq!(
            Dhcpv6MessageType::AddrRegReply.code(),
            DHCPV6_ADDR_REG_REPLY
        );
        assert_eq!(enable.codepoint(), DHCPV6_OPTION_ADDR_REG_ENABLE);
        assert_eq!(enable.payload(), &[]);
        assert!(enable.addr_reg_enable_present().unwrap());

        assert_eq!(
            Dhcpv6Option::raw(DHCPV6_OPTION_ADDR_REG_ENABLE, [1])
                .addr_reg_enable_present()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.addr_reg_enable",
                "payload length does not match option format",
            ),
        );
    }

    #[test]
    fn dhcpv6_address_registration_inform_roundtrips_unknown_options() {
        let unknown = Dhcpv6Option::raw(65_004u16, [0xde, 0xad]);
        let message = Dhcpv6::addr_reg_inform(0x010203)
            .addr_reg_enable()
            .client_id([0, 3, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
            .option(unknown.clone());
        let bytes = Packet::from_layer(message).compile().unwrap();
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();

        assert_eq!(
            decoded.message_type_value(),
            Dhcpv6MessageType::AddrRegInform
        );
        assert_eq!(decoded.transaction_id_value(), 0x010203);
        assert!(decoded.addr_reg_enable_present().unwrap());
        assert_eq!(decoded.options_ref().last(), Some(&unknown));
        assert_eq!(Packet::from_layer(decoded).compile().unwrap(), bytes);
    }

    #[test]
    fn dhcpv6_address_registration_reply_carries_status_only_as_packet_data() {
        let message = Dhcpv6::addr_reg_reply(0x0a0b0c)
            .status(Dhcpv6StatusCode::AddressInUse)
            .option(Dhcpv6Option::raw(65_005u16, [1, 2, 3]));
        let decoded =
            Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes()).unwrap();
        let status = decoded.status_code_value().unwrap().unwrap();

        assert_eq!(
            decoded.message_type_value(),
            Dhcpv6MessageType::AddrRegReply
        );
        assert_eq!(status.status(), Dhcpv6StatusCode::AddressInUse);
        assert_eq!(status.message_bytes(), &[]);
        assert_eq!(decoded.options_ref()[1].payload(), &[1, 2, 3]);
    }
}

#[cfg(test)]
mod dhcpv6_leasequery_base_tests {
    use core::net::Ipv6Addr;

    use super::Dhcpv6;
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{
        Dhcpv6ClientData, Dhcpv6Leasequery, Dhcpv6LeasequeryType, Dhcpv6MessageType, Dhcpv6Option,
        DHCPV6_LEASEQUERY, DHCPV6_LEASEQUERY_REPLY, DHCPV6_OPTION_CLIENT_DATA,
        DHCPV6_OPTION_CLT_TIME, DHCPV6_OPTION_LQ_CLIENT_LINK, DHCPV6_OPTION_LQ_QUERY,
    };

    fn link() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 55, 0, 0, 0, 0, 1)
    }

    #[test]
    fn dhcpv6_leasequery_base_message_codepoints_and_query_payloads() {
        let nested = Dhcpv6Option::client_id([0, 3, 0, 1, 0, 1, 2, 3]);
        let query =
            Dhcpv6Leasequery::new(Dhcpv6LeasequeryType::ByAddress, link()).option(nested.clone());
        let option = Dhcpv6Option::leasequery(query.clone()).unwrap();

        assert_eq!(Dhcpv6MessageType::LeaseQuery.code(), DHCPV6_LEASEQUERY);
        assert_eq!(
            Dhcpv6MessageType::LeaseQueryReply.code(),
            DHCPV6_LEASEQUERY_REPLY
        );
        assert_eq!(option.codepoint(), DHCPV6_OPTION_LQ_QUERY);

        let decoded = option.leasequery_value().unwrap().unwrap();
        assert_eq!(decoded, query);
        assert_eq!(decoded.query_type(), Dhcpv6LeasequeryType::ByAddress);
        assert_eq!(decoded.link_address(), link());
        assert_eq!(decoded.options_ref(), &[nested]);
    }

    #[test]
    fn dhcpv6_leasequery_base_preserves_unknown_query_types() {
        let query = Dhcpv6Leasequery::new(Dhcpv6LeasequeryType::Unknown(250), link());
        let decoded = Dhcpv6Option::leasequery(query.clone())
            .unwrap()
            .leasequery_value()
            .unwrap()
            .unwrap();

        assert_eq!(decoded, query);
        assert_eq!(decoded.query_type(), Dhcpv6LeasequeryType::Unknown(250));
    }

    #[test]
    fn dhcpv6_leasequery_base_request_and_reply_roundtrip() {
        let query = Dhcpv6Leasequery::new(Dhcpv6LeasequeryType::ByClientId, link())
            .option(Dhcpv6Option::client_id([0, 3, 0, 1, 0xaa, 0xbb]));
        let request = Dhcpv6::leasequery(0x010203)
            .leasequery_option(query.clone())
            .unwrap();
        let decoded_request =
            Dhcpv6::decode(Packet::from_layer(request).compile().unwrap().as_bytes()).unwrap();

        assert_eq!(
            decoded_request.message_type_value(),
            Dhcpv6MessageType::LeaseQuery
        );
        assert_eq!(decoded_request.leasequery_value().unwrap(), Some(query));

        let client_data =
            Dhcpv6ClientData::new().option(Dhcpv6Option::raw(65_006u16, [0xde, 0xad]));
        let reply_link = Ipv6Addr::new(0x2001, 0x0db8, 55, 0, 0, 0, 0, 2);
        let reply = Dhcpv6::leasequery_reply(0x010203)
            .client_data(client_data.clone())
            .unwrap()
            .client_time(300)
            .leasequery_client_link([reply_link])
            .leasequery_relay_data([0xaa, 0xbb, 0xcc]);
        let decoded_reply =
            Dhcpv6::decode(Packet::from_layer(reply).compile().unwrap().as_bytes()).unwrap();

        assert_eq!(
            decoded_reply.message_type_value(),
            Dhcpv6MessageType::LeaseQueryReply
        );
        assert_eq!(
            decoded_reply.client_data_value().unwrap(),
            Some(client_data)
        );
        assert_eq!(decoded_reply.client_time_value().unwrap(), Some(300));
        assert_eq!(
            decoded_reply.leasequery_client_link_value().unwrap(),
            Some(vec![reply_link]),
        );
        assert_eq!(
            decoded_reply.leasequery_relay_data_value(),
            Some(&[0xaa, 0xbb, 0xcc][..]),
        );
    }

    #[test]
    fn dhcpv6_leasequery_base_rejects_malformed_lengths() {
        let short_query = Dhcpv6Option::raw(DHCPV6_OPTION_LQ_QUERY, vec![0; 16]);
        assert_eq!(
            short_query.leasequery_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.lq_query", 17, 16),
        );

        let bad_client_data =
            Dhcpv6Option::raw(DHCPV6_OPTION_CLIENT_DATA, [0x00, 0x01, 0x00, 0x02, 0xff]);
        assert_eq!(
            bad_client_data.client_data_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.payload", 6, 5),
        );

        let bad_time = Dhcpv6Option::raw(DHCPV6_OPTION_CLT_TIME, [0, 0, 0]);
        assert_eq!(
            bad_time.client_time_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.clt_time",
                "payload length does not match option format",
            ),
        );

        let bad_link = Dhcpv6Option::raw(DHCPV6_OPTION_LQ_CLIENT_LINK, [0; 15]);
        assert_eq!(
            bad_link.leasequery_client_link_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.lq_client_link",
                "payload length must be a multiple of 16 bytes",
            ),
        );
    }
}

#[cfg(test)]
mod dhcpv6_bulk_leasequery_tests {
    use super::Dhcpv6;
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{
        Dhcpv6ClientData, Dhcpv6MessageType, Dhcpv6Option, Dhcpv6StatusCode,
        DHCPV6_LEASEQUERY_DATA, DHCPV6_LEASEQUERY_DONE, DHCPV6_OPTION_LQ_BASE_TIME,
        DHCPV6_OPTION_LQ_END_TIME, DHCPV6_OPTION_LQ_START_TIME,
    };

    #[test]
    fn dhcpv6_bulk_leasequery_message_codepoints_are_named() {
        assert_eq!(
            Dhcpv6MessageType::LeaseQueryData.code(),
            DHCPV6_LEASEQUERY_DATA
        );
        assert_eq!(
            Dhcpv6MessageType::LeaseQueryDone.code(),
            DHCPV6_LEASEQUERY_DONE
        );
    }

    #[test]
    fn dhcpv6_bulk_leasequery_data_roundtrips_client_payloads() {
        let client_data =
            Dhcpv6ClientData::new().option(Dhcpv6Option::raw(65_007u16, [0xaa, 0xbb]));
        let message = Dhcpv6::leasequery_data(0x010203)
            .client_data(client_data.clone())
            .unwrap()
            .client_time(60)
            .leasequery_base_time(1_000)
            .option(Dhcpv6Option::raw(65_008u16, [0xde, 0xad]));
        let decoded =
            Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes()).unwrap();

        assert_eq!(
            decoded.message_type_value(),
            Dhcpv6MessageType::LeaseQueryData
        );
        assert_eq!(decoded.client_data_value().unwrap(), Some(client_data));
        assert_eq!(decoded.client_time_value().unwrap(), Some(60));
        assert_eq!(decoded.leasequery_base_time_value().unwrap(), Some(1_000));
        assert_eq!(
            decoded.options_ref().last().unwrap().payload(),
            &[0xde, 0xad]
        );
    }

    #[test]
    fn dhcpv6_bulk_leasequery_done_roundtrips_status_and_window_times() {
        let message = Dhcpv6::leasequery_done(0x0a0b0c)
            .status(Dhcpv6StatusCode::QueryTerminated)
            .leasequery_start_time(10)
            .leasequery_end_time(20);
        let decoded =
            Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes()).unwrap();

        assert_eq!(
            decoded.message_type_value(),
            Dhcpv6MessageType::LeaseQueryDone
        );
        assert_eq!(
            decoded.status_code_value().unwrap().unwrap().status(),
            Dhcpv6StatusCode::QueryTerminated,
        );
        assert_eq!(decoded.leasequery_start_time_value().unwrap(), Some(10));
        assert_eq!(decoded.leasequery_end_time_value().unwrap(), Some(20));
    }

    #[test]
    fn dhcpv6_bulk_leasequery_rejects_malformed_time_options() {
        for (option, context) in [
            (
                Dhcpv6Option::raw(DHCPV6_OPTION_LQ_BASE_TIME, [0, 0, 0]),
                "dhcpv6.option.lq_base_time",
            ),
            (
                Dhcpv6Option::raw(DHCPV6_OPTION_LQ_START_TIME, [0, 0, 0]),
                "dhcpv6.option.lq_start_time",
            ),
            (
                Dhcpv6Option::raw(DHCPV6_OPTION_LQ_END_TIME, [0, 0, 0]),
                "dhcpv6.option.lq_end_time",
            ),
        ] {
            let error = match option.codepoint() {
                DHCPV6_OPTION_LQ_BASE_TIME => option.leasequery_base_time_value().unwrap_err(),
                DHCPV6_OPTION_LQ_START_TIME => option.leasequery_start_time_value().unwrap_err(),
                DHCPV6_OPTION_LQ_END_TIME => option.leasequery_end_time_value().unwrap_err(),
                _ => unreachable!(),
            };
            assert_eq!(
                error,
                CrafterError::invalid_field_value(
                    context,
                    "payload length does not match option format",
                ),
            );
        }
    }
}

#[cfg(test)]
mod dhcpv6_active_leasequery_tests {
    use super::Dhcpv6;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{
        Dhcpv6MessageType, Dhcpv6Option, Dhcpv6StatusCode, DHCPV6_ACTIVE_LEASEQUERY,
        DHCPV6_STARTTLS,
    };

    #[test]
    fn dhcpv6_active_leasequery_constructors_use_registered_codepoints() {
        let active = Dhcpv6::active_leasequery(0x010203);
        let starttls = Dhcpv6::starttls(0x0a0b0c);

        assert_eq!(
            Dhcpv6MessageType::ActiveLeaseQuery.code(),
            DHCPV6_ACTIVE_LEASEQUERY
        );
        assert_eq!(Dhcpv6MessageType::StartTls.code(), DHCPV6_STARTTLS);
        assert_eq!(
            active.message_type_value(),
            Dhcpv6MessageType::ActiveLeaseQuery
        );
        assert_eq!(starttls.message_type_value(), Dhcpv6MessageType::StartTls);
    }

    #[test]
    fn dhcpv6_active_leasequery_decodes_options_and_summary_labels() {
        let message = Dhcpv6::active_leasequery(0x010203)
            .leasequery_base_time(1_000)
            .status(Dhcpv6StatusCode::CatchUpComplete)
            .option(Dhcpv6Option::raw(65_009u16, [0xca, 0xfe]));
        let decoded =
            Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes()).unwrap();

        assert_eq!(
            decoded.message_type_value(),
            Dhcpv6MessageType::ActiveLeaseQuery,
        );
        assert_eq!(decoded.leasequery_base_time_value().unwrap(), Some(1_000));
        assert_eq!(
            decoded.status_code_value().unwrap().unwrap().status(),
            Dhcpv6StatusCode::CatchUpComplete,
        );
        assert_eq!(
            decoded.options_ref().last().unwrap().payload(),
            &[0xca, 0xfe]
        );
        assert!(crate::packet::Layer::summary(&decoded).contains("activeleasequery"));
    }

    #[test]
    fn dhcpv6_starttls_is_packet_data_only_and_roundtrips_raw_options() {
        let message = Dhcpv6::starttls(0x0a0b0c)
            .status(Dhcpv6StatusCode::TlsConnectionRefused)
            .option(Dhcpv6Option::raw(65_010u16, [1, 2, 3, 4]));
        let bytes = Packet::from_layer(message).compile().unwrap();
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();

        assert_eq!(decoded.message_type_value(), Dhcpv6MessageType::StartTls);
        assert_eq!(
            decoded.status_code_value().unwrap().unwrap().status(),
            Dhcpv6StatusCode::TlsConnectionRefused,
        );
        assert_eq!(
            decoded.options_ref().last().unwrap().payload(),
            &[1, 2, 3, 4]
        );
        assert!(crate::packet::Layer::summary(&decoded).contains("starttls"));
        assert_eq!(Packet::from_layer(decoded).compile().unwrap(), bytes);
    }
}

#[cfg(test)]
mod dhcpv6_dhcpv4_query_tests {
    use super::Dhcpv6;
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v4::Dhcpv4;
    use crate::protocols::dhcp::v6::{
        Dhcpv6MessageType, Dhcpv6Option, DHCPV6_DHCPV4_QUERY, DHCPV6_DHCPV4_RESPONSE,
        DHCPV6_OPTION_DHCPV4_MSG,
    };

    #[test]
    fn dhcpv6_dhcpv4_query_message_codepoints_are_named() {
        assert_eq!(Dhcpv6MessageType::Dhcpv4Query.code(), DHCPV6_DHCPV4_QUERY);
        assert_eq!(
            Dhcpv6MessageType::Dhcpv4Response.code(),
            DHCPV6_DHCPV4_RESPONSE,
        );
    }

    #[test]
    fn dhcpv6_dhcpv4_query_preserves_raw_embedded_payloads() {
        let embedded = [0x01, 0x02, 0x03, 0x04];
        let message = Dhcpv6::dhcpv4_query(0x010203).dhcpv4_msg(embedded);
        let decoded =
            Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes()).unwrap();

        assert_eq!(decoded.message_type_value(), Dhcpv6MessageType::Dhcpv4Query);
        assert_eq!(decoded.dhcpv4_msg_value(), Some(&embedded[..]));
        assert_eq!(
            decoded.options_ref()[0].codepoint(),
            DHCPV6_OPTION_DHCPV4_MSG
        );
    }

    #[test]
    fn dhcpv6_dhcpv4_response_can_decode_embedded_dhcpv4_layer() {
        let embedded = Packet::from_layer(Dhcpv4::new()).compile().unwrap();
        let option = Dhcpv6Option::dhcpv4_msg(embedded.as_bytes());
        let typed = option.dhcpv4_message_value().unwrap().unwrap();
        let message = Dhcpv6::dhcpv4_response(0x0a0b0c)
            .dhcpv4_message(typed)
            .unwrap();
        let decoded =
            Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes()).unwrap();

        assert_eq!(
            decoded.message_type_value(),
            Dhcpv6MessageType::Dhcpv4Response,
        );
        assert_eq!(decoded.dhcpv4_msg_value(), Some(embedded.as_bytes()));
        assert!(decoded.dhcpv4_message_value().unwrap().is_some());
    }

    #[test]
    fn dhcpv6_dhcpv4_query_surfaces_malformed_embedded_payloads() {
        let malformed = Dhcpv6Option::dhcpv4_msg([0u8; 10]);

        assert_eq!(
            malformed.dhcpv4_message_value().unwrap_err(),
            CrafterError::buffer_too_short("dhcpv4 packet", 240, 10),
        );
        assert_eq!(malformed.dhcpv4_msg_value(), Some(&[0u8; 10][..]));
    }
}

#[cfg(test)]
mod dhcpv6_failover_codepoints_tests {
    use super::Dhcpv6;
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{
        Dhcpv6MessageType, Dhcpv6Option, DHCPV6_BNDUPD, DHCPV6_CONTACT,
        DHCPV6_OPTION_F_BINDING_STATUS, DHCPV6_OPTION_F_SERVER_STATE,
    };

    #[test]
    fn dhcpv6_failover_codepoints_constructors_encode_decode_and_summarize() {
        let cases = [
            (Dhcpv6::bndupd(1), Dhcpv6MessageType::BndUpd, "bndupd"),
            (Dhcpv6::bndreply(2), Dhcpv6MessageType::BndReply, "bndreply"),
            (Dhcpv6::poolreq(3), Dhcpv6MessageType::PoolReq, "poolreq"),
            (Dhcpv6::poolresp(4), Dhcpv6MessageType::PoolResp, "poolresp"),
            (Dhcpv6::updreq(5), Dhcpv6MessageType::UpdReq, "updreq"),
            (
                Dhcpv6::updreqall(6),
                Dhcpv6MessageType::UpdReqAll,
                "updreqall",
            ),
            (Dhcpv6::upddone(7), Dhcpv6MessageType::UpdDone, "upddone"),
            (Dhcpv6::connect(8), Dhcpv6MessageType::Connect, "connect"),
            (
                Dhcpv6::connect_reply(9),
                Dhcpv6MessageType::ConnectReply,
                "connectreply",
            ),
            (
                Dhcpv6::disconnect(10),
                Dhcpv6MessageType::Disconnect,
                "disconnect",
            ),
            (Dhcpv6::state(11), Dhcpv6MessageType::State, "state"),
            (Dhcpv6::contact(12), Dhcpv6MessageType::Contact, "contact"),
        ];

        assert_eq!(Dhcpv6MessageType::BndUpd.code(), DHCPV6_BNDUPD);
        assert_eq!(Dhcpv6MessageType::Contact.code(), DHCPV6_CONTACT);
        for (message, message_type, label) in cases {
            let decoded =
                Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes()).unwrap();
            assert_eq!(decoded.message_type_value(), message_type);
            assert!(crate::packet::Layer::summary(&decoded).contains(label));
        }
    }

    #[test]
    fn dhcpv6_failover_codepoints_preserve_registered_raw_options() {
        let option = Dhcpv6Option::failover_option(DHCPV6_OPTION_F_BINDING_STATUS, [0x01]).unwrap();
        let message = Dhcpv6::connect(0x010203)
            .failover_option(DHCPV6_OPTION_F_SERVER_STATE, [0x02])
            .unwrap()
            .option(option.clone());
        let decoded =
            Dhcpv6::decode(Packet::from_layer(message).compile().unwrap().as_bytes()).unwrap();

        assert_eq!(option.failover_option_value(), Some(&[0x01][..]));
        assert_eq!(
            decoded.options_ref()[0].codepoint(),
            DHCPV6_OPTION_F_SERVER_STATE
        );
        assert_eq!(
            decoded.options_ref()[0].failover_option_value(),
            Some(&[0x02][..])
        );
        assert_eq!(decoded.options_ref()[1], option);
    }

    #[test]
    fn dhcpv6_failover_codepoints_reject_non_failover_option_code() {
        assert_eq!(
            Dhcpv6Option::failover_option(65_000, [0]).unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.failover.code",
                "option code is not in the DHCPv6 failover option range",
            ),
        );
    }
}
