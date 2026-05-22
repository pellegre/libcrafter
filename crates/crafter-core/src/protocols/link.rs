//! Link-layer protocol implementations.

use core::any::Any;
use core::net::Ipv4Addr;
use core::ops::Div;
use core::str::FromStr;

use crate::endian::{read_u16_be, read_u32_le};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::mac::MacAddr;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet, Raw};

/// Ethernet type for IPv4 payloads.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// Ethernet type for ARP payloads.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// Ethernet type for 802.1Q VLAN tags.
pub const ETHERTYPE_VLAN: u16 = 0x8100;
/// Ethernet type for IPv6 payloads.
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_HEADER_LEN: usize = 4;
const ARP_FIXED_HEADER_LEN: usize = 8;
const LINUX_SLL_HEADER_LEN: usize = 16;
const NULL_LOOPBACK_HEADER_LEN: usize = 4;

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

/// Ethernet II frame header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ethernet {
    destination: Field<MacAddr>,
    source: Field<MacAddr>,
    ethertype: Field<u16>,
}

impl Ethernet {
    /// Create an Ethernet header with libcrafter-style defaults.
    pub fn new() -> Self {
        Self {
            destination: Field::defaulted(MacAddr::BROADCAST),
            source: Field::defaulted(MacAddr::ZERO),
            ethertype: Field::defaulted(ETHERTYPE_IPV4),
        }
    }

    /// Create an Ethernet header with an explicit source and destination.
    pub fn with_addresses(source: MacAddr, destination: MacAddr) -> Self {
        Self::new().src(source).dst(destination)
    }

    /// Set the destination MAC address.
    pub fn dst(mut self, destination: impl Into<MacAddr>) -> Self {
        self.destination.set_user(destination.into());
        self
    }

    /// Set the destination MAC address from text.
    pub fn dst_str(self, destination: &str) -> Result<Self> {
        Ok(self.dst(MacAddr::from_str(destination)?))
    }

    /// Set the source MAC address.
    pub fn src(mut self, source: impl Into<MacAddr>) -> Self {
        self.source.set_user(source.into());
        self
    }

    /// Set the source MAC address from text.
    pub fn src_str(self, source: &str) -> Result<Self> {
        Ok(self.src(MacAddr::from_str(source)?))
    }

    /// Set the Ethernet type.
    pub fn ethertype(mut self, ethertype: u16) -> Self {
        self.ethertype.set_user(ethertype);
        self
    }

    /// Current destination field value, if present.
    pub fn destination(&self) -> Option<MacAddr> {
        self.destination.value().copied()
    }

    /// Current source field value, if present.
    pub fn source(&self) -> Option<MacAddr> {
        self.source.value().copied()
    }

    /// Current Ethernet type field value, if present.
    pub fn ethertype_value(&self) -> Option<u16> {
        self.ethertype.value().copied()
    }

    fn effective_destination(&self) -> MacAddr {
        value_or_copy(&self.destination, MacAddr::BROADCAST)
    }

    fn effective_source(&self) -> MacAddr {
        value_or_copy(&self.source, MacAddr::ZERO)
    }

    fn effective_ethertype(&self, next: Option<&dyn Layer>) -> u16 {
        if self.ethertype.is_user_set() {
            return value_or_copy(&self.ethertype, ETHERTYPE_IPV4);
        }

        next.and_then(layer_ethertype)
            .or_else(|| self.ethertype.value().copied())
            .unwrap_or(0)
    }
}

impl Default for Ethernet {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ethernet {
    fn name(&self) -> &'static str {
        "Ethernet"
    }

    fn summary(&self) -> String {
        format!(
            "Ethernet(src={}, dst={}, type=0x{:04x})",
            self.effective_source(),
            self.effective_destination(),
            value_or_copy(&self.ethertype, ETHERTYPE_IPV4)
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("dst", self.effective_destination().to_string()),
            ("src", self.effective_source().to_string()),
            (
                "ethertype",
                format!("0x{:04x}", value_or_copy(&self.ethertype, ETHERTYPE_IPV4)),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        ETHERNET_HEADER_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.effective_destination().octets());
        out.extend_from_slice(&self.effective_source().octets());
        out.extend_from_slice(&self.effective_ethertype(ctx.next()).to_be_bytes());
        Ok(())
    }

    impl_layer_object!(Ethernet);
}

impl_layer_div!(Ethernet);

/// ARP operation value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ArpOperation {
    /// ARP who-has request.
    Request = 1,
    /// ARP is-at reply.
    Reply = 2,
}

impl From<ArpOperation> for u16 {
    fn from(value: ArpOperation) -> Self {
        value as u16
    }
}

/// Address Resolution Protocol packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arp {
    hardware_type: Field<u16>,
    protocol_type: Field<u16>,
    hardware_len: Field<u8>,
    protocol_len: Field<u8>,
    operation: Field<u16>,
    sender_hardware_addr: Field<Vec<u8>>,
    sender_protocol_addr: Field<Vec<u8>>,
    target_hardware_addr: Field<Vec<u8>>,
    target_protocol_addr: Field<Vec<u8>>,
}

impl Arp {
    /// Create an Ethernet/IPv4 ARP request with libcrafter-style defaults.
    pub fn new() -> Self {
        Self {
            hardware_type: Field::defaulted(1),
            protocol_type: Field::defaulted(ETHERTYPE_IPV4),
            hardware_len: Field::defaulted(6),
            protocol_len: Field::defaulted(4),
            operation: Field::defaulted(ArpOperation::Request.into()),
            sender_hardware_addr: Field::defaulted(MacAddr::ZERO.octets().to_vec()),
            sender_protocol_addr: Field::defaulted(Ipv4Addr::LOCALHOST.octets().to_vec()),
            target_hardware_addr: Field::defaulted(MacAddr::ZERO.octets().to_vec()),
            target_protocol_addr: Field::defaulted(Ipv4Addr::LOCALHOST.octets().to_vec()),
        }
    }

    /// Create an ARP who-has request.
    pub fn who_has(
        sender_protocol_addr: Ipv4Addr,
        target_protocol_addr: Ipv4Addr,
        sender_hardware_addr: MacAddr,
    ) -> Self {
        Self::new()
            .operation(ArpOperation::Request)
            .sender_hardware_addr(sender_hardware_addr)
            .sender_protocol_addr(sender_protocol_addr)
            .target_hardware_addr(MacAddr::ZERO)
            .target_protocol_addr(target_protocol_addr)
    }

    /// Create an ARP is-at reply.
    pub fn is_at(
        sender_protocol_addr: Ipv4Addr,
        sender_hardware_addr: MacAddr,
        target_protocol_addr: Ipv4Addr,
        target_hardware_addr: MacAddr,
    ) -> Self {
        Self::new()
            .operation(ArpOperation::Reply)
            .sender_hardware_addr(sender_hardware_addr)
            .sender_protocol_addr(sender_protocol_addr)
            .target_hardware_addr(target_hardware_addr)
            .target_protocol_addr(target_protocol_addr)
    }

    /// Set the hardware type.
    pub fn hardware_type(mut self, hardware_type: u16) -> Self {
        self.hardware_type.set_user(hardware_type);
        self
    }

    /// Set the protocol type.
    pub fn protocol_type(mut self, protocol_type: u16) -> Self {
        self.protocol_type.set_user(protocol_type);
        self
    }

    /// Set the hardware address length.
    pub fn hardware_len(mut self, hardware_len: u8) -> Self {
        self.hardware_len.set_user(hardware_len);
        self
    }

    /// Set the protocol address length.
    pub fn protocol_len(mut self, protocol_len: u8) -> Self {
        self.protocol_len.set_user(protocol_len);
        self
    }

    /// Set the ARP operation.
    pub fn operation(mut self, operation: ArpOperation) -> Self {
        self.operation.set_user(operation.into());
        self
    }

    /// Set the ARP operation as a raw numeric opcode.
    pub fn opcode(mut self, operation: u16) -> Self {
        self.operation.set_user(operation);
        self
    }

    /// Set the sender hardware address to a MAC address.
    pub fn sender_hardware_addr(mut self, address: impl Into<MacAddr>) -> Self {
        self.sender_hardware_addr
            .set_user(address.into().octets().to_vec());
        self.hardware_len.set_default_if_unset(6);
        self
    }

    /// Scapy/libcrafter-style alias for sender hardware address.
    pub fn hwsrc(self, address: impl Into<MacAddr>) -> Self {
        self.sender_hardware_addr(address)
    }

    /// Set the sender hardware address from text.
    pub fn hwsrc_str(self, address: &str) -> Result<Self> {
        Ok(self.hwsrc(MacAddr::from_str(address)?))
    }

    /// Set the target hardware address to a MAC address.
    pub fn target_hardware_addr(mut self, address: impl Into<MacAddr>) -> Self {
        self.target_hardware_addr
            .set_user(address.into().octets().to_vec());
        self.hardware_len.set_default_if_unset(6);
        self
    }

    /// Scapy/libcrafter-style alias for target hardware address.
    pub fn hwdst(self, address: impl Into<MacAddr>) -> Self {
        self.target_hardware_addr(address)
    }

    /// Set the target hardware address from text.
    pub fn hwdst_str(self, address: &str) -> Result<Self> {
        Ok(self.hwdst(MacAddr::from_str(address)?))
    }

    /// Set the sender protocol address to an IPv4 address.
    pub fn sender_protocol_addr(mut self, address: Ipv4Addr) -> Self {
        self.sender_protocol_addr
            .set_user(address.octets().to_vec());
        self.protocol_len.set_default_if_unset(4);
        self.protocol_type.set_default_if_unset(ETHERTYPE_IPV4);
        self
    }

    /// Scapy/libcrafter-style alias for sender protocol address.
    pub fn psrc(self, address: Ipv4Addr) -> Self {
        self.sender_protocol_addr(address)
    }

    /// Set the sender protocol address from text.
    pub fn psrc_str(self, address: &str) -> Result<Self> {
        Ok(self.psrc(parse_ipv4(address)?))
    }

    /// Set the target protocol address to an IPv4 address.
    pub fn target_protocol_addr(mut self, address: Ipv4Addr) -> Self {
        self.target_protocol_addr
            .set_user(address.octets().to_vec());
        self.protocol_len.set_default_if_unset(4);
        self.protocol_type.set_default_if_unset(ETHERTYPE_IPV4);
        self
    }

    /// Scapy/libcrafter-style alias for target protocol address.
    pub fn pdst(self, address: Ipv4Addr) -> Self {
        self.target_protocol_addr(address)
    }

    /// Set the target protocol address from text.
    pub fn pdst_str(self, address: &str) -> Result<Self> {
        Ok(self.pdst(parse_ipv4(address)?))
    }

    /// Set raw sender hardware address bytes.
    pub fn sender_hardware_bytes(mut self, address: impl Into<Vec<u8>>) -> Self {
        self.sender_hardware_addr.set_user(address.into());
        self
    }

    /// Set raw sender protocol address bytes.
    pub fn sender_protocol_bytes(mut self, address: impl Into<Vec<u8>>) -> Self {
        self.sender_protocol_addr.set_user(address.into());
        self
    }

    /// Set raw target hardware address bytes.
    pub fn target_hardware_bytes(mut self, address: impl Into<Vec<u8>>) -> Self {
        self.target_hardware_addr.set_user(address.into());
        self
    }

    /// Set raw target protocol address bytes.
    pub fn target_protocol_bytes(mut self, address: impl Into<Vec<u8>>) -> Self {
        self.target_protocol_addr.set_user(address.into());
        self
    }

    /// Hardware type value.
    pub fn hardware_type_value(&self) -> u16 {
        value_or_copy(&self.hardware_type, 1)
    }

    /// Protocol type value.
    pub fn protocol_type_value(&self) -> u16 {
        value_or_copy(&self.protocol_type, ETHERTYPE_IPV4)
    }

    /// Hardware address length.
    pub fn hardware_len_value(&self) -> u8 {
        value_or_copy(&self.hardware_len, 6)
    }

    /// Protocol address length.
    pub fn protocol_len_value(&self) -> u8 {
        value_or_copy(&self.protocol_len, 4)
    }

    /// Operation opcode.
    pub fn opcode_value(&self) -> u16 {
        value_or_copy(&self.operation, ArpOperation::Request.into())
    }

    /// Sender hardware address bytes.
    pub fn sender_hardware_bytes_value(&self) -> Vec<u8> {
        value_or_vec(&self.sender_hardware_addr, self.hardware_len_value())
    }

    /// Sender protocol address bytes.
    pub fn sender_protocol_bytes_value(&self) -> Vec<u8> {
        value_or_vec(&self.sender_protocol_addr, self.protocol_len_value())
    }

    /// Target hardware address bytes.
    pub fn target_hardware_bytes_value(&self) -> Vec<u8> {
        value_or_vec(&self.target_hardware_addr, self.hardware_len_value())
    }

    /// Target protocol address bytes.
    pub fn target_protocol_bytes_value(&self) -> Vec<u8> {
        value_or_vec(&self.target_protocol_addr, self.protocol_len_value())
    }

    /// Sender hardware address as a MAC address when the address length is six.
    pub fn sender_mac(&self) -> Option<MacAddr> {
        mac_from_bytes(&self.sender_hardware_bytes_value())
    }

    /// Target hardware address as a MAC address when the address length is six.
    pub fn target_mac(&self) -> Option<MacAddr> {
        mac_from_bytes(&self.target_hardware_bytes_value())
    }

    /// Sender protocol address as IPv4 when the protocol is IPv4 and length is four.
    pub fn sender_ipv4(&self) -> Option<Ipv4Addr> {
        ipv4_from_bytes(
            self.protocol_type_value(),
            &self.sender_protocol_bytes_value(),
        )
    }

    /// Target protocol address as IPv4 when the protocol is IPv4 and length is four.
    pub fn target_ipv4(&self) -> Option<Ipv4Addr> {
        ipv4_from_bytes(
            self.protocol_type_value(),
            &self.target_protocol_bytes_value(),
        )
    }

    fn validate_lengths(&self) -> Result<()> {
        validate_len(
            "arp.sender_hardware_addr",
            self.sender_hardware_addr.value(),
            self.hardware_len_value(),
        )?;
        validate_len(
            "arp.sender_protocol_addr",
            self.sender_protocol_addr.value(),
            self.protocol_len_value(),
        )?;
        validate_len(
            "arp.target_hardware_addr",
            self.target_hardware_addr.value(),
            self.hardware_len_value(),
        )?;
        validate_len(
            "arp.target_protocol_addr",
            self.target_protocol_addr.value(),
            self.protocol_len_value(),
        )
    }
}

impl Default for Arp {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Arp {
    fn name(&self) -> &'static str {
        "Arp"
    }

    fn summary(&self) -> String {
        let sender = self
            .sender_ipv4()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| hex_bytes(&self.sender_protocol_bytes_value()));
        let target = self
            .target_ipv4()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| hex_bytes(&self.target_protocol_bytes_value()));

        format!(
            "Arp(op={}, psrc={}, pdst={})",
            operation_summary(self.opcode_value()),
            sender,
            target
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "hardware_type",
                format!("0x{:04x}", self.hardware_type_value()),
            ),
            (
                "protocol_type",
                format!("0x{:04x}", self.protocol_type_value()),
            ),
            ("hardware_len", self.hardware_len_value().to_string()),
            ("protocol_len", self.protocol_len_value().to_string()),
            ("operation", operation_summary(self.opcode_value())),
            (
                "sender_hardware_addr",
                address_summary_mac(&self.sender_hardware_bytes_value()),
            ),
            (
                "sender_protocol_addr",
                address_summary_ipv4(
                    self.protocol_type_value(),
                    &self.sender_protocol_bytes_value(),
                ),
            ),
            (
                "target_hardware_addr",
                address_summary_mac(&self.target_hardware_bytes_value()),
            ),
            (
                "target_protocol_addr",
                address_summary_ipv4(
                    self.protocol_type_value(),
                    &self.target_protocol_bytes_value(),
                ),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        ARP_FIXED_HEADER_LEN
            + (self.hardware_len_value() as usize * 2)
            + (self.protocol_len_value() as usize * 2)
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate_lengths()?;

        out.extend_from_slice(&self.hardware_type_value().to_be_bytes());
        out.extend_from_slice(&self.protocol_type_value().to_be_bytes());
        out.push(self.hardware_len_value());
        out.push(self.protocol_len_value());
        out.extend_from_slice(&self.opcode_value().to_be_bytes());
        out.extend_from_slice(&self.sender_hardware_bytes_value());
        out.extend_from_slice(&self.sender_protocol_bytes_value());
        out.extend_from_slice(&self.target_hardware_bytes_value());
        out.extend_from_slice(&self.target_protocol_bytes_value());
        Ok(())
    }

    impl_layer_object!(Arp);
}

impl_layer_div!(Arp);

/// 802.1Q VLAN tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vlan {
    pcp: Field<u8>,
    dei: Field<bool>,
    vlan_id: Field<u16>,
    ethertype: Field<u16>,
}

/// Scapy-compatible alias for an 802.1Q tag.
pub type Dot1Q = Vlan;

impl Vlan {
    /// Create an 802.1Q tag.
    pub fn new() -> Self {
        Self {
            pcp: Field::defaulted(0),
            dei: Field::defaulted(false),
            vlan_id: Field::defaulted(0),
            ethertype: Field::defaulted(ETHERTYPE_IPV4),
        }
    }

    /// Set the priority code point.
    pub fn pcp(mut self, pcp: u8) -> Self {
        self.pcp.set_user(pcp);
        self
    }

    /// Scapy-style alias for priority.
    pub fn prio(self, pcp: u8) -> Self {
        self.pcp(pcp)
    }

    /// Set the drop eligible indicator.
    pub fn dei(mut self, dei: bool) -> Self {
        self.dei.set_user(dei);
        self
    }

    /// Set the VLAN identifier.
    pub fn vlan_id(mut self, vlan_id: u16) -> Self {
        self.vlan_id.set_user(vlan_id);
        self
    }

    /// Scapy-style alias for VLAN identifier.
    pub fn vlan(self, vlan_id: u16) -> Self {
        self.vlan_id(vlan_id)
    }

    /// Set the encapsulated Ethernet type.
    pub fn ethertype(mut self, ethertype: u16) -> Self {
        self.ethertype.set_user(ethertype);
        self
    }

    /// Priority code point.
    pub fn pcp_value(&self) -> u8 {
        value_or_copy(&self.pcp, 0)
    }

    /// Drop eligible indicator.
    pub fn dei_value(&self) -> bool {
        value_or_copy(&self.dei, false)
    }

    /// VLAN identifier.
    pub fn vlan_id_value(&self) -> u16 {
        value_or_copy(&self.vlan_id, 0)
    }

    /// Encapsulated Ethernet type.
    pub fn ethertype_value(&self) -> u16 {
        value_or_copy(&self.ethertype, ETHERTYPE_IPV4)
    }

    fn effective_ethertype(&self, next: Option<&dyn Layer>) -> u16 {
        if self.ethertype.is_user_set() {
            return self.ethertype_value();
        }

        next.and_then(layer_ethertype)
            .or_else(|| self.ethertype.value().copied())
            .unwrap_or(0)
    }

    fn validate(&self) -> Result<()> {
        if self.pcp_value() > 7 {
            return Err(CrafterError::invalid_field_value(
                "vlan.pcp",
                "priority code point must be <= 7",
            ));
        }
        if self.vlan_id_value() > 0x0fff {
            return Err(CrafterError::invalid_field_value(
                "vlan.vlan_id",
                "VLAN identifier must be <= 4095",
            ));
        }
        Ok(())
    }
}

impl Default for Vlan {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Vlan {
    fn name(&self) -> &'static str {
        "Vlan"
    }

    fn summary(&self) -> String {
        format!(
            "Vlan(id={}, pcp={}, type=0x{:04x})",
            self.vlan_id_value(),
            self.pcp_value(),
            self.ethertype_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("pcp", self.pcp_value().to_string()),
            ("dei", self.dei_value().to_string()),
            ("vlan_id", self.vlan_id_value().to_string()),
            ("ethertype", format!("0x{:04x}", self.ethertype_value())),
        ]
    }

    fn encoded_len(&self) -> usize {
        VLAN_HEADER_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;

        let tci = ((self.pcp_value() as u16) << 13)
            | ((self.dei_value() as u16) << 12)
            | self.vlan_id_value();
        out.extend_from_slice(&tci.to_be_bytes());
        out.extend_from_slice(&self.effective_ethertype(ctx.next()).to_be_bytes());
        Ok(())
    }

    impl_layer_object!(Vlan);
}

impl_layer_div!(Vlan);

/// Linux cooked capture v1 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSll {
    packet_type: Field<u16>,
    address_type: Field<u16>,
    address_len: Field<u16>,
    source_address: Field<[u8; 8]>,
    protocol: Field<u16>,
}

impl LinuxSll {
    /// Create a Linux cooked capture header.
    pub fn new() -> Self {
        Self {
            packet_type: Field::defaulted(0),
            address_type: Field::defaulted(1),
            address_len: Field::defaulted(6),
            source_address: Field::defaulted([0; 8]),
            protocol: Field::defaulted(ETHERTYPE_IPV4),
        }
    }

    /// Set the packet type.
    pub fn packet_type(mut self, packet_type: u16) -> Self {
        self.packet_type.set_user(packet_type);
        self
    }

    /// Set the ARPHRD address type.
    pub fn address_type(mut self, address_type: u16) -> Self {
        self.address_type.set_user(address_type);
        self
    }

    /// Set the source address as a MAC address.
    pub fn source_address(mut self, address: impl Into<MacAddr>) -> Self {
        let mut padded = [0u8; 8];
        padded[..6].copy_from_slice(&address.into().octets());
        self.source_address.set_user(padded);
        self.address_len.set_default_if_unset(6);
        self
    }

    /// Set the raw padded source address and address length.
    pub fn source_address_bytes(mut self, address: [u8; 8], address_len: u16) -> Self {
        self.source_address.set_user(address);
        self.address_len.set_user(address_len);
        self
    }

    /// Set the encapsulated protocol.
    pub fn protocol(mut self, protocol: u16) -> Self {
        self.protocol.set_user(protocol);
        self
    }

    /// Packet type value.
    pub fn packet_type_value(&self) -> u16 {
        value_or_copy(&self.packet_type, 0)
    }

    /// ARPHRD address type value.
    pub fn address_type_value(&self) -> u16 {
        value_or_copy(&self.address_type, 1)
    }

    /// Source address length.
    pub fn address_len_value(&self) -> u16 {
        value_or_copy(&self.address_len, 6)
    }

    /// Padded source address bytes.
    pub fn source_address_value(&self) -> [u8; 8] {
        value_or_copy(&self.source_address, [0; 8])
    }

    /// Encapsulated protocol.
    pub fn protocol_value(&self) -> u16 {
        value_or_copy(&self.protocol, ETHERTYPE_IPV4)
    }

    /// Source address as a MAC address when the address length is six.
    pub fn source_mac(&self) -> Option<MacAddr> {
        let address = self.source_address_value();
        mac_from_bytes(&address[..self.address_len_value().min(8) as usize])
    }

    fn effective_protocol(&self, next: Option<&dyn Layer>) -> u16 {
        if self.protocol.is_user_set() {
            return self.protocol_value();
        }

        next.and_then(layer_ethertype)
            .or_else(|| self.protocol.value().copied())
            .unwrap_or(0)
    }

    fn validate(&self) -> Result<()> {
        if self.address_len_value() > 8 {
            return Err(CrafterError::invalid_field_value(
                "linux_sll.address_len",
                "Linux SLL source address length must be <= 8",
            ));
        }
        Ok(())
    }
}

impl Default for LinuxSll {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for LinuxSll {
    fn name(&self) -> &'static str {
        "LinuxSll"
    }

    fn summary(&self) -> String {
        format!(
            "LinuxSll(type={}, addr_type={}, protocol=0x{:04x})",
            self.packet_type_value(),
            self.address_type_value(),
            self.protocol_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("packet_type", self.packet_type_value().to_string()),
            ("address_type", self.address_type_value().to_string()),
            ("address_len", self.address_len_value().to_string()),
            (
                "source_address",
                address_summary_mac(
                    &self.source_address_value()[..self.address_len_value().min(8) as usize],
                ),
            ),
            ("protocol", format!("0x{:04x}", self.protocol_value())),
        ]
    }

    fn encoded_len(&self) -> usize {
        LINUX_SLL_HEADER_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;

        out.extend_from_slice(&self.packet_type_value().to_be_bytes());
        out.extend_from_slice(&self.address_type_value().to_be_bytes());
        out.extend_from_slice(&self.address_len_value().to_be_bytes());
        out.extend_from_slice(&self.source_address_value());
        out.extend_from_slice(&self.effective_protocol(ctx.next()).to_be_bytes());
        Ok(())
    }

    impl_layer_object!(LinuxSll);
}

impl_layer_div!(LinuxSll);

/// Byte order used for BSD null/loopback family values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NullByteOrder {
    /// Encode and decode the family as little-endian.
    LittleEndian,
    /// Encode and decode the family as big-endian.
    BigEndian,
}

/// BSD null/loopback link-layer header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NullLoopback {
    family: Field<u32>,
    byte_order: NullByteOrder,
}

impl NullLoopback {
    /// Create a null/loopback header.
    pub fn new() -> Self {
        Self {
            family: Field::defaulted(0),
            byte_order: NullByteOrder::LittleEndian,
        }
    }

    /// Create a null/loopback header for IPv4 payloads.
    pub fn ipv4() -> Self {
        Self::new().family(2)
    }

    /// Set the address family.
    pub fn family(mut self, family: u32) -> Self {
        self.family.set_user(family);
        self
    }

    /// Encode as little-endian.
    pub fn little_endian(mut self) -> Self {
        self.byte_order = NullByteOrder::LittleEndian;
        self
    }

    /// Encode as big-endian.
    pub fn big_endian(mut self) -> Self {
        self.byte_order = NullByteOrder::BigEndian;
        self
    }

    /// Address family value.
    pub fn family_value(&self) -> u32 {
        value_or_copy(&self.family, 0)
    }

    /// Address family byte order.
    pub fn byte_order(&self) -> NullByteOrder {
        self.byte_order
    }
}

impl Default for NullLoopback {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for NullLoopback {
    fn name(&self) -> &'static str {
        "NullLoopback"
    }

    fn summary(&self) -> String {
        format!("NullLoopback(family={})", self.family_value())
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("family", self.family_value().to_string()),
            ("byte_order", format!("{:?}", self.byte_order)),
        ]
    }

    fn encoded_len(&self) -> usize {
        NULL_LOOPBACK_HEADER_LEN
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        match self.byte_order {
            NullByteOrder::LittleEndian => {
                out.extend_from_slice(&self.family_value().to_le_bytes())
            }
            NullByteOrder::BigEndian => out.extend_from_slice(&self.family_value().to_be_bytes()),
        }
        Ok(())
    }

    impl_layer_object!(NullLoopback);
}

impl_layer_div!(NullLoopback);

/// Decode an Ethernet frame.
pub(crate) fn decode_ethernet(bytes: &[u8]) -> Result<Packet> {
    if bytes.len() < ETHERNET_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ethernet header",
            ETHERNET_HEADER_LEN,
            bytes.len(),
        ));
    }

    let ethernet = Ethernet {
        destination: Field::user(MacAddr::new(copy_array_6(&bytes[0..6]))),
        source: Field::user(MacAddr::new(copy_array_6(&bytes[6..12]))),
        ethertype: Field::user(read_u16_be(&bytes[12..14])?),
    };

    append_ethertype_payload(
        Packet::new().push(ethernet),
        read_u16_be(&bytes[12..14])?,
        &bytes[ETHERNET_HEADER_LEN..],
    )
}

/// Decode a Linux cooked capture v1 frame.
pub(crate) fn decode_linux_sll(bytes: &[u8]) -> Result<Packet> {
    if bytes.len() < LINUX_SLL_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "linux sll header",
            LINUX_SLL_HEADER_LEN,
            bytes.len(),
        ));
    }

    let mut source_address = [0u8; 8];
    source_address.copy_from_slice(&bytes[6..14]);
    let protocol = read_u16_be(&bytes[14..16])?;
    let linux_sll = LinuxSll {
        packet_type: Field::user(read_u16_be(&bytes[0..2])?),
        address_type: Field::user(read_u16_be(&bytes[2..4])?),
        address_len: Field::user(read_u16_be(&bytes[4..6])?),
        source_address: Field::user(source_address),
        protocol: Field::user(protocol),
    };

    append_ethertype_payload(
        Packet::new().push(linux_sll),
        protocol,
        &bytes[LINUX_SLL_HEADER_LEN..],
    )
}

/// Decode a little-endian BSD null/loopback frame.
pub(crate) fn decode_null_loopback(bytes: &[u8]) -> Result<Packet> {
    if bytes.len() < NULL_LOOPBACK_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "null loopback header",
            NULL_LOOPBACK_HEADER_LEN,
            bytes.len(),
        ));
    }

    let null = NullLoopback {
        family: Field::user(read_u32_le(&bytes[0..4])?),
        byte_order: NullByteOrder::LittleEndian,
    };
    let mut packet = Packet::new().push(null);
    if bytes.len() > NULL_LOOPBACK_HEADER_LEN {
        packet = packet.push(Raw::from_bytes(&bytes[NULL_LOOPBACK_HEADER_LEN..]));
    }
    Ok(packet)
}

fn append_ethertype_payload(mut packet: Packet, ethertype: u16, payload: &[u8]) -> Result<Packet> {
    match ethertype {
        ETHERTYPE_ARP => {
            let (arp, rest) = decode_arp(payload)?;
            packet = packet.push(arp);
            if !rest.is_empty() {
                packet = packet.push(Raw::from_bytes(rest));
            }
        }
        ETHERTYPE_VLAN => {
            let (vlan, rest) = decode_vlan(payload)?;
            let inner = vlan.ethertype_value();
            packet = packet.push(vlan);
            packet = append_ethertype_payload(packet, inner, rest)?;
        }
        _ => {
            packet = packet.push(Raw::from_bytes(payload));
        }
    }

    Ok(packet)
}

fn decode_vlan(bytes: &[u8]) -> Result<(Vlan, &[u8])> {
    if bytes.len() < VLAN_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "vlan header",
            VLAN_HEADER_LEN,
            bytes.len(),
        ));
    }

    let tci = read_u16_be(&bytes[0..2])?;
    let vlan = Vlan {
        pcp: Field::user((tci >> 13) as u8),
        dei: Field::user(((tci >> 12) & 1) != 0),
        vlan_id: Field::user(tci & 0x0fff),
        ethertype: Field::user(read_u16_be(&bytes[2..4])?),
    };

    Ok((vlan, &bytes[VLAN_HEADER_LEN..]))
}

fn decode_arp(bytes: &[u8]) -> Result<(Arp, &[u8])> {
    if bytes.len() < ARP_FIXED_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "arp header",
            ARP_FIXED_HEADER_LEN,
            bytes.len(),
        ));
    }

    let hardware_len = bytes[4] as usize;
    let protocol_len = bytes[5] as usize;
    let total_len = ARP_FIXED_HEADER_LEN + hardware_len * 2 + protocol_len * 2;
    if bytes.len() < total_len {
        return Err(CrafterError::buffer_too_short(
            "arp addresses",
            total_len,
            bytes.len(),
        ));
    }

    let mut offset = ARP_FIXED_HEADER_LEN;
    let sender_hardware_addr = bytes[offset..offset + hardware_len].to_vec();
    offset += hardware_len;
    let sender_protocol_addr = bytes[offset..offset + protocol_len].to_vec();
    offset += protocol_len;
    let target_hardware_addr = bytes[offset..offset + hardware_len].to_vec();
    offset += hardware_len;
    let target_protocol_addr = bytes[offset..offset + protocol_len].to_vec();

    let arp = Arp {
        hardware_type: Field::user(read_u16_be(&bytes[0..2])?),
        protocol_type: Field::user(read_u16_be(&bytes[2..4])?),
        hardware_len: Field::user(bytes[4]),
        protocol_len: Field::user(bytes[5]),
        operation: Field::user(read_u16_be(&bytes[6..8])?),
        sender_hardware_addr: Field::user(sender_hardware_addr),
        sender_protocol_addr: Field::user(sender_protocol_addr),
        target_hardware_addr: Field::user(target_hardware_addr),
        target_protocol_addr: Field::user(target_protocol_addr),
    };

    Ok((arp, &bytes[total_len..]))
}

fn layer_ethertype(layer: &dyn Layer) -> Option<u16> {
    if layer.as_any().is::<Arp>() {
        Some(ETHERTYPE_ARP)
    } else if layer.as_any().is::<Vlan>() {
        Some(ETHERTYPE_VLAN)
    } else {
        None
    }
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn value_or_vec(field: &Field<Vec<u8>>, len: u8) -> Vec<u8> {
    field
        .value()
        .cloned()
        .unwrap_or_else(|| vec![0; len as usize])
}

fn validate_len(field: &'static str, value: Option<&Vec<u8>>, expected: u8) -> Result<()> {
    if let Some(value) = value {
        if value.len() != expected as usize {
            return Err(CrafterError::invalid_field_value(
                field,
                "address length does not match ARP length field",
            ));
        }
    }
    Ok(())
}

fn parse_ipv4(input: &str) -> Result<Ipv4Addr> {
    input.parse().map_err(|_| {
        CrafterError::invalid_field_value("ipv4_address", "expected dotted-quad IPv4 address")
    })
}

fn mac_from_bytes(bytes: &[u8]) -> Option<MacAddr> {
    if bytes.len() == 6 {
        Some(MacAddr::new(copy_array_6(bytes)))
    } else {
        None
    }
}

fn ipv4_from_bytes(protocol_type: u16, bytes: &[u8]) -> Option<Ipv4Addr> {
    if protocol_type == ETHERTYPE_IPV4 && bytes.len() == 4 {
        Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        None
    }
}

fn address_summary_mac(bytes: &[u8]) -> String {
    mac_from_bytes(bytes)
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| hex_bytes(bytes))
}

fn address_summary_ipv4(protocol_type: u16, bytes: &[u8]) -> String {
    ipv4_from_bytes(protocol_type, bytes)
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| hex_bytes(bytes))
}

fn operation_summary(operation: u16) -> String {
    match operation {
        1 => "request".to_string(),
        2 => "reply".to_string(),
        value => value.to_string(),
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

fn copy_array_6(bytes: &[u8]) -> [u8; 6] {
    let mut out = [0u8; 6];
    out.copy_from_slice(&bytes[..6]);
    out
}

#[cfg(test)]
mod ethernet {
    use super::{Arp, Ethernet, ETHERTYPE_ARP};
    use crate::{LinkType, MacAddr, Packet, Raw};
    use core::net::Ipv4Addr;

    const ETHERNET_FIXTURE: &[u8] = include_bytes!("../../../../tests/fixtures/scapy/ethernet.bin");
    const ARP_REQUEST_FIXTURE: &[u8] =
        include_bytes!("../../../../tests/fixtures/scapy/arp-request.bin");

    fn src_mac() -> MacAddr {
        "02:00:5e:00:53:01".parse().unwrap()
    }

    fn dst_mac() -> MacAddr {
        "02:00:5e:00:53:02".parse().unwrap()
    }

    #[test]
    fn ethernet_frame_matches_scapy_fixture() {
        let packet = Ethernet::new()
            .src(src_mac())
            .dst(dst_mac())
            .ethertype(0x9000)
            / Raw::from("libcrafter-ethernet");

        assert_eq!(packet.compile().unwrap().as_bytes(), ETHERNET_FIXTURE);
    }

    #[test]
    fn ethernet_decode_preserves_unknown_payload_as_raw() {
        let decoded = Packet::decode_from_link(LinkType::Ethernet, ETHERNET_FIXTURE).unwrap();
        let ethernet = decoded.layer::<Ethernet>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(ethernet.source(), Some(src_mac()));
        assert_eq!(ethernet.destination(), Some(dst_mac()));
        assert_eq!(ethernet.ethertype_value(), Some(0x9000));
        assert_eq!(raw.as_bytes(), b"libcrafter-ethernet");
        assert_eq!(decoded.compile().unwrap().as_bytes(), ETHERNET_FIXTURE);
    }

    #[test]
    fn ethernet_autofills_arp_ethertype() {
        let packet = Ethernet::new().src(src_mac())
            / Arp::who_has(
                Ipv4Addr::new(192, 0, 2, 10),
                Ipv4Addr::new(192, 0, 2, 1),
                src_mac(),
            );

        assert_eq!(
            &packet.compile().unwrap().as_bytes()[12..14],
            &ETHERTYPE_ARP.to_be_bytes()
        );
        assert_eq!(packet.compile().unwrap().as_bytes(), ARP_REQUEST_FIXTURE);
    }

    #[test]
    fn ethernet_short_decode_reports_error() {
        let err = Packet::decode_from_link(LinkType::Ethernet, [0u8; 13]).unwrap_err();

        assert!(err.to_string().contains("ethernet header"));
    }
}

#[cfg(test)]
mod arp {
    use super::{Arp, ArpOperation, Ethernet};
    use crate::{LinkType, MacAddr, Packet};
    use core::net::Ipv4Addr;

    const ARP_REQUEST_FIXTURE: &[u8] =
        include_bytes!("../../../../tests/fixtures/scapy/arp-request.bin");

    fn src_mac() -> MacAddr {
        "02:00:5e:00:53:01".parse().unwrap()
    }

    #[test]
    fn arp_request_matches_scapy_fixture() {
        let packet = Ethernet::new().src(src_mac())
            / Arp::who_has(
                Ipv4Addr::new(192, 0, 2, 10),
                Ipv4Addr::new(192, 0, 2, 1),
                src_mac(),
            );

        assert_eq!(packet.compile().unwrap().as_bytes(), ARP_REQUEST_FIXTURE);
    }

    #[test]
    fn arp_decode_exposes_ipv4_and_mac_fields() {
        let decoded = Packet::decode_from_link(LinkType::Ethernet, ARP_REQUEST_FIXTURE).unwrap();
        let arp = decoded.layer::<Arp>().unwrap();

        assert_eq!(arp.hardware_type_value(), 1);
        assert_eq!(arp.protocol_type_value(), super::ETHERTYPE_IPV4);
        assert_eq!(arp.opcode_value(), ArpOperation::Request as u16);
        assert_eq!(arp.sender_mac(), Some(src_mac()));
        assert_eq!(arp.target_mac(), Some(MacAddr::ZERO));
        assert_eq!(arp.sender_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(arp.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(decoded.compile().unwrap().as_bytes(), ARP_REQUEST_FIXTURE);
    }

    #[test]
    fn arp_rejects_inconsistent_address_lengths() {
        let packet = Packet::new().push(
            Arp::new()
                .hardware_len(5)
                .sender_hardware_addr(src_mac())
                .target_hardware_addr(MacAddr::ZERO),
        );
        let err = packet.compile().unwrap_err();

        assert!(err.to_string().contains("address length"));
    }

    #[test]
    fn arp_reply_builder_sets_expected_operation() {
        let arp = Arp::is_at(
            Ipv4Addr::new(192, 0, 2, 10),
            src_mac(),
            Ipv4Addr::new(192, 0, 2, 1),
            MacAddr::BROADCAST,
        );

        assert_eq!(arp.opcode_value(), ArpOperation::Reply as u16);
        assert_eq!(arp.sender_mac(), Some(src_mac()));
    }
}

#[cfg(test)]
mod link_layers {
    use super::{Arp, Ethernet, LinuxSll, NullByteOrder, NullLoopback, Vlan, ETHERTYPE_IPV4};
    use crate::{LinkType, MacAddr, Packet, Raw};
    use core::net::Ipv4Addr;

    const VLAN_FIXTURE: &[u8] =
        include_bytes!("../../../../tests/fixtures/scapy/vlan-ipv4-udp.bin");

    fn src_mac() -> MacAddr {
        "02:00:5e:00:53:01".parse().unwrap()
    }

    fn dst_mac() -> MacAddr {
        "02:00:5e:00:53:02".parse().unwrap()
    }

    #[test]
    fn vlan_decode_preserves_inner_payload_as_raw() {
        let decoded = Packet::decode_from_link(LinkType::Ethernet, VLAN_FIXTURE).unwrap();
        let ethernet = decoded.layer::<Ethernet>().unwrap();
        let vlan = decoded.layer::<Vlan>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(ethernet.source(), Some(src_mac()));
        assert_eq!(ethernet.destination(), Some(dst_mac()));
        assert_eq!(vlan.pcp_value(), 3);
        assert!(!vlan.dei_value());
        assert_eq!(vlan.vlan_id_value(), 42);
        assert_eq!(vlan.ethertype_value(), ETHERTYPE_IPV4);
        assert_eq!(raw.as_bytes(), &VLAN_FIXTURE[18..]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), VLAN_FIXTURE);
    }

    #[test]
    fn vlan_builder_matches_scapy_fixture_when_payload_is_known_bytes() {
        let packet = Ethernet::new().src(src_mac()).dst(dst_mac())
            / Vlan::new().prio(3).vlan(42).ethertype(ETHERTYPE_IPV4)
            / Raw::from_bytes(&VLAN_FIXTURE[18..]);

        assert_eq!(packet.compile().unwrap().as_bytes(), VLAN_FIXTURE);
    }

    #[test]
    fn linux_sll_compiles_decodes_and_autofills_arp_protocol() {
        let packet = LinuxSll::new().source_address(src_mac())
            / Arp::who_has(
                Ipv4Addr::new(192, 0, 2, 10),
                Ipv4Addr::new(192, 0, 2, 1),
                src_mac(),
            );
        let bytes = packet.compile().unwrap();

        assert_eq!(
            &bytes.as_bytes()[14..16],
            &super::ETHERTYPE_ARP.to_be_bytes()
        );

        let decoded = Packet::decode_from_link(LinkType::LinuxCooked, bytes.as_bytes()).unwrap();
        let linux_sll = decoded.layer::<LinuxSll>().unwrap();
        let arp = decoded.layer::<Arp>().unwrap();

        assert_eq!(linux_sll.source_mac(), Some(src_mac()));
        assert_eq!(arp.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn null_loopback_compiles_and_decodes_little_endian_family() {
        let packet = NullLoopback::ipv4() / Raw::from("loopback");
        let bytes = packet.compile().unwrap();

        assert_eq!(&bytes.as_bytes()[..4], &[2, 0, 0, 0]);

        let decoded = Packet::decode_from_link(LinkType::NullLoopback, bytes.as_bytes()).unwrap();
        let null = decoded.layer::<NullLoopback>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(null.family_value(), 2);
        assert_eq!(null.byte_order(), NullByteOrder::LittleEndian);
        assert_eq!(raw.as_bytes(), b"loopback");
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn null_loopback_can_encode_big_endian_family() {
        let packet = Packet::new().push(NullLoopback::new().family(2).big_endian());

        assert_eq!(packet.compile().unwrap().as_bytes(), &[0, 0, 0, 2]);
    }
}
