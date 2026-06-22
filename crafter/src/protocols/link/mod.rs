//! Link-layer protocol implementations.
//!
//! This module exposes the link roots and link-adjacent encapsulations used by
//! packet stacks: Ethernet, Linux cooked capture, null/loopback, radiotap,
//! IEEE 802.11 MAC frames, and LLC/SNAP. Wi-Fi IP payloads carry LLC/SNAP
//! explicitly; `Dot11 / Ipv4` is not rewritten into `Dot11 / LlcSnap / Ipv4`.
//!
//! ```rust
//! use crafter::prelude::*;
//! use std::net::Ipv4Addr;
//!
//! # fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
//! let station = MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x11]);
//! let access_point = MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x12]);
//! let packet = Radiotap::new()
//!     / Dot11::data()
//!         .addr1(access_point)
//!         .addr2(station)
//!         .addr3(access_point)
//!     / LlcSnap::new().ethertype(ETHERTYPE_IPV4)
//!     / Ipv4::new()
//!         .src(Ipv4Addr::new(192, 0, 2, 30))
//!         .dst(Ipv4Addr::new(198, 51, 100, 40))
//!     / Icmpv4::echo_request()
//!     / Raw::from("offline");
//!
//! let compiled = packet.compile()?;
//! let decoded = Packet::decode_from_link(LinkType::Radiotap, compiled.as_bytes())?;
//! assert!(decoded.layer::<Dot11>().is_some());
//! let _hexdump = compiled.hexdump();
//! # Ok(())
//! # }
//! ```

use core::any::Any;
use core::ops::Div;
use core::str::FromStr;

use crate::endian::{read_u16_be, read_u32_le};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::mac::MacAddr;
use crate::packet::{IntoPacket, Layer, LayerContext, NetworkLayer, Packet, Raw};
use crate::protocols::eapol::Eapol;
use crate::protocols::ipv4::Ipv4;
use crate::protocols::ipv6::Ipv6;
use crate::registry::ProtocolRegistry;

mod arp;
mod ble;
mod dot11;
mod dot15d4;
mod llc;
mod radiotap;

pub(crate) use self::arp::{append_arp_packet, decode_arp};
pub use self::arp::{
    arp_hardware_type_label, arp_protocol_type_label, Arp, ArpOperation, ARP_HRD_ATM,
    ARP_HRD_ETHERNET, ARP_HRD_FIBRE_CHANNEL, ARP_HRD_IEEE_802, ARP_HRD_INFINIBAND, ARP_HRD_MAPOS,
    ARP_OP_ARP_NAK, ARP_OP_DRARP_ERROR, ARP_OP_DRARP_REPLY, ARP_OP_DRARP_REQUEST, ARP_OP_EXP1,
    ARP_OP_EXP2, ARP_OP_INARP_REPLY, ARP_OP_INARP_REQUEST, ARP_OP_MAPOS_UNARP, ARP_OP_RARP_REPLY,
    ARP_OP_RARP_REQUEST, ARP_OP_REPLY, ARP_OP_REQUEST, ARP_OP_RESERVED, ARP_OP_RESERVED_MAX,
    ARP_PRO_IPV4,
};
pub(crate) use self::ble::decode_ble_adv;
use self::ble::decode_ble_radio;
pub use self::ble::{AdList, AdStructure, BleAdvPduType, BleLlAdv, BlePhy, BleRadio};
pub(crate) use self::dot11::decode_dot11_with_registry;
pub use self::dot11::*;
pub(crate) use self::llc::append_llc_snap_packet_with_registry;
pub use self::llc::LlcSnap;
pub(crate) use self::radiotap::decode_radiotap_with_registry;
pub use self::radiotap::*;

/// Ethernet type for IPv4 payloads.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// Ethernet type for ARP payloads.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// Ethernet type for 802.1Q VLAN tags.
pub const ETHERTYPE_VLAN: u16 = 0x8100;
/// Ethernet type for IPv6 payloads.
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
/// Ethernet type for IEEE 802.1X EAPOL payloads.
pub const ETHERTYPE_EAPOL: u16 = 0x888e;

const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_HEADER_LEN: usize = 4;
const LINUX_SLL_HEADER_LEN: usize = 16;
const NULL_LOOPBACK_HEADER_LEN: usize = 4;
const BLE_LL_ACCESS_ADDRESS_LEN: usize = 4;
const BLE_LL_CRC_LEN: usize = 3;

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

/// 802.1Q VLAN tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vlan {
    pcp: Field<u8>,
    dei: Field<bool>,
    vlan_id: Field<u16>,
    ethertype: Field<u16>,
}

/// Compatibility alias for an 802.1Q tag.
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

    /// Compatibility alias for priority.
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

    /// Compatibility alias for VLAN identifier.
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
pub(crate) fn decode_ethernet_with_registry(
    registry: &ProtocolRegistry,
    bytes: &[u8],
) -> Result<Packet> {
    if bytes.len() < ETHERNET_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ethernet header",
            ETHERNET_HEADER_LEN,
            bytes.len(),
        ));
    }

    let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
    let ethernet = Ethernet {
        destination: Field::user(MacAddr::new([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
        ])),
        source: Field::user(MacAddr::new([
            bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
        ])),
        ethertype: Field::user(ethertype),
    };

    let packet_capacity = match ethertype {
        ETHERTYPE_ARP => 2,
        ETHERTYPE_VLAN => 5,
        _ => 4,
    };
    let payload = &bytes[ETHERNET_HEADER_LEN..];
    if ethertype == ETHERTYPE_ARP && registry.uses_builtin_ethertype_dispatch() {
        let (arp, rest) = decode_arp(payload)?;
        let mut packet = Packet::with_capacity(if rest.is_empty() { 2 } else { 3 });
        packet.push_ethernet_mut(ethernet).push_arp_mut(arp);
        if !rest.is_empty() {
            packet.push_mut(Raw::from_bytes(rest));
        }
        return Ok(packet);
    }

    registry.decode_ethertype(
        Packet::with_capacity(packet_capacity).push_ethernet(ethernet),
        ethertype,
        payload,
    )
}

/// Decode a Linux cooked capture v1 frame.
pub(crate) fn decode_linux_sll_with_registry(
    registry: &ProtocolRegistry,
    bytes: &[u8],
) -> Result<Packet> {
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

    registry.decode_ethertype(
        Packet::new().push(linux_sll),
        protocol,
        &bytes[LINUX_SLL_HEADER_LEN..],
    )
}

/// Decode a little-endian BSD null/loopback frame.
pub(crate) fn decode_null_loopback_with_registry(
    registry: &ProtocolRegistry,
    bytes: &[u8],
) -> Result<Packet> {
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
    let payload = &bytes[NULL_LOOPBACK_HEADER_LEN..];
    if payload.is_empty() {
        return Ok(packet);
    }

    let family = packet
        .layer::<NullLoopback>()
        .map(NullLoopback::family_value)
        .unwrap_or_default();
    if family == 2 && payload.first().is_some_and(|first| first >> 4 == 4) {
        if let Ok(decoded) = registry.decode_from_l3(NetworkLayer::Ipv4, payload) {
            return Ok(packet.concat(decoded));
        }
    }

    packet = packet.push_raw(Raw::from_bytes(payload));
    Ok(packet)
}

/// Decode a BLE LE Link Layer frame with pcap pseudo-header metadata.
pub(crate) fn decode_ble_ll_with_registry(
    _registry: &ProtocolRegistry,
    bytes: &[u8],
) -> Result<Packet> {
    let (radio, rest) = decode_ble_radio(bytes)?;
    if rest.len() < BLE_LL_ACCESS_ADDRESS_LEN {
        return Err(CrafterError::buffer_too_short(
            "ble.ll.access_address",
            BLE_LL_ACCESS_ADDRESS_LEN,
            rest.len(),
        ));
    }

    let radio_access_address = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let ll_access_address = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
    if ll_access_address != radio_access_address {
        return Err(CrafterError::invalid_field_value(
            "ble.ll.access_address",
            "does not match pseudo-header access address",
        ));
    }

    let (adv, tail) = decode_ble_adv(&rest[BLE_LL_ACCESS_ADDRESS_LEN..])?;
    match tail.len() {
        0 | BLE_LL_CRC_LEN => {}
        1..=2 => {
            return Err(CrafterError::buffer_too_short(
                "ble.ll.crc",
                BLE_LL_CRC_LEN,
                tail.len(),
            ));
        }
        _ => {
            return Err(CrafterError::invalid_field_value(
                "ble.ll.trailer",
                "expected optional 3-byte CRC",
            ));
        }
    }

    Ok(Packet::new().push(radio).push(adv))
}

/// Append a decoded VLAN layer and dispatch its inner Ethernet type.
pub(crate) fn append_vlan_packet_with_registry(
    registry: &ProtocolRegistry,
    packet: Packet,
    payload: &[u8],
) -> Result<Packet> {
    let (vlan, rest) = decode_vlan(payload)?;
    let inner = vlan.ethertype_value();
    registry.decode_ethertype(packet.push_vlan(vlan), inner, rest)
}

fn decode_vlan(bytes: &[u8]) -> Result<(Vlan, &[u8])> {
    if bytes.len() < VLAN_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "vlan header",
            VLAN_HEADER_LEN,
            bytes.len(),
        ));
    }

    let tci = u16::from_be_bytes([bytes[0], bytes[1]]);
    let vlan = Vlan {
        pcp: Field::user((tci >> 13) as u8),
        dei: Field::user(((tci >> 12) & 1) != 0),
        vlan_id: Field::user(tci & 0x0fff),
        ethertype: Field::user(u16::from_be_bytes([bytes[2], bytes[3]])),
    };

    Ok((vlan, &bytes[VLAN_HEADER_LEN..]))
}

fn layer_ethertype(layer: &dyn Layer) -> Option<u16> {
    if layer.as_any().is::<Arp>() {
        Some(ETHERTYPE_ARP)
    } else if layer.as_any().is::<Vlan>() {
        Some(ETHERTYPE_VLAN)
    } else if layer.as_any().is::<Ipv4>() {
        Some(ETHERTYPE_IPV4)
    } else if layer.as_any().is::<Ipv6>() {
        Some(ETHERTYPE_IPV6)
    } else if layer.as_any().is::<Eapol>() {
        Some(ETHERTYPE_EAPOL)
    } else {
        None
    }
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn mac_from_bytes(bytes: &[u8]) -> Option<MacAddr> {
    if bytes.len() == 6 {
        Some(MacAddr::new(copy_array_6(bytes)))
    } else {
        None
    }
}

fn address_summary_mac(bytes: &[u8]) -> String {
    mac_from_bytes(bytes)
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| hex_bytes(bytes))
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

    const ETHERNET_FIXTURE: &[u8] = fixture_bytes!("bytes/ethernet-experimental-raw.bin");
    const ARP_REQUEST_FIXTURE: &[u8] = fixture_bytes!("bytes/arp-who-has.bin");

    fn src_mac() -> MacAddr {
        "02:00:5e:00:53:01".parse().unwrap()
    }

    fn dst_mac() -> MacAddr {
        "02:00:5e:00:53:02".parse().unwrap()
    }

    #[test]
    fn ethernet_frame_matches_golden_bytes() {
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
mod link_layers {
    use super::{
        decode_ble_ll_with_registry, Arp, Ethernet, LinuxSll, NullByteOrder, NullLoopback, Vlan,
        ETHERTYPE_IPV4,
    };
    use crate::registry::ProtocolRegistry;
    use crate::{Ipv4, Udp};
    use crate::{LinkType, MacAddr, Packet, Raw};
    use core::net::Ipv4Addr;

    const VLAN_FIXTURE: &[u8] = fixture_bytes!("bytes/ethernet-vlan-ipv4-udp-raw.bin");

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
        let ipv4 = decoded.layer::<Ipv4>().unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(ethernet.source(), Some(src_mac()));
        assert_eq!(ethernet.destination(), Some(dst_mac()));
        assert_eq!(vlan.pcp_value(), 3);
        assert!(!vlan.dei_value());
        assert_eq!(vlan.vlan_id_value(), 42);
        assert_eq!(vlan.ethertype_value(), ETHERTYPE_IPV4);
        assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 20));
        assert_eq!(udp.source_port_value(), 53002);
        assert_eq!(udp.destination_port_value(), 9999);
        assert_eq!(raw.as_bytes(), &VLAN_FIXTURE[46..]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), VLAN_FIXTURE);
    }

    #[test]
    fn vlan_builder_matches_golden_bytes_when_payload_is_known_bytes() {
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

    #[test]
    fn decode_ble_ll_builds_radio_and_advertising_layers() {
        let frame = [
            37, 0xc4, 0x00, 0x00, 0xd6, 0xbe, 0x89, 0x8e, 0x13, 0x0c, 0xd6, 0xbe, 0x89, 0x8e, 0x40,
            0x0f, 0x01, 0x53, 0x00, 0x5e, 0x00, 0x02, 0x02, 0x01, 0x06, 0x05, 0x09, b't', b'e',
            b's', b't', 0xaa, 0xbb, 0xcc,
        ];

        let decoded = decode_ble_ll_with_registry(ProtocolRegistry::builtin(), &frame).unwrap();
        let summary = decoded.summary();

        assert_eq!(decoded.iter().count(), 2);
        assert!(summary.contains("BleRadio"));
        assert!(summary.contains("BleLlAdv"));
    }

    #[test]
    fn ble_public_exports_resolve_at_crate_root() {
        let _radio: crate::BleRadio = crate::BleRadio::new().phy(crate::BlePhy::Le1M);
        let _adv: crate::BleLlAdv = crate::BleLlAdv::new().pdu_type(crate::BleAdvPduType::AdvInd);
        let ad: crate::AdStructure = crate::AdStructure::flags_general_disc();
        let _ads: crate::AdList = crate::AdList(vec![ad]);
    }
}
