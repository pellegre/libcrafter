//! Link-layer protocol implementations.

use core::any::Any;
use core::net::Ipv4Addr;
use core::ops::Div;
use core::str::FromStr;

use crate::endian::{read_u16_be, read_u32_le};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::mac::MacAddr;
use crate::packet::{IntoPacket, Layer, LayerContext, NetworkLayer, Packet, Raw};
use crate::protocols::ip::Ipv4;
use crate::protocols::ipv6::Ipv6;
use crate::registry::ProtocolRegistry;

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

/// ARP operation codepoint: Reserved (RFC 5494, IANA arp-parameters-1 value 0).
pub const ARP_OP_RESERVED: u16 = 0;
/// ARP operation codepoint: REQUEST (RFC 826, IANA arp-parameters-1 value 1).
pub const ARP_OP_REQUEST: u16 = 1;
/// ARP operation codepoint: REPLY (RFC 826, IANA arp-parameters-1 value 2).
pub const ARP_OP_REPLY: u16 = 2;
/// ARP operation codepoint: request Reverse / RARP request
/// (RFC 903, IANA arp-parameters-1 value 3). Codepoint-only: rides the base
/// ARP wire format with no extension-specific behavior.
pub const ARP_OP_RARP_REQUEST: u16 = 3;
/// ARP operation codepoint: reply Reverse / RARP reply
/// (RFC 903, IANA arp-parameters-1 value 4). Codepoint-only.
pub const ARP_OP_RARP_REPLY: u16 = 4;
/// ARP operation codepoint: DRARP-Request
/// (RFC 1931, IANA arp-parameters-1 value 5). Codepoint-only.
pub const ARP_OP_DRARP_REQUEST: u16 = 5;
/// ARP operation codepoint: DRARP-Reply
/// (RFC 1931, IANA arp-parameters-1 value 6). Codepoint-only.
pub const ARP_OP_DRARP_REPLY: u16 = 6;
/// ARP operation codepoint: DRARP-Error
/// (RFC 1931, IANA arp-parameters-1 value 7). Codepoint-only.
pub const ARP_OP_DRARP_ERROR: u16 = 7;
/// ARP operation codepoint: InARP-Request
/// (RFC 2390, IANA arp-parameters-1 value 8). Codepoint-only.
pub const ARP_OP_INARP_REQUEST: u16 = 8;
/// ARP operation codepoint: InARP-Reply
/// (RFC 2390, IANA arp-parameters-1 value 9). Codepoint-only.
pub const ARP_OP_INARP_REPLY: u16 = 9;
/// ARP operation codepoint: ARP-NAK
/// (RFC 1577, IANA arp-parameters-1 value 10). Codepoint-only.
pub const ARP_OP_ARP_NAK: u16 = 10;
/// ARP operation codepoint: MAPOS-UNARP
/// (RFC 2176, IANA arp-parameters-1 value 23). Codepoint-only.
pub const ARP_OP_MAPOS_UNARP: u16 = 23;
/// ARP operation codepoint: experimental OP_EXP1
/// (RFC 5494, IANA arp-parameters-1 value 24).
pub const ARP_OP_EXP1: u16 = 24;
/// ARP operation codepoint: experimental OP_EXP2
/// (RFC 5494, IANA arp-parameters-1 value 25).
pub const ARP_OP_EXP2: u16 = 25;
/// ARP operation codepoint: Reserved (RFC 5494, IANA arp-parameters-1 value 65535).
pub const ARP_OP_RESERVED_MAX: u16 = 65535;

/// ARP hardware type: Ethernet (10Mb) (IANA arp-parameters-2 value 1). Default HRD.
pub const ARP_HRD_ETHERNET: u16 = 1;
/// ARP hardware type: IEEE 802 Networks (IANA arp-parameters-2 value 6).
pub const ARP_HRD_IEEE_802: u16 = 6;
/// ARP hardware type: Fibre Channel (RFC 4338, IANA arp-parameters-2 value 18).
pub const ARP_HRD_FIBRE_CHANNEL: u16 = 18;
/// ARP hardware type: ATM (RFC 2225, IANA arp-parameters-2 value 19).
pub const ARP_HRD_ATM: u16 = 19;
/// ARP hardware type: MAPOS (RFC 2176, IANA arp-parameters-2 value 25).
pub const ARP_HRD_MAPOS: u16 = 25;
/// ARP hardware type: InfiniBand (RFC 4391, IANA arp-parameters-2 value 32).
pub const ARP_HRD_INFINIBAND: u16 = 32;

/// ARP protocol type: IPv4. The protocol-type field shares the EtherType space
/// (IANA arp-parameters-3, administered per RFC 5342), so this equals
/// [`ETHERTYPE_IPV4`]. Default PRO.
pub const ARP_PRO_IPV4: u16 = ETHERTYPE_IPV4;

/// Short label for a known ARP hardware type, or `None` for unknown values.
///
/// This is a data-only lookup over the source-backed hardware-type codepoints
/// (IANA registry arp-parameters-2, `target/arp-rfc/scope.md`). It never blocks
/// or rewrites any value: unknown numeric hardware types simply return `None`
/// and remain usable through [`Arp::hardware_type`]. Mirrors the
/// [`ArpOperation::label`] shape so summaries and generated tools can recognize
/// a hardware type without narrowing the packet model.
pub fn arp_hardware_type_label(hardware_type: u16) -> Option<&'static str> {
    match hardware_type {
        ARP_HRD_ETHERNET => Some("ethernet"),
        ARP_HRD_IEEE_802 => Some("ieee-802"),
        ARP_HRD_FIBRE_CHANNEL => Some("fibre-channel"),
        ARP_HRD_ATM => Some("atm"),
        ARP_HRD_MAPOS => Some("mapos"),
        ARP_HRD_INFINIBAND => Some("infiniband"),
        _ => None,
    }
}

/// Short label for a known ARP protocol type, or `None` for unknown values.
///
/// This is a data-only lookup over the source-backed protocol-type codepoints.
/// The ARP protocol-type field shares the EtherType space (IANA registry
/// arp-parameters-3, administered per RFC 5342), and that sub-registry returned
/// no records of its own in the manifest build, so the only source-backed known
/// value is the IPv4 default ([`ARP_PRO_IPV4`] = [`ETHERTYPE_IPV4`])
/// (`target/arp-rfc/scope.md`, assumption 3). It never blocks or rewrites any
/// value: unknown numeric protocol types simply return `None` and remain usable
/// through [`Arp::protocol_type`]. Mirrors the [`arp_hardware_type_label`] shape
/// so summaries and generated tools can recognize a protocol type without
/// narrowing the packet model.
pub fn arp_protocol_type_label(protocol_type: u16) -> Option<&'static str> {
    match protocol_type {
        ARP_PRO_IPV4 => Some("ipv4"),
        _ => None,
    }
}

/// ARP operation value.
///
/// Source-backed known operation codepoints from IANA registry
/// arp-parameters-1 (`target/arp-rfc/scope.md`). Base ARP behavior is built
/// around [`ArpOperation::Request`] and [`ArpOperation::Reply`] (RFC 826); the
/// remaining ARP-family operations are exposed as named codepoints only, with
/// no extension-specific behavior. Unknown numeric values are never blocked:
/// use [`Arp::opcode`] for any value this enum does not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u16)]
pub enum ArpOperation {
    /// ARP who-has request (RFC 826).
    Request = ARP_OP_REQUEST,
    /// ARP is-at reply (RFC 826).
    Reply = ARP_OP_REPLY,
    /// RARP request (RFC 903).
    RarpRequest = ARP_OP_RARP_REQUEST,
    /// RARP reply (RFC 903).
    RarpReply = ARP_OP_RARP_REPLY,
    /// DRARP request (RFC 1931).
    DrarpRequest = ARP_OP_DRARP_REQUEST,
    /// DRARP reply (RFC 1931).
    DrarpReply = ARP_OP_DRARP_REPLY,
    /// DRARP error (RFC 1931).
    DrarpError = ARP_OP_DRARP_ERROR,
    /// Inverse ARP request (RFC 2390).
    InArpRequest = ARP_OP_INARP_REQUEST,
    /// Inverse ARP reply (RFC 2390).
    InArpReply = ARP_OP_INARP_REPLY,
    /// ARP-NAK (RFC 1577).
    ArpNak = ARP_OP_ARP_NAK,
    /// MAPOS UNARP (RFC 2176).
    MaposUnarp = ARP_OP_MAPOS_UNARP,
}

impl ArpOperation {
    /// Map a raw operation opcode to a named [`ArpOperation`].
    ///
    /// Returns `None` for any value not named by this enum (reserved,
    /// experimental, MARS, or unassigned codepoints, and any other unknown
    /// number). Those values stay usable through [`Arp::opcode`] and remain
    /// round-trippable; this conversion only reports whether a name exists.
    pub fn from_opcode(opcode: u16) -> Option<Self> {
        match opcode {
            ARP_OP_REQUEST => Some(Self::Request),
            ARP_OP_REPLY => Some(Self::Reply),
            ARP_OP_RARP_REQUEST => Some(Self::RarpRequest),
            ARP_OP_RARP_REPLY => Some(Self::RarpReply),
            ARP_OP_DRARP_REQUEST => Some(Self::DrarpRequest),
            ARP_OP_DRARP_REPLY => Some(Self::DrarpReply),
            ARP_OP_DRARP_ERROR => Some(Self::DrarpError),
            ARP_OP_INARP_REQUEST => Some(Self::InArpRequest),
            ARP_OP_INARP_REPLY => Some(Self::InArpReply),
            ARP_OP_ARP_NAK => Some(Self::ArpNak),
            ARP_OP_MAPOS_UNARP => Some(Self::MaposUnarp),
            _ => None,
        }
    }

    /// Numeric opcode for this operation (IANA arp-parameters-1).
    pub fn opcode(self) -> u16 {
        self as u16
    }

    /// Short, stable label for this operation.
    ///
    /// `Request`/`Reply` keep the `request`/`reply` labels base ARP summaries
    /// have always used; the remaining ARP-family operations use compact names.
    pub fn label(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Reply => "reply",
            Self::RarpRequest => "rarp-request",
            Self::RarpReply => "rarp-reply",
            Self::DrarpRequest => "drarp-request",
            Self::DrarpReply => "drarp-reply",
            Self::DrarpError => "drarp-error",
            Self::InArpRequest => "inarp-request",
            Self::InArpReply => "inarp-reply",
            Self::ArpNak => "arp-nak",
            Self::MaposUnarp => "mapos-unarp",
        }
    }
}

impl From<ArpOperation> for u16 {
    fn from(value: ArpOperation) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for ArpOperation {
    type Error = u16;

    /// Convert a raw opcode into a named operation, returning the original
    /// value as the error when it is not a known codepoint so callers can keep
    /// it via [`Arp::opcode`].
    fn try_from(value: u16) -> core::result::Result<Self, Self::Error> {
        Self::from_opcode(value).ok_or(value)
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

    /// Compatibility alias for sender hardware address.
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

    /// Compatibility alias for target hardware address.
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

    /// Compatibility alias for sender protocol address.
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

    /// Compatibility alias for target protocol address.
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

    /// Set the sender hardware address from raw bytes of any length and let the
    /// hardware address length follow the byte count.
    ///
    /// This is the canonical generic path for variable-length or unknown-family
    /// hardware addresses. The hardware address length is filled from the byte
    /// count only when it has not been explicitly set with [`Arp::hardware_len`];
    /// an explicit length is always honored, even when it disagrees with the
    /// bytes, so deliberately inconsistent packets remain expressible. The raw
    /// bytes themselves are never rewritten.
    pub fn sender_hardware(mut self, address: impl Into<Vec<u8>>) -> Self {
        let bytes = address.into();
        self.fill_hardware_len_from(&bytes);
        self.sender_hardware_addr.set_user(bytes);
        self
    }

    /// Set the target hardware address from raw bytes of any length and let the
    /// hardware address length follow the byte count.
    ///
    /// See [`Arp::sender_hardware`] for the length-fill and override rules.
    pub fn target_hardware(mut self, address: impl Into<Vec<u8>>) -> Self {
        let bytes = address.into();
        self.fill_hardware_len_from(&bytes);
        self.target_hardware_addr.set_user(bytes);
        self
    }

    /// Set the sender protocol address from raw bytes of any length and let the
    /// protocol address length follow the byte count.
    ///
    /// This is the canonical generic path for variable-length or unknown-family
    /// protocol addresses. The protocol address length is filled from the byte
    /// count only when it has not been explicitly set with [`Arp::protocol_len`];
    /// an explicit length is always honored, even when it disagrees with the
    /// bytes. The raw bytes themselves are never rewritten.
    pub fn sender_protocol(mut self, address: impl Into<Vec<u8>>) -> Self {
        let bytes = address.into();
        self.fill_protocol_len_from(&bytes);
        self.sender_protocol_addr.set_user(bytes);
        self
    }

    /// Set the target protocol address from raw bytes of any length and let the
    /// protocol address length follow the byte count.
    ///
    /// See [`Arp::sender_protocol`] for the length-fill and override rules.
    pub fn target_protocol(mut self, address: impl Into<Vec<u8>>) -> Self {
        let bytes = address.into();
        self.fill_protocol_len_from(&bytes);
        self.target_protocol_addr.set_user(bytes);
        self
    }

    /// Fill the hardware address length from a byte slice unless the caller set
    /// it explicitly. A length truncated by [`u8`] saturation is left for the
    /// later compile-time length validation rather than silently corrected.
    fn fill_hardware_len_from(&mut self, bytes: &[u8]) {
        if !self.hardware_len.is_user_set() {
            self.hardware_len = Field::defaulted(saturating_len_u8(bytes.len()));
        }
    }

    /// Fill the protocol address length from a byte slice unless the caller set
    /// it explicitly. See [`Arp::fill_hardware_len_from`].
    fn fill_protocol_len_from(&mut self, bytes: &[u8]) {
        if !self.protocol_len.is_user_set() {
            self.protocol_len = Field::defaulted(saturating_len_u8(bytes.len()));
        }
    }

    /// Hardware type value.
    pub fn hardware_type_value(&self) -> u16 {
        value_or_copy(&self.hardware_type, 1)
    }

    /// Short label for this packet's hardware type, or `None` if it is not a
    /// known source-backed codepoint (IANA arp-parameters-2). Unknown numeric
    /// hardware types stay intact and usable; this only reports whether a name
    /// exists. See [`arp_hardware_type_label`].
    pub fn hardware_type_label(&self) -> Option<&'static str> {
        arp_hardware_type_label(self.hardware_type_value())
    }

    /// Protocol type value.
    pub fn protocol_type_value(&self) -> u16 {
        value_or_copy(&self.protocol_type, ETHERTYPE_IPV4)
    }

    /// Short label for this packet's protocol type, or `None` if it is not a
    /// known source-backed codepoint. The ARP protocol-type field shares the
    /// EtherType space (IANA arp-parameters-3), so the only source-backed known
    /// value is the IPv4 default. Unknown numeric protocol types stay intact and
    /// usable; this only reports whether a name exists. See
    /// [`arp_protocol_type_label`].
    pub fn protocol_type_label(&self) -> Option<&'static str> {
        arp_protocol_type_label(self.protocol_type_value())
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

    let ethernet = Ethernet {
        destination: Field::user(MacAddr::new(copy_array_6(&bytes[0..6]))),
        source: Field::user(MacAddr::new(copy_array_6(&bytes[6..12]))),
        ethertype: Field::user(read_u16_be(&bytes[12..14])?),
    };

    registry.decode_ethertype(
        Packet::new().push(ethernet),
        read_u16_be(&bytes[12..14])?,
        &bytes[ETHERNET_HEADER_LEN..],
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

    packet = packet.push(Raw::from_bytes(payload));
    Ok(packet)
}

/// Append a decoded ARP packet to an existing packet stack.
pub(crate) fn append_arp_packet(mut packet: Packet, payload: &[u8]) -> Result<Packet> {
    let (arp, rest) = decode_arp(payload)?;
    packet = packet.push(arp);
    if !rest.is_empty() {
        packet = packet.push(Raw::from_bytes(rest));
    }
    Ok(packet)
}

/// Append a decoded VLAN layer and dispatch its inner Ethernet type.
pub(crate) fn append_vlan_packet_with_registry(
    registry: &ProtocolRegistry,
    packet: Packet,
    payload: &[u8],
) -> Result<Packet> {
    let (vlan, rest) = decode_vlan(payload)?;
    let inner = vlan.ethertype_value();
    registry.decode_ethertype(packet.push(vlan), inner, rest)
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
    } else if layer.as_any().is::<Ipv4>() {
        Some(ETHERTYPE_IPV4)
    } else if layer.as_any().is::<Ipv6>() {
        Some(ETHERTYPE_IPV6)
    } else {
        None
    }
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

/// Clamp a byte length into the [`u8`] ARP length field without overflow. A
/// length beyond 255 is saturated rather than wrapped so it surfaces as a
/// length mismatch at compile time instead of silently aliasing a small value.
fn saturating_len_u8(len: usize) -> u8 {
    u8::try_from(len).unwrap_or(u8::MAX)
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
            // The declared ARP length field and the explicit address byte vector
            // disagree. Surface a structured error that names the failing field
            // and both the expected length (the declared length field) and the
            // available length (the supplied byte count). `expected` is a `u8`,
            // so the required/available widths are bounded and the comparison
            // cannot overflow even at the `u8::MAX` boundary.
            return Err(CrafterError::buffer_too_short(
                field,
                expected as usize,
                value.len(),
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
    match ArpOperation::from_opcode(operation) {
        Some(named) => named.label().to_string(),
        None => operation.to_string(),
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
mod arp {
    use super::{Arp, ArpOperation, Ethernet, ETHERTYPE_ARP};
    use crate::{CrafterError, LinkType, MacAddr, Packet};
    use core::net::Ipv4Addr;

    const ARP_REQUEST_FIXTURE: &[u8] = fixture_bytes!("bytes/arp-who-has.bin");

    fn src_mac() -> MacAddr {
        "02:00:5e:00:53:01".parse().unwrap()
    }

    #[test]
    fn arp_request_matches_golden_bytes() {
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

        // The conflict surfaces as a structured error naming the failing field
        // and both the declared length (5) and the supplied byte count (6).
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "arp.sender_hardware_addr");
                assert_eq!(required, 5);
                assert_eq!(available, 6);
            }
            other => panic!("expected a structured length error, got {other:?}"),
        }
    }

    #[test]
    fn arp_length_matching_explicit_lengths_compile_without_false_positive() {
        // Explicit length fields that agree with the supplied byte vectors must
        // not trip the conflict check. A nonstandard but self-consistent
        // 8-octet hardware / 16-octet protocol body compiles cleanly and the
        // declared lengths reach the wire unchanged.
        let sender_hw = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];
        let sender_pa = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let target_hw = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let target_pa = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

        let arp = Arp::new()
            .hardware_len(8)
            .protocol_len(16)
            .sender_hardware_bytes(sender_hw.clone())
            .sender_protocol_bytes(sender_pa.clone())
            .target_hardware_bytes(target_hw.clone())
            .target_protocol_bytes(target_pa.clone());

        let frame = Ethernet::new().src(src_mac()) / arp;
        let compiled = frame.compile().expect("matching lengths must compile");
        let decoded = Packet::decode_from_link(LinkType::Ethernet, compiled.as_bytes()).unwrap();
        let decoded_arp = decoded.layer::<Arp>().unwrap();
        assert_eq!(decoded_arp.hardware_len_value(), 8);
        assert_eq!(decoded_arp.protocol_len_value(), 16);
        assert_eq!(decoded_arp.sender_hardware_bytes_value(), sender_hw);
        assert_eq!(decoded_arp.target_protocol_bytes_value(), target_pa);
    }

    #[test]
    fn arp_length_mismatch_on_protocol_field_returns_structured_error() {
        // A length conflict on the protocol address field (not just the
        // hardware field) is rejected with a structured error that names the
        // failing field and the declared vs. supplied lengths. This guards
        // against a validation gap that only checks one of the two length
        // fields.
        let packet = Packet::new().push(
            Arp::new()
                .protocol_len(6)
                .sender_protocol_bytes(vec![192, 0, 2, 10]),
        );
        let err = packet.compile().unwrap_err();
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "arp.sender_protocol_addr");
                assert_eq!(required, 6);
                assert_eq!(available, 4);
            }
            other => panic!("expected a structured length error, got {other:?}"),
        }
    }

    #[test]
    fn arp_length_mismatch_on_target_field_returns_structured_error() {
        // The conflict check covers the target address fields as well, so a
        // target hardware byte vector that disagrees with the declared
        // hardware length is rejected with the failing field named.
        let packet = Packet::new().push(
            Arp::new()
                .hardware_len(6)
                .target_hardware_bytes(vec![0xde, 0xad, 0xbe]),
        );
        let err = packet.compile().unwrap_err();
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "arp.target_hardware_addr");
                assert_eq!(required, 6);
                assert_eq!(available, 3);
            }
            other => panic!("expected a structured length error, got {other:?}"),
        }
    }

    #[test]
    fn arp_length_zero_length_addresses_compile_and_round_trip() {
        // Zero-length addresses are valid generic-format ARP per the scope
        // decision (target/arp-rfc/scope.md). An explicit zero length that
        // agrees with empty byte vectors must not be flagged as a conflict,
        // and the eight-byte fixed header round-trips byte-exact.
        let arp = Arp::new()
            .hardware_len(0)
            .protocol_len(0)
            .sender_hardware_bytes(Vec::new())
            .sender_protocol_bytes(Vec::new())
            .target_hardware_bytes(Vec::new())
            .target_protocol_bytes(Vec::new());

        let frame = Ethernet::new().src(src_mac()) / arp;
        let compiled = frame.compile().expect("zero-length ARP must compile");
        let decoded = Packet::decode_from_link(LinkType::Ethernet, compiled.as_bytes()).unwrap();
        let decoded_arp = decoded.layer::<Arp>().unwrap();
        assert_eq!(decoded_arp.hardware_len_value(), 0);
        assert_eq!(decoded_arp.protocol_len_value(), 0);
        assert!(decoded_arp.sender_hardware_bytes_value().is_empty());
        assert!(decoded_arp.target_protocol_bytes_value().is_empty());
    }

    #[test]
    fn arp_length_zero_length_field_against_nonempty_bytes_is_a_conflict() {
        // A zero-length field paired with a non-empty byte vector is still a
        // conflict: zero-length is only valid when the bytes are also empty.
        let packet = Packet::new().push(
            Arp::new()
                .protocol_len(0)
                .sender_protocol_bytes(vec![0x01]),
        );
        let err = packet.compile().unwrap_err();
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "arp.sender_protocol_addr");
                assert_eq!(required, 0);
                assert_eq!(available, 1);
            }
            other => panic!("expected a structured length error, got {other:?}"),
        }
    }

    #[test]
    fn arp_length_maximum_u8_length_arithmetic_does_not_overflow() {
        // The maximum representable ARP length is u8::MAX (255). A byte vector
        // of exactly that width agrees with an explicit u8::MAX length and must
        // compile; the encoded_len arithmetic (fixed header + len*2 + len*2)
        // must not overflow. encoded_len reports 8 + 255*2 + 255*2 = 1028.
        let max = u8::MAX;
        let full = vec![0x5a_u8; max as usize];

        let arp = Arp::new()
            .hardware_len(max)
            .protocol_len(max)
            .sender_hardware_bytes(full.clone())
            .sender_protocol_bytes(full.clone())
            .target_hardware_bytes(full.clone())
            .target_protocol_bytes(full.clone());

        assert_eq!(arp.hardware_len_value(), max);
        assert_eq!(arp.protocol_len_value(), max);

        let frame = Ethernet::new().src(src_mac()) / arp;
        let compiled = frame
            .compile()
            .expect("maximum-width ARP addresses must compile");
        let decoded = Packet::decode_from_link(LinkType::Ethernet, compiled.as_bytes()).unwrap();
        let decoded_arp = decoded.layer::<Arp>().unwrap();
        assert_eq!(decoded_arp.hardware_len_value(), max);
        assert_eq!(decoded_arp.protocol_len_value(), max);
        assert_eq!(decoded_arp.sender_hardware_bytes_value(), full);
        assert_eq!(decoded_arp.target_protocol_bytes_value(), full);
    }

    #[test]
    fn arp_length_oversized_byte_vector_saturates_then_conflicts() {
        // A byte vector beyond the u8 length field saturates the auto-filled
        // length to u8::MAX rather than wrapping, so the genuine mismatch
        // (300 bytes vs. a 255 length ceiling) is caught by the conflict check
        // at compile time instead of silently aliasing a small length.
        let oversized = vec![0u8; 300];
        let arp = Arp::new().sender_hardware(oversized);
        assert_eq!(arp.hardware_len_value(), u8::MAX);

        let err = (Ethernet::new().src(src_mac()) / arp)
            .compile()
            .unwrap_err();
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "arp.sender_hardware_addr");
                assert_eq!(required, u8::MAX as usize);
                assert_eq!(available, 300);
            }
            other => panic!("expected a structured length error, got {other:?}"),
        }
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

    #[test]
    fn arp_constants_match_source_backed_codepoints() {
        use super::{
            ARP_HRD_ATM, ARP_HRD_ETHERNET, ARP_HRD_FIBRE_CHANNEL, ARP_HRD_IEEE_802,
            ARP_HRD_INFINIBAND, ARP_HRD_MAPOS, ARP_OP_ARP_NAK, ARP_OP_DRARP_ERROR,
            ARP_OP_DRARP_REPLY, ARP_OP_DRARP_REQUEST, ARP_OP_EXP1, ARP_OP_EXP2, ARP_OP_INARP_REPLY,
            ARP_OP_INARP_REQUEST, ARP_OP_MAPOS_UNARP, ARP_OP_RARP_REPLY, ARP_OP_RARP_REQUEST,
            ARP_OP_REPLY, ARP_OP_REQUEST, ARP_OP_RESERVED, ARP_OP_RESERVED_MAX, ARP_PRO_IPV4,
            ETHERTYPE_IPV4,
        };

        // Operation codepoints (IANA arp-parameters-1).
        assert_eq!(ARP_OP_RESERVED, 0);
        assert_eq!(ARP_OP_REQUEST, 1);
        assert_eq!(ARP_OP_REPLY, 2);
        assert_eq!(ARP_OP_RARP_REQUEST, 3);
        assert_eq!(ARP_OP_RARP_REPLY, 4);
        assert_eq!(ARP_OP_DRARP_REQUEST, 5);
        assert_eq!(ARP_OP_DRARP_REPLY, 6);
        assert_eq!(ARP_OP_DRARP_ERROR, 7);
        assert_eq!(ARP_OP_INARP_REQUEST, 8);
        assert_eq!(ARP_OP_INARP_REPLY, 9);
        assert_eq!(ARP_OP_ARP_NAK, 10);
        assert_eq!(ARP_OP_MAPOS_UNARP, 23);
        assert_eq!(ARP_OP_EXP1, 24);
        assert_eq!(ARP_OP_EXP2, 25);
        assert_eq!(ARP_OP_RESERVED_MAX, 65535);

        // Named operations agree with the existing ArpOperation enum.
        assert_eq!(ARP_OP_REQUEST, ArpOperation::Request as u16);
        assert_eq!(ARP_OP_REPLY, ArpOperation::Reply as u16);

        // Hardware-type codepoints (IANA arp-parameters-2).
        assert_eq!(ARP_HRD_ETHERNET, 1);
        assert_eq!(ARP_HRD_IEEE_802, 6);
        assert_eq!(ARP_HRD_FIBRE_CHANNEL, 18);
        assert_eq!(ARP_HRD_ATM, 19);
        assert_eq!(ARP_HRD_MAPOS, 25);
        assert_eq!(ARP_HRD_INFINIBAND, 32);

        // Protocol type shares the EtherType space (IANA arp-parameters-3 / RFC 5342).
        assert_eq!(ARP_PRO_IPV4, ETHERTYPE_IPV4);
    }

    #[test]
    fn arp_constants_drive_builder_and_preserve_unknown_values() {
        use super::{ARP_HRD_INFINIBAND, ARP_OP_INARP_REQUEST};

        // Known codepoint constant works through the raw opcode escape hatch.
        let arp = Arp::new()
            .hardware_type(ARP_HRD_INFINIBAND)
            .opcode(ARP_OP_INARP_REQUEST);
        assert_eq!(arp.hardware_type_value(), ARP_HRD_INFINIBAND);
        assert_eq!(arp.opcode_value(), ARP_OP_INARP_REQUEST);

        // An unknown numeric value the constants do not name stays usable and intact.
        let unknown_op: u16 = 0x0fa0;
        let unknown = Arp::new().opcode(unknown_op);
        assert_eq!(unknown.opcode_value(), unknown_op);
    }

    #[test]
    fn arp_constants_reexported_through_prelude() {
        use crate::prelude::{ARP_OP_REPLY, ARP_OP_REQUEST};

        assert_eq!(ARP_OP_REQUEST, 1);
        assert_eq!(ARP_OP_REPLY, 2);
    }

    #[test]
    fn arp_operation_names_known_source_backed_codepoints() {
        use super::{
            ARP_OP_ARP_NAK, ARP_OP_DRARP_ERROR, ARP_OP_DRARP_REPLY, ARP_OP_DRARP_REQUEST,
            ARP_OP_INARP_REPLY, ARP_OP_INARP_REQUEST, ARP_OP_MAPOS_UNARP, ARP_OP_RARP_REPLY,
            ARP_OP_RARP_REQUEST, ARP_OP_REPLY, ARP_OP_REQUEST,
        };
        use crate::packet::Layer;

        // Every named operation round-trips opcode <-> enum (IANA arp-parameters-1).
        let named = [
            (ArpOperation::Request, ARP_OP_REQUEST),
            (ArpOperation::Reply, ARP_OP_REPLY),
            (ArpOperation::RarpRequest, ARP_OP_RARP_REQUEST),
            (ArpOperation::RarpReply, ARP_OP_RARP_REPLY),
            (ArpOperation::DrarpRequest, ARP_OP_DRARP_REQUEST),
            (ArpOperation::DrarpReply, ARP_OP_DRARP_REPLY),
            (ArpOperation::DrarpError, ARP_OP_DRARP_ERROR),
            (ArpOperation::InArpRequest, ARP_OP_INARP_REQUEST),
            (ArpOperation::InArpReply, ARP_OP_INARP_REPLY),
            (ArpOperation::ArpNak, ARP_OP_ARP_NAK),
            (ArpOperation::MaposUnarp, ARP_OP_MAPOS_UNARP),
        ];

        for (operation, opcode) in named {
            assert_eq!(operation.opcode(), opcode);
            assert_eq!(u16::from(operation), opcode);
            assert_eq!(ArpOperation::from_opcode(opcode), Some(operation));
            assert_eq!(ArpOperation::try_from(opcode), Ok(operation));

            // Building through the typed setter records the same opcode.
            let arp = Arp::new().operation(operation);
            assert_eq!(arp.opcode_value(), opcode);
        }

        // request/reply keep their historic short summary labels (golden output).
        assert_eq!(ArpOperation::Request.label(), "request");
        assert_eq!(ArpOperation::Reply.label(), "reply");
        // ARP-family operations are surfaced in summaries by name.
        assert_eq!(ArpOperation::InArpRequest.label(), "inarp-request");

        let reply = Arp::new().operation(ArpOperation::Reply);
        assert!(reply.summary().contains("op=reply"));
        let inarp = Arp::new().operation(ArpOperation::InArpRequest);
        assert!(inarp.summary().contains("op=inarp-request"));
    }

    #[test]
    fn arp_unknown_opcode_stays_numeric_and_round_trips() {
        use crate::packet::Layer;
        use crate::{LinkType, Packet};

        // Values the enum does not name have no conversion but stay usable.
        for unknown in [0_u16, 11, 22, 24, 25, 1024, 0x1234, 65279, 65535] {
            assert_eq!(ArpOperation::from_opcode(unknown), None);
            assert_eq!(ArpOperation::try_from(unknown), Err(unknown));

            let arp = Arp::new().opcode(unknown);
            assert_eq!(arp.opcode_value(), unknown);
            // Unknown opcodes show as their numeric value in summaries.
            assert!(arp.summary().contains(&format!("op={unknown}")));
        }

        // An unknown opcode survives a full Ethernet/ARP compile -> decode cycle.
        let unknown_op: u16 = 0x0fa0;
        let packet = Ethernet::new().src(src_mac())
            / Arp::who_has(
                Ipv4Addr::new(192, 0, 2, 10),
                Ipv4Addr::new(192, 0, 2, 1),
                src_mac(),
            )
            .opcode(unknown_op);
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, bytes.as_bytes()).unwrap();
        let arp = decoded.layer::<Arp>().unwrap();
        assert_eq!(arp.opcode_value(), unknown_op);
        assert_eq!(ArpOperation::from_opcode(arp.opcode_value()), None);
    }

    #[test]
    fn arp_hardware_type_labels_known_source_backed_codepoints() {
        use super::{
            arp_hardware_type_label, ARP_HRD_ATM, ARP_HRD_ETHERNET, ARP_HRD_FIBRE_CHANNEL,
            ARP_HRD_IEEE_802, ARP_HRD_INFINIBAND, ARP_HRD_MAPOS,
        };

        // Each scoped hardware-type constant (IANA arp-parameters-2) gets a label.
        let named = [
            (ARP_HRD_ETHERNET, "ethernet"),
            (ARP_HRD_IEEE_802, "ieee-802"),
            (ARP_HRD_FIBRE_CHANNEL, "fibre-channel"),
            (ARP_HRD_ATM, "atm"),
            (ARP_HRD_MAPOS, "mapos"),
            (ARP_HRD_INFINIBAND, "infiniband"),
        ];

        for (value, label) in named {
            assert_eq!(arp_hardware_type_label(value), Some(label));

            // The same lookup is reachable from a built packet's accessor, and
            // setting the value through the raw u16 setter is preserved intact.
            let arp = Arp::new().hardware_type(value);
            assert_eq!(arp.hardware_type_value(), value);
            assert_eq!(arp.hardware_type_label(), Some(label));
        }
    }

    #[test]
    fn arp_hardware_type_unknown_values_stay_raw_and_unlabeled() {
        use super::{arp_hardware_type_label, ARP_HRD_ETHERNET};

        // Values the registry lookup does not name return None but remain
        // fully usable through the raw hardware_type(u16) setter.
        for unknown in [0_u16, 2, 7, 100, 0x1234, 65535] {
            assert_eq!(arp_hardware_type_label(unknown), None);

            let arp = Arp::new().hardware_type(unknown);
            assert_eq!(arp.hardware_type_value(), unknown);
            assert_eq!(arp.hardware_type_label(), None);
        }

        // The default hardware type (unset) is still Ethernet and labels as such.
        let default_arp = Arp::new();
        assert_eq!(default_arp.hardware_type_value(), ARP_HRD_ETHERNET);
        assert_eq!(default_arp.hardware_type_label(), Some("ethernet"));
    }

    #[test]
    fn arp_hardware_type_label_reexported_through_prelude() {
        use crate::prelude::{arp_hardware_type_label, ARP_HRD_INFINIBAND};

        assert_eq!(
            arp_hardware_type_label(ARP_HRD_INFINIBAND),
            Some("infiniband")
        );
        assert_eq!(arp_hardware_type_label(0x4242), None);
    }

    #[test]
    fn arp_protocol_type_label_known_source_backed_codepoint() {
        use super::{arp_protocol_type_label, ARP_PRO_IPV4, ETHERTYPE_IPV4};

        // The only source-backed known protocol type is IPv4: arp-parameters-3
        // shares the EtherType space and returned no records of its own
        // (scope.md assumption 3). ARP_PRO_IPV4 == ETHERTYPE_IPV4.
        assert_eq!(ARP_PRO_IPV4, ETHERTYPE_IPV4);
        assert_eq!(arp_protocol_type_label(ARP_PRO_IPV4), Some("ipv4"));

        // The label is reachable from a built packet's accessor, and the raw
        // u16 setter preserves the value intact.
        let arp = Arp::new().protocol_type(ARP_PRO_IPV4);
        assert_eq!(arp.protocol_type_value(), ARP_PRO_IPV4);
        assert_eq!(arp.protocol_type_label(), Some("ipv4"));

        // The default protocol type (unset) is still IPv4 and labels as such.
        let default_arp = Arp::new();
        assert_eq!(default_arp.protocol_type_value(), ETHERTYPE_IPV4);
        assert_eq!(default_arp.protocol_type_label(), Some("ipv4"));
    }

    #[test]
    fn arp_protocol_type_unknown_values_stay_raw_and_unlabeled() {
        use super::arp_protocol_type_label;

        // Non-IPv4 protocol identifiers (e.g. IPv6's EtherType, experimental or
        // arbitrary values) are not narrowed: the lookup returns None but the
        // raw protocol_type(u16) setter round-trips the value byte-exact.
        for unknown in [0_u16, 0x0805, 0x86dd, 0x1234, 65535] {
            assert_eq!(arp_protocol_type_label(unknown), None);

            let arp = Arp::new().protocol_type(unknown);
            assert_eq!(arp.protocol_type_value(), unknown);
            assert_eq!(arp.protocol_type_label(), None);
        }
    }

    #[test]
    fn arp_protocol_type_label_reexported_through_prelude() {
        use crate::prelude::{arp_protocol_type_label, ARP_PRO_IPV4};

        assert_eq!(arp_protocol_type_label(ARP_PRO_IPV4), Some("ipv4"));
        assert_eq!(arp_protocol_type_label(0x4242), None);
    }

    #[test]
    fn arp_raw_address_builders_fill_lengths_from_byte_count() {
        let sender_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x10, 0xaa, 0xbb];
        let sender_pa = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let target_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x20, 0xcc, 0xdd];
        let target_pa = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

        let arp = Arp::new()
            .sender_hardware(sender_hw.clone())
            .sender_protocol(sender_pa.clone())
            .target_hardware(target_hw.clone())
            .target_protocol(target_pa.clone());

        // Lengths follow the supplied byte counts.
        assert_eq!(arp.hardware_len_value(), 8);
        assert_eq!(arp.protocol_len_value(), 16);

        // Raw bytes are preserved exactly.
        assert_eq!(arp.sender_hardware_bytes_value(), sender_hw);
        assert_eq!(arp.sender_protocol_bytes_value(), sender_pa);
        assert_eq!(arp.target_hardware_bytes_value(), target_hw);
        assert_eq!(arp.target_protocol_bytes_value(), target_pa);

        // The variable-length packet compiles and round-trips byte-exact
        // through an Ethernet frame.
        let frame = Ethernet::new().src(src_mac()) / arp;
        let bytes = frame.compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &bytes).unwrap();
        let decoded_arp = decoded.layer::<Arp>().unwrap();
        assert_eq!(decoded_arp.hardware_len_value(), 8);
        assert_eq!(decoded_arp.protocol_len_value(), 16);
        assert_eq!(decoded_arp.sender_hardware_bytes_value(), sender_hw);
        assert_eq!(decoded_arp.target_protocol_bytes_value(), target_pa);
    }

    #[test]
    fn arp_raw_address_builders_honor_explicit_length_override() {
        // An explicit length set before the bytes is not overwritten, so a
        // deliberately inconsistent packet stays expressible for the later
        // compile-time validation path.
        let arp = Arp::new()
            .hardware_len(5)
            .sender_hardware(vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x11]);
        assert_eq!(arp.hardware_len_value(), 5);
        assert_eq!(
            arp.sender_hardware_bytes_value(),
            vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x11]
        );

        // An explicit length set after the bytes is likewise honored.
        let arp = Arp::new()
            .target_protocol(vec![0x0a, 0x0b, 0x0c, 0x0d])
            .protocol_len(2);
        assert_eq!(arp.protocol_len_value(), 2);
        assert_eq!(
            arp.target_protocol_bytes_value(),
            vec![0x0a, 0x0b, 0x0c, 0x0d]
        );
    }

    #[test]
    fn arp_raw_address_builders_accept_zero_length_addresses() {
        let arp = Arp::new()
            .sender_hardware(Vec::<u8>::new())
            .sender_protocol(Vec::<u8>::new())
            .target_hardware(Vec::<u8>::new())
            .target_protocol(Vec::<u8>::new());

        assert_eq!(arp.hardware_len_value(), 0);
        assert_eq!(arp.protocol_len_value(), 0);
        assert!(arp.sender_hardware_bytes_value().is_empty());

        // A zero-length ARP body is just the eight-byte fixed header and
        // round-trips through an Ethernet frame.
        let frame = Ethernet::new().src(src_mac()) / arp;
        let bytes = frame.compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &bytes).unwrap();
        let decoded_arp = decoded.layer::<Arp>().unwrap();
        assert_eq!(decoded_arp.hardware_len_value(), 0);
        assert_eq!(decoded_arp.protocol_len_value(), 0);
    }

    #[test]
    fn arp_raw_address_builder_saturates_oversized_length() {
        // A byte vector longer than a u8 length field saturates rather than
        // wrapping, so the mismatch is caught by length validation later
        // instead of silently aliasing a small length.
        let oversized = vec![0u8; 300];
        let arp = Arp::new().sender_hardware(oversized);
        assert_eq!(arp.hardware_len_value(), u8::MAX);
        assert_eq!(arp.sender_hardware_bytes_value().len(), 300);
    }

    #[test]
    fn arp_preserves_explicit_fields_through_compile_and_decode() {
        // Every fixed-header field is set explicitly to a value that disagrees
        // with the Ethernet/IPv4 defaults, including the deliberately unusual
        // hardware/protocol types and an unknown opcode. compile() fills nothing
        // it did not need to; each explicit value must reach the wire untouched.
        let sender_hw = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];
        let sender_pa = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let target_hw = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let target_pa = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

        let arp = Arp::new()
            .hardware_type(super::ARP_HRD_INFINIBAND)
            .protocol_type(0x86dd)
            .hardware_len(8)
            .protocol_len(16)
            .opcode(0x0fa0)
            .sender_hardware_bytes(sender_hw.clone())
            .sender_protocol_bytes(sender_pa.clone())
            .target_hardware_bytes(target_hw.clone())
            .target_protocol_bytes(target_pa.clone());

        // The builder records exactly what was set.
        assert_eq!(arp.hardware_type_value(), super::ARP_HRD_INFINIBAND);
        assert_eq!(arp.protocol_type_value(), 0x86dd);
        assert_eq!(arp.hardware_len_value(), 8);
        assert_eq!(arp.protocol_len_value(), 16);
        assert_eq!(arp.opcode_value(), 0x0fa0);
        assert_eq!(arp.sender_hardware_bytes_value(), sender_hw);
        assert_eq!(arp.sender_protocol_bytes_value(), sender_pa);
        assert_eq!(arp.target_hardware_bytes_value(), target_hw);
        assert_eq!(arp.target_protocol_bytes_value(), target_pa);

        // Those values survive a full Ethernet/ARP compile -> decode round trip.
        let frame = Ethernet::new().src(src_mac()) / arp;
        let bytes = frame.compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &bytes).unwrap();
        let decoded_arp = decoded.layer::<Arp>().unwrap();
        assert_eq!(decoded_arp.hardware_type_value(), super::ARP_HRD_INFINIBAND);
        assert_eq!(decoded_arp.protocol_type_value(), 0x86dd);
        assert_eq!(decoded_arp.hardware_len_value(), 8);
        assert_eq!(decoded_arp.protocol_len_value(), 16);
        assert_eq!(decoded_arp.opcode_value(), 0x0fa0);
        assert_eq!(decoded_arp.sender_hardware_bytes_value(), sender_hw);
        assert_eq!(decoded_arp.sender_protocol_bytes_value(), sender_pa);
        assert_eq!(decoded_arp.target_hardware_bytes_value(), target_hw);
        assert_eq!(decoded_arp.target_protocol_bytes_value(), target_pa);
    }

    #[test]
    fn arp_preserves_intentionally_malformed_address_bytes() {
        // A consistent but nonstandard 3-octet hardware / 1-octet protocol body:
        // the bytes are wrong for a real Ethernet/IPv4 ARP yet must compile and
        // round-trip exactly, since generated tools need malformed packets to
        // exercise a stack.
        let arp = Arp::new()
            .hardware_len(3)
            .protocol_len(1)
            .opcode(0)
            .sender_hardware_bytes(vec![0xde, 0xad, 0xbe])
            .sender_protocol_bytes(vec![0x01])
            .target_hardware_bytes(vec![0xca, 0xfe, 0x99])
            .target_protocol_bytes(vec![0x02]);

        let frame = Ethernet::new().src(src_mac()) / arp;
        let bytes = frame.compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &bytes).unwrap();
        let decoded_arp = decoded.layer::<Arp>().unwrap();

        assert_eq!(decoded_arp.hardware_len_value(), 3);
        assert_eq!(decoded_arp.protocol_len_value(), 1);
        assert_eq!(decoded_arp.opcode_value(), 0);
        assert_eq!(decoded_arp.sender_hardware_bytes_value(), vec![0xde, 0xad, 0xbe]);
        assert_eq!(decoded_arp.sender_protocol_bytes_value(), vec![0x01]);
        assert_eq!(decoded_arp.target_hardware_bytes_value(), vec![0xca, 0xfe, 0x99]);
        assert_eq!(decoded_arp.target_protocol_bytes_value(), vec![0x02]);
    }

    #[test]
    fn arp_preserves_user_values_against_later_helper_defaults() {
        // Helper defaults (set_default_if_unset / length auto-fill) must only
        // touch UNSET fields. Setting the lengths and protocol type explicitly
        // first, then calling the convenience MAC/IPv4 helpers, must leave the
        // explicit values intact even though those helpers would otherwise
        // default them to 6 / 4 / IPv4.
        let arp = Arp::new()
            .hardware_len(9)
            .protocol_len(7)
            .protocol_type(0xbeef)
            .sender_hardware_addr(MacAddr::ZERO)
            .sender_protocol_addr(Ipv4Addr::new(192, 0, 2, 10))
            .target_hardware_addr(MacAddr::BROADCAST)
            .target_protocol_addr(Ipv4Addr::new(192, 0, 2, 1));

        assert_eq!(arp.hardware_len_value(), 9);
        assert_eq!(arp.protocol_len_value(), 7);
        assert_eq!(arp.protocol_type_value(), 0xbeef);

        // The raw byte payloads the MAC/IPv4 helpers wrote are themselves never
        // rewritten by any later default.
        assert_eq!(arp.sender_hardware_bytes_value(), MacAddr::ZERO.octets().to_vec());
        assert_eq!(
            arp.target_protocol_bytes_value(),
            Ipv4Addr::new(192, 0, 2, 1).octets().to_vec()
        );
    }

    #[test]
    fn arp_override_of_helper_defaulted_lengths_and_types_is_honored() {
        // The generic address builders auto-fill lengths only as a Defaulted
        // value, so a later explicit override of the length or type wins, and
        // the raw bytes set by the builder are preserved unchanged.
        let arp = Arp::new()
            .sender_hardware(vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x10, 0xaa, 0xbb])
            .hardware_len(4)
            .protocol_type(0x86dd);

        assert_eq!(arp.hardware_len_value(), 4);
        assert_eq!(arp.protocol_type_value(), 0x86dd);
        assert_eq!(
            arp.sender_hardware_bytes_value(),
            vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x10, 0xaa, 0xbb]
        );
    }

    #[test]
    fn arp_override_of_opcode_and_types_survives_who_has_helper() {
        // Building from the who_has helper (which sets request opcode and IPv4
        // addresses) and then overriding the opcode, hardware type, and protocol
        // type must keep every override; who_has supplied no explicit override
        // for these so the later setters take effect and are not reset.
        let arp = Arp::who_has(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(192, 0, 2, 1),
            src_mac(),
        )
        .opcode(0x1234)
        .hardware_type(super::ARP_HRD_ATM)
        .protocol_type(0x0805);

        assert_eq!(arp.opcode_value(), 0x1234);
        assert_eq!(arp.hardware_type_value(), super::ARP_HRD_ATM);
        assert_eq!(arp.protocol_type_value(), 0x0805);

        // The overrides reach the wire and decode back unchanged.
        let frame = Ethernet::new().src(src_mac()) / arp;
        let bytes = frame.compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &bytes).unwrap();
        let decoded_arp = decoded.layer::<Arp>().unwrap();
        assert_eq!(decoded_arp.opcode_value(), 0x1234);
        assert_eq!(decoded_arp.hardware_type_value(), super::ARP_HRD_ATM);
        assert_eq!(decoded_arp.protocol_type_value(), 0x0805);
    }

    #[test]
    fn arp_decode_variable_hardware_length_preserves_bytes() {
        // A nonstandard 8-octet hardware address with a standard 4-octet IPv4
        // protocol address is structurally valid generic-format ARP. Decode
        // splits the four address fields by HLN/PLN and preserves the exact
        // bytes. The wider hardware address is not a MAC, so sender_mac() and
        // target_mac() report None while the raw byte accessors stay exact.
        let sender_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x10, 0xaa, 0xbb];
        let target_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x20, 0xcc, 0xdd];
        let sender_pa = vec![192, 0, 2, 10];
        let target_pa = vec![192, 0, 2, 1];

        let mut bytes = vec![
            0x00, 0x20, // HRD = 32 (InfiniBand)
            0x08, 0x00, // PRO = IPv4
            0x08, // HLN = 8
            0x04, // PLN = 4
            0x00, 0x01, // OP = request
        ];
        bytes.extend_from_slice(&sender_hw);
        bytes.extend_from_slice(&sender_pa);
        bytes.extend_from_slice(&target_hw);
        bytes.extend_from_slice(&target_pa);

        let arp = decode_arp_layer(&bytes);

        assert_eq!(arp.hardware_type_value(), super::ARP_HRD_INFINIBAND);
        assert_eq!(arp.protocol_type_value(), super::ETHERTYPE_IPV4);
        assert_eq!(arp.hardware_len_value(), 8);
        assert_eq!(arp.protocol_len_value(), 4);
        assert_eq!(arp.opcode_value(), ArpOperation::Request as u16);
        assert_eq!(arp.sender_hardware_bytes_value(), sender_hw);
        assert_eq!(arp.target_hardware_bytes_value(), target_hw);
        assert_eq!(arp.sender_protocol_bytes_value(), sender_pa);
        assert_eq!(arp.target_protocol_bytes_value(), target_pa);

        // Eight-octet hardware addresses are not MACs.
        assert_eq!(arp.sender_mac(), None);
        assert_eq!(arp.target_mac(), None);
        // The protocol is IPv4 with a four-octet address, so the IPv4 typed
        // accessors still resolve.
        assert_eq!(arp.sender_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(arp.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));

        // The decoded packet re-compiles to the exact input bytes.
        let frame = Ethernet::new().src(src_mac()) / arp;
        let recompiled = Packet::decode_from_link(LinkType::Ethernet, frame.compile().unwrap().as_bytes())
            .unwrap();
        assert_eq!(
            recompiled.layer::<Arp>().unwrap().sender_hardware_bytes_value(),
            sender_hw
        );
    }

    #[test]
    fn arp_decode_variable_protocol_length_preserves_bytes() {
        // A standard 6-octet MAC with a nonstandard 16-octet protocol address
        // (e.g. an IPv6-sized payload) under an unknown protocol type. Decode
        // splits by HLN/PLN and preserves exact bytes; the wide protocol field
        // is not IPv4 so sender_ipv4()/target_ipv4() report None.
        let sender_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x10];
        let target_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x20];
        let sender_pa = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let target_pa = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

        let mut bytes = vec![
            0x00, 0x01, // HRD = Ethernet
            0x86, 0xdd, // PRO = IPv6 EtherType (not IPv4)
            0x06, // HLN = 6
            0x10, // PLN = 16
            0x00, 0x02, // OP = reply
        ];
        bytes.extend_from_slice(&sender_hw);
        bytes.extend_from_slice(&sender_pa);
        bytes.extend_from_slice(&target_hw);
        bytes.extend_from_slice(&target_pa);

        let arp = decode_arp_layer(&bytes);

        assert_eq!(arp.hardware_len_value(), 6);
        assert_eq!(arp.protocol_len_value(), 16);
        assert_eq!(arp.protocol_type_value(), 0x86dd);
        assert_eq!(arp.sender_protocol_bytes_value(), sender_pa);
        assert_eq!(arp.target_protocol_bytes_value(), target_pa);

        // Six-octet hardware addresses are valid MACs.
        assert_eq!(arp.sender_mac().map(|m| m.octets().to_vec()), Some(sender_hw));
        assert_eq!(arp.target_mac().map(|m| m.octets().to_vec()), Some(target_hw));
        // The protocol type is not IPv4 (and the address is 16 octets), so the
        // typed IPv4 accessors decline.
        assert_eq!(arp.sender_ipv4(), None);
        assert_eq!(arp.target_ipv4(), None);
    }

    #[test]
    fn arp_decode_unknown_type_combination_preserves_fields() {
        // A fully nonstandard packet: unknown hardware type, unknown protocol
        // type, unknown operation, and matching nonstandard address lengths.
        // Decode must accept it structurally, preserve every field and address
        // byte, and decline both typed accessor families.
        let sender_hw = vec![0xde, 0xad, 0xbe];
        let target_hw = vec![0xca, 0xfe, 0x99];
        let sender_pa = vec![0x11, 0x22];
        let target_pa = vec![0x33, 0x44];

        let mut bytes = vec![
            0xab, 0xcd, // HRD = 0xabcd (unknown)
            0x12, 0x34, // PRO = 0x1234 (unknown)
            0x03, // HLN = 3
            0x02, // PLN = 2
            0x04, 0x00, // OP = 1024 (unknown numeric)
        ];
        bytes.extend_from_slice(&sender_hw);
        bytes.extend_from_slice(&sender_pa);
        bytes.extend_from_slice(&target_hw);
        bytes.extend_from_slice(&target_pa);

        let arp = decode_arp_layer(&bytes);

        assert_eq!(arp.hardware_type_value(), 0xabcd);
        assert_eq!(arp.protocol_type_value(), 0x1234);
        assert_eq!(arp.hardware_len_value(), 3);
        assert_eq!(arp.protocol_len_value(), 2);
        assert_eq!(arp.opcode_value(), 1024);
        assert_eq!(arp.sender_hardware_bytes_value(), sender_hw);
        assert_eq!(arp.target_hardware_bytes_value(), target_hw);
        assert_eq!(arp.sender_protocol_bytes_value(), sender_pa);
        assert_eq!(arp.target_protocol_bytes_value(), target_pa);

        // Neither typed accessor family matches a 3-octet hardware address or a
        // non-IPv4 2-octet protocol address.
        assert_eq!(arp.sender_mac(), None);
        assert_eq!(arp.target_mac(), None);
        assert_eq!(arp.sender_ipv4(), None);
        assert_eq!(arp.target_ipv4(), None);
        // The unknown operation has no named label.
        assert_eq!(ArpOperation::from_opcode(1024), None);
    }

    #[test]
    fn arp_decode_zero_length_addresses_does_not_overflow() {
        // Zero-length hardware and protocol fields are valid generic-format ARP
        // and decode to the bare eight-byte fixed header. The address-split
        // arithmetic must not over-read or panic on empty fields.
        let bytes = vec![
            0x00, 0x01, // HRD
            0x08, 0x00, // PRO
            0x00, // HLN = 0
            0x00, // PLN = 0
            0x00, 0x01, // OP
        ];

        let arp = decode_arp_layer(&bytes);

        assert_eq!(arp.hardware_len_value(), 0);
        assert_eq!(arp.protocol_len_value(), 0);
        assert!(arp.sender_hardware_bytes_value().is_empty());
        assert!(arp.sender_protocol_bytes_value().is_empty());
        assert!(arp.target_hardware_bytes_value().is_empty());
        assert!(arp.target_protocol_bytes_value().is_empty());
        // Empty hardware/protocol fields are neither a MAC nor an IPv4 address.
        assert_eq!(arp.sender_mac(), None);
        assert_eq!(arp.sender_ipv4(), None);
    }

    #[test]
    fn arp_decode_truncated_header_returns_structured_error() {
        // A buffer shorter than the eight-byte fixed header fails with a
        // structured BufferTooShort naming the failing context and the
        // required/available byte counts, never a panic.
        let bytes = [0x00, 0x01, 0x08, 0x00, 0x06]; // 5 bytes, header needs 8
        let err = Packet::decode_from_link(LinkType::Ethernet, arp_frame(&bytes)).unwrap_err();
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "arp header");
                assert_eq!(required, 8);
                assert_eq!(available, 5);
            }
            other => panic!("expected a structured truncation error, got {other:?}"),
        }
    }

    #[test]
    fn arp_decode_truncated_address_fields_returns_structured_error() {
        // A complete fixed header declaring 6/4 address lengths but with the
        // address bytes truncated fails with a BufferTooShort naming the
        // address context and the required vs. available lengths.
        let bytes = vec![
            0x00, 0x01, // HRD
            0x08, 0x00, // PRO
            0x06, // HLN = 6
            0x04, // PLN = 4
            0x00, 0x01, // OP
            0xaa, 0xbb, 0xcc, // only 3 of the 20 declared address bytes
        ];
        let err = Packet::decode_from_link(LinkType::Ethernet, arp_frame(&bytes)).unwrap_err();
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "arp addresses");
                // Fixed header (8) + 6*2 + 4*2 = 28 required; 11 available.
                assert_eq!(required, 28);
                assert_eq!(available, 11);
            }
            other => panic!("expected a structured truncation error, got {other:?}"),
        }
    }

    #[test]
    fn arp_variable_lengths_decode_round_trips_byte_exact() {
        // An end-to-end variable-length round trip: build a nonstandard
        // 8-octet-hardware / 16-octet-protocol ARP through the raw byte
        // builders, compile inside an Ethernet frame, decode, and confirm every
        // field and byte survives the split-by-length decode path unchanged.
        let sender_hw = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];
        let sender_pa = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let target_hw = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let target_pa = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

        let arp = Arp::new()
            .hardware_type(super::ARP_HRD_INFINIBAND)
            .protocol_type(0x86dd)
            .opcode(0x0fa0)
            .sender_hardware(sender_hw.clone())
            .sender_protocol(sender_pa.clone())
            .target_hardware(target_hw.clone())
            .target_protocol(target_pa.clone());

        let frame = Ethernet::new().src(src_mac()) / arp;
        let bytes = frame.compile().unwrap().as_bytes().to_vec();
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &bytes).unwrap();
        let decoded_arp = decoded.layer::<Arp>().unwrap();

        assert_eq!(decoded_arp.hardware_type_value(), super::ARP_HRD_INFINIBAND);
        assert_eq!(decoded_arp.protocol_type_value(), 0x86dd);
        assert_eq!(decoded_arp.hardware_len_value(), 8);
        assert_eq!(decoded_arp.protocol_len_value(), 16);
        assert_eq!(decoded_arp.opcode_value(), 0x0fa0);
        assert_eq!(decoded_arp.sender_hardware_bytes_value(), sender_hw);
        assert_eq!(decoded_arp.sender_protocol_bytes_value(), sender_pa);
        assert_eq!(decoded_arp.target_hardware_bytes_value(), target_hw);
        assert_eq!(decoded_arp.target_protocol_bytes_value(), target_pa);

        // Nonstandard widths decline the typed accessors.
        assert_eq!(decoded_arp.sender_mac(), None);
        assert_eq!(decoded_arp.target_mac(), None);
        assert_eq!(decoded_arp.sender_ipv4(), None);
        assert_eq!(decoded_arp.target_ipv4(), None);

        // The full frame re-compiles to the identical bytes.
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_slice());
    }

    #[test]
    fn arp_variable_zero_protocol_length_with_ipv4_type_returns_none() {
        // sender_ipv4()/target_ipv4() must key off BOTH the protocol type and a
        // four-octet length. An IPv4 protocol type with a zero-length address
        // is not a valid IPv4 address, so the typed accessor declines even
        // though the protocol type matches.
        let bytes = vec![
            0x00, 0x01, // HRD = Ethernet
            0x08, 0x00, // PRO = IPv4
            0x06, // HLN = 6
            0x00, // PLN = 0
            0x00, 0x01, // OP
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x10, // sender hardware (6 octets)
            // sender protocol: 0 octets
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x20, // target hardware (6 octets)
            // target protocol: 0 octets
        ];

        let arp = decode_arp_layer(&bytes);

        assert_eq!(arp.protocol_type_value(), super::ETHERTYPE_IPV4);
        assert_eq!(arp.protocol_len_value(), 0);
        // MACs still resolve, but the IPv4 accessors decline on a zero-length
        // protocol address.
        assert!(arp.sender_mac().is_some());
        assert_eq!(arp.sender_ipv4(), None);
        assert_eq!(arp.target_ipv4(), None);
    }

    /// Decode a bare ARP body inside an Ethernet frame and return the `Arp`
    /// layer, panicking on any decode error. Centralizes the variable-length
    /// decode assertions so each test reads as data plus expectations.
    fn decode_arp_layer(body: &[u8]) -> Arp {
        let frame = arp_frame(body);
        let decoded = Packet::decode_from_link(LinkType::Ethernet, &frame)
            .expect("structurally valid ARP body must decode");
        decoded
            .layer::<Arp>()
            .expect("decoded packet must carry an Arp layer")
            .clone()
    }

    /// Wrap an ARP body in a minimal Ethernet header (broadcast dst, the test
    /// source MAC, EtherType 0x0806) so it decodes through the link root.
    fn arp_frame(body: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + body.len());
        frame.extend_from_slice(&MacAddr::BROADCAST.octets());
        frame.extend_from_slice(&src_mac().octets());
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        frame.extend_from_slice(body);
        frame
    }
}

#[cfg(test)]
mod link_layers {
    use super::{Arp, Ethernet, LinuxSll, NullByteOrder, NullLoopback, Vlan, ETHERTYPE_IPV4};
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
}
