use core::any::Any;
use core::net::Ipv4Addr;
use core::ops::Div;
use core::str::FromStr;

use crate::error::Result;
use crate::field::Field;
use crate::mac::MacAddr;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

use super::super::{address_summary_mac, hex_bytes, mac_from_bytes, value_or_copy};
use super::address::{
    address_summary_ipv4, ipv4_from_bytes, parse_ipv4, saturating_len_u8, validate_len,
    value_or_vec,
};
use super::constants::{ARP_FIXED_HEADER_LEN, ARP_HRD_ETHERNET, ARP_PRO_IPV4};
use super::labels::{
    arp_hardware_type_label, arp_protocol_type_label, hardware_type_inspection,
    operation_inspection, operation_summary, protocol_type_inspection,
};
use super::operation::ArpOperation;

/// Address Resolution Protocol packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arp {
    pub(super) hardware_type: Field<u16>,
    pub(super) protocol_type: Field<u16>,
    pub(super) hardware_len: Field<u8>,
    pub(super) protocol_len: Field<u8>,
    pub(super) operation: Field<u16>,
    pub(super) sender_hardware_addr: Field<Vec<u8>>,
    pub(super) sender_protocol_addr: Field<Vec<u8>>,
    pub(super) target_hardware_addr: Field<Vec<u8>>,
    pub(super) target_protocol_addr: Field<Vec<u8>>,
}

impl Arp {
    /// Create an Ethernet/IPv4 ARP request with libcrafter-style defaults.
    pub fn new() -> Self {
        Self {
            hardware_type: Field::defaulted(ARP_HRD_ETHERNET),
            protocol_type: Field::defaulted(ARP_PRO_IPV4),
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
        self.protocol_type.set_default_if_unset(ARP_PRO_IPV4);
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
        self.protocol_type.set_default_if_unset(ARP_PRO_IPV4);
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
        value_or_copy(&self.hardware_type, ARP_HRD_ETHERNET)
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
        value_or_copy(&self.protocol_type, ARP_PRO_IPV4)
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
        let protocol_type = self.protocol_type_value();
        let sender_hardware = self.sender_hardware_bytes_value();
        let sender_protocol = self.sender_protocol_bytes_value();
        let target_hardware = self.target_hardware_bytes_value();
        let target_protocol = self.target_protocol_bytes_value();

        vec![
            (
                "hardware_type",
                hardware_type_inspection(self.hardware_type_value()),
            ),
            ("protocol_type", protocol_type_inspection(protocol_type)),
            ("hardware_len", self.hardware_len_value().to_string()),
            ("protocol_len", self.protocol_len_value().to_string()),
            ("operation", operation_inspection(self.opcode_value())),
            (
                "sender_hardware_addr",
                address_summary_mac(&sender_hardware),
            ),
            ("sender_hardware_bytes", hex_bytes(&sender_hardware)),
            (
                "sender_protocol_addr",
                address_summary_ipv4(protocol_type, &sender_protocol),
            ),
            ("sender_protocol_bytes", hex_bytes(&sender_protocol)),
            (
                "target_hardware_addr",
                address_summary_mac(&target_hardware),
            ),
            ("target_hardware_bytes", hex_bytes(&target_hardware)),
            (
                "target_protocol_addr",
                address_summary_ipv4(protocol_type, &target_protocol),
            ),
            ("target_protocol_bytes", hex_bytes(&target_protocol)),
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

impl<R> Div<R> for Arp
where
    R: IntoPacket,
{
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        Packet::from_layer(self).concat(rhs)
    }
}
