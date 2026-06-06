use core::net::Ipv6Addr;

use crate::endian::read_u32_be;
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Layer, LayerContext};

use super::super::constants::{
    IPV6_EXTENSION_MIN_LEN, IPV6_MOBILE_ROUTING_HEADER_EXT_LEN, IPV6_MOBILE_ROUTING_LEN,
    IPV6_MOBILE_ROUTING_RESERVED, IPV6_MOBILE_ROUTING_SEGMENTS_LEFT, IPV6_ROUTING_TYPE_MOBILE,
};
use super::super::display::{
    ipv6_routing_type_label, ipv6_routing_type_status, next_header_summary, routing_type_summary,
};
use super::super::{copy_array_16, layer_ipv6_next_header, parse_ipv6, value_or_copy};
use super::{header_ext_len_from_total, validate_extension_total_len};

use super::routing::Ipv6RoutingTypeStatus;

/// RFC 6275 packet-field status for a Mobile IPv6 Type 2 Routing Header.
///
/// This status checks only source-backed wire fields visible in the packet.
/// Whether the Home Address is one of the receiving node's home addresses, and
/// whether it is routable in the current network, require node and routing
/// context outside `crafter`'s packet-layer scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6MobileRoutingHeaderStatus {
    /// The fixed Type 2 Routing Header fields match RFC 6275.
    Valid,
    /// Routing Type is not 2.
    InvalidRoutingType,
    /// Header extension length is not 2.
    InvalidHeaderExtLen,
    /// Segments Left is not 1.
    InvalidSegmentsLeft,
    /// Reserved field is nonzero.
    NonzeroReserved,
}

impl Ipv6MobileRoutingHeaderStatus {
    /// Whether this status represents an RFC 6275-shaped Type 2 Routing Header.
    pub const fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// IPv6 Mobile Routing Header (Routing Header type 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6MobileRoutingHeader {
    next_header: Field<u8>,
    header_ext_len: Field<u8>,
    routing_type: Field<u8>,
    segments_left: Field<u8>,
    reserved: Field<u32>,
    home_address: Field<Ipv6Addr>,
}

impl Ipv6MobileRoutingHeader {
    /// Create a mobile routing header.
    pub fn new() -> Self {
        Self {
            next_header: Field::defaulted(0),
            header_ext_len: Field::unset(),
            routing_type: Field::defaulted(IPV6_ROUTING_TYPE_MOBILE),
            segments_left: Field::defaulted(IPV6_MOBILE_ROUTING_SEGMENTS_LEFT),
            reserved: Field::defaulted(IPV6_MOBILE_ROUTING_RESERVED),
            home_address: Field::defaulted(Ipv6Addr::LOCALHOST),
        }
    }

    /// Set the next header after this routing header.
    pub fn next_header(mut self, next_header: u8) -> Self {
        self.next_header.set_user(next_header);
        self
    }

    /// Compatibility alias for next header.
    pub fn nh(self, next_header: u8) -> Self {
        self.next_header(next_header)
    }

    /// Set the encoded header extension length.
    pub fn header_ext_len(mut self, header_ext_len: u8) -> Self {
        self.header_ext_len.set_user(header_ext_len);
        self
    }

    /// Set the routing type field.
    pub fn routing_type(mut self, routing_type: u8) -> Self {
        self.routing_type.set_user(routing_type);
        self
    }

    /// Set the segments-left field.
    pub fn segments_left(mut self, segments_left: u8) -> Self {
        self.segments_left.set_user(segments_left);
        self
    }

    /// libcrafter-style alias for segments left.
    pub fn segleft(self, segments_left: u8) -> Self {
        self.segments_left(segments_left)
    }

    /// Set the reserved field.
    pub fn reserved(mut self, reserved: u32) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Set the home address.
    pub fn home_address(mut self, home_address: Ipv6Addr) -> Self {
        self.home_address.set_user(home_address);
        self
    }

    /// libcrafter-style alias for home address.
    pub fn home(self, home_address: Ipv6Addr) -> Self {
        self.home_address(home_address)
    }

    /// Set the home address from text.
    pub fn home_address_str(self, home_address: &str) -> Result<Self> {
        Ok(self.home_address(parse_ipv6(home_address)?))
    }

    /// libcrafter-style alias for textual home address.
    pub fn home_str(self, home_address: &str) -> Result<Self> {
        self.home_address_str(home_address)
    }

    /// Next-header value.
    pub fn next_header_value(&self) -> u8 {
        value_or_copy(&self.next_header, 0)
    }

    /// Header extension length when explicit or decoded.
    pub fn header_ext_len_value(&self) -> Option<u8> {
        self.header_ext_len.value().copied()
    }

    /// Header extension length that will be emitted if the header compiles.
    pub fn effective_header_ext_len_value(&self) -> u8 {
        self.header_ext_len
            .value()
            .copied()
            .unwrap_or(IPV6_MOBILE_ROUTING_HEADER_EXT_LEN)
    }

    /// RFC 6275 status of the header extension length field.
    pub fn header_ext_len_status(&self) -> Ipv6MobileRoutingHeaderStatus {
        if self.effective_header_ext_len_value() == IPV6_MOBILE_ROUTING_HEADER_EXT_LEN {
            Ipv6MobileRoutingHeaderStatus::Valid
        } else {
            Ipv6MobileRoutingHeaderStatus::InvalidHeaderExtLen
        }
    }

    /// Routing type.
    pub fn routing_type_value(&self) -> u8 {
        value_or_copy(&self.routing_type, IPV6_ROUTING_TYPE_MOBILE)
    }

    /// Routing type label from the IANA IPv6 Routing Types registry.
    pub fn routing_type_label(&self) -> &'static str {
        ipv6_routing_type_label(self.routing_type_value())
    }

    /// Routing type status from the IANA IPv6 Routing Types registry.
    pub fn routing_type_status(&self) -> Ipv6RoutingTypeStatus {
        ipv6_routing_type_status(self.routing_type_value())
    }

    /// Segments-left value.
    pub fn segments_left_value(&self) -> u8 {
        value_or_copy(&self.segments_left, IPV6_MOBILE_ROUTING_SEGMENTS_LEFT)
    }

    /// Whether Segments Left is still using the RFC 6275 builder default.
    pub fn segments_left_is_defaulted(&self) -> bool {
        !self.segments_left.is_user_set()
            && self.segments_left_value() == IPV6_MOBILE_ROUTING_SEGMENTS_LEFT
    }

    /// RFC 6275 status of the Segments Left field.
    pub fn segments_left_status(&self) -> Ipv6MobileRoutingHeaderStatus {
        if self.segments_left_value() == IPV6_MOBILE_ROUTING_SEGMENTS_LEFT {
            Ipv6MobileRoutingHeaderStatus::Valid
        } else {
            Ipv6MobileRoutingHeaderStatus::InvalidSegmentsLeft
        }
    }

    /// Reserved field.
    pub fn reserved_value(&self) -> u32 {
        value_or_copy(&self.reserved, IPV6_MOBILE_ROUTING_RESERVED)
    }

    /// Whether the reserved field is zero as initialized by RFC 6275 senders.
    pub fn reserved_is_zero(&self) -> bool {
        self.reserved_value() == IPV6_MOBILE_ROUTING_RESERVED
    }

    /// RFC 6275 status of the reserved field.
    pub fn reserved_status(&self) -> Ipv6MobileRoutingHeaderStatus {
        if self.reserved_is_zero() {
            Ipv6MobileRoutingHeaderStatus::Valid
        } else {
            Ipv6MobileRoutingHeaderStatus::NonzeroReserved
        }
    }

    /// Home address value.
    pub fn home_address_value(&self) -> Ipv6Addr {
        value_or_copy(&self.home_address, Ipv6Addr::LOCALHOST)
    }

    /// Home address field bytes in network order.
    pub fn home_address_bytes(&self) -> [u8; 16] {
        self.home_address_value().octets()
    }

    /// RFC 6275 packet-field status for this Type 2 Routing Header.
    pub fn validity_status(&self) -> Ipv6MobileRoutingHeaderStatus {
        if self.routing_type_value() != IPV6_ROUTING_TYPE_MOBILE {
            return Ipv6MobileRoutingHeaderStatus::InvalidRoutingType;
        }
        if self.effective_header_ext_len_value() != IPV6_MOBILE_ROUTING_HEADER_EXT_LEN {
            return Ipv6MobileRoutingHeaderStatus::InvalidHeaderExtLen;
        }
        if self.segments_left_value() != IPV6_MOBILE_ROUTING_SEGMENTS_LEFT {
            return Ipv6MobileRoutingHeaderStatus::InvalidSegmentsLeft;
        }
        if self.reserved_value() != IPV6_MOBILE_ROUTING_RESERVED {
            return Ipv6MobileRoutingHeaderStatus::NonzeroReserved;
        }
        Ipv6MobileRoutingHeaderStatus::Valid
    }

    fn effective_total_len(&self) -> usize {
        self.header_ext_len
            .value()
            .map(|value| IPV6_EXTENSION_MIN_LEN + *value as usize * 8)
            .unwrap_or(IPV6_MOBILE_ROUTING_LEN)
    }

    fn effective_header_ext_len(&self) -> Result<u8> {
        header_ext_len_from_total("ipv6.mobile.header_ext_len", self.effective_total_len())
    }

    fn effective_next_header(&self, next: Option<&dyn Layer>) -> u8 {
        if self.next_header.is_user_set() {
            return self.next_header_value();
        }

        next.and_then(layer_ipv6_next_header)
            .or_else(|| self.next_header.value().copied())
            .unwrap_or(0)
    }

    fn validate(&self) -> Result<()> {
        validate_extension_total_len("ipv6.mobile.header_ext_len", self.effective_total_len())?;
        if self.effective_total_len() < IPV6_MOBILE_ROUTING_LEN {
            return Err(CrafterError::invalid_field_value(
                "ipv6.mobile.header_ext_len",
                "mobile routing header must be at least 24 bytes",
            ));
        }
        Ok(())
    }
}

impl Default for Ipv6MobileRoutingHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ipv6MobileRoutingHeader {
    fn name(&self) -> &'static str {
        "Ipv6MobileRoutingHeader"
    }

    fn summary(&self) -> String {
        format!(
            "Ipv6MobileRoutingHeader(type={}, home={}, next={})",
            routing_type_summary(self.routing_type_value()),
            self.home_address_value(),
            next_header_summary(self.next_header_value())
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("next_header", next_header_summary(self.next_header_value())),
            (
                "header_ext_len",
                self.header_ext_len_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            (
                "routing_type",
                routing_type_summary(self.routing_type_value()),
            ),
            (
                "routing_type_status",
                format!("{:?}", self.routing_type_status()),
            ),
            ("validity_status", format!("{:?}", self.validity_status())),
            ("segments_left", self.segments_left_value().to_string()),
            (
                "segments_left_status",
                format!("{:?}", self.segments_left_status()),
            ),
            ("reserved", format!("0x{:08x}", self.reserved_value())),
            ("reserved_status", format!("{:?}", self.reserved_status())),
            ("home_address", self.home_address_value().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.effective_total_len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;
        let start = out.len();
        let total_len = self.effective_total_len();

        out.push(self.effective_next_header(ctx.next()));
        out.push(self.effective_header_ext_len()?);
        out.push(self.routing_type_value());
        out.push(self.segments_left_value());
        out.extend_from_slice(&self.reserved_value().to_be_bytes());
        out.extend_from_slice(&self.home_address_value().octets());
        out.resize(start + total_len, 0);
        Ok(())
    }

    impl_ipv6_extension_layer_object!(Ipv6MobileRoutingHeader);
}

impl_ipv6_extension_layer_div!(Ipv6MobileRoutingHeader);

pub(in crate::protocols::ip::v6::extension) fn decode_mobile_routing_header(
    bytes: &[u8],
    total_len: usize,
) -> Result<Ipv6MobileRoutingHeader> {
    if total_len < IPV6_MOBILE_ROUTING_LEN {
        return Err(CrafterError::invalid_field_value(
            "ipv6.mobile.header_ext_len",
            "mobile routing header must be at least 24 bytes",
        ));
    }

    Ok(Ipv6MobileRoutingHeader {
        next_header: Field::user(bytes[0]),
        header_ext_len: Field::user(bytes[1]),
        routing_type: Field::user(bytes[2]),
        segments_left: Field::user(bytes[3]),
        reserved: Field::user(read_u32_be(&bytes[4..8])?),
        home_address: Field::user(Ipv6Addr::from(copy_array_16(&bytes[8..24]))),
    })
}
