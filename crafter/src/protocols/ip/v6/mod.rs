//! IPv6 base header and IPv6 extension header implementations.

mod constants;
mod display;
mod header;
mod options;

use core::any::Any;
use core::net::Ipv6Addr;
use core::ops::Div;
use core::str::FromStr;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet, Raw};
use crate::protocols::icmp::Icmpv6;
use crate::protocols::ip::shared::{IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};
use crate::protocols::transport::{Tcp, Udp};
use crate::registry::ProtocolRegistry;

pub use constants::{
    IPPROTO_IPV6_AH, IPPROTO_IPV6_DSTOPTS, IPPROTO_IPV6_ESP, IPPROTO_IPV6_EXPERIMENTAL_1,
    IPPROTO_IPV6_EXPERIMENTAL_2, IPPROTO_IPV6_FRAGMENT, IPPROTO_IPV6_HIP, IPPROTO_IPV6_HOPOPTS,
    IPPROTO_IPV6_MOBILITY, IPPROTO_IPV6_NO_NEXT, IPPROTO_IPV6_ROUTE, IPPROTO_IPV6_SHIM6,
    IPV6_MOBILE_ROUTING_HEADER_EXT_LEN, IPV6_MOBILE_ROUTING_RESERVED,
    IPV6_MOBILE_ROUTING_SEGMENTS_LEFT, IPV6_OPTION_HOME_ADDRESS, IPV6_OPTION_JUMBO_PAYLOAD,
    IPV6_OPTION_PAD1, IPV6_OPTION_PADN, IPV6_OPTION_ROUTER_ALERT,
    IPV6_ROUTER_ALERT_ACTIVE_NETWORKS, IPV6_ROUTER_ALERT_MLD, IPV6_ROUTER_ALERT_MPLS_OAM,
    IPV6_ROUTER_ALERT_RESERVED, IPV6_ROUTER_ALERT_RSVP, IPV6_ROUTING_TYPE_CRH16,
    IPV6_ROUTING_TYPE_CRH32, IPV6_ROUTING_TYPE_EXPERIMENTAL_1, IPV6_ROUTING_TYPE_EXPERIMENTAL_2,
    IPV6_ROUTING_TYPE_MOBILE, IPV6_ROUTING_TYPE_NIMROD, IPV6_ROUTING_TYPE_RESERVED,
    IPV6_ROUTING_TYPE_RH0, IPV6_ROUTING_TYPE_RPL, IPV6_ROUTING_TYPE_SEGMENT,
    IPV6_ROUTING_TYPE_SOURCE_ROUTE, IPV6_SEGMENT_POLICY_EGRESS, IPV6_SEGMENT_POLICY_INGRESS,
    IPV6_SEGMENT_POLICY_SOURCE_ADDRESS, IPV6_SEGMENT_POLICY_UNSET,
};
use constants::{
    IPV6_EXTENSION_MIN_LEN, IPV6_FRAGMENT_HEADER_LEN, IPV6_HEADER_LEN, IPV6_MAX_FLOW_LABEL,
    IPV6_MAX_FRAGMENT_OFFSET, IPV6_MAX_HEADER_EXT_LEN, IPV6_MOBILE_ROUTING_LEN,
    IPV6_SEGMENT_BASE_LEN, IPV6_SEGMENT_HMAC_LEN,
};
use display::{
    hex_bytes, ipv6_list_summary, ipv6_options_summary, next_header_summary, routing_type_summary,
};
pub use display::{
    ipv6_fragment_header_status_label, ipv6_routing_type_label, ipv6_routing_type_status,
};
pub use header::Ipv6;
pub use options::{ipv6_router_alert_value_label, Ipv6Option, Ipv6OptionAction, Ipv6OptionIter};

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

/// Source-backed status for an IPv6 Routing Header type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6RoutingTypeStatus {
    /// Assigned routing type that is not marked deprecated or reserved here.
    Assigned,
    /// Assigned routing type marked deprecated by IANA or RFC guidance.
    Deprecated,
    /// RFC3692-style experiment/testing value.
    Experimental,
    /// IANA-reserved value.
    Reserved,
    /// Value not assigned in the current IANA Routing Types registry.
    Unknown,
}

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

/// Source-backed classification for an IPv6 Fragment Header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6FragmentHeaderStatus {
    /// Fragment Offset is zero and the M flag is clear.
    Atomic,
    /// Fragment Offset is zero and the M flag is set.
    Initial,
    /// Fragment Offset is nonzero.
    NonInitial,
}

impl Ipv6FragmentHeaderStatus {
    /// Whether this status is an RFC 6946 atomic fragment.
    pub const fn is_atomic(self) -> bool {
        matches!(self, Self::Atomic)
    }

    /// Whether this status carries the first bytes of the fragmentable part.
    pub const fn is_initial(self) -> bool {
        matches!(self, Self::Atomic | Self::Initial)
    }

    /// Whether this status is a non-initial fragment.
    pub const fn is_non_initial(self) -> bool {
        matches!(self, Self::NonInitial)
    }

    /// Human-readable status label.
    pub const fn label(self) -> &'static str {
        ipv6_fragment_header_status_label(self)
    }
}

/// IPv6 Hop-by-Hop Options Header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6HopByHopOptionsHeader {
    next_header: Field<u8>,
    header_ext_len: Field<u8>,
    options: Vec<Ipv6Option>,
}

impl Ipv6HopByHopOptionsHeader {
    /// Create an empty Hop-by-Hop Options header.
    pub fn new() -> Self {
        Self {
            next_header: Field::defaulted(0),
            header_ext_len: Field::unset(),
            options: Vec::new(),
        }
    }

    /// Set the next header after this Hop-by-Hop Options header.
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

    /// Replace the Hop-by-Hop options.
    pub fn options(mut self, options: impl Into<Vec<Ipv6Option>>) -> Self {
        self.options = options.into();
        self
    }

    /// Append one Hop-by-Hop option.
    pub fn option(mut self, option: Ipv6Option) -> Self {
        self.options.push(option);
        self
    }

    /// Compatibility alias for appending one Hop-by-Hop option.
    pub fn push_option(self, option: Ipv6Option) -> Self {
        self.option(option)
    }

    /// Next-header value.
    pub fn next_header_value(&self) -> u8 {
        value_or_copy(&self.next_header, 0)
    }

    /// Header extension length when explicit or decoded.
    pub fn header_ext_len_value(&self) -> Option<u8> {
        self.header_ext_len.value().copied()
    }

    /// Hop-by-Hop options in caller order.
    pub fn options_value(&self) -> &[Ipv6Option] {
        &self.options
    }

    /// Compatibility alias for Hop-by-Hop options.
    pub fn options_list(&self) -> &[Ipv6Option] {
        self.options_value()
    }

    fn options_len(&self) -> usize {
        self.options.iter().map(Ipv6Option::encoded_len).sum()
    }

    fn minimum_total_len(&self) -> usize {
        round_up_to_8(2 + self.options_len())
    }

    fn effective_total_len(&self) -> usize {
        self.header_ext_len
            .value()
            .map(|value| IPV6_EXTENSION_MIN_LEN + *value as usize * 8)
            .unwrap_or_else(|| self.minimum_total_len())
    }

    fn effective_header_ext_len(&self) -> Result<u8> {
        header_ext_len_from_total("ipv6.hop_by_hop.header_ext_len", self.effective_total_len())
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
        validate_extension_total_len("ipv6.hop_by_hop.header_ext_len", self.effective_total_len())?;
        if self.effective_total_len() < 2 + self.options_len() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.hop_by_hop.options",
                "Hop-by-Hop options do not fit in the header extension length",
            ));
        }
        for option in &self.options {
            option.encode()?;
        }
        Ok(())
    }
}

impl Default for Ipv6HopByHopOptionsHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ipv6HopByHopOptionsHeader {
    fn name(&self) -> &'static str {
        "Ipv6HopByHopOptionsHeader"
    }

    fn summary(&self) -> String {
        format!(
            "Ipv6HopByHopOptionsHeader(options={}, next={})",
            ipv6_options_summary(&self.options),
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
            ("options", ipv6_options_summary(&self.options)),
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
        for option in &self.options {
            out.extend_from_slice(&option.encode()?);
        }
        out.resize(start + total_len, 0);
        Ok(())
    }

    impl_layer_object!(Ipv6HopByHopOptionsHeader);
}

impl_layer_div!(Ipv6HopByHopOptionsHeader);

/// IPv6 Destination Options Header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6DestinationOptionsHeader {
    next_header: Field<u8>,
    header_ext_len: Field<u8>,
    options: Vec<Ipv6Option>,
}

impl Ipv6DestinationOptionsHeader {
    /// Create an empty Destination Options header.
    pub fn new() -> Self {
        Self {
            next_header: Field::defaulted(0),
            header_ext_len: Field::unset(),
            options: Vec::new(),
        }
    }

    /// Set the next header after this Destination Options header.
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

    /// Replace the Destination options.
    pub fn options(mut self, options: impl Into<Vec<Ipv6Option>>) -> Self {
        self.options = options.into();
        self
    }

    /// Append one Destination option.
    pub fn option(mut self, option: Ipv6Option) -> Self {
        self.options.push(option);
        self
    }

    /// Compatibility alias for appending one Destination option.
    pub fn push_option(self, option: Ipv6Option) -> Self {
        self.option(option)
    }

    /// Next-header value.
    pub fn next_header_value(&self) -> u8 {
        value_or_copy(&self.next_header, 0)
    }

    /// Header extension length when explicit or decoded.
    pub fn header_ext_len_value(&self) -> Option<u8> {
        self.header_ext_len.value().copied()
    }

    /// Destination options in caller order.
    pub fn options_value(&self) -> &[Ipv6Option] {
        &self.options
    }

    /// Compatibility alias for Destination options.
    pub fn options_list(&self) -> &[Ipv6Option] {
        self.options_value()
    }

    fn options_len(&self) -> usize {
        self.options.iter().map(Ipv6Option::encoded_len).sum()
    }

    fn minimum_total_len(&self) -> usize {
        round_up_to_8(2 + self.options_len())
    }

    fn effective_total_len(&self) -> usize {
        self.header_ext_len
            .value()
            .map(|value| IPV6_EXTENSION_MIN_LEN + *value as usize * 8)
            .unwrap_or_else(|| self.minimum_total_len())
    }

    fn effective_header_ext_len(&self) -> Result<u8> {
        header_ext_len_from_total(
            "ipv6.destination_options.header_ext_len",
            self.effective_total_len(),
        )
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
        validate_extension_total_len(
            "ipv6.destination_options.header_ext_len",
            self.effective_total_len(),
        )?;
        if self.effective_total_len() < 2 + self.options_len() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.destination_options.options",
                "Destination options do not fit in the header extension length",
            ));
        }
        for option in &self.options {
            option.encode()?;
        }
        Ok(())
    }
}

impl Default for Ipv6DestinationOptionsHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ipv6DestinationOptionsHeader {
    fn name(&self) -> &'static str {
        "Ipv6DestinationOptionsHeader"
    }

    fn summary(&self) -> String {
        format!(
            "Ipv6DestinationOptionsHeader(options={}, next={})",
            ipv6_options_summary(&self.options),
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
            ("options", ipv6_options_summary(&self.options)),
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
        for option in &self.options {
            out.extend_from_slice(&option.encode()?);
        }
        out.resize(start + total_len, 0);
        Ok(())
    }

    impl_layer_object!(Ipv6DestinationOptionsHeader);
}

impl_layer_div!(Ipv6DestinationOptionsHeader);

/// Generic IPv6 Routing Header for routing types not represented by a specialized layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6RoutingHeader {
    next_header: Field<u8>,
    header_ext_len: Field<u8>,
    routing_type: Field<u8>,
    segments_left: Field<u8>,
    type_data: Vec<u8>,
}

impl Ipv6RoutingHeader {
    /// Create a generic routing header with type 0 and no type-specific data.
    pub fn new() -> Self {
        Self {
            next_header: Field::defaulted(0),
            header_ext_len: Field::unset(),
            routing_type: Field::defaulted(0),
            segments_left: Field::defaulted(0),
            type_data: Vec::new(),
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

    /// Set the routing type.
    pub fn routing_type(mut self, routing_type: u8) -> Self {
        self.routing_type.set_user(routing_type);
        self
    }

    /// Alias for generated code that wants the protocol field name.
    pub fn type_(self, routing_type: u8) -> Self {
        self.routing_type(routing_type)
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

    /// Replace the type-specific data bytes after the first four header bytes.
    pub fn type_data(mut self, type_data: impl Into<Vec<u8>>) -> Self {
        self.type_data = type_data.into();
        self
    }

    /// Append type-specific data bytes.
    pub fn append_type_data(mut self, type_data: impl AsRef<[u8]>) -> Self {
        self.type_data.extend_from_slice(type_data.as_ref());
        self
    }

    /// Next-header value.
    pub fn next_header_value(&self) -> u8 {
        value_or_copy(&self.next_header, 0)
    }

    /// Header extension length when explicit or decoded.
    pub fn header_ext_len_value(&self) -> Option<u8> {
        self.header_ext_len.value().copied()
    }

    /// Routing type.
    pub fn routing_type_value(&self) -> u8 {
        value_or_copy(&self.routing_type, 0)
    }

    /// Routing type label from the IANA IPv6 Routing Types registry.
    pub fn routing_type_label(&self) -> &'static str {
        ipv6_routing_type_label(self.routing_type_value())
    }

    /// Routing type status from the IANA IPv6 Routing Types registry and RFC 5095.
    pub fn routing_type_status(&self) -> Ipv6RoutingTypeStatus {
        ipv6_routing_type_status(self.routing_type_value())
    }

    /// Segments-left value.
    pub fn segments_left_value(&self) -> u8 {
        value_or_copy(&self.segments_left, 0)
    }

    /// Type-specific data bytes.
    pub fn type_data_bytes(&self) -> &[u8] {
        &self.type_data
    }

    fn effective_total_len(&self) -> usize {
        self.header_ext_len
            .value()
            .map(|value| IPV6_EXTENSION_MIN_LEN + *value as usize * 8)
            .unwrap_or_else(|| routing_total_len_for_type_data(self.type_data.len()))
    }

    fn effective_header_ext_len(&self) -> Result<u8> {
        header_ext_len_from_total("ipv6.routing.header_ext_len", self.effective_total_len())
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
        validate_extension_total_len("ipv6.routing.header_ext_len", self.effective_total_len())?;
        if self.effective_total_len() < 4 + self.type_data.len() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.routing.type_data",
                "type-specific data does not fit in the routing header length",
            ));
        }
        Ok(())
    }
}

impl Default for Ipv6RoutingHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ipv6RoutingHeader {
    fn name(&self) -> &'static str {
        "Ipv6RoutingHeader"
    }

    fn summary(&self) -> String {
        format!(
            "Ipv6RoutingHeader(type={}, segleft={}, next={})",
            routing_type_summary(self.routing_type_value()),
            self.segments_left_value(),
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
            ("segments_left", self.segments_left_value().to_string()),
            ("type_data", hex_bytes(&self.type_data)),
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
        out.extend_from_slice(&self.type_data);
        out.resize(start + total_len, 0);
        Ok(())
    }

    impl_layer_object!(Ipv6RoutingHeader);
}

impl_layer_div!(Ipv6RoutingHeader);

/// IPv6 Fragment Header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6FragmentHeader {
    next_header: Field<u8>,
    reserved: Field<u8>,
    fragment_offset: Field<u16>,
    res: Field<u8>,
    more_fragments: Field<bool>,
    identification: Field<u32>,
}

impl Ipv6FragmentHeader {
    /// Create a fragment header with deterministic defaults.
    pub fn new() -> Self {
        Self {
            next_header: Field::defaulted(IPPROTO_TCP),
            reserved: Field::defaulted(0),
            fragment_offset: Field::defaulted(0),
            res: Field::defaulted(0),
            more_fragments: Field::defaulted(false),
            identification: Field::defaulted(0),
        }
    }

    /// Set the next header after this fragment header.
    pub fn next_header(mut self, next_header: u8) -> Self {
        self.next_header.set_user(next_header);
        self
    }

    /// Compatibility alias for next header.
    pub fn nh(self, next_header: u8) -> Self {
        self.next_header(next_header)
    }

    /// Set the reserved byte.
    pub fn reserved(mut self, reserved: u8) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Set the fragment offset in 8-byte units.
    pub fn fragment_offset(mut self, fragment_offset: u16) -> Self {
        self.fragment_offset.set_user(fragment_offset);
        self
    }

    /// Alias for fragment offset.
    pub fn offset(self, fragment_offset: u16) -> Self {
        self.fragment_offset(fragment_offset)
    }

    /// Compatibility alias for fragment offset.
    pub fn frag(self, fragment_offset: u16) -> Self {
        self.fragment_offset(fragment_offset)
    }

    /// Set the two reserved flag bits in the fragment field.
    pub fn res(mut self, res: u8) -> Self {
        self.res.set_user(res);
        self
    }

    /// Set or clear the more-fragments flag.
    pub fn more_fragments(mut self, more_fragments: bool) -> Self {
        self.more_fragments.set_user(more_fragments);
        self
    }

    /// libcrafter-style alias for more-fragments flag.
    pub fn mflag(self, more_fragments: bool) -> Self {
        self.more_fragments(more_fragments)
    }

    /// Set the fragment identification.
    pub fn identification(mut self, identification: u32) -> Self {
        self.identification.set_user(identification);
        self
    }

    /// Compatibility alias for identification.
    pub fn id(self, identification: u32) -> Self {
        self.identification(identification)
    }

    /// Next-header value.
    pub fn next_header_value(&self) -> u8 {
        value_or_copy(&self.next_header, IPPROTO_TCP)
    }

    /// Reserved byte value.
    pub fn reserved_value(&self) -> u8 {
        value_or_copy(&self.reserved, 0)
    }

    /// Fragment offset in 8-byte units.
    pub fn fragment_offset_value(&self) -> u16 {
        value_or_copy(&self.fragment_offset, 0)
    }

    /// Alias for the Fragment Offset field in 8-octet units.
    pub fn offset_value(&self) -> u16 {
        self.fragment_offset_value()
    }

    /// Fragment Offset field in RFC 8200 8-octet units.
    pub fn fragment_offset_units(&self) -> u16 {
        self.fragment_offset_value()
    }

    /// Fragment Offset field converted to octets.
    pub fn fragment_offset_bytes(&self) -> u32 {
        u32::from(self.fragment_offset_value()) * 8
    }

    /// Two reserved bits in the fragment field.
    pub fn res_value(&self) -> u8 {
        value_or_copy(&self.res, 0)
    }

    /// Reserved byte value.
    pub fn reserved_byte_value(&self) -> u8 {
        self.reserved_value()
    }

    /// Two reserved bits in the fragment field.
    pub fn reserved_bits_value(&self) -> u8 {
        self.res_value()
    }

    /// Whether the two fragment-field reserved bits are zero.
    pub fn reserved_bits_are_zero(&self) -> bool {
        self.reserved_bits_value() == 0
    }

    /// Whether all reserved Fragment Header fields are zero.
    pub fn reserved_fields_are_zero(&self) -> bool {
        self.reserved_byte_value() == 0 && self.reserved_bits_are_zero()
    }

    /// Return true when the more-fragments flag is set.
    pub fn has_more_fragments(&self) -> bool {
        value_or_copy(&self.more_fragments, false)
    }

    /// More-fragments flag value.
    pub fn more_fragments_value(&self) -> bool {
        self.has_more_fragments()
    }

    /// Compatibility alias for the more-fragments flag value.
    pub fn mflag_value(&self) -> bool {
        self.has_more_fragments()
    }

    /// Whether this header marks the last fragment.
    pub fn is_last_fragment(&self) -> bool {
        !self.has_more_fragments()
    }

    /// Fragment identification value.
    pub fn identification_value(&self) -> u32 {
        value_or_copy(&self.identification, 0)
    }

    /// Compatibility alias for the fragment identification value.
    pub fn id_value(&self) -> u32 {
        self.identification_value()
    }

    /// RFC 6946/RFC 8200 classification from Fragment Offset and M flag.
    pub fn fragment_status(&self) -> Ipv6FragmentHeaderStatus {
        match (self.fragment_offset_value(), self.has_more_fragments()) {
            (0, false) => Ipv6FragmentHeaderStatus::Atomic,
            (0, true) => Ipv6FragmentHeaderStatus::Initial,
            _ => Ipv6FragmentHeaderStatus::NonInitial,
        }
    }

    /// Alias for the Fragment Header classification.
    pub fn status(&self) -> Ipv6FragmentHeaderStatus {
        self.fragment_status()
    }

    /// Human-readable Fragment Header classification.
    pub fn fragment_status_label(&self) -> &'static str {
        self.fragment_status().label()
    }

    /// Whether this header is an RFC 6946 atomic fragment.
    pub fn is_atomic_fragment(&self) -> bool {
        self.fragment_status().is_atomic()
    }

    /// Whether the Fragment Offset field is zero.
    pub fn is_initial_fragment(&self) -> bool {
        self.fragment_status().is_initial()
    }

    /// Whether the Fragment Offset field is nonzero.
    pub fn is_non_initial_fragment(&self) -> bool {
        self.fragment_status().is_non_initial()
    }

    fn effective_next_header(&self, next: Option<&dyn Layer>) -> u8 {
        if self.next_header.is_user_set() {
            return self.next_header_value();
        }

        next.and_then(layer_ipv6_next_header)
            .or_else(|| self.next_header.value().copied())
            .unwrap_or(IPPROTO_TCP)
    }

    fn validate(&self) -> Result<()> {
        if self.fragment_offset_value() > IPV6_MAX_FRAGMENT_OFFSET {
            return Err(CrafterError::invalid_field_value(
                "ipv6.fragment.fragment_offset",
                "fragment offset must fit in 13 bits",
            ));
        }
        if self.res_value() > 0x03 {
            return Err(CrafterError::invalid_field_value(
                "ipv6.fragment.res",
                "fragment reserved bits must fit in two bits",
            ));
        }
        Ok(())
    }
}

impl Default for Ipv6FragmentHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ipv6FragmentHeader {
    fn name(&self) -> &'static str {
        "Ipv6FragmentHeader"
    }

    fn summary(&self) -> String {
        format!(
            "Ipv6FragmentHeader(offset={}, m={}, next={})",
            self.fragment_offset_value(),
            self.has_more_fragments(),
            next_header_summary(self.next_header_value())
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("next_header", next_header_summary(self.next_header_value())),
            ("reserved", format!("0x{:02x}", self.reserved_value())),
            ("fragment_offset", self.fragment_offset_value().to_string()),
            (
                "fragment_offset_bytes",
                self.fragment_offset_bytes().to_string(),
            ),
            ("fragment_status", self.fragment_status_label().to_string()),
            ("res", self.res_value().to_string()),
            (
                "reserved_bits",
                format!("0b{:02b}", self.reserved_bits_value()),
            ),
            (
                "reserved_fields_zero",
                self.reserved_fields_are_zero().to_string(),
            ),
            ("more_fragments", self.has_more_fragments().to_string()),
            (
                "identification",
                format!("0x{:08x}", self.identification_value()),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        IPV6_FRAGMENT_HEADER_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;
        let fragment_field = (self.fragment_offset_value() << 3)
            | ((self.res_value() as u16) << 1)
            | u16::from(self.has_more_fragments());

        out.push(self.effective_next_header(ctx.next()));
        out.push(self.reserved_value());
        out.extend_from_slice(&fragment_field.to_be_bytes());
        out.extend_from_slice(&self.identification_value().to_be_bytes());
        Ok(())
    }

    impl_layer_object!(Ipv6FragmentHeader);
}

impl_layer_div!(Ipv6FragmentHeader);

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

    impl_layer_object!(Ipv6MobileRoutingHeader);
}

impl_layer_div!(Ipv6MobileRoutingHeader);

/// IPv6 Segment Routing Header (Routing Header type 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6SegmentRoutingHeader {
    next_header: Field<u8>,
    header_ext_len: Field<u8>,
    routing_type: Field<u8>,
    segments_left: Field<u8>,
    last_entry: Field<u8>,
    flags: Field<u8>,
    tag: Field<u16>,
    policy_flag1: Field<u8>,
    policy_flag2: Field<u8>,
    policy_flag3: Field<u8>,
    policy_flag4: Field<u8>,
    hmac_key_id: Field<u8>,
    segments: Vec<Ipv6Addr>,
    policies: [Ipv6Addr; 4],
    hmac: [u8; IPV6_SEGMENT_HMAC_LEN],
    trailing_data: Vec<u8>,
}

impl Ipv6SegmentRoutingHeader {
    /// Create an empty segment routing header.
    pub fn new() -> Self {
        Self {
            next_header: Field::defaulted(0),
            header_ext_len: Field::unset(),
            routing_type: Field::defaulted(IPV6_ROUTING_TYPE_SEGMENT),
            segments_left: Field::unset(),
            last_entry: Field::unset(),
            flags: Field::defaulted(0),
            tag: Field::defaulted(0),
            policy_flag1: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
            policy_flag2: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
            policy_flag3: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
            policy_flag4: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
            hmac_key_id: Field::defaulted(0),
            segments: Vec::new(),
            policies: [Ipv6Addr::UNSPECIFIED; 4],
            hmac: [0; IPV6_SEGMENT_HMAC_LEN],
            trailing_data: Vec::new(),
        }
    }

    /// Set the next header after this segment routing header.
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

    /// Set the RFC 8754 Last Entry field.
    pub fn last_entry(mut self, last_entry: u8) -> Self {
        self.last_entry.set_user(last_entry);
        self
    }

    /// Compatibility alias for the RFC 8754 Last Entry field.
    pub fn first_segment(self, first_segment: u8) -> Self {
        self.last_entry(first_segment)
    }

    /// Set the RFC 8754 Flags byte.
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags.set_user(flags);
        self
    }

    /// Set the RFC 8754 Tag field.
    pub fn tag(mut self, tag: u16) -> Self {
        self.tag.set_user(tag);
        self
    }

    /// Set or clear the cleanup flag.
    pub fn c_flag(mut self, c_flag: bool) -> Self {
        self.set_flag_bit(0x80, c_flag);
        self
    }

    /// Set or clear the protected flag.
    pub fn p_flag(mut self, p_flag: bool) -> Self {
        self.set_flag_bit(0x40, p_flag);
        self
    }

    /// libcrafter-style alias for protected flag.
    pub fn pflag(self, p_flag: bool) -> Self {
        self.p_flag(p_flag)
    }

    /// Set the two reserved bits.
    pub fn reserved(mut self, reserved: u8) -> Self {
        let mut flags = self.flags_value();
        flags &= !0x30;
        flags |= (reserved & 0x03) << 4;
        self.flags.set_user(flags);
        self
    }

    /// Set policy flag 1.
    pub fn policy_flag1(mut self, policy_flag: u8) -> Self {
        self.policy_flag1.set_user(policy_flag);
        self
    }

    /// Set policy flag 2.
    pub fn policy_flag2(mut self, policy_flag: u8) -> Self {
        self.policy_flag2.set_user(policy_flag);
        self
    }

    /// Set policy flag 3.
    pub fn policy_flag3(mut self, policy_flag: u8) -> Self {
        self.policy_flag3.set_user(policy_flag);
        self
    }

    /// Set policy flag 4.
    pub fn policy_flag4(mut self, policy_flag: u8) -> Self {
        self.policy_flag4.set_user(policy_flag);
        self
    }

    /// Set one policy flag by zero-based policy index.
    pub fn policy_flag(mut self, index: usize, policy_flag: u8) -> Result<Self> {
        self.set_policy_flag(index, policy_flag)?;
        Ok(self)
    }

    /// Set the HMAC key identifier.
    pub fn hmac_key_id(mut self, hmac_key_id: u8) -> Self {
        self.hmac_key_id.set_user(hmac_key_id);
        self
    }

    /// Replace the HMAC bytes.
    pub fn hmac(mut self, hmac: [u8; IPV6_SEGMENT_HMAC_LEN]) -> Self {
        self.hmac = hmac;
        self
    }

    /// Append a segment address.
    pub fn segment(mut self, segment: Ipv6Addr) -> Self {
        self.segments.push(segment);
        self
    }

    /// libcrafter-style alias for appending a segment.
    pub fn push_segment(self, segment: Ipv6Addr) -> Self {
        self.segment(segment)
    }

    /// Append a textual segment address.
    pub fn segment_str(self, segment: &str) -> Result<Self> {
        Ok(self.segment(parse_ipv6(segment)?))
    }

    /// libcrafter-style alias for appending a textual segment.
    pub fn push_ipv6_segment(self, segment: &str) -> Result<Self> {
        self.segment_str(segment)
    }

    /// Set a policy address and flag by zero-based policy index.
    pub fn policy(mut self, index: usize, policy: Ipv6Addr, policy_flag: u8) -> Result<Self> {
        self.set_policy(index, policy, policy_flag)?;
        Ok(self)
    }

    /// Set a textual policy address and flag by zero-based policy index.
    pub fn policy_str(self, index: usize, policy: &str, policy_flag: u8) -> Result<Self> {
        self.policy(index, parse_ipv6(policy)?, policy_flag)
    }

    /// Preserve or append raw bytes after the RFC 8754 Segment List.
    pub fn raw_trailing_data(mut self, raw_trailing_data: impl Into<Vec<u8>>) -> Self {
        self.trailing_data = raw_trailing_data.into();
        self
    }

    /// Compatibility alias for raw bytes after the RFC 8754 Segment List.
    pub fn extra_data(mut self, extra_data: impl Into<Vec<u8>>) -> Self {
        self.trailing_data = extra_data.into();
        self
    }

    /// Next-header value.
    pub fn next_header_value(&self) -> u8 {
        value_or_copy(&self.next_header, 0)
    }

    /// Header extension length when explicit or decoded.
    pub fn header_ext_len_value(&self) -> Option<u8> {
        self.header_ext_len.value().copied()
    }

    /// Routing type.
    pub fn routing_type_value(&self) -> u8 {
        value_or_copy(&self.routing_type, IPV6_ROUTING_TYPE_SEGMENT)
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
        self.segments_left
            .value()
            .copied()
            .unwrap_or_else(|| saturating_last_index(self.segments.len()))
    }

    /// RFC 8754 Last Entry value.
    pub fn last_entry_value(&self) -> u8 {
        self.last_entry
            .value()
            .copied()
            .unwrap_or_else(|| saturating_last_index(self.segments.len()))
    }

    /// Compatibility alias for the RFC 8754 Last Entry value.
    pub fn first_segment_value(&self) -> u8 {
        self.last_entry_value()
    }

    /// RFC 8754 Flags byte.
    pub fn flags_value(&self) -> u8 {
        value_or_copy(&self.flags, 0)
    }

    /// RFC 8754 Tag value.
    pub fn tag_value(&self) -> u16 {
        value_or_copy(&self.tag, 0)
    }

    /// Return true when the cleanup flag is set.
    pub fn c_flag_value(&self) -> bool {
        self.flags_value() & 0x80 != 0
    }

    /// Return true when the protected flag is set.
    pub fn p_flag_value(&self) -> bool {
        self.flags_value() & 0x40 != 0
    }

    /// Reserved two-bit value.
    pub fn reserved_value(&self) -> u8 {
        (self.flags_value() >> 4) & 0x03
    }

    /// Policy flags.
    pub fn policy_flags(&self) -> [u8; 4] {
        [
            value_or_copy(&self.policy_flag1, IPV6_SEGMENT_POLICY_UNSET),
            value_or_copy(&self.policy_flag2, IPV6_SEGMENT_POLICY_UNSET),
            value_or_copy(&self.policy_flag3, IPV6_SEGMENT_POLICY_UNSET),
            value_or_copy(&self.policy_flag4, IPV6_SEGMENT_POLICY_UNSET),
        ]
    }

    /// HMAC key identifier.
    pub fn hmac_key_id_value(&self) -> u8 {
        value_or_copy(&self.hmac_key_id, 0)
    }

    /// Segment addresses.
    pub fn segments(&self) -> &[Ipv6Addr] {
        &self.segments
    }

    /// RFC 8754 Segment List entries in encoded order.
    pub fn segment_list(&self) -> &[Ipv6Addr] {
        &self.segments
    }

    /// Policy addresses.
    pub fn policies(&self) -> &[Ipv6Addr; 4] {
        &self.policies
    }

    /// HMAC bytes.
    pub fn hmac_bytes(&self) -> &[u8; IPV6_SEGMENT_HMAC_LEN] {
        &self.hmac
    }

    /// Raw bytes preserved after the RFC 8754 Segment List.
    pub fn raw_trailing_data_bytes(&self) -> &[u8] {
        &self.trailing_data
    }

    /// Compatibility alias for raw bytes preserved after the RFC 8754 Segment List.
    pub fn extra_data_bytes(&self) -> &[u8] {
        &self.trailing_data
    }

    fn set_flag_bit(&mut self, mask: u8, enabled: bool) {
        let mut flags = self.flags_value();
        if enabled {
            flags |= mask;
        } else {
            flags &= !mask;
        }
        self.flags.set_user(flags);
    }

    fn set_policy(&mut self, index: usize, policy: Ipv6Addr, policy_flag: u8) -> Result<()> {
        if index >= self.policies.len() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.policy",
                "policy index must be in the range 0..4",
            ));
        }
        self.policies[index] = policy;
        self.set_policy_flag(index, policy_flag)
    }

    fn set_policy_flag(&mut self, index: usize, policy_flag: u8) -> Result<()> {
        if policy_flag > 0x07 {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.policy_flag",
                "policy flag must fit in three bits",
            ));
        }
        match index {
            0 => self.policy_flag1.set_user(policy_flag),
            1 => self.policy_flag2.set_user(policy_flag),
            2 => self.policy_flag3.set_user(policy_flag),
            3 => self.policy_flag4.set_user(policy_flag),
            _ => {
                return Err(CrafterError::invalid_field_value(
                    "ipv6.segment.policy",
                    "policy index must be in the range 0..4",
                ))
            }
        }
        Ok(())
    }

    fn known_variable_len(&self) -> usize {
        self.segments.len() * 16 + self.trailing_data.len()
    }

    fn effective_total_len(&self) -> usize {
        self.header_ext_len
            .value()
            .map(|value| IPV6_EXTENSION_MIN_LEN + *value as usize * 8)
            .unwrap_or_else(|| round_up_to_8(IPV6_SEGMENT_BASE_LEN + self.known_variable_len()))
    }

    fn effective_header_ext_len(&self) -> Result<u8> {
        header_ext_len_from_total("ipv6.segment.header_ext_len", self.effective_total_len())
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
        validate_extension_total_len("ipv6.segment.header_ext_len", self.effective_total_len())?;
        if self.routing_type_value() != IPV6_ROUTING_TYPE_SEGMENT {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.routing_type",
                "segment routing header type must be 4",
            ));
        }
        if self.segments.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.segments",
                "segment routing header requires at least one segment",
            ));
        }
        if self.last_entry_value() as usize >= self.segments.len() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.last_entry",
                "last entry must refer to an existing segment",
            ));
        }
        if self.segments_left_value() as usize >= self.segments.len() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.segments_left",
                "segments left must refer to an existing segment",
            ));
        }
        if self.policy_flags().iter().any(|flag| *flag > 0x07) {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.policy_flag",
                "policy flags must fit in three bits",
            ));
        }
        if self.effective_total_len() < IPV6_SEGMENT_BASE_LEN + self.known_variable_len() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.header_ext_len",
                "header extension length is too small for segment data",
            ));
        }
        validate_segment_routing_tlv_shape(&self.trailing_data)?;
        Ok(())
    }
}

impl Default for Ipv6SegmentRoutingHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ipv6SegmentRoutingHeader {
    fn name(&self) -> &'static str {
        "Ipv6SegmentRoutingHeader"
    }

    fn summary(&self) -> String {
        format!(
            "Ipv6SegmentRoutingHeader(type={}, segments={}, segleft={}, flags=0x{:02x}, tag=0x{:04x}, next={})",
            routing_type_summary(self.routing_type_value()),
            self.segments.len(),
            self.segments_left_value(),
            self.flags_value(),
            self.tag_value(),
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
            ("segments_left", self.segments_left_value().to_string()),
            ("last_entry", self.last_entry_value().to_string()),
            ("first_segment", self.first_segment_value().to_string()),
            ("flags", format!("0x{:02x}", self.flags_value())),
            ("c_flag", self.c_flag_value().to_string()),
            ("p_flag", self.p_flag_value().to_string()),
            ("tag", format!("0x{:04x}", self.tag_value())),
            ("reserved", self.reserved_value().to_string()),
            ("policy_flags", format!("{:?}", self.policy_flags())),
            ("hmac_key_id", self.hmac_key_id_value().to_string()),
            ("segment_list", ipv6_list_summary(&self.segments)),
            ("raw_trailing_data", hex_bytes(&self.trailing_data)),
            ("extra_data", hex_bytes(&self.trailing_data)),
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
        out.push(self.last_entry_value());
        out.push(self.flags_value());
        out.extend_from_slice(&self.tag_value().to_be_bytes());
        for segment in &self.segments {
            out.extend_from_slice(&segment.octets());
        }
        out.extend_from_slice(&self.trailing_data);
        out.resize(start + total_len, 0);
        Ok(())
    }

    impl_layer_object!(Ipv6SegmentRoutingHeader);
}

impl_layer_div!(Ipv6SegmentRoutingHeader);

/// Append a decoded IPv6 packet using an explicit registry.
pub(crate) fn append_ipv6_packet_with_registry(
    registry: &ProtocolRegistry,
    packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    let (ipv6, payload, rest) = decode_ipv6_parts(bytes)?;
    append_ipv6_payload_with_registry(registry, packet.push(ipv6), payload, rest)
}

fn decode_ipv6_parts(bytes: &[u8]) -> Result<(Ipv6, &[u8], &[u8])> {
    if bytes.len() < IPV6_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ipv6 header",
            IPV6_HEADER_LEN,
            bytes.len(),
        ));
    }

    let version_class_flow = read_u32_be(&bytes[0..4])?;
    let version = (version_class_flow >> 28) as u8;
    if version != 6 {
        return Err(CrafterError::invalid_field_value(
            "ipv6.version",
            "IPv6 packets must have version 6",
        ));
    }

    let payload_length = read_u16_be(&bytes[4..6])? as usize;
    let total_length = IPV6_HEADER_LEN + payload_length;
    if bytes.len() < total_length {
        return Err(CrafterError::buffer_too_short(
            "ipv6 packet",
            total_length,
            bytes.len(),
        ));
    }

    let ipv6 = Ipv6 {
        version: Field::user(version),
        traffic_class: Field::user(((version_class_flow >> 20) & 0xff) as u8),
        flow_label: Field::user(version_class_flow & IPV6_MAX_FLOW_LABEL),
        payload_length: Field::user(payload_length as u16),
        next_header: Field::user(bytes[6]),
        hop_limit: Field::user(bytes[7]),
        source: Field::user(Ipv6Addr::from(copy_array_16(&bytes[8..24]))),
        destination: Field::user(Ipv6Addr::from(copy_array_16(&bytes[24..40]))),
    };

    Ok((
        ipv6,
        &bytes[IPV6_HEADER_LEN..total_length],
        &bytes[total_length..],
    ))
}

fn append_ipv6_payload_with_registry(
    registry: &ProtocolRegistry,
    mut packet: Packet,
    payload: &[u8],
    rest: &[u8],
) -> Result<Packet> {
    let next_header = packet
        .layer::<Ipv6>()
        .map(Ipv6::next_header_value)
        .unwrap_or_default();

    packet = append_ipv6_next_with_registry(registry, packet, next_header, payload)?;

    if !rest.is_empty() {
        packet = packet.push(Raw::from_bytes(rest));
    }

    Ok(packet)
}

fn append_ipv6_next_with_registry(
    registry: &ProtocolRegistry,
    mut packet: Packet,
    mut next_header: u8,
    mut payload: &[u8],
) -> Result<Packet> {
    loop {
        match next_header {
            IPPROTO_IPV6_HOPOPTS => {
                let (hop_by_hop, inner_next_header, remaining) = decode_hop_by_hop_header(payload)?;
                packet = packet.push(hop_by_hop);
                next_header = inner_next_header;
                payload = remaining;
            }
            IPPROTO_IPV6_DSTOPTS => {
                let (destination_options, inner_next_header, remaining) =
                    decode_destination_options_header(payload)?;
                packet = packet.push(destination_options);
                next_header = inner_next_header;
                payload = remaining;
            }
            IPPROTO_IPV6_ROUTE => {
                let (routing, inner_next_header, remaining) = decode_routing_header(payload)?;
                packet = match routing {
                    DecodedRoutingHeader::Generic(layer) => packet.push(layer),
                    DecodedRoutingHeader::Mobile(layer) => packet.push(layer),
                    DecodedRoutingHeader::Segment(layer) => packet.push(layer),
                };
                next_header = inner_next_header;
                payload = remaining;
            }
            IPPROTO_IPV6_FRAGMENT => {
                let (fragment, inner_next_header, remaining) = decode_fragment_header(payload)?;
                let is_non_initial_fragment = fragment.fragment_offset_value() > 0;
                packet = packet.push(fragment);
                if is_non_initial_fragment {
                    if !remaining.is_empty() {
                        packet = packet.push(Raw::from_bytes(remaining));
                    }
                    return Ok(packet);
                }
                next_header = inner_next_header;
                payload = remaining;
            }
            _ => return registry.decode_ipv6_next_header(packet, next_header, payload),
        }
    }
}

enum DecodedRoutingHeader {
    Generic(Ipv6RoutingHeader),
    Mobile(Ipv6MobileRoutingHeader),
    Segment(Ipv6SegmentRoutingHeader),
}

fn decode_hop_by_hop_header(bytes: &[u8]) -> Result<(Ipv6HopByHopOptionsHeader, u8, &[u8])> {
    let total_len = decode_extension_total_len("ipv6 hop-by-hop header", bytes)?;
    let next_header = bytes[0];
    let options = Ipv6Option::decode_all(&bytes[2..total_len])?;

    Ok((
        Ipv6HopByHopOptionsHeader {
            next_header: Field::user(next_header),
            header_ext_len: Field::user(bytes[1]),
            options,
        },
        next_header,
        &bytes[total_len..],
    ))
}

fn decode_destination_options_header(
    bytes: &[u8],
) -> Result<(Ipv6DestinationOptionsHeader, u8, &[u8])> {
    let total_len = decode_extension_total_len("ipv6 destination options header", bytes)?;
    let next_header = bytes[0];
    let options = Ipv6Option::decode_all(&bytes[2..total_len])?;

    Ok((
        Ipv6DestinationOptionsHeader {
            next_header: Field::user(next_header),
            header_ext_len: Field::user(bytes[1]),
            options,
        },
        next_header,
        &bytes[total_len..],
    ))
}

fn decode_routing_header(bytes: &[u8]) -> Result<(DecodedRoutingHeader, u8, &[u8])> {
    let total_len = decode_extension_total_len("ipv6 routing header", bytes)?;
    let next_header = bytes[0];
    let routing_type = bytes[2];

    let header = match routing_type {
        IPV6_ROUTING_TYPE_MOBILE => {
            if total_len < IPV6_MOBILE_ROUTING_LEN {
                return Err(CrafterError::invalid_field_value(
                    "ipv6.mobile.header_ext_len",
                    "mobile routing header must be at least 24 bytes",
                ));
            }
            DecodedRoutingHeader::Mobile(Ipv6MobileRoutingHeader {
                next_header: Field::user(next_header),
                header_ext_len: Field::user(bytes[1]),
                routing_type: Field::user(bytes[2]),
                segments_left: Field::user(bytes[3]),
                reserved: Field::user(read_u32_be(&bytes[4..8])?),
                home_address: Field::user(Ipv6Addr::from(copy_array_16(&bytes[8..24]))),
            })
        }
        IPV6_ROUTING_TYPE_SEGMENT => {
            DecodedRoutingHeader::Segment(decode_segment_routing_header(bytes, total_len)?)
        }
        _ => DecodedRoutingHeader::Generic(Ipv6RoutingHeader {
            next_header: Field::user(next_header),
            header_ext_len: Field::user(bytes[1]),
            routing_type: Field::user(bytes[2]),
            segments_left: Field::user(bytes[3]),
            type_data: bytes[4..total_len].to_vec(),
        }),
    };

    Ok((header, next_header, &bytes[total_len..]))
}

fn decode_segment_routing_header(
    bytes: &[u8],
    total_len: usize,
) -> Result<Ipv6SegmentRoutingHeader> {
    if total_len < IPV6_SEGMENT_BASE_LEN {
        return Err(CrafterError::invalid_field_value(
            "ipv6.segment.header_ext_len",
            "segment routing header must be at least 8 bytes",
        ));
    }

    let flags = bytes[5];
    let tag = read_u16_be(&bytes[6..8])?;
    let last_entry = bytes[4] as usize;
    let segment_count = last_entry + 1;
    let required_variable_len = segment_count * 16;
    let variable = &bytes[IPV6_SEGMENT_BASE_LEN..total_len];
    if variable.len() < required_variable_len {
        return Err(CrafterError::invalid_field_value(
            "ipv6.segment.header_ext_len",
            "segment routing data is shorter than its fields require",
        ));
    }

    let mut cursor = 0;
    let mut segments = Vec::with_capacity(segment_count);
    for _ in 0..segment_count {
        segments.push(Ipv6Addr::from(copy_array_16(
            &variable[cursor..cursor + 16],
        )));
        cursor += 16;
    }
    let trailing_data = variable[cursor..].to_vec();
    validate_segment_routing_tlv_shape(&trailing_data)?;

    Ok(Ipv6SegmentRoutingHeader {
        next_header: Field::user(bytes[0]),
        header_ext_len: Field::user(bytes[1]),
        routing_type: Field::user(bytes[2]),
        segments_left: Field::user(bytes[3]),
        last_entry: Field::user(bytes[4]),
        flags: Field::user(flags),
        tag: Field::user(tag),
        policy_flag1: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
        policy_flag2: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
        policy_flag3: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
        policy_flag4: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
        hmac_key_id: Field::defaulted(0),
        segments,
        policies: [Ipv6Addr::UNSPECIFIED; 4],
        hmac: [0; IPV6_SEGMENT_HMAC_LEN],
        trailing_data,
    })
}

fn validate_segment_routing_tlv_shape(bytes: &[u8]) -> Result<()> {
    let mut cursor = 0;
    while cursor < bytes.len() {
        let tlv_type = bytes[cursor];
        cursor += 1;
        if tlv_type == 0 {
            continue;
        }
        if cursor >= bytes.len() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.tlv",
                "segment routing TLV is missing its length byte",
            ));
        }

        let value_len = bytes[cursor] as usize;
        cursor += 1;
        if bytes.len() - cursor < value_len {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.tlv",
                "segment routing TLV length exceeds trailing data",
            ));
        }
        cursor += value_len;
    }
    Ok(())
}

fn decode_fragment_header(bytes: &[u8]) -> Result<(Ipv6FragmentHeader, u8, &[u8])> {
    if bytes.len() < IPV6_FRAGMENT_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ipv6 fragment header",
            IPV6_FRAGMENT_HEADER_LEN,
            bytes.len(),
        ));
    }

    let fragment_field = read_u16_be(&bytes[2..4])?;
    let fragment = Ipv6FragmentHeader {
        next_header: Field::user(bytes[0]),
        reserved: Field::user(bytes[1]),
        fragment_offset: Field::user(fragment_field >> 3),
        res: Field::user(((fragment_field >> 1) & 0x03) as u8),
        more_fragments: Field::user(fragment_field & 1 != 0),
        identification: Field::user(read_u32_be(&bytes[4..8])?),
    };

    Ok((fragment, bytes[0], &bytes[IPV6_FRAGMENT_HEADER_LEN..]))
}

fn payload_len_after(ctx: LayerContext<'_>) -> usize {
    ctx.packet()
        .iter()
        .enumerate()
        .skip(ctx.index() + 1)
        .map(|(index, layer)| {
            let layer_ctx = LayerContext::new(ctx.packet(), index);
            layer.encoded_len_with_context(&layer_ctx)
        })
        .sum()
}

fn layer_ipv6_next_header(layer: &dyn Layer) -> Option<u8> {
    if layer.as_any().is::<Ipv6HopByHopOptionsHeader>() {
        Some(IPPROTO_IPV6_HOPOPTS)
    } else if layer.as_any().is::<Ipv6DestinationOptionsHeader>() {
        Some(IPPROTO_IPV6_DSTOPTS)
    } else if layer.as_any().is::<Ipv6RoutingHeader>()
        || layer.as_any().is::<Ipv6MobileRoutingHeader>()
        || layer.as_any().is::<Ipv6SegmentRoutingHeader>()
    {
        Some(IPPROTO_IPV6_ROUTE)
    } else if layer.as_any().is::<Ipv6FragmentHeader>() {
        Some(IPPROTO_IPV6_FRAGMENT)
    } else if layer.as_any().is::<Tcp>() {
        Some(IPPROTO_TCP)
    } else if layer.as_any().is::<Udp>() {
        Some(IPPROTO_UDP)
    } else if layer.as_any().is::<Icmpv6>() {
        Some(IPPROTO_ICMPV6)
    } else {
        None
    }
}

fn decode_extension_total_len(context: &'static str, bytes: &[u8]) -> Result<usize> {
    if bytes.len() < IPV6_EXTENSION_MIN_LEN {
        return Err(CrafterError::buffer_too_short(
            context,
            IPV6_EXTENSION_MIN_LEN,
            bytes.len(),
        ));
    }

    let total_len = IPV6_EXTENSION_MIN_LEN + bytes[1] as usize * 8;
    if bytes.len() < total_len {
        return Err(CrafterError::buffer_too_short(
            context,
            total_len,
            bytes.len(),
        ));
    }
    Ok(total_len)
}

fn validate_extension_total_len(field: &'static str, total_len: usize) -> Result<()> {
    if total_len < IPV6_EXTENSION_MIN_LEN {
        return Err(CrafterError::invalid_field_value(
            field,
            "IPv6 extension header must be at least 8 bytes",
        ));
    }
    if total_len > IPV6_MAX_HEADER_EXT_LEN {
        return Err(CrafterError::invalid_field_value(
            field,
            "IPv6 extension header length exceeds the 8-bit header length field",
        ));
    }
    if total_len % 8 != 0 {
        return Err(CrafterError::invalid_field_value(
            field,
            "IPv6 extension header length must be a multiple of 8 bytes",
        ));
    }
    Ok(())
}

fn header_ext_len_from_total(field: &'static str, total_len: usize) -> Result<u8> {
    validate_extension_total_len(field, total_len)?;
    u8::try_from((total_len - IPV6_EXTENSION_MIN_LEN) / 8)
        .map_err(|_| CrafterError::invalid_field_value(field, "header extension length overflow"))
}

fn routing_total_len_for_type_data(type_data_len: usize) -> usize {
    round_up_to_8(4 + type_data_len.max(4))
}

fn round_up_to_8(len: usize) -> usize {
    (len + 7) & !7
}

fn saturating_last_index(len: usize) -> u8 {
    len.saturating_sub(1).min(u8::MAX as usize) as u8
}

fn parse_ipv6(input: &str) -> Result<Ipv6Addr> {
    Ipv6Addr::from_str(input).map_err(|_| {
        CrafterError::invalid_field_value("ipv6_address", "expected textual IPv6 address")
    })
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn copy_array_16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[..16]);
    out
}

#[cfg(test)]
mod ipv6_tests {
    use super::{Ipv6, IPPROTO_IPV6_ROUTE};
    use crate::checksum::ipv6_pseudo_header_checksum;
    use crate::{NetworkLayer, Packet, Raw, Tcp, TCP_FLAG_SYN};
    use core::net::Ipv6Addr;

    fn src() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1)
    }

    fn dst() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 2)
    }

    #[test]
    fn ipv6_tcp_header_autofills_length_next_header_and_checksum() {
        let packet = Ipv6::new()
            .src(src())
            .dst(dst())
            .tc(0xab)
            .fl(0x12345)
            .hlim(32)
            / Tcp::new().sport(1234).dport(80).seq(7).flags(TCP_FLAG_SYN)
            / Raw::from("abc");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[0], 0x6a);
        assert_eq!(&bytes.as_bytes()[4..6], &(23u16).to_be_bytes());
        assert_eq!(bytes.as_bytes()[6], crate::IPPROTO_TCP);
        assert_eq!(bytes.as_bytes()[7], 32);

        let mut tcp = bytes.as_bytes()[40..].to_vec();
        tcp[16] = 0;
        tcp[17] = 0;
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[56], bytes.as_bytes()[57]]),
            ipv6_pseudo_header_checksum(src(), dst(), crate::IPPROTO_TCP, &tcp)
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let ipv6 = decoded.layer::<Ipv6>().unwrap();
        assert_eq!(ipv6.source(), src());
        assert_eq!(ipv6.destination(), dst());
        assert_eq!(ipv6.traffic_class_value(), 0xab);
        assert_eq!(ipv6.flow_label_value(), 0x12345);
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_explicit_base_next_header_is_preserved() {
        let bytes = (Ipv6::new().src(src()).dst(dst()).nh(IPPROTO_IPV6_ROUTE) / Raw::from("abc"))
            .compile()
            .unwrap();

        assert_eq!(bytes.as_bytes()[6], IPPROTO_IPV6_ROUTE);
    }

    #[test]
    fn ipv6_decode_rejects_short_and_malformed_headers() {
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv6, [0u8; 39]).is_err());

        let mut bad_version = (Ipv6::new() / Raw::from("abc"))
            .compile()
            .unwrap()
            .into_bytes();
        bad_version[0] = 0x40;
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv6, bad_version).is_err());

        let mut bad_length = (Ipv6::new() / Raw::from("abc"))
            .compile()
            .unwrap()
            .into_bytes();
        bad_length[4..6].copy_from_slice(&(10u16).to_be_bytes());
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv6, bad_length).is_err());
    }
}

#[cfg(test)]
mod ipv6_extensions {
    use super::{Ipv6FragmentHeader, IPPROTO_IPV6_FRAGMENT};
    use crate::checksum::ipv6_pseudo_header_checksum;
    use crate::{Ipv6, NetworkLayer, Packet, Raw, Udp};
    use core::net::Ipv6Addr;

    fn src() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 10, 0, 0, 0, 0, 1)
    }

    fn dst() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 20, 0, 0, 0, 0, 2)
    }

    #[test]
    fn ipv6_fragment_header_chains_to_udp_and_preserves_checksum_context() {
        let packet = Ipv6::new().src(src()).dst(dst())
            / Ipv6FragmentHeader::new()
                .identification(0x0102_0304)
                .more_fragments(true)
            / Udp::new().sport(1234).dport(5678)
            / Raw::from("payload");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[6], IPPROTO_IPV6_FRAGMENT);
        assert_eq!(bytes.as_bytes()[40], crate::IPPROTO_UDP);
        assert_eq!(&bytes.as_bytes()[42..44], &1u16.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[44..48], &0x0102_0304u32.to_be_bytes());

        let mut udp = bytes.as_bytes()[48..].to_vec();
        udp[6] = 0;
        udp[7] = 0;
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[54], bytes.as_bytes()[55]]),
            ipv6_pseudo_header_checksum(src(), dst(), crate::IPPROTO_UDP, &udp)
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let fragment = decoded.layer::<Ipv6FragmentHeader>().unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(fragment.identification_value(), 0x0102_0304);
        assert!(fragment.has_more_fragments());
        assert_eq!(udp.source_port_value(), 1234);
        assert_eq!(raw.as_bytes(), b"payload");
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_non_initial_fragments_preserve_remaining_bytes_as_raw() {
        let bytes = (Ipv6::new().src(src()).dst(dst())
            / Ipv6FragmentHeader::new()
                .nh(crate::IPPROTO_UDP)
                .fragment_offset(2)
                .identification(9)
            / Raw::from_bytes([1, 2, 3, 4]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        assert!(decoded.layer::<Udp>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn ipv6_unknown_next_header_preserves_payload_as_raw() {
        let bytes = (Ipv6::new().src(src()).dst(dst()).nh(253) / Raw::from_bytes([9, 8, 7]))
            .compile()
            .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();

        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[9, 8, 7]);
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_extension_decode_rejects_short_fragment_headers() {
        let bytes = (Ipv6::new().src(src()).dst(dst()).nh(IPPROTO_IPV6_FRAGMENT)
            / Raw::from_bytes([0u8; 7]))
        .compile()
        .unwrap();

        assert!(Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).is_err());
    }
}

#[cfg(test)]
mod ipv6_routing_header {
    use super::{
        Ipv6MobileRoutingHeader, Ipv6RoutingHeader, Ipv6SegmentRoutingHeader, IPPROTO_IPV6_ROUTE,
        IPV6_ROUTING_TYPE_SEGMENT,
    };
    use crate::{Ipv6, NetworkLayer, Packet, Raw, Tcp};
    use core::net::Ipv6Addr;

    fn src() -> Ipv6Addr {
        "2001:db8:dead:beef:cafe::".parse().unwrap()
    }

    fn dst() -> Ipv6Addr {
        "2001:db8:1234::1".parse().unwrap()
    }

    #[test]
    fn ipv6_segment_routing_header_matches_rfc8754_shape() {
        let sr_header = Ipv6SegmentRoutingHeader::new()
            .push_ipv6_segment("2001:db8:1234::2")
            .unwrap()
            .push_ipv6_segment("2001:db8:1234::3")
            .unwrap()
            .push_ipv6_segment("2001:db8:1234::4")
            .unwrap()
            .push_ipv6_segment("2001:db8:1234::5")
            .unwrap()
            .last_entry(3)
            .flags(0x40)
            .tag(0x1234)
            .raw_trailing_data([0x05, 0x02, 0xaa, 0xbb]);
        let packet = Ipv6::new().src(src()).dst(dst())
            / sr_header
            / Tcp::new().sport(1234).dport(80)
            / Raw::from("Hello World!");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[6], IPPROTO_IPV6_ROUTE);
        assert_eq!(bytes.as_bytes()[40], crate::IPPROTO_TCP);
        assert_eq!(bytes.as_bytes()[41], 9);
        assert_eq!(bytes.as_bytes()[42], IPV6_ROUTING_TYPE_SEGMENT);
        assert_eq!(bytes.as_bytes()[43], 3);
        assert_eq!(bytes.as_bytes()[44], 3);
        assert_eq!(bytes.as_bytes()[45], 0x40);
        assert_eq!(&bytes.as_bytes()[46..48], &[0x12, 0x34]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let sr = decoded.layer::<Ipv6SegmentRoutingHeader>().unwrap();
        assert_eq!(sr.segments().len(), 4);
        assert_eq!(sr.segments_left_value(), 3);
        assert_eq!(sr.last_entry_value(), 3);
        assert_eq!(sr.first_segment_value(), 3);
        assert_eq!(sr.flags_value(), 0x40);
        assert!(sr.p_flag_value());
        assert_eq!(sr.tag_value(), 0x1234);
        assert_eq!(
            sr.raw_trailing_data_bytes(),
            &[0x05, 0x02, 0xaa, 0xbb, 0, 0, 0, 0]
        );
        assert_eq!(decoded.layer::<Tcp>().unwrap().destination_port_value(), 80);
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), b"Hello World!");
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_mobile_routing_header_encodes_home_address_and_decodes_tcp() {
        let packet = Ipv6::new().src(src()).dst(dst())
            / Ipv6MobileRoutingHeader::new()
                .home_address_str("2001:db8::1")
                .unwrap()
            / Tcp::new().sport(1111).dport(2222)
            / Raw::from("mobile");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[6], IPPROTO_IPV6_ROUTE);
        assert_eq!(bytes.as_bytes()[40], crate::IPPROTO_TCP);
        assert_eq!(bytes.as_bytes()[41], 2);
        assert_eq!(bytes.as_bytes()[42], 2);
        assert_eq!(bytes.as_bytes()[43], 1);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let mobile = decoded.layer::<Ipv6MobileRoutingHeader>().unwrap();
        assert_eq!(
            mobile.home_address_value(),
            "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(decoded.layer::<Tcp>().unwrap().source_port_value(), 1111);
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_generic_routing_header_preserves_unknown_type_data() {
        let data = [0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5];
        let packet = Ipv6::new().src(src()).dst(dst())
            / Ipv6RoutingHeader::new()
                .nh(crate::IPPROTO_IPV6_EXPERIMENTAL_1)
                .routing_type(253)
                .segments_left(0)
                .append_type_data(data)
            / Raw::from("tail");
        let bytes = packet.compile().unwrap();
        assert_eq!(bytes.as_bytes()[40], crate::IPPROTO_IPV6_EXPERIMENTAL_1);
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let routing = decoded.layer::<Ipv6RoutingHeader>().unwrap();

        assert_eq!(routing.routing_type_value(), 253);
        assert_eq!(&routing.type_data_bytes()[..data.len()], &data);
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), b"tail");
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_routing_header_builder_rejects_malformed_segment_fields() {
        let bad_empty_segment_header = Packet::new().push(Ipv6SegmentRoutingHeader::new());
        assert!(bad_empty_segment_header.compile().is_err());

        let bad_policy_flag = Ipv6SegmentRoutingHeader::new().policy_flag(4, 1);
        assert!(bad_policy_flag.is_err());
    }
}
