use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Layer, LayerContext};

use super::super::constants::IPV6_EXTENSION_MIN_LEN;
use super::super::display::{
    hex_bytes, ipv6_routing_type_label, ipv6_routing_type_status, next_header_summary,
    routing_type_summary,
};
use super::super::{layer_ipv6_next_header, value_or_copy};
use super::{header_ext_len_from_total, round_up_to_8, validate_extension_total_len};

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

/// Generic IPv6 Routing Header for routing types not represented by a specialized layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6RoutingHeader {
    pub(in crate::protocols::ip::v6) next_header: Field<u8>,
    pub(in crate::protocols::ip::v6) header_ext_len: Field<u8>,
    pub(in crate::protocols::ip::v6) routing_type: Field<u8>,
    pub(in crate::protocols::ip::v6) segments_left: Field<u8>,
    pub(in crate::protocols::ip::v6) type_data: Vec<u8>,
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

    impl_ipv6_extension_layer_object!(Ipv6RoutingHeader);
}

impl_ipv6_extension_layer_div!(Ipv6RoutingHeader);

fn routing_total_len_for_type_data(type_data_len: usize) -> usize {
    round_up_to_8(4 + type_data_len.max(4))
}
