//! IPv6 fixed header layer implementation.

use core::any::Any;
use core::net::Ipv6Addr;
use core::ops::Div;

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet, TransportChecksumContext};
use crate::protocols::ip::shared::{Dscp, Ecn, DSCP_SHIFT, ECN_MASK};

use super::constants::{IPV6_HEADER_LEN, IPV6_MAX_FLOW_LABEL};
use super::{display, layer_ipv6_next_header, parse_ipv6, payload_len_after, value_or_copy};

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

/// IPv6 base header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6 {
    pub(super) version: Field<u8>,
    pub(super) traffic_class: Field<u8>,
    pub(super) flow_label: Field<u32>,
    pub(super) payload_length: Field<u16>,
    pub(super) next_header: Field<u8>,
    pub(super) hop_limit: Field<u8>,
    pub(super) source: Field<Ipv6Addr>,
    pub(super) destination: Field<Ipv6Addr>,
}

impl Ipv6 {
    /// Create an IPv6 header with deterministic defaults.
    pub fn new() -> Self {
        Self {
            version: Field::defaulted(6),
            traffic_class: Field::defaulted(0),
            flow_label: Field::defaulted(0),
            payload_length: Field::unset(),
            next_header: Field::defaulted(0),
            hop_limit: Field::defaulted(64),
            source: Field::defaulted(Ipv6Addr::LOCALHOST),
            destination: Field::defaulted(Ipv6Addr::LOCALHOST),
        }
    }

    /// Create an IPv6 header with explicit source and destination addresses.
    pub fn with_addresses(source: Ipv6Addr, destination: Ipv6Addr) -> Self {
        Self::new().src(source).dst(destination)
    }

    /// Set the IP version field.
    pub fn version(mut self, version: u8) -> Self {
        self.version.set_user(version);
        self
    }

    /// Set the traffic class field.
    pub fn traffic_class(mut self, traffic_class: u8) -> Self {
        self.traffic_class.set_user(traffic_class);
        self
    }

    /// Compatibility alias for traffic class.
    pub fn tc(self, traffic_class: u8) -> Self {
        self.traffic_class(traffic_class)
    }

    /// Set the DSCP bits in the traffic class field, preserving the ECN bits.
    pub fn dscp(mut self, dscp: Dscp) -> Self {
        let traffic_class = (dscp.value() << DSCP_SHIFT) | (self.traffic_class_value() & ECN_MASK);
        self.traffic_class.set_user(traffic_class);
        self
    }

    /// Set the ECN bits in the traffic class field, preserving the DSCP bits.
    pub fn ecn(mut self, ecn: Ecn) -> Self {
        let traffic_class = (self.traffic_class_value() & !ECN_MASK) | ecn.value();
        self.traffic_class.set_user(traffic_class);
        self
    }

    /// Set the flow label.
    pub fn flow_label(mut self, flow_label: u32) -> Self {
        self.flow_label.set_user(flow_label);
        self
    }

    /// Set the flow label after validating that it fits the IPv6 20-bit field.
    pub fn try_flow_label(mut self, flow_label: u32) -> Result<Self> {
        validate_flow_label(flow_label)?;
        self.flow_label.set_user(flow_label);
        Ok(self)
    }

    /// Compatibility alias for flow label.
    pub fn fl(self, flow_label: u32) -> Self {
        self.flow_label(flow_label)
    }

    /// Set the payload length field explicitly.
    pub fn payload_length(mut self, payload_length: u16) -> Self {
        self.payload_length.set_user(payload_length);
        self
    }

    /// Compatibility alias for payload length.
    pub fn plen(self, payload_length: u16) -> Self {
        self.payload_length(payload_length)
    }

    /// Set the next-header field.
    pub fn next_header(mut self, next_header: u8) -> Self {
        self.next_header.set_user(next_header);
        self
    }

    /// Compatibility alias for next header.
    pub fn nh(self, next_header: u8) -> Self {
        self.next_header(next_header)
    }

    /// Set the hop limit.
    pub fn hop_limit(mut self, hop_limit: u8) -> Self {
        self.hop_limit.set_user(hop_limit);
        self
    }

    /// Compatibility alias for hop limit.
    pub fn hlim(self, hop_limit: u8) -> Self {
        self.hop_limit(hop_limit)
    }

    /// Set the source IPv6 address.
    pub fn src(mut self, source: Ipv6Addr) -> Self {
        self.source.set_user(source);
        self
    }

    /// Set the source IPv6 address from text.
    pub fn src_str(self, source: &str) -> Result<Self> {
        Ok(self.src(parse_ipv6(source)?))
    }

    /// Set the destination IPv6 address.
    pub fn dst(mut self, destination: Ipv6Addr) -> Self {
        self.destination.set_user(destination);
        self
    }

    /// Set the destination IPv6 address from text.
    pub fn dst_str(self, destination: &str) -> Result<Self> {
        Ok(self.dst(parse_ipv6(destination)?))
    }

    /// IP version value.
    pub fn version_value(&self) -> u8 {
        value_or_copy(&self.version, 6)
    }

    /// Traffic class value.
    pub fn traffic_class_value(&self) -> u8 {
        value_or_copy(&self.traffic_class, 0)
    }

    /// DSCP value carried in the upper six traffic class bits.
    pub fn dscp_value(&self) -> Dscp {
        Dscp::from_u6(self.traffic_class_value() >> DSCP_SHIFT)
    }

    /// ECN value carried in the lower two traffic class bits.
    pub fn ecn_value(&self) -> Ecn {
        Ecn::from_u2(self.traffic_class_value() & ECN_MASK)
    }

    /// Flow label value.
    pub fn flow_label_value(&self) -> u32 {
        value_or_copy(&self.flow_label, 0)
    }

    /// Payload length when explicitly stored or decoded.
    pub fn payload_length_value(&self) -> Option<u16> {
        self.payload_length.value().copied()
    }

    /// Next-header value.
    pub fn next_header_value(&self) -> u8 {
        value_or_copy(&self.next_header, 0)
    }

    /// Hop limit value.
    pub fn hop_limit_value(&self) -> u8 {
        value_or_copy(&self.hop_limit, 64)
    }

    /// Source address.
    pub fn source(&self) -> Ipv6Addr {
        value_or_copy(&self.source, Ipv6Addr::LOCALHOST)
    }

    /// Destination address.
    pub fn destination(&self) -> Ipv6Addr {
        value_or_copy(&self.destination, Ipv6Addr::LOCALHOST)
    }

    fn effective_payload_length(&self, payload_len: usize) -> Result<u16> {
        if let Some(payload_length) = self.payload_length.value().copied() {
            return Ok(payload_length);
        }

        u16::try_from(payload_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "ipv6.payload_length",
                "IPv6 payload length exceeds 65535 bytes",
            )
        })
    }

    fn effective_next_header(&self, next: Option<&dyn Layer>) -> u8 {
        if self.next_header.is_user_set() {
            return self.next_header_value();
        }

        next.and_then(layer_ipv6_next_header)
            .or_else(|| self.next_header.value().copied())
            .unwrap_or(0)
    }

    fn validate(&self, payload_len: usize) -> Result<()> {
        if self.version_value() != 6 {
            return Err(CrafterError::invalid_field_value(
                "ipv6.version",
                "IPv6 layer version must be 6",
            ));
        }
        validate_flow_label(self.flow_label_value())?;
        self.effective_payload_length(payload_len)?;
        Ok(())
    }
}

fn validate_flow_label(flow_label: u32) -> Result<()> {
    if flow_label > IPV6_MAX_FLOW_LABEL {
        return Err(CrafterError::invalid_field_value(
            "ipv6.flow_label",
            "flow label must fit in 20 bits",
        ));
    }
    Ok(())
}

impl Default for Ipv6 {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ipv6 {
    fn name(&self) -> &'static str {
        "Ipv6"
    }

    fn summary(&self) -> String {
        display::summary(self)
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        display::inspection_fields(self)
    }

    fn encoded_len(&self) -> usize {
        IPV6_HEADER_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let payload_len = payload_len_after(*ctx);
        self.validate(payload_len)?;

        let version_class_flow = ((self.version_value() as u32) << 28)
            | ((self.traffic_class_value() as u32) << 20)
            | self.flow_label_value();
        out.extend_from_slice(&version_class_flow.to_be_bytes());
        out.extend_from_slice(&self.effective_payload_length(payload_len)?.to_be_bytes());
        out.push(self.effective_next_header(ctx.next()));
        out.push(self.hop_limit_value());
        out.extend_from_slice(&self.source().octets());
        out.extend_from_slice(&self.destination().octets());
        Ok(())
    }

    fn transport_checksum_context(
        &self,
        transport_protocol: u8,
    ) -> Option<TransportChecksumContext> {
        Some(TransportChecksumContext::Ipv6 {
            source: self.source(),
            destination: self.destination(),
            next_header: transport_protocol,
        })
    }

    impl_layer_object!(Ipv6);
}

impl_layer_div!(Ipv6);
