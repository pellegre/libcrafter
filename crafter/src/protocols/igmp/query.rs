//! IGMP membership query model.
//!
//! The common IGMP fixed header remains the [`Igmp`](super::Igmp) layer. This
//! layer models the IGMPv3 query-specific body that follows it: Flags/S/QRV,
//! QQIC, Number of Sources, and the source address vector.

use core::any::Any;
use core::net::Ipv4Addr;
use core::ops::Div;

use crate::error::Result;
use crate::field::{Field, FieldState};
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

use super::constants::{
    IGMP_DEFAULT_QUERY_FLAGS, IGMP_V3_QUERY_FLAGS_MASK, IGMP_V3_QUERY_FLAG_EXTENSION,
};

const IGMP_V3_QUERY_BODY_MIN_LEN: usize = 4;
const IGMP_V3_QUERY_SUPPRESS_ROUTER_SIDE_PROCESSING: u8 = 0x08;
const IGMP_V3_QUERY_QRV_MASK: u8 = 0x07;

/// IGMPv3 Membership Query body fields after the common fixed header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgmpQuery {
    /// Raw Flags/S/QRV octet.
    flags_qrv: Field<u8>,
    /// Querier's Query Interval Code.
    qqic: Field<u8>,
    /// Number of Sources field. Unset values are derived from `sources`.
    number_of_sources: Field<u16>,
    /// Source Address vector.
    sources: Vec<Ipv4Addr>,
}

impl IgmpQuery {
    /// Create an empty IGMPv3 query body.
    pub fn new() -> Self {
        Self {
            flags_qrv: Field::defaulted(IGMP_DEFAULT_QUERY_FLAGS),
            qqic: Field::defaulted(0),
            number_of_sources: Field::unset(),
            sources: Vec::new(),
        }
    }

    /// Set the raw Flags/S/QRV octet, preserving reserved and unknown bits.
    pub fn with_raw_flags_qrv(mut self, flags_qrv: u8) -> Self {
        self.flags_qrv.set_user(flags_qrv);
        self
    }

    /// Set the registry-managed query flags nibble while preserving S/QRV.
    pub fn with_query_flags(self, flags: u8) -> Self {
        let preserved = self.raw_flags_qrv_value() & !IGMP_V3_QUERY_FLAGS_MASK;
        self.with_raw_flags_qrv((flags & IGMP_V3_QUERY_FLAGS_MASK) | preserved)
    }

    /// Set or clear the Suppress Router-Side Processing flag.
    pub fn with_suppress_router_side_processing(self, suppress: bool) -> Self {
        let mut raw = self.raw_flags_qrv_value();
        if suppress {
            raw |= IGMP_V3_QUERY_SUPPRESS_ROUTER_SIDE_PROCESSING;
        } else {
            raw &= !IGMP_V3_QUERY_SUPPRESS_ROUTER_SIDE_PROCESSING;
        }
        self.with_raw_flags_qrv(raw)
    }

    /// Set the Querier's Robustness Variable low three bits.
    pub fn with_querier_robustness_variable(self, qrv: u8) -> Self {
        let preserved = self.raw_flags_qrv_value() & !IGMP_V3_QUERY_QRV_MASK;
        self.with_raw_flags_qrv(preserved | (qrv & IGMP_V3_QUERY_QRV_MASK))
    }

    /// Set the raw QQIC byte.
    pub fn with_qqic(mut self, qqic: u8) -> Self {
        self.qqic.set_user(qqic);
        self
    }

    /// Set the raw Number of Sources field.
    pub fn with_number_of_sources(mut self, count: u16) -> Self {
        self.number_of_sources.set_user(count);
        self
    }

    /// Replace the source-address vector.
    pub fn with_source_addresses(mut self, sources: impl Into<Vec<Ipv4Addr>>) -> Self {
        self.sources = sources.into();
        self
    }

    /// Append one source address.
    pub fn with_source_address(mut self, source: Ipv4Addr) -> Self {
        self.sources.push(source);
        self
    }

    /// Raw Flags/S/QRV octet.
    pub fn raw_flags_qrv_value(&self) -> u8 {
        value_or_copy(&self.flags_qrv, IGMP_DEFAULT_QUERY_FLAGS)
    }

    /// Registry-managed query flags nibble.
    pub fn query_flags_value(&self) -> u8 {
        self.raw_flags_qrv_value() & IGMP_V3_QUERY_FLAGS_MASK
    }

    /// Whether the RFC 9279 extension flag bit is set.
    pub fn extension_flag(&self) -> bool {
        self.query_flags_value() & IGMP_V3_QUERY_FLAG_EXTENSION != 0
    }

    /// Suppress Router-Side Processing flag.
    pub fn suppress_router_side_processing(&self) -> bool {
        self.raw_flags_qrv_value() & IGMP_V3_QUERY_SUPPRESS_ROUTER_SIDE_PROCESSING != 0
    }

    /// Querier's Robustness Variable low three bits.
    pub fn querier_robustness_variable(&self) -> u8 {
        self.raw_flags_qrv_value() & IGMP_V3_QUERY_QRV_MASK
    }

    /// Raw QQIC byte.
    pub fn qqic_value(&self) -> u8 {
        value_or_copy(&self.qqic, 0)
    }

    /// Number of Sources field value, derived from the vector unless explicit.
    pub fn number_of_sources_value(&self) -> u16 {
        value_or_copy(&self.number_of_sources, self.sources.len() as u16)
    }

    /// Source Address vector.
    pub fn source_addresses(&self) -> &[Ipv4Addr] {
        &self.sources
    }

    /// Assignment state for the Flags/S/QRV octet.
    pub fn raw_flags_qrv_state(&self) -> FieldState {
        self.flags_qrv.state()
    }

    /// Assignment state for the QQIC field.
    pub fn qqic_state(&self) -> FieldState {
        self.qqic.state()
    }

    /// Assignment state for the Number of Sources field.
    pub fn number_of_sources_state(&self) -> FieldState {
        self.number_of_sources.state()
    }
}

impl Default for IgmpQuery {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IgmpQuery {
    fn name(&self) -> &'static str {
        "IgmpQuery"
    }

    fn summary(&self) -> String {
        format!(
            "IgmpQuery(flags=0x{:02x}, s={}, qrv={}, qqic={}, sources={})",
            self.query_flags_value(),
            self.suppress_router_side_processing(),
            self.querier_robustness_variable(),
            self.qqic_value(),
            self.number_of_sources_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "flags_s_qrv",
                format!("0x{:02x}", self.raw_flags_qrv_value()),
            ),
            ("query_flags", format!("0x{:02x}", self.query_flags_value())),
            ("extension_flag", self.extension_flag().to_string()),
            (
                "suppress_router_side_processing",
                self.suppress_router_side_processing().to_string(),
            ),
            (
                "querier_robustness_variable",
                self.querier_robustness_variable().to_string(),
            ),
            ("qqic", self.qqic_value().to_string()),
            (
                "number_of_sources",
                self.number_of_sources_value().to_string(),
            ),
            (
                "source_addresses",
                self.sources
                    .iter()
                    .map(Ipv4Addr::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        IGMP_V3_QUERY_BODY_MIN_LEN + self.sources.len() * 4
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.push(self.raw_flags_qrv_value());
        out.push(self.qqic_value());
        out.extend_from_slice(&self.number_of_sources_value().to_be_bytes());
        for source in &self.sources {
            out.extend_from_slice(&source.octets());
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

impl<R> Div<R> for IgmpQuery
where
    R: IntoPacket,
{
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        Packet::from_layer(self).concat(rhs)
    }
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

#[cfg(test)]
mod igmp_v3_query_model {
    use super::*;
    use crate::protocols::igmp::Igmp;
    use crate::IGMP_TYPE_MEMBERSHIP_QUERY;

    #[test]
    fn igmp_v3_query_model_defaults_to_empty_general_query_body() {
        let query = IgmpQuery::default();

        assert_eq!(query.raw_flags_qrv_value(), 0);
        assert_eq!(query.query_flags_value(), 0);
        assert!(!query.extension_flag());
        assert!(!query.suppress_router_side_processing());
        assert_eq!(query.querier_robustness_variable(), 0);
        assert_eq!(query.qqic_value(), 0);
        assert_eq!(query.number_of_sources_value(), 0);
        assert!(query.source_addresses().is_empty());
        assert_eq!(query.raw_flags_qrv_state(), FieldState::Defaulted);
        assert_eq!(query.qqic_state(), FieldState::Defaulted);
        assert_eq!(query.number_of_sources_state(), FieldState::Unset);
        assert_eq!(query.encoded_len(), IGMP_V3_QUERY_BODY_MIN_LEN);
    }

    #[test]
    fn igmp_v3_query_model_preserves_raw_flags_and_source_count_override() {
        let sources = vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 2)];
        let query = IgmpQuery::new()
            .with_raw_flags_qrv(0xff)
            .with_qqic(0x7d)
            .with_number_of_sources(7)
            .with_source_addresses(sources.clone());

        assert_eq!(query.raw_flags_qrv_value(), 0xff);
        assert_eq!(query.query_flags_value(), 0xf0);
        assert!(query.extension_flag());
        assert!(query.suppress_router_side_processing());
        assert_eq!(query.querier_robustness_variable(), 7);
        assert_eq!(query.qqic_value(), 0x7d);
        assert_eq!(query.number_of_sources_value(), 7);
        assert_eq!(query.source_addresses(), sources.as_slice());
        assert_eq!(query.raw_flags_qrv_state(), FieldState::User);
        assert_eq!(query.qqic_state(), FieldState::User);
        assert_eq!(query.number_of_sources_state(), FieldState::User);
    }

    #[test]
    fn igmp_v3_query_model_compiles_as_body_after_common_header() -> crate::Result<()> {
        let query = IgmpQuery::new()
            .with_suppress_router_side_processing(true)
            .with_querier_robustness_variable(3)
            .with_qqic(125)
            .with_source_address(Ipv4Addr::new(192, 0, 2, 10));
        let packet = Igmp::membership_query().with_max_response_code(100) / query.clone();

        let bytes = packet.compile()?;
        assert_eq!(bytes.as_bytes()[0], IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(bytes.as_bytes()[1], 100);
        assert_eq!(&bytes.as_bytes()[8..], &[0x0b, 125, 0, 1, 192, 0, 2, 10]);
        assert_eq!(packet.layer::<IgmpQuery>(), Some(&query));

        Ok(())
    }
}
