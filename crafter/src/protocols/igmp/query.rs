//! IGMP membership query model.
//!
//! The common IGMP fixed header remains the [`Igmp`](super::Igmp) layer. This
//! layer models the IGMPv3 query-specific body that follows it: Flags/S/QRV,
//! QQIC, Number of Sources, and the source address vector.

use core::any::Any;
use core::net::Ipv4Addr;
use core::ops::Div;
use core::time::Duration;

use crate::error::Result;
use crate::field::{Field, FieldState};
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

use super::constants::{
    igmp_v3_timer_code_from_units_floor, igmp_v3_timer_code_units, IGMP_DEFAULT_QUERY_FLAGS,
    IGMP_V3_QUERY_FLAGS_MASK, IGMP_V3_QUERY_FLAGS_UNASSIGNED_MASK,
    IGMP_V3_QUERY_FLAG_EXTENSION,
};
use super::message::Igmp;

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

    /// Build an IGMPv3 General Query body.
    ///
    /// The common [`Igmp`] header carries the zero Group Address for a General
    /// Query; use [`Igmp::v3_general_query`] to build both layers at once.
    pub fn general() -> Self {
        Self::new()
    }

    /// Build an IGMPv3 Group-Specific Query body.
    ///
    /// The group address lives in the common [`Igmp`] header; use
    /// [`Igmp::v3_group_specific_query`] to build both layers at once.
    pub fn group_specific() -> Self {
        Self::new()
    }

    /// Build an IGMPv3 Group-and-Source-Specific Query body.
    ///
    /// The Number of Sources field is derived from `sources` unless the caller
    /// later pins it with [`IgmpQuery::with_number_of_sources`].
    pub fn group_and_source_specific(sources: impl Into<Vec<Ipv4Addr>>) -> Self {
        Self::new().with_source_addresses(sources)
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

    /// Set or clear a registry-managed query flag bit while preserving S/QRV.
    pub fn with_query_flag(self, flag: u8, enabled: bool) -> Self {
        let flag = flag & IGMP_V3_QUERY_FLAGS_MASK;
        let mut raw = self.raw_flags_qrv_value();
        if enabled {
            raw |= flag;
        } else {
            raw &= !flag;
        }
        self.with_raw_flags_qrv(raw)
    }

    /// Set or clear the RFC 9279 Extension flag bit.
    pub fn with_extension_flag(self, enabled: bool) -> Self {
        self.with_query_flag(IGMP_V3_QUERY_FLAG_EXTENSION, enabled)
    }

    /// Set the currently unassigned query flag bits while preserving E/S/QRV.
    pub fn with_unassigned_query_flags(self, flags: u8) -> Self {
        let preserved = self.raw_flags_qrv_value() & !IGMP_V3_QUERY_FLAGS_UNASSIGNED_MASK;
        self.with_raw_flags_qrv((flags & IGMP_V3_QUERY_FLAGS_UNASSIGNED_MASK) | preserved)
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

    /// Compatibility alias for setting the Querier's Robustness Variable bits.
    pub fn with_qrv(self, qrv: u8) -> Self {
        self.with_querier_robustness_variable(qrv)
    }

    /// Set the raw QQIC byte.
    pub fn with_qqic(mut self, qqic: u8) -> Self {
        self.qqic.set_user(qqic);
        self
    }

    /// Set the QQIC field from an IGMPv3 Querier's Query Interval in seconds.
    ///
    /// RFC 9776 section 4.1.7 gives QQIC the same linear and floating
    /// exponent/mantissa representation as Max Resp Code, with seconds as the
    /// unit. Values that are not exactly representable use the nearest lower
    /// wire code, and values above the wire maximum saturate.
    pub fn with_querier_query_interval_seconds(mut self, seconds: u32) -> Self {
        self.qqic
            .set_user(igmp_v3_timer_code_from_units_floor(seconds));
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

    /// Whether a registry-managed query flag bit is set.
    pub fn has_query_flag(&self, flag: u8) -> bool {
        self.query_flags_value() & (flag & IGMP_V3_QUERY_FLAGS_MASK) != 0
    }

    /// Whether the RFC 9279 extension flag bit is set.
    pub fn extension_flag(&self) -> bool {
        self.has_query_flag(IGMP_V3_QUERY_FLAG_EXTENSION)
    }

    /// Whether the RFC 9279 Extension flag bit is set.
    pub fn query_extension_flag(&self) -> bool {
        self.extension_flag()
    }

    /// Currently unassigned query flag bits.
    pub fn unassigned_query_flags_value(&self) -> u8 {
        self.query_flags_value() & IGMP_V3_QUERY_FLAGS_UNASSIGNED_MASK
    }

    /// Suppress Router-Side Processing flag.
    pub fn suppress_router_side_processing(&self) -> bool {
        self.raw_flags_qrv_value() & IGMP_V3_QUERY_SUPPRESS_ROUTER_SIDE_PROCESSING != 0
    }

    /// Querier's Robustness Variable low three bits.
    pub fn querier_robustness_variable(&self) -> u8 {
        self.raw_flags_qrv_value() & IGMP_V3_QUERY_QRV_MASK
    }

    /// Querier's Robustness Variable low three bits.
    pub fn querier_robustness_variable_value(&self) -> u8 {
        self.querier_robustness_variable()
    }

    /// Compatibility alias for the Querier's Robustness Variable bits.
    pub fn qrv_value(&self) -> u8 {
        self.querier_robustness_variable()
    }

    /// Raw QQIC byte.
    pub fn qqic_value(&self) -> u8 {
        value_or_copy(&self.qqic, 0)
    }

    /// IGMPv3 Querier's Query Interval decoded from QQIC, in seconds.
    ///
    /// Use [`IgmpQuery::qqic_value`] when the raw byte is needed.
    pub fn querier_query_interval_seconds(&self) -> u32 {
        igmp_v3_timer_code_units(self.qqic_value())
    }

    /// IGMPv3 Querier's Query Interval decoded as a [`Duration`].
    pub fn querier_query_interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.querier_query_interval_seconds()))
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

impl Igmp {
    /// Build an IGMPv3 Membership Query packet from a common IGMP header and an
    /// IGMPv3 query body.
    ///
    /// `group_address` is `0.0.0.0` for a General Query and the target group for
    /// Group-Specific or Group-and-Source-Specific Queries. `query` carries the
    /// Flags/S/QRV, QQIC, and Source Address list. Source counts remain
    /// auto-filled from the body unless `query` has an explicit Number of
    /// Sources override.
    pub fn v3_membership_query(
        max_response_code: u8,
        group_address: Ipv4Addr,
        query: IgmpQuery,
    ) -> Packet {
        Self::membership_query()
            .with_max_response_code(max_response_code)
            .with_group_address(group_address)
            / query
    }

    /// Build an IGMPv3 General Query packet.
    pub fn v3_general_query(max_response_code: u8) -> Packet {
        Self::v3_membership_query(
            max_response_code,
            Ipv4Addr::UNSPECIFIED,
            IgmpQuery::general(),
        )
    }

    /// Build an IGMPv3 Group-Specific Query packet for `group_address`.
    pub fn v3_group_specific_query(max_response_code: u8, group_address: Ipv4Addr) -> Packet {
        Self::v3_membership_query(
            max_response_code,
            group_address,
            IgmpQuery::group_specific(),
        )
    }

    /// Build an IGMPv3 Group-and-Source-Specific Query packet.
    pub fn v3_group_and_source_specific_query(
        max_response_code: u8,
        group_address: Ipv4Addr,
        sources: impl Into<Vec<Ipv4Addr>>,
    ) -> Packet {
        Self::v3_membership_query(
            max_response_code,
            group_address,
            IgmpQuery::group_and_source_specific(sources),
        )
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

#[cfg(test)]
mod igmp_v3_query_builders {
    use super::*;
    use crate::protocols::igmp::constants::{IGMP_FIXED_HEADER_LEN, IGMP_TYPE_MEMBERSHIP_QUERY};
    use crate::protocols::igmp::registry::IgmpType;

    fn doc_group() -> Ipv4Addr {
        Ipv4Addr::new(233, 252, 0, 32)
    }

    fn doc_sources() -> Vec<Ipv4Addr> {
        vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 2)]
    }

    #[test]
    fn igmp_v3_query_builders_general_query_uses_zero_group_and_no_sources() -> crate::Result<()> {
        assert_eq!(IgmpQuery::general(), IgmpQuery::new());

        let packet = Igmp::v3_general_query(100);
        let igmp = packet.layer::<Igmp>().expect("IGMP header layer");
        let query = packet.layer::<IgmpQuery>().expect("IGMPv3 query body");

        assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(igmp.max_response_code_value(), 100);
        assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(query.number_of_sources_value(), 0);
        assert_eq!(query.number_of_sources_state(), FieldState::Unset);
        assert!(query.source_addresses().is_empty());

        let bytes = packet.compile()?;
        assert_eq!(bytes.as_bytes()[0], IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(bytes.as_bytes()[1], 100);
        assert_eq!(&bytes.as_bytes()[4..8], &Ipv4Addr::UNSPECIFIED.octets());
        assert_eq!(&bytes.as_bytes()[IGMP_FIXED_HEADER_LEN..], &[0, 0, 0, 0]);

        Ok(())
    }

    #[test]
    fn igmp_v3_query_builders_group_specific_query_uses_group_and_no_sources() -> crate::Result<()>
    {
        assert_eq!(IgmpQuery::group_specific(), IgmpQuery::new());

        let packet = Igmp::v3_group_specific_query(10, doc_group());
        let igmp = packet.layer::<Igmp>().expect("IGMP header layer");
        let query = packet.layer::<IgmpQuery>().expect("IGMPv3 query body");

        assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
        assert_eq!(igmp.max_response_code_value(), 10);
        assert_eq!(igmp.group_address_value(), doc_group());
        assert_eq!(query.number_of_sources_value(), 0);
        assert_eq!(query.number_of_sources_state(), FieldState::Unset);
        assert!(query.source_addresses().is_empty());

        let bytes = packet.compile()?;
        assert_eq!(&bytes.as_bytes()[4..8], &doc_group().octets());
        assert_eq!(&bytes.as_bytes()[IGMP_FIXED_HEADER_LEN..], &[0, 0, 0, 0]);

        Ok(())
    }

    #[test]
    fn igmp_v3_query_builders_group_and_source_specific_query_auto_fills_count() -> crate::Result<()>
    {
        let sources = doc_sources();
        let packet = Igmp::v3_group_and_source_specific_query(125, doc_group(), sources.clone());
        let igmp = packet.layer::<Igmp>().expect("IGMP header layer");
        let query = packet.layer::<IgmpQuery>().expect("IGMPv3 query body");

        assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
        assert_eq!(igmp.max_response_code_value(), 125);
        assert_eq!(igmp.group_address_value(), doc_group());
        assert_eq!(query.number_of_sources_value(), 2);
        assert_eq!(query.number_of_sources_state(), FieldState::Unset);
        assert_eq!(query.source_addresses(), sources.as_slice());

        let bytes = packet.compile()?;
        assert_eq!(&bytes.as_bytes()[4..8], &doc_group().octets());
        assert_eq!(
            &bytes.as_bytes()[IGMP_FIXED_HEADER_LEN..IGMP_FIXED_HEADER_LEN + 4],
            &[0, 0, 0, 2]
        );
        assert_eq!(
            &bytes.as_bytes()[IGMP_FIXED_HEADER_LEN + 4..],
            &[192, 0, 2, 1, 198, 51, 100, 2]
        );

        Ok(())
    }

    #[test]
    fn igmp_v3_query_builders_preserve_explicit_source_count_override() -> crate::Result<()> {
        let sources = doc_sources();
        let query = IgmpQuery::group_and_source_specific(sources.clone()).with_number_of_sources(7);
        let packet = Igmp::v3_membership_query(125, doc_group(), query.clone());

        let stored = packet.layer::<IgmpQuery>().expect("IGMPv3 query body");
        assert_eq!(stored, &query);
        assert_eq!(stored.number_of_sources_value(), 7);
        assert_eq!(stored.number_of_sources_state(), FieldState::User);
        assert_eq!(stored.source_addresses(), sources.as_slice());

        let bytes = packet.compile()?;
        assert_eq!(
            &bytes.as_bytes()[IGMP_FIXED_HEADER_LEN + 2..IGMP_FIXED_HEADER_LEN + 4],
            &7u16.to_be_bytes()
        );
        assert_eq!(
            &bytes.as_bytes()[IGMP_FIXED_HEADER_LEN + 4..],
            &[192, 0, 2, 1, 198, 51, 100, 2]
        );

        Ok(())
    }
}

#[cfg(test)]
mod igmp_v3_query_encode {
    use super::*;
    use crate::checksum::verify_internet_checksum;
    use crate::protocols::igmp::constants::IGMP_FIXED_HEADER_LEN;

    fn doc_group() -> Ipv4Addr {
        Ipv4Addr::new(233, 252, 0, 33)
    }

    fn compile_query_body(query: IgmpQuery) -> crate::Result<Vec<u8>> {
        let bytes = Igmp::v3_membership_query(100, doc_group(), query).compile()?;
        assert!(verify_internet_checksum(bytes.as_bytes()));
        Ok(bytes.as_bytes()[IGMP_FIXED_HEADER_LEN..].to_vec())
    }

    #[test]
    fn igmp_v3_query_encode_empty_source_list_uses_zero_count() -> crate::Result<()> {
        let body = compile_query_body(IgmpQuery::new())?;

        assert_eq!(body, vec![0x00, 0x00, 0x00, 0x00]);

        Ok(())
    }

    #[test]
    fn igmp_v3_query_encode_one_source_auto_fills_count() -> crate::Result<()> {
        let source = Ipv4Addr::new(192, 0, 2, 10);
        let body = compile_query_body(IgmpQuery::new().with_source_address(source))?;

        assert_eq!(body, vec![0x00, 0x00, 0x00, 0x01, 192, 0, 2, 10]);

        Ok(())
    }

    #[test]
    fn igmp_v3_query_encode_many_sources_auto_fills_count() -> crate::Result<()> {
        let sources = (0..300)
            .map(|index| {
                if index < 256 {
                    Ipv4Addr::new(198, 51, 100, index as u8)
                } else {
                    Ipv4Addr::new(203, 0, 113, (index - 256) as u8)
                }
            })
            .collect::<Vec<_>>();
        let body = compile_query_body(IgmpQuery::new().with_source_addresses(sources.clone()))?;

        assert_eq!(body.len(), 4 + sources.len() * 4);
        assert_eq!(&body[..4], &[0x00, 0x00, 0x01, 0x2c]);
        assert_eq!(&body[4..8], &sources[0].octets());
        assert_eq!(
            &body[body.len() - 4..],
            &sources[sources.len() - 1].octets()
        );

        Ok(())
    }

    #[test]
    fn igmp_v3_query_encode_preserves_explicit_wrong_source_count() -> crate::Result<()> {
        let sources = vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 2)];
        let body = compile_query_body(
            IgmpQuery::new()
                .with_source_addresses(sources)
                .with_number_of_sources(7),
        )?;

        assert_eq!(
            body,
            vec![0x00, 0x00, 0x00, 0x07, 192, 0, 2, 1, 198, 51, 100, 2]
        );

        Ok(())
    }

    #[test]
    fn igmp_v3_query_encode_preserves_reserved_flags_bits() -> crate::Result<()> {
        let body = compile_query_body(
            IgmpQuery::new()
                .with_raw_flags_qrv(0xf8)
                .with_qqic(0x7d)
                .with_source_address(Ipv4Addr::new(192, 0, 2, 44)),
        )?;

        assert_eq!(body, vec![0xf8, 0x7d, 0x00, 0x01, 192, 0, 2, 44]);

        Ok(())
    }
}

#[cfg(test)]
mod igmp_v3_query_codes {
    use super::*;
    use crate::field::FieldState;
    use crate::packet::Packet;
    use crate::protocols::igmp::constants::{
        IGMP_TYPE_MEMBERSHIP_QUERY, IGMP_V3_TIMER_CODE_MAX_UNITS,
    };
    use crate::protocols::igmp::decode::append_igmp_packet;

    #[test]
    fn igmp_v3_query_codes_linear_range_stays_raw_and_interpreted() {
        for units in [0, 1, 100, 127] {
            let igmp = Igmp::membership_query().with_v3_max_response_time_tenths(units);
            let query = IgmpQuery::new().with_querier_query_interval_seconds(units);

            assert_eq!(igmp.max_response_code_value(), units as u8);
            assert_eq!(igmp.v3_max_response_time_tenths(), units);
            assert_eq!(
                igmp.v3_max_response_time(),
                Duration::from_millis(u64::from(units) * 100)
            );

            assert_eq!(query.qqic_value(), units as u8);
            assert_eq!(query.querier_query_interval_seconds(), units);
            assert_eq!(
                query.querier_query_interval(),
                Duration::from_secs(u64::from(units))
            );
        }
    }

    #[test]
    fn igmp_v3_query_codes_floating_range_uses_rfc9776_encoding() {
        let exact = Igmp::membership_query().with_v3_max_response_time_tenths(200);
        let floored = Igmp::membership_query().with_v3_max_response_time_tenths(201);
        let query = IgmpQuery::new().with_querier_query_interval_seconds(512);

        assert_eq!(exact.max_response_code_value(), 0x89);
        assert_eq!(exact.v3_max_response_time_tenths(), 200);
        assert_eq!(floored.max_response_code_value(), 0x89);
        assert_eq!(floored.v3_max_response_time_tenths(), 200);

        assert_eq!(query.qqic_value(), 0xa0);
        assert_eq!(query.querier_query_interval_seconds(), 512);
        assert_eq!(query.querier_query_interval(), Duration::from_secs(512));
    }

    #[test]
    fn igmp_v3_query_codes_maximum_values_saturate_to_max_wire_code() {
        let igmp = Igmp::membership_query().with_v3_max_response_time_tenths(u32::MAX);
        let query = IgmpQuery::new().with_querier_query_interval_seconds(u32::MAX);

        assert_eq!(igmp.max_response_code_value(), u8::MAX);
        assert_eq!(igmp.v3_max_response_time_tenths(), IGMP_V3_TIMER_CODE_MAX_UNITS);
        assert_eq!(
            igmp.v3_max_response_time(),
            Duration::from_millis(u64::from(IGMP_V3_TIMER_CODE_MAX_UNITS) * 100)
        );

        assert_eq!(query.qqic_value(), u8::MAX);
        assert_eq!(
            query.querier_query_interval_seconds(),
            IGMP_V3_TIMER_CODE_MAX_UNITS
        );
        assert_eq!(
            query.querier_query_interval(),
            Duration::from_secs(u64::from(IGMP_V3_TIMER_CODE_MAX_UNITS))
        );
    }

    #[test]
    fn igmp_v3_query_codes_decode_roundtrips_raw_bytes() {
        let bytes = [
            IGMP_TYPE_MEMBERSHIP_QUERY,
            0x91,
            0x12,
            0x34,
            233,
            252,
            0,
            35,
            0x00,
            0xff,
            0x00,
            0x00,
        ];

        let decoded = append_igmp_packet(Packet::new(), &bytes).expect("decode IGMPv3 query code");
        let igmp = decoded.layer::<Igmp>().expect("IGMP header");
        let query = decoded.layer::<IgmpQuery>().expect("IGMPv3 query body");

        assert_eq!(igmp.max_response_code_value(), 0x91);
        assert_eq!(igmp.v3_max_response_time_tenths(), 272);
        assert_eq!(igmp.max_response_code_state(), FieldState::User);
        assert_eq!(query.qqic_value(), 0xff);
        assert_eq!(
            query.querier_query_interval_seconds(),
            IGMP_V3_TIMER_CODE_MAX_UNITS
        );
        assert_eq!(query.qqic_state(), FieldState::User);

        assert_eq!(
            Igmp::membership_query()
                .with_v3_max_response_time_tenths(igmp.v3_max_response_time_tenths())
                .max_response_code_value(),
            0x91
        );
        assert_eq!(
            IgmpQuery::new()
                .with_querier_query_interval_seconds(query.querier_query_interval_seconds())
                .qqic_value(),
            0xff
        );
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }
}

#[cfg(test)]
mod igmp_v3_query_flags {
    use super::*;
    use crate::field::FieldState;
    use crate::packet::Packet;
    use crate::protocols::igmp::constants::{
        IGMP_FIXED_HEADER_LEN, IGMP_TYPE_MEMBERSHIP_QUERY, IGMP_V3_QUERY_FLAGS_MASK,
        IGMP_V3_QUERY_FLAGS_UNASSIGNED_MASK, IGMP_V3_QUERY_FLAG_EXTENSION,
    };
    use crate::protocols::igmp::decode::append_igmp_packet;
    use crate::protocols::igmp::registry::{
        igmp_query_flag, igmp_query_flag_meta, igmp_query_flag_name, igmp_query_flag_status,
        IgmpFlagStatus, IgmpQueryFlag,
    };

    fn doc_group() -> Ipv4Addr {
        Ipv4Addr::new(233, 252, 0, 36)
    }

    fn compile_query_body(query: IgmpQuery) -> crate::Result<Vec<u8>> {
        let bytes = Igmp::v3_membership_query(100, doc_group(), query).compile()?;
        Ok(bytes.as_bytes()[IGMP_FIXED_HEADER_LEN..].to_vec())
    }

    #[test]
    fn igmp_v3_query_flags_named_bits_preserve_s_and_qrv() -> crate::Result<()> {
        let query = IgmpQuery::new()
            .with_extension_flag(true)
            .with_suppress_router_side_processing(true)
            .with_qrv(5)
            .with_qqic(125);

        assert_eq!(query.raw_flags_qrv_value(), 0x8d);
        assert_eq!(query.query_flags_value(), IGMP_V3_QUERY_FLAG_EXTENSION);
        assert!(query.has_query_flag(IGMP_V3_QUERY_FLAG_EXTENSION));
        assert!(query.extension_flag());
        assert!(query.query_extension_flag());
        assert_eq!(query.unassigned_query_flags_value(), 0);
        assert!(query.suppress_router_side_processing());
        assert_eq!(query.querier_robustness_variable(), 5);
        assert_eq!(query.querier_robustness_variable_value(), 5);
        assert_eq!(query.qrv_value(), 5);
        assert_eq!(query.raw_flags_qrv_state(), FieldState::User);

        let cleared = query.clone().with_extension_flag(false);
        assert_eq!(cleared.raw_flags_qrv_value(), 0x0d);
        assert!(!cleared.extension_flag());
        assert!(cleared.suppress_router_side_processing());
        assert_eq!(cleared.querier_robustness_variable(), 5);

        let body = compile_query_body(query)?;
        assert_eq!(body, vec![0x8d, 125, 0, 0]);

        Ok(())
    }

    #[test]
    fn igmp_v3_query_flags_reserved_bits_are_visible_and_preserved() -> crate::Result<()> {
        let query = IgmpQuery::new()
            .with_extension_flag(true)
            .with_unassigned_query_flags(IGMP_V3_QUERY_FLAGS_UNASSIGNED_MASK)
            .with_suppress_router_side_processing(true)
            .with_querier_robustness_variable(7);

        assert_eq!(query.raw_flags_qrv_value(), 0xff);
        assert_eq!(query.query_flags_value(), IGMP_V3_QUERY_FLAGS_MASK);
        assert_eq!(
            query.unassigned_query_flags_value(),
            IGMP_V3_QUERY_FLAGS_UNASSIGNED_MASK
        );
        assert!(query.extension_flag());
        assert!(query.suppress_router_side_processing());
        assert_eq!(query.querier_robustness_variable(), 7);

        let without_unassigned = query.clone().with_unassigned_query_flags(0);
        assert_eq!(without_unassigned.raw_flags_qrv_value(), 0x8f);
        assert_eq!(without_unassigned.unassigned_query_flags_value(), 0);
        assert!(without_unassigned.extension_flag());
        assert!(without_unassigned.suppress_router_side_processing());
        assert_eq!(without_unassigned.querier_robustness_variable(), 7);

        let rebuilt = IgmpQuery::new()
            .with_raw_flags_qrv(0x0a)
            .with_query_flags(IGMP_V3_QUERY_FLAGS_MASK);
        assert_eq!(rebuilt.raw_flags_qrv_value(), 0xfa);
        assert_eq!(compile_query_body(rebuilt)?, vec![0xfa, 0, 0, 0]);

        Ok(())
    }

    #[test]
    fn igmp_v3_query_flags_registry_surface_names_extension_bit() {
        let extension = igmp_query_flag_meta(0);
        assert_eq!(extension.bit, 0);
        assert_eq!(extension.mask, IGMP_V3_QUERY_FLAG_EXTENSION);
        assert_eq!(extension.flag, IgmpQueryFlag::Extension);
        assert_eq!(extension.name, "Extension");
        assert_eq!(extension.status, IgmpFlagStatus::Assigned);
        assert_eq!(IgmpQueryFlag::Extension.bit(), 0);
        assert_eq!(IgmpQueryFlag::Extension.mask(), IGMP_V3_QUERY_FLAG_EXTENSION);
        assert_eq!(IgmpQueryFlag::Extension.meta(), extension);
        assert_eq!(igmp_query_flag(0), IgmpQueryFlag::Extension);
        assert_eq!(igmp_query_flag_name(0), Some("Extension"));
        assert_eq!(igmp_query_flag_status(0), IgmpFlagStatus::Assigned);

        let unassigned = igmp_query_flag_meta(3);
        assert_eq!(unassigned.bit, 3);
        assert_eq!(unassigned.mask, 0x10);
        assert_eq!(unassigned.flag, IgmpQueryFlag::Unassigned(3));
        assert_eq!(unassigned.status, IgmpFlagStatus::Unassigned);
        assert_eq!(igmp_query_flag_name(3), None);

        let not_flag = igmp_query_flag_meta(4);
        assert_eq!(not_flag.mask, 0);
        assert_eq!(not_flag.flag, IgmpQueryFlag::NotFlag(4));
        assert_eq!(not_flag.status, IgmpFlagStatus::NotFlag);
        assert_eq!(igmp_query_flag_name(4), None);
    }

    #[test]
    fn igmp_v3_query_flags_raw_roundtrip_preserves_unknown_bits() {
        let bytes = [
            IGMP_TYPE_MEMBERSHIP_QUERY,
            0x64,
            0x12,
            0x34,
            233,
            252,
            0,
            36,
            0xf5,
            0x7d,
            0x00,
            0x01,
            192,
            0,
            2,
            55,
        ];

        let decoded = append_igmp_packet(Packet::new(), &bytes).expect("decode IGMPv3 query");
        let query = decoded.layer::<IgmpQuery>().expect("IGMPv3 query body");

        assert_eq!(query.raw_flags_qrv_value(), 0xf5);
        assert_eq!(query.query_flags_value(), IGMP_V3_QUERY_FLAGS_MASK);
        assert_eq!(
            query.unassigned_query_flags_value(),
            IGMP_V3_QUERY_FLAGS_UNASSIGNED_MASK
        );
        assert!(query.extension_flag());
        assert!(!query.suppress_router_side_processing());
        assert_eq!(query.querier_robustness_variable(), 5);
        assert_eq!(query.qqic_value(), 0x7d);
        assert_eq!(query.number_of_sources_value(), 1);
        assert_eq!(
            query.source_addresses(),
            &[Ipv4Addr::new(192, 0, 2, 55)]
        );
        assert_eq!(query.raw_flags_qrv_state(), FieldState::User);
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }
}
