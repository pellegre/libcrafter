//! IGMP fixed-header message model.
//!
//! IGMP starts with the same 8-octet fixed header for the bootstrap v1/v2
//! message shapes and the leading bytes of the v3 report format: Type, Code
//! or Max Response Code, Checksum, and Group Address. Later steps add packet
//! layer compilation, decode registration, and typed v3 bodies.

use core::any::Any;
use core::net::Ipv4Addr;
use core::ops::Div;
use core::time::Duration;

use crate::checksum::internet_checksum;
use crate::error::Result;
use crate::field::{Field, FieldState};
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

use super::constants::{
    IGMP_DEFAULT_CHECKSUM, IGMP_DEFAULT_CODE, IGMP_FIXED_HEADER_LEN, IGMP_TYPE_MEMBERSHIP_QUERY,
};
use super::registry::{
    igmp_code_meta, igmp_type, igmp_type_meta, IgmpCodeMeta, IgmpType, IgmpTypeMeta,
};

/// Internet Group Management Protocol fixed header.
///
/// The fixed header fields use [`Field`] wrappers so later `compile()` support
/// can fill unset values such as the checksum without clobbering values that a
/// caller set deliberately. The raw Type and Code bytes remain representable
/// even for reserved, unassigned, experimental, or not-yet-typed IGMP values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Igmp {
    /// IGMP Type octet from the IANA IGMP Type Numbers registry.
    pub(crate) igmp_type: Field<u8>,
    /// IGMP Code octet, or Max Response Code for membership queries.
    pub(crate) code: Field<u8>,
    /// IGMP checksum over the IGMP message.
    pub(crate) checksum: Field<u16>,
    /// Group Address field from the common IGMP fixed header.
    pub(crate) group_address: Field<Ipv4Addr>,
}

impl Igmp {
    /// Create an IGMP header with conservative membership-query defaults.
    ///
    /// The source manifest names IGMP Membership Query (`0x11`) and the scoped
    /// Code value `0` for IGMPv1. The group address defaults to `0.0.0.0`,
    /// the all-systems/general-query address in the fixed header, while the
    /// checksum remains unset for compile-time calculation.
    pub fn new() -> Self {
        Self {
            igmp_type: Field::defaulted(IGMP_TYPE_MEMBERSHIP_QUERY),
            code: Field::defaulted(IGMP_DEFAULT_CODE),
            checksum: Field::unset(),
            group_address: Field::defaulted(Ipv4Addr::UNSPECIFIED),
        }
    }

    /// Build an IGMP Membership Query fixed header.
    ///
    /// Sets the Type to Membership Query, the Code/Max Response Code to the
    /// IGMPv1-compatible zero value, and the Group Address to `0.0.0.0`.
    pub fn membership_query() -> Self {
        Self::new()
            .with_igmp_type(IgmpType::MembershipQuery)
            .with_code(IGMP_DEFAULT_CODE)
            .with_group_address(Ipv4Addr::UNSPECIFIED)
    }

    /// Build an IGMPv1 Membership Report fixed header for `group_address`.
    pub fn v1_membership_report(group_address: Ipv4Addr) -> Self {
        Self::new()
            .with_igmp_type(IgmpType::V1MembershipReport)
            .with_code(IGMP_DEFAULT_CODE)
            .with_group_address(group_address)
    }

    /// Build an IGMPv2 Membership Report fixed header for `group_address`.
    pub fn v2_membership_report(group_address: Ipv4Addr) -> Self {
        Self::new()
            .with_igmp_type(IgmpType::V2MembershipReport)
            .with_code(IGMP_DEFAULT_CODE)
            .with_group_address(group_address)
    }

    /// Build an IGMPv3 Membership Report leading header.
    ///
    /// Later report-body steps model group records. Until then this constructor
    /// pins the registered Type and zero-valued reserved fields.
    pub fn v3_membership_report() -> Self {
        Self::new()
            .with_igmp_type(IgmpType::V3MembershipReport)
            .with_code(IGMP_DEFAULT_CODE)
            .with_group_address(Ipv4Addr::UNSPECIFIED)
    }

    /// Set the IGMP Type from source-backed registry metadata.
    pub fn with_igmp_type(mut self, igmp_type: IgmpType) -> Self {
        self.igmp_type.set_user(igmp_type.code());
        self
    }

    /// Set the raw IGMP Type byte.
    pub fn type_code(mut self, type_code: u8) -> Self {
        self.igmp_type.set_user(type_code);
        self
    }

    /// Alias for generated code that wants the protocol field name.
    pub fn type_(self, type_code: u8) -> Self {
        self.type_code(type_code)
    }

    /// Set the raw IGMP Code byte.
    pub fn with_code(mut self, code: u8) -> Self {
        self.code.set_user(code);
        self
    }

    /// Set the Membership Query Max Response Code byte.
    ///
    /// This is the same octet as the raw Code field and is exposed separately
    /// so generated tools can use the RFC field name for query packets.
    pub fn with_max_response_code(self, max_response_code: u8) -> Self {
        self.with_code(max_response_code)
    }

    /// Set the IGMPv2 Max Response Time in tenths of a second.
    ///
    /// RFC 2236 interprets the Membership Query second octet linearly in
    /// tenths of a second. The value is still the raw Code/Max Response octet,
    /// so every byte value remains representable for compatibility and
    /// malformed-packet construction.
    pub fn with_v2_max_response_time_tenths(self, tenths: u8) -> Self {
        self.with_code(tenths)
    }

    /// Compatibility alias for IGMPv2 Max Response Time.
    pub fn with_max_response_time_tenths(self, tenths: u8) -> Self {
        self.with_v2_max_response_time_tenths(tenths)
    }

    /// Set the IGMP checksum explicitly.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum.set_user(checksum);
        self
    }

    /// Compatibility alias for checksum.
    pub fn chksum(self, checksum: u16) -> Self {
        self.checksum(checksum)
    }

    /// Set the common IGMP Group Address field.
    pub fn with_group_address(mut self, group_address: Ipv4Addr) -> Self {
        self.group_address.set_user(group_address);
        self
    }

    /// Raw IGMP Type value.
    pub fn igmp_type_value(&self) -> u8 {
        value_or_copy(&self.igmp_type, IGMP_TYPE_MEMBERSHIP_QUERY)
    }

    /// Raw IGMP Type value, using the packet-field spelling.
    pub fn type_value(&self) -> u8 {
        self.igmp_type_value()
    }

    /// Source-backed IGMP Type classification.
    pub fn igmp_type(&self) -> IgmpType {
        igmp_type(self.igmp_type_value())
    }

    /// Source-backed IGMP Type registry metadata.
    pub fn type_meta(&self) -> IgmpTypeMeta {
        igmp_type_meta(self.igmp_type_value())
    }

    /// Raw Code field value.
    pub fn code_value(&self) -> u8 {
        value_or_copy(&self.code, IGMP_DEFAULT_CODE)
    }

    /// Raw Max Response Code byte.
    ///
    /// For membership queries this is the same octet as the scoped Code field:
    /// Code `0` is the IGMPv1 query form, and `1..=255` carries IGMPv2-or-later
    /// max-response timing semantics. For other Types this accessor still
    /// returns the raw byte so explicit overrides remain inspectable.
    pub fn max_response_code_value(&self) -> u8 {
        self.code_value()
    }

    /// IGMPv2 Max Response Time as the raw number of tenths of a second.
    ///
    /// This returns the common Code/Max Response octet for every Type. Reports,
    /// leave messages, and intentionally malformed packets can therefore be
    /// decoded and re-emitted without losing the raw byte.
    pub fn v2_max_response_time_tenths(&self) -> u8 {
        self.code_value()
    }

    /// Compatibility alias for the IGMPv2 Max Response Time raw tenths value.
    pub fn max_response_time_tenths(&self) -> u8 {
        self.v2_max_response_time_tenths()
    }

    /// IGMPv2 Max Response Time as a [`Duration`].
    pub fn v2_max_response_time(&self) -> Duration {
        Duration::from_millis(u64::from(self.v2_max_response_time_tenths()) * 100)
    }

    /// Source-backed scoped Code registry metadata.
    pub fn code_meta(&self) -> IgmpCodeMeta {
        igmp_code_meta(self.igmp_type_value(), self.code_value())
    }

    /// Stored checksum value, when explicit or decoded.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    /// Raw Group Address field value.
    pub fn group_address_value(&self) -> Ipv4Addr {
        value_or_copy(&self.group_address, Ipv4Addr::UNSPECIFIED)
    }

    /// Assignment state for the IGMP Type field.
    pub fn igmp_type_state(&self) -> FieldState {
        self.igmp_type.state()
    }

    /// Assignment state for the Code field.
    pub fn code_state(&self) -> FieldState {
        self.code.state()
    }

    /// Assignment state for the Max Response Code alias of the Code field.
    pub fn max_response_code_state(&self) -> FieldState {
        self.code_state()
    }

    /// Assignment state for the IGMPv2 Max Response Time alias of the Code field.
    pub fn v2_max_response_time_state(&self) -> FieldState {
        self.code_state()
    }

    /// Assignment state for the checksum field.
    pub fn checksum_state(&self) -> FieldState {
        self.checksum.state()
    }

    /// Assignment state for the Group Address field.
    pub fn group_address_state(&self) -> FieldState {
        self.group_address.state()
    }
}

impl Default for Igmp {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Igmp {
    fn name(&self) -> &'static str {
        "Igmp"
    }

    fn summary(&self) -> String {
        format!(
            "Igmp(type={}, code={}, group={})",
            self.type_meta().name,
            self.code_meta().name,
            self.group_address_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("type", igmp_type_summary(self.type_meta())),
            ("code", igmp_code_summary(self.code_meta())),
            (
                "checksum",
                self.checksum_value()
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("group_address", self.group_address_value().to_string()),
            ("length", IGMP_FIXED_HEADER_LEN.to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        IGMP_FIXED_HEADER_LEN
    }

    fn encoded_len_with_context(&self, ctx: &LayerContext<'_>) -> usize {
        IGMP_FIXED_HEADER_LEN + ctx.packet().encoded_len_after(ctx.index())
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.reserve(IGMP_FIXED_HEADER_LEN);
        out.push(self.igmp_type_value());
        out.push(self.code_value());
        out.extend_from_slice(&IGMP_DEFAULT_CHECKSUM.to_be_bytes());
        out.extend_from_slice(&self.group_address_value().octets());

        if let Err(err) = ctx.packet().compile_layers_after_into(ctx.index(), out) {
            out.truncate(start);
            return Err(err);
        }

        let checksum = self
            .checksum
            .value()
            .copied()
            .unwrap_or_else(|| internet_checksum(&out[start..]));
        out[start + 2..start + 4].copy_from_slice(&checksum.to_be_bytes());
        Ok(())
    }

    fn consumes_following(&self) -> bool {
        true
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

impl<R> Div<R> for Igmp
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

fn igmp_type_summary(meta: IgmpTypeMeta) -> String {
    format!("{} (0x{:02x})", meta.name, meta.code)
}

fn igmp_code_summary(meta: IgmpCodeMeta) -> String {
    format!("{} (0x{:02x})", meta.name, meta.code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldState;
    use crate::protocols::igmp::constants::IGMP_TYPE_EXPERIMENTAL_FIRST;
    use crate::protocols::igmp::registry::IgmpTypeStatus;

    #[test]
    fn igmp_message_model_defaults_to_membership_query() {
        let igmp = Igmp::default();

        assert_eq!(igmp.igmp_type.state(), FieldState::Defaulted);
        assert_eq!(igmp.code.state(), FieldState::Defaulted);
        assert_eq!(igmp.checksum.state(), FieldState::Unset);
        assert_eq!(igmp.group_address.state(), FieldState::Defaulted);

        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(igmp.type_value(), IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
        assert_eq!(igmp.type_meta().status, IgmpTypeStatus::Assigned);
        assert_eq!(igmp.code_value(), IGMP_DEFAULT_CODE);
        assert_eq!(igmp.max_response_code_value(), IGMP_DEFAULT_CODE);
        assert_eq!(igmp.code_meta().name, "IGMP Version 1");
        assert_eq!(igmp.checksum_value(), None);
        assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn igmp_message_model_preserves_explicit_raw_fields() {
        let mut igmp = Igmp::default();
        igmp.igmp_type.set_user(IGMP_TYPE_EXPERIMENTAL_FIRST);
        igmp.code.set_user(0xaa);
        igmp.checksum.set_user(0x1234);
        igmp.group_address.set_user(Ipv4Addr::new(239, 255, 0, 1));

        assert_eq!(
            igmp.igmp_type(),
            IgmpType::Experimental(IGMP_TYPE_EXPERIMENTAL_FIRST)
        );
        assert_eq!(igmp.type_meta().status, IgmpTypeStatus::Experimental);
        assert_eq!(igmp.code_value(), 0xaa);
        assert_eq!(igmp.max_response_code_value(), 0xaa);
        assert_eq!(igmp.code_meta().status, IgmpTypeStatus::Experimental);
        assert_eq!(igmp.checksum_value(), Some(0x1234));
        assert_eq!(igmp.group_address_value(), Ipv4Addr::new(239, 255, 0, 1));
    }
}

#[cfg(test)]
mod igmp_layer_impl {
    use super::*;
    use crate::checksum::internet_checksum;
    use crate::packet::{Packet, Raw};

    #[test]
    fn compiles_base_layer_bytes() {
        let packet = Packet::from_layer(Igmp::default());

        assert_eq!(packet.encoded_len(), IGMP_FIXED_HEADER_LEN);
        assert_eq!(
            packet.compile().expect("compile default IGMP").as_bytes(),
            &[0x11, 0x00, 0xee, 0xff, 0, 0, 0, 0]
        );
    }

    #[test]
    fn summary_and_show_fields_are_stable() {
        let packet = Packet::from_layer(Igmp::default());

        assert_eq!(
            packet.summary(),
            "Igmp(type=IGMP Membership Query, code=IGMP Version 1, group=0.0.0.0)"
        );

        let show = packet.show();
        assert!(show.contains("Packet(len=8, layers=1)"), "{show}");
        assert!(show.contains("[0] Igmp"), "{show}");
        assert!(
            show.contains("type: IGMP Membership Query (0x11)"),
            "{show}"
        );
        assert!(show.contains("code: IGMP Version 1 (0x00)"), "{show}");
        assert!(show.contains("checksum: auto"), "{show}");
        assert!(show.contains("group_address: 0.0.0.0"), "{show}");
        assert!(show.contains("length: 8"), "{show}");
    }

    #[test]
    fn composes_with_following_payload_and_checksums_it() {
        let packet = Igmp::default() / Raw::from_bytes([0xde, 0xad, 0xbe, 0xef]);
        let mut expected = vec![0x11, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef];
        let checksum = internet_checksum(&expected);
        expected[2..4].copy_from_slice(&checksum.to_be_bytes());

        assert_eq!(packet.encoded_len(), IGMP_FIXED_HEADER_LEN + 4);
        assert_eq!(
            packet
                .compile()
                .expect("compile IGMP with payload")
                .as_bytes(),
            expected.as_slice()
        );
    }
}

#[cfg(test)]
mod igmp_checksum {
    use super::*;
    use crate::checksum::{internet_checksum, verify_internet_checksum};
    use crate::packet::{Packet, Raw};

    fn checksum_field(bytes: &[u8]) -> u16 {
        u16::from_be_bytes([bytes[2], bytes[3]])
    }

    #[test]
    fn igmp_checksum_auto_fills_fixed_header() {
        let bytes = Packet::from_layer(Igmp::default())
            .compile()
            .expect("compile default IGMP");
        let mut zeroed = bytes.as_bytes().to_vec();
        zeroed[2] = 0;
        zeroed[3] = 0;

        assert_eq!(checksum_field(bytes.as_bytes()), internet_checksum(&zeroed));
        assert!(verify_internet_checksum(bytes.as_bytes()));
    }

    #[test]
    fn igmp_checksum_auto_fills_following_payload() {
        let packet = Igmp::default() / Raw::from_bytes([0xde, 0xad, 0xbe, 0xef]);
        let bytes = packet.compile().expect("compile IGMP with payload");
        let mut zeroed = bytes.as_bytes().to_vec();
        zeroed[2] = 0;
        zeroed[3] = 0;

        assert_eq!(bytes.len(), IGMP_FIXED_HEADER_LEN + 4);
        assert_eq!(checksum_field(bytes.as_bytes()), internet_checksum(&zeroed));
        assert!(verify_internet_checksum(bytes.as_bytes()));
    }

    #[test]
    fn igmp_checksum_explicit_zero_is_preserved() {
        let mut igmp = Igmp::default();
        igmp.checksum.set_user(0);

        let bytes = Packet::from_layer(igmp)
            .compile()
            .expect("compile explicit zero checksum");

        assert_eq!(checksum_field(bytes.as_bytes()), 0);
        assert!(!verify_internet_checksum(bytes.as_bytes()));
    }

    #[test]
    fn igmp_checksum_explicit_nonzero_is_preserved() {
        let mut igmp = Igmp::default();
        igmp.checksum.set_user(0x1234);

        let bytes = (igmp / Raw::from_bytes([0xde, 0xad]))
            .compile()
            .expect("compile explicit nonzero checksum");

        assert_eq!(checksum_field(bytes.as_bytes()), 0x1234);
        assert!(!verify_internet_checksum(bytes.as_bytes()));
    }

    #[test]
    fn igmp_checksum_roundtrips_through_compile() {
        let packet = Igmp::default() / Raw::from_bytes([0x01, 0x02, 0x03]);

        let first = packet.compile().expect("first compile");
        let second = packet.compile().expect("second compile");
        let mut zeroed = first.as_bytes().to_vec();
        zeroed[2] = 0;
        zeroed[3] = 0;

        assert_eq!(first, second);
        assert_eq!(checksum_field(first.as_bytes()), internet_checksum(&zeroed));
        assert!(verify_internet_checksum(first.as_bytes()));
    }
}

#[cfg(test)]
mod igmp_builders {
    use super::*;
    use crate::checksum::verify_internet_checksum;
    use crate::field::FieldState;
    use crate::packet::Packet;
    use crate::protocols::igmp::constants::{
        IGMP_TYPE_EXPERIMENTAL_FIRST, IGMP_TYPE_MEMBERSHIP_QUERY, IGMP_TYPE_V1_MEMBERSHIP_REPORT,
        IGMP_TYPE_V2_MEMBERSHIP_REPORT, IGMP_TYPE_V3_MEMBERSHIP_REPORT,
    };

    fn compile_layer(igmp: Igmp) -> Vec<u8> {
        Packet::from_layer(igmp)
            .compile()
            .expect("compile IGMP builder")
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn igmp_builders_mark_query_fields_user_set() {
        let group = Ipv4Addr::new(239, 1, 2, 3);
        let igmp = Igmp::membership_query()
            .with_max_response_code(10)
            .with_group_address(group);

        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
        assert_eq!(igmp.code_value(), 10);
        assert_eq!(igmp.max_response_code_value(), 10);
        assert_eq!(igmp.group_address_value(), group);
        assert_eq!(igmp.igmp_type_state(), FieldState::User);
        assert_eq!(igmp.code_state(), FieldState::User);
        assert_eq!(igmp.max_response_code_state(), FieldState::User);
        assert_eq!(igmp.group_address_state(), FieldState::User);
        assert_eq!(igmp.checksum_state(), FieldState::Unset);

        let bytes = compile_layer(igmp);

        assert_eq!(bytes[0], IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(bytes[1], 10);
        assert_eq!(&bytes[4..8], &group.octets());
        assert!(verify_internet_checksum(&bytes));
    }

    #[test]
    fn igmp_builders_create_source_backed_report_types() {
        let v1_group = Ipv4Addr::new(224, 0, 0, 1);
        let v2_group = Ipv4Addr::new(239, 255, 0, 1);

        let v1 = Igmp::v1_membership_report(v1_group);
        let v2 = Igmp::v2_membership_report(v2_group);
        let v3 = Igmp::v3_membership_report();

        assert_eq!(v1.igmp_type_value(), IGMP_TYPE_V1_MEMBERSHIP_REPORT);
        assert_eq!(v1.igmp_type(), IgmpType::V1MembershipReport);
        assert_eq!(v1.group_address_value(), v1_group);
        assert_eq!(v1.igmp_type_state(), FieldState::User);
        assert_eq!(v1.group_address_state(), FieldState::User);

        assert_eq!(v2.igmp_type_value(), IGMP_TYPE_V2_MEMBERSHIP_REPORT);
        assert_eq!(v2.igmp_type(), IgmpType::V2MembershipReport);
        assert_eq!(v2.group_address_value(), v2_group);
        assert_eq!(v2.igmp_type_state(), FieldState::User);
        assert_eq!(v2.group_address_state(), FieldState::User);

        assert_eq!(v3.igmp_type_value(), IGMP_TYPE_V3_MEMBERSHIP_REPORT);
        assert_eq!(v3.igmp_type(), IgmpType::V3MembershipReport);
        assert_eq!(v3.code_value(), IGMP_DEFAULT_CODE);
        assert_eq!(v3.group_address_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(v3.igmp_type_state(), FieldState::User);
        assert_eq!(v3.code_state(), FieldState::User);
    }

    #[test]
    fn igmp_builders_user_set_overrides_survive_compile() {
        let group = Ipv4Addr::new(239, 255, 0, 42);
        let bytes = compile_layer(
            Igmp::new()
                .type_code(IGMP_TYPE_EXPERIMENTAL_FIRST)
                .with_code(0xaa)
                .checksum(0)
                .with_group_address(group),
        );

        assert_eq!(
            bytes.as_slice(),
            &[IGMP_TYPE_EXPERIMENTAL_FIRST, 0xaa, 0x00, 0x00, 239, 255, 0, 42]
        );
        assert!(!verify_internet_checksum(&bytes));
    }

    #[test]
    fn igmp_builders_typed_type_and_checksum_alias_survive_compile() {
        let group = Ipv4Addr::new(224, 0, 0, 22);
        let bytes = compile_layer(
            Igmp::new()
                .with_igmp_type(IgmpType::V2MembershipReport)
                .chksum(0x1234)
                .with_group_address(group),
        );

        assert_eq!(bytes[0], IGMP_TYPE_V2_MEMBERSHIP_REPORT);
        assert_eq!(bytes[1], IGMP_DEFAULT_CODE);
        assert_eq!(&bytes[2..4], &0x1234u16.to_be_bytes());
        assert_eq!(&bytes[4..8], &group.octets());
        assert!(!verify_internet_checksum(&bytes));
    }
}

#[cfg(test)]
mod igmp_v2_max_response {
    use super::*;
    use crate::field::FieldState;
    use crate::packet::Packet;
    use crate::protocols::igmp::constants::{
        IGMP_TYPE_MEMBERSHIP_QUERY, IGMP_TYPE_V2_MEMBERSHIP_REPORT,
    };
    use crate::protocols::igmp::decode::decode;

    fn compile_layer(igmp: Igmp) -> Vec<u8> {
        Packet::from_layer(igmp)
            .compile()
            .expect("compile IGMP max-response case")
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn igmp_v2_max_response_defaults_to_v1_compatibility_zero() {
        let igmp = Igmp::default();

        assert_eq!(igmp.code_value(), 0);
        assert_eq!(igmp.max_response_code_value(), 0);
        assert_eq!(igmp.v2_max_response_time_tenths(), 0);
        assert_eq!(igmp.max_response_time_tenths(), 0);
        assert_eq!(igmp.v2_max_response_time(), Duration::ZERO);
        assert_eq!(igmp.v2_max_response_time_state(), FieldState::Defaulted);

        let bytes = compile_layer(igmp);
        assert_eq!(bytes[0], IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(bytes[1], 0);
    }

    #[test]
    fn igmp_v2_max_response_explicit_time_sets_the_raw_octet() {
        let igmp = Igmp::membership_query().with_v2_max_response_time_tenths(10);

        assert_eq!(igmp.code_value(), 10);
        assert_eq!(igmp.max_response_code_value(), 10);
        assert_eq!(igmp.v2_max_response_time_tenths(), 10);
        assert_eq!(igmp.max_response_time_tenths(), 10);
        assert_eq!(igmp.v2_max_response_time(), Duration::from_secs(1));
        assert_eq!(igmp.v2_max_response_time_state(), FieldState::User);

        let bytes = compile_layer(igmp);
        assert_eq!(bytes[0], IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(bytes[1], 10);
    }

    #[test]
    fn igmp_v2_max_response_boundaries_remain_representable() {
        let explicit_zero = Igmp::new().with_max_response_time_tenths(0);
        let max = Igmp::new().with_v2_max_response_time_tenths(u8::MAX);

        assert_eq!(explicit_zero.v2_max_response_time_tenths(), 0);
        assert_eq!(explicit_zero.v2_max_response_time(), Duration::ZERO);
        assert_eq!(explicit_zero.v2_max_response_time_state(), FieldState::User);

        assert_eq!(max.code_value(), u8::MAX);
        assert_eq!(max.max_response_code_value(), u8::MAX);
        assert_eq!(max.v2_max_response_time_tenths(), u8::MAX);
        assert_eq!(max.v2_max_response_time(), Duration::from_millis(25_500));

        assert_eq!(compile_layer(explicit_zero)[1], 0);
        assert_eq!(compile_layer(max)[1], u8::MAX);
    }

    #[test]
    fn igmp_v2_max_response_decoded_values_preserve_raw_octet_for_any_type() {
        let query = [
            IGMP_TYPE_MEMBERSHIP_QUERY,
            200,
            0x00,
            0x00,
            239,
            1,
            2,
            3,
        ];
        let report = [
            IGMP_TYPE_V2_MEMBERSHIP_REPORT,
            0xfe,
            0x00,
            0x00,
            224,
            0,
            0,
            22,
        ];

        let decoded_query = decode(&query).expect("decode query");
        let decoded_report = decode(&report).expect("decode report");

        assert_eq!(decoded_query.v2_max_response_time_tenths(), 200);
        assert_eq!(
            decoded_query.v2_max_response_time(),
            Duration::from_millis(20_000)
        );
        assert_eq!(decoded_query.v2_max_response_time_state(), FieldState::User);

        assert_eq!(decoded_report.igmp_type(), IgmpType::V2MembershipReport);
        assert_eq!(decoded_report.code_value(), 0xfe);
        assert_eq!(decoded_report.max_response_code_value(), 0xfe);
        assert_eq!(decoded_report.v2_max_response_time_tenths(), 0xfe);
        assert_eq!(decoded_report.v2_max_response_time_state(), FieldState::User);

        assert_eq!(compile_layer(decoded_query), query);
        assert_eq!(compile_layer(decoded_report), report);
    }
}
