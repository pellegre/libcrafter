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
    igmp_v3_timer_code_from_units_floor, igmp_v3_timer_code_units, IGMP_DEFAULT_CHECKSUM,
    IGMP_DEFAULT_CODE, IGMP_FIXED_HEADER_LEN, IGMP_MRD_ADVERTISEMENT_LEN,
    IGMP_MRD_DEFAULT_RESERVED, IGMP_MRD_SOLICITATION_LEN, IGMP_MRD_TERMINATION_LEN,
    IGMP_TYPE_MEMBERSHIP_QUERY,
};
use super::registry::{
    igmp_code_meta, igmp_type, igmp_type_meta, IgmpCodeMeta, IgmpType, IgmpTypeMeta,
};
use super::validation::{igmp_group_address_class, IgmpGroupAddressClass};

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
    /// Decode-time checksum verification status for the whole IGMP message.
    pub(crate) checksum_status: IgmpChecksumStatus,
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
            checksum_status: IgmpChecksumStatus::NotChecked,
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

    /// Build an IGMPv1 Membership Query fixed header.
    ///
    /// IGMPv1 uses Code `0` for Membership Query. That value remains the raw
    /// Code field and is surfaced through scoped registry metadata as
    /// "IGMP Version 1" instead of being rewritten into a v2 max-response
    /// timer during compile or decode.
    pub fn v1_membership_query() -> Self {
        Self::membership_query()
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

    /// Build an IGMPv2 Leave Group fixed header for `group_address`.
    pub fn v2_leave_group(group_address: Ipv4Addr) -> Self {
        Self::new()
            .with_igmp_type(IgmpType::V2LeaveGroup)
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

    /// Build an RFC 4286 Multicast Router Advertisement.
    ///
    /// The common IGMP octets are interpreted as Type, Advertisement Interval,
    /// Checksum, Query Interval, and Robustness Variable. The IPv4 TTL,
    /// Router Alert option, and All-Snoopers destination remain explicit IPv4
    /// composition choices for callers.
    pub fn mrd_advertisement(
        advertisement_interval: u8,
        query_interval: u16,
        robustness_variable: u16,
    ) -> Self {
        Self::new()
            .with_igmp_type(IgmpType::MulticastRouterAdvertisement)
            .with_mrd_advertisement_interval(advertisement_interval)
            .with_mrd_query_interval(query_interval)
            .with_mrd_robustness_variable(robustness_variable)
    }

    /// Build an RFC 4286 Multicast Router Solicitation.
    ///
    /// Solicitation has only Type, Reserved, and Checksum fields. Extra bytes
    /// can still be attached as a following [`Raw`](crate::packet::Raw) layer;
    /// the IGMP checksum covers those bytes and decode preserves them as raw.
    pub fn mrd_solicitation() -> Self {
        Self::new()
            .with_igmp_type(IgmpType::MulticastRouterSolicitation)
            .with_mrd_reserved(IGMP_MRD_DEFAULT_RESERVED)
    }

    /// Build an RFC 4286 Multicast Router Termination.
    ///
    /// Termination has only Type, Reserved, and Checksum fields. Extra bytes
    /// can still be attached as a following [`Raw`](crate::packet::Raw) layer;
    /// the IGMP checksum covers those bytes and decode preserves them as raw.
    pub fn mrd_termination() -> Self {
        Self::new()
            .with_igmp_type(IgmpType::MulticastRouterTermination)
            .with_mrd_reserved(IGMP_MRD_DEFAULT_RESERVED)
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

    /// Set the RFC 4286 MRD Advertisement Interval field in seconds.
    ///
    /// This is the same wire octet as the raw IGMP Code field.
    pub fn with_mrd_advertisement_interval(self, advertisement_interval: u8) -> Self {
        self.with_code(advertisement_interval)
    }

    /// Set the RFC 4286 MRD Reserved field.
    ///
    /// This is the same wire octet as the raw IGMP Code field for
    /// Solicitation and Termination messages, so nonzero malformed values
    /// remain representable.
    pub fn with_mrd_reserved(self, reserved: u8) -> Self {
        self.with_code(reserved)
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

    /// Set the IGMPv3 Max Response Code from a time in tenths of seconds.
    ///
    /// RFC 9776 section 4.1.1 uses a linear range for values below 128 and a
    /// floating exponent/mantissa range above it. Values that are not exactly
    /// representable use the nearest lower wire code, matching the RFC's
    /// configured-timer guidance, and values above the wire maximum saturate.
    pub fn with_v3_max_response_time_tenths(self, tenths: u32) -> Self {
        self.with_max_response_code(igmp_v3_timer_code_from_units_floor(tenths))
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

    /// Set the RFC 4286 MRD Query Interval field in seconds.
    pub fn with_mrd_query_interval(mut self, query_interval: u16) -> Self {
        let robustness_variable = self.mrd_robustness_variable_value();
        self.group_address
            .set_user(mrd_advertisement_body(query_interval, robustness_variable));
        self
    }

    /// Set the RFC 4286 MRD Robustness Variable field.
    pub fn with_mrd_robustness_variable(mut self, robustness_variable: u16) -> Self {
        let query_interval = self.mrd_query_interval_value();
        self.group_address
            .set_user(mrd_advertisement_body(query_interval, robustness_variable));
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

    /// RFC 4286 MRD Advertisement Interval field in seconds.
    pub fn mrd_advertisement_interval_value(&self) -> u8 {
        self.code_value()
    }

    /// RFC 4286 MRD Reserved field for Solicitation and Termination messages.
    pub fn mrd_reserved_value(&self) -> u8 {
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

    /// IGMPv3 Max Response Time decoded from the Max Response Code.
    ///
    /// The returned value is in tenths of a second per RFC 9776 section 4.1.1.
    /// Use [`Igmp::max_response_code_value`] when the raw byte is needed.
    pub fn v3_max_response_time_tenths(&self) -> u32 {
        igmp_v3_timer_code_units(self.max_response_code_value())
    }

    /// IGMPv3 Max Response Time decoded as a [`Duration`].
    pub fn v3_max_response_time(&self) -> Duration {
        Duration::from_millis(u64::from(self.v3_max_response_time_tenths()) * 100)
    }

    /// Source-backed scoped Code registry metadata.
    pub fn code_meta(&self) -> IgmpCodeMeta {
        igmp_code_meta(self.igmp_type_value(), self.code_value())
    }

    /// Stored checksum value, when explicit or decoded.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    /// Decode-time checksum verification status.
    pub fn checksum_status(&self) -> IgmpChecksumStatus {
        self.checksum_status
    }

    /// Raw Group Address field value.
    pub fn group_address_value(&self) -> Ipv4Addr {
        value_or_copy(&self.group_address, Ipv4Addr::UNSPECIFIED)
    }

    /// RFC 4286 MRD Query Interval field in seconds.
    pub fn mrd_query_interval_value(&self) -> u16 {
        let octets = self.group_address_value().octets();
        u16::from_be_bytes([octets[0], octets[1]])
    }

    /// RFC 4286 MRD Robustness Variable field.
    pub fn mrd_robustness_variable_value(&self) -> u16 {
        let octets = self.group_address_value().octets();
        u16::from_be_bytes([octets[2], octets[3]])
    }

    /// Diagnostic classification for the Group Address field.
    pub fn group_address_class(&self) -> IgmpGroupAddressClass {
        igmp_group_address_class(self.group_address_value())
    }

    /// Stable diagnostic label for the Group Address field classification.
    pub fn group_address_class_name(&self) -> &'static str {
        self.group_address_class().name()
    }

    /// Whether the Group Address field is in IPv4 multicast address space.
    pub fn group_address_is_multicast(&self) -> bool {
        self.group_address_class().is_multicast()
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

/// Decode-time checksum verification status for an IGMP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IgmpChecksumStatus {
    /// Checksum has not been verified, usually because the packet was built in memory.
    NotChecked,
    /// The decoded checksum is valid for the IGMP message bytes.
    Valid,
    /// The decoded checksum is present but invalid for the IGMP message bytes.
    Invalid,
}

impl IgmpChecksumStatus {
    /// Stable label for summaries and inspection output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        }
    }
}

impl Layer for Igmp {
    fn name(&self) -> &'static str {
        "Igmp"
    }

    fn summary(&self) -> String {
        let type_summary = igmp_type_summary(self.type_meta());
        match self.igmp_type() {
            IgmpType::MulticastRouterAdvertisement => format!(
                "Igmp(version=MRD, type={type_summary}, advertisement_interval={}s, query_interval={}s, robustness_variable={}, checksum={}, checksum_status={})",
                self.mrd_advertisement_interval_value(),
                self.mrd_query_interval_value(),
                self.mrd_robustness_variable_value(),
                self.checksum_summary(),
                self.checksum_status.label()
            ),
            IgmpType::MulticastRouterSolicitation | IgmpType::MulticastRouterTermination => {
                format!(
                    "Igmp(version=MRD, type={type_summary}, reserved=0x{:02x}, checksum={}, checksum_status={})",
                    self.mrd_reserved_value(),
                    self.checksum_summary(),
                    self.checksum_status.label()
                )
            }
            _ => format!(
                "Igmp(version={}, type={type_summary}, code={}, group={} ({}), checksum={}, checksum_status={})",
                self.version_summary(),
                igmp_code_summary(self.code_meta()),
                self.group_address_value(),
                self.group_address_class_name(),
                self.checksum_summary(),
                self.checksum_status.label()
            ),
        }
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("version", self.version_summary().to_string()),
            ("type", igmp_type_summary(self.type_meta())),
        ];

        match self.igmp_type() {
            IgmpType::MulticastRouterAdvertisement => {
                fields.push((
                    "advertisement_interval",
                    format!("{}s", self.mrd_advertisement_interval_value()),
                ));
                fields.push((
                    "query_interval",
                    format!("{}s", self.mrd_query_interval_value()),
                ));
                fields.push((
                    "robustness_variable",
                    self.mrd_robustness_variable_value().to_string(),
                ));
            }
            IgmpType::MulticastRouterSolicitation | IgmpType::MulticastRouterTermination => {
                fields.push(("reserved", format!("0x{:02x}", self.mrd_reserved_value())));
            }
            _ => {
                fields.push(("code", igmp_code_summary(self.code_meta())));
                fields.push((
                    "group_address",
                    format!(
                        "{} ({})",
                        self.group_address_value(),
                        self.group_address_class_name()
                    ),
                ));
            }
        }

        fields.extend([
            ("checksum", self.checksum_summary()),
            ("checksum_status", self.checksum_status.label().to_string()),
            ("length", self.base_header_len().to_string()),
        ]);
        fields
    }

    fn encoded_len(&self) -> usize {
        self.base_header_len()
    }

    fn encoded_len_with_context(&self, ctx: &LayerContext<'_>) -> usize {
        self.base_header_len() + ctx.packet().encoded_len_after(ctx.index())
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        let base_header_len = self.base_header_len();
        out.reserve(base_header_len);
        out.push(self.igmp_type_value());
        out.push(self.code_value());
        out.extend_from_slice(&IGMP_DEFAULT_CHECKSUM.to_be_bytes());
        if base_header_len > IGMP_MRD_SOLICITATION_LEN {
            out.extend_from_slice(&self.group_address_value().octets());
        }

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

impl Igmp {
    fn version_summary(&self) -> &'static str {
        match self.igmp_type() {
            IgmpType::MembershipQuery if self.code_value() == IGMP_DEFAULT_CODE => "IGMPv1 query",
            IgmpType::MembershipQuery => "IGMPv2/v3 query",
            IgmpType::V1MembershipReport => "IGMPv1",
            IgmpType::V2MembershipReport | IgmpType::V2LeaveGroup => "IGMPv2",
            IgmpType::V3MembershipReport => "IGMPv3",
            IgmpType::MulticastRouterAdvertisement
            | IgmpType::MulticastRouterSolicitation
            | IgmpType::MulticastRouterTermination => "MRD",
            _ => "unknown",
        }
    }

    fn base_header_len(&self) -> usize {
        match self.igmp_type() {
            IgmpType::MulticastRouterSolicitation => {
                mrd_short_message_len(self.group_address.state(), IGMP_MRD_SOLICITATION_LEN)
            }
            IgmpType::MulticastRouterTermination => {
                mrd_short_message_len(self.group_address.state(), IGMP_MRD_TERMINATION_LEN)
            }
            IgmpType::MulticastRouterAdvertisement => IGMP_MRD_ADVERTISEMENT_LEN,
            _ => IGMP_FIXED_HEADER_LEN,
        }
    }

    fn checksum_summary(&self) -> String {
        self.checksum_value()
            .map(|value| format!("0x{value:04x}"))
            .unwrap_or_else(|| "auto".to_string())
    }
}

fn mrd_short_message_len(group_address_state: FieldState, default_len: usize) -> usize {
    if group_address_state == FieldState::User {
        IGMP_FIXED_HEADER_LEN
    } else {
        default_len
    }
}

fn mrd_advertisement_body(query_interval: u16, robustness_variable: u16) -> Ipv4Addr {
    let query = query_interval.to_be_bytes();
    let robustness = robustness_variable.to_be_bytes();
    Ipv4Addr::new(query[0], query[1], robustness[0], robustness[1])
}

fn igmp_type_summary(meta: IgmpTypeMeta) -> String {
    format!("0x{:02x} ({})", meta.code, meta.name)
}

fn igmp_code_summary(meta: IgmpCodeMeta) -> String {
    format!("0x{:02x} ({})", meta.code, meta.name)
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
            "Igmp(version=IGMPv1 query, type=0x11 (IGMP Membership Query), code=0x00 (IGMP Version 1), group=0.0.0.0 (zero), checksum=auto, checksum_status=not_checked)"
        );

        let show = packet.show();
        assert!(show.contains("Packet(len=8, layers=1)"), "{show}");
        assert!(show.contains("[0] Igmp"), "{show}");
        assert!(
            show.contains("type: 0x11 (IGMP Membership Query)"),
            "{show}"
        );
        assert!(show.contains("code: 0x00 (IGMP Version 1)"), "{show}");
        assert!(show.contains("checksum: auto"), "{show}");
        assert!(show.contains("checksum_status: not_checked"), "{show}");
        assert!(show.contains("group_address: 0.0.0.0 (zero)"), "{show}");
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
mod igmp_group_address {
    use super::*;
    use crate::packet::Packet;

    #[test]
    fn igmp_group_address_helpers_classify_layer_field() {
        let general_query = Igmp::membership_query();
        assert_eq!(
            general_query.group_address_class(),
            IgmpGroupAddressClass::Zero
        );
        assert_eq!(general_query.group_address_class_name(), "zero");
        assert!(!general_query.group_address_is_multicast());

        let all_systems = Igmp::membership_query().with_group_address(Ipv4Addr::new(224, 0, 0, 1));
        assert_eq!(
            all_systems.group_address_class(),
            IgmpGroupAddressClass::AllSystems
        );
        assert_eq!(all_systems.group_address_class_name(), "all-systems");
        assert!(all_systems.group_address_is_multicast());

        let all_routers = Igmp::v2_leave_group(Ipv4Addr::new(224, 0, 0, 2));
        assert_eq!(
            all_routers.group_address_class(),
            IgmpGroupAddressClass::AllRouters
        );
        assert_eq!(all_routers.group_address_class_name(), "all-routers");
        assert!(all_routers.group_address_is_multicast());

        let multicast = Igmp::v2_membership_report(Ipv4Addr::new(233, 252, 0, 42));
        assert_eq!(
            multicast.group_address_class(),
            IgmpGroupAddressClass::Multicast
        );
        assert_eq!(multicast.group_address_class_name(), "multicast");
        assert!(multicast.group_address_is_multicast());
    }

    #[test]
    fn igmp_group_address_non_multicast_override_is_preserved() {
        let non_multicast = Ipv4Addr::new(192, 0, 2, 42);
        let igmp = Igmp::v2_membership_report(non_multicast);

        assert_eq!(igmp.group_address_value(), non_multicast);
        assert_eq!(
            igmp.group_address_class(),
            IgmpGroupAddressClass::NonMulticast
        );
        assert_eq!(igmp.group_address_class_name(), "non-multicast");
        assert!(!igmp.group_address_is_multicast());

        let bytes = Packet::from_layer(igmp)
            .compile()
            .expect("compile IGMP with non-multicast group override");

        assert_eq!(&bytes.as_bytes()[4..8], &non_multicast.octets());
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
            &[
                IGMP_TYPE_EXPERIMENTAL_FIRST,
                0xaa,
                0x00,
                0x00,
                239,
                255,
                0,
                42
            ]
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
        let query = [IGMP_TYPE_MEMBERSHIP_QUERY, 200, 0x00, 0x00, 239, 1, 2, 3];
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
        assert_eq!(
            decoded_report.v2_max_response_time_state(),
            FieldState::User
        );

        assert_eq!(compile_layer(decoded_query), query);
        assert_eq!(compile_layer(decoded_report), report);
    }
}

#[cfg(test)]
mod igmp_v2_membership_report {
    use super::*;
    use crate::checksum::verify_internet_checksum;
    use crate::field::FieldState;
    use crate::packet::Packet;
    use crate::protocols::igmp::constants::{IGMP_DEFAULT_CODE, IGMP_TYPE_V2_MEMBERSHIP_REPORT};
    use crate::protocols::igmp::decode::decode;
    use crate::protocols::igmp::registry::IgmpTypeStatus;
    use crate::protocols::ip::v4::Ipv4;

    fn report_group() -> Ipv4Addr {
        Ipv4Addr::new(224, 0, 0, 251)
    }

    fn compile_layer(igmp: Igmp) -> Vec<u8> {
        Packet::from_layer(igmp)
            .compile()
            .expect("compile IGMPv2 membership report")
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn igmp_v2_membership_report_constructor_sets_report_fields() {
        let group = report_group();
        let igmp = Igmp::v2_membership_report(group);

        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_V2_MEMBERSHIP_REPORT);
        assert_eq!(igmp.igmp_type(), IgmpType::V2MembershipReport);
        assert_eq!(igmp.type_meta().name, "IGMPv2 Membership Report");
        assert_eq!(igmp.type_meta().status, IgmpTypeStatus::Assigned);
        assert_eq!(igmp.code_value(), IGMP_DEFAULT_CODE);
        assert_eq!(igmp.code_meta().name, "No registered code");
        assert_eq!(igmp.group_address_value(), group);
        assert_eq!(igmp.igmp_type_state(), FieldState::User);
        assert_eq!(igmp.code_state(), FieldState::User);
        assert_eq!(igmp.group_address_state(), FieldState::User);
        assert_eq!(igmp.checksum_state(), FieldState::Unset);
        assert_eq!(igmp.checksum_value(), None);
    }

    #[test]
    fn igmp_v2_membership_report_compiles_with_autofilled_checksum() {
        let group = report_group();
        let bytes = compile_layer(Igmp::v2_membership_report(group));

        assert_eq!(bytes.len(), IGMP_FIXED_HEADER_LEN);
        assert_eq!(bytes[0], IGMP_TYPE_V2_MEMBERSHIP_REPORT);
        assert_eq!(bytes[1], IGMP_DEFAULT_CODE);
        assert_eq!(&bytes[4..8], &group.octets());
        assert!(verify_internet_checksum(&bytes));
    }

    #[test]
    fn igmp_v2_membership_report_decodes_to_inspectable_fields() {
        let group = report_group();
        let bytes = compile_layer(Igmp::v2_membership_report(group));
        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let decoded = decode(&bytes).expect("decode IGMPv2 membership report");

        assert_eq!(decoded.igmp_type(), IgmpType::V2MembershipReport);
        assert_eq!(decoded.type_meta().name, "IGMPv2 Membership Report");
        assert_eq!(decoded.code_value(), IGMP_DEFAULT_CODE);
        assert_eq!(decoded.group_address_value(), group);
        assert_eq!(decoded.checksum_value(), Some(checksum));
        assert_eq!(decoded.igmp_type_state(), FieldState::User);
        assert_eq!(decoded.code_state(), FieldState::User);
        assert_eq!(decoded.checksum_state(), FieldState::User);
        assert_eq!(decoded.group_address_state(), FieldState::User);
        assert_eq!(compile_layer(decoded.clone()), bytes);

        let packet = Packet::from_layer(decoded);
        assert_eq!(
            packet.summary(),
            format!("Igmp(version=IGMPv2, type=0x16 (IGMPv2 Membership Report), code=0x00 (No registered code), group=224.0.0.251 (multicast), checksum=0x{checksum:04x}, checksum_status=valid)")
        );
        let show = packet.show();
        assert!(
            show.contains("type: 0x16 (IGMPv2 Membership Report)"),
            "{show}"
        );
        assert!(
            show.contains("group_address: 224.0.0.251 (multicast)"),
            "{show}"
        );
        assert!(
            show.contains(&format!("checksum: 0x{checksum:04x}")),
            "{show}"
        );
    }

    #[test]
    fn igmp_v2_membership_report_does_not_force_ipv4_destination_or_ttl() {
        let packet = Ipv4::new() / Igmp::v2_membership_report(report_group());
        let bytes = packet.compile().expect("compile IPv4 / IGMPv2 report");

        assert_eq!(bytes[8], 64);
        assert_eq!(&bytes[16..20], &Ipv4Addr::LOCALHOST.octets());
    }
}

#[cfg(test)]
mod igmp_v2_leave_group {
    use super::*;
    use crate::checksum::verify_internet_checksum;
    use crate::field::FieldState;
    use crate::packet::Packet;
    use crate::protocols::igmp::constants::{IGMP_DEFAULT_CODE, IGMP_TYPE_V2_LEAVE_GROUP};
    use crate::protocols::igmp::decode::decode;
    use crate::protocols::igmp::registry::IgmpTypeStatus;

    const DOC_GROUP: Ipv4Addr = Ipv4Addr::new(233, 252, 0, 17);
    const LEAVE_GROUP_FIXTURE: [u8; IGMP_FIXED_HEADER_LEN] = [
        IGMP_TYPE_V2_LEAVE_GROUP,
        IGMP_DEFAULT_CODE,
        0xfe,
        0xf1,
        233,
        252,
        0,
        17,
    ];

    fn compile_layer(igmp: Igmp) -> Vec<u8> {
        Packet::from_layer(igmp)
            .compile()
            .expect("compile IGMPv2 leave group")
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn igmp_v2_leave_group_constructor_sets_leave_fields() {
        let igmp = Igmp::v2_leave_group(DOC_GROUP);

        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_V2_LEAVE_GROUP);
        assert_eq!(igmp.igmp_type(), IgmpType::V2LeaveGroup);
        assert_eq!(igmp.type_meta().name, "IGMPv2 Leave Group");
        assert_eq!(igmp.type_meta().status, IgmpTypeStatus::Assigned);
        assert_eq!(igmp.code_value(), IGMP_DEFAULT_CODE);
        assert_eq!(igmp.code_meta().name, "No registered code");
        assert_eq!(igmp.group_address_value(), DOC_GROUP);
        assert_eq!(igmp.igmp_type_state(), FieldState::User);
        assert_eq!(igmp.code_state(), FieldState::User);
        assert_eq!(igmp.group_address_state(), FieldState::User);
        assert_eq!(igmp.checksum_state(), FieldState::Unset);
        assert_eq!(igmp.checksum_value(), None);
    }

    #[test]
    fn igmp_v2_leave_group_compiles_to_documentation_fixture() {
        let bytes = compile_layer(Igmp::v2_leave_group(DOC_GROUP));

        assert_eq!(bytes, LEAVE_GROUP_FIXTURE);
        assert!(verify_internet_checksum(&bytes));
    }

    #[test]
    fn igmp_v2_leave_group_decodes_to_inspectable_fields() {
        let checksum = u16::from_be_bytes([LEAVE_GROUP_FIXTURE[2], LEAVE_GROUP_FIXTURE[3]]);
        let decoded = decode(&LEAVE_GROUP_FIXTURE).expect("decode IGMPv2 leave group");

        assert_eq!(decoded.igmp_type(), IgmpType::V2LeaveGroup);
        assert_eq!(decoded.type_meta().name, "IGMPv2 Leave Group");
        assert_eq!(decoded.code_value(), IGMP_DEFAULT_CODE);
        assert_eq!(decoded.group_address_value(), DOC_GROUP);
        assert_eq!(decoded.checksum_value(), Some(checksum));
        assert_eq!(decoded.igmp_type_state(), FieldState::User);
        assert_eq!(decoded.code_state(), FieldState::User);
        assert_eq!(decoded.checksum_state(), FieldState::User);
        assert_eq!(decoded.group_address_state(), FieldState::User);
        assert_eq!(compile_layer(decoded.clone()), LEAVE_GROUP_FIXTURE);

        let packet = Packet::from_layer(decoded);
        assert_eq!(
            packet.summary(),
            "Igmp(version=IGMPv2, type=0x17 (IGMPv2 Leave Group), code=0x00 (No registered code), group=233.252.0.17 (multicast), checksum=0xfef1, checksum_status=valid)"
        );
        let show = packet.show();
        assert!(show.contains("type: 0x17 (IGMPv2 Leave Group)"), "{show}");
        assert!(show.contains("code: 0x00 (No registered code)"), "{show}");
        assert!(
            show.contains("group_address: 233.252.0.17 (multicast)"),
            "{show}"
        );
        assert!(
            show.contains(&format!("checksum: 0x{checksum:04x}")),
            "{show}"
        );
    }

    #[test]
    fn igmp_v2_leave_group_preserves_explicit_code_and_checksum() {
        let bytes = compile_layer(
            Igmp::v2_leave_group(DOC_GROUP)
                .with_code(0xaa)
                .checksum(0x1234),
        );

        assert_eq!(
            bytes.as_slice(),
            &[IGMP_TYPE_V2_LEAVE_GROUP, 0xaa, 0x12, 0x34, 233, 252, 0, 17]
        );
        assert!(!verify_internet_checksum(&bytes));
    }
}

#[cfg(test)]
mod igmp_mrd_builders {
    use super::*;
    use crate::checksum::verify_internet_checksum;
    use crate::field::FieldState;
    use crate::packet::{Packet, Raw};
    use crate::protocols::igmp::constants::{
        IGMP_MRD_ADVERTISEMENT_LEN, IGMP_MRD_DEFAULT_RESERVED, IGMP_MRD_SOLICITATION_LEN,
        IGMP_MRD_TERMINATION_LEN, IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT,
        IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION, IGMP_TYPE_MULTICAST_ROUTER_TERMINATION,
    };
    use crate::protocols::igmp::decode::{append_igmp_packet, decode};
    use crate::protocols::igmp::registry::IgmpTypeStatus;

    fn compile_layer(igmp: Igmp) -> crate::Result<Vec<u8>> {
        Ok(Packet::from_layer(igmp).compile()?.as_bytes().to_vec())
    }

    #[test]
    fn igmp_mrd_builders_advertisement_compiles_and_decodes() -> crate::Result<()> {
        let igmp = Igmp::mrd_advertisement(20, 125, 2);

        assert_eq!(igmp.igmp_type(), IgmpType::MulticastRouterAdvertisement);
        assert_eq!(
            igmp.igmp_type_value(),
            IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT
        );
        assert_eq!(igmp.type_meta().name, "Multicast Router Advertisement");
        assert_eq!(igmp.type_meta().status, IgmpTypeStatus::Assigned);
        assert_eq!(igmp.mrd_advertisement_interval_value(), 20);
        assert_eq!(igmp.mrd_query_interval_value(), 125);
        assert_eq!(igmp.mrd_robustness_variable_value(), 2);
        assert_eq!(igmp.igmp_type_state(), FieldState::User);
        assert_eq!(igmp.code_state(), FieldState::User);
        assert_eq!(igmp.group_address_state(), FieldState::User);
        assert_eq!(igmp.checksum_state(), FieldState::Unset);

        let bytes = compile_layer(igmp)?;

        assert_eq!(bytes.len(), IGMP_MRD_ADVERTISEMENT_LEN);
        assert_eq!(bytes[0], IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT);
        assert_eq!(bytes[1], 20);
        assert_eq!(&bytes[4..6], &125u16.to_be_bytes());
        assert_eq!(&bytes[6..8], &2u16.to_be_bytes());
        assert!(verify_internet_checksum(&bytes));

        let decoded = decode(&bytes)?;
        assert_eq!(decoded.igmp_type(), IgmpType::MulticastRouterAdvertisement);
        assert_eq!(decoded.mrd_advertisement_interval_value(), 20);
        assert_eq!(decoded.mrd_query_interval_value(), 125);
        assert_eq!(decoded.mrd_robustness_variable_value(), 2);
        assert_eq!(decoded.checksum_state(), FieldState::User);
        assert_eq!(decoded.group_address_state(), FieldState::User);
        assert_eq!(compile_layer(decoded)?, bytes);

        Ok(())
    }

    #[test]
    fn igmp_mrd_builders_solicitation_compiles_and_decodes() -> crate::Result<()> {
        let igmp = Igmp::mrd_solicitation();

        assert_eq!(igmp.igmp_type(), IgmpType::MulticastRouterSolicitation);
        assert_eq!(
            igmp.igmp_type_value(),
            IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION
        );
        assert_eq!(igmp.type_meta().name, "Multicast Router Solicitation");
        assert_eq!(igmp.type_meta().status, IgmpTypeStatus::Assigned);
        assert_eq!(igmp.mrd_reserved_value(), IGMP_MRD_DEFAULT_RESERVED);
        assert_eq!(igmp.igmp_type_state(), FieldState::User);
        assert_eq!(igmp.code_state(), FieldState::User);
        assert_eq!(igmp.group_address_state(), FieldState::Defaulted);

        let bytes = compile_layer(igmp)?;

        assert_eq!(bytes.len(), IGMP_MRD_SOLICITATION_LEN);
        assert_eq!(bytes[0], IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION);
        assert_eq!(bytes[1], IGMP_MRD_DEFAULT_RESERVED);
        assert!(verify_internet_checksum(&bytes));

        let decoded = decode(&bytes)?;
        assert_eq!(decoded.igmp_type(), IgmpType::MulticastRouterSolicitation);
        assert_eq!(decoded.mrd_reserved_value(), IGMP_MRD_DEFAULT_RESERVED);
        assert_eq!(decoded.group_address_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(decoded.group_address_state(), FieldState::Defaulted);
        assert_eq!(compile_layer(decoded)?, bytes);

        Ok(())
    }

    #[test]
    fn igmp_mrd_builders_termination_compiles_and_decodes() -> crate::Result<()> {
        let igmp = Igmp::mrd_termination();

        assert_eq!(igmp.igmp_type(), IgmpType::MulticastRouterTermination);
        assert_eq!(
            igmp.igmp_type_value(),
            IGMP_TYPE_MULTICAST_ROUTER_TERMINATION
        );
        assert_eq!(igmp.type_meta().name, "Multicast Router Termination");
        assert_eq!(igmp.type_meta().status, IgmpTypeStatus::Assigned);
        assert_eq!(igmp.mrd_reserved_value(), IGMP_MRD_DEFAULT_RESERVED);
        assert_eq!(igmp.igmp_type_state(), FieldState::User);
        assert_eq!(igmp.code_state(), FieldState::User);
        assert_eq!(igmp.group_address_state(), FieldState::Defaulted);

        let bytes = compile_layer(igmp)?;

        assert_eq!(bytes.len(), IGMP_MRD_TERMINATION_LEN);
        assert_eq!(bytes[0], IGMP_TYPE_MULTICAST_ROUTER_TERMINATION);
        assert_eq!(bytes[1], IGMP_MRD_DEFAULT_RESERVED);
        assert!(verify_internet_checksum(&bytes));

        let decoded = decode(&bytes)?;
        assert_eq!(decoded.igmp_type(), IgmpType::MulticastRouterTermination);
        assert_eq!(decoded.mrd_reserved_value(), IGMP_MRD_DEFAULT_RESERVED);
        assert_eq!(decoded.group_address_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(decoded.group_address_state(), FieldState::Defaulted);
        assert_eq!(compile_layer(decoded)?, bytes);

        Ok(())
    }

    #[test]
    fn igmp_mrd_builders_preserve_checksum_overrides_and_ignored_raw_tail() -> crate::Result<()> {
        for igmp in [
            Igmp::mrd_advertisement(20, 125, 2),
            Igmp::mrd_solicitation(),
            Igmp::mrd_termination(),
        ] {
            let bytes = compile_layer(igmp.checksum(0x1234))?;
            assert_eq!(&bytes[2..4], &0x1234u16.to_be_bytes());
            assert!(!verify_internet_checksum(&bytes));
        }

        let packet = Igmp::mrd_solicitation()
            .with_mrd_reserved(0xa5)
            .checksum(0x1234)
            / Raw::from_bytes([0xde, 0xad]);
        let bytes = packet.compile()?.as_bytes().to_vec();

        assert_eq!(
            bytes.as_slice(),
            &[
                IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION,
                0xa5,
                0x12,
                0x34,
                0xde,
                0xad,
            ]
        );

        let decoded = append_igmp_packet(Packet::new(), &bytes)?;
        let decoded_igmp = decoded.layer::<Igmp>().expect("decoded MRD solicitation");
        let raw = decoded.layer::<Raw>().expect("ignored MRD tail");

        assert_eq!(
            decoded_igmp.igmp_type(),
            IgmpType::MulticastRouterSolicitation
        );
        assert_eq!(decoded_igmp.mrd_reserved_value(), 0xa5);
        assert_eq!(decoded_igmp.checksum_value(), Some(0x1234));
        assert_eq!(raw.as_bytes(), &[0xde, 0xad]);
        assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());

        Ok(())
    }
}

#[cfg(test)]
mod igmp_v1_compatibility {
    use super::*;
    use crate::checksum::verify_internet_checksum;
    use crate::field::FieldState;
    use crate::packet::Packet;
    use crate::protocols::igmp::constants::{
        IGMP_QUERY_CODE_V1, IGMP_TYPE_MEMBERSHIP_QUERY, IGMP_TYPE_V1_MEMBERSHIP_REPORT,
    };
    use crate::protocols::igmp::decode::decode;
    use crate::protocols::igmp::registry::IgmpTypeStatus;

    const DOC_GROUP: Ipv4Addr = Ipv4Addr::new(233, 252, 0, 18);

    fn compile_layer(igmp: Igmp) -> Vec<u8> {
        Packet::from_layer(igmp)
            .compile()
            .expect("compile IGMPv1 compatibility case")
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn igmp_v1_compatibility_query_constructor_keeps_code_zero_as_version_one() {
        let igmp = Igmp::v1_membership_query();

        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
        assert_eq!(igmp.code_value(), IGMP_QUERY_CODE_V1);
        assert_eq!(igmp.max_response_code_value(), IGMP_QUERY_CODE_V1);
        assert_eq!(igmp.code_meta().name, "IGMP Version 1");
        assert_eq!(igmp.code_meta().status, IgmpTypeStatus::Assigned);
        assert_eq!(igmp.igmp_type_state(), FieldState::User);
        assert_eq!(igmp.code_state(), FieldState::User);
        assert_eq!(igmp.group_address_state(), FieldState::User);

        let bytes = compile_layer(igmp);
        assert_eq!(bytes[0], IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(bytes[1], IGMP_QUERY_CODE_V1);
        assert_eq!(&bytes[4..8], &Ipv4Addr::UNSPECIFIED.octets());
        assert!(verify_internet_checksum(&bytes));

        let decoded = decode(&bytes).expect("decode IGMPv1 query");
        assert_eq!(decoded.code_value(), IGMP_QUERY_CODE_V1);
        assert_eq!(decoded.code_meta().name, "IGMP Version 1");
        assert_eq!(decoded.code_state(), FieldState::User);
        assert_eq!(compile_layer(decoded), bytes);
    }

    #[test]
    fn igmp_v1_compatibility_distinguishes_nonzero_query_response_code() {
        let igmp = Igmp::membership_query().with_max_response_code(10);

        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(igmp.code_value(), 10);
        assert_eq!(igmp.max_response_code_value(), 10);
        assert_eq!(igmp.code_meta().name, "Max Response Time");
        assert_eq!(igmp.v2_max_response_time_tenths(), 10);
        assert_eq!(igmp.v2_max_response_time(), Duration::from_secs(1));

        let bytes = compile_layer(igmp);
        let decoded = decode(&bytes).expect("decode v2-or-later query");

        assert_eq!(bytes[0], IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(bytes[1], 10);
        assert_eq!(decoded.code_value(), 10);
        assert_eq!(decoded.code_meta().name, "Max Response Time");
        assert_eq!(decoded.v2_max_response_time_tenths(), 10);
        assert_eq!(compile_layer(decoded), bytes);
    }

    #[test]
    fn igmp_v1_compatibility_report_constructor_sets_v1_report_type() {
        let igmp = Igmp::v1_membership_report(DOC_GROUP);

        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_V1_MEMBERSHIP_REPORT);
        assert_eq!(igmp.igmp_type(), IgmpType::V1MembershipReport);
        assert_eq!(igmp.type_meta().name, "IGMPv1 Membership Report");
        assert_eq!(igmp.type_meta().status, IgmpTypeStatus::Assigned);
        assert_eq!(igmp.code_value(), IGMP_DEFAULT_CODE);
        assert_eq!(igmp.code_meta().name, "No registered code");
        assert_eq!(igmp.group_address_value(), DOC_GROUP);
        assert_eq!(igmp.igmp_type_state(), FieldState::User);
        assert_eq!(igmp.code_state(), FieldState::User);
        assert_eq!(igmp.group_address_state(), FieldState::User);

        let bytes = compile_layer(igmp);
        let decoded = decode(&bytes).expect("decode IGMPv1 report");

        assert_eq!(bytes[0], IGMP_TYPE_V1_MEMBERSHIP_REPORT);
        assert_eq!(bytes[1], IGMP_DEFAULT_CODE);
        assert_eq!(&bytes[4..8], &DOC_GROUP.octets());
        assert!(verify_internet_checksum(&bytes));
        assert_eq!(decoded.igmp_type(), IgmpType::V1MembershipReport);
        assert_eq!(decoded.group_address_value(), DOC_GROUP);
        assert_eq!(compile_layer(decoded), bytes);
    }
}
