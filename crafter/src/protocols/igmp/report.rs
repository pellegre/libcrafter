//! IGMP membership report model.
//!
//! The common IGMP fixed header remains the [`Igmp`](super::Igmp) layer. This
//! layer models the IGMPv3 report-specific body that follows it: Reserved/Flags,
//! Number of Group Records, and the ordered group-record vector.

use core::any::Any;
use core::ops::Div;

use crate::error::Result;
use crate::field::{Field, FieldState};
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

use super::constants::{IGMP_DEFAULT_GROUP_RECORD_COUNT, IGMP_DEFAULT_REPORT_FLAGS};
use super::record::IgmpGroupRecord;

const IGMP_V3_REPORT_BODY_MIN_LEN: usize = 4;

/// IGMPv3 Membership Report body fields after the common fixed header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgmpReport {
    /// Raw 16-bit Reserved/Flags field.
    reserved_flags: Field<u16>,
    /// Number of Group Records field. Unset values are derived from `records`.
    number_of_group_records: Field<u16>,
    /// Ordered Group Record vector.
    records: Vec<IgmpGroupRecord>,
}

impl IgmpReport {
    /// Create an empty IGMPv3 membership report body.
    pub fn new() -> Self {
        Self {
            reserved_flags: Field::defaulted(IGMP_DEFAULT_REPORT_FLAGS),
            number_of_group_records: Field::unset(),
            records: Vec::new(),
        }
    }

    /// Set the raw Reserved/Flags field, preserving every bit.
    pub fn with_reserved_flags(mut self, reserved_flags: u16) -> Self {
        self.reserved_flags.set_user(reserved_flags);
        self
    }

    /// Compatibility alias for the report Flags field.
    pub fn with_report_flags(self, report_flags: u16) -> Self {
        self.with_reserved_flags(report_flags)
    }

    /// Compatibility alias for the raw report Flags field.
    pub fn with_raw_flags(self, flags: u16) -> Self {
        self.with_reserved_flags(flags)
    }

    /// Set the raw Number of Group Records field.
    pub fn with_number_of_group_records(mut self, count: u16) -> Self {
        self.number_of_group_records.set_user(count);
        self
    }

    /// Compatibility alias for the raw Number of Group Records field.
    pub fn with_number_of_records(self, count: u16) -> Self {
        self.with_number_of_group_records(count)
    }

    /// Replace the group-record vector.
    pub fn with_group_records(mut self, records: impl Into<Vec<IgmpGroupRecord>>) -> Self {
        self.records = records.into();
        self
    }

    /// Append one group record.
    pub fn with_group_record(mut self, record: IgmpGroupRecord) -> Self {
        self.records.push(record);
        self
    }

    /// Raw Reserved/Flags field.
    pub fn reserved_flags_value(&self) -> u16 {
        value_or_copy(&self.reserved_flags, IGMP_DEFAULT_REPORT_FLAGS)
    }

    /// Compatibility alias for the report Flags field.
    pub fn report_flags_value(&self) -> u16 {
        self.reserved_flags_value()
    }

    /// Number of Group Records field value, derived from the vector unless explicit.
    pub fn number_of_group_records_value(&self) -> u16 {
        if self.records.is_empty() {
            return value_or_copy(
                &self.number_of_group_records,
                IGMP_DEFAULT_GROUP_RECORD_COUNT,
            );
        }
        value_or_copy(&self.number_of_group_records, self.records.len() as u16)
    }

    /// Compatibility alias for the Number of Group Records field.
    pub fn number_of_records_value(&self) -> u16 {
        self.number_of_group_records_value()
    }

    /// Group Record vector.
    pub fn group_records(&self) -> &[IgmpGroupRecord] {
        &self.records
    }

    /// Compatibility alias for the Group Record vector.
    pub fn records(&self) -> &[IgmpGroupRecord] {
        self.group_records()
    }

    /// Assignment state for the Reserved/Flags field.
    pub fn reserved_flags_state(&self) -> FieldState {
        self.reserved_flags.state()
    }

    /// Compatibility alias for the report Flags field state.
    pub fn report_flags_state(&self) -> FieldState {
        self.reserved_flags_state()
    }

    /// Assignment state for the Number of Group Records field.
    pub fn number_of_group_records_state(&self) -> FieldState {
        self.number_of_group_records.state()
    }

    /// Compatibility alias for the Number of Group Records field state.
    pub fn number_of_records_state(&self) -> FieldState {
        self.number_of_group_records_state()
    }
}

impl Default for IgmpReport {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IgmpReport {
    fn name(&self) -> &'static str {
        "IgmpReport"
    }

    fn summary(&self) -> String {
        format!(
            "IgmpReport(flags=0x{:04x}, records={})",
            self.reserved_flags_value(),
            self.number_of_group_records_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            (
                "reserved_flags",
                format!("0x{:04x}", self.reserved_flags_value()),
            ),
            (
                "number_of_group_records",
                self.number_of_group_records_value().to_string(),
            ),
            ("records", self.records.len().to_string()),
        ];
        for (index, record) in self.records.iter().enumerate() {
            fields.push((record_field_name(index), record.summary()));
        }
        fields
    }

    fn encoded_len(&self) -> usize {
        IGMP_V3_REPORT_BODY_MIN_LEN
            + self
                .records
                .iter()
                .map(IgmpGroupRecord::encoded_len)
                .sum::<usize>()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.reserved_flags_value().to_be_bytes());
        out.extend_from_slice(&self.number_of_group_records_value().to_be_bytes());
        for record in &self.records {
            record.encode_into(out)?;
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

impl<R> Div<R> for IgmpReport
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

fn record_field_name(index: usize) -> &'static str {
    const NAMES: [&str; 8] = [
        "record[0]",
        "record[1]",
        "record[2]",
        "record[3]",
        "record[4]",
        "record[5]",
        "record[6]",
        "record[7]",
    ];
    NAMES.get(index).copied().unwrap_or("record[*]")
}

#[cfg(test)]
mod igmp_report_model {
    use super::*;
    use crate::protocols::igmp::constants::{
        IGMP_FIXED_HEADER_LEN, IGMP_TYPE_V3_MEMBERSHIP_REPORT,
    };
    use crate::protocols::igmp::message::Igmp;
    use crate::protocols::igmp::record::IgmpRecordType;

    fn doc_group() -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::new(233, 252, 0, 90)
    }

    fn doc_source() -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::new(192, 0, 2, 90)
    }

    fn report_body_bytes(report: IgmpReport) -> crate::Result<Vec<u8>> {
        let bytes = (Igmp::v3_membership_report() / report).compile()?;
        Ok(bytes.as_bytes()[IGMP_FIXED_HEADER_LEN..].to_vec())
    }

    #[test]
    fn igmp_report_model_defaults_to_empty_report_body() -> crate::Result<()> {
        let report = IgmpReport::default();

        assert_eq!(report.reserved_flags_value(), 0);
        assert_eq!(report.report_flags_value(), 0);
        assert_eq!(report.number_of_group_records_value(), 0);
        assert_eq!(report.number_of_records_value(), 0);
        assert!(report.group_records().is_empty());
        assert!(report.records().is_empty());
        assert_eq!(report.reserved_flags_state(), FieldState::Defaulted);
        assert_eq!(report.report_flags_state(), FieldState::Defaulted);
        assert_eq!(report.number_of_group_records_state(), FieldState::Unset);
        assert_eq!(report.number_of_records_state(), FieldState::Unset);
        assert_eq!(report.encoded_len(), IGMP_V3_REPORT_BODY_MIN_LEN);
        assert_eq!(report_body_bytes(report)?, vec![0, 0, 0, 0]);

        Ok(())
    }

    #[test]
    fn igmp_report_model_preserves_explicit_reserved_flags() -> crate::Result<()> {
        let report = IgmpReport::new().with_reserved_flags(0xa55a);

        assert_eq!(report.reserved_flags_value(), 0xa55a);
        assert_eq!(report.report_flags_value(), 0xa55a);
        assert_eq!(report.reserved_flags_state(), FieldState::User);
        assert_eq!(report_body_bytes(report)?, vec![0xa5, 0x5a, 0, 0]);

        Ok(())
    }

    #[test]
    fn igmp_report_model_auto_fills_count_from_records() -> crate::Result<()> {
        let first = IgmpGroupRecord::mode_is_include(doc_group()).with_source_address(doc_source());
        let second = IgmpGroupRecord::new(IgmpRecordType::ModeIsExclude, doc_group());
        let report = IgmpReport::new().with_group_records(vec![first.clone(), second.clone()]);

        assert_eq!(report.number_of_group_records_value(), 2);
        assert_eq!(report.number_of_group_records_state(), FieldState::Unset);
        assert_eq!(report.group_records(), &[first.clone(), second.clone()]);
        assert_eq!(
            report.encoded_len(),
            IGMP_V3_REPORT_BODY_MIN_LEN + first.encoded_len() + second.encoded_len()
        );

        let body = report_body_bytes(report)?;
        assert_eq!(&body[..4], &[0, 0, 0, 2]);
        assert_eq!(
            &body[4..],
            &[
                0x01, 0x00, 0x00, 0x01, 233, 252, 0, 90, 192, 0, 2, 90, 0x02, 0x00, 0x00, 0x00,
                233, 252, 0, 90,
            ]
        );

        Ok(())
    }

    #[test]
    fn igmp_report_model_preserves_explicit_count_override() -> crate::Result<()> {
        let record = IgmpGroupRecord::allow_new_sources(doc_group());
        let report = IgmpReport::new()
            .with_group_record(record)
            .with_number_of_group_records(7);

        assert_eq!(report.number_of_group_records_value(), 7);
        assert_eq!(report.number_of_records_value(), 7);
        assert_eq!(report.number_of_group_records_state(), FieldState::User);

        let body = report_body_bytes(report)?;
        assert_eq!(&body[..4], &[0, 0, 0, 7]);

        Ok(())
    }

    #[test]
    fn igmp_report_model_summary_and_inspection_fields_are_stable() {
        let record = IgmpGroupRecord::block_old_sources(doc_group());
        let report = IgmpReport::new()
            .with_report_flags(0x8001)
            .with_group_record(record.clone());

        assert_eq!(report.summary(), "IgmpReport(flags=0x8001, records=1)");
        assert_eq!(
            report.inspection_fields(),
            vec![
                ("reserved_flags", "0x8001".to_string()),
                ("number_of_group_records", "1".to_string()),
                ("records", "1".to_string()),
                ("record[0]", record.summary()),
            ]
        );
    }

    #[test]
    fn igmp_report_model_composes_after_v3_membership_report_header() -> crate::Result<()> {
        let report = IgmpReport::new();
        let packet = Igmp::v3_membership_report() / report.clone();

        let igmp = packet.layer::<Igmp>().expect("IGMP header layer");
        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_V3_MEMBERSHIP_REPORT);
        assert_eq!(packet.layer::<IgmpReport>(), Some(&report));

        let bytes = packet.compile()?;
        assert_eq!(bytes.as_bytes()[0], IGMP_TYPE_V3_MEMBERSHIP_REPORT);
        assert_eq!(&bytes.as_bytes()[IGMP_FIXED_HEADER_LEN..], &[0, 0, 0, 0]);

        Ok(())
    }
}
