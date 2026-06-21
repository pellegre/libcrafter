//! IGMP decode helpers.
//!
//! Later decode steps should type supported messages and preserve unsupported
//! IGMP payload bytes as raw data where possible.

use core::net::Ipv4Addr;

use crate::checksum::verify_internet_checksum;
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Packet, Raw};

use super::constants::{
    IGMP_FIXED_HEADER_LEN, IGMP_MRD_SOLICITATION_LEN, IGMP_MRD_TERMINATION_LEN,
    IGMP_TYPE_MEMBERSHIP_QUERY, IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT,
    IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION, IGMP_TYPE_MULTICAST_ROUTER_TERMINATION,
    IGMP_TYPE_V3_MEMBERSHIP_REPORT, IGMP_V3_GROUP_RECORD_HEADER_LEN, IGMP_V3_QUERY_MIN_LEN,
};
use super::extension::decode_extensions;
use super::message::{Igmp, IgmpChecksumStatus};
use super::query::IgmpQuery;
use super::record::IgmpGroupRecord;
use super::report::IgmpReport;

const IGMP_V3_REPORT_BODY_HEADER_LEN: usize = 4;

/// Decode the common IGMP fixed header into a typed layer.
#[cfg(test)]
pub(crate) fn decode(bytes: &[u8]) -> Result<Igmp> {
    let (igmp, _) = decode_igmp_parts(bytes)?;
    Ok(igmp)
}

/// Append a decoded IGMP packet to an existing packet stack.
///
/// This decoder recovers the fixed IGMP header, types source-backed bodies, and
/// preserves unsupported or extension bytes as [`Raw`] where the RFC format
/// permits them. A Membership Query with the IGMPv3 minimum length is decoded as
/// an IGMPv3 query body; a short declared source list is a structured error.
pub(crate) fn append_igmp_packet(mut packet: Packet, bytes: &[u8]) -> Result<Packet> {
    let (igmp, payload) = decode_igmp_parts(bytes)?;
    let is_v3_query = igmp.igmp_type_value() == IGMP_TYPE_MEMBERSHIP_QUERY
        && (bytes.len() >= IGMP_V3_QUERY_MIN_LEN || !payload.is_empty());
    let is_v3_report = igmp.igmp_type_value() == IGMP_TYPE_V3_MEMBERSHIP_REPORT;
    packet = packet.push_igmp(igmp);

    if is_v3_query {
        let (query, tail) = decode_v3_query(bytes)?;
        let has_extensions = query.extension_flag();
        packet = packet.push(query);
        if has_extensions {
            packet = append_igmp_extensions(packet, tail)?;
        } else if !tail.is_empty() {
            // RFC 9776 says extra Query octets are checksum-covered and ignored;
            // keeping them as Raw makes the bytes inspectable and roundtrippable.
            packet = packet.push_raw(Raw::from_bytes(tail));
        }
        return Ok(packet);
    }

    if is_v3_report {
        let (report, tail) = decode_v3_report(bytes)?;
        let has_extensions = report.extension_flag();
        packet = packet.push(report);
        if has_extensions {
            packet = append_igmp_extensions(packet, tail)?;
        } else if !tail.is_empty() {
            // RFC 9776 says extra Report octets are checksum-covered and ignored;
            // keeping them as Raw makes the bytes inspectable and roundtrippable.
            packet = packet.push_raw(Raw::from_bytes(tail));
        }
        return Ok(packet);
    }

    if !payload.is_empty() {
        packet = packet.push_raw(Raw::from_bytes(payload));
    }

    Ok(packet)
}

fn append_igmp_extensions(mut packet: Packet, tail: &[u8]) -> Result<Packet> {
    let extensions = decode_extensions(tail)?;
    if extensions.is_empty() {
        return Err(CrafterError::buffer_too_short(
            "igmp.extension.header",
            super::constants::IGMP_EXTENSION_HEADER_LEN,
            0,
        ));
    }

    for extension in extensions {
        packet = packet.push(extension);
    }

    Ok(packet)
}

fn decode_igmp_parts(bytes: &[u8]) -> Result<(Igmp, &[u8])> {
    let (header_context, header_len) = bytes
        .first()
        .copied()
        .map(igmp_header_shape_for_type)
        .unwrap_or(("igmp header", IGMP_FIXED_HEADER_LEN));
    if bytes.len() < header_len {
        return Err(CrafterError::buffer_too_short(
            header_context,
            header_len,
            bytes.len(),
        ));
    }

    let igmp = Igmp {
        igmp_type: Field::user(bytes[0]),
        code: Field::user(bytes[1]),
        checksum: Field::user(u16::from_be_bytes([bytes[2], bytes[3]])),
        group_address: if header_len >= IGMP_FIXED_HEADER_LEN {
            Field::user(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]))
        } else {
            Field::defaulted(Ipv4Addr::UNSPECIFIED)
        },
        checksum_status: if verify_internet_checksum(bytes) {
            IgmpChecksumStatus::Valid
        } else {
            IgmpChecksumStatus::Invalid
        },
    };

    Ok((igmp, &bytes[header_len..]))
}

fn igmp_header_shape_for_type(type_code: u8) -> (&'static str, usize) {
    match type_code {
        IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT => {
            ("igmp mrd advertisement", IGMP_FIXED_HEADER_LEN)
        }
        IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION => {
            ("igmp mrd solicitation", IGMP_MRD_SOLICITATION_LEN)
        }
        IGMP_TYPE_MULTICAST_ROUTER_TERMINATION => {
            ("igmp mrd termination", IGMP_MRD_TERMINATION_LEN)
        }
        _ => ("igmp header", IGMP_FIXED_HEADER_LEN),
    }
}

fn decode_v3_query(bytes: &[u8]) -> Result<(IgmpQuery, &[u8])> {
    if bytes.len() < IGMP_V3_QUERY_MIN_LEN {
        return Err(CrafterError::buffer_too_short(
            "igmp v3 query",
            IGMP_V3_QUERY_MIN_LEN,
            bytes.len(),
        ));
    }

    let flags_qrv = bytes[IGMP_FIXED_HEADER_LEN];
    let qqic = bytes[IGMP_FIXED_HEADER_LEN + 1];
    let number_of_sources = u16::from_be_bytes([
        bytes[IGMP_FIXED_HEADER_LEN + 2],
        bytes[IGMP_FIXED_HEADER_LEN + 3],
    ]);
    let sources_len = usize::from(number_of_sources) * 4;
    let sources_end = IGMP_V3_QUERY_MIN_LEN + sources_len;
    if bytes.len() < sources_end {
        return Err(CrafterError::buffer_too_short(
            "igmp v3 query source list",
            sources_end,
            bytes.len(),
        ));
    }

    let mut sources = Vec::with_capacity(usize::from(number_of_sources));
    let sources_bytes = &bytes[IGMP_V3_QUERY_MIN_LEN..sources_end];
    for source in sources_bytes.chunks_exact(4) {
        sources.push(Ipv4Addr::new(source[0], source[1], source[2], source[3]));
    }

    let query = IgmpQuery::new()
        .with_raw_flags_qrv(flags_qrv)
        .with_qqic(qqic)
        .with_number_of_sources(number_of_sources)
        .with_source_addresses(sources);

    Ok((query, &bytes[sources_end..]))
}

fn decode_v3_report(bytes: &[u8]) -> Result<(IgmpReport, &[u8])> {
    let report_min_len = IGMP_FIXED_HEADER_LEN + IGMP_V3_REPORT_BODY_HEADER_LEN;
    if bytes.len() < report_min_len {
        return Err(CrafterError::buffer_too_short(
            "igmp v3 report",
            report_min_len,
            bytes.len(),
        ));
    }

    let body = &bytes[IGMP_FIXED_HEADER_LEN..];
    let reserved_flags = u16::from_be_bytes([body[0], body[1]]);
    let number_of_group_records = u16::from_be_bytes([body[2], body[3]]);
    let mut records = Vec::with_capacity(usize::from(number_of_group_records));
    let mut tail = &body[IGMP_V3_REPORT_BODY_HEADER_LEN..];
    let mut record_offset = report_min_len;

    for _ in 0..number_of_group_records {
        if tail.len() < IGMP_V3_GROUP_RECORD_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "igmp v3 report group record",
                record_offset + IGMP_V3_GROUP_RECORD_HEADER_LEN,
                bytes.len(),
            ));
        }

        let available_before = tail.len();
        let (record, remaining) = IgmpGroupRecord::decode_with_tail(tail)?;
        let consumed = available_before - remaining.len();
        record_offset += consumed;
        tail = remaining;
        records.push(record);
    }

    let report = IgmpReport::new()
        .with_reserved_flags(reserved_flags)
        .with_number_of_group_records(number_of_group_records)
        .with_group_records(records);

    Ok((report, tail))
}

#[cfg(test)]
mod igmp_decode_fixed_header {
    use super::*;
    use crate::error::CrafterError;
    use crate::field::FieldState;
    use crate::protocols::igmp::constants::{
        IGMP_TYPE_DVMRP, IGMP_TYPE_MEMBERSHIP_QUERY, IGMP_TYPE_UNASSIGNED_FIRST,
        IGMP_TYPE_V2_MEMBERSHIP_REPORT,
    };
    use crate::protocols::igmp::registry::{IgmpType, IgmpTypeStatus};

    #[test]
    fn valid_query_bytes_decode_to_user_set_fields() {
        let bytes = [IGMP_TYPE_MEMBERSHIP_QUERY, 0x00, 0xee, 0xff, 0, 0, 0, 0];

        let igmp = decode(&bytes).expect("decode query fixed header");

        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
        assert_eq!(igmp.code_value(), 0x00);
        assert_eq!(igmp.checksum_value(), Some(0xeeff));
        assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(igmp.igmp_type_state(), FieldState::User);
        assert_eq!(igmp.code_state(), FieldState::User);
        assert_eq!(igmp.checksum_state(), FieldState::User);
        assert_eq!(igmp.group_address_state(), FieldState::User);
        assert_eq!(
            Packet::new()
                .push(igmp)
                .compile()
                .expect("roundtrip decoded query")
                .as_bytes(),
            &bytes
        );
    }

    #[test]
    fn valid_report_bytes_decode_to_user_set_fields() {
        let bytes = [
            IGMP_TYPE_V2_MEMBERSHIP_REPORT,
            0x00,
            0xab,
            0xcd,
            224,
            0,
            0,
            251,
        ];

        let decoded = append_igmp_packet(Packet::new(), &bytes).expect("decode report");
        let igmp = decoded.layer::<Igmp>().expect("typed IGMP header");

        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_V2_MEMBERSHIP_REPORT);
        assert_eq!(igmp.igmp_type(), IgmpType::V2MembershipReport);
        assert_eq!(igmp.code_value(), 0x00);
        assert_eq!(igmp.checksum_value(), Some(0xabcd));
        assert_eq!(igmp.group_address_value(), Ipv4Addr::new(224, 0, 0, 251));
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }

    #[test]
    fn unsupported_registered_type_preserves_raw_payload() {
        let bytes = [
            IGMP_TYPE_DVMRP,
            0x07,
            0x12,
            0x34,
            224,
            0,
            0,
            251,
            0xde,
            0xad,
            0xbe,
            0xef,
        ];

        let decoded = append_igmp_packet(Packet::new(), &bytes).expect("decode DVMRP as IGMP raw");
        let igmp = decoded.layer::<Igmp>().expect("typed IGMP header");
        let raw = decoded.layer::<Raw>().expect("raw unsupported body");

        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_DVMRP);
        assert_eq!(igmp.igmp_type(), IgmpType::Dvmrp);
        assert_eq!(igmp.type_meta().status, IgmpTypeStatus::UnsupportedAssigned);
        assert_eq!(igmp.code_value(), 0x07);
        assert_eq!(igmp.checksum_value(), Some(0x1234));
        assert_eq!(igmp.group_address_value(), Ipv4Addr::new(224, 0, 0, 251));
        assert_eq!(igmp.igmp_type_state(), FieldState::User);
        assert_eq!(igmp.code_state(), FieldState::User);
        assert_eq!(igmp.checksum_state(), FieldState::User);
        assert_eq!(igmp.group_address_state(), FieldState::User);
        assert_eq!(raw.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }

    #[test]
    fn unassigned_type_preserves_raw_payload() {
        let bytes = [
            IGMP_TYPE_UNASSIGNED_FIRST,
            0xaa,
            0x00,
            0x00,
            239,
            1,
            2,
            3,
            0x01,
            0x02,
            0x03,
        ];

        let decoded =
            append_igmp_packet(Packet::new(), &bytes).expect("decode unassigned IGMP as raw");
        let igmp = decoded.layer::<Igmp>().expect("typed IGMP header");
        let raw = decoded.layer::<Raw>().expect("raw unsupported body");

        assert_eq!(
            igmp.igmp_type(),
            IgmpType::Unassigned(IGMP_TYPE_UNASSIGNED_FIRST)
        );
        assert_eq!(igmp.type_meta().status, IgmpTypeStatus::Unassigned);
        assert_eq!(raw.as_bytes(), &[0x01, 0x02, 0x03]);
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }

    #[test]
    fn valid_fixed_header_without_payload_does_not_synthesize_raw() {
        let bytes = [IGMP_TYPE_MEMBERSHIP_QUERY, 0x00, 0xee, 0xff, 0, 0, 0, 0];

        let decoded = append_igmp_packet(Packet::new(), &bytes).expect("decode fixed header");

        assert!(decoded.layer::<Igmp>().is_some());
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }

    #[test]
    fn empty_input_returns_structured_error() {
        let err = decode(&[]).unwrap_err();

        assert_eq!(
            err,
            CrafterError::buffer_too_short("igmp header", IGMP_FIXED_HEADER_LEN, 0)
        );
    }

    #[test]
    fn short_header_returns_structured_error() {
        let err =
            append_igmp_packet(Packet::new(), &[IGMP_TYPE_MEMBERSHIP_QUERY, 0, 0]).unwrap_err();

        assert_eq!(
            err,
            CrafterError::buffer_too_short("igmp header", IGMP_FIXED_HEADER_LEN, 3)
        );
    }
}

#[cfg(test)]
mod igmp_v3_query_decode {
    use super::*;
    use crate::field::FieldState;
    use crate::protocols::igmp::constants::IGMP_TYPE_MEMBERSHIP_QUERY;

    fn doc_group() -> Ipv4Addr {
        Ipv4Addr::new(233, 252, 0, 34)
    }

    #[test]
    fn igmp_v3_query_decode_empty_source_list_into_typed_body() {
        let bytes = [
            IGMP_TYPE_MEMBERSHIP_QUERY,
            100,
            0x12,
            0x34,
            0,
            0,
            0,
            0,
            0x0b,
            125,
            0,
            0,
        ];

        let decoded = append_igmp_packet(Packet::new(), &bytes).expect("decode IGMPv3 query");
        let igmp = decoded.layer::<Igmp>().expect("typed IGMP header");
        let query = decoded.layer::<IgmpQuery>().expect("typed query body");

        assert_eq!(decoded.len(), 2);
        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(igmp.max_response_code_value(), 100);
        assert_eq!(igmp.checksum_value(), Some(0x1234));
        assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(query.raw_flags_qrv_value(), 0x0b);
        assert!(query.suppress_router_side_processing());
        assert_eq!(query.querier_robustness_variable(), 3);
        assert_eq!(query.qqic_value(), 125);
        assert_eq!(query.number_of_sources_value(), 0);
        assert_eq!(query.number_of_sources_state(), FieldState::User);
        assert!(query.source_addresses().is_empty());
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }

    #[test]
    fn igmp_v3_query_decode_source_addresses_into_typed_body() {
        let bytes = [
            IGMP_TYPE_MEMBERSHIP_QUERY,
            100,
            0xab,
            0xcd,
            233,
            252,
            0,
            34,
            0x08,
            0x7d,
            0,
            2,
            192,
            0,
            2,
            1,
            198,
            51,
            100,
            2,
        ];

        let decoded =
            append_igmp_packet(Packet::new(), &bytes).expect("decode IGMPv3 query sources");
        let igmp = decoded.layer::<Igmp>().expect("typed IGMP header");
        let query = decoded.layer::<IgmpQuery>().expect("typed query body");

        assert_eq!(decoded.len(), 2);
        assert_eq!(igmp.group_address_value(), doc_group());
        assert_eq!(query.raw_flags_qrv_value(), 0x08);
        assert!(!query.extension_flag());
        assert!(query.suppress_router_side_processing());
        assert_eq!(query.querier_robustness_variable(), 0);
        assert_eq!(query.qqic_value(), 0x7d);
        assert_eq!(query.number_of_sources_value(), 2);
        assert_eq!(
            query.source_addresses(),
            &[Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 2)]
        );
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }

    #[test]
    fn igmp_v3_query_decode_truncated_source_list_is_structured_error() {
        let bytes = [
            IGMP_TYPE_MEMBERSHIP_QUERY,
            100,
            0xab,
            0xcd,
            233,
            252,
            0,
            34,
            0x00,
            0x7d,
            0,
            2,
            192,
            0,
            2,
            1,
        ];

        let err = append_igmp_packet(Packet::new(), &bytes).expect_err("source list is short");

        assert_eq!(
            err,
            CrafterError::buffer_too_short("igmp v3 query source list", 20, 16)
        );
    }

    #[test]
    fn igmp_v3_query_decode_preserves_extra_query_octets_as_raw() {
        let bytes = [
            IGMP_TYPE_MEMBERSHIP_QUERY,
            100,
            0xab,
            0xcd,
            233,
            252,
            0,
            34,
            0x00,
            0x7d,
            0,
            1,
            192,
            0,
            2,
            1,
            0xde,
            0xad,
            0xbe,
            0xef,
        ];

        let decoded =
            append_igmp_packet(Packet::new(), &bytes).expect("decode IGMPv3 query with tail");
        let query = decoded.layer::<IgmpQuery>().expect("typed query body");
        let raw = decoded.layer::<Raw>().expect("extra query bytes");

        assert_eq!(decoded.len(), 3);
        assert_eq!(query.number_of_sources_value(), 1);
        assert_eq!(query.source_addresses(), &[Ipv4Addr::new(192, 0, 2, 1)]);
        assert_eq!(raw.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }
}

#[cfg(test)]
mod igmp_report_decode {
    use super::*;
    use crate::field::FieldState;
    use crate::protocols::igmp::record::{IgmpRecordType, IgmpRecordTypeStatus};

    fn report_bytes(reserved_flags: u16, count: u16, records: &[u8]) -> Vec<u8> {
        let mut bytes = vec![IGMP_TYPE_V3_MEMBERSHIP_REPORT, 0x00, 0x12, 0x34, 0, 0, 0, 0];
        bytes.extend_from_slice(&reserved_flags.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes.extend_from_slice(records);
        bytes
    }

    fn doc_group() -> Ipv4Addr {
        Ipv4Addr::new(233, 252, 0, 80)
    }

    fn doc_group_b() -> Ipv4Addr {
        Ipv4Addr::new(233, 252, 0, 81)
    }

    fn doc_source_a() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn doc_source_b() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn igmp_report_decode_empty_report_body() {
        let bytes = report_bytes(0xa55a, 0, &[]);

        let decoded = append_igmp_packet(Packet::new(), &bytes).expect("decode empty report");
        let igmp = decoded.layer::<Igmp>().expect("typed IGMP header");
        let report = decoded.layer::<IgmpReport>().expect("typed report body");

        assert_eq!(decoded.len(), 2);
        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_V3_MEMBERSHIP_REPORT);
        assert_eq!(igmp.code_value(), 0x00);
        assert_eq!(igmp.checksum_value(), Some(0x1234));
        assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(report.reserved_flags_value(), 0xa55a);
        assert_eq!(report.reserved_flags_state(), FieldState::User);
        assert_eq!(report.number_of_group_records_value(), 0);
        assert_eq!(report.number_of_group_records_state(), FieldState::User);
        assert!(report.group_records().is_empty());
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }

    #[test]
    fn igmp_report_decode_known_record() {
        let record = [0x01, 0x00, 0x00, 0x01, 233, 252, 0, 80, 192, 0, 2, 10];
        let bytes = report_bytes(0, 1, &record);

        let decoded = append_igmp_packet(Packet::new(), &bytes).expect("decode report record");
        let report = decoded.layer::<IgmpReport>().expect("typed report body");
        let decoded_record = &report.group_records()[0];

        assert_eq!(report.number_of_group_records_value(), 1);
        assert_eq!(decoded_record.record_type(), IgmpRecordType::ModeIsInclude);
        assert_eq!(decoded_record.auxiliary_data_len_value(), 0);
        assert_eq!(decoded_record.auxiliary_data_len_state(), FieldState::User);
        assert_eq!(decoded_record.number_of_sources_value(), 1);
        assert_eq!(decoded_record.number_of_sources_state(), FieldState::User);
        assert_eq!(decoded_record.multicast_address(), doc_group());
        assert_eq!(decoded_record.source_addresses(), &[doc_source_a()]);
        assert!(decoded_record.auxiliary_data().is_empty());
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }

    #[test]
    fn igmp_report_decode_multiple_records() {
        let records = [
            0x05, 0x00, 0x00, 0x02, 233, 252, 0, 80, 192, 0, 2, 10, 198, 51, 100, 20, 0x06, 0x00,
            0x00, 0x00, 233, 252, 0, 81,
        ];
        let bytes = report_bytes(0x0001, 2, &records);

        let decoded = append_igmp_packet(Packet::new(), &bytes).expect("decode report records");
        let report = decoded.layer::<IgmpReport>().expect("typed report body");

        assert_eq!(report.reserved_flags_value(), 0x0001);
        assert_eq!(report.number_of_group_records_value(), 2);
        assert_eq!(report.group_records().len(), 2);
        assert_eq!(
            report.group_records()[0].record_type(),
            IgmpRecordType::AllowNewSources
        );
        assert_eq!(
            report.group_records()[0].source_addresses(),
            &[doc_source_a(), doc_source_b()]
        );
        assert_eq!(
            report.group_records()[1].record_type(),
            IgmpRecordType::BlockOldSources
        );
        assert_eq!(report.group_records()[1].multicast_address(), doc_group_b());
        assert!(report.group_records()[1].source_addresses().is_empty());
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }

    #[test]
    fn igmp_report_decode_unknown_record_type() {
        let record = [0xc8, 0x00, 0x00, 0x00, 233, 252, 0, 80];
        let bytes = report_bytes(0, 1, &record);

        let decoded = append_igmp_packet(Packet::new(), &bytes).expect("decode unknown record");
        let report = decoded.layer::<IgmpReport>().expect("typed report body");
        let record = &report.group_records()[0];

        assert_eq!(record.record_type(), IgmpRecordType::Unknown(0xc8));
        assert_eq!(record.record_type_value(), 0xc8);
        assert_eq!(
            record.record_type_meta().status,
            IgmpRecordTypeStatus::Unassigned
        );
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);
    }

    #[test]
    fn igmp_report_decode_preserves_extra_report_octets_as_raw() {
        let mut bytes = report_bytes(0, 0, &[0xde, 0xad, 0xbe, 0xef]);

        let decoded = append_igmp_packet(Packet::new(), &bytes).expect("decode report tail");
        let report = decoded.layer::<IgmpReport>().expect("typed report body");
        let raw = decoded.layer::<Raw>().expect("extra report bytes");

        assert_eq!(decoded.len(), 3);
        assert_eq!(report.number_of_group_records_value(), 0);
        assert_eq!(raw.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decoded.compile().expect("roundtrip").as_bytes(), &bytes);

        bytes.truncate(IGMP_FIXED_HEADER_LEN + IGMP_V3_REPORT_BODY_HEADER_LEN);
        assert!(append_igmp_packet(Packet::new(), &bytes).is_ok());
    }

    #[test]
    fn igmp_report_decode_short_report_header_returns_structured_error() {
        let bytes = [
            IGMP_TYPE_V3_MEMBERSHIP_REPORT,
            0x00,
            0x12,
            0x34,
            0,
            0,
            0,
            0,
            0xaa,
            0xbb,
        ];

        let error = append_igmp_packet(Packet::new(), &bytes).expect_err("short report header");

        assert_eq!(
            error,
            CrafterError::buffer_too_short(
                "igmp v3 report",
                IGMP_FIXED_HEADER_LEN + IGMP_V3_REPORT_BODY_HEADER_LEN,
                bytes.len()
            )
        );
    }

    #[test]
    fn igmp_report_decode_truncated_record_header_returns_structured_error() {
        let bytes = report_bytes(0, 1, &[0x01, 0x00, 0x00]);

        let error = append_igmp_packet(Packet::new(), &bytes).expect_err("short record header");

        assert_eq!(
            error,
            CrafterError::buffer_too_short(
                "igmp v3 report group record",
                IGMP_FIXED_HEADER_LEN
                    + IGMP_V3_REPORT_BODY_HEADER_LEN
                    + IGMP_V3_GROUP_RECORD_HEADER_LEN,
                bytes.len()
            )
        );
    }

    #[test]
    fn igmp_report_decode_truncated_record_sources_uses_record_helper_error() {
        let record = [0x01, 0x00, 0x00, 0x02, 233, 252, 0, 80, 192, 0, 2, 10, 198];
        let bytes = report_bytes(0, 1, &record);

        let error = append_igmp_packet(Packet::new(), &bytes).expect_err("short source list");

        assert_eq!(
            error,
            CrafterError::buffer_too_short("igmp.group_record.source_addresses", 16, record.len())
        );
    }

    #[test]
    fn igmp_report_decode_truncated_record_auxiliary_uses_record_helper_error() {
        let record = [
            0x06, 0x02, 0x00, 0x01, 233, 252, 0, 80, 192, 0, 2, 10, 0xde, 0xad, 0xbe, 0xef, 0x00,
        ];
        let bytes = report_bytes(0, 1, &record);

        let error = append_igmp_packet(Packet::new(), &bytes).expect_err("short auxiliary data");

        assert_eq!(
            error,
            CrafterError::buffer_too_short("igmp.group_record.auxiliary_data", 20, record.len())
        );
    }

    #[test]
    fn igmp_report_decode_count_overrun_returns_structured_error() {
        let record = [0x01, 0x00, 0x00, 0x00, 233, 252, 0, 80];
        let bytes = report_bytes(0, 2, &record);

        let error = append_igmp_packet(Packet::new(), &bytes).expect_err("count overrun");

        assert_eq!(
            error,
            CrafterError::buffer_too_short(
                "igmp v3 report group record",
                IGMP_FIXED_HEADER_LEN
                    + IGMP_V3_REPORT_BODY_HEADER_LEN
                    + record.len()
                    + IGMP_V3_GROUP_RECORD_HEADER_LEN,
                bytes.len()
            )
        );
    }
}

#[cfg(test)]
mod igmp_extension_decode {
    use super::*;
    use crate::field::FieldState;
    use crate::protocols::igmp::extension::IgmpExtension;
    use crate::protocols::igmp::registry::IgmpExtensionType;

    fn query_bytes(flags_qrv: u8, tail: &[u8]) -> Vec<u8> {
        let mut bytes = vec![
            IGMP_TYPE_MEMBERSHIP_QUERY,
            100,
            0x12,
            0x34,
            233,
            252,
            0,
            90,
            flags_qrv,
            0x7d,
            0,
            0,
        ];
        bytes.extend_from_slice(tail);
        bytes
    }

    fn report_bytes(flags: u16, tail: &[u8]) -> Vec<u8> {
        let mut bytes = vec![IGMP_TYPE_V3_MEMBERSHIP_REPORT, 0, 0x12, 0x34, 0, 0, 0, 0];
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(tail);
        bytes
    }

    #[test]
    fn igmp_extension_decode_query_tlv_when_e_flag_is_set() -> crate::Result<()> {
        let tail = [0x00, 0x00, 0x00, 0x00];
        let bytes = query_bytes(0x80, &tail);

        let decoded = append_igmp_packet(Packet::new(), &bytes)?;
        let query = decoded.layer::<IgmpQuery>().expect("typed query body");
        let extension = decoded
            .layer::<IgmpExtension>()
            .expect("typed extension TLV");

        assert_eq!(decoded.len(), 3);
        assert!(query.extension_flag());
        assert_eq!(extension.extension_type(), IgmpExtensionType::Noop);
        assert_eq!(extension.extension_type_value(), 0);
        assert_eq!(extension.extension_length_value(), 0);
        assert_eq!(extension.extension_length_state(), FieldState::User);
        assert!(extension.value_bytes().is_empty());
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());

        Ok(())
    }

    #[test]
    fn igmp_extension_decode_report_preserves_unknown_extension_type() -> crate::Result<()> {
        let tail = [0x12, 0x34, 0x00, 0x03, 0xde, 0xad, 0xbe];
        let bytes = report_bytes(0x8000, &tail);

        let decoded = append_igmp_packet(Packet::new(), &bytes)?;
        let report = decoded.layer::<IgmpReport>().expect("typed report body");
        let extension = decoded
            .layer::<IgmpExtension>()
            .expect("typed extension TLV");

        assert_eq!(decoded.len(), 3);
        assert!(report.extension_flag());
        assert_eq!(
            extension.extension_type(),
            IgmpExtensionType::Unassigned(0x1234)
        );
        assert_eq!(extension.extension_type_value(), 0x1234);
        assert_eq!(extension.extension_length_value(), 3);
        assert_eq!(extension.extension_length_state(), FieldState::User);
        assert_eq!(extension.value_bytes(), &[0xde, 0xad, 0xbe]);
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());

        Ok(())
    }

    #[test]
    fn igmp_extension_decode_keeps_query_tail_raw_when_e_flag_is_clear() -> crate::Result<()> {
        let tail = [0x00, 0x00, 0x00, 0x00];
        let bytes = query_bytes(0x00, &tail);

        let decoded = append_igmp_packet(Packet::new(), &bytes)?;
        let raw = decoded.layer::<Raw>().expect("raw query tail");

        assert!(decoded.layer::<IgmpExtension>().is_none());
        assert_eq!(raw.as_bytes(), &tail);
        assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());

        Ok(())
    }

    #[test]
    fn igmp_extension_decode_truncated_query_header_is_structured_error() {
        let bytes = query_bytes(0x80, &[0x00, 0x01, 0x00]);

        let err = append_igmp_packet(Packet::new(), &bytes).expect_err("extension header is short");

        assert_eq!(
            err,
            CrafterError::buffer_too_short("igmp.extension.header", 4, 3)
        );
    }

    #[test]
    fn igmp_extension_decode_truncated_report_value_is_structured_error() {
        let bytes = report_bytes(0x8000, &[0x12, 0x34, 0x00, 0x04, 0xde, 0xad]);

        let err = append_igmp_packet(Packet::new(), &bytes).expect_err("extension value is short");

        assert_eq!(
            err,
            CrafterError::buffer_too_short("igmp.extension.value", 8, 6)
        );
    }
}
