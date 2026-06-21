//! Bounded IGMPv3 encode/decode roundtrip properties.
//!
//! These tests keep generated packets offline with documentation-space IPv4
//! addresses while exercising variable source-list and report record-list
//! shapes through the public packet abstraction.

use std::net::Ipv4Addr;

use crafter::prelude::*;
use proptest::prelude::*;

const IGMPV3_REPORT_DESTINATION: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 22);

#[derive(Clone, Debug)]
struct ReportRecordInput {
    record_type: u8,
    multicast_address: Ipv4Addr,
    source_addresses: Vec<Ipv4Addr>,
    auxiliary_data: Vec<u8>,
}

fn ipv4_igmp(src: Ipv4Addr, dst: Ipv4Addr, id: u16) -> Ipv4 {
    Ipv4::new()
        .src(src)
        .dst(dst)
        .id(id)
        .ttl(1)
        .ipv4_protocol(Ipv4Protocol::Igmp)
}

fn doc_source_addr() -> impl Strategy<Value = Ipv4Addr> {
    prop_oneof![
        (1u8..=254).prop_map(|host| Ipv4Addr::new(192, 0, 2, host)),
        (1u8..=254).prop_map(|host| Ipv4Addr::new(198, 51, 100, host)),
        (1u8..=254).prop_map(|host| Ipv4Addr::new(203, 0, 113, host)),
    ]
}

fn doc_multicast_group() -> impl Strategy<Value = Ipv4Addr> {
    (1u8..=254).prop_map(|host| Ipv4Addr::new(233, 252, 0, host))
}

fn raw_tail() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=8)
}

fn query_flags_without_extensions() -> impl Strategy<Value = u8> {
    any::<u8>().prop_map(|flags| flags & !IGMP_V3_QUERY_FLAG_EXTENSION)
}

fn report_flags_without_extensions() -> impl Strategy<Value = u16> {
    any::<u16>().prop_map(|flags| flags & !IGMP_V3_REPORT_FLAG_EXTENSION)
}

fn auxiliary_data_words() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=8)
        .prop_filter("auxiliary data is encoded in 32-bit words", |bytes| {
            bytes.len() % 4 == 0
        })
}

fn report_record_input() -> impl Strategy<Value = ReportRecordInput> {
    (
        1u8..=6,
        doc_multicast_group(),
        prop::collection::vec(doc_source_addr(), 0..=3),
        auxiliary_data_words(),
    )
        .prop_map(
            |(record_type, multicast_address, source_addresses, auxiliary_data)| {
                ReportRecordInput {
                    record_type,
                    multicast_address,
                    source_addresses,
                    auxiliary_data,
                }
            },
        )
}

fn report_record(input: &ReportRecordInput) -> IgmpGroupRecord {
    IgmpGroupRecord::raw(input.record_type, input.multicast_address)
        .with_source_addresses(input.source_addresses.clone())
        .with_auxiliary_data(input.auxiliary_data.clone())
}

fn append_raw_tail(packet: Packet, tail: &[u8]) -> Packet {
    if tail.is_empty() {
        packet
    } else {
        packet / Raw::from_bytes(tail)
    }
}

fn assert_raw_tail(decoded: &Packet, expected: &[u8]) {
    if expected.is_empty() {
        assert!(
            decoded.layer::<Raw>().is_none(),
            "empty raw tail must not synthesize a Raw layer"
        );
    } else {
        let raw = decoded.layer::<Raw>().expect("decoded raw tail");
        assert_eq!(raw.as_bytes(), expected);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn igmp_v3_query_source_lists_roundtrip(
        src in doc_source_addr(),
        group in doc_multicast_group(),
        max_response_code in any::<u8>(),
        raw_flags_qrv in query_flags_without_extensions(),
        qqic in any::<u8>(),
        sources in prop::collection::vec(doc_source_addr(), 0..=4),
        tail in raw_tail(),
    ) {
        let query = IgmpQuery::group_and_source_specific(sources.clone())
            .with_raw_flags_qrv(raw_flags_qrv)
            .with_qqic(qqic);
        let packet = append_raw_tail(
            ipv4_igmp(src, group, 0x5301) / Igmp::v3_membership_query(max_response_code, group, query),
            &tail,
        );

        let compiled = packet.compile().expect("generated IGMPv3 query should compile");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())
            .expect("generated IGMPv3 query should decode");
        let recompiled = decoded.compile().expect("decoded IGMPv3 query should compile");
        prop_assert_eq!(recompiled.as_bytes(), compiled.as_bytes());

        let ipv4 = decoded.layer::<Ipv4>().expect("decoded IPv4 layer");
        prop_assert_eq!(ipv4.source(), src);
        prop_assert_eq!(ipv4.destination(), group);
        prop_assert_eq!(ipv4.protocol_value(), IPPROTO_IGMP);

        let igmp = decoded.layer::<Igmp>().expect("decoded IGMP layer");
        prop_assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
        prop_assert_eq!(igmp.code_value(), max_response_code);
        prop_assert_eq!(igmp.group_address_value(), group);
        prop_assert_eq!(igmp.checksum_state(), FieldState::User);

        let decoded_query = decoded.layer::<IgmpQuery>().expect("decoded IGMPv3 query body");
        prop_assert_eq!(decoded_query.raw_flags_qrv_value(), raw_flags_qrv);
        prop_assert_eq!(decoded_query.qqic_value(), qqic);
        prop_assert_eq!(decoded_query.number_of_sources_value(), sources.len() as u16);
        prop_assert_eq!(decoded_query.source_addresses(), sources.as_slice());
        prop_assert_eq!(decoded_query.raw_flags_qrv_state(), FieldState::User);
        prop_assert_eq!(decoded_query.qqic_state(), FieldState::User);
        prop_assert_eq!(decoded_query.number_of_sources_state(), FieldState::User);

        assert_raw_tail(&decoded, &tail);
    }

    #[test]
    fn igmp_v3_report_record_lists_roundtrip(
        src in doc_source_addr(),
        reserved_flags in report_flags_without_extensions(),
        records in prop::collection::vec(report_record_input(), 0..=3),
        tail in raw_tail(),
    ) {
        let group_records = records.iter().map(report_record).collect::<Vec<_>>();
        let report = IgmpReport::from_group_records(group_records).with_reserved_flags(reserved_flags);
        let packet = append_raw_tail(
            ipv4_igmp(src, IGMPV3_REPORT_DESTINATION, 0x5302)
                / Igmp::v3_membership_report()
                / report,
            &tail,
        );

        let compiled = packet.compile().expect("generated IGMPv3 report should compile");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())
            .expect("generated IGMPv3 report should decode");
        let recompiled = decoded.compile().expect("decoded IGMPv3 report should compile");
        prop_assert_eq!(recompiled.as_bytes(), compiled.as_bytes());

        let ipv4 = decoded.layer::<Ipv4>().expect("decoded IPv4 layer");
        prop_assert_eq!(ipv4.source(), src);
        prop_assert_eq!(ipv4.destination(), IGMPV3_REPORT_DESTINATION);
        prop_assert_eq!(ipv4.protocol_value(), IPPROTO_IGMP);

        let igmp = decoded.layer::<Igmp>().expect("decoded IGMP layer");
        prop_assert_eq!(igmp.igmp_type(), IgmpType::V3MembershipReport);
        prop_assert_eq!(igmp.code_value(), IGMP_DEFAULT_CODE);
        prop_assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);
        prop_assert_eq!(igmp.checksum_state(), FieldState::User);

        let decoded_report = decoded.layer::<IgmpReport>().expect("decoded IGMPv3 report body");
        prop_assert_eq!(decoded_report.reserved_flags_value(), reserved_flags);
        prop_assert_eq!(decoded_report.number_of_group_records_value(), records.len() as u16);
        prop_assert_eq!(decoded_report.group_records().len(), records.len());
        prop_assert_eq!(decoded_report.reserved_flags_state(), FieldState::User);
        prop_assert_eq!(decoded_report.number_of_group_records_state(), FieldState::User);

        for (decoded_record, expected) in decoded_report.group_records().iter().zip(records.iter()) {
            prop_assert_eq!(decoded_record.record_type_value(), expected.record_type);
            prop_assert_eq!(decoded_record.record_type(), IgmpRecordType::from_u8(expected.record_type));
            prop_assert_eq!(decoded_record.multicast_address(), expected.multicast_address);
            prop_assert_eq!(decoded_record.source_addresses(), expected.source_addresses.as_slice());
            prop_assert_eq!(
                decoded_record.number_of_sources_value(),
                expected.source_addresses.len() as u16
            );
            prop_assert_eq!(decoded_record.auxiliary_data(), expected.auxiliary_data.as_slice());
            prop_assert_eq!(
                decoded_record.auxiliary_data_len_value(),
                (expected.auxiliary_data.len() / 4) as u8
            );
            prop_assert_eq!(decoded_record.number_of_sources_state(), FieldState::User);
            prop_assert_eq!(decoded_record.auxiliary_data_len_state(), FieldState::User);
        }

        assert_raw_tail(&decoded, &tail);
    }
}
