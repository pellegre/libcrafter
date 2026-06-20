//! Public-surface baseline test for the IGMP layer.
//!
//! Pins that the bootstrap IGMP type, constants, and registry metadata are
//! reachable through `crafter::prelude::*` and stay inside the standard packet
//! abstraction. The test is fully offline and uses documentation address space.

use std::net::Ipv4Addr;

use crafter::prelude::*;

const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);
const DOC_REPORT_GROUP: Ipv4Addr = Ipv4Addr::new(233, 252, 0, 61);
const DOC_REPORT_SOURCE_A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 61);
const DOC_REPORT_SOURCE_B: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 61);
const IGMPV3_REPORT_DEST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 22);

#[test]
fn igmp_public_api_builds_via_prelude() -> crafter::Result<()> {
    let igmp = Igmp::membership_query()
        .with_max_response_code(10)
        .with_group_address(DOC_GROUP);

    assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
    assert_eq!(igmp.type_meta().status, IgmpTypeStatus::Assigned);
    assert_eq!(igmp.code_meta().status, IgmpTypeStatus::Assigned);
    assert_eq!(
        igmp_type(IGMP_TYPE_MEMBERSHIP_QUERY),
        IgmpType::MembershipQuery
    );
    assert_eq!(
        igmp_type_name(IGMP_TYPE_V2_MEMBERSHIP_REPORT),
        Some("IGMPv2 Membership Report")
    );
    assert_eq!(
        igmp_code_name(IGMP_TYPE_MEMBERSHIP_QUERY, IGMP_QUERY_CODE_V1),
        Some("IGMP Version 1")
    );
    assert_eq!(
        igmp_type_status(IGMP_TYPE_RESERVED),
        IgmpTypeStatus::Reserved
    );
    let _: IgmpTypeMeta = igmp_type_meta(IGMP_TYPE_MEMBERSHIP_QUERY);
    let _: IgmpCodeMeta = igmp_code_meta(IGMP_TYPE_MEMBERSHIP_QUERY, IGMP_QUERY_CODE_V1);

    let packet = Ipv4::new()
        .src(DOC_SRC)
        .dst(DOC_GROUP)
        .ipv4_protocol(Ipv4Protocol::Igmp)
        / igmp;
    let compiled = packet.compile()?;

    assert_eq!(IGMP_HEADER_LEN, IGMP_FIXED_HEADER_LEN);
    assert_eq!(compiled.as_bytes()[9], IPPROTO_IGMP);
    assert_eq!(compiled.as_bytes()[20], IGMP_TYPE_MEMBERSHIP_QUERY);
    assert_eq!(compiled.as_bytes()[21], 10);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let decoded_igmp = decoded.layer::<Igmp>().expect("decoded IGMP layer");
    assert_eq!(decoded_igmp.igmp_type(), IgmpType::MembershipQuery);
    assert_eq!(decoded_igmp.max_response_code_value(), 10);
    assert_eq!(decoded_igmp.group_address_value(), DOC_GROUP);

    Ok(())
}

#[test]
fn igmp_unknown_records_decode_roundtrip_and_show_public_api() -> crafter::Result<()> {
    let record = IgmpGroupRecord::raw(0xc8, DOC_REPORT_GROUP)
        .with_source_addresses(vec![DOC_REPORT_SOURCE_A, DOC_REPORT_SOURCE_B])
        .with_auxiliary_data([0xde, 0xad, 0xbe, 0xef]);
    let packet = Ipv4::new()
        .src(DOC_SRC)
        .dst(IGMPV3_REPORT_DEST)
        .ttl(1)
        .ipv4_protocol(Ipv4Protocol::Igmp)
        / Igmp::v3_membership_report()
        / IgmpReport::from_group_records(vec![record]);
    let bytes = packet.compile()?;

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
    let report = decoded.layer::<IgmpReport>().expect("decoded IGMPv3 report");
    let decoded_record = &report.group_records()[0];

    assert_eq!(decoded_record.record_type(), IgmpRecordType::Unknown(0xc8));
    assert_eq!(decoded_record.record_type_value(), 0xc8);
    assert_eq!(
        decoded_record.record_type_meta().status,
        IgmpRecordTypeStatus::Unassigned
    );
    assert_eq!(decoded_record.multicast_address(), DOC_REPORT_GROUP);
    assert_eq!(
        decoded_record.source_addresses(),
        &[DOC_REPORT_SOURCE_A, DOC_REPORT_SOURCE_B]
    );
    assert_eq!(decoded_record.auxiliary_data(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(
        decoded_record.compile()?,
        vec![
            0xc8, 0x01, 0x00, 0x02, 233, 252, 0, 61, 192, 0, 2, 61, 198, 51, 100, 61, 0xde,
            0xad, 0xbe, 0xef,
        ]
    );
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_bytes());

    let changed_record = decoded_record.clone().with_raw_record_type(0x07);
    let changed_bytes = changed_record.compile()?;
    let original_record_bytes = decoded_record.compile()?;
    assert_eq!(changed_bytes[0], 0x07);
    assert_eq!(&changed_bytes[1..], &original_record_bytes[1..]);
    assert_ne!(changed_bytes, original_record_bytes);

    let record_summary =
        "IgmpGroupRecord(type=Unknown(200), group=233.252.0.61, sources=2, aux_words=1, aux=4B)";
    assert_eq!(decoded_record.summary(), record_summary);
    let show = decoded.show();
    assert!(show.contains(&format!("record[0]: {record_summary}")), "{show}");
    assert!(show.contains("record[0].record_type: Unknown(200) (0xc8)"), "{show}");
    assert!(show.contains("record[0].number_of_sources: 2"), "{show}");
    assert!(
        show.contains("record[0].source_addresses: 192.0.2.61,198.51.100.61"),
        "{show}"
    );
    assert!(show.contains("record[0].auxiliary_data: de ad be ef"), "{show}");

    Ok(())
}

#[test]
fn igmp_unknown_records_report_tail_stays_raw_and_roundtrips() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(DOC_SRC)
        .dst(IGMPV3_REPORT_DEST)
        .ttl(1)
        .ipv4_protocol(Ipv4Protocol::Igmp)
        / Igmp::v3_membership_report()
        / IgmpReport::new()
        / Raw::from_bytes([0xfa, 0xce, 0xbe, 0xef]);
    let bytes = packet.compile()?;

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
    let raw = decoded.layer::<Raw>().expect("extra report payload");

    assert_eq!(raw.as_bytes(), &[0xfa, 0xce, 0xbe, 0xef]);
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_bytes());
    assert!(decoded.summary().contains("Raw(len=4)"));
    assert!(decoded.show().contains("fa ce be ef"));

    Ok(())
}
