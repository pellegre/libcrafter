//! Golden byte fixtures pinning bootstrap IPv4/IGMP behavior.
//!
//! The cases here cover the source-backed fixed-header surface currently
//! implemented for IGMP: a Membership Query and an IGMPv1 Membership Report.
//! They stay offline and use RFC 5771's multicast documentation block
//! (`233.252.0.0/24`) plus IPv4 documentation source addresses.

#[macro_use]
mod support;

use std::net::Ipv4Addr;

use crafter::prelude::*;
use crafter::wire::backend::pcap::{
    PcapLinkType, PcapReader, PcapTimestamp, PcapWriter, PcapWriterOptions, TimestampPrecision,
};

const DOC_SRC_QUERY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_SRC_REPORT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);
const DOC_MCAST_QUERY: Ipv4Addr = Ipv4Addr::new(233, 252, 0, 1);
const DOC_MCAST_REPORT: Ipv4Addr = Ipv4Addr::new(233, 252, 0, 42);

const QUERY_BYTES: &str = fixture_str!("bytes/ipv4-igmp-v1-query.hex");
const REPORT_BYTES: &str = fixture_str!("bytes/ipv4-igmp-v1-report.hex");
const QUERY_SUMMARY: &str = fixture_str!("summaries/ipv4-igmp-v1-query.summary.txt");
const REPORT_SUMMARY: &str = fixture_str!("summaries/ipv4-igmp-v1-report.summary.txt");
const QUERY_SHOW: &str = fixture_str!("summaries/ipv4-igmp-v1-query-show.summary.txt");
const REPORT_SHOW: &str = fixture_str!("summaries/ipv4-igmp-v1-report-show.summary.txt");
const IGMP_PCAP: &[u8] = fixture_bytes!("pcaps/raw-ipv4-igmp-bootstrap.pcap");

#[derive(Clone, Copy)]
struct IgmpGoldenCase {
    name: &'static str,
    build: fn() -> Packet,
    bytes_fixture: &'static str,
    summary_fixture: &'static str,
    show_fixture: &'static str,
    timestamp_micros: u32,
}

const CASES: &[IgmpGoldenCase] = &[
    IgmpGoldenCase {
        name: "ipv4-igmp-v1-query",
        build: build_query,
        bytes_fixture: QUERY_BYTES,
        summary_fixture: QUERY_SUMMARY,
        show_fixture: QUERY_SHOW,
        timestamp_micros: 1,
    },
    IgmpGoldenCase {
        name: "ipv4-igmp-v1-report",
        build: build_report,
        bytes_fixture: REPORT_BYTES,
        summary_fixture: REPORT_SUMMARY,
        show_fixture: REPORT_SHOW,
        timestamp_micros: 2,
    },
];

fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, id: u16) -> Ipv4 {
    Ipv4::new()
        .src(src)
        .dst(dst)
        .id(id)
        .ttl(1)
        .ipv4_protocol(Ipv4Protocol::Igmp)
}

fn build_query() -> Packet {
    ipv4(DOC_SRC_QUERY, DOC_MCAST_QUERY, 0x1701) / Igmp::membership_query()
}

fn build_report() -> Packet {
    ipv4(DOC_SRC_REPORT, DOC_MCAST_REPORT, 0x1702)
        / Igmp::v1_membership_report(DOC_MCAST_REPORT)
}

fn decode_hex(label: &str, text: &str) -> Vec<u8> {
    let mut compact = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        compact.extend(line.chars().filter(|ch| !ch.is_whitespace()));
    }

    assert!(
        compact.len() % 2 == 0,
        "hex fixture {label} must have even length"
    );
    compact
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = std::str::from_utf8(chunk).expect("hex fixture should be UTF-8");
            u8::from_str_radix(byte, 16).expect("hex fixture should contain valid hex")
        })
        .collect()
}

fn expected_bytes(case: IgmpGoldenCase) -> Vec<u8> {
    decode_hex(case.name, case.bytes_fixture)
}

fn assert_case(case: IgmpGoldenCase) -> crafter::Result<Packet> {
    let packet = (case.build)();
    let compiled = packet.compile()?;
    let expected = expected_bytes(case);

    maybe_dump(case.name, compiled.as_bytes(), None);
    assert_eq!(compiled.as_bytes(), expected.as_slice());
    assert_eq!(compiled.as_bytes()[9], IPPROTO_IGMP);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let recompiled = decoded.compile()?;
    assert_eq!(
        recompiled.as_bytes(),
        expected.as_slice(),
        "{} decode/recompile changed bytes",
        case.name
    );

    let igmp = decoded.layer::<Igmp>().expect("decoded IGMP layer");
    assert_eq!(igmp.checksum_state(), FieldState::User);

    maybe_dump(case.name, compiled.as_bytes(), Some(&decoded));
    assert_eq!(decoded.summary().trim_end(), case.summary_fixture.trim_end());
    assert_eq!(decoded.show().trim_end(), case.show_fixture.trim_end());

    Ok(decoded)
}

fn maybe_dump(name: &str, bytes: &[u8], packet: Option<&Packet>) {
    if std::env::var_os("CRAFTER_IGMP_GOLDEN_DUMP").is_none() {
        return;
    }

    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    println!("GOLDEN {name} = {hex}");
    if let Some(packet) = packet {
        println!("SUMMARY {name}:\n{}", packet.summary());
        println!("SHOW {name}:\n{}", packet.show());
    }
}

#[test]
fn igmp_golden_v1_membership_query() -> crafter::Result<()> {
    let decoded = assert_case(CASES[0])?;
    let igmp = decoded.layer::<Igmp>().expect("decoded IGMP query");

    assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
    assert_eq!(igmp.code_value(), IGMP_QUERY_CODE_V1);
    assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);

    Ok(())
}

#[test]
fn igmp_golden_v1_membership_report() -> crafter::Result<()> {
    let decoded = assert_case(CASES[1])?;
    let igmp = decoded.layer::<Igmp>().expect("decoded IGMP report");

    assert_eq!(igmp.igmp_type(), IgmpType::V1MembershipReport);
    assert_eq!(igmp.code_value(), IGMP_DEFAULT_CODE);
    assert_eq!(igmp.group_address_value(), DOC_MCAST_REPORT);

    Ok(())
}

#[test]
fn igmp_golden_raw_ip_pcap_fixture() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let records = PcapReader::from_reader(IGMP_PCAP)?.collect_records()?;
    assert_eq!(records.len(), CASES.len());

    let packets = PcapReader::from_reader(IGMP_PCAP)?.collect_packets()?;
    assert_eq!(packets.len(), CASES.len());

    for ((record, packet), case) in records.iter().zip(packets.iter()).zip(CASES) {
        let expected = expected_bytes(*case);
        let timestamp = PcapTimestamp::micros(17, case.timestamp_micros)?;

        assert_eq!(record.timestamp(), timestamp);
        assert_eq!(record.pcap_link_type(), PcapLinkType::RawIp);
        assert_eq!(record.data(), expected.as_slice());
        assert_eq!(packet.timestamp(), timestamp);
        assert_eq!(packet.pcap_link_type(), PcapLinkType::RawIp);
        assert_eq!(packet.data(), expected.as_slice());
        assert_eq!(packet.packet().compile()?.as_bytes(), expected.as_slice());
    }

    let mut rewritten = Vec::new();
    {
        let options =
            PcapWriterOptions::new(PcapLinkType::RawIp).precision(TimestampPrecision::Microseconds);
        let mut writer = PcapWriter::from_writer_with_options(&mut rewritten, options)?;
        for case in CASES {
            let packet = (case.build)();
            writer.write_packet_with_timestamp(
                &packet,
                PcapTimestamp::micros(17, case.timestamp_micros)?,
            )?;
        }
        writer.flush()?;
    }

    assert_eq!(rewritten, IGMP_PCAP);
    Ok(())
}
