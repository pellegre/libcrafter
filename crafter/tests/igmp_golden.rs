//! Golden byte fixtures pinning bootstrap IPv4/IGMP behavior.
//!
//! The cases here cover the source-backed fixed-header surface currently
//! implemented for IGMP: Membership Query, IGMPv1/v2 Membership Report,
//! IGMPv2 Leave Group, and IGMPv3 Membership Query bodies. They stay offline
//! and use RFC 5737 source addresses, RFC 5771 multicast documentation group
//! addresses, and the source-backed all-systems/all-routers destinations where
//! the packet shape calls for them.

#[macro_use]
mod support;

use std::net::Ipv4Addr;

use crafter::prelude::*;
use crafter::wire::backend::pcap::{
    PcapLinkType, PcapReader, PcapTimestamp, PcapWriter, PcapWriterOptions, TimestampPrecision,
};

const DOC_SRC_QUERY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_SRC_REPORT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);
const DOC_SRC_V2_QUERY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 30);
const DOC_SRC_V2_REPORT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 40);
const DOC_SRC_V2_LEAVE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
const DOC_SRC_V3_GENERAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 60);
const DOC_SRC_V3_GROUP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 61);
const DOC_SRC_V3_GROUP_SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 62);
const DOC_SRC_V3_TIMERS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 63);
const DOC_SRC_V3_RESERVED_FLAGS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 64);
const DOC_MCAST_QUERY: Ipv4Addr = Ipv4Addr::new(233, 252, 0, 1);
const DOC_MCAST_REPORT: Ipv4Addr = Ipv4Addr::new(233, 252, 0, 42);
const DOC_MCAST_V2_REPORT: Ipv4Addr = Ipv4Addr::new(233, 252, 0, 43);
const DOC_MCAST_V2_LEAVE: Ipv4Addr = Ipv4Addr::new(233, 252, 0, 17);
const DOC_MCAST_V3_GROUP: Ipv4Addr = Ipv4Addr::new(233, 252, 0, 60);
const DOC_MCAST_V3_GROUP_SOURCE: Ipv4Addr = Ipv4Addr::new(233, 252, 0, 61);
const DOC_MCAST_V3_RESERVED_FLAGS: Ipv4Addr = Ipv4Addr::new(233, 252, 0, 62);
const ALL_SYSTEMS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);
const ALL_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);
const V2_QUERY_MAX_RESPONSE_TENTHS: u8 = 100;
const V3_QUERY_MAX_RESPONSE_CODE: u8 = 100;
const V3_QUERY_TIMER_MAX_RESPONSE_CODE: u8 = 0x91;
const V3_QUERY_TIMER_MAX_RESPONSE_TENTHS: u32 = 272;
const V3_QUERY_TIMER_QQIC: u8 = 0xff;
const V3_QUERY_TIMER_INTERVAL_SECONDS: u32 = 31_744;
const V3_QUERY_GROUP_SOURCE_FLAGS_QRV: u8 = 0x0a;
const V3_QUERY_RESERVED_FLAGS_QRV: u8 = 0xf5;
const V3_QUERY_QQIC_LINEAR: u8 = 125;
const DOC_V3_SOURCE_A: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const DOC_V3_SOURCE_B: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 20);
const DOC_V3_SOURCE_RESERVED_FLAGS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 65);
const V3_GROUP_SOURCE_SOURCES: [Ipv4Addr; 2] = [DOC_V3_SOURCE_A, DOC_V3_SOURCE_B];
const V3_RESERVED_FLAGS_SOURCES: [Ipv4Addr; 1] = [DOC_V3_SOURCE_RESERVED_FLAGS];

const QUERY_BYTES: &str = fixture_str!("bytes/ipv4-igmp-v1-query.hex");
const REPORT_BYTES: &str = fixture_str!("bytes/ipv4-igmp-v1-report.hex");
const V2_QUERY_BYTES: &str = fixture_str!("bytes/ipv4-igmp-v2-query.hex");
const V2_REPORT_BYTES: &str = fixture_str!("bytes/ipv4-igmp-v2-report.hex");
const V2_LEAVE_BYTES: &str = fixture_str!("bytes/ipv4-igmp-v2-leave.hex");
const QUERY_SUMMARY: &str = fixture_str!("summaries/ipv4-igmp-v1-query.summary.txt");
const REPORT_SUMMARY: &str = fixture_str!("summaries/ipv4-igmp-v1-report.summary.txt");
const V2_QUERY_SUMMARY: &str = fixture_str!("summaries/ipv4-igmp-v2-query.summary.txt");
const V2_REPORT_SUMMARY: &str = fixture_str!("summaries/ipv4-igmp-v2-report.summary.txt");
const V2_LEAVE_SUMMARY: &str = fixture_str!("summaries/ipv4-igmp-v2-leave.summary.txt");
const QUERY_SHOW: &str = fixture_str!("summaries/ipv4-igmp-v1-query-show.summary.txt");
const REPORT_SHOW: &str = fixture_str!("summaries/ipv4-igmp-v1-report-show.summary.txt");
const V2_QUERY_SHOW: &str = fixture_str!("summaries/ipv4-igmp-v2-query-show.summary.txt");
const V2_REPORT_SHOW: &str = fixture_str!("summaries/ipv4-igmp-v2-report-show.summary.txt");
const V2_LEAVE_SHOW: &str = fixture_str!("summaries/ipv4-igmp-v2-leave-show.summary.txt");
const IGMP_PCAP: &[u8] = fixture_bytes!("pcaps/raw-ipv4-igmp-bootstrap.pcap");

const V3_GENERAL_QUERY_BYTES: &str = "\
45 00 00 20 17 06 00 00 01 02 00 99 c0 00 02 3c e0 00 00 01
11 64 ee 9b 00 00 00 00 00 00 00 00";
const V3_GROUP_QUERY_BYTES: &str = "\
45 00 00 20 17 07 00 00 01 02 f6 5f c0 00 02 3d e9 fc 00 3c
11 0a 04 bd e9 fc 00 3c 00 00 00 00";
const V3_GROUP_SOURCE_QUERY_BYTES: &str = "\
45 00 00 28 17 08 00 00 01 02 f6 54 c0 00 02 3e e9 fc 00 3d
11 7d 93 76 e9 fc 00 3d 0a 7d 00 02 c6 33 64 0a cb 00 71 14";
const V3_TIMER_QUERY_BYTES: &str = "\
45 00 00 20 17 09 00 00 01 02 00 93 c0 00 02 3f e0 00 00 01
11 91 eb 6f 00 00 00 00 02 ff 00 00";
const V3_RESERVED_FLAGS_QUERY_BYTES: &str = "\
45 00 00 24 17 0a 00 00 01 02 f6 53 c0 00 02 40 e9 fc 00 3e
11 64 4c a0 e9 fc 00 3e f5 7d 00 01 c0 00 02 41";

const V3_GENERAL_QUERY_SUMMARY: &str = "Ipv4(src=192.0.2.60, dst=224.0.0.1, proto=igmp(2)) / Igmp(type=IGMP Membership Query, code=Max Response Time, group=0.0.0.0) / IgmpQuery(flags=0x00, s=false, qrv=0, qqic=0, sources=0)";
const V3_GROUP_QUERY_SUMMARY: &str = "Ipv4(src=192.0.2.61, dst=233.252.0.60, proto=igmp(2)) / Igmp(type=IGMP Membership Query, code=Max Response Time, group=233.252.0.60) / IgmpQuery(flags=0x00, s=false, qrv=0, qqic=0, sources=0)";
const V3_GROUP_SOURCE_QUERY_SUMMARY: &str = "Ipv4(src=192.0.2.62, dst=233.252.0.61, proto=igmp(2)) / Igmp(type=IGMP Membership Query, code=Max Response Time, group=233.252.0.61) / IgmpQuery(flags=0x00, s=true, qrv=2, qqic=125, sources=2)";
const V3_TIMER_QUERY_SUMMARY: &str = "Ipv4(src=192.0.2.63, dst=224.0.0.1, proto=igmp(2)) / Igmp(type=IGMP Membership Query, code=Max Response Time, group=0.0.0.0) / IgmpQuery(flags=0x00, s=false, qrv=2, qqic=255, sources=0)";
const V3_RESERVED_FLAGS_QUERY_SUMMARY: &str = "Ipv4(src=192.0.2.64, dst=233.252.0.62, proto=igmp(2)) / Igmp(type=IGMP Membership Query, code=Max Response Time, group=233.252.0.62) / IgmpQuery(flags=0xf0, s=false, qrv=5, qqic=125, sources=1)";

const V3_GENERAL_QUERY_SHOW: &str = "\
Packet(len=32, layers=3)
  [0] Ipv4
      version: 4
      ihl: 5
      tos: 0
      dscp: 0
      ecn: Not-ECT
      total_length: 32
      id: 0x1706
      flags: none
      fragment_offset: 0
      ttl: 1
      protocol: igmp(2)
      checksum: 0x0099
      checksum_status: valid
      src: 192.0.2.60
      dst: 224.0.0.1
      option_count: 0
      options: 
  [1] Igmp
      type: IGMP Membership Query (0x11)
      code: Max Response Time (0x64)
      checksum: 0xee9b
      group_address: 0.0.0.0
      length: 8
  [2] IgmpQuery
      flags_s_qrv: 0x00
      query_flags: 0x00
      extension_flag: false
      suppress_router_side_processing: false
      querier_robustness_variable: 0
      qqic: 0
      number_of_sources: 0
      source_addresses: ";
const V3_GROUP_QUERY_SHOW: &str = "\
Packet(len=32, layers=3)
  [0] Ipv4
      version: 4
      ihl: 5
      tos: 0
      dscp: 0
      ecn: Not-ECT
      total_length: 32
      id: 0x1707
      flags: none
      fragment_offset: 0
      ttl: 1
      protocol: igmp(2)
      checksum: 0xf65f
      checksum_status: valid
      src: 192.0.2.61
      dst: 233.252.0.60
      option_count: 0
      options: 
  [1] Igmp
      type: IGMP Membership Query (0x11)
      code: Max Response Time (0x0a)
      checksum: 0x04bd
      group_address: 233.252.0.60
      length: 8
  [2] IgmpQuery
      flags_s_qrv: 0x00
      query_flags: 0x00
      extension_flag: false
      suppress_router_side_processing: false
      querier_robustness_variable: 0
      qqic: 0
      number_of_sources: 0
      source_addresses: ";
const V3_GROUP_SOURCE_QUERY_SHOW: &str = "\
Packet(len=40, layers=3)
  [0] Ipv4
      version: 4
      ihl: 5
      tos: 0
      dscp: 0
      ecn: Not-ECT
      total_length: 40
      id: 0x1708
      flags: none
      fragment_offset: 0
      ttl: 1
      protocol: igmp(2)
      checksum: 0xf654
      checksum_status: valid
      src: 192.0.2.62
      dst: 233.252.0.61
      option_count: 0
      options: 
  [1] Igmp
      type: IGMP Membership Query (0x11)
      code: Max Response Time (0x7d)
      checksum: 0x9376
      group_address: 233.252.0.61
      length: 8
  [2] IgmpQuery
      flags_s_qrv: 0x0a
      query_flags: 0x00
      extension_flag: false
      suppress_router_side_processing: true
      querier_robustness_variable: 2
      qqic: 125
      number_of_sources: 2
      source_addresses: 198.51.100.10,203.0.113.20";
const V3_TIMER_QUERY_SHOW: &str = "\
Packet(len=32, layers=3)
  [0] Ipv4
      version: 4
      ihl: 5
      tos: 0
      dscp: 0
      ecn: Not-ECT
      total_length: 32
      id: 0x1709
      flags: none
      fragment_offset: 0
      ttl: 1
      protocol: igmp(2)
      checksum: 0x0093
      checksum_status: valid
      src: 192.0.2.63
      dst: 224.0.0.1
      option_count: 0
      options: 
  [1] Igmp
      type: IGMP Membership Query (0x11)
      code: Max Response Time (0x91)
      checksum: 0xeb6f
      group_address: 0.0.0.0
      length: 8
  [2] IgmpQuery
      flags_s_qrv: 0x02
      query_flags: 0x00
      extension_flag: false
      suppress_router_side_processing: false
      querier_robustness_variable: 2
      qqic: 255
      number_of_sources: 0
      source_addresses: ";
const V3_RESERVED_FLAGS_QUERY_SHOW: &str = "\
Packet(len=36, layers=3)
  [0] Ipv4
      version: 4
      ihl: 5
      tos: 0
      dscp: 0
      ecn: Not-ECT
      total_length: 36
      id: 0x170a
      flags: none
      fragment_offset: 0
      ttl: 1
      protocol: igmp(2)
      checksum: 0xf653
      checksum_status: valid
      src: 192.0.2.64
      dst: 233.252.0.62
      option_count: 0
      options: 
  [1] Igmp
      type: IGMP Membership Query (0x11)
      code: Max Response Time (0x64)
      checksum: 0x4ca0
      group_address: 233.252.0.62
      length: 8
  [2] IgmpQuery
      flags_s_qrv: 0xf5
      query_flags: 0xf0
      extension_flag: true
      suppress_router_side_processing: false
      querier_robustness_variable: 5
      qqic: 125
      number_of_sources: 1
      source_addresses: 192.0.2.65";

#[derive(Clone, Copy)]
struct IgmpGoldenCase {
    name: &'static str,
    build: fn() -> Packet,
    bytes_fixture: &'static str,
    summary_fixture: &'static str,
    show_fixture: &'static str,
    timestamp_micros: u32,
}

#[derive(Clone, Copy)]
struct IgmpV3QueryGoldenCase {
    name: &'static str,
    build: fn() -> Packet,
    bytes_fixture: &'static str,
    summary_fixture: &'static str,
    show_fixture: &'static str,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    group_address: Ipv4Addr,
    max_response_code: u8,
    max_response_tenths: u32,
    checksum: u16,
    raw_flags_qrv: u8,
    query_flags: u8,
    suppress: bool,
    qrv: u8,
    qqic: u8,
    query_interval_seconds: u32,
    sources: &'static [Ipv4Addr],
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
    IgmpGoldenCase {
        name: "ipv4-igmp-v2-query",
        build: build_v2_query,
        bytes_fixture: V2_QUERY_BYTES,
        summary_fixture: V2_QUERY_SUMMARY,
        show_fixture: V2_QUERY_SHOW,
        timestamp_micros: 3,
    },
    IgmpGoldenCase {
        name: "ipv4-igmp-v2-report",
        build: build_v2_report,
        bytes_fixture: V2_REPORT_BYTES,
        summary_fixture: V2_REPORT_SUMMARY,
        show_fixture: V2_REPORT_SHOW,
        timestamp_micros: 4,
    },
    IgmpGoldenCase {
        name: "ipv4-igmp-v2-leave",
        build: build_v2_leave,
        bytes_fixture: V2_LEAVE_BYTES,
        summary_fixture: V2_LEAVE_SUMMARY,
        show_fixture: V2_LEAVE_SHOW,
        timestamp_micros: 5,
    },
];

const V3_QUERY_CASES: &[IgmpV3QueryGoldenCase] = &[
    IgmpV3QueryGoldenCase {
        name: "ipv4-igmp-v3-general-query",
        build: build_v3_general_query,
        bytes_fixture: V3_GENERAL_QUERY_BYTES,
        summary_fixture: V3_GENERAL_QUERY_SUMMARY,
        show_fixture: V3_GENERAL_QUERY_SHOW,
        source: DOC_SRC_V3_GENERAL,
        destination: ALL_SYSTEMS,
        group_address: Ipv4Addr::UNSPECIFIED,
        max_response_code: V3_QUERY_MAX_RESPONSE_CODE,
        max_response_tenths: V3_QUERY_MAX_RESPONSE_CODE as u32,
        checksum: 0xee9b,
        raw_flags_qrv: 0x00,
        query_flags: 0x00,
        suppress: false,
        qrv: 0,
        qqic: 0,
        query_interval_seconds: 0,
        sources: &[],
    },
    IgmpV3QueryGoldenCase {
        name: "ipv4-igmp-v3-group-query",
        build: build_v3_group_query,
        bytes_fixture: V3_GROUP_QUERY_BYTES,
        summary_fixture: V3_GROUP_QUERY_SUMMARY,
        show_fixture: V3_GROUP_QUERY_SHOW,
        source: DOC_SRC_V3_GROUP,
        destination: DOC_MCAST_V3_GROUP,
        group_address: DOC_MCAST_V3_GROUP,
        max_response_code: 10,
        max_response_tenths: 10,
        checksum: 0x04bd,
        raw_flags_qrv: 0x00,
        query_flags: 0x00,
        suppress: false,
        qrv: 0,
        qqic: 0,
        query_interval_seconds: 0,
        sources: &[],
    },
    IgmpV3QueryGoldenCase {
        name: "ipv4-igmp-v3-group-source-query",
        build: build_v3_group_source_query,
        bytes_fixture: V3_GROUP_SOURCE_QUERY_BYTES,
        summary_fixture: V3_GROUP_SOURCE_QUERY_SUMMARY,
        show_fixture: V3_GROUP_SOURCE_QUERY_SHOW,
        source: DOC_SRC_V3_GROUP_SOURCE,
        destination: DOC_MCAST_V3_GROUP_SOURCE,
        group_address: DOC_MCAST_V3_GROUP_SOURCE,
        max_response_code: V3_QUERY_QQIC_LINEAR,
        max_response_tenths: V3_QUERY_QQIC_LINEAR as u32,
        checksum: 0x9376,
        raw_flags_qrv: V3_QUERY_GROUP_SOURCE_FLAGS_QRV,
        query_flags: 0x00,
        suppress: true,
        qrv: 2,
        qqic: V3_QUERY_QQIC_LINEAR,
        query_interval_seconds: V3_QUERY_QQIC_LINEAR as u32,
        sources: &V3_GROUP_SOURCE_SOURCES,
    },
    IgmpV3QueryGoldenCase {
        name: "ipv4-igmp-v3-explicit-timer-query",
        build: build_v3_timer_query,
        bytes_fixture: V3_TIMER_QUERY_BYTES,
        summary_fixture: V3_TIMER_QUERY_SUMMARY,
        show_fixture: V3_TIMER_QUERY_SHOW,
        source: DOC_SRC_V3_TIMERS,
        destination: ALL_SYSTEMS,
        group_address: Ipv4Addr::UNSPECIFIED,
        max_response_code: V3_QUERY_TIMER_MAX_RESPONSE_CODE,
        max_response_tenths: V3_QUERY_TIMER_MAX_RESPONSE_TENTHS,
        checksum: 0xeb6f,
        raw_flags_qrv: 0x02,
        query_flags: 0x00,
        suppress: false,
        qrv: 2,
        qqic: V3_QUERY_TIMER_QQIC,
        query_interval_seconds: V3_QUERY_TIMER_INTERVAL_SECONDS,
        sources: &[],
    },
    IgmpV3QueryGoldenCase {
        name: "ipv4-igmp-v3-reserved-flags-query",
        build: build_v3_reserved_flags_query,
        bytes_fixture: V3_RESERVED_FLAGS_QUERY_BYTES,
        summary_fixture: V3_RESERVED_FLAGS_QUERY_SUMMARY,
        show_fixture: V3_RESERVED_FLAGS_QUERY_SHOW,
        source: DOC_SRC_V3_RESERVED_FLAGS,
        destination: DOC_MCAST_V3_RESERVED_FLAGS,
        group_address: DOC_MCAST_V3_RESERVED_FLAGS,
        max_response_code: V3_QUERY_MAX_RESPONSE_CODE,
        max_response_tenths: V3_QUERY_MAX_RESPONSE_CODE as u32,
        checksum: 0x4ca0,
        raw_flags_qrv: V3_QUERY_RESERVED_FLAGS_QRV,
        query_flags: 0xf0,
        suppress: false,
        qrv: 5,
        qqic: V3_QUERY_QQIC_LINEAR,
        query_interval_seconds: V3_QUERY_QQIC_LINEAR as u32,
        sources: &V3_RESERVED_FLAGS_SOURCES,
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
    ipv4(DOC_SRC_REPORT, DOC_MCAST_REPORT, 0x1702) / Igmp::v1_membership_report(DOC_MCAST_REPORT)
}

fn build_v2_query() -> Packet {
    ipv4(DOC_SRC_V2_QUERY, ALL_SYSTEMS, 0x1703)
        / Igmp::membership_query().with_v2_max_response_time_tenths(V2_QUERY_MAX_RESPONSE_TENTHS)
}

fn build_v2_report() -> Packet {
    ipv4(DOC_SRC_V2_REPORT, DOC_MCAST_V2_REPORT, 0x1704)
        / Igmp::v2_membership_report(DOC_MCAST_V2_REPORT)
}

fn build_v2_leave() -> Packet {
    ipv4(DOC_SRC_V2_LEAVE, ALL_ROUTERS, 0x1705) / Igmp::v2_leave_group(DOC_MCAST_V2_LEAVE)
}

fn build_v3_general_query() -> Packet {
    ipv4(DOC_SRC_V3_GENERAL, ALL_SYSTEMS, 0x1706)
        / Igmp::v3_general_query(V3_QUERY_MAX_RESPONSE_CODE)
}

fn build_v3_group_query() -> Packet {
    ipv4(DOC_SRC_V3_GROUP, DOC_MCAST_V3_GROUP, 0x1707)
        / Igmp::v3_group_specific_query(10, DOC_MCAST_V3_GROUP)
}

fn build_v3_group_source_query() -> Packet {
    let query = IgmpQuery::group_and_source_specific(V3_GROUP_SOURCE_SOURCES)
        .with_suppress_router_side_processing(true)
        .with_querier_robustness_variable(2)
        .with_qqic(V3_QUERY_QQIC_LINEAR);
    ipv4(DOC_SRC_V3_GROUP_SOURCE, DOC_MCAST_V3_GROUP_SOURCE, 0x1708)
        / Igmp::v3_membership_query(
            V3_QUERY_QQIC_LINEAR,
            DOC_MCAST_V3_GROUP_SOURCE,
            query,
        )
}

fn build_v3_timer_query() -> Packet {
    let query = IgmpQuery::new()
        .with_querier_robustness_variable(2)
        .with_qqic(V3_QUERY_TIMER_QQIC);
    ipv4(DOC_SRC_V3_TIMERS, ALL_SYSTEMS, 0x1709)
        / Igmp::v3_membership_query(
            V3_QUERY_TIMER_MAX_RESPONSE_CODE,
            Ipv4Addr::UNSPECIFIED,
            query,
        )
}

fn build_v3_reserved_flags_query() -> Packet {
    let query = IgmpQuery::new()
        .with_raw_flags_qrv(V3_QUERY_RESERVED_FLAGS_QRV)
        .with_qqic(V3_QUERY_QQIC_LINEAR)
        .with_source_addresses(V3_RESERVED_FLAGS_SOURCES);
    ipv4(
        DOC_SRC_V3_RESERVED_FLAGS,
        DOC_MCAST_V3_RESERVED_FLAGS,
        0x170a,
    ) / Igmp::v3_membership_query(
        V3_QUERY_MAX_RESPONSE_CODE,
        DOC_MCAST_V3_RESERVED_FLAGS,
        query,
    )
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
    assert_eq!(
        decoded.summary().trim_end(),
        case.summary_fixture.trim_end()
    );
    assert_eq!(decoded.show().trim_end(), case.show_fixture.trim_end());

    Ok(decoded)
}

fn assert_v3_query_case(case: IgmpV3QueryGoldenCase) -> crafter::Result<Packet> {
    let packet = (case.build)();
    let compiled = packet.compile()?;
    let expected = decode_hex(case.name, case.bytes_fixture);

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

    let ipv4 = decoded.layer::<Ipv4>().expect("decoded IPv4 layer");
    assert_eq!(ipv4.source(), case.source);
    assert_eq!(ipv4.destination(), case.destination);

    let igmp = decoded.layer::<Igmp>().expect("decoded IGMP layer");
    assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
    assert_eq!(igmp.code_value(), case.max_response_code);
    assert_eq!(
        igmp.v3_max_response_time_tenths(),
        case.max_response_tenths
    );
    assert_eq!(igmp.group_address_value(), case.group_address);
    assert_eq!(igmp.checksum_value(), Some(case.checksum));
    assert_eq!(igmp.checksum_state(), FieldState::User);

    let query = decoded
        .layer::<IgmpQuery>()
        .expect("decoded IGMPv3 query body");
    assert_eq!(query.raw_flags_qrv_value(), case.raw_flags_qrv);
    assert_eq!(query.query_flags_value(), case.query_flags);
    assert_eq!(query.suppress_router_side_processing(), case.suppress);
    assert_eq!(query.querier_robustness_variable(), case.qrv);
    assert_eq!(query.qqic_value(), case.qqic);
    assert_eq!(
        query.querier_query_interval_seconds(),
        case.query_interval_seconds
    );
    assert_eq!(query.number_of_sources_value(), case.sources.len() as u16);
    assert_eq!(query.source_addresses(), case.sources);
    assert_eq!(query.raw_flags_qrv_state(), FieldState::User);
    assert_eq!(query.qqic_state(), FieldState::User);
    assert_eq!(query.number_of_sources_state(), FieldState::User);

    maybe_dump(case.name, compiled.as_bytes(), Some(&decoded));
    assert_eq!(
        decoded.summary().trim_end(),
        case.summary_fixture.trim_end()
    );
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
fn igmp_golden_v3_query_general() -> crafter::Result<()> {
    assert_v3_query_case(V3_QUERY_CASES[0])?;
    Ok(())
}

#[test]
fn igmp_golden_v3_query_group_specific() -> crafter::Result<()> {
    assert_v3_query_case(V3_QUERY_CASES[1])?;
    Ok(())
}

#[test]
fn igmp_golden_v3_query_group_and_source_specific() -> crafter::Result<()> {
    let decoded = assert_v3_query_case(V3_QUERY_CASES[2])?;
    let query = decoded
        .layer::<IgmpQuery>()
        .expect("decoded group-and-source query body");

    assert_eq!(query.source_addresses(), V3_GROUP_SOURCE_SOURCES);
    assert!(query.suppress_router_side_processing());
    assert_eq!(query.querier_robustness_variable_value(), 2);

    Ok(())
}

#[test]
fn igmp_golden_v3_query_explicit_timer_codes() -> crafter::Result<()> {
    let decoded = assert_v3_query_case(V3_QUERY_CASES[3])?;
    let igmp = decoded.layer::<Igmp>().expect("decoded IGMP timer query");
    let query = decoded
        .layer::<IgmpQuery>()
        .expect("decoded IGMPv3 timer query body");

    assert_eq!(igmp.max_response_code_value(), V3_QUERY_TIMER_MAX_RESPONSE_CODE);
    assert_eq!(
        igmp.v3_max_response_time_tenths(),
        V3_QUERY_TIMER_MAX_RESPONSE_TENTHS
    );
    assert_eq!(query.qqic_value(), V3_QUERY_TIMER_QQIC);
    assert_eq!(
        query.querier_query_interval_seconds(),
        V3_QUERY_TIMER_INTERVAL_SECONDS
    );

    Ok(())
}

#[test]
fn igmp_golden_v3_query_reserved_flag_bits() -> crafter::Result<()> {
    let decoded = assert_v3_query_case(V3_QUERY_CASES[4])?;
    let query = decoded
        .layer::<IgmpQuery>()
        .expect("decoded reserved-flags query body");

    assert_eq!(query.raw_flags_qrv_value(), V3_QUERY_RESERVED_FLAGS_QRV);
    assert_eq!(query.query_flags_value(), 0xf0);
    assert_eq!(query.unassigned_query_flags_value(), 0x70);
    assert!(query.extension_flag());
    assert!(!query.suppress_router_side_processing());
    assert_eq!(query.source_addresses(), V3_RESERVED_FLAGS_SOURCES);

    Ok(())
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
fn igmp_golden_v2_membership_query() -> crafter::Result<()> {
    let decoded = assert_case(CASES[2])?;
    let ipv4 = decoded.layer::<Ipv4>().expect("decoded IPv4 query");
    let igmp = decoded.layer::<Igmp>().expect("decoded IGMP v2 query");

    assert_eq!(ipv4.source(), DOC_SRC_V2_QUERY);
    assert_eq!(ipv4.destination(), ALL_SYSTEMS);
    assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
    assert_eq!(igmp.code_value(), V2_QUERY_MAX_RESPONSE_TENTHS);
    assert_eq!(
        igmp.v2_max_response_time_tenths(),
        V2_QUERY_MAX_RESPONSE_TENTHS
    );
    assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);
    assert_eq!(igmp.checksum_value(), Some(0xee9b));

    Ok(())
}

#[test]
fn igmp_golden_v2_membership_report() -> crafter::Result<()> {
    let decoded = assert_case(CASES[3])?;
    let ipv4 = decoded.layer::<Ipv4>().expect("decoded IPv4 report");
    let igmp = decoded.layer::<Igmp>().expect("decoded IGMP v2 report");

    assert_eq!(ipv4.source(), DOC_SRC_V2_REPORT);
    assert_eq!(ipv4.destination(), DOC_MCAST_V2_REPORT);
    assert_eq!(igmp.igmp_type(), IgmpType::V2MembershipReport);
    assert_eq!(igmp.code_value(), IGMP_DEFAULT_CODE);
    assert_eq!(igmp.group_address_value(), DOC_MCAST_V2_REPORT);
    assert_eq!(igmp.checksum_value(), Some(0xffd7));

    Ok(())
}

#[test]
fn igmp_golden_v2_leave_group() -> crafter::Result<()> {
    let decoded = assert_case(CASES[4])?;
    let ipv4 = decoded.layer::<Ipv4>().expect("decoded IPv4 leave");
    let igmp = decoded.layer::<Igmp>().expect("decoded IGMP v2 leave");

    assert_eq!(ipv4.source(), DOC_SRC_V2_LEAVE);
    assert_eq!(ipv4.destination(), ALL_ROUTERS);
    assert_eq!(igmp.igmp_type(), IgmpType::V2LeaveGroup);
    assert_eq!(igmp.code_value(), IGMP_DEFAULT_CODE);
    assert_eq!(igmp.group_address_value(), DOC_MCAST_V2_LEAVE);
    assert_eq!(igmp.checksum_value(), Some(0xfef1));

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
