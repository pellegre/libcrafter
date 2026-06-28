use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use crafter::prelude::*;
use crafter::wire::backend::pcap::{
    PcapLinkType, PcapReader, PcapTimestamp, PcapWriter, PcapWriterOptions, TimestampPrecision,
};

const RAW_IPV4_SSDP_PCAP: &str = "ssdp/raw-ipv4-udp-ssdp-m-search.pcap";
const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

fn fixture_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

fn search_message() -> Ssdp {
    Ssdp::m_search()
        .with_raw_header(SSDP_HEADER_HOST, SSDP_IPV4_MULTICAST_HOST)
        .expect("HOST header is valid")
        .with_raw_header(SSDP_HEADER_MAN, SSDP_MAN_DISCOVER)
        .expect("MAN header is valid")
        .with_raw_header(SSDP_HEADER_MX, "1")
        .expect("MX header is valid")
        .with_raw_header(SSDP_HEADER_ST, SSDP_ST_ALL)
        .expect("ST header is valid")
}

fn raw_ipv4_ssdp_packet() -> Packet {
    Ipv4::new().src(DOC_SRC).dst(SSDP_GROUP).id(0x1900).ttl(2)
        / Ssdp::udp().sport(49_152)
        / search_message()
}

fn raw_ipv4_ssdp_bytes() -> Vec<u8> {
    raw_ipv4_ssdp_packet()
        .compile()
        .expect("SSDP raw IPv4 fixture packet should compile")
        .as_bytes()
        .to_vec()
}

fn raw_ipv4_ssdp_pcap_bytes() -> Vec<u8> {
    let options =
        PcapWriterOptions::new(PcapLinkType::RawIp).precision(TimestampPrecision::Microseconds);
    let mut pcap = Vec::new();
    {
        let mut writer = PcapWriter::from_writer_with_options(&mut pcap, options)
            .expect("SSDP pcap writer should initialize");
        writer
            .write_packet_with_timestamp(
                &raw_ipv4_ssdp_packet(),
                PcapTimestamp::micros(63, 1_900).expect("SSDP timestamp should be valid"),
            )
            .expect("SSDP pcap packet should write");
        writer.flush().expect("SSDP pcap writer should flush");
    }
    pcap
}

fn assert_raw_ssdp_packet(packet: &Packet) {
    let ipv4 = packet.layer::<Ipv4>().expect("IPv4 layer");
    let udp = packet.layer::<Udp>().expect("UDP layer");
    let ssdp = packet.layer::<Ssdp>().expect("SSDP layer");

    assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);
    assert_eq!(udp.source_port_value(), 49_152);
    assert_eq!(udp.destination_port_value(), SSDP_UDP_PORT);
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
    assert_eq!(
        ssdp.headers()
            .get_first(SsdpHeaderNameKind::St)
            .expect("ST header")
            .as_bytes(),
        SSDP_ST_ALL.as_bytes()
    );
    assert!(packet.layer::<Raw>().is_none());

    let summary = packet.summary();
    assert!(summary.contains("SSDP("), "{summary}");
    assert!(summary.contains("M-SEARCH * HTTP/1.1"), "{summary}");
}

#[test]
fn raw_ssdp_pcap_fixture_reads_decodes_and_summarizes_offline() {
    let fixture =
        fs::read(fixture_path(RAW_IPV4_SSDP_PCAP)).expect("SSDP raw pcap fixture should exist");
    assert_eq!(fixture, raw_ipv4_ssdp_pcap_bytes());

    let reader =
        PcapReader::from_reader(fixture.as_slice()).expect("SSDP pcap header should parse");
    assert_eq!(reader.header().pcap_link_type(), PcapLinkType::RawIp);
    assert_eq!(reader.header().link_type(), LinkType::Raw);
    assert_eq!(
        reader.header().precision(),
        TimestampPrecision::Microseconds
    );

    let records = PcapReader::from_reader(fixture.as_slice())
        .expect("SSDP pcap header should parse for records")
        .collect_records()
        .expect("SSDP pcap records should read");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(
        record.timestamp(),
        PcapTimestamp::micros(63, 1_900).expect("SSDP timestamp should be valid")
    );
    assert_eq!(record.pcap_link_type(), PcapLinkType::RawIp);
    assert_eq!(record.data(), raw_ipv4_ssdp_bytes());

    let packets = PcapReader::from_reader(fixture.as_slice())
        .expect("SSDP pcap header should parse for packets")
        .collect_packets()
        .expect("SSDP pcap packets should decode");
    assert_eq!(packets.len(), 1);
    assert_raw_ssdp_packet(packets[0].packet());
}

#[test]
#[ignore = "regenerates the committed raw SSDP pcap fixture"]
fn write_raw_ssdp_pcap_fixture() {
    fs::write(fixture_path(RAW_IPV4_SSDP_PCAP), raw_ipv4_ssdp_pcap_bytes())
        .expect("SSDP raw pcap fixture should write");
}
