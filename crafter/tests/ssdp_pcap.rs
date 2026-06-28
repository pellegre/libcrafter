use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use crafter::prelude::*;
use crafter::wire::backend::pcap::{
    PcapLinkType, PcapReader, PcapTimestamp, PcapWriter, PcapWriterOptions, TimestampPrecision,
};

const RAW_IPV4_SSDP_PCAP: &str = "ssdp/raw-ipv4-udp-ssdp-m-search.pcap";
const ETHERNET_IPV4_SSDP_PCAP: &str = "ssdp/ethernet-ipv4-udp-ssdp-m-search.pcap";
const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const DOC_SRC_MAC: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
const SSDP_IPV4_GROUP_MAC: MacAddr = MacAddr::new([0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa]);
static NEXT_TEMP_PCAP: AtomicUsize = AtomicUsize::new(0);

struct TempPcap {
    path: PathBuf,
}

impl TempPcap {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ssdp-pcap-{name}-{}-{}.pcap",
            std::process::id(),
            NEXT_TEMP_PCAP.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_file(&path);
        Self { path }
    }
}

impl Drop for TempPcap {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

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

fn ethernet_ipv4_ssdp_packet() -> Packet {
    Ethernet::with_addresses(DOC_SRC_MAC, SSDP_IPV4_GROUP_MAC) / raw_ipv4_ssdp_packet()
}

fn raw_ipv4_ssdp_bytes() -> Vec<u8> {
    raw_ipv4_ssdp_packet()
        .compile()
        .expect("SSDP raw IPv4 fixture packet should compile")
        .as_bytes()
        .to_vec()
}

fn ethernet_ipv4_ssdp_bytes() -> Vec<u8> {
    ethernet_ipv4_ssdp_packet()
        .compile()
        .expect("SSDP Ethernet fixture packet should compile")
        .as_bytes()
        .to_vec()
}

fn raw_ipv4_ssdp_pcap_bytes() -> Vec<u8> {
    pcap_bytes(
        PcapLinkType::RawIp,
        &raw_ipv4_ssdp_packet(),
        PcapTimestamp::micros(63, 1_900).expect("SSDP timestamp should be valid"),
    )
}

fn ethernet_ipv4_ssdp_pcap_bytes() -> Vec<u8> {
    pcap_bytes(
        PcapLinkType::Ethernet,
        &ethernet_ipv4_ssdp_packet(),
        PcapTimestamp::micros(63, 1_901).expect("SSDP timestamp should be valid"),
    )
}

fn pcap_bytes(link_type: PcapLinkType, packet: &Packet, timestamp: PcapTimestamp) -> Vec<u8> {
    let options = PcapWriterOptions::new(link_type).precision(TimestampPrecision::Microseconds);
    let mut pcap = Vec::new();
    {
        let mut writer = PcapWriter::from_writer_with_options(&mut pcap, options)
            .expect("SSDP pcap writer should initialize");
        writer
            .write_packet_with_timestamp(packet, timestamp)
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

fn assert_packetwire_roundtrip(
    name: &str,
    link_type: LinkType,
    packet: Packet,
    expected_bytes: Vec<u8>,
) {
    let temp = TempPcap::new(name);
    let timestamp = PcapTimestamp::micros(64, 1_900).expect("SSDP timestamp should be valid");
    let record = PacketRecord::new(packet).with_timestamp(timestamp);
    let mut writer = PacketWire::pcap_recorder(&temp.path, link_type)
        .open()
        .expect("SSDP PacketWire pcap writer should open")
        .writer()
        .expect("SSDP PacketWire pcap recorder should expose writer");

    let report = writer
        .write_record(&record)
        .expect("SSDP PacketWire pcap record should write");
    assert_eq!(report.backend(), &BackendKind::PcapFile);
    assert_eq!(report.bytes_requested(), expected_bytes.len());
    assert_eq!(report.bytes_written(), expected_bytes.len());
    let target_details = temp.path.display().to_string();
    assert_eq!(report.target_details(), Some(target_details.as_str()));
    drop(writer);

    let mut source = PacketWire::pcap_file(&temp.path)
        .open()
        .expect("SSDP PacketWire pcap reader should open")
        .source()
        .expect("SSDP PacketWire pcap file should expose source");
    let captured = source
        .next_record()
        .expect("SSDP PacketWire pcap source should read")
        .expect("SSDP PacketWire pcap source should contain one record");
    assert!(source
        .next_record()
        .expect("SSDP PacketWire pcap source should finish")
        .is_none());

    let metadata = captured.metadata();
    assert_eq!(metadata.backend(), &BackendKind::PcapFile);
    assert_eq!(metadata.file(), Some(temp.path.as_path()));
    assert_eq!(metadata.timestamp(), Some(timestamp));
    assert_eq!(metadata.original_len(), Some(expected_bytes.len() as u32));
    assert_eq!(metadata.captured_len(), Some(expected_bytes.len() as u32));
    assert_eq!(metadata.captured_bytes(), Some(expected_bytes.as_slice()));
    assert_eq!(metadata.link_type(), Some(link_type));
    assert_eq!(
        metadata.pcap_link_type(),
        Some(PcapLinkType::from(link_type))
    );
    assert_raw_ssdp_packet(captured.packet());
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
fn ethernet_ssdp_pcap_fixture_decodes_link_network_udp_and_ssdp_layers() {
    let fixture =
        fs::read(fixture_path(ETHERNET_IPV4_SSDP_PCAP)).expect("SSDP Ethernet pcap fixture");
    assert_eq!(fixture, ethernet_ipv4_ssdp_pcap_bytes());

    let reader = PcapReader::from_reader(fixture.as_slice())
        .expect("SSDP Ethernet pcap header should parse");
    assert_eq!(reader.header().pcap_link_type(), PcapLinkType::Ethernet);
    assert_eq!(reader.header().link_type(), LinkType::Ethernet);

    let records = PcapReader::from_reader(fixture.as_slice())
        .expect("SSDP Ethernet pcap header should parse for records")
        .collect_records()
        .expect("SSDP Ethernet pcap records should read");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(
        record.timestamp(),
        PcapTimestamp::micros(63, 1_901).expect("SSDP timestamp should be valid")
    );
    assert_eq!(record.pcap_link_type(), PcapLinkType::Ethernet);
    assert_eq!(record.data(), ethernet_ipv4_ssdp_bytes());

    let packets = PcapReader::from_reader(fixture.as_slice())
        .expect("SSDP Ethernet pcap header should parse for packets")
        .collect_packets()
        .expect("SSDP Ethernet pcap packets should decode");
    assert_eq!(packets.len(), 1);
    let packet = packets[0].packet();
    let ethernet = packet.layer::<Ethernet>().expect("Ethernet layer");
    assert_eq!(ethernet.source(), Some(DOC_SRC_MAC));
    assert_eq!(ethernet.destination(), Some(SSDP_IPV4_GROUP_MAC));
    assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_IPV4));
    assert_raw_ssdp_packet(packet);
}

#[test]
fn packetwire_ssdp_pcap_roundtrip_supported_link_types() {
    assert_packetwire_roundtrip(
        "raw-ipv4",
        LinkType::Raw,
        raw_ipv4_ssdp_packet(),
        raw_ipv4_ssdp_bytes(),
    );
    assert_packetwire_roundtrip(
        "ethernet-ipv4",
        LinkType::Ethernet,
        ethernet_ipv4_ssdp_packet(),
        ethernet_ipv4_ssdp_bytes(),
    );
}

#[test]
#[ignore = "regenerates the committed raw SSDP pcap fixture"]
fn write_raw_ssdp_pcap_fixture() {
    fs::write(fixture_path(RAW_IPV4_SSDP_PCAP), raw_ipv4_ssdp_pcap_bytes())
        .expect("SSDP raw pcap fixture should write");
}

#[test]
#[ignore = "regenerates the committed Ethernet SSDP pcap fixture"]
fn write_ethernet_ssdp_pcap_fixture() {
    fs::write(
        fixture_path(ETHERNET_IPV4_SSDP_PCAP),
        ethernet_ipv4_ssdp_pcap_bytes(),
    )
    .expect("SSDP Ethernet pcap fixture should write");
}
