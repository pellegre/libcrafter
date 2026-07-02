use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use crafter::prelude::*;
use crafter::wire::backend::pcap::{
    PcapLinkType, PcapReader, PcapTimestamp, PcapWriter, PcapWriterOptions, TimestampPrecision,
};

const RAW_IPV4_NTP_PCAP: &str = "pcaps/raw-ipv4-udp-ntp-client.pcap";
const ETHERNET_IPV4_NTP_PCAP: &str = "pcaps/ethernet-ipv4-udp-ntp-client.pcap";
const DOC_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 123);
const DOC_CLIENT_PORT: u16 = 49_152;
const DOC_CLIENT_MAC: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x7b, 0x01]);
const DOC_SERVER_MAC: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x7b, 0x02]);
static NEXT_TEMP_PCAP: AtomicUsize = AtomicUsize::new(0);

struct TempPcap {
    path: PathBuf,
}

impl TempPcap {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ntp-pcap-{name}-{}-{}.pcap",
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

fn raw_ipv4_ntp_packet() -> Packet {
    Ipv4::new()
        .src(DOC_CLIENT)
        .dst(DOC_SERVER)
        .id(0x4e54)
        .ttl(64)
        / Udp::ntp().sport(DOC_CLIENT_PORT)
        / Ntp::client()
            .poll(6)
            .precision(-20)
            .reference_id(*b"LOCL")
            .transmit_timestamp(NtpTimestamp::from_parts(0xecc0_0000, 0x1234_5678))
}

fn raw_ipv4_ntp_bytes() -> Vec<u8> {
    raw_ipv4_ntp_packet()
        .compile()
        .expect("NTP RawIp fixture packet should compile")
        .as_bytes()
        .to_vec()
}

fn ethernet_ntp_packet() -> Packet {
    Ethernet::with_addresses(DOC_CLIENT_MAC, DOC_SERVER_MAC) / raw_ipv4_ntp_packet()
}

fn ethernet_ntp_bytes() -> Vec<u8> {
    ethernet_ntp_packet()
        .compile()
        .expect("NTP Ethernet fixture packet should compile")
        .as_bytes()
        .to_vec()
}

fn raw_ipv4_ntp_timestamp() -> PcapTimestamp {
    PcapTimestamp::micros(65, 123).expect("NTP pcap timestamp should be valid")
}

fn ethernet_ntp_timestamp() -> PcapTimestamp {
    PcapTimestamp::micros(65, 124).expect("NTP Ethernet pcap timestamp should be valid")
}

fn raw_ipv4_ntp_pcap_bytes() -> Vec<u8> {
    let options =
        PcapWriterOptions::new(PcapLinkType::RawIp).precision(TimestampPrecision::Microseconds);
    let mut pcap = Vec::new();
    {
        let mut writer = PcapWriter::from_writer_with_options(&mut pcap, options)
            .expect("NTP pcap writer should initialize");
        writer
            .write_packet_with_timestamp(&raw_ipv4_ntp_packet(), raw_ipv4_ntp_timestamp())
            .expect("NTP pcap packet should write");
        writer.flush().expect("NTP pcap writer should flush");
    }
    pcap
}

fn ethernet_ntp_pcap_bytes() -> Vec<u8> {
    let options =
        PcapWriterOptions::new(PcapLinkType::Ethernet).precision(TimestampPrecision::Microseconds);
    let mut pcap = Vec::new();
    {
        let mut writer = PcapWriter::from_writer_with_options(&mut pcap, options)
            .expect("NTP Ethernet pcap writer should initialize");
        writer
            .write_packet_with_timestamp(&ethernet_ntp_packet(), ethernet_ntp_timestamp())
            .expect("NTP Ethernet pcap packet should write");
        writer
            .flush()
            .expect("NTP Ethernet pcap writer should flush");
    }
    pcap
}

fn assert_raw_ipv4_ntp_packet(packet: &Packet) {
    let ipv4 = packet.layer::<Ipv4>().expect("IPv4 layer");
    assert_eq!(ipv4.source(), DOC_CLIENT);
    assert_eq!(ipv4.destination(), DOC_SERVER);
    assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

    let udp = packet.layer::<Udp>().expect("UDP layer");
    assert_eq!(udp.source_port_value(), DOC_CLIENT_PORT);
    assert_eq!(udp.destination_port_value(), NTP_PORT);
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);

    let ntp = packet.layer::<Ntp>().expect("NTP layer");
    assert_eq!(ntp.mode_value(), NtpMode::Client);
    assert_eq!(ntp.version_value_effective(), NtpVersion::current());
    assert_eq!(ntp.poll_value(), 6);
    assert_eq!(ntp.precision_value(), -20);
    assert_eq!(ntp.reference_id_value().bytes(), *b"LOCL");
    assert_eq!(ntp.transmit_timestamp_value().raw(), 0xecc0_0000_1234_5678);
    assert!(packet.layer::<Raw>().is_none());
}

fn assert_ethernet_ntp_packet(packet: &Packet) {
    let ethernet = packet.layer::<Ethernet>().expect("Ethernet layer");
    assert_eq!(ethernet.source(), Some(DOC_CLIENT_MAC));
    assert_eq!(ethernet.destination(), Some(DOC_SERVER_MAC));
    assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_IPV4));
    assert_raw_ipv4_ntp_packet(packet);
}

fn assert_ethernet_packetwire_roundtrip() {
    let temp = TempPcap::new("ethernet");
    let timestamp = ethernet_ntp_timestamp();
    let expected_bytes = ethernet_ntp_bytes();
    let record = PacketRecord::new(ethernet_ntp_packet()).with_timestamp(timestamp);
    let mut writer = PacketWire::pcap_recorder(&temp.path, LinkType::Ethernet)
        .open()
        .expect("NTP PacketWire pcap writer should open")
        .writer()
        .expect("NTP PacketWire pcap recorder should expose writer");

    let report = writer
        .write_record(&record)
        .expect("NTP PacketWire pcap record should write");
    assert_eq!(report.backend(), &BackendKind::PcapFile);
    assert_eq!(report.bytes_requested(), expected_bytes.len());
    assert_eq!(report.bytes_written(), expected_bytes.len());
    drop(writer);

    let mut source = PacketWire::pcap_file(&temp.path)
        .open()
        .expect("NTP PacketWire pcap source should open")
        .source()
        .expect("NTP PacketWire pcap file should expose source");
    let captured = source
        .next_record()
        .expect("NTP PacketWire pcap source should read")
        .expect("NTP PacketWire pcap source should contain one record");
    assert!(source
        .next_record()
        .expect("NTP PacketWire pcap source should finish")
        .is_none());

    let metadata = captured.metadata();
    assert_eq!(metadata.backend(), &BackendKind::PcapFile);
    assert_eq!(metadata.file(), Some(temp.path.as_path()));
    assert_eq!(metadata.timestamp(), Some(timestamp));
    assert_eq!(metadata.original_len(), Some(expected_bytes.len() as u32));
    assert_eq!(metadata.captured_len(), Some(expected_bytes.len() as u32));
    assert_eq!(metadata.captured_bytes(), Some(expected_bytes.as_slice()));
    assert_eq!(metadata.link_type(), Some(LinkType::Ethernet));
    assert_eq!(metadata.pcap_link_type(), Some(PcapLinkType::Ethernet));
    assert_ethernet_ntp_packet(captured.packet());
}

#[test]
fn raw_ipv4_ntp_pcap_fixture_matches_writer_and_decodes() {
    let fixture =
        fs::read(fixture_path(RAW_IPV4_NTP_PCAP)).expect("NTP raw pcap fixture should exist");
    assert_eq!(fixture, raw_ipv4_ntp_pcap_bytes());

    let reader =
        PcapReader::from_reader(fixture.as_slice()).expect("NTP pcap fixture should parse header");
    assert_eq!(reader.header().pcap_link_type(), PcapLinkType::RawIp);
    assert_eq!(reader.header().link_type(), LinkType::Raw);
    assert_eq!(
        reader.header().precision(),
        TimestampPrecision::Microseconds
    );

    let records = PcapReader::from_reader(fixture.as_slice())
        .expect("NTP pcap fixture should parse header for records")
        .collect_records()
        .expect("NTP pcap fixture should read records");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.timestamp(), raw_ipv4_ntp_timestamp());
    assert_eq!(record.pcap_link_type(), PcapLinkType::RawIp);
    assert_eq!(record.link_type(), LinkType::Raw);
    assert_eq!(record.captured_len(), raw_ipv4_ntp_bytes().len() as u32);
    assert_eq!(record.original_len(), raw_ipv4_ntp_bytes().len() as u32);
    assert_eq!(record.data(), raw_ipv4_ntp_bytes().as_slice());

    let packets = PcapReader::from_reader(fixture.as_slice())
        .expect("NTP pcap fixture should parse header for packets")
        .collect_packets()
        .expect("NTP pcap fixture should decode packets");
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].timestamp(), raw_ipv4_ntp_timestamp());
    assert_eq!(packets[0].pcap_link_type(), PcapLinkType::RawIp);
    assert_eq!(packets[0].data(), raw_ipv4_ntp_bytes().as_slice());
    assert_raw_ipv4_ntp_packet(packets[0].packet());
}

#[test]
fn ethernet_ntp_pcap_fixture_decodes_stack_and_packetwire_roundtrips() {
    let fixture =
        fs::read(fixture_path(ETHERNET_IPV4_NTP_PCAP)).expect("NTP Ethernet pcap fixture");
    assert_eq!(fixture, ethernet_ntp_pcap_bytes());

    let reader = PcapReader::from_reader(fixture.as_slice())
        .expect("NTP Ethernet pcap fixture should parse header");
    assert_eq!(reader.header().pcap_link_type(), PcapLinkType::Ethernet);
    assert_eq!(reader.header().link_type(), LinkType::Ethernet);
    assert_eq!(
        reader.header().precision(),
        TimestampPrecision::Microseconds
    );

    let records = PcapReader::from_reader(fixture.as_slice())
        .expect("NTP Ethernet pcap fixture should parse header for records")
        .collect_records()
        .expect("NTP Ethernet pcap fixture should read records");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.timestamp(), ethernet_ntp_timestamp());
    assert_eq!(record.pcap_link_type(), PcapLinkType::Ethernet);
    assert_eq!(record.link_type(), LinkType::Ethernet);
    assert_eq!(record.captured_len(), ethernet_ntp_bytes().len() as u32);
    assert_eq!(record.original_len(), ethernet_ntp_bytes().len() as u32);
    assert_eq!(record.data(), ethernet_ntp_bytes().as_slice());

    let packets = PcapReader::from_reader(fixture.as_slice())
        .expect("NTP Ethernet pcap fixture should parse header for packets")
        .collect_packets()
        .expect("NTP Ethernet pcap fixture should decode packets");
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].timestamp(), ethernet_ntp_timestamp());
    assert_eq!(packets[0].pcap_link_type(), PcapLinkType::Ethernet);
    assert_eq!(packets[0].link_type(), LinkType::Ethernet);
    assert_eq!(packets[0].data(), ethernet_ntp_bytes().as_slice());
    assert_ethernet_ntp_packet(packets[0].packet());

    assert_ethernet_packetwire_roundtrip();
}

#[test]
#[ignore = "regenerates the committed raw IPv4 NTP pcap fixture"]
fn write_raw_ipv4_ntp_pcap_fixture() {
    fs::write(fixture_path(RAW_IPV4_NTP_PCAP), raw_ipv4_ntp_pcap_bytes())
        .expect("NTP raw pcap fixture should write");
}

#[test]
#[ignore = "regenerates the committed Ethernet NTP pcap fixture"]
fn write_ethernet_ntp_pcap_fixture() {
    fs::write(
        fixture_path(ETHERNET_IPV4_NTP_PCAP),
        ethernet_ntp_pcap_bytes(),
    )
    .expect("NTP Ethernet pcap fixture should write");
}
