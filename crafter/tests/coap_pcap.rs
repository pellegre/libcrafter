use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crafter::prelude::*;
use crafter::wire::backend::pcap::{
    PcapLinkType, PcapReader, PcapTimestamp, PcapWriter, PcapWriterOptions, TimestampPrecision,
};

const RAW_IPV4_COAP_PCAP: &str = "pcaps/raw-ipv4-udp-coap-get.pcap";
const RAW_IPV6_COAP_PCAP: &str = "pcaps/raw-ipv6-udp-coap-content.pcap";
const ETHERNET_IPV4_COAP_PCAP: &str = "pcaps/ethernet-ipv4-udp-coap-get.pcap";

const DOC_V4_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 41);
const DOC_V4_SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 41);
const DOC_V6_CLIENT: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x41, 0, 0, 0, 0, 1);
const DOC_V6_SERVER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x41, 0, 0, 0, 0, 2);
const DOC_CLIENT_MAC: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x41, 0x01]);
const DOC_SERVER_MAC: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x41, 0x02]);
const CLIENT_PORT: u16 = 49_152;

static NEXT_TEMP_PCAP: AtomicUsize = AtomicUsize::new(0);

struct TempPcap {
    path: PathBuf,
}

impl TempPcap {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "coap-pcap-{name}-{}-{}.pcap",
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

struct FixtureCase {
    name: &'static str,
    path: &'static str,
    pcap_link_type: PcapLinkType,
    link_type: LinkType,
    timestamp: fn() -> PcapTimestamp,
    packet: fn() -> Packet,
    assert_packet: fn(&Packet),
}

fn fixture_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

fn request(message_id: u16, token: [u8; 2]) -> Coap {
    Coap::get()
        .confirmable()
        .message_id(message_id)
        .token(CoapToken::from_bytes(token))
        .option(CoapOption::from_string(COAP_OPTION_URI_PATH, "status"))
}

fn response(message_id: u16, token: [u8; 2]) -> Coap {
    Coap::response(CoapCode::content())
        .acknowledgement()
        .message_id(message_id)
        .token(CoapToken::from_bytes(token))
        .option(CoapOption::from_uint(COAP_OPTION_CONTENT_FORMAT, 0))
        .payload(b"ready".to_vec())
}

fn raw_ipv4_coap_packet() -> Packet {
    Ipv4::new()
        .src(DOC_V4_CLIENT)
        .dst(DOC_V4_SERVER)
        .id(0xc041)
        .ttl(64)
        / Udp::new().sport(CLIENT_PORT).dport(COAP_PORT)
        / request(0x4141, [0xc0, 0x41])
}

fn raw_ipv6_coap_packet() -> Packet {
    Ipv6::new().src(DOC_V6_SERVER).dst(DOC_V6_CLIENT).hlim(64)
        / Udp::new().sport(COAP_PORT).dport(CLIENT_PORT)
        / response(0x4142, [0xc0, 0x42])
}

fn ethernet_ipv4_coap_packet() -> Packet {
    Ethernet::with_addresses(DOC_CLIENT_MAC, DOC_SERVER_MAC)
        / Ipv4::new()
            .src(DOC_V4_CLIENT)
            .dst(DOC_V4_SERVER)
            .id(0xc043)
            .ttl(63)
        / Udp::new().sport(CLIENT_PORT + 1).dport(COAP_PORT)
        / request(0x4143, [0xc0, 0x43])
}

fn raw_ipv4_timestamp() -> PcapTimestamp {
    PcapTimestamp::micros(65, 41_001).expect("CoAP raw IPv4 timestamp should be valid")
}

fn raw_ipv6_timestamp() -> PcapTimestamp {
    PcapTimestamp::micros(65, 41_002).expect("CoAP raw IPv6 timestamp should be valid")
}

fn ethernet_timestamp() -> PcapTimestamp {
    PcapTimestamp::micros(65, 41_003).expect("CoAP Ethernet timestamp should be valid")
}

fn fixture_cases() -> [FixtureCase; 3] {
    [
        FixtureCase {
            name: "raw-ipv4",
            path: RAW_IPV4_COAP_PCAP,
            pcap_link_type: PcapLinkType::RawIp,
            link_type: LinkType::Raw,
            timestamp: raw_ipv4_timestamp,
            packet: raw_ipv4_coap_packet,
            assert_packet: assert_raw_ipv4_coap_packet,
        },
        FixtureCase {
            name: "raw-ipv6",
            path: RAW_IPV6_COAP_PCAP,
            pcap_link_type: PcapLinkType::RawIp,
            link_type: LinkType::Raw,
            timestamp: raw_ipv6_timestamp,
            packet: raw_ipv6_coap_packet,
            assert_packet: assert_raw_ipv6_coap_packet,
        },
        FixtureCase {
            name: "ethernet-ipv4",
            path: ETHERNET_IPV4_COAP_PCAP,
            pcap_link_type: PcapLinkType::Ethernet,
            link_type: LinkType::Ethernet,
            timestamp: ethernet_timestamp,
            packet: ethernet_ipv4_coap_packet,
            assert_packet: assert_ethernet_ipv4_coap_packet,
        },
    ]
}

fn compiled_bytes(packet: &Packet) -> Vec<u8> {
    packet
        .compile()
        .expect("CoAP pcap fixture packet should compile")
        .into_bytes()
}

fn pcap_bytes(case: &FixtureCase) -> Vec<u8> {
    let options =
        PcapWriterOptions::new(case.pcap_link_type).precision(TimestampPrecision::Microseconds);
    let mut pcap = Vec::new();
    {
        let mut writer = PcapWriter::from_writer_with_options(&mut pcap, options)
            .expect("CoAP memory pcap writer should initialize");
        writer
            .write_packet_with_timestamp(&(case.packet)(), (case.timestamp)())
            .expect("CoAP memory pcap packet should write");
        writer
            .flush()
            .expect("CoAP memory pcap writer should flush");
    }
    pcap
}

fn assert_request(coap: &Coap, message_id: u16, token: [u8; 2]) {
    assert_eq!(coap.version_value(), CoapVersion::current());
    assert_eq!(coap.message_type_value(), CoapMessageType::Confirmable);
    assert_eq!(coap.code_value(), CoapCode::get());
    assert_eq!(coap.message_id_value(), message_id);
    assert_eq!(coap.token_value().as_bytes(), token);
    assert_eq!(coap.options_value().len(), 1);
    assert_eq!(
        coap.options_value()[0].number(),
        CoapOptionNumber::from(COAP_OPTION_URI_PATH)
    );
    assert_eq!(coap.options_value()[0].value(), b"status");
    assert_eq!(coap.payload_marker_value(), CoapPayloadMarker::Absent);
    assert!(coap.payload_value().is_empty());
}

fn assert_response(coap: &Coap, message_id: u16, token: [u8; 2]) {
    assert_eq!(coap.version_value(), CoapVersion::current());
    assert_eq!(coap.message_type_value(), CoapMessageType::Acknowledgement);
    assert_eq!(coap.code_value(), CoapCode::content());
    assert_eq!(coap.message_id_value(), message_id);
    assert_eq!(coap.token_value().as_bytes(), token);
    assert_eq!(coap.options_value().len(), 1);
    assert_eq!(
        coap.options_value()[0].number(),
        CoapOptionNumber::from(COAP_OPTION_CONTENT_FORMAT)
    );
    assert!(coap.options_value()[0].value().is_empty());
    assert_eq!(coap.payload_marker_value(), CoapPayloadMarker::Present);
    assert_eq!(coap.payload_value(), b"ready");
}

fn assert_raw_ipv4_coap_packet(packet: &Packet) {
    assert!(packet.layer::<Ethernet>().is_none());
    let ipv4 = packet.layer::<Ipv4>().expect("CoAP raw IPv4 layer");
    assert_eq!(ipv4.source(), DOC_V4_CLIENT);
    assert_eq!(ipv4.destination(), DOC_V4_SERVER);
    assert_eq!(ipv4.identification_value(), 0xc041);
    assert_eq!(ipv4.ttl_value(), 64);
    assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);
    assert_eq!(ipv4.checksum_status(), Ipv4ChecksumStatus::Valid);

    let udp = packet.layer::<Udp>().expect("CoAP raw IPv4 UDP layer");
    assert_eq!(udp.source_port_value(), CLIENT_PORT);
    assert_eq!(udp.destination_port_value(), COAP_PORT);
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);

    assert_request(
        packet.layer::<Coap>().expect("CoAP raw IPv4 message"),
        0x4141,
        [0xc0, 0x41],
    );
    assert!(packet.layer::<Raw>().is_none());
}

fn assert_raw_ipv6_coap_packet(packet: &Packet) {
    assert!(packet.layer::<Ethernet>().is_none());
    let ipv6 = packet.layer::<Ipv6>().expect("CoAP raw IPv6 layer");
    assert_eq!(ipv6.source(), DOC_V6_SERVER);
    assert_eq!(ipv6.destination(), DOC_V6_CLIENT);
    assert_eq!(ipv6.hop_limit_value(), 64);
    assert_eq!(ipv6.next_header_value(), IPPROTO_UDP);

    let udp = packet.layer::<Udp>().expect("CoAP raw IPv6 UDP layer");
    assert_eq!(udp.source_port_value(), COAP_PORT);
    assert_eq!(udp.destination_port_value(), CLIENT_PORT);
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);

    assert_response(
        packet.layer::<Coap>().expect("CoAP raw IPv6 message"),
        0x4142,
        [0xc0, 0x42],
    );
    assert!(packet.layer::<Raw>().is_none());
}

fn assert_ethernet_ipv4_coap_packet(packet: &Packet) {
    let ethernet = packet.layer::<Ethernet>().expect("CoAP Ethernet layer");
    assert_eq!(ethernet.source(), Some(DOC_CLIENT_MAC));
    assert_eq!(ethernet.destination(), Some(DOC_SERVER_MAC));
    assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_IPV4));

    let ipv4 = packet.layer::<Ipv4>().expect("CoAP Ethernet IPv4 layer");
    assert_eq!(ipv4.source(), DOC_V4_CLIENT);
    assert_eq!(ipv4.destination(), DOC_V4_SERVER);
    assert_eq!(ipv4.identification_value(), 0xc043);
    assert_eq!(ipv4.ttl_value(), 63);
    assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);
    assert_eq!(ipv4.checksum_status(), Ipv4ChecksumStatus::Valid);

    let udp = packet.layer::<Udp>().expect("CoAP Ethernet UDP layer");
    assert_eq!(udp.source_port_value(), CLIENT_PORT + 1);
    assert_eq!(udp.destination_port_value(), COAP_PORT);
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);

    assert_request(
        packet.layer::<Coap>().expect("CoAP Ethernet message"),
        0x4143,
        [0xc0, 0x43],
    );
    assert!(packet.layer::<Raw>().is_none());
}

fn assert_memory_writer_regeneration(
    case: &FixtureCase,
    record: &crafter::wire::backend::pcap::PcapRecord,
    fixture: &[u8],
) {
    let options =
        PcapWriterOptions::new(case.pcap_link_type).precision(TimestampPrecision::Microseconds);
    let mut regenerated = Vec::new();
    {
        let mut writer = PcapWriter::from_writer_with_options(&mut regenerated, options)
            .expect("CoAP memory pcap rewrite should initialize");
        writer
            .write_record(record)
            .expect("CoAP memory pcap record should rewrite");
        writer
            .flush()
            .expect("CoAP memory pcap rewrite should flush");
    }
    assert_eq!(regenerated, fixture, "{} memory rewrite", case.name);
}

fn assert_packetwire_source(case: &FixtureCase, path: &Path, expected_packet_bytes: &[u8]) {
    let mut source = PacketWire::pcap_file(path)
        .open()
        .expect("CoAP PacketWire pcap source should open")
        .source()
        .expect("CoAP PacketWire pcap file should expose a source");
    let captured = source
        .next_record()
        .expect("CoAP PacketWire pcap source should read")
        .expect("CoAP PacketWire pcap source should contain one record");
    assert!(source
        .next_record()
        .expect("CoAP PacketWire pcap source should finish")
        .is_none());

    let metadata = captured.metadata();
    assert_eq!(metadata.backend(), &BackendKind::PcapFile);
    assert_eq!(metadata.file(), Some(path));
    assert_eq!(metadata.timestamp(), Some((case.timestamp)()));
    assert_eq!(
        metadata.original_len(),
        Some(expected_packet_bytes.len() as u32)
    );
    assert_eq!(
        metadata.captured_len(),
        Some(expected_packet_bytes.len() as u32)
    );
    assert_eq!(metadata.captured_bytes(), Some(expected_packet_bytes));
    assert_eq!(metadata.link_type(), Some(case.link_type));
    assert_eq!(metadata.pcap_link_type(), Some(case.pcap_link_type));
    (case.assert_packet)(captured.packet());
}

fn assert_packetwire_file_writer(case: &FixtureCase, fixture: &[u8], packet_bytes: &[u8]) {
    let temp = TempPcap::new(case.name);
    let record = PacketRecord::new((case.packet)()).with_timestamp((case.timestamp)());
    let mut writer = PacketWire::pcap_recorder(&temp.path, case.pcap_link_type)
        .open()
        .expect("CoAP PacketWire pcap recorder should open")
        .writer()
        .expect("CoAP PacketWire pcap recorder should expose a writer");
    let report = writer
        .write_record(&record)
        .expect("CoAP PacketWire pcap record should write");
    assert_eq!(report.backend(), &BackendKind::PcapFile);
    assert_eq!(report.bytes_requested(), packet_bytes.len());
    assert_eq!(report.bytes_written(), packet_bytes.len());
    assert!(!report.is_dry_run());
    let target_details = temp.path.display().to_string();
    assert_eq!(report.target_details(), Some(target_details.as_str()));
    drop(writer);

    let written = fs::read(&temp.path).expect("CoAP PacketWire pcap output should read");
    assert_eq!(written, fixture, "{} PacketWire file output", case.name);
    assert_packetwire_source(case, &temp.path, packet_bytes);
}

fn assert_fixture(case: &FixtureCase) {
    let path = fixture_path(case.path);
    let fixture = fs::read(&path).expect("committed CoAP pcap fixture should exist");
    assert_eq!(fixture, pcap_bytes(case), "{} fixture bytes", case.name);

    let reader =
        PcapReader::from_reader(fixture.as_slice()).expect("CoAP pcap fixture header should parse");
    assert_eq!(reader.header().pcap_link_type(), case.pcap_link_type);
    assert_eq!(reader.header().link_type(), case.link_type);
    assert_eq!(
        reader.header().precision(),
        TimestampPrecision::Microseconds
    );

    let records = PcapReader::from_reader(fixture.as_slice())
        .expect("CoAP pcap fixture header should parse for records")
        .collect_records()
        .expect("CoAP pcap fixture records should read");
    assert_eq!(records.len(), 1);
    let expected_packet_bytes = compiled_bytes(&(case.packet)());
    let record = &records[0];
    assert_eq!(record.timestamp(), (case.timestamp)());
    assert_eq!(record.pcap_link_type(), case.pcap_link_type);
    assert_eq!(record.link_type(), case.link_type);
    assert_eq!(record.captured_len(), expected_packet_bytes.len() as u32);
    assert_eq!(record.original_len(), expected_packet_bytes.len() as u32);
    assert_eq!(record.data(), expected_packet_bytes.as_slice());
    assert_memory_writer_regeneration(case, record, &fixture);

    let packets = PcapReader::from_reader(fixture.as_slice())
        .expect("CoAP pcap fixture header should parse for packets")
        .collect_packets()
        .expect("CoAP pcap fixture packets should decode");
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].timestamp(), (case.timestamp)());
    assert_eq!(packets[0].pcap_link_type(), case.pcap_link_type);
    assert_eq!(packets[0].link_type(), case.link_type);
    assert_eq!(packets[0].data(), expected_packet_bytes.as_slice());
    (case.assert_packet)(packets[0].packet());

    assert_packetwire_source(case, &path, &expected_packet_bytes);
    assert_packetwire_file_writer(case, &fixture, &expected_packet_bytes);
}

#[test]
fn coap_pcap_fixtures_match_writers_metadata_and_typed_packet_stacks() {
    for case in fixture_cases() {
        assert_fixture(&case);
    }
}

#[test]
#[ignore = "regenerates the committed deterministic CoAP pcap fixtures"]
fn write_coap_pcap_fixtures() {
    for case in fixture_cases() {
        fs::write(fixture_path(case.path), pcap_bytes(&case))
            .expect("CoAP pcap fixture should write");
    }
}
