//! Deterministic SNMP pcap fixture generation and roundtrip checks.
//!
//! These fixtures are synthetic, offline-only, and use documentation address
//! space plus locally administered documentation MAC addresses.

use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use crafter::prelude::*;
use crafter::wire::backend::pcap::{
    PcapLinkType, PcapReader, PcapTimestamp, PcapWriter, PcapWriterOptions, TimestampPrecision,
};

const ETHERNET_SNMP_HEX: &str = "bytes/ethernet-ipv4-udp-snmp-get-request.hex";
const RAW_IP_SNMP_HEX: &str = "bytes/ipv4-udp-snmp-response.hex";
const ETHERNET_SNMP_SUMMARY: &str = "summaries/ethernet-ipv4-udp-snmp-get-request.summary.txt";
const RAW_IP_SNMP_SUMMARY: &str = "summaries/ipv4-udp-snmp-response.summary.txt";
const ETHERNET_SNMP_PCAP: &str = "pcaps/ethernet-ipv4-udp-snmp-get-request.pcap";
const RAW_IP_SNMP_PCAP: &str = "pcaps/raw-ipv4-udp-snmp-response.pcap";

const DOC_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 161);
const DOC_AGENT: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 161);
const DOC_CLIENT_PORT: u16 = 49_152;
const DOC_CLIENT_MAC: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0xa1]);
const DOC_AGENT_MAC: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0xa2]);

fn fixture_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

fn oid(dotted: &str) -> SnmpOid {
    SnmpOid::from_dotted(dotted).expect("SNMP fixture OID should parse")
}

fn sys_uptime_varbind() -> SnmpVarBind {
    SnmpVarBind::time_ticks(oid("1.3.6.1.2.1.1.3.0"), 12_345)
}

fn snmp_get_request_packet() -> Packet {
    Ethernet::with_addresses(DOC_CLIENT_MAC, DOC_AGENT_MAC)
        / Ipv4::new()
            .src(DOC_CLIENT)
            .dst(DOC_AGENT)
            .id(0x7061)
            .ttl(64)
        / Udp::new().sport(DOC_CLIENT_PORT).dport(SNMP_PORT)
        / Snmp::v2c_get_request(
            b"public".to_vec(),
            0x7061,
            SnmpVarBindList::new(vec![SnmpVarBind::null(oid("1.3.6.1.2.1.1.1.0"))]),
        )
        .expect("SNMP GetRequest fixture should build")
}

fn snmp_response_packet() -> Packet {
    Ipv4::new()
        .src(DOC_AGENT)
        .dst(DOC_CLIENT)
        .id(0x7062)
        .ttl(64)
        / Udp::new().sport(SNMP_PORT).dport(DOC_CLIENT_PORT)
        / Snmp::v2c_response(
            b"public".to_vec(),
            0x7061,
            SnmpVarBindList::new(vec![sys_uptime_varbind()]),
        )
        .expect("SNMP Response fixture should build")
}

fn compiled_bytes(packet: &Packet) -> Vec<u8> {
    packet
        .compile()
        .expect("SNMP fixture packet should compile")
        .as_bytes()
        .to_vec()
}

fn ethernet_snmp_bytes() -> Vec<u8> {
    compiled_bytes(&snmp_get_request_packet())
}

fn raw_ip_snmp_bytes() -> Vec<u8> {
    compiled_bytes(&snmp_response_packet())
}

fn ethernet_snmp_pcap_bytes() -> Vec<u8> {
    pcap_bytes(
        PcapLinkType::Ethernet,
        &snmp_get_request_packet(),
        PcapTimestamp::micros(62, 161).expect("SNMP pcap timestamp should be valid"),
    )
}

fn raw_ip_snmp_pcap_bytes() -> Vec<u8> {
    pcap_bytes(
        PcapLinkType::RawIp,
        &snmp_response_packet(),
        PcapTimestamp::micros(62, 162).expect("SNMP pcap timestamp should be valid"),
    )
}

fn pcap_bytes(link_type: PcapLinkType, packet: &Packet, timestamp: PcapTimestamp) -> Vec<u8> {
    let options = PcapWriterOptions::new(link_type).precision(TimestampPrecision::Microseconds);
    let mut pcap = Vec::new();
    {
        let mut writer = PcapWriter::from_writer_with_options(&mut pcap, options)
            .expect("SNMP pcap writer should initialize");
        writer
            .write_packet_with_timestamp(packet, timestamp)
            .expect("SNMP pcap packet should write");
        writer.flush().expect("SNMP pcap writer should flush");
    }
    pcap
}

fn decode_hex(text: &str) -> Vec<u8> {
    let compact = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .flat_map(str::chars)
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();

    compact
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = std::str::from_utf8(chunk).expect("hex fixture byte should be UTF-8");
            u8::from_str_radix(byte, 16).expect("hex fixture byte should be valid")
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(16) {
        for (index, byte) in chunk.iter().enumerate() {
            if index > 0 {
                out.push(' ');
            }
            out.push_str(&format!("{byte:02x}"));
        }
        out.push('\n');
    }
    out
}

fn decoded_summary(target: NetworkLayer, bytes: &[u8]) -> String {
    Packet::decode_from_l3(target, bytes)
        .expect("SNMP raw IP fixture should decode")
        .summary()
}

fn decoded_link_summary(link_type: LinkType, bytes: &[u8]) -> String {
    Packet::decode_from_link(link_type, bytes)
        .expect("SNMP Ethernet fixture should decode")
        .summary()
}

fn assert_snmp_packet(packet: &Packet, request_id: i64, expected_tag: u8) {
    let udp = packet.layer::<Udp>().expect("SNMP fixture UDP layer");
    assert_ne!(udp.checksum_value(), Some(0));
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);

    let snmp = packet.layer::<Snmp>().expect("SNMP fixture SNMP layer");
    assert_eq!(snmp.version(), SnmpVersion::V2c);
    assert_eq!(snmp.pdu().tag_number(), expected_tag);
    assert_eq!(
        snmp.pdu()
            .as_get_request()
            .expect("SNMP GetRequest fields should parse")
            .or_else(|| {
                snmp.pdu()
                    .as_response()
                    .expect("SNMP Response fields should parse")
            })
            .expect("SNMP request-style PDU fields")
            .request_id(),
        request_id
    );
    assert!(!packet.summary().contains("public"));
    assert!(!packet.show().contains("public"));
}

#[test]
fn snmp_pcap_roundtrip_fixtures_decode_and_rewrite() {
    let ethernet_hex =
        fs::read_to_string(fixture_path(ETHERNET_SNMP_HEX)).expect("SNMP Ethernet hex fixture");
    let raw_ip_hex = fs::read_to_string(fixture_path(RAW_IP_SNMP_HEX)).expect("SNMP RawIp fixture");
    assert_eq!(decode_hex(&ethernet_hex), ethernet_snmp_bytes());
    assert_eq!(decode_hex(&raw_ip_hex), raw_ip_snmp_bytes());

    let ethernet_summary =
        fs::read_to_string(fixture_path(ETHERNET_SNMP_SUMMARY)).expect("SNMP Ethernet summary");
    let raw_ip_summary =
        fs::read_to_string(fixture_path(RAW_IP_SNMP_SUMMARY)).expect("SNMP RawIp summary");
    assert_eq!(
        ethernet_summary.trim_end(),
        decoded_link_summary(LinkType::Ethernet, &ethernet_snmp_bytes())
    );
    assert_eq!(
        raw_ip_summary.trim_end(),
        decoded_summary(NetworkLayer::Ipv4, &raw_ip_snmp_bytes())
    );

    assert_snmp_pcap_fixture(
        ETHERNET_SNMP_PCAP,
        PcapLinkType::Ethernet,
        LinkType::Ethernet,
        PcapTimestamp::micros(62, 161).expect("SNMP pcap timestamp should be valid"),
        &ethernet_snmp_bytes(),
        ethernet_snmp_pcap_bytes(),
        SNMP_PDU_TAG_GET_REQUEST,
    );
    assert_snmp_pcap_fixture(
        RAW_IP_SNMP_PCAP,
        PcapLinkType::RawIp,
        LinkType::Raw,
        PcapTimestamp::micros(62, 162).expect("SNMP pcap timestamp should be valid"),
        &raw_ip_snmp_bytes(),
        raw_ip_snmp_pcap_bytes(),
        SNMP_PDU_TAG_RESPONSE,
    );
}

fn assert_snmp_pcap_fixture(
    path: &str,
    pcap_link_type: PcapLinkType,
    link_type: LinkType,
    timestamp: PcapTimestamp,
    expected_record: &[u8],
    expected_pcap: Vec<u8>,
    expected_tag: u8,
) {
    let fixture = fs::read(fixture_path(path)).expect("SNMP pcap fixture should exist");
    assert_eq!(fixture, expected_pcap);

    let reader =
        PcapReader::from_reader(fixture.as_slice()).expect("SNMP pcap fixture should parse header");
    assert_eq!(reader.header().pcap_link_type(), pcap_link_type);
    assert_eq!(reader.header().link_type(), link_type);
    assert_eq!(
        reader.header().precision(),
        TimestampPrecision::Microseconds
    );

    let records = PcapReader::from_reader(fixture.as_slice())
        .expect("SNMP pcap fixture should parse header for records")
        .collect_records()
        .expect("SNMP pcap fixture should read records");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.timestamp(), timestamp);
    assert_eq!(record.pcap_link_type(), pcap_link_type);
    assert_eq!(record.link_type(), link_type);
    assert_eq!(record.captured_len(), expected_record.len() as u32);
    assert_eq!(record.original_len(), expected_record.len() as u32);
    assert_eq!(record.data(), expected_record);

    let packets = PcapReader::from_reader(fixture.as_slice())
        .expect("SNMP pcap fixture should parse header for packets")
        .collect_packets()
        .expect("SNMP pcap fixture should decode packets");
    assert_eq!(packets.len(), 1);
    assert_snmp_packet(packets[0].packet(), 0x7061, expected_tag);

    let mut rewritten = Vec::new();
    {
        let options =
            PcapWriterOptions::new(pcap_link_type).precision(TimestampPrecision::Microseconds);
        let mut writer = PcapWriter::from_writer_with_options(&mut rewritten, options)
            .expect("SNMP pcap writer should initialize");
        writer
            .write_record(record)
            .expect("SNMP pcap record should rewrite");
        writer.flush().expect("SNMP pcap writer should flush");
    }
    assert_eq!(rewritten, fixture);
}

#[test]
#[ignore = "regenerates the committed SNMP byte, summary, and pcap fixtures"]
fn snmp_pcap_write_fixtures() {
    let ethernet_bytes = ethernet_snmp_bytes();
    let raw_ip_bytes = raw_ip_snmp_bytes();

    fs::write(fixture_path(ETHERNET_SNMP_HEX), encode_hex(&ethernet_bytes))
        .expect("SNMP Ethernet hex fixture should write");
    fs::write(fixture_path(RAW_IP_SNMP_HEX), encode_hex(&raw_ip_bytes))
        .expect("SNMP RawIp hex fixture should write");
    fs::write(
        fixture_path(ETHERNET_SNMP_SUMMARY),
        format!(
            "{}\n",
            decoded_link_summary(LinkType::Ethernet, &ethernet_bytes)
        ),
    )
    .expect("SNMP Ethernet summary fixture should write");
    fs::write(
        fixture_path(RAW_IP_SNMP_SUMMARY),
        format!("{}\n", decoded_summary(NetworkLayer::Ipv4, &raw_ip_bytes)),
    )
    .expect("SNMP RawIp summary fixture should write");
    fs::write(fixture_path(ETHERNET_SNMP_PCAP), ethernet_snmp_pcap_bytes())
        .expect("SNMP Ethernet pcap fixture should write");
    fs::write(fixture_path(RAW_IP_SNMP_PCAP), raw_ip_snmp_pcap_bytes())
        .expect("SNMP RawIp pcap fixture should write");
}
