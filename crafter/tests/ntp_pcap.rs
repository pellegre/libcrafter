use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use crafter::prelude::*;
use crafter::wire::backend::pcap::{
    PcapLinkType, PcapReader, PcapTimestamp, PcapWriter, PcapWriterOptions, TimestampPrecision,
};

const RAW_IPV4_NTP_PCAP: &str = "pcaps/raw-ipv4-udp-ntp-client.pcap";
const DOC_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 123);
const DOC_CLIENT_PORT: u16 = 49_152;

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

fn raw_ipv4_ntp_timestamp() -> PcapTimestamp {
    PcapTimestamp::micros(65, 123).expect("NTP pcap timestamp should be valid")
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
#[ignore = "regenerates the committed raw IPv4 NTP pcap fixture"]
fn write_raw_ipv4_ntp_pcap_fixture() {
    fs::write(fixture_path(RAW_IPV4_NTP_PCAP), raw_ipv4_ntp_pcap_bytes())
        .expect("NTP raw pcap fixture should write");
}
