mod support;

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;
use crafter::wire::backend::pcap::{
    PcapLinkType, PcapReader, PcapTimestamp, PcapWriter, PcapWriterOptions, TimestampPrecision,
};
use support::fixture_path;

const RAW_IPV4_SCTP_DATA_PCAP: &str = "pcaps/raw-ipv4-sctp-data.pcap";
const RAW_IPV6_SCTP_DATA_PCAP: &str = "pcaps/raw-ipv6-sctp-data.pcap";
const RAW_IPV4_UDP_SCTP_DATA_PCAP: &str = "pcaps/raw-ipv4-udp-sctp-data.pcap";

const DOC_V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 91);
const DOC_V4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 91);
const DOC_V4_UDP_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 191);
const DOC_V4_UDP_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 191);
const DOC_V6_SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x91, 0, 0, 0, 0, 1);
const DOC_V6_DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x91, 0, 0, 0, 0, 2);

fn raw_ipv4_sctp_data_packet() -> Packet {
    Ipv4::new()
        .src(DOC_V4_SRC)
        .dst(DOC_V4_DST)
        .id(0x5091)
        .ttl(64)
        / Sctp::data(
            0x0102_0391,
            0x0091,
            0x0001,
            SCTP_PPID_WEBRTC_STRING,
            b"pcap-v4".to_vec(),
        )
        .sport(21_091)
        .dport(21_092)
        .vtag(0x1122_3391)
}

fn raw_ipv6_sctp_data_packet() -> Packet {
    Ipv6::new().src(DOC_V6_SRC).dst(DOC_V6_DST).hlim(64)
        / Sctp::data(
            0x0102_0691,
            0x0092,
            0x0002,
            SCTP_PPID_WEBRTC_BINARY,
            b"pcap-v6".to_vec(),
        )
        .sport(21_093)
        .dport(21_094)
        .vtag(0x1122_6691)
}

fn raw_ipv4_udp_sctp_data_packet() -> Packet {
    Ipv4::new()
        .src(DOC_V4_UDP_SRC)
        .dst(DOC_V4_UDP_DST)
        .id(0x5191)
        .ttl(64)
        / Udp::new().sport(49_191).dport(SCTP_UDP_ENCAPSULATION_PORT)
        / Sctp::data(
            0x0102_1991,
            0x0093,
            0x0003,
            SCTP_PPID_WEBRTC_STRING,
            b"pcap-udp-v4".to_vec(),
        )
        .sport(21_095)
        .dport(21_096)
        .vtag(0x1122_9991)
}

fn compiled_bytes(packet: &Packet) -> Vec<u8> {
    packet
        .compile()
        .expect("SCTP pcap fixture packet should compile")
        .as_bytes()
        .to_vec()
}

fn pcap_bytes(packet: &Packet, timestamp: PcapTimestamp) -> Vec<u8> {
    let options =
        PcapWriterOptions::new(PcapLinkType::RawIp).precision(TimestampPrecision::Microseconds);
    let mut pcap = Vec::new();
    {
        let mut writer = PcapWriter::from_writer_with_options(&mut pcap, options)
            .expect("SCTP pcap writer should initialize");
        writer
            .write_packet_with_timestamp(packet, timestamp)
            .expect("SCTP pcap packet should write");
        writer.flush().expect("SCTP pcap writer should flush");
    }
    pcap
}

fn raw_ipv4_sctp_data_bytes() -> Vec<u8> {
    compiled_bytes(&raw_ipv4_sctp_data_packet())
}

fn raw_ipv6_sctp_data_bytes() -> Vec<u8> {
    compiled_bytes(&raw_ipv6_sctp_data_packet())
}

fn raw_ipv4_udp_sctp_data_bytes() -> Vec<u8> {
    compiled_bytes(&raw_ipv4_udp_sctp_data_packet())
}

fn raw_ipv4_sctp_data_timestamp() -> PcapTimestamp {
    PcapTimestamp::micros(91, 100).expect("SCTP IPv4 pcap timestamp should be valid")
}

fn raw_ipv6_sctp_data_timestamp() -> PcapTimestamp {
    PcapTimestamp::micros(91, 200).expect("SCTP IPv6 pcap timestamp should be valid")
}

fn raw_ipv4_udp_sctp_data_timestamp() -> PcapTimestamp {
    PcapTimestamp::micros(91, 300).expect("SCTP UDP pcap timestamp should be valid")
}

fn raw_ipv4_sctp_data_pcap_bytes() -> Vec<u8> {
    pcap_bytes(&raw_ipv4_sctp_data_packet(), raw_ipv4_sctp_data_timestamp())
}

fn raw_ipv6_sctp_data_pcap_bytes() -> Vec<u8> {
    pcap_bytes(&raw_ipv6_sctp_data_packet(), raw_ipv6_sctp_data_timestamp())
}

fn raw_ipv4_udp_sctp_data_pcap_bytes() -> Vec<u8> {
    pcap_bytes(
        &raw_ipv4_udp_sctp_data_packet(),
        raw_ipv4_udp_sctp_data_timestamp(),
    )
}

fn assert_direct_ipv4_sctp_packet(packet: &Packet) {
    let ipv4 = packet.layer::<Ipv4>().expect("IPv4 layer");
    assert_eq!(ipv4.source(), DOC_V4_SRC);
    assert_eq!(ipv4.destination(), DOC_V4_DST);
    assert_eq!(ipv4.identification_value(), 0x5091);
    assert_eq!(ipv4.ttl_value(), 64);
    assert_eq!(ipv4.protocol_value(), IPPROTO_SCTP);

    let sctp = packet.layer::<Sctp>().expect("SCTP layer");
    assert_eq!(sctp.source_port_value(), 21_091);
    assert_eq!(sctp.destination_port_value(), 21_092);
    assert_eq!(sctp.verification_tag_value(), 0x1122_3391);
    assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Valid);
    assert_eq!(sctp.chunk_count(), 1);
    let SctpChunk::Data(data) = &sctp.chunks()[0] else {
        panic!("expected direct IPv4 SCTP DATA chunk");
    };
    assert_eq!(
        data.user_data()
            .expect("direct IPv4 SCTP DATA payload should parse"),
        b"pcap-v4"
    );
    assert_eq!(
        data.ppid()
            .expect("direct IPv4 SCTP DATA PPID should parse"),
        SCTP_PPID_WEBRTC_STRING
    );
    assert!(packet.layer::<Udp>().is_none());
    assert!(packet.layer::<Raw>().is_none());
}

fn assert_direct_ipv6_sctp_packet(packet: &Packet) {
    let ipv6 = packet.layer::<Ipv6>().expect("IPv6 layer");
    assert_eq!(ipv6.source(), DOC_V6_SRC);
    assert_eq!(ipv6.destination(), DOC_V6_DST);
    assert_eq!(ipv6.hop_limit_value(), 64);
    assert_eq!(ipv6.next_header_value(), IPPROTO_SCTP);

    let sctp = packet.layer::<Sctp>().expect("SCTP layer");
    assert_eq!(sctp.source_port_value(), 21_093);
    assert_eq!(sctp.destination_port_value(), 21_094);
    assert_eq!(sctp.verification_tag_value(), 0x1122_6691);
    assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Valid);
    assert_eq!(sctp.chunk_count(), 1);
    let SctpChunk::Data(data) = &sctp.chunks()[0] else {
        panic!("expected direct IPv6 SCTP DATA chunk");
    };
    assert_eq!(
        data.user_data()
            .expect("direct IPv6 SCTP DATA payload should parse"),
        b"pcap-v6"
    );
    assert_eq!(
        data.ppid()
            .expect("direct IPv6 SCTP DATA PPID should parse"),
        SCTP_PPID_WEBRTC_BINARY
    );
    assert!(packet.layer::<Udp>().is_none());
    assert!(packet.layer::<Raw>().is_none());
}

fn assert_udp_encapsulated_sctp_packet(packet: &Packet) {
    let ipv4 = packet.layer::<Ipv4>().expect("IPv4 layer");
    assert_eq!(ipv4.source(), DOC_V4_UDP_SRC);
    assert_eq!(ipv4.destination(), DOC_V4_UDP_DST);
    assert_eq!(ipv4.identification_value(), 0x5191);
    assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

    let udp = packet.layer::<Udp>().expect("UDP layer");
    assert_eq!(udp.source_port_value(), 49_191);
    assert_eq!(udp.destination_port_value(), SCTP_UDP_ENCAPSULATION_PORT);
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);

    let sctp = packet.layer::<Sctp>().expect("UDP-encapsulated SCTP layer");
    assert_eq!(sctp.source_port_value(), 21_095);
    assert_eq!(sctp.destination_port_value(), 21_096);
    assert_eq!(sctp.verification_tag_value(), 0x1122_9991);
    assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Valid);
    assert_eq!(sctp.chunk_count(), 1);
    let SctpChunk::Data(data) = &sctp.chunks()[0] else {
        panic!("expected UDP-encapsulated SCTP DATA chunk");
    };
    assert_eq!(
        data.user_data()
            .expect("UDP-encapsulated SCTP DATA payload should parse"),
        b"pcap-udp-v4"
    );
    assert!(packet.layer::<Raw>().is_none());
}

fn assert_sctp_pcap_fixture(
    path: &str,
    timestamp: PcapTimestamp,
    expected_record: &[u8],
    expected_pcap: Vec<u8>,
    assert_packet: fn(&Packet),
) {
    let fixture = fs::read(fixture_path(path)).expect("SCTP pcap fixture should exist");
    assert_eq!(fixture, expected_pcap);

    let reader =
        PcapReader::from_reader(fixture.as_slice()).expect("SCTP pcap fixture should parse header");
    assert_eq!(reader.header().pcap_link_type(), PcapLinkType::RawIp);
    assert_eq!(reader.header().link_type(), LinkType::Raw);
    assert_eq!(
        reader.header().precision(),
        TimestampPrecision::Microseconds
    );

    let records = PcapReader::from_reader(fixture.as_slice())
        .expect("SCTP pcap fixture should parse header for records")
        .collect_records()
        .expect("SCTP pcap fixture should read records");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.timestamp(), timestamp);
    assert_eq!(record.pcap_link_type(), PcapLinkType::RawIp);
    assert_eq!(record.link_type(), LinkType::Raw);
    assert_eq!(record.captured_len(), expected_record.len() as u32);
    assert_eq!(record.original_len(), expected_record.len() as u32);
    assert_eq!(record.data(), expected_record);

    let packets = PcapReader::from_reader(fixture.as_slice())
        .expect("SCTP pcap fixture should parse header for packets")
        .collect_packets()
        .expect("SCTP pcap fixture should decode packets");
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].timestamp(), timestamp);
    assert_eq!(packets[0].pcap_link_type(), PcapLinkType::RawIp);
    assert_eq!(packets[0].link_type(), LinkType::Raw);
    assert_eq!(packets[0].data(), expected_record);
    assert_packet(packets[0].packet());

    let mut rewritten = Vec::new();
    {
        let options =
            PcapWriterOptions::new(PcapLinkType::RawIp).precision(TimestampPrecision::Microseconds);
        let mut writer = PcapWriter::from_writer_with_options(&mut rewritten, options)
            .expect("SCTP pcap writer should initialize");
        writer
            .write_record(record)
            .expect("SCTP pcap record should rewrite");
        writer.flush().expect("SCTP pcap writer should flush");
    }
    assert_eq!(rewritten, fixture);
}

#[test]
fn sctp_pcap_fixture_raw_ip_files_match_writer_decode_and_rewrite() {
    assert_sctp_pcap_fixture(
        RAW_IPV4_SCTP_DATA_PCAP,
        raw_ipv4_sctp_data_timestamp(),
        &raw_ipv4_sctp_data_bytes(),
        raw_ipv4_sctp_data_pcap_bytes(),
        assert_direct_ipv4_sctp_packet,
    );
    assert_sctp_pcap_fixture(
        RAW_IPV6_SCTP_DATA_PCAP,
        raw_ipv6_sctp_data_timestamp(),
        &raw_ipv6_sctp_data_bytes(),
        raw_ipv6_sctp_data_pcap_bytes(),
        assert_direct_ipv6_sctp_packet,
    );
    assert_sctp_pcap_fixture(
        RAW_IPV4_UDP_SCTP_DATA_PCAP,
        raw_ipv4_udp_sctp_data_timestamp(),
        &raw_ipv4_udp_sctp_data_bytes(),
        raw_ipv4_udp_sctp_data_pcap_bytes(),
        assert_udp_encapsulated_sctp_packet,
    );
}

#[test]
#[ignore = "regenerates the committed SCTP pcap fixtures"]
fn sctp_pcap_fixture_write_fixtures() {
    fs::write(
        fixture_path(RAW_IPV4_SCTP_DATA_PCAP),
        raw_ipv4_sctp_data_pcap_bytes(),
    )
    .expect("SCTP IPv4 pcap fixture should write");
    fs::write(
        fixture_path(RAW_IPV6_SCTP_DATA_PCAP),
        raw_ipv6_sctp_data_pcap_bytes(),
    )
    .expect("SCTP IPv6 pcap fixture should write");
    fs::write(
        fixture_path(RAW_IPV4_UDP_SCTP_DATA_PCAP),
        raw_ipv4_udp_sctp_data_pcap_bytes(),
    )
    .expect("SCTP UDP pcap fixture should write");
}
