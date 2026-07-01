//! Deterministic TLS pcap fixture generation and roundtrip checks.
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

const RAW_IP_TLS_PCAP: &str = "pcaps/raw-ipv4-tcp-tls-client-hello.pcap";
const ETHERNET_TLS_PCAP: &str = "pcaps/ethernet-ipv4-tcp-tls-client-hello.pcap";

const DOC_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 68);
const DOC_SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 68);
const DOC_CLIENT_PORT: u16 = 49_168;
const DOC_CLIENT_MAC: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x54, 0x68]);
const DOC_SERVER_MAC: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x54, 0x69]);

fn fixture_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

fn tls_client_hello_record() -> crafter::Result<TlsRecord> {
    let hello = TlsClientHello::new()
        .with_random([0x68; TLS_CLIENT_HELLO_RANDOM_LEN])
        .with_session_id([0x68, 0x69, 0x6a, 0x6b])
        .with_raw_cipher_suites([
            TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
            TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
        ])
        .with_extensions(vec![
            TlsRawExtension::server_name(TlsServerNameList::from_host_name(
                "tls.pcap.example.test",
            ))?,
            TlsRawExtension::alpn(TlsAlpnProtocols::h2_then_http_1_1())?,
            TlsRawExtension::supported_versions_client(vec![
                TlsVersion::tls_1_3(),
                TlsVersion::tls_1_2(),
            ])?,
            TlsRawExtension::supported_groups(TlsSupportedGroups::from_raws([
                TLS_NAMED_GROUP_X25519,
                TLS_NAMED_GROUP_SECP256R1,
            ]))?,
            TlsRawExtension::signature_algorithms(TlsSignatureAlgorithms::from_raws([
                TLS_SIGNATURE_SCHEME_ED25519,
                TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256,
            ]))?,
            TlsRawExtension::key_share_client(vec![TlsKeyShareEntry::x25519([0x68; 32])])?,
        ]);
    TlsRecord::handshake_messages([TlsHandshake::from_client_hello(hello)?])
}

fn tls_alert_record() -> TlsRecord {
    TlsRecord::alert(TlsAlert::decode_error().encode_to_vec())
}

fn tls_application_data_record() -> TlsRecord {
    TlsRecord::application_data([0xde, 0xad, 0xbe, 0xef, 0x68, 0x00, 0x01])
}

fn raw_ipv4_tls_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    id: u16,
    seq: u32,
    ack: u32,
    record: TlsRecord,
) -> Packet {
    Ipv4::new().src(src).dst(dst).id(id).ttl(64)
        / Tcp::new()
            .sport(sport)
            .dport(dport)
            .seq(seq)
            .ack(ack)
            .ack_segment()
        / Tls::from_record(record)
}

fn ethernet_ipv4_tls_packet(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    id: u16,
    seq: u32,
    ack: u32,
    record: TlsRecord,
) -> Packet {
    Ethernet::with_addresses(src_mac, dst_mac)
        / Ipv4::new().src(src).dst(dst).id(id).ttl(64)
        / Tcp::new()
            .sport(sport)
            .dport(dport)
            .seq(seq)
            .ack(ack)
            .ack_segment()
        / Tls::from_record(record)
}

fn raw_ip_tls_packets() -> crafter::Result<Vec<(Packet, PcapTimestamp)>> {
    Ok(vec![
        (
            raw_ipv4_tls_packet(
                DOC_CLIENT,
                DOC_SERVER,
                DOC_CLIENT_PORT,
                TLS_PORT_HTTPS,
                0x6801,
                0x6801_0001,
                0x6802_0001,
                tls_client_hello_record()?,
            ),
            PcapTimestamp::micros(68, 1).expect("TLS pcap timestamp should be valid"),
        ),
        (
            raw_ipv4_tls_packet(
                DOC_SERVER,
                DOC_CLIENT,
                TLS_PORT_HTTPS,
                DOC_CLIENT_PORT,
                0x6802,
                0x6802_0001,
                0x6801_00a0,
                tls_alert_record(),
            ),
            PcapTimestamp::micros(68, 2).expect("TLS pcap timestamp should be valid"),
        ),
        (
            raw_ipv4_tls_packet(
                DOC_CLIENT,
                DOC_SERVER,
                DOC_CLIENT_PORT,
                TLS_PORT_HTTPS,
                0x6803,
                0x6801_00a0,
                0x6802_0008,
                tls_application_data_record(),
            ),
            PcapTimestamp::micros(68, 3).expect("TLS pcap timestamp should be valid"),
        ),
    ])
}

fn ethernet_tls_packets() -> crafter::Result<Vec<(Packet, PcapTimestamp)>> {
    Ok(vec![
        (
            ethernet_ipv4_tls_packet(
                DOC_CLIENT_MAC,
                DOC_SERVER_MAC,
                DOC_CLIENT,
                DOC_SERVER,
                DOC_CLIENT_PORT,
                TLS_PORT_HTTPS,
                0x6811,
                0x6811_0001,
                0x6812_0001,
                tls_client_hello_record()?,
            ),
            PcapTimestamp::micros(68, 11).expect("TLS pcap timestamp should be valid"),
        ),
        (
            ethernet_ipv4_tls_packet(
                DOC_SERVER_MAC,
                DOC_CLIENT_MAC,
                DOC_SERVER,
                DOC_CLIENT,
                TLS_PORT_HTTPS,
                DOC_CLIENT_PORT,
                0x6812,
                0x6812_0001,
                0x6811_00a0,
                tls_alert_record(),
            ),
            PcapTimestamp::micros(68, 12).expect("TLS pcap timestamp should be valid"),
        ),
        (
            ethernet_ipv4_tls_packet(
                DOC_CLIENT_MAC,
                DOC_SERVER_MAC,
                DOC_CLIENT,
                DOC_SERVER,
                DOC_CLIENT_PORT,
                TLS_PORT_HTTPS,
                0x6813,
                0x6811_00a0,
                0x6812_0008,
                tls_application_data_record(),
            ),
            PcapTimestamp::micros(68, 13).expect("TLS pcap timestamp should be valid"),
        ),
    ])
}

fn compiled_bytes(packet: &Packet) -> Vec<u8> {
    packet
        .compile()
        .expect("TLS fixture packet should compile")
        .as_bytes()
        .to_vec()
}

fn pcap_bytes(link_type: PcapLinkType, packets: &[(Packet, PcapTimestamp)]) -> Vec<u8> {
    let options = PcapWriterOptions::new(link_type).precision(TimestampPrecision::Microseconds);
    let mut pcap = Vec::new();
    {
        let mut writer = PcapWriter::from_writer_with_options(&mut pcap, options)
            .expect("TLS pcap writer should initialize");
        for (packet, timestamp) in packets {
            writer
                .write_packet_with_timestamp(packet, *timestamp)
                .expect("TLS pcap packet should write");
        }
        writer.flush().expect("TLS pcap writer should flush");
    }
    pcap
}

fn raw_ip_tls_pcap_bytes() -> crafter::Result<Vec<u8>> {
    Ok(pcap_bytes(PcapLinkType::RawIp, &raw_ip_tls_packets()?))
}

fn ethernet_tls_pcap_bytes() -> crafter::Result<Vec<u8>> {
    Ok(pcap_bytes(PcapLinkType::Ethernet, &ethernet_tls_packets()?))
}

#[test]
fn tls_pcap_roundtrip_fixtures_decode_and_rewrite() -> crafter::Result<()> {
    assert_tls_pcap_fixture(
        RAW_IP_TLS_PCAP,
        PcapLinkType::RawIp,
        LinkType::Raw,
        raw_ip_tls_packets()?,
        raw_ip_tls_pcap_bytes()?,
    )?;
    assert_tls_pcap_fixture(
        ETHERNET_TLS_PCAP,
        PcapLinkType::Ethernet,
        LinkType::Ethernet,
        ethernet_tls_packets()?,
        ethernet_tls_pcap_bytes()?,
    )?;
    Ok(())
}

fn assert_tls_pcap_fixture(
    path: &str,
    pcap_link_type: PcapLinkType,
    link_type: LinkType,
    packets: Vec<(Packet, PcapTimestamp)>,
    expected_pcap: Vec<u8>,
) -> crafter::Result<()> {
    let fixture = fs::read(fixture_path(path)).expect("TLS pcap fixture should exist");
    assert_eq!(fixture, expected_pcap);

    let reader =
        PcapReader::from_reader(fixture.as_slice()).expect("TLS pcap fixture should parse header");
    assert_eq!(reader.header().pcap_link_type(), pcap_link_type);
    assert_eq!(reader.header().link_type(), link_type);
    assert_eq!(
        reader.header().precision(),
        TimestampPrecision::Microseconds
    );

    let expected_records = packets
        .iter()
        .map(|(packet, timestamp)| (compiled_bytes(packet), *timestamp))
        .collect::<Vec<_>>();
    let records = PcapReader::from_reader(fixture.as_slice())
        .expect("TLS pcap fixture should parse header for records")
        .collect_records()
        .expect("TLS pcap fixture should read records");
    assert_eq!(records.len(), expected_records.len());
    for (record, (expected_record, expected_timestamp)) in records.iter().zip(&expected_records) {
        assert_eq!(record.timestamp(), *expected_timestamp);
        assert_eq!(record.pcap_link_type(), pcap_link_type);
        assert_eq!(record.link_type(), link_type);
        assert_eq!(record.captured_len(), expected_record.len() as u32);
        assert_eq!(record.original_len(), expected_record.len() as u32);
        assert_eq!(record.data(), expected_record.as_slice());
    }

    let decoded = PcapReader::from_reader(fixture.as_slice())
        .expect("TLS pcap fixture should parse header for packets")
        .collect_packets()
        .expect("TLS pcap fixture should decode packets");
    assert_eq!(decoded.len(), expected_records.len());
    assert_tls_packet(decoded[0].packet(), TlsContentType::handshake());
    assert_tls_packet(decoded[1].packet(), TlsContentType::alert());
    assert_tls_packet(decoded[2].packet(), TlsContentType::application_data());

    let mut rewritten = Vec::new();
    {
        let options =
            PcapWriterOptions::new(pcap_link_type).precision(TimestampPrecision::Microseconds);
        let mut writer = PcapWriter::from_writer_with_options(&mut rewritten, options)
            .expect("TLS pcap writer should initialize");
        for record in &records {
            writer
                .write_record(record)
                .expect("TLS pcap record should rewrite");
        }
        writer.flush().expect("TLS pcap writer should flush");
    }
    assert_eq!(rewritten, fixture);
    Ok(())
}

fn assert_tls_packet(packet: &Packet, expected_content_type: TlsContentType) {
    let tcp = packet
        .layer::<Tcp>()
        .expect("TLS pcap packet should have TCP");
    let tls = packet
        .layer::<Tls>()
        .expect("TLS pcap packet should have TLS");

    assert!(
        (tcp.source_port_value() == DOC_CLIENT_PORT
            && tcp.destination_port_value() == TLS_PORT_HTTPS)
            || (tcp.source_port_value() == TLS_PORT_HTTPS
                && tcp.destination_port_value() == DOC_CLIENT_PORT)
    );
    assert_eq!(tls.record_count(), 1);
    assert_eq!(tls.records()[0].content_type(), expected_content_type);

    match expected_content_type {
        TlsContentType::HANDSHAKE => {
            let messages = tls.records()[0]
                .body()
                .handshake_messages()
                .expect("TLS pcap ClientHello should decode as handshake");
            assert_eq!(messages.len(), 1);
            assert!(
                messages[0].client_hello_body().is_some(),
                "TLS pcap handshake should be a ClientHello"
            );
        }
        TlsContentType::ALERT => {
            assert_eq!(
                TlsAlert::decode(tls.records()[0].fragment())
                    .expect("TLS pcap alert should decode"),
                TlsAlert::decode_error()
            );
        }
        TlsContentType::APPLICATION_DATA => {
            assert_eq!(
                tls.records()[0]
                    .application_data_body()
                    .expect("TLS pcap application_data should decode")
                    .bytes(),
                &[0xde, 0xad, 0xbe, 0xef, 0x68, 0x00, 0x01]
            );
        }
        _ => unreachable!("TLS pcap fixture only uses selected content types"),
    }
}

#[test]
#[ignore = "regenerates the committed TLS pcap fixtures"]
fn tls_pcap_write_fixtures() {
    fs::write(
        fixture_path(RAW_IP_TLS_PCAP),
        raw_ip_tls_pcap_bytes().expect("RawIp TLS pcap fixture should build"),
    )
    .expect("RawIp TLS pcap fixture should write");
    fs::write(
        fixture_path(ETHERNET_TLS_PCAP),
        ethernet_tls_pcap_bytes().expect("Ethernet TLS pcap fixture should build"),
    )
    .expect("Ethernet TLS pcap fixture should write");
}
