//! Deterministic TLS pcap fixture generation and roundtrip checks.
//!
//! These fixtures are synthetic, offline-only, and use documentation address
//! space plus locally administered documentation MAC addresses.

use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crafter::prelude::*;
use crafter::wire::backend::pcap::{
    PcapLinkType, PcapReader, PcapRecord, PcapTimestamp, PcapWriter, PcapWriterOptions,
    TimestampPrecision,
};

const RAW_IP_TLS_PCAP: &str = "pcaps/raw-ipv4-tcp-tls-client-hello.pcap";
const ETHERNET_TLS_PCAP: &str = "pcaps/ethernet-ipv4-tcp-tls-client-hello.pcap";
const RAW_IP_TLS_CLIENT_HELLO_HEX: &str = "bytes/ipv4-tcp-tls-client-hello.hex";
const RAW_IP_TLS_ALERT_HEX: &str = "bytes/ipv4-tcp-tls-alert.hex";
const RAW_IP_TLS_APPLICATION_DATA_HEX: &str = "bytes/ipv4-tcp-tls-application-data.hex";
const ETHERNET_TLS_CLIENT_HELLO_HEX: &str = "bytes/ethernet-ipv4-tcp-tls-client-hello.hex";
const ETHERNET_TLS_ALERT_HEX: &str = "bytes/ethernet-ipv4-tcp-tls-alert.hex";
const ETHERNET_TLS_APPLICATION_DATA_HEX: &str = "bytes/ethernet-ipv4-tcp-tls-application-data.hex";
const RAW_IP_TLS_PORT_RAW_FALLBACK_HEX: &str = "bytes/ipv4-tcp-tls-port-raw-fallback.hex";

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

struct TempPcap {
    path: PathBuf,
}

impl TempPcap {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after Unix epoch")
            .as_nanos();
        Self {
            path: std::env::temp_dir().join(format!(
                "crafter-tls-{label}-{}-{nanos}.pcap",
                std::process::id()
            )),
        }
    }

    fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl Drop for TempPcap {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
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

fn tls_port_raw_fallback_packet() -> Packet {
    Ipv4::new()
        .src(DOC_CLIENT)
        .dst(DOC_SERVER)
        .id(0x6820)
        .ttl(64)
        / Tcp::new()
            .sport(DOC_CLIENT_PORT)
            .dport(TLS_PORT_HTTPS)
            .seq(0x6820_0001)
            .ack(0x6821_0001)
            .ack_segment()
        / Raw::from("not-a-tls-record")
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

fn expected_packet_summaries(pcap_link_type: PcapLinkType, records: &[PcapRecord]) -> Vec<String> {
    records
        .iter()
        .map(|record| {
            pcap_link_type
                .decode(record.data())
                .expect("TLS pcap record should decode for expected summary")
                .summary()
        })
        .collect()
}

fn sniff_filtered_tls_pcap(path: &str) -> Vec<PacketRecord> {
    let source = PacketWire::pcap_file(fixture_path(path))
        .filter("tcp port 443")
        .open()
        .expect("TLS pcap PacketWire should open")
        .source()
        .expect("TLS pcap PacketWire should expose source");
    Sniffer::new(source)
        .no_timeout()
        .collect_records()
        .expect("filtered TLS pcap records should sniff")
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

#[test]
fn tls_pcap_read_write_filtered_sniffer_decodes_tls_fixtures() -> crafter::Result<()> {
    assert_filtered_tls_pcap_fixture(
        RAW_IP_TLS_PCAP,
        PcapLinkType::RawIp,
        LinkType::Raw,
        &[
            TlsContentType::handshake(),
            TlsContentType::alert(),
            TlsContentType::application_data(),
        ],
    );
    assert_filtered_tls_pcap_fixture(
        ETHERNET_TLS_PCAP,
        PcapLinkType::Ethernet,
        LinkType::Ethernet,
        &[
            TlsContentType::handshake(),
            TlsContentType::alert(),
            TlsContentType::application_data(),
        ],
    );
    Ok(())
}

fn assert_filtered_tls_pcap_fixture(
    path: &str,
    pcap_link_type: PcapLinkType,
    link_type: LinkType,
    expected_content_types: &[TlsContentType],
) {
    let fixture_path = fixture_path(path);
    let fixture = fs::read(&fixture_path).expect("TLS pcap fixture should exist");
    let pcap_records = PcapReader::from_reader(fixture.as_slice())
        .expect("TLS pcap fixture should parse for raw records")
        .collect_records()
        .expect("TLS pcap fixture records should read");
    let expected_summaries = expected_packet_summaries(pcap_link_type, &pcap_records);

    let records = sniff_filtered_tls_pcap(path);
    assert_eq!(records.len(), expected_content_types.len());
    assert_eq!(records.len(), pcap_records.len());

    for ((record, pcap_record), expected_content_type) in records
        .iter()
        .zip(&pcap_records)
        .zip(expected_content_types.iter().copied())
    {
        assert_eq!(record.metadata().backend(), &BackendKind::PcapFile);
        assert_eq!(record.metadata().file(), Some(fixture_path.as_path()));
        assert_eq!(record.metadata().timestamp(), Some(pcap_record.timestamp()));
        assert_eq!(
            record.metadata().original_len(),
            Some(pcap_record.original_len())
        );
        assert_eq!(
            record.metadata().captured_len(),
            Some(pcap_record.captured_len())
        );
        assert_eq!(record.metadata().captured_bytes(), Some(pcap_record.data()));
        assert_eq!(record.metadata().pcap_link_type(), Some(pcap_link_type));
        assert_eq!(record.metadata().link_type(), Some(link_type));
        assert_tls_packet(record.packet(), expected_content_type);
    }

    let actual_summaries = records
        .iter()
        .map(|record| record.packet().summary())
        .collect::<Vec<_>>();
    assert_eq!(actual_summaries, expected_summaries);
}

#[test]
fn tls_pcap_read_write_packet_wire_recorder_roundtrips_tls_records() -> crafter::Result<()> {
    let temp = TempPcap::new("packet-wire-roundtrip");
    let packets = raw_ip_tls_packets()?;
    let expected = packets
        .iter()
        .map(|(packet, timestamp)| {
            let bytes = compiled_bytes(packet);
            let summary = PcapLinkType::RawIp
                .decode(&bytes)
                .expect("TLS RawIp packet should decode for expected summary")
                .summary();
            (bytes, summary, *timestamp)
        })
        .collect::<Vec<_>>();

    {
        let writer = PacketWire::pcap_recorder(temp.path(), PcapLinkType::RawIp)
            .open()
            .expect("TLS pcap recorder should open")
            .writer()
            .expect("TLS pcap recorder should expose writer");
        let mut transmitter = Transmitter::new(writer);

        for ((packet, timestamp), (expected_bytes, _summary, _expected_timestamp)) in
            packets.iter().zip(&expected)
        {
            let record = PacketRecord::new(packet.clone())
                .with_pcap_link_type(PcapLinkType::RawIp)
                .with_timestamp(*timestamp);
            let reports = transmitter
                .write_record(record)
                .expect("TLS pcap record should write through transmitter");
            assert_eq!(reports.len(), 1);
            assert_eq!(reports[0].backend(), &BackendKind::PcapFile);
            assert_eq!(reports[0].bytes_requested(), expected_bytes.len());
            assert_eq!(reports[0].bytes_written(), expected_bytes.len());
            assert!(!reports[0].is_dry_run());
            assert_eq!(
                reports[0].target_details(),
                Some(temp.path().display().to_string().as_str())
            );
        }
    }

    let source = PacketWire::pcap_file(temp.path())
        .filter("tcp port 443")
        .open()
        .expect("written TLS pcap should open")
        .source()
        .expect("written TLS pcap should expose source");
    let records = Sniffer::new(source)
        .no_timeout()
        .collect_records()
        .expect("written TLS pcap should sniff");
    assert_eq!(records.len(), expected.len());

    for (index, (record, (expected_bytes, expected_summary, expected_timestamp))) in
        records.iter().zip(&expected).enumerate()
    {
        assert_eq!(record.metadata().backend(), &BackendKind::PcapFile);
        assert_eq!(record.metadata().file(), Some(temp.path().as_path()));
        assert_eq!(record.metadata().timestamp(), Some(*expected_timestamp));
        assert_eq!(
            record.metadata().original_len(),
            Some(expected_bytes.len() as u32)
        );
        assert_eq!(
            record.metadata().captured_len(),
            Some(expected_bytes.len() as u32)
        );
        assert_eq!(
            record.metadata().captured_bytes(),
            Some(expected_bytes.as_slice())
        );
        assert_eq!(
            record.metadata().pcap_link_type(),
            Some(PcapLinkType::RawIp)
        );
        assert_eq!(record.metadata().link_type(), Some(LinkType::Raw));
        assert_eq!(record.packet().summary(), *expected_summary);
        assert_tls_packet(
            record.packet(),
            [
                TlsContentType::handshake(),
                TlsContentType::alert(),
                TlsContentType::application_data(),
            ][index],
        );
    }

    let pcap_records = PcapReader::open(temp.path())
        .expect("written TLS pcap should parse")
        .collect_records()
        .expect("written TLS pcap records should read");
    let actual_bytes = pcap_records
        .iter()
        .map(|record| record.data().to_vec())
        .collect::<Vec<_>>();
    let expected_bytes = expected
        .iter()
        .map(|(bytes, _summary, _timestamp)| bytes.clone())
        .collect::<Vec<_>>();
    assert_eq!(actual_bytes, expected_bytes);

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

#[test]
#[ignore = "regenerates the committed TLS byte fixtures used by the pcap catalog"]
fn tls_pcap_write_byte_fixtures() -> crafter::Result<()> {
    let raw_packets = raw_ip_tls_packets()?;
    let ethernet_packets = ethernet_tls_packets()?;

    fs::write(
        fixture_path(RAW_IP_TLS_CLIENT_HELLO_HEX),
        encode_hex(&compiled_bytes(&raw_packets[0].0)),
    )
    .expect("RawIp TLS ClientHello byte fixture should write");
    fs::write(
        fixture_path(RAW_IP_TLS_ALERT_HEX),
        encode_hex(&compiled_bytes(&raw_packets[1].0)),
    )
    .expect("RawIp TLS alert byte fixture should write");
    fs::write(
        fixture_path(RAW_IP_TLS_APPLICATION_DATA_HEX),
        encode_hex(&compiled_bytes(&raw_packets[2].0)),
    )
    .expect("RawIp TLS application_data byte fixture should write");
    fs::write(
        fixture_path(ETHERNET_TLS_CLIENT_HELLO_HEX),
        encode_hex(&compiled_bytes(&ethernet_packets[0].0)),
    )
    .expect("Ethernet TLS ClientHello byte fixture should write");
    fs::write(
        fixture_path(ETHERNET_TLS_ALERT_HEX),
        encode_hex(&compiled_bytes(&ethernet_packets[1].0)),
    )
    .expect("Ethernet TLS alert byte fixture should write");
    fs::write(
        fixture_path(ETHERNET_TLS_APPLICATION_DATA_HEX),
        encode_hex(&compiled_bytes(&ethernet_packets[2].0)),
    )
    .expect("Ethernet TLS application_data byte fixture should write");
    fs::write(
        fixture_path(RAW_IP_TLS_PORT_RAW_FALLBACK_HEX),
        encode_hex(&compiled_bytes(&tls_port_raw_fallback_packet())),
    )
    .expect("TLS port raw fallback byte fixture should write");

    Ok(())
}
