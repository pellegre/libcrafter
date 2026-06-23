//! End-to-end pcap path for IEEE 802.15.4 frames.
//!
//! Mirrors `ble_pcap.rs`: a committed pcap fixture is read, the records decode
//! into the expected typed layers, the records are re-written to an in-memory
//! pcap, and the output is asserted to round-trip byte-for-byte and re-decode
//! identically. Two link types are exercised — the TAP pseudo-header form
//! (DLT 283, `Dot15d4Radio` + `Dot15d4`) and the bare MAC-with-FCS form
//! (DLT 195, `Dot15d4` only).

use std::fs;
use std::path::PathBuf;

use crafter::wire::backend::pcap::{
    PcapLinkType, PcapReader, PcapRecord, PcapTimestamp, PcapWriter, PcapWriterOptions,
    TimestampPrecision, DLT_IEEE802_15_4_TAP, DLT_IEEE802_15_4_WITHFCS,
};
use crafter::{Dot15d4, Dot15d4Radio, Layer, LinkType, Packet};

const TAP_PCAP_FIXTURE: &str = "pcaps/dot15d4-tap.pcap";
const WITHFCS_PCAP_FIXTURE: &str = "pcaps/dot15d4-withfcs.pcap";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn dot15d4_pcap_timestamp() -> PcapTimestamp {
    PcapTimestamp::micros(15, 4).expect("802.15.4 fixture timestamp should be valid")
}

/// The TAP fixture frame: a `Dot15d4Radio` pseudo-header over a MAC data frame
/// using documentation-space PAN IDs and short addresses on channel 20. The MAC
/// frame carries no payload so it decodes into exactly the radio + MAC layers
/// (an unmodeled payload would surface as a trailing `Raw` layer).
fn dot15d4_tap_packet() -> Packet {
    Dot15d4Radio::on_channel(20).rssi(-55).fcs_valid(true)
        / Dot15d4::data()
            .seq(9)
            .dest_short(0x1234, 0x0000)
            .src_short(0x1234, 0xABCD)
}

/// The with-FCS fixture frame: a bare MAC data frame (no radio pseudo-header,
/// no payload) so it decodes into exactly the MAC layer.
fn dot15d4_withfcs_packet() -> Packet {
    Packet::new().push(
        Dot15d4::data()
            .seq(7)
            .dest_short(0x1234, 0x0000)
            .src_short(0x1234, 0xABCD),
    )
}

fn dot15d4_tap_record_bytes() -> Vec<u8> {
    dot15d4_tap_packet()
        .compile()
        .expect("802.15.4 TAP fixture packet should compile")
        .as_bytes()
        .to_vec()
}

fn dot15d4_withfcs_record_bytes() -> Vec<u8> {
    dot15d4_withfcs_packet()
        .compile()
        .expect("802.15.4 with-FCS fixture packet should compile")
        .as_bytes()
        .to_vec()
}

fn dot15d4_pcap_bytes(link_type: PcapLinkType, record_bytes: Vec<u8>) -> Vec<u8> {
    let record = PcapRecord::new(
        dot15d4_pcap_timestamp(),
        record_bytes.len() as u32,
        record_bytes,
        link_type,
    )
    .expect("802.15.4 fixture record should be valid");

    let options = PcapWriterOptions::new(link_type).precision(TimestampPrecision::Microseconds);
    let mut pcap = Vec::new();
    {
        let mut writer = PcapWriter::from_writer_with_options(&mut pcap, options)
            .expect("802.15.4 fixture pcap writer should initialize");
        writer
            .write_record(&record)
            .expect("802.15.4 fixture pcap record should write");
        writer.flush().expect("802.15.4 fixture pcap should flush");
    }
    pcap
}

fn dot15d4_tap_pcap_bytes() -> Vec<u8> {
    dot15d4_pcap_bytes(PcapLinkType::Ieee802154Tap, dot15d4_tap_record_bytes())
}

fn dot15d4_withfcs_pcap_bytes() -> Vec<u8> {
    dot15d4_pcap_bytes(
        PcapLinkType::Ieee802154WithFcs,
        dot15d4_withfcs_record_bytes(),
    )
}

#[test]
fn dot15d4_tap_pcap_roundtrip_fixture_decodes_and_rewrites() {
    let fixture =
        fs::read(fixture_path(TAP_PCAP_FIXTURE)).expect("802.15.4 TAP pcap fixture should exist");
    assert_eq!(fixture, dot15d4_tap_pcap_bytes());

    let reader = PcapReader::from_reader(fixture.as_slice())
        .expect("802.15.4 TAP pcap fixture should parse header");
    assert_eq!(
        reader.header().pcap_link_type(),
        PcapLinkType::Ieee802154Tap
    );
    assert_eq!(reader.header().link_type(), LinkType::Ieee802154Tap);
    assert_eq!(
        reader.header().precision(),
        TimestampPrecision::Microseconds
    );
    assert_eq!(
        reader.header().pcap_link_type().datalink(),
        DLT_IEEE802_15_4_TAP
    );

    let records = PcapReader::from_reader(fixture.as_slice())
        .expect("802.15.4 TAP pcap fixture should parse header for records")
        .collect_records()
        .expect("802.15.4 TAP pcap fixture should read records");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    let expected_record = dot15d4_tap_record_bytes();
    assert_eq!(record.timestamp(), dot15d4_pcap_timestamp());
    assert_eq!(record.pcap_link_type(), PcapLinkType::Ieee802154Tap);
    assert_eq!(record.link_type(), LinkType::Ieee802154Tap);
    assert_eq!(record.captured_len(), expected_record.len() as u32);
    assert_eq!(record.original_len(), expected_record.len() as u32);
    assert_eq!(record.data(), expected_record.as_slice());

    let packets = PcapReader::from_reader(fixture.as_slice())
        .expect("802.15.4 TAP pcap fixture should parse header for packets")
        .collect_packets()
        .expect("802.15.4 TAP pcap fixture should decode packets");
    assert_eq!(packets.len(), 1);
    let packet = packets[0].packet();
    let layer_names = packet.iter().map(|layer| layer.name()).collect::<Vec<_>>();
    assert_eq!(layer_names, vec!["Dot15d4Radio", "Dot15d4"]);

    let radio = packet
        .layer::<Dot15d4Radio>()
        .expect("decoded 802.15.4 radio layer");
    assert!(
        radio.summary().contains("ch=20"),
        "radio summary: {}",
        radio.summary()
    );

    let mac = packet
        .layer::<Dot15d4>()
        .expect("decoded 802.15.4 MAC layer");
    let mac_summary = mac.summary();
    assert!(mac_summary.contains("Data"), "mac summary: {mac_summary}");
    assert!(mac_summary.contains("seq=9"), "mac summary: {mac_summary}");
    assert!(
        mac_summary.contains("dst=0x0000"),
        "mac summary: {mac_summary}"
    );
    assert!(
        mac_summary.contains("src=0xABCD"),
        "mac summary: {mac_summary}"
    );

    let mut rewritten = Vec::new();
    {
        let options = PcapWriterOptions::new(PcapLinkType::Ieee802154Tap)
            .precision(TimestampPrecision::Microseconds);
        let mut writer = PcapWriter::from_writer_with_options(&mut rewritten, options)
            .expect("802.15.4 TAP pcap writer should initialize");
        writer
            .write_record(record)
            .expect("802.15.4 TAP pcap record should rewrite");
        writer
            .flush()
            .expect("802.15.4 TAP pcap writer should flush");
    }
    assert_eq!(rewritten, fixture);
}

#[test]
fn dot15d4_withfcs_pcap_roundtrip_fixture_decodes_and_rewrites() {
    let fixture = fs::read(fixture_path(WITHFCS_PCAP_FIXTURE))
        .expect("802.15.4 with-FCS pcap fixture should exist");
    assert_eq!(fixture, dot15d4_withfcs_pcap_bytes());

    let reader = PcapReader::from_reader(fixture.as_slice())
        .expect("802.15.4 with-FCS pcap fixture should parse header");
    assert_eq!(
        reader.header().pcap_link_type(),
        PcapLinkType::Ieee802154WithFcs
    );
    assert_eq!(reader.header().link_type(), LinkType::Ieee802154);
    assert_eq!(
        reader.header().precision(),
        TimestampPrecision::Microseconds
    );
    assert_eq!(
        reader.header().pcap_link_type().datalink(),
        DLT_IEEE802_15_4_WITHFCS
    );

    let records = PcapReader::from_reader(fixture.as_slice())
        .expect("802.15.4 with-FCS pcap fixture should parse header for records")
        .collect_records()
        .expect("802.15.4 with-FCS pcap fixture should read records");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    let expected_record = dot15d4_withfcs_record_bytes();
    assert_eq!(record.timestamp(), dot15d4_pcap_timestamp());
    assert_eq!(record.pcap_link_type(), PcapLinkType::Ieee802154WithFcs);
    assert_eq!(record.link_type(), LinkType::Ieee802154);
    assert_eq!(record.captured_len(), expected_record.len() as u32);
    assert_eq!(record.original_len(), expected_record.len() as u32);
    assert_eq!(record.data(), expected_record.as_slice());

    let packets = PcapReader::from_reader(fixture.as_slice())
        .expect("802.15.4 with-FCS pcap fixture should parse header for packets")
        .collect_packets()
        .expect("802.15.4 with-FCS pcap fixture should decode packets");
    assert_eq!(packets.len(), 1);
    let packet = packets[0].packet();
    let layer_names = packet.iter().map(|layer| layer.name()).collect::<Vec<_>>();
    assert_eq!(layer_names, vec!["Dot15d4"]);
    assert!(
        packet.layer::<Dot15d4Radio>().is_none(),
        "bare MAC decode must not carry a radio pseudo-header"
    );

    let mac = packet
        .layer::<Dot15d4>()
        .expect("decoded 802.15.4 MAC layer");
    let mac_summary = mac.summary();
    assert!(mac_summary.contains("Data"), "mac summary: {mac_summary}");
    assert!(mac_summary.contains("seq=7"), "mac summary: {mac_summary}");
    assert!(
        mac_summary.contains("dst=0x0000"),
        "mac summary: {mac_summary}"
    );
    assert!(
        mac_summary.contains("src=0xABCD"),
        "mac summary: {mac_summary}"
    );

    let mut rewritten = Vec::new();
    {
        let options = PcapWriterOptions::new(PcapLinkType::Ieee802154WithFcs)
            .precision(TimestampPrecision::Microseconds);
        let mut writer = PcapWriter::from_writer_with_options(&mut rewritten, options)
            .expect("802.15.4 with-FCS pcap writer should initialize");
        writer
            .write_record(record)
            .expect("802.15.4 with-FCS pcap record should rewrite");
        writer
            .flush()
            .expect("802.15.4 with-FCS pcap writer should flush");
    }
    assert_eq!(rewritten, fixture);
}

#[test]
#[ignore = "regenerates the committed 802.15.4 pcap fixtures"]
fn dot15d4_pcap_write_fixtures() {
    fs::write(fixture_path(TAP_PCAP_FIXTURE), dot15d4_tap_pcap_bytes())
        .expect("802.15.4 TAP pcap fixture should write");
    fs::write(
        fixture_path(WITHFCS_PCAP_FIXTURE),
        dot15d4_withfcs_pcap_bytes(),
    )
    .expect("802.15.4 with-FCS pcap fixture should write");
}
