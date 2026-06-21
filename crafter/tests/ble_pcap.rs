use std::fs;
use std::path::PathBuf;

use crafter::wire::backend::pcap::{
    PcapLinkType, PcapReader, PcapRecord, PcapTimestamp, PcapWriter, PcapWriterOptions,
    TimestampPrecision, DLT_BLUETOOTH_LE_LL_WITH_PHDR,
};
use crafter::{AdStructure, BleLlAdv, BleRadio, Layer, LinkType, MacAddr, Packet};

const BLE_PCAP_FIXTURE: &str = "pcaps/ble-le-ll-adv.pcap";
const BLE_RADIO_PSEUDO_HEADER_LEN: usize = 10;
const BLE_RADIO_ACCESS_ADDRESS_OFFSET: usize = 4;
const BLE_LL_ACCESS_ADDRESS_LEN: usize = 4;

fn ble_pcap_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(BLE_PCAP_FIXTURE)
}

fn ble_pcap_timestamp() -> PcapTimestamp {
    PcapTimestamp::micros(46, 37).expect("BLE fixture timestamp should be valid")
}

fn ble_le_ll_adv_decoded_packet() -> Packet {
    BleRadio::advertising(37).rssi(-40).crc_valid(true)
        / BleLlAdv::adv_ind()
            .tx_add(false)
            .adv_a(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x46]))
            .push_ad(AdStructure::flags_general_disc())
            .push_ad(AdStructure::complete_local_name("crafter-ble"))
}

fn ble_le_ll_adv_record_bytes() -> Vec<u8> {
    let compiled = ble_le_ll_adv_decoded_packet()
        .compile()
        .expect("BLE fixture packet should compile");
    let packet_bytes = compiled.as_bytes();
    let access_address = &packet_bytes[BLE_RADIO_ACCESS_ADDRESS_OFFSET
        ..BLE_RADIO_ACCESS_ADDRESS_OFFSET + BLE_LL_ACCESS_ADDRESS_LEN];

    let mut bytes = Vec::with_capacity(packet_bytes.len() + BLE_LL_ACCESS_ADDRESS_LEN);
    bytes.extend_from_slice(&packet_bytes[..BLE_RADIO_PSEUDO_HEADER_LEN]);
    bytes.extend_from_slice(access_address);
    bytes.extend_from_slice(&packet_bytes[BLE_RADIO_PSEUDO_HEADER_LEN..]);
    bytes
}

fn ble_le_ll_adv_pcap_bytes() -> Vec<u8> {
    let record_bytes = ble_le_ll_adv_record_bytes();
    let record = PcapRecord::new(
        ble_pcap_timestamp(),
        record_bytes.len() as u32,
        record_bytes,
        PcapLinkType::BluetoothLeLl,
    )
    .expect("BLE fixture record should be valid");

    let options = PcapWriterOptions::new(PcapLinkType::BluetoothLeLl)
        .precision(TimestampPrecision::Microseconds);
    let mut pcap = Vec::new();
    {
        let mut writer = PcapWriter::from_writer_with_options(&mut pcap, options)
            .expect("BLE fixture pcap writer should initialize");
        writer
            .write_record(&record)
            .expect("BLE fixture pcap record should write");
        writer.flush().expect("BLE fixture pcap should flush");
    }
    pcap
}

#[test]
fn ble_pcap_roundtrip_fixture_decodes_and_rewrites() {
    let fixture = fs::read(ble_pcap_fixture_path()).expect("BLE pcap fixture should be checked in");
    assert_eq!(fixture, ble_le_ll_adv_pcap_bytes());

    let reader =
        PcapReader::from_reader(fixture.as_slice()).expect("BLE pcap fixture should parse header");
    assert_eq!(
        reader.header().pcap_link_type(),
        PcapLinkType::BluetoothLeLl
    );
    assert_eq!(reader.header().link_type(), LinkType::BluetoothLeLl);
    assert_eq!(
        reader.header().precision(),
        TimestampPrecision::Microseconds
    );
    assert_eq!(
        reader.header().pcap_link_type().datalink(),
        DLT_BLUETOOTH_LE_LL_WITH_PHDR
    );

    let records = PcapReader::from_reader(fixture.as_slice())
        .expect("BLE pcap fixture should parse header for records")
        .collect_records()
        .expect("BLE pcap fixture should read records");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    let expected_record = ble_le_ll_adv_record_bytes();
    assert_eq!(record.timestamp(), ble_pcap_timestamp());
    assert_eq!(record.pcap_link_type(), PcapLinkType::BluetoothLeLl);
    assert_eq!(record.link_type(), LinkType::BluetoothLeLl);
    assert_eq!(record.captured_len(), expected_record.len() as u32);
    assert_eq!(record.original_len(), expected_record.len() as u32);
    assert_eq!(record.data(), expected_record.as_slice());

    let packets = PcapReader::from_reader(fixture.as_slice())
        .expect("BLE pcap fixture should parse header for packets")
        .collect_packets()
        .expect("BLE pcap fixture should decode packets");
    assert_eq!(packets.len(), 1);
    let packet = packets[0].packet();
    let layer_names = packet.iter().map(|layer| layer.name()).collect::<Vec<_>>();
    assert_eq!(layer_names, vec!["BleRadio", "BleLlAdv"]);

    let radio = packet.layer::<BleRadio>().expect("decoded BLE radio layer");
    assert_eq!(radio.summary(), "BleRadio(ch=37, aa=0x8e89bed6, phy=1M)");

    let adv = packet
        .layer::<BleLlAdv>()
        .expect("decoded BLE advertising layer");
    assert_eq!(
        adv.summary(),
        "BleLlAdv(ADV_IND, AdvA=00:00:5E:00:53:46, len=22)"
    );
    assert_eq!(
        adv.adv_a_value(),
        Some(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x46]))
    );

    let adv_debug = format!("{adv:?}");
    assert!(
        adv_debug.contains("AdStructure { ad_type: 1, data: [6], length_override: None }"),
        "{adv_debug}"
    );
    assert!(
        adv_debug.contains(
            "AdStructure { ad_type: 9, data: [99, 114, 97, 102, 116, 101, 114, 45, 98, 108, 101], length_override: None }"
        ),
        "{adv_debug}"
    );

    let mut rewritten = Vec::new();
    {
        let options = PcapWriterOptions::new(PcapLinkType::BluetoothLeLl)
            .precision(TimestampPrecision::Microseconds);
        let mut writer = PcapWriter::from_writer_with_options(&mut rewritten, options)
            .expect("BLE pcap writer should initialize");
        writer
            .write_record(record)
            .expect("BLE pcap record should rewrite");
        writer.flush().expect("BLE pcap writer should flush");
    }
    assert_eq!(rewritten, fixture);
}

#[test]
#[ignore = "regenerates the committed BLE pcap fixture"]
fn ble_pcap_write_fixture() {
    fs::write(ble_pcap_fixture_path(), ble_le_ll_adv_pcap_bytes())
        .expect("BLE pcap fixture should write");
}
