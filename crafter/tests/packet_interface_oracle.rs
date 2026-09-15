//! Checked reference corpus consumed independently of the Rust packet serializers.
use crafter::prelude::*;
use crafter::wire::backend::pcap::{PcapRecord, PcapTimestamp, TimestampPrecision};
use crafter::wire::{
    normalized_wifi_pcap_record, CaptureFcs, MemoryPacketWriter, MonitorWriter, PacketWriter,
};
use serde_json::Value;

fn bytes(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn normalized_capture_and_monitor_output_match_reference_corpus() {
    let corpus: Value = serde_json::from_str(include_str!(
        "fixtures/dot11/packet-interface-references.json"
    ))
    .unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 10);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let capture = bytes(&case["capture_hex"]);
        let link = match case["link_type"].as_u64().unwrap() {
            105 => LinkType::Ieee80211,
            127 => LinkType::Radiotap,
            other => panic!("unsupported corpus link {other}"),
        };
        let timestamp = PcapTimestamp::new(
            case["timestamp"]["seconds"].as_u64().unwrap(),
            case["timestamp"]["micros"].as_u64().unwrap() as u32,
            TimestampPrecision::Microseconds,
        )
        .unwrap();
        let original_len = case["original_len"].as_u64().unwrap() as u32;
        let record = normalized_wifi_pcap_record(
            PcapRecord::new(timestamp, original_len, capture.clone(), link).unwrap(),
        )
        .unwrap();
        assert_eq!(
            record.packet().compile().unwrap().as_bytes(),
            bytes(&case["expected"]["normalized_hex"]),
            "{name}"
        );
        assert_eq!(
            record.metadata().captured_bytes(),
            Some(capture.as_slice()),
            "{name}"
        );
        assert_eq!(
            record.metadata().captured_len(),
            Some(case["captured_len"].as_u64().unwrap() as u32)
        );
        assert_eq!(record.metadata().original_len(), Some(original_len));
        assert_eq!(record.metadata().timestamp(), Some(timestamp));
        let evidence = record.metadata().wifi_capture().unwrap();
        assert_eq!(evidence.link_type, link);
        assert_eq!(evidence.padding, bytes(&case["expected"]["padding_hex"]));
        assert_eq!(
            evidence.driver_failed_fcs,
            case["expected"]["driver_failed_fcs"].as_bool()
        );
        assert_eq!(
            evidence.hardware_decrypted,
            case["expected"]["hardware_decrypted"].as_bool()
        );
        let expected = &case["expected"]["fcs"];
        match (&evidence.fcs, expected["state"].as_str().unwrap()) {
            (CaptureFcs::Unknown, "unknown") | (CaptureFcs::Absent, "absent") => {}
            (
                CaptureFcs::Present {
                    bytes: actual,
                    valid,
                },
                "present",
            ) => {
                assert_eq!(actual.as_slice(), bytes(&expected["bytes_hex"]));
                assert_eq!(*valid, expected["valid"].as_bool().unwrap());
            }
            (CaptureFcs::Truncated { bytes: actual }, "truncated") => {
                assert_eq!(*actual, bytes(&expected["bytes_hex"]));
                assert!(expected["valid"].is_null());
            }
            (actual, expected) => panic!("{name}: {actual:?} differs from {expected}"),
        }
        let mut writer = MonitorWriter::new(MemoryPacketWriter::dry_run());
        writer.write_record(&record).unwrap();
        assert_eq!(
            writer.into_inner().writes()[0].bytes(),
            bytes(&case["monitor_tx_hex"]),
            "{name}"
        );
    }
}
