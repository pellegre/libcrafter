//! Deterministic normalized interface contracts using synthetic capture bytes.

use crafter::prelude::*;
use crafter::wire::backend::pcap::{PcapRecord, PcapTimestamp, TimestampPrecision};
use crafter::wire::{
    normalize_wifi_record, normalized_wifi_pcap_record, CaptureFcs, InterfaceMode,
    MemoryPacketWriter, MonitorWriter, NormalizedWifiSource, PacketFormat, PacketRecord,
    PacketSource, PacketWriter, VecPacketSource, WireError,
};

fn timestamp() -> PcapTimestamp {
    PcapTimestamp::new(123, 456, TimestampPrecision::Microseconds).unwrap()
}

fn monitor_backend() -> WifiBackend {
    let packet =
        Packet::decode_from_link(LinkType::Radiotap, &radiotap(&data_frame(), None)).unwrap();
    WifiBackend::MonitorAdapters {
        source: Some(Box::new(VecPacketSource::from_packets([packet]))),
        writer: Some(Box::new(MemoryPacketWriter::dry_run())),
        framing: LinkType::Radiotap,
        radiotap_override: None,
    }
}

// Backend choice is the only input which differs between monitor and IQ callers.
fn shared_receive_send(backend: WifiBackend) -> (PacketRecord, WriteReport, WifiInterfaceStatus) {
    let wire = PacketWire::wifi(backend, WifiInterfaceConfig::default()).unwrap();
    let descriptor = wire.wifi_descriptor().unwrap();
    assert_eq!(descriptor.packet_format, PacketFormat::Dot11);
    let generic = wire.descriptor();
    assert_eq!(generic.packet_format, Some(PacketFormat::Dot11));
    assert_eq!(generic.mode, Some(descriptor.mode));
    assert!(generic.receive && generic.transmit);
    assert_eq!(descriptor.observed_frequency_hz, None);
    let control = wire.wifi_control().unwrap();
    let (mut source, mut writer) = wire.split().unwrap();
    let record = source.next_record().unwrap().unwrap();
    let report = writer.write_record(&record).unwrap();
    assert!(source.next_record().unwrap().is_none());
    (record, report, control.status())
}

#[test]
fn opened_monitor_uses_shared_pipeline_and_controls_survive_split() {
    let (record, report, status) = shared_receive_send(monitor_backend());
    assert_eq!(record.packet().compile().unwrap().as_bytes(), data_frame());
    assert!(report.is_dry_run());
    assert_eq!(status.received_records, 1);
    assert_eq!(status.submitted_records, 1);
    assert!(status.receive_ended);

    let wire = PacketWire::wifi(monitor_backend(), WifiInterfaceConfig::default()).unwrap();
    let control = wire.wifi_control().unwrap();
    let (mut source, mut writer) = wire.split().unwrap();
    control.cancel();
    assert!(source.next_record().unwrap().is_none());
    assert!(writer
        .write_record(&record)
        .unwrap_err()
        .to_string()
        .contains("cancelled"));
    assert!(control.status().cancelled);
    assert_eq!(control.status().received_records, 0);
}

#[test]
fn opened_interface_rejects_inconsistent_and_unsupported_configuration() {
    for config in [
        WifiInterfaceConfig {
            width_mhz: 40,
            ..WifiInterfaceConfig::default()
        },
        WifiInterfaceConfig {
            channel: Some(1),
            ..WifiInterfaceConfig::default()
        },
        WifiInterfaceConfig {
            transmit_phy: WifiPhy::Ofdm { rate_mbps: 7 },
            ..WifiInterfaceConfig::default()
        },
    ] {
        assert!(PacketWire::wifi(monitor_backend(), config).is_err());
    }
    let missing = WifiBackend::MonitorAdapters {
        source: None,
        writer: None,
        framing: LinkType::Radiotap,
        radiotap_override: None,
    };
    assert!(matches!(
        PacketWire::wifi(missing, WifiInterfaceConfig::default()),
        Err(WireError::UnsupportedCapability {
            capability: "read",
            ..
        })
    ));
    let config = WifiInterfaceConfig {
        directions: WifiDirections::Receive,
        ..WifiInterfaceConfig::default()
    };
    let wire = PacketWire::wifi(monitor_backend(), config).unwrap();
    assert!(wire.has_source());
    assert!(!wire.has_writer());
}

#[test]
fn source_and_writer_failures_remain_inspectable() {
    struct FailureSource;
    impl PacketSource for FailureSource {
        fn next_record(&mut self) -> crafter::wire::Result<Option<PacketRecord>> {
            Err(WireError::backend("fixture", "receive", "source failed"))
        }
    }
    struct FailureWriter;
    impl PacketWriter for FailureWriter {
        fn write_record(&mut self, _: &PacketRecord) -> crafter::wire::Result<WriteReport> {
            Err(WireError::backend("fixture", "write", "sink failed"))
        }
    }
    let backend = WifiBackend::MonitorAdapters {
        source: Some(Box::new(FailureSource)),
        writer: Some(Box::new(FailureWriter)),
        framing: LinkType::Radiotap,
        radiotap_override: None,
    };
    let wire = PacketWire::wifi(backend, WifiInterfaceConfig::default()).unwrap();
    let control = wire.wifi_control().unwrap();
    let (mut source, mut writer) = wire.split().unwrap();
    assert!(source.next_record().is_err());
    let record =
        PacketRecord::new(Packet::decode_from_link(LinkType::Ieee80211, &data_frame()).unwrap());
    assert!(writer.write_record(&record).is_err());
    assert!(control
        .status()
        .receive_error
        .unwrap()
        .contains("source failed"));
    assert!(control
        .status()
        .transmit_error
        .unwrap()
        .contains("sink failed"));
}

#[cfg(not(feature = "radio-hackrf"))]
#[test]
fn hackrf_selection_reports_the_disabled_feature() {
    let error = PacketWire::wifi(WifiBackend::HackRf, WifiInterfaceConfig::default()).unwrap_err();
    assert!(matches!(
        error,
        WireError::UnsupportedCapability {
            capability: "HackRF",
            ..
        }
    ));
    assert!(error.to_string().contains("radio-hackrf"));
}

#[cfg(feature = "radio")]
#[test]
fn iq_and_monitor_use_identical_receive_send_code() {
    use crafter::radio::{IqPosition, RxConfig};
    let packet = Packet::decode_from_link(LinkType::Ieee80211, &data_frame()).unwrap();
    let tx = RadioPacketWriter::new(
        LegacyWifiTxConfig::ofdm(LegacyOfdmRate::Mbps6),
        MemoryIqSink::new(),
    )
    .encode_record(&PacketRecord::new(packet))
    .unwrap();
    let bounds = RxConfig {
        sample_rate_hz: 20_000_000,
        center_frequency_hz: 2_437_000_000,
        max_chunk_samples: 20_000,
        max_buffer_samples: 400_000,
        max_frame_bytes: 4095,
        max_pending_frames: 4,
        max_capture_samples: 1_000_000,
        max_duration: std::time::Duration::from_secs(1),
    };
    let position = IqPosition {
        epoch: 0,
        sequence: 0,
        sample_index: 0,
        time_anchor: None,
        discontinuity: None,
    };
    let source =
        crafter::radio::MemoryIqSource::from_cs8(tx.cs8().to_vec(), bounds.clone(), position)
            .unwrap();
    let backend = WifiBackend::RadioAdapters {
        source: Some(Box::new(source)),
        sink: Some(Box::new(MemoryIqSink::<crafter::radio::OwnedSamples>::new())),
        bounds,
    };
    let (radio, report, status) = shared_receive_send(backend);
    let (monitor, _, _) = shared_receive_send(monitor_backend());
    assert_eq!(
        radio.packet().compile().unwrap().as_bytes(),
        monitor.packet().compile().unwrap().as_bytes()
    );
    assert!(radio.metadata().radio().is_some());
    assert_eq!(status.received_records, 1);
    assert_eq!(
        report.radio_outcome().unwrap().completion,
        crafter::radio::SampleCompletion::Stored
    );
    assert_eq!(status.radio_end, Some(crafter::radio::StreamEnd::Eof));
}

#[cfg(feature = "radio")]
#[test]
fn common_control_cancels_idle_sample_acquisition() {
    use crafter::radio::{IqEvent, IqSource, RadioResult, RxConfig, StreamEnd};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    struct Source(Arc<AtomicBool>);
    impl IqSource for Source {
        fn next_event(&mut self) -> RadioResult<IqEvent> {
            Ok(IqEvent::End(StreamEnd::Eof))
        }
        fn cancel(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let bounds = RxConfig {
        sample_rate_hz: 20_000_000,
        center_frequency_hz: 2_437_000_000,
        max_chunk_samples: 100,
        max_buffer_samples: 200,
        max_frame_bytes: 4095,
        max_pending_frames: 4,
        max_capture_samples: 1000,
        max_duration: std::time::Duration::from_secs(1),
    };
    let backend = WifiBackend::RadioAdapters {
        source: Some(Box::new(Source(cancelled.clone()))),
        sink: None,
        bounds,
    };
    let wire = PacketWire::wifi(
        backend,
        WifiInterfaceConfig {
            directions: WifiDirections::Receive,
            ..WifiInterfaceConfig::default()
        },
    )
    .unwrap();
    let control = wire.wifi_control().unwrap();
    let mut source = wire.source().unwrap();
    control.cancel();
    assert!(cancelled.load(Ordering::SeqCst));
    assert!(source.next_record().unwrap().is_none());
}

fn capture(bytes: Vec<u8>, link: LinkType, missing: usize) -> PcapRecord {
    PcapRecord::new(timestamp(), (bytes.len() + missing) as u32, bytes, link).unwrap()
}

fn data_frame() -> Vec<u8> {
    // Data MAC header with an unknown LLC payload, including a four-byte tail.
    let mut bytes = vec![0x08, 0x00, 0x00, 0x00];
    bytes.extend_from_slice(&[0x02, 0, 0x5e, 0, 0, 1]);
    bytes.extend_from_slice(&[0x02, 0, 0x5e, 0, 0, 2]);
    bytes.extend_from_slice(&[0x02, 0, 0x5e, 0, 0, 3]);
    bytes.extend_from_slice(&[0x10, 0]);
    bytes.extend_from_slice(&[0x17, 0x23, 0x45, 0x67, 0x89]);
    bytes
}

fn radiotap(frame: &[u8], flags: Option<u8>) -> Vec<u8> {
    let mut bytes = match flags {
        Some(flags) => vec![0, 0, 9, 0, 2, 0, 0, 0, flags],
        None => vec![0, 0, 8, 0, 0, 0, 0, 0],
    };
    bytes.extend_from_slice(frame);
    bytes
}

#[test]
fn bare_and_radiotap_agree_and_capture_provenance_is_retained() {
    let frame = data_frame();
    let wrapped = radiotap(&frame, None);
    let bare = normalized_wifi_pcap_record(capture(frame.clone(), LinkType::Ieee80211, 0)).unwrap();
    let monitor =
        normalized_wifi_pcap_record(capture(wrapped.clone(), LinkType::Radiotap, 0)).unwrap();
    assert_eq!(bare.packet().compile().unwrap().as_bytes(), frame);
    assert_eq!(monitor.packet().compile().unwrap().as_bytes(), frame);
    assert_eq!(
        monitor.metadata().captured_bytes(),
        Some(wrapped.as_slice())
    );
    assert_eq!(monitor.metadata().timestamp(), Some(timestamp()));
    assert_eq!(
        monitor.metadata().original_len(),
        Some(wrapped.len() as u32)
    );
    assert_eq!(
        monitor.metadata().captured_len(),
        Some(wrapped.len() as u32)
    );
    assert_eq!(monitor.metadata().link_type(), Some(LinkType::Ieee80211));
    assert_eq!(
        monitor.metadata().pcap_link_type().unwrap().link_type(),
        LinkType::Radiotap
    );
    let evidence = monitor.metadata().wifi_capture().unwrap();
    assert_eq!(evidence.link_type, LinkType::Radiotap);
    assert!(evidence.radiotap.is_some());
    assert_eq!(evidence.fcs, CaptureFcs::Unknown);
    assert_eq!(evidence.driver_failed_fcs, None);
    assert_eq!(evidence.hardware_decrypted, None);
    assert_eq!(monitor.metadata().wifi().unwrap().protected(), Some(false));
    let again = normalize_wifi_record(monitor).unwrap();
    assert_eq!(again.packet().compile().unwrap().as_bytes(), frame);
}

#[test]
fn explicit_absence_keeps_the_whole_payload_and_driver_failure_is_separate() {
    for flags in [0, 0x40] {
        let frame = data_frame();
        let record = normalized_wifi_pcap_record(capture(
            radiotap(&frame, Some(flags)),
            LinkType::Radiotap,
            0,
        ))
        .unwrap();
        assert_eq!(record.packet().compile().unwrap().as_bytes(), frame);
        let evidence = record.metadata().wifi_capture().unwrap();
        assert_eq!(evidence.fcs, CaptureFcs::Absent);
        assert_eq!(evidence.driver_failed_fcs, Some(flags == 0x40));
    }
}

#[test]
fn fcs_validity_is_computed_and_invalid_trailers_are_retained() {
    // CRC-32/ISO-HDLC expected bytes independently generated with zlib.
    for (expected, valid) in [([0x49, 0xae, 0x6d, 0xa4], true), ([1, 2, 3, 4], false)] {
        let mut ack = vec![0xd4, 0, 0, 0, 2, 0, 0x5e, 0, 0, 1];
        ack.extend_from_slice(&expected);
        let record =
            normalized_wifi_pcap_record(capture(radiotap(&ack, Some(0x10)), LinkType::Radiotap, 0))
                .unwrap();
        assert_eq!(record.packet().compile().unwrap().as_bytes(), &ack[..10]);
        assert_eq!(
            record.metadata().wifi_capture().unwrap().fcs,
            CaptureFcs::Present {
                bytes: expected,
                valid
            }
        );
    }
}

#[test]
fn truncated_trailers_never_consume_payload() {
    let frame = data_frame();
    for missing in 1..=5 {
        let mut payload = frame.clone();
        let partial = &[1, 2, 3, 4][..4usize.saturating_sub(missing)];
        payload.extend_from_slice(partial);
        let record = normalized_wifi_pcap_record(capture(
            radiotap(&payload, Some(0x10)),
            LinkType::Radiotap,
            missing,
        ))
        .unwrap();
        assert_eq!(record.packet().compile().unwrap().as_bytes(), frame);
        assert_eq!(
            record.metadata().wifi_capture().unwrap().fcs,
            CaptureFcs::Truncated {
                bytes: partial.to_vec()
            }
        );
    }
}

#[test]
fn qos_padding_is_removed_before_payload_decode_and_protection_is_preserved() {
    let mut frame = data_frame();
    frame[0] = 0x88; // QoS data.
    frame[1] = 0x40; // Protected.
    frame.splice(24..24, [0, 0]);
    let mut padded = frame.clone();
    padded.splice(26..26, [0xab, 0xcd]);
    let record = normalized_wifi_pcap_record(capture(
        radiotap(&padded, Some(0x20)),
        LinkType::Radiotap,
        0,
    ))
    .unwrap();
    assert_eq!(record.packet().compile().unwrap().as_bytes(), frame);
    assert_eq!(
        record.metadata().wifi_capture().unwrap().padding,
        [0xab, 0xcd]
    );
    assert_eq!(record.metadata().wifi().unwrap().protected(), Some(true));
    assert_eq!(
        record.metadata().wifi_capture().unwrap().hardware_decrypted,
        None
    );
}

#[test]
fn malformed_wrappers_and_incompatible_roots_are_structured_errors() {
    for bytes in [vec![0; 7], vec![0, 0, 20, 0, 0, 0, 0, 0]] {
        let error = normalized_wifi_pcap_record(capture(bytes, LinkType::Radiotap, 0)).unwrap_err();
        assert!(matches!(
            error,
            WireError::Packet(CrafterError::BufferTooShort { .. })
        ));
    }
    let error =
        normalized_wifi_pcap_record(capture(vec![0; 14], LinkType::Ethernet, 0)).unwrap_err();
    assert!(matches!(
        error,
        WireError::Packet(CrafterError::InvalidFieldValue { .. })
    ));
    assert!(normalize_wifi_record(PacketRecord::new(Ethernet::new() / Dot11::new())).is_err());
}

#[test]
fn operating_mode_and_backend_identity_do_not_conflate_formats() {
    assert_eq!(
        InterfaceMode::ManagedWifi.packet_format(),
        PacketFormat::Ethernet
    );
    assert_eq!(
        InterfaceMode::Ethernet.packet_format(),
        PacketFormat::Ethernet
    );
    assert_eq!(
        InterfaceMode::MonitorWifi.packet_format(),
        PacketFormat::Dot11
    );
    assert_eq!(InterfaceMode::WifiIq.packet_format(), PacketFormat::Dot11);
    assert_eq!(
        InterfaceMode::RawCapture(LinkType::Radiotap).packet_format(),
        PacketFormat::Capture(LinkType::Radiotap)
    );
}

#[test]
fn monitor_writer_materializes_exact_driver_bytes_and_honors_overrides() {
    let frame = data_frame();
    let record =
        normalized_wifi_pcap_record(capture(frame.clone(), LinkType::Ieee80211, 0)).unwrap();
    let mut writer = MonitorWriter::new(MemoryPacketWriter::new());
    let represented = writer.frame_record(&record).unwrap();
    assert_eq!(
        represented.packet().compile().unwrap().as_bytes(),
        radiotap(&frame, None)
    );
    let report = writer.write_record(&record).unwrap();
    assert_eq!(report.bytes_written(), frame.len() + 8);
    let writer = writer.with_radiotap(Radiotap::new().flags(0x50).rate(0));
    let mut expected = vec![0, 0, 10, 0, 6, 0, 0, 0, 0x50, 0];
    expected.extend_from_slice(&frame);
    assert_eq!(
        writer
            .frame_record(&record)
            .unwrap()
            .packet()
            .compile()
            .unwrap()
            .as_bytes(),
        expected
    );
    assert!(writer
        .frame_record(&PacketRecord::new(Ethernet::new()))
        .is_err());
    let bare = MonitorWriter::bare(MemoryPacketWriter::new());
    assert_eq!(
        bare.frame_record(&record)
            .unwrap()
            .packet()
            .compile()
            .unwrap()
            .as_bytes(),
        frame
    );
}

#[test]
fn source_adapter_preserves_duplicate_occurrences_and_termination() {
    let original = PacketRecord::try_from_pcap_record(capture(
        radiotap(&data_frame(), None),
        LinkType::Radiotap,
        0,
    ))
    .unwrap();
    let mut source = NormalizedWifiSource::new(VecPacketSource::new([original.clone(), original]));
    for _ in 0..2 {
        assert_eq!(
            source
                .next_record()
                .unwrap()
                .unwrap()
                .packet()
                .compile()
                .unwrap()
                .as_bytes(),
            data_frame()
        );
    }
    assert!(source.next_record().unwrap().is_none());
}

#[test]
fn annotation_preserves_prior_transform_evidence() {
    use crafter::wire::{Dot11Metadata, WifiDecryptState, WifiMetadata};
    for state in [
        WifiDecryptState::Decrypted,
        WifiDecryptState::Failed,
        WifiDecryptState::KeyMaterialMissing,
    ] {
        let record = PacketRecord::new(Dot11::new())
            .with_wifi_metadata(WifiMetadata::new().with_decrypt_state(state));
        let normalized = normalize_wifi_record(record).unwrap();
        let output = Dot11Metadata::new().annotate(normalized).unwrap();
        assert_eq!(
            output.records()[0]
                .metadata()
                .wifi()
                .unwrap()
                .decrypt_state(),
            Some(state)
        );
    }
}

#[test]
fn unknown_radiotap_bytes_survive_normalization() {
    // Unknown bit 25 leaves an opaque metadata suffix; it is not MAC payload.
    let mut wrapped = vec![0, 0, 11, 0, 0, 0, 0, 2, 0xa1, 0xb2, 0xc3];
    wrapped.extend_from_slice(&data_frame());
    let normalized =
        normalized_wifi_pcap_record(capture(wrapped.clone(), LinkType::Radiotap, 0)).unwrap();
    let header = normalized
        .metadata()
        .wifi_capture()
        .unwrap()
        .radiotap
        .as_ref()
        .unwrap();
    assert_eq!(header.raw_fields(), &[0xa1, 0xb2, 0xc3]);
    assert_eq!(
        normalized.metadata().captured_bytes(),
        Some(wrapped.as_slice())
    );
    assert_eq!(
        normalized.packet().compile().unwrap().as_bytes(),
        data_frame()
    );
}

#[test]
fn checksum_excludes_capture_padding() {
    let mut frame = data_frame();
    frame[0] = 0x88;
    frame[1] = 0x40;
    frame.splice(24..24, [0, 0]);
    let mut padded = frame.clone();
    padded.splice(26..26, [0xab, 0xcd]);
    // Independent zlib CRC of the unpadded frame, not of the capture bytes.
    let checksum = [0x34, 0x28, 0x9d, 0x6b];
    padded.extend_from_slice(&checksum);
    let record = normalized_wifi_pcap_record(capture(
        radiotap(&padded, Some(0x30)),
        LinkType::Radiotap,
        0,
    ))
    .unwrap();
    assert_eq!(record.packet().compile().unwrap().as_bytes(), frame);
    assert_eq!(
        record.metadata().wifi_capture().unwrap().fcs,
        CaptureFcs::Present {
            bytes: checksum,
            valid: true
        }
    );
}

#[test]
fn normalized_pcap_roundtrip_and_raw_capture_remain_distinct() {
    use crafter::wire::backend::pcap::{OfflinePcapSource, PcapFileWriter, PcapWriter};
    struct Captures(std::path::PathBuf);
    impl Drop for Captures {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0.join("input.pcap"));
            let _ = std::fs::remove_file(self.0.join("normalized.pcap"));
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("crafter-interface-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    let dir = Captures(path);
    let input = dir.0.join("input.pcap");
    let output = dir.0.join("normalized.pcap");
    let wrapped = radiotap(&data_frame(), Some(0));
    let mut writer = PcapWriter::create(&input, LinkType::Radiotap).unwrap();
    writer
        .write_record(&capture(wrapped.clone(), LinkType::Radiotap, 0))
        .unwrap();
    writer.flush().unwrap();
    let raw = OfflinePcapSource::open(&input)
        .unwrap()
        .next_record()
        .unwrap()
        .unwrap();
    assert!(raw.packet().get(0).unwrap().as_any().is::<Radiotap>());
    assert!(raw.metadata().wifi_capture().is_none());
    assert_eq!(raw.packet().compile().unwrap().as_bytes(), wrapped);
    let normalized = OfflinePcapSource::open(&input)
        .unwrap()
        .normalized_wifi()
        .next_record()
        .unwrap()
        .unwrap();
    PcapFileWriter::create(&output, LinkType::Ieee80211)
        .unwrap()
        .write_record(&normalized)
        .unwrap();
    let reopened = OfflinePcapSource::open(&output)
        .unwrap()
        .next_record()
        .unwrap()
        .unwrap();
    assert_eq!(
        reopened.packet().compile().unwrap().as_bytes(),
        data_frame()
    );
    assert_eq!(reopened.metadata().timestamp(), Some(timestamp()));
    assert_eq!(
        reopened.metadata().original_len(),
        Some(data_frame().len() as u32)
    );
}
