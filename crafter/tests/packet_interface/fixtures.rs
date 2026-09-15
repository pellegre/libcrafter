use super::*;
use crafter::radio::{FrameIntegrity, IqPosition, MemoryIqSource, RxConfig};
use crafter::wire::{PacketOrigin, WpaDecryptConfig, WpaDecryptReason};
use std::{fs, path::PathBuf, time::Duration};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn bounds() -> RxConfig {
    RxConfig {
        sample_rate_hz: 20_000_000,
        center_frequency_hz: 2_437_000_000,
        max_chunk_samples: 997,
        max_buffer_samples: 400_000,
        max_frame_bytes: 65535,
        max_pending_frames: 32,
        max_capture_samples: 1_000_000,
        max_duration: Duration::from_secs(1),
    }
}

fn iq_backend(bytes: Vec<u8>) -> WifiBackend {
    let bounds = bounds();
    let source = MemoryIqSource::from_cs8(
        bytes.into_iter().map(|b| b as i8).collect(),
        bounds.clone(),
        IqPosition {
            epoch: 7,
            sequence: 0,
            sample_index: 0,
            time_anchor: None,
            discontinuity: None,
        },
    )
    .unwrap();
    WifiBackend::RadioAdapters {
        source: Some(Box::new(source)),
        sink: None,
        bounds,
    }
}

fn receive(backend: WifiBackend) -> Vec<PacketRecord> {
    let wire = PacketWire::wifi(
        backend,
        WifiInterfaceConfig {
            directions: WifiDirections::Receive,
            ..WifiInterfaceConfig::default()
        },
    )
    .unwrap();
    Sniffer::new(wire.source().unwrap())
        .collect_records()
        .unwrap()
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn independent_legacy_and_ht_vectors_cross_packet_wire() {
    for (index, prefix, psdu_column, end_column) in [
        (
            include_str!("../fixtures/iq/ofdm-index.tsv"),
            "ofdm-6-clean",
            6,
            None,
        ),
        (
            include_str!("../fixtures/iq/ht-bcc-index.tsv"),
            "ht-bcc-0-gi400-len100-clean",
            4,
            Some(8),
        ),
    ] {
        let row = index
            .lines()
            .skip(1)
            .find(|row| row.split('\t').next() == Some(prefix))
            .unwrap();
        let columns: Vec<_> = row.split('\t').collect();
        let expected = decode_hex(columns[psdu_column]);
        let records = receive(iq_backend(
            fs::read(fixtures().join(format!("iq/{prefix}.cs8"))).unwrap(),
        ));
        assert_eq!(records.len(), 1, "{prefix}");
        let record = &records[0];
        assert_eq!(
            record.metadata().captured_bytes(),
            Some(expected.as_slice())
        );
        assert_eq!(
            record.packet().compile().unwrap().as_bytes(),
            &expected[..expected.len() - 4]
        );
        let radio = record.metadata().radio().unwrap();
        assert_eq!(radio.integrity, FrameIntegrity::ValidFcs);
        assert_eq!(radio.start.epoch, 7);
        assert_eq!(radio.start.sample_index, 37);
        if let Some(column) = end_column {
            assert_eq!(
                radio.end_sample_index,
                columns[column].parse::<u64>().unwrap()
            );
        } else {
            assert_eq!(
                radio.end_sample_index,
                37 + 400 + columns[4].parse::<u64>().unwrap() * 80
            );
        }
    }
}

#[test]
fn independent_ht_duplicates_remain_two_occurrences() {
    let name = "ht-ampdu-0-gi400-bcc-duplicate";
    let row = include_str!("../fixtures/iq/ht-ampdu-index.tsv")
        .lines()
        .find(|row| row.split('\t').next() == Some(name))
        .unwrap();
    let columns: Vec<_> = row.split('\t').collect();
    let expected: Vec<_> = columns[6].split(',').map(decode_hex).collect();
    let records = receive(iq_backend(
        fs::read(fixtures().join(format!("iq/{name}.cs8"))).unwrap(),
    ));
    assert_eq!(records.len(), 2);
    for (record, expected) in records.iter().zip(&expected) {
        assert_eq!(
            record.metadata().captured_bytes(),
            Some(expected.as_slice())
        );
        assert_eq!(
            record.metadata().radio().unwrap().end_sample_index,
            columns[8].parse::<u64>().unwrap()
        );
    }
    assert_eq!(
        records[0].packet().compile().unwrap(),
        records[1].packet().compile().unwrap()
    );
}

fn protected_fixture() -> Vec<Vec<u8>> {
    let source = PacketWire::pcap_file(fixtures().join("pcaps/wpa2-psk-ccmp-unicast.pcap"))
        .open()
        .unwrap()
        .source()
        .unwrap();
    Sniffer::new(NormalizedWifiSource::new(source))
        .collect_records()
        .unwrap()
        .iter()
        .map(|record| record.packet().compile().unwrap().as_bytes().to_vec())
        .collect()
}

fn observations(frames: &[Vec<u8>], radio: bool) -> Vec<PacketRecord> {
    if radio {
        let encoder = RadioPacketWriter::new(
            LegacyWifiTxConfig::ofdm(LegacyOfdmRate::Mbps6),
            MemoryIqSink::new(),
        );
        let mut samples = Vec::new();
        for frame in frames {
            let record =
                PacketRecord::new(Packet::decode_from_link(LinkType::Ieee80211, frame).unwrap());
            samples.extend_from_slice(encoder.encode_record(&record).unwrap().cs8());
            samples.extend_from_slice(&[0; 2048]);
        }
        receive(iq_backend(samples.into_iter().map(|b| b as u8).collect()))
    } else {
        receive(WifiBackend::MonitorAdapters {
            source: Some(Box::new(VecPacketSource::new(frames.iter().map(|frame| {
                let bytes = radiotap(frame, None);
                PacketRecord::new(Packet::decode_from_link(LinkType::Radiotap, &bytes).unwrap())
                    .with_link_type(LinkType::Radiotap)
                    .with_origin(PacketOrigin::Captured)
                    .with_timestamp(timestamp())
                    .with_original_len(bytes.len() as u32)
                    .with_captured_bytes(bytes)
            })))),
            writer: None,
            framing: LinkType::Radiotap,
            radiotap_override: None,
        })
    }
}

fn protected_chain(records: Vec<PacketRecord>, password: Option<&str>) -> Vec<PacketRecord> {
    let mut decrypt = WpaDecrypt::new().with_config(WpaDecryptConfig::new().pass_originals(true));
    if let Some(password) = password {
        decrypt = decrypt.network("libcrafter-wpa", password).unwrap();
    }
    Sniffer::new(VecPacketSource::new(records))
        .with(Dot11Metadata::new())
        .with(decrypt)
        .with(Dot11Metadata::new())
        .collect_records()
        .unwrap()
}

#[test]
fn shared_wpa_chain_preserves_plaintext_encrypted_evidence_and_replay() {
    let mut frames = protected_fixture();
    let encrypted = frames.last().unwrap().clone();
    frames.push(encrypted.clone());
    let mut plaintext = Vec::new();
    for radio in [false, true] {
        let inputs = observations(&frames, radio);
        assert_eq!(inputs.len(), frames.len());
        let captured = inputs[inputs.len() - 2]
            .metadata()
            .captured_bytes()
            .unwrap()
            .to_vec();
        let outputs = protected_chain(inputs, Some("libcrafter-pass"));
        let decrypted: Vec<_> = outputs
            .iter()
            .filter(|r| r.metadata().origin() == PacketOrigin::Transformed)
            .collect();
        assert_eq!(decrypted.len(), 1);
        let record = decrypted[0];
        assert!(record.packet().layer::<Ethernet>().is_some());
        assert!(record.packet().layer::<Ipv4>().is_some());
        assert_eq!(
            record.packet().layer::<Raw>().unwrap().as_bytes(),
            b"libcrafter wpa"
        );
        assert_eq!(
            record.metadata().captured_bytes(),
            Some(captured.as_slice())
        );
        assert_eq!(record.metadata().radio().is_some(), radio);
        assert_eq!(
            record.metadata().wifi().unwrap().decrypt_state(),
            Some(WifiDecryptState::Decrypted)
        );
        assert!(outputs.iter().any(|record| record
            .metadata()
            .wifi()
            .and_then(|w| w.wpa_metadata())
            .and_then(|w| w.decrypt_reason())
            == Some(WpaDecryptReason::ReplayDetected)));
        plaintext.push(record.packet().compile().unwrap().as_bytes().to_vec());
    }
    assert_eq!(plaintext[0], plaintext[1]);
}

#[test]
fn shared_wpa_chain_rejects_missing_keys_and_bad_authentication() {
    for radio in [false, true] {
        for password in [None, Some("incorrect-password")] {
            let records = protected_chain(observations(&protected_fixture(), radio), password);
            assert!(!records
                .iter()
                .any(|r| r.metadata().origin() == PacketOrigin::Transformed));
            assert!(!records.iter().any(|r| r
                .metadata()
                .wifi()
                .is_some_and(|w| w.decrypt_state() == Some(WifiDecryptState::Decrypted))));
        }
        let mut frames = protected_fixture();
        *frames.last_mut().unwrap().last_mut().unwrap() ^= 1;
        let records = protected_chain(observations(&frames, radio), Some("libcrafter-pass"));
        assert!(!records
            .iter()
            .any(|r| r.metadata().origin() == PacketOrigin::Transformed));
        assert!(records.iter().any(|r| r
            .metadata()
            .wifi()
            .and_then(|w| w.wpa_metadata())
            .and_then(|w| w.decrypt_reason())
            == Some(WpaDecryptReason::AuthenticationFailed)));
    }
}

#[test]
fn driver_plaintext_is_preserved_without_software_authentication_claim() {
    for radio in [false, true] {
        let mut inputs = observations(&[data_frame()], radio);
        let record = inputs.pop().unwrap();
        let mut capture = record.metadata().wifi_capture().unwrap().clone();
        capture.hardware_decrypted = Some(true);
        let metadata = record.metadata().clone().with_wifi_capture(capture);
        let outputs = protected_chain(vec![record.with_metadata(metadata)], None);
        assert_eq!(outputs.len(), 1);
        let output = &outputs[0];
        assert_eq!(output.packet().compile().unwrap().as_bytes(), data_frame());
        assert_eq!(
            output.metadata().wifi_capture().unwrap().hardware_decrypted,
            Some(true)
        );
        assert_ne!(output.metadata().origin(), PacketOrigin::Transformed);
        assert_ne!(
            output.metadata().wifi().unwrap().decrypt_state(),
            Some(WifiDecryptState::Decrypted)
        );
    }
}

#[test]
fn shared_transmit_matches_independent_waveform_and_monitor_bytes() {
    use crafter::radio::{IqSink, OwnedSamples, RadioResult};
    use std::sync::{Arc, Mutex};
    struct Sink(Arc<Mutex<Vec<i8>>>);
    impl IqSink<OwnedSamples> for Sink {
        fn write(&mut self, samples: &OwnedSamples) -> RadioResult<()> {
            *self.0.lock().unwrap() = samples.cs8.clone();
            Ok(())
        }
    }
    let expected = fs::read(fixtures().join("iq/ofdm-tx-6.psdu")).unwrap();
    let record = PacketRecord::new(
        Packet::decode_from_link(LinkType::Ieee80211, &expected[..expected.len() - 4]).unwrap(),
    );
    let samples = Arc::new(Mutex::new(Vec::new()));
    let wire = PacketWire::wifi(
        WifiBackend::RadioAdapters {
            source: None,
            sink: Some(Box::new(Sink(samples.clone()))),
            bounds: bounds(),
        },
        WifiInterfaceConfig {
            directions: WifiDirections::Transmit,
            ..WifiInterfaceConfig::default()
        },
    )
    .unwrap();
    let report = wire.writer().unwrap().write_record(&record).unwrap();
    assert_eq!(
        report.radio_outcome().unwrap().completion,
        crafter::radio::SampleCompletion::Unconfirmed
    );
    let actual: Vec<u8> = samples.lock().unwrap().iter().map(|b| *b as u8).collect();
    assert_eq!(
        actual,
        fs::read(fixtures().join("iq/ofdm-tx-6.cs8")).unwrap()
    );
    let mut monitor = MonitorWriter::new(MemoryPacketWriter::dry_run());
    monitor.write_record(&record).unwrap();
    assert_eq!(
        monitor.into_inner().writes()[0].bytes(),
        radiotap(&expected[..expected.len() - 4], None)
    );

    // A deliberately invalid MAC duration remains part of the typed record.
    let mut malformed = expected[..expected.len() - 4].to_vec();
    malformed[2..4].copy_from_slice(&[0xff, 0xff]);
    let record =
        PacketRecord::new(Packet::decode_from_link(LinkType::Ieee80211, &malformed).unwrap());
    let encoder = RadioPacketWriter::new(
        LegacyWifiTxConfig::ofdm(LegacyOfdmRate::Mbps6),
        MemoryIqSink::new(),
    );
    let tx = encoder.encode_record(&record).unwrap();
    assert_eq!(&tx.psdu_bytes()[..malformed.len()], malformed);
    let mut monitor = MonitorWriter::new(MemoryPacketWriter::dry_run());
    monitor.write_record(&record).unwrap();
    assert_eq!(
        monitor.into_inner().writes()[0].bytes(),
        radiotap(&malformed, None)
    );
}

#[test]
fn partial_sample_submission_is_an_interface_error() {
    use crafter::radio::{IqSink, IqSinkOutcome, OwnedSamples, RadioResult, SampleCompletion};
    struct PartialSink;
    impl IqSink<OwnedSamples> for PartialSink {
        fn write(&mut self, _: &OwnedSamples) -> RadioResult<()> {
            Ok(())
        }
        fn write_outcome(&mut self, samples: &OwnedSamples) -> RadioResult<IqSinkOutcome> {
            let requested = samples.cs8.len() as u64 / 2;
            Ok(IqSinkOutcome {
                samples_requested: requested,
                samples_supplied: Some(requested - 1),
                padded_samples: 0,
                completion: SampleCompletion::Incomplete,
                live: Some(false),
            })
        }
    }
    let wire = PacketWire::wifi(
        WifiBackend::RadioAdapters {
            source: None,
            sink: Some(Box::new(PartialSink)),
            bounds: bounds(),
        },
        WifiInterfaceConfig {
            directions: WifiDirections::Transmit,
            ..WifiInterfaceConfig::default()
        },
    )
    .unwrap();
    let control = wire.wifi_control().unwrap();
    let record =
        PacketRecord::new(Packet::decode_from_link(LinkType::Ieee80211, &data_frame()).unwrap());
    let error = wire.writer().unwrap().write_record(&record).unwrap_err();
    assert!(error.to_string().contains("Incomplete"));
    assert_eq!(control.status().submitted_records, 0);
    assert!(control
        .status()
        .transmit_error
        .unwrap()
        .contains("sample submission failed"));
}

#[test]
fn interrupted_waveform_cannot_yield_a_complete_packet() {
    use crafter::radio::{Discontinuity, GapReason, IqEvent, IqSource, RadioResult, SampleLoss};
    struct Gapped {
        source: MemoryIqSource,
        calls: usize,
        loss: SampleLoss,
    }
    impl IqSource for Gapped {
        fn next_event(&mut self) -> RadioResult<IqEvent> {
            if self.calls == 1 {
                self.source.mark_gap(Discontinuity {
                    reason: GapReason::SourceLoss,
                    loss: self.loss,
                })?;
            }
            self.calls += 1;
            self.source.next_event()
        }
        fn cancel(&mut self) {
            self.source.cancel();
        }
    }
    for loss in [SampleLoss::Known(19), SampleLoss::Unknown] {
        let config = bounds();
        let samples = fs::read(fixtures().join("iq/ofdm-6-clean.cs8"))
            .unwrap()
            .into_iter()
            .map(|b| b as i8)
            .collect();
        let source = MemoryIqSource::from_cs8(
            samples,
            config.clone(),
            IqPosition {
                epoch: 0,
                sequence: 0,
                sample_index: 0,
                time_anchor: None,
                discontinuity: None,
            },
        )
        .unwrap();
        let records = receive(WifiBackend::RadioAdapters {
            source: Some(Box::new(Gapped {
                source,
                calls: 0,
                loss,
            })),
            sink: None,
            bounds: config,
        });
        assert!(records.is_empty(), "{loss:?}");
    }
}

#[test]
fn radio_encoder_overrides_survive_the_public_interface() {
    use crafter::radio::{IqSink, OwnedSamples, PacketEncoder, RadioResult};
    use std::sync::{Arc, Mutex};
    struct Sink(Arc<Mutex<Vec<i8>>>);
    impl IqSink<OwnedSamples> for Sink {
        fn write(&mut self, samples: &OwnedSamples) -> RadioResult<()> {
            *self.0.lock().unwrap() = samples.cs8.clone();
            Ok(())
        }
    }
    let record =
        PacketRecord::new(Packet::decode_from_link(LinkType::Ieee80211, &data_frame()).unwrap());
    let mut legacy = LegacyWifiTxConfig::ofdm(LegacyOfdmRate::Mbps6);
    legacy.ofdm.scale = 450.0;
    legacy.ofdm.leading_samples = 19;
    legacy.fcs = WifiFcsPolicy::Explicit([1, 2, 3, 4]);
    let expected_legacy = legacy.encode_packet(&record).unwrap().cs8().to_vec();
    let mut ht = HtTxConfig::new(HtMcs::Mcs3);
    ht.scale = 400.0;
    ht.leading_samples = 23;
    ht.fcs = WifiFcsPolicy::Explicit([5, 6, 7, 8]);
    let expected_ht = ht.encode_packet(&record).unwrap().cs8().to_vec();
    for (encoder, phy, expected) in [
        (
            WifiPacketEncoder::Legacy(legacy),
            WifiPhy::Ofdm { rate_mbps: 6 },
            expected_legacy,
        ),
        (
            WifiPacketEncoder::Ht20(ht),
            WifiPhy::Ht20 {
                mcs: 3,
                short_guard: false,
                greenfield: false,
                ldpc: false,
            },
            expected_ht,
        ),
    ] {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let config = WifiInterfaceConfig {
            directions: WifiDirections::Transmit,
            transmit_phy: phy,
            radio_encoder: Some(encoder),
            ..Default::default()
        };
        let wire = PacketWire::wifi(
            WifiBackend::RadioAdapters {
                source: None,
                sink: Some(Box::new(Sink(captured.clone()))),
                bounds: bounds(),
            },
            config.clone(),
        )
        .unwrap();
        wire.writer().unwrap().write_record(&record).unwrap();
        assert_eq!(*captured.lock().unwrap(), expected);
        let error = PacketWire::wifi(
            WifiBackend::MonitorAdapters {
                source: None,
                writer: Some(Box::new(MemoryPacketWriter::dry_run())),
                framing: LinkType::Radiotap,
                radiotap_override: None,
            },
            config,
        )
        .err()
        .unwrap();
        assert!(error
            .to_string()
            .contains("monitor drivers do not accept IQ encoder settings"));
    }
    let error = PacketWire::wifi(
        WifiBackend::RadioAdapters {
            source: None,
            sink: None,
            bounds: bounds(),
        },
        WifiInterfaceConfig {
            directions: WifiDirections::Transmit,
            radio_encoder: Some(WifiPacketEncoder::Ht20(HtTxConfig::new(HtMcs::Mcs0))),
            ..Default::default()
        },
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("radio encoder PHY differs"));
}
