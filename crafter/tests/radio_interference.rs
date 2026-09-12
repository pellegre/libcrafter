#![cfg(feature = "radio")]

use crafter::radio::*;
use std::{io::Cursor, time::Duration};

#[test]
fn radio_recovers_frame_inside_false_long_candidate() {
    let mut tx = LegacyOfdmTxConfig::new(LegacyOfdmRate::Mbps6);
    let mut signal = [0; 24];
    signal[..4].copy_from_slice(&[1, 1, 0, 1]);
    signal[5..17].fill(1); // Valid SIGNAL declares the maximum length.
    signal[17] = signal[..17].iter().fold(0, |a, b| a ^ b);
    tx.signal_override = Some(signal);
    let false_frame = LegacyOfdmTransmission::encode(&[0; 16], None, &tx).unwrap();
    let good = include_bytes!("fixtures/iq/ofdm-6-clean.cs8");
    let expected_hex = include_str!("fixtures/iq/ofdm-index.tsv")
        .lines()
        .find(|line| line.starts_with("ofdm-6-clean\t"))
        .unwrap()
        .split('\t')
        .nth(6)
        .unwrap();
    let expected: Vec<u8> = expected_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let mut bytes: Vec<u8> = false_frame.cs8.iter().map(|b| *b as u8).collect();
    bytes.extend_from_slice(&[0; 1024]);
    let expected_start = bytes.len() as u64 / 2 + 37;
    bytes.extend_from_slice(good);
    for chunk in [1, 127, 4096] {
        let config = combined_config(chunk);
        let mut source =
            ReaderIqSource::new(Cursor::new(&bytes), config, combined_position()).unwrap();
        let mut decoder = LegacyOfdmDecoder::new();
        let mut frames = Vec::new();
        loop {
            let event = source.next_event().unwrap();
            let end = matches!(event, IqEvent::End(_));
            frames.extend(decoder.consume(event).unwrap().frames);
            if end {
                break;
            }
        }
        assert_eq!(frames.len(), 1, "chunk={chunk}");
        assert_eq!(frames[0].start.sample_index, expected_start);
        assert_eq!(frames[0].bytes, expected);
        assert_eq!(frames[0].integrity, FrameIntegrity::ValidFcs);
    }
}

#[test]
fn radio_periodic_interference_then_independent_frame() {
    let mut bytes = Vec::new();
    for n in 0..4096 {
        let phase = std::f32::consts::TAU * (n % 16) as f32 / 16.;
        bytes.push((64. * phase.cos()).round() as i8 as u8);
        bytes.push((64. * phase.sin()).round() as i8 as u8);
    }
    bytes.extend_from_slice(&[0; 384 * 2]);
    bytes.extend_from_slice(include_bytes!("fixtures/iq/ofdm-6-clean.cs8"));
    let expected_hex = include_str!("fixtures/iq/ofdm-index.tsv")
        .lines()
        .find(|line| line.starts_with("ofdm-6-clean\t"))
        .unwrap()
        .split('\t')
        .nth(6)
        .unwrap();
    let expected: Vec<u8> = expected_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    for chunk_samples in [1, 17, 65536] {
        let config = RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: chunk_samples,
            max_buffer_samples: 120_000,
            max_frame_bytes: 4095,
            max_pending_frames: 4,
            max_capture_samples: 100_000,
            max_duration: Duration::from_secs(1),
        };
        let position = IqPosition {
            epoch: 0,
            sequence: 0,
            sample_index: 0,
            time_anchor: None,
            discontinuity: None,
        };
        let mut source = ReaderIqSource::new(Cursor::new(&bytes), config, position).unwrap();
        let mut decoder = LegacyOfdmDecoder::new();
        let mut frames = Vec::new();
        loop {
            let event = source.next_event().unwrap();
            let end = matches!(event, IqEvent::End(_));
            frames.extend(decoder.consume(event).unwrap().frames);
            if end {
                break;
            }
        }
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].bytes, expected);
        assert_eq!(frames[0].integrity, FrameIntegrity::ValidFcs);
        assert_eq!(frames[0].start.sample_index, 4096 + 384 + 37);
    }
}

fn combined_config(chunk: usize) -> RxConfig {
    RxConfig {
        sample_rate_hz: 20_000_000,
        center_frequency_hz: 2_412_000_000,
        max_chunk_samples: chunk,
        max_buffer_samples: 120_000,
        max_frame_bytes: 4095,
        max_pending_frames: 32,
        max_capture_samples: 2_000_000,
        max_duration: Duration::from_secs(1),
    }
}
fn combined_position() -> IqPosition {
    IqPosition {
        epoch: 0,
        sequence: 0,
        sample_index: 0,
        time_anchor: None,
        discontinuity: None,
    }
}

#[test]
fn radio_combined_mixed_adjacent_repeated_and_impaired_packets() {
    use crafter::wire::Sniffer;
    let ofdm = include_bytes!("fixtures/iq/ofdm-6-clean.cs8").as_slice();
    let dsss = include_bytes!("fixtures/iq/dsss-10-long-impaired-64.cs8").as_slice();
    let cck = include_bytes!("fixtures/iq/dsss-110-long-impaired-64.cs8").as_slice();
    let mut samples = vec![0u8; 1024];
    for bytes in [ofdm, dsss, cck, ofdm, cck] {
        samples.extend_from_slice(bytes);
    }
    for chunk in [17, 65_536] {
        let config = combined_config(chunk);
        let reader = ReaderIqSource::new(
            Cursor::new(samples.clone()),
            config.clone(),
            combined_position(),
        )
        .unwrap();
        let source =
            RadioPacketSource::new(reader, LegacyWifiDecoder::new(), config.clone()).unwrap();
        let records = Sniffer::new(source).collect_records().unwrap();
        let rates: Vec<_> = records
            .iter()
            .map(|r| r.metadata().radio().unwrap().rate_bps)
            .collect();
        assert_eq!(
            rates,
            [6_000_000, 1_000_000, 11_000_000, 6_000_000, 11_000_000]
        );
        for record in &records {
            assert_eq!(record.metadata().radio().unwrap().config, config);
            assert_eq!(
                record.metadata().radio().unwrap().integrity,
                FrameIntegrity::ValidFcs
            );
        }
        assert_eq!(
            records[0].metadata().captured_bytes(),
            records[3].metadata().captured_bytes()
        );
        assert_eq!(
            records[2].metadata().captured_bytes(),
            records[4].metadata().captured_bytes()
        );
        for pair in records.windows(2) {
            assert!(
                pair[0].metadata().radio().unwrap().end_sample_index
                    < pair[1].metadata().radio().unwrap().start.sample_index
            );
        }
    }
}

#[test]
fn radio_combined_noise_gap_and_output_budget() {
    use crafter::wire::PacketSource;
    struct Events(std::collections::VecDeque<IqEvent>);
    impl IqSource for Events {
        fn next_event(&mut self) -> RadioResult<IqEvent> {
            Ok(self.0.pop_front().unwrap_or(IqEvent::End(StreamEnd::Eof)))
        }
        fn cancel(&mut self) {
            self.0.clear();
        }
    }
    let config = combined_config(65_536);
    for bytes in [
        include_bytes!("fixtures/iq/ofdm-6-clean.cs8").as_slice(),
        include_bytes!("fixtures/iq/dsss-110-long-clean-48.cs8").as_slice(),
    ] {
        let middle = bytes.len() / 4 * 2;
        let mut next = combined_position();
        next.sequence = 1;
        next.sample_index = (middle / 2) as u64;
        next.discontinuity = Some(Discontinuity {
            reason: GapReason::SourceLoss,
            loss: SampleLoss::Unknown,
        });
        let events = Events(std::collections::VecDeque::from([
            IqEvent::Chunk(
                IqChunk::new(
                    config.clone(),
                    combined_position(),
                    bytes[..middle].iter().map(|v| *v as i8).collect(),
                )
                .unwrap(),
            ),
            IqEvent::Chunk(
                IqChunk::new(
                    config.clone(),
                    next,
                    bytes[middle..].iter().map(|v| *v as i8).collect(),
                )
                .unwrap(),
            ),
        ]));
        let mut source =
            RadioPacketSource::new(events, LegacyWifiDecoder::new(), config.clone()).unwrap();
        assert!(source.next_record().unwrap().is_none());
    }
    let mut random = 1u32;
    let samples: Vec<u8> = (0..40_000)
        .map(|_| {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            random as u8
        })
        .collect();
    let reader =
        ReaderIqSource::new(Cursor::new(samples), config.clone(), combined_position()).unwrap();
    let mut source =
        RadioPacketSource::new(reader, LegacyWifiDecoder::new(), config.clone()).unwrap();
    assert!(source.next_record().unwrap().is_none());
    let mut limited = config;
    limited.max_pending_frames = 3;
    let mut samples = include_bytes!("fixtures/iq/ofdm-6-clean.cs8").to_vec();
    samples.extend_from_within(..);
    let reader =
        ReaderIqSource::new(Cursor::new(samples), limited.clone(), combined_position()).unwrap();
    let mut source = RadioPacketSource::new(reader, LegacyWifiDecoder::new(), limited).unwrap();
    assert!(source.next_record().is_err());
}

#[test]
fn radio_combined_all_independent_vectors_preserve_bytes_and_rejections() {
    use crafter::wire::Sniffer;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    for (index, hex_column, expectation_column) in [
        (include_str!("fixtures/iq/ofdm-index.tsv"), 6, 9),
        (include_str!("fixtures/iq/dsss-index.tsv"), 4, 6),
    ] {
        for line in index.lines().skip(1) {
            let columns: Vec<_> = line.split('\t').collect();
            let bytes = std::fs::read(root.join(format!("{}.cs8", columns[0]))).unwrap();
            let config = combined_config(127);
            let reader =
                ReaderIqSource::new(Cursor::new(bytes), config.clone(), combined_position())
                    .unwrap();
            let source = RadioPacketSource::new(reader, LegacyWifiDecoder::new(), config).unwrap();
            let records = Sniffer::new(source).collect_records().unwrap();
            assert_eq!(
                records.len(),
                usize::from(columns[expectation_column] == "frame"),
                "{}",
                columns[0]
            );
            if let Some(record) = records.first() {
                let expected: Vec<_> = columns[hex_column]
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect();
                assert_eq!(
                    record.metadata().captured_bytes().unwrap(),
                    expected,
                    "{}",
                    columns[0]
                );
            }
        }
    }
}
