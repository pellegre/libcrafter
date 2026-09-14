#![cfg(feature = "radio")]
use crafter::radio::*;
use std::{io::Cursor, time::Duration};
fn config(chunk: usize) -> RxConfig {
    RxConfig {
        sample_rate_hz: 20_000_000,
        center_frequency_hz: 2_437_000_000,
        max_chunk_samples: chunk,
        max_buffer_samples: 1_000_000,
        max_frame_bytes: 4095,
        max_pending_frames: 64,
        max_capture_samples: 20_000_000,
        max_duration: Duration::from_secs(1),
    }
}
fn position() -> IqPosition {
    IqPosition {
        epoch: 0,
        sequence: 0,
        sample_index: 0,
        time_anchor: None,
        discontinuity: None,
    }
}
fn clone_event(event: &IqEvent) -> IqEvent {
    match event {
        IqEvent::Chunk(c) => IqEvent::Chunk(c.clone()),
        IqEvent::End(e) => IqEvent::End(*e),
    }
}
#[test]
fn parallel_matches_serial_on_all_independent_vectors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    for index in [
        include_str!("fixtures/iq/ofdm-index.tsv"),
        include_str!("fixtures/iq/dsss-index.tsv"),
    ] {
        for line in index.lines().skip(1) {
            let name = line.split('\t').next().unwrap();
            let bytes = std::fs::read(root.join(format!("{name}.cs8"))).unwrap();
            for size in [127, 4096] {
                let mut source =
                    ReaderIqSource::new(Cursor::new(&bytes), config(size), position()).unwrap();
                let mut serial = LegacyWifiDecoder::new();
                let mut parallel = ParallelLegacyWifiDecoder::new().unwrap();
                loop {
                    let event = source.next_event().unwrap();
                    let end = matches!(event, IqEvent::End(_));
                    let expected = serial.consume(clone_event(&event)).unwrap();
                    let actual = parallel.consume(event).unwrap();
                    assert_eq!(
                        format!("{actual:?}"),
                        format!("{expected:?}"),
                        "{name}, chunk={size}"
                    );
                    if end {
                        break;
                    }
                }
                assert_eq!(parallel.ofdm_stats(), serial.ofdm_stats());
                assert_eq!(parallel.dsss_stats(), serial.dsss_stats());
            }
        }
    }
}
#[test]
fn parallel_preserves_gap_budget_and_terminal_behavior() {
    let mut serial = LegacyWifiDecoder::new();
    let mut parallel = ParallelLegacyWifiDecoder::new().unwrap();
    let mut c = config(512);
    c.max_pending_frames = 3;
    for sequence in 0..8 {
        let mut p = position();
        p.sequence = sequence;
        p.sample_index = sequence * 512;
        if sequence == 2 {
            p.discontinuity = Some(Discontinuity {
                reason: GapReason::SourceLoss,
                loss: SampleLoss::Unknown,
            });
        }
        let event = IqEvent::Chunk(IqChunk::new(c.clone(), p, vec![0; 1024]).unwrap());
        assert_eq!(
            format!("{:?}", serial.consume(clone_event(&event))),
            format!("{:?}", parallel.consume(event))
        );
    }
    for reason in [ResetReason::End(StreamEnd::Eof), ResetReason::Explicit] {
        assert_eq!(
            format!("{:?}", serial.reset(reason)),
            format!("{:?}", parallel.reset(reason))
        );
        let event = IqEvent::Chunk(IqChunk::new(c.clone(), position(), vec![0; 1024]).unwrap());
        assert_eq!(
            format!("{:?}", serial.consume(clone_event(&event))),
            format!("{:?}", parallel.consume(event))
        );
    }
    c.max_pending_frames = 2;
    let event = IqEvent::Chunk(IqChunk::new(c, position(), vec![0; 1024]).unwrap());
    assert_eq!(
        format!("{:?}", serial.consume(clone_event(&event))),
        format!("{:?}", parallel.consume(event))
    );
}

#[test]
fn parallel_output_overflow_resets_both_workers() {
    let packet = include_bytes!("fixtures/iq/ofdm-6-clean.cs8");
    let mut bytes = packet.to_vec();
    bytes.extend_from_slice(&[0; 1024]);
    bytes.extend_from_slice(packet);
    let mut c = config(bytes.len() / 2);
    c.max_pending_frames = 3;
    let mut serial = LegacyWifiDecoder::new();
    let mut parallel = ParallelLegacyWifiDecoder::new().unwrap();
    let event = IqEvent::Chunk(
        IqChunk::new(c, position(), bytes.into_iter().map(|b| b as i8).collect()).unwrap(),
    );
    let expected = serial.consume(clone_event(&event)).unwrap_err();
    let actual = parallel.consume(event).unwrap_err();
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
    assert!(matches!(actual, RadioError::Limit { .. }));
    let event = IqEvent::Chunk(
        IqChunk::new(
            config(packet.len() / 2),
            position(),
            packet.iter().map(|b| *b as i8).collect(),
        )
        .unwrap(),
    );
    let expected = serial.consume(clone_event(&event)).unwrap();
    let actual = parallel.consume(event).unwrap();
    assert_eq!(actual.frames.len(), 1);
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
}

#[test]
fn parallel_frames_enter_the_existing_packet_source() {
    use crafter::wire::PacketSource;
    let bytes = include_bytes!("fixtures/iq/ofdm-6-clean.cs8");
    let c = config(4096);
    let source = ReaderIqSource::new(Cursor::new(bytes), c.clone(), position()).unwrap();
    let mut source =
        RadioPacketSource::new(source, ParallelLegacyWifiDecoder::new().unwrap(), c).unwrap();
    let record = source.next_record().unwrap().unwrap();
    assert!(!record.metadata().captured_bytes().unwrap().is_empty());
    assert!(source.next_record().unwrap().is_none());
}

#[test]
fn parallel_wifi_preserves_ht_frames_and_metadata() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    for name in [
        "ht-bcc-0-gi800-len100-clean",
        "ht-ldpc-7-gi800-len100-clean",
        "ht-greenfield-7-ldpc-len100-clean",
        "ht-stbc-7-ldpc-gf-gi800-len100-clean",
        "ht-extension-7-bcc-mf-gi800-stbc0-ess3-len100-clean",
        "ht-ampdu-7-gi800-ldpc-duplicate",
    ] {
        let bytes = std::fs::read(root.join(format!("{name}.cs8"))).unwrap();
        for size in [127, 4096] {
            let mut source =
                ReaderIqSource::new(Cursor::new(&bytes), config(size), position()).unwrap();
            let mut serial = WifiDecoder::new();
            let mut parallel = ParallelWifiDecoder::new().unwrap();
            let mut split = ParallelWifiDecoder::with_parallel_dsss().unwrap();
            let mut expected = Vec::new();
            let mut actual = Vec::new();
            let mut split_actual = Vec::new();
            loop {
                let event = source.next_event().unwrap();
                let end = matches!(event, IqEvent::End(_));
                expected.extend(serial.consume(clone_event(&event)).unwrap().frames);
                actual.extend(parallel.consume(clone_event(&event)).unwrap().frames);
                split_actual.extend(split.consume(event).unwrap().frames);
                if end {
                    break;
                }
            }
            assert_eq!(
                format!("{actual:?}"),
                format!("{expected:?}"),
                "{name}, chunk={size}"
            );
            assert_eq!(
                format!("{split_actual:?}"),
                format!("{expected:?}"),
                "{name}, chunk={size}, split DSSS"
            );
        }
    }
}

#[test]
fn windowed_parallelism_preserves_frames_across_core_boundaries() {
    const CORE: usize = 2_000_000;
    let packet = include_bytes!("fixtures/iq/dsss-10-long-clean-48.cs8");
    let offsets = [CORE - 20_000, CORE + 1_000];
    let mut bytes = vec![0u8; (CORE + 1_000 + packet.len() / 2 + 64) * 2];
    for offset in offsets {
        bytes[offset * 2..offset * 2 + packet.len()].copy_from_slice(packet);
    }
    let mut c = config(65_536);
    c.max_buffer_samples = 14_000_000;
    c.max_capture_samples = bytes.len() as u64 / 2;
    let mut source = ReaderIqSource::new(Cursor::new(&bytes), c.clone(), position()).unwrap();
    let mut serial = LegacyWifiDecoder::new();
    let mut windowed = WindowedLegacyWifiDecoder::new(4).unwrap();
    let mut expected = Vec::new();
    let mut actual = Vec::new();
    loop {
        let event = source.next_event().unwrap();
        let end = matches!(event, IqEvent::End(_));
        expected.extend(serial.consume(clone_event(&event)).unwrap().frames);
        actual.extend(windowed.consume(event).unwrap().frames);
        if end {
            break;
        }
    }
    assert_eq!(actual.len(), 2);
    assert_eq!(windowed.dsss_stats().valid_frames, 2);
    assert_eq!(windowed.ofdm_stats().valid_frames, 0);
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected) {
        assert_eq!(actual.bytes, expected.bytes);
        assert_eq!(actual.rate_bps, expected.rate_bps);
        assert_eq!(actual.start.epoch, expected.start.epoch);
        assert_eq!(actual.start.sample_index, expected.start.sample_index);
        assert_eq!(actual.end_sample_index, expected.end_sample_index);
    }
}

#[test]
fn windowed_wifi_preserves_ht_frames_and_metadata_across_core_boundaries() {
    const CORE: usize = 1_600_000;
    let packet = include_bytes!("fixtures/iq/ht-bcc-0-gi800-len100-clean.cs8");
    let offsets = [CORE - 1_000, CORE + 10_000];
    let mut bytes = vec![0u8; (CORE + 10_000 + packet.len() / 2 + 64) * 2];
    for offset in offsets {
        bytes[offset * 2..offset * 2 + packet.len()].copy_from_slice(packet);
    }
    let mut c = config(65_536);
    c.max_buffer_samples = 20_000_000;
    c.max_capture_samples = bytes.len() as u64 / 2;
    let mut source = ReaderIqSource::new(Cursor::new(&bytes), c.clone(), position()).unwrap();
    let mut serial = WifiDecoder::new();
    let mut windowed = WindowedWifiDecoder::new(4).unwrap();
    let mut expected = Vec::new();
    let mut actual = Vec::new();
    loop {
        let event = source.next_event().unwrap();
        let end = matches!(event, IqEvent::End(_));
        expected.extend(serial.consume(clone_event(&event)).unwrap().frames);
        actual.extend(windowed.consume(event).unwrap().frames);
        if end {
            break;
        }
    }
    assert_eq!(actual.len(), 2);
    assert_eq!(windowed.ofdm_stats().valid_frames, 2);
    assert_eq!(windowed.dsss_stats().valid_frames, 0);
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected) {
        assert_eq!(actual.bytes, expected.bytes);
        assert_eq!(actual.rate_bps, expected.rate_bps);
        assert_eq!(actual.integrity, expected.integrity);
        assert_eq!(actual.start.epoch, expected.start.epoch);
        assert_eq!(actual.start.sample_index, expected.start.sample_index);
        assert_eq!(actual.end_sample_index, expected.end_sample_index);
        assert_eq!(actual.diagnostics, expected.diagnostics);
    }
}

#[test]
fn windowed_reports_partial_frames_at_eof_and_gap() {
    for bytes in [
        &include_bytes!("fixtures/iq/ofdm-6-truncated.cs8")[..],
        &include_bytes!("fixtures/iq/dsss-10-long-truncated_payload-48.cs8")[..],
    ] {
        for gap in [false, true] {
            let mut c = config(bytes.len() / 2);
            c.max_buffer_samples = 6_000_000;
            let mut serial = LegacyWifiDecoder::new();
            let mut windowed = WindowedLegacyWifiDecoder::new(1).unwrap();
            let event = IqEvent::Chunk(
                IqChunk::new(
                    c.clone(),
                    position(),
                    bytes.iter().map(|b| *b as i8).collect(),
                )
                .unwrap(),
            );
            assert!(serial
                .consume(clone_event(&event))
                .unwrap()
                .frames
                .is_empty());
            assert!(windowed.consume(event).unwrap().frames.is_empty());
            let boundary = if gap {
                let mut p = position();
                p.epoch = 1;
                p.discontinuity = Some(Discontinuity {
                    reason: GapReason::SourceLoss,
                    loss: SampleLoss::Unknown,
                });
                IqEvent::Chunk(IqChunk::new(c.clone(), p, vec![0; 256]).unwrap())
            } else {
                IqEvent::End(StreamEnd::Eof)
            };
            let expected = serial.consume(clone_event(&boundary)).unwrap();
            let actual = windowed.consume(boundary).unwrap();
            assert!(actual.frames.is_empty());
            let truncations = |out: &DecodeOutput| {
                out.diagnostics
                    .iter()
                    .filter(|d| matches!(d, PhyDiagnostic::TruncatedFrame))
                    .count()
            };
            assert!(truncations(&expected) > 0);
            assert_eq!(truncations(&actual), truncations(&expected), "gap={gap}");
            assert_eq!(
                windowed.ofdm_stats().truncated_frames,
                serial.ofdm_stats().truncated_frames
            );
            assert_eq!(
                windowed.dsss_stats().truncated_frames,
                serial.dsss_stats().truncated_frames
            );
            assert!(windowed
                .consume(IqEvent::End(StreamEnd::Eof))
                .unwrap()
                .frames
                .is_empty());
        }
    }
}

#[test]
fn split_dsss_workers_preserve_frame_occurrences() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    for index in [
        include_str!("fixtures/iq/ofdm-index.tsv"),
        include_str!("fixtures/iq/dsss-index.tsv"),
    ] {
        for line in index.lines().skip(1) {
            let name = line.split('\t').next().unwrap();
            let packet = std::fs::read(root.join(format!("{name}.cs8"))).unwrap();
            // Repeated identical frames must remain distinct occurrences.
            let mut bytes = packet.clone();
            bytes.extend_from_slice(&[0; 1024]);
            bytes.extend_from_slice(&packet);
            for size in [1, 127, 4096] {
                let mut source =
                    ReaderIqSource::new(Cursor::new(&bytes), config(size), position()).unwrap();
                let mut serial = LegacyWifiDecoder::new();
                let mut parallel = ParallelLegacyWifiDecoder::with_parallel_dsss().unwrap();
                let mut expected = Vec::new();
                let mut actual = Vec::new();
                loop {
                    let event = source.next_event().unwrap();
                    let end = matches!(event, IqEvent::End(_));
                    expected.extend(serial.consume(clone_event(&event)).unwrap().frames);
                    actual.extend(parallel.consume(event).unwrap().frames);
                    if end {
                        break;
                    }
                }
                assert_eq!(actual.len(), expected.len(), "{name}, chunk={size}");
                for (a, e) in actual.iter().zip(&expected) {
                    assert_eq!(a.bytes, e.bytes, "{name}, chunk={size}");
                    assert_eq!(a.rate_bps, e.rate_bps, "{name}, chunk={size}");
                    assert!(
                        a.start.sample_index.abs_diff(e.start.sample_index) <= 3,
                        "{name}"
                    );
                    assert!(
                        a.end_sample_index.abs_diff(e.end_sample_index) <= 3,
                        "{name}"
                    );
                }
            }
        }
    }
}

#[test]
fn split_dsss_budget_and_reset_clear_duplicate_history() {
    let bytes = include_bytes!("fixtures/iq/dsss-20-short-clean-48.cs8");
    let mut c = config(bytes.len() / 2);
    c.max_pending_frames = 6;
    let event = |c: RxConfig| {
        IqEvent::Chunk(
            IqChunk::new(c, position(), bytes.iter().map(|b| *b as i8).collect()).unwrap(),
        )
    };
    let mut decoder = ParallelLegacyWifiDecoder::with_parallel_dsss().unwrap();
    assert_eq!(decoder.consume(event(c.clone())).unwrap().frames.len(), 1);
    decoder.reset(ResetReason::Explicit);
    assert_eq!(decoder.consume(event(c.clone())).unwrap().frames.len(), 1);
    // A repeated source position is a discontinuity, which must also clear history.
    assert_eq!(decoder.consume(event(c.clone())).unwrap().frames.len(), 1);
    let mut repeated = bytes.to_vec();
    repeated.extend_from_slice(&[0; 1024]);
    repeated.extend_from_slice(bytes);
    c.max_chunk_samples = repeated.len() / 2;
    let overflow = IqEvent::Chunk(
        IqChunk::new(
            c.clone(),
            position(),
            repeated.iter().map(|b| *b as i8).collect(),
        )
        .unwrap(),
    );
    assert!(matches!(
        decoder.consume(overflow),
        Err(RadioError::Limit { .. })
    ));
    assert_eq!(decoder.consume(event(c.clone())).unwrap().frames.len(), 1);
    c.max_pending_frames = 5;
    assert!(matches!(
        decoder.consume(event(c.clone())),
        Err(RadioError::Invalid { .. })
    ));
    c.max_pending_frames = 6;
    c.max_buffer_samples = 639;
    c.max_chunk_samples = 128;
    let small = IqEvent::Chunk(IqChunk::new(c, position(), vec![0; 256]).unwrap());
    assert!(matches!(
        decoder.consume(small),
        Err(RadioError::Invalid { .. })
    ));
}
