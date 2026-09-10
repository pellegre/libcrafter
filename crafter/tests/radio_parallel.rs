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
    assert_eq!(actual, expected);
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
