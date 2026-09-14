use super::*;
use crate::radio::{
    sync::{SyncEvent, Synchronizer},
    DecodeOutput, IqChunk, IqEvent, IqPosition, LegacyWifiDecoder, PhyDecoder, PhyDiagnostic,
    RxConfig, StreamEnd, WifiDecoder,
};
use std::time::Duration;

fn fixture(bytes: &[u8]) -> (Vec<ComplexSample>, Acquisition) {
    let samples: Vec<_> = bytes
        .chunks_exact(2)
        .map(|bytes| ComplexSample {
            i: bytes[0] as i8 as f32 / 128.,
            q: bytes[1] as i8 as f32 / 128.,
        })
        .collect();
    let mut synchronizer = Synchronizer::default();
    for (index, sample) in samples.iter().enumerate() {
        if let Some(SyncEvent::Acquired(acquisition)) = synchronizer.push(*sample, index as u64) {
            return (samples, acquisition);
        }
    }
    panic!("fixture did not acquire")
}

#[test]
fn radio_eht_prefix_independent_iq() {
    let rows = include_str!("../../../../tests/fixtures/iq/eht-prefix-index.tsv");
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-prefix-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(rows.lines().skip(1).count(), 384);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[4].parse().unwrap();
        let length: usize = columns[5].parse().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        let input = &samples[acquisition.signal_start as usize..];
        let bits: Vec<_> = columns[1].bytes().map(|value| value - b'0').collect();
        let expected = EhtUsigFields::decode(&bits).unwrap();
        let prefix = decode_prefix(input, &acquisition).expect(columns[0]);
        assert_eq!(prefix.fields, expected, "{}", columns[0]);
        assert_eq!(prefix.legacy_length, columns[2].parse().unwrap());
        assert_eq!(prefix.end_sample, columns[3].parse().unwrap());
        assert_eq!(acquisition.preamble_start, 37);
        assert_eq!(repeated_legacy_signal(input, &acquisition), Some(300));
        assert_eq!(
            repeated_legacy_signal(&input[..160], &acquisition),
            Some(300)
        );
        assert!(crate::radio::he::iq::repeated_su_signal(input, &acquisition).is_none());
        assert!(crate::radio::he::iq::repeated_er_signal(input, &acquisition).is_none());
        assert!(crate::radio::ht::decode_iq(&input[80..240], &acquisition).is_none());
        assert!(crate::radio::vht::iq::signal_a(&input[80..240], &acquisition).is_none());
    }
}

#[test]
fn radio_eht_prefix_rejects_other_and_damaged_formats() {
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-prefix-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    for row in include_str!("../../../../tests/fixtures/iq/eht-prefix-invalid-index.tsv")
        .lines()
        .skip(1)
    {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[2].parse().unwrap();
        let length: usize = columns[3].parse().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        assert!(
            decode_prefix(&samples[acquisition.signal_start as usize..], &acquisition).is_none(),
            "{}",
            columns[0]
        );
    }
}

#[test]
fn radio_eht_prefix_bounds_and_nonfinite_samples() {
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-prefix-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let row: Vec<_> = include_str!("../../../../tests/fixtures/iq/eht-prefix-index.tsv")
        .lines()
        .nth(1)
        .unwrap()
        .split('\t')
        .collect();
    let offset: usize = row[4].parse().unwrap();
    let length: usize = row[5].parse().unwrap();
    let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
    let input = &samples[acquisition.signal_start as usize..];
    for length in [0, 79, 159, 239, 319] {
        assert!(decode_prefix(&input[..length], &acquisition).is_none());
    }
    for index in [16, 96, 176, 256, 319] {
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut damaged = input.to_vec();
            damaged[index].i = value;
            assert!(decode_prefix(&damaged, &acquisition).is_none());
        }
    }
    for offset in [40, 319] {
        let mut overflow = acquisition.clone();
        overflow.signal_start = u64::MAX - offset;
        overflow.phase_origin =
            overflow.signal_start - (acquisition.signal_start - acquisition.phase_origin);
        assert!(decode_prefix(input, &overflow).is_none());
    }
}

fn config() -> RxConfig {
    RxConfig {
        sample_rate_hz: 20_000_000,
        center_frequency_hz: 2_412_000_000,
        max_chunk_samples: 10000,
        max_buffer_samples: 120000,
        max_frame_bytes: 4095,
        max_pending_frames: 4,
        max_capture_samples: 1000000,
        max_duration: Duration::from_secs(1),
    }
}

fn feed(decoder: &mut impl PhyDecoder, bytes: &[u8], size: usize) -> DecodeOutput {
    let mut result = DecodeOutput::default();
    for (sequence, part) in bytes.chunks(size * 2).enumerate() {
        let chunk = IqChunk::new(
            config(),
            IqPosition {
                epoch: 0,
                sequence: sequence as u64,
                sample_index: (sequence * size) as u64,
                time_anchor: None,
                discontinuity: None,
            },
            part.iter().map(|value| *value as i8).collect(),
        )
        .unwrap();
        let mut output = decoder.consume(IqEvent::Chunk(chunk)).unwrap();
        result.frames.append(&mut output.frames);
        result.diagnostics.append(&mut output.diagnostics);
    }
    let mut output = decoder.consume(IqEvent::End(StreamEnd::Eof)).unwrap();
    result.diagnostics.append(&mut output.diagnostics);
    result
}

#[test]
fn radio_eht_usig_streaming_iq() {
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-prefix-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let rows: Vec<_> = include_str!("../../../../tests/fixtures/iq/eht-prefix-index.tsv")
        .lines()
        .skip(1)
        .collect();
    assert_eq!(rows.len(), 384);
    for (index, row) in rows.into_iter().enumerate() {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[4].parse().unwrap();
        let length: usize = columns[5].parse().unwrap();
        let bytes = &corpus[offset..offset + length];
        let bits: Vec<_> = columns[1].bytes().map(|value| value - b'0').collect();
        let expected = PhyDiagnostic::EhtUsig {
            fields: EhtUsigFields::decode(&bits).unwrap(),
            preamble_sample_index: 37,
        };
        let chunk_size = [1, 37, 128, 997].get(index).copied().unwrap_or(997);
        let output = feed(&mut WifiDecoder::new(), bytes, chunk_size);
        assert!(output.frames.is_empty(), "{}", columns[0]);
        assert!(output.diagnostics.contains(&expected), "{}", columns[0]);
        assert!(
            output.diagnostics.contains(&PhyDiagnostic::UnsupportedPhy),
            "{}",
            columns[0]
        );
        assert!(!output.diagnostics.iter().any(|diagnostic| matches!(
            diagnostic,
            PhyDiagnostic::HtSignal { .. }
                | PhyDiagnostic::VhtSignalA { .. }
                | PhyDiagnostic::HeSignal { .. }
                | PhyDiagnostic::HeErSignal { .. }
                | PhyDiagnostic::HeMuSignal { .. }
                | PhyDiagnostic::HeTbSignal { .. }
        )));
    }

    let first: Vec<_> = include_str!("../../../../tests/fixtures/iq/eht-prefix-index.tsv")
        .lines()
        .nth(1)
        .unwrap()
        .split('\t')
        .collect();
    let offset: usize = first[4].parse().unwrap();
    let length: usize = first[5].parse().unwrap();
    let output = feed(
        &mut LegacyWifiDecoder::new(),
        &corpus[offset..offset + length],
        37,
    );
    assert!(!output
        .diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic, PhyDiagnostic::EhtUsig { .. })));
}

#[test]
fn radio_eht_usig_streaming_rejects_invalid_prefixes() {
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-prefix-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    for row in include_str!("../../../../tests/fixtures/iq/eht-prefix-invalid-index.tsv")
        .lines()
        .skip(1)
    {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[2].parse().unwrap();
        let length: usize = columns[3].parse().unwrap();
        let output = feed(
            &mut WifiDecoder::new(),
            &corpus[offset..offset + length],
            37,
        );
        assert!(output.frames.is_empty(), "{}", columns[0]);
        assert!(
            !output
                .diagnostics
                .iter()
                .any(|diagnostic| matches!(diagnostic, PhyDiagnostic::EhtUsig { .. })),
            "{}",
            columns[0]
        );
    }
}
