use super::*;
use crate::radio::sync::{SyncEvent, Synchronizer};

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
fn radio_eht_sig_iq_independent_waveforms() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-sig-iq-index.tsv");
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-sig-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(rows.lines().skip(1).count(), 512);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[6].parse().unwrap();
        let length: usize = columns[7].parse().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        let input = &samples[acquisition.signal_start as usize..];
        let usig_bits: Vec<_> = columns[1].bytes().map(|value| value - b'0').collect();
        let signal_bits: Vec<_> = columns[2].bytes().map(|value| value - b'0').collect();
        let usig = EhtUsigFields::decode(&usig_bits).unwrap();
        let expected = EhtNonOfdmaSignal::decode(&signal_bits, &usig).unwrap();
        let fields = recover(input, &acquisition).expect(columns[0]);
        assert_eq!(fields.usig, usig, "{}", columns[0]);
        assert_eq!(fields.signal, expected, "{}", columns[0]);
        assert_eq!(fields.symbols, columns[4].parse().unwrap());
        assert_eq!(fields.end_sample, columns[5].parse().unwrap());
        assert_eq!(acquisition.preamble_start, 37);
    }
}

#[test]
fn radio_eht_sig_iq_rejects_invalid_waveforms() {
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-sig-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-sig-iq-invalid-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 21);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[2].parse().unwrap();
        let length: usize = columns[3].parse().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        assert!(
            recover(&samples[acquisition.signal_start as usize..], &acquisition).is_err(),
            "{}",
            columns[0]
        );
    }
}

#[test]
fn radio_eht_sig_iq_bounds_nonfinite_and_overflow() {
    let index: Vec<_> = include_str!("../../../../../tests/fixtures/iq/eht-sig-iq-index.tsv")
        .lines()
        .nth(1)
        .unwrap()
        .split('\t')
        .collect();
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-sig-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let offset: usize = index[6].parse().unwrap();
    let length: usize = index[7].parse().unwrap();
    let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
    let input = &samples[acquisition.signal_start as usize..];
    for length in [0, 79, 159, 239, 319, 399, 479] {
        assert!(recover(&input[..length], &acquisition).is_err());
    }
    for index in [16, 96, 176, 256, 336, 416, 479] {
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut damaged = input.to_vec();
            damaged[index].i = value;
            assert!(recover(&damaged, &acquisition).is_err());
        }
    }
    let mut overflow = acquisition.clone();
    overflow.signal_start = u64::MAX - 400;
    overflow.phase_origin =
        overflow.signal_start - (acquisition.signal_start - acquisition.phase_origin);
    assert!(recover(input, &overflow).is_err());
}
