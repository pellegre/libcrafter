use super::*;
use crate::radio::{
    eht::test_support::{feed, fixture},
    PhyDiagnostic, WifiDecoder,
};

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
        let fields = Receiver::recover(input, &acquisition).expect(columns[0]);
        assert_eq!(fields.usig, usig, "{}", columns[0]);
        assert_eq!(
            fields.signal,
            SignalFields::NonOfdma(expected),
            "{}",
            columns[0]
        );
        assert_eq!(fields.symbols, columns[4].parse().unwrap());
        assert_eq!(fields.end_sample, columns[5].parse().unwrap());
        assert_eq!(acquisition.preamble_start, 37);
    }
}

#[test]
fn radio_eht_mu_sig_iq_independent_waveforms() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-mu-sig-iq-index.tsv");
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-mu-sig-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(rows.lines().skip(1).count(), 448);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[7].parse().unwrap();
        let length: usize = columns[8].parse().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        let input = &samples[acquisition.signal_start as usize..];
        let usig_bits: Vec<_> = columns[1].bytes().map(|value| value - b'0').collect();
        let signal_bits: Vec<_> = columns[2].bytes().map(|value| value - b'0').collect();
        let usig = EhtUsigFields::decode(&usig_bits).unwrap();
        let expected = EhtNonOfdmaSignal::decode(&signal_bits, &usig).unwrap();
        let fields = Receiver::recover(input, &acquisition).expect(columns[0]);
        assert_eq!(fields.usig, usig, "{}", columns[0]);
        assert_eq!(
            fields.signal,
            SignalFields::NonOfdma(expected.clone()),
            "{}",
            columns[0]
        );
        assert_eq!(expected.users.len(), columns[3].parse().unwrap());
        assert_eq!(fields.symbols, columns[5].parse().unwrap());
        assert_eq!(fields.end_sample, columns[6].parse().unwrap());
        assert_eq!(acquisition.preamble_start, 37);
    }
}

#[test]
fn radio_eht_ofdma_sig_iq_independent_waveforms() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-ofdma-sig-iq-index.tsv");
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-ofdma-sig-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(rows.lines().skip(1).count(), 464);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[9].parse().unwrap();
        let length: usize = columns[10].parse().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        let input = &samples[acquisition.signal_start as usize..];
        let usig_bits: Vec<_> = columns[1].bytes().map(|value| value - b'0').collect();
        let signal_bits: Vec<_> = columns[2].bytes().map(|value| value - b'0').collect();
        let usig = EhtUsigFields::decode(&usig_bits).unwrap();
        let expected = EhtOfdmaSignal::decode(&signal_bits, &usig).unwrap();
        let fields = Receiver::recover(input, &acquisition).expect(columns[0]);
        assert_eq!(fields.usig, usig, "{}", columns[0]);
        assert_eq!(
            fields.signal,
            SignalFields::Ofdma(expected.clone()),
            "{}",
            columns[0]
        );
        assert_eq!(
            expected.common.allocation.code(),
            columns[3].parse().unwrap()
        );
        assert_eq!(expected.users.len(), columns[4].parse().unwrap());
        assert_eq!(fields.symbols, columns[7].parse().unwrap());
        assert_eq!(fields.end_sample, columns[8].parse().unwrap());
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
            Receiver::recover(&samples[acquisition.signal_start as usize..], &acquisition).is_err(),
            "{}",
            columns[0]
        );
    }
}

#[test]
fn radio_eht_mu_sig_iq_rejects_invalid_waveforms() {
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-mu-sig-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-mu-sig-iq-invalid-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 21);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[2].parse().unwrap();
        let length: usize = columns[3].parse().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        assert!(
            Receiver::recover(&samples[acquisition.signal_start as usize..], &acquisition).is_err(),
            "{}",
            columns[0]
        );
    }
}

#[test]
fn radio_eht_ofdma_sig_iq_rejects_invalid_waveforms() {
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-ofdma-sig-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-ofdma-sig-iq-invalid-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 21);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[2].parse().unwrap();
        let length: usize = columns[3].parse().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        assert!(
            Receiver::recover(&samples[acquisition.signal_start as usize..], &acquisition).is_err(),
            "{}",
            columns[0]
        );
    }
}

#[test]
fn radio_eht_sig_iq_streaming_dispatch() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-sig-iq-index.tsv");
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-sig-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    for (index, row) in rows.lines().skip(1).enumerate() {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[6].parse().unwrap();
        let length: usize = columns[7].parse().unwrap();
        let usig_bits: Vec<_> = columns[1].bytes().map(|value| value - b'0').collect();
        let signal_bits: Vec<_> = columns[2].bytes().map(|value| value - b'0').collect();
        let usig = EhtUsigFields::decode(&usig_bits).unwrap();
        let signal = EhtNonOfdmaSignal::decode(&signal_bits, &usig).unwrap();
        let output = feed(
            &mut WifiDecoder::new(),
            &corpus[offset..offset + length],
            [1, 37, 128, 997].get(index).copied().unwrap_or(997),
        );
        assert!(output.frames.is_empty(), "{}", columns[0]);
        assert!(output.diagnostics.contains(&PhyDiagnostic::EhtUsig {
            fields: usig,
            preamble_sample_index: 37,
        }));
        assert!(output.diagnostics.contains(&PhyDiagnostic::EhtSignal {
            fields: signal,
            preamble_sample_index: 37,
        }));
        assert!(output.diagnostics.contains(&PhyDiagnostic::UnsupportedPhy));
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
}

#[test]
fn radio_eht_mu_sig_iq_streaming_dispatch() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-mu-sig-iq-index.tsv");
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-mu-sig-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    for (index, row) in rows.lines().skip(1).enumerate() {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[7].parse().unwrap();
        let length: usize = columns[8].parse().unwrap();
        let usig_bits: Vec<_> = columns[1].bytes().map(|value| value - b'0').collect();
        let signal_bits: Vec<_> = columns[2].bytes().map(|value| value - b'0').collect();
        let usig = EhtUsigFields::decode(&usig_bits).unwrap();
        let signal = EhtNonOfdmaSignal::decode(&signal_bits, &usig).unwrap();
        let output = feed(
            &mut WifiDecoder::new(),
            &corpus[offset..offset + length],
            [1, 37, 128, 997].get(index).copied().unwrap_or(997),
        );
        assert!(output.frames.is_empty(), "{}", columns[0]);
        assert!(output.diagnostics.contains(&PhyDiagnostic::EhtUsig {
            fields: usig,
            preamble_sample_index: 37,
        }));
        assert!(output.diagnostics.contains(&PhyDiagnostic::EhtSignal {
            fields: signal,
            preamble_sample_index: 37,
        }));
        assert!(output.diagnostics.contains(&PhyDiagnostic::UnsupportedPhy));
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
}

#[test]
fn radio_eht_ofdma_sig_iq_streaming_dispatch() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-ofdma-sig-iq-index.tsv");
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-ofdma-sig-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    for (index, row) in rows.lines().skip(1).enumerate() {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[9].parse().unwrap();
        let length: usize = columns[10].parse().unwrap();
        let usig_bits: Vec<_> = columns[1].bytes().map(|value| value - b'0').collect();
        let signal_bits: Vec<_> = columns[2].bytes().map(|value| value - b'0').collect();
        let usig = EhtUsigFields::decode(&usig_bits).unwrap();
        let signal = EhtOfdmaSignal::decode(&signal_bits, &usig).unwrap();
        let output = feed(
            &mut WifiDecoder::new(),
            &corpus[offset..offset + length],
            [1, 37, 128, 997].get(index).copied().unwrap_or(997),
        );
        assert!(output.frames.is_empty(), "{}", columns[0]);
        assert!(output.diagnostics.contains(&PhyDiagnostic::EhtUsig {
            fields: usig,
            preamble_sample_index: 37,
        }));
        assert!(output.diagnostics.contains(&PhyDiagnostic::EhtOfdmaSignal {
            fields: signal,
            preamble_sample_index: 37,
        }));
        assert!(output.diagnostics.contains(&PhyDiagnostic::UnsupportedPhy));
        assert!(!output
            .diagnostics
            .iter()
            .any(|diagnostic| matches!(diagnostic, PhyDiagnostic::EhtSignal { .. })));
    }
}

#[test]
fn radio_eht_sig_iq_streaming_rejects_invalid_waveforms() {
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-sig-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    for row in include_str!("../../../../../tests/fixtures/iq/eht-sig-iq-invalid-index.tsv")
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
        assert!(!output
            .diagnostics
            .iter()
            .any(|diagnostic| matches!(diagnostic, PhyDiagnostic::EhtSignal { .. })));
        assert!(output.diagnostics.iter().any(|diagnostic| matches!(
            diagnostic,
            PhyDiagnostic::UnsupportedPhy
                | PhyDiagnostic::InvalidHeader
                | PhyDiagnostic::TruncatedFrame
        )));
    }
}

#[test]
fn radio_eht_mu_sig_iq_streaming_rejects_invalid_waveforms() {
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-mu-sig-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    for row in include_str!("../../../../../tests/fixtures/iq/eht-mu-sig-iq-invalid-index.tsv")
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
        assert!(!output
            .diagnostics
            .iter()
            .any(|diagnostic| matches!(diagnostic, PhyDiagnostic::EhtSignal { .. })));
        assert!(output.diagnostics.iter().any(|diagnostic| matches!(
            diagnostic,
            PhyDiagnostic::UnsupportedPhy
                | PhyDiagnostic::InvalidHeader
                | PhyDiagnostic::TruncatedFrame
        )));
    }
}

#[test]
fn radio_eht_ofdma_sig_iq_streaming_rejects_invalid_waveforms() {
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-ofdma-sig-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    for row in include_str!("../../../../../tests/fixtures/iq/eht-ofdma-sig-iq-invalid-index.tsv")
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
        assert!(!output
            .diagnostics
            .iter()
            .any(|diagnostic| matches!(diagnostic, PhyDiagnostic::EhtOfdmaSignal { .. })));
        assert!(output.diagnostics.iter().any(|diagnostic| matches!(
            diagnostic,
            PhyDiagnostic::UnsupportedPhy
                | PhyDiagnostic::InvalidHeader
                | PhyDiagnostic::TruncatedFrame
        )));
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
        assert!(Receiver::recover(&input[..length], &acquisition).is_err());
    }
    for index in [16, 96, 176, 256, 336, 416, 479] {
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut damaged = input.to_vec();
            damaged[index].i = value;
            assert!(Receiver::recover(&damaged, &acquisition).is_err());
        }
    }
    let mut overflow = acquisition.clone();
    overflow.signal_start = u64::MAX - 400;
    overflow.phase_origin =
        overflow.signal_start - (acquisition.signal_start - acquisition.phase_origin);
    assert!(Receiver::recover(input, &overflow).is_err());
}
