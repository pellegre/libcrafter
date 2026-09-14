use super::*;
use crate::radio::eht::{
    sig::iq::{Receiver as SignalReceiver, SignalFields},
    test_support::fixture,
    training, EhtNonOfdmaUsers,
};
use crate::radio::{PhyDiagnostic, WifiDecoder};

fn corpus() -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-data-bcc-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|octet| u8::from_str_radix(std::str::from_utf8(octet).unwrap(), 16).unwrap())
        .collect()
}

fn first_mpdu(psdu: &[u8]) -> &[u8] {
    let header = u16::from_le_bytes([psdu[0], psdu[1]]);
    let length = usize::from(header >> 4) | (usize::from(psdu[0] & 12) << 10);
    &psdu[4..4 + length]
}

#[test]
fn radio_eht_data_bcc_independent_iq_waveforms() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-data-bcc-iq-index.tsv");
    let corpus = corpus();
    assert_eq!(rows.lines().skip(1).count(), 352);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[14].parse().unwrap();
        let length: usize = columns[15].parse().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        let input = &samples[acquisition.signal_start as usize..];
        let signal = SignalReceiver::recover(input, &acquisition).expect(columns[0]);
        assert_eq!(signal.legacy_length, columns[9].parse().unwrap());
        let trained = training::Receiver::recover(input, &acquisition, signal).expect(columns[0]);
        assert_eq!(trained.data_start, columns[11].parse().unwrap());
        let admission =
            super::super::Receiver::admit(trained, usize::MAX, usize::MAX).expect(columns[0]);
        assert_eq!(admission.capacity.mcs, columns[3].parse::<u8>().unwrap());
        assert_eq!(admission.timing.data_symbols, columns[7].parse().unwrap());
        assert_eq!(admission.trained.guard, columns[5].parse().unwrap());
        assert_eq!(
            admission.info.end_sample_index,
            columns[12].parse().unwrap()
        );
        assert_eq!(admission.required_samples, input.len());
        let recovered = super::super::Receiver::recover(admission, input, &acquisition, usize::MAX)
            .expect(columns[0]);
        assert_eq!(recovered.psdu, bytes(columns[8]), "{}", columns[0]);
        let SignalFields::NonOfdma(signal) = recovered.admission.trained.signal.signal else {
            panic!("{}: expected non-OFDMA", columns[0]);
        };
        let EhtNonOfdmaUsers::Single(user) = signal.users else {
            panic!("{}: expected single user", columns[0]);
        };
        assert_eq!(user.mcs, columns[3].parse::<u8>().unwrap());
        assert_eq!(
            signal.common.pre_fec_padding_factor,
            columns[6].parse::<u8>().unwrap()
        );
    }
}

#[test]
fn radio_eht_data_bcc_streams_raw_mpdu_bytes() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-data-bcc-iq-index.tsv");
    let corpus = corpus();
    for (index, row) in rows.lines().skip(1).enumerate() {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[14].parse().unwrap();
        let length: usize = columns[15].parse().unwrap();
        let expected_psdu = bytes(columns[8]);
        let output = crate::radio::eht::test_support::feed(
            &mut WifiDecoder::new(),
            &corpus[offset..offset + length],
            [1, 37, 128, 997][index % 4],
        );
        assert_eq!(output.frames.len(), 1, "{}: {output:?}", columns[0]);
        assert_eq!(
            output.frames[0].bytes,
            first_mpdu(&expected_psdu),
            "{}",
            columns[0]
        );
        assert_eq!(
            output.frames[0].end_sample_index,
            columns[12].parse().unwrap(),
            "{}",
            columns[0]
        );
        assert!(
            output.frames[0]
                .diagnostics
                .iter()
                .any(|diagnostic| matches!(diagnostic, PhyDiagnostic::EhtSignal { .. })),
            "{}",
            columns[0]
        );
        assert!(
            output.frames[0]
                .diagnostics
                .iter()
                .any(|diagnostic| matches!(diagnostic, PhyDiagnostic::Ampdu { .. })),
            "{}",
            columns[0]
        );
    }
}

#[test]
fn radio_eht_data_iq_rejects_truncation_timing_and_nonfinite_samples() {
    let columns: Vec<_> =
        include_str!("../../../../../tests/fixtures/iq/eht-data-bcc-iq-index.tsv")
            .lines()
            .nth(1)
            .unwrap()
            .split('\t')
            .collect();
    let corpus = corpus();
    let offset: usize = columns[14].parse().unwrap();
    let length: usize = columns[15].parse().unwrap();
    let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
    let input = &samples[acquisition.signal_start as usize..];
    let signal = SignalReceiver::recover(input, &acquisition).unwrap();
    let trained = training::Receiver::recover(input, &acquisition, signal).unwrap();
    let admission = super::super::Receiver::admit(trained, usize::MAX, usize::MAX).unwrap();

    assert!(matches!(
        Demodulator::new(&input[..input.len() - 1], &acquisition, &admission),
        Err(Error::Truncated { .. })
    ));
    let mut mistimed = acquisition.clone();
    mistimed.preamble_start += 1;
    assert!(matches!(
        Demodulator::new(input, &mistimed, &admission),
        Err(Error::Training)
    ));
    let mut nonfinite = input.to_vec();
    let data = usize::try_from(admission.info.data_start - acquisition.signal_start).unwrap();
    nonfinite[data + admission.trained.guard].i = f32::NAN;
    assert!(matches!(
        Demodulator::new(&nonfinite, &acquisition, &admission)
            .unwrap()
            .recover(),
        Err(Error::Samples)
    ));
}
