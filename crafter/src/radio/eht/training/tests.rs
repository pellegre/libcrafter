use super::*;
use crate::radio::{
    eht::{
        sig::iq::{Receiver as SignalReceiver, SignalFields},
        test_support::fixture,
        EhtNonOfdmaUsers,
    },
    resource_unit::Tones,
    PhyDiagnostic, WifiDecoder,
};

fn corpus() -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-training-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn ofdma_corpus() -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-ofdma-training-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn radio_eht_training_streaming_dispatch() {
    let rows = include_str!("../../../../tests/fixtures/iq/eht-training-iq-index.tsv");
    let corpus = corpus();
    for (index, row) in rows.lines().skip(1).enumerate() {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[11].parse().unwrap();
        let length: usize = columns[12].parse().unwrap();
        let fixture_bytes = &corpus[offset..offset + length];
        let (samples, acquisition) = fixture(fixture_bytes);
        let input = &samples[acquisition.signal_start as usize..];
        let signal = SignalReceiver::recover(input, &acquisition).unwrap();
        let trained = Receiver::recover(input, &acquisition, signal).unwrap();
        let expected =
            match crate::radio::eht::data::Receiver::admit(trained, usize::MAX, usize::MAX) {
                Ok(_) => PhyDiagnostic::TruncatedFrame,
                Err(
                    crate::radio::eht::data::Error::UnsupportedFormat
                    | crate::radio::eht::data::Error::Modulation(_)
                    | crate::radio::eht::data::Error::Coding
                    | crate::radio::eht::data::Error::FrameLimit
                    | crate::radio::eht::data::Error::SampleLimit,
                ) => PhyDiagnostic::UnsupportedPhy,
                Err(_) => PhyDiagnostic::InvalidHeader,
            };
        let output = crate::radio::eht::test_support::feed(
            &mut WifiDecoder::new(),
            fixture_bytes,
            [1, 37, 128, 997].get(index).copied().unwrap_or(997),
        );
        assert!(output.frames.is_empty(), "{}", columns[0]);
        assert!(output
            .diagnostics
            .iter()
            .any(|diagnostic| matches!(diagnostic, PhyDiagnostic::EhtSignal { .. })));
        assert!(
            output.diagnostics.contains(&expected),
            "{}: {:?}",
            columns[0],
            output.diagnostics
        );
    }
}

#[test]
fn radio_eht_training_independent_waveforms() {
    let rows = include_str!("../../../../tests/fixtures/iq/eht-training-iq-index.tsv");
    let corpus = corpus();
    assert_eq!(rows.lines().skip(1).count(), 160);
    let tones = Tones::ru(242, 1).unwrap();
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[11].parse().unwrap();
        let length: usize = columns[12].parse().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        let input = &samples[acquisition.signal_start as usize..];
        let signal = SignalReceiver::recover(input, &acquisition).expect(columns[0]);
        let trained = Receiver::recover(input, &acquisition, signal.clone()).expect(columns[0]);
        assert_eq!(trained.signal, signal, "{}", columns[0]);
        assert_eq!(trained.guard, columns[5].parse::<usize>().unwrap());
        assert_eq!(trained.data_start, columns[9].parse::<u64>().unwrap());
        assert_eq!(trained.data_start as usize, samples.len());
        assert_eq!(trained.resources.len(), 1);
        let channel = trained.resources[0].channel.as_ref().unwrap();
        let energy: f32 = tones
            .active()
            .map(|tone| channel[tone.rem_euclid(256) as usize].power())
            .sum();
        assert!(energy.is_finite() && energy > 1., "{}", columns[0]);
        for tone in -128i32..128 {
            let value = channel[tone.rem_euclid(256) as usize];
            assert!(value.power().is_finite(), "{} tone {tone}", columns[0]);
            if !tones.contains(tone) {
                assert_eq!(value, crate::radio::ComplexSample::ZERO, "{}", columns[0]);
            }
        }
    }
}

#[test]
fn radio_eht_ofdma_training_independent_waveforms() {
    let rows = include_str!("../../../../tests/fixtures/iq/eht-ofdma-training-iq-index.tsv");
    let corpus = ofdma_corpus();
    assert_eq!(rows.lines().skip(1).count(), 116);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[16].parse().unwrap();
        let length: usize = columns[17].parse().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        let input = &samples[acquisition.signal_start as usize..];
        let signal = SignalReceiver::recover(input, &acquisition).expect(columns[0]);
        let result = Receiver::recover(input, &acquisition, signal.clone());
        if columns[6] == "0" {
            assert!(
                matches!(result, Err(Error::UnsupportedFormat)),
                "{}",
                columns[0]
            );
            continue;
        }
        let trained = result.expect(columns[0]);
        assert_eq!(trained.signal, signal, "{}", columns[0]);
        assert_eq!(trained.guard, columns[11].parse::<usize>().unwrap());
        assert_eq!(trained.data_start, columns[14].parse::<u64>().unwrap());
        assert_eq!(trained.data_start as usize, samples.len());
        let SignalFields::Ofdma(fields) = &trained.signal.signal else {
            panic!("{} was not OFDMA", columns[0])
        };
        assert_eq!(fields.common.allocation.code(), columns[3].parse().unwrap());
        assert_eq!(trained.resources.len(), columns[4].parse().unwrap());
        let mut user = 0;
        for (actual, &expected) in trained
            .resources
            .iter()
            .zip(fields.common.allocation.resources())
        {
            assert_eq!(actual.resource, expected, "{}", columns[0]);
            let end = user + usize::from(expected.user_count());
            assert_eq!(actual.users, user..end, "{}", columns[0]);
            user = end;
            let channel = actual.channel.as_ref().expect(columns[0]);
            let mut energy = 0.;
            for tone in -128i16..=127 {
                let value = channel[tone.rem_euclid(256) as usize];
                assert!(value.power().is_finite(), "{} tone {tone}", columns[0]);
                if expected.contains_tone(tone) {
                    energy += value.power();
                } else {
                    assert_eq!(value, crate::radio::ComplexSample::ZERO, "{}", columns[0]);
                }
            }
            assert!(energy > 1., "{}", columns[0]);
        }
        assert_eq!(user, fields.users.len());
    }
}

#[test]
fn radio_eht_training_rejects_incomplete_and_unsupported_layouts() {
    let rows = include_str!("../../../../tests/fixtures/iq/eht-training-iq-index.tsv");
    let first: Vec<_> = rows.lines().nth(1).unwrap().split('\t').collect();
    let corpus = corpus();
    let offset: usize = first[11].parse().unwrap();
    let length: usize = first[12].parse().unwrap();
    let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
    let input = &samples[acquisition.signal_start as usize..];
    let signal = SignalReceiver::recover(input, &acquisition).unwrap();

    assert!(matches!(
        Receiver::recover(&input[..input.len() - 1], &acquisition, signal.clone()),
        Err(Error::Truncated { .. })
    ));
    let mut nonfinite = input.to_vec();
    let ltf_start = first[8].parse::<usize>().unwrap() - acquisition.signal_start as usize;
    let guard = first[5].parse::<usize>().unwrap();
    nonfinite[ltf_start + guard].i = f32::NAN;
    assert!(matches!(
        Receiver::recover(&nonfinite, &acquisition, signal.clone()),
        Err(Error::Samples)
    ));

    let mut spatial = signal.clone();
    let SignalFields::NonOfdma(fields) = &mut spatial.signal else {
        unreachable!()
    };
    let EhtNonOfdmaUsers::Single(user) = &mut fields.users else {
        unreachable!()
    };
    user.space_time_streams = 2;
    assert!(matches!(
        Receiver::recover(input, &acquisition, spatial),
        Err(Error::SpatialStreams(2))
    ));

    let mut timing = acquisition.clone();
    timing.preamble_start += 1;
    assert!(matches!(
        Receiver::recover(input, &timing, signal.clone()),
        Err(Error::Timing)
    ));
    let mut overflow = signal;
    overflow.end_sample = u64::MAX;
    assert!(matches!(
        Receiver::recover(input, &acquisition, overflow),
        Err(Error::Timing)
    ));
}

#[test]
fn radio_eht_training_waits_for_ofdma_and_rejects_mu_mimo() {
    for (index, corpus_name, offset_column, length_column) in [
        (
            include_str!("../../../../tests/fixtures/iq/eht-mu-sig-iq-index.tsv"),
            "eht-mu-sig-iq.cs8",
            7,
            8,
        ),
        (
            include_str!("../../../../tests/fixtures/iq/eht-ofdma-sig-iq-index.tsv"),
            "eht-ofdma-sig-iq.cs8",
            9,
            10,
        ),
    ] {
        let columns: Vec<_> = index.lines().nth(1).unwrap().split('\t').collect();
        let corpus = std::fs::read(format!(
            "{}/tests/fixtures/iq/{corpus_name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let offset: usize = columns[offset_column].parse().unwrap();
        let length: usize = columns[length_column].parse().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        let input = &samples[acquisition.signal_start as usize..];
        let signal = SignalReceiver::recover(input, &acquisition).unwrap();
        let result = Receiver::recover(input, &acquisition, signal);
        if corpus_name.starts_with("eht-ofdma") {
            assert!(matches!(result, Err(Error::Truncated { .. })));
        } else {
            assert!(matches!(result, Err(Error::UnsupportedFormat)));
        }
    }
}
