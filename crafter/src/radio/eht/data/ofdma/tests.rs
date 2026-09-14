use super::super::Error;
use super::*;
use crate::radio::eht::{
    sig::iq::{Receiver as SignalReceiver, SignalFields},
    test_support::fixture,
    training, EhtOfdmaUser, EhtRuSize,
};
use crate::radio::{PhyDiagnostic, WifiDecoder};

fn corpus() -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-ofdma-training-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn data_corpus() -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-ofdma-data-bcc-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn ldpc_data_corpus() -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-ofdma-data-ldpc-iq.cs8",
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

#[test]
fn radio_eht_ofdma_data_admits_each_independent_ru() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-ofdma-training-iq-index.tsv");
    let corpus = corpus();
    let mut checked = 0usize;
    for row in rows
        .lines()
        .skip(1)
        .filter(|row| row.split('\t').nth(6) == Some("1"))
    {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[16].parse().unwrap();
        let length: usize = columns[17].parse().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        let input = &samples[acquisition.signal_start as usize..];
        let signal = SignalReceiver::recover(input, &acquisition).expect(columns[0]);
        let mut trained =
            training::Receiver::recover(input, &acquisition, signal).expect(columns[0]);
        let SignalFields::Ofdma(fields) = &mut trained.signal.signal else {
            panic!("{} is not OFDMA", columns[0])
        };
        fields.common.pre_fec_padding_factor = 4;
        fields.common.ldpc_extra_symbol = false;
        fields.common.pe_disambiguity = false;
        for user in &mut fields.users {
            if let Ok(EhtOfdmaUser::NonMu(user)) = user {
                user.mcs = 0;
                user.space_time_streams = 1;
                user.ldpc = false;
            }
        }
        trained.signal.legacy_length = 900;
        let expected: Vec<_> = fields
            .common
            .allocation
            .resources()
            .iter()
            .map(|resource| resource.user_count() == 1)
            .collect();
        let timing = super::super::Timing::new(&trained.signal).expect(columns[0]);
        let SignalFields::Ofdma(fields) = &trained.signal.signal else {
            unreachable!()
        };
        for (&resource, user) in fields
            .common
            .allocation
            .resources()
            .iter()
            .zip(&fields.users)
            .filter(|(resource, _)| resource.user_count() == 1)
        {
            let Ok(EhtOfdmaUser::NonMu(user)) = user else {
                continue;
            };
            super::super::Capacity::for_ofdma(&fields.common, user, resource, timing.data_symbols)
                .unwrap_or_else(|error| panic!("{}: {error:?}", columns[0]));
        }
        let admitted = Receiver::admit(trained, usize::MAX, usize::MAX).expect(columns[0]);
        assert_eq!(admitted.users.len(), expected.len(), "{}", columns[0]);
        assert!(admitted.required_samples > input.len(), "{}", columns[0]);
        for (user, supported) in admitted.users.iter().zip(expected) {
            assert_eq!(user.is_ok(), supported, "{}", columns[0]);
            let Ok(user) = user else { continue };
            let coded: usize = user
                .resource
                .components()
                .iter()
                .map(|component| match component.size() {
                    EhtRuSize::Ru26 => 24,
                    EhtRuSize::Ru52 => 48,
                    EhtRuSize::Ru106 => 102,
                    EhtRuSize::Ru242 => 234,
                })
                .sum();
            assert_eq!(user.capacity.coded_per_symbol, coded, "{}", columns[0]);
            assert_eq!(user.capacity.data_per_symbol, coded / 2, "{}", columns[0]);
            assert_eq!(user.info.data_start, admitted.trained.data_start);
            checked += 1;
        }
    }
    assert!(checked > 100);
}

#[test]
fn radio_eht_ofdma_data_rejects_bounds_and_missing_training() {
    let row = include_str!("../../../../../tests/fixtures/iq/eht-ofdma-training-iq-index.tsv")
        .lines()
        .find(|row| row.split('\t').nth(3) == Some("0"))
        .unwrap();
    let columns: Vec<_> = row.split('\t').collect();
    let corpus = corpus();
    let offset: usize = columns[16].parse().unwrap();
    let length: usize = columns[17].parse().unwrap();
    let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
    let input = &samples[acquisition.signal_start as usize..];
    let signal = SignalReceiver::recover(input, &acquisition).unwrap();
    let mut trained = training::Receiver::recover(input, &acquisition, signal).unwrap();
    let SignalFields::Ofdma(fields) = &mut trained.signal.signal else {
        unreachable!()
    };
    fields.common.pre_fec_padding_factor = 4;
    fields.common.ldpc_extra_symbol = false;
    fields.common.pe_disambiguity = false;
    for user in &mut fields.users {
        let Ok(EhtOfdmaUser::NonMu(user)) = user else {
            unreachable!()
        };
        user.mcs = 0;
        user.space_time_streams = 1;
        user.ldpc = false;
    }
    trained.signal.legacy_length = 900;
    let data_end = super::super::Timing::new(&trained.signal).unwrap().data_end - 320;
    let mut missing = trained;
    for resource in &mut missing.resources {
        resource.channel = None;
    }
    assert!(matches!(
        Receiver::admit(missing, usize::MAX, usize::MAX),
        Err(Error::Training)
    ));

    let signal = SignalReceiver::recover(input, &acquisition).unwrap();
    let mut trained = training::Receiver::recover(input, &acquisition, signal).unwrap();
    let SignalFields::Ofdma(fields) = &mut trained.signal.signal else {
        unreachable!()
    };
    fields.common.pre_fec_padding_factor = 4;
    fields.common.ldpc_extra_symbol = false;
    fields.common.pe_disambiguity = false;
    for user in &mut fields.users {
        let Ok(EhtOfdmaUser::NonMu(user)) = user else {
            unreachable!()
        };
        user.mcs = 0;
        user.space_time_streams = 1;
        user.ldpc = false;
    }
    trained.signal.legacy_length = 900;
    assert!(matches!(
        Receiver::admit(trained, usize::MAX, data_end - 1),
        Err(Error::SampleLimit)
    ));
}

#[test]
fn radio_eht_ofdma_data_bcc_independent_iq_waveforms() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-ofdma-data-bcc-iq-index.tsv");
    let corpus = data_corpus();
    assert_eq!(rows.lines().skip(1).count(), 48);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[16].parse().unwrap();
        let length: usize = columns[17].parse().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        let input = &samples[acquisition.signal_start as usize..];
        let signal = SignalReceiver::recover(input, &acquisition).expect(columns[0]);
        let trained = training::Receiver::recover(input, &acquisition, signal).expect(columns[0]);
        let admission = Receiver::admit(trained, usize::MAX, usize::MAX).expect(columns[0]);
        assert_eq!(admission.required_samples, input.len(), "{}", columns[0]);
        let recovered =
            Receiver::recover(admission, input, &acquisition, usize::MAX).expect(columns[0]);
        let expected: Vec<_> = columns[6].split(';').map(bytes).collect();
        assert_eq!(recovered.users.len(), expected.len(), "{}", columns[0]);
        for (user, expected) in recovered.users.into_iter().zip(expected) {
            let payload = user.unwrap_or_else(|error| panic!("{}: {error:?}", columns[0]));
            assert_eq!(
                payload.psdu, expected,
                "{} user {}",
                columns[0], payload.user_index
            );
            assert_eq!(payload.failed_codewords, 0);
            assert_eq!(payload.first_failure, None);
        }
    }
}

#[test]
fn radio_eht_ofdma_data_bcc_streams_each_raw_mpdu() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-ofdma-data-bcc-iq-index.tsv");
    let corpus = data_corpus();
    for (index, row) in rows.lines().skip(1).enumerate() {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[16].parse().unwrap();
        let length: usize = columns[17].parse().unwrap();
        let output = crate::radio::eht::test_support::feed(
            &mut WifiDecoder::new(),
            &corpus[offset..offset + length],
            [1, 37, 128, 997][index % 4],
        );
        let expected: Vec<_> = columns[7].split(';').map(bytes).collect();
        assert_eq!(
            output.frames.len(),
            expected.len(),
            "{}: {output:?}",
            columns[0]
        );
        let mut recovered_users = vec![false; expected.len()];
        for frame in &output.frames {
            let user_index = frame
                .diagnostics
                .iter()
                .find_map(|diagnostic| match diagnostic {
                    PhyDiagnostic::EhtOfdmaUser { user_index, .. } => Some(*user_index),
                    _ => None,
                })
                .expect(columns[0]);
            assert!(
                user_index < expected.len(),
                "{} user {user_index}",
                columns[0]
            );
            assert!(
                !recovered_users[user_index],
                "{} duplicate user {user_index}",
                columns[0]
            );
            recovered_users[user_index] = true;
            assert_eq!(frame.bytes, expected[user_index], "{}", columns[0]);
            assert_eq!(
                frame.end_sample_index,
                columns[14].parse().unwrap(),
                "{}",
                columns[0]
            );
        }
        assert!(
            recovered_users.into_iter().all(|recovered| recovered),
            "{}",
            columns[0]
        );
    }
}

#[test]
fn radio_eht_ofdma_data_ldpc_independent_iq_waveforms() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-ofdma-data-ldpc-iq-index.tsv");
    let corpus = ldpc_data_corpus();
    assert_eq!(rows.lines().skip(1).count(), 24);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[19].parse().unwrap();
        let length: usize = columns[20].parse().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        let input = &samples[acquisition.signal_start as usize..];
        let signal = SignalReceiver::recover(input, &acquisition).expect(columns[0]);
        let trained = training::Receiver::recover(input, &acquisition, signal).expect(columns[0]);
        let admission = Receiver::admit(trained, usize::MAX, usize::MAX).expect(columns[0]);
        assert_eq!(admission.required_samples, input.len(), "{}", columns[0]);
        assert!(
            admission
                .users
                .iter()
                .filter_map(|user| user.as_ref().ok())
                .all(|user| user.capacity.ldpc),
            "{}",
            columns[0]
        );
        let recovered =
            Receiver::recover(admission, input, &acquisition, usize::MAX).expect(columns[0]);
        let expected: Vec<_> = columns[6].split(';').map(bytes).collect();
        assert_eq!(recovered.users.len(), expected.len(), "{}", columns[0]);
        for (user, expected) in recovered.users.into_iter().zip(expected) {
            let payload = user.unwrap_or_else(|error| panic!("{}: {error:?}", columns[0]));
            assert_eq!(
                payload.psdu, expected,
                "{} user {}",
                columns[0], payload.user_index
            );
            assert_eq!(payload.failed_codewords, 0, "{}", columns[0]);
            assert_eq!(payload.first_failure, None, "{}", columns[0]);
        }
    }
}

#[test]
fn radio_eht_ofdma_data_ldpc_streams_each_raw_mpdu() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-ofdma-data-ldpc-iq-index.tsv");
    let corpus = ldpc_data_corpus();
    for (index, row) in rows.lines().skip(1).enumerate() {
        let columns: Vec<_> = row.split('\t').collect();
        let offset: usize = columns[19].parse().unwrap();
        let length: usize = columns[20].parse().unwrap();
        let output = crate::radio::eht::test_support::feed(
            &mut WifiDecoder::new(),
            &corpus[offset..offset + length],
            [1, 37, 128, 997][index % 4],
        );
        let expected: Vec<_> = columns[7].split(';').map(bytes).collect();
        assert_eq!(
            output.frames.len(),
            expected.len(),
            "{}: {output:?}",
            columns[0]
        );
        let mut recovered_users = vec![false; expected.len()];
        for frame in &output.frames {
            let user_index = frame
                .diagnostics
                .iter()
                .find_map(|diagnostic| match diagnostic {
                    PhyDiagnostic::EhtOfdmaUser { user_index, .. } => Some(*user_index),
                    _ => None,
                })
                .expect(columns[0]);
            assert!(
                user_index < expected.len(),
                "{} user {user_index}",
                columns[0]
            );
            assert!(
                !recovered_users[user_index],
                "{} duplicate user {user_index}",
                columns[0]
            );
            recovered_users[user_index] = true;
            assert_eq!(frame.bytes, expected[user_index], "{}", columns[0]);
            assert_eq!(
                frame.end_sample_index,
                columns[17].parse().unwrap(),
                "{}",
                columns[0]
            );
        }
        assert!(
            recovered_users.into_iter().all(|recovered| recovered),
            "{}",
            columns[0]
        );
    }
}
