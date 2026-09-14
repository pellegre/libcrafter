use super::*;
use crate::protocols::link::{
    Dot11EhtTriggerCommonFields, Dot11EhtTriggerSpecialUserFields, Dot11EhtTriggerUserFields,
};
use crate::radio::eht::{test_support::fixture, EhtResourceUnit};
use crate::radio::{PhyDiagnostic, WifiDecoder};

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|octet| u8::from_str_radix(std::str::from_utf8(octet).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn radio_eht_tb_bcc_independent_iq_waveforms() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-tb-data-bcc-iq-index.tsv");
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-tb-data-bcc-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(rows.lines().skip(1).count(), 12);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let offset = columns[15].parse::<usize>().unwrap();
        let length = columns[16].parse::<usize>().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        let input = &samples[acquisition.signal_start as usize..];
        let common = Dot11EhtTriggerCommonFields {
            ul_length: columns[10].parse().unwrap(),
            gi_ltf: columns[4].parse().unwrap(),
            ltf_symbols: columns[5].parse().unwrap(),
            pre_fec_padding_raw: 0,
            ..Default::default()
        };
        let special = Dot11EhtTriggerSpecialUserFields {
            spatial_reuse_1: columns[11].parse().unwrap(),
            spatial_reuse_2: columns[12].parse().unwrap(),
            ..Default::default()
        };
        let user = Dot11EhtTriggerUserFields {
            aid12: 1,
            ru_allocation: columns[2].parse().unwrap(),
            mcs: columns[3].parse().unwrap(),
            ..Default::default()
        };
        let resource = EhtResourceUnit::from_trigger_20(user.ru_allocation).unwrap();
        let admission = Receiver::admit(
            input,
            &acquisition,
            &common,
            &special,
            &user,
            resource,
            usize::MAX,
            usize::MAX,
        )
        .unwrap_or_else(|error| panic!("{}: {error:?}", columns[0]));
        assert_eq!(admission.required_samples, input.len(), "{}", columns[0]);
        assert_eq!(
            admission.timing.data_symbols,
            columns[9].parse::<usize>().unwrap(),
            "{}",
            columns[0]
        );
        let recovered = Receiver::recover(admission, input, &acquisition, usize::MAX, false)
            .unwrap_or_else(|error| panic!("{}: {error:?}", columns[0]));
        assert_eq!(recovered.psdu, bytes(columns[13]), "{}", columns[0]);
        assert_eq!(recovered.failed_codewords, 0);
        assert_eq!(recovered.first_failure, None);
    }
}

#[test]
fn radio_eht_tb_ldpc_independent_iq_waveforms() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-tb-data-ldpc-iq-index.tsv");
    let corpus = std::fs::read(format!(
        "{}/tests/fixtures/iq/eht-tb-data-ldpc-iq.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(rows.lines().skip(1).count(), 7);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let offset = columns[17].parse::<usize>().unwrap();
        let length = columns[18].parse::<usize>().unwrap();
        let (samples, acquisition) = fixture(&corpus[offset..offset + length]);
        let input = &samples[acquisition.signal_start as usize..];
        let padding = columns[10].parse::<u8>().unwrap();
        let common = Dot11EhtTriggerCommonFields {
            ul_length: columns[12].parse().unwrap(),
            gi_ltf: columns[4].parse().unwrap(),
            ltf_symbols: columns[5].parse().unwrap(),
            pre_fec_padding_raw: padding % 4,
            ldpc_extra_segment: columns[11] == "1",
            ..Default::default()
        };
        let special = Dot11EhtTriggerSpecialUserFields {
            spatial_reuse_1: columns[13].parse().unwrap(),
            spatial_reuse_2: columns[14].parse().unwrap(),
            ..Default::default()
        };
        let user = Dot11EhtTriggerUserFields {
            aid12: 1,
            ru_allocation: columns[2].parse().unwrap(),
            mcs: columns[3].parse().unwrap(),
            ldpc: true,
            ..Default::default()
        };
        let resource = EhtResourceUnit::from_trigger_20(user.ru_allocation).unwrap();
        let admission = Receiver::admit(
            input,
            &acquisition,
            &common,
            &special,
            &user,
            resource,
            usize::MAX,
            usize::MAX,
        )
        .unwrap_or_else(|error| panic!("{}: {error:?}", columns[0]));
        assert_eq!(admission.required_samples, input.len(), "{}", columns[0]);
        assert_eq!(
            admission.timing.data_symbols,
            columns[9].parse::<usize>().unwrap(),
            "{}",
            columns[0]
        );
        let recovered = Receiver::recover(admission, input, &acquisition, usize::MAX, false)
            .unwrap_or_else(|error| panic!("{}: {error:?}", columns[0]));
        assert_eq!(recovered.psdu, bytes(columns[15]), "{}", columns[0]);
        assert_eq!(recovered.failed_codewords, 0);
        assert_eq!(recovered.first_failure, None);
    }
}

#[test]
fn radio_eht_tb_streaming_requires_a_matching_trigger() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let rows = std::fs::read_to_string(root.join("eht-tb-exchange-index.tsv")).unwrap();
    assert_eq!(rows.lines().skip(1).count(), 9);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let iq = std::fs::read(root.join(format!("{}.cs8", columns[0]))).unwrap();
        for chunk in [7, 128, 4096] {
            let output = crate::radio::eht::test_support::feed(&mut WifiDecoder::new(), &iq, chunk);
            let mut expected = Vec::new();
            if columns[8] != "-" {
                expected.push(bytes(columns[8]));
            }
            if columns[9] != "-" {
                expected.push(bytes(columns[9]));
            }
            assert_eq!(
                output
                    .frames
                    .iter()
                    .map(|frame| &frame.bytes)
                    .collect::<Vec<_>>(),
                expected.iter().collect::<Vec<_>>(),
                "{} chunk {chunk}: {:?}",
                columns[0],
                output.diagnostics
            );
            if columns[9] != "-" {
                let response = output.frames.last().unwrap();
                assert_eq!(
                    response.start.sample_index,
                    columns[7].parse::<u64>().unwrap(),
                    "{}",
                    columns[0]
                );
                assert!(response.diagnostics.iter().any(|diagnostic| matches!(
                    diagnostic,
                    PhyDiagnostic::EhtTbUser {
                        trigger_preamble_sample_index: 64,
                        ..
                    }
                )));
            } else {
                assert!(!output.frames.iter().any(|frame| frame
                    .diagnostics
                    .iter()
                    .any(|diagnostic| matches!(diagnostic, PhyDiagnostic::EhtTbUser { .. }))));
            }
        }
    }
}
