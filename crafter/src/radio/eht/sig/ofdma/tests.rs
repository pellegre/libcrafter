use super::*;
use crate::radio::{
    EhtMuPpduType, EhtMuUsigFields, EhtSigMcs, EhtTbUsigFields, EhtUsigFields, EhtUsigFormat,
};

fn bits(text: &str) -> Vec<u8> {
    text.bytes().map(|value| value - b'0').collect()
}

fn put(bits: &mut [u8], start: usize, count: usize, value: u16) {
    for index in 0..count {
        bits[start + index] = ((value >> index) & 1) as u8;
    }
}

fn repair(bits: &mut [u8], protected: usize) {
    let crc = crate::radio::ht::crc(&bits[..protected]) >> 4;
    for index in 0..4 {
        bits[protected + index] = (crc >> (3 - index)) & 1;
    }
}

fn assert_common(common: &EhtOfdmaCommon, fields: &[&str]) {
    assert_eq!(common.spatial_reuse, fields[2].parse::<u8>().unwrap());
    assert_eq!(common.ltf_mode as u8, fields[3].parse::<u8>().unwrap());
    assert_eq!(common.ltf_mode.size(), fields[4].parse::<u8>().unwrap());
    assert_eq!(
        common.ltf_mode.guard_interval_ns(),
        fields[5].parse::<u16>().unwrap()
    );
    assert_eq!(common.ltf_symbols, fields[6].parse::<u8>().unwrap());
    assert_eq!(common.ldpc_extra_symbol, fields[7] == "1");
    assert_eq!(
        common.pre_fec_padding_factor,
        fields[8].parse::<u8>().unwrap()
    );
    assert_eq!(common.pe_disambiguity, fields[9] == "1");
    assert_eq!(common.disregard, fields[10].parse::<u8>().unwrap());
    assert_eq!(common.allocation.code(), fields[11].parse::<u16>().unwrap());
    assert_eq!(
        common.allocation.user_count(),
        fields[12].parse::<u8>().unwrap()
    );
    assert_eq!(
        common.allocation.user_kind(),
        if fields[13] == "mu" {
            EhtOfdmaUserKind::MuMimo
        } else {
            EhtOfdmaUserKind::NonMu
        }
    );
}

#[test]
fn radio_eht_sig_ofdma_complete_block_chains() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-ofdma-sig-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 928);
    for row in rows.lines().skip(1) {
        let fields: Vec<_> = row.split('\t').collect();
        let usig = EhtUsigFields::decode(&bits(fields[0])).unwrap();
        let decoded = EhtOfdmaSignal::decode(&bits(fields[1]), &usig).unwrap();
        assert_common(&decoded.common, &fields);
        assert_eq!(decoded.users.len(), fields[12].parse::<usize>().unwrap());
        let expected: Vec<Vec<u16>> = fields[14]
            .split(';')
            .map(|user| {
                user.split(':')
                    .map(|value| value.parse::<u16>().unwrap())
                    .collect()
            })
            .collect();
        assert_eq!(decoded.users.len(), expected.len());
        for (actual, expected) in decoded.users.iter().zip(expected) {
            match actual.as_ref().unwrap() {
                EhtOfdmaUser::NonMu(user) => {
                    assert_eq!(expected.len(), 6);
                    assert_eq!(user.sta_id, expected[0]);
                    assert_eq!(u16::from(user.mcs), expected[1]);
                    assert_eq!(u16::from(user.reserved), expected[2]);
                    assert_eq!(u16::from(user.space_time_streams), expected[3]);
                    assert_eq!(u16::from(user.beamformed), expected[4]);
                    assert_eq!(u16::from(user.ldpc), expected[5]);
                }
                EhtOfdmaUser::MuMimo(user) => {
                    assert_eq!(expected.len(), 4);
                    assert_eq!(user.sta_id, expected[0]);
                    assert_eq!(u16::from(user.mcs), expected[1]);
                    assert_eq!(u16::from(user.ldpc), expected[2]);
                    assert_eq!(u16::from(user.spatial_configuration), expected[3]);
                }
            }
        }
    }
}

#[test]
fn radio_eht_sig_ofdma_allocation_and_context_bounds() {
    let fields: Vec<_> = include_str!("../../../../../tests/fixtures/iq/eht-ofdma-sig-index.tsv")
        .lines()
        .nth(1)
        .unwrap()
        .split('\t')
        .collect();
    let usig = EhtUsigFields::decode(&bits(fields[0])).unwrap();
    let original = bits(fields[1]);
    for code in 0..=511u16 {
        let mut first = original[..36].to_vec();
        put(&mut first, 17, 9, code);
        repair(&mut first, 26);
        let valid = matches!(code, 0..=25 | 32..=55 | 64..=71);
        assert_eq!(
            EhtOfdmaSignal::required_bits(&first, &usig).is_ok(),
            valid,
            "allocation {code}"
        );
    }

    let mut wider = usig;
    wider.bandwidth_code = 1;
    assert_eq!(
        EhtOfdmaSignal::decode(&original, &wider),
        Err(EhtSigError::Bandwidth(1))
    );
    let mut other = usig;
    let EhtUsigFormat::Mu(ref mut mu) = other.format else {
        unreachable!()
    };
    mu.ppdu_type = EhtMuPpduType::SingleUser;
    assert_eq!(
        EhtOfdmaSignal::decode(&original, &other),
        Err(EhtSigError::UnsupportedFormat)
    );
    let trigger = EhtUsigFields {
        format: EhtUsigFormat::TriggerBased(EhtTbUsigFields {
            spatial_reuse: [0, 0],
        }),
        ..usig
    };
    assert_eq!(
        EhtOfdmaSignal::decode(&original, &trigger),
        Err(EhtSigError::UnsupportedFormat)
    );
    let manual = EhtUsigFields {
        format: EhtUsigFormat::Mu(EhtMuUsigFields {
            ppdu_type: EhtMuPpduType::DownlinkOfdma,
            punctured_channel_information: 0,
            eht_sig_mcs: EhtSigMcs::Mcs0,
            eht_sig_symbols: 2,
        }),
        ..usig
    };
    assert!(EhtOfdmaSignal::required_bits(&original[..36], &manual).is_ok());
}

#[test]
fn radio_eht_sig_ofdma_integrity_and_semantic_errors() {
    let fields: Vec<_> = include_str!("../../../../../tests/fixtures/iq/eht-ofdma-sig-index.tsv")
        .lines()
        .skip(1)
        .find(|row| row.split('\t').nth(11) == Some("65"))
        .unwrap()
        .split('\t')
        .collect();
    let usig = EhtUsigFields::decode(&bits(fields[0])).unwrap();
    let original = bits(fields[1]);
    for available in [0, 35, original.len() - 1, original.len() + 1] {
        let input = if available <= original.len() {
            original[..available].to_vec()
        } else {
            let mut input = original.clone();
            input.push(0);
            input
        };
        assert!(matches!(
            EhtOfdmaSignal::decode(&input, &usig),
            Err(EhtSigError::BitCount { .. })
        ));
    }
    for (index, block) in [(26, 0), (80, 1)] {
        let mut damaged = original.clone();
        damaged[index] ^= 1;
        assert!(matches!(
            EhtOfdmaSignal::decode(&damaged, &usig),
            Err(EhtSigError::Crc { block: actual, .. }) if actual == block
        ));
    }
    for (index, block) in [(30, 0), (84, 1)] {
        let mut damaged = original.clone();
        damaged[index] = 1;
        assert!(matches!(
            EhtOfdmaSignal::decode(&damaged, &usig),
            Err(EhtSigError::TailBit { block: actual, index: actual_index })
                if actual == block && actual_index == index
        ));
    }
    let mut nonbinary = original.clone();
    nonbinary[40] = 255;
    assert_eq!(
        EhtOfdmaSignal::decode(&nonbinary, &usig),
        Err(EhtSigError::NonBinary {
            index: 40,
            value: 255,
        })
    );

    let mut sta_id = original.clone();
    put(&mut sta_id, 36, 11, 2046);
    repair(&mut sta_id[36..90], 44);
    let decoded = EhtOfdmaSignal::decode(&sta_id, &usig).unwrap();
    assert_eq!(decoded.users[0], Err(EhtSigError::MuMimoStaId { user: 0 }));
    assert!(decoded.users[1].is_ok());

    let mut mcs = original;
    put(&mut mcs, 47, 4, 14);
    repair(&mut mcs[36..90], 44);
    let decoded = EhtOfdmaSignal::decode(&mcs, &usig).unwrap();
    assert_eq!(
        decoded.users[0],
        Err(EhtSigError::MuMimoMcs { user: 0, value: 14 })
    );
    assert!(decoded.users[1].is_ok());
}
