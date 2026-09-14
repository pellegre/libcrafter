use super::*;
use crate::radio::{
    EhtLtfMode, EhtMuPpduType, EhtMuUsigFields, EhtSigMcs, EhtTbUsigFields, EhtUsigFields,
    EhtUsigFormat,
};

fn bits(value: &str) -> Vec<u8> {
    value.bytes().map(|bit| bit - b'0').collect()
}

fn context(ppdu_type: EhtMuPpduType) -> EhtUsigFields {
    EhtUsigFields {
        bandwidth_code: 0,
        uplink: false,
        bss_color: 0,
        txop: 0,
        format: EhtUsigFormat::Mu(EhtMuUsigFields {
            ppdu_type,
            punctured_channel_information: 15,
            eht_sig_mcs: EhtSigMcs::Mcs0,
            eht_sig_symbols: 2,
        }),
    }
}

fn repair(value: &mut [u8], protected: usize) {
    let crc = crate::radio::ht::crc(&value[..protected]) >> 4;
    for (index, shift) in (0..4).zip((0..4).rev()) {
        value[protected + index] = (crc >> shift) & 1;
    }
}

fn assert_common(decoded: &EhtNonOfdmaCommon, fields: &[&str]) {
    let ltf_mode = [
        EhtLtfMode::TwoXGi800,
        EhtLtfMode::TwoXGi1600,
        EhtLtfMode::FourXGi800,
        EhtLtfMode::FourXGi3200,
    ][fields[3].parse::<usize>().unwrap()];
    assert_eq!(decoded.spatial_reuse, fields[2].parse::<u8>().unwrap());
    assert_eq!(decoded.ltf_mode, ltf_mode);
    assert_eq!(decoded.ltf_mode.size(), fields[4].parse::<u8>().unwrap());
    assert_eq!(
        decoded.ltf_mode.guard_interval_ns(),
        fields[5].parse::<u16>().unwrap()
    );
    assert_eq!(decoded.ltf_symbols, fields[6].parse::<u8>().unwrap());
    assert_eq!(decoded.ldpc_extra_symbol, fields[7] == "1");
    assert_eq!(
        decoded.pre_fec_padding_factor,
        fields[8].parse::<u8>().unwrap()
    );
    assert_eq!(decoded.pe_disambiguity, fields[9] == "1");
    assert_eq!(decoded.disregard, fields[10].parse::<u8>().unwrap());
}

#[test]
fn radio_eht_sig_non_ofdma_single_user_blocks() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-sig-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 2048);
    for row in rows.lines().skip(1) {
        let fields: Vec<_> = row.split('\t').collect();
        let usig = EhtUsigFields::decode(&bits(fields[0])).unwrap();
        let decoded = EhtNonOfdmaSignal::decode(&bits(fields[1]), &usig).unwrap();
        assert_common(&decoded.common, &fields);
        assert_eq!(decoded.common.users, 1);
        assert_eq!(decoded.users.len(), 1);
        assert!(!decoded.users.is_empty());
        let EhtNonOfdmaUsers::Single(user) = decoded.users else {
            panic!("single-user U-SIG returned MU-MIMO users")
        };
        assert_eq!(user.sta_id, fields[11].parse::<u16>().unwrap());
        assert_eq!(user.mcs, fields[12].parse::<u8>().unwrap());
        assert_eq!(user.reserved, fields[13] == "1");
        assert_eq!(user.space_time_streams, fields[14].parse::<u8>().unwrap());
        assert_eq!(user.beamformed, fields[15] == "1");
        assert_eq!(user.ldpc, fields[16] == "1");
    }
}

#[test]
fn radio_eht_sig_non_ofdma_mu_mimo_block_chains() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-mu-sig-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 1792);
    for row in rows.lines().skip(1) {
        let fields: Vec<_> = row.split('\t').collect();
        let usig = EhtUsigFields::decode(&bits(fields[0])).unwrap();
        let decoded = EhtNonOfdmaSignal::decode(&bits(fields[1]), &usig).unwrap();
        assert_common(&decoded.common, &fields);
        let expected_count = fields[11].parse::<usize>().unwrap();
        assert_eq!(usize::from(decoded.common.users), expected_count);
        assert_eq!(decoded.users.len(), expected_count);
        let EhtNonOfdmaUsers::MuMimo(users) = decoded.users else {
            panic!("MU-MIMO U-SIG returned a single-user field")
        };
        let expected: Vec<Vec<u16>> = fields[12]
            .split(';')
            .map(|user| {
                user.split(':')
                    .map(|field| field.parse::<u16>().unwrap())
                    .collect()
            })
            .collect();
        assert_eq!(users.len(), expected.len());
        for (user, expected) in users.iter().zip(expected) {
            let user = user.unwrap();
            assert_eq!(user.sta_id, expected[0]);
            assert_eq!(u16::from(user.mcs), expected[1]);
            assert_eq!(u16::from(user.ldpc), expected[2]);
            assert_eq!(u16::from(user.spatial_configuration), expected[3]);
        }
    }
}

#[test]
fn radio_eht_sig_non_ofdma_context_and_first_block_integrity() {
    let row: Vec<_> = include_str!("../../../../../tests/fixtures/iq/eht-sig-index.tsv")
        .lines()
        .nth(1)
        .unwrap()
        .split('\t')
        .collect();
    let original = bits(row[1]);
    let single = context(EhtMuPpduType::SingleUser);
    for size in [0, 51, 53] {
        let input = if size <= original.len() {
            original[..size].to_vec()
        } else {
            vec![0; size]
        };
        assert_eq!(
            EhtNonOfdmaSignal::decode(&input, &single),
            Err(EhtSigError::BitCount {
                required: 52,
                available: size
            })
        );
    }
    let mut nonbinary = original.clone();
    nonbinary[17] = 2;
    assert_eq!(
        EhtNonOfdmaSignal::decode(&nonbinary, &single),
        Err(EhtSigError::NonBinary {
            index: 17,
            value: 2
        })
    );
    assert_eq!(
        EhtNonOfdmaSignal::decode(&original, &context(EhtMuPpduType::DownlinkOfdma)),
        Err(EhtSigError::UnsupportedFormat)
    );
    assert_eq!(
        EhtNonOfdmaSignal::decode(&original, &context(EhtMuPpduType::DownlinkMuMimo)),
        Err(EhtSigError::UserCount(1))
    );
    let trigger = EhtUsigFields {
        format: EhtUsigFormat::TriggerBased(EhtTbUsigFields {
            spatial_reuse: [0, 0],
        }),
        ..single
    };
    assert_eq!(
        EhtNonOfdmaSignal::decode(&original, &trigger),
        Err(EhtSigError::UnsupportedFormat)
    );

    let mut users = original.clone();
    users[17] = 1;
    repair(&mut users, 42);
    assert_eq!(
        EhtNonOfdmaSignal::decode(&users, &single),
        Err(EhtSigError::UserCount(2))
    );
    let mut ltf = original.clone();
    ltf[6..9].copy_from_slice(&[1, 0, 1]);
    repair(&mut ltf, 42);
    assert_eq!(
        EhtNonOfdmaSignal::decode(&ltf, &single),
        Err(EhtSigError::LtfSymbols(5))
    );
    let mut crc = original.clone();
    crc[42] ^= 1;
    assert!(matches!(
        EhtNonOfdmaSignal::decode(&crc, &single),
        Err(EhtSigError::Crc { block: 0, .. })
    ));
    let mut tail = original;
    tail[49] = 1;
    assert_eq!(
        EhtNonOfdmaSignal::decode(&tail, &single),
        Err(EhtSigError::TailBit {
            block: 0,
            index: 49
        })
    );
    assert_eq!(
        EhtSigError::UnsupportedFormat.to_string(),
        "EHT-SIG: UnsupportedFormat"
    );
}

#[test]
fn radio_eht_sig_non_ofdma_mu_mimo_integrity_and_bounds() {
    let fields: Vec<_> = include_str!("../../../../../tests/fixtures/iq/eht-mu-sig-index.tsv")
        .lines()
        .nth(1)
        .unwrap()
        .split('\t')
        .collect();
    let usig = EhtUsigFields::decode(&bits(fields[0])).unwrap();
    let original = bits(fields[1]);
    assert_eq!(original.len(), 84);
    for size in [52, 83, 85] {
        let mut value = original.clone();
        value.resize(size, 0);
        assert_eq!(
            EhtNonOfdmaSignal::decode(&value, &usig),
            Err(EhtSigError::BitCount {
                required: 84,
                available: size
            })
        );
    }
    let mut nonbinary = original.clone();
    nonbinary[52] = 2;
    assert_eq!(
        EhtNonOfdmaSignal::decode(&nonbinary, &usig),
        Err(EhtSigError::NonBinary {
            index: 52,
            value: 2
        })
    );
    let mut crc = original.clone();
    crc[74] ^= 1;
    assert!(matches!(
        EhtNonOfdmaSignal::decode(&crc, &usig),
        Err(EhtSigError::Crc { block: 1, .. })
    ));
    let mut tail = original.clone();
    tail[83] = 1;
    assert_eq!(
        EhtNonOfdmaSignal::decode(&tail, &usig),
        Err(EhtSigError::TailBit {
            block: 1,
            index: 83
        })
    );
    let mut sta_id = original.clone();
    sta_id[20..31].copy_from_slice(&[0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
    repair(&mut sta_id[..52], 42);
    let decoded = EhtNonOfdmaSignal::decode(&sta_id, &usig).unwrap();
    let EhtNonOfdmaUsers::MuMimo(users) = decoded.users else {
        panic!("MU-MIMO U-SIG returned a single-user field")
    };
    assert_eq!(users[0], Err(EhtSigError::MuMimoStaId { user: 0 }));
    let mut mcs = original;
    mcs[31..35].copy_from_slice(&[0, 1, 1, 1]);
    repair(&mut mcs[..52], 42);
    let decoded = EhtNonOfdmaSignal::decode(&mcs, &usig).unwrap();
    let EhtNonOfdmaUsers::MuMimo(users) = decoded.users else {
        panic!("MU-MIMO U-SIG returned a single-user field")
    };
    assert_eq!(users[0], Err(EhtSigError::MuMimoMcs { user: 0, value: 14 }));
}
