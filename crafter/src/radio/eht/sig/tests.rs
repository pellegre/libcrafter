use super::*;
use crate::radio::{
    EhtMuPpduType, EhtMuUsigFields, EhtSigMcs, EhtTbUsigFields, EhtUsigFields, EhtUsigFormat,
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

fn repair(value: &mut [u8]) {
    let crc = crate::radio::ht::crc(&value[..42]) >> 4;
    for (index, shift) in (0..4).zip((0..4).rev()) {
        value[42 + index] = (crc >> shift) & 1;
    }
}

#[test]
fn radio_eht_sig_non_ofdma_independent_blocks() {
    let rows = include_str!("../../../../tests/fixtures/iq/eht-sig-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 2048);
    for row in rows.lines().skip(1) {
        let fields: Vec<_> = row.split('\t').collect();
        let usig = EhtUsigFields::decode(&bits(fields[0])).unwrap();
        let decoded = EhtNonOfdmaSignal::decode(&bits(fields[1]), &usig).unwrap();
        let ltf_mode = [
            EhtLtfMode::TwoXGi800,
            EhtLtfMode::TwoXGi1600,
            EhtLtfMode::FourXGi800,
            EhtLtfMode::FourXGi3200,
        ][fields[3].parse::<usize>().unwrap()];
        assert_eq!(decoded.spatial_reuse, fields[2].parse().unwrap());
        assert_eq!(decoded.ltf_mode, ltf_mode);
        assert_eq!(decoded.ltf_mode.size(), fields[4].parse().unwrap());
        assert_eq!(
            decoded.ltf_mode.guard_interval_ns(),
            fields[5].parse().unwrap()
        );
        assert_eq!(decoded.ltf_symbols, fields[6].parse().unwrap());
        assert_eq!(decoded.ldpc_extra_symbol, fields[7] == "1");
        assert_eq!(decoded.pre_fec_padding_factor, fields[8].parse().unwrap());
        assert_eq!(decoded.pe_disambiguity, fields[9] == "1");
        assert_eq!(decoded.disregard, fields[10].parse().unwrap());
        assert_eq!(decoded.users, 1);
        assert_eq!(decoded.first_user.sta_id, fields[11].parse().unwrap());
        assert_eq!(decoded.first_user.mcs, fields[12].parse().unwrap());
        assert_eq!(decoded.first_user.reserved, fields[13] == "1");
        assert_eq!(
            decoded.first_user.space_time_streams,
            fields[14].parse().unwrap()
        );
        assert_eq!(decoded.first_user.beamformed, fields[15] == "1");
        assert_eq!(decoded.first_user.ldpc, fields[16] == "1");
    }
}

#[test]
fn radio_eht_sig_non_ofdma_context_and_integrity() {
    let row: Vec<_> = include_str!("../../../../tests/fixtures/iq/eht-sig-index.tsv")
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
    for ppdu_type in [EhtMuPpduType::DownlinkOfdma, EhtMuPpduType::DownlinkMuMimo] {
        assert_eq!(
            EhtNonOfdmaSignal::decode(&original, &context(ppdu_type)),
            Err(EhtSigError::UnsupportedFormat)
        );
    }
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
    repair(&mut users);
    assert_eq!(
        EhtNonOfdmaSignal::decode(&users, &single),
        Err(EhtSigError::UserCount(2))
    );
    let mut ltf = original.clone();
    ltf[6..9].copy_from_slice(&[1, 0, 1]);
    repair(&mut ltf);
    assert_eq!(
        EhtNonOfdmaSignal::decode(&ltf, &single),
        Err(EhtSigError::LtfSymbols(5))
    );
    let mut crc = original.clone();
    crc[42] ^= 1;
    assert!(matches!(
        EhtNonOfdmaSignal::decode(&crc, &single),
        Err(EhtSigError::Crc { .. })
    ));
    let mut tail = original;
    tail[49] = 1;
    assert_eq!(
        EhtNonOfdmaSignal::decode(&tail, &single),
        Err(EhtSigError::TailBit { index: 49 })
    );
    assert_eq!(
        EhtSigError::UnsupportedFormat.to_string(),
        "EHT-SIG: UnsupportedFormat"
    );
}
