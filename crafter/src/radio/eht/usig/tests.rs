use super::*;

fn set_field(bits: &mut [u8], start: usize, count: usize, value: u8) {
    for index in 0..count {
        bits[start + index] = (value >> index) & 1;
    }
}

// Independent bit-at-a-time rendition of the published x^8+x^2+x+1 CRC.
fn crc(bits: &[u8]) -> [u8; 4] {
    let mut state = [1u8; 8];
    for &bit in bits {
        let feedback = state[7] ^ bit;
        for index in (1..8).rev() {
            state[index] = state[index - 1];
        }
        state[0] = 0;
        state[1] ^= feedback;
        state[2] ^= feedback;
        state[0] ^= feedback;
    }
    std::array::from_fn(|index| state[7 - index] ^ 1)
}

fn repair_crc(bits: &mut [u8; 52]) {
    let value = crc(&bits[..42]);
    bits[42..46].copy_from_slice(&value);
}

fn mu_bits(uplink: bool, ppdu_type: u8, mcs: u8, symbols: u8) -> [u8; 52] {
    let mut bits = [0u8; 52];
    set_field(&mut bits, 3, 3, 0);
    bits[6] = u8::from(uplink);
    set_field(&mut bits, 7, 6, 37);
    set_field(&mut bits, 13, 7, 91);
    set_field(&mut bits, 20, 5, 0b10101);
    bits[25] = 1;
    set_field(&mut bits, 26, 2, ppdu_type);
    bits[28] = 1;
    set_field(&mut bits, 29, 5, 0b0_1111);
    bits[34] = 1;
    set_field(&mut bits, 35, 2, mcs);
    set_field(&mut bits, 37, 5, symbols - 1);
    repair_crc(&mut bits);
    bits
}

fn tb_bits(spatial_reuse: [u8; 2]) -> [u8; 52] {
    let mut bits = [0u8; 52];
    bits[6] = 1;
    set_field(&mut bits, 7, 6, 11);
    set_field(&mut bits, 13, 7, 127);
    set_field(&mut bits, 20, 6, 0b10_1010);
    bits[28] = 1;
    set_field(&mut bits, 29, 4, spatial_reuse[0]);
    set_field(&mut bits, 33, 4, spatial_reuse[1]);
    set_field(&mut bits, 37, 5, 0b10101);
    repair_crc(&mut bits);
    bits
}

fn interleaved_metrics(bits: &[u8; 52], scale: f32) -> [f32; 104] {
    let mut register = 0u8;
    let mut coded = [0.; 104];
    for (index, &bit) in bits.iter().enumerate() {
        register = (register << 1 | bit) & 0x7f;
        for (output, polynomial) in [0o155, 0o117].into_iter().enumerate() {
            let encoded = (register & polynomial).count_ones() & 1;
            coded[2 * index + output] = if encoded == 0 { -scale } else { scale };
        }
    }
    let mut metrics = [0.; 104];
    for symbol in 0..2 {
        for bit in 0..52 {
            metrics[symbol * 52 + 4 * (bit % 13) + bit / 13] = coded[symbol * 52 + bit];
        }
    }
    metrics
}

#[test]
fn radio_eht_usig_independent_vectors() {
    let rows = include_str!("../../../../tests/fixtures/iq/eht-usig-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 2112);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let bits: Vec<_> = columns[0].bytes().map(|value| value - b'0').collect();
        let values: Vec<u8> = columns[2..]
            .iter()
            .map(|value| value.parse().unwrap())
            .collect();
        let format = if values[4] == 0 {
            let ppdu_type = match values[5] {
                0 => EhtMuPpduType::DownlinkOfdma,
                1 => EhtMuPpduType::SingleUser,
                2 => EhtMuPpduType::DownlinkMuMimo,
                value => panic!("invalid oracle PPDU type {value}"),
            };
            let eht_sig_mcs = match values[7] {
                0 => EhtSigMcs::Mcs0,
                1 => EhtSigMcs::Mcs1,
                2 => EhtSigMcs::Mcs3,
                3 => EhtSigMcs::Mcs0Dcm,
                value => panic!("invalid oracle EHT-SIG MCS {value}"),
            };
            EhtUsigFormat::Mu(EhtMuUsigFields {
                ppdu_type,
                punctured_channel_information: values[6],
                eht_sig_mcs,
                eht_sig_symbols: values[8],
            })
        } else {
            EhtUsigFormat::TriggerBased(EhtTbUsigFields {
                spatial_reuse: [values[9], values[10]],
            })
        };
        let expected = EhtUsigFields {
            bandwidth_code: values[0],
            uplink: values[1] != 0,
            bss_color: values[2],
            txop: values[3],
            format,
        };
        assert_eq!(EhtUsigFields::decode(&bits), Ok(expected));
        for scale in [f32::MIN_POSITIVE, 1., f32::MAX] {
            let metrics: Vec<_> = columns[1]
                .bytes()
                .map(|value| if value == b'1' { scale } else { -scale })
                .collect();
            assert_eq!(EhtUsigFields::decode_interleaved(&metrics), Ok(expected));
        }
    }
}

#[test]
fn radio_eht_usig_all_20mhz_mu_modes() {
    for (uplink, raw_type, expected_type) in [
        (false, 0, EhtMuPpduType::DownlinkOfdma),
        (false, 1, EhtMuPpduType::SingleUser),
        (true, 1, EhtMuPpduType::SingleUser),
        (false, 2, EhtMuPpduType::DownlinkMuMimo),
    ] {
        for raw_mcs in 0..4 {
            for symbols in 1..=32 {
                let fields =
                    EhtUsigFields::decode(&mu_bits(uplink, raw_type, raw_mcs, symbols)).unwrap();
                assert_eq!(fields.bandwidth_code, 0);
                assert_eq!(fields.uplink, uplink);
                assert_eq!(fields.bss_color, 37);
                assert_eq!(fields.txop, 91);
                let EhtUsigFormat::Mu(mu) = fields.format else {
                    panic!("MU vector classified as TB")
                };
                assert_eq!(mu.ppdu_type, expected_type);
                assert_eq!(mu.eht_sig_symbols, symbols);
                assert_eq!(
                    mu.eht_sig_mcs,
                    [
                        EhtSigMcs::Mcs0,
                        EhtSigMcs::Mcs1,
                        EhtSigMcs::Mcs3,
                        EhtSigMcs::Mcs0Dcm,
                    ][usize::from(raw_mcs)]
                );
            }
        }
    }
}

#[test]
fn radio_eht_usig_trigger_based_fields_and_disregard_bits() {
    for first in 0..16 {
        for second in 0..16 {
            let fields = EhtUsigFields::decode(&tb_bits([first, second])).unwrap();
            assert_eq!(fields.bandwidth_code, 0);
            assert!(fields.uplink);
            assert_eq!(fields.bss_color, 11);
            assert_eq!(fields.txop, 127);
            assert_eq!(
                fields.format,
                EhtUsigFormat::TriggerBased(EhtTbUsigFields {
                    spatial_reuse: [first, second]
                })
            );
        }
    }
}

#[test]
fn radio_eht_usig_rejects_invalid_states() {
    let valid = mu_bits(false, 1, 0, 1);
    for version in 1..8 {
        let mut bits = valid;
        set_field(&mut bits, 0, 3, version);
        repair_crc(&mut bits);
        assert_eq!(
            EhtUsigFields::decode(&bits),
            Err(EhtUsigError::PhyVersion(version))
        );
    }
    for bandwidth in 6..8 {
        let mut bits = valid;
        set_field(&mut bits, 3, 3, bandwidth);
        repair_crc(&mut bits);
        assert_eq!(
            EhtUsigFields::decode(&bits),
            Err(EhtUsigError::Bandwidth(bandwidth))
        );
    }
    for index in [25, 28, 34] {
        let mut bits = valid;
        bits[index] = 0;
        repair_crc(&mut bits);
        assert_eq!(
            EhtUsigFields::decode(&bits),
            Err(EhtUsigError::ValidateBit { index })
        );
    }
    for &(uplink, raw_type) in &[(false, 3), (true, 2), (true, 3)] {
        let mut bits = valid;
        bits[6] = u8::from(uplink);
        set_field(&mut bits, 26, 2, raw_type);
        repair_crc(&mut bits);
        assert_eq!(
            EhtUsigFields::decode(&bits),
            Err(EhtUsigError::PpduType {
                uplink,
                value: raw_type
            })
        );
    }
    let mut punctured = valid;
    punctured[29] = 0;
    repair_crc(&mut punctured);
    assert_eq!(
        EhtUsigFields::decode(&punctured),
        Err(EhtUsigError::PuncturedChannelInformation(14))
    );
}

#[test]
fn radio_eht_usig_integrity_and_metric_bounds() {
    let valid = mu_bits(false, 1, 2, 7);
    for index in 0..52 {
        let mut changed = valid;
        changed[index] ^= 1;
        let received: [u8; 4] = changed[42..46].try_into().unwrap();
        if index >= 42 || crc(&changed[..42]) != received {
            assert!(EhtUsigFields::decode(&changed).is_err(), "bit {index}");
        }
    }
    for length in [0, 51] {
        assert!(matches!(
            EhtUsigFields::decode(&valid[..length]),
            Err(EhtUsigError::BitCount { .. })
        ));
    }
    let mut oversized = valid.to_vec();
    oversized.push(0);
    assert!(matches!(
        EhtUsigFields::decode(&oversized),
        Err(EhtUsigError::BitCount { .. })
    ));
    let mut nonbinary = valid;
    nonbinary[17] = 2;
    assert_eq!(
        EhtUsigFields::decode(&nonbinary),
        Err(EhtUsigError::NonBinary {
            index: 17,
            value: 2
        })
    );
    for length in [0, 103, 105] {
        assert!(matches!(
            EhtUsigFields::decode_interleaved(&vec![1.; length]),
            Err(EhtUsigError::MetricCount { .. })
        ));
    }
    assert_eq!(
        EhtUsigFields::decode_interleaved(&[0.; 104]),
        Err(EhtUsigError::UnusableMetrics)
    );
    for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let mut metrics = [1.; 104];
        metrics[73] = value;
        assert_eq!(
            EhtUsigFields::decode_interleaved(&metrics),
            Err(EhtUsigError::NonFiniteMetric { index: 73 })
        );
    }
}

#[test]
fn radio_eht_usig_published_crc_and_independent_soft_encoding() {
    let published: Vec<_> = "1101110000000010000001100000000000100110100111000000"
        .bytes()
        .map(|byte| byte - b'0')
        .collect();
    assert_eq!(published.len(), 52);
    assert_eq!(validate_integrity(&published), Ok(()));

    for bits in [mu_bits(false, 0, 3, 32), tb_bits([4, 13])] {
        let expected = EhtUsigFields::decode(&bits).unwrap();
        for scale in [f32::MIN_POSITIVE, 1., f32::MAX] {
            assert_eq!(
                EhtUsigFields::decode_interleaved(&interleaved_metrics(&bits, scale)),
                Ok(expected)
            );
        }
    }
}
