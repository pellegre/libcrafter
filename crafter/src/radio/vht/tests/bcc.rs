use super::*;

fn case(row: &str) -> (SignalInfo, VhtSignalB20Fields, Vec<f32>, Vec<u8>, bool) {
    let c: Vec<_> = row.split('\t').collect();
    let mcs: usize = c[0].parse().unwrap();
    let symbols = c[1].parse().unwrap();
    let (nbpsc, ndbps) = [
        (1, 26),
        (2, 52),
        (2, 78),
        (4, 104),
        (4, 156),
        (6, 208),
        (6, 234),
        (6, 260),
        (8, 312),
    ][mcs];
    let bits: Vec<_> = c[3].bytes().map(|b| b - b'0').collect();
    let sig_b = VhtSignalB20Fields::decode(&bits, false).unwrap();
    let expected: Vec<_> = c[4]
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect();
    let coded = c[5]
        .bytes()
        .map(|b| if b == b'1' { 1. } else { -1. })
        .collect();
    (
        SignalInfo {
            rate_bps: 0,
            coded_bits_per_symbol: 52 * nbpsc,
            data_bits_per_symbol: ndbps,
            psdu_bytes: expected.len(),
            data_symbols: symbols,
            data_start: 0,
            end_sample_index: 0,
        },
        sig_b,
        coded,
        expected,
        c[6] == "1",
    )
}

#[test]
fn radio_vht_bcc_independent_data_recovery() {
    let index = include_str!("../../../../tests/fixtures/iq/vht-bcc-data-index.tsv");
    assert_eq!(index.lines().skip(1).count(), 316);
    for row in index.lines().skip(1) {
        let (info, sig_b, coded, expected, valid) = case(row);
        let scales: &[f32] = if info.data_symbols > 17 {
            &[1.]
        } else {
            &[1e-30, 1., 1e30]
        };
        for &scale in scales {
            let scaled: Vec<_> = coded.iter().map(|m| m * scale).collect();
            let recovered = recover_vht_bcc(&scaled, info, sig_b);
            if valid {
                assert_eq!(
                    recovered.unwrap(),
                    expected,
                    "mcs={} symbols={}",
                    row.split('\t').next().unwrap(),
                    info.data_symbols
                );
            } else {
                assert!(
                    recovered.is_err(),
                    "invalid SERVICE or seed accepted: {row}"
                );
            }
        }
        if valid {
            let mut erased = coded;
            erased[5] = 0.;
            assert_eq!(recover_vht_bcc(&erased, info, sig_b).unwrap(), expected);
        }
    }
}

#[test]
fn radio_vht_bcc_rejects_invalid_inputs() {
    let row = include_str!("../../../../tests/fixtures/iq/vht-bcc-data-index.tsv")
        .lines()
        .nth(1)
        .unwrap();
    let (info, sig_b, coded, _, _) = case(row);
    for length in [0, coded.len() - 1, coded.len() + 1] {
        assert!(recover_vht_bcc(&vec![1.; length], info, sig_b).is_err());
    }
    for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let mut metrics = coded.clone();
        metrics[0] = bad;
        assert!(recover_vht_bcc(&metrics, info, sig_b).is_err());
    }
    assert!(recover_vht_bcc(&vec![0.; coded.len()], info, sig_b).is_err());
    for bytes in [0, info.psdu_bytes - 1, info.psdu_bytes + 1, usize::MAX] {
        assert!(recover_vht_bcc(
            &coded,
            SignalInfo {
                psdu_bytes: bytes,
                ..info
            },
            sig_b
        )
        .is_err());
    }
    for symbols in [0, 1, usize::MAX] {
        assert!(recover_vht_bcc(
            &coded,
            SignalInfo {
                data_symbols: symbols,
                ..info
            },
            sig_b
        )
        .is_err());
    }
    for bits in [0, 51, 53, usize::MAX] {
        assert!(recover_vht_bcc(
            &coded,
            SignalInfo {
                coded_bits_per_symbol: bits,
                ..info
            },
            sig_b
        )
        .is_err());
        assert!(recover_vht_bcc(
            &coded,
            SignalInfo {
                data_bits_per_symbol: bits,
                ..info
            },
            sig_b
        )
        .is_err());
    }
    let mut other: Vec<_> = row
        .split('\t')
        .nth(3)
        .unwrap()
        .bytes()
        .map(|b| b - b'0')
        .collect();
    other[0] ^= 1;
    let other = VhtSignalB20Fields::decode(&other, false).unwrap();
    assert_ne!(other.expected_service_crc(), sig_b.expected_service_crc());
    assert!(recover_vht_bcc(&coded, info, other).is_err());
    let ndp: Vec<_> = b"00000111010001000010000000"
        .iter()
        .map(|b| b - b'0')
        .collect();
    assert!(recover_vht_bcc(
        &coded,
        info,
        VhtSignalB20Fields::decode(&ndp, false).unwrap()
    )
    .is_err());
}
