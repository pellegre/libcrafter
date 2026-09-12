use super::*;
fn bits(text: &str) -> Vec<u8> {
    text.bytes().map(|b| b - b'0').collect()
}

#[test]
fn radio_vht_sig_b_independent_recovery_and_service() {
    let rows: Vec<_> = include_str!("../../tests/fixtures/iq/vht-signal-b20-index.tsv")
        .lines()
        .skip(1)
        .collect();
    assert_eq!(rows.len(), 225);
    assert_eq!(
        crate::radio::ht::crc(&bits("10011000000000000000011")),
        0x1c
    );
    for row in rows {
        let c: Vec<_> = row.split('\t').collect();
        let input = bits(c[0]);
        let multi = c[1] == "1";
        let f = VhtSignalB20Fields::decode(&input, multi).unwrap();
        let length_units = c[3].parse().unwrap();
        let expected = if c[2] == "1" {
            VhtSignalB20Content::Ndp
        } else if multi {
            VhtSignalB20Content::MultiUser {
                length_units,
                mcs: c[4].parse().unwrap(),
            }
        } else {
            VhtSignalB20Content::SingleUser { length_units }
        };
        assert_eq!(f.content(), expected);
        let metrics: Vec<f32> = bits(c[8])
            .iter()
            .map(|b| if *b == 1 { 1. } else { -1. })
            .collect();
        assert_eq!(
            VhtSignalB20Fields::decode_interleaved(&metrics, multi),
            Ok(f)
        );
        if c[2] == "1" {
            assert_eq!(f.apep_length_bounds(), None);
            assert_eq!(f.expected_service_crc(), None);
            assert_eq!(
                f.verify_service(&[0; 16]),
                Err(VhtSignalB20Error::NoServiceForNdp)
            );
            assert!(matches!(
                VhtSignalB20Fields::decode(&input, true).unwrap().content(),
                VhtSignalB20Content::MultiUser { .. }
            ));
            continue;
        }
        assert_eq!(
            f.apep_length_bounds(),
            Some((c[5].parse().unwrap(), c[6].parse().unwrap()))
        );
        let service = bits(c[7]);
        assert_eq!(f.verify_service(&service), Ok(()));
        assert_eq!(
            f.expected_service_crc(),
            Some(service[8..].iter().fold(0u8, |v, b| (v << 1) | b))
        );
        for i in 0..16 {
            let mut changed = service.clone();
            changed[i] ^= 1;
            assert!(f.verify_service(&changed).is_err(), "SERVICE bit={i}");
        }
        for i in 0..26 {
            let mut changed = input.clone();
            changed[i] ^= 1;
            if let Ok(parsed) = VhtSignalB20Fields::decode(&changed, multi) {
                assert!(parsed.verify_service(&service).is_err(), "SIG-B bit={i}");
            }
        }
    }
}

#[test]
fn radio_vht_sig_b_input_bounds() {
    let row: Vec<_> = include_str!("../../tests/fixtures/iq/vht-signal-b20-index.tsv")
        .lines()
        .nth(1)
        .unwrap()
        .split('\t')
        .collect();
    let input = bits(row[0]);
    let f = VhtSignalB20Fields::decode(&input, false).unwrap();
    let service = bits(row[7]);
    for n in [0, 1, 25, 27, 52] {
        assert!(
            matches!(VhtSignalB20Fields::decode(&vec![0;n], false), Err(VhtSignalB20Error::BitCount { context:"SIG-B", required:26, available }) if available==n)
        );
    }
    for n in [0, 1, 15, 17] {
        assert!(
            matches!(f.verify_service(&vec![0;n]), Err(VhtSignalB20Error::BitCount { context:"SERVICE", required:16, available }) if available==n)
        );
    }
    for i in 0..26 {
        let mut changed = input.clone();
        changed[i] = 2;
        assert!(
            matches!(VhtSignalB20Fields::decode(&changed,false), Err(VhtSignalB20Error::NonBinary { index, .. }) if index==i)
        );
    }
    for i in 0..16 {
        let mut changed = service.clone();
        changed[i] = 2;
        assert!(
            matches!(f.verify_service(&changed), Err(VhtSignalB20Error::NonBinary { index, .. }) if index==i)
        );
    }
    for i in 17..20 {
        let mut changed = input.clone();
        changed[i] = 0;
        assert_eq!(
            VhtSignalB20Fields::decode(&changed, false),
            Err(VhtSignalB20Error::ReservedBit { index: i })
        );
    }
    for i in 20..26 {
        let mut changed = input.clone();
        changed[i] = 1;
        assert_eq!(
            VhtSignalB20Fields::decode(&changed, false),
            Err(VhtSignalB20Error::TailBit { index: i })
        );
    }
    for n in [0, 1, 51, 53] {
        assert_eq!(
            VhtSignalB20Fields::decode_interleaved(&vec![0.; n], false),
            Err(VhtSignalB20Error::MetricCount {
                required: 52,
                available: n
            })
        );
    }
    assert_eq!(
        VhtSignalB20Fields::decode_interleaved(&[0.; 52], false),
        Err(VhtSignalB20Error::UnusableMetrics)
    );
    let metrics: Vec<f32> = bits(row[8])
        .iter()
        .map(|b| if *b == 1 { 1. } else { -1. })
        .collect();
    for i in 0..52 {
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut changed = metrics.clone();
            changed[i] = bad;
            assert_eq!(
                VhtSignalB20Fields::decode_interleaved(&changed, false),
                Err(VhtSignalB20Error::NonFiniteMetric { index: i })
            );
        }
    }
    for scale in [f32::MIN_POSITIVE, 1e-20, 1., 1e20, f32::MAX] {
        let scaled: Vec<_> = metrics.iter().map(|v| v * scale).collect();
        assert_eq!(
            VhtSignalB20Fields::decode_interleaved(&scaled, false),
            Ok(f)
        );
    }
}
