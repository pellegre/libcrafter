use super::*;
use crate::radio::{ofdm_tx as ofdm, RadioError};

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn assert_iq(case: &str, actual: &[i8]) {
    let expected = std::fs::read(format!(
        "{}/tests/fixtures/iq/{case}.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(actual.len(), expected.len(), "{case}");
    for (index, (actual, expected)) in actual.iter().zip(&expected).enumerate() {
        let delta = (*actual as i16 - *expected as i8 as i16).abs();
        assert!(
            delta <= 1,
            "{case} differs at byte {index}: actual={actual}, expected={}",
            *expected as i8
        );
    }
}

#[test]
fn radio_ht_tx_rates_cover_long_and_short_guard_intervals() {
    assert_eq!(HtMcs::Mcs0.rate_bps(HtGuardInterval::Long), 6_500_000);
    assert_eq!(HtMcs::Mcs7.rate_bps(HtGuardInterval::Long), 65_000_000);
    assert_eq!(HtMcs::Mcs7.rate_bps(HtGuardInterval::Short), 72_222_222);
}

#[test]
fn radio_ht_tx_matches_independent_bcc_waveforms() {
    let index = include_str!("../../../../tests/fixtures/iq/ht-bcc-index.tsv");
    let mut cases = 0;
    for row in index.lines().skip(1).filter(|row| row.contains("-clean")) {
        let columns: Vec<_> = row.split('\t').collect();
        let psdu = bytes(columns[4]);
        let mut config =
            HtTxConfig::new(HtMcs::try_from(columns[1].parse::<u8>().unwrap()).unwrap());
        config.guard_interval = match columns[2] {
            "8" => HtGuardInterval::Short,
            "16" => HtGuardInterval::Long,
            _ => panic!(),
        };
        config.leading_samples = 37;
        config.trailing_samples = 64;
        let tx = HtTransmission::encode(
            &psdu[..psdu.len() - 4],
            Some(psdu[psdu.len() - 4..].try_into().unwrap()),
            &config,
        )
        .unwrap();
        assert_eq!(
            tx.data_symbols,
            columns[3].parse::<usize>().unwrap(),
            "{}",
            columns[0]
        );
        assert_iq(columns[0], &tx.cs8);
        cases += 1;
    }
    assert_eq!(cases, 32);
}

#[test]
fn radio_ht_tx_matches_independent_greenfield_waveforms() {
    let index = include_str!("../../../../tests/fixtures/iq/ht-greenfield-index.tsv");
    let mut cases = 0;
    for row in index
        .lines()
        .skip(1)
        .filter(|row| row.contains("-bcc-") && row.contains("-clean"))
    {
        let columns: Vec<_> = row.split('\t').collect();
        let psdu = bytes(columns[4]);
        let mut config =
            HtTxConfig::new(HtMcs::try_from(columns[1].parse::<u8>().unwrap()).unwrap())
                .with_format(HtFormat::Greenfield);
        config.leading_samples = 37;
        config.trailing_samples = 64;
        let tx = HtTransmission::encode(
            &psdu[..psdu.len() - 4],
            Some(psdu[psdu.len() - 4..].try_into().unwrap()),
            &config,
        )
        .unwrap();
        assert_eq!(tx.data_symbols, columns[3].parse::<usize>().unwrap());
        assert_iq(columns[0], &tx.cs8);
        cases += 1;
    }
    assert_eq!(cases, 16);
}

#[test]
fn radio_ht_tx_matches_independent_ldpc_waveforms() {
    let index = include_str!("../../../../tests/fixtures/iq/ht-ldpc-index.tsv");
    let mut cases = 0;
    for row in index.lines().skip(1).filter(|row| row.contains("-clean")) {
        let columns: Vec<_> = row.split('\t').collect();
        let psdu = bytes(columns[4]);
        let mut config =
            HtTxConfig::new(HtMcs::try_from(columns[1].parse::<u8>().unwrap()).unwrap())
                .with_coding(HtCoding::Ldpc);
        config.guard_interval = match columns[2] {
            "8" => HtGuardInterval::Short,
            "16" => HtGuardInterval::Long,
            _ => panic!(),
        };
        config.leading_samples = 37;
        config.trailing_samples = 64;
        let tx = HtTransmission::encode(
            &psdu[..psdu.len() - 4],
            Some(psdu[psdu.len() - 4..].try_into().unwrap()),
            &config,
        )
        .unwrap();
        assert_eq!(tx.data_symbols, columns[3].parse::<usize>().unwrap());
        assert_iq(columns[0], &tx.cs8);
        cases += 1;
    }
    assert_eq!(cases, 32);
}

#[test]
fn radio_ht_tx_matches_independent_greenfield_ldpc_waveforms() {
    let index = include_str!("../../../../tests/fixtures/iq/ht-greenfield-index.tsv");
    let mut cases = 0;
    for row in index
        .lines()
        .skip(1)
        .filter(|row| row.contains("-ldpc-") && row.contains("-clean"))
    {
        let columns: Vec<_> = row.split('\t').collect();
        let psdu = bytes(columns[4]);
        let mut config =
            HtTxConfig::new(HtMcs::try_from(columns[1].parse::<u8>().unwrap()).unwrap())
                .with_format(HtFormat::Greenfield)
                .with_coding(HtCoding::Ldpc);
        config.leading_samples = 37;
        config.trailing_samples = 64;
        let tx = HtTransmission::encode(
            &psdu[..psdu.len() - 4],
            Some(psdu[psdu.len() - 4..].try_into().unwrap()),
            &config,
        )
        .unwrap();
        assert_eq!(tx.data_symbols, columns[3].parse::<usize>().unwrap());
        assert_iq(columns[0], &tx.cs8);
        cases += 1;
    }
    assert_eq!(cases, 16);
}

#[test]
fn radio_ht_tx_bounds_overrides_and_formats() {
    let mac = b"wifi four";
    let config = HtTxConfig::new(HtMcs::Mcs7);
    let first = HtTransmission::encode(mac, None, &config).unwrap();
    assert_eq!(first, HtTransmission::encode(mac, None, &config).unwrap());
    assert_eq!(&first.psdu_bytes[..mac.len()], mac);
    assert_eq!(
        &first.psdu_bytes[mac.len()..],
        &ofdm::crc32(mac).to_le_bytes()
    );
    assert_eq!(first.sample_rate_hz, 20_000_000);

    let greenfield =
        HtTransmission::encode(mac, None, &config.clone().with_format(HtFormat::Greenfield))
            .unwrap();
    assert_eq!(greenfield.format, HtFormat::Greenfield);
    assert!(greenfield.legacy_signal.is_none());

    let mut explicit = config.clone();
    let mut malformed = first.ht_signal.derived;
    malformed[34] ^= 1;
    explicit.ht_signal_override = Some(malformed);
    explicit.legacy_signal_override = first.legacy_signal.map(|signal| signal.derived);
    let tx = HtTransmission::encode(mac, Some([0; 4]), &explicit).unwrap();
    assert_eq!(tx.ht_signal.transmitted, malformed);
    assert!(tx.ht_signal.explicit && tx.explicit_fcs);

    let mut bounded = config.clone();
    bounded.max_samples = first.sample_count() - 1;
    assert!(matches!(
        HtTransmission::encode(mac, None, &bounded),
        Err(RadioError::Limit {
            context: "HT waveform samples",
            ..
        })
    ));
    bounded.max_samples = usize::MAX;
    bounded.max_psdu_bytes = 4;
    assert!(matches!(
        HtTransmission::encode(mac, None, &bounded),
        Err(RadioError::Limit {
            context: "HT PSDU bytes",
            ..
        })
    ));
    let ldpc =
        HtTransmission::encode(mac, None, &config.clone().with_coding(HtCoding::Ldpc)).unwrap();
    assert_eq!(ldpc.coding, HtCoding::Ldpc);
    assert!(HtTransmission::encode(
        mac,
        None,
        &config
            .clone()
            .with_format(HtFormat::Greenfield)
            .with_guard_interval(HtGuardInterval::Short)
    )
    .is_err());
}
