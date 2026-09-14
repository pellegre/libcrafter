//! HE BCC payload kernel, IEEE802.11ax-2021 27.3.12.1-5.
use super::{capacity::Capacity, SuSignal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    Coding,
    Capacity,
    Length,
    Limit,
    Metrics,
    Allocation,
    Service,
}

/// Metrics are deinterleaved, stream-recombined symbol blocks, positive for1.
/// PSDU output is not MAC/FCS qualified. Caller supplies a payload allocation cap.
pub(in crate::radio) fn recover(
    a: &SuSignal,
    symbols: usize,
    metrics: &[f32],
    max_psdu: usize,
) -> Result<Vec<u8>, Error> {
    recover_for_format(a, symbols, metrics, max_psdu, false)
}

/// ER format must come from validated signaling. This does not demodulate IQ.
pub(in crate::radio) fn recover_for_format(
    a: &SuSignal,
    symbols: usize,
    metrics: &[f32],
    max_psdu: usize,
    er: bool,
) -> Result<Vec<u8>, Error> {
    if a.ldpc {
        return Err(Error::Coding);
    }
    let c = Capacity::for_format(a, symbols, er).map_err(|_| Error::Capacity)?;
    recover_capacity(c, symbols, usize::from(a.stbc) + 1, metrics, max_psdu)
}

/// Per-user MU metrics, already deinterleaved and stream-recombined. This
/// checks SERVICE, not MAC/FCS integrity, and does not admit spatial layouts.
pub(in crate::radio) fn recover_mu(
    signal: &crate::radio::he::mu::MuSignal,
    user: &crate::radio::he::mu::sig_b::HeSigBUserFields,
    ru_tones: u16,
    symbols: usize,
    metrics: &[f32],
    max_psdu: usize,
) -> Result<Vec<u8>, Error> {
    let c = Capacity::for_mu(signal, user, ru_tones, symbols).map_err(|_| Error::Capacity)?;
    if c.tail_bits != 6 {
        return Err(Error::Coding);
    }
    recover_capacity(c, symbols, usize::from(signal.stbc) + 1, metrics, max_psdu)
}

/// Trigger-configured per-user metrics, already deinterleaved/recombined.
/// This returns PSDU estimates with checked SERVICE, not FCS-qualified frames.
pub(in crate::radio) fn recover_tb(
    common: &crate::Dot11TriggerCommonFields,
    user: &crate::Dot11TriggerUserFields,
    symbols: usize,
    metrics: &[f32],
    max_psdu: usize,
) -> Result<Vec<u8>, Error> {
    let c = Capacity::for_tb(common, user, symbols).map_err(|_| Error::Capacity)?;
    if c.tail_bits != 6 {
        return Err(Error::Coding);
    }
    recover_capacity(c, symbols, usize::from(common.stbc) + 1, metrics, max_psdu)
}

fn recover_capacity(
    c: Capacity,
    symbols: usize,
    group: usize,
    metrics: &[f32],
    max_psdu: usize,
) -> Result<Vec<u8>, Error> {
    if c.psdu_bytes > max_psdu {
        return Err(Error::Limit);
    }
    let decoder = crate::radio::bcc::Decoder::new(crate::radio::bcc::Parameters {
        symbols,
        symbol_group: group,
        coded_per_symbol: c.coded_per_symbol,
        coded_last: c.coded_last,
        data_per_symbol: c.data_per_symbol,
        data_bits: c.data_bits,
        rate_num: c.rate_num,
        rate_den: c.rate_den,
        dcm_filler: c.bcc_dcm_filler,
    })
    .map_err(map_error)?;
    let bits = decoder.recover(metrics).map_err(map_error)?;
    crate::radio::data::descramble_psdu(bits, c.psdu_bytes).map_err(|_| Error::Service)
}

fn map_error(error: crate::radio::bcc::Error) -> Error {
    match error {
        crate::radio::bcc::Error::Parameters => Error::Capacity,
        crate::radio::bcc::Error::Coding => Error::Coding,
        crate::radio::bcc::Error::Length => Error::Length,
        crate::radio::bcc::Error::Metrics => Error::Metrics,
        crate::radio::bcc::Error::Allocation => Error::Allocation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn radio_he_mu_tb_bcc_independent_payloads() {
        use crate::radio::{HeSigBUserEncoding, HeSigBUserFields};
        let bits: Vec<_> = include_str!("../../../tests/fixtures/iq/he-mu-signal-a-index.tsv")
            .lines()
            .nth(1)
            .unwrap()
            .split('\t')
            .next()
            .unwrap()
            .bytes()
            .map(|b| b - b'0')
            .collect();
        let mut signal = crate::radio::he::mu::MuSignal::decode(&bits).unwrap();
        signal.bandwidth = 0;
        signal.sig_b_mcs = 1;
        signal.sig_b_dcm = true;
        signal.ldpc_extra_segment = true; // BCC ignores this global LDPC flag.
        for (ru, index, total) in [
            (
                26,
                include_str!("../../../tests/fixtures/iq/he-mu26-bcc-index.tsv"),
                415,
            ),
            (
                52,
                include_str!("../../../tests/fixtures/iq/he-mu52-bcc-index.tsv"),
                429,
            ),
            (
                106,
                include_str!("../../../tests/fixtures/iq/he-mu106-bcc-index.tsv"),
                435,
            ),
            (
                242,
                include_str!("../../../tests/fixtures/iq/he-mu242-bcc-index.tsv"),
                435,
            ),
        ] {
            assert_eq!(index.lines().skip(1).count(), total);
            for (n, input) in index.lines().skip(1).enumerate() {
                let (a, symbols, expected, metrics, valid) = row(input);
                signal.stbc = a.stbc;
                signal.pre_fec_padding = a.pre_fec_padding;
                let user = HeSigBUserFields {
                    sta_id: 1,
                    encoding: HeSigBUserEncoding::NonMu {
                        space_time_streams: a.space_time_streams,
                        beamformed: false,
                        mcs: a.mcs,
                        dcm: a.dcm,
                        ldpc: false,
                    },
                };
                let result = recover_mu(&signal, &user, ru, symbols, &metrics, 65535);
                let common = crate::Dot11TriggerCommonFields {
                    stbc: a.stbc,
                    pre_fec_padding_raw: a.pre_fec_padding % 4,
                    ldpc_extra_segment: true, // BCC ignores the common LDPC flag.
                    ..Default::default()
                };
                let trigger_user = crate::Dot11TriggerUserFields {
                    aid12: 1,
                    ru_allocation: match ru {
                        26 => 0,
                        52 => 74,
                        106 => 106,
                        242 => 122,
                        _ => unreachable!(),
                    },
                    mcs: a.mcs,
                    dcm: a.dcm,
                    spatial_allocation: ((a.space_time_streams / (1 + u8::from(a.stbc))) - 1) << 3,
                    ..Default::default()
                };
                assert_eq!(
                    recover_tb(&common, &trigger_user, symbols, &metrics, 65535),
                    result,
                    "TB ru{ru} case{n}"
                );
                assert_eq!(
                    recover_tb(
                        &common,
                        &trigger_user,
                        symbols,
                        &metrics[..metrics.len() - 1],
                        65535
                    ),
                    Err(Error::Length)
                );
                if !expected.is_empty() {
                    assert_eq!(
                        recover_tb(
                            &common,
                            &trigger_user,
                            symbols,
                            &metrics,
                            expected.len() - 1
                        ),
                        Err(Error::Limit)
                    );
                }
                if n % 100 == 0 {
                    let mut bad = metrics.clone();
                    bad[0] = f32::NAN;
                    assert_eq!(
                        recover_tb(&common, &trigger_user, symbols, &bad, 65535),
                        Err(Error::Metrics)
                    );
                    assert_eq!(
                        recover_tb(
                            &common,
                            &trigger_user,
                            symbols,
                            &vec![0.; metrics.len()],
                            65535
                        ),
                        Err(Error::Metrics)
                    );
                    let mut ldpc = trigger_user;
                    ldpc.ldpc = true;
                    assert!(recover_tb(&common, &ldpc, symbols, &metrics, 65535).is_err());
                }
                if valid {
                    assert_eq!(result, Ok(expected.clone()), "ru{ru} case{n}");
                } else {
                    assert_eq!(result, Err(Error::Service), "ru{ru} case{n}");
                }
                assert_eq!(
                    recover_mu(
                        &signal,
                        &user,
                        ru,
                        symbols,
                        &metrics[..metrics.len() - 1],
                        65535
                    ),
                    Err(Error::Length)
                );
                if !expected.is_empty() {
                    assert_eq!(
                        recover_mu(&signal, &user, ru, symbols, &metrics, expected.len() - 1),
                        Err(Error::Limit)
                    );
                }
                if n % 100 == 0 {
                    let scaled: Vec<_> = metrics.iter().map(|v| v * 1e-20).collect();
                    assert_eq!(
                        recover_mu(&signal, &user, ru, symbols, &scaled, 65535),
                        result
                    );
                    let mut bad = metrics.clone();
                    bad[0] = f32::NAN;
                    assert_eq!(
                        recover_mu(&signal, &user, ru, symbols, &bad, 65535),
                        Err(Error::Metrics)
                    );
                    assert_eq!(
                        recover_mu(&signal, &user, ru, symbols, &vec![0.; metrics.len()], 65535),
                        Err(Error::Metrics)
                    );
                }
            }
        }
    }
    #[test]
    fn radio_he_mu_bcc_rejects_other_coding() {
        use crate::radio::{HeSigBUserEncoding, HeSigBUserFields};
        let bits: Vec<_> = include_str!("../../../tests/fixtures/iq/he-mu-signal-a-index.tsv")
            .lines()
            .nth(1)
            .unwrap()
            .split('\t')
            .next()
            .unwrap()
            .bytes()
            .map(|b| b - b'0')
            .collect();
        let mut signal = crate::radio::he::mu::MuSignal::decode(&bits).unwrap();
        signal.bandwidth = 0;
        signal.stbc = false;
        signal.pre_fec_padding = 4;
        signal.ldpc_extra_segment = false;
        let mut user = HeSigBUserFields {
            sta_id: 1,
            encoding: HeSigBUserEncoding::NonMu {
                space_time_streams: 1,
                beamformed: false,
                mcs: 0,
                dcm: false,
                ldpc: true,
            },
        };
        assert_eq!(
            recover_mu(&signal, &user, 26, 10, &[], 65535),
            Err(Error::Coding)
        );
        user.encoding = HeSigBUserEncoding::Unused { raw_parameters: 0 };
        assert_eq!(
            recover_mu(&signal, &user, 26, 10, &[], 65535),
            Err(Error::Capacity)
        );
    }

    fn row(input: &str) -> (SuSignal, usize, Vec<u8>, Vec<f32>, bool) {
        let c: Vec<_> = input.split('\t').collect();
        let mut a = SuSignal::decode(
            &b"1000000000000010000000000000000000100000100111000000"
                .iter()
                .map(|b| b - b'0')
                .collect::<Vec<_>>(),
        )
        .unwrap();
        a.mcs = c[0].parse().unwrap();
        a.stbc = c[2] == "1";
        a.dcm = c[3] == "1";
        a.space_time_streams = c[1].parse::<u8>().unwrap() * if a.stbc { 2 } else { 1 };
        a.pre_fec_padding = c[5].parse().unwrap();
        let psdu = (0..c[7].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&c[7][i..i + 2], 16).unwrap())
            .collect();
        let metrics = c[8]
            .bytes()
            .map(|b| if b == b'1' { 1. } else { -1. })
            .collect();
        (a, c[4].parse().unwrap(), psdu, metrics, c[9] == "1")
    }

    #[test]
    fn radio_he_bcc_independent_payloads_and_service() {
        payloads(
            include_str!("../../../tests/fixtures/iq/he-bcc-index.tsv"),
            None,
            435,
        );
    }

    #[test]
    fn radio_he_er_bcc_independent_payloads_and_service() {
        payloads(
            include_str!("../../../tests/fixtures/iq/he-er106-bcc-index.tsv"),
            Some(1),
            165,
        );
        payloads(
            include_str!("../../../tests/fixtures/iq/he-er242-bcc-index.tsv"),
            Some(0),
            225,
        );
    }

    fn payloads(index: &str, er_bandwidth: Option<u8>, total: usize) {
        let mut count = 0;
        for input in index.lines().skip(1) {
            let (mut a, symbols, expected, metrics, valid) = row(input);
            a.bandwidth = er_bandwidth.unwrap_or(0);
            let result = recover_for_format(&a, symbols, &metrics, 65535, er_bandwidth.is_some());
            if er_bandwidth == Some(1) {
                assert_eq!(recover(&a, symbols, &metrics, 65535), Err(Error::Capacity));
            } else {
                assert_eq!(recover(&a, symbols, &metrics, 65535), result);
            }
            if valid {
                assert_eq!(result.unwrap(), expected, "case{count}");
            } else {
                assert_eq!(result, Err(Error::Service), "case{count}");
            }
            count += 1;
        }
        assert_eq!(count, total);
    }

    #[test]
    fn radio_he_bcc_soft_metrics_padding_and_bounds() {
        soft_bounds(
            include_str!("../../../tests/fixtures/iq/he-bcc-index.tsv"),
            None,
        );
    }

    #[test]
    fn radio_he_er_bcc_soft_metrics_padding_and_bounds() {
        soft_bounds(
            include_str!("../../../tests/fixtures/iq/he-er106-bcc-index.tsv"),
            Some(1),
        );
        soft_bounds(
            include_str!("../../../tests/fixtures/iq/he-er242-bcc-index.tsv"),
            Some(0),
        );
    }

    fn soft_bounds(cases: &str, er_bandwidth: Option<u8>) {
        for input in cases
            .lines()
            .skip(1)
            .filter(|l| l.starts_with("0\t1\t0\t"))
            .take(32)
        {
            let (mut a, symbols, expected, metrics, _) = row(input);
            a.bandwidth = er_bandwidth.unwrap_or(0);
            let er = er_bandwidth.is_some();
            let c = Capacity::for_format(&a, symbols, er).unwrap();
            for scale in [1e-20, 1., 1e20] {
                let mut soft: Vec<_> = metrics
                    .iter()
                    .enumerate()
                    .map(|(i, v)| v * scale * (1. + (i % 7) as f32 / 8.))
                    .collect();
                soft[31] *= -0.01; // One low-confidence error, corrected by the code.
                                   // Arbitrary unused positions must not change normalization/bytes.
                for (s, block) in soft.chunks_exact_mut(c.coded_per_symbol).enumerate() {
                    if s == symbols - 1 {
                        for value in &mut block[c.coded_last..] {
                            *value = f32::MAX;
                        }
                    }
                    if c.bcc_dcm_filler && (s < symbols - 1 || c.coded_last == c.coded_per_symbol) {
                        block[2 * c.data_per_symbol] = -f32::MAX;
                    }
                }
                assert_eq!(
                    recover_for_format(&a, symbols, &soft, expected.len(), er).unwrap(),
                    expected
                );
            }
            assert_eq!(
                recover_for_format(&a, symbols, &metrics, expected.len() - 1, er),
                Err(Error::Limit)
            );
            assert_eq!(
                recover_for_format(&a, symbols, &metrics[..metrics.len() - 1], 65535, er),
                Err(Error::Length)
            );
            for value in [0., f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
                let bad = vec![value; metrics.len()];
                assert_eq!(
                    recover_for_format(&a, symbols, &bad, 65535, er),
                    Err(Error::Metrics)
                );
            }
            let mut ldpc = a;
            ldpc.ldpc = true;
            assert_eq!(
                recover_for_format(&ldpc, symbols, &metrics, 65535, er),
                Err(Error::Coding)
            );
            assert_eq!(
                recover_for_format(&a, usize::MAX, &metrics, usize::MAX, er),
                Err(Error::Capacity)
            );
        }
    }
}
