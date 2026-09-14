//! Per-user HE20 MU/TB LDPC payloads; ax-2021 27.3.12.4/5. No IQ admission.
use super::{sig_b::HeSigBUserFields, MuSignal};
use crate::radio::{
    he::capacity::Capacity,
    ldpc::rate::{self, Layout, Recovery},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    Capacity,
    Coding,
    Length,
    Limit,
    Metrics,
    Allocation,
    Service,
    Fec(rate::Error),
}

#[derive(Debug)]
pub(in crate::radio) struct Recovered {
    pub psdu: Vec<u8>,
    pub iterations: usize,
    pub failed_codewords: usize,
    pub first_failure: Option<rate::Error>,
}

/// Full-symbol metrics, already tone-demapped and stream-recombined, positive
/// for one. Removes post-FEC padding from every last STBC-group symbol. Neither
/// strict convergence nor partial estimates establish MAC integrity: callers
/// must verify every emitted MPDU's FCS. SERVICE is mandatory in both modes.
pub(in crate::radio) fn recover(
    signal: &MuSignal,
    user: &HeSigBUserFields,
    ru_tones: u16,
    symbols: usize,
    metrics: &[f32],
    max_psdu: usize,
    partial: bool,
) -> Result<Recovered, Error> {
    let c = Capacity::for_mu(signal, user, ru_tones, symbols).map_err(|_| Error::Capacity)?;
    if c.tail_bits != 0 {
        return Err(Error::Coding);
    }
    if c.psdu_bytes > max_psdu {
        return Err(Error::Limit);
    }
    let layout = Layout::he_mu(
        signal,
        user,
        ru_tones,
        u16::try_from(symbols).map_err(|_| Error::Length)?,
    )
    .map_err(Error::Fec)?;
    recover_layout(c, layout, usize::from(signal.stbc) + 1, metrics, partial)
}

/// Explicit Trigger-controlled TB coding. Neither strict nor partial recovery
/// establishes MAC integrity; each published aggregate member still needs FCS.
pub(in crate::radio) fn recover_tb(
    common: &crate::Dot11TriggerCommonFields,
    user: &crate::Dot11TriggerUserFields,
    symbols: usize,
    metrics: &[f32],
    max_psdu: usize,
    partial: bool,
) -> Result<Recovered, Error> {
    let c = Capacity::for_tb(common, user, symbols).map_err(|_| Error::Capacity)?;
    if c.tail_bits != 0 {
        return Err(Error::Coding);
    }
    if c.psdu_bytes > max_psdu {
        return Err(Error::Limit);
    }
    let layout = Layout::he_tb(
        common,
        user,
        u16::try_from(symbols).map_err(|_| Error::Length)?,
    )
    .map_err(Error::Fec)?;
    recover_layout(c, layout, usize::from(common.stbc) + 1, metrics, partial)
}

fn recover_layout(
    c: Capacity,
    layout: Layout,
    group: usize,
    metrics: &[f32],
    partial: bool,
) -> Result<Recovered, Error> {
    let symbols = layout.symbols;
    if symbols.checked_mul(c.coded_per_symbol) != Some(metrics.len()) {
        return Err(Error::Length);
    }
    if metrics.iter().any(|v| !v.is_finite()) {
        return Err(Error::Metrics);
    }
    let mut coded = Vec::new();
    coded
        .try_reserve_exact(c.coded_bits)
        .map_err(|_| Error::Allocation)?;
    for (n, block) in metrics.chunks_exact(c.coded_per_symbol).enumerate() {
        let keep = if n >= symbols - group {
            c.coded_last
        } else {
            c.coded_per_symbol
        };
        coded.extend_from_slice(&block[..keep]);
    }
    let recovered = if partial {
        layout.recover_partial(&coded, 64).map_err(Error::Fec)?
    } else {
        let (bits, iterations) = layout.recover(&coded, 64).map_err(Error::Fec)?;
        Recovery {
            bits,
            iterations,
            failed_codewords: 0,
            first_failure: None,
        }
    };
    let psdu = crate::radio::data::descramble_psdu(recovered.bits, c.psdu_bytes)
        .map_err(|_| Error::Service)?;
    Ok(Recovered {
        psdu,
        iterations: recovered.iterations,
        failed_codewords: recovered.failed_codewords,
        first_failure: recovered.first_failure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::radio::HeSigBUserEncoding;

    #[test]
    fn radio_he_tb_ldpc_payloads() {
        let mut counts = [0usize; 3];
        for (index, row) in include_str!("../../../../tests/fixtures/iq/he-tb-ldpc-payload.tsv")
            .lines()
            .skip(1)
            .enumerate()
        {
            let c: Vec<_> = row.split('\t').collect();
            let ru = c[0].parse::<u16>().unwrap();
            let symbols = c[4].parse().unwrap();
            let common = crate::Dot11TriggerCommonFields {
                stbc: c[3] == "2",
                pre_fec_padding_raw: c[5].parse::<u8>().unwrap() % 4,
                ldpc_extra_segment: c[6] == "1",
                ..Default::default()
            };
            let user = crate::Dot11TriggerUserFields {
                aid12: 1,
                ru_allocation: match ru {
                    26 => 0,
                    52 => 74,
                    106 => 106,
                    242 => 122,
                    _ => unreachable!(),
                },
                mcs: c[1].parse().unwrap(),
                dcm: c[2] == "1",
                ldpc: true,
                ..Default::default()
            };
            let expected: Vec<_> = (0..c[8].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&c[8][i..i + 2], 16).unwrap())
                .collect();
            let metrics: Vec<_> = c[9]
                .bytes()
                .map(|b| if b == b'1' { 1. } else { -1. })
                .collect();
            let strict = recover_tb(&common, &user, symbols, &metrics, 65535, false);
            let partial = recover_tb(&common, &user, symbols, &metrics, 65535, true);
            match c[7] {
                "ok" => {
                    let strict = strict.unwrap_or_else(|e| panic!("TB case{index}: {e:?}"));
                    let partial = partial.unwrap();
                    assert_eq!(strict.psdu, expected, "TB case{index}");
                    assert_eq!(partial.psdu, expected);
                    assert_eq!(strict.failed_codewords, 0);
                    assert_eq!(partial.failed_codewords, 0);
                    assert!(strict.first_failure.is_none() && partial.first_failure.is_none());
                    counts[0] += 1;
                }
                "service" => {
                    assert!(matches!(strict, Err(Error::Service)), "TB case{index}");
                    assert!(matches!(partial, Err(Error::Service)));
                    counts[1] += 1;
                }
                "damage" => {
                    assert!(matches!(strict, Err(Error::Fec(_))));
                    let partial = partial.unwrap();
                    assert!(partial.failed_codewords > 0 && partial.first_failure.is_some());
                    let layout = Layout::he_tb(&common, &user, symbols as u16).unwrap();
                    let prefix = (layout.word(0).unwrap().information_bits - 16) / 8;
                    assert_eq!(partial.psdu[..prefix], expected[..prefix]);
                    assert_eq!(partial.psdu.len(), expected.len());
                    counts[2] += 1;
                }
                _ => panic!("unknown status"),
            }
            assert!(matches!(
                recover_tb(
                    &common,
                    &user,
                    symbols,
                    &metrics[..metrics.len() - 1],
                    65535,
                    false
                ),
                Err(Error::Length)
            ));
            if !expected.is_empty() {
                assert!(matches!(
                    recover_tb(&common, &user, symbols, &metrics, expected.len() - 1, false),
                    Err(Error::Limit)
                ));
            }
            if index % 100 == 0 {
                if c[7] == "ok" {
                    let capacity = Capacity::for_tb(&common, &user, symbols).unwrap();
                    let mut padded = metrics.clone();
                    for symbol in symbols - (1 + usize::from(common.stbc))..symbols {
                        let offset = symbol * capacity.coded_per_symbol;
                        padded[offset + capacity.coded_last..offset + capacity.coded_per_symbol]
                            .fill(f32::MAX);
                    }
                    assert_eq!(
                        recover_tb(&common, &user, symbols, &padded, 65535, false)
                            .unwrap()
                            .psdu,
                        expected
                    );
                }
                let mut bad = metrics.clone();
                bad[0] = f32::NAN;
                assert!(matches!(
                    recover_tb(&common, &user, symbols, &bad, 65535, true),
                    Err(Error::Metrics)
                ));
                assert!(matches!(
                    recover_tb(
                        &common,
                        &user,
                        symbols,
                        &vec![0.; metrics.len()],
                        65535,
                        true
                    ),
                    Err(Error::Fec(_))
                ));
                let mut bcc = user;
                bcc.ldpc = false;
                assert!(recover_tb(&common, &bcc, symbols, &metrics, 65535, false).is_err());
            }
        }
        assert_eq!(counts[0], 672);
        assert_eq!(&counts[1..], &[4, 1]);
    }

    #[test]
    fn radio_he_mu_ldpc_payloads() {
        let bits: Vec<_> = include_str!("../../../../tests/fixtures/iq/he-mu-signal-a-index.tsv")
            .lines()
            .nth(1)
            .unwrap()
            .split('\t')
            .next()
            .unwrap()
            .bytes()
            .map(|b| b - b'0')
            .collect();
        let mut signal = MuSignal::decode(&bits).unwrap();
        signal.bandwidth = 0;
        signal.sig_b_mcs = 1;
        signal.sig_b_dcm = true;
        let mut damaged = 0;
        let mut service = 0;
        let mut valid = 0;
        for (n, row) in include_str!("../../../../tests/fixtures/iq/he-mu-ldpc-payload.tsv")
            .lines()
            .skip(1)
            .enumerate()
        {
            let c: Vec<_> = row.split('\t').collect();
            let ru = c[0].parse().unwrap();
            let mcs = c[1].parse().unwrap();
            let dcm = c[2] == "1";
            let group = c[3].parse::<u8>().unwrap();
            let symbols = c[4].parse().unwrap();
            signal.stbc = group == 2;
            signal.pre_fec_padding = c[5].parse().unwrap();
            signal.ldpc_extra_segment = c[6] == "1";
            let user = HeSigBUserFields {
                sta_id: 1,
                encoding: HeSigBUserEncoding::NonMu {
                    space_time_streams: group,
                    beamformed: false,
                    mcs,
                    dcm,
                    ldpc: true,
                },
            };
            let expected: Vec<_> = (0..c[8].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&c[8][i..i + 2], 16).unwrap())
                .collect();
            let metrics: Vec<_> = c[9]
                .bytes()
                .map(|b| if b == b'1' { 1. } else { -1. })
                .collect();
            let strict = recover(&signal, &user, ru, symbols, &metrics, 65535, false);
            let partial = recover(&signal, &user, ru, symbols, &metrics, 65535, true);
            match c[7] {
                "ok" => {
                    let strict = strict.unwrap_or_else(|e| panic!("case{n}: {e:?}"));
                    let partial = partial.unwrap();
                    assert_eq!(strict.psdu, expected, "case{n}");
                    assert_eq!(partial.psdu, expected);
                    assert_eq!(strict.failed_codewords, 0);
                    assert_eq!(partial.failed_codewords, 0);
                    assert!(strict.first_failure.is_none());
                    assert!(partial.first_failure.is_none());
                    assert_eq!(strict.iterations, partial.iterations);
                    valid += 1;
                }
                "service" => {
                    assert!(matches!(strict, Err(Error::Service)));
                    assert!(matches!(partial, Err(Error::Service)));
                    service += 1;
                }
                "damage" => {
                    assert!(matches!(strict, Err(Error::Fec(_))));
                    let partial = partial.unwrap();
                    assert!(partial.failed_codewords > 0);
                    assert!(partial.first_failure.is_some());
                    assert_eq!(partial.psdu.len(), expected.len());
                    let layout = Layout::he_mu(&signal, &user, ru, symbols as u16).unwrap();
                    let prefix = (layout.word(0).unwrap().information_bits - 16) / 8;
                    assert_eq!(partial.psdu[..prefix], expected[..prefix]);
                    damaged += 1;
                }
                _ => panic!("unknown fixture"),
            }
            assert!(matches!(
                recover(
                    &signal,
                    &user,
                    ru,
                    symbols,
                    &metrics[..metrics.len() - 1],
                    65535,
                    false
                ),
                Err(Error::Length)
            ));
            if !expected.is_empty() {
                assert!(matches!(
                    recover(
                        &signal,
                        &user,
                        ru,
                        symbols,
                        &metrics,
                        expected.len() - 1,
                        false
                    ),
                    Err(Error::Limit)
                ));
            }
            if n % 100 == 0 {
                if c[7] == "ok" {
                    let capacity = Capacity::for_mu(&signal, &user, ru, symbols).unwrap();
                    let mut padded = metrics.clone();
                    for symbol in symbols - usize::from(group)..symbols {
                        let offset = symbol * capacity.coded_per_symbol;
                        padded[offset + capacity.coded_last..offset + capacity.coded_per_symbol]
                            .fill(f32::MAX);
                    }
                    assert_eq!(
                        recover(&signal, &user, ru, symbols, &padded, 65535, false)
                            .unwrap()
                            .psdu,
                        expected
                    );
                }
                let mut bad = metrics.clone();
                bad[0] = f32::NAN;
                assert!(matches!(
                    recover(&signal, &user, ru, symbols, &bad, 65535, true),
                    Err(Error::Metrics)
                ));
                assert!(matches!(
                    recover(
                        &signal,
                        &user,
                        ru,
                        symbols,
                        &vec![0.; metrics.len()],
                        65535,
                        true
                    ),
                    Err(Error::Fec(_))
                ));
            }
            if n == 0 {
                let mut other = user;
                other.encoding = HeSigBUserEncoding::NonMu {
                    space_time_streams: group,
                    beamformed: false,
                    mcs,
                    dcm,
                    ldpc: false,
                };
                assert!(matches!(
                    recover(&signal, &other, ru, symbols, &metrics, 65535, false),
                    Err(Error::Coding)
                ));
                other.encoding = HeSigBUserEncoding::Unused { raw_parameters: 0 };
                assert!(matches!(
                    recover(&signal, &other, ru, symbols, &metrics, 65535, false),
                    Err(Error::Capacity)
                ));
                assert!(recover(&signal, &user, ru, usize::MAX, &[], usize::MAX, false).is_err());
            }
        }
        assert!(valid > 400);
        assert_eq!(service, 4);
        assert_eq!(damaged, 1);
    }
}
