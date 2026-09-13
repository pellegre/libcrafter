//! HE BCC payload kernel, IEEE802.11ax-2021 27.3.12.1-5.
use super::{he::SuSignal, he_capacity::Capacity, signal::TRELLIS_SIGNS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
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
pub(super) fn recover(
    a: &SuSignal,
    symbols: usize,
    metrics: &[f32],
    max_psdu: usize,
) -> Result<Vec<u8>, Error> {
    recover_for_format(a, symbols, metrics, max_psdu, false)
}

/// ER format must come from validated signaling. This does not demodulate IQ.
pub(super) fn recover_for_format(
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
    if c.psdu_bytes > max_psdu {
        return Err(Error::Limit);
    }
    if symbols.checked_mul(c.coded_per_symbol) != Some(metrics.len()) {
        return Err(Error::Length);
    }
    if metrics.iter().any(|v| !v.is_finite()) {
        return Err(Error::Metrics);
    }
    let group = if a.stbc { 2 } else { 1 };
    let mut coded = Vec::new();
    coded
        .try_reserve_exact(c.coded_bits)
        .map_err(|_| Error::Allocation)?;
    for (i, block) in metrics.chunks_exact(c.coded_per_symbol).enumerate() {
        let keep = if i >= symbols - group {
            c.coded_last
        } else {
            c.coded_per_symbol
        };
        for (j, value) in block[..keep].iter().enumerate() {
            // 27.3.12.5.1: filler after2*NDBPS (50 for106,116 for242),
            // only DCM BPSK/NSS1. Exclude it before soft-metric normalization.
            if c.bcc_dcm_filler && j == 2 * c.data_per_symbol {
                continue;
            }
            coded.push(*value);
        }
    }
    let scale = coded.iter().map(|v| v.abs()).fold(0f32, f32::max);
    if scale == 0. {
        return Err(Error::Metrics);
    }
    let pattern: &[u8] = match (c.rate_num, c.rate_den) {
        (1, 2) => &[1, 1],
        (2, 3) => &[1, 1, 1, 0],
        (3, 4) => &[1, 1, 1, 0, 0, 1],
        (5, 6) => &[1, 1, 1, 0, 0, 1, 1, 0, 0, 1],
        _ => return Err(Error::Coding),
    };
    let mut history = Vec::new();
    history
        .try_reserve_exact(c.data_bits)
        .map_err(|_| Error::Allocation)?;
    history.resize(c.data_bits, [0u8; 64]);
    let mut costs = [f32::INFINITY; 64];
    costs[0] = 0.;
    let mut cursor = 0;
    for (t, row) in history.iter_mut().enumerate() {
        let mut pair = [0.; 2];
        for (j, value) in pair.iter_mut().enumerate() {
            if pattern[(2 * t + j) % pattern.len()] != 0 {
                *value = *coded.get(cursor).ok_or(Error::Length)? / scale;
                cursor += 1;
            }
        }
        let mut next = [f32::INFINITY; 64];
        for (state, cost) in costs.iter().enumerate() {
            for bit in 0..2 {
                let reg = (state << 1) | bit;
                let signs = TRELLIS_SIGNS[reg];
                let score = cost - pair[0] * signs[0] - pair[1] * signs[1];
                if score < next[reg & 63] {
                    next[reg & 63] = score;
                    row[reg & 63] = state as u8;
                }
            }
        }
        let minimum = next.iter().copied().fold(f32::INFINITY, f32::min);
        for v in &mut next {
            *v -= minimum;
        }
        costs = next;
    }
    if cursor != coded.len() {
        return Err(Error::Length);
    }
    // HE tail is after pre-FEC PHY padding and terminates the encoder.
    let mut state = 0;
    let mut bits = Vec::new();
    bits.try_reserve_exact(c.data_bits)
        .map_err(|_| Error::Allocation)?;
    bits.resize(c.data_bits, 0);
    for (t, row) in history.iter().enumerate().rev() {
        bits[t] = (state & 1) as u8;
        state = row[state] as usize;
    }
    super::data::descramble_psdu(bits, c.psdu_bytes).map_err(|_| Error::Service)
}

#[cfg(test)]
mod tests {
    use super::*;
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
            include_str!("../../tests/fixtures/iq/he-bcc-index.tsv"),
            None,
            435,
        );
    }

    #[test]
    fn radio_he_er_bcc_independent_payloads_and_service() {
        payloads(
            include_str!("../../tests/fixtures/iq/he-er106-bcc-index.tsv"),
            Some(1),
            165,
        );
        payloads(
            include_str!("../../tests/fixtures/iq/he-er242-bcc-index.tsv"),
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
            include_str!("../../tests/fixtures/iq/he-bcc-index.tsv"),
            None,
        );
    }

    #[test]
    fn radio_he_er_bcc_soft_metrics_padding_and_bounds() {
        soft_bounds(
            include_str!("../../tests/fixtures/iq/he-er106-bcc-index.tsv"),
            Some(1),
        );
        soft_bounds(
            include_str!("../../tests/fixtures/iq/he-er242-bcc-index.tsv"),
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
