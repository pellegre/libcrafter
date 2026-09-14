//! HT LDPC sizing: IEEE 802.11-2020 19.3.11.7.5, Table 19-16.
//! Integer inequalities preserve the strict thresholds in Equations 19-38–40.
use super::Rate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    EmptyPayload,
    InvalidCodedBits,
    PayloadBitCount { required: usize, available: usize },
    Encoding(super::Error),
    Metrics(super::Error),
    Codeword { index: usize, error: super::Error },
    Shortening { index: usize },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) struct Word {
    pub information_bits: usize,
    pub shortened_bits: usize,
    pub punctured_bits: usize,
    pub repeated_bits: usize,
    pub transmitted_bits: usize,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) struct Layout {
    pub symbols: usize,
    pub codewords: usize,
    pub block_bits: usize,
    pub shortened_bits: usize,
    pub punctured_bits: usize,
    pub repeated_bits: usize,
    pub extra_symbol_group: bool,
    pub payload_bits: usize,
    pub coded_bits_per_symbol: usize,
    pub rate: Rate,
}
pub(in crate::radio) struct Recovery {
    pub bits: Vec<u8>,
    pub iterations: usize,
    pub failed_codewords: usize,
    pub first_failure: Option<Error>,
}
impl Layout {
    /// Encode the scrambled SERVICE and PSDU bits, then apply shortening,
    /// puncturing, and repetition in transmitted codeword order.
    pub(in crate::radio) fn encode(self, bits: &[u8]) -> Result<Vec<u8>, Error> {
        if bits.len() != self.payload_bits {
            return Err(Error::PayloadBitCount {
                required: self.payload_bits,
                available: bits.len(),
            });
        }
        let code = super::Code::new(self.block_bits, self.rate).map_err(Error::Encoding)?;
        let (num, den) = self.rate.ratio();
        let information_bits = self.block_bits * num / den;
        let mut output = Vec::with_capacity(self.symbols * self.coded_bits_per_symbol);
        let mut offset = 0;
        for index in 0..self.codewords {
            let spec = self.word(index).unwrap();
            let end = offset + spec.information_bits;
            let mut information = Vec::with_capacity(information_bits);
            information.extend_from_slice(&bits[offset..end]);
            information.resize(information_bits, 0);
            let word = code.encode(&information).map_err(Error::Encoding)?;
            output.extend_from_slice(&word[..spec.information_bits]);
            output
                .extend_from_slice(&word[information_bits..self.block_bits - spec.punctured_bits]);
            let base = output.len() - (self.block_bits - spec.shortened_bits - spec.punctured_bits);
            for repeat in 0..spec.repeated_bits {
                output.push(output[base + repeat % (self.block_bits - spec.shortened_bits)]);
            }
            offset = end;
        }
        debug_assert_eq!(offset, bits.len());
        debug_assert_eq!(output.len(), self.symbols * self.coded_bits_per_symbol);
        Ok(output)
    }

    /// Restore omitted known-zero information bits and erased parity, combine
    /// repeated observations, and recover the concatenated information stream.
    /// Input is in transmitted codeword order (LDPC bypasses BCC interleaving).
    pub(in crate::radio) fn recover(
        self,
        metrics: &[f32],
        limit: usize,
    ) -> Result<(Vec<u8>, usize), Error> {
        let recovered = self.recover_impl(metrics, limit, false)?;
        Ok((recovered.bits, recovered.iterations))
    }
    /// Retain bounded estimates across damaged codewords for A-MPDU scanning.
    /// The caller must validate SERVICE and every delivered MPDU's FCS.
    pub(in crate::radio) fn recover_partial(
        self,
        metrics: &[f32],
        limit: usize,
    ) -> Result<Recovery, Error> {
        self.recover_impl(metrics, limit, true)
    }
    fn recover_impl(self, metrics: &[f32], limit: usize, partial: bool) -> Result<Recovery, Error> {
        use super::{Code, Error as CodeError};
        let required = self.symbols * self.coded_bits_per_symbol;
        if metrics.len() != required {
            return Err(Error::Metrics(CodeError::MetricCount {
                required,
                available: metrics.len(),
            }));
        }
        let mut maximum = 0f32;
        for (index, &m) in metrics.iter().enumerate() {
            if !m.is_finite() {
                return Err(Error::Metrics(CodeError::NonFiniteMetric { index }));
            }
            maximum = maximum.max(m.abs());
        }
        if maximum == 0. {
            return Err(Error::Metrics(CodeError::UnusableMetrics));
        }
        let code = Code::new(self.block_bits, self.rate).map_err(Error::Metrics)?;
        let (num, den) = self.rate.ratio();
        let k = self.block_bits * num / den;
        let mut output = Vec::with_capacity(self.payload_bits);
        let (mut offset, mut iterations) = (0, 0);
        let (mut failed_codewords, mut first_failure) = (0, None);
        for index in 0..self.codewords {
            let spec = self.word(index).unwrap();
            let mut word = vec![0.; self.block_bits]; // Unknown punctures have zero LLR.
            let normalize = |m: f32| 4. * (m / maximum);
            for (i, m) in word[..spec.information_bits].iter_mut().enumerate() {
                *m = normalize(metrics[offset + i]);
            }
            word[spec.information_bits..k].fill(-32.); // Known zero, not an erasure.
            let parity = self.block_bits - k - spec.punctured_bits;
            for (i, m) in word[k..k + parity].iter_mut().enumerate() {
                *m = normalize(metrics[offset + spec.information_bits + i]);
            }
            let base = self.block_bits - spec.shortened_bits - spec.punctured_bits;
            for repeat in 0..spec.repeated_bits {
                let source = repeat % (self.block_bits - spec.shortened_bits);
                let bit = if source < spec.information_bits {
                    source
                } else {
                    source + spec.shortened_bits
                };
                word[bit] += normalize(metrics[offset + base + repeat]);
            }
            let estimate = code
                .estimate(&word, limit)
                .map_err(|error| Error::Codeword { index, error })?;
            let mut bits = estimate.bits;
            let failure = if estimate.failed_checks != 0 {
                Some(Error::Codeword {
                    index,
                    error: CodeError::Nonconvergence {
                        iterations: estimate.iterations,
                        failed_checks: estimate.failed_checks,
                    },
                })
            } else if bits[spec.information_bits..].iter().any(|&b| b != 0) {
                Some(Error::Shortening { index })
            } else {
                None
            };
            if let Some(error) = failure {
                if !partial {
                    return Err(error);
                }
                failed_codewords += 1;
                first_failure.get_or_insert(error);
            }
            bits.truncate(spec.information_bits);
            output.extend(bits);
            iterations += estimate.iterations;
            offset += spec.transmitted_bits;
        }
        Ok(Recovery {
            bits: output,
            iterations,
            failed_codewords,
            first_failure,
        })
    }
    /// u16 dimensions bound all arithmetic even on 32-bit hosts. The enclosing
    /// PHY must additionally validate that its MCS actually permits `coded`.
    pub(in crate::radio) fn new(
        bytes: u16,
        coded: u16,
        rate: Rate,
        stbc: bool,
    ) -> Result<Self, Error> {
        if bytes == 0 {
            return Err(Error::EmptyPayload);
        }
        let (num, den) = rate.ratio();
        let coded = usize::from(coded);
        if coded == 0 || coded * num % den != 0 {
            return Err(Error::InvalidCodedBits);
        }
        let group = if stbc { 2 } else { 1 };
        let payload = 8 * usize::from(bytes) + 16;
        let mut available = coded * group * payload.div_ceil(coded * num / den * group);
        let original = available;
        let threshold = |constant| available * den >= payload * den + constant * (den - num);
        let (count, size) = match available {
            0..=648 => (1, if threshold(912) { 1296 } else { 648 }),
            649..=1296 => (1, if threshold(1464) { 1944 } else { 1296 }),
            1297..=1944 => (1, 1944),
            1945..=2592 => (2, if threshold(2916) { 1944 } else { 1296 }),
            _ => (payload.div_ceil(1944 * num / den), 1944),
        };
        let short = (count * size * num / den).saturating_sub(payload);
        let mut puncture = (count * size).saturating_sub(available + short);
        let parity = count * size * (den - num) / den;
        if (10 * puncture > parity && 5 * short * (den - num) < 6 * puncture * num)
            || 10 * puncture > 3 * parity
        {
            available += coded * group;
            puncture = (count * size).saturating_sub(available + short);
        }
        let repeat = available.saturating_sub(parity + payload);
        Ok(Self {
            symbols: available / coded,
            codewords: count,
            block_bits: size,
            shortened_bits: short,
            punctured_bits: puncture,
            repeated_bits: repeat,
            extra_symbol_group: available != original,
            payload_bits: payload,
            coded_bits_per_symbol: coded,
            rate,
        })
    }
    pub(in crate::radio) fn word(self, index: usize) -> Option<Word> {
        if index >= self.codewords {
            return None;
        }
        let share = |total| total / self.codewords + usize::from(index < total % self.codewords);
        let shortened = share(self.shortened_bits);
        let punctured = share(self.punctured_bits);
        let repeated = share(self.repeated_bits);
        let (num, den) = self.rate.ratio();
        Some(Word {
            information_bits: self.block_bits * num / den - shortened,
            shortened_bits: shortened,
            punctured_bits: punctured,
            repeated_bits: repeated,
            transmitted_bits: self.block_bits - shortened - punctured + repeated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn radio_ldpc_independent_rate_matched_recovery() {
        let rows: Vec<_> = include_str!("../../../tests/fixtures/iq/ldpc-rate-codewords.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 48);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let mcs = c[1].parse::<usize>().unwrap();
            let (coded, rate) = [
                (52, Rate::Half),
                (104, Rate::Half),
                (104, Rate::ThreeQuarters),
                (208, Rate::Half),
                (208, Rate::ThreeQuarters),
                (312, Rate::TwoThirds),
                (312, Rate::ThreeQuarters),
                (312, Rate::FiveSixths),
            ][mcs];
            let layout = Layout::new(c[0].parse().unwrap(), coded, rate, c[2] == "2").unwrap();
            let expected: Vec<_> = c[3].bytes().map(|b| b - b'0').collect();
            let clean: Vec<_> = c[4]
                .bytes()
                .map(|b| if b == b'1' { 1. } else { -1. })
                .collect();
            let transmitted: Vec<_> = c[4].bytes().map(|b| b - b'0').collect();
            assert_eq!(layout.encode(&expected).unwrap(), transmitted);
            for scale in [1., f32::MAX, f32::MIN_POSITIVE] {
                let metrics: Vec<_> = clean.iter().map(|v| v * scale).collect();
                let (actual, iterations) = layout.recover(&metrics, 64).unwrap_or_else(|e| {
                    panic!(
                        "length={} mcs={mcs} group={} scale={scale}: {e:?}",
                        c[0], c[2]
                    )
                });
                assert_eq!(actual, expected);
                assert!(iterations <= layout.codewords * 64);
            }
            assert!(matches!(
                layout.recover(&clean[..clean.len() - 1], 64),
                Err(Error::Metrics(super::super::Error::MetricCount { .. }))
            ));
            let mut damaged = clean.clone();
            for index in [7, 53] {
                let bit = index % damaged.len();
                damaged[bit] *= -0.25;
            }
            assert_eq!(
                layout
                    .recover(&damaged, 64)
                    .unwrap_or_else(|e| panic!(
                        "damaged length={} mcs={mcs} group={}: {e:?}",
                        c[0], c[2]
                    ))
                    .0,
                expected
            );
            let mut invalid = clean.clone();
            invalid[3] = f32::NAN;
            assert_eq!(
                layout.recover(&invalid, 64),
                Err(Error::Metrics(super::super::Error::NonFiniteMetric {
                    index: 3
                }))
            );
            assert_eq!(
                layout.recover(&vec![0.; clean.len()], 64),
                Err(Error::Metrics(super::super::Error::UnusableMetrics))
            );
        }
    }
    #[test]
    fn radio_ldpc_independent_rate_matching_geometry() {
        let rows: Vec<_> = include_str!("../../../tests/fixtures/iq/ldpc-rate-index.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 208);
        let (mut extra, mut punctured, mut repeated) = (0, 0, 0);
        let mut blocks = std::collections::BTreeSet::new();
        for row in rows {
            let c: Vec<usize> = row.split('\t').map(|v| v.parse().unwrap()).collect();
            let rate = match c[5] {
                2 => Rate::Half,
                3 => Rate::TwoThirds,
                4 => Rate::ThreeQuarters,
                6 => Rate::FiveSixths,
                _ => panic!(),
            };
            let layout = Layout::new(c[0] as u16, c[3] as u16, rate, c[2] == 2).unwrap();
            assert_eq!(
                [
                    layout.symbols,
                    layout.codewords,
                    layout.block_bits,
                    layout.shortened_bits,
                    layout.punctured_bits,
                    layout.repeated_bits,
                    usize::from(layout.extra_symbol_group)
                ],
                c[6..],
                "{row}"
            );
            let mut totals = [0usize; 5];
            for index in 0..layout.codewords {
                let word = layout.word(index).unwrap();
                for (sum, value) in totals.iter_mut().zip([
                    word.information_bits,
                    word.shortened_bits,
                    word.punctured_bits,
                    word.repeated_bits,
                    word.transmitted_bits,
                ]) {
                    *sum += value;
                }
                assert!(word.information_bits > 0);
                assert!(word.punctured_bits < layout.block_bits * (c[5] - c[4]) / c[5]);
            }
            assert_eq!(
                totals,
                [
                    layout.payload_bits,
                    layout.shortened_bits,
                    layout.punctured_bits,
                    layout.repeated_bits,
                    layout.symbols * c[3]
                ]
            );
            assert!(layout.word(layout.codewords).is_none());
            assert!(!(layout.punctured_bits > 0 && layout.repeated_bits > 0));
            extra += usize::from(layout.extra_symbol_group);
            punctured += usize::from(layout.punctured_bits > 0);
            repeated += usize::from(layout.repeated_bits > 0);
            blocks.insert(layout.block_bits);
        }
        assert!(extra > 0 && punctured > 0 && repeated > 0);
        assert_eq!(blocks, std::collections::BTreeSet::from([648, 1296, 1944]));
    }
    #[test]
    fn radio_ldpc_rate_dimensions_and_extremes() {
        assert_eq!(
            Layout::new(0, 52, Rate::Half, false),
            Err(Error::EmptyPayload)
        );
        assert_eq!(
            Layout::new(1, 0, Rate::Half, false),
            Err(Error::InvalidCodedBits)
        );
        assert_eq!(
            Layout::new(1, 52, Rate::TwoThirds, false),
            Err(Error::InvalidCodedBits)
        );
        let layout = Layout::new(1, 52, Rate::Half, false).unwrap();
        assert_eq!(
            layout.encode(&[]),
            Err(Error::PayloadBitCount {
                required: 24,
                available: 0
            })
        );
        for rate in [
            Rate::Half,
            Rate::TwoThirds,
            Rate::ThreeQuarters,
            Rate::FiveSixths,
        ] {
            let (_, den) = rate.ratio();
            for coded in [den as u16, (65535 / den * den) as u16] {
                for bytes in [1, 65535] {
                    let layout = Layout::new(bytes, coded, rate, true).unwrap();
                    assert!(layout.symbols > 0 && layout.symbols % 2 == 0);
                    assert_eq!(
                        layout.codewords * layout.block_bits
                            - layout.shortened_bits
                            - layout.punctured_bits
                            + layout.repeated_bits,
                        layout.symbols * usize::from(coded)
                    );
                }
            }
        }
    }
}
