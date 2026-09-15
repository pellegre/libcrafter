//! Bounded HT LDPC codeword primitive. Rate matching and IQ dispatch are separate.
//! IEEE 802.11-2020 19.3.11.7.3–4 and Annex F define the parity constraints;
//! normalized min-sum is a receiver implementation choice, not a wire rule.
mod encoder;
mod matrices;
pub(super) mod rate;

use matrices::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rate {
    Half,
    TwoThirds,
    ThreeQuarters,
    FiveSixths,
}
impl Rate {
    pub(super) fn ratio(self) -> (usize, usize) {
        match self {
            Self::Half => (1, 2),
            Self::TwoThirds => (2, 3),
            Self::ThreeQuarters => (3, 4),
            Self::FiveSixths => (5, 6),
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Half => 0,
            Self::TwoThirds => 1,
            Self::ThreeQuarters => 2,
            Self::FiveSixths => 3,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    CodeLength,
    InformationCount {
        required: usize,
        available: usize,
    },
    NonBinaryInformation {
        index: usize,
        value: u8,
    },
    SingularParity,
    MetricCount {
        required: usize,
        available: usize,
    },
    NonFiniteMetric {
        index: usize,
    },
    UnusableMetrics,
    IterationLimit,
    Nonconvergence {
        iterations: usize,
        failed_checks: usize,
    },
}
pub(super) struct Code {
    pub(super) n: usize,
    pub(super) k: usize,
    rate: Rate,
    pub(super) checks: Vec<Vec<usize>>,
}
pub(super) struct Estimate {
    pub bits: Vec<u8>,
    pub iterations: usize,
    pub failed_checks: usize,
}
impl Code {
    pub(super) fn new(n: usize, rate: Rate) -> Result<Self, Error> {
        let prototype: &[[i8; 24]] = match (n, rate) {
            (648, Rate::Half) => &H_648_1_2,
            (648, Rate::TwoThirds) => &H_648_2_3,
            (648, Rate::ThreeQuarters) => &H_648_3_4,
            (648, Rate::FiveSixths) => &H_648_5_6,
            (1296, Rate::Half) => &H_1296_1_2,
            (1296, Rate::TwoThirds) => &H_1296_2_3,
            (1296, Rate::ThreeQuarters) => &H_1296_3_4,
            (1296, Rate::FiveSixths) => &H_1296_5_6,
            (1944, Rate::Half) => &H_1944_1_2,
            (1944, Rate::TwoThirds) => &H_1944_2_3,
            (1944, Rate::ThreeQuarters) => &H_1944_3_4,
            (1944, Rate::FiveSixths) => &H_1944_5_6,
            _ => return Err(Error::CodeLength),
        };
        let z = n / 24;
        let (num, den) = rate.ratio();
        let checks = prototype
            .iter()
            .flat_map(|row| {
                (0..z).map(move |i| {
                    row.iter()
                        .enumerate()
                        .filter_map(|(column, &shift)| {
                            (shift >= 0).then(|| column * z + (i + shift as usize) % z)
                        })
                        .collect()
                })
            })
            .collect();
        Ok(Self {
            n,
            k: n * num / den,
            rate,
            checks,
        })
    }
    pub(super) fn failed_checks(&self, bits: &[u8]) -> usize {
        self.checks
            .iter()
            .filter(|row| row.iter().fold(0, |p, &i| p ^ bits[i]) != 0)
            .count()
    }
    pub(super) fn encode(&self, information: &[u8]) -> Result<Vec<u8>, Error> {
        encoder::encode(self, information)
    }
    /// Positive input favors one, consistent with the OFDM demapper. At most
    /// 64 layered normalized-min-sum iterations; only zero-syndrome words exit.
    /// This is not MAC integrity: the caller must still validate SERVICE/FCS.
    #[cfg(test)]
    pub(super) fn decode(&self, metrics: &[f32], limit: usize) -> Result<(Vec<u8>, usize), Error> {
        let estimate = self.estimate(metrics, limit)?;
        if estimate.failed_checks != 0 {
            return Err(Error::Nonconvergence {
                iterations: estimate.iterations,
                failed_checks: estimate.failed_checks,
            });
        }
        Ok((estimate.bits, estimate.iterations))
    }
    /// Tentative information bits at the bounded stopping point. Nonzero
    /// syndrome is explicit; these bits are NOT integrity-checked payload.
    pub(super) fn estimate(&self, metrics: &[f32], limit: usize) -> Result<Estimate, Error> {
        if metrics.len() != self.n {
            return Err(Error::MetricCount {
                required: self.n,
                available: metrics.len(),
            });
        }
        if limit == 0 || limit > 64 {
            return Err(Error::IterationLimit);
        }
        let mut maximum = 0f32;
        for (index, &m) in metrics.iter().enumerate() {
            if !m.is_finite() {
                return Err(Error::NonFiniteMetric { index });
            }
            maximum = maximum.max(m.abs());
        }
        if maximum == 0. {
            return Err(Error::UnusableMetrics);
        }
        // Normalize before multiplication so finite extreme inputs do not overflow.
        let mut belief: Vec<f32> = metrics.iter().map(|&m| -8. * (m / maximum)).collect();
        let mut messages: Vec<Vec<f32>> =
            self.checks.iter().map(|row| vec![0.; row.len()]).collect();
        let mut bits: Vec<u8> = belief.iter().map(|&m| u8::from(m < 0.)).collect();
        for iteration in 0..=limit {
            let failed = self.failed_checks(&bits);
            if failed == 0 || iteration == limit {
                bits.truncate(self.k);
                return Ok(Estimate {
                    bits,
                    iterations: iteration,
                    failed_checks: failed,
                });
            }
            for (row, old) in self.checks.iter().zip(&mut messages) {
                let mut extrinsic = [0f32; 24];
                let (mut first, mut second, mut sign) = (f32::INFINITY, f32::INFINITY, 1f32);
                for (edge, &bit) in row.iter().enumerate() {
                    let value = (belief[bit] - old[edge]).clamp(-64., 64.);
                    extrinsic[edge] = value;
                    sign *= if value < 0. { -1. } else { 1. };
                    let magnitude = value.abs();
                    if magnitude < first {
                        second = first;
                        first = magnitude;
                    } else {
                        second = second.min(magnitude);
                    }
                }
                for (edge, &bit) in row.iter().enumerate() {
                    let value = extrinsic[edge];
                    let magnitude = if value.abs() == first { second } else { first };
                    let message = 0.8 * sign * if value < 0. { -magnitude } else { magnitude };
                    old[edge] = message;
                    belief[bit] = value + message;
                }
            }
            for (bit, &m) in bits.iter_mut().zip(&belief) {
                *bit = u8::from(m < 0.);
            }
        }
        unreachable!("bounded loop returns on convergence or final iteration")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn radio_ldpc_independent_codewords_and_correction() {
        let entries: Vec<_> = include_str!("../../../../../tests/fixtures/iq/ldpc-codewords.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(entries.len(), 12);
        for entry in entries {
            let fields: Vec<_> = entry.split('\t').collect();
            let n = fields[0].parse::<usize>().unwrap();
            let k = fields[1].parse::<usize>().unwrap();
            let rate = match fields[4].parse::<usize>().unwrap() {
                2 => Rate::Half,
                3 => Rate::TwoThirds,
                4 => Rate::ThreeQuarters,
                6 => Rate::FiveSixths,
                _ => panic!(),
            };
            let code = Code::new(n, rate).unwrap();
            assert_eq!(code.k, k);
            assert_eq!(code.checks.len(), n - k);
            let z = n / 24;
            for (row, expected) in fields[5].split(';').enumerate() {
                for offset in 0..z {
                    let expected: Vec<_> = expected
                        .split(',')
                        .enumerate()
                        .filter_map(|(col, v)| {
                            let shift = v.parse::<i8>().unwrap();
                            (shift >= 0).then(|| col * z + (offset + shift as usize) % z)
                        })
                        .collect();
                    assert_eq!(code.checks[row * z + offset], expected);
                }
            }
            for word in fields[6].split(';') {
                let bits: Vec<_> = word.bytes().map(|b| b - b'0').collect();
                assert_eq!(bits.len(), n);
                assert_eq!(code.failed_checks(&bits), 0);
                assert_eq!(code.encode(&bits[..k]).unwrap(), bits);
                let clean: Vec<_> = bits
                    .iter()
                    .map(|&b| if b == 1 { 4. } else { -4. })
                    .collect();
                assert_eq!(code.decode(&clean, 64).unwrap(), (bits[..k].to_vec(), 0));
                let mut damaged = clean.clone();
                for i in 0..8 {
                    let pos = (i * 79 + 11) % n;
                    damaged[pos] *= -0.25;
                }
                let (actual, iterations) = code
                    .decode(&damaged, 64)
                    .unwrap_or_else(|e| panic!("n={n} rate={rate:?}: {e:?}"));
                assert_eq!(actual, bits[..k]);
                assert!(iterations > 0 && iterations <= 64);
            }
        }
    }
    #[test]
    fn radio_ldpc_input_and_iteration_bounds() {
        assert!(matches!(Code::new(650, Rate::Half), Err(Error::CodeLength)));
        let code = Code::new(648, Rate::Half).unwrap();
        assert!(matches!(
            code.encode(&[]),
            Err(Error::InformationCount { .. })
        ));
        let mut invalid = vec![0; 324];
        invalid[17] = 2;
        assert_eq!(
            code.encode(&invalid),
            Err(Error::NonBinaryInformation {
                index: 17,
                value: 2
            })
        );
        assert!(matches!(
            code.decode(&[], 64),
            Err(Error::MetricCount { .. })
        ));
        assert_eq!(code.decode(&[0.; 648], 64), Err(Error::UnusableMetrics));
        assert_eq!(code.decode(&[1.; 648], 65), Err(Error::IterationLimit));
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut metrics = vec![1.; 648];
            metrics[31] = value;
            assert_eq!(
                code.decode(&metrics, 64),
                Err(Error::NonFiniteMetric { index: 31 })
            );
        }
        for scale in [f32::MAX, f32::MIN_POSITIVE, f32::from_bits(1)] {
            assert_eq!(
                code.decode(&vec![-scale; 648], 64).unwrap(),
                (vec![0; 324], 0)
            );
        }
        let noise: Vec<_> = (0..648)
            .map(|i| if (i * 17 + i * i) % 31 < 15 { 1. } else { -1. })
            .collect();
        assert!(matches!(
            code.decode(&noise, 1),
            Err(Error::Nonconvergence { iterations: 1, .. })
        ));
        let tentative = code.estimate(&noise, 1).unwrap();
        assert_eq!(tentative.bits.len(), 324);
        assert_eq!(tentative.iterations, 1);
        assert!(tentative.failed_checks > 0);
        assert_eq!(
            code.decode(&noise, 1),
            Err(Error::Nonconvergence {
                iterations: tentative.iterations,
                failed_checks: tentative.failed_checks,
            })
        );
    }
}
