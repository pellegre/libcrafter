//! HE SIG-B 27.3.11.8.5: reset BCC per block, puncture the concatenated output.
//! Input is already deinterleaved and DCM-combined; positive metrics favor one.
use super::he_sig_b::{HeSigBCommon20Fields, HeSigBError, HeSigBUserBlock, HeSigBUserContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    Mcs(u8),
    NonFinite { index: usize },
    Truncated { required: usize, available: usize },
    Erased,
    Header(HeSigBError),
}

pub(super) struct Blocks<'a> {
    metrics: &'a [f32],
    pattern: &'static [u8],
    cursor: usize,
    phase: usize,
}

impl<'a> Blocks<'a> {
    pub(super) fn new(metrics: &'a [f32], mcs: u8) -> Result<Self, Error> {
        // Table 27-111. DCM changes the mapper, not the BCC puncturing rate.
        let pattern: &[u8] = match mcs {
            0 | 1 | 3 => &[1, 1],
            2 | 4 => &[1, 1, 1, 0, 0, 1],
            5 => &[1, 1, 1, 0],
            _ => return Err(Error::Mcs(mcs)),
        };
        if let Some(index) = metrics.iter().position(|m| !m.is_finite()) {
            return Err(Error::NonFinite { index });
        }
        Ok(Self {
            metrics,
            pattern,
            cursor: 0,
            phase: 0,
        })
    }

    pub(super) fn consumed(&self) -> usize {
        self.cursor
    }

    pub(super) fn common(&mut self) -> Result<HeSigBCommon20Fields, Error> {
        HeSigBCommon20Fields::decode(&self.bits::<18>()?).map_err(Error::Header)
    }

    pub(super) fn users(
        &mut self,
        contexts: &[HeSigBUserContext],
    ) -> Result<HeSigBUserBlock, Error> {
        match contexts.len() {
            1 => HeSigBUserBlock::decode(&self.bits::<31>()?, contexts),
            2 => HeSigBUserBlock::decode(&self.bits::<52>()?, contexts),
            available => Err(HeSigBError::UserCount { available }),
        }
        .map_err(Error::Header)
    }

    fn bits<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        // N is one of the three fixed SIG-B block lengths. No untrusted-size
        // trellis allocation. Check the whole block before advancing anything.
        let required = (0..2 * N)
            .filter(|i| self.pattern[(self.phase + i) % self.pattern.len()] != 0)
            .count();
        let available = self.metrics.len() - self.cursor;
        if available < required {
            return Err(Error::Truncated {
                required,
                available,
            });
        }
        let block = &self.metrics[self.cursor..self.cursor + required];
        let scale = block.iter().map(|m| m.abs()).fold(0f32, f32::max);
        let mut at = 0;
        let pairs = std::array::from_fn::<_, N, _>(|t| {
            std::array::from_fn(|j| {
                if self.pattern[(self.phase + 2 * t + j) % self.pattern.len()] == 0 {
                    0.
                } else {
                    let metric = block[at];
                    at += 1;
                    if scale == 0. {
                        0.
                    } else {
                        metric / scale
                    }
                }
            })
        });
        self.cursor += required;
        self.phase = (self.phase + 2 * N) % self.pattern.len();
        if scale == 0. {
            return Err(Error::Erased);
        }
        // Leave final-state selection unconstrained so invalid tail bits are
        // observable by the checked parser instead of silently forced to zero.
        Ok(super::signal::decode_bcc(&pairs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(decoder: &mut Blocks<'_>, length: usize) -> Result<Vec<u8>, Error> {
        match length {
            18 => decoder.bits::<18>().map(|b| b.to_vec()),
            31 => decoder.bits::<31>().map(|b| b.to_vec()),
            52 => decoder.bits::<52>().map(|b| b.to_vec()),
            _ => panic!("invalid fixture length"),
        }
    }

    #[test]
    fn radio_he_sig_b_coded_erasure_and_truncation() {
        for row in include_str!("../../tests/fixtures/iq/he-sig-b-coded.tsv")
            .lines()
            .skip(1)
        {
            let c: Vec<_> = row.split('\t').collect();
            if c[2] != "3" || c[3] != "none" {
                continue;
            }
            let expected: Vec<Vec<u8>> = c[4]
                .split(';')
                .map(|s| s.bytes().map(|b| b - b'0').collect())
                .collect();
            let metrics: Vec<_> = c[5]
                .bytes()
                .map(|b| if b == b'1' { 1. } else { -1. })
                .collect();
            let mcs = c[0].parse().unwrap();
            let mut baseline = Blocks::new(&metrics, mcs).unwrap();
            let mut ranges = Vec::new();
            for bits in &expected {
                let start = baseline.consumed();
                assert_eq!(read(&mut baseline, bits.len()).unwrap(), *bits);
                ranges.push(start..baseline.consumed());
            }
            for (erased, range) in ranges.iter().enumerate() {
                let mut damaged = metrics.clone();
                damaged[range.clone()].fill(0.);
                let mut decoder = Blocks::new(&damaged, mcs).unwrap();
                for (i, bits) in expected.iter().enumerate() {
                    let result = read(&mut decoder, bits.len());
                    if i == erased {
                        assert_eq!(result, Err(Error::Erased));
                    } else {
                        assert_eq!(result, Ok(bits.clone()));
                    }
                    assert_eq!(decoder.consumed(), ranges[i].end);
                }
                // Truncate inside every block, after all preceding blocks.
                let mut short = Blocks::new(&metrics[..range.end - 1], mcs).unwrap();
                for bits in &expected[..erased] {
                    read(&mut short, bits.len()).unwrap();
                }
                let state = (short.cursor, short.phase);
                assert_eq!(
                    read(&mut short, expected[erased].len()),
                    Err(Error::Truncated {
                        required: range.len(),
                        available: range.len() - 1,
                    })
                );
                assert_eq!((short.cursor, short.phase), state);
            }
        }
    }

    #[test]
    fn radio_he_sig_b_coded_independent() {
        let rows = include_str!("../../tests/fixtures/iq/he-sig-b-coded.tsv");
        assert_eq!(rows.lines().skip(1).count(), 450);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let mcs = c[0].parse().unwrap();
            let common = c[1] == "1";
            let expected: Vec<Vec<u8>> = c[4]
                .split(';')
                .map(|s| s.bytes().map(|b| b - b'0').collect())
                .collect();
            for scale in [f32::MIN_POSITIVE, 1., f32::MAX] {
                let metrics: Vec<_> = c[5]
                    .bytes()
                    .map(|b| if b == b'1' { scale } else { -scale })
                    .collect();
                let mut decoder = Blocks::new(&metrics, mcs).unwrap();
                for bits in &expected {
                    let actual = read(&mut decoder, bits.len()).unwrap();
                    assert_eq!(&actual, bits, "MCS {mcs}: {row}");
                }
                assert_eq!(decoder.consumed(), c[6].parse::<usize>().unwrap());
                assert!(decoder.consumed() < metrics.len());
                let mut checked = Blocks::new(&metrics, mcs).unwrap();
                for (i, bits) in expected.iter().enumerate() {
                    let result = if i == 0 && common {
                        checked.common().map(|_| ())
                    } else {
                        checked
                            .users(&vec![HeSigBUserContext::NonMu; (bits.len() - 10) / 21])
                            .map(|b| assert!(b.users().iter().all(Result::is_ok)))
                    };
                    match (i, c[3]) {
                        (0, "crc") => assert!(matches!(
                            result,
                            Err(Error::Header(HeSigBError::Crc { .. }))
                        )),
                        (0, "tail") => assert!(matches!(
                            result,
                            Err(Error::Header(HeSigBError::Tail { .. }))
                        )),
                        _ => assert_eq!(result, Ok(()), "{row}"),
                    }
                }
            }
        }
    }

    #[test]
    fn radio_he_sig_b_coded_bounds() {
        for mcs in 6..=255 {
            assert!(matches!(Blocks::new(&[], mcs), Err(Error::Mcs(n)) if n==mcs));
        }
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            for index in 0..4 {
                let mut metrics = [1.; 4];
                metrics[index] = value;
                assert!(
                    matches!(Blocks::new(&metrics, 0), Err(Error::NonFinite { index: i }) if i==index)
                );
            }
        }
        for mcs in 0..6 {
            let mut decoder = Blocks::new(&[0.; 512], mcs).unwrap();
            assert_eq!(
                decoder.users(&[]),
                Err(Error::Header(HeSigBError::UserCount { available: 0 }))
            );
            assert_eq!(decoder.consumed(), 0);
            assert_eq!(decoder.common(), Err(Error::Erased));
            assert!(decoder.consumed() > 0);
            for count in [1, 2] {
                let contexts = vec![HeSigBUserContext::NonMu; count];
                let before = decoder.consumed();
                let phase = decoder.phase;
                assert_eq!(decoder.users(&contexts), Err(Error::Erased));
                let required = decoder.consumed() - before;
                for available in 0..required {
                    let metrics = vec![1.; available];
                    let mut short = Blocks::new(&metrics, mcs).unwrap();
                    short.phase = phase;
                    let old = (short.cursor, short.phase);
                    let result = short.users(&contexts);
                    assert_eq!(
                        result,
                        Err(Error::Truncated {
                            required,
                            available
                        })
                    );
                    assert_eq!((short.cursor, short.phase), old);
                }
            }
        }
    }
}
