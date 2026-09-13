//! Equalized HE SIG-B data tones; ax-2021 Eq 27-21, Tables 27-35/111.
use super::{
    data::{demap, demap_dcm_for_half},
    ComplexSample,
};

#[derive(Debug, Clone, Copy)]
pub(super) struct Modulation {
    bits: usize,
    dcm: bool,
}

impl Modulation {
    pub(super) fn new(mcs: u8, dcm: bool) -> Option<Self> {
        if mcs > 5 || (dcm && !matches!(mcs, 0 | 1 | 3 | 4)) {
            return None;
        }
        Some(Self {
            bits: [1, 2, 2, 4, 4, 6][mcs as usize],
            dcm,
        })
    }

    pub(super) fn coded_per_symbol(self) -> usize {
        52 * self.bits / (1 + usize::from(self.dcm))
    }

    /// Values are constellation-normalized and pilot/channel-corrected, with
    /// nonnegative reliability weights. Returns deinterleaved BCC metrics.
    /// Zero-weight/erased tones are allowed; no header or MAC integrity claim.
    pub(super) fn decode(self, tones: &[(ComplexSample, f32)]) -> Option<Vec<f32>> {
        if tones.len() != 52
            || tones
                .iter()
                .any(|(v, w)| !v.power().is_finite() || !w.is_finite() || *w < 0.)
        {
            return None;
        }
        let corrected: [(ComplexSample, f32); 52] = std::array::from_fn(|k| {
            let (v, w) = tones[k];
            // Eq 27-21: lower half unchanged, alternating upper-half sign,
            // except MCS0+DCM where Gamma is one everywhere.
            (
                v.scale(if k >= 26 && k % 2 == 1 && !(self.bits == 1 && self.dcm) {
                    -1.
                } else {
                    1.
                }),
                w,
            )
        });
        let count = self.coded_per_symbol();
        let mut interleaved = Vec::with_capacity(count);
        if self.dcm {
            for k in 0..26 {
                let metrics =
                    demap_dcm_for_half([corrected[k], corrected[k + 26]], self.bits, k, 26)?;
                interleaved.extend_from_slice(&metrics[..self.bits]);
            }
        } else {
            let width = (self.bits / 2).max(1);
            let scale = match self.bits {
                1 => 1f32,
                2 => 2.,
                4 => 10.,
                6 => 42.,
                _ => return None,
            }
            .sqrt();
            for (v, w) in corrected {
                demap(v.i, width, scale, w, &mut interleaved);
                if self.bits != 1 {
                    demap(v.q, width, scale, w, &mut interleaved);
                }
            }
        }
        if interleaved.iter().any(|m| !m.is_finite()) {
            return None;
        }
        let s = (self.bits / 2).max(1);
        Some(
            (0..count)
                .map(|k| {
                    // 13 columns, 4*NBPSCS rows (2*NBPSCS with DCM).
                    let i = (count / 13) * (k % 13) + k / 13;
                    let j = s * (i / s) + (i + count - 13 * i / count) % s;
                    interleaved[j]
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::radio::{
        he_sig_b_coded::{Blocks, Error},
        HeSigBCommon20Fields, HeSigBUserBlock, HeSigBUserContext,
    };

    #[test]
    fn radio_he_sig_b_modulation_independent_streams() {
        let rows = include_str!("../../tests/fixtures/iq/he-sig-b-modulation.tsv");
        assert_eq!(rows.lines().skip(1).count(), 1564);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let mcs = c[0].parse().unwrap();
            let mode = Modulation::new(mcs, c[1] == "1").unwrap();
            let energy: f32 = match mode.bits {
                1 => 1.,
                2 => 2.,
                4 => 10.,
                _ => 42.,
            };
            let points: Vec<_> = c[8]
                .split(';')
                .enumerate()
                .map(|(n, s)| {
                    let (i, q) = s.split_once(',').unwrap();
                    let value = ComplexSample {
                        i: i.parse::<f32>().unwrap() / energy.sqrt(),
                        q: q.parse::<f32>().unwrap() / energy.sqrt(),
                    };
                    let k = n % 52;
                    let weight = match c[5] {
                        "lower" if k >= 26 => 0.,
                        "upper" if k < 26 => 0.,
                        _ => 0.5 + (k % 4) as f32 / 2.,
                    };
                    (value, weight)
                })
                .collect();
            assert_eq!(points.len() % 52, 0);
            let metrics: Vec<_> = points
                .chunks_exact(52)
                .flat_map(|symbol| mode.decode(symbol).unwrap())
                .collect();
            assert_eq!(metrics.len(), c[7].len());
            for (i, (m, b)) in metrics.iter().zip(c[7].bytes()).enumerate() {
                assert_eq!(
                    u8::from(*m > 0.),
                    b - b'0',
                    "MCS {mcs} DCM {} bit {i}",
                    c[1]
                );
            }
            if c[6] == "-" {
                continue;
            }
            let mut decoder = Blocks::new(&metrics, mcs).unwrap();
            for (i, bits) in c[6].split(';').enumerate() {
                let bits: Vec<_> = bits.bytes().map(|b| b - b'0').collect();
                if i == 0 && c[2] == "1" {
                    assert_eq!(
                        decoder.common(),
                        HeSigBCommon20Fields::decode(&bits).map_err(Error::Header)
                    );
                } else {
                    let contexts = vec![HeSigBUserContext::NonMu; (bits.len() - 10) / 21];
                    assert_eq!(
                        decoder.users(&contexts),
                        HeSigBUserBlock::decode(&bits, &contexts).map_err(Error::Header)
                    );
                }
            }
            assert!(decoder.consumed() < metrics.len());
        }
    }

    #[test]
    fn radio_he_sig_b_modulation_bounds() {
        let points = [(ComplexSample::ZERO, 1.); 52];
        for mcs in 0..=255 {
            for dcm in [false, true] {
                let mode = Modulation::new(mcs, dcm);
                assert_eq!(
                    mode.is_some(),
                    mcs <= 5 && (!dcm || matches!(mcs, 0 | 1 | 3 | 4))
                );
                let Some(mode) = mode else {
                    continue;
                };
                for length in [0, 26, 51, 53, 104] {
                    assert!(mode.decode(&vec![points[0]; length]).is_none());
                }
                assert_eq!(
                    mode.decode(&[(ComplexSample::ZERO, 0.); 52]).unwrap(),
                    vec![0.; mode.coded_per_symbol()]
                );
                for k in [0, 25, 26, 51] {
                    for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
                        for field in 0..3 {
                            let mut bad = points;
                            match field {
                                0 => bad[k].0.i = value,
                                1 => bad[k].0.q = value,
                                _ => bad[k].1 = value,
                            };
                            assert!(mode.decode(&bad).is_none());
                        }
                    }
                    let mut bad = points;
                    bad[k].1 = -1.;
                    assert!(mode.decode(&bad).is_none());
                    bad = points;
                    bad[k].0.i = f32::MAX;
                    assert!(mode.decode(&bad).is_none());
                }
            }
        }
    }
}
