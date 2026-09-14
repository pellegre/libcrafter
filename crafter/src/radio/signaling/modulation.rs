//! Equalized 52-tone HE-SIG-B and EHT-SIG constellation recovery.

use crate::radio::{
    data::{demap, demap_dcm_for_half},
    ComplexSample,
};

/// Modulation, DCM combining, PAPR-rotation removal and BCC deinterleaving for
/// a 52-data-tone OFDM signaling symbol.
#[derive(Debug, Clone, Copy)]
pub(in crate::radio) struct Modulation {
    bits: usize,
    dcm: bool,
}

impl Modulation {
    pub(in crate::radio) fn new(mcs: u8, dcm: bool) -> Option<Self> {
        if mcs > 5 || (dcm && !matches!(mcs, 0 | 1 | 3 | 4)) {
            return None;
        }
        Some(Self {
            bits: [1, 2, 2, 4, 4, 6][mcs as usize],
            dcm,
        })
    }

    #[cfg(test)]
    pub(in crate::radio) const fn bits_per_subcarrier(self) -> usize {
        self.bits
    }

    pub(in crate::radio) const fn coded_per_symbol(self) -> usize {
        52 * self.bits / (1 + self.dcm as usize)
    }

    /// Values are constellation-normalized and pilot/channel-corrected, with
    /// nonnegative reliability weights. Returns deinterleaved BCC metrics.
    /// Zero-weight/erased tones are allowed; no header or MAC integrity claim.
    pub(in crate::radio) fn decode(self, tones: &[(ComplexSample, f32)]) -> Option<Vec<f32>> {
        if tones.len() != 52
            || tones.iter().any(|(value, weight)| {
                !value.power().is_finite() || !weight.is_finite() || *weight < 0.
            })
        {
            return None;
        }
        let corrected: [(ComplexSample, f32); 52] = std::array::from_fn(|index| {
            let (value, weight) = tones[index];
            // The upper-half alternating rotation is omitted for MCS0+DCM.
            (
                value.scale(
                    if index >= 26 && index % 2 == 1 && !(self.bits == 1 && self.dcm) {
                        -1.
                    } else {
                        1.
                    },
                ),
                weight,
            )
        });
        let count = self.coded_per_symbol();
        let mut interleaved = Vec::with_capacity(count);
        if self.dcm {
            for index in 0..26 {
                let metrics = demap_dcm_for_half(
                    [corrected[index], corrected[index + 26]],
                    self.bits,
                    index,
                    26,
                )?;
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
            for (value, weight) in corrected {
                demap(value.i, width, scale, weight, &mut interleaved);
                if self.bits != 1 {
                    demap(value.q, width, scale, weight, &mut interleaved);
                }
            }
        }
        if interleaved.iter().any(|metric| !metric.is_finite()) {
            return None;
        }
        let group = (self.bits / 2).max(1);
        Some(
            (0..count)
                .map(|index| {
                    // 13 columns, 4*NBPSCS rows (2*NBPSCS with DCM).
                    let first = (count / 13) * (index % 13) + index / 13;
                    let second =
                        group * (first / group) + (first + count - 13 * first / count) % group;
                    interleaved[second]
                })
                .collect(),
        )
    }
}
