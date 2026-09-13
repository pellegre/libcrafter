//! HE20 SU/ER tone geometry, IEEE 802.11ax-2021 Tables 27-35/36/40/41.
#[derive(Clone, Copy)]
pub(super) struct Tones {
    upper106: bool,
}

impl Tones {
    /// Bandwidth bits have allocation meaning only in independently verified ER.
    pub fn new(er: bool, bandwidth: u8) -> Option<Self> {
        if bandwidth > u8::from(er) {
            return None;
        }
        Some(Self {
            upper106: er && bandwidth == 1,
        })
    }
    pub fn pilots(self) -> &'static [i32] {
        if self.upper106 {
            &[22, 48, 90, 116]
        } else {
            &[-116, -90, -48, -22, 22, 48, 90, 116]
        }
    }
    pub fn pilot_sign(self, symbol: usize, pilot: usize) -> f32 {
        let signs: &[f32] = if self.upper106 {
            &[1., 1., 1., -1.]
        } else {
            &[1., 1., 1., -1., -1., 1., 1., 1.]
        };
        signs[(symbol % signs.len() + pilot % signs.len()) % signs.len()]
    }
    pub fn data(self) -> impl Iterator<Item = i32> {
        (-122..=122).filter(move |&k| {
            (if self.upper106 {
                k >= 17
            } else {
                !(-1..=1).contains(&k)
            }) && !self.pilots().contains(&k)
        })
    }
    pub fn count(self) -> usize {
        if self.upper106 {
            102
        } else {
            234
        }
    }
    pub fn ldpc_tone(self, k: usize, dcm: bool) -> Option<usize> {
        let count = self.count() / (1 + usize::from(dcm));
        if k >= count {
            return None;
        }
        let distance = if self.upper106 {
            if dcm {
                3
            } else {
                6
            }
        } else {
            9
        };
        let columns = count / distance;
        Some(distance * (k % columns) + k / columns)
    }
    pub fn bcc_bit(self, k: usize, bits: usize, dcm: bool) -> Option<usize> {
        if !matches!(bits, 1 | 2 | 4 | 6 | 8) {
            return None;
        }
        let count = self.count() / (1 + usize::from(dcm)) * bits;
        if k >= count {
            return None;
        }
        let columns = if self.upper106 {
            17
        } else if dcm {
            13
        } else {
            26
        };
        let i = (count / columns) * (k % columns) + k / columns;
        let s = (bits / 2).max(1);
        Some(s * (i / s) + (i + count - columns * i / count) % s)
    }
}

#[cfg(test)]
mod tests {
    use super::Tones;
    #[test]
    fn radio_he_tone_geometry_and_permutations() {
        assert!(Tones::new(false, 1).is_none());
        assert!(Tones::new(true, 2).is_none());
        for upper in [false, true] {
            let tones = Tones::new(true, u8::from(upper)).unwrap();
            if upper {
                assert_eq!(tones.pilots(), &[22, 48, 90, 116]);
                for symbol in 0..16 {
                    for pilot in 0..4 {
                        assert_eq!(
                            tones.pilot_sign(symbol, pilot),
                            if (symbol + pilot) % 4 == 3 { -1. } else { 1. }
                        );
                    }
                }
            }
            let data: Vec<_> = tones.data().collect();
            assert_eq!(data.len(), tones.count());
            assert_eq!(data[0], if upper { 17 } else { -122 });
            assert_eq!(data.last(), Some(&122));
            for dcm in [false, true] {
                let count = tones.count() / (1 + usize::from(dcm));
                // Independent matrix traversal: columns of a row-major matrix
                // provide the transmitted order for logical column-major input.
                let rows = if upper {
                    if dcm {
                        3
                    } else {
                        6
                    }
                } else {
                    9
                };
                let expected: Vec<_> = (0..rows)
                    .flat_map(|r| (0..count / rows).map(move |c| c * rows + r))
                    .collect();
                assert_eq!(
                    (0..count)
                        .map(|k| tones.ldpc_tone(k, dcm).unwrap())
                        .collect::<Vec<_>>(),
                    expected
                );
                assert!(tones.ldpc_tone(count, dcm).is_none());
                for bits in [1, 2, 4, 6, 8] {
                    let mut mapped: Vec<_> = (0..count * bits)
                        .map(|k| tones.bcc_bit(k, bits, dcm).unwrap())
                        .collect();
                    mapped.sort_unstable();
                    assert_eq!(mapped, (0..count * bits).collect::<Vec<_>>());
                    assert!(tones.bcc_bit(count * bits, bits, dcm).is_none());
                }
                assert!(tones.bcc_bit(0, usize::MAX, dcm).is_none());
                assert!(tones.ldpc_tone(usize::MAX, dcm).is_none());
            }
        }
    }
}
