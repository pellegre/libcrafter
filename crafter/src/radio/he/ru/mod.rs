//! HE20 tone geometry, IEEE 802.11ax-2021 Tables 27-7 and 27-35..43.

pub(in crate::radio) mod symbol;

#[derive(Clone, Copy)]
pub(in crate::radio) struct Tones {
    size: u16,
    index: usize,
}

impl Tones {
    /// Normal Trigger User Info RU byte, Table9-29i. MU-RTS uses a different
    /// encoding and must be excluded by the caller. No RA range is expanded.
    pub fn from_trigger(bandwidth: u8, allocation: u8) -> Option<Self> {
        if bandwidth != 0 || allocation & 1 != 0 {
            return None;
        }
        let code = allocation >> 1;
        let (size, index) = match code {
            0..=8 => (26, usize::from(code) + 1),
            37..=40 => (52, usize::from(code) - 36),
            53..=54 => (106, usize::from(code) - 52),
            61 => (242, 1),
            _ => return None,
        };
        Self::ru(size, index)
    }

    /// Table 27-26 columns to Table 27-7 equal-size RU ordinals. User counts
    /// do not change geometry, including explicitly empty allocations.
    pub fn assignment(ru: &crate::radio::he::mu::sig_b::HeRu20Assignment) -> Option<Self> {
        let index = match (ru.tones, ru.first_slot) {
            (26, slot @ 1..=9) => usize::from(slot),
            (52, 1) | (106, 1) | (242, 1) => 1,
            (52, 3) | (106, 6) => 2,
            (52, 6) => 3,
            (52, 8) => 4,
            _ => return None,
        };
        Self::ru(ru.tones, index)
    }
    /// Bandwidth bits have allocation meaning only in independently verified ER.
    pub fn new(er: bool, bandwidth: u8) -> Option<Self> {
        if bandwidth > u8::from(er) {
            return None;
        }
        Self::ru(
            if er && bandwidth == 1 { 106 } else { 242 },
            if er && bandwidth == 1 { 2 } else { 1 },
        )
    }
    /// One-based RU index within its size, NOT the SIG-B first 26-tone slot.
    pub fn ru(size: u16, index: usize) -> Option<Self> {
        let count = match size {
            26 => 9,
            52 => 4,
            106 => 2,
            242 => 1,
            _ => return None,
        };
        (1..=count).contains(&index).then_some(Self { size, index })
    }
    pub fn pilots(self) -> &'static [i32] {
        match self.size {
            26 => &[
                [-116, -102],
                [-90, -76],
                [-62, -48],
                [-36, -22],
                [-10, 10],
                [22, 36],
                [48, 62],
                [76, 90],
                [102, 116],
            ][self.index - 1],
            52 => &[
                [-116, -102, -90, -76],
                [-62, -48, -36, -22],
                [22, 36, 48, 62],
                [76, 90, 102, 116],
            ][self.index - 1],
            106 => &[[-116, -90, -48, -22], [22, 48, 90, 116]][self.index - 1],
            _ => &[-116, -90, -48, -22, 22, 48, 90, 116],
        }
    }
    pub fn pilot_sign(self, symbol: usize, pilot: usize) -> f32 {
        let signs: &[f32] = match self.size {
            26 => &[1., -1.],
            52 | 106 => &[1., 1., 1., -1.],
            _ => &[1., 1., 1., -1., -1., 1., 1., 1.],
        };
        signs[(symbol % signs.len() + pilot % signs.len()) % signs.len()]
    }
    pub fn data(self) -> impl Iterator<Item = i32> {
        self.active().filter(move |k| !self.pilots().contains(k))
    }
    pub fn active(self) -> impl Iterator<Item = i32> {
        (-122..=122).filter(move |&k| self.contains(k))
    }
    pub fn contains(self, k: i32) -> bool {
        let (lo, hi) = match self.size {
            26 if self.index == 5 => return (-16..=-4).contains(&k) || (4..=16).contains(&k),
            26 => [
                (-121, -96),
                (-95, -70),
                (-68, -43),
                (-42, -17),
                (0, 0),
                (17, 42),
                (43, 68),
                (70, 95),
                (96, 121),
            ][self.index - 1],
            52 => [(-121, -70), (-68, -17), (17, 68), (70, 121)][self.index - 1],
            106 => [(-122, -17), (17, 122)][self.index - 1],
            _ => return (-122..=-2).contains(&k) || (2..=122).contains(&k),
        };
        (lo..=hi).contains(&k)
    }
    pub fn count(self) -> usize {
        usize::from(self.size) - self.pilots().len()
    }
    pub fn ldpc_tone(self, k: usize, dcm: bool) -> Option<usize> {
        let count = self.count() / (1 + usize::from(dcm));
        if k >= count {
            return None;
        }
        let distance = match (self.size, dcm) {
            (26, _) | (52, true) => 1,
            (52, false) | (106, true) => 3,
            (106, false) => 6,
            _ => 9,
        };
        let columns = count / distance;
        Some(distance * (k % columns) + k / columns)
    }
    /// One-stream BCC interleaving; additional spatial-stream rotation is not
    /// represented by this mapping and must not be inferred from RU geometry.
    pub fn bcc_bit(self, k: usize, bits: usize, dcm: bool) -> Option<usize> {
        if !matches!(bits, 1 | 2 | 4 | 6 | 8) {
            return None;
        }
        let count = self.count() / (1 + usize::from(dcm)) * bits;
        if k >= count {
            return None;
        }
        let columns = match self.size {
            26 => 8 / (1 + usize::from(dcm)),
            52 => 16 / (1 + usize::from(dcm)),
            106 => 17,
            _ => 26 / (1 + usize::from(dcm)),
        };
        let i = (count / columns) * (k % columns) + k / columns;
        let s = (bits / 2).max(1);
        Some(s * (i / s) + (i + count - columns * i / count) % s)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn radio_he_tb_trigger_ru_codepoints() {
        // Table9-29i, encoded bytes in increasing physical RU order by size.
        let entries = [
            (26, &[0u8, 2, 4, 6, 8, 10, 12, 14, 16][..]),
            (52, &[74, 76, 78, 80][..]),
            (106, &[106, 108][..]),
            (242, &[122][..]),
        ];
        for raw in 0..=255u8 {
            let expected = entries.iter().find_map(|(size, codes)| {
                codes
                    .iter()
                    .position(|&code| code == raw)
                    .map(|index| (*size, index + 1))
            });
            let actual = super::Tones::from_trigger(0, raw);
            assert_eq!(actual.is_some(), expected.is_some(), "{raw}");
            if let Some((size, index)) = expected {
                let reference = super::Tones::ru(size, index).unwrap();
                let actual = actual.unwrap();
                assert_eq!(
                    actual.active().collect::<Vec<_>>(),
                    reference.active().collect::<Vec<_>>()
                );
                assert_eq!(actual.pilots(), reference.pilots());
            }
            for bandwidth in [1, 2, 3, 255] {
                assert!(super::Tones::from_trigger(bandwidth, raw).is_none());
            }
        }
    }

    use super::Tones;
    #[test]
    fn radio_he_assignment_slot_bounds() {
        use crate::radio::he::mu::sig_b::HeRu20Assignment;
        for size in [0, 26, 52, 106, 242, 484, u16::MAX] {
            for slot in 0..=u8::MAX {
                let expected = match size {
                    26 => (1..=9).contains(&slot),
                    52 => [1, 3, 6, 8].contains(&slot),
                    106 => [1, 6].contains(&slot),
                    242 => slot == 1,
                    _ => false,
                };
                for users in [0, 1, 8] {
                    assert_eq!(
                        Tones::assignment(&HeRu20Assignment {
                            tones: size,
                            first_slot: slot,
                            users
                        })
                        .is_some(),
                        expected
                    );
                }
            }
        }
    }
    #[test]
    fn radio_he_mu_all_resource_units() {
        // Independent signed-tone masks, transcribed from Table 27-7. Pilots
        // are checked separately against Tables 27-37/39/41/42, not inferred
        // from the production RU constructor.
        type Case<'a> = (u16, usize, &'a [(i32, i32)], &'a [i32]);
        let cases: &[Case<'_>] = &[
            (26, 1, &[(-121, -96)], &[-116, -102]),
            (26, 2, &[(-95, -70)], &[-90, -76]),
            (26, 3, &[(-68, -43)], &[-62, -48]),
            (26, 4, &[(-42, -17)], &[-36, -22]),
            (26, 5, &[(-16, -4), (4, 16)], &[-10, 10]),
            (26, 6, &[(17, 42)], &[22, 36]),
            (26, 7, &[(43, 68)], &[48, 62]),
            (26, 8, &[(70, 95)], &[76, 90]),
            (26, 9, &[(96, 121)], &[102, 116]),
            (52, 1, &[(-121, -70)], &[-116, -102, -90, -76]),
            (52, 2, &[(-68, -17)], &[-62, -48, -36, -22]),
            (52, 3, &[(17, 68)], &[22, 36, 48, 62]),
            (52, 4, &[(70, 121)], &[76, 90, 102, 116]),
            (106, 1, &[(-122, -17)], &[-116, -90, -48, -22]),
            (106, 2, &[(17, 122)], &[22, 48, 90, 116]),
            (
                242,
                1,
                &[(-122, -2), (2, 122)],
                &[-116, -90, -48, -22, 22, 48, 90, 116],
            ),
        ];
        for &(size, index, ranges, pilots) in cases {
            let t = Tones::ru(size, index).unwrap();
            let active: Vec<_> = ranges.iter().flat_map(|&(a, b)| a..=b).collect();
            assert_eq!(t.active().collect::<Vec<_>>(), active);
            assert_eq!(active.len(), usize::from(size));
            assert_eq!(t.pilots(), pilots);
            for k in -256..=256 {
                assert_eq!(t.contains(k), active.contains(&k));
            }
            assert!(!t.contains(i32::MIN));
            assert!(!t.contains(i32::MAX));
            let data: Vec<_> = active.into_iter().filter(|k| !pilots.contains(k)).collect();
            assert_eq!(t.data().collect::<Vec<_>>(), data);
            assert_eq!(t.count(), data.len());
            let signs: &[f32] = match size {
                26 => &[1., -1.],
                242 => &[1., 1., 1., -1., -1., 1., 1., 1.],
                _ => &[1., 1., 1., -1.],
            };
            for n in 0..32 {
                for p in 0..pilots.len() {
                    assert_eq!(t.pilot_sign(n, p), signs[(n + p) % signs.len()]);
                }
            }
            for dcm in [false, true] {
                let count = data.len() / if dcm { 2 } else { 1 };
                let distance = match (size, dcm) {
                    (26, _) | (52, true) => 1,
                    (52, false) | (106, true) => 3,
                    (106, false) => 6,
                    _ => 9,
                };
                let expected: Vec<_> = (0..distance)
                    .flat_map(|r| (0..count / distance).map(move |c| c * distance + r))
                    .collect();
                assert_eq!(
                    (0..count)
                        .map(|k| t.ldpc_tone(k, dcm).unwrap())
                        .collect::<Vec<_>>(),
                    expected
                );
                assert!(t.ldpc_tone(count, dcm).is_none());
                for bits in [1, 2, 4, 6, 8] {
                    // Independent matrix traversal plus per-column rotations
                    // (Table 27-35), checking exact order, not just bijection.
                    let columns = match (size, dcm) {
                        (26, false) => 8,
                        (26, true) => 4,
                        (52, false) => 16,
                        (52, true) => 8,
                        (106, _) => 17,
                        (242, false) => 26,
                        _ => 13,
                    };
                    let rows = count * bits / columns;
                    let group = (bits / 2).max(1);
                    for column in 0..columns {
                        for row in 0..rows {
                            let position = column * rows + row;
                            let base = position / group * group;
                            let rotated = (position % group + group - column % group) % group;
                            assert_eq!(
                                t.bcc_bit(row * columns + column, bits, dcm),
                                Some(base + rotated)
                            );
                        }
                    }
                    let mut mapped: Vec<_> = (0..count * bits)
                        .map(|k| t.bcc_bit(k, bits, dcm).unwrap())
                        .collect();
                    mapped.sort_unstable();
                    assert_eq!(mapped, (0..count * bits).collect::<Vec<_>>());
                    assert!(t.bcc_bit(count * bits, bits, dcm).is_none());
                }
            }
        }
        for (size, max) in [(26, 9), (52, 4), (106, 2), (242, 1)] {
            for index in [0, max + 1, usize::MAX] {
                assert!(Tones::ru(size, index).is_none());
            }
        }
        for size in [0, 25, 53, 105, 243, 484, u16::MAX] {
            assert!(Tones::ru(size, 1).is_none());
        }
    }
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
