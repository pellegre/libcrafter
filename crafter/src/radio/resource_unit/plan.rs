use super::Tones;

#[derive(Clone, Copy)]
enum Kind {
    Ru(Tones),
    SmallMru { tones: u16 },
}

/// Owned frequency-order view of one RU or a supported small EHT MRU.
#[derive(Clone)]
pub(in crate::radio) struct TonePlan {
    kind: Kind,
    data: Vec<i32>,
    pilots: Vec<i32>,
}

impl TonePlan {
    pub fn ru(tones: Tones) -> Self {
        Self {
            kind: Kind::Ru(tones),
            data: tones.data().collect(),
            pilots: tones.pilots().to_vec(),
        }
    }

    pub fn small_mru(first: Tones, second: Tones) -> Option<Self> {
        let tones = first.size().checked_add(second.size())?;
        if !matches!(
            (
                first.size().min(second.size()),
                first.size().max(second.size())
            ),
            (26, 52) | (26, 106)
        ) {
            return None;
        }
        let first_active: Vec<_> = first.active().collect();
        let second_active: Vec<_> = second.active().collect();
        if first_active.last()? >= second_active.first()?
            || first_active.iter().any(|tone| second.contains(*tone))
        {
            return None;
        }
        let mut data: Vec<_> = first.data().chain(second.data()).collect();
        let mut pilots: Vec<_> = first
            .pilots()
            .iter()
            .chain(second.pilots())
            .copied()
            .collect();
        data.sort_unstable();
        pilots.sort_unstable();
        if pilots.len() != 6
            || data.len().checked_add(pilots.len()) != Some(usize::from(tones))
            || data.windows(2).any(|pair| pair[0] >= pair[1])
            || pilots.windows(2).any(|pair| pair[0] >= pair[1])
            || data.iter().any(|tone| pilots.contains(tone))
        {
            return None;
        }
        Some(Self {
            kind: Kind::SmallMru { tones },
            data,
            pilots,
        })
    }

    pub fn pilots(&self) -> &[i32] {
        &self.pilots
    }

    pub fn pilot_sign(&self, symbol: usize, pilot: usize) -> f32 {
        match self.kind {
            Kind::Ru(tones) => tones.pilot_sign(symbol, pilot),
            Kind::SmallMru { .. } => {
                const SIGNS: [f32; 6] = [1., 1., 1., -1., -1., 1.];
                SIGNS[(symbol % SIGNS.len() + pilot % SIGNS.len()) % SIGNS.len()]
            }
        }
    }

    pub fn data(&self) -> impl Iterator<Item = i32> + '_ {
        self.data.iter().copied()
    }

    pub fn count(&self) -> usize {
        self.data.len()
    }

    pub fn ldpc_tone(&self, index: usize, dcm: bool) -> Option<usize> {
        let Kind::SmallMru { tones } = self.kind else {
            let Kind::Ru(tones) = self.kind else {
                unreachable!()
            };
            return tones.ldpc_tone(index, dcm);
        };
        let count = self.count() / (1 + usize::from(dcm));
        if index >= count {
            return None;
        }
        let distance = match (tones, dcm) {
            (78, false) => 4,
            (78, true) => 3,
            (132, false) => 6,
            (132, true) => 3,
            _ => return None,
        };
        let columns = count.checked_div(distance)?;
        (columns * distance == count).then_some(distance * (index % columns) + index / columns)
    }

    pub fn bcc_bit(&self, index: usize, bits: usize, dcm: bool) -> Option<usize> {
        let Kind::SmallMru { tones } = self.kind else {
            let Kind::Ru(tones) = self.kind else {
                unreachable!()
            };
            return tones.bcc_bit(index, bits, dcm);
        };
        if !matches!(bits, 1 | 2 | 4 | 6 | 8) {
            return None;
        }
        let count = self.count() / (1 + usize::from(dcm)) * bits;
        if index >= count {
            return None;
        }
        let columns = match (tones, dcm) {
            (78, false) => 18,
            (78, true) => 12,
            (132, _) => 21,
            _ => return None,
        };
        if count % columns != 0 {
            return None;
        }
        let transposed = (count / columns) * (index % columns) + index / columns;
        let significance = (bits / 2).max(1);
        Some(
            significance * (transposed / significance)
                + (transposed + count - columns * transposed / count) % significance,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_eht_small_mru_joint_mappings() {
        let cases = [
            (
                TonePlan::small_mru(Tones::ru(26, 2).unwrap(), Tones::ru(52, 2).unwrap()).unwrap(),
                78,
            ),
            (
                TonePlan::small_mru(Tones::ru(106, 1).unwrap(), Tones::ru(26, 5).unwrap()).unwrap(),
                132,
            ),
        ];
        for (plan, size) in cases {
            assert_eq!(plan.count(), if size == 78 { 72 } else { 126 });
            assert_eq!(plan.pilots().len(), 6);
            for symbol in 0..18 {
                for pilot in 0..6 {
                    let signs = [1., 1., 1., -1., -1., 1.];
                    assert_eq!(plan.pilot_sign(symbol, pilot), signs[(symbol + pilot) % 6]);
                }
            }
            for dcm in [false, true] {
                let tone_count = plan.count() / (1 + usize::from(dcm));
                let distance = match (size, dcm) {
                    (78, false) => 4,
                    (78, true) => 3,
                    (132, false) => 6,
                    _ => 3,
                };
                let columns = tone_count / distance;
                let expected: Vec<_> = (0..tone_count)
                    .map(|index| distance * (index % columns) + index / columns)
                    .collect();
                assert_eq!(
                    (0..tone_count)
                        .map(|index| plan.ldpc_tone(index, dcm).unwrap())
                        .collect::<Vec<_>>(),
                    expected
                );
                assert!(plan.ldpc_tone(tone_count, dcm).is_none());
                for bits in [1, 2, 4, 6, 8] {
                    let bit_count = tone_count * bits;
                    let columns = match (size, dcm) {
                        (78, false) => 18,
                        (78, true) => 12,
                        _ => 21,
                    };
                    let rows = bit_count / columns;
                    let significance = (bits / 2).max(1);
                    for column in 0..columns {
                        for row in 0..rows {
                            let transposed = column * rows + row;
                            let base = transposed / significance * significance;
                            let rotated = (transposed % significance + significance
                                - column % significance)
                                % significance;
                            assert_eq!(
                                plan.bcc_bit(row * columns + column, bits, dcm),
                                Some(base + rotated)
                            );
                        }
                    }
                    assert!(plan.bcc_bit(bit_count, bits, dcm).is_none());
                }
            }
        }
    }

    #[test]
    fn radio_eht_small_mru_rejects_invalid_components() {
        assert!(
            TonePlan::small_mru(Tones::ru(26, 1).unwrap(), Tones::ru(26, 2).unwrap()).is_none()
        );
        assert!(
            TonePlan::small_mru(Tones::ru(52, 1).unwrap(), Tones::ru(26, 1).unwrap()).is_none()
        );
        assert!(
            TonePlan::small_mru(Tones::ru(242, 1).unwrap(), Tones::ru(26, 1).unwrap()).is_none()
        );
    }
}
