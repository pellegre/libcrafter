//! HE20 Trigger allocation geometry, ax-2021 9.3.1.22.1 and26.5.4.2.
//! No exchange association, spatial separation or DATA integrity is inferred.
use super::he_tones::Tones;
use crate::{Dot11Trigger, Dot11TriggerRemainder, Dot11TriggerUserFields};

// Explicit receiver resource bound, not a general MAC parser restriction.
const MAX_ALLOCATIONS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    Unsupported,
    Opaque,
    Limit,
    Ru,
}

#[derive(Clone, Copy)]
pub(super) struct Allocation {
    pub user_index: usize,
    /// Original fields, except the RU byte selects this particular RA-RU.
    pub fields: Dot11TriggerUserFields,
    pub eligible: bool,
    tones: Tones,
}

#[derive(Clone)]
pub(super) struct Schedule {
    allocations: [Option<Allocation>; MAX_ALLOCATIONS],
    len: usize,
}

impl Schedule {
    pub fn from_trigger(trigger: &Dot11Trigger) -> Result<Self, Error> {
        if trigger.common.bandwidth != 0 || !matches!(trigger.common.trigger_type, 0..=2 | 4..=6) {
            return Err(Error::Unsupported);
        }
        // An undecidable trailing User Info can overlap an earlier allocation.
        if matches!(trigger.remainder, Dot11TriggerRemainder::Opaque(_)) {
            return Err(Error::Opaque);
        }
        if trigger.users.len() > MAX_ALLOCATIONS {
            return Err(Error::Limit);
        }
        let mut result = Self {
            allocations: [None; MAX_ALLOCATIONS],
            len: 0,
        };
        for (user_index, user) in trigger.users.iter().enumerate() {
            let fields = user.fields;
            if !matches!(fields.aid12, 0..=2007 | 2045 | 2046) {
                return Err(Error::Unsupported);
            }
            let first = Tones::from_trigger(0, fields.ru_allocation).ok_or(Error::Ru)?;
            let random = matches!(fields.aid12, 0 | 2045);
            let count = if random {
                usize::from(fields.spatial_allocation & 31) + 1
            } else {
                1
            };
            for offset in 0..count {
                let code = fields
                    .ru_allocation
                    .checked_add((2 * offset) as u8)
                    .ok_or(Error::Ru)?;
                let tones = Tones::from_trigger(0, code).ok_or(Error::Ru)?;
                if tones.count() != first.count() {
                    return Err(Error::Ru);
                }
                if result.len == MAX_ALLOCATIONS {
                    return Err(Error::Limit);
                }
                result.allocations[result.len] = Some(Allocation {
                    user_index,
                    fields: Dot11TriggerUserFields {
                        ru_allocation: code,
                        ..fields
                    },
                    eligible: fields.aid12 != 2046 && (random || fields.spatial_allocation == 0),
                    tones,
                });
                result.len += 1;
            }
        }
        // Count every allocation, including unsupported spatial entries and
        // explicitly unallocated RUs. Never admit just the first spatial user
        // of a shared RU, or silently discard evidence of an overlap.
        for i in 0..result.len {
            for j in 0..i {
                let a = result.allocations[i].unwrap();
                let b = result.allocations[j].unwrap();
                if a.tones.active().any(|k| b.tones.contains(k)) {
                    result.allocations[i].as_mut().unwrap().eligible = false;
                    result.allocations[j].as_mut().unwrap().eligible = false;
                }
            }
        }
        Ok(result)
    }

    pub fn allocations(&self) -> impl Iterator<Item = &Allocation> {
        self.allocations[..self.len].iter().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Dot11TriggerUser;
    fn trigger(users: &[(u16, u8, u8)]) -> Dot11Trigger {
        users.iter().fold(
            Dot11Trigger::new(),
            |t, &(aid12, ru_allocation, spatial_allocation)| {
                t.user(Dot11TriggerUser {
                    fields: Dot11TriggerUserFields {
                        aid12,
                        ru_allocation,
                        spatial_allocation,
                        ..Default::default()
                    },
                    dependent: vec![0],
                })
            },
        )
    }

    #[test]
    fn radio_he_tb_schedule_independent_geometry() {
        let rows = include_str!("../../tests/fixtures/iq/he-tb-schedule.tsv");
        let mut count = 0;
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let number = |i: usize| c[i].parse::<u16>().unwrap();
            if c[0] == "ra" {
                let fields = (
                    number(1),
                    number(2) as u8,
                    (number(3) - 1) as u8 | ((number(4) as u8) << 5),
                );
                let value = Schedule::from_trigger(&trigger(&[fields]));
                if c[5] == "invalid" {
                    assert!(value.is_err(), "{row}");
                } else {
                    let value = value.unwrap();
                    let expected: Vec<u8> = c[5].split(',').map(|s| s.parse().unwrap()).collect();
                    assert_eq!(
                        value
                            .allocations()
                            .map(|a| a.fields.ru_allocation)
                            .collect::<Vec<_>>(),
                        expected,
                        "{row}"
                    );
                    assert!(value.allocations().all(|a| a.eligible
                        && a.user_index == 0
                        && a.fields.aid12 == fields.0
                        && a.fields.spatial_allocation == fields.2));
                }
            } else {
                let value = Schedule::from_trigger(&trigger(&[
                    (1, number(1) as u8, 0),
                    (2, number(2) as u8, 0),
                ]))
                .unwrap();
                assert!(
                    value.allocations().all(|a| a.eligible == (c[5] == "0")),
                    "{row}"
                );
            }
            count += 1;
        }
        assert_eq!(count, 2304);
    }

    #[test]
    fn radio_he_tb_schedule_from_decoded_packet() {
        use crate::{Dot11, Dot11ControlSubtype, LinkType, Packet};
        let packet =
            Dot11::control(Dot11ControlSubtype::Trigger) / trigger(&[(0, 0, 1), (7, 4, 0)]);
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_link(LinkType::Ieee80211, &bytes).unwrap();
        let schedule = Schedule::from_trigger(decoded.layer::<Dot11Trigger>().unwrap()).unwrap();
        assert_eq!(
            schedule
                .allocations()
                .map(|a| (a.user_index, a.fields.ru_allocation, a.eligible))
                .collect::<Vec<_>>(),
            vec![(0, 0, true), (0, 2, true), (1, 4, true)]
        );
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn radio_he_tb_schedule_spatial_opaque_and_bounds() {
        let value =
            Schedule::from_trigger(&trigger(&[(1, 0, 0), (2, 0, 1), (3, 2, 0), (2046, 4, 0)]))
                .unwrap();
        assert_eq!(
            value
                .allocations()
                .map(|a| (a.user_index, a.eligible))
                .collect::<Vec<_>>(),
            vec![(0, false), (1, false), (2, true), (3, false)]
        );
        let value = Schedule::from_trigger(&trigger(&[(1, 0, 8), (2, 2, 0)])).unwrap();
        assert_eq!(
            value.allocations().map(|a| a.eligible).collect::<Vec<_>>(),
            vec![false, true]
        );
        let mut t = trigger(&[(1, 0, 0)]);
        t.remainder = Dot11TriggerRemainder::Opaque(vec![0]);
        assert!(matches!(Schedule::from_trigger(&t), Err(Error::Opaque)));
        t.remainder = Dot11TriggerRemainder::Padding(vec![255, 255]);
        assert!(Schedule::from_trigger(&t).is_ok());
        for kind in [3, 7, 15] {
            t.common.trigger_type = kind;
            assert!(matches!(
                Schedule::from_trigger(&t),
                Err(Error::Unsupported)
            ));
        }
        assert!(matches!(
            Schedule::from_trigger(&trigger(&[(2008, 0, 0)])),
            Err(Error::Unsupported)
        ));
        assert!(matches!(
            Schedule::from_trigger(&trigger(&[(1, 0, 0); 17])),
            Err(Error::Limit)
        ));
        assert!(matches!(
            Schedule::from_trigger(&trigger(&[(0, 0, 8), (2045, 0, 8)])),
            Err(Error::Limit)
        ));
        let mut wide = trigger(&[(1, 0, 0)]);
        wide.common.bandwidth = 1;
        assert!(matches!(
            Schedule::from_trigger(&wide),
            Err(Error::Unsupported)
        ));
    }
}
