//! EHT20 Trigger allocation geometry.

use crate::protocols::link::{Dot11EhtTrigger, Dot11EhtTriggerUserFields, Dot11EhtTriggerUserInfo};
use crate::radio::eht::EhtResourceUnit;

const MAX_ALLOCATIONS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    Unsupported,
    Resource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) struct Allocation {
    pub user_index: usize,
    pub fields: Dot11EhtTriggerUserFields,
    pub resource: EhtResourceUnit,
    pub eligible: bool,
}

#[derive(Debug, Clone)]
pub(in crate::radio) struct Schedule {
    allocations: [Option<Allocation>; MAX_ALLOCATIONS],
    len: usize,
}

impl Schedule {
    pub fn from_trigger(trigger: &Dot11EhtTrigger) -> Result<Self, Error> {
        if trigger.common.bandwidth != 0
            || trigger.special.fields.bandwidth_extension != 0
            || !matches!(trigger.common.trigger_type, 0..=2 | 4..=6)
            || trigger.users.len() > MAX_ALLOCATIONS
        {
            return Err(Error::Unsupported);
        }
        let mut result = Self {
            allocations: [None; MAX_ALLOCATIONS],
            len: 0,
        };
        for (user_index, user) in trigger.users.iter().enumerate() {
            let Dot11EhtTriggerUserInfo::Eht(user) = user else {
                // A colocated HE user can occupy tones in this 20 MHz segment;
                // do not infer that an EHT allocation is isolated from it.
                return Err(Error::Unsupported);
            };
            let fields = user.fields;
            if !matches!(fields.aid12, 1..=2006 | 2046)
                || fields.reserved
                || fields.ps160
                || fields.mcs == 14
                || fields.mcs > 15
            {
                return Err(Error::Unsupported);
            }
            let resource =
                EhtResourceUnit::from_trigger_20(fields.ru_allocation).ok_or(Error::Resource)?;
            let stream_start = fields.spatial_allocation & 7;
            let stream_count = (fields.spatial_allocation >> 3) + 1;
            result.allocations[result.len] = Some(Allocation {
                user_index,
                fields,
                resource,
                eligible: fields.aid12 != 2046 && stream_start == 0 && stream_count == 1,
            });
            result.len += 1;
        }
        result.invalidate_overlaps();
        if !result.allocations().any(|allocation| allocation.eligible) {
            return Err(Error::Unsupported);
        }
        Ok(result)
    }

    pub fn allocations(&self) -> impl Iterator<Item = &Allocation> {
        self.allocations[..self.len].iter().flatten()
    }

    fn invalidate_overlaps(&mut self) {
        for i in 0..self.len {
            for j in 0..i {
                let a = self.allocations[i].unwrap();
                let b = self.allocations[j].unwrap();
                if (-128..=127)
                    .any(|tone| a.resource.contains_tone(tone) && b.resource.contains_tone(tone))
                {
                    self.allocations[i].as_mut().unwrap().eligible = false;
                    self.allocations[j].as_mut().unwrap().eligible = false;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::link::{
        Dot11EhtTriggerCommonFields, Dot11EhtTriggerSpecialUser, Dot11EhtTriggerSpecialUserFields,
        Dot11EhtTriggerUser,
    };

    fn trigger(users: &[(u16, u8, u8)]) -> Dot11EhtTrigger {
        users.iter().fold(
            Dot11EhtTrigger::new(
                Dot11EhtTriggerCommonFields::default(),
                Dot11EhtTriggerSpecialUser {
                    fields: Dot11EhtTriggerSpecialUserFields::default(),
                    dependent: vec![0],
                },
            ),
            |trigger, &(aid12, ru_allocation, spatial_allocation)| {
                trigger.user(Dot11EhtTriggerUser {
                    fields: Dot11EhtTriggerUserFields {
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
    fn radio_eht_tb_maps_every_valid_20_mhz_trigger_resource() {
        let rows = include_str!("../../../../tests/fixtures/iq/eht-tb-resource-index.tsv");
        assert_eq!(rows.lines().skip(1).count(), 256);
        for row in rows.lines().skip(1) {
            let columns: Vec<_> = row.split('\t').collect();
            let raw = columns[0].parse::<u8>().unwrap();
            let decoded = EhtResourceUnit::from_trigger_20(raw);
            if columns[1] == "unsupported" {
                assert!(decoded.is_none(), "{row}");
                continue;
            }
            let expected = columns[2]
                .split('+')
                .map(|component| {
                    let (size, index) = component.split_once(':').unwrap();
                    (size.parse::<u16>().unwrap(), index.parse::<u8>().unwrap())
                })
                .collect::<Vec<_>>();
            let resource = decoded.unwrap();
            assert_eq!(
                resource
                    .components()
                    .iter()
                    .map(|component| (component.tone_count(), component.index()))
                    .collect::<Vec<_>>(),
                expected,
                "{row}"
            );
            assert!(Schedule::from_trigger(&trigger(&[(1, raw, 0)])).is_ok());
        }
    }

    #[test]
    fn radio_eht_tb_admits_only_isolated_single_stream_users() {
        let schedule = Schedule::from_trigger(&trigger(&[
            (1, 0, 0),
            (2, 2, 8),
            (3, 4, 1),
            (2046, 6, 0),
            (4, 80, 0),
        ]))
        .unwrap();
        assert_eq!(
            schedule
                .allocations()
                .map(|allocation| allocation.eligible)
                .collect::<Vec<_>>(),
            vec![true, false, false, false, true]
        );
    }

    #[test]
    fn radio_eht_tb_excludes_overlapping_allocations() {
        let schedule =
            Schedule::from_trigger(&trigger(&[(1, 0, 0), (2, 74, 0), (3, 6, 0)])).unwrap();
        assert_eq!(
            schedule
                .allocations()
                .map(|allocation| allocation.eligible)
                .collect::<Vec<_>>(),
            vec![false, false, true]
        );
    }

    #[test]
    fn radio_eht_tb_capacity_uses_trigger_coding_and_padding() {
        let mut trigger = trigger(&[(1, 140, 0)]);
        trigger.common.pre_fec_padding_raw = 0;
        trigger.common.ldpc_extra_segment = false;
        let allocation = *Schedule::from_trigger(&trigger)
            .unwrap()
            .allocations()
            .next()
            .unwrap();
        let bcc = crate::radio::eht::data::Capacity::for_tb(
            &trigger.common,
            &allocation.fields,
            allocation.resource,
            10,
        )
        .unwrap();
        assert_eq!((bcc.coded_per_symbol, bcc.data_per_symbol), (72, 36));
        assert_eq!((bcc.coded_bits, bcc.data_bits), (720, 360));
        assert_eq!((bcc.psdu_bytes, bcc.phy_pad_bits), (42, 2));

        let mut fields = allocation.fields;
        fields.mcs = 13;
        fields.ldpc = true;
        let ldpc = crate::radio::eht::data::Capacity::for_tb(
            &trigger.common,
            &fields,
            allocation.resource,
            10,
        )
        .unwrap();
        assert_eq!((ldpc.coded_per_symbol, ldpc.data_per_symbol), (864, 720));
        assert_eq!((ldpc.psdu_bytes, ldpc.phy_pad_bits), (898, 0));
    }
}
