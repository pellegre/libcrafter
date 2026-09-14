//! Bounded EHT Trigger exchange context.

use super::schedule::{Error as ScheduleError, Schedule};
use crate::protocols::link::{Dot11EhtTrigger, Dot11Trigger};
use crate::radio::{data::valid_fcs, eht::iq::Prefix, RecoveredFrame};
use crate::{Dot11, LinkType, Packet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    Frame,
    Duration,
    Trigger,
    Schedule(ScheduleError),
}

#[derive(Debug, Clone)]
pub(in crate::radio) struct Context {
    pub trigger: Dot11EhtTrigger,
    pub schedule: Schedule,
    pub trigger_start: u64,
    packet_end: u64,
    expires: u64,
}

impl Context {
    pub fn from_frame(frame: &RecoveredFrame, packet_end: u64) -> Result<Self, Error> {
        if !valid_fcs(&frame.bytes) || packet_end < frame.end_sample_index {
            return Err(Error::Frame);
        }
        let packet = Packet::decode_from_link(
            LinkType::Ieee80211,
            frame
                .bytes
                .get(..frame.bytes.len().checked_sub(4).ok_or(Error::Frame)?)
                .ok_or(Error::Frame)?,
        )
        .map_err(|_| Error::Frame)?;
        let duration = packet
            .layer::<Dot11>()
            .and_then(Dot11::duration_id_value)
            .filter(|duration| *duration > 0 && *duration < 32768)
            .ok_or(Error::Duration)?;
        let trigger = packet
            .layer::<Dot11Trigger>()
            .ok_or(Error::Trigger)?
            .eht()
            .map_err(|_| Error::Trigger)?;
        let schedule = Schedule::from_trigger(&trigger).map_err(Error::Schedule)?;
        let signal_extension =
            if (2_400_000_000..2_500_000_000).contains(&frame.config.center_frequency_hz) {
                120
            } else {
                0
            };
        let expires = packet_end
            .checked_add(signal_extension)
            .and_then(|end| end.checked_add(u64::from(duration) * 20))
            .ok_or(Error::Duration)?;
        Ok(Self {
            trigger,
            schedule,
            trigger_start: frame.start.sample_index,
            packet_end,
            expires,
        })
    }

    pub fn matches(&self, start: u64, prefix: &Prefix) -> bool {
        start > self.packet_end
            && start < self.expires
            && prefix.legacy_length == usize::from(self.trigger.common.ul_length)
            && prefix.fields.bandwidth_code == 0
            && prefix.fields.uplink
            && matches!(
                prefix.fields.format,
                crate::radio::eht::EhtUsigFormat::TriggerBased(fields)
                    if fields.spatial_reuse
                        == [
                            self.trigger.special.fields.spatial_reuse_1,
                            self.trigger.special.fields.spatial_reuse_2,
                        ]
            )
    }

    pub fn expired(&self, at: u64) -> bool {
        at >= self.expires
    }
}
