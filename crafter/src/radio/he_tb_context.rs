//! Bounded candidate context, not authenticated BSS or exact SIFS association.
use super::{he_tb_schedule::Schedule, RecoveredFrame};
use crate::{Dot11, Dot11Trigger, Dot11TriggerCommonFields, LinkType, Packet};

#[derive(Clone)]
pub(super) struct Context {
    pub common: Dot11TriggerCommonFields,
    pub schedule: Schedule,
    pub trigger_start: u64,
    packet_end: u64,
    expires: u64,
    color: Option<u8>,
}

impl Context {
    /// Caller supplies true PPDU end (including PE, excluding signal extension)
    /// and has excluded prohibited triggering carriers under ax26.5.2.2.1.
    pub fn from_frame(frame: &RecoveredFrame, packet_end: u64, color: Option<u8>) -> Option<Self> {
        if frame.bytes.first().copied()? != 0x24 || !super::data::valid_fcs(&frame.bytes) {
            return None;
        }
        let packet = Packet::decode_from_link(
            LinkType::Ieee80211,
            frame.bytes.get(..frame.bytes.len().checked_sub(4)?)?,
        )
        .ok()?;
        let duration = packet.layer::<Dot11>()?.duration_id_value()?;
        // Table9-9: bit15 set is not a duration. Zero provides no search window.
        if duration == 0 || duration >= 32768 || packet_end < frame.end_sample_index {
            return None;
        }
        let trigger = packet.layer::<Dot11Trigger>()?;
        let schedule = Schedule::from_trigger(trigger).ok()?;
        if !schedule.allocations().any(|a| a.eligible) {
            return None;
        }
        // Duration protects subsequent exchange time (ax9.2.5.2). Use it only
        // as a capture search horizon; propagation and acquisition uncertainty
        // prevent treating transmitter ±0.4us as an exact observer window.
        let extension =
            if (2_400_000_000..2_500_000_000).contains(&frame.config.center_frequency_hz) {
                120
            } else {
                0
            };
        let expires = packet_end
            .checked_add(extension)?
            .checked_add(u64::from(duration) * 20)?;
        Some(Self {
            common: trigger.common,
            schedule,
            trigger_start: frame.start.sample_index,
            packet_end,
            expires,
            color,
        })
    }

    pub fn matches(&self, start: u64, signal: &super::he_tb::TbSignal) -> bool {
        start > self.packet_end
            && start < self.expires
            && self.color.map_or(true, |color| color == signal.bss_color)
    }
    pub fn expired(&self, at: u64) -> bool {
        at >= self.expires
    }
}
