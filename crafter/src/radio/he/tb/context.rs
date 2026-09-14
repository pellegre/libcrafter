//! Bounded candidate context, not authenticated BSS or exact SIFS association.
use super::schedule::{self, Schedule};
use crate::radio::RecoveredFrame;
use crate::{Dot11, Dot11Trigger, Dot11TriggerCommonFields, Dot11TrsControl, LinkType, Packet};

#[derive(Clone, Copy)]
pub(in crate::radio) struct Carrier {
    packet_end: u64,
    color: Option<u8>,
    he_response: Option<HeResponse>,
    combines_aggregates: bool,
}

#[derive(Clone, Copy)]
struct HeResponse {
    dcm: bool,
    gi_ltf: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum MergeError {
    Carrier,
    Common,
    Schedule(schedule::Error),
}

impl Carrier {
    pub fn legacy(packet_end: u64) -> Self {
        Self {
            packet_end,
            color: None,
            he_response: None,
            combines_aggregates: false,
        }
    }

    pub fn he(packet_end: u64, color: u8, dcm: bool, ltf_size: u8, guard_ns: u16) -> Option<Self> {
        Self::he_with_scope(packet_end, color, dcm, ltf_size, guard_ns, false)
    }

    pub fn he_mu(
        packet_end: u64,
        color: u8,
        dcm: bool,
        ltf_size: u8,
        guard_ns: u16,
    ) -> Option<Self> {
        Self::he_with_scope(packet_end, color, dcm, ltf_size, guard_ns, true)
    }

    fn he_with_scope(
        packet_end: u64,
        color: u8,
        dcm: bool,
        ltf_size: u8,
        guard_ns: u16,
        combines_aggregates: bool,
    ) -> Option<Self> {
        let gi_ltf = match (ltf_size, guard_ns) {
            (4, 3200) | (2, 1600) => 2,
            (1 | 2 | 4, 800) => 1,
            _ => return None,
        };
        Some(Self {
            packet_end,
            color: Some(color),
            he_response: Some(HeResponse { dcm, gi_ltf }),
            combines_aggregates,
        })
    }

    pub fn packet_end(self) -> u64 {
        self.packet_end
    }
}

#[derive(Clone)]
pub(in crate::radio) struct Context {
    pub common: Dot11TriggerCommonFields,
    pub schedule: Schedule,
    pub trigger_start: u64,
    packet_end: u64,
    expires: u64,
    color: Option<u8>,
    trs: Option<Dot11TrsControl>,
    combines_aggregates: bool,
}

impl Context {
    /// Caller supplies true PPDU end (including PE, excluding signal extension)
    /// and has excluded prohibited triggering carriers under ax26.5.2.2.1.
    pub fn from_frame(frame: &RecoveredFrame, carrier: Carrier) -> Option<Self> {
        if !crate::radio::data::valid_fcs(&frame.bytes) {
            return None;
        }
        let packet = Packet::decode_from_link(
            LinkType::Ieee80211,
            frame.bytes.get(..frame.bytes.len().checked_sub(4)?)?,
        )
        .ok()?;
        let duration = packet.layer::<Dot11>()?.duration_id_value()?;
        // Table9-9: bit15 set is not a duration. Zero provides no search window.
        if duration == 0 || duration >= 32768 || carrier.packet_end < frame.end_sample_index {
            return None;
        }
        let dot11 = packet.layer::<Dot11>()?;
        let (common, schedule, trs) = if frame.bytes.first().copied() == Some(0x24) {
            let trigger = packet.layer::<Dot11Trigger>()?;
            (trigger.common, Schedule::from_trigger(trigger).ok()?, None)
        } else {
            let response = carrier.he_response?;
            let control = dot11.trs_control()?;
            if dot11.receiver()?.is_multicast() {
                return None;
            }
            let common = Dot11TriggerCommonFields {
                trigger_type: 0,
                ul_length: 0,
                more_tf: false,
                cs_required: false,
                bandwidth: 0,
                gi_ltf: response.gi_ltf,
                masked_ltf: false,
                ltf_symbols_midamble: 0,
                stbc: false,
                ldpc_extra_segment: false,
                ap_tx_power: control.ap_tx_power(),
                pre_fec_padding_raw: 0,
                pe_disambiguity: false,
                spatial_reuse: u16::MAX,
                doppler: false,
                sig_a2_reserved: 511,
                reserved: false,
            };
            (
                common,
                Schedule::from_trs(control, response.dcm).ok()?,
                Some(control),
            )
        };
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
        let expires = carrier
            .packet_end
            .checked_add(extension)?
            .checked_add(u64::from(duration) * 20)?;
        Some(Self {
            common,
            schedule,
            trigger_start: frame.start.sample_index,
            packet_end: carrier.packet_end,
            expires,
            color: carrier.color,
            trs,
            combines_aggregates: carrier.combines_aggregates,
        })
    }

    pub fn resolve(
        &self,
        start: u64,
        signal: &crate::radio::he::tb::TbSignal,
        legacy_length: usize,
    ) -> Option<Self> {
        if !self.matches(start, signal) {
            return None;
        }
        let Some(trs) = self.trs else {
            return Some(self.clone());
        };
        let mut resolved = None;
        for pe_disambiguity in [false, true] {
            let mut candidate = self.clone();
            candidate.common.ul_length = legacy_length.try_into().ok()?;
            candidate.common.pe_disambiguity = pe_disambiguity;
            let Ok(timing) = crate::radio::he::timing::Timing::for_tb(
                6_000_000,
                legacy_length,
                &candidate.common,
            ) else {
                continue;
            };
            if timing.data_symbols == usize::from(trs.ul_data_symbols()) {
                if resolved.is_some() {
                    return None;
                }
                resolved = Some(candidate);
            }
        }
        resolved
    }

    pub fn matches(&self, start: u64, signal: &crate::radio::he::tb::TbSignal) -> bool {
        start > self.packet_end
            && start < self.expires
            && self.color.map_or(true, |color| color == signal.bss_color)
    }

    pub fn same_carrier(&self, other: &Self) -> bool {
        self.combines_aggregates
            && other.combines_aggregates
            && self.trigger_start == other.trigger_start
            && self.packet_end == other.packet_end
            && self.color == other.color
    }

    pub fn merge(&mut self, other: &Self) -> Result<(), MergeError> {
        if !self.same_carrier(other) {
            return Err(MergeError::Carrier);
        }
        let normalize = |mut common: Dot11TriggerCommonFields| {
            common.trigger_type = 0;
            common.more_tf = false;
            common.cs_required = false;
            common
        };
        if normalize(self.common) != normalize(other.common) {
            return Err(MergeError::Common);
        }
        self.schedule
            .merge(&other.schedule)
            .map_err(MergeError::Schedule)
    }

    pub fn expired(&self, at: u64) -> bool {
        at >= self.expires
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_he_tb_trs_resolves_all_symbol_counts_and_packet_extensions() {
        let signal = crate::radio::he::tb::TbSignal {
            bss_color: 37,
            spatial_reuse: [15; 4],
            bandwidth: 0,
            txop: 0,
            trigger_reserved: 511,
        };
        for (gi_ltf, training, stride) in [(1, 160usize, 288usize), (2, 320, 320)] {
            for symbols in 1usize..=32 {
                for packet_extension in [0usize, 80, 160, 240, 320] {
                    let packet_end = 800 + training + symbols * stride + packet_extension;
                    let length = 3 * (packet_end - 400).div_ceil(80) - 5;
                    let trs = Dot11TrsControl::new()
                        .with_ul_data_symbols_raw((symbols - 1) as u8)
                        .with_ru_allocation(0)
                        .with_mcs(0);
                    let context = Context {
                        common: Dot11TriggerCommonFields {
                            gi_ltf,
                            spatial_reuse: u16::MAX,
                            sig_a2_reserved: 511,
                            pre_fec_padding_raw: 0,
                            ..Default::default()
                        },
                        schedule: Schedule::from_trs(trs, false).unwrap(),
                        trigger_start: 64,
                        packet_end: 100,
                        expires: 1000,
                        color: Some(37),
                        trs: Some(trs),
                        combines_aggregates: false,
                    };
                    let resolved = context.resolve(101, &signal, length).unwrap_or_else(|| {
                        panic!(
                            "gi_ltf={gi_ltf} symbols={symbols} packet_extension={packet_extension}"
                        )
                    });
                    assert_eq!(resolved.common.ul_length, length as u16);
                    assert_eq!(
                        crate::radio::he::timing::Timing::for_tb(
                            6_000_000,
                            length,
                            &resolved.common,
                        )
                        .unwrap()
                        .data_symbols,
                        symbols
                    );
                }
            }
        }
    }

    #[test]
    fn radio_he_tb_trs_context_rejects_wrong_exchange_identity() {
        let trs = Dot11TrsControl::new().with_ru_allocation(0);
        let context = Context {
            common: Dot11TriggerCommonFields::default(),
            schedule: Schedule::from_trs(trs, false).unwrap(),
            trigger_start: 64,
            packet_end: 100,
            expires: 1000,
            color: Some(37),
            trs: Some(trs),
            combines_aggregates: false,
        };
        let mut signal = crate::radio::he::tb::TbSignal {
            bss_color: 38,
            spatial_reuse: [15; 4],
            bandwidth: 0,
            txop: 0,
            trigger_reserved: 511,
        };
        assert!(context.resolve(101, &signal, 301).is_none());
        signal.bss_color = 37;
        assert!(context.resolve(100, &signal, 301).is_none());
        assert!(context.resolve(1000, &signal, 301).is_none());

        let mut first = context.clone();
        let mut second = context.clone();
        assert!(!first.same_carrier(&second));
        first.combines_aggregates = true;
        second.combines_aggregates = true;
        assert!(first.same_carrier(&second));
        second.common.ul_length ^= 1;
        assert_eq!(first.merge(&second), Err(MergeError::Common));
    }
}
