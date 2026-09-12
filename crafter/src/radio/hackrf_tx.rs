//! Explicit, bounded HackRF transmission of encoded legacy Wi-Fi IQ.

#[cfg(feature = "radio-hackrf")]
use super::{IqSink, LegacyWifiTransmission};
use super::{RadioError, RadioResult};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HackRfTxConfig {
    pub serial: String,
    pub center_frequency_hz: u64,
    pub sample_rate_hz: u32,
    pub baseband_filter_hz: u32,
    pub tx_vga_gain_db: u32,
    pub amplifier_enabled: bool,
    pub antenna_power_enabled: bool,
    pub max_duration: Duration,
    pub max_supplied_samples: u64,
    pub repetitions: u32,
    pub inter_burst_gap_samples: usize,
}

impl HackRfTxConfig {
    pub fn validate(&self) -> RadioResult<()> {
        if self.serial.is_empty() || self.serial.as_bytes().contains(&0) {
            return Err(RadioError::Invalid {
                field: "serial",
                reason: "explicit nonempty device serial required",
            });
        }
        if self.center_frequency_hz == 0
            || self.sample_rate_hz != 20_000_000
            || self.baseband_filter_hz == 0
        {
            return Err(RadioError::Invalid {
                field: "RF configuration",
                reason: "requires explicit frequency, 20 Msps, and nonzero filter",
            });
        }
        if self.tx_vga_gain_db > 47 {
            return Err(RadioError::Invalid {
                field: "tx_vga_gain_db",
                reason: "requires 0..47 dB",
            });
        }
        if self.max_duration.is_zero() || self.max_supplied_samples == 0 || self.repetitions == 0 {
            return Err(RadioError::Invalid {
                field: "transmit bounds",
                reason: "duration, samples, and repetitions must be nonzero",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HackRfTxStats {
    pub requested_samples: u64,
    pub supplied_samples: u64,
    pub padded_samples: u64,
    pub discarded_samples: u64,
    pub callbacks: u64,
    pub completed_repetitions: u32,
    pub firmware_shortfalls: u32,
    pub longest_shortfall: u32,
    pub stopped: bool,
    pub cancelled: bool,
}

struct PlanState {
    offset: usize,
    stats: HackRfTxStats,
    fault: Option<RadioError>,
    done: bool,
}

pub(super) struct TxShared {
    plan: Vec<u8>,
    repetitions: u32,
    max_samples: u64,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    state: Mutex<PlanState>,
}

impl TxShared {
    fn new(iq: &[i8], config: &HackRfTxConfig, cancelled: Arc<AtomicBool>) -> RadioResult<Self> {
        config.validate()?;
        if iq.is_empty() || iq.len() % 2 != 0 {
            return Err(RadioError::Invalid {
                field: "cs8",
                reason: "requires nonempty complete I/Q pairs",
            });
        }
        let samples = (iq.len() / 2) as u64;
        let requested = samples
            .checked_mul(u64::from(config.repetitions))
            .and_then(|n| {
                n.checked_add(
                    (config.inter_burst_gap_samples as u64)
                        .checked_mul(u64::from(config.repetitions - 1))?,
                )
            })
            .ok_or(RadioError::Overflow {
                context: "HackRF TX plan samples",
            })?;
        if requested > config.max_supplied_samples {
            return Err(RadioError::Limit {
                context: "HackRF TX supplied samples",
                limit: config.max_supplied_samples,
                actual: requested,
            });
        }
        let capacity = usize::try_from(requested)
            .ok()
            .and_then(|samples| samples.checked_mul(2))
            .ok_or(RadioError::Overflow {
                context: "HackRF TX plan bytes",
            })?;
        let mut plan = Vec::with_capacity(capacity);
        for repetition in 0..config.repetitions {
            plan.extend(iq.iter().map(|value| *value as u8));
            if repetition + 1 < config.repetitions {
                plan.resize(plan.len() + config.inter_burst_gap_samples * 2, 0);
            }
        }
        Ok(Self {
            plan,
            repetitions: config.repetitions,
            max_samples: config.max_supplied_samples,
            deadline: Instant::now() + config.max_duration,
            cancelled,
            state: Mutex::new(PlanState {
                offset: 0,
                stats: HackRfTxStats {
                    requested_samples: requested,
                    ..Default::default()
                },
                fault: None,
                done: false,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, PlanState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(super) fn fill(&self, output: &mut [u8]) -> bool {
        let mut state = self.lock();
        if state.done {
            return false;
        }
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            state.stats.cancelled = self.cancelled.load(Ordering::Relaxed);
            state.fault = Some(RadioError::Source(
                if state.stats.cancelled {
                    "HackRF transmission cancelled"
                } else {
                    "HackRF transmission timed out"
                }
                .into(),
            ));
            state.done = true;
            return false;
        }
        if output.is_empty() || output.len() % 2 != 0 {
            state.fault = Some(RadioError::Source(
                "invalid HackRF TX transfer buffer".into(),
            ));
            state.done = true;
            return false;
        }
        state.stats.callbacks += 1;
        let cursor = (self.plan.len() - state.offset).min(output.len());
        output[..cursor].copy_from_slice(&self.plan[state.offset..state.offset + cursor]);
        state.offset += cursor;
        state.stats.supplied_samples += (cursor / 2) as u64;
        if state.stats.supplied_samples > self.max_samples {
            state.fault = Some(RadioError::Limit {
                context: "HackRF TX supplied samples",
                limit: self.max_samples,
                actual: state.stats.supplied_samples,
            });
            state.done = true;
            return false;
        }
        if cursor < output.len() {
            output[cursor..].fill(0);
            state.stats.padded_samples += ((output.len() - cursor) / 2) as u64;
        }
        if state.offset == self.plan.len() {
            state.stats.completed_repetitions = self.repetitions;
            state.done = true;
        }
        true
    }

    pub(super) fn done(&self) -> bool {
        self.lock().done
    }
    pub(super) fn fail(&self, error: RadioError) {
        let mut s = self.lock();
        s.fault = Some(error);
        s.done = true;
    }
    pub(super) fn finish(
        &self,
        shortfalls: (u32, u32),
        stopped: bool,
    ) -> RadioResult<HackRfTxStats> {
        let mut state = self.lock();
        state.stats.firmware_shortfalls = shortfalls.0;
        state.stats.longest_shortfall = shortfalls.1;
        state.stats.stopped = stopped;
        if let Some(error) = state.fault.take() {
            return Err(error);
        }
        if state.stats.completed_repetitions != self.repetitions {
            return Err(RadioError::Source(
                "HackRF transmission stopped before plan completion".into(),
            ));
        }
        if shortfalls.0 != 0 {
            return Err(RadioError::Source(format!(
                "HackRF TX reported {} shortfalls",
                shortfalls.0
            )));
        }
        Ok(state.stats.clone())
    }
}

pub struct HackRfTxSink {
    config: HackRfTxConfig,
    cancelled: Arc<AtomicBool>,
    last_stats: Option<HackRfTxStats>,
    #[cfg(feature = "radio-hackrf")]
    native: super::hackrf::native::NativeTx,
}

impl HackRfTxSink {
    #[cfg(feature = "radio-hackrf")]
    pub fn open_live(config: HackRfTxConfig) -> RadioResult<Self> {
        config.validate()?;
        let native = super::hackrf::native::NativeTx::open(&config)?;
        Ok(Self {
            config,
            cancelled: Arc::new(AtomicBool::new(false)),
            last_stats: None,
            native,
        })
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    pub fn last_stats(&self) -> Option<&HackRfTxStats> {
        self.last_stats.as_ref()
    }
}

#[cfg(feature = "radio-hackrf")]
impl IqSink for HackRfTxSink {
    fn write(&mut self, tx: &LegacyWifiTransmission) -> RadioResult<()> {
        self.cancelled.store(false, Ordering::Release);
        let shared = Arc::new(TxShared::new(
            tx.cs8(),
            &self.config,
            Arc::clone(&self.cancelled),
        )?);
        self.last_stats = Some(self.native.transmit(shared)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> HackRfTxConfig {
        HackRfTxConfig {
            serial: "test".into(),
            center_frequency_hz: 2_437_000_000,
            sample_rate_hz: 20_000_000,
            baseband_filter_hz: 17_500_000,
            tx_vga_gain_db: 0,
            amplifier_enabled: false,
            antenna_power_enabled: false,
            max_duration: Duration::from_secs(1),
            max_supplied_samples: 100,
            repetitions: 2,
            inter_burst_gap_samples: 2,
        }
    }

    #[test]
    fn radio_hackrf_tx_fills_repetitions_gap_and_padding() {
        let shared =
            TxShared::new(&[1, 2, 3, 4], &config(), Arc::new(AtomicBool::new(false))).unwrap();
        let mut output = [99; 16];
        assert!(shared.fill(&mut output));
        assert_eq!(output, [1, 2, 3, 4, 0, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0]);
        let stats = shared.finish((0, 0), true).unwrap();
        assert_eq!(
            (
                stats.requested_samples,
                stats.supplied_samples,
                stats.padded_samples
            ),
            (6, 6, 2)
        );
    }

    #[test]
    fn radio_hackrf_tx_rejects_invalid_config_cancel_and_buffer() {
        let mut invalid = config();
        invalid.tx_vga_gain_db = 48;
        assert!(invalid.validate().is_err());
        let shared = TxShared::new(&[1, 2], &config(), Arc::new(AtomicBool::new(true))).unwrap();
        assert!(!shared.fill(&mut [0; 2]));
        let shared = TxShared::new(&[1, 2], &config(), Arc::new(AtomicBool::new(false))).unwrap();
        assert!(!shared.fill(&mut [0; 3]));
    }

    #[test]
    fn radio_hackrf_tx_large_plan_is_preassembled_and_chunked() {
        let mut config = config();
        config.repetitions = 100;
        config.inter_burst_gap_samples = 17;
        config.max_supplied_samples = 10_000;
        let shared =
            TxShared::new(&[1, 2, 3, 4], &config, Arc::new(AtomicBool::new(false))).unwrap();
        let mut first = [0u8; 512];
        let mut callbacks = 0;
        while !shared.done() {
            assert!(shared.fill(&mut first));
            callbacks += 1;
        }
        let stats = shared.finish((0, 0), true).unwrap();
        assert!(callbacks > 1);
        assert_eq!(stats.completed_repetitions, 100);
        assert_eq!(stats.supplied_samples, stats.requested_samples);
    }
}
