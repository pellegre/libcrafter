//! Bounded, receive-only IQ contracts. No device is opened by this module.
//!
//! Sources transfer owned interleaved signed eight-bit I/Q storage. DSP consumes
//! normalized samples lazily: each component is divided by 128, giving [-1, 1).
//! IQ is never a packet layer; only recovered MAC bytes cross the packet boundary.
mod replay;
pub use replay::{MemoryIqSource, ReaderIqSource};

use crate::LinkType;
use std::{
    fmt,
    time::{Duration, SystemTime},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RadioError {
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    Limit {
        context: &'static str,
        limit: u64,
        actual: u64,
    },
    Overflow {
        context: &'static str,
    },
    Source(String),
}
impl fmt::Display for RadioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RadioError {}
pub type RadioResult<T> = Result<T, RadioError>;

/// Explicit acquisition and allocation bounds; construction never enables live I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RxConfig {
    pub sample_rate_hz: u32,
    pub center_frequency_hz: u64,
    pub max_chunk_samples: usize,
    pub max_buffer_samples: usize,
    pub max_frame_bytes: usize,
    pub max_pending_frames: usize,
    pub max_capture_samples: u64,
    pub max_duration: Duration,
}
impl RxConfig {
    pub fn validate(&self) -> RadioResult<()> {
        for (field, zero) in [
            ("sample_rate_hz", self.sample_rate_hz == 0),
            ("center_frequency_hz", self.center_frequency_hz == 0),
            ("max_chunk_samples", self.max_chunk_samples == 0),
            ("max_buffer_samples", self.max_buffer_samples == 0),
            ("max_frame_bytes", self.max_frame_bytes == 0),
            ("max_pending_frames", self.max_pending_frames == 0),
            ("max_capture_samples", self.max_capture_samples == 0),
            ("max_duration", self.max_duration.is_zero()),
        ] {
            if zero {
                return Err(RadioError::Invalid {
                    field,
                    reason: "must be nonzero",
                });
            }
        }
        if self.max_chunk_samples > self.max_buffer_samples {
            return Err(RadioError::Invalid {
                field: "max_chunk_samples",
                reason: "exceeds buffer bound",
            });
        }
        self.max_buffer_samples
            .checked_mul(std::mem::size_of::<ComplexSample>())
            .ok_or(RadioError::Overflow {
                context: "normalized buffer bytes",
            })?;
        self.max_frame_bytes
            .checked_mul(self.max_pending_frames)
            .ok_or(RadioError::Overflow {
                context: "pending frame bytes",
            })?;
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ComplexSample {
    pub i: f32,
    pub q: f32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeAnchor {
    pub sample_index: u64,
    pub time: SystemTime,
    pub uncertainty: Duration,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleLoss {
    Known(u64),
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapReason {
    SourceLoss,
    QueueOverflow,
    Reconfiguration,
    Reordered,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Discontinuity {
    pub reason: GapReason,
    pub loss: SampleLoss,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IqPosition {
    pub epoch: u64,
    pub sequence: u64,
    /// Absolute sample position within the epoch. Unknown loss starts a new epoch.
    pub sample_index: u64,
    pub time_anchor: Option<TimeAnchor>,
    pub discontinuity: Option<Discontinuity>,
}
/// Immutable configuration/position and owned cs8 storage, checked at construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IqChunk {
    config: RxConfig,
    position: IqPosition,
    cs8: Vec<i8>,
}
impl IqChunk {
    pub fn new(config: RxConfig, position: IqPosition, cs8: Vec<i8>) -> RadioResult<Self> {
        config.validate()?;
        if cs8.is_empty() || cs8.len() % 2 != 0 {
            return Err(RadioError::Invalid {
                field: "cs8",
                reason: "requires nonempty complete I/Q pairs",
            });
        }
        let samples = cs8.len() / 2;
        if samples > config.max_chunk_samples {
            return Err(RadioError::Limit {
                context: "chunk samples",
                limit: config.max_chunk_samples as u64,
                actual: samples as u64,
            });
        }
        position
            .sample_index
            .checked_add(samples as u64)
            .ok_or(RadioError::Overflow {
                context: "sample end",
            })?;
        Ok(Self {
            config,
            position,
            cs8,
        })
    }
    pub fn config(&self) -> &RxConfig {
        &self.config
    }
    pub fn position(&self) -> &IqPosition {
        &self.position
    }
    pub fn cs8(&self) -> &[i8] {
        &self.cs8
    }
    pub fn into_cs8(self) -> Vec<i8> {
        self.cs8
    }
    pub fn len(&self) -> usize {
        self.cs8.len() / 2
    }
    pub fn is_empty(&self) -> bool {
        self.cs8.is_empty()
    }
    pub fn normalized(&self) -> impl ExactSizeIterator<Item = ComplexSample> + '_ {
        self.cs8.chunks_exact(2).map(|s| ComplexSample {
            i: s[0] as f32 / 128.0,
            q: s[1] as f32 / 128.0,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEnd {
    Eof,
    Cancelled,
    LimitReached,
}
#[derive(Debug)]
pub enum IqEvent {
    Chunk(IqChunk),
    End(StreamEnd),
}
/// Implementations enforce cumulative sample/duration bounds and return the same
/// terminal event on subsequent polls. Cancellation discards queued samples.
/// Live implementations must require a separate explicit opt-in.
pub trait IqSource {
    fn next_event(&mut self) -> RadioResult<IqEvent>;
    fn cancel(&mut self);
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetReason {
    Gap(Discontinuity),
    End(StreamEnd),
    Explicit,
}
#[derive(Debug, Clone, PartialEq)]
pub enum PhyDiagnostic {
    Reset(ResetReason),
    TruncatedFrame,
    InvalidHeader,
    InvalidFcs,
    UnsupportedPhy,
    Clipping { samples: u64 },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameIntegrity {
    ValidFcs,
    InvalidFcs,
    FcsAbsent,
}
/// Original recovered bytes including a received FCS when integrity says present.
#[derive(Debug, Clone)]
pub struct RecoveredFrame {
    pub bytes: Vec<u8>,
    pub link_type: LinkType,
    pub integrity: FrameIntegrity,
    pub config: RxConfig,
    pub start: IqPosition,
    pub end_sample_index: u64,
    pub rate_bps: u32,
    pub diagnostics: Vec<PhyDiagnostic>,
}
#[derive(Debug, Default)]
pub struct DecodeOutput {
    pub frames: Vec<RecoveredFrame>,
    pub diagnostics: Vec<PhyDiagnostic>,
}
/// Stateful decoder contract: retain incomplete symbols across contiguous chunks,
/// reset before consuming discontinuous chunks, and never join different epochs.
/// `reset` discards partial frames and returns a Reset diagnostic plus
/// TruncatedFrame when appropriate. End is terminal until an explicit reset.
/// Implementations enforce the config's buffer/frame/output bounds per call.
pub trait PhyDecoder {
    fn consume(&mut self, event: IqEvent) -> RadioResult<DecodeOutput>;
    fn reset(&mut self, reason: ResetReason) -> DecodeOutput;
}

/// Detect continuity independently of callback chunk sizes. Explicit source gaps
/// take precedence; even a known zero-sized gap forces a decoder reset.
#[derive(Debug, Default)]
pub struct IqContinuity {
    previous: Option<(RxConfig, u64, u64, u64)>,
}
impl IqContinuity {
    pub fn reset(&mut self) {
        self.previous = None;
    }
    pub fn observe(&mut self, chunk: &IqChunk) -> Option<Discontinuity> {
        let p = chunk.position();
        let gap = p.discontinuity.or_else(|| {
            let (config, epoch, sequence, end) = self.previous.as_ref()?;
            if config != chunk.config() || *epoch != p.epoch {
                Some(Discontinuity {
                    reason: GapReason::Reconfiguration,
                    loss: SampleLoss::Unknown,
                })
            } else if sequence.checked_add(1) != Some(p.sequence) || p.sample_index < *end {
                Some(Discontinuity {
                    reason: GapReason::Reordered,
                    loss: SampleLoss::Unknown,
                })
            } else if p.sample_index > *end {
                Some(Discontinuity {
                    reason: GapReason::SourceLoss,
                    loss: SampleLoss::Known(p.sample_index - end),
                })
            } else {
                None
            }
        });
        self.previous = Some((
            chunk.config.clone(),
            p.epoch,
            p.sequence,
            p.sample_index + chunk.len() as u64,
        ));
        gap
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> RxConfig {
        RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: 16,
            max_buffer_samples: 64,
            max_frame_bytes: 4096,
            max_pending_frames: 4,
            max_capture_samples: 100,
            max_duration: Duration::from_secs(1),
        }
    }
    fn position(sequence: u64, sample_index: u64) -> IqPosition {
        IqPosition {
            epoch: 0,
            sequence,
            sample_index,
            time_anchor: None,
            discontinuity: None,
        }
    }
    #[test]
    fn radio_invalid_dimensions_and_limits() {
        for bytes in [vec![], vec![1], vec![0; 34]] {
            assert!(IqChunk::new(config(), position(0, 0), bytes).is_err());
        }
        assert!(IqChunk::new(config(), position(0, u64::MAX), vec![0; 2]).is_err());
        let mut c = config();
        c.sample_rate_hz = 0;
        assert!(c.validate().is_err());
        let mut c = config();
        c.max_buffer_samples = 1;
        assert!(c.validate().is_err());
        let mut c = config();
        c.max_frame_bytes = usize::MAX;
        assert!(c.validate().is_err());
    }
    #[test]
    fn radio_sample_ownership_and_scale() {
        let bytes = vec![-128, 127, 64, -64];
        let ptr = bytes.as_ptr();
        let chunk = IqChunk::new(config(), position(0, 0), bytes).unwrap();
        assert_eq!(ptr, chunk.cs8().as_ptr());
        assert_eq!(
            chunk.normalized().collect::<Vec<_>>(),
            vec![
                ComplexSample {
                    i: -1.,
                    q: 127. / 128.
                },
                ComplexSample { i: 0.5, q: -0.5 }
            ]
        );
        assert_eq!(chunk.into_cs8(), vec![-128, 127, 64, -64]);
    }
    #[test]
    fn radio_chunk_boundaries_and_gap_propagation() {
        let mut tracker = IqContinuity::default();
        let mut index = 0;
        for (sequence, size) in [1, 7, 2, 16].into_iter().enumerate() {
            let chunk = IqChunk::new(
                config(),
                position(sequence as u64, index),
                vec![0; size * 2],
            )
            .unwrap();
            assert_eq!(tracker.observe(&chunk), None);
            index += size as u64;
        }
        let chunk = IqChunk::new(config(), position(4, index + 3), vec![0; 2]).unwrap();
        assert_eq!(tracker.observe(&chunk).unwrap().loss, SampleLoss::Known(3));
        let mut p = position(5, index + 4);
        p.discontinuity = Some(Discontinuity {
            reason: GapReason::QueueOverflow,
            loss: SampleLoss::Unknown,
        });
        let chunk = IqChunk::new(config(), p.clone(), vec![0; 2]).unwrap();
        assert_eq!(tracker.observe(&chunk), p.discontinuity);
        tracker.reset();
        assert_eq!(
            tracker.observe(&IqChunk::new(config(), position(0, 0), vec![0; 2]).unwrap()),
            None
        );
    }
    #[test]
    fn radio_reconfiguration_reordering_and_anchor() {
        let mut tracker = IqContinuity::default();
        let mut p = position(0, 0);
        p.time_anchor = Some(TimeAnchor {
            sample_index: 0,
            time: SystemTime::UNIX_EPOCH,
            uncertainty: Duration::from_micros(2),
        });
        let chunk = IqChunk::new(config(), p.clone(), vec![0; 2]).unwrap();
        assert_eq!(chunk.position(), &p);
        tracker.observe(&chunk);
        assert_eq!(
            tracker.observe(&chunk).unwrap().reason,
            GapReason::Reordered
        );
        let mut c = config();
        c.sample_rate_hz /= 2;
        assert_eq!(
            tracker
                .observe(&IqChunk::new(c, position(1, 1), vec![0; 2]).unwrap())
                .unwrap()
                .reason,
            GapReason::Reconfiguration
        );
    }
}
