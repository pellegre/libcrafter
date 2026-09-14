//! Bounded, receive-only IQ contracts. No device is opened by this module.
//!
//! Sources transfer owned interleaved signed eight-bit I/Q storage. DSP consumes
//! normalized samples lazily: each component is divided by 128, giving [-1, 1).
//! IQ is never a packet layer; only recovered MAC bytes cross the packet boundary.
mod ampdu;
mod data;
mod dsss;
mod dsss_tx;
mod eht;
pub use eht::{
    EhtMuPpduType, EhtMuUsigFields, EhtSigMcs, EhtTbUsigFields, EhtUsigError, EhtUsigFields,
    EhtUsigFormat,
};
mod he;
pub use he::mu::sig_b::coded::Error as HeSigBCodedError;
pub use he::mu::sig_b::iq::Fields as HeMuSigBFields;
pub use he::mu::sig_b::{
    HeRu20Assignment, HeSigBCommon20Fields, HeSigBError, HeSigBUserBlock, HeSigBUserContext,
    HeSigBUserEncoding, HeSigBUserFields,
};
pub use he::mu::MuSignal as HeMuSignalFields;
pub use he::tb::{Error as HeTbSignalError, TbSignal as HeTbSignalFields};
pub use he::{Error as HeSignalError, SuSignal as HeSuSignalFields};
mod ht;
mod vht;
pub use vht::{
    VhtSignalAError, VhtSignalAFields, VhtSignalAUsers, VhtSignalB20Content, VhtSignalB20Error,
    VhtSignalB20Fields,
};
mod ldpc;
pub use ht::{
    HtCoding, HtFormat, HtGuardInterval, HtMcs, HtSignalBits, HtSignalError, HtSignalFields,
    HtTransmission, HtTxConfig,
};
#[cfg(any(feature = "radio-hackrf", test))]
mod hackrf;
#[cfg(any(feature = "radio-hackrf", test))]
mod hackrf_tx;
mod ofdm_tx;
#[cfg(feature = "radio-hackrf")]
pub use hackrf::{HackRfConfig, HackRfSource, HackRfStats};
#[cfg(feature = "radio-hackrf")]
pub use hackrf_tx::{HackRfTxConfig, HackRfTxSink, HackRfTxStats};
mod parallel;
pub use parallel::{ParallelLegacyWifiDecoder, ParallelWifiDecoder};
mod replay;
mod signal;
mod source;
mod stbc;
mod sync;
mod tx;
mod wifi;
mod windowed;
pub use data::{DecoderStats, LegacyOfdmDecoder};
pub use dsss::DsssCckDecoder;
pub use dsss_tx::{
    DsssPlcpFields, DsssPreamble, LegacyDsssCckRate, LegacyDsssCckTransmission,
    LegacyDsssCckTxConfig,
};
pub use ofdm_tx::{LegacyOfdmRate, LegacyOfdmTransmission, LegacyOfdmTxConfig, OfdmSignalFields};
pub use replay::{MemoryIqSource, ReaderIqSource};
pub use signal::SignalInfo;
pub use source::{RadioPacketSource, RadioReceiveMetadata};
pub use tx::{
    EncodedWifiTransmission, IqSink, LegacyWifiPhy, LegacyWifiTransmission, LegacyWifiTxConfig,
    MemoryIqSink, RadioPacketWriter, WifiFcsPolicy, WifiTxEncoder,
};
pub use wifi::{LegacyWifiDecoder, WifiDecoder};
pub use windowed::{WindowedLegacyWifiDecoder, WindowedWifiDecoder};

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
#[derive(Debug, Clone)]
pub enum PhyDiagnostic {
    /// Trigger parameters used for this RU. Matching is not BSS authentication.
    HeTbUser {
        common: crate::Dot11TriggerCommonFields,
        /// Effective per-RU parameters; an RA range's RU byte is expanded.
        user: crate::Dot11TriggerUserFields,
        /// Position of the original User Info, shared by all RUs in an RA range.
        user_index: usize,
        trigger_preamble_sample_index: u64,
        preamble_sample_index: u64,
    },
    /// Checked HE TB signaling only; DATA requires matching Trigger context.
    HeTbSignal {
        fields: HeTbSignalFields,
        preamble_sample_index: u64,
    },
    /// Zero-based original User field position in the accompanying HeMuSigB.
    /// Present on MU frames after per-user DATA recovery and MPDU FCS checks.
    HeMuUser {
        user_index: usize,
        preamble_sample_index: u64,
    },
    /// Checked MU SIG-B fields, including independent per-user/block failures.
    HeMuSigB {
        fields: HeMuSigBFields,
        preamble_sample_index: u64,
    },
    /// CRC-checked HE MU signaling, not proof of SIG-B or DATA integrity.
    HeMuSignal {
        fields: HeMuSignalFields,
        preamble_sample_index: u64,
    },
    /// CRC-checked HE ER SU signaling. `bandwidth` selects 242/upper106 tones,
    /// not a wider RF channel. This does not establish DATA or MAC integrity.
    HeErSignal {
        fields: HeSuSignalFields,
        preamble_sample_index: u64,
    },
    /// CRC-checked HE SU signaling, not proof of DATA or MAC integrity.
    HeSignal {
        fields: HeSuSignalFields,
        preamble_sample_index: u64,
    },
    /// Byte offset of this MPDU's delimiter within its HT/VHT/HE A-MPDU PSDU.
    /// Frame sample coordinates describe the entire containing PPDU.
    /// Control bits preserve HT's low nibble or VHT/HE's EOF/Tag/reserved bits;
    /// VHT high-length bits are not control flags.
    Ampdu {
        delimiter_offset: usize,
        control_bits: u8,
    },
    /// Bounded summary of aggregate recovery failures, not one diagnostic per scan step.
    AmpduErrors {
        preamble_sample_index: u64,
        invalid_delimiters: usize,
        invalid_fcs: usize,
        truncated_mpdus: usize,
        oversized_mpdus: usize,
    },
    /// The associated integrity-checked HT-SIG used a greenfield preamble.
    /// This format marker does not establish MAC integrity.
    HtGreenfield {
        preamble_sample_index: u64,
    },
    /// An integrity-checked HT header, not an integrity-checked MAC frame.
    HtSignal {
        fields: HtSignalFields,
        preamble_sample_index: u64,
    },
    /// CRC-checked VHT-SIG-A, not proof of MAC or DATA integrity.
    VhtSignalA {
        fields: VhtSignalAFields,
        preamble_sample_index: u64,
    },
    /// VHT-SIG-B whose CRC has been verified against descrambled DATA SERVICE.
    VhtSignalB {
        fields: VhtSignalB20Fields,
        preamble_sample_index: u64,
    },
    Reset(ResetReason),
    TruncatedFrame,
    InvalidHeader,
    InvalidFcs,
    /// DATA failed after a valid SIGNAL header. This is not a header failure.
    InvalidData,
    /// LDPC effort across processed codewords; not RF quality. When LdpcPartial
    /// is also present, some codewords remain tentative despite valid MAC FCS.
    Ldpc {
        codewords: usize,
        iterations: usize,
    },
    /// A-MPDU recovery used tentative estimates for damaged codewords. Only
    /// individually FCS-valid MPDUs from that PSDU may become recovered frames.
    LdpcPartial {
        failed_codewords: usize,
    },
    /// A codeword exhausted its bounded decoder without satisfying parity.
    LdpcNonconvergence {
        codeword: usize,
        iterations: usize,
        failed_checks: usize,
    },
    /// DATA pilot tracking, not a calibrated RF quality measurement.
    OfdmTracking {
        /// Positive means the receiving sample clock is faster. None for one symbol.
        sampling_clock_offset_ppm: Option<f32>,
        /// Channel-weighted RMS pilot phase error after slope/offset removal.
        pilot_residual_rms_rad: f32,
        data_symbols: usize,
    },
    Ofdm {
        frequency_offset_hz: f32,
        training_correlation: f32,
    },
    Dsss {
        short_preamble: bool,
        frequency_offset_hz: f32,
        timing_uncertainty_samples: u32,
    },
    UnsupportedPhy,
    Clipping {
        samples: u64,
    },
}
// Bitwise floating-point equality preserves Eq for packet metadata, including NaNs.
impl PartialEq for PhyDiagnostic {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::HeTbUser {
                    common: a,
                    user: b,
                    user_index: c,
                    trigger_preamble_sample_index: d,
                    preamble_sample_index: e,
                },
                Self::HeTbUser {
                    common: f,
                    user: g,
                    user_index: h,
                    trigger_preamble_sample_index: i,
                    preamble_sample_index: j,
                },
            ) => a == f && b == g && c == h && d == i && e == j,
            (
                Self::HeTbSignal {
                    fields: a,
                    preamble_sample_index: b,
                },
                Self::HeTbSignal {
                    fields: c,
                    preamble_sample_index: d,
                },
            ) => a == c && b == d,
            (
                Self::HeMuUser {
                    user_index: a,
                    preamble_sample_index: b,
                },
                Self::HeMuUser {
                    user_index: c,
                    preamble_sample_index: d,
                },
            ) => a == c && b == d,
            (
                Self::HeMuSigB {
                    fields: a,
                    preamble_sample_index: b,
                },
                Self::HeMuSigB {
                    fields: c,
                    preamble_sample_index: d,
                },
            ) => a == c && b == d,
            (
                Self::HeMuSignal {
                    fields: a,
                    preamble_sample_index: b,
                },
                Self::HeMuSignal {
                    fields: c,
                    preamble_sample_index: d,
                },
            ) => a == c && b == d,
            (
                Self::HeErSignal {
                    fields: a,
                    preamble_sample_index: b,
                },
                Self::HeErSignal {
                    fields: c,
                    preamble_sample_index: d,
                },
            ) => a == c && b == d,
            (
                Self::HeSignal {
                    fields: a,
                    preamble_sample_index: b,
                },
                Self::HeSignal {
                    fields: c,
                    preamble_sample_index: d,
                },
            ) => a == c && b == d,
            (
                Self::LdpcPartial {
                    failed_codewords: a,
                },
                Self::LdpcPartial {
                    failed_codewords: b,
                },
            ) => a == b,
            (
                Self::Ampdu {
                    delimiter_offset: a,
                    control_bits: b,
                },
                Self::Ampdu {
                    delimiter_offset: c,
                    control_bits: d,
                },
            ) => a == c && b == d,
            (
                Self::VhtSignalA {
                    fields: a,
                    preamble_sample_index: b,
                },
                Self::VhtSignalA {
                    fields: c,
                    preamble_sample_index: d,
                },
            ) => a == c && b == d,
            (
                Self::VhtSignalB {
                    fields: a,
                    preamble_sample_index: b,
                },
                Self::VhtSignalB {
                    fields: c,
                    preamble_sample_index: d,
                },
            ) => a == c && b == d,
            (
                Self::AmpduErrors {
                    preamble_sample_index: a,
                    invalid_delimiters: b,
                    invalid_fcs: c,
                    truncated_mpdus: d,
                    oversized_mpdus: e,
                },
                Self::AmpduErrors {
                    preamble_sample_index: f,
                    invalid_delimiters: g,
                    invalid_fcs: h,
                    truncated_mpdus: i,
                    oversized_mpdus: j,
                },
            ) => (a, b, c, d, e) == (f, g, h, i, j),
            (
                Self::Ldpc {
                    codewords: a,
                    iterations: b,
                },
                Self::Ldpc {
                    codewords: c,
                    iterations: d,
                },
            ) => a == c && b == d,
            (
                Self::LdpcNonconvergence {
                    codeword: a,
                    iterations: b,
                    failed_checks: c,
                },
                Self::LdpcNonconvergence {
                    codeword: d,
                    iterations: e,
                    failed_checks: f,
                },
            ) => a == d && b == e && c == f,
            (
                Self::HtGreenfield {
                    preamble_sample_index: a,
                },
                Self::HtGreenfield {
                    preamble_sample_index: b,
                },
            ) => a == b,
            (
                Self::HtSignal {
                    fields: a,
                    preamble_sample_index: b,
                },
                Self::HtSignal {
                    fields: c,
                    preamble_sample_index: d,
                },
            ) => a == c && b == d,
            (
                Self::OfdmTracking {
                    sampling_clock_offset_ppm: a,
                    pilot_residual_rms_rad: b,
                    data_symbols: c,
                },
                Self::OfdmTracking {
                    sampling_clock_offset_ppm: d,
                    pilot_residual_rms_rad: e,
                    data_symbols: f,
                },
            ) => a.map(f32::to_bits) == d.map(f32::to_bits) && b.to_bits() == e.to_bits() && c == f,
            (Self::Reset(a), Self::Reset(b)) => a == b,
            (
                Self::Ofdm {
                    frequency_offset_hz: a,
                    training_correlation: b,
                },
                Self::Ofdm {
                    frequency_offset_hz: c,
                    training_correlation: d,
                },
            ) => a.to_bits() == c.to_bits() && b.to_bits() == d.to_bits(),
            (
                Self::Dsss {
                    short_preamble: a,
                    frequency_offset_hz: b,
                    timing_uncertainty_samples: c,
                },
                Self::Dsss {
                    short_preamble: d,
                    frequency_offset_hz: e,
                    timing_uncertainty_samples: f,
                },
            ) => a == d && b.to_bits() == e.to_bits() && c == f,
            (Self::Clipping { samples: a }, Self::Clipping { samples: b }) => a == b,
            (Self::TruncatedFrame, Self::TruncatedFrame)
            | (Self::InvalidHeader, Self::InvalidHeader)
            | (Self::InvalidFcs, Self::InvalidFcs)
            | (Self::InvalidData, Self::InvalidData)
            | (Self::UnsupportedPhy, Self::UnsupportedPhy) => true,
            _ => false,
        }
    }
}
impl Eq for PhyDiagnostic {}
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
