use super::{
    error::RadioResult,
    transport::{Discontinuity, IqEvent, IqPosition, RxConfig, StreamEnd},
    wifi::ht::HtSignalFields,
};
use crate::LinkType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetReason {
    Gap(Discontinuity),
    End(StreamEnd),
    Explicit,
}

#[derive(Debug, Clone)]
pub enum PhyDiagnostic {
    /// Byte offset of this MPDU's delimiter within its HT A-MPDU PSDU.
    /// Frame sample coordinates describe the entire containing PPDU.
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
    /// Bounded DATA hypotheses tried for one PPDU. Valid MPDUs retain their
    /// first successful decoding when aggregate members use different attempts.
    OfdmRecovery {
        attempts: u8,
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
            (Self::OfdmRecovery { attempts: a }, Self::OfdmRecovery { attempts: b }) => a == b,
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

/// Codec-declared trailer length, independent of whether its integrity passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameFraming {
    pub trailer_bytes: usize,
}

/// Original recovered bytes; the codec declares capture-only trailer framing.
#[derive(Debug, Clone)]
pub struct RecoveredFrame {
    pub bytes: Vec<u8>,
    pub link_type: LinkType,
    pub integrity: FrameIntegrity,
    pub framing: FrameFraming,
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
