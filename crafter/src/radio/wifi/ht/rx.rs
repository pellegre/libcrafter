//! HT20 receive classification, training, coding recovery, and A-MPDU publication.

use super::{ampdu, decode_iq, decode_iq_at, ldpc, train_single_stream, train_stbc_second};
use crate::radio::wifi::recovery::{self, DecodeAttempt, Profile};
use crate::radio::{
    wifi::ofdm::{
        demod::{decode_data_profile, demodulate_data_profile, descramble_psdu},
        signal::SignalInfo,
        sync::Acquisition,
    },
    ComplexSample, DecodeOutput, HtSignalFields, IqPosition, PhyDiagnostic, RadioError,
    RadioResult, RecoveredFrame, RxConfig,
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum ReceiveMode {
    #[default]
    LegacyOnly,
    Ht20,
}

/// Private policy and algorithm boundary between legacy OFDM acquisition and HT receive.
#[derive(Debug, Clone, Copy, Default)]
pub(in crate::radio) struct Receiver {
    mode: ReceiveMode,
}

impl Receiver {
    pub(in crate::radio) const fn ht20() -> Self {
        Self {
            mode: ReceiveMode::Ht20,
        }
    }

    pub(in crate::radio) const fn accepts_ht(&self) -> bool {
        matches!(self.mode, ReceiveMode::Ht20)
    }

    pub(in crate::radio) fn signal_limit(&self, config: &RxConfig) -> usize {
        if self.accepts_ht() {
            4095
        } else {
            config.max_frame_bytes.min(4095)
        }
    }

    /// Validate and reserve a legacy SIGNAL candidate. A 6 Mbps L-SIG first
    /// reserves the two HT-SIG symbols when HT recognition is enabled.
    pub(in crate::radio) fn reserve_signal_candidate(
        &self,
        samples: &mut Vec<ComplexSample>,
        info: SignalInfo,
        config: &RxConfig,
        available: usize,
    ) -> bool {
        if (!self.accepts_ht() || info.rate_bps != 6_000_000)
            && info.psdu_bytes > config.max_frame_bytes
        {
            return false;
        }
        let required = if self.accepts_ht() && info.rate_bps == 6_000_000 {
            160
        } else {
            info.data_symbols * 80
        };
        if required > available {
            return false;
        }
        samples.reserve_exact(required);
        true
    }

    /// Reserve the second possible HT-SIG symbol after an invalid L-SIG so a
    /// greenfield candidate is not rejected before its complete header exists.
    pub(in crate::radio) fn reserve_greenfield_probe(
        &self,
        samples: &mut Vec<ComplexSample>,
        available: usize,
    ) -> bool {
        if !self.accepts_ht() || available < 80 {
            return false;
        }
        samples.reserve_exact(80);
        true
    }

    pub(in crate::radio) fn recognize_greenfield(
        &self,
        samples: &mut Vec<ComplexSample>,
        acquisition: &Acquisition,
        start: &IqPosition,
        config: &RxConfig,
        reserved: usize,
    ) -> HeaderOutcome {
        if !self.accepts_ht() {
            return HeaderOutcome::NotHt;
        }
        let Some(fields) = decode_iq_at(samples, acquisition, 0) else {
            return HeaderOutcome::NotHt;
        };
        self.configure(fields, true, samples, acquisition, start, config, reserved)
    }

    pub(in crate::radio) fn recognize_mixed(
        &self,
        samples: &mut Vec<ComplexSample>,
        acquisition: &Acquisition,
        start: &IqPosition,
        config: &RxConfig,
        reserved: usize,
    ) -> HeaderOutcome {
        let Some(fields) = decode_iq(&samples[80..240], acquisition) else {
            return HeaderOutcome::NotHt;
        };
        if !self.accepts_ht() {
            return HeaderOutcome::Unsupported {
                diagnostics: header_diagnostics(fields, false, start.sample_index),
            };
        }
        self.configure(fields, false, samples, acquisition, start, config, reserved)
    }

    fn configure(
        &self,
        fields: HtSignalFields,
        greenfield: bool,
        samples: &mut Vec<ComplexSample>,
        acquisition: &Acquisition,
        start: &IqPosition,
        config: &RxConfig,
        reserved: usize,
    ) -> HeaderOutcome {
        let diagnostics = header_diagnostics(fields, greenfield, start.sample_index);
        let Some((candidate, info)) =
            Candidate::configure(fields, greenfield, samples, acquisition, config, reserved)
        else {
            return HeaderOutcome::Unsupported { diagnostics };
        };
        HeaderOutcome::Supported {
            candidate,
            info,
            diagnostics,
        }
    }

    /// Restore the original legacy 6 Mbps reservation after a mixed-format
    /// probe did not recognize HT-SIG.
    pub(in crate::radio) fn reserve_legacy_fallback(
        &self,
        samples: &mut Vec<ComplexSample>,
        info: SignalInfo,
        config: &RxConfig,
        reserved: usize,
    ) -> bool {
        if !self.accepts_ht() {
            return true;
        }
        let required = 80 + info.data_symbols * 80;
        if info.psdu_bytes > config.max_frame_bytes
            || required.saturating_sub(samples.capacity())
                > config.max_buffer_samples.saturating_sub(reserved)
        {
            return false;
        }
        samples.reserve_exact(required.saturating_sub(samples.len()));
        true
    }

    pub(in crate::radio) const fn strict_output_limit(&self) -> bool {
        self.accepts_ht()
    }
}

pub(in crate::radio) enum HeaderOutcome {
    NotHt,
    Supported {
        candidate: Candidate,
        info: SignalInfo,
        diagnostics: Vec<PhyDiagnostic>,
    },
    Unsupported {
        diagnostics: Vec<PhyDiagnostic>,
    },
}

#[derive(Debug, Clone, Copy)]
pub(in crate::radio) struct Candidate {
    fields: HtSignalFields,
    ldpc: Option<ldpc::rate::Layout>,
    greenfield: bool,
}

impl Candidate {
    fn configure(
        fields: HtSignalFields,
        greenfield: bool,
        samples: &mut Vec<ComplexSample>,
        acquisition: &Acquisition,
        config: &RxConfig,
        reserved: usize,
    ) -> Option<(Self, SignalInfo)> {
        if fields.channel_width_40_mhz
            || fields.mcs >= 8
            || fields.stbc > 1
            || u16::from(fields.stbc) + u16::from(fields.extension_spatial_streams) > 3
            || fields.psdu_bytes < 4
            || (!fields.aggregation && usize::from(fields.psdu_bytes) > config.max_frame_bytes)
            || (greenfield && fields.short_guard_interval)
        {
            return None;
        }
        let (nbpsc, ndbps) = [
            (1, 26),
            (2, 52),
            (2, 78),
            (4, 104),
            (4, 156),
            (6, 208),
            (6, 234),
            (6, 260),
        ][fields.mcs as usize];
        let stride = if fields.short_guard_interval { 72 } else { 80 };
        let ldpc = if fields.ldpc {
            use ldpc::Rate::*;
            let rate = [
                Half,
                Half,
                ThreeQuarters,
                Half,
                ThreeQuarters,
                TwoThirds,
                ThreeQuarters,
                FiveSixths,
            ][fields.mcs as usize];
            Some(
                ldpc::rate::Layout::new(
                    fields.psdu_bytes,
                    (52 * nbpsc) as u16,
                    rate,
                    fields.stbc == 1,
                )
                .ok()?,
            )
        } else {
            None
        };
        let group = if fields.stbc == 1 { 2 } else { 1 };
        let symbols = ldpc.map_or_else(
            || group * (16 + 8 * usize::from(fields.psdu_bytes) + 6).div_ceil(group * ndbps),
            |layout| layout.symbols,
        );
        let extension_fields = [0, 1, 2, 4][usize::from(fields.extension_spatial_streams)];
        let data_offset = (if greenfield { 160 } else { 400 })
            + (usize::from(fields.stbc) + extension_fields) * 80;
        let required = data_offset + symbols * stride;
        if required.saturating_sub(samples.capacity())
            > config.max_buffer_samples.saturating_sub(reserved)
        {
            return None;
        }
        let end = acquisition.signal_start.checked_add(required as u64)?;
        samples.reserve_exact(required.saturating_sub(samples.len()));
        let info = SignalInfo {
            rate_bps: (ndbps as u64 * 20_000_000 / stride as u64) as u32,
            coded_bits_per_symbol: 52 * nbpsc,
            data_bits_per_symbol: ndbps,
            psdu_bytes: usize::from(fields.psdu_bytes),
            data_symbols: symbols,
            data_start: acquisition.signal_start + data_offset as u64,
            end_sample_index: end,
        };
        Some((
            Self {
                fields,
                ldpc,
                greenfield,
            },
            info,
        ))
    }

    pub(in crate::radio) const fn aggregate(&self) -> bool {
        self.fields.aggregation
    }

    pub(in crate::radio) fn decode(
        self,
        samples: &[ComplexSample],
        acquisition: &Acquisition,
        info: SignalInfo,
        start: &IqPosition,
    ) -> DecodeAttempt {
        recovery::recover(self.aggregate(), |profile| {
            self.decode_profile(samples, acquisition, info, start, profile)
        })
    }

    fn decode_profile(
        self,
        samples: &[ComplexSample],
        acquisition: &Acquisition,
        info: SignalInfo,
        start: &IqPosition,
        profile: Profile,
    ) -> DecodeAttempt {
        let first_end = if self.greenfield { 160 } else { 400 };
        let data_offset = (info.data_start - acquisition.signal_start) as usize;
        let trained = if self.greenfield {
            Some(acquisition.clone())
        } else {
            train_single_stream(
                &samples[320..400],
                acquisition.signal_start + 320,
                acquisition,
            )
        };
        let mut coding_stats = None;
        let mut coding_failure = None;
        let mut partial_stats = Vec::new();
        let decoded = trained.ok_or(()).and_then(|a| {
            let (a, second) = if self.fields.stbc == 1 {
                let (a, other) = train_stbc_second(
                    a,
                    &samples[first_end..first_end + 80],
                    acquisition.signal_start + first_end as u64,
                )
                .ok_or(())?;
                (a, Some(other))
            } else {
                (a, None)
            };
            if let Some(layout) = self.ldpc {
                let (coded, tracking) = demodulate_data_profile(
                    &samples[data_offset..],
                    &a,
                    info,
                    Some(if self.fields.short_guard_interval {
                        8
                    } else {
                        16
                    }),
                    false,
                    self.greenfield,
                    second.as_ref(),
                    profile,
                )?;
                let (bits, iterations) = if self.fields.aggregation {
                    let recovered = layout.recover_partial(&coded, 64).map_err(|error| {
                        coding_failure = Some(error);
                    })?;
                    if recovered.failed_codewords != 0 {
                        partial_stats.push(PhyDiagnostic::LdpcPartial {
                            failed_codewords: recovered.failed_codewords,
                        });
                        if let Some(ldpc::rate::Error::Codeword {
                            index,
                            error:
                                ldpc::Error::Nonconvergence {
                                    iterations,
                                    failed_checks,
                                },
                        }) = recovered.first_failure
                        {
                            partial_stats.push(PhyDiagnostic::LdpcNonconvergence {
                                codeword: index,
                                iterations,
                                failed_checks,
                            });
                        }
                    }
                    (recovered.bits, recovered.iterations)
                } else {
                    layout.recover(&coded, 64).map_err(|error| {
                        coding_failure = Some(error);
                    })?
                };
                coding_stats = Some(PhyDiagnostic::Ldpc {
                    codewords: layout.codewords,
                    iterations,
                });
                return Ok((descramble_psdu(bits, info.psdu_bytes)?, tracking));
            }
            decode_data_profile(
                &samples[data_offset..],
                &a,
                info,
                Some(if self.fields.short_guard_interval {
                    8
                } else {
                    16
                }),
                self.greenfield,
                second.as_ref(),
                profile,
            )
        });

        let mut frame_diagnostics = vec![PhyDiagnostic::HtSignal {
            fields: self.fields,
            preamble_sample_index: start.sample_index,
        }];
        if let Some(stats) = coding_stats {
            frame_diagnostics.push(stats);
        }
        frame_diagnostics.extend(partial_stats.iter().cloned());
        if self.greenfield {
            frame_diagnostics.push(PhyDiagnostic::HtGreenfield {
                preamble_sample_index: start.sample_index,
            });
        }
        let mut failure_diagnostics = Vec::new();
        if let Some(ldpc::rate::Error::Codeword {
            index,
            error:
                ldpc::Error::Nonconvergence {
                    iterations,
                    failed_checks,
                },
        }) = coding_failure
        {
            failure_diagnostics.push(PhyDiagnostic::LdpcNonconvergence {
                codeword: index,
                iterations,
                failed_checks,
            });
        }
        DecodeAttempt {
            decoded,
            output_diagnostics: partial_stats,
            frame_diagnostics,
            failure_diagnostics,
            aggregate_members: None,
        }
    }
}

pub(in crate::radio) struct AggregateCounts {
    pub valid_frames: u64,
    pub invalid_fcs: u64,
}

pub(in crate::radio) fn publish_aggregate(
    mut frame: RecoveredFrame,
    limit: usize,
    out: &mut DecodeOutput,
    members: Option<&[std::ops::Range<usize>]>,
) -> RadioResult<AggregateCounts> {
    let bytes = std::mem::take(&mut frame.bytes);
    let scan =
        ampdu::Scan::new(&bytes, frame.config.max_frame_bytes).map_err(|_| RadioError::Limit {
            context: "HT aggregate bytes",
            limit: 65535,
            actual: bytes.len() as u64,
        })?;
    let (mut delimiters, mut fcs, mut truncated, mut oversized) = (0, 0, 0, 0);
    let mut valid_frames = 0u64;
    let verified = members.into_iter().flatten().map(|range| {
        // Ranges originate in Scan and are retained only across equal-length
        // PSDUs. Their complete checked delimiter and MPDU bytes stay intact.
        let member = &bytes[range.clone()];
        let delimiter = ampdu::Delimiter::decode(&member[..4]).unwrap();
        ampdu::Event::Frame {
            delimiter_offset: range.start,
            control_bits: delimiter.control_bits,
            bytes: &member[4..],
        }
    });
    for event in scan
        .filter(|event| members.is_none() || !matches!(event, ampdu::Event::Frame { .. }))
        .chain(verified)
    {
        match event {
            ampdu::Event::Frame {
                delimiter_offset,
                control_bits,
                bytes,
            } => {
                if out.frames.len() >= limit {
                    return Err(RadioError::Limit {
                        context: "HT aggregate pending frames",
                        limit: limit as u64,
                        actual: (out.frames.len() + 1) as u64,
                    });
                }
                let mut recovered = frame.clone();
                recovered.bytes = bytes.to_vec();
                recovered.diagnostics.push(PhyDiagnostic::Ampdu {
                    delimiter_offset,
                    control_bits,
                });
                out.frames.push(recovered);
                valid_frames = valid_frames.saturating_add(1);
            }
            ampdu::Event::Empty { .. } => {}
            ampdu::Event::Invalid { error, .. } => match error {
                ampdu::Error::BadFcs => fcs += 1,
                ampdu::Error::TruncatedMpdu { .. } => truncated += 1,
                ampdu::Error::MpduLimit { .. } => oversized += 1,
                _ => delimiters += 1,
            },
        }
    }
    if delimiters + fcs + truncated + oversized != 0 {
        out.diagnostics.push(PhyDiagnostic::AmpduErrors {
            preamble_sample_index: frame.start.sample_index,
            invalid_delimiters: delimiters,
            invalid_fcs: fcs,
            truncated_mpdus: truncated,
            oversized_mpdus: oversized,
        });
    }
    Ok(AggregateCounts {
        valid_frames,
        invalid_fcs: fcs as u64,
    })
}

fn header_diagnostics(
    fields: HtSignalFields,
    greenfield: bool,
    preamble_sample_index: u64,
) -> Vec<PhyDiagnostic> {
    let mut diagnostics = Vec::with_capacity(2);
    if greenfield {
        diagnostics.push(PhyDiagnostic::HtGreenfield {
            preamble_sample_index,
        });
    }
    diagnostics.push(PhyDiagnostic::HtSignal {
        fields,
        preamble_sample_index,
    });
    diagnostics
}
