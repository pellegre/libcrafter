//! Legacy and opt-in HT/VHT DATA receive paths; source map in docs/wifi-phy-evidence.json.
use super::{
    signal::{decode_signal, TRELLIS_SIGNS},
    sync::{fft64, Acquisition, SyncEvent, Synchronizer},
    *,
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DecoderStats {
    pub valid_frames: u64,
    pub invalid_fcs: u64,
    pub rejected_frames: u64,
    pub truncated_frames: u64,
    pub dropped_frames: u64,
}
struct Pending {
    acquisition: Acquisition,
    start: IqPosition,
    samples: Vec<ComplexSample>,
    info: Option<SignalInfo>,
    ht: Option<HtSignalFields>,
    vht: Option<VhtSignalAFields>,
    ldpc: Option<ldpc::rate::Layout>,
    greenfield: bool,
}
impl Pending {
    fn configure_vht(&mut self, config: &RxConfig, reserved: usize) -> bool {
        let Ok((fields, info)) = vht_iq::admit(&self.samples, &self.acquisition) else {
            return false;
        };
        let Some(required) = info
            .end_sample_index
            .checked_sub(self.acquisition.signal_start)
            .and_then(|n| usize::try_from(n).ok())
        else {
            return false;
        };
        if required.saturating_sub(self.samples.capacity())
            > config.max_buffer_samples.saturating_sub(reserved)
        {
            return false;
        }
        if self
            .samples
            .try_reserve_exact(required.saturating_sub(self.samples.len()))
            .is_err()
        {
            return false;
        }
        self.info = Some(info);
        self.vht = Some(fields);
        true
    }
    fn configure_ht(
        &mut self,
        fields: HtSignalFields,
        config: &RxConfig,
        reserved: usize,
        greenfield: bool,
    ) -> bool {
        if fields.channel_width_40_mhz
            || fields.mcs >= 8
            || fields.stbc > 1
            || u16::from(fields.stbc) + u16::from(fields.extension_spatial_streams) > 3
            || fields.psdu_bytes < 4
            || (!fields.aggregation && usize::from(fields.psdu_bytes) > config.max_frame_bytes)
            || (greenfield && fields.short_guard_interval)
        {
            return false;
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
            let Ok(layout) = ldpc::rate::Layout::new(
                fields.psdu_bytes,
                (52 * nbpsc) as u16,
                rate,
                fields.stbc == 1,
            ) else {
                return false;
            };
            Some(layout)
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
        if required.saturating_sub(self.samples.capacity())
            > config.max_buffer_samples.saturating_sub(reserved)
        {
            return false;
        }
        let Some(end) = self.acquisition.signal_start.checked_add(required as u64) else {
            return false;
        };
        self.samples
            .reserve_exact(required.saturating_sub(self.samples.len()));
        self.info = Some(SignalInfo {
            rate_bps: (ndbps as u64 * 20_000_000 / stride as u64) as u32,
            coded_bits_per_symbol: 52 * nbpsc,
            data_bits_per_symbol: ndbps,
            psdu_bytes: usize::from(fields.psdu_bytes),
            data_symbols: symbols,
            data_start: self.acquisition.signal_start + data_offset as u64,
            end_sample_index: end,
        });
        self.ht = Some(fields);
        self.ldpc = ldpc;
        self.greenfield = greenfield;
        true
    }
}
#[derive(Clone, Copy)]
enum Aggregation {
    Ht,
    Vht,
}
/// Bounded streaming legacy OFDM receiver. Only integrity-valid PSDUs are delivered.
#[derive(Default)]
pub struct LegacyOfdmDecoder {
    sync: Synchronizer,
    continuity: IqContinuity,
    // Continue acquisition while DATA is pending, without an unbounded set of
    // hypotheses. Reservations across both slots share max_buffer_samples.
    pending: [Option<Pending>; 2],
    terminal: bool,
    stats: DecoderStats,
    ht_enabled: bool,
    // Dispatcher output budget is not a capture reconfiguration. Changing
    // RxConfig between internal slices would discard an in-flight PPDU.
    output_allowance: Option<usize>,
}
impl LegacyOfdmDecoder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn stats(&self) -> DecoderStats {
        self.stats
    }
    pub(super) fn with_ht() -> Self {
        Self {
            ht_enabled: true,
            ..Self::default()
        }
    }
    pub(super) fn ht_enabled(&self) -> bool {
        self.ht_enabled
    }
    pub(super) fn set_output_allowance(&mut self, allowance: usize) {
        self.output_allowance = Some(allowance);
    }
    fn publish_psdu(
        &mut self,
        mut frame: RecoveredFrame,
        aggregate: Option<Aggregation>,
        out: &mut DecodeOutput,
    ) -> RadioResult<()> {
        let limit = self
            .output_allowance
            .unwrap_or(frame.config.max_pending_frames)
            .min(frame.config.max_pending_frames);
        if let Some(aggregate) = aggregate {
            let bytes = std::mem::take(&mut frame.bytes);
            let scan =
                match aggregate {
                    Aggregation::Vht => ampdu::Scan::vht(&bytes, frame.config.max_frame_bytes),
                    Aggregation::Ht => ampdu::Scan::new(&bytes, frame.config.max_frame_bytes)
                        .map_err(|_| RadioError::Limit {
                            context: "HT aggregate bytes",
                            limit: 65535,
                            actual: bytes.len() as u64,
                        })?,
                };
            let (mut delimiters, mut fcs, mut truncated, mut oversized) = (0, 0, 0, 0);
            for event in scan {
                match event {
                    ampdu::Event::Frame {
                        delimiter_offset,
                        control_bits,
                        bytes,
                    } => {
                        if out.frames.len() >= limit {
                            return Err(RadioError::Limit {
                                context: match aggregate {
                                    Aggregation::Ht => "HT aggregate pending frames",
                                    Aggregation::Vht => "VHT aggregate pending frames",
                                },
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
                        self.stats.valid_frames = self.stats.valid_frames.saturating_add(1);
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
            self.stats.invalid_fcs = self.stats.invalid_fcs.saturating_add(fcs as u64);
            if delimiters + fcs + truncated + oversized != 0 {
                out.diagnostics.push(PhyDiagnostic::AmpduErrors {
                    preamble_sample_index: frame.start.sample_index,
                    invalid_delimiters: delimiters,
                    invalid_fcs: fcs,
                    truncated_mpdus: truncated,
                    oversized_mpdus: oversized,
                });
            }
        } else if valid_fcs(&frame.bytes) {
            self.stats.valid_frames = self.stats.valid_frames.saturating_add(1);
            if out.frames.len() < limit {
                out.frames.push(frame);
            } else if self.ht_enabled {
                return Err(RadioError::Limit {
                    context: "Wi-Fi pending frames",
                    limit: limit as u64,
                    actual: (out.frames.len() + 1) as u64,
                });
            } else {
                self.stats.dropped_frames = self.stats.dropped_frames.saturating_add(1);
                out.diagnostics
                    .push(PhyDiagnostic::Reset(ResetReason::Gap(Discontinuity {
                        reason: GapReason::QueueOverflow,
                        loss: SampleLoss::Known(0),
                    })));
            }
        } else {
            self.stats.invalid_fcs = self.stats.invalid_fcs.saturating_add(1);
            out.diagnostics.push(PhyDiagnostic::InvalidFcs);
        }
        Ok(())
    }
}
impl PhyDecoder for LegacyOfdmDecoder {
    fn reset(&mut self, reason: ResetReason) -> DecodeOutput {
        let mut out = DecodeOutput::default();
        let partials = self.pending.iter_mut().filter_map(Option::take).count()
            + usize::from(self.sync.clear());
        if partials != 0 {
            self.stats.truncated_frames =
                self.stats.truncated_frames.saturating_add(partials as u64);
            out.diagnostics.push(PhyDiagnostic::TruncatedFrame);
        }
        self.sync.reset();
        self.continuity.reset();
        self.terminal = matches!(reason, ResetReason::End(_));
        out.diagnostics.push(PhyDiagnostic::Reset(reason));
        out
    }
    fn consume(&mut self, event: IqEvent) -> RadioResult<DecodeOutput> {
        if self.terminal {
            return Ok(DecodeOutput::default());
        }
        let chunk = match event {
            IqEvent::End(end) => return Ok(self.reset(ResetReason::End(end))),
            IqEvent::Chunk(c) => c,
        };
        let config = chunk.config();
        if config.sample_rate_hz != 20_000_000 || config.max_buffer_samples < 384 {
            self.reset(ResetReason::Explicit);
            return Err(RadioError::Invalid {
                field: "config",
                reason: "legacy OFDM requires 20 Msps and at least 384 buffer samples",
            });
        }
        let mut out = DecodeOutput::default();
        if let Some(gap) = self.continuity.observe(&chunk) {
            out = self.reset(ResetReason::Gap(gap));
            self.continuity.observe(&chunk);
        }
        for (offset, sample) in chunk.normalized().enumerate() {
            let index = chunk.position().sample_index + offset as u64;
            for slot in 0..self.pending.len() {
                let reserved: usize = self
                    .pending
                    .iter()
                    .flatten()
                    .map(|p| p.samples.capacity())
                    .sum();
                let Some(p) = &mut self.pending[slot] else {
                    continue;
                };
                p.samples.push(sample);
                if p.info.is_none() && p.samples.len() == 80 {
                    match decode_signal(
                        &p.samples,
                        &p.acquisition,
                        if self.ht_enabled {
                            4095
                        } else {
                            config.max_frame_bytes.min(4095)
                        },
                    ) {
                        Ok(info)
                            if (self.ht_enabled && info.rate_bps == 6_000_000
                                || info.psdu_bytes <= config.max_frame_bytes)
                                && (if self.ht_enabled && info.rate_bps == 6_000_000 {
                                    160
                                } else {
                                    info.data_symbols * 80
                                }) <= config.max_buffer_samples.saturating_sub(reserved) =>
                        {
                            p.samples.reserve_exact(
                                if self.ht_enabled && info.rate_bps == 6_000_000 {
                                    160
                                } else {
                                    info.data_symbols * 80
                                },
                            );
                            p.info = Some(info);
                        }
                        _ if self.ht_enabled
                            && 80 <= config.max_buffer_samples.saturating_sub(reserved) =>
                        {
                            // A greenfield preamble has HT-SIG here, not L-SIG.
                            // Wait for both symbols before rejecting this candidate.
                            p.samples.reserve_exact(80);
                        }
                        _ => {
                            self.stats.rejected_frames =
                                self.stats.rejected_frames.saturating_add(1);
                            out.diagnostics.push(PhyDiagnostic::InvalidHeader);
                            self.pending[slot] = None;
                            continue;
                        }
                    }
                }
                if self.ht_enabled && p.samples.len() == 160 {
                    if let Some(fields) = ht::decode_iq_at(&p.samples, &p.acquisition, 0) {
                        out.diagnostics.push(PhyDiagnostic::HtGreenfield {
                            preamble_sample_index: p.start.sample_index,
                        });
                        out.diagnostics.push(PhyDiagnostic::HtSignal {
                            fields,
                            preamble_sample_index: p.start.sample_index,
                        });
                        if p.configure_ht(fields, config, reserved, true) {
                            continue;
                        }
                        out.diagnostics.push(PhyDiagnostic::UnsupportedPhy);
                        self.stats.rejected_frames = self.stats.rejected_frames.saturating_add(1);
                        self.pending[slot] = None;
                        continue;
                    }
                    if p.info.is_none() {
                        self.stats.rejected_frames = self.stats.rejected_frames.saturating_add(1);
                        out.diagnostics.push(PhyDiagnostic::InvalidHeader);
                        self.pending[slot] = None;
                        continue;
                    }
                }
                if p.samples.len() == 240 && p.info.is_some_and(|info| info.rate_bps == 6_000_000) {
                    if let Some(fields) = super::ht::decode_iq(&p.samples[80..240], &p.acquisition)
                    {
                        out.diagnostics.push(PhyDiagnostic::HtSignal {
                            fields,
                            preamble_sample_index: p.start.sample_index,
                        });
                        if self.ht_enabled && p.configure_ht(fields, config, reserved, false) {
                            continue;
                        }
                        out.diagnostics.push(PhyDiagnostic::UnsupportedPhy);
                        self.stats.rejected_frames = self.stats.rejected_frames.saturating_add(1);
                        self.pending[slot] = None;
                        continue;
                    }
                    if let Some(fields) = self
                        .ht_enabled
                        .then(|| vht_iq::signal_a(&p.samples[80..240], &p.acquisition))
                        .flatten()
                    {
                        out.diagnostics.push(PhyDiagnostic::VhtSignalA {
                            fields,
                            preamble_sample_index: p.start.sample_index,
                        });
                        if self.ht_enabled && p.configure_vht(config, reserved) {
                            continue;
                        }
                        out.diagnostics.push(PhyDiagnostic::UnsupportedPhy);
                        self.stats.rejected_frames = self.stats.rejected_frames.saturating_add(1);
                        self.pending[slot] = None;
                        continue;
                    }
                    if self.ht_enabled {
                        let info = p.info.unwrap();
                        let required = 80 + info.data_symbols * 80;
                        if info.psdu_bytes > config.max_frame_bytes
                            || required.saturating_sub(p.samples.capacity())
                                > config.max_buffer_samples.saturating_sub(reserved)
                        {
                            self.stats.rejected_frames =
                                self.stats.rejected_frames.saturating_add(1);
                            out.diagnostics.push(PhyDiagnostic::InvalidHeader);
                            self.pending[slot] = None;
                            continue;
                        }
                        p.samples
                            .reserve_exact(required.saturating_sub(p.samples.len()));
                    }
                }
                if p.info
                    .is_some_and(|info| index + 1 == info.end_sample_index)
                {
                    let p = self.pending[slot].take().unwrap();
                    let info = p.info.unwrap();
                    let (mut coding_stats, mut coding_failure) = (None, None);
                    let mut partial_stats = Vec::new();
                    let mut vht_signal_b = None;
                    let decoded = if p.vht.is_some() {
                        vht_iq::decode(&p.samples, &p.acquisition).map(|decoded| {
                            debug_assert_eq!(Some(decoded.signal_a), p.vht);
                            debug_assert_eq!(decoded.info, info);
                            vht_signal_b = Some(decoded.signal_b);
                            partial_stats.extend(decoded.coding);
                            (decoded.bytes, decoded.tracking)
                        })
                    } else if let Some(fields) = p.ht {
                        let first_end = if p.greenfield { 160 } else { 400 };
                        // HT-ELTFs sound dimensions not used by DATA. Keep the
                        // data-training estimates, but include every extension
                        // field in the configured DATA position and CFO time.
                        let data_offset = (info.data_start - p.acquisition.signal_start) as usize;
                        let trained = if p.greenfield {
                            Some(p.acquisition.clone())
                        } else {
                            ht::train_single_stream(
                                &p.samples[320..400],
                                p.acquisition.signal_start + 320,
                                &p.acquisition,
                            )
                        };
                        trained.ok_or(()).and_then(|a| {
                            let (a, second) = if fields.stbc == 1 {
                                let (a, other) = ht::train_stbc_second(
                                    a,
                                    &p.samples[first_end..first_end + 80],
                                    p.acquisition.signal_start + first_end as u64,
                                )
                                .ok_or(())?;
                                (a, Some(other))
                            } else {
                                (a, None)
                            };
                            if let Some(layout) = p.ldpc {
                                let (coded, tracking) = demodulate_data(
                                    &p.samples[data_offset..],
                                    &a,
                                    info,
                                    Some(if fields.short_guard_interval { 8 } else { 16 }),
                                    false,
                                    p.greenfield,
                                    second.as_ref(),
                                )?;
                                let (bits, iterations) = if fields.aggregation {
                                    let recovered =
                                        layout.recover_partial(&coded, 64).map_err(|error| {
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
                            decode_data_mode_with_format(
                                &p.samples[data_offset..],
                                &a,
                                info,
                                Some(if fields.short_guard_interval { 8 } else { 16 }),
                                p.greenfield,
                                second.as_ref(),
                            )
                        })
                    } else {
                        decode_data(&p.samples[80..], &p.acquisition, info)
                    };
                    out.diagnostics.extend(partial_stats.iter().cloned());
                    match decoded {
                        Ok((bytes, tracking)) => {
                            let mut diagnostics = vec![
                                PhyDiagnostic::Ofdm {
                                    frequency_offset_hz: p.acquisition.frequency_rad * 20_000_000.
                                        / std::f32::consts::TAU,
                                    training_correlation: p.acquisition.correlation,
                                },
                                tracking,
                            ];
                            if let Some(fields) = p.ht {
                                diagnostics.push(PhyDiagnostic::HtSignal {
                                    fields,
                                    preamble_sample_index: p.start.sample_index,
                                });
                            }
                            if let Some(fields) = p.vht {
                                diagnostics.push(PhyDiagnostic::VhtSignalA {
                                    fields,
                                    preamble_sample_index: p.start.sample_index,
                                });
                            }
                            if let Some(fields) = vht_signal_b {
                                diagnostics.push(PhyDiagnostic::VhtSignalB {
                                    fields,
                                    preamble_sample_index: p.start.sample_index,
                                });
                            }
                            if let Some(stats) = coding_stats {
                                diagnostics.push(stats);
                            }
                            diagnostics.extend(partial_stats);
                            if p.greenfield {
                                diagnostics.push(PhyDiagnostic::HtGreenfield {
                                    preamble_sample_index: p.start.sample_index,
                                });
                            }
                            let frame = RecoveredFrame {
                                bytes,
                                link_type: LinkType::Ieee80211,
                                integrity: FrameIntegrity::ValidFcs,
                                config: config.clone(),
                                start: p.start,
                                end_sample_index: info.end_sample_index,
                                rate_bps: info.rate_bps,
                                diagnostics,
                            };
                            if let Err(error) = self.publish_psdu(
                                frame,
                                if p.vht.is_some() {
                                    Some(Aggregation::Vht)
                                } else {
                                    p.ht.filter(|f| f.aggregation).map(|_| Aggregation::Ht)
                                },
                                &mut out,
                            ) {
                                self.reset(ResetReason::Explicit);
                                return Err(error);
                            }
                        }
                        Err(()) => {
                            self.stats.rejected_frames =
                                self.stats.rejected_frames.saturating_add(1);
                            out.diagnostics.push(PhyDiagnostic::InvalidData);
                            if let Some(ldpc::rate::Error::Codeword {
                                index,
                                error:
                                    ldpc::Error::Nonconvergence {
                                        iterations,
                                        failed_checks,
                                    },
                            }) = coding_failure
                            {
                                out.diagnostics.push(PhyDiagnostic::LdpcNonconvergence {
                                    codeword: index,
                                    iterations,
                                    failed_checks,
                                });
                            }
                        }
                    }
                }
            }
            if let Some(event) = self.sync.push(sample, index) {
                match event {
                    SyncEvent::Acquired(a) => {
                        let mut start = chunk.position().clone();
                        start.sample_index = a.preamble_start;
                        let reserved: usize = self
                            .pending
                            .iter()
                            .flatten()
                            .map(|p| p.samples.capacity())
                            .sum();
                        let free = self.pending.iter().position(Option::is_none);
                        let Some(slot) = free
                            .filter(|_| config.max_buffer_samples.saturating_sub(reserved) >= 80)
                        else {
                            self.stats.rejected_frames =
                                self.stats.rejected_frames.saturating_add(1);
                            continue;
                        };
                        self.pending[slot] = Some(Pending {
                            acquisition: a,
                            start,
                            samples: Vec::with_capacity(80),
                            info: None,
                            ht: None,
                            vht: None,
                            ldpc: None,
                            greenfield: false,
                        });
                    }
                    SyncEvent::Failure(_) => {
                        self.stats.rejected_frames = self.stats.rejected_frames.saturating_add(1);
                    }
                    SyncEvent::Reset(_) => {}
                }
            }
        }
        Ok(out)
    }
}
fn feedback(state: &mut u8) -> u8 {
    let bit = ((*state >> 6) ^ (*state >> 3)) & 1;
    *state = ((*state << 1) | bit) & 127;
    bit
}
fn axis(label: usize, width: usize) -> f32 {
    let sign = 2. * (label & 1) as f32 - 1.;
    match width {
        1 => sign,
        2 => sign * (3. - 2. * ((label >> 1) & 1) as f32),
        3 => {
            sign * (4.
                - (2. * ((label >> 1) & 1) as f32 - 1.) * (3. - 2. * ((label >> 2) & 1) as f32))
        }
        // IEEE 802.11-2020 Figures 21-24..27; label bit zero is sent first.
        4 => {
            sign * (8.
                - (2. * ((label >> 1) & 1) as f32 - 1.)
                    * (4.
                        - (2. * ((label >> 2) & 1) as f32 - 1.)
                            * (3. - 2. * ((label >> 3) & 1) as f32)))
        }
        _ => unreachable!("validated modulation width"),
    }
}

fn constellation_energy(coded_bits: usize, carriers: usize) -> Result<f32, ()> {
    if carriers == 0 || coded_bits % carriers != 0 {
        return Err(());
    }
    match coded_bits / carriers {
        1 => Ok(1.),
        2 => Ok(2.),
        4 => Ok(10.),
        6 => Ok(42.),
        8 => Ok(170.),
        _ => Err(()),
    }
}
// Max-log bit metrics, weighted by channel power; punctures later have zero weight.
fn demap(value: f32, width: usize, scale: f32, weight: f32, out: &mut Vec<f32>) {
    for bit in 0..width {
        let mut distance = [f32::INFINITY; 2];
        for label in 0..1 << width {
            let d = (value - axis(label, width) / scale).powi(2);
            let b = (label >> bit) & 1;
            distance[b] = distance[b].min(d);
        }
        out.push((distance[0] - distance[1]) * weight);
    }
}
fn decode_data(
    samples: &[ComplexSample],
    a: &Acquisition,
    info: SignalInfo,
) -> Result<(Vec<u8>, PhyDiagnostic), ()> {
    decode_data_mode(samples, a, info, None)
}

pub(super) fn decode_data_mode(
    samples: &[ComplexSample],
    a: &Acquisition,
    info: SignalInfo,
    ht_guard: Option<usize>,
) -> Result<(Vec<u8>, PhyDiagnostic), ()> {
    decode_data_mode_with_format(samples, a, info, ht_guard, false, None)
}
fn decode_data_mode_with_format(
    samples: &[ComplexSample],
    a: &Acquisition,
    info: SignalInfo,
    ht_guard: Option<usize>,
    greenfield: bool,
    stbc_second: Option<&[ComplexSample; 64]>,
) -> Result<(Vec<u8>, PhyDiagnostic), ()> {
    let (coded, tracking) =
        demodulate_data(samples, a, info, ht_guard, true, greenfield, stbc_second)?;
    Ok((recover_bcc(&coded, info)?, tracking))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PilotFormat {
    LegacyOrHt,
    Greenfield,
    Vht,
}

fn demodulate_data(
    samples: &[ComplexSample],
    a: &Acquisition,
    info: SignalInfo,
    ht_guard: Option<usize>,
    bcc_interleaving: bool,
    greenfield: bool,
    stbc_second: Option<&[ComplexSample; 64]>,
) -> Result<(Vec<f32>, PhyDiagnostic), ()> {
    demodulate_data_format(
        samples,
        a,
        info,
        ht_guard,
        bcc_interleaving,
        if greenfield {
            PilotFormat::Greenfield
        } else {
            PilotFormat::LegacyOrHt
        },
        stbc_second,
    )
}

pub(super) fn decode_vht_bcc_data(
    samples: &[ComplexSample],
    a: &Acquisition,
    info: SignalInfo,
    guard: usize,
    sig_b: VhtSignalB20Fields,
    stbc_second: Option<&[ComplexSample; 64]>,
) -> Result<(Vec<u8>, PhyDiagnostic), ()> {
    let (coded, tracking) = demodulate_data_format(
        samples,
        a,
        info,
        Some(guard),
        true,
        PilotFormat::Vht,
        stbc_second,
    )?;
    Ok((recover_vht_bcc(&coded, info, sig_b)?, tracking))
}

pub(super) fn decode_vht_ldpc_data(
    samples: &[ComplexSample],
    a: &Acquisition,
    info: SignalInfo,
    guard: usize,
    sig_b: VhtSignalB20Fields,
    layout: ldpc_rate::Layout,
    stbc_second: Option<&[ComplexSample; 64]>,
) -> Result<(Vec<u8>, PhyDiagnostic, Vec<PhyDiagnostic>), ()> {
    if layout.symbols != info.data_symbols
        || layout.coded_bits_per_symbol != info.coded_bits_per_symbol
        || layout.payload_bits.checked_sub(16).ok_or(())? / 8 != info.psdu_bytes
    {
        return Err(());
    }
    let (coded, tracking) = demodulate_data_format(
        samples,
        a,
        info,
        Some(guard),
        false,
        PilotFormat::Vht,
        stbc_second,
    )?;
    // VHT PSDUs contain aggregates. Damaged codewords must not prevent recovery
    // of another MPDU, but every published MPDU still requires a valid FCS.
    let recovered = layout.recover_partial(&coded, 64).map_err(|_| ())?;
    let mut diagnostics = vec![PhyDiagnostic::Ldpc {
        codewords: layout.codewords,
        iterations: recovered.iterations,
    }];
    if recovered.failed_codewords != 0 {
        diagnostics.push(PhyDiagnostic::LdpcPartial {
            failed_codewords: recovered.failed_codewords,
        });
        if let Some(ldpc_rate::Error::Codeword {
            index,
            error:
                ldpc::Error::Nonconvergence {
                    iterations,
                    failed_checks,
                },
        }) = recovered.first_failure
        {
            diagnostics.push(PhyDiagnostic::LdpcNonconvergence {
                codeword: index,
                iterations,
                failed_checks,
            });
        }
    }
    let mut service = [0; 16];
    let crc = sig_b.expected_service_crc().ok_or(())?;
    for (i, bit) in service[8..].iter_mut().enumerate() {
        *bit = crc >> (7 - i) & 1;
    }
    let bytes = descramble_psdu_with_service(recovered.bits, info.psdu_bytes, &service)?;
    Ok((bytes, tracking, diagnostics))
}

fn demodulate_data_format(
    samples: &[ComplexSample],
    a: &Acquisition,
    info: SignalInfo,
    ht_guard: Option<usize>,
    bcc_interleaving: bool,
    format: PilotFormat,
    stbc_second: Option<&[ComplexSample; 64]>,
) -> Result<(Vec<f32>, PhyDiagnostic), ()> {
    let guard = ht_guard.unwrap_or(16);
    let stride = 64 + guard;
    let carriers = if ht_guard.is_some() { 52 } else { 48 };
    let columns = if ht_guard.is_some() { 13 } else { 16 };
    let edge: i32 = if ht_guard.is_some() { 28 } else { 26 };
    if samples.len() != info.data_symbols * stride || ![8, 16].contains(&guard) {
        return Err(());
    }
    if stbc_second.is_some() && (ht_guard.is_none() || info.data_symbols % 2 != 0) {
        return Err(());
    }
    let nbpsc = info.coded_bits_per_symbol / carriers;
    let scale = constellation_energy(info.coded_bits_per_symbol, carriers)?;
    let mut coded = Vec::with_capacity(info.data_symbols * info.coded_bits_per_symbol);
    let mut pilot_state = 127;
    for _ in 0..if format == PilotFormat::Vht {
        4
    } else if format == PilotFormat::Greenfield {
        2
    } else if ht_guard.is_some() {
        3
    } else {
        1
    } {
        feedback(&mut pilot_state);
    }
    let mut phase_slope = 0.;
    let mut preceding = [ComplexSample::ZERO; 64];
    let (mut sum_x, mut sum_xx, mut sum_y, mut sum_xy) = (0f64, 0f64, 0f64, 0f64);
    let (mut residual_energy, mut residual_weight) = (0f64, 0f64);
    for (symbol, samples) in samples.chunks_exact(stride).enumerate() {
        let time = std::array::from_fn(|n| {
            samples[guard + n].mul(ComplexSample::rotation(
                -a.frequency_rad
                    * (info.data_start + (symbol * stride + guard + n) as u64 - a.phase_origin)
                        as f32,
            ))
        });
        let bins = fft64(time);
        let polarity = 1. - 2. * feedback(&mut pilot_state) as f32;
        // Sampling-clock drift is a phase slope across subcarriers, not a
        // common carrier rotation. Remove the previous slope before measuring
        // residual pilot phases, then fit a weighted line each symbol.
        let pilots = std::array::from_fn::<_, 4, _>(|j| {
            let k: i32 = [-21, -7, 7, 21][j];
            let sign = [1., 1., 1., -1.][if ht_guard.is_some() {
                (symbol + j) % 4
            } else {
                j
            }];
            let bin = k.rem_euclid(64) as usize;
            // VHT training retains the combined pilot channel in `a`; its
            // pilots use the NSS1 pattern even with two STS. HT is different.
            let corrected = if let Some(second) = stbc_second.filter(|_| format != PilotFormat::Vht)
            {
                let prediction = a.channel[bin]
                    .scale([1., 1., -1., -1.][(symbol + j) % 4])
                    .add(second[bin].scale([1., -1., -1., 1.][(symbol + j) % 4]))
                    .scale(polarity);
                bins[bin].mul(prediction.conj())
            } else {
                bins[bin].mul(a.channel[bin].conj()).scale(sign * polarity)
            };
            let value = corrected.mul(ComplexSample::rotation(-phase_slope * k as f32));
            (k as f32, value)
        });
        let common = pilots
            .iter()
            .fold(ComplexSample::ZERO, |sum, (_, v)| sum.add(*v));
        if !common.power().is_finite() || common.power() < 1e-12 {
            return Err(());
        }
        let reference = common.phase();
        let (mut w, mut x, mut xx, mut y, mut xy) = (0., 0., 0., 0., 0.);
        for (k, value) in pilots {
            let weight = value.power().sqrt();
            let residual = value.mul(ComplexSample::rotation(-reference)).phase();
            w += weight;
            x += weight * k;
            xx += weight * k * k;
            y += weight * residual;
            xy += weight * k * residual;
        }
        let determinant = w * xx - x * x;
        if !determinant.is_finite() || determinant < 1e-12 {
            return Err(());
        }
        let slope_delta = (w * xy - x * y) / determinant;
        let intercept = reference + (y - slope_delta * x) / w;
        phase_slope += slope_delta;
        let time = (symbol * stride) as f64;
        sum_x += time;
        sum_xx += time * time;
        sum_y += phase_slope as f64;
        sum_xy += time * phase_slope as f64;
        for (k, value) in pilots {
            let weight = value.power().sqrt() as f64;
            let error = value
                .mul(ComplexSample::rotation(-intercept - slope_delta * k))
                .phase() as f64;
            residual_energy += weight * error * error;
            residual_weight += weight;
        }
        if stbc_second.is_some() && symbol % 2 == 0 {
            for k in (-edge..=edge).filter(|k| ![-21, -7, 0, 7, 21].contains(k)) {
                preceding[k.rem_euclid(64) as usize] = bins[k.rem_euclid(64) as usize]
                    .mul(ComplexSample::rotation(-intercept - phase_slope * k as f32));
            }
            continue;
        }
        let mut interleaved = Vec::with_capacity(info.coded_bits_per_symbol);
        let mut companion = stbc_second.map(|_| Vec::with_capacity(info.coded_bits_per_symbol));
        for k in (-edge..=edge).filter(|k| ![-21, -7, 0, 7, 21].contains(k)) {
            let rotation = ComplexSample::rotation(-intercept - phase_slope * k as f32);
            let k = k.rem_euclid(64) as usize;
            let power = a.channel[k].power() + stbc_second.map_or(0., |second| second[k].power());
            if !power.is_finite() || power < 1e-12 {
                interleaved.extend(std::iter::repeat(0.).take(nbpsc));
                if let Some(other) = &mut companion {
                    other.extend(std::iter::repeat(0.).take(nbpsc));
                }
                continue;
            }
            let v = if let Some(second) = stbc_second {
                let raw = bins[k].mul(rotation);
                let pair = stbc::recover_pair([a.channel[k], second[k]], [preceding[k], raw])
                    .map_err(|_| ())?;
                let other = companion.as_mut().ok_or(())?;
                demap(
                    pair[1].i,
                    if nbpsc == 1 { 1 } else { nbpsc / 2 },
                    scale.sqrt(),
                    power,
                    other,
                );
                if nbpsc > 1 {
                    demap(pair[1].q, nbpsc / 2, scale.sqrt(), power, other);
                }
                pair[0]
            } else {
                // Preserve the legacy equalizer operation order.
                bins[k]
                    .mul(a.channel[k].conj())
                    .mul(rotation)
                    .scale(1. / power)
            };
            if !v.power().is_finite() {
                return Err(());
            }
            demap(
                v.i,
                if nbpsc == 1 { 1 } else { nbpsc / 2 },
                scale.sqrt(),
                power,
                &mut interleaved,
            );
            if nbpsc > 1 {
                demap(v.q, nbpsc / 2, scale.sqrt(), power, &mut interleaved);
            }
        }
        for block in std::iter::once(interleaved).chain(companion) {
            let n = info.coded_bits_per_symbol;
            if !bcc_interleaving {
                if format == PilotFormat::Vht {
                    // Inverse VHT20 LDPC constellation-group permutation,
                    // 21.3.10.9.2: transmitted t(k)=4*(k%13)+floor(k/13).
                    for k in 0..52 {
                        let tone = 4 * (k % 13) + k / 13;
                        coded.extend_from_slice(&block[tone * nbpsc..(tone + 1) * nbpsc]);
                    }
                } else {
                    coded.extend(block);
                }
                continue;
            }
            let s = (nbpsc / 2).max(1);
            for k in 0..n {
                let i = (n / columns) * (k % columns) + k / columns;
                let j = s * (i / s) + (i + n - columns * i / n) % s;
                coded.push(block[j]);
            }
        }
    }
    let symbols = info.data_symbols as f64;
    let sampling_clock_offset_ppm = (info.data_symbols > 1).then(|| {
        let slope_per_sample =
            (symbols * sum_xy - sum_x * sum_y) / (symbols * sum_xx - sum_x * sum_x);
        (-slope_per_sample * 64. / std::f64::consts::TAU * 1e6) as f32
    });
    Ok((
        coded,
        PhyDiagnostic::OfdmTracking {
            sampling_clock_offset_ppm,
            pilot_residual_rms_rad: (residual_energy / residual_weight).sqrt() as f32,
            data_symbols: info.data_symbols,
        },
    ))
}

fn recover_bcc(coded: &[f32], info: SignalInfo) -> Result<Vec<u8>, ()> {
    recover_bcc_format(coded, info, None)
}

/// Single-encoder VHT DATA; caller supplies admitted timing/MCS dimensions.
/// This returns PSDU bytes, not FCS-qualified MPDUs or admitted aggregates.
#[allow(dead_code)] // Connected by the forthcoming VHT IQ integration.
pub(super) fn recover_vht_bcc(
    coded: &[f32],
    info: SignalInfo,
    sig_b: VhtSignalB20Fields,
) -> Result<Vec<u8>, ()> {
    if ![
        (52, 26),
        (104, 52),
        (104, 78),
        (208, 104),
        (208, 156),
        (312, 208),
        (312, 234),
        (312, 260),
        (416, 312),
    ]
    .contains(&(info.coded_bits_per_symbol, info.data_bits_per_symbol))
    {
        return Err(());
    }
    recover_bcc_format(coded, info, Some(sig_b))
}

fn recover_bcc_format(
    coded: &[f32],
    info: SignalInfo,
    vht: Option<VhtSignalB20Fields>,
) -> Result<Vec<u8>, ()> {
    let count = info
        .data_symbols
        .checked_mul(info.data_bits_per_symbol)
        .ok_or(())?;
    let expected_coded = info
        .data_symbols
        .checked_mul(info.coded_bits_per_symbol)
        .ok_or(())?;
    let psdu_end = info
        .psdu_bytes
        .checked_mul(8)
        .and_then(|n| n.checked_add(16))
        .ok_or(())?;
    if coded.len() != expected_coded
        || count < 22
        || psdu_end.checked_add(6).ok_or(())? > count
        || info.data_bits_per_symbol > usize::MAX / 6
        || info.coded_bits_per_symbol > usize::MAX / 5
    {
        return Err(());
    }
    let mut service = [0; 16];
    let mut scale = 1.;
    if let Some(sig_b) = vht {
        if info.psdu_bytes != (count - 22) / 8 || coded.iter().any(|m| !m.is_finite()) {
            return Err(());
        }
        let crc = sig_b.expected_service_crc().ok_or(())?;
        for (i, bit) in service[8..].iter_mut().enumerate() {
            *bit = (crc >> (7 - i)) & 1;
        }
        scale = coded.iter().map(|m| m.abs()).fold(0f32, f32::max);
        if scale == 0. {
            return Err(());
        }
    }
    let pattern: &[u8] = if info.data_bits_per_symbol * 2 == info.coded_bits_per_symbol {
        &[1, 1]
    } else if info.data_bits_per_symbol * 3 == info.coded_bits_per_symbol * 2 {
        &[1, 1, 1, 0]
    } else if info.data_bits_per_symbol * 4 == info.coded_bits_per_symbol * 3 {
        &[1, 1, 1, 0, 0, 1]
    } else if info.data_bits_per_symbol * 6 == info.coded_bits_per_symbol * 5 {
        &[1, 1, 1, 0, 0, 1, 1, 0, 0, 1]
    } else {
        return Err(());
    };
    let mut metric = [f32::INFINITY; 64];
    metric[0] = 0.;
    let mut history = Vec::new();
    history.try_reserve_exact(count).map_err(|_| ())?;
    history.resize(count, [0u8; 64]);
    let mut cursor = 0;
    for t in 0..count {
        let row = &mut history[t];
        let mut pair = [0.; 2];
        for j in 0..2 {
            if pattern[(2 * t + j) % pattern.len()] == 1 {
                pair[j] = *coded.get(cursor).ok_or(())? / scale;
                cursor += 1;
            }
        }
        let mut next = [f32::INFINITY; 64];
        for (state, cost) in metric.iter().enumerate() {
            for bit in 0..2 {
                let reg = (state << 1) | bit;
                let [a, b] = TRELLIS_SIGNS[reg];
                let score = cost - pair[0] * a - pair[1] * b;
                let dest = reg & 63;
                if score < next[dest] {
                    next[dest] = score;
                    row[dest] = state as u8;
                }
            }
        }
        // Future trellis extensions cannot change any surviving path's prefix.
        // Once every state has an invalid SERVICE field, no final traceback can
        // produce a deliverable frame. Keep all possible states, not just the
        // currently cheapest path, to preserve the full decoder's decisions.
        if t == 47 && !possible_service_prefix(&history[..48], &service) {
            return Err(());
        }
        let minimum = next.iter().copied().fold(f32::INFINITY, f32::min);
        for cost in &mut next {
            *cost -= minimum;
        }
        metric = next;
    }
    if cursor != coded.len() {
        return Err(());
    }
    let mut state = if vht.is_some() {
        0
    } else {
        (0..64)
            .min_by(|x, y| metric[*x].total_cmp(&metric[*y]))
            .ok_or(())?
    };
    let mut bits = vec![0; count];
    for t in (0..count).rev() {
        bits[t] = (state & 1) as u8;
        state = history[t][state] as usize;
    }
    let tail = if vht.is_some() { count - 6 } else { psdu_end };
    if bits[tail..tail + 6].iter().any(|b| *b != 0) {
        return Err(());
    }
    descramble_psdu_with_service(bits, info.psdu_bytes, &service)
}

pub(super) fn descramble_psdu(bits: Vec<u8>, psdu_bytes: usize) -> Result<Vec<u8>, ()> {
    descramble_psdu_with_service(bits, psdu_bytes, &[0; 16])
}

fn descramble_psdu_with_service(
    mut bits: Vec<u8>,
    psdu_bytes: usize,
    service: &[u8; 16],
) -> Result<Vec<u8>, ()> {
    let tail = psdu_bytes
        .checked_mul(8)
        .and_then(|n| n.checked_add(16))
        .ok_or(())?;
    if bits.len() < tail {
        return Err(());
    }
    let seed = (1u8..128)
        .find(|seed| {
            let mut s = *seed;
            bits[..7].iter().all(|b| *b == feedback(&mut s))
        })
        .ok_or(())?;
    let mut state = seed;
    for bit in &mut bits {
        *bit ^= feedback(&mut state);
    }
    // Receive PLCP discards padding after the PSDU (802.11-2007 17.3.12).
    // Errors in those bits do not invalidate an otherwise FCS-valid PSDU.
    if bits[..16] != *service {
        return Err(());
    }
    Ok(bits[16..tail]
        .chunks_exact(8)
        .map(|b| b.iter().enumerate().fold(0, |v, (i, b)| v | (b << i)))
        .collect())
}
fn possible_service_prefix(history: &[[u8; 64]], expected: &[u8; 16]) -> bool {
    for final_state in 0..64 {
        let mut state = final_state;
        for row in history[16..].iter().rev() {
            state = row[state] as usize;
        }
        let mut service = [0u8; 16];
        for t in (0..16).rev() {
            service[t] = (state & 1) as u8;
            state = history[t][state] as usize;
        }
        if (1u8..128).any(|mut seed| {
            service
                .iter()
                .zip(expected)
                .all(|(b, e)| *b == (feedback(&mut seed) ^ e))
        }) {
            return true;
        }
    }
    false
}

pub(super) fn valid_fcs(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let mut crc = !0u32;
    for byte in &bytes[..bytes.len() - 4] {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320u32 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    (!crc).to_le_bytes() == bytes[bytes.len() - 4..]
}

#[cfg(test)]
#[path = "vht_bcc_data_tests.rs"]
mod vht_bcc_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn radio_vht_qam_independent_metrics() {
        let index = include_str!("../../tests/fixtures/iq/vht-qam-index.tsv");
        assert_eq!(index.lines().skip(1).count(), 401);
        let scale = constellation_energy(416, 52).unwrap().sqrt();
        let mut energy = 0.;
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            assert_eq!(c.len(), 11);
            let i: f32 = c[0].parse().unwrap();
            let q: f32 = c[1].parse().unwrap();
            if c[2] != "-" {
                energy += (i * i + q * q) / scale.powi(2);
            }
            for weight in [0., 0.125, 1., 7.] {
                let mut out = Vec::new();
                demap(i / scale, 4, scale, weight, &mut out);
                demap(q / scale, 4, scale, weight, &mut out);
                assert_eq!(out.len(), 8);
                for (bit, actual) in out.into_iter().enumerate() {
                    let expected = c[3 + bit].parse::<f32>().unwrap() * weight;
                    assert!(
                        (actual - expected).abs() <= 2e-5 * (1. + expected.abs()),
                        "{row}: bit={bit} weight={weight} actual={actual} expected={expected}"
                    );
                    if weight == 0. {
                        assert_eq!(actual, 0.);
                    } else if c[2] != "-" {
                        assert_eq!(u8::from(actual > 0.), c[2].as_bytes()[bit] - b'0');
                    }
                }
            }
        }
        assert!((energy / 256. - 1.).abs() < 1e-6);
    }

    #[test]
    fn radio_qam_dimensions_and_lower_order_compatibility() {
        // Numeric indices are little-endian bit labels, matching demap().
        for (width, expected) in [
            (1, &[-1., 1.][..]),
            (2, &[-3., 3., -1., 1.][..]),
            (3, &[-7., 7., -1., 1., -5., 5., -3., 3.][..]),
        ] {
            for (label, &value) in expected.iter().enumerate() {
                assert_eq!(axis(label, width), value);
            }
        }
        for carriers in [48, 52] {
            for coded in 0..=carriers * 10 {
                let expected = [(1, 1.), (2, 2.), (4, 10.), (6, 42.), (8, 170.)]
                    .into_iter()
                    .find_map(|(bits, energy)| (coded == carriers * bits).then_some(energy));
                assert_eq!(constellation_energy(coded, carriers).ok(), expected);
            }
            assert!(constellation_energy(usize::MAX, carriers).is_err());
        }
        assert!(constellation_energy(0, 0).is_err());
    }

    #[test]
    fn radio_ht_bcc_independent_payload_kernel() {
        use sha2::{Digest, Sha256};
        let index = include_str!("../../tests/fixtures/iq/ht-bcc-index.tsv");
        assert_eq!(index.lines().skip(1).count(), 64);
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            assert_eq!(format!("{:x}", Sha256::digest(&bytes)), c[5]);
            assert_eq!(bytes.len(), c[6].parse::<usize>().unwrap() * 2);
            let samples: Vec<_> = bytes
                .chunks_exact(2)
                .map(|s| ComplexSample {
                    i: s[0] as i8 as f32 / 128.,
                    q: s[1] as i8 as f32 / 128.,
                })
                .collect();
            let expected: Vec<_> = c[4]
                .as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect();
            let mcs = c[1].parse::<usize>().unwrap();
            let guard = c[2].parse::<usize>().unwrap();
            let data_start = c[7].parse::<usize>().unwrap();
            let end = c[8].parse::<usize>().unwrap();
            let (nbpsc, ndbps) = [
                (1, 26),
                (2, 52),
                (2, 78),
                (4, 104),
                (4, 156),
                (6, 208),
                (6, 234),
                (6, 260),
            ][mcs];
            // This isolates DATA/training correctness, not packet acquisition:
            // timing and CFO are supplied by the independent fixture contract.
            let a = Acquisition {
                preamble_start: 37,
                signal_start: 357,
                phase_origin: 0,
                frequency_rad: if c[0].ends_with("offset") { 0.018 } else { 0. },
                coarse_frequency_rad: 0.,
                channel: [ComplexSample::ZERO; 64],
                correlation: 1.,
            };
            let a = ht::train_single_stream(
                &samples[data_start - 80..data_start],
                (data_start - 80) as u64,
                &a,
            )
            .unwrap();
            let info = SignalInfo {
                rate_bps: (ndbps as u64 * 20_000_000 / (64 + guard) as u64) as u32,
                coded_bits_per_symbol: 52 * nbpsc,
                data_bits_per_symbol: ndbps,
                psdu_bytes: expected.len(),
                data_symbols: c[3].parse().unwrap(),
                data_start: data_start as u64,
                end_sample_index: end as u64,
            };
            let (actual, _) = decode_data_mode(&samples[data_start..end], &a, info, Some(guard))
                .unwrap_or_else(|_| panic!("{} DATA rejected", c[0]));
            assert_eq!(actual, expected, "{}", c[0]);
            assert!(valid_fcs(&actual), "{}", c[0]);
        }
    }
    fn config() -> RxConfig {
        RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: 10000,
            max_buffer_samples: 120000,
            max_frame_bytes: 4095,
            max_pending_frames: 4,
            max_capture_samples: 1000000,
            max_duration: Duration::from_secs(1),
        }
    }
    fn feed(decoder: &mut impl PhyDecoder, bytes: &[u8], size: usize) -> DecodeOutput {
        feed_config(decoder, bytes, size, config()).unwrap()
    }
    fn feed_config(
        decoder: &mut impl PhyDecoder,
        bytes: &[u8],
        size: usize,
        config: RxConfig,
    ) -> RadioResult<DecodeOutput> {
        let mut result = DecodeOutput::default();
        for (sequence, part) in bytes.chunks(size * 2).enumerate() {
            let chunk = IqChunk::new(
                config.clone(),
                IqPosition {
                    epoch: 0,
                    sequence: sequence as u64,
                    sample_index: (sequence * size) as u64,
                    time_anchor: None,
                    discontinuity: None,
                },
                part.iter().map(|v| *v as i8).collect(),
            )
            .unwrap();
            let mut out = decoder.consume(IqEvent::Chunk(chunk))?;
            result.frames.append(&mut out.frames);
            result.diagnostics.append(&mut out.diagnostics);
        }
        let mut out = decoder.consume(IqEvent::End(StreamEnd::Eof)).unwrap();
        result.diagnostics.append(&mut out.diagnostics);
        Ok(result)
    }
    #[test]
    fn radio_vht_streaming_independent_iq() {
        for row in include_str!("../../tests/fixtures/iq/vht-bcc-iq-index.tsv")
            .lines()
            .skip(1)
        {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let expected: Vec<_> = c[8]
                .as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect();
            for size in [1, 79, 4096] {
                let out = feed(&mut WifiDecoder::new(), &bytes, size);
                assert_eq!(
                    out.frames.len(),
                    1,
                    "{} chunk={size}: {:?}",
                    c[0],
                    out.diagnostics
                );
                let frame = &out.frames[0];
                assert_eq!(frame.bytes, expected, "{} chunk={size}", c[0]);
                assert_eq!(frame.start.sample_index, 37);
                assert_eq!(frame.end_sample_index, c[11].parse::<u64>().unwrap());
                assert_eq!(frame.integrity, FrameIntegrity::ValidFcs);
                assert_eq!(frame.config, config());
                let bits = |s: &str| s.bytes().map(|b| b - b'0').collect::<Vec<_>>();
                assert!(frame.diagnostics.contains(&PhyDiagnostic::VhtSignalA {
                    fields: VhtSignalAFields::decode(&bits(c[5])).unwrap(),
                    preamble_sample_index: 37,
                }));
                assert!(frame.diagnostics.contains(&PhyDiagnostic::VhtSignalB {
                    fields: VhtSignalB20Fields::decode(&bits(c[6]), false).unwrap(),
                    preamble_sample_index: 37,
                }));
                assert!(frame.diagnostics.contains(&PhyDiagnostic::Ampdu {
                    delimiter_offset: 0,
                    control_bits: 1
                }));
            }
        }
    }
    #[test]
    fn radio_vht_streaming_aggregate_iq() {
        verify_vht_aggregates(
            include_str!("../../tests/fixtures/iq/vht-ampdu-iq-index.tsv"),
            54,
            false,
        );
    }
    #[test]
    fn radio_vht_ldpc_streaming_iq() {
        verify_vht_aggregates(
            include_str!("../../tests/fixtures/iq/vht-ldpc-iq-index.tsv"),
            73,
            true,
        );
    }
    #[test]
    fn radio_vht_ldpc_streaming_rejection_and_bounds() {
        for row in include_str!("../../tests/fixtures/iq/vht-ldpc-iq-invalid-index.tsv")
            .lines()
            .skip(1)
        {
            let name = row.split('\t').next().unwrap();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{name}.cs8",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            assert!(
                feed(&mut WifiDecoder::new(), &bytes, 79).frames.is_empty(),
                "{name}"
            );
        }
        let bytes = include_bytes!("../../tests/fixtures/iq/vht-ldpc-0-gi800-large.cs8");
        let mut cfg = config();
        cfg.max_chunk_samples = 79;
        cfg.max_buffer_samples = 800;
        assert!(feed_config(&mut WifiDecoder::new(), bytes, 79, cfg)
            .unwrap()
            .frames
            .is_empty());
        let out = feed(&mut WifiDecoder::new(), bytes, 79);
        assert_eq!(out.frames.len(), 1); // 4100-byte first MPDU exceeds config's4095 bound.
        assert_eq!(out.frames[0].bytes.len(), 56);
        let mut decoder = WifiDecoder::new();
        for (sequence, start, end) in [(0, 0, 700), (1, 701, bytes.len() / 2)] {
            let mut cfg = config();
            cfg.max_chunk_samples = bytes.len() / 2;
            let chunk = IqChunk::new(
                cfg,
                IqPosition {
                    epoch: 0,
                    sequence,
                    sample_index: start as u64,
                    time_anchor: None,
                    discontinuity: None,
                },
                bytes[2 * start..2 * end].iter().map(|b| *b as i8).collect(),
            )
            .unwrap();
            assert!(decoder
                .consume(IqEvent::Chunk(chunk))
                .unwrap()
                .frames
                .is_empty());
        }
        assert!(decoder
            .consume(IqEvent::End(StreamEnd::Eof))
            .unwrap()
            .frames
            .is_empty());
    }
    #[test]
    fn radio_vht_stbc_streaming_iq() {
        let rows = include_str!("../../tests/fixtures/iq/vht-stbc-iq-index.tsv");
        for coding in ["0", "1"] {
            let selected = std::iter::once(rows.lines().next().unwrap())
                .chain(
                    rows.lines()
                        .skip(1)
                        .filter(|r| r.split('\t').nth(9) == Some(coding)),
                )
                .collect::<Vec<_>>()
                .join("\n");
            verify_vht_aggregates(&selected, 55, coding == "1");
        }
        for row in include_str!("../../tests/fixtures/iq/vht-stbc-iq-invalid-index.tsv")
            .lines()
            .skip(1)
        {
            let name = row.split('\t').next().unwrap();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{name}.cs8",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            assert!(
                feed(&mut WifiDecoder::new(), &bytes, 79).frames.is_empty(),
                "{name}"
            );
        }
    }
    fn verify_vht_aggregates(rows: &str, count: usize, ldpc: bool) {
        let hex = |s: &str| {
            s.as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(rows.lines().skip(1).count(), count);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let expected: Vec<_> = c[5].split(',').map(hex).collect();
            let offsets: Vec<_> = c[4]
                .split(',')
                .map(|s| s.parse::<usize>().unwrap() - 4)
                .collect();
            let mut cfg = config();
            cfg.max_frame_bytes = 4100;
            cfg.max_pending_frames = 8;
            for size in [1, 79, 4096] {
                let out = feed_config(&mut WifiDecoder::new(), &bytes, size, cfg.clone()).unwrap();
                assert_eq!(
                    out.frames.iter().map(|f| &f.bytes).collect::<Vec<_>>(),
                    expected.iter().collect::<Vec<_>>(),
                    "{} chunk={size}: {:?}",
                    c[0],
                    out.diagnostics
                );
                for (frame, offset) in out.frames.iter().zip(&offsets) {
                    assert_eq!(
                        frame.diagnostics.iter().any(|d| matches!(
                            d,
                            PhyDiagnostic::LdpcPartial {
                                failed_codewords: 1
                            }
                        )),
                        c[0].ends_with("codeword")
                    );
                    assert_eq!(frame.diagnostics.iter().any(|d| matches!(d,PhyDiagnostic::Ldpc { codewords,iterations } if *codewords>0 && *iterations<=64*codewords)),ldpc);
                    assert!(frame.diagnostics.iter().any(|d| matches!(d,PhyDiagnostic::VhtSignalA { fields,.. } if matches!(fields.users,VhtSignalAUsers::Single {ldpc: coding,mcs,..} if coding==ldpc && mcs==c[1].parse::<u8>().unwrap()))));
                    assert!(frame.diagnostics.iter().any(|d| matches!(d,PhyDiagnostic::VhtSignalA { fields,.. } if fields.stbc==c[0].starts_with("vht-stbc-"))));
                    assert_eq!(frame.start.sample_index, 37);
                    assert_eq!(frame.end_sample_index, c[7].parse::<u64>().unwrap());
                    assert_eq!(frame.integrity, FrameIntegrity::ValidFcs);
                    assert!(frame.diagnostics.contains(&PhyDiagnostic::Ampdu {
                        delimiter_offset: *offset,
                        control_bits: 0
                    }));
                }
                assert_eq!(
                    out.diagnostics
                        .iter()
                        .any(|d| matches!(d, PhyDiagnostic::AmpduErrors { invalid_fcs: 1, .. })),
                    c[8] == "1",
                    "{}",
                    c[0]
                );
            }
        }
    }
    #[test]
    fn radio_vht_streaming_mixed_families() {
        let parts = [
            include_bytes!("../../tests/fixtures/iq/ofdm-6-clean.cs8").as_slice(),
            include_bytes!("../../tests/fixtures/iq/vht-bcc-8-gi400-case0-clean.cs8").as_slice(),
            include_bytes!("../../tests/fixtures/iq/ht-bcc-7-gi800-len100-clean.cs8").as_slice(),
        ];
        let mut combined = Vec::new();
        let mut expected = Vec::new();
        for part in parts {
            let shift = combined.len() as u64 / 2;
            let frames = feed(&mut WifiDecoder::new(), part, 79).frames;
            assert_eq!(frames.len(), 1);
            for frame in frames {
                expected.push((
                    frame.bytes,
                    frame.start.sample_index + shift,
                    frame.end_sample_index + shift,
                ));
            }
            combined.extend_from_slice(part);
            combined.extend_from_slice(&[0; 512]);
        }
        let mut cfg = config();
        cfg.max_pending_frames = 8;
        for size in [79, 4096, 10000] {
            let out = feed_config(&mut WifiDecoder::new(), &combined, size, cfg.clone()).unwrap();
            assert_eq!(
                out.frames
                    .into_iter()
                    .map(|f| (f.bytes, f.start.sample_index, f.end_sample_index))
                    .collect::<Vec<_>>(),
                expected,
                "chunk={size}"
            );
        }
    }
    #[test]
    fn radio_vht_streaming_rejection_and_bounds() {
        for row in include_str!("../../tests/fixtures/iq/vht-bcc-iq-invalid-index.tsv")
            .lines()
            .skip(1)
        {
            let name = row.split('\t').next().unwrap();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{name}.cs8",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            let out = feed(&mut WifiDecoder::new(), &bytes, 79);
            assert!(out.frames.is_empty(), "{name}");
        }
        let name = include_str!("../../tests/fixtures/iq/vht-bcc-iq-index.tsv")
            .lines()
            .nth(1)
            .unwrap()
            .split('\t')
            .next()
            .unwrap();
        let bytes = std::fs::read(format!(
            "{}/tests/fixtures/iq/{name}.cs8",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        assert!(feed(&mut LegacyWifiDecoder::new(), &bytes, 79)
            .frames
            .is_empty());
        for limit in [512, 800] {
            let mut cfg = config();
            cfg.max_buffer_samples = limit;
            cfg.max_chunk_samples = 79;
            let out = feed_config(&mut WifiDecoder::new(), &bytes, 79, cfg).unwrap();
            assert!(out.frames.is_empty());
        }
        let mut cfg = config();
        cfg.max_frame_bytes = 4;
        let out = feed_config(&mut WifiDecoder::new(), &bytes, 79, cfg).unwrap();
        assert!(out.frames.is_empty());
        assert!(out.diagnostics.iter().any(|d| matches!(
            d,
            PhyDiagnostic::AmpduErrors {
                oversized_mpdus: 1,
                ..
            }
        )));
        let mut decoder = WifiDecoder::new();
        for (sequence, range) in [(0, 0..700), (1, 701..bytes.len() / 2)] {
            let chunk = IqChunk::new(
                config(),
                IqPosition {
                    epoch: 3,
                    sequence,
                    sample_index: range.start as u64,
                    time_anchor: None,
                    discontinuity: None,
                },
                bytes[2 * range.start..2 * range.end]
                    .iter()
                    .map(|b| *b as i8)
                    .collect(),
            )
            .unwrap();
            assert!(decoder
                .consume(IqEvent::Chunk(chunk))
                .unwrap()
                .frames
                .is_empty());
        }
        assert!(decoder
            .consume(IqEvent::End(StreamEnd::Eof))
            .unwrap()
            .frames
            .is_empty());
        let mut doubled = bytes.clone();
        doubled.extend_from_slice(&bytes);
        let mut cfg = config();
        cfg.max_pending_frames = 3; // one output plus two child slots
        cfg.max_chunk_samples = doubled.len() / 2;
        let result = feed_config(&mut WifiDecoder::new(), &doubled, doubled.len() / 2, cfg);
        assert!(matches!(
            result,
            Err(RadioError::Limit {
                context: "VHT aggregate pending frames",
                ..
            })
        ));
    }
    #[test]
    fn radio_ht_extension_training_streaming_independent_iq() {
        let rows: Vec<_> = include_str!("../../tests/fixtures/iq/ht-extension-index.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 540);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let expected: Vec<_> = c[4]
                .as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect();
            for size in [1, 79, 4096] {
                let out = feed(&mut WifiDecoder::new(), &bytes, size);
                assert_eq!(
                    out.frames.len(),
                    1,
                    "{} chunk={size}: {:?}",
                    c[0],
                    out.diagnostics
                );
                let frame = &out.frames[0];
                assert_eq!(frame.bytes, expected, "{} chunk={size}", c[0]);
                assert_eq!(frame.integrity, FrameIntegrity::ValidFcs);
                assert_eq!(frame.start.sample_index, 37);
                assert_eq!(frame.end_sample_index, c[8].parse::<u64>().unwrap());
                assert!(frame.diagnostics.iter().any(
                    |d| matches!(d,PhyDiagnostic::HtSignal{fields,..}
                    if fields.mcs==c[1].parse::<u8>().unwrap() && fields.ldpc==(c[9]=="1")
                        && fields.stbc==c[11].parse::<u8>().unwrap()
                        && fields.extension_spatial_streams==c[12].parse::<u8>().unwrap()
                        && !fields.not_sounding)
                ));
                assert_eq!(
                    frame
                        .diagnostics
                        .iter()
                        .any(|d| matches!(d, PhyDiagnostic::HtGreenfield { .. })),
                    c[10] == "1"
                );
            }
        }
    }
    #[test]
    fn radio_ht_extension_training_bounds_and_gaps() {
        let rows: Vec<_> = include_str!("../../tests/fixtures/iq/ht-extension-index.tsv")
            .lines()
            .skip(1)
            .filter(|row| {
                let c: Vec<_> = row.split('\t').collect();
                c[1] == "0" && c[9] == "0" && c[0].ends_with("len100-clean")
            })
            .collect();
        assert_eq!(rows.len(), 15);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let data_start = c[7].parse::<usize>().unwrap();
            let count = [0, 1, 2, 4][c[12].parse::<usize>().unwrap()];
            let first_extension = data_start - 80 * count;
            for stop in [first_extension + 1, data_start - 1] {
                for size in [1, 79, 4096] {
                    let out = feed(&mut WifiDecoder::new(), &bytes[..2 * stop], size);
                    assert!(out.frames.is_empty(), "{} stop={stop}", c[0]);
                    assert!(
                        out.diagnostics.contains(&PhyDiagnostic::TruncatedFrame),
                        "{} stop={stop}: {:?}",
                        c[0],
                        out.diagnostics
                    );
                }
            }
            for (buffer, limit) in [(512, 4095), (120000, 99)] {
                let mut cfg = config();
                cfg.max_chunk_samples = 128;
                cfg.max_buffer_samples = buffer;
                cfg.max_frame_bytes = limit;
                let out = feed_config(&mut WifiDecoder::new(), &bytes, 79, cfg).unwrap();
                assert!(out.frames.is_empty());
                assert!(
                    out.diagnostics.contains(&PhyDiagnostic::UnsupportedPhy),
                    "{}: {:?}",
                    c[0],
                    out.diagnostics
                );
            }
            let mut decoder = WifiDecoder::new();
            let gap = first_extension + 40;
            for (sequence, range) in [(0, 0..gap), (1, gap + 1..bytes.len() / 2)] {
                let chunk = IqChunk::new(
                    config(),
                    IqPosition {
                        epoch: 3,
                        sequence,
                        sample_index: range.start as u64,
                        time_anchor: None,
                        discontinuity: None,
                    },
                    bytes[2 * range.start..2 * range.end]
                        .iter()
                        .map(|b| *b as i8)
                        .collect(),
                )
                .unwrap();
                assert!(
                    decoder
                        .consume(IqEvent::Chunk(chunk))
                        .unwrap()
                        .frames
                        .is_empty(),
                    "{}",
                    c[0]
                );
            }
            assert!(decoder
                .consume(IqEvent::End(StreamEnd::Eof))
                .unwrap()
                .frames
                .is_empty());
        }
    }
    #[test]
    fn radio_ht_stbc_streaming_independent_iq() {
        let rows: Vec<_> = include_str!("../../tests/fixtures/iq/ht-stbc-index.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 192);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let expected: Vec<_> = c[4]
                .as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect();
            for size in [1, 79, 4096] {
                let out = feed(&mut WifiDecoder::new(), &bytes, size);
                assert_eq!(
                    out.frames.len(),
                    1,
                    "{} chunk={size}: {:?}",
                    c[0],
                    out.diagnostics
                );
                let frame = &out.frames[0];
                assert_eq!(frame.bytes, expected, "{} chunk={size}", c[0]);
                assert_eq!(frame.integrity, FrameIntegrity::ValidFcs);
                assert_eq!(frame.start.sample_index, 37);
                assert_eq!(frame.end_sample_index, c[8].parse::<u64>().unwrap());
                assert!(frame.diagnostics.iter().any(|d|matches!(d,
                    PhyDiagnostic::HtSignal {fields,..} if fields.stbc==1 && fields.ldpc==(c[9]=="1")
                        && fields.mcs==c[1].parse::<u8>().unwrap())));
                assert_eq!(
                    frame
                        .diagnostics
                        .iter()
                        .any(|d| matches!(d, PhyDiagnostic::HtGreenfield { .. })),
                    c[10] == "1"
                );
            }
            assert!(feed(&mut LegacyOfdmDecoder::new(), &bytes, 4096)
                .frames
                .is_empty());
        }
    }
    #[test]
    fn radio_ht_stbc_integrity_and_bounds() {
        let rows: Vec<_> = include_str!("../../tests/fixtures/iq/ht-stbc-invalid-index.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 9);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            for size in [1, 79, 4096] {
                let out = feed(&mut WifiDecoder::new(), &bytes, size);
                assert!(out.frames.is_empty(), "{} chunk={size}", c[0]);
                if c[1] == "header_crc" {
                    assert!(
                        !out.diagnostics
                            .iter()
                            .any(|d| matches!(d, PhyDiagnostic::HtSignal { .. })),
                        "{}: {:?}",
                        c[0],
                        out.diagnostics
                    );
                    continue;
                }
                let expected = match c[1] {
                    "stbc2" | "mcs8" | "extension3" => PhyDiagnostic::UnsupportedPhy,
                    "invalid_fcs" => PhyDiagnostic::InvalidFcs,
                    "truncated_data" => PhyDiagnostic::TruncatedFrame,
                    "zero_training" | "invalid_service" | "nonconvergence" => {
                        PhyDiagnostic::InvalidData
                    }
                    other => panic!("unknown STBC negative case {other}"),
                };
                assert!(
                    out.diagnostics.contains(&expected),
                    "{} chunk={size}: {:?}",
                    c[0],
                    out.diagnostics
                );
            }
        }
    }
    #[test]
    fn radio_ht_greenfield_streaming_independent_iq() {
        let rows: Vec<_> = include_str!("../../tests/fixtures/iq/ht-greenfield-index.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 64);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let expected: Vec<_> = c[4]
                .as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect();
            for size in [1, 79, 4096] {
                let out = feed(&mut WifiDecoder::new(), &bytes, size);
                assert_eq!(
                    out.frames.len(),
                    1,
                    "{} chunk={size}: {:?}",
                    c[0],
                    out.diagnostics
                );
                let frame = &out.frames[0];
                assert_eq!(frame.bytes, expected, "{} chunk={size}", c[0]);
                assert_eq!(frame.integrity, FrameIntegrity::ValidFcs);
                assert_eq!(frame.start.sample_index, 37);
                assert_eq!(frame.end_sample_index, c[8].parse::<u64>().unwrap());
                assert!(frame.diagnostics.iter().any(|d| matches!(
                    d,
                    PhyDiagnostic::HtGreenfield {
                        preamble_sample_index: 37
                    }
                )));
                assert!(frame.diagnostics.iter().any(|d| matches!(d,
                    PhyDiagnostic::HtSignal { fields, .. } if usize::from(fields.mcs) == c[1].parse::<usize>().unwrap()
                        && fields.ldpc == (c[9] == "1") && !fields.short_guard_interval)));
            }
            assert!(feed(&mut LegacyOfdmDecoder::new(), &bytes, 4096)
                .frames
                .is_empty());
        }
    }
    #[test]
    fn radio_ht_greenfield_integrity_and_bounds() {
        let rows: Vec<_> = include_str!("../../tests/fixtures/iq/ht-greenfield-invalid-index.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 8);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let expected = match c[1] {
                "header_crc" => PhyDiagnostic::InvalidHeader,
                "invalid_service" => PhyDiagnostic::InvalidData,
                "invalid_fcs" => PhyDiagnostic::InvalidFcs,
                _ => PhyDiagnostic::UnsupportedPhy,
            };
            for size in [1, 79, 4096] {
                let out = feed(&mut WifiDecoder::new(), &bytes, size);
                assert!(out.frames.is_empty(), "{}", c[0]);
                assert!(
                    out.diagnostics.contains(&expected),
                    "{}: {:?}",
                    c[0],
                    out.diagnostics
                );
            }
        }
        let bytes = include_bytes!("../../tests/fixtures/iq/ht-greenfield-7-ldpc-len100-clean.cs8");
        for stop in [250, 400, 516, 550] {
            let out = feed(&mut WifiDecoder::new(), &bytes[..2 * stop], 79);
            assert!(out.frames.is_empty());
            assert!(
                out.diagnostics.contains(&PhyDiagnostic::TruncatedFrame),
                "stop={stop}"
            );
        }
        let bounded_bytes =
            include_bytes!("../../tests/fixtures/iq/ht-greenfield-0-ldpc-len100-clean.cs8");
        for (buffer, limit) in [(512, 4095), (120000, 99)] {
            let mut config = config();
            config.max_chunk_samples = 128;
            config.max_buffer_samples = buffer;
            config.max_frame_bytes = limit;
            let out = feed_config(&mut WifiDecoder::new(), bounded_bytes, 79, config).unwrap();
            assert!(out.frames.is_empty());
            assert!(out.diagnostics.contains(&PhyDiagnostic::UnsupportedPhy));
        }
        let mut decoder = WifiDecoder::new();
        for (sequence, range) in [(0, 0..550), (1, 551..bytes.len() / 2)] {
            let chunk = IqChunk::new(
                config(),
                IqPosition {
                    epoch: 3,
                    sequence,
                    sample_index: range.start as u64,
                    time_anchor: None,
                    discontinuity: None,
                },
                bytes[2 * range.start..2 * range.end]
                    .iter()
                    .map(|b| *b as i8)
                    .collect(),
            )
            .unwrap();
            assert!(decoder
                .consume(IqEvent::Chunk(chunk))
                .unwrap()
                .frames
                .is_empty());
        }
        assert!(decoder
            .consume(IqEvent::End(StreamEnd::Eof))
            .unwrap()
            .frames
            .is_empty());
    }
    #[test]
    fn radio_ht_ampdu_independent_iq() {
        use sha2::{Digest, Sha256};
        fn hex(value: &str) -> Vec<u8> {
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect()
        }
        let rows: Vec<_> = include_str!("../../tests/fixtures/iq/ht-ampdu-index.tsv")
            .lines()
            .skip(1)
            .chain(
                include_str!("../../tests/fixtures/iq/ht-greenfield-ampdu-index.tsv")
                    .lines()
                    .skip(1),
            )
            .collect();
        let rows: Vec<_> = rows
            .into_iter()
            .chain(
                include_str!("../../tests/fixtures/iq/ht-stbc-ampdu-index.tsv")
                    .lines()
                    .skip(1),
            )
            .chain(
                include_str!("../../tests/fixtures/iq/ht-extension-ampdu-index.tsv")
                    .lines()
                    .skip(1),
            )
            .collect();
        assert_eq!(rows.len(), 208);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            assert_eq!(format!("{:x}", Sha256::digest(&bytes)), c[7]);
            let expected: Vec<Vec<u8>> = c[6].split(',').map(hex).collect();
            let offsets: Vec<usize> = c[5]
                .split(',')
                .map(|s| s.parse::<usize>().unwrap() - 4)
                .collect();
            let mut config = config();
            config.max_pending_frames = 100;
            config.max_frame_bytes = 64; // Less than the aggregate, enough for each MPDU.
            if c[0].ends_with("damaged_codeword") {
                config.max_frame_bytes = 2048;
            }
            for size in [1, 79, 4096] {
                let out =
                    feed_config(&mut WifiDecoder::new(), &bytes, size, config.clone()).unwrap();
                assert_eq!(
                    out.frames.iter().map(|f| &f.bytes).collect::<Vec<_>>(),
                    expected.iter().collect::<Vec<_>>(),
                    "{}, chunk={size}: {:?}",
                    c[0],
                    out.diagnostics
                );
                for (frame, offset) in out.frames.iter().zip(&offsets) {
                    assert_eq!(
                        frame
                            .diagnostics
                            .iter()
                            .any(|d| matches!(d, PhyDiagnostic::HtGreenfield { .. })),
                        c[0].starts_with("ht-greenfield") || c[0].contains("-gf-")
                    );
                    assert_eq!(frame.start.sample_index, 37, "{}", c[0]);
                    assert_eq!(frame.end_sample_index, c[8].parse::<u64>().unwrap());
                    assert_eq!(frame.config, config);
                    assert_eq!(frame.integrity, FrameIntegrity::ValidFcs);
                    let expected_stbc = if c.len() == 12 {
                        c[9].parse::<u8>().unwrap()
                    } else {
                        u8::from(c[0].starts_with("ht-stbc"))
                    };
                    let expected_extension = if c.len() == 12 {
                        c[10].parse::<u8>().unwrap()
                    } else {
                        0
                    };
                    assert!(frame.diagnostics.iter().any(|d| matches!(d,
                        PhyDiagnostic::HtSignal { fields, .. }
                            if fields.stbc == expected_stbc && fields.extension_spatial_streams==expected_extension)));
                    assert!(frame.diagnostics.contains(&PhyDiagnostic::Ampdu {
                        delimiter_offset: *offset,
                        control_bits: 0
                    }));
                    assert!(frame.diagnostics.iter().any(|d| matches!(d, PhyDiagnostic::HtSignal { fields, .. } if fields.aggregation && fields.ldpc == (c[3]=="1") && fields.mcs == c[1].parse::<u8>().unwrap() && fields.short_guard_interval == (c[2]=="8"))));
                }
                if c[0].ends_with("bad_fcs") {
                    assert!(
                        out.diagnostics.iter().any(|d| matches!(
                            d,
                            PhyDiagnostic::AmpduErrors { invalid_fcs: 1, .. }
                        )),
                        "{}: {:?}",
                        c[0],
                        out.diagnostics
                    );
                }
                if c[0].ends_with("damaged_codeword") {
                    assert!(out.frames[0].diagnostics.iter().any(|d| matches!(d,PhyDiagnostic::LdpcPartial { failed_codewords } if *failed_codewords > 0)),"{}",c[0]);
                    assert!(
                        out.frames[0].diagnostics.iter().any(|d| matches!(
                            d,
                            PhyDiagnostic::LdpcNonconvergence {
                                codeword: 2,
                                iterations: 64,
                                ..
                            }
                        )),
                        "{}",
                        c[0]
                    );
                }
            }
        }
    }
    #[test]
    fn radio_ht_ampdu_output_bounds_and_continuity() {
        for bytes in [
            include_bytes!("../../tests/fixtures/iq/ht-ampdu-7-gi800-bcc-duplicate.cs8").as_slice(),
            include_bytes!("../../tests/fixtures/iq/ht-ampdu-7-gi800-ldpc-duplicate.cs8")
                .as_slice(),
            include_bytes!("../../tests/fixtures/iq/ht-greenfield-ampdu-7-bcc.cs8").as_slice(),
            include_bytes!("../../tests/fixtures/iq/ht-greenfield-ampdu-7-ldpc.cs8").as_slice(),
            include_bytes!("../../tests/fixtures/iq/ht-stbc-ampdu-7-bcc-mf-gi400.cs8").as_slice(),
            include_bytes!("../../tests/fixtures/iq/ht-stbc-ampdu-7-ldpc-mf-gi800.cs8").as_slice(),
            include_bytes!("../../tests/fixtures/iq/ht-stbc-ampdu-7-bcc-gf-gi800.cs8").as_slice(),
            include_bytes!("../../tests/fixtures/iq/ht-stbc-ampdu-7-ldpc-gf-gi800.cs8").as_slice(),
            include_bytes!(
                "../../tests/fixtures/iq/ht-extension-ampdu-7-bcc-mf-gi800-stbc0-ess3.cs8"
            )
            .as_slice(),
            include_bytes!(
                "../../tests/fixtures/iq/ht-extension-ampdu-7-ldpc-gf-gi800-stbc0-ess3.cs8"
            )
            .as_slice(),
            include_bytes!(
                "../../tests/fixtures/iq/ht-extension-ampdu-7-ldpc-mf-gi400-stbc1-ess2.cs8"
            )
            .as_slice(),
            include_bytes!(
                "../../tests/fixtures/iq/ht-extension-ampdu-7-bcc-gf-gi800-stbc1-ess2.cs8"
            )
            .as_slice(),
        ] {
            let mut config = config();
            config.max_pending_frames = 3;
            assert!(matches!(
                feed_config(&mut WifiDecoder::new(), bytes, 4096, config.clone()),
                Err(RadioError::Limit {
                    context: "HT aggregate pending frames",
                    limit: 1,
                    actual: 2
                })
            ));
            config.max_pending_frames = 4;
            let out = feed_config(&mut WifiDecoder::new(), bytes, 4096, config.clone()).unwrap();
            assert_eq!(out.frames.len(), 2);
            config.max_frame_bytes = 55;
            let out = feed_config(&mut WifiDecoder::new(), bytes, 4096, config.clone()).unwrap();
            assert!(out.frames.is_empty());
            assert!(out.diagnostics.iter().any(|d| matches!(
                d,
                PhyDiagnostic::AmpduErrors {
                    oversized_mpdus: 2,
                    ..
                }
            )));
            config.max_frame_bytes = 56;
            config.max_pending_frames = 6;
            let mut paired = bytes.to_vec();
            paired.extend_from_slice(bytes);
            // Both PPDUs in one source chunk; available output shrinks between
            // them, but this must not look like an IQ reconfiguration.
            let out = feed_config(&mut WifiDecoder::new(), &paired, 10000, config.clone()).unwrap();
            assert_eq!(out.frames.len(), 4, "{:?}", out.diagnostics);
            assert_eq!(
                out.frames[2].start.sample_index,
                37 + bytes.len() as u64 / 2
            );
            assert!(!out.diagnostics.iter().any(|d| matches!(
                d,
                PhyDiagnostic::Reset(ResetReason::Gap(Discontinuity {
                    reason: GapReason::Reconfiguration,
                    ..
                }))
            )));
            config.max_pending_frames = 5;
            assert!(matches!(
                feed_config(&mut WifiDecoder::new(), &paired, 10000, config),
                Err(RadioError::Limit { .. })
            ));
        }
    }
    #[test]
    fn radio_ht_bcc_bounds_and_truncation() {
        let bytes = include_bytes!("../../tests/fixtures/iq/ht-bcc-0-gi800-len100-clean.cs8");
        let end = bytes.len() / 2 - 64;
        for cut in [597, 677, 756, 757, end - 1] {
            let out = feed(&mut WifiDecoder::new(), &bytes[..cut * 2], 79);
            assert!(out.frames.is_empty(), "cut={cut}");
            assert!(
                out.diagnostics.contains(&PhyDiagnostic::TruncatedFrame),
                "cut={cut}: {:?}",
                out.diagnostics
            );
        }
        for max_frame in [99, 100] {
            let mut config = config();
            config.max_frame_bytes = max_frame;
            config.max_buffer_samples = 4096;
            config.max_chunk_samples = 4096;
            let mut decoder = WifiDecoder::new();
            let out = decoder
                .consume(IqEvent::Chunk(
                    IqChunk::new(
                        config,
                        IqPosition {
                            epoch: 3,
                            sequence: 0,
                            sample_index: 1_000_000,
                            time_anchor: None,
                            discontinuity: None,
                        },
                        bytes.iter().map(|v| *v as i8).collect(),
                    )
                    .unwrap(),
                ))
                .unwrap();
            assert_eq!(
                out.frames.len(),
                usize::from(max_frame == 100),
                "max_frame={max_frame}: {:?}",
                out.diagnostics
            );
            if let Some(frame) = out.frames.first() {
                assert_eq!(frame.start.epoch, 3);
                assert_eq!(frame.start.sample_index, 1_000_037);
                assert_eq!(frame.end_sample_index, 1_000_000 + end as u64);
            }
        }
        let mut zero_data = bytes.to_vec();
        zero_data[757 * 2..end * 2].fill(0);
        let out = feed(&mut WifiDecoder::new(), &zero_data, 79);
        assert!(out.frames.is_empty());
        assert!(out.diagnostics.contains(&PhyDiagnostic::InvalidData));
    }
    #[test]
    fn radio_ht_bcc_streaming_independent_iq() {
        verify_ht_streaming(
            include_str!("../../tests/fixtures/iq/ht-bcc-index.tsv"),
            false,
        );
    }
    #[test]
    fn radio_ht_ldpc_streaming_independent_iq() {
        verify_ht_streaming(
            include_str!("../../tests/fixtures/iq/ht-ldpc-index.tsv"),
            true,
        );
    }
    #[test]
    fn radio_ht_ldpc_independent_rejection_stages() {
        use sha2::{Digest, Sha256};
        for row in include_str!("../../tests/fixtures/iq/ht-ldpc-invalid-index.tsv")
            .lines()
            .skip(1)
        {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            assert_eq!(format!("{:x}", Sha256::digest(&bytes)), c[2]);
            for size in [1, 4096] {
                let out = feed(&mut WifiDecoder::new(), &bytes, size);
                assert!(out.frames.is_empty(), "{}", c[0]);
                assert!(out
                    .diagnostics
                    .iter()
                    .any(|d| matches!(d,PhyDiagnostic::HtSignal{fields,..} if fields.ldpc)));
                assert_eq!(
                    out.diagnostics.contains(&PhyDiagnostic::InvalidFcs),
                    c[1] == "invalid_fcs",
                    "{}: {:?}",
                    c[0],
                    out.diagnostics
                );
                assert_eq!(
                    out.diagnostics.contains(&PhyDiagnostic::InvalidData),
                    c[1] != "invalid_fcs",
                    "{}: {:?}",
                    c[0],
                    out.diagnostics
                );
                assert_eq!(out.diagnostics.iter().any(|d|matches!(d,PhyDiagnostic::LdpcNonconvergence{iterations:64,failed_checks,..} if *failed_checks>0)),c[1]=="nonconvergence","{}: {:?}",c[0],out.diagnostics);
            }
        }
    }
    #[test]
    fn radio_ht_ldpc_truncation_and_gap() {
        let bytes = include_bytes!("../../tests/fixtures/iq/ht-ldpc-7-gi800-len100-clean.cs8");
        let end = bytes.len() / 2 - 64;
        for cut in [597, 677, 756, 757, end - 1] {
            let out = feed(&mut WifiDecoder::new(), &bytes[..cut * 2], 79);
            assert!(out.frames.is_empty());
            assert!(
                out.diagnostics.contains(&PhyDiagnostic::TruncatedFrame),
                "cut={cut}: {:?}",
                out.diagnostics
            );
        }
        let mut decoder = WifiDecoder::new();
        for (sequence, start, stop) in [(0, 0, 757), (1, 774, bytes.len() / 2)] {
            let out = decoder
                .consume(IqEvent::Chunk(
                    IqChunk::new(
                        config(),
                        IqPosition {
                            epoch: 0,
                            sequence,
                            sample_index: start as u64,
                            time_anchor: None,
                            discontinuity: if sequence == 1 {
                                Some(Discontinuity {
                                    reason: GapReason::QueueOverflow,
                                    loss: SampleLoss::Known(17),
                                })
                            } else {
                                None
                            },
                        },
                        bytes[start * 2..stop * 2]
                            .iter()
                            .map(|b| *b as i8)
                            .collect(),
                    )
                    .unwrap(),
                ))
                .unwrap();
            assert!(out.frames.is_empty());
            if sequence == 1 {
                assert!(out.diagnostics.contains(&PhyDiagnostic::TruncatedFrame));
            }
        }
        assert_eq!(decoder.ofdm_stats().valid_frames, 0);
    }
    fn verify_ht_streaming(index: &str, ldpc: bool) {
        use sha2::{Digest, Sha256};
        assert_eq!(index.lines().skip(1).count(), 64);
        for row in index.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            assert_eq!(format!("{:x}", Sha256::digest(&bytes)), c[5]);
            assert_eq!(bytes.len(), c[6].parse::<usize>().unwrap() * 2);
            let expected: Vec<_> = c[4]
                .as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect();
            for size in [1, 79, 4096] {
                let mut decoder = WifiDecoder::new();
                let out = feed(&mut decoder, &bytes, size);
                assert_eq!(
                    out.frames.len(),
                    1,
                    "{} chunk={size}: {:?}",
                    c[0],
                    out.diagnostics
                );
                let frame = &out.frames[0];
                assert_eq!(frame.bytes, expected, "{} chunk={size}", c[0]);
                assert!(valid_fcs(&frame.bytes));
                assert_eq!(frame.diagnostics.iter().any(|d|matches!(d,PhyDiagnostic::Ldpc{codewords,iterations} if *codewords>0 && *iterations<=64*codewords)),ldpc);
                assert!(frame
                    .diagnostics
                    .iter()
                    .any(|d| matches!(d,PhyDiagnostic::HtSignal{fields,..} if fields.ldpc==ldpc)));
                assert_eq!(frame.start.sample_index, 37);
                assert_eq!(frame.end_sample_index, c[8].parse::<u64>().unwrap());
                assert!(frame.diagnostics.iter().any(|d| matches!(d,PhyDiagnostic::HtSignal{fields,..} if fields.mcs == c[1].parse::<u8>().unwrap())));
                assert_eq!(decoder.ofdm_stats().valid_frames, 1);
            }
        }
    }
    #[test]
    fn radio_ht_mixed_headers_from_independent_iq() {
        use sha2::{Digest, Sha256};
        let index = include_str!("../../tests/fixtures/iq/ht-mixed-index.tsv");
        assert_eq!(index.lines().skip(1).count(), 32);
        for row in index.lines().skip(1) {
            let columns: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                columns[0]
            ))
            .unwrap();
            assert_eq!(format!("{:x}", Sha256::digest(&bytes)), columns[3]);
            assert_eq!(bytes.len(), columns[4].parse::<usize>().unwrap() * 2);
            let bits: Vec<_> = columns[1].bytes().map(|b| b - b'0').collect();
            for size in [1, 79, 4096] {
                let out = feed(&mut LegacyOfdmDecoder::new(), &bytes, size);
                assert!(out.frames.is_empty(), "{}", columns[0]);
                let headers: Vec<_> = out
                    .diagnostics
                    .iter()
                    .filter_map(|d| match d {
                        PhyDiagnostic::HtSignal {
                            fields,
                            preamble_sample_index,
                        } => Some((*fields, *preamble_sample_index)),
                        _ => None,
                    })
                    .collect();
                if ["clean", "offset"].contains(&columns[2]) {
                    assert_eq!(
                        headers,
                        [(HtSignalFields::decode(&bits).unwrap(), 37)],
                        "{} chunk={size}",
                        columns[0]
                    );
                    assert!(out.diagnostics.contains(&PhyDiagnostic::UnsupportedPhy));
                } else {
                    assert!(headers.is_empty(), "{} chunk={size}", columns[0]);
                }
            }
        }
    }

    #[test]
    fn radio_data_rejections_identify_the_failed_stage() {
        for (bytes, expected) in [
            (
                include_bytes!("../../tests/fixtures/iq/ofdm-6-invalid_signal.cs8").as_slice(),
                PhyDiagnostic::InvalidHeader,
            ),
            (
                include_bytes!("../../tests/fixtures/iq/ofdm-6-invalid_service.cs8").as_slice(),
                PhyDiagnostic::InvalidData,
            ),
            (
                include_bytes!("../../tests/fixtures/iq/ofdm-6-bad_fcs.cs8").as_slice(),
                PhyDiagnostic::InvalidFcs,
            ),
        ] {
            let out = feed(&mut LegacyOfdmDecoder::new(), bytes, 127);
            assert!(out.frames.is_empty());
            assert!(out.diagnostics.contains(&expected), "{:?}", out.diagnostics);
            for other in [
                PhyDiagnostic::InvalidHeader,
                PhyDiagnostic::InvalidData,
                PhyDiagnostic::InvalidFcs,
            ] {
                if other != expected {
                    assert!(!out.diagnostics.contains(&other));
                }
            }
        }
    }
    #[test]
    fn radio_data_independent_vectors_all_rates_chunkings_and_integrity() {
        for line in include_str!("../../tests/fixtures/iq/ofdm-index.tsv")
            .lines()
            .skip(1)
        {
            let fields: Vec<_> = line.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                fields[0]
            ))
            .unwrap();
            let expected: Vec<u8> = fields[6]
                .as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect();
            for size in [1, 17, 79, 320, 10000] {
                let mut decoder = LegacyOfdmDecoder::new();
                let out = feed(&mut decoder, &bytes, size);
                if fields[9] == "frame" && fields[8] == "True" {
                    assert_eq!(
                        out.frames.len(),
                        1,
                        "{} size {size}, {:?}, {:?}",
                        fields[0],
                        out.diagnostics,
                        decoder.stats()
                    );
                    assert_eq!(out.frames[0].bytes, expected, "{}", fields[0]);
                    assert_eq!(out.frames[0].start.sample_index, 37);
                    assert_eq!(
                        out.frames[0].rate_bps,
                        fields[1].parse::<u32>().unwrap() * 1000000
                    );
                    assert_eq!(decoder.stats.valid_frames, 1);
                } else {
                    assert!(out.frames.is_empty(), "{}", fields[0]);
                    if fields[0].ends_with("bad_fcs") {
                        assert_eq!(decoder.stats.invalid_fcs, 1);
                    }
                    if fields[0].ends_with("truncated") {
                        assert_eq!(decoder.stats.truncated_frames, 1);
                    }
                }
            }
        }
    }
    #[test]
    fn radio_data_multipath_and_noise_only() {
        for rate in [6, 54] {
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/ofdm-{rate}-clean.cs8",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            // A weak three-sample echo lies inside the cyclic prefix.
            let impaired: Vec<u8> = bytes
                .iter()
                .enumerate()
                .map(|(n, v)| {
                    let echo = if n >= 6 {
                        bytes[n - 6] as i8 as f32 * 0.15
                    } else {
                        0.
                    };
                    ((*v as i8 as f32 * 0.8 + echo).round() as i8) as u8
                })
                .collect();
            let mut decoder = LegacyOfdmDecoder::new();
            assert_eq!(
                feed(&mut decoder, &impaired, 31).frames.len(),
                1,
                "rate {rate}"
            );
        }
        let mut state = 123u32;
        let noise: Vec<u8> = (0..20000)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 24) as u8
            })
            .collect();
        assert!(feed(&mut LegacyOfdmDecoder::new(), &noise, 127)
            .frames
            .is_empty());
    }
    #[test]
    fn radio_data_end_gap_and_buffer_bound() {
        let bytes = include_bytes!("../../tests/fixtures/iq/ofdm-6-clean.cs8");
        let mut decoder = LegacyOfdmDecoder::new();
        let out = feed(&mut decoder, &bytes[..1200], 17);
        assert!(out.frames.is_empty());
        assert_eq!(decoder.stats.truncated_frames, 1);
        assert!(feed(&mut decoder, bytes, 17).frames.is_empty());
        decoder.reset(ResetReason::Explicit);
        assert_eq!(feed(&mut decoder, bytes, 17).frames.len(), 1);
        let mut decoder = LegacyOfdmDecoder::new();
        let chunk = |index, sequence, data: &[u8], limit| {
            let mut c = config();
            c.max_buffer_samples = limit;
            c.max_chunk_samples = limit;
            IqChunk::new(
                c,
                IqPosition {
                    epoch: 0,
                    sequence,
                    sample_index: index,
                    time_anchor: None,
                    discontinuity: None,
                },
                data.iter().map(|v| *v as i8).collect(),
            )
            .unwrap()
        };
        decoder
            .consume(IqEvent::Chunk(chunk(0, 0, &bytes[..1200], 20000)))
            .unwrap();
        let out = decoder
            .consume(IqEvent::Chunk(chunk(601, 1, &bytes[1200..], 20000)))
            .unwrap();
        assert!(out.frames.is_empty());
        assert_eq!(decoder.stats.truncated_frames, 1);
        let mut decoder = LegacyOfdmDecoder::new();
        for (n, data) in bytes.chunks(768).enumerate() {
            assert!(decoder
                .consume(IqEvent::Chunk(chunk((n * 384) as u64, n as u64, data, 384)))
                .unwrap()
                .frames
                .is_empty());
        }
        assert!(decoder.stats.rejected_frames > 0);
    }
}
