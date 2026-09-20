//! Legacy OFDM streaming coordination with optional HT receive delegation.
use super::{
    demod::{decode_data, valid_fcs},
    signal::{decode_signal, SignalInfo},
    sync::{Acquisition, SyncEvent, Synchronizer},
};
use crate::radio::{
    codec::{
        DecodeOutput, FrameFraming, FrameIntegrity, PhyDecoder, PhyDiagnostic, RecoveredFrame,
        ResetReason,
    },
    error::{RadioError, RadioResult},
    transport::{
        ComplexSample, Discontinuity, GapReason, IqContinuity, IqEvent, IqPosition, SampleLoss,
    },
    wifi::ht,
};
use crate::LinkType;

#[cfg(test)]
use super::demod::decode_data_mode;
#[cfg(test)]
use crate::radio::{
    transport::{IqChunk, RxConfig, StreamEnd},
    wifi::{HtSignalFields, WifiDecoder},
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
    weak: bool,
    acquisition: Acquisition,
    start: IqPosition,
    samples: Vec<ComplexSample>,
    info: Option<SignalInfo>,
    ht: Option<ht::rx::Candidate>,
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
    ht: ht::rx::Receiver,
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
    pub(in crate::radio) fn with_ht() -> Self {
        Self {
            ht: ht::rx::Receiver::ht20(),
            ..Self::default()
        }
    }
    pub(in crate::radio) fn uses_ht(&self) -> bool {
        self.ht.accepts_ht()
    }
    pub(in crate::radio) fn set_output_allowance(&mut self, allowance: usize) {
        self.output_allowance = Some(allowance);
    }
    fn publish_psdu(
        &mut self,
        frame: RecoveredFrame,
        aggregate: bool,
        out: &mut DecodeOutput,
        members: Option<&[std::ops::Range<usize>]>,
    ) -> RadioResult<()> {
        let limit = self
            .output_allowance
            .unwrap_or(frame.config.max_pending_frames)
            .min(frame.config.max_pending_frames);
        if aggregate {
            let counts = ht::rx::publish_aggregate(frame, limit, out, members)?;
            self.stats.valid_frames = self.stats.valid_frames.saturating_add(counts.valid_frames);
            self.stats.invalid_fcs = self.stats.invalid_fcs.saturating_add(counts.invalid_fcs);
        } else if valid_fcs(&frame.bytes) {
            self.stats.valid_frames = self.stats.valid_frames.saturating_add(1);
            if out.frames.len() < limit {
                out.frames.push(frame);
            } else if self.ht.strict_output_limit() {
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
                // Header reservations on the original acquisition path take
                // priority over the optional weak-training hypothesis.
                if self.pending[slot]
                    .as_ref()
                    .is_some_and(|p| !p.weak && matches!(p.samples.len(), 79 | 159 | 239))
                {
                    for other in &mut self.pending {
                        if other.as_ref().is_some_and(|p| p.weak) {
                            *other = None;
                        }
                    }
                }
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
                    match decode_signal(&p.samples, &p.acquisition, self.ht.signal_limit(config)) {
                        Ok(info)
                            if self.ht.reserve_signal_candidate(
                                &mut p.samples,
                                info,
                                config,
                                config.max_buffer_samples.saturating_sub(reserved),
                            ) =>
                        {
                            p.info = Some(info);
                        }
                        _ if self.ht.reserve_greenfield_probe(
                            &mut p.samples,
                            config.max_buffer_samples.saturating_sub(reserved),
                        ) =>
                        {
                            // A greenfield preamble has HT-SIG here, not L-SIG.
                            // Wait for both symbols before rejecting this candidate.
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
                if p.samples.len() == 160 {
                    match self.ht.recognize_greenfield(
                        &mut p.samples,
                        &p.acquisition,
                        &p.start,
                        config,
                        reserved,
                    ) {
                        ht::rx::HeaderOutcome::Supported {
                            candidate,
                            info,
                            diagnostics,
                        } => {
                            out.diagnostics.extend(diagnostics);
                            p.ht = Some(candidate);
                            p.info = Some(info);
                            continue;
                        }
                        ht::rx::HeaderOutcome::Unsupported { diagnostics } => {
                            out.diagnostics.extend(diagnostics);
                            out.diagnostics.push(PhyDiagnostic::UnsupportedPhy);
                            self.stats.rejected_frames =
                                self.stats.rejected_frames.saturating_add(1);
                            self.pending[slot] = None;
                            continue;
                        }
                        ht::rx::HeaderOutcome::NotHt if p.info.is_none() => {
                            self.stats.rejected_frames =
                                self.stats.rejected_frames.saturating_add(1);
                            out.diagnostics.push(PhyDiagnostic::InvalidHeader);
                            self.pending[slot] = None;
                            continue;
                        }
                        ht::rx::HeaderOutcome::NotHt => {}
                    }
                }
                if p.samples.len() == 240 && p.info.is_some_and(|info| info.rate_bps == 6_000_000) {
                    match self.ht.recognize_mixed(
                        &mut p.samples,
                        &p.acquisition,
                        &p.start,
                        config,
                        reserved,
                    ) {
                        ht::rx::HeaderOutcome::Supported {
                            candidate,
                            info,
                            diagnostics,
                        } => {
                            out.diagnostics.extend(diagnostics);
                            p.ht = Some(candidate);
                            p.info = Some(info);
                            continue;
                        }
                        ht::rx::HeaderOutcome::Unsupported { diagnostics } => {
                            out.diagnostics.extend(diagnostics);
                            out.diagnostics.push(PhyDiagnostic::UnsupportedPhy);
                            self.stats.rejected_frames =
                                self.stats.rejected_frames.saturating_add(1);
                            self.pending[slot] = None;
                            continue;
                        }
                        ht::rx::HeaderOutcome::NotHt => {}
                    }
                    let info = p.info.unwrap();
                    if !self
                        .ht
                        .reserve_legacy_fallback(&mut p.samples, info, config, reserved)
                    {
                        self.stats.rejected_frames = self.stats.rejected_frames.saturating_add(1);
                        out.diagnostics.push(PhyDiagnostic::InvalidHeader);
                        self.pending[slot] = None;
                        continue;
                    }
                }
                if p.info
                    .is_some_and(|info| index + 1 == info.end_sample_index)
                {
                    let p = self.pending[slot].take().unwrap();
                    let info = p.info.unwrap();
                    let (decoded, frame_diagnostics, failure_diagnostics, aggregate, members) =
                        if let Some(candidate) = p.ht {
                            let aggregate = candidate.aggregate();
                            let attempt =
                                candidate.decode(&p.samples, &p.acquisition, info, &p.start);
                            out.diagnostics.extend(attempt.output_diagnostics);
                            (
                                attempt.decoded,
                                attempt.frame_diagnostics,
                                attempt.failure_diagnostics,
                                aggregate,
                                attempt.aggregate_members,
                            )
                        } else {
                            let attempt = decode_data(&p.samples[80..], &p.acquisition, info);
                            (
                                attempt.decoded,
                                attempt.frame_diagnostics,
                                attempt.failure_diagnostics,
                                false,
                                None,
                            )
                        };
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
                            diagnostics.extend(frame_diagnostics);
                            let frame = RecoveredFrame {
                                bytes,
                                link_type: LinkType::Ieee80211,
                                integrity: FrameIntegrity::ValidFcs,
                                framing: FrameFraming { trailer_bytes: 4 },
                                config: config.clone(),
                                start: p.start,
                                end_sample_index: info.end_sample_index,
                                rate_bps: info.rate_bps,
                                diagnostics,
                            };
                            if let Err(error) =
                                self.publish_psdu(frame, aggregate, &mut out, members.as_deref())
                            {
                                self.reset(ResetReason::Explicit);
                                return Err(error);
                            }
                        }
                        Err(()) => {
                            self.stats.rejected_frames =
                                self.stats.rejected_frames.saturating_add(1);
                            out.diagnostics.push(PhyDiagnostic::InvalidData);
                            out.diagnostics.extend(failure_diagnostics);
                        }
                    }
                }
            }
            if let Some(event) = self.sync.push(sample, index) {
                let weak = matches!(event, SyncEvent::WeakAcquired(_));
                match event {
                    SyncEvent::Acquired(a) | SyncEvent::WeakAcquired(a) => {
                        // The two searches can locate the same training pair.
                        // Prefer the original path before either DATA decode.
                        if weak
                            && self.pending.iter().flatten().any(|p| {
                                !p.weak
                                    && p.acquisition.preamble_start.abs_diff(a.preamble_start)
                                        <= 128
                            })
                        {
                            continue;
                        }
                        if !weak {
                            for p in &mut self.pending {
                                if p.as_ref().is_some_and(|p| {
                                    p.weak
                                        && p.acquisition.preamble_start.abs_diff(a.preamble_start)
                                            <= 128
                                }) {
                                    *p = None;
                                }
                            }
                            let reserved: usize = self
                                .pending
                                .iter()
                                .flatten()
                                .map(|p| p.samples.capacity())
                                .sum();
                            if self.pending.iter().all(Option::is_some)
                                || config.max_buffer_samples.saturating_sub(reserved) < 80
                            {
                                for p in &mut self.pending {
                                    if p.as_ref().is_some_and(|p| p.weak) {
                                        *p = None;
                                    }
                                }
                            }
                        }
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
                            weak,
                            acquisition: a,
                            start,
                            samples: Vec::with_capacity(80),
                            info: None,
                            ht: None,
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

#[cfg(all(test, not(crafter_packaged)))]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn radio_aggregate_recovery_publishes_only_verified_member_ranges() {
        let mut decoded = feed(
            &mut WifiDecoder::new(),
            include_bytes!("../../../../tests/fixtures/iq/ht-bcc-0-gi800-len100-clean.cs8"),
            127,
        );
        let mut frame = decoded.frames.remove(0);
        let fields: Vec<_> = include_str!("../../../../tests/fixtures/iq/ampdu-index.tsv")
            .lines()
            .nth(1)
            .unwrap()
            .split('\t')
            .collect();
        let hex = |text: &str| {
            text.as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>()
        };
        frame.bytes = hex(fields[1]);
        let offsets: Vec<usize> = fields[2].split(',').map(|v| v.parse().unwrap()).collect();
        let expected: Vec<_> = fields[3].split(',').map(hex).collect();
        // Select a later member: an earlier valid-looking frame must neither
        // be published nor hide the explicitly verified original offset.
        let ranges = [offsets[1] - 4..offsets[1] + expected[1].len()];
        let mut out = DecodeOutput::default();
        let counts = ht::rx::publish_aggregate(frame, 1, &mut out, Some(&ranges)).unwrap();
        assert_eq!(counts.valid_frames, 1);
        assert_eq!(out.frames.len(), 1);
        assert_eq!(out.frames[0].bytes, expected[1]);
        assert!(out.frames[0].diagnostics.iter().any(|d| matches!(d,
            PhyDiagnostic::Ampdu { delimiter_offset, .. } if *delimiter_offset == offsets[1] - 4)));
    }

    #[test]
    fn radio_ht_bcc_independent_payload_kernel() {
        use sha2::{Digest, Sha256};
        let index = include_str!("../../../../tests/fixtures/iq/ht-bcc-index.tsv");
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
                iq_balance: [1., 0.],
                noise_power: [0.; 2],
                early_channel: [[ComplexSample::ZERO; 64]; 3],
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
            for (guard_eighths, common_phase, decision_iterations, mmse, progressive_pilots) in [
                (4, false, 0, false, false),
                (4, false, 3, false, false),
                (2, true, 0, false, false),
                (2, false, 3, false, false),
                (6, true, 0, false, false),
                (6, false, 3, false, false),
                (4, false, 0, true, false),
                (4, false, 0, false, true),
            ] {
                let profile = crate::radio::wifi::recovery::Profile {
                    boundary_metrics: true,
                    mmse,
                    correct_iq: mmse || progressive_pilots,
                    progressive_pilots,
                    track_timing: !progressive_pilots,
                    guard_eighths,
                    common_phase,
                    decision_iterations,
                    ..crate::radio::wifi::recovery::Profile::TRACKED
                };
                let (actual, _) = super::super::demod::decode_data_profile(
                    &samples[data_start..end],
                    &a,
                    info,
                    Some(guard),
                    false,
                    None,
                    profile,
                )
                .unwrap_or_else(|_| panic!("{} equalized DATA rejected", c[0]));
                assert_eq!(actual, expected, "{}", c[0]);
                assert!(valid_fcs(&actual), "{}", c[0]);
            }
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
    fn radio_false_short_preamble_does_not_hide_following_frame() {
        let mut fixtures: Vec<_> = [6, 9, 12, 18, 24, 36, 48, 54]
            .into_iter()
            .map(|rate| format!("ofdm-{rate}-clean"))
            .collect();
        fixtures.extend((0..8).map(|mcs| format!("ht-bcc-{mcs}-gi800-len100-clean")));
        for name in fixtures {
            let original = std::fs::read(format!(
                "{}/tests/fixtures/iq/{name}.cs8",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            let baseline = feed(&mut WifiDecoder::new(), &original, 127);
            assert_eq!(baseline.frames.len(), 1, "{name}");
            let expected = &baseline.frames[0];
            for (tone_samples, gap_samples) in [(80, 16), (96, 32), (128, 64)] {
                let mut bytes = Vec::new();
                for n in 0..tone_samples {
                    let angle = -std::f32::consts::TAU * 200_000. * n as f32 / 20_000_000.;
                    bytes.push((48. * angle.cos()).round() as i8 as u8);
                    bytes.push((48. * angle.sin()).round() as i8 as u8);
                }
                bytes.resize(bytes.len() + 2 * gap_samples, 0);
                let prefix = bytes.len() / 2;
                bytes.extend_from_slice(&original);
                for chunk in [1, 127, 4096] {
                    let recovered = feed(&mut WifiDecoder::new(), &bytes, chunk);
                    assert_eq!(
                        recovered.frames.len(),
                        1,
                        "{name}, tone={tone_samples}, gap={gap_samples}, chunk={chunk}"
                    );
                    let frame = &recovered.frames[0];
                    assert_eq!(frame.bytes, expected.bytes, "{name}");
                    assert_eq!(
                        frame.start.sample_index,
                        expected.start.sample_index + prefix as u64,
                        "{name}"
                    );
                    assert_eq!(
                        frame.end_sample_index,
                        expected.end_sample_index + prefix as u64,
                        "{name}"
                    );
                }
            }
        }
    }
    #[test]
    fn radio_ht_extension_training_streaming_independent_iq() {
        let rows: Vec<_> = include_str!("../../../../tests/fixtures/iq/ht-extension-index.tsv")
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
        let rows: Vec<_> = include_str!("../../../../tests/fixtures/iq/ht-extension-index.tsv")
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
        let rows: Vec<_> = include_str!("../../../../tests/fixtures/iq/ht-stbc-index.tsv")
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
        let rows: Vec<_> = include_str!("../../../../tests/fixtures/iq/ht-stbc-invalid-index.tsv")
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
        let rows: Vec<_> = include_str!("../../../../tests/fixtures/iq/ht-greenfield-index.tsv")
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
        let rows: Vec<_> =
            include_str!("../../../../tests/fixtures/iq/ht-greenfield-invalid-index.tsv")
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
        let bytes =
            include_bytes!("../../../../tests/fixtures/iq/ht-greenfield-7-ldpc-len100-clean.cs8");
        for stop in [250, 400, 516, 550] {
            let out = feed(&mut WifiDecoder::new(), &bytes[..2 * stop], 79);
            assert!(out.frames.is_empty());
            assert!(
                out.diagnostics.contains(&PhyDiagnostic::TruncatedFrame),
                "stop={stop}"
            );
        }
        let bounded_bytes =
            include_bytes!("../../../../tests/fixtures/iq/ht-greenfield-0-ldpc-len100-clean.cs8");
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
        let rows: Vec<_> = include_str!("../../../../tests/fixtures/iq/ht-ampdu-index.tsv")
            .lines()
            .skip(1)
            .chain(
                include_str!("../../../../tests/fixtures/iq/ht-greenfield-ampdu-index.tsv")
                    .lines()
                    .skip(1),
            )
            .collect();
        let rows: Vec<_> = rows
            .into_iter()
            .chain(
                include_str!("../../../../tests/fixtures/iq/ht-stbc-ampdu-index.tsv")
                    .lines()
                    .skip(1),
            )
            .chain(
                include_str!("../../../../tests/fixtures/iq/ht-extension-ampdu-index.tsv")
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
            include_bytes!("../../../../tests/fixtures/iq/ht-ampdu-7-gi800-bcc-duplicate.cs8")
                .as_slice(),
            include_bytes!("../../../../tests/fixtures/iq/ht-ampdu-7-gi800-ldpc-duplicate.cs8")
                .as_slice(),
            include_bytes!("../../../../tests/fixtures/iq/ht-greenfield-ampdu-7-bcc.cs8")
                .as_slice(),
            include_bytes!("../../../../tests/fixtures/iq/ht-greenfield-ampdu-7-ldpc.cs8")
                .as_slice(),
            include_bytes!("../../../../tests/fixtures/iq/ht-stbc-ampdu-7-bcc-mf-gi400.cs8")
                .as_slice(),
            include_bytes!("../../../../tests/fixtures/iq/ht-stbc-ampdu-7-ldpc-mf-gi800.cs8")
                .as_slice(),
            include_bytes!("../../../../tests/fixtures/iq/ht-stbc-ampdu-7-bcc-gf-gi800.cs8")
                .as_slice(),
            include_bytes!("../../../../tests/fixtures/iq/ht-stbc-ampdu-7-ldpc-gf-gi800.cs8")
                .as_slice(),
            include_bytes!(
                "../../../../tests/fixtures/iq/ht-extension-ampdu-7-bcc-mf-gi800-stbc0-ess3.cs8"
            )
            .as_slice(),
            include_bytes!(
                "../../../../tests/fixtures/iq/ht-extension-ampdu-7-ldpc-gf-gi800-stbc0-ess3.cs8"
            )
            .as_slice(),
            include_bytes!(
                "../../../../tests/fixtures/iq/ht-extension-ampdu-7-ldpc-mf-gi400-stbc1-ess2.cs8"
            )
            .as_slice(),
            include_bytes!(
                "../../../../tests/fixtures/iq/ht-extension-ampdu-7-bcc-gf-gi800-stbc1-ess2.cs8"
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
        let bytes = include_bytes!("../../../../tests/fixtures/iq/ht-bcc-0-gi800-len100-clean.cs8");
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
            include_str!("../../../../tests/fixtures/iq/ht-bcc-index.tsv"),
            false,
        );
    }
    #[test]
    fn radio_ht_ldpc_streaming_independent_iq() {
        verify_ht_streaming(
            include_str!("../../../../tests/fixtures/iq/ht-ldpc-index.tsv"),
            true,
        );
    }
    #[test]
    fn radio_ht_ldpc_independent_rejection_stages() {
        use sha2::{Digest, Sha256};
        for row in include_str!("../../../../tests/fixtures/iq/ht-ldpc-invalid-index.tsv")
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
        let bytes =
            include_bytes!("../../../../tests/fixtures/iq/ht-ldpc-7-gi800-len100-clean.cs8");
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
        let index = include_str!("../../../../tests/fixtures/iq/ht-mixed-index.tsv");
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
                include_bytes!("../../../../tests/fixtures/iq/ofdm-6-invalid_signal.cs8")
                    .as_slice(),
                PhyDiagnostic::InvalidHeader,
            ),
            (
                include_bytes!("../../../../tests/fixtures/iq/ofdm-6-invalid_service.cs8")
                    .as_slice(),
                PhyDiagnostic::InvalidData,
            ),
            (
                include_bytes!("../../../../tests/fixtures/iq/ofdm-6-bad_fcs.cs8").as_slice(),
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
        for line in include_str!("../../../../tests/fixtures/iq/ofdm-index.tsv")
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
        let bytes = include_bytes!("../../../../tests/fixtures/iq/ofdm-6-clean.cs8");
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
