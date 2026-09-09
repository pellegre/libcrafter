//! Legacy DATA receive path; IEEE 802.11-2007 17.3.5, evidence in docs/radio.md.
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
}
/// Bounded streaming legacy OFDM receiver. Only integrity-valid PSDUs are delivered.
#[derive(Default)]
pub struct LegacyOfdmDecoder {
    sync: Synchronizer,
    continuity: IqContinuity,
    pending: Option<Pending>,
    terminal: bool,
    stats: DecoderStats,
}
impl LegacyOfdmDecoder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn stats(&self) -> DecoderStats {
        self.stats
    }
}
impl PhyDecoder for LegacyOfdmDecoder {
    fn reset(&mut self, reason: ResetReason) -> DecodeOutput {
        let mut out = DecodeOutput::default();
        if self.pending.take().is_some() || self.sync.clear() {
            self.stats.truncated_frames = self.stats.truncated_frames.saturating_add(1);
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
            if let Some(p) = &mut self.pending {
                p.samples.push(sample);
                if p.info.is_none() && p.samples.len() == 80 {
                    match decode_signal(
                        &p.samples,
                        &p.acquisition,
                        config.max_frame_bytes.min(4095),
                    ) {
                        Ok(info) if 80 + info.data_symbols * 80 <= config.max_buffer_samples => {
                            p.samples.reserve_exact(info.data_symbols * 80);
                            p.info = Some(info);
                        }
                        _ => {
                            self.stats.rejected_frames =
                                self.stats.rejected_frames.saturating_add(1);
                            out.diagnostics.push(PhyDiagnostic::InvalidHeader);
                            self.pending = None;
                            self.sync.clear();
                            continue;
                        }
                    }
                }
                if p.info
                    .is_some_and(|info| index + 1 == info.end_sample_index)
                {
                    let p = self.pending.take().unwrap();
                    let info = p.info.unwrap();
                    match decode_data(&p.samples[80..], &p.acquisition, info) {
                        Ok(bytes) => {
                            if valid_fcs(&bytes) {
                                self.stats.valid_frames = self.stats.valid_frames.saturating_add(1);
                                if out.frames.len() < config.max_pending_frames {
                                    out.frames.push(RecoveredFrame {
                                        bytes,
                                        link_type: LinkType::Ieee80211,
                                        integrity: FrameIntegrity::ValidFcs,
                                        config: config.clone(),
                                        start: p.start,
                                        end_sample_index: info.end_sample_index,
                                        rate_bps: info.rate_bps,
                                        diagnostics: vec![PhyDiagnostic::Ofdm {
                                            frequency_offset_hz: p.acquisition.frequency_rad
                                                * 20_000_000.
                                                / std::f32::consts::TAU,
                                            training_correlation: p.acquisition.correlation,
                                        }],
                                    });
                                } else {
                                    self.stats.dropped_frames =
                                        self.stats.dropped_frames.saturating_add(1);
                                    out.diagnostics.push(PhyDiagnostic::Reset(ResetReason::Gap(
                                        Discontinuity {
                                            reason: GapReason::QueueOverflow,
                                            loss: SampleLoss::Known(0),
                                        },
                                    )));
                                }
                            } else {
                                self.stats.invalid_fcs = self.stats.invalid_fcs.saturating_add(1);
                                out.diagnostics.push(PhyDiagnostic::InvalidFcs);
                            }
                        }
                        Err(()) => {
                            self.stats.rejected_frames =
                                self.stats.rejected_frames.saturating_add(1);
                            out.diagnostics.push(PhyDiagnostic::InvalidHeader);
                        }
                    }
                    self.sync.clear();
                }
            } else if let Some(event) = self.sync.push(sample, index) {
                match event {
                    SyncEvent::Acquired(a) => {
                        let mut start = chunk.position().clone();
                        start.sample_index = a.preamble_start;
                        self.pending = Some(Pending {
                            acquisition: a,
                            start,
                            samples: Vec::with_capacity(80),
                            info: None,
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
        _ => {
            sign * (4.
                - (2. * ((label >> 1) & 1) as f32 - 1.) * (3. - 2. * ((label >> 2) & 1) as f32))
        }
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
) -> Result<Vec<u8>, ()> {
    if samples.len() != info.data_symbols * 80 {
        return Err(());
    }
    let nbpsc = info.coded_bits_per_symbol / 48;
    let scale: f32 = match nbpsc {
        1 => 1.,
        2 => 2.,
        4 => 10.,
        _ => 42.,
    };
    let mut coded = Vec::with_capacity(info.data_symbols * info.coded_bits_per_symbol);
    let mut pilot_state = 127;
    feedback(&mut pilot_state); // SIGNAL occupies polarity zero.
    for (symbol, samples) in samples.chunks_exact(80).enumerate() {
        let time = std::array::from_fn(|n| {
            samples[16 + n].mul(ComplexSample::rotation(
                -a.frequency_rad
                    * (info.data_start + (symbol * 80 + 16 + n) as u64 - a.phase_origin) as f32,
            ))
        });
        let bins = fft64(time);
        let polarity = 1. - 2. * feedback(&mut pilot_state) as f32;
        let mut pilot = ComplexSample::ZERO;
        for (k, sign) in [(43, 1.), (57, 1.), (7, 1.), (21, -1.)] {
            pilot = pilot.add(bins[k].mul(a.channel[k].conj()).scale(sign * polarity));
        }
        if !pilot.power().is_finite() || pilot.power() < 1e-12 {
            return Err(());
        }
        let rotation = ComplexSample::rotation(-pilot.phase());
        let mut interleaved = Vec::with_capacity(info.coded_bits_per_symbol);
        for k in (-26i32..=26).filter(|k| ![-21, -7, 0, 7, 21].contains(k)) {
            let k = k.rem_euclid(64) as usize;
            let power = a.channel[k].power();
            if !power.is_finite() || power < 1e-12 {
                interleaved.extend(std::iter::repeat(0.).take(nbpsc));
                continue;
            }
            let v = bins[k]
                .mul(a.channel[k].conj())
                .mul(rotation)
                .scale(1. / power);
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
        let n = info.coded_bits_per_symbol;
        let s = (nbpsc / 2).max(1);
        for k in 0..n {
            let i = (n / 16) * (k % 16) + k / 16;
            let j = s * (i / s) + (i + n - 16 * i / n) % s;
            coded.push(interleaved[j]);
        }
    }
    let pattern: &[u8] = if info.data_bits_per_symbol * 2 == info.coded_bits_per_symbol {
        &[1, 1]
    } else if info.rate_bps == 48_000_000 {
        &[1, 1, 1, 0]
    } else {
        &[1, 1, 1, 0, 0, 1]
    };
    let count = info.data_symbols * info.data_bits_per_symbol;
    let mut metric = [f32::INFINITY; 64];
    metric[0] = 0.;
    let mut history = vec![[0u8; 64]; count];
    let mut cursor = 0;
    for t in 0..count {
        let row = &mut history[t];
        let mut pair = [0.; 2];
        for j in 0..2 {
            if pattern[(2 * t + j) % pattern.len()] == 1 {
                pair[j] = coded[cursor];
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
        if t == 47 && !possible_service_prefix(&history[..48]) {
            return Err(());
        }
        let minimum = next.iter().copied().fold(f32::INFINITY, f32::min);
        for cost in &mut next {
            *cost -= minimum;
        }
        metric = next;
    }
    let mut state = (0..64)
        .min_by(|x, y| metric[*x].total_cmp(&metric[*y]))
        .ok_or(())?;
    let mut bits = vec![0; count];
    for t in (0..count).rev() {
        bits[t] = (state & 1) as u8;
        state = history[t][state] as usize;
    }
    let tail = 16 + 8 * info.psdu_bytes;
    if bits[tail..tail + 6].iter().any(|b| *b != 0) {
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
    if bits[..16].iter().any(|b| *b != 0) {
        return Err(());
    }
    Ok(bits[16..tail]
        .chunks_exact(8)
        .map(|b| b.iter().enumerate().fold(0, |v, (i, b)| v | (b << i)))
        .collect())
}
fn possible_service_prefix(history: &[[u8; 64]]) -> bool {
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
        if (1u8..128).any(|mut seed| service.iter().all(|b| *b == feedback(&mut seed))) {
            return true;
        }
    }
    false
}

fn valid_fcs(bytes: &[u8]) -> bool {
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
mod tests {
    use super::*;
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
    fn feed(decoder: &mut LegacyOfdmDecoder, bytes: &[u8], size: usize) -> DecodeOutput {
        let mut result = DecodeOutput::default();
        for (sequence, part) in bytes.chunks(size * 2).enumerate() {
            let chunk = IqChunk::new(
                config(),
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
            let mut out = decoder.consume(IqEvent::Chunk(chunk)).unwrap();
            result.frames.append(&mut out.frames);
            result.diagnostics.append(&mut out.diagnostics);
        }
        let mut out = decoder.consume(IqEvent::End(StreamEnd::Eof)).unwrap();
        result.diagnostics.append(&mut out.diagnostics);
        result
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
