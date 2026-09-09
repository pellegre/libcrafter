//! Private clause 15/18 acquisition. Coordinates refer to the original 20 Msps stream.
use super::*;
use std::f32::consts::PI;
const BARKER: [f32; 11] = [1., -1., 1., 1., -1., 1., 1., 1., -1., -1., -1.];

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Descrambler(u8);
impl Descrambler {
    pub fn bit(&mut self, bit: u8) -> u8 {
        let plain = bit ^ ((self.0 >> 3) & 1) ^ ((self.0 >> 6) & 1);
        self.0 = (self.0 << 1) | bit;
        plain
    }
}
#[derive(Clone, Debug)]
pub(super) struct Header {
    pub short: bool,
    pub rate_bps: u32,
    pub psdu_bytes: usize,
    pub preamble_start: f64,
    pub payload_start: f64,
    pub frequency_rad: f32,
    pub previous_symbol: ComplexSample,
    pub descrambler: Descrambler,
    pub correlation: f32,
}

pub(super) fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &byte in bytes {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x8408 & 0u16.wrapping_sub(crc & 1));
        }
    }
    !crc
}
fn length(header: [u8; 6], short: bool, bound: usize) -> Option<(u32, usize)> {
    if crc16(&header[..4]) != u16::from_le_bytes([header[4], header[5]]) {
        return None;
    }
    let rate = u32::from(header[0]);
    let service = header[1];
    if service & !0x84 != 0 || (rate != 110 && service & 0x80 != 0) || (short && rate == 10) {
        return None;
    }
    let duration = usize::from(u16::from_le_bytes([header[2], header[3]]));
    let extension = usize::from(service >> 7);
    let n = match rate {
        10 => duration / 8,
        20 => duration / 4,
        55 => duration * 11 / 16,
        110 => (duration * 11 / 8).checked_sub(extension)?,
        _ => return None,
    };
    if n < 4 || n > bound || (n * 80).div_ceil(rate as usize) != duration {
        return None;
    }
    if rate == 110 && usize::from(11 * duration - 8 * n >= 8) != extension {
        return None;
    }
    Some((rate * 100_000, n))
}

/// Fixed history and normalized 256-phase, 16-tap Hann-windowed sinc kernels.
struct Samples {
    ring: [ComplexSample; 128],
    kernels: [[f32; 16]; 256],
    begin: u64,
    end: u64,
}
impl Samples {
    fn new() -> Self {
        let mut kernels = [[0.; 16]; 256];
        for (phase, kernel) in kernels.iter_mut().enumerate() {
            let fraction = phase as f32 / 256.;
            for (k, coefficient) in kernel.iter_mut().enumerate() {
                let x = k as f32 - 7. - fraction;
                let sinc = if x.abs() < 1e-6 {
                    1.
                } else {
                    (PI * x).sin() / (PI * x)
                };
                *coefficient = sinc * (0.5 + 0.5 * (PI * x / 8.).cos());
            }
            let gain: f32 = kernel.iter().sum();
            for coefficient in kernel {
                *coefficient /= gain;
            }
        }
        Self {
            ring: [ComplexSample::ZERO; 128],
            kernels,
            begin: 0,
            end: 0,
        }
    }
    fn clear(&mut self, start: u64) {
        self.begin = start;
        self.end = start;
    }
    fn push(&mut self, value: ComplexSample) {
        self.ring[self.end as usize % 128] = value;
        self.end += 1;
        self.begin = self.begin.max(self.end.saturating_sub(128));
    }
    fn at(&self, time: f64) -> Option<ComplexSample> {
        let center = time.floor() as i128;
        let start = center - 7;
        if start < self.begin as i128 || start + 16 > self.end as i128 {
            return None;
        }
        let phase = ((time - time.floor()) * 256.).round() as usize;
        // Nearest phase; carry into the next source sample at the phase boundary.
        let (start, phase) = if phase == 256 {
            (start + 1, 0)
        } else {
            (start, phase)
        };
        if start + 16 > self.end as i128 {
            return None;
        }
        let mut sum = ComplexSample::ZERO;
        for (k, &weight) in self.kernels[phase].iter().enumerate() {
            sum = sum.add(self.ring[(start as usize + k) % 128].scale(weight));
        }
        Some(sum)
    }
    fn barker(&self, start: f64) -> Option<(ComplexSample, f32)> {
        let mut sum = ComplexSample::ZERO;
        let mut power = 0.;
        for (k, &sign) in BARKER.iter().enumerate() {
            let value = self.at(start + (k as f64 + 0.5) * 20. / 11.)?;
            sum = sum.add(value.scale(sign));
            power += value.power();
        }
        let quality = sum.power() / (11. * power).max(1e-12);
        Some((sum.scale(1. / 11.), quality))
    }
}
#[derive(Clone)]
struct Track {
    previous: ComplexSample,
    descrambler: Descrambler,
    shift: u16,
    run: usize,
    last: u8,
    frequency: f32,
    short: Option<bool>,
    header: [u8; 6],
    bits: usize,
    sfd_end: f64,
    quality: f32,
    timing: f64,
}
impl Default for Track {
    fn default() -> Self {
        Self {
            previous: ComplexSample::ZERO,
            descrambler: Descrambler::default(),
            shift: 0,
            run: 0,
            last: 0,
            frequency: 0.,
            short: None,
            header: [0; 6],
            bits: 0,
            sfd_end: 0.,
            quality: 0.,
            timing: 0.,
        }
    }
}
impl Track {
    fn symbol(
        &mut self,
        symbol: ComplexSample,
        quality: f32,
        start: f64,
        bound: usize,
    ) -> Option<Result<Header, ()>> {
        let delta = symbol.mul(self.previous.conj());
        self.previous = symbol;
        if quality < 0.25 || symbol.power() < 1e-5 {
            *self = Self::default();
            return None;
        }
        if let Some(short) = self.short {
            let corrected = delta.mul(ComplexSample::rotation(-self.frequency));
            let quadrant = (corrected.phase() / (PI / 2.)).round() as i32;
            let pair = match quadrant.rem_euclid(4) {
                0 => [0, 0],
                1 => [0, 1],
                2 => [1, 1],
                _ => [1, 0],
            };
            let serial = if short {
                pair
            } else {
                [u8::from(corrected.i < 0.), 0]
            };
            for bit in serial.into_iter().take(if short { 2 } else { 1 }) {
                self.header[self.bits / 8] |= self.descrambler.bit(bit) << (self.bits % 8);
                self.bits += 1;
            }
            self.quality += quality;
            if self.bits == 48 {
                let decoded =
                    length(self.header, short, bound).map(|(rate_bps, psdu_bytes)| Header {
                        short,
                        rate_bps,
                        psdu_bytes,
                        preamble_start: self.sfd_end - if short { 72. * 20. } else { 144. * 20. },
                        payload_start: start + 20.,
                        frequency_rad: self.frequency / 20.,
                        previous_symbol: symbol,
                        descrambler: self.descrambler,
                        correlation: self.quality / if short { 24. } else { 48. },
                    });
                *self = Self::default();
                return Some(decoded.ok_or(()));
            }
            return None;
        }
        let bit = u8::from(delta.i < 0.);
        let residual = delta.scale(if bit == 0 { 1. } else { -1. }).phase();
        self.frequency = 0.95 * self.frequency + 0.05 * residual;
        let plain = self.descrambler.bit(bit);
        self.shift = (self.shift >> 1) | (u16::from(plain) << 15);
        // SYNC must precede the complete SFD, not merely resemble its last bits.
        if self.shift == 0xf3a0 || self.shift == 0x05cf {
            let short = self.shift == 0x05cf;
            if self.run >= 32 && self.last == u8::from(!short) {
                self.short = Some(short);
                self.sfd_end = start + 20.;
                self.bits = 0;
                self.header = [0; 6];
                self.quality = 0.;
            }
        }
        // Count the bit leaving the SFD window, retaining the preceding SYNC run.
        let oldest = (self.shift & 1) as u8;
        if oldest == self.last {
            self.run = self.run.saturating_add(1).min(256);
        } else {
            self.last = oldest;
            self.run = 1;
        }
        None
    }
}

pub(super) struct Acquisition {
    samples: Samples,
    tracks: [Track; 20],
    config: Option<RxConfig>,
    position: Option<IqPosition>,
    pending: Option<Header>,
    suppress_until: f64,
    stream_start: u64,
    pub resets: u64,
    pub invalid_headers: u64,
    pub truncated_headers: u64,
}
impl Acquisition {
    pub fn new() -> Self {
        Self {
            samples: Samples::new(),
            tracks: std::array::from_fn(|_| Track::default()),
            config: None,
            position: None,
            pending: None,
            suppress_until: 0.,
            stream_start: 0,
            resets: 0,
            invalid_headers: 0,
            truncated_headers: 0,
        }
    }
    pub fn reset(&mut self) {
        self.truncated_headers += u64::from(self.tracks.iter().any(|track| track.short.is_some()));
        self.tracks.fill(Track::default());
        self.pending = None;
        self.position = None;
        self.config = None;
        self.suppress_until = 0.;
        self.resets += 1;
    }
    /// Header callback avoids an unbounded output allocation. No payload storage here.
    #[cfg(test)]
    pub fn push(&mut self, chunk: &IqChunk, mut emit: impl FnMut(Header)) -> RadioResult<()> {
        self.push_samples(chunk, |header, _| {
            if let Some(header) = header {
                emit(header);
            }
        })
    }
    fn push_samples(
        &mut self,
        chunk: &IqChunk,
        mut emit: impl FnMut(Option<Header>, &Samples),
    ) -> RadioResult<()> {
        if chunk.config().sample_rate_hz != 20_000_000 {
            self.reset();
            return Err(RadioError::Invalid {
                field: "sample_rate_hz",
                reason: "DSSS acquisition requires 20 Msps",
            });
        }
        let p = chunk.position();
        let continuous = self.config.as_ref() == Some(chunk.config())
            && self.position.as_ref().is_some_and(|old| {
                old.epoch == p.epoch && old.sequence.checked_add(1) == Some(p.sequence)
            })
            && self.samples.end == p.sample_index
            && p.discontinuity.is_none();
        if !continuous {
            self.reset();
            self.samples.clear(p.sample_index);
            self.stream_start = p.sample_index;
        }
        self.config = Some(chunk.config().clone());
        self.position = Some(p.clone());
        for value in chunk.normalized() {
            self.samples.push(value);
            // Eight samples of lookahead plus one complete Barker symbol.
            if self.samples.end < 29 {
                continue;
            }
            let start = self.samples.end - 29;
            let track_index = start as usize % 20;
            let timing = self.tracks[track_index].timing;
            let symbol_start = start as f64 + timing;
            if self.tracks[track_index].run >= 32 || self.tracks[track_index].short.is_some() {
                if let (Some((_, early)), Some((_, late))) = (
                    self.samples.barker(symbol_start - 0.5),
                    self.samples.barker(symbol_start + 0.5),
                ) {
                    // Bounded early/late correction in original sample units, retained
                    // across chunks. Adjacent acquisition tracks cover the other phases.
                    self.tracks[track_index].timing = (timing
                        + f64::from((late - early).clamp(-0.1, 0.1)) * 0.2)
                        .clamp(-0.5, 0.5);
                }
            }
            if let Some((symbol, quality)) = self.samples.barker(symbol_start) {
                if let Some(result) = self.tracks[track_index].symbol(
                    symbol,
                    quality,
                    symbol_start,
                    chunk.config().max_frame_bytes,
                ) {
                    let header = match result {
                        Ok(header) => header,
                        Err(()) => {
                            self.invalid_headers += 1;
                            continue;
                        }
                    };
                    if header.preamble_start >= self.suppress_until
                        && header.preamble_start >= self.stream_start as f64
                    {
                        if self
                            .pending
                            .as_ref()
                            .map_or(true, |old| header.correlation > old.correlation)
                        {
                            self.pending = Some(header);
                        }
                    }
                }
            }
            if self
                .pending
                .as_ref()
                .is_some_and(|h| start as f64 >= h.payload_start + 20.)
            {
                let header = self.pending.take().unwrap();
                self.suppress_until = header.payload_start;
                emit(Some(header), &self.samples);
            }
            emit(None, &self.samples);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> RxConfig {
        RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_437_000_000,
            max_chunk_samples: 100_000,
            max_buffer_samples: 100_000,
            max_frame_bytes: 4096,
            max_pending_frames: 8,
            max_capture_samples: 1_000_000,
            max_duration: Duration::from_secs(1),
        }
    }
    fn decode(bytes: &[u8], width: usize) -> Vec<Header> {
        let mut acquisition = Acquisition::new();
        let mut output = Vec::new();
        let mut offset = 0;
        for (sequence, bytes) in bytes.chunks(width * 2).enumerate() {
            let chunk = IqChunk::new(
                config(),
                IqPosition {
                    epoch: 0,
                    sequence: sequence as u64,
                    sample_index: offset,
                    time_anchor: None,
                    discontinuity: None,
                },
                bytes.iter().map(|&x| x as i8).collect(),
            )
            .unwrap();
            acquisition.push(&chunk, |h| output.push(h)).unwrap();
            offset += chunk.len() as u64;
        }
        output
    }
    #[test]
    fn radio_dsss_headers_independent_vectors() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
        let index = std::fs::read_to_string(root.join("dsss-index.tsv")).unwrap();
        for row in index.lines().skip(1) {
            let columns: Vec<_> = row.split('\t').collect();
            let name = columns[0];
            let bytes = std::fs::read(root.join(format!("{name}.cs8"))).unwrap();
            let expected = ![
                "bad_crc",
                "bad_signal",
                "bad_sfd",
                "pbcc",
                "truncated_sync",
                "truncated_sfd",
                "truncated_header",
            ]
            .iter()
            .any(|part| name.contains(part));
            for width in [1, 137, 4096] {
                let decoded = decode(&bytes, width);
                assert_eq!(
                    decoded.len(),
                    usize::from(expected),
                    "{name}, chunk {width}: {decoded:?}"
                );
                if expected {
                    let h = &decoded[0];
                    assert_eq!(h.rate_bps, columns[1].parse::<u32>().unwrap(), "{name}");
                    assert_eq!(h.psdu_bytes, columns[4].len() / 2);
                    assert_eq!(h.short, columns[2] == "short");
                    let impaired = name.contains("impaired");
                    let origin = if impaired { 37.375 } else { 37. };
                    let duration = if h.short { 1920. } else { 3840. };
                    let payload = origin + duration * if impaired { 1.000035 } else { 1. };
                    assert!((h.preamble_start - origin).abs() < 3., "{name}: {h:?}");
                    assert!((h.payload_start - payload).abs() < 3., "{name}: {h:?}");
                    let carrier = if impaired { 45_000. } else { 0. };
                    assert!(
                        (h.frequency_rad * 20_000_000. / std::f32::consts::TAU - carrier).abs()
                            < 10_000.,
                        "{name}: {h:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn radio_dsss_short_fractional_carrier_and_clock_offsets() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
        for rate in [20, 55, 110] {
            let input =
                std::fs::read(root.join(format!("dsss-{rate}-short-clean-48.cs8"))).unwrap();
            for carrier in [-45_000., 45_000.] {
                let samples: Vec<_> = input
                    .chunks_exact(2)
                    .map(|b| ComplexSample {
                        i: b[0] as i8 as f32,
                        q: b[1] as i8 as f32,
                    })
                    .collect();
                let mut output = Vec::with_capacity(input.len());
                for n in 0..samples.len() {
                    let position = (n as f64 - 0.375) / 1.000035;
                    let base = position.floor() as isize;
                    let fraction = (position - position.floor()) as f32;
                    let at = |index: isize| {
                        if index < 0 {
                            ComplexSample::ZERO
                        } else {
                            samples
                                .get(index as usize)
                                .copied()
                                .unwrap_or(ComplexSample::ZERO)
                        }
                    };
                    let value = at(base)
                        .scale(1. - fraction)
                        .add(at(base + 1).scale(fraction))
                        .mul(ComplexSample::rotation(
                            std::f32::consts::TAU * carrier * n as f32 / 20_000_000.,
                        ));
                    output.push(value.i.round().clamp(-128., 127.) as i8 as u8);
                    output.push(value.q.round().clamp(-128., 127.) as i8 as u8);
                }
                let decoded = decode(&output, 137);
                assert_eq!(decoded.len(), 1, "short rate {rate}, CFO {carrier}");
                assert!(decoded[0].short);
                assert_eq!(decoded[0].rate_bps, rate * 100_000);
                assert!((decoded[0].preamble_start - 37.375).abs() < 3.);
            }
        }
    }

    #[test]
    fn radio_dsss_header_validation_bounds() {
        assert_eq!(crc16(&[0x0a, 0, 0xc0, 0]), 0xeada);
        let mut h = [10, 0, 0xc0, 0, 0xda, 0xea];
        assert_eq!(length(h, false, 24), Some((1_000_000, 24)));
        assert!(length(h, false, 23).is_none());
        assert!(length(h, true, 24).is_none());
        for service in [1, 2, 8, 16, 32, 64, 128] {
            h[1] = service;
            let crc = crc16(&h[..4]).to_le_bytes();
            h[4..].copy_from_slice(&crc);
            assert!(length(h, false, 4096).is_none());
        }
        assert!(decode(&vec![0; 100_000], 127).is_empty());
        let noise: Vec<u8> = (0..100_000u32)
            .map(|i| {
                i.wrapping_mul(1664525)
                    .wrapping_add(1013904223)
                    .rotate_left(13) as u8
            })
            .collect();
        assert!(decode(&noise, 113).is_empty());
    }
    #[test]
    fn radio_dsss_continuity_resets() {
        let bytes = include_bytes!("../../tests/fixtures/iq/dsss-10-long-clean-48.cs8");
        for variant in 0..5 {
            let mut acquisition = Acquisition::new();
            let mut output = Vec::new();
            for (i, part) in bytes.chunks(3200).enumerate() {
                let mut cfg = config();
                let mut position = IqPosition {
                    epoch: 0,
                    sequence: i as u64,
                    sample_index: (i * 1600) as u64,
                    time_anchor: None,
                    discontinuity: None,
                };
                if i == 1 {
                    match variant {
                        0 => position.epoch += 1,
                        1 => position.sequence += 1,
                        2 => position.sample_index += 1,
                        3 => {
                            position.discontinuity = Some(Discontinuity {
                                reason: GapReason::SourceLoss,
                                loss: SampleLoss::Unknown,
                            })
                        }
                        _ => cfg.center_frequency_hz += 1,
                    }
                }
                let chunk =
                    IqChunk::new(cfg, position, part.iter().map(|&b| b as i8).collect()).unwrap();
                acquisition.push(&chunk, |h| output.push(h)).unwrap();
            }
            assert!(output.is_empty(), "reset variant {variant}");
            assert!(acquisition.resets >= 2);
        }
    }
}

struct Payload {
    header: Header,
    start: IqPosition,
    bytes: Vec<u8>,
    bits: usize,
    next: f64,
}
impl Payload {
    fn advance(&mut self, samples: &Samples) -> bool {
        while samples.end as f64 >= self.next + 29. {
            let Some((symbol, _)) = samples.barker(self.next) else {
                return false;
            };
            let corrected = symbol
                .mul(self.header.previous_symbol.conj())
                .mul(ComplexSample::rotation(-self.header.frequency_rad * 20.));
            self.header.previous_symbol = symbol;
            let pair = match ((corrected.phase() / (PI / 2.)).round() as i32).rem_euclid(4) {
                0 => [0, 0],
                1 => [0, 1],
                2 => [1, 1],
                _ => [1, 0],
            };
            let serial = if self.header.rate_bps == 1_000_000 {
                [u8::from(corrected.i < 0.), 0]
            } else {
                pair
            };
            for bit in serial
                .into_iter()
                .take(if self.header.rate_bps == 1_000_000 {
                    1
                } else {
                    2
                })
            {
                self.bytes[self.bits / 8] |= self.header.descrambler.bit(bit) << (self.bits % 8);
                self.bits += 1;
            }
            // Track slow sample-clock drift using the Barker correlation slope.
            let adjustment = match (
                samples.barker(self.next - 0.5),
                samples.barker(self.next + 0.5),
            ) {
                (Some((_, early)), Some((_, late))) => {
                    f64::from((late - early).clamp(-0.1, 0.1)) * 0.2
                }
                _ => 0.,
            };
            self.next += 20. + adjustment;
            if self.bits == self.bytes.len() * 8 {
                return true;
            }
        }
        false
    }
}
/// Streaming 20 Msps DSSS receiver. CCK headers are recognized but their payloads
/// are currently rejected explicitly. Only received-FCS-valid frames are emitted.
pub struct DsssCckDecoder {
    acquisition: Acquisition,
    continuity: IqContinuity,
    pending: Option<Payload>,
    terminal: bool,
    stats: DecoderStats,
}
impl Default for DsssCckDecoder {
    fn default() -> Self {
        Self {
            acquisition: Acquisition::new(),
            continuity: IqContinuity::default(),
            pending: None,
            terminal: false,
            stats: DecoderStats::default(),
        }
    }
}
impl DsssCckDecoder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn stats(&self) -> DecoderStats {
        self.stats
    }
}
impl PhyDecoder for DsssCckDecoder {
    fn reset(&mut self, reason: ResetReason) -> DecodeOutput {
        let mut out = DecodeOutput::default();
        if self.pending.take().is_some()
            || self.acquisition.pending.is_some()
            || self.acquisition.tracks.iter().any(|t| t.short.is_some())
        {
            self.stats.truncated_frames += 1;
            out.diagnostics.push(PhyDiagnostic::TruncatedFrame);
        }
        self.acquisition.reset();
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
        if config.sample_rate_hz != 20_000_000 || config.max_buffer_samples < 128 {
            self.reset(ResetReason::Explicit);
            return Err(RadioError::Invalid {
                field: "config",
                reason: "DSSS requires 20 Msps and at least 128 buffer samples",
            });
        }
        let mut out = DecodeOutput::default();
        if let Some(gap) = self.continuity.observe(&chunk) {
            out = self.reset(ResetReason::Gap(gap));
            self.continuity.observe(&chunk);
        }
        let old_invalid = self.acquisition.invalid_headers;
        let pending = &mut self.pending;
        let stats = &mut self.stats;
        self.acquisition.push_samples(&chunk, |header, samples| {
            if let Some(header) = header {
                if pending.is_none() {
                    if header.rate_bps > 2_000_000 {
                        stats.rejected_frames += 1;
                        if out.diagnostics.len() < config.max_pending_frames {
                            out.diagnostics.push(PhyDiagnostic::UnsupportedPhy);
                        }
                    } else {
                        let mut start = chunk.position().clone();
                        start.sample_index = header.preamble_start.floor() as u64;
                        *pending = Some(Payload {
                            next: header.payload_start,
                            bytes: vec![0; header.psdu_bytes],
                            bits: 0,
                            start,
                            header,
                        });
                    }
                }
            }
            if pending.as_mut().is_some_and(|p| p.advance(samples)) {
                let p = pending.take().unwrap();
                let split = p.bytes.len() - 4;
                let mut crc = !0u32;
                for byte in &p.bytes[..split] {
                    crc ^= u32::from(*byte);
                    for _ in 0..8 {
                        crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
                    }
                }
                if !crc == u32::from_le_bytes(p.bytes[split..].try_into().unwrap()) {
                    stats.valid_frames += 1;
                    if out.frames.len() < config.max_pending_frames {
                        out.frames.push(RecoveredFrame {
                            bytes: p.bytes,
                            link_type: LinkType::Ieee80211,
                            integrity: FrameIntegrity::ValidFcs,
                            config: config.clone(),
                            start: p.start,
                            end_sample_index: p.next.ceil() as u64,
                            rate_bps: p.header.rate_bps,
                            diagnostics: vec![PhyDiagnostic::Dsss {
                                short_preamble: p.header.short,
                                frequency_offset_hz: p.header.frequency_rad * 20_000_000.
                                    / std::f32::consts::TAU,
                                timing_uncertainty_samples: 3,
                            }],
                        });
                    } else {
                        stats.dropped_frames += 1;
                        if out.diagnostics.len() < config.max_pending_frames {
                            out.diagnostics.push(PhyDiagnostic::Reset(ResetReason::Gap(
                                Discontinuity {
                                    reason: GapReason::QueueOverflow,
                                    loss: SampleLoss::Known(0),
                                },
                            )));
                        }
                    }
                } else {
                    stats.invalid_fcs += 1;
                    if out.diagnostics.len() < config.max_pending_frames {
                        out.diagnostics.push(PhyDiagnostic::InvalidFcs);
                    }
                }
            }
        })?;
        let rejected = self.acquisition.invalid_headers - old_invalid;
        self.stats.rejected_frames += rejected;
        if rejected > 0 && out.diagnostics.len() < config.max_pending_frames {
            out.diagnostics.push(PhyDiagnostic::InvalidHeader);
        }
        Ok(out)
    }
}
