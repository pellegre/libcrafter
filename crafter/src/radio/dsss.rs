//! Private clause 15/18 acquisition. Coordinates refer to the original 20 Msps stream.
use super::*;
use std::f32::consts::PI;
const BARKER: [f32; 11] = [1., -1., 1., 1., -1., 1., 1., 1., -1., -1., -1.];
const GRID_PHASES: [usize; 11] = [0, 23, 47, 70, 93, 116, 140, 163, 186, 209, 233];

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

/// Fixed history with separate coarse-search and refined interpolation kernels.
struct Samples {
    // The first sixteen entries are mirrored at the end so every FIR window
    // is contiguous, including windows crossing the logical 64-sample wrap.
    ring: [ComplexSample; 80],
    kernels: [[f32; 16]; 256],
    coarse_kernels: [[f32; 8]; 11],
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
        let mut coarse_kernels = [[0.; 8]; 11];
        for (phase, kernel) in coarse_kernels.iter_mut().enumerate() {
            let fraction = GRID_PHASES[phase] as f32 / 256.;
            for (k, coefficient) in kernel.iter_mut().enumerate() {
                let x = k as f32 - 3. - fraction;
                let sinc = if x.abs() < 1e-6 {
                    1.
                } else {
                    (PI * x).sin() / (PI * x)
                };
                *coefficient = sinc * (0.5 + 0.5 * (PI * x / 4.).cos());
            }
            let gain: f32 = kernel.iter().sum();
            for coefficient in kernel {
                *coefficient /= gain;
            }
        }
        Self {
            ring: [ComplexSample::ZERO; 80],
            kernels,
            coarse_kernels,
            begin: 0,
            end: 0,
        }
    }
    fn clear(&mut self, start: u64) {
        self.begin = start;
        self.end = start;
    }
    fn push(&mut self, value: ComplexSample) {
        let offset = self.end as usize % 64;
        self.ring[offset] = value;
        if offset < 16 {
            self.ring[offset + 64] = value;
        }
        self.end += 1;
        self.begin = self.begin.max(self.end.saturating_sub(64));
    }
    fn at(&self, time: f64) -> Option<ComplexSample> {
        // Source coordinates are nonnegative. Truncation therefore supplies
        // floor without a libm call or a floating-point-to-i128 conversion.
        if !time.is_finite() || time < 0. {
            return None;
        }
        let center = time as u64;
        let start = center.checked_sub(7)?;
        let last_start = self.end.checked_sub(16)?;
        if start < self.begin || start > last_start {
            return None;
        }
        let phase = ((time - center as f64) * 256. + 0.5) as usize;
        // Nearest phase; carry into the next source sample at the phase boundary.
        let (start, phase) = if phase == 256 {
            (start + 1, 0)
        } else {
            (start, phase)
        };
        if start > last_start {
            return None;
        }
        Some(self.at_window(start, phase))
    }
    #[inline]
    fn at_grid(&self, center: u64, phase: usize) -> Option<ComplexSample> {
        let start = center.checked_sub(3)?;
        if start < self.begin || start > self.end.checked_sub(8)? {
            return None;
        }
        let offset = (start % 64) as usize;
        Some(Self::dot(
            &self.ring[offset..offset + 8],
            &self.coarse_kernels[phase],
        ))
    }
    #[inline]
    fn at_window(&self, start: u64, phase: usize) -> ComplexSample {
        let offset = (start % 64) as usize;
        Self::dot(&self.ring[offset..offset + 16], &self.kernels[phase])
    }
    #[inline(always)]
    fn dot<const N: usize>(values: &[ComplexSample], weights: &[f32; N]) -> ComplexSample {
        // Independent accumulators expose parallel arithmetic without unsafe
        // SIMD or changing the interpolation coefficients.
        let mut sums = [ComplexSample::ZERO; 4];
        for k in (0..N).step_by(4) {
            for lane in 0..4 {
                sums[lane] = sums[lane].add(values[k + lane].scale(weights[k + lane]));
            }
        }
        sums[0].add(sums[1]).add(sums[2]).add(sums[3])
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
        if quality < 0.25 || symbol.power() < 1e-5 {
            // A zero previous symbol denotes the already-reset search state.
            // Do not rewrite the entire track for every subsequent noise chip.
            // Accepted symbols have positive power, so an active track always
            // takes the full reset on the first failed correlation.
            if self.previous != ComplexSample::ZERO {
                *self = Self::default();
            }
            return None;
        }
        let delta = symbol.mul(self.previous.conj());
        self.previous = symbol;
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
        // Refinement belongs to an active SYNC/SFD or PLCP header. Once a
        // suspected SYNC expires, resume the shared nominal chip grid instead
        // of carrying its correction through unrelated payload or noise.
        if self.short.is_none() && self.run < 32 {
            self.timing = 0.;
        }
        None
    }
}

pub(super) struct Acquisition {
    samples: Samples,
    tracks: [Track; 22],
    // Internal half-chip grid (22 Msps), derived from the original 20 Msps
    // coordinates. Its 32 entries plus the 80 raw/mirrored entries stay below the
    // existing 128-sample private history reservation.
    chips: [ComplexSample; 32],
    next_chip: u64,
    chip_center: u64,
    chip_fraction: u8,
    first_chip: Option<u64>,
    chip_power: [f64; 2],
    config: Option<RxConfig>,
    position: Option<IqPosition>,
    pending: Option<Header>,
    payload_active: bool,
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
            chips: [ComplexSample::ZERO; 32],
            next_chip: 0,
            chip_center: 0,
            chip_fraction: 0,
            first_chip: None,
            chip_power: [0.; 2],
            config: None,
            position: None,
            pending: None,
            payload_active: false,
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
        self.next_chip = 0;
        self.chip_center = 0;
        self.chip_fraction = 0;
        self.first_chip = None;
        self.chip_power = [0.; 2];
        self.pending = None;
        self.payload_active = false;
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
            false
        })
    }
    fn push_samples(
        &mut self,
        chunk: &IqChunk,
        mut emit: impl FnMut(Option<Header>, &Samples) -> bool,
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
            self.chip_center = p.sample_index;
        }
        self.config = Some(chunk.config().clone());
        self.position = Some(p.clone());
        for value in chunk.normalized() {
            self.samples.push(value);
            loop {
                // Rational 10/11 source-sample steps visit only eleven of the
                // coarse interpolation phases. Keep the cursor in integers;
                // corrected timing still uses the general interpolator.
                let lookahead = 10 + u64::from(self.chip_fraction != 0);
                if self
                    .chip_center
                    .checked_add(lookahead)
                    .map_or(true, |end| end > self.samples.end)
                {
                    break;
                }
                let center = self.chip_center;
                let phase = self.chip_fraction as usize;
                self.chip_fraction += 10;
                if self.chip_fraction >= 11 {
                    self.chip_fraction -= 11;
                    self.chip_center =
                        self.chip_center
                            .checked_add(1)
                            .ok_or(RadioError::Overflow {
                                context: "DSSS source chip cursor",
                            })?;
                }
                let chip_index = self.next_chip;
                self.next_chip = self.next_chip.checked_add(1).ok_or(RadioError::Overflow {
                    context: "DSSS internal chip clock",
                })?;
                let Some(chip) = self.samples.at_grid(center, phase) else {
                    self.first_chip = None;
                    self.chip_power = [0.; 2];
                    continue;
                };
                let first = *self.first_chip.get_or_insert(chip_index);
                let parity = (chip_index % 2) as usize;
                // Each parity contains the eleven chip-spaced samples of one
                // Barker window. f64 state avoids accumulating f32 drift.
                if chip_index - first >= 22 {
                    self.chip_power[parity] -=
                        f64::from(self.chips[((chip_index - 22) % 32) as usize].power());
                }
                self.chip_power[parity] += f64::from(chip.power());
                self.chips[chip_index as usize % 32] = chip;
                if chip_index - first < 20 {
                    continue;
                }
                let start = self.stream_start as f64 + (chip_index as f64 - 21.) * (10. / 11.);
                let track_index = (chip_index % 22) as usize;
                let timing = self.tracks[track_index].timing;
                let symbol_start = start + timing;
                let coarse = if timing == 0. {
                    // Spell out the fixed signs so this hot correlation has
                    // no dynamic coefficient loads or inner loop branches.
                    let chip = |offset| self.chips[((chip_index - 20 + offset) % 32) as usize];
                    let sum = ComplexSample::ZERO
                        .add(chip(0))
                        .sub(chip(2))
                        .add(chip(4))
                        .add(chip(6))
                        .sub(chip(8))
                        .add(chip(10))
                        .add(chip(12))
                        .add(chip(14))
                        .sub(chip(16))
                        .sub(chip(18))
                        .sub(chip(20));
                    let power = self.chip_power[parity] as f32;
                    Some((sum.scale(1. / 11.), sum.power() / (11. * power).max(1e-12)))
                } else {
                    self.samples.barker(symbol_start)
                };
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
                if let Some((symbol, quality)) = coarse {
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
                    .is_some_and(|h| start >= h.payload_start + 20.)
                {
                    let header = self.pending.take().unwrap();
                    self.suppress_until = header.payload_start;
                    self.payload_active = emit(Some(header), &self.samples);
                }
                // The consumer requests sample notifications only while it
                // has a payload to finish. A new header always wakes it.
                if self.payload_active {
                    self.payload_active = emit(None, &self.samples);
                }
            }
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
    fn radio_dsss_rational_grid_matches_source_clock() {
        for origin in [0, u64::from(u32::MAX) - 8] {
            let mut acquisition = Acquisition::new();
            for sequence in 0..8 {
                let bytes: Vec<i8> = (0..226)
                    .map(|n| ((n * 37 + sequence * 17) % 255) as u8 as i8)
                    .collect();
                let chunk = IqChunk::new(
                    config(),
                    IqPosition {
                        epoch: 0,
                        sequence,
                        sample_index: origin + sequence * 113,
                        time_anchor: None,
                        discontinuity: None,
                    },
                    bytes,
                )
                .unwrap();
                acquisition.push(&chunk, |_| {}).unwrap();
                for index in acquisition.next_chip - 32..acquisition.next_chip {
                    // Closed-form source coordinates independently check the
                    // incremental rational cursor across chunk/ring boundaries.
                    let center = origin + index * 10 / 11;
                    let phase = (index * 10 % 11) as usize;
                    assert_eq!(
                        acquisition.chips[(index % 32) as usize],
                        acquisition.samples.at_grid(center, phase).unwrap(),
                        "origin {origin} chip {index}"
                    );
                }
            }
        }
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
    fn cck(&self, samples: &Samples, start: f64) -> Option<(ComplexSample, u8, f32)> {
        let mut chips = [ComplexSample::ZERO; 8];
        let mut power = 0.;
        for (k, chip) in chips.iter_mut().enumerate() {
            let offset = (k as f64 + 0.5) * 20. / 11.;
            *chip = samples.at(start + offset)?.mul(ComplexSample::rotation(
                -self.header.frequency_rad * (offset as f32 - 80. / 11.),
            ));
            power += chip.power();
        }
        let mut best = (ComplexSample::ZERO, 0, 0.);
        let count = if self.header.rate_bps == 5_500_000 {
            4
        } else {
            64
        };
        for word in 0..count {
            // Clause 18 binary phase map, unlike the differential Gray map.
            let (b, c, d) = if count == 4 {
                (2 * (word & 1) + 1, 0, 2 * (word >> 1))
            } else {
                let phase = |v: u8| 2 * (v & 1) + ((v >> 1) & 1);
                (phase(word), phase(word >> 2), phase(word >> 4))
            };
            let phases = [b + c + d, c + d, b + d, d, b + c, c, b, 0];
            let mut sum = ComplexSample::ZERO;
            for (k, chip) in chips.iter().enumerate() {
                let v = match phases[k] % 4 {
                    0 => *chip,
                    1 => ComplexSample {
                        i: chip.q,
                        q: -chip.i,
                    },
                    2 => chip.scale(-1.),
                    _ => ComplexSample {
                        i: -chip.q,
                        q: chip.i,
                    },
                };
                sum = sum.add(v.scale(if k == 3 || k == 6 { -1. } else { 1. }));
            }
            let quality = sum.power() / (8. * power).max(1e-12);
            if quality > best.2 {
                best = (sum.scale(0.125), word, quality);
            }
        }
        Some(best)
    }
    fn advance_cck(&mut self, samples: &Samples) -> bool {
        const SYMBOL: f64 = 160. / 11.;
        let width = if self.header.rate_bps == 5_500_000 {
            4
        } else {
            8
        };
        while samples.end as f64 >= self.next + SYMBOL + 9. {
            let Some((symbol, word, _)) = self.cck(samples, self.next) else {
                return false;
            };
            // First CCK center follows the last Barker center by half of each
            // symbol duration. Later CCK centers are one CCK symbol apart.
            let elapsed = if self.bits == 0 {
                10. + SYMBOL / 2.
            } else {
                SYMBOL
            };
            let delta =
                symbol
                    .mul(self.header.previous_symbol.conj())
                    .mul(ComplexSample::rotation(
                        -self.header.frequency_rad * elapsed as f32,
                    ));
            let parity = (self.bits / width) % 2;
            let quadrant =
                (((delta.phase() / (PI / 2.)).round() as i32) - 2 * parity as i32).rem_euclid(4);
            let pair = match quadrant {
                0 => 0,
                1 => 2,
                2 => 3,
                _ => 1,
            };
            let serial = pair | (word << 2);
            for k in 0..width {
                self.bytes[self.bits / 8] |=
                    self.header.descrambler.bit((serial >> k) & 1) << (self.bits % 8);
                self.bits += 1;
            }
            self.header.previous_symbol = symbol;
            let adjustment = match (
                self.cck(samples, self.next - 0.5),
                self.cck(samples, self.next + 0.5),
            ) {
                (Some((_, _, early)), Some((_, _, late))) => {
                    f64::from((late - early).clamp(-0.1, 0.1)) * 0.2
                }
                _ => 0.,
            };
            self.next += SYMBOL + adjustment;
            if self.bits == self.bytes.len() * 8 {
                return true;
            }
        }
        false
    }
    fn advance(&mut self, samples: &Samples) -> bool {
        if self.header.rate_bps > 2_000_000 {
            return self.advance_cck(samples);
        }
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
/// Streaming 20 Msps DSSS/CCK receiver. Only received-FCS-valid frames are emitted.
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
            pending.is_some()
        })?;
        let rejected = self.acquisition.invalid_headers - old_invalid;
        self.stats.rejected_frames += rejected;
        if rejected > 0 && out.diagnostics.len() < config.max_pending_frames {
            out.diagnostics.push(PhyDiagnostic::InvalidHeader);
        }
        Ok(out)
    }
}
