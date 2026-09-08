//! Private 20 Msps legacy OFDM acquisition (IEEE 802.11-2007 17.3.3).
//! Fixed storage, sample-at-a-time operation; no packet is asserted by acquisition.
#![allow(dead_code)] // Consumed by the subsequent SIGNAL/DATA decoder increment.
use super::*;
use std::f32::consts::TAU;

impl ComplexSample {
    pub(super) const ZERO: Self = Self { i: 0., q: 0. };
    pub(super) fn add(self, b: Self) -> Self {
        Self {
            i: self.i + b.i,
            q: self.q + b.q,
        }
    }
    pub(super) fn sub(self, b: Self) -> Self {
        Self {
            i: self.i - b.i,
            q: self.q - b.q,
        }
    }
    pub(super) fn mul(self, b: Self) -> Self {
        Self {
            i: self.i * b.i - self.q * b.q,
            q: self.i * b.q + self.q * b.i,
        }
    }
    pub(super) fn scale(self, s: f32) -> Self {
        Self {
            i: self.i * s,
            q: self.q * s,
        }
    }
    pub(super) fn conj(self) -> Self {
        Self {
            i: self.i,
            q: -self.q,
        }
    }
    pub(super) fn power(self) -> f32 {
        self.i * self.i + self.q * self.q
    }
    pub(super) fn phase(self) -> f32 {
        self.q.atan2(self.i)
    }
    pub(super) fn rotation(angle: f32) -> Self {
        Self {
            i: angle.cos(),
            q: angle.sin(),
        }
    }
}

/// Natural-order, unnormalized forward FFT. Negative carriers use bin 64+k.
pub(super) fn fft64(mut x: [ComplexSample; 64]) -> [ComplexSample; 64] {
    for i in 0usize..64 {
        let j = i.reverse_bits() >> (usize::BITS - 6);
        if j > i {
            x.swap(i, j);
        }
    }
    let mut width = 2;
    while width <= 64 {
        for base in (0..64).step_by(width) {
            for j in 0..width / 2 {
                let b = x[base + j + width / 2]
                    .mul(ComplexSample::rotation(-TAU * j as f32 / width as f32));
                let a = x[base + j];
                x[base + j] = a.add(b);
                x[base + j + width / 2] = a.sub(b);
            }
        }
        width *= 2;
    }
    x
}
// Equation 17-8, ascending signed carrier order -26..26.
const LONG: [i8; 53] = [
    1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, 1, 1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, 1, 0, 1, -1,
    -1, 1, 1, -1, 1, -1, 1, -1, -1, -1, -1, -1, 1, 1, -1, -1, 1, -1, 1, -1, 1, 1, 1, 1,
];
fn long_time() -> [ComplexSample; 64] {
    let mut bins = [ComplexSample::ZERO; 64];
    for (i, v) in LONG.iter().enumerate() {
        bins[((i as i32 - 26).rem_euclid(64)) as usize].i = *v as f32;
    }
    fft64(bins).map(|v| v.conj().scale(1. / 64.))
}
#[derive(Debug, Clone)]
pub(super) struct Acquisition {
    pub preamble_start: u64,
    pub signal_start: u64,
    /// Correction is exp(-j*frequency_rad*(index-phase_origin)).
    pub phase_origin: u64,
    pub frequency_rad: f32,
    pub coarse_frequency_rad: f32,
    pub channel: [ComplexSample; 64],
    pub correlation: f32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AcquisitionFailure {
    LongTrainingNotFound,
    Interrupted,
    UnsupportedSampleRate,
}
#[derive(Debug)]
pub(super) enum SyncEvent {
    Acquired(Acquisition),
    Failure(AcquisitionFailure),
    Reset(Discontinuity),
}
struct Candidate {
    detected: u64,
    coarse: f32,
}
#[derive(Clone, Copy)]
struct LongWindow {
    index: u64,
    cross: ComplexSample,
    energy: [f32; 2],
}
pub(super) struct Synchronizer {
    ring: [ComplexSample; 384],
    count: usize,
    next: usize,
    short_correlation: ComplexSample,
    short_energy: [f32; 2],
    long_window: Option<LongWindow>,
    candidate: Option<Candidate>,
    reference: [ComplexSample; 64],
    continuity: IqContinuity,
}
impl Default for Synchronizer {
    fn default() -> Self {
        Self {
            ring: [ComplexSample::ZERO; 384],
            count: 0,
            next: 0,
            short_correlation: ComplexSample::ZERO,
            short_energy: [0.; 2],
            long_window: None,
            candidate: None,
            reference: long_time(),
            continuity: IqContinuity::default(),
        }
    }
}
impl Synchronizer {
    pub fn clear(&mut self) -> bool {
        let interrupted = self.candidate.take().is_some();
        self.count = 0;
        self.next = 0;
        self.short_correlation = ComplexSample::ZERO;
        self.short_energy = [0.; 2];
        self.long_window = None;
        interrupted
    }
    pub fn reset(&mut self) -> bool {
        self.continuity.reset();
        self.clear()
    }
    /// Call before feeding each chunk with `push`; preserves continuity separately
    /// from acquisition state, allowing DATA reception to suspend the search.
    pub fn begin_chunk(
        &mut self,
        chunk: &IqChunk,
        mut emit: impl FnMut(SyncEvent),
    ) -> RadioResult<()> {
        if chunk.config().max_buffer_samples < 384 {
            return Err(RadioError::Limit {
                context: "OFDM synchronization buffer",
                limit: chunk.config().max_buffer_samples as u64,
                actual: 384,
            });
        }
        if let Some(gap) = self.continuity.observe(chunk) {
            if self.clear() {
                emit(SyncEvent::Failure(AcquisitionFailure::Interrupted));
            }
            emit(SyncEvent::Reset(gap));
        }
        if chunk.config().sample_rate_hz != 20_000_000 {
            self.clear();
            emit(SyncEvent::Failure(
                AcquisitionFailure::UnsupportedSampleRate,
            ));
            return Err(RadioError::Invalid {
                field: "sample_rate_hz",
                reason: "legacy OFDM requires 20 Msps",
            });
        }
        Ok(())
    }
    fn ago(&self, n: usize) -> ComplexSample {
        let offset = self.next + 383 - n;
        self.ring[if offset >= 384 { offset - 384 } else { offset }]
    }
    #[inline]
    pub fn push(&mut self, sample: ComplexSample, index: u64) -> Option<SyncEvent> {
        self.ring[self.next] = sample;
        self.next += 1;
        if self.next == 384 {
            self.next = 0;
        }
        self.count = (self.count + 1).min(384);
        if self.count == 80 {
            for n in 0..64 {
                let x = self.ago(n + 16);
                let y = self.ago(n);
                self.short_correlation = self.short_correlation.add(x.conj().mul(y));
                self.short_energy[0] += x.power();
                self.short_energy[1] += y.power();
            }
        } else if self.count > 80 {
            // Slide the 64-pair lag-16 window in constant work per sample.
            // cs8 / 128 products and these bounded sums are exact in f32.
            let entering = self.ago(16);
            let leaving_x = self.ago(80);
            let leaving_y = self.ago(64);
            self.short_correlation = self
                .short_correlation
                .sub(leaving_x.conj().mul(leaving_y))
                .add(entering.conj().mul(sample));
            self.short_energy[0] += entering.power() - leaving_x.power();
            self.short_energy[1] += sample.power() - leaving_y.power();
        }
        if self.candidate.is_none() && self.count >= 80 {
            let p = self.short_correlation;
            let [a, b] = self.short_energy;
            if a > 0.001 && b > 0.001 && p.power() > 0.85 * a * b {
                self.candidate = Some(Candidate {
                    detected: index,
                    coarse: p.phase() / 16.,
                });
            }
        }
        let c = self.candidate.as_ref()?;
        // Two complete LTFs must follow the detected short-period window.
        if index - c.detected < 128 || self.count < 128 {
            return None;
        }
        if index - c.detected > 320 {
            self.candidate = None;
            return Some(SyncEvent::Failure(AcquisitionFailure::LongTrainingNotFound));
        }
        self.acquire_long(index, c.coarse)
    }
    // Consecutive training candidates share 63 of their 64 lag-64 pairs.
    fn training_window(&mut self, index: u64) -> LongWindow {
        let window = if let Some(previous) = self
            .long_window
            .filter(|w| w.index.checked_add(1) == Some(index))
        {
            let leaving = self.ago(128);
            let middle = self.ago(64);
            let entering = self.ago(0);
            LongWindow {
                index,
                cross: previous
                    .cross
                    .sub(leaving.conj().mul(middle))
                    .add(middle.conj().mul(entering)),
                energy: [
                    previous.energy[0] + middle.power() - leaving.power(),
                    previous.energy[1] + entering.power() - middle.power(),
                ],
            }
        } else {
            let mut window = LongWindow {
                index,
                cross: ComplexSample::ZERO,
                energy: [0.; 2],
            };
            for n in 0..64 {
                let first = self.ago(127 - n);
                let second = self.ago(63 - n);
                window.cross = window.cross.add(first.conj().mul(second));
                window.energy[0] += first.power();
                window.energy[1] += second.power();
            }
            window
        };
        self.long_window = Some(window);
        window
    }
    // Keep the training buffers and phase work off the per-sample search path.
    #[inline(never)]
    fn acquire_long(&mut self, index: u64, coarse: f32) -> Option<SyncEvent> {
        let window = self.training_window(index);
        let mut cross = window.cross;
        let [repeat_a, repeat_b] = window.energy;
        // A common frequency correction rotates the cross correlation but
        // preserves its magnitude and both energies. Reject nonrepeating
        // candidates before phase correction and reference matching.
        if cross.power() < 0.8 * repeat_a * repeat_b {
            return None;
        }
        cross = cross.mul(ComplexSample::rotation(-coarse * 64.));
        let fine = cross.phase() / 64.;
        let frequency = coarse + fine;
        let mut match_sum = ComplexSample::ZERO;
        let mut energy = 0.;
        let step = ComplexSample::rotation(-frequency);
        let mut phase_first = ComplexSample { i: 1., q: 0. };
        let mut phase_second = ComplexSample::rotation(-frequency * 64.);
        let mut first = [ComplexSample::ZERO; 64];
        let mut second = first;
        for n in 0..64 {
            first[n] = self.ago(127 - n).mul(phase_first);
            second[n] = self.ago(63 - n).mul(phase_second);
            phase_first = phase_first.mul(step);
            phase_second = phase_second.mul(step);
            let average = first[n].add(second[n]).scale(0.5);
            match_sum = match_sum.add(self.reference[n].conj().mul(average));
            energy += average.power();
        }
        // Reference energy is 52/64 by Parseval (IFFT normalization 1/64).
        let score = match_sum.power() / (energy * (52. / 64.) + f32::MIN_POSITIVE);
        if score < 0.65 || energy < 0.001 {
            return None;
        }
        let first_index = index.checked_sub(127)?;
        let preamble_start = first_index.checked_sub(192)?;
        let bins = fft64(std::array::from_fn(|n| first[n].add(second[n]).scale(0.5)));
        let mut channel = [ComplexSample::ZERO; 64];
        for (i, v) in LONG.iter().enumerate() {
            let k = (i as i32 - 26).rem_euclid(64) as usize;
            channel[k] = bins[k].scale(*v as f32);
        }
        self.clear();
        Some(SyncEvent::Acquired(Acquisition {
            preamble_start,
            signal_start: index + 1,
            phase_origin: first_index,
            frequency_rad: frequency,
            coarse_frequency_rad: coarse,
            channel,
            correlation: score,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn radio_sync_incremental_correlation_matches_direct_window() {
        let mut sync = Synchronizer::default();
        let mut random = 123u32;
        for index in 0..10_000 {
            if index == 5000 {
                sync.clear();
            }
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            let sample = ComplexSample {
                i: (random >> 24) as u8 as i8 as f32 / 128.,
                q: (random >> 16) as u8 as i8 as f32 / 128.,
            };
            sync.push(sample, index);
            if sync.count >= 80 {
                let mut correlation = ComplexSample::ZERO;
                let mut energy = [0.; 2];
                for n in 0..64 {
                    let x = sync.ago(n + 16);
                    let y = sync.ago(n);
                    correlation = correlation.add(x.conj().mul(y));
                    energy[0] += x.power();
                    energy[1] += y.power();
                }
                assert_eq!(sync.short_correlation, correlation);
                assert_eq!(sync.short_energy, energy);
            }
            if sync.count >= 128 && index % 17 != 0 {
                let window = sync.training_window(index);
                let mut correlation = ComplexSample::ZERO;
                let mut energy = [0.; 2];
                for n in 0..64 {
                    let x = sync.ago(127 - n);
                    let y = sync.ago(63 - n);
                    correlation = correlation.add(x.conj().mul(y));
                    energy[0] += x.power();
                    energy[1] += y.power();
                }
                assert_eq!(window.cross, correlation);
                assert_eq!(window.energy, energy);
            }
        }
    }
    fn run(bytes: &[u8], size: usize) -> Vec<Acquisition> {
        let mut s = Synchronizer::default();
        let mut out = Vec::new();
        let c = RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: size,
            max_buffer_samples: size.max(384),
            max_frame_bytes: 4096,
            max_pending_frames: 4,
            max_capture_samples: 100000,
            max_duration: Duration::from_secs(1),
        };
        let mut index = 0;
        for (seq, b) in bytes.chunks(size * 2).enumerate() {
            let chunk = IqChunk::new(
                c.clone(),
                IqPosition {
                    epoch: 0,
                    sequence: seq as u64,
                    sample_index: index,
                    time_anchor: None,
                    discontinuity: None,
                },
                b.iter().map(|v| *v as i8).collect(),
            )
            .unwrap();
            s.begin_chunk(&chunk, |_| {}).unwrap();
            for v in chunk.normalized() {
                if let Some(SyncEvent::Acquired(a)) = s.push(v, index) {
                    out.push(a);
                }
                index += 1;
            }
        }
        out
    }
    #[test]
    fn radio_sync_independent_timing_frequency_and_chunk_invariance() {
        for (bytes, hz) in [
            (
                include_bytes!("../../tests/fixtures/iq/ofdm-6-clean.cs8").as_slice(),
                0.,
            ),
            (
                include_bytes!("../../tests/fixtures/iq/ofdm-6-offset.cs8").as_slice(),
                80000.,
            ),
            (
                include_bytes!("../../tests/fixtures/iq/ofdm-6-noisy.cs8").as_slice(),
                0.,
            ),
        ] {
            let baseline = run(bytes, 4096);
            assert_eq!(baseline.len(), 1);
            let a = &baseline[0];
            assert_eq!(a.preamble_start, 37);
            assert_eq!(a.signal_start, 357);
            assert!((a.frequency_rad * 20_000_000. / TAU - hz).abs() < 1500.);
            assert!((a.coarse_frequency_rad * 20_000_000. / TAU - hz).abs() < 4000.);
            assert!(a.correlation > 0.9);
            for size in [1, 7, 16, 63, 80, 127, 321] {
                let b = run(bytes, size);
                assert_eq!(b.len(), 1);
                assert_eq!(b[0].signal_start, a.signal_start);
                assert_eq!(b[0].frequency_rad, a.frequency_rad);
                assert_eq!(b[0].channel, a.channel);
            }
            // The independent vector's SIGNAL is BPSK: equalizing its FFT must
            // recover its published intermediate interleaved bit sequence.
            let mut signal = [ComplexSample::ZERO; 64];
            for (n, v) in signal.iter_mut().enumerate() {
                let index = 373 + n;
                *v = ComplexSample {
                    i: bytes[index * 2] as i8 as f32 / 128.,
                    q: bytes[index * 2 + 1] as i8 as f32 / 128.,
                }
                .mul(ComplexSample::rotation(
                    -a.frequency_rad * (index as u64 - a.phase_origin) as f32,
                ));
            }
            let bins = fft64(signal);
            let expected = "101111110000110010100100110010100010000010000110";
            let actual: String = (-26i32..=26)
                .filter(|k| ![-21, -7, 0, 7, 21].contains(k))
                .map(|k| {
                    let k = k.rem_euclid(64) as usize;
                    if bins[k].mul(a.channel[k].conj()).i > 0. {
                        '1'
                    } else {
                        '0'
                    }
                })
                .collect();
            assert_eq!(actual, expected);
        }
    }
    #[test]
    fn radio_sync_fft_analytic_bins() {
        let x = std::array::from_fn(|n| ComplexSample::rotation(TAU * 5. * n as f32 / 64.));
        let bins = fft64(x);
        for (k, v) in bins.iter().enumerate() {
            assert!((v.i - if k == 5 { 64. } else { 0. }).abs() < 0.0001);
            assert!(v.q.abs() < 0.0001);
        }
    }
    #[test]
    fn radio_sync_noise_rejection_and_bounded_failure() {
        let mut state = 7u32;
        let bytes: Vec<u8> = (0..20000)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 24) as u8
            })
            .collect();
        assert!(run(&bytes, 31).is_empty());
        let mut s = Synchronizer::default();
        let mut failed = false;
        for i in 0..1000 {
            if let Some(SyncEvent::Failure(AcquisitionFailure::LongTrainingNotFound)) =
                s.push(ComplexSample { i: 0.5, q: 0. }, i)
            {
                failed = true;
            }
        }
        assert!(failed);
        assert_eq!(s.ring.len(), 384);
        assert!(s.count <= 384);
    }
    #[test]
    fn radio_sync_loss_recovery() {
        let bytes = include_bytes!("../../tests/fixtures/iq/ofdm-6-clean.cs8");
        let mut s = Synchronizer::default();
        for (i, b) in bytes[..400].chunks_exact(2).enumerate() {
            s.push(
                ComplexSample {
                    i: b[0] as i8 as f32 / 128.,
                    q: b[1] as i8 as f32 / 128.,
                },
                i as u64,
            );
        }
        assert!(s.reset());
        assert_eq!(s.count, 0);
        let mut found = None;
        for (i, b) in bytes.chunks_exact(2).enumerate() {
            if let Some(SyncEvent::Acquired(a)) = s.push(
                ComplexSample {
                    i: b[0] as i8 as f32 / 128.,
                    q: b[1] as i8 as f32 / 128.,
                },
                1000 + i as u64,
            ) {
                found = Some(a);
            }
        }
        assert_eq!(found.unwrap().preamble_start, 1037);
    }
    #[test]
    fn radio_sync_discontinuities_and_config_limits() {
        let mut config = RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: 200,
            max_buffer_samples: 384,
            max_frame_bytes: 4096,
            max_pending_frames: 4,
            max_capture_samples: 10000,
            max_duration: Duration::from_secs(1),
        };
        let position = IqPosition {
            epoch: 0,
            sequence: 0,
            sample_index: 0,
            time_anchor: None,
            discontinuity: None,
        };
        let bytes = include_bytes!("../../tests/fixtures/iq/ofdm-6-clean.cs8");
        for mode in 0..3 {
            let mut sync = Synchronizer::default();
            let first = IqChunk::new(
                config.clone(),
                position.clone(),
                bytes[..400].iter().map(|v| *v as i8).collect(),
            )
            .unwrap();
            sync.begin_chunk(&first, |_| {}).unwrap();
            for (i, v) in first.normalized().enumerate() {
                sync.push(v, i as u64);
            }
            let mut next = position.clone();
            next.sequence = 1;
            next.sample_index = 200;
            let mut next_config = config.clone();
            if mode == 0 {
                next.sample_index += 7;
            }
            if mode == 1 {
                next.discontinuity = Some(Discontinuity {
                    reason: GapReason::QueueOverflow,
                    loss: SampleLoss::Unknown,
                });
            }
            if mode == 2 {
                next_config.center_frequency_hz += 20_000_000;
            }
            let next = IqChunk::new(next_config, next, vec![0; 2]).unwrap();
            let mut events = Vec::new();
            sync.begin_chunk(&next, |e| events.push(e)).unwrap();
            assert!(matches!(
                events[0],
                SyncEvent::Failure(AcquisitionFailure::Interrupted)
            ));
            assert!(matches!(events[1], SyncEvent::Reset(_)));
            assert_eq!(sync.count, 0);
        }
        config.sample_rate_hz = 10_000_000;
        let mut sync = Synchronizer::default();
        let chunk = IqChunk::new(config.clone(), position.clone(), vec![0; 2]).unwrap();
        let mut unsupported = false;
        assert!(sync
            .begin_chunk(&chunk, |e| unsupported = matches!(
                e,
                SyncEvent::Failure(AcquisitionFailure::UnsupportedSampleRate)
            ))
            .is_err());
        assert!(unsupported);
        config.sample_rate_hz = 20_000_000;
        config.max_buffer_samples = 200;
        let chunk = IqChunk::new(config, position, vec![0; 2]).unwrap();
        assert!(matches!(
            sync.begin_chunk(&chunk, |_| {}),
            Err(RadioError::Limit { .. })
        ));
    }
}
