//! One-stream HE20 RU DATA, including STBC, ax-2021 27.3.12.8-13.
//! No MU-MIMO separation, header admission, FEC or MAC integrity is implied.
use super::{he_tones::Tones, ComplexSample};

#[derive(Clone)]
pub(super) struct Demodulator {
    tones: Tones,
    bits: usize,
    ldpc: bool,
    dcm: bool,
    slope: f32,
}

impl Demodulator {
    pub fn new(tones: Tones, bits: usize, ldpc: bool, dcm: bool) -> Option<Self> {
        if !matches!(bits, 1 | 2 | 4 | 6 | 8 | 10) || (!ldpc && bits == 10) || (dcm && bits > 4) {
            return None;
        }
        Some(Self {
            tones,
            bits,
            ldpc,
            dcm,
            slope: 0.,
        })
    }

    /// Reset after a new channel estimate (including a midamble).
    pub fn reset(&mut self) {
        self.slope = 0.;
    }

    /// FFT and pilot phase estimate without changing the phase tracker.
    fn observe(
        &self,
        wave: &[ComplexSample],
        channel: &[ComplexSample; 256],
        frequency_rad: f32,
        elapsed: u64,
        symbol: usize,
        polarity: f32,
    ) -> Option<([ComplexSample; 256], f32, f32)> {
        if wave.len() != 256 || !frequency_rad.is_finite() || !matches!(polarity, -1. | 1.) {
            return None;
        }
        elapsed.checked_add(255)?;
        let mut time = [ComplexSample::ZERO; 256];
        for (n, value) in time.iter_mut().enumerate() {
            if !wave[n].power().is_finite() {
                return None;
            }
            *value = wave[n].mul(ComplexSample::rotation(
                -frequency_rad * (elapsed + n as u64) as f32,
            ));
        }
        let bins = super::he_fft::fft256(time);
        let mut pilots = Vec::with_capacity(self.tones.pilots().len());
        let mut common = ComplexSample::ZERO;
        for (j, &tone) in self.tones.pilots().iter().enumerate() {
            let bin = tone.rem_euclid(256) as usize;
            let value = bins[bin]
                .mul(channel[bin].conj())
                .scale(self.tones.pilot_sign(symbol, j) * polarity)
                .mul(ComplexSample::rotation(-self.slope * tone as f32));
            if !value.power().is_finite() {
                return None;
            }
            common = common.add(value);
            pilots.push((tone as f32, value));
        }
        if !common.power().is_finite() || common.power() < 1e-12 {
            return None;
        }
        let reference = common.phase();
        let (mut w, mut x, mut xx, mut y, mut xy) = (0., 0., 0., 0., 0.);
        for (k, v) in pilots {
            let weight = v.power().sqrt();
            let residual = v.mul(ComplexSample::rotation(-reference)).phase();
            w += weight;
            x += weight * k;
            xx += weight * k * k;
            y += weight * residual;
            xy += weight * k * residual;
        }
        let determinant = w * xx - x * x;
        if !determinant.is_finite() || determinant < 1e-12 {
            return None;
        }
        let delta = (w * xy - x * y) / determinant;
        let intercept = reference + (y - delta * x) / w;
        let slope = self.slope + delta;
        if !intercept.is_finite() || !slope.is_finite() {
            return None;
        }
        Some((bins, intercept, slope))
    }

    /// Exactly one useful 256-sample symbol, excluding its guard interval.
    /// `elapsed` is measured from the acquisition CFO phase origin. Pilot
    /// polarity and DATA symbol index are provided by the PPDU-level caller.
    /// Returns the full symbol, including post-FEC padding; FEC removes it.
    pub fn recover(
        &mut self,
        wave: &[ComplexSample],
        channel: &[ComplexSample; 256],
        frequency_rad: f32,
        elapsed: u64,
        symbol: usize,
        polarity: f32,
    ) -> Option<Vec<f32>> {
        let (bins, intercept, slope) =
            self.observe(wave, channel, frequency_rad, elapsed, symbol, polarity)?;
        let mut observations = Vec::with_capacity(self.tones.count());
        for tone in self.tones.data() {
            let bin = tone.rem_euclid(256) as usize;
            let power = channel[bin].power();
            if !power.is_finite() {
                return None;
            }
            let value = if power < 1e-12 {
                ComplexSample::ZERO
            } else {
                bins[bin]
                    .mul(channel[bin].conj())
                    .scale(1. / power)
                    .mul(ComplexSample::rotation(-intercept - slope * tone as f32))
            };
            if !value.power().is_finite() {
                return None;
            }
            observations.push((value, if power < 1e-12 { 0. } else { power }));
        }
        let ordered = self.demap_observations(&observations)?;
        // A rejected symbol must not corrupt the phase tracker.
        self.slope = slope;
        Some(ordered)
    }

    /// Two consecutive useful symbols, starting at an even DATA symbol.
    /// Effective channels include STS cyclic shifts and must be coherent over
    /// the pair. Pilots are identical on both STS (27.3.12.13), so phase is
    /// measured against their summed channel before Alamouti combining.
    /// Reject the entire pair atomically; do not retain a half-pair or advance
    /// the phase tracker if either symbol or its metrics are invalid.
    pub fn recover_stbc_pair(
        &mut self,
        waves: [&[ComplexSample]; 2],
        channels: &[[ComplexSample; 256]; 2],
        frequency_rad: f32,
        elapsed: [u64; 2],
        symbol: usize,
        polarity: [f32; 2],
    ) -> Option<[Vec<f32>; 2]> {
        if self.dcm
            || symbol % 2 != 0
            || !matches!(elapsed[1].checked_sub(elapsed[0])?, 272 | 288 | 320)
        {
            return None;
        }
        let second_symbol = symbol.checked_add(1)?;
        let pilot_channel = std::array::from_fn(|k| channels[0][k].add(channels[1][k]));
        let mut tracker = self.clone();
        let mut corrected = [[ComplexSample::ZERO; 256]; 2];
        for (j, index) in [symbol, second_symbol].into_iter().enumerate() {
            let (bins, intercept, slope) = tracker.observe(
                waves[j],
                &pilot_channel,
                frequency_rad,
                elapsed[j],
                index,
                polarity[j],
            )?;
            for tone in self.tones.data() {
                let k = tone.rem_euclid(256) as usize;
                corrected[j][k] =
                    bins[k].mul(ComplexSample::rotation(-intercept - slope * tone as f32));
            }
            tracker.slope = slope;
        }
        let mut observations = [
            Vec::with_capacity(self.tones.count()),
            Vec::with_capacity(self.tones.count()),
        ];
        for tone in self.tones.data() {
            let k = tone.rem_euclid(256) as usize;
            let power = channels[0][k].power() + channels[1][k].power();
            if !power.is_finite() {
                return None;
            }
            let values = if power < 1e-12 {
                [ComplexSample::ZERO; 2]
            } else {
                super::stbc::recover_pair(
                    [channels[0][k], channels[1][k]],
                    [corrected[0][k], corrected[1][k]],
                )
                .ok()?
            };
            for j in 0..2 {
                observations[j].push((values[j], if power < 1e-12 { 0. } else { power }));
            }
        }
        let result = [
            self.demap_observations(&observations[0])?,
            self.demap_observations(&observations[1])?,
        ];
        self.slope = tracker.slope;
        Some(result)
    }

    fn demap_observations(&self, observations: &[(ComplexSample, f32)]) -> Option<Vec<f32>> {
        if observations.len() != self.tones.count() {
            return None;
        }
        let count = self.tones.count() / (1 + usize::from(self.dcm));
        let mut mapped = Vec::with_capacity(count * self.bits);
        let energy: f32 = match self.bits {
            1 => 1.,
            2 => 2.,
            4 => 10.,
            6 => 42.,
            8 => 170.,
            _ => 682.,
        };
        for k in 0..count {
            let tone = if self.ldpc {
                self.tones.ldpc_tone(k, self.dcm)?
            } else {
                k
            };
            if self.dcm {
                let metrics = super::data::demap_dcm_for_half(
                    [observations[tone], observations[tone + count]],
                    self.bits,
                    k,
                    count,
                )?;
                mapped.extend_from_slice(&metrics[..self.bits]);
            } else {
                let (v, power) = observations[tone];
                super::data::demap(
                    v.i,
                    (self.bits / 2).max(1),
                    energy.sqrt(),
                    power,
                    &mut mapped,
                );
                if self.bits > 1 {
                    super::data::demap(v.q, self.bits / 2, energy.sqrt(), power, &mut mapped);
                }
            }
        }
        let ordered = if self.ldpc {
            mapped
        } else {
            (0..mapped.len())
                .map(|k| Some(mapped[self.tones.bcc_bit(k, self.bits, self.dcm)?]))
                .collect::<Option<Vec<_>>>()?
        };
        if ordered.iter().any(|v| !v.is_finite()) {
            return None;
        }
        Some(ordered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_he_ru_independent_stbc_iq_pairs() {
        let rows = include_str!("../../tests/fixtures/iq/he-ru-stbc-symbol.tsv");
        assert_eq!(rows.lines().skip(1).count(), 880);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let tones = Tones::ru(c[0].parse().unwrap(), c[1].parse().unwrap()).unwrap();
            let bits = c[2].parse().unwrap();
            let ldpc = c[3] == "1";
            let case: u8 = c[4].parse().unwrap();
            let symbol = c[5].parse().unwrap();
            let polarity = [c[6].parse().unwrap(), c[7].parse().unwrap()];
            let elapsed = c[8].parse::<u64>().unwrap();
            let times = [elapsed, elapsed + c[9].parse::<u64>().unwrap()];
            let cfo = c[10].parse().unwrap();
            let waves: [Vec<_>; 2] = std::array::from_fn(|j| {
                let numbers: Vec<f32> = c[13 + j].split(',').map(|v| v.parse().unwrap()).collect();
                numbers
                    .chunks_exact(2)
                    .map(|v| ComplexSample { i: v[0], q: v[1] })
                    .collect()
            });
            let wave = [waves[0].as_slice(), waves[1].as_slice()];
            let mut channels = [[ComplexSample::ZERO; 256]; 2];
            let erased = if case == 4 {
                tones.data().nth(tones.count() / 3)
            } else {
                None
            };
            for k in tones.active() {
                let angle = std::f32::consts::TAU * k as f32 / 256.;
                let h0 = if case == 2 || erased == Some(k) {
                    ComplexSample::ZERO
                } else if case == 0 {
                    ComplexSample { i: 1., q: 0. }
                } else {
                    ComplexSample { i: 1., q: 0.25 }.mul(ComplexSample::rotation(-3. * angle))
                };
                let h1 = if case == 3 || erased == Some(k) {
                    ComplexSample::ZERO
                } else {
                    (if case == 0 {
                        ComplexSample { i: 0.4, q: 0.3 }
                    } else {
                        ComplexSample { i: 0.6, q: -0.3 }.add(
                            ComplexSample { i: 0., q: 0.2 }
                                .mul(ComplexSample::rotation(-5. * angle)),
                        )
                    })
                    .mul(ComplexSample::rotation(8. * angle))
                };
                let bin = k.rem_euclid(256) as usize;
                channels[0][bin] = h0.scale(std::f32::consts::FRAC_1_SQRT_2);
                channels[1][bin] = h1.scale(std::f32::consts::FRAC_1_SQRT_2);
            }
            let mut demod = Demodulator::new(tones, bits, ldpc, false).unwrap();
            let actual = demod
                .recover_stbc_pair(wave, &channels, cfo, times, symbol, polarity)
                .unwrap_or_else(|| panic!("{:?}", &c[..11]));
            for j in 0..2 {
                assert_eq!(actual[j].len(), c[11 + j].len());
                for (k, (&metric, bit)) in actual[j].iter().zip(c[11 + j].bytes()).enumerate() {
                    if bit == b'-' {
                        assert_eq!(metric, 0.);
                    } else {
                        assert_eq!(
                            u8::from(metric > 0.),
                            bit - b'0',
                            "{:?} symbol {j} bit {k}: {metric}",
                            &c[..11]
                        );
                    }
                }
            }
            assert!((demod.slope - if case == 0 { 0. } else { 0.0043 }).abs() < 1e-5);
            let repeated = demod
                .recover_stbc_pair(wave, &channels, cfo, times, symbol, polarity)
                .unwrap();
            for j in 0..2 {
                assert!(actual[j]
                    .iter()
                    .zip(&repeated[j])
                    .all(|(a, b)| (a - b).abs() < 1e-4 * (1. + a.abs())));
            }
            let before = demod.slope;
            assert!(demod
                .recover_stbc_pair(
                    [wave[0], &wave[1][..255]],
                    &channels,
                    cfo,
                    times,
                    symbol,
                    polarity
                )
                .is_none());
            assert!(demod
                .recover_stbc_pair(
                    [&wave[0][..255], wave[1]],
                    &channels,
                    cfo,
                    times,
                    symbol,
                    polarity
                )
                .is_none());
            assert!(demod
                .recover_stbc_pair(wave, &channels, cfo, times, symbol + 1, polarity)
                .is_none());
            assert!(demod
                .recover_stbc_pair(wave, &channels, cfo, [elapsed, elapsed], symbol, polarity)
                .is_none());
            assert!(demod
                .recover_stbc_pair(wave, &channels, cfo, [elapsed, u64::MAX], symbol, polarity)
                .is_none());
            assert!(demod
                .recover_stbc_pair(wave, &channels, f32::NAN, times, symbol, polarity)
                .is_none());
            assert!(demod
                .recover_stbc_pair(wave, &channels, cfo, times, symbol, [1., 0.])
                .is_none());
            let mut bad = waves[1].clone();
            bad[127].i = f32::NAN;
            assert!(demod
                .recover_stbc_pair([wave[0], &bad], &channels, cfo, times, symbol, polarity)
                .is_none());
            let mut bad_channel = channels;
            bad_channel[0][tones.data().next().unwrap().rem_euclid(256) as usize].q = f32::NAN;
            assert!(demod
                .recover_stbc_pair(wave, &bad_channel, cfo, times, symbol, polarity)
                .is_none());
            assert!(demod
                .recover_stbc_pair(
                    wave,
                    &[[ComplexSample::ZERO; 256]; 2],
                    cfo,
                    times,
                    symbol,
                    polarity
                )
                .is_none());
            assert_eq!(demod.slope, before);
            demod.reset();
            assert_eq!(demod.slope, 0.);
            if bits <= 4 {
                let mut dcm = Demodulator::new(tones, bits, ldpc, true).unwrap();
                assert!(dcm
                    .recover_stbc_pair(wave, &channels, cfo, times, symbol, polarity)
                    .is_none());
                assert_eq!(dcm.slope, 0.);
            }
        }
    }

    #[test]
    fn radio_he_ru_independent_iq_symbols() {
        let rows = include_str!("../../tests/fixtures/iq/he-ru-symbol.tsv");
        assert_eq!(rows.lines().skip(1).count(), 640);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let ru = c[0].parse().unwrap();
            let tones = Tones::ru(ru, c[1].parse().unwrap()).unwrap();
            let bits = c[2].parse().unwrap();
            let ldpc = c[3] == "1";
            let dcm = c[4] == "1";
            let case: u8 = c[5].parse().unwrap();
            let symbol = c[6].parse().unwrap();
            let polarity = c[7].parse().unwrap();
            let elapsed = c[8].parse().unwrap();
            let cfo = c[9].parse().unwrap();
            let values: Vec<f32> = c[11].split(',').map(|v| v.parse().unwrap()).collect();
            let wave: Vec<_> = values
                .chunks_exact(2)
                .map(|v| ComplexSample { i: v[0], q: v[1] })
                .collect();
            let mut channel = [ComplexSample::ZERO; 256];
            for k in tones.active() {
                channel[k.rem_euclid(256) as usize] = if case == 0 {
                    ComplexSample { i: 1., q: 0. }
                } else {
                    ComplexSample { i: 1., q: 0. }.add(ComplexSample { i: 0., q: 0.25 }.mul(
                        ComplexSample::rotation(-std::f32::consts::TAU * k as f32 * 3. / 256.),
                    ))
                };
            }
            if case == 2 {
                for k in tones.data().take(tones.count() / 2) {
                    channel[k.rem_euclid(256) as usize] = ComplexSample::ZERO;
                }
            }
            let mut demod = Demodulator::new(tones, bits, ldpc, dcm).unwrap();
            let actual = demod
                .recover(&wave, &channel, cfo, elapsed, symbol, polarity)
                .unwrap();
            let expected = c[10].as_bytes();
            assert_eq!(actual.len(), expected.len());
            for (i, (&metric, &bit)) in actual.iter().zip(expected).enumerate() {
                assert_eq!(
                    u8::from(metric > 0.),
                    bit - b'0',
                    "{:?} bit {i}: {metric}",
                    &c[..10]
                );
            }
            assert!((demod.slope - if case == 0 { 0. } else { 0.004 }).abs() < 1e-5);
            // Tracking the same phase twice must not add the slope twice.
            let repeated = demod
                .recover(&wave, &channel, cfo, elapsed, symbol, polarity)
                .unwrap();
            assert!(actual
                .iter()
                .zip(repeated)
                .all(|(a, b)| (a - b).abs() < 1e-4 * (1. + a.abs())));
            let before = demod.slope;
            assert!(demod
                .recover(&wave[..255], &channel, cfo, elapsed, symbol, polarity)
                .is_none());
            assert!(demod
                .recover(&wave, &channel, cfo, u64::MAX, symbol, polarity)
                .is_none());
            assert!(demod
                .recover(&wave, &channel, f32::NAN, elapsed, symbol, polarity)
                .is_none());
            assert!(demod
                .recover(&wave, &channel, cfo, elapsed, symbol, 0.)
                .is_none());
            assert_eq!(demod.slope, before);
            let mut bad = wave.clone();
            bad[0].i = f32::NAN;
            assert!(demod
                .recover(&bad, &channel, cfo, elapsed, symbol, polarity)
                .is_none());
            let mut bad_channel = channel;
            bad_channel[tones.pilots()[0].rem_euclid(256) as usize].i = f32::NAN;
            assert!(demod
                .recover(&wave, &bad_channel, cfo, elapsed, symbol, polarity)
                .is_none());
            assert!(demod
                .recover(
                    &wave,
                    &[ComplexSample::ZERO; 256],
                    cfo,
                    elapsed,
                    symbol,
                    polarity
                )
                .is_none());
            assert_eq!(demod.slope, before);
            demod.reset();
            assert_eq!(demod.slope, 0.);
        }
        let tones = Tones::ru(26, 1).unwrap();
        for bits in [0, 3, 5, 7, 9, 11, usize::MAX] {
            assert!(Demodulator::new(tones, bits, true, false).is_none());
        }
        assert!(Demodulator::new(tones, 10, false, false).is_none());
        for bits in [6, 8, 10] {
            assert!(Demodulator::new(tones, bits, true, true).is_none());
        }
    }
}
