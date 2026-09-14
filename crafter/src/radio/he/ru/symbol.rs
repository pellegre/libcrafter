//! One-stream HE20 RU DATA, including STBC, ax-2021 27.3.12.8-13.
//! No MU-MIMO separation, header admission, FEC or MAC integrity is implied.
use super::Tones;
use crate::radio::ComplexSample;

pub(in crate::radio) struct Observation {
    bins: [ComplexSample; 256],
    phase: f32,
    slope: f32,
}

/// A bounded constant-clock retry model inferred only from received pilots.
/// Fits carrier phase and sampling-clock slope across uniformly spaced DATA
/// symbols; never span a midamble/channel reset. FEC and MAC still decide
/// whether a retry is usable, not the regression residual or assumed payload.
pub(in crate::radio) fn fit_pilot_clock(observed: &[Observation]) -> Option<Vec<(f32, f32)>> {
    if !(3..=400).contains(&observed.len()) {
        return None;
    }
    let center = (observed.len() - 1) as f64 / 2.;
    let mut previous = f64::from(observed[0].phase);
    let (mut phase, mut phase_x, mut slope, mut slope_x, mut xx) = (0., 0., 0., 0., 0.);
    for (n, item) in observed.iter().enumerate() {
        if !item.phase.is_finite() || !item.slope.is_finite() {
            return None;
        }
        let value = previous
            + (f64::from(item.phase) - previous + std::f64::consts::PI)
                .rem_euclid(std::f64::consts::TAU)
            - std::f64::consts::PI;
        previous = value;
        let x = n as f64 - center;
        phase += value;
        phase_x += x * value;
        slope += f64::from(item.slope);
        slope_x += x * f64::from(item.slope);
        xx += x * x;
    }
    let mut result = Vec::new();
    result.try_reserve_exact(observed.len()).ok()?;
    for n in 0..observed.len() {
        let x = n as f64 - center;
        let p = (phase / observed.len() as f64 + x * phase_x / xx) as f32;
        let s = (slope / observed.len() as f64 + x * slope_x / xx) as f32;
        if !p.is_finite() || !s.is_finite() {
            return None;
        }
        result.push((p, s));
    }
    Some(result)
}

#[derive(Clone)]
pub(in crate::radio) struct Demodulator {
    tones: Tones,
    bits: usize,
    ldpc: bool,
    dcm: bool,
    slope: f32,
    // FFT-domain noise floor and constellation-energy SNR target.
    pilot_quality: Option<(f32, f32)>,
}

impl Demodulator {
    pub fn new(tones: Tones, bits: usize, ldpc: bool, dcm: bool) -> Option<Self> {
        if !matches!(bits, 1 | 2 | 4 | 6 | 8 | 10 | 12)
            || (!ldpc && bits >= 10)
            || (dcm && bits > 4)
        {
            return None;
        }
        Some(Self {
            tones,
            bits,
            ldpc,
            dcm,
            slope: 0.,
            pilot_quality: None,
        })
    }

    pub fn for_tb(
        tones: Tones,
        bits: usize,
        ldpc: bool,
        dcm: bool,
        quantization_noise: f32,
    ) -> Option<Self> {
        if !quantization_noise.is_finite() || quantization_noise < 0. {
            return None;
        }
        let mut result = Self::new(tones, bits, ldpc, dcm)?;
        // Unit-power QAM has a half-decision interval of1/sqrt(energy).
        // Higher-order constellations therefore require cleaner pilot phase.
        let energy = match bits {
            1 => 1.,
            2 => 2.,
            4 => 10.,
            6 => 42.,
            8 => 170.,
            10 => 682.,
            12 => 2730.,
            _ => return None,
        };
        result.pilot_quality = Some((quantization_noise, energy));
        Some(result)
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
        if !matches!(polarity, -1. | 1.) {
            return None;
        }
        let pilots: Vec<_> = self
            .tones
            .pilots()
            .iter()
            .enumerate()
            .map(|(j, &k)| (k, self.tones.pilot_sign(symbol, j) * polarity))
            .collect();
        observe_with_pilot_policy(
            wave,
            channel,
            frequency_rad,
            elapsed,
            &pilots,
            self.slope,
            self.pilot_quality,
        )
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
        self.recover_observed(wave, channel, frequency_rad, elapsed, symbol, polarity)
            .map(|(metrics, _)| metrics)
    }

    pub fn recover_observed(
        &mut self,
        wave: &[ComplexSample],
        channel: &[ComplexSample; 256],
        frequency_rad: f32,
        elapsed: u64,
        symbol: usize,
        polarity: f32,
    ) -> Option<(Vec<f32>, Observation)> {
        let (bins, intercept, slope) =
            self.observe(wave, channel, frequency_rad, elapsed, symbol, polarity)?;
        let observation = Observation {
            bins,
            phase: intercept,
            slope,
        };
        let ordered = self.recover_observation(&observation, channel, intercept, slope)?;
        // A rejected symbol must not corrupt the phase tracker.
        self.slope = slope;
        Some((ordered, observation))
    }

    pub fn recover_observation(
        &self,
        observation: &Observation,
        channel: &[ComplexSample; 256],
        intercept: f32,
        slope: f32,
    ) -> Option<Vec<f32>> {
        if !intercept.is_finite() || !slope.is_finite() {
            return None;
        }
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
                observation.bins[bin]
                    .mul(channel[bin].conj())
                    .scale(1. / power)
                    .mul(ComplexSample::rotation(-intercept - slope * tone as f32))
            };
            if !value.power().is_finite() {
                return None;
            }
            observations.push((value, if power < 1e-12 { 0. } else { power }));
        }
        self.demap_observations(&observations)
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
        let result = self.recover_stbc_bins(&corrected, channels)?;
        self.slope = tracker.slope;
        Some(result)
    }

    /// Already phase-corrected consecutive DATA symbols. The PPDU caller
    /// owns shared pilot tracking, STBC pairing and channel coherence.
    pub fn recover_stbc_bins(
        &self,
        corrected: &[[ComplexSample; 256]; 2],
        channels: &[[ComplexSample; 256]; 2],
    ) -> Option<[Vec<f32>; 2]> {
        if self.dcm {
            return None;
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
                crate::radio::stbc::recover_pair(
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
            10 => 682.,
            _ => 2730.,
        };
        for k in 0..count {
            let tone = if self.ldpc {
                self.tones.ldpc_tone(k, self.dcm)?
            } else {
                k
            };
            if self.dcm {
                let metrics = crate::radio::data::demap_dcm_for_half(
                    [observations[tone], observations[tone + count]],
                    self.bits,
                    k,
                    count,
                )?;
                mapped.extend_from_slice(&metrics[..self.bits]);
            } else {
                let (v, power) = observations[tone];
                crate::radio::data::demap(
                    v.i,
                    (self.bits / 2).max(1),
                    energy.sqrt(),
                    power,
                    &mut mapped,
                );
                if self.bits > 1 {
                    crate::radio::data::demap(
                        v.q,
                        self.bits / 2,
                        energy.sqrt(),
                        power,
                        &mut mapped,
                    );
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

/// A common clock estimate from an explicit pilot map. MU may pool pilots
/// across RUs after applying each RU's own rotation and estimated channel.
pub(in crate::radio) fn observe_with_pilots(
    wave: &[ComplexSample],
    channel: &[ComplexSample; 256],
    frequency_rad: f32,
    elapsed: u64,
    pilot_map: &[(i32, f32)],
    previous_slope: f32,
) -> Option<([ComplexSample; 256], f32, f32)> {
    observe_with_pilot_policy(
        wave,
        channel,
        frequency_rad,
        elapsed,
        pilot_map,
        previous_slope,
        None,
    )
}

fn observe_with_pilot_policy(
    wave: &[ComplexSample],
    channel: &[ComplexSample; 256],
    frequency_rad: f32,
    elapsed: u64,
    pilot_map: &[(i32, f32)],
    previous_slope: f32,
    quality: Option<(f32, f32)>,
) -> Option<([ComplexSample; 256], f32, f32)> {
    if wave.len() != 256
        || !frequency_rad.is_finite()
        || !previous_slope.is_finite()
        || pilot_map.len() < 2
        || pilot_map.len() > 18
    {
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
    let bins = crate::radio::he::fft::fft256(time);
    // HE20 leaves these guard/DC bins unmodulated, even with other RUs active.
    // A median limits the influence of one interferer on the noise estimate.
    let noise = if let Some((floor, _)) = quality {
        let mut powers = [
            0, 1, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 255,
        ]
        .map(|k| bins[k].power());
        powers.sort_by(f32::total_cmp);
        (0.75 * (powers[6] + powers[7])).max(floor)
    } else {
        0.
    };
    let mut pilots = Vec::with_capacity(pilot_map.len());
    let mut common = ComplexSample::ZERO;
    let strongest = pilot_map
        .iter()
        .map(|&(k, _)| channel[k.rem_euclid(256) as usize].power())
        .fold(0., f32::max);
    for &(tone, sign) in pilot_map {
        if !(-122..=122).contains(&tone) || !matches!(sign, -1. | 1.) {
            return None;
        }
        let bin = tone.rem_euclid(256) as usize;
        let value = bins[bin]
            .mul(channel[bin].conj())
            .scale(sign)
            .mul(ComplexSample::rotation(-previous_slope * tone as f32));
        if !value.power().is_finite() {
            return None;
        }
        // A weak, noisy summed STBC pilot is not useful slope evidence.
        // With two pilots an unconstrained line passes through both phases
        // regardless of weight. Retain the prior slope if only one survives;
        // do not substitute a different TB transmitter's pilot phase.
        if pilot_map.len() == 2
            && quality.is_some_and(|(_, required_snr)| {
                channel[bin].power() * 2. < strongest && channel[bin].power() < required_snr * noise
            })
        {
            continue;
        }
        common = common.add(value);
        pilots.push((tone as f32, value));
    }
    if !common.power().is_finite() || common.power() < 1e-12 {
        return None;
    }
    let reference = common.phase();
    let single = pilots.len() == 1;
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
    if !determinant.is_finite() || (!single && determinant < 1e-12) {
        return None;
    }
    let delta = if single {
        0.
    } else {
        (w * xy - x * y) / determinant
    };
    let intercept = reference + (y - delta * x) / w;
    let slope = previous_slope + delta;
    if !intercept.is_finite() || !slope.is_finite() {
        return None;
    }
    Some((bins, intercept, slope))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_he_tb_pilot_clock_fit_wraps_noise_and_bounds() {
        let mut observed: Vec<_> = (0..20)
            .map(|n| {
                let noise = if n % 2 == 0 { 0.04 } else { -0.04 };
                Observation {
                    bins: [ComplexSample::ZERO; 256],
                    phase: (0.2 + 0.4 * n as f32 + noise + std::f32::consts::PI)
                        .rem_euclid(std::f32::consts::TAU)
                        - std::f32::consts::PI,
                    slope: 0.001 + 0.00001 * n as f32 + noise * 0.002,
                }
            })
            .collect();
        let fitted = fit_pilot_clock(&observed).unwrap();
        for (n, (phase, slope)) in fitted.into_iter().enumerate() {
            assert!((phase - (0.2 + 0.4 * n as f32)).abs() < 0.01);
            assert!((slope - (0.001 + 0.00001 * n as f32)).abs() < 0.00002);
        }
        for len in 0..3 {
            assert!(fit_pilot_clock(&observed[..len]).is_none());
        }
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            observed[3].phase = bad;
            assert!(fit_pilot_clock(&observed).is_none());
        }
        observed[3].phase = 0.;
        observed[3].slope = f32::NAN;
        assert!(fit_pilot_clock(&observed).is_none());
        let oversized: Vec<_> = (0..401)
            .map(|_| Observation {
                bins: [ComplexSample::ZERO; 256],
                phase: 0.,
                slope: 0.,
            })
            .collect();
        assert!(fit_pilot_clock(&oversized).is_none());
    }

    #[test]
    fn radio_he_tb_pilot_null_retains_prior_slope() {
        let tones = Tones::ru(26, 2).unwrap();
        for floor in [-1., f32::NAN, f32::INFINITY] {
            assert!(Demodulator::for_tb(tones, 10, true, false, floor).is_none());
        }
        let map: [(i32, f32); 2] = [(-90, 1.), (-76, -1.)];
        let mut channel = [ComplexSample::ZERO; 256];
        channel[166].i = 1.;
        channel[180].i = 0.01;
        let prior = 0.0043;
        let wave: Vec<_> = (0..256)
            .map(|n| {
                map.iter()
                    .enumerate()
                    .fold(ComplexSample::ZERO, |v, (j, &(k, sign))| {
                        let phase = std::f32::consts::TAU * k as f32 * n as f32 / 256.
                            + 0.4
                            + prior * k as f32
                            + if j == 1 { 1.2 } else { 0. };
                        v.add(
                            channel[k.rem_euclid(256) as usize]
                                .scale(sign / 256.)
                                .mul(ComplexSample::rotation(phase)),
                        )
                    })
                    .add(
                        [
                            0, 1, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 255,
                        ]
                        .iter()
                        .fold(ComplexSample::ZERO, |v, &k| {
                            v.add(
                                ComplexSample::rotation(
                                    std::f32::consts::TAU * k as f32 * n as f32 / 256.,
                                )
                                .scale(0.05 / 256.),
                            )
                        }),
                    )
            })
            .collect();
        let (_, phase, slope) =
            observe_with_pilot_policy(&wave, &channel, 0., 0, &map, prior, Some((0., 64.)))
                .unwrap();
        assert!((phase - 0.4).abs() < 1e-5);
        assert_eq!(slope, prior);
        let empty = [ComplexSample::ZERO; 256];
        assert!(
            observe_with_pilot_policy(&wave, &empty, 0., 0, &map, prior, Some((0., 64.))).is_none()
        );
        let mut bad = channel;
        bad[180].i = f32::NAN;
        assert!(
            observe_with_pilot_policy(&wave, &bad, 0., 0, &map, prior, Some((0., 64.))).is_none()
        );
    }

    #[test]
    fn radio_he_ru_independent_stbc_iq_pairs() {
        let rows = include_str!("../../../../tests/fixtures/iq/he-ru-stbc-symbol.tsv");
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
            // Weak but noise-free pilots still contain slope information.
            // TB's null rejection must not freeze a valid clock estimate.
            let mut tb = Demodulator::for_tb(tones, bits, ldpc, false, 0.).unwrap();
            let tb_actual = tb
                .recover_stbc_pair(wave, &channels, cfo, times, symbol, polarity)
                .unwrap();
            for j in 0..2 {
                for (&got, &reference) in tb_actual[j].iter().zip(&actual[j]) {
                    assert!(got.is_finite());
                    assert_eq!(got > 0., reference > 0., "TB {:?}", &c[..11]);
                }
            }
            assert!((tb.slope - if case == 0 { 0. } else { 0.0043 }).abs() < 1e-5);
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
        let rows = include_str!("../../../../tests/fixtures/iq/he-ru-symbol.tsv");
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
