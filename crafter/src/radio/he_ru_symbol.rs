//! One-stream HE20 RU DATA, ax-2021 27.3.12.8-10/13.
//! No spatial separation, header admission, FEC or MAC integrity is implied.
use super::{he_tones::Tones, ComplexSample};

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
        // A rejected symbol must not corrupt the phase tracker.
        self.slope = slope;
        Some(ordered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
