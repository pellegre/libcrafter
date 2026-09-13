//! HE20 SU/ER training and isolated MU RU estimation; IEEE802.11ax-2021 27.3.11.10.
use super::{
    he_iq::{decode_prefix, Prefix},
    he_tones::Tones,
    sync::Acquisition,
    ComplexSample,
};

// Equation27-43, exactly245 signed tones in ascending order -122..122.
// Equations27-41/42 use the same signed-tone order, with sparse training.
const LTF1: &[u8;245] = b"00-000+000+000-000+000-000+000+000+000+000-000-000+000+000+000-000-000-000+000-000-000+000+000-000-000+000-000-000+000-0000000-000+000+000+000+000+000+000-000-000-000-000-000+000-000-000-000+000-000-000+000-000-000+000-000+000-000-000-000-000-00";
const LTF2: &[u8;245] = b"-0-0-0+0+0-0+0-0-0-0-0+0-0+0-0-0+0+0-0+0+0+0+0+0-0+0-0+0-0-0+0+0-0+0-0-0-0-0+0-0+0+0+0-0-0+0-0-0-0-0-0+0-0-0-0+0+0+0-0-0+000+0-0+0+0-0+0+0-0+0+0-0-0+0-0+0+0+0+0-0+0-0+0+0-0-0+0-0-0-0-0-0+0-0+0+0-0-0+0+0-0+0-0-0-0-0+0-0+0+0+0-0-0+0-0-0-0-0-0+0-0+";
const LTF4: &[u8;245] = b"--+-+-+++-+++--+-----++----++-+-++++-+--++-++++--+---++++-++----+--++-+----+-+------++-----+--+++-+++-+-+-----+++---+-+++000-+-+-++-+++--+--+-+-+++-+++--+-----++------+-+----+-++--+----++-+++++++-++----+--++-+----+-+--++++--+++++-++---+---+-+-++";

pub(super) struct Trained {
    pub prefix: Prefix,
    pub channel: [ComplexSample; 256],
    pub second: Option<[ComplexSample; 256]>,
    pub data_start: u64,
    pub guard: usize,
}

impl Trained {
    /// ER LTFs, including midambles, have sqrt2 amplitude relative to DATA
    /// (27.3.10, 27-58). Restore the DATA channel scale after each estimate.
    pub fn normalize_er(&mut self) {
        if self.prefix.er {
            for value in &mut self.channel {
                *value = value.scale(std::f32::consts::FRAC_1_SQRT_2);
            }
            if let Some(second) = &mut self.second {
                for value in second {
                    *value = value.scale(std::f32::consts::FRAC_1_SQRT_2);
                }
            }
        }
    }
}

/// Fit a finite impulse response to sparse measurements. This receiver model
/// includes four precursor samples and delays within the cyclic prefix; it
/// averages quantization noise instead of amplifying it at interpolated tones.
/// The diagonal ridge stabilizes missing DC/edge measurements. This is not a
/// claim that channels outside the guard interval can be reconstructed.
/// For small RUs the system may be underdetermined; the ridge selects an
/// estimate without claiming unique recovery of the physical delay taps.
fn delay_fit(
    channel: &mut [ComplexSample; 256],
    tones: &[i32],
    guard: usize,
    allocation: Tones,
) -> Option<()> {
    let count = guard.checked_add(4)?;
    if count > 68 || tones.is_empty() {
        return None;
    }
    let mut normal = vec![vec![ComplexSample::ZERO; count + 1]; count];
    for &tone in tones {
        let basis: Vec<_> = (0..count)
            .map(|n| {
                ComplexSample::rotation(
                    -std::f32::consts::TAU * tone as f32 * (n as f32 - 4.) / 256.,
                )
            })
            .collect();
        for i in 0..count {
            let conjugate = basis[i].conj();
            for (j, &v) in basis.iter().enumerate() {
                normal[i][j] = normal[i][j].add(conjugate.mul(v));
            }
            normal[i][count] =
                normal[i][count].add(conjugate.mul(channel[tone.rem_euclid(256) as usize]));
        }
    }
    for (i, row) in normal.iter_mut().enumerate() {
        row[i].i += 0.001 * tones.len() as f32;
    }
    // Partial-pivot complex Gaussian elimination of the regularized normal equations.
    for col in 0..count {
        let pivot = (col..count)
            .max_by(|&a, &b| normal[a][col].power().total_cmp(&normal[b][col].power()))?;
        normal.swap(col, pivot);
        let divisor = normal[col][col];
        if !divisor.power().is_finite() || divisor.power() < 1e-12 {
            return None;
        }
        let inverse = divisor.conj().scale(1. / divisor.power());
        let (before, rest) = normal.split_at_mut(col);
        let (pivot_row, after) = rest.split_first_mut()?;
        for value in &mut pivot_row[col..] {
            *value = value.mul(inverse);
        }
        for row in before.iter_mut().chain(after) {
            let factor = row[col];
            for (value, &pivot_value) in row[col..].iter_mut().zip(&pivot_row[col..]) {
                *value = value.sub(factor.mul(pivot_value));
            }
        }
    }
    for tone in allocation.active() {
        let mut value = ComplexSample::ZERO;
        for (n, row) in normal.iter().enumerate() {
            value = value.add(row[count].mul(ComplexSample::rotation(
                -std::f32::consts::TAU * tone as f32 * (n as f32 - 4.) / 256.,
            )));
        }
        if !value.power().is_finite() {
            return None;
        }
        channel[tone.rem_euclid(256) as usize] = value;
    }
    Some(())
}

/// Input begins at L-SIG. Reject unsupported training layouts explicitly.
pub(super) fn train_su(samples: &[ComplexSample], a: &Acquisition) -> Option<Trained> {
    let prefix = decode_prefix(samples, a)?;
    let fields = prefix.signal;
    // Prefix then80 samples of HE-STF; ER repeats SIG-A (160 extra samples).
    let cp = 400 + 160 * usize::from(prefix.er);
    let (channel, second) = if fields.stbc {
        let [first, second] = if prefix.er {
            train_stbc_for_format(samples, a, &fields, cp, true)?
        } else {
            train_stbc_field(samples, a, &fields, cp)?
        };
        (first, Some(second))
    } else {
        (
            if prefix.er {
                train_for_format(samples, a, &fields, cp, true)?
            } else {
                train_field(samples, a, &fields, cp)?
            },
            None,
        )
    };
    let guard = usize::from(fields.guard_ns) / 50;
    let mut trained = Trained {
        prefix,
        channel,
        second,
        data_start: a.signal_start.checked_add(
            (cp + (1 + usize::from(fields.stbc)) * (guard + 64 * usize::from(fields.ltf_size)))
                as u64,
        )?,
        guard,
    };
    trained.normalize_er();
    Some(trained)
}

/// A preamble LTF or identical midamble field. `cp` is relative to L-SIG;
/// absolute phase uses the original acquisition, not a restarted CFO clock.
pub(super) fn train_field(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &super::he::SuSignal,
    cp: usize,
) -> Option<[ComplexSample; 256]> {
    train_for_format(samples, a, fields, cp, false)
}

pub(super) fn train_for_format(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &super::he::SuSignal,
    cp: usize,
    er: bool,
) -> Option<[ComplexSample; 256]> {
    let allocation = Tones::new(er, fields.bandwidth)?;
    if fields.space_time_streams != 1 || fields.stbc {
        return None;
    }
    let (mut channel, trained, guard) = observe_for_format(samples, a, fields, cp, er)?;
    let energy: f32 = channel.iter().map(|v| v.power()).sum();
    if !energy.is_finite() || energy < 1e-9 {
        return None;
    }
    delay_fit(&mut channel, &trained, guard, allocation)?;
    Some(channel)
}

/// SU uses P on DATA tones and R on pilots: the second LTF observes
/// -h1+h2 on DATA, but -(h1+h2) on pilots (27-55..57). Never treat
/// those pilot observations as separate-channel measurements.
pub(super) fn train_stbc_field(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &super::he::SuSignal,
    cp: usize,
) -> Option<[[ComplexSample; 256]; 2]> {
    train_stbc_for_format(samples, a, fields, cp, false)
}

pub(super) fn train_stbc_for_format(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &super::he::SuSignal,
    cp: usize,
    er: bool,
) -> Option<[[ComplexSample; 256]; 2]> {
    let allocation = Tones::new(er, fields.bandwidth)?;
    if !fields.stbc || fields.dcm || fields.space_time_streams != 2 {
        return None;
    }
    let (first, tones, guard) = observe_for_format(samples, a, fields, cp, er)?;
    let next = cp.checked_add(guard + 64 * usize::from(fields.ltf_size))?;
    let (second, _, _) = observe_for_format(samples, a, fields, next, er)?;
    let pilots = allocation.pilots();
    let mut phase = ComplexSample::ZERO;
    for &tone in tones.iter().filter(|k| pilots.contains(k)) {
        let bin = tone.rem_euclid(256) as usize;
        phase = phase.sub(second[bin].mul(first[bin].conj()));
    }
    if !phase.power().is_finite() {
        return None;
    }
    // A pilot null cannot measure residual phase: retain the acquisition CFO.
    let correction = ComplexSample::rotation(if phase.power() > 1e-18 {
        -phase.phase()
    } else {
        0.
    });
    let data: Vec<_> = tones.into_iter().filter(|k| !pilots.contains(k)).collect();
    let mut channels = [[ComplexSample::ZERO; 256]; 2];
    for &tone in &data {
        let bin = tone.rem_euclid(256) as usize;
        let separated =
            super::stbc::separate_training([first[bin], second[bin].mul(correction)]).ok()?;
        channels[0][bin] = separated[0];
        channels[1][bin] = separated[1];
    }
    let energy: f32 = channels.iter().flatten().map(|v| v.power()).sum();
    if !energy.is_finite() || energy < 1e-9 {
        return None;
    }
    // Remove each known STS cyclic shift for delay fitting, then restore it.
    // Keeping a common physical delay interval avoids fitting extra noise
    // degrees of freedom just to accommodate STS2's -400 ns shift.
    for (stream, channel) in channels.iter_mut().enumerate() {
        for &tone in &data {
            let bin = tone.rem_euclid(256) as usize;
            channel[bin] = channel[bin].mul(ComplexSample::rotation(
                -std::f32::consts::TAU * tone as f32 * (8 * stream) as f32 / 256.,
            ));
        }
        delay_fit(channel, &data, guard, allocation)?;
        for tone in allocation.active() {
            let bin = tone.rem_euclid(256) as usize;
            channel[bin] = channel[bin].mul(ComplexSample::rotation(
                std::f32::consts::TAU * tone as f32 * (8 * stream) as f32 / 256.,
            ));
        }
    }
    Some(channels)
}

#[cfg(test)]
fn observe_field(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &super::he::SuSignal,
    cp: usize,
) -> Option<([ComplexSample; 256], Vec<i32>, usize)> {
    observe_for_format(samples, a, fields, cp, false)
}

fn observe_for_format(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &super::he::SuSignal,
    cp: usize,
    er: bool,
) -> Option<([ComplexSample; 256], Vec<i32>, usize)> {
    let allocation = Tones::new(er, fields.bandwidth)?;
    observe_ru(samples, a, allocation, fields.ltf_size, fields.guard_ns, cp)
}

/// Isolated one-stream RU LTF, with spatial admission and symbol position
/// established by the caller. No STBC/MU-MIMO separation or DATA admission.
/// Expects the common LTF sequence polarity; any orthogonal training-matrix
/// coefficient must be accounted for by the caller.
pub(super) fn train_ru_field(
    samples: &[ComplexSample],
    a: &Acquisition,
    allocation: Tones,
    ltf_size: u8,
    guard_ns: u16,
    cp: usize,
) -> Option<[ComplexSample; 256]> {
    if !matches!((ltf_size, guard_ns), (2, 800 | 1600) | (4, 800 | 3200)) {
        return None;
    }
    let (mut channel, tones, guard) = observe_ru(samples, a, allocation, ltf_size, guard_ns, cp)?;
    let energy: f32 = channel.iter().map(|v| v.power()).sum();
    if !energy.is_finite() || energy < 1e-9 {
        return None;
    }
    delay_fit(&mut channel, &tones, guard, allocation)?;
    Some(channel)
}

/// Separate the two STBC channels of one MU RU using all signaled LTFs.
/// The caller establishes STBC/STS admission and the RU's LTF position.
/// DATA uses P, pilots use R (27-55..57); P6 is complex, not P4 repeated.
pub(super) fn train_stbc_ru_field(
    samples: &[ComplexSample],
    a: &Acquisition,
    allocation: Tones,
    fields: &super::he_mu::MuSignal,
    cp: usize,
) -> Option<[[ComplexSample; 256]; 2]> {
    let count = usize::from(fields.ltf_symbols);
    if !fields.stbc
        || !matches!(count, 2 | 4 | 6 | 8)
        || !matches!(
            (fields.ltf_size, fields.guard_ns),
            (2, 800 | 1600) | (4, 800 | 3200)
        )
    {
        return None;
    }
    let (first, tones, guard) =
        observe_ru(samples, a, allocation, fields.ltf_size, fields.guard_ns, cp)?;
    let pilots = allocation.pilots();
    let data: Vec<_> = tones
        .iter()
        .copied()
        .filter(|k| !pilots.contains(k))
        .collect();
    let stride = guard + 64 * usize::from(fields.ltf_size);
    let mut channels = [[ComplexSample::ZERO; 256]; 2];
    for j in 0..count {
        let observed = if j == 0 {
            first
        } else {
            observe_ru(
                samples,
                a,
                allocation,
                fields.ltf_size,
                fields.guard_ns,
                cp.checked_add(j.checked_mul(stride)?)?,
            )?
            .0
        };
        let p = mu_stbc_training_column(count, j)?;
        let mut phase = ComplexSample::ZERO;
        for &tone in tones.iter().filter(|k| pilots.contains(k)) {
            let bin = tone.rem_euclid(256) as usize;
            phase = phase.add(observed[bin].mul(first[bin].conj()).mul(p[0].conj()));
        }
        if !phase.power().is_finite() {
            return None;
        }
        // A summed-channel pilot null cannot measure residual phase.
        let correction = ComplexSample::rotation(if phase.power() > 1e-18 {
            -phase.phase()
        } else {
            0.
        });
        for (stream, channel) in channels.iter_mut().enumerate() {
            let coefficient = correction.mul(p[stream].conj()).scale(1. / count as f32);
            for &tone in &data {
                let bin = tone.rem_euclid(256) as usize;
                channel[bin] = channel[bin].add(observed[bin].mul(coefficient));
            }
        }
    }
    let energy: f32 = channels.iter().flatten().map(|v| v.power()).sum();
    if !energy.is_finite() || energy < 1e-9 {
        return None;
    }
    for (stream, channel) in channels.iter_mut().enumerate() {
        for &tone in &data {
            let bin = tone.rem_euclid(256) as usize;
            channel[bin] = channel[bin].mul(ComplexSample::rotation(
                -std::f32::consts::TAU * tone as f32 * (8 * stream) as f32 / 256.,
            ));
        }
        delay_fit(channel, &data, guard, allocation)?;
        for tone in allocation.active() {
            let bin = tone.rem_euclid(256) as usize;
            channel[bin] = channel[bin].mul(ComplexSample::rotation(
                std::f32::consts::TAU * tone as f32 * (8 * stream) as f32 / 256.,
            ));
        }
    }
    Some(channels)
}

fn mu_stbc_training_column(count: usize, j: usize) -> Option<[ComplexSample; 2]> {
    if j >= count || !matches!(count, 2 | 4 | 6 | 8) {
        return None;
    }
    if count == 6 {
        let sign = [1., -1., 1., 1., 1., -1.][j];
        Some([
            ComplexSample { i: sign, q: 0. },
            ComplexSample::rotation(-std::f32::consts::TAU * j as f32 / 6.).scale(sign),
        ])
    } else {
        Some([
            ComplexSample {
                i: [1., -1., 1., 1.][j % 4],
                q: 0.,
            },
            ComplexSample {
                i: [1., 1., -1., 1.][j % 4],
                q: 0.,
            },
        ])
    }
}

fn observe_ru(
    samples: &[ComplexSample],
    a: &Acquisition,
    allocation: Tones,
    ltf_size: u8,
    guard_ns: u16,
    cp: usize,
) -> Option<([ComplexSample; 256], Vec<i32>, usize)> {
    let (sequence, nfft, guard) = match (ltf_size, guard_ns) {
        (1, 800) => (LTF1, 64, 16),
        (2, 800) => (LTF2, 128, 16),
        (2, 1600) => (LTF2, 128, 32),
        (4, 800) => (LTF4, 256, 16),
        (4, 3200) => (LTF4, 256, 64),
        _ => return None,
    };
    let useful = cp.checked_add(guard)?;
    let wave = samples.get(useful..useful.checked_add(nfft)?)?;
    let start = a.signal_start.checked_add(useful as u64)?;
    let mut time = [ComplexSample::ZERO; 256];
    for (n, value) in time.iter_mut().take(nfft).enumerate() {
        let elapsed = start.checked_add(n as u64)?.checked_sub(a.phase_origin)?;
        *value = wave[n].mul(ComplexSample::rotation(-a.frequency_rad * elapsed as f32));
    }
    let mut bins = [ComplexSample::ZERO; 256];
    match nfft {
        64 => bins[..64].copy_from_slice(&super::sync::fft64(time[..64].try_into().ok()?)),
        128 => bins[..128].copy_from_slice(&super::he_fft::fft128(time[..128].try_into().ok()?)),
        _ => bins = super::he_fft::fft256(time),
    }
    // Equations27-5/58 define K_HE-LTF = K_RU * nfft/256, without rounding.
    // This differs from counting populated tones (60.5/121 versus60/122).
    // Compensate both that normalization and the shorter FFT's gain.
    let scale = (256. / nfft as f32).sqrt();
    let mut channel = [ComplexSample::ZERO; 256];
    for (i, sign) in sequence.iter().enumerate() {
        if !allocation.contains(i as i32 - 122) {
            continue;
        }
        let k = (i as i32 - 122).rem_euclid(256) as usize;
        let multiplier = match sign {
            b'+' => 1.,
            b'-' => -1.,
            _ => continue,
        };
        let short_bin = ((i as i32 - 122) / (256 / nfft) as i32).rem_euclid(nfft as i32) as usize;
        channel[k] = bins[short_bin].scale(multiplier * scale);
    }
    let trained: Vec<i32> = sequence
        .iter()
        .enumerate()
        .filter(|(_, s)| **s != b'0')
        .map(|(i, _)| i as i32 - 122)
        .filter(|tone| allocation.contains(*tone))
        .collect();
    Some((channel, trained, guard))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn radio_he_mu_stbc_ru_training_channels() {
        let (_, mut a) = fixture("he-training4-gi800-flat-gain160");
        a.signal_start = 0;
        a.phase_origin = 0;
        a.frequency_rad = 0.018;
        let bits: Vec<_> = include_str!("../../tests/fixtures/iq/he-mu-signal-a-index.tsv")
            .lines()
            .nth(1)
            .unwrap()
            .split('\t')
            .next()
            .unwrap()
            .bytes()
            .map(|b| b - b'0')
            .collect();
        let mut fields = super::super::he_mu::MuSignal::decode(&bits).unwrap();
        fields.stbc = true;
        let rows = include_str!("../../tests/fixtures/iq/he-mu-stbc-training-index.tsv");
        assert_eq!(rows.lines().skip(1).count(), 768);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let ru: u16 = c[1].parse().unwrap();
            let allocation = Tones::ru(ru, c[2].parse().unwrap()).unwrap();
            fields.ltf_size = c[3].parse().unwrap();
            fields.guard_ns = c[4].parse::<u16>().unwrap() * 50;
            fields.ltf_symbols = c[5].parse().unwrap();
            let branch: usize = c[6].parse().unwrap();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let wave: Vec<_> = bytes
                .chunks_exact(2)
                .map(|b| ComplexSample {
                    i: b[0] as i8 as f32 / 128.,
                    q: b[1] as i8 as f32 / 128.,
                })
                .collect();
            let channels = train_stbc_ru_field(&wave, &a, allocation, &fields, 0)
                .unwrap_or_else(|| panic!("{}", c[0]));
            let gain = c[7].parse::<f32>().unwrap() / 128.
                * 4.
                * (52. / f32::from(ru)).sqrt()
                * std::f32::consts::FRAC_1_SQRT_2;
            let mut error = 0.;
            let mut energy = 0.;
            for k in allocation.active() {
                let angle = std::f32::consts::TAU * k as f32 / 256.;
                let expected = [
                    if branch == 1 {
                        ComplexSample::ZERO
                    } else {
                        ComplexSample { i: 1., q: 0.25 }.mul(ComplexSample::rotation(-3. * angle))
                    },
                    if branch == 2 {
                        ComplexSample::ZERO
                    } else {
                        ComplexSample { i: 0.6, q: -0.3 }
                            .add(
                                ComplexSample { i: 0., q: 0.2 }
                                    .mul(ComplexSample::rotation(-5. * angle)),
                            )
                            .mul(ComplexSample::rotation(8. * angle))
                    },
                ];
                for stream in 0..2 {
                    let h = expected[stream]
                        .mul(ComplexSample::rotation(0.7))
                        .scale(gain);
                    error += channels[stream][k.rem_euclid(256) as usize].sub(h).power();
                    energy += h.power();
                }
            }
            assert!(
                (error / energy).sqrt() < 0.06,
                "{}: {}",
                c[0],
                (error / energy).sqrt()
            );
            for k in -128i32..128 {
                if !allocation.contains(k) {
                    assert!(channels
                        .iter()
                        .all(|h| h[k.rem_euclid(256) as usize].power() == 0.));
                }
            }
            assert!(
                train_stbc_ru_field(&wave[..wave.len() - 1], &a, allocation, &fields, 0).is_none()
            );
            assert!(train_stbc_ru_field(&wave, &a, allocation, &fields, usize::MAX).is_none());
            assert!(train_stbc_ru_field(
                &vec![ComplexSample::ZERO; wave.len()],
                &a,
                allocation,
                &fields,
                0
            )
            .is_none());
            let mut bad = wave.clone();
            bad[wave.len() - 1].i = f32::NAN;
            assert!(train_stbc_ru_field(&bad, &a, allocation, &fields, 0).is_none());
        }
        for count in [0, 1, 3, 5, 7, 9, 255] {
            fields.ltf_symbols = count;
            assert!(train_stbc_ru_field(&[], &a, Tones::ru(26, 1).unwrap(), &fields, 0).is_none());
        }
    }

    #[test]
    fn radio_he_mu_ru_training_channels() {
        let (_, mut a) = fixture("he-training4-gi800-flat-gain160");
        a.signal_start = 0;
        a.phase_origin = 0;
        a.frequency_rad = 0.;
        let rows = include_str!("../../tests/fixtures/iq/he-mu-training-index.tsv");
        assert_eq!(rows.lines().skip(1).count(), 384);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let ru: u16 = c[1].parse().unwrap();
            let allocation = Tones::ru(ru, c[2].parse().unwrap()).unwrap();
            let size = c[3].parse().unwrap();
            let guard = c[4].parse::<u16>().unwrap() * 50;
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let wave: Vec<_> = bytes
                .chunks_exact(2)
                .map(|b| ComplexSample {
                    i: b[0] as i8 as f32 / 128.,
                    q: b[1] as i8 as f32 / 128.,
                })
                .collect();
            let channel = train_ru_field(&wave, &a, allocation, size, guard, 0)
                .unwrap_or_else(|| panic!("{}", c[0]));
            let gain = c[5].parse::<f32>().unwrap() / 128. * 4. * (52. / f32::from(ru)).sqrt();
            let mut error = 0.;
            let mut energy = 0.;
            for k in allocation.active() {
                let h = ComplexSample { i: 1., q: 0. }
                    .add(if c[6] == "1" {
                        ComplexSample { i: 0., q: 0.25 }.mul(ComplexSample::rotation(
                            -std::f32::consts::TAU * k as f32 * 3. / 256.,
                        ))
                    } else {
                        ComplexSample::ZERO
                    })
                    .scale(gain);
                error += channel[k.rem_euclid(256) as usize].sub(h).power();
                energy += h.power();
            }
            assert!(
                (error / energy).sqrt() < 0.06,
                "{}: {}",
                c[0],
                (error / energy).sqrt()
            );
            for k in -128i32..128 {
                if !allocation.contains(k) {
                    assert_eq!(channel[k.rem_euclid(256) as usize].power(), 0.);
                }
            }
            assert!(
                train_ru_field(&wave[..wave.len() - 1], &a, allocation, size, guard, 0).is_none()
            );
            assert!(train_ru_field(&wave, &a, allocation, size, guard, usize::MAX).is_none());
            assert!(train_ru_field(
                &vec![ComplexSample::ZERO; wave.len()],
                &a,
                allocation,
                size,
                guard,
                0
            )
            .is_none());
            let mut bad = wave.clone();
            bad[usize::from(guard) / 50].i = f32::NAN;
            assert!(train_ru_field(&bad, &a, allocation, size, guard, 0).is_none());
        }
        for (size, guard) in [(1, 800), (2, 3200), (4, 1600), (0, 0), (255, u16::MAX)] {
            assert!(train_ru_field(&[], &a, Tones::ru(26, 1).unwrap(), size, guard, 0).is_none());
        }
    }
    #[test]
    fn radio_he_er106_training_channels() {
        let (samples, mut a) = fixture("he-training4-gi800-flat-gain160");
        let mut fields = decode_prefix(&samples[a.signal_start as usize..], &a)
            .unwrap()
            .signal;
        a.signal_start = 0;
        a.phase_origin = 0;
        a.frequency_rad = 0.;
        let rows = include_str!("../../tests/fixtures/iq/he-er106-training-index.tsv");
        assert_eq!(rows.lines().skip(1).count(), 54);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            fields.bandwidth = 1;
            fields.ltf_size = c[1].parse().unwrap();
            fields.guard_ns = c[2].parse::<u16>().unwrap() * 50;
            fields.stbc = c[3] == "1";
            fields.space_time_streams = if fields.stbc { 2 } else { 1 };
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let wave: Vec<_> = bytes
                .chunks_exact(2)
                .map(|b| ComplexSample {
                    i: b[0] as i8 as f32 / 128.,
                    q: b[1] as i8 as f32 / 128.,
                })
                .collect();
            assert_eq!(wave.len(), c[6].parse::<usize>().unwrap());
            let recover = |input: &[ComplexSample], er| {
                if fields.stbc {
                    train_stbc_for_format(input, &a, &fields, 0, er).map(|v| v.to_vec())
                } else {
                    train_for_format(input, &a, &fields, 0, er).map(|v| vec![v])
                }
            };
            assert!(recover(&wave, false).is_none());
            assert!(recover(&wave[..wave.len() - 1], true).is_none());
            assert!(recover(&vec![ComplexSample::ZERO; wave.len()], true).is_none());
            let mut bad = wave.clone();
            bad[usize::from(fields.guard_ns) / 50].i = f32::NAN;
            assert!(recover(&bad, true).is_none());
            let channels = recover(&wave, true).unwrap_or_else(|| panic!("{}", c[0]));
            let gain = c[4].parse::<f32>().unwrap() / 128.
                * 4.
                * (52f32 / 106.).sqrt()
                * (2. / f32::from(fields.space_time_streams)).sqrt();
            for (stream, channel) in channels.iter().enumerate() {
                let mut error = 0.;
                let mut energy = 0.;
                for (k, value) in channel.iter().enumerate().take(123).skip(17) {
                    let expected = if stream == 0 {
                        ComplexSample { i: 1., q: 0. }.add(if c[5] == "1" {
                            ComplexSample { i: 0., q: 0.25 }.mul(ComplexSample::rotation(
                                -std::f32::consts::TAU * k as f32 * 3. / 256.,
                            ))
                        } else {
                            ComplexSample::ZERO
                        })
                    } else {
                        ComplexSample { i: 0.55, q: 0.35 }.mul(ComplexSample::rotation(
                            std::f32::consts::TAU * k as f32 * 8. / 256.,
                        ))
                    }
                    .scale(gain);
                    error += value.sub(expected).power();
                    energy += expected.power();
                }
                assert!(
                    (error / energy).sqrt() < 0.06,
                    "{} stream{stream}: {}",
                    c[0],
                    (error / energy).sqrt()
                );
                assert!(channel[..17]
                    .iter()
                    .chain(&channel[123..])
                    .all(|v| v.power() == 0.));
            }
        }
    }
    #[test]
    fn radio_he_ltf_fractional_normalization() {
        let (samples, mut a) = fixture("he-training4-gi800-flat-gain160");
        let mut fields = decode_prefix(&samples[a.signal_start as usize..], &a)
            .unwrap()
            .signal;
        a.frequency_rad = 0.;
        for (size, guard_ns, norm, sequence) in [
            (1, 800, 60.5f64, LTF1),
            (2, 800, 121., LTF2),
            (2, 1600, 121., LTF2),
            (4, 800, 242., LTF4),
            (4, 3200, 242., LTF4),
        ] {
            fields.ltf_size = size;
            fields.guard_ns = guard_ns;
            let guard = usize::from(guard_ns) / 50;
            let nfft = 64 * usize::from(size);
            // One known modulated tone, evaluated directly from Eq27-58 in
            // double precision. Absolute gain detects the populated-count bug
            // independently of equalization, quantization and channel fitting.
            let tone = 28usize;
            let sign = match sequence[tone + 122] {
                b'+' => 1.,
                b'-' => -1.,
                _ => panic!("unmodulated"),
            };
            let mut wave = vec![ComplexSample::ZERO; guard + nfft];
            for n in 0..nfft {
                let phase = std::f64::consts::TAU * tone as f64 * n as f64 / 256.;
                let amplitude = sign / (256. * norm.sqrt());
                wave[guard + n] = ComplexSample {
                    i: (amplitude * phase.cos()) as f32,
                    q: (amplitude * phase.sin()) as f32,
                };
            }
            let (channel, _, _) = observe_field(&wave, &a, &fields, 0).unwrap();
            assert!(
                (channel[tone].i - 1. / 242f32.sqrt()).abs() < 1e-6,
                "ltf{size}: {:?}",
                channel[tone]
            );
            assert!(channel[tone].q.abs() < 1e-6);
        }
    }
    #[test]
    fn radio_he_stbc_training_bounds() {
        for row in include_str!("../../tests/fixtures/iq/he-stbc-iq-index.tsv")
            .lines()
            .skip(1)
            .filter(|r| r.starts_with("he-stbc-iq-mcs0-bcc-") && r.contains("-pad1-flat\t"))
        {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let input = &samples[a.signal_start as usize..];
            let trained = train_su(input, &a).expect(c[0]);
            let fields = trained.prefix.signal;
            let end = (trained.data_start - a.signal_start) as usize;
            assert!(trained.second.is_some());
            assert!(train_stbc_field(&input[..end], &a, &fields, 400).is_some());
            assert!(train_stbc_field(&input[..end - 1], &a, &fields, 400).is_none());
            assert!(train_stbc_field(input, &a, &fields, usize::MAX).is_none());
            let mut bad_a = a.clone();
            bad_a.signal_start = u64::MAX - 40;
            assert!(train_stbc_field(input, &bad_a, &fields, 400).is_none());
            for n in [400 + trained.guard, end - 1] {
                for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
                    let mut bad_input = input.to_vec();
                    bad_input[n].q = bad;
                    assert!(train_stbc_field(&bad_input, &a, &fields, 400).is_none());
                }
            }
            let mut zero = input.to_vec();
            zero[400..end].fill(ComplexSample::ZERO);
            assert!(train_stbc_field(&zero, &a, &fields, 400).is_none());
            let mut bad = fields;
            bad.dcm = true;
            assert!(train_stbc_field(input, &a, &bad, 400).is_none());
            bad = fields;
            bad.space_time_streams = 1;
            assert!(train_stbc_field(input, &a, &bad, 400).is_none());
        }
    }

    fn train_su4(samples: &[ComplexSample], a: &Acquisition) -> Option<Trained> {
        let trained = train_su(samples, a)?;
        (trained.prefix.signal.ltf_size == 4).then_some(trained)
    }
    fn fixture(name: &str) -> (Vec<ComplexSample>, Acquisition) {
        let bytes = std::fs::read(format!(
            "{}/tests/fixtures/iq/{name}.cs8",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let samples: Vec<_> = bytes
            .chunks_exact(2)
            .map(|b| ComplexSample {
                i: b[0] as i8 as f32 / 128.,
                q: b[1] as i8 as f32 / 128.,
            })
            .collect();
        let mut sync = super::super::sync::Synchronizer::default();
        let a = samples
            .iter()
            .enumerate()
            .find_map(|(i, s)| match sync.push(*s, i as u64) {
                Some(super::super::sync::SyncEvent::Acquired(a)) => Some(a),
                _ => None,
            })
            .expect("independent preamble acquisition");
        (samples, a)
    }

    #[test]
    fn radio_he_training4_independent_channels_and_probe() {
        let rows: Vec<_> = include_str!("../../tests/fixtures/iq/he-training4-index.tsv")
            .lines()
            .skip(1)
            .chain(
                include_str!("../../tests/fixtures/iq/he-training-sparse-index.tsv")
                    .lines()
                    .skip(1),
            )
            .collect();
        assert_eq!(rows.len(), 60);
        assert_eq!(LTF4.iter().filter(|b| **b != b'0').count(), 242);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let trained = train_su(&samples[a.signal_start as usize..], &a)
                .unwrap_or_else(|| panic!("{}", c[0]));
            if c.len() == 15 {
                assert_eq!(trained.prefix.signal.ltf_size, c[14].parse::<u8>().unwrap());
            }
            assert_eq!(a.preamble_start, 37);
            assert_eq!(trained.prefix.end_sample, 677);
            assert_eq!(trained.prefix.signal.beam_change, c[2] == "1");
            assert_eq!(trained.guard, c[1].parse::<usize>().unwrap());
            assert_eq!(trained.data_start, c[11].parse::<u64>().unwrap());
            let beam = ComplexSample {
                i: c[7].parse().unwrap(),
                q: c[8].parse().unwrap(),
            };
            let taps: Vec<_> = c[6]
                .split(';')
                .map(|s| {
                    let v: Vec<f32> = s.split(':').map(|n| n.parse().unwrap()).collect();
                    (v[0], ComplexSample { i: v[1], q: v[2] })
                })
                .collect();
            let mut expected = [ComplexSample::ZERO; 256];
            let mut fit = ComplexSample::ZERO;
            let mut denominator = 0.;
            for k in (-122i32..=-2).chain(2..=122) {
                let bin = k.rem_euclid(256) as usize;
                for (delay, h) in &taps {
                    let phase = -std::f32::consts::TAU * k as f32 * delay / 256.;
                    expected[bin] = expected[bin].add(h.mul(ComplexSample::rotation(phase)));
                }
                expected[bin] = expected[bin].mul(beam);
                fit = fit.add(trained.channel[bin].mul(expected[bin].conj()));
                denominator += expected[bin].power();
            }
            let fit = fit.scale(1. / denominator);
            let amplitude = c[5].parse::<f32>().unwrap() / 128. * 4. * (52f32 / 242.).sqrt();
            assert!(
                (fit.power().sqrt() / amplitude - 1.).abs() < 0.04,
                "{} amplitude",
                c[0]
            );
            let mut residual = 0.;
            let mut energy = 0.;
            for k in 0..256 {
                residual += trained.channel[k].sub(expected[k].mul(fit)).power();
                energy += trained.channel[k].power();
            }
            assert!((residual / energy).sqrt() < 0.08, "{} channel shape", c[0]);

            // Known uncoded probe tests the trained channel, not MAC decoding.
            let start = trained.data_start as usize + trained.guard;
            let time = std::array::from_fn(|n| {
                let elapsed = start as u64 + n as u64 - a.phase_origin;
                samples[start + n].mul(ComplexSample::rotation(-a.frequency_rad * elapsed as f32))
            });
            let observed = super::super::he_fft::fft256(time);
            let mut corrected = Vec::new();
            let mut common = ComplexSample::ZERO;
            for (tone, bit) in (-122i32..=-2).chain(2..=122).zip(c[9].bytes()) {
                let bin = tone.rem_euclid(256) as usize;
                let sign = if bit == b'1' { 1. } else { -1. };
                let value = observed[bin].mul(trained.channel[bin].conj()).scale(sign);
                common = common.add(value);
                corrected.push(value);
            }
            assert_eq!(corrected.len(), 242);
            let rotation = ComplexSample::rotation(-common.phase());
            assert!(
                corrected.iter().all(|v| v.mul(rotation).i > 0.),
                "{} probe signs",
                c[0]
            );
        }
    }

    #[test]
    fn radio_he_training4_bounds_and_invalid_modes() {
        for row in include_str!("../../tests/fixtures/iq/he-training4-invalid-index.tsv")
            .lines()
            .skip(1)
        {
            let name = row.split('\t').next().unwrap();
            let (samples, a) = fixture(name);
            if name.ends_with("stbc") {
                // Historical unsupported-mode fixture: it has a STBC header
                // but only one LTF followed by an uncoded probe. Training
                // estimates alone cannot qualify that probe as valid DATA.
                assert!(
                    super::super::he_iq::decode_su_prefix(&samples[a.signal_start as usize..], &a)
                        .unwrap()
                        .signal
                        .stbc
                );
                continue;
            }
            assert!(
                train_su4(&samples[a.signal_start as usize..], &a).is_none(),
                "{name}"
            );
        }
        let (samples, a) = fixture("he-training4-gi800-flat-gain160");
        let input = &samples[a.signal_start as usize..];
        for end in [0, 79, 319, 399, 400, 415, 671] {
            assert!(train_su4(&input[..end], &a).is_none());
        }
        let mut overflow = a.clone();
        overflow.signal_start = u64::MAX - 40;
        assert!(train_su4(input, &overflow).is_none());
    }

    #[test]
    fn radio_he_training_sparse_bounds_and_nonfinite() {
        for row in include_str!("../../tests/fixtures/iq/he-training-sparse-index.tsv")
            .lines()
            .skip(1)
        {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let end = c[11].parse::<usize>().unwrap() - a.signal_start as usize;
            let input = &samples[a.signal_start as usize..];
            assert!(train_su(&input[..end - 1], &a).is_none());
            assert!(train_su(&input[..end], &a).is_some());
            for invalid in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
                let mut bad = input.to_vec();
                bad[end - 1].i = invalid;
                assert!(train_su(&bad, &a).is_none(), "{} {invalid}", c[0]);
            }
        }
    }
}
