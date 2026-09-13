//! HE20 SU / ER242 one DATA stream, including STBC; IEEE802.11ax-2021 27.3.11.10.
use super::{
    he_iq::{decode_prefix, Prefix},
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
fn delay_fit(channel: &mut [ComplexSample; 256], tones: &[i32], guard: usize) -> Option<()> {
    let count = guard.checked_add(4)?;
    if count > 68 || tones.len() < count {
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
    for tone in (-122i32..=-2).chain(2..=122) {
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
        let [first, second] = train_stbc_field(samples, a, &fields, cp)?;
        (first, Some(second))
    } else {
        (train_field(samples, a, &fields, cp)?, None)
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
    if fields.space_time_streams != 1 || fields.stbc {
        return None;
    }
    let (mut channel, trained, guard) = observe_field(samples, a, fields, cp)?;
    let energy: f32 = channel.iter().map(|v| v.power()).sum();
    if !energy.is_finite() || energy < 1e-9 {
        return None;
    }
    delay_fit(&mut channel, &trained, guard)?;
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
    if !fields.stbc || fields.dcm || fields.space_time_streams != 2 {
        return None;
    }
    let (first, tones, guard) = observe_field(samples, a, fields, cp)?;
    let next = cp.checked_add(guard + 64 * usize::from(fields.ltf_size))?;
    let (second, _, _) = observe_field(samples, a, fields, next)?;
    const PILOTS: [i32; 8] = [-116, -90, -48, -22, 22, 48, 90, 116];
    let mut phase = ComplexSample::ZERO;
    for &tone in tones.iter().filter(|k| PILOTS.contains(k)) {
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
    let data: Vec<_> = tones.into_iter().filter(|k| !PILOTS.contains(k)).collect();
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
        delay_fit(channel, &data, guard)?;
        for tone in (-122i32..=-2).chain(2..=122) {
            let bin = tone.rem_euclid(256) as usize;
            channel[bin] = channel[bin].mul(ComplexSample::rotation(
                std::f32::consts::TAU * tone as f32 * (8 * stream) as f32 / 256.,
            ));
        }
    }
    Some(channels)
}

fn observe_field(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &super::he::SuSignal,
    cp: usize,
) -> Option<([ComplexSample; 256], Vec<i32>, usize)> {
    let (sequence, nfft, guard, active) = match (fields.ltf_size, fields.guard_ns) {
        (1, 800) => (LTF1, 64, 16, 60),
        (2, 800) => (LTF2, 128, 16, 122),
        (2, 1600) => (LTF2, 128, 32, 122),
        (4, 800) => (LTF4, 256, 16, 242),
        (4, 3200) => (LTF4, 256, 64, 242),
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
    // Convert the short-LTF FFT gain to the 256-point DATA gain. Equation27-58
    // normalizes by sqrt(active training tones), DATA uses sqrt(242).
    let scale = 256. / nfft as f32 * (active as f32 / 242.).sqrt();
    let mut channel = [ComplexSample::ZERO; 256];
    for (i, sign) in sequence.iter().enumerate() {
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
        .collect();
    Some((channel, trained, guard))
}

#[cfg(test)]
mod tests {
    use super::*;
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
