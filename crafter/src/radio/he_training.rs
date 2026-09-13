//! HE20 SU one-stream training; IEEE802.11ax-2021 27.3.11.10.
use super::{
    he_iq::{decode_su_prefix, Prefix},
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
    pub data_start: u64,
    pub guard: usize,
}

/// Input begins at L-SIG. Reject unsupported training layouts explicitly.
pub(super) fn train_su(samples: &[ComplexSample], a: &Acquisition) -> Option<Trained> {
    let prefix = decode_su_prefix(samples, a)?;
    let fields = prefix.signal;
    if fields.space_time_streams != 1 || fields.stbc {
        return None;
    }
    let (sequence, nfft, guard, active) = match (fields.ltf_size, fields.guard_ns) {
        (1, 800) => (LTF1, 64, 16, 60),
        (2, 800) => (LTF2, 128, 16, 122),
        (2, 1600) => (LTF2, 128, 32, 122),
        (4, 800) => (LTF4, 256, 16, 242),
        (4, 3200) => (LTF4, 256, 64, 242),
        _ => return None,
    };
    // L-SIG/RL-SIG/SIG-A total320 samples, then80 samples of HE-STF.
    let useful = 400 + guard;
    let wave = samples.get(useful..useful + nfft)?;
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
    let mut energy = 0.;
    for (i, sign) in sequence.iter().enumerate() {
        let k = (i as i32 - 122).rem_euclid(256) as usize;
        let multiplier = match sign {
            b'+' => 1.,
            b'-' => -1.,
            _ => continue,
        };
        let short_bin = ((i as i32 - 122) / (256 / nfft) as i32).rem_euclid(nfft as i32) as usize;
        channel[k] = bins[short_bin].scale(multiplier * scale);
        energy += channel[k].power();
    }
    if !energy.is_finite() || energy < 1e-9 {
        return None;
    }
    // Complex linear interpolation is a receiver estimator, not a normative
    // channel model. Keep measured tones untouched; extrapolate at band edges.
    let trained: Vec<i32> = sequence
        .iter()
        .enumerate()
        .filter(|(_, s)| **s != b'0')
        .map(|(i, _)| i as i32 - 122)
        .collect();
    for tone in (-122i32..=-2).chain(2..=122) {
        if sequence[(tone + 122) as usize] != b'0' {
            continue;
        }
        let upper = trained
            .partition_point(|k| *k < tone)
            .clamp(1, trained.len() - 1);
        let lo = trained[upper - 1];
        let hi = trained[upper];
        let left = channel[lo.rem_euclid(256) as usize];
        let right = channel[hi.rem_euclid(256) as usize];
        channel[tone.rem_euclid(256) as usize] =
            left.add(right.sub(left).scale((tone - lo) as f32 / (hi - lo) as f32));
    }
    Some(Trained {
        prefix,
        channel,
        data_start: start.checked_add(nfft as u64)?,
        guard,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
