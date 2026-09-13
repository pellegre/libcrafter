//! HE20 SU one-stream 4x training; IEEE802.11ax-2021 27.3.11.10.
use super::{
    he_iq::{decode_su_prefix, Prefix},
    sync::Acquisition,
    ComplexSample,
};

// Equation27-43, exactly245 signed tones in ascending order -122..122.
const LTF4: &[u8;245] = b"--+-+-+++-+++--+-----++----++-+-++++-+--++-++++--+---++++-++----+--++-+----+-+------++-----+--+++-+++-+-+-----+++---+-+++000-+-+-++-+++--+--+-+-+++-+++--+-----++------+-+----+-++--+----++-+++++++-++----+--++-+----+-+--++++--+++++-++---+---+-+-++";

pub(super) struct Trained {
    pub prefix: Prefix,
    pub channel: [ComplexSample; 256],
    pub data_start: u64,
    pub guard: usize,
}

/// Input begins at L-SIG. Reject unsupported training layouts explicitly.
pub(super) fn train_su4(samples: &[ComplexSample], a: &Acquisition) -> Option<Trained> {
    let prefix = decode_su_prefix(samples, a)?;
    let fields = prefix.signal;
    if fields.ltf_size != 4 || fields.space_time_streams != 1 || fields.stbc {
        return None;
    }
    let guard = match fields.guard_ns {
        800 => 16,
        3200 => 64,
        _ => return None,
    };
    // L-SIG/RL-SIG/SIG-A total320 samples, then80 samples of HE-STF.
    let useful = 400 + guard;
    let wave = samples.get(useful..useful + 256)?;
    let start = a.signal_start.checked_add(useful as u64)?;
    let mut time = [ComplexSample::ZERO; 256];
    for (n, value) in time.iter_mut().enumerate() {
        let elapsed = start.checked_add(n as u64)?.checked_sub(a.phase_origin)?;
        *value = wave[n].mul(ComplexSample::rotation(-a.frequency_rad * elapsed as f32));
    }
    let bins = super::he_fft::fft256(time);
    let mut channel = [ComplexSample::ZERO; 256];
    let mut energy = 0.;
    for (i, sign) in LTF4.iter().enumerate() {
        let k = (i as i32 - 122).rem_euclid(256) as usize;
        let multiplier = match sign {
            b'+' => 1.,
            b'-' => -1.,
            _ => continue,
        };
        channel[k] = bins[k].scale(multiplier);
        energy += channel[k].power();
    }
    if !energy.is_finite() || energy < 1e-9 {
        return None;
    }
    Some(Trained {
        prefix,
        channel,
        data_start: start.checked_add(256)?,
        guard,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
            .collect();
        assert_eq!(rows.len(), 24);
        assert_eq!(LTF4.iter().filter(|b| **b != b'0').count(), 242);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let trained = train_su4(&samples[a.signal_start as usize..], &a)
                .unwrap_or_else(|| panic!("{}", c[0]));
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
}
