//! HE20 SU BCC IQ, IEEE802.11ax-2021 27.3.12.8/9/13/14.
use super::{
    he_capacity::Capacity, he_timing::Timing, he_training::train_su, sync::Acquisition,
    ComplexSample,
};

const PILOTS: [i32; 8] = [-116, -90, -48, -22, 22, 48, 90, 116];
const SIGNS: [f32; 8] = [1., 1., 1., -1., -1., 1., 1., 1.];

/// Input starts at L-SIG. Bytes are not yet MAC/FCS qualified.
pub(super) fn recover(
    samples: &[ComplexSample],
    a: &Acquisition,
    max_psdu: usize,
) -> Option<Vec<u8>> {
    let trained = train_su(samples, a)?;
    let h = trained.prefix.signal;
    if h.ldpc || h.dcm || h.stbc || h.midamble_period.is_some() {
        return None;
    }
    let timing = Timing::new(6_000_000, trained.prefix.legacy_length.into(), &h).ok()?;
    let c = Capacity::new(&h, timing.data_symbols).ok()?;
    if c.psdu_bytes > max_psdu || c.spatial_streams != 1 {
        return None;
    }
    let offset = a.signal_start.checked_sub(a.preamble_start)?;
    let required = timing.data_end.checked_sub(usize::try_from(offset).ok()?)?;
    if samples.len() < required {
        return None;
    }
    let mut coded = Vec::new();
    coded
        .try_reserve_exact(timing.data_symbols.checked_mul(c.coded_per_symbol)?)
        .ok()?;
    let energy: f32 = match c.bits_per_tone {
        1 => 1.,
        2 => 2.,
        4 => 10.,
        6 => 42.,
        8 => 170.,
        _ => return None,
    };
    let mut pilot_state = 127u8;
    for _ in 0..4 {
        super::data::feedback(&mut pilot_state);
    }
    let mut slope = 0.;
    for symbol in 0..timing.data_symbols {
        let absolute = a
            .preamble_start
            .checked_add(timing.symbol_start(symbol)? as u64)?
            .checked_add(trained.guard as u64)?;
        let start = usize::try_from(absolute.checked_sub(a.signal_start)?).ok()?;
        let wave = samples.get(start..start.checked_add(256)?)?;
        let mut time = [ComplexSample::ZERO; 256];
        for (n, v) in time.iter_mut().enumerate() {
            let elapsed = absolute
                .checked_add(n as u64)?
                .checked_sub(a.phase_origin)?;
            *v = wave[n].mul(ComplexSample::rotation(-a.frequency_rad * elapsed as f32));
        }
        let bins = super::he_fft::fft256(time);
        let polarity = 1. - 2. * super::data::feedback(&mut pilot_state) as f32;
        let pilots: [(f32, ComplexSample); 8] = std::array::from_fn(|j| {
            let k = PILOTS[j];
            let bin = k.rem_euclid(256) as usize;
            (
                k as f32,
                bins[bin]
                    .mul(trained.channel[bin].conj())
                    .scale(SIGNS[(symbol + j) % 8] * polarity)
                    .mul(ComplexSample::rotation(-slope * k as f32)),
            )
        });
        let common = pilots
            .iter()
            .fold(ComplexSample::ZERO, |sum, (_, v)| sum.add(*v));
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
        slope += delta;
        let mut interleaved = Vec::with_capacity(c.coded_per_symbol);
        for tone in (-122i32..=-2)
            .chain(2..=122)
            .filter(|k| !PILOTS.contains(k))
        {
            let bin = tone.rem_euclid(256) as usize;
            let channel = trained.channel[bin];
            let power = channel.power();
            if !power.is_finite() {
                return None;
            }
            if power < 1e-12 {
                interleaved.extend(std::iter::repeat(0.).take(c.bits_per_tone));
                continue;
            }
            let v = bins[bin]
                .mul(channel.conj())
                .scale(1. / power)
                .mul(ComplexSample::rotation(-intercept - slope * tone as f32));
            if !v.power().is_finite() {
                return None;
            }
            super::data::demap(
                v.i,
                if c.bits_per_tone == 1 {
                    1
                } else {
                    c.bits_per_tone / 2
                },
                energy.sqrt(),
                power,
                &mut interleaved,
            );
            if c.bits_per_tone > 1 {
                super::data::demap(
                    v.q,
                    c.bits_per_tone / 2,
                    energy.sqrt(),
                    power,
                    &mut interleaved,
                );
            }
        }
        let n = c.coded_per_symbol;
        let s = (c.bits_per_tone / 2).max(1);
        for k in 0..n {
            let i = 9 * c.bits_per_tone * (k % 26) + k / 26;
            let j = s * (i / s) + (i + n - 26 * i / n) % s;
            coded.push(*interleaved.get(j)?);
        }
    }
    super::he_bcc::recover(&h, timing.data_symbols, &coded, max_psdu).ok()
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
            .map(|v| ComplexSample {
                i: v[0] as i8 as f32 / 128.,
                q: v[1] as i8 as f32 / 128.,
            })
            .collect();
        let mut sync = super::super::sync::Synchronizer::default();
        let acquired = samples
            .iter()
            .enumerate()
            .find_map(|(i, v)| match sync.push(*v, i as u64) {
                Some(super::super::sync::SyncEvent::Acquired(a)) => Some(a),
                _ => None,
            })
            .expect("independent preamble acquisition");
        (samples, acquired)
    }

    #[test]
    fn radio_he_bcc_iq_independent_complete_waveforms() {
        let mut count = 0;
        for row in include_str!("../../tests/fixtures/iq/he-bcc-iq-index.tsv")
            .lines()
            .skip(1)
        {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let expected: Vec<_> = (0..c[6].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&c[6][i..i + 2], 16).unwrap())
                .collect();
            let input = &samples[a.signal_start as usize..];
            let decoded = recover(input, &a, 65535).unwrap_or_else(|| panic!("{}", c[0]));
            assert_eq!(decoded, expected, "{}", c[0]);
            let end = c[11].parse::<usize>().unwrap() - a.signal_start as usize;
            assert_eq!(
                recover(&input[..end], &a, expected.len()),
                Some(expected.clone()),
                "{} exactend",
                c[0]
            );
            assert!(
                recover(&input[..end - 1], &a, 65535).is_none(),
                "{} truncated",
                c[0]
            );
            assert!(recover(input, &a, expected.len() - 1).is_none());
            count += 1;
        }
        assert_eq!(count, 151);
    }

    #[test]
    fn radio_he_bcc_iq_invalid_layouts_and_bounds() {
        for row in include_str!("../../tests/fixtures/iq/he-bcc-iq-invalid-index.tsv")
            .lines()
            .skip(1)
        {
            let name = row.split('\t').next().unwrap();
            let (samples, a) = fixture(name);
            assert!(
                recover(&samples[a.signal_start as usize..], &a, 65535).is_none(),
                "{name}"
            );
        }
        let (samples, a) = fixture("he-bcc-iq-mcs0-ltf4-gi3200-flat");
        let input = &samples[a.signal_start as usize..];
        for end in [0, 79, 319, 400, 719] {
            assert!(recover(&input[..end], &a, 65535).is_none());
        }
        let mut bad = a.clone();
        bad.preamble_start = u64::MAX;
        assert!(recover(input, &bad, 65535).is_none());
        let mut nonfinite = input.to_vec();
        nonfinite[1000].i = f32::NAN;
        assert!(recover(&nonfinite, &a, 65535).is_none());
    }
}
