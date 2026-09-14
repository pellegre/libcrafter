//! HT20 channel training shared by HT and VHT receivers.

use crate::radio::{
    stbc,
    sync::{fft64, Acquisition, LONG},
    ComplexSample,
};

/// One-stream HT20 channel estimate from a complete HT-LTF (including its GI).
/// IEEE 802.11-2020 19.3.9.4.6, Equation 19-23. The phase reference is retained
/// from acquisition so the DATA oscillator correction uses the same origin.
pub(in crate::radio) fn train_single_stream(
    samples: &[ComplexSample],
    start: u64,
    acquisition: &Acquisition,
) -> Option<Acquisition> {
    if samples.len() != 80 || start < acquisition.phase_origin {
        return None;
    }
    let bins = fft64(std::array::from_fn(|n| {
        samples[16 + n].mul(ComplexSample::rotation(
            -acquisition.frequency_rad
                * ((start - acquisition.phase_origin) as f32 + (16 + n) as f32),
        ))
    }));
    let mut trained = acquisition.clone();
    trained.channel = [ComplexSample::ZERO; 64];
    for k in -28i32..=28 {
        if k == 0 {
            continue;
        }
        let sign = match k {
            -28 | -27 => 1.,
            27 | 28 => -1.,
            _ => LONG[(k + 26) as usize] as f32,
        };
        let bin = k.rem_euclid(64) as usize;
        trained.channel[bin] = bins[bin].scale(sign);
        if !trained.channel[bin].power().is_finite() {
            return None;
        }
    }
    Some(trained)
}

/// Separate the first two HT-LTF columns, whose known-tone-removed values
/// observe h1+h2 and -h1+h2 respectively (Equation 19-27). The first estimate
/// may come from either mixed HT-LTF1 or greenfield's repeated HT-LTF1.
pub(in crate::radio) fn train_stbc_second(
    mut first: Acquisition,
    samples: &[ComplexSample],
    start: u64,
) -> Option<(Acquisition, [ComplexSample; 64])> {
    let second = train_single_stream(samples, start, &first)?;
    let mut other = [ComplexSample::ZERO; 64];
    for (k, value) in other.iter_mut().enumerate() {
        let channels = stbc::separate_training([first.channel[k], second.channel[k]]).ok()?;
        first.channel[k] = channels[0];
        *value = channels[1];
    }
    Some((first, other))
}
