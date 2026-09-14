//! Phase-corrected 64-point OFDM signaling symbols.

use crate::radio::{
    sync::{fft64, Acquisition},
    ComplexSample,
};

/// Remove acquisition CFO and pilot phase from one 80-sample signaling symbol.
pub(in crate::radio) fn corrected_bins(
    samples: &[ComplexSample],
    start: u64,
    acquisition: &Acquisition,
    pilot_polarity: f32,
) -> Option<[ComplexSample; 64]> {
    if samples.len() != 80 || !pilot_polarity.is_finite() {
        return None;
    }
    let mut time = [ComplexSample::ZERO; 64];
    for (index, value) in time.iter_mut().enumerate() {
        let elapsed = start
            .checked_add(16 + index as u64)?
            .checked_sub(acquisition.phase_origin)?;
        *value = samples[16 + index].mul(ComplexSample::rotation(
            -acquisition.frequency_rad * elapsed as f32,
        ));
    }
    let bins = fft64(time);
    let mut pilot = ComplexSample::ZERO;
    for (tone, sign) in [(43, 1.), (57, 1.), (7, 1.), (21, -1.)] {
        pilot = pilot.add(
            bins[tone]
                .mul(acquisition.channel[tone].conj())
                .scale(sign * pilot_polarity),
        );
    }
    if !pilot.power().is_finite() || pilot.power() < 1e-12 {
        return None;
    }
    let rotation = ComplexSample::rotation(-pilot.phase());
    let corrected = bins.map(|value| value.mul(rotation));
    corrected
        .iter()
        .all(|value| value.power().is_finite())
        .then_some(corrected)
}
