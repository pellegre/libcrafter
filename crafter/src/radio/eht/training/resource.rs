use crate::radio::{eht::EhtResourceUnit, resource_unit::Tones, sync::Acquisition, ComplexSample};

pub(super) fn train(
    samples: &[ComplexSample],
    acquisition: &Acquisition,
    resource: EhtResourceUnit,
    ltf_size: u8,
    guard: usize,
    ltf_start: usize,
) -> Option<[ComplexSample; 256]> {
    let mut channel = [ComplexSample::ZERO; 256];
    for component in resource.components() {
        let tones = Tones::ru(component.tone_count(), usize::from(component.index()))?;
        let estimate = crate::radio::he::training::train_ru_field(
            samples,
            acquisition,
            tones,
            ltf_size,
            (guard * 50) as u16,
            ltf_start,
        )?;
        for tone in tones.active() {
            let bin = tone.rem_euclid(256) as usize;
            channel[bin] = estimate[bin];
        }
    }
    let energy: f32 = channel.iter().map(|value| value.power()).sum();
    (energy.is_finite() && energy > 1e-9).then_some(channel)
}
