//! EHT preamble and U-SIG recovery from a legacy-acquired 20 Msps stream.

use super::EhtUsigFields;
use crate::radio::{
    signal,
    sync::{fft64, Acquisition},
    ComplexSample,
};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) struct Prefix {
    pub fields: EhtUsigFields,
    pub legacy_length: usize,
    pub end_sample: u64,
}

struct Receiver<'a> {
    samples: &'a [ComplexSample],
    acquisition: &'a Acquisition,
}

impl<'a> Receiver<'a> {
    fn new(samples: &'a [ComplexSample], acquisition: &'a Acquisition) -> Option<Self> {
        samples.get(..160)?;
        Some(Self {
            samples,
            acquisition,
        })
    }

    fn decode(self) -> Option<Prefix> {
        self.samples.get(..320)?;
        let legacy_length = self.repeated_legacy_length()?;
        let fields = EhtUsigFields::decode_interleaved(&self.usig_metrics()?).ok()?;
        Some(Prefix {
            fields,
            legacy_length,
            end_sample: self.acquisition.signal_start.checked_add(320)?,
        })
    }

    fn repeated_legacy_length(&self) -> Option<usize> {
        let first = signal::decode_signal(&self.samples[..80], self.acquisition, 4095).ok()?;
        if first.rate_bps != 6_000_000 || first.psdu_bytes % 3 != 0 {
            return None;
        }
        let mut repeated = self.acquisition.clone();
        repeated.signal_start = self.acquisition.signal_start.checked_add(80)?;
        let second = signal::decode_signal(&self.samples[80..160], &repeated, 4095).ok()?;
        (second.rate_bps == first.rate_bps && second.psdu_bytes == first.psdu_bytes)
            .then_some(first.psdu_bytes)
    }

    fn corrected_bins(&self, offset: usize) -> Option<[ComplexSample; 64]> {
        let samples = self.samples.get(offset..offset.checked_add(80)?)?;
        let start = self.acquisition.signal_start.checked_add(offset as u64)?;
        let mut time = [ComplexSample::ZERO; 64];
        for (index, value) in time.iter_mut().enumerate() {
            let elapsed = start
                .checked_add(16 + index as u64)?
                .checked_sub(self.acquisition.phase_origin)?;
            *value = samples[16 + index].mul(ComplexSample::rotation(
                -self.acquisition.frequency_rad * elapsed as f32,
            ));
        }
        let bins = fft64(time);
        let mut pilot = ComplexSample::ZERO;
        for (tone, sign) in [(43, 1.), (57, 1.), (7, 1.), (21, -1.)] {
            pilot = pilot.add(
                bins[tone]
                    .mul(self.acquisition.channel[tone].conj())
                    .scale(sign),
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

    fn usig_metrics(&self) -> Option<[f32; 104]> {
        let lsig = self.corrected_bins(0)?;
        let repeated = self.corrected_bins(80)?;
        let mut channel = self.acquisition.channel;
        for (tone, sign) in [(36, -1.), (37, -1.), (27, -1.), (28, 1.)] {
            channel[tone] = lsig[tone].add(repeated[tone]).scale(0.5 * sign);
        }
        let mut metrics = [0.; 104];
        for symbol in 0..2 {
            let bins = self.corrected_bins(160 + symbol * 80)?;
            let (mut desired, mut orthogonal) = (0., 0.);
            for (index, tone) in (-28i32..=28)
                .filter(|tone| ![-21, -7, 0, 7, 21].contains(tone))
                .enumerate()
            {
                let bin = tone.rem_euclid(64) as usize;
                let value = bins[bin].mul(channel[bin].conj());
                metrics[52 * symbol + index] = value.i;
                desired += value.i * value.i;
                orthogonal += value.q * value.q;
            }
            if !desired.is_finite()
                || !orthogonal.is_finite()
                || desired < 1e-12
                || desired <= 4. * orthogonal
            {
                return None;
            }
        }
        Some(metrics)
    }
}

/// Recognize an EHT preamble and recover U-SIG after legacy OFDM acquisition.
/// The caller supplies samples beginning at L-SIG; complete DATA is not implied.
pub(in crate::radio) fn decode_prefix(
    samples: &[ComplexSample],
    acquisition: &Acquisition,
) -> Option<Prefix> {
    Receiver::new(samples, acquisition)?.decode()
}

/// Check only the 6 Mb/s, modulo-zero L-SIG and exact RL-SIG pair.
pub(in crate::radio) fn repeated_legacy_signal(
    samples: &[ComplexSample],
    acquisition: &Acquisition,
) -> Option<usize> {
    Receiver::new(samples, acquisition)?.repeated_legacy_length()
}
