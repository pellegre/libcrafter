use super::{Admission, Error};
use crate::radio::{sync::Acquisition, ComplexSample};

#[cfg(test)]
mod tests;

/// One-stream EHT20 DATA symbol demodulator over an admitted trained channel.
pub(super) struct Demodulator<'a> {
    samples: &'a [ComplexSample],
    acquisition: &'a Acquisition,
    admission: &'a Admission,
}

impl<'a> Demodulator<'a> {
    pub fn new(
        samples: &'a [ComplexSample],
        acquisition: &'a Acquisition,
        admission: &'a Admission,
    ) -> Result<Self, Error> {
        if samples.len() < admission.required_samples {
            return Err(Error::Truncated {
                required: admission.required_samples,
                available: samples.len(),
            });
        }
        if acquisition
            .signal_start
            .checked_sub(acquisition.preamble_start)
            != Some(320)
            || admission.trained.data_start != admission.info.data_start
        {
            return Err(Error::Training);
        }
        Ok(Self {
            samples: &samples[..admission.required_samples],
            acquisition,
            admission,
        })
    }

    pub fn recover(self) -> Result<Vec<f32>, Error> {
        let tones =
            crate::radio::resource_unit::Tones::ru(242, 1).ok_or(Error::UnsupportedFormat)?;
        let capacity = self.admission.capacity;
        let mut demodulator = crate::radio::resource_unit::symbol::Demodulator::new(
            tones,
            capacity.bits_per_tone,
            capacity.ldpc,
            capacity.dcm,
        )
        .ok_or(Error::Modulation(capacity.mcs))?;
        let mut metrics = Vec::new();
        let required_metrics = self
            .admission
            .timing
            .data_symbols
            .checked_mul(capacity.coded_per_symbol)
            .ok_or(Error::Overflow)?;
        metrics
            .try_reserve_exact(required_metrics)
            .map_err(|_| Error::Overflow)?;
        let mut pilot_state = 127u8;
        for _ in 0..4 + self.admission.trained.signal.symbols {
            crate::radio::data::feedback(&mut pilot_state);
        }
        for symbol in 0..self.admission.timing.data_symbols {
            let symbol_start = self
                .admission
                .timing
                .symbol_start(symbol)
                .and_then(|start| u64::try_from(start).ok())
                .and_then(|start| self.acquisition.preamble_start.checked_add(start))
                .and_then(|start| start.checked_add(self.admission.trained.guard as u64))
                .ok_or(Error::Overflow)?;
            let offset = symbol_start
                .checked_sub(self.acquisition.signal_start)
                .and_then(|offset| usize::try_from(offset).ok())
                .ok_or(Error::Training)?;
            let wave = self
                .samples
                .get(offset..offset.checked_add(256).ok_or(Error::Overflow)?)
                .ok_or(Error::Truncated {
                    required: offset.saturating_add(256),
                    available: self.samples.len(),
                })?;
            let elapsed = symbol_start
                .checked_sub(self.acquisition.phase_origin)
                .ok_or(Error::Training)?;
            let polarity = 1. - 2. * crate::radio::data::feedback(&mut pilot_state) as f32;
            metrics.extend(
                demodulator
                    .recover(
                        wave,
                        &self.admission.trained.channel,
                        self.acquisition.frequency_rad,
                        elapsed,
                        symbol,
                        polarity,
                    )
                    .ok_or(Error::Samples)?,
            );
        }
        if metrics.len() != required_metrics {
            return Err(Error::Samples);
        }
        Ok(metrics)
    }
}
