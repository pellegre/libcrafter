//! Shared EHT RU/MRU DATA demodulation.

use super::{Capacity, Error};
use crate::radio::{eht::EhtResourceUnit, resource_unit::Tones, sync::Acquisition, ComplexSample};

pub(in crate::radio::eht) struct Demodulator<'a> {
    samples: &'a [ComplexSample],
    acquisition: &'a Acquisition,
    resource: EhtResourceUnit,
    channel: &'a [ComplexSample; 256],
    capacity: Capacity,
    data_start: u64,
    guard: usize,
    data_symbols: usize,
    symbol_samples: usize,
    pilot_updates: usize,
}

impl<'a> Demodulator<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        samples: &'a [ComplexSample],
        acquisition: &'a Acquisition,
        required_samples: usize,
        resource: EhtResourceUnit,
        channel: &'a [ComplexSample; 256],
        capacity: Capacity,
        data_start: u64,
        guard: usize,
        data_symbols: usize,
        symbol_samples: usize,
        pilot_updates: usize,
    ) -> Result<Self, Error> {
        if samples.len() < required_samples {
            return Err(Error::Truncated {
                required: required_samples,
                available: samples.len(),
            });
        }
        data_start
            .checked_sub(acquisition.signal_start)
            .ok_or(Error::Training)?;
        Ok(Self {
            samples: &samples[..required_samples],
            acquisition,
            resource,
            channel,
            capacity,
            data_start,
            guard,
            data_symbols,
            symbol_samples,
            pilot_updates,
        })
    }

    pub fn recover(self) -> Result<Vec<f32>, Error> {
        let components = self.resource.components();
        let first = components.first().ok_or(Error::UnsupportedFormat)?;
        let first = Tones::ru(first.tone_count(), usize::from(first.index()))
            .ok_or(Error::UnsupportedFormat)?;
        let mut demodulator = match components {
            [_] => crate::radio::resource_unit::symbol::Demodulator::new(
                first,
                self.capacity.bits_per_tone,
                self.capacity.ldpc,
                self.capacity.dcm,
            ),
            [_, second] => {
                let second = Tones::ru(second.tone_count(), usize::from(second.index()))
                    .ok_or(Error::UnsupportedFormat)?;
                crate::radio::resource_unit::symbol::Demodulator::for_small_mru(
                    first,
                    second,
                    self.capacity.bits_per_tone,
                    self.capacity.ldpc,
                    self.capacity.dcm,
                )
            }
            _ => None,
        }
        .ok_or(Error::Modulation(self.capacity.mcs))?;
        let required_metrics = self
            .data_symbols
            .checked_mul(self.capacity.coded_per_symbol)
            .ok_or(Error::Overflow)?;
        let mut metrics = Vec::new();
        metrics
            .try_reserve_exact(required_metrics)
            .map_err(|_| Error::Overflow)?;
        let mut pilot_state = 127u8;
        for _ in 0..self.pilot_updates {
            crate::radio::data::feedback(&mut pilot_state);
        }
        for symbol in 0..self.data_symbols {
            let symbol_start = u64::try_from(symbol)
                .ok()
                .and_then(|index| index.checked_mul(self.symbol_samples as u64))
                .and_then(|offset| self.data_start.checked_add(offset))
                .and_then(|start| start.checked_add(self.guard as u64))
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
                        self.channel,
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
