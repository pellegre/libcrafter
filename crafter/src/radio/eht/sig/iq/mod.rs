//! EHT-SIG recovery for 20 MHz non-OFDMA single-user PPDUs.

use super::super::{
    EhtMuPpduType, EhtNonOfdmaSignal, EhtSigError, EhtSigMcs, EhtUsigFields, EhtUsigFormat,
};
use crate::radio::{
    signaling::{corrected_bins, Modulation},
    sync::Acquisition,
    ComplexSample,
};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    Prefix,
    UnsupportedFormat,
    Bandwidth(u8),
    SymbolCount { required: usize, advertised: u8 },
    Truncated { required: usize, available: usize },
    Samples,
    Overflow,
    Signal(EhtSigError),
}

/// Integrity-checked EHT signaling recovered directly from IQ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) struct Fields {
    pub usig: EhtUsigFields,
    pub signal: EhtNonOfdmaSignal,
    pub symbols: usize,
    pub end_sample: u64,
}

#[derive(Debug, Clone, Copy)]
struct Mode {
    modulation: Modulation,
    symbols: usize,
}

impl Mode {
    fn new(mcs: EhtSigMcs) -> Self {
        let (mcs, dcm) = match mcs {
            EhtSigMcs::Mcs0 => (0, false),
            EhtSigMcs::Mcs1 => (1, false),
            EhtSigMcs::Mcs3 => (3, false),
            EhtSigMcs::Mcs0Dcm => (0, true),
        };
        let modulation = Modulation::new(mcs, dcm).expect("EHT-SIG MCS is defined");
        let data_bits = modulation.coded_per_symbol() / 2;
        Self {
            modulation,
            symbols: 52usize.div_ceil(data_bits),
        }
    }
}

pub(in crate::radio) struct Receiver<'a> {
    samples: &'a [ComplexSample],
    acquisition: &'a Acquisition,
    usig: EhtUsigFields,
    mode: Mode,
    required: usize,
}

impl<'a> Receiver<'a> {
    pub(in crate::radio) fn recover(
        samples: &'a [ComplexSample],
        acquisition: &'a Acquisition,
    ) -> Result<Fields, Error> {
        Self::new(samples, acquisition)?.decode()
    }

    fn new(samples: &'a [ComplexSample], acquisition: &'a Acquisition) -> Result<Self, Error> {
        let prefix = super::super::iq::decode_prefix(samples, acquisition).ok_or(Error::Prefix)?;
        if prefix.fields.bandwidth_code != 0 {
            return Err(Error::Bandwidth(prefix.fields.bandwidth_code));
        }
        let EhtUsigFormat::Mu(fields) = prefix.fields.format else {
            return Err(Error::UnsupportedFormat);
        };
        if fields.ppdu_type != EhtMuPpduType::SingleUser {
            return Err(Error::UnsupportedFormat);
        }
        let mode = Mode::new(fields.eht_sig_mcs);
        if usize::from(fields.eht_sig_symbols) != mode.symbols {
            return Err(Error::SymbolCount {
                required: mode.symbols,
                advertised: fields.eht_sig_symbols,
            });
        }
        let required = 320usize
            .checked_add(80usize.checked_mul(mode.symbols).ok_or(Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        acquisition
            .signal_start
            .checked_add(required as u64)
            .ok_or(Error::Overflow)?;
        if samples.len() < required {
            return Err(Error::Truncated {
                required,
                available: samples.len(),
            });
        }
        Ok(Self {
            samples: &samples[..required],
            acquisition,
            usig: prefix.fields,
            mode,
            required,
        })
    }

    fn decode(self) -> Result<Fields, Error> {
        let metrics = self.metrics()?;
        let scale = metrics[..104]
            .iter()
            .map(|metric| metric.abs())
            .fold(0f32, f32::max);
        if !scale.is_finite() || scale == 0. {
            return Err(Error::Samples);
        }
        let pairs = std::array::from_fn::<_, 52, _>(|index| {
            [metrics[2 * index] / scale, metrics[2 * index + 1] / scale]
        });
        let bits = crate::radio::signal::decode_bcc(&pairs);
        let signal = EhtNonOfdmaSignal::decode(&bits, &self.usig).map_err(Error::Signal)?;
        Ok(Fields {
            usig: self.usig,
            signal,
            symbols: self.mode.symbols,
            end_sample: self.acquisition.signal_start + self.required as u64,
        })
    }

    fn metrics(&self) -> Result<Vec<f32>, Error> {
        let lsig = corrected_bins(
            &self.samples[..80],
            self.acquisition.signal_start,
            self.acquisition,
            1.,
        )
        .ok_or(Error::Samples)?;
        let repeated = corrected_bins(
            &self.samples[80..160],
            self.acquisition.signal_start + 80,
            self.acquisition,
            1.,
        )
        .ok_or(Error::Samples)?;
        let mut channel = self.acquisition.channel;
        for (tone, sign) in [(36, -1.), (37, -1.), (27, -1.), (28, 1.)] {
            channel[tone] = lsig[tone].add(repeated[tone]).scale(0.5 * sign);
        }
        if channel.iter().any(|value| !value.power().is_finite()) {
            return Err(Error::Samples);
        }
        let mut pilot_state = 127;
        for _ in 0..4 {
            crate::radio::data::feedback(&mut pilot_state);
        }
        let mut metrics = Vec::with_capacity(
            self.mode
                .symbols
                .saturating_mul(self.mode.modulation.coded_per_symbol()),
        );
        for symbol in 0..self.mode.symbols {
            let offset = 320 + 80 * symbol;
            let polarity = 1. - 2. * f32::from(crate::radio::data::feedback(&mut pilot_state));
            let bins = corrected_bins(
                &self.samples[offset..offset + 80],
                self.acquisition.signal_start + offset as u64,
                self.acquisition,
                polarity,
            )
            .ok_or(Error::Samples)?;
            let tones: Vec<_> = (-28i32..=28)
                .filter(|tone| ![-21, -7, 0, 7, 21].contains(tone))
                .map(|tone| {
                    let bin = tone.rem_euclid(64) as usize;
                    let weight = channel[bin].power();
                    if weight > 1e-12 {
                        (
                            bins[bin].mul(channel[bin].conj()).scale(1. / weight),
                            weight,
                        )
                    } else {
                        (ComplexSample::ZERO, 0.)
                    }
                })
                .collect();
            metrics.extend(self.mode.modulation.decode(&tones).ok_or(Error::Samples)?);
        }
        (metrics.len() >= 104)
            .then_some(metrics)
            .ok_or(Error::Samples)
    }
}
