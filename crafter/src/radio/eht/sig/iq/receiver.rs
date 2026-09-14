use super::{Error, Fields, SignalFields};
use crate::radio::{
    eht::{
        EhtMuPpduType, EhtNonOfdmaSignal, EhtOfdmaSignal, EhtSigMcs, EhtUsigFields, EhtUsigFormat,
    },
    signaling::{corrected_bins, Modulation},
    sync::Acquisition,
    ComplexSample,
};

#[derive(Debug, Clone, Copy)]
struct Mode {
    modulation: Modulation,
    data_bits_per_symbol: usize,
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
        Self {
            modulation,
            data_bits_per_symbol: modulation.coded_per_symbol() / 2,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Format {
    NonOfdma,
    Ofdma,
}

impl Format {
    fn new(ppdu_type: EhtMuPpduType) -> Self {
        match ppdu_type {
            EhtMuPpduType::DownlinkOfdma => Self::Ofdma,
            EhtMuPpduType::SingleUser | EhtMuPpduType::DownlinkMuMimo => Self::NonOfdma,
        }
    }

    fn first(self, blocks: &mut super::super::coded::Blocks<'_>) -> Result<Vec<u8>, Error> {
        match self {
            Self::NonOfdma => blocks.bits::<52>().map(Vec::from).map_err(Error::Coded),
            Self::Ofdma => blocks.bits::<36>().map(Vec::from).map_err(Error::Coded),
        }
    }

    fn required_bits(self, first: &[u8], usig: &EhtUsigFields) -> Result<usize, Error> {
        match self {
            Self::NonOfdma => EhtNonOfdmaSignal::required_bits(first, usig),
            Self::Ofdma => EhtOfdmaSignal::required_bits(first, usig),
        }
        .map_err(Error::Signal)
    }

    fn decode(self, bits: &[u8], usig: &EhtUsigFields) -> Result<SignalFields, Error> {
        match self {
            Self::NonOfdma => EhtNonOfdmaSignal::decode(bits, usig).map(SignalFields::NonOfdma),
            Self::Ofdma => EhtOfdmaSignal::decode(bits, usig).map(SignalFields::Ofdma),
        }
        .map_err(Error::Signal)
    }
}

pub(in crate::radio) struct Receiver<'a> {
    samples: &'a [ComplexSample],
    acquisition: &'a Acquisition,
    usig: EhtUsigFields,
    format: Format,
    mode: Mode,
    symbols: usize,
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
        let prefix =
            crate::radio::eht::iq::decode_prefix(samples, acquisition).ok_or(Error::Prefix)?;
        if prefix.fields.bandwidth_code != 0 {
            return Err(Error::Bandwidth(prefix.fields.bandwidth_code));
        }
        let EhtUsigFormat::Mu(fields) = prefix.fields.format else {
            return Err(Error::UnsupportedFormat);
        };
        let format = Format::new(fields.ppdu_type);
        let mode = Mode::new(fields.eht_sig_mcs);
        let symbols = usize::from(fields.eht_sig_symbols);
        let required = 320usize
            .checked_add(80usize.checked_mul(symbols).ok_or(Error::Overflow)?)
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
            format,
            mode,
            symbols,
            required,
        })
    }

    fn decode(self) -> Result<Fields, Error> {
        let metrics = self.metrics()?;
        let mut blocks = super::super::coded::Blocks::new(&metrics).map_err(Error::Coded)?;
        let first = self.format.first(&mut blocks)?;
        let required_bits = self.format.required_bits(&first, &self.usig)?;
        let required_symbols = required_bits.div_ceil(self.mode.data_bits_per_symbol);
        if self.symbols != required_symbols {
            return Err(Error::SymbolCount {
                required: required_symbols,
                advertised: self.symbols as u8,
            });
        }
        let mut bits = Vec::with_capacity(required_bits);
        bits.extend(first);
        while required_bits - bits.len() >= 54 {
            bits.extend(blocks.bits::<54>().map_err(Error::Coded)?);
        }
        if required_bits - bits.len() == 32 {
            bits.extend(blocks.bits::<32>().map_err(Error::Coded)?);
        }
        let signal = self.format.decode(&bits, &self.usig)?;
        Ok(Fields {
            usig: self.usig,
            signal,
            symbols: self.symbols,
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
            self.symbols
                .saturating_mul(self.mode.modulation.coded_per_symbol()),
        );
        for symbol in 0..self.symbols {
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
        (metrics.len() >= 72)
            .then_some(metrics)
            .ok_or(Error::Samples)
    }
}
