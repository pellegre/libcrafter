use super::{Error, Trained};
use crate::radio::{
    eht::{
        sig::iq::{Fields as SignalFields, SignalFields as SignalKind},
        EhtNonOfdmaUsers,
    },
    resource_unit::Tones,
    sync::Acquisition,
    ComplexSample,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Layout {
    ltf_start: usize,
    ltf_size: u8,
    ltf_symbols: usize,
    guard: usize,
    required: usize,
    data_start: u64,
}

impl Layout {
    fn new(signal: &SignalFields, acquisition: &Acquisition) -> Result<Self, Error> {
        if acquisition
            .signal_start
            .checked_sub(acquisition.preamble_start)
            != Some(320)
        {
            return Err(Error::Timing);
        }
        let SignalKind::NonOfdma(fields) = &signal.signal else {
            return Err(Error::UnsupportedFormat);
        };
        let EhtNonOfdmaUsers::Single(user) = &fields.users else {
            return Err(Error::UnsupportedFormat);
        };
        if user.space_time_streams != 1 {
            return Err(Error::SpatialStreams(user.space_time_streams));
        }
        let ltf_size = fields.common.ltf_mode.size();
        let guard = usize::from(fields.common.ltf_mode.guard_interval_ns()) / 50;
        let stride = 64usize
            .checked_mul(usize::from(ltf_size))
            .and_then(|useful| useful.checked_add(guard))
            .ok_or(Error::Timing)?;
        let signal_end = signal
            .end_sample
            .checked_sub(acquisition.signal_start)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(Error::Timing)?;
        let ltf_start = signal_end.checked_add(80).ok_or(Error::Timing)?;
        let ltf_symbols = usize::from(fields.common.ltf_symbols);
        let required = stride
            .checked_mul(ltf_symbols)
            .and_then(|training| ltf_start.checked_add(training))
            .ok_or(Error::Timing)?;
        let data_start = acquisition
            .signal_start
            .checked_add(required as u64)
            .ok_or(Error::Timing)?;
        Ok(Self {
            ltf_start,
            ltf_size,
            ltf_symbols,
            guard,
            required,
            data_start,
        })
    }
}

/// Recover the SISO EHT-LTF channel for one 20 MHz non-OFDMA PPDU.
pub(in crate::radio) struct Receiver<'a> {
    samples: &'a [ComplexSample],
    acquisition: &'a Acquisition,
    signal: SignalFields,
    layout: Layout,
}

impl<'a> Receiver<'a> {
    pub(in crate::radio) fn recover(
        samples: &'a [ComplexSample],
        acquisition: &'a Acquisition,
        signal: SignalFields,
    ) -> Result<Trained, Error> {
        Self::new(samples, acquisition, signal)?.train()
    }

    fn new(
        samples: &'a [ComplexSample],
        acquisition: &'a Acquisition,
        signal: SignalFields,
    ) -> Result<Self, Error> {
        let layout = Layout::new(&signal, acquisition)?;
        if samples.len() < layout.required {
            return Err(Error::Truncated {
                required: layout.required,
                available: samples.len(),
            });
        }
        Ok(Self {
            samples: &samples[..layout.required],
            acquisition,
            signal,
            layout,
        })
    }

    fn train(self) -> Result<Trained, Error> {
        debug_assert!(self.layout.ltf_symbols > 0);
        let allocation = Tones::ru(242, 1).ok_or(Error::UnsupportedFormat)?;
        let channel = crate::radio::he::training::train_ru_field(
            self.samples,
            self.acquisition,
            allocation,
            self.layout.ltf_size,
            (self.layout.guard * 50) as u16,
            self.layout.ltf_start,
        )
        .ok_or(Error::Samples)?;
        Ok(Trained {
            signal: self.signal,
            channel,
            data_start: self.layout.data_start,
            guard: self.layout.guard,
        })
    }
}
