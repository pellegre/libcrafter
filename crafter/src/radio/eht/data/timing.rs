use super::Error;
use crate::radio::eht::sig::iq::{Fields, SignalFields};

/// Complete EHT20 DATA timeline, expressed as offsets from PPDU start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) struct Timing {
    pub data_symbols: usize,
    pub data_start: usize,
    pub data_end: usize,
    pub packet_end: usize,
    pub signaled_end: usize,
    pub pe_samples: usize,
    pub symbol_samples: usize,
}

impl Timing {
    /// Resolve the downlink one-stream timeline after checked EHT-SIG.
    pub fn new(fields: &Fields) -> Result<Self, Error> {
        if fields.legacy_length > 4095 || fields.legacy_length % 3 != 0 {
            return Err(Error::Length);
        }
        let (ltf_mode, ltf_symbols, pe_disambiguity) = match &fields.signal {
            SignalFields::NonOfdma(signal) => (
                signal.common.ltf_mode,
                signal.common.ltf_symbols,
                signal.common.pe_disambiguity,
            ),
            SignalFields::Ofdma(signal) => (
                signal.common.ltf_mode,
                signal.common.ltf_symbols,
                signal.common.pe_disambiguity,
            ),
        };
        let guard = usize::from(ltf_mode.guard_interval_ns()) / 50;
        let symbol_samples = 256usize.checked_add(guard).ok_or(Error::Overflow)?;
        let training_samples = usize::from(ltf_symbols)
            .checked_mul(
                64usize
                    .checked_mul(usize::from(ltf_mode.size()))
                    .and_then(|useful| useful.checked_add(guard))
                    .ok_or(Error::Overflow)?,
            )
            .ok_or(Error::Overflow)?;
        let signal_samples = fields.symbols.checked_mul(80).ok_or(Error::Overflow)?;
        let rounded = fields
            .legacy_length
            .checked_add(3)
            .and_then(|length| length.checked_div(3))
            .and_then(|symbols| symbols.checked_mul(80))
            .ok_or(Error::Overflow)?;
        let fixed = 320usize
            .checked_add(signal_samples)
            .and_then(|value| value.checked_add(training_samples))
            .ok_or(Error::Overflow)?;
        let available = rounded.checked_sub(fixed).ok_or(Error::Duration)?;
        let disambiguity = usize::from(pe_disambiguity);
        let data_symbols = (available / symbol_samples)
            .checked_sub(disambiguity)
            .filter(|symbols| *symbols > 0)
            .ok_or(Error::Duration)?;
        let data_start = 720usize
            .checked_add(signal_samples)
            .and_then(|value| value.checked_add(training_samples))
            .ok_or(Error::Overflow)?;
        let data_end = data_symbols
            .checked_mul(symbol_samples)
            .and_then(|samples| data_start.checked_add(samples))
            .ok_or(Error::Overflow)?;
        let leftover = available
            .checked_sub(data_symbols * symbol_samples)
            .ok_or(Error::Duration)?;
        let pe_samples = leftover / 80 * 80;
        if pe_samples > 320 {
            return Err(Error::Duration);
        }
        let packet_end = data_end.checked_add(pe_samples).ok_or(Error::Overflow)?;
        let signaled_end = rounded.checked_add(400).ok_or(Error::Overflow)?;
        Ok(Self {
            data_symbols,
            data_start,
            data_end,
            packet_end,
            signaled_end,
            pe_samples,
            symbol_samples,
        })
    }

    pub fn symbol_start(self, symbol: usize) -> Option<usize> {
        if symbol >= self.data_symbols {
            return None;
        }
        self.data_start
            .checked_add(symbol.checked_mul(self.symbol_samples)?)
    }
}
