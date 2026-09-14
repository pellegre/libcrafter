//! EHT20 trigger-based training and DATA timeline.

use crate::protocols::link::Dot11EhtTriggerCommonFields;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    Length,
    Format,
    Guard,
    LtfSymbols,
    Duration,
    Overflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) struct Timing {
    pub ltf_size: u8,
    pub ltf_symbols: usize,
    pub guard: usize,
    pub data_symbols: usize,
    pub data_start: usize,
    pub data_end: usize,
    pub packet_end: usize,
    pub signaled_end: usize,
    pub pe_samples: usize,
    pub symbol_samples: usize,
}

impl Timing {
    pub fn new(legacy_length: usize, common: &Dot11EhtTriggerCommonFields) -> Result<Self, Error> {
        if legacy_length > 4095
            || legacy_length % 3 != 0
            || legacy_length != usize::from(common.ul_length)
        {
            return Err(Error::Length);
        }
        if common.bandwidth != 0 || !matches!(common.trigger_type, 0..=2 | 4..=6) {
            return Err(Error::Format);
        }
        let (ltf_size, guard) = match common.gi_ltf {
            1 => (2, 32),
            2 => (4, 64),
            _ => return Err(Error::Guard),
        };
        let ltf_symbols = [1usize, 2, 4, 6, 8]
            .get(usize::from(common.ltf_symbols))
            .copied()
            .ok_or(Error::LtfSymbols)?;
        let ltf_stride = 64usize
            .checked_mul(usize::from(ltf_size))
            .and_then(|useful| useful.checked_add(guard))
            .ok_or(Error::Overflow)?;
        let training_samples = ltf_symbols.checked_mul(ltf_stride).ok_or(Error::Overflow)?;
        let symbol_samples = 256usize.checked_add(guard).ok_or(Error::Overflow)?;
        let rounded = legacy_length
            .checked_add(3)
            .and_then(|length| length.checked_div(3))
            .and_then(|symbols| symbols.checked_mul(80))
            .ok_or(Error::Overflow)?;
        // Relative to L-SIG: RL-SIG, U-SIG, and the 8 us EHT-STF occupy 20 us.
        let available = rounded
            .checked_sub(400)
            .and_then(|samples| samples.checked_sub(training_samples))
            .ok_or(Error::Duration)?;
        let data_symbols = (available / symbol_samples)
            .checked_sub(usize::from(common.pe_disambiguity))
            .filter(|symbols| *symbols > 0)
            .ok_or(Error::Duration)?;
        let data_start = 800usize
            .checked_add(training_samples)
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
        Ok(Self {
            ltf_size,
            ltf_symbols,
            guard,
            data_symbols,
            data_start,
            data_end,
            packet_end: data_end.checked_add(pe_samples).ok_or(Error::Overflow)?,
            signaled_end: rounded.checked_add(400).ok_or(Error::Overflow)?,
            pe_samples,
            symbol_samples,
        })
    }

    pub fn symbol_start(self, symbol: usize) -> Option<usize> {
        (symbol < self.data_symbols)
            .then(|| symbol.checked_mul(self.symbol_samples))
            .flatten()
            .and_then(|offset| self.data_start.checked_add(offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_eht_tb_timing_matches_forward_oracle() {
        let rows = include_str!("../../../../tests/fixtures/iq/eht-tb-timing.tsv");
        assert_eq!(rows.lines().skip(1).count(), 450);
        for row in rows.lines().skip(1) {
            let columns: Vec<_> = row.split('\t').collect();
            let values: Vec<usize> = columns.iter().map(|value| value.parse().unwrap()).collect();
            let common = Dot11EhtTriggerCommonFields {
                gi_ltf: values[0] as u8,
                ltf_symbols: values[1] as u8,
                ul_length: values[4] as u16,
                pe_disambiguity: values[5] != 0,
                ..Default::default()
            };
            let timing =
                Timing::new(values[4], &common).unwrap_or_else(|error| panic!("{row}: {error:?}"));
            assert_eq!(
                [
                    timing.ltf_size as usize,
                    timing.guard,
                    timing.ltf_symbols,
                    timing.data_symbols,
                    timing.pe_samples,
                    timing.data_start,
                    timing.data_end,
                    timing.packet_end,
                    timing.signaled_end,
                ],
                [
                    values[6], values[7], values[8], values[2], values[3], values[9], values[10],
                    values[11], values[12],
                ],
                "{row}"
            );
            for symbol in 0..timing.data_symbols {
                assert_eq!(
                    timing.symbol_start(symbol),
                    Some(timing.data_start + symbol * timing.symbol_samples)
                );
            }
            assert!(timing.symbol_start(timing.data_symbols).is_none());
        }
    }

    #[test]
    fn radio_eht_tb_timing_rejects_inconsistent_context() {
        let common = Dot11EhtTriggerCommonFields {
            ul_length: 300,
            gi_ltf: 1,
            ..Default::default()
        };
        for length in [0, 1, 299, 301, 4096, usize::MAX] {
            assert_eq!(Timing::new(length, &common), Err(Error::Length));
        }
        for gi_ltf in [0, 3, u8::MAX] {
            assert_eq!(
                Timing::new(300, &Dot11EhtTriggerCommonFields { gi_ltf, ..common }),
                Err(Error::Guard)
            );
        }
        for ltf_symbols in [5, 6, 7, u8::MAX] {
            assert_eq!(
                Timing::new(
                    300,
                    &Dot11EhtTriggerCommonFields {
                        ltf_symbols,
                        ..common
                    }
                ),
                Err(Error::LtfSymbols)
            );
        }
    }
}
