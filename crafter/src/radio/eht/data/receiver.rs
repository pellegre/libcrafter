use super::{Capacity, Error, Timing};
use crate::radio::{eht::training::Trained, SignalInfo};

pub(in crate::radio) struct Admission {
    pub trained: Trained,
    pub timing: Timing,
    pub capacity: Capacity,
    pub info: SignalInfo,
    /// Total retained samples beginning at L-SIG.
    pub required_samples: usize,
}

/// Admit checked and trained EHT20 signaling into the bounded DATA receiver.
pub(in crate::radio) struct Receiver;

impl Receiver {
    pub fn admit(
        trained: Trained,
        max_psdu: usize,
        max_samples: usize,
    ) -> Result<Admission, Error> {
        let timing = Timing::new(&trained.signal)?;
        let capacity = Capacity::new(&trained.signal, timing.data_symbols)?;
        let crate::radio::eht::sig::iq::SignalFields::NonOfdma(signal) = &trained.signal.signal
        else {
            return Err(Error::UnsupportedFormat);
        };
        let ltf_stride = 64u64
            .checked_mul(u64::from(signal.common.ltf_mode.size()))
            .and_then(|useful| useful.checked_add(trained.guard as u64))
            .ok_or(Error::Overflow)?;
        let expected_data_start = trained
            .signal
            .end_sample
            .checked_add(80)
            .and_then(|start| {
                u64::from(signal.common.ltf_symbols)
                    .checked_mul(ltf_stride)
                    .and_then(|training| start.checked_add(training))
            })
            .ok_or(Error::Overflow)?;
        if trained.data_start != expected_data_start {
            return Err(Error::Training);
        }
        let required_samples = timing.data_end.checked_sub(320).ok_or(Error::Overflow)?;
        if capacity.psdu_bytes > max_psdu {
            return Err(Error::FrameLimit);
        }
        if required_samples > max_samples {
            return Err(Error::SampleLimit);
        }
        let rate_bps = u32::try_from(
            u64::try_from(capacity.data_per_symbol)
                .map_err(|_| Error::Overflow)?
                .checked_mul(20_000_000)
                .and_then(|bits| bits.checked_div(timing.symbol_samples as u64))
                .ok_or(Error::Overflow)?,
        )
        .map_err(|_| Error::Overflow)?;
        let info = SignalInfo {
            rate_bps,
            coded_bits_per_symbol: capacity.coded_per_symbol,
            data_bits_per_symbol: capacity.data_per_symbol,
            psdu_bytes: capacity.psdu_bytes,
            data_symbols: timing.data_symbols,
            data_start: trained.data_start,
            end_sample_index: trained
                .data_start
                .checked_add(
                    u64::try_from(timing.data_end - timing.data_start)
                        .map_err(|_| Error::Overflow)?,
                )
                .ok_or(Error::Overflow)?,
        };
        Ok(Admission {
            trained,
            timing,
            capacity,
            info,
            required_samples,
        })
    }
}
