//! One-stream EHT20 trigger-based RU/MRU DATA receiver.

use crate::protocols::link::{
    Dot11EhtTriggerCommonFields, Dot11EhtTriggerSpecialUserFields, Dot11EhtTriggerUserFields,
};
use crate::radio::{
    eht::{self, data::Capacity, EhtResourceUnit, EhtUsigFormat},
    sync::Acquisition,
    ComplexSample, SignalInfo,
};

use super::super::timing::Timing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    Header,
    Context,
    Timing,
    Unsupported,
    Limit,
    Samples,
    Training,
    Data(eht::data::Error),
}

pub(in crate::radio) struct Admission {
    pub timing: Timing,
    pub common: Dot11EhtTriggerCommonFields,
    pub user: Dot11EhtTriggerUserFields,
    pub resource: EhtResourceUnit,
    pub capacity: Capacity,
    pub info: SignalInfo,
    pub required_samples: usize,
}

pub(in crate::radio) struct Recovered {
    pub admission: Admission,
    pub psdu: Vec<u8>,
    pub failed_codewords: usize,
    pub first_failure: Option<crate::radio::ldpc::rate::Error>,
}

pub(in crate::radio) struct Receiver;

impl Receiver {
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        samples: &[ComplexSample],
        acquisition: &Acquisition,
        common: &Dot11EhtTriggerCommonFields,
        special: &Dot11EhtTriggerSpecialUserFields,
        user: &Dot11EhtTriggerUserFields,
        resource: EhtResourceUnit,
        max_psdu: usize,
        max_samples: usize,
    ) -> Result<Admission, Error> {
        if acquisition
            .signal_start
            .checked_sub(acquisition.preamble_start)
            != Some(320)
        {
            return Err(Error::Timing);
        }
        let prefix = eht::iq::decode_prefix(samples, acquisition).ok_or(Error::Header)?;
        let EhtUsigFormat::TriggerBased(usig) = prefix.fields.format else {
            return Err(Error::Header);
        };
        if prefix.fields.bandwidth_code != 0
            || !prefix.fields.uplink
            || usig.spatial_reuse != [special.spatial_reuse_1, special.spatial_reuse_2]
        {
            return Err(Error::Context);
        }
        if EhtResourceUnit::from_trigger_20(user.ru_allocation) != Some(resource) {
            return Err(Error::Context);
        }
        let timing = Timing::new(prefix.legacy_length, common).map_err(|_| Error::Timing)?;
        if timing.data_symbols > 400 {
            return Err(Error::Limit);
        }
        let required_samples = timing.data_end.checked_sub(320).ok_or(Error::Timing)?;
        if required_samples > max_samples {
            return Err(Error::Limit);
        }
        let capacity = Capacity::for_tb(common, user, resource, timing.data_symbols)
            .map_err(|_| Error::Unsupported)?;
        if capacity.psdu_bytes > max_psdu {
            return Err(Error::Limit);
        }
        if user.ldpc {
            crate::radio::ldpc::rate::Layout::eht_tb(
                common,
                user,
                resource,
                timing.data_symbols.try_into().map_err(|_| Error::Limit)?,
            )
            .map_err(|_| Error::Unsupported)?;
        }
        let data_start = acquisition
            .preamble_start
            .checked_add(timing.data_start as u64)
            .ok_or(Error::Timing)?;
        let end_sample_index = acquisition
            .preamble_start
            .checked_add(timing.data_end as u64)
            .ok_or(Error::Timing)?;
        let rate_bps = u32::try_from(
            u64::try_from(capacity.data_per_symbol)
                .map_err(|_| Error::Limit)?
                .checked_mul(20_000_000)
                .and_then(|bits| bits.checked_div(timing.symbol_samples as u64))
                .ok_or(Error::Limit)?,
        )
        .map_err(|_| Error::Limit)?;
        Ok(Admission {
            timing,
            common: *common,
            user: *user,
            resource,
            capacity,
            info: SignalInfo {
                rate_bps,
                coded_bits_per_symbol: capacity.coded_per_symbol,
                data_bits_per_symbol: capacity.data_per_symbol,
                psdu_bytes: capacity.psdu_bytes,
                data_symbols: timing.data_symbols,
                data_start,
                end_sample_index,
            },
            required_samples,
        })
    }

    pub fn recover(
        admission: Admission,
        samples: &[ComplexSample],
        acquisition: &Acquisition,
        max_psdu: usize,
        partial: bool,
    ) -> Result<Recovered, Error> {
        if samples.len() < admission.required_samples {
            return Err(Error::Samples);
        }
        let channel = eht::training::resource::train(
            samples,
            acquisition,
            admission.resource,
            admission.timing.ltf_size,
            admission.timing.guard,
            480,
        )
        .ok_or(Error::Training)?;
        let metrics = eht::data::resource::Demodulator::new(
            samples,
            acquisition,
            admission.required_samples,
            admission.resource,
            &channel,
            admission.capacity,
            admission.info.data_start,
            admission.timing.guard,
            admission.timing.data_symbols,
            admission.timing.symbol_samples,
            4,
        )
        .map_err(Error::Data)?
        .recover()
        .map_err(Error::Data)?;
        let (psdu, failed_codewords, first_failure) = if admission.capacity.ldpc {
            let recovered = eht::data::ldpc::Decoder::for_tb(
                &admission.common,
                &admission.user,
                admission.resource,
                admission.capacity,
                admission.timing.data_symbols,
            )
            .map_err(Error::Data)?
            .recover(&metrics, max_psdu, partial)
            .map_err(Error::Data)?;
            (
                recovered.psdu,
                recovered.failed_codewords,
                recovered.first_failure,
            )
        } else {
            (
                eht::data::bcc::recover(
                    admission.capacity,
                    admission.timing.data_symbols,
                    &metrics,
                    max_psdu,
                )
                .map_err(Error::Data)?,
                0,
                None,
            )
        };
        Ok(Recovered {
            admission,
            psdu,
            failed_codewords,
            first_failure,
        })
    }
}
