use super::super::{Capacity, Error, Timing};
use crate::radio::{
    eht::{training::Trained, EhtNonMuUser, EhtOfdmaUser, EhtResourceUnit, SignalFields},
    sync::Acquisition,
    ComplexSample, SignalInfo,
};

pub(in crate::radio) struct UserAdmission {
    pub resource_index: usize,
    pub user_index: usize,
    pub resource: EhtResourceUnit,
    pub user: EhtNonMuUser,
    pub capacity: Capacity,
    pub info: SignalInfo,
}

pub(in crate::radio) struct Admission {
    pub trained: Trained,
    pub timing: Timing,
    /// Original EHT-SIG User-field order, retaining independently unsupported
    /// or malformed users without discarding decodable resources.
    pub users: Vec<Result<UserAdmission, Error>>,
    pub required_samples: usize,
}

impl Admission {
    pub fn info(&self) -> SignalInfo {
        self.users
            .iter()
            .find_map(|user| user.as_ref().ok().map(|user| user.info))
            .expect("OFDMA admission requires one supported user")
    }
}

pub(in crate::radio) struct Payload {
    pub user_index: usize,
    pub resource: EhtResourceUnit,
    pub info: SignalInfo,
    pub psdu: Vec<u8>,
    pub failed_codewords: usize,
    pub first_failure: Option<crate::radio::ldpc::rate::Error>,
}

pub(in crate::radio) struct Recovered {
    pub admission: Admission,
    pub users: Vec<Result<Payload, Error>>,
}

pub(in crate::radio) struct Receiver;

impl Receiver {
    pub fn admit(
        trained: Trained,
        max_psdu: usize,
        max_samples: usize,
    ) -> Result<Admission, Error> {
        let timing = Timing::new(&trained.signal)?;
        let SignalFields::Ofdma(signal) = &trained.signal.signal else {
            return Err(Error::UnsupportedFormat);
        };
        let resources = signal.common.allocation.resources();
        if trained.resources.len() != resources.len() || trained.resources.is_empty() {
            return Err(Error::Training);
        }
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
        if required_samples > max_samples {
            return Err(Error::SampleLimit);
        }

        let mut users = Vec::with_capacity(signal.users.len());
        let mut cursor = 0usize;
        for (resource_index, (&resource, trained_resource)) in
            resources.iter().zip(&trained.resources).enumerate()
        {
            let end = cursor
                .checked_add(usize::from(resource.user_count()))
                .ok_or(Error::Overflow)?;
            if trained_resource.resource != resource || trained_resource.users != (cursor..end) {
                return Err(Error::Training);
            }
            for user_index in cursor..end {
                let admitted = (|| {
                    if resource.user_count() != 1 {
                        return Err(Error::UnsupportedFormat);
                    }
                    let user = match signal.users.get(user_index) {
                        Some(Ok(EhtOfdmaUser::NonMu(user))) => user,
                        Some(Err(_)) => return Err(Error::User),
                        _ => return Err(Error::UnsupportedFormat),
                    };
                    if trained_resource.channel.is_none() {
                        return Err(Error::Training);
                    }
                    let capacity =
                        Capacity::for_ofdma(&signal.common, user, resource, timing.data_symbols)?;
                    if capacity.psdu_bytes > max_psdu {
                        return Err(Error::FrameLimit);
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
                    Ok(UserAdmission {
                        resource_index,
                        user_index,
                        resource,
                        user: *user,
                        capacity,
                        info,
                    })
                })();
                users.push(admitted);
            }
            cursor = end;
        }
        if cursor != signal.users.len() {
            return Err(Error::Training);
        }
        if !users.iter().any(Result::is_ok) {
            return Err(users
                .iter()
                .find_map(|user| user.as_ref().err().copied())
                .unwrap_or(Error::UnsupportedFormat));
        }
        Ok(Admission {
            trained,
            timing,
            users,
            required_samples,
        })
    }

    pub fn recover(
        admission: Admission,
        samples: &[ComplexSample],
        acquisition: &Acquisition,
        max_psdu: usize,
    ) -> Result<Recovered, Error> {
        if samples.len() < admission.required_samples {
            return Err(Error::Truncated {
                required: admission.required_samples,
                available: samples.len(),
            });
        }
        let mut users = Vec::with_capacity(admission.users.len());
        for admitted in &admission.users {
            let recovered = match admitted {
                Err(error) => Err(*error),
                Ok(user) => (|| {
                    if user.capacity.psdu_bytes > max_psdu {
                        return Err(Error::FrameLimit);
                    }
                    let channel = admission
                        .trained
                        .resources
                        .get(user.resource_index)
                        .and_then(|resource| resource.channel.as_ref())
                        .ok_or(Error::Training)?;
                    let metrics = super::super::resource::Demodulator::new(
                        samples,
                        acquisition,
                        admission.required_samples,
                        user.resource,
                        channel,
                        user.capacity,
                        user.info.data_start,
                        admission.trained.guard,
                        admission.timing.data_symbols,
                        admission.timing.symbol_samples,
                        4 + admission.trained.signal.symbols,
                    )?
                    .recover()?;
                    let (psdu, failed_codewords, first_failure) = if user.capacity.ldpc {
                        let SignalFields::Ofdma(signal) = &admission.trained.signal.signal else {
                            return Err(Error::UnsupportedFormat);
                        };
                        let recovered = super::super::ldpc::Decoder::for_ofdma(
                            &signal.common,
                            &user.user,
                            user.resource,
                            user.capacity,
                            admission.timing.data_symbols,
                        )?
                        .recover(&metrics, max_psdu, true)?;
                        (
                            recovered.psdu,
                            recovered.failed_codewords,
                            recovered.first_failure,
                        )
                    } else {
                        (
                            super::super::bcc::recover(
                                user.capacity,
                                admission.timing.data_symbols,
                                &metrics,
                                max_psdu,
                            )?,
                            0,
                            None,
                        )
                    };
                    Ok(Payload {
                        user_index: user.user_index,
                        resource: user.resource,
                        info: user.info,
                        psdu,
                        failed_codewords,
                        first_failure,
                    })
                })(),
            };
            users.push(recovered);
        }
        Ok(Recovered { admission, users })
    }
}
