use super::Error;
use crate::radio::{
    eht::{
        sig::iq::{Fields as SignalFields, SignalFields as SignalKind},
        EhtNonOfdmaUsers, EhtOfdmaUser, EhtResourceUnit,
    },
    sync::Acquisition,
};
use std::ops::Range;

pub(super) struct ResourceLayout {
    pub resource: EhtResourceUnit,
    pub users: Range<usize>,
    pub train: bool,
}

pub(super) struct Layout {
    pub ltf_start: usize,
    pub ltf_size: u8,
    pub ltf_symbols: usize,
    pub guard: usize,
    pub required: usize,
    pub data_start: u64,
    pub resources: Vec<ResourceLayout>,
}

impl Layout {
    pub fn new(signal: &SignalFields, acquisition: &Acquisition) -> Result<Self, Error> {
        if acquisition
            .signal_start
            .checked_sub(acquisition.preamble_start)
            != Some(320)
        {
            return Err(Error::Timing);
        }
        let (ltf_mode, ltf_symbols, resources) = match &signal.signal {
            SignalKind::NonOfdma(fields) => {
                let EhtNonOfdmaUsers::Single(user) = &fields.users else {
                    return Err(Error::UnsupportedFormat);
                };
                if user.space_time_streams != 1 {
                    return Err(Error::SpatialStreams(user.space_time_streams));
                }
                let resource = EhtResourceUnit::full_band(1).ok_or(Error::UnsupportedFormat)?;
                (
                    fields.common.ltf_mode,
                    fields.common.ltf_symbols,
                    vec![ResourceLayout {
                        resource,
                        users: 0..1,
                        train: true,
                    }],
                )
            }
            SignalKind::Ofdma(fields) => {
                let mut resources = Vec::with_capacity(fields.common.allocation.resources().len());
                let mut cursor = 0usize;
                let mut spatial_streams = None;
                for &resource in fields.common.allocation.resources() {
                    let end = cursor
                        .checked_add(usize::from(resource.user_count()))
                        .ok_or(Error::Timing)?;
                    let train = if resource.user_count() == 1 {
                        match fields.users.get(cursor) {
                            Some(Ok(EhtOfdmaUser::NonMu(user))) if user.space_time_streams == 1 => {
                                true
                            }
                            Some(Ok(EhtOfdmaUser::NonMu(user))) => {
                                spatial_streams.get_or_insert(user.space_time_streams);
                                false
                            }
                            _ => false,
                        }
                    } else {
                        false
                    };
                    resources.push(ResourceLayout {
                        resource,
                        users: cursor..end,
                        train,
                    });
                    cursor = end;
                }
                if cursor != fields.users.len() {
                    return Err(Error::UnsupportedFormat);
                }
                if !resources.iter().any(|resource| resource.train) {
                    return Err(spatial_streams
                        .map(Error::SpatialStreams)
                        .unwrap_or(Error::UnsupportedFormat));
                }
                (fields.common.ltf_mode, fields.common.ltf_symbols, resources)
            }
        };
        let ltf_size = ltf_mode.size();
        let guard = usize::from(ltf_mode.guard_interval_ns()) / 50;
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
        let ltf_symbols = usize::from(ltf_symbols);
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
            resources,
        })
    }
}
