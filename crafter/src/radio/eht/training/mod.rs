//! EHT20 channel training recovered after integrity-checked signaling.

mod layout;
mod receiver;
pub(in crate::radio::eht) mod resource;
#[cfg(test)]
mod tests;

pub(in crate::radio) use receiver::Receiver;

use super::sig::iq::Fields as SignalFields;
use crate::radio::{eht::EhtResourceUnit, ComplexSample};
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    UnsupportedFormat,
    SpatialStreams(u8),
    Timing,
    Truncated { required: usize, available: usize },
    Samples,
}

/// Channel state for one frequency-ordered RU or MRU.
pub(in crate::radio) struct TrainedResource {
    pub resource: EhtResourceUnit,
    pub users: Range<usize>,
    pub channel: Option<[ComplexSample; 256]>,
}

/// EHT20 channel state positioned at the first DATA symbol.
pub(in crate::radio) struct Trained {
    pub signal: SignalFields,
    pub resources: Vec<TrainedResource>,
    pub data_start: u64,
    pub guard: usize,
}
