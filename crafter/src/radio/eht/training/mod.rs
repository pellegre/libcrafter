//! EHT20 channel training recovered after integrity-checked signaling.

mod receiver;
#[cfg(test)]
mod tests;

pub(in crate::radio) use receiver::Receiver;

use super::sig::iq::Fields as SignalFields;
use crate::radio::ComplexSample;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    UnsupportedFormat,
    SpatialStreams(u8),
    Timing,
    Truncated { required: usize, available: usize },
    Samples,
}

/// One-stream EHT20 channel state positioned at the first DATA symbol.
pub(in crate::radio) struct Trained {
    pub signal: SignalFields,
    pub channel: [ComplexSample; 256],
    pub data_start: u64,
    pub guard: usize,
}
