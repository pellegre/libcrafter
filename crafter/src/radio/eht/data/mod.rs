//! EHT20 DATA timing, payload geometry, and IQ recovery.

mod non_ofdma;
mod scrambler;

pub(in crate::radio) use non_ofdma::{Admission, Capacity, Receiver};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    UnsupportedFormat,
    Length,
    Modulation(u8),
    Coding,
    Padding,
    Duration,
    Overflow,
    Training,
    FrameLimit,
    SampleLimit,
    Fec,
    Ldpc(crate::radio::ldpc::rate::Error),
    Service,
    Truncated { required: usize, available: usize },
    Samples,
}
