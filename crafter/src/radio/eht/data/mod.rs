//! EHT20 DATA timing, payload geometry, and IQ recovery.

pub(in crate::radio::eht) mod bcc;
mod capacity;
pub(in crate::radio::eht) mod ldpc;
mod non_ofdma;
mod ofdma;
mod receiver;
pub(in crate::radio::eht) mod resource;
mod scrambler;
mod timing;

pub(in crate::radio) use capacity::Capacity;
pub(in crate::radio) use receiver::{Admission, Receiver, Recovered};
pub(super) use timing::Timing;

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
    User,
}
