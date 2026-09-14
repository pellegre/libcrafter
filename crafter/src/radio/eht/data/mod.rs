//! EHT20 DATA timing, payload geometry, and IQ recovery.

mod bcc;
mod capacity;
mod iq;
mod ldpc;
mod receiver;
mod scrambler;
#[cfg(test)]
mod tests;
mod timing;

pub(in crate::radio) use capacity::Capacity;
pub(in crate::radio) use receiver::{Admission, Receiver};
pub(in crate::radio) use timing::Timing;

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
