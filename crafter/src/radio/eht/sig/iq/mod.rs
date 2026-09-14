//! EHT-SIG recovery from 20 Msps IQ.

mod receiver;
#[cfg(test)]
mod tests;

pub(in crate::radio) use receiver::Receiver;

use super::{EhtNonOfdmaSignal, EhtOfdmaSignal, EhtSigError};
use crate::radio::EhtUsigFields;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    Prefix,
    UnsupportedFormat,
    Bandwidth(u8),
    SymbolCount { required: usize, advertised: u8 },
    Truncated { required: usize, available: usize },
    Samples,
    Overflow,
    Coded(super::coded::Error),
    Signal(EhtSigError),
}

/// Format-specific EHT-SIG content recovered directly from IQ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::radio) enum SignalFields {
    NonOfdma(EhtNonOfdmaSignal),
    Ofdma(EhtOfdmaSignal),
}

/// Integrity-checked EHT signaling recovered directly from IQ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::radio) struct Fields {
    pub usig: EhtUsigFields,
    pub signal: SignalFields,
    pub legacy_length: usize,
    pub symbols: usize,
    pub end_sample: u64,
}
