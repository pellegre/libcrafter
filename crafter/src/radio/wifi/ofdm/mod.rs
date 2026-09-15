//! Legacy OFDM receive, transmit, and shared waveform internals.

pub(in crate::radio) mod demod;
pub(in crate::radio) mod rx;
pub(in crate::radio) mod signal;
pub(in crate::radio) mod sync;
mod tx;
pub(in crate::radio) mod waveform;

pub use rx::{DecoderStats, LegacyOfdmDecoder};
pub use signal::SignalInfo;
pub use tx::{LegacyOfdmRate, LegacyOfdmTransmission, LegacyOfdmTxConfig, OfdmSignalFields};
