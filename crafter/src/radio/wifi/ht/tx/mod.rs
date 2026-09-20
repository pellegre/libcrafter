//! Typed, bounded single-stream HT20 transmission.

mod config;
mod encoder;
mod waveform;

pub use config::{HtCoding, HtFormat, HtGuardInterval, HtMcs, HtTxConfig};
pub use encoder::{HtSignalBits, HtTransmission};

#[cfg(all(test, not(crafter_packaged)))]
mod tests;
