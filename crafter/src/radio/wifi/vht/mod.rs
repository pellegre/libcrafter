//! IEEE 802.11 VHT20 signaling, layout, receive, and transmit.

mod config;
mod layout;
pub(in crate::radio) mod rx;
mod signal;
mod tx;

pub use tx::{VhtSignalBits, VhtTransmission};

pub use config::{VhtCoding, VhtGuardInterval, VhtMcs, VhtTxConfig};
pub use signal::{
    VhtSignalAFields, VhtSignalAUsers, VhtSignalB20Content, VhtSignalB20Fields, VhtSignalError,
};

#[cfg(test)]
mod tests;

#[cfg(all(test, not(crafter_packaged)))]
mod vectors;
