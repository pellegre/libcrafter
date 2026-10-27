//! IEEE 802.11 VHT20 signaling, layout, receive, and transmit.

mod config;
mod signal;

pub use config::{VhtCoding, VhtGuardInterval, VhtMcs, VhtTxConfig};
pub use signal::{
    VhtSignalAFields, VhtSignalAUsers, VhtSignalB20Content, VhtSignalB20Fields, VhtSignalError,
};

#[cfg(test)]
mod tests;
