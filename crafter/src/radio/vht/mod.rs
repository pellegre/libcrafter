//! VHT20 signaling and DATA recovery.

pub(in crate::radio) mod data;
mod signal;

pub use signal::{
    VhtSignalAError, VhtSignalAFields, VhtSignalAUsers, VhtSignalB20Content, VhtSignalB20Error,
    VhtSignalB20Fields,
};
