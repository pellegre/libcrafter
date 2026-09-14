//! VHT-SIG-A and VHT-SIG-B field decoding.

mod a;
mod b;

pub use a::{VhtSignalAError, VhtSignalAFields, VhtSignalAUsers};
pub use b::{VhtSignalB20Content, VhtSignalB20Error, VhtSignalB20Fields};
