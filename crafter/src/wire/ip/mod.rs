//! IP fragmentation and defragmentation packet-stream transforms.
//!
//! This module is rooted in the existing wire transform pipeline. `IpDefrag`
//! will receive fragment records and emit reassembled packet records once a
//! datagram is complete. `IpFragment` will split one packet-shaped record into
//! packet-shaped fragments for transmission. The initial step keeps both
//! transforms as explicit pass-through stages while the receive and transmit
//! behavior is added in later implementation steps.

mod config;
mod defrag;
mod fragmentation;
mod metadata;
mod range;

#[cfg(test)]
mod tests;

pub use config::{IpDefragConfig, IpFragmentConfig};
pub use defrag::IpDefrag;
pub use fragmentation::IpFragment;
pub use metadata::{
    IpDefragEvictionReason, IpDefragMetadata, IpDefragOverlapStatus, IpFragmentFamily,
    IpFragmentMetadata, IpFragmentRange, IpFragmentReason,
};
