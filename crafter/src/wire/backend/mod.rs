//! Packet wire backend adapters.

#![forbid(unsafe_code)]

pub mod pcap;
pub mod raw_socket;

#[cfg(feature = "whad")]
pub mod whad;
