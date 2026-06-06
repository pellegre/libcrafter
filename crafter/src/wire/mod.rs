//! Packet-shaped wire I/O abstractions.
//!
//! This module owns the source, writer, transform, sniffer, transmitter, and
//! backend contracts for packet I/O. Concrete behavior is added in later
//! modules while this skeleton reserves the crate-level export surface.

#![forbid(unsafe_code)]

pub mod backend;
mod error;
pub mod packet_wire;
pub mod record;
pub mod sniffer;
pub mod source;
pub mod transform;
pub mod transmitter;
pub mod writer;

pub use error::{Result, WireError};
