//! Routing Information Protocol (RIP) support.
//!
//! RIP is a distance-vector interior gateway protocol. This module provides
//! packet-layer construction and decoding for RIP messages, added
//! incrementally across the governing specifications:
//!
//! - RFC 1058 — RIP version 1.
//! - RFC 2453 — RIP version 2.
//! - RFC 2080 — RIPng for IPv6 (RIPng).
//! - RFC 2082 / RFC 4822 — RIP version 2 cryptographic authentication.
//! - RFC 2091 — triggered (demand) RIP for on-demand circuits.
//!
//! Types and constants are populated in later steps; this module starts as an
//! empty scaffold so the rest of the crate has a stable home to build against.

pub mod constants;
pub mod registry;

pub use constants::*;
