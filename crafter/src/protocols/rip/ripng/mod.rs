//! RIPng — RIP for IPv6 (RFC 2080).
//!
//! RIPng is the IPv6 variant of the Routing Information Protocol. It runs over
//! UDP port 521 and uses the link-local multicast group `ff02::9` for periodic
//! and triggered responses. Following the project's explicit v4/v6 layer-naming
//! convention (mirroring `Icmpv4`/`Icmpv6`), RIPng is modeled as its own
//! `Ripng` layer rather than being folded into the IPv4 `Rip` layer.
//!
//! Types and constants are populated in later steps; this module starts as an
//! empty scaffold so the rest of the crate has a stable home to build against.

pub mod constants;

pub use constants::*;
