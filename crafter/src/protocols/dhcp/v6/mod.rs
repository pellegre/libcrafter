//! DHCPv6 protocol-family home.
//!
//! This module is the target home for the DHCPv6 packet layer defined by
//! RFC 9915, "Dynamic Host Configuration Protocol for IPv6 (DHCPv6)", plus
//! public IANA DHCPv6 registry metadata and packet-data extensions.
//!
//! The module is intentionally a skeleton at this stage. It exposes no packet
//! builders, decoders, option types, or UDP bindings until later steps add
//! source-backed DHCPv6 wire behavior.

pub mod constants;

pub use constants::*;
