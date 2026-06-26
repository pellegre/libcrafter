//! DHCP protocol family organization.
//!
//! This module owns the versioned DHCP packet family. DHCPv4 lives in [`v4`],
//! and DHCPv6 will live in [`v6`] as RFC 9915 support is added.
//!
//! Packet behavior belongs in the versioned submodules so public imports are
//! explicit about the wire family.

pub mod v4;
pub mod v6;

pub(crate) use v4::{append_dhcp_packet, is_dhcp_port_pair, looks_like_dhcp_payload};
pub use v4::*;
