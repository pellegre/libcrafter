//! DHCP protocol family organization.
//!
//! This module owns the versioned DHCP packet family. DHCPv4 lives in [`v4`],
//! and DHCPv6 will live in [`v6`] as RFC 9915 support is added.
//!
//! Packet behavior belongs in the versioned submodules so public imports are
//! explicit about the wire family.

pub mod v4;
pub mod v6;

pub use v4::*;
pub(crate) use v4::{append_dhcpv4_packet, is_dhcpv4_port_pair, looks_like_dhcpv4_payload};
