//! IP protocol family organization.
//!
//! This module is the canonical home for version-neutral IP concepts and the
//! per-version IPv4 and IPv6 implementations. The intended layout mirrors the
//! ICMP family: shared code in [`shared`], IPv4-specific code in [`v4`], and
//! IPv6-specific code in [`v6`].
//!
//! During the module refactor, the existing public compatibility paths
//! [`crate::protocols::ipv4`] and [`crate::protocols::ipv6`] remain in place.
//! Later steps move behavior under this tree and leave those legacy modules as
//! re-export shims, so downstream imports keep resolving to the same public
//! types without introducing duplicate packet layer definitions.

pub mod shared;
pub mod v4;
pub mod v6;
