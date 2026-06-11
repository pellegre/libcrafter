//! Border Gateway Protocol version 4 (BGP-4, RFC 4271) support.
//!
//! This module provides packet-layer construction and decoding for BGP-4
//! messages. Types and constants are added in subsequent steps; for now this is
//! an empty-but-compiling scaffold that mirrors the DNS/DHCP module layout.

mod constants;

pub mod attribute;
pub mod capability;
pub mod decode;
pub mod message;

// `constants` is empty until later steps populate it; allow the glob re-export
// now so the scaffold compiles warning-free.
#[allow(unused_imports)]
pub use constants::*;

// Minimal compiling stubs so the public type names resolve through
// `crafter::protocols` and `crafter::prelude` from this step onward. The NAMES
// are the public API contract and must stay stable; later steps replace these
// placeholders with the real BGP layer and message types.
//
// `#[allow(dead_code)]` keeps clippy quiet while the bodies are still empty.

/// BGP-4 message layer (RFC 4271). Placeholder stub; filled in a later step.
#[allow(dead_code)]
pub struct Bgp;

/// BGP OPEN message (RFC 4271 §4.2). Placeholder stub; filled in a later step.
#[allow(dead_code)]
pub struct BgpOpen;

/// BGP UPDATE message (RFC 4271 §4.3). Placeholder stub; filled in a later step.
#[allow(dead_code)]
pub struct BgpUpdate;

/// BGP NOTIFICATION message (RFC 4271 §4.5). Placeholder stub; filled in a later step.
#[allow(dead_code)]
pub struct BgpNotification;

/// BGP KEEPALIVE message (RFC 4271 §4.4). Placeholder stub; filled in a later step.
#[allow(dead_code)]
pub struct BgpKeepalive;

/// BGP ROUTE-REFRESH message (RFC 2918). Placeholder stub; filled in a later step.
#[allow(dead_code)]
pub struct BgpRouteRefresh;

#[cfg(test)]
mod tests {
    /// Confirms the BGP type names resolve through the public prelude path so
    /// generated tools can reach them via `use crafter::prelude::*;`.
    #[test]
    fn bgp_prelude_resolves() {
        let _ = core::mem::size_of::<crate::prelude::Bgp>();
    }
}
