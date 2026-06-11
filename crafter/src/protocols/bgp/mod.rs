//! Border Gateway Protocol version 4 (BGP-4, RFC 4271) support.
//!
//! This module provides packet-layer construction and decoding for BGP-4
//! messages. Types and constants are added in subsequent steps; for now the
//! [`Bgp`] layer implements the [`Layer`] trait with KEEPALIVE — the
//! header-only message (RFC 4271 §4.4) — as the first working body.

mod constants;

pub mod attribute;
pub mod capability;
pub mod decode;
pub mod message;

// Re-export the populated BGP codepoint constants at the module root.
pub use constants::*;

use crate::packet::{Layer, LayerContext};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::Result;

use self::message::BgpHeader;

/// The body of a BGP-4 message (RFC 4271 §4), following the shared 19-octet
/// header.
///
/// KEEPALIVE (RFC 4271 §4.4) is header-only, so its variant carries no fields.
/// The remaining message bodies — OPEN, UPDATE, NOTIFICATION, ROUTE-REFRESH —
/// are added in later steps. The [`BgpBody::Unknown`] variant preserves the raw
/// body of a message type the builder/decoder does not model, keeping the
/// bytes verbatim rather than discarding them.
#[derive(Debug, Clone)]
pub(crate) enum BgpBody {
    /// KEEPALIVE message (RFC 4271 §4.4): the header alone, no body.
    Keepalive,
    /// A message body the layer does not (yet) model, preserved verbatim.
    #[allow(dead_code)]
    Unknown {
        /// The BGP message Type code this body belongs to.
        type_code: u8,
        /// The raw body bytes following the 19-octet header.
        body: Vec<u8>,
    },
}

impl BgpBody {
    /// The on-wire length of this body, in octets (the bytes after the header).
    fn encoded_len(&self) -> usize {
        match self {
            BgpBody::Keepalive => 0,
            BgpBody::Unknown { body, .. } => body.len(),
        }
    }

    /// Append this body's bytes to `out` (none for KEEPALIVE).
    fn write_body(&self, out: &mut Vec<u8>) {
        match self {
            BgpBody::Keepalive => {}
            BgpBody::Unknown { body, .. } => out.extend_from_slice(body),
        }
    }
}

/// BGP-4 message layer (RFC 4271).
///
/// A `Bgp` layer is the shared 19-octet message header ([`BgpHeader`]) followed
/// by a typed [`BgpBody`]. `compile()` writes the header — auto-filling the
/// Length field from the body size unless the caller pinned it — then the body
/// bytes. KEEPALIVE (RFC 4271 §4.4) is header-only, so `Bgp::keepalive()`
/// compiles to exactly the 19-octet header.
#[derive(Debug, Clone)]
pub struct Bgp {
    /// The shared 19-octet BGP message header (Marker, Length, Type).
    header: BgpHeader,
    /// The typed message body following the header.
    body: BgpBody,
}

impl Bgp {
    /// Build a KEEPALIVE message (RFC 4271 §4.4).
    ///
    /// The header Type defaults to [`BGP_TYPE_KEEPALIVE`] and the Length is left
    /// unset so `compile()` fills it with the 19-octet header length (KEEPALIVE
    /// has no body). Composing `Packet::from_layer(Bgp::keepalive())` therefore
    /// compiles to exactly 19 octets.
    pub fn keepalive() -> Self {
        Self {
            header: BgpHeader::new(BGP_TYPE_KEEPALIVE),
            body: BgpBody::Keepalive,
        }
    }
}

impl Layer for Bgp {
    fn name(&self) -> &'static str {
        "BGP"
    }

    fn encoded_len(&self) -> usize {
        BGP_HEADER_LEN + self.body.encoded_len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // The header Length auto-fills from the body size unless the caller
        // pinned it; the body bytes (none for KEEPALIVE) follow the 19-octet
        // header.
        let body_len = self.body.encoded_len();
        self.header.write_header(body_len, out);
        self.body.write_body(out);
        Ok(())
    }

    impl_layer_object!(Bgp);
}

impl_layer_div!(Bgp);

// Minimal compiling stubs for the remaining message type names so the public
// API contract stays stable; later steps replace these placeholders with the
// real message types. `#[allow(dead_code)]` keeps clippy quiet while the bodies
// are still empty.

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
    use super::*;
    use crate::packet::Packet;

    /// Confirms the BGP type names resolve through the public prelude path so
    /// generated tools can reach them via `use crafter::prelude::*;`.
    #[test]
    fn bgp_prelude_resolves() {
        let _ = core::mem::size_of::<crate::prelude::Bgp>();
    }

    #[test]
    fn keepalive_defaults_to_type_four() {
        let bgp = Bgp::keepalive();
        assert_eq!(bgp.name(), "BGP");
        assert!(matches!(bgp.body, BgpBody::Keepalive));
        assert_eq!(bgp.encoded_len(), BGP_HEADER_LEN);
    }

    #[test]
    fn keepalive_compiles_to_nineteen_bytes() {
        let packet = Packet::from_layer(Bgp::keepalive());
        let bytes = packet.compile().unwrap();

        // KEEPALIVE is header-only: 16-octet marker (all ones), 2-octet length
        // (19, big-endian), 1-octet type (4). RFC 4271 §4.4.
        assert_eq!(bytes.len(), 19);
        assert_eq!(&bytes[..BGP_MARKER_LEN], &[0xFF; BGP_MARKER_LEN]);
        assert_eq!(
            &bytes[BGP_MARKER_LEN..BGP_MARKER_LEN + 2],
            &(BGP_HEADER_LEN as u16).to_be_bytes()
        );
        assert_eq!(bytes[BGP_MARKER_LEN + 2], BGP_TYPE_KEEPALIVE);
    }
}
