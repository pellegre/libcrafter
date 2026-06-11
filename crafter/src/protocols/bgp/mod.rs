//! Border Gateway Protocol version 4 (BGP-4, RFC 4271) support.
//!
//! This module provides packet-layer construction and decoding for BGP-4
//! messages. Types and constants are added in subsequent steps; for now the
//! [`Bgp`] layer implements the [`Layer`] trait with KEEPALIVE — the
//! header-only message (RFC 4271 §4.4) — and the OPEN builder as the first
//! working bodies.

mod constants;

pub mod attribute;
pub mod capability;
pub mod decode;
pub mod message;

// Re-export the populated BGP codepoint constants at the module root.
pub use constants::*;
pub use message::BgpOpen;

use crate::packet::{Layer, LayerContext};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::Result;

use self::message::BgpHeader;

/// Human-readable name for a BGP message Type code (IANA `bgp-parameters-1`).
///
/// Maps the `BGP_TYPE_*` constants to their canonical names for `summary()` and
/// inspection output. An unmodelled or reserved code resolves to `"UNKNOWN"` so
/// decoded messages stay inspectable rather than surfacing a bare number.
fn message_type_name(message_type: u8) -> &'static str {
    match message_type {
        BGP_TYPE_OPEN => "OPEN",
        BGP_TYPE_UPDATE => "UPDATE",
        BGP_TYPE_NOTIFICATION => "NOTIFICATION",
        BGP_TYPE_KEEPALIVE => "KEEPALIVE",
        BGP_TYPE_ROUTE_REFRESH => "ROUTE-REFRESH",
        _ => "UNKNOWN",
    }
}

/// The body of a BGP-4 message (RFC 4271 §4), following the shared 19-octet
/// header.
///
/// KEEPALIVE (RFC 4271 §4.4) is header-only, so its variant carries no fields.
/// OPEN carries its fixed RFC 4271 §4.2 fields and raw optional parameters for
/// now; typed capabilities are added in later steps. The remaining message
/// bodies — UPDATE, NOTIFICATION, ROUTE-REFRESH — are added in later steps. The
/// [`BgpBody::Unknown`] variant preserves the raw body of a message type the
/// builder/decoder does not model, keeping the bytes verbatim rather than
/// discarding them.
#[derive(Debug, Clone)]
pub(crate) enum BgpBody {
    /// OPEN message (RFC 4271 §4.2).
    Open(BgpOpen),
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
            BgpBody::Open(open) => open.body_len(),
            BgpBody::Keepalive => 0,
            BgpBody::Unknown { body, .. } => body.len(),
        }
    }

    /// Append this body's bytes to `out` (none for KEEPALIVE).
    fn write_body(&self, out: &mut Vec<u8>) {
        match self {
            BgpBody::Open(open) => open.write_body(out),
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
    /// Build an OPEN message (RFC 4271 §4.2).
    ///
    /// The header Type defaults to [`BGP_TYPE_OPEN`]. The body defaults to
    /// BGP-4 and empty optional parameters; other OPEN fields are filled through
    /// the chainable setters.
    pub fn open() -> Self {
        Self {
            header: BgpHeader::new(BGP_TYPE_OPEN),
            body: BgpBody::Open(BgpOpen::new()),
        }
    }

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

    /// Set the OPEN version field.
    pub fn version(mut self, version: u8) -> Self {
        if let BgpBody::Open(open) = &mut self.body {
            open.version.set_user(version);
        }
        self
    }

    /// Set the OPEN My Autonomous System field.
    pub fn my_as(mut self, my_as: u16) -> Self {
        if let BgpBody::Open(open) = &mut self.body {
            open.my_as.set_user(my_as);
        }
        self
    }

    /// Set the OPEN Hold Time field, in seconds.
    pub fn hold_time(mut self, hold_time: u16) -> Self {
        if let BgpBody::Open(open) = &mut self.body {
            open.hold_time.set_user(hold_time);
        }
        self
    }

    /// Set the OPEN BGP Identifier field.
    pub fn bgp_id(mut self, bgp_id: impl Into<std::net::Ipv4Addr>) -> Self {
        if let BgpBody::Open(open) = &mut self.body {
            open.bgp_id.set_user(bgp_id.into());
        }
        self
    }

    /// Force the OPEN optional-parameters length field.
    ///
    /// This preserves malformed-on-purpose OPEN messages whose declared
    /// optional-parameters length differs from the emitted parameter bytes.
    pub fn opt_params_len(mut self, opt_params_len: u8) -> Self {
        if let BgpBody::Open(open) = &mut self.body {
            open.opt_params_len.set_user(opt_params_len);
        }
        self
    }

    /// Build a `Bgp` layer from decoded wire fields.
    ///
    /// The header is reconstructed from the observed marker, length, and type
    /// (every field marked caller-supplied so re-compiling preserves the bytes
    /// exactly), and the typed `body` is the decoded message body. Used by the
    /// decode path so a round-trip through `decode_bgp_message` reproduces the
    /// original bytes.
    pub(crate) fn from_decoded_parts(
        marker: [u8; BGP_MARKER_LEN],
        length: u16,
        message_type: u8,
        body: BgpBody,
    ) -> Self {
        Self {
            header: BgpHeader::from_decoded_parts(marker, length, message_type),
            body,
        }
    }
}

impl Layer for Bgp {
    fn name(&self) -> &'static str {
        "BGP"
    }

    fn summary(&self) -> String {
        // The effective length over the current body — auto-filled from the body
        // size unless the caller pinned it. Dispatch on the body variant so later
        // message types extend this with their own fields.
        let len = self.header.effective_length(self.body.encoded_len());
        match &self.body {
            BgpBody::Open(_) => {
                format!("BGP {} len={len}", message_type_name(BGP_TYPE_OPEN))
            }
            BgpBody::Keepalive => {
                format!("BGP {} len={len}", message_type_name(BGP_TYPE_KEEPALIVE))
            }
            BgpBody::Unknown { type_code, .. } => {
                format!("BGP {} len={len}", message_type_name(*type_code))
            }
        }
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        // Report the marker presence (all-ones per RFC 4271 §4.1, or modified for
        // a deliberately malformed message), the effective on-wire length, and the
        // message type name so decoded messages are readable without log-fishing.
        let marker = if self.header.effective_marker() == [0xFF; BGP_MARKER_LEN] {
            "all-ones".to_string()
        } else {
            "modified".to_string()
        };
        let len = self.header.effective_length(self.body.encoded_len());
        vec![
            ("marker", marker),
            ("length", len.to_string()),
            (
                "type",
                message_type_name(self.header.effective_type()).to_string(),
            ),
        ]
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
    fn open_builder_stores_values() {
        let bgp = Bgp::open()
            .version(4)
            .my_as(65000)
            .hold_time(90)
            .bgp_id([192, 0, 2, 1]);

        assert_eq!(bgp.header.effective_type(), BGP_TYPE_OPEN);
        match bgp.body {
            BgpBody::Open(open) => {
                assert_eq!(open.version.value(), Some(&BGP_VERSION));
                assert!(open.version.is_user_set());
                assert_eq!(open.my_as.value(), Some(&65000));
                assert!(open.my_as.is_user_set());
                assert_eq!(open.hold_time.value(), Some(&90));
                assert!(open.hold_time.is_user_set());
                assert_eq!(
                    open.bgp_id.value(),
                    Some(&std::net::Ipv4Addr::new(192, 0, 2, 1))
                );
                assert!(open.bgp_id.is_user_set());
                assert_eq!(open.opt_params_len.value(), None);
                assert!(open.opt_params.is_empty());
                assert_eq!(open.body_len(), 10);
            }
            other => panic!("expected OPEN body, got {other:?}"),
        }
    }

    #[test]
    fn message_type_name_maps_known_and_unknown_codes() {
        assert_eq!(message_type_name(BGP_TYPE_OPEN), "OPEN");
        assert_eq!(message_type_name(BGP_TYPE_UPDATE), "UPDATE");
        assert_eq!(message_type_name(BGP_TYPE_NOTIFICATION), "NOTIFICATION");
        assert_eq!(message_type_name(BGP_TYPE_KEEPALIVE), "KEEPALIVE");
        assert_eq!(message_type_name(BGP_TYPE_ROUTE_REFRESH), "ROUTE-REFRESH");
        assert_eq!(message_type_name(0), "UNKNOWN");
        assert_eq!(message_type_name(99), "UNKNOWN");
    }

    #[test]
    fn keepalive_summary_reports_type_and_length() {
        let summary = Bgp::keepalive().summary();
        assert_eq!(summary, "BGP KEEPALIVE len=19");
    }

    #[test]
    fn keepalive_show_contains_keepalive() {
        let shown = Packet::from_layer(Bgp::keepalive()).show();

        // The inspection fields surface the marker presence, length, and the
        // message type name, so the rendered tree names the KEEPALIVE message.
        assert!(
            shown.contains("KEEPALIVE"),
            "show() should name the KEEPALIVE message, got:\n{shown}"
        );
        assert!(shown.contains("marker: all-ones"));
        assert!(shown.contains("length: 19"));
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

    #[test]
    fn minimal_open_compiles_with_auto_lengths() {
        let packet = Packet::from_layer(
            Bgp::open()
                .version(4)
                .my_as(65000)
                .hold_time(180)
                .bgp_id([192, 0, 2, 1]),
        );
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.len(), 29);
        assert_eq!(&bytes[..BGP_MARKER_LEN], &[0xFF; BGP_MARKER_LEN]);
        assert_eq!(&bytes[BGP_MARKER_LEN..BGP_MARKER_LEN + 2], &[0x00, 0x1d]);
        assert_eq!(bytes[BGP_MARKER_LEN + 2], BGP_TYPE_OPEN);
        assert_eq!(
            &bytes[BGP_HEADER_LEN..],
            &[4, 0xfd, 0xe8, 0x00, 0xb4, 192, 0, 2, 1, 0]
        );
        assert_eq!(bytes[BGP_HEADER_LEN + 9], 0);
    }

    #[test]
    fn open_optional_parameters_length_override_is_preserved() {
        let packet = Packet::from_layer(
            Bgp::open()
                .my_as(65000)
                .hold_time(180)
                .bgp_id([192, 0, 2, 1])
                .opt_params_len(7),
        );
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes[BGP_HEADER_LEN + 9], 7);
    }
}
