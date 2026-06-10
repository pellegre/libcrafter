//! IKEv2 Vendor ID (V) payload, type 43 (RFC 7296 §3.12).
//!
//! The Vendor ID payload carries a vendor-defined constant that lets a peer
//! advertise an implementation, version, or capability another implementation
//! may recognize. The body that follows the 4-octet generic payload header
//! (emitted by [`write_generic_payload_header`]) is simply:
//!
//! ```text
//!  Vendor ID (variable)
//! ```
//!
//! (RFC 7296 §3.12). The Vendor ID is an opaque blob whose meaning is private to
//! the issuing vendor; an implementation that does not recognize it ignores it.
//!
//! This crate models the **wire form only** — the Vendor ID is opaque bytes
//! carried verbatim and no value is interpreted. The generic-header Payload Length
//! is auto-filled by `compile()` from the body length, while any caller-pinned
//! value (Next Payload, Payload Length, Critical) is emitted verbatim so
//! deliberately malformed Vendor ID payloads can be constructed for testing.

use crate::packet::{Layer, LayerContext};
use crate::protocols::ipsec::ikev2::payload::{
    write_generic_payload_header, IkePayload, PayloadHeaderFields, PayloadType,
};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::Result;

/// Layer name for the IKEv2 Vendor ID payload, registered in
/// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_VENDOR_ID_PAYLOAD_NAME: &str = "IkeVendorIdPayload";

/// IKEv2 Vendor ID (V) payload, type 43 (RFC 7296 §3.12).
///
/// Carries the opaque Vendor ID bytes. As a [`Layer`] it emits the 4-octet
/// generic payload header (via [`write_generic_payload_header`]) followed by the
/// body, which is the Vendor ID itself. The generic-header Next Payload, Critical
/// flag, and Payload Length are the shared overridable fields carried in
/// [`PayloadHeaderFields`].
///
/// The crate carries the Vendor ID verbatim and never interprets it; the caller
/// supplies those bytes.
#[derive(Debug, Clone)]
pub struct IkeVendorIdPayload {
    /// Vendor ID: the opaque vendor-defined constant (RFC 7296 §3.12). Carried
    /// verbatim; never interpreted.
    vendor_id: Vec<u8>,
    /// Shared generic-payload-header overrides (Next Payload, Length, Critical).
    header: PayloadHeaderFields,
}

impl IkeVendorIdPayload {
    /// A Vendor ID payload carrying the given Vendor ID bytes verbatim
    /// (RFC 7296 §3.12). The bytes are supplied by the caller; the crate does
    /// not interpret them.
    pub fn new(vendor_id: impl Into<Vec<u8>>) -> Self {
        Self {
            vendor_id: vendor_id.into(),
            header: PayloadHeaderFields::new(),
        }
    }

    /// Set the Vendor ID bytes (RFC 7296 §3.12), consuming-builder style. The
    /// bytes are carried verbatim.
    pub fn vendor_id(mut self, vendor_id: impl Into<Vec<u8>>) -> Self {
        self.vendor_id = vendor_id.into();
        self
    }

    /// Pin the generic-header Next Payload explicitly (RFC 7296 §3.2).
    pub fn next_payload(mut self, next_payload: u8) -> Self {
        self.header.set_next_payload(next_payload);
        self
    }

    /// Pin the generic-header Payload Length explicitly (RFC 7296 §3.2).
    pub fn payload_length(mut self, length: u16) -> Self {
        self.header.set_length(length);
        self
    }

    /// Set the Critical (C) flag for this payload explicitly (RFC 7296 §3.2).
    pub fn critical(mut self, critical: bool) -> Self {
        self.header.set_critical(critical);
        self
    }

    /// The Vendor ID bytes (RFC 7296 §3.12).
    pub fn vendor_id_bytes(&self) -> &[u8] {
        &self.vendor_id
    }
}

impl IkePayload for IkeVendorIdPayload {
    fn payload_type(&self) -> PayloadType {
        PayloadType::VendorId
    }

    fn payload_body(&self, _ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        Ok(self.vendor_id.clone())
    }

    fn next_payload_override(&self) -> Option<u8> {
        self.header.next_payload_override()
    }

    fn payload_length_override(&self) -> Option<u16> {
        self.header.payload_length_override()
    }

    fn critical(&self) -> bool {
        self.header.critical()
    }
}

impl Layer for IkeVendorIdPayload {
    fn name(&self) -> &'static str {
        IKE_VENDOR_ID_PAYLOAD_NAME
    }

    fn summary(&self) -> String {
        format!("IkeVendorIdPayload(vendor_id_len={})", self.vendor_id.len())
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![("vendor_id_len", self.vendor_id.len().to_string())]
    }

    fn encoded_len(&self) -> usize {
        super::GENERIC_PAYLOAD_HEADER_LEN + self.vendor_id.len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Emit the 4-octet generic payload header (auto Next Payload from the
        // following payload and auto Payload Length unless overridden), then the
        // Vendor ID body (the Vendor ID bytes verbatim).
        let body = self.payload_body(ctx)?;
        write_generic_payload_header(
            out,
            ctx,
            self.next_payload_override(),
            self.critical(),
            self.payload_length_override(),
            body.len(),
        )?;
        out.extend_from_slice(&body);
        Ok(())
    }

    impl_layer_object!(IkeVendorIdPayload);
}

impl_layer_div!(IkeVendorIdPayload);

// --- Local parse helper (Step 45 closes the full registry decode) -----------

/// Parse a Vendor ID payload **body** (the bytes after the 4-octet generic
/// header) per RFC 7296 §3.12. Local to this step; the registry-driven chain
/// decode lands in Step 45.
///
/// The whole body is the Vendor ID, carried verbatim (an empty body yields an
/// empty Vendor ID; both are valid wire shapes). A re-compile reproduces the
/// bytes exactly.
pub(crate) fn parse_vendor_id_payload_body(bytes: &[u8]) -> Result<IkeVendorIdPayload> {
    Ok(IkeVendorIdPayload::new(bytes.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LayerContext, Packet, Raw};
    use crate::protocols::ipsec::ikev2::payload::GENERIC_PAYLOAD_HEADER_LEN;

    /// Compile a standalone Vendor ID payload and return its full bytes (generic
    /// header + body), gathered through a one-layer packet.
    fn compile_payload(payload: IkeVendorIdPayload) -> Vec<u8> {
        let packet = Packet::from_layer(payload);
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    /// A representative Vendor ID payload carrying a fixed 16-octet MD5-style
    /// vendor constant (RFC 7296 §3.12). The bytes are arbitrary fixed test data
    /// carried verbatim.
    fn vendor_payload() -> IkeVendorIdPayload {
        IkeVendorIdPayload::new((0u8..16).collect::<Vec<u8>>())
    }

    #[test]
    fn vendor_payload_type_and_name() {
        let payload = vendor_payload();
        assert_eq!(payload.payload_type(), PayloadType::VendorId);
        // The VendorId payload-type codepoint (RFC 7296 §3.2 / §3.12).
        assert_eq!(PayloadType::VendorId.codepoint(), 43);
        // The layer name is registered for the chain next-payload derivation.
        assert_eq!(payload.name(), IKE_VENDOR_ID_PAYLOAD_NAME);
    }

    #[test]
    fn body_is_vendor_id_bytes() {
        // RFC 7296 §3.12: the body is exactly the Vendor ID.
        let payload = vendor_payload();
        let packet = Packet::from_layer(Raw::from_bytes([0u8; 0]));
        let ctx = LayerContext::new(&packet, 0);
        let body = payload.payload_body(&ctx).unwrap();
        assert_eq!(&body[..], &(0u8..16).collect::<Vec<u8>>()[..]);
        assert_eq!(
            payload.vendor_id_bytes(),
            &(0u8..16).collect::<Vec<u8>>()[..]
        );
    }

    #[test]
    fn payload_compiles_generic_header_then_body() {
        // The compiled payload is the 4-octet generic header (Next Payload 0
        // terminator, auto length) followed by the Vendor ID bytes.
        let payload = vendor_payload();
        let bytes = compile_payload(payload.clone());

        assert_eq!(bytes[0], 0); // Next Payload terminator.
        assert_eq!(bytes[1], 0); // Critical clear.
        let payload_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(payload_len, bytes.len());
        assert_eq!(payload_len, payload.encoded_len());
        assert_eq!(
            &bytes[GENERIC_PAYLOAD_HEADER_LEN..],
            &(0u8..16).collect::<Vec<u8>>()[..]
        );
    }

    #[test]
    fn payload_honors_generic_header_overrides() {
        // Caller-pinned Next Payload, Critical, and Payload Length survive.
        let payload = vendor_payload()
            .next_payload(40)
            .critical(true)
            .payload_length(0xBEEF);
        let bytes = compile_payload(payload);
        assert_eq!(bytes[0], 40);
        assert_eq!(bytes[1], 0x80); // Critical bit set.
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0xBEEF);
    }

    #[test]
    fn chain_next_payload_points_at_vendor_id() {
        // A Vendor ID payload following another layer derives the preceding
        // header's Next Payload through payload_type_for_layer_name (registered
        // this step) as the Vendor ID codepoint (43).
        use crate::protocols::ipsec::ikev2::payload::{
            following_next_payload, payload_type_for_layer_name, PAYLOAD_VENDOR_ID,
        };
        assert_eq!(
            payload_type_for_layer_name(IKE_VENDOR_ID_PAYLOAD_NAME),
            Some(PayloadType::VendorId)
        );
        let packet: Packet = Packet::from_layer(Raw::from_bytes([0u8; 0])) / vendor_payload();
        let ctx = LayerContext::new(&packet, 0);
        assert_eq!(following_next_payload(&ctx), PAYLOAD_VENDOR_ID);
    }

    #[test]
    fn round_trip_preserves_vendor_id() {
        // Build a Vendor ID payload with fixed bytes, compile to wire, parse the
        // body back, and confirm it round-trips byte-for-byte (Step 45 closes the
        // registry decode; this is the local parse helper).
        let payload = vendor_payload();
        let bytes = compile_payload(payload.clone());

        let parsed = parse_vendor_id_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(
            parsed.vendor_id_bytes(),
            &(0u8..16).collect::<Vec<u8>>()[..]
        );
        let recompiled = compile_payload(parsed);
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn empty_vendor_id_round_trips() {
        // An empty Vendor ID is a valid wire shape: the body is empty and the
        // payload is just the 4-octet generic header.
        let payload = IkeVendorIdPayload::new(Vec::<u8>::new());
        let bytes = compile_payload(payload.clone());
        assert_eq!(bytes.len(), GENERIC_PAYLOAD_HEADER_LEN);
        let parsed = parse_vendor_id_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert!(parsed.vendor_id_bytes().is_empty());
        assert_eq!(compile_payload(parsed), bytes);
    }
}
