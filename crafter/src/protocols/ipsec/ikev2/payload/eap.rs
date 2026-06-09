//! IKEv2 Extensible Authentication (EAP) payload, type 48 (RFC 7296 §3.16).
//!
//! The EAP payload allows IKE SAs to be authenticated using one of the methods
//! defined in EAP (RFC 3748). The body that follows the 4-octet generic payload
//! header (emitted by [`write_generic_payload_header`]) is a complete EAP message:
//!
//! ```text
//!  EAP Message (variable): Code (1) | Identifier (1) | Length (2) | Data (...)
//! ```
//!
//! (RFC 7296 §3.16; the EAP message format is RFC 3748 §4). The crate carries the
//! whole EAP message as opaque bytes — it does **not** run an EAP method, parse
//! the EAP Code/Identifier/Length, or validate the message; the caller supplies
//! the encoded EAP message.
//!
//! The generic-header Payload Length is auto-filled by `compile()` from the body
//! length, while any caller-pinned value (Next Payload, Payload Length, Critical)
//! is emitted verbatim so deliberately malformed EAP payloads can be constructed
//! for testing.

use crate::packet::{Layer, LayerContext};
use crate::protocols::ipsec::ikev2::payload::{
    write_generic_payload_header, IkePayload, PayloadHeaderFields, PayloadType,
};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::Result;

/// Layer name for the IKEv2 EAP payload, registered in
/// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_EAP_PAYLOAD_NAME: &str = "IkeEapPayload";

/// IKEv2 Extensible Authentication (EAP) payload, type 48 (RFC 7296 §3.16).
///
/// Carries a complete EAP message (RFC 3748) as opaque bytes. As a [`Layer`] it
/// emits the 4-octet generic payload header (via [`write_generic_payload_header`])
/// followed by the body, which is the EAP message itself. The generic-header Next
/// Payload, Critical flag, and Payload Length are the shared overridable fields
/// carried in [`PayloadHeaderFields`].
///
/// The crate carries the EAP message verbatim and never runs an EAP method or
/// parses the message; the caller supplies those bytes.
#[derive(Debug, Clone)]
pub struct IkeEapPayload {
    /// EAP Message: a complete EAP packet (RFC 3748 §4), carried verbatim; never
    /// parsed.
    eap_message: Vec<u8>,
    /// Shared generic-payload-header overrides (Next Payload, Length, Critical).
    header: PayloadHeaderFields,
}

impl IkeEapPayload {
    /// An EAP payload carrying the given EAP message bytes verbatim
    /// (RFC 7296 §3.16). The bytes are supplied by the caller; the crate does
    /// not run an EAP method or parse the message.
    pub fn new(eap_message: impl Into<Vec<u8>>) -> Self {
        Self {
            eap_message: eap_message.into(),
            header: PayloadHeaderFields::new(),
        }
    }

    /// Set the EAP message bytes (RFC 7296 §3.16), consuming-builder style. The
    /// bytes are carried verbatim.
    pub fn eap_message(mut self, eap_message: impl Into<Vec<u8>>) -> Self {
        self.eap_message = eap_message.into();
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

    /// The EAP message bytes (RFC 7296 §3.16).
    pub fn eap_message_bytes(&self) -> &[u8] {
        &self.eap_message
    }
}

impl IkePayload for IkeEapPayload {
    fn payload_type(&self) -> PayloadType {
        PayloadType::ExtensibleAuthentication
    }

    fn payload_body(&self, _ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        Ok(self.eap_message.clone())
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

impl Layer for IkeEapPayload {
    fn name(&self) -> &'static str {
        IKE_EAP_PAYLOAD_NAME
    }

    fn summary(&self) -> String {
        format!("IkeEapPayload(eap_message_len={})", self.eap_message.len())
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![("eap_message_len", self.eap_message.len().to_string())]
    }

    fn encoded_len(&self) -> usize {
        super::GENERIC_PAYLOAD_HEADER_LEN + self.eap_message.len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Emit the 4-octet generic payload header (auto Next Payload from the
        // following payload and auto Payload Length unless overridden), then the
        // EAP body (the EAP message bytes verbatim).
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

    impl_layer_object!(IkeEapPayload);
}

impl_layer_div!(IkeEapPayload);

// --- Local parse helper (Step 45 closes the full registry decode) -----------

/// Parse an EAP payload **body** (the bytes after the 4-octet generic header)
/// per RFC 7296 §3.16. Local to this step; the registry-driven chain decode
/// lands in Step 45.
///
/// The whole body is the EAP message, carried verbatim. A re-compile reproduces
/// the bytes exactly.
#[cfg(test)]
fn parse_eap_payload_body(bytes: &[u8]) -> Result<IkeEapPayload> {
    Ok(IkeEapPayload::new(bytes.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LayerContext, Packet, Raw};
    use crate::protocols::ipsec::ikev2::payload::GENERIC_PAYLOAD_HEADER_LEN;

    /// Compile a standalone EAP payload and return its full bytes (generic header
    /// + body), gathered through a one-layer packet.
    fn compile_payload(payload: IkeEapPayload) -> Vec<u8> {
        let packet = Packet::from_layer(payload);
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    /// A representative EAP-Request/Identity message (RFC 3748 §4, §5.1): Code 1
    /// (Request), Identifier 0x2A, Length 0x0005, Type 1 (Identity). The bytes
    /// are carried verbatim; the crate does not parse them.
    fn eap_request_identity() -> IkeEapPayload {
        IkeEapPayload::new(vec![0x01u8, 0x2A, 0x00, 0x05, 0x01])
    }

    #[test]
    fn eap_payload_type_and_name() {
        let payload = eap_request_identity();
        assert_eq!(
            payload.payload_type(),
            PayloadType::ExtensibleAuthentication
        );
        // The EAP payload-type codepoint (RFC 7296 §3.2 / §3.16).
        assert_eq!(PayloadType::ExtensibleAuthentication.codepoint(), 48);
        // The layer name is registered for the chain next-payload derivation.
        assert_eq!(payload.name(), IKE_EAP_PAYLOAD_NAME);
    }

    #[test]
    fn body_is_eap_message_bytes() {
        // RFC 7296 §3.16: the body is exactly the EAP message.
        let payload = eap_request_identity();
        assert_eq!(payload.eap_message_bytes(), &[0x01, 0x2A, 0x00, 0x05, 0x01]);
    }

    #[test]
    fn payload_compiles_generic_header_then_body() {
        // The compiled payload is the 4-octet generic header (Next Payload 0
        // terminator, auto length) followed by the EAP message bytes.
        let payload = eap_request_identity();
        let bytes = compile_payload(payload.clone());

        assert_eq!(bytes[0], 0); // Next Payload terminator.
        assert_eq!(bytes[1], 0); // Critical clear.
        let payload_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(payload_len, bytes.len());
        assert_eq!(payload_len, payload.encoded_len());
        assert_eq!(
            &bytes[GENERIC_PAYLOAD_HEADER_LEN..],
            &[0x01, 0x2A, 0x00, 0x05, 0x01]
        );
    }

    #[test]
    fn payload_honors_generic_header_overrides() {
        // Caller-pinned Next Payload, Critical, and Payload Length survive.
        let payload = eap_request_identity()
            .next_payload(40)
            .critical(true)
            .payload_length(0xBEEF);
        let bytes = compile_payload(payload);
        assert_eq!(bytes[0], 40);
        assert_eq!(bytes[1], 0x80); // Critical bit set.
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0xBEEF);
    }

    #[test]
    fn chain_next_payload_points_at_eap() {
        // An EAP payload following another layer derives the preceding header's
        // Next Payload through payload_type_for_layer_name (registered this step)
        // as the EAP codepoint (48).
        use crate::protocols::ipsec::ikev2::payload::{
            following_next_payload, payload_type_for_layer_name, PAYLOAD_EAP,
        };
        assert_eq!(
            payload_type_for_layer_name(IKE_EAP_PAYLOAD_NAME),
            Some(PayloadType::ExtensibleAuthentication)
        );
        let packet: Packet = Packet::from_layer(Raw::from_bytes([0u8; 0])) / eap_request_identity();
        let ctx = LayerContext::new(&packet, 0);
        assert_eq!(following_next_payload(&ctx), PAYLOAD_EAP);
    }

    #[test]
    fn round_trip_preserves_eap_message() {
        // Build an EAP payload with a fixed message, compile to wire, parse the
        // body back, and confirm it round-trips byte-for-byte (Step 45 closes the
        // registry decode; this is the local parse helper).
        let payload = eap_request_identity();
        let bytes = compile_payload(payload.clone());

        let parsed = parse_eap_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(parsed.eap_message_bytes(), &[0x01, 0x2A, 0x00, 0x05, 0x01]);
        let recompiled = compile_payload(parsed);
        assert_eq!(recompiled, bytes);
    }
}
