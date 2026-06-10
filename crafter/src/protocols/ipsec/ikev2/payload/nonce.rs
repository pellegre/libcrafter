//! IKEv2 Nonce payload (Ni, Nr), type 40 (RFC 7296 §3.9).
//!
//! The Nonce payload carries random data used to guarantee liveness during an
//! exchange and to protect against replay attacks. The body that follows the
//! 4-octet generic payload header (emitted by [`write_generic_payload_header`])
//! is simply the nonce data:
//!
//! ```text
//!  Nonce Data (variable)
//! ```
//!
//! (RFC 7296 §3.9). RFC 7296 §3.9 requires the nonce to be between 16 and 256
//! octets in length (and at least half the key size of the negotiated PRF).
//! This crate models the **wire form only**: the nonce is opaque bytes and the
//! RFC length range is **not** enforced — a caller may build a Nonce payload of
//! any length so that deliberately malformed payloads can be constructed for
//! testing. The Nonce Data is never silently clamped.
//!
//! The generic-header Payload Length is auto-filled by `compile()` from the body
//! length and any caller-pinned value (Next Payload, Payload Length, Critical) is
//! emitted verbatim.

use crate::packet::{Layer, LayerContext};
use crate::protocols::ipsec::ikev2::payload::{
    write_generic_payload_header, IkePayload, PayloadHeaderFields, PayloadType,
};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::Result;

/// Layer name for the IKEv2 Nonce payload, registered in
/// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_NONCE_PAYLOAD_NAME: &str = "IkeNoncePayload";

/// Minimum Nonce Data length per RFC 7296 §3.9 (16 octets). Provided for
/// reference and well-formedness checks; **not** enforced by this crate, which
/// allows any length so malformed Nonce payloads can be constructed for testing.
pub const NONCE_MIN_LEN: usize = 16;

/// Maximum Nonce Data length per RFC 7296 §3.9 (256 octets). Provided for
/// reference; **not** enforced by this crate (see [`NONCE_MIN_LEN`]).
pub const NONCE_MAX_LEN: usize = 256;

/// IKEv2 Nonce payload (Ni, Nr), type 40 (RFC 7296 §3.9).
///
/// Carries the opaque nonce data. As a [`Layer`] it emits the 4-octet generic
/// payload header (via [`write_generic_payload_header`]) followed by the nonce
/// bytes. The generic-header Next Payload, Critical flag, and Payload Length are
/// the shared overridable fields carried in [`PayloadHeaderFields`].
///
/// RFC 7296 §3.9 specifies a nonce length of 16–256 octets ([`NONCE_MIN_LEN`]..=
/// [`NONCE_MAX_LEN`]); this type does **not** enforce that range so that
/// deliberately malformed payloads can be constructed for testing.
#[derive(Debug, Clone)]
pub struct IkeNoncePayload {
    /// Nonce Data: the opaque random value (RFC 7296 §3.9).
    nonce: Vec<u8>,
    /// Shared generic-payload-header overrides (Next Payload, Length, Critical).
    header: PayloadHeaderFields,
}

impl IkeNoncePayload {
    /// A Nonce payload carrying the given nonce data bytes (RFC 7296 §3.9).
    ///
    /// The bytes are stored verbatim and not range-checked, so a length outside
    /// the RFC 7296 §3.9 16–256-octet window can be built for malformed testing.
    pub fn new(nonce: impl Into<Vec<u8>>) -> Self {
        Self {
            nonce: nonce.into(),
            header: PayloadHeaderFields::new(),
        }
    }

    /// Set the Nonce Data bytes (RFC 7296 §3.9), consuming-builder style.
    pub fn nonce(mut self, nonce: impl Into<Vec<u8>>) -> Self {
        self.nonce = nonce.into();
        self
    }

    /// The Nonce Data bytes (RFC 7296 §3.9).
    pub fn nonce_bytes(&self) -> &[u8] {
        &self.nonce
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

    /// The Nonce body (everything after the 4-octet generic header), per
    /// RFC 7296 §3.9: the nonce data with no additional framing.
    fn nonce_body(&self) -> Vec<u8> {
        self.nonce.clone()
    }
}

impl IkePayload for IkeNoncePayload {
    fn payload_type(&self) -> PayloadType {
        PayloadType::Nonce
    }

    fn payload_body(&self, _ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        Ok(self.nonce_body())
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

impl Layer for IkeNoncePayload {
    fn name(&self) -> &'static str {
        IKE_NONCE_PAYLOAD_NAME
    }

    fn summary(&self) -> String {
        format!("IkeNoncePayload(nonce_len={})", self.nonce.len())
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![("nonce_len", self.nonce.len().to_string())]
    }

    fn encoded_len(&self) -> usize {
        super::GENERIC_PAYLOAD_HEADER_LEN + self.nonce.len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Emit the 4-octet generic payload header (auto Next Payload from the
        // following payload and auto Payload Length unless overridden), then the
        // nonce body (the nonce data, no additional framing).
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

    impl_layer_object!(IkeNoncePayload);
}

impl_layer_div!(IkeNoncePayload);

// --- Local parse helper (Step 45 closes the full registry decode) -----------

/// Parse a Nonce payload **body** (the bytes after the 4-octet generic header)
/// per RFC 7296 §3.9. The whole body is the nonce data. Local to this step; the
/// registry-driven chain decode lands in Step 45.
///
/// No length range check is applied: a body outside the RFC 7296 §3.9
/// 16–256-octet window is accepted verbatim so malformed wire bytes round-trip.
pub(crate) fn parse_nonce_payload_body(bytes: &[u8]) -> Result<IkeNoncePayload> {
    Ok(IkeNoncePayload::new(bytes.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LayerContext, Packet, Raw};
    use crate::protocols::ipsec::ikev2::payload::GENERIC_PAYLOAD_HEADER_LEN;

    /// Compile a standalone Nonce payload and return its full bytes (generic
    /// header + body), gathered through a one-layer packet.
    fn compile_payload(payload: IkeNoncePayload) -> Vec<u8> {
        let packet = Packet::from_layer(payload);
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    /// A representative Nonce payload: a fixed 16-octet nonce (the RFC 7296 §3.9
    /// minimum length).
    fn sample_nonce() -> Vec<u8> {
        (0u8..16).map(|i| 0xA0 ^ i).collect()
    }

    fn sample_payload() -> IkeNoncePayload {
        IkeNoncePayload::new(sample_nonce())
    }

    #[test]
    fn nonce_constants_match_rfc() {
        // RFC 7296 §3.9: nonce data is 16–256 octets (range documented, not
        // enforced by this crate).
        assert_eq!(NONCE_MIN_LEN, 16);
        assert_eq!(NONCE_MAX_LEN, 256);
    }

    #[test]
    fn payload_type_is_nonce() {
        assert_eq!(sample_payload().payload_type(), PayloadType::Nonce);
        // The layer name is registered for the chain next-payload derivation.
        assert_eq!(sample_payload().name(), IKE_NONCE_PAYLOAD_NAME);
    }

    #[test]
    fn body_is_the_nonce_data() {
        // RFC 7296 §3.9: the body is exactly the nonce data, no framing.
        let payload = sample_payload();
        let body = payload.nonce_body();
        assert_eq!(body, sample_nonce());
        assert_eq!(body.len(), 16);
    }

    #[test]
    fn payload_compiles_generic_header_then_body() {
        // The compiled payload is the 4-octet generic header (Next Payload 0
        // terminator, auto length) followed by the nonce body.
        let payload = sample_payload();
        let bytes = compile_payload(payload.clone());

        // Generic header: Next Payload terminator, Critical clear.
        assert_eq!(bytes[0], 0);
        assert_eq!(bytes[1], 0);
        let payload_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(payload_len, bytes.len());
        assert_eq!(payload_len, payload.encoded_len());
        // The body after the generic header is the nonce verbatim.
        assert_eq!(&bytes[GENERIC_PAYLOAD_HEADER_LEN..], &sample_nonce()[..]);
    }

    #[test]
    fn payload_honors_generic_header_overrides() {
        // Caller-pinned Next Payload, Critical, and Payload Length survive,
        // including a length that disagrees with the body (malformed).
        let payload = sample_payload()
            .next_payload(34)
            .critical(true)
            .payload_length(0xBEEF);
        let bytes = compile_payload(payload);
        assert_eq!(bytes[0], 34);
        assert_eq!(bytes[1], 0x80); // Critical bit set.
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0xBEEF);
    }

    #[test]
    fn allows_any_length_for_malformed_testing() {
        // RFC 7296 §3.9 mandates 16–256 octets, but the crate accepts any length
        // verbatim so malformed payloads can be built. Below-minimum and
        // above-maximum nonces both compile and re-parse unchanged.
        let short = IkeNoncePayload::new(vec![0xFFu8; 4]);
        let short_bytes = compile_payload(short.clone());
        assert_eq!(short_bytes.len(), GENERIC_PAYLOAD_HEADER_LEN + 4);
        let parsed_short =
            parse_nonce_payload_body(&short_bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(parsed_short.nonce_bytes(), short.nonce_bytes());

        let long = IkeNoncePayload::new(vec![0x5Au8; 300]);
        let long_bytes = compile_payload(long.clone());
        assert_eq!(long_bytes.len(), GENERIC_PAYLOAD_HEADER_LEN + 300);
        let parsed_long =
            parse_nonce_payload_body(&long_bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(parsed_long.nonce_bytes(), long.nonce_bytes());

        // An empty nonce is also accepted (no clamping); the body is empty.
        let empty = IkeNoncePayload::new(Vec::<u8>::new());
        let empty_bytes = compile_payload(empty);
        assert_eq!(empty_bytes.len(), GENERIC_PAYLOAD_HEADER_LEN);
        let parsed_empty =
            parse_nonce_payload_body(&empty_bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert!(parsed_empty.nonce_bytes().is_empty());
    }

    #[test]
    fn payload_chain_next_payload_points_at_nonce() {
        // A Nonce payload following another layer derives the preceding header's
        // Next Payload through payload_type_for_layer_name (registered this
        // step) as the Nonce codepoint (40).
        use crate::protocols::ipsec::ikev2::payload::{
            following_next_payload, payload_type_for_layer_name, PAYLOAD_NONCE,
        };
        assert_eq!(
            payload_type_for_layer_name(IKE_NONCE_PAYLOAD_NAME),
            Some(PayloadType::Nonce)
        );
        let packet: Packet = Packet::from_layer(Raw::from_bytes([0u8; 0])) / sample_payload();
        let ctx = LayerContext::new(&packet, 0);
        assert_eq!(following_next_payload(&ctx), PAYLOAD_NONCE);
    }

    #[test]
    fn round_trip_preserves_nonce() {
        // Build a Nonce payload, compile to wire, parse the body back, and
        // confirm the nonce data round-trips (Step 45 closes the registry
        // decode; this is the local parse helper for the step).
        let payload = sample_payload();
        let bytes = compile_payload(payload.clone());

        // Skip the 4-octet generic header to reach the nonce body.
        let parsed = parse_nonce_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(parsed.nonce_bytes(), payload.nonce_bytes());
    }

    #[test]
    fn round_trip_recompiles_byte_for_byte() {
        // The parsed payload re-compiles to the same bytes as the original.
        let payload = sample_payload();
        let bytes = compile_payload(payload);
        let parsed = parse_nonce_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        let recompiled = compile_payload(parsed);
        assert_eq!(recompiled, bytes);
    }
}
