//! IKEv2 Key Exchange (KE) payload, type 34 (RFC 7296 §3.4).
//!
//! The KE payload carries the Diffie-Hellman public value for the negotiated
//! key-exchange method. The body that follows the 4-octet generic payload
//! header (emitted by [`write_generic_payload_header`]) is:
//!
//! ```text
//!  Diffie-Hellman Group Num (2) | RESERVED (2) | Key Exchange Data (variable)
//! ```
//!
//! (RFC 7296 §3.4). The Group Num names the D-H group whose public value fills
//! the Key Exchange Data; the two RESERVED octets are sent as zero. This crate
//! models the **wire form only** — the Key Exchange Data is opaque bytes and no
//! Diffie-Hellman math is performed (spec out of scope).
//!
//! The generic-header Payload Length is auto-filled by `compile()` from the
//! body length and any caller-pinned value (Next Payload, Payload Length,
//! Critical) is emitted verbatim, so deliberately malformed KE payloads can be
//! constructed for testing.

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::ipsec::ikev2::payload::{
    write_generic_payload_header, IkePayload, PayloadHeaderFields, PayloadType,
};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::CrafterError;
use crate::Result;

/// Layer name for the IKEv2 KE payload, registered in
/// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_KE_PAYLOAD_NAME: &str = "IkeKePayload";

/// Length of the fixed KE payload body header (RFC 7296 §3.4): Diffie-Hellman
/// Group Num (2) + RESERVED (2) = 4 octets, excluding the variable Key Exchange
/// Data that follows.
pub const KE_FIXED_LEN: usize = 4;

// --- Diffie-Hellman Group Num (RFC 7296 §3.3.2; IANA "Transform Type 4 - DH") -

/// D-H Group `2` — 1024-bit MODP (RFC 7296 §3.3.2). Legacy; included for
/// completeness.
pub const DH_GROUP_MODP_1024: u16 = 2;
/// D-H Group `14` — 2048-bit MODP (RFC 7296 §3.3.2): a common IKEv2 default.
pub const DH_GROUP_MODP_2048: u16 = 14;
/// D-H Group `19` — 256-bit random ECP (RFC 5903).
pub const DH_GROUP_ECP_256: u16 = 19;
/// D-H Group `31` — Curve25519 (RFC 8031).
pub const DH_GROUP_CURVE25519: u16 = 31;

/// IKEv2 Key Exchange (KE) payload, type 34 (RFC 7296 §3.4).
///
/// Carries the Diffie-Hellman Group Num and the opaque Key Exchange Data. As a
/// [`Layer`] it emits the 4-octet generic payload header (via
/// [`write_generic_payload_header`]) followed by the body `Group Num (2) |
/// RESERVED (2) | Key Exchange Data`. The generic-header Next Payload, Critical
/// flag, and Payload Length are the shared overridable fields carried in
/// [`PayloadHeaderFields`].
#[derive(Debug, Clone)]
pub struct IkeKePayload {
    /// Diffie-Hellman Group Num (RFC 7296 §3.4; see `DH_GROUP_*`).
    dh_group: Field<u16>,
    /// Key Exchange Data: the opaque D-H public value (RFC 7296 §3.4).
    key_exchange_data: Vec<u8>,
    /// Shared generic-payload-header overrides (Next Payload, Length, Critical).
    header: PayloadHeaderFields,
}

impl IkeKePayload {
    /// A KE payload for the given Diffie-Hellman group carrying the given Key
    /// Exchange Data bytes (RFC 7296 §3.4).
    pub fn new(dh_group: u16, key_exchange_data: impl Into<Vec<u8>>) -> Self {
        Self {
            dh_group: Field::user(dh_group),
            key_exchange_data: key_exchange_data.into(),
            header: PayloadHeaderFields::new(),
        }
    }

    /// Set the Diffie-Hellman Group Num (RFC 7296 §3.4).
    pub fn dh_group(mut self, dh_group: u16) -> Self {
        self.dh_group.set_user(dh_group);
        self
    }

    /// Set the Key Exchange Data bytes (RFC 7296 §3.4), consuming-builder style.
    pub fn key_exchange_data(mut self, key_exchange_data: impl Into<Vec<u8>>) -> Self {
        self.key_exchange_data = key_exchange_data.into();
        self
    }

    /// The Diffie-Hellman Group Num (RFC 7296 §3.4).
    pub fn dh_group_num(&self) -> u16 {
        self.dh_group.value().copied().unwrap_or(0)
    }

    /// The Key Exchange Data bytes (RFC 7296 §3.4).
    pub fn key_exchange_data_bytes(&self) -> &[u8] {
        &self.key_exchange_data
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

    /// The KE body (everything after the 4-octet generic header), per
    /// RFC 7296 §3.4: Group Num (2) | RESERVED (2) | Key Exchange Data.
    fn ke_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KE_FIXED_LEN + self.key_exchange_data.len());
        out.extend_from_slice(&self.dh_group_num().to_be_bytes());
        out.extend_from_slice(&[0u8, 0u8]); // RESERVED.
        out.extend_from_slice(&self.key_exchange_data);
        out
    }
}

impl IkePayload for IkeKePayload {
    fn payload_type(&self) -> PayloadType {
        PayloadType::KeyExchange
    }

    fn payload_body(&self, _ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        Ok(self.ke_body())
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

impl Layer for IkeKePayload {
    fn name(&self) -> &'static str {
        IKE_KE_PAYLOAD_NAME
    }

    fn summary(&self) -> String {
        format!(
            "IkeKePayload(dh_group={}, kex_len={})",
            self.dh_group_num(),
            self.key_exchange_data.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("dh_group", self.dh_group_num().to_string()),
            ("kex_len", self.key_exchange_data.len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        super::GENERIC_PAYLOAD_HEADER_LEN + KE_FIXED_LEN + self.key_exchange_data.len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Emit the 4-octet generic payload header (auto Next Payload from the
        // following payload and auto Payload Length unless overridden), then the
        // KE body (Group Num | RESERVED | Key Exchange Data).
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

    impl_layer_object!(IkeKePayload);
}

impl_layer_div!(IkeKePayload);

// --- Local parse helper (Step 45 closes the full registry decode) -----------

/// Parse a KE payload **body** (the bytes after the 4-octet generic header) per
/// RFC 7296 §3.4. Local to this step; the registry-driven chain decode lands in
/// Step 45.
pub(crate) fn parse_ke_payload_body(bytes: &[u8]) -> Result<IkeKePayload> {
    if bytes.len() < KE_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ikev2.ke",
            KE_FIXED_LEN,
            bytes.len(),
        ));
    }
    let dh_group = u16::from_be_bytes([bytes[0], bytes[1]]);
    // bytes[2..4] are RESERVED and ignored on decode.
    let key_exchange_data = bytes[KE_FIXED_LEN..].to_vec();
    Ok(IkeKePayload::new(dh_group, key_exchange_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LayerContext, Packet, Raw};

    /// Compile a standalone KE payload and return its full bytes (generic header
    /// + body), gathered through a one-layer packet.
    fn compile_payload(payload: IkeKePayload) -> Vec<u8> {
        let packet = Packet::from_layer(payload);
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    /// A representative KE payload: MODP-2048 (group 14) with a fixed public
    /// value buffer.
    fn sample_payload() -> IkeKePayload {
        IkeKePayload::new(
            DH_GROUP_MODP_2048,
            vec![0xDEu8, 0xAD, 0xBE, 0xEF, 0x01, 0x02],
        )
    }

    #[test]
    fn ke_constants_match_rfc() {
        // RFC 7296 §3.4: the fixed body header is Group Num (2) + RESERVED (2).
        assert_eq!(KE_FIXED_LEN, 4);
        // D-H Group codepoints (RFC 7296 §3.3.2 / IANA Transform Type 4).
        assert_eq!(DH_GROUP_MODP_1024, 2);
        assert_eq!(DH_GROUP_MODP_2048, 14);
        assert_eq!(DH_GROUP_ECP_256, 19);
        assert_eq!(DH_GROUP_CURVE25519, 31);
    }

    #[test]
    fn payload_type_is_key_exchange() {
        assert_eq!(sample_payload().payload_type(), PayloadType::KeyExchange);
        // The layer name is registered for the chain next-payload derivation.
        assert_eq!(sample_payload().name(), IKE_KE_PAYLOAD_NAME);
    }

    #[test]
    fn body_lays_out_group_reserved_then_data() {
        // RFC 7296 §3.4: Group Num (2) | RESERVED (2, zero) | Key Exchange Data.
        let payload = sample_payload();
        let body = payload.ke_body();
        assert_eq!(u16::from_be_bytes([body[0], body[1]]), DH_GROUP_MODP_2048);
        assert_eq!(&body[2..4], &[0, 0]); // RESERVED.
        assert_eq!(&body[4..], &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02]);
        assert_eq!(body.len(), KE_FIXED_LEN + 6);
    }

    #[test]
    fn payload_compiles_generic_header_then_body() {
        // The compiled payload is the 4-octet generic header (Next Payload 0
        // terminator, auto length) followed by the KE body.
        let payload = sample_payload();
        let bytes = compile_payload(payload.clone());

        // Generic header: Next Payload terminator, Critical clear.
        assert_eq!(bytes[0], 0);
        assert_eq!(bytes[1], 0);
        let payload_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(payload_len, bytes.len());
        assert_eq!(payload_len, payload.encoded_len());
    }

    #[test]
    fn payload_honors_generic_header_overrides() {
        // Caller-pinned Next Payload, Critical, and Payload Length survive.
        let payload = sample_payload()
            .next_payload(40)
            .critical(true)
            .payload_length(0xBEEF);
        let bytes = compile_payload(payload);
        assert_eq!(bytes[0], 40);
        assert_eq!(bytes[1], 0x80); // Critical bit set.
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0xBEEF);
    }

    #[test]
    fn payload_chain_next_payload_points_at_ke() {
        // A KE payload following another layer derives the preceding header's
        // Next Payload through payload_type_for_layer_name (registered this
        // step) as the KE codepoint (34).
        use crate::protocols::ipsec::ikev2::payload::{
            following_next_payload, payload_type_for_layer_name, PAYLOAD_KE,
        };
        assert_eq!(
            payload_type_for_layer_name(IKE_KE_PAYLOAD_NAME),
            Some(PayloadType::KeyExchange)
        );
        let packet: Packet = Packet::from_layer(Raw::from_bytes([0u8; 0])) / sample_payload();
        let ctx = LayerContext::new(&packet, 0);
        assert_eq!(following_next_payload(&ctx), PAYLOAD_KE);
    }

    #[test]
    fn round_trip_preserves_group_and_data() {
        // Build a KE payload, compile to wire, parse the body back, and confirm
        // the D-H group and Key Exchange Data round-trip (Step 45 closes the
        // registry decode; this is the local parse helper for the step).
        let payload = sample_payload();
        let bytes = compile_payload(payload.clone());

        // Skip the 4-octet generic header to reach the KE body.
        let parsed = parse_ke_payload_body(&bytes[4..]).unwrap();
        assert_eq!(parsed.dh_group_num(), DH_GROUP_MODP_2048);
        assert_eq!(
            parsed.key_exchange_data_bytes(),
            payload.key_exchange_data_bytes()
        );
    }

    #[test]
    fn round_trip_recompiles_byte_for_byte() {
        // The parsed payload re-compiles to the same bytes as the original.
        let payload = sample_payload();
        let bytes = compile_payload(payload);
        let parsed = parse_ke_payload_body(&bytes[4..]).unwrap();
        let recompiled = compile_payload(parsed);
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn parse_rejects_truncated_body() {
        // A buffer shorter than the fixed KE body header is a structured error.
        let err = parse_ke_payload_body(&[0u8, 14, 0]).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }
}
