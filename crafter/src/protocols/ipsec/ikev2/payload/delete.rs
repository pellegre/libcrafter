//! IKEv2 Delete (D) payload, type 42 (RFC 7296 §3.11).
//!
//! The Delete payload announces a Security Association the sender is deleting.
//! The body that follows the 4-octet generic payload header (emitted by
//! [`write_generic_payload_header`]) is:
//!
//! ```text
//!  Protocol ID (1) | SPI Size (1) | Num of SPIs (2) | SPIs (variable)
//! ```
//!
//! (RFC 7296 §3.11). The Protocol ID names the protocol whose SAs are being
//! deleted: `1` for an IKE SA, or the AH/ESP protocol numbers (`2`/`3`) for a
//! child SA. The SPI Size gives the length of each SPI (`0` and no SPIs for a
//! Delete of the IKE SA; `4` for AH and ESP). The Num of SPIs is the count of
//! SPIs that follow, each of the fixed SPI Size. The SPIs are the opaque
//! Security Parameter Indexes the sender is deleting.
//!
//! This crate models the **wire form only** — the SPIs are opaque bytes and no
//! per-protocol semantics are interpreted. The generic-header Payload Length,
//! the SPI Size (from the SPIs' element length), and the Num of SPIs (from the
//! number of SPIs) are auto-filled by `compile()`, while any caller-pinned value
//! (Next Payload, Payload Length, Critical, SPI Size, Num of SPIs) is emitted
//! verbatim so deliberately malformed Delete payloads can be constructed for
//! testing.

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::ipsec::ikev2::payload::{
    write_generic_payload_header, IkePayload, PayloadHeaderFields, PayloadType,
};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
#[cfg(test)]
use crate::CrafterError;
use crate::Result;

/// Layer name for the IKEv2 Delete payload, registered in
/// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_DELETE_PAYLOAD_NAME: &str = "IkeDeletePayload";

/// Length of the fixed Delete payload body header (RFC 7296 §3.11): Protocol ID
/// (1) + SPI Size (1) + Num of SPIs (2) = 4 octets, excluding the variable SPIs
/// that follow.
pub const DELETE_FIXED_LEN: usize = 4;

// --- Protocol ID (RFC 7296 §3.11; shared with the SA-protocol numbering) ------

/// Protocol ID `1` — IKE SA (RFC 7296 §3.11). A Delete of the IKE SA carries no
/// SPIs (SPI Size `0`, Num of SPIs `0`).
pub const DELETE_PROTOCOL_IKE: u8 = 1;
/// Protocol ID `2` — AH (RFC 7296 §3.11); child-SA SPIs are 4 octets.
pub const DELETE_PROTOCOL_AH: u8 = 2;
/// Protocol ID `3` — ESP (RFC 7296 §3.11); child-SA SPIs are 4 octets.
pub const DELETE_PROTOCOL_ESP: u8 = 3;

/// IKEv2 Delete (D) payload, type 42 (RFC 7296 §3.11).
///
/// Carries the Protocol ID, SPI Size, Num of SPIs, and the SPIs being deleted.
/// As a [`Layer`] it emits the 4-octet generic payload header (via
/// [`write_generic_payload_header`]) followed by the body `Protocol ID (1) | SPI
/// Size (1) | Num of SPIs (2) | SPIs`. The generic-header Next Payload, Critical
/// flag, and Payload Length are the shared overridable fields carried in
/// [`PayloadHeaderFields`].
///
/// The SPI Size is auto-filled from the length of the SPI elements and the Num
/// of SPIs from the number of SPIs, unless the caller pins either, so a
/// deliberately inconsistent SPI Size or Num of SPIs can be built for malformed
/// testing.
#[derive(Debug, Clone)]
pub struct IkeDeletePayload {
    /// Protocol ID (RFC 7296 §3.11; see `DELETE_PROTOCOL_*`).
    protocol_id: Field<u8>,
    /// SPI Size override (RFC 7296 §3.11); auto-filled from the SPI element
    /// length.
    spi_size: Field<u8>,
    /// Num of SPIs override (RFC 7296 §3.11); auto-filled from the SPI count.
    num_spis: Field<u16>,
    /// Security Parameter Indexes being deleted: opaque bytes (RFC 7296 §3.11).
    spis: Vec<Vec<u8>>,
    /// Shared generic-payload-header overrides (Next Payload, Length, Critical).
    header: PayloadHeaderFields,
}

impl IkeDeletePayload {
    /// A Delete payload for the given Protocol ID with no SPIs (RFC 7296 §3.11).
    ///
    /// This is the IKE-SA Delete shape when `protocol_id` is
    /// [`DELETE_PROTOCOL_IKE`] (no SPIs follow). Add child-SA SPIs with
    /// [`IkeDeletePayload::spi`] or [`IkeDeletePayload::spis`].
    pub fn new(protocol_id: u8) -> Self {
        Self {
            protocol_id: Field::user(protocol_id),
            spi_size: Field::unset(),
            num_spis: Field::unset(),
            spis: Vec::new(),
            header: PayloadHeaderFields::new(),
        }
    }

    /// Set the Protocol ID (RFC 7296 §3.11; see `DELETE_PROTOCOL_*`).
    pub fn protocol_id(mut self, protocol_id: u8) -> Self {
        self.protocol_id.set_user(protocol_id);
        self
    }

    /// Append a single SPI (RFC 7296 §3.11). The SPI Size auto-fills to the
    /// length of the SPI elements and the Num of SPIs to the count, unless
    /// either is pinned explicitly.
    pub fn spi(mut self, spi: impl Into<Vec<u8>>) -> Self {
        self.spis.push(spi.into());
        self
    }

    /// Replace the full list of SPIs (RFC 7296 §3.11), consuming-builder style.
    /// The SPI Size auto-fills to the element length and the Num of SPIs to the
    /// count unless either is pinned explicitly.
    pub fn spis(mut self, spis: impl IntoIterator<Item = Vec<u8>>) -> Self {
        self.spis = spis.into_iter().collect();
        self
    }

    /// Pin the SPI Size explicitly (RFC 7296 §3.11), overriding the value
    /// auto-derived from the SPI element length. A deliberately inconsistent
    /// value is emitted verbatim for malformed testing.
    pub fn spi_size(mut self, spi_size: u8) -> Self {
        self.spi_size.set_user(spi_size);
        self
    }

    /// Pin the Num of SPIs explicitly (RFC 7296 §3.11), overriding the value
    /// auto-derived from the number of SPIs. A deliberately inconsistent value
    /// is emitted verbatim for malformed testing.
    pub fn num_spis(mut self, num_spis: u16) -> Self {
        self.num_spis.set_user(num_spis);
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

    /// The Protocol ID (RFC 7296 §3.11).
    pub fn protocol_id_value(&self) -> u8 {
        self.protocol_id.value().copied().unwrap_or(0)
    }

    /// The effective SPI Size (RFC 7296 §3.11): the caller-pinned override when
    /// set, otherwise the length of the first SPI (all SPIs share one size),
    /// truncated to 8 bits, or `0` when there are no SPIs.
    pub fn effective_spi_size(&self) -> u8 {
        self.spi_size
            .value()
            .copied()
            .unwrap_or_else(|| self.spis.first().map(|spi| spi.len() as u8).unwrap_or(0))
    }

    /// The effective Num of SPIs (RFC 7296 §3.11): the caller-pinned override
    /// when set, otherwise the number of SPIs truncated to 16 bits.
    pub fn effective_num_spis(&self) -> u16 {
        self.num_spis
            .value()
            .copied()
            .unwrap_or_else(|| self.spis.len() as u16)
    }

    /// The SPIs being deleted (RFC 7296 §3.11).
    pub fn spis_list(&self) -> &[Vec<u8>] {
        &self.spis
    }

    /// The Delete body (everything after the 4-octet generic header), per
    /// RFC 7296 §3.11: Protocol ID (1) | SPI Size (1) | Num of SPIs (2) | SPIs.
    fn delete_body(&self) -> Vec<u8> {
        let spis_len: usize = self.spis.iter().map(|spi| spi.len()).sum();
        let mut out = Vec::with_capacity(DELETE_FIXED_LEN + spis_len);
        out.push(self.protocol_id_value());
        out.push(self.effective_spi_size());
        out.extend_from_slice(&self.effective_num_spis().to_be_bytes());
        for spi in &self.spis {
            out.extend_from_slice(spi);
        }
        out
    }
}

impl IkePayload for IkeDeletePayload {
    fn payload_type(&self) -> PayloadType {
        PayloadType::Delete
    }

    fn payload_body(&self, _ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        Ok(self.delete_body())
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

impl Layer for IkeDeletePayload {
    fn name(&self) -> &'static str {
        IKE_DELETE_PAYLOAD_NAME
    }

    fn summary(&self) -> String {
        format!(
            "IkeDeletePayload(protocol_id={}, spi_size={}, num_spis={})",
            self.protocol_id_value(),
            self.effective_spi_size(),
            self.effective_num_spis()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("protocol_id", self.protocol_id_value().to_string()),
            ("spi_size", self.effective_spi_size().to_string()),
            ("num_spis", self.effective_num_spis().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        let spis_len: usize = self.spis.iter().map(|spi| spi.len()).sum();
        super::GENERIC_PAYLOAD_HEADER_LEN + DELETE_FIXED_LEN + spis_len
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Emit the 4-octet generic payload header (auto Next Payload from the
        // following payload and auto Payload Length unless overridden), then the
        // Delete body (Protocol ID | SPI Size | Num of SPIs | SPIs).
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

    impl_layer_object!(IkeDeletePayload);
}

impl_layer_div!(IkeDeletePayload);

// --- Local parse helper (Step 45 closes the full registry decode) -----------

/// Parse a Delete payload **body** (the bytes after the 4-octet generic header)
/// per RFC 7296 §3.11. Local to this step; the registry-driven chain decode
/// lands in Step 45.
///
/// The SPIs are read as `Num of SPIs` fixed-width slices of the on-wire SPI
/// Size; a SPI region that runs past the available bytes is a structured error
/// rather than a panic. Decoded fields are stored with `Field::user`, and the
/// on-wire SPI Size and Num of SPIs are pinned so a re-compile reproduces the
/// bytes exactly even when they disagree with the SPI list (malformed inputs
/// round-trip).
#[cfg(test)]
fn parse_delete_payload_body(bytes: &[u8]) -> Result<IkeDeletePayload> {
    if bytes.len() < DELETE_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ikev2.delete",
            DELETE_FIXED_LEN,
            bytes.len(),
        ));
    }
    let protocol_id = bytes[0];
    let spi_size = bytes[1] as usize;
    let num_spis = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;

    let spis_end = DELETE_FIXED_LEN + spi_size * num_spis;
    if bytes.len() < spis_end {
        return Err(CrafterError::buffer_too_short(
            "ikev2.delete.spis",
            spis_end,
            bytes.len(),
        ));
    }
    let mut spis = Vec::with_capacity(num_spis);
    let mut offset = DELETE_FIXED_LEN;
    for _ in 0..num_spis {
        spis.push(bytes[offset..offset + spi_size].to_vec());
        offset += spi_size;
    }

    Ok(IkeDeletePayload::new(protocol_id)
        .spis(spis)
        // Pin the on-wire SPI Size and Num of SPIs so a re-compile is byte-exact
        // even if they disagree with the SPI list (malformed inputs round-trip).
        .spi_size(bytes[1])
        .num_spis(u16::from_be_bytes([bytes[2], bytes[3]])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LayerContext, Packet, Raw};
    use crate::protocols::ipsec::ikev2::payload::GENERIC_PAYLOAD_HEADER_LEN;

    /// Compile a standalone Delete payload and return its full bytes (generic
    /// header + body), gathered through a one-layer packet.
    fn compile_payload(payload: IkeDeletePayload) -> Vec<u8> {
        let packet = Packet::from_layer(payload);
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    /// A representative ESP child-SA Delete (RFC 7296 §3.11) with two 4-octet
    /// SPIs.
    fn esp_delete_payload() -> IkeDeletePayload {
        IkeDeletePayload::new(DELETE_PROTOCOL_ESP)
            .spi(vec![0x11u8, 0x22, 0x33, 0x44])
            .spi(vec![0xAAu8, 0xBB, 0xCC, 0xDD])
    }

    #[test]
    fn delete_constants_match_rfc() {
        // RFC 7296 §3.11: the fixed body header is Protocol ID (1) + SPI Size (1)
        // + Num of SPIs (2).
        assert_eq!(DELETE_FIXED_LEN, 4);
        // Protocol IDs shared with the SA-protocol numbering.
        assert_eq!(DELETE_PROTOCOL_IKE, 1);
        assert_eq!(DELETE_PROTOCOL_AH, 2);
        assert_eq!(DELETE_PROTOCOL_ESP, 3);
    }

    #[test]
    fn payload_type_is_delete() {
        let payload = esp_delete_payload();
        assert_eq!(payload.payload_type(), PayloadType::Delete);
        // The layer name is registered for the chain next-payload derivation.
        assert_eq!(payload.name(), IKE_DELETE_PAYLOAD_NAME);
    }

    #[test]
    fn ike_delete_has_no_spis() {
        // RFC 7296 §3.11: a Delete of the IKE SA carries no SPIs, so SPI Size and
        // Num of SPIs auto-fill to 0.
        let payload = IkeDeletePayload::new(DELETE_PROTOCOL_IKE);
        assert_eq!(payload.effective_spi_size(), 0);
        assert_eq!(payload.effective_num_spis(), 0);
        let body = payload.delete_body();
        assert_eq!(body[0], DELETE_PROTOCOL_IKE);
        assert_eq!(body[1], 0); // SPI Size.
        assert_eq!(u16::from_be_bytes([body[2], body[3]]), 0); // Num of SPIs.
        assert_eq!(body.len(), DELETE_FIXED_LEN);
    }

    #[test]
    fn body_lays_out_fixed_header_then_spis() {
        // RFC 7296 §3.11: Protocol ID | SPI Size | Num of SPIs | SPIs. The ESP
        // Delete carries two 4-octet SPIs, so SPI Size auto-fills to 4 and Num of
        // SPIs to 2.
        let payload = esp_delete_payload();
        let body = payload.delete_body();
        assert_eq!(body[0], DELETE_PROTOCOL_ESP); // Protocol ID.
        assert_eq!(body[1], 4); // Auto SPI Size.
        assert_eq!(u16::from_be_bytes([body[2], body[3]]), 2); // Auto Num of SPIs.
        assert_eq!(
            &body[DELETE_FIXED_LEN..DELETE_FIXED_LEN + 4],
            &[0x11, 0x22, 0x33, 0x44]
        );
        assert_eq!(&body[DELETE_FIXED_LEN + 4..], &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(body.len(), DELETE_FIXED_LEN + 8);
    }

    #[test]
    fn spi_size_and_num_spis_auto_fill() {
        // With two 4-octet SPIs, the SPI Size auto-fills to 4 and Num of SPIs to
        // 2.
        let payload = esp_delete_payload();
        assert_eq!(payload.effective_spi_size(), 4);
        assert_eq!(payload.effective_num_spis(), 2);
    }

    #[test]
    fn spi_size_override_is_honored() {
        // A pinned SPI Size is emitted verbatim even when it disagrees with the
        // actual SPI length (malformed input for testing).
        let payload = esp_delete_payload().spi_size(99);
        assert_eq!(payload.effective_spi_size(), 99);
        assert_eq!(payload.delete_body()[1], 99);
    }

    #[test]
    fn num_spis_override_is_honored() {
        // A pinned Num of SPIs is emitted verbatim even when it disagrees with the
        // actual number of SPIs (malformed input for testing).
        let payload = esp_delete_payload().num_spis(7);
        assert_eq!(payload.effective_num_spis(), 7);
        let body = payload.delete_body();
        assert_eq!(u16::from_be_bytes([body[2], body[3]]), 7);
    }

    #[test]
    fn payload_compiles_generic_header_then_body() {
        // The compiled payload is the 4-octet generic header (Next Payload 0
        // terminator, auto length) followed by the Delete body.
        let payload = esp_delete_payload();
        let bytes = compile_payload(payload.clone());

        assert_eq!(bytes[0], 0); // Next Payload terminator.
        assert_eq!(bytes[1], 0); // Critical clear.
        let payload_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(payload_len, bytes.len());
        assert_eq!(payload_len, payload.encoded_len());
        // The body after the generic header is the Delete body verbatim.
        assert_eq!(
            &bytes[GENERIC_PAYLOAD_HEADER_LEN..],
            &payload.delete_body()[..]
        );
    }

    #[test]
    fn payload_honors_generic_header_overrides() {
        // Caller-pinned Next Payload, Critical, and Payload Length survive.
        let payload = esp_delete_payload()
            .next_payload(42)
            .critical(true)
            .payload_length(0xBEEF);
        let bytes = compile_payload(payload);
        assert_eq!(bytes[0], 42);
        assert_eq!(bytes[1], 0x80); // Critical bit set.
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0xBEEF);
    }

    #[test]
    fn payload_chain_next_payload_points_at_delete() {
        // A Delete payload following another layer derives the preceding header's
        // Next Payload through payload_type_for_layer_name (registered this step)
        // as the Delete codepoint (42).
        use crate::protocols::ipsec::ikev2::payload::{
            following_next_payload, payload_type_for_layer_name, PAYLOAD_DELETE,
        };
        assert_eq!(
            payload_type_for_layer_name(IKE_DELETE_PAYLOAD_NAME),
            Some(PayloadType::Delete)
        );
        let packet: Packet = Packet::from_layer(Raw::from_bytes([0u8; 0])) / esp_delete_payload();
        let ctx = LayerContext::new(&packet, 0);
        assert_eq!(following_next_payload(&ctx), PAYLOAD_DELETE);
    }

    #[test]
    fn round_trip_preserves_spis_and_counts() {
        // Build a Delete with two 4-byte SPIs, compile to wire, parse the body
        // back, and confirm the SPIs and counts round-trip (Step 45 closes the
        // registry decode; this is the local parse helper for the step).
        let payload = esp_delete_payload();
        let bytes = compile_payload(payload.clone());

        let parsed = parse_delete_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(parsed.protocol_id_value(), DELETE_PROTOCOL_ESP);
        assert_eq!(parsed.effective_spi_size(), 4);
        assert_eq!(parsed.effective_num_spis(), 2);
        assert_eq!(
            parsed.spis_list(),
            &[
                vec![0x11u8, 0x22, 0x33, 0x44],
                vec![0xAAu8, 0xBB, 0xCC, 0xDD]
            ]
        );
    }

    #[test]
    fn round_trip_recompiles_byte_for_byte() {
        // The parsed Delete re-compiles byte-exact.
        let payload = esp_delete_payload();
        let bytes = compile_payload(payload);
        let parsed = parse_delete_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        let recompiled = compile_payload(parsed);
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn round_trip_ike_delete_recompiles_byte_for_byte() {
        // An IKE-SA Delete (no SPIs) parses and re-compiles byte-exact.
        let payload = IkeDeletePayload::new(DELETE_PROTOCOL_IKE);
        let bytes = compile_payload(payload);
        let parsed = parse_delete_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        let recompiled = compile_payload(parsed);
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn parse_rejects_truncated_fixed_header() {
        // A buffer shorter than the fixed Delete body header is a structured
        // error, not a panic.
        let err = parse_delete_payload_body(&[0u8, 0, 0]).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }

    #[test]
    fn parse_rejects_spis_past_end() {
        // A SPI region that runs past the available bytes is a structured error.
        // Protocol ID 3 | SPI Size 4 | Num of SPIs 2 | (only 4 SPI bytes present).
        let body = [3u8, 4, 0x00, 0x02, 0x11, 0x22, 0x33, 0x44];
        let err = parse_delete_payload_body(&body).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }
}
