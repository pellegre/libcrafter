//! IKEv2 message header and constants (RFC 7296 §3.1).
//!
//! Every IKEv2 message begins with a fixed 28-octet header: Initiator SPI (8) |
//! Responder SPI (8) | Next Payload (1) | Major/Minor Version (1) | Exchange
//! Type (1) | Flags (1) | Message ID (4) | Length (4) (RFC 7296 §3.1). IKEv2
//! messages are carried in UDP payloads, so the header composes after UDP.
//!
//! This module defines the [`IkeHeader`] field model, the IKEv2 codepoint
//! constants (version, exchange types, flag bits), and the builder plus
//! `Layer` impl that auto-fills the Next Payload and total message Length. The
//! decode path is added by a later step.

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object, payload_bytes_after};
use crate::Result;

/// Length of the fixed IKEv2 message header (RFC 7296 §3.1): Initiator SPI (8) +
/// Responder SPI (8) + Next Payload (1) + Version (1) + Exchange Type (1) +
/// Flags (1) + Message ID (4) + Length (4) = 28 octets.
pub const IKE_HEADER_LEN: usize = 28;

/// IKE version octet for IKEv2: major version 2, minor version 0, packed as the
/// high and low nibbles of a single octet (RFC 7296 §3.1).
pub const IKE_VERSION_2: u8 = 0x20;

/// Payload-type value `No Next Payload` (RFC 7296 §3.2; IANA IKEv2 Payload
/// Types): the value `0` placed in a Next Payload field when no further payload
/// follows. The header's Next Payload defaults to this until a following
/// payload (a later step) supplies its own type.
pub const NO_NEXT_PAYLOAD: u8 = 0;

/// Exchange Type `IKE_SA_INIT` (RFC 7296 §3.1; IANA IKEv2 Parameters).
pub const IKE_SA_INIT: u8 = 34;

/// Exchange Type `IKE_AUTH` (RFC 7296 §3.1; IANA IKEv2 Parameters).
pub const IKE_AUTH: u8 = 35;

/// Exchange Type `CREATE_CHILD_SA` (RFC 7296 §3.1; IANA IKEv2 Parameters).
pub const CREATE_CHILD_SA: u8 = 36;

/// Exchange Type `INFORMATIONAL` (RFC 7296 §3.1; IANA IKEv2 Parameters).
pub const INFORMATIONAL: u8 = 37;

/// Flags bit 3 — Initiator (I): set when the message originates from the SA
/// initiator (RFC 7296 §3.1).
pub const IKE_FLAG_INITIATOR: u8 = 0x08;

/// Flags bit 4 — Version (V): set when the transmitter implements a higher minor
/// version than negotiated (RFC 7296 §3.1).
pub const IKE_FLAG_VERSION: u8 = 0x10;

/// Flags bit 5 — Response (R): set when the message is a response to a message
/// carrying the same Message ID (RFC 7296 §3.1).
pub const IKE_FLAG_RESPONSE: u8 = 0x20;

/// IKEv2 message header (RFC 7296 §3.1).
///
/// The header carries the initiator/responder SPIs, the next-payload pointer
/// into the payload chain, the IKE version, exchange type, flags, message ID,
/// and the total message length. `Field` tracks which values the caller pinned
/// versus which `compile()` (a later step) auto-fills: the `next_payload` is
/// derived from the first payload in the chain, the `version` defaults to
/// `0x20`, and the `length` is the total message length. Any caller-set value —
/// including a deliberately wrong one for malformed testing — is preserved.
#[derive(Debug, Clone)]
pub struct IkeHeader {
    /// IKE SA Initiator's SPI (RFC 7296 §3.1).
    initiator_spi: Field<u64>,
    /// IKE SA Responder's SPI; zero in the first `IKE_SA_INIT` request
    /// (RFC 7296 §3.1).
    responder_spi: Field<u64>,
    /// Payload type of the first payload in the message; auto-filled from the
    /// first payload in the chain (RFC 7296 §3.1).
    next_payload: Field<u8>,
    /// Major/minor version octet; defaults to [`IKE_VERSION_2`] (`0x20`).
    version: Field<u8>,
    /// Exchange Type (RFC 7296 §3.1; see the `IKE_*` exchange constants).
    exchange_type: Field<u8>,
    /// Flags octet (RFC 7296 §3.1; see the `IKE_FLAG_*` bit constants).
    flags: Field<u8>,
    /// Message ID matching requests to responses (RFC 7296 §3.1).
    message_id: Field<u32>,
    /// Total message length in octets; auto-filled to header + all payloads.
    length: Field<u32>,
}

/// Default Responder SPI assigned when the caller pins none.
///
/// The first `IKE_SA_INIT` request carries a zero Responder SPI (RFC 7296
/// §3.1), so zero is the natural builder default.
const DEFAULT_RESPONDER_SPI: u64 = 0;

/// Default Message ID assigned when the caller pins none.
///
/// The initial `IKE_SA_INIT` exchange uses Message ID 0 (RFC 7296 §2.2).
const DEFAULT_MESSAGE_ID: u32 = 0;

impl IkeHeader {
    /// Create an IKE header with deterministic packet-builder defaults.
    ///
    /// The `version` is defaulted to [`IKE_VERSION_2`], the `responder_spi` and
    /// `message_id` to zero (the `IKE_SA_INIT`-request values per RFC 7296 §2.2
    /// and §3.1); the `next_payload` and `length` are left unset so a later
    /// `compile()` can fill them from the payload chain. The `initiator_spi`,
    /// `exchange_type`, and `flags` are unset for the caller (the builder in a
    /// later step) to supply. Any value the caller sets afterwards is preserved
    /// untouched.
    pub fn new() -> Self {
        Self {
            initiator_spi: Field::unset(),
            responder_spi: Field::defaulted(DEFAULT_RESPONDER_SPI),
            next_payload: Field::unset(),
            version: Field::defaulted(IKE_VERSION_2),
            exchange_type: Field::unset(),
            flags: Field::unset(),
            message_id: Field::defaulted(DEFAULT_MESSAGE_ID),
            length: Field::unset(),
        }
    }

    /// Set the IKE SA Initiator's SPI explicitly (RFC 7296 §3.1).
    pub fn initiator_spi(mut self, initiator_spi: u64) -> Self {
        self.initiator_spi.set_user(initiator_spi);
        self
    }

    /// Set the IKE SA Responder's SPI explicitly (RFC 7296 §3.1).
    pub fn responder_spi(mut self, responder_spi: u64) -> Self {
        self.responder_spi.set_user(responder_spi);
        self
    }

    /// Set the Next Payload explicitly (RFC 7296 §3.1).
    ///
    /// `compile()` otherwise derives this from the first following payload (a
    /// later step wires that in); setting it pins the value, including a
    /// deliberately wrong one for malformed tests.
    pub fn next_payload(mut self, next_payload: u8) -> Self {
        self.next_payload.set_user(next_payload);
        self
    }

    /// Set the IKE version octet explicitly (RFC 7296 §3.1).
    ///
    /// Defaults to [`IKE_VERSION_2`] (`0x20`); an override emits the value
    /// verbatim for deliberately malformed output.
    pub fn version(mut self, version: u8) -> Self {
        self.version.set_user(version);
        self
    }

    /// Set the Exchange Type explicitly (RFC 7296 §3.1; see the `IKE_*`
    /// exchange constants such as [`IKE_SA_INIT`]).
    pub fn exchange(mut self, exchange_type: u8) -> Self {
        self.exchange_type.set_user(exchange_type);
        self
    }

    /// Set the Flags octet explicitly (RFC 7296 §3.1; see the `IKE_FLAG_*` bit
    /// constants).
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags.set_user(flags);
        self
    }

    /// Set the Initiator (I) flag bit, preserving any other flag bits already
    /// set (RFC 7296 §3.1).
    ///
    /// The message originates from the SA initiator. This is a convenience over
    /// [`IkeHeader::flags`] that OR-s in [`IKE_FLAG_INITIATOR`] rather than
    /// replacing the whole octet.
    pub fn initiator(mut self) -> Self {
        let flags = self.flags.value().copied().unwrap_or(0) | IKE_FLAG_INITIATOR;
        self.flags.set_user(flags);
        self
    }

    /// Set the Response (R) flag bit, preserving any other flag bits already
    /// set (RFC 7296 §3.1).
    ///
    /// The message is a response to a request carrying the same Message ID.
    /// This is a convenience over [`IkeHeader::flags`] that OR-s in
    /// [`IKE_FLAG_RESPONSE`] rather than replacing the whole octet.
    pub fn response(mut self) -> Self {
        let flags = self.flags.value().copied().unwrap_or(0) | IKE_FLAG_RESPONSE;
        self.flags.set_user(flags);
        self
    }

    /// Set the Message ID explicitly (RFC 7296 §3.1).
    ///
    /// Defaults to `0` (the initial `IKE_SA_INIT` exchange, RFC 7296 §2.2); an
    /// override emits the value verbatim.
    pub fn message_id(mut self, message_id: u32) -> Self {
        self.message_id.set_user(message_id);
        self
    }

    /// Set the total message Length explicitly (RFC 7296 §3.1).
    ///
    /// `compile()` otherwise auto-fills the Length to the 28-octet header plus
    /// all following payload bytes; setting it pins the value, including a
    /// deliberately wrong one for malformed tests.
    pub fn length(mut self, length: u32) -> Self {
        self.length.set_user(length);
        self
    }

    /// Stored IKE SA Initiator's SPI, when explicit or decoded.
    pub fn initiator_spi_value(&self) -> Option<u64> {
        self.initiator_spi.value().copied()
    }

    /// Stored IKE SA Responder's SPI, when explicit, defaulted, or decoded.
    pub fn responder_spi_value(&self) -> Option<u64> {
        self.responder_spi.value().copied()
    }

    /// Stored Next Payload value, when explicit or decoded.
    pub fn next_payload_value(&self) -> Option<u8> {
        self.next_payload.value().copied()
    }

    /// Stored IKE version octet, when explicit, defaulted, or decoded.
    pub fn version_value(&self) -> Option<u8> {
        self.version.value().copied()
    }

    /// Stored Exchange Type, when explicit or decoded.
    pub fn exchange_type_value(&self) -> Option<u8> {
        self.exchange_type.value().copied()
    }

    /// Stored Flags octet, when explicit or decoded.
    pub fn flags_value(&self) -> Option<u8> {
        self.flags.value().copied()
    }

    /// Stored Message ID, when explicit, defaulted, or decoded.
    pub fn message_id_value(&self) -> Option<u32> {
        self.message_id.value().copied()
    }

    /// Stored total message Length, when explicit or decoded.
    pub fn length_value(&self) -> Option<u32> {
        self.length.value().copied()
    }

    /// Resolved IKE SA Initiator's SPI for inspection and `compile()` (explicit
    /// or decoded, else `0`).
    fn display_initiator_spi(&self) -> u64 {
        self.initiator_spi.value().copied().unwrap_or(0)
    }

    /// Resolved IKE SA Responder's SPI for inspection and `compile()`.
    fn display_responder_spi(&self) -> u64 {
        self.responder_spi
            .value()
            .copied()
            .unwrap_or(DEFAULT_RESPONDER_SPI)
    }

    /// Resolved IKE version octet for inspection and `compile()`.
    fn display_version(&self) -> u8 {
        self.version.value().copied().unwrap_or(IKE_VERSION_2)
    }

    /// Resolved Exchange Type for inspection and `compile()` (explicit or
    /// decoded, else `0`).
    fn display_exchange_type(&self) -> u8 {
        self.exchange_type.value().copied().unwrap_or(0)
    }

    /// Resolved Flags octet for inspection and `compile()` (explicit or
    /// decoded, else `0`).
    fn display_flags(&self) -> u8 {
        self.flags.value().copied().unwrap_or(0)
    }

    /// Resolved Message ID for inspection and `compile()`.
    fn display_message_id(&self) -> u32 {
        self.message_id
            .value()
            .copied()
            .unwrap_or(DEFAULT_MESSAGE_ID)
    }

    /// Resolve the Next Payload value for `compile()` (RFC 7296 §3.1).
    ///
    /// A caller-set value (including a deliberately wrong one) wins. Otherwise
    /// it defaults to [`NO_NEXT_PAYLOAD`] (`0`).
    ///
    /// TODO(step 34): when the IKEv2 generic-payload chain lands, derive the
    /// Next Payload from the first following `IkePayload` layer
    /// (`ctx.next()` → `payload_type()`) instead of defaulting to
    /// `NO_NEXT_PAYLOAD`. The `IkePayload` trait does not exist yet, so this
    /// step deliberately does not forward-reference it.
    fn effective_next_payload(&self, _ctx: &LayerContext<'_>) -> u8 {
        if let Some(next_payload) = self.next_payload.value().copied() {
            return next_payload;
        }
        NO_NEXT_PAYLOAD
    }

    /// Resolve the total message Length for `compile()` (RFC 7296 §3.1).
    ///
    /// A caller-set value (including a deliberately wrong one) wins. Otherwise
    /// the Length is the 28-octet header plus every following payload's bytes:
    /// `IKE_HEADER_LEN + payload_bytes_after(ctx).len()`.
    fn effective_length(&self, ctx: &LayerContext<'_>) -> Result<u32> {
        if let Some(length) = self.length.value().copied() {
            return Ok(length);
        }
        let payload_len = payload_bytes_after(*ctx)?.len();
        Ok((IKE_HEADER_LEN + payload_len) as u32)
    }
}

impl Layer for IkeHeader {
    fn name(&self) -> &'static str {
        "IkeHeader"
    }

    fn summary(&self) -> String {
        format!(
            "IkeHeader(exchange={}, flags=0x{:02x}, msgid={}, ispi=0x{:016x}, rspi=0x{:016x})",
            self.display_exchange_type(),
            self.display_flags(),
            self.display_message_id(),
            self.display_initiator_spi(),
            self.display_responder_spi(),
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "initiator_spi",
                format!("0x{:016x}", self.display_initiator_spi()),
            ),
            (
                "responder_spi",
                format!("0x{:016x}", self.display_responder_spi()),
            ),
            (
                "next_payload",
                self.next_payload
                    .value()
                    .map(|np| np.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("version", format!("0x{:02x}", self.display_version())),
            ("exchange_type", self.display_exchange_type().to_string()),
            ("flags", format!("0x{:02x}", self.display_flags())),
            ("message_id", self.display_message_id().to_string()),
            (
                "length",
                self.length
                    .value()
                    .map(|len| len.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        // The IKE header is always the fixed 28 octets; the following payloads
        // emit themselves (the header does not consume the tail).
        IKE_HEADER_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Auto-fill: Next Payload from the first following payload (defaulting to
        // NO_NEXT_PAYLOAD until step 34 wires the payload chain) unless the caller
        // pinned one; Length = 28 + all following payload bytes unless overridden.
        // A caller override of either field is emitted verbatim, including a
        // deliberately wrong value for malformed testing.
        let next_payload = self.effective_next_payload(ctx);
        let length = self.effective_length(ctx)?;

        out.reserve(IKE_HEADER_LEN);
        out.extend_from_slice(&self.display_initiator_spi().to_be_bytes());
        out.extend_from_slice(&self.display_responder_spi().to_be_bytes());
        out.push(next_payload);
        out.push(self.display_version());
        out.push(self.display_exchange_type());
        out.push(self.display_flags());
        out.extend_from_slice(&self.display_message_id().to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        Ok(())
    }

    impl_layer_object!(IkeHeader);
}

impl_layer_div!(IkeHeader);

impl Default for IkeHeader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_octet_matches_manifest() {
        // RFC 7296 §3.1 / docs/ipsec-rfc-manifest.md: IKEv2 is 0x20 (major 2,
        // minor 0).
        assert_eq!(IKE_VERSION_2, 0x20);
    }

    #[test]
    fn exchange_types_match_iana_values() {
        // IANA IKEv2 Parameters / docs/ipsec-rfc-manifest.md exchange-type table.
        assert_eq!(IKE_SA_INIT, 34);
        assert_eq!(IKE_AUTH, 35);
        assert_eq!(CREATE_CHILD_SA, 36);
        assert_eq!(INFORMATIONAL, 37);
    }

    #[test]
    fn flag_bits_match_manifest() {
        // RFC 7296 §3.1 / docs/ipsec-rfc-manifest.md: bit 3 Initiator, bit 4
        // Version, bit 5 Response.
        assert_eq!(IKE_FLAG_INITIATOR, 0x08);
        assert_eq!(IKE_FLAG_VERSION, 0x10);
        assert_eq!(IKE_FLAG_RESPONSE, 0x20);
    }

    #[test]
    fn header_length_is_twenty_eight_octets() {
        // RFC 7296 §3.1: the fixed IKE header is 28 octets.
        assert_eq!(IKE_HEADER_LEN, 28);
    }

    #[test]
    fn new_applies_packet_builder_defaults() {
        let header = IkeHeader::new();

        // Version defaults to IKEv2; responder SPI and message ID to the
        // IKE_SA_INIT-request zero values; auto-filled fields stay unset.
        assert_eq!(header.version_value(), Some(IKE_VERSION_2));
        assert_eq!(header.responder_spi_value(), Some(0));
        assert_eq!(header.message_id_value(), Some(0));
        assert_eq!(header.initiator_spi_value(), None);
        assert_eq!(header.next_payload_value(), None);
        assert_eq!(header.exchange_type_value(), None);
        assert_eq!(header.flags_value(), None);
        assert_eq!(header.length_value(), None);
    }

    // --- builder setters --------------------------------------------------

    #[test]
    fn setters_mark_fields_and_flag_helpers_or_in_bits() {
        let header = IkeHeader::new()
            .initiator_spi(0x0102_0304_0506_0708)
            .responder_spi(0x1112_1314_1516_1718)
            .exchange(IKE_SA_INIT)
            .message_id(7)
            .initiator()
            .response();

        assert_eq!(header.initiator_spi_value(), Some(0x0102_0304_0506_0708));
        assert_eq!(header.responder_spi_value(), Some(0x1112_1314_1516_1718));
        assert_eq!(header.exchange_type_value(), Some(IKE_SA_INIT));
        assert_eq!(header.message_id_value(), Some(7));
        // initiator() then response() OR their bits together (RFC 7296 §3.1).
        assert_eq!(
            header.flags_value(),
            Some(IKE_FLAG_INITIATOR | IKE_FLAG_RESPONSE)
        );
    }

    // --- Layer::compile auto-fill -----------------------------------------

    use crate::packet::{LayerContext, Packet, Raw};

    /// Compile a single-layer `IkeHeader` packet and return its 28-octet header.
    fn compile_header(header: IkeHeader) -> Vec<u8> {
        let packet = Packet::from_layer(header);
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    /// Compile `IkeHeader / Raw(body)` and return only the IKE header bytes.
    fn compile_header_with_body(header: IkeHeader, body: &[u8]) -> Vec<u8> {
        let packet: Packet = Packet::from_layer(header) / Raw::from_bytes(body);
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    #[test]
    fn compile_no_payloads_emits_length_twenty_eight() {
        // RFC 7296 §3.1: with no following payloads the message Length is the
        // 28-octet header alone, and Next Payload defaults to NO_NEXT_PAYLOAD (0).
        let header = IkeHeader::new().exchange(IKE_SA_INIT).initiator();
        let bytes = compile_header(header);

        assert_eq!(bytes.len(), IKE_HEADER_LEN);
        // Next Payload (offset 16) defaults to 0.
        assert_eq!(bytes[16], NO_NEXT_PAYLOAD);
        // Version (offset 17) defaults to IKEv2.
        assert_eq!(bytes[17], IKE_VERSION_2);
        // Exchange Type (offset 18) and Flags (offset 19) reflect the builder.
        assert_eq!(bytes[18], IKE_SA_INIT);
        assert_eq!(bytes[19], IKE_FLAG_INITIATOR);
        // Length (offset 24..28) is the 28-octet header (big-endian).
        assert_eq!(&bytes[24..28], &(IKE_HEADER_LEN as u32).to_be_bytes());
    }

    #[test]
    fn compile_with_raw_payload_adds_payload_to_length() {
        // The auto-filled Length is 28 + the following payload bytes (RFC 7296
        // §3.1). A 9-octet Raw "payload" yields Length 37.
        let body = [0xAAu8; 9];
        let bytes = compile_header_with_body(IkeHeader::new().exchange(IKE_AUTH), &body);

        assert_eq!(bytes.len(), IKE_HEADER_LEN);
        let length = u32::from_be_bytes(bytes[24..28].try_into().unwrap());
        assert_eq!(length as usize, IKE_HEADER_LEN + body.len());
    }

    #[test]
    fn compile_keeps_caller_length_override() {
        // A caller-set Length wins over the computed value, even when it
        // disagrees with the actual message size (deliberately malformed).
        let body = [0xBBu8; 4];
        let bytes =
            compile_header_with_body(IkeHeader::new().exchange(IKE_SA_INIT).length(0x1234), &body);

        let length = u32::from_be_bytes(bytes[24..28].try_into().unwrap());
        assert_eq!(length, 0x1234);
    }

    #[test]
    fn compile_keeps_caller_next_payload_override() {
        // A caller-set Next Payload wins over the NO_NEXT_PAYLOAD default.
        let bytes = compile_header(IkeHeader::new().exchange(IKE_SA_INIT).next_payload(33));
        assert_eq!(bytes[16], 33);
    }

    #[test]
    fn compile_emits_spis_big_endian() {
        // Initiator/Responder SPIs occupy the first 16 octets, big-endian.
        let header = IkeHeader::new()
            .initiator_spi(0x0102_0304_0506_0708)
            .responder_spi(0x1112_1314_1516_1718)
            .exchange(IKE_SA_INIT);
        let bytes = compile_header(header);

        assert_eq!(&bytes[0..8], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&bytes[8..16], &0x1112_1314_1516_1718u64.to_be_bytes());
    }
}
