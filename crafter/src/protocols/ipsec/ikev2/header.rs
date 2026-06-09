//! IKEv2 message header and constants (RFC 7296 §3.1).
//!
//! Every IKEv2 message begins with a fixed 28-octet header: Initiator SPI (8) |
//! Responder SPI (8) | Next Payload (1) | Major/Minor Version (1) | Exchange
//! Type (1) | Flags (1) | Message ID (4) | Length (4) (RFC 7296 §3.1). IKEv2
//! messages are carried in UDP payloads, so the header composes after UDP.
//!
//! This module defines the [`IkeHeader`] field model and the IKEv2 codepoint
//! constants (version, exchange types, flag bits). The `Layer` impl, builder,
//! and decode paths are added by later steps; the struct and constants are the
//! Step 32 scope.

use crate::field::Field;

/// Length of the fixed IKEv2 message header (RFC 7296 §3.1): Initiator SPI (8) +
/// Responder SPI (8) + Next Payload (1) + Version (1) + Exchange Type (1) +
/// Flags (1) + Message ID (4) + Length (4) = 28 octets.
pub const IKE_HEADER_LEN: usize = 28;

/// IKE version octet for IKEv2: major version 2, minor version 0, packed as the
/// high and low nibbles of a single octet (RFC 7296 §3.1).
pub const IKE_VERSION_2: u8 = 0x20;

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
#[allow(dead_code)]
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
    #[allow(dead_code)]
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

    /// Stored IKE SA Initiator's SPI, when explicit or decoded.
    #[allow(dead_code)]
    pub fn initiator_spi_value(&self) -> Option<u64> {
        self.initiator_spi.value().copied()
    }

    /// Stored IKE SA Responder's SPI, when explicit, defaulted, or decoded.
    #[allow(dead_code)]
    pub fn responder_spi_value(&self) -> Option<u64> {
        self.responder_spi.value().copied()
    }

    /// Stored Next Payload value, when explicit or decoded.
    #[allow(dead_code)]
    pub fn next_payload_value(&self) -> Option<u8> {
        self.next_payload.value().copied()
    }

    /// Stored IKE version octet, when explicit, defaulted, or decoded.
    #[allow(dead_code)]
    pub fn version_value(&self) -> Option<u8> {
        self.version.value().copied()
    }

    /// Stored Exchange Type, when explicit or decoded.
    #[allow(dead_code)]
    pub fn exchange_type_value(&self) -> Option<u8> {
        self.exchange_type.value().copied()
    }

    /// Stored Flags octet, when explicit or decoded.
    #[allow(dead_code)]
    pub fn flags_value(&self) -> Option<u8> {
        self.flags.value().copied()
    }

    /// Stored Message ID, when explicit, defaulted, or decoded.
    #[allow(dead_code)]
    pub fn message_id_value(&self) -> Option<u32> {
        self.message_id.value().copied()
    }

    /// Stored total message Length, when explicit or decoded.
    #[allow(dead_code)]
    pub fn length_value(&self) -> Option<u32> {
        self.length.value().copied()
    }
}

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
}
