//! IKEv2 payloads and the generic-payload chain (RFC 7296 §3.2).
//!
//! Every IKEv2 payload begins with a fixed 4-octet generic payload header:
//! Next Payload (1) | Critical (C) + Reserved (1) | Payload Length (2)
//! (RFC 7296 §3.2). The Next Payload octet names the *type of the payload that
//! follows* in the chain (or `0` to terminate it), so the chain is linked head
//! to tail rather than each payload declaring its own type. The Payload Length
//! counts this payload including its 4-octet generic header.
//!
//! This module defines:
//!
//! - [`PayloadType`], the IANA IKEv2 Payload Type codepoints (RFC 7296 §3.2),
//!   preserving unrecognized values as [`PayloadType::Unknown`];
//! - [`IkePayload`], the trait every concrete payload layer (Steps 35–44)
//!   implements to expose its own [`PayloadType`] and its body bytes;
//! - [`write_generic_payload_header`], the shared helper that emits the 4-octet
//!   generic header with auto Next Payload (derived from the following payload
//!   layer) and auto Payload Length (`4 + body.len()`), honoring caller
//!   overrides; and
//! - [`following_ike_payload_type`], the name-based discovery used both here and
//!   by the IKE header to point Next Payload at the first/next payload in the
//!   chain.
//!
//! A `&dyn Layer` trait object cannot be downcast to `&dyn IkePayload` directly,
//! so the next-payload derivation maps the following layer's [`Layer::name`] to
//! its [`PayloadType`] through [`payload_type_for_layer_name`]. Each payload
//! layer added in a later step registers its name there; the map is the single
//! place the chain wiring consults.

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::Result;

pub mod auth;
pub mod cert;
pub mod config;
pub mod delete;
pub mod eap;
pub mod encrypted;
pub mod id;
pub mod ke;
pub mod nonce;
pub mod notify;
pub mod sa;
pub mod ts;
pub mod vendor;

pub use auth::{AuthMethod, IkeAuthPayload};
pub use cert::{CertEncoding, IkeCertPayload, IkeCertReqPayload};
pub use config::{CfgType, ConfigAttribute, IkeConfigPayload};
pub use delete::IkeDeletePayload;
pub use eap::IkeEapPayload;
pub use encrypted::{DecodedSk, IkeEncryptedPayload};
pub use id::{IdRole, IdType, IkeIdPayload};
pub use ke::IkeKePayload;
pub use nonce::IkeNoncePayload;
pub use notify::{IkeNotifyPayload, NotifyType};
pub use sa::{IkeSaPayload, Proposal, Transform, TransformAttribute};
pub use ts::{IkeTsPayload, TrafficSelector, TsRole};
pub use vendor::IkeVendorIdPayload;

/// Length of the IKEv2 generic payload header (RFC 7296 §3.2): Next Payload (1) +
/// Critical/Reserved (1) + Payload Length (2) = 4 octets.
pub const GENERIC_PAYLOAD_HEADER_LEN: usize = 4;

/// Payload-type value `No Next Payload` (RFC 7296 §3.2): the value `0` placed in
/// a Next Payload field to terminate the payload chain.
pub const PAYLOAD_TYPE_NONE: u8 = 0;

/// The Critical (C) flag bit of the second generic-header octet (RFC 7296 §3.2):
/// the high bit; the remaining 7 bits are reserved and sent as zero.
pub const PAYLOAD_CRITICAL_BIT: u8 = 0x80;

/// IKEv2 payload type (RFC 7296 §3.2; IANA "IKEv2 Payload Types" registry).
///
/// Each variant maps a generic-header Next Payload codepoint to the payload it
/// names. `None` (`0`) terminates the chain. An unrecognized codepoint is
/// preserved as [`PayloadType::Unknown`] so a decoded value round-trips
/// byte-for-byte and unknown payloads survive as preserved `Raw` payloads, per
/// the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadType {
    /// `0` — No Next Payload (chain terminator).
    None,
    /// `33` — Security Association (SA).
    SecurityAssociation,
    /// `34` — Key Exchange (KE).
    KeyExchange,
    /// `35` — Identification - Initiator (IDi).
    IdInitiator,
    /// `36` — Identification - Responder (IDr).
    IdResponder,
    /// `37` — Certificate (CERT).
    Certificate,
    /// `38` — Certificate Request (CERTREQ).
    CertificateRequest,
    /// `39` — Authentication (AUTH).
    Authentication,
    /// `40` — Nonce (Ni, Nr).
    Nonce,
    /// `41` — Notify (N).
    Notify,
    /// `42` — Delete (D).
    Delete,
    /// `43` — Vendor ID (V).
    VendorId,
    /// `44` — Traffic Selector - Initiator (TSi).
    TrafficSelectorInitiator,
    /// `45` — Traffic Selector - Responder (TSr).
    TrafficSelectorResponder,
    /// `46` — Encrypted and Authenticated (SK).
    Encrypted,
    /// `47` — Configuration (CP).
    Configuration,
    /// `48` — Extensible Authentication (EAP).
    ExtensibleAuthentication,
    /// Any codepoint not assigned above, preserved verbatim.
    Unknown(u8),
}

/// Payload Type `0` — No Next Payload (RFC 7296 §3.2).
pub const PAYLOAD_NONE: u8 = 0;
/// Payload Type `33` — Security Association (RFC 7296 §3.2).
pub const PAYLOAD_SA: u8 = 33;
/// Payload Type `34` — Key Exchange (RFC 7296 §3.2).
pub const PAYLOAD_KE: u8 = 34;
/// Payload Type `35` — Identification - Initiator (RFC 7296 §3.2).
pub const PAYLOAD_IDI: u8 = 35;
/// Payload Type `36` — Identification - Responder (RFC 7296 §3.2).
pub const PAYLOAD_IDR: u8 = 36;
/// Payload Type `37` — Certificate (RFC 7296 §3.2).
pub const PAYLOAD_CERT: u8 = 37;
/// Payload Type `38` — Certificate Request (RFC 7296 §3.2).
pub const PAYLOAD_CERTREQ: u8 = 38;
/// Payload Type `39` — Authentication (RFC 7296 §3.2).
pub const PAYLOAD_AUTH: u8 = 39;
/// Payload Type `40` — Nonce (RFC 7296 §3.2).
pub const PAYLOAD_NONCE: u8 = 40;
/// Payload Type `41` — Notify (RFC 7296 §3.2).
pub const PAYLOAD_NOTIFY: u8 = 41;
/// Payload Type `42` — Delete (RFC 7296 §3.2).
pub const PAYLOAD_DELETE: u8 = 42;
/// Payload Type `43` — Vendor ID (RFC 7296 §3.2).
pub const PAYLOAD_VENDOR_ID: u8 = 43;
/// Payload Type `44` — Traffic Selector - Initiator (RFC 7296 §3.2).
pub const PAYLOAD_TSI: u8 = 44;
/// Payload Type `45` — Traffic Selector - Responder (RFC 7296 §3.2).
pub const PAYLOAD_TSR: u8 = 45;
/// Payload Type `46` — Encrypted and Authenticated (RFC 7296 §3.2).
pub const PAYLOAD_SK: u8 = 46;
/// Payload Type `47` — Configuration (RFC 7296 §3.2).
pub const PAYLOAD_CP: u8 = 47;
/// Payload Type `48` — Extensible Authentication (RFC 7296 §3.2).
pub const PAYLOAD_EAP: u8 = 48;

impl PayloadType {
    /// The IKEv2 generic-header Next Payload codepoint for this payload type
    /// (RFC 7296 §3.2). [`PayloadType::Unknown`] returns its preserved value.
    pub fn codepoint(self) -> u8 {
        match self {
            Self::None => PAYLOAD_NONE,
            Self::SecurityAssociation => PAYLOAD_SA,
            Self::KeyExchange => PAYLOAD_KE,
            Self::IdInitiator => PAYLOAD_IDI,
            Self::IdResponder => PAYLOAD_IDR,
            Self::Certificate => PAYLOAD_CERT,
            Self::CertificateRequest => PAYLOAD_CERTREQ,
            Self::Authentication => PAYLOAD_AUTH,
            Self::Nonce => PAYLOAD_NONCE,
            Self::Notify => PAYLOAD_NOTIFY,
            Self::Delete => PAYLOAD_DELETE,
            Self::VendorId => PAYLOAD_VENDOR_ID,
            Self::TrafficSelectorInitiator => PAYLOAD_TSI,
            Self::TrafficSelectorResponder => PAYLOAD_TSR,
            Self::Encrypted => PAYLOAD_SK,
            Self::Configuration => PAYLOAD_CP,
            Self::ExtensibleAuthentication => PAYLOAD_EAP,
            Self::Unknown(value) => value,
        }
    }
}

impl From<u8> for PayloadType {
    /// Map an IKEv2 Next Payload codepoint to a [`PayloadType`], preserving an
    /// unrecognized value as [`PayloadType::Unknown`] (never erroring).
    fn from(value: u8) -> Self {
        match value {
            PAYLOAD_NONE => Self::None,
            PAYLOAD_SA => Self::SecurityAssociation,
            PAYLOAD_KE => Self::KeyExchange,
            PAYLOAD_IDI => Self::IdInitiator,
            PAYLOAD_IDR => Self::IdResponder,
            PAYLOAD_CERT => Self::Certificate,
            PAYLOAD_CERTREQ => Self::CertificateRequest,
            PAYLOAD_AUTH => Self::Authentication,
            PAYLOAD_NONCE => Self::Nonce,
            PAYLOAD_NOTIFY => Self::Notify,
            PAYLOAD_DELETE => Self::Delete,
            PAYLOAD_VENDOR_ID => Self::VendorId,
            PAYLOAD_TSI => Self::TrafficSelectorInitiator,
            PAYLOAD_TSR => Self::TrafficSelectorResponder,
            PAYLOAD_SK => Self::Encrypted,
            PAYLOAD_CP => Self::Configuration,
            PAYLOAD_EAP => Self::ExtensibleAuthentication,
            other => Self::Unknown(other),
        }
    }
}

// `TryFrom<u8>` is provided automatically by the blanket
// `impl<T, U: Into<T>> TryFrom<U> for T` (`Error = Infallible`): unknown
// codepoints are preserved as `Unknown` rather than rejected, so the conversion
// never fails. This mirrors `EncryptionAlgorithm` / `IntegrityAlgorithm`.

impl From<PayloadType> for u8 {
    fn from(payload_type: PayloadType) -> Self {
        payload_type.codepoint()
    }
}

/// A typed IKEv2 payload layer (RFC 7296 §3.2).
///
/// Every concrete payload layer added in Steps 35–44 implements this trait in
/// addition to [`Layer`]. It exposes the payload's own [`PayloadType`] — used to
/// fill the *preceding* generic header's Next Payload and the IKE header's Next
/// Payload — and the payload **body** (everything after the 4-octet generic
/// header). The generic header itself is emitted by
/// [`write_generic_payload_header`] so the shared chaining and length rules live
/// in one place; an implementor's [`Layer::compile`] writes the generic header
/// then appends `payload_body`.
///
/// The optional length/critical override fields keep the "honored overrides"
/// contract: a caller-set generic-header Next Payload, Payload Length, or
/// Critical flag is emitted verbatim, including a deliberately wrong value for
/// malformed testing.
pub trait IkePayload: Layer {
    /// This payload's own type codepoint (RFC 7296 §3.2). It populates the Next
    /// Payload of whichever header precedes this payload in the chain.
    fn payload_type(&self) -> PayloadType;

    /// The payload body: the bytes after the 4-octet generic payload header.
    ///
    /// [`write_generic_payload_header`] derives the auto Payload Length from this
    /// body (`4 + body.len()`), and an implementor's `compile` appends it after
    /// the generic header. The body is gathered with the same compile context so
    /// nested/context-dependent payloads (e.g. the SK payload's inner chain) see
    /// the packet.
    fn payload_body(&self, ctx: &LayerContext<'_>) -> Result<Vec<u8>>;

    /// Caller override for the generic-header Next Payload, if pinned.
    ///
    /// `None` lets [`write_generic_payload_header`] derive it from the following
    /// payload layer. `Some` is emitted verbatim, including a deliberately wrong
    /// value for malformed testing.
    fn next_payload_override(&self) -> Option<u8> {
        None
    }

    /// Caller override for the generic-header Payload Length, if pinned.
    ///
    /// `None` lets [`write_generic_payload_header`] compute `4 + body.len()`.
    /// `Some` is emitted verbatim (including a deliberately wrong value).
    fn payload_length_override(&self) -> Option<u16> {
        None
    }

    /// The Critical (C) flag for this payload (RFC 7296 §3.2). Defaults to clear
    /// (`false`); the 7 reserved bits are always sent as zero.
    fn critical(&self) -> bool {
        false
    }
}

/// Map a [`Layer::name`] to the [`PayloadType`] it carries, for IKEv2 payload
/// layers (RFC 7296 §3.2).
///
/// A `&dyn Layer` trait object cannot be downcast to `&dyn IkePayload`, so the
/// next-payload chain derivation discovers a following payload's type from its
/// stable layer name. Each concrete payload layer (Steps 35–44) adds its name
/// and type here; this is the single registry the chain wiring consults. A name
/// that is not an IKEv2 payload (a trailing `Raw`, a non-IKE layer) returns
/// `None`, which the chain treats as the end of the payload sequence.
pub fn payload_type_for_layer_name(name: &str) -> Option<PayloadType> {
    // Steps 35–44 extend this table as each payload layer lands. Keeping it in
    // one place keeps the chaining model maintainable: the generic-header writer
    // and the IKE header both derive Next Payload through this function. A name
    // that is not an IKEv2 payload (a trailing `Raw`, the `IkeHeader`) resolves
    // to `None`, terminating the chain.
    match name {
        sa::IKE_SA_PAYLOAD_NAME => Some(PayloadType::SecurityAssociation),
        ke::IKE_KE_PAYLOAD_NAME => Some(PayloadType::KeyExchange),
        id::IKE_IDI_PAYLOAD_NAME => Some(PayloadType::IdInitiator),
        id::IKE_IDR_PAYLOAD_NAME => Some(PayloadType::IdResponder),
        cert::IKE_CERT_PAYLOAD_NAME => Some(PayloadType::Certificate),
        cert::IKE_CERTREQ_PAYLOAD_NAME => Some(PayloadType::CertificateRequest),
        auth::IKE_AUTH_PAYLOAD_NAME => Some(PayloadType::Authentication),
        nonce::IKE_NONCE_PAYLOAD_NAME => Some(PayloadType::Nonce),
        notify::IKE_NOTIFY_PAYLOAD_NAME => Some(PayloadType::Notify),
        delete::IKE_DELETE_PAYLOAD_NAME => Some(PayloadType::Delete),
        vendor::IKE_VENDOR_ID_PAYLOAD_NAME => Some(PayloadType::VendorId),
        ts::IKE_TSI_PAYLOAD_NAME => Some(PayloadType::TrafficSelectorInitiator),
        ts::IKE_TSR_PAYLOAD_NAME => Some(PayloadType::TrafficSelectorResponder),
        config::IKE_CONFIG_PAYLOAD_NAME => Some(PayloadType::Configuration),
        eap::IKE_EAP_PAYLOAD_NAME => Some(PayloadType::ExtensibleAuthentication),
        encrypted::IKE_ENCRYPTED_PAYLOAD_NAME => Some(PayloadType::Encrypted),
        _ => None,
    }
}

/// The [`PayloadType`] of the payload that follows the current layer in the
/// chain, if any (RFC 7296 §3.2).
///
/// Used to fill a generic header's (or the IKE header's) Next Payload from the
/// *next* layer. Returns `None` when there is no following layer or the
/// following layer is not a known IKEv2 payload (so the chain terminates with
/// Next Payload `0`).
pub fn following_ike_payload_type(ctx: &LayerContext<'_>) -> Option<PayloadType> {
    let next = ctx.next()?;
    payload_type_for_layer_name(next.name())
}

/// The Next Payload codepoint to place in a generic (or IKE) header that
/// precedes the current layer's following payload (RFC 7296 §3.2).
///
/// Derives the codepoint from the following payload layer via
/// [`following_ike_payload_type`], defaulting to [`PAYLOAD_TYPE_NONE`] (`0`,
/// chain terminator) when no IKEv2 payload follows.
pub fn following_next_payload(ctx: &LayerContext<'_>) -> u8 {
    following_ike_payload_type(ctx)
        .map(PayloadType::codepoint)
        .unwrap_or(PAYLOAD_TYPE_NONE)
}

/// Write the 4-octet IKEv2 generic payload header (RFC 7296 §3.2) for a payload.
///
/// Emits `Next Payload (1) | Critical/Reserved (1) | Payload Length (2)`:
///
/// - **Next Payload** is the `next_payload` override when `Some`, otherwise the
///   type of the following payload layer derived from `ctx`
///   ([`following_next_payload`]) — `0` when none follows.
/// - **Critical/Reserved** sets the high [`PAYLOAD_CRITICAL_BIT`] when
///   `critical` is true; the 7 reserved bits are always zero.
/// - **Payload Length** is the `payload_length` override when `Some`, otherwise
///   `GENERIC_PAYLOAD_HEADER_LEN + body_len` (the payload including its generic
///   header), truncated to 16 bits.
///
/// Every override is emitted verbatim so a caller-set value — including a
/// deliberately wrong one for malformed testing — survives untouched.
pub fn write_generic_payload_header(
    out: &mut Vec<u8>,
    ctx: &LayerContext<'_>,
    next_payload: Option<u8>,
    critical: bool,
    payload_length: Option<u16>,
    body_len: usize,
) -> Result<()> {
    let next_payload = next_payload.unwrap_or_else(|| following_next_payload(ctx));
    let critical_octet = if critical { PAYLOAD_CRITICAL_BIT } else { 0 };
    let length = payload_length.unwrap_or_else(|| (GENERIC_PAYLOAD_HEADER_LEN + body_len) as u16);

    out.reserve(GENERIC_PAYLOAD_HEADER_LEN);
    out.push(next_payload);
    out.push(critical_octet);
    out.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

/// A shared generic-payload-header field set every concrete payload layer
/// embeds (RFC 7296 §3.2).
///
/// It carries the three caller-overridable generic-header fields — Next Payload,
/// the Critical flag, and Payload Length — as [`Field`]s so a builder setter can
/// pin any of them while `compile()` auto-fills the rest. A concrete payload
/// layer holds one of these alongside its body fields and forwards
/// [`PayloadHeaderFields::next_payload_override`],
/// [`PayloadHeaderFields::payload_length_override`], and
/// [`PayloadHeaderFields::critical`] into its [`IkePayload`] impl.
#[derive(Debug, Clone)]
pub struct PayloadHeaderFields {
    /// Generic-header Next Payload override; unset lets the chain derive it.
    next_payload: Field<u8>,
    /// Generic-header Payload Length override; unset lets `compile()` fill it.
    length: Field<u16>,
    /// Critical (C) flag; defaults to clear (`false`).
    critical: Field<bool>,
}

impl PayloadHeaderFields {
    /// A generic-header field set with builder defaults: Next Payload and
    /// Payload Length unset (auto-filled), Critical defaulted to clear.
    pub fn new() -> Self {
        Self {
            next_payload: Field::unset(),
            length: Field::unset(),
            critical: Field::defaulted(false),
        }
    }

    /// Pin the generic-header Next Payload explicitly (RFC 7296 §3.2).
    pub fn set_next_payload(&mut self, next_payload: u8) {
        self.next_payload.set_user(next_payload);
    }

    /// Pin the generic-header Payload Length explicitly (RFC 7296 §3.2).
    pub fn set_length(&mut self, length: u16) {
        self.length.set_user(length);
    }

    /// Set the Critical (C) flag explicitly (RFC 7296 §3.2).
    pub fn set_critical(&mut self, critical: bool) {
        self.critical.set_user(critical);
    }

    /// Caller-set Next Payload override, if any.
    pub fn next_payload_override(&self) -> Option<u8> {
        self.next_payload.value().copied()
    }

    /// Caller-set Payload Length override, if any.
    pub fn payload_length_override(&self) -> Option<u16> {
        self.length.value().copied()
    }

    /// The Critical (C) flag value (defaulted to clear).
    pub fn critical(&self) -> bool {
        self.critical.value().copied().unwrap_or(false)
    }
}

impl Default for PayloadHeaderFields {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_type_codepoints_match_manifest() {
        // docs/guide/ipsec.md "IKEv2 Payload Types" table / RFC 7296 §3.2.
        assert_eq!(PayloadType::None.codepoint(), 0);
        assert_eq!(PayloadType::SecurityAssociation.codepoint(), 33);
        assert_eq!(PayloadType::KeyExchange.codepoint(), 34);
        assert_eq!(PayloadType::IdInitiator.codepoint(), 35);
        assert_eq!(PayloadType::IdResponder.codepoint(), 36);
        assert_eq!(PayloadType::Certificate.codepoint(), 37);
        assert_eq!(PayloadType::CertificateRequest.codepoint(), 38);
        assert_eq!(PayloadType::Authentication.codepoint(), 39);
        assert_eq!(PayloadType::Nonce.codepoint(), 40);
        assert_eq!(PayloadType::Notify.codepoint(), 41);
        assert_eq!(PayloadType::Delete.codepoint(), 42);
        assert_eq!(PayloadType::VendorId.codepoint(), 43);
        assert_eq!(PayloadType::TrafficSelectorInitiator.codepoint(), 44);
        assert_eq!(PayloadType::TrafficSelectorResponder.codepoint(), 45);
        assert_eq!(PayloadType::Encrypted.codepoint(), 46);
        assert_eq!(PayloadType::Configuration.codepoint(), 47);
        assert_eq!(PayloadType::ExtensibleAuthentication.codepoint(), 48);
    }

    #[test]
    fn payload_type_constants_match_variants() {
        // The `PAYLOAD_*` codepoint constants and the enum variants agree.
        assert_eq!(
            PayloadType::from(PAYLOAD_SA),
            PayloadType::SecurityAssociation
        );
        assert_eq!(PayloadType::from(PAYLOAD_SK), PayloadType::Encrypted);
        assert_eq!(
            PayloadType::from(PAYLOAD_EAP),
            PayloadType::ExtensibleAuthentication
        );
        assert_eq!(PayloadType::None.codepoint(), PAYLOAD_TYPE_NONE);
    }

    #[test]
    fn payload_type_round_trips_through_u8() {
        // u8 -> PayloadType -> u8 is the identity for every assigned codepoint
        // (0, 33..=48) and for unassigned codepoints (preserved verbatim).
        for value in 0u8..=255 {
            let payload_type = PayloadType::from(value);
            assert_eq!(payload_type.codepoint(), value);
            assert_eq!(u8::from(payload_type), value);
        }
    }

    #[test]
    fn unknown_payload_type_is_preserved() {
        // A codepoint outside the assigned set survives as Unknown and
        // round-trips byte-for-byte.
        let unassigned = 200u8;
        assert_eq!(
            PayloadType::from(unassigned),
            PayloadType::Unknown(unassigned)
        );
        assert_eq!(PayloadType::Unknown(unassigned).codepoint(), unassigned);

        // The chain terminator (0) is `None`, not `Unknown`.
        assert_eq!(PayloadType::from(0), PayloadType::None);
        // The first reserved-after-EAP value (49, GSPM) is still unknown to this
        // build, so it is preserved verbatim rather than misclassified.
        assert_eq!(PayloadType::from(49), PayloadType::Unknown(49));
    }

    // The blanket `TryFrom<u8>` (from `From<u8>`) is infallible, so clippy flags
    // the explicit `try_into`; the point of this test is to exercise that
    // fallible surface, so the lint is allowed here (mirroring the SA algorithm
    // enums).
    #[allow(clippy::unnecessary_fallible_conversions)]
    #[test]
    fn try_from_u8_is_infallible_and_preserves_unknown() {
        // `TryFrom<u8>` comes from the blanket impl over `From<u8>`; it never
        // errors and preserves unknown codepoints, matching the algorithm enums.
        let known: PayloadType = u8::try_into(PAYLOAD_KE).unwrap();
        assert_eq!(known, PayloadType::KeyExchange);
        let unknown: PayloadType = u8::try_into(222u8).unwrap();
        assert_eq!(unknown, PayloadType::Unknown(222));
    }

    #[test]
    fn unknown_layer_name_has_no_payload_type() {
        // A non-IKEv2-payload layer name (e.g. a trailing Raw) resolves to no
        // payload type, so the chain terminates with Next Payload 0.
        assert_eq!(payload_type_for_layer_name("Raw"), None);
        assert_eq!(payload_type_for_layer_name("IkeHeader"), None);
    }

    #[test]
    fn header_fields_defaults_and_overrides() {
        // Defaults: Next Payload and Payload Length auto (unset), Critical clear.
        let mut fields = PayloadHeaderFields::new();
        assert_eq!(fields.next_payload_override(), None);
        assert_eq!(fields.payload_length_override(), None);
        assert!(!fields.critical());

        // Overrides are recorded and reported back verbatim.
        fields.set_next_payload(33);
        fields.set_length(0x1234);
        fields.set_critical(true);
        assert_eq!(fields.next_payload_override(), Some(33));
        assert_eq!(fields.payload_length_override(), Some(0x1234));
        assert!(fields.critical());
    }

    // --- generic header writer (chaining + length) ------------------------

    use crate::packet::{LayerContext, Packet, Raw};

    #[test]
    fn generic_header_auto_length_and_terminator_next_payload() {
        // With no following IKEv2 payload, Next Payload terminates the chain (0)
        // and Payload Length is 4 (generic header) + body length.
        let packet = Packet::from_layer(Raw::from_bytes([0u8; 0]));
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        let body = [0xAAu8; 6];
        write_generic_payload_header(&mut out, &ctx, None, false, None, body.len()).unwrap();

        assert_eq!(out.len(), GENERIC_PAYLOAD_HEADER_LEN);
        assert_eq!(out[0], PAYLOAD_TYPE_NONE); // Next Payload: end of chain.
        assert_eq!(out[1], 0); // Critical clear, reserved zero.
        let length = u16::from_be_bytes([out[2], out[3]]);
        assert_eq!(length as usize, GENERIC_PAYLOAD_HEADER_LEN + body.len());
    }

    #[test]
    fn generic_header_honors_overrides() {
        // Caller-set Next Payload, Critical, and Payload Length are emitted
        // verbatim, including a length that disagrees with the body (malformed).
        let packet = Packet::from_layer(Raw::from_bytes([0u8; 0]));
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        write_generic_payload_header(&mut out, &ctx, Some(PAYLOAD_KE), true, Some(0x00FF), 6)
            .unwrap();

        assert_eq!(out[0], PAYLOAD_KE);
        assert_eq!(out[1], PAYLOAD_CRITICAL_BIT);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 0x00FF);
    }

    #[test]
    fn following_next_payload_is_terminator_for_non_payload_tail() {
        // A trailing Raw is not an IKEv2 payload, so the derived Next Payload is
        // the chain terminator.
        let packet: Packet =
            Packet::from_layer(Raw::from_bytes([1u8, 2, 3])) / Raw::from_bytes([4u8]);
        let ctx = LayerContext::new(&packet, 0);
        assert_eq!(following_ike_payload_type(&ctx), None);
        assert_eq!(following_next_payload(&ctx), PAYLOAD_TYPE_NONE);
    }
}
