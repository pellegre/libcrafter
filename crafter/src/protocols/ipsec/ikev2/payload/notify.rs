//! IKEv2 Notify (N) payload, type 41 (RFC 7296 §3.10).
//!
//! The Notify payload carries error and status information between IKE peers.
//! The body that follows the 4-octet generic payload header (emitted by
//! [`write_generic_payload_header`]) is:
//!
//! ```text
//!  Protocol ID (1) | SPI Size (1) | Notify Message Type (2)
//!    | SPI (variable) | Notification Data (variable)
//! ```
//!
//! (RFC 7296 §3.10). The Protocol ID names the protocol (IKE/AH/ESP) the Notify
//! is about, or `0` when the notification concerns no specific SA. The SPI Size
//! gives the length of the SPI field (`0` when no SPI is present); for AH and ESP
//! it is normally 4. The Notify Message Type is the [`NotifyType`] codepoint:
//! values `1..=16383` are errors, `16384..=65535` are status notifications
//! (RFC 7296 §3.10.1). The Notification Data is type-specific opaque bytes.
//!
//! This crate models the **wire form only** — the SPI and Notification Data are
//! opaque bytes and no per-type semantics are interpreted. The generic-header
//! Payload Length and the SPI Size are auto-filled by `compile()` (the SPI Size
//! from the SPI length unless overridden), while any caller-pinned value (Next
//! Payload, Payload Length, Critical, SPI Size) is emitted verbatim so
//! deliberately malformed Notify payloads can be constructed for testing.

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::ipsec::ikev2::payload::{
    write_generic_payload_header, IkePayload, PayloadHeaderFields, PayloadType,
};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::CrafterError;
use crate::Result;

/// Layer name for the IKEv2 Notify payload, registered in
/// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_NOTIFY_PAYLOAD_NAME: &str = "IkeNotifyPayload";

/// Length of the fixed Notify payload body header (RFC 7296 §3.10): Protocol ID
/// (1) + SPI Size (1) + Notify Message Type (2) = 4 octets, excluding the
/// variable SPI and Notification Data that follow.
pub const NOTIFY_FIXED_LEN: usize = 4;

// --- Protocol ID (RFC 7296 §3.10; shared with the SA-protocol numbering) -----

/// Protocol ID `0` — the Notify concerns no specific protocol / SA
/// (RFC 7296 §3.10). Used when the SPI is absent (SPI Size `0`).
pub const NOTIFY_PROTOCOL_NONE: u8 = 0;
/// Protocol ID `1` — IKE (RFC 7296 §3.10).
pub const NOTIFY_PROTOCOL_IKE: u8 = 1;
/// Protocol ID `2` — AH (RFC 7296 §3.10).
pub const NOTIFY_PROTOCOL_AH: u8 = 2;
/// Protocol ID `3` — ESP (RFC 7296 §3.10).
pub const NOTIFY_PROTOCOL_ESP: u8 = 3;

// --- Notify Message Types (RFC 7296 §3.10.1; IANA "IKEv2 Notify Message
//     Types - Error / Status Types"). Authoritative IANA values; the manifest's
//     status table is off by 4 in the status range, see DESIGN_DECISIONS. ------

/// Error `1` — UNSUPPORTED_CRITICAL_PAYLOAD (RFC 7296 §3.10.1).
pub const NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD: u16 = 1;
/// Error `7` — INVALID_SYNTAX (RFC 7296 §3.10.1).
pub const NOTIFY_INVALID_SYNTAX: u16 = 7;
/// Error `14` — NO_PROPOSAL_CHOSEN (RFC 7296 §3.10.1).
pub const NOTIFY_NO_PROPOSAL_CHOSEN: u16 = 14;
/// Error `17` — INVALID_KE_PAYLOAD (RFC 7296 §3.10.1).
pub const NOTIFY_INVALID_KE_PAYLOAD: u16 = 17;
/// Error `24` — AUTHENTICATION_FAILED (RFC 7296 §3.10.1).
pub const NOTIFY_AUTHENTICATION_FAILED: u16 = 24;
/// Status `16384` — INITIAL_CONTACT (RFC 7296 §3.10.1).
pub const NOTIFY_INITIAL_CONTACT: u16 = 16384;
/// Status `16385` — SET_WINDOW_SIZE (RFC 7296 §3.10.1).
pub const NOTIFY_SET_WINDOW_SIZE: u16 = 16385;
/// Status `16386` — ADDITIONAL_TS_POSSIBLE (RFC 7296 §3.10.1).
pub const NOTIFY_ADDITIONAL_TS_POSSIBLE: u16 = 16386;
/// Status `16387` — IPCOMP_SUPPORTED (RFC 7296 §3.10.1).
pub const NOTIFY_IPCOMP_SUPPORTED: u16 = 16387;
/// Status `16388` — NAT_DETECTION_SOURCE_IP (RFC 7296 §3.10.1).
pub const NOTIFY_NAT_DETECTION_SOURCE_IP: u16 = 16388;
/// Status `16389` — NAT_DETECTION_DESTINATION_IP (RFC 7296 §3.10.1).
pub const NOTIFY_NAT_DETECTION_DESTINATION_IP: u16 = 16389;
/// Status `16390` — COOKIE (RFC 7296 §3.10.1).
pub const NOTIFY_COOKIE: u16 = 16390;
/// Status `16391` — USE_TRANSPORT_MODE (RFC 7296 §3.10.1).
pub const NOTIFY_USE_TRANSPORT_MODE: u16 = 16391;
/// Status `16393` — REKEY_SA (RFC 7296 §3.10.1).
pub const NOTIFY_REKEY_SA: u16 = 16393;

/// An IKEv2 Notify Message Type (RFC 7296 §3.10.1; IANA "IKEv2 Notify Message
/// Types" registries).
///
/// Values `1..=16383` are error types and `16384..=65535` are status types
/// (RFC 7296 §3.10.1). Only the common types referenced by the manifest are
/// given named variants; any other codepoint is preserved as
/// [`NotifyType::Unknown`] so a decoded value round-trips byte-for-byte and the
/// crate never rejects an unrecognized Notify type (the IANA registry remains
/// the authority).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotifyType {
    /// `1` — UNSUPPORTED_CRITICAL_PAYLOAD (error).
    UnsupportedCriticalPayload,
    /// `7` — INVALID_SYNTAX (error).
    InvalidSyntax,
    /// `14` — NO_PROPOSAL_CHOSEN (error).
    NoProposalChosen,
    /// `17` — INVALID_KE_PAYLOAD (error).
    InvalidKePayload,
    /// `24` — AUTHENTICATION_FAILED (error).
    AuthenticationFailed,
    /// `16384` — INITIAL_CONTACT (status).
    InitialContact,
    /// `16385` — SET_WINDOW_SIZE (status).
    SetWindowSize,
    /// `16386` — ADDITIONAL_TS_POSSIBLE (status).
    AdditionalTsPossible,
    /// `16387` — IPCOMP_SUPPORTED (status).
    IpcompSupported,
    /// `16388` — NAT_DETECTION_SOURCE_IP (status).
    NatDetectionSourceIp,
    /// `16389` — NAT_DETECTION_DESTINATION_IP (status).
    NatDetectionDestinationIp,
    /// `16390` — COOKIE (status).
    Cookie,
    /// `16391` — USE_TRANSPORT_MODE (status).
    UseTransportMode,
    /// `16393` — REKEY_SA (status).
    RekeySa,
    /// Any Notify Message Type not named above, preserved verbatim.
    Unknown(u16),
}

impl NotifyType {
    /// The 16-bit Notify Message Type codepoint for this type (RFC 7296 §3.10.1).
    /// [`NotifyType::Unknown`] returns its preserved value.
    pub fn codepoint(self) -> u16 {
        match self {
            Self::UnsupportedCriticalPayload => NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD,
            Self::InvalidSyntax => NOTIFY_INVALID_SYNTAX,
            Self::NoProposalChosen => NOTIFY_NO_PROPOSAL_CHOSEN,
            Self::InvalidKePayload => NOTIFY_INVALID_KE_PAYLOAD,
            Self::AuthenticationFailed => NOTIFY_AUTHENTICATION_FAILED,
            Self::InitialContact => NOTIFY_INITIAL_CONTACT,
            Self::SetWindowSize => NOTIFY_SET_WINDOW_SIZE,
            Self::AdditionalTsPossible => NOTIFY_ADDITIONAL_TS_POSSIBLE,
            Self::IpcompSupported => NOTIFY_IPCOMP_SUPPORTED,
            Self::NatDetectionSourceIp => NOTIFY_NAT_DETECTION_SOURCE_IP,
            Self::NatDetectionDestinationIp => NOTIFY_NAT_DETECTION_DESTINATION_IP,
            Self::Cookie => NOTIFY_COOKIE,
            Self::UseTransportMode => NOTIFY_USE_TRANSPORT_MODE,
            Self::RekeySa => NOTIFY_REKEY_SA,
            Self::Unknown(value) => value,
        }
    }

    /// Whether this is an error-class Notify Message Type (`1..=16383`), per
    /// RFC 7296 §3.10.1. Status types are `16384..=65535`. Type `0` is reserved
    /// and classified here as neither error nor status (returns `false`).
    pub fn is_error(self) -> bool {
        let value = self.codepoint();
        (1..=16383).contains(&value)
    }

    /// Whether this is a status-class Notify Message Type (`16384..=65535`), per
    /// RFC 7296 §3.10.1.
    pub fn is_status(self) -> bool {
        self.codepoint() >= 16384
    }
}

impl From<u16> for NotifyType {
    /// Map a Notify Message Type codepoint to a [`NotifyType`], preserving an
    /// unrecognized value as [`NotifyType::Unknown`] (never erroring).
    fn from(value: u16) -> Self {
        match value {
            NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD => Self::UnsupportedCriticalPayload,
            NOTIFY_INVALID_SYNTAX => Self::InvalidSyntax,
            NOTIFY_NO_PROPOSAL_CHOSEN => Self::NoProposalChosen,
            NOTIFY_INVALID_KE_PAYLOAD => Self::InvalidKePayload,
            NOTIFY_AUTHENTICATION_FAILED => Self::AuthenticationFailed,
            NOTIFY_INITIAL_CONTACT => Self::InitialContact,
            NOTIFY_SET_WINDOW_SIZE => Self::SetWindowSize,
            NOTIFY_ADDITIONAL_TS_POSSIBLE => Self::AdditionalTsPossible,
            NOTIFY_IPCOMP_SUPPORTED => Self::IpcompSupported,
            NOTIFY_NAT_DETECTION_SOURCE_IP => Self::NatDetectionSourceIp,
            NOTIFY_NAT_DETECTION_DESTINATION_IP => Self::NatDetectionDestinationIp,
            NOTIFY_COOKIE => Self::Cookie,
            NOTIFY_USE_TRANSPORT_MODE => Self::UseTransportMode,
            NOTIFY_REKEY_SA => Self::RekeySa,
            other => Self::Unknown(other),
        }
    }
}

// `TryFrom<u16>` is provided automatically by the blanket
// `impl<T, U: Into<T>> TryFrom<U> for T` (`Error = Infallible`): unknown
// codepoints are preserved as `Unknown` rather than rejected, so the conversion
// never fails. This mirrors `PayloadType` and the SA algorithm enums.

impl From<NotifyType> for u16 {
    fn from(notify_type: NotifyType) -> Self {
        notify_type.codepoint()
    }
}

/// IKEv2 Notify (N) payload, type 41 (RFC 7296 §3.10).
///
/// Carries the Protocol ID, SPI, Notify Message Type, and Notification Data. As
/// a [`Layer`] it emits the 4-octet generic payload header (via
/// [`write_generic_payload_header`]) followed by the body `Protocol ID (1) | SPI
/// Size (1) | Notify Message Type (2) | SPI | Notification Data`. The
/// generic-header Next Payload, Critical flag, and Payload Length are the shared
/// overridable fields carried in [`PayloadHeaderFields`].
///
/// The SPI Size is auto-filled from the SPI length unless the caller pins it, so
/// a deliberately inconsistent SPI Size can be built for malformed testing.
#[derive(Debug, Clone)]
pub struct IkeNotifyPayload {
    /// Protocol ID (RFC 7296 §3.10; see `NOTIFY_PROTOCOL_*`).
    protocol_id: Field<u8>,
    /// SPI Size override (RFC 7296 §3.10); auto-filled from the SPI length.
    spi_size: Field<u8>,
    /// Notify Message Type (RFC 7296 §3.10.1; see [`NotifyType`]).
    notify_type: Field<u16>,
    /// Security Parameter Index: opaque bytes (RFC 7296 §3.10).
    spi: Vec<u8>,
    /// Notification Data: type-specific opaque bytes (RFC 7296 §3.10).
    data: Vec<u8>,
    /// Shared generic-payload-header overrides (Next Payload, Length, Critical).
    header: PayloadHeaderFields,
}

impl IkeNotifyPayload {
    /// A Notify payload for the given Protocol ID and Notify Message Type,
    /// carrying the given Notification Data and no SPI (RFC 7296 §3.10).
    ///
    /// The Notify Message Type accepts anything convertible into a [`NotifyType`]
    /// (a named variant, a `NotifyType::Unknown`, or a bare `u16`). The SPI is
    /// empty by default (SPI Size auto-fills to `0`); add one with
    /// [`IkeNotifyPayload::spi`].
    pub fn new(
        protocol_id: u8,
        notify_type: impl Into<NotifyType>,
        data: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            protocol_id: Field::user(protocol_id),
            spi_size: Field::unset(),
            notify_type: Field::user(notify_type.into().codepoint()),
            spi: Vec::new(),
            data: data.into(),
            header: PayloadHeaderFields::new(),
        }
    }

    /// Set the Protocol ID (RFC 7296 §3.10; see `NOTIFY_PROTOCOL_*`).
    pub fn protocol_id(mut self, protocol_id: u8) -> Self {
        self.protocol_id.set_user(protocol_id);
        self
    }

    /// Set the Notify Message Type (RFC 7296 §3.10.1), accepting a named
    /// [`NotifyType`], a `NotifyType::Unknown`, or a bare `u16`.
    pub fn notify_type(mut self, notify_type: impl Into<NotifyType>) -> Self {
        self.notify_type.set_user(notify_type.into().codepoint());
        self
    }

    /// Set the SPI bytes (RFC 7296 §3.10). The SPI Size auto-fills to this
    /// length unless explicitly pinned with [`IkeNotifyPayload::spi_size`].
    pub fn spi(mut self, spi: impl Into<Vec<u8>>) -> Self {
        self.spi = spi.into();
        self
    }

    /// Pin the SPI Size explicitly (RFC 7296 §3.10), overriding the value
    /// auto-derived from the SPI length. A deliberately inconsistent value is
    /// emitted verbatim for malformed testing.
    pub fn spi_size(mut self, spi_size: u8) -> Self {
        self.spi_size.set_user(spi_size);
        self
    }

    /// Set the Notification Data bytes (RFC 7296 §3.10), consuming-builder style.
    pub fn data(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.data = data.into();
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

    /// The Protocol ID (RFC 7296 §3.10).
    pub fn protocol_id_value(&self) -> u8 {
        self.protocol_id.value().copied().unwrap_or(0)
    }

    /// The effective SPI Size (RFC 7296 §3.10): the caller-pinned override when
    /// set, otherwise the SPI byte length truncated to 8 bits.
    pub fn effective_spi_size(&self) -> u8 {
        self.spi_size
            .value()
            .copied()
            .unwrap_or(self.spi.len() as u8)
    }

    /// The Notify Message Type as a [`NotifyType`] (RFC 7296 §3.10.1).
    pub fn notify_message_type(&self) -> NotifyType {
        NotifyType::from(self.notify_type.value().copied().unwrap_or(0))
    }

    /// The raw Notify Message Type codepoint (RFC 7296 §3.10.1).
    pub fn notify_message_type_value(&self) -> u16 {
        self.notify_type.value().copied().unwrap_or(0)
    }

    /// The SPI bytes (RFC 7296 §3.10).
    pub fn spi_bytes(&self) -> &[u8] {
        &self.spi
    }

    /// The Notification Data bytes (RFC 7296 §3.10).
    pub fn data_bytes(&self) -> &[u8] {
        &self.data
    }

    /// The Notify body (everything after the 4-octet generic header), per
    /// RFC 7296 §3.10: Protocol ID (1) | SPI Size (1) | Notify Message Type (2) |
    /// SPI | Notification Data.
    fn notify_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NOTIFY_FIXED_LEN + self.spi.len() + self.data.len());
        out.push(self.protocol_id_value());
        out.push(self.effective_spi_size());
        out.extend_from_slice(&self.notify_message_type_value().to_be_bytes());
        out.extend_from_slice(&self.spi);
        out.extend_from_slice(&self.data);
        out
    }
}

impl IkePayload for IkeNotifyPayload {
    fn payload_type(&self) -> PayloadType {
        PayloadType::Notify
    }

    fn payload_body(&self, _ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        Ok(self.notify_body())
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

impl Layer for IkeNotifyPayload {
    fn name(&self) -> &'static str {
        IKE_NOTIFY_PAYLOAD_NAME
    }

    fn summary(&self) -> String {
        format!(
            "IkeNotifyPayload(protocol_id={}, notify_type={}, spi_len={}, data_len={})",
            self.protocol_id_value(),
            self.notify_message_type_value(),
            self.spi.len(),
            self.data.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("protocol_id", self.protocol_id_value().to_string()),
            ("notify_type", self.notify_message_type_value().to_string()),
            ("spi_size", self.effective_spi_size().to_string()),
            ("spi_len", self.spi.len().to_string()),
            ("data_len", self.data.len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        super::GENERIC_PAYLOAD_HEADER_LEN + NOTIFY_FIXED_LEN + self.spi.len() + self.data.len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Emit the 4-octet generic payload header (auto Next Payload from the
        // following payload and auto Payload Length unless overridden), then the
        // Notify body (Protocol ID | SPI Size | Notify Message Type | SPI |
        // Notification Data).
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

    impl_layer_object!(IkeNotifyPayload);
}

impl_layer_div!(IkeNotifyPayload);

// --- Local parse helper (Step 45 closes the full registry decode) -----------

/// Parse a Notify payload **body** (the bytes after the 4-octet generic header)
/// per RFC 7296 §3.10. Local to this step; the registry-driven chain decode
/// lands in Step 45.
///
/// The SPI is read using the on-wire SPI Size; a SPI Size larger than the
/// remaining bytes is a structured error rather than a panic. The Notification
/// Data is the remainder of the body. Decoded fields are stored with
/// `Field::user`, and the on-wire SPI Size is pinned so a re-compile reproduces
/// the bytes exactly even when it disagrees with the SPI length.
pub(crate) fn parse_notify_payload_body(bytes: &[u8]) -> Result<IkeNotifyPayload> {
    if bytes.len() < NOTIFY_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ikev2.notify",
            NOTIFY_FIXED_LEN,
            bytes.len(),
        ));
    }
    let protocol_id = bytes[0];
    let spi_size = bytes[1] as usize;
    let notify_type = u16::from_be_bytes([bytes[2], bytes[3]]);

    let spi_end = NOTIFY_FIXED_LEN + spi_size;
    if bytes.len() < spi_end {
        return Err(CrafterError::buffer_too_short(
            "ikev2.notify.spi",
            spi_end,
            bytes.len(),
        ));
    }
    let spi = bytes[NOTIFY_FIXED_LEN..spi_end].to_vec();
    let data = bytes[spi_end..].to_vec();

    Ok(IkeNotifyPayload::new(protocol_id, notify_type, data)
        .spi(spi)
        // Pin the on-wire SPI Size so a re-compile is byte-exact even if it
        // disagrees with the SPI length (malformed inputs round-trip).
        .spi_size(bytes[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LayerContext, Packet, Raw};
    use crate::protocols::ipsec::ikev2::payload::GENERIC_PAYLOAD_HEADER_LEN;

    /// Compile a standalone Notify payload and return its full bytes (generic
    /// header + body), gathered through a one-layer packet.
    fn compile_payload(payload: IkeNotifyPayload) -> Vec<u8> {
        let packet = Packet::from_layer(payload);
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    /// A representative NAT_DETECTION_SOURCE_IP Notify (RFC 7296 §2.23): no SPI,
    /// Protocol ID 0, and a 20-octet SHA-1 NAT-detection digest as data.
    fn nat_detection_source_payload() -> IkeNotifyPayload {
        IkeNotifyPayload::new(
            NOTIFY_PROTOCOL_NONE,
            NotifyType::NatDetectionSourceIp,
            (0u8..20).collect::<Vec<u8>>(),
        )
    }

    #[test]
    fn notify_constants_match_manifest() {
        // docs/ipsec-rfc-manifest.md "IKEv2 Notify Message Types" /
        // RFC 7296 §3.10.1 / IANA. The manifest's error-range codepoints match
        // IANA exactly; these are the authoritative values used here.
        assert_eq!(NOTIFY_INVALID_SYNTAX, 7);
        assert_eq!(NOTIFY_NO_PROPOSAL_CHOSEN, 14);
        assert_eq!(NOTIFY_INVALID_KE_PAYLOAD, 17);
        assert_eq!(NOTIFY_AUTHENTICATION_FAILED, 24);
        // §3.10 fixed body header width and Protocol IDs.
        assert_eq!(NOTIFY_FIXED_LEN, 4);
        assert_eq!(NOTIFY_PROTOCOL_IKE, 1);
        assert_eq!(NOTIFY_PROTOCOL_AH, 2);
        assert_eq!(NOTIFY_PROTOCOL_ESP, 3);
    }

    #[test]
    fn notify_status_codepoints_match_iana() {
        // RFC 7296 §3.10.1 / IANA "Status Types": INITIAL_CONTACT is 16384 and
        // the NAT-detection / REKEY_SA codepoints follow from it. (The manifest's
        // status table is off by 4 in this range; IANA is the authority — see the
        // step notes.)
        assert_eq!(NOTIFY_INITIAL_CONTACT, 16384);
        assert_eq!(NOTIFY_NAT_DETECTION_SOURCE_IP, 16388);
        assert_eq!(NOTIFY_NAT_DETECTION_DESTINATION_IP, 16389);
        assert_eq!(NOTIFY_USE_TRANSPORT_MODE, 16391);
        assert_eq!(NOTIFY_REKEY_SA, 16393);
    }

    #[test]
    fn notify_type_round_trips_through_u16() {
        // u16 -> NotifyType -> u16 is the identity for every named codepoint and
        // for unassigned codepoints (preserved verbatim as Unknown).
        for &value in &[
            NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD,
            NOTIFY_INVALID_SYNTAX,
            NOTIFY_NO_PROPOSAL_CHOSEN,
            NOTIFY_INVALID_KE_PAYLOAD,
            NOTIFY_AUTHENTICATION_FAILED,
            NOTIFY_INITIAL_CONTACT,
            NOTIFY_SET_WINDOW_SIZE,
            NOTIFY_ADDITIONAL_TS_POSSIBLE,
            NOTIFY_IPCOMP_SUPPORTED,
            NOTIFY_NAT_DETECTION_SOURCE_IP,
            NOTIFY_NAT_DETECTION_DESTINATION_IP,
            NOTIFY_COOKIE,
            NOTIFY_USE_TRANSPORT_MODE,
            NOTIFY_REKEY_SA,
            0,
            9999,
            40000,
            65535,
        ] {
            let notify_type = NotifyType::from(value);
            assert_eq!(notify_type.codepoint(), value);
            assert_eq!(u16::from(notify_type), value);
        }
    }

    #[test]
    fn unknown_notify_type_is_preserved() {
        // A codepoint outside the named set survives as Unknown and round-trips.
        let unassigned = 16450u16;
        assert_eq!(
            NotifyType::from(unassigned),
            NotifyType::Unknown(unassigned)
        );
        assert_eq!(NotifyType::Unknown(unassigned).codepoint(), unassigned);
    }

    #[test]
    fn notify_type_error_status_classification() {
        // RFC 7296 §3.10.1: 1..=16383 errors, 16384..=65535 status.
        assert!(NotifyType::InvalidSyntax.is_error());
        assert!(!NotifyType::InvalidSyntax.is_status());
        assert!(NotifyType::NatDetectionSourceIp.is_status());
        assert!(!NotifyType::NatDetectionSourceIp.is_error());
        // An unknown status-range codepoint classifies as status.
        assert!(NotifyType::from(40000).is_status());
        // An unknown error-range codepoint classifies as error.
        assert!(NotifyType::from(100).is_error());
    }

    #[test]
    fn payload_type_is_notify() {
        let payload = nat_detection_source_payload();
        assert_eq!(payload.payload_type(), PayloadType::Notify);
        // The layer name is registered for the chain next-payload derivation.
        assert_eq!(payload.name(), IKE_NOTIFY_PAYLOAD_NAME);
    }

    #[test]
    fn body_lays_out_fixed_header_then_spi_and_data() {
        // RFC 7296 §3.10: Protocol ID | SPI Size | Notify Message Type | SPI |
        // Notification Data. NAT_DETECTION_SOURCE_IP carries no SPI.
        let payload = nat_detection_source_payload();
        let body = payload.notify_body();
        assert_eq!(body[0], NOTIFY_PROTOCOL_NONE); // Protocol ID.
        assert_eq!(body[1], 0); // SPI Size (no SPI).
        assert_eq!(
            u16::from_be_bytes([body[2], body[3]]),
            NOTIFY_NAT_DETECTION_SOURCE_IP
        );
        assert_eq!(
            &body[NOTIFY_FIXED_LEN..],
            &(0u8..20).collect::<Vec<u8>>()[..]
        );
        assert_eq!(body.len(), NOTIFY_FIXED_LEN + 20);
    }

    #[test]
    fn spi_size_auto_fills_from_spi_length() {
        // With a 4-octet SPI, the SPI Size auto-fills to 4 and the body carries
        // the SPI between the fixed header and the data.
        let payload = IkeNotifyPayload::new(NOTIFY_PROTOCOL_ESP, NotifyType::RekeySa, vec![0xAAu8])
            .spi(vec![0x01u8, 0x02, 0x03, 0x04]);
        assert_eq!(payload.effective_spi_size(), 4);
        let body = payload.notify_body();
        assert_eq!(body[0], NOTIFY_PROTOCOL_ESP);
        assert_eq!(body[1], 4); // Auto SPI Size.
        assert_eq!(u16::from_be_bytes([body[2], body[3]]), NOTIFY_REKEY_SA);
        assert_eq!(&body[NOTIFY_FIXED_LEN..NOTIFY_FIXED_LEN + 4], &[1, 2, 3, 4]);
        assert_eq!(&body[NOTIFY_FIXED_LEN + 4..], &[0xAA]);
    }

    #[test]
    fn spi_size_override_is_honored() {
        // A pinned SPI Size is emitted verbatim even when it disagrees with the
        // actual SPI length (malformed input for testing).
        let payload =
            IkeNotifyPayload::new(NOTIFY_PROTOCOL_AH, NotifyType::Cookie, Vec::<u8>::new())
                .spi(vec![0x01u8, 0x02, 0x03, 0x04])
                .spi_size(99);
        assert_eq!(payload.effective_spi_size(), 99);
        assert_eq!(payload.notify_body()[1], 99);
    }

    #[test]
    fn payload_compiles_generic_header_then_body() {
        // The compiled payload is the 4-octet generic header (Next Payload 0
        // terminator, auto length) followed by the Notify body.
        let payload = nat_detection_source_payload();
        let bytes = compile_payload(payload.clone());

        assert_eq!(bytes[0], 0); // Next Payload terminator.
        assert_eq!(bytes[1], 0); // Critical clear.
        let payload_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(payload_len, bytes.len());
        assert_eq!(payload_len, payload.encoded_len());
        // The body after the generic header is the Notify body verbatim.
        assert_eq!(
            &bytes[GENERIC_PAYLOAD_HEADER_LEN..],
            &payload.notify_body()[..]
        );
    }

    #[test]
    fn payload_honors_generic_header_overrides() {
        // Caller-pinned Next Payload, Critical, and Payload Length survive.
        let payload = nat_detection_source_payload()
            .next_payload(41)
            .critical(true)
            .payload_length(0xBEEF);
        let bytes = compile_payload(payload);
        assert_eq!(bytes[0], 41);
        assert_eq!(bytes[1], 0x80); // Critical bit set.
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0xBEEF);
    }

    #[test]
    fn payload_chain_next_payload_points_at_notify() {
        // A Notify payload following another layer derives the preceding header's
        // Next Payload through payload_type_for_layer_name (registered this step)
        // as the Notify codepoint (41).
        use crate::protocols::ipsec::ikev2::payload::{
            following_next_payload, payload_type_for_layer_name, PAYLOAD_NOTIFY,
        };
        assert_eq!(
            payload_type_for_layer_name(IKE_NOTIFY_PAYLOAD_NAME),
            Some(PayloadType::Notify)
        );
        let packet: Packet =
            Packet::from_layer(Raw::from_bytes([0u8; 0])) / nat_detection_source_payload();
        let ctx = LayerContext::new(&packet, 0);
        assert_eq!(following_next_payload(&ctx), PAYLOAD_NOTIFY);
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        // Build a Notify with a SPI and data, compile to wire, parse the body
        // back, and confirm every field round-trips (Step 45 closes the registry
        // decode; this is the local parse helper for the step).
        let payload =
            IkeNotifyPayload::new(NOTIFY_PROTOCOL_ESP, NotifyType::RekeySa, vec![0xDE, 0xAD])
                .spi(vec![0x10u8, 0x20, 0x30, 0x40]);
        let bytes = compile_payload(payload.clone());

        let parsed = parse_notify_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(parsed.protocol_id_value(), NOTIFY_PROTOCOL_ESP);
        assert_eq!(parsed.effective_spi_size(), 4);
        assert_eq!(parsed.notify_message_type(), NotifyType::RekeySa);
        assert_eq!(parsed.spi_bytes(), &[0x10, 0x20, 0x30, 0x40]);
        assert_eq!(parsed.data_bytes(), &[0xDE, 0xAD]);
    }

    #[test]
    fn round_trip_nat_detection_recompiles_byte_for_byte() {
        // The NAT_DETECTION_SOURCE_IP Notify parses and re-compiles byte-exact.
        let payload = nat_detection_source_payload();
        let bytes = compile_payload(payload);
        let parsed = parse_notify_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        let recompiled = compile_payload(parsed);
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn parse_rejects_truncated_fixed_header() {
        // A buffer shorter than the fixed Notify body header is a structured
        // error, not a panic.
        let err = parse_notify_payload_body(&[0u8, 0, 0]).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }

    #[test]
    fn parse_rejects_spi_size_past_end() {
        // A SPI Size that runs past the available bytes is a structured error.
        // Protocol ID 3 | SPI Size 8 | type 16393 | (only 2 SPI bytes present).
        let body = [3u8, 8, 0x40, 0x09, 0xAA, 0xBB];
        let err = parse_notify_payload_body(&body).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }
}
