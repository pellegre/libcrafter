//! IKEv2 Identification payloads IDi (type 35) and IDr (type 36)
//! (RFC 7296 §3.5).
//!
//! The Identification payload carries the identity of the IKE peer. The body
//! that follows the 4-octet generic payload header (emitted by
//! [`write_generic_payload_header`]) is:
//!
//! ```text
//!  ID Type (1) | RESERVED (3) | Identification Data (variable)
//! ```
//!
//! (RFC 7296 §3.5). The ID Type names the format of the Identification Data —
//! an IPv4 or IPv6 address, a fully-qualified domain name, an RFC 822 e-mail
//! address, a key id, and so on (see [`IdType`]). The three RESERVED octets are
//! sent as zero. The Identification Data is the type-specific identity bytes.
//!
//! IDi (Identification - Initiator, type 35) and IDr (Identification -
//! Responder, type 36) share this exact wire form and differ only in their
//! payload type. This module models both with one [`IkeIdPayload`] carrying an
//! [`IdRole`], with [`IkeIdPayload::initiator`] / [`IkeIdPayload::responder`]
//! constructors (aliased as `IkeIdiPayload` / `IkeIdrPayload`) selecting the
//! role and therefore the reported [`PayloadType`] and [`Layer::name`].
//!
//! This crate models the **wire form only** — the Identification Data is opaque
//! bytes and no identity validation is performed. The generic-header Payload
//! Length is auto-filled by `compile()` from the body length, while any
//! caller-pinned value (Next Payload, Payload Length, Critical) is emitted
//! verbatim so deliberately malformed Identification payloads can be
//! constructed for testing.

use core::net::{Ipv4Addr, Ipv6Addr};

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::ipsec::ikev2::payload::{
    write_generic_payload_header, IkePayload, PayloadHeaderFields, PayloadType,
};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
#[cfg(test)]
use crate::CrafterError;
use crate::Result;

/// Layer name for the IKEv2 IDi (Identification - Initiator) payload, registered
/// in [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_IDI_PAYLOAD_NAME: &str = "IkeIdiPayload";

/// Layer name for the IKEv2 IDr (Identification - Responder) payload, registered
/// in [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_IDR_PAYLOAD_NAME: &str = "IkeIdrPayload";

/// Length of the fixed Identification payload body header (RFC 7296 §3.5): ID
/// Type (1) + RESERVED (3) = 4 octets, excluding the variable Identification
/// Data that follows.
pub const ID_FIXED_LEN: usize = 4;

// --- ID Type (RFC 7296 §3.5; IANA "IKEv2 Identification Payload ID Types") ----

/// ID Type `1` — ID_IPV4_ADDR: a single four-octet IPv4 address (RFC 7296 §3.5).
pub const ID_IPV4_ADDR: u8 = 1;
/// ID Type `2` — ID_FQDN: a fully-qualified domain name, not null-terminated
/// (RFC 7296 §3.5).
pub const ID_FQDN: u8 = 2;
/// ID Type `3` — ID_RFC822_ADDR: an RFC 822 e-mail address, not null-terminated
/// (RFC 7296 §3.5).
pub const ID_RFC822_ADDR: u8 = 3;
/// ID Type `5` — ID_IPV6_ADDR: a single sixteen-octet IPv6 address
/// (RFC 7296 §3.5).
pub const ID_IPV6_ADDR: u8 = 5;
/// ID Type `11` — ID_KEY_ID: an opaque octet stream that may identify a
/// pre-shared key or similar (RFC 7296 §3.5).
pub const ID_KEY_ID: u8 = 11;

/// An IKEv2 Identification payload ID Type (RFC 7296 §3.5; IANA "IKEv2
/// Identification Payload ID Types" registry).
///
/// Names the format of the Identification Data. Only the common types named in
/// RFC 7296 §3.5 are given variants; any other codepoint is preserved as
/// [`IdType::Unknown`] so a decoded value round-trips byte-for-byte and the
/// crate never rejects an unrecognized ID Type (the IANA registry remains the
/// authority).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdType {
    /// `1` — ID_IPV4_ADDR (a four-octet IPv4 address).
    Ipv4Addr,
    /// `2` — ID_FQDN (a fully-qualified domain name).
    Fqdn,
    /// `3` — ID_RFC822_ADDR (an RFC 822 e-mail address).
    Rfc822Addr,
    /// `5` — ID_IPV6_ADDR (a sixteen-octet IPv6 address).
    Ipv6Addr,
    /// `11` — ID_KEY_ID (an opaque key identifier).
    KeyId,
    /// Any ID Type not named above, preserved verbatim.
    Unknown(u8),
}

impl IdType {
    /// The 8-bit ID Type codepoint for this type (RFC 7296 §3.5).
    /// [`IdType::Unknown`] returns its preserved value.
    pub fn codepoint(self) -> u8 {
        match self {
            Self::Ipv4Addr => ID_IPV4_ADDR,
            Self::Fqdn => ID_FQDN,
            Self::Rfc822Addr => ID_RFC822_ADDR,
            Self::Ipv6Addr => ID_IPV6_ADDR,
            Self::KeyId => ID_KEY_ID,
            Self::Unknown(value) => value,
        }
    }
}

impl From<u8> for IdType {
    /// Map an ID Type codepoint to an [`IdType`], preserving an unrecognized
    /// value as [`IdType::Unknown`] (never erroring).
    fn from(value: u8) -> Self {
        match value {
            ID_IPV4_ADDR => Self::Ipv4Addr,
            ID_FQDN => Self::Fqdn,
            ID_RFC822_ADDR => Self::Rfc822Addr,
            ID_IPV6_ADDR => Self::Ipv6Addr,
            ID_KEY_ID => Self::KeyId,
            other => Self::Unknown(other),
        }
    }
}

// `TryFrom<u8>` is provided automatically by the blanket
// `impl<T, U: Into<T>> TryFrom<U> for T` (`Error = Infallible`): unknown
// codepoints are preserved as `Unknown` rather than rejected, so the conversion
// never fails. This mirrors `PayloadType` and the SA algorithm enums.

impl From<IdType> for u8 {
    fn from(id_type: IdType) -> Self {
        id_type.codepoint()
    }
}

/// Which Identification payload an [`IkeIdPayload`] is: IDi (Initiator, type 35)
/// or IDr (Responder, type 36) (RFC 7296 §3.5).
///
/// The two share the identical wire form and differ only in payload type and
/// layer name. The role selects both: [`IkePayload::payload_type`] and
/// [`Layer::name`] report the IDi/IDr value for the chosen role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdRole {
    /// IDi — Identification - Initiator (payload type 35).
    Initiator,
    /// IDr — Identification - Responder (payload type 36).
    Responder,
}

impl IdRole {
    /// The [`PayloadType`] this role reports (RFC 7296 §3.5): IDi → 35, IDr → 36.
    fn payload_type(self) -> PayloadType {
        match self {
            Self::Initiator => PayloadType::IdInitiator,
            Self::Responder => PayloadType::IdResponder,
        }
    }

    /// The stable [`Layer::name`] for this role, registered in
    /// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
    fn layer_name(self) -> &'static str {
        match self {
            Self::Initiator => IKE_IDI_PAYLOAD_NAME,
            Self::Responder => IKE_IDR_PAYLOAD_NAME,
        }
    }
}

/// IKEv2 Identification payload — IDi (type 35) or IDr (type 36)
/// (RFC 7296 §3.5).
///
/// Carries the ID Type and the opaque Identification Data, plus an [`IdRole`]
/// selecting whether this is the Initiator (IDi) or Responder (IDr) payload. As
/// a [`Layer`] it emits the 4-octet generic payload header (via
/// [`write_generic_payload_header`]) followed by the body `ID Type (1) |
/// RESERVED (3) | Identification Data`. The generic-header Next Payload,
/// Critical flag, and Payload Length are the shared overridable fields carried
/// in [`PayloadHeaderFields`].
#[derive(Debug, Clone)]
pub struct IkeIdPayload {
    /// Whether this is the IDi (Initiator) or IDr (Responder) payload.
    role: IdRole,
    /// ID Type (RFC 7296 §3.5; see `ID_*` constants and [`IdType`]).
    id_type: Field<u8>,
    /// Identification Data: the type-specific identity bytes (RFC 7296 §3.5).
    id_data: Vec<u8>,
    /// Shared generic-payload-header overrides (Next Payload, Length, Critical).
    header: PayloadHeaderFields,
}

impl IkeIdPayload {
    /// An Identification payload of the given role, ID Type, and Identification
    /// Data bytes (RFC 7296 §3.5).
    ///
    /// The ID Type accepts anything convertible into an [`IdType`] (a named
    /// variant, an `IdType::Unknown`, or a bare `u8`).
    pub fn new(role: IdRole, id_type: impl Into<IdType>, id_data: impl Into<Vec<u8>>) -> Self {
        Self {
            role,
            id_type: Field::user(id_type.into().codepoint()),
            id_data: id_data.into(),
            header: PayloadHeaderFields::new(),
        }
    }

    /// An IDi (Identification - Initiator, type 35) payload with the given ID
    /// Type and Identification Data (RFC 7296 §3.5).
    pub fn initiator(id_type: impl Into<IdType>, id_data: impl Into<Vec<u8>>) -> Self {
        Self::new(IdRole::Initiator, id_type, id_data)
    }

    /// An IDr (Identification - Responder, type 36) payload with the given ID
    /// Type and Identification Data (RFC 7296 §3.5).
    pub fn responder(id_type: impl Into<IdType>, id_data: impl Into<Vec<u8>>) -> Self {
        Self::new(IdRole::Responder, id_type, id_data)
    }

    /// An IDi payload identifying the initiator by an IPv4 address
    /// (ID_IPV4_ADDR; RFC 7296 §3.5). Use a documentation address
    /// (`192.0.2.0/24`) in tests and examples.
    pub fn initiator_ipv4(addr: Ipv4Addr) -> Self {
        Self::initiator(IdType::Ipv4Addr, addr.octets().to_vec())
    }

    /// An IDr payload identifying the responder by an IPv4 address
    /// (ID_IPV4_ADDR; RFC 7296 §3.5).
    pub fn responder_ipv4(addr: Ipv4Addr) -> Self {
        Self::responder(IdType::Ipv4Addr, addr.octets().to_vec())
    }

    /// An IDi payload identifying the initiator by an IPv6 address
    /// (ID_IPV6_ADDR; RFC 7296 §3.5). Use a documentation address
    /// (`2001:db8::/32`) in tests and examples.
    pub fn initiator_ipv6(addr: Ipv6Addr) -> Self {
        Self::initiator(IdType::Ipv6Addr, addr.octets().to_vec())
    }

    /// An IDr payload identifying the responder by an IPv6 address
    /// (ID_IPV6_ADDR; RFC 7296 §3.5).
    pub fn responder_ipv6(addr: Ipv6Addr) -> Self {
        Self::responder(IdType::Ipv6Addr, addr.octets().to_vec())
    }

    /// An IDi payload identifying the initiator by a fully-qualified domain name
    /// (ID_FQDN; RFC 7296 §3.5). The FQDN is sent as its UTF-8 bytes, not
    /// null-terminated.
    pub fn initiator_fqdn(fqdn: impl AsRef<str>) -> Self {
        Self::initiator(IdType::Fqdn, fqdn.as_ref().as_bytes().to_vec())
    }

    /// An IDr payload identifying the responder by a fully-qualified domain name
    /// (ID_FQDN; RFC 7296 §3.5).
    pub fn responder_fqdn(fqdn: impl AsRef<str>) -> Self {
        Self::responder(IdType::Fqdn, fqdn.as_ref().as_bytes().to_vec())
    }

    /// Set the ID Type (RFC 7296 §3.5), accepting a named [`IdType`], an
    /// `IdType::Unknown`, or a bare `u8`.
    pub fn id_type(mut self, id_type: impl Into<IdType>) -> Self {
        self.id_type.set_user(id_type.into().codepoint());
        self
    }

    /// Set the Identification Data bytes (RFC 7296 §3.5), consuming-builder
    /// style.
    pub fn id_data(mut self, id_data: impl Into<Vec<u8>>) -> Self {
        self.id_data = id_data.into();
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

    /// Whether this is the IDi (Initiator) or IDr (Responder) payload.
    pub fn role(&self) -> IdRole {
        self.role
    }

    /// The raw ID Type codepoint (RFC 7296 §3.5).
    pub fn id_type_value(&self) -> u8 {
        self.id_type.value().copied().unwrap_or(0)
    }

    /// The ID Type as an [`IdType`] (RFC 7296 §3.5).
    pub fn id_type_kind(&self) -> IdType {
        IdType::from(self.id_type_value())
    }

    /// The Identification Data bytes (RFC 7296 §3.5).
    pub fn id_data_bytes(&self) -> &[u8] {
        &self.id_data
    }

    /// The Identification body (everything after the 4-octet generic header),
    /// per RFC 7296 §3.5: ID Type (1) | RESERVED (3, zero) | Identification Data.
    fn id_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ID_FIXED_LEN + self.id_data.len());
        out.push(self.id_type_value());
        out.extend_from_slice(&[0u8, 0u8, 0u8]); // RESERVED (3 octets).
        out.extend_from_slice(&self.id_data);
        out
    }
}

impl IkePayload for IkeIdPayload {
    fn payload_type(&self) -> PayloadType {
        self.role.payload_type()
    }

    fn payload_body(&self, _ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        Ok(self.id_body())
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

impl Layer for IkeIdPayload {
    fn name(&self) -> &'static str {
        self.role.layer_name()
    }

    fn summary(&self) -> String {
        format!(
            "{}(id_type={}, id_data_len={})",
            self.role.layer_name(),
            self.id_type_value(),
            self.id_data.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("id_type", self.id_type_value().to_string()),
            ("id_data_len", self.id_data.len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        super::GENERIC_PAYLOAD_HEADER_LEN + ID_FIXED_LEN + self.id_data.len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Emit the 4-octet generic payload header (auto Next Payload from the
        // following payload and auto Payload Length unless overridden), then the
        // Identification body (ID Type | RESERVED | Identification Data).
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

    impl_layer_object!(IkeIdPayload);
}

impl_layer_div!(IkeIdPayload);

// --- Local parse helper (Step 45 closes the full registry decode) -----------

/// Parse an Identification payload **body** (the bytes after the 4-octet generic
/// header) per RFC 7296 §3.5, for the given [`IdRole`]. Local to this step; the
/// registry-driven chain decode lands in Step 45.
///
/// The ID Type is read from the first octet, the three RESERVED octets are
/// ignored, and the remainder is the Identification Data. A buffer shorter than
/// the fixed body header is a structured error rather than a panic. Decoded
/// fields are stored with `Field::user` so a re-compile reproduces the bytes
/// exactly.
#[cfg(test)]
fn parse_id_payload_body(role: IdRole, bytes: &[u8]) -> Result<IkeIdPayload> {
    if bytes.len() < ID_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ikev2.id",
            ID_FIXED_LEN,
            bytes.len(),
        ));
    }
    let id_type = bytes[0];
    // bytes[1..4] are RESERVED and ignored on decode.
    let id_data = bytes[ID_FIXED_LEN..].to_vec();
    Ok(IkeIdPayload::new(role, id_type, id_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LayerContext, Packet, Raw};
    use crate::protocols::ipsec::ikev2::payload::GENERIC_PAYLOAD_HEADER_LEN;

    /// Compile a standalone Identification payload and return its full bytes
    /// (generic header + body), gathered through a one-layer packet.
    fn compile_payload(payload: IkeIdPayload) -> Vec<u8> {
        let packet = Packet::from_layer(payload);
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    /// A representative IDi from a documentation IPv4 address (RFC 5737:
    /// `192.0.2.1`), ID_IPV4_ADDR.
    fn idi_ipv4_payload() -> IkeIdPayload {
        IkeIdPayload::initiator_ipv4(Ipv4Addr::new(192, 0, 2, 1))
    }

    /// A representative IDr from a fully-qualified domain name in the
    /// documentation domain, ID_FQDN.
    fn idr_fqdn_payload() -> IkeIdPayload {
        IkeIdPayload::responder_fqdn("responder.example.com")
    }

    #[test]
    fn id_constants_match_manifest() {
        // RFC 7296 §3.5 / IANA "IKEv2 Identification Payload ID Types".
        assert_eq!(ID_FIXED_LEN, 4);
        assert_eq!(ID_IPV4_ADDR, 1);
        assert_eq!(ID_FQDN, 2);
        assert_eq!(ID_RFC822_ADDR, 3);
        assert_eq!(ID_IPV6_ADDR, 5);
        assert_eq!(ID_KEY_ID, 11);
        // The IDi/IDr payload-type codepoints (RFC 7296 §3.2 / §3.5).
        assert_eq!(PayloadType::IdInitiator.codepoint(), 35);
        assert_eq!(PayloadType::IdResponder.codepoint(), 36);
    }

    #[test]
    fn id_type_round_trips_through_u8() {
        // u8 -> IdType -> u8 is the identity for every named codepoint and for
        // unassigned codepoints (preserved verbatim as Unknown).
        for value in 0u8..=255 {
            let id_type = IdType::from(value);
            assert_eq!(id_type.codepoint(), value);
            assert_eq!(u8::from(id_type), value);
        }
    }

    #[test]
    fn unknown_id_type_is_preserved() {
        // A codepoint outside the named set survives as Unknown and round-trips.
        let unassigned = 200u8;
        assert_eq!(IdType::from(unassigned), IdType::Unknown(unassigned));
        assert_eq!(IdType::Unknown(unassigned).codepoint(), unassigned);
        // The IANA-reserved value 4 (ID_IPV4_ADDR_SUBNET in IKEv1, unused in
        // IKEv2) is unknown to this build, preserved verbatim.
        assert_eq!(IdType::from(4), IdType::Unknown(4));
    }

    #[test]
    fn role_selects_payload_type_and_name() {
        // IDi reports payload type 35 / the IDi name; IDr reports 36 / the IDr
        // name. Both register for the chain next-payload derivation.
        let idi = idi_ipv4_payload();
        assert_eq!(idi.role(), IdRole::Initiator);
        assert_eq!(idi.payload_type(), PayloadType::IdInitiator);
        assert_eq!(idi.name(), IKE_IDI_PAYLOAD_NAME);

        let idr = idr_fqdn_payload();
        assert_eq!(idr.role(), IdRole::Responder);
        assert_eq!(idr.payload_type(), PayloadType::IdResponder);
        assert_eq!(idr.name(), IKE_IDR_PAYLOAD_NAME);
    }

    #[test]
    fn idi_ipv4_body_lays_out_type_reserved_then_address() {
        // RFC 7296 §3.5: ID Type (1) | RESERVED (3, zero) | Identification Data.
        // ID_IPV4_ADDR carries the four-octet documentation address 192.0.2.1.
        let payload = idi_ipv4_payload();
        let body = payload.id_body();
        assert_eq!(body[0], ID_IPV4_ADDR);
        assert_eq!(&body[1..4], &[0, 0, 0]); // RESERVED.
        assert_eq!(&body[ID_FIXED_LEN..], &[192, 0, 2, 1]);
        assert_eq!(body.len(), ID_FIXED_LEN + 4);
        assert_eq!(payload.id_type_kind(), IdType::Ipv4Addr);
    }

    #[test]
    fn idr_fqdn_body_lays_out_type_reserved_then_name() {
        // RFC 7296 §3.5: ID_FQDN carries the FQDN's UTF-8 bytes, not
        // null-terminated.
        let payload = idr_fqdn_payload();
        let body = payload.id_body();
        assert_eq!(body[0], ID_FQDN);
        assert_eq!(&body[1..4], &[0, 0, 0]); // RESERVED.
        assert_eq!(&body[ID_FIXED_LEN..], b"responder.example.com");
        assert_eq!(payload.id_type_kind(), IdType::Fqdn);
    }

    #[test]
    fn ipv6_constructor_uses_documentation_address() {
        // ID_IPV6_ADDR carries the sixteen-octet 2001:db8::1 documentation
        // address.
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let payload = IkeIdPayload::initiator_ipv6(addr);
        assert_eq!(payload.id_type_value(), ID_IPV6_ADDR);
        let body = payload.id_body();
        assert_eq!(&body[ID_FIXED_LEN..], &addr.octets());
        assert_eq!(body.len(), ID_FIXED_LEN + 16);
    }

    #[test]
    fn payload_compiles_generic_header_then_body() {
        // The compiled payload is the 4-octet generic header (Next Payload 0
        // terminator, auto length) followed by the Identification body.
        let payload = idi_ipv4_payload();
        let bytes = compile_payload(payload.clone());

        assert_eq!(bytes[0], 0); // Next Payload terminator.
        assert_eq!(bytes[1], 0); // Critical clear.
        let payload_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(payload_len, bytes.len());
        assert_eq!(payload_len, payload.encoded_len());
        // The body after the generic header is the Identification body verbatim.
        assert_eq!(&bytes[GENERIC_PAYLOAD_HEADER_LEN..], &payload.id_body()[..]);
    }

    #[test]
    fn payload_honors_generic_header_overrides() {
        // Caller-pinned Next Payload, Critical, and Payload Length survive.
        let payload = idi_ipv4_payload()
            .next_payload(39)
            .critical(true)
            .payload_length(0xBEEF);
        let bytes = compile_payload(payload);
        assert_eq!(bytes[0], 39);
        assert_eq!(bytes[1], 0x80); // Critical bit set.
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0xBEEF);
    }

    #[test]
    fn payload_chain_next_payload_points_at_idi_and_idr() {
        // An IDi/IDr payload following another layer derives the preceding
        // header's Next Payload through payload_type_for_layer_name (registered
        // this step) as the IDi (35) / IDr (36) codepoint.
        use crate::protocols::ipsec::ikev2::payload::{
            following_next_payload, payload_type_for_layer_name, PAYLOAD_IDI, PAYLOAD_IDR,
        };
        assert_eq!(
            payload_type_for_layer_name(IKE_IDI_PAYLOAD_NAME),
            Some(PayloadType::IdInitiator)
        );
        assert_eq!(
            payload_type_for_layer_name(IKE_IDR_PAYLOAD_NAME),
            Some(PayloadType::IdResponder)
        );

        let idi_packet: Packet = Packet::from_layer(Raw::from_bytes([0u8; 0])) / idi_ipv4_payload();
        let idi_ctx = LayerContext::new(&idi_packet, 0);
        assert_eq!(following_next_payload(&idi_ctx), PAYLOAD_IDI);

        let idr_packet: Packet = Packet::from_layer(Raw::from_bytes([0u8; 0])) / idr_fqdn_payload();
        let idr_ctx = LayerContext::new(&idr_packet, 0);
        assert_eq!(following_next_payload(&idr_ctx), PAYLOAD_IDR);
    }

    #[test]
    fn round_trip_idi_ipv4_preserves_type_and_data() {
        // Build an IDi from a documentation IPv4 address, compile to wire, parse
        // the body back, and confirm the ID Type and data round-trip (Step 45
        // closes the registry decode; this is the local parse helper).
        let payload = idi_ipv4_payload();
        let bytes = compile_payload(payload.clone());

        let parsed =
            parse_id_payload_body(IdRole::Initiator, &bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(parsed.role(), IdRole::Initiator);
        assert_eq!(parsed.id_type_kind(), IdType::Ipv4Addr);
        assert_eq!(parsed.id_data_bytes(), &[192, 0, 2, 1]);
        // The parsed payload re-compiles byte-exact.
        let recompiled = compile_payload(parsed);
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn round_trip_idr_fqdn_preserves_type_and_data() {
        // Build an IDr from an FQDN, compile to wire, parse the body back, and
        // confirm the ID Type and data round-trip and re-compile byte-exact.
        let payload = idr_fqdn_payload();
        let bytes = compile_payload(payload.clone());

        let parsed =
            parse_id_payload_body(IdRole::Responder, &bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(parsed.role(), IdRole::Responder);
        assert_eq!(parsed.id_type_kind(), IdType::Fqdn);
        assert_eq!(parsed.id_data_bytes(), b"responder.example.com");
        let recompiled = compile_payload(parsed);
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn parse_rejects_truncated_body() {
        // A buffer shorter than the fixed Identification body header is a
        // structured error, not a panic.
        let err = parse_id_payload_body(IdRole::Initiator, &[1u8, 0, 0]).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }
}
