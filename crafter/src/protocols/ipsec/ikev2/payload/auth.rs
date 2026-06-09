//! IKEv2 Authentication (AUTH) payload, type 39 (RFC 7296 §3.8).
//!
//! The Authentication payload carries the result of the authentication
//! computation each peer performs over the first message it sent (RFC 7296
//! §2.15). The body that follows the 4-octet generic payload header (emitted by
//! [`write_generic_payload_header`]) is:
//!
//! ```text
//!  Auth Method (1) | RESERVED (3) | Authentication Data (variable)
//! ```
//!
//! (RFC 7296 §3.8). The Auth Method names how the Authentication Data was
//! produced — an RSA digital signature, a shared-key message integrity code, a
//! DSS digital signature, or the algorithm-agile Digital Signature of RFC 7427
//! (see [`AuthMethod`]). The three RESERVED octets are sent as zero. The
//! Authentication Data is the method-specific signature or MIC bytes.
//!
//! This crate models the **wire form only** — the Authentication Data is opaque
//! bytes that the crate carries verbatim. It does **not** compute, sign, or
//! verify any signature or MIC; the caller supplies the Authentication Data. The
//! generic-header Payload Length is auto-filled by `compile()` from the body
//! length, while any caller-pinned value (Next Payload, Payload Length, Critical)
//! is emitted verbatim so deliberately malformed Authentication payloads can be
//! constructed for testing.

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::ipsec::ikev2::payload::{
    write_generic_payload_header, IkePayload, PayloadHeaderFields, PayloadType,
};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
#[cfg(test)]
use crate::CrafterError;
use crate::Result;

/// Layer name for the IKEv2 Authentication payload, registered in
/// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_AUTH_PAYLOAD_NAME: &str = "IkeAuthPayload";

/// Length of the fixed Authentication payload body header (RFC 7296 §3.8): Auth
/// Method (1) + RESERVED (3) = 4 octets, excluding the variable Authentication
/// Data that follows.
pub const AUTH_FIXED_LEN: usize = 4;

// --- Auth Method (RFC 7296 §3.8; IANA "IKEv2 Authentication Method" registry) -

/// Auth Method `1` — RSA Digital Signature: a digital signature computed with an
/// RSA key, encoded per RFC 3447 (PKCS #1) (RFC 7296 §3.8).
pub const AUTH_RSA_DIGITAL_SIGNATURE: u8 = 1;
/// Auth Method `2` — Shared Key Message Integrity Code: a MIC computed with a
/// shared key over the authenticated octets (RFC 7296 §3.8).
pub const AUTH_SHARED_KEY_MIC: u8 = 2;
/// Auth Method `3` — DSS Digital Signature: a digital signature computed with a
/// DSS key (RFC 7296 §3.8).
pub const AUTH_DSS_DIGITAL_SIGNATURE: u8 = 3;
/// Auth Method `14` — Digital Signature: the algorithm-agile signature method
/// whose Authentication Data carries an ASN.1 AlgorithmIdentifier prefix
/// (RFC 7427).
pub const AUTH_DIGITAL_SIGNATURE: u8 = 14;

/// An IKEv2 Authentication Method (RFC 7296 §3.8; IANA "IKEv2 Authentication
/// Method" registry).
///
/// Names how the Authentication Data was produced. Only the common methods named
/// in RFC 7296 §3.8 and the RFC 7427 Digital Signature are given variants; any
/// other codepoint is preserved as [`AuthMethod::Unknown`] so a decoded value
/// round-trips byte-for-byte and the crate never rejects an unrecognized Auth
/// Method (the IANA registry remains the authority).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    /// `1` — RSA Digital Signature.
    RsaDigitalSignature,
    /// `2` — Shared Key Message Integrity Code.
    SharedKeyMic,
    /// `3` — DSS Digital Signature.
    DssDigitalSignature,
    /// `14` — Digital Signature (RFC 7427, algorithm-agile).
    DigitalSignature,
    /// Any Auth Method not named above, preserved verbatim.
    Unknown(u8),
}

impl AuthMethod {
    /// The 8-bit Auth Method codepoint for this method (RFC 7296 §3.8).
    /// [`AuthMethod::Unknown`] returns its preserved value.
    pub fn codepoint(self) -> u8 {
        match self {
            Self::RsaDigitalSignature => AUTH_RSA_DIGITAL_SIGNATURE,
            Self::SharedKeyMic => AUTH_SHARED_KEY_MIC,
            Self::DssDigitalSignature => AUTH_DSS_DIGITAL_SIGNATURE,
            Self::DigitalSignature => AUTH_DIGITAL_SIGNATURE,
            Self::Unknown(value) => value,
        }
    }
}

impl From<u8> for AuthMethod {
    /// Map an Auth Method codepoint to an [`AuthMethod`], preserving an
    /// unrecognized value as [`AuthMethod::Unknown`] (never erroring).
    fn from(value: u8) -> Self {
        match value {
            AUTH_RSA_DIGITAL_SIGNATURE => Self::RsaDigitalSignature,
            AUTH_SHARED_KEY_MIC => Self::SharedKeyMic,
            AUTH_DSS_DIGITAL_SIGNATURE => Self::DssDigitalSignature,
            AUTH_DIGITAL_SIGNATURE => Self::DigitalSignature,
            other => Self::Unknown(other),
        }
    }
}

// `TryFrom<u8>` is provided automatically by the blanket
// `impl<T, U: Into<T>> TryFrom<U> for T` (`Error = Infallible`): unknown
// codepoints are preserved as `Unknown` rather than rejected, so the conversion
// never fails. This mirrors `PayloadType` and the SA algorithm enums.

impl From<AuthMethod> for u8 {
    fn from(auth_method: AuthMethod) -> Self {
        auth_method.codepoint()
    }
}

/// IKEv2 Authentication (AUTH) payload, type 39 (RFC 7296 §3.8).
///
/// Carries the Auth Method and the opaque Authentication Data. As a [`Layer`] it
/// emits the 4-octet generic payload header (via
/// [`write_generic_payload_header`]) followed by the body `Auth Method (1) |
/// RESERVED (3, zero) | Authentication Data`. The generic-header Next Payload,
/// Critical flag, and Payload Length are the shared overridable fields carried in
/// [`PayloadHeaderFields`].
///
/// The crate carries the Authentication Data verbatim and never computes or
/// verifies a signature or MIC; the caller supplies those bytes.
#[derive(Debug, Clone)]
pub struct IkeAuthPayload {
    /// Auth Method (RFC 7296 §3.8; see `AUTH_*` constants and [`AuthMethod`]).
    auth_method: Field<u8>,
    /// Authentication Data: the method-specific signature/MIC bytes
    /// (RFC 7296 §3.8). Carried verbatim; never computed.
    auth_data: Vec<u8>,
    /// Shared generic-payload-header overrides (Next Payload, Length, Critical).
    header: PayloadHeaderFields,
}

impl IkeAuthPayload {
    /// An Authentication payload of the given Auth Method, carrying the given
    /// Authentication Data bytes verbatim (RFC 7296 §3.8).
    ///
    /// The Auth Method accepts anything convertible into an [`AuthMethod`] (a
    /// named variant, an `AuthMethod::Unknown`, or a bare `u8`). The
    /// Authentication Data is supplied by the caller; the crate does not compute
    /// or verify a signature or MIC.
    pub fn new(auth_method: impl Into<AuthMethod>, auth_data: impl Into<Vec<u8>>) -> Self {
        Self {
            auth_method: Field::user(auth_method.into().codepoint()),
            auth_data: auth_data.into(),
            header: PayloadHeaderFields::new(),
        }
    }

    /// A Shared Key Message Integrity Code AUTH payload (Auth Method 2;
    /// RFC 7296 §3.8) carrying the given pre-computed MIC bytes verbatim.
    pub fn shared_key_mic(auth_data: impl Into<Vec<u8>>) -> Self {
        Self::new(AuthMethod::SharedKeyMic, auth_data)
    }

    /// An RSA Digital Signature AUTH payload (Auth Method 1; RFC 7296 §3.8)
    /// carrying the given pre-computed signature bytes verbatim.
    pub fn rsa_digital_signature(auth_data: impl Into<Vec<u8>>) -> Self {
        Self::new(AuthMethod::RsaDigitalSignature, auth_data)
    }

    /// A Digital Signature AUTH payload (Auth Method 14, RFC 7427) carrying the
    /// given Authentication Data verbatim. Per RFC 7427 the data begins with an
    /// ASN.1 AlgorithmIdentifier prefix; the crate carries whatever bytes the
    /// caller supplies.
    pub fn digital_signature(auth_data: impl Into<Vec<u8>>) -> Self {
        Self::new(AuthMethod::DigitalSignature, auth_data)
    }

    /// Set the Auth Method (RFC 7296 §3.8), accepting a named [`AuthMethod`], an
    /// `AuthMethod::Unknown`, or a bare `u8`.
    pub fn auth_method(mut self, auth_method: impl Into<AuthMethod>) -> Self {
        self.auth_method.set_user(auth_method.into().codepoint());
        self
    }

    /// Set the Authentication Data bytes (RFC 7296 §3.8), consuming-builder
    /// style. The bytes are carried verbatim; no signature/MIC is computed.
    pub fn auth_data(mut self, auth_data: impl Into<Vec<u8>>) -> Self {
        self.auth_data = auth_data.into();
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

    /// The raw Auth Method codepoint (RFC 7296 §3.8).
    pub fn auth_method_value(&self) -> u8 {
        self.auth_method.value().copied().unwrap_or(0)
    }

    /// The Auth Method as an [`AuthMethod`] (RFC 7296 §3.8).
    pub fn auth_method_kind(&self) -> AuthMethod {
        AuthMethod::from(self.auth_method_value())
    }

    /// The Authentication Data bytes (RFC 7296 §3.8).
    pub fn auth_data_bytes(&self) -> &[u8] {
        &self.auth_data
    }

    /// The Authentication body (everything after the 4-octet generic header),
    /// per RFC 7296 §3.8: Auth Method (1) | RESERVED (3, zero) | Authentication
    /// Data.
    fn auth_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(AUTH_FIXED_LEN + self.auth_data.len());
        out.push(self.auth_method_value());
        out.extend_from_slice(&[0u8, 0u8, 0u8]); // RESERVED (3 octets).
        out.extend_from_slice(&self.auth_data);
        out
    }
}

impl IkePayload for IkeAuthPayload {
    fn payload_type(&self) -> PayloadType {
        PayloadType::Authentication
    }

    fn payload_body(&self, _ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        Ok(self.auth_body())
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

impl Layer for IkeAuthPayload {
    fn name(&self) -> &'static str {
        IKE_AUTH_PAYLOAD_NAME
    }

    fn summary(&self) -> String {
        format!(
            "IkeAuthPayload(auth_method={}, auth_data_len={})",
            self.auth_method_value(),
            self.auth_data.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("auth_method", self.auth_method_value().to_string()),
            ("auth_data_len", self.auth_data.len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        super::GENERIC_PAYLOAD_HEADER_LEN + AUTH_FIXED_LEN + self.auth_data.len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Emit the 4-octet generic payload header (auto Next Payload from the
        // following payload and auto Payload Length unless overridden), then the
        // Authentication body (Auth Method | RESERVED | Authentication Data).
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

    impl_layer_object!(IkeAuthPayload);
}

impl_layer_div!(IkeAuthPayload);

// --- Local parse helper (Step 45 closes the full registry decode) -----------

/// Parse an Authentication payload **body** (the bytes after the 4-octet generic
/// header) per RFC 7296 §3.8. Local to this step; the registry-driven chain
/// decode lands in Step 45.
///
/// The Auth Method is read from the first octet, the three RESERVED octets are
/// ignored, and the remainder is the Authentication Data, carried verbatim. A
/// buffer shorter than the fixed body header is a structured error rather than a
/// panic. Decoded fields are stored with `Field::user` so a re-compile reproduces
/// the bytes exactly.
#[cfg(test)]
fn parse_auth_payload_body(bytes: &[u8]) -> Result<IkeAuthPayload> {
    if bytes.len() < AUTH_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ikev2.auth",
            AUTH_FIXED_LEN,
            bytes.len(),
        ));
    }
    let auth_method = bytes[0];
    // bytes[1..4] are RESERVED and ignored on decode.
    let auth_data = bytes[AUTH_FIXED_LEN..].to_vec();
    Ok(IkeAuthPayload::new(auth_method, auth_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LayerContext, Packet, Raw};
    use crate::protocols::ipsec::ikev2::payload::GENERIC_PAYLOAD_HEADER_LEN;

    /// Compile a standalone Authentication payload and return its full bytes
    /// (generic header + body), gathered through a one-layer packet.
    fn compile_payload(payload: IkeAuthPayload) -> Vec<u8> {
        let packet = Packet::from_layer(payload);
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    /// A representative Shared-Key-MIC AUTH payload with fixed data: a 20-octet
    /// HMAC-SHA1-style MIC value (RFC 7296 §3.8). The bytes are arbitrary fixed
    /// test data; the crate carries them verbatim and does not compute a MIC.
    fn shared_key_mic_payload() -> IkeAuthPayload {
        IkeAuthPayload::shared_key_mic((0u8..20).collect::<Vec<u8>>())
    }

    #[test]
    fn auth_constants_match_manifest() {
        // RFC 7296 §3.8 / RFC 7427 / IANA "IKEv2 Authentication Method".
        assert_eq!(AUTH_FIXED_LEN, 4);
        assert_eq!(AUTH_RSA_DIGITAL_SIGNATURE, 1);
        assert_eq!(AUTH_SHARED_KEY_MIC, 2);
        assert_eq!(AUTH_DSS_DIGITAL_SIGNATURE, 3);
        assert_eq!(AUTH_DIGITAL_SIGNATURE, 14);
        // The AUTH payload-type codepoint (RFC 7296 §3.2 / §3.8).
        assert_eq!(PayloadType::Authentication.codepoint(), 39);
    }

    #[test]
    fn auth_method_round_trips_through_u8() {
        // u8 -> AuthMethod -> u8 is the identity for every named codepoint and for
        // unassigned codepoints (preserved verbatim as Unknown).
        for value in 0u8..=255 {
            let auth_method = AuthMethod::from(value);
            assert_eq!(auth_method.codepoint(), value);
            assert_eq!(u8::from(auth_method), value);
        }
    }

    #[test]
    fn named_auth_methods_map_to_codepoints() {
        // RFC 7296 §3.8 / RFC 7427: the named methods map to their codepoints.
        assert_eq!(
            AuthMethod::from(AUTH_RSA_DIGITAL_SIGNATURE),
            AuthMethod::RsaDigitalSignature
        );
        assert_eq!(
            AuthMethod::from(AUTH_SHARED_KEY_MIC),
            AuthMethod::SharedKeyMic
        );
        assert_eq!(
            AuthMethod::from(AUTH_DSS_DIGITAL_SIGNATURE),
            AuthMethod::DssDigitalSignature
        );
        assert_eq!(
            AuthMethod::from(AUTH_DIGITAL_SIGNATURE),
            AuthMethod::DigitalSignature
        );
    }

    #[test]
    fn unknown_auth_method_is_preserved() {
        // A codepoint outside the named set survives as Unknown and round-trips.
        let unassigned = 200u8;
        assert_eq!(
            AuthMethod::from(unassigned),
            AuthMethod::Unknown(unassigned)
        );
        assert_eq!(AuthMethod::Unknown(unassigned).codepoint(), unassigned);
        // The IANA value 9 (ECDSA with SHA-256, not named in this build) is
        // unknown here, preserved verbatim rather than misclassified.
        assert_eq!(AuthMethod::from(9), AuthMethod::Unknown(9));
    }

    // The blanket `TryFrom<u8>` (from `From<u8>`) is infallible, so clippy flags
    // the explicit `try_into`; the point of this test is to exercise that
    // fallible surface, so the lint is allowed here (mirroring the SA algorithm
    // enums and `PayloadType`).
    #[allow(clippy::unnecessary_fallible_conversions)]
    #[test]
    fn try_from_u8_is_infallible_and_preserves_unknown() {
        let known: AuthMethod = u8::try_into(AUTH_SHARED_KEY_MIC).unwrap();
        assert_eq!(known, AuthMethod::SharedKeyMic);
        let unknown: AuthMethod = u8::try_into(222u8).unwrap();
        assert_eq!(unknown, AuthMethod::Unknown(222));
    }

    #[test]
    fn payload_type_is_authentication() {
        let payload = shared_key_mic_payload();
        assert_eq!(payload.payload_type(), PayloadType::Authentication);
        // The layer name is registered for the chain next-payload derivation.
        assert_eq!(payload.name(), IKE_AUTH_PAYLOAD_NAME);
    }

    #[test]
    fn body_lays_out_method_reserved_then_data() {
        // RFC 7296 §3.8: Auth Method (1) | RESERVED (3, zero) | Authentication
        // Data. The Shared-Key-MIC payload carries the 20-octet fixed MIC.
        let payload = shared_key_mic_payload();
        let body = payload.auth_body();
        assert_eq!(body[0], AUTH_SHARED_KEY_MIC);
        assert_eq!(&body[1..4], &[0, 0, 0]); // RESERVED.
        assert_eq!(&body[AUTH_FIXED_LEN..], &(0u8..20).collect::<Vec<u8>>()[..]);
        assert_eq!(body.len(), AUTH_FIXED_LEN + 20);
        assert_eq!(payload.auth_method_kind(), AuthMethod::SharedKeyMic);
    }

    #[test]
    fn payload_compiles_generic_header_then_body() {
        // The compiled payload is the 4-octet generic header (Next Payload 0
        // terminator, auto length) followed by the Authentication body.
        let payload = shared_key_mic_payload();
        let bytes = compile_payload(payload.clone());

        assert_eq!(bytes[0], 0); // Next Payload terminator.
        assert_eq!(bytes[1], 0); // Critical clear.
        let payload_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(payload_len, bytes.len());
        assert_eq!(payload_len, payload.encoded_len());
        // The body after the generic header is the Authentication body verbatim.
        assert_eq!(
            &bytes[GENERIC_PAYLOAD_HEADER_LEN..],
            &payload.auth_body()[..]
        );
    }

    #[test]
    fn payload_honors_generic_header_overrides() {
        // Caller-pinned Next Payload, Critical, and Payload Length survive.
        let payload = shared_key_mic_payload()
            .next_payload(40)
            .critical(true)
            .payload_length(0xBEEF);
        let bytes = compile_payload(payload);
        assert_eq!(bytes[0], 40);
        assert_eq!(bytes[1], 0x80); // Critical bit set.
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0xBEEF);
    }

    #[test]
    fn payload_chain_next_payload_points_at_auth() {
        // An AUTH payload following another layer derives the preceding header's
        // Next Payload through payload_type_for_layer_name (registered this step)
        // as the AUTH codepoint (39).
        use crate::protocols::ipsec::ikev2::payload::{
            following_next_payload, payload_type_for_layer_name, PAYLOAD_AUTH,
        };
        assert_eq!(
            payload_type_for_layer_name(IKE_AUTH_PAYLOAD_NAME),
            Some(PayloadType::Authentication)
        );
        let packet: Packet =
            Packet::from_layer(Raw::from_bytes([0u8; 0])) / shared_key_mic_payload();
        let ctx = LayerContext::new(&packet, 0);
        assert_eq!(following_next_payload(&ctx), PAYLOAD_AUTH);
    }

    #[test]
    fn round_trip_shared_key_mic_preserves_method_and_data() {
        // Build a Shared-Key-MIC AUTH with fixed data, compile to wire, parse the
        // body back, and confirm the Auth Method and data round-trip (Step 45
        // closes the registry decode; this is the local parse helper).
        let payload = shared_key_mic_payload();
        let bytes = compile_payload(payload.clone());

        let parsed = parse_auth_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(parsed.auth_method_value(), AUTH_SHARED_KEY_MIC);
        assert_eq!(parsed.auth_method_kind(), AuthMethod::SharedKeyMic);
        assert_eq!(
            parsed.auth_data_bytes(),
            &(0u8..20).collect::<Vec<u8>>()[..]
        );
        // The parsed payload re-compiles byte-exact.
        let recompiled = compile_payload(parsed);
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn round_trip_digital_signature_preserves_method_and_data() {
        // The RFC 7427 Digital Signature method (14) round-trips with arbitrary
        // fixed Authentication Data carried verbatim.
        let payload = IkeAuthPayload::digital_signature(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let bytes = compile_payload(payload.clone());

        let parsed = parse_auth_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(parsed.auth_method_value(), AUTH_DIGITAL_SIGNATURE);
        assert_eq!(parsed.auth_method_kind(), AuthMethod::DigitalSignature);
        assert_eq!(parsed.auth_data_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD]);
        let recompiled = compile_payload(parsed);
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn parse_rejects_truncated_body() {
        // A buffer shorter than the fixed Authentication body header is a
        // structured error, not a panic.
        let err = parse_auth_payload_body(&[2u8, 0, 0]).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }
}
