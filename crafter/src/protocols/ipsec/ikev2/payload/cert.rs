//! IKEv2 Certificate (CERT) and Certificate Request (CERTREQ) payloads,
//! types 37 and 38 (RFC 7296 §3.6, §3.7).
//!
//! The Certificate payload carries a certificate (or related authentication
//! material) so a peer can validate the other's signature. The body that follows
//! the 4-octet generic payload header (emitted by
//! [`write_generic_payload_header`]) is:
//!
//! ```text
//!  Cert Encoding (1) | Certificate Data (variable)
//! ```
//!
//! (RFC 7296 §3.6). The Certificate Request payload asks for the kind of
//! certificate(s) the sender will accept; its body shares the same one-octet
//! Cert Encoding prefix followed by the Certification Authority field:
//!
//! ```text
//!  Cert Encoding (1) | Certification Authority (variable)
//! ```
//!
//! (RFC 7296 §3.7). For an X.509 Certificate - Signature encoding the
//! Certification Authority is a concatenated list of SHA-1 hashes of the trusted
//! CA Subject Public Key Info values; for other encodings it is encoding-specific.
//!
//! This crate models the **wire form only** — the Certificate Data and the
//! Certification Authority field are opaque bytes carried verbatim. The
//! generic-header Payload Length is auto-filled by `compile()` from the body
//! length, while any caller-pinned value (Next Payload, Payload Length, Critical)
//! is emitted verbatim so deliberately malformed payloads can be constructed for
//! testing.

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::ipsec::ikev2::payload::{
    write_generic_payload_header, IkePayload, PayloadHeaderFields, PayloadType,
};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::CrafterError;
use crate::Result;

/// Layer name for the IKEv2 Certificate payload, registered in
/// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_CERT_PAYLOAD_NAME: &str = "IkeCertPayload";

/// Layer name for the IKEv2 Certificate Request payload, registered in
/// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_CERTREQ_PAYLOAD_NAME: &str = "IkeCertReqPayload";

/// Length of the fixed Certificate / Certificate Request body header
/// (RFC 7296 §3.6, §3.7): Cert Encoding (1), excluding the variable Certificate
/// Data / Certification Authority bytes that follow.
pub const CERT_FIXED_LEN: usize = 1;

// --- Cert Encoding (RFC 7296 §3.6; IANA "IKEv2 Certificate Encodings") --------

/// Cert Encoding `4` — X.509 Certificate - Signature (RFC 7296 §3.6). The
/// Certificate Data is a DER-encoded X.509 certificate, and the most common
/// encoding for the Certificate and Certificate Request payloads.
pub const CERT_ENCODING_X509_SIGNATURE: u8 = 4;
/// Cert Encoding `2` — PKCS #7 wrapped X.509 certificate (RFC 7296 §3.6).
pub const CERT_ENCODING_PKCS7_X509: u8 = 2;
/// Cert Encoding `7` — DNS Signed Key (RFC 7296 §3.6).
pub const CERT_ENCODING_DNS_SIGNED_KEY: u8 = 7;
/// Cert Encoding `12` — Hash and URL of X.509 certificate (RFC 7296 §3.6).
pub const CERT_ENCODING_HASH_URL_X509: u8 = 12;
/// Cert Encoding `13` — Hash and URL of X.509 bundle (RFC 7296 §3.6).
pub const CERT_ENCODING_HASH_URL_X509_BUNDLE: u8 = 13;

/// An IKEv2 Certificate Encoding (RFC 7296 §3.6; IANA "IKEv2 Certificate
/// Encodings" registry).
///
/// Names the type of the Certificate Data (or, in a Certificate Request, the
/// kind of certificate requested). Only the common encodings are given named
/// variants; any other codepoint is preserved as [`CertEncoding::Unknown`] so a
/// decoded value round-trips byte-for-byte and the crate never rejects an
/// unrecognized encoding (the IANA registry remains the authority).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertEncoding {
    /// `2` — PKCS #7 wrapped X.509 certificate.
    Pkcs7X509,
    /// `4` — X.509 Certificate - Signature.
    X509Signature,
    /// `7` — DNS Signed Key.
    DnsSignedKey,
    /// `12` — Hash and URL of X.509 certificate.
    HashUrlX509,
    /// `13` — Hash and URL of X.509 bundle.
    HashUrlX509Bundle,
    /// Any Cert Encoding not named above, preserved verbatim.
    Unknown(u8),
}

impl CertEncoding {
    /// The 8-bit Cert Encoding codepoint for this encoding (RFC 7296 §3.6).
    /// [`CertEncoding::Unknown`] returns its preserved value.
    pub fn codepoint(self) -> u8 {
        match self {
            Self::Pkcs7X509 => CERT_ENCODING_PKCS7_X509,
            Self::X509Signature => CERT_ENCODING_X509_SIGNATURE,
            Self::DnsSignedKey => CERT_ENCODING_DNS_SIGNED_KEY,
            Self::HashUrlX509 => CERT_ENCODING_HASH_URL_X509,
            Self::HashUrlX509Bundle => CERT_ENCODING_HASH_URL_X509_BUNDLE,
            Self::Unknown(value) => value,
        }
    }
}

impl From<u8> for CertEncoding {
    /// Map a Cert Encoding codepoint to a [`CertEncoding`], preserving an
    /// unrecognized value as [`CertEncoding::Unknown`] (never erroring).
    fn from(value: u8) -> Self {
        match value {
            CERT_ENCODING_PKCS7_X509 => Self::Pkcs7X509,
            CERT_ENCODING_X509_SIGNATURE => Self::X509Signature,
            CERT_ENCODING_DNS_SIGNED_KEY => Self::DnsSignedKey,
            CERT_ENCODING_HASH_URL_X509 => Self::HashUrlX509,
            CERT_ENCODING_HASH_URL_X509_BUNDLE => Self::HashUrlX509Bundle,
            other => Self::Unknown(other),
        }
    }
}

// `TryFrom<u8>` is provided automatically by the blanket
// `impl<T, U: Into<T>> TryFrom<U> for T` (`Error = Infallible`): unknown
// codepoints are preserved as `Unknown` rather than rejected, so the conversion
// never fails. This mirrors `PayloadType` and the SA algorithm enums.

impl From<CertEncoding> for u8 {
    fn from(cert_encoding: CertEncoding) -> Self {
        cert_encoding.codepoint()
    }
}

/// IKEv2 Certificate (CERT) payload, type 37 (RFC 7296 §3.6).
///
/// Carries the Cert Encoding and the opaque Certificate Data. As a [`Layer`] it
/// emits the 4-octet generic payload header (via
/// [`write_generic_payload_header`]) followed by the body `Cert Encoding (1) |
/// Certificate Data`. The generic-header Next Payload, Critical flag, and Payload
/// Length are the shared overridable fields carried in [`PayloadHeaderFields`].
///
/// The crate carries the Certificate Data verbatim and never parses or validates
/// a certificate; the caller supplies those bytes.
#[derive(Debug, Clone)]
pub struct IkeCertPayload {
    /// Cert Encoding (RFC 7296 §3.6; see `CERT_ENCODING_*` and [`CertEncoding`]).
    cert_encoding: Field<u8>,
    /// Certificate Data: the encoding-specific certificate bytes
    /// (RFC 7296 §3.6). Carried verbatim; never parsed.
    cert_data: Vec<u8>,
    /// Shared generic-payload-header overrides (Next Payload, Length, Critical).
    header: PayloadHeaderFields,
}

impl IkeCertPayload {
    /// A Certificate payload of the given Cert Encoding, carrying the given
    /// Certificate Data bytes verbatim (RFC 7296 §3.6).
    ///
    /// The Cert Encoding accepts anything convertible into a [`CertEncoding`] (a
    /// named variant, a `CertEncoding::Unknown`, or a bare `u8`). The Certificate
    /// Data is supplied by the caller; the crate does not parse or validate it.
    pub fn new(cert_encoding: impl Into<CertEncoding>, cert_data: impl Into<Vec<u8>>) -> Self {
        Self {
            cert_encoding: Field::user(cert_encoding.into().codepoint()),
            cert_data: cert_data.into(),
            header: PayloadHeaderFields::new(),
        }
    }

    /// An X.509 Certificate - Signature CERT payload (Cert Encoding 4;
    /// RFC 7296 §3.6) carrying the given DER-encoded certificate bytes verbatim.
    pub fn x509_signature(cert_data: impl Into<Vec<u8>>) -> Self {
        Self::new(CertEncoding::X509Signature, cert_data)
    }

    /// Set the Cert Encoding (RFC 7296 §3.6), accepting a named [`CertEncoding`],
    /// a `CertEncoding::Unknown`, or a bare `u8`.
    pub fn cert_encoding(mut self, cert_encoding: impl Into<CertEncoding>) -> Self {
        self.cert_encoding
            .set_user(cert_encoding.into().codepoint());
        self
    }

    /// Set the Certificate Data bytes (RFC 7296 §3.6), consuming-builder style.
    /// The bytes are carried verbatim; no certificate is parsed.
    pub fn cert_data(mut self, cert_data: impl Into<Vec<u8>>) -> Self {
        self.cert_data = cert_data.into();
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

    /// The raw Cert Encoding codepoint (RFC 7296 §3.6).
    pub fn cert_encoding_value(&self) -> u8 {
        self.cert_encoding.value().copied().unwrap_or(0)
    }

    /// The Cert Encoding as a [`CertEncoding`] (RFC 7296 §3.6).
    pub fn cert_encoding_kind(&self) -> CertEncoding {
        CertEncoding::from(self.cert_encoding_value())
    }

    /// The Certificate Data bytes (RFC 7296 §3.6).
    pub fn cert_data_bytes(&self) -> &[u8] {
        &self.cert_data
    }

    /// The Certificate body (everything after the 4-octet generic header), per
    /// RFC 7296 §3.6: Cert Encoding (1) | Certificate Data.
    fn cert_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CERT_FIXED_LEN + self.cert_data.len());
        out.push(self.cert_encoding_value());
        out.extend_from_slice(&self.cert_data);
        out
    }
}

impl IkePayload for IkeCertPayload {
    fn payload_type(&self) -> PayloadType {
        PayloadType::Certificate
    }

    fn payload_body(&self, _ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        Ok(self.cert_body())
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

impl Layer for IkeCertPayload {
    fn name(&self) -> &'static str {
        IKE_CERT_PAYLOAD_NAME
    }

    fn summary(&self) -> String {
        format!(
            "IkeCertPayload(cert_encoding={}, cert_data_len={})",
            self.cert_encoding_value(),
            self.cert_data.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("cert_encoding", self.cert_encoding_value().to_string()),
            ("cert_data_len", self.cert_data.len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        super::GENERIC_PAYLOAD_HEADER_LEN + CERT_FIXED_LEN + self.cert_data.len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Emit the 4-octet generic payload header (auto Next Payload from the
        // following payload and auto Payload Length unless overridden), then the
        // Certificate body (Cert Encoding | Certificate Data).
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

    impl_layer_object!(IkeCertPayload);
}

impl_layer_div!(IkeCertPayload);

/// IKEv2 Certificate Request (CERTREQ) payload, type 38 (RFC 7296 §3.7).
///
/// Carries the Cert Encoding and the opaque Certification Authority field. As a
/// [`Layer`] it emits the 4-octet generic payload header (via
/// [`write_generic_payload_header`]) followed by the body `Cert Encoding (1) |
/// Certification Authority`. The generic-header Next Payload, Critical flag, and
/// Payload Length are the shared overridable fields carried in
/// [`PayloadHeaderFields`].
///
/// The crate carries the Certification Authority field verbatim and never
/// interprets it; the caller supplies those bytes.
#[derive(Debug, Clone)]
pub struct IkeCertReqPayload {
    /// Cert Encoding (RFC 7296 §3.7; see `CERT_ENCODING_*` and [`CertEncoding`]).
    cert_encoding: Field<u8>,
    /// Certification Authority: encoding-specific bytes naming the accepted CAs
    /// (RFC 7296 §3.7). Carried verbatim; never parsed.
    ca_data: Vec<u8>,
    /// Shared generic-payload-header overrides (Next Payload, Length, Critical).
    header: PayloadHeaderFields,
}

impl IkeCertReqPayload {
    /// A Certificate Request payload of the given Cert Encoding, carrying the
    /// given Certification Authority bytes verbatim (RFC 7296 §3.7).
    ///
    /// The Cert Encoding accepts anything convertible into a [`CertEncoding`] (a
    /// named variant, a `CertEncoding::Unknown`, or a bare `u8`). The
    /// Certification Authority field is supplied by the caller; the crate does
    /// not interpret it.
    pub fn new(cert_encoding: impl Into<CertEncoding>, ca_data: impl Into<Vec<u8>>) -> Self {
        Self {
            cert_encoding: Field::user(cert_encoding.into().codepoint()),
            ca_data: ca_data.into(),
            header: PayloadHeaderFields::new(),
        }
    }

    /// An X.509 Certificate - Signature CERTREQ payload (Cert Encoding 4;
    /// RFC 7296 §3.7) carrying the given Certification Authority bytes (a
    /// concatenation of SHA-1 hashes of trusted CA Subject Public Key Info
    /// values) verbatim.
    pub fn x509_signature(ca_data: impl Into<Vec<u8>>) -> Self {
        Self::new(CertEncoding::X509Signature, ca_data)
    }

    /// Set the Cert Encoding (RFC 7296 §3.7), accepting a named [`CertEncoding`],
    /// a `CertEncoding::Unknown`, or a bare `u8`.
    pub fn cert_encoding(mut self, cert_encoding: impl Into<CertEncoding>) -> Self {
        self.cert_encoding
            .set_user(cert_encoding.into().codepoint());
        self
    }

    /// Set the Certification Authority bytes (RFC 7296 §3.7), consuming-builder
    /// style. The bytes are carried verbatim; nothing is parsed.
    pub fn ca_data(mut self, ca_data: impl Into<Vec<u8>>) -> Self {
        self.ca_data = ca_data.into();
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

    /// The raw Cert Encoding codepoint (RFC 7296 §3.7).
    pub fn cert_encoding_value(&self) -> u8 {
        self.cert_encoding.value().copied().unwrap_or(0)
    }

    /// The Cert Encoding as a [`CertEncoding`] (RFC 7296 §3.7).
    pub fn cert_encoding_kind(&self) -> CertEncoding {
        CertEncoding::from(self.cert_encoding_value())
    }

    /// The Certification Authority bytes (RFC 7296 §3.7).
    pub fn ca_data_bytes(&self) -> &[u8] {
        &self.ca_data
    }

    /// The Certificate Request body (everything after the 4-octet generic
    /// header), per RFC 7296 §3.7: Cert Encoding (1) | Certification Authority.
    fn certreq_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CERT_FIXED_LEN + self.ca_data.len());
        out.push(self.cert_encoding_value());
        out.extend_from_slice(&self.ca_data);
        out
    }
}

impl IkePayload for IkeCertReqPayload {
    fn payload_type(&self) -> PayloadType {
        PayloadType::CertificateRequest
    }

    fn payload_body(&self, _ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        Ok(self.certreq_body())
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

impl Layer for IkeCertReqPayload {
    fn name(&self) -> &'static str {
        IKE_CERTREQ_PAYLOAD_NAME
    }

    fn summary(&self) -> String {
        format!(
            "IkeCertReqPayload(cert_encoding={}, ca_data_len={})",
            self.cert_encoding_value(),
            self.ca_data.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("cert_encoding", self.cert_encoding_value().to_string()),
            ("ca_data_len", self.ca_data.len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        super::GENERIC_PAYLOAD_HEADER_LEN + CERT_FIXED_LEN + self.ca_data.len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Emit the 4-octet generic payload header (auto Next Payload from the
        // following payload and auto Payload Length unless overridden), then the
        // Certificate Request body (Cert Encoding | Certification Authority).
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

    impl_layer_object!(IkeCertReqPayload);
}

impl_layer_div!(IkeCertReqPayload);

// --- Local parse helpers (Step 45 closes the full registry decode) ----------

/// Parse a Certificate payload **body** (the bytes after the 4-octet generic
/// header) per RFC 7296 §3.6. Local to this step; the registry-driven chain
/// decode lands in Step 45.
///
/// The Cert Encoding is read from the first octet and the remainder is the
/// Certificate Data, carried verbatim. A buffer shorter than the fixed body
/// header is a structured error rather than a panic. Decoded fields are stored
/// with `Field::user` so a re-compile reproduces the bytes exactly.
pub(crate) fn parse_cert_payload_body(bytes: &[u8]) -> Result<IkeCertPayload> {
    if bytes.len() < CERT_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ikev2.cert",
            CERT_FIXED_LEN,
            bytes.len(),
        ));
    }
    let cert_encoding = bytes[0];
    let cert_data = bytes[CERT_FIXED_LEN..].to_vec();
    Ok(IkeCertPayload::new(cert_encoding, cert_data))
}

/// Parse a Certificate Request payload **body** (the bytes after the 4-octet
/// generic header) per RFC 7296 §3.7. Local to this step; the registry-driven
/// chain decode lands in Step 45.
///
/// The Cert Encoding is read from the first octet and the remainder is the
/// Certification Authority field, carried verbatim. A buffer shorter than the
/// fixed body header is a structured error rather than a panic.
pub(crate) fn parse_certreq_payload_body(bytes: &[u8]) -> Result<IkeCertReqPayload> {
    if bytes.len() < CERT_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ikev2.certreq",
            CERT_FIXED_LEN,
            bytes.len(),
        ));
    }
    let cert_encoding = bytes[0];
    let ca_data = bytes[CERT_FIXED_LEN..].to_vec();
    Ok(IkeCertReqPayload::new(cert_encoding, ca_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LayerContext, Packet, Raw};
    use crate::protocols::ipsec::ikev2::payload::GENERIC_PAYLOAD_HEADER_LEN;

    /// Compile a standalone payload and return its full bytes (generic header +
    /// body), gathered through a one-layer packet.
    fn compile_payload(payload: impl Layer) -> Vec<u8> {
        let packet = Packet::from_layer(payload);
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    /// A representative X.509 Certificate payload carrying 16 bytes of fixed
    /// stand-in certificate data (RFC 7296 §3.6). The bytes are arbitrary fixed
    /// test data; the crate carries them verbatim and does not parse a cert.
    fn x509_cert_payload() -> IkeCertPayload {
        IkeCertPayload::x509_signature((0u8..16).collect::<Vec<u8>>())
    }

    #[test]
    fn cert_constants_match_manifest() {
        // RFC 7296 §3.6, §3.7 / IANA "IKEv2 Certificate Encodings".
        assert_eq!(CERT_FIXED_LEN, 1);
        assert_eq!(CERT_ENCODING_PKCS7_X509, 2);
        assert_eq!(CERT_ENCODING_X509_SIGNATURE, 4);
        assert_eq!(CERT_ENCODING_DNS_SIGNED_KEY, 7);
        assert_eq!(CERT_ENCODING_HASH_URL_X509, 12);
        assert_eq!(CERT_ENCODING_HASH_URL_X509_BUNDLE, 13);
        // The CERT / CERTREQ payload-type codepoints (RFC 7296 §3.2).
        assert_eq!(PayloadType::Certificate.codepoint(), 37);
        assert_eq!(PayloadType::CertificateRequest.codepoint(), 38);
    }

    #[test]
    fn cert_encoding_round_trips_through_u8() {
        // u8 -> CertEncoding -> u8 is the identity for every codepoint, named or
        // unassigned (preserved verbatim as Unknown).
        for value in 0u8..=255 {
            let cert_encoding = CertEncoding::from(value);
            assert_eq!(cert_encoding.codepoint(), value);
            assert_eq!(u8::from(cert_encoding), value);
        }
    }

    #[test]
    fn named_cert_encodings_map_to_codepoints() {
        // RFC 7296 §3.6: the named encodings map to their codepoints.
        assert_eq!(
            CertEncoding::from(CERT_ENCODING_X509_SIGNATURE),
            CertEncoding::X509Signature
        );
        assert_eq!(
            CertEncoding::from(CERT_ENCODING_PKCS7_X509),
            CertEncoding::Pkcs7X509
        );
        assert_eq!(
            CertEncoding::from(CERT_ENCODING_HASH_URL_X509),
            CertEncoding::HashUrlX509
        );
    }

    #[test]
    fn unknown_cert_encoding_is_preserved() {
        // A codepoint outside the named set survives as Unknown and round-trips.
        let unassigned = 200u8;
        assert_eq!(
            CertEncoding::from(unassigned),
            CertEncoding::Unknown(unassigned)
        );
        assert_eq!(CertEncoding::Unknown(unassigned).codepoint(), unassigned);
    }

    #[test]
    fn payload_types_and_names_are_registered() {
        let cert = x509_cert_payload();
        assert_eq!(cert.payload_type(), PayloadType::Certificate);
        assert_eq!(cert.name(), IKE_CERT_PAYLOAD_NAME);

        let certreq = IkeCertReqPayload::x509_signature(vec![0xAAu8; 20]);
        assert_eq!(certreq.payload_type(), PayloadType::CertificateRequest);
        assert_eq!(certreq.name(), IKE_CERTREQ_PAYLOAD_NAME);
    }

    #[test]
    fn cert_body_lays_out_encoding_then_data() {
        // RFC 7296 §3.6: Cert Encoding (1) | Certificate Data.
        let payload = x509_cert_payload();
        let body = payload.cert_body();
        assert_eq!(body[0], CERT_ENCODING_X509_SIGNATURE);
        assert_eq!(&body[CERT_FIXED_LEN..], &(0u8..16).collect::<Vec<u8>>()[..]);
        assert_eq!(body.len(), CERT_FIXED_LEN + 16);
        assert_eq!(payload.cert_encoding_kind(), CertEncoding::X509Signature);
    }

    #[test]
    fn certreq_body_lays_out_encoding_then_ca_data() {
        // RFC 7296 §3.7: Cert Encoding (1) | Certification Authority.
        let payload = IkeCertReqPayload::x509_signature(vec![0x11u8, 0x22, 0x33]);
        let body = payload.certreq_body();
        assert_eq!(body[0], CERT_ENCODING_X509_SIGNATURE);
        assert_eq!(&body[CERT_FIXED_LEN..], &[0x11, 0x22, 0x33]);
        assert_eq!(body.len(), CERT_FIXED_LEN + 3);
    }

    #[test]
    fn cert_compiles_generic_header_then_body() {
        // The compiled payload is the 4-octet generic header (Next Payload 0
        // terminator, auto length) followed by the Certificate body.
        let payload = x509_cert_payload();
        let bytes = compile_payload(payload.clone());

        assert_eq!(bytes[0], 0); // Next Payload terminator.
        assert_eq!(bytes[1], 0); // Critical clear.
        let payload_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(payload_len, bytes.len());
        assert_eq!(payload_len, payload.encoded_len());
        assert_eq!(
            &bytes[GENERIC_PAYLOAD_HEADER_LEN..],
            &payload.cert_body()[..]
        );
    }

    #[test]
    fn payloads_honor_generic_header_overrides() {
        // Caller-pinned Next Payload, Critical, and Payload Length survive on both
        // the CERT and CERTREQ payloads.
        let cert = x509_cert_payload()
            .next_payload(39)
            .critical(true)
            .payload_length(0xBEEF);
        let bytes = compile_payload(cert);
        assert_eq!(bytes[0], 39);
        assert_eq!(bytes[1], 0x80); // Critical bit set.
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0xBEEF);

        let certreq = IkeCertReqPayload::x509_signature(vec![0xAAu8])
            .next_payload(37)
            .critical(true)
            .payload_length(0x00FF);
        let bytes = compile_payload(certreq);
        assert_eq!(bytes[0], 37);
        assert_eq!(bytes[1], 0x80);
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0x00FF);
    }

    #[test]
    fn chain_next_payload_points_at_cert_and_certreq() {
        // CERT (37) and CERTREQ (38) following another layer derive the preceding
        // header's Next Payload through payload_type_for_layer_name (registered
        // this step).
        use crate::protocols::ipsec::ikev2::payload::{
            following_next_payload, payload_type_for_layer_name, PAYLOAD_CERT, PAYLOAD_CERTREQ,
        };
        assert_eq!(
            payload_type_for_layer_name(IKE_CERT_PAYLOAD_NAME),
            Some(PayloadType::Certificate)
        );
        assert_eq!(
            payload_type_for_layer_name(IKE_CERTREQ_PAYLOAD_NAME),
            Some(PayloadType::CertificateRequest)
        );

        let packet: Packet = Packet::from_layer(Raw::from_bytes([0u8; 0])) / x509_cert_payload();
        let ctx = LayerContext::new(&packet, 0);
        assert_eq!(following_next_payload(&ctx), PAYLOAD_CERT);

        let packet: Packet = Packet::from_layer(Raw::from_bytes([0u8; 0]))
            / IkeCertReqPayload::x509_signature(vec![0xAAu8]);
        let ctx = LayerContext::new(&packet, 0);
        assert_eq!(following_next_payload(&ctx), PAYLOAD_CERTREQ);
    }

    #[test]
    fn round_trip_cert_preserves_encoding_and_data() {
        // Build an X.509 CERT with fixed data, compile to wire, parse the body
        // back, and confirm the encoding and data round-trip byte-for-byte
        // (Step 45 closes the registry decode; this is the local parse helper).
        let payload = x509_cert_payload();
        let bytes = compile_payload(payload.clone());

        let parsed = parse_cert_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(parsed.cert_encoding_value(), CERT_ENCODING_X509_SIGNATURE);
        assert_eq!(parsed.cert_encoding_kind(), CertEncoding::X509Signature);
        assert_eq!(
            parsed.cert_data_bytes(),
            &(0u8..16).collect::<Vec<u8>>()[..]
        );
        let recompiled = compile_payload(parsed);
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn round_trip_certreq_preserves_encoding_and_ca_data() {
        // The CERTREQ payload round-trips with arbitrary fixed Certification
        // Authority bytes carried verbatim.
        let payload = IkeCertReqPayload::x509_signature(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let bytes = compile_payload(payload.clone());

        let parsed = parse_certreq_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(parsed.cert_encoding_value(), CERT_ENCODING_X509_SIGNATURE);
        assert_eq!(parsed.ca_data_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        let recompiled = compile_payload(parsed);
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn parse_rejects_empty_body() {
        // An empty buffer is shorter than the fixed body header (the Cert
        // Encoding octet) and is a structured error, not a panic.
        let err = parse_cert_payload_body(&[]).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
        let err = parse_certreq_payload_body(&[]).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }
}
