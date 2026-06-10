//! IKEv2 Encrypted (SK) payload, type 46 (RFC 7296 §3.14).
//!
//! The Encrypted payload — `SK` in the RFC notation — confidentiality- and
//! integrity-protects the IKEv2 payloads that follow it in a message. Its body,
//! after the 4-octet generic payload header, is:
//!
//! ```text
//!  Initialization Vector (variable) | Encrypted IKE Payloads (variable)
//!    | Padding (0–255) | Pad Length (1) | Integrity Checksum Data (variable)
//! ```
//!
//! (RFC 7296 §3.14). The encrypted blob covers the inner IKE payload chain
//! followed by `Padding || Pad Length`; for a block cipher the padding aligns
//! that plaintext to the cipher's block size. The inner payloads form their own
//! Next Payload chain, and the SK generic header's Next Payload names the **first**
//! inner payload's type (RFC 7296 §3.14). Because the SK payload *owns* the inner
//! payloads (they are encrypted inside it, not emitted as sibling layers), an SK
//! payload is always the last payload of the message and does not consume any
//! following sibling layers.
//!
//! The crypto is driven by a [`SecurityAssociation`] through the shared
//! [`seal`]/[`open`] driver (Step 09), exactly as ESP does. RFC 7296 §3.14
//! specifies that, for a
//! non-AEAD suite, the Integrity Checksum Data covers the entire IKE message from
//! the first octet of the IKE header through the end of the SK payload (excluding
//! the checksum field itself). At the level of this payload's own `compile`, the
//! preceding IKE header bytes are not reachable, so the ICV here is computed over
//! the SK body's own integrity input (`IV || ciphertext`) via the SA driver. That
//! keeps `compile` and the SA-aware decode **symmetric** so the round-trip is
//! correct; wiring the full-message AAD belongs to the message-chain decode step
//! (Step 45) and does not change this payload's surface.

use crate::field::Field;
use crate::packet::{Layer, LayerContext, Packet};
use crate::protocols::ipsec::ikev2::payload::{
    write_generic_payload_header, IkePayload, PayloadHeaderFields, PayloadType,
};
use crate::protocols::ipsec::sa::{iv_requirement, open, seal, SecurityAssociation};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::{CrafterError, Result};

/// Layer name for the IKEv2 Encrypted (SK) payload, registered in
/// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_ENCRYPTED_PAYLOAD_NAME: &str = "IkeEncryptedPayload";

/// Length of the Pad Length field (RFC 7296 §3.14): a single octet giving the
/// number of Padding octets that precede it inside the encrypted blob.
pub const SK_PAD_LENGTH_FIELD_LEN: usize = 1;

/// IKEv2 Encrypted (SK) payload, type 46 (RFC 7296 §3.14).
///
/// Holds the inner IKE payload chain (as an owned [`Packet`]) and the
/// [`SecurityAssociation`] that seals/opens it. As a [`Layer`] it emits the
/// 4-octet generic payload header (via [`write_generic_payload_header`]) followed
/// by the SK body `IV || encrypted(inner || pad || pad-length) || ICV`.
///
/// The IV, padding, and ICV are auto-filled by `compile()` from the SA's crypto
/// parameters unless the caller pins them; any caller-set value (including a
/// deliberately wrong one for malformed testing) is emitted verbatim. The
/// generic-header Next Payload defaults to the first inner payload's type
/// (RFC 7296 §3.14); the Critical flag and Payload Length follow the shared
/// [`PayloadHeaderFields`] rules.
#[derive(Debug, Clone)]
pub struct IkeEncryptedPayload {
    /// The inner IKE payloads this SK payload encrypts (their own Next Payload
    /// chain). Owned, not sibling layers.
    inner: Packet,
    /// The crypto context driving seal/open (RFC 7296 §3.14).
    sa: SecurityAssociation,
    /// Explicit IV override; otherwise a deterministic IV of the cipher's length.
    iv: Field<Vec<u8>>,
    /// Explicit Padding override; otherwise computed to the cipher block boundary.
    pad: Field<Vec<u8>>,
    /// Explicit Pad Length override; otherwise derived from the padding length.
    pad_length: Field<u8>,
    /// Explicit Integrity Checksum Data override; otherwise the SA-computed ICV.
    icv: Field<Vec<u8>>,
    /// Shared generic-payload-header overrides (Next Payload, Length, Critical).
    header: PayloadHeaderFields,
}

impl IkeEncryptedPayload {
    /// Create an Encrypted (SK) payload sealed under `sa`, with no inner payloads
    /// yet (RFC 7296 §3.14). Add the inner payload chain with
    /// [`IkeEncryptedPayload::payloads`] or [`IkeEncryptedPayload::payload`].
    pub fn new(sa: SecurityAssociation) -> Self {
        Self {
            inner: Packet::new(),
            sa,
            iv: Field::unset(),
            pad: Field::unset(),
            pad_length: Field::unset(),
            icv: Field::unset(),
            header: PayloadHeaderFields::new(),
        }
    }

    /// Set the inner IKE payload chain from a [`Packet`] of payload layers
    /// (RFC 7296 §3.14), replacing any previously added inner payloads.
    ///
    /// The inner payloads form their own Next Payload chain; the SK generic-header
    /// Next Payload is derived from the first of them at `compile()`.
    pub fn payloads(mut self, inner: impl Into<Packet>) -> Self {
        self.inner = inner.into();
        self
    }

    /// Append one inner IKE payload layer to the encrypted chain (RFC 7296 §3.14).
    pub fn payload<L>(mut self, layer: L) -> Self
    where
        L: Layer,
    {
        self.inner = self.inner.push(layer);
        self
    }

    /// Set an explicit Initialization Vector for deterministic ciphertext
    /// (RFC 7296 §3.14). Overrides the cipher's default IV.
    pub fn iv(mut self, iv: impl Into<Vec<u8>>) -> Self {
        self.iv.set_user(iv.into());
        self
    }

    /// Set explicit Padding bytes (RFC 7296 §3.14), overriding the computed
    /// block-aligned padding for deterministic or deliberately malformed output.
    pub fn pad(mut self, pad: impl Into<Vec<u8>>) -> Self {
        self.pad.set_user(pad.into());
        self
    }

    /// Pin the Pad Length octet explicitly (RFC 7296 §3.14), overriding the value
    /// derived from the padding length. A deliberately inconsistent value is
    /// emitted verbatim for malformed testing.
    pub fn pad_length(mut self, pad_length: u8) -> Self {
        self.pad_length.set_user(pad_length);
        self
    }

    /// Set explicit Integrity Checksum Data (RFC 7296 §3.14), overriding the
    /// SA-computed ICV for deterministic or deliberately malformed output.
    pub fn icv(mut self, icv: impl Into<Vec<u8>>) -> Self {
        self.icv.set_user(icv.into());
        self
    }

    /// Pin the generic-header Next Payload explicitly (RFC 7296 §3.2). Otherwise
    /// it is derived from the first inner payload's type.
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

    /// The attached Security Association (RFC 7296 §3.14).
    pub fn security_association(&self) -> &SecurityAssociation {
        &self.sa
    }

    /// The inner IKE payload chain this SK payload encrypts (RFC 7296 §3.14).
    pub fn inner_payloads(&self) -> &Packet {
        &self.inner
    }

    /// Explicit IV override bytes, when set.
    pub fn iv_value(&self) -> Option<&[u8]> {
        self.iv.value().map(Vec::as_slice)
    }

    /// Explicit Padding override bytes, when set.
    pub fn pad_value(&self) -> Option<&[u8]> {
        self.pad.value().map(Vec::as_slice)
    }

    /// Explicit ICV override bytes, when set.
    pub fn icv_value(&self) -> Option<&[u8]> {
        self.icv.value().map(Vec::as_slice)
    }

    /// Serialize the inner IKE payload chain to bytes (RFC 7296 §3.14).
    ///
    /// Each inner payload is compiled in a context where its siblings follow it,
    /// so the inner Next Payload chain is derived correctly (the first inner
    /// payload's Next Payload names the second, and so on).
    fn inner_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for (index, layer) in self.inner.iter().enumerate() {
            let ctx = LayerContext::new(&self.inner, index);
            layer.compile(&ctx, &mut out)?;
        }
        Ok(out)
    }

    /// The Next Payload codepoint naming the first inner payload (RFC 7296 §3.14).
    ///
    /// A caller-pinned Next Payload wins; otherwise it is the type of the first
    /// inner payload (mapped from its layer name via
    /// [`payload_type_for_layer_name`](super::payload_type_for_layer_name)),
    /// defaulting to the chain terminator `0` when there are no inner payloads.
    fn effective_next_payload(&self) -> u8 {
        if let Some(next_payload) = self.header.next_payload_override() {
            return next_payload;
        }
        self.inner
            .get(0)
            .and_then(|layer| super::payload_type_for_layer_name(layer.name()))
            .map(PayloadType::codepoint)
            .unwrap_or(super::PAYLOAD_TYPE_NONE)
    }

    /// Compute the RFC 7296 §3.14 padding for an encrypted plaintext of
    /// `inner_len` octets under `block_size`.
    ///
    /// The plaintext sealed by the cipher is `inner || pad || pad-length`; its
    /// total length must be a multiple of the cipher block size (RFC 7296 §3.14).
    /// A caller-set [`pad`] override is returned verbatim, even when it breaks the
    /// alignment, so deliberately malformed packets remain buildable.
    ///
    /// [`pad`]: IkeEncryptedPayload::pad
    fn effective_pad(&self, inner_len: usize, block_size: usize) -> Vec<u8> {
        if let Some(pad) = self.pad.value() {
            return pad.clone();
        }
        let alignment = block_size.max(1);
        // The Pad Length octet always follows the padding inside the encrypted
        // blob, so the alignment target covers `inner + pad + 1`.
        let unaligned = inner_len + SK_PAD_LENGTH_FIELD_LEN;
        let remainder = unaligned % alignment;
        let pad_len = if remainder == 0 {
            0
        } else {
            alignment - remainder
        };
        // RFC 7296 §3.14 leaves the Padding values to the sender; mirror RFC 4303
        // ESP and emit the monotonically increasing sequence 1, 2, 3, ….
        (1..=pad_len as u8).collect()
    }

    /// Build the SK plaintext (`inner || pad || pad-length`) and explicit IV that
    /// `compile()` seals (RFC 7296 §3.14).
    ///
    /// Returns `(plaintext, iv)`.
    fn sk_seal_inputs(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let inner = self.inner_payload_bytes()?;

        let block_size = self.sa.enc.block_size();
        let pad = self.effective_pad(inner.len(), block_size);
        let pad_len = match self.pad_length.value().copied() {
            Some(pad_len) => pad_len,
            None => u8::try_from(pad.len()).map_err(|_| {
                CrafterError::invalid_field_value("ikev2.sk.pad", "SK padding exceeds 255 octets")
            })?,
        };

        let mut plaintext = Vec::with_capacity(inner.len() + pad.len() + SK_PAD_LENGTH_FIELD_LEN);
        plaintext.extend_from_slice(&inner);
        plaintext.extend_from_slice(&pad);
        plaintext.push(pad_len);

        // Explicit IV: caller override, else a deterministic all-zero IV of the
        // cipher's IV length (RFC 7296 §3.14 leaves IV generation to the sender;
        // an all-zero default keeps the bytes reproducible for tests/oracle).
        let iv = match self.iv.value() {
            Some(iv) => iv.clone(),
            None => vec![0u8; iv_requirement(&self.sa).iv_len],
        };

        Ok((plaintext, iv))
    }

    /// The SK body (everything after the 4-octet generic header), per
    /// RFC 7296 §3.14: `IV || encrypted(inner || pad || pad-length) || ICV`.
    ///
    /// The encryption and ICV come from the shared SA driver. The ICV integrity
    /// input here is the SK body's own `IV || ciphertext` (the full-message AAD of
    /// §3.14 is wired by the message-chain decode step); `compile` and the
    /// SA-aware decode use the same input so the round-trip is symmetric. A caller
    /// IV/pad/ICV override is honored verbatim.
    fn sk_body(&self) -> Result<Vec<u8>> {
        let (plaintext, iv) = self.sk_seal_inputs()?;

        // AAD is empty at the payload level: the SK body's integrity input is
        // `IV || ciphertext` (the driver prepends the IV). The full IKE-message
        // AAD of RFC 7296 §3.14 is applied by the chain decode step (Step 45).
        let sealed = seal(&self.sa, &iv, &[], &plaintext)?;
        let icv = match self.icv.value() {
            Some(icv) => icv.clone(),
            None => sealed.icv,
        };

        let mut body = Vec::with_capacity(iv.len() + sealed.ciphertext.len() + icv.len());
        body.extend_from_slice(&iv);
        body.extend_from_slice(&sealed.ciphertext);
        body.extend_from_slice(&icv);
        Ok(body)
    }
}

impl IkePayload for IkeEncryptedPayload {
    fn payload_type(&self) -> PayloadType {
        PayloadType::Encrypted
    }

    fn payload_body(&self, _ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        self.sk_body()
    }

    fn next_payload_override(&self) -> Option<u8> {
        // The SK generic-header Next Payload names the FIRST inner payload, not a
        // sibling. Resolve it here so `write_generic_payload_header` does not try
        // to derive it from a following sibling layer (there is none).
        Some(self.effective_next_payload())
    }

    fn payload_length_override(&self) -> Option<u16> {
        self.header.payload_length_override()
    }

    fn critical(&self) -> bool {
        self.header.critical()
    }
}

impl Layer for IkeEncryptedPayload {
    fn name(&self) -> &'static str {
        IKE_ENCRYPTED_PAYLOAD_NAME
    }

    fn summary(&self) -> String {
        format!(
            "IkeEncryptedPayload(inner_payloads={}, {})",
            self.inner.len(),
            self.sa.summary(),
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("next_payload", self.effective_next_payload().to_string()),
            ("inner_payloads", self.inner.len().to_string()),
            ("spi", format!("0x{:08x}", self.sa.spi)),
            ("mode", self.sa.mode.label().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        // Best-effort estimate: generic header + SK body. The body's exact size
        // depends on the inner payloads and the cipher; compile to measure when
        // possible, else fall back to the generic header alone.
        match self.sk_body() {
            Ok(body) => super::GENERIC_PAYLOAD_HEADER_LEN + body.len(),
            Err(_) => super::GENERIC_PAYLOAD_HEADER_LEN,
        }
    }

    fn consumes_following(&self) -> bool {
        // The SK payload owns its inner payloads (they are encrypted inside it),
        // so they are NOT sibling layers in the parent packet. An SK payload is
        // therefore the last payload of a message and consumes no following
        // sibling layers — the default false is correct (RFC 7296 §3.14).
        false
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Emit the 4-octet generic payload header (Next Payload = the first inner
        // payload's type unless overridden, auto Payload Length unless
        // overridden), then the SK body `IV || ciphertext || ICV`.
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

    impl_layer_object!(IkeEncryptedPayload);
}

impl_layer_div!(IkeEncryptedPayload);

// --- SA-aware decode (Step 45 closes the full registry chain decode) ---------

/// A decoded Encrypted (SK) payload: the recovered inner payload bytes plus the
/// generic-header Next Payload naming the first inner payload (RFC 7296 §3.14).
///
/// The inner payload chain itself is parsed by the message-chain decode step
/// (Step 45); this struct carries the decrypted, pad-stripped inner bytes and the
/// first inner payload type so that walker can start the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSk {
    /// Next Payload from the SK generic header: the type of the first inner
    /// payload (RFC 7296 §3.14).
    pub first_inner_payload: u8,
    /// The decrypted inner IKE payload bytes (padding and Pad Length stripped).
    pub inner_payloads: Vec<u8>,
}

/// Decode an Encrypted (SK) **payload** (generic header + body) under `sa`,
/// verifying integrity, decrypting, and stripping the padding (RFC 7296 §3.14).
///
/// `bytes` is the full SK payload including its 4-octet generic header. The body
/// is split into `IV || ciphertext || ICV` by the SA's IV and ICV lengths, opened
/// through the shared [`open`] driver (which verifies the ICV in constant time
/// before decrypting, and never returns unauthenticated plaintext), and the
/// trailing `Pad Length` octet and its padding removed. A truncated buffer, an
/// inconsistent length, or an integrity failure is a structured error, never a
/// panic.
///
/// This is the SA-aware counterpart of [`IkeEncryptedPayload::compile`]; the two
/// share the same `IV || ciphertext` integrity input so the round-trip is exact.
/// The full registry-driven chain decode lands in Step 45.
pub fn decode_sk_payload_with_sa(bytes: &[u8], sa: &SecurityAssociation) -> Result<DecodedSk> {
    use super::GENERIC_PAYLOAD_HEADER_LEN;

    if bytes.len() < GENERIC_PAYLOAD_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ikev2.sk",
            GENERIC_PAYLOAD_HEADER_LEN,
            bytes.len(),
        ));
    }
    let first_inner_payload = bytes[0];
    let body = &bytes[GENERIC_PAYLOAD_HEADER_LEN..];

    let iv_len = iv_requirement(sa).iv_len;
    let icv_len = sk_icv_len(sa);

    let fixed = iv_len + icv_len;
    if body.len() < fixed {
        return Err(CrafterError::buffer_too_short(
            "ikev2.sk.body",
            fixed,
            body.len(),
        ));
    }

    let iv = &body[..iv_len];
    let ciphertext = &body[iv_len..body.len() - icv_len];
    let icv = &body[body.len() - icv_len..];

    // Open: verify the ICV first, then decrypt. The integrity input matches
    // compile's (`IV || ciphertext` with empty AAD); a tampered ICV or ciphertext
    // is a structured error, never plaintext.
    let plaintext = open(sa, iv, &[], ciphertext, icv)?;

    // Strip the trailing Pad Length octet and its padding (RFC 7296 §3.14).
    if plaintext.is_empty() {
        return Err(CrafterError::buffer_too_short(
            "ikev2.sk.plaintext",
            SK_PAD_LENGTH_FIELD_LEN,
            0,
        ));
    }
    let pad_len = *plaintext.last().unwrap() as usize;
    let inner_end = plaintext.len() - SK_PAD_LENGTH_FIELD_LEN;
    if pad_len > inner_end {
        return Err(CrafterError::invalid_field_value(
            "ikev2.sk.pad_length",
            "SK Pad Length exceeds the decrypted plaintext",
        ));
    }
    let inner_payloads = plaintext[..inner_end - pad_len].to_vec();

    Ok(DecodedSk {
        first_inner_payload,
        inner_payloads,
    })
}

/// The Integrity Checksum Data length in octets for `sa` (RFC 7296 §3.14).
///
/// For an AEAD suite this is the AEAD tag length; for a cipher+integrity suite it
/// is the separate integrity algorithm's ICV length. A suite with neither carries
/// no checksum (length 0).
fn sk_icv_len(sa: &SecurityAssociation) -> usize {
    if sa.enc.is_aead() {
        sa.enc.icv_len().unwrap_or(0)
    } else {
        sa.integ.icv_len().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::ipsec::ikev2::header::IkeHeader;
    use crate::protocols::ipsec::ikev2::payload::notify::{
        IkeNotifyPayload, NotifyType, IKE_NOTIFY_PAYLOAD_NAME, NOTIFY_PROTOCOL_ESP,
    };
    use crate::protocols::ipsec::ikev2::payload::{
        payload_type_for_layer_name, GENERIC_PAYLOAD_HEADER_LEN, PAYLOAD_NOTIFY,
    };
    use crate::protocols::ipsec::sa::{EncryptionAlgorithm, IntegrityAlgorithm};

    /// A CBC + HMAC-SHA-256-128 SA driving the SK crypto (documentation keys).
    fn cbc_hmac_sa() -> SecurityAssociation {
        SecurityAssociation::new(0x0000_2000)
            .encryption(EncryptionAlgorithm::AesCbc, vec![0x11u8; 16])
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0x33u8; 32])
    }

    /// An AES-GCM AEAD SA driving the SK crypto (documentation keys).
    fn gcm_sa() -> SecurityAssociation {
        SecurityAssociation::new(0x0000_2000)
            .encryption(EncryptionAlgorithm::AesGcm16, vec![0x22u8; 16])
            .salt(vec![0xAA, 0xBB, 0xCC, 0xDD])
    }

    /// A representative inner Notify payload (REKEY_SA, ESP protocol, a SPI).
    fn inner_notify() -> IkeNotifyPayload {
        IkeNotifyPayload::new(NOTIFY_PROTOCOL_ESP, NotifyType::RekeySa, vec![0xDE, 0xAD])
            .spi(vec![0x10u8, 0x20, 0x30, 0x40])
    }

    /// Compile a standalone SK payload (generic header + body) through a one-layer
    /// packet, returning its full bytes.
    fn compile_sk(payload: IkeEncryptedPayload) -> Vec<u8> {
        let packet = Packet::from_layer(payload);
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    #[test]
    fn payload_type_is_encrypted_and_name_registered() {
        let sk = IkeEncryptedPayload::new(cbc_hmac_sa()).payload(inner_notify());
        assert_eq!(sk.payload_type(), PayloadType::Encrypted);
        assert_eq!(sk.name(), IKE_ENCRYPTED_PAYLOAD_NAME);
        // The name resolves to the Encrypted type so the chain wiring can derive
        // the preceding header's Next Payload.
        assert_eq!(
            payload_type_for_layer_name(IKE_ENCRYPTED_PAYLOAD_NAME),
            Some(PayloadType::Encrypted)
        );
    }

    #[test]
    fn sk_does_not_consume_following_siblings() {
        // The inner payloads are owned, not siblings; the SK payload consumes no
        // following sibling layer (RFC 7296 §3.14).
        let sk = IkeEncryptedPayload::new(cbc_hmac_sa()).payload(inner_notify());
        assert!(!sk.consumes_following());
    }

    #[test]
    fn generic_header_next_payload_names_first_inner_payload() {
        // RFC 7296 §3.14: the SK generic-header Next Payload names the FIRST inner
        // payload's type (Notify = 41 here), not a sibling.
        let sk = IkeEncryptedPayload::new(cbc_hmac_sa()).payload(inner_notify());
        let bytes = compile_sk(sk);
        assert_eq!(bytes[0], PAYLOAD_NOTIFY);
    }

    #[test]
    fn cbc_round_trip_recovers_inner_notify() {
        // Build IkeHeader / SK(sa, [Notify]); compile the SK, then decode-with-SA
        // recovers the inner Notify bytes exactly.
        let sa = cbc_hmac_sa();
        let inner = inner_notify();

        // The inner payload bytes, as they appear inside the encrypted blob.
        let inner_packet = Packet::from_layer(inner.clone());
        let inner_ctx = LayerContext::new(&inner_packet, 0);
        let mut inner_bytes = Vec::new();
        inner_packet
            .get(0)
            .unwrap()
            .compile(&inner_ctx, &mut inner_bytes)
            .unwrap();

        // A full IKE message header / SK(sa, [Notify]) compiles cleanly.
        let header = IkeHeader::new().exchange(35).initiator();
        let sk = IkeEncryptedPayload::new(sa.clone()).payload(inner);
        let message: Packet = Packet::from_layer(header) / sk;
        // The header's Next Payload points at the SK payload (Encrypted = 46).
        let mut header_bytes = Vec::new();
        let header_ctx = LayerContext::new(&message, 0);
        message
            .get(0)
            .unwrap()
            .compile(&header_ctx, &mut header_bytes)
            .unwrap();
        assert_eq!(header_bytes[16], PayloadType::Encrypted.codepoint());

        // Compile just the SK payload and decode it back with the SA.
        let mut sk_bytes = Vec::new();
        let sk_ctx = LayerContext::new(&message, 1);
        message
            .get(1)
            .unwrap()
            .compile(&sk_ctx, &mut sk_bytes)
            .unwrap();

        let decoded = decode_sk_payload_with_sa(&sk_bytes, &sa).unwrap();
        assert_eq!(decoded.first_inner_payload, PAYLOAD_NOTIFY);
        assert_eq!(decoded.inner_payloads, inner_bytes);

        // The recovered bytes parse back into the same Notify payload type.
        assert_eq!(
            payload_type_for_layer_name(IKE_NOTIFY_PAYLOAD_NAME),
            Some(PayloadType::Notify)
        );
    }

    #[test]
    fn gcm_round_trip_recovers_inner_notify() {
        // The same round-trip over an AEAD (AES-GCM) suite.
        let sa = gcm_sa();
        let inner = inner_notify();

        let inner_packet = Packet::from_layer(inner.clone());
        let inner_ctx = LayerContext::new(&inner_packet, 0);
        let mut inner_bytes = Vec::new();
        inner_packet
            .get(0)
            .unwrap()
            .compile(&inner_ctx, &mut inner_bytes)
            .unwrap();

        let sk = IkeEncryptedPayload::new(sa.clone()).payload(inner);
        let sk_bytes = compile_sk(sk);

        let decoded = decode_sk_payload_with_sa(&sk_bytes, &sa).unwrap();
        assert_eq!(decoded.first_inner_payload, PAYLOAD_NOTIFY);
        assert_eq!(decoded.inner_payloads, inner_bytes);
    }

    #[test]
    fn body_layout_is_iv_ciphertext_icv() {
        // RFC 7296 §3.14: the SK body is IV | ciphertext | ICV. For CBC the IV is
        // 16 octets, the ICV (HMAC-SHA-256-128) is 16 octets, and the ciphertext
        // is block-aligned to 16 octets.
        let sa = cbc_hmac_sa();
        let sk = IkeEncryptedPayload::new(sa.clone()).payload(inner_notify());
        let bytes = compile_sk(sk);
        let body = &bytes[GENERIC_PAYLOAD_HEADER_LEN..];

        let iv_len = 16;
        let icv_len = 16;
        assert!(body.len() > iv_len + icv_len);
        let ciphertext_len = body.len() - iv_len - icv_len;
        // The ciphertext (inner || pad || pad-length) is a multiple of the block.
        assert_eq!(ciphertext_len % 16, 0);
        // The generic-header Payload Length covers the whole payload.
        let payload_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(payload_len, bytes.len());
    }

    #[test]
    fn iv_and_icv_overrides_are_emitted_verbatim() {
        // A caller-pinned IV and ICV survive untouched (deterministic / malformed).
        let sa = cbc_hmac_sa();
        let iv: Vec<u8> = (0u8..16).collect();
        let icv = vec![0xEEu8; 16];
        let sk = IkeEncryptedPayload::new(sa)
            .payload(inner_notify())
            .iv(iv.clone())
            .icv(icv.clone());
        let bytes = compile_sk(sk);
        let body = &bytes[GENERIC_PAYLOAD_HEADER_LEN..];
        assert_eq!(&body[..16], &iv[..]);
        assert_eq!(&body[body.len() - 16..], &icv[..]);
    }

    #[test]
    fn flipped_icv_bit_makes_decode_error() {
        // A one-bit ICV tamper must make decode fail (no panic, no wrong plaintext).
        let sa = cbc_hmac_sa();
        let sk = IkeEncryptedPayload::new(sa.clone()).payload(inner_notify());
        let mut bytes = compile_sk(sk);
        // The last octet is part of the ICV.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let result = decode_sk_payload_with_sa(&bytes, &sa);
        assert!(result.is_err(), "a tampered ICV must make decode error");
    }

    #[test]
    fn flipped_ciphertext_bit_makes_decode_error() {
        // A one-bit ciphertext tamper must fail integrity verification.
        let sa = cbc_hmac_sa();
        let sk = IkeEncryptedPayload::new(sa.clone()).payload(inner_notify());
        let mut bytes = compile_sk(sk);
        // Flip a byte inside the ciphertext (just past the generic header + IV).
        let ct_index = GENERIC_PAYLOAD_HEADER_LEN + 16; // first ciphertext octet
        bytes[ct_index] ^= 0x01;
        let result = decode_sk_payload_with_sa(&bytes, &sa);
        assert!(
            result.is_err(),
            "a tampered ciphertext must make decode error"
        );
    }

    #[test]
    fn gcm_flipped_icv_bit_makes_decode_error() {
        // The AEAD tag tamper also fails closed.
        let sa = gcm_sa();
        let sk = IkeEncryptedPayload::new(sa.clone()).payload(inner_notify());
        let mut bytes = compile_sk(sk);
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(decode_sk_payload_with_sa(&bytes, &sa).is_err());
    }

    #[test]
    fn decode_rejects_truncated_body() {
        // A buffer too short to hold IV + ICV is a structured error, not a panic.
        let sa = cbc_hmac_sa();
        // Generic header (4) + a few stray body octets, far short of IV(16)+ICV(16).
        let bytes = vec![PAYLOAD_NOTIFY, 0, 0, 8, 0xAA, 0xBB, 0xCC, 0xDD];
        let err = decode_sk_payload_with_sa(&bytes, &sa).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }

    #[test]
    fn decode_rejects_truncated_generic_header() {
        // Fewer than 4 octets cannot even hold the generic header.
        let sa = cbc_hmac_sa();
        let err = decode_sk_payload_with_sa(&[0u8, 0, 0], &sa).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }

    #[test]
    fn multiple_inner_payloads_chain_and_round_trip() {
        // Two inner payloads: the first inner Next Payload names the second, and
        // the SK generic header names the first (Notify). Decode recovers both.
        let sa = cbc_hmac_sa();
        let first = inner_notify();
        let second = IkeNotifyPayload::new(
            NOTIFY_PROTOCOL_ESP,
            NotifyType::InitialContact,
            Vec::<u8>::new(),
        );

        // Reference inner bytes: compile the two-payload chain directly.
        let inner_packet: Packet = Packet::from_layer(first.clone()) / second.clone();
        let mut inner_bytes = Vec::new();
        for (index, layer) in inner_packet.iter().enumerate() {
            let ctx = LayerContext::new(&inner_packet, index);
            layer.compile(&ctx, &mut inner_bytes).unwrap();
        }
        // The first inner payload's Next Payload must name the second (Notify).
        assert_eq!(inner_bytes[0], PAYLOAD_NOTIFY);

        let sk = IkeEncryptedPayload::new(sa.clone())
            .payload(first)
            .payload(second);
        let sk_bytes = compile_sk(sk);
        let decoded = decode_sk_payload_with_sa(&sk_bytes, &sa).unwrap();
        assert_eq!(decoded.first_inner_payload, PAYLOAD_NOTIFY);
        assert_eq!(decoded.inner_payloads, inner_bytes);
    }
}
