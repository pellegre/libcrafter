//! QUIC packet-protection helpers.
//!
//! This module stays utility-level: it exposes source-backed helpers for
//! explicit caller-supplied inputs and fixed vectors, but it never implies
//! ownership of TLS session state or a complete QUIC endpoint.

use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use aes::Aes128;
use aes_gcm::aead::{consts::U12 as AesGcmU12, Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit as AesGcmKeyInit, Nonce as AesGcmNonce};
use chacha20::cipher::{KeyIvInit as ChaChaKeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use cipher::generic_array::GenericArray;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::connection_id::QUIC_CONNECTION_ID_MAX_LEN;
use super::constants::{QUIC_VERSION_1, QUIC_VERSION_2};
use super::frame::QuicFrame;
use super::header::{classify_quic_header, QuicHeaderClassification, QuicLongPacketKind};
use super::packet::{
    QuicLongHeaderPacket, QuicPacket, QuicRetryPacket, QUIC_RETRY_INTEGRITY_TAG_LEN,
};
use super::packet_number::{header_bits_for_len, len_from_header_bits, QuicPacketNumber};
use super::varint::{encoded_len_from_prefix, QuicVarInt};
use crate::error::{CrafterError, Result};

type HmacSha256 = Hmac<Sha256>;
type AesGcmNonce12 = AesGcmNonce<AesGcmU12>;

/// Length of a QUIC Initial secret derived with SHA-256.
pub const QUIC_INITIAL_SECRET_LEN: usize = 32;
/// Length of the AES-128 packet-protection key used by Initial vectors.
pub const QUIC_INITIAL_AES_128_KEY_LEN: usize = 16;
/// Length of the Initial packet-protection IV.
pub const QUIC_INITIAL_IV_LEN: usize = 12;
/// Length of the AES header-protection key used by Initial vectors.
pub const QUIC_INITIAL_HP_KEY_LEN: usize = 16;
/// Length of the AES-GCM authentication tag carried by Initial payloads.
pub const QUIC_INITIAL_AEAD_TAG_LEN: usize = 16;
/// Length of a QUIC header-protection ciphertext sample.
pub const QUIC_HEADER_PROTECTION_SAMPLE_LEN: usize = 16;
/// Length of the QUIC header-protection mask consumed by packet headers.
pub const QUIC_HEADER_PROTECTION_MASK_LEN: usize = 5;
/// Length of the AES-128 header-protection key.
pub const QUIC_AES128_HEADER_PROTECTION_KEY_LEN: usize = 16;
/// Length of the ChaCha20 header-protection key.
pub const QUIC_CHACHA20_HEADER_PROTECTION_KEY_LEN: usize = 32;

const QUIC_RETRY_INTEGRITY_KEY_LEN: usize = 16;
const QUIC_RETRY_INTEGRITY_NONCE_LEN: usize = 12;

/// RFC 9001 QUIC v1 Initial salt.
pub const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// RFC 9369 QUIC v2 Initial salt.
pub const QUIC_V2_INITIAL_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

const QUIC_V1_RETRY_INTEGRITY_KEY: [u8; QUIC_RETRY_INTEGRITY_KEY_LEN] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

const QUIC_V1_RETRY_INTEGRITY_NONCE: [u8; QUIC_RETRY_INTEGRITY_NONCE_LEN] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

const QUIC_V2_RETRY_INTEGRITY_KEY: [u8; QUIC_RETRY_INTEGRITY_KEY_LEN] = [
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
];

const QUIC_V2_RETRY_INTEGRITY_NONCE: [u8; QUIC_RETRY_INTEGRITY_NONCE_LEN] = [
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
];

/// Placeholder context for future higher-level packet-protection helpers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuicCryptoContext;

impl QuicCryptoContext {
    /// Create an empty context.
    pub const fn new() -> Self {
        Self
    }

    /// Non-panicking placeholder that reports deferred automatic protection.
    pub fn protect_placeholder(self, _packet: &[u8]) -> Result<Vec<u8>> {
        Err(CrafterError::invalid_field_value(
            "quic.crypto",
            "automatic QUIC packet protection is not implemented; use explicit helpers",
        ))
    }
}

/// QUIC Initial secrets for one version and destination connection ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicInitialSecrets {
    version: u32,
    initial_secret: [u8; QUIC_INITIAL_SECRET_LEN],
    client_initial_secret: [u8; QUIC_INITIAL_SECRET_LEN],
    server_initial_secret: [u8; QUIC_INITIAL_SECRET_LEN],
}

impl QuicInitialSecrets {
    /// Return the QUIC version used to select salt and packet-protection labels.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Return the common Initial PRK from HKDF-Extract.
    pub const fn initial_secret(&self) -> &[u8; QUIC_INITIAL_SECRET_LEN] {
        &self.initial_secret
    }

    /// Return the client Initial traffic secret.
    pub const fn client_initial_secret(&self) -> &[u8; QUIC_INITIAL_SECRET_LEN] {
        &self.client_initial_secret
    }

    /// Return the server Initial traffic secret.
    pub const fn server_initial_secret(&self) -> &[u8; QUIC_INITIAL_SECRET_LEN] {
        &self.server_initial_secret
    }

    /// Derive client Initial AES-128 key, IV, and header-protection key.
    pub fn client_packet_keys(&self) -> Result<QuicInitialPacketKeys> {
        derive_initial_packet_keys(self.version, &self.client_initial_secret)
    }

    /// Derive server Initial AES-128 key, IV, and header-protection key.
    pub fn server_packet_keys(&self) -> Result<QuicInitialPacketKeys> {
        derive_initial_packet_keys(self.version, &self.server_initial_secret)
    }
}

/// QUIC Initial packet-protection material for deterministic vector checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicInitialPacketKeys {
    key: [u8; QUIC_INITIAL_AES_128_KEY_LEN],
    iv: [u8; QUIC_INITIAL_IV_LEN],
    header_protection_key: [u8; QUIC_INITIAL_HP_KEY_LEN],
}

impl QuicInitialPacketKeys {
    /// Return the AES-128 packet-protection key.
    pub const fn key(&self) -> &[u8; QUIC_INITIAL_AES_128_KEY_LEN] {
        &self.key
    }

    /// Return the packet-protection IV.
    pub const fn iv(&self) -> &[u8; QUIC_INITIAL_IV_LEN] {
        &self.iv
    }

    /// Return the AES header-protection key.
    pub const fn header_protection_key(&self) -> &[u8; QUIC_INITIAL_HP_KEY_LEN] {
        &self.header_protection_key
    }

    /// Generate the AES-128 Initial header-protection mask for a ciphertext
    /// sample.
    pub fn header_protection_mask(
        &self,
        sample: impl AsRef<[u8]>,
    ) -> Result<[u8; QUIC_HEADER_PROTECTION_MASK_LEN]> {
        quic_aes128_header_protection_mask(&self.header_protection_key, sample)
    }

    /// Encrypt an Initial packet payload with AES-128-GCM and append the tag.
    pub fn protect_payload(
        &self,
        packet_number: u64,
        associated_data: impl AsRef<[u8]>,
        plaintext: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>> {
        quic_initial_aes128gcm_protect_payload(self, packet_number, associated_data, plaintext)
    }

    /// Decrypt an Initial packet ciphertext-and-tag with AES-128-GCM.
    pub fn unprotect_payload(
        &self,
        packet_number: u64,
        associated_data: impl AsRef<[u8]>,
        ciphertext_and_tag: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>> {
        quic_initial_aes128gcm_unprotect_payload(
            self,
            packet_number,
            associated_data,
            ciphertext_and_tag,
        )
    }

    /// Remove Initial header protection, decrypt the payload, and decode frames.
    pub fn decode_protected_initial_payload(
        &self,
        packet: impl AsRef<[u8]>,
    ) -> Result<QuicInitialProtectedPayload> {
        quic_decode_initial_protected_payload_with_keys(packet, self)
    }
}

/// Direction of Initial keys used to protect a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicInitialPacketDirection {
    /// Packets protected with client Initial packet keys.
    Client,
    /// Packets protected with server Initial packet keys.
    Server,
}

impl QuicInitialPacketDirection {
    /// Return a stable label for summaries and diagnostics.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

/// Result of explicitly decoding a protected QUIC Initial payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicInitialProtectedPayload {
    version: u32,
    packet_number: QuicPacketNumber,
    packet_number_offset: usize,
    packet_number_len: usize,
    unprotected_header: Vec<u8>,
    protected_payload: Vec<u8>,
    decrypted_payload: Vec<u8>,
    frames: Vec<QuicFrame>,
}

/// Retry Integrity Tag verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicRetryIntegrityStatus {
    /// The supplied tag matches the source-backed computed tag.
    Valid,
    /// The supplied tag does not match the source-backed computed tag.
    Invalid,
    /// The packet version has no source-backed Retry integrity key in this crate.
    UnsupportedVersion,
}

impl QuicRetryIntegrityStatus {
    /// Return a stable label for summaries and diagnostics.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::UnsupportedVersion => "unsupported_version",
        }
    }
}

impl QuicInitialProtectedPayload {
    /// QUIC version from the packet header.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Decoded truncated packet number.
    pub const fn packet_number(&self) -> QuicPacketNumber {
        self.packet_number
    }

    /// Offset of the packet-number bytes in the packet header.
    pub const fn packet_number_offset(&self) -> usize {
        self.packet_number_offset
    }

    /// Encoded packet-number length after removing header protection.
    pub const fn packet_number_len(&self) -> usize {
        self.packet_number_len
    }

    /// Header bytes after removing header protection.
    pub fn unprotected_header(&self) -> &[u8] {
        &self.unprotected_header
    }

    /// Encrypted payload bytes, including the AEAD tag.
    pub fn protected_payload(&self) -> &[u8] {
        &self.protected_payload
    }

    /// Decrypted Initial payload bytes.
    pub fn decrypted_payload(&self) -> &[u8] {
        &self.decrypted_payload
    }

    /// Decoded frame sequence from the decrypted payload.
    pub fn frames(&self) -> &[QuicFrame] {
        &self.frames
    }

    /// Number of decoded frame entries.
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }
}

/// Source-backed QUIC header-protection mask algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicHeaderProtectionAlgorithm {
    /// AES-128 ECB mask generation, used with AES-128-GCM Initial vectors.
    Aes128,
    /// Raw ChaCha20 mask generation, used with ChaCha20-Poly1305 vectors.
    ChaCha20,
}

impl QuicHeaderProtectionAlgorithm {
    /// Return the expected header-protection key length.
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128 => QUIC_AES128_HEADER_PROTECTION_KEY_LEN,
            Self::ChaCha20 => QUIC_CHACHA20_HEADER_PROTECTION_KEY_LEN,
        }
    }

    /// Return a stable algorithm label for inspection and diagnostics.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Aes128 => "aes128",
            Self::ChaCha20 => "chacha20",
        }
    }
}

/// Return the source-backed QUIC Initial salt for supported versions.
pub fn quic_initial_salt(version: u32) -> Result<&'static [u8; 20]> {
    match version {
        QUIC_VERSION_1 => Ok(&QUIC_V1_INITIAL_SALT),
        QUIC_VERSION_2 => Ok(&QUIC_V2_INITIAL_SALT),
        _ => Err(CrafterError::invalid_field_value(
            "quic.crypto.initial.version",
            "unsupported QUIC Initial salt version",
        )),
    }
}

/// Derive QUIC Initial secrets from a destination connection ID.
///
/// This is the RFC 9001 / RFC 9369 Initial-only path. It does not derive
/// Handshake, 0-RTT, 1-RTT, update, or TLS transcript secrets.
pub fn derive_quic_initial_secrets(
    version: u32,
    destination_connection_id: impl AsRef<[u8]>,
) -> Result<QuicInitialSecrets> {
    let initial_secret = hkdf_extract_sha256(
        quic_initial_salt(version)?,
        destination_connection_id.as_ref(),
    )?;
    let client_initial_secret = hkdf_expand_label_sha256_array(
        &initial_secret,
        "client in",
        QUIC_INITIAL_SECRET_LEN,
        "quic.crypto.initial.client_initial_secret",
    )?;
    let server_initial_secret = hkdf_expand_label_sha256_array(
        &initial_secret,
        "server in",
        QUIC_INITIAL_SECRET_LEN,
        "quic.crypto.initial.server_initial_secret",
    )?;
    Ok(QuicInitialSecrets {
        version,
        initial_secret,
        client_initial_secret,
        server_initial_secret,
    })
}

/// Protect one complete, explicitly constructed QUIC Initial packet.
///
/// The input packet's payload is treated as plaintext. The caller supplies the
/// full packet number used for the AEAD nonce and selects the truncated
/// packet-number width carried on the wire. This helper corrects the QUIC
/// Length field for the authentication tag, but otherwise preserves the
/// caller's header values and encoded varint widths. It does not add padding,
/// connection IDs, tokens, or endpoint policy.
pub fn quic_protect_complete_initial_packet(
    packet: &QuicLongHeaderPacket,
    full_packet_number: u64,
    keys: &QuicInitialPacketKeys,
    packet_number_len: usize,
) -> Result<QuicPacket> {
    if packet.packet_kind() != QuicLongPacketKind::Initial {
        return Err(CrafterError::invalid_field_value(
            "quic.crypto.initial.packet",
            "packet is not a QUIC Initial long-header packet",
        ));
    }
    quic_initial_salt(packet.version())?;
    let packet_number_bits = header_bits_for_len(packet_number_len)?;
    if full_packet_number >= (1u64 << 62) {
        return Err(CrafterError::invalid_field_value(
            "quic.crypto.initial.packet_number",
            "full QUIC packet number exceeds the 62-bit limit",
        ));
    }

    let packet_number_mask = (1u64 << (packet_number_len * 8)) - 1;
    let truncated_packet_number = full_packet_number & packet_number_mask;
    if packet.packet_number().value() != truncated_packet_number {
        return Err(CrafterError::invalid_field_value(
            "quic.crypto.initial.packet_number",
            "unprotected packet number does not match the supplied full packet number",
        ));
    }

    let protected_payload_len = packet
        .protected_payload()
        .len()
        .checked_add(QUIC_INITIAL_AEAD_TAG_LEN)
        .ok_or_else(initial_decode_length_overflow_error)?;
    let length_value = packet_number_len
        .checked_add(protected_payload_len)
        .ok_or_else(initial_decode_length_overflow_error)?;
    let length = QuicVarInt::new(
        u64::try_from(length_value).map_err(|_| initial_decode_length_overflow_error())?,
    )?;

    // Header protection changes only the low four bits of the long-header
    // first byte. Set the selected packet-number length before using the
    // serialized header as AEAD associated data.
    let first_byte = (packet.first_byte() & !0x03) | packet_number_bits;
    let unprotected = QuicLongHeaderPacket::initial_builder()
        .first_byte(first_byte)
        .version(packet.version())
        .destination_connection_id(packet.destination_connection_id().clone())
        .source_connection_id(packet.source_connection_id().clone())
        .token_length(
            packet
                .token_length()
                .expect("Initial packets carry token length"),
        )
        .token_length_encoded_len(
            packet
                .token_length_encoded_len()
                .expect("Initial packets carry token length width"),
        )
        .token(packet.token())
        .length(length)
        .length_encoded_len(packet.length_encoded_len())
        .packet_number(
            QuicPacketNumber::new(truncated_packet_number).with_encoded_len(packet_number_len),
        )
        .protected_payload(packet.protected_payload())
        .build()?;

    let header_len = unprotected
        .as_bytes()
        .len()
        .checked_sub(packet.protected_payload().len())
        .ok_or_else(initial_decode_length_overflow_error)?;
    let mut protected = unprotected.as_bytes()[..header_len].to_vec();
    let ciphertext =
        keys.protect_payload(full_packet_number, &protected, packet.protected_payload())?;
    protected.extend_from_slice(&ciphertext);

    let packet_number_offset = header_len
        .checked_sub(packet_number_len)
        .ok_or_else(initial_decode_length_overflow_error)?;
    let sample_start = packet_number_offset
        .checked_add(4)
        .ok_or_else(initial_decode_length_overflow_error)?;
    let sample_end = sample_start
        .checked_add(QUIC_HEADER_PROTECTION_SAMPLE_LEN)
        .ok_or_else(initial_decode_length_overflow_error)?;
    if protected.len() < sample_end {
        return Err(CrafterError::buffer_too_short(
            "quic.crypto.header_protection.sample",
            sample_end,
            protected.len(),
        ));
    }
    let mask = keys.header_protection_mask(&protected[sample_start..sample_end])?;
    protected[0] ^= mask[0] & 0x0f;
    for index in 0..packet_number_len {
        protected[packet_number_offset + index] ^= mask[index + 1];
    }

    Ok(QuicPacket::from_bytes(protected))
}

/// Explicitly remove Initial protection and decode the payload as frames.
///
/// `original_destination_connection_id` is the Destination Connection ID used
/// for Initial secret derivation. For server Initial packets this can differ
/// from the packet's current Destination Connection ID.
pub fn quic_decode_initial_protected_payload(
    version: u32,
    original_destination_connection_id: impl AsRef<[u8]>,
    direction: QuicInitialPacketDirection,
    packet: impl AsRef<[u8]>,
) -> Result<QuicInitialProtectedPayload> {
    let packet = packet.as_ref();
    let parts = parse_initial_protected_packet(packet)?;
    if parts.version != version {
        return Err(CrafterError::invalid_field_value(
            "quic.crypto.initial.version",
            "packet version does not match requested QUIC Initial version",
        ));
    }

    let secrets = derive_quic_initial_secrets(version, original_destination_connection_id)?;
    let keys = match direction {
        QuicInitialPacketDirection::Client => secrets.client_packet_keys()?,
        QuicInitialPacketDirection::Server => secrets.server_packet_keys()?,
    };
    let decoded = quic_decode_initial_protected_payload_with_keys(packet, &keys)?;
    Ok(decoded)
}

/// Explicitly remove Initial protection using caller-supplied keys and decode frames.
pub fn quic_decode_initial_protected_payload_with_keys(
    packet: impl AsRef<[u8]>,
    keys: &QuicInitialPacketKeys,
) -> Result<QuicInitialProtectedPayload> {
    let packet = packet.as_ref();
    let parts = parse_initial_protected_packet(packet)?;
    let sample = &packet[parts.header_protection_sample_start
        ..parts.header_protection_sample_start + QUIC_HEADER_PROTECTION_SAMPLE_LEN];
    let mask = keys.header_protection_mask(sample)?;
    let first_byte = packet[0] ^ (mask[0] & 0x0f);
    let packet_number_len = len_from_header_bits(first_byte);
    if parts.length_value < packet_number_len {
        return Err(CrafterError::invalid_field_value(
            "quic.long_header.length",
            "QUIC long-header length must cover the packet number",
        ));
    }

    let protected_payload_start = parts
        .packet_number_offset
        .checked_add(packet_number_len)
        .ok_or_else(initial_decode_length_overflow_error)?;
    if parts.packet_end < protected_payload_start {
        return Err(CrafterError::buffer_too_short(
            "quic.long_header.packet_number",
            protected_payload_start,
            parts.packet_end,
        ));
    }

    let mut unprotected_header = packet[..protected_payload_start].to_vec();
    unprotected_header[0] = first_byte;
    for i in 0..packet_number_len {
        unprotected_header[parts.packet_number_offset + i] ^= mask[1 + i];
    }

    let (packet_number, consumed) = QuicPacketNumber::decode(
        &unprotected_header[parts.packet_number_offset..protected_payload_start],
        packet_number_len,
    )?;
    debug_assert_eq!(consumed, packet_number_len);

    let protected_payload = packet[protected_payload_start..parts.packet_end].to_vec();
    let decrypted_payload = keys.unprotect_payload(
        packet_number.value(),
        &unprotected_header,
        &protected_payload,
    )?;
    let frames = QuicFrame::decode_sequence(&decrypted_payload)?;

    Ok(QuicInitialProtectedPayload {
        version: parts.version,
        packet_number,
        packet_number_offset: parts.packet_number_offset,
        packet_number_len,
        unprotected_header,
        protected_payload,
        decrypted_payload,
        frames,
    })
}

/// Build the RFC 9001 Retry pseudo-packet bytes.
pub fn quic_retry_pseudo_packet(
    original_destination_connection_id: impl AsRef<[u8]>,
    retry_without_integrity_tag: impl AsRef<[u8]>,
) -> Result<Vec<u8>> {
    let original_destination_connection_id = original_destination_connection_id.as_ref();
    if original_destination_connection_id.len() > QUIC_CONNECTION_ID_MAX_LEN {
        return Err(CrafterError::invalid_field_value(
            "quic.retry.original_destination_connection_id",
            "QUIC Retry original destination connection ID exceeds 20 bytes",
        ));
    }

    let retry_without_integrity_tag = retry_without_integrity_tag.as_ref();
    let mut pseudo = Vec::with_capacity(
        1 + original_destination_connection_id.len() + retry_without_integrity_tag.len(),
    );
    pseudo.push(original_destination_connection_id.len() as u8);
    pseudo.extend_from_slice(original_destination_connection_id);
    pseudo.extend_from_slice(retry_without_integrity_tag);
    Ok(pseudo)
}

/// Compute a Retry Integrity Tag for a Retry packet without its tag bytes.
pub fn quic_retry_integrity_tag(
    version: u32,
    original_destination_connection_id: impl AsRef<[u8]>,
    retry_without_integrity_tag: impl AsRef<[u8]>,
) -> Result<[u8; QUIC_RETRY_INTEGRITY_TAG_LEN]> {
    let (key, nonce) = retry_integrity_key_nonce(version).ok_or_else(|| {
        CrafterError::invalid_field_value(
            "quic.retry.version",
            "unsupported QUIC Retry integrity version",
        )
    })?;
    let pseudo = quic_retry_pseudo_packet(
        original_destination_connection_id,
        retry_without_integrity_tag,
    )?;
    retry_integrity_tag_with_key(key, nonce, &pseudo)
}

/// Verify a decoded Retry packet's Retry Integrity Tag.
pub fn quic_verify_retry_integrity_tag(
    original_destination_connection_id: impl AsRef<[u8]>,
    retry: &QuicRetryPacket,
) -> Result<QuicRetryIntegrityStatus> {
    let Some((key, nonce)) = retry_integrity_key_nonce(retry.version()) else {
        return Ok(QuicRetryIntegrityStatus::UnsupportedVersion);
    };
    let retry_without_tag = &retry.as_bytes()[..retry.len() - QUIC_RETRY_INTEGRITY_TAG_LEN];
    let pseudo = quic_retry_pseudo_packet(original_destination_connection_id, retry_without_tag)?;
    let expected = retry_integrity_tag_with_key(key, nonce, &pseudo)?;
    if expected.ct_eq(retry.integrity_tag()).into() {
        Ok(QuicRetryIntegrityStatus::Valid)
    } else {
        Ok(QuicRetryIntegrityStatus::Invalid)
    }
}

/// Build the AEAD nonce for an Initial packet number.
///
/// QUIC left-pads the packet number to the IV length and XORs it with the IV.
pub fn quic_initial_payload_nonce(
    iv: &[u8; QUIC_INITIAL_IV_LEN],
    packet_number: u64,
) -> [u8; QUIC_INITIAL_IV_LEN] {
    let mut packet_number_bytes = [0u8; QUIC_INITIAL_IV_LEN];
    packet_number_bytes[QUIC_INITIAL_IV_LEN - 8..].copy_from_slice(&packet_number.to_be_bytes());

    let mut nonce = [0u8; QUIC_INITIAL_IV_LEN];
    for (out, (iv_byte, pn_byte)) in nonce
        .iter_mut()
        .zip(iv.iter().zip(packet_number_bytes.iter()))
    {
        *out = *iv_byte ^ *pn_byte;
    }
    nonce
}

/// Encrypt a QUIC Initial packet payload with AES-128-GCM.
///
/// The returned bytes are `ciphertext || tag`. The caller supplies the
/// unprotected packet header, including packet-number bytes, as associated data.
pub fn quic_initial_aes128gcm_protect_payload(
    keys: &QuicInitialPacketKeys,
    packet_number: u64,
    associated_data: impl AsRef<[u8]>,
    plaintext: impl AsRef<[u8]>,
) -> Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(keys.key()).map_err(|_| {
        CrafterError::invalid_field_value(
            "quic.crypto.initial.key",
            "invalid AES-128-GCM Initial key length",
        )
    })?;
    let nonce = AesGcmNonce12::from(quic_initial_payload_nonce(keys.iv(), packet_number));
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_ref(),
                aad: associated_data.as_ref(),
            },
        )
        .map_err(|_| {
            CrafterError::invalid_field_value(
                "quic.crypto.initial.payload",
                "AES-128-GCM Initial encryption failed",
            )
        })
}

/// Decrypt a QUIC Initial packet payload with AES-128-GCM.
///
/// The input bytes are `ciphertext || tag`. The caller supplies the
/// unprotected packet header, including packet-number bytes, as associated data.
pub fn quic_initial_aes128gcm_unprotect_payload(
    keys: &QuicInitialPacketKeys,
    packet_number: u64,
    associated_data: impl AsRef<[u8]>,
    ciphertext_and_tag: impl AsRef<[u8]>,
) -> Result<Vec<u8>> {
    let ciphertext_and_tag = ciphertext_and_tag.as_ref();
    if ciphertext_and_tag.len() < QUIC_INITIAL_AEAD_TAG_LEN {
        return Err(CrafterError::buffer_too_short(
            "quic.crypto.initial.ciphertext_tag",
            QUIC_INITIAL_AEAD_TAG_LEN,
            ciphertext_and_tag.len(),
        ));
    }

    let cipher = Aes128Gcm::new_from_slice(keys.key()).map_err(|_| {
        CrafterError::invalid_field_value(
            "quic.crypto.initial.key",
            "invalid AES-128-GCM Initial key length",
        )
    })?;
    let nonce = AesGcmNonce12::from(quic_initial_payload_nonce(keys.iv(), packet_number));
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext_and_tag,
                aad: associated_data.as_ref(),
            },
        )
        .map_err(|_| {
            CrafterError::invalid_field_value(
                "quic.crypto.initial.ciphertext_tag",
                "AES-128-GCM Initial authentication failed",
            )
        })
}

/// Generate a QUIC header-protection mask with an explicit algorithm.
pub fn quic_header_protection_mask(
    algorithm: QuicHeaderProtectionAlgorithm,
    key: impl AsRef<[u8]>,
    sample: impl AsRef<[u8]>,
) -> Result<[u8; QUIC_HEADER_PROTECTION_MASK_LEN]> {
    match algorithm {
        QuicHeaderProtectionAlgorithm::Aes128 => quic_aes128_header_protection_mask(key, sample),
        QuicHeaderProtectionAlgorithm::ChaCha20 => {
            quic_chacha20_header_protection_mask(key, sample)
        }
    }
}

/// Generate the RFC 9001 AES-128 header-protection mask.
pub fn quic_aes128_header_protection_mask(
    key: impl AsRef<[u8]>,
    sample: impl AsRef<[u8]>,
) -> Result<[u8; QUIC_HEADER_PROTECTION_MASK_LEN]> {
    let key = fixed_bytes::<QUIC_AES128_HEADER_PROTECTION_KEY_LEN>(
        key.as_ref(),
        "quic.crypto.header_protection.aes128.key",
    )?;
    let sample = fixed_bytes::<QUIC_HEADER_PROTECTION_SAMPLE_LEN>(
        sample.as_ref(),
        "quic.crypto.header_protection.sample",
    )?;
    let cipher = Aes128::new(GenericArray::from_slice(&key));
    let mut block = GenericArray::clone_from_slice(&sample);
    cipher.encrypt_block(&mut block);
    let mut mask = [0u8; QUIC_HEADER_PROTECTION_MASK_LEN];
    mask.copy_from_slice(&block[..QUIC_HEADER_PROTECTION_MASK_LEN]);
    Ok(mask)
}

/// Generate the RFC 9001 ChaCha20 header-protection mask.
pub fn quic_chacha20_header_protection_mask(
    key: impl AsRef<[u8]>,
    sample: impl AsRef<[u8]>,
) -> Result<[u8; QUIC_HEADER_PROTECTION_MASK_LEN]> {
    let key = fixed_bytes::<QUIC_CHACHA20_HEADER_PROTECTION_KEY_LEN>(
        key.as_ref(),
        "quic.crypto.header_protection.chacha20.key",
    )?;
    let sample = fixed_bytes::<QUIC_HEADER_PROTECTION_SAMPLE_LEN>(
        sample.as_ref(),
        "quic.crypto.header_protection.sample",
    )?;
    let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sample[4..]);

    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    cipher.try_seek(u64::from(counter) * 64).map_err(|_| {
        CrafterError::invalid_field_value(
            "quic.crypto.header_protection.chacha20.counter",
            "invalid ChaCha20 header-protection counter",
        )
    })?;
    let mut mask = [0u8; QUIC_HEADER_PROTECTION_MASK_LEN];
    cipher.try_apply_keystream(&mut mask).map_err(|_| {
        CrafterError::invalid_field_value(
            "quic.crypto.header_protection.chacha20.mask",
            "failed to generate ChaCha20 header-protection mask",
        )
    })?;
    Ok(mask)
}

fn derive_initial_packet_keys(version: u32, secret: &[u8]) -> Result<QuicInitialPacketKeys> {
    Ok(QuicInitialPacketKeys {
        key: hkdf_expand_label_sha256_array(
            secret,
            packet_key_label(version)?,
            QUIC_INITIAL_AES_128_KEY_LEN,
            "quic.crypto.initial.key",
        )?,
        iv: hkdf_expand_label_sha256_array(
            secret,
            packet_iv_label(version)?,
            QUIC_INITIAL_IV_LEN,
            "quic.crypto.initial.iv",
        )?,
        header_protection_key: hkdf_expand_label_sha256_array(
            secret,
            packet_hp_label(version)?,
            QUIC_INITIAL_HP_KEY_LEN,
            "quic.crypto.initial.hp",
        )?,
    })
}

fn retry_integrity_key_nonce(
    version: u32,
) -> Option<(
    &'static [u8; QUIC_RETRY_INTEGRITY_KEY_LEN],
    &'static [u8; QUIC_RETRY_INTEGRITY_NONCE_LEN],
)> {
    match version {
        QUIC_VERSION_1 => Some((&QUIC_V1_RETRY_INTEGRITY_KEY, &QUIC_V1_RETRY_INTEGRITY_NONCE)),
        QUIC_VERSION_2 => Some((&QUIC_V2_RETRY_INTEGRITY_KEY, &QUIC_V2_RETRY_INTEGRITY_NONCE)),
        _ => None,
    }
}

fn retry_integrity_tag_with_key(
    key: &[u8; QUIC_RETRY_INTEGRITY_KEY_LEN],
    nonce: &[u8; QUIC_RETRY_INTEGRITY_NONCE_LEN],
    pseudo_packet: &[u8],
) -> Result<[u8; QUIC_RETRY_INTEGRITY_TAG_LEN]> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| {
        CrafterError::invalid_field_value(
            "quic.retry.integrity_key",
            "invalid AES-128-GCM Retry integrity key length",
        )
    })?;
    let nonce = AesGcmNonce12::from(*nonce);
    let tag = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &[],
                aad: pseudo_packet,
            },
        )
        .map_err(|_| {
            CrafterError::invalid_field_value(
                "quic.retry.integrity_tag",
                "AES-128-GCM Retry integrity tag computation failed",
            )
        })?;
    fixed_bytes::<QUIC_RETRY_INTEGRITY_TAG_LEN>(&tag, "quic.retry.integrity_tag")
}

#[derive(Debug, Clone, Copy)]
struct InitialProtectedPacketParts {
    version: u32,
    length_value: usize,
    packet_number_offset: usize,
    packet_end: usize,
    header_protection_sample_start: usize,
}

fn parse_initial_protected_packet(packet: &[u8]) -> Result<InitialProtectedPacketParts> {
    let classification = classify_quic_header(packet)?;
    let QuicHeaderClassification::LongHeader {
        version,
        invariant_len,
        packet_kind: QuicLongPacketKind::Initial,
        ..
    } = classification
    else {
        return Err(CrafterError::invalid_field_value(
            "quic.crypto.initial.packet",
            "packet is not a QUIC Initial long-header packet",
        ));
    };

    let token_length_start = invariant_len;
    let first_token_length_byte = packet.get(token_length_start).copied().ok_or_else(|| {
        CrafterError::buffer_too_short(
            "quic.initial.token_length",
            token_length_start + 1,
            packet.len(),
        )
    })?;
    let token_length_encoded_len = encoded_len_from_prefix(first_token_length_byte);
    let token_length_end = token_length_start
        .checked_add(token_length_encoded_len)
        .ok_or_else(initial_decode_length_overflow_error)?;
    if packet.len() < token_length_end {
        return Err(CrafterError::buffer_too_short(
            "quic.initial.token_length",
            token_length_end,
            packet.len(),
        ));
    }
    let (token_length, consumed) = QuicVarInt::decode(&packet[token_length_start..])?;
    debug_assert_eq!(consumed, token_length_encoded_len);
    let token_len = usize::try_from(token_length.value())
        .map_err(|_| initial_decode_length_overflow_error())?;
    let token_end = token_length_end
        .checked_add(token_len)
        .ok_or_else(initial_decode_length_overflow_error)?;
    if packet.len() < token_end {
        return Err(CrafterError::buffer_too_short(
            "quic.initial.token",
            token_end,
            packet.len(),
        ));
    }

    let first_length_byte = packet.get(token_end).copied().ok_or_else(|| {
        CrafterError::buffer_too_short("quic.long_header.length", token_end + 1, packet.len())
    })?;
    let length_encoded_len = encoded_len_from_prefix(first_length_byte);
    let length_end = token_end
        .checked_add(length_encoded_len)
        .ok_or_else(initial_decode_length_overflow_error)?;
    if packet.len() < length_end {
        return Err(CrafterError::buffer_too_short(
            "quic.long_header.length",
            length_end,
            packet.len(),
        ));
    }
    let (length, consumed) = QuicVarInt::decode(&packet[token_end..])?;
    debug_assert_eq!(consumed, length_encoded_len);
    let length_value =
        usize::try_from(length.value()).map_err(|_| initial_decode_length_overflow_error())?;

    let packet_number_offset = length_end;
    let packet_end = length_end
        .checked_add(length_value)
        .ok_or_else(initial_decode_length_overflow_error)?;
    if packet.len() < packet_end {
        return Err(CrafterError::buffer_too_short(
            "quic.long_header.protected_payload",
            packet_end,
            packet.len(),
        ));
    }

    let header_protection_sample_start = packet_number_offset
        .checked_add(4)
        .ok_or_else(initial_decode_length_overflow_error)?;
    let header_protection_sample_end = header_protection_sample_start
        .checked_add(QUIC_HEADER_PROTECTION_SAMPLE_LEN)
        .ok_or_else(initial_decode_length_overflow_error)?;
    if packet_end < header_protection_sample_end {
        return Err(CrafterError::buffer_too_short(
            "quic.crypto.header_protection.sample",
            header_protection_sample_end,
            packet_end,
        ));
    }

    Ok(InitialProtectedPacketParts {
        version,
        length_value,
        packet_number_offset,
        packet_end,
        header_protection_sample_start,
    })
}

fn initial_decode_length_overflow_error() -> CrafterError {
    CrafterError::invalid_field_value(
        "quic.crypto.initial.length",
        "QUIC Initial protected packet length overflow",
    )
}

fn fixed_bytes<const N: usize>(bytes: &[u8], field: &'static str) -> Result<[u8; N]> {
    if bytes.len() != N {
        return Err(CrafterError::invalid_field_value(
            field,
            "unexpected QUIC crypto input length",
        ));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn packet_key_label(version: u32) -> Result<&'static str> {
    match version {
        QUIC_VERSION_1 => Ok("quic key"),
        QUIC_VERSION_2 => Ok("quicv2 key"),
        _ => Err(CrafterError::invalid_field_value(
            "quic.crypto.initial.version",
            "unsupported QUIC packet-protection key label version",
        )),
    }
}

fn packet_iv_label(version: u32) -> Result<&'static str> {
    match version {
        QUIC_VERSION_1 => Ok("quic iv"),
        QUIC_VERSION_2 => Ok("quicv2 iv"),
        _ => Err(CrafterError::invalid_field_value(
            "quic.crypto.initial.version",
            "unsupported QUIC packet-protection IV label version",
        )),
    }
}

fn packet_hp_label(version: u32) -> Result<&'static str> {
    match version {
        QUIC_VERSION_1 => Ok("quic hp"),
        QUIC_VERSION_2 => Ok("quicv2 hp"),
        _ => Err(CrafterError::invalid_field_value(
            "quic.crypto.initial.version",
            "unsupported QUIC header-protection label version",
        )),
    }
}

fn hkdf_extract_sha256(salt: &[u8], input_keying_material: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).map_err(|_| {
        CrafterError::invalid_field_value("quic.crypto.hkdf.salt", "invalid HKDF salt length")
    })?;
    mac.update(input_keying_material);
    let output = mac.finalize().into_bytes();
    let mut extracted = [0u8; 32];
    extracted.copy_from_slice(&output);
    Ok(extracted)
}

fn hkdf_expand_label_sha256_array<const N: usize>(
    secret: &[u8],
    label: &str,
    len: usize,
    field: &'static str,
) -> Result<[u8; N]> {
    if len != N {
        return Err(CrafterError::invalid_field_value(
            field,
            "requested HKDF output length does not match fixed output",
        ));
    }
    let expanded = hkdf_expand_label_sha256(secret, label.as_bytes(), &[], len, field)?;
    let mut output = [0u8; N];
    output.copy_from_slice(&expanded);
    Ok(output)
}

fn hkdf_expand_label_sha256(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
    field: &'static str,
) -> Result<Vec<u8>> {
    let info = tls13_hkdf_label(label, context, len, field)?;
    hkdf_expand_sha256(secret, &info, len, field)
}

fn tls13_hkdf_label(
    label: &[u8],
    context: &[u8],
    len: usize,
    field: &'static str,
) -> Result<Vec<u8>> {
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "HKDF output length exceeds TLS 1.3 label limit",
        ));
    }
    let label_len = 6usize
        .checked_add(label.len())
        .ok_or_else(|| CrafterError::invalid_field_value(field, "HKDF label length overflow"))?;
    if label_len > u8::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "HKDF label exceeds TLS 1.3 label length limit",
        ));
    }
    if context.len() > u8::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "HKDF context exceeds TLS 1.3 context length limit",
        ));
    }

    let mut encoded = Vec::with_capacity(2 + 1 + label_len + 1 + context.len());
    encoded.extend_from_slice(&(len as u16).to_be_bytes());
    encoded.push(label_len as u8);
    encoded.extend_from_slice(b"tls13 ");
    encoded.extend_from_slice(label);
    encoded.push(context.len() as u8);
    encoded.extend_from_slice(context);
    Ok(encoded)
}

fn hkdf_expand_sha256(
    pseudo_random_key: &[u8],
    info: &[u8],
    len: usize,
    field: &'static str,
) -> Result<Vec<u8>> {
    if len > 255 * 32 {
        return Err(CrafterError::invalid_field_value(
            field,
            "HKDF output length exceeds RFC 5869 limit",
        ));
    }

    let mut output = Vec::with_capacity(len);
    let mut previous = Vec::new();
    let mut counter = 1u8;
    while output.len() < len {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(pseudo_random_key).map_err(|_| {
            CrafterError::invalid_field_value("quic.crypto.hkdf.prk", "invalid HKDF PRK length")
        })?;
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter]);
        previous = mac.finalize().into_bytes().to_vec();

        let remaining = len - output.len();
        output.extend_from_slice(&previous[..remaining.min(previous.len())]);
        if output.len() < len {
            counter = counter.checked_add(1).ok_or_else(|| {
                CrafterError::invalid_field_value(field, "HKDF block counter overflow")
            })?;
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    #[test]
    fn quic_initial_secret_derivation_matches_rfc9001_v1_vectors() -> Result<()> {
        let secrets = derive_quic_initial_secrets(QUIC_VERSION_1, TEST_DCID)?;
        assert_eq!(secrets.version(), QUIC_VERSION_1);
        assert_eq!(quic_initial_salt(QUIC_VERSION_1)?, &QUIC_V1_INITIAL_SALT);
        assert_eq!(
            secrets.initial_secret(),
            &hex_array::<32>("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
        );
        assert_eq!(
            secrets.client_initial_secret(),
            &hex_array::<32>("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
        assert_eq!(
            secrets.server_initial_secret(),
            &hex_array::<32>("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        );

        let client_keys = secrets.client_packet_keys()?;
        assert_eq!(
            client_keys.key(),
            &hex_array::<16>("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(
            client_keys.iv(),
            &hex_array::<12>("fa044b2f42a3fd3b46fb255c")
        );
        assert_eq!(
            client_keys.header_protection_key(),
            &hex_array::<16>("9f50449e04a0e810283a1e9933adedd2")
        );

        let server_keys = secrets.server_packet_keys()?;
        assert_eq!(
            server_keys.key(),
            &hex_array::<16>("cf3a5331653c364c88f0f379b6067e37")
        );
        assert_eq!(
            server_keys.iv(),
            &hex_array::<12>("0ac1493ca1905853b0bba03e")
        );
        assert_eq!(
            server_keys.header_protection_key(),
            &hex_array::<16>("c206b8d9b9f0f37644430b490eeaa314")
        );

        Ok(())
    }

    #[test]
    fn quic_initial_secret_derivation_matches_rfc9369_v2_vectors() -> Result<()> {
        let secrets = derive_quic_initial_secrets(QUIC_VERSION_2, TEST_DCID)?;
        assert_eq!(secrets.version(), QUIC_VERSION_2);
        assert_eq!(quic_initial_salt(QUIC_VERSION_2)?, &QUIC_V2_INITIAL_SALT);
        assert_eq!(
            secrets.initial_secret(),
            &hex_array::<32>("2062e8b3cd8d52092614b8071d0aa1fb7c2e3ac193f78b280e72d8f5751f6aba")
        );
        assert_eq!(
            secrets.client_initial_secret(),
            &hex_array::<32>("14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b")
        );
        assert_eq!(
            secrets.server_initial_secret(),
            &hex_array::<32>("0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1")
        );

        let client_keys = secrets.client_packet_keys()?;
        assert_eq!(
            client_keys.key(),
            &hex_array::<16>("8b1a0bc121284290a29e0971b5cd045d")
        );
        assert_eq!(
            client_keys.iv(),
            &hex_array::<12>("91f73e2351d8fa91660e909f")
        );
        assert_eq!(
            client_keys.header_protection_key(),
            &hex_array::<16>("45b95e15235d6f45a6b19cbcb0294ba9")
        );

        let server_keys = secrets.server_packet_keys()?;
        assert_eq!(
            server_keys.key(),
            &hex_array::<16>("82db637861d55e1d011f19ea71d5d2a7")
        );
        assert_eq!(
            server_keys.iv(),
            &hex_array::<12>("dd13c276499c0249d3310652")
        );
        assert_eq!(
            server_keys.header_protection_key(),
            &hex_array::<16>("edf6d05c83121201b436e16877593c3a")
        );

        Ok(())
    }

    #[test]
    fn quic_initial_secret_derivation_rejects_unsupported_versions() {
        assert_eq!(
            derive_quic_initial_secrets(0xface_feed, TEST_DCID).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.crypto.initial.version",
                "unsupported QUIC Initial salt version"
            )
        );
    }

    #[test]
    fn quic_initial_secret_derivation_encodes_tls13_labels() -> Result<()> {
        assert_eq!(
            tls13_hkdf_label(b"client in", &[], 32, "test")?,
            hex_vec("00200f746c73313320636c69656e7420696e00")
        );
        assert_eq!(
            tls13_hkdf_label(b"server in", &[], 32, "test")?,
            hex_vec("00200f746c7331332073657276657220696e00")
        );
        assert_eq!(
            tls13_hkdf_label(b"quic key", &[], 16, "test")?,
            hex_vec("00100e746c7331332071756963206b657900")
        );
        assert_eq!(
            tls13_hkdf_label(b"quicv2 hp", &[], 16, "test")?,
            hex_vec("00100f746c7331332071756963763220687000")
        );
        Ok(())
    }

    #[test]
    fn quic_header_protection_utilities_aes128_match_rfc9001_vectors() -> Result<()> {
        let secrets = derive_quic_initial_secrets(QUIC_VERSION_1, TEST_DCID)?;
        let client_keys = secrets.client_packet_keys()?;
        let server_keys = secrets.server_packet_keys()?;

        assert_eq!(QuicHeaderProtectionAlgorithm::Aes128.key_len(), 16);
        assert_eq!(QuicHeaderProtectionAlgorithm::Aes128.label(), "aes128");
        assert_eq!(
            client_keys.header_protection_mask(hex_vec("d1b1c98dd7689fb8ec11d242b123dc9b"))?,
            hex_array::<5>("437b9aec36")
        );
        assert_eq!(
            quic_header_protection_mask(
                QuicHeaderProtectionAlgorithm::Aes128,
                client_keys.header_protection_key(),
                hex_vec("d1b1c98dd7689fb8ec11d242b123dc9b")
            )?,
            hex_array::<5>("437b9aec36")
        );
        assert_eq!(
            quic_aes128_header_protection_mask(
                server_keys.header_protection_key(),
                hex_vec("2cd0991cd25b0aac406a5816b6394100")
            )?,
            hex_array::<5>("2ec0d8356a")
        );

        Ok(())
    }

    #[test]
    fn quic_header_protection_utilities_aes128_match_rfc9369_vectors() -> Result<()> {
        let secrets = derive_quic_initial_secrets(QUIC_VERSION_2, TEST_DCID)?;
        let client_keys = secrets.client_packet_keys()?;
        let server_keys = secrets.server_packet_keys()?;

        assert_eq!(
            client_keys.header_protection_mask(hex_vec("ffe67b6abcdb4298b485dd04de806071"))?,
            hex_array::<5>("94a0c95e80")
        );
        assert_eq!(
            server_keys.header_protection_mask(hex_vec("6f05d8a4398c47089698baeea26b91eb"))?,
            hex_array::<5>("4dd92e91ea")
        );

        Ok(())
    }

    #[test]
    fn quic_header_protection_utilities_chacha20_match_rfc9001_and_rfc9369_vectors() -> Result<()> {
        assert_eq!(QuicHeaderProtectionAlgorithm::ChaCha20.key_len(), 32);
        assert_eq!(QuicHeaderProtectionAlgorithm::ChaCha20.label(), "chacha20");
        assert_eq!(
            quic_chacha20_header_protection_mask(
                hex_vec("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
                hex_vec("5e5cd55c41f69080575d7999c25a5bfb")
            )?,
            hex_array::<5>("aefefe7d03")
        );
        assert_eq!(
            quic_header_protection_mask(
                QuicHeaderProtectionAlgorithm::ChaCha20,
                hex_vec("d659760d2ba434a226fd37b35c69e2da8211d10c4f12538787d65645d5d1b8e2"),
                hex_vec("e7b6b932bc27d786f4bc2bb20f2162ba")
            )?,
            hex_array::<5>("97580e32bf")
        );
        Ok(())
    }

    #[test]
    fn quic_header_protection_utilities_report_bad_lengths() {
        assert_eq!(
            quic_aes128_header_protection_mask([0u8; 15], [0u8; 16]).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.crypto.header_protection.aes128.key",
                "unexpected QUIC crypto input length"
            )
        );
        assert_eq!(
            quic_chacha20_header_protection_mask([0u8; 32], [0u8; 15]).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.crypto.header_protection.sample",
                "unexpected QUIC crypto input length"
            )
        );
    }

    #[test]
    fn quic_protected_payload_decode_mode_decrypts_initial_into_frames() -> Result<()> {
        let clear_payload = [0x01, 0x06, 0x00, 0x01, 0xaa];
        let protected_packet = protected_initial_packet(
            QUIC_VERSION_1,
            QuicInitialPacketDirection::Client,
            0x1234,
            2,
            &clear_payload,
        )?;

        let decoded = quic_decode_initial_protected_payload(
            QUIC_VERSION_1,
            TEST_DCID,
            QuicInitialPacketDirection::Client,
            &protected_packet,
        )?;

        assert_eq!(decoded.version(), QUIC_VERSION_1);
        assert_eq!(decoded.packet_number().value(), 0x1234);
        assert_eq!(decoded.packet_number_len(), 2);
        assert_eq!(decoded.decrypted_payload(), clear_payload);
        assert_eq!(decoded.frame_count(), 2);
        assert!(decoded.frames()[0].is_ping());
        assert_eq!(decoded.frames()[1].crypto_frame()?.unwrap().data(), &[0xaa]);
        assert_eq!(
            QuicFrame::encode_sequence(decoded.frames().iter().cloned()),
            clear_payload
        );

        let default_packet = crate::protocols::quic::QuicPacket::decode(&protected_packet)?;
        assert_eq!(default_packet.as_bytes(), protected_packet.as_slice());
        assert!(default_packet.is_long_header());
        assert_ne!(
            default_packet.long_header().unwrap().protected_payload(),
            clear_payload
        );

        let keys = derive_quic_initial_secrets(QUIC_VERSION_1, TEST_DCID)?.client_packet_keys()?;
        let decoded_with_keys = keys.decode_protected_initial_payload(&protected_packet)?;
        assert_eq!(decoded_with_keys.decrypted_payload(), clear_payload);
        assert_eq!(
            quic_decode_initial_protected_payload_with_keys(&protected_packet, &keys)?
                .frame_count(),
            2
        );

        Ok(())
    }

    #[test]
    fn quic_protected_payload_decode_mode_reports_authentication_failure() -> Result<()> {
        let mut protected_packet = protected_initial_packet(
            QUIC_VERSION_1,
            QuicInitialPacketDirection::Client,
            0x1234,
            2,
            [0x01, 0x06, 0x00, 0x01, 0xaa],
        )?;
        let last = protected_packet
            .last_mut()
            .expect("protected packet has ciphertext");
        *last ^= 0x01;

        assert_eq!(
            quic_decode_initial_protected_payload(
                QUIC_VERSION_1,
                TEST_DCID,
                QuicInitialPacketDirection::Client,
                &protected_packet,
            )
            .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.crypto.initial.ciphertext_tag",
                "AES-128-GCM Initial authentication failed"
            )
        );

        Ok(())
    }

    #[test]
    fn quic_protected_payload_decode_mode_rejects_version_mismatch() -> Result<()> {
        let protected_packet = protected_initial_packet(
            QUIC_VERSION_1,
            QuicInitialPacketDirection::Client,
            0x1234,
            2,
            [0x01, 0x06, 0x00, 0x01, 0xaa],
        )?;

        assert_eq!(
            quic_decode_initial_protected_payload(
                QUIC_VERSION_2,
                TEST_DCID,
                QuicInitialPacketDirection::Client,
                &protected_packet,
            )
            .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.crypto.initial.version",
                "packet version does not match requested QUIC Initial version"
            )
        );

        Ok(())
    }

    fn protected_initial_packet(
        version: u32,
        direction: QuicInitialPacketDirection,
        packet_number: u64,
        packet_number_len: usize,
        clear_payload: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>> {
        let secrets = derive_quic_initial_secrets(version, TEST_DCID)?;
        let keys = match direction {
            QuicInitialPacketDirection::Client => secrets.client_packet_keys()?,
            QuicInitialPacketDirection::Server => secrets.server_packet_keys()?,
        };
        let packet_number_len_bits =
            super::super::packet_number::header_bits_for_len(packet_number_len)?;
        let first_byte = match version {
            QUIC_VERSION_1 => 0xc0 | packet_number_len_bits,
            QUIC_VERSION_2 => 0xd0 | packet_number_len_bits,
            _ => {
                return Err(CrafterError::invalid_field_value(
                    "test.version",
                    "unsupported test QUIC version",
                ))
            }
        };

        let mut header = Vec::new();
        header.push(first_byte);
        header.extend_from_slice(&version.to_be_bytes());
        header.push(TEST_DCID.len() as u8);
        header.extend_from_slice(&TEST_DCID);
        header.push(0);
        header.push(0);
        let length = packet_number_len
            .checked_add(clear_payload.as_ref().len())
            .and_then(|len| len.checked_add(QUIC_INITIAL_AEAD_TAG_LEN))
            .ok_or_else(initial_decode_length_overflow_error)?;
        QuicVarInt::new(length as u64)?.encode(&mut header)?;
        let packet_number_offset = header.len();
        QuicPacketNumber::new(packet_number)
            .with_encoded_len(packet_number_len)
            .encode(&mut header)?;

        let ciphertext = keys.protect_payload(packet_number, &header, clear_payload)?;
        let sample_offset = 4usize
            .checked_sub(packet_number_len)
            .ok_or_else(initial_decode_length_overflow_error)?;
        let mask = keys.header_protection_mask(
            &ciphertext[sample_offset..sample_offset + QUIC_HEADER_PROTECTION_SAMPLE_LEN],
        )?;
        header[0] ^= mask[0] & 0x0f;
        for i in 0..packet_number_len {
            header[packet_number_offset + i] ^= mask[1 + i];
        }

        header.extend_from_slice(&ciphertext);
        Ok(header)
    }

    fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = hex_vec(hex);
        assert_eq!(bytes.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    fn hex_vec(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        hex.as_bytes()
            .chunks_exact(2)
            .map(|byte| {
                let byte = std::str::from_utf8(byte).expect("hex is UTF-8");
                u8::from_str_radix(byte, 16).expect("valid hex")
            })
            .collect()
    }
}
