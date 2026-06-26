//! QUIC packet-layer skeleton.
//!
//! This module is intentionally conservative: it creates the QUIC module
//! boundary and raw-preserving placeholder types, but it does not register any
//! UDP application dispatch or claim version-specific QUIC parsing support.
//! Later implementation steps must take wire facts from
//! `.agents/docs/quic-manifest.md`, `.agents/docs/quic-codepoints.md`, or the
//! narrower source-backed QUIC notes produced from those files.
//!
//! The only layer behavior provided here is explicit raw payload preservation
//! through [`Quic`]. Parsing helpers return structured [`crate::CrafterError`]
//! values instead of panicking while the real packet grammar is still deferred.

pub mod connection_id;
pub mod constants;
pub mod crypto;
#[allow(dead_code)]
pub(crate) mod decode;
pub mod frame;
pub mod header;
pub mod packet;
pub mod packet_number;
pub mod transport_parameter;
pub mod varint;

pub use connection_id::QuicConnectionId;
pub use crypto::{
    derive_quic_initial_secrets, quic_aes128_header_protection_mask,
    quic_chacha20_header_protection_mask, quic_decode_initial_protected_payload,
    quic_decode_initial_protected_payload_with_keys, quic_header_protection_mask,
    quic_initial_aes128gcm_protect_payload, quic_initial_aes128gcm_unprotect_payload,
    quic_initial_payload_nonce, quic_initial_salt, quic_retry_integrity_tag,
    quic_retry_pseudo_packet, quic_verify_retry_integrity_tag, QuicCryptoContext,
    QuicHeaderProtectionAlgorithm, QuicInitialPacketDirection, QuicInitialPacketKeys,
    QuicInitialProtectedPayload, QuicInitialSecrets, QuicRetryIntegrityStatus,
    QUIC_AES128_HEADER_PROTECTION_KEY_LEN, QUIC_CHACHA20_HEADER_PROTECTION_KEY_LEN,
    QUIC_HEADER_PROTECTION_MASK_LEN, QUIC_HEADER_PROTECTION_SAMPLE_LEN, QUIC_INITIAL_AEAD_TAG_LEN,
    QUIC_INITIAL_AES_128_KEY_LEN, QUIC_INITIAL_HP_KEY_LEN, QUIC_INITIAL_IV_LEN,
    QUIC_INITIAL_SECRET_LEN, QUIC_V1_INITIAL_SALT, QUIC_V2_INITIAL_SALT,
};
pub use frame::{
    QuicAckEcnCounts, QuicAckFrame, QuicAckRange, QuicConnectionCloseFrame,
    QuicConnectionCloseKind, QuicCryptoFrame, QuicDataBlockedFrame, QuicFrame, QuicFrameKind,
    QuicHandshakeDoneFrame, QuicKnownFrameType, QuicMaxDataFrame, QuicMaxStreamDataFrame,
    QuicMaxStreamsFrame, QuicNewConnectionIdFrame, QuicNewTokenFrame, QuicPathChallengeFrame,
    QuicPathResponseFrame, QuicResetStreamFrame, QuicRetireConnectionIdFrame, QuicStopSendingFrame,
    QuicStreamDataBlockedFrame, QuicStreamDirection, QuicStreamFrame, QuicStreamsBlockedFrame,
    QuicUnknownFrame, QUIC_STATELESS_RESET_TOKEN_LEN, QUIC_TRANSPORT_ERROR_AEAD_LIMIT_REACHED,
    QUIC_TRANSPORT_ERROR_APPLICATION_ERROR, QUIC_TRANSPORT_ERROR_CONNECTION_ID_LIMIT_ERROR,
    QUIC_TRANSPORT_ERROR_CONNECTION_REFUSED, QUIC_TRANSPORT_ERROR_CRYPTO_BUFFER_EXCEEDED,
    QUIC_TRANSPORT_ERROR_CRYPTO_ERROR_END, QUIC_TRANSPORT_ERROR_CRYPTO_ERROR_START,
    QUIC_TRANSPORT_ERROR_FINAL_SIZE_ERROR, QUIC_TRANSPORT_ERROR_FLOW_CONTROL_ERROR,
    QUIC_TRANSPORT_ERROR_FRAME_ENCODING_ERROR, QUIC_TRANSPORT_ERROR_INTERNAL_ERROR,
    QUIC_TRANSPORT_ERROR_INVALID_TOKEN, QUIC_TRANSPORT_ERROR_KEY_UPDATE_ERROR,
    QUIC_TRANSPORT_ERROR_NO_ERROR, QUIC_TRANSPORT_ERROR_NO_VIABLE_PATH,
    QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION, QUIC_TRANSPORT_ERROR_STREAM_LIMIT_ERROR,
    QUIC_TRANSPORT_ERROR_STREAM_STATE_ERROR, QUIC_TRANSPORT_ERROR_TRANSPORT_PARAMETER_ERROR,
    QUIC_TRANSPORT_ERROR_VERSION_NEGOTIATION_ERROR,
};
pub use header::QuicHeader;
pub use packet::{
    Quic, QuicHandshakeBuilder, QuicInitialBuilder, QuicLongHeaderPacket, QuicPacket,
    QuicRetryBuilder, QuicRetryPacket, QuicShortHeaderBuilder, QuicShortHeaderPacket,
    QuicVersionNegotiationBuilder, QuicVersionNegotiationPacket, QuicZeroRttBuilder,
    QUIC_RETRY_INTEGRITY_TAG_LEN,
};
pub use packet_number::QuicPacketNumber;
pub use transport_parameter::{
    grease_transport_parameter_id, is_grease_transport_parameter_id,
    QuicConnectionIdTransportParameter, QuicIntegerTransportParameter,
    QuicIntegerTransportParameterValidation, QuicKnownTransportParameter, QuicPreferredAddress,
    QuicPreferredAddressValidation, QuicStatelessResetToken, QuicTransportParameter,
    QuicTransportParameterDuplicate, QuicTransportParameterKind, QuicVersionInformation,
    QuicVersionInformationValidation,
};
pub use varint::QuicVarInt;

#[cfg(test)]
mod tests;
