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
pub use crypto::QuicCryptoContext;
pub use frame::{
    QuicAckEcnCounts, QuicAckFrame, QuicAckRange, QuicConnectionCloseFrame,
    QuicConnectionCloseKind, QuicCryptoFrame, QuicDataBlockedFrame, QuicFrame, QuicFrameKind,
    QuicHandshakeDoneFrame, QuicKnownFrameType, QuicMaxDataFrame, QuicMaxStreamDataFrame,
    QuicMaxStreamsFrame, QuicNewConnectionIdFrame, QuicNewTokenFrame, QuicPathChallengeFrame,
    QuicPathResponseFrame, QuicResetStreamFrame, QuicRetireConnectionIdFrame, QuicStopSendingFrame,
    QuicStreamDataBlockedFrame, QuicStreamDirection, QuicStreamFrame, QuicStreamsBlockedFrame,
    QuicUnknownFrame, QUIC_TRANSPORT_ERROR_AEAD_LIMIT_REACHED,
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
    is_grease_transport_parameter_id, QuicConnectionIdTransportParameter,
    QuicIntegerTransportParameter, QuicIntegerTransportParameterValidation,
    QuicKnownTransportParameter, QuicTransportParameter, QuicTransportParameterDuplicate,
    QuicTransportParameterKind,
};
pub use varint::QuicVarInt;

#[cfg(test)]
mod tests;
