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
pub use frame::QuicFrame;
pub use header::QuicHeader;
pub use packet::{
    Quic, QuicHandshakeBuilder, QuicInitialBuilder, QuicLongHeaderPacket, QuicPacket,
    QuicRetryBuilder, QuicRetryPacket, QuicShortHeaderPacket, QuicVersionNegotiationBuilder,
    QuicVersionNegotiationPacket, QuicZeroRttBuilder, QUIC_RETRY_INTEGRITY_TAG_LEN,
};
pub use packet_number::QuicPacketNumber;
pub use transport_parameter::QuicTransportParameter;
pub use varint::QuicVarInt;

#[cfg(test)]
mod tests;
