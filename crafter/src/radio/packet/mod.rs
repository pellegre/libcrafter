//! Adapters between radio codecs and the typed packet I/O surface.

mod source;
pub(super) mod writer;

pub use source::{RadioPacketSource, RadioReceiveMetadata};
pub use writer::{PacketEncoder, RadioPacketWriter};
