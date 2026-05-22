//! Core packet model, protocol encoding, protocol decoding, checksums, and formatting.

#![forbid(unsafe_code)]

pub mod checksum;
pub mod endian;
pub mod error;
pub mod field;
pub mod mac;
pub mod packet;
pub mod protocols {
    //! Protocol layer exports.

    pub use crate::packet::Raw;
}

pub use error::{CrafterError, Result};
pub use field::{Field, FieldState};
pub use mac::MacAddr;
pub use packet::{
    hexdump, CompiledPacket, IntoPacket, Layer, LayerContext, LinkType, NetworkLayer, Packet, Raw,
};
