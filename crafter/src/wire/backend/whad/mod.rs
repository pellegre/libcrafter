//! WHAD-compatible live backend support.

/// WHAD protocol version matched by the regenerated vendored protobuf subset.
#[cfg(feature = "whad")]
pub(crate) const WHAD_TARGET_PROTOCOL_VERSION: u32 = 3;

pub(crate) mod capability;
pub use capability::WhadBleMode;

#[cfg(feature = "whad")]
pub(crate) mod discovery;

#[cfg(feature = "whad")]
pub(crate) mod dot15d4;

#[cfg(feature = "whad")]
#[cfg(test)]
pub(crate) mod duplex;

#[cfg(feature = "whad")]
pub(crate) mod framing;

#[cfg(feature = "whad")]
pub(crate) mod messages;

#[cfg(feature = "whad")]
pub(crate) mod reader;

#[cfg(feature = "whad")]
pub(crate) mod transport;

#[cfg(feature = "whad")]
pub(crate) mod writer;

#[cfg(feature = "whad")]
pub(crate) mod proto {
    #![allow(dead_code)]
    // The vendored WHAD protobuf schema owns its enum variant names.
    #![allow(clippy::enum_variant_names)]

    include!(concat!(env!("OUT_DIR"), "/whad_proto.rs"));
}
