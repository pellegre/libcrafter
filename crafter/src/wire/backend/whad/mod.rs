//! WHAD-compatible live backend support.

/// WHAD protocol version matched by the regenerated vendored protobuf subset.
pub(crate) const WHAD_TARGET_PROTOCOL_VERSION: u32 = 3;

#[cfg(feature = "whad")]
pub(crate) mod framing;

#[cfg(feature = "whad")]
pub(crate) mod messages;

pub(crate) mod proto {
    #![allow(dead_code)]

    include!(concat!(env!("OUT_DIR"), "/whad_proto.rs"));
}
