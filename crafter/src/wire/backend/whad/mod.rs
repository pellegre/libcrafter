//! WHAD-compatible live backend support.

#[cfg(feature = "whad")]
pub(crate) mod messages;

pub(crate) mod proto {
    #![allow(dead_code)]

    include!(concat!(env!("OUT_DIR"), "/whad_proto.rs"));
}
