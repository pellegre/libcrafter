//! WHAD-compatible live backend support.

pub(crate) mod proto {
    #![allow(dead_code)]

    include!(concat!(env!("OUT_DIR"), "/whad_proto.rs"));
}
