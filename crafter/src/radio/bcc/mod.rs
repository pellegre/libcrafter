//! Shared one-stream BCC payload recovery.

mod decoder;

pub(in crate::radio) use decoder::{Decoder, Error, Parameters};
