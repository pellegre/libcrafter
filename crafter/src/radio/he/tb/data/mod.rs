//! HE20 trigger-based DATA admission and isolated-user IQ recovery.

mod receiver;

pub(in crate::radio) use receiver::{Error, Receiver};
