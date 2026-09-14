//! Trigger-configured EHT20 DATA admission and isolated-user IQ recovery.

mod receiver;

pub(in crate::radio) use receiver::{Error, Receiver};

#[cfg(test)]
mod tests;
