//! Single-user EHT20 non-OFDMA DATA recovery.

mod iq;
mod receiver;
#[cfg(test)]
mod tests;

use super::{Capacity, Error, Timing};
pub(in crate::radio) use receiver::{Admission, Receiver, Recovered};
