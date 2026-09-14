//! Shared OFDM PHY-signaling primitives.

mod modulation;
mod symbol;

pub(in crate::radio) use modulation::Modulation;
pub(in crate::radio) use symbol::corrected_bins;
