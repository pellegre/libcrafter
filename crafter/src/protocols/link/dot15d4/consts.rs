//! IEEE 802.15.4 and Zigbee constants and codepoints.
//!
//! Fuller codepoint and channel tables are added in step 07; this placeholder
//! exists so the module is a valid compilation unit. Values are grounded in
//! `.agents/docs/dot15d4-codepoints.md`.

/// Lowest 2.4 GHz O-QPSK PHY channel number (IEEE 802.15.4 channel page 0).
pub const CHANNEL_MIN_2P4_GHZ: u8 = 11;
/// Highest 2.4 GHz O-QPSK PHY channel number (IEEE 802.15.4 channel page 0).
pub const CHANNEL_MAX_2P4_GHZ: u8 = 26;
