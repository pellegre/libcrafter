//! IEEE 802.15.4 and Zigbee link-layer support.
//!
//! This module will hold the 802.15.4 radio descriptor pseudo-header
//! (`Dot15d4Radio`), the 802.15.4 MAC frame layer (`Dot15d4`), and the Zigbee
//! Network (`ZigbeeNwk`) and Application Support (`ZigbeeAps`) layers that
//! stack on the MAC payload. Mirrors the `ble` module layout.

mod aps;
mod consts;
mod fcs;
mod mac;
mod nwk;
mod radio;

pub use aps::ZigbeeAps;
pub use mac::Dot15d4;
pub use nwk::ZigbeeNwk;
pub use radio::Dot15d4Radio;
