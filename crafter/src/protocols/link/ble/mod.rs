//! Bluetooth Low Energy advertising link-layer support.
//!
//! This module will hold the BLE radio pseudo-header (`BleRadio`), advertising
//! Link Layer PDU (`BleLlAdv`), and GAP Advertising Data structure layers.

mod adv;
mod consts;
mod radio;

pub use adv::BleLlAdv;
pub use radio::{BlePhy, BleRadio};
