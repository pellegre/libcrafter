//! Bluetooth Low Energy advertising link-layer support.
//!
//! This module will hold the BLE radio pseudo-header (`BleRadio`), advertising
//! Link Layer PDU (`BleLlAdv`), and GAP Advertising Data structure layers.

mod ad;
mod adv;
mod consts;
mod radio;

pub use ad::{AdList, AdStructure};
pub use adv::{BleAdvPduType, BleLlAdv};
pub use radio::{BlePhy, BleRadio};
