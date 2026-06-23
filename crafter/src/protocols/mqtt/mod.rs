//! MQTT 3.1.1 support.
//!
//! MQTT codepoints are copied from `.agents/docs/mqtt-codepoints.md`, which is
//! the source of truth derived from `.agents/docs/mqtt-manifest.md`.

pub mod constants;
pub mod header;
pub mod varint;

pub use constants::*;
pub use header::MqttControlPacketType;
