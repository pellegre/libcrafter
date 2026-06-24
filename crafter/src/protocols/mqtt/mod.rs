//! MQTT 3.1.1 support.
//!
//! MQTT codepoints are copied from `.agents/docs/mqtt-codepoints.md`, which is
//! the source of truth derived from `.agents/docs/mqtt-manifest.md`.

pub mod constants;
pub(crate) mod decode;
pub mod header;
pub mod message;
pub mod varint;
pub mod wire;

pub use constants::*;
pub use header::MqttControlPacketType;
pub use message::Mqtt;
