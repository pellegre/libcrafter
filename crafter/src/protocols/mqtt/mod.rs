//! MQTT 3.1.1 control packet support.
//!
//! This module provides packet-layer construction and decoding for cleartext
//! MQTT 3.1.1 control packets on TCP port [`MQTT_PORT`]. The [`Mqtt`] layer
//! follows the same builder and decode model as the rest of `crafter`: fields
//! left unset are filled during `compile()`, while fields set explicitly are
//! preserved so malformed packets can still be built intentionally.
//!
//! MQTT-over-TLS on [`MQTT_TLS_PORT`] is treated as TLS-wrapped traffic rather
//! than cleartext MQTT, so TCP payloads on that port are preserved as raw bytes.
//!
//! MQTT codepoints are copied from `.agents/docs/mqtt-codepoints.md`, which is
//! the source of truth derived from `.agents/docs/mqtt-manifest.md`.
//!
//! ```rust
//! use crafter::prelude::*;
//! use std::net::Ipv4Addr;
//!
//! # fn main() -> crafter::Result<()> {
//! let packet = Ipv4::new()
//!     .src(Ipv4Addr::new(192, 0, 2, 10))
//!     .dst(Ipv4Addr::new(198, 51, 100, 20))
//!     / Tcp::new()
//!         .sport(49_194)
//!         .dport(MQTT_PORT)
//!         .seq(0x0102_0304)
//!         .ack(0x0506_0708)
//!         .ack_segment()
//!     / Mqtt::connect()
//!         .client_id("crafter-client")
//!         .keep_alive(30)
//!         .clean_session(true);
//!
//! let compiled = packet.compile()?;
//! let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
//! let mqtt = decoded.layer::<Mqtt>().expect("MQTT layer");
//! assert_eq!(mqtt.packet_type(), MqttControlPacketType::Connect);
//! assert_eq!(mqtt.client_id_value(), Some("crafter-client"));
//! # Ok(())
//! # }
//! ```

pub mod constants;
pub(crate) mod decode;
pub mod header;
pub mod message;
pub mod property;
pub mod varint;
pub mod wire;

pub use constants::*;
pub use header::MqttControlPacketType;
pub use message::{Mqtt, MqttSubscriptionOptions};
pub use property::{MqttProperties, MqttProperty};
