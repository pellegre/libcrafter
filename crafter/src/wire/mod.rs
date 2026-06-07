//! Packet-shaped wire I/O abstractions.
//!
//! `crafter::wire` is the high-level packet stream layer. Open one
//! [`PacketWire`] per backend or interface, split it into a [`PacketSource`] or
//! [`PacketWriter`], and then drive it with a [`Sniffer`] or [`Transmitter`].
//! Each stream item is a [`PacketRecord`]: a typed [`crate::Packet`] plus
//! inspectable metadata such as backend, interface, file path, pcap timestamp,
//! link type, medium annotations, and transform traces.
//!
//! Backends are adapters, not the abstraction. The current backend set covers
//! offline pcap input, pcap recording, live libpcap interfaces, raw socket
//! writing, and in-memory test streams. Future WPA, fragmentation, stream
//! reassembly, Bluetooth, or SDR integrations should fit as packet sources,
//! packet writers, or stateful [`PacketTransform`] stages without changing the
//! packet-shaped stream contract.

#![forbid(unsafe_code)]

pub mod backend;
pub mod dot11_metadata;
mod error;
pub mod packet_wire;
pub mod record;
pub mod sniffer;
pub mod source;
pub mod transform;
#[cfg(test)]
mod transform_contract;
pub mod transmitter;
pub mod wpa;
pub mod writer;

pub use backend::raw_socket::RawSocketWriter;
pub use dot11_metadata::Dot11Metadata;
pub use error::{Result, WireError};
pub use packet_wire::{
    OpenedPacketSource, OpenedPacketWriter, PacketWire, PacketWireBuilder, PacketWireTarget,
    RawSocketWireBuilder,
};
pub use record::{
    BackendKind, BluetoothMetadata, MediumMetadata, PacketMetadata, PacketOrigin, PacketRecord,
    RadioMetadata, TransformTrace, WifiDecryptState, WifiMetadata, WifiProtectionStatus,
};
pub use sniffer::{Sniffer, SnifferCancel, SnifferHandle};
pub use source::{PacketSource, VecPacketSource};
pub use transform::{
    DropAllTransform, DuplicateTransform, PacketTransform, PassThroughTransform,
    TraceAppendTransform, TransformOutput,
};
pub use transmitter::Transmitter;
pub use wpa::{
    derive_pmk, Pmk, WpaAkm, WpaCipher, WpaCredentialStatus, WpaDecrypt, WpaDecryptConfig,
    WpaDecryptReason, WpaHandshakeStatus, WpaKeyKind, WpaMetadata, WpaNetwork,
};
pub use writer::{MemoryPacketWriter, MemoryWrite, PacketWriter, WriteReport};
