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
pub mod ip;
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

#[cfg(feature = "whad")]
pub use backend::whad::WhadBleMode;
pub use backend::raw_socket::RawSocketWriter;
pub use dot11_metadata::Dot11Metadata;
pub use error::{Result, WireError};
pub use ip::{
    IpDefrag, IpDefragConfig, IpDefragEvictionReason, IpDefragMetadata, IpDefragOverlapPolicy,
    IpDefragOverlapStatus, IpDefragStats, IpFragment, IpFragmentConfig, IpFragmentFamily,
    IpFragmentMetadata, IpFragmentRange, IpFragmentReason, IpFragmentStats, Ipv4DontFragmentPolicy,
    Ipv4FragmentIdentificationPolicy, Ipv6AtomicFragmentPolicy, Ipv6FragmentIdentificationPolicy,
    IP_DEFRAG_DEFAULT_MAX_AGE, IP_DEFRAG_DEFAULT_MAX_BYTES_PER_DATAGRAM,
    IP_DEFRAG_DEFAULT_MAX_DATAGRAMS, IP_FRAGMENT_MIN_MTU,
};
pub use packet_wire::{
    OpenedPacketSource, OpenedPacketWriter, PacketWire, PacketWireBuilder, PacketWireTarget,
    RawSocketWireBuilder,
};
#[cfg(feature = "whad")]
pub use packet_wire::WhadWireBuilder;
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
    derive_pmk, derive_ptk, PairwiseTransientKey, Pmk, WpaAkm, WpaCipher, WpaCredentialStatus,
    WpaDecrypt, WpaDecryptConfig, WpaDecryptReason, WpaHandshakeStatus, WpaKeyKind, WpaMetadata,
    WpaNetwork,
};
pub use writer::{MemoryPacketWriter, MemoryWrite, PacketWriter, WriteReport};
