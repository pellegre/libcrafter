//! Public crate for packet-level network interaction.
//!
//! `crafter` is the only public crate. It exposes a self-contained API for
//! examples, generated tools, and agent-directed packet workflows:
//!
//! - packet construction, decode, checksums, and protocol layers
//! - classic pcap file input/output and libpcap-backed wire adapters
//! - interface, send, send/receive, batch, and address helpers
//! - `PacketWire` source/writer backends, `PacketRecord` metadata,
//!   `Sniffer`/`Transmitter` pipelines, and packet transforms
//! - Ethernet, IEEE 802.11/radiotap, LLC/SNAP, IP, transport, and selected
//!   application protocol primitives
//!
//! Public modules are organized as `crafter::core`, `crafter::net`,
//! `crafter::wire`, and `crafter::prelude`. The `wire` module is the
//! packet-stream API that generated tools should use for backend-neutral
//! capture, transforms, pcap file I/O, and transmission. Most examples should
//! start with `use crafter::prelude::*;`.
//!
//! Local examples use dry-run send plans or offline pcaps unless live behavior
//! is explicitly requested.
//!
//! ```rust
//! use crafter::prelude::*;
//! use std::net::Ipv4Addr;
//!
//! # fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
//! let packet = Ipv4::new()
//!     .src(Ipv4Addr::new(192, 0, 2, 10))
//!     .dst(Ipv4Addr::new(198, 51, 100, 20))
//!     / Icmpv4::echo_request().id(0x4242).seq(1)
//!     / Raw::from("hello");
//!
//! let compiled = packet.compile()?;
//! println!("{}", packet.summary());
//! println!("{}", compiled.hexdump());
//! # Ok(())
//! # }
//! ```
//!
//! Wi-Fi stacks use the same offline packet model. IP over IEEE 802.11 is
//! represented with explicit LLC/SNAP, and the example below only compiles,
//! decodes, and inspects synthetic bytes.
//!
//! ```rust
//! use crafter::prelude::*;
//! use std::net::Ipv4Addr;
//!
//! # fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
//! let sta = MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]);
//! let ap = MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]);
//! let dot11 = Dot11::data();
//! let to_ds = dot11.frame_control_value().with_to_ds(true);
//!
//! let packet = Radiotap::new()
//!     / dot11
//!         .frame_control(to_ds)
//!         .addr1(ap)
//!         .addr2(sta)
//!         .addr3(ap)
//!         .sequence_number(1)
//!     / LlcSnap::new().ethertype(ETHERTYPE_IPV4)
//!     / Ipv4::new()
//!         .src(Ipv4Addr::new(192, 0, 2, 10))
//!         .dst(Ipv4Addr::new(198, 51, 100, 20))
//!     / Icmpv4::echo_request().id(0x4242).seq(1)
//!     / Raw::from("hello");
//!
//! let compiled = packet.compile()?;
//! let decoded = Packet::decode_from_link(LinkType::Radiotap, compiled.as_bytes())?;
//! assert!(decoded.layer::<Radiotap>().is_some());
//! assert!(decoded.layer::<Dot11>().is_some());
//! assert!(decoded.layer::<LlcSnap>().is_some());
//! assert!(decoded.layer::<Ipv4>().is_some());
//! let _show = decoded.show();
//! let _hexdump = compiled.hexdump();
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

#[cfg(test)]
#[macro_use]
#[path = "../tests/support/mod.rs"]
mod test_support;

pub mod checksum;
pub mod endian;
pub mod error;
pub mod field;
pub mod mac;
pub mod packet;
pub mod protocols;
pub mod registry;

pub mod net;
pub mod wire;

pub use error::{CrafterError, Result};
pub use field::{Field, FieldState};
pub use mac::MacAddr;
pub use packet::{
    hexdump, CompiledPacket, IntoPacket, Layer, LayerContext, LinkType, NetworkLayer, Packet, Raw,
    TransportChecksumContext,
};
pub use protocols::exports::*;
pub use registry::{
    EthertypeBindingContext, Ipv4ProtocolBindingContext, Ipv6NextHeaderBindingContext,
    ProtocolRegistry, TcpBindingContext, UdpBindingContext,
};

pub use net::{
    default_interface, default_interface_in, default_interface_name, find_interface,
    find_interface_in, get_ip_strings, get_ips, get_my_ip, get_my_ip_in, get_my_ipv6,
    get_my_ipv6_in, get_my_mac, get_my_mac_in, interface_for, interface_for_in, interfaces,
    parse_ip_range, parse_numbers, reply_filter, reply_matches, send_packet, send_packets,
    send_plan, send_recv_packet, send_recv_packets, BatchSend, BatchSendEntry, BatchSendRecv,
    BatchSendRecvEntry, BatchSendRecvReport, BatchSendReport, InterfaceAddress, InterfaceInfo,
    Ipv4Range, NetError, PacketBatchSendExt, PacketBatchSendRecvExt, PacketSendExt,
    PacketSendRecvExt, RawSender, ReplyMatcher, SendMode, SendOptions, SendPlan, SendRecv,
    SendRecvOptions, SendRecvReport, SendReport, SendTarget, SocketSend, SocketSender,
};
pub use wire::Sniffer;
pub use wire::{
    derive_pmk, derive_ptk, BackendKind, BluetoothMetadata, Dot11Metadata, DropAllTransform,
    DuplicateTransform, IpDefrag, IpDefragConfig, IpDefragEvictionReason, IpDefragMetadata,
    IpDefragOverlapPolicy, IpDefragOverlapStatus, IpDefragStats, IpFragment, IpFragmentConfig,
    IpFragmentFamily, IpFragmentMetadata, IpFragmentRange, IpFragmentReason, IpFragmentStats,
    Ipv4DontFragmentPolicy, Ipv4FragmentIdentificationPolicy, Ipv6AtomicFragmentPolicy,
    Ipv6FragmentIdentificationPolicy, MediumMetadata, MemoryPacketWriter, MemoryWrite,
    OpenedPacketSource, OpenedPacketWriter, PacketMetadata, PacketOrigin, PacketRecord,
    PacketSource, PacketTransform, PacketWire, PacketWireBuilder, PacketWireTarget, PacketWriter,
    PairwiseTransientKey, PassThroughTransform, Pmk, RadioMetadata, RawSocketWireBuilder,
    RawSocketWriter, SnifferCancel, SnifferHandle, TraceAppendTransform, TransformOutput,
    TransformTrace, Transmitter, VecPacketSource, WifiDecryptState, WifiMetadata,
    WifiProtectionStatus, WireError, WpaAkm, WpaCipher, WpaCredentialStatus, WpaDecrypt,
    WpaDecryptConfig, WpaDecryptReason, WpaHandshakeStatus, WpaKeyKind, WpaMetadata, WpaNetwork,
    WriteReport, IP_DEFRAG_DEFAULT_MAX_AGE, IP_DEFRAG_DEFAULT_MAX_BYTES_PER_DATAGRAM,
    IP_DEFRAG_DEFAULT_MAX_DATAGRAMS, IP_FRAGMENT_MIN_MTU,
};

/// Core packet and protocol APIs.
pub mod core {
    pub use crate::checksum;
    pub use crate::endian;
    pub use crate::error;
    pub use crate::field;
    pub use crate::mac;
    pub use crate::packet;
    pub use crate::protocols;
    pub use crate::protocols::exports::*;
    pub use crate::registry;
    pub use crate::registry::{
        EthertypeBindingContext, Ipv4ProtocolBindingContext, Ipv6NextHeaderBindingContext,
        ProtocolRegistry, TcpBindingContext, UdpBindingContext,
    };
    pub use crate::{
        hexdump, CompiledPacket, CrafterError, Field, FieldState, IntoPacket, Layer, LayerContext,
        LinkType, MacAddr, NetworkLayer, Packet, Raw, Result, TransportChecksumContext,
    };
}

/// Common imports for generated packet tools and examples.
///
/// The prelude includes packet construction and decode types plus the
/// high-level wire primitives: [`PacketWire`], [`PacketRecord`],
/// [`PacketTransform`], [`Sniffer`], and [`Transmitter`].
pub mod prelude {
    pub use crate::core::*;
    pub use crate::{
        default_interface, default_interface_in, default_interface_name, derive_pmk, derive_ptk,
        find_interface, find_interface_in, get_ip_strings, get_ips, get_my_ip, get_my_ip_in,
        get_my_ipv6, get_my_ipv6_in, get_my_mac, get_my_mac_in, interface_for, interface_for_in,
        interfaces, parse_ip_range, parse_numbers, reply_filter, reply_matches, send_packet,
        send_packets, send_plan, send_recv_packet, send_recv_packets, BatchSend, BatchSendEntry,
        BatchSendRecv, BatchSendRecvEntry, BatchSendRecvReport, BatchSendReport, Dot11Metadata,
        InterfaceAddress, InterfaceInfo, Ipv4Range, NetError, PacketBatchSendExt,
        PacketBatchSendRecvExt, PacketSendExt, PacketSendRecvExt, PairwiseTransientKey, Pmk,
        RawSender, ReplyMatcher, SendMode, SendOptions, SendPlan, SendRecv, SendRecvOptions,
        SendRecvReport, SendReport, SendTarget, Sniffer, SocketSend, SocketSender, Transmitter,
        VecPacketSource, WifiDecryptState, WifiMetadata, WifiProtectionStatus, WireError, WpaAkm,
        WpaCipher, WpaCredentialStatus, WpaDecrypt, WpaDecryptConfig, WpaDecryptReason,
        WpaHandshakeStatus, WpaKeyKind, WpaMetadata, WpaNetwork, WriteReport,
    };
    pub use crate::{
        BackendKind, BluetoothMetadata, DropAllTransform, DuplicateTransform, IpDefrag,
        IpDefragConfig, IpDefragEvictionReason, IpDefragMetadata, IpDefragOverlapPolicy,
        IpDefragOverlapStatus, IpDefragStats, IpFragment, IpFragmentConfig, IpFragmentFamily,
        IpFragmentMetadata, IpFragmentRange, IpFragmentReason, IpFragmentStats,
        Ipv4DontFragmentPolicy, Ipv4FragmentIdentificationPolicy, Ipv6AtomicFragmentPolicy,
        Ipv6FragmentIdentificationPolicy, MediumMetadata, MemoryPacketWriter, MemoryWrite,
        OpenedPacketSource, OpenedPacketWriter, PacketMetadata, PacketOrigin, PacketRecord,
        PacketSource, PacketTransform, PacketWire, PacketWireBuilder, PacketWireTarget,
        PacketWriter, PassThroughTransform, RadioMetadata, RawSocketWireBuilder, RawSocketWriter,
        SnifferCancel, SnifferHandle, TraceAppendTransform, TransformOutput, TransformTrace,
        IP_DEFRAG_DEFAULT_MAX_AGE, IP_DEFRAG_DEFAULT_MAX_BYTES_PER_DATAGRAM,
        IP_DEFRAG_DEFAULT_MAX_DATAGRAMS, IP_FRAGMENT_MIN_MTU,
    };
}
