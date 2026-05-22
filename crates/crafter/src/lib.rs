//! Public facade for the packet crafting workspace.

#![forbid(unsafe_code)]

pub use crafter_core as core;
pub use crafter_core::*;
pub use crafter_live as live;
pub use crafter_net as net;
pub use crafter_net::{
    send_packet, send_plan, NetError, PacketSendExt, RawSender, SendMode, SendOptions, SendPlan,
    SendReport, SendTarget, SocketSend, SocketSender,
};
pub use crafter_pcap as pcap;
pub use crafter_pcap::{
    dump_pcap, read_pcap, read_pcap_filtered, Capture, CaptureControl, CaptureHandle, FileSniffer,
    PcapError, PcapFilter, PcapHeader, PcapLinkType, PcapPacket, PcapReader, PcapRecord,
    PcapTimestamp, PcapWriter, PcapWriterOptions, Sniffer, TimestampPrecision,
};

/// Common imports for generated packet tools and examples.
pub mod prelude {
    pub use crafter_core::*;
    pub use crafter_net::{
        send_packet, send_plan, NetError, PacketSendExt, RawSender, SendMode, SendOptions,
        SendPlan, SendReport, SendTarget, SocketSend, SocketSender,
    };
    pub use crafter_pcap::{
        dump_pcap, read_pcap, read_pcap_filtered, Capture, CaptureControl, CaptureHandle,
        FileSniffer, PcapError, PcapFilter, PcapHeader, PcapLinkType, PcapPacket, PcapReader,
        PcapRecord, PcapTimestamp, PcapWriter, PcapWriterOptions, Sniffer, TimestampPrecision,
    };
}
