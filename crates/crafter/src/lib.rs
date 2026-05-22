//! Public facade for the packet crafting workspace.

#![forbid(unsafe_code)]

pub use crafter_core as core;
pub use crafter_core::*;
pub use crafter_live as live;
pub use crafter_net as net;
pub use crafter_net::{
    arp_resolve, default_interface, default_interface_in, default_interface_name,
    derive_mac_from_ipv6, find_interface, find_interface_in, get_ip_strings, get_ips, get_mac,
    get_my_ip, get_my_ip_in, get_my_ipv6, get_my_ipv6_in, get_my_mac, get_my_mac_in, interface_for,
    interface_for_in, interfaces, parse_ip_range, parse_numbers, reply_filter, reply_matches,
    resolve_mac, send_packet, send_packets, send_plan, send_recv_packet, send_recv_packets,
    ArpResolveOptions, ArpResolveReport, BatchSend, BatchSendEntry, BatchSendRecv,
    BatchSendRecvEntry, BatchSendRecvReport, BatchSendReport, InterfaceAddress, InterfaceInfo,
    Ipv4Range, NetError, PacketBatchSendExt, PacketBatchSendRecvExt, PacketSendExt,
    PacketSendRecvExt, RawSender, ReplyMatcher, SendMode, SendOptions, SendPlan, SendRecv,
    SendRecvOptions, SendRecvReport, SendReport, SendTarget, SocketSend, SocketSender,
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
        arp_resolve, default_interface, default_interface_in, default_interface_name,
        derive_mac_from_ipv6, find_interface, find_interface_in, get_ip_strings, get_ips, get_mac,
        get_my_ip, get_my_ip_in, get_my_ipv6, get_my_ipv6_in, get_my_mac, get_my_mac_in,
        interface_for, interface_for_in, interfaces, parse_ip_range, parse_numbers, reply_filter,
        reply_matches, resolve_mac, send_packet, send_packets, send_plan, send_recv_packet,
        send_recv_packets, ArpResolveOptions, ArpResolveReport, BatchSend, BatchSendEntry,
        BatchSendRecv, BatchSendRecvEntry, BatchSendRecvReport, BatchSendReport, InterfaceAddress,
        InterfaceInfo, Ipv4Range, NetError, PacketBatchSendExt, PacketBatchSendRecvExt,
        PacketSendExt, PacketSendRecvExt, RawSender, ReplyMatcher, SendMode, SendOptions, SendPlan,
        SendRecv, SendRecvOptions, SendRecvReport, SendReport, SendTarget, SocketSend,
        SocketSender,
    };
    pub use crafter_pcap::{
        dump_pcap, read_pcap, read_pcap_filtered, Capture, CaptureControl, CaptureHandle,
        FileSniffer, PcapError, PcapFilter, PcapHeader, PcapLinkType, PcapPacket, PcapReader,
        PcapRecord, PcapTimestamp, PcapWriter, PcapWriterOptions, Sniffer, TimestampPrecision,
    };
}
