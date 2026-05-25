//! Network interface, raw socket, routing, and send/receive helpers.
//!
//! Local callers can compile packets into send plans without transmitting
//! traffic. Live send and send/receive helpers require explicit live options
//! and platform privileges; examples keep those paths gated for disposable
//! labs.

#![forbid(unsafe_code)]

pub mod batch;
mod error;
pub mod interface;
pub mod range;
pub mod reply;
pub mod send;
pub mod send_recv;

pub use batch::{send_packets, BatchSend, BatchSendEntry, BatchSendReport, PacketBatchSendExt};
pub use error::{NetError, Result};
pub use interface::{
    default_interface, default_interface_in, default_interface_name, find_interface,
    find_interface_in, get_my_ip, get_my_ip_in, get_my_ipv6, get_my_ipv6_in, get_my_mac,
    get_my_mac_in, interface_for, interface_for_in, interfaces, InterfaceAddress, InterfaceInfo,
};
pub use range::{get_ip_strings, get_ips, parse_ip_range, parse_numbers, Ipv4Range};
pub use reply::{reply_filter, reply_matches, ReplyMatcher};
pub use send::{
    send_packet, send_plan, PacketSendExt, RawSender, SendMode, SendOptions, SendPlan, SendReport,
    SendTarget, SocketSend, SocketSender,
};
pub use send_recv::{
    send_recv_packet, send_recv_packets, BatchSendRecv, BatchSendRecvEntry, BatchSendRecvReport,
    PacketBatchSendRecvExt, PacketSendRecvExt, SendRecv, SendRecvOptions, SendRecvReport,
};

/// Routing helper namespace.
pub mod route {
    pub use super::interface::{
        default_interface, default_interface_name, interface_for, interface_for_in,
    };
}

/// Socket helper namespace re-exporting the first stable sender types.
pub mod socket {
    pub use super::{
        reply_filter, reply_matches, send_packet, send_packets, send_plan, send_recv_packet,
        send_recv_packets, BatchSend, BatchSendEntry, BatchSendRecv, BatchSendRecvEntry,
        BatchSendRecvReport, BatchSendReport, NetError, PacketBatchSendExt, PacketBatchSendRecvExt,
        PacketSendExt, PacketSendRecvExt, RawSender, ReplyMatcher, SendMode, SendOptions, SendPlan,
        SendRecv, SendRecvOptions, SendRecvReport, SendReport, SendTarget, SocketSend,
        SocketSender,
    };
}

#[cfg(test)]
mod tests;
