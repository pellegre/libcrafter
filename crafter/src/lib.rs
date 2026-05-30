//! Public crate for packet-level network interaction.
//!
//! `crafter` is the only public crate. It exposes a self-contained API for
//! examples, generated tools, and agent-directed packet workflows:
//!
//! - packet construction, decode, checksums, and protocol layers
//! - pcap read/write and sniffing helpers
//! - interface, send, send/receive, batch, and address helpers
//!
//! Public modules are organized as `crafter::core`, `crafter::pcap`,
//! `crafter::net`, and `crafter::prelude`. Most examples should start with
//! `use crafter::prelude::*;`.
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
//!     / Icmp::echo_request().id(0x4242).seq(1)
//!     / Raw::from("hello");
//!
//! let compiled = packet.compile()?;
//! println!("{}", packet.summary());
//! println!("{}", compiled.hexdump());
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
pub mod pcap;

pub use error::{CrafterError, Result};
pub use field::{Field, FieldState};
pub use mac::MacAddr;
pub use packet::{
    hexdump, CompiledPacket, IntoPacket, Layer, LayerContext, LinkType, NetworkLayer, Packet, Raw,
    TransportChecksumContext,
};
pub use protocols::{
    decode_dns_name, decode_tftp_server_addresses, option_meta, option_name, option_status,
    scan_dhcp_option_segments, typed_option_value, Arp, ArpOperation, ClientNetworkDeviceInterface,
    ClientSystemArchitecture, Dhcp, DhcpClasslessRoute, DhcpClientIdentifier, DhcpClientUuid,
    DhcpMalformed, DhcpMessageType, DhcpOption, DhcpOptionArea, DhcpOptionCode, DhcpOptionFormat,
    DhcpOptionKind, DhcpOptionMeta, DhcpOptionSegment, DhcpOptionStatus, DhcpOptionValue,
    DhcpRelayAgentInfo, DhcpRelaySuboption, DhcpRelayVendorSpecific, DhcpStaticRoute,
    DhcpUserClass, DhcpVendorClassData, DhcpVendorIdentifyingOption, DhcpVendorSuboption,
    DhcpVssInfo, Dns, DnsQuestion, DnsRecord, DnsRecordData, Dot1Q, Ethernet, Icmp, IcmpExtension,
    IcmpExtensionMpls, IcmpExtensionObject, IcmpKind, IcmpLayer, Icmpv6, IpProtocol, Ipv4,
    Ipv4Option, Ipv4OptionIter, Ipv4RouteOptionKind, Ipv6, Ipv6FragmentHeader,
    Ipv6MobileRoutingHeader, Ipv6RoutingHeader, Ipv6SegmentRoutingHeader, LinuxSll, NullByteOrder,
    NullLoopback, OptionOverload, SipServers, Tcp, TcpExtendedDataOffset, TcpOption, TcpOptionIter,
    TcpSackBlock, Udp, Vlan, BOOTP_REPLY, BOOTP_REQUEST, DHCP_ACK, DHCP_CLIENT_PORT, DHCP_DECLINE,
    DHCP_DISCOVER, DHCP_HTYPE_ETHERNET, DHCP_INFORM, DHCP_MAGIC_COOKIE, DHCP_MAGIC_COOKIE_LEN,
    DHCP_MIN_LEN, DHCP_NAK, DHCP_OFFER, DHCP_OPTION_BROADCAST_ADDRESS,
    DHCP_OPTION_CLIENT_IDENTIFIER, DHCP_OPTION_DOMAIN_NAME, DHCP_OPTION_DOMAIN_NAME_SERVER,
    DHCP_OPTION_END, DHCP_OPTION_HOST_NAME, DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
    DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_OVERLOAD, DHCP_OPTION_PAD,
    DHCP_OPTION_PARAMETER_REQUEST_LIST, DHCP_OPTION_PRIVATE_USE_END, DHCP_OPTION_PRIVATE_USE_START,
    DHCP_OPTION_REBINDING_TIME, DHCP_OPTION_RELAY_AGENT_INFORMATION, DHCP_OPTION_RENEWAL_TIME,
    DHCP_OPTION_REQUESTED_IP_ADDRESS, DHCP_OPTION_ROUTER, DHCP_OPTION_SERVER_IDENTIFIER,
    DHCP_OPTION_SUBNET_MASK, DHCP_OVERLOAD_BOTH, DHCP_OVERLOAD_FILE, DHCP_OVERLOAD_SNAME,
    DHCP_RELAY_FLAG_UNICAST, DHCP_RELAY_SUBOPTION_ACCESS_NETWORK_NAME,
    DHCP_RELAY_SUBOPTION_ACCESS_POINT_BSSID, DHCP_RELAY_SUBOPTION_ACCESS_POINT_NAME,
    DHCP_RELAY_SUBOPTION_ACCESS_TECHNOLOGY_TYPE, DHCP_RELAY_SUBOPTION_AUTHENTICATION,
    DHCP_RELAY_SUBOPTION_CIRCUIT_ID, DHCP_RELAY_SUBOPTION_DOCSIS_DEVICE_CLASS,
    DHCP_RELAY_SUBOPTION_LINK_SELECTION, DHCP_RELAY_SUBOPTION_OPERATOR_IDENTIFIER,
    DHCP_RELAY_SUBOPTION_OPERATOR_REALM, DHCP_RELAY_SUBOPTION_RADIUS_ATTRIBUTES,
    DHCP_RELAY_SUBOPTION_RELAY_AGENT_ID, DHCP_RELAY_SUBOPTION_RELAY_FLAGS,
    DHCP_RELAY_SUBOPTION_RELAY_SOURCE_PORT, DHCP_RELAY_SUBOPTION_REMOTE_ID,
    DHCP_RELAY_SUBOPTION_SERVER_ID_OVERRIDE, DHCP_RELAY_SUBOPTION_SUBSCRIBER_ID,
    DHCP_RELAY_SUBOPTION_VENDOR_SPECIFIC, DHCP_RELAY_SUBOPTION_VSS,
    DHCP_RELAY_SUBOPTION_VSS_CONTROL, DHCP_RELEASE, DHCP_REQUEST, DHCP_SERVER_PORT,
    DHCP_VSS_TYPE_GLOBAL_DEFAULT, DHCP_VSS_TYPE_NVT_ASCII, DHCP_VSS_TYPE_VPN_ID, DNS_CLASS_IN,
    DNS_FLAG_AUTHENTIC_DATA, DNS_FLAG_AUTHORITATIVE, DNS_FLAG_CHECKING_DISABLED,
    DNS_FLAG_QR_RESPONSE, DNS_FLAG_RECURSION_AVAILABLE, DNS_FLAG_RECURSION_DESIRED,
    DNS_FLAG_TRUNCATED, DNS_HEADER_LEN, DNS_PORT, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME,
    DNS_TYPE_MX, DNS_TYPE_NS, DNS_TYPE_PTR, DNS_TYPE_TXT, ETHERTYPE_ARP, ETHERTYPE_IPV4,
    ETHERTYPE_IPV6, ETHERTYPE_VLAN, ICMPV6_DESTINATION_UNREACHABLE, ICMPV6_ECHO_REPLY,
    ICMPV6_ECHO_REQUEST, ICMPV6_PACKET_TOO_BIG, ICMPV6_PARAMETER_PROBLEM, ICMPV6_TIME_EXCEEDED,
    ICMP_DESTINATION_UNREACHABLE, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST, ICMP_EXTENSION_CLASS_MPLS,
    ICMP_EXTENSION_CTYPE_MPLS_INCOMING, ICMP_PARAMETER_PROBLEM, ICMP_REDIRECT, ICMP_SOURCE_QUENCH,
    ICMP_TIME_EXCEEDED, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IPV6, IPPROTO_IPV6_DSTOPTS,
    IPPROTO_IPV6_FRAGMENT, IPPROTO_IPV6_HOPOPTS, IPPROTO_IPV6_ROUTE, IPPROTO_TCP, IPPROTO_UDP,
    IPV4_FLAG_DONT_FRAGMENT, IPV4_FLAG_MORE_FRAGMENTS, IPV4_FLAG_RESERVED, IPV4_OPTION_EOL,
    IPV4_OPTION_LOOSE_SOURCE_ROUTE, IPV4_OPTION_NOP, IPV4_OPTION_RECORD_ROUTE,
    IPV4_OPTION_STRICT_SOURCE_ROUTE, IPV4_OPTION_TRACEROUTE, IPV6_ROUTING_TYPE_MOBILE,
    IPV6_ROUTING_TYPE_SEGMENT, IPV6_SEGMENT_POLICY_EGRESS, IPV6_SEGMENT_POLICY_INGRESS,
    IPV6_SEGMENT_POLICY_SOURCE_ADDRESS, IPV6_SEGMENT_POLICY_UNSET, TCP_EDO_HEADER_AND_SEGMENT_LEN,
    TCP_EDO_HEADER_LEN, TCP_EDO_REQUEST_LEN, TCP_FLAG_ACK, TCP_FLAG_CWR, TCP_FLAG_ECE,
    TCP_FLAG_FIN, TCP_FLAG_NS, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN, TCP_FLAG_URG,
    TCP_OPTION_EDO, TCP_OPTION_EOL, TCP_OPTION_FAST_OPEN, TCP_OPTION_MPTCP, TCP_OPTION_MSS,
    TCP_OPTION_NOP, TCP_OPTION_SACK, TCP_OPTION_SACK_PERMITTED, TCP_OPTION_TIMESTAMP,
    TCP_OPTION_WINDOW_SCALE,
};
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
pub use pcap::{
    dump_pcap, read_pcap, read_pcap_filtered, Capture, CaptureControl, CaptureHandle, FileSniffer,
    PcapError, PcapHeader, PcapLinkType, PcapPacket, PcapReader, PcapRecord, PcapRecords,
    PcapTimestamp, PcapWriter, PcapWriterOptions, Sniffer, TimestampPrecision,
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
    pub use crate::registry;
    pub use crate::{
        decode_dns_name, decode_tftp_server_addresses, hexdump, option_meta, option_name,
        option_status, scan_dhcp_option_segments, typed_option_value, Arp, ArpOperation,
        ClientNetworkDeviceInterface, ClientSystemArchitecture, CompiledPacket, CrafterError, Dhcp,
        DhcpClasslessRoute, DhcpClientIdentifier, DhcpClientUuid, DhcpMalformed, DhcpMessageType,
        DhcpOption, DhcpOptionArea, DhcpOptionCode, DhcpOptionFormat, DhcpOptionKind,
        DhcpOptionMeta, DhcpOptionSegment, DhcpOptionStatus, DhcpOptionValue, DhcpRelayAgentInfo,
        DhcpRelaySuboption, DhcpRelayVendorSpecific, DhcpStaticRoute, DhcpUserClass,
        DhcpVendorClassData, DhcpVendorIdentifyingOption, DhcpVendorSuboption, DhcpVssInfo, Dns,
        DnsQuestion, DnsRecord, DnsRecordData, Dot1Q, Ethernet, EthertypeBindingContext, Field,
        FieldState, Icmp, IcmpExtension, IcmpExtensionMpls, IcmpExtensionObject, IcmpKind,
        IcmpLayer, Icmpv6, IntoPacket, IpProtocol, Ipv4, Ipv4Option, Ipv4OptionIter,
        Ipv4ProtocolBindingContext, Ipv4RouteOptionKind, Ipv6, Ipv6FragmentHeader,
        Ipv6MobileRoutingHeader, Ipv6NextHeaderBindingContext, Ipv6RoutingHeader,
        Ipv6SegmentRoutingHeader, Layer, LayerContext, LinkType, LinuxSll, MacAddr, NetworkLayer,
        NullByteOrder, NullLoopback, OptionOverload, Packet, ProtocolRegistry, Raw, Result,
        SipServers, Tcp, TcpBindingContext, TcpExtendedDataOffset, TcpOption, TcpOptionIter,
        TcpSackBlock, TransportChecksumContext, Udp, UdpBindingContext, Vlan, BOOTP_REPLY,
        BOOTP_REQUEST, DHCP_ACK, DHCP_CLIENT_PORT, DHCP_DECLINE, DHCP_DISCOVER,
        DHCP_HTYPE_ETHERNET, DHCP_INFORM, DHCP_MAGIC_COOKIE, DHCP_MAGIC_COOKIE_LEN, DHCP_MIN_LEN,
        DHCP_NAK, DHCP_OFFER, DHCP_OPTION_BROADCAST_ADDRESS, DHCP_OPTION_CLIENT_IDENTIFIER,
        DHCP_OPTION_DOMAIN_NAME, DHCP_OPTION_DOMAIN_NAME_SERVER, DHCP_OPTION_END,
        DHCP_OPTION_HOST_NAME, DHCP_OPTION_IP_ADDRESS_LEASE_TIME, DHCP_OPTION_MESSAGE_TYPE,
        DHCP_OPTION_OVERLOAD, DHCP_OPTION_PAD, DHCP_OPTION_PARAMETER_REQUEST_LIST,
        DHCP_OPTION_PRIVATE_USE_END, DHCP_OPTION_PRIVATE_USE_START, DHCP_OPTION_REBINDING_TIME,
        DHCP_OPTION_RELAY_AGENT_INFORMATION, DHCP_OPTION_RENEWAL_TIME,
        DHCP_OPTION_REQUESTED_IP_ADDRESS, DHCP_OPTION_ROUTER, DHCP_OPTION_SERVER_IDENTIFIER,
        DHCP_OPTION_SUBNET_MASK, DHCP_OVERLOAD_BOTH, DHCP_OVERLOAD_FILE, DHCP_OVERLOAD_SNAME,
        DHCP_RELAY_FLAG_UNICAST, DHCP_RELAY_SUBOPTION_ACCESS_NETWORK_NAME,
        DHCP_RELAY_SUBOPTION_ACCESS_POINT_BSSID, DHCP_RELAY_SUBOPTION_ACCESS_POINT_NAME,
        DHCP_RELAY_SUBOPTION_ACCESS_TECHNOLOGY_TYPE, DHCP_RELAY_SUBOPTION_AUTHENTICATION,
        DHCP_RELAY_SUBOPTION_CIRCUIT_ID, DHCP_RELAY_SUBOPTION_DOCSIS_DEVICE_CLASS,
        DHCP_RELAY_SUBOPTION_LINK_SELECTION, DHCP_RELAY_SUBOPTION_OPERATOR_IDENTIFIER,
        DHCP_RELAY_SUBOPTION_OPERATOR_REALM, DHCP_RELAY_SUBOPTION_RADIUS_ATTRIBUTES,
        DHCP_RELAY_SUBOPTION_RELAY_AGENT_ID, DHCP_RELAY_SUBOPTION_RELAY_FLAGS,
        DHCP_RELAY_SUBOPTION_RELAY_SOURCE_PORT, DHCP_RELAY_SUBOPTION_REMOTE_ID,
        DHCP_RELAY_SUBOPTION_SERVER_ID_OVERRIDE, DHCP_RELAY_SUBOPTION_SUBSCRIBER_ID,
        DHCP_RELAY_SUBOPTION_VENDOR_SPECIFIC, DHCP_RELAY_SUBOPTION_VSS,
        DHCP_RELAY_SUBOPTION_VSS_CONTROL, DHCP_RELEASE, DHCP_REQUEST, DHCP_SERVER_PORT,
        DHCP_VSS_TYPE_GLOBAL_DEFAULT, DHCP_VSS_TYPE_NVT_ASCII, DHCP_VSS_TYPE_VPN_ID, DNS_CLASS_IN,
        DNS_FLAG_AUTHENTIC_DATA, DNS_FLAG_AUTHORITATIVE, DNS_FLAG_CHECKING_DISABLED,
        DNS_FLAG_QR_RESPONSE, DNS_FLAG_RECURSION_AVAILABLE, DNS_FLAG_RECURSION_DESIRED,
        DNS_FLAG_TRUNCATED, DNS_HEADER_LEN, DNS_PORT, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME,
        DNS_TYPE_MX, DNS_TYPE_NS, DNS_TYPE_PTR, DNS_TYPE_TXT, ETHERTYPE_ARP, ETHERTYPE_IPV4,
        ETHERTYPE_IPV6, ETHERTYPE_VLAN, ICMPV6_DESTINATION_UNREACHABLE, ICMPV6_ECHO_REPLY,
        ICMPV6_ECHO_REQUEST, ICMPV6_PACKET_TOO_BIG, ICMPV6_PARAMETER_PROBLEM, ICMPV6_TIME_EXCEEDED,
        ICMP_DESTINATION_UNREACHABLE, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST,
        ICMP_EXTENSION_CLASS_MPLS, ICMP_EXTENSION_CTYPE_MPLS_INCOMING, ICMP_PARAMETER_PROBLEM,
        ICMP_REDIRECT, ICMP_SOURCE_QUENCH, ICMP_TIME_EXCEEDED, IPPROTO_ICMP, IPPROTO_ICMPV6,
        IPPROTO_IPV6, IPPROTO_IPV6_DSTOPTS, IPPROTO_IPV6_FRAGMENT, IPPROTO_IPV6_HOPOPTS,
        IPPROTO_IPV6_ROUTE, IPPROTO_TCP, IPPROTO_UDP, IPV4_FLAG_DONT_FRAGMENT,
        IPV4_FLAG_MORE_FRAGMENTS, IPV4_FLAG_RESERVED, IPV4_OPTION_EOL,
        IPV4_OPTION_LOOSE_SOURCE_ROUTE, IPV4_OPTION_NOP, IPV4_OPTION_RECORD_ROUTE,
        IPV4_OPTION_STRICT_SOURCE_ROUTE, IPV4_OPTION_TRACEROUTE, IPV6_ROUTING_TYPE_MOBILE,
        IPV6_ROUTING_TYPE_SEGMENT, IPV6_SEGMENT_POLICY_EGRESS, IPV6_SEGMENT_POLICY_INGRESS,
        IPV6_SEGMENT_POLICY_SOURCE_ADDRESS, IPV6_SEGMENT_POLICY_UNSET,
        TCP_EDO_HEADER_AND_SEGMENT_LEN, TCP_EDO_HEADER_LEN, TCP_EDO_REQUEST_LEN, TCP_FLAG_ACK,
        TCP_FLAG_CWR, TCP_FLAG_ECE, TCP_FLAG_FIN, TCP_FLAG_NS, TCP_FLAG_PSH, TCP_FLAG_RST,
        TCP_FLAG_SYN, TCP_FLAG_URG, TCP_OPTION_EDO, TCP_OPTION_EOL, TCP_OPTION_FAST_OPEN,
        TCP_OPTION_MPTCP, TCP_OPTION_MSS, TCP_OPTION_NOP, TCP_OPTION_SACK,
        TCP_OPTION_SACK_PERMITTED, TCP_OPTION_TIMESTAMP, TCP_OPTION_WINDOW_SCALE,
    };
}

/// Common imports for generated packet tools and examples.
pub mod prelude {
    pub use crate::core::*;
    pub use crate::{
        default_interface, default_interface_in, default_interface_name, dump_pcap, find_interface,
        find_interface_in, get_ip_strings, get_ips, get_my_ip, get_my_ip_in, get_my_ipv6,
        get_my_ipv6_in, get_my_mac, get_my_mac_in, interface_for, interface_for_in, interfaces,
        parse_ip_range, parse_numbers, read_pcap, read_pcap_filtered, reply_filter, reply_matches,
        send_packet, send_packets, send_plan, send_recv_packet, send_recv_packets, BatchSend,
        BatchSendEntry, BatchSendRecv, BatchSendRecvEntry, BatchSendRecvReport, BatchSendReport,
        Capture, CaptureControl, CaptureHandle, FileSniffer, InterfaceAddress, InterfaceInfo,
        Ipv4Range, NetError, PacketBatchSendExt, PacketBatchSendRecvExt, PacketSendExt,
        PacketSendRecvExt, PcapError, PcapHeader, PcapLinkType, PcapPacket, PcapReader, PcapRecord,
        PcapRecords, PcapTimestamp, PcapWriter, PcapWriterOptions, RawSender, ReplyMatcher,
        SendMode, SendOptions, SendPlan, SendRecv, SendRecvOptions, SendRecvReport, SendReport,
        SendTarget, Sniffer, SocketSend, SocketSender, TimestampPrecision,
    };
}
