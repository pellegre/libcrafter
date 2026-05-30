#[macro_use]
mod support;

use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use crafter::core::{
    Arp, Dhcp, DhcpMessageType, DhcpOption, DhcpRelayAgentInfo, DhcpRelaySuboption, Dns, DnsRecord,
    DnsRecordData, EdnsOption, Ethernet, Icmp, IcmpKind, Icmpv6, Ipv4, Ipv4Option, Ipv6,
    Ipv6FragmentHeader, Layer, LinkType, LinuxSll, MacAddr, NetworkLayer, NullByteOrder,
    NullLoopback, OptionOverload, Packet, Raw, Tcp, TcpOption, TcpSackBlock, Udp,
    UdpChecksumStatus, UdpOption, UdpOptionStatus, UdpOptions, Vlan, ARP_HRD_INFINIBAND,
    BOOTP_REQUEST, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, DNS_CLASS_IN,
    DNS_EDNS_DEFAULT_UDP_PAYLOAD_SIZE, DNS_EDNS_OPTION_COOKIE, DNS_EDNS_OPTION_NSID,
    DNS_FLAG_AUTHORITATIVE, DNS_FLAG_QR_RESPONSE, DNS_FLAG_RECURSION_DESIRED, DNS_TYPE_A,
    DNS_TYPE_AAAA, DNS_TYPE_CNAME, DNS_TYPE_OPT, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_VLAN,
    ICMPV6_ECHO_REQUEST, ICMPV6_TIME_EXCEEDED, ICMP_DESTINATION_UNREACHABLE, ICMP_ECHO_REQUEST,
    IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IPV6_FRAGMENT, IPPROTO_TCP, IPPROTO_UDP, TCP_FLAG_ACK,
    TCP_FLAG_PSH, TCP_FLAG_SYN, UDP_HEADER_LEN, UDP_OPTION_EOL, UDP_OPTION_NOP,
};
use crafter::{PcapError, PcapLinkType, PcapReader, PcapTimestamp, TimestampPrecision};
use support::fixture_path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketDecodeTarget {
    Raw,
    Link(LinkType),
    L3(NetworkLayer),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureDecodeTarget {
    Packet(PacketDecodeTarget),
    DhcpOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureContents {
    Bytes(&'static [u8]),
    Hex(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedLayer {
    Ethernet,
    LinuxSll,
    NullLoopback,
    Vlan,
    Arp,
    Ipv4,
    Ipv6,
    Ipv6Fragment,
    Icmp,
    Icmpv6,
    Tcp,
    Udp,
    UdpOptions,
    Dns,
    Dhcp,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CoverageFamily {
    RawPayload,
    EthernetUnknownEthertype,
    EthernetArpRequest,
    EthernetArpReply,
    EthernetArpNonstandard,
    VlanIpv4Udp,
    LinuxSllArp,
    NullLoopbackIpv4,
    NullLoopbackIpv6,
    Ipv4IcmpEcho,
    Ipv4IcmpError,
    Ipv4Options,
    Ipv4TcpOptions,
    Ipv4UdpDnsQuery,
    Ipv4UdpDnsResponse,
    Ipv4UdpDhcp,
    Ipv4UdpOptions,
    Ipv6IcmpEcho,
    Ipv6IcmpError,
    Ipv6Udp,
    Ipv6UdpOptions,
    Ipv6Tcp,
    Ipv6ExtensionHeader,
    DhcpOptions,
    DhcpMessageTypes,
    DhcpRoutesDomains,
    DhcpClientIdentifier,
    DhcpAuthForcerenew,
    DhcpLeasequery,
    DhcpUnknownOptions,
    DhcpOptionOverload,
    DhcpLongOption,
    DhcpRelayOption82,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PcapCoverageFamily {
    Ethernet,
    RawIpIpv4,
    RawIpIpv6,
    LinuxSll,
    NullLoopback,
}

#[derive(Debug, Clone, Copy)]
struct ValidFixtureCase {
    name: &'static str,
    path: &'static str,
    contents: FixtureContents,
    target: FixtureDecodeTarget,
    expected_layers: &'static [ExpectedLayer],
    preserve_exact_bytes: bool,
    summary_path: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
struct PcapFixtureCase {
    name: &'static str,
    path: &'static str,
    contents: &'static [u8],
    pcap_link_type: PcapLinkType,
    link_type: LinkType,
    timestamp_precision: TimestampPrecision,
    coverage: PcapCoverageFamily,
    records: &'static [PcapFixtureRecord],
}

#[derive(Debug, Clone, Copy)]
struct PcapFixtureRecord {
    seconds: u64,
    fractional: u32,
    fixture_name: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MalformedFixtureRow {
    name: String,
    target: String,
    expected_kind: Option<String>,
    expected_context_or_field: Option<String>,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MalformedPcapRow {
    name: String,
    expected_kind: String,
    bytes: Vec<u8>,
}

const VALID_FIXTURES: &[ValidFixtureCase] = &[
    ValidFixtureCase {
        name: "raw-hello-agents",
        path: "bytes/raw-hello-agents.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/raw-hello-agents.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Raw),
        expected_layers: &[ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "arp-who-has",
        path: "bytes/arp-who-has.bin",
        contents: FixtureContents::Bytes(fixture_bytes!("bytes/arp-who-has.bin")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ethernet)),
        expected_layers: &[ExpectedLayer::Ethernet, ExpectedLayer::Arp],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ethernet-arp-reply",
        path: "bytes/ethernet-arp-reply.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ethernet-arp-reply.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ethernet)),
        expected_layers: &[ExpectedLayer::Ethernet, ExpectedLayer::Arp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ethernet-arp-reply.summary.txt"),
    },
    ValidFixtureCase {
        name: "ethernet-arp-infiniband-ipv6-nonstandard",
        path: "bytes/ethernet-arp-infiniband-ipv6-nonstandard.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ethernet-arp-infiniband-ipv6-nonstandard.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ethernet)),
        expected_layers: &[ExpectedLayer::Ethernet, ExpectedLayer::Arp],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-offer-options",
        path: "bytes/dhcp-offer-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-offer-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-discover-options",
        path: "bytes/dhcp-discover-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-discover-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-request-options",
        path: "bytes/dhcp-request-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-request-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-offer-extended-options",
        path: "bytes/dhcp-offer-extended-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-offer-extended-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-ack-options",
        path: "bytes/dhcp-ack-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-ack-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-nak-options",
        path: "bytes/dhcp-nak-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-nak-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-decline-options",
        path: "bytes/dhcp-decline-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-decline-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-release-options",
        path: "bytes/dhcp-release-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-release-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-inform-options",
        path: "bytes/dhcp-inform-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-inform-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-classless-static-routes-options",
        path: "bytes/dhcp-classless-static-routes-options.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/dhcp-classless-static-routes-options.hex"
        )),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-domain-search-options",
        path: "bytes/dhcp-domain-search-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-domain-search-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-client-id-rfc4361-options",
        path: "bytes/dhcp-client-id-rfc4361-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-client-id-rfc4361-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-authentication-options",
        path: "bytes/dhcp-authentication-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-authentication-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-forcerenew-options",
        path: "bytes/dhcp-forcerenew-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-forcerenew-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-leasequery-options",
        path: "bytes/dhcp-leasequery-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-leasequery-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-leasequery-status-options",
        path: "bytes/dhcp-leasequery-status-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-leasequery-status-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-unknown-private-options",
        path: "bytes/dhcp-unknown-private-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-unknown-private-options.hex")),
        target: FixtureDecodeTarget::DhcpOptions,
        expected_layers: &[],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-option-overload-file-sname",
        path: "bytes/dhcp-option-overload-file-sname.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-option-overload-file-sname.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Dhcp],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-rfc3396-long-option",
        path: "bytes/dhcp-rfc3396-long-option.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-rfc3396-long-option.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Dhcp],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dhcp-relay-option82",
        path: "bytes/dhcp-relay-option82.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/dhcp-relay-option82.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Dhcp],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "linux-sll-arp-who-has",
        path: "bytes/linux-sll-arp-who-has.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/linux-sll-arp-who-has.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::LinuxSll)),
        expected_layers: &[ExpectedLayer::LinuxSll, ExpectedLayer::Arp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/linux-sll-arp-who-has.summary.txt"),
    },
    ValidFixtureCase {
        name: "ethernet-experimental-raw",
        path: "bytes/ethernet-experimental-raw.bin",
        contents: FixtureContents::Bytes(fixture_bytes!("bytes/ethernet-experimental-raw.bin")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ethernet)),
        expected_layers: &[ExpectedLayer::Ethernet, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ethernet-vlan-ipv4-udp-raw",
        path: "bytes/ethernet-vlan-ipv4-udp-raw.bin",
        contents: FixtureContents::Bytes(fixture_bytes!("bytes/ethernet-vlan-ipv4-udp-raw.bin")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ethernet)),
        expected_layers: &[
            ExpectedLayer::Ethernet,
            ExpectedLayer::Vlan,
            ExpectedLayer::Ipv4,
            ExpectedLayer::Udp,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "null-loopback-ipv4-udp-raw",
        path: "bytes/null-loopback-ipv4-udp-raw.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/null-loopback-ipv4-udp-raw.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::NullLoopback)),
        expected_layers: &[
            ExpectedLayer::NullLoopback,
            ExpectedLayer::Ipv4,
            ExpectedLayer::Udp,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "null-loopback-ipv6-raw",
        path: "bytes/null-loopback-ipv6-raw.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/null-loopback-ipv6-raw.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::NullLoopback)),
        expected_layers: &[ExpectedLayer::NullLoopback, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-icmp-echo-request",
        path: "bytes/ipv4-icmp-echo-request.bin",
        contents: FixtureContents::Bytes(fixture_bytes!("bytes/ipv4-icmp-echo-request.bin")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Icmp, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-icmp-destination-unreachable",
        path: "bytes/ipv4-icmp-destination-unreachable.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-icmp-destination-unreachable.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Icmp, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-options-traceroute-udp-raw",
        path: "bytes/ipv4-options-traceroute-udp-raw.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-options-traceroute-udp-raw.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-tcp-syn-options",
        path: "bytes/ipv4-tcp-syn-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-tcp-syn-options.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Tcp, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-tcp-syn-options.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-udp-dns-query-example-com",
        path: "bytes/ipv4-udp-dns-query-example-com.bin",
        contents: FixtureContents::Bytes(fixture_bytes!(
            "bytes/ipv4-udp-dns-query-example-com.bin"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Dns],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-udp-dns-response-example-com",
        path: "bytes/ipv4-udp-dns-response-example-com.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-udp-dns-response-example-com.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Dns],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-udp-dns-response-example-com.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-udp-dhcp-discover",
        path: "bytes/ipv4-udp-dhcp-discover.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-udp-dhcp-discover.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Dhcp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-udp-dhcp-discover.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-udp-options-known",
        path: "bytes/ipv4-udp-options-known.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-udp-options-known.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[
            ExpectedLayer::Ipv4,
            ExpectedLayer::Udp,
            ExpectedLayer::Raw,
            ExpectedLayer::UdpOptions,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-udp-options-known.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-udp-options-unknown-safe",
        path: "bytes/ipv4-udp-options-unknown-safe.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-udp-options-unknown-safe.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[
            ExpectedLayer::Ipv4,
            ExpectedLayer::Udp,
            ExpectedLayer::Raw,
            ExpectedLayer::UdpOptions,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-udp-options-unknown-safe.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv6-icmp-echo-request",
        path: "bytes/ipv6-icmp-echo-request.bin",
        contents: FixtureContents::Bytes(fixture_bytes!("bytes/ipv6-icmp-echo-request.bin")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[
            ExpectedLayer::Ipv6,
            ExpectedLayer::Icmpv6,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv6-icmpv6-time-exceeded",
        path: "bytes/ipv6-icmpv6-time-exceeded.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv6-icmpv6-time-exceeded.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[
            ExpectedLayer::Ipv6,
            ExpectedLayer::Icmpv6,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv6-udp-raw",
        path: "bytes/ipv6-udp-raw.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv6-udp-raw.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[ExpectedLayer::Ipv6, ExpectedLayer::Udp, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv6-udp-options-unknown-unsafe",
        path: "bytes/ipv6-udp-options-unknown-unsafe.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv6-udp-options-unknown-unsafe.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[
            ExpectedLayer::Ipv6,
            ExpectedLayer::Udp,
            ExpectedLayer::Raw,
            ExpectedLayer::UdpOptions,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv6-udp-options-unknown-unsafe.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv6-udp-options-frag",
        path: "bytes/ipv6-udp-options-frag.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv6-udp-options-frag.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[
            ExpectedLayer::Ipv6,
            ExpectedLayer::Udp,
            ExpectedLayer::Raw,
            ExpectedLayer::UdpOptions,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv6-udp-options-frag.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv6-tcp-raw",
        path: "bytes/ipv6-tcp-raw.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv6-tcp-raw.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[ExpectedLayer::Ipv6, ExpectedLayer::Tcp, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv6-fragment-udp-raw",
        path: "bytes/ipv6-fragment-udp-raw.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv6-fragment-udp-raw.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[
            ExpectedLayer::Ipv6,
            ExpectedLayer::Ipv6Fragment,
            ExpectedLayer::Udp,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv6-fragment-udp-raw.summary.txt"),
    },
];

const PCAP_FIXTURES: &[PcapFixtureCase] = &[
    PcapFixtureCase {
        name: "ethernet-arp-request-reply",
        path: "pcaps/ethernet-arp-request-reply.pcap",
        contents: fixture_bytes!("pcaps/ethernet-arp-request-reply.pcap"),
        pcap_link_type: PcapLinkType::Ethernet,
        link_type: LinkType::Ethernet,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::Ethernet,
        records: &[
            PcapFixtureRecord {
                seconds: 10,
                fractional: 101,
                fixture_name: "arp-who-has",
            },
            PcapFixtureRecord {
                seconds: 10,
                fractional: 202,
                fixture_name: "ethernet-arp-reply",
            },
        ],
    },
    PcapFixtureCase {
        name: "ethernet-arp-nonstandard",
        path: "pcaps/ethernet-arp-nonstandard.pcap",
        contents: fixture_bytes!("pcaps/ethernet-arp-nonstandard.pcap"),
        pcap_link_type: PcapLinkType::Ethernet,
        link_type: LinkType::Ethernet,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::Ethernet,
        records: &[PcapFixtureRecord {
            seconds: 50,
            fractional: 5,
            fixture_name: "ethernet-arp-infiniband-ipv6-nonstandard",
        }],
    },
    PcapFixtureCase {
        name: "raw-ipv4-icmp-echo-request",
        path: "pcaps/raw-ipv4-icmp-echo-request.pcap",
        contents: fixture_bytes!("pcaps/raw-ipv4-icmp-echo-request.pcap"),
        pcap_link_type: PcapLinkType::RawIp,
        link_type: LinkType::Raw,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::RawIpIpv4,
        records: &[PcapFixtureRecord {
            seconds: 20,
            fractional: 1,
            fixture_name: "ipv4-icmp-echo-request",
        }],
    },
    PcapFixtureCase {
        name: "raw-ipv6-icmp-echo-request",
        path: "pcaps/raw-ipv6-icmp-echo-request.pcap",
        contents: fixture_bytes!("pcaps/raw-ipv6-icmp-echo-request.pcap"),
        pcap_link_type: PcapLinkType::RawIp,
        link_type: LinkType::Raw,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::RawIpIpv6,
        records: &[PcapFixtureRecord {
            seconds: 20,
            fractional: 2,
            fixture_name: "ipv6-icmp-echo-request",
        }],
    },
    PcapFixtureCase {
        name: "linux-sll-arp-who-has",
        path: "pcaps/linux-sll-arp-who-has.pcap",
        contents: fixture_bytes!("pcaps/linux-sll-arp-who-has.pcap"),
        pcap_link_type: PcapLinkType::LinuxSll,
        link_type: LinkType::LinuxSll,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::LinuxSll,
        records: &[PcapFixtureRecord {
            seconds: 30,
            fractional: 3,
            fixture_name: "linux-sll-arp-who-has",
        }],
    },
    PcapFixtureCase {
        name: "null-loopback-ipv4-udp-raw",
        path: "pcaps/null-loopback-ipv4-udp-raw.pcap",
        contents: fixture_bytes!("pcaps/null-loopback-ipv4-udp-raw.pcap"),
        pcap_link_type: PcapLinkType::NullLoopback,
        link_type: LinkType::NullLoopback,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::NullLoopback,
        records: &[PcapFixtureRecord {
            seconds: 40,
            fractional: 4,
            fixture_name: "null-loopback-ipv4-udp-raw",
        }],
    },
];

const REQUIRED_VALID_COVERAGE: &[(CoverageFamily, &str)] = &[
    (CoverageFamily::RawPayload, "raw payload decode"),
    (
        CoverageFamily::EthernetUnknownEthertype,
        "Ethernet unknown ethertype raw payload",
    ),
    (CoverageFamily::EthernetArpRequest, "Ethernet ARP request"),
    (CoverageFamily::EthernetArpReply, "Ethernet ARP reply"),
    (
        CoverageFamily::EthernetArpNonstandard,
        "Ethernet nonstandard ARP (variable address lengths, unknown codepoints)",
    ),
    (
        CoverageFamily::VlanIpv4Udp,
        "Ethernet VLAN IPv4 UDP payload",
    ),
    (CoverageFamily::LinuxSllArp, "Linux cooked ARP payload"),
    (
        CoverageFamily::NullLoopbackIpv4,
        "null loopback IPv4 payload",
    ),
    (
        CoverageFamily::NullLoopbackIpv6,
        "null loopback IPv6 payload",
    ),
    (CoverageFamily::Ipv4IcmpEcho, "IPv4 ICMP echo"),
    (CoverageFamily::Ipv4IcmpError, "IPv4 ICMP error message"),
    (
        CoverageFamily::Ipv4Options,
        "IPv4 route or traceroute options",
    ),
    (CoverageFamily::Ipv4TcpOptions, "IPv4 TCP SYN options"),
    (CoverageFamily::Ipv4UdpDnsQuery, "IPv4 UDP DNS query"),
    (CoverageFamily::Ipv4UdpDnsResponse, "IPv4 UDP DNS response"),
    (CoverageFamily::Ipv4UdpDhcp, "IPv4 UDP DHCP message"),
    (
        CoverageFamily::Ipv4UdpOptions,
        "IPv4 UDP options surplus decode",
    ),
    (CoverageFamily::Ipv6IcmpEcho, "IPv6 ICMPv6 echo"),
    (CoverageFamily::Ipv6IcmpError, "IPv6 ICMPv6 error message"),
    (CoverageFamily::Ipv6Udp, "IPv6 UDP payload"),
    (
        CoverageFamily::Ipv6UdpOptions,
        "IPv6 UDP options surplus decode",
    ),
    (CoverageFamily::Ipv6Tcp, "IPv6 TCP payload"),
    (
        CoverageFamily::Ipv6ExtensionHeader,
        "IPv6 extension header stack",
    ),
    (CoverageFamily::DhcpOptions, "DHCP option corpus"),
    (
        CoverageFamily::DhcpMessageTypes,
        "DHCP message type option corpus",
    ),
    (
        CoverageFamily::DhcpRoutesDomains,
        "DHCP classless route and domain search options",
    ),
    (
        CoverageFamily::DhcpClientIdentifier,
        "DHCP RFC 4361 client identifier option",
    ),
    (
        CoverageFamily::DhcpAuthForcerenew,
        "DHCP authentication and FORCERENEW options",
    ),
    (
        CoverageFamily::DhcpLeasequery,
        "DHCP leasequery and leasequery status options",
    ),
    (
        CoverageFamily::DhcpUnknownOptions,
        "DHCP unknown and private-use options",
    ),
    (
        CoverageFamily::DhcpOptionOverload,
        "DHCP option overload across file and sname",
    ),
    (
        CoverageFamily::DhcpLongOption,
        "DHCP RFC 3396 long option splitting",
    ),
    (
        CoverageFamily::DhcpRelayOption82,
        "DHCP relay agent option 82 with multiple suboptions",
    ),
];

const REQUIRED_PCAP_COVERAGE: &[(PcapCoverageFamily, &str)] = &[
    (PcapCoverageFamily::Ethernet, "Ethernet pcap link type"),
    (
        PcapCoverageFamily::RawIpIpv4,
        "RawIp pcap with IPv4 payload",
    ),
    (
        PcapCoverageFamily::RawIpIpv6,
        "RawIp pcap with IPv6 payload",
    ),
    (PcapCoverageFamily::LinuxSll, "Linux cooked pcap link type"),
    (
        PcapCoverageFamily::NullLoopback,
        "null loopback pcap link type",
    ),
];

fn coverage_for_case(name: &str) -> &'static [CoverageFamily] {
    match name {
        "raw-hello-agents" => &[CoverageFamily::RawPayload],
        "arp-who-has" => &[CoverageFamily::EthernetArpRequest],
        "ethernet-arp-reply" => &[CoverageFamily::EthernetArpReply],
        "ethernet-arp-infiniband-ipv6-nonstandard" => &[CoverageFamily::EthernetArpNonstandard],
        "dhcp-offer-options" => &[CoverageFamily::DhcpOptions],
        "dhcp-discover-options"
        | "dhcp-request-options"
        | "dhcp-offer-extended-options"
        | "dhcp-ack-options"
        | "dhcp-nak-options"
        | "dhcp-decline-options"
        | "dhcp-release-options"
        | "dhcp-inform-options" => &[CoverageFamily::DhcpMessageTypes],
        "dhcp-classless-static-routes-options" | "dhcp-domain-search-options" => {
            &[CoverageFamily::DhcpRoutesDomains]
        }
        "dhcp-client-id-rfc4361-options" => &[CoverageFamily::DhcpClientIdentifier],
        "dhcp-authentication-options" | "dhcp-forcerenew-options" => {
            &[CoverageFamily::DhcpAuthForcerenew]
        }
        "dhcp-leasequery-options" | "dhcp-leasequery-status-options" => {
            &[CoverageFamily::DhcpLeasequery]
        }
        "dhcp-unknown-private-options" => &[CoverageFamily::DhcpUnknownOptions],
        "dhcp-option-overload-file-sname" => &[CoverageFamily::DhcpOptionOverload],
        "dhcp-rfc3396-long-option" => &[CoverageFamily::DhcpLongOption],
        "dhcp-relay-option82" => &[CoverageFamily::DhcpRelayOption82],
        "ethernet-experimental-raw" => &[CoverageFamily::EthernetUnknownEthertype],
        "ethernet-vlan-ipv4-udp-raw" => &[CoverageFamily::VlanIpv4Udp],
        "linux-sll-arp-who-has" => &[CoverageFamily::LinuxSllArp],
        "null-loopback-ipv4-udp-raw" => &[CoverageFamily::NullLoopbackIpv4],
        "null-loopback-ipv6-raw" => &[CoverageFamily::NullLoopbackIpv6],
        "ipv4-icmp-echo-request" => &[CoverageFamily::Ipv4IcmpEcho],
        "ipv4-icmp-destination-unreachable" => &[CoverageFamily::Ipv4IcmpError],
        "ipv4-options-traceroute-udp-raw" => &[CoverageFamily::Ipv4Options],
        "ipv4-tcp-syn-options" => &[CoverageFamily::Ipv4TcpOptions],
        "ipv4-udp-dns-query-example-com" => &[CoverageFamily::Ipv4UdpDnsQuery],
        "ipv4-udp-dns-response-example-com" => &[CoverageFamily::Ipv4UdpDnsResponse],
        "ipv4-udp-dhcp-discover" => &[CoverageFamily::Ipv4UdpDhcp],
        "ipv4-udp-options-known" | "ipv4-udp-options-unknown-safe" => {
            &[CoverageFamily::Ipv4UdpOptions]
        }
        "ipv6-icmp-echo-request" => &[CoverageFamily::Ipv6IcmpEcho],
        "ipv6-icmpv6-time-exceeded" => &[CoverageFamily::Ipv6IcmpError],
        "ipv6-udp-raw" => &[CoverageFamily::Ipv6Udp],
        "ipv6-udp-options-unknown-unsafe" | "ipv6-udp-options-frag" => {
            &[CoverageFamily::Ipv6UdpOptions]
        }
        "ipv6-tcp-raw" => &[CoverageFamily::Ipv6Tcp],
        "ipv6-fragment-udp-raw" => &[CoverageFamily::Ipv6ExtensionHeader],
        other => panic!("fixture {other} has no coverage-family mapping"),
    }
}

fn fixture_bytes_for_case(case: &ValidFixtureCase) -> Vec<u8> {
    match case.contents {
        FixtureContents::Bytes(bytes) => bytes.to_vec(),
        FixtureContents::Hex(hex) => decode_hex(case.name, hex),
    }
}

fn valid_fixture_case(name: &str) -> &'static ValidFixtureCase {
    VALID_FIXTURES
        .iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("pcap fixture references unknown byte fixture {name}"))
}

fn packet_target_for_case(case: &ValidFixtureCase) -> PacketDecodeTarget {
    match case.target {
        FixtureDecodeTarget::Packet(target) => target,
        FixtureDecodeTarget::DhcpOptions => {
            panic!(
                "pcap fixture {} references DHCP option-only fixture",
                case.name
            )
        }
    }
}

fn decode_hex(label: &str, text: &str) -> Vec<u8> {
    let mut compact = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        for ch in line.chars().filter(|ch| !ch.is_whitespace()) {
            assert!(
                ch.is_ascii_hexdigit(),
                "hex fixture {label} contains non-hex character {ch:?}"
            );
            compact.push(ch);
        }
    }

    assert!(
        compact.len() % 2 == 0,
        "hex fixture {label} has an odd hex length"
    );

    compact
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = std::str::from_utf8(chunk)
                .unwrap_or_else(|_| panic!("hex fixture {label} contains non-UTF8 hex"));
            u8::from_str_radix(byte, 16)
                .unwrap_or_else(|_| panic!("hex fixture {label} has invalid hex byte {byte}"))
        })
        .collect()
}

fn decode_packet(target: PacketDecodeTarget, bytes: &[u8]) -> crafter::core::Result<Packet> {
    match target {
        PacketDecodeTarget::Raw => Packet::decode_raw(bytes),
        PacketDecodeTarget::Link(link_type) => Packet::decode_from_link(link_type, bytes),
        PacketDecodeTarget::L3(network_layer) => Packet::decode_from_l3(network_layer, bytes),
    }
}

fn assert_compile_decode_compile(
    case: &ValidFixtureCase,
    target: PacketDecodeTarget,
    packet: &Packet,
    fixture_bytes: &[u8],
) {
    let compiled = packet
        .compile()
        .unwrap_or_else(|err| panic!("fixture {} should compile: {err}", case.path));

    if case.preserve_exact_bytes {
        assert_eq!(
            compiled.as_bytes(),
            fixture_bytes,
            "fixture {} did not preserve original bytes after decode/compile",
            case.path
        );
    }

    let decoded_again = decode_packet(target, compiled.as_bytes()).unwrap_or_else(|err| {
        panic!(
            "fixture {} should decode after compile/decode/compile setup: {err}",
            case.path
        )
    });
    let recompiled = decoded_again
        .compile()
        .unwrap_or_else(|err| panic!("fixture {} should recompile: {err}", case.path));
    assert_eq!(
        recompiled.as_bytes(),
        compiled.as_bytes(),
        "fixture {} compile/decode/compile bytes changed",
        case.path
    );
}

fn assert_packet_surface(case: &ValidFixtureCase, packet: &Packet) {
    assert_expected_layers(case, packet);

    let summary = packet.summary();
    assert!(
        !summary.is_empty(),
        "fixture {} produced an empty summary",
        case.path
    );

    let show = packet.show();
    assert!(
        show.starts_with("Packet("),
        "fixture {} produced unexpected show output: {show}",
        case.path
    );

    if let Some(summary_path) = case.summary_path {
        let expected = read_summary_fixture(summary_path);
        assert_eq!(
            expected.trim_end(),
            summary.trim_end(),
            "fixture {} summary did not match {}",
            case.path,
            summary_path
        );
    }
}

fn assert_expected_layers(case: &ValidFixtureCase, packet: &Packet) {
    for expected in case.expected_layers {
        match expected {
            ExpectedLayer::Ethernet => {
                let _ = expect_layer::<Ethernet>(case, packet);
            }
            ExpectedLayer::LinuxSll => {
                let _ = expect_layer::<LinuxSll>(case, packet);
            }
            ExpectedLayer::NullLoopback => {
                let _ = expect_layer::<NullLoopback>(case, packet);
            }
            ExpectedLayer::Vlan => {
                let _ = expect_layer::<Vlan>(case, packet);
            }
            ExpectedLayer::Arp => {
                let _ = expect_layer::<Arp>(case, packet);
            }
            ExpectedLayer::Ipv4 => {
                let _ = expect_layer::<Ipv4>(case, packet);
            }
            ExpectedLayer::Ipv6 => {
                let _ = expect_layer::<Ipv6>(case, packet);
            }
            ExpectedLayer::Ipv6Fragment => {
                let _ = expect_layer::<Ipv6FragmentHeader>(case, packet);
            }
            ExpectedLayer::Icmp => {
                let _ = expect_layer::<Icmp>(case, packet);
            }
            ExpectedLayer::Icmpv6 => {
                let _ = expect_layer::<Icmpv6>(case, packet);
            }
            ExpectedLayer::Tcp => {
                let _ = expect_layer::<Tcp>(case, packet);
            }
            ExpectedLayer::Udp => {
                let _ = expect_layer::<Udp>(case, packet);
            }
            ExpectedLayer::UdpOptions => {
                let _ = expect_layer::<UdpOptions>(case, packet);
            }
            ExpectedLayer::Dns => {
                let _ = expect_layer::<Dns>(case, packet);
            }
            ExpectedLayer::Dhcp => {
                let _ = expect_layer::<Dhcp>(case, packet);
            }
            ExpectedLayer::Raw => {
                let _ = expect_layer::<Raw>(case, packet);
            }
        };
    }
}

fn expect_layer<'a, T>(case: &ValidFixtureCase, packet: &'a Packet) -> &'a T
where
    T: Layer,
{
    packet.layer::<T>().unwrap_or_else(|| {
        panic!(
            "fixture {} missing layer {}; actual stack: {}",
            case.path,
            std::any::type_name::<T>(),
            packet.summary()
        )
    })
}

fn assert_fixture_fields(case: &ValidFixtureCase, packet: &Packet) {
    match case.name {
        "arp-who-has" => {
            let ethernet = expect_layer::<Ethernet>(case, packet);
            assert_eq!(ethernet.destination(), Some(MacAddr::BROADCAST));
            assert_eq!(
                ethernet.source(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
            );
            assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_ARP));

            let arp = expect_layer::<Arp>(case, packet);
            assert_eq!(arp.opcode_value(), 1);
            assert_eq!(arp.sender_mac(), ethernet.source());
            assert_eq!(arp.sender_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
            assert_eq!(arp.target_mac(), Some(MacAddr::ZERO));
            assert_eq!(arp.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));
        }
        "raw-hello-agents" => {
            assert_eq!(
                expect_layer::<Raw>(case, packet).as_bytes(),
                b"Hello, agents!"
            );
        }
        "ethernet-arp-reply" => {
            let ethernet = expect_layer::<Ethernet>(case, packet);
            assert_eq!(
                ethernet.destination(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
            );
            assert_eq!(
                ethernet.source(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x02]))
            );
            assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_ARP));

            let arp = expect_layer::<Arp>(case, packet);
            assert_eq!(arp.opcode_value(), 2);
            assert_eq!(
                arp.sender_mac(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x02]))
            );
            assert_eq!(arp.sender_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));
            assert_eq!(
                arp.target_mac(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
            );
            assert_eq!(arp.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
        }
        "ethernet-arp-infiniband-ipv6-nonstandard" => {
            let ethernet = expect_layer::<Ethernet>(case, packet);
            assert_eq!(
                ethernet.source(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
            );
            assert_eq!(
                ethernet.destination(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x02]))
            );
            assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_ARP));

            let arp = expect_layer::<Arp>(case, packet);
            // Nonstandard codepoints stay raw/numeric and round-trip exactly.
            assert_eq!(arp.hardware_type_value(), ARP_HRD_INFINIBAND);
            assert_eq!(arp.protocol_type_value(), 0x86dd);
            assert_eq!(arp.hardware_len_value(), 8);
            assert_eq!(arp.protocol_len_value(), 16);
            assert_eq!(arp.opcode_value(), 1024);
            // Variable-length raw addresses are preserved byte-exact.
            assert_eq!(
                arp.sender_hardware_bytes_value(),
                vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x10, 0x11, 0x12]
            );
            assert_eq!(
                arp.sender_protocol_bytes_value(),
                vec![
                    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x10,
                ]
            );
            assert_eq!(
                arp.target_hardware_bytes_value(),
                vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x20, 0x21, 0x22]
            );
            assert_eq!(
                arp.target_protocol_bytes_value(),
                vec![
                    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x20,
                ]
            );
            // Typed views decline on nonstandard widths / unknown protocol type.
            assert_eq!(arp.sender_mac(), None);
            assert_eq!(arp.target_mac(), None);
            assert_eq!(arp.sender_ipv4(), None);
            assert_eq!(arp.target_ipv4(), None);
        }
        "linux-sll-arp-who-has" => {
            let linux_sll = expect_layer::<LinuxSll>(case, packet);
            assert_eq!(linux_sll.packet_type_value(), 0);
            assert_eq!(linux_sll.address_type_value(), 1);
            assert_eq!(linux_sll.address_len_value(), 6);
            assert_eq!(
                linux_sll.source_mac(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
            );
            assert_eq!(linux_sll.protocol_value(), ETHERTYPE_ARP);

            let arp = expect_layer::<Arp>(case, packet);
            assert_eq!(arp.opcode_value(), 1);
            assert_eq!(arp.sender_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
            assert_eq!(arp.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));
        }
        "ethernet-experimental-raw" => {
            let ethernet = expect_layer::<Ethernet>(case, packet);
            assert_eq!(
                ethernet.destination(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x02]))
            );
            assert_eq!(
                ethernet.source(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
            );
            assert_eq!(ethernet.ethertype_value(), Some(0x9000));
            assert_eq!(
                expect_layer::<Raw>(case, packet).as_bytes(),
                b"libcrafter-ethernet"
            );
        }
        "ethernet-vlan-ipv4-udp-raw" => {
            let ethernet = expect_layer::<Ethernet>(case, packet);
            assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_VLAN));

            let vlan = expect_layer::<Vlan>(case, packet);
            assert_eq!(vlan.pcp_value(), 3);
            assert!(!vlan.dei_value());
            assert_eq!(vlan.vlan_id_value(), 42);
            assert_eq!(vlan.ethertype_value(), ETHERTYPE_IPV4);

            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 20));
            assert_eq!(ipv4.ttl_value(), 58);
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 53_002);
            assert_eq!(udp.destination_port_value(), 9_999);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"vlan-udp");
        }
        "null-loopback-ipv4-udp-raw" => {
            let null = expect_layer::<NullLoopback>(case, packet);
            assert_eq!(null.family_value(), 2);
            assert_eq!(null.byte_order(), NullByteOrder::LittleEndian);

            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 20));
            assert_eq!(ipv4.identification_value(), 0x2250);
            assert_eq!(ipv4.ttl_value(), 44);
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 53_003);
            assert_eq!(udp.destination_port_value(), 10_000);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"null-v4");
        }
        "null-loopback-ipv6-raw" => {
            let null = expect_layer::<NullLoopback>(case, packet);
            assert_eq!(null.family_value(), 24);
            assert_eq!(null.byte_order(), NullByteOrder::LittleEndian);

            let raw = expect_layer::<Raw>(case, packet).as_bytes();
            assert_eq!(raw[0] >> 4, 6);
            assert!(raw.ends_with(b"null-v6"));
        }
        "ipv4-icmp-echo-request" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 20));
            assert_eq!(ipv4.identification_value(), 0x1234);
            assert!(ipv4.is_dont_fragment());
            assert_eq!(ipv4.protocol_value(), IPPROTO_ICMP);

            let icmp = expect_layer::<Icmp>(case, packet);
            assert_eq!(icmp.icmp_type_value(), ICMP_ECHO_REQUEST);
            assert_eq!(icmp.kind_value(), Some(IcmpKind::EchoRequest));
            assert_eq!(icmp.identifier_value(), Some(0x4242));
            assert_eq!(icmp.sequence_number_value(), Some(1));
            assert_eq!(
                expect_layer::<Raw>(case, packet).as_bytes(),
                b"libcrafter-icmp"
            );
        }
        "ipv4-icmp-destination-unreachable" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(198, 51, 100, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.identification_value(), 0x2255);
            assert_eq!(ipv4.protocol_value(), IPPROTO_ICMP);

            let icmp = expect_layer::<Icmp>(case, packet);
            assert_eq!(icmp.icmp_type_value(), ICMP_DESTINATION_UNREACHABLE);
            assert_eq!(icmp.kind_value(), Some(IcmpKind::DestinationUnreachable));
            assert_eq!(icmp.code_value(), 3);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"orig-v4");
        }
        "ipv4-options-traceroute-udp-raw" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 20));
            assert_eq!(ipv4.identification_value(), 0x2251);
            assert_eq!(ipv4.ttl_value(), 55);
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);
            assert_eq!(
                ipv4.parsed_options().unwrap_or_else(|err| {
                    panic!("fixture {} IPv4 options should parse: {err}", case.path)
                }),
                vec![
                    Ipv4Option::record_route(4, vec![Ipv4Addr::new(203, 0, 113, 1)]),
                    Ipv4Option::traceroute(0x1234, 1, 0xffff, Ipv4Addr::new(192, 0, 2, 10)),
                    Ipv4Option::EndOfList,
                ]
            );

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 53_005);
            assert_eq!(udp.destination_port_value(), 10_002);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"ip-options");
        }
        "ipv4-tcp-syn-options" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 20));
            assert_eq!(ipv4.identification_value(), 0x2252);
            assert_eq!(ipv4.protocol_value(), IPPROTO_TCP);

            let tcp = expect_layer::<Tcp>(case, packet);
            assert_eq!(tcp.source_port_value(), 44_444);
            assert_eq!(tcp.destination_port_value(), 443);
            assert_eq!(tcp.sequence_number_value(), 0x0102_0304);
            assert_eq!(tcp.flags_value(), TCP_FLAG_SYN);
            assert_eq!(
                tcp.parsed_options().unwrap_or_else(|err| {
                    panic!("fixture {} TCP options should parse: {err}", case.path)
                }),
                vec![
                    TcpOption::MaximumSegmentSize(1460),
                    TcpOption::WindowScale(7),
                    TcpOption::Timestamp {
                        value: 398_303_815,
                        echo_reply: 12_345,
                    },
                    TcpOption::SackPermitted,
                    TcpOption::Sack(vec![TcpSackBlock::new(10, 20)]),
                    TcpOption::EndOfList,
                ]
            );
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"syn-options");
        }
        "ipv4-udp-dns-query-example-com" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 53));
            assert_eq!(ipv4.ttl_value(), 61);
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 53_001);
            assert_eq!(udp.destination_port_value(), 53);

            let dns = expect_layer::<Dns>(case, packet);
            assert_eq!(dns.id_value(), 0xbeef);
            assert_eq!(dns.flags_value(), DNS_FLAG_RECURSION_DESIRED);
            assert!(!dns.is_response());
            assert_eq!(dns.questions().len(), 1);
            assert_eq!(dns.questions()[0].name(), "example.com.");
            assert_eq!(dns.questions()[0].question_type(), DNS_TYPE_A);
            assert_eq!(dns.questions()[0].question_class(), DNS_CLASS_IN);
        }
        "ipv4-udp-dns-response-example-com" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(198, 51, 100, 53));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.identification_value(), 0x2253);
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 53);
            assert_eq!(udp.destination_port_value(), 53_001);

            let dns = expect_layer::<Dns>(case, packet);
            assert_eq!(dns.id_value(), 0x1234);
            assert!(dns.is_response());
            assert_eq!(
                dns.flags_value() & (DNS_FLAG_QR_RESPONSE | DNS_FLAG_AUTHORITATIVE),
                DNS_FLAG_QR_RESPONSE | DNS_FLAG_AUTHORITATIVE
            );
            assert_eq!(dns.questions().len(), 1);
            assert_eq!(dns.questions()[0].name(), "example.com.");
            assert_eq!(dns.answers().len(), 3);
            assert_eq!(dns.answers()[0].record_type(), DNS_TYPE_A);
            assert_eq!(
                dns.answers()[0].data(),
                &DnsRecordData::A(Ipv4Addr::new(203, 0, 113, 10))
            );
            assert_eq!(dns.answers()[1].record_type(), DNS_TYPE_AAAA);
            assert_eq!(
                dns.answers()[1].data(),
                &DnsRecordData::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
            );
            assert_eq!(dns.answers()[2].record_type(), DNS_TYPE_CNAME);
            assert_eq!(
                dns.answers()[2].data(),
                &DnsRecordData::name("example.com.")
            );
        }
        "ipv4-udp-dhcp-discover" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::UNSPECIFIED);
            assert_eq!(ipv4.destination(), Ipv4Addr::BROADCAST);
            assert_eq!(ipv4.identification_value(), 0x2254);
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), DHCP_CLIENT_PORT);
            assert_eq!(udp.destination_port_value(), DHCP_SERVER_PORT);

            let dhcp = expect_layer::<Dhcp>(case, packet);
            assert_eq!(dhcp.op_value(), BOOTP_REQUEST);
            assert_eq!(
                dhcp.client_mac_value(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
            );
            assert_eq!(dhcp.transaction_id_value(), 0x3903_f326);
            assert_eq!(dhcp.flags_value(), 0x8000);
            assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Discover));
            assert_eq!(dhcp.host_name_value(), Some("agent"));
        }
        "ipv4-udp-options-known" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 31));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 31));
            assert_eq!(ipv4.identification_value(), 0x3101);
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 53_010);
            assert_eq!(udp.destination_port_value(), 10_010);
            assert_eq!(udp.length_value(), Some(12));
            assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"opts");

            let udp_options = expect_layer::<UdpOptions>(case, packet);
            assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
            assert_eq!(udp_options.option_checksum_value(), Some(0xc88a));
            assert_eq!(udp_options.alignment_bytes(), Some(&[][..]));
            assert_eq!(
                udp_options.options(),
                &[
                    UdpOption::additional_payload_checksum(0x1e38_cf62),
                    UdpOption::maximum_datagram_size(1500),
                    UdpOption::maximum_reassembled_datagram_size(9000, 32),
                    UdpOption::echo_request(0x0102_0304),
                    UdpOption::echo_response(0x0506_0708),
                    UdpOption::timestamp(0x1122_3344, 0x5566_7788),
                    UdpOption::experimental(0x1234, [0xaa, 0xbb]),
                    UdpOption::unsafe_experimental(0x5678, [0xcc]),
                    UdpOption::NoOperation,
                    UdpOption::EndOfList,
                ]
            );
        }
        "ipv4-udp-options-unknown-safe" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 32));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 32));
            assert_eq!(ipv4.identification_value(), 0x3102);
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 53_011);
            assert_eq!(udp.destination_port_value(), 10_011);
            assert_eq!(udp.length_value(), Some(12));
            assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"safe");

            let udp_options = expect_layer::<UdpOptions>(case, packet);
            assert_eq!(udp_options.status(), UdpOptionStatus::UnknownSafe);
            assert_eq!(udp_options.option_checksum_value(), Some(0x4af4));
            assert_eq!(udp_options.alignment_bytes(), Some(&[][..]));
            assert_eq!(
                udp_options.options(),
                &[
                    UdpOption::generic(10, [0xab]),
                    UdpOption::NoOperation,
                    UdpOption::EndOfList,
                ]
            );
        }
        "ipv6-icmp-echo-request" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0001, 0, 0, 0, 0, 0x0010)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0002, 0, 0, 0, 0, 0x0020)
            );
            assert_eq!(ipv6.flow_label_value(), 0x12345);
            assert_eq!(ipv6.next_header_value(), IPPROTO_ICMPV6);
            assert_eq!(ipv6.hop_limit_value(), 64);

            let icmpv6 = expect_layer::<Icmpv6>(case, packet);
            assert_eq!(icmpv6.icmp_type_value(), ICMPV6_ECHO_REQUEST);
            assert_eq!(icmpv6.kind_value(), Some(IcmpKind::EchoRequest));
            assert_eq!(icmpv6.identifier_value(), Some(0x4242));
            assert_eq!(icmpv6.sequence_number_value(), Some(2));
            assert_eq!(
                expect_layer::<Raw>(case, packet).as_bytes(),
                b"libcrafter-ipv6"
            );
        }
        "ipv6-icmpv6-time-exceeded" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0020, 0, 0, 0, 0, 0x0020)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0010, 0, 0, 0, 0, 0x0010)
            );
            assert_eq!(ipv6.next_header_value(), IPPROTO_ICMPV6);

            let icmpv6 = expect_layer::<Icmpv6>(case, packet);
            assert_eq!(icmpv6.icmp_type_value(), ICMPV6_TIME_EXCEEDED);
            assert_eq!(icmpv6.kind_value(), Some(IcmpKind::TimeExceeded));
            assert_eq!(icmpv6.code_value(), 0);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"orig-v6");
        }
        "ipv6-udp-raw" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0010, 0, 0, 0, 0, 0x0010)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0020, 0, 0, 0, 0, 0x0020)
            );
            assert_eq!(ipv6.flow_label_value(), 0x24680);
            assert_eq!(ipv6.next_header_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 53_006);
            assert_eq!(udp.destination_port_value(), 10_003);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"ipv6-udp");
        }
        "ipv6-udp-options-unknown-unsafe" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0031, 0, 0, 0, 0, 0x0031)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0032, 0, 0, 0, 0, 0x0032)
            );
            assert_eq!(ipv6.next_header_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 53_012);
            assert_eq!(udp.destination_port_value(), 10_012);
            assert_eq!(udp.length_value(), Some(12));
            assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"unus");

            let udp_options = expect_layer::<UdpOptions>(case, packet);
            assert_eq!(udp_options.status(), UdpOptionStatus::UnknownUnsafe);
            assert_eq!(udp_options.option_checksum_value(), Some(0x70f6));
            assert_eq!(udp_options.alignment_bytes(), Some(&[][..]));
            assert_eq!(udp_options.options(), &[UdpOption::generic(194, [0xcd])]);
        }
        "ipv6-udp-options-frag" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0031, 0, 0, 0, 0, 0x0031)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0033, 0, 0, 0, 0, 0x0033)
            );
            assert_eq!(ipv6.next_header_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 53_013);
            assert_eq!(udp.destination_port_value(), 10_013);
            assert_eq!(udp.length_value(), Some(12));
            assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"frag");

            let udp_options = expect_layer::<UdpOptions>(case, packet);
            assert_eq!(
                udp_options.status(),
                UdpOptionStatus::UnsupportedFragmentation
            );
            assert_eq!(udp_options.option_checksum_value(), Some(0xf8e2));
            assert_eq!(udp_options.alignment_bytes(), Some(&[][..]));
            assert_eq!(
                udp_options.options(),
                &[UdpOption::generic(3, [1, 2, 3, 4, 0, 0, 0, 1])]
            );
        }
        "ipv6-tcp-raw" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0020, 0, 0, 0, 0, 0x0020)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0010, 0, 0, 0, 0, 0x0010)
            );
            assert_eq!(ipv6.traffic_class_value(), 0x22);
            assert_eq!(ipv6.flow_label_value(), 0x13579);
            assert_eq!(ipv6.next_header_value(), IPPROTO_TCP);

            let tcp = expect_layer::<Tcp>(case, packet);
            assert_eq!(tcp.source_port_value(), 443);
            assert_eq!(tcp.destination_port_value(), 49_152);
            assert_eq!(tcp.sequence_number_value(), 0x1020_3040);
            assert_eq!(tcp.acknowledgment_number_value(), 0x5060_7080);
            assert_eq!(tcp.flags_value(), TCP_FLAG_ACK | TCP_FLAG_PSH);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"ipv6-tcp");
        }
        "ipv6-fragment-udp-raw" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0010, 0, 0, 0, 0, 0x0010)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0020, 0, 0, 0, 0, 0x0020)
            );
            assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_FRAGMENT);

            let fragment = expect_layer::<Ipv6FragmentHeader>(case, packet);
            assert_eq!(fragment.next_header_value(), IPPROTO_UDP);
            assert_eq!(fragment.fragment_offset_value(), 0);
            assert!(fragment.has_more_fragments());
            assert_eq!(fragment.identification_value(), 0x0102_0304);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 1234);
            assert_eq!(udp.destination_port_value(), 5678);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"frag-v6");
        }
        "dhcp-option-overload-file-sname" => {
            let dhcp = expect_layer::<Dhcp>(case, packet);
            assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Discover));
            assert_eq!(dhcp.transaction_id_value(), 0x0102_0304);
            assert_eq!(dhcp.option_overload(), Some(OptionOverload::Both));
            assert!(dhcp.file_is_overloaded());
            assert!(dhcp.sname_is_overloaded());
            assert_eq!(
                dhcp.file_options_value(),
                &[
                    DhcpOption::bootfile_name(b"boot/pxelinux.0".to_vec()),
                    DhcpOption::End,
                ],
                "overloaded file area must surface the bootfile-name option"
            );
            assert_eq!(
                dhcp.sname_options_value(),
                &[
                    DhcpOption::HostName("oracle-server".to_string()),
                    DhcpOption::End,
                ],
                "overloaded sname area must surface the host-name option"
            );
        }
        "dhcp-rfc3396-long-option" => {
            let dhcp = expect_layer::<Dhcp>(case, packet);
            assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Discover));
            assert_eq!(dhcp.transaction_id_value(), 0x1111_2222);
            let expected_domain = format!("{}.example", "a".repeat(300));
            let concatenated = dhcp
                .concatenated_option(15)
                .expect("rfc3396 domain-name option must be present")
                .unwrap_or_else(|err| {
                    panic!("fixture {} rfc3396 option should decode: {err}", case.path)
                });
            let payload = concatenated
                .payload()
                .unwrap_or_else(|err| panic!("rfc3396 payload should encode: {err}"));
            assert_eq!(payload, expected_domain.as_bytes());
            assert!(
                payload.len() > 255,
                "rfc3396 fixture must exceed a single 255-octet option instance"
            );
        }
        "dhcp-relay-option82" => {
            let dhcp = expect_layer::<Dhcp>(case, packet);
            assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Discover));
            assert_eq!(dhcp.transaction_id_value(), 0x3333_4444);
            let info = dhcp
                .relay_agent_information()
                .expect("relay agent option 82 must be present")
                .unwrap_or_else(|err| {
                    panic!("fixture {} relay option 82 should decode: {err}", case.path)
                });
            assert_eq!(
                info,
                DhcpRelayAgentInfo::new(vec![
                    DhcpRelaySuboption::circuit_id(b"eth0:vlan100".to_vec()),
                    DhcpRelaySuboption::remote_id(vec![0x02, 0x00, 0x5e, 0x00, 0x53, 0xff]),
                ])
            );
        }
        other => panic!("fixture {other} is missing typed field assertions"),
    }
}

fn assert_dhcp_option_fixture(case: &ValidFixtureCase, bytes: &[u8]) {
    let options = DhcpOption::decode_all(bytes)
        .unwrap_or_else(|err| panic!("fixture {} should decode DHCP options: {err}", case.path));
    assert_eq!(
        options,
        expected_dhcp_options(case.name),
        "fixture {} decoded an unexpected DHCP option list",
        case.path
    );

    if case.preserve_exact_bytes {
        let reencoded = encode_dhcp_options(&options);
        assert_eq!(
            reencoded, bytes,
            "fixture {} did not preserve DHCP option bytes",
            case.path
        );
    }
}

fn expected_dhcp_options(name: &str) -> Vec<DhcpOption> {
    match name {
        "dhcp-offer-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::Offer),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 0, 2, 1)),
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::Router(vec![Ipv4Addr::new(192, 0, 2, 1)]),
            DhcpOption::DomainNameServer(vec![
                Ipv4Addr::new(192, 0, 2, 53),
                Ipv4Addr::new(198, 51, 100, 53),
            ]),
            DhcpOption::IpAddressLeaseTime(3_600),
            DhcpOption::End,
        ],
        "dhcp-discover-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::Discover),
            DhcpOption::ParameterRequestList(vec![1, 3, 6, 15, 51, 54]),
            DhcpOption::HostName("agent".to_string()),
            DhcpOption::End,
        ],
        "dhcp-request-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::Request),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 0, 2, 100)),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 0, 2, 1)),
            DhcpOption::ParameterRequestList(vec![1, 3, 6, 15]),
            DhcpOption::End,
        ],
        "dhcp-offer-extended-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::Offer),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 0, 2, 1)),
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::Router(vec![Ipv4Addr::new(192, 0, 2, 1)]),
            DhcpOption::DomainNameServer(vec![
                Ipv4Addr::new(192, 0, 2, 53),
                Ipv4Addr::new(198, 51, 100, 53),
            ]),
            DhcpOption::IpAddressLeaseTime(3_600),
            DhcpOption::RenewalTime(1_800),
            DhcpOption::RebindingTime(3_150),
            DhcpOption::End,
        ],
        "dhcp-ack-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::Ack),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 0, 2, 1)),
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::IpAddressLeaseTime(3_600),
            DhcpOption::End,
        ],
        "dhcp-nak-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::Nak),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 0, 2, 1)),
            DhcpOption::End,
        ],
        "dhcp-decline-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::Decline),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 0, 2, 100)),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 0, 2, 1)),
            DhcpOption::End,
        ],
        "dhcp-release-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::Release),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 0, 2, 1)),
            DhcpOption::End,
        ],
        "dhcp-inform-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::Inform),
            DhcpOption::ParameterRequestList(vec![1, 3, 6, 15]),
            DhcpOption::End,
        ],
        // Classless static routes (option 121) and domain search (option 119)
        // are preserved as raw Generic options by the legacy DhcpOption decoder;
        // the typed views are asserted via the Dhcp-layer frame fixtures.
        "dhcp-classless-static-routes-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::Ack),
            DhcpOption::generic(
                121,
                vec![24, 192, 0, 2, 198, 51, 100, 1, 0, 198, 51, 100, 254],
            ),
            DhcpOption::End,
        ],
        "dhcp-domain-search-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::Ack),
            DhcpOption::generic(
                119,
                vec![
                    7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 3, 101, 110, 103, 7,
                    101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0,
                ],
            ),
            DhcpOption::End,
        ],
        "dhcp-client-id-rfc4361-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::Discover),
            DhcpOption::ClientIdentifier(vec![255, 10, 11, 12, 13, 0, 1, 2, 3]),
            DhcpOption::End,
        ],
        "dhcp-authentication-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::Request),
            DhcpOption::generic(
                90,
                vec![
                    1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 2, 171, 171, 171, 171, 171, 171, 171, 171, 171,
                    171, 171, 171, 171, 171, 171, 171,
                ],
            ),
            DhcpOption::End,
        ],
        "dhcp-forcerenew-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::Discover),
            DhcpOption::generic(145, vec![1]),
            DhcpOption::End,
        ],
        "dhcp-leasequery-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::LeaseQuery),
            DhcpOption::generic(92, vec![192, 0, 2, 100, 192, 0, 2, 101]),
            DhcpOption::End,
        ],
        "dhcp-leasequery-status-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::LeaseUnknown),
            DhcpOption::generic(151, vec![0, 111, 107]),
            DhcpOption::generic(156, vec![2]),
            DhcpOption::End,
        ],
        "dhcp-unknown-private-options" => vec![
            DhcpOption::MessageType(DhcpMessageType::Discover),
            DhcpOption::generic(224, vec![0xde, 0xad, 0xbe, 0xef]),
            DhcpOption::generic(250, vec![0x01, 0x02, 0x03]),
            DhcpOption::End,
        ],
        other => panic!("DHCP option fixture {other} has no expected option list"),
    }
}

fn encode_dhcp_options(options: &[DhcpOption]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for option in options {
        encoded.extend(
            option
                .encode()
                .unwrap_or_else(|err| panic!("DHCP option should re-encode: {err}")),
        );
    }
    encoded
}

fn read_summary_fixture(path: &str) -> String {
    fs::read_to_string(fixture_path(path))
        .unwrap_or_else(|err| panic!("summary fixture {path} should be readable: {err}"))
}

fn parse_malformed_rows(path: &str) -> Vec<MalformedFixtureRow> {
    fixture_str!("malformed/core-decode-corpus.hex")
        .lines()
        .filter_map(|line| parse_malformed_row(path, line))
        .collect()
}

fn parse_malformed_row(path: &str, line: &str) -> Option<MalformedFixtureRow> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let fields = line.split('|').collect::<Vec<_>>();
    let (name, target, expected_kind, expected_context_or_field, hex) = match fields.as_slice() {
        [name, target, hex] => (*name, *target, None, None, *hex),
        [name, target, expected_kind, expected_context_or_field, hex] => (
            *name,
            *target,
            Some((*expected_kind).to_string()),
            Some((*expected_context_or_field).to_string()),
            *hex,
        ),
        _ => panic!(
            "malformed fixture {path} row {line:?} must have either 3 or 5 pipe-separated fields"
        ),
    };

    Some(MalformedFixtureRow {
        name: name.to_string(),
        target: target.to_string(),
        expected_kind,
        expected_context_or_field,
        bytes: decode_hex(name, hex),
    })
}

fn parse_malformed_pcap_rows(path: &str) -> Vec<MalformedPcapRow> {
    fixture_str!("malformed/pcap-corpus.hex")
        .lines()
        .filter_map(|line| parse_malformed_pcap_row(path, line))
        .collect()
}

fn parse_malformed_pcap_row(path: &str, line: &str) -> Option<MalformedPcapRow> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let fields = line.split('|').collect::<Vec<_>>();
    let [name, expected_kind, hex] = fields.as_slice() else {
        panic!("malformed pcap fixture {path} row {line:?} must have 3 pipe-separated fields");
    };

    Some(MalformedPcapRow {
        name: (*name).to_string(),
        expected_kind: (*expected_kind).to_string(),
        bytes: decode_hex(name, hex),
    })
}

fn assert_pcap_error_kind(row: &MalformedPcapRow, err: PcapError) {
    match (row.expected_kind.as_str(), err) {
        ("invalid-header", PcapError::InvalidHeader(_)) => {}
        ("invalid-record", PcapError::InvalidRecord(_)) => {}
        (expected, actual) => panic!(
            "malformed pcap fixture {} expected {expected}, got {actual:?}",
            row.name
        ),
    }
}

fn ensure_fixture_exists(path: &str) {
    let full_path = fixture_path(path);
    assert!(
        full_path.is_file(),
        "catalog fixture {path} must exist at {}",
        full_path.display()
    );
}

fn fixture_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();

    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(&path).unwrap_or_else(|err| {
            panic!(
                "fixture directory {} should be readable: {err}",
                path.display()
            )
        }) {
            let entry = entry.unwrap_or_else(|err| {
                panic!(
                    "fixture directory {} contained unreadable entry: {err}",
                    path.display()
                )
            });
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }

    files.sort();
    files
}

fn assert_fixture_filename_convention(relative: &Path) {
    let relative_str = relative
        .to_str()
        .unwrap_or_else(|| panic!("fixture path {relative:?} should be UTF-8"));
    if relative_str == "README.md"
        || relative.file_name().and_then(|name| name.to_str()) == Some(".gitkeep")
    {
        return;
    }

    let category = relative
        .components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
        .unwrap_or_else(|| panic!("fixture path {relative_str} must have a category"));
    let file_name = relative
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_else(|| panic!("fixture path {relative_str} must have a UTF-8 file name"));

    let base_name = match category {
        "bytes" => strip_allowed_suffix(file_name, &[".bin", ".hex"]),
        "malformed" => strip_allowed_suffix(file_name, &[".bin", ".hex"]),
        "pcaps" => strip_allowed_suffix(file_name, &[".pcap", ".pcapng"]),
        "summaries" => strip_allowed_suffix(file_name, &[".summary.txt", ".summary.json"]),
        _ => panic!("fixture path {relative_str} uses unknown category {category}"),
    };

    assert_lower_dash_name(base_name, relative_str);
}

fn strip_allowed_suffix<'a>(file_name: &'a str, suffixes: &[&str]) -> &'a str {
    suffixes
        .iter()
        .find_map(|suffix| file_name.strip_suffix(suffix))
        .unwrap_or_else(|| panic!("fixture file {file_name} uses an unsupported extension"))
}

fn assert_lower_dash_name(name: &str, label: &str) {
    assert!(!name.is_empty(), "fixture {label} has an empty base name");
    assert!(
        !name.starts_with('-') && !name.ends_with('-') && !name.contains("--"),
        "fixture {label} should use dash-separated name segments"
    );
    assert!(
        name.chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-'),
        "fixture {label} should use lowercase dash-separated ASCII names"
    );
}

#[test]
fn valid_fixture_catalog_covers_supported_protocols() {
    let covered = VALID_FIXTURES
        .iter()
        .flat_map(|case| coverage_for_case(case.name).iter().copied())
        .collect::<HashSet<_>>();

    for (required, label) in REQUIRED_VALID_COVERAGE {
        assert!(
            covered.contains(required),
            "valid fixture catalog is missing required coverage for {label}"
        );
    }
}

#[test]
fn valid_byte_fixtures_decode_compile_and_summarize() {
    for case in VALID_FIXTURES {
        ensure_fixture_exists(case.path);
        let bytes = fixture_bytes_for_case(case);

        match case.target {
            FixtureDecodeTarget::Packet(target) => {
                let packet = decode_packet(target, &bytes)
                    .unwrap_or_else(|err| panic!("fixture {} should decode: {err}", case.path));
                assert_packet_surface(case, &packet);
                assert_fixture_fields(case, &packet);
                assert_compile_decode_compile(case, target, &packet, &bytes);
            }
            FixtureDecodeTarget::DhcpOptions => assert_dhcp_option_fixture(case, &bytes),
        }
    }
}

#[test]
fn udp_options_fixture_corpus_decodes_compile_and_summarizes() {
    let udp_options_cases = VALID_FIXTURES
        .iter()
        .filter(|case| {
            coverage_for_case(case.name).iter().any(|coverage| {
                matches!(
                    coverage,
                    CoverageFamily::Ipv4UdpOptions | CoverageFamily::Ipv6UdpOptions
                )
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(udp_options_cases.len(), 4);

    for case in udp_options_cases {
        ensure_fixture_exists(case.path);
        let bytes = fixture_bytes_for_case(case);
        let target = packet_target_for_case(case);
        let packet = decode_packet(target, &bytes)
            .unwrap_or_else(|err| panic!("fixture {} should decode: {err}", case.path));
        assert_packet_surface(case, &packet);
        assert_fixture_fields(case, &packet);
        assert_compile_decode_compile(case, target, &packet, &bytes);
    }
}

#[test]
fn ipv4_udp_dns_decode_keeps_surplus_options_out_of_application_payload() {
    let dns = Dns::a_query("example.com").id(0xbeef);
    let dns_len = dns.encoded_len();
    let option_bytes = [UDP_OPTION_NOP, UDP_OPTION_EOL];
    let bytes = (Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 53))
        .id(0x3326)
        / Udp::new().sport(53_001).dport(53)
        / dns
        / UdpOptions::from_bytes(option_bytes))
    .compile()
    .unwrap();

    assert_eq!(
        &bytes.as_bytes()[24..26],
        &((UDP_HEADER_LEN + dns_len) as u16).to_be_bytes()
    );

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let dns = decoded.layer::<Dns>().unwrap();
    assert_eq!(dns.id_value(), 0xbeef);
    assert_eq!(dns.questions().len(), 1);
    assert_eq!(dns.questions()[0].name(), "example.com.");
    assert_eq!(dns.questions()[0].question_type(), DNS_TYPE_A);
    assert!(decoded.layers::<Raw>().next().is_none());

    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(udp_options.as_bytes(), &option_bytes);
    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn ipv4_udp_dhcp_decode_keeps_surplus_options_out_of_application_payload() {
    let client_mac = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
    let dhcp = Dhcp::discover(client_mac)
        .transaction_id(0x3903_f326)
        .flags(0x8000)
        .host_name("agent");
    let dhcp_len = dhcp.encoded_len();
    let option_bytes = [UDP_OPTION_NOP, UDP_OPTION_EOL];
    let bytes = (Ipv4::new()
        .src(Ipv4Addr::UNSPECIFIED)
        .dst(Ipv4Addr::BROADCAST)
        .id(0x3327)
        / Udp::dhcp_client()
        / dhcp
        / UdpOptions::from_bytes(option_bytes))
    .compile()
    .unwrap();

    assert_eq!(
        &bytes.as_bytes()[24..26],
        &((UDP_HEADER_LEN + dhcp_len) as u16).to_be_bytes()
    );

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let dhcp = decoded.layer::<Dhcp>().unwrap();
    assert_eq!(dhcp.transaction_id_value(), 0x3903_f326);
    assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Discover));
    assert_eq!(dhcp.host_name_value(), Some("agent"));
    assert!(decoded.layers::<Raw>().next().is_none());

    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(udp_options.as_bytes(), &option_bytes);
    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn pcap_fixture_corpus_decodes_supported_link_types() {
    let covered = PCAP_FIXTURES
        .iter()
        .map(|case| case.coverage)
        .collect::<HashSet<_>>();
    for (required, label) in REQUIRED_PCAP_COVERAGE {
        assert!(
            covered.contains(required),
            "pcap fixture catalog is missing required coverage for {label}"
        );
    }

    let pcap_root = fixture_path("pcaps");
    let catalog_paths = PCAP_FIXTURES
        .iter()
        .map(|case| case.path)
        .collect::<HashSet<_>>();
    let mut pcap_fixture_paths = HashSet::new();
    for file in fixture_files(&pcap_root) {
        let relative = file.strip_prefix(fixture_path("")).unwrap_or_else(|err| {
            panic!(
                "pcap fixture path {} should be under fixture root: {err}",
                file.display()
            )
        });
        let is_gitkeep = relative.file_name().and_then(|name| name.to_str()) == Some(".gitkeep");
        if !is_gitkeep {
            let path = relative
                .to_str()
                .unwrap_or_else(|| panic!("fixture path {relative:?} should be UTF-8"));
            pcap_fixture_paths.insert(path.to_string());
        }
    }

    for case in PCAP_FIXTURES {
        assert_lower_dash_name(case.name, case.name);
        ensure_fixture_exists(case.path);
        assert!(
            pcap_fixture_paths.contains(case.path),
            "pcap catalog entry {} must live under the fixture pcaps/ directory",
            case.path
        );

        let reader = PcapReader::from_reader(case.contents)
            .unwrap_or_else(|err| panic!("pcap fixture {} should parse header: {err}", case.path));
        assert_eq!(reader.pcap_link_type(), case.pcap_link_type);
        assert_eq!(reader.link_type(), case.link_type);
        assert_eq!(reader.header().pcap_link_type(), case.pcap_link_type);
        assert_eq!(reader.header().link_type(), case.link_type);
        assert_eq!(reader.header().precision(), case.timestamp_precision);
        assert!(reader.header().snaplen() >= 64);

        let records = reader
            .collect_records()
            .unwrap_or_else(|err| panic!("pcap fixture {} should read records: {err}", case.path));
        assert_eq!(
            records.len(),
            case.records.len(),
            "pcap fixture {} record count changed",
            case.path
        );

        let packets = PcapReader::from_reader(case.contents)
            .unwrap_or_else(|err| {
                panic!(
                    "pcap fixture {} should parse header twice: {err}",
                    case.path
                )
            })
            .collect_packets()
            .unwrap_or_else(|err| {
                panic!("pcap fixture {} should decode packets: {err}", case.path)
            });
        assert_eq!(packets.len(), records.len());

        for ((record, packet), expected) in records.iter().zip(packets.iter()).zip(case.records) {
            let expected_fixture = valid_fixture_case(expected.fixture_name);
            let expected_bytes = fixture_bytes_for_case(expected_fixture);
            let expected_timestamp = PcapTimestamp::new(
                expected.seconds,
                expected.fractional,
                case.timestamp_precision,
            )
            .unwrap_or_else(|err| {
                panic!(
                    "pcap fixture {} timestamp should be valid: {err}",
                    case.path
                )
            });

            assert_eq!(record.timestamp(), expected_timestamp);
            assert_eq!(record.pcap_link_type(), case.pcap_link_type);
            assert_eq!(record.link_type(), case.link_type);
            assert_eq!(record.captured_len(), expected_bytes.len() as u32);
            assert_eq!(record.original_len(), expected_bytes.len() as u32);
            assert_eq!(record.data(), expected_bytes.as_slice());

            assert_eq!(packet.timestamp(), expected_timestamp);
            assert_eq!(packet.original_len(), expected_bytes.len() as u32);
            assert_eq!(packet.pcap_link_type(), case.pcap_link_type);
            assert_eq!(packet.link_type(), case.link_type);

            assert_packet_surface(expected_fixture, packet.packet());
            assert_fixture_fields(expected_fixture, packet.packet());
            assert_compile_decode_compile(
                expected_fixture,
                packet_target_for_case(expected_fixture),
                packet.packet(),
                &expected_bytes,
            );
        }
    }

    for path in pcap_fixture_paths {
        assert!(
            catalog_paths.contains(path.as_str()),
            "pcap fixture {path} must be listed in PCAP_FIXTURES"
        );
    }
}

#[test]
fn fixture_tree_hygiene_matches_readme_conventions() {
    let root = fixture_path("");
    let catalog_paths = VALID_FIXTURES
        .iter()
        .map(|case| case.path)
        .collect::<HashSet<_>>();
    let mut bytes_fixture_paths = HashSet::new();

    for file in fixture_files(&root) {
        let relative = file.strip_prefix(&root).unwrap_or_else(|err| {
            panic!(
                "fixture path {} should be under root: {err}",
                file.display()
            )
        });
        assert_fixture_filename_convention(relative);

        let is_gitkeep = relative.file_name().and_then(|name| name.to_str()) == Some(".gitkeep");
        if !is_gitkeep
            && relative
                .components()
                .next()
                .and_then(|component| component.as_os_str().to_str())
                == Some("bytes")
        {
            let path = relative
                .to_str()
                .unwrap_or_else(|| panic!("fixture path {relative:?} should be UTF-8"));
            bytes_fixture_paths.insert(path.to_string());
        }
    }

    for case in VALID_FIXTURES {
        ensure_fixture_exists(case.path);
        assert!(
            bytes_fixture_paths.contains(case.path),
            "catalog entry {} must live under the fixture bytes/ directory",
            case.path
        );
    }

    for path in bytes_fixture_paths {
        assert!(
            catalog_paths.contains(path.as_str()),
            "bytes fixture {path} must be listed in VALID_FIXTURES"
        );
    }
}

#[test]
fn malformed_corpus_rows_are_well_formed() {
    let rows = parse_malformed_rows("malformed/core-decode-corpus.hex");
    assert!(!rows.is_empty(), "malformed corpus must not be empty");

    let valid_targets = HashSet::from([
        "dhcp",
        "dhcp-options",
        "dns-name",
        "ethernet",
        "ipv4",
        "ipv4-options",
        "ipv6",
        "linux-sll",
        "null-loopback",
        "tcp-options",
    ]);

    for row in rows {
        assert_lower_dash_name(&row.name, &row.name);
        assert!(
            valid_targets.contains(row.target.as_str()),
            "malformed fixture {} has unknown target {}",
            row.name,
            row.target
        );
        assert!(
            !row.bytes.is_empty(),
            "malformed fixture {} should carry input bytes",
            row.name
        );
        if let Some(expected_kind) = &row.expected_kind {
            assert_lower_dash_name(expected_kind, &row.name);
        }
    }
}

#[test]
fn malformed_pcap_fixtures_report_structured_errors() {
    let rows = parse_malformed_pcap_rows("malformed/pcap-corpus.hex");
    assert!(!rows.is_empty(), "malformed pcap corpus must not be empty");

    let required_rows = HashSet::from([
        "unknown-magic",
        "unsupported-major-version",
        "zero-snapshot-length",
        "partial-record-header",
        "captured-length-greater-than-snapshot",
        "truncated-record-body",
    ]);
    let valid_error_kinds = HashSet::from(["invalid-header", "invalid-record"]);
    let mut covered_rows = HashSet::new();

    for row in rows {
        assert_lower_dash_name(&row.name, &row.name);
        assert!(
            valid_error_kinds.contains(row.expected_kind.as_str()),
            "malformed pcap fixture {} has unknown expected error kind {}",
            row.name,
            row.expected_kind
        );
        assert!(
            !row.bytes.is_empty(),
            "malformed pcap fixture {} should carry input bytes",
            row.name
        );

        let result = PcapReader::from_reader(row.bytes.as_slice())
            .and_then(|reader| reader.collect_records().map(|_| ()));
        let err = match result {
            Ok(()) => panic!(
                "malformed pcap fixture {} unexpectedly decoded successfully",
                row.name
            ),
            Err(err) => err,
        };
        assert_pcap_error_kind(&row, err);
        covered_rows.insert(row.name);
    }

    for required in required_rows {
        assert!(
            covered_rows.contains(required),
            "malformed pcap corpus is missing required case {required}"
        );
    }
}

/// Build a deterministic IPv4/UDP/DNS query carrying one EDNS(0) OPT additional
/// record, compile it, decode it back, and return the decoded DNS layer plus the
/// original and recompiled bytes for byte-stable round-trip assertions. Uses
/// documentation address space and no live traffic.
fn dns_edns_round_trip(opt: DnsRecord) -> (Dns, Vec<u8>, Vec<u8>) {
    let original = Dns::a_query("example.com.").id(0xbeef).additional(opt);
    let bytes = (Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 53))
        / Udp::new().sport(53001).dport(53)
        / original)
        .compile()
        .expect("EDNS query should compile");

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
        .expect("EDNS query should decode");
    let dns = decoded
        .layer::<Dns>()
        .expect("decoded packet has a Dns layer")
        .clone();
    let recompiled = decoded
        .compile()
        .expect("decoded EDNS query should compile");
    (
        dns,
        bytes.as_bytes().to_vec(),
        recompiled.as_bytes().to_vec(),
    )
}

#[test]
fn dns_edns_opt_with_typed_and_unknown_options_round_trips() {
    // A query with an OPT additional record carrying NSID (typed, source-backed)
    // and an unknown option code that must round trip as raw bytes.
    let unknown_code = 0xfffeu16;
    let opt = DnsRecord::opt(
        DNS_EDNS_DEFAULT_UDP_PAYLOAD_SIZE,
        0,
        0,
        true,
        vec![
            EdnsOption::cookie(b"clientcookie".to_vec()),
            EdnsOption::nsid(b"ns1".to_vec()),
            EdnsOption::new(unknown_code, vec![0xde, 0xad]),
        ],
    );
    let (dns, original, recompiled) = dns_edns_round_trip(opt);

    let record = &dns.additionals()[0];
    assert!(record.is_opt());
    assert_eq!(record.record_type(), DNS_TYPE_OPT);
    assert_eq!(
        record.edns_udp_payload_size(),
        DNS_EDNS_DEFAULT_UDP_PAYLOAD_SIZE
    );
    assert!(record.edns_dnssec_ok());

    let options = record
        .edns_options()
        .expect("OPT record exposes its options");
    assert_eq!(options.len(), 3);
    assert_eq!(options[0].code(), DNS_EDNS_OPTION_COOKIE);
    assert_eq!(options[1].code(), DNS_EDNS_OPTION_NSID);
    assert_eq!(options[1].data(), b"ns1");
    assert_eq!(options[2].code(), unknown_code);
    assert_eq!(options[2].option_code_name(), None);
    assert_eq!(options[2].data(), &[0xde, 0xad]);

    // The original question survives alongside the OPT additional record, and
    // the stable wire bytes round trip unchanged.
    assert_eq!(dns.questions()[0].question_type(), DNS_TYPE_A);
    assert_eq!(recompiled, original);
}

#[test]
fn dns_edns_opt_with_no_options_round_trips() {
    let opt = DnsRecord::opt(1232, 0, 0, false, Vec::new());
    let (dns, original, recompiled) = dns_edns_round_trip(opt);

    let record = &dns.additionals()[0];
    assert!(record.is_opt());
    assert_eq!(record.edns_udp_payload_size(), 1232);
    assert!(!record.edns_dnssec_ok());
    assert_eq!(record.data(), &DnsRecordData::Opt(Vec::new()));
    assert_eq!(recompiled, original);
}

#[test]
fn summary_fixture_reader_matches_current_summary_fixture() {
    let packet = decode_packet(PacketDecodeTarget::Raw, b"Hello, agents!")
        .expect("raw fixture should decode");
    let expected = read_summary_fixture("summaries/raw-hello-agents.summary.txt");
    let actual = format!(
        "summary:\n{}\n\nshow:\n{}\n\nhexdump:\n{}\n\nraw_string_lossy_debug:\n{:?}\n",
        packet.summary(),
        packet.show(),
        packet.hexdump().expect("raw fixture should hexdump"),
        packet
            .raw_string_lossy()
            .expect("raw fixture should stringify")
    );

    assert_eq!(actual, expected);
}

fn assert_show_matches_fixture(label: &str, packet: &Packet, show_fixture: &str) {
    let expected = read_summary_fixture(show_fixture);
    assert_eq!(
        expected.trim_end(),
        packet.show().trim_end(),
        "{label} show() did not match {show_fixture}"
    );
}

/// Standard Ethernet/IPv4 ARP `show()` output stays readable and byte-stable
/// against its golden snapshot (labelled hardware/protocol type and operation,
/// typed MAC/IPv4 address views). Decoded from the existing golden byte fixture
/// so the snapshot tracks the same packet the rest of the suite exercises.
#[test]
fn ethernet_arp_reply_show_matches_snapshot() {
    let case = valid_fixture_case("ethernet-arp-reply");
    let bytes = fixture_bytes_for_case(case);
    let packet = decode_packet(PacketDecodeTarget::Link(LinkType::Ethernet), &bytes)
        .expect("ethernet ARP reply fixture should decode");
    assert_show_matches_fixture(
        "ethernet-arp-reply",
        &packet,
        "summaries/ethernet-arp-reply-show.summary.txt",
    );
}

/// Standard Linux cooked ARP who-has `show()` output stays readable and stable
/// against its golden snapshot. Decoded from the existing golden byte fixture.
#[test]
fn linux_sll_arp_who_has_show_matches_snapshot() {
    let case = valid_fixture_case("linux-sll-arp-who-has");
    let bytes = fixture_bytes_for_case(case);
    let packet = decode_packet(PacketDecodeTarget::Link(LinkType::LinuxSll), &bytes)
        .expect("linux cooked ARP who-has fixture should decode");
    assert_show_matches_fixture(
        "linux-sll-arp-who-has",
        &packet,
        "summaries/linux-sll-arp-who-has-show.summary.txt",
    );
}

/// Nonstandard ARP `show()` output remains inspectable against its golden
/// snapshot: an InfiniBand hardware type (HRD 32), an IPv6 EtherType protocol
/// type, variable-length raw sender/target addresses (HLN=8, PLN=16), and an
/// unknown numeric opcode. Unknown codepoints render as bare hex / numeric
/// values and the raw address bytes stay visible. Documentation address space
/// only (RFC 7042 MAC OUI, RFC 3849 2001:db8::/32 IPv6).
#[test]
fn ethernet_arp_nonstandard_show_matches_snapshot() {
    let arp = Arp::new()
        .hardware_type(ARP_HRD_INFINIBAND)
        .protocol_type(0x86dd)
        .opcode(1024)
        .sender_hardware(vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x10, 0x11, 0x12])
        .sender_protocol(vec![
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x10,
        ])
        .target_hardware(vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x20, 0x21, 0x22])
        .target_protocol(vec![
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x20,
        ]);

    let packet = Packet::from_layer(
        Ethernet::new()
            .src(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
            .dst(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x02]))
            .ethertype(ETHERTYPE_ARP),
    )
    .push(arp);

    assert_show_matches_fixture(
        "ethernet-arp-infiniband-ipv6-nonstandard",
        &packet,
        "summaries/ethernet-arp-infiniband-ipv6-nonstandard-show.summary.txt",
    );
}
