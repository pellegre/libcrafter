#[macro_use]
mod support;

use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use crafter::core::{
    Ah, Arp, Bgp, Dhcp, DhcpMessageType, DhcpOption, DhcpRelayAgentInfo, DhcpRelaySuboption, Dns,
    DnsName, DnsRecord, DnsRecordData, Dot11, Dot11DataSubtype, Dot11ManagementSubtype, Dscp,
    Eapol, EapolKey, Ecn, EdnsOption, Esp, Ethernet, IcmpKind, Icmpv4, Icmpv6, Igmp,
    IgmpExtensionType, IgmpGroupRecord, IgmpQuery, IgmpRecordType, IgmpReport, IgmpType,
    IkeHeader, IkeKePayload, IkeNoncePayload, IkeSaPayload, Ipv4, Ipv4ChecksumStatus,
    Ipv4Option, Ipv6, Ipv6DestinationOptionsHeader, Ipv6FragmentHeader, Ipv6FragmentHeaderStatus,
    Ipv6HopByHopOptionsHeader,
    Ipv6MobileRoutingHeader, Ipv6MobileRoutingHeaderStatus, Ipv6Option, Ipv6RoutingHeader,
    Ipv6RoutingTypeStatus, Ipv6SegmentRoutingHeader, Layer, LinkType, LinuxSll, LlcSnap, MacAddr,
    NetworkLayer, NullByteOrder, NullLoopback, OptionOverload, OspfChecksumStatus, Ospfv2, Ospfv3,
    Packet, Radiotap, Raw, Rip, Ripng, Tcp, TcpOption, TcpSackBlock, Udp, UdpChecksumStatus,
    UdpOption, UdpOptionStatus, UdpOptions, Vlan, ARP_HRD_INFINIBAND, BOOTP_REQUEST,
    DHCP_CLIENT_PORT, DHCP_SERVER_PORT, DNS_CLASS_IN,
    DNS_EDNS_DEFAULT_UDP_PAYLOAD_SIZE, DNS_EDNS_OPTION_COOKIE, DNS_EDNS_OPTION_NSID,
    DNS_FLAG_AUTHORITATIVE, DNS_FLAG_QR_RESPONSE, DNS_FLAG_RECURSION_DESIRED, DNS_SVCB_KEY_ALPN,
    DNS_SVCB_KEY_IPV4HINT, DNS_SVCB_KEY_IPV6HINT, DNS_SVCB_KEY_PORT, DNS_TYPE_A, DNS_TYPE_AAAA,
    DNS_TYPE_CNAME, DNS_TYPE_DNSKEY, DNS_TYPE_DS, DNS_TYPE_HTTPS, DNS_TYPE_NS, DNS_TYPE_NSEC,
    DNS_TYPE_NSEC3, DNS_TYPE_OPT, DNS_TYPE_RRSIG, DNS_TYPE_SOA, DNS_TYPE_SRV, DNS_TYPE_SVCB,
    ETHERTYPE_ARP, ETHERTYPE_EAPOL, ETHERTYPE_IPV4, ETHERTYPE_VLAN, ICMPV6_ECHO_REQUEST,
    ICMPV6_TIME_EXCEEDED, ICMP_DESTINATION_UNREACHABLE, ICMP_ECHO_REQUEST, IGMP_FIXED_HEADER_LEN,
    IGMP_QUERY_CODE_V1, IGMP_TYPE_UNASSIGNED_FIRST, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IGMP,
    IPPROTO_IPV6_DSTOPTS, IPPROTO_IPV6_EXPERIMENTAL_1, IPPROTO_IPV6_FRAGMENT,
    IPPROTO_IPV6_HOPOPTS, IPPROTO_IPV6_ROUTE, IPPROTO_TCP, IPPROTO_UDP, IPV4_FLAG_DONT_FRAGMENT,
    IPV4_FLAG_MORE_FRAGMENTS, IPV4_FLAG_RESERVED, IPV6_ROUTING_TYPE_MOBILE,
    IPV6_ROUTING_TYPE_SEGMENT, TCP_FLAG_ACK, TCP_FLAG_PSH, TCP_FLAG_SYN, UDP_HEADER_LEN,
    UDP_OPTION_EOL, UDP_OPTION_NOP,
};
use crafter::protocols::igmp::IgmpExtension;
use crafter::wire::backend::pcap::{
    PcapError, PcapLinkType, PcapReader, PcapTimestamp, PcapWriter, PcapWriterOptions,
    TimestampPrecision,
};
use crafter::{
    BackendKind, CrafterError, Dot11Metadata, IpDefrag, IpDefragOverlapStatus, IpFragment,
    IpFragmentConfig, IpFragmentFamily, IpFragmentRange, IpFragmentReason, PacketOrigin,
    PacketRecord, PacketWire, Sniffer, WifiDecryptState, WireError, WpaAkm, WpaCipher,
    WpaCredentialStatus, WpaDecrypt, WpaDecryptReason, WpaHandshakeStatus, WpaKeyKind,
    IPV4_OPTION_NOP,
};
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
    Radiotap,
    Dot11,
    LlcSnap,
    Eapol,
    EapolKey,
    Ethernet,
    LinuxSll,
    NullLoopback,
    Vlan,
    Arp,
    Ipv4,
    Ipv6,
    Ipv6HopByHopOptions,
    Ipv6DestinationOptions,
    Ipv6Routing,
    Ipv6MobileRouting,
    Ipv6SegmentRouting,
    Ipv6Fragment,
    Icmp,
    Igmp,
    IgmpQuery,
    IgmpReport,
    IgmpExtension,
    Icmpv6,
    Tcp,
    Udp,
    UdpOptions,
    Bgp,
    Rip,
    Ripng,
    Dns,
    Dhcp,
    Ospf,
    Ospfv3,
    Esp,
    Ah,
    IkeHeader,
    IkeSaPayload,
    IkeKePayload,
    IkeNoncePayload,
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
    Ipv4IgmpBootstrap,
    Ipv4IgmpExtension,
    Ipv4DscpEcn,
    Ipv4Fragment,
    Ipv4Options,
    Ipv4TcpOptions,
    Ipv4TcpBgp,
    Ipv4UdpDnsQuery,
    Ipv4UdpDnsResponse,
    Ipv4UdpDnsSoaSrv,
    Ipv4UdpDnsDnssec,
    Ipv4UdpDnsSvcbHttps,
    Ipv4UdpDnsEdnsOpt,
    Ipv4UdpDnsRawUnknown,
    Ipv4UdpDnsSectionPlacement,
    Ipv4UdpDhcp,
    Ipv4Ospf,
    Ipv6Ospfv3,
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
    IpsecEsp,
    IpsecAh,
    IpsecIkev2,
    Ipv4UdpRip,
    Ipv6UdpRipng,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PcapCoverageFamily {
    Ethernet,
    Ieee80211,
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

#[derive(Debug, Clone, Copy)]
struct Dot11TextArtifact {
    path: &'static str,
    section_start: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
struct IpFragmentTextArtifact {
    path: &'static str,
    section_start: Option<&'static str>,
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
        name: "ipv4-igmp-v1-query",
        path: "bytes/ipv4-igmp-v1-query.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-igmp-v1-query.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Igmp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-igmp-v1-query.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-igmp-v1-report",
        path: "bytes/ipv4-igmp-v1-report.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-igmp-v1-report.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Igmp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-igmp-v1-report.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-igmp-v2-query",
        path: "bytes/ipv4-igmp-v2-query.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-igmp-v2-query.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Igmp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-igmp-v2-query.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-igmp-v2-report",
        path: "bytes/ipv4-igmp-v2-report.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-igmp-v2-report.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Igmp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-igmp-v2-report.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-igmp-v2-leave",
        path: "bytes/ipv4-igmp-v2-leave.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-igmp-v2-leave.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Igmp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-igmp-v2-leave.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-igmp-mrd-advertisement",
        path: "bytes/ipv4-igmp-mrd-advertisement.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-igmp-mrd-advertisement.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Igmp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-igmp-mrd-advertisement.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-igmp-mrd-solicitation",
        path: "bytes/ipv4-igmp-mrd-solicitation.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-igmp-mrd-solicitation.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Igmp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-igmp-mrd-solicitation.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-igmp-mrd-termination",
        path: "bytes/ipv4-igmp-mrd-termination.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-igmp-mrd-termination.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Igmp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-igmp-mrd-termination.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-igmp-v3-query-extension",
        path: "bytes/ipv4-igmp-v3-query-extension.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-igmp-v3-query-extension.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[
            ExpectedLayer::Ipv4,
            ExpectedLayer::Igmp,
            ExpectedLayer::IgmpQuery,
            ExpectedLayer::IgmpExtension,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-igmp-v3-query-extension.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-igmp-v3-report-extension",
        path: "bytes/ipv4-igmp-v3-report-extension.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-igmp-v3-report-extension.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[
            ExpectedLayer::Ipv4,
            ExpectedLayer::Igmp,
            ExpectedLayer::IgmpReport,
            ExpectedLayer::IgmpExtension,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-igmp-v3-report-extension.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-udp-dscp-ecn-raw",
        path: "bytes/ipv4-udp-dscp-ecn-raw.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-udp-dscp-ecn-raw.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-fragment-noninitial-raw",
        path: "bytes/ipv4-fragment-noninitial-raw.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-fragment-noninitial-raw.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-fragment-defrag-complete-final",
        path: "bytes/ipv4-fragment-defrag-complete-final.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ipv4-fragment-defrag-complete-final.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-fragment-defrag-complete-first",
        path: "bytes/ipv4-fragment-defrag-complete-first.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ipv4-fragment-defrag-complete-first.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-fragment-defrag-duplicate-final",
        path: "bytes/ipv4-fragment-defrag-duplicate-final.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ipv4-fragment-defrag-duplicate-final.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-fragment-defrag-duplicate-first",
        path: "bytes/ipv4-fragment-defrag-duplicate-first.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ipv4-fragment-defrag-duplicate-first.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-fragment-defrag-duplicate-repeat",
        path: "bytes/ipv4-fragment-defrag-duplicate-repeat.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ipv4-fragment-defrag-duplicate-repeat.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-fragment-defrag-missing-final",
        path: "bytes/ipv4-fragment-defrag-missing-final.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ipv4-fragment-defrag-missing-final.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-fragment-defrag-missing-first",
        path: "bytes/ipv4-fragment-defrag-missing-first.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ipv4-fragment-defrag-missing-first.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-fragment-defrag-overlap-conflict",
        path: "bytes/ipv4-fragment-defrag-overlap-conflict.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ipv4-fragment-defrag-overlap-conflict.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-fragment-defrag-overlap-first",
        path: "bytes/ipv4-fragment-defrag-overlap-first.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ipv4-fragment-defrag-overlap-first.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-fragment-ipfragment-generated-first",
        path: "bytes/ipv4-fragment-ipfragment-generated-first.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ipv4-fragment-ipfragment-generated-first.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv4-fragment-ipfragment-generated-final",
        path: "bytes/ipv4-fragment-ipfragment-generated-final.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ipv4-fragment-ipfragment-generated-final.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Raw],
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
        summary_path: Some("summaries/ipv4-options-traceroute-udp-raw.summary.txt"),
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
        name: "ipv4-tcp-syn-rich-options",
        path: "bytes/ipv4-tcp-syn-rich-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-tcp-syn-rich-options.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Tcp, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-tcp-syn-rich-options.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-tcp-bgp-open",
        path: "bytes/ipv4-tcp-bgp-open.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-tcp-bgp-open.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Tcp, ExpectedLayer::Bgp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-tcp-bgp-open.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-tcp-bgp-update-announce",
        path: "bytes/ipv4-tcp-bgp-update-announce.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-tcp-bgp-update-announce.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Tcp, ExpectedLayer::Bgp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-tcp-bgp-update-announce.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-tcp-bgp-notification",
        path: "bytes/ipv4-tcp-bgp-notification.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-tcp-bgp-notification.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Tcp, ExpectedLayer::Bgp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-tcp-bgp-notification.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-tcp-bgp-keepalive",
        path: "bytes/ipv4-tcp-bgp-keepalive.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-tcp-bgp-keepalive.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Tcp, ExpectedLayer::Bgp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-tcp-bgp-keepalive.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-udp-rip-v1-request",
        path: "bytes/ipv4-udp-rip-v1-request.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-udp-rip-v1-request.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Rip],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-udp-rip-v1-request.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-udp-rip-v2-auth-response",
        path: "bytes/ipv4-udp-rip-v2-auth-response.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-udp-rip-v2-auth-response.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Rip],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-udp-rip-v2-auth-response.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv6-udp-ripng-response",
        path: "bytes/ipv6-udp-ripng-response.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv6-udp-ripng-response.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[
            ExpectedLayer::Ipv6,
            ExpectedLayer::Udp,
            ExpectedLayer::Ripng,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv6-udp-ripng-response.summary.txt"),
    },
    ValidFixtureCase {
        name: "ospf-hello-single-neighbor",
        path: "bytes/ospf-hello-single-neighbor.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospf-hello-single-neighbor.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Ospf],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ospf-hello-single-neighbor.summary.txt"),
    },
    ValidFixtureCase {
        name: "ospf-database-description",
        path: "bytes/ospf-database-description.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospf-database-description.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Ospf],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ospf-link-state-request",
        path: "bytes/ospf-link-state-request.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospf-link-state-request.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Ospf],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ospf-link-state-ack",
        path: "bytes/ospf-link-state-ack.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospf-link-state-ack.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Ospf],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ospf-link-state-update",
        path: "bytes/ospf-link-state-update.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospf-link-state-update.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Ospf],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ospf-router-lsa",
        path: "bytes/ospf-router-lsa.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospf-router-lsa.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Ospf],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ospf-router-lsa.summary.txt"),
    },
    ValidFixtureCase {
        name: "ospf-network-lsa",
        path: "bytes/ospf-network-lsa.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospf-network-lsa.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Ospf],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ospf-summary-lsa-ip",
        path: "bytes/ospf-summary-lsa-ip.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospf-summary-lsa-ip.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Ospf],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ospf-summary-lsa-asbr",
        path: "bytes/ospf-summary-lsa-asbr.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospf-summary-lsa-asbr.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Ospf],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ospf-as-external-lsa",
        path: "bytes/ospf-as-external-lsa.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospf-as-external-lsa.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Ospf],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ospf-nssa-lsa",
        path: "bytes/ospf-nssa-lsa.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospf-nssa-lsa.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Ospf],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ospf-opaque-lsa-area",
        path: "bytes/ospf-opaque-lsa-area.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospf-opaque-lsa-area.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Ospf],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ospf-te-lsa",
        path: "bytes/ospf-te-lsa.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospf-te-lsa.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Ospf],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ospf-hello-simple-auth",
        path: "bytes/ospf-hello-simple-auth.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospf-hello-simple-auth.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Ospf],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ospf-hello-crypto-md5",
        path: "bytes/ospf-hello-crypto-md5.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospf-hello-crypto-md5.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Ospf],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ospfv3-hello",
        path: "bytes/ospfv3-hello.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospfv3-hello.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[ExpectedLayer::Ipv6, ExpectedLayer::Ospfv3],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ospfv3-hello.summary.txt"),
    },
    ValidFixtureCase {
        name: "ospfv3-router-lsa",
        path: "bytes/ospfv3-router-lsa.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ospfv3-router-lsa.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[ExpectedLayer::Ipv6, ExpectedLayer::Ospfv3],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ethernet-ipv4-tcp-bgp-open",
        path: "bytes/ethernet-ipv4-tcp-bgp-open.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ethernet-ipv4-tcp-bgp-open.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ethernet)),
        expected_layers: &[
            ExpectedLayer::Ethernet,
            ExpectedLayer::Ipv4,
            ExpectedLayer::Tcp,
            ExpectedLayer::Bgp,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ethernet-ipv4-tcp-bgp-keepalive",
        path: "bytes/ethernet-ipv4-tcp-bgp-keepalive.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ethernet-ipv4-tcp-bgp-keepalive.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ethernet)),
        expected_layers: &[
            ExpectedLayer::Ethernet,
            ExpectedLayer::Ipv4,
            ExpectedLayer::Tcp,
            ExpectedLayer::Bgp,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ethernet-ipv4-tcp-bgp-update-announce",
        path: "bytes/ethernet-ipv4-tcp-bgp-update-announce.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ethernet-ipv4-tcp-bgp-update-announce.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ethernet)),
        expected_layers: &[
            ExpectedLayer::Ethernet,
            ExpectedLayer::Ipv4,
            ExpectedLayer::Tcp,
            ExpectedLayer::Bgp,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
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
        name: "ipv4-udp-dns-soa-srv-response",
        path: "bytes/ipv4-udp-dns-soa-srv-response.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-udp-dns-soa-srv-response.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Dns],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-udp-dns-soa-srv-response.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-udp-dns-dnssec-response",
        path: "bytes/ipv4-udp-dns-dnssec-response.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-udp-dns-dnssec-response.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Dns],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-udp-dns-dnssec-response.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-udp-dns-svcb-https-response",
        path: "bytes/ipv4-udp-dns-svcb-https-response.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-udp-dns-svcb-https-response.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Dns],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-udp-dns-svcb-https-response.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-udp-dns-edns-opt-query",
        path: "bytes/ipv4-udp-dns-edns-opt-query.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-udp-dns-edns-opt-query.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Dns],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-udp-dns-edns-opt-query.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-udp-dns-raw-unknown-records-response",
        path: "bytes/ipv4-udp-dns-raw-unknown-records-response.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ipv4-udp-dns-raw-unknown-records-response.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Dns],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-udp-dns-raw-unknown-records-response.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv4-udp-dns-section-placement-response",
        path: "bytes/ipv4-udp-dns-section-placement-response.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ipv4-udp-dns-section-placement-response.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Udp, ExpectedLayer::Dns],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-udp-dns-section-placement-response.summary.txt"),
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
        name: "ipv6-base-traffic-flow-udp-raw",
        path: "bytes/ipv6-base-traffic-flow-udp-raw.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv6-base-traffic-flow-udp-raw.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[ExpectedLayer::Ipv6, ExpectedLayer::Udp, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv6-options-hop-destination-udp",
        path: "bytes/ipv6-options-hop-destination-udp.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv6-options-hop-destination-udp.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[
            ExpectedLayer::Ipv6,
            ExpectedLayer::Ipv6HopByHopOptions,
            ExpectedLayer::Ipv6DestinationOptions,
            ExpectedLayer::Udp,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv6-options-hop-destination-udp.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv6-routing-generic-unknown-raw",
        path: "bytes/ipv6-routing-generic-unknown-raw.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv6-routing-generic-unknown-raw.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[
            ExpectedLayer::Ipv6,
            ExpectedLayer::Ipv6Routing,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv6-routing-generic-unknown-raw.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv6-mobile-routing-raw",
        path: "bytes/ipv6-mobile-routing-raw.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv6-mobile-routing-raw.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[
            ExpectedLayer::Ipv6,
            ExpectedLayer::Ipv6MobileRouting,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv6-mobile-routing-raw.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv6-segment-routing-raw",
        path: "bytes/ipv6-segment-routing-raw.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv6-segment-routing-raw.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[
            ExpectedLayer::Ipv6,
            ExpectedLayer::Ipv6SegmentRouting,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv6-segment-routing-raw.summary.txt"),
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
        name: "ipv6-tcp-rich-options",
        path: "bytes/ipv6-tcp-rich-options.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv6-tcp-rich-options.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[ExpectedLayer::Ipv6, ExpectedLayer::Tcp, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv6-tcp-rich-options.summary.txt"),
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
    ValidFixtureCase {
        name: "ipv6-fragment-atomic-udp-raw",
        path: "bytes/ipv6-fragment-atomic-udp-raw.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv6-fragment-atomic-udp-raw.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[
            ExpectedLayer::Ipv6,
            ExpectedLayer::Ipv6Fragment,
            ExpectedLayer::Udp,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv6-fragment-atomic-udp-raw.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv6-fragment-non-initial-udp-raw",
        path: "bytes/ipv6-fragment-non-initial-udp-raw.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv6-fragment-non-initial-udp-raw.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[
            ExpectedLayer::Ipv6,
            ExpectedLayer::Ipv6Fragment,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv6-fragment-non-initial-udp-raw.summary.txt"),
    },
    ValidFixtureCase {
        name: "ipv6-fragment-oracle-reference-first",
        path: "bytes/ipv6-fragment-oracle-reference-first.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ipv6-fragment-oracle-reference-first.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[
            ExpectedLayer::Ipv6,
            ExpectedLayer::Ipv6Fragment,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "ipv6-fragment-oracle-reference-final",
        path: "bytes/ipv6-fragment-oracle-reference-final.hex",
        contents: FixtureContents::Hex(fixture_str!(
            "bytes/ipv6-fragment-oracle-reference-final.hex"
        )),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv6)),
        expected_layers: &[
            ExpectedLayer::Ipv6,
            ExpectedLayer::Ipv6Fragment,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    // IPSec ESP transport over IPv4, AES-GCM-16 AEAD (RFC 4303 + RFC 4106). The
    // built-in registry carries no SA, so the sealed body decodes opaquely as a
    // typed ESP header (SPI/Seq) whose ciphertext re-compiles byte-for-byte.
    ValidFixtureCase {
        name: "ipv4-esp-aead-gcm-opaque",
        path: "bytes/ipv4-esp-aead-gcm-opaque.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-esp-aead-gcm-opaque.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Esp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-esp-aead-gcm-opaque.summary.txt"),
    },
    // IPSec ESP transport over IPv4, AES-CBC encryption + HMAC-SHA-256-128
    // integrity (RFC 4303 + RFC 3602 + RFC 4868). Decodes opaquely (no SA in the
    // default registry) and re-compiles byte-for-byte.
    ValidFixtureCase {
        name: "ipv4-esp-cbc-hmac-opaque",
        path: "bytes/ipv4-esp-cbc-hmac-opaque.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-esp-cbc-hmac-opaque.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[ExpectedLayer::Ipv4, ExpectedLayer::Esp],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-esp-cbc-hmac-opaque.summary.txt"),
    },
    // IPSec AH transport over IPv4, HMAC-SHA-256-128 (RFC 4302 + RFC 4868). AH
    // never encrypts, so the cleartext TCP / Raw tail is dispatched by the AH
    // Next Header and the whole datagram (including the captured ICV) round-trips.
    ValidFixtureCase {
        name: "ipv4-ah-hmac-sha256-transport",
        path: "bytes/ipv4-ah-hmac-sha256-transport.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-ah-hmac-sha256-transport.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[
            ExpectedLayer::Ipv4,
            ExpectedLayer::Ah,
            ExpectedLayer::Tcp,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-ah-hmac-sha256-transport.summary.txt"),
    },
    // IPSec IKEv2 IKE_SA_INIT message over UDP/500 (RFC 7296 §1.2): the IKE
    // header plus the SA / KE / Ni payload chain. UDP/500 routes to IKEv2 and the
    // Next Payload chain decodes into one typed layer per payload, re-compiling
    // byte-for-byte including the auto-filled IKE message length.
    ValidFixtureCase {
        name: "ipv4-udp-ikev2-sa-init",
        path: "bytes/ipv4-udp-ikev2-sa-init.hex",
        contents: FixtureContents::Hex(fixture_str!("bytes/ipv4-udp-ikev2-sa-init.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::L3(NetworkLayer::Ipv4)),
        expected_layers: &[
            ExpectedLayer::Ipv4,
            ExpectedLayer::Udp,
            ExpectedLayer::IkeHeader,
            ExpectedLayer::IkeSaPayload,
            ExpectedLayer::IkeKePayload,
            ExpectedLayer::IkeNoncePayload,
        ],
        preserve_exact_bytes: true,
        summary_path: Some("summaries/ipv4-udp-ikev2-sa-init.summary.txt"),
    },
];

const DOT11_FIXTURES: &[ValidFixtureCase] = &[
    ValidFixtureCase {
        name: "dot11-bare-data",
        path: "dot11/bare-data.hex",
        contents: FixtureContents::Hex(fixture_str!("dot11/bare-data.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ieee80211)),
        expected_layers: &[ExpectedLayer::Dot11, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dot11-qos-data",
        path: "dot11/qos-data.hex",
        contents: FixtureContents::Hex(fixture_str!("dot11/qos-data.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ieee80211)),
        expected_layers: &[ExpectedLayer::Dot11, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dot11-protected-data",
        path: "dot11/protected-data.hex",
        contents: FixtureContents::Hex(fixture_str!("dot11/protected-data.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ieee80211)),
        expected_layers: &[ExpectedLayer::Dot11, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dot11-beacon-tags",
        path: "dot11/beacon-tags.hex",
        contents: FixtureContents::Hex(fixture_str!("dot11/beacon-tags.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ieee80211)),
        expected_layers: &[ExpectedLayer::Dot11],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dot11-radiotap-data",
        path: "dot11/radiotap-data.hex",
        contents: FixtureContents::Hex(fixture_str!("dot11/radiotap-data.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Radiotap)),
        expected_layers: &[
            ExpectedLayer::Radiotap,
            ExpectedLayer::Dot11,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dot11-llc-snap-ipv4",
        path: "dot11/llc-snap-ipv4.hex",
        contents: FixtureContents::Hex(fixture_str!("dot11/llc-snap-ipv4.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ieee80211)),
        expected_layers: &[
            ExpectedLayer::Dot11,
            ExpectedLayer::LlcSnap,
            ExpectedLayer::Ipv4,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dot11-llc-snap-eapol",
        path: "dot11/llc-snap-eapol.hex",
        contents: FixtureContents::Hex(fixture_str!("dot11/llc-snap-eapol.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ieee80211)),
        expected_layers: &[
            ExpectedLayer::Dot11,
            ExpectedLayer::LlcSnap,
            ExpectedLayer::Eapol,
            ExpectedLayer::Raw,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dot11-eapol-key",
        path: "dot11/eapol-key.hex",
        contents: FixtureContents::Hex(fixture_str!("dot11/eapol-key.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ieee80211)),
        expected_layers: &[
            ExpectedLayer::Dot11,
            ExpectedLayer::LlcSnap,
            ExpectedLayer::Eapol,
            ExpectedLayer::EapolKey,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dot11-rsn-ie",
        path: "dot11/rsn-ie.hex",
        contents: FixtureContents::Hex(fixture_str!("dot11/rsn-ie.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ieee80211)),
        expected_layers: &[ExpectedLayer::Dot11],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dot11-wpa2-psk-ccmp-beacon",
        path: "dot11/wpa2-psk-ccmp-beacon.hex",
        contents: FixtureContents::Hex(fixture_str!("dot11/wpa2-psk-ccmp-beacon.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ieee80211)),
        expected_layers: &[ExpectedLayer::Dot11],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dot11-wpa2-psk-ccmp-message-1",
        path: "dot11/wpa2-psk-ccmp-message-1.hex",
        contents: FixtureContents::Hex(fixture_str!("dot11/wpa2-psk-ccmp-message-1.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ieee80211)),
        expected_layers: &[
            ExpectedLayer::Dot11,
            ExpectedLayer::LlcSnap,
            ExpectedLayer::Eapol,
            ExpectedLayer::EapolKey,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dot11-wpa2-psk-ccmp-message-2",
        path: "dot11/wpa2-psk-ccmp-message-2.hex",
        contents: FixtureContents::Hex(fixture_str!("dot11/wpa2-psk-ccmp-message-2.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ieee80211)),
        expected_layers: &[
            ExpectedLayer::Dot11,
            ExpectedLayer::LlcSnap,
            ExpectedLayer::Eapol,
            ExpectedLayer::EapolKey,
        ],
        preserve_exact_bytes: true,
        summary_path: None,
    },
    ValidFixtureCase {
        name: "dot11-wpa2-psk-ccmp-unicast-data",
        path: "dot11/wpa2-psk-ccmp-unicast-data.hex",
        contents: FixtureContents::Hex(fixture_str!("dot11/wpa2-psk-ccmp-unicast-data.hex")),
        target: FixtureDecodeTarget::Packet(PacketDecodeTarget::Link(LinkType::Ieee80211)),
        expected_layers: &[ExpectedLayer::Dot11, ExpectedLayer::Raw],
        preserve_exact_bytes: true,
        summary_path: None,
    },
];

const DOT11_TEXT_ARTIFACTS: &[Dot11TextArtifact] = &[
    Dot11TextArtifact {
        path: "docs/guide/dot11.md",
        section_start: None,
    },
    Dot11TextArtifact {
        path: "docs/operations/dot11-live-manual.md",
        section_start: None,
    },
    Dot11TextArtifact {
        path: "crafter/tests/fixtures/dot11/README.md",
        section_start: None,
    },
    Dot11TextArtifact {
        path: ".agents/docs/cookbook.md",
        section_start: Some("## Build Dot11 Stacks"),
    },
];

const ALLOWED_DOT11_SYNTHETIC_SSIDS: &[&str] = &[
    "crafter",
    "libcrafter-wpa",
    "libcrafter-dot11-dry-run",
    "libcrafter-rsn",
    "rsn-fixture",
];

const ALLOWED_DOT11_SYNTHETIC_SSID_PREFIXES: &[&str] = &["dot11-agent-"];

const IP_FRAGMENT_TEXT_ARTIFACTS: &[IpFragmentTextArtifact] = &[
    IpFragmentTextArtifact {
        path: "docs/reference/wire.md",
        section_start: Some("Built-in transform shapes include:"),
    },
    IpFragmentTextArtifact {
        path: "docs/operations/lab.md",
        section_start: Some("## IP Fragment Lab Safety"),
    },
    IpFragmentTextArtifact {
        path: "docs/operations/validation.md",
        section_start: Some("## IP Fragment Transform Validation"),
    },
    IpFragmentTextArtifact {
        path: "crafter/tests/fixtures/README.md",
        section_start: Some("## Current Coverage Matrix"),
    },
    IpFragmentTextArtifact {
        path: ".agents/context/ip-fragment-live-audit.md",
        section_start: None,
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
        name: "ipv4-tcp-bgp-session",
        path: "pcaps/ipv4-tcp-bgp-session.pcap",
        contents: fixture_bytes!("pcaps/ipv4-tcp-bgp-session.pcap"),
        pcap_link_type: PcapLinkType::Ethernet,
        link_type: LinkType::Ethernet,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::Ethernet,
        records: &[
            PcapFixtureRecord {
                seconds: 61,
                fractional: 101,
                fixture_name: "ethernet-ipv4-tcp-bgp-open",
            },
            PcapFixtureRecord {
                seconds: 61,
                fractional: 202,
                fixture_name: "ethernet-ipv4-tcp-bgp-keepalive",
            },
            PcapFixtureRecord {
                seconds: 61,
                fractional: 303,
                fixture_name: "ethernet-ipv4-tcp-bgp-update-announce",
            },
        ],
    },
    // RawIp pcap fixtures carrying the RIP / RIPng UDP fixtures so the full
    // read -> decode -> summary path is exercised: a RIPv1 whole-table request
    // (Ipv4/Udp 520), a RIPv2 simple-password authenticated response
    // (Ipv4/Udp 520), and a RIPng response with a next-hop RTE plus route RTEs
    // (Ipv6/Udp 521). All addresses are documentation space.
    PcapFixtureCase {
        name: "rip-v1-request",
        path: "pcaps/rip-v1-request.pcap",
        contents: fixture_bytes!("pcaps/rip-v1-request.pcap"),
        pcap_link_type: PcapLinkType::RawIp,
        link_type: LinkType::Raw,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::RawIpIpv4,
        records: &[PcapFixtureRecord {
            seconds: 80,
            fractional: 1,
            fixture_name: "ipv4-udp-rip-v1-request",
        }],
    },
    PcapFixtureCase {
        name: "rip-v2-auth-response",
        path: "pcaps/rip-v2-auth-response.pcap",
        contents: fixture_bytes!("pcaps/rip-v2-auth-response.pcap"),
        pcap_link_type: PcapLinkType::RawIp,
        link_type: LinkType::Raw,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::RawIpIpv4,
        records: &[PcapFixtureRecord {
            seconds: 80,
            fractional: 2,
            fixture_name: "ipv4-udp-rip-v2-auth-response",
        }],
    },
    PcapFixtureCase {
        name: "ripng-response",
        path: "pcaps/ripng-response.pcap",
        contents: fixture_bytes!("pcaps/ripng-response.pcap"),
        pcap_link_type: PcapLinkType::RawIp,
        link_type: LinkType::Raw,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::RawIpIpv6,
        records: &[PcapFixtureRecord {
            seconds: 80,
            fractional: 3,
            fixture_name: "ipv6-udp-ripng-response",
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
        name: "raw-ipv4-igmp-bootstrap",
        path: "pcaps/raw-ipv4-igmp-bootstrap.pcap",
        contents: fixture_bytes!("pcaps/raw-ipv4-igmp-bootstrap.pcap"),
        pcap_link_type: PcapLinkType::RawIp,
        link_type: LinkType::Raw,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::RawIpIpv4,
        records: &[
            PcapFixtureRecord {
                seconds: 17,
                fractional: 1,
                fixture_name: "ipv4-igmp-v1-query",
            },
            PcapFixtureRecord {
                seconds: 17,
                fractional: 2,
                fixture_name: "ipv4-igmp-v1-report",
            },
            PcapFixtureRecord {
                seconds: 17,
                fractional: 3,
                fixture_name: "ipv4-igmp-v2-query",
            },
            PcapFixtureRecord {
                seconds: 17,
                fractional: 4,
                fixture_name: "ipv4-igmp-v2-report",
            },
            PcapFixtureRecord {
                seconds: 17,
                fractional: 5,
                fixture_name: "ipv4-igmp-v2-leave",
            },
        ],
    },
    PcapFixtureCase {
        name: "raw-ipv4-igmp-mrd",
        path: "pcaps/raw-ipv4-igmp-mrd.pcap",
        contents: fixture_bytes!("pcaps/raw-ipv4-igmp-mrd.pcap"),
        pcap_link_type: PcapLinkType::RawIp,
        link_type: LinkType::Raw,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::RawIpIpv4,
        records: &[
            PcapFixtureRecord {
                seconds: 18,
                fractional: 1,
                fixture_name: "ipv4-igmp-mrd-advertisement",
            },
            PcapFixtureRecord {
                seconds: 18,
                fractional: 2,
                fixture_name: "ipv4-igmp-mrd-solicitation",
            },
            PcapFixtureRecord {
                seconds: 18,
                fractional: 3,
                fixture_name: "ipv4-igmp-mrd-termination",
            },
        ],
    },
    PcapFixtureCase {
        name: "raw-ipv4-udp-dscp-ecn-raw",
        path: "pcaps/raw-ipv4-udp-dscp-ecn-raw.pcap",
        contents: fixture_bytes!("pcaps/raw-ipv4-udp-dscp-ecn-raw.pcap"),
        pcap_link_type: PcapLinkType::RawIp,
        link_type: LinkType::Raw,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::RawIpIpv4,
        records: &[PcapFixtureRecord {
            seconds: 21,
            fractional: 11,
            fixture_name: "ipv4-udp-dscp-ecn-raw",
        }],
    },
    PcapFixtureCase {
        name: "raw-ipv4-ipfragment-generated",
        path: "pcaps/raw-ipv4-ipfragment-generated.pcap",
        contents: fixture_bytes!("pcaps/raw-ipv4-ipfragment-generated.pcap"),
        pcap_link_type: PcapLinkType::RawIp,
        link_type: LinkType::Raw,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::RawIpIpv4,
        records: &[
            PcapFixtureRecord {
                seconds: 90,
                fractional: 120_300,
                fixture_name: "ipv4-fragment-ipfragment-generated-first",
            },
            PcapFixtureRecord {
                seconds: 90,
                fractional: 120_301,
                fixture_name: "ipv4-fragment-ipfragment-generated-final",
            },
        ],
    },
    // Deterministic RawIp pcap carrying the IPSec ESP / AH / IKEv2 byte fixtures
    // as four records: ESP AES-GCM transport, ESP AES-CBC + HMAC transport, AH
    // HMAC-SHA-256-128 transport, and an IKE_SA_INIT message over UDP/500. The
    // records are read back and decoded as the typed ESP / AH / IKE layer stacks.
    PcapFixtureCase {
        name: "raw-ipsec-esp-ah-ikev2",
        path: "pcaps/raw-ipsec-esp-ah-ikev2.pcap",
        contents: fixture_bytes!("pcaps/raw-ipsec-esp-ah-ikev2.pcap"),
        pcap_link_type: PcapLinkType::RawIp,
        link_type: LinkType::Raw,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::RawIpIpv4,
        records: &[
            PcapFixtureRecord {
                seconds: 40,
                fractional: 1,
                fixture_name: "ipv4-esp-aead-gcm-opaque",
            },
            PcapFixtureRecord {
                seconds: 40,
                fractional: 2,
                fixture_name: "ipv4-esp-cbc-hmac-opaque",
            },
            PcapFixtureRecord {
                seconds: 40,
                fractional: 3,
                fixture_name: "ipv4-ah-hmac-sha256-transport",
            },
            PcapFixtureRecord {
                seconds: 40,
                fractional: 4,
                fixture_name: "ipv4-udp-ikev2-sa-init",
            },
        ],
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
        name: "raw-ipv6-base-traffic-flow-udp-raw",
        path: "pcaps/raw-ipv6-base-traffic-flow-udp-raw.pcap",
        contents: fixture_bytes!("pcaps/raw-ipv6-base-traffic-flow-udp-raw.pcap"),
        pcap_link_type: PcapLinkType::RawIp,
        link_type: LinkType::Raw,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::RawIpIpv6,
        records: &[PcapFixtureRecord {
            seconds: 20,
            fractional: 3,
            fixture_name: "ipv6-base-traffic-flow-udp-raw",
        }],
    },
    PcapFixtureCase {
        name: "raw-ipv6-fragment-oracle-reference",
        path: "pcaps/raw-ipv6-fragment-oracle-reference.pcap",
        contents: fixture_bytes!("pcaps/raw-ipv6-fragment-oracle-reference.pcap"),
        pcap_link_type: PcapLinkType::RawIp,
        link_type: LinkType::Raw,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::RawIpIpv6,
        records: &[
            PcapFixtureRecord {
                seconds: 91,
                fractional: 120_300,
                fixture_name: "ipv6-fragment-oracle-reference-first",
            },
            PcapFixtureRecord {
                seconds: 91,
                fractional: 120_301,
                fixture_name: "ipv6-fragment-oracle-reference-final",
            },
        ],
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
    PcapFixtureCase {
        name: "wpa2-psk-ccmp-unicast",
        path: "pcaps/wpa2-psk-ccmp-unicast.pcap",
        contents: fixture_bytes!("pcaps/wpa2-psk-ccmp-unicast.pcap"),
        pcap_link_type: PcapLinkType::Ieee80211,
        link_type: LinkType::Ieee80211,
        timestamp_precision: TimestampPrecision::Microseconds,
        coverage: PcapCoverageFamily::Ieee80211,
        records: &[
            PcapFixtureRecord {
                seconds: 70,
                fractional: 100,
                fixture_name: "dot11-wpa2-psk-ccmp-beacon",
            },
            PcapFixtureRecord {
                seconds: 70,
                fractional: 200,
                fixture_name: "dot11-wpa2-psk-ccmp-message-1",
            },
            PcapFixtureRecord {
                seconds: 70,
                fractional: 300,
                fixture_name: "dot11-wpa2-psk-ccmp-message-2",
            },
            PcapFixtureRecord {
                seconds: 70,
                fractional: 400,
                fixture_name: "dot11-wpa2-psk-ccmp-unicast-data",
            },
        ],
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
        CoverageFamily::Ipv4IgmpBootstrap,
        "IPv4 IGMP bootstrap query and report",
    ),
    (
        CoverageFamily::Ipv4IgmpExtension,
        "IPv4 IGMPv3 generic extension TLVs",
    ),
    (
        CoverageFamily::Ipv4DscpEcn,
        "IPv4 DSCP and ECN differentiated services field",
    ),
    (
        CoverageFamily::Ipv4Fragment,
        "IPv4 fragmentation fields without reassembly",
    ),
    (
        CoverageFamily::Ipv4Options,
        "IPv4 route or traceroute options",
    ),
    (CoverageFamily::Ipv4TcpOptions, "IPv4 TCP SYN options"),
    (CoverageFamily::Ipv4TcpBgp, "IPv4 TCP BGP messages"),
    (CoverageFamily::Ipv4UdpDnsQuery, "IPv4 UDP DNS query"),
    (CoverageFamily::Ipv4UdpDnsResponse, "IPv4 UDP DNS response"),
    (
        CoverageFamily::Ipv4UdpDnsSoaSrv,
        "IPv4 UDP DNS SOA and SRV records",
    ),
    (
        CoverageFamily::Ipv4UdpDnsDnssec,
        "IPv4 UDP DNS DNSSEC wire records",
    ),
    (
        CoverageFamily::Ipv4UdpDnsSvcbHttps,
        "IPv4 UDP DNS SVCB and HTTPS records",
    ),
    (
        CoverageFamily::Ipv4UdpDnsEdnsOpt,
        "IPv4 UDP DNS EDNS(0) OPT pseudo-record",
    ),
    (
        CoverageFamily::Ipv4UdpDnsRawUnknown,
        "IPv4 UDP DNS unknown and deferred raw records",
    ),
    (
        CoverageFamily::Ipv4UdpDnsSectionPlacement,
        "IPv4 UDP DNS four-section placement",
    ),
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
    (
        CoverageFamily::IpsecEsp,
        "IPSec ESP datagram (RFC 4303) over IPv4",
    ),
    (
        CoverageFamily::IpsecAh,
        "IPSec AH datagram (RFC 4302) over IPv4",
    ),
    (
        CoverageFamily::IpsecIkev2,
        "IPSec IKEv2 IKE_SA_INIT message (RFC 7296) over UDP",
    ),
];

const REQUIRED_PCAP_COVERAGE: &[(PcapCoverageFamily, &str)] = &[
    (PcapCoverageFamily::Ethernet, "Ethernet pcap link type"),
    (
        PcapCoverageFamily::Ieee80211,
        "IEEE 802.11 pcap with WPA2-PSK CCMP fixture",
    ),
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
        "ipv4-igmp-v1-query"
        | "ipv4-igmp-v1-report"
        | "ipv4-igmp-v2-query"
        | "ipv4-igmp-v2-report"
        | "ipv4-igmp-v2-leave" => &[CoverageFamily::Ipv4IgmpBootstrap],
        "ipv4-igmp-v3-query-extension" | "ipv4-igmp-v3-report-extension" => {
            &[CoverageFamily::Ipv4IgmpExtension]
        }
        "ipv4-udp-dscp-ecn-raw" => &[CoverageFamily::Ipv4DscpEcn],
        "ipv4-fragment-noninitial-raw"
        | "ipv4-fragment-defrag-complete-final"
        | "ipv4-fragment-defrag-complete-first"
        | "ipv4-fragment-defrag-duplicate-final"
        | "ipv4-fragment-defrag-duplicate-first"
        | "ipv4-fragment-defrag-duplicate-repeat"
        | "ipv4-fragment-defrag-missing-final"
        | "ipv4-fragment-defrag-missing-first"
        | "ipv4-fragment-defrag-overlap-conflict"
        | "ipv4-fragment-defrag-overlap-first"
        | "ipv4-fragment-ipfragment-generated-first"
        | "ipv4-fragment-ipfragment-generated-final" => &[CoverageFamily::Ipv4Fragment],
        "ipv4-options-traceroute-udp-raw" => &[CoverageFamily::Ipv4Options],
        "ipv4-tcp-syn-options" | "ipv4-tcp-syn-rich-options" => &[CoverageFamily::Ipv4TcpOptions],
        "ipv4-tcp-bgp-open"
        | "ipv4-tcp-bgp-update-announce"
        | "ipv4-tcp-bgp-notification"
        | "ipv4-tcp-bgp-keepalive"
        | "ethernet-ipv4-tcp-bgp-open"
        | "ethernet-ipv4-tcp-bgp-keepalive"
        | "ethernet-ipv4-tcp-bgp-update-announce" => &[CoverageFamily::Ipv4TcpBgp],
        "ipv4-udp-dns-query-example-com" => &[CoverageFamily::Ipv4UdpDnsQuery],
        "ipv4-udp-dns-response-example-com" => &[CoverageFamily::Ipv4UdpDnsResponse],
        "ipv4-udp-dns-soa-srv-response" => &[CoverageFamily::Ipv4UdpDnsSoaSrv],
        "ipv4-udp-dns-dnssec-response" => &[CoverageFamily::Ipv4UdpDnsDnssec],
        "ipv4-udp-dns-svcb-https-response" => &[CoverageFamily::Ipv4UdpDnsSvcbHttps],
        "ipv4-udp-dns-edns-opt-query" => &[CoverageFamily::Ipv4UdpDnsEdnsOpt],
        "ipv4-udp-dns-raw-unknown-records-response" => &[CoverageFamily::Ipv4UdpDnsRawUnknown],
        "ipv4-udp-dns-section-placement-response" => &[CoverageFamily::Ipv4UdpDnsSectionPlacement],
        "ipv4-udp-dhcp-discover" => &[CoverageFamily::Ipv4UdpDhcp],
        "ospf-hello-single-neighbor"
        | "ospf-database-description"
        | "ospf-link-state-request"
        | "ospf-link-state-ack"
        | "ospf-link-state-update"
        | "ospf-router-lsa"
        | "ospf-network-lsa"
        | "ospf-summary-lsa-ip"
        | "ospf-summary-lsa-asbr"
        | "ospf-as-external-lsa"
        | "ospf-nssa-lsa"
        | "ospf-opaque-lsa-area"
        | "ospf-te-lsa"
        | "ospf-hello-simple-auth"
        | "ospf-hello-crypto-md5" => &[CoverageFamily::Ipv4Ospf],
        "ospfv3-hello" | "ospfv3-router-lsa" => &[CoverageFamily::Ipv6Ospfv3],
        "ipv4-udp-options-known" | "ipv4-udp-options-unknown-safe" => {
            &[CoverageFamily::Ipv4UdpOptions]
        }
        "ipv6-icmp-echo-request" => &[CoverageFamily::Ipv6IcmpEcho],
        "ipv6-icmpv6-time-exceeded" => &[CoverageFamily::Ipv6IcmpError],
        "ipv6-udp-raw" | "ipv6-base-traffic-flow-udp-raw" => &[CoverageFamily::Ipv6Udp],
        "ipv6-options-hop-destination-udp"
        | "ipv6-routing-generic-unknown-raw"
        | "ipv6-mobile-routing-raw"
        | "ipv6-segment-routing-raw" => &[CoverageFamily::Ipv6ExtensionHeader],
        "ipv6-udp-options-unknown-unsafe" | "ipv6-udp-options-frag" => {
            &[CoverageFamily::Ipv6UdpOptions]
        }
        "ipv6-tcp-raw" | "ipv6-tcp-rich-options" => &[CoverageFamily::Ipv6Tcp],
        "ipv6-fragment-udp-raw"
        | "ipv6-fragment-atomic-udp-raw"
        | "ipv6-fragment-non-initial-udp-raw"
        | "ipv6-fragment-oracle-reference-first"
        | "ipv6-fragment-oracle-reference-final" => &[CoverageFamily::Ipv6ExtensionHeader],
        "ipv4-esp-aead-gcm-opaque" | "ipv4-esp-cbc-hmac-opaque" => &[CoverageFamily::IpsecEsp],
        "ipv4-ah-hmac-sha256-transport" => &[CoverageFamily::IpsecAh],
        "ipv4-udp-ikev2-sa-init" => &[CoverageFamily::IpsecIkev2],
        "ipv4-udp-rip-v1-request" | "ipv4-udp-rip-v2-auth-response" => {
            &[CoverageFamily::Ipv4UdpRip]
        }
        "ipv6-udp-ripng-response" => &[CoverageFamily::Ipv6UdpRipng],
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
        .chain(DOT11_FIXTURES.iter())
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("pcap fixture references unknown packet fixture {name}"))
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

fn ipv4_fragment_record_from_fixture(name: &str, timestamp_micros: u32) -> PacketRecord {
    let case = valid_fixture_case(name);
    let bytes = fixture_bytes_for_case(case);
    let packet = decode_packet(packet_target_for_case(case), &bytes)
        .unwrap_or_else(|err| panic!("fixture {} should decode: {err}", case.path));
    let len = bytes.len() as u32;

    PacketRecord::new(packet)
        .with_origin(PacketOrigin::Captured)
        .with_backend(BackendKind::PcapFile)
        .with_file(fixture_path(case.path))
        .with_pcap_metadata(
            PcapTimestamp::micros(14, timestamp_micros)
                .unwrap_or_else(|err| panic!("fixture timestamp should be valid: {err}")),
            len,
            len,
            PcapLinkType::RawIp,
        )
        .with_captured_bytes(bytes)
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
            ExpectedLayer::Radiotap => {
                let _ = expect_layer::<Radiotap>(case, packet);
            }
            ExpectedLayer::Dot11 => {
                let _ = expect_layer::<Dot11>(case, packet);
            }
            ExpectedLayer::LlcSnap => {
                let _ = expect_layer::<LlcSnap>(case, packet);
            }
            ExpectedLayer::Eapol => {
                let _ = expect_layer::<Eapol>(case, packet);
            }
            ExpectedLayer::EapolKey => {
                let _ = expect_layer::<EapolKey>(case, packet);
            }
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
            ExpectedLayer::Ipv6HopByHopOptions => {
                let _ = expect_layer::<Ipv6HopByHopOptionsHeader>(case, packet);
            }
            ExpectedLayer::Ipv6DestinationOptions => {
                let _ = expect_layer::<Ipv6DestinationOptionsHeader>(case, packet);
            }
            ExpectedLayer::Ipv6Routing => {
                let _ = expect_layer::<Ipv6RoutingHeader>(case, packet);
            }
            ExpectedLayer::Ipv6MobileRouting => {
                let _ = expect_layer::<Ipv6MobileRoutingHeader>(case, packet);
            }
            ExpectedLayer::Ipv6SegmentRouting => {
                let _ = expect_layer::<Ipv6SegmentRoutingHeader>(case, packet);
            }
            ExpectedLayer::Ipv6Fragment => {
                let _ = expect_layer::<Ipv6FragmentHeader>(case, packet);
            }
            ExpectedLayer::Icmp => {
                let _ = expect_layer::<Icmpv4>(case, packet);
            }
            ExpectedLayer::Igmp => {
                let _ = expect_layer::<Igmp>(case, packet);
            }
            ExpectedLayer::IgmpQuery => {
                let _ = expect_layer::<IgmpQuery>(case, packet);
            }
            ExpectedLayer::IgmpReport => {
                let _ = expect_layer::<IgmpReport>(case, packet);
            }
            ExpectedLayer::IgmpExtension => {
                let _ = expect_layer::<IgmpExtension>(case, packet);
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
            ExpectedLayer::Bgp => {
                let _ = expect_layer::<Bgp>(case, packet);
            }
            ExpectedLayer::Rip => {
                let _ = expect_layer::<Rip>(case, packet);
            }
            ExpectedLayer::Ripng => {
                let _ = expect_layer::<Ripng>(case, packet);
            }
            ExpectedLayer::Dns => {
                let _ = expect_layer::<Dns>(case, packet);
            }
            ExpectedLayer::Dhcp => {
                let _ = expect_layer::<Dhcp>(case, packet);
            }
            ExpectedLayer::Ospf => {
                let _ = expect_layer::<Ospfv2>(case, packet);
            }
            ExpectedLayer::Ospfv3 => {
                let _ = expect_layer::<Ospfv3>(case, packet);
            }
            ExpectedLayer::Esp => {
                let _ = expect_layer::<Esp>(case, packet);
            }
            ExpectedLayer::Ah => {
                let _ = expect_layer::<Ah>(case, packet);
            }
            ExpectedLayer::IkeHeader => {
                let _ = expect_layer::<IkeHeader>(case, packet);
            }
            ExpectedLayer::IkeSaPayload => {
                let _ = expect_layer::<IkeSaPayload>(case, packet);
            }
            ExpectedLayer::IkeKePayload => {
                let _ = expect_layer::<IkeKePayload>(case, packet);
            }
            ExpectedLayer::IkeNoncePayload => {
                let _ = expect_layer::<IkeNoncePayload>(case, packet);
            }
            ExpectedLayer::Raw => {
                let _ = expect_layer::<Raw>(case, packet);
            }
        };
    }
}

fn assert_exact_layer_stack(case: &ValidFixtureCase, packet: &Packet) {
    let actual = packet.iter().map(|layer| layer.name()).collect::<Vec<_>>();
    let expected = case
        .expected_layers
        .iter()
        .copied()
        .map(expected_layer_name)
        .collect::<Vec<_>>();

    assert_eq!(
        actual, expected,
        "fixture {} decoded with unexpected layer order",
        case.path
    );
}

fn expected_layer_name(expected: ExpectedLayer) -> &'static str {
    match expected {
        ExpectedLayer::Radiotap => "Radiotap",
        ExpectedLayer::Dot11 => "Dot11",
        ExpectedLayer::LlcSnap => "LlcSnap",
        ExpectedLayer::Eapol => "Eapol",
        ExpectedLayer::EapolKey => "EapolKey",
        ExpectedLayer::Ethernet => "Ethernet",
        ExpectedLayer::LinuxSll => "LinuxSll",
        ExpectedLayer::NullLoopback => "NullLoopback",
        ExpectedLayer::Vlan => "Vlan",
        ExpectedLayer::Arp => "Arp",
        ExpectedLayer::Ipv4 => "Ipv4",
        ExpectedLayer::Ipv6 => "Ipv6",
        ExpectedLayer::Ipv6HopByHopOptions => "Ipv6HopByHopOptionsHeader",
        ExpectedLayer::Ipv6DestinationOptions => "Ipv6DestinationOptionsHeader",
        ExpectedLayer::Ipv6Routing => "Ipv6RoutingHeader",
        ExpectedLayer::Ipv6MobileRouting => "Ipv6MobileRoutingHeader",
        ExpectedLayer::Ipv6SegmentRouting => "Ipv6SegmentRoutingHeader",
        ExpectedLayer::Ipv6Fragment => "Ipv6FragmentHeader",
        ExpectedLayer::Icmp => "Icmpv4",
        ExpectedLayer::Igmp => "Igmp",
        ExpectedLayer::IgmpQuery => "IgmpQuery",
        ExpectedLayer::IgmpReport => "IgmpReport",
        ExpectedLayer::IgmpExtension => "IgmpExtension",
        ExpectedLayer::Icmpv6 => "Icmpv6",
        ExpectedLayer::Tcp => "Tcp",
        ExpectedLayer::Udp => "Udp",
        ExpectedLayer::UdpOptions => "UdpOptions",
        ExpectedLayer::Bgp => "BGP",
        ExpectedLayer::Rip => "Rip",
        ExpectedLayer::Ripng => "Ripng",
        ExpectedLayer::Dns => "Dns",
        ExpectedLayer::Dhcp => "Dhcp",
        ExpectedLayer::Ospf => "Ospf",
        ExpectedLayer::Ospfv3 => "Ospfv3",
        ExpectedLayer::Esp => "Esp",
        ExpectedLayer::Ah => "Ah",
        ExpectedLayer::IkeHeader => "IkeHeader",
        ExpectedLayer::IkeSaPayload => "IkeSaPayload",
        ExpectedLayer::IkeKePayload => "IkeKePayload",
        ExpectedLayer::IkeNoncePayload => "IkeNoncePayload",
        ExpectedLayer::Raw => "Raw",
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

fn assert_ipv4_fragment_defrag_fixture_fields(case: &ValidFixtureCase, packet: &Packet) {
    let (host_octet, identification, flags, offset, payload): (u8, u16, u8, u16, &'static [u8]) =
        match case.name {
            "ipv4-fragment-defrag-complete-final" => (70, 0x5141, 0, 1, b"ijklmnop"),
            "ipv4-fragment-defrag-complete-first" => {
                (70, 0x5141, IPV4_FLAG_MORE_FRAGMENTS, 0, b"abcdefgh")
            }
            "ipv4-fragment-defrag-duplicate-final" => (71, 0x5142, 0, 1, b"IJKLMNOP"),
            "ipv4-fragment-defrag-duplicate-first" | "ipv4-fragment-defrag-duplicate-repeat" => {
                (71, 0x5142, IPV4_FLAG_MORE_FRAGMENTS, 0, b"ABCDEFGH")
            }
            "ipv4-fragment-defrag-missing-final" => (72, 0x5143, 0, 2, b"tail"),
            "ipv4-fragment-defrag-missing-first" => {
                (72, 0x5143, IPV4_FLAG_MORE_FRAGMENTS, 0, b"missfrag")
            }
            "ipv4-fragment-defrag-overlap-conflict" => (73, 0x5144, 0, 1, b"QRSTUVWX"),
            "ipv4-fragment-defrag-overlap-first" => {
                (73, 0x5144, IPV4_FLAG_MORE_FRAGMENTS, 0, b"abcdefghijklmnop")
            }
            other => panic!("fixture {other} is not an IPv4 defrag fixture"),
        };

    let ipv4 = expect_layer::<Ipv4>(case, packet);
    assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, host_octet));
    assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, host_octet));
    assert_eq!(ipv4.identification_value(), identification);
    assert_eq!(ipv4.flags_value(), flags);
    assert_eq!(
        ipv4.has_more_fragments(),
        flags & IPV4_FLAG_MORE_FRAGMENTS != 0
    );
    assert_eq!(ipv4.fragment_offset_value(), offset);
    assert!(ipv4.is_fragmented());
    assert_eq!(ipv4.ttl_value(), 64);
    assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);
    assert_eq!(ipv4.total_length_value(), Some((20 + payload.len()) as u16));
    assert_eq!(ipv4.checksum_status(), Ipv4ChecksumStatus::Valid);
    assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), payload);

    let compiled = packet
        .compile()
        .unwrap_or_else(|err| panic!("fixture {} should compile: {err}", case.path));
    assert_eq!(compiled.as_bytes(), fixture_bytes_for_case(case).as_slice());
}

fn assert_ipv4_ipfragment_generated_fixture_fields(case: &ValidFixtureCase, packet: &Packet) {
    let (flags, offset, total_len, payload): (u8, u16, u16, Vec<u8>) = match case.name {
        "ipv4-fragment-ipfragment-generated-first" => {
            (IPV4_FLAG_MORE_FRAGMENTS, 0, 44, (0x40u8..0x58).collect())
        }
        "ipv4-fragment-ipfragment-generated-final" => (0, 3, 28, (0x58u8..0x60).collect()),
        other => panic!("fixture {other} is not an IpFragment-generated IPv4 fixture"),
    };

    let ipv4 = expect_layer::<Ipv4>(case, packet);
    assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 74));
    assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 74));
    assert_eq!(ipv4.identification_value(), 0x5145);
    assert_eq!(ipv4.flags_value(), flags);
    assert_eq!(
        ipv4.has_more_fragments(),
        flags & IPV4_FLAG_MORE_FRAGMENTS != 0
    );
    assert_eq!(ipv4.fragment_offset_value(), offset);
    assert!(ipv4.is_fragmented());
    assert_eq!(ipv4.ttl_value(), 43);
    assert_eq!(ipv4.protocol_value(), 253);
    assert_eq!(ipv4.ds_field_value(), 0x29);
    assert_eq!(ipv4.total_length_value(), Some(total_len));
    assert_eq!(ipv4.checksum_status(), Ipv4ChecksumStatus::Valid);
    assert_eq!(
        expect_layer::<Raw>(case, packet).as_bytes(),
        payload.as_slice()
    );
}

fn assert_ipv6_oracle_reference_fixture_fields(case: &ValidFixtureCase, packet: &Packet) {
    let (offset, more_fragments, payload_len, payload): (u16, bool, u16, Vec<u8>) = match case.name
    {
        "ipv6-fragment-oracle-reference-first" => (0, true, 32, (0x60u8..0x78).collect()),
        "ipv6-fragment-oracle-reference-final" => (3, false, 16, (0x78u8..0x80).collect()),
        other => panic!("fixture {other} is not an oracle reference IPv6 fragment fixture"),
    };

    let ipv6 = expect_layer::<Ipv6>(case, packet);
    assert_eq!(
        ipv6.source(),
        Ipv6Addr::new(0x2001, 0x0db8, 0x0074, 0, 0, 0, 0, 0x0040)
    );
    assert_eq!(
        ipv6.destination(),
        Ipv6Addr::new(0x2001, 0x0db8, 0x0074, 0, 0, 0, 0, 0x0041)
    );
    assert_eq!(ipv6.traffic_class_value(), 0x40);
    assert_eq!(ipv6.flow_label_value(), 0x74040);
    assert_eq!(ipv6.hop_limit_value(), 41);
    assert_eq!(ipv6.payload_length_value(), Some(payload_len));
    assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_FRAGMENT);

    let fragment = expect_layer::<Ipv6FragmentHeader>(case, packet);
    assert_eq!(fragment.next_header_value(), 253);
    assert_eq!(fragment.fragment_offset_value(), offset);
    assert_eq!(fragment.fragment_offset_bytes(), u32::from(offset) * 8);
    assert_eq!(fragment.has_more_fragments(), more_fragments);
    assert_eq!(fragment.is_last_fragment(), !more_fragments);
    assert_eq!(fragment.identification_value(), 0x1203_0040);
    assert_eq!(
        fragment.fragment_status(),
        if offset == 0 {
            Ipv6FragmentHeaderStatus::Initial
        } else {
            Ipv6FragmentHeaderStatus::NonInitial
        }
    );
    assert_eq!(
        expect_layer::<Raw>(case, packet).as_bytes(),
        payload.as_slice()
    );
}

fn assert_dot11_fixture_fields(case: &ValidFixtureCase, packet: &Packet) {
    match case.name {
        "dot11-bare-data" => {
            let dot11 = expect_layer::<Dot11>(case, packet);
            assert_eq!(dot11.data_subtype(), Some(Dot11DataSubtype::Data));
            assert_eq!(dot11.sequence_number_value(), Some(1));
            assert!(!dot11.is_protected());
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"bare-data");
        }
        "dot11-qos-data" => {
            let dot11 = expect_layer::<Dot11>(case, packet);
            assert_eq!(dot11.data_subtype(), Some(Dot11DataSubtype::QosData));
            assert_eq!(dot11.sequence_number_value(), Some(2));
            assert_eq!(dot11.qos_control_value(), Some(0x1205));
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"qos-data");
        }
        "dot11-protected-data" => {
            let dot11 = expect_layer::<Dot11>(case, packet);
            let raw = expect_layer::<Raw>(case, packet);
            assert!(dot11.is_protected());
            assert_eq!(dot11.encrypted_body_len(), Some(12));
            assert_eq!(
                raw.as_bytes(),
                &[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef]
            );
            assert!(packet.layer::<LlcSnap>().is_none());
            assert!(packet.layer::<Ipv4>().is_none());
        }
        "dot11-beacon-tags" => {
            let dot11 = expect_layer::<Dot11>(case, packet);
            assert_eq!(
                dot11.management_subtype(),
                Some(Dot11ManagementSubtype::Beacon)
            );
            let tags = dot11.tagged_parameters();
            assert_eq!(tags.len(), 4);
            assert_eq!(tags[0].id(), 0);
            assert_eq!(tags[0].value(), b"crafter");
            assert_eq!(tags[1].id(), 1);
            assert_eq!(tags[1].value(), &[0x82, 0x84, 0x8b, 0x96]);
            assert_eq!(tags[2].id(), 3);
            assert_eq!(tags[2].value(), &[6]);
            assert_eq!(tags[3].id(), 5);
            assert_eq!(tags[3].value(), &[0, 1, 0, 0]);
        }
        "dot11-radiotap-data" => {
            let radiotap = expect_layer::<Radiotap>(case, packet);
            let dot11 = expect_layer::<Dot11>(case, packet);
            assert_eq!(radiotap.length_value(), Some(10));
            assert_eq!(radiotap.rate_value(), Some(0x16));
            assert_eq!(dot11.data_subtype(), Some(Dot11DataSubtype::Data));
            assert_eq!(dot11.sequence_number_value(), Some(5));
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"radiotap");
        }
        "dot11-llc-snap-ipv4" => {
            let llc = expect_layer::<LlcSnap>(case, packet);
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(llc.ethertype_value(), ETHERTYPE_IPV4);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 20));
            assert_eq!(ipv4.protocol_value(), 253);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"v4");
        }
        "dot11-llc-snap-eapol" => {
            let llc = expect_layer::<LlcSnap>(case, packet);
            let eapol = expect_layer::<Eapol>(case, packet);
            let raw = expect_layer::<Raw>(case, packet);
            assert_eq!(llc.ethertype_value(), ETHERTYPE_EAPOL);
            assert_eq!(eapol.version_value(), 2);
            assert_eq!(eapol.packet_type_value(), 0);
            assert_eq!(eapol.body_length_value(), Some(5));
            assert_eq!(raw.as_bytes(), &[0x01, 0x02, 0x00, 0x05, 0x01]);
        }
        "dot11-eapol-key" => {
            let llc = expect_layer::<LlcSnap>(case, packet);
            let eapol = expect_layer::<Eapol>(case, packet);
            let key = expect_layer::<EapolKey>(case, packet);
            assert_eq!(llc.ethertype_value(), ETHERTYPE_EAPOL);
            assert_eq!(eapol.version_value(), 2);
            assert_eq!(eapol.packet_type_value(), 3);
            assert_eq!(eapol.body_length_value(), Some(95));
            assert_eq!(key.descriptor_type_value(), 2);
            assert_eq!(key.key_information_value().bits(), 0x13ca);
            assert_eq!(key.key_length_value(), 16);
            assert_eq!(key.replay_counter_value(), 1);
            assert_eq!(key.key_data_length_value(), Some(0));
            assert!(key.key_data_bytes().is_empty());
        }
        "dot11-rsn-ie" => {
            let dot11 = expect_layer::<Dot11>(case, packet);
            assert_eq!(
                dot11.management_subtype(),
                Some(Dot11ManagementSubtype::Beacon)
            );
            let tags = dot11.tagged_parameters();
            let rsn = tags
                .iter()
                .find(|tag| tag.id() == 48)
                .expect("RSN tag must be present");
            assert_eq!(
                rsn.value(),
                &[
                    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01,
                    0x00, 0x00, 0x0f, 0xac, 0x02, 0x0c, 0x00,
                ]
            );
        }
        "dot11-wpa2-psk-ccmp-beacon" => {
            let dot11 = expect_layer::<Dot11>(case, packet);
            assert_eq!(
                dot11.management_subtype(),
                Some(Dot11ManagementSubtype::Beacon)
            );
            assert_eq!(
                dot11.addr2_value(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, 0x01]))
            );
            assert_eq!(
                dot11.addr3_value(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, 0x01]))
            );

            let tags = dot11.tagged_parameters();
            let ssid = tags
                .iter()
                .find(|tag| tag.id() == 0)
                .expect("WPA fixture beacon should carry SSID");
            assert_eq!(ssid.value(), b"libcrafter-wpa");
            assert!(tags.iter().any(|tag| tag.id() == 48));
        }
        "dot11-wpa2-psk-ccmp-message-1" => {
            let dot11 = expect_layer::<Dot11>(case, packet);
            assert_eq!(
                dot11.addr1_value(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, 0x02]))
            );
            assert_eq!(
                dot11.addr2_value(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, 0x01]))
            );
            assert_eq!(
                dot11.addr3_value(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, 0x01]))
            );

            let llc = expect_layer::<LlcSnap>(case, packet);
            assert_eq!(llc.ethertype_value(), ETHERTYPE_EAPOL);
            let key = expect_layer::<EapolKey>(case, packet);
            assert_eq!(key.replay_counter_value(), 77);
            assert_eq!(key.nonce_value(), [0x41; 32]);
            assert!(key.key_information_value().key_ack());
            assert!(!key.key_information_value().key_mic());
        }
        "dot11-wpa2-psk-ccmp-message-2" => {
            let dot11 = expect_layer::<Dot11>(case, packet);
            assert_eq!(
                dot11.addr1_value(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, 0x01]))
            );
            assert_eq!(
                dot11.addr2_value(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, 0x02]))
            );
            assert_eq!(
                dot11.addr3_value(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, 0x01]))
            );

            let key = expect_layer::<EapolKey>(case, packet);
            assert_eq!(key.replay_counter_value(), 77);
            assert_eq!(key.nonce_value(), [0x62; 32]);
            assert!(key.key_information_value().key_mic());
            assert!(key.mic_value().iter().any(|byte| *byte != 0));
            assert_eq!(key.key_data_bytes(), &[0x30, 0x14]);
        }
        "dot11-wpa2-psk-ccmp-unicast-data" => {
            let dot11 = expect_layer::<Dot11>(case, packet);
            assert!(dot11.is_protected());
            assert_eq!(
                dot11.addr1_value(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, 0x01]))
            );
            assert_eq!(
                dot11.addr2_value(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, 0x02]))
            );
            assert_eq!(
                dot11.addr3_value(),
                Some(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, 0x03]))
            );
            assert_eq!(dot11.sequence_number_value(), Some(0x333));

            let encrypted = expect_layer::<Raw>(case, packet).as_bytes();
            assert!(encrypted.len() > 16);
            assert_eq!(encrypted[0], 0x33);
            assert_eq!(encrypted[3] & 0x20, 0x20);
            assert_eq!(encrypted[3] >> 6, 1);
        }
        other => panic!("dot11 fixture {other} is missing typed field assertions"),
    }
}

fn assert_bgp_fixture_fields(case: &ValidFixtureCase, packet: &Packet) {
    assert_exact_layer_stack(case, packet);

    let ipv4 = expect_layer::<Ipv4>(case, packet);
    assert!(is_documentation_ip(IpAddr::V4(ipv4.source())));
    assert!(is_documentation_ip(IpAddr::V4(ipv4.destination())));
    assert_eq!(ipv4.protocol_value(), IPPROTO_TCP);

    let tcp = expect_layer::<Tcp>(case, packet);
    assert!(
        tcp.source_port_value() == 179 || tcp.destination_port_value() == 179,
        "fixture {} should use TCP/179 for BGP, got sport={} dport={}",
        case.path,
        tcp.source_port_value(),
        tcp.destination_port_value()
    );

    if case.name.starts_with("ethernet-ipv4-tcp-bgp-") {
        let ethernet = expect_layer::<Ethernet>(case, packet);
        assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_IPV4));
        match case.name {
            "ethernet-ipv4-tcp-bgp-open" => {
                assert_eq!(
                    ethernet.source(),
                    Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
                );
                assert_eq!(
                    ethernet.destination(),
                    Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x02]))
                );
            }
            "ethernet-ipv4-tcp-bgp-keepalive" | "ethernet-ipv4-tcp-bgp-update-announce" => {
                assert_eq!(
                    ethernet.source(),
                    Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x02]))
                );
                assert_eq!(
                    ethernet.destination(),
                    Some(MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
                );
            }
            _ => unreachable!("BGP Ethernet fixture names are matched by prefix"),
        }
    }

    assert_eq!(packet.layers::<Bgp>().count(), 1);
    let summary = expect_layer::<Bgp>(case, packet).summary();
    match case.name {
        "ipv4-tcp-bgp-open" | "ethernet-ipv4-tcp-bgp-open" => {
            assert!(summary.starts_with("BGP OPEN "), "{summary}");
        }
        "ipv4-tcp-bgp-update-announce" | "ethernet-ipv4-tcp-bgp-update-announce" => {
            assert!(summary.starts_with("BGP UPDATE "), "{summary}");
            assert!(summary.contains("203.0.113.0/24"), "{summary}");
        }
        "ipv4-tcp-bgp-notification" => {
            assert!(summary.starts_with("BGP NOTIFICATION "), "{summary}");
        }
        "ipv4-tcp-bgp-keepalive" | "ethernet-ipv4-tcp-bgp-keepalive" => {
            assert_eq!(summary, "BGP KEEPALIVE len=19");
        }
        _ => unreachable!("BGP fixture names are matched before dispatch"),
    }
}

fn assert_igmp_fixture_fields(case: &ValidFixtureCase, packet: &Packet) {
    assert_exact_layer_stack(case, packet);

    let ipv4 = expect_layer::<Ipv4>(case, packet);
    assert_eq!(ipv4.protocol_value(), IPPROTO_IGMP);

    let igmp = expect_layer::<Igmp>(case, packet);
    match case.name {
        "ipv4-igmp-v1-query" => {
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(233, 252, 0, 1));
            assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
            assert_eq!(igmp.code_value(), IGMP_QUERY_CODE_V1);
            assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);
        }
        "ipv4-igmp-v1-report" => {
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 20));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(233, 252, 0, 42));
            assert_eq!(igmp.igmp_type(), IgmpType::V1MembershipReport);
            assert_eq!(igmp.code_value(), 0);
            assert_eq!(igmp.group_address_value(), Ipv4Addr::new(233, 252, 0, 42));
        }
        "ipv4-igmp-v2-query" => {
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 30));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 1));
            assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
            assert_eq!(igmp.code_value(), 100);
            assert_eq!(igmp.v2_max_response_time_tenths(), 100);
            assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);
        }
        "ipv4-igmp-v2-report" => {
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 40));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(233, 252, 0, 43));
            assert_eq!(igmp.igmp_type(), IgmpType::V2MembershipReport);
            assert_eq!(igmp.code_value(), 0);
            assert_eq!(igmp.group_address_value(), Ipv4Addr::new(233, 252, 0, 43));
        }
        "ipv4-igmp-v2-leave" => {
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 50));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 2));
            assert_eq!(igmp.igmp_type(), IgmpType::V2LeaveGroup);
            assert_eq!(igmp.code_value(), 0);
            assert_eq!(igmp.group_address_value(), Ipv4Addr::new(233, 252, 0, 17));
        }
        "ipv4-igmp-mrd-advertisement" => {
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 90));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 106));
            assert_eq!(ipv4.ttl_value(), 1);
            assert_eq!(igmp.igmp_type(), IgmpType::MulticastRouterAdvertisement);
            assert_eq!(igmp.mrd_advertisement_interval_value(), 20);
            assert_eq!(igmp.mrd_query_interval_value(), 125);
            assert_eq!(igmp.mrd_robustness_variable_value(), 2);
            assert_eq!(igmp.checksum_value(), Some(0xcf6c));
        }
        "ipv4-igmp-mrd-solicitation" => {
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 91));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 2));
            assert_eq!(ipv4.ttl_value(), 1);
            assert_eq!(igmp.igmp_type(), IgmpType::MulticastRouterSolicitation);
            assert_eq!(igmp.mrd_reserved_value(), 0);
            assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);
            assert_eq!(igmp.checksum_value(), Some(0xceff));
        }
        "ipv4-igmp-mrd-termination" => {
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 92));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 106));
            assert_eq!(ipv4.ttl_value(), 1);
            assert_eq!(igmp.igmp_type(), IgmpType::MulticastRouterTermination);
            assert_eq!(igmp.mrd_reserved_value(), 0);
            assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);
            assert_eq!(igmp.checksum_value(), Some(0xcdff));
        }
        "ipv4-igmp-v3-query-extension" => {
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 80));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(233, 252, 0, 80));
            assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
            assert_eq!(igmp.code_value(), 100);
            assert_eq!(igmp.group_address_value(), Ipv4Addr::new(233, 252, 0, 80));

            let query = expect_layer::<IgmpQuery>(case, packet);
            assert_eq!(query.raw_flags_qrv_value(), 0x82);
            assert!(query.extension_flag());
            assert_eq!(query.querier_robustness_variable(), 2);
            assert_eq!(query.qqic_value(), 0x7d);
            assert_eq!(query.number_of_sources_value(), 1);
            assert_eq!(query.source_addresses(), &[Ipv4Addr::new(198, 51, 100, 80)]);

            let extension = expect_layer::<IgmpExtension>(case, packet);
            assert_eq!(extension.extension_type(), IgmpExtensionType::Unassigned(0x1234));
            assert_eq!(extension.extension_type_value(), 0x1234);
            assert_eq!(extension.extension_length_value(), 4);
            assert_eq!(extension.value_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        }
        "ipv4-igmp-v3-report-extension" => {
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 81));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 22));
            assert_eq!(igmp.igmp_type(), IgmpType::V3MembershipReport);
            assert_eq!(igmp.code_value(), 0);
            assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);

            let report = expect_layer::<IgmpReport>(case, packet);
            assert_eq!(report.report_flags_value(), 0x8000);
            assert!(report.extension_flag());
            assert_eq!(report.number_of_group_records_value(), 1);
            let record = &report.group_records()[0];
            assert_eq!(record.record_type(), IgmpRecordType::ModeIsInclude);
            assert_eq!(record.multicast_address(), Ipv4Addr::new(233, 252, 0, 81));
            assert_eq!(record.source_addresses(), &[Ipv4Addr::new(203, 0, 113, 81)]);

            let extension = expect_layer::<IgmpExtension>(case, packet);
            assert_eq!(extension.extension_type(), IgmpExtensionType::Experimental(0xfffe));
            assert_eq!(extension.extension_type_value(), 0xfffe);
            assert_eq!(extension.extension_length_value(), 2);
            assert_eq!(extension.value_bytes(), &[0xca, 0xfe]);
        }
        other => panic!("IGMP fixture {other} is missing typed field assertions"),
    }
}

fn assert_fixture_fields(case: &ValidFixtureCase, packet: &Packet) {
    match case.name {
        name if name.starts_with("dot11-") => assert_dot11_fixture_fields(case, packet),
        name if name.starts_with("ipv4-tcp-bgp-") || name.starts_with("ethernet-ipv4-tcp-bgp-") => {
            assert_bgp_fixture_fields(case, packet)
        }
        name if name.starts_with("ipv4-fragment-defrag-") => {
            assert_ipv4_fragment_defrag_fixture_fields(case, packet)
        }
        name if name.starts_with("ipv4-fragment-ipfragment-generated-") => {
            assert_ipv4_ipfragment_generated_fixture_fields(case, packet)
        }
        name if name.starts_with("ipv6-fragment-oracle-reference-") => {
            assert_ipv6_oracle_reference_fixture_fields(case, packet)
        }
        name if name.starts_with("ipv4-igmp-") => assert_igmp_fixture_fields(case, packet),
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

            let icmp = expect_layer::<Icmpv4>(case, packet);
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

            let icmp = expect_layer::<Icmpv4>(case, packet);
            assert_eq!(icmp.icmp_type_value(), ICMP_DESTINATION_UNREACHABLE);
            assert_eq!(icmp.kind_value(), Some(IcmpKind::DestinationUnreachable));
            assert_eq!(icmp.code_value(), 3);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"orig-v4");
        }
        "ipv4-udp-dscp-ecn-raw" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 20));
            assert_eq!(ipv4.identification_value(), 0x2260);
            assert!(ipv4.is_dont_fragment());
            assert_eq!(ipv4.ttl_value(), 64);
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);
            assert_eq!(ipv4.ds_field_value(), 0xbb);
            assert_eq!(ipv4.tos_value(), 0xbb);
            assert_eq!(ipv4.dscp_value(), Dscp::new(46).expect("DSCP EF"));
            assert_eq!(ipv4.ecn_value(), Ecn::Ce);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 53_014);
            assert_eq!(udp.destination_port_value(), 10_014);
            assert_eq!(udp.length_value(), Some(UDP_HEADER_LEN as u16 + 7));
            assert_eq!(udp.checksum_value(), Some(0));
            assert_eq!(udp.checksum_status(), UdpChecksumStatus::Ipv4NoChecksum);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"ds-ecn!");

            assert_eq!(
                packet.summary(),
                "Ipv4(src=192.0.2.10, dst=198.51.100.20, proto=udp(17), ds=dscp=46/ecn=CE, flags=DF) / Udp(sport=53014, dport=10014, len=15, checksum_status=Ipv4NoChecksum) / Raw(len=7)"
            );
            let compiled = packet
                .compile()
                .unwrap_or_else(|err| panic!("fixture {} should compile: {err}", case.path));
            assert_eq!(compiled.as_bytes()[1], 0xbb);
        }
        "ipv4-fragment-noninitial-raw" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 44));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 44));
            assert_eq!(ipv4.identification_value(), 0x4a6f);
            assert_eq!(
                ipv4.flags_value(),
                IPV4_FLAG_RESERVED | IPV4_FLAG_DONT_FRAGMENT | IPV4_FLAG_MORE_FRAGMENTS
            );
            assert!(ipv4.is_reserved_flag_set());
            assert!(ipv4.is_dont_fragment());
            assert!(ipv4.has_more_fragments());
            assert_eq!(ipv4.fragment_offset_value(), 0x0123);
            assert!(ipv4.is_fragmented());
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

            let fragment_info = ipv4.fragment_info();
            assert_eq!(fragment_info.identification(), 0x4a6f);
            assert_eq!(
                fragment_info.flags(),
                IPV4_FLAG_RESERVED | IPV4_FLAG_DONT_FRAGMENT | IPV4_FLAG_MORE_FRAGMENTS
            );
            assert!(fragment_info.is_reserved_flag_set());
            assert!(fragment_info.is_dont_fragment());
            assert!(fragment_info.has_more_fragments());
            assert_eq!(fragment_info.fragment_offset(), 0x0123);
            assert!(fragment_info.is_fragmented());

            assert_eq!(
                expect_layer::<Raw>(case, packet).as_bytes(),
                b"\xde\xad\xbe\xefnoninit"
            );
            assert_eq!(
                packet.summary(),
                "Ipv4(src=192.0.2.44, dst=198.51.100.44, proto=udp(17), flags=reserved|DF|MF, fragment_offset=291) / Raw(len=11)"
            );
            let compiled = packet
                .compile()
                .unwrap_or_else(|err| panic!("fixture {} should compile: {err}", case.path));
            assert_eq!(compiled.as_bytes(), fixture_bytes_for_case(case).as_slice());
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
                    Ipv4Option::timestamp(9, 0, vec![0x0102_0304]),
                    Ipv4Option::router_alert(0),
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
        "ipv4-tcp-syn-rich-options" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 20));
            assert_eq!(ipv4.identification_value(), 0x2256);
            assert_eq!(ipv4.protocol_value(), IPPROTO_TCP);

            let tcp = expect_layer::<Tcp>(case, packet);
            assert_eq!(tcp.source_port_value(), 44_444);
            assert_eq!(tcp.destination_port_value(), 443);
            assert_eq!(tcp.sequence_number_value(), 0x0102_0304);
            assert_eq!(tcp.flags_value(), TCP_FLAG_SYN);
            // MSS, Window Scale, SACK Permitted, Timestamp, the RFC 5482 User
            // Timeout typed option (kind 28), and a classified Generic option
            // (kind 222) all survive decode and recompile.
            assert_eq!(
                tcp.parsed_options().unwrap_or_else(|err| {
                    panic!("fixture {} TCP options should parse: {err}", case.path)
                }),
                vec![
                    TcpOption::MaximumSegmentSize(1460),
                    TcpOption::WindowScale(7),
                    TcpOption::SackPermitted,
                    TcpOption::Timestamp {
                        value: 398_303_815,
                        echo_reply: 12_345,
                    },
                    TcpOption::UserTimeout {
                        granularity: true,
                        value: 240,
                    },
                    TcpOption::generic(222, vec![0xde, 0xad, 0xbe, 0xef]),
                    TcpOption::EndOfList,
                ]
            );
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"syn-rich");
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
        "ipv4-udp-dns-soa-srv-response" => {
            let dns = expect_layer::<Dns>(case, packet);
            assert_eq!(dns.id_value(), 0x2a01);
            assert!(dns.is_response());

            assert_eq!(dns.answers().len(), 1);
            let srv = &dns.answers()[0];
            assert_eq!(srv.record_type(), DNS_TYPE_SRV);
            assert_eq!(srv.name(), "_sip._tcp.example.com.");
            assert_eq!(
                srv.data(),
                &DnsRecordData::Srv {
                    priority: 10,
                    weight: 60,
                    port: 5060,
                    target: DnsName::parse("sipserver.example.com.").unwrap(),
                }
            );

            assert_eq!(dns.authorities().len(), 1);
            let soa = &dns.authorities()[0];
            assert_eq!(soa.record_type(), DNS_TYPE_SOA);
            assert_eq!(
                soa.data(),
                &DnsRecordData::Soa {
                    mname: DnsName::parse("ns1.example.com.").unwrap(),
                    rname: DnsName::parse("hostmaster.example.com.").unwrap(),
                    serial: 2_024_010_101,
                    refresh: 7200,
                    retry: 3600,
                    expire: 1_209_600,
                    minimum: 3600,
                }
            );
        }
        "ipv4-udp-dns-dnssec-response" => {
            let dns = expect_layer::<Dns>(case, packet);
            assert_eq!(dns.id_value(), 0x2a02);
            assert!(dns.is_response());

            assert_eq!(dns.answers().len(), 2);
            let dnskey = &dns.answers()[0];
            assert_eq!(dnskey.record_type(), DNS_TYPE_DNSKEY);
            assert_eq!(
                dnskey.data(),
                &DnsRecordData::Dnskey {
                    flags: 256,
                    protocol: 3,
                    algorithm: 8,
                    public_key: vec![0x03, 0x01, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef],
                }
            );
            let rrsig = &dns.answers()[1];
            assert_eq!(rrsig.record_type(), DNS_TYPE_RRSIG);
            assert_eq!(
                rrsig.data(),
                &DnsRecordData::Rrsig {
                    type_covered: DNS_TYPE_DNSKEY,
                    algorithm: 8,
                    labels: 2,
                    original_ttl: 3600,
                    signature_expiration: 1_735_689_600,
                    signature_inception: 1_733_011_200,
                    key_tag: 12345,
                    signer_name: DnsName::parse("example.com.").unwrap(),
                    signature: vec![0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89],
                }
            );

            assert_eq!(dns.authorities().len(), 3);
            let ds = &dns.authorities()[0];
            assert_eq!(ds.record_type(), DNS_TYPE_DS);
            match ds.data() {
                DnsRecordData::Ds {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                } => {
                    assert_eq!(*key_tag, 12345);
                    assert_eq!(*algorithm, 8);
                    assert_eq!(*digest_type, 2);
                    assert_eq!(digest.len(), 32);
                }
                other => panic!("expected DS RDATA, got {other:?}"),
            }

            let nsec = &dns.authorities()[1];
            assert_eq!(nsec.record_type(), DNS_TYPE_NSEC);
            match nsec.data() {
                DnsRecordData::Nsec {
                    next_domain_name,
                    type_bitmaps,
                } => {
                    assert_eq!(next_domain_name.presentation(), "mail.example.com.");
                    assert!(type_bitmaps.contains(DNS_TYPE_A));
                    assert!(type_bitmaps.contains(DNS_TYPE_RRSIG));
                    assert!(type_bitmaps.contains(DNS_TYPE_AAAA));
                    assert!(!type_bitmaps.contains(DNS_TYPE_DNSKEY));
                }
                other => panic!("expected NSEC RDATA, got {other:?}"),
            }

            let nsec3 = &dns.authorities()[2];
            assert_eq!(nsec3.record_type(), DNS_TYPE_NSEC3);
            match nsec3.data() {
                DnsRecordData::Nsec3 {
                    hash_algorithm,
                    flags,
                    iterations,
                    salt,
                    next_hashed_owner_name,
                    type_bitmaps,
                } => {
                    assert_eq!(*hash_algorithm, 1);
                    assert_eq!(*flags, 0);
                    assert_eq!(*iterations, 10);
                    assert_eq!(salt, &vec![0xaa, 0xbb, 0xcc, 0xdd]);
                    assert_eq!(next_hashed_owner_name.len(), 20);
                    assert!(type_bitmaps.contains(DNS_TYPE_A));
                    assert!(type_bitmaps.contains(DNS_TYPE_RRSIG));
                }
                other => panic!("expected NSEC3 RDATA, got {other:?}"),
            }
        }
        "ipv4-udp-dns-svcb-https-response" => {
            let dns = expect_layer::<Dns>(case, packet);
            assert_eq!(dns.id_value(), 0x2a03);
            assert!(dns.is_response());
            assert_eq!(dns.answers().len(), 2);

            let https = &dns.answers()[0];
            assert_eq!(https.record_type(), DNS_TYPE_HTTPS);
            match https.data() {
                DnsRecordData::Https {
                    priority,
                    target,
                    params,
                } => {
                    assert_eq!(*priority, 1);
                    assert_eq!(target.presentation(), "svc.example.com.");
                    // SvcParams are stored in strictly increasing key order.
                    let keys: Vec<u16> = params.params().iter().map(|p| p.key()).collect();
                    assert_eq!(
                        keys,
                        vec![
                            DNS_SVCB_KEY_ALPN,
                            DNS_SVCB_KEY_PORT,
                            DNS_SVCB_KEY_IPV4HINT,
                            DNS_SVCB_KEY_IPV6HINT,
                        ]
                    );
                    assert_eq!(params.get(DNS_SVCB_KEY_PORT), Some([0x01, 0xbb].as_slice()));
                }
                other => panic!("expected HTTPS RDATA, got {other:?}"),
            }

            let svcb = &dns.answers()[1];
            assert_eq!(svcb.record_type(), DNS_TYPE_SVCB);
            match svcb.data() {
                DnsRecordData::Svcb {
                    priority,
                    target,
                    params,
                } => {
                    assert_eq!(*priority, 2);
                    assert_eq!(target.presentation(), "svc.example.com.");
                    assert_eq!(params.get(DNS_SVCB_KEY_PORT), Some([0x20, 0xfb].as_slice()));
                }
                other => panic!("expected SVCB RDATA, got {other:?}"),
            }
        }
        "ipv4-udp-dns-raw-unknown-records-response" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(198, 51, 100, 53));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 53);
            assert_eq!(udp.destination_port_value(), 53_001);

            let dns = expect_layer::<Dns>(case, packet);
            assert_eq!(dns.id_value(), 0x2a05);
            assert!(dns.is_response());
            assert_eq!(dns.questions().len(), 1);
            assert_eq!(dns.questions()[0].name(), "example.com.");

            // An unknown TYPE (65280, RFC 6895 private use) stays opaque rather
            // than being mis-mapped to a typed record.
            assert_eq!(dns.answers().len(), 1);
            let unknown = &dns.answers()[0];
            assert_eq!(unknown.name(), "example.com.");
            assert_eq!(unknown.record_type(), 65_280);
            assert_eq!(
                unknown.data(),
                &DnsRecordData::Raw(vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02])
            );

            // A deferred well-known TYPE (NSEC3PARAM, 51) is likewise carried as
            // raw RDATA in the additional section.
            assert_eq!(dns.additionals().len(), 1);
            let deferred = &dns.additionals()[0];
            assert_eq!(deferred.record_type(), 51);
            assert_eq!(
                deferred.data(),
                &DnsRecordData::Raw(vec![0x01, 0x00, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd])
            );
            assert_eq!(dns.authorities().len(), 0);
        }
        "ipv4-udp-dns-section-placement-response" => {
            let dns = expect_layer::<Dns>(case, packet);
            assert_eq!(dns.id_value(), 0x2a06);
            assert!(dns.is_response());

            // Each of the four DNS sections is populated and survives decode in
            // place: 1 question, 1 answer, 1 authority, 2 additionals.
            assert_eq!(dns.questions().len(), 1);
            assert_eq!(dns.questions()[0].name(), "example.com.");
            assert_eq!(dns.questions()[0].question_type(), DNS_TYPE_A);

            assert_eq!(dns.answers().len(), 1);
            let answer = &dns.answers()[0];
            assert_eq!(answer.record_type(), DNS_TYPE_A);
            assert_eq!(
                answer.data(),
                &DnsRecordData::A(Ipv4Addr::new(192, 0, 2, 10))
            );

            assert_eq!(dns.authorities().len(), 1);
            let authority = &dns.authorities()[0];
            assert_eq!(authority.record_type(), DNS_TYPE_NS);
            assert_eq!(authority.data(), &DnsRecordData::name("ns1.example.com."));

            // The additional section keeps a non-OPT glue A record before the
            // OPT pseudo-record; neither migrates to another section.
            assert_eq!(dns.additionals().len(), 2);
            let glue = &dns.additionals()[0];
            assert_eq!(glue.name(), "ns1.example.com.");
            assert_eq!(glue.record_type(), DNS_TYPE_A);
            assert!(!glue.is_opt());
            assert_eq!(
                glue.data(),
                &DnsRecordData::A(Ipv4Addr::new(198, 51, 100, 53))
            );
            let opt = &dns.additionals()[1];
            assert_eq!(opt.record_type(), DNS_TYPE_OPT);
            assert!(opt.is_opt());
            assert_eq!(opt.edns_udp_payload_size(), 1232);
            assert!(!opt.edns_dnssec_ok());
        }
        "ipv4-udp-dns-edns-opt-query" => {
            let dns = expect_layer::<Dns>(case, packet);
            assert_eq!(dns.id_value(), 0x2a04);
            assert!(!dns.is_response());
            assert_eq!(dns.questions().len(), 1);
            assert_eq!(dns.questions()[0].question_type(), DNS_TYPE_A);

            assert_eq!(dns.additionals().len(), 1);
            let opt = &dns.additionals()[0];
            assert_eq!(opt.record_type(), DNS_TYPE_OPT);
            assert!(opt.is_opt());
            assert_eq!(
                opt.edns_udp_payload_size(),
                DNS_EDNS_DEFAULT_UDP_PAYLOAD_SIZE
            );
            assert!(opt.edns_dnssec_ok());
            let options = opt.edns_options().expect("OPT record exposes EDNS options");
            assert_eq!(options.len(), 3);
            assert_eq!(options[0].code(), DNS_EDNS_OPTION_COOKIE);
            assert_eq!(options[1].code(), DNS_EDNS_OPTION_NSID);
            assert_eq!(options[2].code(), 0xfffe);
            assert_eq!(options[2].data(), &[0xde, 0xad]);
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
        "ipv6-base-traffic-flow-udp-raw" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0049, 0, 0, 0, 0, 0x0010)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0049, 0, 0, 0, 0, 0x0020)
            );
            assert_eq!(ipv6.traffic_class_value(), 0xbb);
            assert_eq!(ipv6.dscp_value().value(), 46);
            assert_eq!(ipv6.ecn_value().value(), 3);
            assert_eq!(ipv6.flow_label_value(), 0xabcde);
            assert_eq!(ipv6.payload_length_value(), Some(16));
            assert_eq!(ipv6.next_header_value(), IPPROTO_UDP);
            assert_eq!(ipv6.hop_limit_value(), 37);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 54_049);
            assert_eq!(udp.destination_port_value(), 1_049);
            assert_eq!(udp.length_value(), Some(16));
            assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"base-v6!");
        }
        "ipv6-options-hop-destination-udp" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0050, 0, 0, 0, 0, 0x0010)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0050, 0, 0, 0, 0, 0x0020)
            );
            assert_eq!(ipv6.traffic_class_value(), 0x5a);
            assert_eq!(ipv6.flow_label_value(), 0x50050);
            assert_eq!(ipv6.payload_length_value(), Some(55));
            assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_HOPOPTS);
            assert_eq!(ipv6.hop_limit_value(), 50);

            let hop_by_hop = expect_layer::<Ipv6HopByHopOptionsHeader>(case, packet);
            assert_eq!(hop_by_hop.next_header_value(), IPPROTO_IPV6_DSTOPTS);
            assert_eq!(hop_by_hop.header_ext_len_value(), Some(1));
            assert_eq!(
                hop_by_hop.options_value(),
                &[
                    Ipv6Option::router_alert(1),
                    Ipv6Option::jumbo_payload(65_536),
                    Ipv6Option::unknown(0x13, []).unwrap(),
                    Ipv6Option::pad1(),
                    Ipv6Option::pad1(),
                ]
            );

            let destination_options = expect_layer::<Ipv6DestinationOptionsHeader>(case, packet);
            assert_eq!(destination_options.next_header_value(), IPPROTO_UDP);
            assert_eq!(destination_options.header_ext_len_value(), Some(2));
            assert_eq!(
                destination_options.options_value(),
                &[
                    Ipv6Option::home_address(Ipv6Addr::new(
                        0x2001, 0x0db8, 0x0050, 0, 0, 0, 0, 0x0040,
                    )),
                    Ipv6Option::unknown(0x1e, [0xee]).unwrap(),
                    Ipv6Option::pad1(),
                ]
            );

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 55_050);
            assert_eq!(udp.destination_port_value(), 1_050);
            assert_eq!(udp.length_value(), Some(15));
            assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"opts-v6");

            let show = packet.show();
            assert!(
                show.contains("options: Router Alert(0x05,value=RSVP(1)),Jumbo Payload(0xc2,length=65536),Generic(kind=0x13,len=0,act=0,chg=0,rest=0x13,data=empty),0x00,0x00"),
                "{show}"
            );
            assert!(
                show.contains("options: Home Address(0xc9,address=2001:db8:50::40),Generic(kind=0x1e,len=1,act=0,chg=0,rest=0x1e,data=ee),0x00"),
                "{show}"
            );
        }
        "ipv6-routing-generic-unknown-raw" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0051, 0, 0, 0, 0, 0x0010)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0051, 0, 0, 0, 0, 0x0020)
            );
            assert_eq!(ipv6.traffic_class_value(), 0x31);
            assert_eq!(ipv6.flow_label_value(), 0x51051);
            assert_eq!(ipv6.payload_length_value(), Some(21));
            assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_ROUTE);
            assert_eq!(ipv6.hop_limit_value(), 51);

            let routing = expect_layer::<Ipv6RoutingHeader>(case, packet);
            assert_eq!(routing.next_header_value(), IPPROTO_IPV6_EXPERIMENTAL_1);
            assert_eq!(routing.header_ext_len_value(), Some(1));
            assert_eq!(routing.routing_type_value(), 99);
            assert_eq!(routing.routing_type_label(), "Unknown");
            assert_eq!(
                routing.routing_type_status(),
                Ipv6RoutingTypeStatus::Unknown
            );
            assert_eq!(routing.segments_left_value(), 2);
            assert_eq!(
                routing.type_data_bytes(),
                &[0x63, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0]
            );
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"route");
        }
        "ipv6-mobile-routing-raw" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0052, 0, 0, 0, 0, 0x0010)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0052, 0, 0, 0, 0, 0x0020)
            );
            assert_eq!(ipv6.traffic_class_value(), 0x52);
            assert_eq!(ipv6.flow_label_value(), 0x52052);
            assert_eq!(ipv6.payload_length_value(), Some(33));
            assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_ROUTE);
            assert_eq!(ipv6.hop_limit_value(), 52);

            let mobile = expect_layer::<Ipv6MobileRoutingHeader>(case, packet);
            assert_eq!(mobile.next_header_value(), IPPROTO_IPV6_EXPERIMENTAL_1);
            assert_eq!(mobile.header_ext_len_value(), Some(2));
            assert_eq!(mobile.routing_type_value(), IPV6_ROUTING_TYPE_MOBILE);
            assert_eq!(
                mobile.routing_type_status(),
                Ipv6RoutingTypeStatus::Assigned
            );
            assert_eq!(
                mobile.validity_status(),
                Ipv6MobileRoutingHeaderStatus::Valid
            );
            assert_eq!(mobile.segments_left_value(), 1);
            assert_eq!(
                mobile.segments_left_status(),
                Ipv6MobileRoutingHeaderStatus::Valid
            );
            assert_eq!(mobile.reserved_value(), 0);
            assert_eq!(
                mobile.reserved_status(),
                Ipv6MobileRoutingHeaderStatus::Valid
            );
            assert_eq!(
                mobile.home_address_value(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0052, 0, 0, 0, 0, 0x0040)
            );
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"mobile-v6");
        }
        "ipv6-segment-routing-raw" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0053, 0, 0, 0, 0, 0x0010)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0053, 0, 0, 0, 0, 0x0020)
            );
            assert_eq!(ipv6.traffic_class_value(), 0x63);
            assert_eq!(ipv6.flow_label_value(), 0x53053);
            assert_eq!(ipv6.payload_length_value(), Some(62));
            assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_ROUTE);
            assert_eq!(ipv6.hop_limit_value(), 53);

            let segment = expect_layer::<Ipv6SegmentRoutingHeader>(case, packet);
            assert_eq!(segment.next_header_value(), IPPROTO_IPV6_EXPERIMENTAL_1);
            assert_eq!(segment.header_ext_len_value(), Some(6));
            assert_eq!(segment.routing_type_value(), IPV6_ROUTING_TYPE_SEGMENT);
            assert_eq!(
                segment.routing_type_status(),
                Ipv6RoutingTypeStatus::Assigned
            );
            assert_eq!(segment.segments_left_value(), 1);
            assert_eq!(segment.last_entry_value(), 1);
            assert_eq!(segment.first_segment_value(), 1);
            assert_eq!(segment.flags_value(), 0xa5);
            assert!(segment.c_flag_value());
            assert!(!segment.p_flag_value());
            assert_eq!(segment.reserved_value(), 2);
            assert_eq!(segment.tag_value(), 0x5353);
            assert_eq!(
                segment.segment_list(),
                &[
                    Ipv6Addr::new(0x2001, 0x0db8, 0x0053, 0, 0, 0, 0, 0x0030),
                    Ipv6Addr::new(0x2001, 0x0db8, 0x0053, 0, 0, 0, 0, 0x0040),
                ]
            );
            assert_eq!(
                segment.raw_trailing_data_bytes(),
                &[0x00, 0x01, 0x02, 0x00, 0x00, 0xee, 0x03, 0xaa, 0xbb, 0xcc, 0, 0, 0, 0, 0, 0]
            );
            assert_eq!(
                segment.extra_data_bytes(),
                segment.raw_trailing_data_bytes()
            );
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"srh-v6");

            let show = packet.show();
            assert!(show.contains("last_entry: 1"), "{show}");
            assert!(show.contains("flags: 0xa5"), "{show}");
            assert!(show.contains("tag: 0x5353"), "{show}");
            assert!(
                show.contains("raw_trailing_data: 00 01 02 00 00 ee 03 aa bb cc 00 00 00 00 00 00"),
                "{show}"
            );
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
        "ipv6-tcp-rich-options" => {
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
            assert_eq!(tcp.source_port_value(), 50_000);
            assert_eq!(tcp.destination_port_value(), 443);
            assert_eq!(tcp.sequence_number_value(), 0x1020_3040);
            assert_eq!(tcp.acknowledgment_number_value(), 0x5060_7080);
            assert_eq!(tcp.flags_value(), TCP_FLAG_SYN | TCP_FLAG_ACK);
            // Multiple TCP options decode under IPv6 (whose pseudo-header differs
            // from IPv4) and survive recompile byte-for-byte: MSS, Window Scale,
            // SACK Permitted, Timestamp, the RFC 5482 User Timeout typed option
            // (kind 28), and a classified Generic option (kind 222).
            assert_eq!(
                tcp.parsed_options().unwrap_or_else(|err| {
                    panic!("fixture {} TCP options should parse: {err}", case.path)
                }),
                vec![
                    TcpOption::MaximumSegmentSize(1460),
                    TcpOption::WindowScale(7),
                    TcpOption::SackPermitted,
                    TcpOption::Timestamp {
                        value: 398_303_815,
                        echo_reply: 12_345,
                    },
                    TcpOption::UserTimeout {
                        granularity: true,
                        value: 240,
                    },
                    TcpOption::generic(222, vec![0xde, 0xad, 0xbe, 0xef]),
                    TcpOption::EndOfList,
                ]
            );
            assert_eq!(
                expect_layer::<Raw>(case, packet).as_bytes(),
                b"ipv6-tcp-rich"
            );
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
            assert_eq!(fragment.fragment_offset_bytes(), 0);
            assert!(fragment.has_more_fragments());
            assert!(!fragment.is_last_fragment());
            assert_eq!(
                fragment.fragment_status(),
                Ipv6FragmentHeaderStatus::Initial
            );
            assert!(fragment.is_initial_fragment());
            assert!(!fragment.is_atomic_fragment());
            assert!(!fragment.is_non_initial_fragment());
            assert_eq!(fragment.identification_value(), 0x0102_0304);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 1234);
            assert_eq!(udp.destination_port_value(), 5678);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"frag-v6");
        }
        "ipv6-fragment-atomic-udp-raw" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0010, 0, 0, 0, 0, 0x0052)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0020, 0, 0, 0, 0, 0x0052)
            );
            assert_eq!(ipv6.payload_length_value(), Some(25));
            assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_FRAGMENT);

            let fragment = expect_layer::<Ipv6FragmentHeader>(case, packet);
            assert_eq!(fragment.next_header_value(), IPPROTO_UDP);
            assert_eq!(fragment.fragment_offset_value(), 0);
            assert_eq!(fragment.fragment_offset_bytes(), 0);
            assert!(!fragment.has_more_fragments());
            assert!(fragment.is_last_fragment());
            assert_eq!(fragment.fragment_status(), Ipv6FragmentHeaderStatus::Atomic);
            assert_eq!(fragment.status(), Ipv6FragmentHeaderStatus::Atomic);
            assert!(fragment.is_atomic_fragment());
            assert!(fragment.is_initial_fragment());
            assert!(!fragment.is_non_initial_fragment());
            assert_eq!(fragment.identification_value(), 0x6946_0052);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 6946);
            assert_eq!(udp.destination_port_value(), 6952);
            assert_eq!(udp.length_value(), Some(17));
            assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"atomic-v6");
        }
        "ipv6-fragment-non-initial-udp-raw" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0010, 0, 0, 0, 0, 0x0053)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0x2001, 0x0db8, 0x0020, 0, 0, 0, 0, 0x0053)
            );
            assert_eq!(ipv6.payload_length_value(), Some(26));
            assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_FRAGMENT);

            let fragment = expect_layer::<Ipv6FragmentHeader>(case, packet);
            assert_eq!(fragment.next_header_value(), IPPROTO_UDP);
            assert_eq!(fragment.fragment_offset_value(), 2);
            assert_eq!(fragment.fragment_offset_bytes(), 16);
            assert!(!fragment.has_more_fragments());
            assert!(fragment.is_last_fragment());
            assert_eq!(
                fragment.fragment_status(),
                Ipv6FragmentHeaderStatus::NonInitial
            );
            assert!(!fragment.is_atomic_fragment());
            assert!(!fragment.is_initial_fragment());
            assert!(fragment.is_non_initial_fragment());
            assert_eq!(fragment.identification_value(), 0x5200_0002);

            assert!(packet.layer::<Udp>().is_none());
            assert_eq!(
                expect_layer::<Raw>(case, packet).as_bytes(),
                b"\x1b\x5a\x1b\x5b\x00\x12\x37\x27noninit-v6"
            );
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
        "ipv4-esp-aead-gcm-opaque" | "ipv4-esp-cbc-hmac-opaque" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 20));
            // The enclosing IPv4 advertises ESP (protocol 50).
            assert_eq!(ipv4.protocol_value(), 50);

            let esp = expect_layer::<Esp>(case, packet);
            let expected_spi = if case.name == "ipv4-esp-aead-gcm-opaque" {
                0x0000_2100
            } else {
                0x0000_2800
            };
            assert_eq!(esp.spi_value(), Some(expected_spi));
            assert_eq!(esp.sequence_value(), Some(1));
            // No SA in the default registry: the encrypted body is opaque and the
            // sealed datagram carries no cleartext inner layers.
            assert!(
                esp.opaque_body().is_some(),
                "ESP fixture {} decodes opaquely without an SA",
                case.name
            );
            assert!(
                packet.layer::<Tcp>().is_none(),
                "no SA: the ESP inner TCP stays encrypted"
            );
        }
        "ipv4-ah-hmac-sha256-transport" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 20));
            // The enclosing IPv4 advertises AH (protocol 51).
            assert_eq!(ipv4.protocol_value(), 51);

            let ah = expect_layer::<Ah>(case, packet);
            assert_eq!(ah.spi_value(), Some(0x0000_3100));
            assert_eq!(ah.sequence_value(), Some(1));
            // AH Next Header dispatches the cleartext TCP upper layer.
            assert_eq!(ah.next_header_value(), Some(IPPROTO_TCP));
            // HMAC-SHA-256-128 emits a 16-octet ICV (RFC 4868), 32-bit aligned.
            assert_eq!(ah.icv_value().map(<[u8]>::len), Some(16));
            // No SA in the default registry: AH decodes opaque (no verify status).
            assert_eq!(ah.verification_status(), None);

            // AH only authenticates: the protected upper layer survives in clear.
            let tcp = expect_layer::<Tcp>(case, packet);
            assert_eq!(tcp.source_port_value(), 43000);
            assert_eq!(tcp.destination_port_value(), 443);
            assert_eq!(expect_layer::<Raw>(case, packet).as_bytes(), b"ah-golden");
        }
        "ipv4-udp-ikev2-sa-init" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 500);
            assert_eq!(udp.destination_port_value(), 500);

            let header = expect_layer::<IkeHeader>(case, packet);
            assert_eq!(header.initiator_spi_value(), Some(0x0102_0304_0506_0708));
            assert_eq!(header.exchange_type_value(), Some(34)); // IKE_SA_INIT
                                                                // The header's Next Payload names the first payload in the chain (SA).
            assert_eq!(header.next_payload_value(), Some(33));

            // The SA / KE / Ni payload chain all decode as typed layers.
            let _ = expect_layer::<IkeSaPayload>(case, packet);
            let ke = expect_layer::<IkeKePayload>(case, packet);
            // The KE payload preserves the D-H group it was built with (group 14).
            assert_eq!(ke.dh_group_num(), 14);
            let _ = expect_layer::<IkeNoncePayload>(case, packet);
        }
        "ipv4-udp-rip-v1-request" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 520);
            assert_eq!(udp.destination_port_value(), 520);

            // RFC 1058 §3.4.1 whole-table request: command Request (1), version 1,
            // a single AFI-0 sentinel entry with metric infinity (16).
            let rip = expect_layer::<Rip>(case, packet);
            assert_eq!(rip.command_value(), 1);
            assert_eq!(rip.version_value(), 1);
            assert_eq!(rip.entries().len(), 1);
            let entry = &rip.entries()[0];
            assert_eq!(entry.address_family_value(), 0);
            assert_eq!(entry.metric_value(), 16);
        }
        "ipv4-udp-rip-v2-auth-response" => {
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 10));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 9));
            assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 520);
            assert_eq!(udp.destination_port_value(), 520);

            // RFC 2082 Keyed-MD5 authenticated response: command Response (2),
            // version 2. On the wire the keyed-digest form is a leading AFI-0xFFFF
            // header entry, the two RIPv2 route entries (tag/mask/metric), and a
            // trailing AFI-0xFFFF digest block (also a 20-octet entry slot), all of
            // which decode as plain entries and round-trip byte-for-byte. (The
            // decode-side digest verifier is exercised by rip_golden.rs against the
            // freshly-compiled message; the keyed-digest fixture here covers the
            // read -> decode -> summary path.)
            let rip = expect_layer::<Rip>(case, packet);
            assert_eq!(rip.command_value(), 2);
            assert_eq!(rip.version_value(), 2);
            assert_eq!(rip.entries().len(), 4);
            let auth_header = &rip.entries()[0];
            assert_eq!(auth_header.address_family_value(), 0xffff);
            let first_route = &rip.entries()[1];
            assert_eq!(first_route.address_value(), Ipv4Addr::new(198, 51, 100, 0));
            assert_eq!(
                first_route.subnet_mask_value(),
                Ipv4Addr::new(255, 255, 255, 0)
            );
            assert_eq!(first_route.route_tag_value(), 64512);
            assert_eq!(first_route.metric_value(), 1);
            let second_route = &rip.entries()[2];
            assert_eq!(
                second_route.address_value(),
                Ipv4Addr::new(198, 51, 100, 128)
            );
            assert_eq!(
                second_route.subnet_mask_value(),
                Ipv4Addr::new(255, 255, 255, 128)
            );
            assert_eq!(second_route.route_tag_value(), 64513);
            assert_eq!(second_route.metric_value(), 2);
            let digest_trailer = &rip.entries()[3];
            assert_eq!(digest_trailer.address_family_value(), 0xffff);
        }
        "ipv6-udp-ripng-response" => {
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(
                ipv6.source(),
                Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010)
            );
            assert_eq!(
                ipv6.destination(),
                Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0009)
            );
            assert_eq!(ipv6.next_header_value(), IPPROTO_UDP);

            let udp = expect_layer::<Udp>(case, packet);
            assert_eq!(udp.source_port_value(), 521);
            assert_eq!(udp.destination_port_value(), 521);

            // RFC 2080 §2.1.1 / §2.2 response: command Response (2), a next-hop RTE
            // (metric 0xFF) followed by two route RTEs over documentation prefixes.
            let ripng = expect_layer::<Ripng>(case, packet);
            assert_eq!(ripng.command_value(), 2);
            assert_eq!(ripng.rtes().len(), 3);
            let next_hop = &ripng.rtes()[0];
            assert!(next_hop.is_next_hop());
            assert_eq!(
                next_hop.next_hop_address(),
                Some(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x00fe))
            );
            let first_route = &ripng.rtes()[1];
            assert!(!first_route.is_next_hop());
            assert_eq!(
                first_route.prefix_value(),
                Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0)
            );
            assert_eq!(first_route.prefix_len_value(), 48);
            assert_eq!(first_route.metric_value(), 1);
            let second_route = &ripng.rtes()[2];
            assert_eq!(
                second_route.prefix_value(),
                Ipv6Addr::new(0x2001, 0x0db8, 2, 0, 0, 0, 0, 0)
            );
            assert_eq!(second_route.prefix_len_value(), 48);
            assert_eq!(second_route.metric_value(), 2);
        }
        "ospf-hello-single-neighbor" => {
            // OSPF rides directly on IPv4 protocol 89 (RFC 2328).
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), 89);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 5));

            // Common header: version 2 Hello from a documentation router id in
            // the backbone area (0.0.0.0).
            let ospf = expect_layer::<Ospfv2>(case, packet);
            assert_eq!(ospf.version_value(), 2);
            assert_eq!(ospf.packet_type_value(), 1); // Hello
            assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // The Hello body fields are surfaced through the public inspection
            // surface (the typed body is private), including the single neighbor.
            let fields = ospf.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("network_mask"), Some("255.255.255.0"));
            assert_eq!(value_of("hello_interval"), Some("10"));
            assert_eq!(value_of("dead_interval"), Some("40"));
            assert_eq!(value_of("priority"), Some("1"));
            assert_eq!(value_of("designated_router"), Some("192.0.2.1"));
            assert_eq!(value_of("backup_designated_router"), Some("192.0.2.2"));
            assert_eq!(value_of("neighbor_count"), Some("1"));
            let neighbors: Vec<&str> = fields
                .iter()
                .filter(|(field, _)| *field == "neighbor")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(neighbors, vec!["192.0.2.2"]);
        }
        "ospf-database-description" => {
            // OSPF rides directly on IPv4 protocol 89 (RFC 2328).
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), 89);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 5));

            // Common header: a version 2 Database Description (type 2) from a
            // documentation router id in the backbone area (0.0.0.0).
            let ospf = expect_layer::<Ospfv2>(case, packet);
            assert_eq!(ospf.version_value(), 2);
            assert_eq!(ospf.packet_type_value(), 2); // Database Description
            assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // The Database Description body and its two carried LSA headers are
            // surfaced through the public inspection surface (the typed body is
            // private).
            let fields = ospf.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("interface_mtu"), Some("1500"));
            // The Options octet renders its raw hex plus the decoded RFC 2328
            // §A.2 capability labels (0x02 sets the E-bit).
            assert_eq!(value_of("options"), Some("0x02 (E)"));
            // flags carry the I, M, and MS bits (0x04 | 0x02 | 0x01); the
            // inspection rendering shows the raw hex plus the decoded labels.
            assert_eq!(value_of("dd_flags"), Some("0x07 (I|M|MS)"));
            assert_eq!(value_of("dd_sequence_number"), Some("0x00001a2b"));
            assert_eq!(value_of("lsa_header_count"), Some("2"));
            let lsa_headers: Vec<&str> = fields
                .iter()
                .filter(|(field, _)| *field == "lsa_header")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(lsa_headers.len(), 2);
        }
        "ospf-link-state-request" => {
            // OSPF rides directly on IPv4 protocol 89 (RFC 2328).
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), 89);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 5));

            // Common header: a version 2 Link State Request (type 3) from a
            // documentation router id in the backbone area (0.0.0.0).
            let ospf = expect_layer::<Ospfv2>(case, packet);
            assert_eq!(ospf.version_value(), 2);
            assert_eq!(ospf.packet_type_value(), 3); // Link State Request
            assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // The Link State Request body and its two carried entries are
            // surfaced through the public inspection surface (the typed body is
            // private). Each entry names one LSA by the RFC 2328 §A.3.4 triple:
            // a full 4-octet LS type, the Link State ID, and the Advertising
            // Router.
            let fields = ospf.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("request_count"), Some("2"));
            let requests: Vec<&str> = fields
                .iter()
                .filter(|(field, _)| *field == "request")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(
                requests,
                vec![
                    "ls_type=0x00000001, id=192.0.2.1, adv=192.0.2.1",
                    "ls_type=0x00000002, id=192.0.2.2, adv=198.51.100.7",
                ]
            );
        }
        "ospf-link-state-ack" => {
            // OSPF rides directly on IPv4 protocol 89 (RFC 2328).
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), 89);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 5));

            // Common header: a version 2 Link State Acknowledgment (type 5) from
            // a documentation router id in the backbone area (0.0.0.0).
            let ospf = expect_layer::<Ospfv2>(case, packet);
            assert_eq!(ospf.version_value(), 2);
            assert_eq!(ospf.packet_type_value(), 5); // Link State Acknowledgment
            assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // The Link State Acknowledgment body and its two carried LSA headers
            // are surfaced through the public inspection surface (the typed body
            // is private). The body is just the concatenation of bare 20-octet
            // LSA headers (RFC 2328 §A.3.6).
            let fields = ospf.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("lsa_header_count"), Some("2"));
            let lsa_headers: Vec<&str> = fields
                .iter()
                .filter(|(field, _)| *field == "lsa_header")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(
                lsa_headers,
                vec![
                    "LSA(type=Router, id=192.0.2.1, adv=192.0.2.1, seq=0x80000001, age=0, len=20)",
                    "LSA(type=Network, id=192.0.2.2, adv=198.51.100.7, seq=0x80000002, age=0, len=20)",
                ]
            );
        }
        "ospf-link-state-update" => {
            // OSPF rides directly on IPv4 protocol 89 (RFC 2328).
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), 89);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 5));

            // Common header: a version 2 Link State Update (type 4) from a
            // documentation router id in the backbone area (0.0.0.0).
            let ospf = expect_layer::<Ospfv2>(case, packet);
            assert_eq!(ospf.version_value(), 2);
            assert_eq!(ospf.packet_type_value(), 4); // Link State Update
            assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // The Link State Update body carries one LSA whose LS type (99) is
            // unknown, so its body is preserved verbatim as raw (RFC 2328
            // §A.3.5). The body is surfaced through the public inspection
            // surface (the typed body is private): `num_lsas` and `lsa_count`
            // both report one LSA, and the single `lsa` entry renders the
            // 20-octet header summary plus the 4-octet raw body length.
            let fields = ospf.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("num_lsas"), Some("1"));
            assert_eq!(value_of("lsa_count"), Some("1"));
            let lsas: Vec<&str> = fields
                .iter()
                .filter(|(field, _)| *field == "lsa")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(
                lsas,
                vec![concat!(
                    "LSA(type=Unknown, id=192.0.2.1, adv=192.0.2.1, ",
                    "seq=0x80000001, age=0, len=24) body=4B",
                )]
            );
        }
        "ospf-router-lsa" => {
            // OSPF rides directly on IPv4 protocol 89 (RFC 2328).
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), 89);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 5));

            // Common header: a version 2 Link State Update (type 4) from a
            // documentation router id in the backbone area (0.0.0.0).
            let ospf = expect_layer::<Ospfv2>(case, packet);
            assert_eq!(ospf.version_value(), 2);
            assert_eq!(ospf.packet_type_value(), 4); // Link State Update
            assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // The Link State Update carries one Router-LSA (LS type 1, RFC 2328
            // §A.4.2) describing two links: a point-to-point connection and a
            // stub network. The typed Router body is private, so it is surfaced
            // through the public inspection surface: `num_lsas`/`lsa_count`
            // report one LSA, the `lsa` entry renders the 20-octet header summary
            // plus the 28-octet Router body, a `router_lsa` pair reports the B
            // flag and the two-link count, and one `router_link` pair per link
            // names the link type, ids, and metric.
            let fields = ospf.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("num_lsas"), Some("1"));
            assert_eq!(value_of("lsa_count"), Some("1"));
            assert_eq!(
                value_of("lsa"),
                Some(concat!(
                    "LSA(type=Router, id=192.0.2.1, adv=192.0.2.1, ",
                    "seq=0x80000001, age=0, len=48) body=28B",
                ))
            );
            assert_eq!(value_of("router_lsa"), Some("flags=B links=2"));
            let router_links: Vec<&str> = fields
                .iter()
                .filter(|(field, _)| *field == "router_link")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(
                router_links,
                vec![
                    "type=PointToPoint, id=192.0.2.2, data=198.51.100.1, metric=10",
                    "type=Stub, id=198.51.100.0, data=255.255.255.0, metric=20",
                ]
            );
        }
        "ospf-network-lsa" => {
            // OSPF rides directly on IPv4 protocol 89 (RFC 2328).
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), 89);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 5));

            // Common header: a version 2 Link State Update (type 4) from a
            // documentation router id in the backbone area (0.0.0.0).
            let ospf = expect_layer::<Ospfv2>(case, packet);
            assert_eq!(ospf.version_value(), 2);
            assert_eq!(ospf.packet_type_value(), 4); // Link State Update
            assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // The Link State Update carries one Network-LSA (LS type 2, RFC 2328
            // §A.4.3) for a transit network: the 4-octet network mask followed by
            // two attached Router IDs (8 octets), a 12-octet body after the
            // 20-octet header. The typed Network body is private, so it is
            // surfaced through the public inspection surface:
            // `num_lsas`/`lsa_count` report one LSA, the `lsa` entry renders the
            // 20-octet header summary plus the 12-octet Network body, a
            // `network_lsa` pair reports the mask and the attached-router count,
            // and one `attached_router` pair per attached Router ID.
            let fields = ospf.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("num_lsas"), Some("1"));
            assert_eq!(value_of("lsa_count"), Some("1"));
            assert_eq!(
                value_of("lsa"),
                Some(concat!(
                    "LSA(type=Network, id=192.0.2.1, adv=192.0.2.1, ",
                    "seq=0x80000001, age=0, len=32) body=12B",
                ))
            );
            assert_eq!(
                value_of("network_lsa"),
                Some("mask=255.255.255.0 routers=2")
            );
            let attached_routers: Vec<&str> = fields
                .iter()
                .filter(|(field, _)| *field == "attached_router")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(attached_routers, vec!["192.0.2.1", "198.51.100.7"]);
        }
        "ospf-summary-lsa-ip" => {
            // OSPF rides directly on IPv4 protocol 89 (RFC 2328).
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), 89);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 5));

            // Common header: a version 2 Link State Update (type 4) from a
            // documentation router id in the backbone area (0.0.0.0).
            let ospf = expect_layer::<Ospfv2>(case, packet);
            assert_eq!(ospf.version_value(), 2);
            assert_eq!(ospf.packet_type_value(), 4); // Link State Update
            assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // The Link State Update carries one type 3 Summary-LSA (LS type 3,
            // RFC 2328 §A.4.4) describing a route to an IP network: the 4-octet
            // network mask followed by two TOS/metric entries (8 octets), a
            // 12-octet body after the 20-octet header. The typed Summary body is
            // private, so it is surfaced through the public inspection surface:
            // `num_lsas`/`lsa_count` report one LSA, the `lsa` entry renders the
            // 20-octet header summary plus the 12-octet Summary body, a
            // `summary_lsa` pair reports the mask, the TOS 0 metric, and the
            // entry count, and one `summary_tos` pair per TOS/metric entry.
            let fields = ospf.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("num_lsas"), Some("1"));
            assert_eq!(value_of("lsa_count"), Some("1"));
            assert_eq!(
                value_of("lsa"),
                Some(concat!(
                    "LSA(type=Summary-IP, id=198.51.100.0, adv=192.0.2.1, ",
                    "seq=0x80000001, age=0, len=32) body=12B",
                ))
            );
            assert_eq!(
                value_of("summary_lsa"),
                Some("mask=255.255.255.0 metric=10 tos=2")
            );
            let summary_tos: Vec<&str> = fields
                .iter()
                .filter(|(field, _)| *field == "summary_tos")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(summary_tos, vec!["tos=0 metric=10", "tos=2 metric=30"]);
        }
        "ospf-summary-lsa-asbr" => {
            // OSPF rides directly on IPv4 protocol 89 (RFC 2328).
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), 89);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 5));

            // Common header: a version 2 Link State Update (type 4) from a
            // documentation router id in the backbone area (0.0.0.0).
            let ospf = expect_layer::<Ospfv2>(case, packet);
            assert_eq!(ospf.version_value(), 2);
            assert_eq!(ospf.packet_type_value(), 4); // Link State Update
            assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // The Link State Update carries one type 4 Summary-LSA (LS type 4,
            // RFC 2328 §A.4.4) describing a route to an AS boundary router: the
            // network mask is not meaningful and is zero, followed by a single
            // TOS 0 metric entry, an 8-octet body after the 20-octet header. The
            // typed Summary body is private, so it is surfaced through the public
            // inspection surface: `num_lsas`/`lsa_count` report one LSA, the
            // `lsa` entry renders the 20-octet header summary plus the 8-octet
            // Summary body, a `summary_lsa` pair reports the zero mask, the
            // TOS 0 metric, and the single entry, and one `summary_tos` pair
            // names the TOS 0 metric.
            let fields = ospf.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("num_lsas"), Some("1"));
            assert_eq!(value_of("lsa_count"), Some("1"));
            assert_eq!(
                value_of("lsa"),
                Some(concat!(
                    "LSA(type=Summary-ASBR, id=192.0.2.9, adv=192.0.2.1, ",
                    "seq=0x80000001, age=0, len=28) body=8B",
                ))
            );
            assert_eq!(
                value_of("summary_lsa"),
                Some("mask=0.0.0.0 metric=20 tos=1")
            );
            let summary_tos: Vec<&str> = fields
                .iter()
                .filter(|(field, _)| *field == "summary_tos")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(summary_tos, vec!["tos=0 metric=20"]);
        }
        "ospf-as-external-lsa" => {
            // OSPF rides directly on IPv4 protocol 89 (RFC 2328).
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), 89);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 5));

            // Common header: a version 2 Link State Update (type 4) from a
            // documentation router id in the backbone area (0.0.0.0).
            let ospf = expect_layer::<Ospfv2>(case, packet);
            assert_eq!(ospf.version_value(), 2);
            assert_eq!(ospf.packet_type_value(), 4); // Link State Update
            assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // The Link State Update carries one type 5 AS-External-LSA (LS type
            // 5, RFC 2328 §A.4.5) describing an external route: the 4-octet
            // network mask followed by two 12-octet external metric entries (one
            // Type 1 / E1, one Type 2 / E2), a 28-octet body after the 20-octet
            // header. The typed AS-External body is private, so it is surfaced
            // through the public inspection surface: `num_lsas`/`lsa_count`
            // report one LSA, the `lsa` entry renders the 20-octet header summary
            // plus the 28-octet AS-External body, an `as_external_lsa` pair
            // reports the mask, the TOS 0 metric and its metric type, and the
            // entry count, and one `as_external_tos` pair per external metric
            // entry naming the metric type, metric, forwarding address, and
            // external route tag.
            let fields = ospf.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("num_lsas"), Some("1"));
            assert_eq!(value_of("lsa_count"), Some("1"));
            assert_eq!(
                value_of("lsa"),
                Some(concat!(
                    "LSA(type=AS-External, id=198.51.100.0, adv=192.0.2.1, ",
                    "seq=0x80000001, age=0, len=48) body=28B",
                ))
            );
            assert_eq!(
                value_of("as_external_lsa"),
                Some("mask=255.255.255.0 metric=10 type=E1 tos=2")
            );
            let as_external_tos: Vec<&str> = fields
                .iter()
                .filter(|(field, _)| *field == "as_external_tos")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(
                as_external_tos,
                vec![
                    "type=E1 metric=10 fwd=0.0.0.0 tag=0x00000000",
                    "type=E2 metric=20 fwd=192.0.2.9 tag=0xdeadbeef",
                ]
            );
        }
        "ospf-nssa-lsa" => {
            // OSPF rides directly on IPv4 protocol 89 (RFC 2328).
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), 89);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 5));

            // Common header: a version 2 Link State Update (type 4) from a
            // documentation router id in the backbone area (0.0.0.0).
            let ospf = expect_layer::<Ospfv2>(case, packet);
            assert_eq!(ospf.version_value(), 2);
            assert_eq!(ospf.packet_type_value(), 4); // Link State Update
            assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // The Link State Update carries one type 7 NSSA-LSA (LS type 7, RFC
            // 3101 §2.2) describing an external route within a not-so-stubby
            // area: the 4-octet network mask followed by a single 12-octet
            // external metric entry (Type 2 / E2), a 16-octet body after the
            // 20-octet header. The N/P-bit is set in the enclosing LSA header
            // Options field (RFC 3101 §2.5) so the area's translating border
            // router propagates the route as a Type-5 AS-External-LSA. The typed
            // NSSA body is private, so it is surfaced through the public
            // inspection surface: `num_lsas`/`lsa_count` report one LSA, the
            // `lsa` entry renders the 20-octet header summary plus the 16-octet
            // NSSA body, an `nssa_lsa` pair reports the P-bit, the mask, the
            // TOS 0 metric and its metric type, and the entry count, and one
            // `nssa_tos` pair per external metric entry naming the metric type,
            // metric, forwarding address, and external route tag.
            let fields = ospf.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("num_lsas"), Some("1"));
            assert_eq!(value_of("lsa_count"), Some("1"));
            assert_eq!(
                value_of("lsa"),
                Some(concat!(
                    "LSA(type=NSSA, id=198.51.100.0, adv=192.0.2.1, ",
                    "seq=0x80000001, age=0, len=36) body=16B",
                ))
            );
            assert_eq!(
                value_of("nssa_lsa"),
                Some("P=set mask=255.255.255.0 metric=658188 type=E2 tos=1")
            );
            let nssa_tos: Vec<&str> = fields
                .iter()
                .filter(|(field, _)| *field == "nssa_tos")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(
                nssa_tos,
                vec!["type=E2 metric=658188 fwd=0.0.0.0 tag=0x00000000"]
            );
        }
        "ospf-opaque-lsa-area" => {
            // OSPF rides directly on IPv4 protocol 89 (RFC 2328).
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), 89);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 5));

            // Common header: a version 2 Link State Update (type 4) from a
            // documentation router id in the backbone area (0.0.0.0).
            let ospf = expect_layer::<Ospfv2>(case, packet);
            assert_eq!(ospf.version_value(), 2);
            assert_eq!(ospf.packet_type_value(), 4); // Link State Update
            assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // The Link State Update carries one area-scope Opaque-LSA (LS type 10,
            // RFC 5250 §3) whose Link State ID packs the Opaque Type (10) into the
            // first octet and a 24-bit Opaque ID (0x010203) into the remaining
            // three, rendering as 10.1.2.3. The body is two generic Opaque TLVs: a
            // 4-octet (already aligned) value and a 5-octet value padded to the
            // next 4-octet boundary, for a 20-octet body after the 20-octet header.
            // The typed Opaque body is private, so it is surfaced through the
            // public inspection surface: `num_lsas`/`lsa_count` report one LSA, the
            // `lsa` entry renders the 20-octet header summary plus the 20-octet
            // Opaque body, an `opaque_lsa` pair reports the Opaque Type read from
            // the header Link State ID plus the TLV count, and one `opaque_tlv`
            // pair per TLV naming the TLV type and its value byte length (the
            // padding is not counted).
            let fields = ospf.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("num_lsas"), Some("1"));
            assert_eq!(value_of("lsa_count"), Some("1"));
            assert_eq!(
                value_of("lsa"),
                Some(concat!(
                    "LSA(type=Opaque-Area, id=10.1.2.3, adv=192.0.2.1, ",
                    "seq=0x80000001, age=0, len=40) body=20B",
                ))
            );
            assert_eq!(value_of("opaque_lsa"), Some("type=10 tlvs=2"));
            let opaque_tlv: Vec<&str> = fields
                .iter()
                .filter(|(field, _)| *field == "opaque_tlv")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(opaque_tlv, vec!["type=1 value=4B", "type=2 value=5B"]);
        }
        "ospf-te-lsa" => {
            // OSPF rides directly on IPv4 protocol 89 (RFC 2328).
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), 89);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 5));

            // Common header: a version 2 Link State Update (type 4) from a
            // documentation router id in the backbone area (0.0.0.0).
            let ospf = expect_layer::<Ospfv2>(case, packet);
            assert_eq!(ospf.version_value(), 2);
            assert_eq!(ospf.packet_type_value(), 4); // Link State Update
            assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // The Link State Update carries one area-scope Traffic Engineering
            // Opaque-LSA (RFC 3630 §2): an area-scope Opaque-LSA (LS type 10) whose
            // Link State ID packs the TE Opaque Type (1) into the first octet and a
            // 24-bit Opaque ID (0x2a) into the remaining three, rendering as
            // 1.0.0.42. The body is two top-level TE TLVs decoded as generic Opaque
            // TLVs (the decode path has no TE-specific knowledge): a 4-octet Router
            // Address TLV (type 1) and a 16-octet Link TLV (type 2) nesting a Link
            // Type and a Link ID sub-TLV, for a 28-octet body after the 20-octet
            // header. The typed Opaque body is private, so it is surfaced through
            // the public inspection surface: `num_lsas`/`lsa_count` report one LSA,
            // the `lsa` entry renders the header summary plus the 28-octet body, an
            // `opaque_lsa` pair reports the TE Opaque Type read from the header plus
            // the TLV count, and one `opaque_tlv` pair per TLV naming the TLV type
            // and its value byte length.
            let fields = ospf.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("num_lsas"), Some("1"));
            assert_eq!(value_of("lsa_count"), Some("1"));
            assert_eq!(
                value_of("lsa"),
                Some(concat!(
                    "LSA(type=Opaque-Area, id=1.0.0.42, adv=192.0.2.1, ",
                    "seq=0x80000001, age=0, len=48) body=28B",
                ))
            );
            assert_eq!(value_of("opaque_lsa"), Some("type=1 tlvs=2"));
            let opaque_tlv: Vec<&str> = fields
                .iter()
                .filter(|(field, _)| *field == "opaque_tlv")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(opaque_tlv, vec!["type=1 value=4B", "type=2 value=16B"]);
        }
        "ospf-hello-simple-auth" => {
            // OSPF rides directly on IPv4 protocol 89 (RFC 2328).
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), 89);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 5));

            // Common header: a version 2 Hello (type 1) authenticated with the
            // simple-password scheme (AuType 1, RFC 2328 §D.2).
            let ospf = expect_layer::<Ospfv2>(case, packet);
            assert_eq!(ospf.version_value(), 2);
            assert_eq!(ospf.packet_type_value(), 1); // Hello
            assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // AuType 1 carries the cleartext password right-padded into the
            // 8-octet authentication field; the auth field is excluded from the
            // OSPF checksum so the checksum decodes as valid.
            assert_eq!(ospf.autype_value(), 1);
            assert_eq!(
                ospf.authentication_value(),
                [b's', b'e', b'c', b'r', b'e', b't', 0, 0]
            );
            assert_eq!(ospf.checksum_status(), OspfChecksumStatus::Valid);
            assert!(ospf.auth_trailer().is_empty());

            // The auth type is surfaced in the inspection fields as "<n> (<Name>)".
            let fields = ospf.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("autype"), Some("1 (Simple)"));
            assert_eq!(value_of("neighbor_count"), Some("1"));
        }
        "ospf-hello-crypto-md5" => {
            // OSPF rides directly on IPv4 protocol 89 (RFC 2328).
            let ipv4 = expect_layer::<Ipv4>(case, packet);
            assert_eq!(ipv4.protocol_value(), 89);
            assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ipv4.destination(), Ipv4Addr::new(224, 0, 0, 5));

            // Common header: a version 2 Hello (type 1) authenticated with the
            // cryptographic keyed-MD5 scheme (AuType 2, RFC 2328 §D.3).
            let ospf = expect_layer::<Ospfv2>(case, packet);
            assert_eq!(ospf.version_value(), 2);
            assert_eq!(ospf.packet_type_value(), 1); // Hello
            assert_eq!(ospf.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospf.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // The structured authentication field exposes the Key ID, Auth Data
            // Length (16 for keyed-MD5), and cryptographic sequence number.
            assert_eq!(ospf.autype_value(), 2);
            assert_eq!(ospf.crypto_key_id(), Some(7));
            assert_eq!(ospf.crypto_auth_data_length(), Some(16));
            assert_eq!(ospf.crypto_sequence_number(), Some(0x0000_002a));

            // The OSPF checksum field is zero for cryptographic auth, so the
            // decoded checksum status is NotChecked.
            assert_eq!(ospf.checksum_status(), OspfChecksumStatus::NotChecked);

            // The appended 16-octet keyed-MD5 digest is captured verbatim as the
            // auth trailer and round-trips byte-for-byte (the decoder holds no
            // secret key). `preserve_exact_bytes` already verifies the full
            // re-compile, but assert the trailer explicitly here.
            let trailer = ospf.auth_trailer();
            assert_eq!(trailer.len(), 16);
            assert_eq!(
                trailer,
                &[
                    0x54, 0x2a, 0x38, 0x62, 0xa2, 0x76, 0x1d, 0x79, 0x68, 0x48, 0x86, 0xa9, 0xd2,
                    0x7e, 0x39, 0x95,
                ]
            );

            // The auth type is surfaced in the inspection fields as "<n> (<Name>)".
            let fields = ospf.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("autype"), Some("2 (Cryptographic)"));
            assert_eq!(value_of("neighbor_count"), Some("1"));
        }
        "ospfv3-hello" => {
            // OSPFv3 rides directly on IPv6 next header 89 (RFC 5340 §2.5).
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(ipv6.next_header_value(), 89);
            assert_eq!(ipv6.source(), "2001:db8::1".parse::<Ipv6Addr>().unwrap());
            assert_eq!(
                ipv6.destination(),
                "2001:db8::2".parse::<Ipv6Addr>().unwrap()
            );

            // Common header: a version 3 Hello (type 1) from a documentation
            // router id in the backbone area (0.0.0.0), instance 0.
            let ospfv3 = expect_layer::<Ospfv3>(case, packet);
            assert_eq!(ospfv3.version_value(), 3);
            assert_eq!(ospfv3.packet_type_value(), 1); // Hello
            assert_eq!(ospfv3.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospfv3.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));
            assert_eq!(ospfv3.instance_id_value(), 0);

            // The Hello body fields are surfaced through the public inspection
            // surface (the typed body is private). OSPFv3 carries no Network
            // Mask and a 24-bit Options field rendered as raw hex.
            let fields = ospfv3.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("type"), Some("Hello"));
            assert_eq!(value_of("interface_id"), Some("5"));
            assert_eq!(value_of("hello_interval"), Some("10"));
            assert_eq!(value_of("dead_interval"), Some("40"));
            assert_eq!(value_of("options"), Some("0x000013"));
            assert_eq!(value_of("priority"), Some("1"));
            assert_eq!(value_of("designated_router"), Some("192.0.2.1"));
            assert_eq!(value_of("backup_designated_router"), Some("192.0.2.2"));
            assert_eq!(value_of("neighbor_count"), Some("1"));
            let neighbors: Vec<&str> = fields
                .iter()
                .filter(|(field, _)| *field == "neighbor")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(neighbors, vec!["192.0.2.2"]);
        }
        "ospfv3-router-lsa" => {
            // OSPFv3 rides directly on IPv6 next header 89 (RFC 5340 §2.5).
            let ipv6 = expect_layer::<Ipv6>(case, packet);
            assert_eq!(ipv6.next_header_value(), 89);
            assert_eq!(ipv6.source(), "2001:db8::1".parse::<Ipv6Addr>().unwrap());
            assert_eq!(
                ipv6.destination(),
                "2001:db8::2".parse::<Ipv6Addr>().unwrap()
            );

            // Common header: a version 3 Link State Update (type 4) from a
            // documentation router id in the backbone area (0.0.0.0).
            let ospfv3 = expect_layer::<Ospfv3>(case, packet);
            assert_eq!(ospfv3.version_value(), 3);
            assert_eq!(ospfv3.packet_type_value(), 4); // Link State Update
            assert_eq!(ospfv3.router_id_value(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(ospfv3.area_id_value(), Ipv4Addr::new(0, 0, 0, 0));

            // The Link State Update carries one OSPFv3 Router-LSA (LS type
            // 0x2001, RFC 5340 §A.4.3) describing a single point-to-point
            // interface. The typed body is private, so it is surfaced through the
            // public inspection surface: `num_lsas`/`lsa_count` report one LSA,
            // the `lsa` entry renders the 20-octet header summary plus the
            // 20-octet Router body, a `router_lsa` pair reports the flags,
            // options, and interface count, and one `router_interface` pair names
            // the interface fields.
            let fields = ospfv3.inspection_fields();
            let value_of = |name: &str| {
                fields
                    .iter()
                    .find(|(field, _)| *field == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(value_of("type"), Some("LSUpdate"));
            assert_eq!(value_of("num_lsas"), Some("1"));
            assert_eq!(value_of("lsa_count"), Some("1"));
            assert_eq!(
                value_of("lsa"),
                Some(concat!(
                    "LSAv3(type=0x2001, id=0.0.0.0, adv=192.0.2.1, ",
                    "seq=0x80000001, age=0, len=40) body=20B",
                ))
            );
            assert_eq!(
                value_of("router_lsa"),
                Some("flags=0x00 options=0x000013 interfaces=1")
            );
            let router_interfaces: Vec<&str> = fields
                .iter()
                .filter(|(field, _)| *field == "router_interface")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(
                router_interfaces,
                vec!["type=1 metric=10 if_id=5 nbr_if_id=6 nbr_rid=192.0.2.2"]
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
    if relative.file_name().and_then(|name| name.to_str()) == Some("README.md")
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
        "dot11" => strip_allowed_suffix(file_name, &[".hex"]),
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

fn repository_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| panic!("CARGO_MANIFEST_DIR should have a repository parent"))
        .join(path)
}

fn focused_repository_artifact_text(
    path_label: &str,
    section_start: Option<&str>,
    kind: &str,
) -> (String, usize) {
    let path = repository_path(path_label);
    let text = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "{kind} artifact {} should be readable at {}: {err}",
            path_label,
            path.display()
        )
    });

    let Some(section_start) = section_start else {
        return (text, 1);
    };

    let start = text.find(section_start).unwrap_or_else(|| {
        panic!(
            "{kind} artifact {} should contain focused section {section_start:?}",
            path_label
        )
    });
    let first_line = text[..start].lines().count() + 1;
    let section = &text[start..];
    let end = section[section_start.len()..]
        .find("\n## ")
        .map(|offset| section_start.len() + offset)
        .unwrap_or(section.len());

    (section[..end].to_string(), first_line)
}

fn focused_dot11_artifact_text(artifact: Dot11TextArtifact) -> (String, usize) {
    focused_repository_artifact_text(artifact.path, artifact.section_start, "Dot11")
}

fn focused_ip_fragment_artifact_text(artifact: IpFragmentTextArtifact) -> (String, usize) {
    focused_repository_artifact_text(artifact.path, artifact.section_start, "IP fragment")
}

fn add_dot11_violation(
    violations: &mut Vec<String>,
    label: &str,
    line_number: Option<usize>,
    reason: impl Into<String>,
) {
    let reason = reason.into();
    if let Some(line_number) = line_number {
        violations.push(format!("{label}:{line_number}: {reason}"));
    } else {
        violations.push(format!("{label}: {reason}"));
    }
}

fn scan_dot11_text_artifact(artifact: Dot11TextArtifact, violations: &mut Vec<String>) {
    let (text, first_line) = focused_dot11_artifact_text(artifact);
    for (line_index, line) in text.lines().enumerate() {
        scan_dot11_text_line(artifact.path, first_line + line_index, line, violations);
    }
}

fn scan_dot11_text_line(label: &str, line_number: usize, line: &str, violations: &mut Vec<String>) {
    let lower = line.to_ascii_lowercase();

    for marker in [
        "password=",
        "password:",
        "passphrase=",
        "passphrase:",
        "psk=",
        "psk:",
        "wpa_passphrase=",
        "api_key=",
        "secret=",
        "token=",
        "private_key=",
        "-----begin ",
    ] {
        if lower.contains(marker) {
            add_dot11_violation(
                violations,
                label,
                Some(line_number),
                format!("contains credential marker {marker:?}"),
            );
        }
    }

    for marker in [
        "ssid=",
        "ssid:",
        "bssid=",
        "bssid:",
        "captured on ",
        "captured from ",
        "pcap captured",
        "tcpdump -i",
        "airodump",
        "airmon-ng",
        "wlan0",
        "wlp",
        "mon0",
    ] {
        if lower.contains(marker) {
            add_dot11_violation(
                violations,
                label,
                Some(line_number),
                format!("contains live-capture or live-identifier marker {marker:?}"),
            );
        }
    }

    scan_dot11_ssid_builders(label, line_number, line, violations);
    scan_dot11_macaddr_constructors(label, line_number, line, violations);
    scan_dot11_ipv4addr_constructors(label, line_number, line, violations);
    scan_dot11_text_ip_and_mac_tokens(label, line_number, line, violations);
}

fn scan_dot11_ssid_builders(
    label: &str,
    line_number: usize,
    line: &str,
    violations: &mut Vec<String>,
) {
    let mut rest = line;
    while let Some(index) = rest.find(".ssid(") {
        rest = &rest[index + ".ssid(".len()..];
        let Some(start_quote) = rest.find('"') else {
            continue;
        };
        let after_quote = &rest[start_quote + 1..];
        let Some(end_quote) = after_quote.find('"') else {
            continue;
        };
        let ssid = &after_quote[..end_quote];
        assert_allowed_dot11_ssid(label, Some(line_number), ssid, violations);
        rest = &after_quote[end_quote + 1..];
    }
}

fn scan_dot11_macaddr_constructors(
    label: &str,
    line_number: usize,
    line: &str,
    violations: &mut Vec<String>,
) {
    for marker in ["MacAddr::new([", "MacAddr::from(["] {
        let mut rest = line;
        while let Some(index) = rest.find(marker) {
            rest = &rest[index + marker.len()..];
            let Some(end) = rest.find(']') else {
                break;
            };
            if let Some(bytes) = parse_u8_array::<6>(&rest[..end]) {
                assert_allowed_dot11_mac(
                    label,
                    Some(line_number),
                    MacAddr::new(bytes),
                    "MacAddr constructor",
                    violations,
                );
            }
            rest = &rest[end + 1..];
        }
    }
}

fn scan_dot11_ipv4addr_constructors(
    label: &str,
    line_number: usize,
    line: &str,
    violations: &mut Vec<String>,
) {
    let mut rest = line;
    while let Some(index) = rest.find("Ipv4Addr::new(") {
        rest = &rest[index + "Ipv4Addr::new(".len()..];
        let Some(end) = rest.find(')') else {
            break;
        };
        if let Some(bytes) = parse_u8_array::<4>(&rest[..end]) {
            assert_allowed_dot11_ip(
                label,
                Some(line_number),
                IpAddr::V4(Ipv4Addr::from(bytes)),
                "Ipv4Addr constructor",
                violations,
            );
        }
        rest = &rest[end + 1..];
    }
}

fn scan_dot11_text_ip_and_mac_tokens(
    label: &str,
    line_number: usize,
    line: &str,
    violations: &mut Vec<String>,
) {
    for token in line.split(|ch: char| {
        !(ch.is_ascii_alphanumeric()
            || ch == '.'
            || ch == ':'
            || ch == '/'
            || ch == '-'
            || ch == '_')
    }) {
        let token = token.trim_matches(|ch| ch == '-' || ch == '.' || ch == ':' || ch == '/');
        if token.is_empty() {
            continue;
        }

        let without_cidr = token.split('/').next().unwrap_or(token);
        let mac_candidate = if without_cidr.matches(':').count() >= 5 {
            without_cidr.split('-').next().unwrap_or(without_cidr)
        } else {
            without_cidr
        };
        if let Ok(mac) = mac_candidate.parse::<MacAddr>() {
            assert_allowed_dot11_mac(label, Some(line_number), mac, "MAC literal", violations);
            continue;
        }

        if without_cidr.contains(['.', ':']) {
            let ip_candidate = without_cidr.trim_matches(|ch| ch == '-' || ch == '.' || ch == ':');
            if let Ok(ip) = ip_candidate.parse::<IpAddr>() {
                assert_allowed_dot11_ip(label, Some(line_number), ip, "IP literal", violations);
            }
        }
    }
}

fn parse_u8_array<const N: usize>(body: &str) -> Option<[u8; N]> {
    let parts = body.split(',').map(str::trim).collect::<Vec<_>>();
    if parts.len() != N {
        return None;
    }

    let mut bytes = [0u8; N];
    for (index, part) in parts.iter().enumerate() {
        bytes[index] = parse_u8_literal(part)?;
    }
    Some(bytes)
}

fn parse_u8_literal(input: &str) -> Option<u8> {
    let input = input.trim();
    if let Some(hex) = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
    {
        u8::from_str_radix(hex, 16).ok()
    } else {
        input.parse::<u8>().ok()
    }
}

fn scan_dot11_packet_fixture(
    case: &ValidFixtureCase,
    packet: &Packet,
    violations: &mut Vec<String>,
) {
    let label = format!("crafter/tests/fixtures/{}", case.path);
    scan_dot11_packet(&label, packet, violations);
}

fn scan_dot11_packet(label: &str, packet: &Packet, violations: &mut Vec<String>) {
    if let Some(dot11) = packet.layer::<Dot11>() {
        for (field, mac) in [
            ("addr1", dot11.addr1_value()),
            ("addr2", dot11.addr2_value()),
            ("addr3", dot11.addr3_value()),
            ("addr4", dot11.addr4_value()),
            ("bssid", dot11.bssid()),
        ] {
            if let Some(mac) = mac {
                assert_allowed_dot11_mac(label, None, mac, field, violations);
            }
        }

        for tag in dot11.tagged_parameters() {
            if tag.id() == 0 {
                let ssid = std::str::from_utf8(tag.data()).unwrap_or_else(|_| {
                    add_dot11_violation(
                        violations,
                        label,
                        None,
                        "SSID tag contains non-UTF-8 bytes",
                    );
                    ""
                });
                assert_allowed_dot11_ssid(label, None, ssid, violations);
            }
        }
    }

    if let Some(ipv4) = packet.layer::<Ipv4>() {
        assert_allowed_dot11_ip(
            label,
            None,
            IpAddr::V4(ipv4.source()),
            "IPv4 source",
            violations,
        );
        assert_allowed_dot11_ip(
            label,
            None,
            IpAddr::V4(ipv4.destination()),
            "IPv4 destination",
            violations,
        );
    }

    if let Some(ipv6) = packet.layer::<Ipv6>() {
        assert_allowed_dot11_ip(
            label,
            None,
            IpAddr::V6(ipv6.source()),
            "IPv6 source",
            violations,
        );
        assert_allowed_dot11_ip(
            label,
            None,
            IpAddr::V6(ipv6.destination()),
            "IPv6 destination",
            violations,
        );
    }
}

fn assert_allowed_dot11_ssid(
    label: &str,
    line_number: Option<usize>,
    ssid: &str,
    violations: &mut Vec<String>,
) {
    if ssid.is_empty()
        || ALLOWED_DOT11_SYNTHETIC_SSIDS.contains(&ssid)
        || ALLOWED_DOT11_SYNTHETIC_SSID_PREFIXES
            .iter()
            .any(|prefix| ssid.starts_with(prefix))
    {
        return;
    }

    add_dot11_violation(
        violations,
        label,
        line_number,
        format!("SSID {ssid:?} is not an allowed synthetic Dot11 identifier"),
    );
}

fn assert_allowed_dot11_mac(
    label: &str,
    line_number: Option<usize>,
    mac: MacAddr,
    context: &str,
    violations: &mut Vec<String>,
) {
    if is_allowed_dot11_mac(mac) {
        return;
    }

    add_dot11_violation(
        violations,
        label,
        line_number,
        format!("{context} {mac} is not an allowed synthetic Dot11 MAC"),
    );
}

fn is_allowed_dot11_mac(mac: MacAddr) -> bool {
    let octets = mac.octets();
    mac == MacAddr::ZERO
        || mac.is_broadcast()
        || matches!(octets, [0x00, 0x00, 0x5e, 0x00, 0x53, _])
        || matches!(octets, [0x02, 0x00, 0x5e, 0x10, _, _])
}

fn assert_allowed_dot11_ip(
    label: &str,
    line_number: Option<usize>,
    ip: IpAddr,
    context: &str,
    violations: &mut Vec<String>,
) {
    if is_allowed_dot11_ip(ip) {
        return;
    }

    add_dot11_violation(
        violations,
        label,
        line_number,
        format!("{context} {ip} is outside documentation address space"),
    );
}

fn is_allowed_dot11_ip(ip: IpAddr) -> bool {
    is_documentation_ip(ip)
}

fn is_documentation_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => matches!(
            ipv4.octets(),
            [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
        ),
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            segments[0] == 0x2001 && segments[1] == 0x0db8
        }
    }
}

fn scan_ip_fragment_hygiene(violations: &mut Vec<String>) {
    for artifact in IP_FRAGMENT_TEXT_ARTIFACTS {
        scan_ip_fragment_text_artifact(*artifact, violations);
    }

    assert_ip_fragment_target_artifacts_are_ignored(violations);

    for case in VALID_FIXTURES
        .iter()
        .filter(|case| is_ip_fragment_case(case.name))
    {
        ensure_fixture_exists(case.path);
        let bytes = fixture_bytes_for_case(case);
        let target = packet_target_for_case(case);
        let packet = decode_packet(target, &bytes)
            .unwrap_or_else(|err| panic!("fixture {} should decode: {err}", case.path));
        scan_ip_fragment_packet(
            &format!("crafter/tests/fixtures/{}", case.path),
            &packet,
            violations,
        );
    }

    for case in PCAP_FIXTURES
        .iter()
        .filter(|case| is_ip_fragment_case(case.name))
    {
        assert!(
            case.path.starts_with("pcaps/raw-ip"),
            "IP fragment pcap fixture {} must stay a RawIp fixture, not a live link capture",
            case.path
        );
        let packets = PcapReader::from_reader(case.contents)
            .unwrap_or_else(|err| panic!("pcap fixture {} should parse: {err}", case.path))
            .collect_packets()
            .unwrap_or_else(|err| {
                panic!("pcap fixture {} should decode packets: {err}", case.path)
            });
        for (index, packet) in packets.iter().enumerate() {
            scan_ip_fragment_packet(
                &format!("crafter/tests/fixtures/{} record {index}", case.path),
                packet.packet(),
                violations,
            );
        }
    }
}

fn is_ip_fragment_case(name: &str) -> bool {
    name.starts_with("ipv4-fragment-")
        || name.starts_with("ipv6-fragment-")
        || name.contains("ipfragment")
        || name.contains("fragment-oracle-reference")
}

fn scan_ip_fragment_text_artifact(artifact: IpFragmentTextArtifact, violations: &mut Vec<String>) {
    let (text, first_line) = focused_ip_fragment_artifact_text(artifact);
    for (line_index, line) in text.lines().enumerate() {
        scan_ip_fragment_text_line(artifact.path, first_line + line_index, line, violations);
    }
}

fn scan_ip_fragment_text_line(
    label: &str,
    line_number: usize,
    line: &str,
    violations: &mut Vec<String>,
) {
    let lower = line.to_ascii_lowercase();
    for marker in [
        "password=",
        "password:",
        "passphrase=",
        "passphrase:",
        "api_key=",
        "secret=",
        "private_key=",
        "-----begin ",
    ] {
        if lower.contains(marker) {
            add_dot11_violation(
                violations,
                label,
                Some(line_number),
                format!("contains credential marker {marker:?}"),
            );
        }
    }

    for token in hygiene_tokens(line) {
        let without_cidr = token.split('/').next().unwrap_or(token);
        let ip_candidate = without_cidr.trim_matches(|ch| ch == '-' || ch == '.' || ch == ':');
        if let Ok(ip) = ip_candidate.parse::<IpAddr>() {
            assert_allowed_ip_fragment_ip(label, Some(line_number), ip, "IP literal", violations);
        }

        if token.contains("ip-fragment") && looks_like_artifact_path(token) {
            assert_allowed_ip_fragment_artifact_path(label, Some(line_number), token, violations);
        }
    }
}

fn hygiene_tokens(line: &str) -> impl Iterator<Item = &str> {
    line.split(|ch: char| {
        !(ch.is_ascii_alphanumeric()
            || ch == '.'
            || ch == ':'
            || ch == '/'
            || ch == '-'
            || ch == '_')
    })
    .map(|token| token.trim_matches(|ch| ch == '.' || ch == ':' || ch == '/'))
    .filter(|token| !token.is_empty())
}

fn looks_like_artifact_path(token: &str) -> bool {
    token.contains('/') || token.ends_with(".pcap") || token.ends_with(".pcapng")
}

fn assert_allowed_ip_fragment_artifact_path(
    label: &str,
    line_number: Option<usize>,
    path: &str,
    violations: &mut Vec<String>,
) {
    if path.starts_with("target/oracle/ip-fragment-")
        || path.starts_with("target/lab/ip-fragment-")
        || path.starts_with("crafter/tests/fixtures/bytes/ipv4-fragment-")
        || path.starts_with("crafter/tests/fixtures/bytes/ipv6-fragment-")
        || path.starts_with("crafter/tests/fixtures/pcaps/raw-ipv4-ipfragment-generated.pcap")
        || path.starts_with("crafter/tests/fixtures/pcaps/raw-ipv6-fragment-oracle-reference.pcap")
        || path.starts_with("crafter/tests/fixtures/summaries/ipv6-fragment-")
        || path.starts_with("pcaps/raw-ipv4-ipfragment-generated.pcap")
        || path.starts_with("pcaps/raw-ipv6-fragment-oracle-reference.pcap")
    {
        return;
    }

    add_dot11_violation(
        violations,
        label,
        line_number,
        format!("IP fragment artifact path {path:?} is not a sanitized target/ or fixture path"),
    );
}

fn assert_ip_fragment_target_artifacts_are_ignored(violations: &mut Vec<String>) {
    let path = repository_path(".gitignore");
    let text = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            ".gitignore should be readable at {} for artifact hygiene checks: {err}",
            path.display()
        )
    });
    if text.lines().map(str::trim).any(|line| line == "/target/") {
        return;
    }

    add_dot11_violation(
        violations,
        ".gitignore",
        None,
        "target/ must stay ignored so live IP fragment artifacts are not tracked",
    );
}

fn scan_ip_fragment_packet(label: &str, packet: &Packet, violations: &mut Vec<String>) {
    if let Some(ipv4) = packet.layer::<Ipv4>() {
        assert_allowed_ip_fragment_ip(
            label,
            None,
            IpAddr::V4(ipv4.source()),
            "IPv4 source",
            violations,
        );
        assert_allowed_ip_fragment_ip(
            label,
            None,
            IpAddr::V4(ipv4.destination()),
            "IPv4 destination",
            violations,
        );
    }

    if let Some(ipv6) = packet.layer::<Ipv6>() {
        assert_allowed_ip_fragment_ip(
            label,
            None,
            IpAddr::V6(ipv6.source()),
            "IPv6 source",
            violations,
        );
        assert_allowed_ip_fragment_ip(
            label,
            None,
            IpAddr::V6(ipv6.destination()),
            "IPv6 destination",
            violations,
        );
    }
}

fn assert_allowed_ip_fragment_ip(
    label: &str,
    line_number: Option<usize>,
    ip: IpAddr,
    context: &str,
    violations: &mut Vec<String>,
) {
    if is_documentation_ip(ip) {
        return;
    }

    add_dot11_violation(
        violations,
        label,
        line_number,
        format!("{context} {ip} is outside documentation address space"),
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
fn igmp_fixture_suite_bootstrap_decodes_compile_and_summarizes() {
    for name in [
        "ipv4-igmp-v1-query",
        "ipv4-igmp-v1-report",
        "ipv4-igmp-v2-query",
        "ipv4-igmp-v2-report",
        "ipv4-igmp-v2-leave",
    ] {
        let case = valid_fixture_case(name);
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
fn igmp_mrd_fixture_suite_decodes_compile_and_summarizes() {
    for name in [
        "ipv4-igmp-mrd-advertisement",
        "ipv4-igmp-mrd-solicitation",
        "ipv4-igmp-mrd-termination",
    ] {
        let case = valid_fixture_case(name);
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
fn igmp_extension_fixture_suite_decodes_compile_and_summarizes() {
    for name in [
        "ipv4-igmp-v3-query-extension",
        "ipv4-igmp-v3-report-extension",
    ] {
        let case = valid_fixture_case(name);
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
fn fixture_dot11_corpus_decodes_layer_stacks() {
    for case in DOT11_FIXTURES {
        ensure_fixture_exists(case.path);
        let bytes = fixture_bytes_for_case(case);
        let target = packet_target_for_case(case);
        let packet = decode_packet(target, &bytes)
            .unwrap_or_else(|err| panic!("fixture {} should decode: {err}", case.path));

        assert_packet_surface(case, &packet);
        assert_exact_layer_stack(case, &packet);
        assert_dot11_fixture_fields(case, &packet);
        assert_compile_decode_compile(case, target, &packet, &bytes);
    }
}

#[test]
fn ipv6_routing_fixtures_decode_compile_and_summarize() {
    for name in [
        "ipv6-routing-generic-unknown-raw",
        "ipv6-mobile-routing-raw",
        "ipv6-segment-routing-raw",
    ] {
        let case = valid_fixture_case(name);
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
fn ipv6_fragment_fixtures_decode_compile_and_summarize() {
    for name in [
        "ipv6-fragment-udp-raw",
        "ipv6-fragment-atomic-udp-raw",
        "ipv6-fragment-non-initial-udp-raw",
    ] {
        let case = valid_fixture_case(name);
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
fn ipv4_fragment_defrag_fixtures_decode_compile_and_summarize() {
    for name in [
        "ipv4-fragment-defrag-complete-final",
        "ipv4-fragment-defrag-complete-first",
        "ipv4-fragment-defrag-duplicate-final",
        "ipv4-fragment-defrag-duplicate-first",
        "ipv4-fragment-defrag-duplicate-repeat",
        "ipv4-fragment-defrag-missing-final",
        "ipv4-fragment-defrag-missing-first",
        "ipv4-fragment-defrag-overlap-conflict",
        "ipv4-fragment-defrag-overlap-first",
    ] {
        let case = valid_fixture_case(name);
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

fn assert_ipv4_fragment_defrag_reassembled_record(
    record: &PacketRecord,
    host_octet: u8,
    identification: u16,
    payload: &[u8],
    fragment_count: usize,
    duplicate_count: usize,
) {
    let ipv4 = record
        .packet()
        .layer::<Ipv4>()
        .expect("reassembled fixture output should contain IPv4");
    assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, host_octet));
    assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, host_octet));
    assert_eq!(ipv4.identification_value(), identification);
    assert_eq!(ipv4.flags_value(), 0);
    assert_eq!(ipv4.fragment_offset_value(), 0);
    assert!(!ipv4.is_fragmented());
    assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);
    assert_eq!(ipv4.total_length_value(), Some((20 + payload.len()) as u16));
    assert_eq!(ipv4.checksum_status(), Ipv4ChecksumStatus::Valid);
    assert_eq!(
        record
            .packet()
            .layer::<Raw>()
            .expect("reassembled fixture output should keep raw payload")
            .as_bytes(),
        payload
    );

    let expected_total_len = (20 + payload.len()) as u32;
    assert_eq!(record.metadata().origin(), PacketOrigin::Transformed);
    assert_eq!(record.metadata().backend(), &BackendKind::PcapFile);
    assert_eq!(
        record.metadata().pcap_link_type(),
        Some(PcapLinkType::RawIp)
    );
    assert_eq!(record.metadata().original_len(), Some(expected_total_len));
    assert_eq!(record.metadata().captured_len(), Some(expected_total_len));
    assert_eq!(record.metadata().emitted_len(), Some(expected_total_len));
    assert!(record.metadata().captured_bytes().is_none());

    let metadata = record.metadata().ip_defrag_metadata();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].family(), IpFragmentFamily::Ipv4);
    assert_eq!(metadata[0].identification(), identification as u32);
    let expected_key =
        format!("192.0.2.{host_octet}>198.51.100.{host_octet} proto=17 id=0x{identification:04x}");
    assert_eq!(metadata[0].datagram_key(), Some(expected_key.as_str()));
    assert_eq!(metadata[0].fragment_count(), fragment_count);
    assert_eq!(metadata[0].duplicate_count(), duplicate_count);
    assert_eq!(metadata[0].overlap_status(), IpDefragOverlapStatus::None);
    assert_eq!(
        metadata[0].byte_ranges(),
        [IpFragmentRange::new(0, 8), IpFragmentRange::new(8, 16)].as_slice()
    );
    assert_eq!(metadata[0].total_len(), Some(expected_total_len));

    let traces = record.metadata().transforms();
    assert_eq!(traces.len(), 1);
    assert_eq!(traces[0].name(), "ip-defrag");
    assert_eq!(traces[0].note(), Some("reassembled"));
    assert_eq!(traces[0].output_len(), Some(expected_total_len));
}

#[test]
fn ipv4_fragment_defrag_complete_out_of_order_fixture_reassembles() {
    let mut transform = IpDefrag::new();

    let final_output = transform
        .defrag_record(ipv4_fragment_record_from_fixture(
            "ipv4-fragment-defrag-complete-final",
            1,
        ))
        .expect("final fragment should buffer");
    let first_output = transform
        .defrag_record(ipv4_fragment_record_from_fixture(
            "ipv4-fragment-defrag-complete-first",
            2,
        ))
        .expect("first fragment should complete the datagram");

    assert!(final_output.is_empty());
    assert_eq!(first_output.len(), 1);
    assert_eq!(transform.input_count(), 2);
    assert_eq!(transform.emitted_count(), 1);
    assert_ipv4_fragment_defrag_reassembled_record(
        &first_output.records()[0],
        70,
        0x5141,
        b"abcdefghijklmnop",
        2,
        0,
    );
}

#[test]
fn ipv4_fragment_defrag_duplicate_fixture_records_duplicate_count() {
    let mut transform = IpDefrag::new();

    assert!(transform
        .defrag_record(ipv4_fragment_record_from_fixture(
            "ipv4-fragment-defrag-duplicate-first",
            1,
        ))
        .expect("first fragment should buffer")
        .is_empty());
    assert!(transform
        .defrag_record(ipv4_fragment_record_from_fixture(
            "ipv4-fragment-defrag-duplicate-repeat",
            2,
        ))
        .expect("duplicate fragment should buffer")
        .is_empty());
    let output = transform
        .defrag_record(ipv4_fragment_record_from_fixture(
            "ipv4-fragment-defrag-duplicate-final",
            3,
        ))
        .expect("final fragment should complete duplicate fixture");

    assert_eq!(output.len(), 1);
    assert_eq!(transform.input_count(), 3);
    assert_eq!(transform.emitted_count(), 1);
    assert_ipv4_fragment_defrag_reassembled_record(
        &output.records()[0],
        71,
        0x5142,
        b"ABCDEFGHIJKLMNOP",
        2,
        1,
    );
}

#[test]
fn ipv4_fragment_defrag_missing_fixture_does_not_emit_incomplete_datagram() {
    let mut transform = IpDefrag::new();

    let first_output = transform
        .defrag_record(ipv4_fragment_record_from_fixture(
            "ipv4-fragment-defrag-missing-first",
            1,
        ))
        .expect("first missing-vector fragment should buffer");
    let final_output = transform
        .defrag_record(ipv4_fragment_record_from_fixture(
            "ipv4-fragment-defrag-missing-final",
            2,
        ))
        .expect("final missing-vector fragment should buffer");

    assert!(first_output.is_empty());
    assert!(final_output.is_empty());
    assert_eq!(transform.input_count(), 2);
    assert_eq!(transform.emitted_count(), 0);
}

#[test]
fn ipv4_fragment_defrag_overlap_fixture_rejects_conflicting_bytes() {
    let mut transform = IpDefrag::new();

    let first_output = transform
        .defrag_record(ipv4_fragment_record_from_fixture(
            "ipv4-fragment-defrag-overlap-first",
            1,
        ))
        .expect("first overlap-vector fragment should buffer");
    let error = match transform.defrag_record(ipv4_fragment_record_from_fixture(
        "ipv4-fragment-defrag-overlap-conflict",
        2,
    )) {
        Ok(output) => panic!(
            "conflicting overlap fixture unexpectedly emitted {} records",
            output.len()
        ),
        Err(error) => error,
    };

    assert!(first_output.is_empty());
    assert_eq!(transform.input_count(), 2);
    assert_eq!(transform.emitted_count(), 0);
    match error {
        WireError::Packet(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(field, "ip.defrag.ipv4.overlap");
            assert!(reason.contains("ambiguous"));
        }
        other => panic!("expected structured overlap rejection, got {other:?}"),
    }
}

fn pcap_fixture_case(name: &str) -> &'static PcapFixtureCase {
    PCAP_FIXTURES
        .iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("pcap fixture {name} should be cataloged"))
}

fn packet_records_from_pcap_fixture(case: &PcapFixtureCase) -> Vec<PacketRecord> {
    let path = fixture_path(case.path);
    let source = PacketWire::pcap_file(path.clone())
        .open()
        .unwrap_or_else(|err| panic!("pcap fixture {} should open: {err}", case.path))
        .source()
        .unwrap_or_else(|err| panic!("pcap fixture {} should expose source: {err}", case.path));
    Sniffer::new(source)
        .collect_records()
        .unwrap_or_else(|err| panic!("pcap fixture {} should read records: {err}", case.path))
}

fn defrag_pcap_records(records: Vec<PacketRecord>) -> (IpDefrag, Vec<PacketRecord>) {
    let mut transform = IpDefrag::new();
    let mut emitted = Vec::new();
    for record in records {
        emitted.extend(
            transform
                .defrag_record(record)
                .expect("pcap fragment record should defrag")
                .into_records(),
        );
    }
    (transform, emitted)
}

fn ipfragment_generated_ipv4_pcap_bytes() -> Vec<u8> {
    let payload = (0x40u8..0x60).collect::<Vec<_>>();
    let input = PacketRecord::new(
        Ipv4::with_addresses(
            Ipv4Addr::new(192, 0, 2, 74),
            Ipv4Addr::new(198, 51, 100, 74),
        )
        .protocol(253)
        .identification(0x5145)
        .ttl(43)
        .ds_field(0x29)
            / Raw::from_bytes(&payload),
    );
    let mut transform = IpFragment::new(44);
    let output = transform
        .fragment_record(input)
        .expect("IpFragment should generate deterministic IPv4 pcap fixture records");
    assert_eq!(output.len(), 2);

    let timestamps = [
        PcapTimestamp::new(90, 120_300, TimestampPrecision::Microseconds).unwrap(),
        PcapTimestamp::new(90, 120_301, TimestampPrecision::Microseconds).unwrap(),
    ];
    let mut pcap = Vec::new();
    {
        let options =
            PcapWriterOptions::new(PcapLinkType::RawIp).precision(TimestampPrecision::Microseconds);
        let mut writer = PcapWriter::from_writer_with_options(&mut pcap, options)
            .expect("in-memory pcap writer should initialize");
        for (record, timestamp) in output.records().iter().zip(timestamps) {
            writer
                .write_packet_with_timestamp(record.packet(), timestamp)
                .expect("generated IpFragment record should write to pcap");
        }
        writer.flush().expect("in-memory pcap should flush");
    }
    pcap
}

fn assert_ipfragment_generated_ipv4_defrag_output(record: &PacketRecord) {
    let payload = (0x40u8..0x60).collect::<Vec<_>>();
    let ipv4 = record
        .packet()
        .layer::<Ipv4>()
        .expect("IpFragment pcap defrag output should contain IPv4");
    assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 74));
    assert_eq!(ipv4.destination(), Ipv4Addr::new(198, 51, 100, 74));
    assert_eq!(ipv4.identification_value(), 0x5145);
    assert_eq!(ipv4.flags_value(), 0);
    assert_eq!(ipv4.fragment_offset_value(), 0);
    assert_eq!(ipv4.protocol_value(), 253);
    assert_eq!(ipv4.total_length_value(), Some(52));
    assert_eq!(ipv4.checksum_status(), Ipv4ChecksumStatus::Valid);
    assert_eq!(
        record
            .packet()
            .layer::<Raw>()
            .expect("IpFragment pcap defrag output should preserve Raw payload")
            .as_bytes(),
        payload.as_slice()
    );
    assert_eq!(record.metadata().origin(), PacketOrigin::Transformed);
    assert_eq!(record.metadata().backend(), &BackendKind::PcapFile);
    assert_eq!(
        record.metadata().pcap_link_type(),
        Some(PcapLinkType::RawIp)
    );
    assert_eq!(
        record.metadata().timestamp(),
        Some(PcapTimestamp::new(90, 120_300, TimestampPrecision::Microseconds).unwrap())
    );
    assert_eq!(record.metadata().original_len(), Some(52));
    assert_eq!(record.metadata().captured_len(), Some(52));
    assert_eq!(record.metadata().emitted_len(), Some(52));

    let metadata = &record.metadata().ip_defrag_metadata()[0];
    assert_eq!(metadata.family(), IpFragmentFamily::Ipv4);
    assert_eq!(metadata.identification(), 0x5145);
    assert_eq!(
        metadata.datagram_key(),
        Some("192.0.2.74>198.51.100.74 proto=253 id=0x5145")
    );
    assert_eq!(metadata.fragment_count(), 2);
    assert_eq!(metadata.duplicate_count(), 0);
    assert_eq!(metadata.overlap_status(), IpDefragOverlapStatus::None);
    assert_eq!(
        metadata.byte_ranges(),
        &[IpFragmentRange::new(0, 24), IpFragmentRange::new(24, 32)]
    );
    assert_eq!(metadata.total_len(), Some(52));
}

fn assert_oracle_reference_ipv6_defrag_output(record: &PacketRecord) {
    let payload = (0x60u8..0x80).collect::<Vec<_>>();
    let ipv6 = record
        .packet()
        .layer::<Ipv6>()
        .expect("oracle pcap defrag output should contain IPv6");
    assert_eq!(
        ipv6.source(),
        Ipv6Addr::new(0x2001, 0x0db8, 0x0074, 0, 0, 0, 0, 0x0040)
    );
    assert_eq!(
        ipv6.destination(),
        Ipv6Addr::new(0x2001, 0x0db8, 0x0074, 0, 0, 0, 0, 0x0041)
    );
    assert_eq!(ipv6.traffic_class_value(), 0x40);
    assert_eq!(ipv6.flow_label_value(), 0x74040);
    assert_eq!(ipv6.hop_limit_value(), 41);
    assert_eq!(ipv6.payload_length_value(), Some(32));
    assert_eq!(ipv6.next_header_value(), 253);
    assert!(record.packet().layer::<Ipv6FragmentHeader>().is_none());
    assert_eq!(
        record
            .packet()
            .layer::<Raw>()
            .expect("oracle pcap defrag output should preserve Raw payload")
            .as_bytes(),
        payload.as_slice()
    );
    assert_eq!(record.metadata().origin(), PacketOrigin::Transformed);
    assert_eq!(record.metadata().backend(), &BackendKind::PcapFile);
    assert_eq!(
        record.metadata().pcap_link_type(),
        Some(PcapLinkType::RawIp)
    );
    assert_eq!(
        record.metadata().timestamp(),
        Some(PcapTimestamp::new(91, 120_300, TimestampPrecision::Microseconds).unwrap())
    );
    assert_eq!(record.metadata().original_len(), Some(72));
    assert_eq!(record.metadata().captured_len(), Some(72));
    assert_eq!(record.metadata().emitted_len(), Some(72));

    let metadata = &record.metadata().ip_defrag_metadata()[0];
    assert_eq!(metadata.family(), IpFragmentFamily::Ipv6);
    assert_eq!(metadata.identification(), 0x1203_0040);
    assert_eq!(
        metadata.datagram_key(),
        Some("2001:db8:74::40>2001:db8:74::41 id=0x12030040")
    );
    assert_eq!(metadata.fragment_count(), 2);
    assert_eq!(metadata.duplicate_count(), 0);
    assert_eq!(metadata.overlap_status(), IpDefragOverlapStatus::None);
    assert_eq!(
        metadata.byte_ranges(),
        &[IpFragmentRange::new(0, 24), IpFragmentRange::new(24, 32)]
    );
    assert_eq!(metadata.total_len(), Some(72));
}

#[test]
fn ip_fragment_generated_pcap_fixture_matches_ipfragment_and_defrags() {
    let case = pcap_fixture_case("raw-ipv4-ipfragment-generated");
    assert_eq!(case.contents, ipfragment_generated_ipv4_pcap_bytes());

    let records = packet_records_from_pcap_fixture(case);
    assert_eq!(records.len(), 2);
    let (transform, emitted) = defrag_pcap_records(records);
    assert_eq!(transform.input_count(), 2);
    assert_eq!(transform.fragments_observed(), 2);
    assert_eq!(transform.completed_datagrams(), 1);
    assert_eq!(emitted.len(), 1);
    assert_ipfragment_generated_ipv4_defrag_output(&emitted[0]);
}

#[test]
fn ip_fragment_oracle_reference_pcap_fixture_defrags_ipv6() {
    let case = pcap_fixture_case("raw-ipv6-fragment-oracle-reference");
    let records = packet_records_from_pcap_fixture(case);
    assert_eq!(records.len(), 2);

    let (transform, emitted) = defrag_pcap_records(records);
    assert_eq!(transform.input_count(), 2);
    assert_eq!(transform.fragments_observed(), 2);
    assert_eq!(transform.completed_datagrams(), 1);
    assert_eq!(emitted.len(), 1);
    assert_oracle_reference_ipv6_defrag_output(&emitted[0]);
}

#[derive(Debug, Clone, Copy)]
struct Ipv4FragmentEmitExpected {
    start: usize,
    end: usize,
    offset: u16,
    more_fragments: bool,
    total_len: u16,
}

impl Ipv4FragmentEmitExpected {
    const fn new(
        start: usize,
        end: usize,
        offset: u16,
        more_fragments: bool,
        total_len: u16,
    ) -> Self {
        Self {
            start,
            end,
            offset,
            more_fragments,
            total_len,
        }
    }
}

fn ipv4_fragment_emit_record(payload: &[u8], with_options: bool) -> PacketRecord {
    let mut ipv4 = Ipv4::with_addresses(
        Ipv4Addr::new(192, 0, 2, 72),
        Ipv4Addr::new(198, 51, 100, 72),
    )
    .protocol(253)
    .identification(0x5129)
    .ttl(43)
    .ds_field(0x29);
    if with_options {
        ipv4 = ipv4.option([IPV4_OPTION_NOP]);
    }

    PacketRecord::new(ipv4 / Raw::from_bytes(payload))
}

fn assert_ipv4_fragment_emit_fixture(
    name: &str,
    mtu: usize,
    with_options: bool,
    payload: &[u8],
    expected: &[Ipv4FragmentEmitExpected],
) {
    let mut transform = IpFragment::new(mtu);

    let output = transform
        .fragment_record(ipv4_fragment_emit_record(payload, with_options))
        .unwrap_or_else(|error| panic!("{name} should fragment: {error}"));

    assert_eq!(output.len(), expected.len(), "{name} fragment count");
    assert_eq!(
        transform.emitted_count(),
        expected.len(),
        "{name} emissions"
    );
    let mut reconstructed = Vec::new();
    for (index, (record, fragment)) in output.records().iter().zip(expected).enumerate() {
        assert_eq!(fragment.start, reconstructed.len(), "{name} order");
        let wire = record.packet().compile().unwrap();
        assert!(
            wire.as_bytes().len() <= mtu,
            "{name} fragment {index} exceeded MTU"
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, wire.as_bytes()).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().unwrap();
        assert_eq!(ipv4.source(), Ipv4Addr::new(192, 0, 2, 72), "{name}");
        assert_eq!(
            ipv4.destination(),
            Ipv4Addr::new(198, 51, 100, 72),
            "{name}"
        );
        assert_eq!(ipv4.protocol_value(), 253, "{name}");
        assert_eq!(ipv4.identification_value(), 0x5129, "{name}");
        assert_eq!(ipv4.checksum_status(), Ipv4ChecksumStatus::Valid, "{name}");
        assert_eq!(ipv4.fragment_offset_value(), fragment.offset, "{name}");
        assert_eq!(ipv4.has_more_fragments(), fragment.more_fragments, "{name}");
        assert_eq!(
            ipv4.total_length_value(),
            Some(fragment.total_len),
            "{name}"
        );
        if with_options {
            assert_eq!(ipv4.option_bytes(), &[IPV4_OPTION_NOP, 0, 0, 0], "{name}");
        }

        let raw = decoded.layer::<Raw>().unwrap();
        assert_eq!(
            raw.as_bytes(),
            &payload[fragment.start..fragment.end],
            "{name}"
        );
        reconstructed.extend_from_slice(raw.as_bytes());

        let metadata = &record.metadata().ip_fragment_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv4, "{name}");
        assert_eq!(metadata.fragment_count(), expected.len(), "{name}");
        assert_eq!(metadata.fragment_index(), index, "{name}");
        assert_eq!(
            metadata.byte_range(),
            IpFragmentRange::new(fragment.start as u32, fragment.end as u32),
            "{name}"
        );
        assert_eq!(
            metadata.reason(),
            Some(&IpFragmentReason::Fragmented),
            "{name}"
        );
    }

    assert_eq!(reconstructed, payload, "{name} reconstructed payload");
}

#[test]
fn ipv4_fragment_emit_boundary_fixture_rows_decode_and_reconstruct() {
    let one_byte_over_payload = (0u8..21).collect::<Vec<_>>();
    assert_ipv4_fragment_emit_fixture(
        "one_byte_over_mtu",
        40,
        false,
        &one_byte_over_payload,
        &[
            Ipv4FragmentEmitExpected::new(0, 16, 0, true, 36),
            Ipv4FragmentEmitExpected::new(16, 21, 2, false, 25),
        ],
    );

    let many_fragments_payload = (0u8..73).collect::<Vec<_>>();
    assert_ipv4_fragment_emit_fixture(
        "many_fragments",
        36,
        false,
        &many_fragments_payload,
        &[
            Ipv4FragmentEmitExpected::new(0, 16, 0, true, 36),
            Ipv4FragmentEmitExpected::new(16, 32, 2, true, 36),
            Ipv4FragmentEmitExpected::new(32, 48, 4, true, 36),
            Ipv4FragmentEmitExpected::new(48, 64, 6, true, 36),
            Ipv4FragmentEmitExpected::new(64, 73, 8, false, 29),
        ],
    );

    let options_odd_final_payload = (0u8..35).collect::<Vec<_>>();
    assert_ipv4_fragment_emit_fixture(
        "options_odd_final",
        40,
        true,
        &options_odd_final_payload,
        &[
            Ipv4FragmentEmitExpected::new(0, 16, 0, true, 40),
            Ipv4FragmentEmitExpected::new(16, 32, 2, true, 40),
            Ipv4FragmentEmitExpected::new(32, 35, 4, false, 27),
        ],
    );
}

#[derive(Debug, Clone, Copy)]
struct Ipv6FragmentEmitExpected {
    start: usize,
    end: usize,
    offset: u16,
    more_fragments: bool,
    payload_len: u16,
}

impl Ipv6FragmentEmitExpected {
    const fn new(
        start: usize,
        end: usize,
        offset: u16,
        more_fragments: bool,
        payload_len: u16,
    ) -> Self {
        Self {
            start,
            end,
            offset,
            more_fragments,
            payload_len,
        }
    }
}

fn ipv6_fragment_source() -> Ipv6Addr {
    "2001:db8:74::1".parse().unwrap()
}

fn ipv6_fragment_destination() -> Ipv6Addr {
    "2001:db8:74::2".parse().unwrap()
}

fn ipv6_fragment_emit_record(payload: &[u8], with_destination_options: bool) -> PacketRecord {
    let ipv6 = Ipv6::new()
        .src(ipv6_fragment_source())
        .dst(ipv6_fragment_destination())
        .traffic_class(0x74)
        .flow_label(0x07474)
        .hop_limit(52);

    if with_destination_options {
        PacketRecord::new(
            ipv6.next_header(IPPROTO_IPV6_DSTOPTS)
                / Ipv6DestinationOptionsHeader::new().next_header(IPPROTO_UDP)
                / Raw::from_bytes(payload),
        )
    } else {
        PacketRecord::new(ipv6.next_header(IPPROTO_UDP) / Raw::from_bytes(payload))
    }
}

fn ipv6_unsupported_extension_emit_record(payload: &[u8]) -> PacketRecord {
    PacketRecord::new(
        Ipv6::new()
            .src(ipv6_fragment_source())
            .dst(ipv6_fragment_destination())
            .next_header(IPPROTO_IPV6_EXPERIMENTAL_1)
            / Raw::from_bytes(payload),
    )
}

fn assert_ipv6_fragment_emit_fixture(
    name: &str,
    mtu: usize,
    with_destination_options: bool,
    payload: &[u8],
    expected: &[Ipv6FragmentEmitExpected],
) {
    let config = IpFragmentConfig::new(mtu).ipv6_identification(0x5174_0001);
    let mut transform = IpFragment::with_config(config);

    let output = transform
        .fragment_record(ipv6_fragment_emit_record(payload, with_destination_options))
        .unwrap_or_else(|error| panic!("{name} should fragment: {error}"));

    assert_eq!(output.len(), expected.len(), "{name} fragment count");
    assert_eq!(
        transform.emitted_count(),
        expected.len(),
        "{name} emissions"
    );
    let mut reconstructed = Vec::new();
    for (index, (record, fragment)) in output.records().iter().zip(expected).enumerate() {
        assert_eq!(fragment.start, reconstructed.len(), "{name} order");
        let wire = record.packet().compile().unwrap();
        assert!(
            wire.as_bytes().len() <= mtu,
            "{name} fragment {index} exceeded MTU"
        );

        let ipv6 = record.packet().layer::<Ipv6>().unwrap();
        assert_eq!(ipv6.source(), ipv6_fragment_source(), "{name}");
        assert_eq!(ipv6.destination(), ipv6_fragment_destination(), "{name}");
        assert_eq!(ipv6.traffic_class_value(), 0x74, "{name}");
        assert_eq!(ipv6.flow_label_value(), 0x07474, "{name}");
        assert_eq!(ipv6.hop_limit_value(), 52, "{name}");
        assert_eq!(
            ipv6.payload_length_value(),
            Some(fragment.payload_len),
            "{name}"
        );
        if with_destination_options {
            assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_DSTOPTS, "{name}");
            let destination_options = record
                .packet()
                .layer::<Ipv6DestinationOptionsHeader>()
                .unwrap();
            assert_eq!(
                destination_options.next_header_value(),
                IPPROTO_IPV6_FRAGMENT,
                "{name}"
            );
        } else {
            assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_FRAGMENT, "{name}");
        }

        let fragment_header = record.packet().layer::<Ipv6FragmentHeader>().unwrap();
        assert_eq!(fragment_header.next_header_value(), IPPROTO_UDP, "{name}");
        assert_eq!(
            fragment_header.identification_value(),
            0x5174_0001,
            "{name}"
        );
        assert_eq!(
            fragment_header.fragment_offset_value(),
            fragment.offset,
            "{name}"
        );
        assert_eq!(
            fragment_header.more_fragments_value(),
            fragment.more_fragments,
            "{name}"
        );

        let raw = record.packet().layer::<Raw>().unwrap();
        assert_eq!(
            raw.as_bytes(),
            &payload[fragment.start..fragment.end],
            "{name}"
        );
        reconstructed.extend_from_slice(raw.as_bytes());

        let metadata = &record.metadata().ip_fragment_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv6, "{name}");
        assert_eq!(metadata.fragment_count(), expected.len(), "{name}");
        assert_eq!(metadata.fragment_index(), index, "{name}");
        assert_eq!(
            metadata.byte_range(),
            IpFragmentRange::new(fragment.start as u32, fragment.end as u32),
            "{name}"
        );
        assert_eq!(
            metadata.reason(),
            Some(&IpFragmentReason::Fragmented),
            "{name}"
        );
    }

    assert_eq!(reconstructed, payload, "{name} reconstructed payload");
}

#[test]
fn ipv6_fragment_emit_boundary_fixture_rows_decode_and_reconstruct() {
    let exact_mtu_payload = (0u8..32).collect::<Vec<_>>();
    let exact_input = ipv6_fragment_emit_record(&exact_mtu_payload, false);
    let exact_summary = exact_input.packet().summary();
    let mut exact_transform =
        IpFragment::with_config(IpFragmentConfig::new(72).ipv6_identification(0x5174_0001));
    let exact_output = exact_transform.fragment_record(exact_input).unwrap();
    assert_eq!(exact_output.len(), 1, "exact_mtu");
    assert_eq!(exact_output.records()[0].packet().summary(), exact_summary);
    assert!(exact_output.records()[0]
        .packet()
        .layer::<Ipv6FragmentHeader>()
        .is_none());

    let one_byte_over_payload = (0u8..33).collect::<Vec<_>>();
    assert_ipv6_fragment_emit_fixture(
        "one_byte_over_mtu",
        72,
        false,
        &one_byte_over_payload,
        &[
            Ipv6FragmentEmitExpected::new(0, 24, 0, true, 32),
            Ipv6FragmentEmitExpected::new(24, 33, 3, false, 17),
        ],
    );

    let many_fragments_payload = (0u8..97).collect::<Vec<_>>();
    assert_ipv6_fragment_emit_fixture(
        "many_fragments",
        72,
        false,
        &many_fragments_payload,
        &[
            Ipv6FragmentEmitExpected::new(0, 24, 0, true, 32),
            Ipv6FragmentEmitExpected::new(24, 48, 3, true, 32),
            Ipv6FragmentEmitExpected::new(48, 72, 6, true, 32),
            Ipv6FragmentEmitExpected::new(72, 96, 9, true, 32),
            Ipv6FragmentEmitExpected::new(96, 97, 12, false, 9),
        ],
    );

    let extension_boundary_payload = (0u8..49).collect::<Vec<_>>();
    assert_ipv6_fragment_emit_fixture(
        "destination_options_boundary",
        80,
        true,
        &extension_boundary_payload,
        &[
            Ipv6FragmentEmitExpected::new(0, 24, 0, true, 40),
            Ipv6FragmentEmitExpected::new(24, 48, 3, true, 40),
            Ipv6FragmentEmitExpected::new(48, 49, 6, false, 17),
        ],
    );

    let mut too_small_mtu_transform =
        IpFragment::with_config(IpFragmentConfig::new(55).ipv6_identification(0x5174_0001));
    let too_small_mtu_error = too_small_mtu_transform
        .fragment_record(ipv6_fragment_emit_record(
            &(0u8..24).collect::<Vec<_>>(),
            false,
        ))
        .unwrap_err();
    match too_small_mtu_error {
        WireError::Packet(CrafterError::InvalidFieldValue { field, .. }) => {
            assert_eq!(field, "ip.fragment.mtu", "too_small_mtu");
        }
        other => panic!("expected too_small_mtu InvalidFieldValue, got {other:?}"),
    }

    let atomic_sized_payload = vec![0x74; 1240];
    let atomic_sized_input = ipv6_fragment_emit_record(&atomic_sized_payload, false);
    let atomic_sized_summary = atomic_sized_input.packet().summary();
    let mut atomic_sized_transform =
        IpFragment::with_config(IpFragmentConfig::new(1280).ipv6_identification(0x5174_0001));
    let atomic_sized_output = atomic_sized_transform
        .fragment_record(atomic_sized_input)
        .unwrap();
    assert_eq!(atomic_sized_output.len(), 1, "atomic_sized");
    assert_eq!(
        atomic_sized_output.records()[0].packet().summary(),
        atomic_sized_summary
    );
    assert!(atomic_sized_output.records()[0]
        .packet()
        .layer::<Ipv6FragmentHeader>()
        .is_none());

    let mut unsupported_extension_transform =
        IpFragment::with_config(IpFragmentConfig::new(72).ipv6_identification(0x5174_0001));
    let unsupported_extension_output = unsupported_extension_transform
        .fragment_record(ipv6_unsupported_extension_emit_record(&[0u8; 96]))
        .unwrap();
    assert_eq!(
        unsupported_extension_output.len(),
        1,
        "unsupported_extension"
    );
    assert!(unsupported_extension_output.records()[0]
        .metadata()
        .ip_fragment_metadata()
        .is_empty());
    assert_eq!(
        unsupported_extension_output.records()[0]
            .metadata()
            .transforms()[0]
            .note(),
        Some("unsupported IPv6 extension chain outside Fragment Header extension scope"),
        "unsupported_extension"
    );
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
fn igmp_fixture_suite_raw_ip_pcap_decodes_records() {
    let case = pcap_fixture_case("raw-ipv4-igmp-bootstrap");
    assert_eq!(case.records.len(), 5);

    let packets = PcapReader::from_reader(case.contents)
        .unwrap_or_else(|err| panic!("pcap fixture {} should parse header: {err}", case.path))
        .collect_packets()
        .unwrap_or_else(|err| panic!("pcap fixture {} should decode packets: {err}", case.path));
    assert_eq!(packets.len(), case.records.len());

    for (packet, expected) in packets.iter().zip(case.records) {
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

        assert_eq!(packet.timestamp(), expected_timestamp);
        assert_eq!(packet.pcap_link_type(), PcapLinkType::RawIp);
        assert_eq!(packet.data(), expected_bytes.as_slice());
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

#[test]
fn igmp_mrd_fixture_suite_raw_ip_pcap_decodes_records() {
    let case = pcap_fixture_case("raw-ipv4-igmp-mrd");
    assert_eq!(case.records.len(), 3);

    let packets = PcapReader::from_reader(case.contents)
        .unwrap_or_else(|err| panic!("pcap fixture {} should parse header: {err}", case.path))
        .collect_packets()
        .unwrap_or_else(|err| panic!("pcap fixture {} should decode packets: {err}", case.path));
    assert_eq!(packets.len(), case.records.len());

    for (packet, expected) in packets.iter().zip(case.records) {
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

        assert_eq!(packet.timestamp(), expected_timestamp);
        assert_eq!(packet.pcap_link_type(), PcapLinkType::RawIp);
        assert_eq!(packet.data(), expected_bytes.as_slice());
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

#[test]
fn pcap_fixture_roundtrips() {
    let case = PCAP_FIXTURES
        .iter()
        .find(|case| case.name == "raw-ipv4-udp-dscp-ecn-raw")
        .expect("raw IPv4 DSCP/ECN pcap fixture should be cataloged");
    let expected = case.records[0];
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

    let records = PcapReader::from_reader(case.contents)
        .unwrap_or_else(|err| panic!("pcap fixture {} should parse header: {err}", case.path))
        .collect_records()
        .unwrap_or_else(|err| panic!("pcap fixture {} should read records: {err}", case.path));
    assert_eq!(records.len(), 1);

    let record = &records[0];
    assert_eq!(record.timestamp(), expected_timestamp);
    assert_eq!(record.pcap_link_type(), case.pcap_link_type);
    assert_eq!(record.link_type(), case.link_type);
    assert_eq!(record.captured_len(), expected_bytes.len() as u32);
    assert_eq!(record.original_len(), expected_bytes.len() as u32);
    assert_eq!(record.data(), expected_bytes.as_slice());

    let decoded = record
        .decode()
        .unwrap_or_else(|err| panic!("pcap fixture {} should decode: {err}", case.path));
    assert_packet_surface(expected_fixture, &decoded);
    assert_fixture_fields(expected_fixture, &decoded);
    assert_compile_decode_compile(
        expected_fixture,
        packet_target_for_case(expected_fixture),
        &decoded,
        &expected_bytes,
    );

    let packets = PcapReader::from_reader(case.contents)
        .unwrap_or_else(|err| {
            panic!(
                "pcap fixture {} should parse header for packets: {err}",
                case.path
            )
        })
        .collect_packets()
        .unwrap_or_else(|err| panic!("pcap fixture {} should decode packets: {err}", case.path));
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    assert_eq!(packet.timestamp(), expected_timestamp);
    assert_eq!(packet.original_len(), expected_bytes.len() as u32);
    assert_eq!(packet.pcap_link_type(), case.pcap_link_type);
    assert_eq!(packet.link_type(), case.link_type);
    assert_eq!(packet.data(), expected_bytes.as_slice());
    assert_fixture_fields(expected_fixture, packet.packet());
    assert_eq!(
        packet.packet().compile().unwrap().as_bytes(),
        expected_bytes.as_slice()
    );

    let mut rewritten_packet = Vec::new();
    {
        let options =
            PcapWriterOptions::new(case.pcap_link_type).precision(case.timestamp_precision);
        let mut writer = PcapWriter::from_writer_with_options(&mut rewritten_packet, options)
            .unwrap_or_else(|err| {
                panic!(
                    "pcap fixture {} packet writer should initialize: {err}",
                    case.path
                )
            });
        writer
            .write_packet_with_timestamp(packet.packet(), expected_timestamp)
            .unwrap_or_else(|err| panic!("pcap fixture {} packet should write: {err}", case.path));
        writer.flush().unwrap_or_else(|err| {
            panic!(
                "pcap fixture {} packet writer should flush: {err}",
                case.path
            )
        });
    }
    assert_eq!(rewritten_packet, case.contents);

    let mut rewritten = Vec::new();
    {
        let options =
            PcapWriterOptions::new(case.pcap_link_type).precision(case.timestamp_precision);
        let mut writer = PcapWriter::from_writer_with_options(&mut rewritten, options)
            .unwrap_or_else(|err| {
                panic!("pcap fixture {} writer should initialize: {err}", case.path)
            });
        for record in &records {
            writer.write_record(record).unwrap_or_else(|err| {
                panic!("pcap fixture {} record should write: {err}", case.path)
            });
        }
        writer
            .flush()
            .unwrap_or_else(|err| panic!("pcap fixture {} writer should flush: {err}", case.path));
    }
    assert_eq!(rewritten, case.contents);
}

#[test]
fn wpa_pcap_fixture_decrypts_through_packet_wire_sniffer() {
    let path = fixture_path("pcaps/wpa2-psk-ccmp-unicast.pcap");
    let source = PacketWire::pcap_file(path.clone())
        .open()
        .expect("WPA pcap fixture should open")
        .source()
        .expect("WPA pcap fixture should expose source capability");
    let records = Sniffer::new(source)
        .with(Dot11Metadata::new())
        .with(
            WpaDecrypt::new()
                .network("libcrafter-wpa", "libcrafter-pass")
                .expect("synthetic WPA fixture credentials should validate"),
        )
        .collect_records()
        .expect("WPA pcap fixture should decrypt");

    assert_eq!(records.len(), 2);
    assert!(records
        .iter()
        .any(|record| record.packet().layer::<Dot11>().is_some()));

    let decrypted = records
        .iter()
        .find(|record| record.metadata().origin() == PacketOrigin::Transformed)
        .expect("WPA pcap fixture should emit one decrypted record");
    assert_eq!(decrypted.metadata().backend(), &BackendKind::PcapFile);
    assert_eq!(decrypted.metadata().file(), Some(path.as_path()));
    assert_eq!(decrypted.metadata().link_type(), Some(LinkType::Ethernet));

    let summary = decrypted.packet().summary();
    assert!(summary.contains("Ethernet("), "{summary}");
    assert!(
        summary.contains("Ipv4(src=192.0.2.10, dst=198.51.100.20"),
        "{summary}"
    );
    assert!(summary.ends_with("Raw(len=14)"), "{summary}");
    assert_eq!(
        decrypted
            .packet()
            .layer::<Raw>()
            .expect("raw payload")
            .as_bytes(),
        b"libcrafter wpa"
    );

    let wifi = decrypted.metadata().wifi().expect("Wi-Fi metadata");
    assert_eq!(wifi.ssid(), Some(b"libcrafter-wpa".as_slice()));
    assert_eq!(
        wifi.bssid(),
        Some(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, 0x01]))
    );
    assert_eq!(
        wifi.transmitter(),
        Some(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, 0x02]))
    );
    assert_eq!(
        wifi.receiver(),
        Some(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, 0x01]))
    );
    assert_eq!(wifi.key_id(), Some(1));
    assert_eq!(wifi.decrypt_state(), Some(WifiDecryptState::Decrypted));

    let wpa = wifi.wpa_metadata().expect("WPA metadata");
    assert_eq!(wpa.cipher(), Some(WpaCipher::Ccmp128));
    assert_eq!(wpa.akm(), Some(WpaAkm::Psk));
    assert_eq!(wpa.key_kind(), Some(WpaKeyKind::Pairwise));
    assert_eq!(wpa.key_id(), Some(1));
    assert_eq!(wpa.packet_number(), Some(0x33));
    assert_eq!(wpa.decrypt_reason(), Some(WpaDecryptReason::Decrypted));
    assert_eq!(wpa.credential_status(), Some(WpaCredentialStatus::Matched));
    assert_eq!(
        wpa.handshake_status(),
        Some(WpaHandshakeStatus::MicVerified)
    );
}

#[test]
fn pcap_ipv6_roundtrip() {
    let case = PCAP_FIXTURES
        .iter()
        .find(|case| case.name == "raw-ipv6-base-traffic-flow-udp-raw")
        .expect("raw IPv6 pcap fixture should be registered");
    assert_eq!(case.path, "pcaps/raw-ipv6-base-traffic-flow-udp-raw.pcap");
    assert_eq!(case.pcap_link_type, PcapLinkType::RawIp);
    assert_eq!(case.link_type, LinkType::Raw);
    assert_eq!(case.timestamp_precision, TimestampPrecision::Microseconds);
    assert_eq!(case.records.len(), 1);

    let expected = case.records[0];
    assert_eq!(expected.seconds, 20);
    assert_eq!(expected.fractional, 3);
    assert_eq!(expected.fixture_name, "ipv6-base-traffic-flow-udp-raw");

    let byte_case = valid_fixture_case(expected.fixture_name);
    let expected_bytes = fixture_bytes_for_case(byte_case);
    let expected_timestamp = PcapTimestamp::micros(expected.seconds, expected.fractional).unwrap();

    let reader = PcapReader::from_reader(case.contents)
        .unwrap_or_else(|err| panic!("pcap fixture {} should parse header: {err}", case.path));
    let header = reader.header();
    assert_eq!(header.pcap_link_type(), PcapLinkType::RawIp);
    assert_eq!(header.link_type(), LinkType::Raw);
    assert_eq!(header.precision(), TimestampPrecision::Microseconds);
    assert!(header.snaplen() >= expected_bytes.len() as u32);

    let records = PcapReader::from_reader(case.contents)
        .unwrap_or_else(|err| {
            panic!(
                "pcap fixture {} should parse header twice: {err}",
                case.path
            )
        })
        .collect_records()
        .unwrap_or_else(|err| panic!("pcap fixture {} should read records: {err}", case.path));
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.timestamp(), expected_timestamp);
    assert_eq!(record.pcap_link_type(), PcapLinkType::RawIp);
    assert_eq!(record.link_type(), LinkType::Raw);
    assert_eq!(record.captured_len(), expected_bytes.len() as u32);
    assert_eq!(record.original_len(), expected_bytes.len() as u32);
    assert_eq!(record.data(), expected_bytes.as_slice());

    let packets = PcapReader::from_reader(case.contents)
        .unwrap_or_else(|err| {
            panic!(
                "pcap fixture {} should parse header for packet decode: {err}",
                case.path
            )
        })
        .collect_packets()
        .unwrap_or_else(|err| panic!("pcap fixture {} should decode packets: {err}", case.path));
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    assert_eq!(packet.timestamp(), expected_timestamp);
    assert_eq!(packet.original_len(), expected_bytes.len() as u32);
    assert_eq!(packet.pcap_link_type(), PcapLinkType::RawIp);
    assert_eq!(packet.link_type(), LinkType::Raw);

    assert_packet_surface(byte_case, packet.packet());
    assert_fixture_fields(byte_case, packet.packet());
    assert!(packet
        .packet()
        .layers::<Ipv6HopByHopOptionsHeader>()
        .next()
        .is_none());
    assert!(packet
        .packet()
        .layers::<Ipv6DestinationOptionsHeader>()
        .next()
        .is_none());
    assert!(packet
        .packet()
        .layers::<Ipv6RoutingHeader>()
        .next()
        .is_none());
    assert!(packet
        .packet()
        .layers::<Ipv6FragmentHeader>()
        .next()
        .is_none());
    assert_compile_decode_compile(
        byte_case,
        packet_target_for_case(byte_case),
        packet.packet(),
        &expected_bytes,
    );

    let mut output = Vec::new();
    {
        let options = PcapWriterOptions::new(case.pcap_link_type)
            .precision(case.timestamp_precision)
            .snaplen(header.snaplen())
            .thiszone(header.thiszone())
            .sigfigs(header.sigfigs());
        let mut writer = PcapWriter::from_writer_with_options(&mut output, options)
            .unwrap_or_else(|err| panic!("pcap fixture {} should open writer: {err}", case.path));
        assert_eq!(writer.header(), header);
        writer
            .write_packet_with_timestamp(packet.packet(), record.timestamp())
            .unwrap_or_else(|err| {
                panic!(
                    "pcap fixture {} should rewrite decoded packet: {err}",
                    case.path
                )
            });
        writer
            .flush()
            .unwrap_or_else(|err| panic!("pcap fixture {} should flush writer: {err}", case.path));
    }
    assert_eq!(
        output.as_slice(),
        case.contents,
        "pcap fixture {} should roundtrip with deterministic header and record bytes",
        case.path
    );
}

#[test]
fn fixture_tree_hygiene_matches_readme_conventions() {
    let root = fixture_path("");
    let catalog_paths = VALID_FIXTURES
        .iter()
        .chain(DOT11_FIXTURES.iter())
        .map(|case| case.path)
        .collect::<HashSet<_>>();
    let mut cataloged_byte_fixture_paths = HashSet::new();

    for file in fixture_files(&root) {
        let relative = file.strip_prefix(&root).unwrap_or_else(|err| {
            panic!(
                "fixture path {} should be under root: {err}",
                file.display()
            )
        });
        assert_fixture_filename_convention(relative);

        let is_gitkeep = relative.file_name().and_then(|name| name.to_str()) == Some(".gitkeep");
        let category = relative
            .components()
            .next()
            .and_then(|component| component.as_os_str().to_str());
        let is_readme = relative.file_name().and_then(|name| name.to_str()) == Some("README.md");
        if !is_gitkeep && !is_readme && matches!(category, Some("bytes" | "dot11")) {
            let path = relative
                .to_str()
                .unwrap_or_else(|| panic!("fixture path {relative:?} should be UTF-8"));
            cataloged_byte_fixture_paths.insert(path.to_string());
        }
    }

    for case in VALID_FIXTURES {
        ensure_fixture_exists(case.path);
        assert!(
            cataloged_byte_fixture_paths.contains(case.path),
            "catalog entry {} must live under the fixture bytes/ directory",
            case.path
        );
    }

    for case in DOT11_FIXTURES {
        ensure_fixture_exists(case.path);
        assert!(
            cataloged_byte_fixture_paths.contains(case.path),
            "catalog entry {} must live under the fixture dot11/ directory",
            case.path
        );
    }

    for path in cataloged_byte_fixture_paths {
        assert!(
            catalog_paths.contains(path.as_str()),
            "byte fixture {path} must be listed in a fixture catalog"
        );
    }
}

#[test]
fn no_sensitive_dot11_artifacts() {
    let mut violations = Vec::new();

    for artifact in DOT11_TEXT_ARTIFACTS {
        scan_dot11_text_artifact(*artifact, &mut violations);
    }

    for case in DOT11_FIXTURES {
        ensure_fixture_exists(case.path);
        let bytes = fixture_bytes_for_case(case);
        let target = packet_target_for_case(case);
        let packet = decode_packet(target, &bytes)
            .unwrap_or_else(|err| panic!("fixture {} should decode: {err}", case.path));
        scan_dot11_packet_fixture(case, &packet, &mut violations);
    }

    for case in PCAP_FIXTURES {
        if !matches!(case.link_type, LinkType::Ieee80211 | LinkType::Radiotap) {
            continue;
        }

        let packets = PcapReader::from_reader(case.contents)
            .unwrap_or_else(|err| panic!("pcap fixture {} should parse: {err}", case.path))
            .collect_packets()
            .unwrap_or_else(|err| {
                panic!("pcap fixture {} should decode packets: {err}", case.path)
            });
        for (index, packet) in packets.iter().enumerate() {
            scan_dot11_packet(
                &format!("crafter/tests/fixtures/{} record {index}", case.path),
                packet.packet(),
                &mut violations,
            );
        }
    }

    scan_ip_fragment_hygiene(&mut violations);

    assert!(
        violations.is_empty(),
        "Dot11/IP fragment artifacts contain sensitive or live-looking identifiers:\n{}",
        violations.join("\n")
    );
}

#[test]
fn malformed_corpus_rows_are_well_formed() {
    let rows = parse_malformed_rows("malformed/core-decode-corpus.hex");
    assert!(!rows.is_empty(), "malformed corpus must not be empty");

    let valid_targets = HashSet::from([
        "dhcp",
        "dhcp-options",
        "dns-name",
        "dot11",
        "ethernet",
        "ipv4",
        "ipv4-options",
        "ipv6",
        "linux-sll",
        "null-loopback",
        "radiotap",
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
fn igmp_malformed_fixture_suite_reports_errors_and_preserves_raw_tails() {
    let error_cases: &[(&str, &str, &str, &str, usize, usize)] = &[
        (
            "ipv4-igmp-empty-payload",
            "malformed/ipv4-igmp-empty-payload.hex",
            fixture_str!("malformed/ipv4-igmp-empty-payload.hex"),
            "igmp header",
            IGMP_FIXED_HEADER_LEN,
            0,
        ),
        (
            "ipv4-igmp-short-fixed-header",
            "malformed/ipv4-igmp-short-fixed-header.hex",
            fixture_str!("malformed/ipv4-igmp-short-fixed-header.hex"),
            "igmp header",
            IGMP_FIXED_HEADER_LEN,
            3,
        ),
        (
            "ipv4-igmp-invalid-wrapper-length",
            "malformed/ipv4-igmp-invalid-wrapper-length.hex",
            fixture_str!("malformed/ipv4-igmp-invalid-wrapper-length.hex"),
            "ipv4 packet",
            29,
            27,
        ),
        (
            "ipv4-igmp-trailing-bytes",
            "malformed/ipv4-igmp-trailing-bytes.hex",
            fixture_str!("malformed/ipv4-igmp-trailing-bytes.hex"),
            "igmp v3 query source list",
            195528,
            12,
        ),
    ];

    for (name, path, hex, context, required, available) in error_cases {
        ensure_fixture_exists(path);
        let bytes = decode_hex(name, hex);
        match Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_slice()) {
            Err(CrafterError::BufferTooShort {
                context: actual_context,
                required: actual_required,
                available: actual_available,
            }) => {
                assert_eq!(&actual_context, context, "{name} context");
                assert_eq!(&actual_required, required, "{name} required");
                assert_eq!(&actual_available, available, "{name} available");
            }
            Ok(packet) => panic!("{name} decoded unexpectedly as {}", packet.summary()),
            Err(other) => panic!("{name} expected BufferTooShort, got {other:?}"),
        }
    }

    let raw_tail_cases: &[(&str, &str, &str, IgmpType, &[u8])] = &[(
        "ipv4-igmp-unknown-type-payload",
        "malformed/ipv4-igmp-unknown-type-payload.hex",
        fixture_str!("malformed/ipv4-igmp-unknown-type-payload.hex"),
        IgmpType::Unassigned(IGMP_TYPE_UNASSIGNED_FIRST),
        &[0x01, 0x02, 0x03, 0x04],
    )];

    for (name, path, hex, expected_type, expected_tail) in raw_tail_cases {
        ensure_fixture_exists(path);
        let bytes = decode_hex(name, hex);
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_slice())
            .unwrap_or_else(|err| panic!("{name} should decode with a Raw tail: {err}"));
        let igmp = packet.layer::<Igmp>().expect("decoded IGMP header");
        let raw = packet.layer::<Raw>().expect("decoded raw IGMP tail");

        assert_eq!(packet.len(), 3, "{name} should decode as IPv4 / IGMP / Raw");
        assert_eq!(igmp.igmp_type(), *expected_type);
        assert_eq!(raw.as_bytes(), *expected_tail);
        assert_eq!(
            packet
                .compile()
                .unwrap_or_else(|err| panic!("{name} should recompile: {err}"))
                .as_bytes(),
            bytes.as_slice(),
            "{name} should preserve bytes"
        );
    }
}

#[test]
fn igmp_extension_malformed_fixture_suite_reports_truncation_errors() {
    let error_cases: &[(&str, &str, &str, &str, usize, usize)] = &[
        (
            "ipv4-igmp-v3-query-extension-truncated-header",
            "malformed/ipv4-igmp-v3-query-extension-truncated-header.hex",
            fixture_str!("malformed/ipv4-igmp-v3-query-extension-truncated-header.hex"),
            "igmp.extension.header",
            4,
            3,
        ),
        (
            "ipv4-igmp-v3-report-extension-truncated-value",
            "malformed/ipv4-igmp-v3-report-extension-truncated-value.hex",
            fixture_str!("malformed/ipv4-igmp-v3-report-extension-truncated-value.hex"),
            "igmp.extension.value",
            8,
            6,
        ),
    ];

    for (name, path, hex, context, required, available) in error_cases {
        ensure_fixture_exists(path);
        let bytes = decode_hex(name, hex);
        match Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_slice()) {
            Err(CrafterError::BufferTooShort {
                context: actual_context,
                required: actual_required,
                available: actual_available,
            }) => {
                assert_eq!(&actual_context, context, "{name} context");
                assert_eq!(&actual_required, required, "{name} required");
                assert_eq!(&actual_available, available, "{name} available");
            }
            Ok(packet) => panic!("{name} decoded unexpectedly as {}", packet.summary()),
            Err(other) => panic!("{name} expected BufferTooShort, got {other:?}"),
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

#[test]
fn ipv4_options_fixture_decodes_typed_options() {
    let case = valid_fixture_case("ipv4-options-traceroute-udp-raw");
    let bytes = fixture_bytes_for_case(case);
    let packet = decode_packet(packet_target_for_case(case), &bytes)
        .expect("IPv4 options fixture should decode");
    let ipv4 = expect_layer::<Ipv4>(case, &packet);
    let options = ipv4
        .parsed_options()
        .expect("IPv4 options fixture should parse typed options");

    assert_eq!(
        options,
        vec![
            Ipv4Option::record_route(4, vec![Ipv4Addr::new(203, 0, 113, 1)]),
            Ipv4Option::traceroute(0x1234, 1, 0xffff, Ipv4Addr::new(192, 0, 2, 10)),
            Ipv4Option::timestamp(9, 0, vec![0x0102_0304]),
            Ipv4Option::router_alert(0),
            Ipv4Option::EndOfList,
        ]
    );
    assert_eq!(options[2].timestamp_values(), Some(&[0x0102_0304][..]));
    assert_eq!(options[2].timestamp_pointer(), Some(9));
    assert_eq!(options[2].timestamp_overflow(), Some(0));
    assert_eq!(options[2].timestamp_flag(), Some(0));
    assert_eq!(options[3].router_alert_value(), Some(0));
    assert_eq!(packet.compile().unwrap().as_bytes(), bytes.as_slice());
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

#[test]
fn igmp_summary_fixtures_cover_major_packet_shapes() -> Result<(), Box<dyn std::error::Error>> {
    fn igmp_ipv4(src: Ipv4Addr, dst: Ipv4Addr, id: u16) -> Ipv4 {
        Ipv4::new()
            .src(src)
            .dst(dst)
            .id(id)
            .ttl(1)
            .protocol(IPPROTO_IGMP)
    }

    fn decoded(packet: Packet) -> Result<Packet, Box<dyn std::error::Error>> {
        let bytes = packet.compile()?;
        Ok(Packet::decode_from_l3(
            NetworkLayer::Ipv4,
            bytes.as_bytes(),
        )?)
    }

    fn assert_snapshot(packet: Packet, summary_fixture: &str, show_fixture: &str) {
        let expected_summary = read_summary_fixture(summary_fixture);
        assert_eq!(packet.summary().trim_end(), expected_summary.trim_end());
        assert_show_matches_fixture(summary_fixture, &packet, show_fixture);
    }

    for (case_name, show_fixture) in [
        (
            "ipv4-igmp-v1-query",
            "summaries/ipv4-igmp-v1-query-show.summary.txt",
        ),
        (
            "ipv4-igmp-v1-report",
            "summaries/ipv4-igmp-v1-report-show.summary.txt",
        ),
        (
            "ipv4-igmp-v2-query",
            "summaries/ipv4-igmp-v2-query-show.summary.txt",
        ),
        (
            "ipv4-igmp-v2-report",
            "summaries/ipv4-igmp-v2-report-show.summary.txt",
        ),
        (
            "ipv4-igmp-v2-leave",
            "summaries/ipv4-igmp-v2-leave-show.summary.txt",
        ),
        (
            "ipv4-igmp-mrd-advertisement",
            "summaries/ipv4-igmp-mrd-advertisement-show.summary.txt",
        ),
        (
            "ipv4-igmp-mrd-solicitation",
            "summaries/ipv4-igmp-mrd-solicitation-show.summary.txt",
        ),
        (
            "ipv4-igmp-mrd-termination",
            "summaries/ipv4-igmp-mrd-termination-show.summary.txt",
        ),
    ] {
        let case = valid_fixture_case(case_name);
        let bytes = fixture_bytes_for_case(case);
        let packet = decode_packet(packet_target_for_case(case), bytes.as_slice())?;
        assert_snapshot(
            packet,
            case.summary_path.expect("IGMP fixture has summary"),
            show_fixture,
        );
    }

    let all_systems = Ipv4Addr::new(224, 0, 0, 1);
    let v3_group = Ipv4Addr::new(233, 252, 0, 60);
    let v3_group_source = Ipv4Addr::new(233, 252, 0, 61);
    let v3_reserved_group = Ipv4Addr::new(233, 252, 0, 62);
    let v3_report_dst = Ipv4Addr::new(224, 0, 0, 22);

    let v3_query_cases = [
        (
            decoded(
                igmp_ipv4(Ipv4Addr::new(192, 0, 2, 60), all_systems, 0x1706)
                    / Igmp::v3_general_query(100),
            )?,
            "summaries/ipv4-igmp-v3-general-query.summary.txt",
            "summaries/ipv4-igmp-v3-general-query-show.summary.txt",
        ),
        (
            decoded(
                igmp_ipv4(Ipv4Addr::new(192, 0, 2, 61), v3_group, 0x1707)
                    / Igmp::v3_group_specific_query(10, v3_group),
            )?,
            "summaries/ipv4-igmp-v3-group-query.summary.txt",
            "summaries/ipv4-igmp-v3-group-query-show.summary.txt",
        ),
        (
            decoded(
                igmp_ipv4(Ipv4Addr::new(192, 0, 2, 62), v3_group_source, 0x1708)
                    / Igmp::v3_membership_query(
                        125,
                        v3_group_source,
                        IgmpQuery::group_and_source_specific([
                            Ipv4Addr::new(198, 51, 100, 10),
                            Ipv4Addr::new(203, 0, 113, 20),
                        ])
                        .with_suppress_router_side_processing(true)
                        .with_querier_robustness_variable(2)
                        .with_qqic(125),
                    ),
            )?,
            "summaries/ipv4-igmp-v3-group-source-query.summary.txt",
            "summaries/ipv4-igmp-v3-group-source-query-show.summary.txt",
        ),
        (
            decoded(
                igmp_ipv4(Ipv4Addr::new(192, 0, 2, 63), all_systems, 0x1709)
                    / Igmp::v3_membership_query(
                        0x91,
                        Ipv4Addr::UNSPECIFIED,
                        IgmpQuery::new()
                            .with_querier_robustness_variable(2)
                            .with_qqic(0xff),
                    ),
            )?,
            "summaries/ipv4-igmp-v3-explicit-timer-query.summary.txt",
            "summaries/ipv4-igmp-v3-explicit-timer-query-show.summary.txt",
        ),
        (
            decoded(
                igmp_ipv4(Ipv4Addr::new(192, 0, 2, 64), v3_reserved_group, 0x170a)
                    / Igmp::v3_membership_query(
                        100,
                        v3_reserved_group,
                        IgmpQuery::new()
                            .with_raw_flags_qrv(0x75)
                            .with_qqic(125)
                            .with_source_addresses([Ipv4Addr::new(192, 0, 2, 65)]),
                    ),
            )?,
            "summaries/ipv4-igmp-v3-reserved-flags-query.summary.txt",
            "summaries/ipv4-igmp-v3-reserved-flags-query-show.summary.txt",
        ),
    ];

    for (packet, summary_fixture, show_fixture) in v3_query_cases {
        assert_snapshot(packet, summary_fixture, show_fixture);
    }

    let v3_report_cases = [
        (
            decoded(
                igmp_ipv4(Ipv4Addr::new(192, 0, 2, 70), v3_report_dst, 0x170b)
                    / Igmp::v3_membership_report()
                    / IgmpReport::from_group_records([IgmpGroupRecord::mode_is_include(
                        Ipv4Addr::new(233, 252, 0, 70),
                    )
                    .with_source_address(Ipv4Addr::new(198, 51, 100, 70))]),
            )?,
            "summaries/ipv4-igmp-v3-report-include.summary.txt",
            "summaries/ipv4-igmp-v3-report-include-show.summary.txt",
        ),
        (
            decoded(
                igmp_ipv4(Ipv4Addr::new(192, 0, 2, 73), v3_report_dst, 0x170e)
                    / Igmp::v3_membership_report()
                    / IgmpReport::from_group_records([
                        IgmpGroupRecord::allow_new_sources(Ipv4Addr::new(233, 252, 0, 74))
                            .with_source_addresses([
                                Ipv4Addr::new(192, 0, 2, 73),
                                Ipv4Addr::new(198, 51, 100, 73),
                            ]),
                        IgmpGroupRecord::block_old_sources(Ipv4Addr::new(233, 252, 0, 75))
                            .with_source_address(Ipv4Addr::new(203, 0, 113, 73)),
                    ]),
            )?,
            "summaries/ipv4-igmp-v3-report-source-list-change.summary.txt",
            "summaries/ipv4-igmp-v3-report-source-list-change-show.summary.txt",
        ),
        (
            decoded(
                igmp_ipv4(Ipv4Addr::new(192, 0, 2, 75), v3_report_dst, 0x1710)
                    / Igmp::v3_membership_report()
                    / IgmpReport::from_group_records([IgmpGroupRecord::raw(
                        0xc8,
                        Ipv4Addr::new(233, 252, 0, 77),
                    )
                    .with_source_addresses([
                        Ipv4Addr::new(192, 0, 2, 75),
                        Ipv4Addr::new(198, 51, 100, 75),
                    ])
                    .with_auxiliary_data([0xca, 0xfe, 0xba, 0xbe])]),
            )?,
            "summaries/ipv4-igmp-v3-report-unknown-record-type.summary.txt",
            "summaries/ipv4-igmp-v3-report-unknown-record-type-show.summary.txt",
        ),
    ];

    for (packet, summary_fixture, show_fixture) in v3_report_cases {
        assert_snapshot(packet, summary_fixture, show_fixture);
    }

    Ok(())
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

#[test]
fn ipv6_options_show_matches_snapshot() {
    let case = valid_fixture_case("ipv6-options-hop-destination-udp");
    let bytes = fixture_bytes_for_case(case);
    let packet = decode_packet(packet_target_for_case(case), bytes.as_slice())
        .expect("IPv6 options fixture should decode");

    assert_packet_surface(case, &packet);
    assert_fixture_fields(case, &packet);
    assert_compile_decode_compile(
        case,
        packet_target_for_case(case),
        &packet,
        bytes.as_slice(),
    );
    assert_show_matches_fixture(
        "ipv6-options-hop-destination-udp",
        &packet,
        "summaries/ipv6-options-hop-destination-udp-show.summary.txt",
    );
}
