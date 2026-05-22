//! Network interface, raw socket, routing, and send/receive helpers.

#![forbid(unsafe_code)]

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::time::Duration;

use crafter_core::{
    CompiledPacket, CrafterError, Ethernet, Icmp, Icmpv6, Ipv4, Ipv6, Layer, LinkType,
    NetworkLayer, Packet, Tcp, Udp, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP,
};
use pnet_datalink::{self as datalink, Channel, ChannelType};
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_transport::{transport_channel, TransportChannelType};

/// Result type returned by network helpers.
pub type Result<T> = std::result::Result<T, NetError>;

/// Errors returned by packet send helpers.
#[derive(Debug)]
pub enum NetError {
    /// Packet compilation failed before a send could be planned.
    Packet(CrafterError),
    /// A send plan or live send was requested without selecting an interface.
    InterfaceRequired,
    /// The selected interface name is structurally invalid.
    InvalidInterfaceName {
        /// Interface name supplied by the caller.
        name: String,
        /// Stable diagnostic reason.
        reason: &'static str,
    },
    /// The selected interface was not present in the local interface table.
    InterfaceNotFound {
        /// Interface name supplied by the caller.
        name: String,
    },
    /// The packet stack cannot be sent with the requested mode.
    UnsupportedPacketShape {
        /// Requested send mode.
        mode: SendMode,
        /// One-line packet summary.
        summary: String,
        /// Stable diagnostic reason.
        reason: &'static str,
    },
    /// The live backend cannot transmit the planned packet target.
    UnsupportedSendTarget {
        /// Planned send target.
        target: SendTarget,
        /// Stable diagnostic reason.
        reason: &'static str,
    },
    /// The datalink backend opened a channel type this crate does not send on.
    UnsupportedDatalinkChannel {
        /// Interface used for the channel.
        interface: String,
    },
    /// The datalink backend could not allocate a write buffer.
    SendBufferUnavailable {
        /// Interface selected for sending.
        interface: String,
        /// Packet byte length.
        len: usize,
    },
    /// A platform or permission error occurred while opening or writing a raw socket.
    Io {
        /// Stable operation name.
        operation: &'static str,
        /// Underlying operating-system error.
        source: io::Error,
    },
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(err) => write!(f, "{err}"),
            Self::InterfaceRequired => write!(f, "send interface is required"),
            Self::InvalidInterfaceName { name, reason } => {
                write!(f, "invalid interface name '{name}': {reason}")
            }
            Self::InterfaceNotFound { name } => write!(f, "interface '{name}' was not found"),
            Self::UnsupportedPacketShape {
                mode,
                summary,
                reason,
            } => write!(
                f,
                "cannot build {mode:?} send plan for packet '{summary}': {reason}"
            ),
            Self::UnsupportedSendTarget { target, reason } => {
                write!(f, "cannot transmit {target:?}: {reason}")
            }
            Self::UnsupportedDatalinkChannel { interface } => {
                write!(
                    f,
                    "unsupported datalink channel for interface '{interface}'"
                )
            }
            Self::SendBufferUnavailable { interface, len } => write!(
                f,
                "send buffer for interface '{interface}' could not accept {len} bytes"
            ),
            Self::Io { operation, source } => write!(f, "{operation} failed: {source}"),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Packet(err) => Some(err),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<CrafterError> for NetError {
    fn from(value: CrafterError) -> Self {
        Self::Packet(value)
    }
}

/// Caller intent for selecting a send path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum SendMode {
    /// Infer L2 vs L3 from the first packet layer.
    #[default]
    Auto,
    /// Require a link-layer frame, such as Ethernet.
    LinkLayer,
    /// Require a network-layer datagram, such as IPv4 or IPv6.
    NetworkLayer,
}

/// Planned packet transmission target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SendTarget {
    /// Send bytes as a link-layer frame.
    LinkLayer {
        /// Link-layer encoding used by the packet.
        link_type: LinkType,
    },
    /// Send bytes as a network-layer packet.
    NetworkLayer {
        /// Network-layer encoding used by the packet.
        network_layer: NetworkLayer,
        /// Destination address extracted from the network header.
        destination: IpAddr,
        /// IPv4 protocol or IPv6 next-header value extracted from compiled bytes.
        protocol: u8,
    },
}

impl SendTarget {
    /// Return true when this target sends a link-layer frame.
    pub const fn is_link_layer(self) -> bool {
        matches!(self, Self::LinkLayer { .. })
    }

    /// Return true when this target sends a network-layer packet.
    pub const fn is_network_layer(self) -> bool {
        matches!(self, Self::NetworkLayer { .. })
    }
}

/// Builder for raw packet send behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendOptions {
    interface: Option<String>,
    mode: SendMode,
    dry_run: bool,
    write_timeout: Option<Duration>,
    write_buffer_size: usize,
}

impl SendOptions {
    /// Create send options with auto L2/L3 detection and live sending enabled.
    pub const fn new() -> Self {
        Self {
            interface: None,
            mode: SendMode::Auto,
            dry_run: false,
            write_timeout: None,
            write_buffer_size: 4096,
        }
    }

    /// Select the interface used for sending.
    pub fn interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = Some(interface.into());
        self
    }

    /// Scapy/libcrafter-style alias for [`Self::interface`].
    pub fn iface(self, interface: impl Into<String>) -> Self {
        self.interface(interface)
    }

    /// Set the send mode.
    pub const fn mode(mut self, mode: SendMode) -> Self {
        self.mode = mode;
        self
    }

    /// Require a link-layer send plan.
    pub const fn link_layer(self) -> Self {
        self.mode(SendMode::LinkLayer)
    }

    /// Require a network-layer send plan.
    pub const fn network_layer(self) -> Self {
        self.mode(SendMode::NetworkLayer)
    }

    /// Compile and plan the send without transmitting bytes.
    pub const fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// Enable live transmission for these options.
    pub const fn live(mut self) -> Self {
        self.dry_run = false;
        self
    }

    /// Set the raw socket write timeout hint.
    pub const fn write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = Some(timeout);
        self
    }

    /// Clear the raw socket write timeout hint.
    pub const fn no_write_timeout(mut self) -> Self {
        self.write_timeout = None;
        self
    }

    /// Set the raw socket write buffer size hint.
    pub const fn write_buffer_size(mut self, size: usize) -> Self {
        self.write_buffer_size = size;
        self
    }

    /// Selected interface, if any.
    pub fn interface_name(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    /// Selected send mode.
    pub const fn send_mode(&self) -> SendMode {
        self.mode
    }

    /// Return true when send calls should only compile and plan.
    pub const fn is_dry_run(&self) -> bool {
        self.dry_run
    }
}

impl Default for SendOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&str> for SendOptions {
    fn from(interface: &str) -> Self {
        Self::new().interface(interface)
    }
}

impl From<String> for SendOptions {
    fn from(interface: String) -> Self {
        Self::new().interface(interface)
    }
}

/// A compiled send plan that can be inspected locally without transmitting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPlan {
    interface: String,
    mode: SendMode,
    target: SendTarget,
    packet: CompiledPacket,
}

impl SendPlan {
    /// Build a send plan by compiling a packet and resolving the requested send target.
    pub fn from_packet(packet: &Packet, options: impl Into<SendOptions>) -> Result<Self> {
        let options = options.into();
        let interface = validated_interface(&options)?;
        let compiled = packet.compile()?;
        let target = infer_send_target(packet, compiled.as_bytes(), options.mode)?;

        Ok(Self {
            interface,
            mode: options.mode,
            target,
            packet: compiled,
        })
    }

    /// Interface selected for sending.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Requested send mode.
    pub const fn requested_mode(&self) -> SendMode {
        self.mode
    }

    /// Resolved send target.
    pub const fn target(&self) -> SendTarget {
        self.target
    }

    /// Compiled packet bytes to send.
    pub fn bytes(&self) -> &[u8] {
        self.packet.as_bytes()
    }

    /// Compiled packet length.
    pub fn len(&self) -> usize {
        self.packet.len()
    }

    /// Return true when the compiled packet is empty.
    pub fn is_empty(&self) -> bool {
        self.packet.is_empty()
    }

    /// Borrow the compiled packet.
    pub const fn compiled_packet(&self) -> &CompiledPacket {
        &self.packet
    }
}

/// Report returned by a send operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReport {
    plan: SendPlan,
    bytes_sent: usize,
    dry_run: bool,
}

impl SendReport {
    /// Create a report from a plan and sent-byte count.
    pub const fn new(plan: SendPlan, bytes_sent: usize, dry_run: bool) -> Self {
        Self {
            plan,
            bytes_sent,
            dry_run,
        }
    }

    /// Send plan used by the operation.
    pub const fn plan(&self) -> &SendPlan {
        &self.plan
    }

    /// Number of bytes accepted by the backend.
    pub const fn bytes_sent(&self) -> usize {
        self.bytes_sent
    }

    /// Return true when the operation was compile-only.
    pub const fn is_dry_run(&self) -> bool {
        self.dry_run
    }
}

/// Raw packet sender with explicit options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketSender {
    options: SendOptions,
}

impl SocketSender {
    /// Create a sender from options.
    pub fn new(options: impl Into<SendOptions>) -> Self {
        Self {
            options: options.into(),
        }
    }

    /// Create a compile-only sender for an interface.
    pub fn dry_run(interface: impl Into<String>) -> Self {
        Self::new(SendOptions::new().interface(interface).dry_run())
    }

    /// Borrow this sender's options.
    pub const fn options(&self) -> &SendOptions {
        &self.options
    }

    /// Compile a packet and return a send plan without transmitting bytes.
    pub fn plan(&self, packet: &Packet) -> Result<SendPlan> {
        SendPlan::from_packet(packet, self.options.clone())
    }

    /// Send a packet or return a dry-run report when configured for dry-run.
    pub fn send(&self, packet: &Packet) -> Result<SendReport> {
        let plan = self.plan(packet)?;
        if self.options.dry_run {
            let len = plan.len();
            return Ok(SendReport::new(plan, len, true));
        }

        let bytes_sent = transmit_plan(&plan, &self.options)?;
        Ok(SendReport::new(plan, bytes_sent, false))
    }
}

/// Backwards-compatible alias for libcrafter's `SocketSend` concept.
pub type SocketSend = SocketSender;

/// Alias used by examples that want an explicitly raw sender name.
pub type RawSender = SocketSender;

/// Extension methods for sending packets.
pub trait PacketSendExt {
    /// Build a compile-only send plan.
    fn send_plan(&self, options: impl Into<SendOptions>) -> Result<SendPlan>;

    /// Compile and plan a send without transmitting bytes.
    fn send_dry_run(&self, options: impl Into<SendOptions>) -> Result<SendPlan>;

    /// Send a packet according to the supplied options.
    fn send(&self, options: impl Into<SendOptions>) -> Result<SendReport>;
}

impl PacketSendExt for Packet {
    fn send_plan(&self, options: impl Into<SendOptions>) -> Result<SendPlan> {
        SendPlan::from_packet(self, options)
    }

    fn send_dry_run(&self, options: impl Into<SendOptions>) -> Result<SendPlan> {
        SendPlan::from_packet(self, options.into().dry_run())
    }

    fn send(&self, options: impl Into<SendOptions>) -> Result<SendReport> {
        SocketSender::new(options).send(self)
    }
}

/// Compile and send a packet in one call.
pub fn send_packet(packet: &Packet, options: impl Into<SendOptions>) -> Result<SendReport> {
    SocketSender::new(options).send(packet)
}

/// Build a dry-run send plan in one call.
pub fn send_plan(packet: &Packet, options: impl Into<SendOptions>) -> Result<SendPlan> {
    SendPlan::from_packet(packet, options.into().dry_run())
}

/// Interface helper namespace reserved for later address discovery APIs.
pub mod interface {}

/// Routing helper namespace reserved for later route lookup APIs.
pub mod route {}

/// Socket helper namespace re-exporting the first stable sender types.
pub mod socket {
    pub use crate::{
        send_packet, send_plan, NetError, PacketSendExt, RawSender, SendMode, SendOptions,
        SendPlan, SendReport, SendTarget, SocketSend, SocketSender,
    };
}

fn validated_interface(options: &SendOptions) -> Result<String> {
    let interface = options
        .interface_name()
        .ok_or(NetError::InterfaceRequired)?
        .to_string();

    if interface.trim().is_empty() {
        return Err(NetError::InvalidInterfaceName {
            name: interface,
            reason: "interface name must not be empty",
        });
    }
    if interface.as_bytes().contains(&0) {
        return Err(NetError::InvalidInterfaceName {
            name: interface,
            reason: "interface name must not contain NUL bytes",
        });
    }

    Ok(interface)
}

fn infer_send_target(packet: &Packet, bytes: &[u8], mode: SendMode) -> Result<SendTarget> {
    let Some(first) = packet.get(0) else {
        return Err(NetError::UnsupportedPacketShape {
            mode,
            summary: packet.summary(),
            reason: "empty packets cannot be sent",
        });
    };

    match mode {
        SendMode::Auto => infer_auto_target(packet, first, bytes),
        SendMode::LinkLayer => infer_link_target(packet, first),
        SendMode::NetworkLayer => infer_network_target(packet, first, bytes),
    }
}

fn infer_auto_target(packet: &Packet, first: &dyn Layer, bytes: &[u8]) -> Result<SendTarget> {
    if is_link_layer(first) {
        infer_link_target(packet, first)
    } else if is_network_layer(first) {
        infer_network_target(packet, first, bytes)
    } else {
        Err(NetError::UnsupportedPacketShape {
            mode: SendMode::Auto,
            summary: packet.summary(),
            reason: "first layer must be Ethernet, LinuxSll, NullLoopback, IPv4, or IPv6",
        })
    }
}

fn infer_link_target(packet: &Packet, first: &dyn Layer) -> Result<SendTarget> {
    if first.as_any().is::<Ethernet>() {
        Ok(SendTarget::LinkLayer {
            link_type: LinkType::Ethernet,
        })
    } else if first.as_any().is::<crafter_core::LinuxSll>() {
        Ok(SendTarget::LinkLayer {
            link_type: LinkType::LinuxSll,
        })
    } else if first.as_any().is::<crafter_core::NullLoopback>() {
        Ok(SendTarget::LinkLayer {
            link_type: LinkType::NullLoopback,
        })
    } else {
        Err(NetError::UnsupportedPacketShape {
            mode: SendMode::LinkLayer,
            summary: packet.summary(),
            reason: "link-layer sends require a supported link header as the first layer",
        })
    }
}

fn infer_network_target(packet: &Packet, first: &dyn Layer, bytes: &[u8]) -> Result<SendTarget> {
    if let Some(ipv4) = first.as_any().downcast_ref::<Ipv4>() {
        let protocol = bytes
            .get(9)
            .copied()
            .unwrap_or_else(|| ipv4_protocol(packet, ipv4));
        Ok(SendTarget::NetworkLayer {
            network_layer: NetworkLayer::Ipv4,
            destination: IpAddr::V4(ipv4.destination()),
            protocol,
        })
    } else if let Some(ipv6) = first.as_any().downcast_ref::<Ipv6>() {
        let protocol = bytes
            .get(6)
            .copied()
            .unwrap_or_else(|| ipv6_next_header(packet, ipv6));
        Ok(SendTarget::NetworkLayer {
            network_layer: NetworkLayer::Ipv6,
            destination: IpAddr::V6(ipv6.destination()),
            protocol,
        })
    } else {
        Err(NetError::UnsupportedPacketShape {
            mode: SendMode::NetworkLayer,
            summary: packet.summary(),
            reason: "network-layer sends require IPv4 or IPv6 as the first layer",
        })
    }
}

fn is_link_layer(layer: &dyn Layer) -> bool {
    layer.as_any().is::<Ethernet>()
        || layer.as_any().is::<crafter_core::LinuxSll>()
        || layer.as_any().is::<crafter_core::NullLoopback>()
}

fn is_network_layer(layer: &dyn Layer) -> bool {
    layer.as_any().is::<Ipv4>() || layer.as_any().is::<Ipv6>()
}

fn ipv4_protocol(packet: &Packet, ipv4: &Ipv4) -> u8 {
    if ipv4.protocol_value() != 0 {
        return ipv4.protocol_value();
    }
    packet.get(1).map(layer_protocol).unwrap_or(0)
}

fn ipv6_next_header(packet: &Packet, ipv6: &Ipv6) -> u8 {
    if ipv6.next_header_value() != 0 {
        return ipv6.next_header_value();
    }
    packet.get(1).map(layer_protocol).unwrap_or(0)
}

fn layer_protocol(layer: &dyn Layer) -> u8 {
    if layer.as_any().is::<Icmp>() {
        IPPROTO_ICMP
    } else if layer.as_any().is::<Icmpv6>() {
        IPPROTO_ICMPV6
    } else if layer.as_any().is::<Tcp>() {
        IPPROTO_TCP
    } else if layer.as_any().is::<Udp>() {
        IPPROTO_UDP
    } else if layer.as_any().is::<Ipv6>() {
        crafter_core::IPPROTO_IPV6
    } else {
        0
    }
}

fn transmit_plan(plan: &SendPlan, options: &SendOptions) -> Result<usize> {
    match plan.target {
        SendTarget::LinkLayer { link_type } => transmit_link(plan, options, link_type),
        SendTarget::NetworkLayer {
            network_layer,
            destination,
            protocol,
        } => transmit_network(plan, options, network_layer, destination, protocol),
    }
}

fn transmit_link(plan: &SendPlan, options: &SendOptions, link_type: LinkType) -> Result<usize> {
    if link_type != LinkType::Ethernet {
        return Err(NetError::UnsupportedSendTarget {
            target: plan.target,
            reason: "live link-layer send currently supports Ethernet frames only",
        });
    }

    let interface = datalink::interfaces()
        .into_iter()
        .find(|candidate| candidate.name == plan.interface)
        .ok_or_else(|| NetError::InterfaceNotFound {
            name: plan.interface.clone(),
        })?;

    let mut config = datalink::Config::default();
    config.channel_type = ChannelType::Layer2;
    config.write_timeout = options.write_timeout;
    config.write_buffer_size = options.write_buffer_size.max(plan.len());

    let channel = datalink::channel(&interface, config).map_err(|source| NetError::Io {
        operation: "open datalink channel",
        source,
    })?;

    match channel {
        Channel::Ethernet(mut tx, _) => {
            let result =
                tx.send_to(plan.bytes(), None)
                    .ok_or_else(|| NetError::SendBufferUnavailable {
                        interface: plan.interface.clone(),
                        len: plan.len(),
                    })?;
            result.map_err(|source| NetError::Io {
                operation: "send datalink frame",
                source,
            })?;
            Ok(plan.len())
        }
        _ => Err(NetError::UnsupportedDatalinkChannel {
            interface: plan.interface.clone(),
        }),
    }
}

fn transmit_network(
    plan: &SendPlan,
    options: &SendOptions,
    network_layer: NetworkLayer,
    destination: IpAddr,
    protocol: u8,
) -> Result<usize> {
    let channel_type = TransportChannelType::Layer3(IpNextHeaderProtocol::new(protocol));
    let buffer_size = options.write_buffer_size.max(plan.len());
    let (mut tx, _) =
        transport_channel(buffer_size, channel_type).map_err(|source| NetError::Io {
            operation: "open raw network socket",
            source,
        })?;

    match network_layer {
        NetworkLayer::Ipv4 => {
            let packet = pnet_packet::ipv4::Ipv4Packet::new(plan.bytes()).ok_or_else(|| {
                NetError::UnsupportedSendTarget {
                    target: plan.target,
                    reason: "compiled bytes are not a complete IPv4 packet",
                }
            })?;
            tx.send_to(packet, destination)
                .map_err(|source| NetError::Io {
                    operation: "send IPv4 packet",
                    source,
                })
        }
        NetworkLayer::Ipv6 => Err(NetError::UnsupportedSendTarget {
            target: plan.target,
            reason: "the selected safe backend does not support full IPv6-header Layer3 sends",
        }),
        NetworkLayer::Raw => Err(NetError::UnsupportedSendTarget {
            target: plan.target,
            reason: "raw network-layer sends require an IPv4 or IPv6 header",
        }),
    }
}

#[cfg(test)]
mod send_plan {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crafter_core::{Ethernet, Icmp, Ipv4, Ipv6, NetworkLayer, Packet, Raw, Tcp, Udp};

    use super::{PacketSendExt, SendMode, SendOptions, SendTarget, SocketSender};

    fn ipv4_packet() -> Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Udp::new().sport(1111).dport(2222)
            / Raw::from("hello")
    }

    #[test]
    fn send_plan_auto_detects_l3_ipv4_and_compiles() {
        let packet = ipv4_packet();
        let plan = packet
            .send_dry_run(SendOptions::new().iface("eth0"))
            .unwrap();

        assert_eq!(plan.interface(), "eth0");
        assert_eq!(plan.requested_mode(), SendMode::Auto);
        assert!(plan.target().is_network_layer());
        assert_eq!(plan.bytes()[0] >> 4, 4);
        assert_eq!(plan.len(), packet.compile().unwrap().len());

        match plan.target() {
            SendTarget::NetworkLayer {
                network_layer,
                destination,
                protocol,
            } => {
                assert_eq!(network_layer, NetworkLayer::Ipv4);
                assert_eq!(destination, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)));
                assert_eq!(protocol, crafter_core::IPPROTO_UDP);
            }
            _ => panic!("expected network-layer send target"),
        }
    }

    #[test]
    fn send_plan_auto_detects_l2_ethernet() {
        let packet = Ethernet::new() / ipv4_packet();
        let plan = packet
            .send_dry_run(SendOptions::new().iface("veth0"))
            .unwrap();

        assert_eq!(plan.interface(), "veth0");
        assert!(plan.target().is_link_layer());
        assert_eq!(
            plan.target(),
            SendTarget::LinkLayer {
                link_type: crafter_core::LinkType::Ethernet
            }
        );
        assert_eq!(
            plan.bytes()[12..14],
            crafter_core::ETHERTYPE_IPV4.to_be_bytes()
        );
    }

    #[test]
    fn send_plan_respects_explicit_network_intent() {
        let packet = ipv4_packet();
        let plan = packet
            .send_plan(SendOptions::new().iface("eth0").network_layer())
            .unwrap();

        assert_eq!(plan.requested_mode(), SendMode::NetworkLayer);
        assert!(plan.target().is_network_layer());
    }

    #[test]
    fn socket_sender_dry_run_returns_report_without_transmitting() {
        let packet =
            Ethernet::new() / Ipv4::new().dst(Ipv4Addr::new(203, 0, 113, 1)) / Icmp::echo_request();
        let report = SocketSender::dry_run("eth0").send(&packet).unwrap();

        assert!(report.is_dry_run());
        assert_eq!(report.bytes_sent(), report.plan().len());
        assert!(report.plan().target().is_link_layer());
    }

    #[test]
    fn send_plan_supports_ipv6_dry_run() {
        let packet = Ipv6::new()
            .src(Ipv6Addr::LOCALHOST)
            .dst(Ipv6Addr::LOCALHOST)
            / Tcp::new().sport(1234).dport(443);
        let plan = packet
            .send_dry_run(SendOptions::new().iface("lo").network_layer())
            .unwrap();

        match plan.target() {
            SendTarget::NetworkLayer {
                network_layer,
                destination,
                protocol,
            } => {
                assert_eq!(network_layer, NetworkLayer::Ipv6);
                assert_eq!(destination, IpAddr::V6(Ipv6Addr::LOCALHOST));
                assert_eq!(protocol, crafter_core::IPPROTO_TCP);
            }
            _ => panic!("expected IPv6 network-layer send target"),
        }
    }
}

#[cfg(test)]
mod send_errors {
    use crafter_core::{Ethernet, Ipv4, Packet, Raw};

    use super::{NetError, PacketSendExt, SendOptions, SocketSender};

    #[test]
    fn send_plan_requires_interface() {
        let packet = Ipv4::new() / Raw::from("payload");
        let error = packet.send_plan(SendOptions::new().dry_run()).unwrap_err();

        assert!(matches!(error, NetError::InterfaceRequired));
    }

    #[test]
    fn send_plan_rejects_empty_interface() {
        let packet = Ipv4::new() / Raw::from("payload");
        let error = packet
            .send_plan(SendOptions::new().iface("  ").dry_run())
            .unwrap_err();

        assert!(matches!(error, NetError::InvalidInterfaceName { .. }));
    }

    #[test]
    fn send_plan_rejects_packet_shape_for_auto_mode() {
        let packet = Packet::new().push(Raw::from("payload"));
        let error = packet
            .send_plan(SendOptions::new().iface("eth0").dry_run())
            .unwrap_err();

        assert!(matches!(error, NetError::UnsupportedPacketShape { .. }));
    }

    #[test]
    fn link_layer_intent_rejects_network_packet() {
        let packet = Ipv4::new() / Raw::from("payload");
        let error = packet
            .send_plan(SendOptions::new().iface("eth0").link_layer().dry_run())
            .unwrap_err();

        assert!(matches!(error, NetError::UnsupportedPacketShape { .. }));
    }

    #[test]
    fn network_layer_intent_rejects_link_packet() {
        let packet = Ethernet::new() / Ipv4::new() / Raw::from("payload");
        let error = packet
            .send_plan(SendOptions::new().iface("eth0").network_layer().dry_run())
            .unwrap_err();

        assert!(matches!(error, NetError::UnsupportedPacketShape { .. }));
    }

    #[test]
    fn live_send_reports_missing_interface_before_opening_raw_socket() {
        let packet = Ethernet::new() / Ipv4::new() / Raw::from("payload");
        let error = SocketSender::new(SendOptions::new().iface("missing-crafter-iface"))
            .send(&packet)
            .unwrap_err();

        assert!(matches!(error, NetError::InterfaceNotFound { .. }));
    }
}
