use std::io;
use std::net::IpAddr;
use std::time::Duration;

use crate::wire::RawSocketWriter;
use crate::{
    CompiledPacket, Ethernet, Icmpv4, Icmpv6, Ipv4, Ipv6, Layer, LinkType, NetworkLayer, Packet,
    Radiotap, Tcp, Udp, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP,
};
use pnet_datalink::{self as datalink, Channel, ChannelType};
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_transport::{transport_channel, TransportChannelType};

use super::error::{NetError, Result};

const IPPROTO_RAW_SOCKET: u8 = 255;

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

    /// Compatibility alias for [`Self::interface`].
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
        RawSocketWriter::new(options).plan_packet(self)
    }

    fn send_dry_run(&self, options: impl Into<SendOptions>) -> Result<SendPlan> {
        RawSocketWriter::new(options.into().dry_run()).plan_packet(self)
    }

    fn send(&self, options: impl Into<SendOptions>) -> Result<SendReport> {
        send_packet(self, options)
    }
}

/// Compile and send a packet in one call.
pub fn send_packet(packet: &Packet, options: impl Into<SendOptions>) -> Result<SendReport> {
    RawSocketWriter::new(options).send_packet(packet)
}

/// Build a dry-run send plan in one call.
pub fn send_plan(packet: &Packet, options: impl Into<SendOptions>) -> Result<SendPlan> {
    RawSocketWriter::new(options.into().dry_run()).plan_packet(packet)
}

pub(crate) fn validated_interface(options: &SendOptions) -> Result<String> {
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

fn net_io_error(operation: &'static str, source: io::Error) -> NetError {
    if source.kind() == io::ErrorKind::PermissionDenied {
        NetError::PermissionDenied { operation, source }
    } else {
        NetError::Io { operation, source }
    }
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
            reason: "first layer must be Ethernet, LinuxSll, NullLoopback, Radiotap / Dot11 for Wi-Fi, IPv4, or IPv6",
        })
    }
}

fn infer_link_target(packet: &Packet, first: &dyn Layer) -> Result<SendTarget> {
    if first.as_any().is::<Ethernet>() {
        Ok(SendTarget::LinkLayer {
            link_type: LinkType::Ethernet,
        })
    } else if first.as_any().is::<crate::LinuxSll>() {
        Ok(SendTarget::LinkLayer {
            link_type: LinkType::LinuxSll,
        })
    } else if first.as_any().is::<crate::NullLoopback>() {
        Ok(SendTarget::LinkLayer {
            link_type: LinkType::NullLoopback,
        })
    } else if first.as_any().is::<Radiotap>() {
        Ok(SendTarget::LinkLayer {
            link_type: LinkType::Radiotap,
        })
    } else {
        Err(NetError::UnsupportedPacketShape {
            mode: SendMode::LinkLayer,
            summary: packet.summary(),
            reason: "link-layer sends require Ethernet, LinuxSll, NullLoopback, or Radiotap / Dot11 Wi-Fi as the first layers",
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
        || layer.as_any().is::<crate::LinuxSll>()
        || layer.as_any().is::<crate::NullLoopback>()
        || layer.as_any().is::<Radiotap>()
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
    if layer.as_any().is::<Icmpv4>() {
        IPPROTO_ICMP
    } else if layer.as_any().is::<Icmpv6>() {
        IPPROTO_ICMPV6
    } else if layer.as_any().is::<Tcp>() {
        IPPROTO_TCP
    } else if layer.as_any().is::<Udp>() {
        IPPROTO_UDP
    } else if layer.as_any().is::<Ipv6>() {
        crate::IPPROTO_IPV6
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
    if link_type == LinkType::Radiotap {
        return Err(NetError::UnsupportedSendTarget {
            target: plan.target,
            reason: "live radiotap Wi-Fi injection is not implemented; use dry-run planning or an explicit monitor-mode radiotap backend",
        });
    }

    if link_type != LinkType::Ethernet {
        return Err(NetError::UnsupportedSendTarget {
            target: plan.target,
            reason: "live link-layer send currently supports Ethernet frames only",
        });
    }

    transmit_layer2(plan, options)
}

fn transmit_layer2(plan: &SendPlan, options: &SendOptions) -> Result<usize> {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|candidate| candidate.name == plan.interface)
        .ok_or_else(|| NetError::InterfaceNotFound {
            name: plan.interface.clone(),
        })?;

    let config = datalink::Config {
        channel_type: ChannelType::Layer2,
        write_timeout: options.write_timeout,
        write_buffer_size: options.write_buffer_size.max(plan.len()),
        ..Default::default()
    };

    let channel = datalink::channel(&interface, config)
        .map_err(|source| net_io_error("open datalink channel", source))?;

    match channel {
        Channel::Ethernet(mut tx, _) => {
            let result =
                tx.send_to(plan.bytes(), None)
                    .ok_or_else(|| NetError::SendBufferUnavailable {
                        interface: plan.interface.clone(),
                        len: plan.len(),
                    })?;
            result.map_err(|source| net_io_error("send datalink frame", source))?;
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
    // IPv4 Layer3 sends include a complete caller-compiled IP header. Opening
    // the socket as IPPROTO_RAW keeps the header's protocol byte authoritative
    // and avoids protocol-specific raw socket filtering of newer ICMP types.
    let socket_protocol = match network_layer {
        NetworkLayer::Ipv4 => IPPROTO_RAW_SOCKET,
        NetworkLayer::Ipv6 | NetworkLayer::Raw => protocol,
    };
    let channel_type = TransportChannelType::Layer3(IpNextHeaderProtocol::new(socket_protocol));
    let buffer_size = options.write_buffer_size.max(plan.len());
    let (mut tx, _) = transport_channel(buffer_size, channel_type)
        .map_err(|source| net_io_error("open raw network socket", source))?;

    match network_layer {
        NetworkLayer::Ipv4 => {
            let packet = pnet_packet::ipv4::Ipv4Packet::new(plan.bytes()).ok_or({
                NetError::UnsupportedSendTarget {
                    target: plan.target,
                    reason: "compiled bytes are not a complete IPv4 packet",
                }
            })?;
            tx.send_to(packet, destination)
                .map_err(|source| net_io_error("send IPv4 packet", source))
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
