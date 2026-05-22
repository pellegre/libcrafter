//! Network interface, raw socket, routing, and send/receive helpers.

#![forbid(unsafe_code)]

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::time::Duration;

use crafter_core::{
    Arp, ArpOperation, CompiledPacket, CrafterError, Dhcp, Dns, Ethernet, Icmp, Icmpv6, Ipv4, Ipv6,
    Layer, LinkType, NetworkLayer, Packet, Tcp, Udp, BOOTP_REPLY, DHCP_CLIENT_PORT,
    DHCP_SERVER_PORT, DNS_PORT, ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST, ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP,
};
use crafter_pcap::{PcapError, Sniffer};
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
    /// Packet capture failed while waiting for a reply.
    Capture(PcapError),
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
            Self::Capture(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Packet(err) => Some(err),
            Self::Io { source, .. } => Some(source),
            Self::Capture(err) => Some(err),
            _ => None,
        }
    }
}

impl From<CrafterError> for NetError {
    fn from(value: CrafterError) -> Self {
        Self::Packet(value)
    }
}

impl From<PcapError> for NetError {
    fn from(value: PcapError) -> Self {
        Self::Capture(value)
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

/// Configuration object for send-and-receive request/reply workflows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendRecv {
    send_options: SendOptions,
    timeout: Duration,
    retries: usize,
    filter: Option<String>,
    capture_limit: usize,
}

impl SendRecv {
    /// Create send/receive options with libcrafter-like defaults.
    pub fn new() -> Self {
        Self {
            send_options: SendOptions::new(),
            timeout: Duration::from_secs(1),
            retries: 3,
            filter: None,
            capture_limit: 64,
        }
    }

    /// Select the interface used for both sending and capture.
    pub fn interface(mut self, interface: impl Into<String>) -> Self {
        self.send_options = self.send_options.interface(interface);
        self
    }

    /// Scapy/libcrafter-style alias for [`Self::interface`].
    pub fn iface(self, interface: impl Into<String>) -> Self {
        self.interface(interface)
    }

    /// Set the send mode.
    pub fn mode(mut self, mode: SendMode) -> Self {
        self.send_options = self.send_options.mode(mode);
        self
    }

    /// Require a link-layer send path.
    pub fn link_layer(self) -> Self {
        self.mode(SendMode::LinkLayer)
    }

    /// Require a network-layer send path.
    pub fn network_layer(self) -> Self {
        self.mode(SendMode::NetworkLayer)
    }

    /// Compile and plan the send without transmitting or opening capture.
    pub fn dry_run(mut self) -> Self {
        self.send_options = self.send_options.dry_run();
        self
    }

    /// Enable live send/receive behavior.
    pub fn live(mut self) -> Self {
        self.send_options = self.send_options.live();
        self
    }

    /// Set the per-attempt capture timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the number of send attempts. A zero value is treated as one attempt.
    pub fn retries(mut self, retries: usize) -> Self {
        self.retries = retries;
        self
    }

    /// libcrafter-style singular alias for [`Self::retries`].
    pub fn retry(self, retries: usize) -> Self {
        self.retries(retries)
    }

    /// Add a caller-supplied BPF filter. It is combined with the derived reply filter.
    pub fn filter(mut self, filter: impl Into<String>) -> Self {
        let filter = filter.into();
        self.filter = (!filter.trim().is_empty()).then_some(filter);
        self
    }

    /// Remove any caller-supplied BPF filter.
    pub fn clear_filter(mut self) -> Self {
        self.filter = None;
        self
    }

    /// Set the maximum captured packets inspected per send attempt.
    pub fn capture_limit(mut self, capture_limit: usize) -> Self {
        self.capture_limit = capture_limit.max(1);
        self
    }

    /// Borrow the underlying send options.
    pub const fn send_options(&self) -> &SendOptions {
        &self.send_options
    }

    /// Per-attempt timeout.
    pub const fn timeout_value(&self) -> Duration {
        self.timeout
    }

    /// Configured retry count.
    pub const fn retries_value(&self) -> usize {
        self.retries
    }

    /// Caller-supplied BPF filter, if present.
    pub fn user_filter(&self) -> Option<&str> {
        self.filter.as_deref()
    }

    /// Effective BPF filter used for capture, combining derived and user filters.
    pub fn effective_filter(&self, packet: &Packet) -> Option<String> {
        combine_filters(
            ReplyMatcher::from_packet(packet).reply_filter(),
            self.user_filter(),
        )
    }

    /// Send a packet and return the first matching reply, if any.
    pub fn send_recv(&self, packet: &Packet) -> Result<Option<Packet>> {
        Ok(self.send_recv_report(packet)?.into_reply())
    }

    /// Send a packet and return the detailed send/receive report.
    pub fn send_recv_report(&self, packet: &Packet) -> Result<SendRecvReport> {
        let interface = validated_interface(&self.send_options)?;
        let matcher = ReplyMatcher::from_packet(packet);
        let effective_filter = combine_filters(matcher.reply_filter(), self.user_filter());
        let sender = SocketSender::new(self.send_options.clone());
        let mut send_reports = Vec::new();

        if self.send_options.is_dry_run() {
            send_reports.push(sender.send(packet)?);
            return Ok(SendRecvReport::new(send_reports, None, effective_filter));
        }

        for _ in 0..self.retries.max(1) {
            let mut sniffer = Sniffer::interface(interface.clone())
                .timeout(self.timeout)
                .count(self.capture_limit);
            if let Some(filter) = effective_filter.as_deref() {
                sniffer = sniffer.filter(filter);
            }

            let mut capture = sniffer.open()?;
            send_reports.push(sender.send(packet)?);
            while let Some(reply) = capture.next_packet()? {
                if matcher.matches(reply.packet()) {
                    return Ok(SendRecvReport::new(
                        send_reports,
                        Some(reply.into_packet()),
                        effective_filter,
                    ));
                }
            }
        }

        Ok(SendRecvReport::new(send_reports, None, effective_filter))
    }
}

impl Default for SendRecv {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&str> for SendRecv {
    fn from(interface: &str) -> Self {
        Self::new().iface(interface)
    }
}

impl From<String> for SendRecv {
    fn from(interface: String) -> Self {
        Self::new().iface(interface)
    }
}

/// Backwards-compatible alias for callers that prefer an options suffix.
pub type SendRecvOptions = SendRecv;

/// Detailed result returned by send/receive operations.
#[derive(Debug, Clone)]
pub struct SendRecvReport {
    send_reports: Vec<SendReport>,
    reply: Option<Packet>,
    effective_filter: Option<String>,
}

impl SendRecvReport {
    /// Create a send/receive report.
    pub fn new(
        send_reports: Vec<SendReport>,
        reply: Option<Packet>,
        effective_filter: Option<String>,
    ) -> Self {
        Self {
            send_reports,
            reply,
            effective_filter,
        }
    }

    /// Per-attempt send reports.
    pub fn send_reports(&self) -> &[SendReport] {
        &self.send_reports
    }

    /// Number of send attempts made.
    pub fn attempts(&self) -> usize {
        self.send_reports.len()
    }

    /// Borrow the matching reply, if one was captured.
    pub fn reply(&self) -> Option<&Packet> {
        self.reply.as_ref()
    }

    /// Consume this report and return the matching reply, if one was captured.
    pub fn into_reply(self) -> Option<Packet> {
        self.reply
    }

    /// Effective capture filter used for this send/receive operation.
    pub fn effective_filter(&self) -> Option<&str> {
        self.effective_filter.as_deref()
    }

    /// Return true when no matching reply was captured.
    pub fn timed_out(&self) -> bool {
        self.reply.is_none()
    }
}

/// Protocol-aware matcher for replies to one request packet.
#[derive(Debug, Clone)]
pub struct ReplyMatcher {
    request: Packet,
}

impl ReplyMatcher {
    /// Create a matcher from a request packet.
    pub fn from_packet(request: &Packet) -> Self {
        Self {
            request: request.clone(),
        }
    }

    /// Derived BPF-style filter for likely replies.
    pub fn reply_filter(&self) -> Option<String> {
        request_reply_filter(&self.request)
    }

    /// Return true when `candidate` is a typed reply to the request.
    pub fn matches(&self, candidate: &Packet) -> bool {
        reply_matches(&self.request, candidate)
    }
}

/// Derive a BPF-style reply filter for one packet.
pub fn reply_filter(packet: &Packet) -> Option<String> {
    ReplyMatcher::from_packet(packet).reply_filter()
}

/// Return true when `candidate` is a typed reply to `request`.
pub fn reply_matches(request: &Packet, candidate: &Packet) -> bool {
    if request.layer::<Dns>().is_some() {
        return dns_reply_matches(request, candidate);
    }
    if request.layer::<Dhcp>().is_some() {
        return dhcp_reply_matches(request, candidate);
    }

    arp_reply_matches(request, candidate)
        || icmp_reply_matches(request, candidate)
        || icmpv6_reply_matches(request, candidate)
        || tcp_reply_matches(request, candidate)
        || udp_reply_matches(request, candidate)
}

/// Extension methods for send/receive packet workflows.
pub trait PacketSendRecvExt {
    /// Derive a BPF-style filter for likely replies.
    fn reply_filter(&self) -> Result<String>;

    /// Send a packet and return the first matching reply, if any.
    fn send_recv(&self, options: impl Into<SendRecv>) -> Result<Option<Packet>>;

    /// Send a packet and return a detailed send/receive report.
    fn send_recv_report(&self, options: impl Into<SendRecv>) -> Result<SendRecvReport>;
}

impl PacketSendRecvExt for Packet {
    fn reply_filter(&self) -> Result<String> {
        Ok(reply_filter(self).unwrap_or_default())
    }

    fn send_recv(&self, options: impl Into<SendRecv>) -> Result<Option<Packet>> {
        options.into().send_recv(self)
    }

    fn send_recv_report(&self, options: impl Into<SendRecv>) -> Result<SendRecvReport> {
        options.into().send_recv_report(self)
    }
}

/// Send a packet and return the first matching reply, if any.
pub fn send_recv_packet(packet: &Packet, options: impl Into<SendRecv>) -> Result<Option<Packet>> {
    options.into().send_recv(packet)
}

/// Interface helper namespace reserved for later address discovery APIs.
pub mod interface {}

/// Routing helper namespace reserved for later route lookup APIs.
pub mod route {}

/// Socket helper namespace re-exporting the first stable sender types.
pub mod socket {
    pub use crate::{
        reply_filter, reply_matches, send_packet, send_plan, send_recv_packet, NetError,
        PacketSendExt, PacketSendRecvExt, RawSender, ReplyMatcher, SendMode, SendOptions, SendPlan,
        SendRecv, SendRecvOptions, SendRecvReport, SendReport, SendTarget, SocketSend,
        SocketSender,
    };
}

/// Send/receive-oriented re-exports.
pub mod send_recv {
    pub use crate::{
        reply_filter, reply_matches, send_recv_packet, PacketSendRecvExt, ReplyMatcher, SendRecv,
        SendRecvOptions, SendRecvReport,
    };
}

fn request_reply_filter(packet: &Packet) -> Option<String> {
    if packet.layer::<Dhcp>().is_some() {
        return Some(dhcp_filter());
    }
    if packet.layer::<Dns>().is_some() {
        return Some(transport_filter("udp", packet, Some(DNS_PORT), None));
    }
    if let Some(arp) = packet.layer::<Arp>() {
        return Some(arp_filter(arp));
    }
    if packet.layer::<Icmp>().is_some() {
        return Some(protocol_filter("icmp", packet));
    }
    if packet.layer::<Icmpv6>().is_some() {
        return Some(protocol_filter("icmp6", packet));
    }
    if let Some(tcp) = packet.layer::<Tcp>() {
        return Some(transport_filter(
            "tcp",
            packet,
            Some(tcp.destination_port_value()),
            Some(tcp.source_port_value()),
        ));
    }
    if let Some(udp) = packet.layer::<Udp>() {
        return Some(transport_filter(
            "udp",
            packet,
            Some(udp.destination_port_value()),
            Some(udp.source_port_value()),
        ));
    }

    None
}

fn combine_filters(derived: Option<String>, user: Option<&str>) -> Option<String> {
    let user = user.map(str::trim).filter(|filter| !filter.is_empty());
    match (derived, user) {
        (Some(derived), Some(user)) => Some(format!("({derived}) and ({user})")),
        (Some(derived), None) => Some(derived),
        (None, Some(user)) => Some(user.to_string()),
        (None, None) => None,
    }
}

fn dhcp_filter() -> String {
    format!("udp and src port {DHCP_SERVER_PORT} and dst port {DHCP_CLIENT_PORT}")
}

fn arp_filter(arp: &Arp) -> String {
    let mut terms = vec!["arp".to_string()];
    if let Some(target) = arp.target_ipv4() {
        terms.push(format!("src host {target}"));
    }
    if let Some(sender) = arp.sender_ipv4() {
        terms.push(format!("dst host {sender}"));
    }
    terms.join(" and ")
}

fn protocol_filter(protocol: &str, packet: &Packet) -> String {
    let mut terms = vec![protocol.to_string()];
    if let Some(hosts) = reversed_host_terms(packet) {
        terms.extend(hosts);
    }
    terms.join(" and ")
}

fn transport_filter(
    protocol: &str,
    packet: &Packet,
    source_port: Option<u16>,
    destination_port: Option<u16>,
) -> String {
    let mut terms = vec![protocol.to_string()];
    if let Some(hosts) = reversed_host_terms(packet) {
        terms.extend(hosts);
    }
    if let Some(source_port) = source_port {
        terms.push(format!("src port {source_port}"));
    }
    if let Some(destination_port) = destination_port {
        terms.push(format!("dst port {destination_port}"));
    }
    terms.join(" and ")
}

fn reversed_host_terms(packet: &Packet) -> Option<Vec<String>> {
    if let Some(ipv4) = packet.layer::<Ipv4>() {
        Some(vec![
            format!("src host {}", ipv4.destination()),
            format!("dst host {}", ipv4.source()),
        ])
    } else {
        packet.layer::<Ipv6>().map(|ipv6| {
            vec![
                format!("src host {}", ipv6.destination()),
                format!("dst host {}", ipv6.source()),
            ]
        })
    }
}

fn arp_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    let Some(request_arp) = request.layer::<Arp>() else {
        return false;
    };
    let Some(candidate_arp) = candidate.layer::<Arp>() else {
        return false;
    };

    request_arp.opcode_value() == u16::from(ArpOperation::Request)
        && candidate_arp.opcode_value() == u16::from(ArpOperation::Reply)
        && candidate_arp.sender_protocol_bytes_value() == request_arp.target_protocol_bytes_value()
        && candidate_arp.target_protocol_bytes_value() == request_arp.sender_protocol_bytes_value()
        && candidate_arp.target_hardware_bytes_value() == request_arp.sender_hardware_bytes_value()
}

fn icmp_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    let Some(request_icmp) = request.layer::<Icmp>() else {
        return false;
    };
    let Some(candidate_icmp) = candidate.layer::<Icmp>() else {
        return false;
    };

    request_icmp.icmp_type_value() == ICMP_ECHO_REQUEST
        && candidate_icmp.icmp_type_value() == ICMP_ECHO_REPLY
        && request_icmp.identifier_value() == candidate_icmp.identifier_value()
        && request_icmp.sequence_number_value() == candidate_icmp.sequence_number_value()
        && ip_addresses_are_reversed(request, candidate)
}

fn icmpv6_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    let Some(request_icmp) = request.layer::<Icmpv6>() else {
        return false;
    };
    let Some(candidate_icmp) = candidate.layer::<Icmpv6>() else {
        return false;
    };

    request_icmp.icmp_type_value() == ICMPV6_ECHO_REQUEST
        && candidate_icmp.icmp_type_value() == ICMPV6_ECHO_REPLY
        && request_icmp.identifier_value() == candidate_icmp.identifier_value()
        && request_icmp.sequence_number_value() == candidate_icmp.sequence_number_value()
        && ip_addresses_are_reversed(request, candidate)
}

fn tcp_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    let Some(request_tcp) = request.layer::<Tcp>() else {
        return false;
    };
    let Some(candidate_tcp) = candidate.layer::<Tcp>() else {
        return false;
    };

    candidate_tcp.source_port_value() == request_tcp.destination_port_value()
        && candidate_tcp.destination_port_value() == request_tcp.source_port_value()
        && ip_addresses_are_reversed(request, candidate)
}

fn udp_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    let Some(request_udp) = request.layer::<Udp>() else {
        return false;
    };
    let Some(candidate_udp) = candidate.layer::<Udp>() else {
        return false;
    };

    candidate_udp.source_port_value() == request_udp.destination_port_value()
        && candidate_udp.destination_port_value() == request_udp.source_port_value()
        && ip_addresses_are_reversed(request, candidate)
}

fn dns_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    let Some(request_dns) = request.layer::<Dns>() else {
        return false;
    };
    let Some(candidate_dns) = candidate.layer::<Dns>() else {
        return false;
    };

    !request_dns.is_response()
        && candidate_dns.is_response()
        && request_dns.id_value() == candidate_dns.id_value()
        && udp_optional_reply_matches(request, candidate)
}

fn dhcp_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    let Some(request_dhcp) = request.layer::<Dhcp>() else {
        return false;
    };
    let Some(candidate_dhcp) = candidate.layer::<Dhcp>() else {
        return false;
    };

    candidate_dhcp.op_value() == BOOTP_REPLY
        && request_dhcp.transaction_id_value() == candidate_dhcp.transaction_id_value()
        && request_dhcp.client_hardware_address_value()
            == candidate_dhcp.client_hardware_address_value()
        && dhcp_transport_reply_matches(request, candidate)
}

fn dhcp_transport_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    match (request.layer::<Udp>(), candidate.layer::<Udp>()) {
        (Some(request_udp), Some(candidate_udp)) => {
            request_udp.source_port_value() == DHCP_CLIENT_PORT
                && request_udp.destination_port_value() == DHCP_SERVER_PORT
                && candidate_udp.source_port_value() == DHCP_SERVER_PORT
                && candidate_udp.destination_port_value() == DHCP_CLIENT_PORT
        }
        (None, None) => true,
        _ => false,
    }
}

fn udp_optional_reply_matches(request: &Packet, candidate: &Packet) -> bool {
    match (request.layer::<Udp>(), candidate.layer::<Udp>()) {
        (Some(_), Some(_)) => udp_reply_matches(request, candidate),
        (None, None) => ip_addresses_are_reversed(request, candidate),
        _ => false,
    }
}

fn ip_addresses_are_reversed(request: &Packet, candidate: &Packet) -> bool {
    ipv4_addresses_are_reversed(request, candidate)
        && ipv6_addresses_are_reversed(request, candidate)
}

fn ipv4_addresses_are_reversed(request: &Packet, candidate: &Packet) -> bool {
    match (request.layer::<Ipv4>(), candidate.layer::<Ipv4>()) {
        (Some(request_ip), Some(candidate_ip)) => {
            candidate_ip.source() == request_ip.destination()
                && candidate_ip.destination() == request_ip.source()
        }
        (None, None) => true,
        _ => false,
    }
}

fn ipv6_addresses_are_reversed(request: &Packet, candidate: &Packet) -> bool {
    match (request.layer::<Ipv6>(), candidate.layer::<Ipv6>()) {
        (Some(request_ip), Some(candidate_ip)) => {
            candidate_ip.source() == request_ip.destination()
                && candidate_ip.destination() == request_ip.source()
        }
        (None, None) => true,
        _ => false,
    }
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

#[cfg(test)]
mod send_recv_filters {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use crafter_core::{Arp, Dns, Icmp, Icmpv6, IntoPacket, Ipv4, Ipv6, MacAddr, Tcp, Udp};

    use super::{PacketSendRecvExt, SendRecv};

    #[test]
    fn reply_filter_for_icmp_reverses_ipv4_hosts() {
        let packet = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Icmp::echo_request().id(7).seq(9);

        assert_eq!(
            packet.reply_filter().unwrap(),
            "icmp and src host 198.51.100.20 and dst host 192.0.2.10"
        );
    }

    #[test]
    fn reply_filter_for_icmpv6_reverses_ipv6_hosts() {
        let packet = Ipv6::new()
            .src(Ipv6Addr::LOCALHOST)
            .dst(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
            / Icmpv6::echo_request().id(7).seq(9);

        assert_eq!(
            packet.reply_filter().unwrap(),
            "icmp6 and src host 2001:db8::1 and dst host ::1"
        );
    }

    #[test]
    fn reply_filter_for_tcp_reverses_ports_and_combines_user_filter() {
        let packet = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Tcp::new().sport(44444).dport(80);

        let options = SendRecv::new()
            .iface("eth0")
            .timeout(Duration::from_millis(100))
            .retry(2)
            .filter("tcp[tcpflags] & tcp-rst != 0");

        assert_eq!(
            options.effective_filter(&packet).unwrap(),
            "(tcp and src host 198.51.100.20 and dst host 192.0.2.10 and src port 80 and dst port 44444) and (tcp[tcpflags] & tcp-rst != 0)"
        );
    }

    #[test]
    fn reply_filter_for_dns_uses_server_port_and_transaction_hosts() {
        let packet = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(8, 8, 8, 8))
            / Udp::new().sport(53000).dport(53)
            / Dns::a_query("example.com").id(0x1234);

        assert_eq!(
            packet.reply_filter().unwrap(),
            "udp and src host 8.8.8.8 and dst host 192.0.2.10 and src port 53"
        );
    }

    #[test]
    fn reply_filter_for_dhcp_uses_server_to_client_ports() {
        let mac = MacAddr::new([0x02, 0, 0, 0, 0, 1]);
        let packet = Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
            / Udp::dhcp_client()
            / crafter_core::Dhcp::discover(mac).xid(0xfeed_beef);

        assert_eq!(
            packet.reply_filter().unwrap(),
            "udp and src port 67 and dst port 68"
        );
    }

    #[test]
    fn reply_filter_for_arp_uses_target_and_sender_hosts() {
        let packet = Arp::who_has(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(192, 0, 2, 1),
            MacAddr::new([0x02, 0, 0, 0, 0, 1]),
        )
        .into_packet();

        assert_eq!(
            packet.reply_filter().unwrap(),
            "arp and src host 192.0.2.1 and dst host 192.0.2.10"
        );
    }
}

#[cfg(test)]
mod reply_matching {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crafter_core::{
        Arp, Dhcp, DhcpMessageType, Dns, DnsRecord, Icmp, Icmpv6, IntoPacket, Ipv4, Ipv6, MacAddr,
        Packet, Raw, Tcp, Udp, DNS_TYPE_A, TCP_FLAG_ACK, TCP_FLAG_RST, TCP_FLAG_SYN,
    };

    use super::{reply_matches, ReplyMatcher};

    #[test]
    fn matches_arp_is_at_reply() {
        let requester = MacAddr::new([0x02, 0, 0, 0, 0, 1]);
        let responder = MacAddr::new([0x02, 0, 0, 0, 0, 2]);
        let request = Arp::who_has(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(192, 0, 2, 1),
            requester,
        )
        .into_packet();
        let reply = Arp::is_at(
            Ipv4Addr::new(192, 0, 2, 1),
            responder,
            Ipv4Addr::new(192, 0, 2, 10),
            requester,
        )
        .into_packet();

        assert!(reply_matches(&request, &reply));
    }

    #[test]
    fn matches_icmp_echo_reply_after_decode_roundtrip() {
        let request = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Icmp::echo_request().id(7).seq(9)
            / Raw::from("hello");
        let reply = Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 20))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Icmp::echo_reply().id(7).seq(9)
            / Raw::from("hello");
        let decoded_reply = Packet::decode_from_l3(
            crafter_core::NetworkLayer::Ipv4,
            reply.compile().unwrap().as_bytes(),
        )
        .unwrap();

        assert!(ReplyMatcher::from_packet(&request).matches(&decoded_reply));
    }

    #[test]
    fn rejects_icmp_echo_reply_with_wrong_sequence() {
        let request = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Icmp::echo_request().id(7).seq(9);
        let reply = Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 20))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Icmp::echo_reply().id(7).seq(10);

        assert!(!reply_matches(&request, &reply));
    }

    #[test]
    fn matches_icmpv6_echo_reply() {
        let request = Ipv6::new()
            .src(Ipv6Addr::LOCALHOST)
            .dst(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
            / Icmpv6::echo_request().id(11).seq(12);
        let reply = Ipv6::new()
            .src(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
            .dst(Ipv6Addr::LOCALHOST)
            / Icmpv6::echo_reply().id(11).seq(12);

        assert!(reply_matches(&request, &reply));
    }

    #[test]
    fn matches_tcp_reply_by_reversed_flow() {
        let request = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Tcp::new()
                .sport(44444)
                .dport(80)
                .seq(100)
                .flags(TCP_FLAG_SYN);
        let reply = Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 20))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Tcp::new()
                .sport(80)
                .dport(44444)
                .seq(900)
                .ack(101)
                .flags(TCP_FLAG_SYN | TCP_FLAG_ACK);
        let reset = Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 20))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Tcp::new()
                .sport(80)
                .dport(44444)
                .ack(101)
                .flags(TCP_FLAG_RST | TCP_FLAG_ACK);

        assert!(reply_matches(&request, &reply));
        assert!(reply_matches(&request, &reset));
    }

    #[test]
    fn matches_udp_reply_by_reversed_flow() {
        let request = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Udp::new().sport(44444).dport(9999)
            / Raw::from("request");
        let reply = Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 20))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Udp::new().sport(9999).dport(44444)
            / Raw::from("reply");

        assert!(reply_matches(&request, &reply));
    }

    #[test]
    fn matches_dns_response_by_id_and_reversed_udp_flow() {
        let request = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(8, 8, 8, 8))
            / Udp::new().sport(53000).dport(53)
            / Dns::a_query("example.com").id(0x1234);
        let reply = Ipv4::new()
            .src(Ipv4Addr::new(8, 8, 8, 8))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Udp::new().sport(53).dport(53000)
            / Dns::a_query("example.com")
                .id(0x1234)
                .response(true)
                .answer(DnsRecord::a(
                    "example.com",
                    Ipv4Addr::new(93, 184, 216, 34),
                    60,
                ));
        let wrong_id = Ipv4::new()
            .src(Ipv4Addr::new(8, 8, 8, 8))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Udp::new().sport(53).dport(53000)
            / Dns::query("example.com", DNS_TYPE_A)
                .id(0x4321)
                .response(true);

        assert!(reply_matches(&request, &reply));
        assert!(!reply_matches(&request, &wrong_id));
    }

    #[test]
    fn matches_dhcp_offer_by_transaction_and_client_hardware_address() {
        let mac = MacAddr::new([0x02, 0, 0, 0, 0, 1]);
        let request = Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
            / Udp::dhcp_client()
            / Dhcp::discover(mac).xid(0xfeed_beef);
        let reply = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::BROADCAST)
            / Udp::dhcp_server()
            / Dhcp::offer(
                mac,
                Ipv4Addr::new(192, 0, 2, 100),
                Ipv4Addr::new(192, 0, 2, 1),
            )
            .xid(0xfeed_beef);
        let wrong_xid = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::BROADCAST)
            / Udp::dhcp_server()
            / Dhcp::new()
                .op(crafter_core::BOOTP_REPLY)
                .client_mac(mac)
                .message_type(DhcpMessageType::Offer)
                .xid(0xfeed_beee);

        assert!(reply_matches(&request, &reply));
        assert!(!reply_matches(&request, &wrong_xid));
    }
}

#[cfg(test)]
mod send_recv_live_lab {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crafter_core::{Icmp, Ipv4};

    use super::{PacketSendRecvExt, SendRecv};

    #[test]
    #[ignore = "requires root, tcpdump, and a disposable live packet lab"]
    fn send_recv_icmp_loopback_smoke() {
        let request = Ipv4::new()
            .src(Ipv4Addr::LOCALHOST)
            .dst(Ipv4Addr::LOCALHOST)
            / Icmp::echo_request();

        let reply = request
            .send_recv(
                SendRecv::new()
                    .iface("lo")
                    .network_layer()
                    .timeout(Duration::from_secs(1))
                    .retry(1),
            )
            .unwrap();

        assert!(reply.is_some());
    }
}
