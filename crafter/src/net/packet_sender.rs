use std::io;
use std::net::IpAddr;

use pnet_datalink::{self as datalink, Channel, ChannelType, DataLinkSender};
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_transport::{transport_channel, TransportChannelType, TransportSender};

use crate::{LinkType, NetworkLayer, Packet};

use super::error::{NetError, Result};
use super::send::{validated_interface, SendMode, SendOptions, SendPlan, SendReport, SendTarget};

pub(crate) const IPPROTO_RAW_SOCKET: u8 = 255;

pub(crate) trait LinkSenderBackend {
    fn send_link(&mut self, target: SendTarget, bytes: &[u8]) -> Result<usize>;
}

pub(crate) trait NetworkSenderBackend {
    fn send_ipv4(
        &mut self,
        target: SendTarget,
        bytes: &[u8],
        destination: IpAddr,
        protocol: u8,
    ) -> Result<usize>;
}

pub(crate) trait PnetBackend {
    type LinkSender: LinkSenderBackend;
    type NetworkSender: NetworkSenderBackend;

    fn open_link_sender(&self, plan: &SendPlan, options: &SendOptions) -> Result<Self::LinkSender>;

    fn open_network_sender(
        &self,
        options: &SendOptions,
        socket_protocol: u8,
        min_packet_len: usize,
    ) -> Result<Self::NetworkSender>;
}

pub(crate) struct PacketSender<B: PnetBackend = PnetIoBackend> {
    options: SendOptions,
    backend: B,
    link_sender: Option<B::LinkSender>,
    network_sender: Option<B::NetworkSender>,
}

impl PacketSender<PnetIoBackend> {
    pub(crate) fn open(options: impl Into<SendOptions>) -> Result<Self> {
        Self::open_with_backend(options, PnetIoBackend)
    }
}

impl<B> PacketSender<B>
where
    B: PnetBackend,
{
    pub(crate) fn open_with_backend(options: impl Into<SendOptions>, backend: B) -> Result<Self> {
        let options = options.into();
        let _interface = validated_interface(&options)?;
        if !options.is_dry_run() && options.send_mode() == SendMode::Auto {
            return Err(NetError::ExplicitSendModeRequired {
                mode: options.send_mode(),
                reason: "stateful live packet senders require explicit link_layer() or network_layer() mode",
            });
        }

        Ok(Self {
            options,
            backend,
            link_sender: None,
            network_sender: None,
        })
    }

    pub(crate) const fn options(&self) -> &SendOptions {
        &self.options
    }

    pub(crate) fn plan(&self, packet: &Packet) -> Result<SendPlan> {
        SendPlan::from_packet(packet, self.options.clone())
    }

    pub(crate) fn send(&mut self, packet: &Packet) -> Result<SendReport> {
        let plan = self.plan(packet)?;
        if self.options.is_dry_run() {
            let len = plan.len();
            return Ok(SendReport::new(plan, len, true));
        }

        let bytes_sent = self.transmit_plan(&plan)?;
        Ok(SendReport::new(plan, bytes_sent, false))
    }

    fn transmit_plan(&mut self, plan: &SendPlan) -> Result<usize> {
        self.validate_target_class(plan)?;

        match plan.target() {
            SendTarget::LinkLayer { link_type } => self.transmit_link_target(plan, link_type),
            SendTarget::NetworkLayer {
                network_layer,
                destination,
                protocol,
            } => self.transmit_network_target(plan, network_layer, destination, protocol),
        }
    }

    fn validate_target_class(&self, plan: &SendPlan) -> Result<()> {
        match (self.options.send_mode(), plan.target()) {
            (SendMode::LinkLayer, target) if target.is_network_layer() => {
                Err(NetError::UnsupportedSendTarget {
                    target,
                    reason: "stateful link-layer sender cannot transmit network-layer packets; open a network_layer() sender for this packet",
                })
            }
            (SendMode::NetworkLayer, target) if target.is_link_layer() => {
                Err(NetError::UnsupportedSendTarget {
                    target,
                    reason: "stateful network-layer sender cannot transmit link-layer frames; open a link_layer() sender for this packet",
                })
            }
            _ => Ok(()),
        }
    }

    fn transmit_link_target(&mut self, plan: &SendPlan, link_type: LinkType) -> Result<usize> {
        match link_type {
            LinkType::Ethernet | LinkType::Radiotap => self.transmit_link(plan),
            _ => Err(NetError::UnsupportedSendTarget {
                target: plan.target(),
                reason: "live link-layer send supports Ethernet and radiotap Wi-Fi frames only",
            }),
        }
    }

    fn transmit_link(&mut self, plan: &SendPlan) -> Result<usize> {
        if self.link_sender.is_none() {
            self.link_sender = Some(self.backend.open_link_sender(plan, &self.options)?);
        }

        self.link_sender
            .as_mut()
            .expect("link sender is initialized before send")
            .send_link(plan.target(), plan.bytes())
    }

    fn transmit_network_target(
        &mut self,
        plan: &SendPlan,
        network_layer: NetworkLayer,
        destination: IpAddr,
        protocol: u8,
    ) -> Result<usize> {
        match network_layer {
            NetworkLayer::Ipv4 => self.transmit_ipv4(plan, destination, protocol),
            NetworkLayer::Ipv6 => Err(NetError::UnsupportedSendTarget {
                target: plan.target(),
                reason: "the selected safe backend does not support full IPv6-header Layer3 sends",
            }),
            NetworkLayer::Raw => Err(NetError::UnsupportedSendTarget {
                target: plan.target(),
                reason: "raw network-layer sends require an IPv4 or IPv6 header",
            }),
        }
    }

    fn transmit_ipv4(
        &mut self,
        plan: &SendPlan,
        destination: IpAddr,
        protocol: u8,
    ) -> Result<usize> {
        if self.network_sender.is_none() {
            self.network_sender = Some(self.backend.open_network_sender(
                &self.options,
                IPPROTO_RAW_SOCKET,
                plan.len(),
            )?);
        }

        self.network_sender
            .as_mut()
            .expect("network sender is initialized before send")
            .send_ipv4(plan.target(), plan.bytes(), destination, protocol)
    }
}

fn transmit_link_target_with_backend<B>(
    backend: &B,
    plan: &SendPlan,
    options: &SendOptions,
    link_type: LinkType,
) -> Result<usize>
where
    B: PnetBackend,
{
    match link_type {
        LinkType::Ethernet | LinkType::Radiotap => {
            transmit_link_with_backend(backend, plan, options)
        }
        _ => Err(NetError::UnsupportedSendTarget {
            target: plan.target(),
            reason: "live link-layer send supports Ethernet and radiotap Wi-Fi frames only",
        }),
    }
}

pub(crate) fn transmit_link_once(plan: &SendPlan, options: &SendOptions) -> Result<usize> {
    transmit_link_with_backend(&PnetIoBackend, plan, options)
}

pub(crate) fn transmit_link_with_backend<B>(
    backend: &B,
    plan: &SendPlan,
    options: &SendOptions,
) -> Result<usize>
where
    B: PnetBackend,
{
    let mut sender = backend.open_link_sender(plan, options)?;
    sender.send_link(plan.target(), plan.bytes())
}

pub(crate) fn transmit_network_once(
    plan: &SendPlan,
    options: &SendOptions,
    network_layer: NetworkLayer,
    destination: IpAddr,
    protocol: u8,
) -> Result<usize> {
    transmit_network_with_backend(
        &PnetIoBackend,
        plan,
        options,
        network_layer,
        destination,
        protocol,
    )
}

pub(crate) fn transmit_network_with_backend<B>(
    backend: &B,
    plan: &SendPlan,
    options: &SendOptions,
    network_layer: NetworkLayer,
    destination: IpAddr,
    protocol: u8,
) -> Result<usize>
where
    B: PnetBackend,
{
    match network_layer {
        NetworkLayer::Ipv4 => {
            let mut sender =
                backend.open_network_sender(options, IPPROTO_RAW_SOCKET, plan.len())?;
            sender.send_ipv4(plan.target(), plan.bytes(), destination, protocol)
        }
        NetworkLayer::Ipv6 => Err(NetError::UnsupportedSendTarget {
            target: plan.target(),
            reason: "the selected safe backend does not support full IPv6-header Layer3 sends",
        }),
        NetworkLayer::Raw => Err(NetError::UnsupportedSendTarget {
            target: plan.target(),
            reason: "raw network-layer sends require an IPv4 or IPv6 header",
        }),
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PnetIoBackend;

pub(crate) struct PnetLinkSender {
    interface: String,
    tx: Box<dyn DataLinkSender>,
}

pub(crate) struct PnetNetworkSender {
    tx: TransportSender,
}

impl PnetBackend for PnetIoBackend {
    type LinkSender = PnetLinkSender;
    type NetworkSender = PnetNetworkSender;

    fn open_link_sender(&self, plan: &SendPlan, options: &SendOptions) -> Result<Self::LinkSender> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|candidate| candidate.name == plan.interface())
            .ok_or_else(|| NetError::InterfaceNotFound {
                name: plan.interface().to_string(),
            })?;

        let config = datalink::Config {
            channel_type: ChannelType::Layer2,
            write_timeout: options.write_timeout_hint(),
            write_buffer_size: options.write_buffer_size_hint().max(plan.len()),
            ..Default::default()
        };

        let channel = datalink::channel(&interface, config)
            .map_err(|source| net_io_error("open datalink channel", source))?;

        match channel {
            Channel::Ethernet(tx, _) => Ok(PnetLinkSender {
                interface: plan.interface().to_string(),
                tx,
            }),
            _ => Err(NetError::UnsupportedDatalinkChannel {
                interface: plan.interface().to_string(),
            }),
        }
    }

    fn open_network_sender(
        &self,
        options: &SendOptions,
        socket_protocol: u8,
        min_packet_len: usize,
    ) -> Result<Self::NetworkSender> {
        let channel_type = TransportChannelType::Layer3(IpNextHeaderProtocol::new(socket_protocol));
        let buffer_size = options.write_buffer_size_hint().max(min_packet_len);
        let (tx, _) = transport_channel(buffer_size, channel_type)
            .map_err(|source| net_io_error("open raw network socket", source))?;
        Ok(PnetNetworkSender { tx })
    }
}

impl LinkSenderBackend for PnetLinkSender {
    fn send_link(&mut self, _target: SendTarget, bytes: &[u8]) -> Result<usize> {
        let result =
            self.tx
                .send_to(bytes, None)
                .ok_or_else(|| NetError::SendBufferUnavailable {
                    interface: self.interface.clone(),
                    len: bytes.len(),
                })?;
        result.map_err(|source| net_io_error("send datalink frame", source))?;
        Ok(bytes.len())
    }
}

impl NetworkSenderBackend for PnetNetworkSender {
    fn send_ipv4(
        &mut self,
        target: SendTarget,
        bytes: &[u8],
        destination: IpAddr,
        _protocol: u8,
    ) -> Result<usize> {
        let packet = pnet_packet::ipv4::Ipv4Packet::new(bytes).ok_or({
            NetError::UnsupportedSendTarget {
                target,
                reason: "compiled bytes are not a complete IPv4 packet",
            }
        })?;
        self.tx
            .send_to(packet, destination)
            .map_err(|source| net_io_error("send IPv4 packet", source))
    }
}

fn net_io_error(operation: &'static str, source: io::Error) -> NetError {
    if source.kind() == io::ErrorKind::PermissionDenied {
        NetError::PermissionDenied { operation, source }
    } else {
        NetError::Io { operation, source }
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct FakePnetBackend {
    state: std::sync::Arc<std::sync::Mutex<FakePnetBackendState>>,
}

#[cfg(test)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FakePnetBackendState {
    pub(crate) link_opens: Vec<FakeLinkOpen>,
    pub(crate) network_opens: Vec<FakeNetworkOpen>,
    pub(crate) link_sends: Vec<FakeLinkSend>,
    pub(crate) network_sends: Vec<FakeNetworkSend>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FakeLinkOpen {
    pub(crate) interface: String,
    pub(crate) target: SendTarget,
    pub(crate) write_timeout: Option<std::time::Duration>,
    pub(crate) write_buffer_size: usize,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FakeNetworkOpen {
    pub(crate) socket_protocol: u8,
    pub(crate) write_buffer_size: usize,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FakeLinkSend {
    pub(crate) target: SendTarget,
    pub(crate) bytes: Vec<u8>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FakeNetworkSend {
    pub(crate) target: SendTarget,
    pub(crate) bytes: Vec<u8>,
    pub(crate) destination: IpAddr,
    pub(crate) protocol: u8,
}

#[cfg(test)]
impl FakePnetBackend {
    pub(crate) fn snapshot(&self) -> FakePnetBackendState {
        self.state
            .lock()
            .expect("fake pnet backend mutex poisoned")
            .clone()
    }
}

#[cfg(test)]
pub(crate) struct FakeLinkSender {
    state: std::sync::Arc<std::sync::Mutex<FakePnetBackendState>>,
}

#[cfg(test)]
pub(crate) struct FakeNetworkSender {
    state: std::sync::Arc<std::sync::Mutex<FakePnetBackendState>>,
}

#[cfg(test)]
impl PnetBackend for FakePnetBackend {
    type LinkSender = FakeLinkSender;
    type NetworkSender = FakeNetworkSender;

    fn open_link_sender(&self, plan: &SendPlan, options: &SendOptions) -> Result<Self::LinkSender> {
        self.state
            .lock()
            .expect("fake pnet backend mutex poisoned")
            .link_opens
            .push(FakeLinkOpen {
                interface: plan.interface().to_string(),
                target: plan.target(),
                write_timeout: options.write_timeout_hint(),
                write_buffer_size: options.write_buffer_size_hint().max(plan.len()),
            });
        Ok(FakeLinkSender {
            state: self.state.clone(),
        })
    }

    fn open_network_sender(
        &self,
        options: &SendOptions,
        socket_protocol: u8,
        min_packet_len: usize,
    ) -> Result<Self::NetworkSender> {
        self.state
            .lock()
            .expect("fake pnet backend mutex poisoned")
            .network_opens
            .push(FakeNetworkOpen {
                socket_protocol,
                write_buffer_size: options.write_buffer_size_hint().max(min_packet_len),
            });
        Ok(FakeNetworkSender {
            state: self.state.clone(),
        })
    }
}

#[cfg(test)]
impl LinkSenderBackend for FakeLinkSender {
    fn send_link(&mut self, target: SendTarget, bytes: &[u8]) -> Result<usize> {
        self.state
            .lock()
            .expect("fake pnet backend mutex poisoned")
            .link_sends
            .push(FakeLinkSend {
                target,
                bytes: bytes.to_vec(),
            });
        Ok(bytes.len())
    }
}

#[cfg(test)]
impl NetworkSenderBackend for FakeNetworkSender {
    fn send_ipv4(
        &mut self,
        target: SendTarget,
        bytes: &[u8],
        destination: IpAddr,
        protocol: u8,
    ) -> Result<usize> {
        self.state
            .lock()
            .expect("fake pnet backend mutex poisoned")
            .network_sends
            .push(FakeNetworkSend {
                target,
                bytes: bytes.to_vec(),
                destination,
                protocol,
            });
        Ok(bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use crate::{
        Dot11, Ethernet, Ipv4, Ipv6, LinkType, LinuxSll, LlcSnap, NetworkLayer, NullLoopback,
        Radiotap, Raw, Udp, IPPROTO_UDP,
    };

    use super::*;

    fn ethernet_packet() -> crate::Packet {
        ethernet_packet_with_payload("payload")
    }

    fn ethernet_packet_with_payload(payload: &'static str) -> crate::Packet {
        Ethernet::new()
            / Ipv4::new()
                .src(Ipv4Addr::new(192, 0, 2, 10))
                .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Udp::new().sport(49152).dport(53)
            / Raw::from(payload)
    }

    fn radiotap_packet_with_payload(payload: &'static str) -> crate::Packet {
        Radiotap::new()
            / Dot11::data()
            / LlcSnap::new()
            / Ipv4::new()
                .src(Ipv4Addr::new(192, 0, 2, 10))
                .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Udp::new().sport(49152).dport(53)
            / Raw::from(payload)
    }

    fn ipv4_packet() -> crate::Packet {
        ipv4_packet_to(Ipv4Addr::new(198, 51, 100, 20), "payload")
    }

    fn ipv4_packet_to(destination: Ipv4Addr, payload: &'static str) -> crate::Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(destination)
            / Udp::new().sport(49152).dport(53)
            / Raw::from(payload)
    }

    fn ipv6_packet() -> crate::Packet {
        Ipv6::new()
            .src(Ipv6Addr::new(2001, 0xdb8, 0, 0, 0, 0, 0, 10))
            .dst(Ipv6Addr::new(2001, 0xdb8, 0, 0, 0, 0, 0, 20))
            / Udp::new().sport(49152).dport(53)
            / Raw::from("payload")
    }

    fn linux_sll_packet() -> crate::Packet {
        LinuxSll::new() / ipv4_packet()
    }

    fn null_loopback_packet() -> crate::Packet {
        NullLoopback::ipv4() / ipv4_packet()
    }

    #[test]
    fn packet_sender_backend_fake_records_link_accounting() {
        let backend = FakePnetBackend::default();
        let options = SendOptions::new()
            .iface("fake0")
            .link_layer()
            .write_timeout(Duration::from_millis(25))
            .write_buffer_size(8);
        let plan = SendPlan::from_packet(&ethernet_packet(), options.clone()).unwrap();

        let bytes_sent = transmit_link_with_backend(&backend, &plan, &options).unwrap();

        assert_eq!(bytes_sent, plan.len());
        let snapshot = backend.snapshot();
        assert_eq!(snapshot.link_opens.len(), 1);
        assert_eq!(snapshot.link_opens[0].interface, "fake0");
        assert_eq!(snapshot.link_opens[0].target, plan.target());
        assert_eq!(
            snapshot.link_opens[0].write_timeout,
            Some(Duration::from_millis(25))
        );
        assert_eq!(snapshot.link_opens[0].write_buffer_size, plan.len());
        assert_eq!(snapshot.link_sends.len(), 1);
        assert_eq!(snapshot.link_sends[0].target, plan.target());
        assert_eq!(snapshot.link_sends[0].bytes, plan.bytes());
        assert!(snapshot.network_opens.is_empty());
        assert!(snapshot.network_sends.is_empty());
    }

    #[test]
    fn packet_sender_backend_fake_records_ipv4_network_accounting() {
        let backend = FakePnetBackend::default();
        let options = SendOptions::new()
            .iface("fake0")
            .network_layer()
            .write_buffer_size(4);
        let plan = SendPlan::from_packet(&ipv4_packet(), options.clone()).unwrap();
        let SendTarget::NetworkLayer {
            network_layer,
            destination,
            protocol,
        } = plan.target()
        else {
            panic!("expected IPv4 network target");
        };

        let bytes_sent = transmit_network_with_backend(
            &backend,
            &plan,
            &options,
            network_layer,
            destination,
            protocol,
        )
        .unwrap();

        assert_eq!(network_layer, NetworkLayer::Ipv4);
        assert_eq!(destination, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)));
        assert_eq!(protocol, IPPROTO_UDP);
        assert_eq!(bytes_sent, plan.len());
        let snapshot = backend.snapshot();
        assert_eq!(snapshot.network_opens.len(), 1);
        assert_eq!(
            snapshot.network_opens[0].socket_protocol,
            IPPROTO_RAW_SOCKET
        );
        assert_eq!(snapshot.network_opens[0].write_buffer_size, plan.len());
        assert_eq!(snapshot.network_sends.len(), 1);
        assert_eq!(snapshot.network_sends[0].target, plan.target());
        assert_eq!(snapshot.network_sends[0].bytes, plan.bytes());
        assert_eq!(snapshot.network_sends[0].destination, destination);
        assert_eq!(snapshot.network_sends[0].protocol, IPPROTO_UDP);
        assert!(snapshot.link_opens.is_empty());
        assert!(snapshot.link_sends.is_empty());
    }

    #[test]
    fn packet_sender_requires_explicit_live_mode() {
        let backend = FakePnetBackend::default();

        let error = match PacketSender::open_with_backend(
            SendOptions::new().iface("fake0").live(),
            backend.clone(),
        ) {
            Ok(_) => panic!("stateful live sender should reject auto mode"),
            Err(error) => error,
        };

        match error {
            NetError::ExplicitSendModeRequired { mode, reason } => {
                assert_eq!(mode, SendMode::Auto);
                assert!(reason.contains("link_layer()"));
                assert!(reason.contains("network_layer()"));
            }
            other => panic!("unexpected error: {other}"),
        }

        let snapshot = backend.snapshot();
        assert!(snapshot.link_opens.is_empty());
        assert!(snapshot.network_opens.is_empty());
        assert!(snapshot.link_sends.is_empty());
        assert!(snapshot.network_sends.is_empty());
    }

    #[test]
    fn packet_sender_dry_run() {
        let backend = FakePnetBackend::default();
        let mut sender = PacketSender::open_with_backend(
            SendOptions::new().iface("fake0").dry_run(),
            backend.clone(),
        )
        .unwrap();

        let report = sender.send(&ethernet_packet()).unwrap();

        assert!(report.is_dry_run());
        assert_eq!(report.bytes_sent(), report.plan().len());
        assert_eq!(report.plan().interface(), "fake0");
        assert_eq!(report.plan().requested_mode(), SendMode::Auto);
        assert_eq!(
            report.plan().target(),
            SendTarget::LinkLayer {
                link_type: LinkType::Ethernet,
            }
        );

        let snapshot = backend.snapshot();
        assert!(snapshot.link_opens.is_empty());
        assert!(snapshot.network_opens.is_empty());
        assert!(snapshot.link_sends.is_empty());
        assert!(snapshot.network_sends.is_empty());
    }

    #[test]
    fn live_link_layer_sender_opens_once() {
        let backend = FakePnetBackend::default();
        let mut sender = PacketSender::open_with_backend(
            SendOptions::new().iface("fake0").link_layer().live(),
            backend.clone(),
        )
        .unwrap();

        let first = ethernet_packet_with_payload("first");
        let second = ethernet_packet_with_payload("second");
        let first_report = sender.send(&first).unwrap();
        let second_report = sender.send(&second).unwrap();

        assert!(!first_report.is_dry_run());
        assert!(!second_report.is_dry_run());
        assert_eq!(first_report.bytes_sent(), first_report.plan().len());
        assert_eq!(second_report.bytes_sent(), second_report.plan().len());

        let snapshot = backend.snapshot();
        assert_eq!(snapshot.link_opens.len(), 1);
        assert_eq!(snapshot.link_sends.len(), 2);
        assert!(snapshot.network_opens.is_empty());
        assert!(snapshot.network_sends.is_empty());
    }

    #[test]
    fn live_link_layer_sender_writes_ethernet_frames() {
        let backend = FakePnetBackend::default();
        let mut sender = PacketSender::open_with_backend(
            SendOptions::new().iface("fake0").link_layer().live(),
            backend.clone(),
        )
        .unwrap();

        let first = ethernet_packet_with_payload("one");
        let second = ethernet_packet_with_payload("two");
        let first_plan = SendPlan::from_packet(
            &first,
            SendOptions::new().iface("fake0").link_layer().dry_run(),
        )
        .unwrap();
        let second_plan = SendPlan::from_packet(
            &second,
            SendOptions::new().iface("fake0").link_layer().dry_run(),
        )
        .unwrap();

        sender.send(&first).unwrap();
        sender.send(&second).unwrap();

        let snapshot = backend.snapshot();
        assert_eq!(snapshot.link_opens.len(), 1);
        assert_eq!(
            snapshot.link_opens[0].target,
            SendTarget::LinkLayer {
                link_type: LinkType::Ethernet,
            }
        );
        assert_eq!(snapshot.link_sends.len(), 2);
        assert_eq!(snapshot.link_sends[0].target, first_plan.target());
        assert_eq!(snapshot.link_sends[0].bytes, first_plan.bytes());
        assert_eq!(snapshot.link_sends[1].target, second_plan.target());
        assert_eq!(snapshot.link_sends[1].bytes, second_plan.bytes());
        assert!(snapshot.network_opens.is_empty());
        assert!(snapshot.network_sends.is_empty());
    }

    #[test]
    fn live_link_layer_sender_writes_radiotap_frames() {
        let backend = FakePnetBackend::default();
        let mut sender = PacketSender::open_with_backend(
            SendOptions::new().iface("fake0").link_layer().live(),
            backend.clone(),
        )
        .unwrap();

        let first = radiotap_packet_with_payload("one");
        let second = radiotap_packet_with_payload("two");
        let first_plan = SendPlan::from_packet(
            &first,
            SendOptions::new().iface("fake0").link_layer().dry_run(),
        )
        .unwrap();
        let second_plan = SendPlan::from_packet(
            &second,
            SendOptions::new().iface("fake0").link_layer().dry_run(),
        )
        .unwrap();

        assert_eq!(
            first_plan.target(),
            SendTarget::LinkLayer {
                link_type: LinkType::Radiotap,
            }
        );
        assert_eq!(
            second_plan.target(),
            SendTarget::LinkLayer {
                link_type: LinkType::Radiotap,
            }
        );
        assert_eq!(first_plan.bytes()[..8], [0, 0, 8, 0, 0, 0, 0, 0]);
        assert_eq!(second_plan.bytes()[..8], [0, 0, 8, 0, 0, 0, 0, 0]);

        sender.send(&first).unwrap();
        sender.send(&second).unwrap();

        let snapshot = backend.snapshot();
        assert_eq!(snapshot.link_opens.len(), 1);
        assert_eq!(
            snapshot.link_opens[0].target,
            SendTarget::LinkLayer {
                link_type: LinkType::Radiotap,
            }
        );
        assert_eq!(snapshot.link_sends.len(), 2);
        assert_eq!(snapshot.link_sends[0].target, first_plan.target());
        assert_eq!(snapshot.link_sends[0].bytes, first_plan.bytes());
        assert_eq!(snapshot.link_sends[1].target, second_plan.target());
        assert_eq!(snapshot.link_sends[1].bytes, second_plan.bytes());
        assert!(snapshot.network_opens.is_empty());
        assert!(snapshot.network_sends.is_empty());
    }

    #[test]
    fn live_ipv4_network_sender_opens_once() {
        let backend = FakePnetBackend::default();
        let mut sender = PacketSender::open_with_backend(
            SendOptions::new().iface("fake0").network_layer().live(),
            backend.clone(),
        )
        .unwrap();

        let first = ipv4_packet_to(Ipv4Addr::new(198, 51, 100, 20), "one");
        let second = ipv4_packet_to(Ipv4Addr::new(203, 0, 113, 30), "two");
        let first_report = sender.send(&first).unwrap();
        let second_report = sender.send(&second).unwrap();

        assert!(!first_report.is_dry_run());
        assert!(!second_report.is_dry_run());
        assert_eq!(first_report.bytes_sent(), first_report.plan().len());
        assert_eq!(second_report.bytes_sent(), second_report.plan().len());

        let snapshot = backend.snapshot();
        assert_eq!(snapshot.network_opens.len(), 1);
        assert_eq!(
            snapshot.network_opens[0].socket_protocol,
            IPPROTO_RAW_SOCKET
        );
        assert_eq!(snapshot.network_sends.len(), 2);
        assert!(snapshot.link_opens.is_empty());
        assert!(snapshot.link_sends.is_empty());
    }

    #[test]
    fn live_ipv4_network_sender_preserves_destinations() {
        let backend = FakePnetBackend::default();
        let mut sender = PacketSender::open_with_backend(
            SendOptions::new().iface("fake0").network_layer().live(),
            backend.clone(),
        )
        .unwrap();

        let first_destination = Ipv4Addr::new(198, 51, 100, 20);
        let second_destination = Ipv4Addr::new(203, 0, 113, 30);
        let first = ipv4_packet_to(first_destination, "first");
        let second = ipv4_packet_to(second_destination, "second");
        let first_plan = SendPlan::from_packet(
            &first,
            SendOptions::new().iface("fake0").network_layer().dry_run(),
        )
        .unwrap();
        let second_plan = SendPlan::from_packet(
            &second,
            SendOptions::new().iface("fake0").network_layer().dry_run(),
        )
        .unwrap();

        sender.send(&first).unwrap();
        sender.send(&second).unwrap();

        let snapshot = backend.snapshot();
        assert_eq!(snapshot.network_opens.len(), 1);
        assert_eq!(snapshot.network_sends.len(), 2);
        assert_eq!(snapshot.network_sends[0].target, first_plan.target());
        assert_eq!(snapshot.network_sends[0].bytes, first_plan.bytes());
        assert_eq!(
            snapshot.network_sends[0].destination,
            IpAddr::V4(first_destination)
        );
        assert_eq!(snapshot.network_sends[0].protocol, IPPROTO_UDP);
        assert_eq!(snapshot.network_sends[1].target, second_plan.target());
        assert_eq!(snapshot.network_sends[1].bytes, second_plan.bytes());
        assert_eq!(
            snapshot.network_sends[1].destination,
            IpAddr::V4(second_destination)
        );
        assert_eq!(snapshot.network_sends[1].protocol, IPPROTO_UDP);
        assert!(snapshot.link_opens.is_empty());
        assert!(snapshot.link_sends.is_empty());
    }

    #[test]
    fn packet_sender_rejects_mixed_send_classes() {
        let link_backend = FakePnetBackend::default();
        let mut link_sender = PacketSender::open_with_backend(
            SendOptions::new().iface("fake0").link_layer().live(),
            link_backend.clone(),
        )
        .unwrap();

        link_sender.send(&ethernet_packet()).unwrap();
        let ipv4_error = link_sender.send(&ipv4_packet()).unwrap_err();
        let ipv6_error = link_sender.send(&ipv6_packet()).unwrap_err();
        let ipv4_plan = SendPlan::from_packet(
            &ipv4_packet(),
            SendOptions::new().iface("fake0").network_layer().dry_run(),
        )
        .unwrap();
        let boundary_error = link_sender.transmit_plan(&ipv4_plan).unwrap_err();

        assert_unsupported_shape(ipv4_error, SendMode::LinkLayer);
        assert_unsupported_shape(ipv6_error, SendMode::LinkLayer);
        assert_mode_boundary_error(
            boundary_error,
            ipv4_plan.target(),
            "stateful link-layer sender cannot transmit network-layer packets",
        );
        let snapshot = link_backend.snapshot();
        assert_eq!(snapshot.link_opens.len(), 1);
        assert_eq!(snapshot.link_sends.len(), 1);
        assert!(snapshot.network_opens.is_empty());
        assert!(snapshot.network_sends.is_empty());

        let network_backend = FakePnetBackend::default();
        let mut network_sender = PacketSender::open_with_backend(
            SendOptions::new().iface("fake0").network_layer().live(),
            network_backend.clone(),
        )
        .unwrap();

        network_sender.send(&ipv4_packet()).unwrap();
        let ethernet_error = network_sender.send(&ethernet_packet()).unwrap_err();
        let radiotap_error = network_sender
            .send(&radiotap_packet_with_payload("wifi"))
            .unwrap_err();
        let ethernet_plan = SendPlan::from_packet(
            &ethernet_packet(),
            SendOptions::new().iface("fake0").link_layer().dry_run(),
        )
        .unwrap();
        let boundary_error = network_sender.transmit_plan(&ethernet_plan).unwrap_err();

        assert_unsupported_shape(ethernet_error, SendMode::NetworkLayer);
        assert_unsupported_shape(radiotap_error, SendMode::NetworkLayer);
        assert_mode_boundary_error(
            boundary_error,
            ethernet_plan.target(),
            "stateful network-layer sender cannot transmit link-layer frames",
        );
        let snapshot = network_backend.snapshot();
        assert!(snapshot.link_opens.is_empty());
        assert!(snapshot.link_sends.is_empty());
        assert_eq!(snapshot.network_opens.len(), 1);
        assert_eq!(snapshot.network_sends.len(), 1);
    }

    #[test]
    fn packet_sender_rejects_unsupported_live_targets() {
        let link_backend = FakePnetBackend::default();
        let mut link_sender = PacketSender::open_with_backend(
            SendOptions::new().iface("fake0").link_layer().live(),
            link_backend.clone(),
        )
        .unwrap();

        let linux_sll_error = link_sender.send(&linux_sll_packet()).unwrap_err();
        let null_loopback_error = link_sender.send(&null_loopback_packet()).unwrap_err();

        assert_unsupported_target(
            linux_sll_error,
            SendTarget::LinkLayer {
                link_type: LinkType::LinuxSll,
            },
            "live link-layer send supports Ethernet and radiotap Wi-Fi frames only",
        );
        assert_unsupported_target(
            null_loopback_error,
            SendTarget::LinkLayer {
                link_type: LinkType::NullLoopback,
            },
            "live link-layer send supports Ethernet and radiotap Wi-Fi frames only",
        );
        let snapshot = link_backend.snapshot();
        assert!(snapshot.link_opens.is_empty());
        assert!(snapshot.link_sends.is_empty());
        assert!(snapshot.network_opens.is_empty());
        assert!(snapshot.network_sends.is_empty());

        let network_backend = FakePnetBackend::default();
        let mut network_sender = PacketSender::open_with_backend(
            SendOptions::new().iface("fake0").network_layer().live(),
            network_backend.clone(),
        )
        .unwrap();

        let ipv6_error = network_sender.send(&ipv6_packet()).unwrap_err();

        assert_unsupported_target(
            ipv6_error,
            SendPlan::from_packet(
                &ipv6_packet(),
                SendOptions::new().iface("fake0").network_layer().dry_run(),
            )
            .unwrap()
            .target(),
            "the selected safe backend does not support full IPv6-header Layer3 sends",
        );
        let snapshot = network_backend.snapshot();
        assert!(snapshot.link_opens.is_empty());
        assert!(snapshot.link_sends.is_empty());
        assert!(snapshot.network_opens.is_empty());
        assert!(snapshot.network_sends.is_empty());
    }

    fn assert_unsupported_shape(error: NetError, mode: SendMode) {
        match error {
            NetError::UnsupportedPacketShape {
                mode: actual_mode, ..
            } => {
                assert_eq!(actual_mode, mode);
            }
            other => panic!("expected unsupported packet shape, got {other}"),
        }
    }

    fn assert_mode_boundary_error(error: NetError, target: SendTarget, expected_reason: &str) {
        match error {
            NetError::UnsupportedSendTarget {
                target: actual,
                reason,
            } => {
                assert_eq!(actual, target);
                assert!(reason.contains(expected_reason));
            }
            other => panic!("expected unsupported send target, got {other}"),
        }
    }

    fn assert_unsupported_target(
        error: NetError,
        expected_target: SendTarget,
        expected_reason: &str,
    ) {
        match error {
            NetError::UnsupportedSendTarget { target, reason } => {
                assert_eq!(target, expected_target);
                assert_eq!(reason, expected_reason);
            }
            other => panic!("expected unsupported send target, got {other}"),
        }
    }
}
