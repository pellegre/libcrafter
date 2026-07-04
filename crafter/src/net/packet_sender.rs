use std::io;
use std::net::IpAddr;

use pnet_datalink::{self as datalink, Channel, ChannelType, DataLinkSender};
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_transport::{transport_channel, TransportChannelType, TransportSender};

use crate::NetworkLayer;

use super::error::{NetError, Result};
use super::send::{SendOptions, SendPlan, SendTarget};

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
    let socket_protocol = match network_layer {
        NetworkLayer::Ipv4 => IPPROTO_RAW_SOCKET,
        NetworkLayer::Ipv6 | NetworkLayer::Raw => protocol,
    };
    let mut sender = backend.open_network_sender(options, socket_protocol, plan.len())?;

    match network_layer {
        NetworkLayer::Ipv4 => sender.send_ipv4(plan.target(), plan.bytes(), destination, protocol),
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
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use crate::{Ethernet, Ipv4, NetworkLayer, Raw, Udp, IPPROTO_UDP};

    use super::*;

    fn ethernet_packet() -> crate::Packet {
        Ethernet::new()
            / Ipv4::new()
                .src(Ipv4Addr::new(192, 0, 2, 10))
                .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Udp::new().sport(49152).dport(53)
            / Raw::from("payload")
    }

    fn ipv4_packet() -> crate::Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Udp::new().sport(49152).dport(53)
            / Raw::from("payload")
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
}
