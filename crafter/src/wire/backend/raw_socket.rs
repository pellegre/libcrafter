//! Raw socket packet writer adapter.

use crate::net::{
    Result as NetResult, SendMode, SendOptions, SendPlan, SendReport, SendTarget, SocketSender,
};
use crate::Packet;
use crate::{LinkType, NetworkLayer};

use super::super::record::{BackendKind, PacketRecord};
use super::super::writer::{PacketWriter, WriteReport};
use super::super::Result;

/// Packet writer that adapts [`SocketSender`] into the [`PacketWriter`] API.
///
/// The adapter delegates planning, dry-run behavior, live transmission,
/// interface validation, send-mode handling, and unsupported target checks to
/// `SocketSender`. In particular, live radiotap injection is routed through the
/// same Layer-2 datalink writer `SocketSender` uses for Ethernet frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSocketWriter {
    sender: SocketSender,
}

impl RawSocketWriter {
    /// Create a raw socket writer from existing send options.
    ///
    /// This preserves the behavior of [`SendOptions`] exactly. Use
    /// [`PacketWire::raw_socket_interface`](crate::wire::PacketWire::raw_socket_interface)
    /// when you want the packet-wire constructor that defaults to dry-run
    /// planning and requires `.live()` for live transmission.
    pub fn new(options: impl Into<SendOptions>) -> Self {
        Self {
            sender: SocketSender::new(options),
        }
    }

    /// Create a compile-only raw socket writer for an interface.
    pub fn dry_run(interface: impl Into<String>) -> Self {
        Self::new(SendOptions::new().interface(interface).dry_run())
    }

    /// Create a live raw socket writer for an interface.
    pub fn live(interface: impl Into<String>) -> Self {
        Self::new(SendOptions::new().interface(interface).live())
    }

    /// Borrow the adapted sender.
    pub const fn sender(&self) -> &SocketSender {
        &self.sender
    }

    /// Borrow the adapted sender options.
    pub const fn options(&self) -> &SendOptions {
        self.sender.options()
    }

    /// Build the send plan this writer would use for a packet.
    pub fn plan_packet(&self, packet: &Packet) -> NetResult<SendPlan> {
        self.sender.plan(packet)
    }

    /// Send a packet through the adapted raw socket sender.
    pub fn send_packet(&self, packet: &Packet) -> NetResult<SendReport> {
        self.sender.send(packet)
    }
}

impl From<SocketSender> for RawSocketWriter {
    fn from(sender: SocketSender) -> Self {
        Self { sender }
    }
}

impl PacketWriter for RawSocketWriter {
    fn write_record(&mut self, record: &PacketRecord) -> Result<WriteReport> {
        let send_report = self.send_packet(record.packet())?;
        Ok(write_report_from_send_report(&send_report))
    }
}

fn write_report_from_send_report(report: &SendReport) -> WriteReport {
    WriteReport::new(
        BackendKind::RawSocket,
        report.plan().len(),
        report.bytes_sent(),
        report.is_dry_run(),
    )
    .with_target_details(send_target_details(report))
}

fn send_target_details(report: &SendReport) -> String {
    let plan = report.plan();
    match plan.target() {
        SendTarget::LinkLayer { link_type } => format!(
            "interface={} mode={} target=link-layer:{}",
            plan.interface(),
            send_mode_name(plan.requested_mode()),
            link_type_name(link_type)
        ),
        SendTarget::NetworkLayer {
            network_layer,
            destination,
            protocol,
        } => format!(
            "interface={} mode={} target=network-layer:{} destination={} protocol={}",
            plan.interface(),
            send_mode_name(plan.requested_mode()),
            network_layer_name(network_layer),
            destination,
            protocol
        ),
    }
}

const fn send_mode_name(mode: SendMode) -> &'static str {
    match mode {
        SendMode::Auto => "auto",
        SendMode::LinkLayer => "link-layer",
        SendMode::NetworkLayer => "network-layer",
    }
}

const fn link_type_name(link_type: LinkType) -> &'static str {
    match link_type {
        LinkType::Raw => "raw",
        LinkType::Ethernet => "ethernet",
        LinkType::Ieee80211 => "ieee80211",
        LinkType::Radiotap => "radiotap",
        LinkType::LinuxCooked => "linux-cooked",
        LinkType::LinuxSll => "linux-sll",
        LinkType::NullLoopback => "null-loopback",
    }
}

const fn network_layer_name(network_layer: NetworkLayer) -> &'static str {
    match network_layer {
        NetworkLayer::Raw => "raw",
        NetworkLayer::Ipv4 => "ipv4",
        NetworkLayer::Ipv6 => "ipv6",
    }
}

#[cfg(test)]
mod raw_socket_writer {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::net::{NetError, SendOptions, SendTarget};
    use crate::{
        Dot11, Ethernet, Ipv4, LlcSnap, MacAddr, Packet, PacketWire, PacketWireTarget, Radiotap,
        Raw, Udp,
    };
    use crate::{PacketRecord, WireError};

    fn ipv4_packet() -> Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Udp::new().sport(1111).dport(2222)
            / Raw::from("hello")
    }

    fn ethernet_packet() -> Packet {
        Ethernet::new()
            .src(MacAddr::new([0x02, 0, 0, 0, 0, 1]))
            .dst(MacAddr::BROADCAST)
            / ipv4_packet()
    }

    fn radiotap_dot11_packet() -> Packet {
        Radiotap::new() / Dot11::data() / LlcSnap::new() / ipv4_packet()
    }

    #[test]
    fn raw_socket_writer_dry_run_maps_socket_send_report() {
        let packet = ipv4_packet();
        let expected_len = packet.compile().unwrap().len();
        let mut writer = RawSocketWriter::dry_run("eth0");

        assert_eq!(writer.options().interface_name(), Some("eth0"));
        assert!(writer.options().is_dry_run());

        let report = writer
            .write_record(&PacketRecord::new(packet.clone()))
            .unwrap();

        assert_eq!(report.backend(), &BackendKind::RawSocket);
        assert_eq!(report.bytes_requested(), expected_len);
        assert_eq!(report.bytes_written(), expected_len);
        assert!(report.is_dry_run());

        let details = report.target_details().unwrap();
        assert!(details.contains("interface=eth0"));
        assert!(details.contains("mode=auto"));
        assert!(details.contains("target=network-layer:ipv4"));
        assert!(details.contains("destination=198.51.100.20"));
        assert!(details.contains("protocol=17"));
    }

    #[test]
    fn raw_socket_writer_packet_wire_builder_is_write_only_and_preserves_mode() {
        let wire = PacketWire::raw_socket_interface("eth0")
            .network_layer()
            .open()
            .unwrap();

        assert_eq!(
            wire.target(),
            &PacketWireTarget::RawSocketInterface {
                interface: "eth0".to_string()
            }
        );
        assert_eq!(wire.target().interface(), Some("eth0"));
        assert!(!wire.has_source());
        assert!(wire.has_writer());

        let mut writer = wire.writer().unwrap();
        let report = writer
            .write_record(&PacketRecord::new(ipv4_packet()))
            .unwrap();

        assert_eq!(report.backend(), &BackendKind::RawSocket);
        assert!(report.is_dry_run());
        assert!(report
            .target_details()
            .unwrap()
            .contains("mode=network-layer"));
    }

    #[test]
    fn raw_socket_writer_packet_wire_split_reports_write_only_target() {
        let result = PacketWire::raw_socket_interface("eth0")
            .open()
            .unwrap()
            .split();
        let error = match result {
            Ok(_) => panic!("expected unsupported split error"),
            Err(error) => error,
        };

        match error {
            WireError::UnsupportedCapability {
                capability,
                backend: Some(backend),
                reason,
            } => {
                assert_eq!(capability, "split");
                assert_eq!(backend, "raw-socket:eth0");
                assert_eq!(
                    reason,
                    "raw socket interface targets are write-only; use pcap_interface for capture"
                );
            }
            other => panic!("expected unsupported split error, got {other:?}"),
        }
    }

    #[test]
    fn raw_socket_writer_dry_run_link_layer_report_keeps_target_shape() {
        let packet = ethernet_packet();
        let mut writer =
            RawSocketWriter::new(SendOptions::new().interface("veth0").link_layer().dry_run());

        let report = writer.write_record(&PacketRecord::new(packet)).unwrap();

        assert_eq!(report.backend(), &BackendKind::RawSocket);
        assert!(report.is_dry_run());
        assert_eq!(
            report.target_details(),
            Some("interface=veth0 mode=link-layer target=link-layer:ethernet")
        );
    }

    #[test]
    fn raw_socket_writer_live_radiotap_routes_to_layer2_via_socket_sender() {
        let mut writer =
            RawSocketWriter::new(SendOptions::new().interface("missing-crafter-wifi0").live());
        let error = writer
            .write_record(&PacketRecord::new(radiotap_dot11_packet()))
            .unwrap_err();

        match error {
            WireError::Net(NetError::InterfaceNotFound { name }) => {
                assert_eq!(name, "missing-crafter-wifi0");
            }
            other => panic!("expected raw socket radiotap missing-interface error, got {other:?}"),
        }
    }

    #[test]
    fn raw_socket_writer_dry_run_reports_ipv4_destination_and_protocol() {
        let mut writer =
            RawSocketWriter::new(SendOptions::new().interface("lo").network_layer().dry_run());
        let report = writer
            .write_record(&PacketRecord::new(ipv4_packet()))
            .unwrap();

        assert_eq!(report.backend(), &BackendKind::RawSocket);
        assert_eq!(report.bytes_requested(), report.bytes_written());
        assert_eq!(
            report.target_details(),
            Some(
                "interface=lo mode=network-layer target=network-layer:ipv4 destination=198.51.100.20 protocol=17"
            )
        );

        let plan = SocketSender::dry_run("lo").plan(&ipv4_packet()).unwrap();
        match plan.target() {
            SendTarget::NetworkLayer {
                destination,
                protocol,
                ..
            } => {
                assert_eq!(destination, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)));
                assert_eq!(protocol, crate::IPPROTO_UDP);
            }
            other => panic!("expected network target, got {other:?}"),
        }
    }
}
