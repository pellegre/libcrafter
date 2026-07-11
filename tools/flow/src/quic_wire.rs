//! Connection-aware QUIC ingress metadata for the private endpoint boundary.

use std::fmt;
use std::net::SocketAddrV4;

use crate::matcher::UdpDatagramMatcher;
use crate::{Matcher, PacketContext};

/// How the captured UDP payload was represented by generic packet decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuicCaptureRepresentation {
    /// A long-header datagram decoded into the typed QUIC packet layer.
    Typed,
    /// An opaque payload retained by generic decoding as raw bytes.
    Raw,
}

impl QuicCaptureRepresentation {
    const fn label(self) -> &'static str {
        match self {
            Self::Typed => "typed",
            Self::Raw => "raw",
        }
    }
}

/// Endpoint-only hints needed to interpret connection-dependent QUIC packets.
///
/// These values identify decode context; they do not contain keys and the
/// ingress envelope never parses or decrypts the captured payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuicIngressContext {
    expected_destination_connection_id_len: Option<usize>,
    connection_identity: Vec<u8>,
}

impl QuicIngressContext {
    pub(crate) fn new(connection_identity: impl AsRef<[u8]>) -> Self {
        Self {
            expected_destination_connection_id_len: None,
            connection_identity: connection_identity.as_ref().to_vec(),
        }
    }

    pub(crate) fn with_expected_destination_connection_id_len(mut self, len: usize) -> Self {
        self.expected_destination_connection_id_len = Some(len);
        self
    }

    pub(crate) const fn expected_destination_connection_id_len(&self) -> Option<usize> {
        self.expected_destination_connection_id_len
    }

    pub(crate) fn connection_identity(&self) -> &[u8] {
        &self.connection_identity
    }
}

/// One matched IPv4/UDP QUIC datagram prepared for a private endpoint driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuicIngress {
    local: SocketAddrV4,
    peer: SocketAddrV4,
    payload: Vec<u8>,
    representation: QuicCaptureRepresentation,
    endpoint_context: Option<QuicIngressContext>,
}

impl QuicIngress {
    /// Copy a packet into an ingress envelope only if `matcher` accepts it.
    pub(crate) fn from_packet(
        packet: &crafter::Packet,
        matcher: &UdpDatagramMatcher,
        context: &PacketContext,
    ) -> Option<Self> {
        if !matcher.matches(packet, context) {
            return None;
        }

        let ipv4 = packet.layer::<crafter::Ipv4>()?;
        let udp = packet.layer::<crafter::Udp>()?;
        let (payload, representation) = payload_after_udp(packet)?;

        Some(Self {
            local: SocketAddrV4::new(ipv4.destination(), udp.destination_port_value()),
            peer: SocketAddrV4::new(ipv4.source(), udp.source_port_value()),
            payload,
            representation,
            endpoint_context: None,
        })
    }

    pub(crate) fn with_endpoint_context(mut self, context: QuicIngressContext) -> Self {
        self.endpoint_context = Some(context);
        self
    }

    pub(crate) const fn local(&self) -> SocketAddrV4 {
        self.local
    }

    pub(crate) const fn peer(&self) -> SocketAddrV4 {
        self.peer
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(crate) const fn representation(&self) -> QuicCaptureRepresentation {
        self.representation
    }

    pub(crate) const fn endpoint_context(&self) -> Option<&QuicIngressContext> {
        self.endpoint_context.as_ref()
    }

    /// Return non-secret capture facts without payload or connection identity.
    pub(crate) fn summary(&self) -> String {
        format!(
            "QUIC ingress {} -> {} payload_len={} representation={}",
            self.peer,
            self.local,
            self.payload.len(),
            self.representation.label(),
        )
    }
}

impl fmt::Display for QuicIngress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary())
    }
}

fn payload_after_udp(packet: &crafter::Packet) -> Option<(Vec<u8>, QuicCaptureRepresentation)> {
    let udp_index = packet
        .iter()
        .position(|layer| layer.as_any().is::<crafter::Udp>())?;
    let payload_layer = packet.get(udp_index.checked_add(1)?)?;

    if let Some(quic) = payload_layer.as_any().downcast_ref::<crafter::Quic>() {
        let bytes = if quic.packets().is_empty() {
            quic.payload_bytes().to_vec()
        } else {
            quic.packets()
                .iter()
                .flat_map(|packet| packet.as_bytes().iter().copied())
                .collect()
        };
        return (!bytes.is_empty()).then_some((bytes, QuicCaptureRepresentation::Typed));
    }

    payload_layer
        .as_any()
        .downcast_ref::<crafter::Raw>()
        .filter(|raw| !raw.is_empty())
        .map(|raw| (raw.as_bytes().to_vec(), QuicCaptureRepresentation::Raw))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crafter::IntoPacket;

    use super::{QuicCaptureRepresentation, QuicIngress, QuicIngressContext};
    use crate::matcher::UdpDatagramMatcher;
    use crate::PacketContext;

    const LOCAL_PORT: u16 = 49_152;
    const PEER_PORT: u16 = 443;
    const LONG_HEADER: &[u8] = &[0xc0, 0x00, 0x00, 0x00, 0x01, 0xaa];
    const SHORT_HEADER: &[u8] = &[0x40, 0x7b, 0xde, 0xad, 0xbe, 0xef];

    fn local_ipv4() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn peer_ipv4() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    fn packet(payload: impl IntoPacket) -> crafter::Packet {
        crafter::Ipv4::new().src(peer_ipv4()).dst(local_ipv4())
            / crafter::Udp::new()
                .source_port(PEER_PORT)
                .destination_port(LOCAL_PORT)
            / payload
    }

    #[test]
    fn quic_ingress_preserves_typed_and_raw_udp_payloads() {
        let matcher = UdpDatagramMatcher::inbound(local_ipv4(), LOCAL_PORT, peer_ipv4(), PEER_PORT);
        let context = PacketContext::new();

        let typed = QuicIngress::from_packet(
            &packet(crafter::Quic::from_bytes(LONG_HEADER)),
            &matcher,
            &context,
        )
        .expect("typed long-header datagram matches");
        assert_eq!(typed.payload(), LONG_HEADER);
        assert_eq!(typed.representation(), QuicCaptureRepresentation::Typed);
        assert_eq!(*typed.local().ip(), local_ipv4());
        assert_eq!(typed.local().port(), LOCAL_PORT);
        assert_eq!(*typed.peer().ip(), peer_ipv4());
        assert_eq!(typed.peer().port(), PEER_PORT);

        let raw = QuicIngress::from_packet(
            &packet(crafter::Raw::from_bytes(SHORT_HEADER)),
            &matcher,
            &context,
        )
        .expect("raw short-header datagram matches")
        .with_endpoint_context(
            QuicIngressContext::new([0xde, 0xad, 0xbe, 0xef])
                .with_expected_destination_connection_id_len(8),
        );
        assert_eq!(raw.payload(), SHORT_HEADER);
        assert_eq!(raw.representation(), QuicCaptureRepresentation::Raw);
        let endpoint = raw.endpoint_context().expect("endpoint hints attached");
        assert_eq!(endpoint.expected_destination_connection_id_len(), Some(8));
        assert_eq!(endpoint.connection_identity(), [0xde, 0xad, 0xbe, 0xef]);

        let wrong_tuple = crafter::Ipv4::new().src(peer_ipv4()).dst(local_ipv4())
            / crafter::Udp::new()
                .source_port(PEER_PORT + 1)
                .destination_port(LOCAL_PORT)
            / crafter::Raw::from_bytes(SHORT_HEADER);
        assert!(QuicIngress::from_packet(&wrong_tuple, &matcher, &context).is_none());

        let summary = raw.summary();
        assert!(summary.contains("198.51.100.20:443 -> 192.0.2.10:49152"));
        assert!(summary.contains("payload_len=6"));
        assert!(summary.contains("representation=raw"));
        assert!(!summary.contains("deadbeef"));
        assert!(!summary.contains("de ad be ef"));
        assert!(!summary.contains("407bdeadbeef"));
    }
}
