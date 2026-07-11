//! Connection-aware QUIC ingress metadata for the private endpoint boundary.

use std::fmt;
use std::net::SocketAddrV4;

use crafter::{
    quic_protect_complete_initial_packet, Ipv4, Packet, Quic, QuicFrame, QuicInitialPacketKeys,
    QuicLongHeaderPacket, QuicPacket, QuicPacketNumber, QuicVarInt, Udp, QUIC_INITIAL_AEAD_TAG_LEN,
};

use crate::matcher::UdpDatagramMatcher;
use crate::{Matcher, PacketContext, Result};

const QUIC_CLIENT_INITIAL_MIN_UDP_PAYLOAD_LEN: usize = 1200;

/// Opaque bytes or ordered QUIC packets carried by one UDP datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QuicUdpPayload {
    Opaque(Vec<u8>),
    Packets(Vec<QuicPacket>),
}

impl QuicUdpPayload {
    pub(crate) fn opaque(bytes: impl AsRef<[u8]>) -> Self {
        Self::Opaque(bytes.as_ref().to_vec())
    }

    pub(crate) fn packets(packets: impl IntoIterator<Item = QuicPacket>) -> Self {
        Self::Packets(packets.into_iter().collect())
    }

    fn into_layer(self) -> Quic {
        match self {
            Self::Opaque(bytes) => Quic::from_bytes(bytes),
            Self::Packets(packets) => Quic::from_packets(packets),
        }
    }
}

/// Wrap exactly one QUIC UDP datagram in the typed packet stack.
///
/// Multiple entries in `payload` remain coalesced in one [`Quic`] layer. A
/// caller emitting multiple UDP datagrams must create multiple `Packet`s so
/// the flow runner can retain their batch boundaries.
pub(crate) fn wrap_quic_udp_datagram(
    local: SocketAddrV4,
    peer: SocketAddrV4,
    payload: QuicUdpPayload,
) -> Packet {
    Ipv4::new().src(*local.ip()).dst(*peer.ip())
        / Udp::new()
            .source_port(local.port())
            .destination_port(peer.port())
        / payload.into_layer()
}

/// Extract one inbound QUIC datagram after verifying the reversed tuple.
pub(crate) fn extract_quic_udp_ingress(
    packet: &Packet,
    local: SocketAddrV4,
    peer: SocketAddrV4,
    context: &PacketContext,
) -> Option<QuicIngress> {
    let matcher = UdpDatagramMatcher::inbound(*local.ip(), local.port(), *peer.ip(), peer.port());
    QuicIngress::from_packet(packet, &matcher, context)
}

/// Explicit datagram padding policy for a protected Initial packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuicInitialPadding {
    /// Preserve the protected Initial size produced by the caller's frames.
    None,
    /// Pad the protected QUIC payload to the RFC 9000 client minimum.
    ClientMinimum,
    /// Pad the protected QUIC payload to an explicit caller-selected minimum.
    AtLeast(usize),
}

impl QuicInitialPadding {
    const fn minimum_udp_payload_len(self) -> Option<usize> {
        match self {
            Self::None => None,
            Self::ClientMinimum => Some(QUIC_CLIENT_INITIAL_MIN_UDP_PAYLOAD_LEN),
            Self::AtLeast(len) => Some(len),
        }
    }
}

/// Protect an Initial packet, apply explicit flow-owned padding, and wrap it in
/// the typed IPv4 / UDP / QUIC stack.
pub(crate) fn assemble_initial_datagram(
    local: SocketAddrV4,
    peer: SocketAddrV4,
    initial: &QuicLongHeaderPacket,
    full_packet_number: u64,
    keys: &QuicInitialPacketKeys,
    packet_number_len: usize,
    padding: QuicInitialPadding,
) -> Result<Packet> {
    let packet_number_mask = match packet_number_len {
        1..=4 => (1u64 << (packet_number_len * 8)) - 1,
        _ => {
            return Err(crafter::CrafterError::invalid_field_value(
                "quic.packet_number.length",
                "QUIC packet-number length must be 1, 2, 3, or 4 bytes",
            )
            .into())
        }
    };
    let padding_len = padding
        .minimum_udp_payload_len()
        .map(|minimum| initial_padding_len(initial, packet_number_len, minimum))
        .transpose()?
        .unwrap_or(0);
    let plaintext_len = initial
        .protected_payload()
        .len()
        .checked_add(padding_len)
        .ok_or_else(initial_length_overflow)?;
    let protected_length = packet_number_len
        .checked_add(plaintext_len)
        .and_then(|len| len.checked_add(QUIC_INITIAL_AEAD_TAG_LEN))
        .ok_or_else(initial_length_overflow)?;
    let required_length_width =
        QuicVarInt::new(u64::try_from(protected_length).map_err(|_| initial_length_overflow())?)?
            .encoded_len()?;
    let length_width = initial.length_encoded_len().max(required_length_width);

    let mut builder = QuicLongHeaderPacket::initial_builder()
        .first_byte(initial.first_byte())
        .version(initial.version())
        .destination_connection_id(initial.destination_connection_id().clone())
        .source_connection_id(initial.source_connection_id().clone())
        .token_length(
            initial
                .token_length()
                .expect("Initial packets carry a token length"),
        )
        .token_length_encoded_len(
            initial
                .token_length_encoded_len()
                .expect("Initial packets carry a token length width"),
        )
        .token(initial.token())
        .length_encoded_len(length_width)
        .packet_number(
            QuicPacketNumber::new(full_packet_number & packet_number_mask)
                .with_encoded_len(packet_number_len),
        )
        .protected_payload(initial.protected_payload());
    if padding_len != 0 {
        builder = builder.frame(QuicFrame::padding(padding_len));
    }

    let padded = builder.build()?;
    let protected =
        quic_protect_complete_initial_packet(&padded, full_packet_number, keys, packet_number_len)?;

    Ok(wrap_quic_udp_datagram(
        local,
        peer,
        QuicUdpPayload::packets([protected]),
    ))
}

fn initial_padding_len(
    initial: &QuicLongHeaderPacket,
    packet_number_len: usize,
    minimum_udp_payload_len: usize,
) -> Result<usize> {
    let prefix_len = 1usize
        .checked_add(4)
        .and_then(|len| len.checked_add(1 + initial.destination_connection_id().len()))
        .and_then(|len| len.checked_add(1 + initial.source_connection_id().len()))
        .and_then(|len| len.checked_add(initial.token_length_encoded_len().unwrap_or(0)))
        .and_then(|len| len.checked_add(initial.token().len()))
        .ok_or_else(initial_length_overflow)?;
    let base_plaintext_len = initial.protected_payload().len();
    let mut padding_len = 0usize;

    loop {
        let protected_length = packet_number_len
            .checked_add(base_plaintext_len)
            .and_then(|len| len.checked_add(padding_len))
            .and_then(|len| len.checked_add(QUIC_INITIAL_AEAD_TAG_LEN))
            .ok_or_else(initial_length_overflow)?;
        let required_width = QuicVarInt::new(
            u64::try_from(protected_length).map_err(|_| initial_length_overflow())?,
        )?
        .encoded_len()?;
        let length_width = initial.length_encoded_len().max(required_width);
        let datagram_len = prefix_len
            .checked_add(length_width)
            .and_then(|len| len.checked_add(protected_length))
            .ok_or_else(initial_length_overflow)?;

        if datagram_len >= minimum_udp_payload_len {
            return Ok(padding_len);
        }
        padding_len = padding_len
            .checked_add(minimum_udp_payload_len - datagram_len)
            .ok_or_else(initial_length_overflow)?;
    }
}

fn initial_length_overflow() -> crafter::CrafterError {
    crafter::CrafterError::invalid_field_value(
        "quic.initial.datagram.length",
        "QUIC Initial datagram length overflow",
    )
}

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
    use std::net::{Ipv4Addr, SocketAddrV4};

    use crafter::{
        derive_quic_initial_secrets, quic_decode_initial_protected_payload_with_keys, IntoPacket,
        NetworkLayer, Packet, QuicConnectionId, QuicFrame, QuicLongHeaderPacket, QuicPacket,
        QuicPacketNumber, QUIC_VERSION_1,
    };

    use super::{
        assemble_initial_datagram, extract_quic_udp_ingress, wrap_quic_udp_datagram,
        QuicCaptureRepresentation, QuicIngress, QuicIngressContext, QuicInitialPadding,
        QuicUdpPayload,
    };
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

    fn initial_with_plaintext_len(plaintext_len: usize) -> crafter::Result<QuicLongHeaderPacket> {
        QuicLongHeaderPacket::initial_builder()
            .first_byte(0xc1)
            .version(QUIC_VERSION_1)
            .destination_connection_id(QuicConnectionId::from_bytes([0x83; 8]))
            .source_connection_id(QuicConnectionId::from_bytes([0x44; 8]))
            .token([0xde, 0xad])
            .length_encoded_len(2)
            .packet_number(QuicPacketNumber::new(7).with_encoded_len(2))
            .frame(QuicFrame::padding(plaintext_len))
            .build()
    }

    fn quic_payload(packet: &crafter::Packet) -> &[u8] {
        packet
            .layer::<crafter::Quic>()
            .expect("typed QUIC layer")
            .packets()[0]
            .as_bytes()
    }

    #[test]
    fn client_initial_udp_payload_is_at_least_1200_bytes() -> crate::Result<()> {
        let local = SocketAddrV4::new(local_ipv4(), LOCAL_PORT);
        let peer = SocketAddrV4::new(peer_ipv4(), PEER_PORT);
        let keys = derive_quic_initial_secrets(QUIC_VERSION_1, [0x83; 8])?.client_packet_keys()?;

        // With these explicit connection IDs, token, two-byte Length, and
        // two-byte packet number, plaintext lengths 1153/1154/1155 produce
        // protected Initials just below, exactly at, and just above 1200.
        for (plaintext_len, unpadded_len, expected_padded_len) in
            [(1153, 1199, 1200), (1154, 1200, 1200), (1155, 1201, 1201)]
        {
            let initial = initial_with_plaintext_len(plaintext_len)?;
            let unpadded = assemble_initial_datagram(
                local,
                peer,
                &initial,
                7,
                &keys,
                2,
                QuicInitialPadding::None,
            )?;
            assert_eq!(quic_payload(&unpadded).len(), unpadded_len);

            let padded = assemble_initial_datagram(
                local,
                peer,
                &initial,
                7,
                &keys,
                2,
                QuicInitialPadding::ClientMinimum,
            )?;
            assert_eq!(quic_payload(&padded).len(), expected_padded_len);

            let decoded =
                quic_decode_initial_protected_payload_with_keys(quic_payload(&padded), &keys)?;
            assert_eq!(decoded.version(), QUIC_VERSION_1);
            assert_eq!(decoded.packet_number().value(), 7);
            assert_eq!(decoded.packet_number_len(), 2);
            assert_eq!(decoded.decrypted_payload().len(), plaintext_len.max(1154));

            // Compilation fills enclosing lengths/checksums without changing
            // the explicit documentation tuple or protected QUIC bytes.
            let compiled = padded.compile()?;
            assert_eq!(compiled.as_bytes().len(), 20 + 8 + expected_padded_len);
            let ipv4 = padded.layer::<crafter::Ipv4>().expect("typed IPv4 layer");
            let udp = padded.layer::<crafter::Udp>().expect("typed UDP layer");
            assert_eq!(ipv4.source(), local_ipv4());
            assert_eq!(ipv4.destination(), peer_ipv4());
            assert_eq!(udp.source_port_value(), LOCAL_PORT);
            assert_eq!(udp.destination_port_value(), PEER_PORT);
            assert_eq!(quic_payload(&padded).len(), expected_padded_len);
        }

        // Server output remains unchanged unless its caller selects padding.
        let server_sized = assemble_initial_datagram(
            local,
            peer,
            &initial_with_plaintext_len(24)?,
            7,
            &keys,
            2,
            QuicInitialPadding::None,
        )?;
        assert!(quic_payload(&server_sized).len() < 1200);

        let explicitly_padded = assemble_initial_datagram(
            local,
            peer,
            &initial_with_plaintext_len(24)?,
            7,
            &keys,
            2,
            QuicInitialPadding::AtLeast(1250),
        )?;
        assert_eq!(quic_payload(&explicitly_padded).len(), 1250);

        Ok(())
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

    #[test]
    fn quic_udp_wrapper_round_trips_typed_packet_stack() -> crate::Result<()> {
        let sender = SocketAddrV4::new(local_ipv4(), LOCAL_PORT);
        let receiver = SocketAddrV4::new(peer_ipv4(), PEER_PORT);
        let initial = QuicLongHeaderPacket::initial_builder()
            .destination_connection_id(QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]))
            .source_connection_id(QuicConnectionId::from_bytes([0xaa]))
            .packet_number(QuicPacketNumber::new(1))
            .payload([0xbe])
            .build()?;
        let handshake = QuicLongHeaderPacket::handshake_builder()
            .destination_connection_id(QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]))
            .source_connection_id(QuicConnectionId::from_bytes([0xaa]))
            .packet_number(QuicPacketNumber::new(2))
            .payload([0xef])
            .build()?;
        let expected_payload = [initial.as_bytes(), handshake.as_bytes()].concat();

        let outgoing = wrap_quic_udp_datagram(
            sender,
            receiver,
            QuicUdpPayload::packets([
                QuicPacket::from_long_header(initial.clone()),
                QuicPacket::from_long_header(handshake.clone()),
            ]),
        );
        let outgoing_quic = outgoing.layer::<crafter::Quic>().expect("typed QUIC layer");
        assert_eq!(outgoing_quic.packets().len(), 2);
        assert_eq!(outgoing_quic.packets()[0].as_bytes(), initial.as_bytes());
        assert_eq!(outgoing_quic.packets()[1].as_bytes(), handshake.as_bytes());

        let compiled = outgoing.compile()?;
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
        let ingress = extract_quic_udp_ingress(&decoded, receiver, sender, &PacketContext::new())
            .expect("receiver sees the reversed sender tuple");
        assert_eq!(ingress.local(), receiver);
        assert_eq!(ingress.peer(), sender);
        assert_eq!(ingress.payload(), expected_payload);
        assert_eq!(ingress.representation(), QuicCaptureRepresentation::Typed);
        assert!(
            extract_quic_udp_ingress(&decoded, sender, receiver, &PacketContext::new(),).is_none()
        );

        let short_outgoing =
            wrap_quic_udp_datagram(sender, receiver, QuicUdpPayload::opaque(SHORT_HEADER));
        let short_compiled = short_outgoing.compile()?;
        let short_decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, short_compiled.as_bytes())?;
        let short_ingress =
            extract_quic_udp_ingress(&short_decoded, receiver, sender, &PacketContext::new())
                .expect("raw short-header ingress retains the tuple");
        assert_eq!(short_ingress.payload(), SHORT_HEADER);
        assert_eq!(
            short_ingress.representation(),
            QuicCaptureRepresentation::Raw
        );

        Ok(())
    }
}
