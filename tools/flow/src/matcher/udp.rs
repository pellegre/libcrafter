use std::net::Ipv4Addr;

use crate::{Matcher, PacketContext};

type PayloadPredicate = dyn Fn(&[u8], &PacketContext) -> bool;

struct UdpPayloadPredicate {
    description: String,
    predicate: Box<PayloadPredicate>,
}

/// Matcher for one direction of an exact IPv4 UDP connection tuple.
///
/// The matcher accepts a decoded [`crafter::Quic`] layer or a [`crafter::Raw`]
/// layer immediately following UDP. Other typed UDP application layers are not
/// treated as QUIC payloads.
pub struct UdpDatagramMatcher {
    source_ipv4: Ipv4Addr,
    source_port: u16,
    destination_ipv4: Ipv4Addr,
    destination_port: u16,
    payload_predicate: Option<UdpPayloadPredicate>,
}

impl UdpDatagramMatcher {
    /// Match datagrams received from the remote endpoint by the local endpoint.
    pub fn inbound(
        local_ipv4: Ipv4Addr,
        local_port: u16,
        remote_ipv4: Ipv4Addr,
        remote_port: u16,
    ) -> Self {
        Self::new(remote_ipv4, remote_port, local_ipv4, local_port)
    }

    /// Match datagrams sent from the local endpoint to the remote endpoint.
    pub fn outbound(
        local_ipv4: Ipv4Addr,
        local_port: u16,
        remote_ipv4: Ipv4Addr,
        remote_port: u16,
    ) -> Self {
        Self::new(local_ipv4, local_port, remote_ipv4, remote_port)
    }

    fn new(
        source_ipv4: Ipv4Addr,
        source_port: u16,
        destination_ipv4: Ipv4Addr,
        destination_port: u16,
    ) -> Self {
        Self {
            source_ipv4,
            source_port,
            destination_ipv4,
            destination_port,
            payload_predicate: None,
        }
    }

    /// Require the extracted UDP payload to equal `expected`.
    pub fn payload(self, expected: impl AsRef<[u8]>) -> Self {
        let expected = expected.as_ref().to_vec();
        self.payload_where(
            format!("payload length {} and exact bytes", expected.len()),
            move |payload, _ctx| payload == expected,
        )
    }

    /// Require the extracted UDP payload to satisfy `predicate`.
    pub fn payload_where(
        mut self,
        description: impl Into<String>,
        predicate: impl Fn(&[u8], &PacketContext) -> bool + 'static,
    ) -> Self {
        self.payload_predicate = Some(UdpPayloadPredicate {
            description: description.into(),
            predicate: Box::new(predicate),
        });
        self
    }
}

impl Matcher for UdpDatagramMatcher {
    fn matches(&self, packet: &crafter::Packet, ctx: &PacketContext) -> bool {
        let Some(ipv4) = packet.layer::<crafter::Ipv4>() else {
            return false;
        };
        if ipv4.source() != self.source_ipv4 || ipv4.destination() != self.destination_ipv4 {
            return false;
        }

        let Some(udp) = packet.layer::<crafter::Udp>() else {
            return false;
        };
        if udp.source_port_value() != self.source_port
            || udp.destination_port_value() != self.destination_port
        {
            return false;
        }

        let Some(payload) = udp_payload(packet) else {
            return false;
        };

        match &self.payload_predicate {
            Some(predicate) => (predicate.predicate)(&payload, ctx),
            None => true,
        }
    }

    fn describe(&self) -> String {
        let mut description = format!(
            "ipv4 udp datagram {}:{} -> {}:{}",
            self.source_ipv4, self.source_port, self.destination_ipv4, self.destination_port,
        );
        if let Some(predicate) = &self.payload_predicate {
            description.push_str(" with ");
            description.push_str(&predicate.description);
        }
        description
    }
}

/// Extract bytes from a typed QUIC payload or a raw layer immediately after UDP.
///
/// Empty payloads and other typed UDP application layers return `None`.
pub fn udp_payload(packet: &crafter::Packet) -> Option<Vec<u8>> {
    let udp_index = packet
        .iter()
        .position(|layer| layer.as_any().is::<crafter::Udp>())?;
    let payload_layer = packet.get(udp_index.checked_add(1)?)?;

    if let Some(quic) = payload_layer.as_any().downcast_ref::<crafter::Quic>() {
        let payload = if quic.packets().is_empty() {
            quic.payload_bytes().to_vec()
        } else {
            quic.packets()
                .iter()
                .flat_map(|packet| packet.as_bytes().iter().copied())
                .collect()
        };
        return (!payload.is_empty()).then_some(payload);
    }

    payload_layer
        .as_any()
        .downcast_ref::<crafter::Raw>()
        .filter(|raw| !raw.is_empty())
        .map(|raw| raw.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crafter::{Dns, Packet};

    use super::{udp_payload, UdpDatagramMatcher};
    use crate::{Matcher, PacketContext};

    const LOCAL_PORT: u16 = 49_152;
    const REMOTE_PORT: u16 = 443;
    const TYPED_PAYLOAD: &[u8] = &[0xc0, 0x00, 0x00, 0x00, 0x01, 0xaa];
    const SHORT_PAYLOAD: &[u8] = &[0x40, 0x7b, 0xde, 0xad, 0xbe, 0xef];

    fn local_ipv4() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn remote_ipv4() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    fn inbound(payload: impl crafter::IntoPacket) -> Packet {
        crafter::Ipv4::new().src(remote_ipv4()).dst(local_ipv4())
            / crafter::Udp::new()
                .source_port(REMOTE_PORT)
                .destination_port(LOCAL_PORT)
            / payload
    }

    #[test]
    fn udp_datagram_matcher_extracts_typed_and_raw_payloads() {
        let context = PacketContext::new();
        let inbound_matcher =
            UdpDatagramMatcher::inbound(local_ipv4(), LOCAL_PORT, remote_ipv4(), REMOTE_PORT);
        let typed = inbound(crafter::Quic::from_bytes(TYPED_PAYLOAD));
        let raw_short = inbound(crafter::Raw::from_bytes(SHORT_PAYLOAD));

        assert!(inbound_matcher.matches(&typed, &context));
        assert!(inbound_matcher.matches(&raw_short, &context));
        assert_eq!(udp_payload(&typed).as_deref(), Some(TYPED_PAYLOAD));
        assert_eq!(udp_payload(&raw_short).as_deref(), Some(SHORT_PAYLOAD));

        let outbound_matcher =
            UdpDatagramMatcher::outbound(local_ipv4(), LOCAL_PORT, remote_ipv4(), REMOTE_PORT);
        assert!(!outbound_matcher.matches(&typed, &context));

        let wrong_tuple = crafter::Ipv4::new().src(remote_ipv4()).dst(local_ipv4())
            / crafter::Udp::new()
                .source_port(REMOTE_PORT + 1)
                .destination_port(LOCAL_PORT)
            / crafter::Raw::from_bytes(SHORT_PAYLOAD);
        assert!(!inbound_matcher.matches(&wrong_tuple, &context));

        let empty = inbound(crafter::Raw::new());
        assert!(!inbound_matcher.matches(&empty, &context));
        assert_eq!(udp_payload(&empty), None);

        let unrelated = inbound(Dns::new());
        assert!(!inbound_matcher.matches(&unrelated, &context));
        assert_eq!(udp_payload(&unrelated), None);

        let payload_matcher =
            UdpDatagramMatcher::inbound(local_ipv4(), LOCAL_PORT, remote_ipv4(), REMOTE_PORT)
                .payload(SHORT_PAYLOAD);
        assert!(payload_matcher.matches(&raw_short, &context));
        assert!(!payload_matcher.matches(&typed, &context));
    }
}
