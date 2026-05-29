//! Explicit protocol binding and decode dispatch.

use crate::error::Result;
use crate::packet::{LinkType, NetworkLayer, Packet, Raw};
use crate::protocols::dhcp::{append_dhcp_packet, is_dhcp_port_pair, looks_like_dhcp_payload};
use crate::protocols::dns::{append_dns_packet, DNS_PORT};
use crate::protocols::icmp::{append_icmp_packet, append_icmpv6_packet};
use crate::protocols::ip::{
    append_ipv4_packet_with_registry, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP,
};
use crate::protocols::ipv6::append_ipv6_packet_with_registry;
use crate::protocols::link::{
    append_arp_packet, append_vlan_packet_with_registry, decode_ethernet_with_registry,
    decode_linux_sll_with_registry, decode_null_loopback_with_registry, ETHERTYPE_ARP,
    ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_VLAN,
};
use crate::protocols::transport::{
    append_tcp_packet_with_registry, append_udp_packet_with_registry,
};

type ProtocolDecoder = dyn for<'a> Fn(&'a ProtocolRegistry, Packet, &'a [u8]) -> Result<Packet>
    + Send
    + Sync
    + 'static;

/// Context passed to Ethernet-type binding predicates.
#[derive(Debug, Clone, Copy)]
pub struct EthertypeBindingContext<'a> {
    /// Ethernet type being dispatched.
    pub ethertype: u16,
    /// Payload bytes after the link header.
    pub payload: &'a [u8],
}

/// Context passed to IPv4 protocol binding predicates.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4ProtocolBindingContext<'a> {
    /// IPv4 protocol number being dispatched.
    pub protocol: u8,
    /// Payload bytes after the IPv4 header.
    pub payload: &'a [u8],
}

/// Context passed to IPv6 next-header binding predicates.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6NextHeaderBindingContext<'a> {
    /// IPv6 next-header value being dispatched.
    pub next_header: u8,
    /// Payload bytes after the IPv6 base header or extension stack.
    pub payload: &'a [u8],
}

/// Context passed to UDP application binding predicates.
#[derive(Debug, Clone, Copy)]
pub struct UdpBindingContext<'a> {
    /// UDP source port.
    pub source_port: u16,
    /// UDP destination port.
    pub destination_port: u16,
    /// UDP payload bytes.
    pub payload: &'a [u8],
}

/// Context passed to TCP application binding predicates.
#[derive(Debug, Clone, Copy)]
pub struct TcpBindingContext<'a> {
    /// TCP source port.
    pub source_port: u16,
    /// TCP destination port.
    pub destination_port: u16,
    /// TCP payload bytes.
    pub payload: &'a [u8],
}

struct EthertypeBinding {
    predicate: Box<dyn for<'a> Fn(EthertypeBindingContext<'a>) -> bool + Send + Sync + 'static>,
    decoder: Box<ProtocolDecoder>,
}

struct Ipv4ProtocolBinding {
    predicate: Box<dyn for<'a> Fn(Ipv4ProtocolBindingContext<'a>) -> bool + Send + Sync + 'static>,
    decoder: Box<ProtocolDecoder>,
}

struct Ipv6NextHeaderBinding {
    predicate:
        Box<dyn for<'a> Fn(Ipv6NextHeaderBindingContext<'a>) -> bool + Send + Sync + 'static>,
    decoder: Box<ProtocolDecoder>,
}

struct UdpBinding {
    predicate: Box<dyn for<'a> Fn(UdpBindingContext<'a>) -> bool + Send + Sync + 'static>,
    decoder: Box<ProtocolDecoder>,
}

struct TcpBinding {
    predicate: Box<dyn for<'a> Fn(TcpBindingContext<'a>) -> bool + Send + Sync + 'static>,
    decoder: Box<ProtocolDecoder>,
}

/// Immutable protocol dispatch table used while decoding packets.
///
/// The registry is an owned value. Built-ins are installed by [`Default`] and
/// [`ProtocolRegistry::new`], while custom bindings are explicit additions on
/// that value. There is no mutable global registry.
pub struct ProtocolRegistry {
    ethertype_bindings: Vec<EthertypeBinding>,
    ipv4_bindings: Vec<Ipv4ProtocolBinding>,
    ipv6_bindings: Vec<Ipv6NextHeaderBinding>,
    udp_bindings: Vec<UdpBinding>,
    tcp_bindings: Vec<TcpBinding>,
}

impl ProtocolRegistry {
    /// Create a registry with the built-in protocol bindings installed.
    pub fn new() -> Self {
        Self::with_builtin_bindings()
    }

    /// Create a registry with no bindings.
    pub fn empty() -> Self {
        Self {
            ethertype_bindings: Vec::new(),
            ipv4_bindings: Vec::new(),
            ipv6_bindings: Vec::new(),
            udp_bindings: Vec::new(),
            tcp_bindings: Vec::new(),
        }
    }

    /// Create a registry containing libcrafter-compatible built-in dispatch.
    pub fn with_builtin_bindings() -> Self {
        let mut registry = Self::empty();

        registry.bind_ethertype_with_registry(ETHERTYPE_ARP, |_registry, packet, payload| {
            append_arp_packet(packet, payload)
        });
        registry.bind_ethertype_with_registry(ETHERTYPE_VLAN, |registry, packet, payload| {
            append_vlan_packet_with_registry(registry, packet, payload)
        });
        registry.bind_ethertype_with_registry(ETHERTYPE_IPV4, |registry, packet, payload| {
            append_ipv4_packet_with_registry(registry, packet, payload)
        });
        registry.bind_ethertype_with_registry(ETHERTYPE_IPV6, |registry, packet, payload| {
            append_ipv6_packet_with_registry(registry, packet, payload)
        });

        registry.bind_ipv4_protocol_with_registry(IPPROTO_ICMP, |_registry, packet, payload| {
            append_icmp_packet(packet, payload)
        });
        registry.bind_ipv4_protocol_with_registry(IPPROTO_TCP, |registry, packet, payload| {
            append_tcp_packet_with_registry(registry, packet, payload)
        });
        registry.bind_ipv4_protocol_with_registry(IPPROTO_UDP, |registry, packet, payload| {
            append_udp_packet_with_registry(registry, packet, payload)
        });

        registry
            .bind_ipv6_next_header_with_registry(IPPROTO_ICMPV6, |_registry, packet, payload| {
                append_icmpv6_packet(packet, payload)
            });
        registry.bind_ipv6_next_header_with_registry(IPPROTO_TCP, |registry, packet, payload| {
            append_tcp_packet_with_registry(registry, packet, payload)
        });
        registry.bind_ipv6_next_header_with_registry(IPPROTO_UDP, |registry, packet, payload| {
            append_udp_packet_with_registry(registry, packet, payload)
        });

        registry.bind_udp_port_with_registry(DNS_PORT, |_registry, packet, payload| {
            append_dns_packet(packet, payload)
        });
        // DHCPv4 decode stays deliberately conservative to avoid false
        // positives: it binds only when the UDP pair is the standard client/
        // server port pair (67/68, in either direction) AND the payload carries
        // enough BOOTP structure with the valid magic cookie. The magic-cookie
        // check is what keeps unrelated traffic that merely happens to use a
        // DHCP port from misdecoding as `Dhcp`.
        //
        // Intentionally unsupported port inference: RFC 8357 lets a relay agent
        // advertise a non-67 UDP source port through the relay source-port
        // sub-option (option 82, sub-option 19), and the server then directs the
        // relayed reply to that port. Inferring DHCP from such non-standard
        // ports would require trusting in-payload option data to widen the port
        // match, which would reintroduce exactly the false-positive surface the
        // magic-cookie gate exists to remove. `crafter` therefore does not infer
        // DHCP on non-67/68 port pairs; callers that need to decode those frames
        // bind the port explicitly via `bind_udp`/`bind_udp_port`.
        registry.bind_udp_with_registry(
            |ctx| {
                is_dhcp_port_pair(ctx.source_port, ctx.destination_port)
                    && looks_like_dhcp_payload(ctx.payload)
            },
            |_registry, packet, payload| append_dhcp_packet(packet, payload),
        );

        registry
    }

    /// Create a registry that types transport headers but stops before any
    /// application-layer dispatch.
    ///
    /// Quoted original datagrams inside ICMPv4 error messages are usually only
    /// the IP header plus the first eight bytes of payload (RFC 792), so a full
    /// recursive decode would fail or drop the typed transport header the moment
    /// an application decoder (DNS, DHCP) sees a truncated prefix. This shallow
    /// registry keeps the IPv4 and transport (UDP/TCP/ICMP) headers typed while
    /// leaving their payloads raw-compatible.
    pub(crate) fn transport_only() -> Self {
        let mut registry = Self::empty();

        registry.bind_ipv4_protocol_with_registry(IPPROTO_ICMP, |_registry, packet, payload| {
            append_icmp_packet(packet, payload)
        });
        registry.bind_ipv4_protocol_with_registry(IPPROTO_TCP, |registry, packet, payload| {
            append_tcp_packet_with_registry(registry, packet, payload)
        });
        registry.bind_ipv4_protocol_with_registry(IPPROTO_UDP, |registry, packet, payload| {
            append_udp_packet_with_registry(registry, packet, payload)
        });

        registry
    }

    /// Decode bytes from a link-layer entrypoint.
    pub fn decode_from_link(&self, link_type: LinkType, bytes: impl AsRef<[u8]>) -> Result<Packet> {
        let bytes = bytes.as_ref();
        match link_type {
            LinkType::Raw => Packet::decode_raw(bytes),
            LinkType::Ethernet => self.decode_ethernet(bytes),
            LinkType::LinuxCooked | LinkType::LinuxSll => self.decode_linux_sll(bytes),
            LinkType::NullLoopback => decode_null_loopback_with_registry(self, bytes),
        }
    }

    /// Decode bytes as an Ethernet frame.
    pub fn decode_ethernet(&self, bytes: impl AsRef<[u8]>) -> Result<Packet> {
        decode_ethernet_with_registry(self, bytes.as_ref())
    }

    /// Decode bytes as a Linux cooked capture v1 frame.
    pub fn decode_linux_sll(&self, bytes: impl AsRef<[u8]>) -> Result<Packet> {
        decode_linux_sll_with_registry(self, bytes.as_ref())
    }

    /// Decode bytes from a network-layer entrypoint.
    pub fn decode_from_l3(
        &self,
        network_layer: NetworkLayer,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Packet> {
        let bytes = bytes.as_ref();
        match network_layer {
            NetworkLayer::Raw => Packet::decode_raw(bytes),
            NetworkLayer::Ipv4 => self.decode_ipv4(bytes),
            NetworkLayer::Ipv6 => self.decode_ipv6(bytes),
        }
    }

    /// Decode bytes as an IPv4 packet.
    pub fn decode_ipv4(&self, bytes: impl AsRef<[u8]>) -> Result<Packet> {
        append_ipv4_packet_with_registry(self, Packet::new(), bytes.as_ref())
    }

    /// Decode bytes as an IPv6 packet.
    pub fn decode_ipv6(&self, bytes: impl AsRef<[u8]>) -> Result<Packet> {
        append_ipv6_packet_with_registry(self, Packet::new(), bytes.as_ref())
    }

    /// Bind an exact Ethernet type to a decoder.
    pub fn bind_ethertype<D>(&mut self, ethertype: u16, decoder: D) -> &mut Self
    where
        D: for<'a> Fn(Packet, &'a [u8]) -> Result<Packet> + Send + Sync + 'static,
    {
        self.bind_ethertype_if(move |ctx| ctx.ethertype == ethertype, decoder)
    }

    /// Bind an Ethernet-type predicate to a decoder.
    pub fn bind_ethertype_if<P, D>(&mut self, predicate: P, decoder: D) -> &mut Self
    where
        P: for<'a> Fn(EthertypeBindingContext<'a>) -> bool + Send + Sync + 'static,
        D: for<'a> Fn(Packet, &'a [u8]) -> Result<Packet> + Send + Sync + 'static,
    {
        self.bind_ethertype_if_with_registry(predicate, move |_registry, packet, payload| {
            decoder(packet, payload)
        })
    }

    /// Bind an IPv4 protocol number to a decoder.
    pub fn bind_ipv4_protocol<D>(&mut self, protocol: u8, decoder: D) -> &mut Self
    where
        D: for<'a> Fn(Packet, &'a [u8]) -> Result<Packet> + Send + Sync + 'static,
    {
        self.bind_ipv4_protocol_if(move |ctx| ctx.protocol == protocol, decoder)
    }

    /// Bind an IPv4 protocol predicate to a decoder.
    pub fn bind_ipv4_protocol_if<P, D>(&mut self, predicate: P, decoder: D) -> &mut Self
    where
        P: for<'a> Fn(Ipv4ProtocolBindingContext<'a>) -> bool + Send + Sync + 'static,
        D: for<'a> Fn(Packet, &'a [u8]) -> Result<Packet> + Send + Sync + 'static,
    {
        self.bind_ipv4_protocol_if_with_registry(predicate, move |_registry, packet, payload| {
            decoder(packet, payload)
        })
    }

    /// Bind an IPv6 next-header value to a decoder.
    pub fn bind_ipv6_next_header<D>(&mut self, next_header: u8, decoder: D) -> &mut Self
    where
        D: for<'a> Fn(Packet, &'a [u8]) -> Result<Packet> + Send + Sync + 'static,
    {
        self.bind_ipv6_next_header_if(move |ctx| ctx.next_header == next_header, decoder)
    }

    /// Bind an IPv6 next-header predicate to a decoder.
    pub fn bind_ipv6_next_header_if<P, D>(&mut self, predicate: P, decoder: D) -> &mut Self
    where
        P: for<'a> Fn(Ipv6NextHeaderBindingContext<'a>) -> bool + Send + Sync + 'static,
        D: for<'a> Fn(Packet, &'a [u8]) -> Result<Packet> + Send + Sync + 'static,
    {
        self.bind_ipv6_next_header_if_with_registry(predicate, move |_registry, packet, payload| {
            decoder(packet, payload)
        })
    }

    /// Bind a UDP source or destination port to an application decoder.
    pub fn bind_udp_port<D>(&mut self, port: u16, decoder: D) -> &mut Self
    where
        D: for<'a> Fn(Packet, &'a [u8]) -> Result<Packet> + Send + Sync + 'static,
    {
        self.bind_udp(
            move |ctx| ctx.source_port == port || ctx.destination_port == port,
            decoder,
        )
    }

    /// Bind a UDP predicate to an application decoder.
    pub fn bind_udp<P, D>(&mut self, predicate: P, decoder: D) -> &mut Self
    where
        P: for<'a> Fn(UdpBindingContext<'a>) -> bool + Send + Sync + 'static,
        D: for<'a> Fn(Packet, &'a [u8]) -> Result<Packet> + Send + Sync + 'static,
    {
        self.bind_udp_with_registry(predicate, move |_registry, packet, payload| {
            decoder(packet, payload)
        })
    }

    /// Bind a TCP source or destination port to an application decoder.
    pub fn bind_tcp_port<D>(&mut self, port: u16, decoder: D) -> &mut Self
    where
        D: for<'a> Fn(Packet, &'a [u8]) -> Result<Packet> + Send + Sync + 'static,
    {
        self.bind_tcp(
            move |ctx| ctx.source_port == port || ctx.destination_port == port,
            decoder,
        )
    }

    /// Bind a TCP predicate to an application decoder.
    pub fn bind_tcp<P, D>(&mut self, predicate: P, decoder: D) -> &mut Self
    where
        P: for<'a> Fn(TcpBindingContext<'a>) -> bool + Send + Sync + 'static,
        D: for<'a> Fn(Packet, &'a [u8]) -> Result<Packet> + Send + Sync + 'static,
    {
        self.bind_tcp_with_registry(predicate, move |_registry, packet, payload| {
            decoder(packet, payload)
        })
    }

    pub(crate) fn decode_ethertype(
        &self,
        packet: Packet,
        ethertype: u16,
        payload: &[u8],
    ) -> Result<Packet> {
        let ctx = EthertypeBindingContext { ethertype, payload };
        if let Some(binding) = self
            .ethertype_bindings
            .iter()
            .rev()
            .find(|binding| (binding.predicate)(ctx))
        {
            return (binding.decoder)(self, packet, payload);
        }
        Ok(packet.push(Raw::from_bytes(payload)))
    }

    pub(crate) fn decode_ipv4_protocol(
        &self,
        packet: Packet,
        protocol: u8,
        payload: &[u8],
    ) -> Result<Packet> {
        let ctx = Ipv4ProtocolBindingContext { protocol, payload };
        if let Some(binding) = self
            .ipv4_bindings
            .iter()
            .rev()
            .find(|binding| (binding.predicate)(ctx))
        {
            return (binding.decoder)(self, packet, payload);
        }
        append_raw_if_needed(packet, payload)
    }

    pub(crate) fn decode_ipv6_next_header(
        &self,
        packet: Packet,
        next_header: u8,
        payload: &[u8],
    ) -> Result<Packet> {
        let ctx = Ipv6NextHeaderBindingContext {
            next_header,
            payload,
        };
        if let Some(binding) = self
            .ipv6_bindings
            .iter()
            .rev()
            .find(|binding| (binding.predicate)(ctx))
        {
            return (binding.decoder)(self, packet, payload);
        }
        append_raw_if_needed(packet, payload)
    }

    pub(crate) fn decode_udp_application(
        &self,
        packet: Packet,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Result<Packet> {
        let ctx = UdpBindingContext {
            source_port,
            destination_port,
            payload,
        };
        if let Some(binding) = self
            .udp_bindings
            .iter()
            .rev()
            .find(|binding| (binding.predicate)(ctx))
        {
            return (binding.decoder)(self, packet, payload);
        }
        append_raw_if_needed(packet, payload)
    }

    pub(crate) fn decode_tcp_application(
        &self,
        packet: Packet,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Result<Packet> {
        let ctx = TcpBindingContext {
            source_port,
            destination_port,
            payload,
        };
        if let Some(binding) = self
            .tcp_bindings
            .iter()
            .rev()
            .find(|binding| (binding.predicate)(ctx))
        {
            return (binding.decoder)(self, packet, payload);
        }
        append_raw_if_needed(packet, payload)
    }

    pub(crate) fn bind_ethertype_with_registry<D>(
        &mut self,
        ethertype: u16,
        decoder: D,
    ) -> &mut Self
    where
        D: for<'a> Fn(&'a ProtocolRegistry, Packet, &'a [u8]) -> Result<Packet>
            + Send
            + Sync
            + 'static,
    {
        self.bind_ethertype_if_with_registry(move |ctx| ctx.ethertype == ethertype, decoder)
    }

    pub(crate) fn bind_ethertype_if_with_registry<P, D>(
        &mut self,
        predicate: P,
        decoder: D,
    ) -> &mut Self
    where
        P: for<'a> Fn(EthertypeBindingContext<'a>) -> bool + Send + Sync + 'static,
        D: for<'a> Fn(&'a ProtocolRegistry, Packet, &'a [u8]) -> Result<Packet>
            + Send
            + Sync
            + 'static,
    {
        self.ethertype_bindings.push(EthertypeBinding {
            predicate: Box::new(predicate),
            decoder: Box::new(decoder),
        });
        self
    }

    pub(crate) fn bind_ipv4_protocol_with_registry<D>(
        &mut self,
        protocol: u8,
        decoder: D,
    ) -> &mut Self
    where
        D: for<'a> Fn(&'a ProtocolRegistry, Packet, &'a [u8]) -> Result<Packet>
            + Send
            + Sync
            + 'static,
    {
        self.bind_ipv4_protocol_if_with_registry(move |ctx| ctx.protocol == protocol, decoder)
    }

    pub(crate) fn bind_ipv4_protocol_if_with_registry<P, D>(
        &mut self,
        predicate: P,
        decoder: D,
    ) -> &mut Self
    where
        P: for<'a> Fn(Ipv4ProtocolBindingContext<'a>) -> bool + Send + Sync + 'static,
        D: for<'a> Fn(&'a ProtocolRegistry, Packet, &'a [u8]) -> Result<Packet>
            + Send
            + Sync
            + 'static,
    {
        self.ipv4_bindings.push(Ipv4ProtocolBinding {
            predicate: Box::new(predicate),
            decoder: Box::new(decoder),
        });
        self
    }

    pub(crate) fn bind_ipv6_next_header_with_registry<D>(
        &mut self,
        next_header: u8,
        decoder: D,
    ) -> &mut Self
    where
        D: for<'a> Fn(&'a ProtocolRegistry, Packet, &'a [u8]) -> Result<Packet>
            + Send
            + Sync
            + 'static,
    {
        self.bind_ipv6_next_header_if_with_registry(
            move |ctx| ctx.next_header == next_header,
            decoder,
        )
    }

    pub(crate) fn bind_ipv6_next_header_if_with_registry<P, D>(
        &mut self,
        predicate: P,
        decoder: D,
    ) -> &mut Self
    where
        P: for<'a> Fn(Ipv6NextHeaderBindingContext<'a>) -> bool + Send + Sync + 'static,
        D: for<'a> Fn(&'a ProtocolRegistry, Packet, &'a [u8]) -> Result<Packet>
            + Send
            + Sync
            + 'static,
    {
        self.ipv6_bindings.push(Ipv6NextHeaderBinding {
            predicate: Box::new(predicate),
            decoder: Box::new(decoder),
        });
        self
    }

    pub(crate) fn bind_udp_port_with_registry<D>(&mut self, port: u16, decoder: D) -> &mut Self
    where
        D: for<'a> Fn(&'a ProtocolRegistry, Packet, &'a [u8]) -> Result<Packet>
            + Send
            + Sync
            + 'static,
    {
        self.bind_udp_with_registry(
            move |ctx| ctx.source_port == port || ctx.destination_port == port,
            decoder,
        )
    }

    pub(crate) fn bind_udp_with_registry<P, D>(&mut self, predicate: P, decoder: D) -> &mut Self
    where
        P: for<'a> Fn(UdpBindingContext<'a>) -> bool + Send + Sync + 'static,
        D: for<'a> Fn(&'a ProtocolRegistry, Packet, &'a [u8]) -> Result<Packet>
            + Send
            + Sync
            + 'static,
    {
        self.udp_bindings.push(UdpBinding {
            predicate: Box::new(predicate),
            decoder: Box::new(decoder),
        });
        self
    }

    pub(crate) fn bind_tcp_with_registry<P, D>(&mut self, predicate: P, decoder: D) -> &mut Self
    where
        P: for<'a> Fn(TcpBindingContext<'a>) -> bool + Send + Sync + 'static,
        D: for<'a> Fn(&'a ProtocolRegistry, Packet, &'a [u8]) -> Result<Packet>
            + Send
            + Sync
            + 'static,
    {
        self.tcp_bindings.push(TcpBinding {
            predicate: Box::new(predicate),
            decoder: Box::new(decoder),
        });
        self
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::with_builtin_bindings()
    }
}

fn append_raw_if_needed(packet: Packet, payload: &[u8]) -> Result<Packet> {
    if payload.is_empty() {
        Ok(packet)
    } else {
        Ok(packet.push(Raw::from_bytes(payload)))
    }
}

#[cfg(test)]
mod protocol_registry {
    use super::ProtocolRegistry;
    use crate::{Ipv4, NetworkLayer, Packet, Raw};

    #[test]
    fn custom_ipv4_protocol_binding_decodes_without_global_state() {
        let mut registry = ProtocolRegistry::empty();
        registry.bind_ipv4_protocol(253, |packet, payload| {
            Ok(packet.push(Raw::from_bytes(payload)))
        });

        let bytes = (Ipv4::new().protocol(253) / Raw::from("agent-proto"))
            .compile()
            .unwrap();
        let decoded = registry
            .decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
            .unwrap();

        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), b"agent-proto");
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
            .unwrap()
            .layer::<Raw>()
            .is_some());
    }

    #[test]
    fn later_bindings_override_builtins_for_that_registry_only() {
        let mut registry = ProtocolRegistry::new();
        registry.bind_udp_port(crate::DNS_PORT, |packet, payload| {
            Ok(packet.push(Raw::from_bytes(payload)))
        });

        let bytes = (Ipv4::new()
            / crate::Udp::new().sport(53001).dport(crate::DNS_PORT)
            / crate::Dns::a_query("example.com."))
        .compile()
        .unwrap();
        let custom = registry
            .decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
            .unwrap();
        let builtin = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();

        assert!(custom.layer::<crate::Dns>().is_none());
        assert!(custom.layer::<Raw>().is_some());
        assert!(builtin.layer::<crate::Dns>().is_some());
    }
}

#[cfg(test)]
mod decode_dispatch {
    use super::ProtocolRegistry;
    use crate::{Ethernet, Ipv4, LinkType, NetworkLayer, Packet, Raw, Udp};

    #[test]
    fn default_registry_dispatches_from_ethernet_to_ipv4_udp() {
        let bytes = (Ethernet::new()
            / Ipv4::new().protocol(crate::IPPROTO_UDP)
            / Udp::new().sport(53002).dport(9999)
            / Raw::from("payload"))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_link(LinkType::Ethernet, bytes.as_bytes()).unwrap();

        assert!(decoded.layer::<Ethernet>().is_some());
        assert!(decoded.layer::<Ipv4>().is_some());
        assert!(decoded.layer::<Udp>().is_some());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), b"payload");
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn explicit_registry_decodes_ipv4_and_ipv6_custom_protocols() {
        let mut registry = ProtocolRegistry::new();
        registry.bind_ipv4_protocol(254, |packet, payload| {
            Ok(packet.push(Raw::from_bytes(payload)))
        });
        registry.bind_ipv6_next_header(253, |packet, payload| {
            Ok(packet.push(Raw::from_bytes(payload)))
        });

        let ipv4_bytes = (Ipv4::new().protocol(254) / Raw::from("v4-private"))
            .compile()
            .unwrap();
        let ipv6_bytes = (crate::Ipv6::new().nh(253) / Raw::from("v6-private"))
            .compile()
            .unwrap();

        let ipv4 = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, ipv4_bytes)
            .unwrap();
        let ipv6 = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv6, ipv6_bytes)
            .unwrap();

        assert_eq!(ipv4.layer::<Raw>().unwrap().as_bytes(), b"v4-private");
        assert_eq!(ipv6.layer::<Raw>().unwrap().as_bytes(), b"v6-private");
    }
}

#[cfg(test)]
mod dns_udp_binding {
    use super::ProtocolRegistry;
    use crate::{Dns, DnsQuestion, Ipv4, NetworkLayer, Packet, Raw, Udp, DNS_PORT, DNS_TYPE_AAAA};

    #[test]
    fn default_registry_decodes_dns_on_udp_53() {
        let bytes = (Ipv4::new()
            / Udp::new().sport(53001).dport(DNS_PORT)
            / Dns::new().question(DnsQuestion::new("example.org.", DNS_TYPE_AAAA)))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let dns = decoded.layer::<Dns>().unwrap();

        assert_eq!(dns.questions()[0].name(), "example.org.");
        assert_eq!(dns.questions()[0].question_type(), DNS_TYPE_AAAA);
    }

    #[test]
    fn custom_udp_port_binding_decodes_application_payload() {
        let mut registry = ProtocolRegistry::new();
        registry.bind_udp_port(5353, |packet, payload| {
            Ok(packet.push(Raw::from_bytes(payload)))
        });

        let bytes =
            (Ipv4::new() / Udp::new().sport(5353).dport(50000) / Raw::from("custom-dns-like"))
                .compile()
                .unwrap();

        let decoded =
            Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, bytes.as_bytes())
                .unwrap();

        assert_eq!(
            decoded.layer::<Raw>().unwrap().as_bytes(),
            b"custom-dns-like"
        );
    }
}
