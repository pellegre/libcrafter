//! Explicit protocol binding and decode dispatch.

use std::sync::OnceLock;

use crate::endian::read_u32_be;
use crate::error::Result;
use crate::packet::{LinkType, NetworkLayer, Packet, Raw};
use crate::protocols::bgp::{decode::append_bgp_packet_with_registry, BGP_PORT};
use crate::protocols::dhcp::{append_dhcp_packet, is_dhcp_port_pair, looks_like_dhcp_payload};
use crate::protocols::dns::{append_dns_packet, DNS_PORT};
use crate::protocols::eapol::append_eapol_packet;
use crate::protocols::icmp::{
    append_icmp_packet, append_icmp_packet_with_checksum_validation, append_icmpv6_packet,
};
use crate::protocols::ipsec::ah::decode::append_ah_packet_with_registry_sa;
use crate::protocols::ipsec::esp::decode::append_esp_packet_with_registry_sa;
use crate::protocols::ipsec::esp::header::ESP_HEADER_LEN;
use crate::protocols::ipsec::ikev2::decode::append_ikev2_packet_with_registry;
use crate::protocols::ipsec::natt::{is_non_esp_marker, NatTraversal, NON_ESP_MARKER_LEN};
use crate::protocols::ipsec::sa::SecurityAssociation;
use crate::protocols::ipv4::{
    append_ipv4_packet_with_registry, IPPROTO_AH, IPPROTO_ESP, IPPROTO_ICMP, IPPROTO_ICMPV6,
    IPPROTO_OSPF, IPPROTO_TCP, IPPROTO_UDP,
};
use crate::protocols::ipv6::{append_ipv6_packet_with_registry, IPPROTO_IPV6_AH, IPPROTO_IPV6_ESP};
use crate::protocols::ospf::decode::append_ospf_packet_with_checksum_validation;
use crate::protocols::ospf::v3::append_ospfv3_packet_with_checksum_validation;
// Re-export the checksum-agnostic OSPF entrypoint alongside the registry so
// callers wiring custom dispatch can decode an OSPF payload without opting into
// decode-time checksum validation (RFC 2328 §A.3.1).
#[allow(unused_imports)]
pub(crate) use crate::protocols::ospf::decode::append_ospf_packet;
use crate::protocols::link::{
    append_arp_packet, append_vlan_packet_with_registry, decode_dot11_with_registry,
    decode_ethernet_with_registry, decode_linux_sll_with_registry,
    decode_null_loopback_with_registry, decode_radiotap_with_registry, ETHERTYPE_ARP,
    ETHERTYPE_EAPOL, ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_VLAN,
};
use crate::protocols::rip::ripng::{append_ripng_packet, looks_like_ripng_payload, RIPNG_UDP_PORT};
use crate::protocols::rip::{append_rip_packet, looks_like_rip_payload, RIP_UDP_PORT};
use crate::protocols::transport::{
    append_tcp_packet_with_registry, append_udp_packet_with_registry,
};

/// UDP port for IKEv2 (RFC 7296 §2; IANA "isakmp" 500). An IKE message on this
/// port is the 28-octet header plus its payload chain; the registry routes it to
/// the IKEv2 decoder.
const IKEV2_UDP_PORT: u16 = 500;

/// UDP port for IPSec NAT traversal (RFC 3948 §2; IANA "ipsec-nat-t" 4500). This
/// port carries both UDP-encapsulated ESP and IKE; the registry disambiguates
/// them by the RFC 3948 non-ESP marker (the leading four octets).
const NATT_UDP_PORT: u16 = 4500;

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
    builtin_ethertype_dispatch: bool,
    ipv4_bindings: Vec<Ipv4ProtocolBinding>,
    builtin_ipv4_protocol_dispatch: bool,
    ipv6_bindings: Vec<Ipv6NextHeaderBinding>,
    builtin_ipv6_next_header_dispatch: bool,
    udp_bindings: Vec<UdpBinding>,
    builtin_udp_application_dispatch: bool,
    tcp_bindings: Vec<TcpBinding>,
    security_associations: Vec<SecurityAssociation>,
    validate_checksums: bool,
    decode_applications: bool,
}

impl ProtocolRegistry {
    /// Create a registry with the built-in protocol bindings installed.
    pub fn new() -> Self {
        Self::with_builtin_bindings()
    }

    /// Shared built-in registry used by default decode entrypoints.
    pub(crate) fn builtin() -> &'static Self {
        static BUILTIN_REGISTRY: OnceLock<ProtocolRegistry> = OnceLock::new();
        BUILTIN_REGISTRY.get_or_init(Self::with_builtin_bindings)
    }

    /// Shared transport-only registry used by shallow ICMP quoted-datagram
    /// decode.
    pub(crate) fn transport_only_builtin() -> &'static Self {
        static TRANSPORT_ONLY_REGISTRY: OnceLock<ProtocolRegistry> = OnceLock::new();
        TRANSPORT_ONLY_REGISTRY.get_or_init(Self::transport_only)
    }

    /// Create a registry with no bindings.
    pub fn empty() -> Self {
        Self {
            ethertype_bindings: Vec::new(),
            builtin_ethertype_dispatch: false,
            ipv4_bindings: Vec::new(),
            builtin_ipv4_protocol_dispatch: false,
            ipv6_bindings: Vec::new(),
            builtin_ipv6_next_header_dispatch: false,
            udp_bindings: Vec::new(),
            builtin_udp_application_dispatch: false,
            tcp_bindings: Vec::new(),
            security_associations: Vec::new(),
            validate_checksums: true,
            decode_applications: true,
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
        registry.bind_ethertype_with_registry(ETHERTYPE_EAPOL, |_registry, packet, payload| {
            append_eapol_packet(packet, payload)
        });
        registry.builtin_ethertype_dispatch = true;

        registry.bind_ipv4_protocol_with_registry(IPPROTO_ICMP, |registry, packet, payload| {
            append_icmp_packet_with_checksum_validation(
                packet,
                payload,
                registry.validates_checksums(),
            )
        });
        registry.bind_ipv4_protocol_with_registry(IPPROTO_TCP, |registry, packet, payload| {
            append_tcp_packet_with_registry(registry, packet, payload)
        });
        registry.bind_ipv4_protocol_with_registry(IPPROTO_UDP, |registry, packet, payload| {
            append_udp_packet_with_registry(registry, packet, payload)
        });
        // ESP (IP protocol 50, RFC 4303). The decoder looks up a registered SA by
        // the on-wire SPI: when one is found it drives the SA-aware path (verify
        // the ICV, decrypt, strip padding, dispatch the inner protocol/IP); when
        // none is found — as in the default SA-less registry — it falls back to
        // the opaque path (SPI/Sequence exposed, encrypted body preserved
        // verbatim). Callers register SAs with
        // [`ProtocolRegistry::register_security_association`].
        registry.bind_ipv4_protocol_with_registry(IPPROTO_ESP, |registry, packet, payload| {
            decode_esp_with_registry_sa(registry, packet, payload)
        });
        // AH (IP protocol 51, RFC 4302). AH only authenticates, so the protected
        // upper-layer data — and, in tunnel mode, the inner IP datagram — is
        // always in the clear: the typed `Ah` header and its variable-length ICV
        // decode without keys, and the inner protocol dispatches by Next Header.
        // When a registered SA matches the on-wire SPI the decoder also verifies
        // the ICV and records the verified status; otherwise — as in the default
        // SA-less registry — the ICV is preserved verbatim rather than verified.
        registry.bind_ipv4_protocol_with_registry(IPPROTO_AH, |registry, packet, payload| {
            decode_ah_with_registry_sa(registry, packet, payload)
        });
        // OSPFv2 (IP protocol 89, RFC 2328). OSPF runs directly over IP, so the
        // IPv4 payload is the OSPF common header plus its body; the decoder is
        // handed the registry checksum policy for decode-time checksum status.
        registry.bind_ipv4_protocol_with_registry(IPPROTO_OSPF, |registry, packet, payload| {
            append_ospf_packet_with_checksum_validation(
                packet,
                payload,
                registry.validates_checksums(),
            )
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
        // ESP as an IPv6 next-header (RFC 4303); same SA-lookup behavior as IPv4.
        registry
            .bind_ipv6_next_header_with_registry(IPPROTO_IPV6_ESP, |registry, packet, payload| {
                decode_esp_with_registry_sa(registry, packet, payload)
            });
        // AH as an IPv6 next-header (RFC 4302). AH can appear in the IPv6
        // extension-header chain, so once the chain walk reaches next-header 51
        // it dispatches here; the cleartext upper-layer data (transport mode) or
        // inner IP datagram (tunnel mode) decodes without keys, and a registered
        // SA matching the SPI additionally verifies the ICV, same as IPv4.
        registry
            .bind_ipv6_next_header_with_registry(IPPROTO_IPV6_AH, |registry, packet, payload| {
                decode_ah_with_registry_sa(registry, packet, payload)
            });
        // OSPFv3 as an IPv6 next-header (RFC 5340 §2.5): next-header 89 carries
        // the 16-octet OSPFv3 common header and its body. The decoder parses the
        // header into a typed `Ospfv3` layer, dispatches the body by packet type
        // and the v3 LSAs, and is handed the registry checksum policy for the
        // decode-time IPv6 upper-layer checksum status (RFC 5340 §2.7).
        registry.bind_ipv6_next_header_with_registry(IPPROTO_OSPF, |registry, packet, payload| {
            append_ospfv3_packet_with_checksum_validation(
                packet,
                payload,
                registry.validates_checksums(),
            )
        });

        registry.bind_udp_port_with_registry(DNS_PORT, |_registry, packet, payload| {
            append_dns_packet(packet, payload)
        });
        // IKEv2 over UDP/500 (RFC 7296 §2). The UDP application dispatch passes the
        // UDP payload, which for port 500 is a complete IKE message (28-octet
        // header + payload chain); the decoder walks it into typed payload layers
        // (Raw for an unmodeled type). UDP/500 carries IKE only and never the
        // non-ESP marker (RFC 3948 §2.2), so no disambiguation is needed here.
        registry.bind_udp_port_with_registry(IKEV2_UDP_PORT, |registry, packet, payload| {
            append_ikev2_packet_with_registry(registry, packet, payload)
        });
        // IPSec NAT traversal over UDP/4500 (RFC 3948). The same flow carries both
        // UDP-encapsulated ESP and IKE, so the registry inspects the leading four
        // octets to disambiguate (RFC 3948 §2.1–§2.2):
        //
        // - **non-ESP marker** (four zero octets): an IKE message. The marker is
        //   pushed as a typed `NatTraversal` layer so it round-trips byte-exact,
        //   then the remaining bytes decode as an IKEv2 message.
        // - **a nonzero leading word**: a UDP-encapsulated ESP datagram whose
        //   leading word is a real ESP SPI (SPI 0 is reserved, RFC 4303 §2.1), so
        //   it decodes through the ESP decoder (opaque in the built-in registry).
        //
        // The binding is deliberately conservative to avoid claiming unrelated
        // traffic that merely uses port 4500: it matches only when the payload is
        // at least the ESP fixed-header length (8 octets, RFC 4303 §2). A shorter
        // payload — the RFC 3948 §4 single-octet NAT keepalive, or any short non-
        // IPSec datagram — cannot be a UDP-encapsulated ESP datagram or a
        // marker+IKE message, so it falls through to the default Raw payload.
        registry.bind_udp_with_registry(
            |ctx| {
                (ctx.source_port == NATT_UDP_PORT || ctx.destination_port == NATT_UDP_PORT)
                    && ctx.payload.len() >= ESP_HEADER_LEN
            },
            |registry, packet, payload| {
                if is_non_esp_marker(payload) {
                    // Strip the four-octet marker, preserving it as a typed layer,
                    // then decode the IKE message that follows it.
                    let marker =
                        NatTraversal::marker().bytes(payload[..NON_ESP_MARKER_LEN].to_vec());
                    let packet = packet.push(marker);
                    append_ikev2_packet_with_registry(
                        registry,
                        packet,
                        &payload[NON_ESP_MARKER_LEN..],
                    )
                } else {
                    decode_esp_with_registry_sa(registry, packet, payload)
                }
            },
        );
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

        // RIP (RFC 1058 / RFC 2453) decode binds on UDP/520, kept conservative
        // by the `looks_like_rip_payload` shape gate (known command, version 1/2,
        // and a whole number of 20-octet entries) so unrelated traffic that
        // merely uses port 520 falls through to `Raw` rather than misdecoding as
        // `Rip`.
        registry.bind_udp_with_registry(
            |ctx| {
                (ctx.source_port == RIP_UDP_PORT || ctx.destination_port == RIP_UDP_PORT)
                    && looks_like_rip_payload(ctx.payload)
            },
            |_registry, packet, payload| append_rip_packet(packet, payload),
        );

        // RIPng (RFC 2080) decode binds on UDP/521, kept conservative by the
        // `looks_like_ripng_payload` shape gate (known command, version 1, and a
        // whole number of 20-octet RTEs) so unrelated traffic that merely uses
        // port 521 falls through to `Raw` rather than misdecoding as `Ripng`.
        registry.bind_udp_with_registry(
            |ctx| {
                (ctx.source_port == RIPNG_UDP_PORT || ctx.destination_port == RIPNG_UDP_PORT)
                    && looks_like_ripng_payload(ctx.payload)
            },
            |_registry, packet, payload| append_ripng_packet(packet, payload),
        );

        registry.bind_tcp_port_with_registry(BGP_PORT, |registry, packet, payload| {
            append_bgp_packet_with_registry(registry, packet, payload)
        });

        registry.builtin_ipv4_protocol_dispatch = true;
        registry.builtin_ipv6_next_header_dispatch = true;
        registry.builtin_udp_application_dispatch = true;

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

    /// Enable or disable decode-time checksum validation for this registry.
    ///
    /// The default registry validates inspectable checksums while decoding, so
    /// decoded IPv4 and UDP layers report `Valid` or `Invalid` when enough
    /// context is present. Benchmark and header-classification workflows can
    /// opt out when they need to compare only parsing/materialization cost
    /// against decoders that do not validate checksums during parse.
    #[must_use]
    pub fn checksum_validation(mut self, enabled: bool) -> Self {
        self.validate_checksums = enabled;
        self
    }

    /// Mutably enable or disable decode-time checksum validation.
    pub fn set_checksum_validation(&mut self, enabled: bool) -> &mut Self {
        self.validate_checksums = enabled;
        self
    }

    pub(crate) const fn validates_checksums(&self) -> bool {
        self.validate_checksums
    }

    /// Enable or disable UDP/TCP application-layer decoding.
    ///
    /// When disabled, transport headers still decode normally but application
    /// payload bytes are preserved as `Raw`, bypassing built-in and custom
    /// application decoders.
    #[must_use]
    pub fn application_decoding(mut self, enabled: bool) -> Self {
        self.decode_applications = enabled;
        self
    }

    /// Mutably enable or disable UDP/TCP application-layer decoding.
    pub fn set_application_decoding(&mut self, enabled: bool) -> &mut Self {
        self.decode_applications = enabled;
        self
    }

    pub(crate) const fn decodes_applications(&self) -> bool {
        self.decode_applications
    }

    pub(crate) const fn uses_builtin_ethertype_dispatch(&self) -> bool {
        self.builtin_ethertype_dispatch
    }

    /// Decode bytes from a link-layer entrypoint.
    pub fn decode_from_link(&self, link_type: LinkType, bytes: impl AsRef<[u8]>) -> Result<Packet> {
        let bytes = bytes.as_ref();
        match link_type {
            LinkType::Raw => Packet::decode_raw(bytes),
            LinkType::Ethernet => self.decode_ethernet(bytes),
            LinkType::Ieee80211 => decode_dot11_with_registry(self, bytes),
            LinkType::Radiotap => decode_radiotap_with_registry(self, bytes),
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

    /// Register a [`SecurityAssociation`] so the ESP and AH decoders can verify
    /// and decrypt (ESP) or verify (AH) datagrams whose on-wire SPI matches it
    /// (RFC 4303 §3.4, RFC 4302 §3.4).
    ///
    /// The default built-in registry carries no SA, so ESP/AH decode opaquely:
    /// the SPI/Sequence are exposed and the encrypted body (ESP) or ICV (AH) is
    /// preserved verbatim. A caller that holds keys registers the matching SA on
    /// its own registry; the ESP/AH bindings then look the SA up by the SPI read
    /// from the wire and drive the SA-aware decode path
    /// ([`Packet::decode_from_l3_with_registry`] with this registry decrypts ESP
    /// and verifies AH). An SA is keyed by its [`SecurityAssociation::spi`]; a
    /// later registration for the same SPI takes precedence (it is matched
    /// first), mirroring how a later binding overrides an earlier one.
    ///
    /// [`Packet::decode_from_l3_with_registry`]: crate::packet::Packet::decode_from_l3_with_registry
    pub fn register_security_association(&mut self, sa: SecurityAssociation) -> &mut Self {
        self.security_associations.push(sa);
        self
    }

    /// Register a [`SecurityAssociation`] and return the owned registry, for
    /// fluent one-expression construction.
    ///
    /// This is the consuming counterpart to
    /// [`ProtocolRegistry::register_security_association`]:
    ///
    /// ```
    /// use crafter::{ProtocolRegistry, SecurityAssociation};
    /// use crafter::protocols::ipsec::sa::EncryptionAlgorithm;
    ///
    /// let registry = ProtocolRegistry::new().with_security_association(
    ///     SecurityAssociation::new(0x0000_2000)
    ///         .encryption(EncryptionAlgorithm::AesGcm16, vec![0u8; 16])
    ///         .salt(vec![0u8; 4]),
    /// );
    /// let _ = registry;
    /// ```
    #[must_use]
    pub fn with_security_association(mut self, sa: SecurityAssociation) -> Self {
        self.security_associations.push(sa);
        self
    }

    /// Find a registered [`SecurityAssociation`] by its SPI, most-recently
    /// registered first (so a later registration overrides an earlier one).
    pub(crate) fn security_association_for_spi(&self, spi: u32) -> Option<&SecurityAssociation> {
        self.security_associations
            .iter()
            .rev()
            .find(|sa| sa.spi == spi)
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
        if self.builtin_ethertype_dispatch {
            return match ethertype {
                ETHERTYPE_ARP => append_arp_packet(packet, payload),
                ETHERTYPE_VLAN => append_vlan_packet_with_registry(self, packet, payload),
                ETHERTYPE_IPV4 => append_ipv4_packet_with_registry(self, packet, payload),
                ETHERTYPE_IPV6 => append_ipv6_packet_with_registry(self, packet, payload),
                ETHERTYPE_EAPOL => append_eapol_packet(packet, payload),
                _ => Ok(packet.push_raw(Raw::from_bytes(payload))),
            };
        }

        let ctx = EthertypeBindingContext { ethertype, payload };
        if let Some(binding) = self
            .ethertype_bindings
            .iter()
            .rev()
            .find(|binding| (binding.predicate)(ctx))
        {
            return (binding.decoder)(self, packet, payload);
        }
        Ok(packet.push_raw(Raw::from_bytes(payload)))
    }

    pub(crate) fn decode_ipv4_protocol(
        &self,
        packet: Packet,
        protocol: u8,
        payload: &[u8],
    ) -> Result<Packet> {
        if self.builtin_ipv4_protocol_dispatch {
            return match protocol {
                IPPROTO_ICMP => append_icmp_packet_with_checksum_validation(
                    packet,
                    payload,
                    self.validates_checksums(),
                ),
                IPPROTO_TCP => append_tcp_packet_with_registry(self, packet, payload),
                IPPROTO_UDP => append_udp_packet_with_registry(self, packet, payload),
                IPPROTO_ESP => decode_esp_with_registry_sa(self, packet, payload),
                IPPROTO_AH => decode_ah_with_registry_sa(self, packet, payload),
                IPPROTO_OSPF => append_ospf_packet_with_checksum_validation(
                    packet,
                    payload,
                    self.validates_checksums(),
                ),
                _ => append_raw_if_needed(packet, payload),
            };
        }

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
        if self.builtin_ipv6_next_header_dispatch {
            return match next_header {
                IPPROTO_ICMPV6 => append_icmpv6_packet(packet, payload),
                IPPROTO_TCP => append_tcp_packet_with_registry(self, packet, payload),
                IPPROTO_UDP => append_udp_packet_with_registry(self, packet, payload),
                IPPROTO_IPV6_ESP => decode_esp_with_registry_sa(self, packet, payload),
                IPPROTO_IPV6_AH => decode_ah_with_registry_sa(self, packet, payload),
                IPPROTO_OSPF => append_ospfv3_packet_with_checksum_validation(
                    packet,
                    payload,
                    self.validates_checksums(),
                ),
                _ => append_raw_if_needed(packet, payload),
            };
        }

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
        if !self.decode_applications {
            return append_raw_if_needed(packet, payload);
        }

        if self.builtin_udp_application_dispatch {
            if is_dhcp_port_pair(source_port, destination_port) && looks_like_dhcp_payload(payload)
            {
                return append_dhcp_packet(packet, payload);
            }

            if (source_port == RIP_UDP_PORT || destination_port == RIP_UDP_PORT)
                && looks_like_rip_payload(payload)
            {
                return append_rip_packet(packet, payload);
            }

            if (source_port == RIPNG_UDP_PORT || destination_port == RIPNG_UDP_PORT)
                && looks_like_ripng_payload(payload)
            {
                return append_ripng_packet(packet, payload);
            }

            if (source_port == NATT_UDP_PORT || destination_port == NATT_UDP_PORT)
                && payload.len() >= ESP_HEADER_LEN
            {
                if is_non_esp_marker(payload) {
                    let marker =
                        NatTraversal::marker().bytes(payload[..NON_ESP_MARKER_LEN].to_vec());
                    let packet = packet.push(marker);
                    return append_ikev2_packet_with_registry(
                        self,
                        packet,
                        &payload[NON_ESP_MARKER_LEN..],
                    );
                }
                return decode_esp_with_registry_sa(self, packet, payload);
            }

            if source_port == IKEV2_UDP_PORT || destination_port == IKEV2_UDP_PORT {
                return append_ikev2_packet_with_registry(self, packet, payload);
            }

            if source_port == DNS_PORT || destination_port == DNS_PORT {
                return append_dns_packet(packet, payload);
            }

            return append_raw_if_needed(packet, payload);
        }

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
        if !self.decode_applications {
            return append_raw_if_needed(packet, payload);
        }

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
        self.builtin_ethertype_dispatch = false;
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
        self.builtin_ipv4_protocol_dispatch = false;
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
        self.builtin_ipv6_next_header_dispatch = false;
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
        self.builtin_udp_application_dispatch = false;
        self
    }

    pub(crate) fn bind_tcp_port_with_registry<D>(&mut self, port: u16, decoder: D) -> &mut Self
    where
        D: for<'a> Fn(&'a ProtocolRegistry, Packet, &'a [u8]) -> Result<Packet>
            + Send
            + Sync
            + 'static,
    {
        self.bind_tcp_with_registry(
            move |ctx| ctx.source_port == port || ctx.destination_port == port,
            decoder,
        )
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
        Ok(packet.push_raw(Raw::from_bytes(payload)))
    }
}

/// Decode an ESP datagram, consulting the registry's registered SAs (RFC 4303).
///
/// The ESP Security Parameters Index is the leading four octets of the datagram
/// (RFC 4303 §2.1). When a [`SecurityAssociation`] registered with
/// [`ProtocolRegistry::register_security_association`] matches that SPI, the
/// SA-aware path verifies the ICV, decrypts, strips the RFC 4303 §2.4 padding,
/// and dispatches the inner protocol (transport) or inner IP (tunnel); an
/// integrity failure surfaces a structured error and the decode fails closed.
/// When no SA matches — the default SA-less registry — the opaque path runs:
/// the SPI/Sequence are exposed and the encrypted body is preserved verbatim.
/// A buffer too short to even hold the SPI falls through to the opaque decode,
/// which reports the structured truncation error.
fn decode_esp_with_registry_sa(
    registry: &ProtocolRegistry,
    packet: Packet,
    payload: &[u8],
) -> Result<Packet> {
    let sa = read_u32_be(payload.get(0..4).unwrap_or(payload))
        .ok()
        .and_then(|spi| registry.security_association_for_spi(spi));
    append_esp_packet_with_registry_sa(registry, packet, payload, sa)
}

/// Decode an AH datagram, consulting the registry's registered SAs (RFC 4302).
///
/// The AH Security Parameters Index follows the Next Header, Payload Len, and
/// Reserved fields, occupying octets 4..8 of the datagram (RFC 4302 §2.4). When
/// a [`SecurityAssociation`] registered with
/// [`ProtocolRegistry::register_security_association`] matches that SPI, the
/// SA-aware path verifies the ICV over the canonicalized immutable IP fields,
/// the ICV-zeroed AH header, and the cleartext upper-layer data, recording the
/// verified status on the recovered [`Ah`] layer; a mismatch fails closed with a
/// structured error. When no SA matches — the default SA-less registry — the
/// opaque path recovers the typed header and inner protocol without verifying.
/// AH never encrypts, so the inner layers are recovered the same either way.
///
/// [`Ah`]: crate::protocols::ipsec::ah::Ah
fn decode_ah_with_registry_sa(
    registry: &ProtocolRegistry,
    packet: Packet,
    payload: &[u8],
) -> Result<Packet> {
    let sa = payload
        .get(4..8)
        .and_then(|spi_bytes| read_u32_be(spi_bytes).ok())
        .and_then(|spi| registry.security_association_for_spi(spi));
    append_ah_packet_with_registry_sa(registry, packet, payload, sa)
}

#[cfg(test)]
mod protocol_registry {
    use super::ProtocolRegistry;
    use crate::{Ipv4, Ipv4ChecksumStatus, NetworkLayer, Packet, Raw, Udp, UdpChecksumStatus};

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

    #[test]
    fn registry_can_skip_application_decoding() {
        let bytes = (Ipv4::new()
            / crate::Udp::new().sport(53001).dport(crate::DNS_PORT)
            / crate::Dns::a_query("example.com."))
        .compile()
        .unwrap();
        let registry = ProtocolRegistry::new().application_decoding(false);

        let decoded = registry
            .decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
            .unwrap();

        assert!(decoded.layer::<crate::Udp>().is_some());
        assert!(decoded.layer::<crate::Dns>().is_none());
        assert!(decoded.layer::<Raw>().is_some());
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
            .unwrap()
            .layer::<crate::Dns>()
            .is_some());
    }

    /// IP protocol 89 dispatches to the OSPF decoder through the default
    /// registry: an `Ipv4 / Ospfv2` Hello round-trips byte-for-byte and exposes
    /// a typed `Ospfv2` layer when decoded via the public `Packet` entrypoint.
    #[test]
    fn default_registry_decodes_ospf_over_ipv4() {
        use core::net::Ipv4Addr;

        use crate::protocols::ospf::decode::{
            append_ospf_packet, append_ospf_packet_with_checksum_validation,
        };
        use crate::protocols::ospf::Ospfv2;

        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(192, 0, 2, 2))
            / Ospfv2::hello())
        .compile()
        .expect("Ipv4 / Ospfv2 Hello compiles");

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
            .expect("the default registry decodes OSPF over IPv4");
        assert!(
            decoded.layer::<Ospfv2>().is_some(),
            "the decoded packet exposes a typed Ospfv2 layer"
        );

        let recompiled = decoded.compile().expect("decoded OSPF re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());

        // The checksum-aware and plain decode entrypoints are both reachable
        // from the registry module: feed the OSPF payload (after the IPv4
        // header) to each and confirm both surface the typed layer.
        let ipv4_header_len = (bytes.as_bytes()[0] & 0x0f) as usize * 4;
        let ospf_payload = &bytes.as_bytes()[ipv4_header_len..];
        assert!(append_ospf_packet(Packet::new(), ospf_payload)
            .expect("append_ospf_packet decodes the payload")
            .layer::<Ospfv2>()
            .is_some());
        assert!(
            append_ospf_packet_with_checksum_validation(Packet::new(), ospf_payload, false)
                .expect("append_ospf_packet_with_checksum_validation decodes the payload")
                .layer::<Ospfv2>()
                .is_some()
        );
    }

    #[test]
    fn registry_can_skip_decode_checksum_validation() {
        let bytes = (Ipv4::new() / Udp::new().sport(53001).dport(9000) / Raw::from("payload"))
            .compile()
            .unwrap();
        let registry = ProtocolRegistry::new().checksum_validation(false);

        let decoded = registry
            .decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
            .unwrap();

        assert_eq!(
            decoded.layer::<Ipv4>().unwrap().checksum_status(),
            Ipv4ChecksumStatus::NotChecked
        );
        assert_eq!(
            decoded.layer::<Udp>().unwrap().checksum_status(),
            UdpChecksumStatus::NotChecked
        );
        assert_eq!(
            Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
                .unwrap()
                .layer::<Udp>()
                .unwrap()
                .checksum_status(),
            UdpChecksumStatus::Valid
        );
    }
}

#[cfg(test)]
mod decode_dispatch {
    use super::ProtocolRegistry;
    use crate::{Ethernet, Ipv4, Ipv4Protocol, LinkType, NetworkLayer, Packet, Raw, Udp};

    #[test]
    fn default_registry_dispatches_from_ethernet_to_ipv4_udp() {
        let bytes = (Ethernet::new()
            / Ipv4::new().ipv4_protocol(Ipv4Protocol::Udp)
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
mod esp_protocol_binding {
    use crate::protocols::ipsec::esp::Esp;
    use crate::protocols::ipv4::IPPROTO_ESP;
    use crate::protocols::ipv6::IPPROTO_IPV6_ESP;
    use crate::{Ipv4, Ipv6, NetworkLayer, Packet, Raw};

    #[test]
    fn default_registry_decodes_ipv4_protocol_50_as_opaque_esp() {
        // The built-in registry has no SA, so IP protocol 50 must decode via the
        // opaque ESP path: the SPI/Sequence are exposed and the body is preserved
        // verbatim. The enclosing IPv4 protocol is pinned to 50 (auto-deriving 50
        // from an inner Esp is not wired; prior ESP tests set it explicitly too).
        let bytes = (Ipv4::new().protocol(IPPROTO_ESP)
            / Esp::new().spi(0x0000_2000).sequence(7)
            / Raw::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();

        // First layer is the IPv4 header; the second is the typed Esp.
        assert!(decoded.layer::<Ipv4>().is_some());
        let esp = decoded
            .get(1)
            .unwrap()
            .as_any()
            .downcast_ref::<Esp>()
            .expect("second layer is Esp");
        assert_eq!(esp.spi_value(), Some(0x0000_2000));
        assert_eq!(esp.sequence_value(), Some(7));
        // No SA in the built-in registry: the body is carried opaquely.
        assert!(esp.opaque_body().is_some());

        // The decoded packet re-compiles byte-for-byte.
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn default_registry_decodes_ipv6_next_header_50_as_opaque_esp() {
        let bytes = (Ipv6::new().nh(IPPROTO_IPV6_ESP)
            / Esp::new().spi(0x0000_3000).sequence(9)
            / Raw::from_bytes(vec![0xAA, 0xBB, 0xCC, 0xDD, 0x10, 0x20, 0x30, 0x40]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();

        assert!(decoded.layer::<Ipv6>().is_some());
        let esp = decoded
            .get(1)
            .unwrap()
            .as_any()
            .downcast_ref::<Esp>()
            .expect("second layer is Esp");
        assert_eq!(esp.spi_value(), Some(0x0000_3000));
        assert_eq!(esp.sequence_value(), Some(9));
        assert!(esp.opaque_body().is_some());

        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }
}

#[cfg(test)]
mod ah_protocol_binding {
    use crate::protocols::ipsec::ah::Ah;
    use crate::protocols::ipsec::sa::{IntegrityAlgorithm, SecurityAssociation};
    use crate::protocols::ipv4::{IPPROTO_AH, IPPROTO_TCP};
    use crate::protocols::ipv6::IPPROTO_IPV6_AH;
    use crate::{Ipv4, Ipv6, NetworkLayer, Packet, Raw, Tcp};

    /// An HMAC-SHA-256-128 (RFC 4868) integrity-only SA with a fixed
    /// documentation key. AH only authenticates, so the built-in registry can
    /// recover the inner protocol in the clear without ever holding this SA.
    fn ah_sa() -> SecurityAssociation {
        SecurityAssociation::new(0x0000_2000)
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0x77u8; 32])
    }

    #[test]
    fn default_registry_decodes_ipv4_protocol_51_as_ah_with_inner_tcp() {
        // The enclosing IPv4 protocol is pinned to AH (51); the AH header is
        // sealed by the SA, but the protected Tcp / Raw travels in the clear.
        let bytes = (Ipv4::new()
            .protocol(IPPROTO_AH)
            .src("192.0.2.1".parse().unwrap())
            .dst("192.0.2.2".parse().unwrap())
            .ttl(64)
            / Ah::secured(ah_sa()).spi(0x0000_2000).sequence(1)
            / Tcp::new().sport(1234).dport(443)
            / Raw::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();

        // IPv4 header, then the typed Ah, then the cleartext inner Tcp / Raw.
        assert!(decoded.layer::<Ipv4>().is_some());
        let ah = decoded
            .get(1)
            .unwrap()
            .as_any()
            .downcast_ref::<Ah>()
            .expect("second layer is Ah");
        assert_eq!(ah.spi_value(), Some(0x0000_2000));
        assert_eq!(ah.sequence_value(), Some(1));
        assert_eq!(ah.next_header_value(), Some(IPPROTO_TCP));
        // The built-in registry has no SA, so the ICV is preserved verbatim and
        // never verified.
        assert_eq!(ah.verification_status(), None);

        let tcp = decoded
            .layer::<Tcp>()
            .expect("inner Tcp decoded in the clear");
        assert_eq!(tcp.source_port_value(), 1234);
        assert_eq!(tcp.destination_port_value(), 443);
        assert_eq!(
            decoded
                .layer::<Raw>()
                .expect("inner Raw decoded")
                .as_bytes(),
            &[0xDE, 0xAD, 0xBE, 0xEF]
        );

        // The decoded packet re-compiles byte-for-byte.
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn default_registry_decodes_ipv6_next_header_51_as_ah_with_inner_tcp() {
        let bytes = (Ipv6::new()
            .nh(IPPROTO_IPV6_AH)
            .src("2001:db8::1".parse().unwrap())
            .dst("2001:db8::2".parse().unwrap())
            .hop_limit(64)
            / Ah::secured(ah_sa()).spi(0x0000_3000).sequence(9)
            / Tcp::new().sport(2345).dport(80)
            / Raw::from_bytes(vec![0xAA, 0xBB, 0xCC, 0xDD]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();

        assert!(decoded.layer::<Ipv6>().is_some());
        let ah = decoded
            .get(1)
            .unwrap()
            .as_any()
            .downcast_ref::<Ah>()
            .expect("second layer is Ah");
        assert_eq!(ah.spi_value(), Some(0x0000_3000));
        assert_eq!(ah.sequence_value(), Some(9));
        assert_eq!(ah.next_header_value(), Some(IPPROTO_TCP));
        assert_eq!(ah.verification_status(), None);

        let tcp = decoded
            .layer::<Tcp>()
            .expect("inner Tcp decoded in the clear");
        assert_eq!(tcp.source_port_value(), 2345);
        assert_eq!(tcp.destination_port_value(), 80);
        assert_eq!(
            decoded
                .layer::<Raw>()
                .expect("inner Raw decoded")
                .as_bytes(),
            &[0xAA, 0xBB, 0xCC, 0xDD]
        );

        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn ah_in_ipv6_decodes_after_a_preceding_extension_header() {
        use crate::protocols::ipv6::Ipv6DestinationOptionsHeader;
        use crate::Ipv6Option;

        // AH following another IPv6 extension header: the next-header chain walk
        // must reach the AH binding. First build a real AH datagram (the AH
        // header + ICV followed by the cleartext Tcp / Raw) from a direct
        // `Ipv6(nh=AH) / Ah / Tcp / Raw` stack, then capture the bytes that
        // follow the IPv6 base header — i.e. the AH-onward wire bytes.
        let direct = (Ipv6::new()
            .nh(IPPROTO_IPV6_AH)
            .src("2001:db8::1".parse().unwrap())
            .dst("2001:db8::2".parse().unwrap())
            .hop_limit(64)
            / Ah::secured(ah_sa()).spi(0x0000_4000).sequence(3)
            / Tcp::new().sport(3456).dport(8080)
            / Raw::from_bytes(vec![0x11, 0x22, 0x33, 0x44]))
        .compile()
        .unwrap();
        // Strip the 40-octet IPv6 base header to leave the AH datagram bytes.
        let ah_datagram = direct.as_bytes()[40..].to_vec();

        // Place the AH datagram after a Destination Options extension header
        // whose own Next Header advertises AH (51). The IPv6 base header points
        // at the Destination Options header, so the registry's extension-header
        // chain walk advances base -> Destination Options -> next-header 51,
        // reaching the AH binding for the trailing bytes.
        let bytes = (Ipv6::new()
            .src("2001:db8::1".parse().unwrap())
            .dst("2001:db8::2".parse().unwrap())
            .hop_limit(64)
            / Ipv6DestinationOptionsHeader::new()
                .nh(IPPROTO_IPV6_AH)
                .option(Ipv6Option::pad1())
            / Raw::from_bytes(ah_datagram))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();

        // The chain walk reaches the AH binding after the Destination Options
        // header, producing a typed `Ah` (not a `Raw` tail).
        let ah = decoded
            .layer::<Ah>()
            .expect("Ah decoded after the extension header");
        assert_eq!(ah.spi_value(), Some(0x0000_4000));
        assert_eq!(ah.next_header_value(), Some(IPPROTO_TCP));

        let tcp = decoded
            .layer::<Tcp>()
            .expect("inner Tcp decoded in the clear");
        assert_eq!(tcp.source_port_value(), 3456);
        assert_eq!(tcp.destination_port_value(), 8080);

        // This case confirms the decode side: the IPv6 extension-header chain
        // walk advances past the Destination Options header and dispatches
        // next-header 51 to the AH binding. (A byte-exact re-compile is asserted
        // by the two direct `Ipv4 / Ah / Tcp` and `Ipv6 / Ah / Tcp` cases above;
        // `Ah::compile` reads only its immediately preceding layer for the IP
        // version, so re-emitting AH that sits *behind* an extension header is a
        // separate build-side concern, not part of registry dispatch.)
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

#[cfg(test)]
mod bgp_tcp_binding {
    use crate::protocols::bgp::BGP_PORT;
    use crate::{Bgp, Ipv4, NetworkLayer, Packet, Raw, Tcp};

    #[test]
    fn default_registry_decodes_bgp_on_tcp_179_and_preserves_other_tcp_payloads() {
        let bgp_bytes = (Ipv4::new() / Tcp::new().sport(49_152).dport(BGP_PORT) / Bgp::keepalive())
            .compile()
            .unwrap();

        let bgp_decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bgp_bytes.as_bytes()).unwrap();

        assert!(bgp_decoded.layer::<Bgp>().is_some());
        assert!(bgp_decoded.layer::<Raw>().is_none());

        let keepalive = Packet::from_layer(Bgp::keepalive())
            .compile()
            .unwrap()
            .into_bytes();
        let raw_bytes =
            (Ipv4::new() / Tcp::new().sport(49_152).dport(80) / Raw::from_bytes(keepalive.clone()))
                .compile()
                .unwrap();

        let raw_decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, raw_bytes.as_bytes()).unwrap();

        assert!(raw_decoded.layer::<Bgp>().is_none());
        assert_eq!(raw_decoded.layer::<Raw>().unwrap().as_bytes(), keepalive);
    }
}
