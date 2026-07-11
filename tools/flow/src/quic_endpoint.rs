//! Provider-neutral configuration for the private QUIC endpoint driver.

use std::{fmt, net::SocketAddr, time::Duration};

#[cfg(feature = "quic-endpoint")]
use std::{net::Ipv4Addr, time::Instant};

use crate::FlowError;
#[cfg(feature = "quic-endpoint")]
use crate::{step::SendIntent, Result};

/// Local and peer address metadata carried with a QUIC UDP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuicEndpointAddresses {
    /// Address at which the datagram is sent or received locally.
    pub local: SocketAddr,
    /// Address at which the peer sends or receives the datagram.
    pub peer: SocketAddr,
}

impl QuicEndpointAddresses {
    /// Creates address metadata without opening a socket.
    pub const fn new(local: SocketAddr, peer: SocketAddr) -> Self {
        Self { local, peer }
    }
}

/// Authentication name and ordered ALPN choices for a QUIC peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicPeerConfig {
    server_name: String,
    alpn_protocols: Vec<Vec<u8>>,
    verify_peer: bool,
    enable_zero_rtt: bool,
}

impl QuicPeerConfig {
    /// Creates peer configuration from a DNS authentication name and ALPN list.
    pub fn new(
        server_name: impl Into<String>,
        alpn_protocols: impl IntoIterator<Item = Vec<u8>>,
    ) -> Self {
        Self {
            server_name: server_name.into(),
            alpn_protocols: alpn_protocols.into_iter().collect(),
            verify_peer: true,
            enable_zero_rtt: false,
        }
    }

    /// Returns the DNS name authenticated by TLS.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Returns ALPN identifiers in caller preference order.
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.alpn_protocols
    }

    /// Selects whether TLS authenticates the configured peer.
    ///
    /// Endpoint construction rejects `false`; this setter exists so invalid
    /// caller configuration can be represented and diagnosed explicitly.
    pub fn with_peer_verification(mut self, enabled: bool) -> Self {
        self.verify_peer = enabled;
        self
    }

    /// Selects whether TLS 0-RTT is enabled.
    ///
    /// Bounded endpoint flows reject `true` because resumption and 0-RTT are
    /// outside their protocol contract.
    pub fn with_zero_rtt(mut self, enabled: bool) -> Self {
        self.enable_zero_rtt = enabled;
        self
    }
}

/// Bounded transport limits shared by QUIC client and server configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicTransportLimits {
    /// Maximum time without authenticated network activity.
    pub max_idle_timeout: Duration,
    /// Maximum UDP payload accepted from the provider.
    pub max_udp_payload_size: u16,
    /// Maximum number of peer-initiated bidirectional streams.
    pub max_bidirectional_streams: u64,
    /// Maximum bytes allowed on the one application stream.
    pub max_stream_bytes: u64,
    /// Maximum aggregate application bytes allowed by flow control.
    pub max_connection_bytes: u64,
}

impl Default for QuicTransportLimits {
    fn default() -> Self {
        Self {
            max_idle_timeout: Duration::from_secs(10),
            max_udp_payload_size: 1_472,
            max_bidirectional_streams: 1,
            max_stream_bytes: 64 * 1024,
            max_connection_bytes: 128 * 1024,
        }
    }
}

/// DER inputs for deterministic, offline endpoint tests.
///
/// Byte contents are intentionally omitted from both `Debug` and error output.
#[derive(Clone, PartialEq, Eq)]
pub struct QuicSyntheticIdentity {
    certificate_chain_der: Vec<Vec<u8>>,
    private_key_der: Vec<u8>,
    trusted_certificates_der: Vec<Vec<u8>>,
}

impl QuicSyntheticIdentity {
    /// Creates an explicitly test-only identity and trust bundle.
    pub fn new(
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        trusted_certificates_der: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            certificate_chain_der,
            private_key_der,
            trusted_certificates_der,
        }
    }
}

impl fmt::Debug for QuicSyntheticIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicSyntheticIdentity")
            .field("certificate_chain_der", &"<redacted>")
            .field("private_key_der", &"<redacted>")
            .field("trusted_certificates_der", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "quic-endpoint")]
const QUIC_FLOW_ALPN: &[u8] = b"crafter-flow";

/// Fully authenticated client configuration for the socket-free provider.
#[cfg(feature = "quic-endpoint")]
pub(crate) struct QuicEndpointClientTls {
    pub(crate) peer_name: String,
    pub(crate) endpoint: quinn_proto::EndpointConfig,
    pub(crate) client: quinn_proto::ClientConfig,
    pub(crate) limits: QuicTransportLimits,
}

#[cfg(feature = "quic-endpoint")]
impl fmt::Debug for QuicEndpointClientTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicEndpointClientTls")
            .field("peer_name", &self.peer_name)
            .field("limits", &self.limits)
            .field("trust_anchors", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "quic-endpoint")]
fn configuration_error(context: &'static str) -> FlowError {
    FlowError::QuicEndpoint {
        category: QuicEndpointErrorCategory::Configuration,
        context: context.to_string(),
    }
}

/// Builds a TLS-1.3-only QUIC client with explicit trust and bounded transport.
#[cfg(feature = "quic-endpoint")]
pub(crate) fn configure_endpoint_client_tls(
    peer: &QuicPeerConfig,
    identity: &QuicSyntheticIdentity,
    limits: QuicTransportLimits,
) -> Result<QuicEndpointClientTls> {
    use std::sync::Arc;

    use quinn_proto::{crypto::rustls::QuicClientConfig, IdleTimeout, TransportConfig, VarInt};
    use rustls::{client::Resumption, pki_types::CertificateDer, RootCertStore};

    if peer.server_name.is_empty()
        || rustls::pki_types::DnsName::try_from(peer.server_name.clone()).is_err()
    {
        return Err(configuration_error("validating authenticated peer name"));
    }
    if !peer.verify_peer {
        return Err(configuration_error("peer verification must remain enabled"));
    }
    if peer.enable_zero_rtt {
        return Err(configuration_error("0-RTT is not supported"));
    }
    if peer.alpn_protocols.as_slice() != [QUIC_FLOW_ALPN] {
        return Err(configuration_error("validating crafter-flow ALPN"));
    }
    if identity.trusted_certificates_der.is_empty() {
        return Err(configuration_error("loading non-empty trust anchors"));
    }
    if limits.max_idle_timeout.is_zero()
        || limits.max_idle_timeout > Duration::from_secs(60)
        || !(1_200..=1_472).contains(&limits.max_udp_payload_size)
        || limits.max_bidirectional_streams > 1
        || limits.max_stream_bytes == 0
        || limits.max_stream_bytes > 64 * 1024
        || limits.max_connection_bytes < limits.max_stream_bytes
        || limits.max_connection_bytes > 128 * 1024
    {
        return Err(configuration_error("validating bounded transport limits"));
    }

    let mut roots = RootCertStore::empty();
    for certificate in &identity.trusted_certificates_der {
        roots
            .add(CertificateDer::from(certificate.clone()))
            .map_err(|error| {
                provider_error(
                    QuicEndpointErrorCategory::Configuration,
                    "loading trust anchor",
                    error,
                )
            })?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| {
            provider_error(
                QuicEndpointErrorCategory::Configuration,
                "selecting TLS 1.3",
                error,
            )
        })?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![QUIC_FLOW_ALPN.to_vec()];
    tls.enable_early_data = false;
    tls.resumption = Resumption::disabled();

    let crypto = QuicClientConfig::try_from(tls).map_err(|error| {
        provider_error(
            QuicEndpointErrorCategory::Configuration,
            "configuring QUIC client crypto",
            error,
        )
    })?;
    let mut transport = TransportConfig::default();
    let idle_timeout = IdleTimeout::try_from(limits.max_idle_timeout).map_err(|error| {
        provider_error(
            QuicEndpointErrorCategory::Configuration,
            "configuring idle timeout",
            error,
        )
    })?;
    let bidirectional_streams =
        VarInt::from_u64(limits.max_bidirectional_streams).map_err(|error| {
            provider_error(
                QuicEndpointErrorCategory::Configuration,
                "configuring bidirectional stream limit",
                error,
            )
        })?;
    let stream_window = VarInt::from_u64(limits.max_stream_bytes).map_err(|error| {
        provider_error(
            QuicEndpointErrorCategory::Configuration,
            "configuring stream receive window",
            error,
        )
    })?;
    let connection_window = VarInt::from_u64(limits.max_connection_bytes).map_err(|error| {
        provider_error(
            QuicEndpointErrorCategory::Configuration,
            "configuring connection receive window",
            error,
        )
    })?;
    transport
        .max_idle_timeout(Some(idle_timeout))
        .max_concurrent_bidi_streams(bidirectional_streams)
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(stream_window)
        .receive_window(connection_window)
        .send_window(limits.max_connection_bytes)
        .initial_mtu(limits.max_udp_payload_size)
        .min_mtu(1_200)
        .mtu_discovery_config(None)
        .datagram_receive_buffer_size(None)
        .datagram_send_buffer_size(0)
        .enable_segmentation_offload(false);

    let mut client = quinn_proto::ClientConfig::new(Arc::new(crypto));
    client.transport_config(Arc::new(transport)).version(1);
    let mut endpoint = quinn_proto::EndpointConfig::default();
    endpoint
        .max_udp_payload_size(limits.max_udp_payload_size)
        .map_err(|error| {
            provider_error(
                QuicEndpointErrorCategory::Configuration,
                "configuring maximum UDP payload",
                error,
            )
        })?;

    Ok(QuicEndpointClientTls {
        peer_name: peer.server_name.clone(),
        endpoint,
        client,
        limits,
    })
}

/// Stable, provider-independent endpoint failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicEndpointErrorCategory {
    /// Endpoint or TLS configuration could not be constructed.
    Configuration,
    /// TLS peer authentication failed.
    TlsAuthentication,
    /// Peer or local transport parameters violated the bounded contract.
    TransportParameters,
    /// A UDP datagram or its address metadata was invalid.
    DatagramIngress,
    /// Protocol timeout scheduling or handling failed.
    TimeoutHandling,
    /// The single-stream lifecycle was invalid.
    StreamState,
    /// The endpoint provider failed outside a more specific category.
    ProviderInternal,
}

impl fmt::Display for QuicEndpointErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configuration => "configuration",
            Self::TlsAuthentication => "tls authentication",
            Self::TransportParameters => "transport parameters",
            Self::DatagramIngress => "datagram ingress",
            Self::TimeoutHandling => "timeout handling",
            Self::StreamState => "stream state",
            Self::ProviderInternal => "provider internal",
        })
    }
}

/// Maps a provider failure while deliberately discarding its potentially secret text.
///
/// `context` must describe the flow operation, not provider-controlled input. The
/// provider error is accepted only to make accidental stringification at call sites
/// less likely.
#[allow(dead_code)] // Used by the private driver introduced in later plan steps.
pub(crate) fn provider_error<E>(
    category: QuicEndpointErrorCategory,
    context: &'static str,
    _provider_error: E,
) -> FlowError {
    FlowError::QuicEndpoint {
        category,
        context: context.to_string(),
    }
}

/// One opaque UDP datagram delivered to a socket-free QUIC endpoint.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuicEndpointDatagram {
    pub(crate) timestamp: Instant,
    pub(crate) local_ip: Ipv4Addr,
    pub(crate) local_port: u16,
    pub(crate) remote_ip: Ipv4Addr,
    pub(crate) remote_port: u16,
    pub(crate) payload: Vec<u8>,
}

/// One provider-generated UDP datagram, retained in provider output order.
///
/// Protected QUIC output is always regeneration-only. The flow runner must ask
/// the driver to generate fresh output after loss rather than replaying these bytes.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuicEndpointTransmit {
    pub(crate) source_ip: Ipv4Addr,
    pub(crate) source_port: u16,
    pub(crate) destination_ip: Ipv4Addr,
    pub(crate) destination_port: u16,
    pub(crate) payload: Vec<u8>,
}

#[cfg(feature = "quic-endpoint")]
impl QuicEndpointTransmit {
    pub(crate) const fn send_intent(&self) -> SendIntent {
        SendIntent::ReplyExpectedRegenerationOnly
    }
}

/// Provider-independent identifier for the one bounded application stream.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct QuicEndpointStreamId(pub(crate) u64);

/// Bytes read from one stream together with its final-size observation.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuicEndpointStreamRead {
    pub(crate) bytes: Vec<u8>,
    pub(crate) finished: bool,
}

/// Inspectable lifecycle labels shared by endpoint adapters and full flows.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuicEndpointLifecycle {
    Starting,
    Handshaking,
    Established,
    Closing,
    Draining,
    Closed,
    Failed,
}

/// A stable, non-secret endpoint event.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QuicEndpointEvent {
    HandshakeProgress,
    Established,
    StreamReadable(QuicEndpointStreamId),
    StreamWritable(QuicEndpointStreamId),
    StreamFinished(QuicEndpointStreamId),
    PeerClose {
        code: u64,
    },
    LocalClose {
        code: u64,
    },
    Draining,
    IdleTimeout,
    FatalError {
        category: QuicEndpointErrorCategory,
        context: &'static str,
    },
}

/// Packet observations for one QUIC packet-number space.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct QuicEndpointPacketSpaceCounts {
    pub(crate) sent: u64,
    pub(crate) received: u64,
    pub(crate) acknowledged: u64,
    pub(crate) lost: u64,
}

/// Recovery observations retained without provider-internal state.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct QuicEndpointRecoveryCounts {
    pub(crate) timeout_events: u64,
    pub(crate) pto_firings: u64,
    pub(crate) packets_declared_lost: u64,
    pub(crate) regenerated_transmits: u64,
}

/// Non-secret state that full flows may copy into context and reports.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuicEndpointSnapshot {
    pub(crate) lifecycle: QuicEndpointLifecycle,
    pub(crate) local_connection_id: Vec<u8>,
    pub(crate) peer_connection_id: Vec<u8>,
    pub(crate) initial: QuicEndpointPacketSpaceCounts,
    pub(crate) handshake: QuicEndpointPacketSpaceCounts,
    pub(crate) application: QuicEndpointPacketSpaceCounts,
    pub(crate) stream_bytes_sent: u64,
    pub(crate) stream_bytes_received: u64,
    pub(crate) recovery: QuicEndpointRecoveryCounts,
}

/// Socket-free boundary around the selected QUIC protocol provider.
///
/// Implementations own TLS, packet-number, recovery, congestion, and stream
/// state. They receive opaque UDP payloads and return ordered UDP payloads; all
/// socket I/O and typed packet wrapping remain owned by the flow engine.
#[cfg(feature = "quic-endpoint")]
pub(crate) trait QuicEndpointDriver {
    fn start(&mut self, now: Instant) -> Result<()>;
    fn handle_datagram(&mut self, datagram: QuicEndpointDatagram) -> Result<()>;
    fn drain_transmits(&mut self) -> Result<Vec<QuicEndpointTransmit>>;
    fn next_timeout(&self) -> Option<Instant>;
    fn handle_timeout(&mut self, now: Instant) -> Result<()>;
    fn poll_events(&mut self) -> Result<Vec<QuicEndpointEvent>>;
    fn open_bidirectional_stream(&mut self) -> Result<QuicEndpointStreamId>;
    fn write_stream(&mut self, stream: QuicEndpointStreamId, bytes: &[u8]) -> Result<usize>;
    fn finish_stream(&mut self, stream: QuicEndpointStreamId) -> Result<()>;
    fn read_stream(
        &mut self,
        stream: QuicEndpointStreamId,
        max_bytes: usize,
    ) -> Result<QuicEndpointStreamRead>;
    fn snapshot(&self) -> QuicEndpointSnapshot;
    fn close(&mut self, now: Instant, code: u64, reason: &[u8]) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::{provider_error, QuicEndpointErrorCategory as Category, QuicSyntheticIdentity};

    #[test]
    fn endpoint_error_categories_are_stable() {
        let expected = [
            (Category::Configuration, "configuration"),
            (Category::TlsAuthentication, "tls authentication"),
            (Category::TransportParameters, "transport parameters"),
            (Category::DatagramIngress, "datagram ingress"),
            (Category::TimeoutHandling, "timeout handling"),
            (Category::StreamState, "stream state"),
            (Category::ProviderInternal, "provider internal"),
        ];

        for (category, label) in expected {
            let error = provider_error(category, "creating endpoint", "provider detail");
            assert_eq!(category.to_string(), label);
            assert_eq!(
                error.to_string(),
                format!("QUIC endpoint {label} error: creating endpoint")
            );
        }
    }

    #[test]
    fn endpoint_errors_redact_secret_material() {
        const PRIVATE_KEY: &str = "private-key-secret";
        const TRAFFIC_SECRET: &str = "traffic-secret";
        const SESSION_TICKET: &str = "session-ticket-secret";
        const CERTIFICATE: &str = "full-certificate-secret";

        let identity = QuicSyntheticIdentity::new(
            vec![CERTIFICATE.as_bytes().to_vec()],
            PRIVATE_KEY.as_bytes().to_vec(),
            vec![CERTIFICATE.as_bytes().to_vec()],
        );
        let provider_detail = format!(
            "key={PRIVATE_KEY} traffic={TRAFFIC_SECRET} ticket={SESSION_TICKET} cert={CERTIFICATE}"
        );
        let error = provider_error(
            Category::TlsAuthentication,
            "authenticating configured peer",
            provider_detail,
        );
        let rendered = format!("{identity:?}\n{identity:#?}\n{error:?}\n{error}");

        for secret in [PRIVATE_KEY, TRAFFIC_SECRET, SESSION_TICKET, CERTIFICATE] {
            assert!(!rendered.contains(secret));
        }
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("authenticating configured peer"));
    }

    #[cfg(feature = "quic-endpoint")]
    #[test]
    fn enabled_provider_errors_use_the_same_redacted_mapping() {
        let provider_error_value = quinn_proto::ConnectError::InvalidServerName("secret".into());
        let error = provider_error(
            Category::Configuration,
            "configuring peer name",
            provider_error_value,
        );
        assert_eq!(
            error.to_string(),
            "QUIC endpoint configuration error: configuring peer name"
        );
        assert!(!format!("{error:?}").contains("secret"));
    }

    #[cfg(feature = "quic-endpoint")]
    #[test]
    fn client_tls_requires_authenticated_peer() {
        use super::{
            configure_endpoint_client_tls, QuicPeerConfig, QuicTransportLimits, QUIC_FLOW_ALPN,
        };
        use crate::FlowError;

        fn decode_hex(input: &str) -> Vec<u8> {
            let bytes = input.trim().as_bytes();
            assert_eq!(bytes.len() % 2, 0);
            bytes
                .chunks_exact(2)
                .map(|pair| {
                    let text = std::str::from_utf8(pair).unwrap();
                    u8::from_str_radix(text, 16).unwrap()
                })
                .collect()
        }

        fn assert_configuration_error(result: crate::Result<super::QuicEndpointClientTls>) {
            assert!(matches!(
                result,
                Err(FlowError::QuicEndpoint {
                    category: Category::Configuration,
                    ..
                })
            ));
        }

        let certificate = decode_hex(include_str!(
            "../tests/fixtures/quic/quic.example.cert.der.hex"
        ));
        let identity =
            QuicSyntheticIdentity::new(Vec::new(), Vec::new(), vec![certificate.clone()]);
        let peer = QuicPeerConfig::new("quic.example", [QUIC_FLOW_ALPN.to_vec()]);
        let configured =
            configure_endpoint_client_tls(&peer, &identity, QuicTransportLimits::default())
                .unwrap();

        assert_eq!(configured.peer_name, "quic.example");
        assert_eq!(configured.limits, QuicTransportLimits::default());
        assert_eq!(configured.endpoint.get_max_udp_payload_size(), 1_472);
        let _provider_client = &configured.client;
        let rendered = format!("{configured:?}");
        assert!(rendered.contains("quic.example"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("3082019c"));

        let empty_name = QuicPeerConfig::new("", [QUIC_FLOW_ALPN.to_vec()]);
        assert_configuration_error(configure_endpoint_client_tls(
            &empty_name,
            &identity,
            QuicTransportLimits::default(),
        ));
        let wrong_alpn = QuicPeerConfig::new("quic.example", [b"h3".to_vec()]);
        assert_configuration_error(configure_endpoint_client_tls(
            &wrong_alpn,
            &identity,
            QuicTransportLimits::default(),
        ));
        assert_configuration_error(configure_endpoint_client_tls(
            &peer.clone().with_peer_verification(false),
            &identity,
            QuicTransportLimits::default(),
        ));
        assert_configuration_error(configure_endpoint_client_tls(
            &peer.clone().with_zero_rtt(true),
            &identity,
            QuicTransportLimits::default(),
        ));
        let empty_trust = QuicSyntheticIdentity::new(Vec::new(), Vec::new(), Vec::new());
        assert_configuration_error(configure_endpoint_client_tls(
            &peer,
            &empty_trust,
            QuicTransportLimits::default(),
        ));
        let malformed_trust =
            QuicSyntheticIdentity::new(Vec::new(), Vec::new(), vec![b"not DER".to_vec()]);
        assert_configuration_error(configure_endpoint_client_tls(
            &peer,
            &malformed_trust,
            QuicTransportLimits::default(),
        ));
    }

    #[cfg(feature = "quic-endpoint")]
    #[test]
    fn driver_contract_is_socket_free_and_inspectable() {
        use std::{collections::VecDeque, net::Ipv4Addr, time::Instant};

        use super::{
            QuicEndpointDatagram, QuicEndpointDriver, QuicEndpointEvent, QuicEndpointLifecycle,
            QuicEndpointPacketSpaceCounts, QuicEndpointRecoveryCounts, QuicEndpointSnapshot,
            QuicEndpointStreamId, QuicEndpointStreamRead, QuicEndpointTransmit,
        };
        use crate::{step::SendIntent, Result};

        struct MemoryDriver {
            now: Option<Instant>,
            transmits: Vec<QuicEndpointTransmit>,
            events: VecDeque<QuicEndpointEvent>,
            snapshot: QuicEndpointSnapshot,
        }

        impl QuicEndpointDriver for MemoryDriver {
            fn start(&mut self, now: Instant) -> Result<()> {
                self.now = Some(now);
                self.snapshot.lifecycle = QuicEndpointLifecycle::Handshaking;
                self.events.push_back(QuicEndpointEvent::HandshakeProgress);
                Ok(())
            }

            fn handle_datagram(&mut self, datagram: QuicEndpointDatagram) -> Result<()> {
                self.now = Some(datagram.timestamp);
                self.snapshot.stream_bytes_received += datagram.payload.len() as u64;
                self.transmits.push(QuicEndpointTransmit {
                    source_ip: datagram.local_ip,
                    source_port: datagram.local_port,
                    destination_ip: datagram.remote_ip,
                    destination_port: datagram.remote_port,
                    payload: datagram.payload,
                });
                Ok(())
            }

            fn drain_transmits(&mut self) -> Result<Vec<QuicEndpointTransmit>> {
                Ok(std::mem::take(&mut self.transmits))
            }

            fn next_timeout(&self) -> Option<Instant> {
                self.now
            }

            fn handle_timeout(&mut self, now: Instant) -> Result<()> {
                self.now = Some(now);
                self.snapshot.recovery.timeout_events += 1;
                Ok(())
            }

            fn poll_events(&mut self) -> Result<Vec<QuicEndpointEvent>> {
                Ok(self.events.drain(..).collect())
            }

            fn open_bidirectional_stream(&mut self) -> Result<QuicEndpointStreamId> {
                Ok(QuicEndpointStreamId(0))
            }

            fn write_stream(&mut self, _: QuicEndpointStreamId, bytes: &[u8]) -> Result<usize> {
                self.snapshot.stream_bytes_sent += bytes.len() as u64;
                Ok(bytes.len())
            }

            fn finish_stream(&mut self, stream: QuicEndpointStreamId) -> Result<()> {
                self.events
                    .push_back(QuicEndpointEvent::StreamFinished(stream));
                Ok(())
            }

            fn read_stream(
                &mut self,
                _: QuicEndpointStreamId,
                max_bytes: usize,
            ) -> Result<QuicEndpointStreamRead> {
                Ok(QuicEndpointStreamRead {
                    bytes: b"response"[..max_bytes.min(8)].to_vec(),
                    finished: true,
                })
            }

            fn snapshot(&self) -> QuicEndpointSnapshot {
                self.snapshot.clone()
            }

            fn close(&mut self, now: Instant, code: u64, _: &[u8]) -> Result<()> {
                self.now = Some(now);
                self.snapshot.lifecycle = QuicEndpointLifecycle::Closing;
                self.events
                    .push_back(QuicEndpointEvent::LocalClose { code });
                Ok(())
            }
        }

        let now = Instant::now();
        let mut driver = MemoryDriver {
            now: None,
            transmits: Vec::new(),
            events: VecDeque::new(),
            snapshot: QuicEndpointSnapshot {
                lifecycle: QuicEndpointLifecycle::Starting,
                local_connection_id: vec![0x11; 8],
                peer_connection_id: vec![0x22; 8],
                initial: QuicEndpointPacketSpaceCounts::default(),
                handshake: QuicEndpointPacketSpaceCounts::default(),
                application: QuicEndpointPacketSpaceCounts::default(),
                stream_bytes_sent: 0,
                stream_bytes_received: 0,
                recovery: QuicEndpointRecoveryCounts::default(),
            },
        };

        driver.start(now).unwrap();
        driver
            .handle_datagram(QuicEndpointDatagram {
                timestamp: now,
                local_ip: Ipv4Addr::new(192, 0, 2, 10),
                local_port: 4433,
                remote_ip: Ipv4Addr::new(198, 51, 100, 20),
                remote_port: 54321,
                payload: vec![0xc0, 0, 0, 0, 1],
            })
            .unwrap();
        let output = driver.drain_transmits().unwrap();
        assert_eq!(output.len(), 1);
        assert_eq!(
            output[0].send_intent(),
            SendIntent::ReplyExpectedRegenerationOnly
        );
        assert_eq!(output[0].source_ip, Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(output[0].destination_port, 54321);

        let stream = driver.open_bidirectional_stream().unwrap();
        assert_eq!(driver.write_stream(stream, b"request").unwrap(), 7);
        driver.finish_stream(stream).unwrap();
        assert_eq!(driver.read_stream(stream, 8).unwrap().bytes, b"response");
        driver.handle_timeout(now).unwrap();
        assert_eq!(driver.next_timeout(), Some(now));
        assert!(driver
            .poll_events()
            .unwrap()
            .contains(&QuicEndpointEvent::HandshakeProgress));
        driver.close(now, 0, b"done").unwrap();

        let snapshot = driver.snapshot();
        assert_eq!(snapshot.lifecycle, QuicEndpointLifecycle::Closing);
        assert_eq!(snapshot.local_connection_id, vec![0x11; 8]);
        assert_eq!(snapshot.peer_connection_id, vec![0x22; 8]);
        assert_eq!(snapshot.stream_bytes_sent, 7);
        assert_eq!(snapshot.stream_bytes_received, 5);
        assert_eq!(snapshot.recovery.timeout_events, 1);
    }
}
