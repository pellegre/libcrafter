//! Provider-neutral configuration for the private QUIC endpoint driver.

use std::{fmt, net::SocketAddr, time::Duration};

#[cfg(feature = "quic-endpoint")]
use std::{net::Ipv4Addr, time::Instant};

use crate::FlowError;
#[cfg(feature = "quic-endpoint")]
use crate::{
    quic_wire::{wrap_opaque_quic_udp_datagram, QuicCaptureRepresentation, QuicIngress},
    step::{SendIntent, Step},
    PacketContext, Result,
};

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

/// Server-side protocol policy for the bounded endpoint flow.
///
/// Setters intentionally allow unsupported values to be represented so flow
/// construction can reject them with a stable, redacted configuration error.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuicEndpointServerPolicy {
    alpn_protocols: Vec<Vec<u8>>,
    enable_zero_rtt: bool,
    enable_datagrams: bool,
    enable_migration: bool,
    server_initiated_bidirectional_streams: u64,
}

#[cfg(feature = "quic-endpoint")]
impl Default for QuicEndpointServerPolicy {
    fn default() -> Self {
        Self {
            alpn_protocols: vec![QUIC_FLOW_ALPN.to_vec()],
            enable_zero_rtt: false,
            enable_datagrams: false,
            enable_migration: false,
            server_initiated_bidirectional_streams: 0,
        }
    }
}

#[cfg(feature = "quic-endpoint")]
impl QuicEndpointServerPolicy {
    #[cfg(test)]
    fn with_alpn_protocols(mut self, protocols: impl IntoIterator<Item = Vec<u8>>) -> Self {
        self.alpn_protocols = protocols.into_iter().collect();
        self
    }

    #[cfg(test)]
    fn with_zero_rtt(mut self, enabled: bool) -> Self {
        self.enable_zero_rtt = enabled;
        self
    }

    #[cfg(test)]
    fn with_datagrams(mut self, enabled: bool) -> Self {
        self.enable_datagrams = enabled;
        self
    }

    #[cfg(test)]
    fn with_migration(mut self, enabled: bool) -> Self {
        self.enable_migration = enabled;
        self
    }

    #[cfg(test)]
    fn with_server_initiated_bidirectional_streams(mut self, streams: u64) -> Self {
        self.server_initiated_bidirectional_streams = streams;
        self
    }
}

#[cfg(feature = "quic-endpoint")]
const QUIC_FLOW_ALPN: &[u8] = b"crafter-flow";

/// Monotonic time source used by the socket-free endpoint adapter.
///
/// The flow runner samples the clock once for an endpoint operation and passes
/// that instant through to the provider. This keeps a complete provider action
/// on one explicit time line and lets offline harnesses substitute deterministic
/// time without changing the process clock.
#[cfg(feature = "quic-endpoint")]
pub(crate) trait QuicEndpointClock {
    fn now(&self) -> Instant;

    fn wakeup_after(&self, deadline: Instant) -> Duration {
        deadline
            .checked_duration_since(self.now())
            .unwrap_or(Duration::ZERO)
    }
}

/// Production monotonic clock. Reading it has no wall-clock or system-time side
/// effects.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct QuicEndpointSystemClock;

#[cfg(feature = "quic-endpoint")]
impl QuicEndpointClock for QuicEndpointSystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Deterministic monotonic clock for tests and the in-memory duplex harness.
#[cfg(all(feature = "quic-endpoint", test))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct QuicEndpointManualClock {
    now: Instant,
}

#[cfg(all(feature = "quic-endpoint", test))]
impl QuicEndpointManualClock {
    pub(crate) const fn new(now: Instant) -> Self {
        Self { now }
    }

    pub(crate) fn advance(&mut self, duration: Duration) -> Instant {
        self.now = saturating_instant_add(self.now, duration);
        self.now
    }

    pub(crate) fn advance_to(&mut self, now: Instant) -> Result<()> {
        if now < self.now {
            return Err(FlowError::QuicEndpoint {
                category: QuicEndpointErrorCategory::TimeoutHandling,
                context: "advancing deterministic endpoint clock".to_string(),
            });
        }
        self.now = now;
        Ok(())
    }
}

#[cfg(all(feature = "quic-endpoint", test))]
impl QuicEndpointClock for QuicEndpointManualClock {
    fn now(&self) -> Instant {
        self.now
    }
}

/// Adds a duration without allowing platform-specific `Instant` overflow to
/// panic. If the requested duration is not representable, return the latest
/// representable instant at or before it.
#[cfg(all(feature = "quic-endpoint", test))]
fn saturating_instant_add(base: Instant, duration: Duration) -> Instant {
    if let Some(instant) = base.checked_add(duration) {
        return instant;
    }

    let requested = duration.as_nanos();
    let mut low = 0_u128;
    let mut high = requested;
    while low < high {
        let middle = low + (high - low + 1) / 2;
        if base.checked_add(duration_from_nanos(middle)).is_some() {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    base.checked_add(duration_from_nanos(low)).unwrap_or(base)
}

#[cfg(all(feature = "quic-endpoint", test))]
fn duration_from_nanos(nanos: u128) -> Duration {
    let seconds = (nanos / 1_000_000_000) as u64;
    let subsecond_nanos = (nanos % 1_000_000_000) as u32;
    Duration::new(seconds, subsecond_nanos)
}

/// Fully authenticated client configuration for the socket-free provider.
#[cfg(feature = "quic-endpoint")]
pub(crate) struct QuicEndpointClientTls {
    pub(crate) peer_name: String,
    pub(crate) endpoint: quinn_proto::EndpointConfig,
    pub(crate) client: quinn_proto::ClientConfig,
    pub(crate) limits: QuicTransportLimits,
}

/// TLS and transport configuration for the socket-free server provider.
#[cfg(feature = "quic-endpoint")]
pub(crate) struct QuicEndpointServerTls {
    pub(crate) endpoint: quinn_proto::EndpointConfig,
    pub(crate) server: quinn_proto::ServerConfig,
    pub(crate) limits: QuicTransportLimits,
}

#[cfg(feature = "quic-endpoint")]
impl fmt::Debug for QuicEndpointServerTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicEndpointServerTls")
            .field("limits", &self.limits)
            .field("alpn", &"crafter-flow")
            .field("identity", &"<redacted>")
            .field("zero_rtt", &false)
            .field("datagrams", &false)
            .field("migration", &false)
            .field("server_initiated_streams", &0)
            .finish_non_exhaustive()
    }
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

/// Builds a TLS-1.3-only QUIC server with explicit identity and bounded transport.
#[cfg(feature = "quic-endpoint")]
pub(crate) fn configure_endpoint_server_tls(
    policy: &QuicEndpointServerPolicy,
    identity: &QuicSyntheticIdentity,
    limits: QuicTransportLimits,
) -> Result<QuicEndpointServerTls> {
    use std::sync::Arc;

    use quinn_proto::{crypto::rustls::QuicServerConfig, IdleTimeout, TransportConfig, VarInt};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    if policy.alpn_protocols.as_slice() != [QUIC_FLOW_ALPN] {
        return Err(configuration_error("validating crafter-flow ALPN"));
    }
    if policy.enable_zero_rtt {
        return Err(configuration_error("0-RTT is not supported"));
    }
    if policy.enable_datagrams {
        return Err(configuration_error(
            "application datagrams are not supported",
        ));
    }
    if policy.enable_migration {
        return Err(configuration_error("connection migration is not supported"));
    }
    if policy.server_initiated_bidirectional_streams != 0 {
        return Err(configuration_error(
            "server-initiated application streams are not supported",
        ));
    }
    if identity.certificate_chain_der.is_empty() || identity.private_key_der.is_empty() {
        return Err(configuration_error("loading non-empty server identity"));
    }
    if limits.max_idle_timeout.is_zero()
        || limits.max_idle_timeout > Duration::from_secs(60)
        || !(1_200..=1_472).contains(&limits.max_udp_payload_size)
        || limits.max_bidirectional_streams != 1
        || limits.max_stream_bytes == 0
        || limits.max_stream_bytes > 64 * 1024
        || limits.max_connection_bytes < limits.max_stream_bytes
        || limits.max_connection_bytes > 128 * 1024
    {
        return Err(configuration_error("validating bounded transport limits"));
    }

    let certificates = identity
        .certificate_chain_der
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    let private_key =
        PrivateKeyDer::try_from(identity.private_key_der.clone()).map_err(|error| {
            provider_error(
                QuicEndpointErrorCategory::Configuration,
                "loading server private key",
                error,
            )
        })?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| {
            provider_error(
                QuicEndpointErrorCategory::Configuration,
                "selecting TLS 1.3",
                error,
            )
        })?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|error| {
            provider_error(
                QuicEndpointErrorCategory::Configuration,
                "loading server identity",
                error,
            )
        })?;
    tls.alpn_protocols = vec![QUIC_FLOW_ALPN.to_vec()];
    tls.max_early_data_size = 0;

    let crypto = QuicServerConfig::try_from(tls).map_err(|error| {
        provider_error(
            QuicEndpointErrorCategory::Configuration,
            "configuring QUIC server crypto",
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
        .max_concurrent_bidi_streams(VarInt::from_u32(1))
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

    let mut server = quinn_proto::ServerConfig::with_crypto(Arc::new(crypto));
    server
        .transport_config(Arc::new(transport))
        .migration(false)
        .max_incoming(1);
    let mut endpoint = quinn_proto::EndpointConfig::default();
    endpoint
        .supported_versions(vec![1])
        .max_udp_payload_size(limits.max_udp_payload_size)
        .map_err(|error| {
            provider_error(
                QuicEndpointErrorCategory::Configuration,
                "configuring maximum UDP payload",
                error,
            )
        })?;

    Ok(QuicEndpointServerTls {
        endpoint,
        server,
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

/// Result of validating a captured datagram at the endpoint boundary.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuicEndpointIngressDisposition {
    /// The opaque UDP payload was delivered to the connection-aware provider.
    Accepted(QuicCaptureRepresentation),
    /// The datagram belonged to another path and was not shown to the provider.
    IgnoredStrayTuple,
}

#[cfg(feature = "quic-endpoint")]
impl QuicEndpointDatagram {
    fn from_ingress(
        ingress: &QuicIngress,
        addresses: QuicEndpointAddresses,
        max_udp_payload_size: u16,
        now: Instant,
    ) -> Result<Option<Self>> {
        let (SocketAddr::V4(expected_local), SocketAddr::V4(expected_peer)) =
            (addresses.local, addresses.peer)
        else {
            return Err(configuration_error("validating IPv4 QUIC endpoint path"));
        };

        if ingress.local() != expected_local || ingress.peer() != expected_peer {
            return Ok(None);
        }
        if ingress.payload().is_empty() {
            return Err(provider_error(
                QuicEndpointErrorCategory::DatagramIngress,
                "rejecting empty QUIC UDP payload",
                (),
            ));
        }
        if ingress.payload().len() > usize::from(max_udp_payload_size) {
            return Err(provider_error(
                QuicEndpointErrorCategory::DatagramIngress,
                "rejecting oversized QUIC UDP payload",
                (),
            ));
        }

        Ok(Some(Self {
            timestamp: now,
            local_ip: *expected_local.ip(),
            local_port: expected_local.port(),
            remote_ip: *expected_peer.ip(),
            remote_port: expected_peer.port(),
            payload: ingress.payload().to_vec(),
        }))
    }
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
    /// Provider-observed packets in each packet-number space carried by this
    /// datagram. These counts are metadata; protected bytes are never copied
    /// into flow context.
    pub(crate) packet_counts: QuicEndpointTransmitPacketCounts,
}

#[cfg(feature = "quic-endpoint")]
impl QuicEndpointTransmit {
    pub(crate) const fn send_intent(&self) -> SendIntent {
        SendIntent::ReplyExpectedRegenerationOnly
    }
}

/// Non-secret packet-space metadata for one provider transmit.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct QuicEndpointTransmitPacketCounts {
    pub(crate) initial: u64,
    pub(crate) handshake: u64,
    pub(crate) application: u64,
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

/// Provider-owned classification for the next endpoint deadline.
///
/// The flow engine uses this only for inspectable observations. It never
/// derives PTO or idle deadlines itself; the endpoint provider remains the
/// authority for both scheduling and recovery behavior.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuicEndpointTimeoutKind {
    /// Bookkeeping such as delayed acknowledgement or key lifecycle work.
    Maintenance,
    /// A provider loss-recovery probe timeout.
    ProbeTimeout,
    /// The provider's authenticated idle timer.
    IdleTimeout,
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
    fn handle_ingress(
        &mut self,
        ingress: &QuicIngress,
        addresses: QuicEndpointAddresses,
        max_udp_payload_size: u16,
        now: Instant,
    ) -> Result<QuicEndpointIngressDisposition> {
        let representation = ingress.representation();
        let Some(datagram) =
            QuicEndpointDatagram::from_ingress(ingress, addresses, max_udp_payload_size, now)?
        else {
            return Ok(QuicEndpointIngressDisposition::IgnoredStrayTuple);
        };
        self.handle_datagram(datagram)?;
        Ok(QuicEndpointIngressDisposition::Accepted(representation))
    }
    fn drain_transmits(&mut self, now: Instant) -> Result<Vec<QuicEndpointTransmit>>;
    fn drain_transmit_step(
        &mut self,
        now: Instant,
        addresses: QuicEndpointAddresses,
        context: &mut PacketContext,
    ) -> Result<Step> {
        let (SocketAddr::V4(local), SocketAddr::V4(peer)) = (addresses.local, addresses.peer)
        else {
            return Err(configuration_error("wrapping IPv4 QUIC endpoint transmits"));
        };
        let transmits = self.drain_transmits(now)?;

        // Validate the complete provider batch before exposing any packet or
        // updating context, so a bad later transmit cannot leave partial facts.
        for transmit in &transmits {
            if transmit.source_ip != *local.ip()
                || transmit.source_port != local.port()
                || transmit.destination_ip != *peer.ip()
                || transmit.destination_port != peer.port()
                || transmit.payload.is_empty()
            {
                return Err(provider_error(
                    QuicEndpointErrorCategory::DatagramIngress,
                    "validating provider transmit metadata",
                    (),
                ));
            }
        }

        let mut initial = 0_u64;
        let mut handshake = 0_u64;
        let mut application = 0_u64;
        let packets = transmits
            .into_iter()
            .map(|transmit| {
                initial = initial.saturating_add(transmit.packet_counts.initial);
                handshake = handshake.saturating_add(transmit.packet_counts.handshake);
                application = application.saturating_add(transmit.packet_counts.application);
                wrap_opaque_quic_udp_datagram(local, peer, transmit.payload)
            })
            .collect::<Vec<_>>();

        increment_quic_counter(context, "datagrams.sent", packets.len() as u64)?;
        increment_quic_counter(context, "packets.initial.sent", initial)?;
        increment_quic_counter(context, "packets.handshake.sent", handshake)?;
        increment_quic_counter(context, "packets.application.sent", application)?;

        let mut step = if packets.is_empty() {
            Step::stay()
        } else {
            Step::send_regeneration_only_batch(packets)
        };
        if let Some(wakeup) = self.next_wakeup(now) {
            step = step.wake_after(wakeup);
        }
        Ok(step)
    }
    fn next_timeout(&self) -> Option<Instant>;
    fn next_timeout_kind(&self) -> QuicEndpointTimeoutKind {
        QuicEndpointTimeoutKind::Maintenance
    }
    fn next_wakeup(&self, now: Instant) -> Option<Duration> {
        self.next_timeout().map(|deadline| {
            deadline
                .checked_duration_since(now)
                .unwrap_or(Duration::ZERO)
        })
    }
    fn handle_timeout(&mut self, now: Instant) -> Result<()>;
    fn handle_timeout_step(
        &mut self,
        now: Instant,
        addresses: QuicEndpointAddresses,
        context: &mut PacketContext,
    ) -> Result<Step> {
        // Classify the deadline before firing it: handling the callback may
        // replace the provider's next deadline with a different timer kind.
        let timeout_kind = self.next_timeout_kind();
        self.handle_timeout(now)?;

        increment_quic_counter(context, "recovery.timeout_events", 1)?;
        match timeout_kind {
            QuicEndpointTimeoutKind::Maintenance => {
                increment_quic_counter(context, "timeouts.maintenance", 1)?;
            }
            QuicEndpointTimeoutKind::ProbeTimeout => {
                increment_quic_counter(context, "recovery.pto_firings", 1)?;
            }
            QuicEndpointTimeoutKind::IdleTimeout => {
                increment_quic_counter(context, "timeouts.idle", 1)?;
            }
        }

        // Provider output is drained only after the callback, so every packet
        // is freshly protected and is marked regeneration-only by the shared
        // transmit wrapper. An empty batch remains an inspectable timer-
        // maintenance step and still carries the provider's next wakeup.
        self.drain_transmit_step(now, addresses, context)
    }
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

#[cfg(feature = "quic-endpoint")]
fn increment_quic_counter(context: &mut PacketContext, key: &str, count: u64) -> Result<()> {
    let current = context.get_namespaced_u64("quic", key)?.unwrap_or(0);
    context.insert_namespaced_u64("quic", key, current.saturating_add(count))
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
    fn server_tls_is_bounded_and_redacts_identity() {
        use super::{
            configure_endpoint_server_tls, QuicEndpointServerPolicy, QuicEndpointServerTls,
            QuicTransportLimits,
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

        fn assert_configuration_error(result: crate::Result<QuicEndpointServerTls>) {
            let error = result.unwrap_err();
            assert!(matches!(
                error,
                FlowError::QuicEndpoint {
                    category: Category::Configuration,
                    ..
                }
            ));
            let rendered = format!("{error:?}\n{error}");
            assert!(!rendered.contains("3082019c"));
            assert!(!rendered.contains("30818702"));
        }

        const PRIVATE_KEY_HEX: &str = concat!(
            "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420",
            "4a1c7377037c53181de9d3ef2c3bb7364ae1f4fa48164e85b06c919b67b803dba144",
            "03420004c8634a405397699a827e0f5af382c6b53023f9b0c79a322cc96dbf366a9b943",
            "a0a4a74aed42c0321e76f7881fa1ae5d8b064cf696e6b918cfade1f4dbcbad3d0",
        );
        let certificate = decode_hex(include_str!(
            "../tests/fixtures/quic/quic.example.cert.der.hex"
        ));
        let private_key = decode_hex(PRIVATE_KEY_HEX);
        let identity =
            QuicSyntheticIdentity::new(vec![certificate.clone()], private_key.clone(), Vec::new());
        let policy = QuicEndpointServerPolicy::default();
        let configured =
            configure_endpoint_server_tls(&policy, &identity, QuicTransportLimits::default())
                .unwrap();

        assert_eq!(configured.limits, QuicTransportLimits::default());
        assert_eq!(configured.endpoint.get_max_udp_payload_size(), 1_472);
        let _provider_server = &configured.server;
        let rendered = format!("{identity:?}\n{configured:?}");
        assert!(rendered.contains("crafter-flow"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("3082019c"));
        assert!(!rendered.contains("30818702"));

        assert_configuration_error(configure_endpoint_server_tls(
            &policy.clone().with_alpn_protocols([b"h3".to_vec()]),
            &identity,
            QuicTransportLimits::default(),
        ));
        assert_configuration_error(configure_endpoint_server_tls(
            &policy.clone().with_zero_rtt(true),
            &identity,
            QuicTransportLimits::default(),
        ));
        assert_configuration_error(configure_endpoint_server_tls(
            &policy.clone().with_datagrams(true),
            &identity,
            QuicTransportLimits::default(),
        ));
        assert_configuration_error(configure_endpoint_server_tls(
            &policy.clone().with_migration(true),
            &identity,
            QuicTransportLimits::default(),
        ));
        assert_configuration_error(configure_endpoint_server_tls(
            &policy
                .clone()
                .with_server_initiated_bidirectional_streams(1),
            &identity,
            QuicTransportLimits::default(),
        ));
        let mut excessive = QuicTransportLimits::default();
        excessive.max_bidirectional_streams = 2;
        assert_configuration_error(configure_endpoint_server_tls(&policy, &identity, excessive));
        assert_configuration_error(configure_endpoint_server_tls(
            &policy,
            &QuicSyntheticIdentity::new(Vec::new(), Vec::new(), Vec::new()),
            QuicTransportLimits::default(),
        ));
        assert_configuration_error(configure_endpoint_server_tls(
            &policy,
            &QuicSyntheticIdentity::new(vec![certificate], b"not DER".to_vec(), Vec::new()),
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
            QuicEndpointTransmitPacketCounts,
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
                    packet_counts: QuicEndpointTransmitPacketCounts::default(),
                });
                Ok(())
            }

            fn drain_transmits(&mut self, now: Instant) -> Result<Vec<QuicEndpointTransmit>> {
                self.now = Some(now);
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
        let output = driver.drain_transmits(now).unwrap();
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

    #[cfg(feature = "quic-endpoint")]
    #[test]
    fn driver_drains_all_transmits_as_typed_ordered_packets() {
        use std::{
            collections::VecDeque,
            net::SocketAddrV4,
            time::{Duration, Instant},
        };

        use super::{
            QuicEndpointAddresses, QuicEndpointDatagram, QuicEndpointDriver, QuicEndpointEvent,
            QuicEndpointLifecycle, QuicEndpointPacketSpaceCounts, QuicEndpointRecoveryCounts,
            QuicEndpointSnapshot, QuicEndpointStreamId, QuicEndpointStreamRead,
            QuicEndpointTransmit, QuicEndpointTransmitPacketCounts,
        };
        use crate::{PacketContext, Result};

        struct TransmitDriver {
            transmits: VecDeque<QuicEndpointTransmit>,
            timeout: Instant,
        }

        impl QuicEndpointDriver for TransmitDriver {
            fn start(&mut self, _: Instant) -> Result<()> {
                Ok(())
            }

            fn handle_datagram(&mut self, _: QuicEndpointDatagram) -> Result<()> {
                Ok(())
            }

            fn drain_transmits(&mut self, _: Instant) -> Result<Vec<QuicEndpointTransmit>> {
                Ok(self.transmits.drain(..).collect())
            }

            fn next_timeout(&self) -> Option<Instant> {
                Some(self.timeout)
            }

            fn handle_timeout(&mut self, _: Instant) -> Result<()> {
                Ok(())
            }

            fn poll_events(&mut self) -> Result<Vec<QuicEndpointEvent>> {
                Ok(Vec::new())
            }

            fn open_bidirectional_stream(&mut self) -> Result<QuicEndpointStreamId> {
                Ok(QuicEndpointStreamId(0))
            }

            fn write_stream(&mut self, _: QuicEndpointStreamId, _: &[u8]) -> Result<usize> {
                Ok(0)
            }

            fn finish_stream(&mut self, _: QuicEndpointStreamId) -> Result<()> {
                Ok(())
            }

            fn read_stream(
                &mut self,
                _: QuicEndpointStreamId,
                _: usize,
            ) -> Result<QuicEndpointStreamRead> {
                Ok(QuicEndpointStreamRead {
                    bytes: Vec::new(),
                    finished: false,
                })
            }

            fn snapshot(&self) -> QuicEndpointSnapshot {
                QuicEndpointSnapshot {
                    lifecycle: QuicEndpointLifecycle::Handshaking,
                    local_connection_id: Vec::new(),
                    peer_connection_id: Vec::new(),
                    initial: QuicEndpointPacketSpaceCounts::default(),
                    handshake: QuicEndpointPacketSpaceCounts::default(),
                    application: QuicEndpointPacketSpaceCounts::default(),
                    stream_bytes_sent: 0,
                    stream_bytes_received: 0,
                    recovery: QuicEndpointRecoveryCounts::default(),
                }
            }

            fn close(&mut self, _: Instant, _: u64, _: &[u8]) -> Result<()> {
                Ok(())
            }
        }

        let now = Instant::now();
        let local = SocketAddrV4::new("192.0.2.10".parse().unwrap(), 49_152);
        let peer = SocketAddrV4::new("198.51.100.20".parse().unwrap(), 443);
        let first_payload = vec![0xc0, 0, 0, 0, 1, 0xaa];
        let second_payload = vec![0xe0, 0, 0, 0, 1, 0xbb, 0x40, 0xcc];
        let transmit = |payload, packet_counts| QuicEndpointTransmit {
            source_ip: *local.ip(),
            source_port: local.port(),
            destination_ip: *peer.ip(),
            destination_port: peer.port(),
            payload,
            packet_counts,
        };
        let mut driver = TransmitDriver {
            transmits: VecDeque::from([
                transmit(
                    first_payload.clone(),
                    QuicEndpointTransmitPacketCounts {
                        initial: 1,
                        ..Default::default()
                    },
                ),
                transmit(
                    second_payload.clone(),
                    QuicEndpointTransmitPacketCounts {
                        handshake: 1,
                        application: 1,
                        ..Default::default()
                    },
                ),
            ]),
            timeout: now + Duration::from_millis(17),
        };
        let mut context = PacketContext::new();

        let step = driver
            .drain_transmit_step(
                now,
                QuicEndpointAddresses::new(local.into(), peer.into()),
                &mut context,
            )
            .unwrap();

        assert_eq!(step.outputs().len(), 2);
        assert_eq!(step.wakeup(), Some(Duration::from_millis(17)));
        assert!(driver.transmits.is_empty());
        for output in step.outputs() {
            assert!(output.requires_regeneration());
            let ipv4 = output.packet().layer::<crafter::Ipv4>().unwrap();
            let udp = output.packet().layer::<crafter::Udp>().unwrap();
            assert_eq!(ipv4.source(), *local.ip());
            assert_eq!(ipv4.destination(), *peer.ip());
            assert_eq!(udp.source_port_value(), local.port());
            assert_eq!(udp.destination_port_value(), peer.port());
        }
        let payloads = step
            .outputs()
            .iter()
            .map(|output| {
                let quic = output.packet().layer::<crafter::Quic>().unwrap();
                assert!(quic.packets().is_empty());
                quic.payload_bytes().to_vec()
            })
            .collect::<Vec<_>>();
        assert_eq!(payloads, [first_payload, second_payload]);
        assert_eq!(
            context
                .get_namespaced_u64("quic", "datagrams.sent")
                .unwrap(),
            Some(2)
        );
        assert_eq!(
            context
                .get_namespaced_u64("quic", "packets.initial.sent")
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            context
                .get_namespaced_u64("quic", "packets.handshake.sent")
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            context
                .get_namespaced_u64("quic", "packets.application.sent")
                .unwrap(),
            Some(1)
        );
    }

    #[cfg(feature = "quic-endpoint")]
    #[test]
    fn manual_clock_drives_provider_time_deterministically() {
        use std::time::{Duration, Instant};

        use super::{QuicEndpointClock, QuicEndpointManualClock, QuicEndpointSystemClock};

        #[derive(Default)]
        struct ProviderTimeline {
            construction: Option<Instant>,
            datagram: Option<Instant>,
            transmit: Option<Instant>,
            timeout: Option<Instant>,
        }

        impl ProviderTimeline {
            fn construct(&mut self, now: Instant) {
                self.construction = Some(now);
            }

            fn handle_datagram(&mut self, now: Instant) {
                self.datagram = Some(now);
            }

            fn poll_transmit(&mut self, now: Instant) {
                self.transmit = Some(now);
            }

            fn handle_timeout(&mut self, now: Instant) {
                self.timeout = Some(now);
            }
        }

        let origin = Instant::now();
        let mut clock = QuicEndpointManualClock::new(origin);
        let mut provider = ProviderTimeline::default();

        provider.construct(clock.now());
        assert_eq!(provider.construction, Some(origin));
        assert_eq!(
            clock.advance(Duration::from_millis(7)),
            origin + Duration::from_millis(7)
        );
        provider.handle_datagram(clock.now());
        assert_eq!(
            clock.advance(Duration::from_millis(5)),
            origin + Duration::from_millis(12)
        );
        provider.poll_transmit(clock.now());
        assert_eq!(
            clock.advance(Duration::from_millis(3)),
            origin + Duration::from_millis(15)
        );
        provider.handle_timeout(clock.now());

        assert_eq!(provider.datagram, Some(origin + Duration::from_millis(7)));
        assert_eq!(provider.transmit, Some(origin + Duration::from_millis(12)));
        assert_eq!(provider.timeout, Some(origin + Duration::from_millis(15)));
        assert_eq!(
            clock.wakeup_after(origin + Duration::from_millis(20)),
            Duration::from_millis(5)
        );
        assert_eq!(
            clock.wakeup_after(origin + Duration::from_millis(14)),
            Duration::ZERO
        );

        let before_backward_attempt = clock.now();
        assert!(clock.advance_to(origin).is_err());
        assert_eq!(clock.now(), before_backward_attempt);

        let before_overflow = clock.now();
        let saturated = clock.advance(Duration::MAX);
        assert!(saturated >= before_overflow);
        assert_eq!(clock.now(), saturated);
        assert_eq!(clock.wakeup_after(before_overflow), Duration::ZERO);

        let production = QuicEndpointSystemClock;
        let first = production.now();
        let second = production.now();
        assert!(second >= first);
    }

    #[cfg(feature = "quic-endpoint")]
    #[test]
    fn driver_accepts_typed_and_raw_ingress_with_connection_context() {
        use std::{net::SocketAddrV4, time::Instant};

        use super::{
            QuicEndpointAddresses, QuicEndpointDatagram, QuicEndpointDriver,
            QuicEndpointIngressDisposition, QuicEndpointLifecycle, QuicEndpointPacketSpaceCounts,
            QuicEndpointRecoveryCounts, QuicEndpointSnapshot, QuicEndpointStreamId,
            QuicEndpointStreamRead, QuicEndpointTransmit,
        };
        use crate::{
            matcher::UdpDatagramMatcher,
            quic_wire::{QuicCaptureRepresentation, QuicIngress, QuicIngressContext},
            FlowError, PacketContext, Result,
        };

        #[derive(Default)]
        struct IngressRecorder {
            datagrams: Vec<QuicEndpointDatagram>,
        }

        impl QuicEndpointDriver for IngressRecorder {
            fn start(&mut self, _: Instant) -> Result<()> {
                Ok(())
            }

            fn handle_datagram(&mut self, datagram: QuicEndpointDatagram) -> Result<()> {
                self.datagrams.push(datagram);
                Ok(())
            }

            fn drain_transmits(&mut self, _: Instant) -> Result<Vec<QuicEndpointTransmit>> {
                Ok(Vec::new())
            }

            fn next_timeout(&self) -> Option<Instant> {
                None
            }

            fn handle_timeout(&mut self, _: Instant) -> Result<()> {
                Ok(())
            }

            fn poll_events(&mut self) -> Result<Vec<super::QuicEndpointEvent>> {
                Ok(Vec::new())
            }

            fn open_bidirectional_stream(&mut self) -> Result<QuicEndpointStreamId> {
                Ok(QuicEndpointStreamId(0))
            }

            fn write_stream(&mut self, _: QuicEndpointStreamId, _: &[u8]) -> Result<usize> {
                Ok(0)
            }

            fn finish_stream(&mut self, _: QuicEndpointStreamId) -> Result<()> {
                Ok(())
            }

            fn read_stream(
                &mut self,
                _: QuicEndpointStreamId,
                _: usize,
            ) -> Result<QuicEndpointStreamRead> {
                Ok(QuicEndpointStreamRead {
                    bytes: Vec::new(),
                    finished: false,
                })
            }

            fn snapshot(&self) -> QuicEndpointSnapshot {
                QuicEndpointSnapshot {
                    lifecycle: QuicEndpointLifecycle::Handshaking,
                    local_connection_id: vec![0x11; 8],
                    peer_connection_id: vec![0x22; 8],
                    initial: QuicEndpointPacketSpaceCounts::default(),
                    handshake: QuicEndpointPacketSpaceCounts::default(),
                    application: QuicEndpointPacketSpaceCounts::default(),
                    stream_bytes_sent: 0,
                    stream_bytes_received: 0,
                    recovery: QuicEndpointRecoveryCounts::default(),
                }
            }

            fn close(&mut self, _: Instant, _: u64, _: &[u8]) -> Result<()> {
                Ok(())
            }
        }

        let local = SocketAddrV4::new("192.0.2.10".parse().unwrap(), 49_152);
        let peer = SocketAddrV4::new("198.51.100.20".parse().unwrap(), 443);
        let addresses = QuicEndpointAddresses::new(local.into(), peer.into());
        let matcher =
            UdpDatagramMatcher::inbound(*local.ip(), local.port(), *peer.ip(), peer.port());
        let context = PacketContext::new();
        let typed_payload = [0xc0, 0, 0, 0, 1, 0xaa];
        let raw_payload = [0x40, 0x7b, 0xde, 0xad, 0xbe, 0xef];
        let typed_packet = crafter::Ipv4::new().src(*peer.ip()).dst(*local.ip())
            / crafter::Udp::new()
                .source_port(peer.port())
                .destination_port(local.port())
            / crafter::Quic::from_bytes(typed_payload);
        let raw_packet = crafter::Ipv4::new().src(*peer.ip()).dst(*local.ip())
            / crafter::Udp::new()
                .source_port(peer.port())
                .destination_port(local.port())
            / crafter::Raw::from_bytes(raw_payload);
        let typed = QuicIngress::from_packet(&typed_packet, &matcher, &context).unwrap();
        let raw = QuicIngress::from_packet(&raw_packet, &matcher, &context)
            .unwrap()
            .with_endpoint_context(
                QuicIngressContext::new([0x11; 8]).with_expected_destination_connection_id_len(8),
            );

        let now = Instant::now();
        let mut driver = IngressRecorder::default();
        assert_eq!(
            driver
                .handle_ingress(&typed, addresses, 1_472, now)
                .unwrap(),
            QuicEndpointIngressDisposition::Accepted(QuicCaptureRepresentation::Typed)
        );
        assert_eq!(
            driver.handle_ingress(&raw, addresses, 1_472, now).unwrap(),
            QuicEndpointIngressDisposition::Accepted(QuicCaptureRepresentation::Raw)
        );
        assert_eq!(driver.datagrams.len(), 2);
        assert_eq!(driver.datagrams[0].timestamp, now);
        assert_eq!(driver.datagrams[0].local_ip, *local.ip());
        assert_eq!(driver.datagrams[0].local_port, local.port());
        assert_eq!(driver.datagrams[0].remote_ip, *peer.ip());
        assert_eq!(driver.datagrams[0].remote_port, peer.port());
        assert_eq!(driver.datagrams[0].payload, typed_payload);
        assert_eq!(driver.datagrams[1].payload, raw_payload);
        assert_eq!(
            raw.endpoint_context()
                .unwrap()
                .expected_destination_connection_id_len(),
            Some(8)
        );

        let stray_peer = SocketAddrV4::new(*peer.ip(), peer.port() + 1);
        let stray_matcher = UdpDatagramMatcher::inbound(
            *local.ip(),
            local.port(),
            *stray_peer.ip(),
            stray_peer.port(),
        );
        let stray_packet = crafter::Ipv4::new().src(*stray_peer.ip()).dst(*local.ip())
            / crafter::Udp::new()
                .source_port(stray_peer.port())
                .destination_port(local.port())
            / crafter::Raw::from_bytes(raw_payload);
        let stray = QuicIngress::from_packet(&stray_packet, &stray_matcher, &context).unwrap();
        assert_eq!(
            driver
                .handle_ingress(&stray, addresses, 1_472, now)
                .unwrap(),
            QuicEndpointIngressDisposition::IgnoredStrayTuple
        );
        assert_eq!(driver.datagrams.len(), 2);

        let oversized = driver
            .handle_ingress(&typed, addresses, 5, now)
            .unwrap_err();
        assert!(matches!(
            oversized,
            FlowError::QuicEndpoint {
                category: super::QuicEndpointErrorCategory::DatagramIngress,
                ..
            }
        ));
        assert_eq!(driver.datagrams.len(), 2);
    }

    #[cfg(feature = "quic-endpoint")]
    #[test]
    fn driver_timeout_generates_fresh_bounded_output() {
        use super::{
            QuicEndpointAddresses, QuicEndpointClock, QuicEndpointDatagram, QuicEndpointDriver,
            QuicEndpointEvent, QuicEndpointLifecycle, QuicEndpointManualClock,
            QuicEndpointPacketSpaceCounts, QuicEndpointRecoveryCounts, QuicEndpointSnapshot,
            QuicEndpointStreamId, QuicEndpointStreamRead, QuicEndpointTimeoutKind,
            QuicEndpointTransmit, QuicEndpointTransmitPacketCounts,
        };
        use crate::{PacketContext, Result};
        use std::{
            net::SocketAddrV4,
            time::{Duration, Instant},
        };

        struct TimerDriver {
            deadline: Option<Instant>,
            timeout_kind: QuicEndpointTimeoutKind,
            timeout_calls: u64,
            transmits: Vec<QuicEndpointTransmit>,
            snapshot: QuicEndpointSnapshot,
            local: SocketAddrV4,
            peer: SocketAddrV4,
        }

        impl QuicEndpointDriver for TimerDriver {
            fn start(&mut self, _: Instant) -> Result<()> {
                Ok(())
            }
            fn handle_datagram(&mut self, _: QuicEndpointDatagram) -> Result<()> {
                Ok(())
            }
            fn drain_transmits(&mut self, _: Instant) -> Result<Vec<QuicEndpointTransmit>> {
                Ok(std::mem::take(&mut self.transmits))
            }
            fn next_timeout(&self) -> Option<Instant> {
                self.deadline
            }
            fn next_timeout_kind(&self) -> QuicEndpointTimeoutKind {
                self.timeout_kind
            }
            fn handle_timeout(&mut self, now: Instant) -> Result<()> {
                self.timeout_calls = self.timeout_calls.saturating_add(1);
                self.snapshot.recovery.timeout_events =
                    self.snapshot.recovery.timeout_events.saturating_add(1);
                if self.timeout_kind == QuicEndpointTimeoutKind::ProbeTimeout {
                    self.snapshot.recovery.pto_firings =
                        self.snapshot.recovery.pto_firings.saturating_add(1);
                    self.transmits.push(QuicEndpointTransmit {
                        source_ip: *self.local.ip(),
                        source_port: self.local.port(),
                        destination_ip: *self.peer.ip(),
                        destination_port: self.peer.port(),
                        payload: vec![0x40, self.timeout_calls as u8, 0xaa],
                        packet_counts: QuicEndpointTransmitPacketCounts {
                            application: 1,
                            ..Default::default()
                        },
                    });
                    self.snapshot.recovery.regenerated_transmits = self
                        .snapshot
                        .recovery
                        .regenerated_transmits
                        .saturating_add(1);
                }
                self.deadline = if self.timeout_calls < 3 {
                    now.checked_add(Duration::from_millis(5))
                } else {
                    None
                };
                if self.timeout_calls == 2 {
                    self.timeout_kind = QuicEndpointTimeoutKind::Maintenance;
                }
                Ok(())
            }
            fn poll_events(&mut self) -> Result<Vec<QuicEndpointEvent>> {
                Ok(Vec::new())
            }
            fn open_bidirectional_stream(&mut self) -> Result<QuicEndpointStreamId> {
                Ok(QuicEndpointStreamId(0))
            }
            fn write_stream(&mut self, _: QuicEndpointStreamId, _: &[u8]) -> Result<usize> {
                Ok(0)
            }
            fn finish_stream(&mut self, _: QuicEndpointStreamId) -> Result<()> {
                Ok(())
            }
            fn read_stream(
                &mut self,
                _: QuicEndpointStreamId,
                _: usize,
            ) -> Result<QuicEndpointStreamRead> {
                Ok(QuicEndpointStreamRead {
                    bytes: Vec::new(),
                    finished: false,
                })
            }
            fn snapshot(&self) -> QuicEndpointSnapshot {
                self.snapshot.clone()
            }
            fn close(&mut self, _: Instant, _: u64, _: &[u8]) -> Result<()> {
                Ok(())
            }
        }

        let origin = Instant::now();
        let local = SocketAddrV4::new("192.0.2.10".parse().unwrap(), 49_152);
        let peer = SocketAddrV4::new("198.51.100.20".parse().unwrap(), 443);
        let addresses = QuicEndpointAddresses::new(local.into(), peer.into());
        let mut clock = QuicEndpointManualClock::new(origin);
        let mut context = PacketContext::new();
        let mut driver = TimerDriver {
            deadline: origin.checked_add(Duration::from_millis(5)),
            timeout_kind: QuicEndpointTimeoutKind::ProbeTimeout,
            timeout_calls: 0,
            transmits: Vec::new(),
            snapshot: QuicEndpointSnapshot {
                lifecycle: QuicEndpointLifecycle::Handshaking,
                local_connection_id: vec![0x11; 8],
                peer_connection_id: vec![0x22; 8],
                initial: QuicEndpointPacketSpaceCounts::default(),
                handshake: QuicEndpointPacketSpaceCounts::default(),
                application: QuicEndpointPacketSpaceCounts::default(),
                stream_bytes_sent: 0,
                stream_bytes_received: 0,
                recovery: QuicEndpointRecoveryCounts::default(),
            },
            local,
            peer,
        };

        let mut protected_payloads = Vec::new();
        for cycle in 0..3 {
            let wakeup = driver.next_wakeup(clock.now()).unwrap();
            assert_eq!(wakeup, Duration::from_millis(5));
            clock.advance(wakeup);
            let step = driver
                .handle_timeout_step(clock.now(), addresses, &mut context)
                .unwrap();
            if cycle < 2 {
                assert_eq!(step.outputs().len(), 1);
                assert!(step.outputs()[0].requires_regeneration());
                protected_payloads.push(
                    step.outputs()[0]
                        .packet()
                        .layer::<crafter::Quic>()
                        .unwrap()
                        .payload_bytes()
                        .to_vec(),
                );
                assert_eq!(step.wakeup(), Some(Duration::from_millis(5)));
            } else {
                assert!(step.outputs().is_empty());
                assert_eq!(step.wakeup(), None);
            }
        }

        assert_ne!(protected_payloads[0], protected_payloads[1]);
        assert_eq!(driver.timeout_calls, 3);
        assert_eq!(driver.snapshot.recovery.timeout_events, 3);
        assert_eq!(driver.snapshot.recovery.pto_firings, 2);
        assert_eq!(driver.snapshot.recovery.regenerated_transmits, 2);
        assert_eq!(
            context
                .get_namespaced_u64("quic", "recovery.timeout_events")
                .unwrap(),
            Some(3)
        );
        assert_eq!(
            context
                .get_namespaced_u64("quic", "recovery.pto_firings")
                .unwrap(),
            Some(2)
        );
        assert_eq!(
            context
                .get_namespaced_u64("quic", "timeouts.maintenance")
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            context
                .get_namespaced_u64("quic", "packets.application.sent")
                .unwrap(),
            Some(2)
        );
    }
}
