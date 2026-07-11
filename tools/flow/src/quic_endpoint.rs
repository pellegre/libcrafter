//! Provider-neutral configuration for the private QUIC endpoint driver.

use std::{fmt, net::SocketAddr, time::Duration};

#[cfg(feature = "quic-endpoint")]
use std::{collections::BTreeSet, net::Ipv4Addr, time::Instant};

use crate::FlowError;
#[cfg(feature = "quic-endpoint")]
use crate::{
    context::ProtocolContextSnapshot,
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

/// Non-secret peer transport parameters after the endpoint provider has
/// decoded and wire-validated them.
///
/// Provider adapters construct this summary from their connection state. It
/// deliberately excludes stateless-reset tokens, preferred-address contents,
/// and connection identifiers.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuicPeerTransportParameters {
    pub(crate) max_idle_timeout_ms: u64,
    pub(crate) max_udp_payload_size: u64,
    pub(crate) initial_max_data: u64,
    pub(crate) initial_max_stream_data_bidi_local: u64,
    pub(crate) initial_max_stream_data_bidi_remote: u64,
    pub(crate) initial_max_stream_data_uni: u64,
    pub(crate) initial_max_streams_bidi: u64,
    pub(crate) initial_max_streams_uni: u64,
    pub(crate) ack_delay_exponent: u64,
    pub(crate) max_ack_delay_ms: u64,
    pub(crate) active_connection_id_limit: u64,
    pub(crate) max_datagram_frame_size: Option<u64>,
    pub(crate) disable_active_migration: bool,
    pub(crate) has_preferred_address: bool,
}

/// Provider transport-parameter decoding failures, kept distinct from local
/// bounded-flow policy rejections.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuicPeerTransportParameterWireError {
    Duplicate,
    Malformed,
}

#[cfg(feature = "quic-endpoint")]
impl QuicPeerTransportParameterWireError {
    fn label(self) -> &'static str {
        match self {
            Self::Duplicate => "provider-wire-duplicate",
            Self::Malformed => "provider-wire-malformed",
        }
    }
}

#[cfg(feature = "quic-endpoint")]
fn reject_peer_transport_parameters(
    context: &mut PacketContext,
    rejection: &'static str,
) -> Result<QuicPeerTransportParameters> {
    context.insert_namespaced_string("quic", "transport.rejection", rejection)?;
    Err(provider_error(
        QuicEndpointErrorCategory::TransportParameters,
        "validating peer transport parameters",
        (),
    ))
}

/// Enforces the single-stream, no-datagram, no-migration full-flow contract.
///
/// The provider remains responsible for parsing the wire format and detecting
/// duplicate parameters. This boundary only validates the resulting numeric
/// summary against RFC limits and the local resource policy.
#[cfg(feature = "quic-endpoint")]
pub(crate) fn validate_peer_transport_parameters(
    decoded: std::result::Result<QuicPeerTransportParameters, QuicPeerTransportParameterWireError>,
    limits: QuicTransportLimits,
    context: &mut PacketContext,
) -> Result<QuicPeerTransportParameters> {
    let parameters = match decoded {
        Ok(parameters) => parameters,
        Err(error) => return reject_peer_transport_parameters(context, error.label()),
    };

    let rejection = if parameters.max_idle_timeout_ms == 0
        || parameters.max_idle_timeout_ms > limits.max_idle_timeout.as_millis() as u64
    {
        Some("policy-idle-timeout")
    } else if !(1_200..=65_527).contains(&parameters.max_udp_payload_size) {
        Some("illegal-max-udp-payload")
    } else if parameters.max_udp_payload_size > u64::from(limits.max_udp_payload_size) {
        Some("policy-max-udp-payload")
    } else if parameters.initial_max_data > limits.max_connection_bytes
        || parameters.initial_max_stream_data_bidi_local > limits.max_stream_bytes
        || parameters.initial_max_stream_data_bidi_remote > limits.max_stream_bytes
        || parameters.initial_max_stream_data_uni > limits.max_stream_bytes
    {
        Some("policy-flow-control")
    } else if parameters.initial_max_streams_bidi > limits.max_bidirectional_streams
        || parameters.initial_max_streams_bidi > 1
        || parameters.initial_max_streams_uni != 0
    {
        Some("policy-stream-count")
    } else if parameters.ack_delay_exponent > 20 || parameters.max_ack_delay_ms >= (1 << 14) {
        Some("illegal-ack-delay")
    } else if !(2..=8).contains(&parameters.active_connection_id_limit) {
        Some("policy-connection-id-limit")
    } else if parameters.max_datagram_frame_size.unwrap_or(0) != 0 {
        Some("policy-application-datagram")
    } else if !parameters.disable_active_migration || parameters.has_preferred_address {
        Some("policy-migration")
    } else {
        None
    };

    if let Some(rejection) = rejection {
        return reject_peer_transport_parameters(context, rejection);
    }

    for (key, value) in [
        (
            "transport.max_idle_timeout_ms",
            parameters.max_idle_timeout_ms,
        ),
        (
            "transport.max_udp_payload_size",
            parameters.max_udp_payload_size,
        ),
        ("transport.initial_max_data", parameters.initial_max_data),
        (
            "transport.initial_max_stream_data_bidi_local",
            parameters.initial_max_stream_data_bidi_local,
        ),
        (
            "transport.initial_max_stream_data_bidi_remote",
            parameters.initial_max_stream_data_bidi_remote,
        ),
        (
            "transport.initial_max_stream_data_uni",
            parameters.initial_max_stream_data_uni,
        ),
        (
            "transport.initial_max_streams_bidi",
            parameters.initial_max_streams_bidi,
        ),
        (
            "transport.initial_max_streams_uni",
            parameters.initial_max_streams_uni,
        ),
        (
            "transport.ack_delay_exponent",
            parameters.ack_delay_exponent,
        ),
        ("transport.max_ack_delay_ms", parameters.max_ack_delay_ms),
        (
            "transport.active_connection_id_limit",
            parameters.active_connection_id_limit,
        ),
        (
            "transport.max_datagram_frame_size",
            parameters.max_datagram_frame_size.unwrap_or(0),
        ),
    ] {
        context.insert_namespaced_u64("quic", key, value)?;
    }
    context.insert_namespaced_string("quic", "transport.validation", "validated")?;

    Ok(parameters)
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

#[cfg(feature = "quic-endpoint")]
impl QuicEndpointTransmitPacketCounts {
    /// Classify a single protected QUIC packet without recovering its packet
    /// number. Long-header packet types are not header-protected. A short
    /// header is Application data only when the endpoint context has already
    /// accepted it for this connection.
    fn classify_single(payload: &[u8], endpoint_accepts_short_header: bool) -> Self {
        let Some(first) = payload.first().copied() else {
            return Self::default();
        };
        let space = if first & 0x80 == 0 {
            endpoint_accepts_short_header.then_some(QuicEndpointPacketSpace::Application)
        } else if payload.len() >= 5 && payload[1..5] == [0, 0, 0, 1] {
            match first & 0x30 {
                0x00 => Some(QuicEndpointPacketSpace::Initial),
                0x20 => Some(QuicEndpointPacketSpace::Handshake),
                _ => None,
            }
        } else {
            None
        };

        match space {
            Some(QuicEndpointPacketSpace::Initial) => Self {
                initial: 1,
                ..Self::default()
            },
            Some(QuicEndpointPacketSpace::Handshake) => Self {
                handshake: 1,
                ..Self::default()
            },
            Some(QuicEndpointPacketSpace::Application) => Self {
                application: 1,
                ..Self::default()
            },
            None => Self::default(),
        }
    }
}

#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicEndpointPacketSpace {
    Initial,
    Handshake,
    Application,
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
    InitialSent,
    Listen,
    Handshaking,
    Established,
    Closing,
    Draining,
    Closed,
    Failed,
}

#[cfg(feature = "quic-endpoint")]
impl QuicEndpointLifecycle {
    fn label(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::InitialSent => "initial-sent",
            Self::Listen => "listen",
            Self::Handshaking => "handshaking",
            Self::Established => "established",
            Self::Closing => "closing",
            Self::Draining => "draining",
            Self::Closed => "closed",
            Self::Failed => "failed",
        }
    }
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
    TlsAuthenticationFailed {
        failure: QuicTlsAuthenticationFailure,
        transport_close: Option<u64>,
    },
    FatalError {
        category: QuicEndpointErrorCategory,
        context: &'static str,
    },
}

/// Stable classification of TLS failures observed before establishment.
///
/// Provider-controlled certificate and alert text is deliberately excluded.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum QuicTlsAuthenticationFailure {
    PeerNameMismatch,
    UnknownIssuer,
    CertificateExpired,
    MalformedCertificate,
    AlpnMismatch,
    HandshakeAlert,
}

#[cfg(feature = "quic-endpoint")]
impl QuicTlsAuthenticationFailure {
    fn label(self) -> &'static str {
        match self {
            Self::PeerNameMismatch => "peer-name-mismatch",
            Self::UnknownIssuer => "unknown-issuer",
            Self::CertificateExpired => "certificate-expired",
            Self::MalformedCertificate => "malformed-certificate",
            Self::AlpnMismatch => "alpn-mismatch",
            Self::HandshakeAlert => "handshake-alert",
        }
    }
}

/// Convert a provider TLS error into a bounded event without retaining its text.
#[cfg(feature = "quic-endpoint")]
pub(crate) fn map_provider_tls_authentication_failure<E>(
    failure: QuicTlsAuthenticationFailure,
    transport_close: Option<u64>,
    _provider_error: E,
) -> QuicEndpointEvent {
    QuicEndpointEvent::TlsAuthenticationFailed {
        failure,
        transport_close,
    }
}

/// Flow-owned normalization state for provider lifecycle notifications.
///
/// Readiness is edge-triggered at this boundary: a provider may report the
/// same readable or writable stream repeatedly until the flow services it, but
/// the state graph only needs one pending observation. Stream completion and
/// close events are never deduplicated because they carry final protocol facts.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug)]
pub(crate) struct QuicEndpointEventMapper {
    lifecycle: QuicEndpointLifecycle,
    handshake_started: bool,
    authenticated_handshake: bool,
    readable: BTreeSet<QuicEndpointStreamId>,
    writable: BTreeSet<QuicEndpointStreamId>,
    recovery: QuicEndpointRecoveryCounts,
}

#[cfg(feature = "quic-endpoint")]
impl QuicEndpointEventMapper {
    pub(crate) fn new(lifecycle: QuicEndpointLifecycle) -> Self {
        Self {
            lifecycle,
            handshake_started: false,
            authenticated_handshake: false,
            readable: BTreeSet::new(),
            writable: BTreeSet::new(),
            recovery: QuicEndpointRecoveryCounts::default(),
        }
    }

    pub(crate) fn poll<D: QuicEndpointDriver + ?Sized>(
        &mut self,
        driver: &mut D,
        context: &mut PacketContext,
    ) -> Result<Vec<QuicEndpointEvent>> {
        let events = driver.poll_events()?;
        let provider_snapshot = driver.snapshot();
        let mut normalized = Vec::with_capacity(events.len());

        if !matches!(context.protocol_snapshot(), Some(snapshot) if snapshot.protocol == "quic") {
            context.set_protocol_snapshot(ProtocolContextSnapshot::new(
                "quic",
                self.lifecycle.label(),
            ));
        }

        for event in events {
            match &event {
                QuicEndpointEvent::HandshakeProgress => {
                    self.handshake_started = true;
                    self.lifecycle = QuicEndpointLifecycle::Handshaking;
                }
                QuicEndpointEvent::Established => {
                    if !self.handshake_started {
                        return Err(provider_error(
                            QuicEndpointErrorCategory::TlsAuthentication,
                            "rejecting established lifecycle before authenticated handshake",
                            (),
                        ));
                    }
                    self.authenticated_handshake = true;
                    self.lifecycle = QuicEndpointLifecycle::Established;
                    context.insert_namespaced_bool("quic", "handshake.authenticated", true)?;
                }
                QuicEndpointEvent::StreamReadable(stream) => {
                    if !self.readable.insert(*stream) {
                        continue;
                    }
                    context.insert_namespaced_bool("quic", "stream.readable", true)?;
                    context.insert_namespaced_u64("quic", "stream.id", stream.0)?;
                }
                QuicEndpointEvent::StreamWritable(stream) => {
                    if !self.writable.insert(*stream) {
                        continue;
                    }
                    context.insert_namespaced_bool("quic", "stream.writable", true)?;
                    context.insert_namespaced_u64("quic", "stream.id", stream.0)?;
                }
                QuicEndpointEvent::StreamFinished(stream) => {
                    self.readable.remove(stream);
                    self.writable.remove(stream);
                    context.insert_namespaced_bool("quic", "stream.readable", false)?;
                    context.insert_namespaced_bool("quic", "stream.writable", false)?;
                    context.insert_namespaced_bool("quic", "stream.finished", true)?;
                    context.insert_namespaced_u64("quic", "stream.id", stream.0)?;
                }
                QuicEndpointEvent::PeerClose { code } => {
                    self.lifecycle = QuicEndpointLifecycle::Closing;
                    update_quic_protocol_snapshot(context, |snapshot| {
                        snapshot.close_category = Some("peer".to_string());
                        snapshot.close_code = Some(*code);
                    });
                }
                QuicEndpointEvent::LocalClose { code } => {
                    self.lifecycle = QuicEndpointLifecycle::Closing;
                    update_quic_protocol_snapshot(context, |snapshot| {
                        snapshot.close_category = Some("local".to_string());
                        snapshot.close_code = Some(*code);
                    });
                }
                QuicEndpointEvent::Draining => {
                    self.lifecycle = QuicEndpointLifecycle::Draining;
                }
                QuicEndpointEvent::IdleTimeout => {
                    self.lifecycle = QuicEndpointLifecycle::Closed;
                    update_quic_protocol_snapshot(context, |snapshot| {
                        snapshot.outcome = Some("idle-timeout".to_string());
                        snapshot.close_category = Some("idle-timeout".to_string());
                    });
                }
                QuicEndpointEvent::TlsAuthenticationFailed {
                    failure,
                    transport_close,
                } => {
                    self.authenticated_handshake = false;
                    self.lifecycle = if transport_close.is_some() {
                        QuicEndpointLifecycle::Closing
                    } else {
                        QuicEndpointLifecycle::Closed
                    };
                    context.insert_namespaced_bool("quic", "handshake.authenticated", false)?;
                    context.insert_namespaced_bool("quic", "handshake.established", false)?;
                    update_quic_protocol_snapshot(context, |snapshot| {
                        snapshot.outcome = Some("tls-authentication-failed".to_string());
                        snapshot.close_category =
                            transport_close.map(|_| "tls-authentication".to_string());
                        snapshot.close_code = *transport_close;
                        snapshot.error_category = Some(failure.label().to_string());
                        snapshot.error_context = Some("authenticating QUIC peer".to_string());
                    });
                }
                QuicEndpointEvent::FatalError {
                    category,
                    context: operation,
                } => {
                    self.lifecycle = QuicEndpointLifecycle::Failed;
                    update_quic_protocol_snapshot(context, |snapshot| {
                        snapshot.outcome = Some("endpoint-error".to_string());
                        snapshot.error_category = Some(category.to_string());
                        snapshot.error_context = Some((*operation).to_string());
                    });
                }
            }
            normalized.push(event);
        }

        let mut snapshot = context
            .protocol_snapshot()
            .cloned()
            .unwrap_or_else(|| ProtocolContextSnapshot::new("quic", self.lifecycle.label()));
        snapshot.protocol = "quic".to_string();
        snapshot.lifecycle = self.lifecycle.label().to_string();
        snapshot.local_connection_id = Some(provider_snapshot.local_connection_id);
        snapshot.peer_connection_id = Some(provider_snapshot.peer_connection_id);
        context.set_protocol_snapshot(snapshot);
        render_quic_packet_space(context, "initial", provider_snapshot.initial)?;
        render_quic_packet_space(context, "handshake", provider_snapshot.handshake)?;
        render_quic_packet_space(context, "application", provider_snapshot.application)?;
        render_quic_recovery(context, &mut self.recovery, provider_snapshot.recovery)?;
        Ok(normalized)
    }

    pub(crate) fn authenticated_handshake(&self) -> bool {
        self.authenticated_handshake
    }

    /// Normalize provider events and drain any resulting close datagrams.
    ///
    /// The shared transmit wrapper marks every protected datagram as
    /// regeneration-only and retains the configured tuple in the typed packet.
    pub(crate) fn poll_and_drain_transmits<D: QuicEndpointDriver + ?Sized>(
        &mut self,
        driver: &mut D,
        now: Instant,
        addresses: QuicEndpointAddresses,
        context: &mut PacketContext,
    ) -> Result<(Vec<QuicEndpointEvent>, Step)> {
        context.insert_namespaced_string("quic", "tuple.local", addresses.local.to_string())?;
        context.insert_namespaced_string("quic", "tuple.peer", addresses.peer.to_string())?;
        let events = self.poll(driver, context)?;
        let transmits = driver.drain_transmit_step(now, addresses, context)?;
        Ok((events, transmits))
    }
}

#[cfg(feature = "quic-endpoint")]
fn update_quic_protocol_snapshot(
    context: &mut PacketContext,
    update: impl FnOnce(&mut ProtocolContextSnapshot),
) {
    let updated = context.update_protocol_snapshot(update);
    debug_assert!(updated, "QUIC event polling installs a snapshot first");
}

/// Packet observations for one QUIC packet-number space.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct QuicEndpointPacketSpaceCounts {
    pub(crate) sent: u64,
    pub(crate) received: u64,
    pub(crate) acknowledged: u64,
    pub(crate) lost: u64,
    pub(crate) discarded: u64,
    pub(crate) state: QuicEndpointPacketSpaceState,
}

/// Whether provider keys and recovery state for a packet-number space remain
/// active. Counters remain intact after discard.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum QuicEndpointPacketSpaceState {
    #[default]
    Active,
    Discarded,
}

#[cfg(feature = "quic-endpoint")]
fn render_quic_packet_space(
    context: &mut PacketContext,
    name: &str,
    counts: QuicEndpointPacketSpaceCounts,
) -> Result<()> {
    for (field, value) in [
        ("sent", counts.sent),
        ("received", counts.received),
        ("acknowledged", counts.acknowledged),
        ("lost", counts.lost),
        ("discarded", counts.discarded),
    ] {
        context.insert_namespaced_u64("quic", &format!("packet_spaces.{name}.{field}"), value)?;
    }
    context.insert_namespaced_bool(
        "quic",
        &format!("packet_spaces.{name}.active"),
        counts.state == QuicEndpointPacketSpaceState::Active,
    )?;
    context.insert_namespaced_bool(
        "quic",
        &format!("packet_spaces.{name}.discarded_state"),
        counts.state == QuicEndpointPacketSpaceState::Discarded,
    )
}

/// Recovery observations retained without provider-internal state.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct QuicEndpointRecoveryCounts {
    pub(crate) timeout_events: u64,
    pub(crate) acknowledgements_processed: u64,
    pub(crate) pto_firings: u64,
    pub(crate) packets_declared_lost: u64,
    pub(crate) regenerated_transmits: u64,
    pub(crate) initial: QuicEndpointRecoverySpaceCounts,
    pub(crate) handshake: QuicEndpointRecoverySpaceCounts,
    pub(crate) application: QuicEndpointRecoverySpaceCounts,
}

/// Provider-owned recovery observations for one packet-number space.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct QuicEndpointRecoverySpaceCounts {
    pub(crate) acknowledgements_processed: u64,
    pub(crate) pto_firings: u64,
    pub(crate) packets_declared_lost: u64,
    pub(crate) regenerated_transmits: u64,
}

/// Packet-number space attached to an endpoint recovery observation.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuicEndpointPacketNumberSpace {
    Initial,
    Handshake,
    Application,
}

/// Safe observation emitted by a provider adapter or deterministic test observer.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuicEndpointRecoveryEvent {
    AcknowledgementProcessed(Option<QuicEndpointPacketNumberSpace>),
    PacketDeclaredLost(Option<QuicEndpointPacketNumberSpace>),
    PtoFired(Option<QuicEndpointPacketNumberSpace>),
    FreshTransmitGenerated(Option<QuicEndpointPacketNumberSpace>),
}

#[cfg(feature = "quic-endpoint")]
impl QuicEndpointRecoveryCounts {
    pub(crate) fn observe(&mut self, event: QuicEndpointRecoveryEvent) {
        let (aggregate, space) = match event {
            QuicEndpointRecoveryEvent::AcknowledgementProcessed(space) => {
                self.acknowledgements_processed = self.acknowledgements_processed.saturating_add(1);
                (0, space)
            }
            QuicEndpointRecoveryEvent::PacketDeclaredLost(space) => {
                self.packets_declared_lost = self.packets_declared_lost.saturating_add(1);
                (1, space)
            }
            QuicEndpointRecoveryEvent::PtoFired(space) => {
                self.pto_firings = self.pto_firings.saturating_add(1);
                (2, space)
            }
            QuicEndpointRecoveryEvent::FreshTransmitGenerated(space) => {
                self.regenerated_transmits = self.regenerated_transmits.saturating_add(1);
                (3, space)
            }
        };
        let Some(space) = space else { return };
        let counts = match space {
            QuicEndpointPacketNumberSpace::Initial => &mut self.initial,
            QuicEndpointPacketNumberSpace::Handshake => &mut self.handshake,
            QuicEndpointPacketNumberSpace::Application => &mut self.application,
        };
        match aggregate {
            0 => {
                counts.acknowledgements_processed =
                    counts.acknowledgements_processed.saturating_add(1)
            }
            1 => counts.packets_declared_lost = counts.packets_declared_lost.saturating_add(1),
            2 => counts.pto_firings = counts.pto_firings.saturating_add(1),
            _ => counts.regenerated_transmits = counts.regenerated_transmits.saturating_add(1),
        }
    }
}

#[cfg(feature = "quic-endpoint")]
fn render_quic_recovery(
    context: &mut PacketContext,
    prior: &mut QuicEndpointRecoveryCounts,
    current: QuicEndpointRecoveryCounts,
) -> Result<()> {
    context.add_timeout_events(current.timeout_events.saturating_sub(prior.timeout_events));
    context.add_acknowledgements_processed(
        current
            .acknowledgements_processed
            .saturating_sub(prior.acknowledgements_processed),
    );
    context.add_pto_firings(current.pto_firings.saturating_sub(prior.pto_firings));
    context.add_packets_declared_lost(
        current
            .packets_declared_lost
            .saturating_sub(prior.packets_declared_lost),
    );
    context.add_regenerated_transmits(
        current
            .regenerated_transmits
            .saturating_sub(prior.regenerated_transmits),
    );

    for (name, counts) in [
        ("initial", current.initial),
        ("handshake", current.handshake),
        ("application", current.application),
    ] {
        for (field, value) in [
            (
                "acknowledgements_processed",
                counts.acknowledgements_processed,
            ),
            ("packets_declared_lost", counts.packets_declared_lost),
            ("pto_firings", counts.pto_firings),
            ("regenerated_transmits", counts.regenerated_transmits),
        ] {
            let key = format!("recovery.packet_spaces.{name}.{field}");
            let observed = context.get_namespaced_u64("quic", &key)?.unwrap_or(0);
            context.insert_namespaced_u64("quic", &key, observed.max(value))?;
        }
    }
    prior.timeout_events = prior.timeout_events.max(current.timeout_events);
    prior.acknowledgements_processed = prior
        .acknowledgements_processed
        .max(current.acknowledgements_processed);
    prior.pto_firings = prior.pto_firings.max(current.pto_firings);
    prior.packets_declared_lost = prior
        .packets_declared_lost
        .max(current.packets_declared_lost);
    prior.regenerated_transmits = prior
        .regenerated_transmits
        .max(current.regenerated_transmits);
    for (retained, observed) in [
        (&mut prior.initial, current.initial),
        (&mut prior.handshake, current.handshake),
        (&mut prior.application, current.application),
    ] {
        retained.acknowledgements_processed = retained
            .acknowledgements_processed
            .max(observed.acknowledgements_processed);
        retained.pto_firings = retained.pto_firings.max(observed.pto_firings);
        retained.packets_declared_lost = retained
            .packets_declared_lost
            .max(observed.packets_declared_lost);
        retained.regenerated_transmits = retained
            .regenerated_transmits
            .max(observed.regenerated_transmits);
    }
    Ok(())
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

/// Private state for the bounded client's single opaque request stream.
///
/// The provider stream identifier and request bytes never enter public flow
/// context. Only the accepted byte count and completion flag are projected for
/// inspection.
#[cfg(feature = "quic-endpoint")]
#[derive(Debug)]
pub(crate) struct QuicEndpointClientRequest {
    request: Vec<u8>,
    max_request_bytes: u64,
    zero_rtt_attempt: bool,
    stream: Option<QuicEndpointStreamId>,
    accepted: usize,
    finished: bool,
}

#[cfg(feature = "quic-endpoint")]
impl QuicEndpointClientRequest {
    pub(crate) fn new(request: Vec<u8>, max_request_bytes: u64) -> Self {
        Self {
            request,
            max_request_bytes,
            zero_rtt_attempt: false,
            stream: None,
            accepted: 0,
            finished: false,
        }
    }

    /// Marks an attempted early-data write so it can be rejected at the same
    /// flow-owned boundary as other invalid stream lifecycle operations.
    pub(crate) fn with_zero_rtt_attempt(mut self, attempted: bool) -> Self {
        self.zero_rtt_attempt = attempted;
        self
    }

    /// Open and incrementally drive the one client-initiated bidirectional
    /// request stream. A `false` result means provider capacity was exhausted
    /// and the caller should retry after a writable event.
    pub(crate) fn drive<D: QuicEndpointDriver + ?Sized>(
        &mut self,
        driver: &mut D,
        context: &mut PacketContext,
    ) -> Result<bool> {
        let established = matches!(
            context.protocol_snapshot(),
            Some(snapshot) if snapshot.protocol == "quic" && snapshot.lifecycle == "established"
        ) && context.get_namespaced_bool("quic", "handshake.authenticated")?
            == Some(true);
        if !established {
            return Err(stream_state_error(
                "opening client request stream before authenticated establishment",
            ));
        }
        if context.get_namespaced_string("quic", "transport.validation")? != Some("validated") {
            return Err(stream_state_error(
                "opening client request stream before transport parameter validation",
            ));
        }
        if self.zero_rtt_attempt {
            return Err(stream_state_error("rejecting client 0-RTT request write"));
        }
        if self.request.len() as u64 > self.max_request_bytes {
            return Err(stream_state_error("rejecting oversized client request"));
        }
        if self.finished {
            return Err(stream_state_error(
                "rejecting second client application stream",
            ));
        }

        let stream = match self.stream {
            Some(stream) => stream,
            None => {
                let stream = driver.open_bidirectional_stream()?;
                // QUIC stream 0 is the first client-initiated bidirectional
                // stream. Any other identifier would exceed this bounded
                // flow's single-stream contract.
                if stream != QuicEndpointStreamId(0) {
                    return Err(stream_state_error(
                        "rejecting non-first client bidirectional stream",
                    ));
                }
                self.stream = Some(stream);
                stream
            }
        };

        if self.accepted < self.request.len() {
            let remaining = &self.request[self.accepted..];
            let accepted = driver.write_stream(stream, remaining)?;
            if accepted > remaining.len() {
                return Err(provider_error(
                    QuicEndpointErrorCategory::ProviderInternal,
                    "rejecting invalid client stream write count",
                    (),
                ));
            }
            self.accepted += accepted;
        }

        context.insert_namespaced_u64(
            "quic",
            "application.request_bytes_sent",
            self.accepted as u64,
        )?;
        if self.accepted != self.request.len() {
            context.insert_namespaced_bool("quic", "application.request_complete", false)?;
            return Ok(false);
        }

        driver.finish_stream(stream)?;
        self.finished = true;
        context.insert_namespaced_bool("quic", "application.request_complete", true)?;
        Ok(true)
    }
}

#[cfg(feature = "quic-endpoint")]
fn stream_state_error(context: &'static str) -> FlowError {
    provider_error(QuicEndpointErrorCategory::StreamState, context, ())
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
                // Provider metadata is authoritative for coalesced datagrams.
                // For a single packet without metadata, classify only the
                // invariant packet form. These bytes came from the endpoint,
                // so its connection context has accepted a short header.
                let packet_counts =
                    if transmit.packet_counts == QuicEndpointTransmitPacketCounts::default() {
                        QuicEndpointTransmitPacketCounts::classify_single(&transmit.payload, true)
                    } else {
                        transmit.packet_counts
                    };
                initial = initial.saturating_add(packet_counts.initial);
                handshake = handshake.saturating_add(packet_counts.handshake);
                application = application.saturating_add(packet_counts.application);
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
    fn peer_transport_parameters_enforce_bounded_contract() {
        use super::{
            validate_peer_transport_parameters, QuicPeerTransportParameterWireError as WireError,
            QuicPeerTransportParameters as Parameters, QuicTransportLimits,
        };
        use crate::{FlowError, PacketContext};

        let limits = QuicTransportLimits::default();
        let valid = Parameters {
            max_idle_timeout_ms: 5_000,
            max_udp_payload_size: 1_400,
            initial_max_data: 96 * 1024,
            initial_max_stream_data_bidi_local: 32 * 1024,
            initial_max_stream_data_bidi_remote: 32 * 1024,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 1,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay_ms: 25,
            active_connection_id_limit: 2,
            max_datagram_frame_size: None,
            disable_active_migration: true,
            has_preferred_address: false,
        };
        let boundary = Parameters {
            max_idle_timeout_ms: limits.max_idle_timeout.as_millis() as u64,
            max_udp_payload_size: u64::from(limits.max_udp_payload_size),
            initial_max_data: limits.max_connection_bytes,
            initial_max_stream_data_bidi_local: limits.max_stream_bytes,
            initial_max_stream_data_bidi_remote: limits.max_stream_bytes,
            initial_max_stream_data_uni: limits.max_stream_bytes,
            ack_delay_exponent: 20,
            max_ack_delay_ms: (1 << 14) - 1,
            active_connection_id_limit: 8,
            max_datagram_frame_size: Some(0),
            ..valid
        };

        let cases = [
            ("valid", Ok(valid), None),
            ("boundary", Ok(boundary), None),
            (
                "duplicate",
                Err(WireError::Duplicate),
                Some("provider-wire-duplicate"),
            ),
            (
                "malformed",
                Err(WireError::Malformed),
                Some("provider-wire-malformed"),
            ),
            (
                "idle timeout disabled",
                Ok(Parameters {
                    max_idle_timeout_ms: 0,
                    ..valid
                }),
                Some("policy-idle-timeout"),
            ),
            (
                "UDP payload below protocol minimum",
                Ok(Parameters {
                    max_udp_payload_size: 1_199,
                    ..valid
                }),
                Some("illegal-max-udp-payload"),
            ),
            (
                "UDP payload above local bound",
                Ok(Parameters {
                    max_udp_payload_size: u64::from(limits.max_udp_payload_size) + 1,
                    ..valid
                }),
                Some("policy-max-udp-payload"),
            ),
            (
                "flow control above local bound",
                Ok(Parameters {
                    initial_max_data: limits.max_connection_bytes + 1,
                    ..valid
                }),
                Some("policy-flow-control"),
            ),
            (
                "excessive bidirectional streams",
                Ok(Parameters {
                    initial_max_streams_bidi: 2,
                    ..valid
                }),
                Some("policy-stream-count"),
            ),
            (
                "unidirectional streams unsupported",
                Ok(Parameters {
                    initial_max_streams_uni: 1,
                    ..valid
                }),
                Some("policy-stream-count"),
            ),
            (
                "illegal acknowledgement delay",
                Ok(Parameters {
                    ack_delay_exponent: 21,
                    ..valid
                }),
                Some("illegal-ack-delay"),
            ),
            (
                "excessive connection identifiers",
                Ok(Parameters {
                    active_connection_id_limit: 9,
                    ..valid
                }),
                Some("policy-connection-id-limit"),
            ),
            (
                "application datagrams unsupported",
                Ok(Parameters {
                    max_datagram_frame_size: Some(1),
                    ..valid
                }),
                Some("policy-application-datagram"),
            ),
            (
                "migration unsupported",
                Ok(Parameters {
                    disable_active_migration: false,
                    ..valid
                }),
                Some("policy-migration"),
            ),
            (
                "preferred address unsupported",
                Ok(Parameters {
                    has_preferred_address: true,
                    ..valid
                }),
                Some("policy-migration"),
            ),
        ];

        for (name, decoded, expected_rejection) in cases {
            let mut context = PacketContext::new();
            let result = validate_peer_transport_parameters(decoded, limits, &mut context);

            match expected_rejection {
                None => {
                    let accepted = result.unwrap_or_else(|error| panic!("{name}: {error}"));
                    assert_eq!(
                        context
                            .get_namespaced_string("quic", "transport.validation")
                            .unwrap(),
                        Some("validated"),
                        "{name}"
                    );
                    assert_eq!(
                        context
                            .get_namespaced_u64("quic", "transport.max_udp_payload_size")
                            .unwrap(),
                        Some(accepted.max_udp_payload_size),
                        "{name}"
                    );
                    assert_eq!(
                        context
                            .get_namespaced_string("quic", "transport.rejection")
                            .unwrap(),
                        None,
                        "{name}"
                    );
                }
                Some(rejection) => {
                    assert!(
                        matches!(
                            result,
                            Err(FlowError::QuicEndpoint {
                                category: Category::TransportParameters,
                                ..
                            })
                        ),
                        "{name}"
                    );
                    assert_eq!(
                        context
                            .get_namespaced_string("quic", "transport.rejection")
                            .unwrap(),
                        Some(rejection),
                        "{name}"
                    );
                    assert_eq!(
                        context
                            .get_namespaced_u64("quic", "transport.max_udp_payload_size")
                            .unwrap(),
                        None,
                        "{name}"
                    );
                }
            }
        }
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

    #[cfg(feature = "quic-endpoint")]
    #[test]
    fn driver_reports_provider_owned_recovery_events() {
        use super::{
            render_quic_recovery, QuicEndpointPacketNumberSpace as Space,
            QuicEndpointRecoveryCounts, QuicEndpointRecoveryEvent as Event,
        };
        use crate::{FlowOutcome, FlowReport, PacketContext, Role};
        use std::time::Duration;

        let script = [
            Event::AcknowledgementProcessed(Some(Space::Initial)),
            Event::AcknowledgementProcessed(Some(Space::Handshake)),
            Event::AcknowledgementProcessed(Some(Space::Application)),
            Event::PacketDeclaredLost(Some(Space::Handshake)),
            Event::PtoFired(Some(Space::Application)),
            Event::FreshTransmitGenerated(Some(Space::Application)),
            Event::FreshTransmitGenerated(None),
        ];
        let mut provider = QuicEndpointRecoveryCounts::default();
        for event in script {
            provider.observe(event);
        }

        let mut prior = QuicEndpointRecoveryCounts::default();
        let mut context = PacketContext::new();
        render_quic_recovery(&mut context, &mut prior, provider).unwrap();
        // Re-rendering an unchanged absolute provider snapshot must not double count.
        render_quic_recovery(&mut context, &mut prior, provider).unwrap();

        let metrics = context.recovery_metrics();
        assert_eq!(metrics.acknowledgements_processed(), 3);
        assert_eq!(metrics.packets_declared_lost(), 1);
        assert_eq!(metrics.pto_firings(), 1);
        assert_eq!(metrics.regenerated_transmits(), 2);
        assert_eq!(
            context
                .get_namespaced_u64(
                    "quic",
                    "recovery.packet_spaces.initial.acknowledgements_processed",
                )
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            context
                .get_namespaced_u64(
                    "quic",
                    "recovery.packet_spaces.handshake.packets_declared_lost",
                )
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            context
                .get_namespaced_u64("quic", "recovery.packet_spaces.application.pto_firings")
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            context
                .get_namespaced_u64(
                    "quic",
                    "recovery.packet_spaces.application.regenerated_transmits",
                )
                .unwrap(),
            Some(1)
        );

        let report = FlowReport::new(
            "provider recovery",
            Role::Initiator,
            true,
            vec!["Handshaking".to_string()],
            2,
            1,
            Vec::new(),
            1,
            Duration::ZERO,
            FlowOutcome::Completed,
            context.summary(),
        )
        .with_recovery_metrics(metrics);
        assert!(report.summary().contains("acknowledgements_processed=3"));
        assert!(report.summary().contains("packets_declared_lost=1"));
        assert!(report.show().contains("    pto_firings: 1"));
        assert!(report.to_json().contains("\"regenerated_transmits\":2"));

        let mut saturated = QuicEndpointRecoveryCounts {
            acknowledgements_processed: u64::MAX,
            ..Default::default()
        };
        saturated.observe(Event::AcknowledgementProcessed(Some(Space::Initial)));
        assert_eq!(saturated.acknowledgements_processed, u64::MAX);
        assert_eq!(saturated.initial.acknowledgements_processed, 1);
    }

    #[cfg(feature = "quic-endpoint")]
    #[test]
    fn provider_events_map_to_stable_lifecycle() {
        use std::{collections::VecDeque, time::Instant};

        use super::{
            QuicEndpointDatagram, QuicEndpointDriver, QuicEndpointErrorCategory, QuicEndpointEvent,
            QuicEndpointEventMapper, QuicEndpointLifecycle, QuicEndpointPacketSpaceCounts,
            QuicEndpointRecoveryCounts, QuicEndpointSnapshot, QuicEndpointStreamId,
            QuicEndpointStreamRead, QuicEndpointTransmit,
        };
        use crate::{FlowError, PacketContext, Result};

        struct ScriptedDriver {
            events: VecDeque<QuicEndpointEvent>,
            snapshot: QuicEndpointSnapshot,
        }

        impl QuicEndpointDriver for ScriptedDriver {
            fn start(&mut self, _: Instant) -> Result<()> {
                Ok(())
            }

            fn handle_datagram(&mut self, _: QuicEndpointDatagram) -> Result<()> {
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

            fn poll_events(&mut self) -> Result<Vec<QuicEndpointEvent>> {
                Ok(self.events.drain(..).collect())
            }

            fn open_bidirectional_stream(&mut self) -> Result<QuicEndpointStreamId> {
                Ok(QuicEndpointStreamId(0))
            }

            fn write_stream(&mut self, _: QuicEndpointStreamId, bytes: &[u8]) -> Result<usize> {
                Ok(bytes.len())
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

        let snapshot = QuicEndpointSnapshot {
            lifecycle: QuicEndpointLifecycle::Established,
            local_connection_id: vec![0x11; 8],
            peer_connection_id: vec![0x22; 8],
            initial: QuicEndpointPacketSpaceCounts::default(),
            handshake: QuicEndpointPacketSpaceCounts::default(),
            application: QuicEndpointPacketSpaceCounts::default(),
            stream_bytes_sent: 7,
            stream_bytes_received: 8,
            recovery: QuicEndpointRecoveryCounts::default(),
        };
        let stream = QuicEndpointStreamId(0);
        let script = [
            QuicEndpointEvent::HandshakeProgress,
            QuicEndpointEvent::Established,
            QuicEndpointEvent::StreamReadable(stream),
            QuicEndpointEvent::StreamReadable(stream),
            QuicEndpointEvent::StreamWritable(stream),
            QuicEndpointEvent::StreamWritable(stream),
            QuicEndpointEvent::StreamFinished(stream),
            QuicEndpointEvent::LocalClose { code: 0 },
            QuicEndpointEvent::PeerClose { code: 42 },
            QuicEndpointEvent::Draining,
            QuicEndpointEvent::IdleTimeout,
            QuicEndpointEvent::FatalError {
                category: QuicEndpointErrorCategory::ProviderInternal,
                context: "polling endpoint lifecycle",
            },
        ];
        let mut driver = ScriptedDriver {
            events: script.clone().into(),
            snapshot: snapshot.clone(),
        };
        let mut mapper = QuicEndpointEventMapper::new(QuicEndpointLifecycle::InitialSent);
        let mut context = PacketContext::new();

        let events = mapper.poll(&mut driver, &mut context).unwrap();

        assert_eq!(events.len(), script.len() - 2);
        assert_eq!(events[0], QuicEndpointEvent::HandshakeProgress);
        assert_eq!(events[1], QuicEndpointEvent::Established);
        assert!(mapper.authenticated_handshake());
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == QuicEndpointEvent::StreamReadable(stream))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == QuicEndpointEvent::StreamWritable(stream))
                .count(),
            1
        );
        assert!(events.contains(&QuicEndpointEvent::LocalClose { code: 0 }));
        assert!(events.contains(&QuicEndpointEvent::PeerClose { code: 42 }));
        assert_eq!(
            context
                .get_namespaced_bool("quic", "handshake.authenticated")
                .unwrap(),
            Some(true)
        );
        assert_eq!(
            context
                .get_namespaced_bool("quic", "stream.finished")
                .unwrap(),
            Some(true)
        );
        let observed = context.protocol_snapshot().unwrap();
        assert_eq!(observed.lifecycle, "failed");
        assert_eq!(
            observed.local_connection_id.as_deref(),
            Some(&[0x11; 8][..])
        );
        assert_eq!(observed.peer_connection_id.as_deref(), Some(&[0x22; 8][..]));
        assert_eq!(observed.close_category.as_deref(), Some("idle-timeout"));
        assert_eq!(observed.close_code, Some(42));
        assert_eq!(observed.outcome.as_deref(), Some("endpoint-error"));
        assert_eq!(
            observed.error_category.as_deref(),
            Some("provider internal")
        );
        assert_eq!(
            observed.error_context.as_deref(),
            Some("polling endpoint lifecycle")
        );

        let mut illegal = ScriptedDriver {
            events: VecDeque::from([QuicEndpointEvent::Established]),
            snapshot,
        };
        let mut illegal_mapper = QuicEndpointEventMapper::new(QuicEndpointLifecycle::Listen);
        let error = illegal_mapper
            .poll(&mut illegal, &mut PacketContext::new())
            .unwrap_err();
        assert!(matches!(
            error,
            FlowError::QuicEndpoint {
                category: QuicEndpointErrorCategory::TlsAuthentication,
                ..
            }
        ));
    }

    #[cfg(feature = "quic-endpoint")]
    #[test]
    fn driver_tracks_three_packet_number_spaces_separately() {
        use std::{collections::VecDeque, time::Instant};

        use super::{
            QuicEndpointDatagram, QuicEndpointDriver, QuicEndpointEvent, QuicEndpointEventMapper,
            QuicEndpointLifecycle, QuicEndpointPacketSpaceCounts, QuicEndpointPacketSpaceState,
            QuicEndpointRecoveryCounts, QuicEndpointSnapshot, QuicEndpointStreamId,
            QuicEndpointStreamRead, QuicEndpointTransmit, QuicEndpointTransmitPacketCounts,
        };
        use crate::{PacketContext, Result};

        struct PacketSpaceDriver {
            snapshots: VecDeque<(QuicEndpointEvent, QuicEndpointSnapshot)>,
            current: QuicEndpointSnapshot,
        }

        impl QuicEndpointDriver for PacketSpaceDriver {
            fn start(&mut self, _: Instant) -> Result<()> {
                Ok(())
            }
            fn handle_datagram(&mut self, _: QuicEndpointDatagram) -> Result<()> {
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
            fn poll_events(&mut self) -> Result<Vec<QuicEndpointEvent>> {
                let Some((event, snapshot)) = self.snapshots.pop_front() else {
                    return Ok(Vec::new());
                };
                self.current = snapshot;
                Ok(vec![event])
            }
            fn open_bidirectional_stream(&mut self) -> Result<QuicEndpointStreamId> {
                Ok(QuicEndpointStreamId(0))
            }
            fn write_stream(&mut self, _: QuicEndpointStreamId, bytes: &[u8]) -> Result<usize> {
                Ok(bytes.len())
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
                self.current.clone()
            }
            fn close(&mut self, _: Instant, _: u64, _: &[u8]) -> Result<()> {
                Ok(())
            }
        }

        fn snapshot(
            lifecycle: QuicEndpointLifecycle,
            initial: QuicEndpointPacketSpaceCounts,
            handshake: QuicEndpointPacketSpaceCounts,
            application: QuicEndpointPacketSpaceCounts,
        ) -> QuicEndpointSnapshot {
            QuicEndpointSnapshot {
                lifecycle,
                local_connection_id: vec![0x11; 8],
                peer_connection_id: vec![0x22; 8],
                initial,
                handshake,
                application,
                stream_bytes_sent: 0,
                stream_bytes_received: 0,
                recovery: QuicEndpointRecoveryCounts::default(),
            }
        }

        let initial = QuicEndpointPacketSpaceCounts {
            sent: 1,
            received: 1,
            ..QuicEndpointPacketSpaceCounts::default()
        };
        let initial_discarded = QuicEndpointPacketSpaceCounts {
            acknowledged: 1,
            discarded: 1,
            state: QuicEndpointPacketSpaceState::Discarded,
            ..initial
        };
        let handshake = QuicEndpointPacketSpaceCounts {
            sent: 2,
            received: 1,
            acknowledged: 1,
            lost: 1,
            ..QuicEndpointPacketSpaceCounts::default()
        };
        let handshake_discarded = QuicEndpointPacketSpaceCounts {
            discarded: 1,
            state: QuicEndpointPacketSpaceState::Discarded,
            ..handshake
        };
        let application = QuicEndpointPacketSpaceCounts {
            sent: 3,
            received: 2,
            acknowledged: 1,
            lost: 1,
            ..QuicEndpointPacketSpaceCounts::default()
        };

        let starting = snapshot(
            QuicEndpointLifecycle::InitialSent,
            initial,
            QuicEndpointPacketSpaceCounts::default(),
            QuicEndpointPacketSpaceCounts::default(),
        );
        let mut driver = PacketSpaceDriver {
            current: starting.clone(),
            snapshots: VecDeque::from([
                (QuicEndpointEvent::HandshakeProgress, starting),
                (
                    QuicEndpointEvent::HandshakeProgress,
                    snapshot(
                        QuicEndpointLifecycle::Handshaking,
                        initial_discarded,
                        handshake,
                        QuicEndpointPacketSpaceCounts::default(),
                    ),
                ),
                (
                    QuicEndpointEvent::Established,
                    snapshot(
                        QuicEndpointLifecycle::Established,
                        initial_discarded,
                        handshake_discarded,
                        application,
                    ),
                ),
            ]),
        };
        let mut mapper = QuicEndpointEventMapper::new(QuicEndpointLifecycle::InitialSent);
        let mut context = PacketContext::new();

        mapper.poll(&mut driver, &mut context).unwrap();
        assert_eq!(
            context
                .get_namespaced_u64("quic", "packet_spaces.initial.sent")
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            context
                .get_namespaced_u64("quic", "packet_spaces.handshake.sent")
                .unwrap(),
            Some(0)
        );

        mapper.poll(&mut driver, &mut context).unwrap();
        assert_eq!(
            context
                .get_namespaced_bool("quic", "packet_spaces.initial.discarded_state")
                .unwrap(),
            Some(true)
        );
        assert_eq!(
            context
                .get_namespaced_u64("quic", "packet_spaces.handshake.lost")
                .unwrap(),
            Some(1)
        );

        mapper.poll(&mut driver, &mut context).unwrap();
        assert_eq!(
            context
                .get_namespaced_u64("quic", "packet_spaces.initial.acknowledged")
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            context
                .get_namespaced_u64("quic", "packet_spaces.handshake.discarded")
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            context
                .get_namespaced_u64("quic", "packet_spaces.application.sent")
                .unwrap(),
            Some(3)
        );
        assert_eq!(
            context
                .get_namespaced_bool("quic", "packet_spaces.application.active")
                .unwrap(),
            Some(true)
        );

        assert_eq!(
            QuicEndpointTransmitPacketCounts::classify_single(&[0xc0, 0, 0, 0, 1], false),
            QuicEndpointTransmitPacketCounts {
                initial: 1,
                ..QuicEndpointTransmitPacketCounts::default()
            }
        );
        assert_eq!(
            QuicEndpointTransmitPacketCounts::classify_single(&[0xe0, 0, 0, 0, 1], false),
            QuicEndpointTransmitPacketCounts {
                handshake: 1,
                ..QuicEndpointTransmitPacketCounts::default()
            }
        );
        assert_eq!(
            QuicEndpointTransmitPacketCounts::classify_single(&[0x40], false),
            QuicEndpointTransmitPacketCounts::default()
        );
        assert_eq!(
            QuicEndpointTransmitPacketCounts::classify_single(&[0x40], true),
            QuicEndpointTransmitPacketCounts {
                application: 1,
                ..QuicEndpointTransmitPacketCounts::default()
            }
        );
        assert!(context
            .summary()
            .contains("quic::packet_spaces.initial.discarded_state"));
        assert!(context
            .summary()
            .contains("quic::packet_spaces.application.sent"));
    }

    #[cfg(feature = "quic-endpoint")]
    #[test]
    fn tls_authentication_failures_are_bounded_and_redacted() {
        use std::{collections::VecDeque, net::SocketAddr, time::Instant};

        use super::{
            map_provider_tls_authentication_failure, QuicEndpointAddresses, QuicEndpointDatagram,
            QuicEndpointDriver, QuicEndpointEvent, QuicEndpointEventMapper, QuicEndpointLifecycle,
            QuicEndpointPacketSpaceCounts, QuicEndpointRecoveryCounts, QuicEndpointSnapshot,
            QuicEndpointStreamId, QuicEndpointStreamRead, QuicEndpointTransmit,
            QuicEndpointTransmitPacketCounts, QuicTlsAuthenticationFailure,
        };
        use crate::{step::SendIntent, FlowOutcome, FlowReport, PacketContext, Result, Role};

        struct AuthenticationFailureDriver {
            events: VecDeque<QuicEndpointEvent>,
            transmits: Vec<QuicEndpointTransmit>,
            snapshot: QuicEndpointSnapshot,
        }

        impl QuicEndpointDriver for AuthenticationFailureDriver {
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
                None
            }

            fn handle_timeout(&mut self, _: Instant) -> Result<()> {
                Ok(())
            }

            fn poll_events(&mut self) -> Result<Vec<QuicEndpointEvent>> {
                Ok(self.events.drain(..).collect())
            }

            fn open_bidirectional_stream(&mut self) -> Result<QuicEndpointStreamId> {
                unreachable!("authentication failed before stream creation")
            }

            fn write_stream(&mut self, _: QuicEndpointStreamId, _: &[u8]) -> Result<usize> {
                unreachable!("authentication failed before stream creation")
            }

            fn finish_stream(&mut self, _: QuicEndpointStreamId) -> Result<()> {
                unreachable!("authentication failed before stream creation")
            }

            fn read_stream(
                &mut self,
                _: QuicEndpointStreamId,
                _: usize,
            ) -> Result<QuicEndpointStreamRead> {
                unreachable!("authentication failed before stream creation")
            }

            fn snapshot(&self) -> QuicEndpointSnapshot {
                self.snapshot.clone()
            }

            fn close(&mut self, _: Instant, _: u64, _: &[u8]) -> Result<()> {
                Ok(())
            }
        }

        let local: SocketAddr = "192.0.2.10:4433".parse().unwrap();
        let peer: SocketAddr = "198.51.100.20:4433".parse().unwrap();
        let addresses = QuicEndpointAddresses::new(local, peer);
        let cases = [
            (
                QuicTlsAuthenticationFailure::PeerNameMismatch,
                "peer-name-mismatch",
            ),
            (
                QuicTlsAuthenticationFailure::UnknownIssuer,
                "unknown-issuer",
            ),
            (
                QuicTlsAuthenticationFailure::CertificateExpired,
                "certificate-expired",
            ),
            (
                QuicTlsAuthenticationFailure::MalformedCertificate,
                "malformed-certificate",
            ),
            (QuicTlsAuthenticationFailure::AlpnMismatch, "alpn-mismatch"),
            (
                QuicTlsAuthenticationFailure::HandshakeAlert,
                "handshake-alert",
            ),
        ];
        let secret = "certificate=deadbeef private-key=feedface alert=attacker-controlled";

        for (index, (failure, expected_category)) in cases.into_iter().enumerate() {
            let emits_close = index % 2 == 0;
            let event = map_provider_tls_authentication_failure(
                failure,
                emits_close.then_some(0x12a),
                secret.to_string(),
            );
            assert!(!format!("{event:?}").contains(secret));

            let transmits = if emits_close {
                vec![QuicEndpointTransmit {
                    source_ip: "192.0.2.10".parse().unwrap(),
                    source_port: 4433,
                    destination_ip: "198.51.100.20".parse().unwrap(),
                    destination_port: 4433,
                    payload: vec![0x40, index as u8, 0xaa],
                    packet_counts: QuicEndpointTransmitPacketCounts {
                        application: 1,
                        ..Default::default()
                    },
                }]
            } else {
                Vec::new()
            };
            let snapshot = QuicEndpointSnapshot {
                lifecycle: QuicEndpointLifecycle::Handshaking,
                local_connection_id: vec![0x11; 8],
                peer_connection_id: vec![0x22; 8],
                initial: QuicEndpointPacketSpaceCounts::default(),
                handshake: QuicEndpointPacketSpaceCounts::default(),
                application: QuicEndpointPacketSpaceCounts::default(),
                stream_bytes_sent: 0,
                stream_bytes_received: 0,
                recovery: QuicEndpointRecoveryCounts::default(),
            };
            let mut driver = AuthenticationFailureDriver {
                events: VecDeque::from([QuicEndpointEvent::HandshakeProgress, event]),
                transmits,
                snapshot,
            };
            let mut mapper = QuicEndpointEventMapper::new(QuicEndpointLifecycle::InitialSent);
            let mut context = PacketContext::new();

            let (_, step) = mapper
                .poll_and_drain_transmits(&mut driver, Instant::now(), addresses, &mut context)
                .unwrap();

            assert!(!mapper.authenticated_handshake());
            assert_eq!(
                context
                    .get_namespaced_bool("quic", "handshake.established")
                    .unwrap(),
                Some(false)
            );
            assert_eq!(
                context
                    .get_namespaced_string("quic", "tuple.local")
                    .unwrap(),
                Some(local.to_string().as_str())
            );
            assert_eq!(
                context.get_namespaced_string("quic", "tuple.peer").unwrap(),
                Some(peer.to_string().as_str())
            );
            let observed = context.protocol_snapshot().unwrap();
            assert_eq!(
                observed.lifecycle,
                if emits_close { "closing" } else { "closed" }
            );
            assert_eq!(
                observed.outcome.as_deref(),
                Some("tls-authentication-failed")
            );
            assert_eq!(observed.error_category.as_deref(), Some(expected_category));
            assert_eq!(
                observed.error_context.as_deref(),
                Some("authenticating QUIC peer")
            );
            assert_eq!(
                observed.local_connection_id.as_deref(),
                Some(&[0x11; 8][..])
            );
            assert_eq!(observed.peer_connection_id.as_deref(), Some(&[0x22; 8][..]));
            assert_eq!(step.outputs().len(), usize::from(emits_close));
            for output in step.outputs() {
                assert_eq!(output.intent(), SendIntent::ReplyExpectedRegenerationOnly);
            }

            let report = FlowReport::new(
                "quic authentication failure",
                Role::Initiator,
                true,
                vec!["Handshaking".to_string(), observed.lifecycle.clone()],
                step.outputs().len(),
                1,
                Vec::new(),
                1,
                std::time::Duration::ZERO,
                FlowOutcome::Completed,
                context.summary(),
            )
            .with_protocol_snapshot(Some(observed.clone()));
            for rendered in [report.summary(), report.show(), report.to_json()] {
                assert!(rendered.contains(expected_category));
                assert!(!rendered.contains("deadbeef"));
                assert!(!rendered.contains("feedface"));
                assert!(!rendered.contains("attacker-controlled"));
            }
        }
    }

    #[cfg(feature = "quic-endpoint")]
    #[test]
    fn client_opens_one_bidi_stream_after_authentication() {
        use std::{collections::VecDeque, time::Instant};

        use super::{
            QuicEndpointClientRequest, QuicEndpointDatagram, QuicEndpointDriver, QuicEndpointEvent,
            QuicEndpointLifecycle, QuicEndpointPacketSpaceCounts, QuicEndpointRecoveryCounts,
            QuicEndpointSnapshot, QuicEndpointStreamId, QuicEndpointStreamRead,
            QuicEndpointTransmit,
        };
        use crate::{context::ProtocolContextSnapshot, PacketContext, Result};

        struct ClientStreamDriver {
            capacities: VecDeque<usize>,
            opened: usize,
            accepted: Vec<u8>,
            finished: usize,
        }

        impl ClientStreamDriver {
            fn new(capacities: impl IntoIterator<Item = usize>) -> Self {
                Self {
                    capacities: capacities.into_iter().collect(),
                    opened: 0,
                    accepted: Vec::new(),
                    finished: 0,
                }
            }
        }

        impl QuicEndpointDriver for ClientStreamDriver {
            fn start(&mut self, _: Instant) -> Result<()> {
                Ok(())
            }

            fn handle_datagram(&mut self, _: QuicEndpointDatagram) -> Result<()> {
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

            fn poll_events(&mut self) -> Result<Vec<QuicEndpointEvent>> {
                Ok(Vec::new())
            }

            fn open_bidirectional_stream(&mut self) -> Result<QuicEndpointStreamId> {
                let stream = QuicEndpointStreamId((self.opened as u64) * 4);
                self.opened += 1;
                Ok(stream)
            }

            fn write_stream(&mut self, _: QuicEndpointStreamId, bytes: &[u8]) -> Result<usize> {
                let accepted = self.capacities.pop_front().unwrap_or(0).min(bytes.len());
                self.accepted.extend_from_slice(&bytes[..accepted]);
                Ok(accepted)
            }

            fn finish_stream(&mut self, _: QuicEndpointStreamId) -> Result<()> {
                self.finished += 1;
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
                    lifecycle: QuicEndpointLifecycle::Established,
                    local_connection_id: Vec::new(),
                    peer_connection_id: Vec::new(),
                    initial: QuicEndpointPacketSpaceCounts::default(),
                    handshake: QuicEndpointPacketSpaceCounts::default(),
                    application: QuicEndpointPacketSpaceCounts::default(),
                    stream_bytes_sent: self.accepted.len() as u64,
                    stream_bytes_received: 0,
                    recovery: QuicEndpointRecoveryCounts::default(),
                }
            }

            fn close(&mut self, _: Instant, _: u64, _: &[u8]) -> Result<()> {
                Ok(())
            }
        }

        fn established_context() -> PacketContext {
            let mut context = PacketContext::new();
            context.set_protocol_snapshot(ProtocolContextSnapshot::new("quic", "established"));
            context
                .insert_namespaced_bool("quic", "handshake.authenticated", true)
                .unwrap();
            context
                .insert_namespaced_string("quic", "transport.validation", "validated")
                .unwrap();
            context
        }

        let request = b"opaque request bytes".to_vec();
        let mut driver = ClientStreamDriver::new([4, 0, 7, usize::MAX]);
        let mut context = established_context();
        let mut operation = QuicEndpointClientRequest::new(request.clone(), 64);

        assert!(!operation.drive(&mut driver, &mut context).unwrap());
        assert!(!operation.drive(&mut driver, &mut context).unwrap());
        assert!(!operation.drive(&mut driver, &mut context).unwrap());
        assert!(operation.drive(&mut driver, &mut context).unwrap());
        assert_eq!(driver.opened, 1);
        assert_eq!(driver.accepted, request);
        assert_eq!(driver.finished, 1);
        assert_eq!(
            context
                .get_namespaced_u64("quic", "application.request_bytes_sent")
                .unwrap(),
            Some(request.len() as u64)
        );
        assert_eq!(
            context
                .get_namespaced_bool("quic", "application.request_complete")
                .unwrap(),
            Some(true)
        );

        let second = operation.drive(&mut driver, &mut context).unwrap_err();
        assert!(second
            .to_string()
            .contains("second client application stream"));
        assert_eq!(driver.opened, 1);

        let mut before_authentication = PacketContext::new();
        let mut driver = ClientStreamDriver::new([usize::MAX]);
        let error = QuicEndpointClientRequest::new(b"early".to_vec(), 64)
            .drive(&mut driver, &mut before_authentication)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("before authenticated establishment"));
        assert_eq!(driver.opened, 0);

        let mut driver = ClientStreamDriver::new([usize::MAX]);
        let error = QuicEndpointClientRequest::new(b"early".to_vec(), 64)
            .with_zero_rtt_attempt(true)
            .drive(&mut driver, &mut established_context())
            .unwrap_err();
        assert!(error.to_string().contains("0-RTT"));
        assert_eq!(driver.opened, 0);

        let mut driver = ClientStreamDriver::new([usize::MAX]);
        let error = QuicEndpointClientRequest::new(vec![0; 65], 64)
            .drive(&mut driver, &mut established_context())
            .unwrap_err();
        assert!(error.to_string().contains("oversized client request"));
        assert_eq!(driver.opened, 0);
    }
}
