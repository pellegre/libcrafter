//! Provider-neutral configuration for the private QUIC endpoint driver.

use std::{fmt, net::SocketAddr, time::Duration};

use crate::FlowError;

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
}
