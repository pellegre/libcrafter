//! Deterministic configuration for bounded QUIC Initial-only flows.

use std::net::SocketAddrV4;

use crafter::{QuicConnectionId, QUIC_VERSION_1};

use crate::{docaddr, FlowError, Result};

const DEFAULT_CLIENT_PORT: u16 = 49_152;
const DEFAULT_SERVER_PORT: u16 = 443;
const MIN_INITIAL_CONNECTION_ID_LEN: usize = 8;
const MAX_INITIAL_CONNECTION_ID_LEN: usize = 20;
const MAX_CONFIGURED_CRYPTO_BYTES: usize = 64 * 1024;

/// Policy applied when a client observes Version Negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicInitialVersionPolicy {
    /// Reject Version Negotiation and require the configured QUIC v1 exchange.
    Version1Only,
    /// Permit negotiation only when the peer advertises QUIC version 1.
    SelectVersion1,
}

/// Policy applied to Retry packets in an Initial-only exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicInitialRetryPolicy {
    /// Do not request or accept Retry behavior.
    Disabled,
    /// Accept and act on one Retry only after its integrity tag validates.
    AcceptValid,
    /// Require the server side to issue one Retry before inspecting an Initial.
    Require,
}

/// Deterministic resource bounds shared by Initial-only client and server flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicInitialBounds {
    /// Maximum CRYPTO-frame bytes accepted from configuration or a peer.
    pub max_crypto_bytes: usize,
    /// Maximum UDP datagrams processed by the bounded exchange.
    pub max_datagrams: usize,
    /// Maximum Retry packets processed by the bounded exchange.
    pub max_retries: usize,
}

impl Default for QuicInitialBounds {
    fn default() -> Self {
        Self {
            max_crypto_bytes: 4 * 1024,
            max_datagrams: 8,
            max_retries: 1,
        }
    }
}

/// Configuration for a deterministic QUIC v1 Initial-only client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicInitialClientConfig {
    /// Local IPv4 address and UDP port.
    pub local: SocketAddrV4,
    /// Peer IPv4 address and UDP port.
    pub peer: SocketAddrV4,
    /// QUIC version; Initial-only flows currently accept only version 1.
    pub version: u32,
    /// Destination connection ID used by the first client Initial.
    pub original_destination_connection_id: QuicConnectionId,
    /// Source connection ID selected by the client.
    pub local_connection_id: QuicConnectionId,
    /// Expected source connection ID selected by the server.
    pub peer_connection_id: QuicConnectionId,
    /// First packet number in the client's Initial packet-number space.
    pub initial_packet_number_seed: u64,
    /// Opaque deterministic CRYPTO-frame bytes.
    pub crypto: Vec<u8>,
    /// Version Negotiation behavior.
    pub version_policy: QuicInitialVersionPolicy,
    /// Retry behavior.
    pub retry_policy: QuicInitialRetryPolicy,
    /// Resource and exchange bounds.
    pub bounds: QuicInitialBounds,
}

impl Default for QuicInitialClientConfig {
    fn default() -> Self {
        Self {
            local: SocketAddrV4::new(docaddr::CLIENT_IPV4, DEFAULT_CLIENT_PORT),
            peer: SocketAddrV4::new(docaddr::SERVER_IPV4, DEFAULT_SERVER_PORT),
            version: QUIC_VERSION_1,
            original_destination_connection_id: QuicConnectionId::from_bytes([0x83; 8]),
            local_connection_id: QuicConnectionId::from_bytes([0xc1; 8]),
            peer_connection_id: QuicConnectionId::from_bytes([0x51; 8]),
            initial_packet_number_seed: 0,
            crypto: b"deterministic client Initial".to_vec(),
            version_policy: QuicInitialVersionPolicy::Version1Only,
            retry_policy: QuicInitialRetryPolicy::AcceptValid,
            bounds: QuicInitialBounds::default(),
        }
    }
}

impl QuicInitialClientConfig {
    /// Validate the bounded QUIC v1 Initial-only client contract.
    pub fn validate(&self) -> Result<()> {
        validate_common(
            self.local,
            self.peer,
            self.version,
            [
                &self.original_destination_connection_id,
                &self.local_connection_id,
                &self.peer_connection_id,
            ],
            &self.crypto,
            self.bounds,
        )?;
        if self.retry_policy == QuicInitialRetryPolicy::Require {
            return Err(FlowError::Build(
                "QUIC Initial clients cannot require server Retry behavior".to_string(),
            ));
        }
        Ok(())
    }
}

/// Configuration for a deterministic QUIC v1 Initial-only server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicInitialServerConfig {
    /// Local IPv4 address and UDP listen port.
    pub local: SocketAddrV4,
    /// Expected peer IPv4 address and UDP port for the bounded exchange.
    pub peer: SocketAddrV4,
    /// QUIC version; Initial-only flows currently accept only version 1.
    pub version: u32,
    /// Destination connection ID expected on the first client Initial.
    pub original_destination_connection_id: QuicConnectionId,
    /// Source connection ID selected by the server.
    pub local_connection_id: QuicConnectionId,
    /// Expected source connection ID selected by the client.
    pub peer_connection_id: QuicConnectionId,
    /// First packet number in the server's Initial packet-number space.
    pub initial_packet_number_seed: u64,
    /// Opaque deterministic CRYPTO-frame bytes.
    pub crypto: Vec<u8>,
    /// Version Negotiation behavior.
    pub version_policy: QuicInitialVersionPolicy,
    /// Retry behavior.
    pub retry_policy: QuicInitialRetryPolicy,
    /// Resource and exchange bounds.
    pub bounds: QuicInitialBounds,
}

impl Default for QuicInitialServerConfig {
    fn default() -> Self {
        Self {
            local: SocketAddrV4::new(docaddr::SERVER_IPV4, DEFAULT_SERVER_PORT),
            peer: SocketAddrV4::new(docaddr::CLIENT_IPV4, DEFAULT_CLIENT_PORT),
            version: QUIC_VERSION_1,
            original_destination_connection_id: QuicConnectionId::from_bytes([0x83; 8]),
            local_connection_id: QuicConnectionId::from_bytes([0x51; 8]),
            peer_connection_id: QuicConnectionId::from_bytes([0xc1; 8]),
            initial_packet_number_seed: 0,
            crypto: b"deterministic server Initial".to_vec(),
            version_policy: QuicInitialVersionPolicy::Version1Only,
            retry_policy: QuicInitialRetryPolicy::Disabled,
            bounds: QuicInitialBounds::default(),
        }
    }
}

impl QuicInitialServerConfig {
    /// Validate the bounded QUIC v1 Initial-only server contract.
    pub fn validate(&self) -> Result<()> {
        validate_common(
            self.local,
            self.peer,
            self.version,
            [
                &self.original_destination_connection_id,
                &self.local_connection_id,
                &self.peer_connection_id,
            ],
            &self.crypto,
            self.bounds,
        )?;
        if self.retry_policy == QuicInitialRetryPolicy::AcceptValid {
            return Err(FlowError::Build(
                "QUIC Initial servers cannot use the client Retry policy".to_string(),
            ));
        }
        Ok(())
    }
}

fn validate_common(
    local: SocketAddrV4,
    peer: SocketAddrV4,
    version: u32,
    connection_ids: [&QuicConnectionId; 3],
    crypto: &[u8],
    bounds: QuicInitialBounds,
) -> Result<()> {
    if version != QUIC_VERSION_1 {
        return Err(FlowError::Build(
            "QUIC Initial-only flows support version 1 only".to_string(),
        ));
    }
    if local.port() == 0 || peer.port() == 0 {
        return Err(FlowError::Build(
            "QUIC Initial UDP ports must be nonzero".to_string(),
        ));
    }
    for connection_id in connection_ids {
        if !(MIN_INITIAL_CONNECTION_ID_LEN..=MAX_INITIAL_CONNECTION_ID_LEN)
            .contains(&connection_id.len())
        {
            return Err(FlowError::Build(format!(
                "QUIC Initial connection IDs must be {MIN_INITIAL_CONNECTION_ID_LEN}..={MAX_INITIAL_CONNECTION_ID_LEN} bytes"
            )));
        }
    }
    if bounds.max_crypto_bytes == 0
        || bounds.max_crypto_bytes > MAX_CONFIGURED_CRYPTO_BYTES
        || crypto.len() > bounds.max_crypto_bytes
    {
        return Err(FlowError::Build(format!(
            "QUIC Initial CRYPTO bytes must fit a nonzero bound no larger than {MAX_CONFIGURED_CRYPTO_BYTES}"
        )));
    }
    if bounds.max_datagrams == 0 {
        return Err(FlowError::Build(
            "QUIC Initial datagram bound must be nonzero".to_string(),
        ));
    }
    if bounds.max_retries > 1 {
        return Err(FlowError::Build(
            "QUIC Initial-only flows permit at most one Retry".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_documentation_addressed_and_valid() {
        let client = QuicInitialClientConfig::default();
        let server = QuicInitialServerConfig::default();

        assert_eq!(*client.local.ip(), docaddr::CLIENT_IPV4);
        assert_eq!(*client.peer.ip(), docaddr::SERVER_IPV4);
        assert_eq!(server.local, client.peer);
        assert_eq!(server.peer, client.local);
        assert!(client.validate().is_ok());
        assert!(server.validate().is_ok());
    }

    #[test]
    fn validation_rejects_unbounded_or_non_v1_configuration() {
        let mut client = QuicInitialClientConfig::default();
        client.version = crafter::QUIC_VERSION_2;
        assert!(client.validate().is_err());

        let mut server = QuicInitialServerConfig::default();
        server.bounds.max_crypto_bytes = 1;
        assert!(server.validate().is_err());
    }
}
