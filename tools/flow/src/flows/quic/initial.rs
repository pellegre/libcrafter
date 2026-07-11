//! Deterministic configuration for bounded QUIC Initial-only flows.

use std::net::SocketAddrV4;

use crafter::{QuicConnectionId, QuicPacketNumber, QUIC_VERSION_1};

use crate::{docaddr, FlowError, Result};

const DEFAULT_CLIENT_PORT: u16 = 49_152;
const DEFAULT_SERVER_PORT: u16 = 443;
const MIN_INITIAL_CONNECTION_ID_LEN: usize = 8;
const MAX_INITIAL_CONNECTION_ID_LEN: usize = 20;
const MAX_CONFIGURED_CRYPTO_BYTES: usize = 64 * 1024;
const QUIC_PACKET_NUMBER_LIMIT: u64 = 1 << 62;

/// Reproducible connection identity and packet-number state for Initial-only flows.
///
/// Full QUIC endpoint flows must use their provider's randomness instead. This
/// value exists for offline packet inspection, fixtures, and documentation
/// examples where byte-for-byte reproducibility is useful.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicInitialIdentifiers {
    original_destination_connection_id: QuicConnectionId,
    current_destination_connection_id: QuicConnectionId,
    local_source_connection_id: QuicConnectionId,
    peer_source_connection_id: QuicConnectionId,
    retry_token: Vec<u8>,
    next_initial_packet_number: u64,
    packet_number_encoded_len: usize,
}

impl QuicInitialIdentifiers {
    /// Construct explicit Initial-only identity state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        original_destination_connection_id: QuicConnectionId,
        current_destination_connection_id: QuicConnectionId,
        local_source_connection_id: QuicConnectionId,
        peer_source_connection_id: QuicConnectionId,
        retry_token: Vec<u8>,
        next_initial_packet_number: u64,
        packet_number_encoded_len: usize,
    ) -> Result<Self> {
        let identifiers = Self {
            original_destination_connection_id,
            current_destination_connection_id,
            local_source_connection_id,
            peer_source_connection_id,
            retry_token,
            next_initial_packet_number,
            packet_number_encoded_len,
        };
        identifiers.validate()?;
        Ok(identifiers)
    }

    /// Documentation-safe client identity state for tests and examples.
    pub fn documentation_client() -> Self {
        Self::new(
            QuicConnectionId::from_bytes([0x83; 8]),
            QuicConnectionId::from_bytes([0x83; 8]),
            QuicConnectionId::from_bytes([0xc1; 8]),
            QuicConnectionId::from_bytes([0x51; 8]),
            Vec::new(),
            0,
            2,
        )
        .expect("documentation client identifiers are valid")
    }

    /// Documentation-safe server identity state for tests and examples.
    pub fn documentation_server() -> Self {
        Self::new(
            QuicConnectionId::from_bytes([0x83; 8]),
            QuicConnectionId::from_bytes([0x83; 8]),
            QuicConnectionId::from_bytes([0x51; 8]),
            QuicConnectionId::from_bytes([0xc1; 8]),
            Vec::new(),
            0,
            2,
        )
        .expect("documentation server identifiers are valid")
    }

    /// Destination ID from the first client Initial, retained across Retry.
    pub fn original_destination_connection_id(&self) -> &QuicConnectionId {
        &self.original_destination_connection_id
    }

    /// Destination ID to use for the next Initial packet.
    pub fn current_destination_connection_id(&self) -> &QuicConnectionId {
        &self.current_destination_connection_id
    }

    /// Source ID selected by this flow role.
    pub fn local_source_connection_id(&self) -> &QuicConnectionId {
        &self.local_source_connection_id
    }

    /// Source ID expected from the peer flow role.
    pub fn peer_source_connection_id(&self) -> &QuicConnectionId {
        &self.peer_source_connection_id
    }

    /// Retry token bytes, kept separate from connection identifiers.
    pub fn retry_token(&self) -> &[u8] {
        &self.retry_token
    }

    /// Full packet number that will be assigned to the next Initial.
    pub const fn next_initial_packet_number(&self) -> u64 {
        self.next_initial_packet_number
    }

    /// Explicit width selected for the truncated wire packet number.
    pub const fn packet_number_encoded_len(&self) -> usize {
        self.packet_number_encoded_len
    }

    /// Consume the next full packet number and return its explicit wire value.
    pub fn take_next_initial_packet_number(&mut self) -> Result<(u64, QuicPacketNumber)> {
        if self.next_initial_packet_number >= QUIC_PACKET_NUMBER_LIMIT {
            return Err(FlowError::Build(
                "QUIC Initial packet number exceeds the 62-bit limit".to_string(),
            ));
        }
        let full = self.next_initial_packet_number;
        let mask = (1u64 << (self.packet_number_encoded_len * 8)) - 1;
        let encoded =
            QuicPacketNumber::new(full & mask).with_encoded_len(self.packet_number_encoded_len);
        self.next_initial_packet_number += 1;
        Ok((full, encoded))
    }

    /// Apply a validated Retry without replacing the original destination ID.
    pub fn apply_valid_retry(
        &mut self,
        destination_connection_id: QuicConnectionId,
        retry_token: Vec<u8>,
    ) -> Result<()> {
        validate_connection_id(&destination_connection_id)?;
        self.current_destination_connection_id = destination_connection_id;
        self.retry_token = retry_token;
        Ok(())
    }

    /// Stable non-secret inspection text. Retry token bytes are intentionally omitted.
    pub fn summary(&self) -> String {
        format!(
            "odcid={} dcid={} local_scid={} peer_scid={} next_initial_packet_number={} encoded_len={}",
            self.original_destination_connection_id,
            self.current_destination_connection_id,
            self.local_source_connection_id,
            self.peer_source_connection_id,
            self.next_initial_packet_number,
            self.packet_number_encoded_len,
        )
    }

    fn validate(&self) -> Result<()> {
        for connection_id in [
            &self.original_destination_connection_id,
            &self.current_destination_connection_id,
            &self.local_source_connection_id,
            &self.peer_source_connection_id,
        ] {
            validate_connection_id(connection_id)?;
        }
        if !(1..=4).contains(&self.packet_number_encoded_len) {
            return Err(FlowError::Build(
                "QUIC Initial packet-number encoded length must be 1..=4 bytes".to_string(),
            ));
        }
        if self.next_initial_packet_number >= QUIC_PACKET_NUMBER_LIMIT {
            return Err(FlowError::Build(
                "QUIC Initial packet number exceeds the 62-bit limit".to_string(),
            ));
        }
        Ok(())
    }
}

fn validate_connection_id(connection_id: &QuicConnectionId) -> Result<()> {
    if !(MIN_INITIAL_CONNECTION_ID_LEN..=MAX_INITIAL_CONNECTION_ID_LEN)
        .contains(&connection_id.len())
    {
        return Err(FlowError::Build(format!(
            "QUIC Initial connection IDs must be {MIN_INITIAL_CONNECTION_ID_LEN}..={MAX_INITIAL_CONNECTION_ID_LEN} bytes"
        )));
    }
    Ok(())
}

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
    /// Explicit reproducible Initial-only identity state.
    pub identifiers: QuicInitialIdentifiers,
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
            identifiers: QuicInitialIdentifiers::documentation_client(),
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
            &self.crypto,
            self.bounds,
        )?;
        self.identifiers.validate()?;
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
    /// Explicit reproducible Initial-only identity state.
    pub identifiers: QuicInitialIdentifiers,
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
            identifiers: QuicInitialIdentifiers::documentation_server(),
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
            &self.crypto,
            self.bounds,
        )?;
        self.identifiers.validate()?;
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
    fn initial_identifiers_are_deterministic_and_distinct() {
        let mut client = QuicInitialIdentifiers::documentation_client();
        let client_again = QuicInitialIdentifiers::documentation_client();
        let server = QuicInitialIdentifiers::documentation_server();

        assert_eq!(client, client_again);
        assert_eq!(
            client.original_destination_connection_id(),
            client.current_destination_connection_id()
        );
        assert_ne!(
            client.local_source_connection_id(),
            client.peer_source_connection_id()
        );
        assert_eq!(
            client.local_source_connection_id(),
            server.peer_source_connection_id()
        );
        assert_eq!(
            client.peer_source_connection_id(),
            server.local_source_connection_id()
        );

        let (full_zero, encoded_zero) = client.take_next_initial_packet_number().unwrap();
        let (full_one, encoded_one) = client.take_next_initial_packet_number().unwrap();
        assert_eq!(full_zero, 0);
        assert_eq!(encoded_zero.value(), 0);
        assert_eq!(encoded_zero.effective_encoded_len().unwrap(), 2);
        assert_eq!(full_one, 1);
        assert_eq!(encoded_one.value(), 1);
        assert_eq!(client.next_initial_packet_number(), 2);

        let original = client.original_destination_connection_id().clone();
        let retry_destination = QuicConnectionId::from_bytes([0xa5; 12]);
        let retry_token = b"opaque retry token".to_vec();
        client
            .apply_valid_retry(retry_destination.clone(), retry_token.clone())
            .unwrap();
        assert_eq!(client.original_destination_connection_id(), &original);
        assert_eq!(
            client.current_destination_connection_id(),
            &retry_destination
        );
        assert_eq!(client.retry_token(), retry_token);
        assert!(!client.summary().contains("opaque retry token"));

        let oversized = QuicInitialIdentifiers::new(
            QuicConnectionId::from_bytes([0xff; 21]),
            QuicConnectionId::from_bytes([0x83; 8]),
            QuicConnectionId::from_bytes([0xc1; 8]),
            QuicConnectionId::from_bytes([0x51; 8]),
            Vec::new(),
            0,
            2,
        );
        assert!(oversized.is_err());
    }

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
