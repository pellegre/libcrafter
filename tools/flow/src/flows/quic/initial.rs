//! Deterministic configuration for bounded QUIC Initial-only flows.

use std::{collections::BTreeSet, net::SocketAddrV4, time::Duration};

use crafter::{
    derive_quic_initial_secrets, QuicAckFrame, QuicAckRange, QuicConnectionCloseFrame,
    QuicConnectionId, QuicCryptoFrame, QuicFrame, QuicLongHeaderPacket, QuicPacketNumber,
    QUIC_VERSION_1,
};

use crate::context::ProtocolContextSnapshot;
use crate::flows::quic::{CLOSED, INITIAL_SENT};
use crate::quic_wire::{assemble_initial_datagram, QuicInitialPadding};
use crate::{docaddr, Flow, FlowBuilderExt, FlowError, FlowState, Result, Role, Step};

const DEFAULT_CLIENT_PORT: u16 = 49_152;
const DEFAULT_SERVER_PORT: u16 = 443;
const MIN_INITIAL_CONNECTION_ID_LEN: usize = 8;
const MAX_INITIAL_CONNECTION_ID_LEN: usize = 20;
const MAX_CONFIGURED_CRYPTO_BYTES: usize = 64 * 1024;
const QUIC_PACKET_NUMBER_LIMIT: u64 = 1 << 62;
const INITIAL_CLIENT_TIMEOUT: Duration = Duration::from_secs(1);
const INITIAL_ONLY_TIMEOUT_OUTCOME: &str = "initial-only-timeout";

/// Build the deterministic, bounded QUIC v1 Initial-only client flow.
pub fn quic_initial_client_flow(config: QuicInitialClientConfig) -> Result<Flow> {
    config.validate()?;

    let mut identifiers = config.identifiers.clone();
    let (full_packet_number, encoded_packet_number) =
        identifiers.take_next_initial_packet_number()?;
    let frames = build_initial_frames(
        &config.crypto,
        config.bounds.max_crypto_bytes,
        &BTreeSet::new(),
    )?;
    let initial = QuicLongHeaderPacket::initial_builder()
        .version(config.version)
        .destination_connection_id(identifiers.current_destination_connection_id().clone())
        .source_connection_id(identifiers.local_source_connection_id().clone())
        .token(identifiers.retry_token())
        .packet_number(encoded_packet_number)
        .frames(frames)
        .build()?;
    let keys = derive_quic_initial_secrets(
        config.version,
        identifiers.original_destination_connection_id().as_bytes(),
    )?
    .client_packet_keys()?;
    let packet = assemble_initial_datagram(
        config.local,
        config.peer,
        &initial,
        full_packet_number,
        &keys,
        identifiers.packet_number_encoded_len(),
        QuicInitialPadding::ClientMinimum,
    )?;

    let local = config.local;
    let peer = config.peer;
    let local_connection_id = identifiers.local_source_connection_id().as_bytes().to_vec();
    let peer_connection_id = identifiers.peer_source_connection_id().as_bytes().to_vec();
    let initial_sent = FlowState::new(INITIAL_SENT)
        .on_entry(move |context| {
            context.insert_namespaced_string("quic", "local_tuple", local.to_string())?;
            context.insert_namespaced_string("quic", "peer_tuple", peer.to_string())?;
            context.insert_namespaced_u64(
                "quic",
                "initial_packet_number_sent",
                full_packet_number,
            )?;

            let mut snapshot = ProtocolContextSnapshot::new("quic", INITIAL_SENT);
            snapshot.local_connection_id = Some(local_connection_id.clone());
            snapshot.peer_connection_id = Some(peer_connection_id.clone());
            context.set_protocol_snapshot(snapshot);

            Ok(Step::send_regeneration_only(packet.clone()).wake_after(INITIAL_CLIENT_TIMEOUT))
        })
        .entry_description("emit one protected minimum-size client Initial")
        .on_timeout(|context| {
            context.update_protocol_snapshot(|snapshot| {
                snapshot.lifecycle = CLOSED.to_string();
                snapshot.outcome = Some(INITIAL_ONLY_TIMEOUT_OUTCOME.to_string());
                snapshot.close_category = Some("timeout".to_string());
            });
            Ok(Step::done_with(INITIAL_ONLY_TIMEOUT_OUTCOME))
        })
        .timeout_description("close the bounded Initial-only exchange on timeout")
        .timeout_terminal();

    let flow = Flow::new("quic-initial-client")
        .role(Role::Initiator)
        .state(initial_sent)
        .initial(INITIAL_SENT);
    flow.validate()?;
    Ok(flow)
}

/// One parsed ACK together with the packet numbers represented by its ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuicInitialAckObservation {
    pub(crate) frame: QuicAckFrame,
    pub(crate) packet_number_ranges: Vec<(u64, u64)>,
}

/// Bounded, separated observations from one decrypted Initial payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct QuicInitialFrameObservations {
    pub(crate) acknowledgements: Vec<QuicInitialAckObservation>,
    pub(crate) crypto_chunks: Vec<QuicCryptoFrame>,
    pub(crate) close_frames: Vec<QuicConnectionCloseFrame>,
    pub(crate) unexpected_frames: Vec<QuicFrame>,
}

/// Build an ACK-before-CRYPTO sequence without adding datagram padding.
pub(crate) fn build_initial_frames(
    crypto: &[u8],
    max_crypto_bytes: usize,
    observed_packet_numbers: &BTreeSet<u64>,
) -> Result<Vec<QuicFrame>> {
    if crypto.len() > max_crypto_bytes {
        return Err(FlowError::Build(format!(
            "QUIC Initial CRYPTO data exceeds the configured {max_crypto_bytes}-byte bound"
        )));
    }

    let mut frames = Vec::with_capacity(2);
    if let Some(ack) = build_initial_ack_frame(observed_packet_numbers)? {
        frames.push(QuicFrame::from_ack_frame(ack)?);
    }
    frames.push(QuicFrame::from_crypto_frame(QuicCryptoFrame::from_values(
        0, crypto,
    )?)?);
    Ok(frames)
}

fn build_initial_ack_frame(observed: &BTreeSet<u64>) -> Result<Option<QuicAckFrame>> {
    let Some(&largest) = observed.last() else {
        return Ok(None);
    };
    if largest >= QUIC_PACKET_NUMBER_LIMIT {
        return Err(FlowError::Build(
            "observed QUIC Initial packet number exceeds the 62-bit limit".to_string(),
        ));
    }

    let mut ranges = Vec::new();
    let mut descending = observed.iter().rev().copied();
    let mut range_high = descending.next().expect("nonempty set has a largest value");
    let mut range_low = range_high;
    for packet_number in descending {
        if packet_number + 1 == range_low {
            range_low = packet_number;
        } else {
            ranges.push((range_low, range_high));
            range_high = packet_number;
            range_low = packet_number;
        }
    }
    ranges.push((range_low, range_high));

    let first_ack_range = ranges[0].1 - ranges[0].0;
    let mut encoded_ranges = Vec::with_capacity(ranges.len().saturating_sub(1));
    let mut previous_low = ranges[0].0;
    for &(low, high) in &ranges[1..] {
        let gap = previous_low - high - 2;
        encoded_ranges.push(QuicAckRange::from_values(gap, high - low)?);
        previous_low = low;
    }

    Ok(Some(QuicAckFrame::from_values(
        largest,
        0,
        first_ack_range,
        encoded_ranges,
    )?))
}

/// Separate decrypted Initial frames while preserving opaque frame bytes.
pub(crate) fn inspect_initial_frames(
    frames: &[QuicFrame],
    max_crypto_bytes: usize,
) -> Result<QuicInitialFrameObservations> {
    let mut observations = QuicInitialFrameObservations::default();
    let mut crypto_bytes = 0usize;

    for frame in frames {
        if frame.is_padding() {
            continue;
        }
        if let Some(ack) = frame.ack_frame()? {
            let packet_number_ranges = acknowledged_packet_number_ranges(&ack)?;
            observations
                .acknowledgements
                .push(QuicInitialAckObservation {
                    frame: ack,
                    packet_number_ranges,
                });
        } else if let Some(crypto) = frame.crypto_frame()? {
            crypto_bytes = crypto_bytes
                .checked_add(crypto.data().len())
                .ok_or_else(|| {
                    FlowError::Build("QUIC Initial CRYPTO observation length overflow".to_string())
                })?;
            if crypto_bytes > max_crypto_bytes {
                return Err(FlowError::Build(format!(
                    "QUIC Initial CRYPTO observations exceed the configured {max_crypto_bytes}-byte bound"
                )));
            }
            observations.crypto_chunks.push(crypto);
        } else if let Some(close) = frame.connection_close_frame()? {
            observations.close_frames.push(close);
        } else {
            observations.unexpected_frames.push(frame.clone());
        }
    }

    Ok(observations)
}

fn acknowledged_packet_number_ranges(ack: &QuicAckFrame) -> Result<Vec<(u64, u64)>> {
    let largest = ack.largest_acknowledged().value();
    let first_length = ack.first_ack_range().value();
    let mut low = largest.checked_sub(first_length).ok_or_else(|| {
        FlowError::Build(
            "QUIC Initial ACK first range exceeds its largest packet number".to_string(),
        )
    })?;
    let mut packet_number_ranges = vec![(low, largest)];

    for range in ack.ack_ranges() {
        let high = low
            .checked_sub(range.gap().value())
            .and_then(|value| value.checked_sub(2))
            .ok_or_else(|| {
                FlowError::Build("QUIC Initial ACK gap underflows packet-number space".to_string())
            })?;
        low = high
            .checked_sub(range.ack_range_length().value())
            .ok_or_else(|| {
                FlowError::Build(
                    "QUIC Initial ACK range underflows packet-number space".to_string(),
                )
            })?;
        packet_number_ranges.push((low, high));
    }

    Ok(packet_number_ranges)
}

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
    use crafter::{quic_decode_initial_protected_payload_with_keys, Ipv4, Quic, QuicVarInt, Udp};

    #[test]
    fn initial_client_starts_with_protected_minimum_datagram() -> crate::Result<()> {
        let config = QuicInitialClientConfig::default();
        let original_destination_connection_id = config
            .identifiers
            .original_destination_connection_id()
            .clone();
        let expected_crypto = config.crypto.clone();
        let local_connection_id = config
            .identifiers
            .local_source_connection_id()
            .as_bytes()
            .to_vec();
        let peer_connection_id = config
            .identifiers
            .peer_source_connection_id()
            .as_bytes()
            .to_vec();
        let local = config.local;
        let peer = config.peer;
        let mut flow = quic_initial_client_flow(config)?;

        assert_eq!(Flow::role(&flow), Role::Initiator);
        assert_eq!(Flow::initial(&flow), INITIAL_SENT);
        flow.validate()?;

        let mut context = crate::PacketContext::new();
        let state = flow
            .state_mut(INITIAL_SENT)
            .expect("InitialSent state exists");
        let step = state
            .run_entry(&mut context)?
            .expect("InitialSent has an entry action");

        assert_eq!(step.outputs().len(), 1);
        assert!(step.outputs()[0].requires_regeneration());
        assert!(step.expects_reply());
        assert_eq!(step.wakeup(), Some(INITIAL_CLIENT_TIMEOUT));

        let packet = step.outputs()[0].packet();
        let ipv4 = packet.layer::<Ipv4>().expect("typed IPv4 layer");
        let udp = packet.layer::<Udp>().expect("typed UDP layer");
        let quic = packet.layer::<Quic>().expect("typed QUIC layer");
        assert_eq!(ipv4.source(), *local.ip());
        assert_eq!(ipv4.destination(), *peer.ip());
        assert_eq!(udp.source_port_value(), local.port());
        assert_eq!(udp.destination_port_value(), peer.port());
        assert_eq!(quic.packets().len(), 1);
        let quic_payload_len = quic.packets()[0].as_bytes().len();
        assert!(quic_payload_len >= 1200);
        assert_eq!(
            packet.compile()?.as_bytes().len(),
            20 + 8 + quic_payload_len
        );

        let keys = derive_quic_initial_secrets(
            QUIC_VERSION_1,
            original_destination_connection_id.as_bytes(),
        )?
        .client_packet_keys()?;
        let decoded =
            quic_decode_initial_protected_payload_with_keys(quic.packets()[0].as_bytes(), &keys)?;
        assert_eq!(decoded.packet_number().value(), 0);
        assert!(!decoded
            .frames()
            .iter()
            .any(|frame| frame.ack_frame().is_ok_and(|ack| ack.is_some())));
        let crypto = decoded
            .frames()
            .iter()
            .find_map(|frame| frame.crypto_frame().ok().flatten())
            .expect("Initial includes a CRYPTO frame");
        assert_eq!(crypto.data(), expected_crypto);

        assert_eq!(
            context.get_namespaced_string("quic", "local_tuple")?,
            Some(local.to_string().as_str())
        );
        assert_eq!(
            context.get_namespaced_string("quic", "peer_tuple")?,
            Some(peer.to_string().as_str())
        );
        assert_eq!(
            context.get_namespaced_u64("quic", "initial_packet_number_sent")?,
            Some(0)
        );
        let snapshot = context.protocol_snapshot().expect("QUIC snapshot exists");
        assert_eq!(snapshot.lifecycle, INITIAL_SENT);
        assert_eq!(
            snapshot.local_connection_id.as_deref(),
            Some(local_connection_id.as_slice())
        );
        assert_eq!(
            snapshot.peer_connection_id.as_deref(),
            Some(peer_connection_id.as_slice())
        );

        let timeout = state
            .run_timeout(&mut context)?
            .expect("InitialSent has a timeout action");
        assert!(timeout.is_terminal());
        assert_eq!(timeout.outcome(), Some(INITIAL_ONLY_TIMEOUT_OUTCOME));
        let snapshot = context.protocol_snapshot().expect("timeout keeps snapshot");
        assert_eq!(snapshot.lifecycle, CLOSED);
        assert_eq!(
            snapshot.outcome.as_deref(),
            Some(INITIAL_ONLY_TIMEOUT_OUTCOME)
        );
        Ok(())
    }

    #[test]
    fn initial_frame_sequence_is_bounded_and_deterministic() {
        let observed = BTreeSet::from([0, 1, 4, 5, 6, 10]);
        let opaque_crypto = [0x00, 0xff, 0x06, 0x80];

        let frames = build_initial_frames(&opaque_crypto, opaque_crypto.len(), &observed).unwrap();
        let encoded = QuicFrame::encode_sequence(frames.clone());
        assert_eq!(
            encoded,
            [
                0x02, 0x0a, 0x00, 0x02, 0x00, 0x02, 0x02, 0x01, 0x01, // ACK
                0x06, 0x00, 0x04, 0x00, 0xff, 0x06, 0x80, // CRYPTO
            ]
        );
        assert_eq!(
            QuicFrame::encode_sequence(
                build_initial_frames(&opaque_crypto, opaque_crypto.len(), &observed).unwrap()
            ),
            encoded
        );
        assert!(!frames.iter().any(QuicFrame::is_padding));

        let ack = frames[0].ack_frame().unwrap().unwrap();
        assert_eq!(ack.largest_acknowledged().value(), 10);
        assert_eq!(ack.first_ack_range().value(), 0);
        assert_eq!(ack.ack_ranges().len(), 2);
        assert_eq!(ack.ack_ranges()[0].gap().value(), 2);
        assert_eq!(ack.ack_ranges()[0].ack_range_length().value(), 2);
        assert_eq!(ack.ack_ranges()[1].gap().value(), 1);
        assert_eq!(ack.ack_ranges()[1].ack_range_length().value(), 1);

        let crypto = frames[1].crypto_frame().unwrap().unwrap();
        assert_eq!(crypto.offset().value(), 0);
        assert_eq!(crypto.data(), opaque_crypto);

        let stream = QuicFrame::stream(QuicVarInt::new(0).unwrap(), b"not Initial data").unwrap();
        let close = QuicFrame::connection_close_transport(
            QuicVarInt::new(0).unwrap(),
            QuicVarInt::new(0x08).unwrap(),
            b"closed",
        )
        .unwrap();
        let mut decrypted = frames;
        decrypted.push(close.clone());
        decrypted.push(stream.clone());
        decrypted.push(QuicFrame::padding(3));

        let observations = inspect_initial_frames(&decrypted, opaque_crypto.len()).unwrap();
        assert_eq!(observations.acknowledgements.len(), 1);
        assert_eq!(
            observations.acknowledgements[0].packet_number_ranges,
            [(10, 10), (4, 6), (0, 1)]
        );
        assert_eq!(
            observations.acknowledgements[0]
                .frame
                .largest_acknowledged()
                .value(),
            10
        );
        assert_eq!(observations.crypto_chunks.len(), 1);
        assert_eq!(observations.crypto_chunks[0].offset().value(), 0);
        assert_eq!(observations.crypto_chunks[0].data(), opaque_crypto);
        assert_eq!(observations.close_frames.len(), 1);
        assert_eq!(
            observations.close_frames[0],
            close.connection_close_frame().unwrap().unwrap()
        );
        assert_eq!(observations.unexpected_frames, [stream]);

        assert!(build_initial_frames(&opaque_crypto, opaque_crypto.len() - 1, &observed).is_err());
        assert!(inspect_initial_frames(&decrypted, opaque_crypto.len() - 1).is_err());
    }

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
