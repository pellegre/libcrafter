//! Deterministic configuration for bounded QUIC Initial-only flows.

use std::{collections::BTreeSet, net::SocketAddrV4, time::Duration};

use crafter::protocols::quic::header::{
    classify_quic_header, QuicHeaderClassification, QuicLongPacketKind,
};
use crafter::{
    derive_quic_initial_secrets, quic_decode_initial_protected_payload_with_keys, CrafterError,
    QuicAckFrame, QuicAckRange, QuicConnectionCloseFrame, QuicConnectionId, QuicCryptoFrame,
    QuicFrame, QuicLongHeaderPacket, QuicPacketNumber, QUIC_VERSION_1,
};

use crate::context::ProtocolContextSnapshot;
use crate::flows::quic::{CLOSED, INITIAL_OBSERVED, INITIAL_SENT, LISTEN};
use crate::matcher::UdpDatagramMatcher;
use crate::quic_wire::{assemble_initial_datagram, extract_quic_udp_ingress, QuicInitialPadding};
use crate::{
    docaddr, Flow, FlowBuilderExt, FlowError, FlowState, Result, Role, Step, StepGotoExt,
    Transition,
};

const DEFAULT_CLIENT_PORT: u16 = 49_152;
const DEFAULT_SERVER_PORT: u16 = 443;
const MIN_INITIAL_CONNECTION_ID_LEN: usize = 8;
const MAX_INITIAL_CONNECTION_ID_LEN: usize = 20;
const MAX_CONFIGURED_CRYPTO_BYTES: usize = 64 * 1024;
const QUIC_PACKET_NUMBER_LIMIT: u64 = 1 << 62;
const INITIAL_CLIENT_TIMEOUT: Duration = Duration::from_secs(1);
const INITIAL_SERVER_TIMEOUT: Duration = Duration::from_secs(1);
const INITIAL_ONLY_TIMEOUT_OUTCOME: &str = "initial-only-timeout";
const INITIAL_AUTHENTICATION_FAILED_OUTCOME: &str = "initial-authentication-failed";
const INITIAL_TRUNCATED_OUTCOME: &str = "initial-truncated-protected-payload";
const INITIAL_INVALID_PACKET_NUMBER_OUTCOME: &str = "initial-invalid-packet-number";
const INITIAL_DISALLOWED_FRAME_OUTCOME: &str = "initial-disallowed-frame";
const INITIAL_CRYPTO_LIMIT_OUTCOME: &str = "initial-crypto-limit-exceeded";
const INITIAL_ACK_RANGE_LIMIT_OUTCOME: &str = "initial-ack-range-limit-exceeded";
const INITIAL_AMPLIFICATION_LIMIT_OUTCOME: &str = "initial-amplification-limit-exceeded";

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

/// Build the passive, bounded QUIC v1 Initial-only server flow.
pub fn quic_initial_server_flow(config: QuicInitialServerConfig) -> Result<Flow> {
    config.validate()?;

    let mut identifiers = config.identifiers.clone();
    let (server_packet_number, encoded_server_packet_number) =
        identifiers.take_next_initial_packet_number()?;
    let server_source_connection_id = identifiers.local_source_connection_id().clone();
    let server_packet_number_len = identifiers.packet_number_encoded_len();
    let server_crypto = config.crypto.clone();
    let local = config.local;
    let peer = config.peer;
    let version = config.version;
    let max_crypto_bytes = config.bounds.max_crypto_bytes;
    let max_ack_ranges = config.bounds.max_datagrams;
    let matcher = UdpDatagramMatcher::inbound(*local.ip(), local.port(), *peer.ip(), peer.port())
        .payload_where(
            "one structurally valid QUIC v1 Initial with a nonempty destination connection ID",
            move |payload, _context| matching_client_initial_header(payload, version).is_some(),
        );

    let listen = FlowState::new(LISTEN)
        .on_entry(|_context| Ok(Step::stay().wake_after(INITIAL_SERVER_TIMEOUT)))
        .entry_description("listen for one matching protected client Initial")
        .on(Transition::on(matcher, move |packet, context| {
            let ingress =
                extract_quic_udp_ingress(packet, local, peer, context).ok_or_else(|| {
                    FlowError::Build(
                        "matched QUIC Initial no longer satisfies its IPv4/UDP tuple".to_string(),
                    )
                })?;
            let (original_destination_connection_id, peer_source_connection_id) =
                matching_client_initial_header(ingress.payload(), version).ok_or_else(|| {
                    FlowError::Build(
                        "matched QUIC Initial no longer has a valid version 1 long header"
                            .to_string(),
                    )
                })?;
            let original_destination_connection_id =
                original_destination_connection_id.as_bytes().to_vec();
            let peer_source_connection_id = peer_source_connection_id.as_bytes().to_vec();

            let keys = derive_quic_initial_secrets(version, &original_destination_connection_id)?
                .client_packet_keys()?;
            let decoded =
                match quic_decode_initial_protected_payload_with_keys(ingress.payload(), &keys) {
                    Ok(decoded) => decoded,
                    Err(error) => return Ok(initial_decode_error_step(context, &error)),
                };
            let expected_packet_number = context
                .get_namespaced_u64("quic", "initial_expected_peer_packet_number")?
                .unwrap_or(0);
            let full_packet_number =
                match decoded.packet_number().reconstruct(expected_packet_number) {
                    Ok(packet_number) => packet_number,
                    Err(_) => {
                        return Ok(initial_error_step(
                            context,
                            INITIAL_INVALID_PACKET_NUMBER_OUTCOME,
                        ))
                    }
                };
            let next_expected_packet_number = match full_packet_number.checked_add(1) {
                Some(packet_number) if packet_number < QUIC_PACKET_NUMBER_LIMIT => packet_number,
                _ => {
                    return Ok(initial_error_step(
                        context,
                        INITIAL_INVALID_PACKET_NUMBER_OUTCOME,
                    ))
                }
            };
            let observations = match inspect_initial_frames(decoded.frames(), max_crypto_bytes) {
                Ok(observations) => observations,
                Err(_) => {
                    return Ok(initial_error_step(
                        context,
                        INITIAL_DISALLOWED_FRAME_OUTCOME,
                    ))
                }
            };
            if !observations.unexpected_frames.is_empty() {
                return Ok(initial_error_step(
                    context,
                    INITIAL_DISALLOWED_FRAME_OUTCOME,
                ));
            }

            let mut crypto_bytes = context
                .get_namespaced_bytes("quic", "initial_crypto_bytes")?
                .unwrap_or_default()
                .to_vec();
            for crypto in &observations.crypto_chunks {
                crypto_bytes.extend_from_slice(crypto.data());
            }
            if crypto_bytes.len() > max_crypto_bytes {
                return Ok(initial_error_step(context, INITIAL_CRYPTO_LIMIT_OUTCOME));
            }
            let observed_ack_ranges = observations
                .acknowledgements
                .iter()
                .flat_map(|ack| ack.packet_number_ranges.iter())
                .map(|(low, high)| format!("{low}-{high}"))
                .collect::<Vec<_>>();
            let prior_ack_ranges = context
                .get_namespaced_string("quic", "initial_ack_ranges")?
                .filter(|ranges| !ranges.is_empty())
                .map(|ranges| ranges.split(',').map(str::to_string).collect::<Vec<_>>())
                .unwrap_or_default();
            if prior_ack_ranges.len() + observed_ack_ranges.len() > max_ack_ranges {
                return Ok(initial_error_step(context, INITIAL_ACK_RANGE_LIMIT_OUTCOME));
            }
            let ack_ranges = prior_ack_ranges
                .into_iter()
                .chain(observed_ack_ranges)
                .collect::<Vec<_>>()
                .join(",");

            let acknowledged_packet_numbers = BTreeSet::from([full_packet_number]);
            let response_frames = build_initial_frames(
                &server_crypto,
                max_crypto_bytes,
                &acknowledged_packet_numbers,
            )?;
            let response_initial = QuicLongHeaderPacket::initial_builder()
                .version(version)
                .destination_connection_id(QuicConnectionId::from_bytes(
                    peer_source_connection_id.clone(),
                ))
                .source_connection_id(server_source_connection_id.clone())
                .packet_number(encoded_server_packet_number.clone())
                .frames(response_frames)
                .build()?;
            let response_keys =
                derive_quic_initial_secrets(version, &original_destination_connection_id)?
                    .server_packet_keys()?;
            let response = assemble_initial_datagram(
                local,
                peer,
                &response_initial,
                server_packet_number,
                &response_keys,
                server_packet_number_len,
                QuicInitialPadding::None,
            )?;
            let received_bytes = u64::try_from(ingress.payload().len()).map_err(|_| {
                FlowError::Build("QUIC Initial ingress size exceeds u64 accounting".to_string())
            })?;
            let response_bytes = u64::try_from(
                response
                    .layer::<crafter::Quic>()
                    .expect("assembled Initial has a typed QUIC layer")
                    .packets()[0]
                    .as_bytes()
                    .len(),
            )
            .map_err(|_| {
                FlowError::Build("QUIC Initial response size exceeds u64 accounting".to_string())
            })?;
            let amplification_limit = received_bytes.saturating_mul(3);

            context.insert_namespaced_string("quic", "local_tuple", ingress.local().to_string())?;
            context.insert_namespaced_string("quic", "peer_tuple", ingress.peer().to_string())?;
            context.insert_namespaced_bytes(
                "quic",
                "original_destination_connection_id",
                original_destination_connection_id.clone(),
            )?;
            context.insert_namespaced_bytes(
                "quic",
                "peer_source_connection_id",
                peer_source_connection_id.clone(),
            )?;
            context.insert_namespaced_u64(
                "quic",
                "initial_packet_number_received",
                full_packet_number,
            )?;
            context.insert_namespaced_u64(
                "quic",
                "initial_expected_peer_packet_number",
                next_expected_packet_number,
            )?;
            context.insert_namespaced_bytes("quic", "initial_crypto_bytes", crypto_bytes)?;
            context.insert_namespaced_string("quic", "initial_ack_ranges", ack_ranges)?;
            context.insert_namespaced_u64("quic", "initial_bytes_received", received_bytes)?;
            context.insert_namespaced_u64("quic", "initial_response_bytes", response_bytes)?;
            context.insert_namespaced_u64(
                "quic",
                "initial_amplification_limit_bytes",
                amplification_limit,
            )?;
            context.insert_namespaced_bool(
                "quic",
                "initial_response_within_amplification_limit",
                response_bytes <= amplification_limit,
            )?;

            if response_bytes > amplification_limit {
                return Ok(initial_error_step(
                    context,
                    INITIAL_AMPLIFICATION_LIMIT_OUTCOME,
                ));
            }
            context.insert_namespaced_u64(
                "quic",
                "initial_packet_number_sent",
                server_packet_number,
            )?;

            let mut snapshot = ProtocolContextSnapshot::new("quic", INITIAL_OBSERVED);
            snapshot.local_connection_id = Some(server_source_connection_id.as_bytes().to_vec());
            snapshot.peer_connection_id = Some(peer_source_connection_id);
            context.set_protocol_snapshot(snapshot);

            Ok(Step::send_regeneration_only(response).goto(INITIAL_OBSERVED))
        })
        .targets([INITIAL_OBSERVED])
        .terminal())
        .on_timeout(|context| {
            let mut snapshot = ProtocolContextSnapshot::new("quic", CLOSED);
            snapshot.outcome = Some(INITIAL_ONLY_TIMEOUT_OUTCOME.to_string());
            snapshot.close_category = Some("timeout".to_string());
            context.set_protocol_snapshot(snapshot);
            Ok(Step::done_with(INITIAL_ONLY_TIMEOUT_OUTCOME))
        })
        .timeout_description("close the bounded Initial-only listener on timeout")
        .timeout_terminal();

    let flow = Flow::new("quic-initial-server")
        .role(Role::Responder)
        .state(listen)
        .state(FlowState::new(INITIAL_OBSERVED))
        .initial(LISTEN);
    flow.validate()?;
    Ok(flow)
}

fn initial_decode_error_step(context: &mut crate::PacketContext, error: &CrafterError) -> Step {
    let outcome = match error {
        CrafterError::BufferTooShort { .. } => INITIAL_TRUNCATED_OUTCOME,
        CrafterError::InvalidFieldValue { field, reason }
            if *field == "quic.crypto.initial.ciphertext_tag"
                && reason.contains("authentication failed") =>
        {
            INITIAL_AUTHENTICATION_FAILED_OUTCOME
        }
        CrafterError::InvalidFieldValue { field, .. } if field.contains("packet_number") => {
            INITIAL_INVALID_PACKET_NUMBER_OUTCOME
        }
        CrafterError::InvalidFieldValue { .. } | CrafterError::InvalidMacAddress { .. } => {
            INITIAL_TRUNCATED_OUTCOME
        }
    };
    initial_error_step(context, outcome)
}

fn initial_error_step(context: &mut crate::PacketContext, outcome: &'static str) -> Step {
    let mut snapshot = ProtocolContextSnapshot::new("quic", CLOSED);
    snapshot.outcome = Some(outcome.to_string());
    snapshot.close_category = Some("initial-error".to_string());
    context.set_protocol_snapshot(snapshot);
    Step::done_with(outcome)
}

fn matching_client_initial_header(
    payload: &[u8],
    version: u32,
) -> Option<(QuicConnectionId, QuicConnectionId)> {
    match classify_quic_header(payload).ok()? {
        QuicHeaderClassification::LongHeader {
            version: observed_version,
            destination_connection_id,
            source_connection_id,
            packet_kind: QuicLongPacketKind::Initial,
            remaining_len,
            ..
        } if observed_version == version
            && !destination_connection_id.is_empty()
            && remaining_len > 0 =>
        {
            Some((destination_connection_id, source_connection_id))
        }
        _ => return None,
    }
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
    fn initial_server_listens_for_matching_client_initial() -> crate::Result<()> {
        let client_config = QuicInitialClientConfig::default();
        let server_config = QuicInitialServerConfig::default();
        let expected_local = server_config.local;
        let expected_peer = server_config.peer;
        let expected_original_destination_connection_id = client_config
            .identifiers
            .original_destination_connection_id()
            .as_bytes()
            .to_vec();
        let expected_peer_source_connection_id = client_config
            .identifiers
            .local_source_connection_id()
            .as_bytes()
            .to_vec();
        let expected_local_connection_id = server_config
            .identifiers
            .local_source_connection_id()
            .as_bytes()
            .to_vec();

        let mut client = quic_initial_client_flow(client_config)?;
        let mut client_context = crate::PacketContext::new();
        let client_step = client
            .state_mut(INITIAL_SENT)
            .expect("InitialSent state exists")
            .run_entry(&mut client_context)?
            .expect("client emits its Initial");
        let valid_initial = client_step.outputs()[0].packet().clone();
        let valid_payload = valid_initial
            .layer::<Quic>()
            .expect("typed QUIC layer")
            .packets()[0]
            .as_bytes()
            .to_vec();

        let mut server = quic_initial_server_flow(server_config.clone())?;
        assert_eq!(Flow::role(&server), Role::Responder);
        assert_eq!(Flow::initial(&server), LISTEN);
        server.validate()?;

        let mut context = crate::PacketContext::new();
        let listen = server.state_mut(LISTEN).expect("Listen state exists");
        let entry = listen
            .run_entry(&mut context)?
            .expect("Listen schedules its bound");
        assert!(entry.outputs().is_empty());
        assert_eq!(entry.wakeup(), Some(INITIAL_SERVER_TIMEOUT));

        let wrong_tuple = Ipv4::new().src(docaddr::DNS_IPV4).dst(*expected_local.ip())
            / Udp::new()
                .source_port(expected_peer.port())
                .destination_port(expected_local.port())
            / Quic::from_bytes(valid_payload.clone());
        assert!(listen.find_transition(&wrong_tuple, &context).is_none());
        assert!(context.protocol_snapshot().is_none());
        assert_eq!(context.get_namespaced_string("quic", "peer_tuple")?, None);

        let mut non_initial_payload = valid_payload;
        non_initial_payload[0] = (non_initial_payload[0] & !0x30) | 0x20;
        let non_initial = Ipv4::new()
            .src(*expected_peer.ip())
            .dst(*expected_local.ip())
            / Udp::new()
                .source_port(expected_peer.port())
                .destination_port(expected_local.port())
            / Quic::from_bytes(non_initial_payload);
        assert!(listen.find_transition(&non_initial, &context).is_none());
        assert!(context.protocol_snapshot().is_none());

        let transition = listen
            .find_transition(&valid_initial, &context)
            .expect("matching client Initial is accepted");
        let accepted = transition.fire(&valid_initial, &mut context)?;
        assert_eq!(accepted.target(), Some(INITIAL_OBSERVED));
        assert_eq!(accepted.outputs().len(), 1);
        assert!(accepted.outputs()[0].requires_regeneration());
        assert_eq!(
            context.get_namespaced_string("quic", "local_tuple")?,
            Some(expected_local.to_string().as_str())
        );
        assert_eq!(
            context.get_namespaced_string("quic", "peer_tuple")?,
            Some(expected_peer.to_string().as_str())
        );
        assert_eq!(
            context.get_namespaced_bytes("quic", "original_destination_connection_id")?,
            Some(expected_original_destination_connection_id.as_slice())
        );
        assert_eq!(
            context.get_namespaced_bytes("quic", "peer_source_connection_id")?,
            Some(expected_peer_source_connection_id.as_slice())
        );
        let snapshot = context.protocol_snapshot().expect("QUIC snapshot exists");
        assert_eq!(snapshot.lifecycle, INITIAL_OBSERVED);
        assert_eq!(
            snapshot.local_connection_id.as_deref(),
            Some(expected_local_connection_id.as_slice())
        );
        assert_eq!(
            snapshot.peer_connection_id.as_deref(),
            Some(expected_peer_source_connection_id.as_slice())
        );

        let mut timeout_server = quic_initial_server_flow(server_config)?;
        let mut timeout_context = crate::PacketContext::new();
        let timeout = timeout_server
            .state_mut(LISTEN)
            .expect("Listen state exists")
            .run_timeout(&mut timeout_context)?
            .expect("Listen has a timeout action");
        assert!(timeout.is_terminal());
        assert!(timeout.outputs().is_empty());
        assert_eq!(timeout.outcome(), Some(INITIAL_ONLY_TIMEOUT_OUTCOME));
        let snapshot = timeout_context
            .protocol_snapshot()
            .expect("timeout records a snapshot");
        assert_eq!(snapshot.lifecycle, CLOSED);
        assert_eq!(
            snapshot.outcome.as_deref(),
            Some(INITIAL_ONLY_TIMEOUT_OUTCOME)
        );
        Ok(())
    }

    #[test]
    fn initial_server_decrypts_and_records_client_crypto() -> crate::Result<()> {
        let client_config = QuicInitialClientConfig::default();
        let expected_crypto = client_config.crypto.clone();
        let mut client = quic_initial_client_flow(client_config)?;
        let mut client_context = crate::PacketContext::new();
        let client_initial = client
            .state_mut(INITIAL_SENT)
            .expect("InitialSent state exists")
            .run_entry(&mut client_context)?
            .expect("client emits its protected Initial")
            .outputs()[0]
            .packet()
            .clone();

        let mut server = quic_initial_server_flow(QuicInitialServerConfig::default())?;
        let mut server_context = crate::PacketContext::new();
        let listen = server.state_mut(LISTEN).expect("Listen state exists");
        let transition = listen
            .find_transition(&client_initial, &server_context)
            .expect("server matches the protected client Initial");
        let observed = transition.fire(&client_initial, &mut server_context)?;

        assert_eq!(observed.target(), Some(INITIAL_OBSERVED));
        assert!(!observed.is_terminal());
        assert_eq!(
            server_context.get_namespaced_u64("quic", "initial_packet_number_received")?,
            Some(0)
        );
        assert_eq!(
            server_context.get_namespaced_u64("quic", "initial_expected_peer_packet_number")?,
            Some(1)
        );
        assert_eq!(
            server_context.get_namespaced_bytes("quic", "initial_crypto_bytes")?,
            Some(expected_crypto.as_slice())
        );
        assert_eq!(
            server_context.get_namespaced_string("quic", "initial_ack_ranges")?,
            Some("")
        );
        let snapshot = server_context
            .protocol_snapshot()
            .expect("server records an Initial observation snapshot");
        assert_eq!(snapshot.lifecycle, INITIAL_OBSERVED);
        assert_ne!(snapshot.lifecycle, "Handshaking");
        assert_ne!(snapshot.lifecycle, "Established");
        Ok(())
    }

    #[test]
    fn initial_server_response_acks_client_and_carries_crypto() -> crate::Result<()> {
        let client_config = QuicInitialClientConfig::default();
        let server_config = QuicInitialServerConfig::default();
        let original_destination_connection_id = client_config
            .identifiers
            .original_destination_connection_id()
            .clone();
        let client_source_connection_id = client_config
            .identifiers
            .local_source_connection_id()
            .clone();
        let server_source_connection_id = server_config
            .identifiers
            .local_source_connection_id()
            .clone();
        let expected_crypto = server_config.crypto.clone();
        let expected_local = server_config.local;
        let expected_peer = server_config.peer;

        let mut client = quic_initial_client_flow(client_config)?;
        let mut client_context = crate::PacketContext::new();
        let client_initial = client
            .state_mut(INITIAL_SENT)
            .expect("InitialSent state exists")
            .run_entry(&mut client_context)?
            .expect("client emits its protected Initial")
            .outputs()[0]
            .packet()
            .clone();

        let mut server = quic_initial_server_flow(server_config)?;
        let mut server_context = crate::PacketContext::new();
        let listen = server.state_mut(LISTEN).expect("Listen state exists");
        let transition = listen
            .find_transition(&client_initial, &server_context)
            .expect("server matches the protected client Initial");
        let response_step = transition.fire(&client_initial, &mut server_context)?;

        assert_eq!(response_step.target(), Some(INITIAL_OBSERVED));
        assert_eq!(response_step.outputs().len(), 1);
        assert!(response_step.outputs()[0].requires_regeneration());
        let response = response_step.outputs()[0].packet();
        let ipv4 = response.layer::<Ipv4>().expect("typed IPv4 layer");
        let udp = response.layer::<Udp>().expect("typed UDP layer");
        let quic = response.layer::<Quic>().expect("typed QUIC layer");
        assert_eq!(ipv4.source(), *expected_local.ip());
        assert_eq!(ipv4.destination(), *expected_peer.ip());
        assert_eq!(udp.source_port_value(), expected_local.port());
        assert_eq!(udp.destination_port_value(), expected_peer.port());
        assert_eq!(quic.packets().len(), 1);

        match classify_quic_header(quic.packets()[0].as_bytes())? {
            QuicHeaderClassification::LongHeader {
                destination_connection_id,
                source_connection_id,
                packet_kind: QuicLongPacketKind::Initial,
                ..
            } => {
                assert_eq!(destination_connection_id, client_source_connection_id);
                assert_eq!(source_connection_id, server_source_connection_id);
            }
            classification => panic!("unexpected server response header: {classification:?}"),
        }

        let server_keys = derive_quic_initial_secrets(
            QUIC_VERSION_1,
            original_destination_connection_id.as_bytes(),
        )?
        .server_packet_keys()?;
        let decoded = quic_decode_initial_protected_payload_with_keys(
            quic.packets()[0].as_bytes(),
            &server_keys,
        )?;
        assert_eq!(decoded.packet_number().value(), 0);
        let observations = inspect_initial_frames(decoded.frames(), expected_crypto.len())?;
        assert_eq!(observations.acknowledgements.len(), 1);
        assert_eq!(
            observations.acknowledgements[0].packet_number_ranges,
            [(0, 0)]
        );
        assert_eq!(observations.crypto_chunks.len(), 1);
        assert_eq!(observations.crypto_chunks[0].data(), expected_crypto);

        assert_eq!(
            server_context.get_namespaced_u64("quic", "initial_packet_number_sent")?,
            Some(0)
        );
        let received_bytes = server_context
            .get_namespaced_u64("quic", "initial_bytes_received")?
            .expect("received byte accounting");
        let response_bytes = server_context
            .get_namespaced_u64("quic", "initial_response_bytes")?
            .expect("response byte accounting");
        assert_eq!(
            server_context.get_namespaced_u64("quic", "initial_amplification_limit_bytes")?,
            Some(received_bytes * 3)
        );
        assert_eq!(
            server_context
                .get_namespaced_bool("quic", "initial_response_within_amplification_limit")?,
            Some(true)
        );
        assert!(response_bytes <= received_bytes * 3);
        assert_eq!(response_bytes as usize, quic.packets()[0].as_bytes().len());
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
