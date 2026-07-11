//! Deterministic configuration for bounded QUIC Initial-only flows.

use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
    net::SocketAddrV4,
    rc::Rc,
    time::Duration,
};

use crafter::protocols::quic::header::{
    classify_quic_header, QuicHeaderClassification, QuicLongPacketKind,
};
use crafter::{
    derive_quic_initial_secrets, quic_decode_initial_protected_payload_with_keys, CrafterError,
    QuicAckFrame, QuicAckRange, QuicConnectionCloseFrame, QuicConnectionId, QuicCryptoFrame,
    QuicFrame, QuicLongHeaderPacket, QuicPacket, QuicPacketNumber, QuicRetryIntegrityStatus,
    QuicRetryPacket, QuicVersionNegotiationPacket, QUIC_VERSION_1, QUIC_VERSION_2,
};

use crate::context::ProtocolContextSnapshot;
use crate::flows::quic::{CLOSED, INITIAL_OBSERVED, INITIAL_SENT, LISTEN, RETRY_RECEIVED};
use crate::matcher::UdpDatagramMatcher;
use crate::quic_wire::{
    assemble_initial_datagram, extract_quic_udp_ingress, wrap_quic_udp_datagram,
    QuicInitialPadding, QuicUdpPayload,
};
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
const INITIAL_ONLY_SERVER_INITIAL_OBSERVED_OUTCOME: &str = "initial-only-server-initial-observed";
const VERSION_NEGOTIATION_SENT: &str = "VersionNegotiationSent";
const RETRY_SENT: &str = "RetrySent";
const INITIAL_ONLY_VERSION_NEGOTIATION_SENT_OUTCOME: &str = "initial-only-version-negotiation-sent";
const INITIAL_ONLY_VERSION_NEGOTIATION_SELECTED_OUTCOME: &str =
    "initial-only-version-negotiation-selected";
const INITIAL_ONLY_VERSION_NEGOTIATION_REJECTED_OUTCOME: &str =
    "initial-only-version-negotiation-rejected";
const INITIAL_ONLY_VERSION_NEGOTIATION_UNSUPPORTED_OUTCOME: &str =
    "initial-only-version-negotiation-unsupported";
const INITIAL_ONLY_RETRY_SENT_OUTCOME: &str = "initial-only-retry-sent";
const INITIAL_ONLY_RETRY_LIMIT_OUTCOME: &str = "initial-only-retry-limit-exceeded";
const INITIAL_AUTHENTICATION_FAILED_OUTCOME: &str = "initial-authentication-failed";
const INITIAL_TRUNCATED_OUTCOME: &str = "initial-truncated-protected-payload";
const INITIAL_INVALID_PACKET_NUMBER_OUTCOME: &str = "initial-invalid-packet-number";
const INITIAL_DISALLOWED_FRAME_OUTCOME: &str = "initial-disallowed-frame";
const INITIAL_CRYPTO_LIMIT_OUTCOME: &str = "initial-crypto-limit-exceeded";
const INITIAL_ACK_RANGE_LIMIT_OUTCOME: &str = "initial-ack-range-limit-exceeded";
const INITIAL_INVALID_ACK_OUTCOME: &str = "initial-invalid-ack";
const INITIAL_AMPLIFICATION_LIMIT_OUTCOME: &str = "initial-amplification-limit-exceeded";

/// Build the deterministic, bounded QUIC v1 Initial-only client flow.
pub fn quic_initial_client_flow(config: QuicInitialClientConfig) -> Result<Flow> {
    config.validate()?;

    let mut identifiers = config.identifiers.clone();
    let initial_packet_number_seed = identifiers.next_initial_packet_number();
    let (packet, full_packet_number) = build_client_initial_datagram(
        config.version,
        &mut identifiers,
        &config.crypto,
        config.local,
        config.peer,
        config.bounds.max_crypto_bytes,
    )?;

    let local = config.local;
    let peer = config.peer;
    let local_connection_id = identifiers.local_source_connection_id().as_bytes().to_vec();
    let peer_connection_id = identifiers.peer_source_connection_id().as_bytes().to_vec();
    let original_destination_connection_id = identifiers
        .original_destination_connection_id()
        .as_bytes()
        .to_vec();
    let expected_destination_connection_id = local_connection_id.clone();
    let expected_source_connection_id = peer_connection_id.clone();
    let entry_local_connection_id = local_connection_id.clone();
    let entry_peer_connection_id = peer_connection_id.clone();
    let originally_offered_version = config.version;
    let active_version = Rc::new(Cell::new(config.version));
    let initial_match_version = Rc::clone(&active_version);
    let version_negotiation_policy = config.version_policy;
    let max_version_negotiations = config.bounds.max_version_negotiations;
    let version_negotiation_local = local_connection_id.clone();
    let version_negotiation_peer = identifiers
        .current_destination_connection_id()
        .as_bytes()
        .to_vec();
    let version_negotiation_crypto = config.crypto.clone();
    let version_negotiation_active_version = Rc::clone(&active_version);
    let retry_identifiers = Rc::new(RefCell::new(identifiers.clone()));
    let retry_state = Rc::clone(&retry_identifiers);
    let retry_active_version = Rc::clone(&active_version);
    let retry_policy = config.retry_policy;
    let max_retries = config.bounds.max_retries;
    let retry_crypto = config.crypto.clone();
    let retry_original_destination_connection_id = original_destination_connection_id.clone();
    let retry_local_connection_id = local_connection_id.clone();
    let retry_peer_connection_id = peer_connection_id.clone();
    let max_crypto_bytes = config.bounds.max_crypto_bytes;
    let max_ack_ranges = config.bounds.max_datagrams;
    let ack_state = Rc::new(RefCell::new(QuicInitialAckState::from_sent([
        full_packet_number,
    ])?));
    let initial_ack_state = Rc::clone(&ack_state);
    let version_negotiation_ack_state = Rc::clone(&ack_state);
    let retry_ack_state = Rc::clone(&ack_state);
    let matcher = UdpDatagramMatcher::inbound(*local.ip(), local.port(), *peer.ip(), peer.port())
        .payload_where(
            "one protected QUIC v1 server Initial with the expected connection identifiers",
            move |payload, _context| {
                matching_server_initial_header(
                    payload,
                    initial_match_version.get(),
                    &expected_destination_connection_id,
                    &expected_source_connection_id,
                )
            },
        );
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
            snapshot.local_connection_id = Some(entry_local_connection_id.clone());
            snapshot.peer_connection_id = Some(entry_peer_connection_id.clone());
            context.set_protocol_snapshot(snapshot);

            Ok(Step::send_regeneration_only(packet.clone()).wake_after(INITIAL_CLIENT_TIMEOUT))
        })
        .entry_description("emit one protected minimum-size client Initial")
        .on(Transition::on(
            UdpDatagramMatcher::inbound(*local.ip(), local.port(), *peer.ip(), peer.port())
                .payload_where(
                    "one QUIC Version Negotiation packet",
                    |payload, _context| {
                        matches!(
                            classify_quic_header(payload),
                            Ok(QuicHeaderClassification::LongHeader {
                                packet_kind: QuicLongPacketKind::VersionNegotiation,
                                ..
                            })
                        )
                    },
                ),
            move |packet, context| {
                let ingress =
                    extract_quic_udp_ingress(packet, local, peer, context).ok_or_else(|| {
                        FlowError::Build(
                            "matched Version Negotiation no longer satisfies its IPv4/UDP tuple"
                                .to_string(),
                        )
                    })?;
                let negotiation = match QuicVersionNegotiationPacket::decode(ingress.payload()) {
                    Ok(negotiation) => negotiation,
                    Err(_) => {
                        return Ok(version_negotiation_terminal_step(
                            context,
                            INITIAL_ONLY_VERSION_NEGOTIATION_REJECTED_OUTCOME,
                        ))
                    }
                };
                let observed = context
                    .get_namespaced_u64("quic", "version_negotiation_count")?
                    .unwrap_or(0);
                let authenticated = context
                    .get_namespaced_bool("quic", "initial_authenticated_server_traffic")?
                    .unwrap_or(false);
                let identifiers_match = negotiation.destination_connection_id().as_bytes()
                    == version_negotiation_local
                    && negotiation.source_connection_id().as_bytes() == version_negotiation_peer;
                let reflects_offer = negotiation
                    .supported_versions()
                    .contains(&originally_offered_version);
                if !identifiers_match
                    || reflects_offer
                    || authenticated
                    || observed >= max_version_negotiations as u64
                    || version_negotiation_policy == QuicInitialVersionPolicy::Version1Only
                {
                    return Ok(version_negotiation_terminal_step(
                        context,
                        INITIAL_ONLY_VERSION_NEGOTIATION_REJECTED_OUTCOME,
                    ));
                }
                if !negotiation.supported_versions().contains(&QUIC_VERSION_1) {
                    return Ok(version_negotiation_terminal_step(
                        context,
                        INITIAL_ONLY_VERSION_NEGOTIATION_UNSUPPORTED_OUTCOME,
                    ));
                }

                identifiers.reset_initial_packet_number(initial_packet_number_seed)?;
                let (restart, restart_packet_number) = build_client_initial_datagram(
                    QUIC_VERSION_1,
                    &mut identifiers,
                    &version_negotiation_crypto,
                    local,
                    peer,
                    max_crypto_bytes,
                )?;
                *version_negotiation_ack_state.borrow_mut() =
                    QuicInitialAckState::from_sent([restart_packet_number])?;
                version_negotiation_active_version.set(QUIC_VERSION_1);
                context.insert_namespaced_u64("quic", "version_negotiation_count", observed + 1)?;
                context.insert_namespaced_u64(
                    "quic",
                    "version_negotiation_selected_version",
                    QUIC_VERSION_1 as u64,
                )?;
                context.insert_namespaced_u64(
                    "quic",
                    "initial_packet_number_sent",
                    restart_packet_number,
                )?;
                let mut snapshot = ProtocolContextSnapshot::new("quic", INITIAL_SENT);
                snapshot.local_connection_id = Some(version_negotiation_local.clone());
                snapshot.peer_connection_id = Some(version_negotiation_peer.clone());
                snapshot.outcome =
                    Some(INITIAL_ONLY_VERSION_NEGOTIATION_SELECTED_OUTCOME.to_string());
                context.set_protocol_snapshot(snapshot);

                Ok(Step::send_regeneration_only(restart).wake_after(INITIAL_CLIENT_TIMEOUT))
            },
        )
        .terminal())
        .on(Transition::on(
            UdpDatagramMatcher::inbound(*local.ip(), local.port(), *peer.ip(), peer.port())
                .payload_where("one QUIC Retry packet", |payload, _context| {
                    matches!(
                        classify_quic_header(payload),
                        Ok(QuicHeaderClassification::LongHeader {
                            packet_kind: QuicLongPacketKind::Retry,
                            ..
                        })
                    )
                }),
            move |packet, context| {
                let ingress =
                    extract_quic_udp_ingress(packet, local, peer, context).ok_or_else(|| {
                        FlowError::Build(
                            "matched Retry no longer satisfies its IPv4/UDP tuple".to_string(),
                        )
                    })?;
                let retry = match QuicRetryPacket::decode(ingress.payload()) {
                    Ok(retry) => retry,
                    Err(_) => return Ok(Step::stay()),
                };
                let observed = context
                    .get_namespaced_u64("quic", "retry_count")?
                    .unwrap_or(0);
                let authenticated = context
                    .get_namespaced_bool("quic", "initial_authenticated_server_traffic")?
                    .unwrap_or(false);
                let identifiers_match = retry.destination_connection_id().as_bytes()
                    == retry_local_connection_id
                    && retry.source_connection_id().as_bytes() == retry_peer_connection_id;
                let integrity_valid = retry
                    .integrity_status(&retry_original_destination_connection_id)
                    .is_ok_and(|status| status == QuicRetryIntegrityStatus::Valid);
                if retry_policy != QuicInitialRetryPolicy::AcceptValid
                    || retry.version() != retry_active_version.get()
                    || !identifiers_match
                    || !integrity_valid
                    || authenticated
                    || observed >= max_retries as u64
                {
                    return Ok(Step::stay());
                }

                let mut identifiers = retry_state.borrow_mut();
                identifiers.apply_valid_retry(
                    retry.source_connection_id().clone(),
                    retry.token().to_vec(),
                )?;
                let (restart, restart_packet_number) = build_client_initial_datagram(
                    retry_active_version.get(),
                    &mut identifiers,
                    &retry_crypto,
                    local,
                    peer,
                    max_crypto_bytes,
                )?;
                *retry_ack_state.borrow_mut() =
                    QuicInitialAckState::from_sent([restart_packet_number])?;
                context.insert_namespaced_u64("quic", "retry_count", observed + 1)?;
                context.insert_namespaced_bool("quic", "retry_token_present", true)?;
                context.insert_namespaced_u64(
                    "quic",
                    "initial_packet_number_sent",
                    restart_packet_number,
                )?;

                let mut snapshot = ProtocolContextSnapshot::new("quic", RETRY_RECEIVED);
                snapshot.local_connection_id = Some(retry_local_connection_id.clone());
                snapshot.peer_connection_id =
                    Some(retry.source_connection_id().as_bytes().to_vec());
                context.set_protocol_snapshot(snapshot);

                Ok(Step::send_regeneration_only(restart).wake_after(INITIAL_CLIENT_TIMEOUT))
            },
        ))
        .on(Transition::on(matcher, move |packet, context| {
            let ingress =
                extract_quic_udp_ingress(packet, local, peer, context).ok_or_else(|| {
                    FlowError::Build(
                        "matched server Initial no longer satisfies its IPv4/UDP tuple".to_string(),
                    )
                })?;
            if !matching_server_initial_header(
                ingress.payload(),
                active_version.get(),
                &local_connection_id,
                &peer_connection_id,
            ) {
                return Err(FlowError::Build(
                    "matched server Initial no longer has the expected connection identifiers"
                        .to_string(),
                ));
            }

            let keys = derive_quic_initial_secrets(
                active_version.get(),
                &original_destination_connection_id,
            )?
            .server_packet_keys()?;
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
            if !observations.unexpected_frames.is_empty() || !observations.close_frames.is_empty() {
                return Ok(initial_error_step(
                    context,
                    INITIAL_DISALLOWED_FRAME_OUTCOME,
                ));
            }
            if initial_ack_state
                .borrow_mut()
                .validate(
                    QuicAckPacketNumberSpace::Initial,
                    observations.acknowledgements.iter().map(|ack| &ack.frame),
                )
                .is_err()
            {
                return Ok(initial_error_step(context, INITIAL_INVALID_ACK_OUTCOME));
            }

            let crypto_bytes = observations
                .crypto_chunks
                .iter()
                .flat_map(|crypto| crypto.data().iter().copied())
                .collect::<Vec<_>>();
            let ack_ranges = observations
                .acknowledgements
                .iter()
                .flat_map(|ack| ack.packet_number_ranges.iter())
                .map(|(low, high)| format!("{low}-{high}"))
                .collect::<Vec<_>>();
            if ack_ranges.len() > max_ack_ranges {
                return Ok(initial_error_step(context, INITIAL_ACK_RANGE_LIMIT_OUTCOME));
            }

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
            context.insert_namespaced_string("quic", "initial_ack_ranges", ack_ranges.join(","))?;
            initial_ack_state.borrow().record(context)?;
            context.insert_namespaced_bool("quic", "initial_authenticated_server_traffic", true)?;

            let mut snapshot = ProtocolContextSnapshot::new("quic", INITIAL_OBSERVED);
            snapshot.local_connection_id = Some(local_connection_id.clone());
            snapshot.peer_connection_id = Some(peer_connection_id.clone());
            snapshot.outcome = Some(INITIAL_ONLY_SERVER_INITIAL_OBSERVED_OUTCOME.to_string());
            context.set_protocol_snapshot(snapshot);

            Ok(Step::done_with(
                INITIAL_ONLY_SERVER_INITIAL_OBSERVED_OUTCOME,
            ))
        })
        .terminal())
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

fn matching_server_initial_header(
    payload: &[u8],
    version: u32,
    expected_destination_connection_id: &[u8],
    expected_source_connection_id: &[u8],
) -> bool {
    matches!(
        classify_quic_header(payload),
        Ok(QuicHeaderClassification::LongHeader {
            version: observed_version,
            destination_connection_id,
            source_connection_id,
            packet_kind: QuicLongPacketKind::Initial,
            remaining_len,
            ..
        }) if observed_version == version
            && destination_connection_id.as_bytes() == expected_destination_connection_id
            && source_connection_id.as_bytes() == expected_source_connection_id
            && remaining_len > 0
    )
}

fn build_client_initial_datagram(
    version: u32,
    identifiers: &mut QuicInitialIdentifiers,
    crypto: &[u8],
    local: SocketAddrV4,
    peer: SocketAddrV4,
    max_crypto_bytes: usize,
) -> Result<(crafter::Packet, u64)> {
    let (full_packet_number, encoded_packet_number) =
        identifiers.take_next_initial_packet_number()?;
    let frames = build_initial_frames(crypto, max_crypto_bytes, &BTreeSet::new())?;
    let initial = QuicLongHeaderPacket::initial_builder()
        .version(version)
        .destination_connection_id(identifiers.current_destination_connection_id().clone())
        .source_connection_id(identifiers.local_source_connection_id().clone())
        .token(identifiers.retry_token())
        .packet_number(encoded_packet_number)
        .frames(frames)
        .build()?;
    let keys = derive_quic_initial_secrets(
        version,
        identifiers.original_destination_connection_id().as_bytes(),
    )?
    .client_packet_keys()?;
    let packet = assemble_initial_datagram(
        local,
        peer,
        &initial,
        full_packet_number,
        &keys,
        identifiers.packet_number_encoded_len(),
        QuicInitialPadding::ClientMinimum,
    )?;
    Ok((packet, full_packet_number))
}

fn version_negotiation_terminal_step(
    context: &mut crate::PacketContext,
    outcome: &'static str,
) -> Step {
    let mut snapshot = ProtocolContextSnapshot::new("quic", CLOSED);
    snapshot.outcome = Some(outcome.to_string());
    snapshot.close_category = Some("version-negotiation".to_string());
    context.set_protocol_snapshot(snapshot);
    Step::done_with(outcome)
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
    let supported_versions = config.supported_versions.clone();
    let version_negotiation_grease_versions = config.version_negotiation_grease_versions.clone();
    let retry_policy = config.retry_policy;
    let max_retries = config.bounds.max_retries;
    let retry_token = identifiers.retry_token().to_vec();
    let max_crypto_bytes = config.bounds.max_crypto_bytes;
    let max_ack_ranges = config.bounds.max_datagrams;
    let mut ack_state = QuicInitialAckState::default();
    let matcher = UdpDatagramMatcher::inbound(*local.ip(), local.port(), *peer.ip(), peer.port())
        .payload_where(
            "one structurally valid nonzero-version QUIC Initial with a nonempty destination connection ID",
            move |payload, _context| classify_client_initial_header(payload).is_some(),
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
            let (
                observed_version,
                original_destination_connection_id,
                peer_source_connection_id,
            ) = classify_client_initial_header(ingress.payload()).ok_or_else(|| {
                    FlowError::Build(
                        "matched QUIC Initial no longer has a structurally valid nonzero-version long header"
                            .to_string(),
                    )
                })?;

            if !supported_versions.contains(&observed_version) {
                let advertised_versions = supported_versions
                    .iter()
                    .copied()
                    .chain(version_negotiation_grease_versions.iter().copied());
                let negotiation = QuicVersionNegotiationPacket::new(
                    peer_source_connection_id.clone(),
                    original_destination_connection_id.clone(),
                    advertised_versions,
                )?;
                let response = wrap_quic_udp_datagram(
                    local,
                    peer,
                    QuicUdpPayload::packets([QuicPacket::from_version_negotiation(negotiation)]),
                );

                let mut snapshot =
                    ProtocolContextSnapshot::new("quic", VERSION_NEGOTIATION_SENT);
                snapshot.local_connection_id =
                    Some(original_destination_connection_id.as_bytes().to_vec());
                snapshot.peer_connection_id =
                    Some(peer_source_connection_id.as_bytes().to_vec());
                snapshot.outcome =
                    Some(INITIAL_ONLY_VERSION_NEGOTIATION_SENT_OUTCOME.to_string());
                context.set_protocol_snapshot(snapshot);

                return Ok(Step::emit(response).goto(VERSION_NEGOTIATION_SENT));
            }
            if observed_version != version {
                return Err(FlowError::Build(format!(
                    "configured QUIC Initial server cannot protect supported version 0x{observed_version:08x}"
                )));
            }

            if retry_policy == QuicInitialRetryPolicy::Require {
                let retry_count = context
                    .get_namespaced_u64("quic", "retry_count")?
                    .unwrap_or(0);
                if retry_count >= max_retries as u64 {
                    return Ok(initial_error_step(
                        context,
                        INITIAL_ONLY_RETRY_LIMIT_OUTCOME,
                    ));
                }

                let retry = QuicRetryPacket::builder()
                    .version(QUIC_VERSION_1)
                    .destination_connection_id(peer_source_connection_id.clone())
                    .source_connection_id(server_source_connection_id.clone())
                    .token(&retry_token)
                    .compute_integrity_tag(original_destination_connection_id.as_bytes())
                    .build()?;
                let response = wrap_quic_udp_datagram(
                    local,
                    peer,
                    QuicUdpPayload::packets([QuicPacket::from_retry(retry)]),
                );

                context.insert_namespaced_bool("quic", "retry_token_present", true)?;
                context.insert_namespaced_u64("quic", "retry_count", retry_count + 1)?;
                let mut snapshot = ProtocolContextSnapshot::new("quic", RETRY_SENT);
                snapshot.local_connection_id =
                    Some(server_source_connection_id.as_bytes().to_vec());
                snapshot.peer_connection_id =
                    Some(peer_source_connection_id.as_bytes().to_vec());
                snapshot.outcome = Some(INITIAL_ONLY_RETRY_SENT_OUTCOME.to_string());
                context.set_protocol_snapshot(snapshot);

                return Ok(Step::send_regeneration_only(response).goto(RETRY_SENT));
            }
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
            if ack_state
                .validate(
                    QuicAckPacketNumberSpace::Initial,
                    observations.acknowledgements.iter().map(|ack| &ack.frame),
                )
                .is_err()
            {
                return Ok(initial_error_step(context, INITIAL_INVALID_ACK_OUTCOME));
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
            ack_state.record(context)?;
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
            ack_state.record_sent(server_packet_number)?;

            let mut snapshot = ProtocolContextSnapshot::new("quic", INITIAL_OBSERVED);
            snapshot.local_connection_id = Some(server_source_connection_id.as_bytes().to_vec());
            snapshot.peer_connection_id = Some(peer_source_connection_id);
            context.set_protocol_snapshot(snapshot);

            Ok(Step::send_regeneration_only(response).goto(INITIAL_OBSERVED))
        })
        .targets([INITIAL_OBSERVED, VERSION_NEGOTIATION_SENT, RETRY_SENT])
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
        .state(FlowState::new(VERSION_NEGOTIATION_SENT))
        .state(FlowState::new(RETRY_SENT))
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

fn classify_client_initial_header(
    payload: &[u8],
) -> Option<(u32, QuicConnectionId, QuicConnectionId)> {
    match classify_quic_header(payload).ok()? {
        QuicHeaderClassification::LongHeader {
            first_byte,
            version: observed_version,
            destination_connection_id,
            source_connection_id,
            packet_kind,
            remaining_len,
            ..
        } if observed_version != 0
            && (packet_kind == QuicLongPacketKind::Initial
                || (packet_kind == QuicLongPacketKind::UnknownVersion
                    && first_byte & 0x30 == 0))
            && !destination_connection_id.is_empty()
            && remaining_len > 0 =>
        {
            Some((
                observed_version,
                destination_connection_id,
                source_connection_id,
            ))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicAckPacketNumberSpace {
    Initial,
    Handshake,
    Application,
}

/// Minimal ACK state for the Initial packet-number space.
///
/// RFC 9000 Sections 12.3, 13.1, and 19.3 require ACKs to stay in their
/// packet-number space and permit rejecting acknowledgements for packets that
/// were never sent. Only packet numbers are retained here, never packet bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct QuicInitialAckState {
    sent: BTreeSet<u64>,
    acknowledged: BTreeSet<u64>,
    largest_acknowledged: Option<u64>,
    duplicate_acknowledgements: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct QuicInitialAckUpdate {
    newly_acknowledged: u64,
    duplicates: u64,
    largest_acknowledged: Option<u64>,
}

impl QuicInitialAckState {
    fn from_sent(packet_numbers: impl IntoIterator<Item = u64>) -> Result<Self> {
        let mut state = Self::default();
        for packet_number in packet_numbers {
            state.record_sent(packet_number)?;
        }
        Ok(state)
    }

    fn record_sent(&mut self, packet_number: u64) -> Result<()> {
        if packet_number >= QUIC_PACKET_NUMBER_LIMIT {
            return Err(FlowError::Build(
                "sent QUIC Initial packet number exceeds the 62-bit limit".to_string(),
            ));
        }
        self.sent.insert(packet_number);
        Ok(())
    }

    fn validate<'a>(
        &mut self,
        space: QuicAckPacketNumberSpace,
        acknowledgements: impl IntoIterator<Item = &'a QuicAckFrame>,
    ) -> Result<QuicInitialAckUpdate> {
        if space != QuicAckPacketNumberSpace::Initial {
            return Err(FlowError::Build(
                "Initial-only QUIC ACK validation rejects Handshake and Application packet-number spaces"
                    .to_string(),
            ));
        }

        let largest_sent = self.sent.last().copied();
        let mut acknowledged_in_update = BTreeSet::new();
        let mut duplicates = 0u64;

        for acknowledgement in acknowledgements {
            let ranges = acknowledged_packet_number_ranges(acknowledgement)?;
            let mut previous_low = None;
            let mut acknowledged_in_frame = BTreeSet::new();

            for (low, high) in ranges {
                if low > high || high >= QUIC_PACKET_NUMBER_LIMIT {
                    return Err(FlowError::Build(
                        "QUIC Initial ACK contains an invalid packet-number range".to_string(),
                    ));
                }
                if let Some(previous_low) = previous_low {
                    let separated = high.checked_add(1).is_some_and(|next| next < previous_low);
                    if !separated {
                        return Err(FlowError::Build(
                            "QUIC Initial ACK ranges overlap or contain an invalid gap".to_string(),
                        ));
                    }
                }
                if largest_sent.map_or(true, |largest| high > largest) {
                    return Err(FlowError::Build(
                        "QUIC Initial ACK exceeds the largest sent packet number".to_string(),
                    ));
                }

                let range_len = high
                    .checked_sub(low)
                    .and_then(|length| length.checked_add(1))
                    .ok_or_else(|| {
                        FlowError::Build("QUIC Initial ACK range length overflow".to_string())
                    })?;
                if range_len > self.sent.len() as u64 {
                    return Err(FlowError::Build(
                        "QUIC Initial ACK range contains unsent packet numbers".to_string(),
                    ));
                }

                for packet_number in low..=high {
                    if !self.sent.contains(&packet_number) {
                        return Err(FlowError::Build(format!(
                            "QUIC Initial ACK acknowledges unsent packet number {packet_number}"
                        )));
                    }
                    if !acknowledged_in_frame.insert(packet_number) {
                        return Err(FlowError::Build(
                            "QUIC Initial ACK ranges overlap".to_string(),
                        ));
                    }
                    if self.acknowledged.contains(&packet_number)
                        || !acknowledged_in_update.insert(packet_number)
                    {
                        duplicates = duplicates.checked_add(1).ok_or_else(|| {
                            FlowError::Build(
                                "QUIC Initial duplicate ACK count overflow".to_string(),
                            )
                        })?;
                    }
                }
                previous_low = Some(low);
            }
        }

        let newly_acknowledged = u64::try_from(acknowledged_in_update.len()).map_err(|_| {
            FlowError::Build("QUIC Initial acknowledged packet count exceeds u64".to_string())
        })?;
        self.acknowledged.extend(acknowledged_in_update);
        self.largest_acknowledged = self.acknowledged.last().copied();
        self.duplicate_acknowledgements = self
            .duplicate_acknowledgements
            .checked_add(duplicates)
            .ok_or_else(|| {
            FlowError::Build("QUIC Initial duplicate ACK count overflow".to_string())
        })?;

        Ok(QuicInitialAckUpdate {
            newly_acknowledged,
            duplicates,
            largest_acknowledged: self.largest_acknowledged,
        })
    }

    fn record(&self, context: &mut crate::PacketContext) -> Result<()> {
        let acknowledged_count = u64::try_from(self.acknowledged.len()).map_err(|_| {
            FlowError::Build("QUIC Initial acknowledged packet count exceeds u64".to_string())
        })?;
        context.insert_namespaced_u64(
            "quic",
            "initial_acknowledged_packet_count",
            acknowledged_count,
        )?;
        context.insert_namespaced_u64(
            "quic",
            "initial_duplicate_acknowledgement_count",
            self.duplicate_acknowledgements,
        )?;
        if let Some(largest) = self.largest_acknowledged {
            context.insert_namespaced_u64(
                "quic",
                "initial_largest_acknowledged_packet_number",
                largest,
            )?;
        }
        Ok(())
    }
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
            b"deterministic server Retry fixture".to_vec(),
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

    fn reset_initial_packet_number(&mut self, packet_number: u64) -> Result<()> {
        if packet_number >= QUIC_PACKET_NUMBER_LIMIT {
            return Err(FlowError::Build(
                "QUIC Initial packet number exceeds the 62-bit limit".to_string(),
            ));
        }
        self.next_initial_packet_number = packet_number;
        Ok(())
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
    /// Maximum Version Negotiation restarts processed by the client.
    pub max_version_negotiations: usize,
}

impl Default for QuicInitialBounds {
    fn default() -> Self {
        Self {
            max_crypto_bytes: 4 * 1024,
            max_datagrams: 8,
            max_retries: 1,
            max_version_negotiations: 1,
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
    /// Initially offered QUIC version; v2 is allowed only to negotiate down to v1.
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
        if !matches!(self.version, QUIC_VERSION_1 | QUIC_VERSION_2) {
            return Err(FlowError::Build(
                "QUIC Initial clients can offer only version 1 or version 2".to_string(),
            ));
        }
        if self.version == QUIC_VERSION_2
            && self.version_policy != QuicInitialVersionPolicy::SelectVersion1
        {
            return Err(FlowError::Build(
                "a QUIC v2 Initial offer requires the bounded version-1 selection policy"
                    .to_string(),
            ));
        }
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
    /// Versions advertised as supported, containing the protected Initial version.
    pub supported_versions: Vec<u32>,
    /// Optional deterministic reserved versions appended to Version Negotiation packets.
    pub version_negotiation_grease_versions: Vec<u32>,
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
            supported_versions: vec![QUIC_VERSION_1],
            version_negotiation_grease_versions: Vec::new(),
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
        if self.version != QUIC_VERSION_1 {
            return Err(FlowError::Build(
                "QUIC Initial-only servers support version 1 only".to_string(),
            ));
        }
        if self.supported_versions.is_empty()
            || self.supported_versions.iter().any(|version| *version == 0)
            || !self.supported_versions.contains(&self.version)
        {
            return Err(FlowError::Build(
                "QUIC Initial server supported versions must be nonzero and include the configured version"
                    .to_string(),
            ));
        }
        if self
            .version_negotiation_grease_versions
            .iter()
            .any(|grease| *grease == 0 || self.supported_versions.contains(grease))
        {
            return Err(FlowError::Build(
                "QUIC Version Negotiation grease versions must be nonzero and distinct from supported versions"
                    .to_string(),
            ));
        }
        if self.retry_policy == QuicInitialRetryPolicy::AcceptValid {
            return Err(FlowError::Build(
                "QUIC Initial servers cannot use the client Retry policy".to_string(),
            ));
        }
        if self.retry_policy == QuicInitialRetryPolicy::Require {
            if self.bounds.max_retries == 0 {
                return Err(FlowError::Build(
                    "QUIC Initial servers requiring Retry need a nonzero Retry bound".to_string(),
                ));
            }
            if self.identifiers.retry_token().is_empty() {
                return Err(FlowError::Build(
                    "QUIC Initial servers requiring Retry need nonempty deterministic fixture bytes"
                        .to_string(),
                ));
            }
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
    if version == 0 {
        return Err(FlowError::Build(
            "QUIC Initial-only flows require a nonzero version".to_string(),
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
    if bounds.max_version_negotiations > 1 {
        return Err(FlowError::Build(
            "QUIC Initial-only flows permit at most one Version Negotiation restart".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crafter::{
        quic_decode_initial_protected_payload_with_keys, Ipv4, Quic, QuicRetryIntegrityStatus,
        QuicVarInt, Udp,
    };

    #[test]
    fn initial_ack_ranges_only_cover_sent_packets() -> crate::Result<()> {
        struct Case {
            name: &'static str,
            sent: &'static [u64],
            acknowledgements: Vec<QuicAckFrame>,
            expected: std::result::Result<(u64, u64, Option<u64>, usize), ()>,
        }

        let single = QuicAckFrame::from_values(2, 0, 2, Vec::new())?;
        let multiple = QuicAckFrame::from_values(
            10,
            0,
            0,
            vec![
                QuicAckRange::from_values(2, 2)?,
                QuicAckRange::from_values(1, 1)?,
            ],
        )?;
        let gap_underflow =
            QuicAckFrame::from_values(0, 0, 0, vec![QuicAckRange::from_values(0, 0)?])?;
        let unsent = QuicAckFrame::from_values(2, 0, 2, Vec::new())?;

        let cases = vec![
            Case {
                name: "single range",
                sent: &[0, 1, 2],
                acknowledgements: vec![single.clone()],
                expected: Ok((3, 0, Some(2), 3)),
            },
            Case {
                name: "multiple ranges",
                sent: &[0, 1, 4, 5, 6, 10],
                acknowledgements: vec![multiple],
                expected: Ok((6, 0, Some(10), 6)),
            },
            Case {
                name: "duplicate acknowledgement",
                sent: &[0, 1, 2],
                acknowledgements: vec![single.clone(), single],
                expected: Ok((3, 3, Some(2), 3)),
            },
            Case {
                name: "gap underflow",
                sent: &[0],
                acknowledgements: vec![gap_underflow],
                expected: Err(()),
            },
            Case {
                name: "unsent acknowledgement",
                sent: &[0, 2],
                acknowledgements: vec![unsent],
                expected: Err(()),
            },
        ];

        for case in cases {
            let mut state = QuicInitialAckState::from_sent(case.sent.iter().copied())?;
            let result = state.validate(
                QuicAckPacketNumberSpace::Initial,
                case.acknowledgements.iter(),
            );
            match case.expected {
                Ok((newly_acknowledged, duplicates, largest, acknowledged_count)) => {
                    let update = result.unwrap_or_else(|error| {
                        panic!("{} unexpectedly failed: {error}", case.name)
                    });
                    assert_eq!(
                        update.newly_acknowledged, newly_acknowledged,
                        "{}",
                        case.name
                    );
                    assert_eq!(update.duplicates, duplicates, "{}", case.name);
                    assert_eq!(update.largest_acknowledged, largest, "{}", case.name);
                    assert_eq!(
                        state.acknowledged.len(),
                        acknowledged_count,
                        "{}",
                        case.name
                    );
                }
                Err(()) => assert!(result.is_err(), "{} unexpectedly passed", case.name),
            }
        }

        let initial_ack = QuicAckFrame::from_values(0, 0, 0, Vec::new())?;
        for space in [
            QuicAckPacketNumberSpace::Handshake,
            QuicAckPacketNumberSpace::Application,
        ] {
            let mut state = QuicInitialAckState::from_sent([0])?;
            assert!(state.validate(space, [&initial_ack]).is_err());
            assert!(state.acknowledged.is_empty());
        }

        let mut context = crate::PacketContext::new();
        let mut state = QuicInitialAckState::from_sent([0, 1, 2])?;
        state.validate(QuicAckPacketNumberSpace::Initial, [&initial_ack])?;
        state.validate(QuicAckPacketNumberSpace::Initial, [&initial_ack])?;
        state.record(&mut context)?;
        assert_eq!(
            context.get_namespaced_u64("quic", "initial_largest_acknowledged_packet_number")?,
            Some(0)
        );
        assert_eq!(
            context.get_namespaced_u64("quic", "initial_acknowledged_packet_count")?,
            Some(1)
        );
        assert_eq!(
            context.get_namespaced_u64("quic", "initial_duplicate_acknowledgement_count")?,
            Some(1)
        );
        Ok(())
    }

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
    fn initial_server_emits_version_negotiation_for_unsupported_version() -> crate::Result<()> {
        const UNSUPPORTED_VERSION: u32 = 0xface_feed;
        const GREASE_VERSION: u32 = 0x0a0a_0a0a;

        let client_config = QuicInitialClientConfig::default();
        let expected_destination_connection_id = client_config
            .identifiers
            .local_source_connection_id()
            .clone();
        let expected_source_connection_id = client_config
            .identifiers
            .original_destination_connection_id()
            .clone();
        let client_local = client_config.local;
        let client_peer = client_config.peer;
        let mut client = quic_initial_client_flow(client_config)?;
        let mut client_context = crate::PacketContext::new();
        let mut unsupported_payload = client
            .state_mut(INITIAL_SENT)
            .expect("InitialSent state exists")
            .run_entry(&mut client_context)?
            .expect("client emits its protected Initial")
            .outputs()[0]
            .packet()
            .layer::<Quic>()
            .expect("typed QUIC layer")
            .packets()[0]
            .as_bytes()
            .to_vec();
        unsupported_payload[1..5].copy_from_slice(&UNSUPPORTED_VERSION.to_be_bytes());
        let unsupported_initial = Ipv4::new().src(*client_local.ip()).dst(*client_peer.ip())
            / Udp::new()
                .source_port(client_local.port())
                .destination_port(client_peer.port())
            / Quic::from_bytes(unsupported_payload);

        let mut server_config = QuicInitialServerConfig::default();
        server_config.version_negotiation_grease_versions = vec![GREASE_VERSION];
        let server_local = server_config.local;
        let server_peer = server_config.peer;
        let mut server = quic_initial_server_flow(server_config)?;
        let mut server_context = crate::PacketContext::new();
        let transition = server
            .state_mut(LISTEN)
            .expect("Listen state exists")
            .find_transition(&unsupported_initial, &server_context)
            .expect("server matches structurally valid unsupported Initial");
        let step = transition.fire(&unsupported_initial, &mut server_context)?;

        assert_eq!(step.target(), Some(VERSION_NEGOTIATION_SENT));
        assert_eq!(step.outputs().len(), 1);
        assert!(!step.expects_reply());
        assert!(!step.outputs()[0].allows_exact_replay());
        assert!(!step.outputs()[0].requires_regeneration());
        let response = step.outputs()[0].packet();
        let ipv4 = response.layer::<Ipv4>().expect("typed IPv4 layer");
        let udp = response.layer::<Udp>().expect("typed UDP layer");
        let quic = response.layer::<Quic>().expect("typed QUIC layer");
        assert_eq!(ipv4.source(), *server_local.ip());
        assert_eq!(ipv4.destination(), *server_peer.ip());
        assert_eq!(udp.source_port_value(), server_local.port());
        assert_eq!(udp.destination_port_value(), server_peer.port());
        let negotiation = quic.packets()[0]
            .version_negotiation()
            .expect("typed Version Negotiation packet");
        assert_eq!(
            negotiation.destination_connection_id(),
            &expected_destination_connection_id
        );
        assert_eq!(
            negotiation.source_connection_id(),
            &expected_source_connection_id
        );
        assert_eq!(
            negotiation.supported_versions(),
            &[QUIC_VERSION_1, GREASE_VERSION]
        );

        assert_eq!(
            server_context.get_namespaced_u64("quic", "initial_packet_number_received")?,
            None
        );
        assert_eq!(
            server_context.get_namespaced_bytes("quic", "initial_crypto_bytes")?,
            None
        );
        let snapshot = server_context
            .protocol_snapshot()
            .expect("Version Negotiation records a lifecycle snapshot");
        assert_eq!(snapshot.lifecycle, VERSION_NEGOTIATION_SENT);
        assert_eq!(
            snapshot.outcome.as_deref(),
            Some(INITIAL_ONLY_VERSION_NEGOTIATION_SENT_OUTCOME)
        );
        Ok(())
    }

    #[test]
    fn initial_server_retry_has_valid_integrity_and_bounded_count() -> crate::Result<()> {
        let client_config = QuicInitialClientConfig::default();
        let original_destination_connection_id = client_config
            .identifiers
            .original_destination_connection_id()
            .clone();
        let client_source_connection_id = client_config
            .identifiers
            .local_source_connection_id()
            .clone();
        let mut client = quic_initial_client_flow(client_config)?;
        let client_initial = client
            .state_mut(INITIAL_SENT)
            .expect("InitialSent state exists")
            .run_entry(&mut crate::PacketContext::new())?
            .expect("client emits its protected Initial")
            .outputs()[0]
            .packet()
            .clone();

        let mut server_config = QuicInitialServerConfig::default();
        server_config.retry_policy = QuicInitialRetryPolicy::Require;
        let expected_server_source_connection_id = server_config
            .identifiers
            .local_source_connection_id()
            .clone();
        let expected_token = server_config.identifiers.retry_token().to_vec();
        let mut server = quic_initial_server_flow(server_config)?;
        let mut context = crate::PacketContext::new();
        let transition = server
            .state_mut(LISTEN)
            .expect("Listen state exists")
            .find_transition(&client_initial, &context)
            .expect("server matches the client Initial");
        let retry_step = transition.fire(&client_initial, &mut context)?;

        assert_eq!(retry_step.target(), Some(RETRY_SENT));
        assert_eq!(retry_step.outputs().len(), 1);
        assert!(retry_step.outputs()[0].requires_regeneration());
        let retry = retry_step.outputs()[0]
            .packet()
            .layer::<Quic>()
            .expect("typed QUIC layer")
            .packets()[0]
            .retry()
            .expect("typed Retry packet");
        assert_eq!(retry.version(), QUIC_VERSION_1);
        assert_eq!(
            retry.destination_connection_id(),
            &client_source_connection_id
        );
        assert_eq!(
            retry.source_connection_id(),
            &expected_server_source_connection_id
        );
        assert_eq!(retry.token(), expected_token);
        assert_eq!(
            retry.integrity_status(original_destination_connection_id.as_bytes())?,
            QuicRetryIntegrityStatus::Valid
        );
        assert_eq!(
            context.get_namespaced_bool("quic", "retry_token_present")?,
            Some(true)
        );
        assert_eq!(context.get_namespaced_u64("quic", "retry_count")?, Some(1));
        assert_eq!(context.get_namespaced_bytes("quic", "retry_token")?, None);
        assert!(!context
            .summary()
            .contains("deterministic server Retry fixture"));
        let snapshot = context
            .protocol_snapshot()
            .expect("Retry records a lifecycle snapshot");
        assert_eq!(snapshot.lifecycle, RETRY_SENT);
        assert_eq!(
            snapshot.outcome.as_deref(),
            Some(INITIAL_ONLY_RETRY_SENT_OUTCOME)
        );

        let repeated = transition.fire(&client_initial, &mut context)?;
        assert!(repeated.is_terminal());
        assert!(repeated.outputs().is_empty());
        assert_eq!(repeated.outcome(), Some(INITIAL_ONLY_RETRY_LIMIT_OUTCOME));
        assert_eq!(context.get_namespaced_u64("quic", "retry_count")?, Some(1));
        Ok(())
    }

    #[test]
    fn initial_client_valid_retry_rebuilds_fresh_token_initial() -> crate::Result<()> {
        let client_config = QuicInitialClientConfig::default();
        let original_destination_connection_id = client_config
            .identifiers
            .original_destination_connection_id()
            .clone();
        let client_source_connection_id = client_config
            .identifiers
            .local_source_connection_id()
            .clone();
        let mut client = quic_initial_client_flow(client_config)?;
        let mut client_context = crate::PacketContext::new();
        let first_initial = client
            .state_mut(INITIAL_SENT)
            .expect("InitialSent state exists")
            .run_entry(&mut client_context)?
            .expect("client emits its first Initial")
            .outputs()[0]
            .packet()
            .clone();

        let mut server_config = QuicInitialServerConfig::default();
        server_config.retry_policy = QuicInitialRetryPolicy::Require;
        let retry_source_connection_id = server_config
            .identifiers
            .local_source_connection_id()
            .clone();
        let retry_token = server_config.identifiers.retry_token().to_vec();
        let mut server = quic_initial_server_flow(server_config)?;
        let mut server_context = crate::PacketContext::new();
        let retry_transition = server
            .state_mut(LISTEN)
            .expect("Listen state exists")
            .find_transition(&first_initial, &server_context)
            .expect("server matches the first Initial");
        let retry_step = retry_transition.fire(&first_initial, &mut server_context)?;
        let retry_packet = retry_step.outputs()[0].packet().clone();

        let client_state = client
            .state_mut(INITIAL_SENT)
            .expect("InitialSent state exists");
        let retry_transition = client_state
            .find_transition(&retry_packet, &client_context)
            .expect("client matches the valid Retry");
        let restarted = retry_transition.fire(&retry_packet, &mut client_context)?;

        assert_eq!(restarted.target(), None);
        assert_eq!(restarted.outputs().len(), 1);
        assert!(restarted.outputs()[0].requires_regeneration());
        assert_eq!(restarted.wakeup(), Some(INITIAL_CLIENT_TIMEOUT));
        let fresh_initial = restarted.outputs()[0].packet();
        let fresh_quic = fresh_initial
            .layer::<Quic>()
            .expect("fresh Initial retains a typed QUIC layer");
        let fresh_bytes = fresh_quic.packets()[0].as_bytes();
        assert_ne!(
            fresh_bytes,
            first_initial
                .layer::<Quic>()
                .expect("first Initial has a QUIC layer")
                .packets()[0]
                .as_bytes()
        );
        assert!(fresh_bytes
            .windows(retry_token.len())
            .any(|window| window == retry_token));
        assert!(matches!(
            classify_quic_header(fresh_bytes)?,
            QuicHeaderClassification::LongHeader {
                version: QUIC_VERSION_1,
                destination_connection_id,
                source_connection_id,
                packet_kind: QuicLongPacketKind::Initial,
                ..
            } if destination_connection_id == retry_source_connection_id
                && source_connection_id == client_source_connection_id
        ));

        let keys = derive_quic_initial_secrets(
            QUIC_VERSION_1,
            original_destination_connection_id.as_bytes(),
        )?
        .client_packet_keys()?;
        let decoded = quic_decode_initial_protected_payload_with_keys(fresh_bytes, &keys)?;
        assert_eq!(decoded.packet_number().value(), 1);
        assert!(fresh_bytes.len() >= 1200);
        assert_eq!(
            client_context.get_namespaced_u64("quic", "retry_count")?,
            Some(1)
        );
        assert_eq!(
            client_context.get_namespaced_bool("quic", "retry_token_present")?,
            Some(true)
        );
        assert_eq!(
            client_context.get_namespaced_bytes("quic", "retry_token")?,
            None
        );
        assert!(!client_context
            .summary()
            .contains("deterministic server Retry fixture"));
        let snapshot = client_context
            .protocol_snapshot()
            .expect("valid Retry records a lifecycle snapshot");
        assert_eq!(snapshot.lifecycle, RETRY_RECEIVED);
        assert_ne!(snapshot.lifecycle, "Established");
        assert_eq!(
            snapshot.peer_connection_id.as_deref(),
            Some(retry_source_connection_id.as_bytes())
        );
        Ok(())
    }

    #[test]
    fn initial_client_handles_version_negotiation_with_downgrade_checks() -> crate::Result<()> {
        const UNKNOWN_VERSION: u32 = 0x0a0a_0a0a;

        fn negotiation_for(
            config: &QuicInitialClientConfig,
            destination_connection_id: QuicConnectionId,
            source_connection_id: QuicConnectionId,
            versions: impl IntoIterator<Item = u32>,
        ) -> crate::Result<crafter::Packet> {
            let negotiation = QuicVersionNegotiationPacket::new(
                destination_connection_id,
                source_connection_id,
                versions,
            )?;
            Ok(wrap_quic_udp_datagram(
                config.peer,
                config.local,
                QuicUdpPayload::packets([QuicPacket::from_version_negotiation(negotiation)]),
            ))
        }

        fn negotiation_outcome(
            config: QuicInitialClientConfig,
            packet: &crafter::Packet,
            prepare: impl FnOnce(&mut crate::PacketContext) -> crate::Result<()>,
        ) -> crate::Result<(String, usize)> {
            let mut flow = quic_initial_client_flow(config)?;
            let mut context = crate::PacketContext::new();
            flow.state_mut(INITIAL_SENT)
                .expect("InitialSent state exists")
                .run_entry(&mut context)?;
            prepare(&mut context)?;
            let state = flow
                .state_mut(INITIAL_SENT)
                .expect("InitialSent state exists");
            let transition = state
                .find_transition(packet, &context)
                .expect("Version Negotiation transition matches");
            let step = transition.fire(packet, &mut context)?;
            Ok((
                step.outcome().expect("terminal outcome").to_string(),
                step.outputs().len(),
            ))
        }

        let mut config = QuicInitialClientConfig::default();
        config.version = QUIC_VERSION_2;
        config.version_policy = QuicInitialVersionPolicy::SelectVersion1;
        let client_source = config.identifiers.local_source_connection_id().clone();
        let original_destination = config
            .identifiers
            .current_destination_connection_id()
            .clone();
        let valid = negotiation_for(
            &config,
            client_source.clone(),
            original_destination.clone(),
            [QUIC_VERSION_1],
        )?;

        let mut flow = quic_initial_client_flow(config.clone())?;
        let mut context = crate::PacketContext::new();
        let first = flow
            .state_mut(INITIAL_SENT)
            .expect("InitialSent state exists")
            .run_entry(&mut context)?
            .expect("client emits its offered-version Initial");
        match classify_quic_header(
            first.outputs()[0]
                .packet()
                .layer::<Quic>()
                .expect("typed QUIC layer")
                .packets()[0]
                .as_bytes(),
        )? {
            QuicHeaderClassification::LongHeader { version, .. } => {
                assert_eq!(version, QUIC_VERSION_2)
            }
            classification => panic!("unexpected offered Initial: {classification:?}"),
        }
        let selected = flow
            .state_mut(INITIAL_SENT)
            .expect("InitialSent state exists")
            .find_transition(&valid, &context)
            .expect("valid Version Negotiation matches")
            .fire(&valid, &mut context)?;
        assert_eq!(selected.outcome(), None);
        assert_eq!(selected.outputs().len(), 1);
        assert!(selected.outputs()[0].requires_regeneration());
        let selected_payload = selected.outputs()[0]
            .packet()
            .layer::<Quic>()
            .expect("typed QUIC layer")
            .packets()[0]
            .as_bytes();
        match classify_quic_header(selected_payload)? {
            QuicHeaderClassification::LongHeader { version, .. } => {
                assert_eq!(version, QUIC_VERSION_1)
            }
            classification => panic!("unexpected selected Initial: {classification:?}"),
        }
        let selected_keys = derive_quic_initial_secrets(
            QUIC_VERSION_1,
            config
                .identifiers
                .original_destination_connection_id()
                .as_bytes(),
        )?
        .client_packet_keys()?;
        let decoded =
            quic_decode_initial_protected_payload_with_keys(selected_payload, &selected_keys)?;
        assert_eq!(decoded.packet_number().value(), 0);
        assert_eq!(
            context.get_namespaced_u64("quic", "version_negotiation_selected_version")?,
            Some(QUIC_VERSION_1 as u64)
        );
        assert_eq!(
            context
                .protocol_snapshot()
                .and_then(|snapshot| snapshot.outcome.as_deref()),
            Some(INITIAL_ONLY_VERSION_NEGOTIATION_SELECTED_OUTCOME)
        );

        let reflected = negotiation_for(
            &config,
            client_source.clone(),
            original_destination.clone(),
            [QUIC_VERSION_2, QUIC_VERSION_1],
        )?;
        assert_eq!(
            negotiation_outcome(config.clone(), &reflected, |_| Ok(()))?,
            (
                INITIAL_ONLY_VERSION_NEGOTIATION_REJECTED_OUTCOME.to_string(),
                0
            )
        );

        let unsupported = negotiation_for(
            &config,
            client_source.clone(),
            original_destination.clone(),
            [UNKNOWN_VERSION],
        )?;
        assert_eq!(
            negotiation_outcome(config.clone(), &unsupported, |_| Ok(()))?,
            (
                INITIAL_ONLY_VERSION_NEGOTIATION_UNSUPPORTED_OUTCOME.to_string(),
                0
            )
        );

        let mut malformed_payload = valid.layer::<Quic>().expect("typed QUIC layer").packets()[0]
            .as_bytes()
            .to_vec();
        malformed_payload.truncate(malformed_payload.len() - 4);
        let malformed = Ipv4::new().src(*config.peer.ip()).dst(*config.local.ip())
            / Udp::new()
                .source_port(config.peer.port())
                .destination_port(config.local.port())
            / Quic::from_bytes(malformed_payload);
        let mut malformed_flow = quic_initial_client_flow(config.clone())?;
        let mut malformed_context = crate::PacketContext::new();
        malformed_flow
            .state_mut(INITIAL_SENT)
            .expect("InitialSent state exists")
            .run_entry(&mut malformed_context)?;
        assert!(malformed_flow
            .state_mut(INITIAL_SENT)
            .expect("InitialSent state exists")
            .find_transition(&malformed, &malformed_context)
            .is_none());
        assert_eq!(
            malformed_context.get_namespaced_u64("quic", "version_negotiation_selected_version")?,
            None
        );

        let wrong_identifiers = negotiation_for(
            &config,
            QuicConnectionId::from_bytes([0xee; 8]),
            original_destination,
            [QUIC_VERSION_1],
        )?;
        assert_eq!(
            negotiation_outcome(config.clone(), &wrong_identifiers, |_| Ok(()))?,
            (
                INITIAL_ONLY_VERSION_NEGOTIATION_REJECTED_OUTCOME.to_string(),
                0
            )
        );

        assert_eq!(
            negotiation_outcome(config.clone(), &valid, |context| {
                context.insert_namespaced_u64("quic", "version_negotiation_count", 1)
            })?,
            (
                INITIAL_ONLY_VERSION_NEGOTIATION_REJECTED_OUTCOME.to_string(),
                0
            )
        );
        assert_eq!(
            negotiation_outcome(config, &valid, |context| {
                context.insert_namespaced_bool("quic", "initial_authenticated_server_traffic", true)
            })?,
            (
                INITIAL_ONLY_VERSION_NEGOTIATION_REJECTED_OUTCOME.to_string(),
                0
            )
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
    fn initial_client_records_server_ack_and_crypto_without_establishment() -> crate::Result<()> {
        let client_config = QuicInitialClientConfig::default();
        let server_config = QuicInitialServerConfig::default();
        let expected_crypto = server_config.crypto.clone();
        let expected_local_connection_id = client_config
            .identifiers
            .local_source_connection_id()
            .as_bytes()
            .to_vec();
        let expected_peer_connection_id = server_config
            .identifiers
            .local_source_connection_id()
            .as_bytes()
            .to_vec();

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
        let server_listen = server.state_mut(LISTEN).expect("Listen state exists");
        let server_transition = server_listen
            .find_transition(&client_initial, &server_context)
            .expect("server accepts the protected client Initial");
        let server_response = server_transition
            .fire(&client_initial, &mut server_context)?
            .outputs()[0]
            .packet()
            .clone();

        let client_initial_sent = client
            .state_mut(INITIAL_SENT)
            .expect("InitialSent state exists");
        let client_transition = client_initial_sent
            .find_transition(&server_response, &client_context)
            .expect("client matches the reversed tuple and expected connection IDs");
        let observed = client_transition.fire(&server_response, &mut client_context)?;

        assert!(observed.is_terminal());
        assert_eq!(
            observed.outcome(),
            Some(INITIAL_ONLY_SERVER_INITIAL_OBSERVED_OUTCOME)
        );
        assert_eq!(
            client_context.get_namespaced_u64("quic", "initial_packet_number_received")?,
            Some(0)
        );
        assert_eq!(
            client_context.get_namespaced_u64("quic", "initial_expected_peer_packet_number")?,
            Some(1)
        );
        assert_eq!(
            client_context.get_namespaced_bytes("quic", "initial_crypto_bytes")?,
            Some(expected_crypto.as_slice())
        );
        assert_eq!(
            client_context.get_namespaced_string("quic", "initial_ack_ranges")?,
            Some("0-0")
        );

        let snapshot = client_context
            .protocol_snapshot()
            .expect("client records an Initial observation snapshot");
        assert_eq!(snapshot.lifecycle, INITIAL_OBSERVED);
        assert_eq!(
            snapshot.outcome.as_deref(),
            Some(INITIAL_ONLY_SERVER_INITIAL_OBSERVED_OUTCOME)
        );
        assert_eq!(
            snapshot.local_connection_id.as_deref(),
            Some(expected_local_connection_id.as_slice())
        );
        assert_eq!(
            snapshot.peer_connection_id.as_deref(),
            Some(expected_peer_connection_id.as_slice())
        );
        assert_ne!(snapshot.lifecycle, "Handshaking");
        assert_ne!(snapshot.lifecycle, "Established");
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
