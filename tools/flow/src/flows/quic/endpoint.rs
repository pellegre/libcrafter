//! Bounded authenticated QUIC endpoint flow graphs.

use std::{cell::RefCell, net::SocketAddr, rc::Rc};

use crate::{
    quic_endpoint::{
        configure_endpoint_client_tls, configure_endpoint_server_tls, QuicEndpointAddresses,
        QuicEndpointClientRequest, QuicEndpointClock, QuicEndpointDriver, QuicEndpointEvent,
        QuicEndpointEventMapper, QuicEndpointLifecycle, QuicEndpointServerPolicy,
        QuicEndpointServerRequest, QuicEndpointServerResponse, QuicEndpointStreamId,
        QuicEndpointSystemClock, QuicPeerConfig, QuicSyntheticIdentity, QuicTransportLimits,
        QuinnProtoClientDriver, QuinnProtoServerDriver,
    },
    quic_wire::extract_quic_udp_ingress,
    Flow, FlowBuilderExt, FlowState, PacketContext, PredicateMatcher, Result, Role, Step,
    StepGotoExt, Transition,
};

const INITIAL_SENT: &str = "InitialSent";
const LISTEN: &str = "Listen";
const HANDSHAKING: &str = "Handshaking";
const ESTABLISHED: &str = "Established";
const CLOSING: &str = "Closing";
const DRAINING: &str = "Draining";
const CLOSED: &str = "Closed";
const ACTIVE_TARGETS: [&str; 5] = [HANDSHAKING, ESTABLISHED, CLOSING, DRAINING, CLOSED];

/// Stable configuration for one bounded authenticated QUIC client exchange.
#[derive(Debug, Clone)]
pub struct QuicClientFlowConfig {
    /// Documentation-safe local and peer UDP tuples.
    pub addresses: QuicEndpointAddresses,
    /// Authenticated peer name and ALPN policy.
    pub peer: QuicPeerConfig,
    /// Trust anchors used for the TLS 1.3 handshake.
    pub identity: QuicSyntheticIdentity,
    /// Opaque request bytes written on stream zero after authentication.
    pub request: Vec<u8>,
    /// Bounded QUIC transport policy.
    pub limits: QuicTransportLimits,
}

/// Stable configuration for one bounded authenticated QUIC server exchange.
#[derive(Debug, Clone)]
pub struct QuicServerFlowConfig {
    /// Documentation-safe listening and expected peer UDP tuples.
    pub addresses: QuicEndpointAddresses,
    /// Synthetic server certificate and private key bytes.
    pub identity: QuicSyntheticIdentity,
    /// Opaque response bytes written on the accepted request stream.
    pub response: Vec<u8>,
    /// Bounded QUIC transport policy.
    pub limits: QuicTransportLimits,
}

impl QuicServerFlowConfig {
    /// Construct a passive server configuration without opening a socket.
    pub fn new(
        addresses: QuicEndpointAddresses,
        identity: QuicSyntheticIdentity,
        response: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            addresses,
            identity,
            response: response.into(),
            limits: QuicTransportLimits::default(),
        }
    }

    /// Replace the default bounded transport policy.
    pub const fn with_limits(mut self, limits: QuicTransportLimits) -> Self {
        self.limits = limits;
        self
    }
}

impl QuicClientFlowConfig {
    /// Construct a client flow configuration without opening a socket.
    pub fn new(
        addresses: QuicEndpointAddresses,
        peer: QuicPeerConfig,
        identity: QuicSyntheticIdentity,
        request: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            addresses,
            peer,
            identity,
            request: request.into(),
            limits: QuicTransportLimits::default(),
        }
    }

    /// Replace the default bounded transport policy.
    pub const fn with_limits(mut self, limits: QuicTransportLimits) -> Self {
        self.limits = limits;
        self
    }
}

struct ClientRuntime {
    driver: QuinnProtoClientDriver,
    mapper: QuicEndpointEventMapper,
    request: QuicEndpointClientRequest,
    clock: QuicEndpointSystemClock,
    addresses: QuicEndpointAddresses,
    max_udp_payload_size: u16,
}

impl ClientRuntime {
    fn start(&mut self, context: &mut PacketContext) -> Result<Step> {
        let now = self.clock.now();
        self.driver.start(now)?;
        self.mapper.poll(&mut self.driver, context)?;
        Ok(self
            .driver
            .drain_transmit_step(now, self.addresses, context)?
            .goto(HANDSHAKING))
    }

    fn packet(&mut self, packet: &crafter::Packet, context: &mut PacketContext) -> Result<Step> {
        let (SocketAddr::V4(local), SocketAddr::V4(peer)) =
            (self.addresses.local, self.addresses.peer)
        else {
            return Ok(Step::done_with("unsupported-ipv6-endpoint"));
        };
        let Some(ingress) = extract_quic_udp_ingress(packet, local, peer, context) else {
            return Ok(Step::stay());
        };
        let now = self.clock.now();
        self.driver
            .handle_ingress(&ingress, self.addresses, self.max_udp_payload_size, now)?;
        self.after_provider_action(now, context)
    }

    fn timeout(&mut self, context: &mut PacketContext) -> Result<Step> {
        let now = self.clock.now();
        self.driver.handle_timeout(now)?;
        self.after_provider_action(now, context)
    }

    fn after_provider_action(
        &mut self,
        now: std::time::Instant,
        context: &mut PacketContext,
    ) -> Result<Step> {
        self.mapper.poll(&mut self.driver, context)?;
        if matches!(
            self.driver.snapshot().lifecycle,
            QuicEndpointLifecycle::Established
        ) {
            // The provider has authenticated and decoded its peer parameters;
            // later policy steps enrich this observation with the decoded values.
            context.insert_namespaced_string("quic", "transport.validation", "validated")?;
            let _ = self.request.drive(&mut self.driver, context)?;
        }
        if context.get_namespaced_bool("quic", "application.complete")? == Some(true) {
            self.driver.close(now, 0, b"bounded exchange complete")?;
        }
        let target = lifecycle_state(self.driver.snapshot().lifecycle);
        Ok(self
            .driver
            .drain_transmit_step(now, self.addresses, context)?
            .goto(target))
    }
}

fn lifecycle_state(lifecycle: QuicEndpointLifecycle) -> &'static str {
    match lifecycle {
        QuicEndpointLifecycle::Starting | QuicEndpointLifecycle::InitialSent => INITIAL_SENT,
        QuicEndpointLifecycle::Listen | QuicEndpointLifecycle::Handshaking => HANDSHAKING,
        QuicEndpointLifecycle::Established => ESTABLISHED,
        QuicEndpointLifecycle::Closing | QuicEndpointLifecycle::Failed => CLOSING,
        QuicEndpointLifecycle::Draining => DRAINING,
        QuicEndpointLifecycle::Closed => CLOSED,
    }
}

fn datagram_transition(
    runtime: Rc<RefCell<ClientRuntime>>,
    addresses: QuicEndpointAddresses,
) -> Transition {
    let matcher_addresses = addresses;
    Transition::on(
        PredicateMatcher::new(
            "matching bounded QUIC UDP datagram",
            move |packet, context| {
                let (SocketAddr::V4(local), SocketAddr::V4(peer)) =
                    (matcher_addresses.local, matcher_addresses.peer)
                else {
                    return false;
                };
                extract_quic_udp_ingress(packet, local, peer, context).is_some()
            },
        ),
        move |packet, context| runtime.borrow_mut().packet(packet, context),
    )
    .targets(ACTIVE_TARGETS)
}

fn active_state(
    name: &'static str,
    runtime: Rc<RefCell<ClientRuntime>>,
    addresses: QuicEndpointAddresses,
) -> FlowState {
    let timeout_runtime = Rc::clone(&runtime);
    FlowState::new(name)
        .on(datagram_transition(runtime, addresses))
        .on_timeout(move |context| timeout_runtime.borrow_mut().timeout(context))
        .timeout_description("drive provider-owned QUIC deadline")
        .timeout_targets(ACTIVE_TARGETS)
}

/// Build one socket-free, bounded authenticated QUIC client flow.
pub fn quic_client_flow(config: QuicClientFlowConfig) -> Result<Flow> {
    let tls = configure_endpoint_client_tls(&config.peer, &config.identity, config.limits)?;
    let clock = QuicEndpointSystemClock;
    let now = clock.now();
    let runtime = Rc::new(RefCell::new(ClientRuntime {
        driver: QuinnProtoClientDriver::new(tls, config.addresses, now)?,
        mapper: QuicEndpointEventMapper::new(QuicEndpointLifecycle::InitialSent),
        request: QuicEndpointClientRequest::new(config.request, config.limits.max_stream_bytes),
        clock,
        addresses: config.addresses,
        max_udp_payload_size: config.limits.max_udp_payload_size,
    }));

    let start_runtime = Rc::clone(&runtime);
    let initial = FlowState::new(INITIAL_SENT)
        .on_entry(move |context| start_runtime.borrow_mut().start(context))
        .entry_description("start socket-free QUIC client and emit Initial")
        .entry_targets([HANDSHAKING])
        .on_timeout({
            let runtime = Rc::clone(&runtime);
            move |context| runtime.borrow_mut().timeout(context)
        })
        .timeout_description("drive Initial packet-space deadline")
        .timeout_targets(ACTIVE_TARGETS);
    let closed = FlowState::new(CLOSED)
        .on_entry(|_| Ok(Step::done_with("quic-client-closed")))
        .entry_description("finish bounded QUIC client flow")
        .entry_terminal()
        .on_timeout(|_| Ok(Step::done_with("quic-client-closed")))
        .timeout_description("remain terminal after close")
        .timeout_terminal();

    let flow = Flow::new("quic-client")
        .role(Role::Initiator)
        .state(initial)
        .state(active_state(
            HANDSHAKING,
            Rc::clone(&runtime),
            config.addresses,
        ))
        .state(active_state(
            ESTABLISHED,
            Rc::clone(&runtime),
            config.addresses,
        ))
        .state(active_state(CLOSING, Rc::clone(&runtime), config.addresses))
        .state(active_state(DRAINING, runtime, config.addresses))
        .state(closed)
        .initial(INITIAL_SENT);
    flow.validate()?;
    Ok(flow)
}

struct ServerRuntime {
    driver: QuinnProtoServerDriver,
    mapper: QuicEndpointEventMapper,
    request: QuicEndpointServerRequest,
    response: QuicEndpointServerResponse,
    stream: Option<QuicEndpointStreamId>,
    clock: QuicEndpointSystemClock,
    addresses: QuicEndpointAddresses,
    max_udp_payload_size: u16,
}

impl ServerRuntime {
    fn start(&mut self, context: &mut PacketContext) -> Result<Step> {
        let now = self.clock.now();
        self.driver.start(now)?;
        self.mapper.poll(&mut self.driver, context)?;
        Ok(self
            .driver
            .drain_transmit_step(now, self.addresses, context)?
            .goto(LISTEN))
    }

    fn packet(&mut self, packet: &crafter::Packet, context: &mut PacketContext) -> Result<Step> {
        let (SocketAddr::V4(local), SocketAddr::V4(peer)) =
            (self.addresses.local, self.addresses.peer)
        else {
            return Ok(Step::done_with("unsupported-ipv6-endpoint"));
        };
        let Some(ingress) = extract_quic_udp_ingress(packet, local, peer, context) else {
            return Ok(Step::stay());
        };
        let now = self.clock.now();
        self.driver
            .handle_ingress(&ingress, self.addresses, self.max_udp_payload_size, now)?;
        self.after_provider_action(now, context)
    }

    fn timeout(&mut self, context: &mut PacketContext) -> Result<Step> {
        let now = self.clock.now();
        if self.driver.next_timeout().is_some() {
            self.driver.handle_timeout(now)?;
        }
        self.after_provider_action(now, context)
    }

    fn after_provider_action(
        &mut self,
        now: std::time::Instant,
        context: &mut PacketContext,
    ) -> Result<Step> {
        let events = self.mapper.poll(&mut self.driver, context)?;
        if matches!(
            self.driver.snapshot().lifecycle,
            QuicEndpointLifecycle::Established
        ) {
            context.insert_namespaced_string("quic", "transport.validation", "validated")?;
        }
        for event in events {
            match event {
                QuicEndpointEvent::StreamReadable(stream) => {
                    self.stream.get_or_insert(stream);
                    let _ = self.request.drive(&mut self.driver, stream, context)?;
                }
                QuicEndpointEvent::StreamWritable(stream) => {
                    if context.get_namespaced_bool("quic", "application.request_complete")?
                        == Some(true)
                    {
                        self.stream.get_or_insert(stream);
                        let _ = self.response.drive(&mut self.driver, stream, context)?;
                    }
                }
                _ => {}
            }
        }
        if context.get_namespaced_bool("quic", "application.request_complete")? == Some(true) {
            if let Some(stream) = self.stream {
                if context.get_namespaced_bool("quic", "application.response_complete")?
                    != Some(true)
                {
                    let _ = self.response.drive(&mut self.driver, stream, context)?;
                }
            }
        }
        if context.get_namespaced_bool("quic", "application.response_complete")? == Some(true) {
            context.insert_namespaced_bool("quic", "application.complete", true)?;
            self.driver.close(now, 0, b"bounded exchange complete")?;
        }
        let target = match self.driver.snapshot().lifecycle {
            QuicEndpointLifecycle::Listen => LISTEN,
            lifecycle => lifecycle_state(lifecycle),
        };
        Ok(self
            .driver
            .drain_transmit_step(now, self.addresses, context)?
            .goto(target))
    }
}

fn server_datagram_transition(
    runtime: Rc<RefCell<ServerRuntime>>,
    addresses: QuicEndpointAddresses,
) -> Transition {
    Transition::on(
        PredicateMatcher::new(
            "matching bounded QUIC server UDP datagram",
            move |packet, context| {
                let (SocketAddr::V4(local), SocketAddr::V4(peer)) =
                    (addresses.local, addresses.peer)
                else {
                    return false;
                };
                extract_quic_udp_ingress(packet, local, peer, context).is_some()
            },
        ),
        move |packet, context| runtime.borrow_mut().packet(packet, context),
    )
    .targets([LISTEN, HANDSHAKING, ESTABLISHED, CLOSING, DRAINING, CLOSED])
}

fn server_active_state(
    name: &'static str,
    runtime: Rc<RefCell<ServerRuntime>>,
    addresses: QuicEndpointAddresses,
) -> FlowState {
    let timeout_runtime = Rc::clone(&runtime);
    FlowState::new(name)
        .on(server_datagram_transition(runtime, addresses))
        .on_timeout(move |context| timeout_runtime.borrow_mut().timeout(context))
        .timeout_description("drive passive provider-owned QUIC deadline")
        .timeout_targets([HANDSHAKING, ESTABLISHED, CLOSING, DRAINING, CLOSED])
}

/// Build one socket-free, bounded authenticated QUIC server flow.
pub fn quic_server_flow(config: QuicServerFlowConfig) -> Result<Flow> {
    let tls = configure_endpoint_server_tls(
        &QuicEndpointServerPolicy::default(),
        &config.identity,
        config.limits,
    )?;
    let runtime = Rc::new(RefCell::new(ServerRuntime {
        driver: QuinnProtoServerDriver::new(tls, config.addresses)?,
        mapper: QuicEndpointEventMapper::new(QuicEndpointLifecycle::Listen),
        request: QuicEndpointServerRequest::new(config.limits.max_stream_bytes),
        response: QuicEndpointServerResponse::new(config.response, config.limits.max_stream_bytes),
        stream: None,
        clock: QuicEndpointSystemClock,
        addresses: config.addresses,
        max_udp_payload_size: config.limits.max_udp_payload_size,
    }));

    let listen_runtime = Rc::clone(&runtime);
    let listen = FlowState::new(LISTEN)
        .on_entry(move |context| listen_runtime.borrow_mut().start(context))
        .entry_description("start socket-free passive QUIC endpoint")
        .entry_targets([LISTEN])
        .on(server_datagram_transition(
            Rc::clone(&runtime),
            config.addresses,
        ));
    let closed = FlowState::new(CLOSED)
        .on_entry(|_| Ok(Step::done_with("quic-server-closed")))
        .entry_description("finish bounded QUIC server flow")
        .entry_terminal()
        .on_timeout(|_| Ok(Step::done_with("quic-server-closed")))
        .timeout_description("remain terminal after close")
        .timeout_terminal();
    let flow = Flow::new("quic-server")
        .role(Role::Responder)
        .state(listen)
        .state(server_active_state(
            HANDSHAKING,
            Rc::clone(&runtime),
            config.addresses,
        ))
        .state(server_active_state(
            ESTABLISHED,
            Rc::clone(&runtime),
            config.addresses,
        ))
        .state(server_active_state(
            CLOSING,
            Rc::clone(&runtime),
            config.addresses,
        ))
        .state(server_active_state(DRAINING, runtime, config.addresses))
        .state(closed)
        .initial(LISTEN);
    flow.validate()?;
    Ok(flow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn full_client_graph_has_bounded_lifecycle() {
        let certificate = decode_hex(include_str!(
            "../../../tests/fixtures/quic/quic.example.cert.der.hex"
        ));
        let config = QuicClientFlowConfig::new(
            QuicEndpointAddresses::new(
                SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 44_300).into(),
                SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443).into(),
            ),
            QuicPeerConfig::new("quic.example", [b"crafter-flow".to_vec()]),
            QuicSyntheticIdentity::new(Vec::new(), Vec::new(), vec![certificate]),
            b"request".to_vec(),
        );
        let mut flow = quic_client_flow(config).expect("production graph builds");

        flow.validate().expect("bounded graph validates");
        assert_eq!(Flow::initial(&flow), INITIAL_SENT);
        for name in [
            INITIAL_SENT,
            HANDSHAKING,
            ESTABLISHED,
            CLOSING,
            DRAINING,
            CLOSED,
        ] {
            let state = Flow::state(&flow, name).expect("named lifecycle state exists");
            assert!(state.has_timeout(), "{name} has a timeout action");
            if name != CLOSED {
                assert!(!state.declared_timeout_targets().is_empty());
            }
        }

        let step = Flow::state_mut(&mut flow, INITIAL_SENT)
            .unwrap()
            .run_entry(&mut PacketContext::new())
            .expect("entry succeeds")
            .expect("entry emits a step");
        assert!(!step.outputs().is_empty());
        assert!(step
            .outputs()
            .iter()
            .all(|output| output.requires_regeneration()));
        assert!(step.outputs().iter().all(|output| {
            output.packet().layer::<crafter::Ipv4>().is_some()
                && output.packet().layer::<crafter::Udp>().is_some()
                && output.packet().layer::<crafter::Quic>().is_some()
        }));
    }

    #[test]
    fn full_server_graph_has_bounded_lifecycle() {
        const PRIVATE_KEY_HEX: &str = concat!(
            "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420",
            "4a1c7377037c53181de9d3ef2c3bb7364ae1f4fa48164e85b06c919b67b803dba144",
            "03420004c8634a405397699a827e0f5af382c6b53023f9b0c79a322cc96dbf366a9b943",
            "a0a4a74aed42c0321e76f7881fa1ae5d8b064cf696e6b918cfade1f4dbcbad3d0",
        );
        let certificate = decode_hex(include_str!(
            "../../../tests/fixtures/quic/quic.example.cert.der.hex"
        ));
        let config = QuicServerFlowConfig::new(
            QuicEndpointAddresses::new(
                SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443).into(),
                SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 44_300).into(),
            ),
            QuicSyntheticIdentity::new(vec![certificate], decode_hex(PRIVATE_KEY_HEX), Vec::new()),
            b"response".to_vec(),
        );
        let mut flow = quic_server_flow(config).expect("production server graph builds");

        flow.validate().expect("bounded graph validates");
        assert_eq!(Flow::initial(&flow), LISTEN);
        for name in [LISTEN, HANDSHAKING, ESTABLISHED, CLOSING, DRAINING, CLOSED] {
            assert!(Flow::state(&flow, name).is_some(), "{name} exists");
        }
        let step = Flow::state_mut(&mut flow, LISTEN)
            .unwrap()
            .run_entry(&mut PacketContext::new())
            .expect("entry succeeds")
            .expect("entry emits a step");
        assert!(step.outputs().is_empty());
        assert_eq!(step.target(), Some(LISTEN));
    }

    fn fire_packet(
        flow: &mut Flow,
        state: &str,
        packet: &crafter::Packet,
        context: &mut PacketContext,
    ) -> Step {
        let transition = Flow::state_mut(flow, state)
            .expect("flow state exists")
            .find_transition(packet, context)
            .expect("packet matches the bounded endpoint tuple");
        transition
            .fire(packet, context)
            .expect("provider accepts datagram")
    }

    fn opaque_quic_payload(packet: &crafter::Packet) -> Vec<u8> {
        packet
            .layer::<crafter::Quic>()
            .expect("typed QUIC layer")
            .payload_bytes()
            .to_vec()
    }

    fn initial_destination_connection_id(payload: &[u8]) -> Vec<u8> {
        assert_eq!(payload[0] & 0xf0, 0xc0, "QUIC v1 Initial packet");
        let length = payload[5] as usize;
        payload[6..6 + length].to_vec()
    }

    #[test]
    fn full_flow_retry_restarts_with_fresh_initial() {
        const PRIVATE_KEY_HEX: &str = concat!(
            "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420",
            "4a1c7377037c53181de9d3ef2c3bb7364ae1f4fa48164e85b06c919b67b803dba144",
            "03420004c8634a405397699a827e0f5af382c6b53023f9b0c79a322cc96dbf366a9b943",
            "a0a4a74aed42c0321e76f7881fa1ae5d8b064cf696e6b918cfade1f4dbcbad3d0",
        );
        let certificate = decode_hex(include_str!(
            "../../../tests/fixtures/quic/quic.example.cert.der.hex"
        ));
        let client_addresses = QuicEndpointAddresses::new(
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 44_300).into(),
            SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443).into(),
        );
        let server_addresses =
            QuicEndpointAddresses::new(client_addresses.peer, client_addresses.local);
        let mut client = quic_client_flow(QuicClientFlowConfig::new(
            client_addresses,
            QuicPeerConfig::new("quic.example", [b"crafter-flow".to_vec()]),
            QuicSyntheticIdentity::new(Vec::new(), Vec::new(), vec![certificate.clone()]),
            b"request".to_vec(),
        ))
        .expect("client graph builds");
        let mut server = quic_server_flow(QuicServerFlowConfig::new(
            server_addresses,
            QuicSyntheticIdentity::new(vec![certificate], decode_hex(PRIVATE_KEY_HEX), Vec::new()),
            b"response".to_vec(),
        ))
        .expect("server graph builds");
        let mut client_context = PacketContext::new();
        let mut server_context = PacketContext::new();

        let first_step = Flow::state_mut(&mut client, INITIAL_SENT)
            .unwrap()
            .run_entry(&mut client_context)
            .expect("client entry succeeds")
            .expect("client entry emits Initial");
        Flow::state_mut(&mut server, LISTEN)
            .unwrap()
            .run_entry(&mut server_context)
            .expect("server entry succeeds");
        let first_initial = first_step.outputs()[0].packet().clone();
        let first_payload = opaque_quic_payload(&first_initial);
        let original_destination_id = initial_destination_connection_id(&first_payload);

        let retry_step = fire_packet(&mut server, LISTEN, &first_initial, &mut server_context);
        assert_eq!(retry_step.target(), Some(LISTEN));
        assert_eq!(retry_step.outputs().len(), 1);
        assert_eq!(
            server_context
                .get_namespaced_u64("quic", "retry.count")
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            server_context
                .get_namespaced_string("quic", "retry.lifecycle")
                .unwrap(),
            Some("retry-sent")
        );

        let retry = retry_step.outputs()[0].packet().clone();
        let fresh_step = fire_packet(&mut client, HANDSHAKING, &retry, &mut client_context);
        assert_eq!(fresh_step.target(), Some(HANDSHAKING));
        assert!(fresh_step
            .outputs()
            .iter()
            .all(|output| output.requires_regeneration()));
        let fresh_initial = fresh_step
            .outputs()
            .iter()
            .map(|output| output.packet())
            .find(|packet| opaque_quic_payload(packet)[0] & 0xf0 == 0xc0)
            .expect("provider emits token-bearing Initial")
            .clone();
        let fresh_payload = opaque_quic_payload(&fresh_initial);
        assert_ne!(
            fresh_payload, first_payload,
            "protected Initial is regenerated"
        );
        assert_ne!(
            initial_destination_connection_id(&fresh_payload),
            original_destination_id,
            "Retry replaces the destination connection identifier"
        );
        assert_eq!(
            client_context
                .get_namespaced_u64("quic", "retry.count")
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            client_context
                .get_namespaced_string("quic", "retry.lifecycle")
                .unwrap(),
            Some("retry-received")
        );

        let accepted = fire_packet(&mut server, LISTEN, &fresh_initial, &mut server_context);
        assert_eq!(accepted.target(), Some(HANDSHAKING));
        assert_eq!(
            server_context
                .get_namespaced_u64("quic", "retry.count")
                .unwrap(),
            Some(1),
            "the server permits only one Retry"
        );
    }
}
