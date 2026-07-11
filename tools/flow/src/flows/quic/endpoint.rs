//! Bounded authenticated QUIC endpoint flow graphs.

use std::{cell::RefCell, net::SocketAddr, rc::Rc};

use crate::{
    quic_endpoint::{
        configure_endpoint_client_tls, QuicEndpointAddresses, QuicEndpointClientRequest,
        QuicEndpointClock, QuicEndpointDriver, QuicEndpointEventMapper, QuicEndpointLifecycle,
        QuicEndpointSystemClock, QuicPeerConfig, QuicSyntheticIdentity, QuicTransportLimits,
        QuinnProtoClientDriver,
    },
    quic_wire::extract_quic_udp_ingress,
    Flow, FlowBuilderExt, FlowState, PacketContext, PredicateMatcher, Result, Role, Step,
    StepGotoExt, Transition,
};

const INITIAL_SENT: &str = "InitialSent";
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
}
