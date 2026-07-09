//! TCP flow templates.
//!
//! The client lifecycle is `SynSent -> Established -> FinWait1 -> FinWait2 ->
//! Closed`.
//! The server lifecycle is `Listen -> SynReceived -> Established -> CloseWait ->
//! LastAck -> Closed`.

use std::net::Ipv4Addr;

use crate::matcher::tcp_segment_for_ipv4;
use crate::{
    Flow, FlowBuilderExt, FlowError, FlowState, PacketContext, Role, Step, StepGotoExt, Transition,
};

const TCP_WINDOW: u16 = 64_240;
const TCP_MSS: u16 = 1_460;
const TCP_CLIENT_ISS: u32 = 0x1020_3040;
const TCP_CLIENT_LOCAL_PORT: u16 = 49_152;

/// Initial client state: active open has sent or will send SYN.
pub const SYN_SENT: &str = "SynSent";
/// Shared connected state after the three-way handshake completes.
pub const ESTABLISHED: &str = "Established";
/// Client active-close state after sending FIN and awaiting its ACK.
pub const FIN_WAIT_1: &str = "FinWait1";
/// Client active-close state after peer ACKs the FIN and before peer FIN.
pub const FIN_WAIT_2: &str = "FinWait2";
/// Terminal client state after graceful close completes.
pub const CLOSED: &str = "Closed";
/// Initial server state: passive open is waiting for SYN.
pub const LISTEN: &str = "Listen";
/// Server state after receiving SYN and sending SYN-ACK.
pub const SYN_RECEIVED: &str = "SynReceived";
/// Server passive-close state after receiving peer FIN.
pub const CLOSE_WAIT: &str = "CloseWait";
/// Server passive-close state after sending FIN and awaiting its ACK.
pub const LAST_ACK: &str = "LastAck";
/// Terminal server state after graceful close completes.
pub const CLOSED_SRV: &str = "ClosedSrv";

fn syn_segment(
    ctx: &PacketContext,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> crafter::Packet {
    ipv4_tcp_packet(
        local_ip,
        remote_ip,
        tcp_with_mss(
            tcp_header(local_port, remote_port)
                .seq(tcp_iss(ctx))
                .syn_segment(),
        ),
    )
}

#[cfg(test)]
mod api_check {
    use std::net::Ipv4Addr;

    use crafter::{
        Ipv4, NetworkLayer, Packet, Tcp, TcpOption, IPPROTO_TCP, TCP_FLAG_ACK, TCP_FLAG_FIN,
        TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN,
    };

    use super::{TCP_MSS, TCP_WINDOW};

    #[test]
    fn tcp_builder_and_accessor_surface_round_trips() {
        const LOCAL_PORT: u16 = 49_152;
        const REMOTE_PORT: u16 = 443;
        const SEQ: u32 = 0x1020_3040;
        const ACK: u32 = 0x5060_7080;

        assert_eq!(Tcp::new().syn_segment().flags_value(), TCP_FLAG_SYN);
        assert_eq!(
            Tcp::new().syn_ack_segment().flags_value(),
            TCP_FLAG_SYN | TCP_FLAG_ACK
        );
        assert_eq!(Tcp::new().fin_ack_segment().flags_value(), TCP_FLAG_FIN | TCP_FLAG_ACK);

        let tcp = Tcp::new()
            .sport(LOCAL_PORT)
            .dport(REMOTE_PORT)
            .seq(SEQ)
            .ack(ACK)
            .window(TCP_WINDOW)
            .syn_segment()
            .ack_segment()
            .syn()
            .fin()
            .psh()
            .rst()
            .tcp_option(TcpOption::maximum_segment_size(TCP_MSS))
            .expect("fixed TCP MSS option encodes");

        let packet = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            .protocol(IPPROTO_TCP)
            / tcp;
        let compiled = packet.compile().expect("TCP packet should compile");
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())
            .expect("TCP packet should decode");
        let tcp = decoded.layer::<Tcp>().expect("TCP layer");

        let expected_flags =
            TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_RST;
        assert_eq!(tcp.source_port_value(), LOCAL_PORT);
        assert_eq!(tcp.destination_port_value(), REMOTE_PORT);
        assert_eq!(tcp.sequence_number_value(), SEQ);
        assert_eq!(tcp.acknowledgment_number_value(), ACK);
        assert_eq!(tcp.window_value(), TCP_WINDOW);
        assert_eq!(tcp.flags_value(), expected_flags);
        assert!(tcp.has_syn());
        assert!(tcp.has_fin());
        assert!(tcp.has_flag(TCP_FLAG_ACK));
        assert!(tcp.has_flag(TCP_FLAG_PSH));
        assert!(tcp.has_flag(TCP_FLAG_RST));
        assert_eq!(
            tcp.parsed_options().expect("TCP options should decode"),
            [TcpOption::maximum_segment_size(TCP_MSS)]
        );
    }
}

fn syn_ack_segment(
    ctx: &PacketContext,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> crafter::Packet {
    ipv4_tcp_packet(
        local_ip,
        remote_ip,
        tcp_with_mss(
            tcp_header(local_port, remote_port)
                .seq(tcp_iss(ctx))
                .ack(tcp_rcv_nxt(ctx))
                .syn_ack_segment(),
        ),
    )
}

fn ack_segment(
    ctx: &PacketContext,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> crafter::Packet {
    ipv4_tcp_packet(
        local_ip,
        remote_ip,
        tcp_header(local_port, remote_port)
            .seq(tcp_snd_nxt(ctx))
            .ack(tcp_rcv_nxt(ctx))
            .ack_segment(),
    )
}

fn data_segment(
    ctx: &PacketContext,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    payload: impl AsRef<[u8]>,
) -> crafter::Packet {
    ipv4_tcp_packet(
        local_ip,
        remote_ip,
        tcp_header(local_port, remote_port)
            .seq(tcp_snd_nxt(ctx))
            .ack(tcp_rcv_nxt(ctx))
            .ack_segment()
            .psh(),
    ) / crafter::Raw::from_bytes(payload)
}

fn fin_segment(
    ctx: &PacketContext,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> crafter::Packet {
    ipv4_tcp_packet(
        local_ip,
        remote_ip,
        tcp_header(local_port, remote_port)
            .seq(tcp_snd_nxt(ctx))
            .ack(tcp_rcv_nxt(ctx))
            .fin_ack_segment(),
    )
}

/// Build the TCP client flow scaffold.
///
/// The client starts with an active-open SYN. Later steps add the reply
/// transitions and payload handling for the rest of the lifecycle.
pub fn client_flow(
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    _payload: Option<Vec<u8>>,
) -> Flow {
    Flow::new("tcp-client")
        .role(Role::Initiator)
        .state(client_syn_sent_state(local_ip, remote_ip, remote_port))
        .state(stub_state(ESTABLISHED, FIN_WAIT_1))
        .state(stub_state(FIN_WAIT_1, FIN_WAIT_2))
        .state(stub_state(FIN_WAIT_2, CLOSED))
        .state(terminal_state(CLOSED))
        .initial(SYN_SENT)
}

/// Build the TCP server flow scaffold.
///
/// The address and port arguments are placeholders for the real TCP actions
/// added by later steps. This scaffold only declares the lifecycle.
pub fn server_flow(_local_ip: Ipv4Addr, _listen_port: u16) -> Flow {
    Flow::new("tcp-server")
        .role(Role::Responder)
        .state(stub_state(LISTEN, SYN_RECEIVED))
        .state(stub_state(SYN_RECEIVED, ESTABLISHED))
        .state(stub_state(ESTABLISHED, CLOSE_WAIT))
        .state(stub_state(CLOSE_WAIT, LAST_ACK))
        .state(stub_state(LAST_ACK, CLOSED_SRV))
        .state(terminal_state(CLOSED_SRV))
        .initial(LISTEN)
}

fn client_syn_sent_state(local_ip: Ipv4Addr, remote_ip: Ipv4Addr, remote_port: u16) -> FlowState {
    FlowState::new(SYN_SENT)
        .on_entry(move |ctx| {
            let iss = TCP_CLIENT_ISS;

            ctx.set_tcp_iss(iss);
            ctx.set_tcp_snd_nxt(iss.wrapping_add(1));
            ctx.set_tcp_local_port(TCP_CLIENT_LOCAL_PORT);
            ctx.set_tcp_remote_port(remote_port);
            ctx.set_tcp_remote_ipv4(remote_ip);

            let syn = syn_segment(
                ctx,
                local_ip,
                TCP_CLIENT_LOCAL_PORT,
                remote_ip,
                remote_port,
            );

            Ok(Step::send(syn))
        })
        .entry_description("TCP SYN")
        .on(client_syn_ack_transition(local_ip, remote_ip, remote_port))
}

fn client_syn_ack_transition(
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> Transition {
    Transition::on(
        tcp_segment_for_ipv4(
            local_ip,
            TCP_CLIENT_LOCAL_PORT,
            remote_ip,
            remote_port,
            crafter::TCP_FLAG_SYN | crafter::TCP_FLAG_ACK,
        )
        .ack_matches_tcp_snd_nxt(),
        move |packet, ctx| {
            let tcp = packet.layer::<crafter::Tcp>().ok_or_else(|| {
                FlowError::Capture("matched TCP SYN-ACK packet has no TCP layer".to_string())
            })?;

            ctx.set_tcp_rcv_nxt(tcp.sequence_number_value().wrapping_add(1));
            if let Some(peer_mss) = tcp
                .parsed_options()?
                .iter()
                .find_map(crafter::TcpOption::maximum_segment_size_value)
            {
                ctx.set_tcp_peer_mss(peer_mss);
            }
            ctx.set_tcp_peer_window(tcp.window_value());

            let ack = ack_segment(
                ctx,
                local_ip,
                TCP_CLIENT_LOCAL_PORT,
                remote_ip,
                remote_port,
            );

            Ok(Step::send(ack).goto(ESTABLISHED))
        },
    )
    .targets([ESTABLISHED])
}

fn stub_state(name: &'static str, next: &'static str) -> FlowState {
    FlowState::new(name)
        .on_entry(move |_ctx| Ok(Step::goto(next)))
        .entry_description("TCP scaffold placeholder")
        .entry_targets([next])
}

fn terminal_state(name: &'static str) -> FlowState {
    FlowState::new(name)
        .on_entry(|_ctx| Ok(Step::done()))
        .entry_terminal()
}

fn ipv4_tcp_packet(local_ip: Ipv4Addr, remote_ip: Ipv4Addr, tcp: crafter::Tcp) -> crafter::Packet {
    crafter::Ipv4::new()
        .src(local_ip)
        .dst(remote_ip)
        .protocol(crafter::IPPROTO_TCP)
        / tcp
}

fn tcp_header(local_port: u16, remote_port: u16) -> crafter::Tcp {
    crafter::Tcp::new()
        .sport(local_port)
        .dport(remote_port)
        .window(TCP_WINDOW)
}

fn tcp_with_mss(tcp: crafter::Tcp) -> crafter::Tcp {
    tcp.tcp_option(crafter::TcpOption::maximum_segment_size(TCP_MSS))
        .expect("fixed TCP MSS option encodes")
}

fn tcp_iss(ctx: &PacketContext) -> u32 {
    ctx.get_tcp_iss()
        .expect("TCP segment build requires tcp_iss in PacketContext")
}

fn tcp_snd_nxt(ctx: &PacketContext) -> u32 {
    ctx.get_tcp_snd_nxt()
        .expect("TCP segment build requires tcp_snd_nxt in PacketContext")
}

fn tcp_rcv_nxt(ctx: &PacketContext) -> u32 {
    ctx.get_tcp_rcv_nxt()
        .expect("TCP segment build requires tcp_rcv_nxt in PacketContext")
}

#[cfg(test)]
mod tests {
    use super::{
        ack_segment, client_flow, data_segment, fin_segment, server_flow, syn_ack_segment,
        syn_segment, CLOSED, CLOSED_SRV, CLOSE_WAIT, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, LAST_ACK,
        LISTEN, SYN_RECEIVED, SYN_SENT, TCP_CLIENT_ISS, TCP_CLIENT_LOCAL_PORT, TCP_MSS, TCP_WINDOW,
    };
    use std::net::Ipv4Addr;

    use crafter::{
        NetworkLayer, Packet, TcpOption, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_SYN,
    };

    use crate::{docaddr, PacketContext, Role};

    const ISS: u32 = 0x2122_2324;
    const SND_NXT: u32 = 0x3132_3334;
    const RCV_NXT: u32 = 0x4142_4344;
    const LOCAL_PORT: u16 = 49_152;
    const REMOTE_PORT: u16 = 443;

    #[test]
    fn tcp_client_flow_exposes_initial_and_named_states() {
        let flow = client_flow(
            docaddr::CLIENT_IPV4,
            docaddr::SERVER_IPV4,
            80,
            Some(b"hello".to_vec()),
        );

        assert_eq!(flow.role(), Role::Initiator);
        assert_eq!(flow.initial(), SYN_SENT);
        assert_named_states(
            &flow,
            &[SYN_SENT, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSED],
        );
        flow.validate().expect("TCP client scaffold is valid");
    }

    #[test]
    fn tcp_server_flow_exposes_initial_and_named_states() {
        let flow = server_flow(docaddr::SERVER_IPV4, 80);

        assert_eq!(flow.role(), Role::Responder);
        assert_eq!(flow.initial(), LISTEN);
        assert_named_states(
            &flow,
            &[
                LISTEN,
                SYN_RECEIVED,
                ESTABLISHED,
                CLOSE_WAIT,
                LAST_ACK,
                CLOSED_SRV,
            ],
        );
        flow.validate().expect("TCP server scaffold is valid");
    }

    #[test]
    fn tcp_client_syn_sent_entry_sends_syn_and_records_initial_state() {
        let mut flow = client_flow(local_ipv4(), remote_ipv4(), REMOTE_PORT, None);
        let mut context = PacketContext::new();

        let step = flow
            .state_mut(SYN_SENT)
            .expect("SynSent state exists")
            .run_entry(&mut context)
            .expect("SynSent entry should run")
            .expect("SynSent entry should return a step");
        let packet = step.outgoing().expect("SynSent entry sends SYN");
        let ipv4 = packet.layer::<crafter::Ipv4>().expect("IPv4 layer");
        let tcp = packet.layer::<crafter::Tcp>().expect("TCP layer");

        assert_eq!(step.target(), None);
        assert!(step.expects_reply());
        assert_eq!(ipv4.source(), local_ipv4());
        assert_eq!(ipv4.destination(), remote_ipv4());
        assert_eq!(tcp.source_port_value(), TCP_CLIENT_LOCAL_PORT);
        assert_eq!(tcp.destination_port_value(), REMOTE_PORT);
        assert_eq!(tcp.sequence_number_value(), TCP_CLIENT_ISS);
        assert_eq!(tcp.flags_value(), TCP_FLAG_SYN);
        assert_has_mss(tcp);
        assert_eq!(context.get_tcp_iss(), Some(TCP_CLIENT_ISS));
        assert_eq!(
            context.get_tcp_snd_nxt(),
            Some(TCP_CLIENT_ISS.wrapping_add(1))
        );
        assert_eq!(context.get_tcp_local_port(), Some(TCP_CLIENT_LOCAL_PORT));
        assert_eq!(context.get_tcp_remote_port(), Some(REMOTE_PORT));
        assert_eq!(context.get_tcp_remote_ipv4(), Some(remote_ipv4()));
    }

    #[test]
    fn tcp_client_syn_ack_transition_records_peer_and_sends_handshake_ack() {
        const PEER_ISS: u32 = 0x5152_5354;
        const PEER_WINDOW: u16 = 32_768;
        const PEER_MSS: u16 = 1_200;

        let mut flow = client_flow(local_ipv4(), remote_ipv4(), REMOTE_PORT, None);
        let mut context = PacketContext::new();

        flow.state_mut(SYN_SENT)
            .expect("SynSent state exists")
            .run_entry(&mut context)
            .expect("SynSent entry should run")
            .expect("SynSent entry should return a step");
        let client_snd_nxt = context
            .get_tcp_snd_nxt()
            .expect("SynSent entry records snd_nxt");
        let syn_ack = syn_ack_from_peer(PEER_ISS, client_snd_nxt, PEER_WINDOW, PEER_MSS);
        let wrong_ack = syn_ack_from_peer(
            PEER_ISS,
            client_snd_nxt.wrapping_add(1),
            PEER_WINDOW,
            PEER_MSS,
        );

        {
            let syn_sent = flow.state(SYN_SENT).expect("SynSent state exists");
            let transition = &syn_sent.transitions()[0];
            assert!(transition.matches(&syn_ack, &context));
            assert!(!transition.matches(&wrong_ack, &context));
        }

        let step = flow
            .state_mut(SYN_SENT)
            .expect("SynSent state exists")
            .find_transition(&syn_ack, &context)
            .expect("SYN-ACK transition matches")
            .fire(&syn_ack, &mut context)
            .expect("SYN-ACK transition should fire");
        let ack = step.outgoing().expect("SYN-ACK transition sends ACK");
        let tcp = ack.layer::<crafter::Tcp>().expect("TCP layer");

        assert_eq!(context.get_tcp_rcv_nxt(), Some(PEER_ISS.wrapping_add(1)));
        assert_eq!(context.get_tcp_peer_mss(), Some(PEER_MSS));
        assert_eq!(context.get_tcp_peer_window(), Some(PEER_WINDOW));
        assert_eq!(tcp.source_port_value(), TCP_CLIENT_LOCAL_PORT);
        assert_eq!(tcp.destination_port_value(), REMOTE_PORT);
        assert_eq!(tcp.sequence_number_value(), client_snd_nxt);
        assert_eq!(tcp.acknowledgment_number_value(), PEER_ISS.wrapping_add(1));
        assert_eq!(tcp.flags_value(), TCP_FLAG_ACK);
        assert_eq!(step.target(), Some(ESTABLISHED));
    }

    fn assert_named_states(flow: &crate::Flow, expected: &[&str]) {
        for name in expected {
            assert!(flow.state(name).is_some(), "missing {name} state");
        }
    }

    #[test]
    fn tcp_syn_segment_uses_context_iss_and_mss_option() {
        let context = tcp_context();
        let packet = syn_segment(
            &context,
            local_ipv4(),
            LOCAL_PORT,
            remote_ipv4(),
            REMOTE_PORT,
        );
        let tcp = packet.layer::<crafter::Tcp>().expect("TCP layer");

        assert_eq!(tcp.source_port_value(), LOCAL_PORT);
        assert_eq!(tcp.destination_port_value(), REMOTE_PORT);
        assert_eq!(tcp.sequence_number_value(), ISS);
        assert_eq!(tcp.acknowledgment_number_value(), 0);
        assert_eq!(tcp.flags_value(), TCP_FLAG_SYN);
        assert_eq!(tcp.window_value(), TCP_WINDOW);
        assert_has_mss(tcp);
    }

    #[test]
    fn tcp_syn_ack_segment_uses_context_iss_rcv_nxt_and_mss_option() {
        let context = tcp_context();
        let packet = syn_ack_segment(
            &context,
            local_ipv4(),
            LOCAL_PORT,
            remote_ipv4(),
            REMOTE_PORT,
        );
        let tcp = packet.layer::<crafter::Tcp>().expect("TCP layer");

        assert_eq!(tcp.sequence_number_value(), ISS);
        assert_eq!(tcp.acknowledgment_number_value(), RCV_NXT);
        assert_eq!(tcp.flags_value(), TCP_FLAG_SYN | TCP_FLAG_ACK);
        assert_eq!(tcp.window_value(), TCP_WINDOW);
        assert_has_mss(tcp);
    }

    #[test]
    fn tcp_ack_segment_uses_context_snd_nxt_and_rcv_nxt() {
        let context = tcp_context();
        let packet = ack_segment(
            &context,
            local_ipv4(),
            LOCAL_PORT,
            remote_ipv4(),
            REMOTE_PORT,
        );
        let tcp = packet.layer::<crafter::Tcp>().expect("TCP layer");

        assert_eq!(tcp.sequence_number_value(), SND_NXT);
        assert_eq!(tcp.acknowledgment_number_value(), RCV_NXT);
        assert_eq!(tcp.flags_value(), TCP_FLAG_ACK);
        assert_eq!(tcp.window_value(), TCP_WINDOW);
        assert!(packet.layer::<crafter::Raw>().is_none());
    }

    #[test]
    fn tcp_data_segment_uses_context_numbers_and_carries_payload() {
        let context = tcp_context();
        let payload = b"hello over tcp";
        let packet = data_segment(
            &context,
            local_ipv4(),
            LOCAL_PORT,
            remote_ipv4(),
            REMOTE_PORT,
            payload,
        );
        let decoded = compiled_ipv4(packet);
        let ipv4 = decoded.layer::<crafter::Ipv4>().expect("IPv4 layer");
        let tcp = decoded.layer::<crafter::Tcp>().expect("TCP layer");
        let raw = decoded.layer::<crafter::Raw>().expect("Raw payload");

        assert_eq!(tcp.sequence_number_value(), SND_NXT);
        assert_eq!(tcp.acknowledgment_number_value(), RCV_NXT);
        assert_eq!(tcp.flags_value(), TCP_FLAG_PSH | TCP_FLAG_ACK);
        assert_eq!(raw.as_bytes(), payload);
        assert_eq!(
            ipv4.total_length_value(),
            Some((ipv4.header_len() + tcp.header_len() + payload.len()) as u16)
        );
    }

    #[test]
    fn tcp_fin_segment_uses_context_snd_nxt_and_rcv_nxt() {
        let context = tcp_context();
        let packet = fin_segment(
            &context,
            local_ipv4(),
            LOCAL_PORT,
            remote_ipv4(),
            REMOTE_PORT,
        );
        let tcp = packet.layer::<crafter::Tcp>().expect("TCP layer");

        assert_eq!(tcp.sequence_number_value(), SND_NXT);
        assert_eq!(tcp.acknowledgment_number_value(), RCV_NXT);
        assert_eq!(tcp.flags_value(), TCP_FLAG_FIN | TCP_FLAG_ACK);
        assert_eq!(tcp.window_value(), TCP_WINDOW);
    }

    fn tcp_context() -> PacketContext {
        let mut context = PacketContext::new();
        context.set_tcp_iss(ISS);
        context.set_tcp_snd_nxt(SND_NXT);
        context.set_tcp_rcv_nxt(RCV_NXT);
        context
    }

    fn local_ipv4() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn remote_ipv4() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    fn compiled_ipv4(packet: crafter::Packet) -> Packet {
        let compiled = packet.compile().expect("TCP packet should compile");

        Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())
            .expect("TCP packet should decode")
    }

    fn syn_ack_from_peer(peer_seq: u32, ack: u32, window: u16, mss: u16) -> Packet {
        let tcp = crafter::Tcp::new()
            .sport(REMOTE_PORT)
            .dport(TCP_CLIENT_LOCAL_PORT)
            .seq(peer_seq)
            .ack(ack)
            .window(window)
            .syn_ack_segment()
            .tcp_option(TcpOption::maximum_segment_size(mss))
            .expect("fixed peer TCP MSS option encodes");

        compiled_ipv4(
            crafter::Ipv4::new()
                .src(remote_ipv4())
                .dst(local_ipv4())
                .protocol(crafter::IPPROTO_TCP)
                / tcp,
        )
    }

    fn assert_has_mss(tcp: &crafter::Tcp) {
        let options = tcp.parsed_options().expect("TCP options should decode");

        assert_eq!(options, [TcpOption::maximum_segment_size(TCP_MSS)]);
    }
}
