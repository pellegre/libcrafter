//! TCP flow templates.
//!
//! The client lifecycle is `SynSent -> Established -> FinWait1 -> FinWait2 ->
//! Closed`.
//! The server lifecycle is `Listen -> SynReceived -> Established -> CloseWait ->
//! LastAck -> Closed`.

use std::net::Ipv4Addr;

use crate::matcher::{predicate, tcp_segment_for_ipv4, MatcherExt};
use crate::{
    Flow, FlowBuilderExt, FlowError, FlowState, Matcher, PacketContext, Role, Step, StepGotoExt,
    Transition,
};

const TCP_WINDOW: u16 = 64_240;
const TCP_MSS: u16 = 1_460;
const TCP_CLIENT_ISS: u32 = 0x1020_3040;
const TCP_CLIENT_LOCAL_PORT: u16 = 49_152;
const TCP_SERVER_ISS: u32 = 0x5060_7080;

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
pub const CLOSED_SRV: &str = CLOSED;

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
    payload: Option<Vec<u8>>,
) -> Flow {
    let flow = Flow::new("tcp-client")
        .role(Role::Initiator)
        .state(client_syn_sent_state(local_ip, remote_ip, remote_port))
        .state(client_established_state(
            local_ip,
            remote_ip,
            remote_port,
            payload,
        ))
        .state(client_fin_wait_1_state(local_ip, remote_ip, remote_port))
        .state(client_fin_wait_2_state(local_ip, remote_ip, remote_port))
        .state(terminal_state(CLOSED))
        .initial(SYN_SENT);

    flow.validate()
        .expect("TCP client flow shape should validate");
    flow
}

/// Build the TCP server flow.
///
/// The server starts in passive-open Listen and answers the first matching SYN.
/// When `response` is set, received client data is answered with that payload.
pub fn server_flow(local_ip: Ipv4Addr, listen_port: u16, response: Option<Vec<u8>>) -> Flow {
    let flow = Flow::new("tcp-server")
        .role(Role::Responder)
        .state(server_listen_state(local_ip, listen_port))
        .state(server_syn_received_state(local_ip, listen_port))
        .state(server_established_state(local_ip, listen_port, response))
        .state(server_close_wait_state(local_ip, listen_port))
        .state(server_last_ack_state(local_ip, listen_port))
        .state(terminal_state(CLOSED))
        .initial(LISTEN);

    flow.validate()
        .expect("TCP server flow shape should validate");
    flow
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
        .on(client_rst_transition(local_ip, remote_ip, remote_port))
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

fn client_established_state(
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    payload: Option<Vec<u8>>,
) -> FlowState {
    FlowState::new(ESTABLISHED)
        .on_entry(move |ctx| {
            let Some(payload) = payload.as_deref() else {
                return Ok(Step::goto(FIN_WAIT_1));
            };

            let data = data_segment(
                ctx,
                local_ip,
                TCP_CLIENT_LOCAL_PORT,
                remote_ip,
                remote_port,
                payload,
            );
            let snd_nxt = tcp_snd_nxt(ctx).wrapping_add(payload.len() as u32);
            ctx.set_tcp_snd_nxt(snd_nxt);

            Ok(Step::send(data))
        })
        .entry_description("TCP PSH-ACK data")
        .entry_targets([FIN_WAIT_1])
        .on(client_data_transition(local_ip, remote_ip, remote_port))
        .on(client_rst_transition(local_ip, remote_ip, remote_port))
}

fn client_data_transition(
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> Transition {
    let matcher = tcp_segment_for_ipv4(
        local_ip,
        TCP_CLIENT_LOCAL_PORT,
        remote_ip,
        remote_port,
        crafter::TCP_FLAG_ACK,
    )
    .ack_matches_tcp_snd_nxt()
    .and(predicate(
        "tcp data seq == tcp_rcv_nxt and payload length > 0",
        |packet, ctx| {
            let Some(tcp) = packet.layer::<crafter::Tcp>() else {
                return false;
            };
            let Some(raw) = packet.layer::<crafter::Raw>() else {
                return false;
            };

            !raw.as_bytes().is_empty()
                && ctx.get_tcp_rcv_nxt() == Some(tcp.sequence_number_value())
        },
    ));

    Transition::on(matcher, move |packet, ctx| {
        let raw = packet.layer::<crafter::Raw>().ok_or_else(|| {
            FlowError::Capture("matched TCP data packet has no Raw payload".to_string())
        })?;
        let payload = raw.as_bytes();
        let rcv_nxt = tcp_rcv_nxt(ctx).wrapping_add(payload.len() as u32);

        ctx.append_tcp_payload(payload);
        ctx.set_tcp_rcv_nxt(rcv_nxt);

        let ack = ack_segment(
            ctx,
            local_ip,
            TCP_CLIENT_LOCAL_PORT,
            remote_ip,
            remote_port,
        );

        Ok(Step::send(ack).goto(FIN_WAIT_1))
    })
    .targets([FIN_WAIT_1])
}

fn client_fin_wait_1_state(
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> FlowState {
    FlowState::new(FIN_WAIT_1)
        .on_entry(move |ctx| {
            let fin = fin_segment(
                ctx,
                local_ip,
                TCP_CLIENT_LOCAL_PORT,
                remote_ip,
                remote_port,
            );
            let snd_nxt = tcp_snd_nxt(ctx).wrapping_add(1);
            ctx.set_tcp_snd_nxt(snd_nxt);

            Ok(Step::send(fin))
        })
        .entry_description("TCP FIN-ACK active close")
        .on(client_fin_wait_1_fin_transition(
            local_ip,
            remote_ip,
            remote_port,
        ))
        .on(client_fin_wait_1_ack_transition(
            local_ip,
            remote_ip,
            remote_port,
        ))
        .on(client_rst_transition(local_ip, remote_ip, remote_port))
}

fn client_fin_wait_1_ack_transition(
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> Transition {
    let matcher = tcp_segment_for_ipv4(
        local_ip,
        TCP_CLIENT_LOCAL_PORT,
        remote_ip,
        remote_port,
        crafter::TCP_FLAG_ACK,
    )
    .ack_matches_tcp_snd_nxt()
    .and(predicate("tcp ACK segment has no FIN or RST", |packet, _ctx| {
        packet.layer::<crafter::Tcp>().is_some_and(|tcp| {
            !tcp.has_fin() && !tcp.has_flag(crafter::TCP_FLAG_RST)
        })
    }));

    Transition::on(matcher, |_packet, _ctx| Ok(Step::goto(FIN_WAIT_2))).targets([FIN_WAIT_2])
}

fn client_fin_wait_1_fin_transition(
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> Transition {
    Transition::on(
        peer_fin_matcher(local_ip, remote_ip, remote_port),
        move |packet, ctx| {
            acknowledge_peer_fin(packet, ctx);
            let ack = ack_segment(
                ctx,
                local_ip,
                TCP_CLIENT_LOCAL_PORT,
                remote_ip,
                remote_port,
            );

            Ok(Step::send(ack).goto(CLOSED))
        },
    )
    .targets([CLOSED])
}

fn client_fin_wait_2_state(
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> FlowState {
    FlowState::new(FIN_WAIT_2).on(client_fin_wait_2_fin_transition(
        local_ip,
        remote_ip,
        remote_port,
    ))
    .on(client_rst_transition(local_ip, remote_ip, remote_port))
}

fn client_rst_transition(
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
            crafter::TCP_FLAG_RST,
        )
        .ack_matches_tcp_snd_nxt(),
        |_packet, _ctx| Ok(Step::goto(CLOSED)),
    )
    .targets([CLOSED])
}

fn client_fin_wait_2_fin_transition(
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> Transition {
    Transition::on(
        peer_fin_matcher(local_ip, remote_ip, remote_port),
        move |packet, ctx| {
            acknowledge_peer_fin(packet, ctx);
            let ack = ack_segment(
                ctx,
                local_ip,
                TCP_CLIENT_LOCAL_PORT,
                remote_ip,
                remote_port,
            );

            Ok(Step::send(ack).goto(CLOSED))
        },
    )
    .targets([CLOSED])
}

fn peer_fin_matcher(
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> impl crate::Matcher {
    tcp_segment_for_ipv4(
        local_ip,
        TCP_CLIENT_LOCAL_PORT,
        remote_ip,
        remote_port,
        crafter::TCP_FLAG_FIN | crafter::TCP_FLAG_ACK,
    )
    .ack_matches_tcp_snd_nxt()
    .and(predicate("tcp FIN seq == tcp_rcv_nxt", |packet, ctx| {
        packet.layer::<crafter::Tcp>().is_some_and(|tcp| {
            ctx.get_tcp_rcv_nxt() == Some(tcp.sequence_number_value())
        })
    }))
}

fn acknowledge_peer_fin(packet: &crafter::Packet, ctx: &mut PacketContext) {
    let tcp = packet
        .layer::<crafter::Tcp>()
        .expect("matched TCP FIN packet has no TCP layer");
    ctx.set_tcp_rcv_nxt(tcp.sequence_number_value().wrapping_add(1));
}

fn server_listen_state(local_ip: Ipv4Addr, listen_port: u16) -> FlowState {
    FlowState::new(LISTEN).on(server_syn_transition(local_ip, listen_port))
}

fn server_syn_received_state(local_ip: Ipv4Addr, listen_port: u16) -> FlowState {
    FlowState::new(SYN_RECEIVED).on(server_final_ack_transition(local_ip, listen_port))
}

fn server_established_state(
    local_ip: Ipv4Addr,
    listen_port: u16,
    response: Option<Vec<u8>>,
) -> FlowState {
    FlowState::new(ESTABLISHED)
        .on(server_data_transition(local_ip, listen_port, response))
        .on(server_fin_transition(local_ip, listen_port))
}

fn server_syn_transition(local_ip: Ipv4Addr, listen_port: u16) -> Transition {
    let matcher = predicate("tcp SYN to listen port", move |packet, _ctx| {
        let Some(ipv4) = packet.layer::<crafter::Ipv4>() else {
            return false;
        };
        if ipv4.destination() != local_ip {
            return false;
        }

        packet.layer::<crafter::Tcp>().is_some_and(|tcp| {
            tcp.destination_port_value() == listen_port
                && tcp.flags_value() == crafter::TCP_FLAG_SYN
        })
    });

    Transition::on(matcher, move |packet, ctx| {
        let ipv4 = packet.layer::<crafter::Ipv4>().ok_or_else(|| {
            FlowError::Capture("matched TCP SYN packet has no IPv4 layer".to_string())
        })?;
        let tcp = packet.layer::<crafter::Tcp>().ok_or_else(|| {
            FlowError::Capture("matched TCP SYN packet has no TCP layer".to_string())
        })?;
        let remote_ip = ipv4.source();
        let remote_port = tcp.source_port_value();
        let iss = TCP_SERVER_ISS;

        ctx.set_tcp_local_port(listen_port);
        ctx.set_tcp_remote_port(remote_port);
        ctx.set_tcp_remote_ipv4(remote_ip);
        ctx.set_tcp_rcv_nxt(tcp.sequence_number_value().wrapping_add(1));
        if let Some(peer_mss) = tcp
            .parsed_options()?
            .iter()
            .find_map(crafter::TcpOption::maximum_segment_size_value)
        {
            ctx.set_tcp_peer_mss(peer_mss);
        }
        ctx.set_tcp_peer_window(tcp.window_value());
        ctx.set_tcp_iss(iss);
        ctx.set_tcp_snd_nxt(iss.wrapping_add(1));

        let syn_ack = syn_ack_segment(ctx, local_ip, listen_port, remote_ip, remote_port);

        Ok(Step::send(syn_ack).goto(SYN_RECEIVED))
    })
    .targets([SYN_RECEIVED])
}

fn server_final_ack_transition(local_ip: Ipv4Addr, listen_port: u16) -> Transition {
    Transition::on(server_final_ack_matcher(local_ip, listen_port), |_packet, _ctx| {
        Ok(Step::goto(ESTABLISHED))
    })
    .targets([ESTABLISHED])
}

fn server_final_ack_matcher(local_ip: Ipv4Addr, listen_port: u16) -> impl crate::Matcher {
    predicate(
        "tcp final ACK for stored four-tuple and seq == tcp_rcv_nxt",
        move |packet, ctx| {
            let Some(remote_ip) = ctx.get_tcp_remote_ipv4() else {
                return false;
            };
            let Some(remote_port) = ctx.get_tcp_remote_port() else {
                return false;
            };

            let matcher = tcp_segment_for_ipv4(
                local_ip,
                listen_port,
                remote_ip,
                remote_port,
                crafter::TCP_FLAG_ACK,
            )
            .ack_matches_tcp_snd_nxt();
            if !matcher.matches(packet, ctx) {
                return false;
            }

            packet.layer::<crafter::Tcp>().is_some_and(|tcp| {
                ctx.get_tcp_rcv_nxt() == Some(tcp.sequence_number_value())
            })
        },
    )
}

fn server_data_transition(
    local_ip: Ipv4Addr,
    listen_port: u16,
    response: Option<Vec<u8>>,
) -> Transition {
    Transition::on(server_data_matcher(local_ip, listen_port), move |packet, ctx| {
        let raw = packet.layer::<crafter::Raw>().ok_or_else(|| {
            FlowError::Capture("matched TCP server data packet has no Raw payload".to_string())
        })?;
        let payload = raw.as_bytes();
        let rcv_nxt = tcp_rcv_nxt(ctx).wrapping_add(payload.len() as u32);

        ctx.append_tcp_payload(payload);
        ctx.set_tcp_rcv_nxt(rcv_nxt);

        let remote_ip = ctx.get_tcp_remote_ipv4().ok_or_else(|| {
            FlowError::Capture("matched TCP server data packet has no remote IPv4".to_string())
        })?;
        let remote_port = ctx.get_tcp_remote_port().ok_or_else(|| {
            FlowError::Capture("matched TCP server data packet has no remote port".to_string())
        })?;
        if let Some(response) = response.as_deref() {
            let data = data_segment(ctx, local_ip, listen_port, remote_ip, remote_port, response);
            let snd_nxt = tcp_snd_nxt(ctx).wrapping_add(response.len() as u32);
            ctx.set_tcp_snd_nxt(snd_nxt);

            return Ok(Step::send(data));
        }

        let ack = ack_segment(ctx, local_ip, listen_port, remote_ip, remote_port);

        Ok(Step::send(ack))
    })
}

fn server_data_matcher(local_ip: Ipv4Addr, listen_port: u16) -> impl crate::Matcher {
    predicate(
        "tcp server data seq == tcp_rcv_nxt and payload length > 0",
        move |packet, ctx| {
            let Some(remote_ip) = ctx.get_tcp_remote_ipv4() else {
                return false;
            };
            let Some(remote_port) = ctx.get_tcp_remote_port() else {
                return false;
            };

            let matcher = tcp_segment_for_ipv4(
                local_ip,
                listen_port,
                remote_ip,
                remote_port,
                crafter::TCP_FLAG_ACK,
            )
            .ack_matches_tcp_snd_nxt();
            if !matcher.matches(packet, ctx) {
                return false;
            }

            let Some(tcp) = packet.layer::<crafter::Tcp>() else {
                return false;
            };
            let Some(raw) = packet.layer::<crafter::Raw>() else {
                return false;
            };

            !tcp.has_fin()
                && !raw.as_bytes().is_empty()
                && ctx.get_tcp_rcv_nxt() == Some(tcp.sequence_number_value())
        },
    )
}

fn server_fin_transition(local_ip: Ipv4Addr, listen_port: u16) -> Transition {
    Transition::on(server_fin_matcher(local_ip, listen_port), move |packet, ctx| {
        acknowledge_server_peer_fin(packet, ctx);

        let remote_ip = ctx.get_tcp_remote_ipv4().ok_or_else(|| {
            FlowError::Capture("matched TCP server FIN packet has no remote IPv4".to_string())
        })?;
        let remote_port = ctx.get_tcp_remote_port().ok_or_else(|| {
            FlowError::Capture("matched TCP server FIN packet has no remote port".to_string())
        })?;
        let ack = ack_segment(ctx, local_ip, listen_port, remote_ip, remote_port);

        Ok(Step::send(ack).goto(CLOSE_WAIT))
    })
    .targets([CLOSE_WAIT])
}

fn server_fin_matcher(local_ip: Ipv4Addr, listen_port: u16) -> impl crate::Matcher {
    predicate(
        "tcp server FIN seq == tcp_rcv_nxt",
        move |packet, ctx| {
            let Some(remote_ip) = ctx.get_tcp_remote_ipv4() else {
                return false;
            };
            let Some(remote_port) = ctx.get_tcp_remote_port() else {
                return false;
            };

            let matcher = tcp_segment_for_ipv4(
                local_ip,
                listen_port,
                remote_ip,
                remote_port,
                crafter::TCP_FLAG_FIN | crafter::TCP_FLAG_ACK,
            )
            .ack_matches_tcp_snd_nxt();
            if !matcher.matches(packet, ctx) {
                return false;
            }

            packet.layer::<crafter::Tcp>().is_some_and(|tcp| {
                ctx.get_tcp_rcv_nxt() == Some(tcp.sequence_number_value())
            })
        },
    )
}

fn acknowledge_server_peer_fin(packet: &crafter::Packet, ctx: &mut PacketContext) {
    let tcp = packet
        .layer::<crafter::Tcp>()
        .expect("matched TCP server FIN packet has no TCP layer");
    let payload_len = packet
        .layer::<crafter::Raw>()
        .map(|raw| {
            let payload = raw.as_bytes();
            if !payload.is_empty() {
                ctx.append_tcp_payload(payload);
            }
            payload.len() as u32
        })
        .unwrap_or(0);
    ctx.set_tcp_rcv_nxt(
        tcp.sequence_number_value()
            .wrapping_add(payload_len)
            .wrapping_add(1),
    );
}

fn server_close_wait_state(local_ip: Ipv4Addr, listen_port: u16) -> FlowState {
    FlowState::new(CLOSE_WAIT)
        .on_entry(move |ctx| {
            let remote_ip = ctx.get_tcp_remote_ipv4().ok_or_else(|| {
                FlowError::Capture("TCP CloseWait entry requires remote IPv4".to_string())
            })?;
            let remote_port = ctx.get_tcp_remote_port().ok_or_else(|| {
                FlowError::Capture("TCP CloseWait entry requires remote port".to_string())
            })?;
            let fin = fin_segment(ctx, local_ip, listen_port, remote_ip, remote_port);
            let snd_nxt = tcp_snd_nxt(ctx).wrapping_add(1);
            ctx.set_tcp_snd_nxt(snd_nxt);

            Ok(Step::send(fin).goto(LAST_ACK))
        })
        .entry_description("TCP FIN-ACK passive close")
        .entry_targets([LAST_ACK])
}

fn server_last_ack_state(local_ip: Ipv4Addr, listen_port: u16) -> FlowState {
    FlowState::new(LAST_ACK).on(server_last_ack_transition(local_ip, listen_port))
}

fn server_last_ack_transition(local_ip: Ipv4Addr, listen_port: u16) -> Transition {
    Transition::on(server_last_ack_matcher(local_ip, listen_port), |_packet, _ctx| {
        Ok(Step::goto(CLOSED))
    })
    .targets([CLOSED])
}

fn server_last_ack_matcher(local_ip: Ipv4Addr, listen_port: u16) -> impl crate::Matcher {
    predicate(
        "tcp server final ACK seq == tcp_rcv_nxt and ack == tcp_snd_nxt",
        move |packet, ctx| {
            let Some(remote_ip) = ctx.get_tcp_remote_ipv4() else {
                return false;
            };
            let Some(remote_port) = ctx.get_tcp_remote_port() else {
                return false;
            };

            let matcher = tcp_segment_for_ipv4(
                local_ip,
                listen_port,
                remote_ip,
                remote_port,
                crafter::TCP_FLAG_ACK,
            )
            .ack_matches_tcp_snd_nxt();
            if !matcher.matches(packet, ctx) {
                return false;
            }

            packet.layer::<crafter::Tcp>().is_some_and(|tcp| {
                !tcp.has_fin()
                    && !tcp.has_flag(crafter::TCP_FLAG_RST)
                    && packet.layer::<crafter::Raw>().is_none()
                    && ctx.get_tcp_rcv_nxt() == Some(tcp.sequence_number_value())
            })
        },
    )
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
        syn_segment, CLOSED, CLOSE_WAIT, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, LAST_ACK, LISTEN,
        SYN_RECEIVED, SYN_SENT, TCP_CLIENT_ISS, TCP_CLIENT_LOCAL_PORT, TCP_MSS, TCP_SERVER_ISS,
        TCP_WINDOW,
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
        assert!(flow.validate().is_ok());

        let show = flow.show();
        for expected in [SYN_SENT, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSED] {
            assert!(show.contains(expected), "show() missing state {expected}");
        }
        for expected in [
            "TCP SYN",
            "flags include 0x012",
            "-> Established",
            "TCP PSH-ACK data",
            "tcp data seq == tcp_rcv_nxt",
            "-> FinWait1",
            "TCP FIN-ACK active close",
            "-> FinWait2",
            "tcp FIN seq == tcp_rcv_nxt",
            "-> Closed [terminal]",
        ] {
            assert!(
                show.contains(expected),
                "show() missing client transition detail {expected:?}:\n{show}"
            );
        }
    }

    #[test]
    fn tcp_server_flow_exposes_initial_and_named_states() {
        let flow = server_flow(docaddr::SERVER_IPV4, 80, None);

        assert_eq!(flow.role(), Role::Responder);
        assert_eq!(flow.initial(), LISTEN);
        assert!(flow.validate().is_ok());
        assert_named_states(
            &flow,
            &[LISTEN, SYN_RECEIVED, ESTABLISHED, CLOSE_WAIT, LAST_ACK, CLOSED],
        );
        let listen = flow.state(LISTEN).expect("Listen state exists");
        assert!(!listen.has_entry(), "Listen must not send on entry");
        assert_eq!(listen.transitions().len(), 1);
        let show = flow.show();
        for expected in [LISTEN, SYN_RECEIVED, ESTABLISHED, CLOSE_WAIT, LAST_ACK, CLOSED] {
            assert!(show.contains(expected), "show() missing state {expected}");
        }
        for expected in [
            "tcp SYN to listen port",
            "-> SynReceived",
            "tcp final ACK for stored four-tuple",
            "-> Established",
            "tcp server data seq == tcp_rcv_nxt",
            "tcp server FIN seq == tcp_rcv_nxt",
            "-> CloseWait",
            "TCP FIN-ACK passive close",
            "-> LastAck",
            "tcp server final ACK seq == tcp_rcv_nxt",
            "-> Closed [terminal]",
        ] {
            assert!(
                show.contains(expected),
                "show() missing server transition detail {expected:?}:\n{show}"
            );
        }
    }

    #[test]
    fn tcp_server_listen_transition_records_client_and_sends_syn_ack() {
        const CLIENT_ISS: u32 = 0x5152_5354;
        const CLIENT_PORT: u16 = 49_153;
        const LISTEN_PORT: u16 = 8080;
        const CLIENT_WINDOW: u16 = 32_768;
        const CLIENT_MSS: u16 = 1_200;

        let mut flow = server_flow(local_ipv4(), LISTEN_PORT, None);
        let mut context = PacketContext::new();
        let syn = syn_to_server(
            CLIENT_ISS,
            CLIENT_PORT,
            LISTEN_PORT,
            CLIENT_WINDOW,
            CLIENT_MSS,
        );
        let syn_ack_from_client = syn_ack_to_server(CLIENT_ISS, CLIENT_PORT, LISTEN_PORT);

        {
            let listen = flow.state(LISTEN).expect("Listen state exists");
            let transition = &listen.transitions()[0];
            assert!(transition.matches(&syn, &context));
            assert!(
                !transition.matches(&syn_ack_from_client, &context),
                "Listen transition must require SYN with no ACK"
            );
        }

        let step = flow
            .state_mut(LISTEN)
            .expect("Listen state exists")
            .find_transition(&syn, &context)
            .expect("SYN transition matches")
            .fire(&syn, &mut context)
            .expect("SYN transition should fire");
        let syn_ack = step.outgoing().expect("SYN transition sends SYN-ACK");
        let ipv4 = syn_ack.layer::<crafter::Ipv4>().expect("IPv4 layer");
        let tcp = syn_ack.layer::<crafter::Tcp>().expect("TCP layer");

        assert_eq!(context.get_tcp_local_port(), Some(LISTEN_PORT));
        assert_eq!(context.get_tcp_remote_port(), Some(CLIENT_PORT));
        assert_eq!(context.get_tcp_remote_ipv4(), Some(remote_ipv4()));
        assert_eq!(
            context.get_tcp_rcv_nxt(),
            Some(CLIENT_ISS.wrapping_add(1))
        );
        assert_eq!(context.get_tcp_peer_mss(), Some(CLIENT_MSS));
        assert_eq!(context.get_tcp_peer_window(), Some(CLIENT_WINDOW));
        assert_eq!(context.get_tcp_iss(), Some(TCP_SERVER_ISS));
        assert_eq!(
            context.get_tcp_snd_nxt(),
            Some(TCP_SERVER_ISS.wrapping_add(1))
        );
        assert_eq!(ipv4.source(), local_ipv4());
        assert_eq!(ipv4.destination(), remote_ipv4());
        assert_eq!(tcp.source_port_value(), LISTEN_PORT);
        assert_eq!(tcp.destination_port_value(), CLIENT_PORT);
        assert_eq!(tcp.sequence_number_value(), TCP_SERVER_ISS);
        assert_eq!(
            tcp.acknowledgment_number_value(),
            CLIENT_ISS.wrapping_add(1)
        );
        assert_eq!(tcp.flags_value(), TCP_FLAG_SYN | TCP_FLAG_ACK);
        assert_has_mss(tcp);
        assert_eq!(step.target(), Some(SYN_RECEIVED));
    }

    #[test]
    fn tcp_server_syn_received_transition_accepts_final_ack_and_reaches_established() {
        const CLIENT_ISS: u32 = 0x5152_5354;
        const CLIENT_PORT: u16 = 49_153;
        const LISTEN_PORT: u16 = 8080;

        let mut flow = server_flow(local_ipv4(), LISTEN_PORT, None);
        let mut context = PacketContext::new();
        let syn = syn_to_server(CLIENT_ISS, CLIENT_PORT, LISTEN_PORT, TCP_WINDOW, TCP_MSS);

        let listen_step = flow
            .state_mut(LISTEN)
            .expect("Listen state exists")
            .find_transition(&syn, &context)
            .expect("SYN transition matches")
            .fire(&syn, &mut context)
            .expect("SYN transition should fire");
        assert_eq!(listen_step.target(), Some(SYN_RECEIVED));

        let server_snd_nxt = context
            .get_tcp_snd_nxt()
            .expect("SYN transition records server snd_nxt");
        let client_rcv_nxt = context
            .get_tcp_rcv_nxt()
            .expect("SYN transition records client rcv_nxt");
        let final_ack = ack_to_server(client_rcv_nxt, server_snd_nxt, CLIENT_PORT, LISTEN_PORT);
        let wrong_ack = ack_to_server(
            client_rcv_nxt,
            server_snd_nxt.wrapping_add(1),
            CLIENT_PORT,
            LISTEN_PORT,
        );
        let wrong_seq = ack_to_server(
            client_rcv_nxt.wrapping_add(1),
            server_snd_nxt,
            CLIENT_PORT,
            LISTEN_PORT,
        );

        {
            let syn_received = flow
                .state(SYN_RECEIVED)
                .expect("SynReceived state exists");
            let transition = &syn_received.transitions()[0];
            assert!(transition.matches(&final_ack, &context));
            assert!(
                !transition.matches(&wrong_ack, &context),
                "SynReceived transition must reject ACKs that do not acknowledge server snd_nxt"
            );
            assert!(
                !transition.matches(&wrong_seq, &context),
                "SynReceived transition must reject ACKs with unexpected client sequence"
            );
        }

        let step = flow
            .state_mut(SYN_RECEIVED)
            .expect("SynReceived state exists")
            .find_transition(&final_ack, &context)
            .expect("final ACK transition matches")
            .fire(&final_ack, &mut context)
            .expect("final ACK transition should fire");

        assert!(step.outgoing().is_none());
        assert_eq!(step.target(), Some(ESTABLISHED));
        assert_eq!(context.get_tcp_snd_nxt(), Some(server_snd_nxt));
        assert_eq!(context.get_tcp_rcv_nxt(), Some(client_rcv_nxt));
    }

    #[test]
    fn tcp_server_established_transition_stores_client_data_and_sends_ack() {
        const CLIENT_PORT: u16 = 49_153;
        const LISTEN_PORT: u16 = 8080;

        let payload = b"client request";
        let mut flow = server_flow(local_ipv4(), LISTEN_PORT, None);
        let mut context = tcp_context();
        context.set_tcp_local_port(LISTEN_PORT);
        context.set_tcp_remote_port(CLIENT_PORT);
        context.set_tcp_remote_ipv4(remote_ipv4());

        let client_data = data_to_server(RCV_NXT, SND_NXT, CLIENT_PORT, LISTEN_PORT, payload);
        let wrong_seq = data_to_server(
            RCV_NXT.wrapping_add(1),
            SND_NXT,
            CLIENT_PORT,
            LISTEN_PORT,
            payload,
        );
        let client_ack = ack_to_server(RCV_NXT, SND_NXT, CLIENT_PORT, LISTEN_PORT);

        {
            let established = flow.state(ESTABLISHED).expect("Established state exists");
            let transition = &established.transitions()[0];
            assert!(transition.matches(&client_data, &context));
            assert!(
                !transition.matches(&wrong_seq, &context),
                "Established transition must reject out-of-order client data"
            );
            assert!(
                !transition.matches(&client_ack, &context),
                "Established transition must reject payload-free ACKs"
            );
        }

        let step = flow
            .state_mut(ESTABLISHED)
            .expect("Established state exists")
            .find_transition(&client_data, &context)
            .expect("client data transition matches")
            .fire(&client_data, &mut context)
            .expect("client data transition should fire");
        let ack = step.outgoing().expect("client data transition sends ACK");
        let tcp = ack.layer::<crafter::Tcp>().expect("TCP layer");
        let expected_rcv_nxt = RCV_NXT.wrapping_add(payload.len() as u32);

        assert_eq!(context.tcp_received_payload(), payload);
        assert_eq!(context.get_tcp_rcv_nxt(), Some(expected_rcv_nxt));
        assert_eq!(tcp.source_port_value(), LISTEN_PORT);
        assert_eq!(tcp.destination_port_value(), CLIENT_PORT);
        assert_eq!(tcp.sequence_number_value(), SND_NXT);
        assert_eq!(tcp.acknowledgment_number_value(), expected_rcv_nxt);
        assert_eq!(tcp.flags_value(), TCP_FLAG_ACK);
        assert_eq!(step.target(), None);
        assert!(step.expects_reply());
    }

    #[test]
    fn tcp_server_established_transition_sends_configured_response_and_advances_snd_nxt() {
        const CLIENT_PORT: u16 = 49_153;
        const LISTEN_PORT: u16 = 8080;

        let request = b"client request";
        let response = b"server response".to_vec();
        let mut flow = server_flow(local_ipv4(), LISTEN_PORT, Some(response.clone()));
        let mut context = tcp_context();
        context.set_tcp_local_port(LISTEN_PORT);
        context.set_tcp_remote_port(CLIENT_PORT);
        context.set_tcp_remote_ipv4(remote_ipv4());

        let client_data = data_to_server(RCV_NXT, SND_NXT, CLIENT_PORT, LISTEN_PORT, request);
        let step = flow
            .state_mut(ESTABLISHED)
            .expect("Established state exists")
            .find_transition(&client_data, &context)
            .expect("client data transition matches")
            .fire(&client_data, &mut context)
            .expect("client data transition should fire");
        let packet = step
            .outgoing()
            .expect("client data transition sends configured response");
        let decoded = compiled_ipv4(packet.clone());
        let tcp = decoded.layer::<crafter::Tcp>().expect("TCP layer");
        let raw = decoded.layer::<crafter::Raw>().expect("Raw payload");
        let expected_rcv_nxt = RCV_NXT.wrapping_add(request.len() as u32);

        assert_eq!(context.tcp_received_payload(), request);
        assert_eq!(context.get_tcp_rcv_nxt(), Some(expected_rcv_nxt));
        assert_eq!(
            context.get_tcp_snd_nxt(),
            Some(SND_NXT.wrapping_add(response.len() as u32))
        );
        assert_eq!(tcp.source_port_value(), LISTEN_PORT);
        assert_eq!(tcp.destination_port_value(), CLIENT_PORT);
        assert_eq!(tcp.sequence_number_value(), SND_NXT);
        assert_eq!(tcp.acknowledgment_number_value(), expected_rcv_nxt);
        assert_eq!(tcp.flags_value(), TCP_FLAG_PSH | TCP_FLAG_ACK);
        assert_eq!(raw.as_bytes(), response.as_slice());
        assert_eq!(step.target(), None);
        assert!(step.expects_reply());
    }

    #[test]
    fn tcp_server_established_fin_transition_sends_ack_and_reaches_close_wait() {
        const CLIENT_PORT: u16 = 49_153;
        const LISTEN_PORT: u16 = 8080;

        let final_payload = b"client final bytes";
        let mut flow = server_flow(local_ipv4(), LISTEN_PORT, None);
        let mut context = tcp_context();
        context.set_tcp_local_port(LISTEN_PORT);
        context.set_tcp_remote_port(CLIENT_PORT);
        context.set_tcp_remote_ipv4(remote_ipv4());

        let client_fin =
            fin_data_ack_to_server(RCV_NXT, SND_NXT, CLIENT_PORT, LISTEN_PORT, final_payload);
        let wrong_seq = fin_ack_to_server(
            RCV_NXT.wrapping_add(1),
            SND_NXT,
            CLIENT_PORT,
            LISTEN_PORT,
        );

        {
            let established = flow.state(ESTABLISHED).expect("Established state exists");
            assert!(
                !established.transitions()[0].matches(&client_fin, &context),
                "data transition must not steal FIN segments carrying payload"
            );
            let transition = &established.transitions()[1];
            assert!(transition.matches(&client_fin, &context));
            assert!(
                !transition.matches(&wrong_seq, &context),
                "FIN transition must reject unexpected client sequence"
            );
        }

        let step = flow
            .state_mut(ESTABLISHED)
            .expect("Established state exists")
            .find_transition(&client_fin, &context)
            .expect("client FIN transition matches")
            .fire(&client_fin, &mut context)
            .expect("client FIN transition should fire");
        let ack = step.outgoing().expect("client FIN transition sends ACK");
        let tcp = ack.layer::<crafter::Tcp>().expect("TCP layer");
        let expected_rcv_nxt = RCV_NXT
            .wrapping_add(final_payload.len() as u32)
            .wrapping_add(1);

        assert_eq!(context.tcp_received_payload(), final_payload);
        assert_eq!(context.get_tcp_rcv_nxt(), Some(expected_rcv_nxt));
        assert_eq!(tcp.source_port_value(), LISTEN_PORT);
        assert_eq!(tcp.destination_port_value(), CLIENT_PORT);
        assert_eq!(tcp.sequence_number_value(), SND_NXT);
        assert_eq!(tcp.acknowledgment_number_value(), expected_rcv_nxt);
        assert_eq!(tcp.flags_value(), TCP_FLAG_ACK);
        assert_eq!(step.target(), Some(CLOSE_WAIT));
    }

    #[test]
    fn tcp_server_close_wait_entry_sends_fin_and_advances_snd_nxt() {
        const CLIENT_PORT: u16 = 49_153;
        const LISTEN_PORT: u16 = 8080;

        let mut flow = server_flow(local_ipv4(), LISTEN_PORT, None);
        let mut context = tcp_context();
        context.set_tcp_local_port(LISTEN_PORT);
        context.set_tcp_remote_port(CLIENT_PORT);
        context.set_tcp_remote_ipv4(remote_ipv4());

        let step = flow
            .state_mut(CLOSE_WAIT)
            .expect("CloseWait state exists")
            .run_entry(&mut context)
            .expect("CloseWait entry should run")
            .expect("CloseWait entry should return a step");
        let fin = step.outgoing().expect("CloseWait entry sends FIN");
        let tcp = fin.layer::<crafter::Tcp>().expect("TCP layer");

        assert_eq!(step.target(), Some(LAST_ACK));
        assert!(step.expects_reply());
        assert_eq!(tcp.source_port_value(), LISTEN_PORT);
        assert_eq!(tcp.destination_port_value(), CLIENT_PORT);
        assert_eq!(tcp.sequence_number_value(), SND_NXT);
        assert_eq!(tcp.acknowledgment_number_value(), RCV_NXT);
        assert_eq!(tcp.flags_value(), TCP_FLAG_FIN | TCP_FLAG_ACK);
        assert_eq!(context.get_tcp_snd_nxt(), Some(SND_NXT.wrapping_add(1)));
    }

    #[test]
    fn tcp_server_last_ack_transition_accepts_final_ack_and_reaches_closed() {
        const CLIENT_PORT: u16 = 49_153;
        const LISTEN_PORT: u16 = 8080;

        let mut flow = server_flow(local_ipv4(), LISTEN_PORT, None);
        let mut context = tcp_context();
        context.set_tcp_snd_nxt(SND_NXT.wrapping_add(1));
        context.set_tcp_local_port(LISTEN_PORT);
        context.set_tcp_remote_port(CLIENT_PORT);
        context.set_tcp_remote_ipv4(remote_ipv4());

        let final_ack = ack_to_server(
            RCV_NXT,
            SND_NXT.wrapping_add(1),
            CLIENT_PORT,
            LISTEN_PORT,
        );
        let wrong_ack = ack_to_server(RCV_NXT, SND_NXT, CLIENT_PORT, LISTEN_PORT);
        let late_data = data_to_server(
            RCV_NXT,
            SND_NXT.wrapping_add(1),
            CLIENT_PORT,
            LISTEN_PORT,
            b"late data",
        );

        {
            let last_ack = flow.state(LAST_ACK).expect("LastAck state exists");
            let transition = &last_ack.transitions()[0];
            assert!(transition.matches(&final_ack, &context));
            assert!(
                !transition.matches(&wrong_ack, &context),
                "LastAck transition must reject ACKs that do not acknowledge server FIN"
            );
            assert!(
                !transition.matches(&late_data, &context),
                "LastAck transition must reject payload-carrying ACKs"
            );
        }

        let step = flow
            .state_mut(LAST_ACK)
            .expect("LastAck state exists")
            .find_transition(&final_ack, &context)
            .expect("final ACK transition matches")
            .fire(&final_ack, &mut context)
            .expect("final ACK transition should fire");

        assert!(step.outgoing().is_none());
        assert_eq!(step.target(), Some(CLOSED));
        assert_eq!(context.get_tcp_snd_nxt(), Some(SND_NXT.wrapping_add(1)));
        assert_eq!(context.get_tcp_rcv_nxt(), Some(RCV_NXT));
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

    #[test]
    fn tcp_client_established_entry_sends_payload_and_advances_snd_nxt() {
        let payload = b"hello over tcp".to_vec();
        let mut flow = client_flow(
            local_ipv4(),
            remote_ipv4(),
            REMOTE_PORT,
            Some(payload.clone()),
        );
        let mut context = tcp_context();

        let step = flow
            .state_mut(ESTABLISHED)
            .expect("Established state exists")
            .run_entry(&mut context)
            .expect("Established entry should run")
            .expect("Established entry should return a step");
        let packet = step
            .outgoing()
            .expect("Established entry sends payload data");
        let decoded = compiled_ipv4(packet.clone());
        let ipv4 = decoded.layer::<crafter::Ipv4>().expect("IPv4 layer");
        let tcp = decoded.layer::<crafter::Tcp>().expect("TCP layer");
        let raw = decoded.layer::<crafter::Raw>().expect("Raw payload");

        assert_eq!(step.target(), None);
        assert!(step.expects_reply());
        assert_eq!(ipv4.source(), local_ipv4());
        assert_eq!(ipv4.destination(), remote_ipv4());
        assert_eq!(tcp.source_port_value(), TCP_CLIENT_LOCAL_PORT);
        assert_eq!(tcp.destination_port_value(), REMOTE_PORT);
        assert_eq!(tcp.sequence_number_value(), SND_NXT);
        assert_eq!(tcp.acknowledgment_number_value(), RCV_NXT);
        assert_eq!(tcp.flags_value(), TCP_FLAG_PSH | TCP_FLAG_ACK);
        assert_eq!(raw.as_bytes(), payload.as_slice());
        assert_eq!(
            context.get_tcp_snd_nxt(),
            Some(SND_NXT.wrapping_add(payload.len() as u32))
        );
    }

    #[test]
    fn tcp_client_established_transition_stores_peer_data_and_sends_ack() {
        let payload = b"server reply";
        let mut flow = client_flow(local_ipv4(), remote_ipv4(), REMOTE_PORT, None);
        let mut context = tcp_context();
        let peer_data = data_from_peer(RCV_NXT, SND_NXT, payload);
        let wrong_seq = data_from_peer(RCV_NXT.wrapping_add(1), SND_NXT, payload);
        let peer_ack = ack_from_peer(RCV_NXT, SND_NXT);

        {
            let established = flow.state(ESTABLISHED).expect("Established state exists");
            let transition = &established.transitions()[0];
            assert!(transition.matches(&peer_data, &context));
            assert!(!transition.matches(&wrong_seq, &context));
            assert!(!transition.matches(&peer_ack, &context));
        }

        let step = flow
            .state_mut(ESTABLISHED)
            .expect("Established state exists")
            .find_transition(&peer_data, &context)
            .expect("TCP peer data transition matches")
            .fire(&peer_data, &mut context)
            .expect("TCP peer data transition should fire");
        let ack = step.outgoing().expect("peer data transition sends ACK");
        let tcp = ack.layer::<crafter::Tcp>().expect("TCP layer");
        let expected_rcv_nxt = RCV_NXT.wrapping_add(payload.len() as u32);

        assert_eq!(context.tcp_received_payload(), payload);
        assert_eq!(context.get_tcp_rcv_nxt(), Some(expected_rcv_nxt));
        assert_eq!(tcp.source_port_value(), TCP_CLIENT_LOCAL_PORT);
        assert_eq!(tcp.destination_port_value(), REMOTE_PORT);
        assert_eq!(tcp.sequence_number_value(), SND_NXT);
        assert_eq!(tcp.acknowledgment_number_value(), expected_rcv_nxt);
        assert_eq!(tcp.flags_value(), TCP_FLAG_ACK);
        assert_eq!(step.target(), Some(FIN_WAIT_1));
    }

    #[test]
    fn tcp_client_fin_wait1_entry_sends_fin_and_advances_snd_nxt() {
        let mut flow = client_flow(local_ipv4(), remote_ipv4(), REMOTE_PORT, None);
        let mut context = tcp_context();

        let step = flow
            .state_mut(FIN_WAIT_1)
            .expect("FinWait1 state exists")
            .run_entry(&mut context)
            .expect("FinWait1 entry should run")
            .expect("FinWait1 entry should return a step");
        let packet = step.outgoing().expect("FinWait1 entry sends FIN");
        let tcp = packet.layer::<crafter::Tcp>().expect("TCP layer");

        assert_eq!(step.target(), None);
        assert!(step.expects_reply());
        assert_eq!(tcp.source_port_value(), TCP_CLIENT_LOCAL_PORT);
        assert_eq!(tcp.destination_port_value(), REMOTE_PORT);
        assert_eq!(tcp.sequence_number_value(), SND_NXT);
        assert_eq!(tcp.acknowledgment_number_value(), RCV_NXT);
        assert_eq!(tcp.flags_value(), TCP_FLAG_FIN | TCP_FLAG_ACK);
        assert_eq!(context.get_tcp_snd_nxt(), Some(SND_NXT.wrapping_add(1)));
    }

    #[test]
    fn tcp_client_fin_wait1_ack_transition_reaches_fin_wait2() {
        let mut flow = client_flow(local_ipv4(), remote_ipv4(), REMOTE_PORT, None);
        let mut context = tcp_context();
        context.set_tcp_snd_nxt(SND_NXT.wrapping_add(1));
        let peer_ack = ack_from_peer(RCV_NXT, SND_NXT.wrapping_add(1));
        let wrong_ack = ack_from_peer(RCV_NXT, SND_NXT);

        {
            let fin_wait1 = flow.state(FIN_WAIT_1).expect("FinWait1 state exists");
            let transition = &fin_wait1.transitions()[1];
            assert!(transition.matches(&peer_ack, &context));
            assert!(!transition.matches(&wrong_ack, &context));
        }

        let step = flow
            .state_mut(FIN_WAIT_1)
            .expect("FinWait1 state exists")
            .find_transition(&peer_ack, &context)
            .expect("FIN ACK transition matches")
            .fire(&peer_ack, &mut context)
            .expect("FIN ACK transition should fire");

        assert_eq!(context.get_tcp_rcv_nxt(), Some(RCV_NXT));
        assert!(step.outgoing().is_none());
        assert_eq!(step.target(), Some(FIN_WAIT_2));
    }

    #[test]
    fn tcp_client_fin_wait2_fin_transition_sends_final_ack_and_closes() {
        let mut flow = client_flow(local_ipv4(), remote_ipv4(), REMOTE_PORT, None);
        let mut context = tcp_context();
        let peer_fin = fin_ack_from_peer(RCV_NXT, SND_NXT);

        {
            let fin_wait2 = flow.state(FIN_WAIT_2).expect("FinWait2 state exists");
            let transition = &fin_wait2.transitions()[0];
            assert!(transition.matches(&peer_fin, &context));
        }

        let step = flow
            .state_mut(FIN_WAIT_2)
            .expect("FinWait2 state exists")
            .find_transition(&peer_fin, &context)
            .expect("peer FIN transition matches")
            .fire(&peer_fin, &mut context)
            .expect("peer FIN transition should fire");
        let ack = step.outgoing().expect("peer FIN transition sends final ACK");
        let tcp = ack.layer::<crafter::Tcp>().expect("TCP layer");

        assert_eq!(context.get_tcp_rcv_nxt(), Some(RCV_NXT.wrapping_add(1)));
        assert_eq!(tcp.source_port_value(), TCP_CLIENT_LOCAL_PORT);
        assert_eq!(tcp.destination_port_value(), REMOTE_PORT);
        assert_eq!(tcp.sequence_number_value(), SND_NXT);
        assert_eq!(tcp.acknowledgment_number_value(), RCV_NXT.wrapping_add(1));
        assert_eq!(tcp.flags_value(), TCP_FLAG_ACK);
        assert_eq!(step.target(), Some(CLOSED));
    }

    #[test]
    fn tcp_client_fin_wait1_combined_fin_ack_sends_final_ack_and_closes() {
        let mut flow = client_flow(local_ipv4(), remote_ipv4(), REMOTE_PORT, None);
        let mut context = tcp_context();
        context.set_tcp_snd_nxt(SND_NXT.wrapping_add(1));
        let peer_fin_ack = fin_ack_from_peer(RCV_NXT, SND_NXT.wrapping_add(1));

        let step = flow
            .state_mut(FIN_WAIT_1)
            .expect("FinWait1 state exists")
            .find_transition(&peer_fin_ack, &context)
            .expect("combined FIN-ACK transition matches")
            .fire(&peer_fin_ack, &mut context)
            .expect("combined FIN-ACK transition should fire");
        let ack = step
            .outgoing()
            .expect("combined FIN-ACK transition sends final ACK");
        let tcp = ack.layer::<crafter::Tcp>().expect("TCP layer");

        assert_eq!(context.get_tcp_rcv_nxt(), Some(RCV_NXT.wrapping_add(1)));
        assert_eq!(tcp.sequence_number_value(), SND_NXT.wrapping_add(1));
        assert_eq!(tcp.acknowledgment_number_value(), RCV_NXT.wrapping_add(1));
        assert_eq!(tcp.flags_value(), TCP_FLAG_ACK);
        assert_eq!(step.target(), Some(CLOSED));
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

    fn syn_to_server(
        client_seq: u32,
        client_port: u16,
        listen_port: u16,
        window: u16,
        mss: u16,
    ) -> Packet {
        let tcp = crafter::Tcp::new()
            .sport(client_port)
            .dport(listen_port)
            .seq(client_seq)
            .window(window)
            .syn_segment()
            .tcp_option(TcpOption::maximum_segment_size(mss))
            .expect("fixed client TCP MSS option encodes");

        compiled_ipv4(
            crafter::Ipv4::new()
                .src(remote_ipv4())
                .dst(local_ipv4())
                .protocol(crafter::IPPROTO_TCP)
                / tcp,
        )
    }

    fn syn_ack_to_server(client_seq: u32, client_port: u16, listen_port: u16) -> Packet {
        let tcp = crafter::Tcp::new()
            .sport(client_port)
            .dport(listen_port)
            .seq(client_seq)
            .ack(TCP_SERVER_ISS.wrapping_add(1))
            .window(TCP_WINDOW)
            .syn_ack_segment();

        compiled_ipv4(
            crafter::Ipv4::new()
                .src(remote_ipv4())
                .dst(local_ipv4())
                .protocol(crafter::IPPROTO_TCP)
                / tcp,
        )
    }

    fn ack_to_server(client_seq: u32, ack: u32, client_port: u16, listen_port: u16) -> Packet {
        let tcp = crafter::Tcp::new()
            .sport(client_port)
            .dport(listen_port)
            .seq(client_seq)
            .ack(ack)
            .window(TCP_WINDOW)
            .ack_segment();

        compiled_ipv4(
            crafter::Ipv4::new()
                .src(remote_ipv4())
                .dst(local_ipv4())
                .protocol(crafter::IPPROTO_TCP)
                / tcp,
        )
    }

    fn data_to_server(
        client_seq: u32,
        ack: u32,
        client_port: u16,
        listen_port: u16,
        payload: impl AsRef<[u8]>,
    ) -> Packet {
        let tcp = crafter::Tcp::new()
            .sport(client_port)
            .dport(listen_port)
            .seq(client_seq)
            .ack(ack)
            .window(TCP_WINDOW)
            .ack_segment()
            .psh();

        compiled_ipv4(
            crafter::Ipv4::new()
                .src(remote_ipv4())
                .dst(local_ipv4())
                .protocol(crafter::IPPROTO_TCP)
                / tcp
                / crafter::Raw::from_bytes(payload),
        )
    }

    fn fin_ack_to_server(client_seq: u32, ack: u32, client_port: u16, listen_port: u16) -> Packet {
        let tcp = crafter::Tcp::new()
            .sport(client_port)
            .dport(listen_port)
            .seq(client_seq)
            .ack(ack)
            .window(TCP_WINDOW)
            .fin_ack_segment();

        compiled_ipv4(
            crafter::Ipv4::new()
                .src(remote_ipv4())
                .dst(local_ipv4())
                .protocol(crafter::IPPROTO_TCP)
                / tcp,
        )
    }

    fn fin_data_ack_to_server(
        client_seq: u32,
        ack: u32,
        client_port: u16,
        listen_port: u16,
        payload: impl AsRef<[u8]>,
    ) -> Packet {
        let tcp = crafter::Tcp::new()
            .sport(client_port)
            .dport(listen_port)
            .seq(client_seq)
            .ack(ack)
            .window(TCP_WINDOW)
            .fin_ack_segment()
            .psh();

        compiled_ipv4(
            crafter::Ipv4::new()
                .src(remote_ipv4())
                .dst(local_ipv4())
                .protocol(crafter::IPPROTO_TCP)
                / tcp
                / crafter::Raw::from_bytes(payload),
        )
    }

    fn data_from_peer(peer_seq: u32, ack: u32, payload: impl AsRef<[u8]>) -> Packet {
        let tcp = crafter::Tcp::new()
            .sport(REMOTE_PORT)
            .dport(TCP_CLIENT_LOCAL_PORT)
            .seq(peer_seq)
            .ack(ack)
            .window(TCP_WINDOW)
            .ack_segment()
            .psh();

        compiled_ipv4(
            crafter::Ipv4::new()
                .src(remote_ipv4())
                .dst(local_ipv4())
                .protocol(crafter::IPPROTO_TCP)
                / tcp
                / crafter::Raw::from_bytes(payload),
        )
    }

    fn ack_from_peer(peer_seq: u32, ack: u32) -> Packet {
        let tcp = crafter::Tcp::new()
            .sport(REMOTE_PORT)
            .dport(TCP_CLIENT_LOCAL_PORT)
            .seq(peer_seq)
            .ack(ack)
            .window(TCP_WINDOW)
            .ack_segment();

        compiled_ipv4(
            crafter::Ipv4::new()
                .src(remote_ipv4())
                .dst(local_ipv4())
                .protocol(crafter::IPPROTO_TCP)
                / tcp,
        )
    }

    fn fin_ack_from_peer(peer_seq: u32, ack: u32) -> Packet {
        let tcp = crafter::Tcp::new()
            .sport(REMOTE_PORT)
            .dport(TCP_CLIENT_LOCAL_PORT)
            .seq(peer_seq)
            .ack(ack)
            .window(TCP_WINDOW)
            .fin_ack_segment();

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
