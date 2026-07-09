//! TCP flow templates.
//!
//! The client lifecycle is `SynSent -> Established -> FinWait1 -> FinWait2 ->
//! Closed`.
//! The server lifecycle is `Listen -> SynReceived -> Established -> CloseWait ->
//! LastAck -> Closed`.

use std::net::Ipv4Addr;

use crate::{Flow, FlowBuilderExt, FlowState, Role, Step};

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

/// Build the TCP client flow scaffold.
///
/// The address, port, and payload arguments are placeholders for the real TCP
/// actions added by later steps. This scaffold only declares the lifecycle.
pub fn client_flow(
    _local_ip: Ipv4Addr,
    _remote_ip: Ipv4Addr,
    _remote_port: u16,
    _payload: Option<Vec<u8>>,
) -> Flow {
    Flow::new("tcp-client")
        .role(Role::Initiator)
        .state(stub_state(SYN_SENT, ESTABLISHED))
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

#[cfg(test)]
mod tests {
    use super::{
        client_flow, server_flow, CLOSED, CLOSED_SRV, CLOSE_WAIT, ESTABLISHED, FIN_WAIT_1,
        FIN_WAIT_2, LAST_ACK, LISTEN, SYN_RECEIVED, SYN_SENT,
    };
    use crate::{docaddr, Role};

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
        assert_named_states(&flow, &[SYN_SENT, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSED]);
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

    fn assert_named_states(flow: &crate::Flow, expected: &[&str]) {
        for name in expected {
            assert!(flow.state(name).is_some(), "missing {name} state");
        }
    }
}
