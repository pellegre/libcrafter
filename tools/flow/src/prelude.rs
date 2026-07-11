//! Common imports for flow tools.
//!
//! ```
//! use crafter_flow::prelude::*;
//!
//! assert_eq!(FlowOutcome::Completed, FlowOutcome::Completed);
//! ```

pub use crate::binding::{BindMode, BindSendClass, BindTarget, Binding};
pub use crate::capture::{
    derive_capture_filter, derive_capture_filter_for_packets, CaptureSource, MemoryCaptureSource,
    PcapCaptureSource,
};
pub use crate::docaddr;
pub use crate::error::{FlowError, Result};
#[cfg(feature = "quic-endpoint")]
pub use crate::flows::quic::{
    quic_client_flow, quic_server_flow, QuicClientFlowConfig, QuicServerFlowConfig,
};
pub use crate::flows::tcp::{
    client_flow, server_flow, CLOSED, CLOSED_SRV, CLOSE_WAIT, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2,
    LAST_ACK, LISTEN, SYN_RECEIVED, SYN_SENT,
};
pub use crate::matcher::{
    all, any, not, And, LayerMatcher, Matcher, MatcherExt, Not, Or, PredicateMatcher, ReplyMatcher,
};
pub use crate::report::{FlowOutcome, FlowReport, RecoveryMetrics};
pub use crate::Bound;
pub use crate::Conversation;
pub use crate::PacketContext;
pub use crate::Role;
pub use crate::Runner;
pub use crate::{run_tool, ToolRun, ToolRunReport};
pub use crate::{Flow, FlowBuilderExt};
pub use crate::{FlowState, FnMutator, Identity, Mutator, Step, StepGotoExt, Transition};
pub use crate::{RetransmitPolicy, RunOptions, SendRepeat};

#[cfg(test)]
mod tests {
    use crate as crafter_flow;

    #[test]
    fn prelude_exports_flow_error() {
        use crafter_flow::prelude::*;

        let error = FlowError::Unsupported("pending engine type".to_string());
        assert!(error.to_string().contains("unsupported flow feature"));
    }

    #[test]
    fn prelude_exports_binding() {
        use crafter_flow::prelude::*;

        let binding = Binding::default().live();
        assert_eq!(binding.mode(), BindMode::Live);
    }

    #[test]
    fn prelude_exports_bound() {
        use crafter_flow::prelude::*;

        assert_eq!(Bound::default(), Bound::Count(1));
    }

    #[test]
    fn prelude_exports_run_options() {
        use crafter_flow::prelude::*;

        assert_eq!(RunOptions::default().retries(2).retries, 2);
    }

    #[test]
    fn prelude_exports_packet_context() {
        use crafter_flow::prelude::*;

        let mut context = PacketContext::new();
        context.set_transaction_id(7);

        assert_eq!(context.get_transaction_id(), Some(7));
    }

    #[test]
    fn prelude_exports_tcp_flows_and_context_helpers() {
        use crafter_flow::prelude::*;
        use std::net::Ipv4Addr;

        let _client_flow: fn(Ipv4Addr, Ipv4Addr, u16, Option<Vec<u8>>) -> Flow = client_flow;
        let _server_flow: fn(Ipv4Addr, u16, Option<Vec<u8>>) -> Flow = server_flow;
        let states = [
            SYN_SENT,
            ESTABLISHED,
            FIN_WAIT_1,
            FIN_WAIT_2,
            CLOSED,
            LISTEN,
            SYN_RECEIVED,
            CLOSE_WAIT,
            LAST_ACK,
            CLOSED_SRV,
        ];
        assert!(states.contains(&SYN_SENT));

        let mut context = PacketContext::new();
        context.set_tcp_snd_nxt(1);
        context.set_tcp_rcv_nxt(2);
        context.set_tcp_iss(3);
        context.set_tcp_local_port(49_152);
        context.set_tcp_remote_port(443);
        context.set_tcp_remote_ipv4(Ipv4Addr::new(198, 51, 100, 20));
        context.set_tcp_peer_mss(1_460);
        context.set_tcp_peer_window(32_768);
        context.append_tcp_payload(b"tcp");

        assert_eq!(context.get_tcp_snd_nxt(), Some(1));
        assert_eq!(context.get_tcp_rcv_nxt(), Some(2));
        assert_eq!(context.get_tcp_iss(), Some(3));
        assert_eq!(context.get_tcp_local_port(), Some(49_152));
        assert_eq!(context.get_tcp_remote_port(), Some(443));
        assert_eq!(
            context.get_tcp_remote_ipv4(),
            Some(Ipv4Addr::new(198, 51, 100, 20))
        );
        assert_eq!(context.get_tcp_peer_mss(), Some(1_460));
        assert_eq!(context.get_tcp_peer_window(), Some(32_768));
        assert_eq!(context.tcp_received_payload(), b"tcp");
    }

    #[test]
    fn prelude_exports_matcher() {
        use crafter_flow::prelude::*;

        let matcher = PredicateMatcher::new("any packet", |_packet, _ctx| true);
        assert_eq!(matcher.describe(), "any packet");
    }

    #[test]
    fn prelude_exports_matcher_combinators() {
        use crafter_flow::prelude::*;

        let matcher = PredicateMatcher::new("any packet", |_packet, _ctx| true).not();
        assert_eq!(matcher.describe(), "not(any packet)");
    }

    #[test]
    fn prelude_exports_step() {
        use crafter_flow::prelude::*;

        let packet =
            crafter::Packet::decode_raw([0xde, 0xad, 0xbe, 0xef]).expect("raw packet decodes");
        let step = Step::send(packet).goto("next");

        assert!(step.outgoing().is_some());
        assert_eq!(step.target(), Some("next"));
    }

    #[test]
    fn prelude_exports_flow_state() {
        use crafter_flow::prelude::*;

        let state = FlowState::new("idle");

        assert_eq!(state.name(), "idle");
    }

    #[test]
    fn prelude_exports_flow() {
        use crafter_flow::prelude::*;

        let flow = Flow::new("empty");

        assert_eq!(Flow::role(&flow), Role::Initiator);
    }

    #[test]
    fn prelude_exports_mutator() {
        use crafter_flow::prelude::*;

        let mut context = PacketContext::new();
        let packet = crafter::Packet::decode_raw([0xde, 0xad]).expect("raw packet decodes");
        let mut mutator: Box<dyn Mutator> = Box::new(Identity);

        let mutated = mutator
            .mutate(packet, 0, &mut context)
            .expect("identity mutation succeeds");

        assert_eq!(mutator.name(), "identity");
        assert_eq!(mutated.summary(), "Raw(len=2)");
    }

    #[test]
    fn prelude_exports_capture_source() {
        use crafter_flow::prelude::*;
        use std::time::Duration;

        let packet = crafter::Packet::decode_raw([0xde, 0xad]).expect("raw packet decodes");
        let mut source = MemoryCaptureSource::new(vec![packet]);

        assert!(source.describe().contains("memory capture source"));
        assert!(source
            .next_packet(Duration::from_millis(1))
            .expect("capture succeeds")
            .is_some());
    }

    #[test]
    fn prelude_exports_conversation() {
        use crafter_flow::prelude::*;

        let conversation = Conversation::open(&Binding::default()).expect("conversation opens");

        assert!(conversation.is_dry_run());
    }

    #[test]
    fn prelude_exports_runner() {
        use crafter_flow::prelude::*;

        let runner = Runner::bind(Binding::default()).expect("runner binds");

        assert!(runner.is_dry_run());
    }

    #[test]
    fn prelude_exports_flow_report() {
        use crafter_flow::prelude::*;
        use std::time::Duration;

        let report = FlowReport::new(
            "prelude-flow",
            Role::Initiator,
            true,
            vec!["Done".to_string()],
            0,
            0,
            Vec::new(),
            1,
            Duration::ZERO,
            FlowOutcome::Completed,
            "PacketContext keys=[]",
        );

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(report.flow_name(), "prelude-flow");
        assert!(report.is_dry_run());
    }
}
