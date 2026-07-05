//! Common imports for flow tools.
//!
//! Later engine types (`Flow`, `Runner`, and `FlowReport`) are added here as
//! they are implemented.
//!
//! ```
//! use crafter_flow::prelude::*;
//!
//! let error = FlowError::Unsupported("pending engine type".to_string());
//! assert!(error.to_string().contains("unsupported flow feature"));
//! ```

pub use crate::Bound;
pub use crate::binding::{BindMode, BindSendClass, BindTarget, Binding};
pub use crate::docaddr;
pub use crate::error::{FlowError, Result};
pub use crate::Flow;
pub use crate::matcher::{
    all, any, not, And, LayerMatcher, Matcher, MatcherExt, Not, Or, PredicateMatcher, ReplyMatcher,
};
pub use crate::PacketContext;
pub use crate::RunOptions;
pub use crate::Role;
pub use crate::{FlowState, FnMutator, Identity, Mutator, Step, StepGotoExt, Transition};

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

        assert_eq!(flow.role(), Role::Initiator);
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
}
