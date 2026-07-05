//! Reactive edges in a protocol flow graph.

use crate::{Matcher, PacketContext, Result, Step};

type TransitionHandler = dyn FnMut(&crafter::Packet, &mut PacketContext) -> Result<Step>;

/// A state-graph edge triggered by a packet matcher.
pub struct Transition {
    matcher: Box<dyn Matcher>,
    handler: Box<TransitionHandler>,
}

impl Transition {
    /// Create a transition from a matcher and a packet handler.
    pub fn on<M, H>(matcher: M, handler: H) -> Self
    where
        M: Matcher + 'static,
        H: FnMut(&crafter::Packet, &mut PacketContext) -> Result<Step> + 'static,
    {
        Self {
            matcher: Box::new(matcher),
            handler: Box::new(handler),
        }
    }

    /// Return a human-readable description of the transition matcher.
    pub fn describe(&self) -> String {
        self.matcher.describe()
    }

    /// Return true when this transition should fire for `packet`.
    pub fn matches(&self, packet: &crafter::Packet, ctx: &PacketContext) -> bool {
        self.matcher.matches(packet, ctx)
    }

    /// Run the transition handler and return the resulting step.
    pub fn fire(&mut self, packet: &crafter::Packet, ctx: &mut PacketContext) -> Result<Step> {
        (self.handler)(packet, ctx)
    }
}

#[cfg(test)]
mod tests {
    use crate::{PacketContext, PredicateMatcher, Step, Transition};

    #[test]
    fn transition_matches_and_fires_handler() {
        let matcher = PredicateMatcher::new("any packet", |_packet, _ctx| true);
        let mut transition = Transition::on(matcher, |_packet, ctx| {
            ctx.set_transaction_id(0x1234_5678);
            Ok(Step::goto("next"))
        });
        let packet = crafter::Packet::decode_raw([0xde, 0xad, 0xbe, 0xef])
            .expect("raw packet should decode");
        let mut context = PacketContext::new();

        assert!(transition.matches(&packet, &context));
        assert_eq!(transition.describe(), "any packet");

        let step = transition
            .fire(&packet, &mut context)
            .expect("transition should fire");

        assert_eq!(context.get_transaction_id(), Some(0x1234_5678));
        assert_eq!(step.target(), Some("next"));
        assert!(!step.is_terminal());
        assert!(step.outgoing().is_none());
    }
}
