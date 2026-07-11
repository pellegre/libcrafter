//! Packet match predicates for flow transitions.

use crate::PacketContext;

mod combinators;
mod layer;
mod reply;
mod tcp;
mod udp;

pub use combinators::{all, any, not, And, MatcherExt, Not, Or};
pub use layer::LayerMatcher;
pub use reply::ReplyMatcher;
pub use tcp::{tcp_segment, tcp_segment_for_ipv4, TcpSegmentMatcher};
pub use udp::{udp_payload, UdpDatagramMatcher};

type PacketPredicate = dyn Fn(&crafter::Packet, &PacketContext) -> bool;

/// Decides whether a received packet advances a flow transition.
pub trait Matcher {
    /// Return true when `packet` satisfies this matcher in the current context.
    fn matches(&self, packet: &crafter::Packet, ctx: &PacketContext) -> bool;

    /// Human-readable matcher description for reports.
    fn describe(&self) -> String;
}

/// Matcher backed by a caller-provided predicate closure.
pub struct PredicateMatcher {
    description: String,
    predicate: Box<PacketPredicate>,
}

impl PredicateMatcher {
    /// Create a matcher from a description and predicate closure.
    pub fn new(
        desc: impl Into<String>,
        predicate: impl Fn(&crafter::Packet, &PacketContext) -> bool + 'static,
    ) -> Self {
        Self {
            description: desc.into(),
            predicate: Box::new(predicate),
        }
    }
}

impl Matcher for PredicateMatcher {
    fn matches(&self, packet: &crafter::Packet, ctx: &PacketContext) -> bool {
        (self.predicate)(packet, ctx)
    }

    fn describe(&self) -> String {
        self.description.clone()
    }
}

/// Create a closure-backed matcher.
pub fn predicate(
    desc: impl Into<String>,
    predicate: impl Fn(&crafter::Packet, &PacketContext) -> bool + 'static,
) -> PredicateMatcher {
    PredicateMatcher::new(desc, predicate)
}

#[cfg(test)]
mod tests {
    use super::{Matcher, PredicateMatcher};
    use crate::PacketContext;

    #[test]
    fn predicate_matcher_matches_non_empty_summary() {
        let matcher = PredicateMatcher::new("packet has a summary", |packet, _ctx| {
            !packet.summary().is_empty()
        });
        let packet = crafter::Packet::decode_raw([0xde, 0xad, 0xbe, 0xef])
            .expect("raw packet should decode");
        let ctx = PacketContext::new();
        let boxed: Box<dyn Matcher> = Box::new(matcher);

        assert!(boxed.matches(&packet, &ctx));
        assert!(!boxed.describe().is_empty());
    }
}
