use crate::{Matcher, PacketContext};

/// Matcher that delegates reply recognition to `crafter`.
pub struct ReplyMatcher {
    request: crafter::Packet,
}

impl ReplyMatcher {
    /// Create a matcher for replies to `request`.
    pub fn to(request: crafter::Packet) -> Self {
        Self { request }
    }
}

impl Matcher for ReplyMatcher {
    fn matches(&self, packet: &crafter::Packet, _ctx: &PacketContext) -> bool {
        crafter::reply_matches(&self.request, packet)
    }

    fn describe(&self) -> String {
        format!("reply to {}", self.request.summary())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::{Matcher, PacketContext};

    use super::ReplyMatcher;

    fn echo_request() -> crafter::Packet {
        crafter::Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / crafter::Icmpv4::echo_request().id(7).seq(9)
            / crafter::Raw::from("hello")
    }

    #[test]
    fn reply_matcher_matches_correct_reply_only() {
        let request = echo_request();
        let reply = crafter::Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 20))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / crafter::Icmpv4::echo_reply().id(7).seq(9)
            / crafter::Raw::from("hello");
        let unrelated = crafter::Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 20))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / crafter::Icmpv4::echo_reply().id(7).seq(10)
            / crafter::Raw::from("hello");
        let request_summary = request.summary();
        let matcher = ReplyMatcher::to(request);
        let ctx = PacketContext::new();

        assert!(matcher.matches(&reply, &ctx));
        assert!(!matcher.matches(&unrelated, &ctx));
        assert!(matcher.describe().contains(&request_summary));
    }
}
