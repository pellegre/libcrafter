use std::net::Ipv4Addr;

use crate::{Matcher, PacketContext};

type AckPredicate = dyn Fn(u32, &PacketContext) -> bool;

struct TcpAckPredicate {
    description: String,
    predicate: Box<AckPredicate>,
}

/// Matcher for TCP segments from a specific peer connection.
///
/// The matcher checks the reversed TCP port pair, the remote IPv4 address, the
/// required TCP flag bits, and optionally the local IPv4 destination and ACK
/// number.
pub struct TcpSegmentMatcher {
    local_ipv4: Option<Ipv4Addr>,
    local_port: u16,
    remote_ipv4: Ipv4Addr,
    remote_port: u16,
    required_flags: u16,
    ack_predicate: Option<TcpAckPredicate>,
}

impl TcpSegmentMatcher {
    /// Create a matcher for a TCP segment from `remote_ipv4:remote_port` to the
    /// local port.
    pub fn new(
        local_port: u16,
        remote_port: u16,
        remote_ipv4: Ipv4Addr,
        required_flags: u16,
    ) -> Self {
        Self {
            local_ipv4: None,
            local_port,
            remote_ipv4,
            remote_port,
            required_flags,
            ack_predicate: None,
        }
    }

    /// Require the IPv4 destination address to match the local endpoint.
    pub fn local_ipv4(mut self, local_ipv4: Ipv4Addr) -> Self {
        self.local_ipv4 = Some(local_ipv4);
        self
    }

    /// Require an exact TCP acknowledgement number.
    pub fn ack_number(self, expected_ack: u32) -> Self {
        self.ack_where(format!("ack == 0x{expected_ack:08x}"), move |ack, _ctx| {
            ack == expected_ack
        })
    }

    /// Require the TCP acknowledgement number to equal `PacketContext`'s
    /// `tcp_snd_nxt` value.
    pub fn ack_matches_tcp_snd_nxt(self) -> Self {
        self.ack_where("ack == tcp_snd_nxt", |ack, ctx| {
            ctx.get_tcp_snd_nxt() == Some(ack)
        })
    }

    /// Require the TCP acknowledgement number to satisfy `predicate`.
    pub fn ack_where(
        mut self,
        description: impl Into<String>,
        predicate: impl Fn(u32, &PacketContext) -> bool + 'static,
    ) -> Self {
        self.ack_predicate = Some(TcpAckPredicate {
            description: description.into(),
            predicate: Box::new(predicate),
        });
        self
    }
}

impl Matcher for TcpSegmentMatcher {
    fn matches(&self, packet: &crafter::Packet, ctx: &PacketContext) -> bool {
        let Some(ipv4) = packet.layer::<crafter::Ipv4>() else {
            return false;
        };
        if ipv4.source() != self.remote_ipv4 {
            return false;
        }
        if let Some(local_ipv4) = self.local_ipv4 {
            if ipv4.destination() != local_ipv4 {
                return false;
            }
        }

        let Some(tcp) = packet.layer::<crafter::Tcp>() else {
            return false;
        };
        if tcp.source_port_value() != self.remote_port
            || tcp.destination_port_value() != self.local_port
        {
            return false;
        }
        if tcp.flags_value() & self.required_flags != self.required_flags {
            return false;
        }

        match &self.ack_predicate {
            Some(predicate) => {
                (predicate.predicate)(tcp.acknowledgment_number_value(), ctx)
            }
            None => true,
        }
    }

    fn describe(&self) -> String {
        let local = match self.local_ipv4 {
            Some(local_ipv4) => format!("{local_ipv4}:{}", self.local_port),
            None => format!("*:{}", self.local_port),
        };
        let mut description = format!(
            "tcp segment {}:{} -> {} flags include 0x{:03x}",
            self.remote_ipv4, self.remote_port, local, self.required_flags
        );

        if let Some(predicate) = &self.ack_predicate {
            description.push_str(" and ");
            description.push_str(&predicate.description);
        }

        description
    }
}

/// Create a matcher for a TCP segment from `remote_ipv4:remote_port` to
/// `local_port`.
pub fn tcp_segment(
    local_port: u16,
    remote_port: u16,
    remote_ipv4: Ipv4Addr,
    required_flags: u16,
) -> TcpSegmentMatcher {
    TcpSegmentMatcher::new(local_port, remote_port, remote_ipv4, required_flags)
}

/// Create a matcher for a TCP segment with the full reversed IPv4 four-tuple.
pub fn tcp_segment_for_ipv4(
    local_ipv4: Ipv4Addr,
    local_port: u16,
    remote_ipv4: Ipv4Addr,
    remote_port: u16,
    required_flags: u16,
) -> TcpSegmentMatcher {
    tcp_segment(local_port, remote_port, remote_ipv4, required_flags).local_ipv4(local_ipv4)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crafter::{NetworkLayer, Packet, TCP_FLAG_ACK, TCP_FLAG_SYN};

    use super::{tcp_segment_for_ipv4, TcpSegmentMatcher};
    use crate::{Matcher, PacketContext};

    const LOCAL_PORT: u16 = 49_152;
    const REMOTE_PORT: u16 = 443;
    const ACK_NUMBER: u32 = 0x0102_0304;

    fn local_ipv4() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn remote_ipv4() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    fn decoded_tcp_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        flags: u16,
        ack: u32,
    ) -> Packet {
        let packet = crafter::Ipv4::new().src(source).dst(destination)
            / crafter::Tcp::new()
                .sport(source_port)
                .dport(destination_port)
                .seq(0x1112_1314)
                .ack(ack)
                .flags(flags);
        let compiled = packet.compile().expect("tcp packet should compile");

        Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())
            .expect("tcp packet should decode")
    }

    fn syn_ack_matcher() -> TcpSegmentMatcher {
        tcp_segment_for_ipv4(
            local_ipv4(),
            LOCAL_PORT,
            remote_ipv4(),
            REMOTE_PORT,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
        )
    }

    #[test]
    fn tcp_segment_matcher_accepts_syn_ack_for_connection() {
        let matcher = syn_ack_matcher();
        let packet = decoded_tcp_packet(
            remote_ipv4(),
            local_ipv4(),
            REMOTE_PORT,
            LOCAL_PORT,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            ACK_NUMBER,
        );
        let context = PacketContext::new();

        assert!(matcher.matches(&packet, &context));
        assert!(matcher.describe().contains("flags include 0x012"));
    }

    #[test]
    fn tcp_segment_matcher_rejects_different_port() {
        let matcher = syn_ack_matcher();
        let wrong_port = decoded_tcp_packet(
            remote_ipv4(),
            local_ipv4(),
            REMOTE_PORT + 1,
            LOCAL_PORT,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            ACK_NUMBER,
        );
        let context = PacketContext::new();

        assert!(!matcher.matches(&wrong_port, &context));
    }

    #[test]
    fn tcp_segment_matcher_rejects_plain_ack_when_syn_ack_required() {
        let matcher = syn_ack_matcher();
        let plain_ack = decoded_tcp_packet(
            remote_ipv4(),
            local_ipv4(),
            REMOTE_PORT,
            LOCAL_PORT,
            TCP_FLAG_ACK,
            ACK_NUMBER,
        );
        let context = PacketContext::new();

        assert!(!matcher.matches(&plain_ack, &context));
    }

    #[test]
    fn tcp_segment_matcher_can_require_ack_number() {
        let matcher = syn_ack_matcher().ack_number(ACK_NUMBER);
        let wrong_ack_matcher = syn_ack_matcher().ack_number(ACK_NUMBER + 1);
        let packet = decoded_tcp_packet(
            remote_ipv4(),
            local_ipv4(),
            REMOTE_PORT,
            LOCAL_PORT,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            ACK_NUMBER,
        );
        let context = PacketContext::new();

        assert!(matcher.matches(&packet, &context));
        assert!(!wrong_ack_matcher.matches(&packet, &context));
    }

    #[test]
    fn tcp_segment_matcher_can_compare_ack_to_context_send_next() {
        let matcher = syn_ack_matcher().ack_matches_tcp_snd_nxt();
        let packet = decoded_tcp_packet(
            remote_ipv4(),
            local_ipv4(),
            REMOTE_PORT,
            LOCAL_PORT,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            ACK_NUMBER,
        );
        let mut context = PacketContext::new();

        assert!(!matcher.matches(&packet, &context));
        context.set_tcp_snd_nxt(ACK_NUMBER);
        assert!(matcher.matches(&packet, &context));
    }
}
