//! Persistent send and receive position for one flow run.

use std::time::{Duration, Instant};

use crafter::net::{PacketSender, SendPlan, SendReport};

use crate::{
    Binding, CaptureSource, FlowError, Matcher, MemoryCaptureSource, PacketContext, Result,
};

/// A single flow execution position with one send half and one capture source.
pub struct Conversation {
    binding: Binding,
    sender: Option<PacketSender>,
    source: Box<dyn CaptureSource>,
    sent_count: usize,
    received_count: usize,
}

impl Conversation {
    /// Open a conversation for the binding using an empty offline capture source.
    pub fn open(binding: &Binding) -> Result<Self> {
        Self::open_with_source(binding, MemoryCaptureSource::default())
    }

    /// Open a conversation for the binding using the provided capture source.
    pub fn open_with_source<S>(binding: &Binding, source: S) -> Result<Self>
    where
        S: CaptureSource + 'static,
    {
        let sender = if binding.is_live() {
            Some(
                PacketSender::open(binding.send_options())
                    .map_err(|error| FlowError::Send(error.to_string()))?,
            )
        } else {
            None
        };

        Ok(Self {
            binding: binding.clone(),
            sender,
            source: Box::new(source),
            sent_count: 0,
            received_count: 0,
        })
    }

    /// Returns true when this conversation is offline and holds no live sender.
    pub fn is_dry_run(&self) -> bool {
        self.binding.is_dry_run()
    }

    /// Borrow the binding used to open this conversation.
    pub const fn binding(&self) -> &Binding {
        &self.binding
    }

    /// Number of packets successfully sent or planned by this conversation.
    pub const fn sent_count(&self) -> usize {
        self.sent_count
    }

    /// Number of packets received from this conversation's persistent capture source.
    pub const fn received_count(&self) -> usize {
        self.received_count
    }

    /// Send or plan one packet through this conversation's persistent send half.
    pub fn send(&mut self, packet: &crafter::Packet) -> Result<SendReport> {
        let report = if self.binding.is_dry_run() {
            let plan = SendPlan::from_packet(packet, self.binding.send_options())
                .map_err(|error| FlowError::Send(error.to_string()))?;
            let len = plan.len();
            SendReport::new(plan, len, true)
        } else {
            self.sender
                .as_mut()
                .ok_or_else(|| FlowError::Send("live conversation has no packet sender".into()))?
                .send(packet)
                .map_err(|error| FlowError::Send(error.to_string()))?
        };

        self.sent_count += 1;
        Ok(report)
    }

    /// Receive packets from the persistent capture source until one matches or timeout elapses.
    pub fn recv_matching(
        &mut self,
        matcher: &dyn Matcher,
        ctx: &PacketContext,
        timeout: Duration,
    ) -> Result<Option<crafter::Packet>> {
        let started = Instant::now();

        loop {
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                return Ok(None);
            }

            let remaining = timeout.saturating_sub(elapsed);
            let Some(packet) = self.source.next_packet(remaining)? else {
                return Ok(None);
            };

            self.received_count += 1;
            if matcher.matches(&packet, ctx) {
                return Ok(Some(packet));
            }
        }
    }

    /// Return an inspectable one-line description of this conversation.
    pub fn describe(&self) -> String {
        let sender = if self.sender.is_some() {
            "open sender"
        } else {
            "no sender"
        };

        format!(
            "Conversation({:?}, {:?}, {:?}, {}, {})",
            self.binding.mode(),
            self.binding.target(),
            self.binding.send_class(),
            sender,
            self.source.describe()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Conversation;
    use crate::{Binding, MemoryCaptureSource, PacketContext, PredicateMatcher};
    use crafter::{Dhcpv4, Ipv4, MacAddr, Udp};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn raw_packet(bytes: impl AsRef<[u8]>) -> crafter::Packet {
        crafter::Packet::decode_raw(bytes).expect("raw packet decodes")
    }

    fn compiled_bytes(packet: &crafter::Packet) -> Vec<u8> {
        packet.compile().expect("packet compiles").as_ref().to_vec()
    }

    fn dhcp_discover_packet() -> crafter::Packet {
        let mac = MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x25]);
        Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
            / Udp::dhcpv4_client()
            / Dhcpv4::discover(mac).xid(0x2500_0001)
    }

    #[test]
    fn conversation_open_default_is_dry_run_without_sender() {
        let binding = Binding::default();
        let conversation = Conversation::open(&binding).expect("dry-run conversation opens");

        assert!(conversation.is_dry_run());
        assert_eq!(conversation.binding(), &binding);
        assert!(conversation.sender.is_none());
        assert_eq!(conversation.sent_count(), 0);
        assert_eq!(conversation.received_count(), 0);
        assert!(conversation.describe().contains("DryRun"));
        assert!(conversation.describe().contains("no sender"));
    }

    #[test]
    fn conversation_open_with_source_accepts_memory_capture_source() {
        let binding = Binding::default();
        let packet = raw_packet([0xde, 0xad]);
        let mut conversation =
            Conversation::open_with_source(&binding, MemoryCaptureSource::new(vec![packet]))
                .expect("conversation opens with injected source");

        assert!(conversation.is_dry_run());
        assert!(conversation.sender.is_none());
        assert!(conversation.describe().contains("memory capture source"));
        assert!(conversation
            .source
            .next_packet(Duration::from_millis(1))
            .expect("capture succeeds")
            .is_some());
    }

    #[test]
    fn conversation_send_default_dry_run_reports_without_sender_and_counts_packet() {
        let binding = Binding::default();
        let mut conversation = Conversation::open(&binding).expect("dry-run conversation opens");
        let packet = dhcp_discover_packet();

        assert!(conversation.sender.is_none());
        assert_eq!(conversation.sent_count(), 0);

        let report = conversation
            .send(&packet)
            .expect("dry-run conversation send succeeds");

        assert!(report.is_dry_run());
        assert_eq!(report.plan().interface(), "flow0");
        assert_eq!(report.bytes_sent(), report.plan().len());
        assert!(report.bytes_sent() > 0);
        assert!(conversation.sender.is_none());
        assert_eq!(conversation.sent_count(), 1);
    }

    #[test]
    fn conversation_recv_matching_skips_non_matching_packets_and_counts_received() {
        let binding = Binding::default();
        let first = raw_packet([0xde, 0xad]);
        let second = raw_packet([0xbe, 0xef, 0x00]);
        let expected = compiled_bytes(&second);
        let expected_for_match = expected.clone();
        let matcher = PredicateMatcher::new("expected raw bytes", move |packet, _ctx| {
            packet
                .compile()
                .map(|bytes| bytes.as_ref() == expected_for_match.as_slice())
                .unwrap_or(false)
        });
        let ctx = PacketContext::new();
        let mut conversation =
            Conversation::open_with_source(&binding, MemoryCaptureSource::new(vec![first, second]))
                .expect("conversation opens with injected source");

        let received = conversation
            .recv_matching(&matcher, &ctx, Duration::from_secs(1))
            .expect("receive succeeds")
            .expect("matching packet is returned");

        assert_eq!(compiled_bytes(&received), expected);
        assert_eq!(conversation.received_count(), 2);
    }

    #[test]
    fn conversation_recv_matching_returns_none_when_no_packet_matches() {
        let binding = Binding::default();
        let packet = raw_packet([0xde, 0xad]);
        let matcher = PredicateMatcher::new("never matches", |_packet, _ctx| false);
        let ctx = PacketContext::new();
        let mut conversation =
            Conversation::open_with_source(&binding, MemoryCaptureSource::new(vec![packet]))
                .expect("conversation opens with injected source");

        let received = conversation
            .recv_matching(&matcher, &ctx, Duration::from_secs(1))
            .expect("receive succeeds");

        assert!(received.is_none());
        assert_eq!(conversation.received_count(), 1);
    }
}
