//! Packet capture sources for flow execution.
//!
//! A live pcap-backed source is added when the runner's live path is wired.
//! Keeping capture behind this trait lets the same conversation loop swap
//! between live packet capture and offline scripted packets.

use std::collections::VecDeque;
use std::time::Duration;

use crate::Result;

/// Derive an advisory BPF capture filter for likely replies to a seed request packet.
///
/// Flow dry-runs can report this filter for inspection. Once live pcap capture
/// is wired, the same derived filter is expected to be applied to the live
/// capture source. Unsupported packet shapes return an empty string.
pub fn derive_capture_filter(packet: &crafter::Packet) -> String {
    crafter::net::reply_filter(packet).unwrap_or_default()
}

/// Derive an advisory BPF capture filter for likely replies to seed request packets.
///
/// Flow dry-runs can report this filter for inspection. Once live pcap capture
/// is wired, the same derived filter is expected to be applied to the live
/// capture source. Unsupported packet shapes are skipped; if no filter can be
/// derived, this returns an empty string.
pub fn derive_capture_filter_for_packets(packets: &[crafter::Packet]) -> String {
    crafter::net::BatchSendRecv::new()
        .effective_filter(packets)
        .unwrap_or_default()
}

/// Source of packets received while a flow is running.
pub trait CaptureSource {
    /// Return the next received packet, or `Ok(None)` when `timeout` elapses.
    fn next_packet(&mut self, timeout: Duration) -> Result<Option<crafter::Packet>>;

    /// Return a human-readable description for reports and diagnostics.
    fn describe(&self) -> String;
}

/// In-memory capture source for offline tests and dry-run conversations.
#[derive(Debug, Clone, Default)]
pub struct MemoryCaptureSource {
    packets: VecDeque<crafter::Packet>,
}

impl MemoryCaptureSource {
    /// Create a memory source seeded with packets that will be yielded in order.
    pub fn new(packets: Vec<crafter::Packet>) -> Self {
        Self {
            packets: packets.into_iter().collect(),
        }
    }

    /// Queue one packet after any packets already waiting.
    pub fn push(&mut self, packet: crafter::Packet) -> &mut Self {
        self.packets.push_back(packet);
        self
    }
}

impl From<Vec<crafter::Packet>> for MemoryCaptureSource {
    fn from(packets: Vec<crafter::Packet>) -> Self {
        Self::new(packets)
    }
}

impl CaptureSource for MemoryCaptureSource {
    fn next_packet(&mut self, _timeout: Duration) -> Result<Option<crafter::Packet>> {
        Ok(self.packets.pop_front())
    }

    fn describe(&self) -> String {
        format!("memory capture source ({} queued packets)", self.packets.len())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        derive_capture_filter, derive_capture_filter_for_packets, CaptureSource,
        MemoryCaptureSource,
    };
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn raw_packet(bytes: impl AsRef<[u8]>) -> crafter::Packet {
        crafter::Packet::decode_raw(bytes).expect("raw packet decodes")
    }

    fn compiled_bytes(packet: &crafter::Packet) -> Vec<u8> {
        packet.compile().expect("packet compiles").as_ref().to_vec()
    }

    #[test]
    fn memory_capture_source_yields_seeded_packets_in_order_then_none() {
        let first = raw_packet([0xde, 0xad]);
        let second = raw_packet([0xbe, 0xef, 0x00]);
        let mut source = MemoryCaptureSource::new(vec![first]);
        source.push(second);

        let timeout = Duration::from_millis(1);
        let first = source
            .next_packet(timeout)
            .expect("first receive succeeds")
            .expect("first packet is queued");
        let second = source
            .next_packet(timeout)
            .expect("second receive succeeds")
            .expect("second packet is queued");
        let empty = source
            .next_packet(timeout)
            .expect("empty receive succeeds");

        assert_eq!(compiled_bytes(&first), [0xde, 0xad]);
        assert_eq!(compiled_bytes(&second), [0xbe, 0xef, 0x00]);
        assert!(empty.is_none());
    }

    #[test]
    fn derive_capture_filter_for_ipv4_udp_dns_request_uses_reply_filter() {
        let request = crafter::Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 53))
            / crafter::Udp::new().sport(53000).dport(53)
            / crafter::Dns::a_query("example.com").id(0x1234);

        let filter = derive_capture_filter(&request);

        assert!(!filter.is_empty());
        assert!(filter.contains("udp"), "filter was {filter:?}");
        assert!(filter.contains("src port 53"), "filter was {filter:?}");
    }

    #[test]
    fn derive_capture_filter_for_packets_skips_unsupported_packets() {
        let unsupported = raw_packet([0xde, 0xad]);

        assert_eq!(derive_capture_filter_for_packets(&[unsupported]), "");
    }
}
