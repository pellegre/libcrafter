//! Packet capture sources for flow execution.
//!
//! A live pcap-backed source is added when the runner's live path is wired.
//! Keeping capture behind this trait lets the same conversation loop swap
//! between live packet capture and offline scripted packets.

use std::collections::VecDeque;
use std::time::Duration;

use crate::Result;

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
    use super::{CaptureSource, MemoryCaptureSource};
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
}
