//! Packet capture sources for flow execution.
//!
//! A live pcap-backed source is added when the runner's live path is wired.
//! Keeping capture behind this trait lets the same conversation loop swap
//! between live packet capture and offline scripted packets.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::{FlowError, Result};

const PCAP_CAPTURE_POLL_INTERVAL: Duration = Duration::from_millis(1);

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

/// Live pcap-backed capture source.
pub struct PcapCaptureSource {
    sniffer: Option<crafter::Sniffer>,
    interface: String,
    filter: Option<String>,
}

impl PcapCaptureSource {
    /// Open a live pcap capture on `interface`.
    pub fn open(interface: &str, filter: Option<&str>, timeout: Duration) -> Result<Self> {
        let mut builder = crafter::PacketWire::pcap_interface(interface.to_owned())
            .timeout(timeout)
            .nonblock();
        if let Some(filter) = filter {
            builder = builder.filter(filter);
        }

        let source = builder
            .open()
            .and_then(crafter::PacketWire::source)
            .map_err(|err| {
                FlowError::Capture(format!(
                    "failed to open pcap capture on interface '{interface}': {err}"
                ))
            })?;

        Ok(Self {
            sniffer: Some(crafter::Sniffer::new(source).timeout(timeout)),
            interface: interface.to_owned(),
            filter: filter.map(str::to_owned),
        })
    }
}

impl CaptureSource for PcapCaptureSource {
    fn next_packet(&mut self, timeout: Duration) -> Result<Option<crafter::Packet>> {
        if timeout.is_zero() {
            return Ok(None);
        }

        let Some(sniffer) = self.sniffer.take() else {
            return Err(FlowError::Capture(
                "pcap capture source is not available".to_string(),
            ));
        };

        let deadline = Instant::now().checked_add(timeout);
        let mut sniffer = sniffer;
        let result = loop {
            let remaining =
                deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
            if remaining.is_some_and(|remaining| remaining.is_zero()) {
                break Ok(None);
            }

            sniffer = sniffer.timeout(remaining.unwrap_or(timeout));
            match sniffer.next_record() {
                Ok(Some(record)) => break Ok(Some(record.into_packet())),
                Ok(None) => {
                    let remaining =
                        deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
                    if remaining.is_some_and(|remaining| remaining.is_zero()) {
                        break Ok(None);
                    }
                    let sleep = remaining
                        .map(|remaining| remaining.min(PCAP_CAPTURE_POLL_INTERVAL))
                        .unwrap_or(PCAP_CAPTURE_POLL_INTERVAL);
                    std::thread::sleep(sleep);
                }
                Err(err) => {
                    break Err(FlowError::Capture(format!(
                        "pcap capture read failed on interface '{}': {err}",
                        self.interface
                    )));
                }
            }
        };
        self.sniffer = Some(sniffer);
        result
    }

    fn describe(&self) -> String {
        match self.filter.as_deref() {
            Some(filter) if !filter.is_empty() => {
                format!("pcap capture on {} filter={}", self.interface, filter)
            }
            _ => format!("pcap capture on {} filter=<none>", self.interface),
        }
    }
}

impl CaptureSource for Box<dyn CaptureSource> {
    fn next_packet(&mut self, timeout: Duration) -> Result<Option<crafter::Packet>> {
        self.as_mut().next_packet(timeout)
    }

    fn describe(&self) -> String {
        self.as_ref().describe()
    }
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
        format!(
            "memory capture source ({} queued packets)",
            self.packets.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        derive_capture_filter, derive_capture_filter_for_packets, CaptureSource,
        MemoryCaptureSource, PcapCaptureSource,
    };
    use crate::FlowError;
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
        let empty = source.next_packet(timeout).expect("empty receive succeeds");

        assert_eq!(compiled_bytes(&first), [0xde, 0xad]);
        assert_eq!(compiled_bytes(&second), [0xbe, 0xef, 0x00]);
        assert!(empty.is_none());
    }

    #[test]
    fn pcap_capture_source_open_missing_interface_returns_capture_error() {
        let result =
            PcapCaptureSource::open("nonexistent-iface-zzz", None, Duration::from_millis(10));

        assert!(matches!(result, Err(FlowError::Capture(_))));
    }

    #[test]
    fn pcap_capture_source_can_be_boxed_as_capture_source() {
        let result: Result<Box<dyn CaptureSource>, FlowError> =
            PcapCaptureSource::open("nonexistent-iface-zzz", None, Duration::from_millis(10))
                .map(|source| Box::new(source) as Box<dyn CaptureSource>);

        assert!(matches!(result, Err(FlowError::Capture(_))));
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
