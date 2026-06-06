use std::fmt;
use std::path::Path;
use std::time::Duration;

use pcap as pcap_crate;

use super::{PcapError, PcapLinkType, PcapRecord, PcapTimestamp, Result};

pub(crate) struct LibpcapOfflineCapture {
    capture: pcap_crate::Capture<pcap_crate::Offline>,
    link_type: PcapLinkType,
}

impl fmt::Debug for LibpcapOfflineCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LibpcapOfflineCapture")
            .field("link_type", &self.link_type)
            .finish_non_exhaustive()
    }
}

impl LibpcapOfflineCapture {
    pub(crate) fn open(path: impl AsRef<Path>, filter: Option<&str>) -> Result<Self> {
        let mut capture = pcap_crate::Capture::from_file(path)?;
        if let Some(filter) = filter.filter(|filter| !filter.trim().is_empty()) {
            capture.filter(filter, true)?;
        }
        let link_type = pcap_link_type(capture.get_datalink());
        Ok(Self { capture, link_type })
    }

    pub(crate) fn next_record(&mut self) -> Result<Option<PcapRecord>> {
        next_libpcap_record(&mut self.capture, self.link_type)
    }
}

pub(super) struct LibpcapCapture {
    capture: pcap_crate::Capture<pcap_crate::Active>,
    link_type: PcapLinkType,
}

impl fmt::Debug for LibpcapCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LibpcapCapture")
            .field("link_type", &self.link_type)
            .finish_non_exhaustive()
    }
}

impl LibpcapCapture {
    pub(super) fn open(
        iface: &str,
        filter: Option<&str>,
        timeout: Option<Duration>,
        snaplen: u32,
        promisc: bool,
        immediate: bool,
        nonblocking: bool,
    ) -> Result<Self> {
        if iface.trim().is_empty() {
            return Err(PcapError::LiveCaptureUnavailable(
                "interface name must not be empty",
            ));
        }

        let mut capture = pcap_crate::Capture::from_device(iface)?
            .promisc(promisc)
            .snaplen(snaplen_to_i32(snaplen))
            .timeout(timeout_to_millis(timeout))
            .immediate_mode(immediate)
            .open()?;

        if nonblocking {
            capture = capture.setnonblock()?;
        }

        if let Some(filter) = filter.filter(|filter| !filter.trim().is_empty()) {
            capture.filter(filter, true)?;
        }

        let link_type = pcap_link_type(capture.get_datalink());
        Ok(Self { capture, link_type })
    }

    pub(super) fn next_record(&mut self) -> Result<Option<PcapRecord>> {
        next_libpcap_record(&mut self.capture, self.link_type)
    }
}

fn next_libpcap_record<T>(
    capture: &mut pcap_crate::Capture<T>,
    link_type: PcapLinkType,
) -> Result<Option<PcapRecord>>
where
    T: pcap_crate::Activated,
{
    match capture.next_packet() {
        Ok(packet) => {
            let timestamp = libpcap_timestamp(packet.header)?;
            PcapRecord::new(
                timestamp,
                packet.header.len,
                packet.data.to_vec(),
                link_type,
            )
            .map(Some)
        }
        Err(pcap_crate::Error::TimeoutExpired | pcap_crate::Error::NoMorePackets) => Ok(None),
        Err(err) => Err(PcapError::Libpcap(err)),
    }
}

fn libpcap_timestamp(header: &pcap_crate::PacketHeader) -> Result<PcapTimestamp> {
    let seconds = u64::try_from(header.ts.tv_sec)
        .map_err(|_| PcapError::InvalidRecord("timestamp seconds must be non-negative"))?;
    let micros = u32::try_from(header.ts.tv_usec)
        .map_err(|_| PcapError::InvalidRecord("timestamp fractional field is out of range"))?;
    PcapTimestamp::micros(seconds, micros)
}

fn pcap_link_type(link_type: pcap_crate::Linktype) -> PcapLinkType {
    u32::try_from(link_type.0)
        .map(PcapLinkType::from_datalink)
        .unwrap_or(PcapLinkType::Unknown(link_type.0 as u32))
}

fn timeout_to_millis(timeout: Option<Duration>) -> i32 {
    timeout
        .map(|timeout| timeout.as_millis().clamp(1, i32::MAX as u128) as i32)
        .unwrap_or(0)
}

fn snaplen_to_i32(snaplen: u32) -> i32 {
    snaplen.min(i32::MAX as u32) as i32
}
