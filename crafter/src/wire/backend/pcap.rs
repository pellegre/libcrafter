//! Pcap packet wire backend adapters.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use crate::pcap::{LibpcapOfflineCapture, PcapReader, PcapRecord};

use super::super::record::{BackendKind, PacketOrigin, PacketRecord};
use super::super::source::PacketSource;
use super::super::Result;

/// Offline pcap packet source.
#[derive(Debug)]
pub struct OfflinePcapSource {
    path: PathBuf,
    filter: Option<String>,
    inner: OfflinePcapSourceInner,
}

#[derive(Debug)]
enum OfflinePcapSourceInner {
    Reader(PcapReader<BufReader<File>>),
    Filtered(LibpcapOfflineCapture),
}

impl OfflinePcapSource {
    /// Open an offline pcap file source with no filter.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_optional_filter(path, None)
    }

    /// Open an offline pcap file source with a libpcap BPF filter.
    pub fn open_filtered(path: impl AsRef<Path>, filter: impl AsRef<str>) -> Result<Self> {
        Self::open_with_optional_filter(path, Some(filter.as_ref()))
    }

    pub(crate) fn open_with_optional_filter(
        path: impl AsRef<Path>,
        filter: Option<&str>,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let filter = filter
            .map(str::trim)
            .filter(|filter| !filter.is_empty())
            .map(ToOwned::to_owned);

        let inner = if let Some(filter) = filter.as_deref() {
            OfflinePcapSourceInner::Filtered(LibpcapOfflineCapture::open(&path, Some(filter))?)
        } else {
            OfflinePcapSourceInner::Reader(PcapReader::open(&path)?)
        };

        Ok(Self {
            path,
            filter,
            inner,
        })
    }

    /// File backing this offline source.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Configured BPF filter, if this source is filtered.
    pub fn filter(&self) -> Option<&str> {
        self.filter.as_deref()
    }

    fn next_pcap_record(&mut self) -> Result<Option<PcapRecord>> {
        match &mut self.inner {
            OfflinePcapSourceInner::Reader(reader) => reader.next_record().map_err(Into::into),
            OfflinePcapSourceInner::Filtered(capture) => capture.next_record().map_err(Into::into),
        }
    }
}

impl PacketSource for OfflinePcapSource {
    fn next_record(&mut self) -> Result<Option<PacketRecord>> {
        self.next_pcap_record()?
            .map(|record| pcap_record_to_packet_record(self.path(), record))
            .transpose()
    }
}

fn pcap_record_to_packet_record(path: &Path, record: PcapRecord) -> Result<PacketRecord> {
    let packet = record.decode()?;
    Ok(PacketRecord::new(packet)
        .with_origin(PacketOrigin::Captured)
        .with_backend(BackendKind::PcapFile)
        .with_file(path.to_path_buf())
        .with_pcap_metadata(
            record.timestamp(),
            record.original_len(),
            record.captured_len(),
            record.pcap_link_type(),
        )
        .with_captured_bytes(record.data().to_vec()))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::pcap::{PcapLinkType, PcapTimestamp, PcapWriter};
    use crate::{Ethernet, Ipv4, LinkType, MacAddr, Packet, PacketWire, Raw, Tcp, WireError};

    static NEXT_TEMP_PCAP: AtomicUsize = AtomicUsize::new(0);

    struct TempPcap {
        path: PathBuf,
    }

    impl TempPcap {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempPcap {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn temp_pcap_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "wire-pcap-{name}-{}-{}.pcap",
            std::process::id(),
            NEXT_TEMP_PCAP.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn write_temp_pcap(
        name: &str,
        packets: impl IntoIterator<Item = (Packet, PcapTimestamp)>,
    ) -> TempPcap {
        let path = temp_pcap_path(name);
        {
            let mut writer = PcapWriter::create(&path, LinkType::Ethernet).unwrap();
            for (packet, timestamp) in packets {
                writer
                    .write_packet_with_timestamp(&packet, timestamp)
                    .unwrap();
            }
            writer.flush().unwrap();
        }
        TempPcap { path }
    }

    fn tcp_packet(source_port: u16, destination_port: u16) -> Packet {
        Ethernet::new()
            .src(MacAddr::new([0x02, 0, 0, 0, 0, 1]))
            .dst(MacAddr::BROADCAST)
            / Ipv4::new()
                .src_str("192.0.2.10")
                .unwrap()
                .dst_str("198.51.100.20")
                .unwrap()
            / Tcp::new().sport(source_port).dport(destination_port)
            / Raw::from("payload")
    }

    #[test]
    fn offline_source_reads_records_with_pcap_metadata() {
        let timestamp = PcapTimestamp::micros(123, 456).unwrap();
        let packet = tcp_packet(40000, 443);
        let captured = packet.compile().unwrap().into_bytes();
        let temp = write_temp_pcap("metadata", [(packet, timestamp)]);
        let mut source = OfflinePcapSource::open(temp.path()).unwrap();

        let record = source.next_record().unwrap().unwrap();

        assert!(record.packet().layer::<Tcp>().is_some());
        assert_eq!(record.metadata().origin(), PacketOrigin::Captured);
        assert_eq!(record.metadata().backend(), &BackendKind::PcapFile);
        assert_eq!(record.metadata().file(), Some(temp.path()));
        assert_eq!(record.metadata().timestamp(), Some(timestamp));
        assert_eq!(
            record.metadata().original_len(),
            Some(captured.len() as u32)
        );
        assert_eq!(
            record.metadata().captured_len(),
            Some(captured.len() as u32)
        );
        assert_eq!(
            record.metadata().captured_bytes(),
            Some(captured.as_slice())
        );
        assert_eq!(record.metadata().link_type(), Some(LinkType::Ethernet));
        assert_eq!(
            record.metadata().pcap_link_type(),
            Some(PcapLinkType::Ethernet)
        );
        assert!(source.next_record().unwrap().is_none());
    }

    #[test]
    fn offline_source_filtered_uses_libpcap_bpf() {
        let https = tcp_packet(12345, 443);
        let http = tcp_packet(12345, 80);
        let temp = write_temp_pcap(
            "filtered",
            [
                (https, PcapTimestamp::micros(1, 0).unwrap()),
                (http, PcapTimestamp::micros(2, 0).unwrap()),
            ],
        );
        let mut source =
            OfflinePcapSource::open_filtered(temp.path(), "tcp and dst port 443").unwrap();

        assert_eq!(source.filter(), Some("tcp and dst port 443"));

        let record = source.next_record().unwrap().unwrap();
        assert_eq!(
            record
                .packet()
                .layer::<Tcp>()
                .unwrap()
                .destination_port_value(),
            443
        );
        assert!(source.next_record().unwrap().is_none());
    }

    #[test]
    fn packet_wire_pcap_file_opens_offline_source() {
        let temp = write_temp_pcap(
            "packet-wire",
            [(tcp_packet(40000, 80), PcapTimestamp::zero())],
        );
        let wire = PacketWire::pcap_file(temp.path()).open().unwrap();

        assert!(wire.has_source());
        assert!(!wire.has_writer());

        let mut source = wire.source().unwrap();
        let record = source.next_record().unwrap().unwrap();
        assert_eq!(
            record
                .packet()
                .layer::<Tcp>()
                .unwrap()
                .destination_port_value(),
            80
        );
    }

    #[test]
    fn packet_wire_pcap_file_filter_opens_filtered_source() {
        let temp = write_temp_pcap(
            "packet-wire-filtered",
            [
                (tcp_packet(11111, 443), PcapTimestamp::zero()),
                (tcp_packet(11111, 80), PcapTimestamp::zero()),
            ],
        );
        let mut source = PacketWire::pcap_file(temp.path())
            .filter("tcp and dst port 80")
            .open()
            .unwrap()
            .source()
            .unwrap();

        let record = source.next_record().unwrap().unwrap();
        assert_eq!(
            record
                .packet()
                .layer::<Tcp>()
                .unwrap()
                .destination_port_value(),
            80
        );
        assert!(source.next_record().unwrap().is_none());
    }

    #[test]
    fn packet_wire_pcap_file_open_reports_missing_file() {
        let path = temp_pcap_path("missing");
        let err = PacketWire::pcap_file(&path).open().unwrap_err();

        match err {
            WireError::Pcap(_) => {}
            other => panic!("expected pcap error for missing file, got {other:?}"),
        }
    }
}
