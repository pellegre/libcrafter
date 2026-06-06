//! Packet source contracts.

use std::collections::VecDeque;

use crate::IntoPacket;

use super::record::{BackendKind, PacketOrigin, PacketRecord};
use super::Result;

/// Packet-shaped input for sniffers and inbound transform pipelines.
///
/// Implementers may read from pcap files, live interfaces, provider endpoints,
/// radio backends, or in-memory fixtures. Source identity is intentionally not
/// part of the required contract; record metadata carries origin details when a
/// backend has them.
pub trait PacketSource {
    /// Return the next available packet record, or `None` when the source is
    /// exhausted.
    fn next_record(&mut self) -> Result<Option<PacketRecord>>;
}

/// In-memory packet source for deterministic tests and synthetic pipelines.
#[derive(Debug, Clone, Default)]
pub struct VecPacketSource {
    records: VecDeque<PacketRecord>,
}

impl VecPacketSource {
    /// Create a source from prebuilt packet records.
    ///
    /// Existing record metadata is preserved exactly.
    pub fn new(records: impl IntoIterator<Item = PacketRecord>) -> Self {
        Self {
            records: records.into_iter().collect(),
        }
    }

    /// Create an empty source.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create a source from packets tagged as generated in-memory records.
    pub fn from_packets<I, P>(packets: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: IntoPacket,
    {
        Self::new(packets.into_iter().map(memory_record))
    }

    /// Number of records remaining in the source.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the source has no records remaining.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Append a prebuilt packet record.
    ///
    /// Existing record metadata is preserved exactly.
    pub fn push_record(&mut self, record: PacketRecord) -> &mut Self {
        self.records.push_back(record);
        self
    }

    /// Append a packet tagged as a generated in-memory record.
    pub fn push_packet(&mut self, packet: impl IntoPacket) -> &mut Self {
        self.records.push_back(memory_record(packet));
        self
    }

    /// Consume the source and return the remaining records in delivery order.
    pub fn into_records(self) -> Vec<PacketRecord> {
        self.records.into_iter().collect()
    }
}

impl PacketSource for VecPacketSource {
    fn next_record(&mut self) -> Result<Option<PacketRecord>> {
        Ok(self.records.pop_front())
    }
}

impl<T> PacketSource for Box<T>
where
    T: PacketSource + ?Sized,
{
    fn next_record(&mut self) -> Result<Option<PacketRecord>> {
        (**self).next_record()
    }
}

fn memory_record(packet: impl IntoPacket) -> PacketRecord {
    PacketRecord::new(packet)
        .with_origin(PacketOrigin::Generated)
        .with_backend(BackendKind::Memory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Raw;

    #[test]
    fn vec_packet_source_yields_records_in_order() {
        let records = vec![
            PacketRecord::new(Raw::from("first")).with_origin(PacketOrigin::Replayed),
            PacketRecord::new(Raw::from("second")),
        ];
        let mut source = VecPacketSource::new(records);

        let first = source.next_record().unwrap().unwrap();
        assert_eq!(first.packet().summary(), "Raw(len=5)");
        assert_eq!(first.metadata().origin(), PacketOrigin::Replayed);

        let second = source.next_record().unwrap().unwrap();
        assert_eq!(second.packet().summary(), "Raw(len=6)");

        assert!(source.next_record().unwrap().is_none());
        assert!(source.is_empty());
    }

    #[test]
    fn vec_packet_source_can_build_memory_records_from_packets() {
        let mut source = VecPacketSource::from_packets([Raw::from("one"), Raw::from("two")]);

        assert_eq!(source.len(), 2);

        let record = source.next_record().unwrap().unwrap();
        assert_eq!(record.packet().summary(), "Raw(len=3)");
        assert_eq!(record.metadata().origin(), PacketOrigin::Generated);
        assert_eq!(record.metadata().backend(), &BackendKind::Memory);
    }

    #[test]
    fn vec_packet_source_supports_appending_records_and_packets() {
        let mut source = VecPacketSource::empty();
        source
            .push_record(
                PacketRecord::new(Raw::from("record"))
                    .with_backend(BackendKind::Other("fixture".to_string())),
            )
            .push_packet(Raw::from("packet"));

        assert_eq!(source.len(), 2);

        let remaining = source.into_records();
        assert_eq!(
            remaining[0].metadata().backend(),
            &BackendKind::Other("fixture".to_string())
        );
        assert_eq!(remaining[1].metadata().backend(), &BackendKind::Memory);
    }

    #[test]
    fn packet_source_is_object_safe() {
        let mut source = VecPacketSource::from_packets([Raw::from("payload")]);
        let source: &mut dyn PacketSource = &mut source;

        let record = source.next_record().unwrap().unwrap();
        assert_eq!(record.packet().summary(), "Raw(len=7)");
        assert!(source.next_record().unwrap().is_none());
    }
}
