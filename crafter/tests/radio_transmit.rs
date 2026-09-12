#![cfg(feature = "radio")]

use crafter::prelude::*;

fn packet() -> Packet {
    Dot11::data()
        .addr1(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 1]))
        .addr2(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 2]))
        .addr3(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 3]))
        / Raw::from("offline transmit")
}

#[test]
fn writer_compiles_packet_appends_fcs_and_reports_cs8() {
    let record = PacketRecord::new(packet());
    let compiled = record.packet().compile().unwrap();
    let mut writer = RadioPacketWriter::new(
        LegacyWifiTxConfig::ofdm(LegacyOfdmRate::Mbps6),
        MemoryIqSink::new(),
    );
    let report = writer.write_record(&record).unwrap();
    let tx = writer.last_transmission().unwrap();
    assert_eq!(tx.mac_bytes(), compiled.as_bytes());
    assert_eq!(
        &tx.psdu_bytes()[..compiled.as_bytes().len()],
        compiled.as_bytes()
    );
    assert_eq!(tx.psdu_bytes().len(), compiled.as_bytes().len() + 4);
    assert_eq!(report.bytes_requested(), tx.cs8().len());
    assert_eq!(report.bytes_written(), tx.cs8().len());
    assert!(report.is_dry_run());
}

#[test]
fn explicit_fcs_is_preserved() {
    let writer = RadioPacketWriter::new(
        LegacyWifiTxConfig::dsss_cck(LegacyDsssCckRate::Mbps11, DsssPreamble::Short)
            .with_fcs(WifiFcsPolicy::Explicit([1, 2, 3, 4])),
        MemoryIqSink::new(),
    );
    let tx = writer.encode_record(&PacketRecord::new(packet())).unwrap();
    assert_eq!(&tx.psdu_bytes()[tx.psdu_bytes().len() - 4..], &[1, 2, 3, 4]);
}

#[test]
fn all_fifteen_decoder_modes_encode_through_packet_writer() {
    let mut configs = LegacyOfdmRate::ALL
        .into_iter()
        .map(LegacyWifiTxConfig::ofdm)
        .collect::<Vec<_>>();
    for (rate, preamble) in [
        (LegacyDsssCckRate::Mbps1, DsssPreamble::Long),
        (LegacyDsssCckRate::Mbps2, DsssPreamble::Long),
        (LegacyDsssCckRate::Mbps2, DsssPreamble::Short),
        (LegacyDsssCckRate::Mbps5_5, DsssPreamble::Long),
        (LegacyDsssCckRate::Mbps5_5, DsssPreamble::Short),
        (LegacyDsssCckRate::Mbps11, DsssPreamble::Long),
        (LegacyDsssCckRate::Mbps11, DsssPreamble::Short),
    ] {
        configs.push(LegacyWifiTxConfig::dsss_cck(rate, preamble));
    }
    assert_eq!(configs.len(), 15);
    for config in configs {
        let writer = RadioPacketWriter::new(config, MemoryIqSink::new());
        assert!(!writer
            .encode_record(&PacketRecord::new(packet()))
            .unwrap()
            .cs8()
            .is_empty());
    }
}

#[test]
fn transmitter_accepts_radio_writer_and_non_dot11_is_rejected() {
    let mut transmitter = Transmitter::new(RadioPacketWriter::new(
        LegacyWifiTxConfig::ofdm(LegacyOfdmRate::Mbps24),
        MemoryIqSink::new(),
    ));
    let reports = transmitter.send(packet()).unwrap();
    assert_eq!(reports.len(), 1);
    assert!(transmitter.send(Raw::from("not wifi")).is_err());
}

#[test]
fn hackrf_offline_preparation_requires_no_device() {
    let writer = RadioPacketWriter::new(
        LegacyWifiTxConfig::ofdm(LegacyOfdmRate::Mbps54),
        MemoryIqSink::new(),
    );
    let transmission = writer.encode_record(&PacketRecord::new(packet())).unwrap();
    assert_eq!(transmission.sample_count() * 2, transmission.cs8().len());
}
