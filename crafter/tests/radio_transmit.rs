#![cfg(feature = "radio")]

use crafter::prelude::*;
use crafter::radio::{FrameIntegrity, IqChunk, IqEvent, IqPosition, PhyDecoder, RxConfig};
use std::time::Duration;

fn packet() -> Packet {
    Dot11::data()
        .addr1(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 1]))
        .addr2(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 2]))
        .addr3(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 3]))
        / Raw::from("offline transmit")
}

#[test]
fn writer_compiles_packet_appends_fcs_and_reports_packet_and_sample_units() {
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
    assert_eq!(report.bytes_requested(), compiled.as_bytes().len());
    assert_eq!(report.bytes_written(), compiled.as_bytes().len());
    assert_eq!(
        report.radio_outcome().unwrap().samples_supplied,
        Some(tx.sample_count() as u64)
    );
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

#[test]
fn ht20_uses_the_same_packet_writer_and_iq_sink() {
    let record = PacketRecord::new(packet());
    let compiled = record.packet().compile().unwrap();
    let mut writer = RadioPacketWriter::new(
        HtTxConfig::new(HtMcs::Mcs7)
            .with_guard_interval(HtGuardInterval::Short)
            .with_fcs(WifiFcsPolicy::Explicit([1, 2, 3, 4])),
        MemoryIqSink::new(),
    );
    let report = writer.write_record(&record).unwrap();
    let transmission = writer.last_transmission().unwrap();
    assert_eq!(transmission.mac_bytes, compiled.as_bytes());
    assert_eq!(
        &transmission.psdu_bytes[transmission.psdu_bytes.len() - 4..],
        &[1, 2, 3, 4]
    );
    assert_eq!(transmission.mcs, HtMcs::Mcs7);
    assert_eq!(transmission.guard_interval, HtGuardInterval::Short);
    assert_eq!(report.bytes_written(), compiled.as_bytes().len());
    assert_eq!(
        report.radio_outcome().unwrap().samples_supplied,
        Some((transmission.cs8.len() / 2) as u64)
    );
    assert_eq!(
        writer.sink().transmissions(),
        std::slice::from_ref(transmission)
    );

    let writer = RadioPacketWriter::new(
        HtTxConfig::new(HtMcs::Mcs5).with_coding(HtCoding::Ldpc),
        MemoryIqSink::new(),
    );
    let transmission = writer.encode_record(&record).unwrap();
    assert_eq!(transmission.coding, HtCoding::Ldpc);
    assert!(transmission.ht_signal.derived[30] != 0);
}

#[test]
fn all_ht20_transmit_modes_round_trip_through_the_wifi_decoder() {
    let expected = packet().compile().unwrap();
    for format in [HtFormat::Mixed, HtFormat::Greenfield] {
        for coding in [HtCoding::Bcc, HtCoding::Ldpc] {
            for guard_interval in [HtGuardInterval::Long, HtGuardInterval::Short] {
                if format == HtFormat::Greenfield && guard_interval == HtGuardInterval::Short {
                    continue;
                }
                for mcs in HtMcs::ALL {
                    let config = HtTxConfig::new(mcs)
                        .with_format(format)
                        .with_coding(coding)
                        .with_guard_interval(guard_interval);
                    let transmission = RadioPacketWriter::new(config, MemoryIqSink::new())
                        .encode_record(&PacketRecord::new(packet()))
                        .unwrap();
                    let bounds = RxConfig {
                        sample_rate_hz: 20_000_000,
                        center_frequency_hz: 2_412_000_000,
                        max_chunk_samples: 20_000,
                        max_buffer_samples: 400_000,
                        max_frame_bytes: 4095,
                        max_pending_frames: 4,
                        max_capture_samples: 1_000_000,
                        max_duration: Duration::from_secs(1),
                    };
                    let chunk = IqChunk::new(
                        bounds,
                        IqPosition {
                            epoch: 0,
                            sequence: 0,
                            sample_index: 0,
                            time_anchor: None,
                            discontinuity: None,
                        },
                        transmission.cs8.clone(),
                    )
                    .unwrap();
                    let output = WifiDecoder::new().consume(IqEvent::Chunk(chunk)).unwrap();
                    assert_eq!(
                        output.frames.len(),
                        1,
                        "{format:?} {coding:?} {guard_interval:?} {mcs:?}"
                    );
                    assert_eq!(
                        &output.frames[0].bytes[..expected.as_bytes().len()],
                        expected.as_bytes(),
                        "{format:?} {coding:?} {guard_interval:?} {mcs:?}"
                    );
                    assert_eq!(output.frames[0].integrity, FrameIntegrity::ValidFcs);
                }
            }
        }
    }
}
