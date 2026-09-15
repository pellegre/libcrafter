//! Offline shared packet pipeline: `cargo run -p crafter --features radio
//! --example wifi_interface -- monitor` (or `radio`). No device is opened.
use crafter::prelude::*;
use crafter::radio::{IqPosition, MemoryIqSource, OwnedSamples, RxConfig};
use std::time::Duration;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "monitor".into());
    let backend = offline_backend(&mode)?;
    println!("{:?}", relay(backend)?);
    Ok(())
}

pub fn offline_backend(mode: &str) -> std::result::Result<WifiBackend, Box<dyn std::error::Error>> {
    let packet = Dot11::data()
        .addr1(MacAddr::new([0x02, 0, 0x5e, 0, 0x53, 1]))
        .addr2(MacAddr::new([0x02, 0, 0x5e, 0, 0x53, 2]))
        .addr3(MacAddr::new([0x02, 0, 0x5e, 0, 0x53, 3]))
        / Raw::from("offline Wi-Fi interface");
    let backend = match mode {
        "monitor" => WifiBackend::MonitorAdapters {
            source: Some(Box::new(VecPacketSource::from_packets([
                Radiotap::new() / packet
            ]))),
            writer: Some(Box::new(MemoryPacketWriter::dry_run())),
            framing: LinkType::Radiotap,
            radiotap_override: None,
        },
        "radio" => {
            let bounds = RxConfig {
                sample_rate_hz: 20_000_000,
                center_frequency_hz: 2_437_000_000,
                max_chunk_samples: 20_000,
                max_buffer_samples: 400_000,
                max_frame_bytes: 4095,
                max_pending_frames: 4,
                max_capture_samples: 1_000_000,
                max_duration: Duration::from_secs(1),
            };
            let transmission = RadioPacketWriter::new(
                LegacyWifiTxConfig::ofdm(LegacyOfdmRate::Mbps6),
                MemoryIqSink::new(),
            )
            .encode_record(&PacketRecord::new(packet))?;
            let source = MemoryIqSource::from_cs8(
                transmission.cs8().to_vec(),
                bounds.clone(),
                IqPosition {
                    epoch: 0,
                    sequence: 0,
                    sample_index: 0,
                    time_anchor: None,
                    discontinuity: None,
                },
            )?;
            WifiBackend::RadioAdapters {
                source: Some(Box::new(source)),
                sink: Some(Box::new(MemoryIqSink::<OwnedSamples>::new())),
                bounds,
            }
        }
        _ => return Err("expected monitor or radio".into()),
    };
    Ok(backend)
}

// README shared-pipeline start
pub fn relay(backend: WifiBackend) -> crafter::wire::Result<WifiInterfaceStatus> {
    let wire = PacketWire::wifi(backend, WifiInterfaceConfig::default())?;
    let control = wire.wifi_control().expect("Wi-Fi control");
    let (source, writer) = wire.split()?;
    let mut sniffer = Sniffer::new(source).with(Dot11Metadata::new());
    let mut transmitter = Transmitter::new(writer);
    while let Some(record) = sniffer.next_record()? {
        println!("{}", record.packet().summary());
        for report in transmitter.send_record(record)? {
            println!("{:?}", report);
        }
    }
    Ok(control.status())
}
// README shared-pipeline end
