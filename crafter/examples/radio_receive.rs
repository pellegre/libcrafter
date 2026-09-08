//! Offline by default. Live syntax is deliberately positional and explicit;
//! see docs/radio.md for all parameters. Does not transmit or select machines.
use crafter::{radio::*, wire::PacketSource};
use std::{error::Error, fs::File, io::Cursor, time::Duration};

struct Borrowed<'a, S>(&'a mut S);
impl<S: IqSource> IqSource for Borrowed<'_, S> {
    fn next_event(&mut self) -> RadioResult<IqEvent> {
        self.0.next_event()
    }
    fn cancel(&mut self) {
        self.0.cancel();
    }
}
fn receive(source: &mut impl IqSource, config: RxConfig) -> Result<(), Box<dyn Error>> {
    let mut packets = RadioPacketSource::new(Borrowed(source), LegacyOfdmDecoder::new(), config)?;
    let mut count = 0u64;
    while let Some(record) = packets.next_record()? {
        count += 1;
        let bytes = record.metadata().captured_bytes().unwrap_or_default();
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        println!("{{\"kind\":\"frame\",\"ordinal\":{count},\"original_mac_hex\":\"{hex}\"}}");
    }
    println!("{{\"kind\":\"summary\",\"frames\":{count},\"complete\":true}}");
    Ok(())
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = RxConfig {
        sample_rate_hz: 20_000_000,
        center_frequency_hz: 2_412_000_000,
        max_chunk_samples: 65_536,
        max_buffer_samples: 2_097_152,
        max_frame_bytes: 4095,
        max_pending_frames: 64,
        max_capture_samples: 20_000_000,
        max_duration: Duration::from_secs(1),
    };
    let position = IqPosition {
        epoch: 0,
        sequence: 0,
        sample_index: 0,
        time_anchor: None,
        discontinuity: None,
    };
    if args.first().map(String::as_str) == Some("--live") {
        // --live SERIAL HZ SECONDS MAX_SAMPLES FILTER_HZ LNA_DB VGA_DB AMP BIAS
        if args.len() != 10 {
            return Err("expected --live SERIAL HZ SECONDS MAX_SAMPLES FILTER_HZ LNA_DB VGA_DB AMP_BOOL BIAS_BOOL".into());
        }
        #[cfg(feature = "radio-hackrf")]
        {
            let mut config = config;
            config.center_frequency_hz = args[2].parse()?;
            config.max_duration = Duration::from_secs(args[3].parse()?);
            config.max_capture_samples = args[4].parse()?;
            let settings = HackRfConfig {
                rx: config.clone(),
                serial: args[1].clone(),
                baseband_filter_hz: args[5].parse()?,
                lna_gain_db: args[6].parse()?,
                vga_gain_db: args[7].parse()?,
                amplifier_enabled: args[8].parse()?,
                antenna_power_enabled: args[9].parse()?,
            };
            let mut source = HackRfSource::open_live(settings)?;
            let result = receive(&mut source, config);
            let stats = source.stats();
            println!("{{\"kind\":\"acquisition\",\"received_samples\":{},\"verified_samples\":{},\"discarded_samples\":{},\"queue_overflows\":{},\"unknown_loss_intervals\":{}}}", stats.received_samples, stats.verified_samples, stats.discarded_samples, stats.queue_overflows, stats.unknown_loss_intervals);
            return result;
        }
        #[cfg(not(feature = "radio-hackrf"))]
        return Err("live reception requires the radio-hackrf feature".into());
    }
    match args.as_slice() {
        [] => receive(&mut ReaderIqSource::new(Cursor::new(include_bytes!("../tests/fixtures/iq/ofdm-6-clean.cs8")), config.clone(), position)?, config),
        [flag, path] if flag == "--replay" => receive(&mut ReaderIqSource::new(File::open(path)?, config.clone(), position)?, config),
        _ => Err("use no arguments for the synthetic fixture, --replay FILE for cs8, or explicit --live parameters".into()),
    }
}
