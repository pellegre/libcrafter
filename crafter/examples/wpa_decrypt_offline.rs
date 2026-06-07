mod common;

use std::path::PathBuf;

use common::{arg_value, print_help_if_requested, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example wpa_decrypt_offline -- [--pcap FILE]\n\nRead a synthetic WPA2-PSK CCMP pcap through PacketWire, Sniffer, and WpaDecrypt without live Wi-Fi access.",
    ) {
        return Ok(());
    }

    let path = arg_value("--pcap").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/pcaps/wpa2-psk-ccmp-unicast.pcap")
    });
    let source = PacketWire::pcap_file(path.clone()).open()?.source()?;
    let records = Sniffer::new(source)
        .with(Dot11Metadata::new())
        .with(
            WpaDecrypt::new()
                .network("libcrafter-wpa", "libcrafter-pass")?
                .network_bytes(b"\xffdry-run".as_slice(), "unused-passphrase")?
                .with_config(WpaDecryptConfig::new().pass_originals(false)),
        )
        .collect_records()?;

    println!("example: wpa_decrypt_offline");
    println!("mode: offline");
    println!("pcap: {}", path.display());
    println!("records: {}", records.len());

    for (index, record) in records.iter().enumerate() {
        println!("record[{index}] summary: {}", record.packet().summary());

        if let Some(wifi) = record.metadata().wifi() {
            println!(
                "record[{index}] wifi: ssid={} bssid={:?} transmitter={:?} receiver={:?} decrypt_state={:?}",
                ssid_label(wifi.ssid()),
                wifi.bssid(),
                wifi.transmitter(),
                wifi.receiver(),
                wifi.decrypt_state()
            );

            if let Some(wpa) = wifi.wpa_metadata() {
                println!(
                    "record[{index}] wpa: cipher={:?} akm={:?} key_kind={:?} key_id={:?} packet_number={:?} handshake={:?} credentials={:?} reason={:?}",
                    wpa.cipher(),
                    wpa.akm(),
                    wpa.key_kind(),
                    wpa.key_id(),
                    wpa.packet_number(),
                    wpa.handshake_status(),
                    wpa.credential_status(),
                    wpa.decrypt_reason()
                );
            }
        }
    }

    Ok(())
}

fn ssid_label(ssid: Option<&[u8]>) -> String {
    match ssid {
        Some(bytes) if bytes.is_ascii() => String::from_utf8_lossy(bytes).into_owned(),
        Some(bytes) => format!("{bytes:02x?}"),
        None => "-".to_string(),
    }
}
