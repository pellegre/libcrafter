mod common;

use common::{
    arg_or, live_mode, parse_usize_arg, print_help_if_requested, print_send_report, ExampleResult,
    ADVANCED_LIVE_ACK_FLAG, LIVE_WIRE_ENV,
};
use crafter::prelude::*;

/// Documentation-safe monitor interface name. The crate never configures
/// monitor mode; an operator sets the interface up beforehand.
const EXAMPLE_MONITOR_IFACE: &str = "dot11-monitor-dry-run";

/// Build one documentation-safe beacon frame for the given SSID/BSSID/channel.
fn build_beacon(ssid: &str, bssid: MacAddr, channel: u8, seq: u16) -> Packet {
    Radiotap::monitor_tx(
        2,
        RadiotapChannel::channel_2ghz(channel),
        RadiotapTxFlags::NO_ACK,
    ) / Dot11::beacon()
        .addr1(MacAddr::BROADCAST)
        .addr2(bssid)
        .addr3(bssid)
        .sequence_number(seq)
        .with_beacon_fixed_fields(Dot11BeaconFixedFields::new(0, 100, DOT11_CAPABILITY_ESS))
        .ssid(ssid.as_bytes())
        .supported_rates([0x82, 0x84, 0x8b, 0x96])
        .ds_parameter_set(channel)
}

/// Documentation-safe per-index BSSID in the 02:00:5e:00:53:.. range.
fn example_bssid(index: usize) -> MacAddr {
    let low = u8::try_from(index & 0xff).unwrap_or(0xff);
    MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, low])
}

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example dot11_beacon_inject -- [--live] [--iface IFACE] [--channel CHANNEL] [--count COUNT] [--prefix PREFIX]\n\nBuild synthetic monitor-mode beacon frames and print a dry-run injection plan by default. Live transmission requires --live, the isolated-lab acknowledgement, and the wire-endpoint environment marker, plus an interface the operator has already placed into monitor mode.",
    ) {
        return Ok(());
    }

    // Gate live transmission behind the project's explicit live markers. Returns
    // true only with --live AND --i-understand-isolated-lab AND LIBCRAFTER_ENDPOINT=1.
    let live = live_mode("dot11_beacon_inject")?;

    let iface = arg_or("--iface", EXAMPLE_MONITOR_IFACE);
    let channel: u8 = arg_or("--channel", "6").parse()?;
    let count = parse_usize_arg("--count", 5)?;
    let prefix = arg_or("--prefix", "lcftest");

    let ssids: Vec<String> = (0..count).map(|index| format!("{prefix}-{index}")).collect();

    println!("example: dot11_beacon_inject");
    println!("mode: {}", if live { "live" } else { "dry-run" });
    if live {
        println!(
            "safety: --live, {ADVANCED_LIVE_ACK_FLAG}, and {LIVE_WIRE_ENV}=1 were required; \
             transmitting on the operator-configured monitor interface"
        );
    } else {
        println!(
            "safety: no frames are transmitted; this prints a dry-run injection plan only. \
             Live transmission requires --live {ADVANCED_LIVE_ACK_FLAG} and {LIVE_WIRE_ENV}=1"
        );
    }
    // The crate never configures monitor mode: the operator must place the
    // interface into monitor mode on the chosen channel before a live run.
    println!("note: the interface must already be in monitor mode on the chosen channel; this example does not configure monitor mode");
    println!("interface: {iface}");
    println!("channel: {channel}");
    println!("beacons: {count}");

    // Plan the first beacon's dry-run injection through the public planner so the
    // resolved radiotap link-layer target and compiled bytes are inspectable.
    if let Some(first_ssid) = ssids.first() {
        let first = build_beacon(first_ssid, example_bssid(0), channel, 0);
        let plan = send_plan(
            &first,
            SendOptions::new().iface(&iface).link_layer().dry_run(),
        )?;

        println!("plan target: {:?}", plan.target());
        println!("plan interface: {}", plan.interface());
        println!("plan len: {}", plan.len());
        println!("first beacon summary: {}", first.summary());
        println!("first beacon hexdump:\n{}", plan.compiled_packet().hexdump());
    }

    for (index, ssid) in ssids.iter().enumerate() {
        let beacon = build_beacon(ssid, example_bssid(index), channel, index as u16);

        if live {
            // Transmit through the crate's now-enabled radiotap injection on the
            // operator-configured monitor interface, via the same public send
            // entry point used by send_packet.rs.
            let options = SendOptions::new().iface(&iface).link_layer().live();
            let report = send_packet(&beacon, options)?;
            print_send_report(&format!("dot11_beacon_inject beacon {index} ssid {ssid}"), &beacon, &report);
        } else {
            println!("beacon {index} ssid {ssid}: {}", beacon.summary());
        }
    }

    Ok(())
}
