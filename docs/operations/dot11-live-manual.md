# Manual Dot11 Radiotap Testing

This page is for manual IEEE 802.11 monitor-mode testing with a local Wi-Fi
dongle. It is not part of automated CI, oracle acceptance, release validation,
or the default offline workflow. Automated validation must pass without a
dongle, monitor-mode interface, root privileges, provider credentials, real
network identifiers, or packet captures.

libcrafter now injects radiotap frames on the air: a `Radiotap / Dot11` packet
sent through the live send API is routed to the same Layer-2 datalink writer
that transmits Ethernet frames, so the crate puts 802.11 frames on the air over
an operator-configured monitor-mode interface. Injection stays behind the
project's explicit live gates — `--live`, the `--i-understand-isolated-lab`
acknowledgement, and `LIBCRAFTER_ENDPOINT=1` — the same gates the
`crafter/examples/dot11_beacon_inject.rs` example uses. The crate intentionally
does not configure the radio: putting the interface into monitor mode, pinning
the channel, and setting the regulatory domain are operator steps that this
manual covers as prerequisites. The default, ungated path remains dry-run send
planning: build the radiotap-wrapped packet, compile it, inspect the resolved
link-layer target, and verify the emitted bytes without transmitting.

## Prerequisites

- A disposable or isolated RF test environment that the operator is authorized
  to use.
- A Wi-Fi dongle and driver stack that support monitor mode and radiotap
  injection.
- A monitor-mode interface created outside libcrafter and pinned to the test
  channel before any manual live attempt.
- Permission to open the relevant packet injection and capture handles for the
  selected backend.
- A dry-run plan for the exact packet shape, interface name, and backend options
  that would be used for any later manual live test.

Do not use real SSIDs, BSSIDs, public IPs, credentials, sensitive captures, or
traffic from a production network in examples, documentation, fixtures, or
tracked artifacts. Use documentation MAC addresses from the `00:00:5e:00:53:00`
range and synthetic payload bytes.

## Packet Shape

A monitor-mode injection candidate is a link-layer stack with radiotap first:

```text
Radiotap / Dot11 / optional LlcSnap / synthetic payload
```

The radiotap header must be the outer layer. It carries version, header length,
present bitmap words, optional typed fields, and any raw metadata required by
the backend. It must not invent channel, signal, rate, FCS, antenna, retry, or
similar values that the caller did not set.

The IEEE 802.11 MAC frame follows radiotap. Data payloads that represent a
higher-layer protocol use `LlcSnap` explicitly. `Dot11 / Ipv4` is only a
sequential byte stack and is not a valid IP-over-802.11 shape.

## Dry-Run First

Use `send_dry_run` or `SendOptions::dry_run()` before any manual live work. The
interface name below is a placeholder for a monitor-mode interface; dry-run
planning only validates that the name is present and compiles the bytes.

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let monitor_iface = "dot11-monitor-dry-run";

    let packet = Radiotap::new()
        / Dot11::data()
            .addr1(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]))
            .addr2(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]))
            .addr3(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x03]))
        / Raw::from("libcrafter-dot11-dry-run");

    let plan = packet.send_dry_run(
        SendOptions::new()
            .iface(monitor_iface)
            .link_layer(),
    )?;

    assert!(plan.target().is_link_layer());
    println!("{}", packet.summary());
    println!("planned bytes: {}", plan.len());
    Ok(())
}
```

Inspect the plan bytes, packet `summary()`, and `show()` output before changing
any backend flag from dry-run to live. Keep the synthetic payload recognizable
and non-sensitive so captures, when intentionally taken, are easy to identify
and discard.

## Monitor-Mode Capture

Capture uses the wire pcap backend, not the raw socket sender. Create the
monitor-mode interface outside libcrafter, pin it to the authorized test
channel, and open it with `PacketWire::pcap_interface`:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let monitor_iface = "dot11-doc-iface";

    let source = PacketWire::pcap_interface(monitor_iface)
        .filter("type mgt or type data")
        .open()?
        .source()?;

    let records = Sniffer::new(source)
        .with(Dot11Metadata::new())
        .count(10)
        .collect_records()?;

    for record in records {
        println!("{}", record.packet().summary());
        println!("{:?}", record.metadata().wifi());
    }

    Ok(())
}
```

This is a live monitor-mode pcap source. Use it only in an authorized isolated
RF environment, and do not commit captures or identifiers from real networks.
`Dot11Metadata` is a `PacketTransform` that adds best-effort Wi-Fi annotations
without decrypting frames or changing live gates.

For explicit authorized monitor-mode decryption, add `WpaDecrypt` as the next
inbound `PacketTransform` after `Dot11Metadata`, followed by any IP/TCP or
application transforms. Configure only SSIDs and passphrases or PMKs for
networks the operator is authorized to observe. Prefer the offline
`wpa_decrypt_offline` example and synthetic pcap fixture before any live
capture.

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let monitor_iface = "dot11-doc-iface";

    let source = PacketWire::pcap_interface(monitor_iface)
        .filter("type mgt or type data")
        .open()?
        .source()?;

    let records = Sniffer::new(source)
        .with(Dot11Metadata::new())
        .with(WpaDecrypt::new().network("libcrafter-wpa", "libcrafter-pass")?)
        .count(25)
        .collect_records()?;

    for record in records {
        println!("{}", record.packet().summary());
        println!("{:?}", record.metadata().wifi());
    }

    Ok(())
}
```

The placeholder SSID and passphrase above must be replaced only in local,
untracked code for an authorized isolated RF environment. Do not add real
credentials, PMKs, BSSIDs, SSIDs, packet captures, or decrypted traffic to
tracked files or automated tests. `WpaDecrypt` is passive; this manual does not
provide active deauthentication, password cracking, association, scanning, or
channel-hopping instructions.

## Manual Live Gates

Live transmission stays behind explicit live flags. Use the same project
convention as other live-capable examples and provider tools: a dry-run default
plus the explicit `--live` marker, the `--i-understand-isolated-lab`
acknowledgement, and the `LIBCRAFTER_ENDPOINT=1` environment marker. The
`crafter/examples/dot11_beacon_inject.rs` example follows exactly this gate, and
any tool you build on top should keep it.

The live request must name the monitor-mode interface created and configured per
this manual. The crate refuses an interface that is missing or that does not
resolve to a usable Layer-2 datalink channel, surfacing an interface-not-found
or datalink-channel error rather than transmitting. Putting the interface into
monitor mode, disconnecting managed network services from it, and pinning the
channel and regulatory domain remain the operator's responsibility; the crate
writes only to an already-configured interface.

The full flow is: build the `Radiotap / Dot11` frames with crafter, set the
interface to monitor mode and pin the channel per this manual, then run the
`dot11_beacon_inject` example (or your own tool) with `--live
--i-understand-isolated-lab` and `LIBCRAFTER_ENDPOINT=1` to put the frames on
the air. Without those gates the example defaults to dry-run and transmits
nothing.

## Manual Dongle Checklist

1. Run offline unit, fixture, pcap, and oracle checks without the dongle.
2. Create or select the monitor-mode interface outside libcrafter.
3. Pin the interface to the isolated test channel and disconnect managed
   network services from that interface.
4. Build the exact `Radiotap / Dot11` packet with documentation MAC addresses
   and synthetic payload bytes.
5. Run dry-run planning and inspect the compiled bytes.
6. To inject, run the `dot11_beacon_inject` example (or your own tool) with
   `--live --i-understand-isolated-lab` and `LIBCRAFTER_ENDPOINT=1`, only in the
   authorized RF environment.
7. Record manual observations outside tracked files unless the artifact is
   synthetic, sanitized, and intentionally added.

## Cleanup

After a manual test, stop any capture process, remove or sanitize generated
pcap files, return the dongle to managed mode or remove the monitor interface,
restore channel and network-manager state, and destroy any disposable endpoint
or VM used to isolate the test. Do not commit live captures, host identifiers,
credentials, public addresses, real SSIDs, real BSSIDs, or backend state.
