# Manual Dot11 Radiotap Testing

This page is for manual IEEE 802.11 monitor-mode testing with a local Wi-Fi
dongle. It is not part of automated CI, oracle acceptance, release validation,
or the default offline workflow. Automated validation must pass without a
dongle, monitor-mode interface, root privileges, provider credentials, real
network identifiers, or packet captures.

Current libcrafter live radiotap transmission is intentionally gated as
unsupported. The supported path today is dry-run send planning: build the
radiotap-wrapped packet, compile it, inspect the resolved link-layer target,
and verify the emitted bytes without transmitting. Real injection belongs to a
future explicit monitor-mode radiotap backend or a separate human-controlled
manual tool that keeps the same live gates.

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

A future `Wpa2PskDecryptor` belongs as the next inbound `PacketTransform` after
`Dot11Metadata`, followed by any IP/TCP or application transforms. This manual
page intentionally does not define secret handling or implement WPA
decryption.

## Manual Live Gates

Any future manual dongle runner or backend must keep live transmission behind
explicit live flags. Use the same project convention as other live-capable
examples and provider tools: a dry-run default plus an explicit marker such as
`--live` with a safety acknowledgement, or `--confirm-live-run` for provider
style runners.

The live request must name the monitor-mode interface and the radiotap backend.
It must refuse managed interfaces, missing monitor mode, missing radiotap
support, and absent live confirmation. In the current crate, trying to send a
`Radiotap / Dot11` packet through the built-in live socket sender returns an
unsupported-send error instead of transmitting.

## Manual Dongle Checklist

1. Run offline unit, fixture, pcap, and oracle checks without the dongle.
2. Create or select the monitor-mode interface outside libcrafter.
3. Pin the interface to the isolated test channel and disconnect managed
   network services from that interface.
4. Build the exact `Radiotap / Dot11` packet with documentation MAC addresses
   and synthetic payload bytes.
5. Run dry-run planning and inspect the compiled bytes.
6. If using a future explicit backend, run it only with the required live flags
   and only in the authorized RF environment.
7. Record manual observations outside tracked files unless the artifact is
   synthetic, sanitized, and intentionally added.

## Cleanup

After a manual test, stop any capture process, remove or sanitize generated
pcap files, return the dongle to managed mode or remove the monitor interface,
restore channel and network-manager state, and destroy any disposable endpoint
or VM used to isolate the test. Do not commit live captures, host identifiers,
credentials, public addresses, real SSIDs, real BSSIDs, or backend state.
