# IEEE 802.15.4 WHAD Live Manual

This page is for manual IEEE 802.15.4 and Zigbee testing with a WHAD-compatible
dongle. It is not part of automated CI, oracle acceptance, release validation, or
the default offline workflow. Automated validation must pass without an 802.15.4
dongle, serial access, provider credentials, real device identifiers, or packet
captures.

The WHAD backend is feature-gated and dry-run by default. `PacketWire::whad_serial`
records the requested serial target and 802.15.4 mode without opening the port
until the caller explicitly opts in with `.live()`. Use live mode only in an
authorized RF environment with devices you own or are allowed to test.

The offline build, decode, pcap, and dry-run behavior for these layers is
documented in the [802.15.4 / Zigbee guide](../guide/dot15d4.md). The wire facts
the live backend relies on are recorded in
[`.agents/docs/whad-dot15d4-manifest.md`](../../.agents/docs/whad-dot15d4-manifest.md);
the protocol-layer facts are in `.agents/docs/dot15d4-manifest.md`,
`.agents/docs/dot15d4-codepoints.md`, `.agents/docs/zigbee-manifest.md`, and
`.agents/docs/zigbee-scope.md`.

## Cargo Feature

Build code that opens a WHAD serial backend with the optional `whad` feature:

```sh
cargo build -p crafter --features whad
```

Generated tools that depend on `crafter` by path should enable the same feature:

```toml
[dependencies]
crafter = { path = "../libcrafter/crafter", features = ["whad"] }
```

The default crate build does not include WHAD protobuf or serial dependencies.
Without the feature, offline 802.15.4 / Zigbee packet construction, decode, pcap,
fixtures, and dry-run planning remain available, but opening a live WHAD serial
target is reported as an unsupported backend capability.

## Dongle Preparation

Use a WHAD-compatible 802.15.4 dongle. The expected manual target for this
backend is ButteRFly firmware on an nRF52840 USB dongle flashed through DFU,
which reports the WHAD 802.15.4 domain.

Checklist:

1. Put the nRF52840 dongle into its DFU bootloader mode.
2. Flash the ButteRFly firmware image that matches the dongle and WHAD protocol
   version selected for this repository.
3. Reattach the dongle to the host or isolated VM that will run the manual test.
4. Confirm the serial device path, usually `/dev/ttyACM0` on Linux guests.
5. Make sure the operator account can read and write that serial device.

The ignored smoke harness used during development assumes the ButteRFly dongle is
passed through to the local `.scratch/nrf-dongle` VM as `/dev/ttyACM0`, but the
crate API only needs the serial port path.

## Capability Check

Before sniffing or injecting, confirm that the connected WHAD device advertises
the 802.15.4 domain and the command set needed for the selected mode.

For sniffing, the device must support the 802.15.4 sniff command plus start and
stop control. For injection, it must support the send (and raw-send) command plus
start control. `PacketWire::whad_serial(port).live().open()` performs the
crate-side discovery and returns a structured WHAD backend error when the device
lacks the required domain or command.

When the WHAD reference tools are available in an ignored local workspace,
cross-check discovery with the reference client (`whad-client` / `wsniff` for the
802.15.4 domain) before running libcrafter live traffic. Keep firmware names,
local serial paths, and observations in local notes unless they are synthetic and
intentionally sanitized.

## Dry-Run First

Opening a WHAD serial target is dry-run by default:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let builder = PacketWire::whad_serial("/dev/ttyACM0")
        .dot15d4_send()
        .channel(15);

    assert!(builder.is_dry_run());

    let wire = builder.open()?;
    assert!(!wire.has_source());
    assert!(!wire.has_writer());
    Ok(())
}
```

This records a WHAD target without opening the serial port or sending WHAD
control frames. Build and inspect the packet separately before any live run:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let packet = Dot15d4Radio::on_channel(15)
        / Dot15d4::data()
            .seq(7)
            .dest_short(0x1234, 0x0002)
            .src_short(0x1234, 0x0001)
            .payload(&[0xde, 0xad, 0xbe, 0xef]);

    println!("{}", packet.summary());
    println!("{}", packet.show());
    println!("{}", packet.hexdump()?);
    Ok(())
}
```

Use lab-safe data in examples and tracked docs: 802.15.4 channels 11 through 26,
lab-safe PAN ids such as `0x1234`, lab-safe short addresses such as `0x0001` and
`0x0002`, documentation IP address space when an IP address appears, and
synthetic payload bytes.

## Live Injection

Only call `.live()` after the dry-run packet bytes, channel, dongle, and test
environment have been checked. The live injection path opens the serial port,
runs WHAD discovery, enters the 802.15.4 send mode, and transmits through the
WHAD backend.

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let port = "/dev/ttyACM0";
    let channel = 15;

    let packet = Dot15d4Radio::on_channel(channel)
        / Dot15d4::data()
            .seq(7)
            .dest_short(0x1234, 0x0002)
            .src_short(0x1234, 0x0001)
            .payload(&[0xde, 0xad, 0xbe, 0xef]);

    let wire = PacketWire::whad_serial(port)
        .dot15d4_send()
        .channel(channel)
        .live()
        .open()?;

    let mut writer = wire.writer()?;
    let report = writer.write_record(&PacketRecord::new(packet))?;
    assert!(!report.is_dry_run());
    Ok(())
}
```

Keep live transmit tools gated by a local `--live` flag or equivalent operator
acknowledgement. Without that flag, tools should compile and inspect the packet
only, then exit without opening WHAD serial or transmitting.

## 802.15.4 Sniff

Use `dot15d4_sniff(channel)` to capture 802.15.4 frames on one channel.
802.15.4 2.4 GHz channels run from 11 through 26.

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let wire = PacketWire::whad_serial("/dev/ttyACM0")
        .dot15d4_sniff(15)
        .live()
        .open()?;

    let records = Sniffer::new(wire.source()?)
        .count(10)
        .collect_records()?;

    for record in records {
        if let Some(MediumMetadata::Dot15d4(meta)) = record.metadata().medium() {
            println!(
                "ch={:?} rssi={:?} lqi={:?} fcs_valid={:?}",
                meta.channel(),
                meta.signal_dbm(),
                meta.lqi(),
                meta.fcs_valid(),
            );
        }
        println!("{}", record.packet().summary());
        println!("{}", record.packet().show());
    }

    Ok(())
}
```

Each captured frame becomes a `Dot15d4Radio / Dot15d4` record (with Zigbee
`ZigbeeNwk` / `ZigbeeAps` layers when the payload is recognized, or a trailing
`Raw` layer otherwise). The radio metadata is exposed through
`MediumMetadata::Dot15d4` on the record.

Sniffing is passive, but it can still observe nearby devices. Run it only in an
authorized RF environment, bound the capture count or timeout, and do not commit
captures, PAN ids, device addresses, host identifiers, or other data from real
devices.

## Smoke Harness Pattern

Live validation during development runs as a throwaway smoke harness kept out of
the committed repository. The harness lives under `.scratch/dot15d4-smoke`, which
is git-ignored, and depends on `crafter` by path with the `whad` feature:

```toml
[dependencies]
crafter = { path = "../../crafter", features = ["whad"] }
```

The harness drives the dongle directly:

- a sniff path that opens
  `PacketWire::whad_serial("/dev/ttyACM0").dot15d4_sniff(ch).live().open()?`,
  reads records, and prints the radio metadata plus `summary()` / `show()` so the
  output can be cross-checked against the WHAD reference client (`whad-client` /
  `wsniff`) on the same channel;
- an inject path that builds a lab-safe `Dot15d4Radio / Dot15d4` frame, opens
  `.dot15d4_send().channel(ch).live().open()?.writer()?`, and writes a bounded
  number of frames for an independent receiver on the same channel to observe.

The harness assumes the ButteRFly dongle is passed through to the
`.scratch/nrf-dongle` VM as `/dev/ttyACM0`. It is disposable: it is never
committed, and if a live mismatch reveals a crate bug, the fix is to promote the
smallest synthetic reproducer into a committed unit test, WHAD backend test,
fixture, or oracle case, not to commit the harness or its output.

## On-Air Verification

On-air injection verification uses an external receiver, matching the ignored
802.15.4 WHAD smoke harness: a second 802.15.4 sniffer or another receiver tuned
to the same channel that is not the transmitting dongle. The receiver should
confirm only the synthetic frame fields used for the test, such as the frame
type, sequence number, PAN id, and short addresses.

Do not commit receiver logs, screenshots, packet captures, hardware serial
numbers, or raw observations from real devices.

## Safety And Legal Boundary

- Use only devices and RF environments you own or are explicitly authorized to
  test.
- Stay on lab-safe 802.15.4 channels (11 through 26) with lab-safe PAN ids and
  short/extended addresses.
- Do not jam, flood, interfere with, or degrade other devices.
- Do not use live transmit near production Zigbee or 802.15.4 deployments or
  public spaces.
- Do not put real device PAN ids, addresses, captures, credentials, provider
  account data, public IPs, or live host identifiers into tracked files.
- Keep examples and tracked docs lab-safe and synthetic; no real-network captures
  are committed.
- Start with offline construction, decode, pcap, and dry-run behavior before any
  live serial operation.

## Cleanup

After a manual run, stop sniffing, disconnect or power down the dongle, remove or
sanitize generated captures and logs, detach any VM USB passthrough, and delete
local scratch artifacts that are no longer needed. Do not commit live captures or
local hardware state.
