# BLE WHAD Live Manual

This page is for manual Bluetooth Low Energy advertising-channel testing with a
WHAD-compatible dongle. It is not part of automated CI, oracle acceptance,
release validation, or the default offline workflow. Automated validation must
pass without a BLE dongle, serial access, provider credentials, real device
identifiers, or packet captures.

The WHAD backend is feature-gated and dry-run by default. `PacketWire::whad_serial`
records the requested serial target and BLE mode without opening the port until
the caller explicitly opts in with `.live()`. Use live mode only in an
authorized RF environment with devices you own or are allowed to test.

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
Without the feature, offline BLE packet construction, decode, pcap, fixtures,
and dry-run planning remain available, but opening a live WHAD serial target is
reported as an unsupported backend capability.

## Dongle Preparation

Use a WHAD-compatible BLE dongle. The expected manual target for this backend
is ButteRFly firmware on an nRF52840 USB dongle flashed through DFU.

Checklist:

1. Put the nRF52840 dongle into its DFU bootloader mode.
2. Flash the ButteRFly firmware image that matches the dongle and WHAD protocol
   version selected for this repository.
3. Reattach the dongle to the host or isolated VM that will run the manual test.
4. Confirm the serial device path, usually `/dev/ttyACM0` on Linux guests.
5. Make sure the operator account can read and write that serial device.

The ignored smoke harness used during development assumes the ButteRFly dongle
is passed through to the local `.scratch/nrf-dongle` VM as `/dev/ttyACM0`, but
the crate API only needs the serial port path.

## Capability Check

Before injecting or sniffing, confirm that the connected WHAD device advertises
the BLE domain and the command set needed for the selected mode.

For sniffing, the device must support BLE advertising sniff mode and start
control. For injection, it must support the BLE central/raw-PDU path, raw PDU
send, and start control. `PacketWire::whad_serial(port).live().open()` performs
the crate-side discovery and returns a structured WHAD backend error when the
device lacks the required domain or command.

When the WHAD reference tools are available in an ignored local workspace,
cross-check discovery with the reference client before running libcrafter live
traffic. Keep firmware names, local serial paths, and observations in local
notes unless they are synthetic and intentionally sanitized.

## Dry-Run First

Opening a WHAD serial target is dry-run by default:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let builder = PacketWire::whad_serial("/dev/ttyACM0")
        .ble_inject()
        .channel(37);

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
    let packet = BleRadio::advertising(37)
        / BleLlAdv::adv_ind()
            .tx_add(false)
            .adv_a(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x46]))
            .push_ad(AdStructure::flags_general_disc())
            .push_ad(AdStructure::complete_local_name("crafter-ble"));

    println!("{}", packet.summary());
    println!("{}", packet.show());
    println!("{}", packet.hexdump()?);
    Ok(())
}
```

Use documentation-safe data in examples and tracked docs: documentation MAC
addresses from `00:00:5e:00:53:*`, documentation IP address space when an IP
address appears, synthetic local names, and synthetic payload bytes.

## Live Injection

Only call `.live()` after the dry-run packet bytes, channel, dongle, and test
environment have been checked. The live injection path opens the serial port,
runs WHAD discovery, enters BLE mode, and transmits through the WHAD backend.

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let port = "/dev/ttyACM0";
    let channel = 37;

    let packet = BleRadio::advertising(channel)
        / BleLlAdv::adv_ind()
            .tx_add(false)
            .adv_a(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x46]))
            .push_ad(AdStructure::flags_general_disc())
            .push_ad(AdStructure::complete_local_name("crafter-ble"));

    let wire = PacketWire::whad_serial(port)
        .ble_inject()
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

## Advertising Sniff

Use `ble_sniff(channel)` to capture advertising PDUs on one BLE advertising
channel. Primary advertising channels are 37, 38, and 39.

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let wire = PacketWire::whad_serial("/dev/ttyACM0")
        .ble_sniff(37)
        .live()
        .open()?;

    let records = Sniffer::new(wire.source()?)
        .count(10)
        .collect_records()?;

    for record in records {
        println!("{}", record.packet().summary());
        println!("{}", record.packet().show());
    }

    Ok(())
}
```

Sniffing is passive, but it can still observe nearby devices. Run it only in an
authorized RF environment, bound the capture count or timeout, and do not commit
captures, device addresses, local names, serial numbers, host identifiers, or
other data from real devices.

## On-Air Verification

On-air injection verification uses an external receiver, matching the ignored
BLE WHAD smoke harness: a second BLE sniffer, a phone running a BLE inspection
app, or another receiver that is not the transmitting host's own Bluetooth
adapter. The receiver should confirm only the synthetic advertisement fields
used for the test, such as AdvA, PDU type, local name, and manufacturer data.

Do not commit receiver logs, screenshots, packet captures, hardware serial
numbers, or raw observations from real devices. If a live mismatch reveals a
crate bug, promote the smallest synthetic reproducer into a committed unit
test, WHAD backend test, BLE fixture, or oracle case.

## Safety And Legal Boundary

- Use only devices and RF environments you own or are explicitly authorized to
  test.
- Do not jam, flood, deauthenticate, interfere with, or degrade other devices.
- Do not use live transmit near production BLE deployments or public spaces.
- Do not put real device names, BLE addresses, captures, credentials, provider
  account data, public IPs, or live host identifiers into tracked files.
- Keep examples and tracked docs documentation-safe and synthetic.
- Start with offline construction, decode, pcap, and dry-run behavior before
  any live serial operation.

## Cleanup

After a manual run, stop sniffing, disconnect or power down the dongle, remove
or sanitize generated captures and logs, detach any VM USB passthrough, and
delete local scratch artifacts that are no longer needed. Do not commit live
captures or local hardware state.
