# Packet Wire API

`crafter::wire` is the Rust packet I/O abstraction. It keeps the library's
normal `Packet` model at the center while adding stream primitives for capture,
transform, and transmit.

Application code should enter through `PacketWire` when it wants a stream of
`PacketRecord` values from a backend or wants to write packet records through a
backend. The pcap codec and libpcap integration are owned by the pcap wire
backend rather than a separate public crate module.

## Model

A `PacketWire` represents one opened packet-capable backend or interface. It is
not a global device manager and it does not own application concurrency. If an
application needs Wi-Fi plus Bluetooth, two Wi-Fi adapters, or Wi-Fi plus SDR,
open one `PacketWire` for each backend and run the resulting sources and
writers in the application's own threads, tasks, or channels.

An opened wire may support reading, writing, or both:

- `source()` consumes a wire and returns one `PacketSource`.
- `writer()` consumes a wire and returns one `PacketWriter`.
- `split()` consumes a wire and returns both capabilities when the backend
  supports both.

Unsupported directions are typed errors. For example, a pcap file input is
read-only, a pcap recorder is write-only, and a raw socket wire is write-only.

`Sniffer` owns one `PacketSource` and an inbound transform chain.
`Transmitter` owns one `PacketWriter` and an outbound transform chain. Each
transform receives a `PacketRecord` and may emit zero, one, or many
`PacketRecord` values. That shape is what lets stateful transforms buffer
handshake frames, wait for fragments, emit multiple reassembled packets, or drop
records that are not ready yet while keeping every stream item packet-shaped.

## Packet Records

`PacketRecord` is the common stream item. It always contains a `Packet`; opaque
or undecoded data is represented as a `Raw` layer inside that packet rather than
as a separate byte-only object.

`PacketRecord` also carries `PacketMetadata`:

- origin, such as captured or generated;
- backend kind, interface name, or file path;
- pcap timestamp, original length, captured length, captured bytes, and emitted
  length when available;
- link type and pcap link type;
- transform trace entries;
- medium metadata, including Wi-Fi placeholders for SSID bytes, BSSID, channel,
  protection state, Dot11 frame kind, and decrypt state.

Metadata is deliberately inspectable. Packet processing tools should be able to
log `record.packet().summary()` and inspect `record.metadata()` without guessing
which backend or transform produced the record.

## Offline Capture

Prefer offline pcap examples in tests, docs, and generated tools unless a live
run is explicitly needed.

```rust
use crafter::prelude::*;

let source = PacketWire::pcap_file("fixtures/input.pcap")
    .filter("tcp or udp")
    .open()?
    .source()?;

let mut sniffer = Sniffer::new(source)
    .with(Dot11Metadata::new())
    .count(10);

while let Some(record) = sniffer.next_record()? {
    println!("{}", record.packet().summary());
    println!("{:?}", record.metadata());
}
# Ok::<(), crafter::CrafterError>(())
```

The pcap file constructor accepts an optional libpcap BPF filter. The source
decodes each record into a `PacketRecord` and preserves pcap timestamp, lengths,
captured bytes, and link metadata.

## Offline Writing

Use a pcap recorder when the output should be deterministic and inspectable.

```rust
use crafter::prelude::*;

let writer = PacketWire::pcap_recorder("target/out.pcap", LinkType::Ethernet)
    .open()?
    .writer()?;

let packet =
    Ethernet::new()
    / Ipv4::new().src("192.0.2.10")?.dst("198.51.100.20")?
    / Udp::new().sport(40000).dport(53)
    / Raw::from("payload");

let mut tx = Transmitter::new(writer);
let reports = tx.send(packet)?;

for report in reports {
    println!("{:?}", report);
}
# Ok::<(), crafter::CrafterError>(())
```

The recorder compiles the packet from each `PacketRecord`, validates compatible
link metadata when present, writes the pcap record, and returns a `WriteReport`.

## Transform Chains

`PacketTransform` is the state-machine contract shared by inbound and outbound
pipelines.

```rust
use crafter::prelude::*;

struct KeepIpv4;

impl PacketTransform for KeepIpv4 {
    fn name(&self) -> &'static str {
        "keep-ipv4"
    }

    fn transform(
        &mut self,
        record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> crafter::wire::Result<()>,
    ) -> crafter::wire::Result<()> {
        if record.packet().layer::<Ipv4>().is_some() {
            emit(record)?;
        }
        Ok(())
    }
}
```

Transforms are ordered. The output from one transform becomes the input to the
next. If a transform emits no records, the rest of the chain is skipped for that
input. If it emits many records, downstream transforms and writers see each
record in emission order.

Built-in transform shapes include:

- Wi-Fi metadata annotation, such as `Dot11Metadata`;
- WPA/WPA2 key-state tracking and protected-data decryption, such as
  `WpaDecrypt`;
- IPv4 and IPv6 receive-side fragment reassembly through `IpDefrag`;
- IPv4 and IPv6 transmit-side fragmentation through `IpFragment`.

TCP stream reassembly and application reconstruction are out of scope for the
built-in wire transforms. Tools that need those workflows can implement their
own `PacketTransform`, but the crate keeps its built-in transforms at packet
datagram scope.

`IpDefrag` is an inbound transform for sources and sniffers. It consumes
fragmented IPv4 records and supported IPv6 Fragment Header records, buffers
bounded per-datagram state, and emits a reassembled packet-shaped record when
all byte ranges are present. Metadata stays inspectable through
`PacketMetadata::ip_defrag_metadata()` and transform traces.

```rust
use crafter::prelude::*;

let source = PacketWire::pcap_file(
    "crafter/tests/fixtures/pcaps/raw-ipv4-ipfragment-generated.pcap",
)
    .open()?
    .source()?;

let records = Sniffer::new(source)
    .with(IpDefrag::new())
    .collect_records()?;

for record in records {
    println!("{}", record.packet().summary());
    println!("{:?}", record.metadata().ip_defrag_metadata());
}
# Ok::<(), crafter::CrafterError>(())
```

`IpFragment` is an outbound transform with an explicit MTU. For IPv4, the
default `Ipv4DontFragmentPolicy::Error` honors Don't Fragment (DF): when a
DF-set packet exceeds the configured MTU, the transform returns a structured
`ip-fragment` error instead of silently fragmenting. Callers that want an
explicit no-fragment result can configure
`IpFragmentConfig::new(mtu).dont_fragment_policy(Ipv4DontFragmentPolicy::PassThrough)`,
which emits the original record with `IpFragmentReason::DontFragment` metadata
and an `ipv4 don't-fragment pass-through` trace. The only override that plans
fragmentation despite DF is the explicit
`Ipv4DontFragmentPolicy::FragmentAnyway` policy; the legacy
`honor_dont_fragment(false)` builder maps to that same override.

Place `IpFragment` on `Transmitter`, not on `Sniffer`. Offline writers keep
fragment output deterministic and reviewable:

```rust
use crafter::prelude::*;

let writer = MemoryPacketWriter::dry_run();
let mut tx = Transmitter::new(writer).with(IpFragment::new(1280));

let reports = tx.send(
    Ipv6::new().src_str("2001:db8:20::1")?.dst_str("2001:db8:20::2")?
        / Udp::new().sport(53000).dport(53001)
        / Raw::from_bytes(&[0u8; 1600]),
)?;

assert!(reports.iter().all(|report| report.is_dry_run()));
# Ok::<(), crafter::CrafterError>(())
```

Use documentation address space in examples and dry-run or pcap writers by
default. Provider-backed lab sessions are the live path when a workflow needs
real packet exchange.

For `IpDefrag` and `IpFragment` validation, run transform tests, oracle offline
checks, and pcap checks before any live workflow. Live fragment behavior must go
through a disposable lab provider session with `--confirm-live-run`, artifacts
under `target/lab/ip-fragment-*`, and teardown or skip artifacts that explain
what happened. Do not validate IP fragmentation by sending raw live traffic from
the developer machine; use the lab-backed workflow in [validation.md](../operations/validation.md)
and [lab.md](../operations/lab.md).

`WpaDecrypt` is an inbound transform. It accepts one or more configured SSIDs
with either passphrases or pre-derived PMKs, observes beacons, RSN information,
EAPOL-Key handshakes, and protected Dot11 data frames, and emits decrypted
packet records when the observed WPA2-PSK CCMP-128 state verifies.

Put `Dot11Metadata` before `WpaDecrypt` so the WPA transform can extend the
same Wi-Fi metadata record:

```rust
use crafter::prelude::*;

let source = PacketWire::pcap_file(
    "crafter/tests/fixtures/pcaps/wpa2-psk-ccmp-unicast.pcap",
)
    .open()?
    .source()?;

let records = Sniffer::new(source)
    .with(Dot11Metadata::new())
    .with(WpaDecrypt::new().network("libcrafter-wpa", "libcrafter-pass")?)
    .collect_records()?;

for record in records {
    println!("{}", record.packet().summary());
    if let Some(wpa) = record
        .metadata()
        .wifi()
        .and_then(|wifi| wifi.wpa_metadata())
    {
        println!("{:?} {:?}", wpa.cipher(), wpa.decrypt_reason());
    }
}
# Ok::<(), crafter::CrafterError>(())
```

The first complete decrypt path is passive WPA2-Personal with CCMP-128. TKIP,
GCMP, CCMP-256, WPA3/SAE, enterprise authentication, password cracking,
deauthentication, channel management, and AP or supplicant behavior are outside
this transform. Unsupported ciphers or AKMs remain packet-shaped observations
with inspectable `WpaMetadata` such as `WpaDecryptReason::UnsupportedCipher` or
`WpaDecryptReason::UnsupportedAkm`; they are not treated as silently decrypted
or guessed plaintext.

By default `WpaDecrypt` suppresses handshake-only records and undecryptable
protected originals while still passing non-Wi-Fi and unprotected non-handshake
records. Use `WpaDecryptConfig::new().pass_originals(true)` for diagnostic
captures that need the original protected records annotated with WPA metadata.
Real SSIDs, passphrases, PMKs, live captures, and unauthorized RF observations
do not belong in tracked files or automated tests. Use synthetic offline pcap
fixtures for examples and CI.

## Live Capture

Live examples must be explicit and bounded. Use disposable provider-backed
endpoints or an authorized lab environment for real traffic. Do not run live
capture against networks you do not control.

```rust
use crafter::prelude::*;
use std::time::Duration;

let source = PacketWire::pcap_interface("eth0")
    .filter("icmp")
    .timeout(Duration::from_secs(1))
    .snaplen(262_144)
    .promisc(true)
    .immediate_mode(true)
    .nonblocking(true)
    .open()?
    .source()?;

let records = Sniffer::new(source)
    .timeout(Duration::from_secs(3))
    .count(5)
    .collect_records()?;

for record in records {
    println!("{}", record.packet().summary());
}
# Ok::<(), crafter::CrafterError>(())
```

`PacketWire::pcap_interface` opens one live libpcap interface. It can expose a
source, and when the platform and libpcap backend support it, a pcap interface
writer. Use `split()` only when the application needs both capabilities from
the same interface target and is prepared to handle a typed capability error.

## Live Writing

For raw socket sends through the wire API, use the dedicated raw socket
constructor. It defaults to dry-run planning; `.live()` is the explicit opt-in
for live raw socket transmission.

```rust
use crafter::prelude::*;

let writer = PacketWire::raw_socket_interface("eth0")
    .network_layer()
    .open()?
    .writer()?;

let packet =
    Ipv4::new().src("192.0.2.10")?.dst("198.51.100.20")?
    / Udp::new().sport(40000).dport(33434)
    / Raw::from("dry-run payload");

let reports = Transmitter::new(writer).send(packet)?;
assert!(reports.iter().all(|report| report.is_dry_run()));
# Ok::<(), crafter::CrafterError>(())
```

Live send requires `.live()` and the normal raw socket privileges for the
selected platform:

```rust
use crafter::prelude::*;

let writer = PacketWire::raw_socket_interface("eth0")
    .network_layer()
    .live()
    .open()?
    .writer()?;

let mut tx = Transmitter::new(writer);
let _reports = tx.send(
    Ipv4::new().src("192.0.2.10")?.dst("198.51.100.20")?
    / Udp::new().sport(40000).dport(33434)
    / Raw::from("authorized live payload"),
)?;
# Ok::<(), crafter::CrafterError>(())
```

Unsupported radiotap Wi-Fi injection is not silently rerouted through this raw
socket path. Monitor-mode Dot11 injection needs a backend that explicitly
supports that medium.

## Parallel Interfaces

Parallel work is application-owned. Open one wire per interface or backend and
move each source or writer into the runtime the application already uses.

```rust
use crafter::prelude::*;

let wifi_source = PacketWire::pcap_interface("wlan0mon")
    .filter("type mgt or type data")
    .open()?
    .source()?;

let ethernet_source = PacketWire::pcap_interface("eth0")
    .filter("ip")
    .open()?
    .source()?;

let wifi = Sniffer::new(wifi_source).with(Dot11Metadata::new()).spawn()?;
let ethernet = Sniffer::new(ethernet_source).count(100).spawn()?;

let wifi_records = wifi.join()?;
let ethernet_records = ethernet.join()?;
# Ok::<(), crafter::CrafterError>(())
```

The crate deliberately does not provide a multi-wire builder. Keeping each
`PacketWire` tied to one backend makes ownership, capabilities, live safety, and
failure reporting explicit.
