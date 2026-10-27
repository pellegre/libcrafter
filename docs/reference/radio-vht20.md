# Wi-Fi 5 VHT20

The `radio` feature integrates IEEE 802.11ac VHT20 into `WifiDecoder`,
`RadioPacketSource`, `RadioPacketWriter`, and `PacketWire::wifi`. Packet
construction, original-byte retention, `Sniffer`, and packet transforms use
the same interfaces as legacy Wi-Fi and HT20.

| Property | Supported scope |
| --- | --- |
| Channel and streams | 20 MHz, single user, one spatial/space-time stream, no STBC |
| Modulation and coding | MCS0–8, BCC or LDPC, through 256-QAM 3/4 |
| Guard interval | 800 ns or 400 ns |
| Receive payload | S-MPDUs and A-MPDUs; individual MPDU FCS validation |
| Transmit payload | One compiled MAC frame, FCS, S-MPDU delimiter and PHY padding |
| Signaling | L-SIG, VHT-SIG-A CRC/tail/reserved checks, VHT-SIG-B linked to DATA SERVICE |

MCS9 is invalid for VHT20 with one spatial stream. Wider channels, multiple
streams, VHT STBC, MU DATA, and HE/EHT reception are outside this codec.
Integrity-checked SIG-A observations remain available for unsupported VHT
configurations; those observations do not establish MAC integrity.

VHT has a legacy training and SIGNAL prefix followed by VHT signaling and
training. It does not use the HT mixed/greenfield format choice. BCC/LDPC
and long/short guard intervals select coding and symbol timing within VHT.
See IEEE 802.11-2020 clauses 9.7, 10.12.6–8, 21.3 and Table 21-29, with
reviewed anchors in [`wifi-phy-evidence.json`](../wifi-phy-evidence.json).

## Packet-to-IQ encoding

```rust
use crafter::prelude::*;

let packet = Dot11::data()
    .addr1(MacAddr::new([0, 0, 0x5e, 0, 0x53, 1]))
    .addr2(MacAddr::new([0, 0, 0x5e, 0, 0x53, 2]))
    .addr3(MacAddr::new([0, 0, 0x5e, 0, 0x53, 3]))
    / Raw::from(b"VHT20 example".as_slice());
let config = VhtTxConfig::new(VhtMcs::Mcs8)
    .with_coding(VhtCoding::Ldpc)
    .with_guard_interval(VhtGuardInterval::Short);
let writer = RadioPacketWriter::new(config, MemoryIqSink::new());
let tx = writer.encode_record(&PacketRecord::new(packet))?;
assert_eq!(tx.sample_rate_hz, 20_000_000);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`VhtTransmission` retains the compiled MAC, FCS-bearing MPDU, padded PSDU,
APEP length, symbol/sample geometry and both derived and transmitted
signaling bits. Explicit FCS and SIGNAL overrides survive encoding, including
intentionally invalid values. Allocation and duration limits remain explicit
in `VhtTxConfig`.

For the interchangeable packet interface, select
`WifiPhy::Vht20 { mcs: 8, short_guard: true, ldpc: true }`. An explicit
`WifiPacketEncoder::Vht20(config)` can preserve additional encoder settings.
The monitor backend expresses the requested PHY using radiotap VHT fields;
the device driver determines whether it honors those requests.

## Receive and compare

`WifiDecoder` and its parallel/windowed variants classify VHT after common
legacy OFDM acquisition. VHT reuses OFDM synchronization, equalization,
constellation mapping, LDPC primitives and aggregate publication. VHT-specific
signaling, duration, SERVICE, pilot rotation and LDPC tone mapping live under
`radio/wifi/vht`.

`PhyDiagnostic::VhtSignal` preserves SIG-A fields.
`PhyDiagnostic::VhtSignalB` reports SIG-B after validating its SERVICE CRC.
Aggregate members retain their delimiter offsets and the containing PPDU's
sample interval; equal payloads in separate receptions remain separate events.

The `radio_receive` example's `--modern` selection includes VHT, with `vht`
metadata in frame records. `radio_compare` uses observed radiotap VHT MCS,
NSS, guard interval, bandwidth and coding. Missing STBC/group observations
remain unknown; incompatible known fields prevent a PHY-qualified match.
The `radio_transmit` example adds `--family vht20`; `--matrix` selects all 36
MCS/coding/guard combinations. These examples operate offline by default.

The deterministic corpus includes 235 independent positive waveforms and 11
negative controls, plus independent LDPC rate-matching dimensions. It covers
stream boundaries, frequency offset/multipath, duplicate occurrences, damaged
aggregate members, limits and explicit overrides. Offline waveforms establish
codec behavior; hardware qualification also needs retained RF captures and
independent receiver observations.

## Hardware qualification limits

Paired 5 GHz captures exercise ordinary station traffic, identifiable monitor
injection and HackRF transmission with MT7612U and RTL8812AU receivers. Raw
IQ, reference pcaps, acquisition counters, clock bounds and per-case recovery
counts belong to the external qualification artifacts. The library contains
the codec and deterministic fixtures; device setup and live collectors remain
operator supplied.

High-order modulation needs adequate received signal quality. MCS8 recovery
varies considerably with RF gain and the transmitting device; observing a
valid packet establishes interoperability without establishing a reliable link
budget. A complete list of generated modes is not a claim of complete RF
recovery on every receiver.

Reference drivers can omit STBC/group information or report coding fields that
conflict with independent observations. Preserve those gaps and conflicts when
comparing PHY metadata. Exact MAC-byte overlap and complete observed PHY
agreement are separate measurements. A transmitter's local radiotap echo
records its request, so independent reception is needed to verify the signal
that reached the air. Saved-IQ replay measures decode behavior rather than
sustained real-time throughput.
