# Legacy Wi-Fi IQ receive and transmit

The optional `radio` feature decodes legacy OFDM and DSSS/CCK IQ into ordinary
libcrafter packets and encodes bare typed Wi-Fi packets as owned CS8 waveforms at
a 20 Msps source clock. It supports offline replay and generation without
hardware; `radio-hackrf` adds explicit bounded native reception and transmission. Three independent
paired live runs qualified DSSS and CCK agreement with a separate Wi-Fi receiver;
the earlier OFDM qualification and its replay regression evidence are retained
separately below.

## Boundary and scope

IQ sources supply owned sample chunks to a stateful PHY decoder. Reconstructed
MAC bytes enter the existing packet decoder and `PacketSource` surface. IQ is
never a `Raw` packet layer. Original recovered bytes remain available even when
the parsed packet is later modified. RF context coexists with Wi-Fi metadata.

`IqSource` supplies `IqEvent` values to a `PhyDecoder`. The provided
`ReaderIqSource` reads signed interleaved 8-bit I/Q. `LegacyWifiDecoder` combines
OFDM and DSSS/CCK reception; `LegacyOfdmDecoder` and `DsssCckDecoder` select one
receiver explicitly. Each reconstructs FCS-valid `RecoveredFrame` values.
`RadioPacketSource::new(source, decoder, bounds)` implements the ordinary
`PacketSource` contract and can be consumed by `Sniffer`. It calls
`Packet::decode_from_link(LinkType::Ieee80211, ...)` after stripping the verified
four-byte FCS from parser input only. `PacketRecord` retains the original
FCS-bearing bytes and additive `RadioReceiveMetadata`; Wi-Fi annotations remain
available independently. Future sources can implement `IqSource` without
changing the PHY decoder or the packet parser.

Supported modes are legacy OFDM with 20 MHz channel spacing (including ERP-OFDM)
and DSSS/CCK at 1, 2, 5.5 and 11 Mbps. Long preambles support all four
DSSS/CCK rates; short preambles support 2, 5.5 and 11 Mbps. DSSS-OFDM, PBCC,
HT, VHT, HE, half-clocked and quarter-clocked OFDM remain unsupported. A valid
legacy SIGNAL alone does not prove a supported frame:
later PHY formats can share a legacy preamble. DATA integrity must also pass.
There is no decryption, association, authentication, scanning, retransmission,
rate-control, or other Wi-Fi state-machine API. Radiotap monitor injection is a
separate link-layer path; native packet-to-IQ transmission is described below.

## Packet-shaped IQ transmission

`RadioPacketWriter<S>` implements the ordinary `PacketWriter` contract for a
bare `Dot11 / ...` packet stack. `encode_record()` compiles the packet without
opening hardware and returns an owned `LegacyWifiTransmission`; `write_record()`
passes that value to an `IqSink`. `MemoryIqSink` is the deterministic offline
sink. A radiotap root is rejected because radiotap is capture metadata rather
than part of the transmitted MAC frame.

```rust
use crafter::prelude::*;

let packet = Dot11::data()
    .addr1(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]))
    .addr2(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]))
    .addr3(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x03]))
    / Raw::from("offline IQ");
let writer = RadioPacketWriter::new(
    LegacyWifiTxConfig::ofdm(LegacyOfdmRate::Mbps6),
    MemoryIqSink::new(),
);
let tx = writer.encode_record(&PacketRecord::new(packet))?;
assert_eq!(tx.sample_count() * 2, tx.cs8().len());
# Ok::<(), Box<dyn std::error::Error>>(())
```

The closed transmit matrix has fifteen cases: OFDM at 6, 9, 12, 18, 24, 36,
48, and 54 Mb/s; DSSS/CCK at 1, 2, 5.5, and 11 Mb/s with a long preamble; and
2, 5.5, and 11 Mb/s with a short preamble. Short-preamble 1 Mb/s is rejected.
Every mode produces signed, interleaved 8-bit I/Q (`I0,Q0,I1,Q1,...`) at exactly
20,000,000 complex samples per second. One complex sample therefore occupies
two bytes. Literal WAV/RIFF files, later HT/VHT/HE PHYs, DSSS-OFDM, PBCC, and
reduced-clock PHYs are outside this surface.

`WifiFcsPolicy::Auto` appends a derived IEEE 802.11 FCS. `Explicit([u8; 4])`
places those four bytes on the wire unchanged, including an intentionally bad
FCS. OFDM derives SIGNAL rate, length, parity, reserved and tail bits unless
`LegacyOfdmTxConfig::signal_override` is set. DSSS/CCK derives SIGNAL, SERVICE,
LENGTH, length extension, and PLCP CRC unless
`LegacyDsssCckTxConfig::plcp_override` is set. Scrambler seeds, leading and
trailing samples, amplitude, PSDU limit, and generated-sample limit are explicit
and validated. Overrides change the requested wire fields verbatim; they do not
silently select a different modulation.

The owned transmission retains compiled MAC bytes without FCS, the transmitted
PSDU including FCS, CS8 samples, PHY selection, sample count, rate/preamble,
derived and transmitted PLCP fields, override indicators, sample layout, scale,
and scrambler settings. Invalid combinations, unsupported sample rates,
oversized PSDUs, invalid seeds or amplitudes, arithmetic overflow, and waveform
sizes beyond `max_samples` return structured `RadioError` values before a sink
accepts samples.

Run the offline example without arguments for one 6 Mb/s case, or generate the
complete matrix and non-overwriting CS8 files:

```sh
cargo run -p crafter --features radio --example radio_transmit
cargo run -p crafter --features radio --example radio_transmit -- \
  --matrix --save-iq target/radio-transmit/offline
```

Its JSON Lines schema is `crafter.radio.transmit/v1`: a header declares the
case count, CS8 format, 20 Msps rate, and offline state; each case records its
stable ID, family, bit rate, preamble, complete MAC and FCS-bearing PSDU hex,
sample count, CS8 SHA-256, and optional IQ path; the terminal summary must say
`complete:true` and `terminal:"complete"`. Files use create-new semantics and
are never silently overwritten.

### Explicit bounded HackRF transmission

`HackRfTxSink::open_live(HackRfTxConfig { ... })` exists only with
`radio-hackrf`. Merely constructing `LegacyWifiTxConfig`, encoding a packet, or
using `MemoryIqSink` cannot open a device. Live configuration requires a
nonempty device serial, center frequency, exactly 20 Msps, nonzero baseband
filter, TX VGA gain from 0 through 47 dB, explicit amplifier and antenna-power
states, and nonzero duration, supplied-sample, and repetition bounds. The
inter-burst gap, delay between matrix cases, OFDM CS8 scale, and case selection
are also explicit. `--case-id all` emits the selected matrix; a stable case ID
emits only that case so a qualification runner can retry device failures
without invalidating successful cases. The complete repeated waveform and gaps
must fit `max_supplied_samples` before transmission begins.

```text
cargo run --release -p crafter --features radio-hackrf --example radio_transmit -- \
  --live-hackrf --serial SERIAL --frequency-hz HZ --sample-rate-hz 20000000 \
  --filter-hz HZ --tx-gain-db DB --amplifier false --antenna-power false \
  --max-duration-ms MS --max-samples N --repetitions N --gap-samples N \
  --case-gap-ms MS --ofdm-scale SCALE --case-id all --matrix true
```

The native callback owns its waveform and initializes every valid transfer
byte; the final transfer is rounded to a USB packet, zero-padded to that
boundary, and padding is counted separately. RX and
TX share one process-wide libhackrf ownership lock. Cancellation, deadline,
native start/stop/query errors, firmware shortfalls, incomplete repetitions,
and invalid callback buffers fail with a structured error. `HackRfTxStats`
reports requested, supplied, padded and discarded samples, callbacks, completed
repetitions, firmware shortfalls, longest shortfall, cancellation, and whether
the device stopped. Callback panics are caught before the FFI boundary, stop
quiesces callbacks before their context is released, and dropping the sink
attempts TX stop and device close. Treat any non-complete terminal state as a
failed run and restore external device and capture state after every attempt.

### External transmit qualification

Generate the `crafter.radio.transmit/v1` plan from the exact candidate revision,
then have operator-supplied, untracked tooling transmit each case and capture a
radiotap pcap. The repository comparator accepts only radiotap records, removes
the capture header, rejects truncation and bad-FCS indications, and strips an
FCS only when radiotap says it is present and the trailer verifies. With absent
FCS it compares every captured MAC byte to the planned MAC bytes and labels
integrity `absent`; that match is useful but does not prove FCS integrity.

An eligible match requires complete normalized MAC-byte equality plus the
observed legacy rate and short/long preamble state. Matching consumes capture
occurrences one-to-one, so repeated receptions of one case cannot cover another
case. The comparison output uses `crafter.radio.transmit-comparison/v1` and
must report all 15 cases passed. Final `crafter.radio.transmit-qualification/v1`
evidence requires at least three independent bounded runs from one unchanged
candidate revision. Each run must cover all fifteen cases, have complete
transmit and capture artifacts, contain no underrun, shortfall, truncation,
bad-FCS, rate/preamble mismatch, timeout, cancellation, or cleanup failure, and
record successful restoration of external state.

Keep the aggregate, comparisons, CS8 files, pcaps, device settings, and cleanup
receipts in ignored storage such as `target/`. Do not commit VM aliases, device
serials, credentials, interface names, RF topology, public addresses, or raw
captures. Machine provisioning and hardware orchestration remain external to
the crate. `radio_compare --compare-transmit PLAN.jsonl CAPTURE.pcap
REPORT.json` creates one comparison; `radio_compare
--verify-transmit-qualification QUALIFICATION.json` verifies the aggregate and
its referenced files.

The qualification aggregate has a lowercase 40-hex `revision` and at least
three uniquely named runs. Each run repeats that revision and provides a
nonempty `settings` object, `cleanup:true`, `invalidating_failures:0`, and
`capture`, `comparison`, and `transmits` file records. A file record is
`{"path":"relative/child","sha256":"..."}`. The verifier rejects absolute
or parent paths, empty files, digest changes, incomplete comparison matrices,
and live transmit artifacts with missing cases, duplicate cases, shortfalls,
sample-count disagreement, cancellation, or an incomplete stop. Multiple
bounded transmit artifacts may jointly cover the fifteen cases in one run.

Revision `11b4d1fccf647a4ecf30e5906de25acbd55a6747` passed this
qualification in three independent bounded runs. Every run produced exact MAC
matches for all eight OFDM rates and all seven valid DSSS/CCK rate/preamble
cases, with zero accepted transmit shortfalls and successful cleanup. The
receiver omitted FCS in these captures, so the result qualifies MAC bytes,
radiotap rate, and DSSS/CCK preamble agreement while recording FCS integrity as
absent. The runs used 20 Msps, a 20 MHz filter, disabled RF amplifier and
antenna power, OFDM TX gain 47 dB, OFDM scale 450 except scale 400 at 48 Mb/s,
and DSSS/CCK TX gains of 20, 30, or 47 dB as recorded per bounded artifact.

## Primary evidence

The normative source reviewed for this implementation is
[IEEE Std 802.11-2007](https://www.cs.mun.ca/~yzchen/bib/802.11-2007.pdf), a
university-hosted copy of the IEEE publication. Download SHA-256:
`54368534fc6e29eb787809c78418f499409ab471f189842544ff56b84616f664`.
The source itself identifies its edition and publisher. References below use
that edition's clause numbers, not clause numbers from newer editions.

| Area | Source location | Implementation obligation |
| --- | --- | --- |
| Rates and timing | 17.3.2.2–17.3.2.5, Tables 17-3/17-4 | Use the 20 MHz column only; distinguish sample clock from RF bandwidth. |
| Synchronization | 17.3.3, Equations 17-6/17-8 | Validate short and long training; estimate timing, frequency offset and channel. |
| SIGNAL | 17.3.4, Table 17-5 | Decode BPSK rate-1/2 without descrambling; validate rate, parity, reserved bit and tail. |
| DATA layout | 17.3.5.1–17.3.5.4 | Recover SERVICE, PSDU, tail and padding; infer a nonzero scrambler state. |
| Coding | 17.3.5.5, Figures 17-8/17-9 | Constraint length 7; generators 133/171 octal; preserve A-before-B and puncturing order. |
| Interleaving | 17.3.5.6 | Invert both permutations within each OFDM symbol. |
| Constellations | 17.3.5.7, Figure 17-10 | Preserve Gray mapping and normalization for each rate. |
| Pilots | 17.3.5.8–17.3.5.9 | SIGNAL uses polarity index 0; DATA starts at index 1. |
| MAC integrity | 7.1.3.7 | Verify CRC over MAC header and body, excluding the received FCS. |
| ERP | 19.3.2.3 | Same OFDM decode, with a 6 microsecond signal extension outside PSDU bytes. |
| Independent example | Annex G | Cross-check intermediate values before relying on generated vectors. |

The RFC/IANA discovery tool returned no IEEE PHY evidence. Its empty manifest
is not an authority for these facts; the reviewed IEEE document and section
map above provide the supplementary protocol evidence manifest.

## Rate and bit conventions

RATE bits below are written in transmission order R1 through R4. They must not
be confused with a numeric hexadecimal field read most-significant-bit first.

| Mb/s | R1–R4 | Modulation | Code rate | Coded bits/symbol | Data bits/symbol |
| --- | --- | --- | --- | --- | --- |
| 6 | 1101 | BPSK | 1/2 | 48 | 24 |
| 9 | 1111 | BPSK | 3/4 | 48 | 36 |
| 12 | 0101 | QPSK | 1/2 | 96 | 48 |
| 18 | 0111 | QPSK | 3/4 | 96 | 72 |
| 24 | 1001 | 16-QAM | 1/2 | 192 | 96 |
| 36 | 1011 | 16-QAM | 3/4 | 192 | 144 |
| 48 | 0001 | 64-QAM | 2/3 | 288 | 192 |
| 54 | 0011 | 64-QAM | 3/4 | 288 | 216 |

At 20 Msps, a useful symbol has 64 samples and its ordinary guard has 16.
There are 48 data carriers and four pilots; DC is unused. The preamble has
160 short-training samples, followed by a 32-sample guard and two 64-sample
long-training periods. Synchronization must tolerate arbitrary chunk boundaries.

SIGNAL has 24 decoded bits: RATE, reserved zero, 12-bit little-endian LENGTH,
even parity over bits 0–16, and six zero tail bits. Reject unsupported RATE,
nonzero reserved/tail, failed parity and lengths outside the configured bound.
LENGTH is PSDU octets, including MAC FCS; it excludes SERVICE and PHY padding.
The number of DATA symbols is `ceil((16 + 8 * LENGTH + 6) / NDBPS)`.

PSDU octets enter the bit stream least-significant bit first. The DATA scrambler
uses `x^7 + x^4 + 1`; the first seven zero SERVICE bits identify its initial
state. Reserved SERVICE bits must decode to zero. The receiver may reject a
frame early only when every surviving trellis path already has an invalid
SERVICE prefix; later input cannot change those prefixes. Independent fixtures
include a corrupted reserved SERVICE bit with a valid PSDU FCS.

The six encoder tail bits are forced to zero *after* scrambling at the
PSDU boundary; do not validate them as ordinary descrambled zeros. Padding
follows the tail, so the final padded trellis state need not be zero. Receive
PLCP discards PAD after the indicated PSDU (17.3.12); nonzero padding does not
invalidate an otherwise FCS-valid frame. An independent fixture deliberately
sets a PAD bit to verify this receiver behavior.

For reflected byte-oriented CRC arithmetic use polynomial `0xedb88320`, initial
remainder `0xffffffff` and final XOR `0xffffffff`; compare its little-endian
four-byte representation with the received trailer. This is the byte-oriented
equivalent of the polynomial/serial convention in 7.1.3.7. Tests must verify
the equivalence using independent vectors, not two copies of the same helper.

The independent OFDM fixtures include a 6 Mb/s case with stronger additive noise
to exercise acquisition at lower signal-to-noise ratios. Repetition checks admit
these candidates; SIGNAL validation and a valid PSDU FCS still govern delivery.
A strong delayed-path fixture also exercises acquisition when multipath reduces
correlation with the ideal long-training waveform.

## Continuity and bounded processing

Legacy OFDM DATA fits a channel-weighted pilot phase offset and subcarrier slope
per symbol to correct sampling-clock drift. Independent fixtures cover all eight
rates, short and 4095-byte PSDUs, and -20/0/+20 ppm receive-clock offsets with
zero carrier offset. Exact PSDU/FCS recovery is checked at two chunk sizes.
This is bounded drift correction, not arbitrary sample-rate conversion; larger
drift, combined impairments and live clock offsets require separate evidence.

Legacy OFDM acquisition continues while DATA is pending, retaining at most two
candidates whose sample reservations share `max_buffer_samples`. A false long
SIGNAL length therefore need not hide a later valid frame. Candidates beyond
the slot or sample budget are rejected; this bounded search is not an unlimited
collision decoder. Gaps and end events discard all incomplete candidates.

Each chunk identifies its sample format, stream epoch, sequence, absolute sample
position, configuration and any time anchor with uncertainty. A gap of unknown
size cannot be represented as a known zero-sized loss. Loss, reconfiguration,
reordering and overflow reset affected PHY state. Cancellation and EOF discard
incomplete frames with inspectable diagnostics. Bounds apply to sample buffers,
frame length, pending output, capture duration and native callback queues.

## Receiver comparison policy

Compare the original bytes, never `Packet::compile()` output. Remove only the
capture header, explicitly indicated capture padding, and an explicitly present
FCS trailer. The [Radiotap Flags definition](https://www.radiotap.org/fields/Flags.html)
defines FCS, bad-FCS and data-padding indications; the
[Rate definition](https://www.radiotap.org/fields/Rate.html) defines legacy rate
units. Unsupported or unparseable framing is an exclusion, not a guessed offset.

An SDR candidate must have a verified received FCS. Reject reference frames
marked bad-FCS, truncated frames, and present trailers that fail verification.
A reference with an omitted FCS may be byte-compared but remains separately
counted as integrity-unverified; never label an absent trailer valid.

Eligibility requires an observed supported legacy PHY rate, configured channel,
and a shared usable capture interval. Unknown rate, incompatible PHY metadata,
unqualified sample continuity and boundary-time uncertainty are separately
reported exclusions. Do not infer a PHY rate from advertised supported rates.
Freeze configuration and eligibility rules before measuring the baseline.

Use one-to-one occurrence matching by complete normalized bytes and bounded
time windows. A hash indexes candidates but full bytes establish equality.
Do not collapse repeated ACKs, retries or identical frames into one occurrence.
Report eligible counts for both receivers, matched occurrences, each receiver's
matched fraction, unique-byte overlap, interval policy and every exclusion.
A zero denominator is inconclusive, never a pass.

Record a numeric target and minimum eligible/matched counts from the initial
baseline before optimization. Keep the target fixed during iteration. Final
qualification requires at least three independent bounded runs, each with real
FCS-valid SDR matches and the fixed target satisfied. Preserve raw evidence,
candidate identity and cleanup results privately; synthetic vectors and transport
checks alone cannot satisfy this gate.

## Explicit HackRF reception

`radio-hackrf` enables `radio` plus a small native RX/TX FFI boundary.
The rest of the crate denies unsafe Rust; only the private native module permits
it. Install libhackrf development and runtime libraries with the
`hackrf_get_m0_state` API (firmware USB API >= 0x0106). Link with `libhackrf` on
the normal native library search path. Custom installations can supply
`LIBRARY_PATH` at link time and their platform's runtime loader search path.
Offline `radio` builds and mock tests do not link or open libhackrf.

The ABI and lifecycle were reviewed against Great Scott Gadgets' libhackrf
`host/libhackrf/src/hackrf.h` and `hackrf.c`, revision `cc691022`.
`hackrf_stop_rx` and `hackrf_stop_tx` cancel their respective transfers;
`hackrf_close` joins the event thread before the callback context is freed. Callback panics
are caught before returning across FFI. A native thread-join failure aborts the
process because the library cannot establish safe memory lifetime afterward.
Native USB calls and shutdown retain the library's timeout/OS scheduling
latency; the capture deadline prevents accepting further samples and an
independent supervisor initiates shutdown without requiring consumer polls.
Only one crafter acquisition may own libhackrf in a process at a time; callers
must not manipulate the same library lifecycle through unrelated bindings.

`HackRfSource::open_live(HackRfConfig { ... })` is the explicit runtime opt-in.
A nonempty device serial, RF frequency, sample rate, baseband filter, LNA/VGA
gains, amplifier state, antenna power state and finite sample/duration bounds
are required. The filter is set **after** sample rate because setting the rate
also changes the native filter. All settings are inspectable Rust values.
The source does not provision devices, change host scheduling or transmit.

Ready chunks may be combined up to `max_chunk_samples` when their original
sample coordinates are contiguous. Coalescing uses only already-verified queued
data, never waits to fill a batch, and never crosses a discontinuity. Emitted
chunk sequence numbers remain consecutive; sample coordinates and acquisition
counters retain their original meaning.

The callback owns copied cs8 data before returning. Pending and verified chunks
share `max_buffer_samples`; overflow terminates acquisition with a structured
error. A query outside the callback verifies only samples received before that
query began. Samples arriving during a query wait for the next query. Firmware
shortfall counters must remain zero while actively receiving; changed,
unavailable or erroneous counters stop acquisition and discard the unverified
interval. The verified prefix remains readable before a sticky error. Shutdown
never retroactively qualifies the remaining tail, even if firmware clears its
counters. No exact lost-sample count or fabricated time anchor is inferred.
`stats()` retains discarded-sample, overflow and unknown-continuity diagnostics
including a final gap when no subsequent chunk exists. Cancellation drops all
queued samples and joins the supervisor. Consumer slowness therefore produces
bounded loss/error rather than unlimited memory growth.

The example emits JSON Lines containing original FCS-bearing MAC bytes, a
completion summary, and (for live operation) acquisition counters. With no
arguments it replays the independent synthetic 6 Mb/s fixture:

```sh
cargo run -p crafter --features radio --example radio_receive
cargo run -p crafter --features radio --example radio_receive -- --replay samples.cs8
```

Raw replay defaults to 20 Msps, one second and 20 million samples at the
documented example frequency. `--replay FILE HZ SECONDS MAX_SAMPLES` supplies
explicit frequency and longer bounds. Live invocation requires every setting explicitly:

```text
cargo run --release -p crafter --features radio-hackrf --example radio_receive -- \
  --live SERIAL FREQUENCY_HZ DURATION_SECONDS MAX_SAMPLES FILTER_HZ LNA_DB VGA_DB AMP_BOOL BIAS_BOOL
```

For the qualified 20 Msps combined receiver, set `FILTER_HZ` explicitly to
`20000000`.
The source can outpace the synchronous decoder; increase the explicit buffer
bound in operator code only within an appropriate finite memory budget. Actual
live decoder throughput and receiver agreement require separate qualification.


## Local artifact and comparison schema v2

`radio_receive` writes newline-terminated JSON records with a first `header`
record whose `schema` is `crafter.radio.receive/v2`. Example-local serde support
keeps serialization out of the packet library. Config fields include frequency,
sample rate, all allocation/sample bounds and `max_duration_ns`. Positions carry
`epoch`, `sequence`, `sample_index`, nullable `anchor` (sample index, Unix
nanoseconds, uncertainty nanoseconds), nullable `gap_reason` and nullable
`lost_samples` (null means unknown when a gap exists).

Records are ordered: header, verified `chunk`/`frame`/`parser_error` events,
`terminal`, `summary`, and an optional live `acquisition` record. Each chunk
records config, position, sample count, verified-prefix status and a nullable
software time bracket. Each frame records original FCS-bearing MAC hex, ordinal,
legacy PHY rate, integrity state, config, start position, exclusive sample end
and diagnostics. Frame output occurs before packet parsing. Parser failures are
recorded and consumption continues; PHY/FCS rejection counters remain separate.
The summary records terminal/error state and decoder counters. Acquisition adds
received, verified and discarded sample counts, overflows, unknown loss intervals
and explicit RF settings. Failed capture summaries are never accepted as complete
comparison input. A missing terminal or summary is an incomplete artifact.

Append `--save-iq NEW_FILE` to a receive/replay invocation to create an optional
IQ artifact without overwriting an existing file. Its JSON header declares
`iq_encoding: "cs8-binary/v1"`. Each chunk metadata JSON line is followed by
exactly `samples * 2` signed 8-bit interleaved I/Q bytes and one newline byte.
Terminal/error records are JSON lines without sample blocks. The configured
sample bound limits file size to two bytes per complex sample plus metadata.
Replay also accepts earlier JSONL artifacts containing `cs8_hex` and no
`iq_encoding` header field. Only the preverified
prefix is saved. A source failure writes a `source_error` record instead of a
successful terminal event; replay decodes the saved prefix and then reports that
failure with `complete:false`. Missing terminal evidence also fails replay.
Replay uses the full saved bounds, configuration and positions.

Recording uses a worker with an eight-chunk queue, separate from the acquisition
queue. A full recording queue or file error fails capture; success is reported
only after the worker flushes and joins. The summary includes `recording_error`.
File operations retain the operating system's I/O latency, including at shutdown.

Use `--chunk-samples N` after the optional `--buffer-samples N` to set the
source chunk limit for live reception or raw replay (128–262144 complex samples;
default 65536). The chunk must fit the buffer. Saved IQ artifacts retain their
recorded configuration. Larger chunks reduce parallel worker synchronization
frequency but can delay frame delivery; this option does not increase the queue
budget or establish sustained reception. At 20 Msps, 262144 samples represent
13.1 ms of input, compared with 3.3 ms for the default limit.

The example accepts an optional leading `--buffer-samples N` for live reception
or raw replay (65536–536870912 complex samples; default 16777216). The maximum
allows 1 GiB of queued CS8 data, plus chunk metadata and decoder state. Memory
is consumed as samples arrive. Size the queue for the available memory and
allow additional time to drain it after bounded reception stops. A 20-second
capture at 20 Msps contains at most 800 MB of CS8 data. Saved artifacts
retain their own configuration. Acquisition overflow errors report pending,
verified-ready, incoming and allowed sample counts to distinguish verification
backlog from consumer backlog. A larger finite buffer absorbs bursts; it does
not remove loss checks or certify sustained throughput.

```sh
cargo run -p crafter --features radio --example radio_receive -- --save-iq saved-iq.iq
cargo run -p crafter --features radio --example radio_receive -- --replay-artifact saved-iq.iq
cargo run -p crafter --features radio --example radio_compare -- receive.jsonl reference.pcap policy.json
```

`policy.json` is an explicit, operator-recorded timing and eligibility contract:

```json
{
  "schema": "crafter.radio.comparison-policy/v1",
  "overlap_ns": [1000000000, 2000000000],
  "hackrf_capture_ns": [900000000, 2100000000],
  "reference_capture_ns": [900000000, 2100000000],
  "center_frequency_hz": 2412000000,
  "reference_uncertainty_ns": 1000000,
  "match_window_ns": 1000000,
  "anchors": [
    {"epoch": 0, "sample_index": 0, "unix_ns": 1000000000, "uncertainty_ns": 1000000}
  ],
  "max_observations": 10000
}
```

The timestamps above are synthetic examples, not measured synchronization.
Intervals are half-open Unix nanoseconds. Both declared capture intervals must
contain the requested overlap. A recorded frame anchor takes precedence over an
external epoch anchor; each supplied epoch must be unique. External anchors must
come from separately recorded measurements, with uncertainty covering software
latency, clock offset/drift and timestamp placement. The native source supplies
no hardware anchor. Its software bracket spans before device open through chunk
delivery; it is retained as coarse evidence and is **not** converted into a
precise sample timestamp. No file mtime is consulted. Unknown timing excludes a
frame; boundary uncertainty excludes it unless the entire frame fits the overlap.
Pcap timestamps are converted to nanoseconds by libpcap; the policy uncertainty
must include their actual precision and semantics.

The comparator accepts radiotap pcap records only. It parses the capture header
separately from the MAC body, requires explicit flags, a supported legacy rate
and the selected frequency, and excludes incompatible PHY/channel metadata.
Unparseable namespaces and newer PHY fields are exclusions. Explicit DATAPAD
removes only the alignment bytes between a recognized legacy MAC header and its
body. Unknown/Order/extension padding layouts are excluded. FCS is recomputed
after that removal, then stripped only when explicitly present. The documented
[radiotap flags source](https://github.com/radiotap/radiotap.github.io/blob/master/fields/Flags.md)
and [rate source](https://github.com/radiotap/radiotap.github.io/blob/master/fields/Rate.md)
are the framing authority; MAC geometry follows the existing IEEE evidence and
library layouts. Absent reference FCS remains separately integrity-unverified.
MAC sequence, retry, duration and all other bytes survive normalization.

Output schema `crafter.radio.comparison/v2` contains the complete policy,
`eligible_dongle_count`, `hackrf_valid_count`, `exact_matches`, both directional
fractions, unique-byte overlap, per-source exclusion counts and maximum timing
uncertainty, receive/acquisition evidence, SHA-256 digests of the three inputs, and one row per matched occurrence
with both ordinals and full normalized bytes. No digest substitutes for equality.
Verified contiguous chunk intervals qualify each recovered frame. Matching pairs
compatible time intervals within `match_window_ns` one-to-one, preserving retries
and identical ACK multiplicity. Zero denominators produce null fractions and
`inconclusive`; otherwise status is `measured`. `target_assessed` is always false:
baseline, numerical target selection and live qualification belong to the
external qualification runner, not the comparator.
The offline example caps each source at 10,000 observations and each JSON line at
1 MiB; exceedance fails explicitly. Dense duplicate matching is quadratic within
that bound. Inputs must be closed captures; before/after hashes detect changes during processing.
Reference capture loss is explicitly unavailable from the pcap alone.
Keep real artifacts and timing policies outside tracked files.


## Qualification and limits

### Earlier OFDM qualification

The standalone OFDM candidate at functional revision `fce1ad75` passed three independent 20-second captures at
20 Msps with a 20 MHz baseband filter, LNA gain 40 dB, VGA gain 4 dB, and both
RF amplifier and antenna power disabled. The optimized native example used a
16,777,216-sample acquisition bound. These are measured settings for one
receiver environment, not universal gain defaults or a throughput guarantee.

| Run | Eligible HackRF frames | Eligible reference frames | Exact matches | HackRF matched | Reference matched |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 203 | 225 | 187 | 92.12% | 83.11% |
| 2 | 73 | 113 | 71 | 97.26% | 62.83% |
| 3 | 53 | 50 | 30 | 56.60% | 60.00% |

Each run exceeded the previously frozen 50% overlap requirement in both
directions and the minimum counts of 5 HackRF frames, 10 reference frames and
5 exact matches. Counts are eligible occurrences within the comparison interval,
not all frames seen during the invocation. All three acquisitions reported zero
sample loss, queue overflow, discarded samples, recording errors and parser
errors. Raw IQ replay with the same native executable reproduced every frame
record exactly. Cross-platform replay reproduced packet bytes and sample
positions exactly; small floating-point RF diagnostic differences were checked
with explicit tolerances. Candidate, library, artifact and cleanup evidence is
retained privately; no live capture or receiver identity is shipped here.

This evidence establishes bounded receive agreement for the observed traffic.
Independent synthetic OFDM fixtures cover all eight listed OFDM rates, including adverse
and rejected inputs; the live results do not establish equal sensitivity at
every rate, universal real-time throughput, or support for later Wi-Fi PHYs.
Unsupported observations and corrupt signals can be rejected without a reliable
PHY-family classification; a rejected candidate is not proof of HT/VHT/HE.
Software timestamp uncertainty also limits temporal discrimination between
identical repeated frames.

Decoder work varies with signal density and apparent frame lengths. Use optimized
builds for native reception, bound every queue, and treat a source or recording
overflow as failed continuity rather than silently accepting the remaining
capture. Requalify changed runtime code, RF settings or execution environments;
increasing a buffer alone does not establish sustained operation.

### Combined receiver qualification

The extended receiver at functional revision `878c7f46` passed three independent
20-second paired captures at 20 Msps with a 20 MHz analog filter. The native
executable and build inputs were identical across these runs. Run A used
LNA/VGA gains of 32/12 dB; B and C used 40/4 dB. Amplifier and antenna power
were disabled. Each run allowed 400 million queued complex samples (up to
800 MB of CS8 data plus metadata), followed by a bounded 180-second drain.
This demonstrates bounded acquisition and eventual decoding, not sustained
real-time processing.

| Run | Family | Eligible HackRF | Eligible reference | Exact matches | HackRF matched | Reference matched |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| A | DSSS | 1135 | 929 | 708 | 62.38% | 76.21% |
| A | CCK | 122 | 182 | 121 | 99.18% | 66.48% |
| B | DSSS | 1183 | 1159 | 851 | 71.94% | 73.43% |
| B | CCK | 11 | 22 | 11 | 100.00% | 50.00% |
| C | DSSS | 1383 | 1401 | 1039 | 75.13% | 74.16% |
| C | CCK | 62 | 95 | 60 | 96.77% | 63.16% |

For each row, HackRF matched means exact matches divided by eligible HackRF
occurrences; reference matched uses the reference denominator. For example,
run B CCK matched all 11 HackRF frames but only 11 of 22 reference frames.
Each family independently met the frozen minimum of 50% in both directions,
5 eligible HackRF frames, 10 eligible reference frames and 5 matches in every
run. These are complete eligible occurrences, not selected packet types or
unique byte strings. Timing used an independently recorded first-chunk software
anchor, a 1 ms reference uncertainty and a fixed 10 ms matching window; packet
matches were never used to fit the clock.

| DSSS/CCK rate | Run A H / R / matches | Run B H / R / matches | Run C H / R / matches | Live interpretation |
| --- | ---: | ---: | ---: | --- |
| 1 Mbps | 1135 / 929 / 708 | 1183 / 1159 / 851 | 1383 / 1401 / 1039 | Repeated successful DSSS agreement |
| 2 Mbps | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | Absent; not live-qualified |
| 5.5 Mbps | 0 / 0 / 0 | 0 / 0 / 0 | 4 / 3 / 3 | Three exact matches; too sparse for independent rate qualification |
| 11 Mbps | 122 / 182 / 121 | 11 / 22 / 11 | 58 / 92 / 57 | Repeated successful CCK agreement |

H and R are eligible HackRF and reference counts. Independent offline fixtures
cover all four rates and all seven valid rate/preamble combinations, including
clock/carrier offsets, channel echoes and rejected inputs. Family qualification
does not establish every rate's live sensitivity or preamble coverage.

All three accepted acquisitions had zero queue overflow, unknown sample loss,
discarded samples, reference kernel drops, parser errors and recording errors.
Exact replay with the captured native executable reproduced all 1302, 1196 and
1469 frame records respectively, including their chunk positions/counts.
The private verifier recomputed full-byte, equal-observed-rate matches from raw
inputs, checked artifact/build hashes and independently verified cleanup.
Reference reception required a temporary, narrowly scoped driver receive-filter
correction to include RTS frames; operator tooling verified and restored it.
That host-specific correction is not part of the crate.

These were independent successful runs selected from an iterative campaign,
not three consecutive successful attempts. Other attempts suffered USB transfer
shortfalls or failed the unchanged overlap targets; those failures remain in
private evidence. The implementation detects such loss and fails qualification.
It does not promise reliable uninterrupted USB capture in every environment.

The final combined receiver also replayed the three earlier OFDM recordings,
preserving all 203, 74 and 53 original recovered OFDM frame identities (330 total),
including bytes, rates and source positions. Those replay counts include original
frames outside the earlier comparison eligibility interval. This preserves the
earlier evidence; the new DSSS/CCK captures did not independently requalify OFDM
at their RF settings. Their OFDM H / R / match counts were 41 / 102 / 40,
1 / 260 / 1 and 15 / 146 / 13. No all-family or all-rate live claim follows.

## Local validation

The offline feature has no libhackrf dependency and leaves default features
unchanged. Run the feature tests and the ordinary static release gate locally:

```sh
cargo test -p crafter --features radio --all-targets
cargo fmt --all -- --check
.agents/scripts/check-crafter-release --static
```

Native mock/build checks require the separate native feature and development
library. Actual device qualification additionally requires bounded paired
captures, saved IQ replay, fixed eligibility and overlap rules, and independently
verified cleanup through operator-supplied untracked tooling. Offline tests alone
do not replace that evidence.

## DSSS/CCK receive contract

DSSS/CCK reception shares the existing packet boundary with OFDM. The same
IEEE 802.11-2007 PDF and SHA-256 above were retrieved and inspected for this extension. RFC/IANA
manifest discovery again returned no candidates or extracted facts. The following
reviewed IEEE map supplies the PHY evidence; an empty RFC manifest supplies none.

| Area | IEEE 802.11-2007 location | Receive contract |
| --- | --- | --- |
| Barker and differential mapping | 15.4.6.3–15.4.6.4; 18.4.6.4, Tables 18-10/18-11 | Eleven chips per DBPSK/DQPSK symbol; transmission-order dibits and positive counterclockwise phase. |
| Preamble, SIGNAL, SERVICE, LENGTH | 18.2.2–18.2.3.5; 18.2.3.7–18.2.3.14 | Distinguish long/short headers and payload modulation; recover exact PSDU octets. |
| PLCP CRC | 15.2.3.6, Figures 15-2/15-3; 18.2.3.6 | Check the 32 protected bits before descrambled payload processing. |
| Scrambling | 15.2.4; 18.2.4, Figures 18-5/18-6 | Self-synchronizing feedthrough descrambler, continuous across fields. |
| CCK | 18.4.6.5, Equation 18-1, Tables 18-12–18-14 | Eight complex chips per symbol, differential common phase, payload symbol parity. |
| Length ambiguity | 18.2.3.5, Table 18-2 | Integer microseconds are not an octet count; honor extension bit. |

Barker chips in time order are `+ - + + - + + + - - -`. DBPSK zero preserves
phase and one adds pi. DQPSK transmission-order dibits `00,01,11,10` add
`0,pi/2,pi,3pi/2`. Differential decisions compare symbol phase before Barker
spreading; the last negative Barker chip is not that phase reference.

Write CCK phases as `a,b,c,d`. Its eight chips are complex exponentials of
`a+b+c+d, a+c+d, a+b+d, a+d, a+b+c, a+c, a+b, a`, with signs of chips
3 and 6 inverted (zero-based). Chip 7 carries common phase `a`. The first
two serial bits select its differential change using DQPSK; add pi to that
change on odd payload symbols. Number the first payload symbol zero. Carry
the preceding header symbol phase into the first payload symbol, including
long-header DBPSK transitions; do not restart differential state at the PSDU.
For 5.5 Mbps, bits d2/d3 select `b=pi*d2+pi/2, c=0, d=pi*d3`.
For 11 Mbps, pairs d2/d3, d4/d5 and d6/d7 select b/c/d with the **binary** map
`00,01,10,11 → 0,pi/2,pi,3pi/2`, distinct from differential Gray mapping.

Long SYNC contains 128 input ones; short SYNC contains 56 input zeros. Long
SFD is `0xf3a0`, short SFD `0x05cf`, each serialized LSB first. Long preamble
and 48-bit header use 1 Mbps (192 microseconds total). Short preamble uses
1 Mbps and its header uses 2 Mbps (96 microseconds total). Short format permits
2, 5.5 and 11 Mbps payloads; reject short/1 Mbps. SIGNAL values are
`0x0a,0x14,0x37,0x6e`. Header fields and PSDU octets serialize LSB first.

The scrambler is not the OFDM additive scrambler. If y is the transmitted
scrambled bit, `y[n]=x[n] XOR y[n-4] XOR y[n-7]`; receive uses those delayed
received bits to recover x. HR initial delay states Z1..Z7 are `1101100`
(long) and `0011011` (short). Acquisition must not require one fixed long
SYNC waveform: Clause 18 also requires compatibility with Clause 15 seeds.
After seven received bits the descrambler history is known. Keep that history
through SFD, header, CRC and PSDU; do not reset at rate changes.

PLCP CRC covers SIGNAL, SERVICE and little-endian LENGTH, excluding SYNC/SFD.
Use polynomial x^16+x^12+x^5+1, initial all ones and complemented output.
A reflected implementation uses `0x8408`, final XOR `0xffff`, and little-endian
output. Verify against the literal example below; the CRC-16 is independent of
the existing MAC CRC-32. SERVICE bit 2 reports locked clocks and may be either
value; bit 3 selects unsupported PBCC; bit 7 disambiguates 11 Mbps LENGTH.
Reserved bits 0,1,4,5,6 must be zero for this supported contract.

For PSDU size N including MAC FCS, LENGTH is `8*N` at 1 Mbps, `4*N` at
2 Mbps, `ceil(16*N/11)` at 5.5 Mbps, and `ceil(8*N/11)` at 11 Mbps.
At 11 Mbps set extension E when `11*LENGTH-8*N >= 8`. Recover N with
`LENGTH/8`, `LENGTH/4`, `floor(11*LENGTH/16)`, or
`floor(11*LENGTH/8)-E`, respectively. Validate the forward conversion as well
as the inverse; reject impossible lengths, nonzero extension outside 11 Mbps,
unsupported SIGNAL/PBCC, invalid CRC, over-bound PSDUs, incomplete frames and
invalid MAC FCS. False acquisition never yields an unverified packet.

### Sample timing and bounded DSP design

The chip clock is 11 MHz; Barker symbols last 1 microsecond, while CCK symbols
last 8/11 microsecond. Keep hardware acquisition at the already qualified
20 Msps and feed OFDM the unchanged original samples. There are exactly 20/11
source samples per nominal chip, not two. No 22 Msps device capability is
assumed. HackRF's [sampling/filter guidance](https://hackrf.readthedocs.io/en/latest/sampling_rate.html)
explains why analog filtering and source sample rate must be considered together;
digital interpolation cannot undo aliasing or restore bandwidth already removed.

The DSSS receiver uses an eight-source-sample normalized windowed-sinc kernel
for initial acquisition, with eleven fractional phases selected by the rational
sample clock. Timing refinement and payload recovery use a 16-source-sample
kernel with 256 normalized fractional phases. Acquisition interpolates once onto
an internal half-chip grid and reuses a rolling 32-sample history for Barker
correlation across 22 timing phases. This internal 22 Msps clock does not request
a different hardware sample rate. The 64 original source samples, 16 mirrored
entries for contiguous filtering, 32 derived samples, and 32 cached scalar
powers fit within the existing 128-complex-sample history reservation. Caching
power avoids recalculating it when a chip leaves the rolling window while
preserving the floating-point accumulation order; no whole-capture
resampled buffer is allocated. Timing refinement and payload recovery still
interpolate directly at corrected source-domain chip positions. This reconstruction kernel is a receiver choice, not an IEEE-mandated
transmit pulse shape or spectral-mask claim. Independent vectors must include
bandlimited pulses and clock offsets; real 20 Msps agreement is a qualification
requirement, not a consequence of nominal chip timing alone.

Track source-domain chip time with a rational 20/11 nominal increment plus a
bounded timing correction; retain the accumulator across chunks. Barker
correlation supplies acquisition/early-late errors; estimate carrier rotation
from the repeated SYNC structure and maintain phase through rate transitions.
Use fixed search/history bounds and the configured PSDU bound. CCK uses the
same chip clock with groups of eight. A finite interpolation lookahead delays
processing only; it must not shift the reported on-air frame position.

For CCK, the last sixteen PLCP header symbols also train a bounded channel
estimate at two fractional positions per chip. Eight alternating symbols fit
three neighboring-chip coefficients at each position; the other eight estimate
residual noise. Payload correlation uses those coefficients and noise estimates,
with additional uncertainty for neighboring chips outside the current symbol.
The direct decoder remains the preferred result whenever its MAC FCS is valid.
A second payload candidate supplies a fallback only when it independently passes
the same FCS check. There are at most two PSDU buffers, each bounded by
`max_frame_bytes`, plus fixed channel statistics; no additional source history
or whole-recording buffer is needed. Header training never uses recovered
payload bytes or a reference capture.

Record the recovered preamble origin in original input sample coordinates,
rounding start down and exclusive end up; account for fractional rounding in
time uncertainty. If a causal FIR representation adds delay D, subtract D
before mapping positions. Do not subtract the receive decision latency again.
A mid-SYNC acquisition that cannot locate the actual preamble origin must not
invent one: retain conservative timing uncertainty or reject the candidate.
Every filter, clock, carrier, scrambler and partial-frame state resets on a gap,
epoch/configuration change, cancellation or overflow. EOF lookahead cannot be
satisfied by silently adding zeros to a truncated real frame.


The receive example now selects `LegacyWifiDecoder` by default. A leading
`--ofdm-only` selects the original standalone OFDM receiver. Saved v2 IQ records
include `decoder: "legacy_wifi"` or `"ofdm"`; replay preserves that selection.
Prior v1 IQ artifacts remain readable and replay with the original OFDM decoder.
The binary IQ encoding and actual `config` sample-clock fields are unchanged.

V2 frame records carry `phy: "dsss"`, `"cck"`, or `"legacy_ofdm"`, the observed
`rate_bps`, and `preamble: "long"`/`"short"` for DSSS/CCK (null for OFDM).
Original FCS-bearing bytes, sample coordinates, diagnostics, continuity,
acquisition counters and parser failures remain present. The comparator accepts
prior v1 OFDM receive records, but rejects inconsistent family/rate combinations
and invalid DSSS/CCK preambles.

Reference eligibility uses the observed [Radiotap Rate](https://www.radiotap.org/fields/Rate.html)
and explicit compatible [Channel modulation/band flags](https://www.radiotap.org/fields/Channel.html).
A dynamic CCK/OFDM channel can carry either family; CCK channel flags also cover
1/2 Mbps Barker modes, distinguished by Rate. Missing, contradictory, unknown,
FHSS or reduced-clock metadata is excluded. Advertised capabilities are never
used as evidence of a received rate. Matches require equal observed rates and
complete original MAC bytes after established FCS/padding normalization.

Comparison v2 adds `families` (always DSSS, CCK and OFDM) and `rates` (all twelve
supported rates). Each contains eligible denominators, occurrence match counts,
directional fractions and measured/inconclusive status. Zero denominators yield
null fractions and inconclusive status. Global exclusions remain counted by
reason; unknown PHY exclusions cannot honestly be assigned to a family.
No global overlap can establish a per-family qualification target: validators
must assess each required family separately. Matching uses only the supplied
independent timing policy; it does not fit a clock from matching bytes.

### Measuring sustained receive performance

Bounded capture and successful replay establish decoding correctness, but do
not establish sustained processing capacity. Qualify performance with three
separate workloads: capture into a minimal sink, decoding saved IQ, and the
combined live path. Keep acquisition settings and input identities fixed when
comparing decoder revisions. Record build flags, CPU allocation, competing load,
wall time, CPU time, peak memory, and the exact source revision with each result.
External operator tooling owns machine preparation and capture execution.

For saved IQ, report complex samples processed per second for OFDM, DSSS/CCK,
and combined dispatch. Separate file reading and output serialization from DSP
time; label end-to-end replay measurements accordingly. Test both idle samples
and representative packet-bearing inputs. Preserve exact recovered bytes, rates,
source intervals, gap handling, and bounded-output behavior across optimizations.
Report differences explicitly rather than accepting equal frame counts alone.

At a 20 Msps input rate, sustained decoding must process at least 20 million
complex samples per second. A proposed replay headroom target is 25–30 Msps;
this is an engineering target, not an achieved performance claim. Compare one,
two, and four workers using identical inputs before assuming CPU scaling.

Live qualification must additionally report sample continuity, queue depth over
time, overflow counters, and frame delivery latency distributions. A proposed
initial latency target is p99 below 100 ms. Measure reception-to-delivery latency
using a documented clock mapping and timestamp uncertainty; software callback
time alone does not establish RF arrival time. A growing queue fails sustained
qualification even if every frame eventually decodes after capture stops.

Packet counts per second supplement these metrics. They cannot replace sample
throughput or per-family occurrence matching against an independent receiver.
Longer captures must retain the same correctness criteria and explicitly report
missing evidence, reception variability, and unsuccessful trials.

The receive example provides an offline measurement entrypoint:

```sh
cargo run --release -p crafter --features radio --example radio_receive -- \
  --benchmark-artifact saved.iq combined
```

Replace `combined` with `ofdm` or `dsss` to isolate a PHY family. This explicit
selection overrides the artifact's decoder label for measurement. The original
sample metadata, gaps, and allocation limits remain in force. Output separates
source-reading, decoder-call, and verification time, and includes sample/frame
counts and SHA-256 digests of IQ bytes and ordered frame occurrences. Decoder
time includes the public decoder's allocation and dispatch overhead. It excludes
packet parsing, input hashing, and frame hashing; wall time includes them except
packet parsing, which this mode does not perform. Digests help detect changes,
but do not replace exact qualification records or independent frame validation.
Input is streamed with bounded memory; filesystem cache state still affects
source-reading time. No device is opened by this mode.

To separate acquisition continuity from decoder throughput, a leading
`--capture-only` modifier accepts the same explicit `--live` arguments and
optional `--buffer-samples` limit. For example, use
`--capture-only --buffer-samples 2097152 --live` followed by the documented live
settings. It drains the bounded source without DSP, packet parsing, IQ recording,
or per-chunk output. A final `capture_only` record reports consumed samples,
chunks, wall time after source opening, terminal reason, and any error. The normal
`acquisition` record retains verified/discarded samples and loss/overflow counters.
Recording and decoder-selection flags are rejected in this mode. A successful
exit alone does not prove continuity: assess acquisition counters as well. This
measurement does not establish RF sensitivity, packet recovery, or latency.

### Parallel legacy decoding

`ParallelLegacyWifiDecoder::new()?` implements the same `PhyDecoder` contract as
`LegacyWifiDecoder`, using two persistent workers for OFDM and DSSS/CCK. It can
be supplied directly to `RadioPacketSource`; recovered frames enter the same
packet parser. Construction starts worker threads but never opens a device.

The workers share one owned input chunk and the aggregate output budget. Each
consume call waits for both workers, so the decoder has no hidden input backlog.
The same 128-sample dispatch coordinates, frame completion order, and diagnostic
order are retained. Reset and end events reach both workers; dropping the decoder
closes its channels and joins the workers. Worker creation/channel failures are
structured errors. A failed worker channel requires a new decoder instance.
After a chunk fails, worker statistics may include more processing than serial
execution, because the other worker may already have advanced farther.

Use `--benchmark-artifact saved.iq parallel` to measure this implementation.
Parallelism does not guarantee higher throughput: evaluate it on the actual CPU
allocation and input, including scheduling overhead. This architecture has two
independent PHY workers; allocating four CPUs does not create four DSP stages.

A leading `--parallel` modifier selects the two-worker decoder in the receive
example; `--parallel-dsss` selects three workers. Both support explicit `--live` mode. It is mutually exclusive with
`--ofdm-only` and `--capture-only`. Newly saved IQ headers record `dispatch` as
`serial`, `parallel`, or `parallel_dsss`; ordinary artifact replay preserves this selection.
Older headers without `dispatch` retain serial behavior. Explicit `--parallel`
or `--ofdm-only` overrides the saved selection for a diagnostic replay. Unknown,
non-string, and incompatible dispatch metadata is rejected. The input encoding,
frame records, and protocol parser are unchanged.

`ParallelLegacyWifiDecoder::with_parallel_dsss()` uses three workers: OFDM and
one worker for each of the two DSSS acquisition phases. Both DSSS workers receive
every raw sample for payload decoding. This mode requires at least 640 buffer
samples and six frame slots; three slots cover worker outputs and two cover
recent reception identities retained for duplicate suppression. Identical
DSSS bytes at the same rate and epoch with overlapping sample intervals are
coalesced, including detections completed in consecutive input chunks.
Nonoverlapping retransmissions remain separate. Reset clears this history.
Independent phase searches can change timing estimates and recover additional
FCS-valid frames. DSSS statistics count worker detections before coalescing;
count emitted frames to measure delivered receptions. The receive summary
exposes this separately as `emitted_frames`; comparison requires that count to
match the frame records for `parallel_dsss` artifacts. Incomplete captures
remain ineligible for qualification.

Use `--benchmark-artifact saved.iq parallel-dsss` to evaluate this mode. It is
also usable through the existing `PhyDecoder` and `RadioPacketSource` APIs.
The receive example's `--parallel` flag continues to select two workers;
`--parallel-dsss` selects this three-worker mode for live reception or replay.

`WindowedLegacyWifiDecoder::new(workers)?` scales the complete legacy Wi-Fi
decoder over coarse time windows. Each window contains a 100 ms core followed
by enough overlap to finish the longest permitted 1 Mbps frame. A recovered
frame belongs to the worker whose core contains its preamble coordinate, so
overlap cannot duplicate an occurrence. Discontinuities finish the preceding
epoch before resetting window assembly, and explicit reset drains and discards
old worker results. Real EOF and gap boundaries finalize worker candidates and
retain their truncation diagnostics; an artificial window boundary does not
count as stream loss. Non-frame counters describe worker detections and can
include trailing-overlap observations, while valid-frame counts include only
emitted core-owned occurrences. The configured sample buffer must cover the assembly window
and one in-flight window per worker; insufficient bounds fail before samples
are retained.

Use `--parallel-windows` to select four window workers in the receive example.
Use `--benchmark-artifact saved.iq windowed-3` or `windowed-4` for controlled
offline measurement. Windowed
frames retain their original coordinates and enter `RadioPacketSource` through
the normal `PhyDecoder` interface. Larger worker counts increase bounded memory
and can help only when the assigned CPUs provide corresponding execution time.

An optional final `FRAMES_JSONL` argument to `--benchmark-artifact` writes each
recovered frame's bytes, integrity, rate, epoch, and sample interval. The file
is created exclusively, so an existing report is never overwritten. Output is
streamed with bounded memory. Report serialization is included in verification
time, outside decoder time. These reports allow occurrence-by-occurrence
comparison when timing estimates change; an aggregate frame count or digest
alone does not prove that all baseline receptions were retained.

`HackRfSource::stats()` reports `queued_samples` and `peak_queued_samples` for
the combined pending-verification and ready queues. The receive example includes
both in its final acquisition record. The peak counts accepted samples only;
rejected overflow samples remain in `discarded_samples`. Dividing a queue count
by the configured sample rate gives its duration of IQ data, not a measured
packet-delivery latency or a hardware timestamp. These counts exclude data
still buffered in the device or USB stack and chunks already handed to decoding.
