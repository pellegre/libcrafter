# IQ receive contract

This document defines the initial receive implementation contract. It does not
claim that the decoder or live qualification is complete.

## Boundary and scope

IQ sources supply owned sample chunks to a stateful PHY decoder. Reconstructed
MAC bytes enter the existing packet decoder and `PacketSource` surface. IQ is
never a `Raw` packet layer. Original recovered bytes remain available even when
the parsed packet is later modified. RF context must coexist with Wi-Fi metadata.

The initial scope is legacy OFDM with 20 MHz channel spacing, including ERP-OFDM.
DSSS/CCK, DSSS-OFDM, PBCC, HT, VHT, HE, half-clocked and quarter-clocked OFDM are
unsupported. A valid legacy SIGNAL alone does not prove a supported frame:
later PHY formats can share a legacy preamble. DATA integrity must also pass.
There is no transmit, injection, decryption, or active traffic-generation API.

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
state. The six encoder tail bits are forced to zero *after* scrambling at the
PSDU boundary; do not validate them as ordinary descrambled zeros. Padding
follows the tail, so the final padded trellis state need not be zero.

For reflected byte-oriented CRC arithmetic use polynomial `0xedb88320`, initial
remainder `0xffffffff` and final XOR `0xffffffff`; compare its little-endian
four-byte representation with the received trailer. This is the byte-oriented
equivalent of the polynomial/serial convention in 7.1.3.7. Tests must verify
the equivalence using independent vectors, not two copies of the same helper.

## Continuity and bounded processing

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

`radio-hackrf` enables `radio` plus a small receive-only native FFI boundary.
The rest of the crate denies unsafe Rust; only the private native module permits
it. Install libhackrf development and runtime libraries with the
`hackrf_get_m0_state` API (firmware USB API >= 0x0106). Link with `libhackrf` on
the normal native library search path. Custom installations can supply
`LIBRARY_PATH` at link time and their platform's runtime loader search path.
Offline `radio` builds and mock tests do not link or open libhackrf.

The ABI and lifecycle were reviewed against Great Scott Gadgets' libhackrf
`host/libhackrf/src/hackrf.h` and `hackrf.c`, revision `cc691022`.
`hackrf_stop_rx` cancels transfers; `hackrf_close` joins the event thread before
the callback context is freed. No transmit symbol is declared. Callback panics
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

The replay example assumes 20 Msps, has a one-second/20-million-sample bound and
uses the documented example frequency; use `ReaderIqSource` directly for other
metadata or limits. Live invocation requires every operator setting explicitly:

```text
cargo run -p crafter --features radio-hackrf --example radio_receive -- \
  --live SERIAL FREQUENCY_HZ DURATION_SECONDS MAX_SAMPLES FILTER_HZ LNA_DB VGA_DB AMP_BOOL BIAS_BOOL
```

For the initial 20 Msps OFDM scope, set `FILTER_HZ` explicitly to `20000000`.
The source can outpace the synchronous decoder; increase the explicit buffer
bound in operator code only within an appropriate finite memory budget. Actual
live decoder throughput and receiver agreement require separate qualification.
