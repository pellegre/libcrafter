# Independent IQ vector contract

This directory contains synthetic, offline receive and transmit vectors. It contains no
recorded network traffic. The implementation contract and primary evidence map
are in `docs/radio.md`.

Each fixture manifest must record its format, sample rate, source revision,
generator and parameters, SHA-256 of sample data, expected original PSDU bytes,
expected FCS result, rate and relevant sample boundaries. Keep generator logic
independent of the Rust receiver in `tools/oracle/engine/backends/`.

Use IEEE Std 802.11-2007 Annex G intermediate examples to check the independent
generator's SIGNAL coding/interleaving and DATA scrambling/coding before using
generated samples as an oracle. Reference the exact tables used and record
expected intermediate values. Do not make receiver-produced bytes the expected
answer. Newly generated packets use synthetic local addresses and documentation
IP ranges, with deterministic seeds and non-sensitive payloads.

Coverage must include all eight 20 MHz legacy rates, varied lengths and scrambler
states, arbitrarily split chunks, leading noise, frequency offsets, phase shifts,
multipath, truncation, corrupt SIGNAL, corrupt FCS and explicit discontinuities.
Record impairment parameters separately from the expected original bytes. Add
false-positive checks for noise and unsupported PHY observations. Commit bounded
synthetic regression fixtures and provenance; keep bulk experimental artifacts
ignored. No hardware or network access is needed to replay fixtures.

## Deterministic replay fixture

`ramp.cs8` is an original synthetic eight-sample fixture (16 bytes), created
without RF capture or external data. Bytes encode signed two's-complement
interleaved I then Q, without a header or padding. The sample pairs are
`(-128,127), (-64,64), (-1,1), (0,0), (1,-1), (64,-64), (127,-128), (32,-32)`.
This tests storage, normalization, and replay only; it is not a Wi-Fi waveform.

`ReaderIqSource::new(reader, config, position)` incrementally reads this format;
`MemoryIqSource::from_cs8` uses the same path for owned signed bytes. Supply RF
configuration, initial epoch/sequence/sample index, and optional time anchor
explicitly. No file modification time is used. `mark_gap` records losses before
the next chunk; known loss advances position, while unknown loss starts a new
epoch and clears the anchor. Duration limits count received sample time rather
than replay wall time. At a configured limit unread trailing input is not
validated; otherwise an incomplete final I/Q pair is an error. Reader failures
are sticky, and cancellation discards pending input. Arbitrary chunk sizes and
one-byte short reads reproduce these same eight samples in the radio tests.

## Legacy OFDM vectors (generator version 1)

Regenerate from the repository root with Python 3.10 or later, without optional
packages, devices, network access, or the production decoder:

```sh
python3 tools/oracle/engine/backends/ofdm_vectors.py
```

Use `python3 tools/oracle/engine/backends/ofdm_vectors.py --check` to regenerate
into temporary storage and compare every artifact without changing this directory.
This also verifies the generator hash; Rust fixture tests use only crate-local
files so they remain usable outside the full workspace checkout.

`ofdm-manifest.json` records the generator source SHA-256, version, IEEE edition,
20 Msps cs8 format, IQ hashes, exact PSDUs including little-endian FCS, scrambler
seeds, symbol counts, sample boundaries and impairment settings. The matching
TSV is the dependency-free Rust test inventory. Each per-vector JSON contains
transmission-order SIGNAL bits, convolutional and interleaved SIGNAL bits, and
full DATA before scrambling, after scrambling/tail replacement, before and
after puncturing, and per-symbol interleaving. These expectations come only
from the independent encoder; no Rust receive helper is imported.

The source is IEEE Std 802.11-2007, whose downloaded digest is pinned in
`docs/radio.md`. Constants follow Tables 17-3, 17-5, 17-6, Equations 17-6,
17-8, 17-15 through 17-17 and 17-25, and Figures 17-7 through 17-10. The
encoder checks literal Annex G Tables G.7–G.9 SIGNAL expectations, the first
32 G.15 scrambler bits, and the first 18 G.18 punctured DATA bits before
writing anything. These are partial intermediate cross-checks, not a claim
of reproducing the complete Annex G waveform. The constellation axes follow
Figure 17-10's contiguous I/Q bit groups, and BPSK maps zero to minus one.

Eight clean vectors vary PSDU length and nonzero scrambler seed across all
eight rates. Synthetic MACs are locally administered and IPv4 endpoints are
192.0.2.1 and 198.51.100.2. Five additional 6 Mb/s cases cover deterministic
uniform noise, +80 kHz carrier offset, a 73-sample end truncation, parity-invalid
SIGNAL (still convolutionally encoded), and a deliberately corrupted FCS.
Rejection cases retain the intended PSDU as diagnostic truth, not expected
successful receiver output. The clean 6 Mb/s frame has FCS `fb 56 c3 2d`.

Two maximum-length 4095-byte PSDUs at 6 and 54 Mb/s exercise long traceback
storage and pilot polarity wrap. A 1500-byte PSDU at 24 Mb/s adds +80 kHz carrier
offset across a longer frame. Payload bytes repeat modulo 256. These three
fixtures retain the same independent intermediate and original-byte evidence.

Waveforms have 37 leading zero samples, 320 training samples, an 80-sample
SIGNAL, DATA symbols and 32 trailing zero samples. A 0.4-radian phase rotation
applies to all cases. IFFT normalization is 1/64 and cs8 scale is 300, with
round-to-nearest and signed saturation. The synthetic rectangular symbol
boundaries omit transmitter window overlap; these are receive algorithm vectors,
not RF spectral-mask qualification. Scalar Python math rounding may differ at
quantization boundaries across platforms; the checked-in hashes remain the
canonical sample bytes. Impaired-vector success is an expectation for subsequent
decoder steps, not evidence that a receiver already passes it.

This standalone PHY fixture backend does not advertise a packet-oracle profile:
packet materialization/normalization is unchanged until the receive bridge.
Multipath, unsupported-PHY discrimination and stream-gap behavior require
additional decoder-specific tests in later steps. The existing replay tests
already exercise arbitrary chunks independently of these waveform fixtures.

## DSSS/CCK vectors: source contract for the next generator

This section specifies pending fixtures, not implemented receiver coverage.
Use the retrieved IEEE 802.11-2007 document and digest in `docs/radio.md`.
The extension evidence map identifies clauses 15 and 18; Annex G OFDM examples
are not DSSS/CCK authority. Keep the future encoder independent of Rust DSP.

Before generating waveforms, assert these literal intermediate cross-checks:

- Figure 15-3: protected header octets `0a 00 c0 00` serialize as
  `01010000 00000000 00000011 00000000`; CRC bits in time order are
  `01011011 01010111`, hence trailer octets `da ea`. This cross-check was
  reproduced with reflected polynomial `0x8408`, initial/final XOR `0xffff`.
- Table 18-13: the unrotated 5.5 Mbps code for d2/d3=`00` is
  `[j,1,j,-1,j,1,-j,1]`; for `11` it is `[j,-1,j,1,-j,1,j,1]`.
  These literal rows distinguish chip order, cover signs and phase selection.
- Table 18-14 maps serial pair `10` to pi, whereas Table 18-11 maps that
  same pair to 3pi/2. Assert both; interchanging them silently corrupts CCK.
- Table 18-2 gives 11 Mbps `(octets,LENGTH,extension)` tuples
  `(1023,744,0)`, `(1024,745,0)`, `(1025,746,0)`, `(1026,747,1)`.
- Derived checks from Figure 18-5 (not printed standard test vectors): first
  16 scrambled long SYNC bits are `0111111011101100`, and short SYNC bits
  are `0001100110101001`, with the specified Z1..Z7 seeds and input bits.
  Independently self-descramble them after the first seven bits. Preserve
  serial scrambler state across all subsequent fields.

Cover seven valid rate/preamble combinations: long at 1/2/5.5/11 Mbps and short
at 2/5.5/11 Mbps. Include alternate long scrambler seeds, both CCK symbol
parities, all 5.5 Mbps codewords and all 11 Mbps phase selections, extension
boundaries, varied PSDU lengths and complete independently computed MAC FCS.
Manifest fields must include preamble kind, header bytes/CRC, serial scrambled
bits, selected phase/codeword intermediates, original sample boundaries,
20 Msps source rate and 11 MHz chip rate, pulse filter/delay and all impairments.

Generate fractional chip timing directly from an independent continuous-time
pulse model sampled at 20 Msps, not by copying the receiver interpolation
kernel or pretending each chip occupies two source samples. Include fractional
start phase, sample-clock error, carrier error, amplitude/phase rotation, noise
and delayed paths. Retain clean deterministic cases separately from impairment
cases. Test arbitrary chunks, mixed OFDM/DSSS/CCK streams and explicit gaps.
Reject short/1 Mbps, corrupt SFD/header CRC, unsupported SERVICE/SIGNAL,
impossible/over-bound lengths, bad FCS and truncation at every field boundary.
No synthetic waveform is evidence of live receiver agreement.

### Implemented independent DSSS/CCK inventory

`python3 tools/oracle/engine/backends/dsss_vectors.py` creates 32 bounded
`dsss-*` fixtures. `--check` regenerates in a temporary directory and compares
all bytes, including the inventory and generator digest, without changing the
checked-in files. The encoder imports only Python's standard library. The
literal checks above execute before waveform generation.

Seven clean fixtures cover every valid preamble/rate combination. Four separate
long-preamble impaired fixtures cover each rate with a fractional start at
37.375 source samples, +35 ppm sample-clock error, +45 kHz carrier offset,
0.63 radians phase, deterministic uniform noise and a 0.22-amplitude path
1.3 chips late. Two `channel_echo` fixtures cover long and short 11 Mbps
preambles with a 0.65-amplitude, pi/2-phase path one chip late, retaining those
clock, carrier and noise impairments at gain 0.35. They exercise header-trained
CCK channel correction with independently known transmitted bytes. Four
additional CCK fixtures deliberately corrupt the MAC FCS at both rates and
preamble lengths, ensuring that alternate payload hypotheses still reject it.
Four short/11 Mbps fixtures use the literal 1023–1026 octet
length-extension boundary cases. Remaining cases cover alternate long seed,
header CRC, MAC FCS, SFD, SIGNAL and PBCC rejection, and truncation during SYNC,
SFD, header and payload. All PSDUs are synthetic, with locally administered MAC
addresses. Long payload bytes exercise all 11 Mbps phase selections; the
inventory test also checks all four 5.5 Mbps codeword selections.

Each chip is an impulse at its center convolved with a symmetric raised-cosine
pulse (rolloff 0.35, support truncated to ±8 chips), evaluated directly at
20 Msps. The mathematical raised-cosine pulse is bandlimited; finite support
introduces small spectral leakage and is not a spectral-mask qualification.
The pulse has no causal delay, and its precursor starts before the declared
preamble boundary. `preamble_start`, `payload_start` and exclusive `frame_end`
are nominal modulation boundaries in the original source coordinates, not
first/last nonzero pulse samples. Trailing samples preserve pulse lookahead in
complete fixtures; truncated cases intentionally omit required frame samples.
No receiver interpolation code is reused. Quantization is signed cs8 with
round-to-nearest saturation; the checked-in hashes are canonical across math
library rounding differences.

Per-fixture JSON records contain header bytes, complete input/scrambled serial
bits, initial delay seed, payload chip boundary and every CCK symbol's serial
bits, common phase quadrant and eight complex chips. The manifest hashes both
IQ and intermediate records and records all pulse/impairment parameters.
`radio_dsss_vectors` validates inventory integrity, an independently oriented
CRC-16 implementation, MAC FCS, descrambler truth, rate/length arithmetic and
codeword selection coverage, plus exact production-decoder bytes and positions
across arbitrary chunk boundaries. These deterministic checks do not establish
live receive qualification.

The `barker_interference` fixture adds a Barker-orthogonal chip vector with
amplitude 2 to the final header symbol and uses gain 0.18 to avoid clipping.
It preserves the transmitted header bits and CRC while reducing correlation
quality, exercising acquisition of a distorted but recoverable symbol.

## HT greenfield receive oracle corpus

`ht-greenfield-index.tsv` inventories 64 independent HT20 waveforms: MCS0–7,
BCC/LDPC, 100/4095-byte PSDUs, clean or carrier-offset/multipath conditions.
They contain one space-time stream, no extension streams and 800 ns GI.
The 24 us preamble and DATA pilot polarity offset follow IEEE 802.11-2020
19.3.9.5 and 19.3.11.11.3. Short GI with immediate DATA is excluded by the
19.3.11.11.6 note. `ht_greenfield_vectors.py --check` verifies regeneration;
fixture integrity checks alone do not establish streaming receive support.
`ht-greenfield-invalid-index.tsv` adds eight malformed waveforms for header
CRC, unsupported configurations, SERVICE and MAC FCS rejection tests.
`ht-greenfield-ampdu-index.tsv` adds four two-MPDU aggregates at MCS0/7 with
BCC/LDPC, for exact per-MPDU recovery, duplicate identity and output limits.

## HT STBC arithmetic oracle

`stbc-pairs.tsv` contains 2400 independently generated two-symbol observations
and two HT-LTF observations, with expected channels and constellation symbols.
It covers BPSK/QPSK/16-QAM/64-QAM, either channel missing, opposite channels,
complex gains and weak gains. `stbc_vectors.py --check` verifies regeneration.
These are algebra fixtures, not complete waveforms or hardware qualification.
`ht-stbc-index.tsv` separately inventories 192 full simulated receive waveforms
from two independent transmit chains: MCS0–7, BCC/LDPC, mixed GI400/800 or
greenfield GI800, two PSDU sizes and clean/independent-multipath-plus-CFO cases.
Legacy and HT portions use their distinct per-chain cyclic shifts. These
fixtures do not establish single-antenna STBC transmission or live reception.

## VHT aggregate byte fixtures

`vht-ampdu-delimiters.tsv` covers all 16384 representable delimiter lengths,
including the high-two/low-twelve split, EOF and preserved reserved bits.
`vht-ampdu-index.tsv` contains 144 independent aggregate cases: final padding
alignments, S-MPDU and multi-MPDU, spacing and EOF delimiters, all trailing
octet counts, large MPDUs, a PSDU above the HT total-length limit, corruption,
truncation and invalid EOF ordering. Malformed cases retain earlier recovered
FCS-valid bytes and report errors; an EOF-order violation stops publication.

Regenerate with `python3 tools/oracle/engine/backends/vht_ampdu_vectors.py`;
use `--check` for a read-only exact comparison. Authority is IEEE 802.11-2020
9.7.1-2 and 10.12.6-8, a superseded base recorded in the PHY evidence map.
These are framing fixtures, not evidence of complete VHT RX or RF qualification.

## Legacy transmit oracle corpus

The `ofdm-tx-*` and `dsss-tx-*` artifacts are clean, bounded transmit-oracle
waveforms produced by the same independent standard-library encoders. They are
separate from the receive-stress inventory above. They are ideal offline
waveforms and do not establish spectral-mask compliance, HackRF behavior, or
successful reception by hardware.

Both transmit manifests use schema `crafter.radio.transmit-oracle/v1` and one
canonical synthetic `Dot11 / Raw` frame. Its MAC addresses are locally
administered and its inert IPv4 body uses `192.0.2.1` and `198.51.100.2`.
Each valid matrix case has a stable `legacy-*` case ID, the input MAC bytes
without FCS, transmitted PSDU including little-endian FCS, exact CS8 and PSDU
hashes, PHY fields, scrambler settings, sample boundaries, and expected result.
The `.psdu` file is the exact transmitted PSDU, the `.json` file records
intermediate encoder state, and the `.cs8` file contains interleaved signed I/Q
at 20 Msps. The TSV inventories are dependency-free joins for later Rust tests
and hardware qualification records.

`ofdm-transmit-manifest.json` covers 6, 9, 12, 18, 24, 36, 48, and 54 Mb/s.
`dsss-transmit-manifest.json` covers long preambles at 1, 2, 5.5, and 11 Mb/s
and short preambles at 2, 5.5, and 11 Mb/s. The manifests also record bounded
structured-rejection contracts, including short-preamble 1 Mb/s and exceeded
PSDU/sample limits. Explicit malformed vectors pin a caller-supplied wrong MAC
FCS and caller-supplied wrong OFDM SIGNAL or DSSS PLCP CRC without changing the
selected modulation. Auto-derived cases retain valid FCS and PLCP values.

Regenerate both receive and transmit artifacts with the generator commands
above. Their `--check` modes regenerate every matching artifact in temporary
storage and compare raw bytes, so checking cannot rewrite the committed corpus.
Hardware qualification is a separate bounded process: it must transmit the
production waveform through the HackRF, capture it through the monitor-mode
dongle, compare exact MAC bytes and PHY metadata, and retain its untracked run
evidence as described in `docs/radio.md`.
