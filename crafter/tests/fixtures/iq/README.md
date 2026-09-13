# Independent IQ vector contract

`he-mu{26,52,106,242}-capacity-index.tsv` contains 30858 independent forward
padding cases for per-user MU payload geometry. These include the special
26-tone DCM short-segment size, BCC filler only on 106/242, STBC groups and
per-user LDPC extra segments. They are not LDPC puncturing admission or complete
MU IQ qualification. Regenerate/verify using `he_capacity_vectors.py --mu-tones
SIZE` with optional `--check`.

`he-mu-training-index.tsv` indexes 384 isolated single-stream RU training
fields covering all sixteen HE20 resource units, four MU guard/training pairs,
three quantization gains, and flat/selective channels. These are not complete
MU PPDUs or MAC validation. Regenerate with `he_mu_training_vectors.py` or
verify with `he_mu_training_vectors.py --check`.

`he-mu-timing.tsv` contains 26529 independent forward MU timelines covering
resolved SIG-B lengths, signaled LTF counts, all four MU training/guard pairs,
STBC symbol parity, midamble boundaries and packet extension. These test timing
arithmetic, not per-RU admission or complete IQ transmissions. Regenerate with
`he_mu_timing_vectors.py --write` or verify without arguments.

`he-sigb-iq-index.tsv` indexes 172 independently synthesized time-domain MU
preamble/SIG-B captures: all ten MCS/DCM combinations, compressed/uncompressed
allocations, 1/2/8/9/17 users, empty allocations, long and padded SIG-B fields,
CFO/selective channels, damaged common/user CRCs and invalid count layouts.
Files end at SIG-B, without
HE training or DATA. Regenerate with `he_sig_b_iq_vectors.py`; use `--check` to
verify in a temporary directory. This is offline signaling qualification only.

`he-sig-b-modulation.tsv` contains 270 independent modulated streams plus 1294
single-symbol cases covering every interleaver input position. It covers all
ten valid SIG-B MCS/DCM combinations, the PAPR rotation exception, weighted
noisy observations, either erased DCM half, and checked BCC/header recovery.
Coordinates are before constellation normalization, not time-domain IQ.
Regenerate with `he_sig_b_modulation_vectors.py --write` or verify without flags.

`he-sig-b-coded.tsv` contains 450 independent punctured BCC streams covering
all six SIG-B MCS values, with/without common fields, odd/even user counts,
empty allocations, CRC/tail damage and arbitrary encoded trailing padding. Regenerate with
`he_sig_b_coded_vectors.py --write` or verify without arguments. These are
deinterleaved coded bits, not IQ or end-to-end MU payload qualification.

`he-sig-b-users.tsv` contains 3175 independently generated one/two-user blocks
from IEEE 802.11ax-2021 Tables 27-27 through 27-30. It covers every spatial
configuration and RU-relative position, reserved configurations, all 1024
unused parameter values, non-MU fields, and independent per-user errors.
Regenerate with `he_sig_b_user_vectors.py --write`; omit the flag to verify.
These are bit-level vectors, not SIG-B IQ or MU DATA qualification.

`he-sig-b-common.tsv` exhaustively maps all 256 HE20 SIG-B common allocation
codes, using independent CRC polynomial division and literal Table 27-26
templates. It records ordered RU sizes, first table slots, user counts, empty
RUs, and distinct reserved/wider classifications. Generate with
`he_sig_b_common_vectors.py --write` or verify without arguments. These are
18-bit common-field fixtures, not SIG-B IQ or MU payload qualification.

`he-mu-prefix-index.tsv` contains 160 independent HE20 MU IQ prefixes, covering
SIG-B MCS/DCM, compression, all four guard/training codes, and clean or
frequency-offset/selective channels. Thirteen invalid cases cover legacy-header
checks, constellation discrimination, reserved fields, CRC/tail and erasure.
`he_mu_prefix_vectors.py --check` reproduces them. Chunked receiver tests check
MU diagnostics, bounded storage, gap resets and no MAC delivery. These prefixes
contain neither SIG-B nor DATA and do not qualify MU payload or live reception.

`he-er-prefix-index.tsv` contains 288 independent HE ER SU preamble prefixes,
covering both RU allocations, all allowed MCS/GI/DCM/STBC header combinations,
BCC/LDPC flags, frequency offset/multipath and erased original SIG-A DATA
tones. Repeats bypass interleaving; the second SIG-A DATA constellation is
QBPSK, but pilots remain BPSK with their correct polarity sequence. The 18
negative cases cover reserved values, CRC/tail, repeated legacy-header checks,
rotation and truncation. `he_er_prefix_vectors.py --check` reproduces them.
These are signaling-only fixtures, not full ER DATA or MAC qualification.

`he-dcm-metrics.tsv` contains 660 independent rational-distance cases for
BPSK, QPSK and 16-QAM DCM pairs, including off-grid points, weighted branches
and erasures. `he-dcm-iq-index.tsv` contains 128 complete BCC/LDPC waveforms
covering MCS0/1/3/4, the four compatible training/guard pairs, padding factors,
midambles and corrupted FCS. Eight invalid SERVICE/truncated cases accompany it.
`he_dcm_vectors.py --check` and `he_dcm_iq_vectors.py --check` reproduce them.
These qualify joint demapping, LDPC half-tone mapping, BCC interleaving and
BPSK filler handling, not independent multiple spatial streams or live RF.

`he-midamble-iq-index.tsv` contains 270 complete HE20 SU BCC/LDPC waveforms
with periods of 10 or 20 DATA symbols and channel changes at training boundaries.
It covers every currently qualified SU MCS/GI/LTF combination, short Doppler
packets with no midamble, final-symbol insertion exceptions, multiple refreshes
and long pilot-sequence wraps. Twelve invalid cases erase or truncate training.
`he_midamble_iq_vectors.py --check` independently reproduces both inventories.
The historical `he-bcc-iq-invalid-midamble` fixture is now recognized as a valid
short Doppler-marked PHY carrying an arbitrary, non-MAC PSDU; its filename is
retained for fixture compatibility. These tests are not live RF qualification.

`he-ldpc-iq-index.tsv` contains 240 complete HE20 SU one-stream LDPC waveforms
covering MCS0–11, all five guard/training pairs, four initial padding factors,
tagged aggregates and deliberately corrupted FCS. Six invalid SERVICE/truncated
waveforms are listed separately. `he_ldpc_iq_vectors.py --check` reproduces
the Gaussian-encoded, directly synthesized corpus independently of Rust.
Kernel and chunked public receiver tests require exact PSDUs and valid MPDUs.
MCS11 with sparse training and multipath also exercises finite-delay channel
estimation. These offline fixtures do not qualify live HE interoperability.

`he-qam-index.tsv` contains all 1,024 HE constellation labels and 289 off-grid
points with independent rational-distance soft metrics. `he-ldpc-tones.tsv`
enumerates all 234 DATA-tone positions using a matrix-transpose oracle.
`he_demapping_vectors.py --check` reproduces both from IEEE 802.11ax-2021
Figures 27-37 through 27-40, Table 27-36 and Equation 27-95. Tests cover
normalization, channel weights, bit-group preservation and invalid inputs.
These demapping fixtures alone do not establish full HE LDPC IQ or live
hardware qualification; the complete waveform corpus above tests integration.

`he-ldpc-rate-index.tsv` contains 17,583 independent forward HE20 SU LDPC
sizing cases; `he-ldpc-rate-codewords.tsv` contains 72 Gaussian-encoded
bitstreams. `he_ldpc_rate_vectors.py --check` reproduces both. These qualify
initial-segment inversion, extra-segment thresholds, shortening, puncturing,
repetition and codeword recovery with post-FEC padding excluded. MCS0-11,
DCM/STBC and stream counts here are coding dimensions, not IQ qualification.

`he-mu-signal-a-index.tsv` contains 5,280 HE MU SIG-A bit/encoded-metric
cases covering SIG-B MCS/DCM, compression and bandwidth, GI, Doppler-dependent
LTF counts, and other field values. `he-mu-signal-a-invalid.tsv` adds 24 CRC,
tail and reserved-field cases. Generate with `he_mu_signal_vectors.py --write`
or verify without arguments. The raw symbol/user count is retained: an
uncompressed value of 15 does not determine the exact SIG-B length by itself.
These are header kernels, not MU IQ payload or hardware qualification.

`he-ldpc-partial-index.tsv` contains 18 complete HE LDPC waveforms with one
independently corrupted codeword: SU, ER242 and ER106, each plain/DCM/STBC,
with either the first or a middle codeword damaged. A long first MPDU overlaps
the middle damaged word while a later MPDU remains intact. These check bounded
partial recovery, SERVICE validation, per-MPDU FCS and failure diagnostics.
Reproduce with `he_ldpc_partial_vectors.py --check`. Estimated PSDU bits are
not treated as verified frames; the existing aggregate scanner validates FCS.

`he-er106-ldpc-rate-index.tsv` and `he-er242-ldpc-rate-index.tsv` add
705 and 1,839 independent extended-range sizing cases. Their corresponding
`-codewords.tsv` files contain 57 and 159 independently Gaussian-encoded
bitstreams. Reproduce with `he_ldpc_rate_vectors.py --er-tones 106 --check`
and `--er-tones 242 --check`. These cover the ER MCS restrictions, DCM,
STBC, shortened final segments, extra segments and multi-codeword payloads.
They qualify coding geometry and recovery, not upper-106-tone IQ reception
or live hardware operation (IEEE 802.11ax-2021 27.3.12.5.2).

The private HE DATA tone-layout helper also represents ER upper106 geometry:
tones17..122 with pilots22/48/90/116, 102 DATA tones, and 51-tone DCM halves.
Tables27-35/36 define its BCC and LDPC permutations; Tables27-40/41 define
pilot signs and positions. Geometry tests cover permutations and bounds, while
the existing complete242-tone waveform corpus checks refactor compatibility.
`he-er106-iq-index.tsv` and `he-er106-iq-invalid-index.tsv` add104 complete
waveforms and16 negative cases generated by `he_er_iq_vectors.py --upper106`.
They qualify upper106 MCS0 BCC/LDPC, DCM, STBC, all compatible guard/LTF
pairs, midambles, aggregate FCS handling, streaming limits and packet metadata.
This is offline IQ qualification, not live radio interoperability or throughput.

`he-er106-training-index.tsv` contains54 isolated upper106 HE-LTF fixtures
from `he_er_training_vectors.py`: single-stream and two-STS STBC training,
all compatible guard/LTF pairs, three quantization gains, and flat/selective
channels. These fields omit the PPDU prefix and DATA; they qualify the private
format-aware estimator and zero estimates outside the allocation, not full IQ reception.
The ER amplitude boost, per-stream power factor, and fractional LTF normalization are included.

HE sparse-LTF waveform normalization follows Equation27-5: for a242-tone RU,
the denominator under the square root is60.5 (1x),121 (2x),or242 (4x).
It is not the number of populated training tones (60,122,242). The training,
BCC, LDPC, aggregate, midamble, DCM, STBC and ER waveform corpora use these
normative values. A direct unquantized tone test checks absolute receiver gain
at all five guard/training combinations, independently of successful decoding.

`he-ampdu-iq-index.tsv` records 200 complete HE20 SU BCC PHY/MAC IQ cases
from `he_ampdu_iq_vectors.py`: MCS0-9, all five training/guard pairs, single
and multiple QoS MPDUs, mixed tags, EOF padding and intentionally bad FCS.
Expected PSDUs include corrupted FCS bytes; expected emitted MPDUs exclude
those frames while retaining later valid frames. Independent preamble acquisition,
header admission, IQ recovery and HE aggregate scanning are tested together.
Tagged frames exercise byte framing, not negotiated acknowledgment policy.
Public `WifiDecoder` tests use this corpus at two chunk sizes, and packet-source
tests preserve original bytes and HE metadata. This is not hardware qualification.

`he-bcc-iq-index.tsv` and `he-bcc-iq-invalid-index.tsv` record 151 positive
and six negative HE20 SU one-stream BCC IQ cases from `he_bcc_iq_vectors.py`.
Complete PHY preambles and DATA carry synthetic PSDUs, not qualified MAC
aggregates. Cases cover MCS0-9, all five SU training/guard pairs, frequency
offset, multipath, pilot sequence wrap, invalid modes, SERVICE and truncation.
Per-case gain prevents CS8 clipping; packet extensions use DATA average power.
The same independently recorded DATA offsets and PSDU bytes qualify header-only
admission using only the first 320 samples from L-SIG: exact byte/sample budgets,
large absolute capture positions, overflow and unsupported-mode rejection.
Admission intentionally does not reject a valid header just because later DATA
has invalid SERVICE or is truncated; full recovery still rejects those payloads.

`he-bcc-index.tsv` contains 435 independent HE BCC coded-bit/PSDU cases from
`he_bcc_vectors.py`. It covers MCS0-9, DCM filler, STBC symbol-group geometry,
all nonzero scrambler seeds, invalid SERVICE and zero seed. Inputs are already
deinterleaved and stream-recombined; they are not IQ or complete MAC aggregates.

`he-capacity-index.tsv` contains 8,253 forward padding cases generated by
`he_capacity_vectors.py`, starting from APEP lengths and allocating symbol
segments and MAC/PHY padding. LDPC extra-segment cases test signaled geometry,
not the puncturing threshold decision or codeword validity. This corpus is not
IQ or MAC-frame recovery qualification.

`he-timing-index.tsv` contains 10,252 independent HE20 SU forward timelines
from `he_timing_vectors.py`, including per-DATA-symbol offset hashes, midamble
insertion, all SU guard/training pairs and packet extension. These are timing
checks, not IQ waveforms, DATA mode admission or multi-stream RX qualification.

`he-er-timing-index.tsv` adds 2,479 independent ER SU forward timelines from
the same generator with `--er`: repeated SIG-A, the ER L-SIG remainder, one
DATA stream with/without STBC, midambles and packet extension. Both ER tone
allocations share these clocks. This does not qualify ER payload recovery.

`he-er106-capacity-index.tsv` and `he-er242-capacity-index.tsv` add 177 and
619 independent forward payload-capacity cases from `he_capacity_vectors.py`
with `--er-tones 106` or `--er-tones 242`. They cover explicit ER mode limits,
BCC/LDPC, DCM, STBC, padding boundaries and both LDPC extra-segment branches.
These are bit-budget checks, not upper106 IQ or codeword qualification.

`he-er106-bcc-index.tsv` and `he-er242-bcc-index.tsv` contain 165 and225
independent BCC coded-bit cases from `he_bcc_vectors.py --er-tones 106|242`.
They cover exact PSDUs, all nonzero scrambler seeds, malformed SERVICE/zero
seed, DCM filler and STBC-group post-FEC padding. Tests additionally exercise
soft-metric scales, unused extreme-valued positions and allocation limits.
These fixtures are not complete IQ or MAC frames.

`he-er-iq-index.tsv` and its invalid index contain 280 complete ER242 waveforms
and 16 negative cases from `he_er_iq_vectors.py`. They cover BCC/LDPC MCS0-2,
DCM MCS0/1, STBC, all compatible guards, four padding factors, midambles10/20,
selective channels/CFO, exact PSDUs and independently framed aggregate members.
ER training is boosted while DATA is not, and pilots account for the repeated
header. One bad member must not discard a valid following member. These are
synthetic offline fixtures, not upper106 or live-radio qualification.

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

`vht-reference-index.tsv` contains 9253 independent radiotap metadata cases,
generated by `vht_reference_vectors.py [--check]`. It covers every combination
of known bits, absent-user fields, MCS/NSS values, bandwidth/group/coding values
and A-MPDU status flags. Eligibility is the implemented VHT20 SU NSS1 BCC/LDPC
subset; an excluded record can still describe a valid unsupported waveform.
The reference subset includes one-DATA-stream/two-STS STBC, and checks that
known STBC cannot coexist with short-GI symbol-count disambiguation.
Unknown fields remain unknown rather than inheriting their unused flag bits.

`he-ampdu-index.tsv` contains 46 independent framing cases generated by
`he_ampdu_vectors.py`: mixed tagged/untagged frames, spacing, EOF padding,
malformed ordering, bad FCS recovery, split length bits and preserved flags.
IEEE 802.11ax-2021 Table 9-527 and 26.6.2 distinguish nonempty tagged MPDUs
from zero-length EOF padding. This is byte framing only, not acknowledgment
policy validation, public HE streaming integration or hardware qualification.

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

`vht-ampdu-iq-index.tsv` and its 54 CS8 files extend the complete VHT waveform
model with two-MPDU aggregates across MCS0-8 and both GIs. Cases cover repeated
identical MPDUs, one bad FCS followed by a valid MPDU, and a 4100-byte MPDU.
Regenerate or verify with `vht_ampdu_iq_vectors.py [--check]`. All inputs are
synthetic; complete offline recovery does not establish hardware interoperability.

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

## VHT SU LDPC rate-matching vectors

`vht-ldpc-rate-index.tsv` contains 20412 independent forward geometries for
VHT20 MCS0-8, initial symbol counts through 1512 and one/two-symbol groups.
`vht-ldpc-rate-codewords.tsv` contains 54 independently Gaussian-encoded
information/transmitted streams, including PHY padding, shortening, puncturing
and repetition. Regenerate with `vht_ldpc_rate_vectors.py` in the oracle backend;
`--check` checks exact contents. These are internal coding fixtures, not complete
IQ waveforms or a VHT STBC/LDPC receiver qualification claim.

## VHT LDPC complete IQ vectors

`vht-ldpc-iq-index.tsv` describes 73 complete independent waveforms generated
by `vht_ldpc_iq_vectors.py [--check]`: MCS0-8, both guard intervals, duplicate
frames, a 4100-byte MPDU, corrupted first-MPDU FCS, a deliberately damaged
LDPC codeword followed by an intact MPDU, and CFO/multipath cases.
The three `vht-ldpc-iq-invalid-index.tsv` waveforms corrupt SERVICE, extra-symbol
signaling or SIG-B integrity. Gaussian parity encoding and row/column tone
mapping are independent of the receiver. No physical radio supplied these bytes.

## VHT STBC complete IQ vectors

`vht-stbc-iq-index.tsv` contains 110 complete two-transmit-chain/one-receive-chain
simulations: MCS0-8, BCC/LDPC, both guard intervals, duplicates, large frames,
CFO/multipath, bad FCS and a damaged LDPC codeword. Nine negative cases in
`vht-stbc-iq-invalid-index.tsv` exercise signaling, training, SERVICE, SIG-B and
truncation. `vht_stbc_iq_vectors.py [--check]` constructs the two transmit chains
independently of production code, applies source-defined CSD, and sums them into
one synthetic received IQ stream. These fixtures do not qualify physical
reception or claim single-antenna STBC transmission.
## HE SU signaling vectors

`he-signal-a-index.tsv` contains 1984 independent header bit/encoded-metric
cases generated by `tools/oracle/engine/backends/he_signal_vectors.py --write`.
Run the generator without arguments to verify the committed corpus. Polynomial
division is anchored by the published 802.11ax-2021 27.3.11.7.3 CRC example.
Fields follow Tables 27-18/19; interleaving follows Table 27-35. These test
signaling interpretation, not DATA configuration admission or complete IQ RX.

`he-su-prefix-index.tsv` and `he-su-prefix-invalid-index.tsv` add 96 valid and
10 invalid CS8 preamble prefixes, generated by `he_prefix_iq_vectors.py` (use
`--check` to verify). Each starts with 37 silent samples and ends after HE-SIG-A
at sample677, at 20Msps. The receiver must acquire its own timing/channel and
recover the exact header. Cases cover MCS0-11, all four GI/LTF signaling codes,
CFO/multipath, repeated-header mismatches, format/width exclusions, parity/CRC,
tail and rotated-constellation rejection. HE L-STF/L-LTF include the epsilon
power factor from 27.3.11.3-4. These files intentionally have no HE training or
DATA field and do not establish full HE reception.

`he-transform-index.tsv` supplies 1920 input/output pairs for ten mathematical
128/256-point transform cases. `he_fft_vectors.py --write` generates the file;
without flags it checks it. The reference uses a double-precision direct DFT,
not the receiver's radix-2 implementation. Complex ramps and asymmetric inputs
test bin ordering and phase, alongside DC, impulse and Nyquist cases. Rust
tests additionally check every tone for both transform sizes. This is numerical
validation for HE training/DATA primitives, not frame or throughput qualification.

`he-training4-index.tsv` and its invalid counterpart contain 24 complete HE SU
preambles followed by an uncoded channel probe, plus five malformed/truncated
cases. The generator is `he_training_vectors.py` (`--check` verifies the corpus).
Equation27-43 supplies the 4x LTF sequence; Equations27-22/23/38 supply HE-STF.
Both 4x guard intervals, three gains, CFO, multipath and changed HE-field mapping
are covered. Tests acquire timing and CFO normally, fit the observed channel
against the independently simulated transfer function, and recover all242 probe
signs. The probe is not a standard DATA field; there are no MAC bytes to publish.
`he-training-sparse-index.tsv` lists 36 independent single-stream HE 1x/2x
training and uncoded channel-probe captures generated by `he_training_vectors.py`.
It covers 1x/0.8us, 2x/0.8us and 2x/1.6us guards, three gains and four channel
conditions. These mathematical probes are not valid HE DATA or MAC frames.
## HE STBC IQ corpus

`he-stbc-iq-index.tsv` inventories 368 independent HE20 SU STBC waveforms:
one DATA stream, two space-time streams summed into one receive chain, BCC
MCS0–9 and LDPC MCS0–11, all four compatible LTF/guard pairs, four initial
padding factors, 10/20-symbol changing-channel midambles, and either branch
lost. `he-stbc-iq-invalid-index.tsv` adds eight SERVICE, truncation and erased
training cases. The generator is `he_stbc_iq_vectors.py`; it uses direct IDFT,
source P/R training matrices and Table21-20 mapping, not libcrafter's receiver.
Full PSDUs, expected FCS-valid MPDUs, DATA sample bounds and hashes are indexed.
This corpus does not establish live HE interoperability or TX qualification.
`he-training4-invalid-stbc` is a historical unsupported-mode fixture, not a
complete STBC training field: its uncoded probe follows only one LTF. Its
STBC header is now supported; no DATA or MAC validity is asserted for it.
Likewise, `he-bcc-iq-invalid-stbc` only changes a non-STBC waveform's header;
it is now header-admitted but still must not publish a valid frame.
