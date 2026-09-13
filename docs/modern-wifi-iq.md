# Wi-Fi 4 IQ implementation and evidence

The HT20 radio extension recovers raw IEEE 802.11 frame bytes from IQ and
constructs single-stream transmit IQ from packets. The existing packet, radio
source, replay, and bounded transmitter interfaces remain the integration
boundary. Payload processing is separate from physical-layer byte recovery.

Legacy and HT20 usage and measured coverage are documented in
[radio.md](radio.md). VHT, HE, and EHT are outside this Wi-Fi 4 implementation.

## Scope

Reception covers 20 MHz HT MCS0–7 with BCC or LDPC, mixed and greenfield
formats, valid long/short guard intervals, nonaggregated PSDUs, A-MPDUs,
one-data-stream STBC, and extension training. Transmission covers the 48
single-stream combinations of MCS0–7, BCC/LDPC, mixed long/short GI, and
greenfield long GI. HT40 and additional independent data streams are outside
the supported matrix.

## Evidence requirements

Normative PHY layouts, code matrices, timing and modulation rules use the
reviewed source map in `wifi-phy-evidence.json`. The implemented HT matrix is
covered by independent signaling, coding, modulation, guard-interval,
aggregation, and spatial-arrangement fixtures.

Reference capture metadata is conditional: absent or unknown coding, bandwidth,
STBC or format information must remain unknown. Recover additional parameters
from validated PHY signaling rather than inventing values. The radiotap
[MCS](https://www.radiotap.org/fields/MCS.html) and
[VHT](https://www.radiotap.org/fields/VHT.html) definitions specify which fields
are known; a present field is not sufficient evidence that all its bits apply.

Reference frames are eligible only within independently established overlap
with verified IQ intervals. A saved pcap and IQ file in the same capture session
do not prove that an individual reference frame was recorded in IQ. Incomplete
or overflowing captures remain diagnostic evidence, not passing qualification.

Raw captures and device-specific live evidence remain in operator-owned
artifacts rather than the repository.

## HT-SIG primitive

`HtSignalFields::decode` validates exactly 48 post-BCC binary bits in
transmission order and returns typed HT signaling fields. It checks CRC,
reserved-bit and tail integrity, accepts the zero-length NDP indication, and
preserves all signaled MCS/STBC/extension-stream values. Unsupported combinations
must be checked by the receiving PHY before allocation or DATA decoding.
This primitive alone does not decode an HT waveform or deliver modern frames.

## HT20 BCC receiver increment

`WifiDecoder` uses the existing `PhyDecoder`/radio packet-source interface and
combines legacy reception with mixed-format HT20, one spatial stream, BCC MCS
0–7, and 400/800 ns guard intervals. It estimates the additional HT tones from
HT-LTF, tracks rotating pilots, deinterleaves 52 data carriers and depunctures
all four BCC rates, including 5/6. Only FCS-valid MAC frames are published;
HT aggregate recovery is described below. The existing `LegacyWifiDecoder`
remains legacy-only.

The independent oracle `ht_bcc_vectors.py` supplies 64 full-waveform fixtures:
eight MCS values, both guard intervals, 100/4095-byte PSDUs, and clean or
carrier-offset/multipath conditions. The kernel test supplies timing/CFO to
isolate DATA correctness; the separate streaming test must acquire both from
IQ and checks exact bytes and sample boundaries with three chunk sizes.

Aggregation, greenfield, supported STBC, extension training, and transmission
coverage are described in the sections below. Additional independent streams
and HT40 remain outside the supported matrix.

## LDPC codeword increment

The internal LDPC primitive includes all twelve IEEE HT parity-check matrices:
648/1296/1944-bit blocks at rates 1/2, 2/3, 3/4 and 5/6. Its layered normalized
min-sum decoder is capped at 64 iterations and returns explicit input errors
or nonconvergence. Strict codeword recovery requires a zero syndrome, which
does not replace MAC FCS. Aggregate recovery can retain tentative estimates
from failed codewords under the separate policy below.

`ldpc_vectors.py --check` independently solves systematic parity using GF(2)
Gaussian elimination. The Rust tests verify 36 complete codewords, correction
of eight low-confidence sign errors per word, finite extreme input scales,
dimension checks, unusable metrics and the iteration bound. This primitive is
connected to HT IQ through `WifiDecoder`. The internal rate-matching layer has independent
coverage of 208 geometry cases and 48 shortened/punctured/repeated streams,
including both symbol-group sizes and exact information-bit recovery.

`ht_ldpc_vectors.py --check` supplies 64 complete HT20 LDPC waveforms with the
same MCS/GI/length/impairment matrix as BCC. Streaming recovery checks exact
PSDU bytes, FCS, sample boundaries and coding metadata. Independent malformed
controls target nonconvergence, invalid SERVICE and bad MAC FCS. No BCC
interleaving or tail-bit rules are applied to LDPC DATA.

`PhyDiagnostic::Ldpc` and `LdpcNonconvergence` variants expose codeword
effort and bounded parity failures. Downstream exhaustive matches must add
arms for these variants. These diagnostics and offline fixtures do not by
themselves establish calibrated RF quality or live interoperability.
The legacy receiver recognizes mixed-format HT-SIG after shared legacy
training and emits `PhyDiagnostic::HtSignal` with its original preamble sample
index, followed by `UnsupportedPhy`. It does not deliver the HT payload as a
legacy packet. Recognition requires both a QBPSK constellation check and valid
header integrity. The independent IQ corpus covers clean and carrier-offset /
multipath headers, bad CRCs and unrotated negative controls, not complete HT DATA.
`decode_interleaved` accepts 96 finite soft metrics from two demapped HT-SIG
symbols, reverses each symbol's interleaver and performs one continuous BCC
traceback before the same integrity checks. Positive metrics favor bit 1;
an all-zero metric vector is rejected. Common scaling is normalized to avoid
trellis overflow without changing relative reliability.
Its published baseline and outstanding edition review are recorded in
`wifi-phy-evidence.json`.

## HT aggregate receiver increment

`WifiDecoder` scans HT A-MPDU delimiters after BCC or LDPC PSDU recovery and
publishes one `RecoveredFrame` per FCS-valid MPDU. It checks delimiter CRC and
signature, honors four-byte alignment and zero-length padding delimiters,
and scans again after corruption. A false length or bad MPDU FCS does not
prevent recovery of valid later frames. This receiver policy follows the
informative recovery guidance in IEEE 802.11-2020 Annex O.2; VHT delimiter
length extensions and EOF padding are not interpreted as HT fields.

Each frame retains the containing PPDU's full sample interval. The new
`PhyDiagnostic::Ampdu` records its delimiter byte offset within that PSDU,
preserving distinct occurrences even when two MPDUs have identical bytes.
`AmpduErrors` summarizes malformed delimiters, bad FCS, truncated MPDUs and
oversized MPDUs without allocating a diagnostic for every failed scan step.
Downstream exhaustive diagnostic matches need arms for these new variants.

`max_frame_bytes` applies to each MPDU, not the entire aggregate. The HT PSDU
is bounded by its 16-bit length and the shared IQ buffer reservation. Configure
`max_pending_frames` for the number of output MPDUs per source chunk **plus
two reserved child slots**. Exhausting this bound returns an explicit error
and resets the decoder; it does not return a silently shortened aggregate.

For LDPC aggregates, a failed codeword does not discard the entire PSDU.
The receiver continues bounded decoding of the remaining codewords and scans
the tentative PSDU only after SERVICE validation. Every delivered MPDU must
still pass its own FCS. `PhyDiagnostic::LdpcPartial` counts failed codewords;
the first parity failure also retains `LdpcNonconvergence` details. These
diagnostics accompany recovered frames and require downstream match arms.
Nonaggregated LDPC reception remains strict: any codeword failure rejects it.

`ht_ampdu_vectors.py --check` generates 128 complete independent IQ fixtures
covering both coding families, MCS 0–7, both guard intervals, alignment,
duplicate MPDUs and bad FCS, plus MCS 7 delimiter corruption, truncation,
padding and aggregates larger than 4095 bytes. Four damaged-codeword fixtures
at MCS 3/7 and both guard intervals verify recovery of the intact later MPDU
without publishing the damaged earlier MPDU. These are offline correctness
fixtures, not live HackRF/dongle qualification or a throughput benchmark.

## HT greenfield receiver increment

`WifiDecoder` also recognizes HT20 greenfield with one space-time stream,
no extension streams, MCS0–7, BCC or LDPC, and 800 ns GI. It reads HT-SIG
directly after HT-LTF1, retains all 56 occupied training tones, begins DATA
after the 24 us preamble and uses pilot polarity offset 2. The shared mixed
receiver still uses offset 3 and its additional training field. Greenfield
short GI with immediate DATA is explicitly rejected, following the note in
IEEE 802.11-2020 19.3.11.11.6. The STBC increment below adds a second
space-time stream carrying redundancy, not a second independent data stream.

The 64 independent complete waveforms cover both coding families, all eight
MCS values, two PSDU sizes and clean/carrier-offset-plus-multipath conditions.
The streaming test acquires timing and frequency from IQ at three chunk sizes
and checks exact frame bytes, FCS and original sample coordinates. Eight
negative waveforms cover header CRC, unsupported configurations, SERVICE and
MAC FCS; separate tests exercise truncation, gaps and configured limits.
Four additional aggregate waveforms cover BCC/LDPC at MCS0/7, preserving
identical MPDUs as distinct occurrences and exercising aggregate output bounds.

`PhyDiagnostic::HtGreenfield` tags the associated preamble sample index and
requires an additional downstream exhaustive-match arm. The existing receive
example preserves `ht.format = "greenfield"` in frame and header records;
the comparator checks this against known radiotap format flags. Header-only
diagnostics do not establish MAC integrity. Legacy-only decoder defaults do
not gain greenfield frame delivery. Live interoperability and sustained
throughput require separate evidence.

## HT STBC receiver increment

The internal STBC primitives separate the first two HT-LTF observations into
two effective channels and recover two consecutive constellation symbols for
the NSS1/NSTS2 mapping in IEEE 802.11-2020 Table 19-18. They use bounded,
allocation-free arithmetic, reject nonfinite inputs and unobservable channels,
and retain finite behavior at extreme input scales through wider intermediates.

`stbc_vectors.py --check` independently generates 2400 constellation/training
pairs across BPSK, QPSK, 16-QAM and 64-QAM and six channel pairs. Tests compare
both supplied-channel and training-derived recovery against the independent
expected symbols.

`WifiDecoder` uses these primitives for HT20 NSS1/NSTS2 reception: MCS0–7,
BCC or LDPC, mixed-format GI400/800 and greenfield GI800, without extension
training. It estimates two effective channels from the two data HT-LTFs,
tracks the two-STS pilots and combines consecutive DATA symbols before bit
decoding. Both BCC and LDPC account for the even-symbol STBC grouping.

The independent corpus contains 192 full waveforms covering all eight MCS
values, both coding families, the three supported format/GI combinations,
100/4095-byte PSDUs and clean or independently impaired transmit channels.
Nine negative waveforms cover header CRC, unsupported dimensions, unusable
training, SERVICE, FCS, LDPC nonconvergence and a truncated symbol pair.
Fourteen aggregate waveforms include duplicate MPDUs and damaged LDPC
codewords with an intact later MPDU. Streaming tests check exact bytes,
FCS, sample coordinates and chunk-boundary independence; aggregate tests
also exercise output limits and distinct duplicate occurrences.

The existing receive records preserve STBC metadata and the reference
comparator accepts known STBC=1 without treating unknown reference flags
as zero. Greenfield STBC short-GI applicability remains an explicit source
question; extension training is covered by the increment below, while additional
independent data streams remain unsupported. These offline tests do not
establish live STBC interoperability or real-time throughput. Generating two
synthetic transmit channels for a receive fixture does not enable two-chain
HackRF transmission.

## HT extension-training receiver increment

The independent extension-training corpus models separate sounding dimensions
using IEEE 802.11-2020 Equation 19-26, with DATA dimensions silent during
extension training and extension dimensions silent during DATA. It covers
NESS1–3 without STBC and NESS1–2 with NSS1/NSTS2 STBC, both coding families,
MCS0–7, mixed GI400/800 and greenfield GI800. The 540 full waveforms include
clean and independently impaired short frames plus 4095-byte endpoint cases;
62 aggregates include duplicate MPDUs and corrupted-codeword recovery cases.
Inventory tests verify geometry, hashes, MAC FCS and the configuration matrix.

The streaming receiver now admits these extension-training configurations,
skips the additional training fields, and retains the DATA channel estimates.
Aggregate, truncation, sample-gap, memory-bound and reference-metadata tests
cover this admission path. This is independent-fixture evidence, not live
extension-training qualification. Greenfield short-GI applicability with
additional training remains an explicit source question.

## HT20 transmitter

`HtTxConfig`, `HtTransmission`, and the shared `RadioPacketWriter` encode bare
typed 802.11 packets into bounded 20 Msps CS8 waveforms without opening a
device. The transmitter supports the 48 single-stream HT20 combinations of
MCS0–7, BCC/LDPC, mixed long/short GI, and greenfield long GI. It appends a
derived FCS by default, preserves an explicit FCS verbatim, derives HT-SIG and
mixed-format L-SIG, and retains explicit signaling overrides.

Independent complete-waveform fixtures cover all 32 mixed BCC cases, 32 mixed
LDPC cases, 16 greenfield BCC cases, and 16 greenfield LDPC cases across two
PSDU lengths. LDPC parity and rate matching additionally cover all twelve code
matrices, 36 codewords, and 48 rate-matched streams. The closed live matrix uses
100-byte PSDUs and requires exact reference MAC bytes plus compatible HT
metadata for every case. The same bounded `IqSink` interface serves memory and
HackRF output.

Revision `a55ad8bc374be562d10dea0d376737f3f41ad2b2` passed the repository's
three-run aggregate verifier. Every run recovered all 48 planned raw MAC byte
sequences through an independent monitor receiver with matching MCS and guard
interval metadata, exact HackRF sample supply, zero firmware shortfalls, and
zero kernel capture drops. Optional radiotap coding and format fields were
compared only when the reference driver marked them known; absent reference FCS
remains recorded as such.

## VHT-SIG-A parser increment

The independent `vht_signal_vectors.py --check` corpus contains 1880 header
vectors: 640 SU and 1240 MU cases covering all group IDs and bandwidth codes.
It includes encoded/interleaved bits, per-user MU stream/coding fields and SU
stream, partial-AID and MCS fields. Inventory tests check exact corpus integrity,
dimensions, reserved coding for absent MU users and distinct headers.

`VhtSignalAFields` decodes binary header bits or 96 interleaved soft metrics.
Tests check every fixture, every single-bit corruption, reserved fields,
nonbinary/nonfinite inputs and metric scaling. SU/MU fields are typed separately;
absent MU users retain `None` for coding rather than an inferred coding mode.

The header parser alone does not establish VHT IQ acquisition, DATA recovery,
live qualification or TX. The streaming integration below admits a subset. In particular,
bandwidth code 3 does not distinguish 160 MHz from 80+80 MHz, and the ability
to interpret a header must not be confused with admitting its DATA waveform.

## VHT BCC IQ kernel increment

The private VHT20 SISO BCC IQ kernel connects legacy-preamble acquisition,
L-SIG, VHT-SIG-A, VHT-LTF training, VHT-SIG-B and DATA recovery. Its 108
complete independent waveforms cover MCS 0-8, both guard intervals, short-GI
disambiguation, S-MPDU/EOF/PHY padding, and frequency-offset/multipath cases.
The kernel tests obtain timing and frequency from IQ, not fixture hints, and
compare complete PSDU bytes and sample boundaries. Eight additional waveforms
exercise invalid/unsupported signaling, alongside truncated and unusable inputs.
`WifiDecoder` now connects this kernel to bounded streaming reception and the
VHT-aware aggregate scanner. SIG-A admission reserves DATA samples within the
existing shared candidate buffer budget. Each returned frame has its own FCS,
delimiter offset, and typed SIG-A/SERVICE-verified SIG-B metadata. EOF padding
does not become frame bytes. `radio_receive --modern` labels these frames as
`vht` and adds VHT-only metadata without changing legacy/HT record fields.

The 54 additional complete aggregate waveforms exercise duplicate occurrences,
bad-FCS recovery and 4100-byte MPDUs across MCS0-8 and both GIs. Streaming tests
use one-sample, 79-sample and 4096-sample chunks, with separate gap, buffer and
output-limit checks. Saved-artifact admission permits the same 16383-byte
frame ceiling as the modern example, while retaining explicit allocation bounds.

The example comparator now accepts VHT20 SU NSS1 BCC/LDPC radiotap observations.
It requires known bandwidth/GI and an observed MCS/NSS, interprets other fields
only under their validity bits, and compares known configuration conflicts.
Unknown STBC or SU/MU group information remains an explicit qualification gap.
HT and VHT do not cross-match at equal rates; aggregate frames retain their full
PPDU interval and one-to-one occurrence matching. Header diagnostics never enter
the valid-frame denominator. The 9253 independent metadata vectors and an
IQ-to-synthetic-reference-pcap workflow cover duplicate and large frames; this
is not a substitute for paired hardware qualification. MU, HE/EHT,
hardware qualification, real-time performance and modern TX remain unfinished.

## VHT BCC DATA recovery increment

The internal LDPC rate matcher also has a VHT20 SU geometry entrypoint. Unlike
HT, it includes PHY padding in the encoded information length, derives the
initial symbol count from duration and the extra-symbol flag, and checks that
the resulting puncturing decision agrees with that signaling. Independent
forward fixtures cover 20412 geometries and 54 encoded bitstreams.

VHT LDPC now connects that rate matcher to the same bounded streaming path.
It reverses the VHT20 whole-constellation tone permutation, verifies the SERVICE
CRC against SIG-B, and scans the recovered PSDU with per-MPDU FCS validation.
Partial LDPC estimates carry explicit coding diagnostics; they never bypass FCS.
Seventy-three independent waveforms cover both GIs, MCS0-8, extra-symbol groups,
duplicates, large MPDUs, corrupt FCS, a damaged LDPC codeword and CFO/multipath. This is offline receive
validation, not VHT STBC/MU or hardware qualification.

## VHT one-DATA-stream STBC receiver increment

The VHT receiver also handles two space-time streams carrying one DATA stream.
It separates two LTF DATA columns while retaining the combined channel for
SIG-B and the common VHT pilots. DATA uses the existing two-symbol STBC solver,
not HT's different two-stream pilot patterns. Both BCC and LDPC preserve even
symbol grouping and independent MPDU FCS checks. The 110 complete independent
two-transmitter/one-receiver simulations cover all nine MCS values, both GIs,
large and duplicate frames, CFO/multipath and damaged-codeword recovery.
Nine negative waveforms test malformed signaling and incomplete or corrupt
fields. Reference metadata distinguishes NSS1 from NSTS2 when STBC is known;
unknown STBC remains a qualification gap. Live reception and STBC transmission
are not established by these offline simulations.

## VHT BCC DATA implementation

The private single-encoder VHT BCC DATA recovery path uses the SIG-B CRC in
SERVICE, a nonzero scrambler seed, zero-tail termination after PHY padding,
and the whole-octet PSDU length derived from symbol capacity. Legacy/HT
retain their zero-SERVICE check and tail-before-padding layout. Independent
coded-bit fixtures include all four BCC rates, every nonzero seed, invalid
SERVICE/seed cases, and long payloads up to 58,965 bytes. These are DATA
primitives, not complete IQ or MAC-aggregate qualification.

## VHT 256-QAM demapper increment

The shared data demapper now also handles 256-QAM labels and normalization.
Its independent diagram-derived cases cover all 256 ideal points and 145
off-grid inputs, checking soft metrics, channel weighting and erasures.
Invalid modulation dimensions are rejected instead of falling through to
64-QAM. This does not admit VHT frames through the streaming receiver; pilot,
coding, aggregation and waveform integration remain separate requirements.

## VHT receive timing increment

The private VHT20 timing primitive derives training-field count, DATA start,
DATA symbol count and sample end from validated L-SIG/SIG-A fields. It keeps
the rounded signaled duration separate from the actual DATA end, handles
short-GI symbol-count disambiguation, and rejects inconsistent STBC grouping.
Zero-symbol sounding timing is retained without claiming a DATA payload.

The independent forward-time generator supplies 1,105 cases using exact
rational durations. Receiver tests additionally enumerate every 12-bit L-SIG
length with both guard intervals and disambiguation values, and check invalid
stream counts and input bounds. This is timing groundwork, not integrated
VHT waveform acquisition or DATA decoding.

## VHT20 SIG-B and SERVICE increment

`VhtSignalB20Fields` interprets 26 decoded bits or 52 equalized soft metrics,
using the SU/MU context from SIG-A. It preserves encoded length units and
exposes their inclusive byte-length bounds, not an invented exact length.
The NDP pattern is recognized only in SU context; the same MU bits retain
their length/MCS meaning.

Parsing SIG-B does not verify its CRC. `verify_service` checks the 16
already-descrambled DATA SERVICE bits against the header-derived CRC and
zero prefix. NDP has no DATA/SERVICE and cannot pass that verification.
The independent 225-case corpus covers lengths, all MU MCS field values,
NDP context, BCC/interleaving and SERVICE linkage; tests also reject single-bit
header/SERVICE corruption and malformed inputs. This remains a primitive for
VHT integration, not complete VHT IQ acquisition, frame recovery or TX.

## Existing example and replay workflow

The receive example's leading `--modern` flag selects `WifiDecoder`, including
legacy reception and the HT modes described above. Without it, existing legacy
behavior is unchanged. It uses the same source, IQ recording, packet parsing,
terminal evidence and JSONL artifact path:

```sh
cargo run -p crafter --features radio --example radio_receive -- --modern --replay crafter/tests/fixtures/iq/ht-ampdu-7-gi800-ldpc-duplicate.cs8
cargo run -p crafter --features radio --example radio_receive -- --modern --replay-artifact saved-iq.iq
```

Modern recording writes `decoder: "wifi"` in the existing v2 IQ header. Replay
without an override preserves that selection. `--modern` can explicitly decode
an older recording through the new receiver; original IQ and recorded bounds
are preserved. Modern replay cannot use legacy parallel/windowed dispatch.
New raw/live modern configurations reserve 1024 output slots; older recordings
retain their original output limit and may fail explicitly if an aggregate
exceeds it. No samples are discarded to make an overflowing replay pass.

Frame records report `phy: "ht"`, structured `ht` signaling fields and an
`ampdu` delimiter offset when applicable, alongside original MAC bytes and
sample coordinates. Legacy frames have null HT/aggregate metadata. The
existing benchmark accepts mode `wifi` for this decoder and includes aggregate
offsets in its occurrence digest. This exposes a measurement path; it does not
claim real-time performance.

Modern receive artifacts also emit bounded `ht_signal` diagnostic records for
integrity-checked headers, including modes whose DATA is not supported or not
recovered. These contain the epoch, preamble coordinate and signaling fields,
and explicitly do **not** establish MAC integrity. The comparator validates
their ordering and coordinates and reports their count separately; they never
increase frame counts or matching denominators.

The existing `radio_compare` path now accepts HT20 MCS0–7 reference metadata
when bandwidth, MCS and GI are known. Coding, STBC, format and extension-stream
values are compared only when known; explicitly unsupported configurations
remain exclusions. Missing STBC/format/extension-stream knowledge is counted
and reported as a qualification gap, not silently assumed to mean zero.
Reference FCS absence remains separately integrity-unverified.

HT matching consumes distinct raw-byte occurrences one-to-one, requires
compatible known PHY parameters, and uses the containing PPDU interval for
each recovered MPDU. It retains both the IQ delimiter offset and the dongle's
independently generated aggregation reference. Unknown reference coding can
match either supported coding family; an augmenting-path matcher prevents
such a flexible observation from hiding a more constrained valid pairing.
The matching logic does not derive a clock from byte matches. Independently
recorded timing and capture-loss evidence remain mandatory, and reported
measurements are not automatically a passing live qualification.
