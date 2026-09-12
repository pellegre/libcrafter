# Modern Wi-Fi IQ implementation contract

The modern radio extension recovers raw IEEE 802.11 frame bytes from IQ and
constructs transmit IQ from packets. It does not decrypt payloads. The existing
packet, radio source, replay, and bounded transmitter interfaces remain the
integration boundary.

This is a development contract, not a claim of implemented modern support.
The legacy implementation and its measured coverage are documented in
[radio.md](radio.md).

## Scope and order

The intended scope is applicable 20 MHz HT, VHT, HE and EHT reception and
transmission with one receive channel. A single data stream can still use
space-time coding; spatial-stream count alone does not establish whether a
particular implementation can recover the transmission. Unsupported spatial
arrangements and bandwidths must be identified explicitly.

Implementation proceeds through three gates:

1. Recover correct bytes, including aggregate MPDU boundaries and individual
   FCS validation. Use independently generated intermediate and complete IQ
   vectors, then paired radio/reference captures and exact replay. Repair
   correctness failures before optimizing.
2. Sustain more than 20 million complex samples per second on representative
   modern and legacy traffic. Verify frame occurrences as well as throughput,
   memory bounds, sample continuity, queue growth and delivery latency.
3. Encode packet-derived modern waveforms, preserve explicit field overrides,
   and validate finite transmissions with independent receivers. Agreement
   between the library's own encoder and decoder is supplementary evidence.

## Evidence requirements

Normative PHY layouts, code matrices, timing and modulation rules require a
reviewed source map before implementation. HT/VHT/HE/EHT each need an explicit
matrix of supported signaling, coding, modulation, guard intervals, aggregation
and spatial arrangements. An unimplemented or unverified matrix entry must not
be presented as supported.

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

HT/VHT-capable reference hardware does not establish HE/EHT interoperability.
Independent offline work can proceed, but missing capable-reference live
evidence remains an explicit qualification gap. Raw captures, credentials,
device identities and execution topology belong in operator-owned artifacts,
never in the repository.
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

This BCC increment does not qualify aggregation, STBC, additional streams,
greenfield, VHT, HE, EHT, live interoperability, real-time throughput, or modern
transmission. Those remain required work under the full contract above.

## LDPC codeword increment

The internal LDPC primitive includes all twelve IEEE HT parity-check matrices:
648/1296/1944-bit blocks at rates 1/2, 2/3, 3/4 and 5/6. Its layered normalized
min-sum decoder is capped at 64 iterations and returns explicit input errors
or nonconvergence. A zero syndrome is necessary but does not replace MAC FCS.

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

New `PhyDiagnostic::Ldpc` and `LdpcNonconvergence` variants expose codeword
effort and bounded parity failures. Downstream exhaustive matches must add
arms for these variants. These diagnostics do not establish calibrated RF
quality or live interoperability. Live qualification remains required work,
along with the broader formats in the contract above.
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

`ht_ampdu_vectors.py --check` generates 124 complete independent IQ fixtures
covering both coding families, MCS 0–7, both guard intervals, alignment,
duplicate MPDUs and bad FCS, plus MCS 7 delimiter corruption, truncation,
padding and aggregates larger than 4095 bytes. These are offline correctness
fixtures, not live HackRF/dongle qualification or a throughput benchmark.

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
New raw/live modern configurations reserve1024 output slots; older recordings
retain their original output limit and may fail explicitly if an aggregate
exceeds it. No samples are discarded to make an overflowing replay pass.

Frame records report `phy: "ht"`, structured `ht` signaling fields and an
`ampdu` delimiter offset when applicable, alongside original MAC bytes and
sample coordinates. Legacy frames have null HT/aggregate metadata. The
existing benchmark accepts mode `wifi` for this decoder and includes aggregate
offsets in its occurrence digest. This exposes a measurement path; it does not
claim real-time performance.

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
