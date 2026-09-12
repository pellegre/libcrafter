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
