# Independent IQ vector contract

This directory will contain synthetic, offline receive vectors. It contains no
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
