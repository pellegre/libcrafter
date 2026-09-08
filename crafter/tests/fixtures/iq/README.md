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
false-positive checks for noise and unsupported PHY observations. Keep long or
large generated artifacts ignored; commit compact reproducible fixtures and
provenance only. No hardware or network access is needed to replay fixtures.

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
