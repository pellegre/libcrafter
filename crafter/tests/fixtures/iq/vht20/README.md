# VHT20 independent IQ corpus

The synthetic receive corpus contains 108 BCC waveforms, 73 LDPC waveforms,
and 54 additional BCC aggregate waveforms. It covers MCS0–8, both guard
intervals, carrier offset and multipath, single MPDUs, duplicate occurrences,
large MPDUs, delimiter recovery and damaged LDPC codewords. Eleven negative
waveforms exercise unsupported signaling, header integrity, SERVICE and FCS.

`index.tsv` records expected FCS-bearing MPDUs, coding, MCS, guard length in
samples, SHA-256 and the original exclusive DATA sample end. All waveforms
start their preamble at sample 37. `invalid.tsv` identifies rejection controls.
`ldpc-rate.tsv` independently specifies codeword geometry from initial symbol
counts, MCS and symbol grouping; the one-stream receiver uses group 1.

The forward construction follows IEEE 802.11-2020 clauses 9.7, 10.12.6–8 and
21, including Table 21-29. These are offline correctness fixtures.
