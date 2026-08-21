# SCTP fixture catalog

This catalog plans the deterministic SCTP fixtures that later implementation
steps should add under the crate fixture and validation suites. It records the
byte fixture families, malformed fixture families, summary expectations, and
pcap coverage needed to validate SCTP as a `crafter` packet primitive.

Wire facts come from `.agents/docs/sctp-rfc-manifest.md`,
`.agents/docs/sctp-codepoints.md`, `.agents/docs/sctp-wire-grammar.md`,
`.agents/docs/sctp-scope.md` and
`.agents/docs/sctp-api-design.md`. Later fixture files should cite the narrower
RFC section, IANA row, or erratum used for each case.

## Deterministic inputs

Use only synthetic, documentation-safe values:

| Field class | Fixture values |
| --- | --- |
| IPv4 endpoints | `192.0.2.10` to `198.51.100.20` |
| IPv6 endpoints | `2001:db8::10` to `2001:db8::20` |
| UDP encapsulation | port `9899` only when the RFC 6951 shape gate admits SCTP |
| SCTP ports | source `5000`, destination `5001`, plus explicit malformed `0` cases |
| Verification tags | `0x00000000` for INIT, `0x11223344` for established-shape fixtures, explicit override cases as listed below |
| TSNs and stream IDs | TSN `0x01020304`, stream `7`, sequence `9`, initial TSN `0x10203040` |
| PPIDs | `0` reserved, `50` WebRTC DCEP label-only, and `4242` draft-backed label-only |
| Payload bytes | short ASCII fixtures such as `crafter-sctp-fixture`, never live captures |

Every byte fixture should include the expected wire hex, decoded model shape,
`summary()` line, `show()` fields, and checksum status expectation. Generated
checksums must be deterministic and explicit checksum overrides must survive
unchanged.

## Byte fixtures to add later

| Fixture family | Planned coverage |
| --- | --- |
| `sctp_init_ipv4` | Native IPv4 carrying protocol `132`, SCTP common header, INIT chunk, initiate tag, receive window, outbound and inbound stream counts, initial TSN, IPv4 and IPv6 address parameters, and zero padding where required. |
| `sctp_init_ack_ipv6` | Native IPv6 carrying next-header `132`, INIT ACK chunk, state cookie parameter, supported address types, supported extensions, and checksum status. |
| `sctp_data_minimal` | DATA chunk with E/B flags, TSN, stream ID, stream sequence, PPID label, short user payload, and chunk padding excluded from semantic payload bytes. |
| `sctp_data_unordered_fragment_flags` | DATA chunk preserving U/B/E/I and unassigned flag bits exactly, including explicit noncanonical flag combinations. |
| `sctp_sack_basic` | SACK chunk with cumulative TSN ACK, advertised receiver window, gap acknowledgement blocks, duplicate TSNs, and length handling documented with the RFC 9260 SACK errata note. |
| `sctp_heartbeat_pair` | HEARTBEAT and HEARTBEAT ACK chunks preserving heartbeat-info parameters and parameter padding. |
| `sctp_abort_error_causes` | ABORT with T bit, ERROR chunk causes, known cause labels, unknown well-formed cause preservation, and cause padding. |
| `sctp_shutdown_sequence_controls` | SHUTDOWN, SHUTDOWN ACK, SHUTDOWN COMPLETE with T bit preservation, COOKIE ECHO, COOKIE ACK, ECNE, and CWR control chunk labels. |
| `sctp_extension_chunks_preserved` | AUTH, I-DATA, ASCONF, ASCONF ACK, RE-CONFIG, PAD, FORWARD TSN, ASCONF, I-FORWARD TSN, reserved values, and temporary DTLS chunk values as byte-preserving packet data until typed behavior lands. |
| `sctp_unknown_chunk_actions` | Unknown chunk types in each high-bit action class, preserving type, flags, declared value bytes, and padding without dropping the containing packet. |
| `sctp_unknown_parameters` | Unknown parameter types in each high-bit action class, preserving parameter type, declared value bytes, and padding inside typed chunks. |
| `sctp_checksum_overrides` | Auto-filled CRC32c, explicit valid checksum, explicit invalid checksum, and explicit zero checksum with caller-visible checksum status. |
| `sctp_header_only_builder` | Header-only serialization for deterministic packet tests when the API permits it, with source and destination ports, verification tag, and checksum fields inspectable. |
| `sctp_udp_encap_admitted` | UDP/9899 payload that passes the RFC 6951 SCTP shape gate and decodes as typed SCTP while keeping UDP and SCTP checksums separate. |
| `sctp_udp_9899_raw_rejected` | UDP/9899 payload with unrelated bytes that remains `Raw` rather than being misidentified as SCTP. |

## Malformed fixtures to add later

Malformed fixtures should decode through the same entrypoints as valid
fixtures and assert structured errors with context, required length, and
available length where applicable. They should never assert panics or silent
truncation.

| Fixture family | Expected malformed boundary |
| --- | --- |
| `sctp_truncated_common_header` | Fewer than the 12 common-header octets are available. |
| `sctp_chunk_header_truncated` | A common header is present but fewer than four bytes remain for a chunk header. |
| `sctp_chunk_length_under_minimum` | Chunk length is less than the four-octet chunk header. |
| `sctp_chunk_length_overrun` | Chunk length or required padding exceeds the remaining SCTP packet bytes. |
| `sctp_parameter_header_truncated` | A parameter-bearing chunk value ends before a four-octet parameter header. |
| `sctp_parameter_length_under_minimum` | Parameter length is less than the four-octet parameter header. |
| `sctp_parameter_length_overrun` | Parameter length or required padding exceeds the enclosing chunk value. |
| `sctp_cause_header_truncated` | ERROR or ABORT chunk value ends before a four-octet cause header. |
| `sctp_cause_length_under_minimum` | Cause length is less than the four-octet cause header. |
| `sctp_cause_length_overrun` | Cause length or required padding exceeds the enclosing ERROR or ABORT chunk value. |
| `sctp_explicit_port_zero` | Source or destination port `0` is preserved for construction and inspection while validation reports the malformed wire fact. |
| `sctp_explicit_bad_checksum` | Invalid checksum bytes remain inspectable and report invalid checksum status instead of rejecting otherwise well-formed SCTP. |
| `sctp_nonzero_padding_preserved` | Nonzero padding is byte-preserved for round trip and inspection while semantic chunk, parameter, and cause values exclude padding bytes. |

Unknown but structurally valid chunk types, parameter types, cause codes,
flags, PPIDs, HMAC IDs, adaptation code points, and error-detection method IDs
are not malformed fixtures. They belong in byte-preserving fixtures.

## Summary and show coverage

Later summary fixtures should assert stable, compact strings for:

- native SCTP over IPv4 and IPv6 with protocol or next-header `132`;
- guarded UDP encapsulation with UDP port `9899`;
- common-header ports, verification tag, and checksum status;
- chunk names from current IANA rows and numeric labels for unknown values;
- DATA and I-DATA flags, TSN, stream ID, stream sequence, PPID value, and PPID label;
- INIT and INIT ACK core fields plus parameter labels;
- ERROR and ABORT cause labels plus unknown cause preservation;
- explicit override indicators for caller-supplied checksum, lengths, flags, and codepoints; and
- padding byte counts without folding padding into semantic value lengths.

`show()` fixtures should include enough fields for generated tools to inspect
packet decisions without parsing raw hex: declared lengths, computed padding
lengths, checksum status, raw unknown codepoints, and byte counts for payload,
parameter values, cause values, and padding.

## Pcap coverage to add later

Pcap fixtures should be synthetic and reproducible from the byte fixtures. They
must use documentation address space and must not be copied from live external runner
traffic or local host captures.

| Pcap family | Planned packets |
| --- | --- |
| `sctp_native_ipv4.pcap` | Ethernet plus IPv4 packets for INIT, DATA, SACK, HEARTBEAT, ABORT/ERROR, and unknown chunk preservation. |
| `sctp_native_ipv6.pcap` | Ethernet plus IPv6 packets for INIT ACK, DATA, SHUTDOWN controls, parameter padding, and checksum status cases. |
| `sctp_linux_cooked.pcap` | Linux cooked capture records carrying native SCTP over IPv4 and IPv6 for decode entrypoint parity. |
| `sctp_null_loopback.pcap` | Null or loopback linktype records carrying raw IPv4 or IPv6 SCTP payloads for non-Ethernet fixture coverage. |
| `sctp_udp_encap.pcap` | UDP/9899 admitted SCTP, UDP/9899 unrelated Raw payload, and separate UDP and SCTP checksum expectations. |
| `sctp_malformed.pcap` | Bounded malformed buffers for truncation and length-error assertions where the pcap reader can safely retain packet bytes. |

Oracle and probe coverage should consume these fixtures through offline or
dry-run paths first. Externally executed live validation is out of scope for this
catalog and must stay gated by the SCTP validation-safety note.
