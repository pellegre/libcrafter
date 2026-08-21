# NTP Scapy Coverage Matrix

This matrix records the NTP oracle coverage policy for the Scapy backend.
NTP coverage is packet-layer coverage only: UDP/123 payload bytes, the fixed
48-octet header, extension field envelopes, NTS packet extension bodies,
legacy MAC tails, raw fallback, and structured malformed-input behavior.
Clock synchronization, peer selection, NTS key exchange, Autokey verification,
scanning, retries, and live target selection are out of scope.

Offline oracle runs are the default. External operator tooling owns any later
live validation.

## How To Read This Matrix

- **Case ID** is the executable or declared case name from the NTP layer and
  feature specs.
- **Directions** are `backend_to_libcrafter`, `libcrafter_to_backend`,
  `roundtrip`, or a subset of those directions.
- **Byte policy** is `strict_bytes` when Scapy and libcrafter must preserve the
  exact payload bytes, `normalized` when the case documents a libcrafter
  contract that a reference backend may normalize or reject, and
  `structured_error` for malformed direct-decode cases.
- **Backend path** records whether Scapy should use native NTP materialization
  when available, deterministic raw UDP payload bytes, or no Scapy byte
  comparison.

Scapy is only a byte oracle for valid or raw-preserving packet shapes. It is
not the authority for libcrafter's structured `CrafterError` contexts.

## Strict-Byte Cases

These cases are Scapy-executable once the backend adapter exists. They compare
deterministic NTP payload bytes and the normalized decoded NTP model without
weakening byte preservation.

| Area | Case ID | Directions | Byte policy | Backend path |
| --- | --- | --- | --- | --- |
| Fixed header | `ntp-header-client-request` | `backend_to_libcrafter`, `libcrafter_to_backend`, `roundtrip` | `strict_bytes` | Native NTP or raw UDP/123 payload bytes |
| Fixed header | `ntp-header-server-response` | `backend_to_libcrafter`, `libcrafter_to_backend`, `roundtrip` | `strict_bytes` | Native NTP or raw UDP/123 payload bytes |
| Fixed header | `ntp-header-kiss-o-death` | `backend_to_libcrafter`, `libcrafter_to_backend`, `roundtrip` | `strict_bytes` | Native NTP or raw UDP/123 payload bytes |
| Fixed header | `ntp-header-ntpv3-sntp` | `backend_to_libcrafter`, `libcrafter_to_backend`, `roundtrip` | `strict_bytes` | Native NTP or raw UDP/123 payload bytes |
| Fixed header | `ntp-header-raw-timestamps` | `backend_to_libcrafter`, `libcrafter_to_backend`, `roundtrip` | `strict_bytes` | Native NTP or raw UDP/123 payload bytes |
| Extensions | `ntp-extension-unknown-field` | `backend_to_libcrafter`, `libcrafter_to_backend`, `roundtrip` | `strict_bytes` | Raw extension envelope bytes under NTP |
| Extensions | `ntp-extension-checksum-complement` | `backend_to_libcrafter`, `libcrafter_to_backend`, `roundtrip` | `strict_bytes` | Raw extension envelope bytes under NTP |
| Extensions | `ntp-extension-with-legacy-mac` | `backend_to_libcrafter`, `libcrafter_to_backend`, `roundtrip` | `strict_bytes` | Raw extension envelope plus legacy MAC bytes |
| Extensions | `ntp-extension-standalone-legacy-mac` | `backend_to_libcrafter`, `libcrafter_to_backend`, `roundtrip` | `strict_bytes` | Raw legacy MAC tail bytes |
| NTS | `ntp-nts-unique-identifier` | `backend_to_libcrafter`, `libcrafter_to_backend`, `roundtrip` | `strict_bytes` | Opaque NTS extension body bytes |
| NTS | `ntp-nts-cookie` | `backend_to_libcrafter`, `libcrafter_to_backend`, `roundtrip` | `strict_bytes` | Opaque NTS extension body bytes |
| NTS | `ntp-nts-cookie-placeholder` | `backend_to_libcrafter`, `libcrafter_to_backend`, `roundtrip` | `strict_bytes` | Opaque NTS extension body bytes |
| NTS | `ntp-nts-authenticator-opaque` | `backend_to_libcrafter`, `libcrafter_to_backend`, `roundtrip` | `strict_bytes` | Opaque authenticator extension body bytes |
| NTS | `ntp-nts-authenticator-parts` | `backend_to_libcrafter`, `libcrafter_to_backend`, `roundtrip` | `strict_bytes` | Opaque body bytes plus normalized body-part metadata |
| NTS | `ntp-nts-stack` | `backend_to_libcrafter`, `libcrafter_to_backend`, `roundtrip` | `strict_bytes` | Ordered opaque NTS extension body bytes |

## Normalized Cases

| Area | Case ID | Directions | Byte policy | Decision |
| --- | --- | --- | --- | --- |
| Fixed header overrides | `ntp-header-override-friendly-fields` | `roundtrip` | `normalized` | This is a libcrafter contract-only case. It records that unusual explicit LI, version, mode, stratum, poll, precision, and reference ID values survive serialization. Scapy may normalize or reject some unusual combinations, so a Scapy backend must not claim strict byte support for this row until it can materialize the exact bytes. |

No other NTP case is currently normalized. Valid NTP headers, extension fields,
NTS extension bodies, and legacy MAC tails are byte-preservation cases.

## Backend-To-Libcrafter-Only Cases

These rows use backend-owned bytes to prove libcrafter decode and raw fallback
behavior. They are not malformed Rust-only structured-error cases, but the
Scapy source direction is the meaningful oracle direction.

| Area | Case ID | Directions | Byte policy | Decision |
| --- | --- | --- | --- | --- |
| Ambiguous tail | `ntp-extension-ambiguous-tail` | `backend_to_libcrafter`, `roundtrip` | `strict_bytes` | Backend-owned bytes prove that a plausible 20-octet legacy MAC tail stays a MAC, even when its first four bytes could also be read as an extension envelope. |
| Raw fallback | `ntp-extension-raw-fallback-boundary` | `backend_to_libcrafter`, `roundtrip` | `strict_bytes` | Backend-owned UDP/123 bytes prove stack dispatch keeps an invalid NTP tail as `Raw` while direct NTP decode reports a structured extension error. |

## Rust-Only Malformed Coverage

Malformed short-header and malformed extension cases are declared in the oracle
specs for coverage accounting, but they stay out of Scapy strict-byte fixture
comparison. The current oracle path compares materialized packet bytes and
normalized decoded packet models. It does not compare libcrafter's structured
`CrafterError` fields (`context`, `required`, and `available`). For these
inputs there is no valid NTP packet model after direct decode rejects the
payload, and asking Scapy for a byte comparison would either compare raw bytes
only or depend on Scapy's unrelated malformed-packet tolerance.

The Rust tests are the authority for these malformed decisions because they
assert the packet primitive's required behavior directly: stable structured
errors, no panic, and UDP registry raw fallback when the stack decoder cannot
accept an NTP-shaped payload.

| Case ID | Scope | Rust coverage |
| --- | --- | --- |
| `ntp-malformed-short-header` | Direct NTP payload shorter than the 48-octet fixed header | `crafter/tests/ntp_malformed.rs::ntp_short_header_reports_buffer_too_short_for_every_truncated_length` |
| `malformed-ntp-short-extension-header` | Tail shorter than the four-octet extension envelope header | `crafter/tests/ntp_malformed.rs::ntp_malformed_extension_short_headers_report_structured_errors`; `crafter/tests/ntp_malformed.rs::ntp_malformed_extension_short_fixture_reports_structured_error` |
| `malformed-ntp-invalid-extension-length` | Extension declared length below the source-backed minimum or not four-octet aligned | `crafter/tests/ntp_malformed.rs::ntp_malformed_extension_invalid_lengths_report_structured_errors`; `crafter/tests/ntp_core.rs::ntp_malformed_extension_length_is_structured_error` |
| `malformed-ntp-truncated-mac-after-extension` | Extension followed by too few bytes for a legacy MAC key ID | `crafter/tests/ntp_malformed.rs::ntp_malformed_corpus_reports_structured_outcomes` |
| `ntp-corpus` malformed rows | Short header, short extension header, invalid extension length, truncated MAC after extension, and ambiguous extension-shaped legacy MAC tail | `crafter/tests/ntp_malformed.rs::ntp_malformed_corpus_reports_structured_outcomes`; `crafter/tests/fixtures/malformed/ntp-corpus.hex` |

If the oracle later gains a first-class structured-error comparison pathway,
these rows may move from Rust-only to executable `backend_to_libcrafter`
structured-error cases. Until then, they must not be represented as Scapy
strict-byte successes and must not weaken libcrafter's malformed-input tests.

## Backend Limitations

- Scapy support for NTP extensions and NTS packet extensions may require raw
  UDP payload bytes even when Scapy has a native NTP layer. Raw materialization
  is acceptable for valid packet shapes as long as the exact bytes are owned by
  the case and the decoded libcrafter model is compared.
- NTS data is opaque packet data. The oracle must not attempt NTS-KE, AEAD
  verification, cookie construction, replay-cache decisions, or secret handling.
- Unknown extension field types, duplicate Autokey/NTS registry assignments,
  explicit unusual header values, and legacy MAC tails are preservation cases.
  Backends must not normalize them away.
- Malformed structured-error rows are not Scapy strict-byte rows. External
  qualification must exclude malformed decode-only cases unless its own
  explicitly authorized workload says otherwise.
