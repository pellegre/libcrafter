# TLS Scapy Coverage Matrix

This matrix records the TLS oracle coverage implemented for the Scapy backend
and the parser-only Wireshark backend. TLS coverage is packet-layer coverage
only: record framing, selected handshake structures, selected extension bodies,
alerts, ChangeCipherSpec, heartbeat packet grammar, opaque application data, and
unknown/raw preservation. Endpoint state, transcript hashing, certificates, key
schedule, encryption, TCP stream reassembly, scanning, and live target selection
are out of scope.

All generated stacks use documentation address space and deterministic TCP/TLS
bytes. Offline oracle runs are the default; external operator tooling owns live
validation.

## How To Read This Matrix

- **Case ID** is the executable case name from the TLS feature specs.
- **Directions** are `backend_to_libcrafter`, `libcrafter_to_backend`, or both.
- **Byte policy** is `strict_bytes` when Scapy and libcrafter must agree on
  exact bytes. `normalized` means a future backend may compare decoded structure
  while allowing a valid alternate encoding. TLS currently has no executable
  normalized cases in the Scapy matrix.
- **Backend path** records whether Scapy builds structured fields, exact raw TLS
  bytes, or only decodes through Wireshark.
- **Malformed scope** records cases that assert structured errors rather than a
  strict byte comparison.

## Executable Strict-Byte Cases

| Area | Case ID | Directions | Byte policy | Backend path |
| --- | --- | --- | --- | --- |
| Records | `tls-record-client-hello` | both | strict_bytes | Scapy exact TLS record bytes |
| Records | `tls-record-alert` | both | strict_bytes | Scapy exact TLS alert record |
| Records | `tls-record-change-cipher-spec` | both | strict_bytes | Scapy exact ChangeCipherSpec record |
| Records | `tls-record-application-data-opaque` | both | strict_bytes | Scapy opaque application_data record |
| Records | `tls-record-unknown-content-type` | both | strict_bytes | Scapy raw content type preservation |
| Records | `tls-stacked-records` | both | strict_bytes | Scapy concatenated TLS records |
| Records | `tls-record-explicit-length-override` | libcrafter_to_backend | strict_bytes | libcrafter explicit override bytes |
| Handshake | `tls-handshake-client-hello-tls12` | both | strict_bytes | Scapy raw/structured ClientHello bytes |
| Handshake | `tls-handshake-client-hello-tls13` | both | strict_bytes | Scapy raw/structured ClientHello bytes |
| Handshake | `tls-handshake-server-hello-tls12` | both | strict_bytes | Scapy raw/structured ServerHello bytes |
| Handshake | `tls-handshake-server-hello-tls13` | both | strict_bytes | Scapy raw/structured ServerHello bytes |
| Handshake | `tls-handshake-hello-retry-request` | both | strict_bytes | Scapy ServerHello variant bytes |
| Handshake | `tls-handshake-encrypted-extensions-empty` | both | strict_bytes | Scapy exact handshake bytes |
| Handshake | `tls-handshake-encrypted-extensions-unknown` | both | strict_bytes | Scapy unknown extension bytes |
| Handshake | `tls-handshake-certificate-tls12` | both | strict_bytes | Scapy opaque certificate bytes |
| Handshake | `tls-handshake-certificate-tls13` | both | strict_bytes | Scapy opaque certificate bytes |
| Handshake | `tls-handshake-certificate-request-tls12` | both | strict_bytes | Scapy exact handshake bytes |
| Handshake | `tls-handshake-certificate-request-tls13` | both | strict_bytes | Scapy exact handshake bytes |
| Handshake | `tls-handshake-certificate-verify` | both | strict_bytes | Scapy opaque signature bytes |
| Handshake | `tls-handshake-finished` | both | strict_bytes | Scapy opaque verify_data bytes |
| Handshake | `tls-handshake-new-session-ticket-tls12` | both | strict_bytes | Scapy exact handshake bytes |
| Handshake | `tls-handshake-new-session-ticket-tls13` | both | strict_bytes | Scapy exact handshake bytes |
| Handshake | `tls-handshake-key-update` | both | strict_bytes | Scapy exact handshake bytes |
| Handshake | `tls-handshake-end-of-early-data` | both | strict_bytes | Scapy empty handshake body |
| Handshake | `tls-handshake-unknown-preservation` | both | strict_bytes | Scapy raw handshake type preservation |
| Extensions | `tls-extension-sni` | both | strict_bytes | Scapy ClientHello extension bytes |
| Extensions | `tls-extension-alpn` | both | strict_bytes | Scapy ClientHello extension bytes |
| Extensions | `tls-extension-supported-versions-client` | both | strict_bytes | Scapy ClientHello extension bytes |
| Extensions | `tls-extension-supported-versions-server` | both | strict_bytes | Scapy ServerHello extension bytes |
| Extensions | `tls-extension-supported-groups` | both | strict_bytes | Scapy ClientHello extension bytes |
| Extensions | `tls-extension-signature-algorithms` | both | strict_bytes | Scapy ClientHello extension bytes |
| Extensions | `tls-extension-key-share-client` | both | strict_bytes | Scapy ClientHello extension bytes |
| Extensions | `tls-extension-key-share-server` | both | strict_bytes | Scapy ServerHello extension bytes |
| Extensions | `tls-extension-key-share-hello-retry-request` | both | strict_bytes | Scapy HelloRetryRequest extension bytes |
| Extensions | `tls-extension-psk-key-exchange-modes` | both | strict_bytes | Scapy ClientHello extension bytes |
| Extensions | `tls-extension-pre-shared-key-client` | both | strict_bytes | Scapy ClientHello extension bytes |
| Extensions | `tls-extension-pre-shared-key-server` | both | strict_bytes | Scapy ServerHello extension bytes |
| Extensions | `tls-extension-cookie` | both | strict_bytes | Scapy HelloRetryRequest extension bytes |
| Extensions | `tls-extension-padding` | both | strict_bytes | Scapy ClientHello extension bytes |
| Extensions | `tls-extension-record-size-limit` | both | strict_bytes | Scapy ClientHello extension bytes |
| Extensions | `tls-extension-status-request` | both | strict_bytes | Scapy ClientHello extension bytes |
| Extensions | `tls-extension-certificate-authorities` | both | strict_bytes | Scapy CertificateRequest extension bytes |
| Extensions | `tls-extension-unknown-preservation` | both | strict_bytes | Scapy raw extension preservation |
| Extensions | `tls-extension-duplicate-preservation` | both | strict_bytes | Scapy duplicate extension preservation |

## Normalized Cases

None are executable today. The TLS Scapy backend emits deterministic bytes for
all well-formed selected cases, and libcrafter preserves explicit overrides.
If a future TLS backend normalizes a valid alternate wire shape, add that case
here and mark the feature spec with `byte_policy: normalized` plus the exact
field-level reason.

## Structured-Error Exclusions

Malformed TLS length cases are intentionally outside strict Scapy byte
comparison. They assert that libcrafter returns a structured `CrafterError` with
context, required length, and available length rather than panicking or silently
truncating.

| Area | Case ID | Expected structured-error scope |
| --- | --- | --- |
| Records | `tls-malformed-record-length` | record length exceeds available bytes |
| Handshake | `tls-malformed-handshake-length` | handshake length exceeds record fragment |
| Extensions | `tls-malformed-extension-length` | extension vector or extension body length exceeds available bytes |

## Backend Limitations

- Scapy is the byte materializer for TLS oracle comparisons. Where Scapy lacks a
  stable high-level TLS helper, the backend emits exact Raw bytes under the
  surrounding root (`raw:tls`, IPv4/TCP/TLS, or IPv6/TCP/TLS) and then normalizes
  the decoded TLS model.
- Wireshark is parser-only. It decodes `l3:ipv4`, `l3:ipv6`, and pcap inputs
  when `tshark` is available, and `raw:tls` records are normalized from source
  bytes because tshark has no bare TLS-record datalink decoder.
- Unknown record content types, unknown handshake types, unknown extension
  types, duplicate extensions, opaque encrypted/application bytes, and explicit
  TCP/TLS overrides are preservation cases. Backends must not normalize them
  away.
- TLS-over-UDP, DTLS, QUIC TLS transcript plumbing, certificate validation,
  decryption, and TCP stream behavior are not modeled by this packet primitive.

## Reproducing Coverage

Run the focused Scapy offline suite:

```sh
tools/oracle/run offline --backend scapy --family tls --profile tls-smoke --seed 8446 --count 20 --direction libcrafter_to_backend --out target/oracle/tls-offline-ltr
tools/oracle/run offline --backend scapy --family tls --profile tls-smoke --seed 8447 --count 20 --direction backend_to_libcrafter --out target/oracle/tls-offline-rtl
```

Run pcap checks:

```sh
tools/oracle/run pcap --backend scapy --family tls --profile tls-smoke --seed 8448 --count 10 --out target/oracle/tls-pcap-scapy
tools/oracle/run pcap --backend wireshark --direction libcrafter_to_backend --family tls --profile tls-smoke --seed 8448 --count 5 --out target/oracle/tls-pcap-wireshark
```

When `tshark` is unavailable, Wireshark runs should produce an unsupported
backend report rather than a source failure. Artifacts belong under ignored
`target/` directories.
