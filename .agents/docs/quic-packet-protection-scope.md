# QUIC Packet Protection Scope

This note records the dependency and API boundary for the packet-protection
helpers allowed by the QUIC bootstrap plan. It is source-backed by
`.agents/docs/quic-manifest.md`, especially `E-RFC-9001`, and narrows the
deferred packet-protection row in `.agents/docs/quic-scope.md`.

RFC 9001 is selected only for explicit packet-layer utilities: Initial secret
derivation, header protection, packet-protection vector checks, and Retry
integrity tag verification. It does not authorize a TLS endpoint, TLS transcript
engine, certificate validation path, session ticket handling, stream decryption,
or automatic decryption during QUIC packet decode.

## Dependency Review

`crafter/Cargo.toml` already has the direct primitives needed for the planned
offline helpers:

| Dependency | Current status | Allowed QUIC use |
| --- | --- | --- |
| `sha2` | Direct dependency | SHA-256 for RFC 9001 Initial HKDF extract/expand inputs. |
| `hmac` | Direct dependency | HKDF-Extract and HKDF-Expand implementation for Initial secrets and labels. |
| `aes` | Direct dependency | AES header-protection block primitive when a future helper needs direct block encryption. |
| `aes-gcm` | Direct dependency | AES-128-GCM vector helpers and Retry integrity tag verification. |
| `chacha20` | Direct dependency as of the header-protection utility step | Raw ChaCha20 mask generation for RFC 9001 / RFC 9369 header-protection vectors. |
| `chacha20poly1305` | Direct dependency | Reserved for future ChaCha20-Poly1305 packet-protection vector coverage; not needed for the Initial v1/v2 gates. |
| `cipher` | Direct dependency | Common traits for small packet-protection primitives. |
| `subtle` | Direct dependency | Constant-time tag or byte comparison where public helpers expose verification. |

There is no direct `hkdf` dependency in the manifest, and `cargo tree -p
crafter` did not show an `hkdf` crate. Do not add `hkdf` for the next step:
`hmac` and `sha2` are already direct dependencies and are sufficient for the
small RFC 9001 HKDF operations required by Initial secret derivation. Add a
dedicated `hkdf` dependency only in a later explicit review if the local helper
grows beyond the small RFC 5869 extract/expand shape or if test vectors expose a
maintenance risk.

## Allowed Helpers

The allowed `crafter` surface is intentionally narrow and inspectable:

- Derive QUIC v1 and v2 Initial client/server secrets from a destination
  connection ID and the source-backed Initial salts.
- Expand Initial traffic secrets into packet-protection key, IV, and header
  protection key material using RFC 9001 labels.
- Apply or remove header protection for bounded test/vector inputs without
  inventing endpoint state.
- Protect or unprotect explicit Initial packet test vectors when the caller
  supplies all required packet bytes and connection ID material.
- Verify Retry integrity tags using source-backed static key and nonce material.
- Return structured errors for unsupported cipher suites, wrong key sizes,
  short samples, short tags, or malformed protected packet inputs.

Helpers must be deterministic, offline-friendly, and byte-oriented. They should
return typed secret/key structs or explicit byte vectors that can be inspected
with summaries or test assertions. They must not send traffic, open sockets, or
look up live TLS state.

## Non-Goals

The following remain non-goals for the crate:

- TLS handshakes, TLS transcript processing, certificate validation, ALPN, PSK,
  0-RTT policy, session resumption, or key updates.
- Arbitrary 0-RTT, Handshake, or 1-RTT packet decryption from live sessions.
- Loss recovery, congestion control, stream reassembly, HTTP/3, QPACK, DoQ
  client/server behavior, or any generated scanner workflow.
- Automatic decryption from normal `Packet::decode_*` paths. Protected QUIC
  payloads stay raw unless a caller explicitly invokes a packet-protection
  helper with the required inputs.

## Validation Boundary

Packet-protection work starts offline with RFC 9001 and RFC 9369 test vectors,
golden byte fixtures, malformed input tests, and dry-run oracle/probe records.
Live behavioral validation is only allowed through explicit provider-backed lab
steps after the offline helpers pass and the plan calls for live execution.
