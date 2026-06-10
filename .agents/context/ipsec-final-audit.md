# IPSec Protocol Support Final Audit

Audit time: 2026-06-10T00:00:00Z

Scope: final readiness review for IPSec packet support in `crafter` — the ESP,
AH, and IKEv2 layers, their cryptographic transforms, the per-packet
`SecurityAssociation` context, NAT-T disambiguation, and the SA-aware decode
path. This document records tracked source scope, offline and pcap validation,
provider-backed dry-run outcomes, artifacts, and residual risks. IPSec is a
wire-level primitive, not a kernel security stack. This document intentionally
stores no packet captures, credentials, public addresses, or live host
identifiers; every illustrative address is documentation address space.

## Supported Scope

- **ESP (RFC 4303)** composes as a typed layer over IPv4 and IPv6 in transport
  and tunnel mode. Encryption covers AEAD suites (AES-GCM, AES-CCM,
  ChaCha20-Poly1305), CBC/CTR ciphers with separate HMAC / AES-XCBC / AES-GMAC
  integrity, NULL encryption, opaque pre-sealed bodies, and a keyless
  pass-through path. `compile()` fills pad, pad-length, next-header, IV, and ICV
  per RFC 4303 §2.4 while honoring caller overrides verbatim (including
  deliberately wrong values). AAD is `SPI||Seq` plus the high-order ESN word
  when ESN is enabled; the wire still emits only the low `Seq`.
- **AH (RFC 4302)** composes over IPv4 and IPv6 in transport and tunnel mode and
  authenticates rather than consuming the following layers. The ICV is computed
  over the canonicalized immutable IP fields (mutable fields zeroed per
  RFC 4302 §3.3.3.1), the AH header with the ICV field zeroed, and the
  upper-layer data, with the ESN high word appended when enabled. IPv6 option
  mutability uses the RFC-correct change-en-route bit (0x20). Integrity covers
  HMAC-SHA-1/SHA-2, AES-XCBC-MAC-96, and AES-GMAC. Decode with the matching SA
  re-verifies the ICV constant-time and reports a verified status.
- **IKEv2 (RFC 7296)** message wire format: the 28-byte header plus the full
  payload set — SA (Proposal/Transform/Attribute), KE, Nonce, Notify, Delete,
  IDi/IDr, AUTH, TSi/TSr, CERT, CERTREQ, Vendor ID, Configuration, EAP, and the
  Encrypted (SK) payload. The next-payload chain, auto-filled IKE message
  length, and all payload fields round-trip and re-compile byte-for-byte.
  Unknown payload types decode as a preserved Raw payload. An SK payload built
  with an SA decrypts and re-verifies.
- **NAT-T (RFC 3948)** disambiguates UDP/4500: a 4-byte non-ESP (zero) marker
  selects IKEv2; otherwise the datagram decodes as UDP-encapsulated ESP. UDP/500
  is IKEv2-only. A minimum-length guard keeps RFC 3948 keepalives and unrelated
  short 4500 traffic from being misclassified.
- **`SecurityAssociation`** is a per-packet crypto context carrying SPI, mode,
  encryption/integrity algorithms, keys, salt, and the ESN flag. Its `Debug` and
  `summary()` redact key and salt bytes. Algorithm enums preserve unknown IANA
  transform IDs.
- **SA-aware decode** is reachable from public code through
  `ProtocolRegistry::register_security_association` /
  `with_security_association` (SAs keyed by SPI). ESP/AH registry bindings read
  the on-wire SPI, dispatch the SA-aware decrypt/verify path when matched, and
  fall back to opaque preservation otherwise. ESP decode without an SA exposes
  SPI and sequence and preserves the encrypted body as opaque bytes that
  re-compile byte-for-byte.
- **Public exports**: ESP, AH, IKEv2 (header + every payload type and enum +
  codepoint constants), `SecurityAssociation`, `IpsecMode`,
  `EncryptionAlgorithm`, `IntegrityAlgorithm`, NAT-T, and the `ESP_*`/`AH_*`/IKE
  constants are exported through `crafter::prelude::*` and the crate root.
- **Validation coverage**: RFC known-answer tests for every cryptographic
  transform (AES-GCM/CCM, ChaCha20-Poly1305, AES-CBC/CTR, HMAC, AES-XCBC,
  AES-GMAC); pinned golden byte locks (ESP AES-GCM, ESP CBC+HMAC, AH
  HMAC-SHA-256, IKE_SA_INIT); integration tests across ESP/AH transport+tunnel
  on v4/v6, IKE_AUTH with SK, NAT-T, tamper detection, and no-key-leak;
  malformed-corpus and proptest resilience; oracle byte-and-decode parity with
  the Scapy reference backend (ESP, AH, and IKEv2 offline at 50/50 each in both
  directions, plus a pcap roundtrip); and a behavioral probe `ipsec` profile
  with cross-crypto interop (6/6 in both directions, libcrafter-sealed opened by
  the reference crypto and vice versa).

## Unsupported Cases

- No kernel-style Security Association Database (SAD) or Security Policy
  Database (SPD), no policy lookup. The crate carries a per-packet crypto
  context only (spec.md "Out of scope").
- No IKEv2 negotiation state machine, no Diffie-Hellman key agreement, no
  SK_d / keymat derivation, no EAP method logic, and no rekey or liveness
  timers. IKEv2 here is message wire format only (spec.md "Out of scope").
- No anti-replay window enforcement. Sequence numbers and ESN are built and
  parsed, but replay acceptance is not a crate concern (spec.md "Out of scope").
- No automatic key management or PKI. Keys are supplied by the caller and are
  test material in all examples and tests.
- IKEv2 fragmentation (RFC 7383) is not covered.
- Live raw traffic from the developer machine remains unsupported. Real packet
  exchange is restricted to explicit provider-backed lab/oracle/probe workflows.

## Validation Commands

- `cargo test --workspace`
- `env RUSTDOCFLAGS="-D warnings" cargo doc -p crafter --no-deps`
- `tools/oracle/run offline --backend scapy --family esp --profile esp --seed 1601 --count 50 --out target/oracle/ipsec-esp-offline`
- `tools/oracle/run offline --backend scapy --family ah --profile ah --seed 1602 --count 50 --out target/oracle/ipsec-ah-offline`
- `tools/oracle/run offline --backend scapy --family ikev2 --profile ikev2 --seed 1603 --count 50 --out target/oracle/ipsec-ikev2-offline`
- `tools/oracle/run pcap --backend scapy --profile ipsec-smoke --seed 1604 --count 40 --out target/oracle/ipsec-pcap`
- `tools/probe/run --dry-run --profile ipsec --out target/probe/ipsec-local-dry-run`
- `tools/probe/run --dry-run --provider qemu --profile ipsec --out target/probe/ipsec-qemu-dry-run`
- `.agents/scripts/check-crafter-release --static`

## Offline And Pcap Artifacts

- ESP offline oracle artifacts (both directions) are under
  `target/oracle/ipsec-esp-offline`; AH under `target/oracle/ipsec-ah-offline`;
  IKEv2 under `target/oracle/ipsec-ikev2-offline`. Each passed byte parity on
  the strict well-formed cases and decoded-model parity, with malformed cases
  excluded as `structured_error`. ESP/AH byte parity relies on the generator's
  pinned key/salt/IV material so both backends seal with identical inputs.
- The pcap roundtrip artifacts are under `target/oracle/ipsec-pcap`; the run
  passed all generated cases. ESP opaque records decode byte-exact through the
  classic pcap read/write path.
- Crate-tracked byte and pcap fixtures (ESP AEAD/CBC opaque, AH HMAC,
  IKE_SA_INIT, and a RawIp pcap of all four records) live in the fixture suite
  and use documentation address space only.

## Provider Live Outcomes

- IPSec validation is offline-and-dry-run by design: the oracle `ipsec-smoke`,
  `esp`, `ah`, and `ikev2` profiles carry live and pcap weights such that no
  live wire run is required for parity, and the probe `ipsec` profile is
  dry-run by default.
- probe local dry-run: passed. Artifacts under
  `target/probe/ipsec-local-dry-run`. All four behavioral cases
  (esp-transport-echo, esp-tunnel-echo, ah-transport-verify, ikev2-sa-init)
  planned with zero skips, cross-crypto interop 6/6, and
  `creates_infrastructure=false`.
- probe qemu dry-run: passed. Artifacts under `target/probe/ipsec-qemu-dry-run`.
  Same case and interop outcome with no infrastructure created; the qemu
  provider was exercised in planning mode only.
- Cross-crypto interop artifacts are under `target/probe/ipsec-interop`
  (libcrafter-sealed ESP/AH/SK opened by the Scapy / pyca reference crypto and
  the reverse, plus tamper rejection), feeding the dry-run report metadata.
- No live provider VM was created and no live IPSec packets were placed on any
  network during this readiness work.

## Residual Risks

- **IKEv2 SK full-message ICV simplification.** The SK (Encrypted) payload
  computes its ICV over the SK body (IV||ciphertext) with empty AAD, whereas
  RFC 7296 §3.14 requires the ICV to cover the whole message from the IKE
  header through the SK payload. This gap is not exercised by the oracle:
  the `ikev2` profile uses opaque Raw payloads, not real SK payloads, so byte
  parity with Scapy ISAKMP holds. Mitigation: the no-SA chain decode path and
  the cross-crypto SK interop case both pass; a full-message-AAD revision is a
  contained follow-up if real-SK oracle parity is later required.
- **AH behind an IPv6 extension header is not byte-exact on the build side.**
  `Ah::compile` reads only the immediately preceding layer to determine the IP
  version, so re-compiling an AH header that sits behind an IPv6 extension
  header is not byte-exact; the decode side works. Mitigation: the common
  AH-immediately-after-base-header case is exact and is what the oracle and
  fixtures exercise.
- **AH IPv4 option canonicalization is conservative.** The IPv4 ICV input
  zeroes the entire option region wholesale rather than consulting a
  per-option-type immutability table. This is a superset of the RFC-mandated
  mutable options, so it is self-consistent for libcrafter's own seal/verify
  but would diverge from a peer that preserves an immutable IPv4 option.
  Mitigation: the IPv6 path is per-option RFC-faithful; refining the IPv4 path
  to a per-option table is a localized change.
- **IKEv2 fragmentation (RFC 7383) is not covered.** Oversized IKE messages are
  emitted as a single datagram. Mitigation: out of the documented scope;
  generated tools that need fragmentation can compose it above the layer.
- **Algorithm-suite breadth vs. future RFC 8221 updates.** The implemented
  cipher and integrity suites track the current RFC 8221 requirements and the
  IKEv2 transform registry as captured in the RFC source manifest. A future
  RFC 8221-bis or new mandatory transform would require adding a transform
  variant. Mitigation: `EncryptionAlgorithm` / `IntegrityAlgorithm` preserve
  unknown IANA transform IDs as `Unknown(u16)`, so unrecognized codepoints
  round-trip on the wire rather than failing, and adding a concrete transform
  is an additive enum + KAT change.
- Provider-backed artifacts live under ignored `target/oracle/ipsec-*` and
  `target/probe/ipsec-*` paths. They should remain untracked unless a future
  maintainer sanitizes and promotes a fixture deliberately.
