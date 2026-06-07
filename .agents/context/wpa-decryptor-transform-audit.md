# WPA Decryptor Transform Audit

This audit records the final Step 20 validation context for the
`feature/wpa-decryptor-transform` branch.

## Final API

The WPA decryptor is exposed through the existing packet wire transform
surface. It does not add a second sniffer or decryptor API.

- `WpaDecrypt` is a stateful inbound `PacketTransform` that observes Dot11
  packet records and emits packet-shaped decrypted records when supported key
  state is available.
- `WpaDecrypt::new()` creates the default transform.
- `WpaDecrypt::network(ssid, passphrase)` and
  `WpaDecrypt::network_bytes(ssid, passphrase)` add WPA/WPA2-Personal
  networks from passphrases.
- `WpaDecrypt::with_network(WpaNetwork)` accepts pre-built network
  configuration, including `WpaNetwork::pmk` and `WpaNetwork::pmk_bytes` for
  pre-derived PMK material.
- `WpaDecrypt::with_config(WpaDecryptConfig)` applies transform policy.
  Defaults suppress handshake-only and undecryptable protected originals while
  still passing unrelated records; `pass_originals(true)` keeps diagnostic
  originals annotated with WPA metadata.
- `WpaDecrypt::decrypt_record` runs the transform over one `PacketRecord` and
  collects emitted records into a `TransformOutput` buffer.
- `WpaMetadata` is nested under Wi-Fi metadata and reports BSSID, station,
  cipher, AKM, key kind, key id, packet number, handshake status, credential
  status, and decrypt reason.
- `WpaDecryptReason` records decrypt outcomes such as `Decrypted`,
  `WaitingForHandshake`, `UnsupportedCipher`, `UnsupportedAkm`,
  `MissingKeyMaterial`, `MicFailed`, `AuthenticationFailed`,
  `ReplayDetected`, and `MalformedFrame`.
- `derive_pmk`, `derive_ptk`, `Pmk`, and `PairwiseTransientKey` are exported
  for callers that need explicit WPA key material handling.

The expected transform chain for offline pcap input is:

```rust
Sniffer::new(source)
    .with(Dot11Metadata::new())
    .with(WpaDecrypt::new().network("libcrafter-wpa", "libcrafter-pass")?)
```

## Supported Scope

The implemented decrypt path is passive WPA2-Personal using PSK credentials and
CCMP-128 protected data. It can process synthetic offline monitor-mode Dot11
pcaps through `PacketWire`, learn RSN and EAPOL-Key state, verify configured
credential material, decrypt supported unicast CCMP frames, and decrypt group
CCMP frames when GTK material is learned from supported encrypted key data.

Decrypted RFC 1042 LLC/SNAP plaintext with known EtherTypes is emitted as an
Ethernet-equivalent packet record so later packet tooling can inspect the same
`Packet` shape used by other crate surfaces. Non-SNAP or unknown plaintext
stays packet-shaped through `Raw`.

## Validation Commands

Step 20 final validation uses these acceptance commands:

- `cargo test --workspace`
- `cargo doc --workspace --no-deps`
- `tools/oracle/run offline --family dot11 --profile smoke --seed 1101 --count 20`
- `tools/oracle/run pcap --family dot11 --profile smoke --seed 1102 --count 20`
- `tools/endpoint/run create --provider hetzner --exposure wan --role wpa-decryptor-dry-run --dry-run`
- `tools/endpoint/run create --provider qemu --exposure wan --role wpa-decryptor-dry-run --dry-run`
- `tools/endpoint/run create --provider virtualbox --exposure lan --role wpa-decryptor-dry-run --dry-run`
- `.agents/scripts/check-crafter-release --static`
- `test -f .agents/context/wpa-decryptor-transform-audit.md`

## Skipped Live Checks

No live provider creation, live Wi-Fi capture, live packet injection, or
provider-backed raw traffic was run in this final step. The provider acceptance
coverage is intentionally limited to endpoint `create --dry-run` commands for
Hetzner, QEMU, and VirtualBox.

Live WPA validation remains a protected manual action for an authorized lab.
It must not originate from the developer machine and must not store real SSIDs,
passphrases, PMKs, BSSIDs, station addresses, provider identifiers, public IPs,
or captured traffic in tracked files.

## Known Limitations

- WPA3/SAE is recognized as metadata but is not decrypted.
- WPA-Enterprise / 802.1X authentication is not decrypted.
- TKIP, GCMP, CCMP-256, WEP, management frame protection, and password
  cracking are outside the implemented decrypt path.
- The transform is passive; it is not an AP, supplicant, channel manager,
  deauthentication tool, scanner, or live handshake harvester.
- Direct Dot11 decode preserves protected frame bodies as `Raw`; decryption
  requires the explicit `WpaDecrypt` transform.
- Incomplete handshakes, unsupported ciphers or AKMs, MIC failures,
  authentication failures, replayed packet numbers, malformed CCMP headers,
  and missing key material remain inspectable through metadata and do not emit
  guessed plaintext.
