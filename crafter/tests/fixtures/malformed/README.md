# Malformed decode corpora

Hand-built malformed-input fixtures that lock the crate's "truncated, oversized,
or invalid input surfaces a structured error and never panics" contract. Each
resilience test under `crafter/tests/` loads its corpus, decodes every entry
through the relevant public decode entrypoint, and asserts the decoder reports
a structured outcome rather than panicking.

Most files in this directory are single-frame `.hex` fixtures (one malformed
buffer, raw lowercase hex). The protocol resilience corpora below use a
pipe-delimited, one-case-per-line format.

## BLE — `ble-decode-corpus.hex`

Consumed by `crafter/tests/ble_resilience.rs`. Every entry targets
`LinkType::BluetoothLeLl`. Format:

```
name|expected-kind|expected-context-or-field|hex
```

## 802.15.4 / Zigbee — `dot15d4-decode-corpus.hex`

Consumed by `crafter/tests/dot15d4_resilience.rs`. Format:

```
name|link-type|expected-kind|expected-context-or-marker|hex
```

- `name` — unique, kebab-case case identifier.
- `link-type` — decode entrypoint selector:
  - `mac` — bare 802.15.4 MAC frame (with FCS), `LinkType::Ieee802154`.
  - `tap` — TAP radio-descriptor pseudo-header + MAC frame,
    `LinkType::Ieee802154Tap`.
- `expected-kind` and `expected-context-or-marker`:
  - `buffer-too-short` — decode returns `Err(CrafterError::BufferTooShort)`; the
    field is the expected non-empty `context` string (for example
    `dot15d4.mac.fcf`, `dot15d4.mac.addressing`, `dot15d4.tap.header`,
    `dot15d4.tap.tlv`).
  - `invalid-field-value` — decode returns `Err(CrafterError::InvalidFieldValue)`;
    the field is the expected non-empty `field` string (for example
    `dot15d4.mac.frame_type` for a reserved MAC frame type).
  - `decodes` — decode returns `Ok(Packet)` with the truncated inner payload
    preserved as a trailing `Raw` layer; the marker (`nwk-raw` / `aps-raw`) names
    which Zigbee layer was truncated. A truncated Zigbee NWK/APS payload never
    fails the `decode_from_link` entrypoint — an unrecognized NWK/APS payload is
    kept as `Raw` rather than rejecting the enclosing MAC frame.
- `hex` — the malformed buffer as raw lowercase hex (no `0x`, whitespace
  ignored).

Lines that are blank or start with `#` are comments and are skipped.

## Conventions

- Frames use lab-safe documentation values (documentation PAN/address space,
  all-zero filler) and carry no real-network or device identifiers.
- Each corpus's resilience test pins a required-case set so the malformation
  classes the corpus must exercise cannot be silently dropped.
