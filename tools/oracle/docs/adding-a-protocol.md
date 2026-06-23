# Adding an Oracle Protocol

The oracle handles every protocol through small, auto-discovered per-stage
plugin modules plus per-protocol spec files. Adding a protocol means **dropping
in new files** — you never edit a central dispatcher or a shared lookup table.

The pipeline is `specs -> generator (PacketPlan) -> Scapy/Wireshark backend
encode (bytes) -> backend decode (normalized model) -> compare`. A protocol
plugs into three Python stages plus the spec layer:

| Stage | File to create | Registers |
| --- | --- | --- |
| Generator (sampling + feature behavior) | `tools/oracle/engine/protocols/<name>.py` | `ProtocolSampler` |
| Scapy encode + decode | `tools/oracle/engine/backends/scapy/protocols/<name>.py` | `ScapyProtocol` (and/or `StackEncoder`) |
| Wireshark/tshark decode | `tools/oracle/engine/backends/wireshark/protocols/<name>.py` | `WiresharkProtocol` |
| Specs | `specs/layers/<name>.yaml`, `specs/features/<name>-*.yaml`, optional `specs/stacks.d/<name>.yaml` / `specs/profiles.d/<name>.yaml` | — |

Each module self-registers on import; the package `__init__.py` auto-discovers
it via `pkgutil.iter_modules`, so there is no manifest to update. The Wireshark
stage is optional — it only matters for layers that declare `wireshark` backend
support; only a handful of layers (`arp`, `dns`, `dhcp`, etc.) ship one.

ARP is the reference vertical slice. Read these three files alongside this
guide; they are intentionally minimal and self-contained:

- `tools/oracle/engine/protocols/arp.py`
- `tools/oracle/engine/backends/scapy/protocols/arp.py`
- `tools/oracle/engine/backends/wireshark/protocols/arp.py`

## The import-root rule (read this first)

The engine is imported under **two roots**: as `engine.*` (the CLI, `python -m
engine.cli`) and as `tools.oracle.engine.*` (the test suite, which treats
`tools/` as a PEP 420 namespace package). Every new module must therefore:

- **use relative imports only** — `from ..model import JSONObject`,
  `from ..sampling import _SamplingContext`, `from .base import register`. Never
  write `from tools.oracle.engine...` or `from engine...`.
- rely on `__name__`-relative auto-discovery (already implemented in
  `engine/plugin_registry.py:autodiscover`, called from each `protocols/__init__.py`).

Plugins must **not import the stage orchestrator** (`generator`, `packets`,
`normalize`) — that creates a circular import. Pull shared helpers from the
extracted primitive modules instead (see below). A plugin that needs a helper
which still lives in an orchestrator means the helper should be moved to a
primitives module first.

## Where shared helpers live

| Stage | Primitives module | Contract / registry module |
| --- | --- | --- |
| Generator | `engine/sampling.py` | `engine/protocols/base.py` |
| Scapy | `engine/backends/scapy/encode_helpers.py`, `engine/backends/scapy/decode_helpers.py` | `engine/backends/scapy/protocols/base.py` |
| Wireshark | `engine/backends/wireshark/decode_helpers.py` | `engine/backends/wireshark/protocols/base.py` |

`engine/sampling.py` holds the generator-stage primitives a sampler reaches for:
`_SamplingContext`, the `_SKIP_FIELD` sentinel, `weighted_choice`, `bounded_int`,
`_integer_domain_value`, `_mac_for_domain`, `_field_bits`, `_next_layer_after`,
and the documentation-address helpers (`documentation_ipv4`/`_ipv6`/`_mac`).
The Scapy/Wireshark helper modules hold the cross-protocol encode/decode bits
(`_layer_fields`, `_required_field`, `_optional_field`, `_int`, `_text`,
`_bytes_field`, `_fields_from_aliases`, `_parse_int_fields`, `_layer`, and so on).

## Stage 1 — generator: `engine/protocols/<name>.py`

Register one `ProtocolSampler` per layer you own. The dataclass
(`engine/protocols/base.py`):

```python
@dataclass(frozen=True)
class ProtocolSampler:
    layer: str
    supported_fields: frozenset[str]
    sample: Callable[..., object]
    apply_behavior: Callable[..., None] | None = None
    handles_feature: Callable[[str], bool] | None = None
    post_sample: Callable[..., None] | None = None
```

Callback signatures:

- **`sample(ctx, field_name, domain, *, field_spec, current_fields) -> object`**
  — uniform across every protocol; use only the arguments you need. Return the
  sampled value, or `_SKIP_FIELD` for a field `compile()` derives (lengths,
  checksums, ICVs). ARP's adapter only needs `ctx`, `field_name`, `domain`.
- **`apply_behavior(fields, *, stack, feature, case, behavior, grammar=None) -> None`**
  — mutates `fields` in place for a feature behavior, and may write cross-layer
  (RIP pins the enclosing UDP source/dest port to 520 — see
  `engine/protocols/rip.py`). **Always accept `grammar=None`**: the feature loop
  threads `self.grammar` into every plugin call; protocols that do not consult
  the grammar accept and ignore it.
- **`handles_feature(feature) -> bool`** — reports which feature names the plugin
  owns. RIP uses `feature.startswith("rip_")`; that prefix is disjoint from
  `ripng_`, so registry order never matters.
- **`post_sample(fields, *, stack, case) -> None`** — runs once per stack layer
  whose plugin defines it, **after** the whole sampling loop, for ordering
  dependencies. IPsec uses it to attach the pinned crypto block to esp/ah/ikev2
  (`engine/protocols/ipsec.py`); this is the determinism seam that keeps ESP/AH
  ciphertext byte-reproducible across backends.

`supported_fields` is the per-layer field allowlist. It is a **subset** of the
spec's field names: auto-filled / structural / behavior-driven fields are
excluded. Some layers are entirely behavior-driven and register
`supported_fields=frozenset()` (IGMP, BLE), letting `apply_behavior` build the
whole layer.

**Dispatch rule:** the generator consults `SAMPLER_REGISTRY` before doing
anything else. `_sample_field_value` looks up the layer and calls
`plugin.sample(...)`. `_apply_feature_behavior` iterates registered plugins and
calls the first whose `handles_feature(feature)` is true, whose `apply_behavior`
is set, and **whose layer is in `fields` or in `stack`** — so a feature fires
exactly once. There is no legacy fallback anymore; every spec layer must have a
registered sampler.

Worked example — `engine/protocols/arp.py` (abridged):

```python
from ..sampling import _SamplingContext, _integer_domain_value, _mac_for_domain
from .base import ProtocolSampler, register

_SUPPORTED_FIELDS = frozenset({
    "hardware_type", "protocol_type", "hardware_length", "protocol_length",
    "opcode", "sender_hardware_address", "sender_protocol_address",
    "target_hardware_address", "target_protocol_address",
})

def _sample_arp_field(ctx, field_name, domain):
    if field_name == "hardware_type":
        return "ethernet"
    if field_name == "opcode":
        return domain
    if field_name == "sender_hardware_address":
        return _mac_for_domain(ctx, domain, ctx.src_mac)
    ...  # one branch per field

def _sample(ctx, field_name, domain, *, field_spec, current_fields):
    return _sample_arp_field(ctx, field_name, domain)

register(ProtocolSampler(layer="arp", supported_fields=_SUPPORTED_FIELDS, sample=_sample))
```

## Stage 2 — Scapy: `engine/backends/scapy/protocols/<name>.py`

Encode and decode are co-located here. Register a `ScapyProtocol`
(`engine/backends/scapy/protocols/base.py`):

```python
@dataclass(frozen=True)
class ScapyProtocol:
    layer: str
    scapy_class: str | None               # native Scapy class name, or None for raw bytes
    supported_fields: frozenset[str]
    build: Callable[..., object]
    normalize: Callable[[JSONObject], JSONObject] | None = None
    layer_aliases: tuple[tuple[str, str], ...] = ()   # ScapyClassName -> oracle layer
    field_aliases: tuple[tuple[str, str], ...] = ()   # native field -> oracle field
```

- **`scapy_class`** must match the **native Scapy class name** the encoder
  materializes — it drives the `scapy_stack` metadata and `_is_materialized_layer`.
  ARP is `"ARP"`; some differ from the oracle layer name (BGP is `"BGPHeader"`,
  OSPF is `"OSPF_Hdr"`, IKEv2 is `"ISAKMP"`). Verify against the real Scapy class,
  not the protocol's display name.
- **`build(plan, fields, stack, index, scapy_all) -> object`** — returns a Scapy
  layer object (or a raw-bytes wrapper). Pull fields with `_layer_fields(fields,
  "<layer>")` and `_required_field` / `_optional_field`. Keep the unused
  `plan`/`stack`/`index`/`scapy_all` parameters in the signature even if you do
  not read them — the call is uniform.
- **`normalize(fields) -> JSONObject`** — optional decode-side hook consulted by
  the Scapy decoder. Leave it `None` to use the generic alias path (then
  `field_aliases` / `layer_aliases` carry the native-name mapping).
- **`supported_fields`** here is the **encode allowlist**: canonical field names
  **plus every Scapy/oracle alias** the builder accepts (e.g. ARP allows both
  `opcode` and `op`/`operation`).

`encode_packet_plan` consults `STACK_ENCODER_REGISTRY` first, then `SCAPY_REGISTRY`
per layer; the decoder consults `SCAPY_REGISTRY` for a layer's `normalize` before
its generic path. Register with `register(ScapyProtocol(...))`.

## Stage 3 — Wireshark: `engine/backends/wireshark/protocols/<name>.py`

Only needed for layers that declare `wireshark` backend support. Register a
`WiresharkProtocol` (`engine/backends/wireshark/protocols/base.py`):

```python
@dataclass(frozen=True)
class WiresharkProtocol:
    layer: str
    normalize: Callable[..., JSONObject]   # normalize(layers, *, source_hex=None)
    tshark_aliases: JSONObject             # canonical name -> native tshark field names
```

`normalize` receives the full tshark `layers` object; pull the layer's fields
with the decode helpers (`_layer`, `_fields_from_aliases`, `_parse_int_fields`)
and reduce them to the same canonical names and comparable forms the Scapy
backend and the libcrafter decoder produce. See
`engine/backends/wireshark/protocols/arp.py`. The Wireshark normalizer consults
`WIRESHARK_REGISTRY` before its legacy branches.

## Spec files

The generator and the comparison gate are data-driven from the specs (the
generator rejects invalid stack/feature/case combinations before any backend
runs). Add:

- **`specs/layers/<name>.yaml`** — `kind: layer`, the layer `name`, `parents`,
  the `fields` list (names, types, sampling `domains`/`profile_domains`,
  `codepoints`), `coverage_cases`, and `backend_support` (per-backend
  encode/decode/native-layer metadata). The plugin's generator-stage
  `supported_fields` is a subset of these field names. See `specs/layers/arp.yaml`.
- **`specs/features/<name>-*.yaml`** — `kind: feature`; one file per feature
  (e.g. `rip-header.yaml`, `rip-entries.yaml`, `rip-auth.yaml`). Each declares
  `layers`, `directions`, `byte_policy`/`strict_bytes`, `coverage_cases`, and the
  `behaviors` the generator matches against the case id and hands to your
  `apply_behavior`.
- **Optional fragments** so a new protocol needs *only* new files:
  `specs/stacks.d/<name>.yaml` contributes `roots`/`families`/`stacks`/
  `constraints` and `specs/profiles.d/<name>.yaml` contributes `profiles`,
  glob-merged into the same `OracleSpecs` as the monolithic `stacks.yaml` /
  `profiles.yaml`. A missing fragment directory is fine (back-compat); duplicate
  keys across files are rejected.

## Raw-bytes / whole-stack families: `StackEncoder`

Some families bypass the per-layer `build` and emit the **whole stack** as raw
wire bytes: BLE advertising and Dot11 phase-1.5. For these, register a
`StackEncoder` (same `engine/backends/scapy/protocols/base.py`):

```python
@dataclass(frozen=True)
class StackEncoder:
    name: str
    matches: Callable[[Sequence[str]], bool]   # stack -> owns it?
    encode: Callable[..., bytes]               # encode(plan, scapy_all) -> bytes
```

`encode_packet_plan` checks `STACK_ENCODER_REGISTRY` (in registration order,
first match wins) **before** the per-layer build, so a matching stack is
materialized whole. The per-layer `ScapyProtocol.build` for such layers raises
if called (they are never built per-layer), but you still register a
`ScapyProtocol` per layer so the encoder can resolve each layer's `scapy_class`
and field allowlist from the registry. Register the encoder with
`register_stack_encoder(StackEncoder(...))`. See
`engine/backends/scapy/protocols/ble.py` (`name="ble_advertising"`,
`matches=_is_ble_stack`) and `wifi.py` (`name="dot11_phase15"`).

If selection depends on the **plan** (not just the stack shape) — e.g. the
IPsec SA path — keep the selection check in `encode_packet_plan` and move only
the implementation into the plugin; the frozen `StackEncoder.matches(stack)`
predicate sees the stack alone.

## Sub-layers stay in the orchestrators

Some spec entities are **sub-layers**, not top-level `OracleSpecs.layers`: IPv6
extension headers (declared under `ipv6.yaml extension_layers`), and the
IGMP/DNS/DHCP whole-packet bits. The strict coverage test forbids registering a
plugin under a name that is not a top-level spec layer, so these are co-located
in the owning protocol's plugin modules but reached through the orchestrator's
remaining sub-layer dispatch and whole-packet canonicalize passes. If your
protocol has sub-layers, follow the IPv6 pattern: keep the builders/normalizers
in your plugin module, re-import them where the orchestrator dispatches them, and
register only the top-level layer.

## Test it

Add `tools/oracle/tests/test_<proto>_oracle.py`, modeled on
`tools/oracle/tests/test_rip_oracle.py`. The convention:

- backend-neutral checks (spec loading, seeded plan generation, plan shape)
  **always run** — no Scapy import at module level;
- Scapy assertions are guarded behind a `_require_scapy_backend()` helper that
  raises `unittest.SkipTest` when Scapy is unavailable (the bare interpreter the
  gate uses has no Scapy; the CLI bootstraps it through `uv`);
- assert byte-level / decoded-model agreement between the libcrafter-shaped plan
  and the Scapy reference for at least one `strict_bytes` case.

The strict coverage test (`test_protocol_plugin_coverage.py`) already asserts
that every spec layer has a registered sampler and that `supported_fields` is a
subset of the spec fields, so a half-wired protocol fails there automatically.

### Gate command

Run from the **repository root** (offline; no `uv`, `tshark`, Scapy, or network
required — Scapy-gated assertions skip cleanly):

```sh
python3 -m compileall tools/oracle/engine
python3 -m unittest discover -s tools/oracle/tests -p 'test_*.py'
```

When validating backend bytes, also run with Scapy available (a venv with Scapy
installed, or `tools/oracle/run offline --backend scapy`), since the bare-gate
run skips the Scapy assertions.
