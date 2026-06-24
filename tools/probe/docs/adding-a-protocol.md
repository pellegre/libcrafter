# Adding a probe protocol

The probe engine under `tools/probe` is plug-and-play per protocol. Each
protocol's full surface — cases, plan builders, profile membership,
target-service setup, stimulus routing, live-path address rewrite, failure
reasons, and lab-capability derivation — lives in **one** auto-discovered module
under `tools/probe/engine/protocols/`. Adding a protocol means writing that one
file (plus its Rust adapter, and any per-service shell assets); you do **not**
edit any central dispatcher or shared lookup table.

The worked example throughout this guide is the ARP plugin,
`tools/probe/engine/protocols/arp.py` (the full-surface example). For a
minimal-surface example — a protocol that sets almost every hook to `None` — see
`tools/probe/engine/protocols/ospf.py`.

## The one file to create

Create `tools/probe/engine/protocols/<name>.py`. At import time it builds and
registers a single `ProtocolPlugin`:

```python
from .base import ProtocolPlugin, register

register(
    ProtocolPlugin(
        name="arp",
        cases=(ARP_RESOLUTION_CASE, *BEHAVIOR_ARP_CASES),
        plan_builders=_ARP_PLAN_BUILDERS,
        planned_only_cases=frozenset(),
        profile_counts={},
        stimulus_endpoint_cases=_ARP_STIMULUS_ENDPOINT_CASES,
        target_service=arp_target_service_contribution,
        setup_script=None,
        rewrite_endpoint_addresses=arp_rewrite_endpoint_addresses,
        failure_reasons=arp_failure_reasons,
        lab_capabilities=arp_lab_capabilities,
        live_plan_candidates=arp_live_plan_candidates,
    )
)
```

The module is discovered automatically — there is no central list to append to.
`tools/probe/engine/protocols/__init__.py` calls
`autodiscover(__name__, __path__)`, which imports every non-dunder, non-`base`
submodule of the package so each module's top-level `register(...)` call runs.
The contract and registry live in `tools/probe/engine/protocols/base.py`:
`PROTOCOL_REGISTRY = PluginRegistry("probe-protocol")`, the `register(plugin)`
helper, and the fold accessors (`all_cases`, `all_plan_builders`,
`all_planned_only_cases`, `all_profile_counts`, `all_stimulus_endpoint_cases`,
`ipsec_interop_plugin`, `registered_plugins`).

## The `ProtocolPlugin` fields and hooks

`ProtocolPlugin` is a frozen dataclass (`base.py`). `name` is the registry key
(the protocol label, e.g. `"arp"`). The other fields are the per-concern
contributions the central dispatchers fold over. **Every optional hook defaults
to `None` (or an empty collection); only set what your protocol actually
needs.** Many protocols set most hooks to `None` — OSPF, for instance, sets only
`cases`, `stimulus_endpoint_cases`, and `lab_capabilities` and leaves the rest
empty/`None`. ARP exercises the full surface.

| Field | Type | What it does |
| --- | --- | --- |
| `name` | `str` | Registry key. The protocol label. |
| `cases` | `tuple[ProbeCase, ...]` | The protocol's `ProbeCase` catalog. Folded into `cases.PROBE_CASES` / `PROBE_CASE_BY_NAME`. |
| `plan_builders` | `Mapping[str, PlanBuilder]` | `case_name -> builder` map. Folded into `planning.PLAN_BUILDERS`. A `PlanBuilder` takes `case_name`, `profile`, `seed`, `sequence` keyword args and returns the case's plan dict. |
| `planned_only_cases` | `frozenset[str]` | Case names whose builder records the exchange shape without building packet bytes (`"planned_only": True`). Folded into `planning.PLANNED_ONLY_REGISTERED_CASES`. **Only list a case here if it has a planned-only *builder*** — a case with no registered builder falls through to `planning._planned_only_probe_plan` and must **not** be listed (see OSPF). |
| `profile_counts` | `Mapping[str, Mapping[str, int]]` | Per-profile `case_name -> count` contribution. **Usually leave empty** (see "Profile ordering" below). |
| `stimulus_endpoint_cases` | `frozenset[str]` | Case names routed to the Rust `stimulus_endpoint` adapter on the live path. Union'd into `cli._STIMULUS_ENDPOINT_CASES`. |
| `target_service` | `Callable \| None` | Hook `(probe_plans, *, dry_run) -> JSONObject`. Returns this protocol's contribution to `target_services.target_service_setup_plan` (services, closed-port lists, kernel-state contracts). **Setting a non-`None` hook also diverts this protocol's cases off the legacy target path** (`target_services._registry_owned_case_names`), so a planning-migrated protocol whose service concern does not exist yet must leave this `None`. |
| `setup_script` | `Callable \| None` | Hook returning a line `Sequence` appended to `target_service_setup_script` before its terminal echo. **In practice every migrated protocol leaves this `None`**: the hook receives no plan context, so per-protocol setup-script blocks that need the planned plans are co-located in the plugin and called *directly* by `target_service_setup_script` (e.g. ARP's `arp_target_setup_lines`). |
| `rewrite_endpoint_addresses` | `Callable \| None` | Hook `(plan, *, source_ipv4, target_ipv4, source_mac, target_mac, target_interface, rewrite_source) -> JSONObject`. Rewrites one plan onto the live lab-segment addresses. Return `None` is **not** how you opt out per-case — return the rewritten plan; if your protocol rode the *shared* IPv4 rewrite tail, leave the whole hook `None` (the central dispatcher applies the shared tail). |
| `failure_reasons` | `Callable[[str], list[str] \| None]` | Given a case name, return its ordered failure-reason taxonomy, or `None` to fall through to the shared default (the central dispatcher's `endpoint_addressing.default_failure_reasons`). |
| `lab_capabilities` | `Callable \| None` | Hook `(substrate) -> Mapping[str, object]`. Returns this protocol's derived probe-capability booleans (e.g. `{"arp_resolution": ..., "link_layer_arp": ...}`). Folded into `lab.probe_capabilities_from_lab_capabilities`. |
| `live_plan_candidates` | `Callable \| None` | Hook `(probe_plans) -> list[JSONObject]`. Transforms the full batched live plan sequence (cross-plan context). Only ARP uses it today (annotating alternate sender-protocol candidates). |
| `ipsec_interop` | `Callable \| None` | The IPSec-only cross-crypto interop dry-run hook. Set only by `protocols/ipsec.py`; routed by `cli._dry_run_report` through `base.ipsec_interop_plugin()`. |

### Profile ordering — keep `profile_counts` empty by default

Probe pins a byte-identical snapshot of every emitted plan, **including the
order** cases appear in each profile. The registry-first profile merge would
move a plugin's `profile_counts` contribution to the *front* of a profile and
change that order. So a protocol's profile membership stays in the legacy
*ordered* profile name tables in `tools/probe/engine/cases.py`
(`BEHAVIOR_PROFILE_CASE_NAMES`, `OSPF_SMOKE_PROFILE_CASE_NAMES`,
`IPSEC_PROFILE_CASE_NAMES`, etc.) — those tables now *source* the case names from
the registered plugin cases, but they own the *order*. Leave `profile_counts`
empty unless the profile merge is order-fixed. Both ARP and IPSec document this
in their plugin docstrings.

## Where the shared primitives live

Plugins import shared, protocol-agnostic primitives from these modules (the
import layering runs one way: primitives ← plugins ← orchestrators, never back,
so there is no import cycle):

| Module | Provides |
| --- | --- |
| `tools/probe/engine/planning_helpers.py` | The `PlanBuilder` type alias and the deterministic planning scaffolding: `deterministic_bytes`, `deterministic_ipv4_pair`, `deterministic_router_ipv4`, `deterministic_documentation_mac`, `deterministic_documentation_ipv6`, `dns_label`. |
| `tools/probe/engine/case_helpers.py` | The `_behavior_case(...)` factory that builds a behavioral `ProbeCase`, and `case_name_filters(...)`. |
| `tools/probe/engine/target_service_helpers.py` | The typed descriptors `TargetServiceDescriptor` / `KernelStateDescriptor` and the port/address/plan scaffolding: `plans_by_destination_port`, `target_service_address_fields`, `probe_plan_send_count`, `dedupe_ints`, `string_or`, `json_mapping`. |
| `tools/probe/engine/endpoint_addressing.py` | Live-path rewrite scaffolding: the `FAILURE_*` reason constants, `default_failure_reasons()`, the deterministic lab-address helpers `_lab_arp_alias_ipv4` / `_eui64_link_local_ipv6`, and `apply_shared_ipv4_rewrite_tail(...)` (the shared IPv4 validation/rewrite tail). |
| `tools/probe/engine/capability_derivation.py` | Substrate-flag readers: `capability`, `optional_positive_int`, `capability_default_true`. |

Per-protocol data (case tuples, capability constants, builder dispatch entries,
target-service descriptors and case frozensets, stimulus routing, failure-reason
sets) is declared **once** in your plugin module — not duplicated across the
shared files.

## The import-root rule

The engine is imported under **two** roots: as `engine.*` by the CLI
(`tools/probe/run` runs `python -m engine.cli` with `PYTHONPATH=tools/probe`)
and as `tools.probe.engine.*` by the test suite. Your plugin module must work
under both:

- Use **relative imports only** (e.g. `from ..planning_helpers import ...`,
  `from .base import ProtocolPlugin, register`). Never assume either absolute
  root.
- Auto-discovery is `__name__`-relative (`autodiscover(__name__, __path__)` in
  `protocols/__init__.py`), so it resolves correctly under both roots.

The one exception is `protocols/ipsec.py`, which imports
`from tools.oracle.engine import ipsec_interop` for its cross-crypto interop
hook; that absolute import is deliberately isolated to the single plugin that
owns the only `tools.oracle` dependency in the probe engine.

## Builder object-identity (re-import into `planning`)

The per-protocol behavior tests pin builder **object identity**, e.g.
`test_arp_behavior.py`:

```python
self.assertIs(
    planning.PLAN_BUILDERS["arp-basic-who-has"],
    planning._arp_basic_who_has_probe_plan,
)
```

So after moving a `_<case>_probe_plan` builder (and any companion `_<case>_send`
multi-send helper, and protocol-only deterministic helpers) into your plugin,
**re-import them back into `planning.py`** so `planning._<builder>` resolves to
the *same* function object the plugin registered:

```python
# in tools/probe/engine/planning.py
from .protocols.arp import (  # noqa: F401  (re-exported for identity/back-compat)
    _arp_basic_who_has_probe_plan,
    ...
)
```

`planning.PLAN_BUILDERS` is assembled from `all_plan_builders()` (the registry
fold), so `PLAN_BUILDERS[name] is planning._<builder>` holds. If a `ProbeCase`
must look its case up at build time, import `PROBE_CASE_BY_NAME` *lazily* inside
the builder (`from ..cases import PROBE_CASE_BY_NAME`) to avoid the
`cases → protocols → <plugin>` import cycle (see `protocols/ipsec.py` and
`protocols/igmp.py`).

## The cross-language JSON plan contract and the Rust adapter

A plan dict is the **cross-language wire contract** consumed by the Rust adapter
under `tools/probe/adapters/`. There is one adapter module per protocol —
`tools/probe/adapters/src/{arp,dns,dhcp,udp,ndp,icmp,tcp,igmp,ospf,rip}.rs` — and
`tools/probe/adapters/src/common.rs` dispatches `(mode, case_name)` to it; the
`stimulus_endpoint` binary is `tools/probe/adapters/src/bin/stimulus_endpoint.rs`.

Field-layout rules:

- The plan's field names and shapes must stay **byte-identical**; the Rust
  `serde` decode breaks if a field is renamed or its shape changes.
- A new planner may only **add optional fields**. Adding a field that the Rust
  adapter ignores is safe; renaming, removing, or retyping an existing field is
  a breaking change to the contract.
- Wire a `stimulus_endpoint_case` only when its Rust adapter arm exists. A
  planned-only case (e.g. `ospf-dd-exchange`, `bgp-session-smoke`) plans in
  dry-run but has **no** adapter arm, so it is intentionally absent from
  `stimulus_endpoint_cases`.

A new protocol therefore needs a matching `tools/probe/adapters/src/<name>.rs`
module (and a `common.rs` dispatch arm) for any live-capable case, plus
optionally per-service shell assets under
`tools/probe/target_services/<name>/` (only `bgp`, `rip`, and `igmp` have them
today). Those Rust/shell assets are out of scope for the plugin file itself but
are part of the contributor recipe.

## Tests, the builder-identity pins, and the gate

Add a `tools/probe/tests/test_<proto>_behavior.py` (the convention used by
`test_arp_behavior.py`, `test_dns_behavior.py`, `test_dhcp_behavior.py`,
`test_udp_behavior.py`, `test_ndp_behavior.py`). Such a test:

- asserts the deterministic plan shape each case produces (build plans through a
  constructed `ProbeRunRequest` and `planning.probe_plan_for_case` /
  `planning.probe_plans_for_cases`, the way the existing tests do); and
- **pins the builder identity**: `assertIn(name, planning.PLAN_BUILDERS)` and
  `assertIs(planning.PLAN_BUILDERS[name], planning._<builder>)`.

New **guard** tests must use **probe-prefixed** module names
(`test_probe_*.py`): `tools/probe/tests/` and `tools/oracle/tests/` share a
namespace (each `__init__.py` extends `__path__` to include the other), so a bare
name can collide.

The offline gate, run from the repository root, is:

```sh
python3 -m compileall tools/probe/engine
python3 -m unittest discover -s tools/probe/tests -p 'test_*.py'
```

This is what CI runs (`.github/workflows/local-static.yml`). It is fully offline
and deterministic — no Scapy, `uv`, `cargo`, or network; live/end-to-end arms
self-skip when `uv`/`cargo` are absent. (The repo-wide release gate
`.agents/scripts/check-crafter-release --static` runs the crate's static checks;
the probe test gate above is the relevant one for a probe-only change.)

## The snapshot guards that lock byte-identical behavior

Three guard tests lock the observable behavior so a change to a plugin cannot
silently alter a plan, a rewrite, or the registry coverage:

- `tools/probe/tests/test_probe_plan_snapshot.py` pins a deterministic SHA-256
  digest of every emitted plan JSON across every engine-exposed profile (read off
  `cases.known_profiles()`, never hardcoded) at fixed seeds, plus every
  individual case at a fixed seed. A guard asserts the digest keys still exactly
  match the case/profile set, so **adding a case fails loudly here** — you
  recompute and pin its digest deliberately (the file never self-updates).
- `tools/probe/tests/test_probe_rewrite_snapshot.py` pins a digest of the
  live-path rewrite (`cli._probe_plan_with_endpoint_addresses`) output for every
  case in `cli._STIMULUS_ENDPOINT_CASES`, against a fixed documentation-range
  endpoint context.
- `tools/probe/tests/test_probe_target_service_scripts.py` exercises the
  deterministic `target_service_setup_plan` / `target_service_setup_script`
  output and the typed descriptors.

## How the strict coverage test enforces registration

`tools/probe/tests/test_probe_protocol_coverage.py` reads the live
`PROTOCOL_REGISTRY` (importing the `protocols` package runs auto-discovery) and
locks the plug-and-play end state:

- **Full coverage** — the registry is exactly the known protocol set
  (`arp, dns, dhcp, udp, ndp, icmp, tcp, bgp, rip, ospf, igmp, ipsec`), nothing
  more or less. **A new protocol must be added to `ALL_PROTOCOLS` in this test**,
  or the equality assertion fails.
- **Exactly-one ownership** — every case in `PROBE_CASE_BY_NAME` is owned by
  exactly one plugin (by case name via `plugin.cases`); no plugin owns a phantom
  case, and no case is an orphan. So your plugin must register every one of its
  cases.
- **No legacy dispatcher remains** — `cases` exposes no per-protocol
  `BEHAVIOR_<P>_CASES` tuple, `cli` exposes no per-protocol rewrite/failure
  branch helper, and the central rewrite/failure/lab dispatchers consult the
  registry (verified by source introspection). Keep your per-protocol case tuple
  and branch helpers **inside your plugin module**, not in the shared files.

When this test and the snapshots stay green, your plugin is wired correctly and
changes nothing it should not.
