"""Generator-stage sampler plugin for the RIPng layer.

Moves the ``_sample_ripng_field`` sampler and the ``_apply_ripng_behavior``
feature behavior verbatim out of :mod:`generator` and registers them through the
uniform :class:`~.base.ProtocolSampler` contract. The sampling and behavior logic
is moved unchanged (behavior must stay byte-identical); only the dispatch moves
from the generator's legacy if/elif into this self-contained module, which
self-registers on import.

RIPng owns every feature whose name begins ``ripng_`` (currently ``ripng_rtes``)
and NOT the bare ``rip_`` ones (RIP is a separate layer, migrated in
``protocols/rip.py``). The legacy ``_apply_feature_behavior`` checked the
``ripng_`` prefix *before* the ``rip_`` prefix; that ordering is preserved here
because the two prefixes are disjoint — ``"ripng_rtes".startswith("rip_")`` is
``False`` (the fourth character is ``n``, not ``_``) and
``"rip_header".startswith("ripng_")`` is ``False`` — so a feature is owned by
exactly one of the two plugins regardless of registry iteration order.
``handles_feature`` claims the ``ripng_`` prefix and ``apply_behavior`` reproduces
the legacy ``feature.startswith("ripng_") and "ripng" in fields`` branch: the
registry-first feature loop admits a plugin when its layer is in ``fields`` *or* in
``stack``, so the ``"ripng" not in fields`` early return preserves the exact legacy
guard.

``_apply_ripng_behavior`` performs the cross-layer write that pins the enclosing
UDP source and destination ports to 521 (RIPng, RFC 2080 §2); this write is
preserved exactly. The sampler only seeds the header scalars (``command``/
``version``/``reserved``); the per-case route table entries (the RIPng RTEs) are
attached by ``_apply_ripng_behavior`` during the behavior pass, exactly as before.

``apply_behavior`` accepts a ``grammar`` keyword (the established step-08/20 plugin
call path threads ``self.grammar`` into every registry ``apply_behavior`` call);
RIPng does not consult the grammar, so it accepts and ignores it.
``_apply_ripng_behavior`` keeps its original ``(fields, *, stack, case, behavior)``
signature and is re-imported into :mod:`generator` so the focused rip-smoke profile
path (which calls it directly with ``behavior=""``) keeps working unchanged.

``_rip_command_for_case`` (the shared request/response case selector) comes from
the co-located :mod:`.rip` plugin; it is imported here rather than duplicated.
Shared primitives (``_SamplingContext``) live in :mod:`..sampling`; they are imported
here rather than duplicated. Relative imports only so the package resolves under both
the ``engine.*`` (CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import _SamplingContext
from .base import ProtocolSampler, register
from .rip import _rip_command_for_case


# RIPng fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["ripng"]`` entry.
_SUPPORTED_FIELDS = frozenset({"command", "version", "reserved"})


def _sample_ripng_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "command":
        return _rip_command_for_case(ctx.case)
    if field_name == "version":
        return 1
    if field_name == "reserved":
        return 0
    raise ValueError(f"spec error: unsupported ripng field sampler: {field_name}")


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: RIPng only needs ``ctx``, ``field_name``, ``domain``."""

    return _sample_ripng_field(ctx, field_name, domain)


def _apply_ripng_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    case: str,
    behavior: str,
) -> None:
    ripng = fields["ripng"]
    ripng["command"] = _rip_command_for_case(case)
    ripng["version"] = 1
    ripng.setdefault("reserved", 0)
    ripng.pop("rtes", None)
    ripng.pop("entries", None)

    if "udp" in fields:
        fields["udp"]["src_port"] = 521
        fields["udp"]["dst_port"] = 521
    if "payload" in fields:
        fields["payload"] = {"hex": "", "length": 0}

    normalized = case.replace("_", "-")

    if ripng["command"] == "request":
        # Request-whole-table sentinel (RFC 2080 §2.4.1): one RTE with prefix ::,
        # prefix length 0, metric 16 (infinity).
        ripng["rtes"] = [
            {
                "prefix": "::",
                "route_tag": 0,
                "prefix_len": 0,
                "metric": 16,
            }
        ]
        return

    route_rte = {
        "prefix": "2001:db8::",
        "route_tag": 0,
        "prefix_len": 64,
        "metric": 1,
    }

    if "next-hop" in normalized:
        # Next-hop RTE (RFC 2080 §2.1.1): metric 0xFF, route tag and prefix
        # length zero, immediately followed by the route RTEs it applies to.
        ripng["rtes"] = [
            {
                "prefix": "fe80::1",
                "route_tag": 0,
                "prefix_len": 0,
                "metric": 255,
                "next_hop": True,
            },
            route_rte,
        ]
        return

    rtes = [route_rte]
    if "matrix" in normalized:
        rtes.append(
            {
                "prefix": "2001:db8:1::",
                "route_tag": 64512,
                "prefix_len": 48,
                "metric": 2,
            }
        )
    ripng["rtes"] = rtes


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    """Apply a RIPng feature behavior to the sampled RIPng fields.

    Byte-identical to the legacy ``feature.startswith("ripng_") and "ripng" in
    fields`` branch of ``generator._apply_feature_behavior``. The registry-first
    feature loop admits a plugin when its layer is in ``fields`` *or* in ``stack``,
    so the ``"ripng" not in fields`` early return preserves the exact legacy
    condition. ``grammar`` is accepted to match the uniform plugin call path but
    RIPng does not consult it.
    """

    del feature, grammar  # RIPng owns every ``ripng_`` feature uniformly.
    if "ripng" not in fields:
        return
    _apply_ripng_behavior(fields, stack=stack, case=case, behavior=behavior)


def _handles_feature(feature: str) -> bool:
    # Only ``ripng_`` features belong here; the bare ``rip_`` features belong to
    # the RIP plugin. The prefixes are disjoint, so this never claims a ``rip_``
    # feature even though the legacy dispatch checked ``ripng_`` first.
    return feature.startswith("ripng_")


register(
    ProtocolSampler(
        layer="ripng",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
    )
)
