"""Generator-stage sampler plugin for the RIP layer.

Moves the ``_sample_rip_field`` sampler, the ``_rip_command_for_case`` /
``_rip_version_for_case`` / ``_rip_v2_entry`` helpers, and the
``_apply_rip_behavior`` feature behavior verbatim out of :mod:`generator` and
registers them through the uniform :class:`~.base.ProtocolSampler` contract. The
sampling and behavior logic is moved unchanged (behavior must stay
byte-identical); only the dispatch moves from the generator's legacy if/elif into
this self-contained module, which self-registers on import.

RIP owns every feature whose name begins ``rip_`` (``rip_header``,
``rip_entries``, ``rip_auth``) and NOT ``ripng_`` (RIPng is a separate layer; its
behavior stays in :mod:`generator` until its own migration step). ``handles_feature``
claims the ``rip_`` prefix and ``apply_behavior`` reproduces the legacy
``feature.startswith("rip_") and "rip" in fields`` branch of
``_apply_feature_behavior``: the registry-first feature loop admits a plugin when
its layer is in ``fields`` *or* in ``stack``, so the ``"rip" not in fields`` early
return preserves the exact legacy guard.

``_apply_rip_behavior`` performs the cross-layer write that pins the enclosing UDP
source and destination ports to 520 (RIP, RFC 1058 §3.1); this write is preserved
exactly. The sampler only seeds the header scalars (``command``/``version``/
``reserved``); the per-case route entries and the AFI 0xFFFF authentication entry
are attached by ``_apply_rip_behavior`` during the behavior pass, exactly as before.

``apply_behavior`` accepts a ``grammar`` keyword (the established step-08/20 plugin
call path threads ``self.grammar`` into every registry ``apply_behavior`` call);
RIP does not consult the grammar, so it accepts and ignores it.
``_apply_rip_behavior`` keeps its original ``(fields, *, stack, case, behavior)``
signature and is re-imported into :mod:`generator` so the focused rip-smoke profile
path (which calls it directly with ``behavior=""``) keeps working unchanged.
``_rip_command_for_case`` is re-imported into :mod:`generator` too, because the
still-resident RIPng sampler and RIPng behavior share it.

Shared primitives (``_SamplingContext``) live in :mod:`..sampling`; they are imported
here rather than duplicated. Relative imports only so the package resolves under both
the ``engine.*`` (CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import _SamplingContext
from .base import ProtocolSampler, register


# RIP fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["rip"]`` entry.
_SUPPORTED_FIELDS = frozenset({"command", "version", "reserved"})


def _sample_rip_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    # The RIP header scalars (command/version/reserved) seed the layer so it
    # survives the empty-dict drop in _fields; the per-case entries/auth values
    # are attached by _apply_rip_behavior, mirroring how BGP body bytes attach.
    if field_name == "command":
        return _rip_command_for_case(ctx.case)
    if field_name == "version":
        return _rip_version_for_case(ctx.case)
    if field_name == "reserved":
        return 0
    raise ValueError(f"spec error: unsupported rip field sampler: {field_name}")


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: RIP only needs ``ctx``, ``field_name``, ``domain``."""

    return _sample_rip_field(ctx, field_name, domain)


def _rip_command_for_case(case: str) -> str:
    """RIP/RIPng command for a coverage case: request vs response (RFC 1058 §4)."""

    if "request" in case.replace("_", "-"):
        return "request"
    return "response"


def _rip_version_for_case(case: str) -> int:
    """RIP version for a coverage case: v1 only for the explicit v1 cases."""

    return 1 if "v1" in case.replace("_", "-") else 2


def _apply_rip_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    case: str,
    behavior: str,
) -> None:
    rip = fields["rip"]
    rip["command"] = _rip_command_for_case(case)
    rip["version"] = _rip_version_for_case(case)
    rip.setdefault("reserved", 0)
    rip.pop("auth", None)
    rip.pop("entries", None)

    if "udp" in fields:
        fields["udp"]["src_port"] = 520
        fields["udp"]["dst_port"] = 520
    if "payload" in fields:
        fields["payload"] = {"hex": "", "length": 0}

    normalized = case.replace("_", "-")

    if rip["command"] == "request":
        # Request-whole-table sentinel (RFC 2453 §3.4.1 / RFC 1058 §3.4.1):
        # one AFI 0 entry with metric 16 (infinity).
        rip["entries"] = [
            {
                "address_family": 0,
                "route_tag": 0,
                "address": "0.0.0.0",
                "subnet_mask": "0.0.0.0",
                "next_hop": "0.0.0.0",
                "metric": 16,
            }
        ]
        return

    if "auth" in normalized:
        # Simple-password authenticated response (RFC 2453 §4.1): the AFI 0xFFFF
        # leading entry carries a 16-octet cleartext password, followed by a
        # single v2 route entry.
        rip["auth"] = {"type": 2, "simple_password": "oraclesecret"}
        rip["entries"] = [_rip_v2_entry()]
        return

    if rip["version"] == 1:
        # RFC 1058 v1 route entry: AFI IP, address + metric only (route tag,
        # subnet mask, and next hop are reserved-zero on the wire).
        rip["entries"] = [
            {
                "address_family": 2,
                "route_tag": 0,
                "address": "192.0.2.0",
                "subnet_mask": "0.0.0.0",
                "next_hop": "0.0.0.0",
                "metric": 1,
            }
        ]
        return

    # RFC 2453 v2 response: a route entry carrying route tag, subnet mask, and
    # next hop. The matrix case adds a second entry so a multi-entry message is
    # exercised by the smoke run.
    entries = [_rip_v2_entry()]
    if "matrix" in normalized:
        entries.append(
            {
                "address_family": 2,
                "route_tag": 64512,
                "address": "198.51.100.0",
                "subnet_mask": "255.255.255.0",
                "next_hop": "192.0.2.1",
                "metric": 2,
            }
        )
    rip["entries"] = entries


def _rip_v2_entry() -> dict[str, object]:
    """A canonical RFC 2453 v2 route entry in documentation address space."""

    return {
        "address_family": 2,
        "route_tag": 0,
        "address": "192.0.2.0",
        "subnet_mask": "255.255.255.0",
        "next_hop": "0.0.0.0",
        "metric": 1,
    }


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    """Apply a RIP feature behavior to the sampled RIP fields.

    Byte-identical to the legacy ``feature.startswith("rip_") and "rip" in fields``
    branch of ``generator._apply_feature_behavior``. The registry-first feature loop
    admits a plugin when its layer is in ``fields`` *or* in ``stack``, so the ``"rip"
    not in fields`` early return preserves the exact legacy condition. ``grammar`` is
    accepted to match the uniform plugin call path but RIP does not consult it.
    """

    del feature, grammar  # RIP owns every ``rip_`` feature uniformly.
    if "rip" not in fields:
        return
    _apply_rip_behavior(fields, stack=stack, case=case, behavior=behavior)


def _handles_feature(feature: str) -> bool:
    # ``ripng_`` features belong to the still-resident RIPng path, not RIP.
    return feature.startswith("rip_")


register(
    ProtocolSampler(
        layer="rip",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
    )
)
