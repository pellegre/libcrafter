"""Generator-stage sampler plugin for the BGP layer.

Moves the ``_sample_bgp_field`` sampler, the ``_bgp_*_for_case`` body-hex helpers,
and the ``_apply_bgp_behavior`` feature behavior verbatim out of :mod:`generator`
and registers them through the uniform :class:`~.base.ProtocolSampler` contract.
The sampling and behavior logic is moved unchanged (behavior must stay
byte-identical); only the dispatch moves from the generator's legacy if/elif into
this self-contained module, which self-registers on import.

BGP owns every feature whose name begins ``bgp_`` (``bgp_open``, ``bgp_update``,
``bgp_notification``, ``bgp_keepalive``, ``bgp_route_refresh``,
``bgp_communities``, ``bgp_mp_reach``). ``handles_feature`` claims that prefix and
``apply_behavior`` reproduces the legacy ``feature.startswith("bgp_") and "bgp" in
fields`` branch of ``_apply_feature_behavior``: the registry-first feature loop
admits a plugin when its layer is in ``fields`` *or* in ``stack``, so the ``"bgp"
not in fields`` early return preserves the exact legacy guard. The sampler only
seeds the header scalars (``marker``/``length``/``type``); the message body bytes
are attached by ``_apply_bgp_behavior`` during the behavior pass, exactly as
before.

``apply_behavior`` accepts a ``grammar`` keyword (the established step-08/20 plugin
call path threads ``self.grammar`` into every registry ``apply_behavior`` call);
BGP does not consult the grammar, so it accepts and ignores it. ``_apply_bgp_
behavior`` keeps its original ``(fields, *, stack, case, behavior)`` signature and
is re-imported into :mod:`generator` so the focused bgp-smoke profile path (which
calls it directly with ``behavior=""``) keeps working unchanged.

Shared primitives (``_SamplingContext``, ``_SKIP_FIELD``) live in :mod:`..sampling`;
they are imported here rather than duplicated. Relative imports only so the package
resolves under both the ``engine.*`` (CLI) and ``tools.oracle.engine.*`` (tests)
import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import _SKIP_FIELD, _SamplingContext
from .base import ProtocolSampler, register


# BGP fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["bgp"]`` entry.
_SUPPORTED_FIELDS = frozenset({"marker", "length", "type"})


def _sample_bgp_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "marker":
        return {"hex": "ff" * 16}
    if field_name == "length":
        return _SKIP_FIELD
    if field_name == "type":
        return _bgp_message_type_for_case(ctx.case)
    raise ValueError(f"spec error: unsupported bgp field sampler: {field_name}")


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: BGP only needs ``ctx``, ``field_name``, ``domain``."""

    return _sample_bgp_field(ctx, field_name, domain)


def _bgp_message_type_for_case(case: str) -> str:
    normalized = case.replace("_", "-")
    if "keepalive" in normalized:
        return "keepalive"
    if "notification" in normalized:
        return "notification"
    if "route-refresh" in normalized:
        return "route_refresh"
    if "open" in normalized:
        return "open"
    return "update"


def _bgp_open_body_hex(case: str) -> str:
    base = "04fc00005ac0000201"
    if "capabilities" not in case.replace("_", "-"):
        return base + "00"
    capabilities = (
        "010400010001"  # Multiprotocol IPv4 unicast.
        "010400020001"  # Multiprotocol IPv6 unicast.
        "41040000fc00"  # Four-octet AS 64512.
        "0200"          # Route refresh.
    )
    optional_parameters = "02" + f"{len(bytes.fromhex(capabilities)):02x}" + capabilities
    return base + f"{len(bytes.fromhex(optional_parameters)):02x}" + optional_parameters


def _bgp_update_body_hex(*, stack: Sequence[str], case: str, behavior: str) -> str:
    normalized = f"{case} {behavior}".replace("_", "-")
    if "withdraw" in normalized:
        return "000418c000020000"
    if "mp-reach" in normalized:
        mp_reach_value = "00020110" + "20010db8000000000000000000000001" + "00" + "2020010db8"
        attrs = "800e" + f"{len(bytes.fromhex(mp_reach_value)):02x}" + mp_reach_value
        return "0000" + len(bytes.fromhex(attrs)).to_bytes(2, "big").hex() + attrs
    if "extended-communities" in normalized:
        attrs = "c01010" + "0002fc0000000064" + "0002fc00000000c8"
        return "0000" + len(bytes.fromhex(attrs)).to_bytes(2, "big").hex() + attrs
    if "large-communities" in normalized:
        attrs = (
            "c02018"
            "0000fc000000006400000001"
            "0000fc000000006400000002"
        )
        return "0000" + len(bytes.fromhex(attrs)).to_bytes(2, "big").hex() + attrs
    if "communities" in normalized:
        attrs = "c00808ffffff0100fc0064"
        return "0000" + len(bytes.fromhex(attrs)).to_bytes(2, "big").hex() + attrs
    attrs = "40010100" + "4002040201fc00" + "400304c0000201"
    nlri = "18c63364"
    if "announce" not in normalized and "ipv6" in stack:
        nlri = ""
    return "0000" + len(bytes.fromhex(attrs)).to_bytes(2, "big").hex() + attrs + nlri


def _apply_bgp_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    case: str,
    behavior: str,
) -> None:
    bgp = fields["bgp"]
    bgp["marker"] = {"hex": "ff" * 16}
    bgp["type"] = _bgp_message_type_for_case(case)
    bgp["message_type"] = bgp["type"]

    if "tcp" in fields:
        fields["tcp"]["dst_port"] = 179
    if "payload" in fields:
        fields["payload"] = {"hex": "", "length": 0}

    if bgp["type"] == "keepalive":
        bgp.pop("body", None)
        return

    if bgp["type"] == "open":
        bgp["body"] = {"hex": _bgp_open_body_hex(case)}
        return

    if bgp["type"] == "notification":
        bgp["body"] = {"hex": "0203deadbeef"}
        return

    if bgp["type"] == "route_refresh":
        bgp["body"] = {"hex": "00010001"}
        return

    if bgp["type"] == "update":
        bgp["body"] = {"hex": _bgp_update_body_hex(stack=stack, case=case, behavior=behavior)}


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    """Apply a BGP feature behavior to the sampled BGP fields.

    Byte-identical to the legacy ``feature.startswith("bgp_") and "bgp" in fields``
    branch of ``generator._apply_feature_behavior``. The registry-first feature loop
    admits a plugin when its layer is in ``fields`` *or* in ``stack``, so the ``"bgp"
    not in fields`` early return preserves the exact legacy condition. ``grammar`` is
    accepted to match the uniform plugin call path but BGP does not consult it.
    """

    del feature, grammar  # BGP owns every ``bgp_*`` feature uniformly.
    if "bgp" not in fields:
        return
    _apply_bgp_behavior(fields, stack=stack, case=case, behavior=behavior)


def _handles_feature(feature: str) -> bool:
    return feature.startswith("bgp_")


register(
    ProtocolSampler(
        layer="bgp",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
    )
)
