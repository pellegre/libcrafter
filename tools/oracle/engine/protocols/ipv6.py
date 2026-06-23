"""Generator-stage sampler plugin for the base IPv6 layer.

Moves the ``_sample_ipv6_field`` sampler out of :mod:`generator` and registers it
through the uniform :class:`~.base.ProtocolSampler` contract; only the dispatch
moves from the generator's legacy if/elif into this self-contained module, which
self-registers on import. The sampling logic is moved verbatim (behavior must stay
byte-identical).

The ``ipv6_fragment_routing`` feature behavior — which rewrites the
``ipv6_fragment``/``ipv6_routing`` extension-header fields by case keyword — also
lives here, registered on the base IPv6 plugin via ``apply_behavior`` /
``handles_feature``. The extension headers always ride on a base ``ipv6`` layer (the
stacks never carry an extension header without ``ipv6`` first), so the
generator's registry-first feature loop fires this plugin exactly once whenever the
feature applies — the same selection the legacy ``feature == "ipv6_fragment_routing"``
branch performed. The branch body is moved byte-identically. The IPv6
extension-header *layers* are sub-layers of the ``ipv6`` spec (declared as
``extension_layers`` inside ``specs/layers/ipv6.yaml``, not as separate top-level
spec layers), so they have no per-field sampler entry in ``generator._SUPPORTED_FIELDS``
and no separate registry name of their own; their whole-layer field dicts are still
assembled inline in ``generator._fields``.

Shared primitives (``_integer_domain_value``, ``_ipv6_next_header_for_stack``) live
in :mod:`..sampling` because they are cross-layer stack grammar still used by other
(unmigrated) layers, including the IPv6 extension-header sampling in ``generator``;
they are imported here rather than duplicated. Relative imports only so the package
resolves under both the ``engine.*`` (CLI) and ``tools.oracle.engine.*`` (tests)
import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import (
    _SamplingContext,
    _integer_domain_value,
    _ipv6_next_header_for_stack,
)
from .base import ProtocolSampler, register


# IPv6 fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["ipv6"]`` entry.
_SUPPORTED_FIELDS = frozenset(
    {
        "src",
        "dst",
        "traffic_class",
        "flow_label",
        "next_header",
        "hop_limit",
    }
)


def _sample_ipv6_field(
    ctx: _SamplingContext, field_name: str, domain: object
) -> object:
    if field_name == "src":
        return ctx.src_ipv6
    if field_name == "dst":
        return ctx.dst_ipv6
    if field_name == "traffic_class":
        return _integer_domain_value(ctx, domain, field_name, bits=8)
    if field_name == "flow_label":
        return _integer_domain_value(ctx, domain, field_name, bits=20)
    if field_name == "next_header":
        return _ipv6_next_header_for_stack(ctx.stack, "ipv6")
    if field_name == "hop_limit":
        return _integer_domain_value(ctx, domain, field_name, bits=8)
    raise ValueError(f"spec error: unsupported ipv6 field sampler: {field_name}")


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: base IPv6 needs only ``ctx``/``field_name``/``domain``."""

    return _sample_ipv6_field(ctx, field_name, domain)


def _handles_feature(feature: str) -> bool:
    """The base IPv6 plugin owns the ``ipv6_fragment_routing`` feature."""

    return feature == "ipv6_fragment_routing"


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
) -> None:
    """Apply ``ipv6_fragment_routing`` behavior into the extension-header fields.

    Moved byte-identically out of the legacy ``generator._apply_feature_behavior``
    ``elif feature == "ipv6_fragment_routing"`` branch: the fragment header's
    ``more_fragments``/``fragment_offset`` are reset, and the routing header's
    ``type``/``segments_left``/``addresses`` are set by case keyword
    (``"segment"`` -> type 4 segleft 1 addr ``2001:db8:ffff::1``; ``"mobile"`` ->
    type 2 segleft 1 addr ``2001:db8:ffff::2``; otherwise type 0 segleft 0).
    """

    if "ipv6_fragment" in fields:
        fields["ipv6_fragment"]["more_fragments"] = False
        fields["ipv6_fragment"]["fragment_offset"] = 0
    if "ipv6_routing" in fields:
        routing = fields["ipv6_routing"]
        if "segment" in case:
            routing["type"] = 4
            routing["segments_left"] = 1
            routing["addresses"] = ["2001:db8:ffff::1"]
        elif "mobile" in case:
            routing["type"] = 2
            routing["segments_left"] = 1
            routing["addresses"] = ["2001:db8:ffff::2"]
        else:
            routing["type"] = 0
            routing["segments_left"] = 0


register(
    ProtocolSampler(
        layer="ipv6",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
    )
)
