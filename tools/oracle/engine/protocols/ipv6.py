"""Generator-stage sampler plugin for the base IPv6 layer.

Moves the ``_sample_ipv6_field`` sampler out of :mod:`generator` and registers it
through the uniform :class:`~.base.ProtocolSampler` contract; only the dispatch
moves from the generator's legacy if/elif into this self-contained module, which
self-registers on import. The sampling logic is moved verbatim (behavior must stay
byte-identical).

The base IPv6 layer carries no feature behavior — the ``ipv6_fragment_routing``
feature targets the IPv6 extension headers, which migrate in a later step — so this
plugin registers ``sample`` only.

Shared primitives (``_integer_domain_value``, ``_ipv6_next_header_for_stack``) live
in :mod:`..sampling` because they are cross-layer stack grammar still used by other
(unmigrated) layers, including the IPv6 extension-header sampling in ``generator``;
they are imported here rather than duplicated. Relative imports only so the package
resolves under both the ``engine.*`` (CLI) and ``tools.oracle.engine.*`` (tests)
import roots.
"""

from __future__ import annotations

from collections.abc import Mapping

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


register(
    ProtocolSampler(
        layer="ipv6",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
    )
)
