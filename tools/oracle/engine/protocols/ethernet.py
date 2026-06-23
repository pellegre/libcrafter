"""Generator-stage sampler plugins for the ``ethernet`` and ``vlan`` framing layers.

Unlike most protocols these two were sampled in-line inside
``generator._sample_field_value`` (rather than via a ``_sample_<l>_field`` free
function). This module moves that inline logic verbatim into one
:class:`~.base.ProtocolSampler` per layer (behavior must stay byte-identical);
only the dispatch moves out of the generator's legacy if/elif. The modules
self-register on import.

The EtherType-from-stack routing helpers (``_declared_ethertype_for_stack``) are
shared cross-layer stack grammar used by several framing layers, so they live in
:mod:`..sampling` and are imported here rather than duplicated. Relative imports
only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping

from ..sampling import (
    _SamplingContext,
    _declared_ethertype_for_stack,
    _field_bits,
    _integer_domain_value,
    _mac_for_domain,
)
from .base import ProtocolSampler, register


# Ethernet fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["ethernet"]`` entry.
_ETHERNET_SUPPORTED_FIELDS = frozenset({"dst", "src", "ethertype"})

# VLAN (802.1Q) fields, mirroring the former
# ``generator._SUPPORTED_FIELDS["vlan"]`` entry.
_VLAN_SUPPORTED_FIELDS = frozenset(
    {"priority", "drop_eligible", "vlan_id", "ethertype"}
)


def _sample_ethernet(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    if field_name == "src":
        return _mac_for_domain(ctx, domain, ctx.src_mac)
    if field_name == "dst":
        return _mac_for_domain(ctx, domain, ctx.dst_mac)
    if field_name == "ethertype":
        return _declared_ethertype_for_stack(ctx.stack, "ethernet")
    raise ValueError(f"spec error: unsupported ethernet field sampler: {field_name}")


def _sample_vlan(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    if field_name == "ethertype":
        return _declared_ethertype_for_stack(ctx.stack, "vlan")
    return _integer_domain_value(ctx, domain, field_name, bits=_field_bits(field_spec))


register(
    ProtocolSampler(
        layer="ethernet",
        supported_fields=_ETHERNET_SUPPORTED_FIELDS,
        sample=_sample_ethernet,
    )
)

register(
    ProtocolSampler(
        layer="vlan",
        supported_fields=_VLAN_SUPPORTED_FIELDS,
        sample=_sample_vlan,
    )
)
