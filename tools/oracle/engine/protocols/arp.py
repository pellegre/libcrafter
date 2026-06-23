"""Generator-stage sampler plugin for the ARP layer.

This module is the reference vertical-slice migration: it moves the ARP field
sampler out of :mod:`generator` and registers it through the uniform
:class:`~.base.ProtocolSampler` contract. The sampling logic is moved verbatim
(behavior must stay byte-identical); only the dispatch moves from the generator's
legacy if/elif into this self-contained module, which self-registers on import.

Relative imports only so the package resolves under both the ``engine.*`` (CLI)
and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping

from ..sampling import (
    _SamplingContext,
    _integer_domain_value,
    _mac_for_domain,
)
from .base import ProtocolSampler, register


# ARP fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["arp"]`` entry.
_SUPPORTED_FIELDS = frozenset(
    {
        "hardware_type",
        "protocol_type",
        "hardware_length",
        "protocol_length",
        "opcode",
        "sender_hardware_address",
        "sender_protocol_address",
        "target_hardware_address",
        "target_protocol_address",
    }
)


def _sample_arp_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "hardware_type":
        return "ethernet"
    if field_name == "protocol_type":
        return "ipv4"
    if field_name == "hardware_length":
        return _integer_domain_value(ctx, domain, field_name, bits=8)
    if field_name == "protocol_length":
        return _integer_domain_value(ctx, domain, field_name, bits=8)
    if field_name == "opcode":
        return domain
    if field_name == "sender_hardware_address":
        return _mac_for_domain(ctx, domain, ctx.src_mac)
    if field_name == "target_hardware_address":
        return _mac_for_domain(ctx, domain, ctx.dst_mac)
    if field_name == "sender_protocol_address":
        return _arp_protocol_address_for_domain(ctx, domain, ctx.arp_sender_ip)
    if field_name == "target_protocol_address":
        return _arp_protocol_address_for_domain(ctx, domain, ctx.arp_target_ip)
    raise ValueError(f"spec error: unsupported arp field sampler: {field_name}")


def _arp_protocol_address_for_domain(
    ctx: _SamplingContext, domain: object, default: str
) -> str:
    if domain == "zero":
        return "0.0.0.0"
    return default


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: ARP only needs ``ctx``, ``field_name``, ``domain``."""

    return _sample_arp_field(ctx, field_name, domain)


register(
    ProtocolSampler(
        layer="arp",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
    )
)
