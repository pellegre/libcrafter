"""Generator-stage sampler plugins for the Wi-Fi (802.11) stack.

The 802.11 stack spans ``radiotap``, ``dot11``, ``eapol``, and ``rsn`` (the
``llc_snap`` framing layer migrated separately). This module is the home for all
of them; this step migrates ``radiotap`` and the next two add ``eapol`` / ``rsn``
and ``dot11``.

Moves the ``_sample_radiotap_field`` sampler out of :mod:`generator` verbatim and
registers it through the uniform :class:`~.base.ProtocolSampler` contract; only the
dispatch moves out of the generator's legacy if/elif. Radiotap carries no feature
behavior, so the plugin registers ``sample`` alone. Behavior must stay
byte-identical.

Shared sampling primitives (``_SamplingContext``, ``_SKIP_FIELD``,
``_integer_domain_value``) live in :mod:`..sampling`; they are imported here rather
than duplicated. Relative imports only so the package resolves under both the
``engine.*`` (CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping

from ..sampling import _SamplingContext, _SKIP_FIELD, _integer_domain_value
from .base import ProtocolSampler, register


# Radiotap fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["radiotap"]`` entry.
_RADIOTAP_SUPPORTED_FIELDS = frozenset(
    {
        "antenna",
        "channel_flags",
        "channel_frequency",
        "dbm_antenna_signal",
        "fcs_status",
        "flags",
        "length",
        "pad",
        "present_words",
        "rate",
        "rx_flags",
        "tx_flags",
        "unknown_fields",
        "version",
    }
)


def _sample_radiotap_field(
    ctx: _SamplingContext, field_name: str, domain: object
) -> object:
    if field_name == "version":
        return 0 if domain != "explicit_nonzero" else 1
    if field_name == "pad":
        return 0
    if field_name == "length":
        return 0
    if field_name == "present_words":
        return [0]
    if field_name == "flags":
        if domain == "absent":
            return _SKIP_FIELD
        if domain in {"fcs_present", "fcs_present_failed"}:
            return "fcs_present"
        if domain == "failed_fcs":
            return "failed_fcs"
        return "none"
    if field_name == "rate":
        return _SKIP_FIELD if domain == "absent" else (2 if domain == "2" else _integer_domain_value(ctx, domain, field_name, bits=8))
    if field_name == "channel_frequency":
        return _SKIP_FIELD if domain == "absent" else _integer_domain_value(ctx, domain, field_name, bits=16)
    if field_name == "channel_flags":
        if domain == "absent":
            return _SKIP_FIELD
        return domain
    if field_name == "dbm_antenna_signal":
        if domain == "absent":
            return _SKIP_FIELD
        if domain == "boundary":
            return -128
        return -42 if domain == "synthetic_signal" else _integer_domain_value(ctx, domain, field_name, bits=8)
    if field_name == "antenna":
        return _SKIP_FIELD if domain == "absent" else _integer_domain_value(ctx, domain, field_name, bits=8)
    if field_name == "rx_flags":
        if domain == "absent":
            return _SKIP_FIELD
        return 0x0001 if domain == "failed_fcs" else 0
    if field_name == "tx_flags":
        if domain == "absent":
            return _SKIP_FIELD
        return 0x0008 if domain == "no_ack" else 0
    if field_name == "unknown_fields":
        return _SKIP_FIELD if domain == "absent" else {"hex": "aabbccdd"}
    if field_name == "fcs_status":
        return _SKIP_FIELD if domain == "absent" else domain
    raise ValueError(f"spec error: unsupported radiotap field sampler: {field_name}")


def _sample_radiotap(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: radiotap reads only ctx/field_name/domain."""

    return _sample_radiotap_field(ctx, field_name, domain)


register(
    ProtocolSampler(
        layer="radiotap",
        supported_fields=_RADIOTAP_SUPPORTED_FIELDS,
        sample=_sample_radiotap,
    )
)
