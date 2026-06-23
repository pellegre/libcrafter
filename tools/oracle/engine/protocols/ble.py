"""Generator-stage sampler plugins for the BLE layers (``ble_radio``, ``ble_adv``).

BLE is the last protocol migration. Like IGMP, BLE samples no fields: every field
in ``specs/layers/ble_radio.yaml`` and ``specs/layers/ble_adv.yaml`` is driven by a
feature behavior (``specs/features/ble-radio-phdr.yaml`` / the BLE advertising
feature), never by ``_sample_field_value``. The former ``generator._SUPPORTED_FIELDS``
table carried no ``ble_radio`` / ``ble_adv`` entry, so ``_sample_layer_fields``
skipped every BLE field. The registered :class:`~.base.ProtocolSampler`s therefore
declare an empty ``supported_fields`` set — identical to the legacy
``_SUPPORTED_FIELDS.get("ble_radio", set())`` / ``("ble_adv", set())`` fallback — and
their ``sample`` callbacks are never invoked.

BLE has no Python feature ``apply_behavior``: the BLE feature values are applied
through the generic feature-fields mechanism, not a per-protocol behavior branch, so
these plugins register no ``apply_behavior`` / ``handles_feature``. There was no BLE
sampler function, ``_SUPPORTED_FIELDS`` entry, or feature branch in ``generator.py``
to remove; this module only adds the two registrations the coverage test requires.

Relative imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping

from ..sampling import _SamplingContext
from .base import ProtocolSampler, register


# BLE samples no fields: every ble_radio.yaml / ble_adv.yaml field is behavior-driven,
# so the generator's legacy ``_SUPPORTED_FIELDS`` table had no BLE entry and
# ``_sample_layer_fields`` skipped every BLE field. An empty allowlist reproduces the
# legacy ``_SUPPORTED_FIELDS.get(<ble layer>, set())`` fallback exactly.
_BLE_SUPPORTED_FIELDS: frozenset[str] = frozenset()


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Unreachable BLE field sampler.

    Both BLE layers declare an empty ``supported_fields`` set, so
    ``_sample_layer_fields`` skips every BLE field and never calls this adapter. It
    exists only to satisfy the :class:`ProtocolSampler` contract (``sample`` is
    required) and mirrors the legacy generator, which had no BLE branch in
    ``_sample_field_value``.
    """

    raise ValueError(f"spec error: unsupported BLE field sampler: {field_name}")


register(
    ProtocolSampler(
        layer="ble_radio",
        supported_fields=_BLE_SUPPORTED_FIELDS,
        sample=_sample,
    )
)


register(
    ProtocolSampler(
        layer="ble_adv",
        supported_fields=_BLE_SUPPORTED_FIELDS,
        sample=_sample,
    )
)
