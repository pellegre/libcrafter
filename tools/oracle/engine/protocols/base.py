"""Generator-stage protocol plugin contract and registry.

A protocol module in this package registers one :class:`ProtocolSampler` per layer
it owns. The generator consults :data:`SAMPLER_REGISTRY` before its legacy if/elif
branches, so a registered plugin supersedes the in-line sampling/feature code for
its layer and an absent one falls through to the legacy path. The registry starts
empty; migrating a protocol means dropping a module here that calls
:func:`register`.

The contract is intentionally uniform so every protocol slots into the same shape:
``sample`` covers per-field value sampling, ``apply_behavior`` covers feature
behavior (and may write cross-layer, e.g. RIP -> UDP port), ``handles_feature``
selects which feature names the plugin owns, and ``post_sample`` is the ordered
post-sampling hook (e.g. IPsec pinned crypto). Callbacks a protocol does not need
stay ``None``. Modules use relative imports only so the package works under both the
``engine.*`` (CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..plugin_registry import PluginRegistry


@dataclass(frozen=True)
class ProtocolSampler:
    """Generator-stage plugin for one layer.

    ``layer`` is the layer name the plugin owns; ``supported_fields`` mirrors the
    generator's per-layer field allowlist. ``sample`` returns a per-field value (or
    the sampling-skip sentinel) given the sampling context, the resolved field name,
    and the chosen domain, plus the raw ``field_spec`` and the layer's
    ``current_fields`` sampled so far:
    ``sample(ctx, field_name, domain, *, field_spec, current_fields) -> object``.
    ``apply_behavior(fields, *, stack, feature, case, behavior) -> None`` mutates
    ``fields`` in place for a selected feature behavior;
    ``handles_feature(feature) -> bool`` reports whether the plugin owns a feature
    name; ``post_sample(fields, *, stack, case) -> None`` runs after all field
    sampling for ordering dependencies. The optional callbacks default to ``None``
    when unused.
    """

    layer: str
    supported_fields: frozenset[str]
    sample: Callable[..., object]
    apply_behavior: Callable[..., None] | None = None
    handles_feature: Callable[[str], bool] | None = None
    post_sample: Callable[..., None] | None = None


SAMPLER_REGISTRY: PluginRegistry[ProtocolSampler] = PluginRegistry("sampler")


def register(plugin: ProtocolSampler) -> None:
    """Register ``plugin`` under its layer name in :data:`SAMPLER_REGISTRY`."""

    SAMPLER_REGISTRY.register(plugin.layer, plugin)


__all__ = ["ProtocolSampler", "SAMPLER_REGISTRY", "register"]
