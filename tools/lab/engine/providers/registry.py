"""Lab provider adapter registry."""

from __future__ import annotations

from .base import LabProviderAdapter
from .hetzner import HETZNER_LAB_PROVIDER_ADAPTER


class UnknownLabProviderError(ValueError):
    """Raised when lab is asked for an unregistered provider."""


_REGISTERED_PROVIDERS: dict[str, LabProviderAdapter] = {
    HETZNER_LAB_PROVIDER_ADAPTER.name: HETZNER_LAB_PROVIDER_ADAPTER,
}


def registered_provider_names() -> tuple[str, ...]:
    """Return registered lab provider names."""

    return tuple(sorted(_REGISTERED_PROVIDERS))


def registered_providers() -> tuple[LabProviderAdapter, ...]:
    """Return registered lab provider adapters sorted by name."""

    return tuple(_REGISTERED_PROVIDERS[name] for name in registered_provider_names())


def resolve_lab_provider(name: str) -> LabProviderAdapter:
    """Return the registered adapter for a lab provider name."""

    try:
        return _REGISTERED_PROVIDERS[name]
    except KeyError as exc:
        known = ", ".join(registered_provider_names()) or "<none>"
        raise UnknownLabProviderError(
            f"unsupported lab provider {name!r}; known providers: {known}"
        ) from exc
