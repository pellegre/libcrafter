"""Lab provider adapter registry."""

from __future__ import annotations

from .base import LabProviderAdapter


class UnknownLabProviderError(ValueError):
    """Raised when lab is asked for an unregistered provider."""


_REGISTERED_PROVIDERS: dict[str, LabProviderAdapter] = {}


def registered_provider_names() -> tuple[str, ...]:
    """Return registered lab provider names."""

    return tuple(sorted(_REGISTERED_PROVIDERS))


def resolve_lab_provider(name: str) -> LabProviderAdapter:
    """Return the registered adapter for a lab provider name."""

    try:
        return _REGISTERED_PROVIDERS[name]
    except KeyError as exc:
        known = ", ".join(registered_provider_names()) or "<none>"
        raise UnknownLabProviderError(
            f"unsupported lab provider {name!r}; known providers: {known}"
        ) from exc
