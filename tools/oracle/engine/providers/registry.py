"""Oracle live provider adapter registry."""

from __future__ import annotations

from .base import LiveProviderAdapter
from .hetzner import HETZNER_LIVE_PROVIDER_ADAPTER
from .qemu import QEMU_LIVE_PROVIDER_ADAPTER
from .virtualbox import VIRTUALBOX_LIVE_PROVIDER_ADAPTER


class UnknownLiveProviderError(ValueError):
    """Raised when oracle live mode is asked for an unregistered provider."""


_REGISTERED_PROVIDERS: dict[str, LiveProviderAdapter] = {
    HETZNER_LIVE_PROVIDER_ADAPTER.name: HETZNER_LIVE_PROVIDER_ADAPTER,
    QEMU_LIVE_PROVIDER_ADAPTER.name: QEMU_LIVE_PROVIDER_ADAPTER,
    VIRTUALBOX_LIVE_PROVIDER_ADAPTER.name: VIRTUALBOX_LIVE_PROVIDER_ADAPTER,
}


def registered_provider_names() -> tuple[str, ...]:
    """Return registered provider-backed oracle live provider names."""

    return tuple(sorted(_REGISTERED_PROVIDERS))


def resolve_live_provider(name: str) -> LiveProviderAdapter:
    """Return the registered adapter for a provider-backed oracle live name."""

    try:
        return _REGISTERED_PROVIDERS[name]
    except KeyError as exc:
        known = ", ".join(registered_provider_names()) or "<none>"
        raise UnknownLiveProviderError(
            f"unsupported oracle live provider {name!r}; known providers: {known}"
        ) from exc
