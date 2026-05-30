"""Wire provider and exposure compatibility registry."""

from __future__ import annotations

from collections.abc import Mapping


class ProviderExposureError(ValueError):
    """Raised when a provider/exposure request is not registered as supported."""


_SUPPORTED_EXPOSURES_BY_PROVIDER: Mapping[str, frozenset[str]] = {
    "hetzner": frozenset({"wan", "private"}),
    "qemu": frozenset({"wan", "private"}),
    "virtualbox": frozenset({"lan", "private"}),
}

_KNOWN_EXPOSURES = frozenset({"wan", "private", "lan", "wifi"})


def registered_providers() -> tuple[str, ...]:
    """Return provider names registered with the wire engine."""

    return tuple(sorted(_SUPPORTED_EXPOSURES_BY_PROVIDER))


def known_exposures() -> tuple[str, ...]:
    """Return exposure names understood by the wire engine."""

    return tuple(sorted(_KNOWN_EXPOSURES))


def supported_exposures(provider: str) -> tuple[str, ...]:
    """Return supported exposure names for a registered provider."""

    _validate_provider(provider, exposure="<unspecified>")
    return tuple(sorted(_SUPPORTED_EXPOSURES_BY_PROVIDER[provider]))


def is_supported_request(provider: str, exposure: str) -> bool:
    """Return whether the provider/exposure pair is explicitly supported."""

    return (
        isinstance(provider, str)
        and isinstance(exposure, str)
        and exposure in _SUPPORTED_EXPOSURES_BY_PROVIDER.get(provider, frozenset())
    )


def validate_request(provider: str, exposure: str) -> None:
    """Raise if a provider/exposure pair is unknown or unsupported."""

    _validate_provider(provider, exposure)
    _validate_exposure(provider, exposure)
    if exposure not in _SUPPORTED_EXPOSURES_BY_PROVIDER[provider]:
        supported = ", ".join(supported_exposures(provider))
        raise ProviderExposureError(
            f"unsupported provider/exposure: provider={provider!r}, "
            f"exposure={exposure!r}; supported exposures for provider "
            f"{provider!r}: {supported}"
        )


def _validate_provider(provider: str, exposure: str) -> None:
    if not isinstance(provider, str) or provider == "":
        raise ProviderExposureError(
            f"unsupported provider/exposure: provider={provider!r}, "
            f"exposure={exposure!r}; provider must be a non-empty string"
        )
    if provider not in _SUPPORTED_EXPOSURES_BY_PROVIDER:
        supported = ", ".join(registered_providers())
        raise ProviderExposureError(
            f"unsupported provider/exposure: provider={provider!r}, "
            f"exposure={exposure!r}; supported providers: {supported}"
        )


def _validate_exposure(provider: str, exposure: str) -> None:
    if not isinstance(exposure, str) or exposure == "":
        raise ProviderExposureError(
            f"unsupported provider/exposure: provider={provider!r}, "
            f"exposure={exposure!r}; exposure must be a non-empty string"
        )
    if exposure not in _KNOWN_EXPOSURES:
        supported = ", ".join(known_exposures())
        raise ProviderExposureError(
            f"unsupported provider/exposure: provider={provider!r}, "
            f"exposure={exposure!r}; known exposures: {supported}"
        )
