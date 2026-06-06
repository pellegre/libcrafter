"""Endpoint provider implementations."""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

from ..registry import ProviderExposureError, validate_request


def resolve_provider(provider: str, exposure: str) -> ModuleType:
    """Return the provider module for a supported provider/exposure request."""

    validate_request(provider, exposure)
    module_name = f"{__name__}.{provider}"
    try:
        return import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name != module_name:
            raise
        raise ProviderExposureError(
            f"unsupported provider/exposure: provider={provider!r}, "
            f"exposure={exposure!r}; provider module {module_name!r} is not available"
        ) from exc


__all__ = ["resolve_provider"]
