"""Lab provider adapter package."""

from .base import LabProviderAdapter
from .hetzner import HETZNER_LAB_PROVIDER_ADAPTER, HetznerLabProviderAdapter
from .qemu import QEMU_LAB_PROVIDER_ADAPTER, QemuLabProviderAdapter
from .registry import (
    UnknownLabProviderError,
    registered_providers,
    registered_provider_names,
    resolve_lab_provider,
)

__all__ = [
    "HETZNER_LAB_PROVIDER_ADAPTER",
    "HetznerLabProviderAdapter",
    "LabProviderAdapter",
    "QEMU_LAB_PROVIDER_ADAPTER",
    "QemuLabProviderAdapter",
    "UnknownLabProviderError",
    "registered_providers",
    "registered_provider_names",
    "resolve_lab_provider",
]
