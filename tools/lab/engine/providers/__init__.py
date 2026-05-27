"""Lab provider adapter package."""

from .base import LabProviderAdapter
from .hetzner import HETZNER_LAB_PROVIDER_ADAPTER, HetznerLabProviderAdapter
from .qemu import QEMU_LAB_PROVIDER_ADAPTER, QemuLabProviderAdapter
from .virtualbox import VIRTUALBOX_LAB_PROVIDER_ADAPTER, VirtualBoxLabProviderAdapter
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
    "VIRTUALBOX_LAB_PROVIDER_ADAPTER",
    "VirtualBoxLabProviderAdapter",
    "registered_providers",
    "registered_provider_names",
    "resolve_lab_provider",
]
