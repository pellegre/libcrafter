"""Backend integrations for oracle validation."""

from .registry import (
    BACKEND_CAPABILITY_NAMES,
    BackendAvailability,
    BackendCapabilities,
    BackendCapabilityName,
    BackendRegistration,
    UnknownBackendError,
    backend_report_metadata,
    get_backend,
    get_backend_capability_registration,
    registered_backend_names,
)

__all__ = [
    "BACKEND_CAPABILITY_NAMES",
    "BackendAvailability",
    "BackendCapabilities",
    "BackendCapabilityName",
    "BackendRegistration",
    "UnknownBackendError",
    "backend_report_metadata",
    "get_backend",
    "get_backend_capability_registration",
    "registered_backend_names",
]
