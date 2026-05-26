"""Backend integrations for oracle validation."""

if __name__ == "backends":
    # `unittest discover -s tools/oracle/engine` imports this package as a
    # top-level module. Do not recurse into backend packages under that alias.
    def load_tests(loader, tests, pattern):
        return loader.suiteClass()

else:
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
