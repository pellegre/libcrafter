"""Backend capability registry for oracle validation."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import Literal, TypeAlias

from ..model import JSONObject


BackendCapabilityName: TypeAlias = Literal[
    "encode",
    "decode",
    "pcap_read",
    "pcap_write",
    "live_endpoint",
]
BACKEND_CAPABILITY_NAMES: tuple[BackendCapabilityName, ...] = (
    "encode",
    "decode",
    "pcap_read",
    "pcap_write",
    "live_endpoint",
)


@dataclass(frozen=True, slots=True)
class BackendCapabilities:
    """Capability flags used to validate mode/backend combinations."""

    encode: bool = False
    decode: bool = False
    pcap_read: bool = False
    pcap_write: bool = False
    live_endpoint: bool = False

    def supports(self, capability: BackendCapabilityName) -> bool:
        return bool(getattr(self, capability))

    def enabled(self) -> list[str]:
        return [
            capability
            for capability in BACKEND_CAPABILITY_NAMES
            if self.supports(capability)
        ]

    def missing(self, required: tuple[BackendCapabilityName, ...]) -> list[str]:
        return [
            capability
            for capability in required
            if not self.supports(capability)
        ]

    def to_dict(self) -> JSONObject:
        return {
            "encode": self.encode,
            "decode": self.decode,
            "pcap_read": self.pcap_read,
            "pcap_write": self.pcap_write,
            "live_endpoint": self.live_endpoint,
            "enabled": self.enabled(),
        }


@dataclass(frozen=True, slots=True)
class BackendAvailability:
    """Runtime availability details for optional backend dependencies."""

    available: bool
    dependency: str
    path: str | None = None
    reason: str | None = None

    def to_dict(self) -> JSONObject:
        output: JSONObject = {
            "available": self.available,
            "dependency": self.dependency,
        }
        if self.path is not None:
            output["path"] = self.path
        if self.reason is not None:
            output["reason"] = self.reason
        return output


@dataclass(frozen=True, slots=True)
class BackendRegistration:
    """Registered oracle backend and its supported validation roles."""

    name: str
    display_name: str
    backend_type: str
    capabilities: BackendCapabilities
    availability: BackendAvailability
    description: str

    @property
    def parser_only(self) -> bool:
        return self.backend_type == "parser-only"

    def to_dict(self) -> JSONObject:
        return {
            "backend": self.name,
            "name": self.name,
            "display_name": self.display_name,
            "type": self.backend_type,
            "parser_only": self.parser_only,
            "description": self.description,
            "capabilities": self.capabilities.to_dict(),
            "availability": self.availability.to_dict(),
        }


class UnknownBackendError(ValueError):
    """Raised when a backend name is not registered."""


def registered_backend_names() -> tuple[str, ...]:
    """Return backend names accepted by user-facing oracle commands."""

    return tuple(_BACKEND_FACTORIES)


def get_backend(name: str) -> BackendRegistration:
    """Resolve one backend registration, refreshing availability as needed."""

    factory = _BACKEND_FACTORIES.get(name)
    if factory is None:
        supported = ", ".join(registered_backend_names())
        raise UnknownBackendError(f"unsupported backend: {name}; supported: {supported}")
    return factory()


def backend_report_metadata(
    name: str,
    *,
    include_dependency_metadata: bool = False,
) -> JSONObject:
    """Return JSON metadata for a backend-info report."""

    backend = get_backend(name)
    metadata = backend.to_dict()
    if include_dependency_metadata and name == "scapy":
        from .scapy.bootstrap import backend_info

        metadata.update(backend_info())
    elif name == "wireshark":
        metadata["tshark"] = backend.availability.to_dict()
    return metadata


def _scapy_backend() -> BackendRegistration:
    from .scapy.bootstrap import SCAPY_REQUIREMENT

    return BackendRegistration(
        name="scapy",
        display_name="Scapy",
        backend_type="read-write",
        capabilities=BackendCapabilities(
            encode=True,
            decode=True,
            pcap_read=True,
            pcap_write=True,
            live_endpoint=True,
        ),
        availability=BackendAvailability(
            available=True,
            dependency=SCAPY_REQUIREMENT,
            reason="managed by oracle Scapy bootstrap",
        ),
        description="Full packet writer/parser backend.",
    )


def _wireshark_backend() -> BackendRegistration:
    tshark = shutil.which("tshark")
    return BackendRegistration(
        name="wireshark",
        display_name="Wireshark/tshark",
        backend_type="parser-only",
        capabilities=BackendCapabilities(
            decode=True,
            pcap_read=True,
        ),
        availability=BackendAvailability(
            available=tshark is not None,
            dependency="tshark",
            path=tshark,
            reason=None if tshark is not None else "tshark not found on PATH",
        ),
        description="Parser-only backend for decode and pcap read validation.",
    )


_BACKEND_FACTORIES = {
    "scapy": _scapy_backend,
    "wireshark": _wireshark_backend,
}
