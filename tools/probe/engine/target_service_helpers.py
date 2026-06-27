"""Shared, protocol-agnostic primitives for probe target services.

This module owns the typed service-descriptor dataclasses and the small
plan/port/address scaffolding helpers that every per-protocol target-service
contribution shares. They are deterministic, inspectable data structures and
pure helpers with no per-protocol knowledge, so per-protocol plugins can import
them without depending on the :mod:`target_services` orchestrator (which keeps
the per-protocol descriptor builders and the central setup-plan/setup-script
generators).

This module must not import from :mod:`target_services`; the dependency runs the
other way.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from .model import JSONObject, JSONValue, json_object


# --------------------------------------------------------------------------- #
# Typed service descriptors
# --------------------------------------------------------------------------- #
#
# Each descriptor is a deterministic, inspectable plan for one controlled
# target service or one piece of verified kernel state. They are the typed
# contract the live setup script renders and the dry-run report advertises.


@dataclass(frozen=True, slots=True)
class TargetServiceDescriptor:
    """A controlled, disposable service the target endpoint stands up.

    ``setup_commands`` and ``cleanup_commands`` are deterministic shell
    fragments; ``artifacts`` lists the relative artifact paths the running
    service produces so the live path can collect inspectable evidence.
    """

    name: str
    protocol: str
    purpose: str
    bind_ipv4: str
    source_ipv4: str
    port: int | None = None
    requires: list[str] = field(default_factory=list)
    setup_commands: list[str] = field(default_factory=list)
    cleanup_commands: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class KernelStateDescriptor:
    """A piece of target kernel state the setup verifies or configures.

    Used for closed UDP/TCP port validation, ARP alias addresses, and ARP
    sysctl tuning. ``verify_commands`` assert preconditions; ``setup_commands``
    apply state; ``cleanup_commands`` restore it.
    """

    name: str
    purpose: str
    bind_ipv4: str
    source_ipv4: str
    port: int | None = None
    verify_commands: list[str] = field(default_factory=list)
    setup_commands: list[str] = field(default_factory=list)
    cleanup_commands: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Plan filters and small helpers
# --------------------------------------------------------------------------- #


def plans_by_destination_port(plans: Iterable[JSONObject]) -> dict[int, JSONObject]:
    """Map each plan's destination port to the first plan that used it."""

    by_port: dict[int, JSONObject] = {}
    for plan in plans:
        port = int(plan["destination_port"])
        by_port.setdefault(port, plan)
    return by_port


def target_service_address_fields(plan: Mapping[str, JSONValue]) -> JSONObject:
    """Return the bind/source IPv4 fields for a plan's target service."""

    target_service = json_mapping(
        plan.get("target_service", {}),
        "probe_plan.target_service",
    )
    bind_ipv4 = string_or(
        target_service.get("bind_ipv4"),
        string_or(plan.get("destination_ipv4"), ""),
    )
    source_ipv4 = string_or(
        target_service.get("source_ipv4"),
        string_or(plan.get("source_ipv4"), ""),
    )
    fields: JSONObject = {}
    if bind_ipv4:
        fields["bind_ipv4"] = bind_ipv4
    if source_ipv4:
        fields["source_ipv4"] = source_ipv4
    return fields


def probe_plan_send_count(plan: Mapping[str, JSONValue]) -> int:
    """Return the number of endpoint sends represented by a probe plan."""

    for key in ("sends", "dhcpv4_sends", "arp_sends", "udp_sends"):
        value = plan.get(key)
        if isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            return len(value)
    raw_count = plan.get("send_count")
    if isinstance(raw_count, int) and raw_count > 0:
        return raw_count
    return 1


def dedupe_ints(values: Iterable[int]) -> list[int]:
    """Return the integer sequence with duplicates removed, order preserved."""

    return list(dict.fromkeys(values))


def string_or(value: object, default: str) -> str:
    return value if isinstance(value, str) and value else default


def json_mapping(value: object, name: str) -> JSONObject:
    if isinstance(value, Mapping):
        return json_object(value, name)
    return {}


__all__ = [
    "KernelStateDescriptor",
    "TargetServiceDescriptor",
    "dedupe_ints",
    "json_mapping",
    "plans_by_destination_port",
    "probe_plan_send_count",
    "string_or",
    "target_service_address_fields",
]
