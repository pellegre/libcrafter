"""Shared, protocol-agnostic lab-capability-derivation primitives.

The probe derives per-case capability booleans (``dns_service``, ``udp_*``,
``arp_resolution``, ``bgp_peer``, ``ipsec_*``, ...) from a lab provider's
substrate capability mapping. Most of that derivation is per-protocol, but the
input-parsing scaffolding it stands on carries no protocol knowledge:

* reading a substrate flag that is truthy under any of several aliases
  (:func:`capability`),
* reading an optional positive integer under any of several aliases
  (:func:`optional_positive_int`), and
* reading a substrate flag that defaults to ``True`` when none of its aliases
  are present (:func:`capability_default_true`).

These live here so per-protocol plugins can import them without depending on the
:mod:`lab` orchestrator module. This module must not import from :mod:`lab`
(no cycle).

Behavior is unchanged: the helpers keep their original signatures, defaults, and
derivations so every derived capability stays byte-identical.
"""

from __future__ import annotations

from collections.abc import Mapping

from .model import JSONValue


def capability(capabilities: Mapping[str, JSONValue], *names: str) -> bool:
    return any(capabilities.get(name) is True for name in names)


def optional_positive_int(
    capabilities: Mapping[str, JSONValue],
    *names: str,
) -> int | None:
    for name in names:
        value = capabilities.get(name)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return None


def capability_default_true(
    capabilities: Mapping[str, JSONValue],
    *names: str,
) -> bool:
    for name in names:
        if name in capabilities:
            return capabilities.get(name) is True
    return True


__all__ = [
    "capability",
    "capability_default_true",
    "optional_positive_int",
]
