"""Shared, protocol-agnostic planning primitives for probe plan builders.

These deterministic byte/address/MAC helpers and the :data:`PlanBuilder` type
alias are the foundation every per-case ``_<case>_probe_plan`` builder shares.
They are extracted here so per-protocol plugin modules can import them without a
circular dependency on :mod:`planning` (the layering is
``planning_helpers`` <- protocol plugins <- ``planning``). This module must not
import from :mod:`planning`.

Behavior is unchanged: the helpers keep their original signatures, defaults, and
derivations so every emitted plan stays byte-identical.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from .model import JSONObject


# A plan builder takes the deterministic planning inputs (profile, seed,
# sequence) plus the case name and returns the case's stable plan object.
PlanBuilder = Callable[..., JSONObject]


def deterministic_bytes(case: str, profile: str, seed: int, sequence: int) -> bytes:
    material = f"{case}\0{profile}\0{seed}\0{sequence}".encode("utf-8")
    return hashlib.sha256(material).digest()


def deterministic_ipv4_pair(profile: str, seed: int, sequence: int) -> tuple[str, str]:
    digest = deterministic_bytes("endpoint-addresses", profile, seed, sequence)
    second = 64 + digest[0] % 64
    third = digest[1]
    return f"10.{second}.{third}.10", f"10.{second}.{third}.20"


def deterministic_router_ipv4(profile: str, seed: int, sequence: int) -> str:
    digest = deterministic_bytes("endpoint-addresses", profile, seed, sequence)
    second = 64 + digest[0] % 64
    third = digest[1]
    return f"10.{second}.{third}.1"


def deterministic_documentation_mac(
    profile: str,
    seed: int,
    sequence: int,
    *,
    role: str,
) -> str:
    digest = deterministic_bytes(f"arp-mac-{role}", profile, seed, sequence)
    # RFC 7042 reserves 00:00:5e:00:53:00-ff for documentation unicast MACs.
    return f"00:00:5e:00:53:{digest[0]:02x}"


def deterministic_documentation_ipv6(digest: bytes) -> str:
    """Return a deterministic IPv6 address in the ``2001:db8::/32`` block.

    The four trailing hextets are derived from the case digest so the answer is
    stable per (case, profile, seed, sequence) while staying inside the RFC 3849
    documentation prefix.
    """

    group_e = int.from_bytes(digest[4:6], "big")
    group_f = int.from_bytes(digest[6:8], "big")
    group_g = int.from_bytes(digest[8:10], "big")
    host = 1 + int.from_bytes(digest[10:12], "big") % 0xFFFE
    return f"2001:db8:{group_e:x}:{group_f:x}:0:{group_g:x}:0:{host:x}"


def dns_label(value: str) -> str:
    label = "".join(char.lower() if char.isalnum() else "-" for char in value)
    label = "-".join(part for part in label.split("-") if part)
    return (label or "profile")[:32].strip("-") or "profile"
