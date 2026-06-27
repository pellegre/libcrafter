"""Scapy-stage DHCPv6 registry placeholder.

The DHCPv6 generator and specs are registered before the byte materializer. This
plugin keeps registry coverage explicit while encode/decode support remains
declared partial in the specs.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject
from .base import ScapyProtocol, register


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Sequence[str],
    index: int,
    scapy_all: Any,
) -> Any:
    raise NotImplementedError("DHCPv6 Scapy materialization is registered in a later step")


register(
    ScapyProtocol(
        layer="dhcpv6",
        scapy_class="DHCP6",
        supported_fields=frozenset(),
        build=_build,
        layer_aliases=(("DHCP6", "dhcpv6"),),
    )
)
