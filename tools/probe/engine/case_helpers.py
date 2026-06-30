"""Protocol-agnostic case-construction and selection primitives.

This module holds the shared, protocol-agnostic pieces that build behavioral
:class:`ProbeCase` instances and normalize requested case-name filters. They are
extracted out of :mod:`tools.probe.engine.cases` so per-protocol plugins can
build their cases and declare profile membership without importing the
``cases.py`` aggregator (which would create an import cycle).

Per-protocol case tuples, the ``PROBE_CASES`` aggregation, ``PROBE_CASE_BY_NAME``
index, and the profile tables stay in :mod:`tools.probe.engine.cases`; the
helpers that depend on that catalog (case lookup, profile selection) stay there
too. Only the catalog-independent primitives live here.
"""

from __future__ import annotations

from collections.abc import Sequence

from .model import JSONObject, ProbeCase


_CASE_NAME_ALIASES = {"mdns-ipv4-browse": "mdns-ipv4-multicast-browse"}


def canonical_case_name(name: str) -> str:
    """Return the canonical probe case name for a supported shorthand."""

    return _CASE_NAME_ALIASES.get(name, name)


def _behavior_case(
    *,
    name: str,
    description: str,
    stimulus: str,
    expected_response: str,
    required_capabilities: list[str],
    protocol: str,
    metadata: JSONObject | None = None,
    endpoint_roles: Sequence[str] | None = None,
) -> ProbeCase:
    case_metadata: JSONObject = {
        "protocol": protocol,
        "suite": "behavior",
    }
    if metadata:
        case_metadata.update(metadata)
    return ProbeCase(
        name=name,
        description=description,
        stimulus=stimulus,
        expected_response=expected_response,
        required_capabilities=list(required_capabilities),
        endpoint_roles=list(endpoint_roles or ("stimulus", "target")),
        metadata=case_metadata,
    )


def case_name_filters(values: Sequence[str] | None) -> list[str]:
    """Normalize raw ``--case`` values into a de-duplicated, ordered list.

    Each value may be comma-separated; surrounding whitespace is stripped and
    empty fragments are dropped. Insertion order is preserved while removing
    duplicates so the resulting selection is deterministic.
    """

    if not values:
        return []
    names: list[str] = []
    for value in values:
        for raw_name in value.split(","):
            name = raw_name.strip()
            if name:
                names.append(name)
    return list(dict.fromkeys(names))
