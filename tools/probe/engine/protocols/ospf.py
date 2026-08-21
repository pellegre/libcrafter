"""Deterministic OSPF probe cases and packet plans."""

from __future__ import annotations
from ..case_helpers import _behavior_case
from ..model import ProbeCase
from .base import ProtocolPlugin, register

_OSPF_CAPABILITIES = ["ospf_neighbor_peer"]
BEHAVIOR_OSPF_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="ospf-hello-exchange",
        description="Send an OSPFv2 Hello (RFC 2328 §A.3.2) to the controlled neighbor and validate the peer's Hello or Database Description reply that forms the adjacency.",
        stimulus="ospf_hello",
        expected_response="ospf_hello_or_database_description",
        required_capabilities=_OSPF_CAPABILITIES,
        protocol="ospf",
        metadata={"layer": "network", "stateful": True},
    ),
)
OSPF_SMOKE_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="ospf-dd-exchange",
        description="Send an OSPFv2 Database Description packet (RFC 2328 §A.3.3) to the controlled neighbor and validate the peer's Database Description reply that advances database synchronization.",
        stimulus="ospf_database_description",
        expected_response="ospf_database_description",
        required_capabilities=_OSPF_CAPABILITIES,
        protocol="ospf",
        metadata={
            "layer": "network",
            "stateful": True,
            "planned_only": True,
            "notes": "Needs the peer to advance to the Database Description exchange state; the plan declares that precondition for external execution tooling.",
        },
    ),
)
_OSPF_CASES: tuple[ProbeCase, ...] = (*BEHAVIOR_OSPF_CASES, *OSPF_SMOKE_CASES)
_OSPF_STIMULUS_ENDPOINT_CASES: frozenset[str] = frozenset({"ospf-hello-exchange"})
register(
    ProtocolPlugin(
        name="ospf",
        cases=_OSPF_CASES,
        plan_builders={},
        planned_only_cases=frozenset(),
        profile_counts={},
        stimulus_endpoint_cases=_OSPF_STIMULUS_ENDPOINT_CASES,
        failure_reasons=None,
    )
)
