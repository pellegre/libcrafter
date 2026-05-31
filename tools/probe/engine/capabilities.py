"""Provider capability policy and stable probe skip reasons.

Behavioral DNS and UDP cases mostly need IPv4 unicast plus controlled services,
while DHCP and ARP cases need link-layer send/capture, broadcast, privileged
ports, and provider MAC knowledge. This module is the single owner of:

- the stable skip-reason strings,
- the per-case missing-capability check,
- the mapping from a missing capability to a stable skip reason,
- the provider-capability derivation wrapper shared by dry-run reports, live
  reports, and the provider matrix,
- capability skip result/skip construction for one case and for a whole
  planned run.

Keeping this policy in one place lets dry-run reports, live reports, and the
provider matrix agree on which cases are unsupported and why.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .lab import probe_capabilities_for_provider
from .model import (
    JSONObject,
    JSONValue,
    ProbeCase,
    ProbeResult,
    ProbeRunRequest,
    ProbeSkip,
)


SKIP_CAPABILITY_UNAVAILABLE = "provider_capability_unavailable"
SKIP_CONFIRMATION_REQUIRED = "confirm_live_run_required"
SKIP_REQUIRES_CONTROLLED_ROUTER = "requires_controlled_router"
SKIP_REQUIRES_LINK_LAYER = "requires_link_layer"
SKIP_REQUIRES_BROADCAST = "requires_broadcast"
SKIP_REQUIRES_PROVIDER_MAC = "requires_provider_mac"
SKIP_REQUIRES_PRIVILEGED_PORT = "requires_privileged_port"
SKIP_REQUIRES_CONTROLLED_SERVICE = "requires_controlled_service"


# Capabilities that imply a link-layer (Ethernet/ARP/broadcast) substrate. A
# case that needs any of these and is denied it skips with the stable
# link-layer reason so DHCP and ARP report a single shared cause.
_LINK_LAYER_CAPABILITIES = frozenset(
    {
        "arp_resolution",
        "link_layer_arp",
        "link_layer_send",
        "link_layer_capture",
    }
)

# Reason selected for a single missing capability, independent of the case.
# More specific case-level overrides live in
# :func:`skip_reason_for_missing_capability`.
_CAPABILITY_SKIP_REASONS = {
    "controlled_router": SKIP_REQUIRES_CONTROLLED_ROUTER,
    "arp_resolution": SKIP_REQUIRES_LINK_LAYER,
    "link_layer_arp": SKIP_REQUIRES_LINK_LAYER,
    "link_layer_send": SKIP_REQUIRES_LINK_LAYER,
    "link_layer_capture": SKIP_REQUIRES_LINK_LAYER,
    "broadcast": SKIP_REQUIRES_BROADCAST,
    "provider_mac": SKIP_REQUIRES_PROVIDER_MAC,
    "privileged_udp_port": SKIP_REQUIRES_PRIVILEGED_PORT,
    "controlled_services": SKIP_REQUIRES_CONTROLLED_SERVICE,
}


def probe_capabilities_for_request(
    request: ProbeRunRequest,
    *,
    dry_run: bool,
) -> JSONObject:
    """Return probe capabilities derived from the request's provider."""

    return probe_capabilities_for_provider(request.provider, dry_run=dry_run)


def missing_capabilities(
    case: ProbeCase,
    provider_capabilities: Mapping[str, JSONValue],
) -> list[str]:
    """Return the case's required capabilities the provider does not grant."""

    missing: list[str] = []
    for capability in case.required_capabilities:
        if provider_capabilities.get(capability) is not True:
            missing.append(capability)
    return missing


def skip_reason_for_missing_capability(case: ProbeCase, capability: str) -> str:
    """Return the stable skip reason for a missing capability on a case."""

    if capability == "controlled_router":
        return SKIP_REQUIRES_CONTROLLED_ROUTER
    if capability in _LINK_LAYER_CAPABILITIES:
        return SKIP_REQUIRES_LINK_LAYER
    return _CAPABILITY_SKIP_REASONS.get(capability, SKIP_CAPABILITY_UNAVAILABLE)


def primary_endpoint_role(case: ProbeCase) -> str:
    """Return the case's primary endpoint role, defaulting to ``stimulus``."""

    return case.endpoint_roles[0] if case.endpoint_roles else "stimulus"


def skip_class_for_reason(reason: str) -> str:
    """Classify a stable skip reason as a capability or confirmation skip.

    A skip is *only* a skip when the provider does not declare a required
    capability, or when a live run was not explicitly confirmed. Neither class
    is allowed to absorb a real failure: a case that the provider *can* support
    but that produces a wrong packet, an undecodable response, or a failed
    validation must surface as ``failed`` so libcrafter or the probe
    infrastructure gets fixed. Do not invent a new skip reason to hide such a
    regression.
    """

    if reason == SKIP_CONFIRMATION_REQUIRED:
        return "skipped_by_confirmation"
    return "skipped_by_capability"


def skip_class_counts(skips: Sequence[ProbeSkip]) -> dict[str, int]:
    """Tally skips into ``skipped_by_capability`` / ``skipped_by_confirmation``.

    Every skip lands in exactly one bucket so a report's skip total always
    reconciles with the per-class counts. Failures are deliberately *not*
    counted here; they are tracked separately so a provider skip can never be
    confused with a libcrafter/probe defect that must be fixed.
    """

    counts = {"skipped_by_capability": 0, "skipped_by_confirmation": 0}
    for skip in skips:
        counts[skip_class_for_reason(skip.reason)] += 1
    return counts


def capability_skip_result(
    *,
    request: ProbeRunRequest,
    case: ProbeCase,
    sequence: int,
    probe_plan: JSONObject,
    dry_run: bool,
    provider_capabilities: Mapping[str, JSONValue],
) -> tuple[ProbeSkip, ProbeResult] | None:
    """Return the (skip, result) pair for a case missing a capability.

    Returns ``None`` when the provider grants every required capability so the
    caller can plan or execute the case.
    """

    missing = missing_capabilities(case, provider_capabilities)
    if not missing:
        return None

    skip = ProbeSkip(
        case=case.name,
        sequence=sequence,
        reason=skip_reason_for_missing_capability(case, missing[0]),
        capability=missing[0],
        metadata={
            "missing_capabilities": list(missing),
            "provider": request.provider,
            "dry_run": dry_run,
            "probe_plan": probe_plan,
        },
    )
    result = ProbeResult(
        case=case.name,
        sequence=sequence,
        status="skipped",
        endpoint_role=primary_endpoint_role(case),
        passed=None,
        skip=skip,
        metadata={"dry_run": dry_run, "probe_plan": probe_plan},
    )
    return skip, result


def capability_skip_state(
    *,
    request: ProbeRunRequest,
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    dry_run: bool,
    provider_capabilities: Mapping[str, JSONValue],
) -> tuple[list[ProbeResult], list[ProbeSkip], dict[str, int], set[int]]:
    """Return capability skips for an ordered planned run.

    Yields the skipped results, the skips, a per-reason skip count, and the set
    of skipped sequence numbers so the live path can avoid executing them.
    """

    probe_plans_by_sequence = {
        int(plan["sequence"]): plan
        for plan in probe_plans
        if isinstance(plan.get("sequence"), int)
    }
    results: list[ProbeResult] = []
    skips: list[ProbeSkip] = []
    skip_counts: dict[str, int] = {}
    skipped_sequences: set[int] = set()
    for sequence, case in enumerate(planned_cases):
        capability_skip = capability_skip_result(
            request=request,
            case=case,
            sequence=sequence,
            probe_plan=probe_plans_by_sequence.get(sequence, {}),
            dry_run=dry_run,
            provider_capabilities=provider_capabilities,
        )
        if capability_skip is None:
            continue
        skip, result = capability_skip
        skips.append(skip)
        results.append(result)
        skipped_sequences.add(sequence)
        skip_counts[skip.reason] = skip_counts.get(skip.reason, 0) + 1
    return results, skips, skip_counts, skipped_sequences


__all__ = [
    "SKIP_CAPABILITY_UNAVAILABLE",
    "SKIP_CONFIRMATION_REQUIRED",
    "SKIP_REQUIRES_BROADCAST",
    "SKIP_REQUIRES_CONTROLLED_ROUTER",
    "SKIP_REQUIRES_CONTROLLED_SERVICE",
    "SKIP_REQUIRES_LINK_LAYER",
    "SKIP_REQUIRES_PRIVILEGED_PORT",
    "SKIP_REQUIRES_PROVIDER_MAC",
    "capability_skip_result",
    "capability_skip_state",
    "missing_capabilities",
    "primary_endpoint_role",
    "probe_capabilities_for_request",
    "skip_class_counts",
    "skip_class_for_reason",
    "skip_reason_for_missing_capability",
]
