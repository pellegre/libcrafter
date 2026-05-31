"""Probe result conversion from stimulus endpoint JSON.

The live stimulus endpoint returns its observations as a JSON object. This
module owns the conversion of that JSON into typed :class:`ProbeResult` and
:class:`ObservedResponse` values, the synthesis of failed results when the
endpoint produced nothing usable, and the per-reason failure tally the live
report metadata advertises.

Keeping result conversion here lets the live orchestration module focus on lab
session lifecycle and wire transport while result shaping stays inspectable and
independently testable.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .capabilities import primary_endpoint_role
from .model import (
    JSONObject,
    ObservedResponse,
    ProbeCase,
    ProbeResult,
    json_object,
)


STATUS_FAILED = "failed"
FAILURE_DECODE_FAILED = "decode_failed"


def probe_results_from_endpoint_response(
    response: JSONObject,
) -> tuple[list[ProbeResult], list[ObservedResponse]]:
    """Convert a stimulus endpoint JSON response into typed probe results."""

    results: list[ProbeResult] = []
    observed_responses: list[ObservedResponse] = []
    raw_results = response.get("results", [])
    if not isinstance(raw_results, Sequence) or isinstance(
        raw_results, (str, bytes, bytearray)
    ):
        raw_results = []

    for raw_result in raw_results:
        if not isinstance(raw_result, Mapping):
            continue
        result_obj = json_object(raw_result, "endpoint.results[]")
        observed = None
        raw_observed = result_obj.get("observed_response")
        if isinstance(raw_observed, Mapping):
            observed_obj = json_object(raw_observed, "endpoint.observed_response")
            observed = ObservedResponse(
                case=str(observed_obj.get("case", result_obj.get("case", ""))),
                sequence=int(observed_obj.get("sequence", result_obj.get("sequence", 0))),
                endpoint_role=str(observed_obj.get("endpoint_role", "stimulus")),
                observed=bool(observed_obj.get("observed")),
                response_type=_optional_string(observed_obj.get("response_type")),
                raw_hex=_optional_string(observed_obj.get("raw_hex")),
                decoded=json_object(observed_obj.get("decoded", {}), "observed.decoded"),
                metadata=json_object(observed_obj.get("metadata", {}), "observed.metadata"),
            )
            observed_responses.append(observed)
        results.append(
            ProbeResult(
                case=str(result_obj.get("case", "")),
                sequence=int(result_obj.get("sequence", 0)),
                status=str(result_obj.get("status", STATUS_FAILED)),
                endpoint_role=str(result_obj.get("endpoint_role", "stimulus")),
                passed=(
                    bool(result_obj["passed"])
                    if isinstance(result_obj.get("passed"), bool)
                    else None
                ),
                observed_response=observed,
                metadata=json_object(result_obj.get("metadata", {}), "result.metadata"),
            )
        )
    return results, observed_responses


def failed_live_probe_results(
    *,
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    reason: str,
    errors: Sequence[str],
) -> tuple[list[ProbeResult], list[ObservedResponse]]:
    """Build failed results for executable cases the endpoint could not serve."""

    results: list[ProbeResult] = []
    for index, case in enumerate(planned_cases):
        plan = probe_plans[index] if index < len(probe_plans) else {}
        sequence = (
            int(plan["sequence"])
            if isinstance(plan.get("sequence"), int)
            else index
        )
        results.append(
            ProbeResult(
                case=case.name,
                sequence=sequence,
                status=STATUS_FAILED,
                endpoint_role=primary_endpoint_role(case),
                passed=False,
                metadata={
                    "failure_reason": reason,
                    "errors": list(errors),
                    "probe_plan": plan,
                },
            )
        )
    return results, []


def failed_counts_by_reason(results: Sequence[ProbeResult]) -> JSONObject:
    """Tally failed results by their recorded ``failure_reason``."""

    counts: dict[str, int] = {}
    for result in results:
        if result.passed is not False:
            continue
        reason = result.metadata.get("failure_reason")
        if isinstance(reason, str) and reason:
            counts[reason] = counts.get(reason, 0) + 1
    return counts


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


__all__ = [
    "FAILURE_DECODE_FAILED",
    "STATUS_FAILED",
    "failed_counts_by_reason",
    "failed_live_probe_results",
    "probe_results_from_endpoint_response",
]
