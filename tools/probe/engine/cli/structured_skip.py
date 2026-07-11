"""Redacted structured-skip artifact output for probe plans."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from ..model import JSONValue, JSONObject, ProbeRunRequest, ProbeSkip, json_object, write_json


def write_structured_skip_artifact(
    *,
    report_path: Path,
    request: ProbeRunRequest,
    probe_plan: Mapping[str, JSONValue],
    skip: ProbeSkip,
) -> Path | None:
    """Write an explicitly requested, redacted per-case skip artifact."""

    raw_contract = probe_plan.get("structured_skip_artifact")
    if not isinstance(raw_contract, Mapping):
        return None
    contract = json_object(raw_contract, "probe_plan.structured_skip_artifact")
    relative_path = contract.get("relative_path")
    if not isinstance(relative_path, str) or not relative_path:
        return None
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("structured skip artifact path must stay under the report root")

    reference: JSONObject = {}
    raw_interop = probe_plan.get("reference_interoperability")
    if isinstance(raw_interop, Mapping):
        interop = json_object(raw_interop, "probe_plan.reference_interoperability")
        raw_reference = interop.get("reference")
        if isinstance(raw_reference, Mapping):
            reference = json_object(raw_reference, "reference_interoperability.reference")
        alpn = interop.get("alpn")
        cases = interop.get("cases")
    else:
        alpn = None
        cases = None

    missing = skip.metadata.get("missing_capabilities", [])
    if not isinstance(missing, Sequence) or isinstance(missing, (str, bytes, bytearray)):
        missing = []
    artifact: JSONObject = {
        "schema_version": int(contract.get("schema_version", 1)),
        "status": "skipped",
        "case": skip.case,
        "sequence": skip.sequence,
        "reason": skip.reason,
        "provider": request.provider,
        "dry_run": request.dry_run,
        "confirm_live_run": request.confirm_live_run,
        "missing_capabilities": [str(item) for item in missing],
        "reference": reference,
        "alpn": alpn if isinstance(alpn, str) else None,
        "interop_cases": cases if isinstance(cases, list) else [],
        "redacted": True,
        "contains_credentials": False,
        "contains_endpoint_identity": False,
        "developer_host_fallback": False,
        "teardown_status": "not_started",
    }
    output_path = report_path.parent / relative
    write_json(output_path, artifact)
    return output_path
