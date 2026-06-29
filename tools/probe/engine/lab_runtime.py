"""Probe-report helpers for lab appliance runtime metadata."""

from __future__ import annotations

from collections.abc import Mapping

from tools.lab.engine.model import LabApplianceRuntime, LabSession

from .model import JSONObject, json_object


def probe_appliance_runtime_metadata(
    runtime: LabApplianceRuntime | Mapping[str, object] | None,
) -> JSONObject | None:
    """Return probe-report JSON for an appliance runtime, when present."""

    if runtime is None:
        return None
    if isinstance(runtime, LabApplianceRuntime):
        return runtime.to_dict()
    if isinstance(runtime, Mapping):
        return json_object(runtime, "appliance_runtime")
    raise TypeError("appliance runtime metadata must be an object")


def probe_endpoint_appliance_runtimes(session: LabSession) -> JSONObject:
    """Return endpoint appliance runtimes keyed by probe role."""

    runtimes: JSONObject = {}
    for endpoint in session.endpoints:
        runtime = probe_appliance_runtime_metadata(endpoint.appliance_runtime)
        if runtime is not None:
            runtimes[endpoint.role] = runtime
    return runtimes


def probe_command_record_with_appliance_runtime(
    record: Mapping[str, object],
    *,
    endpoint_appliance_runtimes: Mapping[str, object],
) -> JSONObject:
    """Attach endpoint appliance runtime metadata to role-scoped commands."""

    output = json_object(record, "command_record")
    role = output.get("role")
    if not isinstance(role, str):
        return output
    runtime = probe_appliance_runtime_metadata(endpoint_appliance_runtimes.get(role))
    if runtime is None:
        return output

    metadata = output.get("metadata")
    command_metadata: JSONObject = (
        json_object(metadata, "command_record.metadata")
        if isinstance(metadata, Mapping)
        else {}
    )
    command_metadata.setdefault("appliance_runtime", runtime)
    command_metadata.setdefault("endpoint_appliance_runtime", runtime)
    output["metadata"] = command_metadata
    return output
