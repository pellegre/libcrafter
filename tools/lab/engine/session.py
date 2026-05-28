"""Lab session local state management."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from . import wire_client
from .model import (
    JSONObject,
    LabCommandPlan,
    LabRequest,
    LabSession,
    json_object,
    read_json,
    write_json,
)
from .paths import (
    MANIFEST_FILENAME,
    SESSIONS_DIRNAME,
    LabConfig,
    LabSessionLayout,
    default_config,
    session_layout,
    session_manifest_path,
)


@dataclass(frozen=True, slots=True)
class LabCleanupResult:
    """Result of a best-effort lab endpoint cleanup attempt."""

    cleanup_state: JSONObject
    command_records: list[LabCommandPlan]


def create_session(
    adapter: object,
    request: LabRequest,
    *,
    client: wire_client.WireClient | None = None,
    config: LabConfig | None = None,
) -> LabSession:
    """Create or plan a lab session through an adapter and persist its manifest."""

    if not isinstance(request, LabRequest):
        raise TypeError("request must be a LabRequest")
    plan_session = getattr(adapter, "plan_session", None)
    if not callable(plan_session):
        raise TypeError("adapter must provide plan_session")
    wire = client or wire_client.WireClient()
    created_endpoint_ids: list[str] = []
    tracked_wire = _CreateTrackingWireClient(wire, created_endpoint_ids)
    try:
        session = plan_session(request, client=tracked_wire)
    except Exception as exc:
        if not request.dry_run:
            _cleanup_after_create_failure(
                exc,
                created_endpoint_ids=created_endpoint_ids,
                client=tracked_wire,
            )
        raise
    if not isinstance(session, LabSession):
        raise TypeError("adapter plan_session must return a LabSession")
    write_session_manifest(session, config)
    return session


def ensure_session_dirs(session_id: str, config: LabConfig | None = None) -> LabSessionLayout:
    """Create the local state and artifact directories for a session."""

    layout = session_layout(session_id, config)
    layout.state_dir.mkdir(parents=True, exist_ok=True)
    layout.command_artifact_root.mkdir(parents=True, exist_ok=True)
    return layout


def write_session_manifest(
    session: LabSession,
    config: LabConfig | None = None,
) -> Path:
    """Persist one lab session manifest and return its absolute JSON path."""

    if not isinstance(session, LabSession):
        raise TypeError("session must be a LabSession")
    layout = ensure_session_dirs(session.session_id, config)
    write_json(layout.manifest_path, session)
    return layout.manifest_path


def read_session_manifest(
    session_id: str,
    config: LabConfig | None = None,
) -> LabSession:
    """Read one lab session manifest from local state."""

    path = session_manifest_path(session_id, config)
    value = read_json(path)
    if not isinstance(value, Mapping):
        raise ValueError(f"lab session manifest must be a JSON object: {path}")
    return LabSession.from_dict(value)


def list_session_manifests(config: LabConfig | None = None) -> list[LabSession]:
    """Return all stored lab session manifests sorted by session ID."""

    manifests: dict[str, LabSession] = {}
    for path in _manifest_paths(config):
        value = read_json(path)
        if not isinstance(value, Mapping):
            raise ValueError(f"lab session manifest must be a JSON object: {path}")
        session = LabSession.from_dict(value)
        manifests.setdefault(session.session_id, session)
    return [manifests[session_id] for session_id in sorted(manifests)]


def destroy_session(
    session_id: str,
    *,
    client: wire_client.WireClient | None = None,
    config: LabConfig | None = None,
) -> LabSession:
    """Collect artifacts, destroy tracked endpoints, and persist cleanup state."""

    current = read_session_manifest(session_id, config)
    updated = cleanup_lab_session(current, client=client)
    write_session_manifest(updated, config)
    return updated


def cleanup_lab_session(
    session: LabSession,
    *,
    client: object | None = None,
) -> LabSession:
    """Return a session updated with best-effort artifact collection and teardown."""

    if not isinstance(session, LabSession):
        raise TypeError("session must be a LabSession")
    result = cleanup_created_endpoints(
        _tracked_endpoint_ids(session),
        client=client,
        remote_artifact_root=session.remote_artifact_root,
        endpoint_roles=_endpoint_role_map(session),
        command_records=session.command_records,
    )
    return replace(
        session,
        command_records=result.command_records,
        cleanup_state=result.cleanup_state,
    )


def cleanup_created_endpoints(
    endpoint_ids: Sequence[str],
    *,
    client: object | None = None,
    remote_artifact_root: str | None = None,
    endpoint_roles: Mapping[str, str] | None = None,
    command_records: Sequence[LabCommandPlan] = (),
) -> LabCleanupResult:
    """Collect artifacts and destroy created endpoints without raising on failures."""

    tracked_endpoint_ids = _endpoint_id_list(endpoint_ids)
    role_map = dict(endpoint_roles or {})
    wire = client or wire_client.WireClient()
    updated_command_records = list(command_records)
    artifact_attempts: list[JSONObject] = []
    teardown_attempts: list[JSONObject] = []
    errors: list[str] = []

    for endpoint_id in tracked_endpoint_ids:
        role = role_map.get(endpoint_id)
        try:
            response = wire.collect_artifacts(endpoint_id, remote_artifact_root)
        except Exception as exc:  # pragma: no cover - concrete clients vary.
            artifact_attempts.append(_exception_attempt(endpoint_id, role, "collect_artifacts", exc))
            errors.append(f"artifact collection failed for {endpoint_id}: {exc}")
            continue
        artifact_attempts.append(
            _response_attempt(endpoint_id, role, "collect_artifacts", response)
        )
        updated_command_records.append(
            _response_command_plan(
                response,
                purpose=f"collect artifacts for {endpoint_id}",
                role=role,
                fallback_operation="wire.collect_artifacts",
                fallback_argv=["tools/wire/run", "collect-artifacts", endpoint_id],
                live_mutation=False,
            )
        )
        if not bool(getattr(response, "ok", False)):
            errors.append(_response_error(endpoint_id, "artifact collection", response))

    for endpoint_id in reversed(tracked_endpoint_ids):
        role = role_map.get(endpoint_id)
        try:
            response = wire.destroy(endpoint_id)
        except Exception as exc:  # pragma: no cover - concrete clients vary.
            teardown_attempts.append(_exception_attempt(endpoint_id, role, "destroy", exc))
            errors.append(f"endpoint teardown failed for {endpoint_id}: {exc}")
            continue
        teardown_attempts.append(_response_attempt(endpoint_id, role, "destroy", response))
        updated_command_records.append(
            _response_command_plan(
                response,
                purpose=f"destroy endpoint {endpoint_id}",
                role=role,
                fallback_operation="wire.destroy",
                fallback_argv=["tools/wire/run", "destroy-endpoint", endpoint_id, "--json"],
                live_mutation=True,
            )
        )
        if not bool(getattr(response, "ok", False)):
            errors.append(_response_error(endpoint_id, "endpoint teardown", response))

    cleanup_state = _cleanup_state(
        endpoint_ids=tracked_endpoint_ids,
        remote_artifact_root=remote_artifact_root,
        artifact_attempts=artifact_attempts,
        teardown_attempts=teardown_attempts,
        errors=errors,
    )
    return LabCleanupResult(
        cleanup_state=cleanup_state,
        command_records=updated_command_records,
    )


def _manifest_paths(config: LabConfig | None = None) -> list[Path]:
    cfg = default_config() if config is None else config
    sessions_root = cfg.state_root / SESSIONS_DIRNAME
    if not sessions_root.exists():
        return []
    return sorted(sessions_root.glob(f"*/{MANIFEST_FILENAME}"))


def _tracked_endpoint_ids(session: LabSession) -> list[str]:
    ids = list(session.created_endpoint_ids)
    if not ids and not session.dry_run:
        ids = [endpoint.endpoint_id for endpoint in session.endpoints]
    return _dedupe(ids)


def _endpoint_role_map(session: LabSession) -> dict[str, str]:
    return {endpoint.endpoint_id: endpoint.role for endpoint in session.endpoints}


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _endpoint_id_list(endpoint_ids: Sequence[str]) -> list[str]:
    if isinstance(endpoint_ids, (str, bytes, bytearray)):
        raise TypeError("endpoint_ids must be a sequence of strings")
    output: list[str] = []
    for endpoint_id in endpoint_ids:
        if not isinstance(endpoint_id, str) or endpoint_id == "":
            raise ValueError("endpoint_ids must contain non-empty strings")
        output.append(endpoint_id)
    return _dedupe(output)


def _cleanup_state(
    *,
    endpoint_ids: list[str],
    remote_artifact_root: str | None,
    artifact_attempts: list[JSONObject],
    teardown_attempts: list[JSONObject],
    errors: list[str],
) -> JSONObject:
    if not endpoint_ids:
        status = "no_endpoints"
    elif errors:
        status = "failed"
    else:
        status = "completed"
    return json_object(
        {
            "status": status,
            "endpoint_ids": endpoint_ids,
            "destroy_endpoint_ids": list(reversed(endpoint_ids)),
            "remote_artifact_root": remote_artifact_root,
            "artifact_collection_attempted": bool(endpoint_ids),
            "teardown_attempted": bool(endpoint_ids),
            "artifact_collection": artifact_attempts,
            "teardown": teardown_attempts,
            "errors": errors,
        },
        "session.cleanup_state",
    )


class _CreateTrackingWireClient:
    def __init__(self, client: object, created_endpoint_ids: list[str]) -> None:
        self._client = client
        self._created_endpoint_ids = created_endpoint_ids
        self.command_records: list[LabCommandPlan] = []

    def __getattr__(self, name: str) -> object:
        return getattr(self._client, name)

    def create(self, *args: object, **kwargs: object) -> object:
        response = self._client.create(*args, **kwargs)
        dry_run = bool(kwargs.get("dry_run", getattr(response, "dry_run", False)))
        role = kwargs.get("role") if isinstance(kwargs.get("role"), str) else None
        endpoint_id = _response_endpoint_id(response)
        self.command_records.append(
            _response_command_plan(
                response,
                purpose=f"create endpoint {endpoint_id or role or 'unknown'}",
                role=role,
                fallback_operation="wire.create",
                fallback_argv=_create_fallback_argv(kwargs),
                live_mutation=not dry_run,
            )
        )
        if not dry_run and bool(getattr(response, "ok", True)):
            if endpoint_id is not None:
                self._created_endpoint_ids.append(endpoint_id)
        return response


def _cleanup_after_create_failure(
    exc: Exception,
    *,
    created_endpoint_ids: list[str],
    client: object,
) -> None:
    try:
        partial_session = _partial_session_from_exception(exc)
        if partial_session is not None:
            cleaned = cleanup_lab_session(partial_session, client=client)
            result = LabCleanupResult(
                cleanup_state=cleaned.cleanup_state,
                command_records=cleaned.command_records,
            )
            _attach_cleanup_result(exc, result, session=cleaned)
            return
        result = cleanup_created_endpoints(
            created_endpoint_ids,
            client=client,
            command_records=_tracked_command_records(client),
        )
        _attach_cleanup_result(exc, result, session=None)
    except Exception as cleanup_exc:  # pragma: no cover - defensive fallback.
        try:
            setattr(exc, "lab_cleanup_error", str(cleanup_exc))
        except Exception:
            pass


def _partial_session_from_exception(exc: Exception) -> LabSession | None:
    for name in ("lab_session", "partial_session", "session"):
        value = getattr(exc, name, None)
        if isinstance(value, LabSession):
            return value
    return None


def _attach_cleanup_result(
    exc: Exception,
    result: LabCleanupResult,
    *,
    session: LabSession | None,
) -> None:
    setattr(exc, "lab_cleanup_result", result)
    setattr(exc, "lab_cleanup_state", result.cleanup_state)
    setattr(exc, "lab_cleanup_command_records", result.command_records)
    if session is not None:
        setattr(exc, "lab_cleanup_session", session)


def _tracked_command_records(client: object) -> list[LabCommandPlan]:
    command_records = getattr(client, "command_records", None)
    if not isinstance(command_records, Sequence):
        return []
    return [record for record in command_records if isinstance(record, LabCommandPlan)]


def _create_fallback_argv(kwargs: Mapping[str, object]) -> list[str]:
    argv = ["tools/wire/run", "create-endpoint"]
    _extend_flag(argv, "--provider", kwargs.get("provider"))
    _extend_flag(argv, "--exposure", kwargs.get("exposure"))
    _extend_flag(argv, "--role", kwargs.get("role"))
    _extend_flag(argv, "--private-group", kwargs.get("private_group"))
    _extend_flag(argv, "--private-ip", kwargs.get("private_ip"))
    if kwargs.get("dry_run") is True:
        argv.append("--dry-run")
    if kwargs.get("write_manifest") is True:
        argv.append("--write-manifest")
    if kwargs.get("confirm_live_run") is True:
        argv.append("--confirm-live-run")
    argv.append("--json")
    return argv


def _extend_flag(argv: list[str], flag: str, value: object) -> None:
    if isinstance(value, str) and value:
        argv.extend([flag, value])


def _response_endpoint_id(response: object) -> str | None:
    manifest = getattr(response, "manifest", None)
    endpoint_id = getattr(manifest, "endpoint_id", None)
    if isinstance(endpoint_id, str) and endpoint_id:
        return endpoint_id
    endpoint_id = getattr(response, "endpoint_id", None)
    if isinstance(endpoint_id, str) and endpoint_id:
        return endpoint_id
    json_data = getattr(response, "json_data", None)
    if isinstance(json_data, Mapping):
        endpoint_id = json_data.get("endpoint_id")
        if isinstance(endpoint_id, str) and endpoint_id:
            return endpoint_id
    return None


def _response_attempt(
    endpoint_id: str,
    role: str | None,
    operation: str,
    response: object,
) -> JSONObject:
    ok = bool(getattr(response, "ok", False))
    exit_code = getattr(response, "exit_code", 0 if ok else 1)
    error = _optional_response_error(response)
    return json_object(
        {
            "endpoint_id": endpoint_id,
            "role": role,
            "operation": operation,
            "ok": ok,
            "exit_code": exit_code,
            "error": error,
        },
        "cleanup.attempt",
    )


def _exception_attempt(
    endpoint_id: str,
    role: str | None,
    operation: str,
    exc: Exception,
) -> JSONObject:
    return json_object(
        {
            "endpoint_id": endpoint_id,
            "role": role,
            "operation": operation,
            "ok": False,
            "exit_code": 1,
            "error": str(exc),
        },
        "cleanup.attempt",
    )


def _response_command_plan(
    response: object,
    *,
    purpose: str,
    role: str | None,
    fallback_operation: str,
    fallback_argv: list[str],
    live_mutation: bool,
) -> LabCommandPlan:
    command_plan = getattr(response, "command_plan", None)
    if callable(command_plan):
        plan = command_plan(purpose=purpose, role=role)
        if isinstance(plan, LabCommandPlan):
            return plan
        if isinstance(plan, Mapping):
            return LabCommandPlan.from_dict(plan)
    return LabCommandPlan(
        purpose=purpose,
        role=role,
        argv=fallback_argv,
        operation=fallback_operation,
        dry_run=False,
        live_mutation=live_mutation,
        metadata={
            "ok": bool(getattr(response, "ok", False)),
            "exit_code": getattr(response, "exit_code", 0),
            "error": _optional_response_error(response),
        },
    )


def _response_error(endpoint_id: str, operation: str, response: object) -> str:
    detail = _optional_response_error(response)
    if detail:
        return f"{operation} failed for {endpoint_id}: {detail}"
    return f"{operation} failed for {endpoint_id}: exit {getattr(response, 'exit_code', 1)}"


def _optional_response_error(response: object) -> str | None:
    result = getattr(response, "result", None)
    error = getattr(result, "error", None)
    if isinstance(error, str) and error:
        return error
    record = getattr(response, "record", None)
    error = getattr(record, "error", None)
    if isinstance(error, str) and error:
        return error
    json_data = getattr(response, "json_data", None)
    if isinstance(json_data, Mapping):
        error = json_data.get("error")
        if isinstance(error, str) and error:
            return error
    return None
