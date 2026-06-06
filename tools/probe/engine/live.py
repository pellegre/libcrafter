"""Lab-backed live probe execution and report assembly.

The live path creates a disposable lab session, archives and bootstraps the
repository on the endpoints, sets up controlled target services and stimulus
RST guards, uploads the stimulus request, runs the stimulus endpoint binary,
downloads its artifacts, tears everything down, and assembles a live probe
report. This module owns that orchestration plus the lab-wire transport helpers
(command recording, request upload, endpoint execution, artifact download) and
the JSON parsing used to read the endpoint response.

The CLI stays the argument-parsing and report-metadata glue. The cli-owned
plan-rewrite, report-metadata, and small JSON utility helpers are injected into
:func:`lab_endpoint_live_report` as callables so the live domain logic lives
here without an import cycle back into :mod:`cli`.
"""

from __future__ import annotations

import json
import os
import posixpath
import shlex
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from tools.lab.engine.model import LabSession
from tools.lab.engine import repo as lab_repo
from tools.lab.engine import session as lab_session_state
from tools.lab.engine import wire_client as lab_wire_client

from . import bootstrap as probe_bootstrap
from .capabilities import (
    capability_skip_state,
    probe_capabilities_for_request,
    skip_class_counts,
)
from .lab import (
    STIMULUS_ROLE,
    TARGET_ROLE,
    probe_address_context_from_lab_session,
    resolve_probe_lab_provider,
)
from .model import (
    JSONObject,
    JSONValue,
    ProbeCase,
    ProbeReport,
    ProbeResult,
    ProbeRunRequest,
    json_object,
    write_json,
)
from .report import REPO_ROOT
from . import results as probe_results
from . import target_services as probe_target_services
from .target_services import (
    cleanup_wire_probe_target as _cleanup_target_services_wire,
    prepare_wire_probe_target as _prepare_target_services_wire,
    target_service_setup_plan as _target_service_setup_plan,
)


STATUS_FAILED = "failed"
STATUS_PASSED = "passed"
FAILURE_DECODE_FAILED = "decode_failed"


# --------------------------------------------------------------------------- #
# Lab endpoint address resolution
# --------------------------------------------------------------------------- #


def lab_endpoint_id(endpoint: Mapping[str, JSONValue], *, role: str) -> str:
    endpoint_id = string_or(endpoint.get("endpoint_id"), "")
    if not endpoint_id:
        raise RuntimeError(f"lab session did not include {role} endpoint ID")
    return endpoint_id


def lab_endpoint_ipv4(endpoint: Mapping[str, JSONValue], *, role: str) -> str:
    ipv4 = string_or(endpoint.get("address"), string_or(endpoint.get("ipv4"), ""))
    if not ipv4:
        raise RuntimeError(f"lab session did not include {role} endpoint IPv4")
    return ipv4


def lab_endpoint_interface(endpoint: Mapping[str, JSONValue], *, role: str) -> str:
    interface = string_or(endpoint.get("interface"), "")
    if not interface:
        raise RuntimeError(f"lab session did not include {role} endpoint interface")
    return interface


def wire_command_failed(command: Mapping[str, JSONValue]) -> bool:
    exit_code = command.get("exit_code")
    if isinstance(exit_code, int):
        return exit_code != 0
    ok = command.get("ok")
    if isinstance(ok, bool):
        return not ok
    metadata = command.get("metadata")
    if isinstance(metadata, Mapping):
        metadata_exit = metadata.get("exit_code")
        if isinstance(metadata_exit, int):
            return metadata_exit != 0
        metadata_ok = metadata.get("ok")
        if isinstance(metadata_ok, bool):
            return not metadata_ok
    return False


def plans_with_arp_sender_protocol_candidates(
    probe_plans: Sequence[JSONObject],
) -> list[JSONObject]:
    """Make batched live ARP validation explicit about local sender IP choices.

    Full-suite target setup batches every ARP case onto one VM. Some cases add
    secondary IPv4 addresses to the target interface; Linux may use any matching
    local address as the ARP reply sender protocol while still replying to the
    planned querier SPA. The SPA-variation assertion is about the reply target
    protocol, so keep the possible sender protocol values explicit in its plan.
    """

    target_sender_protocols: list[str] = []
    for plan in probe_plans:
        service = json_mapping(
            plan.get("target_service", {}),
            "probe_plan.target_service",
        )
        for key in (
            "bind_ipv4",
            "target_protocol_addr",
            "alias_ipv4",
            "alt_sender_ipv4",
        ):
            value = string_or(service.get(key), "")
            if value:
                target_sender_protocols.append(value)
        destination = string_or(plan.get("destination_ipv4"), "")
        if destination:
            target_sender_protocols.append(destination)
    target_sender_protocols = dedupe_strings(target_sender_protocols)

    rewritten: list[JSONObject] = []
    for plan in probe_plans:
        if plan.get("case") != "arp-spa-variation":
            rewritten.append(dict(plan))
            continue
        updated = dict(plan)
        validation = dict(
            json_mapping(updated.get("validation", {}), "probe_plan.validation")
        )
        canonical = string_or(validation.get("sender_protocol_addr"), "")
        candidates = dedupe_strings([canonical, *target_sender_protocols])
        if candidates:
            validation["sender_protocol_addrs"] = candidates
            updated["validation"] = validation
        rewritten.append(updated)
    return rewritten


# --------------------------------------------------------------------------- #
# Lab endpoint live report
# --------------------------------------------------------------------------- #


def lab_endpoint_live_report(
    *,
    request: ProbeRunRequest,
    selected_cases: Sequence[ProbeCase],
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    report_path: Path,
    endpoint_roles: Sequence[str],
    probe_lab_request: Callable[..., object],
    probe_plan_with_endpoint_addresses: Callable[..., JSONObject],
    stimulus_endpoint_request_object: Callable[..., JSONObject],
    lab_session_probe_report_metadata: Callable[..., JSONObject],
    probe_interface: Callable[..., str],
    first_plan_address: Callable[..., str],
    selected_specs: Sequence[str],
) -> ProbeReport:
    output_dir = report_path.parent
    endpoint_dir = output_dir / "artifacts" / "lab-stimulus-endpoint"
    endpoint_dir.mkdir(parents=True, exist_ok=True)
    provider_commands: list[JSONObject] = []
    execution_errors: list[str] = []
    endpoint_response: JSONObject | None = None
    wire_endpoint_plan: JSONObject = {}
    endpoints: JSONObject = {}
    address_context: JSONObject = {}
    lab_session: LabSession | None = None
    lab_report_metadata: JSONObject = {}
    created_endpoint_ids: list[str] = []
    endpoint_artifact_paths: list[str] = []
    provider_capabilities = probe_capabilities_for_request(request, dry_run=False)
    skipped_results, skips, skip_counts, skipped_sequences = capability_skip_state(
        request=request,
        planned_cases=planned_cases,
        probe_plans=probe_plans,
        dry_run=False,
        provider_capabilities=provider_capabilities,
    )
    all_live_plans = list(probe_plans)
    live_plans = [
        plan
        for plan in probe_plans
        if int(plan.get("sequence", -1)) not in skipped_sequences
    ]
    executable_planned_cases = [
        case
        for sequence, case in enumerate(planned_cases)
        if sequence not in skipped_sequences
    ]
    local_request_path = endpoint_dir / "stimulus.request.json"
    target_setup_attempted = False
    rst_guard_attempted = False
    stimulus_endpoint: JSONObject = {}
    target_endpoint: JSONObject = {}
    target_endpoint_id = ""
    stimulus_endpoint_id = ""
    remote_dir = ""
    remote_artifact_root = ""
    wire = lab_wire_client.WireClient()

    if live_plans:
        try:
            lab_adapter = resolve_probe_lab_provider(request.provider)
            lab_session = lab_session_state.create_session(
                lab_adapter,
                probe_lab_request(
                    request,
                    dry_run=False,
                    confirm_live_run=True,
                    remote_dir=probe_lab_remote_dir(),
                ),
                client=wire,
            )
            created_endpoint_ids = list(lab_session.created_endpoint_ids)
            address_context = probe_address_context_from_lab_session(lab_session)

            endpoints = json_object(
                address_context.get("endpoints", {}),
                "lab_address_context.endpoints",
            )
            stimulus_endpoint = json_mapping(
                endpoints.get(STIMULUS_ROLE, {}),
                "lab.endpoints.stimulus",
            )
            target_endpoint = json_mapping(
                endpoints.get(TARGET_ROLE, {}),
                "lab.endpoints.target",
            )
            stimulus_endpoint_id = lab_endpoint_id(
                stimulus_endpoint,
                role=STIMULUS_ROLE,
            )
            target_endpoint_id = lab_endpoint_id(
                target_endpoint,
                role=TARGET_ROLE,
            )

            source_ipv4 = string_or(
                stimulus_endpoint.get("address"),
                first_plan_address(probe_plans, "source_ipv4", "192.0.2.10"),
            )
            target_ipv4 = string_or(
                target_endpoint.get("address"),
                first_plan_address(probe_plans, "destination_ipv4", "192.0.2.20"),
            )
            source_mac = string_or(stimulus_endpoint.get("mac"), "")
            target_mac = string_or(target_endpoint.get("mac"), "")
            target_interface = string_or(target_endpoint.get("interface"), "")
            interface = string_or(
                stimulus_endpoint.get("interface"),
                probe_interface(request.provider, dry_run=False),
            )
            all_live_plans = [
                probe_plan_with_endpoint_addresses(
                    plan,
                    source_ipv4=source_ipv4,
                    target_ipv4=target_ipv4,
                    source_mac=source_mac or None,
                    target_mac=target_mac or None,
                    target_interface=target_interface or None,
                )
                for plan in probe_plans
            ]
            all_live_plans = plans_with_arp_sender_protocol_candidates(all_live_plans)
            live_plans = [
                plan
                for plan in all_live_plans
                if int(plan.get("sequence", -1)) not in skipped_sequences
            ]

            repo_archive = lab_repo.create_repository_archive(
                output_dir / "artifacts" / "lab" / "repo",
                source_root=REPO_ROOT,
            )
            lab_session = replace(
                lab_session,
                command_records=[
                    *lab_session.command_records,
                    repo_archive.command_record,
                ],
            )
            endpoint_artifact_paths.extend(
                [
                    str(repo_archive.archive_path),
                    str(repo_archive.stdout_path),
                    str(repo_archive.stderr_path),
                ]
            )
            remote_dir = string_or(lab_session.remote_dir, "/root/libcrafter")
            bootstrap_result = lab_repo.bootstrap_lab_session(
                lab_session,
                probe_bootstrap.bootstrap_commands(),
                remote_dir=remote_dir,
                archive=repo_archive,
                output_dir=output_dir / "artifacts" / "lab" / "bootstrap",
                client=wire,
            )
            lab_session = lab_repo.session_with_bootstrap_records(
                lab_session,
                bootstrap_result,
            )
            lab_session_state.write_session_manifest(lab_session)
            endpoint_artifact_paths.extend(bootstrap_result.artifacts)
            if not bootstrap_result.ok:
                message = f"{request.provider} endpoint bootstrap failed"
                if bootstrap_result.errors:
                    message = f"{message}: {'; '.join(bootstrap_result.errors)}"
                execution_errors.append(message)
                raise RuntimeError(message)

            remote_artifact_root = posixpath.join(
                bootstrap_result.remote_artifact_root,
                "probe",
                "endpoint",
            )
            target_artifact_root = posixpath.join(
                bootstrap_result.remote_artifact_root,
                "probe",
                "target-services",
            )

            remote_request_path = posixpath.join(
                remote_artifact_root,
                "inputs",
                "stimulus.request.json",
            )
            endpoint_request = stimulus_endpoint_request_object(
                request=request,
                probe_plans=live_plans,
                dry_run=False,
                interface=interface,
                artifact_root=remote_artifact_root,
                request_path=remote_request_path,
                stimulus_endpoint=stimulus_endpoint,
            )
            write_json(local_request_path, endpoint_request)

            target_setup = prepare_wire_probe_target(
                wire=wire,
                target_endpoint=target_endpoint,
                artifact_root=target_artifact_root,
                probe_plans=live_plans,
                output_dir=endpoint_dir,
            )
            if target_setup is not None:
                target_setup_attempted = True
                provider_commands.append(target_setup)
                execution_errors.extend(string_list(target_setup.get("errors", [])))
                if target_setup["exit_code"] != 0:
                    execution_errors.append("target endpoint setup failed")

            rst_setup = install_wire_stimulus_rst_guards(
                wire=wire,
                stimulus_endpoint=stimulus_endpoint,
                probe_plans=live_plans,
                output_dir=endpoint_dir,
            )
            if rst_setup is not None:
                rst_guard_attempted = True
                provider_commands.append(rst_setup)
                execution_errors.extend(string_list(rst_setup.get("errors", [])))
                if rst_setup["exit_code"] != 0:
                    execution_errors.append("stimulus RST guard setup failed")

            if not execution_errors:
                upload = upload_wire_probe_request(
                    wire=wire,
                    endpoint_id=stimulus_endpoint_id,
                    local_request_path=local_request_path,
                    remote_request_path=remote_request_path,
                    output_dir=endpoint_dir,
                )
                provider_commands.append(upload)
                if upload["exit_code"] != 0:
                    execution_errors.append("failed to upload stimulus endpoint request")
            else:
                upload = None

            if not execution_errors and upload is not None:
                execution = run_wire_stimulus_endpoint(
                    wire=wire,
                    endpoint_id=stimulus_endpoint_id,
                    remote_dir=remote_dir,
                    remote_request_path=remote_request_path,
                    remote_artifact_root=remote_artifact_root,
                    output_dir=endpoint_dir,
                    timeout_seconds=probe_process_timeout_seconds(len(live_plans)),
                )
                provider_commands.append(execution)
                endpoint_response = execution.get("response") if isinstance(
                    execution.get("response"), dict
                ) else None
                execution_errors.extend(string_list(execution.get("errors", [])))
                if execution["exit_code"] != 0:
                    execution_errors.append("stimulus endpoint command failed")

                downloads = download_wire_probe_artifacts(
                    wire=wire,
                    endpoint_id=stimulus_endpoint_id,
                    artifact_paths=json_object(
                        endpoint_request.get("artifact_paths", {}),
                        "stimulus.artifact_paths",
                    ),
                    output_dir=endpoint_dir,
                    response_path=endpoint_dir / "stimulus.response.json",
                )
                provider_commands.extend(downloads)
                endpoint_artifact_paths.extend(
                    [
                        path
                        for command in downloads
                        for path in command_artifact_paths(command)
                    ]
                )
                if endpoint_response is None:
                    endpoint_response = probe_endpoint_response_from_path(
                        endpoint_dir / "stimulus.response.json"
                    )
                if endpoint_response is None:
                    execution_errors.append("stimulus endpoint did not return JSON")
        except Exception as exc:  # pragma: no cover - live-provider only.
            execution_errors.append(str(exc))
        finally:
            if stimulus_endpoint_id and rst_guard_attempted:
                rst_cleanup = cleanup_wire_stimulus_rst_guards(
                    wire=wire,
                    stimulus_endpoint=stimulus_endpoint,
                    probe_plans=live_plans,
                    output_dir=endpoint_dir,
                )
                provider_commands.append(rst_cleanup)
                execution_errors.extend(string_list(rst_cleanup.get("errors", [])))
                if rst_cleanup["exit_code"] != 0:
                    execution_errors.append("stimulus RST guard cleanup failed")
            if target_endpoint_id and target_setup_attempted:
                target_cleanup = cleanup_wire_probe_target(
                    wire=wire,
                    target_endpoint=target_endpoint,
                    artifact_root=target_artifact_root,
                    output_dir=endpoint_dir,
                )
                provider_commands.append(target_cleanup)
                execution_errors.extend(string_list(target_cleanup.get("errors", [])))
                if target_cleanup["exit_code"] != 0:
                    execution_errors.append("target endpoint cleanup failed")
            if lab_session is not None:
                try:
                    lab_session = lab_session_state.cleanup_lab_session(
                        lab_session,
                        client=wire,
                    )
                    lab_session_state.write_session_manifest(lab_session)
                except Exception as cleanup_exc:  # pragma: no cover - defensive fallback.
                    execution_errors.append(
                        f"{request.provider} lab cleanup failed: {cleanup_exc}"
                    )

    if lab_session is not None:
        address_context = address_context or probe_address_context_from_lab_session(
            lab_session
        )
        lab_report_metadata = lab_session_probe_report_metadata(
            lab_session,
            address_context=address_context,
            provider_capabilities=provider_capabilities,
        )
        wire_endpoint_plan = json_mapping(
            lab_report_metadata.get("wire_endpoint_plan", {}),
            "lab_report.wire_endpoint_plan",
        )
        endpoints = json_mapping(
            lab_report_metadata.get("endpoints", {}),
            "lab_report.endpoints",
        )
        provider_commands = [
            *json_list(
                lab_report_metadata.get("command_records", []),
                "lab_report.command_records",
            ),
            *provider_commands,
        ]

    if not live_plans:
        endpoint_results: list[ProbeResult] = []
        observed_responses = []
    elif endpoint_response is None:
        endpoint_results, observed_responses = probe_results.failed_live_probe_results(
            planned_cases=executable_planned_cases,
            probe_plans=live_plans,
            reason=FAILURE_DECODE_FAILED,
            errors=execution_errors,
        )
    else:
        endpoint_results, observed_responses = (
            probe_results.probe_results_from_endpoint_response(endpoint_response)
        )

    results = sorted(
        [*skipped_results, *endpoint_results],
        key=lambda result: result.sequence,
    )
    failures = [result for result in results if result.passed is False]
    status = STATUS_PASSED if results and not failures and not execution_errors else STATUS_FAILED
    failed_counts = probe_results.failed_counts_by_reason(results)
    executed_count = sum(1 for result in results if result.status != "skipped")
    passed_count = sum(1 for result in results if result.passed is True)
    # Live runs must keep provider skips and real failures in distinct columns.
    # `skip_class` splits the skipped cases into capability vs confirmation; a
    # case the provider can support but that builds the wrong packet, returns an
    # undecodable response, or fails validation is a `failed` outcome that must
    # be fixed in libcrafter or the probe infrastructure and rerun -- it is never
    # demoted to a skip to make the report pass.
    skip_class = skip_class_counts(skips)
    artifact_paths = [str(report_path)]
    if local_request_path.exists():
        artifact_paths.append(str(local_request_path))
    artifact_paths.extend(endpoint_artifact_paths)
    artifact_paths.extend(
        [
            path
            for command in provider_commands
            for path in command_artifact_paths(command)
        ]
    )
    if endpoint_response is not None:
        artifact_paths.extend(string_list(endpoint_response.get("artifacts", [])))
        artifact_paths.extend(string_list(endpoint_response.get("artifact_paths", [])))
    artifact_paths = dedupe_paths(artifact_paths)
    lab_wire_endpoint_lifecycle = json_mapping(
        lab_report_metadata.get("wire_endpoint_lifecycle", {}),
        "lab_report.wire_endpoint_lifecycle",
    )
    cleanup_state = json_mapping(
        lab_wire_endpoint_lifecycle.get("cleanup_state", {}),
        "lab_report.cleanup_state",
    )
    destroy_attempted = bool(
        cleanup_state.get("teardown_attempted", bool(created_endpoint_ids))
    )

    return ProbeReport(
        mode="probe",
        provider=request.provider,
        profile=request.profile,
        seed=request.seed,
        count=len(planned_cases),
        status=status,
        request=request,
        cases=list(selected_cases),
        endpoint_roles=list(endpoint_roles),
        results=results,
        skips=skips,
        observed_responses=observed_responses,
        artifacts=artifact_paths,
        artifact_paths=artifact_paths,
        metadata={
            "provider": request.provider,
            "cases": [case.name for case in selected_cases],
            "requested_count": request.count,
            "planned_count": len(planned_cases),
            "selected_count": len(selected_cases),
            "executed_count": executed_count,
            "executed": executed_count,
            "passed_count": passed_count,
            "passed": passed_count,
            "failed_count": len(failures),
            "failed": len(failures),
            "executed_cases": dedupe_strings(
                [result.case for result in results if result.status != "skipped"]
            ),
            "failed_counts_by_reason": failed_counts,
            "skipped_count": len(skips),
            "skipped_by_capability": skip_class["skipped_by_capability"],
            "skipped_by_confirmation": skip_class["skipped_by_confirmation"],
            "observed_count": sum(
                1 for response in observed_responses if response.observed
            ),
            "provider_capabilities": dict(provider_capabilities),
            "skip_reasons": list(skip_counts),
            "skip_counts_by_reason": skip_counts,
            "selected_case_names": [case.name for case in selected_cases],
            "planned_case_names": [case.name for case in planned_cases],
            "probe_plans": all_live_plans,
            "selected_specs": list(selected_specs),
            "dry_run": False,
            "creates_infrastructure": bool(created_endpoint_ids),
            "requires_provider_lifecycle": True,
            "mutates_lab": True,
            "live_packet_exchange": status == STATUS_PASSED and executed_count > 0,
            "provider_workflow": lab_report_metadata.get("provider_workflow", []),
            "wire_endpoint_plan": wire_endpoint_plan,
            "endpoints": endpoints,
            "wire_endpoint_lifecycle": {
                **lab_wire_endpoint_lifecycle,
                "remote_dir": remote_dir,
                "remote_artifact_root": remote_artifact_root,
                "created_endpoint_ids": list(created_endpoint_ids),
                "destroy_attempted": destroy_attempted,
            },
            "provider_commands": provider_commands,
            "command_records": provider_commands,
            "lab_session": lab_report_metadata.get("lab_session"),
            "planned_infrastructure": lab_report_metadata.get(
                "planned_infrastructure",
                {},
            ),
            "lab_address_context": address_context,
            "execution_errors": execution_errors,
            "target_service_setup": _target_service_setup_plan(
                probe_plans=live_plans,
                dry_run=False,
            ),
        },
    )


# --------------------------------------------------------------------------- #
# Lab-wire transport helpers
# --------------------------------------------------------------------------- #


def probe_lab_remote_dir() -> str | None:
    remote_dir = os.environ.get("LIBCRAFTER_ENDPOINT_REMOTE_DIR")
    if remote_dir is None or remote_dir == "":
        return None
    if not remote_dir.startswith("/"):
        raise RuntimeError("probe lab remote_dir must be an absolute path")
    if "'" in remote_dir:
        raise RuntimeError("probe lab remote_dir must not contain single quotes")
    return remote_dir.rstrip("/") or "/"


def run_lab_wire_command(
    response: object,
    *,
    output_dir: Path,
    label: str,
) -> JSONObject:
    command_dir = output_dir / "provider"
    command_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = command_dir / f"{label}.stdout.txt"
    stderr_path = command_dir / f"{label}.stderr.txt"
    result = getattr(response, "result")
    stdout = str(getattr(result, "stdout", ""))
    stderr = str(getattr(result, "stderr", ""))
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    metadata_func = getattr(response, "metadata", None)
    metadata = (
        json_object(metadata_func(), f"{label}.metadata")
        if callable(metadata_func)
        else {}
    )
    metadata.update(
        {
            "label": label,
            "wire_command": True,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }
    )
    error = getattr(result, "error", None)
    if isinstance(error, str) and error:
        metadata["error"] = error
    collected_artifacts = existing_paths_from_stdout(stdout)
    if collected_artifacts:
        metadata["collected_artifacts"] = collected_artifacts
    return metadata


def upload_wire_probe_request(
    *,
    wire: object,
    endpoint_id: str,
    local_request_path: Path,
    remote_request_path: str,
    output_dir: Path,
) -> JSONObject:
    remote_parent = posixpath.dirname(remote_request_path)
    mkdir = run_lab_wire_command(
        wire.exec(
            endpoint_id,
            ["bash", "-lc", f"mkdir -p {shlex.quote(remote_parent)}"],
            timeout=60,
        ),
        output_dir=output_dir,
        label="upload-stimulus-request-mkdir",
    )
    upload = (
        run_lab_wire_command(
            wire.upload(endpoint_id, local_request_path, remote_request_path),
            output_dir=output_dir,
            label="upload-stimulus-request",
        )
        if mkdir["exit_code"] == 0
        else None
    )
    commands = [mkdir] + ([] if upload is None else [upload])
    exit_code = next(
        (
            int(command.get("exit_code", 1))
            for command in commands
            if command.get("exit_code") != 0
        ),
        0,
    )
    return {
        "wire_command": True,
        "operation": "upload",
        "endpoint_id": endpoint_id,
        "label": "upload-stimulus-request",
        "exit_code": exit_code,
        "request_path": str(local_request_path),
        "remote_request_path": remote_request_path,
        "commands": commands,
        "errors": [
            error
            for command in commands
            for error in string_list(command.get("errors", []))
        ],
    }


def run_wire_stimulus_endpoint(
    *,
    wire: object,
    endpoint_id: str,
    remote_dir: str,
    remote_request_path: str,
    remote_artifact_root: str,
    output_dir: Path,
    timeout_seconds: int,
) -> JSONObject:
    quoted_remote_dir = shlex.quote(remote_dir)
    quoted_request = shlex.quote(remote_request_path)
    quoted_out = shlex.quote(remote_artifact_root)
    script = "\n".join(
        [
            "set -euo pipefail",
            f"cd {quoted_remote_dir}",
            'if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi',
            (
                "cargo run -q -p probe-adapters --bin stimulus_endpoint -- "
                f"--live --input {quoted_request} --out {quoted_out}"
            ),
        ]
    )
    response = wire.exec(
        endpoint_id,
        ["bash", "-lc", script],
        timeout=timeout_seconds,
    )
    command = run_lab_wire_command(
        response,
        output_dir=output_dir,
        label="stimulus-endpoint",
    )
    parsed, parse_errors = parse_json_stdout(
        str(getattr(response.result, "stdout", "")),
        "stimulus-endpoint",
    )
    command["response"] = parsed
    command["errors"] = [
        *string_list(command.get("errors", [])),
        *parse_errors,
    ]
    return command


def prepare_wire_probe_target(
    *,
    wire: object,
    target_endpoint: Mapping[str, JSONValue],
    artifact_root: str,
    probe_plans: Sequence[JSONObject],
    output_dir: Path,
) -> JSONObject | None:
    return _prepare_target_services_wire(
        wire=wire,
        target_endpoint=target_endpoint,
        artifact_root=artifact_root,
        probe_plans=probe_plans,
        output_dir=output_dir,
        endpoint_id_resolver=lab_endpoint_id,
        endpoint_ipv4_resolver=lab_endpoint_ipv4,
        endpoint_interface_resolver=lab_endpoint_interface,
        run_wire_command=run_lab_wire_command,
    )


def cleanup_wire_probe_target(
    *,
    wire: object,
    target_endpoint: Mapping[str, JSONValue],
    artifact_root: str,
    output_dir: Path,
) -> JSONObject:
    return _cleanup_target_services_wire(
        wire=wire,
        target_endpoint=target_endpoint,
        artifact_root=artifact_root,
        output_dir=output_dir,
        endpoint_id_resolver=lab_endpoint_id,
        run_wire_command=run_lab_wire_command,
    )


def install_wire_stimulus_rst_guards(
    *,
    wire: object,
    stimulus_endpoint: Mapping[str, JSONValue],
    probe_plans: Sequence[JSONObject],
    output_dir: Path,
) -> JSONObject | None:
    tcp_plans = probe_target_services.tcp_probe_plans(probe_plans)
    if not tcp_plans:
        return None
    endpoint_id = lab_endpoint_id(stimulus_endpoint, role=STIMULUS_ROLE)
    interface = lab_endpoint_interface(stimulus_endpoint, role=STIMULUS_ROLE)
    return run_lab_wire_command(
        wire.exec(
            endpoint_id,
            [
                "bash",
                "-lc",
                rst_guard_script(
                    tcp_plans,
                    install=True,
                    interface=interface,
                ),
            ],
            timeout=60,
        ),
        output_dir=output_dir,
        label="probe-stimulus-rst-guard-setup",
    )


def cleanup_wire_stimulus_rst_guards(
    *,
    wire: object,
    stimulus_endpoint: Mapping[str, JSONValue],
    probe_plans: Sequence[JSONObject],
    output_dir: Path,
) -> JSONObject:
    endpoint_id = lab_endpoint_id(stimulus_endpoint, role=STIMULUS_ROLE)
    interface = lab_endpoint_interface(stimulus_endpoint, role=STIMULUS_ROLE)
    return run_lab_wire_command(
        wire.exec(
            endpoint_id,
            [
                "bash",
                "-lc",
                rst_guard_script(
                    probe_target_services.tcp_probe_plans(probe_plans),
                    install=False,
                    interface=interface,
                ),
            ],
            timeout=60,
        ),
        output_dir=output_dir,
        label="probe-stimulus-rst-guard-cleanup",
    )


def download_wire_probe_artifacts(
    *,
    wire: object,
    endpoint_id: str,
    artifact_paths: Mapping[str, JSONValue],
    output_dir: Path,
    response_path: Path,
) -> list[JSONObject]:
    local_root = output_dir / "downloads" / "stimulus"
    downloads: list[JSONObject] = []
    local_by_key = {
        "response": response_path,
        "captures": local_root / "captures",
    }
    for key, local_path in local_by_key.items():
        remote_path = artifact_paths.get(key)
        if not isinstance(remote_path, str) or not remote_path.startswith("/"):
            continue
        record = run_lab_wire_command(
            wire.download(endpoint_id, remote_path, local_path),
            output_dir=output_dir,
            label=f"download-stimulus-{key}",
        )
        record.update(
            {
                "endpoint_id": endpoint_id,
                "endpoint_role": "stimulus",
                "artifact_key": key,
                "remote_path": remote_path,
                "local_path": str(local_path),
            }
        )
        downloads.append(record)
    return downloads


def existing_paths_from_stdout(stdout: str) -> list[str]:
    paths: list[str] = []
    for line in stdout.splitlines():
        value = line.strip()
        if not value or "=" in value:
            continue
        path = Path(value)
        try:
            exists = path.exists()
        except OSError:
            continue
        if exists:
            paths.append(str(path))
    return dedupe_paths(paths)


def probe_endpoint_response_from_path(path: Path) -> JSONObject | None:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(value, Mapping):
        return None
    return json_object(value, "stimulus.response")


# --------------------------------------------------------------------------- #
# Stimulus RST guards
# --------------------------------------------------------------------------- #


def rst_guard_script(
    probe_plans: Sequence[JSONObject],
    *,
    install: bool,
    interface: str | None = None,
) -> str:
    lines = [
        "set -euo pipefail",
        "if ! command -v iptables >/dev/null 2>&1; then",
        "  echo 'iptables is required for TCP raw SYN probes' >&2",
        "  exit 69",
        "fi",
    ]
    for argv in rst_guard_iptables_args(probe_plans, interface=interface):
        quoted_args = " ".join(shlex.quote(arg) for arg in argv)
        check = f"iptables -C OUTPUT {quoted_args}"
        if install:
            lines.extend(
                [
                    f"if ! {check} >/dev/null 2>&1; then",
                    f"  iptables -I OUTPUT 1 {quoted_args}",
                    "fi",
                ]
            )
        else:
            lines.extend(
                [
                    f"while {check} >/dev/null 2>&1; do",
                    f"  iptables -D OUTPUT {quoted_args}",
                    "done",
                ]
            )
    lines.append(
        "echo stimulus_rst_guard={}".format("installed" if install else "removed")
    )
    return "\n".join(lines)


def rst_guard_iptables_args(
    probe_plans: Sequence[JSONObject],
    *,
    interface: str | None = None,
) -> list[list[str]]:
    rules: list[list[str]] = []
    for plan in probe_plans:
        guard = json_object(plan.get("stimulus_rst_guard", {}), "stimulus_rst_guard")
        if guard.get("required") is not True:
            continue
        interface_args = ["-o", interface] if interface else []
        rules.append(
            [
                *interface_args,
                "-p",
                "tcp",
                "-s",
                str(guard.get("source_ipv4", plan.get("source_ipv4", ""))),
                "-d",
                str(guard.get("destination_ipv4", plan.get("destination_ipv4", ""))),
                "--sport",
                str(guard.get("source_port", plan.get("source_port", ""))),
                "--dport",
                str(guard.get("destination_port", plan.get("destination_port", ""))),
                "--tcp-flags",
                "RST",
                "RST",
                "-j",
                "DROP",
            ]
        )
    return rules


# --------------------------------------------------------------------------- #
# JSON parsing and small utilities
# --------------------------------------------------------------------------- #


def parse_json_stdout(stdout: str, label: str) -> tuple[JSONObject | None, list[str]]:
    if not stdout.strip():
        return None, [f"{label}: endpoint produced no JSON response"]
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        start = stdout.find("{")
        end = stdout.rfind("}")
        if start < 0 or end <= start:
            return None, [f"{label}: endpoint stdout was not JSON"]
        try:
            value = json.loads(stdout[start : end + 1])
        except json.JSONDecodeError as exc:
            return None, [f"{label}: endpoint stdout JSON parse failed: {exc}"]
    if not isinstance(value, Mapping):
        return None, [f"{label}: endpoint response must be a JSON object"]
    return json_object(value, f"{label}.response"), []


def command_artifact_paths(command: Mapping[str, JSONValue]) -> list[str]:
    paths: list[str] = []
    for key in ("stdout_path", "stderr_path", "request_path"):
        value = command.get(key)
        if isinstance(value, str) and value:
            paths.append(value)
    return paths


def probe_process_timeout_seconds(plan_count: int) -> int:
    return (probe_timeout_seconds(plan_count) * max(plan_count, 1)) + 60


def probe_timeout_seconds(plan_count: int) -> int:
    return 3


def string_or(value: object, default: str) -> str:
    return value if isinstance(value, str) and value else default


def string_list(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def json_mapping(value: object, name: str) -> JSONObject:
    if isinstance(value, Mapping):
        return json_object(value, name)
    return {}


def json_list(value: object, name: str) -> list[JSONObject]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [
        json_object(item, f"{name}[]")
        for item in value
        if isinstance(item, Mapping)
    ]


def dedupe_paths(paths: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(path for path in paths if path))


def dedupe_strings(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


__all__ = [
    "cleanup_wire_probe_target",
    "cleanup_wire_stimulus_rst_guards",
    "command_artifact_paths",
    "dedupe_paths",
    "dedupe_strings",
    "download_wire_probe_artifacts",
    "existing_paths_from_stdout",
    "install_wire_stimulus_rst_guards",
    "json_list",
    "json_mapping",
    "lab_endpoint_id",
    "lab_endpoint_interface",
    "lab_endpoint_ipv4",
    "lab_endpoint_live_report",
    "parse_json_stdout",
    "prepare_wire_probe_target",
    "probe_endpoint_response_from_path",
    "probe_lab_remote_dir",
    "probe_process_timeout_seconds",
    "probe_timeout_seconds",
    "rst_guard_iptables_args",
    "rst_guard_script",
    "run_lab_wire_command",
    "run_wire_stimulus_endpoint",
    "string_list",
    "string_or",
    "upload_wire_probe_request",
    "wire_command_failed",
]
