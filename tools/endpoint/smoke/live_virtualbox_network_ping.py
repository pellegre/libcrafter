#!/usr/bin/env python3
"""Opt-in VirtualBox LAN smoke for the network_ping example.

This script intentionally does not run under default unittest discovery. Use
``--plan-only`` to inspect the command sequence without creating a VM, or pass
``--live --i-understand-isolated-lab`` to create a confirmed VirtualBox LAN
endpoint and send one ICMP echo request to the LAN router through the endpoint
appliance runtime.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from appliance_support import runtime_plan_lines, ssh_docker_runtime_metadata
except ImportError:  # pragma: no cover - package import path
    from tools.endpoint.smoke.appliance_support import (
        runtime_plan_lines,
        ssh_docker_runtime_metadata,
    )

APPLIANCE_PROFILE = "lan-raw"
DEFAULT_REMOTE_BIN = "/root/network_ping"
DEFAULT_ROLE = "network-ping-smoke"
DEFAULT_ROUTER = "192.168.0.1"
DEFAULT_GUEST_STATE_COMMAND = (
    "echo '### ip -brief addr'; "
    "ip -brief addr; "
    "echo '### ip route'; "
    "ip route; "
    "echo '### uname -a'; "
    "uname -a; "
    "echo '### cargo'; "
    "cargo --version; "
    "echo '### workspace'; "
    "pwd; "
    "ls -la"
)


class SmokeError(RuntimeError):
    """Raised when one smoke step fails."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class CommandCapture:
    """Captured command result with a shell-rendered command string."""

    argv: list[str]
    cwd: Path | None
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def command(self) -> str:
        return shlex.join(self.argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repo_root = Path(__file__).resolve().parents[3]
    wire = repo_root / "tools" / "endpoint" / "run"

    plan = _plan_commands(
        repo_root=repo_root,
        wire=wire,
        router=args.router,
        role=args.role,
        icmp_id=args.icmp_id,
        icmp_seq=args.icmp_seq,
        guest_state_command=args.guest_state_command,
    )
    if args.plan_only:
        print(plan)
        return 0

    if not args.live or not args.i_understand_isolated_lab:
        print(
            "live VirtualBox network smoke requires "
            "--live --i-understand-isolated-lab",
            file=sys.stderr,
        )
        print(plan, file=sys.stderr)
        return 2

    endpoint_id: str | None = None
    artifact_dir: Path | None = None
    exit_code = 1

    try:
        create = _run(
            [
                str(wire),
                "create",
                "--provider",
                "virtualbox",
                "--exposure",
                "lan",
                "--role",
                args.role,
                "--confirm-live-run",
                "--json",
            ],
            cwd=repo_root,
            timeout=args.create_timeout,
        )
        if not create.ok:
            _write_unattached_failure(repo_root, "create", create)
            raise SmokeError("VirtualBox endpoint creation failed", create.exit_code)

        manifest = _json_object(create.stdout, "create output")
        endpoint_id = _string(manifest.get("endpoint_id"), "endpoint_id")
        artifact_dir = Path(_string(manifest.get("artifact_dir"), "artifact_dir"))
        artifact_dir.mkdir(parents=True, exist_ok=True)
        _write_result_artifacts(artifact_dir, "create_endpoint", create)

        lan_iface, lan_src = _lan_endpoint(manifest)
        appliance_artifact_dir = artifact_dir / "appliance-network-ping"

        deploy = _run(
            [
                str(wire),
                "appliance",
                "deploy",
                endpoint_id,
                APPLIANCE_PROFILE,
                "--artifact-dir",
                str(appliance_artifact_dir / "deploy"),
                "--json",
            ],
            cwd=repo_root,
            timeout=args.build_timeout,
        )
        _write_result_artifacts(artifact_dir, "appliance_deploy", deploy)
        if not deploy.ok:
            raise SmokeError("endpoint appliance deploy failed", deploy.exit_code)

        network_ping = _run(
            [
                str(wire),
                "appliance",
                "run",
                endpoint_id,
                APPLIANCE_PROFILE,
                "--work-dir",
                str(repo_root),
                "--artifact-dir",
                str(appliance_artifact_dir),
                "--json",
                "--",
                "sh",
                "-lc",
                _appliance_network_ping_command(
                    args=args,
                    lan_iface=lan_iface,
                    lan_src=lan_src,
                ),
            ],
            cwd=repo_root,
            timeout=args.ping_timeout,
        )
        _write_result_artifacts(artifact_dir, "appliance_network_ping", network_ping)

        collect = _run(
            [
                str(wire),
                "appliance",
                "collect",
                endpoint_id,
                APPLIANCE_PROFILE,
                "--artifact-dir",
                str(appliance_artifact_dir),
                "--json",
                "--",
                "true",
            ],
            cwd=repo_root,
            timeout=args.transfer_timeout,
        )
        _write_result_artifacts(artifact_dir, "appliance_collect", collect)
        if not network_ping.ok:
            raise SmokeError("network_ping appliance execution failed", network_ping.exit_code)
        if not collect.ok:
            raise SmokeError("network_ping appliance artifact collection failed", collect.exit_code)

        _write_json(
            artifact_dir / "network_ping_smoke.json",
            {
                "ok": True,
                "endpoint_id": endpoint_id,
                "router": args.router,
                "iface": lan_iface,
                "src": lan_src,
                "appliance_profile": APPLIANCE_PROFILE,
                "appliance_artifact_dir": str(appliance_artifact_dir),
                "appliance_runtime": ssh_docker_runtime_metadata(profile=APPLIANCE_PROFILE),
                "artifact_dir": str(artifact_dir),
            },
        )
        print(f"endpoint_id={endpoint_id}")
        print(f"artifact_dir={artifact_dir}")
        print(network_ping.stdout, end="")
        exit_code = 0
    except SmokeError as exc:
        print(str(exc), file=sys.stderr)
        if artifact_dir is not None:
            _write_json(
                artifact_dir / "network_ping_smoke.json",
                {
                    "ok": False,
                    "endpoint_id": endpoint_id,
                    "router": args.router,
                    "artifact_dir": str(artifact_dir),
                    "error": str(exc),
                },
            )
        exit_code = exc.exit_code
    finally:
        if endpoint_id is not None:
            destroy = _run(
                [str(wire), "destroy", endpoint_id, "--json"],
                cwd=repo_root,
                timeout=args.destroy_timeout,
            )
            if artifact_dir is not None:
                _write_result_artifacts(artifact_dir, "destroy_endpoint", destroy)
            if exit_code == 0 and not destroy.ok:
                print("endpoint destroy failed", file=sys.stderr)
                exit_code = destroy.exit_code

    return exit_code


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the protected VirtualBox LAN network_ping smoke.",
    )
    parser.add_argument(
        "--router",
        default=os.environ.get("LAN_ROUTER", DEFAULT_ROUTER),
        help="router IPv4 target; defaults to LAN_ROUTER or 192.168.0.1",
    )
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="print the command sequence without creating a VM",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="allow confirmed VirtualBox VM creation and live packet send",
    )
    parser.add_argument(
        "--i-understand-isolated-lab",
        action="store_true",
        help="acknowledge this smoke sends live LAN traffic",
    )
    parser.add_argument("--role", default=DEFAULT_ROLE, help="endpoint role label")
    parser.add_argument(
        "--binary",
        default=None,
        help="accepted for compatibility; appliance runs build from the synced workspace",
    )
    parser.add_argument(
        "--remote-bin",
        default=DEFAULT_REMOTE_BIN,
        help="accepted for compatibility; appliance runs do not upload this binary path",
    )
    parser.add_argument("--id", dest="icmp_id", type=_uint16, default=0x4242)
    parser.add_argument("--seq", dest="icmp_seq", type=_uint16, default=1)
    parser.add_argument("--create-timeout", type=float, default=900)
    parser.add_argument("--build-timeout", type=float, default=600)
    parser.add_argument("--transfer-timeout", type=float, default=120)
    parser.add_argument("--exec-timeout", type=float, default=120)
    parser.add_argument("--ping-timeout", type=float, default=90)
    parser.add_argument("--destroy-timeout", type=float, default=300)
    parser.add_argument(
        "--guest-state-command",
        default=DEFAULT_GUEST_STATE_COMMAND,
        help="remote shell command used to collect guest state after network_ping",
    )
    return parser.parse_args(argv)


def _plan_commands(
    *,
    repo_root: Path,
    wire: Path,
    router: str,
    role: str,
    icmp_id: int,
    icmp_seq: int,
    guest_state_command: str,
) -> str:
    runtime = ssh_docker_runtime_metadata(profile=APPLIANCE_PROFILE)
    commands = [
        [
            str(wire),
            "create",
            "--provider",
            "virtualbox",
            "--exposure",
            "lan",
            "--role",
            role,
            "--confirm-live-run",
            "--json",
        ],
        [
            str(wire),
            "appliance",
            "deploy",
            "<endpoint_id>",
            APPLIANCE_PROFILE,
            "--artifact-dir",
            "<artifact_dir>/appliance-network-ping/deploy",
            "--json",
        ],
        [
            str(wire),
            "appliance",
            "run",
            "<endpoint_id>",
            APPLIANCE_PROFILE,
            "--work-dir",
            str(repo_root),
            "--artifact-dir",
            "<artifact_dir>/appliance-network-ping",
            "--json",
            "--",
            "sh",
            "-lc",
            _appliance_network_ping_command(
                args=argparse.Namespace(
                    router=router,
                    icmp_id=icmp_id,
                    icmp_seq=icmp_seq,
                    guest_state_command=guest_state_command,
                ),
                lan_iface="<lan_iface>",
                lan_src="<lan_ipv4>",
            ),
        ],
        [
            str(wire),
            "appliance",
            "collect",
            "<endpoint_id>",
            APPLIANCE_PROFILE,
            "--artifact-dir",
            "<artifact_dir>/appliance-network-ping",
            "--json",
            "--",
            "true",
        ],
        [str(wire), "destroy", "<endpoint_id>", "--json"],
    ]
    lines = [
        "VirtualBox LAN network_ping smoke plan",
        f"repo: {repo_root}",
        "no VM is created in --plan-only mode",
        *runtime_plan_lines(runtime),
        "",
    ]
    lines.extend(f"{index}. {shlex.join(command)}" for index, command in enumerate(commands, 1))
    return "\n".join(lines)


def _appliance_network_ping_command(
    *,
    args: argparse.Namespace,
    lan_iface: str,
    lan_src: str,
) -> str:
    log = "/artifacts/network_ping.log"
    guest_state = "/artifacts/guest_state.txt"
    network_ping = [
        "cargo",
        "run",
        "-p",
        "crafter",
        "--example",
        "network_ping",
        "--",
        "--live",
        "--i-understand-isolated-lab",
        "--iface",
        lan_iface,
        "--src",
        lan_src,
        "--dst",
        args.router,
        "--id",
        str(args.icmp_id),
        "--seq",
        str(args.icmp_seq),
    ]
    return (
        "set -eu; "
        "mkdir -p /artifacts; "
        f"{{ {args.guest_state_command}; }} > {shlex.quote(guest_state)} 2>&1; "
        f"LIBCRAFTER_ENDPOINT=1 {shlex.join(network_ping)} > {shlex.quote(log)} 2>&1; "
        "rc=$?; "
        f"cat {shlex.quote(guest_state)}; "
        f"cat {shlex.quote(log)}; "
        "exit $rc"
    )


def _run(argv: list[str], *, cwd: Path, timeout: float) -> CommandCapture:
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd),
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandCapture(
            argv=argv,
            cwd=cwd,
            exit_code=124,
            stdout=_output_text(exc.stdout),
            stderr=_output_text(exc.stderr) + f"\ncommand timed out after {timeout} seconds\n",
        )
    except OSError as exc:
        return CommandCapture(argv=argv, cwd=cwd, exit_code=127, stdout="", stderr=str(exc))

    return CommandCapture(
        argv=argv,
        cwd=cwd,
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _lan_endpoint(manifest: dict[str, Any]) -> tuple[str, str]:
    interfaces = manifest.get("interfaces")
    if not isinstance(interfaces, list):
        raise SmokeError("create output did not include interfaces")
    for interface in interfaces:
        if not isinstance(interface, dict) or interface.get("exposure") != "lan":
            continue
        name = _string(interface.get("name"), "lan interface name")
        ipv4 = _string(interface.get("ipv4"), "lan interface ipv4")
        return name, ipv4
    raise SmokeError("create output did not include a LAN interface with IPv4")


def _write_result_artifacts(
    artifact_dir: Path,
    stem: str,
    result: CommandCapture,
) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = artifact_dir / f"{stem}.stdout"
    stderr_path = artifact_dir / f"{stem}.stderr"
    report_path = artifact_dir / f"{stem}.json"
    stdout_path.write_text(result.stdout, encoding="utf-8")
    stderr_path.write_text(result.stderr, encoding="utf-8")
    _write_json(
        report_path,
        {
            "command": result.command,
            "argv": result.argv,
            "cwd": str(result.cwd) if result.cwd is not None else None,
            "exit_code": result.exit_code,
            "ok": result.ok,
            "artifacts": {
                "stdout": str(stdout_path),
                "stderr": str(stderr_path),
            },
        },
    )


def _write_unattached_failure(repo_root: Path, stem: str, result: CommandCapture) -> None:
    artifact_dir = repo_root / "tools" / "endpoint" / "artifacts" / "live-virtualbox-network-ping"
    _write_result_artifacts(artifact_dir, stem, result)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _json_object(value: str, name: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise SmokeError(f"{name} was not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SmokeError(f"{name} was not a JSON object")
    return parsed


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise SmokeError(f"{name} must be a non-empty string")
    return value


def _uint16(value: str | int) -> int:
    try:
        parsed = int(str(value), 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if parsed < 0 or parsed > 0xFFFF:
        raise argparse.ArgumentTypeError("value must fit in an unsigned 16-bit integer")
    return parsed


def _output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
