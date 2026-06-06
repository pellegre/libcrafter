#!/usr/bin/env python3
"""Opt-in Docker WAN DNS smoke.

By default this script prints the planned command sequence without creating
Docker resources. Pass ``--live --i-understand-isolated-lab`` to create a
confirmed docker/wan endpoint, upload a small libcrafter DNS workload, and
verify NAT-backed WAN L3 egress to a public resolver.

This smoke does not exercise public inbound reachability or WAN L2 behavior.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_IFACE = "eth0"
DEFAULT_QUERY = "example.com."
DEFAULT_REMOTE_ARTIFACT_DIR = "/root/libcrafter-docker-wan-dns-smoke"
DEFAULT_REMOTE_BIN = "/root/docker-wan-dns-smoke"
DEFAULT_RESOLVER = "1.1.1.1"
DEFAULT_ROLE = "docker-wan-dns-smoke"
DEFAULT_SOURCE_PORT = 53000
DEFAULT_TIMEOUT_MS = 3000
DEFAULT_RETRIES = 3
WORKLOAD_BIN = "docker-wan-dns-smoke"


WORKLOAD_SOURCE = r'''
use crafter::prelude::*;
use std::env;
use std::error::Error;
use std::net::Ipv4Addr;
use std::time::Duration;

fn main() -> std::result::Result<(), Box<dyn Error>> {
    let iface = env_value("IFACE", "eth0");
    let src = env_parse::<Ipv4Addr>("SOURCE_IP")?;
    let resolver = env_parse::<Ipv4Addr>("RESOLVER_IP")?;
    let source_port = env_parse_default("SOURCE_PORT", 53000u16)?;
    let dns_id = env_parse_default("DNS_ID", 0x5301u16)?;
    let timeout_ms = env_parse_default("TIMEOUT_MS", 3000u64)?;
    let retries = env_parse_default("RETRIES", 3usize)?;
    let query_name = env_value("QUERY_NAME", "example.com.");

    let packet = Ipv4::new().src(src).dst(resolver).id(0x5301).dont_fragment(true)
        / Udp::new().sport(source_port).dport(DNS_PORT)
        / Dns::query(query_name.clone(), DNS_TYPE_A).id(dns_id);

    let report = packet.send_recv_report(
        SendRecv::new()
            .iface(iface.clone())
            .network_layer()
            .live()
            .timeout(Duration::from_millis(timeout_ms))
            .retries(retries)
            .capture_limit(64),
    )?;

    println!("iface={iface}");
    println!("src={src}");
    println!("resolver={resolver}");
    println!("query_name={query_name}");
    println!("query_type=A");
    println!("source_port={source_port}");
    println!("dns_id={dns_id}");
    println!("attempts={}", report.attempts());
    println!("timed_out={}", report.timed_out());
    println!(
        "effective_filter={}",
        report.effective_filter().unwrap_or("")
    );
    println!("request={}", packet.summary());

    match report.reply() {
        Some(reply) => {
            println!("reply={}", reply.summary());
            let Some(dns) = reply.layer::<Dns>() else {
                return Err("matching reply did not decode as DNS".into());
            };
            if !dns.is_response() {
                return Err("matching DNS packet was not a response".into());
            }
            if dns.answers().is_empty() {
                return Err("matching DNS response did not contain answers".into());
            }

            println!("response_id={}", dns.id_value());
            println!("response_rcode={}", dns.rcode_value());
            println!("answer_count={}", dns.answers().len());
            for (index, answer) in dns.answers().iter().enumerate() {
                println!(
                    "answer {}: {} type={} ttl={} data={:?}",
                    index + 1,
                    answer.name(),
                    dns_type_label(answer.record_type()),
                    answer.ttl(),
                    answer.data()
                );
            }
            println!("PASS docker/wan DNS response observed");
            Ok(())
        }
        None => Err("no matching DNS response observed".into()),
    }
}

fn env_value(name: &str, default_value: &str) -> String {
    env::var(name).unwrap_or_else(|_| default_value.to_string())
}

fn env_parse<T>(name: &str) -> std::result::Result<T, Box<dyn Error>>
where
    T: std::str::FromStr,
    T::Err: Error + 'static,
{
    env::var(name)
        .map_err(|_| format!("missing required environment variable {name}"))?
        .parse::<T>()
        .map_err(|err| err.into())
}

fn env_parse_default<T>(name: &str, default_value: T) -> std::result::Result<T, Box<dyn Error>>
where
    T: std::str::FromStr,
    T::Err: Error + 'static,
{
    Ok(match env::var(name) {
        Ok(value) => value.parse::<T>()?,
        Err(_) => default_value,
    })
}

fn dns_type_label(record_type: u16) -> String {
    match dns_type_name(record_type) {
        Some(name) => name.to_string(),
        None => format!("TYPE{record_type}"),
    }
}
'''


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

    plan = _plan_commands(repo_root=repo_root, wire=wire, args=args)
    if not args.live or args.plan_only:
        print(plan)
        return 0

    if not args.i_understand_isolated_lab:
        print(
            "live Docker WAN DNS smoke requires --live --i-understand-isolated-lab",
            file=sys.stderr,
        )
        print(plan, file=sys.stderr)
        return 2

    endpoint_id: str | None = None
    artifact_dir: Path | None = None
    exit_code = 1

    try:
        create = _create_endpoint(
            wire=wire,
            repo_root=repo_root,
            role=args.role,
            timeout=args.create_timeout,
        )
        if not create.ok:
            _write_unattached_failure(repo_root, "create_endpoint", create)
            raise SmokeError("Docker WAN endpoint creation failed", create.exit_code)

        manifest = _endpoint_manifest(create.stdout, "create output")
        endpoint_id = _string(manifest.get("endpoint_id"), "endpoint_id")
        artifact_dir = Path(_string(manifest.get("artifact_dir"), "artifact_dir"))
        artifact_dir.mkdir(parents=True, exist_ok=True)
        _write_result_artifacts(artifact_dir, "create_endpoint", create)

        wan_iface = _wan_endpoint(manifest)

        with tempfile.TemporaryDirectory(prefix="libcrafter-docker-wan-dns-") as temp_dir:
            workspace = Path(temp_dir)
            _write_workload_project(workspace=workspace, repo_root=repo_root)
            build = _run(
                [
                    "cargo",
                    "build",
                    "--release",
                    "--manifest-path",
                    str(workspace / "Cargo.toml"),
                ],
                cwd=repo_root,
                timeout=args.build_timeout,
            )
            _write_result_artifacts(artifact_dir, "build_workload", build)
            if not build.ok:
                raise SmokeError("Docker WAN DNS workload build failed", build.exit_code)

            binary = workspace / "target" / "release" / WORKLOAD_BIN
            if not binary.is_file():
                raise SmokeError(f"Docker WAN DNS workload binary not found: {binary}")

            upload = _run(
                [str(wire), "upload", endpoint_id, str(binary), args.remote_bin],
                cwd=repo_root,
                timeout=args.transfer_timeout,
            )
            _write_result_artifacts(artifact_dir, "upload_workload", upload)
            if not upload.ok:
                raise SmokeError("Docker WAN DNS workload upload failed", upload.exit_code)

        chmod = _run(
            [str(wire), "exec", endpoint_id, "--", "chmod", "0755", args.remote_bin],
            cwd=repo_root,
            timeout=args.exec_timeout,
        )
        _write_result_artifacts(artifact_dir, "chmod_workload", chmod)
        if not chmod.ok:
            raise SmokeError("Docker WAN DNS workload chmod failed", chmod.exit_code)

        run_workload = _run(
            [
                str(wire),
                "exec",
                endpoint_id,
                "--",
                "sh",
                "-lc",
                _remote_workload_command(args=args, wan_iface=wan_iface),
            ],
            cwd=repo_root,
            timeout=args.packet_timeout,
        )
        _write_result_artifacts(artifact_dir, "run_workload", run_workload)

        collect = _collect_artifacts(
            wire=wire,
            repo_root=repo_root,
            endpoint_id=endpoint_id,
            remote_artifact_dir=args.remote_artifact_dir,
            timeout=args.transfer_timeout,
        )
        _write_result_artifacts(artifact_dir, "collect_artifacts", collect)

        if not run_workload.ok:
            raise SmokeError("Docker WAN DNS workload execution failed", run_workload.exit_code)
        if not collect.ok:
            raise SmokeError("Docker WAN DNS artifact collection failed", collect.exit_code)

        summary = {
            "ok": True,
            "endpoint_id": endpoint_id,
            "resolver": args.resolver,
            "query": args.query,
            "iface": wan_iface["name"],
            "src": wan_iface["ipv4"],
            "remote_bin": args.remote_bin,
            "remote_artifact_dir": args.remote_artifact_dir,
            "artifact_dir": str(artifact_dir),
            "wan_semantics": _wan_semantics(),
        }
        _write_json(artifact_dir / "docker_wan_dns_smoke.json", summary)
        print(json.dumps(summary, indent=2, sort_keys=True))
        print(
            "public inbound reachability and WAN L2 were not exercised; "
            "docker/wan validates NAT-backed WAN L3 egress only."
        )
        exit_code = 0
    except SmokeError as exc:
        print(str(exc), file=sys.stderr)
        if artifact_dir is not None:
            _write_json(
                artifact_dir / "docker_wan_dns_smoke.json",
                {
                    "ok": False,
                    "endpoint_id": endpoint_id,
                    "resolver": args.resolver,
                    "query": args.query,
                    "artifact_dir": str(artifact_dir),
                    "error": str(exc),
                    "wan_semantics": _wan_semantics(),
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
        description="Run the protected Docker WAN DNS smoke.",
    )
    parser.add_argument(
        "--resolver",
        default=os.environ.get("LIBCRAFTER_DOCKER_WAN_RESOLVER", DEFAULT_RESOLVER),
        help="DNS resolver IPv4 target; defaults to LIBCRAFTER_DOCKER_WAN_RESOLVER or 1.1.1.1",
    )
    parser.add_argument(
        "--query",
        default=os.environ.get("LIBCRAFTER_DOCKER_WAN_QUERY", DEFAULT_QUERY),
        help="DNS A query name; defaults to LIBCRAFTER_DOCKER_WAN_QUERY or example.com.",
    )
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="print the command sequence without creating Docker resources",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="allow confirmed Docker WAN endpoint creation and live packet send",
    )
    parser.add_argument(
        "--i-understand-isolated-lab",
        action="store_true",
        help="acknowledge this smoke sends live WAN traffic from an isolated endpoint",
    )
    parser.add_argument("--role", default=DEFAULT_ROLE, help="endpoint role label")
    parser.add_argument("--iface", default=DEFAULT_IFACE, help="fallback endpoint interface")
    parser.add_argument(
        "--remote-bin",
        default=DEFAULT_REMOTE_BIN,
        help="absolute endpoint path for the uploaded workload binary",
    )
    parser.add_argument(
        "--remote-artifact-dir",
        default=DEFAULT_REMOTE_ARTIFACT_DIR,
        help="absolute endpoint path for smoke artifacts",
    )
    parser.add_argument("--source-port", type=_uint16, default=DEFAULT_SOURCE_PORT)
    parser.add_argument("--dns-id", type=_uint16, default=0x5301)
    parser.add_argument("--timeout-ms", type=_positive_int, default=DEFAULT_TIMEOUT_MS)
    parser.add_argument("--retries", type=_positive_int, default=DEFAULT_RETRIES)
    parser.add_argument("--create-timeout", type=float, default=300)
    parser.add_argument("--build-timeout", type=float, default=600)
    parser.add_argument("--transfer-timeout", type=float, default=120)
    parser.add_argument("--exec-timeout", type=float, default=120)
    parser.add_argument("--packet-timeout", type=float, default=90)
    parser.add_argument("--destroy-timeout", type=float, default=120)
    return parser.parse_args(argv)


def _plan_commands(*, repo_root: Path, wire: Path, args: argparse.Namespace) -> str:
    commands = [
        _create_endpoint_argv(wire=wire, role=args.role),
        [
            "cargo",
            "build",
            "--release",
            "--manifest-path",
            "<generated-workload>/Cargo.toml",
        ],
        [str(wire), "upload", "<endpoint_id>", "<workload_binary>", args.remote_bin],
        [str(wire), "exec", "<endpoint_id>", "--", "chmod", "0755", args.remote_bin],
        [
            str(wire),
            "exec",
            "<endpoint_id>",
            "--",
            "sh",
            "-lc",
            _remote_workload_command(
                args=args,
                wan_iface={"name": args.iface, "ipv4": "<endpoint_ipv4>"},
            ),
        ],
        [
            str(wire),
            "collect-artifacts",
            "<endpoint_id>",
            "--remote",
            args.remote_artifact_dir,
        ],
        [str(wire), "destroy", "<endpoint_id>", "--json"],
    ]
    lines = [
        "Docker WAN DNS smoke plan",
        f"repo: {repo_root}",
        "no Docker resources are created unless --live --i-understand-isolated-lab are both set",
        f"resolver: {args.resolver}",
        f"query: {args.query}",
        "path: NAT-backed WAN L3 egress through Docker bridge routing",
        "public inbound reachability was not exercised by this smoke",
        "WAN L2 was not exercised by this smoke",
        "",
    ]
    lines.extend(f"{index}. {shlex.join(command)}" for index, command in enumerate(commands, 1))
    return "\n".join(lines)


def _create_endpoint(
    *,
    wire: Path,
    repo_root: Path,
    role: str,
    timeout: float,
) -> CommandCapture:
    return _run(_create_endpoint_argv(wire=wire, role=role), cwd=repo_root, timeout=timeout)


def _create_endpoint_argv(*, wire: Path, role: str) -> list[str]:
    return [
        str(wire),
        "create",
        "--provider",
        "docker",
        "--exposure",
        "wan",
        "--role",
        role,
        "--confirm-live-run",
        "--json",
    ]


def _write_workload_project(*, workspace: Path, repo_root: Path) -> None:
    crate_path = repo_root / "crafter"
    src_bin = workspace / "src" / "bin"
    src_bin.mkdir(parents=True, exist_ok=True)
    (workspace / "Cargo.toml").write_text(
        "\n".join(
            [
                "[package]",
                'name = "libcrafter-docker-wan-dns-smoke-workload"',
                'version = "0.0.0"',
                'edition = "2021"',
                "publish = false",
                "",
                "[dependencies]",
                f'crafter = {{ path = "{crate_path.as_posix()}" }}',
                "",
            ]
        ),
        encoding="utf-8",
    )
    (src_bin / f"{WORKLOAD_BIN}.rs").write_text(
        WORKLOAD_SOURCE.strip() + "\n",
        encoding="utf-8",
    )


def _remote_workload_command(
    *,
    args: argparse.Namespace,
    wan_iface: dict[str, str],
) -> str:
    log = f"{args.remote_artifact_dir}/workload.log"
    guest_state = f"{args.remote_artifact_dir}/guest_state.txt"
    env = _shell_env(
        {
            "IFACE": wan_iface["name"],
            "SOURCE_IP": wan_iface["ipv4"],
            "RESOLVER_IP": args.resolver,
            "QUERY_NAME": args.query,
            "SOURCE_PORT": str(args.source_port),
            "DNS_ID": str(args.dns_id),
            "TIMEOUT_MS": str(args.timeout_ms),
            "RETRIES": str(args.retries),
        }
    )
    return (
        "set -u; "
        f"rm -rf {shlex.quote(args.remote_artifact_dir)}; "
        f"mkdir -p {shlex.quote(args.remote_artifact_dir)}; "
        f"{{ echo '### ip -brief addr'; ip -brief addr; "
        f"echo '### ip route'; ip route; "
        f"echo '### uname -a'; uname -a; "
        f"echo '### workload'; ls -l {shlex.quote(args.remote_bin)}; }} "
        f"> {shlex.quote(guest_state)} 2>&1; "
        f"env {env} {shlex.quote(args.remote_bin)} > {shlex.quote(log)} 2>&1; "
        "rc=$?; "
        f"cat {shlex.quote(guest_state)}; "
        f"cat {shlex.quote(log)}; "
        "exit $rc"
    )


def _collect_artifacts(
    *,
    wire: Path,
    repo_root: Path,
    endpoint_id: str,
    remote_artifact_dir: str,
    timeout: float,
) -> CommandCapture:
    return _run(
        [str(wire), "collect-artifacts", endpoint_id, "--remote", remote_artifact_dir],
        cwd=repo_root,
        timeout=timeout,
    )


def _wan_endpoint(manifest: dict[str, Any]) -> dict[str, str]:
    interfaces = manifest.get("interfaces")
    if not isinstance(interfaces, list):
        raise SmokeError("create output did not include interfaces")
    for interface in interfaces:
        if not isinstance(interface, dict) or interface.get("exposure") != "wan":
            continue
        return {
            "name": _string(interface.get("name"), "wan interface name"),
            "ipv4": _string(interface.get("ipv4"), "wan interface ipv4"),
        }
    raise SmokeError("create output did not include a WAN interface with IPv4")


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


def _write_result_artifacts(
    artifact_dir: Path,
    stem: str,
    result: CommandCapture,
) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    safe_stem = _safe_stem(stem)
    stdout_path = artifact_dir / f"{safe_stem}.stdout"
    stderr_path = artifact_dir / f"{safe_stem}.stderr"
    report_path = artifact_dir / f"{safe_stem}.json"
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
    artifact_dir = repo_root / "tools" / "endpoint" / "artifacts" / "live-docker-wan-dns"
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


def _endpoint_manifest(value: str, name: str) -> dict[str, Any]:
    output = _json_object(value, name)
    endpoint = output.get("endpoint")
    if isinstance(endpoint, dict):
        return endpoint
    return output


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise SmokeError(f"{name} must be a non-empty string")
    return value


def _wan_semantics() -> dict[str, object]:
    return {
        "path": "NAT-backed WAN L3 egress through Docker bridge routing",
        "public_inbound_reachability_exercised": False,
        "wan_l2_exercised": False,
        "link_layer_send_exercised": False,
        "link_layer_capture_exercised": False,
        "public_inbound_reachability": False,
    }


def _shell_env(values: dict[str, str]) -> str:
    return " ".join(f"{name}={shlex.quote(value)}" for name, value in values.items())


def _uint16(value: str | int) -> int:
    try:
        parsed = int(str(value), 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if parsed < 0 or parsed > 0xFFFF:
        raise argparse.ArgumentTypeError("value must fit in an unsigned 16-bit integer")
    return parsed


def _positive_int(value: str | int) -> int:
    try:
        parsed = int(str(value), 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _safe_stem(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value)


def _output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
