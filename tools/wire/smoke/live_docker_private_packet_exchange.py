#!/usr/bin/env python3
"""Opt-in Docker private packet exchange smoke.

This script is intentionally outside default test discovery. By default it
prints the planned command sequence without creating containers. Pass
``--live --i-understand-isolated-lab`` to create two confirmed docker/private
wire endpoints on one isolated bridge, upload small libcrafter sender/receiver
workloads, exchange one L3 UDP packet and one L2 Ethernet/IPv4/UDP packet, and
then destroy both endpoints.
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


DEFAULT_DESTINATION_PORT = 39001
DEFAULT_GROUP = "docker-private-smoke"
DEFAULT_IFACE = "eth0"
DEFAULT_L2_PAYLOAD = "libcrafter-docker-smoke-l2"
DEFAULT_L3_PAYLOAD = "libcrafter-docker-smoke-l3"
DEFAULT_RECEIVER_IP = "10.79.0.20"
DEFAULT_RECEIVER_ROLE = "docker-private-smoke-receiver"
DEFAULT_REMOTE_ARTIFACT_DIR = "/root/libcrafter-docker-private-smoke"
DEFAULT_REMOTE_RECEIVER = "/root/docker-private-smoke-receiver"
DEFAULT_REMOTE_SENDER = "/root/docker-private-smoke-sender"
DEFAULT_SENDER_IP = "10.79.0.10"
DEFAULT_SENDER_ROLE = "docker-private-smoke-sender"
DEFAULT_SOURCE_PORT = 39000
DEFAULT_TIMEOUT_SECS = 15
RECEIVER_BIN = "docker-private-smoke-receiver"
SENDER_BIN = "docker-private-smoke-sender"


RECEIVER_SOURCE = r'''
use crafter::prelude::*;
use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::time::Duration;

fn main() -> std::result::Result<(), Box<dyn Error>> {
    let iface = env_value("IFACE", "eth0");
    let source_ip = env_required("SOURCE_IP")?;
    let destination_port = env_parse("DESTINATION_PORT", 39001u16)?;
    let timeout_secs = env_parse("TIMEOUT_SECS", 15u64)?;
    let expected_payloads = env_required("EXPECTED_PAYLOADS")?;
    let mut pending = expected_payloads
        .split(',')
        .filter(|payload| !payload.is_empty())
        .map(|payload| payload.as_bytes().to_vec())
        .collect::<HashSet<_>>();

    if pending.is_empty() {
        return Err("EXPECTED_PAYLOADS must contain at least one payload".into());
    }

    let filter = format!("udp and dst port {destination_port} and src host {source_ip}");
    let mut capture = Sniffer::interface(&iface)
        .filter(&filter)
        .timeout(Duration::from_secs(timeout_secs))
        .promisc(false)
        .immediate_mode(true)
        .nonblock()
        .open()?;

    println!("READY iface={iface} filter={filter:?} pending={}", pending.len());

    while let Some(frame) = capture.next_packet()? {
        let summary = frame.packet().summary();
        let Some(raw) = frame.packet().layer::<Raw>() else {
            println!("observed packet without raw payload: {summary}");
            continue;
        };

        let payload = raw.as_bytes();
        let Some(matched) = pending
            .iter()
            .find(|expected| expected.as_slice() == payload)
            .cloned()
        else {
            println!(
                "observed unexpected payload len={} summary={summary}",
                payload.len()
            );
            continue;
        };

        pending.remove(&matched);
        println!(
            "MATCH payload={} remaining={} summary={summary}",
            String::from_utf8_lossy(&matched),
            pending.len()
        );

        if pending.is_empty() {
            println!("PASS receiver observed all expected payloads");
            return Ok(());
        }
    }

    Err(format!(
        "capture timed out with {} expected payload(s) still pending",
        pending.len()
    )
    .into())
}

fn env_required(name: &str) -> std::result::Result<String, Box<dyn Error>> {
    env::var(name).map_err(|_| format!("missing required environment variable {name}").into())
}

fn env_value(name: &str, default_value: &str) -> String {
    env::var(name).unwrap_or_else(|_| default_value.to_string())
}

fn env_parse<T>(name: &str, default_value: T) -> std::result::Result<T, Box<dyn Error>>
where
    T: std::str::FromStr,
    T::Err: Error + 'static,
{
    Ok(match env::var(name) {
        Ok(value) => value.parse::<T>()?,
        Err(_) => default_value,
    })
}
'''


SENDER_SOURCE = r'''
use crafter::prelude::*;
use std::env;
use std::error::Error;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

fn main() -> std::result::Result<(), Box<dyn Error>> {
    let iface = env_value("IFACE", "eth0");
    let source_ip = env_parse("SOURCE_IP", Ipv4Addr::new(10, 79, 0, 10))?;
    let destination_ip = env_parse("DESTINATION_IP", Ipv4Addr::new(10, 79, 0, 20))?;
    let source_port = env_parse("SOURCE_PORT", 39000u16)?;
    let destination_port = env_parse("DESTINATION_PORT", 39001u16)?;
    let source_mac = MacAddr::from_str(&env_required("SOURCE_MAC")?)?;
    let destination_mac = MacAddr::from_str(&env_required("DESTINATION_MAC")?)?;
    let l3_payload = env_value("L3_PAYLOAD", "libcrafter-docker-smoke-l3");
    let l2_payload = env_value("L2_PAYLOAD", "libcrafter-docker-smoke-l2");

    let l3_packet = ipv4_udp_packet(
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        l3_payload.as_bytes(),
    );
    let l3_plan = l3_packet.send_dry_run(
        SendOptions::new()
            .iface(&iface)
            .network_layer()
            .write_timeout(Duration::from_secs(2)),
    )?;
    println!(
        "PLAN l3 len={} target={:?} summary={}",
        l3_plan.len(),
        l3_plan.target(),
        l3_packet.summary()
    );
    let l3_report = l3_packet.send(
        SendOptions::new()
            .iface(&iface)
            .network_layer()
            .write_timeout(Duration::from_secs(2)),
    )?;
    println!(
        "SENT l3 bytes={} dry_run={}",
        l3_report.bytes_sent(),
        l3_report.is_dry_run()
    );

    thread::sleep(Duration::from_millis(250));

    let l2_packet = Ethernet::new().src(source_mac).dst(destination_mac)
        / ipv4_udp_packet(
            source_ip,
            destination_ip,
            source_port + 1,
            destination_port,
            l2_payload.as_bytes(),
        );
    let l2_plan = l2_packet.send_dry_run(
        SendOptions::new()
            .iface(&iface)
            .link_layer()
            .write_timeout(Duration::from_secs(2)),
    )?;
    println!(
        "PLAN l2 len={} target={:?} summary={}",
        l2_plan.len(),
        l2_plan.target(),
        l2_packet.summary()
    );
    let l2_report = l2_packet.send(
        SendOptions::new()
            .iface(&iface)
            .link_layer()
            .write_timeout(Duration::from_secs(2)),
    )?;
    println!(
        "SENT l2 bytes={} dry_run={}",
        l2_report.bytes_sent(),
        l2_report.is_dry_run()
    );

    Ok(())
}

fn ipv4_udp_packet(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Packet {
    Ipv4::new().src(source_ip).dst(destination_ip)
        / Udp::new().sport(source_port).dport(destination_port)
        / Raw::from_bytes(payload)
}

fn env_required(name: &str) -> std::result::Result<String, Box<dyn Error>> {
    env::var(name).map_err(|_| format!("missing required environment variable {name}").into())
}

fn env_value(name: &str, default_value: &str) -> String {
    env::var(name).unwrap_or_else(|_| default_value.to_string())
}

fn env_parse<T>(name: &str, default_value: T) -> std::result::Result<T, Box<dyn Error>>
where
    T: std::str::FromStr,
    T::Err: Error + 'static,
{
    Ok(match env::var(name) {
        Ok(value) => value.parse::<T>()?,
        Err(_) => default_value,
    })
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
    wire = repo_root / "tools" / "wire" / "run"

    plan = _plan_commands(repo_root=repo_root, wire=wire, args=args)
    if not args.live or args.plan_only:
        print(plan)
        return 0

    if not args.i_understand_isolated_lab:
        print(
            "live Docker private smoke requires --live --i-understand-isolated-lab",
            file=sys.stderr,
        )
        print(plan, file=sys.stderr)
        return 2

    receiver_id: str | None = None
    sender_id: str | None = None
    artifact_dirs: list[Path] = []
    exit_code = 1

    try:
        receiver_create = _create_endpoint(
            wire=wire,
            repo_root=repo_root,
            role=args.receiver_role,
            private_group=args.private_group,
            private_ip=args.receiver_ip,
            timeout=args.create_timeout,
        )
        receiver_manifest = _endpoint_manifest(
            receiver_create.stdout, "receiver create-endpoint output"
        )
        receiver_id = _string(receiver_manifest.get("endpoint_id"), "receiver endpoint_id")
        receiver_artifact_dir = Path(
            _string(receiver_manifest.get("artifact_dir"), "receiver artifact_dir")
        )
        artifact_dirs.append(receiver_artifact_dir)
        _write_result_artifacts(receiver_artifact_dir, "create_receiver", receiver_create)
        if not receiver_create.ok:
            raise SmokeError("receiver endpoint creation failed", receiver_create.exit_code)

        sender_create = _create_endpoint(
            wire=wire,
            repo_root=repo_root,
            role=args.sender_role,
            private_group=args.private_group,
            private_ip=args.sender_ip,
            timeout=args.create_timeout,
        )
        sender_manifest = _endpoint_manifest(sender_create.stdout, "sender create-endpoint output")
        sender_id = _string(sender_manifest.get("endpoint_id"), "sender endpoint_id")
        sender_artifact_dir = Path(_string(sender_manifest.get("artifact_dir"), "sender artifact_dir"))
        artifact_dirs.append(sender_artifact_dir)
        _write_result_artifacts(sender_artifact_dir, "create_sender", sender_create)
        if not sender_create.ok:
            raise SmokeError("sender endpoint creation failed", sender_create.exit_code)

        receiver_iface = _private_endpoint(receiver_manifest)
        sender_iface = _private_endpoint(sender_manifest)
        if receiver_iface["ipv4"] != args.receiver_ip:
            raise SmokeError(
                f"receiver IPv4 mismatch: expected {args.receiver_ip}, got {receiver_iface['ipv4']}"
            )
        if sender_iface["ipv4"] != args.sender_ip:
            raise SmokeError(
                f"sender IPv4 mismatch: expected {args.sender_ip}, got {sender_iface['ipv4']}"
            )

        with tempfile.TemporaryDirectory(prefix="libcrafter-docker-private-smoke-") as temp_dir:
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
            for artifact_dir in artifact_dirs:
                _write_result_artifacts(artifact_dir, "build_workloads", build)
            if not build.ok:
                raise SmokeError("Docker private smoke workload build failed", build.exit_code)

            receiver_bin = workspace / "target" / "release" / RECEIVER_BIN
            sender_bin = workspace / "target" / "release" / SENDER_BIN
            _require_file(receiver_bin, "receiver workload")
            _require_file(sender_bin, "sender workload")

            upload_receiver = _run(
                [str(wire), "upload", receiver_id, str(receiver_bin), args.remote_receiver],
                cwd=repo_root,
                timeout=args.transfer_timeout,
            )
            _write_result_artifacts(receiver_artifact_dir, "upload_receiver", upload_receiver)
            if not upload_receiver.ok:
                raise SmokeError("receiver workload upload failed", upload_receiver.exit_code)

            upload_sender = _run(
                [str(wire), "upload", sender_id, str(sender_bin), args.remote_sender],
                cwd=repo_root,
                timeout=args.transfer_timeout,
            )
            _write_result_artifacts(sender_artifact_dir, "upload_sender", upload_sender)
            if not upload_sender.ok:
                raise SmokeError("sender workload upload failed", upload_sender.exit_code)

        chmod_receiver = _chmod_remote(
            wire=wire,
            repo_root=repo_root,
            endpoint_id=receiver_id,
            remote_bin=args.remote_receiver,
            timeout=args.exec_timeout,
        )
        _write_result_artifacts(receiver_artifact_dir, "chmod_receiver", chmod_receiver)
        if not chmod_receiver.ok:
            raise SmokeError("receiver chmod failed", chmod_receiver.exit_code)

        chmod_sender = _chmod_remote(
            wire=wire,
            repo_root=repo_root,
            endpoint_id=sender_id,
            remote_bin=args.remote_sender,
            timeout=args.exec_timeout,
        )
        _write_result_artifacts(sender_artifact_dir, "chmod_sender", chmod_sender)
        if not chmod_sender.ok:
            raise SmokeError("sender chmod failed", chmod_sender.exit_code)

        start_receiver = _run(
            [
                str(wire),
                "exec",
                receiver_id,
                "--",
                "sh",
                "-lc",
                _receiver_start_command(args, sender_iface["ipv4"]),
            ],
            cwd=repo_root,
            timeout=args.exec_timeout,
        )
        _write_result_artifacts(receiver_artifact_dir, "start_receiver", start_receiver)
        if not start_receiver.ok:
            raise SmokeError("receiver start failed", start_receiver.exit_code)

        wait_ready = _run(
            [
                str(wire),
                "exec",
                receiver_id,
                "--",
                "sh",
                "-lc",
                _receiver_ready_command(args.remote_artifact_dir, args.ready_attempts),
            ],
            cwd=repo_root,
            timeout=args.exec_timeout,
        )
        _write_result_artifacts(receiver_artifact_dir, "receiver_ready", wait_ready)
        if not wait_ready.ok:
            raise SmokeError("receiver did not become ready", wait_ready.exit_code)

        sender_run = _run(
            [
                str(wire),
                "exec",
                sender_id,
                "--",
                "sh",
                "-lc",
                _sender_run_command(args, sender_iface, receiver_iface),
            ],
            cwd=repo_root,
            timeout=args.packet_timeout,
        )
        _write_result_artifacts(sender_artifact_dir, "run_sender", sender_run)
        if not sender_run.ok:
            raise SmokeError("sender packet exchange failed", sender_run.exit_code)

        receiver_done = _run(
            [
                str(wire),
                "exec",
                receiver_id,
                "--",
                "sh",
                "-lc",
                _receiver_done_command(args.remote_artifact_dir, args.done_attempts),
            ],
            cwd=repo_root,
            timeout=args.packet_timeout,
        )
        _write_result_artifacts(receiver_artifact_dir, "receiver_done", receiver_done)
        if not receiver_done.ok:
            raise SmokeError("receiver did not observe both payloads", receiver_done.exit_code)

        collect_receiver = _collect_artifacts(
            wire=wire,
            repo_root=repo_root,
            endpoint_id=receiver_id,
            remote_artifact_dir=args.remote_artifact_dir,
            timeout=args.transfer_timeout,
        )
        _write_result_artifacts(receiver_artifact_dir, "collect_receiver", collect_receiver)
        if not collect_receiver.ok:
            raise SmokeError("receiver artifact collection failed", collect_receiver.exit_code)

        collect_sender = _collect_artifacts(
            wire=wire,
            repo_root=repo_root,
            endpoint_id=sender_id,
            remote_artifact_dir=args.remote_artifact_dir,
            timeout=args.transfer_timeout,
        )
        _write_result_artifacts(sender_artifact_dir, "collect_sender", collect_sender)
        if not collect_sender.ok:
            raise SmokeError("sender artifact collection failed", collect_sender.exit_code)

        summary = {
            "ok": True,
            "private_group": args.private_group,
            "receiver": {
                "endpoint_id": receiver_id,
                "iface": receiver_iface["name"],
                "ipv4": receiver_iface["ipv4"],
                "mac": receiver_iface["mac"],
                "artifact_dir": str(receiver_artifact_dir),
            },
            "sender": {
                "endpoint_id": sender_id,
                "iface": sender_iface["name"],
                "ipv4": sender_iface["ipv4"],
                "mac": sender_iface["mac"],
                "artifact_dir": str(sender_artifact_dir),
            },
            "payloads": [args.l3_payload, args.l2_payload],
            "remote_artifact_dir": args.remote_artifact_dir,
        }
        _write_json(receiver_artifact_dir / "docker_private_packet_exchange_smoke.json", summary)
        _write_json(sender_artifact_dir / "docker_private_packet_exchange_smoke.json", summary)
        print(json.dumps(summary, indent=2, sort_keys=True))
        exit_code = 0
    except SmokeError as exc:
        print(str(exc), file=sys.stderr)
        _write_failure_summary(
            artifact_dirs=artifact_dirs,
            error=str(exc),
            receiver_id=receiver_id,
            sender_id=sender_id,
            private_group=args.private_group,
        )
        exit_code = exc.exit_code
    finally:
        destroy_results = _destroy_endpoints(
            wire=wire,
            repo_root=repo_root,
            endpoint_ids=[endpoint_id for endpoint_id in (sender_id, receiver_id) if endpoint_id],
            artifact_dirs=artifact_dirs,
            timeout=args.destroy_timeout,
        )
        if exit_code == 0:
            for result in destroy_results:
                if not result.ok:
                    print(f"endpoint destroy failed: {result.command}", file=sys.stderr)
                    exit_code = result.exit_code
                    break

    return exit_code


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the protected Docker private L2/L3 packet exchange smoke.",
    )
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="print the command sequence without creating Docker resources",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="allow confirmed Docker private endpoint creation and packet send",
    )
    parser.add_argument(
        "--i-understand-isolated-lab",
        action="store_true",
        help="acknowledge this smoke creates a local isolated Docker packet lab",
    )
    parser.add_argument(
        "--private-group",
        default=os.environ.get("LIBCRAFTER_DOCKER_SMOKE_GROUP", DEFAULT_GROUP),
        help="docker/private coordination group",
    )
    parser.add_argument("--sender-role", default=DEFAULT_SENDER_ROLE)
    parser.add_argument("--receiver-role", default=DEFAULT_RECEIVER_ROLE)
    parser.add_argument("--sender-ip", default=DEFAULT_SENDER_IP)
    parser.add_argument("--receiver-ip", default=DEFAULT_RECEIVER_IP)
    parser.add_argument("--iface", default=DEFAULT_IFACE)
    parser.add_argument("--source-port", type=_uint16, default=DEFAULT_SOURCE_PORT)
    parser.add_argument("--destination-port", type=_uint16, default=DEFAULT_DESTINATION_PORT)
    parser.add_argument("--l3-payload", default=DEFAULT_L3_PAYLOAD)
    parser.add_argument("--l2-payload", default=DEFAULT_L2_PAYLOAD)
    parser.add_argument("--timeout-secs", type=_positive_int, default=DEFAULT_TIMEOUT_SECS)
    parser.add_argument("--remote-sender", default=DEFAULT_REMOTE_SENDER)
    parser.add_argument("--remote-receiver", default=DEFAULT_REMOTE_RECEIVER)
    parser.add_argument("--remote-artifact-dir", default=DEFAULT_REMOTE_ARTIFACT_DIR)
    parser.add_argument("--ready-attempts", type=_positive_int, default=50)
    parser.add_argument("--done-attempts", type=_positive_int, default=100)
    parser.add_argument("--create-timeout", type=float, default=300)
    parser.add_argument("--build-timeout", type=float, default=600)
    parser.add_argument("--transfer-timeout", type=float, default=120)
    parser.add_argument("--exec-timeout", type=float, default=120)
    parser.add_argument("--packet-timeout", type=float, default=90)
    parser.add_argument("--destroy-timeout", type=float, default=120)
    return parser.parse_args(argv)


def _plan_commands(*, repo_root: Path, wire: Path, args: argparse.Namespace) -> str:
    commands = [
        _create_endpoint_argv(
            wire=wire,
            role=args.receiver_role,
            private_group=args.private_group,
            private_ip=args.receiver_ip,
        ),
        _create_endpoint_argv(
            wire=wire,
            role=args.sender_role,
            private_group=args.private_group,
            private_ip=args.sender_ip,
        ),
        [
            "cargo",
            "build",
            "--release",
            "--manifest-path",
            "<generated-workload>/Cargo.toml",
        ],
        [str(wire), "upload", "<receiver_endpoint_id>", "<receiver_binary>", args.remote_receiver],
        [str(wire), "upload", "<sender_endpoint_id>", "<sender_binary>", args.remote_sender],
        [str(wire), "exec", "<receiver_endpoint_id>", "--", "chmod", "0755", args.remote_receiver],
        [str(wire), "exec", "<sender_endpoint_id>", "--", "chmod", "0755", args.remote_sender],
        [
            str(wire),
            "exec",
            "<receiver_endpoint_id>",
            "--",
            "sh",
            "-lc",
            _receiver_start_command(args, args.sender_ip),
        ],
        [
            str(wire),
            "exec",
            "<receiver_endpoint_id>",
            "--",
            "sh",
            "-lc",
            _receiver_ready_command(args.remote_artifact_dir, args.ready_attempts),
        ],
        [
            str(wire),
            "exec",
            "<sender_endpoint_id>",
            "--",
            "sh",
            "-lc",
            _sender_run_command(
                args,
                {
                    "name": args.iface,
                    "ipv4": args.sender_ip,
                    "mac": "<sender_mac>",
                },
                {
                    "name": args.iface,
                    "ipv4": args.receiver_ip,
                    "mac": "<receiver_mac>",
                },
            ),
        ],
        [
            str(wire),
            "exec",
            "<receiver_endpoint_id>",
            "--",
            "sh",
            "-lc",
            _receiver_done_command(args.remote_artifact_dir, args.done_attempts),
        ],
        [
            str(wire),
            "collect-artifacts",
            "<receiver_endpoint_id>",
            "--remote",
            args.remote_artifact_dir,
        ],
        [
            str(wire),
            "collect-artifacts",
            "<sender_endpoint_id>",
            "--remote",
            args.remote_artifact_dir,
        ],
        [str(wire), "destroy-endpoint", "<sender_endpoint_id>", "--json"],
        [str(wire), "destroy-endpoint", "<receiver_endpoint_id>", "--json"],
    ]
    lines = [
        "Docker private packet exchange smoke plan",
        f"repo: {repo_root}",
        "no Docker resources are created unless --live --i-understand-isolated-lab are both set",
        f"private group: {args.private_group}",
        f"sender: {args.sender_ip}",
        f"receiver: {args.receiver_ip}",
        "",
    ]
    lines.extend(f"{index}. {shlex.join(command)}" for index, command in enumerate(commands, 1))
    return "\n".join(lines)


def _create_endpoint(
    *,
    wire: Path,
    repo_root: Path,
    role: str,
    private_group: str,
    private_ip: str,
    timeout: float,
) -> CommandCapture:
    return _run(
        _create_endpoint_argv(
            wire=wire,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
        ),
        cwd=repo_root,
        timeout=timeout,
    )


def _create_endpoint_argv(
    *,
    wire: Path,
    role: str,
    private_group: str,
    private_ip: str,
) -> list[str]:
    return [
        str(wire),
        "create-endpoint",
        "--provider",
        "docker",
        "--exposure",
        "private",
        "--role",
        role,
        "--private-group",
        private_group,
        "--private-ip",
        private_ip,
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
                'name = "libcrafter-docker-private-smoke-workload"',
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
    (src_bin / f"{RECEIVER_BIN}.rs").write_text(RECEIVER_SOURCE.strip() + "\n", encoding="utf-8")
    (src_bin / f"{SENDER_BIN}.rs").write_text(SENDER_SOURCE.strip() + "\n", encoding="utf-8")


def _chmod_remote(
    *,
    wire: Path,
    repo_root: Path,
    endpoint_id: str,
    remote_bin: str,
    timeout: float,
) -> CommandCapture:
    return _run(
        [str(wire), "exec", endpoint_id, "--", "chmod", "0755", remote_bin],
        cwd=repo_root,
        timeout=timeout,
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


def _destroy_endpoints(
    *,
    wire: Path,
    repo_root: Path,
    endpoint_ids: list[str],
    artifact_dirs: list[Path],
    timeout: float,
) -> list[CommandCapture]:
    results: list[CommandCapture] = []
    seen: set[str] = set()
    for endpoint_id in endpoint_ids:
        if endpoint_id in seen:
            continue
        seen.add(endpoint_id)
        result = _run(
            [str(wire), "destroy-endpoint", endpoint_id, "--json"],
            cwd=repo_root,
            timeout=timeout,
        )
        results.append(result)
        for artifact_dir in artifact_dirs:
            _write_result_artifacts(artifact_dir, f"destroy_{endpoint_id}", result)
    return results


def _receiver_start_command(args: argparse.Namespace, sender_ip: str) -> str:
    log = f"{args.remote_artifact_dir}/receiver.log"
    pid = f"{args.remote_artifact_dir}/receiver.pid"
    env = _shell_env(
        {
            "IFACE": args.iface,
            "SOURCE_IP": sender_ip,
            "DESTINATION_PORT": str(args.destination_port),
            "TIMEOUT_SECS": str(args.timeout_secs),
            "EXPECTED_PAYLOADS": f"{args.l3_payload},{args.l2_payload}",
        }
    )
    return (
        "set -eu; "
        f"rm -rf {shlex.quote(args.remote_artifact_dir)}; "
        f"mkdir -p {shlex.quote(args.remote_artifact_dir)}; "
        f"nohup env {env} {shlex.quote(args.remote_receiver)} > {shlex.quote(log)} 2>&1 & "
        f"echo $! > {shlex.quote(pid)}"
    )


def _receiver_ready_command(remote_artifact_dir: str, attempts: int) -> str:
    log = f"{remote_artifact_dir}/receiver.log"
    return (
        "set -eu; "
        f"for _ in $(seq 1 {attempts}); do "
        f"if grep -q '^READY ' {shlex.quote(log)} 2>/dev/null; then "
        f"cat {shlex.quote(log)}; exit 0; "
        "fi; "
        "sleep 0.2; "
        "done; "
        f"cat {shlex.quote(log)} 2>/dev/null || true; "
        "exit 1"
    )


def _sender_run_command(
    args: argparse.Namespace,
    sender_iface: dict[str, str],
    receiver_iface: dict[str, str],
) -> str:
    log = f"{args.remote_artifact_dir}/sender.log"
    env = _shell_env(
        {
            "IFACE": sender_iface["name"],
            "SOURCE_IP": sender_iface["ipv4"],
            "DESTINATION_IP": receiver_iface["ipv4"],
            "SOURCE_PORT": str(args.source_port),
            "DESTINATION_PORT": str(args.destination_port),
            "SOURCE_MAC": sender_iface["mac"],
            "DESTINATION_MAC": receiver_iface["mac"],
            "L3_PAYLOAD": args.l3_payload,
            "L2_PAYLOAD": args.l2_payload,
        }
    )
    return (
        "set -eu; "
        f"rm -rf {shlex.quote(args.remote_artifact_dir)}; "
        f"mkdir -p {shlex.quote(args.remote_artifact_dir)}; "
        f"env {env} {shlex.quote(args.remote_sender)} > {shlex.quote(log)} 2>&1; "
        f"cat {shlex.quote(log)}"
    )


def _receiver_done_command(remote_artifact_dir: str, attempts: int) -> str:
    log = f"{remote_artifact_dir}/receiver.log"
    pid = f"{remote_artifact_dir}/receiver.pid"
    return (
        "set -eu; "
        f"pid=$(cat {shlex.quote(pid)}); "
        f"for _ in $(seq 1 {attempts}); do "
        "if ! kill -0 \"$pid\" 2>/dev/null; then "
        f"if grep -q 'PASS receiver observed all expected payloads' {shlex.quote(log)}; then "
        f"cat {shlex.quote(log)}; exit 0; "
        "fi; "
        f"cat {shlex.quote(log)}; exit 1; "
        "fi; "
        "sleep 0.2; "
        "done; "
        f"cat {shlex.quote(log)}; "
        "exit 124"
    )


def _shell_env(values: dict[str, str]) -> str:
    return " ".join(f"{name}={shlex.quote(value)}" for name, value in values.items())


def _private_endpoint(manifest: dict[str, Any]) -> dict[str, str]:
    interfaces = manifest.get("interfaces")
    if not isinstance(interfaces, list):
        raise SmokeError("create-endpoint output did not include interfaces")
    for interface in interfaces:
        if not isinstance(interface, dict) or interface.get("exposure") != "private":
            continue
        return {
            "name": _string(interface.get("name"), "private interface name"),
            "ipv4": _string(interface.get("ipv4"), "private interface ipv4"),
            "mac": _string(interface.get("mac"), "private interface mac"),
        }
    raise SmokeError("create-endpoint output did not include a private interface")


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


def _write_failure_summary(
    *,
    artifact_dirs: list[Path],
    error: str,
    receiver_id: str | None,
    sender_id: str | None,
    private_group: str,
) -> None:
    for artifact_dir in artifact_dirs:
        _write_json(
            artifact_dir / "docker_private_packet_exchange_smoke.json",
            {
                "ok": False,
                "private_group": private_group,
                "receiver_endpoint_id": receiver_id,
                "sender_endpoint_id": sender_id,
                "error": error,
            },
        )


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


def _require_file(path: Path, name: str) -> None:
    if not path.is_file():
        raise SmokeError(f"{name} not found after build: {path}")


def _safe_stem(value: str) -> str:
    safe = "".join(character if character.isalnum() or character in "._-" else "_" for character in value)
    return safe or "artifact"


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


def _output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
