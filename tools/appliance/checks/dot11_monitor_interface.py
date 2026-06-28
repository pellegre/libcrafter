"""Check that an 802.11 interface is already in monitor mode."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TextIO

from tools.appliance.checks.common import (
    CommandRunner,
    command_fields,
    environment,
    failure,
    resolve_value,
    run_command,
    write_json,
)


CHECK_NAME = "dot11-monitor-interface"
DEFAULT_IFACE_ENV = "LIBCRAFTER_DOT11_IFACE"
DEFAULT_SYSFS_ROOT = "/sys/class/net"
ARPHRD_IEEE80211_RADIOTAP = "803"


def check_dot11_monitor_interface(
    iface: str,
    *,
    sysfs_root: str = DEFAULT_SYSFS_ROOT,
    iw: str = "iw",
    runner: CommandRunner | None = None,
) -> dict[str, object]:
    """Return a structured readiness result for one prepared monitor interface."""

    interface_path = Path(sysfs_root) / iface
    if not interface_path.exists():
        return failure(
            CHECK_NAME,
            "missing_interface",
            f"network interface does not exist: {iface}",
            iface=iface,
            sysfs_root=sysfs_root,
            interface_path=str(interface_path),
            exists=False,
            monitor_mode=False,
        )

    type_path = interface_path / "type"
    if type_path.exists():
        interface_type = type_path.read_text(encoding="utf-8").strip()
        monitor_mode = interface_type == ARPHRD_IEEE80211_RADIOTAP
        if monitor_mode:
            return {
                "ok": True,
                "check": CHECK_NAME,
                "iface": iface,
                "sysfs_root": sysfs_root,
                "interface_path": str(interface_path),
                "exists": True,
                "monitor_mode": True,
                "interface_type": interface_type,
                "source": "sysfs-type",
            }
        if runner is None:
            return failure(
                CHECK_NAME,
                "interface_not_monitor_mode",
                f"network interface is not in monitor mode: {iface}",
                iface=iface,
                sysfs_root=sysfs_root,
                interface_path=str(interface_path),
                exists=True,
                monitor_mode=False,
                interface_type=interface_type,
                source="sysfs-type",
            )
    else:
        interface_type = ""

    command_argv = [iw, "dev", iface, "info"]
    result = run_command(command_argv, runner=runner)
    fields = command_fields(result)
    fields["command_argv"] = command_argv
    fields["iface"] = iface
    fields["sysfs_root"] = sysfs_root
    fields["interface_path"] = str(interface_path)
    fields["exists"] = True
    fields["interface_type"] = interface_type
    fields["source"] = "iw"
    if result.returncode != 0:
        return failure(
            CHECK_NAME,
            "monitor_mode_inspection_failed",
            "iw could not inspect interface mode",
            monitor_mode=False,
            **fields,
        )
    monitor_mode = any(line.strip() == "type monitor" for line in result.stdout.splitlines())
    if not monitor_mode:
        return failure(
            CHECK_NAME,
            "interface_not_monitor_mode",
            f"network interface is not in monitor mode: {iface}",
            monitor_mode=False,
            **fields,
        )
    return {
        "ok": True,
        "check": CHECK_NAME,
        "monitor_mode": True,
        **fields,
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO = sys.stdout,
    runner: CommandRunner | None = None,
) -> int:
    """Run the monitor-interface check and emit one JSON result."""

    args = _parser().parse_args(argv)
    env = environment(environ)
    iface, iface_env = resolve_value(explicit=args.iface, env_name=args.iface_env, environ=env)
    if not iface:
        payload = failure(
            CHECK_NAME,
            "missing_interface_env",
            f"{args.iface_env} is not set",
            iface="",
            iface_env=args.iface_env,
            sysfs_root=args.sysfs_root,
            exists=False,
            monitor_mode=False,
        )
        write_json(payload, stdout)
        return 1

    payload = check_dot11_monitor_interface(
        iface,
        sysfs_root=args.sysfs_root,
        iw=args.iw,
        runner=runner,
    )
    if iface_env:
        payload["iface_env"] = iface_env
    write_json(payload, stdout)
    return 0 if payload["ok"] else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check dot11 monitor-mode interface readiness.")
    parser.add_argument("--iface", default="", help="interface name to check")
    parser.add_argument(
        "--iface-env",
        default=DEFAULT_IFACE_ENV,
        help="environment variable that names the interface",
    )
    parser.add_argument(
        "--sysfs-root",
        default=DEFAULT_SYSFS_ROOT,
        help="sysfs network class root to inspect",
    )
    parser.add_argument("--iw", default="iw", help="iw command for fallback inspection")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
