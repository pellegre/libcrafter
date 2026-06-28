"""Check that a network interface exists through an inspectable sysfs root."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TextIO

from tools.appliance.checks.common import environment, failure, resolve_value, write_json


CHECK_NAME = "interface-exists"
DEFAULT_IFACE_ENV = "LIBCRAFTER_IFACE"
DEFAULT_SYSFS_ROOT = "/sys/class/net"


def check_interface_exists(iface: str, *, sysfs_root: str = DEFAULT_SYSFS_ROOT) -> dict[str, object]:
    """Return a structured readiness result for one interface name."""

    interface_path = Path(sysfs_root) / iface
    exists = interface_path.exists()
    if not exists:
        return failure(
            CHECK_NAME,
            "missing_interface",
            f"network interface does not exist: {iface}",
            iface=iface,
            sysfs_root=sysfs_root,
            interface_path=str(interface_path),
            exists=False,
        )
    return {
        "ok": True,
        "check": CHECK_NAME,
        "iface": iface,
        "sysfs_root": sysfs_root,
        "interface_path": str(interface_path),
        "exists": True,
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO = sys.stdout,
) -> int:
    """Run the interface-exists check and emit one JSON result."""

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
        )
        write_json(payload, stdout)
        return 1

    payload = check_interface_exists(iface, sysfs_root=args.sysfs_root)
    if iface_env:
        payload["iface_env"] = iface_env
    write_json(payload, stdout)
    return 0 if payload["ok"] else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check network interface presence.")
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
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
