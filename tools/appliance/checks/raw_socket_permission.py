"""Check whether raw socket creation is permitted without sending traffic."""

from __future__ import annotations

import argparse
import socket
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import TextIO

from tools.appliance.checks.common import failure, write_json


CHECK_NAME = "raw-socket-permission"
RawSocketOpener = Callable[[str], object]


def check_raw_socket_permission(
    *,
    family: str = "ipv4",
    opener: RawSocketOpener | None = None,
) -> dict[str, object]:
    """Return a structured readiness result for raw socket creation."""

    try:
        sock = _open_raw_socket(family) if opener is None else opener(family)
        close = getattr(sock, "close", None)
        if callable(close):
            close()
    except PermissionError as exc:
        return failure(
            CHECK_NAME,
            "raw_socket_permission_denied",
            "raw socket creation is not permitted",
            family=family,
            errno=exc.errno,
        )
    except OSError as exc:
        return failure(
            CHECK_NAME,
            "raw_socket_open_failed",
            str(exc),
            family=family,
            errno=exc.errno,
        )

    return {
        "ok": True,
        "check": CHECK_NAME,
        "family": family,
        "live_transmit": False,
        "opened": True,
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO = sys.stdout,
    opener: RawSocketOpener | None = None,
) -> int:
    """Run the raw socket permission check and emit one JSON result."""

    del environ
    args = _parser().parse_args(argv)
    payload = check_raw_socket_permission(family=args.family, opener=opener)
    write_json(payload, stdout)
    return 0 if payload["ok"] else 1


def _open_raw_socket(family: str) -> socket.socket:
    if family == "ipv6":
        return socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
    return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check raw socket creation permission.")
    parser.add_argument("--family", choices=("ipv4", "ipv6"), default="ipv4")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
