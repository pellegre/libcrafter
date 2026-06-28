"""Check that a WHAD-style serial device path is present and readable."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TextIO


CHECK_NAME = "serial-device-exists"
DEFAULT_DEVICE_ENV = "LIBCRAFTER_WHAD_DEVICE"


def check_serial_device(device: str) -> dict[str, object]:
    """Return a structured readiness result for one serial device path."""

    path = Path(device)
    if not path.exists():
        return _failure(
            "missing_serial_device",
            device,
            f"serial device does not exist: {device}",
            exists=False,
            readable=False,
            character_device=False,
        )

    readable = os.access(path, os.R_OK)
    character_device = stat.S_ISCHR(path.stat().st_mode)
    if not readable:
        return _failure(
            "serial_device_not_readable",
            device,
            f"serial device is not readable: {device}",
            exists=True,
            readable=False,
            character_device=character_device,
        )

    return {
        "ok": True,
        "check": CHECK_NAME,
        "device": device,
        "exists": True,
        "readable": True,
        "character_device": character_device,
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO = sys.stdout,
) -> int:
    """Run the serial-device check and emit one JSON result."""

    args = _parser().parse_args(argv)
    env = os.environ if environ is None else environ
    device = args.device
    if not device:
        device = env.get(args.device_env, "")
        if not device:
            payload = _failure(
                "missing_device_env",
                "",
                f"{args.device_env} is not set",
                exists=False,
                readable=False,
                character_device=False,
                device_env=args.device_env,
            )
            _write_json(payload, stdout)
            return 1

    payload = check_serial_device(device)
    _write_json(payload, stdout)
    return 0 if payload["ok"] else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check serial device readiness.")
    parser.add_argument("--device", default="", help="serial device path to check")
    parser.add_argument(
        "--device-env",
        default=DEFAULT_DEVICE_ENV,
        help="environment variable that names the serial device path",
    )
    return parser


def _failure(
    error: str,
    device: str,
    message: str,
    *,
    exists: bool,
    readable: bool,
    character_device: bool,
    device_env: str = "",
) -> dict[str, object]:
    payload: dict[str, object] = {
        "ok": False,
        "check": CHECK_NAME,
        "error": error,
        "message": message,
        "device": device,
        "exists": exists,
        "readable": readable,
        "character_device": character_device,
    }
    if device_env:
        payload["device_env"] = device_env
    return payload


def _write_json(payload: Mapping[str, object], stdout: TextIO) -> None:
    stdout.write(json.dumps(payload, indent=2, sort_keys=True))
    stdout.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
