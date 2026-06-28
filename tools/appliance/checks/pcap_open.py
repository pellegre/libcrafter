"""Check whether libpcap can open an interface without capturing packets."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import TextIO

from tools.appliance.checks.common import environment, failure, resolve_value, write_json


CHECK_NAME = "pcap-open"
DEFAULT_IFACE_ENV = "LIBCRAFTER_IFACE"
PCAP_ERRBUF_SIZE = 256
PcapOpener = Callable[[str], Mapping[str, object]]


class PcapOpenError(RuntimeError):
    """Raised when libpcap cannot open an interface."""

    def __init__(self, error: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.error = error
        self.details = details


def check_pcap_open(
    iface: str,
    *,
    opener: PcapOpener | None = None,
) -> dict[str, object]:
    """Return a structured readiness result for opening one pcap interface."""

    try:
        details = dict(_open_pcap_interface(iface) if opener is None else opener(iface))
    except PcapOpenError as exc:
        return failure(
            CHECK_NAME,
            exc.error,
            str(exc),
            iface=iface,
            **exc.details,
        )
    except OSError as exc:
        return failure(
            CHECK_NAME,
            "pcap_open_failed",
            str(exc),
            iface=iface,
            errno=exc.errno,
        )

    return {
        "ok": True,
        "check": CHECK_NAME,
        "iface": iface,
        "live_transmit": False,
        **details,
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO = sys.stdout,
    opener: PcapOpener | None = None,
) -> int:
    """Run the pcap-open check and emit one JSON result."""

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
            live_transmit=False,
        )
        write_json(payload, stdout)
        return 1

    payload = check_pcap_open(iface, opener=opener)
    if iface_env:
        payload["iface_env"] = iface_env
    write_json(payload, stdout)
    return 0 if payload["ok"] else 1


def _open_pcap_interface(iface: str) -> Mapping[str, object]:
    libpcap_path = ctypes.util.find_library("pcap")
    if not libpcap_path:
        raise PcapOpenError("libpcap_not_found", "libpcap shared library was not found")

    libpcap = ctypes.CDLL(libpcap_path)
    libpcap.pcap_create.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    libpcap.pcap_create.restype = ctypes.c_void_p
    libpcap.pcap_set_snaplen.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libpcap.pcap_set_snaplen.restype = ctypes.c_int
    libpcap.pcap_set_promisc.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libpcap.pcap_set_promisc.restype = ctypes.c_int
    libpcap.pcap_set_timeout.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libpcap.pcap_set_timeout.restype = ctypes.c_int
    libpcap.pcap_activate.argtypes = [ctypes.c_void_p]
    libpcap.pcap_activate.restype = ctypes.c_int
    libpcap.pcap_geterr.argtypes = [ctypes.c_void_p]
    libpcap.pcap_geterr.restype = ctypes.c_char_p
    libpcap.pcap_close.argtypes = [ctypes.c_void_p]
    libpcap.pcap_close.restype = None

    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    handle = libpcap.pcap_create(iface.encode("utf-8"), errbuf)
    if not handle:
        message = errbuf.value.decode("utf-8", errors="replace") or "pcap_create failed"
        raise PcapOpenError("pcap_create_failed", message)

    try:
        libpcap.pcap_set_snaplen(handle, 64)
        libpcap.pcap_set_promisc(handle, 0)
        libpcap.pcap_set_timeout(handle, 1)
        status = int(libpcap.pcap_activate(handle))
        if status < 0:
            error = libpcap.pcap_geterr(handle)
            message = error.decode("utf-8", errors="replace") if error else "pcap_activate failed"
            raise PcapOpenError("pcap_activate_failed", message, pcap_status=status)
    finally:
        libpcap.pcap_close(handle)

    return {
        "backend": "libpcap",
        "pcap_status": status,
        "promisc": False,
        "snaplen": 64,
        "timeout_ms": 1,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check libpcap interface opening.")
    parser.add_argument("--iface", default="", help="interface name to open")
    parser.add_argument(
        "--iface-env",
        default=DEFAULT_IFACE_ENV,
        help="environment variable that names the interface",
    )
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
