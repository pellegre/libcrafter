"""Scapy dependency discovery and bootstrap for the oracle backend."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from types import ModuleType
from typing import Any

from ...model import JSONObject


SCAPY_REQUIREMENT = "scapy>=2.5,<3"
PYYAML_REQUIREMENT = "PyYAML>=6.0,<7"
PYTEST_REQUIREMENT = "pytest>=8,<10"
# Scapy's IPSec SecurityAssociation (scapy.layers.ipsec) seals ESP/AH with the
# ``cryptography`` library; without it only the NULL cipher/auth are available
# and AES-GCM/AES-CBC/HMAC sealing raises. Pin it so the ESP/AH oracle backend
# can produce byte-parity ciphertext + ICV against libcrafter.
CRYPTOGRAPHY_REQUIREMENT = "cryptography>=42,<46"
BACKEND_PYTHON_REQUIREMENTS = (
    SCAPY_REQUIREMENT,
    PYYAML_REQUIREMENT,
    PYTEST_REQUIREMENT,
    CRYPTOGRAPHY_REQUIREMENT,
)
BOOTSTRAPPED_ENV = "LIBCRAFTER_SCAPY_BOOTSTRAPPED"
BOOTSTRAP_SOURCE_ENV = "LIBCRAFTER_SCAPY_BOOTSTRAP_SOURCE"


class ScapyBootstrapError(RuntimeError):
    """Raised when Scapy is still unavailable after bootstrap."""


def import_scapy() -> dict[str, Any]:
    """Import Scapy, bootstrapping the dependency if needed."""

    try:
        import scapy  # type: ignore[import-untyped]
        import scapy.all as scapy_all  # type: ignore[import-untyped]
        import scapy.contrib.bgp as scapy_bgp  # type: ignore[import-untyped]
        import scapy.contrib.ospf as scapy_ospf  # type: ignore[import-untyped]
        import scapy.layers.rip as scapy_rip  # type: ignore[import-untyped]
        from scapy.all import conf  # type: ignore[import-untyped]
        # Load the RIP layer explicitly so RIP/RIPEntry/RIPAuth are available to
        # the materializer regardless of lazy contrib loading.
        from scapy.layers.rip import (  # type: ignore[import-untyped]  # noqa: F401
            RIP,
            RIPAuth,
            RIPEntry,
        )
    except ModuleNotFoundError as exc:
        if exc.name != "scapy":
            raise
        _reexec_with_scapy()
        raise ScapyBootstrapError("unreachable after Scapy bootstrap re-exec")

    conf.verb = 0
    return {
        "module": scapy,
        "all": scapy_all,
        "bgp": scapy_bgp,
        "ospf": scapy_ospf,
        "rip": scapy_rip,
        "version": _scapy_version(scapy),
        "metadata": scapy_report_metadata(scapy),
    }


def scapy_report_metadata(scapy_module: ModuleType | None = None) -> JSONObject:
    """Return JSON-compatible Scapy metadata for oracle reports."""

    version = "unknown"
    if scapy_module is not None:
        version = _scapy_version(scapy_module)

    source = os.environ.get(BOOTSTRAP_SOURCE_ENV, "current-python")
    bootstrapped = os.environ.get(BOOTSTRAPPED_ENV) == "1"
    metadata: JSONObject = {
        "backend": "scapy",
        "scapy_requirement": SCAPY_REQUIREMENT,
        "scapy_version": version,
        "python_executable": sys.executable,
        "python_version": platform.python_version(),
        "bootstrap": {
            "bootstrapped": bootstrapped,
            "source": source,
        },
    }

    if source == "uv":
        uv_path = shutil.which(os.environ.get("ORACLE_UV", "uv"))
        metadata["bootstrap"]["uv"] = uv_path or "unknown"

    return metadata


def backend_info() -> JSONObject:
    """Return Scapy backend metadata, bootstrapping Scapy if necessary."""

    scapy = import_scapy()
    metadata = scapy["metadata"]
    if not isinstance(metadata, dict):
        raise TypeError("Scapy metadata did not serialize to an object")
    return metadata


def _scapy_version(scapy_module: ModuleType) -> str:
    version = getattr(scapy_module, "__version__", "unknown")
    return str(version)


def _reexec_with_scapy() -> None:
    if os.environ.get(BOOTSTRAPPED_ENV) == "1":
        raise ScapyBootstrapError("Scapy is not importable after dependency bootstrap")

    uv = shutil.which(os.environ.get("ORACLE_UV", "uv"))
    if uv is None:
        raise ScapyBootstrapError(
            "Scapy is not importable and uv is required to bootstrap oracle backend "
            "dependencies"
        )

    env = _bootstrap_env("uv")
    with_args: list[str] = []
    for requirement in BACKEND_PYTHON_REQUIREMENTS:
        with_args.extend(("--with", requirement))
    os.execvpe(
        uv,
        [
            uv,
            "run",
            "--quiet",
            "--no-project",
            *with_args,
            "--",
            os.environ.get("ORACLE_PYTHON", "python3"),
            *_reexec_python_args(),
        ],
        env,
    )


def _bootstrap_env(source: str) -> dict[str, str]:
    env = os.environ.copy()
    env[BOOTSTRAPPED_ENV] = "1"
    env[BOOTSTRAP_SOURCE_ENV] = source
    env.setdefault("UV_NO_PROGRESS", "1")
    return env


def _reexec_python_args() -> list[str]:
    main_module = sys.modules.get("__main__")
    module_spec = getattr(main_module, "__spec__", None)
    module_name = getattr(module_spec, "name", None)
    argv0 = sys.argv[0] if sys.argv else ""
    if module_name in {"pytest", "pytest.__main__"} or "pytest" in argv0:
        return ["-m", "pytest", *sys.argv[1:]]
    if module_name:
        return ["-m", module_name, *sys.argv[1:]]
    if not sys.argv:
        raise ScapyBootstrapError("cannot determine current Python entrypoint")
    return [sys.argv[0], *sys.argv[1:]]
