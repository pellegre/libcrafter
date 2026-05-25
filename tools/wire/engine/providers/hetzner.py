"""Hetzner provider checks for wire endpoints."""

from __future__ import annotations

import os
import shutil
from collections.abc import Mapping

from ..registry import validate_request


TOKEN_ENV = "HETZNER_API_TOKEN"
HCLOUD_COMMAND = "hcloud"


def doctor(
    *,
    provider: str,
    exposure: str,
    dry_run: bool = False,
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Return non-mutating Hetzner provider prerequisite checks."""

    validate_request(provider, exposure)

    environ = os.environ if env is None else env
    hcloud_path = shutil.which(HCLOUD_COMMAND)
    token_configured = bool(environ.get(TOKEN_ENV))
    credential_required = not dry_run

    checks: list[dict[str, object]] = [
        {
            "name": "provider_exposure",
            "ok": True,
            "message": f"{provider}/{exposure} is supported",
        },
        {
            "name": "hcloud_installed",
            "ok": hcloud_path is not None,
            "message": (
                f"{HCLOUD_COMMAND} found at {hcloud_path}"
                if hcloud_path is not None
                else f"{HCLOUD_COMMAND} was not found on PATH"
            ),
        },
        {
            "name": "hetzner_api_token",
            "ok": token_configured or dry_run,
            "message": (
                f"{TOKEN_ENV} is configured"
                if token_configured
                else f"{TOKEN_ENV} is not configured"
            ),
        },
    ]

    return {
        "provider": provider,
        "exposure": exposure,
        "dry_run": dry_run,
        "ok": all(bool(check["ok"]) for check in checks),
        "checks": checks,
        "hcloud": {
            "command": HCLOUD_COMMAND,
            "installed": hcloud_path is not None,
            "path": hcloud_path,
        },
        "credentials": {
            "env": TOKEN_ENV,
            "configured": token_configured,
            "required": credential_required,
        },
    }
