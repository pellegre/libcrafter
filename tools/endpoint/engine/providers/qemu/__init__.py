"""QEMU endpoint provider lifecycle operations."""

from __future__ import annotations

from .assets import (
    inspect_qemu_asset,
    plan_start_qemu_asset,
    qemu_asset_metadata,
    start_qemu_asset,
    stop_qemu_asset,
)
from .create import create_endpoint
from .destroy import destroy_endpoint
from .doctor import doctor
from .resources import cli_output_manifest

__all__ = [
    "cli_output_manifest",
    "create_endpoint",
    "destroy_endpoint",
    "doctor",
    "inspect_qemu_asset",
    "plan_start_qemu_asset",
    "qemu_asset_metadata",
    "start_qemu_asset",
    "stop_qemu_asset",
]
