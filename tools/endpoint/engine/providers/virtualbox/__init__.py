"""VirtualBox endpoint provider lifecycle operations."""

from __future__ import annotations

from .create import create_endpoint
from .destroy import destroy_endpoint
from .doctor import doctor
from .resources import cli_output_manifest

__all__ = [
    "cli_output_manifest",
    "create_endpoint",
    "destroy_endpoint",
    "doctor",
]
