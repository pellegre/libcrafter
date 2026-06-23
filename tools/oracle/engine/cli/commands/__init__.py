"""Per-subcommand modules for the oracle CLI.

Each module here exposes a ``register(subparsers)`` function that adds one
top-level subcommand's parser to the shared ``argparse`` subparser action and
wires its ``func`` default to the handler. The handlers themselves remain in
:mod:`..main` so that ``unittest.mock.patch.object(cli, "<helper>")`` continues
to patch the very globals the handler bodies read by name; these modules only
move the parser wiring out of ``build_parser``.

:func:`register_all` invokes every command module's ``register`` in the order
``build_parser`` historically declared them, preserving the command surface and
help ordering byte-for-byte.
"""

from __future__ import annotations

import argparse

from . import (
    backend_info,
    corpus,
    generate,
    live,
    offline,
    pcap,
    report,
    self_check,
    specs,
)

# Registration order matches the original ``build_parser`` declaration order so
# ``--help`` output and subcommand listing stay byte-identical.
_COMMAND_MODULES = (
    generate,
    corpus,
    offline,
    pcap,
    live,
    backend_info,
    specs,
    report,
    self_check,
)


def register_all(subparsers: argparse._SubParsersAction) -> None:
    for module in _COMMAND_MODULES:
        module.register(subparsers)
