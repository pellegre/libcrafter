"""Structural lock for the per-protocol plugin refactor.

This test is the final guard of the oracle protocol-plugin refactor. It pins the
*achieved* plug-and-play structure so that future changes cannot silently regrow
the previously monolithic engine files or re-introduce a central dispatcher.

It is intentionally offline and Scapy-free: every file is inspected with
``pathlib`` (read + ``splitlines``) rather than imported, so it runs under the
bare-interpreter gate without Scapy, tshark, or network access.

Bounds rationale
----------------
The previously monolithic files were decomposed into small per-protocol plugin
modules (steps 12-44) and the large ``cli.py`` was split into a package
(steps 47-49). The line-count bounds below are each set to roughly ``1.2x`` the
file's *current* post-refactor size, i.e. they lock against ~20% regrowth at the
sizes actually achieved. They are NOT a target to shrink toward; they exist only
to fail loudly if a file starts regrowing back toward a monolith.

``cli/main.py`` is deliberately large (~8.7k lines). The live-provider machinery
is mock-patch-coupled to the ``cli`` module via the step-47 ``sys.modules``
identity alias, so it cannot be physically relocated without breaking
``unittest.mock.patch.object(cli, ...)`` parity. That is an inherent test-design
constraint, not a refactor failure -- the bound here locks ``cli/main.py``
against regrowth at its real, large size; it does not assert that it is small.
"""

from __future__ import annotations

import math
import unittest
from pathlib import Path

# Worktree/repo root: this file lives at tools/oracle/tests/<file>, so three
# parents up is the repository root that contains tools/.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_ENGINE = _REPO_ROOT / "tools" / "oracle" / "engine"

# Per-stage per-protocol plugin directories.
_PROTOCOL_DIRS = {
    "engine/protocols": _ENGINE / "protocols",
    "engine/backends/scapy/protocols": _ENGINE / "backends" / "scapy" / "protocols",
    "engine/backends/wireshark/protocols": _ENGINE
    / "backends"
    / "wireshark"
    / "protocols",
}

# Minimum number of per-protocol modules each stage directory must hold (counting
# *.py excluding __init__.py and base.py). Floors are set a little below the
# achieved counts (18 / 18 / 12 at lock time) so dropping a plugin trips the
# guard while normal growth does not.
_PROTOCOL_DIR_FLOORS = {
    "engine/protocols": 16,
    "engine/backends/scapy/protocols": 16,
    "engine/backends/wireshark/protocols": 10,
}

# Locked line-count bounds for the previously monolithic engine files. Each bound
# is ceil(current_size * 1.2); see the module docstring for the rationale. The
# achieved sizes at lock time are noted in the trailing comments.
_LINE_BOUNDS = {
    "engine/generator.py": 2950,  # achieved 2458
    "engine/backends/scapy/packets.py": 1061,  # achieved 884
    "engine/backends/scapy/normalize.py": 3737,  # achieved 3114
    "engine/backends/wireshark/normalize.py": 544,  # achieved 453
    # cli/*.py -- main.py is large by design (live-provider mock-patch coupling);
    # the bound locks it against regrowth, it does NOT assert a small file.
    "engine/cli/main.py": 10479,  # achieved 8732
    "engine/cli/__init__.py": 41,  # achieved 34
    "engine/cli/__main__.py": 9,  # achieved 7
    "engine/cli/options.py": 102,  # achieved 85
}

# Generous per-file cap so individual protocol plugins stay small. The largest
# plugin at lock time is protocols/dns.py at 1274 lines; the cap sits above it.
_PLUGIN_FILE_CAP = 1500


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def _plugin_modules(directory: Path) -> list[Path]:
    return [
        p
        for p in sorted(directory.glob("*.py"))
        if p.name not in {"__init__.py", "base.py"}
    ]


class EngineModuleSizesTest(unittest.TestCase):
    def test_protocol_plugin_directories_are_populated(self) -> None:
        for rel, directory in _PROTOCOL_DIRS.items():
            with self.subTest(directory=rel):
                self.assertTrue(
                    directory.is_dir(),
                    f"expected per-protocol plugin directory {rel} to exist",
                )
                modules = _plugin_modules(directory)
                floor = _PROTOCOL_DIR_FLOORS[rel]
                self.assertGreaterEqual(
                    len(modules),
                    floor,
                    f"{rel} has {len(modules)} protocol modules; expected at least "
                    f"{floor} -- a dropped plugin or merged-back dispatcher would "
                    f"trip this. Modules: {[p.name for p in modules]}",
                )

    def test_monolithic_files_under_locked_bounds(self) -> None:
        for rel, bound in _LINE_BOUNDS.items():
            with self.subTest(file=rel):
                path = _ENGINE / Path(rel).relative_to("engine")
                self.assertTrue(path.is_file(), f"expected {rel} to exist")
                count = _line_count(path)
                self.assertLessEqual(
                    count,
                    bound,
                    f"{rel} has {count} lines, exceeding the regrowth lock of "
                    f"{bound} (~1.2x the achieved post-refactor size). If this is "
                    f"intentional growth, re-derive the bound; do not just raise it "
                    f"to make the test pass.",
                )

    def test_plugin_modules_stay_small(self) -> None:
        for rel, directory in _PROTOCOL_DIRS.items():
            for module in _plugin_modules(directory):
                with self.subTest(module=f"{rel}/{module.name}"):
                    count = _line_count(module)
                    self.assertLessEqual(
                        count,
                        _PLUGIN_FILE_CAP,
                        f"{rel}/{module.name} has {count} lines, exceeding the "
                        f"per-plugin cap of {_PLUGIN_FILE_CAP}. A protocol plugin "
                        f"this large suggests logic that belongs in shared helpers "
                        f"or a separate module.",
                    )

    def test_generator_has_no_central_field_table(self) -> None:
        # The legacy central field table was removed when sampling moved to
        # per-protocol plugins (step 40); its absence is part of the plug-and-play
        # end state. Inspect source rather than importing so this stays Scapy-free.
        source = (_ENGINE / "generator.py").read_text(encoding="utf-8")
        self.assertNotIn(
            "_SUPPORTED_FIELDS",
            source,
            "generator.py still references _SUPPORTED_FIELDS; the central field "
            "table must stay gone now that sampling is plugin-driven.",
        )

    def test_line_bounds_are_consistent_with_ratio(self) -> None:
        # Guard the lock itself: every bound must be exactly ceil(achieved * 1.2)
        # for the size noted in the comment, so the intent ("~20% headroom over the
        # achieved size") cannot drift unexplained. achieved sizes mirror the
        # trailing comments above.
        achieved = {
            "engine/generator.py": 2458,
            "engine/backends/scapy/packets.py": 884,
            "engine/backends/scapy/normalize.py": 3114,
            "engine/backends/wireshark/normalize.py": 453,
            "engine/cli/main.py": 8732,
            "engine/cli/__init__.py": 34,
            "engine/cli/__main__.py": 7,
            "engine/cli/options.py": 85,
        }
        self.assertEqual(set(achieved), set(_LINE_BOUNDS))
        for rel, size in achieved.items():
            with self.subTest(file=rel):
                self.assertEqual(
                    _LINE_BOUNDS[rel],
                    math.ceil(size * 1.2),
                    f"{rel} bound {_LINE_BOUNDS[rel]} is not ceil({size} * 1.2); "
                    f"keep the ~20% regrowth headroom intent intact.",
                )


if __name__ == "__main__":
    unittest.main()
