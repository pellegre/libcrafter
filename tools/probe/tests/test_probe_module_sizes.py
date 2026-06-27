"""Structural size/shape lock for the probe protocol-plugin layout.

This guard pins the plug-and-play outcome of the probe refactor against silent
regression. It is pure ``pathlib`` line counting with no engine imports so it
runs fully offline (no uv/cargo, no heavy deps). It asserts that:

* the per-protocol plugin directory is populated (one module per protocol);
* each previously monolithic engine file stays under a regrowth bound locked at
  the achieved size (``ceil(current * 1.2)``);
* no individual plugin module is oversized;
* the registry is the sole protocol source -- ``cases.py`` no longer defines any
  ``BEHAVIOR_<P>_CASES`` per-protocol tuple (the dispatchers/tables removed in
  steps 38-43 stay gone).

The bounds below lock the files against regrowth at their *achieved* sizes after
the refactor (steps 38-48); they are deliberately ~20% headroom over the current
line counts, not an assertion that any file is "small". A file that is
legitimately large (e.g. the mock-patch-coupled ``cli/main.py``) is bounded at
its achieved size, not forced down.
"""

from __future__ import annotations

import math
import re
import unittest
from pathlib import Path

# tools/probe/tests/test_probe_module_sizes.py -> parents[3] is the worktree
# (repository) root. Verified at module import time below.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_ENGINE = _REPO_ROOT / "tools" / "probe" / "engine"
_PROTOCOLS = _ENGINE / "protocols"


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


# Locked regrowth bounds for each previously monolithic engine file, computed as
# ``ceil(current_line_count * 1.2)`` from the achieved post-refactor sizes. The
# parenthetical is the line count observed when this lock was written.
_MONOLITH_BOUNDS: dict[str, int] = {
    # planning.py: orchestration + builder re-exports after the 6460->slim cut.
    "planning.py": math.ceil(365 * 1.2),  # 365 -> 438
    # cases.py: profile scaffolding + registry aggregation (no per-protocol data).
    "cases.py": math.ceil(457 * 1.2),  # 457 -> 549
    # target_services.py: registry-fold orchestration + identity re-exports.
    "target_services.py": math.ceil(838 * 1.2),  # 838 -> 1006
    # lab.py: shared capability substrate + registry fold.
    "lab.py": math.ceil(537 * 1.2),  # 537 -> 645
    # cli/ package files (cli.py was split into a package in steps 44-45).
    "cli/__init__.py": math.ceil(52 * 1.2),  # 52 -> 63
    "cli/__main__.py": math.ceil(13 * 1.2),  # 13 -> 16
    "cli/main.py": math.ceil(1132 * 1.2),  # 1132 -> 1359 (mock-patch-coupled)
    "cli/parser.py": math.ceil(81 * 1.2),  # 81 -> 98
    "cli/report_io.py": math.ceil(134 * 1.2),  # 134 -> 161
}

# Per-protocol plugin floor: there must be at least this many plugin modules
# (one per migrated protocol). Set just below the achieved count of 12.
_PLUGIN_FLOOR = 12

# Generous per-plugin-module size cap. The largest plugin at lock time is
# dns.py (2354 lines); cap at ceil(2354 * 1.2) = 2825 so an isolated protocol
# module that bundles a full surface still has headroom but a runaway module
# trips the guard.
_PLUGIN_MODULE_CAP = math.ceil(2354 * 1.2)  # 2825

# The per-protocol case tuples removed when the registry became the sole source
# (steps 39/43). Anchored to the actual dead pattern -- a top-level
# ``BEHAVIOR_<PROTO>_CASES`` assignment -- so it does NOT false-positive on the
# surviving profile scaffolding (``BEHAVIOR_PROFILE_CASE_NAMES``,
# ``_<P>_BEHAVIOR_CASE_NAMES``), which are differently named.
_DEAD_CASE_TABLE_RE = re.compile(
    r"^BEHAVIOR_(ARP|DNS|DHCPv4|UDP|NDP|ICMP|TCP|BGP|RIP|RIPNG|OSPF|IGMP|IPSEC)"
    r"_CASES\s*[:=]",
    re.MULTILINE,
)


class ProbeRepoRootResolutionTest(unittest.TestCase):
    def test_parents_index_points_at_worktree_root(self) -> None:
        # parents[3] must be the worktree root containing tools/probe/engine.
        self.assertTrue(
            (_REPO_ROOT / "tools" / "probe" / "engine").is_dir(),
            f"repo-root resolution wrong: {_REPO_ROOT} has no tools/probe/engine",
        )


class ProbePluginDirectoryTest(unittest.TestCase):
    def test_protocols_directory_is_populated(self) -> None:
        self.assertTrue(
            _PROTOCOLS.is_dir(),
            f"missing protocol-plugin directory: {_PROTOCOLS}",
        )
        plugin_modules = sorted(
            p.name
            for p in _PROTOCOLS.glob("*.py")
            if p.name not in {"__init__.py", "base.py"}
        )
        self.assertGreaterEqual(
            len(plugin_modules),
            _PLUGIN_FLOOR,
            f"expected at least {_PLUGIN_FLOOR} protocol plugin modules, "
            f"found {len(plugin_modules)}: {plugin_modules}",
        )


class ProbeMonolithSizeLockTest(unittest.TestCase):
    def test_previously_monolithic_files_under_bound(self) -> None:
        for rel, bound in sorted(_MONOLITH_BOUNDS.items()):
            path = _ENGINE / rel
            with self.subTest(file=rel):
                self.assertTrue(path.is_file(), f"missing engine file: {path}")
                count = _line_count(path)
                self.assertLessEqual(
                    count,
                    bound,
                    f"{rel} grew to {count} lines (locked bound {bound}); "
                    f"split per-protocol logic into a plugin instead of "
                    f"regrowing the shared file",
                )


class ProbePluginModuleSizeCapTest(unittest.TestCase):
    def test_no_plugin_module_oversized(self) -> None:
        plugin_modules = [
            p
            for p in sorted(_PROTOCOLS.glob("*.py"))
            if p.name not in {"__init__.py", "base.py"}
        ]
        self.assertTrue(plugin_modules, "no protocol plugin modules found")
        for path in plugin_modules:
            with self.subTest(plugin=path.name):
                count = _line_count(path)
                self.assertLessEqual(
                    count,
                    _PLUGIN_MODULE_CAP,
                    f"plugin {path.name} grew to {count} lines "
                    f"(cap {_PLUGIN_MODULE_CAP})",
                )


class ProbeRegistrySoleSourceTest(unittest.TestCase):
    def test_cases_has_no_per_protocol_case_tables(self) -> None:
        cases_src = (_ENGINE / "cases.py").read_text(encoding="utf-8")
        leftover = _DEAD_CASE_TABLE_RE.findall(cases_src)
        self.assertEqual(
            leftover,
            [],
            "cases.py still defines per-protocol BEHAVIOR_<P>_CASES tables "
            f"{leftover}; the registry must be the sole protocol source",
        )


if __name__ == "__main__":
    unittest.main()
