#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$script_dir/common.sh"

parse_live_args "$@"

mkdir -p "$artifact_root"
summary_file="$artifact_root/summary.json"
versions_file="$artifact_root/versions.txt"
versions_json="$artifact_root/versions.json"

capture_versions() {
  {
    echo "suite=all"
    echo "mode=$live_suite_mode"
    echo "started_at=$(timestamp_utc)"
    echo "project_root=$project_root"
    echo "artifact_root=$artifact_root"
    uname -a || true
    rustc --version || echo "rustc=missing"
    cargo --version || echo "cargo=missing"
    python3 --version || echo "python3=missing"
    if command -v python3 >/dev/null 2>&1; then
      python3 - <<'PY' || true
try:
    from scapy.all import conf
except Exception as exc:
    print(f"reference_tool=unavailable:{exc.__class__.__name__}")
else:
    print(f"reference_tool={conf.version}")
PY
    fi
    if command -v pcap-config >/dev/null 2>&1; then
      printf 'libpcap=%s\n' "$(pcap-config --version)"
    else
      echo "libpcap=pcap-config-missing"
    fi
    ip -Version 2>&1 | head -n 1 || echo "ip=missing"
  } | tee "$versions_file"

  python3 - "$versions_file" "$versions_json" "$live_suite_mode" <<'PY'
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

versions_file, output_file, mode = sys.argv[1:4]
with open(versions_file, "r", encoding="utf-8", errors="replace") as handle:
    lines = [line.rstrip("\n") for line in handle]
with open(output_file, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "mode": mode,
            "captured_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "lines": lines,
        },
        handle,
        indent=2,
        sort_keys=True,
    )
    handle.write("\n")
PY
}

run_static_checks() {
  if [[ "${LIBCRAFTER_LIVE_SKIP_STATIC:-}" == "1" ]]; then
    echo "static_checks=skipped"
    return 0
  fi

  init_suite "static"
  run_logged cargo-test cargo test --workspace
  run_logged cargo-build-examples cargo build --examples
  write_suite_json ok "workspace tests and examples built"
}

run_subsuite() {
  local script_name="$1"
  local status=0
  local mode_arg="--live"
  local log_file="$artifact_root/${script_name%.sh}.stdout.log"

  if is_dry_run; then
    mode_arg="--dry-run"
  fi

  echo "running_suite=${script_name%.sh}"
  if "$script_dir/$script_name" "$mode_arg" >"$log_file" 2>&1; then
    status=0
  else
    status=$?
  fi

  tail -n 30 "$log_file" || true
  return "$status"
}

main() {
  local failures=()
  local suite
  local status
  local suites=(
    scapy-interop.sh
    loopback-icmp.sh
    loopback-udp-tcp.sh
    veth-arp.sh
    dns-local.sh
    pcap-capture.sh
  )

  capture_versions
  require_tool cargo
  require_tool python3
  require_live_lab

  run_static_checks

  for suite in "${suites[@]}"; do
    if run_subsuite "$suite"; then
      status=ok
    else
      status=failed
      failures+=("${suite%.sh}")
    fi
    echo "${suite%.sh}=$status"
  done

  python3 - "$summary_file" "$live_suite_mode" "${failures[@]}" <<'PY'
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

output_file = sys.argv[1]
mode = sys.argv[2]
failures = sys.argv[3:]
with open(output_file, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "suite": "all",
            "mode": mode,
            "status": "failed" if failures else "ok",
            "failures": failures,
            "finished_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        },
        handle,
        indent=2,
        sort_keys=True,
    )
    handle.write("\n")
PY
  echo "summary=$summary_file"

  if [[ "${#failures[@]}" -gt 0 ]]; then
    printf 'failed_suites='
    printf '%s ' "${failures[@]}"
    printf '\n'
    exit 1
  fi

  echo "result=ok"
}

main "$@"
