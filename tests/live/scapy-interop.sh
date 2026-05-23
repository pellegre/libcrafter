#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$script_dir/common.sh"

parse_live_args "$@"
suite_label="${LIBCRAFTER_REFERENCE_INTEROP_SUITE_NAME:-scapy-interop}"
init_suite "$suite_label"
require_tool cargo
require_tool python3
require_live_lab

versions_file="$suite_dir/versions.txt"

cd "$project_root"

{
  echo "suite=$suite_name"
  echo "mode=$live_suite_mode"
  echo "started_at=$(timestamp_utc)"
  echo "project_root=$project_root"
  echo "artifact_root=$artifact_root"
  rustc --version || echo "rustc=missing"
  cargo --version || echo "cargo=missing"
  python3 --version || echo "python3=missing"
  python3 - <<'PY' || true
try:
    from scapy.all import conf
except Exception as exc:
    print(f"reference_tool=unavailable:{exc.__class__.__name__}")
else:
    print(f"reference_tool={conf.version}")
PY
  if command -v pcap-config >/dev/null 2>&1; then
    printf 'libpcap=%s\n' "$(pcap-config --version)"
  else
    echo "libpcap=pcap-config-missing"
  fi
} | tee "$versions_file"

run_logged reference-interop-default \
  tools/reference/check-reference-interop \
    --out "$suite_dir/default" \
    --keep-artifacts
run_logged reference-interop-pcap \
  tools/reference/check-reference-interop \
    --family pcap \
    --out "$suite_dir/pcap" \
    --keep-artifacts

write_suite_json ok "Reference offline interop checks passed"
