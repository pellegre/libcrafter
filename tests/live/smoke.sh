#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="${LIBCRAFTER_PROJECT_ROOT:-$(cd -- "$script_dir/../.." && pwd)}"
artifact_dir="${LIBCRAFTER_LIVE_ARTIFACT_DIR:-$project_root/target/live/smoke}"
allow_degraded="${LIBCRAFTER_LIVE_SMOKE_ALLOW_DEGRADED:-false}"
namespace_name=""

timestamp_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

cleanup() {
  if [[ -n "$namespace_name" ]] && command -v ip >/dev/null 2>&1; then
    ip netns delete "$namespace_name" >/dev/null 2>&1 || true
  fi
}

require_tool() {
  local tool="$1"

  if command -v "$tool" >/dev/null 2>&1; then
    printf '%s=%s\n' "$tool" "$(command -v "$tool")"
    return 0
  fi

  if [[ "$allow_degraded" == true ]]; then
    printf '%s=missing_degraded\n' "$tool"
    return 1
  fi

  echo "error: required tool '$tool' is not installed" >&2
  exit 69
}

first_line() {
  local value="$1"
  printf '%s\n' "$value" | sed -n '1p'
}

print_optional_version() {
  local tool="$1"
  shift

  if command -v "$tool" >/dev/null 2>&1; then
    first_line "$("$tool" "$@" 2>&1)"
  else
    printf '%s=missing_optional\n' "$tool"
  fi
}

verify_scapy() {
  if require_tool python3; then
    python3 --version
  fi

  if python3 - <<'PY'
from scapy.all import IP, ICMP, raw, conf

packet = IP(dst="127.0.0.1") / ICMP()
assert raw(packet)
print(f"scapy={conf.version}")
PY
  then
    echo "scapy_import=ok"
    return 0
  fi

  if [[ "$allow_degraded" == true ]]; then
    echo "scapy_import=missing_degraded"
    return 0
  fi

  echo "error: Scapy import check failed" >&2
  exit 69
}

verify_tcpdump() {
  local version

  if require_tool tcpdump; then
    if version="$(tcpdump --version 2>&1)"; then
      first_line "$version"
    else
      echo "tcpdump_version=unavailable"
    fi
    echo "tcpdump=ok"
  fi
}

verify_isolated_network() {
  local netns_error="$artifact_dir/netns.err"
  local unshare_error="$artifact_dir/unshare.err"

  require_tool ip >/dev/null || true

  if command -v ip >/dev/null 2>&1 && [[ "$(id -u)" == "0" ]]; then
    namespace_name="libcrafter-smoke-$$"
    if ip netns add "$namespace_name" 2>"$netns_error"; then
      ip -n "$namespace_name" link set lo up
      ip netns exec "$namespace_name" ip addr show lo >/dev/null
      ip netns delete "$namespace_name"
      namespace_name=""
      echo "isolated_network=ip-netns"
      return 0
    fi
  fi

  if command -v unshare >/dev/null 2>&1 && unshare -n true 2>"$unshare_error"; then
    echo "isolated_network=unshare-netns"
    return 0
  fi

  if [[ "$allow_degraded" == true ]]; then
    echo "isolated_network=skipped_degraded"
    return 0
  fi

  echo "error: could not create an isolated network primitive" >&2
  if [[ -s "$netns_error" ]]; then
    sed 's/^/netns: /' "$netns_error" >&2
  fi
  if [[ -s "$unshare_error" ]]; then
    sed 's/^/unshare: /' "$unshare_error" >&2
  fi
  exit 75
}

main() {
  mkdir -p "$artifact_dir"
  trap cleanup EXIT

  echo "suite=smoke"
  echo "started_at=$(timestamp_utc)"
  echo "project_root=$project_root"
  echo "artifact_dir=$artifact_dir"

  print_optional_version rustc --version
  print_optional_version cargo --version
  verify_scapy
  verify_tcpdump
  require_tool ip >/dev/null || true
  if command -v ip >/dev/null 2>&1; then
    first_line "$(ip -Version 2>&1)"
  fi
  print_optional_version unshare --version
  verify_isolated_network

  cat >"$artifact_dir/smoke.env" <<EOF
suite=smoke
result=ok
finished_at=$(timestamp_utc)
artifact_dir=$artifact_dir
EOF
  echo "artifact=$artifact_dir/smoke.env"
  echo "result=ok"
}

main "$@"
