#!/usr/bin/env bash
set -euo pipefail

project_root="${LIBCRAFTER_PROJECT_ROOT:-/workspace/libcrafter}"

show_tool_versions() {
  rustc --version
  cargo --version
  python3 --version
  python3 - <<'PY'
from scapy.all import IP, ICMP, raw

packet = IP(dst="127.0.0.1") / ICMP()
assert raw(packet)
print("scapy=ok")
PY
  if command -v pcap-config >/dev/null 2>&1; then
    printf 'libpcap=%s\n' "$(pcap-config --version)"
  fi
  autoconf --version | head -n 1
  automake --version | head -n 1
  libtoolize --version | head -n 1
}

run_check() {
  show_tool_versions

  if [[ -f "$project_root/Cargo.toml" ]]; then
    cd "$project_root"
    cargo metadata --format-version 1 --no-deps >/dev/null
    echo "cargo_metadata=ok"
  else
    echo "cargo_metadata=skipped"
  fi
}

case "${1:-check}" in
  check)
    run_check
    ;;
  shell)
    cd "$project_root"
    exec bash
    ;;
  exec)
    shift
    cd "$project_root"
    exec "$@"
    ;;
  *)
    cd "$project_root"
    exec "$@"
    ;;
esac
