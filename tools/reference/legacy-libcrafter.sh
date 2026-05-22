#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"

legacy_src="$repo_root/libcrafter"
examples_dir="${LIBCRAFTER_EXAMPLES_DIR:-$repo_root/../libcrafter-examples}"
work_root="${LIBCRAFTER_LEGACY_WORK_ROOT:-$repo_root/.libcrafter-live/legacy-libcrafter}"
out_dir="${LIBCRAFTER_LEGACY_OUT_DIR:-$repo_root/tests/fixtures/legacy}"
jobs="${LIBCRAFTER_LEGACY_JOBS:-}"

dry_run=false
clean=false
skip_build=false
skip_examples=false
skip_run=false

DEFAULT_COMPILE_EXAMPLES=(
  HelloWorld
  PayloadHelloWorld
  BasicSend
  Ping
  BasicPingPong
  NetworkPing
  ARPPing
  DNSQuery
  TCPTraceroute
  SimpleSniffer
  ReadPcap
  DumpPcap
  TCPOptions
  IPOptions
  DHCPRequest
  Ping6
  PingIPv4IPv6
  CombineIPv4IPv6
  IPv6RoutingHeader
  UserSockets
)

# Byte references are deterministic examples that can be executed offline in a
# container or disposable lab without sending packets.
BYTE_REFERENCE_EXAMPLES=(
  IPv6RoutingHeader
)

# Behavioral references compile and document legacy workflows, but they are not
# executed by this harness because they depend on root, live interfaces, local
# routing, random fields, pcaps outside the repo, or network replies.
BEHAVIORAL_REFERENCE_EXAMPLES=(
  HelloWorld
  PayloadHelloWorld
  BasicSend
  Ping
  BasicPingPong
  NetworkPing
  ARPPing
  DNSQuery
  TCPTraceroute
  SimpleSniffer
  ReadPcap
  DumpPcap
  TCPOptions
  IPOptions
  DHCPRequest
  Ping6
  PingIPv4IPv6
  CombineIPv4IPv6
  UserSockets
)

compile_examples=("${DEFAULT_COMPILE_EXAMPLES[@]}")

usage() {
  cat <<'EOF'
usage: tools/reference/legacy-libcrafter.sh [options]

Build the legacy libcrafter C++ tree in an isolated ignored work directory,
compile selected examples, and extract deterministic offline reference
artifacts.

Options:
  --dry-run              Print planned actions and exit without building.
  --clean                Remove the isolated work directory before building.
  --work-dir DIR         Override LIBCRAFTER_LEGACY_WORK_ROOT.
  --out DIR              Override LIBCRAFTER_LEGACY_OUT_DIR.
  --examples-dir DIR     Override LIBCRAFTER_EXAMPLES_DIR.
  --examples A,B,C       Compile only this comma-separated example list.
  --skip-build           Reuse an existing isolated libcrafter install.
  --skip-examples        Do not compile example programs.
  --skip-run             Do not run offline byte-reference examples.
  -h, --help             Show this help.

Environment:
  LIBCRAFTER_EXAMPLES_DIR       External libcrafter-examples checkout. Defaults
                                to the conventional sibling path
                                ../libcrafter-examples.
  LIBCRAFTER_LEGACY_WORK_ROOT   Ignored work directory for copied source,
                                installed library, binaries, and logs.
  LIBCRAFTER_LEGACY_OUT_DIR     Output directory for deterministic artifacts.
  LIBCRAFTER_LEGACY_EXAMPLES    Comma-separated example list, used when
                                --examples is not provided.
  LIBCRAFTER_LEGACY_JOBS        make -j value.

Reference classes:
  Byte references:
    IPv6RoutingHeader

  Behavioral references:
    HelloWorld, PayloadHelloWorld, BasicSend, Ping, BasicPingPong,
    NetworkPing, ARPPing, DNSQuery, TCPTraceroute, SimpleSniffer, ReadPcap,
    DumpPcap, TCPOptions, IPOptions, DHCPRequest, Ping6, PingIPv4IPv6,
    CombineIPv4IPv6, UserSockets

Byte-reference examples are executed offline and their stdout plus sha256 files
are written under the output directory. Behavioral references are compile-only
by default; they become live-test material for disposable lab runs.
EOF
}

split_csv() {
  local value="$1"
  local old_ifs="$IFS"
  IFS=','
  read -r -a compile_examples <<< "$value"
  IFS="$old_ifs"
}

if [[ -n "${LIBCRAFTER_LEGACY_EXAMPLES:-}" ]]; then
  split_csv "$LIBCRAFTER_LEGACY_EXAMPLES"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      dry_run=true
      shift
      ;;
    --clean)
      clean=true
      shift
      ;;
    --work-dir)
      if [[ $# -lt 2 ]]; then
        echo "error: --work-dir requires a value" >&2
        exit 64
      fi
      work_root="$2"
      shift 2
      ;;
    --work-dir=*)
      work_root="${1#--work-dir=}"
      shift
      ;;
    --out)
      if [[ $# -lt 2 ]]; then
        echo "error: --out requires a value" >&2
        exit 64
      fi
      out_dir="$2"
      shift 2
      ;;
    --out=*)
      out_dir="${1#--out=}"
      shift
      ;;
    --examples-dir)
      if [[ $# -lt 2 ]]; then
        echo "error: --examples-dir requires a value" >&2
        exit 64
      fi
      examples_dir="$2"
      shift 2
      ;;
    --examples-dir=*)
      examples_dir="${1#--examples-dir=}"
      shift
      ;;
    --examples)
      if [[ $# -lt 2 ]]; then
        echo "error: --examples requires a comma-separated value" >&2
        exit 64
      fi
      split_csv "$2"
      shift 2
      ;;
    --examples=*)
      split_csv "${1#--examples=}"
      shift
      ;;
    --skip-build)
      skip_build=true
      shift
      ;;
    --skip-examples)
      skip_examples=true
      shift
      ;;
    --skip-run)
      skip_run=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

source_copy="$work_root/src"
prefix_dir="$work_root/prefix"
bin_dir="$work_root/examples/bin"
log_dir="$work_root/logs"

if [[ -z "$jobs" ]]; then
  if command -v nproc >/dev/null 2>&1; then
    jobs="$(nproc)"
  else
    jobs="2"
  fi
fi

print_array_csv() {
  local first=true
  local item
  for item in "$@"; do
    if [[ "$first" == true ]]; then
      first=false
    else
      printf ','
    fi
    printf '%s' "$item"
  done
  printf '\n'
}

run() {
  if [[ "$dry_run" == true ]]; then
    printf '+ '
    printf '%q ' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

run_in_dir() {
  local dir="$1"
  shift
  if [[ "$dry_run" == true ]]; then
    printf '+ cd %q && ' "$dir"
    printf '%q ' "$@"
    printf '\n'
    return 0
  fi
  (cd "$dir" && "$@")
}

copy_legacy_source() {
  if [[ "$dry_run" == true ]]; then
    printf '+ copy isolated libcrafter source: %q -> %q\n' "$legacy_src" "$source_copy"
    return 0
  fi

  rm -rf "$source_copy"
  mkdir -p "$source_copy"
  (
    cd "$legacy_src"
    tar \
      --exclude='.git' \
      --exclude='.libs' \
      --exclude='.deps' \
      --exclude='autom4te.cache' \
      --exclude='m4' \
      --exclude='*.o' \
      --exclude='*.lo' \
      --exclude='*.la' \
      -cf - .
  ) | (
    cd "$source_copy"
    tar -xf -
  )
}

ensure_inputs() {
  if [[ ! -d "$legacy_src" ]]; then
    echo "error: legacy source directory not found: $legacy_src" >&2
    exit 66
  fi

  if [[ "$dry_run" == false && "$skip_examples" == false && ! -d "$examples_dir" ]]; then
    echo "error: examples directory not found: $examples_dir" >&2
    echo "hint: set LIBCRAFTER_EXAMPLES_DIR or pass --examples-dir" >&2
    exit 66
  fi
}

build_legacy() {
  if [[ "$skip_build" == true ]]; then
    return 0
  fi

  if [[ "$clean" == true ]]; then
    run rm -rf "$work_root"
  fi

  run mkdir -p "$work_root" "$log_dir" "$prefix_dir"
  copy_legacy_source
  run_in_dir "$source_copy" ./autogen.sh "--prefix=$prefix_dir"
  run_in_dir "$source_copy" make "-j$jobs"
  run_in_dir "$source_copy" make install
}

pkg_config_flags() {
  local flag_kind="$1"
  if PKG_CONFIG_PATH="$prefix_dir/lib/pkgconfig:$prefix_dir/lib64/pkgconfig:${PKG_CONFIG_PATH:-}" \
    pkg-config "$flag_kind" crafter >/dev/null 2>&1
  then
    PKG_CONFIG_PATH="$prefix_dir/lib/pkgconfig:$prefix_dir/lib64/pkgconfig:${PKG_CONFIG_PATH:-}" \
      pkg-config "$flag_kind" crafter
  fi
}

compile_example() {
  local name="$1"
  local src="$examples_dir/$name/main.cpp"
  local out="$bin_dir/$name"
  local cxx="${CXX:-g++}"
  local cflags=()
  local libs=()

  if [[ "$dry_run" == false && ! -f "$src" ]]; then
    echo "warn: skipping missing example: $name ($src)" >&2
    return 0
  fi

  if [[ "$dry_run" == false ]]; then
    read -r -a cflags <<< "$(pkg_config_flags --cflags)"
    read -r -a libs <<< "$(pkg_config_flags --libs)"
  else
    cflags=("-I$prefix_dir/include" "-I$prefix_dir/include/crafter")
    libs=("-L$prefix_dir/lib" "-lcrafter")
  fi

  run mkdir -p "$bin_dir"
  run "$cxx" \
    -std=gnu++03 \
    -I"$prefix_dir/include" \
    -I"$prefix_dir/include/crafter" \
    "${cflags[@]}" \
    "$src" \
    -o "$out" \
    "${libs[@]}" \
    -L"$prefix_dir/lib" \
    -lcrafter \
    -lpcap \
    -lpthread \
    -lresolv \
    "-Wl,-rpath,$prefix_dir/lib"
}

compile_selected_examples() {
  if [[ "$skip_examples" == true ]]; then
    return 0
  fi

  local example
  for example in "${compile_examples[@]}"; do
    [[ -n "$example" ]] || continue
    compile_example "$example"
  done
}

is_selected_example() {
  local needle="$1"
  local example
  for example in "${compile_examples[@]}"; do
    if [[ "$example" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

write_reference_manifest() {
  run mkdir -p "$out_dir"

  if [[ "$dry_run" == true ]]; then
    printf '+ write reference manifest: %q\n' "$out_dir/README.md"
    return 0
  fi

  cat > "$out_dir/README.md" <<EOF
# Legacy libcrafter references

Generated by \`tools/reference/legacy-libcrafter.sh\`.

## Byte references

These examples are deterministic and safe to run offline in the live-test image
or disposable lab. Their stdout captures packet printouts and hexdumps produced
by legacy libcrafter.

$(printf -- '- %s\n' "${BYTE_REFERENCE_EXAMPLES[@]}")

## Behavioral references

These examples are compile-only by default. They document legacy workflows for
the Rust port, but execution depends on root, live interfaces, local routing,
network responses, mutable pcaps, or non-deterministic fields.

$(printf -- '- %s\n' "${BEHAVIORAL_REFERENCE_EXAMPLES[@]}")
EOF
}

run_byte_references() {
  if [[ "$skip_run" == true || "$skip_examples" == true ]]; then
    return 0
  fi

  write_reference_manifest

  local example
  for example in "${BYTE_REFERENCE_EXAMPLES[@]}"; do
    if ! is_selected_example "$example"; then
      continue
    fi

    local bin="$bin_dir/$example"
    local stdout_file="$out_dir/$example.stdout"
    local sha_file="$out_dir/$example.stdout.sha256"

    if [[ "$dry_run" == true ]]; then
      printf '+ LD_LIBRARY_PATH=%q %q > %q\n' \
        "$prefix_dir/lib:$prefix_dir/lib64:\${LD_LIBRARY_PATH:-}" \
        "$bin" \
        "$stdout_file"
      printf '+ sha256sum %q > %q\n' "$stdout_file" "$sha_file"
      continue
    fi

    if [[ ! -x "$bin" ]]; then
      echo "warn: byte-reference example was not compiled: $example" >&2
      continue
    fi

    LD_LIBRARY_PATH="$prefix_dir/lib:$prefix_dir/lib64:${LD_LIBRARY_PATH:-}" \
      "$bin" > "$stdout_file"
    sha256sum "$stdout_file" > "$sha_file"
  done
}

if [[ "$dry_run" == true ]]; then
  echo "legacy_src=$legacy_src"
  echo "examples_dir=$examples_dir"
  echo "work_root=$work_root"
  echo "prefix_dir=$prefix_dir"
  echo "out_dir=$out_dir"
  echo "jobs=$jobs"
  printf 'compile_examples='
  print_array_csv "${compile_examples[@]}"
  printf 'byte_reference_examples='
  print_array_csv "${BYTE_REFERENCE_EXAMPLES[@]}"
  printf 'behavioral_reference_examples='
  print_array_csv "${BEHAVIORAL_REFERENCE_EXAMPLES[@]}"
fi

ensure_inputs
build_legacy
compile_selected_examples
run_byte_references
