#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
image_dir="$script_dir/image"

usage() {
  cat <<'EOF'
usage: tools/live-lab/run-in-image.sh [options] [-- command...]

Build and run the libcrafter live-test image.

Options:
  --dry-run            Print the planned build/run actions and exit.
  --build-only         Build the image but do not run it.
  --no-build           Reuse an existing local image.
  --live               Run with host networking and privileges for live tests.
  --image NAME         Image tag to build or run.
  --runtime NAME       Container runtime, usually docker or podman.
  -h, --help           Show this help.

Without a command, the image runs the offline "check" command. That check does
not send raw packets and is intended for local image validation.
EOF
}

find_runtime() {
  if [[ -n "${LIBCRAFTER_CONTAINER_RUNTIME:-}" ]]; then
    printf '%s\n' "$LIBCRAFTER_CONTAINER_RUNTIME"
    return 0
  fi

  if command -v docker >/dev/null 2>&1; then
    printf '%s\n' "docker"
    return 0
  fi

  if command -v podman >/dev/null 2>&1; then
    printf '%s\n' "podman"
    return 0
  fi

  return 1
}

dry_run=false
build=true
build_only=false
live=false
image="${LIBCRAFTER_LIVE_IMAGE:-libcrafter/live-lab:local}"
runtime=""
container_cmd=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      dry_run=true
      shift
      ;;
    --build-only)
      build_only=true
      shift
      ;;
    --no-build)
      build=false
      shift
      ;;
    --live)
      live=true
      shift
      ;;
    --image)
      if [[ $# -lt 2 ]]; then
        echo "error: --image requires a value" >&2
        exit 64
      fi
      image="$2"
      shift 2
      ;;
    --image=*)
      image="${1#--image=}"
      shift
      ;;
    --runtime)
      if [[ $# -lt 2 ]]; then
        echo "error: --runtime requires a value" >&2
        exit 64
      fi
      runtime="$2"
      shift 2
      ;;
    --runtime=*)
      runtime="${1#--runtime=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      container_cmd+=("$@")
      break
      ;;
    *)
      container_cmd+=("$1")
      shift
      ;;
  esac
done

if [[ ${#container_cmd[@]} -eq 0 ]]; then
  container_cmd=(check)
fi

if [[ -z "$runtime" ]]; then
  if ! runtime="$(find_runtime)"; then
    runtime="docker"
  fi
fi

build_args=(
  build
  -f "$image_dir/Dockerfile"
  -t "$image"
  "$image_dir"
)

run_args=(
  run
  --rm
  -e "LIBCRAFTER_PROJECT_ROOT=/workspace/libcrafter"
  -v "$repo_root:/workspace/libcrafter"
  -w /workspace/libcrafter
)

if [[ "$live" == true ]]; then
  run_args+=(--privileged --network host)
fi

run_args+=("$image")
run_args+=("${container_cmd[@]}")

if [[ "$dry_run" == true ]]; then
  echo "runtime=$runtime"
  echo "image=$image"
  echo "build=$build"
  echo "build_only=$build_only"
  echo "live=$live"
  printf 'build_command='
  printf '%q ' "$runtime" "${build_args[@]}"
  printf '\n'
  if [[ "$build_only" == false ]]; then
    printf 'run_command='
    printf '%q ' "$runtime" "${run_args[@]}"
    printf '\n'
  fi
  exit 0
fi

if ! command -v "$runtime" >/dev/null 2>&1; then
  echo "error: container runtime '$runtime' is not installed" >&2
  exit 69
fi

if [[ "$build" == true ]]; then
  "$runtime" "${build_args[@]}"
fi

if [[ "$build_only" == true ]]; then
  exit 0
fi

"$runtime" "${run_args[@]}"
