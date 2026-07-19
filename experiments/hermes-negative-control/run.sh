#!/usr/bin/env bash
# Run the interlock negative control.
#
# ============================ READ THIS FIRST =============================
# TWO LAYERS OF ISOLATION ARE INTENDED. This script provides the inner one.
#
#   Layer 1 (OUTER, YOUR JOB): a disposable VM.
#   Layer 2 (INNER, THIS SCRIPT): a hardened container.
#
# Containers share the HOST KERNEL. A kernel privilege-escalation reachable
# from inside a container is a host compromise, and no `docker run` flag
# prevents that. The container flags below remove the easy escape paths; they
# do not remove the shared kernel. Only a separate kernel does that.
#
# There is also a risk the container flags do not touch AT ALL: `./run.sh
# build` runs `pip install hermes-agent`, which executes setup code from ~60
# transitive dependencies AS ROOT WITH NETWORK ENABLED. That is the sharpest
# edge in this experiment. Running the BUILD inside a VM is what covers it.
#
# So this script refuses to run on a bare host unless you say so explicitly.
# See `./run.sh preflight` and TESTPLAN.md Step 0.
# ==========================================================================
#
# ISOLATION FLAGS — every one is load-bearing:
#   --network none            no route to your network or the internet
#   --read-only               container filesystem immutable
#   --tmpfs                   only writable paths, wiped on exit
#   --cap-drop ALL            no Linux capabilities
#   --security-opt no-new-privileges   no setuid escalation
#   --pids-limit / --memory   a runaway agent cannot exhaust the host
#   (no -v / --mount)         NOTHING from your filesystem is visible inside
set -euo pipefail

IMAGE="${IMAGE:-interlock-negative-control}"
HERMES_VERSION="${HERMES_VERSION:-0.18.2}"
ENGINE="${ENGINE:-docker}"          # docker | podman
RUNTIME="${RUNTIME:-}"              # e.g. runsc (gVisor); empty = engine default
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ---------------------------------------------------------------- preflight

detect_virt() {
  # --vm is REQUIRED here. Bare `systemd-detect-virt` also reports CONTAINER
  # types, so it answers "docker" when run inside a container and the check
  # would report an outer layer that does not exist. Containers are the inner
  # layer; only a VM isolates the kernel. `--vm` returns none for containers.
  if command -v systemd-detect-virt >/dev/null 2>&1; then
    systemd-detect-virt --vm 2>/dev/null || echo none
  elif [ -r /sys/class/dmi/id/product_name ]; then
    grep -qiE 'virtual|vmware|kvm|qemu|bhyve' /sys/class/dmi/id/product_name \
      && echo "vm-probable" || echo none
  else
    echo unknown
  fi
}

is_rootless() {
  "$ENGINE" info --format '{{.SecurityOptions}}' 2>/dev/null | grep -q rootless
}

preflight() {
  local virt rootless runtime
  virt="$(detect_virt)"
  rootless=no; is_rootless && rootless=yes
  runtime="${RUNTIME:-<engine default>}"

  echo "engine           : $ENGINE ($("$ENGINE" --version 2>/dev/null | head -1))"
  echo "rootless         : $rootless"
  echo "container runtime: $runtime"
  echo "virtualization   : $virt"
  echo

  if [ "$virt" != "none" ] && [ "$virt" != "unknown" ]; then
    echo "OUTER LAYER: present — running inside '$virt'. Host kernel is isolated."
    return 0
  fi

  echo "OUTER LAYER: ABSENT — this looks like a bare host."
  echo
  echo "  The container shares this machine's kernel. A container escape or a"
  echo "  malicious package pulled during 'build' would land on YOUR system."
  echo
  echo "  Recommended, in order:"
  echo "    1. Disposable VM (isolates the kernel AND the pip build):"
  echo "         limactl start template://docker && limactl shell docker"
  echo "         multipass launch --name interlock-test --cpus 2 --memory 4G"
  echo "    2. Rootless Podman (escape lands as your user, not root):"
  echo "         ENGINE=podman ./run.sh both"
  echo "    3. gVisor (syscall interception, no full VM):"
  echo "         RUNTIME=runsc ./run.sh both"
  echo
  echo "  To proceed anyway on this host, set:"
  echo "         INTERLOCK_ACK_HOST_RISK=1"
  return 1
}

require_isolation() {
  # Default-deny, with an explicit opt-out. Same posture the tool under test
  # takes: refuse by default, proceed only on a deliberate approval.
  if [ "${INTERLOCK_ACK_HOST_RISK:-}" = "1" ]; then
    echo "WARNING: INTERLOCK_ACK_HOST_RISK=1 — running without an outer VM layer." >&2
    return 0
  fi
  if is_rootless; then
    return 0   # rootless podman: escape lands unprivileged
  fi
  local virt; virt="$(detect_virt)"
  if [ "$virt" != "none" ] && [ "$virt" != "unknown" ]; then
    return 0
  fi
  echo >&2
  preflight >&2 || true
  echo "REFUSING TO RUN: no outer isolation layer detected." >&2
  exit 78   # EX_CONFIG
}

# ------------------------------------------------------------------ running

run_arm() {
  local runtime_flag=()
  [ -n "$RUNTIME" ] && runtime_flag=(--runtime "$RUNTIME")

  "$ENGINE" run --rm \
    "${runtime_flag[@]}" \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 256 \
    --memory 2g \
    --tmpfs /victim:rw,size=16m \
    --tmpfs /run/interlock:rw,size=1m \
    --tmpfs /home/agent/.hermes:rw,size=256m \
    --tmpfs /tmp:rw,size=64m \
    "$IMAGE" --arm "$1" --json
}

case "${1:-both}" in
  preflight)
    preflight
    ;;
  build)
    require_isolation
    "$ENGINE" build --build-arg "HERMES_VERSION=${HERMES_VERSION}" \
      -t "$IMAGE" \
      -f "${REPO_ROOT}/experiments/hermes-negative-control/Dockerfile" \
      "$REPO_ROOT"
    ;;
  control|interlock)
    require_isolation
    run_arm "$1"
    ;;
  both)
    require_isolation
    echo "=== ARM 1: CONTROL (no interlock) ==="
    run_arm control
    echo
    echo "=== ARM 2: INTERLOCK ==="
    run_arm interlock
    ;;
  *)
    echo "usage: $0 {preflight|build|control|interlock|both}" >&2
    echo "  ENGINE=podman   use rootless podman instead of docker" >&2
    echo "  RUNTIME=runsc   use gVisor" >&2
    exit 64 ;;
esac
