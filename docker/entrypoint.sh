#!/usr/bin/env bash
set -euo pipefail

AKMON_BIN="${AKMON_BIN:-/usr/local/bin/akmon}"

AKMON_ETC="${AKMON_ETC:-/etc/akmon}"
AKMON_LIB="${AKMON_LIB:-/usr/lib/akmon}"
AKMON_LOGDIR="${AKMON_LOGDIR:-/var/log/akmon}"

AKMON_CONFIG="${AKMON_CONFIG:-${AKMON_ETC}/config.yaml}"
AKMON_BEHAVIORAL_TEMPLATES="${AKMON_BEHAVIORAL_TEMPLATES:-${AKMON_ETC}/behavioral-templates}"
AKMON_NUCLEI_TEMPLATES="${AKMON_NUCLEI_TEMPLATES:-${AKMON_ETC}/nuclei-templates}"

# Event output written by --output is split into *_logs.json and *_rules.json.
AKMON_OUTPUT="${AKMON_OUTPUT:-${AKMON_LOGDIR}/events.json}"
AKMON_COMPACT_LOG="${AKMON_COMPACT_LOG:-${AKMON_LOGDIR}/chains.json}"

AKMON_UI_ADDR="${AKMON_UI_ADDR:-:9090}"
AKMON_LOG_LEVEL="${AKMON_LOG_LEVEL:-info}"

ensure_dir() {
  mkdir -p "$1"
}

ensure_mounts() {
  # Akmon attaches to tracepoints; that requires tracefs or debugfs.
  # In many container setups these are not mounted by default.
  #
  # We try to mount them. If the host already has them mounted and the paths
  # are bind-mounted into the container, these become no-ops.
  if ! mountpoint -q /sys/kernel/tracing 2>/dev/null; then
    mkdir -p /sys/kernel/tracing
    mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
  fi

  if ! mountpoint -q /sys/kernel/debug 2>/dev/null; then
    mkdir -p /sys/kernel/debug
    mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
  fi

  if ! mountpoint -q /sys/kernel/tracing 2>/dev/null && ! mountpoint -q /sys/kernel/debug 2>/dev/null; then
    cat >&2 <<'EOF'
[akmon] FATAL: neither tracefs nor debugfs is mounted.
Akmon needs one of them to attach to tracepoints.

Fix (host):
  sudo mkdir -p /sys/kernel/tracing /sys/kernel/debug
  sudo mount -t tracefs tracefs /sys/kernel/tracing
  sudo mount -t debugfs debugfs /sys/kernel/debug

Fix (docker):
  - run privileged
  - mount host paths into container:
      /sys/kernel/tracing:/sys/kernel/tracing
      /sys/kernel/debug:/sys/kernel/debug
EOF
    exit 1
  fi
}

if [[ ! -x "$AKMON_BIN" ]]; then
  echo "[akmon] FATAL: akmon binary not found/executable at ${AKMON_BIN}" >&2
  exit 1
fi

if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
  cat >&2 <<'EOF'
[akmon] FATAL: /sys/kernel/btf/vmlinux not found in container.
This container needs access to the host kernel BTF to compile the BPF object.

Fix:
  - run privileged
  - mount: /sys/kernel/btf:/sys/kernel/btf:ro

Host requirement:
  - Linux kernel with BTF enabled (CONFIG_DEBUG_INFO_BTF=y)
EOF
  exit 1
fi

ensure_dir "${AKMON_LIB}"
ensure_dir "${AKMON_ETC}"
ensure_dir "${AKMON_LOGDIR}"

ensure_mounts

echo "[akmon] Generating bpf/vmlinux.h from host BTF..." >&2
/src/scripts/gen_vmlinux.sh /src/bpf/vmlinux.h

echo "[akmon] Compiling BPF object for running kernel..." >&2
make -C /src bpf-only

cp -f /src/bpf/monitor.bpf.o "${AKMON_LIB}/monitor.bpf.o"

echo "[akmon] Starting..." >&2
exec "$AKMON_BIN" \
  --ui "${AKMON_UI_ADDR}" \
  --config "${AKMON_CONFIG}" \
  --bpf-obj "${AKMON_LIB}/monitor.bpf.o" \
  --behavioral-templates "${AKMON_BEHAVIORAL_TEMPLATES}" \
  --nuclei-templates "${AKMON_NUCLEI_TEMPLATES}" \
  --log-level "${AKMON_LOG_LEVEL}" \
  --output "${AKMON_OUTPUT}" \
  --compact \
  --compact-log "${AKMON_COMPACT_LOG}" \
  "$@"

