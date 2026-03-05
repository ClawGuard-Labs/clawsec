#!/usr/bin/env bash
# check_deps.sh — verify all build and runtime dependencies
#
# Run this before attempting to build or deploy the monitor.
# Exits 0 if all deps are satisfied, 1 if any are missing.

set -euo pipefail

ERRORS=0
WARNINGS=0

check() {
    local name="$1"
    local cmd="$2"
    local install_hint="$3"

    if eval "$cmd" &>/dev/null 2>&1; then
        echo "  [+] $name"
    else
        echo "  [!] MISSING: $name"
        echo "      Install: $install_hint"
        ERRORS=$((ERRORS + 1))
    fi
}

warn() {
    local name="$1"
    local cmd="$2"
    local msg="$3"

    if eval "$cmd" &>/dev/null 2>&1; then
        echo "  [+] $name"
    else
        echo "  [~] WARNING: $name"
        echo "      $msg"
        WARNINGS=$((WARNINGS + 1))
    fi
}

echo "=== Build Dependencies ==="
check "clang >= 12"   "clang --version | grep -E 'version (1[2-9]|[2-9][0-9])'" \
      "sudo apt-get install -y clang"

check "llvm-strip"    "llvm-strip --version" \
      "sudo apt-get install -y llvm"

check "go >= 1.21"    "go version | grep -E 'go1\.(2[1-9]|[3-9][0-9])'" \
      "https://go.dev/dl/ or: sudo snap install go --classic"

check "make"          "make --version" \
      "sudo apt-get install -y make"

check "bpftool"       "bpftool version" \
      "sudo apt-get install -y linux-tools-\$(uname -r) linux-tools-common"

check "libbpf headers" "test -f /usr/include/bpf/bpf_helpers.h" \
      "sudo apt-get install -y libbpf-dev"

echo ""
echo "=== Runtime / Kernel Requirements ==="

check "kernel BTF"    "test -f /sys/kernel/btf/vmlinux" \
      "Kernel needs CONFIG_DEBUG_INFO_BTF=y (Ubuntu 22.04+ stock kernels: yes)"

check "kernel >= 5.15" \
      "awk -F'.' '{if(\$1>5 || (\$1==5 && \$2>=15)) exit 0; exit 1}' <<< \$(uname -r | cut -d- -f1)" \
      "Upgrade to Ubuntu 22.04 (5.15) or 24.04 (6.x)"

check "ring buffer support (>= 5.8)" \
      "awk -F'.' '{if(\$1>5 || (\$1==5 && \$2>=8)) exit 0; exit 1}' <<< \$(uname -r | cut -d- -f1)" \
      "Kernel 5.8+ required for BPF ring buffer"

warn  "debugfs mounted" \
      "mountpoint -q /sys/kernel/debug" \
      "Mount with: sudo mount -t debugfs none /sys/kernel/debug"

warn  "perf_event_paranoid <= 2" \
      "test \$(cat /proc/sys/kernel/perf_event_paranoid) -le 2" \
      "Lower with: sudo sysctl -w kernel.perf_event_paranoid=2"

echo ""
echo "=== Privilege Check ==="
if [ "$(id -u)" -eq 0 ]; then
    echo "  [+] Running as root (required for loading eBPF programs)"
else
    warn "CAP_BPF + CAP_PERFMON" \
         "capsh --print 2>/dev/null | grep -q cap_bpf" \
         "Run as root or grant: setcap cap_bpf,cap_perfmon+eip ./monitor"
fi

echo ""
echo "=== Summary ==="
if [ "$ERRORS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
    echo "  All checks passed. Ready to build."
    exit 0
elif [ "$ERRORS" -eq 0 ]; then
    echo "  $WARNINGS warning(s). Build should succeed. Review warnings above."
    exit 0
else
    echo "  $ERRORS error(s), $WARNINGS warning(s). Fix errors before building."
    exit 1
fi
