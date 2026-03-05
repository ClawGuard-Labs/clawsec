#!/usr/bin/env bash
# gen_vmlinux.sh — generate vmlinux.h from the running kernel's BTF
#
# This header contains ALL kernel type definitions in a single file.
# It is generated from the running kernel's BTF metadata, which is
# the cornerstone of CO-RE (Compile Once Run Everywhere).
#
# Must be run on the TARGET machine (or a machine with the same kernel).
# The output is checked into the repo so CI can build without BTF tools.
#
# Requirements:
#   - bpftool >= 5.13  (ships with linux-tools-$(uname -r) on Ubuntu)
#   - /sys/kernel/btf/vmlinux must exist (CONFIG_DEBUG_INFO_BTF=y)
#
# Usage:
#   ./scripts/gen_vmlinux.sh
#   ./scripts/gen_vmlinux.sh /path/to/vmlinux.h   # custom output path

set -euo pipefail

OUTFILE="${1:-$(dirname "$0")/../bpf/vmlinux.h}"
OUTFILE="$(realpath -m "$OUTFILE")"

echo "[*] Checking for BTF support..."

if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "[!] /sys/kernel/btf/vmlinux not found."
    echo "    Your kernel was not built with CONFIG_DEBUG_INFO_BTF=y."
    echo ""
    echo "    On Ubuntu 22.04/24.04 the stock kernels DO have BTF enabled."
    echo "    If you are on a custom kernel, add CONFIG_DEBUG_INFO_BTF=y"
    echo "    and CONFIG_DEBUG_INFO_BTF_MODULES=y to your kernel config."
    exit 1
fi

echo "[*] BTF found: /sys/kernel/btf/vmlinux"
echo "[*] Kernel: $(uname -r)"

# Find bpftool
BPFTOOL=""
for candidate in bpftool \
                 /usr/sbin/bpftool \
                 /usr/lib/linux-tools/$(uname -r)/bpftool \
                 $(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | tail -1); do
    if command -v "$candidate" &>/dev/null 2>&1; then
        BPFTOOL="$candidate"
        break
    fi
done

if [ -z "$BPFTOOL" ]; then
    echo "[!] bpftool not found. Install it with:"
    echo "    sudo apt-get install -y linux-tools-$(uname -r) linux-tools-common"
    exit 1
fi

echo "[*] Using bpftool: $BPFTOOL ($(${BPFTOOL} version 2>/dev/null | head -1))"
echo "[*] Generating vmlinux.h → $OUTFILE ..."

mkdir -p "$(dirname "$OUTFILE")"
"$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > "$OUTFILE"

LINES=$(wc -l < "$OUTFILE")
echo "[+] Done. vmlinux.h generated: ${LINES} lines."
echo "    You can now run: make build"
