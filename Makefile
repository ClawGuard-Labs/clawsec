# Makefile — ai_agent_monitor
#
# Build pipeline:
#   1. gen-vmlinux : generate bpf/vmlinux.h from running kernel BTF
#   2. bpf         : compile monitor.bpf.c → monitor.bpf.o (eBPF bytecode)
#   3. ui          : build React dashboard (Vite) → internal/graphapi/static/
#   4. build       : compile Go daemon binary (embeds the built UI)
#   5. install     : copy binary to /usr/local/bin
#
# Targets:
#   make deps          — check all build/runtime dependencies
#   make gen-vmlinux   — generate bpf/vmlinux.h (run once per kernel upgrade)
#   make bpf           — compile only the eBPF C programs
#   make ui            — build the React dashboard (requires Node.js ≥ 18)
#   make build         — full build (bpf + ui + go binary)
#   make build-no-ui   — build without rebuilding the React UI
#   make clean         — remove all generated files
#   make run           — build and run as root (requires root)
#   make fmt           — format Go and C source files

# ── Tool configuration ────────────────────────────────────────────────────────
CLANG           ?= clang
LLVM_STRIP      ?= llvm-strip
GO              ?= go
BPFTOOL         ?= bpftool

# ── Paths ─────────────────────────────────────────────────────────────────────
BPF_SRC         := bpf/monitor.bpf.c
BPF_OBJ         := bpf/monitor.bpf.o
BPF_VMLINUX     := bpf/vmlinux.h
BINARY          := bin/monitor
CMD_DIR         := cmd/monitor

# ── Architecture ──────────────────────────────────────────────────────────────
# Detect host arch and map to BPF target arch name.
# This sets __TARGET_ARCH_<arch> which vmlinux.h uses to select
# the correct register definitions.
ARCH            := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
BPF_ARCH_DEFINE := __TARGET_ARCH_$(ARCH)

# ── Clang BPF compiler flags ──────────────────────────────────────────────────
# -g                  : emit BTF (required for CO-RE; NOT debug symbols)
# -O2                 : optimize (eBPF verifier rejects unoptimized code)
# -target bpf         : compile for BPF architecture
# -D__TARGET_ARCH_... : select register layout in vmlinux.h
# -I./bpf             : find common.h and vmlinux.h
# -I/usr/include/bpf  : find bpf_helpers.h, bpf_core_read.h etc.
# -Wall -Wno-unused   : catch bugs, suppress noisy unused-variable warnings
BPF_CFLAGS := \
    -g \
    -O2 \
    -target bpf \
    -D$(BPF_ARCH_DEFINE) \
    -I./bpf \
    -I/usr/include/bpf \
    -Wall \
    -Wno-unused-variable \
    -Wno-unused-function

# ── Default target ────────────────────────────────────────────────────────────
.PHONY: all
all: build

# ── Dependency check ─────────────────────────────────────────────────────────
.PHONY: deps
deps:
	@echo "==> Checking dependencies..."
	@bash scripts/check_deps.sh

# ── Generate vmlinux.h ───────────────────────────────────────────────────────
# Must be run on the target machine (needs /sys/kernel/btf/vmlinux).
# Re-run after every kernel upgrade.
.PHONY: gen-vmlinux
gen-vmlinux:
	@echo "==> Generating bpf/vmlinux.h from kernel BTF..."
	@bash scripts/gen_vmlinux.sh
	@echo "==> vmlinux.h generated."

# ── Compile eBPF C programs ───────────────────────────────────────────────────
# Depends on vmlinux.h — run 'make gen-vmlinux' first if it doesn't exist.
.PHONY: bpf
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) bpf/common.h $(BPF_VMLINUX)
	@echo "==> Compiling eBPF programs: $< → $@"
	@mkdir -p $(dir $@)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "==> Stripping DWARF debug info (keeping BTF)..."
	$(LLVM_STRIP) -g $@
	@echo "==> eBPF object ready: $@"

# ── Build React dashboard ─────────────────────────────────────────────────────
# Requires Node.js ≥ 18 and npm. Output is embedded into the Go binary via
# go:embed in internal/graphapi/server.go.
.PHONY: ui
ui:
	@echo "==> Building React dashboard (Vite)..."
	cd ui && npm install --silent && npm run build
	@echo "==> UI assets written to internal/graphapi/static/"

# ── Build Go binary ───────────────────────────────────────────────────────────
# The Go loader reads monitor.bpf.o from disk (no bpf2go code generation step).
# We copy the compiled BPF object next to the binary so they deploy together.
# `build` rebuilds the React UI first so the embedded assets are always fresh.
.PHONY: build
build: bpf ui
	@echo "==> Building Go daemon..."
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build \
	    -ldflags="-s -w -X main.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)" \
	    -o $(BINARY) \
	    ./$(CMD_DIR)/...
	@echo "==> Copying BPF object next to binary..."
	cp $(BPF_OBJ) bin/monitor.bpf.o
	@echo "==> Build complete: $(BINARY) + bin/monitor.bpf.o"

# ── Build Go binary only (skip UI rebuild) ───────────────────────────────────
.PHONY: build-no-ui
build-no-ui: bpf
	@echo "==> Building Go daemon (skipping UI rebuild)..."
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build \
	    -ldflags="-s -w -X main.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)" \
	    -o $(BINARY) \
	    ./$(CMD_DIR)/...
	cp $(BPF_OBJ) bin/monitor.bpf.o
	@echo "==> Build complete: $(BINARY) + bin/monitor.bpf.o"

# ── Build only the eBPF object (no Go) ───────────────────────────────────────
.PHONY: bpf-only
bpf-only: $(BPF_OBJ)
	@echo "==> eBPF-only build complete."

# ── Verify the eBPF object (dry-run load) ────────────────────────────────────
# Uses bpftool to verify the program without actually loading it.
.PHONY: verify
verify: $(BPF_OBJ)
	@echo "==> Verifying eBPF program with bpftool..."
	@$(BPFTOOL) prog load $(BPF_OBJ) /sys/fs/bpf/monitor_test type tracepoint \
	    2>&1 && rm -f /sys/fs/bpf/monitor_test && echo "  [+] Verification passed." \
	    || echo "  [!] Verification failed. Check verifier output above."

# ── Run (requires root) ───────────────────────────────────────────────────────
.PHONY: run
run: build
	@echo "==> Starting monitor (requires root)..."
	sudo $(BINARY)

# ── Install ──────────────────────────────────────────────────────────────────
.PHONY: install
install: build
	@echo "==> Installing to /usr/local/bin/ai-agent-monitor..."
	sudo install -m 0755 $(BINARY) /usr/local/bin/ai-agent-monitor
	@echo "==> Installed."

# ── Format ───────────────────────────────────────────────────────────────────
.PHONY: fmt
fmt:
	@echo "==> Formatting Go sources..."
	$(GO) fmt ./...
	@echo "==> Formatting C sources with clang-format (if available)..."
	@command -v clang-format >/dev/null 2>&1 && \
	    clang-format -i bpf/*.c bpf/*.h || \
	    echo "  [~] clang-format not found, skipping C formatting."

# ── Clean ────────────────────────────────────────────────────────────────────
.PHONY: clean
clean:
	@echo "==> Cleaning build artifacts..."
	rm -f $(BPF_OBJ)
	rm -f bin/monitor bin/monitor.bpf.o
	rm -rf internal/graphapi/static/assets
	@echo "==> Clean complete. (vmlinux.h and ui/node_modules preserved)"

# ── Deep clean (including vmlinux.h) ─────────────────────────────────────────
.PHONY: distclean
distclean: clean
	rm -f $(BPF_VMLINUX)
	@echo "==> dist-clean complete."

# ── Help ─────────────────────────────────────────────────────────────────────
.PHONY: help
help:
	@echo "ai_agent_monitor — eBPF AI Agent Monitoring Tool"
	@echo ""
	@echo "Targets:"
	@echo "  deps          Check all build and runtime dependencies"
	@echo "  gen-vmlinux   Generate bpf/vmlinux.h from kernel BTF (run once per kernel)"
	@echo "  bpf           Compile eBPF C programs to bpf/monitor.bpf.o"
	@echo "  ui            Build React dashboard (requires Node.js ≥ 18)"
	@echo "  build         Full build: eBPF + UI + Go binary → bin/ (default)"
	@echo "  build-no-ui   Full build skipping React rebuild (faster iteration)"
	@echo "  verify        Dry-run verify eBPF program with bpftool"
	@echo "  run           Build and run as root"
	@echo "  install       Install binary + BPF object to /usr/local/bin"
	@echo "  fmt           Format Go and C source files"
	@echo "  clean         Remove build artifacts"
	@echo "  distclean     Remove all generated files including vmlinux.h"
	@echo ""
	@echo "Quick start:"
	@echo "  make deps"
	@echo "  make gen-vmlinux"
	@echo "  make build"
	@echo "  sudo ./bin/monitor --ui :9090"
