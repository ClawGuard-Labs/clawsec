# Akmon

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/ClawGuard-Labs/akmon.svg)](https://pkg.go.dev/github.com/ClawGuard-Labs/akmon)
[![CI](https://github.com/ClawGuard-Labs/akmon/actions/workflows/ci.yml/badge.svg)](https://github.com/ClawGuard-Labs/akmon/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ClawGuard-Labs/akmon)](https://goreportcard.com/report/github.com/ClawGuard-Labs/akmon)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ClawGuard-Labs/akmon)](go.mod)

**Kernel-level behavioral monitoring and active vulnerability scanning for AI/ML workloads on Linux.**

Akmon is an agentic-security sensor: eBPF-powered observation of every AI process on the box (what it executes, which files it touches, which services it calls), combined with active Nuclei scanning of the local AI stack (Qdrant, Ollama, vLLM, ChromaDB, …) the moment the monitor sees something talk to it.

Two complementary detection engines:

1. **Behavioral detector** — eBPF passive monitoring of syscalls, network events, and file operations matched against YAML rules (our engine, Nuclei-inspired).
2. **Nuclei active scanner** — fires automatically against local AI service endpoints when they're detected, finding real vulnerabilities like unauthenticated vector-DB access.

### What's in this repo

- **eBPF kernel programs** — tracepoints for exec, file, network, and mmap events (CO-RE, BTF)
- **Behavioral detection engine** — YAML template rules (Nuclei-inspired) for process, file, network, and session patterns
- **Nuclei v3 integration** — active scanning of local AI services when connections are observed
- **Session correlation** — process tree and session IDs for grouping events
- **Output** — NDJSON, grouped JSON, or live SSE stream
- **Detection templates** — shipped in **[akmon-templates](https://github.com/ClawGuard-Labs/akmon-templates)** (`behavioral-templates/`, `nuclei-templates/`)
- **React dashboard** (optional) — graph view and alert panel served by the monitor

### Index

- [Architecture](#architecture)
- [Requirements](#requirements)
- [Install](#install)
- [Quick Start](#quick-start)
- [Build Targets](#build-targets)
- [Flags](#flags)
- [Configuration (`config.yaml`)](#configuration-configyaml)
- [Output Format](#output-format)
- [Testing](#testing)
- [Detection Templates](#detection-templates)
- [Running as a Background Service (systemd)](#running-as-a-background-service-systemd)
- [SSE Live Stream](#sse-live-stream)
- [Project Structure](#project-structure)
- [Dependencies](#dependencies)
- [FAQ](#faq)

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  Kernel (eBPF tracepoints — stable ABI, CO-RE, kernel ≥ 5.15)  │
│  execve │ openat │ read/write │ unlinkat │ mmap │ connect │ …  │
└─────────────────────────┬──────────────────────────────────────┘
                          │  ring buffer (8 MB)
┌─────────────────────────▼──────────────────────────────────────┐
│  consumer   → decode raw bytes      → EnrichedEvent            │
│  correlator → assign session ID     → process tree + timing    │
│  detector   → YAML template rules   → tags + risk score        │
│      │                                                         │
│      └─ net_connect to localhost AI port?                      │
│              │                                                 │
│              ▼  (async goroutine)                              │
│         Nuclei engine → scan target → nuclei_finding event     │
│                                                                │
│  output → NDJSON / grouped JSON → stdout / file / SSE          │
└────────────────────────────────────────────────────────────────┘
```

### How the two detectors work together

| | Behavioral Detector | Nuclei Scanner |
|---|---|---|
| **Type** | Passive | Active |
| **Input** | eBPF kernel events | HTTP requests to local services |
| **Runs on** | Every event | Only `net_connect` to localhost AI ports (from `config.yaml` -> `ai.services`) |
| **Detects** | Process behavior, file access patterns, cross-event chains | Service misconfigs, unauth access, exposed APIs |
| **Output** | Tagged `EnrichedEvent` with risk score | `nuclei_finding` event with matched template |
| **Latency** | Real-time (microseconds) | Async scan (seconds) |

Both detectors fire simultaneously when a connection to a local AI service is observed. The Nuclei scanner does not block the main event loop.

---

## Requirements

- Linux kernel **≥ 5.15** with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
- Run as **root** (or with `CAP_BPF` + `CAP_PERFMON` + `CAP_NET_ADMIN`)
- **Go 1.22+** for building
- `clang` / `llvm-strip` / `bpftool` for eBPF compilation (only needed for `make bpf`)

---

## Install

YAML detection rules are **not** in this repository. You will usually want the separate templates bundle: **[akmon-templates](https://github.com/ClawGuard-Labs/akmon-templates)**.

### Local development (no system install)

Clone both repos, build, and run from your workspace:

```bash
git clone https://github.com/ClawGuard-Labs/akmon
git clone https://github.com/ClawGuard-Labs/akmon-templates
cd akmon
make build
```

Then follow [Quick Start](#quick-start) and [Templates setup](#templates-setup-akmon-templates) to point Akmon at your templates.

### System install (systemd)

If you want Akmon to run as a background service and use `/etc/akmon/...` paths, use:

```bash
sudo make install
sudo make enable
```

See [Running as a Background Service (systemd)](#running-as-a-background-service-systemd) for details.

### Build on macOS (via Docker)

The runtime target is Linux only, but contributors can build on macOS using the provided dev image:

```bash
docker build -t akmon-dev -f Dockerfile.dev .
docker run --rm -v "$PWD:/src" -w /src akmon-dev make build-no-ui
```

Loading eBPF programs into the kernel requires a Linux host; use a VM, a cloud Linux box, or CI (see `.github/workflows/ci.yml`) for runtime tests.

---

## Quick Start

### Templates setup (akmon-templates)

Akmon needs two template directories:

- **Behavioral**: `behavioral-templates/` (from `akmon-templates`)
- **Nuclei**: `nuclei-templates/` (from `akmon-templates`)

Choose one of these common layouts.

#### Option A — templates nested inside `akmon` (defaults)

From the `akmon` repo directory, defaults expect:

- `./akmon-templates/behavioral-templates`
- `./nuclei-templates` (you can symlink it to the bundle)

```bash
git clone https://github.com/ClawGuard-Labs/akmon-templates.git akmon-templates
ln -sfn akmon-templates/nuclei-templates ./nuclei-templates   # optional: default nuclei path
```

#### Option B — templates as a sibling repo (pass flags)

If `akmon-templates` sits next to `akmon`:

```bash
sudo ./bin/akmon \
  --behavioral-templates ../akmon-templates/behavioral-templates \
  --nuclei-templates ../akmon-templates/nuclei-templates
```

### Run

If you used **Option A** (defaults), you can run:

```bash
sudo ./bin/akmon
```

**More flags:**

```bash
sudo ./bin/akmon \
  --output          events.json \
  --log-level       info \
  --grouped \
  --group-timeout   500ms
```

See [Detection Templates](#detection-templates) for authoring and rule bundles.

---

## Build Targets

```bash
make build          # Compile Go binary + embed eBPF object → bin/akmon
make bpf            # Recompile eBPF C → bpf/monitor.bpf.o  (needs clang)
make deps           # check all build/runtime dependencies
make gen-vmlinux    # Regenerate vmlinux.h from kernel BTF   (once per kernel)
make ui             # build the React dashboard (requires Node.js ≥ 18)
make run            # Build and run as root
make install        # Install to /usr/local/bin/akmon
make clean          # Remove bin/
make lint           # Run golangci-lint
```

---

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--bpf-obj <path>` | auto-detect | Path to `monitor.bpf.o`. Auto-detected: `./bpf/`, next to binary, `/usr/lib/akmon/` |
| `--behavioral-templates <dir>` | `./akmon-templates/behavioral-templates` | Directory containing behavioral YAML rules |
| `--nuclei-templates <dir>` | `./nuclei-templates` | Directory containing Nuclei YAML templates for active scanning |
| `--no-nuclei` | false | Disable active Nuclei scanning |
| `--output <file>` | stdout | JSON output file (appended) |
| `--sse <addr>` | disabled | SSE live stream address, e.g. `:8080`. Connect with `curl http://localhost:8080/events` |
| `--grouped` | false | Buffer events by session and flush as one JSON block per session |
| `--group-timeout <dur>` | `500ms` | Idle time before a session group is flushed (only with `--grouped`) |
| `--log-level <level>` | `info` | Log verbosity: `debug` \| `info` \| `warn` \| `error` |
| `--config <path>` | auto-detect | Path to `config.yaml` (AI services/ports, model extensions, AI process names). If unset, Akmon searches `./config.yaml`, then `/etc/akmon/config.yaml`, then next to the binary. |
| `--no-tls` | false | Disable TLS uprobe capture (uprobes on `libssl.so`) |
| `--cors-origin <url>` | `http://localhost:9090`, `http://127.0.0.1:9090` | Allowed origins for the dashboard API (repeatable). Defaults cover the local dashboard only. |
| `--version` | — | Print version and exit |

---

## Configuration (`config.yaml`)

Akmon ships with a `config.yaml` that defines the **AI profile** used at runtime:

- **`ai.services`**: localhost ports Akmon treats as AI services (used for service labeling and for triggering the Nuclei scanner on observed connections).
- **`ai.processes`**: process names that should be considered AI runtimes/agents (powers the `is_ai_process` flag used by behavioral rules).
- **`ai.model_extensions`**: model file extensions used by file-access rules (e.g. `.gguf`, `.safetensors`, `.onnx`).

**Scanned AI service ports:**

| Port | Service |
|------|---------|
| 6333 | Qdrant |
| 8000 | ChromaDB |
| 8080 | Weaviate |
| 11434 | Ollama |
| 8001 | vLLM |
| 7860 | Gradio |
| 8501 | Streamlit |
| 3000 | LocalAI |
| 19530 | Milvus |
| 9200 | Elasticsearch |

Deduplication: each unique `host:port` is scanned at most once per 10 minutes.

---

## Output Format

### Flat NDJSON (default)

One JSON line per event:

```json
{"timestamp":"2026-02-21T10:00:01Z","event_type":"exec","pid":12345,"comm":"python3","binary":"/usr/bin/python3","ai_session_id":"sess_a1b2c3d4","risk_score":10,"tags":["ai_process"],"is_ai_process":true}
{"timestamp":"2026-02-21T10:00:02Z","event_type":"net_connect","pid":12345,"comm":"python3","network":{"dst_ip":"127.0.0.1","dst_port":6333,"protocol":"tcp"},"ai_session_id":"sess_a1b2c3d4","risk_score":10,"tags":["outbound_http"]}
{"timestamp":"2026-02-21T10:00:04Z","event_type":"nuclei_finding","pid":12345,"comm":"python3","ai_session_id":"sess_a1b2c3d4","risk_score":70,"tags":["nuclei_finding","qdrant-unauth-access"],"nuclei_result":{"template_id":"qdrant-unauth-access","name":"Qdrant Vector DB Unauthenticated Access","severity":"high","matched_url":"http://127.0.0.1:6333/collections","service":"qdrant"}}
```

### Grouped JSON (`--grouped`)

All events from a session in one block:

```json
{
  "session_id": "sess_a1b2c3d4",
  "parent_comm": "bash",
  "first_seen": "2026-02-21T10:00:01Z",
  "last_seen":  "2026-02-21T10:00:30Z",
  "duration_ms": 29000,
  "peak_risk_score": 80,
  "tags": ["ai_process", "outbound_http", "nuclei_finding", "qdrant-unauth-access"],
  "event_count": 12,
  "events": [ ... ]
}
```

### Risk Score Guide

| Score | Severity | Meaning |
|-------|----------|---------|
| 0–20 | Info | Normal AI activity (process start, model load, HTTP request) |
| 21–50 | Low | Minor concern (config access, file deletion, unusual port) |
| 51–75 | Medium | Elevated risk (download+exec chain, sensitive file access) |
| 76–100 | High | Strong indicator (SSH key access, self-modification) |
| 101+ | Critical | Multiple high-risk patterns in same session |

Nuclei findings add their own score on top of the behavioral score.

---

## Testing

### Test behavioral detection

```bash
# Start monitor
sudo ./bin/akmon --log-level debug --output test.json

# In another terminal — trigger rules:

# ai_process + model_load
python3 -c "open('/tmp/model.pt', 'w').close(); open('/tmp/model.pt')"

# ssh_key_access
cat ~/.ssh/id_rsa 2>/dev/null || echo "no key"

# outbound_http
curl -s https://api.openai.com/v1/models -o /dev/null

# curl_bash_chain (high risk)
bash -c "curl -s http://example.com -o /dev/null"

# Check output
cat test.json | jq '.tags'
```

### Test Nuclei active scanning

```bash
# Start a local Qdrant instance (Docker)
docker run -d -p 6333:6333 qdrant/qdrant

# Start monitor with debug logging
sudo ./bin/akmon --log-level debug --output nuclei_test.json

# Connect something to Qdrant so the monitor sees the port
curl http://localhost:6333/collections

# Within seconds you should see in logs:
# INFO  nuclei: scan triggered  {"target": "http://127.0.0.1:6333", "service": "qdrant"}
# INFO  nuclei finding          {"template_id": "qdrant-unauth-access", "severity": "high"}

# Verify in output
cat nuclei_test.json | jq 'select(.event_type == "nuclei_finding")'
```

### Verify templates load

```bash
# The startup logs print which template directories were loaded.
# If you’re unsure which paths Akmon is using, see:
#   Templates setup: https://github.com/ClawGuard-Labs/akmon#templates-setup-akmon-templates
sudo ./bin/akmon --log-level info 2>&1 | grep -E "templates loaded|nuclei engine ready|active scanner enabled"
```

---

## Detection templates

Rules are maintained in **[akmon-templates](https://github.com/ClawGuard-Labs/akmon-templates)**. YAML-based rules evaluated against every eBPF event. Rules are loaded at startup — no recompilation required to add or modify them.

- **Local dev paths**: see [Templates setup](#templates-setup-akmon-templates).
- **System install paths**: `make install` copies templates under `/etc/akmon/` (see [Running as a Background Service (systemd)](#running-as-a-background-service-systemd)).
- **Tests**: `go test ./...` under `tests/` expects the templates repo as a sibling (`../akmon-templates`). Adjust `tests/helpers_test.go` if your layout differs.

---

## Running as a Background Service (systemd)

The monitor ships with a systemd unit file. Use `make install` to install everything system-wide and `make enable` to start it on boot.

### 1. Build and install

```bash
# Full build (eBPF + React UI + Go binary)
make build

# Install binary, BPF object, templates (from TEMPLATES_SRC), and systemd unit
sudo make install
```

`make install` places files at:

| Path | Contents |
|------|----------|
| `/usr/local/bin/akmon` | Binary |
| `/usr/lib/akmon/monitor.bpf.o` | eBPF object |
| `/etc/akmon/config.yaml` | AI profile used to classify AI processes/services and model file extensions |
| `/etc/akmon/behavioral-templates/` | Behavioral detection rules (from `akmon-templates`) |
| `/etc/akmon/nuclei-templates/` | Nuclei active scan templates (from `akmon-templates`) |
| `/etc/systemd/system/akmon.service` | systemd unit |
| `/etc/logrotate.d/akmon` | Log rotation config |

### 2. Enable and start

```bash
# Enable on boot and start immediately
sudo make enable

# Or manually with systemctl
sudo systemctl enable --now akmon
```

### 3. Check status and logs

```bash
# Service status
sudo systemctl status akmon

# Live logs (journald)
journalctl -u akmon -f

# Output log file (NDJSON events)
tail -f /var/log/akmon/monitor.log
```

### 4. Stop / restart / disable

```bash
sudo systemctl stop    akmon
sudo systemctl restart akmon
sudo systemctl disable akmon   # removes from boot
```

### 5. Uninstall

```bash
# Stops the service, disables it, and removes all installed files
sudo make uninstall

# Logs at /var/log/akmon/ are preserved — remove manually if desired
sudo rm -rf /var/log/akmon/
```

The default `ExecStart` passes the installed template directories and enables the web UI on port 9090:

```
http://localhost:9090    ← live graph dashboard
```
---

## SSE Live Stream

```bash
# Start monitor with SSE
sudo ./bin/akmon --sse :8080

# Stream events in real-time
curl -N http://localhost:8080/events

# Health check
curl http://localhost:8080/healthz
```

---

## Project Structure

```
akmon/
├── bpf/
│   ├── monitor.bpf.c          # eBPF kernel programs (syscall tracepoints)
│   ├── common.h               # Shared kernel/userspace structs and constants
│   ├── vmlinux.h              # BTF-generated kernel headers (CO-RE); see scripts/gen_vmlinux.sh
│   └── monitor.bpf.o          # produced by `make build` (also under bin/ when copied)
├── bin/                       # local build outputs: akmon, monitor.bpf.o (often gitignored)
├── cmd/monitor/
│   └── main.go                # Entry point, flags, config.yaml load, pipeline wiring
├── internal/
│   ├── aiprofile/
│   │   └── config.go          # Loads config.yaml (AI services, processes, model extensions)
│   ├── chagg/                 # Chain aggregation for --compact / --compact-log
│   ├── constants/             # FileExt, IsLocalhost, IsWriteOpen, SeverityScore, …
│   ├── consumer/              # Ring buffer reader + BPF struct decoder
│   ├── correlator/            # PID tracking, session assignment
│   ├── detector/              # Behavioral YAML loader + Analyze()
│   ├── graph/                 # In-memory graph + snapshots + SSE subscribers
│   ├── graphapi/              # Dashboard HTTP server (--ui); embeds Vite build
│   ├── loader/                # eBPF load, tracepoints, optional TLS uprobes / LSM
│   ├── nucleiscanner/         # Nuclei v3 wrapper + localhost service probes
│   ├── output/                # NDJSON, grouped writer, SSE mirror
│   ├── provenance/            # Cross-session file / net_connect taint
│   └── templates/             # Behavioral template YAML schema + loader
├── scripts/
│   ├── akmon.service           # systemd unit (installed to /etc/systemd/system/)
│   ├── logrotate.d/akmon
│   ├── check_deps.sh
│   └── gen_vmlinux.sh
├── tests/                     # `go test ./tests/...`
├── ui/                        # Vite + React dashboard source
├── assets/                    # Screenshots for this README
├── .github/                   # Issue/PR templates, CI workflows, CODEOWNERS
├── config.yaml                # Default AI profile; install copies to /etc/akmon/config.yaml
├── Dockerfile.dev             # Linux build/test toolchain (Go + clang + libbpf + Node)
├── go.mod
├── Makefile
├── README.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── SUPPORT.md
├── CHANGELOG.md
└── LICENSE
```

Behavioral and Nuclei YAML live in the separate **[akmon-templates](https://github.com/ClawGuard-Labs/akmon-templates)** repository.

### Preview

<p align="center">
  <img src="./assets/logs.png" width="1000"><br>
  <em>Realtime logs (Akmon running as a systemd service)</em>
</p>

<p align="center">
  <img src="./assets/dashboard.png" width="1000"><br>
  <em>Akmon Dashboard</em>
</p>

<p align="center">
  <img src="./assets/process_graph.png" width="1000"><br>
  <em>Real-time process graph visualisation</em>
</p>

---

## Dependencies

### Go modules (key)

| Module | Version | Purpose |
|--------|---------|---------|
| `github.com/cilium/ebpf` | v0.16.0 | eBPF program loading and ring buffer |
| `github.com/projectdiscovery/nuclei/v3` | v3.7.0 | Active vulnerability scanning engine |
| `go.uber.org/zap` | v1.27.0 | Structured logging |
| `gopkg.in/yaml.v3` | v3.0.1 | Behavioral template YAML parsing |

### System requirements

| Requirement | Version |
|-------------|---------|
| Linux kernel | ≥ 5.15 with BTF |
| Go toolchain | ≥ 1.22 |
| clang/LLVM | ≥ 14 (for eBPF recompilation only) |
| bpftool | any recent |

---

## FAQ

**`/sys/kernel/btf/vmlinux` does not exist.**
Your kernel wasn't built with `CONFIG_DEBUG_INFO_BTF=y`. Stock Ubuntu 22.04/24.04 and Debian 12 kernels already have BTF. If you're on a custom kernel, rebuild with `CONFIG_DEBUG_INFO_BTF=y` and `CONFIG_DEBUG_INFO_BTF_MODULES=y`.

**Permission denied when loading eBPF.**
You need one of: run as root, or grant `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN` via `setcap cap_bpf,cap_perfmon,cap_net_admin+eip ./bin/akmon`. Some distros also require `sysctl kernel.unprivileged_bpf_disabled=0` for non-root operation.

**`clang: command not found` when running `make bpf`.**
Install the eBPF toolchain: `sudo apt-get install -y clang llvm libbpf-dev linux-tools-$(uname -r) linux-tools-common`.

**I'm on macOS and `make build` fails.**
Akmon is Linux-only at runtime. Use `Dockerfile.dev` to build in a container (see [Build on macOS](#build-on-macos-via-docker)), and run the binary on a Linux host.

**CI says `../akmon-templates/behavioral-templates` missing.**
Tests expect the templates repo to live as a sibling directory. Clone it with `git clone https://github.com/ClawGuard-Labs/akmon-templates ../akmon-templates` (or override `TEMPLATES_SRC` in the Makefile).

---

## Community

- **Report a bug**: [GitHub Issues](https://github.com/ClawGuard-Labs/akmon/issues)
- **Propose a feature**: [GitHub Discussions](https://github.com/ClawGuard-Labs/akmon/discussions)
- **Report a vulnerability**: see [SECURITY.md](./SECURITY.md)

---

## Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, pull request process, and code conventions. By participating, you agree to our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Security

If you discover a security vulnerability, please report it privately. **Do not open a public issue.** See [SECURITY.md](./SECURITY.md) for the disclosure process.
