# ClawSec

**Kernel-level behavioral monitoring and active vulnerability scanning for AI/ML workloads on Linux.**

Combines two complementary detection engines:

1. **Behavioral detector** — eBPF-based passive monitoring of syscalls, network events, and file operations matched against YAML rules (our engine, Nuclei-inspired)
2. **Nuclei active scanner** — fires automatically against local AI service endpoints when they're detected, finding real vulnerabilities like unauthenticated vector DB access

### What's in this repo

- **eBPF kernel programs** — Tracepoints for exec, file, network, and mmap events (CO-RE, BTF)
- **Behavioral detection engine** — YAML template rules (Nuclei-inspired) for process, file, network, and session patterns
- **Nuclei v3 integration** — Active scanning of local AI services (Qdrant, ChromaDB, Ollama, vLLM, etc.) when connections are observed
- **Session correlation** — Process tree and session IDs for grouping events
- **Output** — NDJSON, grouped JSON, or live SSE stream
- **Detection templates** — Ready-made rules under `templates/` and `nuclei-templates/`
- **React dashboard** (optional) — Graph view and alert panel served by the monitor

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  Kernel (eBPF tracepoints — stable ABI, CO-RE, kernel ≥ 5.15) │
│  execve │ openat │ read/write │ unlinkat │ mmap │ connect │ …  │
└─────────────────────────┬──────────────────────────────────────┘
                          │  ring buffer (8 MB)
┌─────────────────────────▼──────────────────────────────────────┐
│  consumer   → decode raw bytes      → EnrichedEvent            │
│  correlator → assign session ID     → process tree + timing    │
│  detector   → YAML template rules   → tags + risk score        │
│      │                                                          │
│      └─ net_connect to localhost AI port?                       │
│              │                                                  │
│              ▼  (async goroutine)                               │
│         Nuclei engine → scan target → nuclei_finding event      │
│                                                                  │
│  output → NDJSON / grouped JSON → stdout / file / SSE          │
└────────────────────────────────────────────────────────────────┘
```

### How the two detectors work together

| | Behavioral Detector | Nuclei Scanner |
|---|---|---|
| **Type** | Passive | Active |
| **Input** | eBPF kernel events | HTTP requests to local services |
| **Runs on** | Every event | Only `net_connect` to localhost AI ports |
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

## Quick Start

```bash
# Clone and build
git clone https://github.com/ClawGuard-Labs/clawsec
cd clawsec
make build

# Run (requires root)
sudo ./bin/monitor

# With all options
sudo ./bin/monitor \
  --templates       ./templates \
  --nuclei-templates ./nuclei-templates \
  --output          events.json \
  --log-level       info \
  --grouped \
  --group-timeout   500ms
```

---

## Build Targets

```bash
make build          # Compile Go binary + embed eBPF object → bin/monitor
make bpf            # Recompile eBPF C → bpf/monitor.bpf.o  (needs clang)
make gen-vmlinux    # Regenerate vmlinux.h from kernel BTF   (once per kernel)
make run            # Build and run as root
make install        # Install to /usr/local/bin/clawsec
make clean          # Remove bin/
```

---

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--bpf-obj <path>` | auto-detect | Path to `monitor.bpf.o`. Auto-detected: `./bpf/`, next to binary, `/usr/lib/clawsec/` |
| `--templates <dir>` | `./templates` | Directory containing behavioral YAML detection templates |
| `--nuclei-templates <dir>` | `./nuclei-templates` | Directory containing Nuclei YAML templates for active scanning |
| `--no-nuclei` | false | Disable active Nuclei scanning |
| `--output <file>` | stdout | JSON output file (appended) |
| `--sse <addr>` | disabled | SSE live stream address, e.g. `:8080`. Connect with `curl http://localhost:8080/events` |
| `--grouped` | false | Buffer events by session and flush as one JSON block per session |
| `--group-timeout <dur>` | `500ms` | Idle time before a session group is flushed (only with `--grouped`) |
| `--log-level <level>` | `info` | Log verbosity: `debug` \| `info` \| `warn` \| `error` |
| `--no-tls` | false | Disable TLS uprobe capture (uprobes on `libssl.so`) |
| `--version` | — | Print version and exit |

---

## Detection Templates

### Behavioral Templates (`templates/`)

YAML-based rules evaluated against every eBPF event. Rules are loaded at startup — no recompilation required to add or modify them.

```
templates/
├── file/
│   ├── model-load.yaml          # AI model file extensions (.pt, .gguf, .safetensors …)
│   ├── large-mmap.yaml          # Memory-mapped files >100 MB (model load via mmap)
│   ├── sensitive-path.yaml      # /etc, /proc, /sys access
│   ├── ssh-key-access.yaml      # SSH private key / authorized_keys access
│   ├── self-modify.yaml         # Process writes to its own binary
│   ├── config-access.yaml       # .json, .yaml, .env, .toml file access
│   └── file-deleted.yaml        # File deletion (unlink)
├── network/
│   ├── outbound-http.yaml       # Connections to port 80/443
│   ├── http-post.yaml           # HTTP POST requests
│   └── unusual-port.yaml        # Connections to non-standard ports
├── process/
│   ├── ai-process.yaml          # Known AI runtimes (python, ollama, vllm …)
│   └── shell-spawned-by-ai.yaml # Shell (bash/sh/zsh) spawned in AI session
└── session/
    ├── download-exec-chain.yaml  # exec within 30s of net_connect
    ├── curl-bash-chain.yaml      # curl/wget → shell pattern (RCE risk)
    ├── long-running-llm.yaml     # AI process active >5 minutes
    └── read-write-inference-loop.yaml  # Read one file, write another (inference pipeline)
```

#### Template Schema

```yaml
id: ssh_key_access                # Used as event tag and session tag

info:
  name: SSH Key Access
  author: sl4y3r
  severity: high                  # info | low | medium | high | critical
  description: "..."
  tags: [ai, credentials, ssh]
  risk-score: 50                  # Added to event.risk_score when rule fires

matchers:
  - type: event-type              # Match on EventType string
    values: [file_open, file_rw]

  - type: filepath                # Match on FilePath
    words: [/.ssh/, /id_rsa, /id_ed25519, /authorized_keys]
    condition: or                 # any word matches → matcher passes

matchers-condition: and           # ALL matchers must pass (default: "and")
```

#### Matcher Types

| Type | Fields | Matches Against |
|------|--------|----------------|
| `event-type` | `values` | `ev.EventType` |
| `process` | `field` (comm/binary/cmdline/is_ai_process), `values`, `words`, `regex` | Process info |
| `filepath` | `words`, `extensions`, `values`, `regex` | `ev.FilePath` |
| `network` | `field` (dst_port/dst_ip/http_method/protocol), `values`, `lt`, `gt` | `ev.Network` |
| `risk-flag` | `flags` (sensitive/large_mmap/http) | `ev.RiskFlags` bitmask |
| `session` | `field` (exec_after_net/has_ai_process/duration_minutes/…), `equals`, `lt`, `gt` | Session state |
| `tls-payload` | `words`, `regex` | `ev.TLSPayload` |

Add `negate: true` to any matcher to invert its result.

#### Adding a custom behavioral rule

Create a new `.yaml` file anywhere under `templates/` and restart the monitor:

```yaml
id: my_custom_rule
info:
  name: My Custom Rule
  severity: high
  risk-score: 60
matchers:
  - type: event-type
    values: [exec]
  - type: process
    field: cmdline
    words: [suspicious-binary]
matchers-condition: and
```

### Nuclei Templates (`nuclei-templates/`)

Standard Nuclei v3 HTTP templates. These run as active scans against detected local AI services.

```
nuclei-templates/ai-services/
├── qdrant-unauth.yaml        # Qdrant vector DB unauthenticated /collections
├── chromadb-unauth.yaml      # ChromaDB unauthenticated /api/v1/collections
├── ollama-api-exposed.yaml   # Ollama /api/tags exposed
├── weaviate-unauth.yaml      # Weaviate /v1/schema exposed
├── vllm-api-exposed.yaml     # vLLM /v1/models exposed
├── gradio-exposed.yaml       # Gradio ML app publicly accessible
└── localai-exposed.yaml      # LocalAI /v1/models exposed
```

#### How Nuclei scanning is triggered

```
eBPF event: net_connect
  DstIP  = 127.0.0.1
  DstPort = 6333           ← known AI service port (Qdrant)
      │
      ├─→ Behavioral detector runs (all YAML rules)
      │
      └─→ Nuclei scanner (async goroutine):
              http://127.0.0.1:6333  ← scan target
              ↓
              nuclei-templates/ai-services/*.yaml
              ↓
              finding: qdrant-unauth-access (severity: high)
              ↓
              emitted as nuclei_finding event → JSON output
```

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
sudo ./bin/monitor --log-level debug --output test.json

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
sudo ./bin/monitor --log-level debug --output nuclei_test.json

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
# Check behavioral templates load (seen in startup logs)
sudo ./bin/monitor --log-level info 2>&1 | grep "templates loaded"
# Expected: INFO  detection templates loaded  {"count": 16, "dir": "./templates"}

# Check Nuclei engine starts
sudo ./bin/monitor --log-level info 2>&1 | grep "nuclei"
# Expected: INFO  nuclei engine ready  {"templates_dir": "./nuclei-templates"}
#           INFO  nuclei active scanner enabled
```

### Full test command

```bash
sudo ./bin/monitor \
  --templates        ./templates \
  --nuclei-templates ./nuclei-templates \
  --output           events.json \
  --log-level        debug \
  --grouped \
  --group-timeout    500ms
```
---

## Running as a Background Service (systemd)

The monitor ships with a systemd unit file. Use `make install` to install everything system-wide and `make enable` to start it on boot.

### 1. Build and install

```bash
# Full build (eBPF + React UI + Go binary)
make build

# Install binary, BPF object, templates, and systemd unit
sudo make install
```

`make install` places files at:

| Path | Contents |
|------|----------|
| `/usr/local/bin/clawsec` | Binary |
| `/usr/lib/clawsec/monitor.bpf.o` | eBPF object |
| `/etc/clawsec/templates/` | Behavioral detection rules |
| `/etc/clawsec/nuclei-templates/` | Nuclei active scan templates |
| `/etc/systemd/system/clawsec.service` | systemd unit |
| `/etc/logrotate.d/clawsec` | Log rotation config |

### 2. Enable and start

```bash
# Enable on boot and start immediately
sudo make enable

# Or manually with systemctl
sudo systemctl enable --now clawsec
```

### 3. Check status and logs

```bash
# Service status
sudo systemctl status clawsec

# Live logs (journald)
journalctl -u clawsec -f

# Output log file (NDJSON events)
tail -f /var/log/clawsec/monitor.log
```

### 4. Stop / restart / disable

```bash
sudo systemctl stop    clawsec
sudo systemctl restart clawsec
sudo systemctl disable clawsec   # removes from boot
```

### 5. Uninstall

```bash
# Stops the service, disables it, and removes all installed files
sudo make uninstall

# Logs at /var/log/clawsec/ are preserved — remove manually if desired
sudo rm -rf /var/log/clawsec/
```

The default `ExecStart` passes the installed template directories and enables the web UI on port 9090:

```
http://localhost:9090    ← live graph dashboard
```
---

## SSE Live Stream

```bash
# Start monitor with SSE
sudo ./bin/monitor --sse :8080

# Stream events in real-time
curl -N http://localhost:8080/events

# Health check
curl http://localhost:8080/healthz
```

---

## Project Structure

```
clawsec/
├── bpf/
│   ├── monitor.bpf.c          # eBPF kernel programs (syscall tracepoints)
│   ├── common.h               # Shared kernel/userspace structs and constants
│   └── vmlinux.h              # BTF-generated kernel headers (CO-RE)
├── cmd/monitor/
│   └── main.go                # Entry point, flag parsing, pipeline wiring
├── internal/
|   ├── constants/
|   |   ├── helpers.go
│   ├── consumer/
│   │   ├── consumer.go        # Ring buffer reader
│   │   └── events.go          # Binary event structs + decoder + NucleiResult
│   ├── correlator/
│   │   ├── correlator.go      # PID tracking, session assignment
│   │   └── session.go         # Session state machine
│   ├── detector/
│   │   ├── detector.go        # YAML template loader + Analyze()
│   │   └── engine.go          # Template evaluation (7 matcher types)
│   ├── loader/
│   │   └── loader.go          # eBPF object loader + tracepoint attachment
│   ├── nucleiscanner/
│   │   └── scanner.go         # Nuclei v3 engine wrapper + async scan queue
│   ├── output/
│   │   └── output.go          # Flat NDJSON + grouped JSON + SSE
│   └── templates/
│       ├── schema.go           # YAML template schema (Template, Matcher structs)
│       └── loader.go           # Walk templates/ dir, parse + compile regex
├── templates/                  # Behavioral detection rules (our YAML engine)
│   ├── file/
│   ├── network/
│   ├── process/
│   └── session/
├── nuclei-templates/           # Active scanning rules (Nuclei v3 HTTP format)
│   └── ai-services/
├── go.mod
├── go.sum
└── Makefile
```

### Preview

<p align="center">
  <img src="./assets/logs.png" width="1000"><br>
  <em>Realtime logs (ClawSec running as a systemd service)</em>
</p>

<p align="center">
  <img src="./assets/dashboard.png" width="1000"><br>
  <em>ClawSec Dashboard</em>
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

## Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, pull request process, and code conventions. By participating, you agree to our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Security

If you discover a security vulnerability, please report it privately. **Do not open a public issue.**

- **Preferred:** Open a [GitHub Security Advisory](https://github.com/clouddefense/agentic-security/security/advisories/new) (if the repo is under your org), or email the maintainers.
- We will acknowledge and work on a fix; we may credit you in the advisory unless you prefer to remain anonymous.
