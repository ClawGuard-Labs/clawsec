# Contributing to ClawSec

Thank you for your interest in contributing. This document explains how to get set up, report issues, and submit changes.

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

## How to contribute

- **Report bugs** — Open an issue with the bug report template. Include environment, steps to reproduce, and expected vs actual behavior.
- **Suggest features** — Open an issue with the feature request template. Describe the use case and, if you can, a proposed design.
- **Contribute code** — Fork the repo, create a branch, make your changes, run tests, and open a pull request.

## Development setup

### Prerequisites

- Linux with kernel **≥ 5.15** and BTF (`/sys/kernel/btf/vmlinux`)
- **Go 1.22+**
- Root or `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN` to run the monitor
- For eBPF recompilation: `clang`, `llvm-strip`, `bpftool`

### Build and run

```bash
git clone https://github.com/ClawGuard-Labs/clawsec.git
cd clawsec
make install  
```

See [README.md](README.md#quick-start) for full options and [Build Targets](README.md#build-targets).

### Useful make targets

- `make build` — Build Go binary and embed eBPF object
- `make bpf` — Recompile eBPF C (requires clang)
- `make gen-vmlinux` — Regenerate `bpf/vmlinux.h` from kernel BTF
- `make run` — Build and run as root
- `make fmt` — Format Go and C source
- `make clean` — Remove build artifacts

## Pull request process

1. **Branch** — Create a branch from `main` (e.g. `feature/add-xyz`, `fix/issue-123`).
2. **Scope** — Keep one logical change per PR when possible.
3. **Description** — Use the PR template: what changed, why, and how to test.
4. **Tests** — Ensure the project builds and any existing tests pass.
5. **Review** — A maintainer will review and may request changes.

## Style and conventions

- **Go** — Use `gofmt`; run `make fmt`. Follow standard Go style.
- **eBPF/C** — Match existing style in `bpf/`; run `make fmt` for C.
- **Templates** — Follow the YAML schema and existing layout under `templates/` and `nuclei-templates/`.
- **Commits** — Use present tense and a clear summary (e.g. "Add CONTRIBUTING.md", "Fix session flush timeout").

## Adding detection rules

- **Behavioral rules** — Add a new `.yaml` under `templates/` (see [Detection Templates](README.md#detection-templates) and the template schema). No code change required; restart the monitor to load.
- **Nuclei rules** — Add Nuclei v3 HTTP templates under `nuclei-templates/ai-services/` for new AI services or checks.

## Recognition

Contributors may be acknowledged in release notes or the README. If you prefer to remain anonymous, say so in your PR or issue.
