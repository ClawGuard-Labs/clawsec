# Contributing to Onyx

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
git clone https://github.com/ClawGuard-Labs/onyx.git
git clone https://github.com/ClawGuard-Labs/onyx-templates.git
cd onyx
make build
```

For running the monitor locally, clone **onyx-templates** under `onyx/onyx-templates` or pass `--behavioral-templates` / `--nuclei-templates` (see [README — Quick Start](README.md#quick-start)). For system install, `sudo make install` reads YAML from `../onyx-templates` by default (`TEMPLATES_SRC`).

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
- **Templates** — YAML rules live in **[onyx-templates](https://github.com/ClawGuard-Labs/onyx-templates)**; follow [AUTHORING.md](https://github.com/ClawGuard-Labs/onyx-templates/blob/main/AUTHORING.md) and the layout there.
- **Commits** — Use present tense and a clear summary (e.g. "Add CONTRIBUTING.md", "Fix session flush timeout").

## Adding detection rules

Open PRs against **[onyx-templates](https://github.com/ClawGuard-Labs/onyx-templates)** (not this repo).

- **Behavioral rules** — Add `.yaml` under `behavioral-templates/session|file|process|network/`. See [Detection Templates](README.md#detection-templates) and onyx-templates [AUTHORING.md](https://github.com/ClawGuard-Labs/onyx-templates/blob/main/AUTHORING.md).
- **Nuclei rules** — Add Nuclei v3 HTTP templates under `nuclei-templates/ai-services/`.

## Recognition

Contributors may be acknowledged in release notes or the README. If you prefer to remain anonymous, say so in your PR or issue.
