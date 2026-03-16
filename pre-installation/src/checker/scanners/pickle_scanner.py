"""Pickle scanner — static analysis of pickle opcodes for dangerous imports."""

from __future__ import annotations

import io
import pickletools
import struct
import sys
from pathlib import Path

from ..models import ModelTarget, RuleFinding
from .base import BaseScanner

PICKLE_EXTENSIONS = {".pkl", ".pt", ".pth", ".bin"}

DANGEROUS_MODULES = {
    "os", "nt", "posix", "subprocess", "socket", "shutil",
    "builtins", "__builtin__", "sys", "importlib",
    "ctypes", "signal", "webbrowser", "code", "codeop",
    "compile", "compileall",
}

DANGEROUS_NAMES = {
    "system", "popen", "exec", "eval", "execfile",
    "compile", "open", "input", "__import__",
    "getattr", "setattr", "delattr",
    "globals", "locals", "vars",
    "Popen", "call", "check_output", "run",
}

PICKLE_MAGIC = b"\x80"
ZIP_MAGIC = b"PK"


class PickleScanner(BaseScanner):
    """Check AI-CE-001: detect dangerous pickle imports via opcode analysis."""

    def scan(self, target: ModelTarget) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        if target.path is None:
            return findings

        path = Path(target.path)
        files = list(path.rglob("*")) if path.is_dir() else [path]
        pickle_files = [f for f in files if f.is_file() and f.suffix.lower() in PICKLE_EXTENSIONS]

        for pf in pickle_files:
            dangerous = self._scan_file(pf)
            if dangerous:
                imports_str = ", ".join(sorted(dangerous)[:10])
                f = self._finding(
                    "AI-CE-001",
                    f"Dangerous pickle imports detected in {pf.name}: {imports_str}",
                    evidence=f"file={pf}, imports=[{imports_str}]",
                )
                if f:
                    findings.append(f)

        return findings

    def _scan_file(self, path: Path) -> set[str]:
        """Scan a single file for dangerous pickle opcodes. Returns set of dangerous import strings."""
        dangerous_found: set[str] = set()
        try:
            data = path.read_bytes()
        except OSError:
            return dangerous_found

        # PyTorch .pt/.pth files are ZIP archives containing pickle streams
        pickle_streams = self._extract_pickle_streams(data)

        for stream in pickle_streams:
            dangerous_found.update(self._analyze_opcodes(stream))

        return dangerous_found

    def _extract_pickle_streams(self, data: bytes) -> list[bytes]:
        """Extract pickle byte streams from raw data or ZIP (PyTorch) containers."""
        streams: list[bytes] = []

        if data[:2] == ZIP_MAGIC:
            streams.extend(self._extract_from_zip(data))
        elif data[:1] == PICKLE_MAGIC or self._looks_like_pickle(data):
            streams.append(data)

        if not streams and len(data) > 0:
            streams.append(data)

        return streams

    def _extract_from_zip(self, data: bytes) -> list[bytes]:
        """Extract .pkl entries from a ZIP archive (PyTorch format)."""
        import zipfile
        streams: list[bytes] = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for name in zf.namelist():
                    if name.endswith(".pkl") or name.endswith("/data.pkl"):
                        streams.append(zf.read(name))
        except (zipfile.BadZipFile, Exception):
            pass
        return streams

    @staticmethod
    def _looks_like_pickle(data: bytes) -> bool:
        return len(data) > 2 and data[-1:] == b"."  # pickle STOP opcode

    def _analyze_opcodes(self, data: bytes) -> set[str]:
        """Use pickletools to disassemble and find GLOBAL/INST opcodes with dangerous modules."""
        dangerous: set[str] = set()

        # Method 1: pickletools disassembly (redirect stdout)
        try:
            old_stdout = sys.stdout
            sys.stdout = buf = io.StringIO()
            try:
                pickletools.dis(io.BytesIO(data))
            finally:
                sys.stdout = old_stdout
            disasm = buf.getvalue()
            for line in disasm.splitlines():
                line_stripped = line.strip()
                if "GLOBAL" in line_stripped or "INST" in line_stripped or "STACK_GLOBAL" in line_stripped:
                    dangerous.update(self._check_import_line(line_stripped))
        except Exception:
            pass

        # Method 2: opcode-level scan for STACK_GLOBAL pattern
        # STACK_GLOBAL (0x93) pops module and name from stack; preceding SHORT_BINUNICODE
        # opcodes (0x8c) carry the strings.
        dangerous.update(self._opcode_scan(data))

        # Method 3: raw byte scan for module.name patterns
        dangerous.update(self._raw_byte_scan(data))

        return dangerous

    def _check_import_line(self, line: str) -> set[str]:
        """Check a disassembled line for dangerous module.name references."""
        found: set[str] = set()
        for token in line.split():
            if "." in token or " " in token:
                parts = token.replace(" ", ".").split(".")
                module = parts[0]
                name = parts[-1] if len(parts) > 1 else ""
                if module in DANGEROUS_MODULES:
                    found.add(f"{module}.{name}" if name else module)
                if name in DANGEROUS_NAMES:
                    found.add(f"{module}.{name}" if module else name)
        return found

    def _opcode_scan(self, data: bytes) -> set[str]:
        """Scan pickle bytecode for SHORT_BINUNICODE strings near STACK_GLOBAL/REDUCE opcodes."""
        found: set[str] = set()
        strings: list[str] = []

        OP_SHORT_BINUNICODE = 0x8C
        OP_BINUNICODE = 0x8D
        OP_STACK_GLOBAL = 0x93
        OP_GLOBAL = 0x63
        OP_INST = 0x69
        OP_REDUCE = 0x52

        i = 0
        while i < len(data):
            op = data[i]
            if op == OP_SHORT_BINUNICODE and i + 1 < len(data):
                length = data[i + 1]
                if i + 2 + length <= len(data):
                    s = data[i + 2: i + 2 + length].decode("utf-8", errors="replace")
                    strings.append(s)
                    i += 2 + length
                    continue
            elif op == OP_STACK_GLOBAL or op == OP_REDUCE:
                if len(strings) >= 2:
                    module, name = strings[-2], strings[-1]
                    if module in DANGEROUS_MODULES or name in DANGEROUS_NAMES:
                        found.add(f"{module}.{name}")
                elif len(strings) == 1:
                    if strings[-1] in DANGEROUS_MODULES or strings[-1] in DANGEROUS_NAMES:
                        found.add(strings[-1])
                i += 1
                continue
            elif op == OP_GLOBAL or op == OP_INST:
                # GLOBAL/INST opcodes have inline "module\nname\n" string
                nl1 = data.find(b"\n", i + 1)
                if nl1 != -1:
                    nl2 = data.find(b"\n", nl1 + 1)
                    if nl2 != -1:
                        module = data[i + 1:nl1].decode("utf-8", errors="replace")
                        name = data[nl1 + 1:nl2].decode("utf-8", errors="replace")
                        if module in DANGEROUS_MODULES or name in DANGEROUS_NAMES:
                            found.add(f"{module}.{name}")
                        i = nl2 + 1
                        continue
            i += 1

        return found

    def _raw_byte_scan(self, data: bytes) -> set[str]:
        """Scan raw bytes for dangerous module references (catches obfuscation bypasses)."""
        found: set[str] = set()
        text = data.decode("latin-1")
        for mod in DANGEROUS_MODULES:
            for name in DANGEROUS_NAMES:
                pattern = f"{mod}\n{name}"
                if pattern in text:
                    found.add(f"{mod}.{name}")
                pattern2 = f"{mod} {name}"
                if pattern2 in text:
                    found.add(f"{mod}.{name}")
        return found
