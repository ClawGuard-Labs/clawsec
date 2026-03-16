"""GGUF scanner — parses GGUF metadata and checks Jinja2 chat templates for SSTI."""

from __future__ import annotations

import struct
from pathlib import Path

from ..models import ModelTarget, RuleFinding
from .base import BaseScanner

GGUF_MAGIC = b"GGUF"

# GGUF metadata value types
GGUF_TYPE_STRING = 8
GGUF_TYPE_UINT8 = 0
GGUF_TYPE_INT8 = 1
GGUF_TYPE_UINT16 = 2
GGUF_TYPE_INT16 = 3
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_INT32 = 5
GGUF_TYPE_FLOAT32 = 6
GGUF_TYPE_BOOL = 7
GGUF_TYPE_UINT64 = 9
GGUF_TYPE_INT64 = 10
GGUF_TYPE_FLOAT64 = 11
GGUF_TYPE_ARRAY = 12

SSTI_DANGEROUS_PATTERNS = [
    "__class__",
    "__globals__",
    "__subclasses__",
    "__import__",
    "__builtins__",
    "__getattr__",
    "__init__",
    "cycler",
    "joiner",
    "namespace",
    "lipsum",
    "request.",
    "config.",
    "self._TemplateReference",
]

CHAT_TEMPLATE_KEY = "tokenizer.chat_template"


class GGUFScanner(BaseScanner):
    """Check AI-MF-002: GGUF files with dangerous Jinja2 chat templates."""

    def scan(self, target: ModelTarget) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        if target.path is None:
            return findings

        path = Path(target.path)
        files = list(path.rglob("*.gguf")) if path.is_dir() else ([path] if path.suffix.lower() == ".gguf" else [])

        for gf in files:
            template, dangerous = self._scan_gguf(gf)
            if dangerous:
                patterns_str = ", ".join(sorted(dangerous)[:5])
                f = self._finding(
                    "AI-MF-002",
                    f"GGUF chat template in {gf.name} contains SSTI-dangerous constructs: {patterns_str}",
                    evidence=f"file={gf}, patterns=[{patterns_str}]",
                )
                if f:
                    findings.append(f)

        return findings

    def _scan_gguf(self, path: Path) -> tuple[str, list[str]]:
        """Parse GGUF header, extract chat_template, check for SSTI patterns.

        Returns (template_string, list_of_dangerous_patterns_found).
        """
        template = ""
        dangerous: list[str] = []
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic != GGUF_MAGIC:
                    return template, dangerous

                version = struct.unpack("<I", f.read(4))[0]
                if version < 2:
                    return template, dangerous

                tensor_count = struct.unpack("<Q", f.read(8))[0]
                metadata_kv_count = struct.unpack("<Q", f.read(8))[0]

                for _ in range(metadata_kv_count):
                    key = self._read_string(f)
                    value_type = struct.unpack("<I", f.read(4))[0]
                    value = self._read_value(f, value_type)

                    if key == CHAT_TEMPLATE_KEY and isinstance(value, str):
                        template = value
                        break
        except (OSError, struct.error, OverflowError, MemoryError):
            return template, dangerous

        if template:
            for pattern in SSTI_DANGEROUS_PATTERNS:
                if pattern in template:
                    dangerous.append(pattern)

        return template, dangerous

    @staticmethod
    def _read_string(f) -> str:
        length = struct.unpack("<Q", f.read(8))[0]
        if length > 10_000_000:
            raise OverflowError(f"GGUF string length too large: {length}")
        return f.read(length).decode("utf-8", errors="replace")

    def _read_value(self, f, value_type: int):
        if value_type == GGUF_TYPE_STRING:
            return self._read_string(f)
        elif value_type == GGUF_TYPE_UINT32:
            return struct.unpack("<I", f.read(4))[0]
        elif value_type == GGUF_TYPE_INT32:
            return struct.unpack("<i", f.read(4))[0]
        elif value_type == GGUF_TYPE_FLOAT32:
            return struct.unpack("<f", f.read(4))[0]
        elif value_type == GGUF_TYPE_UINT64:
            return struct.unpack("<Q", f.read(8))[0]
        elif value_type == GGUF_TYPE_INT64:
            return struct.unpack("<q", f.read(8))[0]
        elif value_type == GGUF_TYPE_FLOAT64:
            return struct.unpack("<d", f.read(8))[0]
        elif value_type == GGUF_TYPE_BOOL:
            return struct.unpack("<?", f.read(1))[0]
        elif value_type == GGUF_TYPE_UINT8:
            return struct.unpack("<B", f.read(1))[0]
        elif value_type == GGUF_TYPE_INT8:
            return struct.unpack("<b", f.read(1))[0]
        elif value_type == GGUF_TYPE_UINT16:
            return struct.unpack("<H", f.read(2))[0]
        elif value_type == GGUF_TYPE_INT16:
            return struct.unpack("<h", f.read(2))[0]
        elif value_type == GGUF_TYPE_ARRAY:
            elem_type = struct.unpack("<I", f.read(4))[0]
            count = struct.unpack("<Q", f.read(8))[0]
            return [self._read_value(f, elem_type) for _ in range(min(count, 100_000))]
        else:
            raise ValueError(f"Unknown GGUF type: {value_type}")
