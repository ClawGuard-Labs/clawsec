#!/usr/bin/env python3
"""Generate binary test fixtures for the checker test suite."""

import pickle
import struct
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def create_malicious_pickle():
    """Create a .pkl file with a dangerous os.system import."""
    # Craft a pickle that contains a GLOBAL opcode referencing os.system
    # This is a minimal pickle that would trigger AI-CE-001
    payload = (
        b"\x80\x04"          # PROTO 4
        b"\x95\x1a\x00\x00\x00\x00\x00\x00\x00"  # FRAME
        b"\x8c\x02os"        # SHORT_BINUNICODE "os"
        b"\x8c\x06system"    # SHORT_BINUNICODE "system"
        b"\x93"              # STACK_GLOBAL (os.system)
        b"\x8c\x02id"        # SHORT_BINUNICODE "id"
        b"\x85"              # TUPLE1
        b"\x52"              # REDUCE
        b"."                 # STOP
    )
    out = FIXTURES / "malicious_pickle" / "model.pkl"
    out.write_bytes(payload)
    print(f"Created: {out} ({len(payload)} bytes)")


def create_clean_safetensors():
    """Create a minimal .safetensors file (empty header, no tensors)."""
    header = b"{}"
    header_len = struct.pack("<Q", len(header))
    data = header_len + header
    out = FIXTURES / "clean_model" / "model.safetensors"
    out.write_bytes(data)
    print(f"Created: {out} ({len(data)} bytes)")


def create_malicious_gguf():
    """Create a minimal GGUF v3 file with a poisoned chat_template."""
    buf = bytearray()

    # Magic
    buf += b"GGUF"
    # Version 3
    buf += struct.pack("<I", 3)
    # Tensor count = 0
    buf += struct.pack("<Q", 0)
    # Metadata KV count = 1
    buf += struct.pack("<Q", 1)

    # Key: tokenizer.chat_template
    key = b"tokenizer.chat_template"
    buf += struct.pack("<Q", len(key))
    buf += key

    # Value type: string (8)
    buf += struct.pack("<I", 8)

    # Value: a chat template with SSTI-dangerous patterns
    template = b"{% for msg in messages %}{{ msg.__class__.__globals__ }}{% endfor %}"
    buf += struct.pack("<Q", len(template))
    buf += template

    out = FIXTURES / "malicious_gguf"
    out.mkdir(exist_ok=True)
    out_file = out / "model.gguf"
    out_file.write_bytes(bytes(buf))
    print(f"Created: {out_file} ({len(buf)} bytes)")

    readme = out / "README.md"
    readme.write_text("# GGUF test\n\n## Training Data\n\nTest dataset.\n")


def create_clean_gguf():
    """Create a minimal clean GGUF v3 file with a safe chat_template."""
    buf = bytearray()
    buf += b"GGUF"
    buf += struct.pack("<I", 3)
    buf += struct.pack("<Q", 0)
    buf += struct.pack("<Q", 1)

    key = b"tokenizer.chat_template"
    buf += struct.pack("<Q", len(key))
    buf += key
    buf += struct.pack("<I", 8)

    template = b"{% for msg in messages %}{{ msg.content }}{% endfor %}"
    buf += struct.pack("<Q", len(template))
    buf += template

    out = FIXTURES / "clean_model" / "model.gguf"
    out.write_bytes(bytes(buf))
    print(f"Created: {out} ({len(buf)} bytes)")


def create_no_readme_model():
    """Create a model dir with only a .safetensors file and no README."""
    header = b"{}"
    header_len = struct.pack("<Q", len(header))
    data = header_len + header
    out = FIXTURES / "no_readme_model" / "model.safetensors"
    out.write_bytes(data)
    print(f"Created: {out} ({len(data)} bytes)")


def create_uncensored_model():
    """Create a clean .safetensors in the uncensored_model dir."""
    header = b"{}"
    header_len = struct.pack("<Q", len(header))
    data = header_len + header
    out = FIXTURES / "uncensored_model" / "model.safetensors"
    out.write_bytes(data)
    print(f"Created: {out} ({len(data)} bytes)")


if __name__ == "__main__":
    create_malicious_pickle()
    create_clean_safetensors()
    create_malicious_gguf()
    create_clean_gguf()
    create_no_readme_model()
    create_uncensored_model()
    print("Done — all fixtures created.")
