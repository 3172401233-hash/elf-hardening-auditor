"""ELF hardening auditor: metadata-only checks for release gates."""

from __future__ import annotations

from typing import Dict, Optional

from .errors import ELFError, UnsupportedELF
from .parser import ET_DYN, ET_EXEC, parse_elf
from .checks import run_checks

__all__ = ["audit_bytes", "audit_file", "ELFError", "UnsupportedELF"]

_TYPE_NAMES = {ET_EXEC: "ET_EXEC", ET_DYN: "ET_DYN"}


def audit_bytes(data: bytes, name: str = "<bytes>") -> Dict:
    """Audit one ELF image given as bytes. Never raises on bad input."""
    try:
        elf = parse_elf(data)
    except UnsupportedELF as exc:
        return {
            "file": name,
            "status": "unsupported",
            "reason": str(exc),
            "error": None,
            "format": None,
            "checks": None,
        }
    except ELFError as exc:
        return {
            "file": name,
            "status": "error",
            "reason": None,
            "error": {"code": exc.code, "message": str(exc)},
            "format": None,
            "checks": None,
        }
    return {
        "file": name,
        "status": "ok",
        "reason": None,
        "error": None,
        "format": {
            "class": elf.elf_class,
            "endian": "little",
            "type": _TYPE_NAMES.get(elf.e_type, "type(%d)" % elf.e_type),
            "machine": elf.machine_name,
        },
        "checks": run_checks(elf),
    }


def audit_file(path: str) -> Dict:
    with open(path, "rb") as fh:
        data = fh.read()
    return audit_bytes(data, name=path)
