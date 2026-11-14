"""Hardening checks over parsed ELF metadata.

Every check returns ``{"status": ..., "evidence": [...]}`` where each
evidence string cites concrete metadata: segment flags, section names,
dynamic tags or symbol names. No conclusion is drawn from a single
section name alone.
"""

from __future__ import annotations

import re
from typing import Dict, List

from .parser import (
    DF_1_NOW,
    DF_BIND_NOW,
    DT_BIND_NOW,
    DT_FLAGS,
    DT_FLAGS_1,
    ET_DYN,
    ET_EXEC,
    PF_R,
    PF_W,
    PF_X,
    PT_GNU_RELRO,
    PT_GNU_STACK,
    PT_INTERP,
    PT_LOAD,
    ELFFile,
)

FORTIFY_SYMBOL = re.compile(r"^__.*_chk$")
STACK_PROTECTOR_SYMBOLS = ("__stack_chk_fail", "__stack_chk_guard")


def _flag_str(flags: int) -> str:
    out = ""
    if flags & PF_R:
        out += "R"
    if flags & PF_W:
        out += "W"
    if flags & PF_X:
        out += "X"
    return out or "-"


def check_nx(elf: ELFFile) -> Dict:
    stacks = [p for p in elf.phdrs if p.type == PT_GNU_STACK]
    if not stacks:
        return {
            "status": "unknown",
            "evidence": [
                "PT_GNU_STACK segment missing; the kernel/loader may fall "
                "back to an executable stack"
            ],
        }
    evidence = []
    executable = False
    for p in stacks:
        evidence.append(
            "PT_GNU_STACK #%d flags=%s (PF_X %s)"
            % (p.index, _flag_str(p.flags), "set" if p.flags & PF_X else "clear")
        )
        if p.flags & PF_X:
            executable = True
    return {"status": "disabled" if executable else "enabled", "evidence": evidence}


def check_pie(elf: ELFFile) -> Dict:
    interp = any(p.type == PT_INTERP for p in elf.phdrs)
    if elf.e_type == ET_DYN:
        kind = "PIE executable" if interp else "shared object (position independent)"
        return {
            "status": "enabled",
            "evidence": [
                "e_type=ET_DYN",
                "PT_INTERP %s" % ("present" if interp else "absent"),
                "file is a %s" % kind,
            ],
        }
    if elf.e_type == ET_EXEC:
        return {
            "status": "disabled",
            "evidence": ["e_type=ET_EXEC (fixed load address, not position independent)"],
        }
    return {
        "status": "unknown",
        "evidence": ["e_type=%d (neither ET_EXEC nor ET_DYN)" % elf.e_type],
    }


def check_relro(elf: ELFFile) -> Dict:
    evidence: List[str] = []
    relro = [p for p in elf.phdrs if p.type == PT_GNU_RELRO]
    for p in relro:
        evidence.append(
            "PT_GNU_RELRO #%d covers vaddr [0x%x, 0x%x)"
            % (p.index, p.vaddr, p.vaddr + p.memsz)
        )
    if not relro:
        evidence.append("PT_GNU_RELRO segment missing")

    tags = {tag for tag, _ in elf.dynamics}
    bind_now = False
    if DT_BIND_NOW in tags:
        bind_now = True
        evidence.append("dynamic tag DT_BIND_NOW present")
    for tag, val in elf.dynamics:
        if tag == DT_FLAGS and val & DF_BIND_NOW:
            bind_now = True
            evidence.append("DT_FLAGS contains DF_BIND_NOW (0x%x)" % val)
        if tag == DT_FLAGS_1 and val & DF_1_NOW:
            bind_now = True
            evidence.append("DT_FLAGS_1 contains DF_1_NOW (0x%x)" % val)
    if not bind_now:
        evidence.append("no DT_BIND_NOW / DF_BIND_NOW / DF_1_NOW dynamic tag")

    if relro and bind_now:
        status = "full"
    elif relro:
        status = "partial"
    else:
        status = "none"
    return {"status": status, "evidence": evidence}


def _symbol_check(elf: ELFFile, matches, label: str) -> Dict:
    if not elf.symbols:
        has_tables = any(s.name for s in elf.sections)
        note = (
            "no symbols found in .dynsym/.symtab"
            if has_tables
            else "no symbol table sections present"
        )
        return {"status": "unknown", "evidence": [note]}
    hits = [s for s in elf.symbols if matches(s.name)]
    if not hits:
        return {
            "status": "absent",
            "evidence": [
                "no %s symbol among %d symbols in .dynsym/.symtab"
                % (label, len(elf.symbols))
            ],
        }
    return {
        "status": "present",
        "evidence": [
            "symbol %s found in section %s" % (s.name, s.section or "?") for s in hits
        ],
    }


def check_stack_protector(elf: ELFFile) -> Dict:
    return _symbol_check(elf, lambda n: n in STACK_PROTECTOR_SYMBOLS, "stack protector")


def check_fortify(elf: ELFFile) -> Dict:
    return _symbol_check(elf, lambda n: bool(FORTIFY_SYMBOL.match(n)), "*_chk (FORTIFY)")


def check_wx(elf: ELFFile) -> Dict:
    evidence: List[str] = []
    violation = False
    loads = [p for p in elf.phdrs if p.type == PT_LOAD]
    for p in loads:
        both = (p.flags & PF_W) and (p.flags & PF_X)
        evidence.append(
            "PT_LOAD #%d vaddr=0x%x flags=%s%s"
            % (p.index, p.vaddr, _flag_str(p.flags), " (W+X!)" if both else "")
        )
        if both:
            violation = True
    if not loads:
        evidence.append("no PT_LOAD segments")
    return {"status": "violation" if violation else "ok", "evidence": evidence}


CHECKS = [
    ("nx", check_nx),
    ("pie", check_pie),
    ("relro", check_relro),
    ("stack_protector", check_stack_protector),
    ("fortify", check_fortify),
    ("wx", check_wx),
]


def run_checks(elf: ELFFile) -> Dict[str, Dict]:
    return {name: fn(elf) for name, fn in CHECKS}
