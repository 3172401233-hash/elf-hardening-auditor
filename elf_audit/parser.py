"""Minimal, bounds-checked ELF metadata parser.

Only reads headers, program headers, section headers, string tables,
dynamic tags and symbol names. Never disassembles or executes anything.
Supports 32/64-bit little-endian files; anything else raises
``UnsupportedELF`` so callers can mark the file unsupported.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from itertools import combinations
from typing import List, Optional, Tuple

from .errors import (
    BadHeaderError,
    DynamicTableError,
    OverlappingSegmentError,
    SectionError,
    StringTableError,
    UnsupportedELF,
)

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8
SHT_DYNSYM = 11

DT_NULL = 0
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x08
DF_1_NOW = 0x01

ET_EXEC = 2
ET_DYN = 3

SHN_XINDEX = 0xFFFF
PN_XNUM = 0xFFFF

MACHINE_NAMES = {
    0x03: "Intel 80386",
    0x08: "MIPS",
    0x28: "ARM",
    0x3E: "x86-64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
}


@dataclass
class ProgramHeader:
    index: int
    type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int


@dataclass
class SectionHeader:
    index: int
    name_offset: int
    type: int
    flags: int
    offset: int
    size: int
    link: int
    info: int
    entsize: int
    name: str = ""


@dataclass
class Symbol:
    name: str
    section: str


@dataclass
class ELFFile:
    is_64: bool
    e_type: int
    machine: int
    phdrs: List[ProgramHeader] = field(default_factory=list)
    sections: List[SectionHeader] = field(default_factory=list)
    dynamics: List[Tuple[int, int]] = field(default_factory=list)
    symbols: List[Symbol] = field(default_factory=list)

    @property
    def elf_class(self) -> str:
        return "ELF64" if self.is_64 else "ELF32"

    @property
    def machine_name(self) -> str:
        return MACHINE_NAMES.get(self.machine, "unknown(%d)" % self.machine)


def _require_range(data: bytes, offset: int, size: int, what: str, exc) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise exc(
            "%s out of bounds: offset=%d size=%d but file is %d bytes"
            % (what, offset, size, len(data))
        )


def _read_cstr(table: bytes, offset: int, what: str) -> str:
    if offset < 0 or offset >= len(table):
        raise StringTableError(
            "%s: name offset %d outside string table of %d bytes"
            % (what, offset, len(table))
        )
    end = table.find(b"\x00", offset)
    if end == -1:
        raise StringTableError(
            "%s: string at offset %d is not NUL-terminated (truncated string table)"
            % (what, offset)
        )
    return table[offset:end].decode("utf-8", "replace")


def _parse_shdr(data: bytes, offset: int, is_64: bool) -> SectionHeader:
    if is_64:
        fields = struct.unpack_from("<IIQQQQIIQQ", data, offset)
        name_off, s_type, _flags, _addr, s_off, size, link, info, _align, entsize = fields
    else:
        fields = struct.unpack_from("<IIIIIIIIII", data, offset)
        name_off, s_type, _flags, _addr, s_off, size, link, info, _align, entsize = fields
    return SectionHeader(
        index=0,
        name_offset=name_off,
        type=s_type,
        flags=_flags,
        offset=s_off,
        size=size,
        link=link,
        info=info,
        entsize=entsize,
    )


def _section_data(data: bytes, sec: SectionHeader, exc) -> bytes:
    if sec.type == SHT_NOBITS:
        return b""
    _require_range(data, sec.offset, sec.size, "section #%d payload" % sec.index, exc)
    return data[sec.offset : sec.offset + sec.size]


def _ranges_overlap(off_a: int, size_a: int, off_b: int, size_b: int) -> bool:
    if size_a == 0 or size_b == 0:
        return False
    return off_a < off_b + size_b and off_b < off_a + size_a


def parse_elf(data: bytes) -> ELFFile:
    if len(data) < 16:
        raise BadHeaderError("file too small for ELF identification (%d bytes)" % len(data))
    if data[:4] != b"\x7fELF":
        raise BadHeaderError("bad magic: not an ELF file")
    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        raise UnsupportedELF("unsupported EI_CLASS %d (only 32/64-bit)" % ei_class)
    if ei_data != 1:
        desc = "big-endian" if ei_data == 2 else "unknown EI_DATA %d" % ei_data
        raise UnsupportedELF("unsupported encoding: %s (only little-endian)" % desc)

    is_64 = ei_class == 2
    ehsize = 64 if is_64 else 52
    if len(data) < ehsize:
        raise BadHeaderError(
            "truncated ELF header: need %d bytes, have %d" % (ehsize, len(data))
        )
    if is_64:
        (
            e_type,
            e_machine,
            _version,
            _entry,
            e_phoff,
            e_shoff,
            _flags,
            _ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        ) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    else:
        (
            e_type,
            e_machine,
            _version,
            _entry,
            e_phoff,
            e_shoff,
            _flags,
            _ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        ) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)

    # Section header 0 carries extended numbering when the real counts
    # do not fit in the 16-bit header fields.
    first_shdr: Optional[SectionHeader] = None
    shdr_size = 64 if is_64 else 40
    if e_shoff:
        if e_shentsize < shdr_size:
            raise BadHeaderError(
                "section header entry size %d smaller than %d" % (e_shentsize, shdr_size)
            )
        _require_range(data, e_shoff, e_shentsize, "section header table", BadHeaderError)
        first_shdr = _parse_shdr(data, e_shoff, is_64)
    if e_phnum == PN_XNUM:
        if first_shdr is None:
            raise BadHeaderError("extended program header count but no section header 0")
        e_phnum = first_shdr.info
    if e_shoff and e_shnum == 0:
        e_shnum = first_shdr.size
    if e_shstrndx == SHN_XINDEX:
        if first_shdr is None:
            raise BadHeaderError("extended shstrndx but no section header 0")
        e_shstrndx = first_shdr.link

    phdrs: List[ProgramHeader] = []
    ph_size = 56 if is_64 else 32
    if e_phnum:
        if e_phentsize < ph_size:
            raise BadHeaderError(
                "program header entry size %d smaller than %d" % (e_phentsize, ph_size)
            )
        _require_range(
            data, e_phoff, e_phentsize * e_phnum, "program header table", BadHeaderError
        )
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if is_64:
                p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = (
                    struct.unpack_from("<IIQQQQQQ", data, off)
                )
            else:
                p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_flags, _align = (
                    struct.unpack_from("<IIIIIIII", data, off)
                )
            phdrs.append(
                ProgramHeader(
                    index=i,
                    type=p_type,
                    flags=p_flags,
                    offset=p_offset,
                    vaddr=p_vaddr,
                    filesz=p_filesz,
                    memsz=p_memsz,
                )
            )

    loads = [p for p in phdrs if p.type == PT_LOAD]
    for a, b in combinations(loads, 2):
        if _ranges_overlap(a.offset, a.filesz, b.offset, b.filesz):
            raise OverlappingSegmentError(
                "PT_LOAD #%d and #%d overlap in file: [0x%x,0x%x) vs [0x%x,0x%x)"
                % (a.index, b.index, a.offset, a.offset + a.filesz, b.offset, b.offset + b.filesz)
            )
        if _ranges_overlap(a.vaddr, a.memsz, b.vaddr, b.memsz):
            raise OverlappingSegmentError(
                "PT_LOAD #%d and #%d overlap in memory: [0x%x,0x%x) vs [0x%x,0x%x)"
                % (a.index, b.index, a.vaddr, a.vaddr + a.memsz, b.vaddr, b.vaddr + b.memsz)
            )

    sections: List[SectionHeader] = []
    if e_shoff and e_shnum:
        _require_range(
            data, e_shoff, e_shentsize * e_shnum, "section header table", BadHeaderError
        )
        for i in range(e_shnum):
            sec = _parse_shdr(data, e_shoff + i * e_shentsize, is_64)
            sec.index = i
            sections.append(sec)
        if 0 < e_shstrndx < len(sections):
            strtab = _section_data(data, sections[e_shstrndx], StringTableError)
            for sec in sections:
                sec.name = _read_cstr(strtab, sec.name_offset, "section #%d" % sec.index)

    dynamics: List[Tuple[int, int]] = []
    for ph in phdrs:
        if ph.type != PT_DYNAMIC or ph.filesz == 0:
            continue
        _require_range(data, ph.offset, ph.filesz, "PT_DYNAMIC segment", DynamicTableError)
        entsize = 16 if is_64 else 8
        for i in range(ph.filesz // entsize):
            off = ph.offset + i * entsize
            if is_64:
                tag, val = struct.unpack_from("<qQ", data, off)
            else:
                tag, val = struct.unpack_from("<iI", data, off)
            dynamics.append((tag, val))
            if tag == DT_NULL:
                break

    symbols: List[Symbol] = []
    for sec in sections:
        if sec.type not in (SHT_DYNSYM, SHT_SYMTAB):
            continue
        if sec.link >= len(sections):
            raise StringTableError(
                "symbol table section #%d links to missing string table #%d"
                % (sec.index, sec.link)
            )
        strtab = _section_data(data, sections[sec.link], StringTableError)
        symdata = _section_data(data, sec, SectionError)
        default_entsize = 24 if is_64 else 16
        entsize = sec.entsize or default_entsize
        if entsize < default_entsize:
            raise SectionError(
                "symbol table section #%d has entsize %d < %d"
                % (sec.index, entsize, default_entsize)
            )
        count = len(symdata) // entsize
        for i in range(count):
            (st_name,) = struct.unpack_from("<I", symdata, i * entsize)
            name = _read_cstr(strtab, st_name, "symbol #%d in %s" % (i, sec.name or sec.index))
            if name:
                symbols.append(Symbol(name=name, section=sec.name))

    return ELFFile(
        is_64=is_64,
        e_type=e_type,
        machine=e_machine,
        phdrs=phdrs,
        sections=sections,
        dynamics=dynamics,
        symbols=symbols,
    )
