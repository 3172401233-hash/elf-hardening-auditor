"""Builds minimal synthetic ELF images (32/64-bit, little-endian) so tests
can exercise many hardening configurations without external toolchains.
"""

import struct

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

PF_X, PF_W, PF_R = 1, 2, 4

SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_DYNSYM = 11

DT_NULL = 0
DT_BIND_NOW = 24

ET_EXEC = 2
ET_DYN = 3


def _align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def build_elf(
    bits=64,
    etype=ET_DYN,
    gnu_stack=True,
    gnu_stack_flags=PF_R | PF_W,
    relro=True,
    bind_now=True,
    symbols=(),
    interp=True,
    rwx_load=False,
    extra_dynamic=(),
    overlap_loads=False,
    dynamic_filesz=None,
    unterminated_strtab=False,
    ei_class=None,
    ei_data=1,
):
    is64 = bits == 64
    ehsize = 64 if is64 else 52
    phentsize = 56 if is64 else 32
    shentsize = 64 if is64 else 40
    syment = 24 if is64 else 16
    dynent = 16 if is64 else 8
    machine = 0x3E if is64 else 0x03

    dynstr = bytearray(b"\x00")
    name_offsets = []
    for name in symbols:
        name_offsets.append(len(dynstr))
        dynstr += name.encode("ascii") + b"\x00"
    if unterminated_strtab and symbols:
        dynstr = dynstr[:-1]  # drop the final NUL: truncated string table
    dynstr = bytes(dynstr)

    dynsym = bytearray(b"\x00" * syment)  # STN_UNDEF
    for off in name_offsets:
        if is64:
            dynsym += struct.pack("<IBBHQQ", off, 0x12, 0, 0, 0, 0)
        else:
            dynsym += struct.pack("<IIIBBH", off, 0, 0, 0x12, 0, 0)
    dynsym = bytes(dynsym)

    dyn_entries = list(extra_dynamic)
    if bind_now:
        dyn_entries.append((DT_BIND_NOW, 0))
    dyn_entries.append((DT_NULL, 0))
    fmt = "<qQ" if is64 else "<iI"
    dynamic = b"".join(struct.pack(fmt, tag, val) for tag, val in dyn_entries)

    sec_names = [".dynstr", ".dynsym", ".dynamic", ".shstrtab"]
    shstrtab = bytearray(b"\x00")
    sh_name_offsets = []
    for name in sec_names:
        sh_name_offsets.append(len(shstrtab))
        shstrtab += name.encode("ascii") + b"\x00"
    shstrtab = bytes(shstrtab)

    data_base = 0x1000
    dynstr_off = data_base
    dynsym_off = _align(dynstr_off + len(dynstr), 8)
    dynamic_off = _align(dynsym_off + len(dynsym), 8)
    shstr_off = dynamic_off + len(dynamic)
    shoff = _align(shstr_off + len(shstrtab), 8)
    n_sh = 1 + len(sec_names)
    filesize = shoff + n_sh * shentsize

    load1_flags = (PF_R | PF_W | PF_X) if rwx_load else (PF_R | PF_X)
    load2_off = 0x800 if overlap_loads else data_base
    load2_vaddr = 0x400800 if overlap_loads else 0x401000

    phdrs = [
        # type, flags, offset, vaddr, filesz, memsz
        (PT_LOAD, load1_flags, 0, 0x400000, data_base, data_base),
        (PT_LOAD, PF_R | PF_W, load2_off, load2_vaddr, filesize - load2_off, filesize - load2_off),
    ]
    if interp:
        phdrs.append((PT_INTERP, PF_R, 0, 0, 0, 0))
    dyn_filesz = dynamic_filesz if dynamic_filesz is not None else len(dynamic)
    phdrs.append(
        (PT_DYNAMIC, PF_R | PF_W, dynamic_off, 0x401000 + (dynamic_off - data_base), dyn_filesz, dyn_filesz)
    )
    if gnu_stack:
        phdrs.append((PT_GNU_STACK, gnu_stack_flags, 0, 0, 0, 0))
    if relro:
        phdrs.append(
            (PT_GNU_RELRO, PF_R, dynamic_off, 0x401000 + (dynamic_off - data_base), len(dynamic), len(dynamic))
        )

    ident = bytearray(b"\x7fELF")
    ident.append(ei_class if ei_class is not None else (2 if is64 else 1))
    ident.append(ei_data)
    ident.append(1)  # EI_VERSION
    ident += b"\x00" * (16 - len(ident))

    if is64:
        header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            bytes(ident), etype, machine, 1, 0, ehsize, shoff, 0,
            ehsize, phentsize, len(phdrs), shentsize, n_sh, n_sh - 1,
        )
        phdr_fmt = "<IIQQQQQQ"
        shdr_fmt = "<IIQQQQIIQQ"
    else:
        header = struct.pack(
            "<16sHHIIIIIHHHHHH",
            bytes(ident), etype, machine, 1, 0, ehsize, shoff, 0,
            ehsize, phentsize, len(phdrs), shentsize, n_sh, n_sh - 1,
        )
        phdr_fmt = "<IIIIIIII"
        shdr_fmt = "<IIIIIIIIII"

    image = bytearray(filesize)
    image[: len(header)] = header

    for i, (p_type, p_flags, p_off, p_vaddr, p_filesz, p_memsz) in enumerate(phdrs):
        if is64:
            entry = struct.pack(phdr_fmt, p_type, p_flags, p_off, p_vaddr, p_vaddr, p_filesz, p_memsz, 0x1000)
        else:
            entry = struct.pack(phdr_fmt, p_type, p_off, p_vaddr, p_vaddr, p_filesz, p_memsz, p_flags, 0x1000)
        start = ehsize + i * phentsize
        image[start : start + phentsize] = entry

    image[dynstr_off : dynstr_off + len(dynstr)] = dynstr
    image[dynsym_off : dynsym_off + len(dynsym)] = dynsym
    image[dynamic_off : dynamic_off + len(dynamic)] = dynamic
    image[shstr_off : shstr_off + len(shstrtab)] = shstrtab

    def vaddr_for(off):
        return 0x401000 + (off - data_base)

    shdrs = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (sh_name_offsets[0], SHT_STRTAB, 2, vaddr_for(dynstr_off), dynstr_off, len(dynstr), 0, 0, 1, 0),
        (sh_name_offsets[1], SHT_DYNSYM, 2, vaddr_for(dynsym_off), dynsym_off, len(dynsym), 1, 1, 8, syment),
        (sh_name_offsets[2], SHT_DYNAMIC, 3, vaddr_for(dynamic_off), dynamic_off, len(dynamic), 1, 0, 8, dynent),
        (sh_name_offsets[3], SHT_STRTAB, 0, 0, shstr_off, len(shstrtab), 0, 0, 1, 0),
    ]
    for i, (name, s_type, flags, addr, off, size, link, info, align, entsize) in enumerate(shdrs):
        if is64:
            entry = struct.pack(shdr_fmt, name, s_type, flags, addr, off, size, link, info, align, entsize)
        else:
            entry = struct.pack(shdr_fmt, name, s_type, flags, addr, off, size, link, info, align, entsize)
        start = shoff + i * shentsize
        image[start : start + shentsize] = entry

    return bytes(image)
