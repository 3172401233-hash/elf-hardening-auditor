"""Structured errors raised while parsing ELF metadata.

Every error carries a stable ``code`` so release gates can react to
specific corruption classes without matching on message text.
"""


class ELFError(Exception):
    """Base class for all ELF parsing/audit errors."""

    code = "elf_error"


class UnsupportedELF(ELFError):
    """The file is not a format this auditor handles (e.g. big-endian)."""

    code = "unsupported"


class BadHeaderError(ELFError):
    """The ELF header or header tables are damaged or truncated."""

    code = "bad_header"


class SectionError(ELFError):
    """A section header or section payload points outside the file."""

    code = "section_out_of_bounds"


class OverlappingSegmentError(ELFError):
    """Two PT_LOAD segments overlap in the file or in virtual memory."""

    code = "overlapping_segments"


class DynamicTableError(ELFError):
    """The PT_DYNAMIC segment lies outside the file bounds."""

    code = "dynamic_table_out_of_bounds"


class StringTableError(ELFError):
    """A string table is truncated or a name offset is out of range."""

    code = "string_table_truncated"
