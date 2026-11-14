"""CLI entry point: python -m elf_audit <file> [file...]"""

import argparse
import json
import sys

from . import audit_file


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="elf_audit",
        description="Metadata-only ELF hardening audit (NX, PIE, RELRO, "
        "stack protector, FORTIFY, W^X).",
    )
    parser.add_argument("files", nargs="+", help="ELF files to audit")
    parser.add_argument("--compact", action="store_true", help="single-line JSON output")
    args = parser.parse_args(argv)

    results = [audit_file(path) for path in args.files]
    indent = None if args.compact else 2
    payload = results[0] if len(results) == 1 else results
    json.dump(payload, sys.stdout, indent=indent, ensure_ascii=False)
    sys.stdout.write("\n")
    return 1 if any(r["status"] == "error" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
