import unittest

from elf_audit import audit_bytes
from tests.elf_builder import (
    ET_EXEC,
    PF_R,
    PF_W,
    PF_X,
    build_elf,
)

SECURE_SYMBOLS = ["__stack_chk_fail", "__printf_chk", "__memcpy_chk", "main"]


def secure_elf(**kwargs):
    params = dict(symbols=SECURE_SYMBOLS)
    params.update(kwargs)
    return build_elf(**params)


class HardenedConfigTests(unittest.TestCase):
    def test_secure_64bit(self):
        result = audit_bytes(secure_elf(), "secure64")
        self.assertEqual(result["status"], "ok")
        checks = result["checks"]
        self.assertEqual(checks["nx"]["status"], "enabled")
        self.assertEqual(checks["pie"]["status"], "enabled")
        self.assertEqual(checks["relro"]["status"], "full")
        self.assertEqual(checks["stack_protector"]["status"], "present")
        self.assertEqual(checks["fortify"]["status"], "present")
        self.assertEqual(checks["wx"]["status"], "ok")
        self.assertEqual(result["format"]["class"], "ELF64")

    def test_secure_32bit(self):
        result = audit_bytes(secure_elf(bits=32), "secure32")
        self.assertEqual(result["status"], "ok")
        checks = result["checks"]
        self.assertEqual(checks["nx"]["status"], "enabled")
        self.assertEqual(checks["pie"]["status"], "enabled")
        self.assertEqual(checks["relro"]["status"], "full")
        self.assertEqual(checks["stack_protector"]["status"], "present")
        self.assertEqual(checks["fortify"]["status"], "present")
        self.assertEqual(result["format"]["class"], "ELF32")

    def test_every_check_has_evidence(self):
        for image in (secure_elf(), secure_elf(bits=32), build_elf()):
            result = audit_bytes(image)
            self.assertEqual(result["status"], "ok")
            for name, check in result["checks"].items():
                self.assertIsInstance(check["evidence"], list)
                self.assertTrue(
                    check["evidence"], "check %s returned no evidence" % name
                )


class DangerousConfigTests(unittest.TestCase):
    def test_dangerous_64bit(self):
        image = build_elf(
            etype=ET_EXEC,
            gnu_stack_flags=PF_R | PF_W | PF_X,
            relro=False,
            bind_now=False,
            symbols=(),
            rwx_load=True,
        )
        checks = audit_bytes(image, "dangerous")["checks"]
        self.assertEqual(checks["nx"]["status"], "disabled")
        self.assertEqual(checks["pie"]["status"], "disabled")
        self.assertEqual(checks["relro"]["status"], "none")
        self.assertEqual(checks["wx"]["status"], "violation")

    def test_partial_relro_without_bind_now(self):
        result = audit_bytes(build_elf(relro=True, bind_now=False))
        self.assertEqual(result["checks"]["relro"]["status"], "partial")

    def test_full_relro_via_dt_flags(self):
        image = build_elf(bind_now=False, extra_dynamic=[(30, 0x08)])  # DT_FLAGS|DF_BIND_NOW
        result = audit_bytes(image)
        self.assertEqual(result["checks"]["relro"]["status"], "full")

    def test_missing_gnu_stack_is_not_reported_nx(self):
        result = audit_bytes(build_elf(gnu_stack=False))
        self.assertEqual(result["checks"]["nx"]["status"], "unknown")

    def test_no_symbols_means_unknown_protections(self):
        result = audit_bytes(build_elf(symbols=()))
        self.assertEqual(result["checks"]["stack_protector"]["status"], "unknown")
        self.assertEqual(result["checks"]["fortify"]["status"], "unknown")

    def test_fortify_absent_when_only_plain_symbols(self):
        result = audit_bytes(build_elf(symbols=["printf", "main"]))
        self.assertEqual(result["checks"]["fortify"]["status"], "absent")
        self.assertEqual(result["checks"]["stack_protector"]["status"], "absent")


class UnsupportedFormatTests(unittest.TestCase):
    def test_big_endian_is_unsupported(self):
        result = audit_bytes(build_elf(ei_data=2))
        self.assertEqual(result["status"], "unsupported")
        self.assertIn("big-endian", result["reason"])

    def test_unknown_class_is_unsupported(self):
        result = audit_bytes(build_elf(ei_class=7))
        self.assertEqual(result["status"], "unsupported")


class StructuredErrorTests(unittest.TestCase):
    def assert_error(self, image, code):
        result = audit_bytes(image)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"]["code"], code)
        self.assertTrue(result["error"]["message"])
        return result

    def test_not_an_elf(self):
        self.assert_error(b"\x7fELG" + b"\x00" * 64, "bad_header")

    def test_truncated_header(self):
        self.assert_error(b"\x7fELF\x02\x01\x01", "bad_header")

    def test_program_headers_out_of_bounds(self):
        image = bytearray(build_elf())
        image[32:40] = (0xFFFFFFFF).to_bytes(8, "little")  # e_phoff
        self.assert_error(bytes(image), "bad_header")

    def test_overlapping_load_segments(self):
        self.assert_error(build_elf(overlap_loads=True), "overlapping_segments")

    def test_dynamic_table_out_of_bounds(self):
        self.assert_error(
            build_elf(dynamic_filesz=0x100000), "dynamic_table_out_of_bounds"
        )

    def test_truncated_string_table(self):
        self.assert_error(
            build_elf(symbols=["__stack_chk_fail"], unterminated_strtab=True),
            "string_table_truncated",
        )

    def test_truncation_fuzz_never_raises(self):
        image = secure_elf()
        for cut in range(len(image)):
            result = audit_bytes(image[:cut])
            self.assertIn(result["status"], ("ok", "error", "unsupported"))


if __name__ == "__main__":
    unittest.main()
