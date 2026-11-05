"""Synthetic ELF data-loading tests; no game input or ARM64 execution needed."""

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def fixture():
    data = bytearray(0x640)
    data[:16] = b'\x7fELF' + bytes([2, 1, 1]) + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, 3, 183, 1, 0x8000, 64,
                     0x500, 0, 64, 56, 2, 64, 5, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0x200, 0x8000, 0, 4, 16, 256)
    struct.pack_into('<IIQQQQQQ', data, 120, 1, 6, 0x300, 0x9000, 0, 8, 32, 256)
    data[0x200:0x204] = bytes.fromhex('c0035fd6') # Data only, never called.
    data[0x300:0x308] = b'original'
    strings = b'\0external\0libfixture.so\0'
    data[0x340:0x340 + len(strings)] = strings
    struct.pack_into('<IBBHQQ', data, 0x398, 1, 0x12, 0, 0, 0, 0)
    struct.pack_into('<QQq', data, 0x400, 0x9000, 1027, -4)
    struct.pack_into('<QQq', data, 0x418, 0x9008, (1 << 32) | 1025, 8)
    struct.pack_into('<QQQQ', data, 0x450, 1, 10, 0, 0)
    for index, (kind, offset, size, link, stride) in enumerate([
            (3, 0x340, len(strings), 0, 0), (11, 0x380, 48, 1, 24),
            (4, 0x400, 48, 2, 24), (6, 0x450, 32, 1, 16)], 1):
        struct.pack_into('<IIQQQQIIQQ', data, 0x500 + index * 64,
                         0, kind, 0, 0, offset, size, link, 0, 8, stride)
    return data


class ImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.runner = cls.directory / 'image-smoke'
        subprocess.run(['c++', '-std=c++11', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
                        '-I', str(ROOT / 'include'), str(ROOT / 'src/runtime.cpp'),
                        str(ROOT / 'src/elf_image.cpp'), str(ROOT / 'tests/image_smoke.cpp'),
                        '-lcrypto', '-o', str(cls.runner)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_image(self, data=None, bias=0x100000000, digest=None, limit=None):
        if data is None:
            data = fixture()
        path = self.directory / 'fixture.elf'
        path.write_bytes(data)
        args = [str(self.runner), str(path), digest or hashlib.sha256(data).hexdigest(), str(bias)]
        if limit is not None:
            args.append(str(limit))
        return subprocess.run(args, capture_output=True, text=True)

    def test_mapping_bss_permissions_holes_and_inventory(self):
        # The native probe checks every file/BSS byte, unmapped boundaries, read-only
        # writes, mutable data, and failed-store atomicity using checked Memory.
        for bias in (0, 0x100000000, 0xFFFFFFFFFFFF0000):
            with self.subTest(bias=bias):
                result = self.run_image(bias=bias)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report['load_bias'], bias)
                self.assertEqual(report['segments'], 2)
                self.assertEqual(report['file_bytes_checked'], 12)
                self.assertEqual(report['bss_bytes_checked'], 36)
                self.assertFalse(report['ready_to_execute'])
                self.assertEqual(report['needed_libraries'], ['libfixture.so'])
                self.assertEqual(report['imports'], [dict(symbol='external', symbol_index=1,
                                                         binding=1, type=2, status='unresolved')])
                self.assertEqual(report['relocations'], [
                    dict(address=bias + 0x9000, type=1027, symbol_index=0, symbol='',
                         addend_bits=(1 << 64) - 4, has_addend=True, status='unresolved'),
                    dict(address=bias + 0x9008, type=1025, symbol_index=1, symbol='external',
                         addend_bits=8, has_addend=True, status='unresolved')])

    def test_sparse_bss_only_and_alignment_forms(self):
        for alignment in (0, 1, 256):
            with self.subTest(alignment=alignment):
                data = fixture()
                struct.pack_into('<Q', data, 136, 0x900000000000)
                struct.pack_into('<Q', data, 152, 0)
                struct.pack_into('<Q', data, 168, alignment)
                result = self.run_image(data, bias=0)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report['file_bytes_checked'], 4)
                self.assertEqual(report['bss_bytes_checked'], 44)

    def test_dynamic_inventory_cannot_disappear(self):
        data = fixture()
        struct.pack_into('<H', data, 56, 3)
        struct.pack_into('<IIQQQQQQ', data, 176, 2, 6, 0x450, 0, 0, 32, 32, 8)
        self.assertEqual(self.run_image(data).returncode, 0)
        struct.pack_into('<H', data, 60, 4)
        result = self.run_image(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('PT_DYNAMIC missing', result.stderr)
        data = fixture()
        struct.pack_into('<QQ', data, 0x450, 6, 0xDEAD0000)
        result = self.run_image(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('dynamic table missing', result.stderr)

    def test_unknown_relocation_is_reported_unresolved(self):
        data = fixture()
        struct.pack_into('<Q', data, 0x408, 0xFFFFFFFF)
        result = self.run_image(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        relocation = json.loads(result.stdout)['relocations'][0]
        self.assertEqual(relocation['type'], 0xFFFFFFFF)
        self.assertEqual(relocation['status'], 'unresolved')

    def test_hash_verification_precedes_elf_parsing(self):
        result = self.run_image(bytes(0x640), digest='0' * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SHA-256 mismatch', result.stderr)
        for digest in ('', 'abcd', 'Z' * 64):
            with self.subTest(digest=digest):
                # Empty digest is intentionally passed directly, rather than run_image's default.
                result = subprocess.run([str(self.runner), 'missing', digest, '0'],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('expected SHA-256', result.stderr)

    def test_malformed_inputs_and_overflow(self):
        # Rehash each corrupted fixture so these exercise validation after identity checks.
        cases = [
            ('magic', 0, 'I', 0), ('class', 4, 'B', 1), ('endian', 5, 'B', 2),
            ('machine', 18, 'H', 62), ('type', 16, 'H', 2), ('version', 20, 'I', 0),
            ('ehsize', 52, 'H', 63), ('phentsize', 54, 'H', 55),
            ('phoff overflow', 32, 'Q', (1 << 64) - 8), ('phnum', 56, 'H', 65535),
            ('no segments', 56, 'H', 0), ('truncated phdr', 32, 'Q', 0x630),
            ('filesz larger than memsz', 96, 'Q', 17),
            ('file range overflow', 72, 'Q', (1 << 64) - 2),
            ('file range truncated', 72, 'Q', 0x63F),
            ('bad alignment', 112, 'Q', 3), ('incongruent alignment', 72, 'Q', 0x201),
            ('guest end overflow', 80, 'Q', (1 << 64) - 256),
            ('allocation limit', 104, 'Q', 1 << 40),
            ('overlap', 136, 'Q', 0x8000), ('unsupported flags', 68, 'I', 15),
            ('missing sections', 40, 'Q', 0), ('extended sections', 60, 'H', 0),
            ('truncated sections', 40, 'Q', 0x630),
            ('bad section data', 0x558, 'Q', (1 << 64) - 1),
            ('bad symbol stride', 0x5B8, 'Q', 16),
            ('bad symbol link', 0x5A8, 'I', 65535),
            ('bad string offset', 0x398, 'I', 65535),
            ('bad relocation stride', 0x5F8, 'Q', 8),
            ('bad relocation symbol', 0x408, 'Q', (10 << 32) | 1025),
            ('packed relocations', 0x5C4, 'I', 19),
            ('packed dynamic relocations', 0x450, 'Q', 36),
            ('unterminated dynamic', 0x460, 'Q', 1),
        ]
        for name, offset, kind, value in cases:
            with self.subTest(name=name):
                data = fixture()
                if name == 'guest end overflow':
                    struct.pack_into('<Q', data, 104, 512)
                struct.pack_into('<' + kind, data, offset, value)
                result = self.run_image(data, bias=0)
                self.assertNotEqual(result.returncode, 0, name)
                self.assertEqual(result.stdout, '')
        for length in (0, 16, 63, 100, 0x63F):
            with self.subTest(length=length):
                self.assertNotEqual(self.run_image(fixture()[:length]).returncode, 0)

    def test_load_bias_and_resource_limits(self):
        for bias in (1, 255, 0xFFFFFFFFFFFFF000):
            with self.subTest(bias=bias):
                self.assertNotEqual(self.run_image(bias=bias).returncode, 0)
        self.assertNotEqual(self.run_image(limit=47).returncode, 0)
        self.assertEqual(self.run_image(limit=48).returncode, 0)

    def test_rel_inventory_preserves_implicit_addend(self):
        data = fixture()
        struct.pack_into('<I', data, 0x5C4, 9)
        struct.pack_into('<Q', data, 0x5E0, 16)
        struct.pack_into('<Q', data, 0x5F8, 16)
        result = self.run_image(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        relocation = json.loads(result.stdout)['relocations'][0]
        self.assertFalse(relocation['has_addend'])
        self.assertEqual(relocation['addend_bits'], 0)

    def test_empty_imports_are_still_not_ready(self):
        data = fixture()
        struct.pack_into('<H', data, 60, 1)
        result = self.run_image(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['imports'], [])
        self.assertEqual(report['relocations'], [])
        self.assertFalse(report['ready_to_execute'])


if __name__ == '__main__':
    unittest.main()
