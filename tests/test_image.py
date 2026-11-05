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


def symbol_fixture(symbols=None, relocations=None, second_symbols=None):
    """Two independent tables, deliberately sharing names and symbol indices."""
    symbols = symbols if symbols is not None else [dict()]
    second_symbols = second_symbols if second_symbols is not None else [dict(value=0x9020)]
    relocations = relocations if relocations is not None else [(0x9000, 257, 1, 0, 2)]
    data = bytearray(0x1a00)
    data[:16] = b'\x7fELF' + bytes([2, 1, 1]) + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, 3, 183, 1, 0, 64,
                     0x1800, 0, 64, 56, 2, 64, 8, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0x200, 0x8000, 0, 16, 16, 1)
    struct.pack_into('<IIQQQQQQ', data, 120, 1, 6, 0x300, 0x9000, 0, 64, 64, 1)
    data[0x300:0x340] = bytes(range(64))
    data[0x500:0x506] = b'\0same\0'
    for offset, syms in ((0x600, symbols), (0x900, second_symbols)):
        for i, spec in enumerate(syms, 1):
            struct.pack_into('<IBBHQQ', data, offset + i * 24, 1,
                             (spec.get('binding', 0) << 4) | spec.get('type', 1),
                             spec.get('other', spec.get('visibility', 0)),
                             spec.get('section', 4), spec.get('value', 0x9010),
                             spec.get('size', 0))
    counts = {2: 0, 3: 0}
    for target, kind, index, addend, table in relocations:
        offset = (0xc00 if table == 2 else 0xf00) + counts[table] * 24
        struct.pack_into('<QQq', data, offset, target, (index << 32) | kind, addend)
        counts[table] += 1
    headers = [(3, 0, 0, 0x500, 6, 0, 0),
               (11, 0, 0, 0x600, (len(symbols) + 1) * 24, 1, 24),
               (2, 0, 0, 0x900, (len(second_symbols) + 1) * 24, 1, 24),
               (1, 3, 0x9000, 0x300, 64, 0, 0),
               (4, 0, 0, 0xc00, counts[2] * 24, 2, 24),
               (4, 0, 0, 0xf00, counts[3] * 24, 3, 24),
               (0, 0, 0, 0, 0, 0, 0)]
    for i, (kind, flags, address, offset, size, link, stride) in enumerate(headers, 1):
        struct.pack_into('<IIQQQQIIQQ', data, 0x1800 + i * 64,
                         0, kind, flags, address, offset, size, link, 0, 8, stride)
    return data


class ImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.runner = cls.directory / 'image-smoke'
        subprocess.run(['c++', '-std=c++11', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
                        '-I', str(ROOT / 'include'), str(ROOT / 'src/runtime.cpp'),
                        str(ROOT / 'src/elf_image.cpp'),
                        str(ROOT / 'src/aps2_rela.cpp'), str(ROOT / 'src/relr.cpp'), str(ROOT / 'tests/image_smoke.cpp'),
                        '-lcrypto', '-o', str(cls.runner)], check=True, capture_output=True)

        # A write-only mapping must permit fixups without granting read access.
        probe = cls.directory / 'write-only.cpp'
        probe.write_text(r'''#include "recomp/elf_image.h"
#include <stdexcept>
int main(int argc, char** argv) {
    if (argc != 3) return 1;
    recomp::ElfImage image = recomp::ElfImage::load(argv[1], argv[2], 0);
    image.apply_relocations();
    image.apply_relocations();
    image.apply_relative_relocations();
    image.apply_symbol_relocations();
    if (image.applied_relocations().size() != 1 || image.ready_to_execute()) return 2;
    try { image.memory().load64(0x9000); }
    catch (const std::out_of_range&) { return 0; }
    return 3;
}
''')
        cls.write_only_runner = cls.directory / 'write-only'
        subprocess.run(['c++', '-std=c++11', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
                        '-I', str(ROOT / 'include'), str(ROOT / 'src/runtime.cpp'),
                        str(ROOT / 'src/elf_image.cpp'),
                        str(ROOT / 'src/aps2_rela.cpp'), str(ROOT / 'src/relr.cpp'), str(probe), '-lcrypto',
                        '-o', str(cls.write_only_runner)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_image(self, data=None, bias=0x100000000, digest=None, limit=None, relocate=False, mode=None):
        if data is None:
            data = fixture()
        path = self.directory / 'fixture.elf'
        path.write_bytes(data)
        args = [str(self.runner), str(path), digest or hashlib.sha256(data).hexdigest(), str(bias)]
        if limit is not None or relocate or mode:
            args.append(str(limit if limit is not None else 536870912))
        if relocate or mode:
            args.append(mode or "--relocate")
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
                self.assertEqual([{k: v for k, v in r.items() if k not in ('definition', 'reason')}
                                  for r in report['relocations']], [
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
        self.assertEqual([{k: v for k, v in r.items() if k not in ('definition', 'reason')}
                                  for r in report['relocations']], [])
        self.assertFalse(report['ready_to_execute'])

    def test_relative_values_bytes_and_reapplication(self):
        for bias in (0, 0x100000000, 0xFFFFFFFFFFFF0000):
            for addend in (0, 0x9010, -4, -(1 << 63), (1 << 63) - 1):
                with self.subTest(bias=bias, addend=addend):
                    data = fixture()
                    struct.pack_into('<q', data, 0x410, addend)
                    result = self.run_image(data, bias=bias, relocate=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    report = json.loads(result.stdout)
                    value = (bias + addend) % (1 << 64)
                    self.assertEqual([{k: v for k, v in r.items() if k not in ('definition', 'type')}
                                      for r in report['applied_relocations']], [dict(
                        address=bias + 0x9000, addend_bits=addend % (1 << 64),
                        value=value, bytes=list(value.to_bytes(8, 'little')), status='applied')])
                    self.assertEqual(len(report['relocations']), 1)
                    self.assertEqual(report['relocations'][0]['type'], 1025)
                    self.assertEqual(len(report['imports']), 1)
                    self.assertFalse(report['ready_to_execute'])

    def test_relative_batch_rejection_is_atomic(self):
        # First write is valid; failure at the second entry must preserve all bytes
        # and both status inventories. The native probe checks this before rethrowing.
        for target, message in ((0xA000, 'unmapped'), (0x8000, 'permission'),
                                (0x9011, 'aligned'), (0x9018, 'unmapped'),
                                (0x9000, 'duplicate')):
            with self.subTest(target=target):
                data = fixture()
                struct.pack_into('<QQq', data, 0x418, target, 1027, 123)
                if target == 0x9018:
                    struct.pack_into('<Q', data, 160, 28) # 8-byte write crosses end.
                result = self.run_image(data, relocate=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertNotIn('partial', result.stderr)
                self.assertEqual(result.stdout, '')
        data = fixture()
        struct.pack_into('<Q', data, 0x420, (1 << 32) | 1027)
        result = self.run_image(data, relocate=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('symbol index zero', result.stderr)

    def test_shared_target_with_unsupported_type_rejects_composition(self):
        data = fixture()
        struct.pack_into('<Q', data, 0x418, 0x9000)
        result = self.run_image(data, relocate=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('composition unsupported', result.stderr)
        self.assertNotIn('partial', result.stderr)

    def test_relative_cannot_span_adjacent_mappings(self):
        data = fixture()
        # First segment directly follows a shortened second segment.
        struct.pack_into('<Q', data, 80, 0x900C)
        struct.pack_into('<Q', data, 112, 1)
        struct.pack_into('<Q', data, 160, 12)
        struct.pack_into('<QQq', data, 0x418, 0x9008, 1027, 12)
        result = self.run_image(data, bias=0, relocate=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unmapped', result.stderr)

    def test_relative_permission_policy_and_unmapped_result(self):
        # The stored value need not itself designate mapped memory. Only the
        # relocation's write range requires mapping and PF_W (not PF_R/PF_X).
        for flags in (4, 5, 0, 1):
            data = fixture()
            struct.pack_into('<I', data, 124, flags)
            result = self.run_image(data, relocate=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('permission', result.stderr)
        data = fixture()
        struct.pack_into('<q', data, 0x410, 0x12345678)
        self.assertEqual(self.run_image(data, relocate=True).returncode, 0)

    def test_write_only_mapping_remains_write_only(self):
        data = fixture()
        struct.pack_into('<I', data, 124, 2)
        path = self.directory / 'write-only.elf'
        path.write_bytes(data)
        result = subprocess.run([str(self.write_only_runner), str(path),
                                 hashlib.sha256(data).hexdigest()], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_biased_relocation_target_overflow_is_rejected(self):
        data = fixture()
        struct.pack_into('<Q', data, 0x400, (1 << 64) - 8)
        result = self.run_image(data, relocate=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('address/size overflow', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_unsupported_relocations_remain_unresolved_after_application(self):
        for kind in (257, 1025, 1026, 1032, 0, 0xFFFFFFFF):
            data = fixture()
            struct.pack_into('<Q', data, 0x408, kind)
            result = self.run_image(data, relocate=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['applied_relocations'], [])
            self.assertEqual(len(report['relocations']), 2)
        data = fixture()
        struct.pack_into('<I', data, 0x5C4, 9)
        struct.pack_into('<Q', data, 0x5E0, 16)
        struct.pack_into('<Q', data, 0x5F8, 16)
        result = self.run_image(data, relocate=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['applied_relocations'], [])
        self.assertFalse(report['relocations'][0]['has_addend'])

    def test_symbol_binding_visibility_and_special_forms(self):
        cases = [({}, None),
                 ({'type': 0}, None), ({'type': 2}, None), ({'type': 3}, None),
                 ({'visibility': 1}, None), ({'visibility': 2}, None),
                 ({'binding': 2, 'visibility': 1}, None),
                 ({'binding': 1, 'visibility': 3, 'section': 0xfff1}, None),
                 ({'binding': 1, 'visibility': 2}, None),
                 ({'binding': 1, 'visibility': 1}, None),
                 ({'binding': 1, 'visibility': 3}, None),
                 ({'binding': 2, 'visibility': 2}, None),
                 ({'binding': 2, 'visibility': 3}, None),
                 ({'binding': 1}, 'preemptible_symbol'),
                 ({'binding': 2}, 'preemptible_symbol'),
                 ({'binding': 1, 'section': 0}, 'undefined_symbol'),
                 ({'binding': 2, 'section': 0}, 'undefined_symbol'),
                 ({'visibility': 3}, 'local_protected_invalid'),
                 ({'binding': 10}, 'symbol_binding_unsupported'),
                 ({'type': 10}, 'ifunc_unsupported'),
                 ({'type': 6}, 'tls_unsupported'),
                 ({'type': 5}, 'common_unsupported'),
                 ({'section': 0xfff2}, 'common_unsupported'),
                 ({'section': 0xffff}, 'special_section_unsupported'),
                 ({'type': 4}, 'symbol_type_unsupported'),
                 ({'other': 0x82}, 'symbol_attributes_unsupported'),
                 ({'other': 4}, 'symbol_attributes_unsupported'),
                 ({'section': 0xff10}, 'special_section_unsupported'),
                 ({'value': 0xa000}, 'symbol_outside_section')]
        for kind in (257, 1025, 1026):
            for spec, reason in cases:
                with self.subTest(kind=kind, spec=spec):
                    data = symbol_fixture([spec], [(0x9000, kind, 1, 0, 2)])
                    result = self.run_image(data, mode='--all')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    report = json.loads(result.stdout)
                    if reason:
                        self.assertEqual(report['applied_relocations'], [])
                        self.assertEqual(report['relocations'][0]['reason'], reason)
                    else:
                        self.assertEqual(report['relocations'], [])
                        self.assertEqual(report['applied_relocations'][0]['value'],
                                         0x9010 if spec.get('section') == 0xfff1 else 0x100009010)
                    self.assertFalse(report['ready_to_execute'])
                    if spec.get('section') == 0:
                        self.assertEqual(len(report['imports']), 1)

    def test_symbol_values_bias_addends_abs_and_overflow(self):
        for kind in (257, 1025, 1026):
            for bias in (0, 0x100000000, 0xffffffffffff0000):
                for absolute in (False, True):
                    for value in ((0, 1, (1 << 64) - 1) if absolute else (0x9010,)):
                        for addend in (0, 4, -4, -(1 << 63), (1 << 63) - 1):
                            with self.subTest(kind=kind, bias=bias, absolute=absolute,
                                              value=value, addend=addend):
                                spec = dict(value=value, section=0xfff1 if absolute else 4)
                                data = symbol_fixture([spec], [(0x9000, kind, 1, addend, 2)])
                                result = self.run_image(data, bias=bias, mode='--all')
                                self.assertEqual(result.returncode, 0, result.stderr)
                                report = json.loads(result.stdout)
                                if kind == 1026 and addend:
                                    self.assertEqual(report['relocations'][0]['reason'],
                                                     'jump_slot_addend_policy_unsupported')
                                    continue
                                applied = report['applied_relocations'][0]
                                expected = (value + (0 if absolute else bias) + addend) % (1 << 64)
                                self.assertEqual(applied['value'], expected)
                                self.assertEqual(applied['bytes'], list(expected.to_bytes(8, 'little')))
                                definition = applied['definition']
                                self.assertEqual(definition['value'], value)
                                self.assertEqual(definition['table_section'], 2)
                                self.assertEqual(definition['index'], 1)
                                self.assertEqual(definition['section_index'], spec['section'])

    def test_symbol_tables_are_resolved_by_identity_and_invalid_indices_fail(self):
        data = symbol_fixture(relocations=[(0x9000, 257, 1, 0, 2), (0x9008, 1025, 1, 0, 3)])
        result = self.run_image(data, mode='--all')
        self.assertEqual(result.returncode, 0, result.stderr)
        applied = json.loads(result.stdout)['applied_relocations']
        self.assertEqual([r['value'] for r in applied], [0x100009010, 0x100009020])
        self.assertEqual([r['definition']['name'] for r in applied], ['same', 'same'])
        self.assertEqual([r['definition']['table_type'] for r in applied], [11, 2])
        for table in (2, 3):
            data = symbol_fixture(relocations=[(0x9000, 257, 20, 0, table)])
            result = self.run_image(data, mode='--all')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('symbol index', result.stderr)
        result = self.run_image(symbol_fixture([dict(section=20)]), mode='--all')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('symbol section index', result.stderr)

    def test_symbol_target_validation_and_transaction(self):
        for kind in (257, 1025, 1026):
            for target, message in ((0xa000, 'unmapped'), (0x8000, 'permission'),
                                    (0x9011, 'aligned'), (0x9038, 'unmapped'),
                                    (0x9000, 'composition')):
                with self.subTest(kind=kind, target=target):
                    data = symbol_fixture(relocations=[(0x9000, 257, 1, 0, 2),
                                                        (target, kind, 1, 0, 2)])
                    if target == 0x9038:
                        struct.pack_into('<Q', data, 160, 60)
                        struct.pack_into('<Q', data, 152, 60)
                    result = self.run_image(data, mode='--all')
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(message, result.stderr)
                    self.assertNotIn('partial', result.stderr)
            for flags in (0, 1, 4, 5):
                data = symbol_fixture(relocations=[(0x9000, kind, 1, 0, 2)])
                struct.pack_into('<I', data, 124, flags)
                result = self.run_image(data, mode='--all')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('permission', result.stderr)
        # Biasing an ordinary definition is checked address formation, separate
        # from S+A field reduction; even a valid first plan entry must not commit.
        data = symbol_fixture([{}, dict(value=(1 << 64) - 256, section=7)],
                              [(0x9000, 257, 1, 0, 2), (0x9008, 257, 2, 0, 2)])
        struct.pack_into('<IIQQQQIIQQ', data, 0x1800 + 7 * 64,
                         0, 8, 2, (1 << 64) - 256, 0, 64, 0, 0, 1, 0)
        result = self.run_image(data, mode='--all')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('address/size overflow', result.stderr)
        self.assertNotIn('partial', result.stderr)
        # An aligned target straddling adjacent mappings still fails as one range.
        data = symbol_fixture(relocations=[(0x9000, 257, 1, 0, 2), (0x9008, 1025, 1, 0, 2)])
        struct.pack_into('<Q', data, 160, 12)
        struct.pack_into('<Q', data, 152, 12)
        struct.pack_into('<Q', data, 80, 0x900c)
        result = self.run_image(data, mode='--all')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unmapped', result.stderr)
        self.assertNotIn('partial', result.stderr)

    def test_symbol_relative_combination_phase_order_and_composition(self):
        entries = [(0x9000, 1027, 0, -4, 2), (0x9008, 257, 1, 8, 2),
                   (0x9010, 1026, 1, 0, 2)]
        for mode in ('--all', '--relative-symbols', '--symbols-relative'):
            result = self.run_image(symbol_fixture(relocations=entries), mode=mode)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(len(report['applied_relocations']), 3)
            self.assertEqual(report['relocations'], [])
        for first_kind, second_kind in ((1027, 257), (257, 1027), (257, 1032), (1025, 257)):
            for target in (0x9000, 0x9004):
                data = symbol_fixture(relocations=[(0x9000, first_kind, int(first_kind != 1027), 0, 2),
                                                    (target, second_kind, int(second_kind != 1027), 0, 2)])
                for mode in ('--all', '--relative-symbols', '--symbols-relative'):
                    result = self.run_image(data, mode=mode)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn('partial', result.stderr)

    def test_later_phase_failure_preserves_prior_applied_entries(self):
        for mode, entries in (
                ('--relative-symbols', [(0x9000, 1027, 0, 1, 2),
                                        (0x9008, 257, 1, 0, 2), (0xa000, 1025, 1, 0, 2)]),
                ('--symbols-relative', [(0x9000, 257, 1, 0, 2),
                                        (0x9008, 1027, 0, 1, 2), (0xa000, 1027, 0, 0, 2)])):
            result = self.run_image(symbol_fixture(relocations=entries), mode=mode)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('unmapped', result.stderr)
            self.assertNotIn('partial', result.stderr)
            self.assertNotIn('incorrectly completed', result.stderr)

    def test_symbol_write_only_rel_and_phase_isolation(self):
        data = symbol_fixture()
        struct.pack_into('<I', data, 124, 2)
        path = self.directory / 'symbol-write-only.elf'
        path.write_bytes(data)
        result = subprocess.run([str(self.write_only_runner), str(path),
                                 hashlib.sha256(data).hexdigest()], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = symbol_fixture(relocations=[(0x9000, 1027, 0, 4, 2), (0x9008, 257, 1, 4, 2)])
        for mode, kind in (('--relocate', 1027), ('--symbols', 257)):
            result = self.run_image(data, mode=mode)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual([r['type'] for r in report['applied_relocations']], [kind])
            self.assertEqual(len(report['relocations']), 1)
        for kind in (257, 1025, 1026):
            data = symbol_fixture(relocations=[(0x9000, kind, 1, 0, 2)])
            struct.pack_into('<I', data, 0x1800 + 5 * 64 + 4, 9)
            struct.pack_into('<Q', data, 0x1800 + 5 * 64 + 32, 16)
            struct.pack_into('<Q', data, 0x1800 + 5 * 64 + 56, 16)
            result = self.run_image(data, mode='--all')
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['applied_relocations'], [])
            self.assertEqual(report['relocations'][0]['reason'], 'rel_implicit_addend_unsupported')

    def test_symbol_versioning_nonallocated_and_tls_sections_remain_unresolved(self):
        for flags, reason in ((0, 'nonallocated_symbol_section'), (0x403, 'tls_unsupported')):
            data = symbol_fixture()
            struct.pack_into('<Q', data, 0x1800 + 4 * 64 + 8, flags)
            report = json.loads(self.run_image(data, mode='--all').stdout)
            self.assertEqual(report['relocations'][0]['reason'], reason)
        data = symbol_fixture()
        struct.pack_into('<IIQQQQIIQQ', data, 0x1800 + 7 * 64,
                         0, 0x6fffffff, 0, 0, 0x1200, 4, 2, 0, 2, 2)
        report = json.loads(self.run_image(data, mode='--all').stdout)
        self.assertEqual(report['relocations'][0]['reason'], 'symbol_versioning_unsupported')



if __name__ == '__main__':
    unittest.main()
