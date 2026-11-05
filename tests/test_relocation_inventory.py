"""Synthetic, data-only inventory binding and publication tests."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
APS = b'APS2\x01\x80\x80\x02\x01\x03\x00\x83\x08'
EMPTY = b'APS2\0\0'


def fixture(standard=False, aps=APS, orphan=False, ordinary_rel=False):
    data = bytearray(0x1400)
    data[:16] = b'\x7fELF' + bytes([2, 1, 1]) + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, 3, 183, 1, 0, 64, 0x1200,
                     0, 64, 56, 3, 64, 8, 0)
    # Target mapping deliberately has no read or write permission.
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 4, 0, 0x4000, 0, 0x1000, 0x1000, 1)
    struct.pack_into('<IIQQQQQQ', data, 120, 1, 0, 0x1000, 0x8000, 0, 16, 0x1000, 1)
    data[0x200:0x209] = b'\0fixture\0'
    struct.pack_into('<IBBHQQ', data, 0x258, 1, 1, 2, 7, 0x8000, 8)
    data[0x300:0x300+len(aps)] = aps
    struct.pack_into('<QQ', data, 0x340, 0x8010, 3)
    struct.pack_into('<QQq', data, 0x380, 0x8020, (1 << 32) | 1026, 0)
    ptr, size, ent = (36, 35, 37) if standard else (0x6fffe000, 0x6fffe001, 0x6fffe003)
    tags = [(5, 0x4200), (10, 9), (6, 0x4240), (11, 24), (9, 24)]
    if not orphan:
        tags += [(0x60000011, 0x4300), (0x60000012, len(aps))]
    tags += [(ptr, 0x4340), (size, 16), (ent, 8), (23, 0x4380),
             (2, 16 if ordinary_rel else 24), (20, 17 if ordinary_rel else 7)]
    if ordinary_rel:
        tags += [(19, 16)]
        tags = [t for t in tags if t[0] != 9 or not orphan]
    tags.append((0, 0))
    for i, (tag, value) in enumerate(tags):
        struct.pack_into('<QQ', data, 0x400 + i * 16, tag, value)
    dynsize = len(tags) * 16
    struct.pack_into('<IIQQQQQQ', data, 176, 2, 4, 0x400, 0x4400, 0, dynsize, dynsize, 8)
    sections = [(3, 2, 0x4200, 0x200, 9, 0, 0),
                (11, 2, 0x4240, 0x240, 48, 1, 24),
                (0x60000002, 2, 0x4300, 0x300, len(aps), 0 if orphan else 2, 1),
                (19 if standard else 0x6fffff00, 2, 0x4340, 0x340, 16, 0, 8),
                (9 if ordinary_rel else 4, 2, 0x4380, 0x380, 16 if ordinary_rel else 24, 2, 16 if ordinary_rel else 24),
                (6, 2, 0x4400, 0x400, dynsize, 1, 16),
                (8, 2, 0x8000, 0x1000, 0x1000, 0, 0)]
    for i, (kind, flags, va, off, size, link, stride) in enumerate(sections, 1):
        struct.pack_into('<IIQQQQIIQQ', data, 0x1200 + i * 64,
                         0, kind, flags, va, off, size, link, 0, 1, stride)
    return data


def section(data, index, offset, value, width=8):
    struct.pack_into('<' + ('I' if width == 4 else 'Q'), data, 0x1200 + index * 64 + offset, value)


def tag(data, wanted, value=None, replacement=None):
    for p in range(0x400, 0x600, 16):
        found = struct.unpack_from('<Q', data, p)[0]
        if found == wanted:
            if replacement is not None:
                struct.pack_into('<Q', data, p, replacement)
            if value is not None:
                struct.pack_into('<Q', data, p+8, value)
            return
    raise AssertionError(wanted)


class RelocationInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.runner = cls.directory / 'inventory'
        sources = ['src/runtime.cpp', 'src/elf_image.cpp', 'src/aps2_rela.cpp', 'src/relr.cpp']
        base = ['c++', '-std=c++11', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
                '-I', str(ROOT / 'include')] + [str(ROOT / p) for p in sources]
        subprocess.run(base + [str(ROOT / 'tools/inventory_image.cpp'), '-lcrypto', '-o', str(cls.runner)],
                       check=True, capture_output=True)
        cls.failure_runner = cls.directory / 'inventory-failure'
        subprocess.run(base + [str(ROOT / 'tests/inventory_failure_runner.cpp'), '-lcrypto',
                               '-o', str(cls.failure_runner)], check=True, capture_output=True)
        cls.atomic = cls.directory / 'atomic'
        subprocess.run(base + [str(ROOT / 'tests/inventory_atomic.cpp'), '-lcrypto', '-o', str(cls.atomic)],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_inventory(self, data, bias=0x100000000, records=1000000, storage=268435456, digest=None):
        path = self.directory / 'fixture.elf'
        path.write_bytes(data)
        return subprocess.run([str(self.runner), str(path), digest or hashlib.sha256(data).hexdigest(),
                               str(bias), str(records), str(storage)], capture_output=True, text=True)

    def success(self, data, **kwargs):
        result = self.run_inventory(data, **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def reject(self, data, **kwargs):
        result = self.run_inventory(data, **kwargs)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        return result.stderr

    def test_android_and_standard_independent_expected_inventory(self):
        for standard in (False, True):
            with self.subTest(standard=standard):
                r = self.success(fixture(standard))
                self.assertEqual(r['profile'], 'native-relocation-inventory-only-v1')
                self.assertEqual(r['application_status'], 'application-not-supported')
                self.assertFalse(r['ready_to_execute'])
                self.assertFalse(r['relro_sealed'])
                self.assertEqual(r['decoded_count'], 4)
                a, b, c = r['tables']
                self.assertEqual([t['section'] for t in r['tables']], [3, 4, 5])
                self.assertEqual([t['load_program_header'] for t in r['tables']], [0, 0, 0])
                self.assertEqual([t['encoded_count'] for t in r['tables']], [13, 2, 1])
                self.assertEqual(a['encoding'], 'ANDROID_APS2_RELA')
                self.assertEqual(a['symbol_table'], 2)
                self.assertEqual(a['records'], [dict(offset=0x8000, address=0x100008000,
                    info=1027, addend=0, addend_kind='explicit', symbol_index=0, ordinal=0,
                    group_ordinal=0, group_begin=8, group_header_end=13, group_end=13,
                    entry_begin=13, entry_end=13, flags=3)])
                self.assertEqual(b['encoding'], 'RELR' if standard else 'ANDROID_RELR')
                self.assertIsNone(b['symbol_table'])
                self.assertEqual(b['records'], [dict(offset=0x8010, address=0x100008010,
                    ordinal=0, word_index=0, byte_offset=0, source=1, bitmap_bit=0,
                    addend_kind='implicit-target'), dict(offset=0x8018, address=0x100008018,
                    ordinal=1, word_index=1, byte_offset=8, source=2, bitmap_bit=1,
                    addend_kind='implicit-target')])
                self.assertEqual(c['records'], [dict(offset=0x8020, address=0x100008020,
                    ordinal=0, byte_offset=0, info=(1 << 32) | 1026, symbol_index=1,
                    addend_kind='explicit', addend_bits=0)])
                self.assertEqual(a['dynamic_associations'], [dict(section=6, index=5,
                    tag=0x60000011, value=0x4300), dict(section=6, index=6,
                    tag=0x60000012, value=13), dict(section=6, index=4, tag=9, value=24)])

    def test_canonical_orphan_and_ordinary_rel(self):
        r = self.success(fixture(aps=EMPTY, orphan=True))
        self.assertEqual(r['tables'][0]['decoded_count'], 0)
        self.assertEqual(r['tables'][0]['dynamic_associations'], [])
        self.assertEqual(r['tables'][0]['encoded_size'], 6)
        data = fixture(aps=EMPTY, orphan=True)
        tag(data, 9, replacement=0x70000100)
        r = self.success(data)  # PLT-only RELA needs no invented DT_RELAENT.
        self.assertEqual(len(r['tables'][-1]['dynamic_associations']), 3)
        r = self.success(fixture(ordinary_rel=True))
        self.assertEqual(r['tables'][-1]['encoding'], 'REL')
        self.assertNotIn('addend_bits', r['tables'][-1]['records'][0])

    def test_ordinary_dynamic_families_and_empty_relr(self):
        for ordinary_rel in (False, True):
            data = fixture(ordinary_rel=ordinary_rel)
            tag(data, 23, replacement=17 if ordinary_rel else 7)
            tag(data, 2, replacement=18 if ordinary_rel else 8)
            tag(data, 20, replacement=0x70000100)
            r = self.success(data)
            self.assertEqual(r['tables'][-1]['decoded_count'], 1)
        for standard in (False, True):
            data = fixture(standard)
            section(data, 4, 32, 0)
            tag(data, 35 if standard else 0x6fffe001, value=0)
            r = self.success(data)
            self.assertEqual(r['tables'][1]['encoded_count'], 0)
            self.assertEqual(r['tables'][1]['decoded_count'], 0)

    def test_unsupported_numbering_and_dynamic_provenance(self):
        for offset, fmt, value in [(40, 'Q', 0), (56, 'H', 65535), (60, 'H', 0),
                                   (58, 'H', 32), (176+16, 'Q', 0x4408),
                                   (176+8, 'Q', 0x408), (176+40, 'Q', 16)]:
            with self.subTest(offset=offset, value=value):
                data = fixture()
                struct.pack_into('<'+fmt, data, offset, value)
                self.reject(data)
        data = fixture()
        # Dynamic table is no longer terminated within its section.
        dynsize = struct.unpack_from('<Q', data, 176+32)[0]
        struct.pack_into('<QQ', data, 0x400+dynsize-16, 0x70000100, 0)
        self.reject(data)

    def test_orphan_policy_after_full_decode(self):
        for aps in (APS, b'APS2\0\1', b'APS2\x80\0\0', EMPTY+b'\0', b'APS2\0'):
            with self.subTest(aps=aps):
                self.reject(fixture(aps=aps, orphan=True))

    def test_section_mismatches(self):
        for index, offset, value, width in [
            (3, 4, 0x60000001, 4), (3, 56, 24, 8), (4, 56, 1, 8), (5, 56, 16, 8),
            (4, 4, 19, 4), (3, 24, 0x301, 8), (3, 16, 0x4301, 8),
            (3, 32, 14, 8), (4, 32, 15, 8), (3, 40, 1, 4), (3, 40, 99, 4),
            (4, 40, 2, 4), (5, 40, 1, 4), (3, 24, len(fixture()), 8),
            (4, 16, (1 << 64)-8, 8), (3, 16, 0x9000, 8), (2, 40, 7, 4),
            (6, 40, 7, 4), (2, 56, 16, 8)]:
            with self.subTest(index=index, offset=offset, value=value):
                data = fixture()
                section(data, index, offset, value, width)
                self.reject(data)

    def test_dynamic_family_rejections(self):
        mutations = [(0x60000011, 0x4301, None), (0x60000012, 14, None),
            (9, 1, None), (0x6fffe003, 1, None), (0x6fffe001, 8, None),
            (0x6fffe000, 0x4348, None), (23, 0x4388, None), (20, 19, None),
            (11, 8, None), (6, 0x4248, None), (5, 0x4201, None)]
        missing = [0x60000011, 0x60000012, 9, 0x6fffe000, 0x6fffe001,
                   0x6fffe003, 23, 2, 20, 6, 11, 5, 10]
        mutations += [(t, None, 0x70000100) for t in missing]
        mutations += [(11, None, 9), (11, None, 0x6fffe005),
                      (11, None, 0x6000000f), (11, None, 0x60000010),
                      (0x6fffe000, None, 36), (0x6fffe001, None, 35),
                      (0x6fffe003, None, 37)]
        for wanted, value, replacement in mutations:
            with self.subTest(wanted=hex(wanted), value=value, replacement=replacement):
                data = fixture()
                tag(data, wanted, value, replacement)
                self.reject(data)
        for standard in (False, True):
            data = fixture(standard)
            for t in ((36, 35, 37) if standard else (0x6fffe000, 0x6fffe001, 0x6fffe003)):
                tag(data, t, replacement=0x70000000+t)
            self.assertIn('orphan RELR', self.reject(data))

    def test_overlap_and_aliases(self):
        data = fixture()
        # A second relocation section aliases the PLT table, including file bytes.
        for field, value, width in [(4, 4, 4), (16, 0x4380, 8), (24, 0x380, 8),
                                    (32, 24, 8), (40, 2, 4), (56, 24, 8)]:
            section(data, 7, field, value, width)
        self.assertIn('overlapping table', self.reject(data))
        data = fixture()
        tag(data, 11, value=0x4380, replacement=7)
        tag(data, 0x60000011, value=24, replacement=8)
        self.assertIn('conflicting table aliases', self.reject(data))
        data = fixture()
        tag(data, 11, value=0x4340, replacement=36)
        self.reject(data)  # Android + standard aliases cannot bind one table.

    def test_target_bias_extents_and_symbols(self):
        for offset in (0x8ffc, 0x9000, 0x5000, 0xfffffffffffffff8):
            data = fixture()
            struct.pack_into('<Q', data, 0x380, offset)
            self.reject(data)
        data = fixture()
        struct.pack_into('<Q', data, 0x380+8, (2 << 32) | 257)
        self.reject(data)
        data = fixture()
        data[0x30b:0x30d] = b'\x81\x82'  # Truncated info continuation.
        self.reject(data)
        self.reject(fixture(), bias=(1 << 64)-0x8000)
        self.reject(fixture(), bias=1)  # Biased RELR alignment.
        data = fixture()
        struct.pack_into('<Q', data, 120+40, 0x24)  # Last ordinary extent crosses mapping end.
        self.reject(data)
        # Adjacent mappings do not authorize an extent spanning both.
        data = fixture()
        struct.pack_into('<Q', data, 64+32, 0x1000)
        struct.pack_into('<Q', data, 64+40, 0x4000)
        struct.pack_into('<Q', data, 0x380, 0x7ffc)
        self.reject(data)

    def test_cross_format_target_composition_remains_deferred(self):
        data = fixture()
        struct.pack_into('<Q', data, 0x340, 0x8000)  # Shares APS2 target.
        struct.pack_into('<Q', data, 0x380, 0x8004)  # Partial overlap with both.
        self.assertEqual(self.success(data)['decoded_count'], 4)
        # Duplicate slots inside RELR itself retain the decoder's rejection.
        struct.pack_into('<Q', data, 0x348, 0x8000)
        self.reject(data)

    def test_cumulative_limits_exact_boundary(self):
        data = fixture()
        r = self.success(data, records=4)
        self.reject(data, records=3)  # Each table alone fits.
        self.reject(data, records=2)  # APS2 and RELR share the same remaining budget.
        storage = r['accounted_storage_bytes']
        self.success(data, storage=storage)
        self.reject(data, storage=storage-1)
        self.reject(data, storage=storage-41)  # Exhausts the later packed table's budget.
        self.reject(data, storage=0)
        self.reject(data, records=0)
        self.success(fixture(aps=EMPTY, orphan=True), records=3)

    def test_hash_and_late_malformed_atomic_report(self):
        output = self.directory / 'report.json'
        path = self.directory / 'cli.elf'
        data = fixture()
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        args = ['python3', str(ROOT / 'tools/inventory_image.py'), '--runner', str(self.runner),
                '--input', str(path), '--sha256', digest, '--instance-id', 'synthetic',
                '--load-bias', '0x100000000', '--output', str(output)]
        subprocess.run(args, check=True, capture_output=True)
        saved = output.read_bytes()
        bad = fixture()
        struct.pack_into('<Q', bad, 0x388, 5 << 32)  # Last table fails after valid packed tables.
        for present in (True, False):
            if not present:
                output.unlink()
            for content, pin, extra in [(data, '0'*64, []), (bad, hashlib.sha256(bad).hexdigest(), []),
                                         (data, digest, ['--max-records', '3'])]:
                path.write_bytes(content)
                call = args.copy()
                call[call.index('--sha256')+1] = pin
                result = subprocess.run(call+extra, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output.read_bytes() if present else output.exists(), saved if present else False)
        self.assertEqual(list(self.directory.glob('tmp*')), [])

    def test_native_cli_allocation_failure_preserves_report(self):
        data = fixture()
        path = self.directory / 'allocation-report.elf'
        path.write_bytes(data)
        output = self.directory / 'allocation-report.json'
        args = ['python3', str(ROOT / 'tools/inventory_image.py'), '--runner', str(self.failure_runner),
                '--input', str(path), '--sha256', hashlib.sha256(data).hexdigest(),
                '--instance-id', 'allocation-test', '--load-bias', '0', '--output', str(output)]
        failures = 0
        for present in (True, False):
            if present:
                output.write_bytes(b'previous report sentinel')
            elif output.exists():
                output.unlink()
            for budget in range(1024):
                env = dict(os.environ, RECOMP_TEST_ALLOCATION_BUDGET=str(budget))
                result = subprocess.run(args, env=env, capture_output=True, text=True)
                if result.returncode == 0:
                    self.assertEqual(json.loads(output.read_text())['decoded_count'], 4)
                    break
                failures += 1
                self.assertEqual(output.read_bytes() if present else output.exists(),
                                 b'previous report sentinel' if present else False)
            else:
                self.fail('allocation injection never reached successful publication')
        self.assertGreater(failures, 10)

    def test_application_guards_and_allocation_atomicity(self):
        for info in (b'\x83\x08', b'\x81\x82\x80\x80\x10',
                     b'\x81\x88\x80\x80\x10', b'\x82\x88\x80\x80\x10'):
            data = fixture(aps=APS[:-2]+info)
            path = self.directory / 'atomic.elf'
            path.write_bytes(data)
            bad = data.copy()
            struct.pack_into('<Q', bad, 0x388, 5 << 32)
            bad_path = self.directory / 'malformed-last.elf'
            bad_path.write_bytes(bad)
            result = subprocess.run([str(self.atomic), str(path), hashlib.sha256(data).hexdigest(),
                                     str(bad_path), hashlib.sha256(bad).hexdigest()],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
