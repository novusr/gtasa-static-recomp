"""Linker audit over synthetic ELF; guest code is never invoked."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

from test_image import ROOT, fixture, symbol_fixture

spec = importlib.util.spec_from_file_location('audit_linker', ROOT / 'tools/audit_linker.py')
audit_linker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_linker)


def add_section(data, kind, offset, size, link, info=0, stride=0, address=0):
    count, = struct.unpack_from('<H', data, 60)
    shoff, = struct.unpack_from('<Q', data, 40)
    end = shoff + (count + 1) * 64
    data.extend(bytes(max(0, end - len(data))))
    struct.pack_into('<IIQQQQIIQQ', data, shoff + count * 64,
                     0, kind, 0, address, offset, size, link, info, 2, stride)
    struct.pack_into('<H', data, 60, count + 1)
    return count


def version_fixture(requirement=False):
    data = symbol_fixture(symbols=[dict(binding=1, section=0 if requirement else 4)])
    # One global versioned symbol, two distinct version string offsets.
    struct.pack_into('<HH', data, 0x1200, 0, 0x8002)
    add_section(data, audit_linker.VERSYM, 0x1200, 4, 2, stride=2, address=0xb200)
    if requirement:
        struct.pack_into('<HHIII', data, 0x1240, 1, 1, 1, 16, 0)
        struct.pack_into('<IHHII', data, 0x1250, 123, 0, 2, 1, 0)
        add_section(data, audit_linker.VERNEED, 0x1240, 32, 1, info=1, address=0xb240)
    else:
        struct.pack_into('<HHHHIII', data, 0x1240, 1, 0, 2, 1, 123, 20, 0)
        struct.pack_into('<II', data, 0x1254, 1, 0)
        add_section(data, audit_linker.VERDEF, 0x1240, 28, 1, info=1, address=0xb240)
    return data


class AuditTests(unittest.TestCase):
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

    def run_audit(self, data, page=0x1000, digest=None):
        path = self.directory / 'fixture.elf'
        path.write_bytes(data)
        before = path.read_bytes()
        report = audit_linker.audit(path, digest or hashlib.sha256(data).hexdigest(),
                                    0x100000000, page, self.runner)
        self.assertEqual(path.read_bytes(), before)
        self.assertFalse(report['ready_to_execute'])
        self.assertTrue(report['relro_sealed'])
        self.assertEqual(report['guest_page_size'], page)
        return report

    def test_strong_weak_and_preemption(self):
        symbols = [dict(binding=1, section=0), dict(binding=2, section=0),
                   dict(binding=1), dict(binding=2), dict(binding=0),
                   dict(binding=1, visibility=1), dict(binding=1, visibility=2),
                   dict(binding=1, visibility=3)]
        data = symbol_fixture(symbols=symbols,
                              relocations=[(0x9000 + 8 * i, 257, i + 1, 0, 2)
                                           for i in range(8)])
        report = self.run_audit(data)
        self.assertEqual(report['summary']['applied'], 4)
        self.assertEqual(report['summary']['unresolved_by_reason'],
                         {'undefined_symbol': 2, 'preemptible_symbol': 2})
        self.assertEqual([s['binding'] for s in report['imports']], [1, 2])
        self.assertEqual(len(report['preemptible_definitions']), 2)
        self.assertTrue(all(len(s['relocation_references']) == 1
                            for s in report['preemptible_definitions']))
        for s in report['imports']:
            self.assertEqual(s['provider'], 'unknown')
            self.assertEqual(s['implementation'], 'unknown')
            self.assertEqual(s['visibility'], 0)
            self.assertEqual(s['table_section'], 2)

    def test_same_names_independent_tables(self):
        data = symbol_fixture(symbols=[dict(binding=1)],
                              second_symbols=[dict(binding=1, value=0x9020)],
                              relocations=[(0x9000, 257, 1, 0, 2), (0x9008, 257, 1, 0, 3)])
        report = self.run_audit(data)
        groups = report['unresolved_groups']
        self.assertEqual(len(groups), 2)
        self.assertEqual([g['symbol'] for g in groups], ['same', 'same'])
        self.assertEqual([g['symbol_identity']['table_section'] for g in groups], [2, 3])
        self.assertEqual([r['relocation_section'] for r in report['unresolved_relocations']], [5, 6])

    def test_two_dynamic_tables_import_identity(self):
        data = symbol_fixture(symbols=[dict(section=0, binding=1)],
                              second_symbols=[dict(section=0, binding=2)], relocations=[])
        struct.pack_into('<I', data, 0x1800 + 3 * 64 + 4, 11)
        report = self.run_audit(data)
        self.assertEqual([(s['name'], s['table_section'], s['index']) for s in report['imports']],
                         [('same', 2, 1), ('same', 3, 1)])

    def test_dynamic_and_absent_versions(self):
        report = self.run_audit(fixture())
        self.assertEqual(report['needed_libraries'], ['libfixture.so'])
        self.assertEqual(report['dependencies'][0]['provider'], 'unknown')
        self.assertEqual(report['dynamic'][0]['tag_name'], 'DT_NEEDED')
        self.assertFalse(report['symbol_versions']['present'])
        self.assertTrue(all(s['version'] is None for s in report['symbols']))
        self.assertEqual(report['summary']['relocation_formats'], {'RELA': 2})

    def test_version_definitions_and_requirements(self):
        for requirement in (False, True):
            with self.subTest(requirement=requirement):
                report = self.run_audit(version_fixture(requirement))
                self.assertTrue(report['symbol_versions']['present'])
                entry = next(s for s in report['symbols'] if s['table_section'] == 2 and s['index'] == 1)
                self.assertEqual(entry['version']['index'], 2)
                self.assertTrue(entry['version']['hidden'])
                self.assertEqual(report['symbol_versions']['records'][0]['kind'],
                                 'requirement' if requirement else 'definition')
                self.assertEqual(report['symbol_versions']['records'][0]['names'][0]['name'], 'same')
                self.assertEqual(report['unresolved_relocations'][0]['version'], entry['version'])

    def test_versioned_internal_stays_unresolved(self):
        data = version_fixture()
        struct.pack_into('<B', data, 0x600 + 24 + 5, 2) # hidden definition
        report = self.run_audit(data)
        self.assertEqual(report['summary']['unresolved_by_reason'], {'symbol_versioning_unsupported': 1})
        self.assertEqual(report['summary']['applied'], 0)

    def test_malformed_versions(self):
        base = version_fixture()
        cases = []
        for offset, fmt, value in [
                (0x1800 + 8 * 64 + 32, '<Q', 2), # truncated versym
                (0x1800 + 8 * 64 + 40, '<I', 1), # non-symbol link
                (0x1800 + 8 * 64 + 56, '<Q', 4), # stride
                (0x1240, '<H', 2), # unsupported version
                (0x1246, '<H', 2), # wrong auxiliary count
                (0x124c, '<I', 0xffff), # aux outside section
                (0x1258, '<I', 8), # last aux must terminate
                (0x1250, '<I', 20), # last record must terminate
                (0x1254, '<I', 99), # bad name
                (0x1202, '<H', 3), # dangling version index
                (0x1800 + 9 * 64 + 44, '<I', 2)]: # wrong header count
            data = bytearray(base)
            struct.pack_into(fmt, data, offset, value)
            cases.append(data)
        for data in cases:
            with self.subTest(change=cases.index(data)):
                with self.assertRaises(ValueError):
                    self.run_audit(data)
        data = version_fixture(True)
        struct.pack_into('<I', data, 0x125c, 16) # unterminated vernaux chain
        with self.assertRaises(ValueError):
            self.run_audit(data)

    def test_version_dynamic_pointer_and_count(self):
        base = version_fixture()
        # Allocate a dynamic table in unused fixture storage.
        for pointer, count, valid in [(0xb240, 1, True), (0xb241, 1, False),
                                      (0xb240, 2, False)]:
            data = bytearray(base)
            struct.pack_into('<QQQQQQQQ', data, 0x1300, 0x6ffffffc, pointer,
                             0x6ffffffd, count, 0x6ffffff0, 0xb200, 0, 0)
            add_section(data, 6, 0x1300, 64, 1, stride=16)
            if valid:
                self.run_audit(data)
            else:
                with self.assertRaises(ValueError):
                    self.run_audit(data)

    def test_rel_and_special_attributes_inventory(self):
        data = symbol_fixture(symbols=[dict(other=0x80, type=6)], relocations=[])
        struct.pack_into('<QQ', data, 0xc00, 0x9000, (1 << 32) | 1031)
        struct.pack_into('<Q', data, 0x1800 + 5 * 64 + 32, 16)
        struct.pack_into('<I', data, 0x1800 + 5 * 64 + 4, 9)
        struct.pack_into('<Q', data, 0x1800 + 5 * 64 + 56, 16)
        # Third program header describes TLS without executing or allocating TLS.
        struct.pack_into('<H', data, 56, 3)
        struct.pack_into('<IIQQQQQQ', data, 176, 7, 4, 0x300, 0x9000, 0, 8, 16, 8)
        struct.pack_into('<Q', data, 0x1800 + 4 * 64 + 8, 0x403)
        report = self.run_audit(data)
        self.assertEqual(report['summary']['relocation_formats'], {'REL': 1})
        self.assertEqual(report['summary']['unresolved_by_reason'], {'rel_implicit_addend_unsupported': 1})
        self.assertEqual(report['special_requirements']['tls_sections'], [4])
        self.assertEqual(report['special_requirements']['tls_segments'][0]['memory_size'], 16)
        self.assertEqual(report['special_requirements']['extra_symbol_attributes'][0]['other'], 0x80)

    def test_dynamic_unknown_flags_and_bad_string(self):
        data = fixture()
        struct.pack_into('<QQQQQQQQ', data, 0x450, 30, 0x80000002,
                         0x6ffffffb, 3, 0x70000000, 123, 0, 0)
        struct.pack_into('<Q', data, 0x500 + 4 * 64 + 32, 64)
        report = self.run_audit(data)
        self.assertEqual(report['dynamic'][0]['known_flags'], ['SYMBOLIC'])
        self.assertEqual(report['dynamic'][0]['other_flag_bits'], 0x80000000)
        self.assertEqual(report['dynamic'][1]['known_flags'], ['NOW', 'GLOBAL'])
        self.assertEqual(report['dynamic'][2]['tag_name'], 'unknown')
        struct.pack_into('<QQ', data, 0x450, 29, 0xffffff)
        with self.assertRaises(ValueError):
            self.run_audit(data)

    def test_multiple_version_records_and_auxiliary_identities(self):
        data = version_fixture(True)
        # Two auxiliary names in the first requirement, distinct version indices.
        struct.pack_into('<H', data, 0x1242, 2)
        struct.pack_into('<I', data, 0x125c, 16)
        struct.pack_into('<IHHII', data, 0x1260, 123, 0, 3, 1, 0)
        struct.pack_into('<Q', data, 0x1800 + 9 * 64 + 32, 48)
        struct.pack_into('<H', data, 0x1202, 3)
        report = self.run_audit(data)
        self.assertEqual(report['imports'][0]['version']['record']['auxiliary_index'], 1)
        # Second requirement header follows all first-record auxiliaries.
        struct.pack_into('<I', data, 0x124c, 48)
        struct.pack_into('<HHIII', data, 0x1270, 1, 1, 1, 16, 0)
        struct.pack_into('<IHHII', data, 0x1280, 123, 0, 4, 1, 0)
        struct.pack_into('<Q', data, 0x1800 + 9 * 64 + 32, 80)
        struct.pack_into('<I', data, 0x1800 + 9 * 64 + 44, 2)
        report = self.run_audit(data)
        self.assertEqual(len(report['symbol_versions']['records']), 2)
        # Duplicate version indices remain an explicit ambiguous-metadata rejection.
        struct.pack_into('<H', data, 0x1286, 3)
        with self.assertRaises(ValueError):
            self.run_audit(data)

    def test_tls_ifunc_only_inventory(self):
        data = symbol_fixture(symbols=[dict(type=6), dict(type=10)],
                              relocations=[(0x9000, 257, 1, 0, 2),
                                           (0x9008, 257, 2, 0, 2),
                                           (0x9010, 1032, 0, 0x8000, 2),
                                           (0x9018, 1031, 1, 0, 2)])
        report = self.run_audit(data)
        self.assertEqual(report['summary']['applied'], 0)
        self.assertEqual(len(report['special_requirements']['tls_symbols']), 1)
        self.assertEqual(len(report['special_requirements']['ifunc_symbols']), 1)
        self.assertEqual(report['summary']['unresolved_by_reason'],
                         {'tls_unsupported': 1, 'ifunc_unsupported': 1, 'relocation_type_unsupported': 2})

    def test_failures_preserve_output_and_do_not_publish(self):
        output = self.directory / 'report.json'
        config = self.directory / 'config.json'
        path = self.directory / 'cli.elf'
        cases = [(fixture(), '0' * 64), (b'invalid ELF', None),
                 (version_fixture(), None)]
        struct.pack_into('<H', cases[2][0], 0x1202, 99)
        for data, digest in cases:
            path.write_bytes(data)
            config.write_text(json.dumps(dict(input=str(path), sha256=digest or hashlib.sha256(data).hexdigest())))
            for existing in (False, True):
                output.unlink(missing_ok=True)
                if existing:
                    output.write_text('prior report')
                result = subprocess.run(['python3', str(ROOT / 'tools/audit_linker.py'),
                                         '--config', str(config), '--runner', str(self.runner),
                                         '--load-bias', '0', '--guest-page-size', '4096',
                                         '--output', str(output)], capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output.read_text() if existing else output.exists(),
                                 'prior report' if existing else False)

    def test_compose_is_read_only_and_deterministic(self):
        data = fixture()
        path = self.directory / 'snapshot.elf'
        path.write_bytes(data)
        result = subprocess.run([str(self.runner), str(path), hashlib.sha256(data).hexdigest(),
                                 '0', '536870912', '--all', '4096'], check=True,
                                capture_output=True, text=True)
        native = json.loads(result.stdout)
        before = copy.deepcopy(native)
        report = audit_linker.compose_report(data, native)
        self.assertEqual(native, before) # includes applied bytes, RELRO permission ranges, sealing and relocation status
        self.assertEqual(report, audit_linker.compose_report(data, native))
        self.assertEqual(report['applied_relocations'][0]['bytes'], native['applied_relocations'][0]['bytes'])
        with mock.patch.object(audit_linker.os, 'replace', side_effect=OSError('publish failure')):
            output = self.directory / 'atomic.json'
            output.write_text('old')
            with self.assertRaises(OSError):
                audit_linker.publish(report, output)
            self.assertEqual(output.read_text(), 'old')


if __name__ == '__main__':
    unittest.main()
