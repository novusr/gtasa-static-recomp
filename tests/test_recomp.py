"""Synthetic inputs only: these tests need neither Ghidra nor game files."""

import importlib.util
from collections import Counter
import contextlib
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('recomp', Path(__file__).parents[1] / 'tools/recomp.py')
recomp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recomp)


def fixture():
    # ELF virtual address 0x8000 maps to file offset 0x100, with a BSS tail.
    ident = b'\x7fELF' + bytes([2, 1, 1]) + bytes(9)
    header = ident + struct.pack('<HHIQQQIHHHHHH', 3, 183, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    segment = struct.pack('<IIQQQQQQ', 1, 5, 256, 0x8000, 0x8000, 4, 16, 256)
    return (header + segment).ljust(256, b'\x00') + bytes.fromhex('c0035fd6')


def symbol_fixture():
    """One real ELF symbol table, with a supported leaf and an alias."""
    data = bytearray(fixture())
    strings = b'\x00leaf\x00alias\x00'
    names = b'\x00.shstrtab\x00.strtab\x00.symtab\x00'
    name_offset = len(data)
    data.extend(names)
    string_offset = len(data)
    data.extend(strings)
    symbol_offset = len(data)
    data.extend(bytes(24))
    for name in (1, 6):
        data.extend(struct.pack('<IBBHQQ', name, 0x12, 0, 1, 0x8000, 4))
    section_offset = len(data)
    data.extend(bytes(64))
    for section in [(1, 3, name_offset, len(names), 0, 0),
                    (11, 3, string_offset, len(strings), 0, 0),
                    (19, 2, symbol_offset, 72, 2, 24)]:
        name, kind, offset, size, link, entsize = section
        data.extend(struct.pack('<IIQQQQIIQQ', name, kind, 0, 0, offset, size,
                                link, 1 if kind == 2 else 0, 1, entsize))
    struct.pack_into('<Q', data, 40, section_offset)
    struct.pack_into('<HH', data, 60, 4, 1)
    return bytes(data)


class ElfTests(unittest.TestCase):
    def test_virtual_address_translation(self):
        image = recomp.Image(fixture())
        self.assertEqual(image.read(0x8000, 4, executable=True), bytes.fromhex('c0035fd6'))
        self.assertEqual(image.inventory()['segments'][0]['p_memsz'], 16)

    def test_bss_and_unmapped_ranges_are_not_code(self):
        image = recomp.Image(fixture())
        for address, size in [(0x8004, 4), (0x7FFF, 4), (0x8000, 8), (-1, 4), (0x8000, 0)]:
            with self.subTest(address=address, size=size), self.assertRaises(recomp.RecompError):
                image.read(address, size)

    def test_wrong_machine_rejected(self):
        data = bytearray(fixture())
        data[18:20] = struct.pack('<H', 62)
        with self.assertRaises(recomp.RecompError):
            recomp.Image(bytes(data))

    def test_nonexecutable_segment_rejected(self):
        data = bytearray(fixture())
        data[68:72] = struct.pack('<I', 4)
        with self.assertRaises(recomp.RecompError):
            recomp.Image(bytes(data)).read(0x8000, 4, executable=True)


class LifterTests(unittest.TestCase):
    def test_empty_leaf_return(self):
        body, count = recomp.lift_body(bytes.fromhex('c0035fd6'), 0x8000)
        self.assertIn('return;', body)
        self.assertEqual(count, {'ret': 1})

    def test_unsupported_branch_is_rejected(self):
        with self.assertRaisesRegex(recomp.RecompError, 'unsupported instruction b'):
            recomp.lift_body(bytes.fromhex('01000014c0035fd6'), 0x8000)

    def test_no_early_or_alternative_return(self):
        for code in ('c0035fd6c0035fd6', '00005fd6'):
            with self.subTest(code=code), self.assertRaises(recomp.RecompError):
                recomp.lift_body(bytes.fromhex(code), 0x8000)

    def test_vector_fp_mode_rejected(self):
        # FMUL d0,d0,d0; RET: the current backend supports S registers only.
        with self.assertRaisesRegex(recomp.RecompError, 'register d0'):
            recomp.lift_body(bytes.fromhex('0008601ec0035fd6'), 0x8000)

    def test_unaligned_or_undecodable_code_rejected(self):
        for code, address in [(b'', 0), (b'123', 0), (bytes(4), 0), (bytes(4), 1)]:
            with self.subTest(code=code, address=address), self.assertRaises(recomp.RecompError):
                recomp.lift_body(code, address)

    def test_relocated_function_must_not_be_lifted(self):
        class RelocatedImage:
            def functions(self):
                return [{'symbol': 'leaf', 'address': 0x8000, 'size': 4}]

            def relocations(self):
                return [{'address': 0x8000}]

        with self.assertRaisesRegex(recomp.RecompError, 'code relocations'):
            recomp.lift(RelocatedImage(), [{'symbol': 'leaf', 'output': 'leaf'}])

    def test_duplicate_output_name_rejected(self):
        class LeafImage:
            def functions(self):
                return [{'symbol': 'leaf', 'address': 0x8000, 'size': 4}]

            def relocations(self):
                return []

            def read(self, address, size, executable=False):
                return bytes.fromhex('c0035fd6')

        with self.assertRaisesRegex(recomp.RecompError, 'unique'):
            recomp.lift(LeafImage(), [{'symbol': 'leaf', 'output': 'leaf'}] * 2)


class CommandTests(unittest.TestCase):
    def test_wrong_hash_never_publishes_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'config').mkdir()
            (root / 'guest.so').write_bytes(fixture())
            config = {'input': 'guest.so', 'sha256': '0' * 64,
                      'guest': 'aarch64-linux-android', 'host': 'x86_64-linux'}
            path = root / 'config/recomp.json'
            path.write_text(json.dumps(config))
            output = root / 'inventory.json'
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                result = recomp.main(['--config', str(path), 'inspect', '--output', str(output)])
            self.assertEqual(result, 1)
            self.assertIn('SHA-256 mismatch', errors.getvalue())
            self.assertFalse(output.exists())

    def test_scan_hash_gate_preserves_existing_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / 'guest.so'
            binary.write_bytes(symbol_fixture())
            config = root / 'config.json'
            config.write_text(json.dumps({'input': str(binary), 'sha256': '0' * 64,
                                         'guest': 'aarch64-linux-android', 'host': 'x86_64-linux'}))
            output = root / 'scan.json'
            output.write_text('previous report')
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                result = recomp.main(['--config', str(config), 'scan', '--output', str(output)])
            self.assertEqual(result, 1)
            self.assertIn('SHA-256 mismatch', errors.getvalue())
            self.assertEqual(output.read_text(), 'previous report')

    def test_scan_real_symbol_table_and_cli(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'config').mkdir()
            data = symbol_fixture()
            (root / 'guest.so').write_bytes(data)
            config = root / 'config/recomp.json'
            config.write_text(json.dumps({'input': 'guest.so',
                                         'sha256': hashlib.sha256(data).hexdigest(),
                                         'guest': 'aarch64-linux-android', 'host': 'x86_64-linux'}))
            output = root / 'reports/scan.json'
            with contextlib.redirect_stdout(io.StringIO()):
                result = recomp.main(['--config', str(config), 'scan', '--output', str(output)])
            self.assertEqual(result, 0)
            report = json.loads(output.read_text())
            self.assertEqual(report['input_sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(report['summary']['symbol_status_counts'], {'translatable': 2})
            self.assertEqual(report['summary']['unique_function_ranges'], 1)
            self.assertEqual({f['symbol'] for f in report['functions']}, {'leaf', 'alias'})
            self.assertTrue(all(f['semantic_verification'] == 'not_verified'
                                for f in report['functions']))

    def test_paths_resolve_relative_to_config_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'config').mkdir()
            (root / 'guest.so').write_bytes(fixture())
            config = {'input': 'guest.so', 'sha256': hashlib.sha256(fixture()).hexdigest(),
                      'guest': 'aarch64-linux-android', 'host': 'x86_64-linux'}
            path = root / 'config/recomp.json'
            path.write_text(json.dumps(config))
            output = root / 'inventory.json'
            with contextlib.redirect_stdout(io.StringIO()):
                result = recomp.main(['--config', str(path), 'inspect', '--output', str(output)])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.read_text())['machine'], 'aarch64')


class ScanTests(unittest.TestCase):
    def test_real_elf_scan_rejects_nonexecutable_and_bss_ranges(self):
        for change, reason in [('permissions', 'executable'), ('bss', 'file-backed')]:
            with self.subTest(change=change):
                data = bytearray(symbol_fixture())
                if change == 'permissions':
                    struct.pack_into('<I', data, 68, 4)
                else:
                    # Both alias symbols now claim a range reaching into BSS.
                    section_offset, = struct.unpack_from('<Q', data, 40)
                    symbol_offset, = struct.unpack_from('<Q', data, section_offset + 3 * 64 + 24)
                    for index in (1, 2):
                        struct.pack_into('<Q', data, symbol_offset + index * 24 + 16, 8)
                report = recomp.scan(recomp.Image(bytes(data)))
                self.assertEqual(report['summary']['symbol_status_counts'], {'blocked': 2})
                blocker, = report['blocker_summary']
                self.assertEqual(blocker['kind'], 'range')
                self.assertIn(reason, blocker['reason'])

    def test_scan_and_lift_accept_exactly_the_same_forms(self):
        for code in ['c0035fd6', '1f2003d5c0035fd6', '000040bdc0035fd6',
                     '000c40bdc0035fd6', '001440bcc0035fd6', '006861bcc0035fd6',
                     'e00340bdc0035fd6', '0008601ec0035fd6', '01000014c0035fd6',
                     '00005fd6', 'c0035fd6c0035fd6', '1f2003d5', 'ffffffffc0035fd6',
                     '0000402dc0035fd6', '', 'abcd', 'c0035fd6ff']:
            for address in (0x8000, 0x8001):
                with self.subTest(code=code, address=address):
                    try:
                        recomp.lift_body(bytes.fromhex(code), address)
                        accepted = True
                    except recomp.RecompError:
                        accepted = False
                    report = recomp.scan_body(bytes.fromhex(code), address)
                    self.assertEqual(not report['blockers'], accepted)

    def test_scan_collects_multiple_failures_and_resumes_after_decode_gap(self):
        # B; undecodable word; indexed load; post-indexed load; SP load; FMUL D; RET.
        code = bytes.fromhex('01000014ffffffff006861bc001440bce00340bd0008601ec0035fd6')
        report = recomp.scan_body(code, 0x8000)
        kinds = Counter(b['kind'] for b in report['blockers'])
        self.assertEqual(kinds, {'unsupported_instruction': 1, 'decode': 1,
                                 'addressing_mode': 3, 'operand_form': 1})
        self.assertEqual(report['opcodes']['ret'], 1)
        self.assertEqual(report['decoded_instruction_count'], 6)
        self.assertEqual(report['blockers'][-1]['examples'][0]['address'], 0x8014)

    def test_scan_range_relocation_alias_and_import_reporting(self):
        class ScanImage:
            def inventory(self):
                return {'sha256': 'synthetic', 'functions': [
                    {'symbol': 'blocked', 'address': 0x8000, 'size': 8},
                    {'symbol': 'alias', 'address': 0x8000, 'size': 8},
                    {'symbol': 'relocated', 'address': 0x9000, 'size': 4},
                    {'symbol': 'unmapped', 'address': 0xA000, 'size': 4}],
                    'imports': [{'symbol': 'service'}],
                    'relocations': [{'address': 0x9000}, {'address': 0x9002},
                                    {'address': 0x9004}]}

            def read(self, address, size, executable=False):
                if address == 0xA000:
                    raise recomp.RecompError('not file-backed')
                return bytes.fromhex('01000014c0035fd6' if size == 8 else 'c0035fd6')

        report = recomp.scan(ScanImage())
        self.assertEqual(report['summary']['symbol_status_counts'], {'blocked': 4})
        self.assertEqual(report['summary']['range_status_counts'], {'blocked': 3})
        blockers = {b['kind']: b for b in report['blocker_summary']}
        self.assertEqual(set(blockers), {'range', 'code_relocation', 'unsupported_instruction'})
        self.assertEqual(blockers['unsupported_instruction']['count'], 1)
        self.assertEqual(blockers['unsupported_instruction']['function_ranges'], 1)
        self.assertEqual(blockers['code_relocation']['count'], 2)
        self.assertEqual(blockers['code_relocation']['examples'],
                         [{'address': 0x9000}, {'address': 0x9002}])
        self.assertEqual(report['imports'], [{'symbol': 'service', 'status': 'unresolved'}])

    def test_repeated_blockers_have_bounded_examples_and_complete_counts(self):
        report = recomp.scan_body(bytes.fromhex('01000014') * 20 + bytes.fromhex('c0035fd6'), 0)
        blocker, = report['blockers']
        self.assertEqual(blocker['count'], 20)
        self.assertEqual(len(blocker['examples']), 3)


if __name__ == '__main__':
    unittest.main()
