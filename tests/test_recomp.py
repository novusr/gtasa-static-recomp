"""Synthetic inputs only: these tests need neither Ghidra nor game files."""

import importlib.util
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


if __name__ == '__main__':
    unittest.main()
