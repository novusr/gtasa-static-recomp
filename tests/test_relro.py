"""Synthetic ELF RELRO ranges, transactions and checked-memory permissions."""
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from test_image import ROOT, symbol_fixture


def fixture(ranges=((0x9010, 16),), flags=6, targets=(0x9000, 0x9010)):
    data = symbol_fixture(relocations=[(target, 1027, 0, 3, 2) for target in targets])
    struct.pack_into('<I', data, 124, flags)
    struct.pack_into('<H', data, 56, 2 + len(ranges))
    for i, (address, size) in enumerate(ranges):
        struct.pack_into('<IIQQQQQQ', data, 176 + i * 56, 0x6474e552, 4,
                         0x300 + address - 0x9000, address, 0, size, size, 1)
    return data


class RelroTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.runner = cls.directory / 'relro-probe'
        subprocess.run(['c++', '-std=c++11', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
                        '-I', str(ROOT / 'include'), str(ROOT / 'src/runtime.cpp'),
                        str(ROOT / 'src/elf_image.cpp'),
                        str(ROOT / 'src/aps2_rela.cpp'), str(ROOT / 'src/relr.cpp'), str(ROOT / 'tests/relro_probe.cpp'),
                        '-lcrypto', '-o', str(cls.runner)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_probe(self, data, page=16, bias=0, mode='after', load_error=None):
        path = self.directory / 'fixture.elf'
        path.write_bytes(data)
        result = subprocess.run([str(self.runner), str(path), hashlib.sha256(data).hexdigest(),
                                 str(bias), str(page), mode], capture_output=True, text=True)
        if load_error:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(load_error, result.stderr)
        else:
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_absent_valid_multiple_bias_and_order(self):
        for ranges in ((), ((0x9010, 16),), ((0x9000, 8), (0x9020, 8))):
            for bias in (0, 0x100000000, 0xffffffffffff0000):
                for mode in ('before', 'after'):
                    with self.subTest(ranges=ranges, bias=bias, mode=mode):
                        self.run_probe(fixture(ranges), bias=bias, mode=mode)

    def test_no_relro_does_not_require_page_aligned_bias(self):
        self.run_probe(fixture(ranges=(), targets=()), bias=1)

    def test_rounding_unaligned_and_exact_mapping_boundaries(self):
        for address, size in ((0x9001, 1), (0x9013, 9), (0x9000, 64), (0x903f, 1)):
            for page in (1, 8, 16, 64, 4096, 16384):
                with self.subTest(address=address, size=size, page=page):
                    data = fixture(((address, size),))
                    if page == 16384:
                        struct.pack_into('<Q', data, 80, 0x4000)
                    self.run_probe(data, page=page)
        # A non-page-aligned original PT_LOAD remains exact; no padding is mapped.
        data = fixture(((0x9003, 5),), targets=())
        struct.pack_into('<Q', data, 136, 0x9003)
        struct.pack_into('<Q', data, 128, 0x303)
        struct.pack_into('<QQ', data, 152, 61, 61)
        self.run_probe(data)

    def test_multiple_loads_and_bss_only_relro(self):
        data = fixture(((0x9000, 8), (0x9020, 8)))
        struct.pack_into('<QQ', data, 184, 0x200, 0x8000)
        for mode in ('before', 'after'):
            self.run_probe(data, mode=mode)
        data = fixture(((0x9030, 8),))
        struct.pack_into('<Q', data, 152, 32)
        struct.pack_into('<Q', data, 208, 0)
        for mode in ('before', 'after'):
            self.run_probe(data, mode=mode)

    def test_write_only_and_neighbor_permission_preservation(self):
        for flags in (0, 1, 2, 3, 4, 5, 6, 7):
            for mode in ('before', 'after'):
                with self.subTest(flags=flags, mode=mode):
                    self.run_probe(fixture(flags=flags, targets=()), mode=mode)
        # Writable-only relocation target: seal before or after a supported fixup.
        for mode in ('before', 'after'):
            self.run_probe(fixture(flags=2, targets=(0x9010,)), mode=mode)

    def test_new_relocation_outside_relro_and_completed_phase_noop(self):
        for targets in ((0x9000,), (0x9010,), (0x9000, 0x9010)):
            for mode in ('before', 'after'):
                self.run_probe(fixture(targets=targets), mode=mode)
        # Internal-symbol phase uses exactly the same permission checks.
        data = fixture(targets=(0x9000, 0x9010))
        struct.pack_into('<Q', data, 0xc20, (1 << 32) | 257)
        for mode in ('before', 'after', 'relative-first'):
            self.run_probe(data, mode=mode)
        # IFUNC remains unresolved; sealing must never invoke its resolver.
        struct.pack_into('<B', data, 0x61c, 10)
        for mode in ('before', 'after', 'relative-first'):
            self.run_probe(data, mode=mode)

    def test_validation_failure_keeps_all_state_and_permissions(self):
        for page, bias in ((0, 0), (3, 0), (16, 1)):
            self.run_probe(fixture(), page=page, bias=bias, mode='failure')
        # First range is valid, second rounds onto its page: no partial first seal.
        self.run_probe(fixture(((0x9000, 1), (0x9008, 1))), mode='failure')
        # Raw range lies in LOAD 2, but page rounding touches LOAD 1.
        self.run_probe(fixture(), page=16384, mode='failure')

    def test_allocation_failure_is_atomic_and_retryable(self):
        self.run_probe(fixture(((0x9000, 8), (0x9020, 8))), mode='oom')

    def test_reject_raw_overlap_empty_unmapped_and_malformed_file_ranges(self):
        self.run_probe(fixture(((0x9000, 16), (0x9008, 16))), load_error='overlapping PT_GNU_RELRO')
        self.run_probe(fixture(((0x9010, 0),)), load_error='empty PT_GNU_RELRO')
        for address, size in ((0x8fff, 1), (0x903f, 2), (0x9040, 1)):
            self.run_probe(fixture(((address, size),)), load_error='must fit one PT_LOAD')
        data = fixture()
        struct.pack_into('<Q', data, 184, 0x310 + 1)
        self.run_probe(data, load_error='file range disagrees')
        data = fixture()
        struct.pack_into('<Q', data, 208, 17)
        self.run_probe(data, load_error='filesz exceeds memsz')
        data = fixture()
        struct.pack_into('<Q', data, 184, len(data))
        self.run_probe(data, load_error='truncated ELF range')
        data = fixture()
        struct.pack_into('<I', data, 180, 8)
        self.run_probe(data, load_error='unsupported ELF segment flags')

    def test_alignment_and_overflow_rejections(self):
        for alignment in (0, 1, 16):
            data = fixture()
            struct.pack_into('<Q', data, 224, alignment)
            self.run_probe(data)
        for alignment in (3, 4096):
            data = fixture()
            struct.pack_into('<Q', data, 224, alignment)
            self.run_probe(data, load_error='invalid ELF segment alignment')
        data = fixture()
        struct.pack_into('<Q', data, 192, (1 << 64) - 8)
        self.run_probe(data, load_error='overflow')
        # End rounding overflows only in sealing, after a valid high mapping load.
        data = fixture(((0x9030, 8),), targets=())
        self.run_probe(data, page=65536, bias=(1 << 64) - 65536, mode='failure')
        # RELRO bias addition can overflow even when every PT_LOAD fits.
        data = fixture()
        struct.pack_into('<Q', data, 192, (1 << 64) - 0x1000)
        self.run_probe(data, bias=0x100000000, load_error='overflow')
