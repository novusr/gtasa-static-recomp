"""Synthetic analysis fixtures; these do not execute or claim support for BL."""

from copy import deepcopy
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'tools'))
from audit_direct_calls import audit, direct_target
from recomp import BACKEND, RecompError
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN


def words(*values):
    return b''.join(struct.pack('<I', v) for v in values)


class Fixture:
    def __init__(self, bodies):
        self.bodies = bodies
        self.elf = self

    def get_section_by_name(self, name):
        return {'sh_addr': 0x9000, 'sh_size': 0x100} if name == '.plt' else None

    def inventory(self):
        return {'sha256': 'fixture', 'relocations': [], 'functions': [
            {'symbol': 'fn_' + hex(a), 'address': a, 'size': len(b)}
            for a, b in self.bodies.items()]}

    def read(self, address, size, executable=False):
        assert executable and size == len(self.bodies[address])
        return self.bodies[address]

    def scan(self):
        return {'input_sha256': 'fixture', 'backend': BACKEND,
                'semantic_verification': 'not_verified',
                'functions': self.inventory()['functions']}


class DirectCallAuditTests(unittest.TestCase):
    def result(self, bodies):
        image = Fixture(bodies)
        return audit(image, image.scan())

    def test_signed_bl_targets_and_guest_return_address(self):
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        for word, expected in [(0x94000002, 0x8008), (0x97FFFFFF, 0x7FFC),
                               (0x95FFFFFF, 0x8007FFC), (0x96000000, (0x8000 - 0x8000000) % (1 << 64))]:
            insn = next(decoder.disasm(words(word), 0x8000))
            self.assertEqual(direct_target(insn), expected)
        with self.assertRaises(RecompError):
            direct_target(next(decoder.disasm(words(0x14000002), 0x8000)))

    def test_explicit_internal_closure_is_only_feasibility(self):
        report = self.result({0x8000: words(0x94000004, 0xD65F03C0),
                              0x8010: words(0xD65F03C0)})
        for profile in report['profiles'].values():
            self.assertEqual(profile['eligible_closures'], 1)
        self.assertEqual(report['semantic_verification'], 'not_verified')
        self.assertEqual(report['candidates'][0]['calls'][0]['return_address'], 0x8004)

    def test_recursion_and_mutual_cycle(self):
        for bodies in [{0x8000: words(0x94000000, 0xD65F03C0)},
                       {0x8000: words(0x94000004, 0xD65F03C0),
                        0x8010: words(0x97FFFFFC, 0xD65F03C0)}]:
            report = self.result(bodies)
            for candidate in report['candidates']:
                self.assertEqual(candidate['optimistic_memory_plus_bl']['failure']['reason'],
                                 'recursive call cycle')

    def test_plt_and_midfunction_targets_do_not_form_closures(self):
        for target, reason in [(0x9000, 'plt_entry_requires_indirect_dispatch'),
                               (0x8014, 'not_a_defined_function_entry')]:
            report = self.result({0x8000: words(0x94000000 | ((target - 0x8000) // 4), 0xD65F03C0),
                                  0x8010: words(0xD503201F, 0xD65F03C0)})
            self.assertEqual(report['candidates'][0]['optimistic_memory_plus_bl']['failure']['reason'], reason)

    def test_indirect_call_in_callee_remains_blocked(self):
        report = self.result({0x8000: words(0x94000004, 0xD65F03C0),
                              0x8010: words(0xD63F0000, 0xD65F03C0)})
        failure = report['candidates'][0]['optimistic_memory_plus_bl']['failure']
        self.assertEqual(failure['function'], 0x8010)
        self.assertEqual(failure['first_blocker']['mnemonic'], 'blr')

    def test_stack_forgiveness_does_not_claim_implementation(self):
        report = self.result({0x8000: words(0xA9BF7BFD, 0x94000007, 0xA8C17BFD, 0xD65F03C0),
                              0x8020: words(0xD65F03C0)})
        candidate = report['candidates'][0]
        self.assertIsNotNone(candidate['current_instructions_plus_bl']['failure'])
        self.assertIsNone(candidate['optimistic_memory_plus_bl']['failure'])
        self.assertIn('NOT implemented support', report['optimistic_screen'])

    def test_cfg_and_decoding_rejections_survive_optimistic_screen(self):
        for body in [words(0x94000004, 0x14000000),
                     words(0x94000004, 0xD503201F),
                     words(0x94000004, 0xD65F03C0, 0xD65F03C0),
                     words(0x94000004, 0)]:
            report = self.result({0x8000: body, 0x8010: words(0xD65F03C0)})
            self.assertEqual(len(report['candidates']), 1)
            self.assertIsNotNone(report['candidates'][0]['optimistic_memory_plus_bl']['failure'])

    def test_scan_identity_backend_and_ranges_required(self):
        image = Fixture({0x8000: words(0xD65F03C0)})
        for field, value in [('input_sha256', 'other'), ('backend', 'other'),
                             ('semantic_verification', 'verified'), ('functions', [])]:
            scan = deepcopy(image.scan())
            scan[field] = value
            with self.assertRaisesRegex(RecompError, 'scan identity'):
                audit(image, scan)


if __name__ == '__main__':
    unittest.main()
