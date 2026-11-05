"""Synthetic integer semantics: native AOT C++11, explicit expectations and ARM64."""

from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'tools'))
from recomp import RecompError, lift_body, scan_body
from verify_integer import compare, vectors

RET = bytes.fromhex('c0035fd6')


def leaf(word):
    return struct.pack('<I', word) + RET


def corpus():
    cases = []

    def add(word, width, rd, value, sp=False):
        mask = (1 << width) - 1

        def expected(state):
            state = list(state)
            result = value(state) & mask
            if rd != 31 or sp:
                state[rd] = result
            return state

        cases.append({'symbol': f'synthetic_{len(cases)}', 'output': f'case_{len(cases)}',
                      'address': 0x8000, 'code': leaf(word), 'expected': expected})

    for width in (32, 64):
        sf = (width == 64) << 31
        # ORR MOV: register 31 is ZR, including discarded destination writes.
        for rd, rm in [(0, 1), (1, 1), (0, 31), (31, 0), (29, 30)]:
            add(sf | 0x2A0003E0 | rm << 16 | rd, width, rd,
                lambda s, rm=rm: 0 if rm == 31 else s[rm])
        # Both halves/all four halfwords, zero/all-one/complement constants.
        for inverted in (False, True):
            for hw in range(width // 16):
                for imm in (0, 0x1234, 0xFFFF):
                    value = imm << (hw * 16)
                    if inverted:
                        value = ~value
                    base = 0x12800000 if inverted else 0x52800000
                    add(sf | base | hw << 21 | imm << 5, width, 0, lambda s, v=value: v)
            add(sf | (0x12800000 if inverted else 0x52800000) | 31, width, 31,
                lambda s: 0)
        # Immediate arithmetic, SP/WSP as both source and destination, and aliases.
        for subtract in (False, True):
            for shift in (0, 12):
                for imm in (0, 1, 4095):
                    for rd, rn in [(0, 1), (0, 0), (0, 31), (31, 0), (31, 31)]:
                        offset = imm << shift
                        # Expected result is calculated independently of the decoder.
                        add(sf | 0x11000000 | subtract << 30 | (shift == 12) << 22 |
                            imm << 10 | rn << 5 | rd, width, rd,
                            lambda s, rn=rn, off=offset, sub=subtract:
                                s[rn] - off if sub else s[rn] + off, sp=True)
            # Register arithmetic: Rn/Rm/Rd == 31 is always ZR, never SP.
            for shift in (0, 1, width - 1):
                for rd, rn, rm in [(0, 1, 2), (0, 0, 0), (0, 31, 1),
                                   (0, 1, 31), (31, 0, 1), (0, 31, 31)]:
                    def value(s, rn=rn, rm=rm, shift=shift, subtract=subtract):
                        a = 0 if rn == 31 else s[rn]
                        b = 0 if rm == 31 else s[rm]
                        return a - (b << shift) if subtract else a + (b << shift)
                    add(sf | 0x0B000000 | subtract << 30 | rm << 16 | shift << 10 |
                        rn << 5 | rd, width, rd, value)
    # Sequential aliasing, SP copies and W writes that must clear preexisting high bits.
    sequences = [
        ([0x910003E0, 0x91000400, 0x9100001F], lambda s: [s[31] + 1] + s[1:31] + [s[31] + 1]),
        ([0x2A0103E0, 0x91000400], lambda s: [(s[1] & 0xFFFFFFFF) + 1] + s[1:]),
    ]
    for words, expected in sequences:
        def bounded(s, expected=expected):
            return [v & ((1 << 64) - 1) for v in expected(s)]
        cases.append({'symbol': f'sequence_{len(cases)}', 'output': f'case_{len(cases)}',
                      'address': 0x8000, 'code': b''.join(struct.pack('<I', w) for w in words) + RET,
                      'expected': bounded})
    return cases


class IntegerTests(unittest.TestCase):
    def test_native_semantics_against_explicit_expectations_and_unicorn(self):
        cases = corpus()
        with tempfile.TemporaryDirectory(prefix='recomp-integer-test-') as temp:
            calls = compare(cases, vectors(), temp)
        self.assertEqual(calls, len(cases) * len(vectors()))

    def test_supported_forms_scan_and_lift_agree(self):
        for case in corpus():
            with self.subTest(case=case['symbol']):
                lift_body(case['code'], case['address'])
                self.assertEqual(scan_body(case['code'], case['address'])['blockers'], [])

    def test_unsupported_forms_are_rejected_by_both_scan_and_lift(self):
        words = {
            'ADDS immediate': 0xB1000420,
            'SUBS register': 0xEB020020,
            'CMP extended register': 0xEB22403F,
            'ADD LSR': 0x8B420020,
            'SUB ASR': 0xCB820020,
            'ADD extended UXTW': 0x8B224020,
            'SUB extended SXTW SP': 0xCB22C3E0,
            'MOVK': 0xF2800020,
            'AND bitmask immediate': 0x92009FE0,
            'MOV vector': 0x4EA11C20,
            'ORR shifted, not MOV copy': 0xAA0107E0,
            'reserved W shift 32': 0x0B028020,
            'reserved W MOVZ hw2': 0x52C00020,
            'reserved shift type': 0x8BC20020,
        }
        for name, word in words.items():
            with self.subTest(form=name):
                with self.assertRaises(RecompError):
                    lift_body(leaf(word), 0x8000)
                self.assertTrue(scan_body(leaf(word), 0x8000)['blockers'])


if __name__ == '__main__':
    unittest.main()
