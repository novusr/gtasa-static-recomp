"""Independent arithmetic expectations, ARM64 oracle and native C++11 execution."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'tools'))
import recomp
from verify_integer import compare, compile_runner, vectors
from test_recomp import symbol_fixture

MASK = (1 << 64) - 1
BASE = 4096


def words(*values):
    return b''.join(struct.pack('<I', value) for value in values)


def flags_expected(a, b, width):
    """Mathematical unsigned borrow and signed result range, not bitwise formulas."""
    modulus = 1 << width
    a, b = a % modulus, b % modulus
    signed = lambda v: v - modulus if v >= modulus // 2 else v
    difference = signed(a) - signed(b)
    return ((int((a - b) % modulus >= modulus // 2) << 31)
            | (int(a == b) << 30) | (int(a >= b) << 29)
            | (int(not -modulus // 2 <= difference < modulus // 2) << 28))


def condition_expected(flags, condition):
    n, z, c, v = (bool(flags & (1 << bit)) for bit in (31, 30, 29, 28))
    # Architectural truth table, separately enumerating every condition.
    return [z, not z, c, not c, n, not n, v, not v, c and not z,
            not c or z, n == v, n != v, not z and n == v,
            z or n != v][condition]


def signed_load(width, rt, rn, offset, scaled):
    opc = 2 if width == 64 else 3
    if scaled:
        return 0x79000000 | opc << 22 | (offset // 2) << 10 | rn << 5 | rt
    return 0x78000000 | opc << 22 | (offset & 511) << 12 | rn << 5 | rt


def cinc(width, rd, rn, condition):
    return ((width == 64) << 31 | 0x1A800400 | rn << 16 |
            (condition ^ 1) << 12 | rn << 5 | rd)


def corpus():
    cases = []

    def add(code, **kwargs):
        index = len(cases)
        cases.append({'symbol': f'new_semantics_{index}', 'output': f'case_{index}',
                      'address': 0x8000, 'code': code + words(0xD65F03C0), **kwargs})

    for width in (32, 64):
        for scaled, offsets in [(True, (0, 2, 8190)), (False, (-256, -1, 0, 1, 255))]:
            for offset in offsets:
                for rt, rn in ((0, 1), (1, 1), (31, 1), (0, 31)):
                    def prepare(trial, registers, rn=rn, offset=offset):
                        registers = list(registers)
                        at = 64 + trial % 2
                        registers[rn] = (BASE + at - offset) & MASK
                        rng = random.Random(0x51A0 + trial)
                        memory = bytearray(rng.randbytes(256))
                        edges = (0, 1, 0x7FFF, 0x8000, 0xFFFF, 0x8001)
                        value = edges[trial % len(edges)] if trial < 96 else rng.randrange(65536)
                        memory[at:at + 2] = value.to_bytes(2, 'little')
                        return BASE, bytes(memory), registers

                    def expected(registers, memory, rt=rt, offset=offset, rn=rn, width=width):
                        state = list(registers)
                        at = ((registers[rn] + offset) & MASK) - BASE
                        value = int.from_bytes(memory[at:at + 2], 'little', signed=True)
                        if rt != 31:
                            state[rt] = value % (1 << width)
                        return state, memory
                    add(words(signed_load(width, rt, rn, offset, scaled)),
                        memory=prepare, expected_memory=expected)

        sf = (width == 64) << 31
        for rn in (1, 31):
            for shift in (0, 12):
                for immediate in (0, 1, 4095):
                    value = immediate << shift
                    add(words(sf | 0x7100001F | (shift == 12) << 22 | immediate << 10 | rn << 5),
                        expected=lambda s: list(s),
                        expected_flags=lambda s, m, f, rn=rn, value=value, width=width:
                            flags_expected(s[rn], value, width))
        for rn, rm in ((1, 2), (1, 1), (31, 2), (1, 31), (31, 31)):
            for shift in (0, 1, width - 1):
                add(words(sf | 0x6B00001F | rm << 16 | shift << 10 | rn << 5),
                    expected=lambda s: list(s),
                    expected_flags=lambda s, m, f, rn=rn, rm=rm, shift=shift, width=width:
                        flags_expected(0 if rn == 31 else s[rn],
                                       (0 if rm == 31 else s[rm]) << shift, width))
        for condition in range(14):
            for rd, rn in ((0, 1), (0, 0), (31, 1)):
                # compare() cycles all 16 initial NZCV states; expectations use trial flags.
                def expected(registers, memory, rd=rd, rn=rn, width=width, condition=condition):
                    # Initial flags are supplied via the trial-index marker in memory below.
                    state = list(registers)
                    if rd != 31:
                        state[rd] = (registers[rn] + condition_expected(memory[0] << 28, condition)) % (1 << width)
                    return state, memory
                def prepare(trial, registers):
                    return BASE, bytes([trial % 16]), list(registers)
                add(words(cinc(width, rd, rn, condition)), memory=prepare, expected_memory=expected)

        # CMP -> CINC aliasing, with both width-specific overflow and flag consumption.
        for condition in (0, 3, 10, 13):
            def expected(s, condition=condition, width=width):
                result = list(s)
                flags = flags_expected(s[0], s[1], width)
                result[0] = (s[0] + condition_expected(flags, condition)) % (1 << width)
                return result
            add(words(sf | 0x6B01001F, cinc(width, 0, 0, condition)), expected=expected,
                expected_flags=lambda s, m, f, width=width: flags_expected(s[0], s[1], width))

    for bit in range(64):
        for rt in ((1, 31) if bit in (0, 31, 32, 63) else (1,)):
            branch = 0x37000000 | (bit >> 5) << 31 | (bit & 31) << 19 | 2 << 5 | rt
            def expected(s, rt=rt, bit=bit):
                state = list(s)
                if rt == 31 or not (s[rt] & (1 << bit)):
                    state[0] = 7
                return state
            add(words(branch, 0x528000E0), expected=expected)
    # Backward edge with an acyclic CFG: B -> TBNZ -> earlier RET or final RET.
    add(words(0x14000002, 0xD65F03C0, 0x3707FFE1), expected=lambda s: list(s))

    # ORR-immediate MOV aliases needed by original small constant returns.
    # Replicated/rotated elements exercise DecodeBitMasks beyond those constants.
    for width in (32, 64):
        sf = (width == 64) << 31
        for size in (2, 4, 8, 16, 32, 64):
            if size > width:
                continue
            for run in sorted({1, size // 2, size - 1}):
                for rotation in (0, 1, size - 1):
                    n = int(size == 64)
                    imms = ((~(size * 2 - 1)) & 63) | (run - 1)
                    pattern = [int((position + rotation) % size < run) for position in range(width)]
                    value = sum(v << bit for bit, v in enumerate(pattern))
                    for rd in (0, 31):
                        def expected(s, rd=rd, value=value):
                            state = list(s)
                            state[rd] = value
                            return state
                        add(words(sf | 0x320003E0 | n << 22 | rotation << 16 | imms << 10 | rd), expected=expected)
    return cases


class BackendSemanticTests(unittest.TestCase):
    def test_explicit_states_and_unicorn(self):
        cases = corpus()
        with tempfile.TemporaryDirectory(prefix='recomp-flags-') as temp:
            self.assertEqual(compare(cases, vectors(), temp), len(cases) * len(vectors()))

    def test_supported_forms_pass_scan_and_lift(self):
        for case in corpus():
            with self.subTest(case=case['symbol']):
                recomp.lift_body(case['code'], case['address'])
                self.assertEqual(recomp.scan_body(case['code'], case['address'])['blockers'], [])

    def test_signed_load_fault_preserves_registers_flags_and_memory(self):
        cases = []
        for width in (32, 64):
            for scaled in (False, True):
                for rt in (0, 1, 31):
                    index = len(cases)
                    cases.append({'symbol': f'fault_{index}', 'output': f'fault_{index}', 'address': 0x8000,
                                  'code': words(signed_load(width, rt, 1, 0, scaled), 0xD65F03C0)})
        source = r'''#include "lifted.h"
#include <stdexcept>
int main() {
    typedef void (*Function)(recomp::State&, recomp::Memory&);
    const Function functions[] = {CALLS};
    for (Function function : functions) {
        for (uint64_t address : {UINT64_C(4095), UINT64_C(4127), UINT64_MAX}) {
            recomp::Memory memory(4096, 32);
            recomp::State state = {};
            for (unsigned i = 0; i < 31; ++i) state.x[i] = UINT64_MAX - i;
            for (unsigned i = 0; i < 32; ++i) state.s[i] = 0xA5A50000 + i;
            state.sp = 8192; state.x[1] = address; state.nzcv = 0x90000000;
            const recomp::State before = state;
            bool failed = false;
            try { function(state, memory); }
            catch (const std::out_of_range&) { failed = true; }
            if (!failed || state.sp != before.sp || state.nzcv != before.nzcv) return 1;
            for (unsigned i = 0; i < 31; ++i) if (state.x[i] != before.x[i]) return 2;
            for (unsigned i = 0; i < 32; ++i) {
                if (state.s[i] != before.s[i] || memory.load8(4096 + i)) return 3;
            }
        }
    }
}
'''
        with tempfile.TemporaryDirectory(prefix='recomp-signed-fault-') as temp:
            executable = compile_runner(cases, temp, source, 'synthetic-faults')
            subprocess.run([str(executable)], check=True)


class BackendRejectionTests(unittest.TestCase):
    def test_unsupported_forms_remain_rejected(self):
        rejected = {
            'LDRSH post-index': 0x78C02420, 'LDRSH pre-index': 0x78802C20,
            'LDRSH register': 0x78A26820, 'LDTRSH': 0x78800820,
            'LDRSB': 0x39800020, 'LDURSB': 0x38800020, 'LDRSW': 0xB9800020,
            'CMP LSR': 0xEB42003F, 'CMP ASR': 0x6B82003F,
            'CMP extended': 0xEB22403F, 'CMP W shift 32': 0x6B02803F,
            'SUBS result': 0xEB020020, 'CMN': 0xAB02003F,
            'CSINC unequal': 0x9A820420, 'CSET': 0x1A9F07E0,
            'CSINC AL': 0x9A81E420, 'CSINV': 0xDA810020,
            'B.EQ outside NE subset': 0x54000020, 'TBZ': 0x36000020,
            'BL': 0x94000001, 'BLR': 0xD63F0000,
            'reserved MOV N for W': 0x324003E0,
            'reserved MOV all ones': 0xB240FFE0,
            'logical ORR not MOV': 0xB2400020,
            'AND logical immediate': 0x92400020,
        }
        for name, word in rejected.items():
            code = words(word, 0xD65F03C0)
            with self.subTest(name=name):
                with self.assertRaises(recomp.RecompError):
                    recomp.lift_body(code, 0x8000)
                self.assertTrue(recomp.scan_body(code, 0x8000)['blockers'])

    def test_tbnz_bounds_cycles_fallthrough_and_dead_code(self):
        for body in [(0x37000040, 0xD65F03C0), (0x3707FFE0, 0xD65F03C0),
                     (0x37000000, 0xD65F03C0), (0x3707FFE0,),
                     (0xD65F03C0, 0x37000020, 0xD65F03C0)]:
            with self.subTest(body=body):
                with self.assertRaises(recomp.RecompError):
                    recomp.lift_body(words(*body), 0x8000)
                self.assertTrue(recomp.scan_body(words(*body), 0x8000)['blockers'])

    def test_failed_generation_preserves_previous_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary, config, output = root / 'guest.so', root / 'config.json', root / 'generated'
            def configure(data):
                binary.write_bytes(data)
                config.write_text(json.dumps({'input': str(binary), 'sha256': hashlib.sha256(data).hexdigest(),
                    'guest': 'aarch64-linux-android', 'host': 'x86_64-linux',
                    'functions': [{'symbol': 'leaf', 'output': 'leaf'}]}))
            configure(symbol_fixture())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(recomp.main(['--config', str(config), 'lift', '--output', str(output)]), 0)
            before = {p.name: p.read_bytes() for p in output.iterdir()}
            for word in (0x78C02420, 0xEB22403F, 0x9A820420, 0x37000040, 0xB240FFE0):
                data = bytearray(symbol_fixture())
                data[256:260] = words(word)
                configure(data)
                for destination in (output, root / 'absent'):
                    with contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(recomp.main(['--config', str(config), 'lift', '--output', str(destination)]), 1)
                self.assertFalse((root / 'absent').exists())
                self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, before)


if __name__ == '__main__':
    unittest.main()
