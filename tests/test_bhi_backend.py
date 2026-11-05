"""B.HI semantics against independent state expectations and the ARM64 oracle."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'tools'))
import recomp
from verify_integer import compare, compile_runner, vectors
from test_count_members_backend import flags_expected
from test_recomp import symbol_fixture

RET = 0xD65F03C0
BASE = 4096
MASK = (1 << 64) - 1


def words(*values):
    return b''.join(struct.pack('<I', value) for value in values)


def bhi(displacement):
    """Displacement is in instructions, including the signed imm19 boundary."""
    return 0x54000008 | (displacement & 0x7FFFF) << 5


def corpus():
    cases = []

    def add(code, **kwargs):
        name = f'bhi_case_{len(cases)}'
        cases.append(dict(symbol=name, output=name, address=0x8000, code=code,
                          return_sentinel=0xFFFF0000, **kwargs))

    # Initial flags include every NZCV combination. HI requires C set and Z clear; N and V have no effect.
    def prepare_flags(trial, registers):
        return BASE, bytes([trial % 16]), list(registers)

    def expected_flags_branch(registers, memory):
        result = list(registers)
        if not (memory[0] & 2 and not memory[0] & 4):
            result[0] = 7
        return result, memory

    add(words(bhi(2), 0x528000E0, RET), memory=prepare_flags,
        expected_memory=expected_flags_branch)
    # The taken path goes backward to an earlier RET, without creating a cycle.
    add(words(0x14000002, RET, bhi(-1), RET), expected=lambda s: list(s))
    # A diamond uses a conditional target and an unconditional join.
    def expected_diamond(registers, memory):
        result = list(registers)
        result[0] = 9 if memory[0] & 2 and not memory[0] & 4 else 7
        return result, memory
    add(words(bhi(3), 0x528000E0, 0x14000002, 0x52800120, RET),
        memory=prepare_flags, expected_memory=expected_diamond)

    # CMP -> B.HI. Math expectations use unsigned ordering and signed range,
    # not the implementation's flags helper or emitted condition evaluator.
    for width in (32, 64):
        sf = int(width == 64) << 31
        for rn, rm in ((1, 2), (1, 1), (0, 2), (1, 0), (31, 2), (1, 31), (31, 31)):
            for shift in (0, width - 1):
                def flag(s, m, f, rn=rn, rm=rm, shift=shift, width=width):
                    return flags_expected(0 if rn == 31 else s[rn],
                                          (0 if rm == 31 else s[rm]) << shift, width)
                def expected(s, rn=rn, rm=rm, shift=shift, width=width):
                    result = list(s)
                    a = 0 if rn == 31 else s[rn] % (1 << width)
                    b = ((0 if rm == 31 else s[rm]) << shift) % (1 << width)
                    if a <= b:
                        result[0] = 7
                    return result
                add(words(sf | 0x6B00001F | rm << 16 | shift << 10 | rn << 5,
                          bhi(2), 0x528000E0, RET), expected=expected, expected_flags=flag)
        # Immediate CMP treats register 31 as SP, unlike the shifted form's ZR.
        for rn in (1, 31):
            for immediate, shift in ((0, 0), (1, 0), (7, 0), (4095, 12)):
                value = immediate << shift
                def expected(s, rn=rn, value=value, width=width):
                    result = list(s)
                    if s[rn] % (1 << width) <= value:
                        result[0] = 7
                    return result
                add(words(sf | 0x7100001F | int(shift == 12) << 22 | immediate << 10 | rn << 5,
                          bhi(2), 0x528000E0, RET), expected=expected,
                    expected_flags=lambda s, m, f, rn=rn, value=value, width=width:
                        flags_expected(s[rn], value, width))

    # Conditional memory writes through X0 or SP, including source/destination
    # aliases and ZR stores. Every byte outside the selected store is preserved.
    for rn, rt in ((0, 2), (31, 2), (0, 0), (0, 31)):
        def prepare(trial, registers, rn=rn):
            registers = list(registers)
            registers[rn] = BASE + 16 + trial % 4
            memory = bytearray((i * 13 + trial) % 256 for i in range(256))
            memory[0] = trial % 16
            return BASE, bytes(memory), registers
        def expected(s, memory, rn=rn, rt=rt):
            result = bytearray(memory)
            if not (memory[0] & 2 and not memory[0] & 4):
                at = s[rn] - BASE + 60
                result[at:at + 4] = (0 if rt == 31 else s[rt] % (1 << 32)).to_bytes(4, 'little')
            return list(s), result
        add(words(bhi(2), 0xB9000000 | 15 << 10 | rn << 5 | rt, RET),
            memory=prepare, expected_memory=expected)
    return cases


def input_vectors():
    """Unsigned/signed cut points, compare threshold 7 and all initial flags."""
    result = vectors()
    edges = (0, 1, 6, 7, 8, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
             0x7FFFFFFFFFFFFFFF, 0x8000000000000000, MASK)
    for left in edges:
        for right in edges:
            state = [((0xA5A50000 + i) << 32) | (left & 0xFFFFFFFF) for i in range(32)]
            state[1], state[2], state[31] = left, right, left
            result.append(state)
    return result


class BhiSemanticTests(unittest.TestCase):
    def test_independent_state_and_unicorn(self):
        cases = corpus()
        with tempfile.TemporaryDirectory(prefix='recomp-bhi-') as temp:
            self.assertEqual(compare(cases, input_vectors(), temp), len(cases) * len(input_vectors()))

    def test_scan_and_lift_agree(self):
        for case in corpus():
            with self.subTest(symbol=case['symbol']):
                recomp.lift_body(case['code'], case['address'])
                self.assertEqual(recomp.scan_body(case['code'], case['address'])['blockers'], [])

    def test_untaken_memory_path_has_no_access_and_taken_fault_is_atomic(self):
        cases = [dict(symbol=f'bhi_fault_{i}', output=f'bhi_fault_{i}', address=0x8000,
                      code=words(bhi(2), word, RET))
                 for i, word in enumerate((0xB9400001, 0xB9000001))]
        source = r'''#include "lifted.h"
#include <stdexcept>
int main() {
    typedef void (*Function)(recomp::State&, recomp::Memory&);
    const Function functions[] = {CALLS};
    for (Function function : functions) {
        for (uint32_t pattern = 0; pattern < 16; ++pattern) {
            const uint32_t flags = pattern << 28;
            recomp::Memory memory(4096, 8);
            for (unsigned i = 0; i < 8; ++i) memory.store8(4096 + i, i + 17);
            recomp::State state = {};
            for (unsigned i = 0; i < 31; ++i) state.x[i] = UINT64_MAX - i;
            for (unsigned i = 0; i < 32; ++i) state.s[i] = 0xA5A50000 + i;
            state.x[0] = 4102; state.sp = 8192; state.nzcv = flags;
            const recomp::State before = state;
            bool failed = false;
            try { function(state, memory); }
            catch (const std::out_of_range&) { failed = true; }
            const bool should_access = !(pattern & 2) || (pattern & 4);
            if (failed != should_access || state.nzcv != flags || state.sp != before.sp) return 1;
            for (unsigned i = 0; i < 31; ++i) if (state.x[i] != before.x[i]) return 2;
            for (unsigned i = 0; i < 32; ++i) if (state.s[i] != before.s[i]) return 3;
            for (unsigned i = 0; i < 8; ++i) if (memory.load8(4096 + i) != i + 17) return 4;
        }
    }
}
'''
        with tempfile.TemporaryDirectory(prefix='recomp-bhi-fault-') as temp:
            executable = compile_runner(cases, temp, source, 'synthetic-bhi-faults')
            subprocess.run([str(executable)], check=True)

    def test_signed_displacement_extremes_and_wrapping(self):
        for immediate in (-(1 << 18), -1, 0, 1, (1 << 18) - 1):
            for address in (0, 0x8000, MASK - 3):
                instruction = SimpleNamespace(mnemonic='b.hi', size=4, address=address,
                                              bytes=words(bhi(immediate)))
                self.assertEqual(recomp.get_branch_target(instruction),
                                 (address + 4 * immediate) % (1 << 64))


class BhiRejectionTests(unittest.TestCase):
    def rejected(self, code):
        with self.assertRaises(recomp.RecompError):
            recomp.lift_body(code, 0x8000)
        self.assertTrue(recomp.scan_body(code, 0x8000)['blockers'])

    def test_other_conditions_and_reserved_encodings(self):
        for condition in range(16):
            if condition not in (1, 8):
                with self.subTest(condition=condition):
                    self.rejected(words(0x54000040 | condition, RET, RET))
        # Bit 4 selects BC.cond on newer ISAs; bit 24 is fixed zero for B.cond.
        for word in (bhi(2) ^ 1, bhi(2) | 0x10, bhi(2) | (1 << 24), bhi(2) ^ (1 << 31)):
            with self.subTest(word=hex(word)):
                self.rejected(words(word, RET, RET))
                # Validate bytes even if disassembler text is forged as B.HI.
                instruction = SimpleNamespace(mnemonic='b.hi', size=4, address=0x8000,
                                              bytes=words(word))
                with self.assertRaises(recomp.RecompError):
                    recomp.get_branch_target(instruction)

    def test_encoding_fields_are_checked_independently_of_mnemonic(self):
        # Every fixed top-byte bit, BC discriminator and condition field is
        # checked from bytes, even when a decoder claims the mnemonic is HI.
        invalid = [bhi(2) ^ (1 << bit) for bit in range(24, 32)]
        invalid += [bhi(2) | 0x10]
        invalid += [(bhi(2) & ~15) | condition for condition in range(16) if condition != 8]
        for word in invalid:
            instruction = SimpleNamespace(mnemonic='b.hi', size=4, address=0x8000,
                                          bytes=words(word))
            with self.subTest(word=hex(word)), self.assertRaises(recomp.RecompError):
                recomp.get_branch_target(instruction)
        for size in (0, 2, 8):
            instruction = SimpleNamespace(mnemonic='b.hi', size=size, address=0x8000,
                                          bytes=words(bhi(2)))
            with self.subTest(size=size), self.assertRaises(recomp.RecompError):
                recomp.get_branch_target(instruction)

    def test_cfg_bounds_cycles_dead_code_and_missing_return(self):
        for body in ((bhi(2), RET), (bhi(-1), RET),
                     (bhi(-(1 << 18)), RET), (bhi((1 << 18) - 1), RET),
                     (bhi(0), RET), (bhi(2), RET, 0x17FFFFFE),
                     (RET, bhi(1), RET), (bhi(-1),),
                     (bhi(1), 0xD503201F)):
            with self.subTest(body=body):
                self.rejected(words(*body))

    def test_target_must_be_decoded_boundary(self):
        branch = SimpleNamespace(mnemonic='b.hi', address=0x8000, bytes=words(bhi(1)), size=4)
        ret = SimpleNamespace(mnemonic='ret', address=0x8008, bytes=words(RET), size=4)
        with self.assertRaisesRegex(recomp.RecompError, 'instruction boundary'):
            recomp.analyze_cfg([branch, ret], 0x8000, 12)

    def test_calls_and_other_instruction_forms_still_reject(self):
        for word in (0x94000001, 0xD63F0000, 0xD61F0000, 0xD65F0000,
                     0x36000040, 0xEB22403F, 0xEB020020):
            self.rejected(words(word, RET))

    def test_generation_failure_preserves_prior_and_absent_output(self):
        with tempfile.TemporaryDirectory(prefix='recomp-bhi-publication-') as temp:
            root = Path(temp)
            binary, config, output = root / 'guest.so', root / 'config.json', root / 'output'
            def configure(data):
                binary.write_bytes(data)
                config.write_text(json.dumps(dict(input=str(binary), sha256=hashlib.sha256(data).hexdigest(),
                    guest='aarch64-linux-android', host='x86_64-linux',
                    functions=[dict(symbol='leaf', output='leaf')])))
            configure(symbol_fixture())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(recomp.main(['--config', str(config), 'lift', '--output', str(output)]), 0)
            before = {p.name: p.read_bytes() for p in output.iterdir()}
            for word in (bhi(1), bhi(-1), bhi(0), 0x5400002E, bhi(1) | 0x10):
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
