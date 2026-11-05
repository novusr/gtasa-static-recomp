"""Integer memory encoding, native fault safety and differential state/memory tests."""

from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'tools'))
from recomp import RecompError, lift_body, scan_body
from verify_integer import MASK, compare, compile_runner, vectors
from verify_memory import BASE, MEMORY_SIZE, memory_bytes

RET = bytes.fromhex('c0035fd6')


def instruction(size, load, rt, rn, immediate=0):
    return 0x39000000 | size << 30 | load << 22 | immediate << 10 | rn << 5 | rt


def case(words, index):
    return {'symbol': f'memory_{index}', 'output': f'memory_{index}', 'address': 0x8000,
            'code': b''.join(struct.pack('<I', w) for w in words) + RET}


def corpus():
    cases = []
    for size in range(4):
        width = 1 << size
        for load in (False, True):
            for imm in (0, 1, 4095):
                for rt, rn in [(0, 1), (1, 1), (31, 1), (0, 31), (31, 31)]:
                    displacement = imm * width

                    def prepare(trial, registers, rn=rn, width=width, displacement=displacement):
                        registers = list(registers)
                        positions = [0, MEMORY_SIZE - width, 1, 7, 8, 63]
                        position = positions[trial % len(positions)]
                        # With maximum immediates this can wrap the base+offset
                        # calculation into low mapped memory, exactly as A64 does.
                        registers[rn] = (BASE + position - displacement) & MASK
                        return BASE, memory_bytes(trial), registers

                    def expected(registers, data, load=load, rt=rt, rn=rn,
                                 width=width, displacement=displacement):
                        registers, data = list(registers), bytearray(data)
                        position = ((registers[rn] + displacement) & MASK) - BASE
                        if load:
                            value = int.from_bytes(data[position:position + width], 'little')
                            if rt != 31:
                                registers[rt] = value
                        else:
                            value = 0 if rt == 31 else registers[rt]
                            data[position:position + width] = value.to_bytes(8, 'little')[:width]
                        return registers, data

                    current = case([instruction(size, load, rt, rn, imm)], len(cases))
                    current.update(memory=prepare, expected_memory=expected)
                    cases.append(current)
    # Overlapping stores and a final load that aliases its address register.
    words = [instruction(3, False, 0, 1), instruction(0, False, 2, 1, 3),
             instruction(1, True, 3, 1, 1), instruction(3, True, 1, 1)]

    def prepare_sequence(trial, registers):
        registers = list(registers)
        registers[1] = BASE + 33
        return BASE, memory_bytes(trial), registers

    def expected_sequence(registers, data):
        registers, data = list(registers), bytearray(data)
        data[33:41] = registers[0].to_bytes(8, 'little')
        data[36] = registers[2] & 255
        registers[3] = int.from_bytes(data[35:37], 'little')
        registers[1] = int.from_bytes(data[33:41], 'little')
        return registers, data

    current = case(words, len(cases))
    current.update(memory=prepare_sequence, expected_memory=expected_sequence)
    cases.append(current)
    return cases


class MemoryTests(unittest.TestCase):
    def test_native_registers_and_every_memory_byte_against_expected_and_arm64(self):
        cases = corpus()
        with tempfile.TemporaryDirectory(prefix='recomp-memory-test-') as temp:
            self.assertEqual(compare(cases, vectors(), temp), len(cases) * len(vectors()))

    def test_scan_and_lift_accept_supported_memory_encodings(self):
        for current in corpus():
            with self.subTest(symbol=current['symbol']):
                lift_body(current['code'], current['address'])
                self.assertEqual(scan_body(current['code'], current['address'])['blockers'], [])

    def test_unsupported_encodings_are_rejected(self):
        words = {
            'LDR post-index': 0xF8408420, 'STR pre-index': 0xF8008C20,
            'LDR register offset': 0xF8626820, 'STRB register offset': 0x38226820,
            'LDRH post-index': 0x78402420, 'STRH pre-index': 0x78002C20,
            'LDR literal': 0x58000020, 'LDUR': 0xF85FF020, 'STUR': 0xF81FF020,
            'LDRSB': 0x39800020, 'LDRSH indexed': 0x78A26820, 'LDRSW': 0xB9800020,
            'LDP integer': 0xA9400820, 'STP integer': 0xA9000820,
            'LDAR': 0xC8DFFC20, 'STLR': 0xC89FFC20,
            'LDR vector': 0x3DC00020, 'STR FP': 0xBD000020,
            'LDRB pre-index': 0x38401C20, 'STRB post-index': 0x38001420,
        }
        for name, word in words.items():
            with self.subTest(form=name):
                code = case([word], 0)['code']
                with self.assertRaises(RecompError):
                    lift_body(code, 0x8000)
                self.assertTrue(scan_body(code, 0x8000)['blockers'])

    def test_faulting_generated_access_has_no_register_or_partial_memory_update(self):
        cases = []
        for size in range(4):
            for load, rt in [(True, 31), (True, 0), (True, 1),
                             (False, 0), (False, 31), (False, 1)]:
                cases.append(case([instruction(size, load, rt, 1)], len(cases)))
        source = r'''#include "lifted.h"
#include <stdexcept>
int main() {
    typedef void (*Leaf)(recomp::State&, recomp::Memory&);
    const Leaf functions[] = {CALLS};
    for (unsigned i = 0; i < sizeof(functions) / sizeof(functions[0]); ++i) {
        const unsigned width = 1U << (i / 6);
        const uint64_t addresses[] = {4095, 4096 + 32 - width + 1, UINT64_MAX};
        for (uint64_t address : addresses) {
            recomp::Memory memory(4096, 32);
            for (unsigned j = 0; j < 32; ++j) memory.store8(4096 + j, 0xA5);
            recomp::State state = {};
            for (unsigned j = 0; j < 31; ++j) state.x[j] = UINT64_MAX - j;
            state.x[1] = address;
            state.sp = 8192;
            for (unsigned j = 0; j < 32; ++j) state.s[j] = 0xA5A50000 + j;
            const recomp::State before = state;
            bool trapped = false;
            try { functions[i](state, memory); }
            catch (const std::out_of_range&) { trapped = true; }
            if (!trapped || state.sp != before.sp) return 1;
            for (unsigned j = 0; j < 31; ++j) if (state.x[j] != before.x[j]) return 2;
            for (unsigned j = 0; j < 32; ++j) {
                if (memory.load8(4096 + j) != 0xA5 || state.s[j] != before.s[j]) return 3;
            }
        }
    }
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='recomp-memory-fault-') as temp:
            executable = compile_runner(cases, temp, source, 'synthetic-fault-test')
            subprocess.run([str(executable)], check=True)


if __name__ == '__main__':
    unittest.main()
