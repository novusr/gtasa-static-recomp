"""Synthetic and differential tests for intrafunction control flow: B, CBZ, CBNZ, multiple RETs."""

from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'tools'))
from recomp import InstructionError, RecompError, lift_body, scan_body
from verify_integer import compare, vectors

RET = bytes.fromhex('c0035fd6')  # ret through x30
NOP = bytes.fromhex('1f2003d5')


def pack_words(*words):
    return b''.join(struct.pack('<I', w) for w in words)


def make_b(imm_signed):
    imm26 = imm_signed & 0x03FFFFFF
    return 0x14000000 | imm26


def make_cbz(sf, rt, imm_signed):
    imm19 = imm_signed & 0x7FFFF
    return (sf << 31) | 0x34000000 | (imm19 << 5) | (rt & 31)


def make_cbnz(sf, rt, imm_signed):
    imm19 = imm_signed & 0x7FFFF
    return (sf << 31) | 0x35000000 | (imm19 << 5) | (rt & 31)


def make_mov_imm(sf, rd, imm16):
    # MOVZ
    return (sf << 31) | 0x52800000 | ((imm16 & 0xFFFF) << 5) | (rd & 31)


def make_str(size, rt, rn, imm12=0):
    return 0x39000000 | (size << 30) | (imm12 << 10) | (rn << 5) | (rt & 31)


class ControlFlowSemanticTests(unittest.TestCase):
    def test_branch_semantics_and_unicorn_differential(self):
        cases = []

        # 1. Unconditional B to ret
        # 0x8000: mov x0, #1
        # 0x8004: b #+4 (to 0x8008)
        # 0x8008: ret
        code1 = pack_words(make_mov_imm(1, 0, 1), make_b(1)) + RET
        cases.append({
            'symbol': 'test_direct_b', 'output': 'test_direct_b', 'address': 0x8000,
            'code': code1,
            'expected': lambda s: [1] + list(s[1:])
        })

        # 2. CBZ W with dirty upper 32 bits (W register width check)
        # 0x8000: cbz w1, #+8 (to 0x8008)
        # 0x8004: mov x0, #100
        # 0x8008: ret
        # When low 32 bits of x1 are 0 (even if high 32 bits are non-zero), branch taken -> x0 untouched.
        # When low 32 bits of x1 are != 0, branch not taken -> x0 = 100.
        code2 = pack_words(make_cbz(0, 1, 2), make_mov_imm(1, 0, 100)) + RET
        def exp_cbz_w(s):
            res = list(s)
            if (s[1] & 0xFFFFFFFF) != 0:
                res[0] = 100
            return res
        cases.append({
            'symbol': 'test_cbz_w', 'output': 'test_cbz_w', 'address': 0x8000,
            'code': code2,
            'expected': exp_cbz_w
        })

        # 3. CBZ X (full 64-bit check)
        # 0x8000: cbz x1, #+8 (to 0x8008)
        # 0x8004: mov x0, #200
        # 0x8008: ret
        # Only taken when full 64-bit x1 == 0.
        code3 = pack_words(make_cbz(1, 1, 2), make_mov_imm(1, 0, 200)) + RET
        def exp_cbz_x(s):
            res = list(s)
            if s[1] != 0:
                res[0] = 200
            return res
        cases.append({
            'symbol': 'test_cbz_x', 'output': 'test_cbz_x', 'address': 0x8000,
            'code': code3,
            'expected': exp_cbz_x
        })

        # 4. CBNZ W with dirty upper bits
        # 0x8000: cbnz w1, #+8 (to 0x8008)
        # 0x8004: mov x0, #300
        # 0x8008: ret
        # Taken when low 32 bits != 0. When low 32 bits == 0, x0 = 300.
        code4 = pack_words(make_cbnz(0, 1, 2), make_mov_imm(1, 0, 300)) + RET
        def exp_cbnz_w(s):
            res = list(s)
            if (s[1] & 0xFFFFFFFF) == 0:
                res[0] = 300
            return res
        cases.append({
            'symbol': 'test_cbnz_w', 'output': 'test_cbnz_w', 'address': 0x8000,
            'code': code4,
            'expected': exp_cbnz_w
        })

        # 5. CBNZ X (full 64-bit check)
        # 0x8000: cbnz x1, #+8 (to 0x8008)
        # 0x8004: mov x0, #400
        # 0x8008: ret
        code5 = pack_words(make_cbnz(1, 1, 2), make_mov_imm(1, 0, 400)) + RET
        def exp_cbnz_x(s):
            res = list(s)
            if s[1] == 0:
                res[0] = 400
            return res
        cases.append({
            'symbol': 'test_cbnz_x', 'output': 'test_cbnz_x', 'address': 0x8000,
            'code': code5,
            'expected': exp_cbnz_x
        })

        # 6. Multiple RETs in one function
        # 0x8000: cbz x1, #+8 (to 0x8008)
        # 0x8004: ret
        # 0x8008: mov x0, #777
        # 0x800c: ret
        code6 = pack_words(make_cbz(1, 1, 2)) + RET + pack_words(make_mov_imm(1, 0, 777)) + RET
        def exp_multi_ret(s):
            res = list(s)
            if s[1] == 0:
                res[0] = 777
            return res
        cases.append({
            'symbol': 'test_multi_ret', 'output': 'test_multi_ret', 'address': 0x8000,
            'code': code6,
            'expected': exp_multi_ret
        })

        # 7. Diamond join with B
        # 0x8000: cbz x1, #+12 (to 0x800c)
        # 0x8004: mov x0, #1
        # 0x8008: b #+8 (to 0x8010)
        # 0x800c: mov x0, #2
        # 0x8010: ret
        code7 = pack_words(make_cbz(1, 1, 3), make_mov_imm(1, 0, 1), make_b(2),
                           make_mov_imm(1, 0, 2)) + RET
        def exp_diamond(s):
            res = list(s)
            res[0] = 2 if s[1] == 0 else 1
            return res
        cases.append({
            'symbol': 'test_diamond', 'output': 'test_diamond', 'address': 0x8000,
            'code': code7,
            'expected': exp_diamond
        })

        # 8. Memory mutation across branches
        # 0x8000: cbz x1, #+8 (to 0x8008)
        # 0x8004: strb w2, [x0, #4]
        # 0x8008: ret
        base = 4096
        code8 = pack_words(make_cbz(1, 1, 2), make_str(0, 2, 0, 4)) + RET
        def prep_mem(trial, regs):
            regs = list(regs)
            regs[0] = base
            regs[1] = 0 if trial % 2 == 0 else 1
            regs[2] = 0xAA
            mem = bytearray(256)
            return base, bytes(mem), regs
        def exp_mem(regs, mem):
            regs = list(regs)
            mem = bytearray(mem)
            if regs[1] != 0:
                mem[4] = regs[2] & 0xFF
            return regs, mem
        cases.append({
            'symbol': 'test_branch_mem', 'output': 'test_branch_mem', 'address': 0x8000,
            'code': code8,
            'memory': prep_mem,
            'expected_memory': exp_mem
        })

        # Run differential test against Unicorn and explicit expectations
        with tempfile.TemporaryDirectory(prefix='recomp-cf-test-') as temp:
            count = compare(cases, vectors(), temp)
        self.assertEqual(count, len(cases) * len(vectors()))


class ControlFlowRejectionTests(unittest.TestCase):
    def assert_rejected(self, code, pattern=None):
        with self.assertRaises(RecompError) as ctx:
            lift_body(code, 0x8000)
        if pattern:
            self.assertRegex(str(ctx.exception), pattern)
        report = scan_body(code, 0x8000)
        self.assertTrue(report['blockers'], f'scan_body did not report blockers for {code.hex()}')

    def test_cycle_self_loop_rejected(self):
        # b #0 (jumps to self)
        code = pack_words(make_b(0))
        self.assert_rejected(code, 'cycle')

    def test_cycle_two_nodes_rejected(self):
        # 0x8000: cbz x0, 0x8008
        # 0x8004: ret
        # 0x8008: b -8 (to 0x8000)
        code = pack_words(make_cbz(1, 0, 2)) + RET + pack_words(make_b(-2))
        self.assert_rejected(code, 'cycle')

    def test_cycle_three_nodes_rejected(self):
        # 0x8000: cbz x0, 0x800c
        # 0x8004: b +4 (to 0x8008)
        # 0x8008: ret
        # 0x800c: b -12 (to 0x8000)
        code = pack_words(make_cbz(1, 0, 3), make_b(1)) + RET + pack_words(make_b(-3))
        self.assert_rejected(code, 'cycle')

    def test_branch_target_outside_function_rejected(self):
        # Branch beyond end
        code1 = pack_words(make_b(2)) + RET
        self.assert_rejected(code1, 'outside function range')
        # Branch before start
        code2 = pack_words(make_b(-1)) + RET
        self.assert_rejected(code2, 'outside function range')

    def test_fallthrough_outside_function_rejected(self):
        # Function ending with NOP
        code1 = pack_words(0xD503201F)
        self.assert_rejected(code1, 'falls through outside function')
        # Function ending with CBZ
        code2 = pack_words(make_cbz(1, 0, 0))
        self.assert_rejected(code2)

    def test_unreachable_block_rejected(self):
        # 0x8000: ret
        # 0x8004: ret
        code1 = RET + RET
        self.assert_rejected(code1, 'unreachable')
        # 0x8000: b +8
        # 0x8004: nop (dead code)
        # 0x8008: ret
        code2 = pack_words(make_b(2), 0xD503201F) + RET
        self.assert_rejected(code2, 'unreachable')

    def test_conditional_branches_outside_ne_subset_rejected(self):
        # B.NE is supported; other B.cond conditions remain outside this milestone.
        b_conds = [
            0x54000040,  # b.eq #+8
            0x5400004B,  # b.lt #+8
            0x5400004C,  # b.gt #+8
        ]
        for cond in b_conds:
            code = pack_words(cond) + RET
            self.assert_rejected(code)

    def test_subroutine_calls_and_indirect_branches_rejected(self):
        # BL #+4
        self.assert_rejected(pack_words(0x94000001) + RET, 'subroutine call')
        # BLR x0
        self.assert_rejected(pack_words(0xD63F0000) + RET, 'subroutine call')
        # BR x0
        self.assert_rejected(pack_words(0xD61F0000) + RET, 'indirect branch')
        # RET x0 (indirect return)
        self.assert_rejected(pack_words(0xD65F0000), 'only RET through x30')
        # TBZ remains outside this milestone; TBNZ must still obey CFG bounds.
        self.assert_rejected(pack_words(0x36000040) + RET, 'test and branch')
        self.assert_rejected(pack_words(0x37000040) + RET, 'outside function range')


class ScanAndLiftAgreementTests(unittest.TestCase):
    def test_agreement_on_valid_control_flow(self):
        valid_cases = [
            # Direct B to RET
            pack_words(make_b(1)) + RET,
            # CBZ W to RET
            pack_words(make_cbz(0, 0, 2)) + RET + RET,
            # CBZ X to RET
            pack_words(make_cbz(1, 5, 2)) + RET + RET,
            # CBNZ W to RET
            pack_words(make_cbnz(0, 10, 2)) + RET + RET,
            # CBNZ X to RET
            pack_words(make_cbnz(1, 20, 2)) + RET + RET,
            # Diamond CFG
            pack_words(make_cbz(1, 0, 3), make_mov_imm(1, 1, 1), make_b(2),
                       make_mov_imm(1, 1, 2)) + RET,
        ]
        for i, code in enumerate(valid_cases):
            with self.subTest(case=i):
                lift_body(code, 0x8000)
                report = scan_body(code, 0x8000)
                self.assertEqual(report['blockers'], [], f'Valid case {i} reported blockers: {report["blockers"]}')


if __name__ == '__main__':
    unittest.main()
