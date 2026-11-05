#!/usr/bin/env python3
"""Inspect or scan the original ELF and lift a deliberately bounded AArch64 leaf subset."""

import argparse
from bisect import bisect_left
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import re
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_MEM
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.common.exceptions import ELFError

ROOT = Path(__file__).resolve().parents[1]
BACKEND = 'integer-flags-v1'


class RecompError(ValueError):
    pass


class InstructionError(RecompError):
    def __init__(self, kind, message, insn=None):
        super().__init__(message)
        self.kind = kind
        self.insn = insn


class Image:
    def __init__(self, data):
        self.data = data
        self.elf = ELFFile(io.BytesIO(data))
        if (self.elf.elfclass != 64 or not self.elf.little_endian
                or self.elf['e_machine'] != 'EM_AARCH64'
                or self.elf['e_type'] != 'ET_DYN'):
            raise RecompError('input must be a little-endian AArch64 ELF64 shared object')

    def read(self, address, size, executable=False):
        if address < 0 or size <= 0:
            raise RecompError('invalid guest address range')
        for segment in self.elf.iter_segments():
            if segment['p_type'] != 'PT_LOAD':
                continue
            offset = address - segment['p_vaddr']
            if 0 <= offset and offset + size <= segment['p_filesz']:
                if executable and not segment['p_flags'] & 1:
                    raise RecompError('function is not in an executable PT_LOAD segment')
                # ELF virtual addresses are not file offsets, even when some happen to agree.
                start = segment['p_offset'] + offset
                result = self.data[start:start + size]
                if len(result) != size:
                    raise RecompError('truncated ELF segment')
                return result
        raise RecompError(f'guest range {address:#x}+{size:#x} is not file-backed PT_LOAD data')

    def functions(self):
        # Preserve aliases, but merge identical entries present in both symbol tables.
        found = {}
        for table in ('.symtab', '.dynsym'):
            section = self.elf.get_section_by_name(table)
            if section is None:
                continue
            for sym in section.iter_symbols():
                if (sym['st_info']['type'] != 'STT_FUNC' or not sym['st_size']
                        or not isinstance(sym['st_shndx'], int)):
                    continue
                key = (sym.name, sym['st_value'], sym['st_size'])
                found[key] = {'symbol': sym.name, 'address': sym['st_value'],
                              'size': sym['st_size']}
        return sorted(found.values(), key=lambda f: (f['address'], f['symbol']))

    def relocations(self):
        result = []
        for section in self.elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            symbols = self.elf.get_section(section['sh_link'])
            for relocation in section.iter_relocations():
                index = relocation['r_info_sym']
                result.append({'section': section.name, 'address': relocation['r_offset'],
                               'type': relocation['r_info_type'],
                               'symbol': symbols.get_symbol(index).name if index else '',
                               'addend': relocation.entry.get('r_addend', 0)})
        return result

    def inventory(self):
        functions = self.functions()
        imports = {}
        table = self.elf.get_section_by_name('.dynsym')
        if table is not None:
            for sym in table.iter_symbols():
                if sym.name and sym['st_shndx'] == 'SHN_UNDEF':
                    imports[sym.name] = {'symbol': sym.name, 'type': sym['st_info']['type'],
                                         'binding': sym['st_info']['bind']}
        needed = []
        dynamic = self.elf.get_section_by_name('.dynamic')
        if dynamic is not None:
            needed = [tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == 'DT_NEEDED']
        segments = [{k: s[k] for k in ('p_offset', 'p_vaddr', 'p_filesz', 'p_memsz', 'p_flags', 'p_align')}
                    for s in self.elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        sizes = {f['address']: f['size'] for f in functions}
        return {'sha256': hashlib.sha256(self.data).hexdigest(), 'machine': 'aarch64',
                'needed_libraries': needed, 'segments': segments,
                'function_symbols': len(functions), 'unique_function_addresses': len(sizes),
                'symbol_code_bytes': sum(sizes.values()), 'functions': functions,
                'imports': sorted(imports.values(), key=lambda s: s['symbol']),
                'relocations': self.relocations()}


def sreg(insn, operand):
    if operand.type != ARM64_OP_REG:
        raise RecompError('expected scalar single-precision register')
    name = insn.reg_name(operand.reg)
    if not re.fullmatch(r's(?:[0-9]|[12][0-9]|3[01])', name):
        raise RecompError(f'unsupported floating-point register {name}')
    return int(name[1:])


def load_statement(insn):
    operands = insn.operands
    paired = insn.mnemonic == 'ldp'
    if len(operands) != (3 if paired else 2) or insn.writeback:
        raise InstructionError('addressing_mode', 'only non-writeback scalar FP loads are supported')
    memory = operands[-1]
    if memory.type != ARM64_OP_MEM or memory.mem.index:
        raise InstructionError('addressing_mode', 'only base-plus-immediate FP loads are supported')
    base = insn.reg_name(memory.mem.base)
    if not re.fullmatch(r'x(?:[0-9]|[12][0-9]|30)', base):
        raise InstructionError('addressing_mode', 'load base must be x0..x30')
    address = f'(state.x[{int(base[1:])}] + UINT64_C({memory.mem.disp % (1 << 64)}))'
    registers = [sreg(insn, op) for op in operands[:-1]]
    if len(registers) == 2 and registers[0] == registers[1]:
        raise RecompError('overlapping LDP destinations are not supported')
    return [f'state.s[{r}] = memory.load32({address} + UINT64_C({i * 4}));'
            for i, r in enumerate(registers)]


def integer_memory_statement(insn):
    """Integer unsigned imm12 scaled offset only; no writeback or register index."""
    word = int.from_bytes(insn.bytes, 'little')
    if word & (1 << 26):
        raise InstructionError('operand_form', 'only integer W/X transfers are supported')
    if word & 0x3F000000 != 0x39000000:
        raise InstructionError('addressing_mode', 'integer memory requires unsigned scaled immediate without writeback')
    size, opc = (word >> 30) & 3, (word >> 22) & 3
    if opc not in (0, 1):
        raise InstructionError('operand_form', 'only zero-extending integer loads and plain stores are supported')
    rt, rn = word & 31, (word >> 5) & 31
    bits = 8 << size
    displacement = ((word >> 10) & 0xFFF) << size
    base = 'state.sp' if rn == 31 else f'state.x[{rn}]'
    # Unsigned guest address arithmetic wraps modulo 2^64. Memory validates
    # the resulting entire access; an access crossing UINT64_MAX never wraps.
    address = f'({base} + UINT64_C({displacement}))'
    if opc == 1:
        value = f'memory.load{bits}({address})'
        # Even a discarded load must perform bounds validation and may trap.
        return [f'(void){value};' if rt == 31 else f'state.x[{rt}] = {value};']
    value = 'UINT64_C(0)' if rt == 31 else f'state.x[{rt}]'
    return [f'memory.store{bits}({address}, static_cast<uint{bits}_t>({value}));']


def integer_statement(insn):
    """Validate encoding classes, so register 31 means SP or ZR unambiguously.

    Flag-setting CMP is validated separately. MOV aliases are accepted only
    for ORR (unshifted register or bitmask immediate), ADD (SP copy), and
    MOVZ/MOVN encodings.
    """
    word = int.from_bytes(insn.bytes, 'little')
    width = 64 if word >> 31 else 32
    rd, rn, rm = word & 31, (word >> 5) & 31, (word >> 16) & 31
    sp = False

    def read(reg, allow_sp=False):
        value = ('state.sp' if allow_sp else 'UINT64_C(0)') if reg == 31 else f'state.x[{reg}]'
        return value if width == 64 else f'static_cast<uint32_t>({value})'

    if insn.mnemonic == 'mov' and word & 0x7FE0FFE0 == 0x2A0003E0:
        expression = read(rm)
    elif insn.mnemonic == 'mov' and word & 0x7F8003E0 == 0x320003E0:
        # ORR-immediate MOV alias: DecodeBitMasks at generation time only.
        # Unlike ORR shifted register, logical immediate Rd=31 denotes SP/WSP.
        sp = True
        n, imms, immr = (word >> 22) & 1, (word >> 10) & 63, (word >> 16) & 63
        length = ((n << 6) | (~imms & 63)).bit_length() - 1
        if (width == 32 and n) or length < 1:
            raise InstructionError('operand_form', 'reserved MOV logical immediate')
        levels = (1 << length) - 1
        s, r = imms & levels, immr & levels
        if s == levels:
            raise InstructionError('operand_form', 'reserved all-ones MOV logical immediate')
        element_size = 1 << length
        element_mask = (1 << element_size) - 1
        ones = (1 << (s + 1)) - 1
        element = ((ones >> r) | (ones << (element_size - r))) & element_mask
        value = sum(element << offset for offset in range(0, width, element_size))
        expression = f'UINT64_C({value})'
    elif insn.mnemonic in ('mov', 'movz', 'movn') and word & 0x7F800000 in (0x52800000, 0x12800000):
        shift = ((word >> 21) & 3) * 16
        if shift >= width:
            raise InstructionError('operand_form', 'move-wide shift exceeds register width')
        value = ((word >> 5) & 0xFFFF) << shift
        if word & 0x7F800000 == 0x12800000:
            value = ~value
        expression = f'UINT64_C({value & ((1 << width) - 1)})'
    elif insn.mnemonic in ('mov', 'add', 'sub') and word & 0x3F800000 == 0x11000000:
        # ADD/SUB immediate: Rn and Rd == 31 denote SP, including WSP.
        if insn.mnemonic == 'mov' and (word & 0x40000000 or (word >> 10) & 0xFFF):
            raise InstructionError('operand_form', 'MOV SP copy requires ADD immediate zero')
        sp = True
        immediate = ((word >> 10) & 0xFFF) << (12 if word & (1 << 22) else 0)
        operator = '-' if word & (1 << 30) else '+'
        expression = f'(uint64_t({read(rn, True)}) {operator} UINT64_C({immediate}))'
    elif insn.mnemonic in ('add', 'sub', 'neg') and word & 0x3F200000 == 0x0B000000:
        # Shifted-register forms use ZR, never SP. Only LSL is supported.
        shift, amount = (word >> 22) & 3, (word >> 10) & 63
        if shift != 0 or amount >= width:
            raise InstructionError('operand_form', 'integer register arithmetic supports only LSL below register width')
        operator = '-' if word & (1 << 30) else '+'
        expression = f'(uint64_t({read(rn)}) {operator} (uint64_t({read(rm)}) << {amount}))'
    else:
        raise InstructionError('operand_form', 'unsupported integer encoding (expected MOV register/wide/SP or ADD/SUB immediate/LSL register)')
    if rd == 31 and not sp:
        # An architectural ZR write is discarded; this instruction has no other effects.
        return []
    destination = 'state.sp' if rd == 31 else f'state.x[{rd}]'
    # Unsigned arithmetic wraps modulo 2^64; narrowing wraps modulo 2^32 and
    # assignment to x[]/sp zero-extends every W/WSP write.
    if width == 32:
        expression = f'static_cast<uint32_t>({expression})'
    return [f'{destination} = {expression};']


def signed_halfword_statement(insn):
    """LDRSH unsigned scaled imm12 or LDURSH signed imm9, no writeback."""
    word = int.from_bytes(insn.bytes, 'little')
    if (word >> 30) != 1 or word & (1 << 26) or ((word >> 22) & 3) not in (2, 3):
        raise InstructionError('operand_form', 'expected signed integer halfword load')
    if insn.mnemonic == 'ldrsh' and word & 0x3F000000 == 0x39000000:
        displacement = ((word >> 10) & 0xFFF) * 2
    elif insn.mnemonic == 'ldursh' and word & 0x3F200C00 == 0x38000000:
        immediate = (word >> 12) & 0x1FF
        displacement = immediate - 512 if immediate & 256 else immediate
    else:
        raise InstructionError('addressing_mode', 'signed halfword loads require unsigned scaled or signed unscaled immediate without writeback')
    rn, rt = (word >> 5) & 31, word & 31
    base = 'state.sp' if rn == 31 else f'state.x[{rn}]'
    address = f'({base} + UINT64_C({displacement % (1 << 64)}))'
    to_x = ((word >> 22) & 3) == 2
    value = f'sign_extend_halfword(memory.load16({address}), {"true" if to_x else "false"})'
    return [f'(void){value};' if rt == 31 else f'state.x[{rt}] = {value};']


def flags_statement(insn):
    """CMP immediate/LSL register; CINC alias only, not general SUBS/CSINC."""
    word = int.from_bytes(insn.bytes, 'little')
    width = 64 if word >> 31 else 32
    rn, rm = (word >> 5) & 31, (word >> 16) & 31

    def read(reg, sp=False):
        value = ('state.sp' if sp else 'UINT64_C(0)') if reg == 31 else f'state.x[{reg}]'
        return value if width == 64 else f'static_cast<uint32_t>({value})'

    if insn.mnemonic == 'cmp':
        if word & 0x7F80001F == 0x7100001F:
            a = read(rn, True)
            immediate = ((word >> 10) & 0xFFF) << (12 if word & (1 << 22) else 0)
            b = f'UINT{width}_C({immediate})'
        elif word & 0x7F20001F == 0x6B00001F:
            shift, amount = (word >> 22) & 3, (word >> 10) & 63
            if shift != 0 or amount >= width:
                raise InstructionError('operand_form', 'CMP register supports only LSL below register width')
            a, b = read(rn), f'static_cast<uint{width}_t>({read(rm)} << {amount})'
        else:
            raise InstructionError('operand_form', 'CMP requires immediate or LSL shifted register encoding')
        return [f'state.nzcv = cmp_flags{width}({a}, {b});']
    condition = ((word >> 12) & 15) ^ 1
    if (word & 0x7FE00C00 != 0x1A800400 or rn != rm or rn == 31 or condition >= 14):
        raise InstructionError('operand_form', 'CINC requires CSINC alias with equal non-ZR sources and EQ..LE condition')
    rd = word & 31
    if rd == 31:
        return []
    return [f'state.x[{rd}] = static_cast<uint{width}_t>(uint64_t({read(rn)}) + '
            f'(condition_holds(state.nzcv, {condition}) ? UINT64_C(1) : UINT64_C(0)));']


def get_branch_target(insn):
    word = int.from_bytes(insn.bytes, 'little')
    if insn.mnemonic == 'b':
        if word & 0xFC000000 != 0x14000000:
            raise InstructionError('operand_form', 'unsupported unconditional branch encoding', insn)
        imm26 = word & 0x03FFFFFF
        offset = ((imm26 - (1 << 26)) << 2) if (imm26 & (1 << 25)) else (imm26 << 2)
        return (insn.address + offset) & 0xFFFFFFFFFFFFFFFF
    elif insn.mnemonic in ('cbz', 'cbnz'):
        if word & 0x7E000000 != 0x34000000:
            raise InstructionError('operand_form', 'unsupported compare-and-branch encoding', insn)
        imm19 = (word >> 5) & 0x7FFFF
        offset = ((imm19 - (1 << 19)) << 2) if (imm19 & (1 << 18)) else (imm19 << 2)
        return (insn.address + offset) & 0xFFFFFFFFFFFFFFFF
    elif insn.mnemonic == 'tbnz':
        if word & 0x7F000000 != 0x37000000:
            raise InstructionError('operand_form', 'unsupported test-bit branch encoding', insn)
        immediate = (word >> 5) & 0x3FFF
        offset = (immediate - (1 << 14) if immediate & (1 << 13) else immediate) * 4
        return (insn.address + offset) & 0xFFFFFFFFFFFFFFFF
    raise InstructionError('control_flow', f'{insn.mnemonic} is not a supported branch', insn)


def branch_statement(insn):
    word = int.from_bytes(insn.bytes, 'little')
    target = get_branch_target(insn)
    if insn.mnemonic == 'b':
        return [f'goto loc_{target:#x};']
    if insn.mnemonic == 'tbnz':
        rt = word & 31
        bit = ((word >> 31) << 5) | ((word >> 19) & 31)
        value = 'UINT64_C(0)' if rt == 31 else f'state.x[{rt}]'
        return [f'if (({value} & UINT64_C({1 << bit})) != 0) goto loc_{target:#x};']
    sf = (word >> 31) & 1
    rt = word & 31
    if rt == 31:
        val = 'UINT32_C(0)' if sf == 0 else 'UINT64_C(0)'
    else:
        val = f'static_cast<uint32_t>(state.x[{rt}])' if sf == 0 else f'state.x[{rt}]'
    op = '==' if insn.mnemonic == 'cbz' else '!='
    return [f'if ({val} {op} 0) goto loc_{target:#x};']


def analyze_cfg(instructions, address, size):
    fn_start = address
    fn_end = address + size
    insn_map = {insn.address: insn for insn in instructions}
    valid_addrs = set(insn_map.keys())

    branch_targets = set()
    for insn in instructions:
        if insn.mnemonic in ('b', 'cbz', 'cbnz', 'tbnz'):
            target = get_branch_target(insn)
            if target < fn_start or target >= fn_end:
                raise InstructionError('control_flow', f'branch target {target:#x} is outside function range [{fn_start:#x}, {fn_end:#x})', insn)
            if target not in valid_addrs:
                raise InstructionError('control_flow', f'branch target {target:#x} does not land on an instruction boundary', insn)
            branch_targets.add(target)

    leaders = {fn_start}
    for insn in instructions:
        if insn.mnemonic in ('b', 'cbz', 'cbnz', 'tbnz'):
            leaders.add(get_branch_target(insn))
            if insn.address + 4 < fn_end:
                leaders.add(insn.address + 4)
        elif insn.mnemonic == 'ret':
            if insn.address + 4 < fn_end:
                leaders.add(insn.address + 4)

    sorted_leaders = sorted(leaders)
    blocks = {}
    succs = {}

    for idx, l_start in enumerate(sorted_leaders):
        l_end = sorted_leaders[idx + 1] if idx + 1 < len(sorted_leaders) else fn_end
        block_insns = [insn_map[a] for a in range(l_start, l_end, 4)]
        blocks[l_start] = block_insns
        last = block_insns[-1]

        if last.mnemonic == 'ret':
            succs[l_start] = []
        elif last.mnemonic == 'b':
            succs[l_start] = [get_branch_target(last)]
        elif last.mnemonic in ('cbz', 'cbnz', 'tbnz'):
            fallthrough = last.address + 4
            if fallthrough >= fn_end:
                raise InstructionError('control_flow', f'block at {l_start:#x} falls through outside function', last)
            succs[l_start] = [fallthrough, get_branch_target(last)]
        else:
            fallthrough = last.address + 4
            if fallthrough >= fn_end:
                raise InstructionError('control_flow', f'function at {last.address:#x} falls through outside function without RET', last)
            succs[l_start] = [fallthrough]

    visited = {}
    def dfs(u):
        visited[u] = 1
        for v in succs[u]:
            if visited.get(v, 0) == 1:
                raise InstructionError('control_flow', f'control flow graph contains a cycle involving block {v:#x}', insn_map.get(v))
            elif visited.get(v, 0) == 0:
                dfs(v)
        visited[u] = 2

    dfs(fn_start)

    unreachable = [l for l in sorted_leaders if visited.get(l, 0) == 0]
    if unreachable:
        raise InstructionError('control_flow', f'function contains unreachable basic block at {unreachable[0]:#x}', insn_map.get(unreachable[0]))

    return {
        'leaders': sorted_leaders,
        'blocks': blocks,
        'successors': succs,
        'branch_targets': branch_targets
    }


def translate_instruction(insn, index=None, count=None):
    del index, count
    mnemonic = insn.mnemonic
    if mnemonic == 'ret':
        word = int.from_bytes(insn.bytes, 'little')
        if word & 0xFFFFFC1F != 0xD65F0000 or ((word >> 5) & 31) != 30 or insn.op_str not in ('', 'x30'):
            raise InstructionError('control_flow', 'only RET through x30 is supported', insn)
        emitted = ['return;']
    elif mnemonic == 'nop':
        emitted = []
    elif mnemonic in ('b', 'cbz', 'cbnz', 'tbnz'):
        emitted = branch_statement(insn)
    elif mnemonic.startswith('b.'):
        raise InstructionError('control_flow', f'conditional branch {mnemonic} requires NZCV branch support which is not implemented', insn)
    elif mnemonic in ('bl', 'blr'):
        raise InstructionError('control_flow', f'subroutine call {mnemonic} is not supported in leaf functions', insn)
    elif mnemonic == 'br':
        raise InstructionError('control_flow', 'indirect branch BR is not supported', insn)
    elif mnemonic == 'tbz':
        raise InstructionError('control_flow', f'test and branch {mnemonic} is not supported', insn)
    elif mnemonic == 'ldp' or (mnemonic == 'ldr' and int.from_bytes(insn.bytes, 'little') & (1 << 26)):
        emitted = load_statement(insn)
    elif mnemonic in ('ldr', 'str', 'ldrb', 'strb', 'ldrh', 'strh'):
        emitted = integer_memory_statement(insn)
    elif mnemonic in ('ldrsh', 'ldursh'):
        emitted = signed_halfword_statement(insn)
    elif mnemonic in ('cmp', 'cinc'):
        emitted = flags_statement(insn)
    elif mnemonic in ('mov', 'movz', 'movn', 'add', 'sub', 'neg'):
        emitted = integer_statement(insn)
    elif mnemonic in ('fmul', 'fmadd', 'fnmsub'):
        expected = 3 if mnemonic == 'fmul' else 4
        if len(insn.operands) != expected:
            raise RecompError('unexpected FP operand count')
        regs = [sreg(insn, operand) for operand in insn.operands]
        dst, a, b = regs[:3]
        if mnemonic == 'fmul':
            expression = f'fp_mul(state.s[{a}], state.s[{b}])'
        else:
            c = regs[3]
            helper = 'fp_madd' if mnemonic == 'fmadd' else 'fp_nmsub'
            expression = f'{helper}(state.s[{a}], state.s[{b}], state.s[{c}])'
        emitted = [f'state.s[{dst}] = {expression};']
    else:
        raise InstructionError('unsupported_instruction', f'unsupported instruction {mnemonic}', insn)
    return emitted


def lift_body(code, address):
    if address % 4 or not code or len(code) % 4:
        raise RecompError('function must be nonempty and 4-byte aligned')
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    instructions = list(decoder.disasm(code, address))
    if sum(i.size for i in instructions) != len(code):
        raise RecompError('instruction decoding did not cover the complete function')
    cfg = analyze_cfg(instructions, address, len(code))
    branch_targets = cfg['branch_targets']
    lines = []
    opcodes = Counter()
    for index, insn in enumerate(instructions):
        try:
            mnemonic = insn.mnemonic
            opcodes[mnemonic] += 1
            if insn.address in branch_targets:
                lines.append(f'loc_{insn.address:#x}:')
            lines.append(f'    // Guest {insn.address:#x}: {mnemonic} {insn.op_str}')
            emitted = translate_instruction(insn, index, len(instructions))
            lines += ['    ' + line for line in emitted]
        except RecompError as exc:
            raise RecompError(f'{insn.address:#x}: {insn.mnemonic} {insn.op_str}: {exc}') from exc
    return '\n'.join(lines), dict(opcodes)


def lift(image, selections):
    functions = image.functions()
    outputs = set()
    results = []
    relocations = image.relocations()
    for selection in selections:
        name, output = selection['symbol'], selection['output']
        if not re.fullmatch(r'[a-z][a-z0-9_]*', output) or output in outputs:
            raise RecompError('output names must be unique lowercase C++ identifiers')
        outputs.add(output)
        found = [f for f in functions if f['symbol'] == name]
        if len(found) != 1:
            raise RecompError(f'{name}: expected one defined function, found {len(found)}')
        fn = found[0]
        lo, hi = fn['address'], fn['address'] + fn['size']
        if any(lo <= r['address'] < hi for r in relocations):
            raise RecompError(f'{name}: code relocations require a linker-aware backend')
        code = image.read(lo, fn['size'], executable=True)
        body, opcodes = lift_body(code, lo)
        results.append({**fn, 'output': output, 'opcodes': opcodes,
                        'instruction_count': len(code) // 4, 'body': body})
    if not results:
        raise RecompError('select at least one function')
    return results


def scan_body(code, address):
    """Validate every decoded instruction, including words after decoding gaps."""
    blockers = {}
    opcodes = Counter()

    def record(kind, reason, insn=None):
        mnemonic = insn.mnemonic if insn is not None else ''
        key = (kind, mnemonic, reason)
        entry = blockers.setdefault(key, {'kind': kind, 'mnemonic': mnemonic,
                                          'reason': reason, 'count': 0, 'examples': []})
        entry['count'] += 1
        if insn is not None and len(entry['examples']) < 3:
            entry['examples'].append({'address': insn.address, 'operands': insn.op_str})

    if address % 4 or not code or len(code) % 4:
        record('range', 'function must be nonempty and 4-byte aligned')
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    # AArch64 skipdata advances one 4-byte word, without treating it as executable.
    decoder.skipdata = True
    covered = 0
    instructions = []
    has_decode_error = False
    for index, insn in enumerate(decoder.disasm(code, address)):
        covered += insn.size
        if insn.id == 0:
            record('decode', 'undecodable instruction bytes', insn)
            has_decode_error = True
            continue
        instructions.append(insn)
        opcodes[insn.mnemonic] += 1
        try:
            translate_instruction(insn, index, len(code) // 4)
        except RecompError as exc:
            record(getattr(exc, 'kind', 'operand_form'), str(exc), insn)
    if covered != len(code):
        record('decode', 'instruction decoding did not cover the complete function')
        has_decode_error = True

    if not has_decode_error and len(instructions) == len(code) // 4 and len(instructions) > 0:
        try:
            analyze_cfg(instructions, address, len(code))
        except InstructionError as exc:
            record(exc.kind, str(exc), exc.insn)
        except RecompError as exc:
            record('control_flow', str(exc))
    elif not instructions or instructions[-1].mnemonic != 'ret':
        if not any(b[0] == 'control_flow' for b in blockers):
            record('control_flow', 'all execution paths must terminate with RET')

    return {'opcodes': dict(opcodes), 'decoded_instruction_count': sum(opcodes.values()),
            'blockers': list(blockers.values())}


def scan(image):
    """Report backend acceptance, never a claim of semantic equivalence."""
    inventory = image.inventory()
    relocation_addresses = sorted(r['address'] for r in inventory['relocations'])
    ranges = {}
    functions = []
    totals = {}
    for fn in inventory['functions']:
        lo, size = fn['address'], fn['size']
        key = (lo, size)
        if key not in ranges:
            try:
                result = scan_body(image.read(lo, size, executable=True), lo)
            except RecompError as exc:
                result = {'opcodes': {}, 'decoded_instruction_count': 0,
                          'blockers': [{'kind': 'range', 'mnemonic': '',
                                        'reason': str(exc), 'count': 1, 'examples': []}]}
            index = bisect_left(relocation_addresses, lo)
            end = bisect_left(relocation_addresses, lo + size)
            if index < end:
                result['blockers'].append({'kind': 'code_relocation', 'mnemonic': '',
                                          'reason': 'code relocations require a linker-aware backend',
                                          'count': end - index,
                                          'examples': [{'address': a} for a in
                                                       relocation_addresses[index:min(end, index + 3)]]})
            result['status'] = 'blocked' if result['blockers'] else 'translatable'
            result['semantic_verification'] = 'not_verified'
            ranges[key] = result
            for blocker in result['blockers']:
                group = (blocker['kind'], blocker['mnemonic'], blocker['reason'])
                entry = totals.setdefault(group, {**blocker, 'count': 0, 'function_ranges': 0})
                entry['count'] += blocker['count']
                entry['function_ranges'] += 1
        functions.append({**fn, **ranges[key]})
    return {'input_sha256': inventory['sha256'], 'backend': BACKEND,
            'scope': 'defined nonzero-sized STT_FUNC symbols; aliases preserved',
            'semantic_verification': 'not_verified',
            'summary': {'function_symbols': len(functions), 'unique_function_ranges': len(ranges),
                        'symbol_status_counts': dict(Counter(f['status'] for f in functions)),
                        'range_status_counts': dict(Counter(r['status'] for r in ranges.values()))},
            'functions': functions,
            'blocker_summary': [totals[k] for k in sorted(totals)],
            'imports': [{**imp, 'status': 'unresolved'} for imp in inventory['imports']]}


def write_lift(out, results, digest):
    # All input was validated before any generated translation is published.
    out.mkdir(parents=True, exist_ok=True)
    declarations = ['#pragma once', '#include "recomp/runtime.h"', 'namespace recomp {']
    implementation = ['#include "lifted.h"', 'namespace recomp {']
    for fn in results:
        declaration = f'void {fn["output"]}(State& state, Memory& memory)'
        declarations.append(declaration + ';')
        implementation += [declaration + ' {', '    (void)state;', '    (void)memory;', fn['body'], '}']
    declarations.append('}')
    implementation.append('}')
    provenance = {'input_sha256': digest, 'backend': BACKEND,
                  'functions': [{k: v for k, v in f.items() if k != 'body'} for f in results]}
    for name, content in [('lifted.h', '\n'.join(declarations) + '\n'),
                          ('lifted.cpp', '\n'.join(implementation) + '\n'),
                          ('manifest.json', json.dumps(provenance, indent=2) + '\n')]:
        temporary = out / (name + '.tmp')
        temporary.write_text(content)
        temporary.replace(out / name)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'config/recomp.json')
    subparsers = parser.add_subparsers(dest='command', required=True)
    for command in ('inspect', 'scan', 'lift'):
        sub = subparsers.add_parser(command)
        sub.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        config = json.loads(args.config.read_text())
        if config['guest'] != 'aarch64-linux-android' or config['host'] != 'x86_64-linux':
            raise RecompError('only AArch64 Android to Linux x86_64 is configured')
        binary = Path(config['input'])
        if not binary.is_absolute():
            binary = args.config.resolve().parent.parent / binary
        data = binary.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != config['sha256']:
            raise RecompError(f'input SHA-256 mismatch: expected {config["sha256"]}, got {digest}')
        image = Image(data)
        if args.command == 'inspect':
            inventory = image.inventory()
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(inventory, indent=2) + '\n')
            print(f'{inventory["function_symbols"]} function symbols; '
                  f'{inventory["unique_function_addresses"]} unique addresses; '
                  f'{len(inventory["imports"])} imports; {len(inventory["relocations"])} relocations')
        elif args.command == 'scan':
            report = scan(image)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + '\n')
            counts = report['summary']['symbol_status_counts']
            print(f'{counts.get("translatable", 0)} translatable; '
                  f'{counts.get("blocked", 0)} blocked function symbols; '
                  'semantic verification: not_verified')
        else:
            results = lift(image, config['functions'])
            write_lift(args.output, results, digest)
            print(f'Lifted {len(results)} leaf functions / '
                  f'{sum(f["instruction_count"] for f in results)} instructions into {args.output}')
        return 0
    except (RecompError, OSError, KeyError, ValueError, ELFError) as exc:
        print(f'recomp: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
