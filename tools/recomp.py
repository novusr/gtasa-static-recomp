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


class RecompError(ValueError):
    pass


class InstructionError(RecompError):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


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


def translate_instruction(insn, index, count):
    mnemonic = insn.mnemonic
    if mnemonic == 'ret':
        if index != count - 1 or insn.op_str not in ('', 'x30'):
            raise InstructionError('control_flow', 'only a final RET through x30 is supported')
        emitted = ['return;']
    elif mnemonic == 'nop':
        emitted = []
    elif mnemonic in ('ldr', 'ldp'):
        emitted = load_statement(insn)
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
        raise InstructionError('unsupported_instruction', f'unsupported instruction {mnemonic}')
    return emitted


def lift_body(code, address):
    if address % 4 or not code or len(code) % 4:
        raise RecompError('function must be nonempty and 4-byte aligned')
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    instructions = list(decoder.disasm(code, address))
    if sum(i.size for i in instructions) != len(code):
        raise RecompError('instruction decoding did not cover the complete function')
    if instructions[-1].mnemonic != 'ret':
        raise RecompError('leaf function must end with RET')
    lines = []
    opcodes = Counter()
    for index, insn in enumerate(instructions):
        try:
            mnemonic = insn.mnemonic
            opcodes[mnemonic] += 1
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
    last = None
    for index, insn in enumerate(decoder.disasm(code, address)):
        covered += insn.size
        last = insn
        if insn.id == 0:
            record('decode', 'undecodable instruction bytes', insn)
            continue
        opcodes[insn.mnemonic] += 1
        try:
            translate_instruction(insn, index, len(code) // 4)
        except RecompError as exc:
            record(getattr(exc, 'kind', 'operand_form'), str(exc), insn)
    if covered != len(code):
        record('decode', 'instruction decoding did not cover the complete function')
    if last is None or last.mnemonic != 'ret':
        record('control_flow', 'leaf function must end with RET')
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
    return {'input_sha256': inventory['sha256'], 'backend': 'scalar-leaf-v1',
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
        declaration = f'void {fn["output"]}(State& state, const Memory& memory)'
        declarations.append(declaration + ';')
        implementation += [declaration + ' {', '    (void)state;', '    (void)memory;', fn['body'], '}']
    declarations.append('}')
    implementation.append('}')
    provenance = {'input_sha256': digest, 'backend': 'scalar-leaf-v1',
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
