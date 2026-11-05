#!/usr/bin/env python3
"""AOT integer leaf differential tests; Unicorn is used only as an ARM oracle."""

import argparse
import hashlib
import json
from pathlib import Path
import random
import subprocess
import tempfile

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as arm

from recomp import BACKEND, Image, ROOT, lift, lift_body, write_lift

XREGS = [getattr(arm, f'UC_ARM64_REG_X{i}') for i in range(31)]
SREGS = [getattr(arm, f'UC_ARM64_REG_S{i}') for i in range(32)]
MASK = (1 << 64) - 1


def vectors():
    """Boundary values in every register, mixed upper halves, then seeded randoms."""
    edges = [0, 1, 0xFFFFFFFF, 0x100000000, 0x7FFFFFFF, 0x80000000,
             0x7FFFFFFFFFFFFFFF, 0x8000000000000000, MASK, MASK - 1,
             0xAAAAAAAA55555555, 0x55555555AAAAAAAA]
    result = [[value] * 32 for value in edges]
    result += [[edges[(i + offset) % len(edges)] for i in range(32)]
               for offset in range(len(edges))]
    rng = random.Random(0xA64)
    result += [[rng.getrandbits(64) for _ in range(32)] for _ in range(128)]
    return result


def compile_runner(cases, directory, source, input_digest):
    """Validate all leaves, then compile a standalone C++11 test executable."""
    directory = Path(directory)
    results = []
    for case in cases:
        body, opcodes = lift_body(case['code'], case['address'])
        results.append({k: case[k] for k in ('symbol', 'output', 'address')})
        results[-1].update(size=len(case['code']), body=body, opcodes=opcodes)
    write_lift(directory, results, input_digest)
    source = source.replace('CALLS', ', '.join('recomp::' + c['output'] for c in cases))
    (directory / 'runner.cpp').write_text(source)
    executable = directory / 'integer_runner'
    subprocess.run(['c++', '-std=c++11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-pedantic', '-ffp-contract=off', '-fno-fast-math',
                    '-I', str(ROOT / 'include'), '-I', str(directory),
                    str(directory / 'runner.cpp'), str(directory / 'lifted.cpp'),
                    str(ROOT / 'src/runtime.cpp'), '-o', str(executable)], check=True)
    return executable


def compare(cases, inputs, directory, input_digest='synthetic-test-input', evidence=None):
    """Compile once, then compare x[], SP, low S[], NZCV and memory.

    cases contain symbol/output/address/code. No host ABI or guest pointer cast
    is involved: the runner consumes explicit register values on stdin. Optional
    case['memory'](trial, registers) supplies (base, bytes, initial registers).
    expected_flags(registers, memory, initial_nzcv) defaults to preservation.
    Optional traces record oracle PCs; instruction count remains bounded by the
    acyclic function size. The native executable consumes state/data only.
    """
    source = '''#include "lifted.h"
#include <iostream>
int main() {
    typedef void (*Leaf)(recomp::State&, recomp::Memory&);
    const Leaf functions[] = {CALLS};
    unsigned index;
    while (std::cin >> index) {
        if (index >= sizeof(functions) / sizeof(functions[0])) return 2;
        recomp::State state = {};
        for (unsigned i = 0; i < 31; ++i) if (!(std::cin >> state.x[i])) return 3;
        if (!(std::cin >> state.sp >> state.nzcv)) return 3;
        uint64_t base;
        std::size_t size;
        if (!(std::cin >> base >> size)) return 3;
        recomp::Memory memory(base, size);
        for (std::size_t i = 0; i < size; ++i) {
            unsigned byte;
            if (!(std::cin >> byte) || byte > 255) return 3;
            memory.store8(base + i, static_cast<uint8_t>(byte));
        }
        for (unsigned i = 0; i < 32; ++i) state.s[i] = UINT32_C(0xA5A50000) + i;
        functions[index](state, memory);
        for (unsigned i = 0; i < 31; ++i) std::cout << state.x[i] << ' ';
        std::cout << state.sp;
        for (unsigned i = 0; i < 32; ++i) std::cout << ' ' << state.s[i];
        std::cout << ' ' << state.nzcv;
        for (std::size_t i = 0; i < size; ++i) std::cout << ' ' << unsigned(memory.load8(base + i));
        std::cout << '\\n';
    }
    return std::cin.eof() ? 0 : 4;
}
'''
    executable = compile_runner(cases, directory, source, input_digest)
    if evidence is not None:
        evidence['native_executable_sha256'] = hashlib.sha256(executable.read_bytes()).hexdigest()
        evidence['compiler_flags'] = ['-std=c++11', '-O2', '-Wall', '-Wextra', '-Werror',
                                      '-pedantic', '-ffp-contract=off', '-fno-fast-math']
    requests, expected = [], []
    for index, case in enumerate(cases):
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        address, code = case['address'], case['code']
        end = address + len(code)
        start = address & ~4095
        cpu.mem_map(start, ((end + 4095) & ~4095) - start)
        cpu.mem_write(address, code)
        mapped = set(range(start, (end + 4095) & ~4095, 4096))
        trace = []
        if 'traces' in case:
            def observe(cpu, pc, size, data):
                del cpu, size, data
                trace.append(pc)
            cpu.hook_add(UC_HOOK_CODE, observe)
        for trial, values in enumerate(inputs):
            trace.clear()
            values = list(values)
            base, memory = 0, b''
            if 'memory' in case:
                base, memory, values = case['memory'](trial, values)
                values = list(values)
                for page in range(base & ~4095, (base + len(memory) + 4095) & ~4095, 4096):
                    if start <= page < end:
                        raise ValueError('oracle data overlaps code')
                    if page not in mapped:
                        cpu.mem_map(page, 4096)
                        mapped.add(page)
                cpu.mem_write(base, bytes(memory))
            sentinel = case.get('return_sentinel', end)
            values[30] = sentinel
            flags = (trial % 16) << 28
            requests.append(' '.join(map(str, [index] + values + [flags, base, len(memory)] + list(memory))))
            for reg, value in zip(XREGS + [arm.UC_ARM64_REG_SP], values):
                cpu.reg_write(reg, value)
            for i, reg in enumerate(SREGS):
                cpu.reg_write(reg, 0xA5A50000 + i)
            cpu.reg_write(arm.UC_ARM64_REG_NZCV, flags)
            cpu.emu_start(address, sentinel, count=len(code) // 4)
            if cpu.reg_read(arm.UC_ARM64_REG_PC) != sentinel:
                raise AssertionError(f'{case["symbol"]}: oracle failed to return')
            wanted_flags = case.get('expected_flags', lambda s, m, f: f)(values, bytes(memory), flags)
            actual_flags = cpu.reg_read(arm.UC_ARM64_REG_NZCV)
            if actual_flags != wanted_flags:
                raise AssertionError(f'{case["symbol"]}, trial {trial}: NZCV {actual_flags:#x} != explicit expected {wanted_flags:#x}')
            if 'traces' in case:
                case['traces'].append(list(trace))
            state = [cpu.reg_read(reg) for reg in XREGS + [arm.UC_ARM64_REG_SP] + SREGS]
            result_memory = bytes(cpu.mem_read(base, len(memory))) if memory else b''
            if 'expected' in case:
                wanted = case['expected'](values) + [0xA5A50000 + i for i in range(32)]
                if state != wanted:
                    raise AssertionError(f'{case["symbol"]}, trial {trial}: oracle differs from explicit expected state')
            if 'expected_memory' in case:
                wanted_regs, wanted_memory = case['expected_memory'](values, bytes(memory))
                wanted = wanted_regs + [0xA5A50000 + i for i in range(32)]
                if state != wanted or result_memory != bytes(wanted_memory):
                    raise AssertionError(f'{case["symbol"]}, trial {trial}: oracle differs from explicit memory/state expectation')
            expected.append(state + [actual_flags] + list(result_memory))
    native = subprocess.run([str(executable)], input='\n'.join(requests) + '\n',
                            capture_output=True, text=True, check=True).stdout.splitlines()
    if len(native) != len(expected):
        raise AssertionError('native runner returned an incomplete corpus')
    for index, (line, wanted) in enumerate(zip(native, expected)):
        actual = [int(word) for word in line.split()]
        if actual != wanted:
            case = cases[index // len(inputs)]
            raise AssertionError(f'{case["symbol"]}, trial {index % len(inputs)}: host {actual} != ARM {wanted}')
    return len(expected)


def verify(config_path, output):
    config = json.loads(config_path.read_text())
    if config['guest'] != 'aarch64-linux-android' or config['host'] != 'x86_64-linux':
        raise ValueError('only AArch64 Android to Linux x86_64 is configured')
    binary = Path(config['input'])
    if not binary.is_absolute():
        binary = config_path.resolve().parent.parent / binary
    data = binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != config['sha256']:
        raise ValueError('input hash does not match the recompilation configuration')
    image = Image(data)
    # Keep the two existing FP oracle functions in their original test harness.
    selections = [s for s in config['functions'] if s['output'] not in ('cross_product', 'multiply3x3')
                  and s.get('verification') not in ('memory', 'control_flow', 'count_members', 'clock_beep')]
    functions = lift(image, selections)
    for fn in functions:
        if not set(fn['opcodes']) <= {'mov', 'movz', 'movn', 'add', 'sub', 'neg', 'nop', 'ret'}:
            raise ValueError(f'{fn["symbol"]}: integer oracle requires register-only integer leaves')
    cases = [{**f, 'code': image.read(f['address'], f['size'], executable=True)} for f in functions]
    with tempfile.TemporaryDirectory(prefix='recomp-integer-') as temp:
        count = compare(cases, vectors(), temp, digest)
    report = {'input_sha256': digest, 'backend': BACKEND,
              'evidence': 'native C++11 executable versus Unicorn ARM64; full represented register state and NZCV preservation',
              'trials_per_function': len(vectors()), 'function_calls': count,
              'functions': [{k: f[k] for k in ('symbol', 'output', 'address', 'size', 'opcodes')} for f in functions]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(f'{len(cases)} original integer leaves / {count} calls agree with ARM64; evidence: {output}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'config/recomp.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'generated/integer-verification.json')
    args = parser.parse_args()
    verify(args.config, args.output)
