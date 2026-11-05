#!/usr/bin/env python3
"""AOT integer leaf differential tests; Unicorn is used only as an ARM oracle."""

import argparse
import hashlib
import json
from pathlib import Path
import random
import subprocess
import tempfile

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
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


def compare(cases, inputs, directory, input_digest='synthetic-test-input'):
    """Compile once, then compare all x[], SP, low S[] and unchanged ARM NZCV.

    cases contain symbol/output/address/code. No host ABI or guest pointer cast
    is involved: the runner consumes explicit register values on stdin.
    """
    directory = Path(directory)
    results = []
    for case in cases:
        body, opcodes = lift_body(case['code'], case['address'])
        results.append({k: case[k] for k in ('symbol', 'output', 'address')})
        results[-1].update(size=len(case['code']), body=body, opcodes=opcodes)
    write_lift(directory, results, input_digest)
    calls = ', '.join('recomp::' + c['output'] for c in cases)
    source = '''#include "lifted.h"
#include <iostream>
int main() {
    typedef void (*Leaf)(recomp::State&, const recomp::Memory&);
    const Leaf functions[] = {CALLS};
    recomp::Memory memory(0, 0);
    unsigned index;
    while (std::cin >> index) {
        if (index >= sizeof(functions) / sizeof(functions[0])) return 2;
        recomp::State state = {};
        for (unsigned i = 0; i < 31; ++i) if (!(std::cin >> state.x[i])) return 3;
        if (!(std::cin >> state.sp)) return 3;
        for (unsigned i = 0; i < 32; ++i) state.s[i] = UINT32_C(0xA5A50000) + i;
        functions[index](state, memory);
        for (unsigned i = 0; i < 31; ++i) std::cout << state.x[i] << ' ';
        std::cout << state.sp;
        for (unsigned i = 0; i < 32; ++i) std::cout << ' ' << state.s[i];
        std::cout << '\\n';
    }
    return std::cin.eof() ? 0 : 4;
}
'''.replace('CALLS', calls)
    (directory / 'runner.cpp').write_text(source)
    executable = directory / 'integer_runner'
    subprocess.run(['c++', '-std=c++11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-pedantic', '-ffp-contract=off', '-fno-fast-math',
                    '-I', str(ROOT / 'include'), '-I', str(directory),
                    str(directory / 'runner.cpp'), str(directory / 'lifted.cpp'),
                    str(ROOT / 'src/runtime.cpp'), '-o', str(executable)], check=True)
    requests, expected = [], []
    for index, case in enumerate(cases):
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        address, code = case['address'], case['code']
        end = address + len(code)
        start = address & ~4095
        cpu.mem_map(start, ((end + 4095) & ~4095) - start)
        cpu.mem_write(address, code)
        for trial, values in enumerate(inputs):
            values = list(values)
            values[30] = end
            requests.append(' '.join(map(str, [index] + values)))
            for reg, value in zip(XREGS + [arm.UC_ARM64_REG_SP], values):
                cpu.reg_write(reg, value)
            for i, reg in enumerate(SREGS):
                cpu.reg_write(reg, 0xA5A50000 + i)
            flags = (trial % 16) << 28
            cpu.reg_write(arm.UC_ARM64_REG_NZCV, flags)
            cpu.emu_start(address, end, count=len(code) // 4)
            if cpu.reg_read(arm.UC_ARM64_REG_PC) != end:
                raise AssertionError(f'{case["symbol"]}: oracle failed to return')
            if cpu.reg_read(arm.UC_ARM64_REG_NZCV) != flags:
                raise AssertionError(f'{case["symbol"]}: unexpected NZCV change')
            state = [cpu.reg_read(reg) for reg in XREGS + [arm.UC_ARM64_REG_SP] + SREGS]
            if 'expected' in case:
                wanted = case['expected'](values) + [0xA5A50000 + i for i in range(32)]
                if state != wanted:
                    raise AssertionError(f'{case["symbol"]}, trial {trial}: oracle differs from explicit expected state')
            expected.append(state)
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
    selections = [s for s in config['functions'] if s['output'] not in ('cross_product', 'multiply3x3')]
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
