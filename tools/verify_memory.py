#!/usr/bin/env python3
"""Compare original integer-memory leaves with ARM64, including all guest bytes."""

import argparse
import hashlib
import json
from pathlib import Path
import random
import tempfile

from recomp import BACKEND, Image, ROOT, lift
from verify_integer import compare, vectors

BASE = 4096
MEMORY_SIZE = 256


def memory_bytes(trial):
    if trial % 16 == 0:
        return bytes([255]) * MEMORY_SIZE
    if trial % 16 == 1:
        return bytes(MEMORY_SIZE)
    rng = random.Random(0xB170 + trial)
    return bytes(rng.randrange(256) for _ in range(MEMORY_SIZE))


def original_memory(pointer_registers):
    """Place explicit guest pointer arguments within an initialized sandbox.

    Alternate alignment and aliasing of pointer arguments. Non-pointer argument
    registers retain the boundary/random integer corpus values.
    """
    def prepare(trial, registers):
        registers = list(registers)
        for i, reg in enumerate(pointer_registers):
            at = 32 + i * 64 + trial % 8
            if trial % 4 == 0:
                at = 32 + trial % 8
            registers[reg] = BASE + at
        return BASE, memory_bytes(trial), registers
    return prepare


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
    selections = [s for s in config['functions'] if s.get('verification') == 'memory']
    image = Image(data)
    functions = lift(image, selections)
    cases = []
    for fn, selection in zip(functions, selections):
        if not set(fn['opcodes']) <= {'ldr', 'str', 'ldrb', 'strb', 'ldrh', 'strh',
                                     'mov', 'movz', 'movn', 'add', 'sub', 'neg', 'nop', 'ret'}:
            raise ValueError('memory oracle requires integer-only leaves')
        pointers = selection['pointer_registers']
        if not pointers or len(set(pointers)) != len(pointers) or any(r not in range(30) for r in pointers):
            raise ValueError('oracle pointer_registers must be unique x0..x29 indices')
        cases.append({**fn, 'code': image.read(fn['address'], fn['size'], executable=True),
                      'memory': original_memory(pointers)})
    with tempfile.TemporaryDirectory(prefix='recomp-memory-') as temp:
        count = compare(cases, vectors(), temp, digest)
    report = {'input_sha256': digest, 'backend': BACKEND,
              'evidence': 'native C++11 versus Unicorn ARM64; all represented registers, full sandbox bytes, NZCV preservation',
              'trials_per_function': len(vectors()), 'function_calls': count,
              'memory_base': BASE, 'compared_memory_bytes_per_call': MEMORY_SIZE,
              'functions': [{**{k: f[k] for k in ('symbol', 'output', 'address', 'size', 'opcodes')},
                             'pointer_registers': selection['pointer_registers']}
                            for f, selection in zip(functions, selections)]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(f'{len(cases)} original memory leaves / {count} calls: registers and all {MEMORY_SIZE} guest bytes agree with ARM64; evidence: {output}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'config/recomp.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'generated/memory-verification.json')
    args = parser.parse_args()
    verify(args.config, args.output)
