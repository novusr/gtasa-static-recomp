#!/usr/bin/env python3
"""Compare real control-flow leaves with ARM64, including registers and guest memory."""

import argparse
import hashlib
import json
from pathlib import Path
import random
import tempfile

from recomp import BACKEND, Image, ROOT, lift
from verify_integer import compare, vectors

BASE = 4096
MEMORY_SIZE = 2048


def control_flow_memory(symbol):
    def prepare(trial, registers):
        registers = list(registers)
        mem = bytearray(random.Random(0xCF00 + trial).randrange(256) for _ in range(MEMORY_SIZE))
        ptr = BASE + 32 + (trial % 8) * 8

        if 'RxPipelineClusterGetCreationAttributes' in symbol:
            registers[0] = 0 if trial % 2 == 0 else ptr
        elif 'RxPipelineClusterSetCreationAttributes' in symbol:
            registers[0] = 0 if trial % 2 == 0 else ptr
            registers[1] = 0x12345678 ^ (trial * 0x11111111)
        elif 'SetPedAtomicVisibilityCB' in symbol:
            registers[0] = ptr
            if trial % 3 == 0:
                registers[1] = 0
            elif trial % 3 == 1:
                # Dirty upper bits with zero in low 32 bits: W read must take branch
                registers[1] = (trial + 1) << 32
            else:
                registers[1] = (trial % 255) + 1
        elif 'ReduceHornCounter' in symbol:
            registers[0] = ptr
            counter_offset = 1700
            if trial % 3 == 0:
                mem[counter_offset:counter_offset + 4] = b'\x00\x00\x00\x00'
            else:
                val = (trial % 100) + 1
                mem[counter_offset:counter_offset + 4] = val.to_bytes(4, 'little')
        elif 'GetActiveTask' in symbol:
            registers[0] = ptr
            task_mode = trial % 5
            for i in range(5):
                t_val = (BASE + 512 + i * 32) if (i == task_mode or i > task_mode) else 0
                mem[i * 8:(i + 1) * 8] = t_val.to_bytes(8, 'little')
        return BASE, bytes(mem), registers
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
    selections = [s for s in config['functions'] if s.get('verification') == 'control_flow']
    image = Image(data)
    functions = lift(image, selections)
    cases = []
    for fn in functions:
        cases.append({**fn, 'code': image.read(fn['address'], fn['size'], executable=True),
                      'memory': control_flow_memory(fn['symbol'])})
    with tempfile.TemporaryDirectory(prefix='recomp-control-flow-') as temp:
        count = compare(cases, vectors(), temp, digest)
    report = {'input_sha256': digest, 'backend': BACKEND,
              'evidence': 'native C++11 versus Unicorn ARM64; all represented registers, full sandbox bytes, NZCV preservation',
              'trials_per_function': len(vectors()), 'function_calls': count,
              'memory_base': BASE, 'compared_memory_bytes_per_call': MEMORY_SIZE,
              'functions': [{**{k: f[k] for k in ('symbol', 'output', 'address', 'size', 'opcodes')}}
                            for f in functions]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(f'{len(cases)} original control-flow leaves / {count} calls: registers and all {MEMORY_SIZE} guest bytes agree with ARM64; evidence: {output}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'config/recomp.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'generated/control-flow-verification.json')
    args = parser.parse_args()
    verify(args.config, args.output)
