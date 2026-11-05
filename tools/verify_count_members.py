#!/usr/bin/env python3
"""Fresh original CountMembers AOT versus bounded ARM64 oracle and independent results."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import tempfile

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from recomp import BACKEND, ROOT, Image, get_branch_target, lift
from verify_integer import compare, vectors

SYMBOL = '_ZN15CLoadedCarGroup12CountMembersEv'
BASE, MEMORY_SIZE, SENTINEL = 4096, 512, 0xFFFF0000
SEED = 0xC017


def arrays():
    """Every first-negative position and final-element sign, over all initial flags."""
    result = []
    for position in range(24):
        for positive in (0, 1, 32767):
            for negative in (-32768, -1):
                values = [positive] * position + [negative] * (23 - position)
                result.extend([values[:23]] * 16)
    rng = random.Random(SEED)
    for trial in range(512):
        # Alternating arbitrary signs and long nonnegative prefixes.
        values = [rng.randrange(-32768, 32768) for _ in range(23)]
        if trial % 2:
            stop = rng.randrange(24)
            values[:stop] = [rng.randrange(32768) for _ in range(stop)]
        result.append(values)
    return result


def array_at(registers, memory):
    start = registers[0] - BASE
    return [int.from_bytes(memory[start + i * 2:start + i * 2 + 2], 'little', signed=True)
            for i in range(23)]


def expected_state(registers, memory):
    values = array_at(registers, memory)
    count = next((i for i, value in enumerate(values) if value < 0), 23)
    result = list(registers)
    result[0] = count
    # Early exits retain the negative W8 load. The final path compares it,
    # then writes the constant 22 to W8 before CINC computes W0.
    result[8] = values[count] % (1 << 32) if count < 22 else 22
    return result, memory


def expected_flags(registers, memory, initial):
    values = array_at(registers, memory)
    if any(value < 0 for value in values[:22]):
        return initial
    # CMP W8,#0 cannot overflow; subtraction of zero always has carry/no borrow.
    return (0x80000000 if values[22] < 0 else 0) | (0x40000000 if values[22] == 0 else 0) | 0x20000000


def verify(config_path, output):
    config = json.loads(config_path.read_text())
    if config['guest'] != 'aarch64-linux-android' or config['host'] != 'x86_64-linux':
        raise ValueError('unsupported configured guest/host')
    binary = Path(config['input'])
    if not binary.is_absolute():
        binary = config_path.resolve().parent.parent / binary
    data = binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != config['sha256']:
        raise ValueError('input hash does not match pinned configuration')
    selections = [s for s in config['functions'] if s.get('verification') == 'count_members']
    if len(selections) != 1 or selections[0]['symbol'] != SYMBOL:
        raise ValueError('oracle requires exactly the explicitly selected original CountMembers')
    image = Image(data)
    functions = lift(image, selections)
    fn = functions[0]
    code = image.read(fn['address'], fn['size'], executable=True)
    corpus = arrays()
    register_inputs = vectors()
    inputs = [register_inputs[i % len(register_inputs)] for i in range(len(corpus))]

    def memory(trial, registers):
        registers = list(registers)
        offset = 32 + trial % 16
        registers[0], registers[31] = BASE + offset, BASE + 384 + trial % 8 * 16
        sandbox = bytearray(random.Random(SEED + trial).randbytes(MEMORY_SIZE))
        for i, value in enumerate(corpus[trial]):
            sandbox[offset + i * 2:offset + i * 2 + 2] = value.to_bytes(2, 'little', signed=True)
        return BASE, bytes(sandbox), registers

    case = {**fn, 'code': code, 'memory': memory, 'expected_memory': expected_state,
            'expected_flags': expected_flags, 'return_sentinel': SENTINEL, 'traces': []}
    artifact = {}
    with tempfile.TemporaryDirectory(prefix='recomp-count-members-') as temp:
        count = compare([case], inputs, temp, digest, artifact)
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    instructions = list(decoder.disasm(code, fn['address']))
    returns = {i.address for i in instructions if i.mnemonic == 'ret'}
    return_counts = Counter(trace[-1] for trace in case['traces'])
    branches = {}
    for instruction in instructions:
        if instruction.mnemonic != 'tbnz':
            continue
        outcomes = Counter()
        target = get_branch_target(instruction)
        for trace in case['traces']:
            if instruction.address in trace:
                next_pc = trace[trace.index(instruction.address) + 1]
                outcomes['taken' if next_pc == target else 'fallthrough'] += 1
        if not outcomes['taken'] or not outcomes['fallthrough']:
            raise AssertionError('corpus missed a TBNZ outcome')
        branches[hex(instruction.address)] = dict(outcomes)
    if set(return_counts) != returns:
        raise AssertionError('corpus missed a RET exit')
    serial_corpus = json.dumps(corpus, separators=(',', ':')).encode()
    report = {'input_sha256': digest, 'backend': BACKEND, 'result': 'passed',
              'evidence': 'fresh native C++11 AOT versus original ARM64 in Unicorn and independent signed-array expectations',
              'function': {k: fn[k] for k in ('symbol', 'output', 'address', 'size', 'opcodes', 'instruction_count')},
              'code_sha256': hashlib.sha256(code).hexdigest(), 'call_graph': {SYMBOL: []},
              'cases': count, 'corpus': {'seed': SEED, 'boundary_cases': 2304, 'random_cases': 512,
                  'description': 'first negative at every position or absent; prefixes 0/1/32767, negatives -32768/-1; all 16 initial NZCV; varied X/SP/S, object alignment and sandbox bytes',
                  'signed_arrays_sha256': hashlib.sha256(serial_corpus).hexdigest(), 'signed_arrays': corpus},
              'compared': ['x0..x30', 'SP', 'low S0..S31', 'NZCV', 'all 512 sandbox bytes'],
              'sandbox': {'base': BASE, 'size': MEMORY_SIZE, 'return_sentinel': SENTINEL,
                          'instruction_limit': len(code) // 4},
              'coverage': {'return_counts': {hex(k): v for k, v in sorted(return_counts.items())},
                           'tbnz_outcomes': branches,
                           'maximum_executed_instructions': max(map(len, case['traces']))},
              'native': artifact,
              'limits': 'bounded corpus and flat checked normal memory; no full SIMD/FPCR/FPSR, faults/permissions/align-check emulation, calls, imports or platform startup'}
    payload = json.dumps(report, indent=2) + '\n'
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=output.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
        temporary.replace(output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print(f'CountMembers: {count} native/ARM64/independent cases agree; {len(returns)} RET exits and {len(branches)} TBNZ pairs covered; evidence: {output}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'config/recomp.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'generated/count-members-verification.json')
    args = parser.parse_args()
    verify(args.config, args.output)
