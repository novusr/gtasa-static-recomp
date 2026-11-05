#!/usr/bin/env python3
"""Fresh original clock countdown AOT versus bounded ARM64 and independent state."""

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

SYMBOL = '_ZN14COnscreenTimer25SetClockBeepCountdownSecsEjj'
ADDRESS, SIZE = 0x3DB37C, 20
BASE, MEMORY_SIZE, SENTINEL = 4096, 512, 0xFFFF0000
SEED = 0xBEE5
MASK32 = (1 << 32) - 1


def corpus():
    """Both compare outcomes and signed/unsigned boundaries at all initial NZCV."""
    edges = (0, 1, 0x7FFFFFFF, 0x80000000, 0x80000001, MASK32)
    result = []
    for loaded in edges:
        for argument in edges:
            # First-byte source, unaligned source/store and final-byte destination.
            for offset in (0, 1, MEMORY_SIZE - 65, MEMORY_SIZE - 64):
                for flags in range(16):
                    trial = len(result)
                    result.append({'loaded_word': loaded,
                                   'x1': ((0xA5000000 + trial) << 32) | argument,
                                   'x2': ((0x5A000000 + trial) << 32) | edges[trial % len(edges)],
                                   'offset': offset, 'initial_nzcv': flags << 28})
    rng = random.Random(SEED)
    for trial in range(512):
        loaded = rng.getrandbits(32)
        argument = loaded if trial % 2 else rng.getrandbits(32)
        result.append({'loaded_word': loaded, 'x1': rng.getrandbits(32) << 32 | argument,
                       'x2': rng.getrandbits(64), 'offset': rng.randrange(MEMORY_SIZE - 63),
                       'initial_nzcv': trial % 16 << 28})
    return result


def loaded_word(registers, memory):
    offset = registers[0] - BASE
    return int.from_bytes(memory[offset:offset + 4], 'little')


def expected_state(registers, memory):
    result, changed = list(registers), bytearray(memory)
    value = loaded_word(registers, memory)
    result[8] = value
    if value == registers[1] % (1 << 32):
        offset = registers[0] - BASE + 60
        changed[offset:offset + 4] = (registers[2] % (1 << 32)).to_bytes(4, 'little')
    return result, changed


def expected_flags(registers, memory, initial):
    del initial
    a, b = loaded_word(registers, memory), registers[1] % (1 << 32)
    signed_a = a - (1 << 32) if a >= (1 << 31) else a
    signed_b = b - (1 << 32) if b >= (1 << 31) else b
    signed_difference = signed_a - signed_b
    return ((int((a - b) % (1 << 32) >= (1 << 31)) << 31)
            | (int(a == b) << 30) | (int(a >= b) << 29)
            | (int(not -(1 << 31) <= signed_difference < (1 << 31)) << 28))


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
    selections = [s for s in config['functions'] if s.get('verification') == 'clock_beep']
    if len(selections) != 1 or selections[0]['symbol'] != SYMBOL:
        raise ValueError('oracle requires exactly the explicitly selected original clock countdown')
    image = Image(data)
    fn, = lift(image, selections)
    if (fn['address'], fn['size']) != (ADDRESS, SIZE):
        raise ValueError('original clock countdown range does not match this harness')
    code = image.read(fn['address'], fn['size'], executable=True)
    cases = corpus()
    register_inputs = vectors()
    inputs = [register_inputs[i % len(register_inputs)] for i in range(len(cases))]
    full_corpus = []

    def memory(trial, registers):
        entry = cases[trial]
        registers = list(registers)
        offset = entry['offset']
        registers[0], registers[1], registers[2] = BASE + offset, entry['x1'], entry['x2']
        registers[31] = BASE + 384 + trial % 8 * 16
        sandbox = bytearray(random.Random(SEED + trial).randbytes(MEMORY_SIZE))
        sandbox[offset:offset + 4] = entry['loaded_word'].to_bytes(4, 'little')
        if entry['initial_nzcv'] != (trial % 16) << 28:
            raise AssertionError('harness initial NZCV scheduling disagrees with corpus')
        # compare() replaces X30 with the explicit sentinel before execution.
        serialized_registers = list(registers)
        serialized_registers[30] = SENTINEL
        full_corpus.append({'x0_to_x30_and_sp': serialized_registers,
                            'initial_nzcv': entry['initial_nzcv'],
                            'low_s0_to_s31': [0xA5A50000 + i for i in range(32)],
                            'sandbox_hex': sandbox.hex()})
        return BASE, bytes(sandbox), registers

    case = {**fn, 'code': code, 'memory': memory, 'expected_memory': expected_state,
            'expected_flags': expected_flags, 'return_sentinel': SENTINEL, 'traces': []}
    artifact = {}
    with tempfile.TemporaryDirectory(prefix='recomp-clock-beep-') as temp:
        count = compare([case], inputs, temp, digest, artifact)
    instructions = list(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(code, ADDRESS))
    branches = [i for i in instructions if i.mnemonic == 'b.ne']
    if len(branches) != 1:
        raise AssertionError('original clock countdown must contain exactly one B.NE')
    branch, = branches
    target = get_branch_target(branch)
    outcomes = Counter()
    for trace in case['traces']:
        index = trace.index(branch.address)
        outcomes['taken' if trace[index + 1] == target else 'fallthrough'] += 1
    if not outcomes['taken'] or not outcomes['fallthrough']:
        raise AssertionError('corpus missed a B.NE outcome')
    returns = {i.address for i in instructions if i.mnemonic == 'ret'}
    return_counts = Counter(trace[-1] for trace in case['traces'])
    if set(return_counts) != returns:
        raise AssertionError('corpus missed a RET exit')
    visited = set(pc for trace in case['traces'] for pc in trace)
    if visited != {i.address for i in instructions}:
        raise AssertionError('corpus missed an original instruction')
    serialized = json.dumps(full_corpus, separators=(',', ':')).encode()
    report = {'input_sha256': digest, 'backend': BACKEND, 'result': 'passed',
              'evidence': 'fresh native C++11 AOT versus original ARM64 in Unicorn and independent mathematical state expectations',
              'function': {k: fn[k] for k in ('symbol', 'output', 'address', 'size', 'opcodes', 'instruction_count')},
              'code_sha256': hashlib.sha256(code).hexdigest(), 'call_graph': {SYMBOL: []},
              'cases': count, 'corpus': {'seed': SEED, 'boundary_cases': 2304, 'random_cases': 512,
                  'description': 'all 36 comparison boundary pairs at four object offsets and all 16 initial flags; dirty upper W1/W2 halves; deterministic random equality/inequality, registers and sandbox bytes',
                  'state_and_sandbox_sha256': hashlib.sha256(serialized).hexdigest(),
                  'initial_states_and_sandboxes': full_corpus},
              'compared': ['x0..x30', 'SP', 'low S0..S31', 'NZCV', 'all 512 sandbox bytes'],
              'sandbox': {'base': BASE, 'size': MEMORY_SIZE, 'return_sentinel': SENTINEL,
                          'instruction_limit': len(code) // 4},
              'coverage': {'return_counts': {hex(k): v for k, v in sorted(return_counts.items())},
                           'bne_outcomes': {hex(branch.address): dict(outcomes)},
                           'instructions_visited': [hex(pc) for pc in sorted(visited)],
                           'maximum_executed_instructions': max(map(len, case['traces']))},
              'native': artifact,
              'limits': 'bounded corpus and flat checked normal memory; low S words fixed varied-by-register patterns; no full SIMD/FPCR/FPSR, faults/permissions/align-check emulation, calls, imports or platform startup'}
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
    print(f'Clock countdown: {count} native/ARM64/independent cases agree; both B.NE outcomes and all instructions covered; evidence: {output}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'config/recomp.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'generated/clock-beep-verification.json')
    args = parser.parse_args()
    verify(args.config, args.output)
