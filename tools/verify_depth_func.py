#!/usr/bin/env python3
"""Fresh original depth-function AOT versus bounded ARM64 and independent state."""

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

SYMBOL = '_Z17GLDepthFuncFromRQ11RQDepthFunc'
ADDRESS, SIZE = 0x264CD0, 24
BASE, MEMORY_SIZE, SENTINEL = 4096, 512, 0xFFFF0000
SEED = 0xDE97
MASK32 = (1 << 32) - 1


def corpus():
    """Unsigned threshold boundaries with clean/dirty upper X0 and all flags."""
    edges = (0, 1, 6, 7, 8, 0x7FFFFFFF, 0x80000000, MASK32)
    result = []
    for value in edges:
        for upper in (0, 0xA5A55A5A, MASK32):
            for flags in range(16):
                result.append({'x0': upper << 32 | value, 'initial_nzcv': flags << 28})
    rng = random.Random(SEED)
    for trial in range(512):
        # Mix both paths; unrestricted random W0 alone almost always takes HI.
        low = rng.randrange(8) if trial % 2 else rng.getrandbits(32)
        result.append({'x0': rng.getrandbits(32) << 32 | low,
                       'initial_nzcv': trial % 16 << 28})
    return result


def expected_state(registers, memory):
    result = list(registers)
    value = registers[0] % (1 << 32)
    result[0] = 0x200 + min(value, 7)
    return result, memory


def expected_flags(registers, memory, initial):
    del memory, initial
    value = registers[0] % (1 << 32)
    signed_value = value - (1 << 32) if value >= (1 << 31) else value
    # CMP W0,#7: unsigned borrow and signed subtraction range are independent
    # mathematical tests; neither runtime flag helpers nor condition_holds is used.
    return ((int((value - 7) % (1 << 32) >= (1 << 31)) << 31)
            | (int(value == 7) << 30) | (int(value >= 7) << 29)
            | (int(not -(1 << 31) <= signed_value - 7 < (1 << 31)) << 28))


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
    selections = [s for s in config['functions'] if s.get('verification') == 'depth_func']
    if len(selections) != 1 or selections[0]['symbol'] != SYMBOL:
        raise ValueError('oracle requires exactly the explicitly selected original depth-function')
    image = Image(data)
    fn, = lift(image, selections)
    if (fn['address'], fn['size']) != (ADDRESS, SIZE):
        raise ValueError('original depth-function range does not match this harness')
    code = image.read(fn['address'], fn['size'], executable=True)
    if code.hex() != '1f1c00716800005400000811c0035fd6e0408052c0035fd6':
        raise ValueError('original depth-function instruction bytes changed')
    cases = corpus()
    register_inputs = vectors()
    inputs = [register_inputs[i % len(register_inputs)] for i in range(len(cases))]
    full_corpus = []

    def memory(trial, registers):
        entry = cases[trial]
        registers = list(registers)
        registers[0] = entry['x0']
        registers[31] = BASE + 384 + trial % 8 * 16
        sandbox = bytearray(random.Random(SEED + trial).randbytes(MEMORY_SIZE))
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
    with tempfile.TemporaryDirectory(prefix='recomp-depth-func-') as temp:
        count = compare([case], inputs, temp, digest, artifact)
    instructions = list(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(code, ADDRESS))
    branches = [i for i in instructions if i.mnemonic == 'b.hi']
    if len(branches) != 1:
        raise AssertionError('original depth-function must contain exactly one B.HI')
    branch, = branches
    target = get_branch_target(branch)
    outcomes = Counter()
    for trace in case['traces']:
        index = trace.index(branch.address)
        outcomes['taken' if trace[index + 1] == target else 'fallthrough'] += 1
    if not outcomes['taken'] or not outcomes['fallthrough']:
        raise AssertionError('corpus missed a B.HI outcome')
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
              'instructions': [{'address': i.address, 'encoding_hex': i.bytes.hex(),
                                'mnemonic': i.mnemonic, 'operands': i.op_str} for i in instructions],
              'independent_result': 'X0 = 0x200 + min(initial X0 modulo 2^32, 7); NZCV = mathematical 32-bit subtraction of 7; other represented state and memory preserved',
              'cases': count, 'corpus': {'seed': SEED, 'boundary_cases': 384, 'random_cases': 512,
                  'description': 'eight unsigned threshold boundaries with three clean/dirty upper X0 patterns and all 16 initial flags; deterministic random threshold paths, other registers, SP and sandbox bytes',
                  'state_and_sandbox_sha256': hashlib.sha256(serialized).hexdigest(),
                  'initial_states_and_sandboxes': full_corpus, 'input_parameters': cases},
              'compared': ['x0..x30', 'SP', 'low S0..S31', 'NZCV', 'all 512 sandbox bytes'],
              'sandbox': {'base': BASE, 'size': MEMORY_SIZE, 'return_sentinel': SENTINEL,
                          'instruction_limit': len(code) // 4},
              'coverage': {'return_counts': {hex(k): v for k, v in sorted(return_counts.items())},
                           'bhi_outcomes': {hex(branch.address): dict(outcomes)},
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
    print(f'Depth function: {count} native/ARM64/independent cases agree; both B.HI outcomes and all instructions covered; evidence: {output}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'config/recomp.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'generated/depth-func-verification.json')
    args = parser.parse_args()
    verify(args.config, args.output)
