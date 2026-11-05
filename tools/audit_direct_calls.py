#!/usr/bin/env python3
"""Read-only feasibility audit for a bounded direct-call AOT milestone.

The optimistic screen deliberately forgives every integer/FP load/store and
pair addressing form. It is an upper bound for candidate discovery, never
translation acceptance, an implementation contract, or semantic evidence.
"""

import argparse
from bisect import bisect_left
from collections import Counter
import hashlib
import json
from pathlib import Path
import tempfile

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

from recomp import BACKEND, ROOT, Image, RecompError, analyze_cfg, translate_instruction


FORGIVEN = {'bl', 'stp', 'ldp', 'ldr', 'str', 'ldrb', 'strb', 'ldrh', 'strh'}


def direct_target(insn):
    word = int.from_bytes(insn.bytes, 'little')
    if insn.size != 4 or word & 0xFC000000 != 0x94000000:
        raise RecompError('not a direct BL immediate encoding')
    immediate = word & 0x3FFFFFF
    if immediate & 0x2000000:
        immediate -= 1 << 26
    return (insn.address + immediate * 4) & ((1 << 64) - 1)


def audit(image, scan_report):
    inventory = image.inventory()
    identities = lambda fs: sorted((f['symbol'], f['address'], f['size']) for f in fs)
    if (scan_report['input_sha256'] != inventory['sha256']
            or scan_report['backend'] != BACKEND
            or scan_report['semantic_verification'] != 'not_verified'
            or identities(scan_report['functions']) != identities(inventory['functions'])):
        raise RecompError('scan identity/backend/symbol ranges do not match verified input')

    # Scan selects no acceptance decisions here: decode every symbol range afresh.
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    decoder.skipdata = True
    nodes = {}
    for fn in inventory['functions']:
        key = (fn['address'], fn['size'])
        if key in nodes:
            nodes[key]['symbols'].append(fn['symbol'])
            continue
        node = {'address': key[0], 'size': key[1], 'symbols': [fn['symbol']],
                'calls': [], 'blockers': [], 'optimistic_blockers': [], 'opcodes': {}}
        nodes[key] = node
        try:
            code = image.read(*key, executable=True)
            instructions = list(decoder.disasm(code, key[0]))
            if key[0] % 4 or key[1] % 4 or sum(i.size for i in instructions) != key[1]:
                raise RecompError('unaligned range or incomplete instruction decoding')
            node['opcodes'] = dict(Counter(i.mnemonic for i in instructions))
            for insn in instructions:
                if insn.id == 0:
                    blocker = {'address': insn.address, 'reason': 'undecodable instruction bytes'}
                    node['blockers'].append(blocker)
                    node['optimistic_blockers'].append(blocker)
                    continue
                if insn.mnemonic == 'bl':
                    node['calls'].append({'address': insn.address,
                                          'return_address': insn.address + 4,
                                          'target': direct_target(insn)})
                    continue
                try:
                    translate_instruction(insn)
                except RecompError as exc:
                    blocker = {'address': insn.address, 'mnemonic': insn.mnemonic,
                               'reason': str(exc)}
                    node['blockers'].append(blocker)
                    if insn.mnemonic not in FORGIVEN:
                        node['optimistic_blockers'].append(blocker)
            analyze_cfg(instructions, *key)
        except RecompError as exc:
            blocker = {'reason': str(exc)}
            node['blockers'].append(blocker)
            node['optimistic_blockers'].append(blocker)

    relocation_addresses = sorted(r['address'] for r in inventory['relocations'])
    for node in nodes.values():
        index = bisect_left(relocation_addresses, node['address'])
        if index < len(relocation_addresses) and relocation_addresses[index] < node['address'] + node['size']:
            blocker = {'reason': 'code relocations require a linker-aware backend'}
            node['blockers'].append(blocker)
            node['optimistic_blockers'].append(blocker)

    entries = {}
    for key in nodes:
        entries.setdefault(key[0], []).append(key)
    plt = image.elf.get_section_by_name('.plt')
    plt_range = (plt['sh_addr'], plt['sh_addr'] + plt['sh_size']) if plt else (0, 0)
    target_counts = Counter()
    for node in nodes.values():
        for call in node['calls']:
            target = call['target']
            if target in entries:
                kind = 'defined_symbol_entry' if len(entries[target]) == 1 else 'ambiguous_entry'
                call['target_functions'] = [
                    {k: nodes[key][k] for k in ('address', 'size', 'symbols')}
                    for key in entries[target]]
            elif plt_range[0] <= target < plt_range[1]:
                kind = 'plt_entry_requires_indirect_dispatch'
            else:
                kind = 'not_a_defined_function_entry'
            call['kind'] = kind
            target_counts[kind] += 1

    def closure(root, optimistic):
        visited, active = set(), set()
        def visit(key):
            if key in active:
                return {'reason': 'recursive call cycle', 'function': key[0]}
            if key in visited:
                return None
            active.add(key)
            node = nodes[key]
            blockers = node['optimistic_blockers' if optimistic else 'blockers']
            if blockers:
                return {'reason': 'function body blocked', 'function': key[0],
                        'first_blocker': blockers[0]}
            for call in node['calls']:
                if call['kind'] != 'defined_symbol_entry':
                    return {'reason': call['kind'], 'function': key[0], 'call': call}
                failure = visit(entries[call['target']][0])
                if failure:
                    return failure
            active.remove(key)
            visited.add(key)
            return None
        failure = visit(root)
        return {'failure': failure, 'closure': [list(k) for k in sorted(visited)]}

    candidates = []
    for key, node in nodes.items():
        if node['calls']:
            candidates.append({**node, 'current_instructions_plus_bl': closure(key, False),
                               'optimistic_memory_plus_bl': closure(key, True)})
    profiles = {}
    for profile in ('current_instructions_plus_bl', 'optimistic_memory_plus_bl'):
        profiles[profile] = {'eligible_closures': sum(c[profile]['failure'] is None for c in candidates),
                             'first_failure_counts': dict(Counter(
                                 c[profile]['failure']['reason'] for c in candidates
                                 if c[profile]['failure']))}
    return {'input_sha256': inventory['sha256'], 'backend': BACKEND,
            'scan_identity_checked': True, 'semantic_verification': 'not_verified',
            'scope': 'all defined nonzero STT_FUNC ranges, aliases merged only at identical address and size',
            'optimistic_screen': 'BL plus all load/store/pair forms forgiven; CFG, other instructions and exact symbol entries still required; NOT implemented support',
            'function_ranges': len(nodes), 'nonleaf_direct_call_ranges': len(candidates),
            'direct_target_counts': dict(target_counts), 'profiles': profiles,
            'candidates': sorted(candidates, key=lambda c: (c['size'], c['address']))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'config/recomp.json')
    parser.add_argument('--scan', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if config['guest'] != 'aarch64-linux-android' or config['host'] != 'x86_64-linux':
        raise RecompError('unsupported configured guest/host')
    binary = Path(config['input'])
    if not binary.is_absolute():
        binary = args.config.resolve().parent.parent / binary
    data = binary.read_bytes()
    if hashlib.sha256(data).hexdigest() != config['sha256']:
        raise RecompError('input hash does not match pinned configuration')
    report = audit(Image(data), json.loads(args.scan.read_text()))
    payload = json.dumps(report, indent=2) + '\n'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Publication follows complete validation; failures preserve previous evidence.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=args.output.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
        temporary.replace(args.output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print(json.dumps({k: report[k] for k in ('input_sha256', 'function_ranges',
                                            'nonleaf_direct_call_ranges', 'direct_target_counts', 'profiles')}, indent=2))


if __name__ == '__main__':
    main()
