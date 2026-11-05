#!/usr/bin/env python3
"""Load and byte-check the configured guest image, without executing guest code."""

import argparse
import json
from pathlib import Path
import subprocess
import hashlib
import struct
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner', type=Path, default=ROOT / 'build/recomp_image_smoke')
    parser.add_argument('--load-bias', required=True, type=lambda s: int(s, 0))
    parser.add_argument('--output', type=Path, default=ROOT / 'generated/image-load.json')
    args = parser.parse_args()
    if not 0 <= args.load_bias < 1 << 64:
        parser.error('load bias must be an unsigned 64-bit guest address')
    config = json.loads((ROOT / 'config/recomp.json').read_text())
    # Native loader verifies this exact file buffer before parsing or mapping.
    source = (ROOT / config['input']).read_bytes()
    if hashlib.sha256(source).hexdigest() != config['sha256']:
        raise RuntimeError('independent smoke input SHA-256 mismatch')
    # Decode sections and symbols directly with struct, independently of the
    # native inventory. Python signed arbitrary-precision sums are reduced last.
    expected = []
    pending = []
    shoff = struct.unpack_from('<Q', source, 40)[0]
    shnum = struct.unpack_from('<H', source, 60)[0]
    sections = [struct.unpack_from('<IIQQQQIIQQ', source, shoff + i * 64)
                for i in range(shnum)]

    def symbol(table, index):
        _, kind, _, _, offset, size, link, _, _, stride = sections[table]
        if kind not in (2, 11) or stride != 24 or index >= size // stride:
            raise RuntimeError('invalid independent symbol reference')
        name, info, other, section, value, length = struct.unpack_from(
            '<IBBHQQ', source, offset + index * stride)
        strings = sections[link]
        name = source[strings[4] + name:strings[4] + strings[5]].split(b'\0', 1)[0].decode('latin1')
        binding, typ, visibility = info >> 4, info & 15, other & 3
        reason = ''
        if not index or not section: reason = 'undefined_symbol'
        elif typ == 10: reason = 'ifunc_unsupported'
        elif typ == 6: reason = 'tls_unsupported'
        elif typ == 5 or section == 0xfff2: reason = 'common_unsupported'
        elif typ > 3: reason = 'symbol_type_unsupported'
        elif binding > 2: reason = 'symbol_binding_unsupported'
        elif other & ~3: reason = 'symbol_attributes_unsupported'
        elif binding == 0 and visibility == 3: reason = 'local_protected_invalid'
        elif binding and not visibility: reason = 'preemptible_symbol'
        elif section >= 0xff00 and section != 0xfff1: reason = 'special_section_unsupported'
        elif section != 0xfff1:
            defining = sections[section]
            if defining[2] & 0x400: reason = 'tls_unsupported'
            elif not defining[2] & 2: reason = 'nonallocated_symbol_section'
            elif not defining[3] <= value <= defining[3] + defining[5] - length:
                reason = 'symbol_outside_section'
        if not reason and any(s[1] == 0x6fffffff and s[6] == table for s in sections):
            reason = 'symbol_versioning_unsupported'
        return dict(name=name, table_section=table, table_type=kind, index=index,
                    value=value, size=length, section_index=section, binding=binding,
                    type=typ, visibility=visibility, other=other, resolution_reason=reason)

    expected_imports = []
    for table, section in enumerate(sections):
        if section[1] != 11:
            continue
        for index in range(section[5] // 24):
            entry = symbol(table, index)
            if entry['section_index'] == 0 and entry['name']:
                expected_imports.append(dict(symbol=entry['name'], symbol_index=index,
                                             binding=entry['binding'], type=entry['type'],
                                             status='unresolved'))

    for section in sections:
        _, kind, _, _, offset, size, table, _, _, stride = section
        if kind not in (4, 9):
            continue
        for position in range(offset, offset + size, stride):
            target, info = struct.unpack_from('<QQ', source, position)
            typ, index = info & 0xFFFFFFFF, info >> 32
            addend = struct.unpack_from('<q', source, position + 16)[0] if kind == 4 else 0
            definition = symbol(table, index)
            reason = ''
            if kind == 9: reason = 'rel_implicit_addend_unsupported'
            elif typ == 1027:
                if index: raise RuntimeError('RELATIVE symbol index is nonzero')
            elif typ not in (257, 1025, 1026): reason = 'relocation_type_unsupported'
            elif definition['resolution_reason']: reason = definition['resolution_reason']
            elif typ == 1026 and addend: reason = 'jump_slot_addend_policy_unsupported'
            if reason:
                pending.append(dict(address=args.load_bias + target, type=typ,
                                    symbol_index=index, symbol=definition['name'],
                                    addend_bits=addend % (1 << 64), has_addend=kind == 4,
                                    status='unresolved', reason=reason, definition=definition))
                continue
            base = args.load_bias if typ == 1027 else definition['value'] + (
                0 if definition['section_index'] == 0xfff1 else args.load_bias)
            value = (base + addend) % (1 << 64)
            expected.append(dict(address=args.load_bias + target, type=typ,
                                 addend_bits=addend % (1 << 64), value=value,
                                 bytes=list(value.to_bytes(8, 'little')), status='applied',
                                 definition=definition))
    result = subprocess.run([str(args.runner.resolve()), str(ROOT / config['input']),
                             config['sha256'], str(args.load_bias), '536870912', '--all'],
                            check=True, capture_output=True, text=True)
    report = json.loads(result.stdout)
    if report['ready_to_execute']:
        raise RuntimeError('data loader incorrectly reported execution readiness')
    if report['applied_relocations'] != expected:
        raise RuntimeError('relocation results differ from independent file expectations')
    if report['relocations'] != pending:
        raise RuntimeError('unresolved metadata/reasons differ from independent ELF decode')
    if report['imports'] != expected_imports:
        raise RuntimeError('unresolved imports differ from independent ELF symbol decode')
    report['relative_values_checked'] = sum(r['type'] == 1027 for r in expected)
    report['symbol_values_checked'] = sum(r['type'] != 1027 for r in expected)
    counts = Counter({str(typ): 0 for typ in (257, 1025, 1026, 1027)})
    counts.update(str(r['type']) for r in expected)
    report['applied_per_type'] = dict(counts)
    report['unresolved_per_reason'] = dict(Counter(r['reason'] for r in pending))
    report['relocation_oracle'] = 'independent ELF RELA decode with signed Python integer arithmetic'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(f"Loaded {report['segments']} PT_LOAD segments; checked "
          f"{report['file_bytes_checked']} file bytes and {report['bss_bytes_checked']} BSS bytes; "
          f"{len(report['imports'])} unresolved imports, "
          f"applied per type {report['applied_per_type']}, "
          f"unresolved per reason {report['unresolved_per_reason']}, "
          f"{len(report['relocations'])} unresolved relocations; ready_to_execute=false")


if __name__ == '__main__':
    main()
