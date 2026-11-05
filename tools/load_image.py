#!/usr/bin/env python3
"""Load and byte-check the configured guest image, without executing guest code."""

import argparse
import json
from pathlib import Path
import subprocess
import hashlib
import struct

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
    # Parse RELA directly from the verified file, independent of native inventory
    # and arithmetic. Python integers retain the signed sum before width reduction.
    expected = []
    shoff = struct.unpack_from('<Q', source, 40)[0]
    shnum = struct.unpack_from('<H', source, 60)[0]
    for index in range(shnum):
        section = shoff + index * 64
        kind = struct.unpack_from('<I', source, section + 4)[0]
        if kind != 4:
            continue
        offset, size = struct.unpack_from('<QQ', source, section + 24)
        for position in range(offset, offset + size, 24):
            target, info, addend = struct.unpack_from('<QQq', source, position)
            if info & 0xFFFFFFFF != 1027:
                continue
            if info >> 32:
                raise RuntimeError('RELATIVE symbol index is nonzero')
            value = (args.load_bias + addend) % (1 << 64)
            expected.append(dict(address=args.load_bias + target,
                                 addend_bits=addend % (1 << 64), value=value,
                                 bytes=list(value.to_bytes(8, 'little')), status='applied'))
    result = subprocess.run([str(args.runner.resolve()), str(ROOT / config['input']),
                             config['sha256'], str(args.load_bias), '536870912', '--relocate'],
                            check=True, capture_output=True, text=True)
    report = json.loads(result.stdout)
    if report['ready_to_execute']:
        raise RuntimeError('data loader incorrectly reported execution readiness')
    if report['applied_relocations'] != expected:
        raise RuntimeError('RELATIVE results differ from independent file expectations')
    report['relative_values_checked'] = len(expected)
    report['relative_oracle'] = 'independent ELF RELA decode with signed Python integer arithmetic'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(f"Loaded {report['segments']} PT_LOAD segments; checked "
          f"{report['file_bytes_checked']} file bytes and {report['bss_bytes_checked']} BSS bytes; "
          f"{len(report['imports'])} unresolved imports, "
          f"{len(report['applied_relocations'])} applied RELATIVE, "
          f"{len(report['relocations'])} unresolved relocations; ready_to_execute=false")


if __name__ == '__main__':
    main()
