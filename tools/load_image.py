#!/usr/bin/env python3
"""Load and byte-check the configured guest image, without executing guest code."""

import argparse
import json
from pathlib import Path
import subprocess

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
    result = subprocess.run([str(args.runner.resolve()), str(ROOT / config['input']),
                             config['sha256'], str(args.load_bias)],
                            check=True, capture_output=True, text=True)
    report = json.loads(result.stdout)
    if report['ready_to_execute']:
        raise RuntimeError('data loader incorrectly reported execution readiness')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(f"Loaded {report['segments']} PT_LOAD segments; checked "
          f"{report['file_bytes_checked']} file bytes and {report['bss_bytes_checked']} BSS bytes; "
          f"{len(report['imports'])} unresolved imports, "
          f"{len(report['relocations'])} unresolved relocations; ready_to_execute=false")


if __name__ == '__main__':
    main()
