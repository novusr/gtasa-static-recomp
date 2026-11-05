#!/usr/bin/env python3
"""Explicit native inventory-only report; no Python ELF acceptance or decoding."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--instance-id', required=True)
    parser.add_argument('--load-bias', required=True, type=lambda v: int(v, 0))
    parser.add_argument('--max-records', type=int, default=1000000)
    parser.add_argument('--max-storage-bytes', type=int, default=268435456)
    parser.add_argument('--runner', type=Path, default=ROOT / 'build/recomp_inventory_image')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not args.instance_id:
        parser.error('instance ID must be nonempty')
    result = subprocess.run([str(args.runner.resolve()), str(args.input.resolve()), args.sha256,
                             str(args.load_bias), str(args.max_records), str(args.max_storage_bytes)],
                            capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'native inventory failed')
    report = json.loads(result.stdout)
    if report['profile'] != 'native-relocation-inventory-only-v1' or report['ready_to_execute']:
        raise RuntimeError('unexpected native profile')
    report['instance_id'] = args.instance_id
    report['input'] = str(args.input.resolve())
    payload = json.dumps(report, indent=2) + '\n'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=args.output.parent, delete=False) as stream:
            temporary = stream.name
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, args.output)
        temporary = None
    finally:
        if temporary is not None:
            os.unlink(temporary)
    print(f"Inventory-only: {report['decoded_count']} records; application-not-supported; readiness=false")


if __name__ == '__main__':
    main()
