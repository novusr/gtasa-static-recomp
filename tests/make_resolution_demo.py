#!/usr/bin/env python3
"""Write two synthetic ELF data fixtures and an explicit planner configuration."""
import argparse
import hashlib
import json
from pathlib import Path

from test_image import symbol_fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path('generated/resolution-demo'))
    args = parser.parse_args()
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    objects = []
    for oid, section, bias in (('A', 0, 0x100000000), ('B', 4, 0x200000000)):
        data = symbol_fixture(symbols=[dict(binding=1, section=section)],
                              second_symbols=[],
                              relocations=[(0x9000, 257, 1, 0, 2)] if oid == 'A' else [])
        path = directory / (oid + '.elf')
        path.write_bytes(data)
        objects.append(dict(object_id=oid, input=str(path),
                            sha256=hashlib.sha256(data).hexdigest(), load_bias=bias))
    config = dict(objects=objects, lookup_scope=['A', 'B'], guest_page_size=4096,
                  references=[dict(object_id='A', table_section=2, index=1)])
    (directory / 'config.json').write_text(json.dumps(config, indent=2) + '\n')


if __name__ == '__main__':
    main()
