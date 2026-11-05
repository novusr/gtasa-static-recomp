#!/usr/bin/env python3
"""Compare compiled host leaf output against the original ARM64 instructions.

Unicorn is a test oracle only. The generated executable does not link or use it.
The corpus covers finite integer-valued binary32 operands, not all FPCR modes.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn import arm64_const as arm

from recomp import Image, ROOT


def verify(config_path, executable):
    config = json.loads(config_path.read_text())
    binary = Path(config['input'])
    if not binary.is_absolute():
        binary = config_path.resolve().parent.parent / binary
    data = binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != config['sha256']:
        raise ValueError('input hash does not match the recompilation configuration')
    manifest = json.loads((ROOT / 'generated/manifest.json').read_text())
    if manifest['input_sha256'] != digest:
        raise ValueError('generated code and oracle input use different binaries')
    image = Image(data)
    functions = {f['symbol']: f for f in image.functions()}
    selected = {f['output']: functions[f['symbol']] for f in config['functions']}
    code = {}
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    cpu.reg_write(arm.UC_ARM64_REG_CPACR_EL1, 3 << 20)
    cpu.mem_map(4096, 4096)
    mapped = set()
    for name in ('cross_product', 'multiply3x3'):
        fn = selected[name]
        for page in range(fn['address'] & ~4095, (fn['address'] + fn['size'] + 4095) & ~4095, 4096):
            if page not in mapped:
                cpu.mem_map(page, 4096)
                mapped.add(page)
        cpu.mem_write(fn['address'], image.read(fn['address'], fn['size'], executable=True))
        code[name] = fn

    def run(name, x0, x1):
        fn = code[name]
        cpu.reg_write(arm.UC_ARM64_REG_X0, x0)
        cpu.reg_write(arm.UC_ARM64_REG_X1, x1)
        end = fn['address'] + fn['size']
        cpu.reg_write(arm.UC_ARM64_REG_X30, end)
        cpu.emu_start(fn['address'], end, count=fn['size'] // 4)
        if cpu.reg_read(arm.UC_ARM64_REG_PC) != end:
            raise ValueError('ARM oracle did not return at the expected instruction boundary')
        return [cpu.reg_read(getattr(arm, f'UC_ARM64_REG_S{i}')) for i in range(3)]

    seed = 1

    def sample():
        nonlocal seed
        seed = (seed * 1664525 + 1013904223) & 0xFFFFFFFF
        return float(((seed >> 16) % 201) - 100)

    def put(address, value):
        cpu.mem_write(address, struct.pack('<f', value))

    native = subprocess.check_output([str(executable.resolve()), '--vectors'], text=True).splitlines()
    if len(native) != 1024:
        raise ValueError('native test did not produce the expected corpus size')
    for trial in range(1024):
        for i in range(3):
            put(4096 + i * 4, sample())
            put(4128 + i * 4, sample())
        expected = run('cross_product', 4096, 4128)
        for i in range(9):
            put(4160 + (i // 3) * 16 + (i % 3) * 4, sample())
        expected += run('multiply3x3', 4160, 4128)
        actual = [int(value) for value in native[trial].split()]
        if expected != actual:
            raise ValueError(f'trial {trial}: ARM {expected} differs from host {actual}')
    print('2048 function calls / 6144 result words agree with the original ARM64 instructions')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'config/recomp.json')
    parser.add_argument('--executable', type=Path, default=ROOT / 'build/recomp_leaf_smoke')
    args = parser.parse_args()
    verify(args.config, args.executable)
