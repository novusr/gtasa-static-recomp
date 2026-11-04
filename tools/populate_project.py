#!/usr/bin/env python3
"""Populates full expected objects, stub sources, config/symbols.json, and objdiff.json
for GTA SA 2.10 Android ARM64 using libGTASA.so symbol definitions and GNU as direct .incbin slicing.
"""

import collections
import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from elftools.elf.elffile import ELFFile

ROOT = Path("/home/novusr/Documents/gtasa-210-byte-m")
SO_PATH = ROOT / "libGTASA.so"
AS = Path("/home/novusr/Android/Sdk/ndk/android-ndk-r16b/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin/aarch64-linux-android-as")
EXPECTED_DIR = ROOT / "expected"
UNITS_DIR = EXPECTED_DIR / "units"
SRC_UNITS_DIR = ROOT / "src" / "units"
BUILD_UNITS_DIR = ROOT / "build" / "units"
CONFIG_DIR = ROOT / "config"

UNITS_DIR.mkdir(parents=True, exist_ok=True)
SRC_UNITS_DIR.mkdir(parents=True, exist_ok=True)
BUILD_UNITS_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

ALREADY_MATCHED = {
    "_Z12CrossProductRK7CVectorS1_": "CrossProduct",
    "_Z11Multiply3x3RK7CMatrixRK7CVector": "Multiply3x3",
    "_ZN7CVector9NormaliseEv": "Normalise",
}

def collect_symbols():
    with open(SO_PATH, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".dynsym")
        classes = collections.defaultdict(list)
        free_funcs = collections.defaultdict(list)
        seen = set()
        symbol_map = {}

        for s in symtab.iter_symbols():
            if s["st_info"]["type"] == "STT_FUNC" and s["st_size"] > 0 and s["st_value"] > 0:
                if s["st_value"] in seen:
                    continue
                seen.add(s["st_value"])
                name = s.name
                vaddr = int(s["st_value"])
                size = int(s["st_size"])

                if name in ALREADY_MATCHED:
                    symbol_map[name] = {
                        "vaddr": vaddr,
                        "ghidra_addr": f"{vaddr + 0x100000:08x}",
                        "size": size,
                        "unit": ALREADY_MATCHED[name],
                    }
                    continue

                unit_name = None
                if name.startswith("_ZN"):
                    rest = name[3:]
                    num_str = ""
                    while rest and rest[0].isdigit():
                        num_str += rest[0]
                        rest = rest[1:]
                    if num_str:
                        n = int(num_str)
                        cls_name = rest[:n]
                        unit_name = cls_name
                        classes[cls_name].append((vaddr, size, name))
                    else:
                        unit_name = "FreeFunctions"
                        free_funcs[unit_name].append((vaddr, size, name))
                elif name.startswith(("Rw", "_Rw")):
                    unit_name = "RenderWare_Rw"
                    free_funcs[unit_name].append((vaddr, size, name))
                elif name.startswith(("Rp", "_Rp")):
                    unit_name = "RenderWare_Rp"
                    free_funcs[unit_name].append((vaddr, size, name))
                elif name.startswith(("Rt", "_Rt")):
                    unit_name = "RenderWare_Rt"
                    free_funcs[unit_name].append((vaddr, size, name))
                elif name.startswith(("OS_", "AND_", "NV_")):
                    unit_name = "OSWrapper"
                    free_funcs[unit_name].append((vaddr, size, name))
                elif name.startswith(("al", "alc")):
                    unit_name = "OpenAL"
                    free_funcs[unit_name].append((vaddr, size, name))
                elif name.startswith("_Z"):
                    unit_name = "CppFreeFunctions"
                    free_funcs[unit_name].append((vaddr, size, name))
                else:
                    unit_name = "GlobalFunctions"
                    free_funcs[unit_name].append((vaddr, size, name))

                symbol_map[name] = {
                    "vaddr": vaddr,
                    "ghidra_addr": f"{vaddr + 0x100000:08x}",
                    "size": size,
                    "unit": unit_name,
                }

    return classes, free_funcs, symbol_map

def assemble_unit(args):
    name, fns = args
    s_path = UNITS_DIR / f"{name}.s"
    o_path = UNITS_DIR / f"{name}.o"
    cpp_path = SRC_UNITS_DIR / f"{name}.cpp"

    if not cpp_path.exists():
        cpp_path.write_text("", encoding="utf-8")

    if not o_path.exists():
        lines = []
        for vaddr, size, sym in sorted(fns, key=lambda x: x[0]):
            lines.append(f".global {sym}")
            lines.append(f".type {sym}, %function")
            lines.append(f"{sym}:")
            lines.append(f'\t.incbin "{SO_PATH}", {vaddr}, {size}')
            lines.append(f".size {sym}, .-{sym}\n")

        s_path.write_text("\n".join(lines), encoding="utf-8")
        subprocess.run([str(AS), "-o", str(o_path), str(s_path)], check=True)

    return name, str(o_path.relative_to(ROOT))

def main():
    print("Collecting symbols from libGTASA.so...")
    classes, free_funcs, symbol_map = collect_symbols()

    (CONFIG_DIR / "symbols.json").write_text(json.dumps(symbol_map, indent=2), encoding="utf-8")
    print(f"Saved {len(symbol_map)} symbols to config/symbols.json.")

    total_cls_fns = sum(len(v) for v in classes.values())
    total_free_fns = sum(len(v) for v in free_funcs.values())
    total_fns = total_cls_fns + total_free_fns + len(ALREADY_MATCHED)
    print(f"Total functions: {total_fns} across {len(classes)} classes and {len(free_funcs)} free groups.")

    work_items = list(classes.items()) + list(free_funcs.items())
    print(f"Preparing {len(work_items)} expected units and source stubs...")
    t0 = time.time()
    unit_targets = []
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 8) as executor:
        for unit_name, rel_path in executor.map(assemble_unit, work_items):
            unit_targets.append((unit_name, rel_path))

    print(f"Prepared {len(unit_targets)} units in {time.time() - t0:.2f}s.")

    units = [
        {
            "name": "CrossProduct",
            "target_path": "expected/CrossProduct.o",
            "base_path": "build/CrossProduct.o",
            "metadata": {
                "source_path": "src/CrossProduct.cpp",
                "complete": True
            }
        },
        {
            "name": "Multiply3x3",
            "target_path": "expected/Multiply3x3.o",
            "base_path": "build/Multiply3x3.o",
            "metadata": {
                "source_path": "src/Multiply3x3.cpp",
                "complete": True
            }
        },
        {
            "name": "Normalise",
            "target_path": "expected/Normalise.o",
            "base_path": "build/Normalise.o",
            "metadata": {
                "source_path": "src/Normalise.cpp",
                "complete": True
            }
        }
    ]

    for unit_name, rel_path in sorted(unit_targets):
        units.append({
            "name": unit_name,
            "target_path": rel_path,
            "base_path": f"build/units/{unit_name}.o",
            "metadata": {
                "source_path": f"src/units/{unit_name}.cpp"
            }
        })

    objdiff_cfg = {
        "min_version": "2.0.0",
        "target_dir": "expected",
        "base_dir": "build",
        "build_target": False,
        "custom_make": "make",
        "units": units
    }

    out_file = ROOT / "objdiff.json"
    out_file.write_text(json.dumps(objdiff_cfg, indent=2), encoding="utf-8")
    print(f"Updated objdiff.json with {len(units)} units.")

if __name__ == "__main__":
    main()
