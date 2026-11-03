#!/usr/bin/env python3
"""High-speed byte-matching workbench runner for GTA SA 2.10 Android ARM64.
Bridges directly to live Ghidra instance (http://127.0.0.1:8089) and NDK r16b Clang.
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NDK = Path("/home/novusr/Android/Sdk/ndk/android-ndk-r16b")
CLANG = NDK / "toolchains/llvm/prebuilt/linux-x86_64/bin/clang++"
AS = NDK / "toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin/aarch64-linux-android-as"
OBJDIFF = Path("/home/novusr/.local/bin/objdiff-cli")
GHIDRA_URL = "http://127.0.0.1:8089"

CFLAGS = [
    "-target", "aarch64-linux-android",
    "-std=c++11",
    "-O3",
    "-ffp-contract=fast",
    "-fno-math-errno",
    "-fno-strict-aliasing",
    "-fno-exceptions",
    "-fno-rtti",
    "-fPIC",
    f"-I{ROOT}/include",
]

def ghidra_request(endpoint: str, payload: dict) -> dict:
    url = f"{GHIDRA_URL}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))

def fetch_function(ghidra_addr: str) -> tuple[str, list[dict]]:
    # Decompile
    dec_res = ghidra_request("/force_decompile", {"address": ghidra_addr, "program": "libGTASA.so"})
    c_code = dec_res.get("decompiled", "")
    fn_name = dec_res.get("name", "")

    # Disassembly
    dis_res = ghidra_request("/disassemble_function", {"address": ghidra_addr, "program": "libGTASA.so"})
    instructions = dis_res.get("instructions", [])
    resolved = dis_res.get("resolved_function", {})
    resolved_name = resolved.get("name", fn_name)

    return resolved_name, c_code, instructions

def extract_target_object(elf_path: Path, elf_vaddr: int, size: int, symbol: str, out_o: Path) -> None:
    bin_file = out_o.with_suffix(".bin")
    with open(elf_path, "rb") as f:
        f.seek(elf_vaddr)
        raw_bytes = f.read(size)
    bin_file.write_bytes(raw_bytes)

    s_file = out_o.with_suffix(".s")
    s_lines = [
        f".global {symbol}",
        f".type {symbol}, %function",
        f"{symbol}:",
        f'\t.incbin "{bin_file}"',
        f".size {symbol}, .-{symbol}\n",
    ]
    s_file.write_text("\n".join(s_lines))
    subprocess.run([str(AS), "-o", str(out_o), str(s_file)], check=True)

def compile_source(src_file: Path, out_o: Path) -> None:
    cmd = [str(CLANG), *CFLAGS, "-c", str(src_file), "-o", str(out_o)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print("Compile Error:\n", res.stderr)
        sys.exit(res.returncode)

def run_diff(target_o: Path, base_o: Path, symbol: str) -> dict:
    cmd = [
        str(OBJDIFF), "diff",
        "-1", str(target_o),
        "-2", str(base_o),
        symbol,
        "-o", "-",
        "--format", "json"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print("objdiff error:\n", res.stderr)
        return {}
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError:
        return {}

def main():
    parser = argparse.ArgumentParser(description="Match ARM64 game function byte-for-byte")
    parser.add_argument("action", choices=["fetch", "diff", "test"])
    parser.add_argument("address", help="Ghidra address (e.g. 006390c8)")
    parser.add_argument("--symbol", help="Mangled symbol name (e.g. _ZN7CVector9NormaliseEv)")
    parser.add_argument("--src", help="Source file path")
    args = parser.parse_args()

    name, c_code, instructions = fetch_function(args.address)
    print(f"=== Function: {name} (Address: {args.address}, {len(instructions)} instructions) ===")

    if args.action == "fetch":
        print("\n--- Decompiled C++ Draft from Ghidra ---")
        print(c_code)
        print("\n--- Assembly Listing ---")
        for inst in instructions:
            print(f"  {inst['address']}: {inst['instruction']}")

    elif args.action in ("diff", "test"):
        if not args.symbol:
            sys.exit("Error: --symbol is required for diff/test")
        
        target_o = ROOT / "expected" / f"{name}.o"
        elf_vaddr = int(args.address, 16) - 0x100000
        size = len(instructions) * 4
        extract_target_object(ROOT / "libGTASA.so", elf_vaddr, size, args.symbol, target_o)
        print(f"Target object extracted directly from libGTASA.so: {target_o} ({size} bytes)")

        src_path = Path(args.src) if args.src else ROOT / "src" / f"{name}.cpp"
        if not src_path.exists():
            sys.exit(f"Source file {src_path} not found")

        build_o = ROOT / "build" / f"{name}.o"
        compile_source(src_path, build_o)
        print(f"Source compiled: {build_o}")

        diff_res = run_diff(target_o, build_o, args.symbol)
        print(f"Diff complete for {args.symbol}!")

if __name__ == "__main__":
    main()
