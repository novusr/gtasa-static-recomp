# GTA: San Andreas 2.10 (v34) Android ARM64 1:1 Byte-Matching Decompilation

This repository is dedicated to the exact 1:1 byte-for-byte binary matching decompilation of `libGTASA.so` from Grand Theft Auto: San Andreas v2.10 (v34) Android ARM64 (`arm64-v8a`).

Every decompiled C++ function is compiled with the game's original compiler toolchain and verified against the original binary using `objdiff`. A function is considered complete only when its compiled machine code is 100% identical in byte layout, instruction selection, register allocation, and scheduling.

---

## Target Binary

* **File**: `libGTASA.so`
* **Format**: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, unstripped
* **Size**: 49,784,160 bytes
* **SHA-256**: `12527bfdb63889c02d24366629e808cb446d354a2b380348bd661da4edc6af11`
* **SHA-1**: `397e4c6984cc2c8641c17b7502c621f45d6ae3d4`
* **Debug Info**: Native DWARF 4 and complete `.symtab` symbol table (24,061 total symbols).

---

## Toolchain & Requirements

### 1. Matching Compiler
The original binary was compiled with Android Clang 5.0 on Windows/Linux (NVIDIA Nsight / NDK r16b). To reproduce exact machine instructions:
* **Toolchain**: **Android NDK r16b** (`r16b-linux-x86_64`)
* **Compiler**: Clang `5.0.300080` (`$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++`)
* **Assembler**: GNU as 2.27 (`$NDK/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin/aarch64-linux-android-as`)

### 2. Verified Compiler Flags
The following compiler flags have been calibrated and proven to produce 100.0% binary matching output:
```bash
clang++ \
  -target aarch64-linux-android \
  -std=c++11 \
  -O3 \
  -ffp-contract=fast \
  -fno-math-errno \
  -fno-strict-aliasing \
  -fno-exceptions \
  -fno-rtti \
  -fPIC \
  -Iinclude
```
* `-ffp-contract=fast`: Crucial. Enables fusing `fmul` and `fsub`/`fadd` into ARM64 `fnmsub` and `fmadd` instructions.
* `-fno-math-errno`: Crucial. Prevents Clang from generating `bl sqrtf` fallback branches and stack frames for floating point math functions like `sqrtf`.

### 3. Verification & Analysis Tools
* **`objdiff-cli`** (v3.8.3+): Standalone tool used to compare compiled object files against original binary slices.
* **Ghidra**: Running instance with MCP/HTTP REST server on `http://127.0.0.1:8089` for instant (<20ms) decompiler output and disassembly queries.

---

## Repository Structure

```text
├── .gitignore
├── AGENTS.md             # Guidelines and rules for AI agents and human contributors
├── README.md             # Project overview and setup instructions
├── docs/                 # Detailed architectural and compiler documentation
│   ├── ARCHITECTURE.md   # ABI, struct layouts, and RenderWare types
│   ├── COMPILER.md       # Clang 5.0 flags and code-generation quirks
│   ├── PROGRESS.md       # Verified matched functions log
│   └── WORKFLOW.md       # Step-by-step matching guide
├── include/              # Clean C++11 header definitions
│   ├── CMatrix.h
│   └── CVector.h
├── src/                  # Decompiled C++ source files
│   ├── CrossProduct.cpp
│   ├── Multiply3x3.cpp
│   └── Normalise.cpp
└── tools/                # Automation and matching utilities
    └── matcher.py        # Workbench tool connecting Ghidra, NDK r16b, and objdiff
```

---

## Quickstart

### 1. Fetching Function Details
To query Ghidra for a function's decompiled C++ draft and assembly instructions:
```bash
python3 tools/matcher.py fetch 006390c8
```

### 2. Testing & Diffing a Function
To slice the original bytes from `libGTASA.so`, compile your C++ implementation, and diff with `objdiff-cli`:
```bash
python3 tools/matcher.py test 006390c8 --symbol _ZN7CVector9NormaliseEv
```

### 3. Generating Progress Report
To run a full progress check across all configured units:
```bash
objdiff-cli report generate -p . -o -
```

---

## Progress

| Class / Unit | Function | Address | Size | Status |
| :--- | :--- | :--- | :--- | :--- |
| `CVector` | `CrossProduct(const CVector&, const CVector&)` | `0x00538ec4` | 44 B | **100.0% MATCH** |
| `CMatrix` | `Multiply3x3(const CMatrix&, const CVector&)` | `0x00538ef0` | 72 B | **100.0% MATCH** |
| `CVector` | `CVector::Normalise()` | `0x005390c8` | 76 B | **100.0% MATCH** |

Total Verified Code: **192 bytes (100.0% match across 3 functions)**.
