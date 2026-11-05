# GTA:SA 2.10 — Static Recompilation for Linux x86_64

This branch translates selected instructions from the Android ARM64
`libGTASA.so` into C++ ahead of time and builds native Linux x86_64 code.
It replaces the byte-matching workflow on `main`; it does not require manually
reconstructing every function before executing translated code.

**Current state: a tested leaf-function prototype, not a playable GTA executable.**
The supported subset recompiles the original `CrossProduct` and `Multiply3x3`
instructions. The next stages are control-flow recovery, a broader instruction
backend, ELF relocation/loading, guest-to-host ABI bridges and platform services.

## What is here

- `tools/recomp.py`: SHA-256 validation, ELF64 inventory and strict leaf lifting.
- `config/recomp.json`: exact input identity, target and selected symbols.
- `include/recomp/runtime.h`, `src/runtime.cpp`: explicit guest register state,
  checked little-endian guest memory and scalar FP operations.
- `CMakeLists.txt`: host C++11 build, independent of the Android NDK.
- `tests/`: synthetic ELF/lifter checks and a native semantic smoke executable.
- `tools/verify_leaf.py`: differential comparison with original ARM64 instructions
  using Unicorn as a test oracle. Unicorn is not used by the host runtime.
- `docs/ARCHITECTURE.md`: contracts, limits and platform boundaries.
- `docs/ROADMAP.md`: remaining work towards a game executable.

The old objdiff configuration, per-class stubs, matcher, symbol grouping and
Android matching Makefile have been removed from this branch. They remain on
`main` and in Git history. This worktree does not run decompdecomp agents.

## Build and verify

Requirements: Linux x86_64, CMake 3.20+, Ninja, a C++11 compiler, and `uv`.
Python dependencies and the test oracle are pinned in `uv.lock`.

Place the original `libGTASA.so` in `inputs/` (a local symlink also works).
The configured SHA-256 is checked before analysis or lifting. File paths in the
config are resolved relative to the project root, not the shell's working directory.

```bash
uv sync --locked
uv run python tools/recomp.py inspect --output generated/inventory.json
uv run python tools/recomp.py lift --output generated
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
uv run python -m unittest discover -s tests -p 'test_*.py'
uv run python tools/verify_leaf.py
```

`build/recomp_leaf_smoke` executes generated native functions. It checks 2,048
calls and memory bounds. The separate oracle compares 6,144 binary32 result words
against execution of the original instructions. These use deterministic finite,
integer-valued inputs; they are not proof of every floating-point corner case.
The native executable runs without opening `libGTASA.so`, Ghidra or Python.

Unsupported instructions, incomplete decoding, unsafe load forms and code
relocations are rejected before translation output is written. A failed lift
returns nonzero; any previous generated files still describe the earlier input.
Do not build after a failed generation step. No interpreter fallback or Android
service stubs are provided.

## Source of truth

`inputs/libGTASA.so` is the guest executable input, not something loaded with
host `dlopen`. ELF virtual addresses are translated through `PT_LOAD` offsets;
BSS is never mistaken for file-backed code. The configured Ghidra image base is
an analysis coordinate only and is never added to guest runtime pointers.

The inventory includes defined function symbols from both `.symtab` and
`.dynsym`, preserves aliases, and separately reports unique addresses. Its totals
will differ from the old decomp queue, which used only `.dynsym` and collapsed
aliases. These totals are not decompilation percentages.

Generated C++, inventory, original binaries and assets are local ignored files.
Native output is expected to differ from ARM64 bytes: semantic equivalence and
runtime correctness are the validation goals for this branch.
