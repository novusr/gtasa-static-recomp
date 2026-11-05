# GTA:SA 2.10 — Static Recompilation for Linux x86_64

This branch translates selected instructions from the Android ARM64
`libGTASA.so` into C++ ahead of time and builds native Linux x86_64 code.
It replaces the byte-matching workflow on `main`; it does not require manually
reconstructing every function before executing translated code.

**Current state: a tested leaf-function and intrafunction control-flow prototype, not a playable GTA executable.**
The supported subset recompiles the original `CrossProduct`, `Multiply3x3`,
five register-only integer leaves, eight integer-memory leaves, and five
control-flow functions with branches/multiple RETs selected in the configuration.
The next stages are cyclic control-flow (loops), switch/jump tables, a broader
instruction backend, further ELF relocation support, guest-to-host ABI bridges
and platform services. PT_LOAD/BSS data loading, explicit RELA RELATIVE and bounded internal-symbol
ABS64/GLOB_DAT/JUMP_SLOT fixups and explicit transactional PT_GNU_RELRO write
removal are now available; these do not authorize initialization or execution.

## What is here

- `tools/recomp.py`: SHA-256 validation, ELF64 inventory, backend capability scan
  and strict AOT lifting with basic block formation and CFG validation.
- `config/recomp.json`: exact input identity, target and selected symbols.
- `include/recomp/runtime.h`, `src/runtime.cpp`: explicit guest register state,
  checked little-endian guest memory and scalar FP operations.
- `include/recomp/elf_image.h`, `src/elf_image.cpp`: hash-verified PT_LOAD/BSS
  loading with explicit bias, checked segment storage, transactional RELA RELATIVE
  and internal-symbol fixups, separate applied/unresolved inventories and explicit
  guest-page RELRO sealing.
- `tools/load_image.py`: original-image data/relocation/RELRO smoke test and applied/unresolved report.
- `docs/ELF_LOADING.md`: loader contracts, verification and remaining linker work.
- `CMakeLists.txt`: host C++11 build, independent of the Android NDK.
- `tests/`: synthetic ELF/lifter checks, control-flow semantics and native smoke tests.
- `tools/verify_leaf.py`: differential comparison with original ARM64 instructions
  using Unicorn as a test oracle. Unicorn is not used by the host runtime.
- `tools/verify_integer.py`: fresh C++11 native runner versus original integer
  leaves, with boundary/random register inputs and an evidence report.
- `tools/verify_memory.py`: compares integer-memory leaves against ARM64,
  including all represented registers and every byte of the guest sandbox.
- `tools/verify_control_flow.py`: compares control-flow leaves with Unicorn ARM64,
  including both taken and fallthrough branch paths, multiple RETs, and memory mutations.
- `docs/ARCHITECTURE.md`: contracts, limits and platform boundaries.
- `docs/ROADMAP.md`: remaining work towards a game executable.

The old objdiff configuration, per-class stubs, matcher, symbol grouping and
Android matching Makefile have been removed from this branch. They remain on
`main` and in Git history. This worktree does not run decompdecomp agents.

## Build and verify

Requirements: Linux x86_64, CMake 3.20+, Ninja, a C++11 compiler, OpenSSL development headers/libcrypto, and `uv`.
Python dependencies and the test oracle are pinned in `uv.lock`.

Place the original `libGTASA.so` in `inputs/` (a local symlink also works).
The configured SHA-256 is checked before analysis or lifting. File paths in the
config are resolved relative to the project root, not the shell's working directory.

```bash
uv sync --locked
uv run python tools/recomp.py inspect --output generated/inventory.json
uv run python tools/recomp.py scan --output generated/scan.json
uv run python tools/recomp.py lift --output generated
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
uv run python -m unittest discover -s tests -p 'test_*.py'
python3 tools/load_image.py --load-bias 0x100000000 --guest-page-size 0x1000 --output generated/image-load.json
uv run python tools/verify_leaf.py
uv run python tools/verify_integer.py
uv run python tools/verify_memory.py
uv run python tools/verify_control_flow.py
```

`build/recomp_leaf_smoke` executes generated native functions. It checks 2,048
calls and memory bounds. The separate oracle compares 6,144 binary32 result words
against execution of the original instructions. These use deterministic finite,
integer-valued inputs; they are not proof of every floating-point corner case.
The native executable runs without opening `libGTASA.so`, Ghidra or Python.

The integer backend supports W/X register moves, MOVZ/MOVN constants, SP copies,
and non-flag-setting ADD/SUB immediate or LSL register operands. W/WSP writes
zero-extend; arithmetic wraps at the guest register width. Encoding determines
whether register 31 means SP or ZR. See the exact forms and exclusions in
`docs/ARCHITECTURE.md`.

The Python suite includes 244 synthetic integer leaves/sequences, tested against
explicit expected register states and Unicorn over 152 inputs each (37,088
calls). It covers overflow/underflow, upper-half clearing, SP versus ZR,
discarded ZR writes, overlapping registers, immediate/shift boundaries and all
16 NZCV patterns. Rejection tests keep unsupported forms blocked in both scan
and lift. These tests require `c++` on PATH and compile a temporary C++11 runner.

`verify_integer.py` separately checks five original leaves from the hash-validated
binary: `_rwCPUHaveMMX`, `png_access_version_number`, `GetMaxStorage`,
`RpMTEffectGetName`, and `CCamera::GetGameCamPosition`. It lifts the non-FP
configuration selections afresh, compiles a temporary executable and compares
760 calls, including all represented registers and unchanged NZCV. Evidence is
written to ignored `generated/integer-verification.json` with input hash,
backend and exact symbol ranges. The fresh executable does not use Unicorn or
read guest bytes at runtime. These register-only leaves exercise MOV and ADD;
the synthetic corpus covers SUB, as does original `ShaderSort` in the memory
oracle below. Constant returns here reproduce the
original instructions; they are not replacements for unresolved imports.

Integer memory support adds LDR/STR W/X, LDRB/STRB and LDRH/STRH using the
unsigned scaled imm12 encoding with an X/SP base and no writeback. Literal,
register-offset, unscaled/signed-offset, pre/post-index, sign-extending, pair,
atomic and SIMD memory forms remain rejected (the earlier scalar FP load subset
is preserved). Memory provides checked little-endian 8/16/32/64-bit accesses;
every operation validates its whole range before touching bytes. Generated
functions now take `Memory&` so stores can modify guest bytes. No guest address
is converted into a host pointer.

The memory suite adds 121 synthetic leaves/sequences over the same 152 inputs
(18,392 calls). It compares explicit expected states and Unicorn with native
C++11, including all 256 sandbox bytes, SP/ZR, unaligned accesses, register and
memory aliasing, and modular effective-address arithmetic. Native fault tests
also check discarded ZR loads, address-register aliases and store atomicity
when a complete access is out of bounds. `recomp_memory_smoke` checks every
access width at every offset of small/empty buffers and high guest addresses,
including the final byte at UINT64_MAX. Crossing the guest address limit fails;
base-plus-offset computation itself wraps modulo 2^64 as A64 arithmetic does.

`verify_memory.py` validates the configured hash, lifts and compiles eight
original leaves afresh, then compares 1,216 calls including complete sandbox
contents and registers. The selections cover byte/halfword/word/doubleword
loads/stores, aliased getters, halfword copying and load–ADD/SUB–store patterns.
They include `ShaderSort`, `RpMTEffectAddRef`, `RwRasterGetOffset` and
`RtDictSchemaSetCurrentDict`. The config's `verification: memory` and explicit
`pointer_registers` specify the test harness inputs; these are not an ABI bridge.
Other integer selections remain in `verify_integer.py`. The memory evidence
report is ignored `generated/memory-verification.json`, with input hash,
backend, symbol ranges and corpus details.

The memory profile is flat, little-endian normal memory with architectural
alignment checks disabled. Host bounds exceptions do not implement guest data
aborts, permissions, tagged memory or MMIO. Passing these bounded corpora does
not establish correctness for every machine state or make the game runnable.

Intrafunction control flow (`control-flow-v1`) adds direct unconditional `b`,
`cbz`, and `cbnz` for W and X registers, along with support for multiple `ret`
instructions in a single function. Acyclic basic block CFGs are constructed by
finding leaders at entry, branch targets, and instruction fallthroughs. The CFG
validator enforces that all branch targets lie within the function bounds and
land on 4-byte decoded instruction boundaries, that all execution paths terminate
with `ret`, and that no block falls through outside the function. Cycles (loops),
out-of-bounds branches, unreachable dead blocks, subroutine calls (`bl`, `blr`),
indirect branches (`br`), indirect returns (`ret xn` where `n != 30`), and
flag-dependent branches (`b.cond`) are strictly rejected. Native C++ control flow
is emitted as labeled blocks and `goto`/`if` statements; no runtime instruction
dispatcher or interpreter is created.

`verify_control_flow.py` validates five original control-flow leaves from `libGTASA.so`
(`RxPipelineClusterGetCreationAttributes`, `RxPipelineClusterSetCreationAttributes`,
`SetPedAtomicVisibilityCB`, `CAutomobile::ReduceHornCounter`, and
`CTaskManager::GetActiveTask`) across 760 differential trials against Unicorn ARM64,
verifying both taken and fallthrough branches, multiple RET exits, register state,
and guest memory modifications. Evidence is recorded in `generated/control-flow-verification.json`.

Unsupported instructions, incomplete decoding, unsafe load forms and code
relocations are rejected before translation output is written. A failed lift
returns nonzero; any previous generated files still describe the earlier input.
Do not build after a failed generation step. No interpreter fallback or Android
service stubs are provided.

## Scan backend coverage

`scan --output generated/scan.json` checks the configured binary's SHA-256 and
architecture before scanning all defined, nonzero-sized function symbols from
both symbol tables. It uses the same instruction validator as `lift`, regardless
of the configured lift selections. It writes a JSON report, without generating
C++ or executing guest code. Exit status 0 means the scan completed; blocked
functions are report data. Invalid input or a hash mismatch returns nonzero
before writing the report; an existing report then remains from the earlier run.

Each function has `status: translatable` or `blocked`, opcode counts and grouped
`blockers`. Categories distinguish unsupported instructions, addressing modes,
operand forms, control flow, decoding failures, invalid ranges and code
relocations. Examples include guest addresses and disassembled operands (up to
three per group); counts include every occurrence. Decoding resumes at the next
4-byte word after an undecodable word, which always blocks translation. These
diagnostics assume symbol bytes are instructions; they do not recover a CFG or
identify embedded data. Addressing-mode diagnostics describe rejected forms of
the current load/store instructions; other mnemonics are unsupported as a whole.

Aliases remain separate in `functions` and symbol totals. `blocker_summary` and
range totals count identical `(address, size)` ranges once; overlapping ranges
of different sizes can still overlap in these counts. The import list labels
every import `unresolved`: no ABI/platform bridge is implemented, and the scan
does not infer call targets or attribute imports to particular functions.
Zero-sized symbols and code without function symbols are outside this scan.

**Translatable means accepted by `control-flow-v1`, not semantically verified.**
Every scan entry has `semantic_verification: not_verified`; scanning does not
run or import differential-test results. Successful translation/build and symbol
counts are not proof of correctness or game completion. The backend's FP/state
limits still apply, and accepted functions still need runtime integration.

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
The native image loader verifies the configured hash again, copies PT_LOAD file
data and zeroes BSS at explicit biased guest addresses. It can explicitly apply
RELA `R_AARCH64_RELATIVE` and internal non-preemptible ABS64/GLOB_DAT/JUMP_SLOT
fixups to existing writable guest mappings after validating the complete batch.
JUMP_SLOT requires a zero addend pending platform policy; preemptible definitions,
undefined symbols, special unsupported forms and all imports remain unresolved. Applied entries are reported separately. It always reports
`ready_to_execute=false`. It never invokes constructors, JNI_OnLoad or game entry
points. See [ELF loading](docs/ELF_LOADING.md) for its bounded input support.

Native output is expected to differ from ARM64 bytes: semantic equivalence and
runtime correctness are the validation goals for this branch.
