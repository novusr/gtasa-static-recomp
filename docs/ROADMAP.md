# Roadmap to a Runnable Game

## Implemented foundation

- Isolated `static-recomp` branch and worktree; original decomp agents unaffected.
- Pinned dependencies, native host build and reproducible configuration.
- Input hash/architecture validation and ELF inventory with VA-to-file mapping.
- Explicit scalar register state and checked guest memory.
- Ahead-of-time lifting of two real math leaves, with rejection of unsupported code.
- Synthetic analyzer tests, native semantic checks and an ARM64 oracle comparison.
- Backend scan of defined function ranges with grouped instruction/addressing
  blockers, unresolved imports and a separate, unverified semantic status.
- W/X MOV and non-flag-setting ADD/SUB subset, with explicit SP/ZR semantics,
  modular arithmetic, native/Unicorn synthetic tests and five original integer
  leaves compared against ARM64 execution.
- Unsigned-immediate W/X and byte/halfword integer load/store subset, mutable
  generated memory interface, checked little-endian accesses at all four widths,
  native fault/bounds tests and register-plus-memory ARM64 differential tests
  for synthetic code and eight original leaves.
- Intrafunction acyclic control flow (`control-flow-v1`): direct unconditional B,
  W/X CBZ and CBNZ with width-accurate register reads, multiple RETs per function,
  basic block formation and CFG validation (rejecting cycles, out-of-bounds/unaligned
  targets, non-RET fallthrough, unreachable blocks, BL/BLR, BR and flag-dependent B.cond),
  native C++ goto/if emission, and differential register/memory verification against
  Unicorn for synthetic suites and five real GTA:SA functions.
- Hash-verified native ELF64 PT_LOAD/BSS data loader with explicit load bias,
  checked disjoint guest ranges and permissions, unresolved import/REL/RELA
  inventories, synthetic malformed/overflow tests and an original-image byte
  smoke test. No initializer or guest entry is executed; readiness remains false.
- Explicit transactional RELA R_AARCH64_RELATIVE application with signed addend
  semantics reduced to 64 bits, aligned checked PF_W targets, separate applied and
  unresolved status, repeat-call protection and synthetic rejection/atomicity
  tests. Original-image smoke independently verifies 5,252 applied entries at
  bias 0x100000000; 21,458 relocations and all 274 imports remain unresolved.
  Readiness stays false and no guest code or initializer is invoked.

These milestones do not mean the game can start or that arbitrary ARM64 can run.

## Next: general instruction and control-flow backend

- Support cyclic CFGs (loops: while, for, do-while) and loop termination analysis.
- Support indirect branches, switch tables, jump tables, and tail calls.
- Broaden the tested integer subset; implement/validate flags, NEON, full FP
  state, atomics and TLS.
- Preserve guest register aliases and exception behavior.
- Extend the current translatable/blocked scan to recovered CFGs and attach
  explicit semantic evidence; never infer completion from symbol counts or
  successful host compilation alone.

## Next: ELF image and ABI runtime

- Extend the bounded PT_LOAD/BSS loader with Android linker requirements,
  relocation target validation, RELRO policy and any required packed-table support.
- Extend relocation support beyond RELA RELATIVE to ABS64, GLOB_DAT, JUMP_SLOT
  and TLS relocations as encountered;
  unrecognized relocation types must fail startup.
- Implement address-to-entry dispatch and guest stack/call/callback conventions.
- Handle initialization, allocation, C++ exceptions/unwinding and threading.
- Build an import manifest with explicit implementations and unresolved entries.

## Next: Linux platform bridge

- Provide window, EGL/GLES rendering and event/input handling.
- Implement Android asset/file semantics using local game data.
- Supply audio, timers, synchronization, logging and lifecycle behavior.
- Resolve the Social Club dependency through a defined compatible boundary;
  do not report startup success while required behavior is missing.

## Final integration gates

- Boot translated initialization with no original ARM64 code executing on the host.
- Load the menu and a save, enter a world and exercise rendering, input and audio.
- Compare deterministic subsystem traces against the original Android runtime.
- Validate long-running behavior and performance before claiming a playable port.

Original textures, maps, models, scripts and audio remain separate local inputs.
No assets or original game executables belong in Git.
