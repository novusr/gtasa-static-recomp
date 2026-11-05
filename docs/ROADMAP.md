# Roadmap to a Runnable Game

## Implemented foundation

- Isolated `static-recomp` branch and worktree; original decomp agents unaffected.
- Pinned dependencies, native host build and reproducible configuration.
- Input hash/architecture validation and ELF inventory with VA-to-file mapping.
- Explicit scalar register state and checked guest memory.
- Ahead-of-time lifting of two real math leaves, with rejection of unsupported code.
- Synthetic analyzer tests, native semantic checks and an ARM64 oracle comparison.

These milestones do not mean the game can start or that arbitrary ARM64 can run.

## Next: general instruction and control-flow backend

- Select a production-capable lifting strategy (evaluate Remill rather than
  expanding a small handwritten decoder without a validation strategy).
- Recover CFGs, branch tables, indirect calls, tails, veneers and symbol-less code.
- Implement/validate integer instructions, flags, NEON, full FP state, atomics and TLS.
- Preserve guest register aliases and exception behavior.
- Produce an explicit translated/blocked report; never infer completion from
  symbol counts or successful host compilation alone.

## Next: ELF image and ABI runtime

- Load PT_LOAD/BSS into guest-addressed memory with bounds/permissions.
- Apply RELATIVE, ABS64, GLOB_DAT, JUMP_SLOT and TLS relocations as encountered;
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
