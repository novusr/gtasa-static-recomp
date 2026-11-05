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
- Transactional RELA ABS64/GLOB_DAT/JUMP_SLOT data fixups for defined,
  non-preemptible internal symbols, with table/index metadata, checked guest
  addresses, SHN_ABS handling, per-reason unresolved status and a combined
  RELATIVE/symbol API. JUMP_SLOT accepts zero addends pending platform policy;
  it supplies no dispatch. Synthetic tests cover resolution, arithmetic,
  rejection, atomicity and phase interaction. Original-image verification finds
  no eligible internal symbols: 5,252 RELATIVE applied, 21,072 preemptible and
  386 undefined relocations unresolved, with all 274 imports unresolved.

- Explicit transactional PT_GNU_RELRO sealing with caller-supplied guest page
  size, raw/biased and effective inventories, Android page rounding over exact
  guest mappings, checked write removal without adding read/execute permissions,
  and independent sealing state. Synthetic tests cover malformed ranges,
  permission boundaries, relocation order and allocation-failure atomicity;
  original-image smoke independently checks RELRO and retained relocation/import
  results. Shared-page PT_LOAD layouts and Android padding/compatibility modes
  remain unsupported; readiness stays false.

- Structured hash-verified linker audit reusing the complete native symbol and
  relocation inventories, with table/index identities, dependency/dynamic and
  validated symbol-version metadata, explicit guest geometry/sealing state and
  unresolved groups. Original input matches the 5,252 applied / 21,458 unresolved /
  274 imports baseline. Providers and platform implementations remain unknown;
  no resolver or initializer runs. See [LINKER_AUDIT.md](LINKER_AUDIT.md).

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

The read-only two-object resolution-plan milestone is implemented for synthetic
unversioned ordinary symbols under an explicit scope. It preserves instance/table/
index provenance, tests preemption and visibility, separates missing strong/weak
from unsupported requirements, and changes no image state. See
[RESOLUTION_PLAN.md](RESOLUTION_PLAN.md). Read-only dependency evidence collection
is now implemented with explicit file/hash/bias instances and DT_NEEDED edges;
see [DEPENDENCY_EVIDENCE.md](DEPENDENCY_EVIDENCE.md). The follow-up user-supplied
APK directory audit accepts GTASA, OpenAL and SCAnd under unchanged validators.
It finds 25 ordered NEEDED entries, two name-only candidates, no attributed
edges, and 11 unique required names with no supplied candidate, including the
newly observed libz.so and libGLESv1_CM.so requirements. Authenticity and Android
process evidence remain unknown; expected hashes pin observed local content.
The next bounded step is acquiring and attributing those missing files, trusted
comparison identities, candidate associations, libc/libm/libdl version-export
evidence and API/device/target/namespace/main/preload/load-order observations,
then repeating the read-only audit. Original-dependency resolution planning and
scope/version policy expansion are outside this evidence milestone.

The concrete [evidence request package](EVIDENCE_REQUEST.md), checked against
`56e1198` on 2026-11-06, now supplies an 11-name matrix with all requester and
version identities, plus an ignored local collection worksheet. Revalidation
against unchanged old pins reproduces the complete three-file report and GTASA
baseline. No additional input was explicitly supplied; acquisition remains
pending, with authenticity, candidate associations and seven platform facts
unknown. The next gate is user-supplied paths/build provenance and external
captures, followed only by read-only validation of explicitly authorized inputs.

- Extend the bounded PT_LOAD/BSS loader with Android linker requirements,
  relocation target validation, further RELRO/platform layouts and any required
  packed-table support.
- Extend bounded internal-symbol relocation support with dependency/preemptible
  resolution, symbol versions and verified platform JUMP_SLOT addend policy;
  implement TLS and other required relocation forms. Unrecognized requirements
  must fail startup.
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

## Device format proposal, 2026-11-06

The later connected-device capture supplies candidates for all 11 requested
names; it supersedes the earlier pending-acquisition status for those candidates,
not unknown game-process associations. libc passes existing validators, while
ten files remain rejected. The [format proposal](RELOCATION_FORMAT_PROPOSAL.md)
finds APS2 RELA in all ten and Android-numbered RELR in nine. The next bounded
format implementation is pure decoding followed by a separately identified
inventory-only path with atomic failure and synthetic rejection tests. This
proposal implements no decoder or fixup and expands no scope/version policy.
Original dependency resolution, initialization and platform work remain pending.
