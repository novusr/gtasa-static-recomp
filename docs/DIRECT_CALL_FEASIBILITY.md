# Direct-call AOT feasibility, 2026-11-06

Follow-up: the proposed [CountMembers leaf milestone](COUNT_MEMBERS.md) is now
implemented with a newer backend. This document preserves the historical
`control-flow-v1` audit and its results; its original non-leaf objective remains
incomplete, and it is not a current-backend coverage report.

**The requested original non-leaf AOT milestone is blocked within the bounded
extension investigated here. No new function was translated or differentially
verified, and BL remains rejected.** The request explicitly permits reporting
candidate evidence when a small closure cannot be selected without expanding
scope. No runtime, loader, relocation, dependency or platform behavior changed.
Work started from clean `static-recomp` HEAD `03fd6bf`; the separate `main`
worktree and its agents were untouched. No commit or push was made.

## Input and discovery evidence

The unchanged configured SHA-256 is
`12527bfdb63889c02d24366629e808cb446d354a2b380348bd661da4edc6af11`.
Pinned dependency sync, input inspection and a fresh `control-flow-v1` scan
succeeded. The old scan had matching hash/backend identity; fresh scanning was
still needed because it does not inventory direct target relationships.
Fresh counts match: 18,265 symbol identities, 17,152 distinct ranges, 1,688
accepted symbol identities / 1,582 distinct accepted ranges. These are analysis
results, not semantic correctness evidence.

`tools/audit_direct_calls.py` independently decodes every defined, nonzero-sized
STT_FUNC range from verified input bytes. It checks scan hash, backend, evidence
label and complete symbol/range identity. Aliases merge only at identical address
and size. BL targets use the signed encoded imm26 and instruction address,
independently of operand text. Existing CFG constraints, code relocation
exclusion and exact function entry identity are checked. The audit never lifts
or executes a function.

The audit found **10,219 ranges containing direct BL**, with **78,715 call sites**:
72,022 target `.plt`; 6,693 target defined function entries. All direct targets
found fall into these two classes. This does not establish the requirements of
code absent from function symbols, nor make PLT an internal static C++ call.
No PLT body was rewritten to its apparent provider; no import was implemented.

Two discovery profiles both found **zero eligible closures**:

| Discovery profile | First failure across caller ranges |
| --- | --- |
| Current validator, provisionally ignoring BL rejection | 10,219 body/CFG failures |
| Optimistically forgive BL and every load/store/pair addressing form | 10,048 body/CFG failures; 171 PLT targets |

The second profile is deliberately more permissive than a proposed integer
stack extension: unsupported FP/pair, register-offset and writeback forms are
also forgiven during screening. It implements none of those instructions and
validates none of their semantics. Counts record the **first** obstruction,
not an exhaustive inventory of requirements. Recursive closure traversal,
shared callees and exact entry checks remain in the audit. Body/CFG checks can
reject a recursive candidate before traversal reaches its recursive edge.
This result supports stopping the bounded milestone; it does not prove that no
larger backend could translate an original non-leaf function.

## Concrete candidates rejected

Ranges are half-open ELF virtual addresses, without Ghidra base or load bias.
Original bytes and disassembly remain in ignored evidence.

| Caller and range | Direct call graph | Reason not selected |
| --- | --- | --- |
| `ES2RQShaderBinding::Setup`, `[0x26151c,0x261548)` (44 bytes) | BL `0x261534` -> `.plt` `0x21e600` | Stack writeback/pairs plus PLT dispatch; target is not an internal function symbol entry. |
| `_rwFramePurgeClone`, `[0x26f81c,0x26f85c)` (64 bytes) | BL `0x26f848` -> `rwSetHierarchyRoot`, `[0x26f85c,0x26f898)` (60 bytes); callee BL `0x26f880` -> itself | Recursion and callee CBNZ loop, plus stack operations. Null/empty inputs cannot justify deleting paths. |
| `mpg123_getparam`, `[0x2dbda4,0x2dbde0)` (60 bytes) | BL `0x2dbdc0` -> `mpg123_getpar`, `[0x2dbde0,0x2dbf18)` (312 bytes) | Caller register-offset store; callee CMP/B.hi, ADRP, signed/indexed loads, BR jump table and binary64 conversion. Null-only inputs cannot establish full-body support. |

No caller or closure was selected for execution. Adding BL and stack pairs alone
would not satisfy the original non-leaf criterion. Analysis fixtures exercise
signed target arithmetic, entry/PLT rejection, recursive and mutual cycles,
blocked callees, CFG/decode rejection, optimistic-screen separation and scan
identity mismatches. These are not semantic tests of a new call backend.

## Backend/runtime contract remains unchanged

Generated functions still receive `State&` and checked `Memory&`. State retains
31 X registers, SP and 32 low S words, with existing size/offset assertions.
The host C++ ABI does not implement guest calls. Native return addresses are
not guest X30; existing leaf RET emission does not establish a general guest
return contract. BL/BLR, integer stack pairs/writeback, recursion, CFG cycles,
indirect branches and NZCV-dependent operations retain existing rejection gates.
No dispatcher, interpreter, JIT, bridge, provider or stub was added.

Future calls must explicitly write guest PC+4 into X30, preserve actual guest
LR saves/restores through checked memory, and validate RET against its expected
continuation separately from native return. AAPCS64 cannot replace instruction
effects. General stack/ABI integration and exception unwinding remain absent.

## Reproduction and evidence

```bash
uv sync --locked
uv run python tools/recomp.py inspect --output generated/direct-call-inventory.json
uv run python tools/recomp.py scan --output generated/direct-call-baseline-scan.json
uv run python tools/audit_direct_calls.py \
  --scan generated/direct-call-baseline-scan.json \
  --output generated/direct-call-feasibility.json
uv run python tools/recomp.py lift --output generated
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
uv run python -m unittest discover -s tests -p 'test_*.py'
python3 tools/load_image.py --load-bias 0x100000000 --guest-page-size 0x1000 \
  --output generated/direct-call-gtasa-load-recheck.json
uv run python tools/verify_integer.py
uv run python tools/verify_memory.py
uv run python tools/verify_control_flow.py
uv run python tools/verify_leaf.py
```

Audit output preserves ranges, aliases, call sites, guest continuations, target
identities, opcodes, blockers and closure failures.
`generated/direct-call-shortlist-bytes.json` records the shortlist's original
bytes/disassembly and the prospective leaf below. All translations, reports,
original bytes and executables remain ignored. No expected hash changed.
There is no new native-vs-ARM64 non-leaf corpus or call semantic evidence.

Validation passed: pinned sync, fresh inspection/scan/lift of the existing 20
selections (91 instructions), C++11 CMake/Ninja build, all seven CTests and all
138 Python methods, including eight new analysis tests. Existing synthetic
semantic/rejection and data-only loader/inventory suites passed. Existing
original-function oracle regressions passed 760 integer, 1,216 memory, 760
control-flow and 2,048 FP calls (6,144 FP result words). These retain their prior
bounded corpora and do not verify a new non-leaf. Evidence remains in the
existing ignored verification reports and `generated/direct-call-regression.log`.

The separate legacy data-only recheck preserved **5,252 RELATIVE applied;
21,458 unresolved (21,072 preemptible / 386 undefined); 274 unresolved imports;
RELRO sealed; readiness false**, at explicit bias `0x100000000` and guest page
size `0x1000`. It checked 8,908,241 original file bytes and 4,908,543 BSS bytes.
No initializer, constructor, JNI_OnLoad, IFUNC resolver, game or device ran.

## Next bounded AOT milestone

First broaden an original **acyclic integer leaf**, keeping the linker frozen.
A concrete candidate is `CLoadedCarGroup::CountMembers`,
`[0x5d16dc,0x5d1850)` (372 bytes): 23 signed halfword loads, 22 TBNZ tests,
one CMP and one CINC, with 23 RET exits and no calls or global-address loads.
Forward-only tests avoid the recursion, indirect dispatch and platform work
blocking the candidates above. It needs independently tested LDRSH, TBNZ and
NZCV/CMP/CINC support before fresh lifting and full-state/memory differential
verification. This is a proposal based on bytes, not acceptance or a verified
function. Its non-leaf callers still contain loops and further unsupported code.

Successful scanning or data loading does not mean a library is fully linked,
a function is safe for all machine states, or the game is runnable.
