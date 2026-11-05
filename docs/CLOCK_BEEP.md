# Clock countdown AOT milestone, 2026-11-06

The selected original leaf is `COnscreenTimer::SetClockBeepCountdownSecs`
(`_ZN14COnscreenTimer25SetClockBeepCountdownSecsEjj`), range
**[0x3db37c,0x3db390)**: 20 bytes, five instructions, no call edges.
It requires only B.NE beyond `integer-flags-v1`. This is a bounded leaf
milestone; the original non-leaf objective remains blocked.

Work started on clean `static-recomp` HEAD `d57d4b8abac908983e70b09c28de572b92f1a2a7`.
Only this worktree was changed. Input SHA-256 remains
`12527bfdb63889c02d24366629e808cb446d354a2b380348bd661da4edc6af11`.
No loader, relocation, provider, ABI or platform implementation changed.
No commit or push was made.

## Evidence and target selection

Locked dependency sync, hash-verified inspection and a fresh
`integer-flags-v1` scan preceded implementation. The scan contains 18,265
symbol identities / 17,152 distinct ranges; 1,991 symbol identities pass the
validator. Every entry remains `semantic_verification: not_verified`.
`audit_direct_calls.py` redecoded the original input and checked hash, backend,
evidence label and the complete symbol/address/size identity against this scan.
There are 10,219 direct-BL ranges and 78,715 BL sites: 72,022 target PLT and
6,693 target defined entries.

The current-instructions-plus-BL profile finds zero eligible closures (all
10,219 fail body/CFG checks). Forgiving BL and every existing audited load/store/
pair mnemonic still finds zero: 9,940 first body/CFG failures and 279 PLT
failures. A separate **discovery-only** screen additionally forgave ordinary
B.cond conditions EQ..LE and treated them as conditional CFG edges, including
bounds, cycle and reachability checks. Even that broader screen finds zero:
9,906 first body/CFG failures and 313 PLT failures. This screen implements no
instruction and its counts are not backend acceptance or semantic evidence.
Failure counts identify the first obstruction, not every closure requirement.

Candidates are ordered by backend growth and complete closure feasibility,
then size. All ranges below are half-open ELF VAs, without analysis/load bias.

| Candidate / range | Call graph | Additional instruction or addressing requirements | Runtime / platform requirements | Decision |
| --- | --- | --- | --- | --- |
| `COnscreenTimer::SetClockBeepCountdownSecs` [0x3db37c,0x3db390) | Leaf | B.NE only; existing LDR/CMP/STR | Checked 64-byte object extent, explicit registers/flags; no globals/imports | Selected: five instructions, one branch, one checked conditional store. |
| `CPed::SetWeaponSkill` [0x59bf24,0x59bf38) | Leaf | B.LO only | Checked object offsets 0x720 and 0x8fc | Equally small code, but larger memory footprint and a different condition; deferred. |
| `GLDepthFuncFromRQ` [0x264cd0,0x264ce8) | Leaf | B.HI only; CMP/ADD/MOV/RET already supported | Registers only; no platform call despite symbol name | Deferred; concrete next bounded condition milestone. |
| `CAEAudioChannel::SetOriginalFrequency` [0x46c1e8,0x46c200) | Leaf | B.EQ only | Checked object offsets 0x28/0x2c | Deferred: six instructions, two stores, different condition. |
| `ES2RQShaderBinding::Setup` [0x26151c,0x261548) | BL 0x261534 -> PLT 0x21e600 | Stack pairs/writeback, BL | Import/indirect dispatch and guest LR/stack contract | Rejected: closure requires excluded platform work. |
| `_rwFramePurgeClone` [0x26f81c,0x26f85c) | -> `rwSetHierarchyRoot` [0x26f85c,0x26f898), which calls itself at 0x26f880 | BL, stack pairs/writeback; callee CBNZ cycle | Guest LR/stack and recursion | Rejected: cycles remain outside milestone. |
| `mpg123_getparam` [0x2dbda4,0x2dbde0) | -> `mpg123_getpar` [0x2dbde0,0x2dbf18) | BL, stack pairs/writeback/indexed store; callee B.HI, ADRP, signed/indexed loads, BR jump table, binary64 conversion | Global data/linking and indirect dispatch | Rejected: substantially broader than a condition branch. |

Ignored `generated/post-count-baseline-scan.json`,
`post-count-direct-audit.json`, `post-count-bcond-cfg-screen.json`,
`post-count-leaf-shortlist.json` and discovery scripts/logs preserve the original
selection evidence. The broad screen used temporary analysis wrappers; its
backend field identifies the validator it screened, not implemented support.
Fresh final-backend scan/audit reports are kept separately. No unsupported
callee was accepted based on null inputs or partial paths.

## Exact support: integer-bne-v1

B.NE accepts the ordinary B.cond encoding only: bits 31:24 = 0x54, bit 4 = 0,
condition bits 3:0 = 1. The signed imm19 is sign-extended and scaled by four,
then added to the instruction VA modulo 2^64. Emission is a direct native
conditional goto using `condition_holds(state.nzcv, 1)`. It preserves registers,
SP, NZCV and memory. No host flags or runtime decoding are involved.

The original body loads W8 from [X0], compares W8 with W1, skips the store on
inequality, otherwise writes low W2 to [X0+0x3c], then returns through X30.
LDR clears X8's upper half. CMP updates guest NZCV; the branch/store preserve it.
X0 and every other represented register remain unchanged. Memory access remains
through checked `Memory`, with no guest-pointer host casts.

All branch targets must be decoded instruction boundaries inside the selected
function. Existing acyclic CFG, reachability, all-path RET, full-decode and
code-relocation gates apply. Backward edges are accepted only if acyclic.
Other B.cond conditions, AL/NV, BC.cond, TBZ, BL/BLR, indirect branches/returns,
loops and previously unsupported arithmetic/addressing modes remain rejected.
Rejected generation preserves prior output and publishes no new output directory.
`State` and its asserted size/offsets are unchanged from CountMembers.

The encoding and signed displacement follow Arm's official
[B.cond reference](https://support.arm.com/documentation/111181/2025-09_ASL1/Base-Instructions/B-cond--Branch-conditionally-).
NE tests Z clear, as specified in Arm's
[condition-code table](https://support.arm.com/documentation/dui0801/h/Condition-Codes/Condition-code-suffixes-and-related-flags).

## Reproduction

```bash
uv sync --locked
uv run python tools/recomp.py inspect --output generated/inventory.json
uv run python tools/recomp.py scan --output generated/clock-beep-scan.json
uv run python tools/audit_direct_calls.py --scan generated/clock-beep-scan.json \
  --output generated/clock-beep-direct-audit.json
uv run python tools/recomp.py lift --output generated
cmake -S . -B build -G Ninja
cmake --build build
PYTHONPATH=tests uv run python -m unittest test_bne_backend
uv run python tools/verify_clock_beep.py
ctest --test-dir build --output-on-failure
uv run python -m unittest discover -s tests -p 'test_*.py'
uv run python tools/verify_leaf.py
uv run python tools/verify_integer.py
uv run python tools/verify_memory.py
uv run python tools/verify_control_flow.py
uv run python tools/verify_count_members.py
python3 tools/load_image.py --load-bias 0x100000000 --guest-page-size 0x1000 \
  --output generated/clock-beep-gtasa-load-recheck.json
```

Scan acceptance, successful lift/build and differential verification are separate
results. The oracle is a bounded corpus in an isolated sandbox; it does not prove
all machine states, full SIMD/FPCR/FPSR, fault/exception delivery or Android
integration. No game, initializer, constructor, JNI_OnLoad, IFUNC resolver or
device operation is executed. The library is not fully linked or game runnable.

## Verification results

The fresh native C++11 runner agreed with original ARM64 and independent
mathematical expectations on **2,816 cases**: 2,304 boundary cases (six loaded
word values by six argument values, four object offsets, all 16 initial NZCV
patterns) and 512 deterministic random cases, seed 0xBEE5. Dirty upper halves
of X1/X2 check W reads/stores; source/store addresses include unaligned cases,
the sandbox start and a destination ending at its final byte. Every case
compares X0..X30, SP, low S0..S31, NZCV and all 512 sandbox bytes.
Low S words use fixed patterns differing per register; arbitrary SIMD states
are not claimed.

Original code SHA-256 is
`adddb711909589c2ae9e543cce5f7da6b2595731ecda13fdcbf25039abb3f5d5`.
Both B.NE outcomes were covered: **2,176 taken, 640 fallthrough**. All five
instruction addresses and the single RET at 0x3db38c were observed; the maximum
path is five instructions. The oracle uses separate code/data, X30 sentinel
0xffff0000 and an explicit five-instruction limit. The native executable is
compiled afresh, consumes explicit state/data only and neither reads ARM64
instructions at runtime nor links Unicorn.
Ignored `generated/clock-beep-verification.json` records the exact range, input/
code/native hashes, call graph, full initial corpus plus hash, coverage and
verification limits. `generated/clock-beep-candidate-matrix.json` retains original
candidate/callee bytes, disassembly, hashes, direct edges and final blockers.

The synthetic suite adds **39 sequences x 152 vectors = 5,928 executions**
against independent state/flag/memory expectations and Unicorn, with W/X CMP,
SP/ZR and register aliases, width/shift/overflow boundaries, all initial NZCV,
forward/backward acyclic and diamond CFGs, conditional memory mutations and
preservation. Native fault checks establish that skipped invalid loads/stores
perform no access and faulting accesses leave their destination/memory intact.
Rejection checks cover other conditions, reserved/BC encodings, signed imm19
extremes and address wrap, target boundaries/bounds, cycles, unreachable blocks,
missing returns, unsupported calls/forms and preservation of prior output on
failed generation.

Final validation passed: fresh lift of **22 functions / 189 instructions**,
C++11 CMake/Ninja build, **all seven CTests** and **all 153 Python tests**,
including unchanged loader/inventory data-only regressions. Original oracle
regressions passed: FP 2,048 calls / 6,144 result words, integer 760 calls,
memory 1,216 calls, control flow 760 calls, and CountMembers 2,816 calls
covering its 23 returns and both outcomes of all 22 TBNZ sites.

The final `integer-bne-v1` scan accepts 2,021 symbol identities; every entry
still says `not_verified`. Only the explicit selections have the separate
bounded oracle evidence. The fresh final direct-call audit again checks full
scan identity and finds **zero eligible closures**: the current-plus-BL profile
has 10,219 body failures; the optimistic-memory profile has 9,930 body failures
and 289 PLT failures. These are first-failure counts, not implementation totals.

The legacy data-only recheck at bias 0x100000000, guest page size 0x1000,
independently retained **5,252 RELATIVE applied; 21,458 unresolved (21,072
preemptible / 386 undefined); 274 unresolved imports; RELRO sealed;
readiness false**. It checked 8,908,241 file bytes, 4,908,543 BSS bytes and
13,816,784 mapped bytes' RELRO permissions, with both endpoint stores rejected.
Reports/logs remain in ignored `generated/clock-beep-*` paths.

The next bounded AOT proposal is B.HI for `GLDepthFuncFromRQ`
(`[0x264cd0,0x264ce8)`), a six-instruction register-only acyclic leaf with two
RET exits. Its original body needs no new memory or arithmetic forms; condition
and path semantics still require separate tests and a fresh original oracle.
That proposal does not establish a non-leaf closure or authorize call support.
