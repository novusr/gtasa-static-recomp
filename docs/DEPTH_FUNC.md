# GLDepthFuncFromRQ B.HI milestone, 2026-11-06

`integer-bhi-v1` adds only ordinary B.HI to the prior `integer-bne-v1`
subset. The original register-only leaf `_Z17GLDepthFuncFromRQ11RQDepthFunc`
is explicitly selected with its own `depth_func` oracle profile. This is a
bounded AOT leaf milestone; BL, non-leaf execution and platform startup remain
unsupported. Loader, relocation, dependency and provider implementation is frozen.

Work started in `/home/novusr/Documents/gtasa-static-recomp`, branch
`static-recomp`, with clean Git status at HEAD
`ca26da9572ebc5f4ae3ad3f84fb0cf9450c2a6f0`. The separate `main` worktree and
its agents were untouched. No commit or push was made. Locked dependency sync
preceded fresh inspection and scanning. Input SHA-256 remains pinned to
`12527bfdb63889c02d24366629e808cb446d354a2b380348bd661da4edc6af11`.

## Original byte confirmation

The sole matching symbol is executable and file-backed at
**[0x264cd0,0x264ce8)**, 24 bytes, with no code relocation. All bytes decode:

| ELF VA | Encoding word | Instruction |
| --- | --- | --- |
| 0x264cd0 | 0x71001c1f | CMP W0,#7 |
| 0x264cd4 | 0x54000068 | B.HI 0x264ce0 |
| 0x264cd8 | 0x11080000 | ADD W0,W0,#0x200 |
| 0x264cdc | 0xd65f03c0 | RET X30 |
| 0x264ce0 | 0x528040e0 | MOV W0,#0x207 (MOVZ alias, shift zero) |
| 0x264ce4 | 0xd65f03c0 | RET X30 |

Code SHA-256 is
`96d25074bfc759575e1e96dbcec51f113ad2ad04227b3be01d9fe2285ca5ba65`.
There are no calls, global accesses or platform requirements. Three reachable
blocks form an acyclic CFG: entry branches to 0x264ce0 or falls through to
0x264cd8, and each successor ends in RET. Prior-backend scan blocks B.HI and
reports an unreachable MOV block because that backend does not recognize the
HI edge. This second diagnostic disappears with the same edge included in CFG
analysis; it is not an additional instruction requirement. All other original
encodings were already supported. No mnemonic-only assumption about MOV was used.

## Exact extension

Ordinary B.cond must have bits 31:24=0x54 and bit4=0, a four-byte encoding,
and condition field 8 for HI (1 for existing NE). BC.cond, reserved fixed bits,
mnemonic/condition mismatches and all other B.cond conditions reject. Signed
imm19 is scaled by four and added to the instruction PC modulo 2^64.

HI consumes explicit guest NZCV: C set and Z clear. N and V do not affect it,
as specified by Arm's [condition-code table](https://support.arm.com/documentation/dui0801/h/Condition-Codes/Condition-code-suffixes-and-related-flags).
The [B.cond encoding reference](https://support.arm.com/documentation/111181/2025-09_ASL1/Base-Instructions/B-cond--Branch-conditionally-)
describes its PC-relative signed offset. Emission is a native conditional goto
using existing `condition_holds(state.nzcv, 8)`. No runtime or State layout change
was needed; no host flags or runtime ARM64 decode is involved.

Scan/lift reuse all existing boundary, bounds, reachability, all-path RET,
acyclic CFG, complete-decode and code-relocation gates. BL/BLR, BR, non-X30 RET,
TBZ, other conditions and previously unsupported arithmetic/addressing remain
rejected. Failed generation preserves prior successful output and creates no
apparently valid new output. No interpreter, JIT, dispatcher, stub or ABI bridge
was added. Guest memory remains checked `Memory`, never a guest-to-host cast.

## Synthetic and original semantic evidence

The B.HI synthetic corpus contains **51 sequences x 273 vectors = 13,923
executions**, compared against independently calculated state/flags/memory and
Unicorn. It covers all 16 initial NZCV combinations, W/X CMP, unsigned/signed
boundaries, SP/ZR, input/output aliases, W upper-half clearing, preservation,
forward, backward acyclic and diamond CFGs, and conditional stores. Separate
native fault checks exercise every NZCV pattern with skipped invalid accesses
and unchanged destinations/memory on fault. Rejections cover displacement
extremes/wrap, bounds and decoded boundaries, cycles, dead blocks, missing RET,
BC.HI, fixed-bit/condition/length mismatches, unsupported calls/forms, and failed
publication with previous or absent outputs. Existing B.NE tests remain active.

`verify_depth_func.py` rehashes the original input, lifts afresh, and compiles a
temporary standalone Linux x86_64 C++11 runner. It consumes only state/data and
neither reads guest instructions at runtime nor links Unicorn. Unicorn executes
only the original leaf with separate code/data, return sentinel 0xffff0000 and
a six-instruction limit. Maximum observed execution is four instructions.

**896 cases passed**: 384 boundaries (0,1,6,7,8,0x7fffffff,0x80000000,0xffffffff,
three clean/dirty upper X0 patterns, all 16 initial flags), plus 512 deterministic
random cases, seed 0xDE97. Other registers, SP and sandbox bytes vary. Independent
expectations are `X0 = 0x200 + min(input W0,7)` and mathematical CMP flags.
Both B.HI outcomes occurred **448 times each**, both RETs occurred 448 times,
and all six instruction addresses were visited. Every case compares X0..X30,
SP, low S0..S31, NZCV and all 512 sandbox bytes. S words use fixed patterns
varying per register; arbitrary SIMD state is not claimed.

Ignored `generated/depth-func-verification.json` records input/code/native
hashes, exact encodings/range, call graph, full corpus and its hash, compiler
flags, comparison fields, coverage and limits. `depth-func-candidate-bytes.json`
retains byte-level target/closure/next-candidate evidence. Scan acceptance,
successful translation/build and bounded semantic verification are separate:
every scan entry remains `semantic_verification: not_verified`.

## Non-leaf closure analysis after HI

The fresh final scan/audit use `integer-bhi-v1`; the audit independently redecodes
original bytes and checks input hash, backend, evidence label and every symbol/
range identity. The scan accepts **2,024 of 18,265 symbol identities**, over
17,152 distinct ranges. Acceptance does not import oracle evidence.
The audit finds **zero eligible closures** under both discovery profiles. All
10,219 current-instructions-plus-BL candidates fail body/CFG checks. The
optimistic memory-plus-BL screen has 9,930 first body/CFG failures and 289 first
PLT failures. There are 78,715 direct call sites: 72,022 to PLT and 6,693 to
defined symbol entries. These are first-failure discovery counts, not exhaustive
blocker counts or implemented call support. The optimistic screen forgives
memory forms only for analysis and still finds no complete eligible closure.

The concrete closure assessed is `mpg123_getparam` **[0x2dbda4,0x2dbde0)**,
BL at 0x2dbdc0 to `mpg123_getpar` **[0x2dbde0,0x2dbf18)**, continuation
0x2dbdc4. The callee contains no BL/BLR or direct PLT/import edge. All instructions
in both ranges were rechecked; neither range has code relocations.

The caller still requires pre-index STR X19,[SP,#-0x20]!, integer STP/LDP
X29/X30 through SP, post-index LDR X19,[SP],#0x20, register-offset STR W0,
[X19,X8], and BL with guest LR/continuation semantics. Existing ADD, MOV and
CBZ forms alone do not make it translatable.

The callee's B.HI is now accepted, but ADRP, LDRSW (both unsigned immediate and
register-indexed scaled forms), BR X9, LDR D0 and fixed-point FCVTZS X8,D0,#15
remain blocked. ADRP+ADD locates a global signed-offset jump table at 0x71a7d8.
The original table's 17 entries for W1=0..16 were read data-only: all resulting
targets are inside the callee. Those bytes and targets are preserved in the
candidate evidence. The present CFG validator does not recover indirect edges
and reports unreachable case blocks; this is a backend CFG obstruction, not
proof that original switch cases are dead. A complete indirect CFG and dispatch
contract is still required, without deleting paths on null-only inputs.

Runtime requirements include checked object/output/global-table memory, actual
guest LR and checked stack saves/restores, validated continuation, jump-table
control flow and binary64 state/conversion semantics. No direct external call
was found in these two bodies, but this analysis supplies no linking, platform
or ABI implementation. B.HI alone does not open this closure. No additional
instruction was implemented for this analysis.

The next bounded AOT proposal is **ordinary B.LO only** for
`CPed::SetWeaponSkill`, `_ZN4CPed14SetWeaponSkillE11eWeaponTypea`,
**[0x59bf24,0x59bf38)**. Original bytes confirm LDR W8,[X0,#0x720], CMP W8,#2,
B.LO to RET, STRB W2,[X0,#0x8fc], RET. Existing memory/CMP forms suffice;
checked object extent and separate LO truth-table/rejection/original oracle
verification remain necessary. This is a proposal, not current acceptance.

## Reproduction and verification limits

```bash
uv sync --locked
uv run python tools/recomp.py inspect --output generated/inventory.json
uv run python tools/recomp.py scan --output generated/depth-func-scan.json
uv run python tools/audit_direct_calls.py --scan generated/depth-func-scan.json \
  --output generated/depth-func-direct-audit.json
uv run python tools/recomp.py lift --output generated
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
uv run python -m unittest discover -s tests -p 'test_*.py'
uv run python tools/verify_depth_func.py
uv run python tools/verify_leaf.py
uv run python tools/verify_integer.py
uv run python tools/verify_memory.py
uv run python tools/verify_control_flow.py
uv run python tools/verify_count_members.py
uv run python tools/verify_clock_beep.py
python3 tools/load_image.py --load-bias 0x100000000 --guest-page-size 0x1000 \
  --output generated/depth-func-gtasa-load-recheck.json
```

Fresh configuration lift/build passed for **23 functions / 195 instructions**.
All **seven CTests** and **163 Python regression tests** passed, including
loader/inventory data-only checks. All six prior original oracles passed: leaf 2,048 calls / 6,144 result words,
integer 760, memory 1,216, control flow 760, CountMembers 2,816 and clock
countdown 2,816. The new target uses its own profile and is excluded from the
generic integer harness; the other harnesses retain explicit selection filters.

Legacy GTASA data-only recheck retained **5,252 RELATIVE applied; 21,458
unresolved (21,072 preemptible / 386 undefined); 274 unresolved imports;
RELRO sealed; readiness false**, with unchanged input hash, explicit bias
0x100000000 and guest page size 0x1000. File/BSS and permission checks remain.
All reports, generated C++, binaries and temporary executables remain ignored.

These bounded tests do not establish correctness for all machine states, full
SIMD/FPCR/FPSR, architectural fault delivery, linked library execution or a
runnable game. No game, initializer, constructor, JNI_OnLoad, IFUNC, device
operation or GTA installation ran.
