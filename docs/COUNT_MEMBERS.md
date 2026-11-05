# CountMembers AOT milestone

`CLoadedCarGroup::CountMembers` (`_ZN15CLoadedCarGroup12CountMembersEv`) now
lifts from the original hash-verified ELF and runs as native Linux x86_64 C++11.
The isolated native runner agreed with original ARM64 execution in Unicorn and
independent signed-array expectations on **2,816 cases**. This is a leaf milestone;
direct calls, the prior non-leaf objective and game startup remain unsupported.

Work began from clean `static-recomp` HEAD `24d4790`. The separate `main`
worktree and agents were untouched. No input hash was updated, no loader or
relocation implementation changed, and no commit or push was made.

## Original function and behavior

Input SHA-256:
`12527bfdb63889c02d24366629e808cb446d354a2b380348bd661da4edc6af11`.
ELF range: **[0x5d16dc, 0x5d1850)**, 372 bytes / 93 instructions.
Function bytes SHA-256:
`889cedd9dca9bb2d82da47671dc9f807878237902643a570c2128cf945eda668`.
There are 23 LDRSH, 22 TBNZ, one CMP, 23 MOV, one CINC and 23 RET instructions.
The call graph is one node with no edges. The symbol range is executable,
file-backed and has no code relocations. No Ghidra coordinates or load bias are
added to the ELF addresses used by the harness.

The function examines up to 23 signed halfwords at X0 and returns the first
negative element's index, or 23 if all are nonnegative. The bytes additionally
determine scratch-register and flag effects: early returns retain the negative
sign-extended W8 load and preserve initial NZCV. The final path compares the
23rd value with zero, writes 22 to W8, and uses CINC GE to produce W0=22 or 23.
All W writes clear the stored register's upper half. Other X registers, SP,
low S registers and memory remain unchanged in this tested function.

Full instruction validation uncovered an additional requirement absent from the
earlier mnemonic-only shortlist: several small MOV constants use ORR-immediate
encodings. Their original bytes are translated using generation-time bitmask
decoding; they are not substituted functions or hand-written behavior.

## Exact backend additions: integer-flags-v1

| Instruction | Accepted forms | Semantics and boundaries |
| --- | --- | --- |
| LDRSH | W/X, unsigned scaled imm12, offset 0..8190 in steps of two | Checked load16; sign-extend to selected width; W result zero-extends into X storage. |
| LDURSH | W/X, signed unscaled imm9, byte offset -256..255 | Same checked access and sign extension; effective-address addition wraps modulo 2^64. |
| TBNZ | Encoded bit 0..63, signed imm14 scaled by four | Direct native conditional goto; Rt=31 is ZR; no NZCV change. Target must be an internal decoded instruction boundary. |
| CMP immediate | W/X SUBS-to-ZR alias, imm12 with optional LSL 12 | Rn=31 is SP/WSP; update NZCV only. |
| CMP shifted register | W/X SUBS-to-ZR alias, LSL 0..31/63 | Both sources use ZR for register 31; update NZCV only; shift result truncated to width. |
| CINC | W/X CSINC alias, equal non-ZR sources, EQ..LE | Decode the inverted encoded condition; increment iff alias condition holds; wrap to width; preserve NZCV. Destination 31 discards the result. |
| MOV bitmask immediate | W/X ORR-immediate alias with ZR source | Decode/rotate/replicate the constant ahead of time. Destination 31 is WSP/SP, including WSP upper-half clearing. No general logical operation was added. |

For LDRSH/LDURSH, Rn=31 means SP, Rt=31 means ZR. A ZR load still performs the
checked memory access. A destination/base alias uses the original base before
assignment. Pre/post-index, writeback, register offset, LDTRSH, other signed
load widths, integer pairs and atomics remain rejected. Unsigned scaled memory
forms already supported by earlier backends retain their behavior.

`scan` and `lift` share validation/emission. Acyclic CFG, full decoding, all-path
RET termination, reachability, bounds and code-relocation gates remain active.
Backward edges are allowed only when they do not form a cycle. BL/BLR, indirect
branches/returns, TBZ, B.cond, generic SUBS/ADDS, CMN, extended-register CMP,
LSR/ASR CMP, general CSINC/CSET and reserved encodings remain rejected.
Rejected generation preserves successful prior output; no interpreter or JIT
fallback is provided. Scan acceptance remains `not_verified` and does not import
the separate oracle evidence.

## Runtime and state contract

`State` adds `uint32_t nzcv` at offset **0x180**. Its size is **0x188**, with
X at 0, SP at 0xF8 and low S words at 0x100; compile-time assertions cover all
offsets and total size. NZCV stores architectural bits 31:28; the other bits are
zero in canonical guest input. Tail padding is not serialized or compared as
architectural state. Existing generated/native artifacts must be rebuilt with
this layout; there is no compatibility claim for the earlier State layout.

Width-specific CMP helpers use unsigned subtraction: N is the result sign, Z
tests zero, C means no unsigned borrow, and V detects signed overflow. They do
not use host condition flags or signed-overflow arithmetic. CINC evaluates the
guest flags explicitly. Halfword extension uses unsigned bits, avoiding an
implementation-defined unsigned-to-signed cast. All memory still goes through
checked `Memory`; guest addresses are never host pointers. Unaligned normal
memory assumes architectural alignment checks disabled. Host bounds exceptions
do not emulate guest data aborts, tags, MMIO or exception delivery.

Encoding/semantic references checked against Arm's official sources:
[A64 instruction guide](https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab)
(LDRSH/LDURSH and TBNZ),
[Armv8-A program flow](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Learn%20the%20Architecture/Armv8-A%20Instruction%20Set%20Architecture.pdf?revision=af73a2a4-620d-4f86-86b0-2987dc04e154)
(CINC versus CSINC condition inversion),
[A64 ISA encoding/operation reference](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85)
(including logical-immediate destination SP), and
[condition flags](https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/condition-codes-1-condition-flags-and-codes).
ELF bytes and instruction semantics remain authoritative; the oracle is an
independent bounded check, not a replacement specification.

## Synthetic and original verification

`tests/test_count_members_backend.py` tests **453 generated sequences over 152
register vectors (68,856 executions)** against independently calculated states
and Unicorn. CMP expectations use mathematical signed range/unsigned ordering,
CINC expectations enumerate a separate condition truth table, halfword results
use Python signed-byte decoding, and MOV masks use a per-bit pattern model.
Coverage includes all 16 NZCV inputs, overflow/borrow/zero/sign boundaries,
W upper-half clearing, all bit numbers, SP/ZR, aliases, displacement boundaries,
unaligned accesses, modular effective addresses and preservation of other state.
Separate native fault checks verify unchanged registers/NZCV/memory on failed
halfword accesses, including discarded ZR destinations and base aliases.
Rejection tests cover addressing, instruction/condition/encoding boundaries,
CFG failures and prior/absent publication behavior.

`tools/verify_count_members.py` rehashes the original input, lifts the selection
afresh and compiles a temporary standalone C++11 executable. The runner consumes
only explicit state/data, never original ARM64 instructions, and does not link
Unicorn. ARM64 executes only this selected leaf with an explicit X30 sentinel
`0xffff0000`, separate code and a 512-byte data/stack sandbox at 0x1000, and a
**93-instruction oracle limit**. The maximum observed path is 49 instructions.
Every trial compares X0..X30, SP, all low S words, NZCV and every sandbox byte.

The corpus comprises 2,304 boundary cases (each first-negative position or
absence, prefixes 0/1/32767, negatives -32768/-1, all 16 initial flags) plus
512 deterministic random arrays, seed 0xC017. It varies object alignment,
surrounding memory and register inputs. **All 23 RET exits and both outcomes of
all 22 TBNZ instructions were observed.** The ignored evidence report records
input/code/native-executable hashes, exact range/opcodes, call graph, complete
signed arrays and corpus hash, sandbox/limit, comparison fields and coverage.
This is not proof for every machine state; full SIMD, FPCR/FPSR, fault delivery,
calls/ABI, imports and platform startup remain outside the contract.

```bash
uv sync --locked
uv run python tools/recomp.py inspect --output generated/count-members-inventory.json
uv run python tools/recomp.py lift --output generated
cmake -S . -B build -G Ninja
cmake --build build
PYTHONPATH=tests uv run python -m unittest test_count_members_backend
uv run python tools/verify_count_members.py
ctest --test-dir build --output-on-failure
uv run python -m unittest discover -s tests -p 'test_*.py'
uv run python tools/verify_integer.py
uv run python tools/verify_memory.py
uv run python tools/verify_control_flow.py
uv run python tools/verify_leaf.py
python3 tools/load_image.py --load-bias 0x100000000 --guest-page-size 0x1000 \
  --output generated/count-members-gtasa-load-recheck.json
```

Evidence stays in ignored `generated/count-members-verification.json`, with
regression logs and the separate data-only baseline report. Original binaries,
lifted output, reports and native executables are not Git inputs. No initializer,
constructor, JNI_OnLoad, IFUNC resolver, device operation or game was executed.

Validation passed: locked dependency sync, fresh input inspection/lifting
(21 selected functions / 184 instructions), C++11 CMake/Ninja build, all seven
CTests and all 144 Python methods. Existing original-function differential
regressions also passed: 760 integer, 1,216 memory, 760 control-flow and 2,048 FP
calls / 6,144 FP result words. Existing instruction/addressing rejection and
loader/inventory data-only tests remain active.

The separate legacy data-only recheck at bias 0x100000000 and guest page size
0x1000 retained **5,252 RELATIVE applied; 21,458 unresolved (21,072 preemptible /
386 undefined); 274 unresolved imports; sealed RELRO; readiness false**.
It checked 8,908,241 file bytes and 4,908,543 BSS bytes. No packed-relocation
application, dependency resolution, ABI bridge or platform initialization was
added. The next bounded AOT proposal is acyclic CMP-driven B.cond support using
the represented flags; the known non-leaf callers still contain other blockers.
