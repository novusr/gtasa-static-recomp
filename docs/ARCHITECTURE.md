# Static Recompilation Architecture

## Pipeline

```text
ARM64 ELF + configured hash
    -> ELF inventory (segments, symbols, imports, relocations)
    -> selected executable symbol ranges
    -> strict AArch64 decoding and instruction validation
    -> generated C++ operations over explicit guest state
    -> host compiler -> native Linux x86_64 executable
```

Code is decoded during generation only. The runtime does not fetch or interpret
ARM64 instructions. Original guest addresses are provenance and address-space
identifiers, not host addresses or permission to dereference a host pointer.

## Current supported subset

The `control-flow-v1` backend accepts acyclic control-flow functions ending with
`ret` through x30 on all paths. It retains the v1 FP instructions (`nop`, scalar
`ldr` and `ldp` into S registers using X-register base plus constant offset
without writeback/indexing, `fmul`, `fmadd`, `fnmsub`) and v3 integer memory
instructions (`ldr`, `str`, `ldrb`, `strb`, `ldrh`, `strh` unsigned scaled
immediate). Every instruction must decode and pass validation. Unsupported
instructions or malformed control flow fail the whole request.

### Control flow subset (Phase 1: Acyclic CFG)

The backend forms basic blocks and validates intrafunction control flow before
emitting native C++:

| Form | Semantics and width | Register 31 / Operands | Successors |
| --- | --- | --- | --- |
| Direct B (`b <target>`) | Unconditional intrafunction jump | None; signed imm26 (* 4) PC offset | Single target block |
| CBZ (`cbz <Rt>, <target>`) | Jump if register is zero; W (32-bit) or X (64-bit) | Rt=31 denotes WZR/XZR (value 0, branch taken) | Fallthrough (PC+4), Target |
| CBNZ (`cbnz <Rt>, <target>`) | Jump if register is nonzero; W (32-bit) or X (64-bit) | Rt=31 denotes WZR/XZR (value 0, branch not taken) | Fallthrough (PC+4), Target |
| RET (`ret [x30]`) | Subroutine return | Only x30 is supported (register 30) | Terminal (none) |

Validation rules enforced equally by `scan` and `lift`:
1. **Target alignment and bounds**: Every branch target must be within `[fn_start, fn_end)`
   and align exactly to a successfully decoded 4-byte instruction start.
2. **Path termination**: Every path from the entry block must terminate with `ret`.
   Fallthrough exiting the function boundary without `ret` is rejected.
3. **Acyclic graph**: Directed cycle detection via DFS rejects loops and backward
   cycles.
4. **No dead/unreachable code**: Every basic block in the function must be reachable
   from the entry point.
5. **Rejected control flow**: Subroutine calls (`bl`, `blr`), indirect branches (`br`),
   indirect returns (`ret xn` where `n != 30`), test-and-branch (`tbz`, `tbnz`), and
   conditional branches requiring condition flags (`b.cond`: `b.eq`, `b.ne`, etc.)
   are rejected. State has no NZCV flags.
6. **Register width accuracy**: CBZ/CBNZ on W registers (`sf=0`) strictly evaluates
   bits 31:0 (`static_cast<uint32_t>(state.x[rt])`), correctly ignoring any dirty
   upper bits 63:32. X registers (`sf=1`) evaluate all 64 bits.

Native C++ control flow is emitted directly using labeled blocks (`loc_<address>:`)
and direct `goto loc_<target>;` or `if (<cond>) goto loc_<target>;` statements.
No runtime interpreter loop, instruction dispatcher, or switch statement is created.

The integer extension validates encoding fields rather than inferring SP/ZR
semantics from disassembler text. The supported forms are:

| Form | Width and operands | Register 31 |
| --- | --- | --- |
| MOV register (ORR alias) | W/W or X/X, unshifted register copy | Source ZR; destination write discarded |
| MOV wide immediate / MOVZ / MOVN | 16-bit immediate, LSL 0/16 for W or 0/16/32/48 for X | Destination write discarded |
| MOV to/from SP (ADD immediate zero alias) | W/WSP or X/SP | Source/destination SP |
| ADD/SUB immediate, S=0 | W/WSP or X/SP, unsigned imm12, optional LSL 12 | Source/destination SP |
| ADD/SUB shifted register, S=0 | Matching W or X width, LSL 0..31 or 0..63; includes NEG alias of SUB with Rn=ZR | All operands use ZR, never SP |

Unsigned C++11 arithmetic and explicit narrowing implement modulo 2^32/2^64.
Every W/WSP destination write clears bits 63:32; ZR writes leave SP and all
stored registers untouched. No flags are written. ADDS/SUBS and their CMP/CMN
aliases, extended-register operands, LSR/ASR/ROR, MOV bitmask-immediate (ORR
alias), MOVK, vector MOV and invalid/reserved encodings are rejected. Integer
arithmetic does not access guest memory or establish a guest stack mapping.

`scan` and `lift` call the same integer validator/emitter. Scan still marks every
function `not_verified`, even when separate differential evidence exists. The
integer oracle reports only the tested input corpus and exact original ranges;
the synthetic suite also compares against explicit arithmetic expectations.
It checks all x[], SP, low S[] and preservation of guest NZCV; it does not model
additional architectural state or prove all possible inputs. The original
register-only selections contain MOV and ADD; SUB is tested with synthetic
encodings and original `ShaderSort` in the memory oracle below. See README for
reproducible commands and corpus sizes.

### Integer memory subset

V3 adds integer LDR/STR W/X, LDRB/STRB and LDRH/STRH in the unsigned scaled
immediate encoding only: `Rt, [Xn|SP, #imm12 * access_size]`, no writeback.
The encoding's V bit must be zero and opc must specify a plain store or
zero-extending load. Rn=31 means SP; Rt=31 means ZR, never SP. Loads into W,
including byte/halfword loads, zero-extend into the stored 64-bit X register.
Stores write only the low 8/16/32/64 source bits. A load to ZR discards the
value but still performs the checked access. Non-writeback Rn/Rt aliases are
valid: the address uses the old base before a load assigns its destination.

Literal, register-offset, LDUR/STUR (including signed immediates), pre/post-index,
sign-extending loads, integer pairs, exclusive/acquire/release and SIMD memory
forms remain unsupported. Existing scalar S-register FP LDR/LDP support remains
unchanged. The instruction emitter used by both scan and lift enforces these
boundaries before publishing translation output.

Generated declarations and definitions use `void fn(State&, Memory&)`. Integer
and FP readers still work with the same interface; stores mutate the checked
guest sandbox. `Memory` has unsigned load/store8/16/32/64 methods, reconstructs
values little-endian and checks the entire width before any byte access.
No wide host dereference, guest-pointer cast or unchecked fast path is used.
Failed individual stores leave all bytes untouched; failed loads leave their
destination unchanged. This does not roll back earlier successful instructions.

Effective addresses wrap modulo 2^64 during unsigned base-plus-offset arithmetic.
The subsequent access may not cross UINT64_MAX or a sandbox boundary. Range
checks use subtraction, so even an 8-byte access ending at UINT64_MAX can be
represented without overflowing an exclusive-end calculation. Unaligned normal
memory is supported, assuming alignment/SP-alignment checking disabled; memory
permissions, devices, tags, guest data aborts and exception delivery are not
modeled. A host bounds exception is a runtime rejection, not an emulated abort.

The native memory smoke test covers all widths, small/empty buffers, every
alignment, high addresses, unchanged bytes after failed stores and bytewise
endian expectations. Synthetic differential tests compare explicit expected
registers and memory with native C++11 and Unicorn; separate compiled generated
fault tests check atomic failure of loads/stores including ZR and base aliases.
The original-memory oracle uses hash-validated code and explicit test pointer
arguments, compares all x[], SP, low S[], complete sandbox bytes and preservation
of NZCV. Its evidence report is separate from scan's `not_verified` status.

`fmul` rounds separately. Fused operations use binary32 `std::fma`; `fnmsub`
computes the product minus the addend. Native compilation disables implicit FP
contraction and fast-math. The prototype assumes round-to-nearest and does not
model FPCR, FPSR, NaN payload rules, traps or all signed-zero/denormal cases.
The smoke test and ARM oracle cover finite integer-valued operands only.

State has 31 general-purpose registers, SP, and the low 32 bits of 32 FP
registers. Static assertions verify its layout. It deliberately cannot represent
full SIMD lanes, condition flags, TLS, exclusive monitors or exceptions. There
is no attempt to execute code requiring that state.

The checked demo memory owns bytes in a guest address range. Access below the
base, beyond the end or through an overflowing range throws. Multi-byte accesses
use explicit little-endian conversion. The leaf test harness populates its input
data directly and maps the HFA return convention to S0/S1/S2 in the explicit guest
state rather than relying on the host C++ ABI. The separate ELF data loader
supplies checked, disjoint PT_LOAD mappings through the same Memory interface;
see [ELF loading](ELF_LOADING.md) for hash, bias, BSS and inventory contracts.

## ELF analysis

`tools/recomp.py inspect` inventories `PT_LOAD` segments with file and memory
sizes, aliases, defined function symbols from both symbol tables, dynamic imports,
`DT_NEEDED` libraries and relocations (including addends). It does not apply
relocations or call ELF initializers. Reading instructions uses `p_offset +
(vaddr - p_vaddr)` and requires file-backed executable segments.

Original Ghidra addresses in this project are generally ELF virtual addresses
plus the configured image base (0x100000). Lifting uses ELF symbol values directly.
The analyzer does not treat zero-sized/undefined symbols as defined function
bodies, nor invent missing function boundaries.

`tools/recomp.py scan` validates the same configured input and checks every
inventoried function range against the leaf backend's shared instruction
validator. It reports all grouped rejections rather than stopping at the first
instruction, and checks executable file backing and code relocations as lifting
does. Unsupported decoded instructions, addressing/operand forms and decoding
gaps are blockers; diagnostic decoding after a gap does not authorize execution.
Aliases share analysis only when both address and size match. The JSON report
separates backend acceptance (`translatable`/`blocked`) from semantic evidence
(`not_verified` for every entry), and lists imports as unresolved. It provides
neither CFG recovery nor evidence that an accepted function is safe under all
guest FP states. See README for the command, aggregation rules and scan scope.

## What a full runtime needs

A full backend must recover basic blocks, direct/indirect branches, jump tables,
PLT calls and function pointers, including code absent from symbol tables.
Import calls must marshal the guest AAPCS64 ABI to the host ABI: pointers,
structures, HFAs, callbacks, variadic calls and return values all need explicit
rules. Reusing host libc with guest pointer values is invalid.

The data loader now maps PT_LOAD data and BSS with an explicit bias, but never
reports execution readiness. Its explicit, transactional RELA RELATIVE phase
writes bias plus signed addend modulo 2^64 through checked guest memory, requiring
aligned targets wholly inside existing PF_W mappings. Applied and unresolved
entries are separate; repeat application is a no-op. A separate internal-symbol phase supports RELA
ABS64/GLOB_DAT/JUMP_SLOT for proven non-preemptible definitions, retaining table
and index identity. SHN_ABS does not receive bias; other supported symbols do.
A combined API plans both phases transactionally, preserving prior applied
entries. JUMP_SLOT accepts only zero addends pending platform policy and patches
a guest-address data slot only. Default-visible global/weak definitions, all
undefined imports, IFUNC, TLS, COMMON, symbol versioning and other unsupported
forms remain unresolved. No resolver is invoked. See [ELF loading](ELF_LOADING.md)
for ABI sources, resolution rules, arithmetic and target policies. A full loader must apply further AArch64 relocations in guest memory,
initialize TLS and constructors, and dispatch guest addresses to compiled entry
points. ELF segments must never be executed directly by the x86_64 host.

The real binary imports Android asset management, logging, EGL/GLES, OpenSL ES,
OpenAL, libc/libm, C++ ABI helpers and Social Club services. Inventory is available
in `generated/inventory.json`. No service is implemented by a fake success stub.
A desktop runtime must provide the corresponding behavior or reject startup.

Potential larger lifting backend: Remill supports AArch64-to-LLVM lifting, but
integrating it still requires CFG recovery, a loader and platform bridges. It is
not a dependency or a claimed capability of this prototype.

References:

- Capstone operand API: https://www.capstone-engine.org/lang_python
- Arm A64 instruction reference (MOV SP alias of ADD immediate): https://support.arm.com/documentation/ddi0602/2025-03/Base-Instructions/MOV--to-from-SP---Move-register-value-to-or-from-SP--an-alias-of-ADD--immediate--
- Arm instruction set reference guide (ADD/SUB and MOV encodings): https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab
- Arm A64 LDR immediate addressing and scaling: https://support.arm.com/documentation/100069/0608/A64-Data-Transfer-Instructions/LDR--immediate-
- Remill: https://github.com/lifting-bits/remill
- Unicorn test oracle: https://www.unicorn-engine.org/
