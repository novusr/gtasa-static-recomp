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

The `scalar-leaf-v1` backend accepts straight-line functions ending with a single
`ret` through x30. The only other accepted instructions are `nop`, scalar `ldr`
and `ldp` into S registers using X-register base plus constant offset without
writeback/indexing, `fmul`, `fmadd` and `fnmsub` on S registers. Every instruction
must decode and pass validation. Unsupported instructions fail the whole request.

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
use explicit little-endian conversion. There is no guest loader yet; the test
harness populates its input data directly. It maps the HFA return convention to
S0/S1/S2 in the explicit guest state rather than relying on the host C++ ABI.

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

The loader must map data and BSS, apply AArch64 relocations in guest memory,
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
- Remill: https://github.com/lifting-bits/remill
- Unicorn test oracle: https://www.unicorn-engine.org/
