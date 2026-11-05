# Guest ELF image data loading

`recomp::ElfImage::load(path, expected_sha256, load_bias, memory_limit)` loads
verified ELF data into the same checked `Memory` interface used by generated
C++ functions. The expected lowercase SHA-256 must come from trusted input
configuration, not a digest computed from an untrusted replacement file. The
loader hashes its single captured file buffer with OpenSSL libcrypto before
parsing ELF headers or publishing any mappings; hashing and copying use the
same buffer. It never uses `dlopen` or creates host executable mappings.

This is a data-loading foundation, not a runnable Android process. The loader
never calls a constructor, `JNI_OnLoad`, ELF entry, import, or game function.
`ready_to_execute()` always returns false, including for empty inventories.
Guest ARM64 instruction bytes can be copied as ordinary data but are never
fetched, interpreted, JIT compiled, or executed by this loader.

## Mapping contract

Supported inputs are little-endian AArch64 ELF64 ET_DYN files with ordinary
program and section header numbering. For every PT_LOAD:

- The guest start is checked `load_bias + p_vaddr`. The caller must supply the
  bias explicitly; the Ghidra analysis base is unrelated.
- Exactly `p_filesz` bytes from `p_offset` are copied. The remainder through
  `p_memsz` is zero-filled, including segments containing only BSS.
- File ranges, `p_filesz <= p_memsz`, address addition, exclusive segment ends,
  allocation sums, host size conversion and segment overlaps are checked.
- `p_align` may be 0, 1, or a power of two. Larger alignments require congruent
  file/virtual offsets and an aligned load bias. Unknown permission bits fail.
- Allocation is per segment. Gaps consume no backing storage and remain unmapped;
  page rounding does not make gaps accessible. Empty segments map no bytes.
- PF_R/PF_W control runtime data accesses. PF_X is metadata, never host execution
  permission. This does not yet implement RELRO transitions or guest exceptions.

The default total guest allocation limit is 512 MiB and can be lowered or raised
explicitly. File ingestion has a separate fixed 512 MiB limit. Segment exclusive
ends equal to 2^64 are rejected, even though the existing standalone sandbox
still supports a final byte at UINT64_MAX. Overlapping PT_LOAD ranges are
rejected rather than merged according to a platform-specific page policy.

Guest addresses remain uint64_t identifiers, never host pointers. Every access
checks its entire width before touching bytes; rejected stores leave all bytes
unchanged. Accesses must fit within one segment, so a multi-byte access spanning
adjacent segments is currently rejected. Existing flat sandbox construction and
its boundary behavior are preserved. The image owns storage; callers may pass
`image.memory()` to compatible generated functions after separately establishing
that the function's data and runtime requirements are satisfied.

## Explicit RELA RELATIVE application

Loading still leaves every relocation unresolved. After a successful verified
load, `image.apply_relative_relocations()` applies only SHT_RELA entries of type
1027 (`R_AARCH64_RELATIVE`), moving them to `applied_relocations()` and removing
them from `unresolved_relocations()`. Imports are unaffected. This operation
never invokes guest code, even when the resulting pointer identifies code or
an initializer array. `ready_to_execute()` remains false.

The normative reference is Arm's [AAELF64](https://github.com/ARM-software/abi-aa/blob/2026Q3/aaelf64/aaelf64.rst),
sections **Relocation operations**, **Dynamic relocations**, **RELATIVE
relocation**, and **Idempotency**, together with the base ELF64 signed
`Elf64_Sxword` definition for `Elf64_Rela.r_addend` in the
[generic ABI](https://gabi.xinuos.com/elf/06-reloc.html).
The stored value is `(load_bias + signed r_addend) mod 2^64`, at checked
`load_bias + r_offset`, encoded as eight little-endian bytes. AAELF64 calls the
bias Delta: the adjustment from link to load addresses. The explicit addend is
a signed two's-complement 64-bit integer; unsigned addition of its raw bits
computes the reduced result without signed C++ overflow or implementation-defined
unsigned-to-signed conversion. A negative sum or sum exceeding UINT64_MAX wraps
to the target width; it is not treated as an overflowing mapping calculation.
Target address addition, by contrast, must not overflow. The pointer value itself
need not designate mapped storage (for example, it may be a sentinel).

Targets must be 8-byte aligned, use symbol index zero, and fit entirely within
one existing mapping. Every full 8-byte write is validated through checked
`Memory::region` with write permission. **Permission policy: require the original
PT_LOAD PF_W bit.** Read permission is not required; write-only mappings stay
write-only. Read-only and executable/read-only mappings are rejected; no global
write window, permission override, host mapping or guest-pointer cast is used.
PF_X remains metadata. PT_GNU_RELRO sealing is still unimplemented: data in a
PF_W load segment is writable during and after this phase; this change does not
claim final linker permissions or execution readiness. Supporting a read-only
relocation target later requires an explicit bounded policy, not an automatic
permission bypass.

All selected entries, symbol constraints, alignment, mapping ranges, permissions
and duplicate targets are validated before any write. Supported targets shared
with any other inventory entry are rejected because relocation composition is outside this phase. Separate
applied/unresolved reports and the write plan are fully allocated before commit;
validation/allocation failure leaves image bytes and statuses unchanged. Commit
uses checked little-endian stores and swaps the prepared reports. Callers must
provide exclusive access during application, as for other mutable Memory access.
A successful invocation records completion; subsequent calls are no-ops, including
when no supported entries existed. It never reads the old pointer as an addend,
so bias cannot accumulate. A failed invocation may be retried after correcting
external memory state; no entries have been consumed.

REL RELATIVE remains unresolved, without reading its implicit addend. All other
ordinary relocation types (including NONE, ABS64, GLOB_DAT, JUMP_SLOT, TLS and
IRELATIVE) remain unresolved, with no resolver calls, host dlsym or success
stubs. Packed formats retain the existing explicit rejection. The full unresolved
inventory is retained for further linker work; applying this subset is not a
complete link operation.

## Unresolved work inventory

`unresolved_imports()` records every named undefined SHT_DYNSYM symbol, including
weak imports, with its symbol index, type and binding. `unresolved_relocations()`
records SHT_REL/SHT_RELA entries with biased target addresses, numeric types,
symbol indices/names and explicit addend bits when present. REL addends remain
implicit and are not read/applied. Unknown ordinary relocation types remain
unresolved report entries. No symbol is assigned a fake implementation and no
relocation changes guest memory during load. Only the explicit operation above
changes supported targets. DT_NEEDED libraries are listed separately.

This first inventory implementation requires section headers. Sectionless ELF,
extended numbering, Android packed relocations and RELR are rejected. A
PT_DYNAMIC must have a matching SHT_DYNAMIC file range; dynamic symbol, string
and relocation table pointers/sizes must match inventoried sections. Malformed
links, entry sizes, strings and symbol references are rejected. This is not a
complete Android linker or a declaration that all dynamic tags are implemented.
Widths and target suitability for unsupported relocations, symbol versions,
visibility/resolution, TLS, dependencies, constructors and ABI requirements still need validation in
a future linker/startup stage. An empty unresolved inventory alone cannot
establish execution readiness.

## Verification

Build requires OpenSSL development headers/libcrypto in addition to the existing
C++11/CMake/Ninja toolchain. Run:

```bash
uv sync --locked
uv run python tools/recomp.py inspect --output generated/inventory.json
uv run python tools/recomp.py lift --output generated
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
uv run python -m unittest discover -s tests -p 'test_*.py'
python3 tools/load_image.py --load-bias 0x100000000 --output generated/image-load.json
```

The synthetic tests compile a fresh native C++11 loader and test nonidentity
VA/file offsets, zero/nonzero/high biases, sparse ranges, BSS-only segments,
permissions, holes, boundary-store atomicity, SHA mismatch, malformed/truncated
ELF, overflow, overlaps, allocation limits and unresolved inventories. They need
no original game input. The standalone sandbox and previous semantic suites
remain in place.

CTest's `original_image_load` uses the configured path/hash, supplies an explicit
nonzero bias, compares every readable file-backed byte and every readable BSS
byte, probes holes and segment permissions, and writes `build/image-load.json`.
The manual command writes separate applied and unresolved inventories to ignored
`generated/`.
Before fixups the native probe retains all existing file/BSS, hole and permission
checks. It snapshots readable image bytes, applies the supported subset, checks
every resulting pointer and little-endian byte, calls application again, and
compares the entire readable image against the expected patched snapshot.
`tools/load_image.py` separately verifies the input hash and decodes RELA from
the original file using Python `struct` and signed arbitrary-precision arithmetic;
it compares every applied address, addend, value and byte with the native report.
Failure returns nonzero without publishing a new report; an old report may still
exist. It never calls any function from the guest image.

For the configured GTA:SA input, the smoke test checks 8,908,241 file bytes and
4,908,543 BSS bytes in two PT_LOAD mappings, with SHA-256
`12527bfdb63889c02d24366629e808cb446d354a2b380348bd661da4edc6af11`
and explicit bias `0x100000000`. Verification on 2026-11-05 applied and independently
checked 5,252 RELATIVE entries, leaving 21,458 relocations and all 274 imports
unresolved. The report records `relative_values_checked=5252` and readiness false.
These counts describe loading, not game completion or instruction-backend coverage.

Synthetic relocation checks cover zero/nonzero/high bias, positive/zero/negative
addends including INT64_MIN/MAX, modular result overflow/underflow, exact pointer
values/bytes, unmapped/unaligned targets, target-address overflow, writes across
mapping ends (including adjacent mappings), original PF_W policy and retained
read denial on write-only segments, duplicate/symbol rejection, failure without
partial byte/status mutations, repeat application, mixed-type composition rejection,
and unsupported REL/types.

The 2026-11-05 validation run passed the C++11 build, all four CTest tests
(including the original-image check), all 55 Python regression tests (17 loader
cases), and the existing leaf/integer/memory/control-flow differential commands.
No game startup, constructors, JNI_OnLoad or initializer execution is part of
the image smoke test.

Next implement symbol-dependent relocations with dependency and symbol resolution,
RELRO sealing and further format support as required, explicit guest/host
ABI bridges and compiled-address dispatch. TLS, stack/thread state and platform
services must precede controlled initializer execution. Unsupported requirements
must reject startup; no interpreter, JIT, or success-stub fallback is implied.
