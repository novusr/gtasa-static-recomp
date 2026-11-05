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

## Unresolved work inventory

`unresolved_imports()` records every named undefined SHT_DYNSYM symbol, including
weak imports, with its symbol index, type and binding. `unresolved_relocations()`
records SHT_REL/SHT_RELA entries with biased target addresses, numeric types,
symbol indices/names and explicit addend bits when present. REL addends remain
implicit and are not read/applied. Unknown ordinary relocation types remain
unresolved report entries. No symbol is assigned a fake implementation and no
relocation changes guest memory. DT_NEEDED libraries are listed separately.

This first inventory implementation requires section headers. Sectionless ELF,
extended numbering, Android packed relocations and RELR are rejected. A
PT_DYNAMIC must have a matching SHT_DYNAMIC file range; dynamic symbol, string
and relocation table pointers/sizes must match inventoried sections. Malformed
links, entry sizes, strings and symbol references are rejected. This is not a
complete Android linker or a declaration that all dynamic tags are implemented.
Relocation widths, target suitability, symbol versions, visibility/resolution,
TLS, dependencies, constructors and ABI requirements still need validation in
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
The manual command writes the full unresolved report to ignored `generated/`.
Failure returns nonzero without publishing a new report; an old report may still
exist. It never calls any function from the guest image.

For the configured GTA:SA input, the smoke test checks 8,908,241 file bytes and
4,908,543 BSS bytes in two PT_LOAD mappings, with 274 imports and 26,710
relocations remaining unresolved. These counts describe loading, not game
completion or instruction-backend coverage.

Next implement tested relocation application (including target-width and
permission/RELRO policy), dependency and symbol resolution, explicit guest/host
ABI bridges and compiled-address dispatch. TLS, stack/thread state and platform
services must precede controlled initializer execution. Unsupported requirements
must reject startup; no interpreter, JIT, or success-stub fallback is implied.
