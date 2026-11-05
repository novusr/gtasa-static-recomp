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
  permission. Explicit RELRO sealing can remove PF_W; guest exceptions are not implemented.

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
PF_X remains metadata. A PF_W target is writable until an explicit RELRO seal
removes its write permission. Neither loading nor relocation application seals
the image or establishes execution readiness. Supporting a read-only
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

REL RELATIVE remains unresolved, without reading its implicit addend. The
separate symbol phase below supports a bounded RELA subset. NONE, TLS, IRELATIVE
and all other ordinary types remain unresolved, with no resolver calls, host
dlsym or success stubs. Packed formats retain the existing explicit rejection.
The full unresolved inventory is retained for further linker work; applying
this subset is not a complete link operation.

## Explicit RELA internal-symbol application

`image.apply_symbol_relocations()` selects supported internal definitions for
RELA ABS64 (257), GLOB_DAT (1025) and JUMP_SLOT (1026).
`image.apply_relocations()` plans both this subset and RELATIVE in **one
transaction**. Prefer the combined API when the entire supported set must succeed
or fail together. Loading alone still performs no fixups. The old RELATIVE API
retains its limited scope. Both phases retain prior applied records, have separate
completion guards, and may be called in either order. A successful empty phase
also completes; failed phases retain their pending entries and may be retried.
Separate calls are separate transactions: a later failure preserves earlier
successful work, while its own bytes and inventories remain unchanged.

The normative sources are Arm [AAELF64 2026Q3](https://github.com/ARM-software/abi-aa/blob/2026Q3/aaelf64/aaelf64.rst),
**Symbol Table**, **Relocation operations**, **Static data relocations**,
**Dynamic relocations**, **ABS relocations**, **GLOB_DAT relocation** and
**JUMP_SLOT relocation**; and the generic ABI [Symbol Table](https://gabi.xinuos.com/elf/05-symtab.html)
(**Binding**, **Type**, **Visibility**, **Section Index**, **Symbol Value**),
plus [Relocation](https://gabi.xinuos.com/elf/06-reloc.html) for explicit addends,
table links and composition. These sources were checked on 2026-11-05.

All three operations use `S + signed A`, reduced modulo 2^64. ABS64 has no
field overflow check. The dynamic-relocation rule requires an 8-byte aligned
64-bit data target, including dynamic ABS64; the static ABS64 table's byte
alignment is not used to relax this ET_DYN loader's policy. Ordinary defined
ET_DYN symbol values are virtual addresses, so `S = checked(bias + st_value)`;
for SHN_ABS, `S = st_value` without bias. Address formation remains checked;
only the final relocation expression wraps. The signed addend is represented
by its raw bits and added with unsigned C++11 arithmetic. Neither S nor the
final value is converted to a host pointer. The final value need not name mapped
storage: addends and absolute values can represent sentinels or end markers.

AAELF64 delegates whether to honor a RELA JUMP_SLOT addend to the platform ABI.
This loader supports **only zero JUMP_SLOT addends**, whose result is independent
of that choice. Nonzero addends stay unresolved pending verified platform policy.
JUMP_SLOT only patches data with a guest address. It supplies no lazy binding,
dispatch, guest/host ABI bridge, execution permission or resolver call.

Resolution uses exactly the relocation section's `sh_link` table and the
relocation's symbol index. It never searches by name or merges aliases across
tables. `symbols()` inventories every SHT_SYMTAB/SHT_DYNSYM entry, preserving
origin section/type, index, name, value, size, section index, binding, type,
visibility and complete st_other. Relocations carry their exact definition
metadata and an unresolved reason. Invalid table/index references and ordinary
out-of-range section indices reject loading before mappings are published.

The bounded resolution policy is:

- A nonzero symbol index must identify a defined symbol. Every undefined symbol,
  including weak, stays unresolved. STN_UNDEF is also unresolved for this phase;
  it is not treated as an internal zero-valued definition.
- Supported bindings are LOCAL, GLOBAL and WEAK. LOCAL is non-preemptible;
  GLOBAL/WEAK require HIDDEN, INTERNAL or PROTECTED visibility. Generic ABI
  INTERNAL includes HIDDEN's non-preemption constraints. LOCAL+PROTECTED is
  invalid. Default-visible global/weak definitions remain preemptible regardless
  of matching names, same-image addresses, or apparent absence of other modules.
  DT_SYMBOLIC/DF_SYMBOLIC are not used to enlarge this policy.
- Supported symbol types are NOTYPE, OBJECT, FUNC and SECTION. IFUNC, TLS,
  COMMON, FILE and other types remain unresolved. No resolver is invoked.
- Supported section indices are ordinary SHF_ALLOC sections and SHN_ABS.
  Ordinary symbols must fit in their defining section (zero-sized end markers
  are allowed). Nonallocated or TLS sections are excluded. COMMON, XINDEX and
  other reserved indices remain unresolved. Extended section indices are not
  inferred from auxiliary tables.
- Any st_other bits beyond the ordinary low two visibility bits are excluded,
  including VARIANT_PCS and additional visibility forms. A symbol table linked
  by SHT_GNU_versym is conservatively excluded from symbol resolution. Version
  definitions/requirements and special binding rules need their own validation.

The `unresolved_reason` strings distinguish undefined/preemptible symbols,
IFUNC/TLS/COMMON, unsupported symbol types/bindings/attributes/sections/versioning,
invalid local-protected visibility, nonallocated sections, symbol values outside
sections, nonzero JUMP_SLOT addend policy, implicit REL addends and other relocation
types. Eligible entries before explicit application use `internal_symbol_not_applied`
or `relative_not_applied`. The smoke report includes these reasons and definition
metadata; imports stay in their independent unresolved inventory.

Every selected write uses the same checked full-range PF_W validation as
RELATIVE. Read permission is never granted for fixups. All report storage and
write plans are allocated before committing any byte. Shared or overlapping
8-byte target ranges are rejected against both unresolved and already applied
entries. For unsupported types the conservative exclusion covers any target
start less than eight bytes away on either side; their actual widths are not
inferred and they do not gain permission to write. No relocation composition is implemented. Successful
commit uses checked little-endian stores, then swaps prepared inventories and
marks only the requested phases complete. Exclusive image access is required.

## Explicit PT_GNU_RELRO sealing

Sources checked on 2026-11-06:

- The generic ABI [Program Header](https://gabi.xinuos.com/elf/07-pheader.html),
  especially the definitions of p_vaddr, p_memsz, p_offset and p_align. Alignment
  0/1 means no alignment requirement; larger p_align values are powers of two
  with congruent virtual/file offsets. p_align is not a declaration of page size.
- Android's official [Bionic linker_phdr.cpp](https://android.googlesource.com/platform/bionic/+/master/linker/linker_phdr.cpp),
  `_phdr_table_set_gnu_relro_prot` and `phdr_table_protect_gnu_relro` (inspected
  blob `5967e2d48a29cbbaca8f87a2be42361ab43decd5`). The ordinary Android path
  protects all pages touched by p_vaddr through p_vaddr+p_memsz, rounding the
  start down and the exclusive end up, with load bias added. Protection is a
  separate step after relocation. Current Bionic also has segment padding and
  16 KiB compatibility paths; this loader does not implement those paths.
- Official Android [page-size guidance](https://developer.android.com/guide/practices/page-sizes),
  including its RELRO alignment discussion. Android supports differing page
  sizes; an unaligned RELRO end can protect subsequent writable data on the
  same page. Neither host page size nor ELF p_align identifies a guest profile.

`image.relro_segments()` retains every original RELRO header's virtual address,
file offset/size, memory size, flags and alignment, together with checked biased
`address`. Loading validates these before publishing mappings. The bounded input
policy requires nonempty raw intervals `[bias+p_vaddr, bias+p_vaddr+p_memsz)`
inside one original PT_LOAD, no raw overlap, filesz <= memsz, valid file bounds,
known flag bits, checked exclusive ends and bias addition, and the same alignment
checks as PT_LOAD. File-backed RELRO must describe the owning load's exact file
bytes; BSS-only RELRO is allowed. Empty headers, straddling/gapped raw intervals,
overlapping headers and inconsistent file provenance are explicitly unsupported.
These are conservative loader restrictions, not a claim that all other layouts
are forbidden by ELF.

Call `image.seal_relro(guest_page_size)` explicitly. The argument must be a nonzero
uint64 power of two, and a nonempty RELRO inventory requires a page-aligned bias.
There is no default page size and no host-page query. The native/Python smoke
passes `--guest-page-size 0x1000` as an explicit 4 KiB test profile, not an inferred
property of the input or a claim about every Android device. Small powers of two
in synthetic tests exercise arithmetic; accepting a geometry does not validate a
complete Android platform configuration.

For each header, calculate `lo=floor(p_vaddr/P)*P+bias` and
`hi=ceil((p_vaddr+p_memsz)/P)*P+bias` with checked rounding and additions.
The effective protected interval is the intersection of `[lo,hi)` with its
owning PT_LOAD. This retains the existing exact-byte mapping contract: unmapped
prefix/suffix page padding acquires neither storage nor access permissions.
If the rounded envelope touches another nonempty PT_LOAD, sealing rejects it;
shared-page segment permission merging is outside this loader. Multiple disjoint
headers are supported, but intersecting rounded protection intervals are rejected
rather than silently merged. `sealed_relro_ranges()` reports the effective biased
intervals; the original unrounded inventory remains available separately.
The rounding can remove write permission from mapped bytes outside the raw
RELRO interval on its boundary pages, as the Android page rule requires.

Sealing removes PF_W only (`old_flags & ~PF_W`). PF_R and PF_X are preserved,
never added: a sealed write-only range becomes inaccessible, while neighboring
write-only storage remains write-only. This permission attenuation is deliberately
more restrictive than assigning Bionic's PROT_READ to a range lacking original
read permission. No host mprotect, dynamic loading, symbol lookup, host executable
mapping or guest-pointer cast is involved.

Memory retains each original storage region and installs a separate immutable
permission overlay instead of splitting byte vectors. `Memory::permissions(a,n)`
requires the **whole** nonempty range to fit one original mapping and returns the
permissions valid for the entire access. Reads crossing an overlay edge remain
valid if the original mapping permits reading. A store touching any protected
byte rejects before writing any byte. Accesses across adjacent original mappings
still reject, even with identical flags; sealing does not weaken full-range
validation. The standalone sandbox, including UINT64_MAX boundary checks, retains
its prior behavior.

The complete overlay is validated and allocated in a temporary vector before
commit. Commit swaps it into Memory, records page size, then marks
`relro_sealed()=true`; no byte changes or allocations occur during commit.
Validation/allocation failure preserves all bytes, permissions, inventories,
page-size and sealing status. Exclusive image access is required throughout,
as for relocation batches. Repeating sealing with the same geometry is a no-op;
a different geometry rejects without changing the committed seal. With no RELRO,
a successful call records an empty completed seal and changes no permissions.

Sealing has its own state, independent of both relocation completion guards and
applied/unresolved inventories. Normal order is load, apply supported relocations,
then seal. Sealing before relocation is allowed for inspection/testing, but any
new supported fixup touching sealed storage rejects through the same full-range
write check. A combined relocation batch with even one such target fails without
partial writes or status changes. Relocations outside protected storage remain
eligible. A previously successful relocation phase still returns as a no-op
after sealing. Unresolved imports, unsupported/preemptible relocations, and
initializer requirements remain unresolved; sealing is not startup authorization.
`ready_to_execute()` remains false, even with an empty unresolved inventory.

## Unresolved work inventory

`unresolved_imports()` records every named undefined SHT_DYNSYM symbol, including
weak imports, with its symbol index, type and binding; the complete symbol
inventory retains its table identity and definition metadata. `unresolved_relocations()`
records SHT_REL/SHT_RELA entries with biased target addresses, numeric types,
symbol indices/names and explicit addend bits when present. REL addends remain
implicit and are not read/applied. Unknown ordinary relocation types remain
unresolved report entries. No symbol is assigned a fake implementation and no
relocation changes guest memory during load. Only the explicit operations above
change supported targets. DT_NEEDED libraries are listed separately.

This first inventory implementation requires section headers. Sectionless ELF,
extended numbering, Android packed relocations and RELR are rejected. A
PT_DYNAMIC must have a matching SHT_DYNAMIC file range; dynamic symbol, string
and relocation table pointers/sizes must match inventoried sections. Malformed
links, entry sizes, strings and symbol references are rejected. This is not a
complete Android linker or a declaration that all dynamic tags are implemented.
Widths and target suitability for unsupported relocations, symbol versions,
preemptible/dependency resolution, TLS, constructors and ABI requirements still need validation in
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
python3 tools/load_image.py --load-bias 0x100000000 --guest-page-size 0x1000 --output generated/image-load.json
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
it compares every applied address, type, definition, addend, value and byte,
and every unresolved relocation reason/definition and undefined dynamic import
with the native report.
Failure returns nonzero without publishing a new report; an old report may still
exist. It never calls any function from the guest image.

For the configured GTA:SA input, the smoke test checks 8,908,241 file bytes and
4,908,543 BSS bytes in two PT_LOAD mappings, with SHA-256
`12527bfdb63889c02d24366629e808cb446d354a2b380348bd661da4edc6af11`
and explicit bias `0x100000000`. Verification on 2026-11-06 applied and independently
checked 5,252 RELATIVE entries and zero internal-symbol entries, leaving
21,458 relocations (21,072 `preemptible_symbol`, 386 `undefined_symbol`) and all
274 imports unresolved. There are no safe eligible symbol fixups in this image;
the resolver does not force any definition to be local. The report records
`relative_values_checked=5252`, `symbol_values_checked=0`, explicit zero counts
for ABS64/GLOB_DAT/JUMP_SLOT and readiness false.
These counts describe loading, not game completion or instruction-backend coverage.

Synthetic relocation checks cover zero/nonzero/high bias, positive/zero/negative
addends including INT64_MIN/MAX, modular result overflow/underflow, exact pointer
values/bytes, unmapped/unaligned targets, target-address overflow, writes across
mapping ends (including adjacent mappings), original PF_W policy and retained
read denial on write-only segments, duplicate/symbol rejection, failure without
partial byte/status mutations, repeat application, mixed-type composition rejection,
and unsupported REL/types.

Synthetic internal-symbol tests additionally cover all three types, LOCAL and
GLOBAL/WEAK visibility combinations, same-name symbols in two independent tables,
undefined strong/weak imports, IFUNC/TLS/COMMON and reserved attributes/sections,
versioning exclusion, SHN_ABS invariance, final-field wraparound, invalid indices,
full-range target checks, write-only preservation, REL rejection, overlap with
supported/unsupported types, phase order/isolation, failed transactions/retries,
prior applied status preservation and combined RELATIVE/symbol atomicity.

The 2026-11-06 validation run passed the C++11 build, all four CTest tests
(including the original-image check), all 63 Python regression tests (25 loader
cases), and the existing leaf/integer/memory/control-flow differential commands.
No game startup, constructors, JNI_OnLoad, initializer or IFUNC resolver execution
is part of the image smoke test. The semantic commands run only the existing
bounded test leaves in synthetic harnesses, never guest initialization.

Next implement dependency/preemptible resolution and symbol versioning, verify
platform-specific JUMP_SLOT addend policy, extend RELRO/platform format
support as required, then explicit guest/host ABI bridges and compiled-address
dispatch. TLS, stack/thread state and platform services must precede controlled
initializer execution. Unsupported requirements must reject startup; no
interpreter, JIT, or success-stub fallback is implied.

The RELRO regression suite adds raw/biased inventories, absent/single/multiple
ranges, unaligned starts/ends, mapping clipping, original and rounded overlap,
file provenance, malformed sizes/flags/alignment, raw/bias/rounded-end overflow,
page geometry, before/after relocation order, internal-symbol rejection,
completed-phase no-ops, every access width/offset across permission edges,
neighbor permissions including all eight PF combinations, write-only fixups,
and failure/retry state checks. A test-only allocator fails each allocation in
sealing to verify that no earlier range acquires partial protection.

The original-image smoke now also independently decodes PT_GNU_RELRO program
headers with Python struct, computes rounded intersections using the explicit
guest geometry, and compares native raw/effective reports. The native probe
checks every mapped byte's permissions before/after sealing, preserves readable
bytes, rejects stores at both ends of protected ranges, and repeats sealing and
completed relocation application. The prior file/BSS, hole, relocation-value,
byte, definition and import checks remain in place. No guest code is called.

RELRO verification on 2026-11-06 passed the C++11 build, all four CTest tests,
all 73 Python tests (including ten RELRO test methods with multiple synthetic
cases), and the existing four differential commands: leaf (2,048 calls / 6,144
result words), integer (760 calls), memory (1,216 calls) and control flow (760
calls). Input inspection and lifting also passed with the configured hash.
Both explicit 4 KiB and 16 KiB smoke profiles passed at bias `0x100000000`:

| Guest page size | Raw biased RELRO interval | Effective protected interval | Bytes protected |
| --- | --- | --- | --- |
| 0x1000 | [0x100821958, 0x100852000) | [0x100821958, 0x100852000) | 198,312 |
| 0x4000 | [0x100821958, 0x100852000) | [0x100821958, 0x100854000) | 206,504 |

Each profile checked all 13,816,784 mapped bytes' permissions before/after
sealing and rejected both endpoint stores. The initial rounded prefix remains
unmapped; the 16 KiB profile additionally protects 8,192 mapped trailing bytes,
as required by its page geometry. This is permission-policy evidence, not proof
that the original game supports that device profile. Hash, file/BSS counts,
5,252 applied RELATIVE entries, zero eligible internal-symbol entries, 21,458
unresolved relocations and all 274 unresolved imports are unchanged. Reports
are ignored `generated/image-load.json`, `generated/image-load-16k.json`, and
CTest's `build/image-load.json`. No game, constructor, JNI_OnLoad, initializer
or IFUNC resolver was invoked. Shared-page load layouts, Android padding/compat
modes, dependency/version/preemption resolution, remaining relocation forms and
platform startup remain future work; readiness remains false.


## Read-only linker audit

`tools/audit_linker.py` consumes the native prepared-image inventory and adds
validated dynamic/version metadata, full table/index import identities and
unresolved groups without mutating an existing image or implementing resolution.
Its validation is additional audit tooling; it does not expand the native
loader's accepted resolution subset. See [LINKER_AUDIT.md](LINKER_AUDIT.md) for
reproduction, original-input findings, official references and remaining work.
