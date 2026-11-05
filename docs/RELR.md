# Pure ELF64 little-endian RELR decoding

Implemented on 2026-11-06 from clean HEAD `f335573` in `static-recomp`.
This standalone C++11 helper decodes bytes only. ElfImage, dependency audit,
resolution planner and relocation application do not call or link it. Existing
packed relocation rejection guards remain unchanged. Android packed REL is
outside this API; APS2 RELA has its own separate decoder.

## API and provenance

`include/recomp/relr.h` declares:

```cpp
void decode_relr(const uint8_t* data, std::size_t length, RelrEncoding encoding,
                 RelrResult& output, const RelrLimits& limits = RelrLimits());
```

The caller supplies a readable, immutable byte range for the entire call and
explicitly selects `RelrEncoding::Android` or `RelrEncoding::Standard`. Unknown
identities reject. NULL is accepted only with zero length. No ELF handle,
mutable Memory, resolver or fixup handle is accepted. Input size must be a
multiple of eight; bytes are assembled explicitly as little-endian uint64 words,
including when the host byte-buffer address is unaligned. ELF32 and big-endian
payloads are outside the supported contract; there is no payload signature that
can independently establish the caller's ELF class or byte order.

`RelrResult` records encoding identity, input byte size, encoded word count,
decoded target count and a vector in stream emission order. Each `RelrRecord`
has target `offset`, zero-based target `ordinal`, zero-based `word_index`,
relative `byte_offset` of that eight-byte word, encoding identity, `source`
(Anchor or Bitmap), `bitmap_bit` (zero for anchors, 1..63 for bitmaps), and
`addend_kind=ImplicitTarget`. There is no explicit addend, fabricated r_info,
symbol identity, biased address or applied status. Empty input still retains
caller-selected encoding metadata. These types have no conversion into
ImageRelocation or any application API.

## Semantics and conservative profile

The [Generic ABI section 6.2](https://gabi.xinuos.com/elf/06-reloc.html),
[Bionic android-16.0.0_r1 relocate_relr](https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/linker/linker.cpp)
and [Bionic elf.h](https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/include/elf.h)
were retrieved for this review. The proposal records the pinned Bionic blob
identities. Android and standard RELR have identical payload semantics and
different ELF constants; this API preserves the caller's identity without
inspecting section/tag families.

An even word emits its address and sets cursor to address+8. An odd word
requires a preceding anchor. Bits 1..63 select cursor+8*(bit-1), in ascending
bit order. Each bitmap advances cursor by 504 bytes, including empty word 1.
Consecutive bitmaps and new anchors are supported. New anchors may move backward;
output is never sorted. Empty payload is valid.

Every target calculation, anchor+8 and bitmap cursor advance must fit uint64,
including the final word's advance and empty bitmaps. Wraparound accepted by
unchecked machine arithmetic is deliberately rejected. The final aligned
address UINT64_MAX-7 can be a cursor but cannot be emitted as an anchor because
its subsequent cursor would overflow. The highest possible emitted target under
this nonwrapping profile is UINT64_MAX-15.

The initial conservative ARM64 profile requires eight-byte aligned targets and
rejects duplicate/overlapping eight-byte slots within this stream. The ABI's
encoding itself only excludes odd anchor addresses; these stronger restrictions
are local policy. With aligned eight-byte starts, overlap is equivalent to equal
starts. A temporary sorted address vector detects duplicates while preserving
record order. Adjacent slots are accepted. No monotonic-anchor rule is imposed.

ELF section/tag/entry-size binding, PT_LOAD/file provenance, mapped extents,
permissions, load bias, symbols and cross-table/format overlaps are later
integration work. The decoder never reads target bytes or opens a library.
It neither computes relocated values nor applies them. Decoding does not make
the ten rejected device libraries accepted, linked or executable.

## Limits and atomic publication

Defaults per call are 1,000,000 targets and 256 MiB. A bitmap can emit 63
records from eight bytes, so encoded length is not an allocation bound. A first
pass validates state/arithmetic and counts targets without allocating record
storage. A second pass fills exact-sized vectors. The storage budget is:

```text
sizeof(RelrResult) + sizeof(vector<uint64_t>)
+ count * (sizeof(RelrRecord) + sizeof(uint64_t))
```

The 64-byte record includes all tuple/provenance fields; its size and every field
offset are statically asserted. The extra eight bytes per target and vector
object cover the entire temporary duplicate-validation array. On this build
fixed storage is 80 bytes and each target costs 72 bytes, so the million-target
budget is 72,000,080 bytes. Sorting uses that array in place without an additional
heap array. The budget covers inventory and validation containers, excluding
allocator bookkeeping, ordinary call-stack frames/scalars, caller-owned input,
exception diagnostic strings, and any old output kept alive for atomicity.
Peak live memory includes the old output as well as these temporary containers.

Checked count increment, subtraction/division before multiplication, host size
conversion checks, and both vectors' max_size checks precede allocation. Invalid
size/identity/state/arithmetic, exceeded limits and allocation errors reject
without clamping, truncation or publishing a prefix. Raised caller limits do
not bypass host storage/container bounds. Limits are per call: cumulative
per-object limits across APS2, RELR and ordinary tables remain unimplemented.

All allocation and validation occur on temporary results, including duplicate
checking after expansion. Publication uses nonthrowing vector swap and scalar
assignments only. On any exception previous contents, metadata, capacity and
storage address are unchanged; an initially empty result stays unchanged.
Allocation exceptions propagate. `RelrDecodeError` reports the relevant encoded
word's byte offset (partial input reports the partial word start). Whole-result
storage/duplicate errors report offset zero; exact target origins remain in the
temporary records but no prefix is exposed on failure.

## Verification

```bash
uv sync --locked
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure \
  -R '^(relr_data_only|aps2_rela_data_only|original_image_load)$'
uv run python -m unittest discover -s tests -p test_relr.py
```

The CMake library `recomp_relr` is separate from runtime and lifted code. Its
Python test independently compiles only decoder and synthetic harness as strict
C++11, without original inputs or generated code. Existing project-wide CMake
configuration still requires previously generated lifted sources; no lifting
or guest execution was needed here.

The synthetic harness passes **953 checks**, also under UndefinedBehaviorSanitizer.
Literal streams and independent expected targets cover empty/anchor-only input,
bit 1/63, sparse/dense/empty and consecutive bitmaps, new/backward anchors,
encoding identity, word/bit/byte provenance, explicit little-endian and unaligned
host input, address/cursor boundaries, malformed lengths, bitmap before anchor,
alignment, duplicate/overlap, and every arithmetic overflow category including
empty-bitmap advancement. Record/storage boundaries include exact-budget success,
one-byte storage failure, 16-byte dense expansion and an input expanding beyond
the million-record default. Test-only allocation injection exhausts allocations
on success and late duplicate-error paths with prior and absent output. Production
has no allocation hook. Existing APS2 tests still pass their 636 checks.

The build and three selected data-only CTests passed. Python data-only suites
passed: RELR (1 method), APS2 (1), image (25), linker audit (14), RELRO (10),
dependency manifest (11), resolution plan (16): **78 methods**. No instruction
semantics suite, guest function, initializer, constructor, JNI_OnLoad, game or
IFUNC resolver was run.

All eleven device files matched unchanged acquisition pins; old native load-only
validation still accepts libc and rejects the ten others with the same packed
section diagnostic. A separate ignored pure-decoder probe matched all **3,684
RELR targets across nine streams** to the historical diagnostic arrays. This is
diagnostic comparison only, not a loader/audit acceptance path. Local source
snapshots, probe and report remain ignored (`generated/relr-source-review/`,
`generated/relr-device-recheck.json`). No device operation was performed.

The fresh original three-file dependency audit is structurally identical to the
historical report (`generated/relr-baseline-recheck.json`). GTASA retains **5,252
RELATIVE applied; 21,458 unresolved (21,072 preemptible, 386 undefined); 274
unresolved imports; RELRO sealed; readiness false**. Existing pins, acquisition
manifests and reports were preserved. No commit or push was made.

Next propose and separately review inventory-only integration of APS2 + RELR,
including structural binding, per-object budgets and explicit application guards.
Format acceptance, target reads, RELR application, original-dependency resolution,
scope/version policy and platform startup remain future work.
