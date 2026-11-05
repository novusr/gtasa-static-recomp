# Native relocation inventory-only profile

Implemented on 2026-11-06 in `static-recomp`, starting from clean HEAD `ec7dd8d`.
Only this worktree was changed; no commit, push, device operation or guest code
execution occurred. This document describes the new profile. Historical decoder
and audit documents retain their original results and boundaries.

## API and application boundary

```cpp
ElfImage ElfImage::load_inventory_only(
    const std::string& path, const std::string& expected_sha256,
    uint64_t load_bias, const InventoryLimits& limits = InventoryLimits(),
    uint64_t memory_limit = 536870912);
```

The result has `inventory_only()==true`; `relocation_inventory()` contains the
validated tables. Shared `load_impl` captures and hashes a single file buffer,
validates ELF/program/section structures and raw RELRO headers, and maps original
PT_LOAD bytes/BSS through checked Memory only after all inventory and symbol
metadata validation. There is no relocation application or RELRO sealing phase.
Targets and implicit addends are never read. Mapping does copy original segment
bytes; this is structural data loading, not reading relocation target values.

The snapshot owns separate `InventoryTable`, `Aps2RelaRecord`, `RelrRecord` and
`InventoryOrdinaryRecord` storage. It does not create `ImageRelocation` entries.
`symbols()`, `unresolved_imports()`, `needed_libraries()` and both legacy
relocation vectors are empty in this profile: linked symbol records/names are
validated, but not duplicated into application/audit inventories. Empty legacy
vectors are not a completion signal. Consumers must check the profile and use
the separate relocation snapshot; readiness is always false.

All three apply APIs reject this image with `application-not-supported` before
phase/idempotency logic, even for empty input or ordinary RELA entries. RELRO
sealing also rejects before changing state. Copying an image preserves the
profile guard. Numeric type, explicit zero addend, or an eligible local symbol
cannot promote packed records into any existing application path. The inventory
accessor is const; there is no conversion/import API into fixup records.

`ElfImage::load`, existing load/audit CLIs, `audit_dependencies` and resolution
planning retain their existing behavior and packed rejection gates. They do not
select this profile. The old Android-numbered orphan RELR section-gate gap
identified in the proposal is not silently changed; the new profile independently
rejects every orphan RELR section. No dependency provider, version/scope policy,
resolution planner capability or relocation operation was added.

## Structural acceptance and contract corrections

The numeric section/tag families are bound against exactly one matching section
and exactly one file-backed PT_LOAD translation. Section/file ranges, address
ends, table overlaps in both coordinates, strides, links, indices, duplicate tags
(except ordered DT_NEEDED), termination and pointer/size partners are checked.
Main ordinary REL/RELA families require their matching ENT tag. Dynamic symbol
and string families are checked along with relocation `sh_link` and dynamic
section/string linkage. A referenced relocation table must link the exact
DT_SYMTAB SHT_DYNSYM, not another same-named table. PT_DYNAMIC file range, VA and
memory size must agree with its dynamic section. Multiple dynamic sections or
PT_DYNAMIC headers are outside this conservative profile.

Supported encodings remain distinct:

| Encoding | Section type | Encoded stride | Required dynamic family |
| --- | ---: | ---: | --- |
| ANDROID_APS2_RELA | 0x60000002 | 1 byte | DT_ANDROID_RELA/RELASZ, decoded DT_RELAENT=24 |
| ANDROID_RELR | 0x6fffff00 | 8 bytes | DT_ANDROID_RELR/RELRSZ/RELRENT=8 |
| RELR | 19 | 8 bytes | DT_RELR/RELRSZ/RELRENT=8 |
| RELA | 4 | 24 bytes | Main RELA/SZ/ENT, or JMPREL/PLTRELSZ/PLTREL=RELA |
| REL | 9 | 16 bytes | Main REL/SZ/ENT, or JMPREL/PLTRELSZ/PLTREL=REL |

Two clarifications correct an overly broad interpretation of the proposal:

1. A **PLT-only** family requires JMPREL, PLTRELSZ and PLTREL. It does not require
   a synthetic RELAENT/RELENT tag. Section type/stride are still mandatory and
   an ENT tag, if present, must match. Main REL[A] and referenced APS2 families
   still require their ENT tag. This follows the separate DT_RELA and DT_JMPREL
   definitions in the [Generic ABI dynamic section](https://gabi.xinuos.com/elf/08-dynamic.html).
   Four device inputs have PLT RELA without DT_RELAENT; accepting this layout is
   based on that contract, not on treating a missing required partner as valid.
2. An orphan canonical empty APS2 section can have **sh_link=0**: there is no
   symbol to reference. Decode the complete stream first and require the exact
   six bytes `41 50 53 32 00 00`, zero count, zero initial offset and no dynamic
   association. Preserve the empty table and raw link zero. A supplied nonzero
   link must still be a valid symbol table. Every referenced or nonempty APS2
   requires valid linkage; nonempty or noncanonical orphan streams reject.

The [Bionic ELF constants](https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/include/elf.h)
were freshly retrieved; their Git blob remains
`24454d73307c00d72368391701713b6753a03104`. The
[LLD 20.1 writer](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.0/lld/ELF/SyntheticSections.cpp)
and [ABI relocation definitions](https://gabi.xinuos.com/elf/06-reloc.html) were
reviewed alongside the proposal's pinned source/decoder evidence. Official source
snapshots stay ignored. None establishes the captured device's toolchain or the
game's actual process environment.

Android packed REL and its dynamic tags, DT_ANDROID_RELRCOUNT (0x6fffe005), mixed
Android/standard aliases for one table, orphan RELR (including empty), ambiguous
bindings and overlapping encoded relocation tables reject. Sectionless/extended
numbering, overlapping PT_LOAD and the existing unsupported raw RELRO layouts
remain rejected. Pure decoder restrictions still apply: APS2 exact consumption
rejects internal padding; RELR requires aligned unique slots within each stream
and checked cursor advancement. No alternative Python decoder exists here.

Every decoded target uses checked bias addition and a complete eight-byte extent
inside one mapping. Adjacent mappings cannot jointly satisfy an extent. RELR's
biased address must also remain eight-byte aligned. Inventory needs neither
PF_R nor PF_W on a target; no target Memory access occurs. Ordinary/APS2 target
alignment beyond this RELR rule is application policy. Duplicate/overlapping
targets **between tables or formats remain inventory data**. Only RELR's existing
within-stream duplicate policy applies. Cross-format composition, widths for
unsupported operations and application-time overlap/order rules are deferred.

## Provenance and identity

Native table identity is its section index within the returned object; reports
add a required caller-supplied instance ID, captured SHA-256, input path and bias.
Each table preserves numeric section type, VA, file offset/size, entry size,
original encoding, owning index in `segments()` and original PT_LOAD program-header index, encoded unit count and separate
decoded record count. The report includes segment VA/file ranges and flags so
the file translation can be inspected. Dynamic associations preserve section,
entry index, tag and raw value; shared RELAENT associations can appear on both
APS2 and ordinary PLT tables without duplicating decoded records.

APS2 retains every decoder ordinal, group ordinal, shared group header/end and
per-entry byte span, flags, raw offset/info/signed addend, initial offset and
group count. Symbol identity is `(table.symbol_table, record.symbol_index())`.
Ordinary entries retain offset/info/addend bits, ordinal and encoded byte offset;
REL has an implicit-target marker in the report and no reported explicit addend.
RELR retains encoding, target/ordinal, word index/byte offset, anchor/bitmap
source, bitmap bit and implicit-target-addend marker. It has no symbol identity,
r_info or explicit addend. Reports compute biased targets only from the already
validated offset and object bias; no normalized fake RELA record is constructed.

`encoded_count` means bytes for APS2, words for RELR, and fixed-size entries for
ordinary REL/RELA. It is never summed with `decoded_count`. Raw `symbol_table=0`
on an empty orphan APS2 is the ELF null link, not an invented symbol table.

## Aggregate accounting and atomicity

Defaults are **1,000,000 decoded records and 256 MiB per object**. They count all
ordinary, APS2 and RELR tables together. Each decoder receives only remaining
records and storage; limits never reset per table. No prefix is returned.

The reported storage reservation is deliberately conservative and reproducible:

- `sizeof(RelocationInventory)` and exact table count times `sizeof(InventoryTable)`;
  table descriptors include all six fixed association slots and vector/result objects.
- Section descriptors for all section headers; two program-header-count segment
  reservations (PT_LOAD/RELRO); the program-header-count PT_DYNAMIC range reservation;
  their vector objects; two ImageSymbol scratch objects; twice the largest string
  section size plus 512 bytes for transient symbol/name/reason validation.
- Per APS2 call: `sizeof(Aps2RelaResult) + count*sizeof(Aps2RelaRecord)`.
- Per RELR call: `sizeof(RelrResult) + sizeof(vector<uint64_t>) +
  count*(sizeof(RelrRecord)+sizeof(uint64_t))`, including the complete temporary
  duplicate-validation array and vector object.
- Per ordinary table: `count*sizeof(InventoryOrdinaryRecord)` (its vector object
  is already in the table descriptor).

Decoder scratch charges are retained in the cumulative reservation after scratch
is freed; result-object overhead is intentionally counted again for decoder
work. Consequently this sum bounds validation scratch conservatively rather
than reporting only the final resident vector bytes or measured process RSS.
Header reservations are checked before their allocations; string scratch before
shared metadata validation; table/record sizes and container maxima before resize.
Subtraction/division precedes expansion multiplication and host conversions.
Source/header limits also bound the remaining fixed-size products. Exact-limit
success and one-byte/count failures are tested.

Excluded are the captured input byte buffer (separate fixed 512 MiB cap), guest
segment bytes/Memory mapping storage (separate caller-visible 512 MiB default),
allocator/library bookkeeping, OpenSSL/iostream/file machinery, hash/path strings,
ordinary stack/scalar frames, exception diagnostics, previous caller-owned results,
and native/JSON report serialization. There is no aggregate process-RSS limit.
Report serialization happens after native inventory acceptance and can still fail;
the Python publisher preserves its old report in that case. Symbol records/names
are validated transiently and not retained as an additional symbol inventory.

All work uses a local image and temporary decoder results. A snapshot is returned
only after every table and linked symbol metadata record validates and all original
mappings allocate. On any exception no successful object is returned; caller-held
objects are untouched. Native table publication uses nonthrowing swaps/scalars.
Hash failures, a malformed last table, exhausted aggregate limits and injected
allocation failures preserve previous contents, capacity, pointers, bytes,
permissions, empty phase/application vectors and RELRO state. An absent result
remains absent. The API never accepts an existing mutable image to decode into.

## CLI and verification

```bash
uv sync --locked
cmake -S . -B build -G Ninja
cmake --build build
python3 tools/inventory_image.py --input /explicit/input.so --sha256 EXPECTED_PIN \
  --instance-id explicit-instance --load-bias 0x100000000 \
  --output generated/explicit-instance-inventory-only.json
ctest --test-dir build --output-on-failure \
  -R '^(relocation_inventory_data_only|relr_data_only|aps2_rela_data_only|original_image_load)$'
PYTHONPATH=tests uv run python -m unittest test_relocation_inventory test_image \
  test_linker_audit test_relro test_dependency_manifest test_resolution_plan \
  test_aps2_rela test_relr
```

The C++ CLI accepts `ELF SHA256 BIAS [MAX_RECORDS MAX_STORAGE]`; the Python wrapper
also exposes both limits. Python only invokes native validation, parses its
complete JSON and adds the caller envelope. The native serializer enables stream
exceptions and builds its whole payload before stdout publication. The Python
publisher serializes fully, writes/fsyncs a temporary in the destination directory
and replaces the destination atomically. Native failure or JSON/serialization
failure occurs before replacement; temporary files are removed on failure. Profile
`native-relocation-inventory-only-v1` has `application_status=application-not-supported`,
`relro_sealed=false` and `ready_to_execute=false`. This is not an application audit.

The new synthetic suite has **14 methods** plus allocation-injection C++ checks;
expected tuples/addresses/spans are literal independent expectations. It covers
both RELR number families, ordinary REL/RELA main and PLT tables, mixed formats,
empty RELR, canonical orphan APS2, optional PLT stride tags, mismatched links,
provenance, sizes/types/strides, missing/duplicate/mixed tags, table overlap,
RELRCOUNT, unsupported numbering/PT_DYNAMIC, target/bias overflow, unmapped/gapped
and cross-mapping extents, cumulative exact limits, deferred cross-format target
composition, late malformed tables, bad hash and report atomicity with prior/absent
outputs. A test-only global allocator fails each allocation on successful and
late-error paths; packed RELATIVE, ABS64, GLOB_DAT and JUMP_SLOT cases exercise
all apply guards, byte/status preservation and no target access on inaccessible
mappings. A separate test-only wrapper also injects failures through the actual native CLI
serializer and verifies prior/absent report preservation. No production allocation
hook exists. No original binary is needed by
these tests.

Pinned sync and C++11 build passed. The four selected data-only CTests and the
**92 data-only Python methods** (14 new, 78 existing) passed. APS2/RELR pure
regressions remain unchanged. The native allocation/guard harness also passed
UndefinedBehaviorSanitizer. No instruction-executing suite was run.

All 11 device inputs were rehashed against unchanged acquisition pins. The new
profile accepted each, retaining **796 APS2 records in ten tables (four empty),
3,684 RELR targets in nine tables**, and ordinary relocation tables:

| File | APS2 records | RELR targets | Ordinary RELA records | Old loader/audit | New inventory |
| --- | ---: | ---: | ---: | --- | --- |
| libandroid.so | 720 | 555 | 413 | rejected | accepted |
| libc.so | absent | absent | 2,210 | accepted | accepted |
| libm.so | 1 | 27 | 5 | rejected | accepted |
| liblog.so | 3 | 7 | 98 | rejected | accepted |
| libEGL.so | 18 | 3,055 | 145 | rejected | accepted |
| libGLESv2.so | 0 | 3 | 2 | rejected | accepted |
| libOpenSLES.so | 53 | 3 | 5 | rejected | accepted |
| libstdc++.so | 0 | 3 | 19 | rejected | accepted |
| libdl.so | 0 | absent | 12 | rejected | accepted |
| libz.so | 1 | 28 | 44 | rejected | accepted |
| libGLESv1_CM.so | 0 | 3 | 9 | rejected | accepted |

The ten old rejections remain `unsupported packed ELF relocation section` and
publish no successful application audit. Separate native inventories and old-profile
rechecks are ignored under `generated/inventory-only-device/`; historical reports,
acquisition records and expected hashes were preserved. Inventory acceptance is
not dependency attribution, symbol resolution or platform compatibility evidence.

The fresh original three-object audit is structurally identical to the historical
report (`generated/inventory-only-apk-baseline-recheck.json`). A separate original
GTASA data load verifies **5,252 RELATIVE applied; 21,458 unresolved (21,072
preemptible / 386 undefined); 274 unresolved imports; sealed RELRO; readiness false**
(`generated/inventory-only-gtasa-load-recheck.json`). No hash was refreshed.

Next work requires a separately reviewed application contract: implicit-addend
transactions, target composition/order, permissions and repeat behavior; fuller
metadata/platform policy and dependency evidence remain separate. APS2/RELR
application, Android packed REL, new providers, scope/version expansion, startup,
TLS, initializer/constructor/JNI/IFUNC execution, bridges and game execution are
not supported. No library is claimed fully linked and the game is not runnable.
