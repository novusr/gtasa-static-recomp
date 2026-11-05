# Device relocation diagnosis and proposed inventory support

Checked **2026-11-06**, foundation `70a8153`, only in the `static-recomp`
worktree. This is a read-only format diagnosis and an implementation proposal,
not implemented format support. The pre-existing uncommitted acquisition notes
in DEPENDENCY_EVIDENCE.md and EVIDENCE_REQUEST.md are preserved. No validator,
loader, runtime, fixup or symbol policy changed. This task ran no commit or push.
During the task HEAD advanced externally to `f41acf7`, committing exactly those
pre-existing acquisition notes. Their content is preserved; no reset or branch
change was performed. The new diagnosis/proposal remains uncommitted.

## Input identity and method

All 11 files in `inputs/device-sm-a155f-api36/lib/arm64-v8a/` match both the
byte sizes and unchanged SHA-256 pins in
`generated/device-sm-a155f-api36/acquisition.json`. Headers confirm ELF64,
little-endian, AArch64 ET_DYN. These are local acquisition pins, not independent
authenticity evidence. The acquisition's reported SM-A155F / Android 16 / API 36
identity does not identify the original game's platform or lookup scope.

The acquisition ledger and validation ledger were read without modification.
The original APK manifest also matches its acquisition-record digest, and all
three original APK libraries match that manifest's unchanged pins. A fresh
three-file dependency audit is structurally identical to the historical report.
GTASA retains **5,252 RELATIVE applied; 21,458 unresolved (21,072 preemptible,
386 undefined); 274 unresolved imports; RELRO sealed; readiness false**.
That audit uses only existing data-image preparation; it adds no fixup support.

Diagnosis reads captured ELF bytes, section headers, PT_LOAD provenance and
SHT_DYNAMIC entries. Every relocation table's file range agrees with its
file-backed PT_LOAD virtual-address translation. A separate local diagnostic
script expands APS2 tuples and RELR target addresses without reading target
addends or modifying mappings. It checks exact APS2 byte consumption/counts and
finds no duplicate target starts across the tables in each file. This is not a
successful native audit or proof of general decoder correctness.

Local ignored evidence is under
`generated/device-sm-a155f-api36/relocation-diagnosis/`: `diagnose.py`,
`diagnosis.json`, fetched official source snapshots, `aosp-revision.json` and
`apk-baseline-recheck.json`. Reproduce the byte diagnosis with:

```bash
python3 generated/device-sm-a155f-api36/relocation-diagnosis/diagnose.py
```

It rechecks pins before analysis, reproduces native load-only results without
`--all`/`--relocate`, and writes only its separate diagnostic report. It does
not refresh expected hashes, replace acquisition/validation records or publish
successful audit reports for rejected files. No ADB or device operation occurs.

## Formats actually present

Every rejected file has `.rela.dyn` of type **SHT_ANDROID_RELA = 0x60000002**,
entry size 1, starting with `41 50 53 32` (`APS2`). The name `.rela.dyn` does
not make this ordinary SHT_RELA. Nine also have `.relr.dyn` of type
**SHT_ANDROID_RELR = 0x6fffff00**, entry size 8. This is the Android-numbered
RELR address/bitmap encoding, not APS2 and not an ELF64_Rela array.

In this capture all table virtual addresses equal their file offsets; that is
an observed layout, not a proposed mapping shortcut. Counts below come from
local diagnostic expansion, not accepted native inventories.

| File | APS2 section / file offset / bytes / decoded tuples | RELR section / file offset / bytes / encoded words / decoded targets | Ordinary `.rela.plt` tuples |
| --- | --- | --- | ---: |
| libandroid.so | 10 / `0x108f0` / `0x8b1` / 720 | 11 / `0x111a8` / `0xf0` / 30 / 555 | 413 |
| libm.so | 10 / `0x3088` / `0x12` / 1 | 11 / `0x30a0` / `0x18` / 3 / 27 | 5 |
| liblog.so | 10 / `0x21e0` / `0x24` / 3 | 11 / `0x2208` / `0x18` / 3 / 7 | 98 |
| libEGL.so | 9 / `0x4788` / `0x9c` / 18 | 10 / `0x4828` / `0x1b0` / 54 / 3,055 | 145 |
| libGLESv2.so | 9 / `0xb8c0` / `0x6` / 0 | 10 / `0xb8c8` / `0x10` / 2 / 3 | 2 |
| libOpenSLES.so | 10 / `0x1118` / `0x1b3` / 53 | 11 / `0x12d0` / `0x10` / 2 / 3 | 5 |
| libstdc++.so | 10 / `0x868` / `0x6` / 0 | 11 / `0x870` / `0x10` / 2 / 3 | 19 |
| libdl.so | 8 / `0x908` / `0x6` / 0 | absent | 12 |
| libz.so | 9 / `0x1698` / `0x12` / 1 | 10 / `0x16b0` / `0x10` / 2 / 28 | 44 |
| libGLESv1_CM.so | 10 / `0x39a8` / `0x6` / 0 | 11 / `0x39b0` / `0x10` / 2 / 3 | 9 |

The four zero-count APS2 streams are exactly `41 50 53 32 00 00`: signature,
count zero, initial offset zero. They have no DT_ANDROID_RELA/RELASZ pair.
libdl has neither APS2 dynamic tags nor RELR; its empty section alone triggers
rejection. The other three empty-section files still have RELR dynamic tags.

The six nonempty APS2 tables have DT_ANDROID_RELA (`0x60000011`) and
DT_ANDROID_RELASZ (`0x60000012`) matching the table addresses/sizes above, plus
DT_RELAENT = 24. That last value describes decoded RELA records, not the packed
byte stride. Their decoded types are ABS64 (257) and/or GLOB_DAT (1025):
libandroid 692/28; libm 0/1; liblog 2/1; libEGL 4/14; libOpenSLES 53/0; libz 0/1.
No APS2 RELATIVE tuple was observed; relative targets occur in RELR here.

All nine RELR tables have matching DT_ANDROID_RELR (`0x6fffe000`),
DT_ANDROID_RELRSZ (`0x6fffe001`), DT_ANDROID_RELRENT (`0x6fffe003`) = 8.
For precise dynamic provenance, their section and pointer/size/entry indices
are respectively: libandroid `21:38/39/40`; libm `20:7/8/9`;
liblog `20:10/11/12`; libEGL `20:29/30/31`; libGLESv2 `18:10/11/12`;
libOpenSLES `19:13/14/15`; libstdc++ `20:4/5/6`; libz `19:9/10/11`;
libGLESv1_CM `19:10/11/12`. For each nonempty APS2 table its pointer and size
entries precede that RELR pointer by three and two indices respectively.
Raw entries remain in the ignored diagnosis report.

No SHT_ANDROID_REL, DT_ANDROID_REL/RELSZ, standard SHT_RELR (19), standard
DT_RELRSZ/RELR/RELRENT (35/36/37), or DT_ANDROID_RELRCOUNT was observed in any
of the 11 inputs. The accepted libc uses ordinary SHT_RELA only: 1,716 dynamic
and 494 PLT tuples. Its existing audit result remains distinct from these ten
rejections; successful libc parsing does not validate the other files.

## Exact current rejection and support boundary

`src/elf_image.cpp` inventories ordinary SHT_REL/SHT_RELA, but explicitly rejects
SHT_ANDROID_REL, SHT_ANDROID_RELA and standard SHT_RELR at the section gate.
All ten native load-only invocations reproduce
`unsupported packed ELF relocation section` at their first APS2 section.
Those sections precede SHT_DYNAMIC, so dynamic rejection is not the first cause.
The guard runs even for a zero-count stream.

The dynamic gate separately rejects Android packed REL/RELA tags, Android RELR
tags and standard RELR tags with `unsupported packed ELF relocation inventory`.
SHT_ANDROID_RELR itself is absent from the explicit section-type rejection list;
these captured nonempty RELR tables would nevertheless encounter the dynamic
gate if APS2 were accepted. This is a diagnostic distinction, not permission to
remove either guard. An unreferenced Android RELR section is a future synthetic
coverage requirement. Merely deleting the APS2 guard would lose inventory and
could expose this gap; merely decoding APS2 would still leave RELR unsupported.

Current data application remains limited to explicit RELA RELATIVE and bounded
internal non-preemptible RELA ABS64/GLOB_DAT/JUMP_SLOT under the existing policy.
REL implicit addends, RELR and packed data have no application support. IFUNC,
TLS, dependency binding, versions and platform implementations remain unresolved.
No accepted native audit report has been published for the ten files.

## Official evidence and revisions

Inspected **2026-11-06**. AOSP references below use tag `android-16.0.0_r1`,
resolved Bionic commit **09a271af557444c9a6b3f3146d6d474156fd6cdb**.
This release is an implementation reference, not a claim that Samsung's captured
files were built from that commit or any particular compiler revision.

| Official source | Revision / inspected blob | Relevance |
| --- | --- | --- |
| [Bionic elf.h](https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/include/elf.h) | `24454d73307c00d72368391701713b6753a03104` | Packed Android and Android/standard RELR constants; same RELR encoding with different constants |
| [Bionic packed iterator](https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/linker/linker_reloc_iterators.h) | `c6a8cf620ab2f7d3ea1c7e921f12e06743265fa2` | APS2 group flags, delta state, grouped addends, REL versus RELA |
| [Bionic SLEB decoder](https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/linker/linker_sleb128.h) | `f48fda8c99d8d481785b72559c8542a136b9164d` | Signed base-128 byte decoding and bounded input; hardening below is a separate proposed contract |
| [Bionic linker.cpp](https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/linker/linker.cpp) | `4cf93b9badb616b892a2b063234abd72fb7c71e8` | Dynamic tag aliases, RELRENT check and RELR address/bitmap expansion |
| [Bionic linker_relocate.cpp](https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/linker/linker_relocate.cpp) | `94281cb4f016a503d60d1d8b9ed95dd53183e1e9` | APS2 signature check, decoder/application separation and RELR-before-packed order |
| [Android linker changes](https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/android-changes-for-ndk-developers.md) | `24304474d01b4f32af50537fad67848ca33c9018` | APS2 since API 23; Android RELR since 28; standard constants since 30; ordering bug before 35 |
| [LLVM LLD encoding description and writer](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.0/lld/ELF/SyntheticSections.cpp) | release tag `llvmorg-20.1.0`, AndroidPackedRelocationSection::updateAllocSize and DynamicSection::computeContents | Concrete APS2 field order, signed deltas, zero-count streams and dynamic tag emission |
| [Generic ABI relocation specification](https://gabi.xinuos.com/elf/06-reloc.html) | ELF Object File Format 4.3 DRAFT, sections 6.1 and 6.2; page has no immutable revision identifier | REL/RELA record distinction and standard RELR address/bitmap contract |

The AOSP browser endpoint failed in the web reader; source text and blob IDs
were retrieved directly from official Gitiles `?format=TEXT`/`?format=JSON`.
The LLD release source was retrieved from LLVM's official repository. These
sources describe format/implementation semantics; they establish no original
dependency association, platform scope, version match or execution readiness.

## Proposed stages and acceptance contracts

The original stages below describe the staged proposal. Stage 1 APS2 RELA is
now implemented separately as documented in [APS2_RELA.md](APS2_RELA.md);
RELR and all structural inventory/application integration remain future work.
Do not remove current rejection guards as part of this documentation milestone.

### 1. Bounded pure decoding, first APS2 RELA then RELR

Introduce pure C++11 decoder helpers over already captured, hash-verified bytes
and checked table descriptors. Return a temporary inventory or a precise error
with table and encoded byte/word location. The helpers receive no mutable Memory,
loader phase handle, resolver callback or executable address. Keep src/include
C++11, fixed-width values and explicit little-endian reads; assert any new runtime
structure layout. No guest address is a host pointer.

APS2 RELA contract:

- The future ELF integration must require SHT_ANDROID_RELA. The pure RELA-only
  byte decoder requires the exact APS2 signature and assumes its caller selected
  RELA semantics; APS2 itself cannot distinguish REL from RELA. Decode signed LEB128 after
  the four signature bytes: total count, initial offset, then groups. Validate
  nonnegative bounded count/initial address and positive group size no larger
  than the remaining count. Zero-count plus initial zero is valid.
- Flags 1/2/4/8 mean grouped info / grouped offset delta / grouped addend /
  has addend. Reject unknown bits and grouped-addend without has-addend.
  Consume optional group fields in offset-delta, info, addend order; consume
  per-entry fields in offset-delta, info, addend order where not grouped.
- Offset state accumulates signed deltas, including backwards deltas between
  groups. Require each resulting unsigned guest VA in range; do not implement
  negative deltas by overflowing signed C++. Preserve raw 64-bit r_info and
  split into uint32 symbol index/type. Validation of the section's exact linked
  symbol table and each index belongs to future structural integration; the pure
  decoder receives no symbol table. Names do not identify a symbol.
- Addend starts at zero. A group without has-addend resets it to zero. With
  ungrouped addends, accumulate a signed delta for each record. With grouped
  addend, add the group delta **once on group entry**, retaining that value for
  each record, matching the inspected Bionic iterator. Test nonzero grouped
  deltas explicitly; current LLD output alone does not exercise every flag.
- Preserve explicit RELA addend semantics even when has-addend is absent (the
  decoded addend is zero). Encoding omission is not an implicit target addend.
  Proposed initial profile rejects signed addend-accumulator overflow rather
  than adopting Bionic's size_t conversions; document this conservative limit.
- Bound SLEB to ten bytes for 64 bits. Validate terminal sign-extension bits
  before shifts, reject truncation, continuation past byte ten and out-of-range
  values; allow nonminimal encodings that still fit, since minimality is not a
  format requirement here. No shift by 64 or signed overflow. Require exact
  record count and no trailing bytes. This is a conservative profile: the official
  LLD writer can append zero padding **inside** sh_size when avoiding shrinkage
  during layout convergence (`relocData.append(oldSize - relocData.size(), 0)`).
  Bionic stops at the declared record count. This decoder deliberately rejects
  such padding, including zero bytes; future integration needs a reviewed policy.
  Padding outside the supplied byte range is not inspected.
- Android packed REL stays explicitly unsupported initially; an ARM64 RELA
  decoder must not guess its addend semantics from the APS2 signature alone.

RELR contract:

- Recognize Android and standard section/tag families by numeric type, retaining
  their original identities. Payloads are little-endian uint64 words, no APS2
  header or LEB. Size must be divisible by eight, entry size eight.
- An even word emits that target VA and sets cursor to VA+8. An odd word requires
  a previous address; bits 1..63 select cursor+8*(bit-1), then advance cursor by
  63*8, even for word 1 (empty bitmap). Support consecutive bitmaps and new
  address anchors. Check the full cursor advance as well as emitted addresses.
- Proposed initial ARM64 profile requires eight-byte aligned targets; generic
  RELR's even-address encoding alone is a weaker condition. Check biased target
  address and complete eight-byte mapped extent without requiring write permission
  just to inventory. Reject overflow, unmapped/gapped targets and duplicate or
  overlapping RELR slots in the strict profile. Preserve encoded word/bit provenance.
- Output relative target records with implicit addend kind, no symbol-table
  identity and no invented explicit addend. Reading target bytes, computing
  bias+old-value, stores, IFUNC and resolver ordering are application work.

### 2. Structural inventory integration without application

Add a separately named native **inventory-only** entry point and report profile;
reuse hash capture and structural ELF validation, but provide no application
phase. Keep existing load/audit defaults rejecting unsupported tables until an
explicit later integration gate is met. Metadata may consume only the fully
validated inventory snapshot, never an unchecked Python bypass of native failure.

Validate complete dynamic pointer/size/entry families against exactly one
section and its PT_LOAD file provenance. Check duplicate/conflicting tags,
missing partners, table overlap, wrong links, address/size disagreement and
integer overflow. Require APS2 byte stride 1 while accepting decoded DT_RELAENT
24; RELR stride and DT_RELRENT are 8. Reject mixed standard/Android aliases
for the same table in the initial profile instead of double counting. An orphan
RELR section must reject, including Android-numbered sections lacking tags.
DT_ANDROID_RELRCOUNT remains unsupported if encountered; do not ignore it.

Permit an unreferenced APS2 section only when it is the fully decoded canonical
zero-count/zero-initial-offset stream observed here. Retain its table record with
zero entries. An unreferenced nonempty APS2 section rejects. Do not require a
nonempty table or fabricate DT_ANDROID_RELA tags for the four empty streams.
Continue rejecting sectionless/extended numbering and unsupported layouts.

Retain each encoded table's section index/type, address, file range, entry size,
dynamic tag section/index associations, encoded size/count and decoded count.
For APS2 entries retain decoded ordinal, group/byte span, raw offset/info/addend,
checked biased target, exact symbol table/index and explicit-addend kind. For
RELR retain decoded ordinal, encoded word/bit and implicit-target-addend kind.
Distinguish `ANDROID_APS2_RELA`, `ANDROID_RELR`, `RELR`, REL and RELA even when
normalizing semantic relocation types. Encoded words/bytes and decoded entries
must never be added together as one relocation count.

All newly decoded entries remain unresolved with a format-specific
application-not-supported reason. Existing apply APIs must not accept them just
because normalized type/addend fields resemble ordinary RELA: preserve source
format and explicitly guard every selection path and combined application.
No new entries enter applied inventories. Do not expand the planner's allowed
dynamic-tag list, scope/version rules or original dependency selection.

### 3. Atomic publication, limits and later application boundary

Validate every table, linked symbol and metadata record before exposing a
successful inventory. Build local vectors and commit by swap only on complete
success. Decoders append to temporary storage, not caller-visible output.
On allocation/validation failure keep bytes, permissions, phase guards, prior
inventory and existing reports unchanged; leave no report if none existed.
The diagnostic report profile must never masquerade as a successful audit.

Retain the existing file-size limit. Add explicit caller-visible ceilings before
expansion: proposed defaults per captured object of 1,000,000 decoded records across all
tables and 256 MiB cumulative inventory storage, covering groups/provenance as
well as entries. Check count
multiplication, allocations and host size conversion against both ceilings;
never clamp, truncate or claim success after hitting a limit. RELR has at most
63 emitted targets per bitmap word; APS2 tiny grouped input can expand greatly,
so encoded length is not an adequate output-memory limit. These proposed values
need acceptance tests and documentation before implementation.

A future application milestone would need a separately reviewed implicit-addend
read/write transaction and cross-format overlap policy, current target permissions,
repeat-call behavior and RELRO ordering. Bionic's RELR-before-packed order is
source evidence, not authorization to run resolvers or implement that phase now.
No dependency resolution, provider host, stub, bridge, interpreter, JIT, additional
fixup, initialization or device change is proposed for these inventory stages.
Readiness remains false after successful decoding, including empty streams.

## Synthetic acceptance tests for the implementation task

| Area | Positive cases | Rejection / invariant cases |
| --- | --- | --- |
| APS2 signature and integers | Empty canonical stream; signed boundary deltas; valid nonminimal SLEB; 10-byte limits | Wrong/old magic, truncated header/field, 11-byte or unterminated SLEB, invalid terminal bits, negative counts, address under/overflow, signed addend overflow |
| APS2 groups | Every valid flag combination; grouped/ungrouped fields; multiple groups; backwards offsets; nonzero grouped-addend delta; reset-to-zero group; explicit zero addends | Zero/negative/excess group size; unknown/inconsistent flags; missing fields; record-count mismatch; trailing bytes; count/allocation bomb |
| APS2 symbol identity | Separate tables with same names/index; zero symbol index; full raw r_info including high bit | Invalid table/link/index; REL payload offered to RELA-only decoder; metadata disagreement |
| RELR expansion | Empty valid table; address-only; bit 1/63; sparse/dense/empty bitmaps; consecutive bitmaps; new anchors; same payload under each constant family | Bitmap first; partial word; wrong stride; unaligned address; cursor/target/bias overflow; unmapped/gap/cross-mapping slot; duplicates/overlaps; expansion ceiling |
| Structural binding | APS2 plus Android RELR plus ordinary PLT; standard RELR; fully linked tables; four unreferenced empty APS2 variants matching this capture | Missing pointer/size/entry partners; duplicate/mixed aliases; mismatched address/size; nonempty orphan APS2; orphan Android/standard RELR; unexpected RELRCOUNT; overlapping tables; unsupported numbering |
| Inventory and application boundary | Exact encoded/decoded counts and provenance; deterministic independent snapshots; all new rows unresolved | No promotion through existing RELATIVE/internal-symbol/combined APIs; no implicit-addend read; no byte/permission/phase/import/sealing change; readiness always false |
| Failure atomicity | Successful replacement only after full validation | Malformed last table after valid first; bad hash; native/metadata failure; injected allocation failure; prior report sentinel unchanged, absent output stays absent, temporary files cleaned |

Use small manually specified synthetic streams with independently listed expected
tuples/addresses, plus an independent reference expander and official-writer
fixtures where practical. No test needs guest execution, initializer or resolver.
Real device files are optional ignored integration evidence, never committed
fixtures or test dependencies. After implementation, recheck the same 11 pins,
compare inventories to this diagnosis, and rerun unchanged ordinary-ELF tests
and GTASA baseline. Passing the format stage alone must not label the ten files
fully linked, runnable, dependency-attributed or successfully audited under the
old application profile.

## Checks for this documentation milestone

Pinned `uv sync --locked` passed. Existing data-only regressions passed: 25 image,
14 linker-audit, 10 RELRO and 11 dependency-manifest tests (60 methods total).
No new production decoder or acceptance test was added; the matrix above is
future acceptance work. Native load-only checks reproduced one acceptance and
ten exact packed-section rejections. Pin and baseline checks passed as described
above. Ignore coverage and `git diff --check` passed.

No tracked C++ or Python source changed, so no lift, build, CTest leaf execution,
full Python instruction suite or differential guest-instruction harness was run.
No game, guest function, constructor, initializer, JNI_OnLoad or IFUNC resolver
was executed. The original worktree, its agents, the device and existing pins
were not modified.

## Contract review for the pure APS2 implementation, 2026-11-06

Implementation starts from HEAD `077466e` with a clean worktree. Official
Bionic iterator/SLEB sources at android-16.0.0_r1 and the LLVM 20.1.0 writer
linked above were retrieved again directly from their official repositories.
Grouped addend is confirmed as one addition on group entry, not per record.
The corrections above separate byte decoding from ELF/symbol binding and
identify LLD in-section padding as intentionally unsupported by the requested
exact-consumption profile. Nonnegative initial offset and nonwrapping offset/
addend arithmetic are conservative limits rather than Bionic modular behavior.
The prior diagnosis and its local script remain historical evidence, not the
production decoder. See APS2_RELA.md for the implemented API and checks.
