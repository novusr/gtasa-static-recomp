# Guest linker requirements audit

Checked 2026-11-06 against foundation `eff6534`. This is analysis of the
hash-verified Android AArch64 ELF, not authorization to start the game. No guest
function, constructor, initializer, JNI_OnLoad or IFUNC resolver is called.
No dependency resolver, import implementation or success stub is added.

## Reproduce and interpret

After the documented dependency sync, inspect/lift and C++11 build:

```bash
python3 tools/audit_linker.py --load-bias 0x100000000 --guest-page-size 0x1000 \
  --output generated/linker-audit.json
```

`--config` and `--runner` support synthetic fixtures and a freshly built native
probe. The configuration's input path remains relative to the project root.
The audit captures at most 512 MiB, verifies the configured SHA-256, and passes
those same captured bytes through the existing native ELF validator. It does
not trust an earlier report or re-open the original path for metadata parsing.

Preparation uses a separate temporary data image: explicit supported RELA
application followed by explicit RELRO sealing. The existing probe independently
checks file/BSS bytes, applied values, unchanged neighboring bytes, permission
boundaries and sealing. Its additive `symbols` field exposes the complete native
symbol inventory; existing fields and loader APIs retain their meaning.
The Python audit then transforms captured bytes and a copied JSON inventory.
It has no live image handle; audit composition cannot change image bytes,
permissions, relocation completion or sealing state. Preparation and read-only
audit are labeled separately in the report. `ready_to_execute` stays false.

Schema version 1 contains the verified hash, bias, explicit guest page profile,
sealing status and raw/effective RELRO ranges. It separates `applied_relocations`,
`unresolved_relocations`, and `imports`; unresolved groups use reason, numeric
relocation type and `(table_section, index)`. Each relocation additionally has
its source section/index and REL/RELA format. A symbol's table/index is its
identity, including across `.dynsym` and `.symtab`; names never merge records.
`preemptible_definitions` describes default-visible GLOBAL/WEAK definitions and
their relocation references, separately from native conservative reason codes.
This classification does not select a winning definition or apply DT_SYMBOLIC.

All dynamic entries before and including DT_NULL are retained with numeric tags,
raw values and known names; string attributes and known FLAGS/FLAGS_1 bits are
reported without discarding unknown bits. Version sections preserve record and
symbol-table identities, raw indices, hidden bits, names, dependency names,
hashes and flags. Version indices 0 and 1 are preserved as special indices;
absence is reported separately. Version names alone are not provider evidence.
The audit validates bounds, links, entry/count sizes, forward chain termination,
overlap, strings, version-index references and dynamic version pointer/count
agreement. This bounded section-based decoder rejects ambiguous duplicate version
indices in a linked string-table scope; it is not a general platform version
resolver or proof that a dependency can satisfy a requirement.

TLS symbols/sections/PT_TLS, IFUNC symbols, extra st_other attributes, all program
headers and relocation formats/types are retained. Unknown tags/attributes are
facts requiring review, not claims of implemented support. Native rejection of
sectionless/extended numbering, packed Android relocations and RELR still applies.
This audit does not bypass a rejection to publish a partial successful report.

Provider and implementation fields remain `unknown`. Facts, `assumptions` (empty)
and explicit unknowns are separate. Output replacement is atomic only after all
validation succeeds; a failure leaves an existing report unchanged, so an old
report can still exist. Reports and captured ELF bytes remain outside Git.

## Findings from the configured input

SHA-256: `12527bfdb63889c02d24366629e808cb446d354a2b380348bd661da4edc6af11`.
At bias `0x100000000`, guest pages `0x1000`, RELRO sealing completes independently
of unresolved work. All 26,710 relocations are RELA. Baseline reconciles exactly:

| State/reason | ABS64 | GLOB_DAT | JUMP_SLOT | RELATIVE | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| Applied | 0 | 0 | 0 | 5,252 | 5,252 |
| Unresolved preemptible_symbol | 10,866 | 4,136 | 6,070 | 0 | 21,072 |
| Unresolved undefined_symbol | 98 | 23 | 265 | 0 | 386 |

All 274 named undefined dynamic imports remain unresolved: 265 FUNC and 9 OBJECT,
all GLOBAL, default visibility; no weak imports in this particular input.
Synthetic tests cover weak imports separately. The native inventory contains
21,923 symbols in table section 2 and 37,912 in table section 31. Across those
tables, 43,292 entries describe default-visible GLOBAL/WEAK definitions;
14,547 identities have relocation references. These are table-entry counts,
including repeated names/definitions across tables, not distinct exported APIs.

DT_SONAME is `libGTASA.so`. DT_BIND_NOW and DF_1_NOW are present. DT_HASH is
present; DT_GNU_HASH, DT_SYMBOLIC/DF_SYMBOLIC, DT_RPATH and DT_RUNPATH are absent.
DT_RELA/RELASZ/RELAENT, DT_JMPREL/PLTRELSZ/PLTREL and DT_RELACOUNT describe the
inventoried tables; DT_RELACOUNT is 5,252. DT_INIT_ARRAY/SZ describes 1,192 bytes
and DT_FINI_ARRAY/SZ 24 bytes. Their addresses are metadata only; nothing in
these arrays is called.

SHT_GNU_versym and SHT_GNU_verneed are present, with two requirement records:
`libc.so` / `LIBC` at version index 3 (131 imports), and `libm.so` / `LIBC` at
index 2 (25 imports). The other 118 imports carry raw version index 0.
No version-definition section is present. These records express requirements;
they do not prove actual provider files, exports or implementations.
No STT_TLS, SHF_TLS, PT_TLS, STT_GNU_IFUNC or extra st_other bits were found.
No TLS/IRELATIVE relocation was found. This absence in this file says nothing
about its uninspected dependencies or future runtime requirements.

DT_NEEDED order is preserved, not alphabetically reordered:

| Dependency | Evidence still required |
| --- | --- |
| libSCAnd.so | Exact ARM64 Android file/hash, exports, versions, transitive dependencies and required behavior |
| libandroid.so | Same input evidence plus applicable Android API contracts |
| libc.so | Exact Bionic build and LIBC version exports, ABI/thread/runtime contracts |
| libm.so | Exact Android build and LIBC version exports, FP contracts |
| liblog.so | Exact Android build, exports and logging contracts |
| libEGL.so | Exact Android build, exports and graphics contracts |
| libGLESv2.so | Exact Android build, exports and graphics contracts |
| libOpenSLES.so | Exact Android build, exports and audio contracts |
| libOpenAL64.so | Exact packaged file/hash, exports and audio contracts |
| libstdc++.so | Exact Android file/hash and C++ ABI/runtime responsibility |
| libdl.so | Exact Bionic build, exports and guest dynamic-loading policy |

These library names are dependency facts, not inferred import behavior. No
provider file in this table was audited. The APK manifest/target SDK, device API,
linker namespaces, main executable, preload/global scope, load order and full
transitive closure are unavailable to this audit. Host Linux libraries cannot
supply evidence about Android exports or guest addresses.

## Official rules and platform boundaries

Sources below were inspected on **2026-11-06**; moving AOSP main is evidence of
current implementation, not proof of the game's historical device configuration.

- The [generic ELF symbol table ABI](https://gabi.xinuos.com/elf/05-symtab.html)
  defines LOCAL/GLOBAL/WEAK, undefined symbols and visibility. Default-visible
  GLOBAL/WEAK shared-object definitions can be preempted. PROTECTED binds internal
  references locally while remaining externally visible; HIDDEN/INTERNAL are
  non-preemptible internally. LOCAL+PROTECTED is invalid. An undefined weak
  reference may resolve to zero when no definition is found; it does not justify
  a success stub. The current loader deliberately leaves all undefined entries
  unresolved, including weak, and supports only its documented internal subset.
- The [generic dynamic-linking ABI](https://gabi.xinuos.com/elf/08-dynamic.html)
  specifies ordered DT_NEEDED entries, lookup scope and DT_SYMBOLIC/DF_SYMBOLIC
  effects. A same-name definition within the image does not by itself settle
  lookup. This loader inventories dependencies/tags but builds no lookup scope
  and does not use symbolic flags to expand its internal fixup policy.
- [Arm AAELF64 2026Q3](https://github.com/ARM-software/abi-aa/blob/2026Q3/aaelf64/aaelf64.rst)
  defines symbol attributes and AArch64 relocation expressions, TLS and dynamic
  relocation forms. JUMP_SLOT addend treatment is delegated to the platform.
  The loader retains its zero-addend JUMP_SLOT restriction. TLS/IFUNC requirements
  are inventoried only; neither TLS allocation nor resolver execution is supplied.
- [Android linker changes](https://android.googlesource.com/platform/bionic/+/refs/heads/main/android-changes-for-ndk-developers.md)
  document breadth-first lookup from API 22, global-group then local transitive
  dependency-group lookup from API 23, versioning and SONAME/path handling from
  API 23, and API-sensitive compatibility. These are Android policies, not
  universal ELF rules. Names in DT_NEEDED do not establish a device search path.
- AOSP [linker_soinfo.cpp](https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/linker_soinfo.cpp)
  (blob `b3b9da3a89eb86a2333ef8c2c2e8710fa5e51199`) implements ordered lookup,
  DT_SYMBOLIC precedence and version matching including the hidden bit, special
  indices and unversioned-provider behavior. Numeric version indices are local
  to an object's metadata; they cannot be compared blindly across files.
  Recording verneed/versym here does not implement this matching policy.
- AOSP [linker_relocate.cpp](https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/linker_relocate.cpp)
  (blob `94281cb4f016a503d60d1d8b9ed95dd53183e1e9`) distinguishes missing strong
  and weak references and adds the explicit RELA addend for JUMP_SLOT. It also
  has separate TLS and IRELATIVE/IFUNC paths. This supports a future explicit
  Bionic profile; it does not relax this loader's zero-addend policy or authorize
  any resolver/initializer execution in this task.

## Next implementation sequence

1. Capture hash-verified dependency files and process/API/namespace evidence.
   Audit each recursively without loading host libraries or running guest code.
2. Add an explicit object graph and lookup-scope policy, then symbol-version
   matching and diagnostic resolution plans. Preserve object/table/index identity,
   visibility, weak versus strong behavior and preemption provenance.
3. Apply validated plans transactionally using guest addresses and existing RELA
   checks, with explicit platform JUMP_SLOT policy and RELRO ordering. Add required
   TLS/format support separately; unsupported startup requirements must reject.
4. Implement platform bridges with specified ABI, guest memory, errors, ownership,
   callbacks and threading. Resolving an ELF address does not implement Android,
   Social Club, graphics or audio behavior. A guest function address also needs
   compiled-entry dispatch before calls are possible. Only later consider
   controlled initialization after every prerequisite has a tested contract.

The next small milestone is a **read-only two-object resolution-plan prototype**
for synthetic, unversioned ordinary GLOBAL/FUNC or OBJECT symbols in an explicitly
ordered scope. Acceptance: two hash-verified synthetic AArch64 ET_DYN inputs;
correct external/preempted selection under that declared scope; distinct object,
table and index provenance; hidden/protected internal-reference behavior;
missing strong and weak references reported distinctly; unsupported versions,
TLS, IFUNC and ambiguous policy rejected. It must write no fixup, call no guest
code, preserve bytes/permissions/sealing, and keep readiness false. That milestone
is resolver planning only; platform implementations remain unknown.

## Validation

Synthetic audit tests cover strong/weak imports, default-visible versus internal
binding, same names in independent tables, absent/present definition/requirement
version metadata, malformed bounds/counts/chains/links/strings/indices and dynamic
pointers/counts, TLS/IFUNC/IRELATIVE inventory, read-only deterministic composition,
failed publication, and hash/native/metadata failures preserving old or absent
reports. The existing native loader, RELRO and semantic regressions remain gates.
Generated reports, original ELF and assets remain ignored and are not source inputs.

The completed 2026-11-06 run passed `uv sync --locked`, input inspect/lift,
CMake/Ninja C++11 build, all four CTest cases and all 87 Python tests (14 audit
methods, each with additional synthetic cases where applicable). Existing original
leaf/integer/memory/control-flow differential commands also passed: respectively
2,048 calls / 6,144 FP result words, 760 calls, 1,216 calls and 760 calls.
These bounded semantic harnesses do not run guest startup. Both explicit 4 KiB
and 16 KiB audit profiles at bias `0x100000000` reconciled the same relocation
and import counts, with their distinct sealed RELRO ranges and readiness false.
Ignored reports are `generated/linker-audit.json` and
`generated/linker-audit-16k.json`; they contain original-input metadata and are
not committed. Passing these tests establishes the reported bounded tooling
behavior, not dependency availability, a complete Android linker or game startup.

## Completed bounded resolution-plan milestone

The next-small-milestone paragraph above is now implemented by
`tools/plan_resolution.py`; [RESOLUTION_PLAN.md](RESOLUTION_PLAN.md) specifies the
exact two-instance contract, supported symbols, trace/status schema, explicit
scope assumptions and conservative exclusions. It reuses validated audit snapshots,
including additive section-header facts, and never applies its symbol selections.
The synthetic plan is `generated/resolution-plan.json`; original dependencies
remain unaudited and unresolved. Scope/version policy and transactional application
remain separate future milestones, with platform implementations still unknown.

The 2026-11-06 planner validation reran the original audit with explicit 4 KiB
guest pages and bias `0x100000000`. The baseline remains 5,252 RELATIVE applied,
21,458 unresolved (21,072 preemptible, 386 undefined), and all 274 imports
unresolved, with sealed RELRO and readiness false. Build, all four CTest cases,
all 103 Python tests and the four existing bounded differential commands passed.
See the planner document for the new synthetic tests and limits; none of these
results establishes original dependency availability or Android startup readiness.

## Completed dependency evidence manifest milestone

The 2026-11-06 [dependency evidence manifest](DEPENDENCY_EVIDENCE.md) extends the
read-only evidence layer with explicit file instances and per-DT_NEEDED edge
attribution, retaining all native audit inventories. The original-input run has
one verified file and 11 missing dependencies, with Android process evidence
unknown. It preserves exactly 5,252 RELATIVE applied, 21,458 unresolved (21,072
preemptible and 386 undefined), 274 unresolved imports, sealed RELRO and readiness
false. No additional fixup or provider selection occurs. All four CTest cases,
114 Python tests and four bounded semantic regressions passed. The next milestone
is obtaining exact missing files and process/device evidence before extending
scope/version policy; no dependency is claimed resolved.
