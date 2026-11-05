# Read-only dependency evidence manifest

Implemented and checked 2026-11-06. `tools/audit_dependencies.py` collects evidence
before extending Android scope/version policy. It performs no symbol lookup,
resolution planning or plan application. It never calls a constructor, initializer,
JNI_OnLoad, guest function or IFUNC resolver. No host Android provider, import
stub, bridge, interpreter, JIT, dlopen/dlsym or dependency search is introduced.

## Manifest contract (schema 1)

Every audited file must be explicitly supplied. A minimal manifest is:

```json
{
  "schema_version": 1,
  "guest_page_size": 4096,
  "objects": [
    {"instance_id": "A", "path": "generated/A.elf",
     "sha256": "<expected 64 lowercase hex digits; document reference or local pin origin>",
     "load_bias": 4294967296}
  ],
  "edges": [],
  "platform_evidence": {},
  "assumptions": []
}
```

The hash placeholder must be replaced before use. Record whether its source is
an independently trusted reference or an observed local content pin. The latter
detects changes after pinning, but does not authenticate an APK or file. Hash
validation proves agreement with the declared identity, not its provenance.
Paths are explicit, absolute
or relative to the project root. IDs are distinct nonempty instance identifiers,
independent of path, hash, filename and SONAME. The same file/hash may be supplied
as multiple instances; every instance is rehashed and audited independently.
Load bias is an explicit uint64 JSON integer; guest page size is an explicit
positive uint64 power of two. Booleans are not accepted as integers.

Objects form a nonempty list. Every listed file must exist and pass validation;
a nonexistent listed file is a configuration/input failure. To record an absent
dependency, omit its file object and leave its edge unspecified or explicitly
set its target to null. Do not invent a path, hash, bias or implementation for it.
There is no claim that this manifest lists all process objects.

`edges` is required (an empty list is valid). Each optional association uses:

```json
{"from_instance": "A", "table_section": 9, "index": 0,
 "to_instance": "B", "source": "device capture or explicit synthetic declaration"}
```

Both non-null endpoints must name supplied instances. `(from_instance,
table_section, index)` must identify exactly one actual DT_NEEDED record in that
instance's validated audit. These are the dynamic section index and entry index,
not the string offset or ordinal among dependencies. A record may have at most
one association. Unknown IDs, non-NEEDED records, duplicate edges or IDs, invalid
numbers, unknown fields and malformed evidence envelopes fail before publication.
Self edges and cycles are valid inventory data. An iterative graph algorithm
reports strongly connected cycle components without recursive traversal.

`source` is a required nonempty attribution for each explicit association.
`to_instance: null` explicitly records missing evidence with no fabricated target.
Each DT_NEEDED without an association also becomes a missing edge, marked
`not_supplied`. All original DT_NEEDED records retain their exact dynamic entry,
section/index, and per-instance ordinal, including duplicate names. Every supplied
object is audited, including objects not reached by any edge. Transitive needs
of supplied files are inventoried; the transitive needs of absent files stay
unknown. Matching SONAMEs and filenames are only file facts in the nested audits;
they never associate an edge or select a symbol provider. An explicit association
can name an instance with a different SONAME; this tool records the caller's
attribution and does not authenticate Android's selection of that instance.

`platform_evidence` is optional. It has slots `android_api`, `device_build`,
`target_sdk`, `namespace`, `main_executable`, `preload`, and `load_order`.
Each supplied slot must use one of these envelopes:

```json
{"status": "known", "value": 23, "sources": ["identified device capture, date and location"]}
{"status": "unknown", "value": null, "sources": []}
```

The example API value is synthetic, not evidence for the game. Known means
caller-supplied evidence: a non-null JSON value and nonempty source list are
required. Values can describe structured process observations, partial namespace
records or ordered captures, with their context in the sources. This prototype
validates the envelope, not the truth or Android semantics of those observations.
Empty known lists (for example observed no preload) differ from unknown.
Omitted slots normalize to unknown. These descriptive values are never interpreted
as file paths to open, instance references to traverse, or lookup instructions.
`assumptions` is an optional list of explicit nonempty statements, reported
separately from evidence and unknowns. Unknowns never require invented values to
produce an inventory. No lookup scope field is accepted.

## Validation, preparation and output

`prepare_manifest` is the untrusted-file entry point. Each file uses the existing
`audit_linker.audit`: capture at most 512 MiB, verify expected SHA-256 before use,
then pass the same captured bytes to native validation and metadata parsing.
Replacing the source path after capture cannot change the parsed metadata.
There is no cache keyed by path/hash and no trust in previously generated JSON.

Each isolated native image performs only the existing supported transactional
RELA preparation and explicit RELRO sealing, with the native probe's byte and
permission checks. There are no additional fixups. Native rejection gates,
including ELF type, layout, packed relocations and unsupported numbering, remain
unchanged. This is not a jointly mapped Android process: overlapping biases
between isolated inventories are retained as evidence, not accepted as a process
layout or used for symbol lookup. A separately validated process mapping would
be required before any later plan application.

`compose_manifest` is pure composition over trusted snapshots, not an alternate
validator for arbitrary JSON. It receives no live image handle. It deep-copies
snapshots, preserving all symbols and table/index identities, versions, dynamic
tags, raw special attributes, applied and unresolved relocations, byte evidence,
permission checks and RELRO state. Explicitly unsealed snapshots stay unsealed.

Schema 1 output has:

- `facts.objects`: instance ID, explicit path, verified hash/bias and complete
  prepared audit. A symbol's full identity is instance ID plus table/index.
- `facts.dependency_edges`: all needed records in original order, explicit target
  or null, attribution and missing/available status. Available means only that
  the explicitly associated file passed audit; symbol provider remains unknown.
- `facts.cycle_components`, normalized `facts.platform_evidence`, and per-instance
  `facts.requirements`: counts, full version records and special requirements (TLS
  symbols/sections/segments, IFUNC and extra attributes), plus unresolved types.
- `missing_dependencies`, separate caller `assumptions`, `unknowns`, and tooling
  `limitations`. Dependency closure, symbol providers, implementation and bridge
  remain unknown even if every observed edge has an available file.
- `plan_applied=false`, `ready_to_execute=false`. Every nested import retains
  `unresolved`; no import is claimed resolved.

`versioned_symbol_entries` counts every symbol with a versym association,
including raw indices 0 and 1; it is not a count of nontrivial version requirements.
The original indices and records remain available for interpretation.

Missing dependencies and cycles are valid audit results (exit zero). Hash mismatch,
invalid ELF, malformed metadata, nonexistent supplied files and invalid manifest
configuration fail nonzero. The atomic publisher runs only after all inputs and
edges validate; failures neither create a report nor replace a prior report.
A prior report can therefore remain after a failed command.

## Reproduce the original-input audit

After sync, inspect/lift and native build, create a local manifest from the
already configured trusted input identity, with no dependency files supplied:

```bash
uv run python - <<'PY'
import json
from pathlib import Path
c = json.loads(Path('config/recomp.json').read_text())
m = dict(schema_version=1, guest_page_size=4096, edges=[], objects=[
    dict(instance_id='GTASA', path=c['input'], sha256=c['sha256'],
         load_bias=4294967296)])
Path('generated/dependency-input.json').write_text(json.dumps(m, indent=2) + '\n')
PY
uv run python tools/audit_dependencies.py \
  --manifest generated/dependency-input.json \
  --output generated/dependency-evidence.json
```

No dependency directory is scanned. Manifest and original-input report remain
ignored under `generated/`, as do all original binary data. Synthetic fixtures
are created in temporary directories by `tests/test_dependency_manifest.py`.

## Official sources checked 2026-11-06

- [Generic ELF dynamic linking ABI](https://gabi.xinuos.com/elf/08-dynamic.html):
  dynamic entries describe needed names and SONAME, with significant relative
  NEEDED order. Retaining this metadata does not establish this Android process's
  scope or actual dependency file identities.
- [AOSP linker changes for NDK developers](https://android.googlesource.com/platform/bionic/+/refs/heads/main/android-changes-for-ndk-developers.md):
  documents API/target-dependent loading behavior, lookup group/order changes,
  SONAME/path handling and symbol versioning. This motivates separate API,
  target SDK, main/preload and load-order evidence slots; it does not identify
  the game's device configuration.
- [AOSP linker namespaces](https://source.android.com/docs/core/architecture/vndk/linker-namespace):
  describes isolation, permitted visibility across namespaces, and runtime
  dependencies beyond static metadata. Namespace configuration and runtime load
  evidence are separate from a DT_NEEDED graph. Current AOSP documentation is
  not proof of a historical game's namespace policy.

The prior [native/audit sources](LINKER_AUDIT.md#official-rules-and-platform-boundaries)
and [planner sources](RESOLUTION_PLAN.md#official-evidence-checked-2026-11-06)
remain the references for unchanged validation and symbol metadata semantics.

## Historical single-input result

The original-input run on 2026-11-06 supplies exactly one verified GTASA instance
at bias `0x100000000`, explicit guest page size `0x1000`. Its 11 DT_NEEDED entries
remain in observed order: libSCAnd.so, libandroid.so, libc.so, libm.so, liblog.so,
libEGL.so, libGLESv2.so, libOpenSLES.so, libOpenAL64.so, libstdc++.so, libdl.so.
All 11 are missing file associations; no dependency file was supplied or searched
for. All seven platform evidence slots are unknown. The graph's transitive
closure is unknown, rather than reported complete because only one file exists.

Independent report assertions preserve 5,252 applied RELATIVE relocations,
21,458 unresolved relocations (21,072 `preemptible_symbol`, 386
`undefined_symbol`), and 274 unresolved imports. RELRO is sealed and readiness
false in both nested and overall reports. Two version requirement records remain
inventoried; this input has no TLS/IFUNC symbol requirement. Absence here says
nothing about missing dependencies. There is no selected symbol provider or
implemented bridge.

Validation passed pinned `uv sync --locked`, hash-verified inspect/lift, the
CMake/Ninja C++11 build, all four CTest cases and all 114 Python tests. Eleven
new manifest test methods cover direct/transitive/missing dependencies, duplicate
NEEDED names, explicit associations and invalid edges/configuration, same hashes
and SONAMEs across distinct instances, cyclic and 2,000-node iterative graphs,
known versus unknown evidence, version requirements/definitions, TLS/IFUNC and
special attributes, each-instance hashing, metadata from captured bytes after
source replacement, deterministic read-only composition, deep-copy independence,
and absent/prior-report preservation on hash/native/metadata/configuration errors.
Snapshot tests include applied bytes, unresolved entries and sealed/unsealed
RELRO; native preparation retains its independent whole-readable-byte and
permission checks. All original fixtures and generated reports remain ignored.

The existing bounded semantic harnesses separately passed: FP 2,048 calls /
6,144 result words, integer 760 calls, memory 1,216 calls and control flow 760
calls. These explicitly requested regression tests use the existing instruction
oracle harnesses; the manifest audit itself invokes no guest function and none
of these commands performs game startup.

## User-supplied APK library audit, 2026-11-06

Foundation: `ef9baca`. Inventory was authorized only in
`inputs/apk-2.10/lib/arm64-v8a/`; no other dependency directory was searched.
The user attributes these files to libraries extracted from the GTA SA 2.10 APK.
This is user attribution, not independently verified APK provenance. No trusted
comparison APK/file hash was supplied; authenticity remains **unknown** for all
three files. GTASA's observed hash also matches the pre-existing configuration,
which establishes baseline content identity, not independent APK authenticity.

All three directory entries are regular little-endian AArch64 ELF64 ET_DYN files
accepted by the existing native and metadata validators. There were no other
architectures, rejected inputs, symlinks or subdirectories in the supplied
directory. No native acceptance rule was extended.

The explicit paths, instance IDs, byte sizes, complete SHA-256 identities,
provenance and validation status are recorded locally in ignored
`generated/apk-2.10-file-inventory.json`. The manifest is
`generated/apk-2.10-dependency-input.json`: each instance ID is `apk-2.10:` followed
by its filename, each path is the filename beneath the authorized directory,
and every expected SHA-256 is a pin of locally observed content. These pins are
not independent authenticity evidence. Every isolated image uses explicit bias
`0x100000000` and guest page size `0x1000`; these are analysis parameters, not
observed Android process addresses or device geometry. Reusing the bias does
not establish a joint mapping or load order.

Reproduce the validated manifest audit with the local manifest already pinned:

```bash
uv run python tools/audit_dependencies.py \
  --manifest generated/apk-2.10-dependency-input.json \
  --output generated/apk-2.10-dependency-evidence.json
```

Do not regenerate expected hashes automatically when repeating this audit: a
changed input should fail against its recorded pin. The successful report retains
the complete symbol tables, dynamic entries, versions, special attributes,
applied/unresolved relocations and RELRO evidence for each instance. The existing
capture/hash/native/metadata/configuration validation and atomic publication
boundary is unchanged. No resolution planner was invoked and no additional
fixup was applied. The earlier single-input report was retained separately.
`generated/apk-2.10-audit-summary.json` contains derived counts, ordered needs
and name candidates; it is descriptive output, never an input validation source.
All binaries, local manifests and original-input reports remain ignored.

| Audited file | Bytes | Applied RELATIVE | Unresolved relocations | Unresolved imports |
| --- | ---: | ---: | ---: | ---: |
| libGTASA.so | 49,784,160 | 5,252 | 21,458 | 274 |
| libOpenAL64.so | 18,165,648 | 1,147 | 2,863 | 191 |
| libSCAnd.so | 8,589,752 | 272 | 5,877 | 149 |
| Total across isolated inventories | 76,539,560 | 6,671 | 30,198 | 614 |

GTASA exactly retains 21,072 `preemptible_symbol` and 386 `undefined_symbol`
relocations. OpenAL has 2,669 preemptible / 194 undefined; SCAnd has 5,727
preemptible / 150 undefined. All applied entries are the existing RELA RELATIVE
subset; all 36,869 relocation records are RELA. Every image has sealed RELRO and
`ready_to_execute=false`. All 614 import entries remain unresolved; counts across
files/tables do not identify unique APIs or selected providers.

### Ordered dependencies and association limits

The following table preserves each original dynamic section/index and NEEDED
ordinal. Full raw entries remain in the ignored report. `GTASA`, `OpenAL` and
`SCAnd` abbreviate the three instance IDs only in this table.

| Ordinal | GTASA section 16: index / name | OpenAL section 17: index / name | SCAnd section 17: index / name |
| ---: | --- | --- | --- |
| 0 | 0 / libSCAnd.so | 0 / libc.so | 0 / libc.so |
| 1 | 1 / libandroid.so | 1 / libm.so | 1 / libm.so |
| 2 | 2 / libc.so | 2 / liblog.so | 2 / liblog.so |
| 3 | 3 / libm.so | 3 / libdl.so | 3 / libdl.so |
| 4 | 4 / liblog.so | 4 / libz.so | 4 / libz.so |
| 5 | 5 / libEGL.so | 5 / libOpenSLES.so | 5 / libGLESv1_CM.so |
| 6 | 6 / libGLESv2.so | 6 / libstdc++.so | 6 / libstdc++.so |
| 7 | 7 / libOpenSLES.so | — | — |
| 8 | 8 / libOpenAL64.so | — | — |
| 9 | 9 / libstdc++.so | — | — |
| 10 | 10 / libdl.so | — | — |

There is no explicit per-entry attribution connecting these instances. Merely
being supplied together as APK-extracted libraries does not identify an actual
DT_NEEDED selection. The manifest therefore has `edges: []`: all 25 required
associations remain `missing` / `not_supplied`, with target null and provider
unknown. The filename and SONAME of supplied SCAnd and OpenAL match GTASA's
section 16 entries 0 and 8 respectively. These are **two name-only candidates**,
not attributed edges, import resolutions or evidence of Android selection.

The other 23 NEEDED occurrences have no supplied name candidate. Their 11 unique
names are libandroid.so, libc.so, libm.so, liblog.so, libEGL.so, libGLESv2.so,
libOpenSLES.so, libstdc++.so, libdl.so, libz.so and libGLESv1_CM.so. All remain
missing within the authorized inventory. In particular libz.so (both additional
files) and libGLESv1_CM.so (SCAnd) were not in GTASA's direct list. These are
observed requirements of separately audited candidate files, not proven
transitive edges from GTASA. Transitive requirements of missing files, runtime
loads and the overall dependency closure remain unknown. An empty attributed
cycle list likewise does not prove that the actual process graph is acyclic.

### Versions, platform evidence and next milestone

All three files have versym and verneed metadata, with no version definitions.
Every requirement below is named `LIBC`, with flags 0; numeric indices are local
to each file. The native and metadata inventories retain all raw records.

| Instance | libc.so version index / import entries | libm.so version index / import entries | libdl.so version index / import entries | Imports with raw versym 0 |
| --- | --- | --- | --- | ---: |
| GTASA | 3 / 131 | 2 / 25 | No requirement record | 118 |
| OpenAL | 2 / 158 | 3 / 25 | 4 / 1 | 7 |
| SCAnd | 2 / 137 | 3 / 4 | 4 / 1 | 7 |

There are eight version requirement records across the files. All are in
section 5: GTASA record indices 0/1 are libc/libm; OpenAL and SCAnd each have
indices 0/1/2 for libdl/libm/libc. No TLS symbols/sections/segments, IFUNC symbols,
extra st_other attributes or TLS/IRELATIVE relocations were observed in these
three inputs. This absence says nothing about missing files or runtime loads.
The additional libdl `LIBC` requirements make its exact file and version exports
another evidence gap alongside libc/libm; matching a version name does not
establish provider eligibility.

Android API, device build, target SDK, namespace, main executable, preload and
load order all remain unknown. The official dynamic ABI, AOSP linker-change and
namespace sources linked above were reopened on **2026-11-06**: dependency names
do not capture process policy, API/target-dependent behavior or runtime namespace
visibility. None identifies this game's process environment.

The next milestone remains **acquisition and attribution of evidence followed
by another read-only audit**: obtain explicitly supplied files for the 11 absent
names, trusted APK/file comparison identities where available, attribution for
the two supplied name candidates, exact libc/libm/libdl version exports, and
process/device evidence for all seven unknown slots. Do not search new locations
without authorization. Missing files' transitive requirements await those inputs.
No original-dependency resolution plan, scope/version policy expansion,
transactional plan application or platform bridge is part of this milestone.

### Validation of this follow-up

`uv sync --locked`, CMake/Ninja build, all four CTest cases and all 114 Python
tests passed. No source code changed, so the four separate original-instruction
differential commands were not rerun; their earlier results above remain
historical. Existing synthetic/native regression tests are separate from the
input audit, which called no guest function, constructor, initializer, JNI_OnLoad
or IFUNC resolver. No game startup was attempted.

Independent report assertions reconciled each file's counts, all 25 missing
associations, unresolved imports, sealed RELRO, seven unknown platform slots and
the exact GTASA baseline. A separate deliberately bad-hash manifest failed
before native use and left the successful three-file report byte-for-byte
unchanged; its diagnostic record is ignored
`generated/apk-2.10-publication-check.json`. The existing manifest regression
suite also passed its native/metadata/configuration failure publication checks.
`git diff --check` passed, and `git check-ignore` confirmed the binaries and local
audit artifacts remain ignored. Only documentation changed in Git; no commit or
push was made.

## Evidence request package, 2026-11-06

Against foundation `56e1198`, the unchanged local pin manifest was revalidated
through `tools/audit_dependencies.py` into the separate ignored
`generated/apk-2.10-dependency-recheck.json`. Independent assertions found full
structural equality with the historical three-file report, including the exact
GTASA baseline, all 25 missing associations, eight version records, sealed RELRO
and false readiness. The original report and expected pins were preserved.
No additional explicitly authorized input path was supplied, so no new file or
location was audited and no new object manifest was made.

[EVIDENCE_REQUEST.md](EVIDENCE_REQUEST.md) now specifies the 11-name matrix,
every requesting instance/ordinal/section/index, relevant version records,
static provenance artifacts and external process captures needed next. Its local
collection worksheet is `generated/dependency-platform-evidence-template.json`;
the full 25-entry matrix is `generated/dependency-evidence-matrix.json`.
Absent paths/hashes/biases remain null, candidate associations and all seven
platform slots remain unknown, and local pins remain distinct from trusted
reference hashes. The worksheet is not an audit manifest or lookup policy.

Official ELF, AOSP linker/namespace and Android manifest sources were checked
on 2026-11-06 and are linked with their limits in the request document. Current
documentation does not establish APK authenticity or this process's platform
facts. Acquisition and attribution followed by an explicitly authorized read-only
audit remain the milestone; original-dependency resolution planning and
scope/version expansion remain outside it.

This package passed pinned `uv sync --locked`, CMake/Ninja build, all four CTest
cases and all 114 Python tests. Documentation and ignored local artifacts alone
changed; separate original-instruction differential commands were not rerun.
The audit executed no guest code or resolver. Worksheet consistency, ignored
artifact coverage and `git diff --check` were also checked. No commit or push
was made.

## Connected-device acquisition and validation, 2026-11-06

Following the user's broader access authorization and explicit notification that
ADB was connected, read-only acquisition was extended to the connected device.
This supersedes the earlier directory-only acquisition boundary for this new
capture, not the historical audits or their pins. Worktree writes remain local
to `static-recomp`; the original worktree and agents were not changed.

One authorized ADB device reported model SM-A155F, Android 16, API 36 and
`arm64-v8a` support. Its reported build identity is retained locally, not
independently authenticated. All 11 names in [EVIDENCE_REQUEST.md](EVIDENCE_REQUEST.md)
were readable without root at `/system/lib64/`. Readlink resolved libc/libm/libdl
to `/apex/com.android.runtime/lib64/bionic/`; the other eight paths resolved to
themselves. Only these explicitly enumerated paths and device build properties
were queried. No game process or unrelated application data was inspected.

The files were copied into ignored `inputs/device-sm-a155f-api36/lib/arm64-v8a/`.
Each local SHA-256 matched device-side sha256sum before and after adb pull.
All headers identify little-endian ELF64 AArch64. The ignored acquisition record
`generated/device-sm-a155f-api36/acquisition.json` retains remote/resolved/local
paths, byte counts, pins, reported build properties, capture time and limits.
This establishes acquisition consistency, not independent authenticity or
association with the APK. No trusted external reference hash was supplied.

Each existing captured file received a separate ignored one-object manifest and
an attempt through `tools/audit_dependencies.py` with unchanged validators.
Bias `0x100000000` and page size `0x1000` were explicit isolated analysis
parameters, not observed process geometry. Each manifest has no attributed
edges and keeps all platform envelopes unknown for the game context. Device API
and build are known only as observations about this acquisition; the original
APK/process environment remains unestablished.

| Captured file(s) | Validation result |
| --- | --- |
| libc.so | Accepted by native and metadata validators; RELRO sealed, readiness false |
| libandroid.so, libm.so, liblog.so, libEGL.so, libGLESv2.so, libOpenSLES.so, libstdc++.so, libdl.so, libz.so, libGLESv1_CM.so | Rejected: `unsupported packed ELF relocation section`; no successful audit report published |

Native rejection diagnostics were retained separately because the existing CLI
surfaces a subprocess failure without displaying the captured native stderr.
No acceptance gate, parser, format support or fixup policy was changed. Rejected
files remain acquired but unsupported, not missing or successfully audited.
The local validation ledger is
`generated/device-sm-a155f-api36/validation-results.json`; individual manifests,
logs and the accepted libc report reside beside it, all ignored.

The isolated libc audit applies 1,662 existing RELATIVE fixups and leaves 548
relocations unresolved: 519 preemptible, 14 undefined, 12 IFUNC and three
unsupported relocation types. All 12 imports remain unresolved. It inventories
30 IFUNC symbols, six TLS symbols, one TLS segment, two TLS sections and nine
extra-attribute symbol entries without executing a resolver. Its two ordered
NEEDED entries are section 22 indices 0/1: `ld-android.so`, `libdl.so`, both
unassociated. The supplied libdl file's rejection does not create an edge or a
provider; no further transitive file acquisition was performed.

The original manifest was preserved byte-for-byte and all three original files
were rehashed against its unchanged expected pins. Historical GTASA report
assertions still match 5,252 RELATIVE applied, 21,458 unresolved (21,072
preemptible / 386 undefined), 274 unresolved imports, sealed RELRO and readiness
false. This device capture does not resolve any original dependency, attribute
SCAnd/OpenAL, identify target SDK, or establish process namespace/main/preload/
load order. It is not evidence that GTA runs on this device.

Next reconcile user-supplied provenance or external process evidence if it
becomes available. Ten acquired files require separately authorized future
format-support work before successful audit; no such implementation is part of
this capture. Dependency closure and original resolution remain unknown.

Validation for this capture passed pinned dependency sync and all 11 dependency
manifest regression tests. Acquisition assertions checked all remote/local
hashes and ARM64 headers, original pins and manifest preservation; audit
assertions checked rejection without publication and accepted libc's sealed,
unresolved, non-executable state. Ignore coverage and `git diff --check` passed.
No tracked source changed, so build/full CTest/Python and separate semantic
commands were not rerun; their prior results remain historical. No commit or
push was made for this capture.

## Read-only relocation diagnosis and proposal, 2026-11-06

The [format diagnosis](RELOCATION_FORMAT_PROPOSAL.md) rechecks all 11 acquisition
pins without refreshing identities and reproduces all ten native section
rejections. All ten contain SHT_ANDROID_RELA/APS2, four with zero entries and no
packed dynamic tags; nine additionally contain Android-numbered RELR. libdl has
only an empty APS2 section and no RELR. Official Android 16 source revisions,
per-file table evidence and a staged decoder/inventory proposal are recorded
there. No acceptance rule, fixup, dependency association or scope/version policy
changed; rejected files remain unsupported. The separate original three-file
audit is structurally identical to the historical report and preserves the
complete GTASA baseline. Existing acquisition notes and ignored records remain
intact; no device operation, guest execution, commit or push occurred.

## Pure APS2 decoder follow-up, 2026-11-06

The standalone [APS2 RELA byte decoder](APS2_RELA.md) adds no dependency-audit
acceptance or symbol policy. Rechecking the existing 11 acquisition pins with
the unchanged native validator still accepts libc and rejects the other ten
packed-section inputs. Separate pure decoding matches all 796 historical APS2
tuples across ten streams, including four empty streams. This is diagnostic
decoder evidence, not a successful audit of those ten files. No device change
or additional acquisition occurred.

A fresh three-file original dependency audit is structurally identical to the
historical report, including the exact GTASA baseline and all missing edges.
The output is ignored `generated/aps2-rela-baseline-recheck.json`; the separate
decoder/native recheck is `generated/aps2-rela-device-recheck.json`. Original
manifest, pins and reports were preserved. No scope/version policy, original
resolution plan, provider or fixup changed. The next bounded format step is
pure RELR decoding; format acceptance and structural integration remain future
work. See the decoder document for the data-only test results and limits.

## Standalone RELR decoder follow-up, 2026-11-06

[Pure RELR decoding](RELR.md) now supports ELF64 little-endian Android and
standard payloads in a separate C++11 library. Stream-order target records retain
implicit-addend and word/bit provenance; aligned unique-target policy, expansion
and temporary validation storage limits, and atomic failure are tested. No ELF
loader, audit, planner, rejection guard or application behavior changed.

All eleven device pins were rechecked unchanged: libc remains accepted and the
ten packed inputs remain rejected. Separate ignored pure decoding matched 3,684
RELR targets in nine streams; this is diagnostic evidence, not successful audit
acceptance. The fresh original three-file audit is structurally identical to its
historical report: GTASA retains 5,252 RELATIVE applied; 21,458 unresolved
(21,072 preemptible / 386 undefined); 274 unresolved imports; RELRO sealed;
readiness false. Three selected data-only CTests and 78 Python data-only methods
passed, including unchanged APS2 tests; RELR also passed UBSan. No guest code or
device operation ran. See the decoder document for exact scope and limits.

Next propose APS2 + RELR inventory-only integration for separate review, including
structural binding and cumulative per-object budgets, without application.
Original-dependency resolution, scope/version policy and platform work remain
unchanged. No commit or push was made.
