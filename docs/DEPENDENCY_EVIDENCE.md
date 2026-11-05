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
     "sha256": "<expected 64 lowercase hex digits from trusted input evidence>",
     "load_bias": 4294967296}
  ],
  "edges": [],
  "platform_evidence": {},
  "assumptions": []
}
```

The hash placeholder must be replaced before use. Paths are explicit, absolute
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

## Verified result and next milestone

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

The next milestone is **acquisition and attribution of the missing dependency
and process evidence**, followed by another read-only manifest audit. The observed
libc/libm version requirements make exact Android builds and their version exports
a concrete prerequisite. The missing libSCAnd.so and the other ten files require
explicit paths, trusted expected hashes and independently attributed associations;
API/device build, target SDK, namespace, main executable, preload and load order
need process/device evidence. No new file path or historical API policy is guessed.
Only after this evidence is available should a separately named scope/version
policy be designed around the observed requirements, with synthetic semantics
and rejection tests. Transactional plan application and bridges remain later,
separate work.
