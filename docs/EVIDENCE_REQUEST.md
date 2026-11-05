# Dependency and platform evidence request

Prepared 2026-11-06 on `static-recomp`, foundation `56e1198`. This milestone
packages missing evidence; it does not design original-dependency resolution or
extend scope/version policy. Only the three previously supplied paths were
re-audited against unchanged `generated/apk-2.10-dependency-input.json` pins.
No additional input path or authorization was supplied. No other dependency
location was searched; inventory permission remains limited to
`inputs/apk-2.10/lib/arm64-v8a/`.

## Reconciliation and local package

The fresh validated `generated/apk-2.10-dependency-recheck.json` is structurally
equal to the historical three-file report. The prior report and pin manifest
were retained. Three accepted files, 25 NEEDED occurrences, zero attributed
edges and two name-only candidates remain. Eleven absent names account for
23 occurrences. These include requirements of separately audited OpenAL/SCAnd;
they are not established transitive edges from GTASA.

GTASA retains **5,252 RELATIVE applied; 21,458 unresolved (21,072 preemptible,
386 undefined); 274 unresolved imports; RELRO sealed; readiness false**.
All three isolated images retain sealed RELRO and unresolved imports. APK/file
authenticity and all seven platform slots remain unknown. The repeated analysis
bias `0x100000000` and page size `0x1000` are unchanged isolated test parameters,
not device observations, joint mappings or load order.

Local artifacts, all ignored:

- `generated/dependency-evidence-matrix.json`: all 25 original ordered requests,
  raw dynamic entries and all relevant requirement records/import identities.
- `generated/dependency-platform-evidence-template.json`: collection worksheet
  with 11 file requests, two candidate-association requests, seven unknown slots
  and an empty artifact catalog. Missing path, hash and bias values are null.
- `generated/evidence-package-reconciliation.json`: independent report/baseline
  assertions and the preserved manifest digest.
- `generated/prepare-evidence-package.py`: local descriptive derivation and
  assertions, not an alternate validator or audit manifest generator.

The worksheet is deliberately **not an object manifest** and must not be passed
to `audit_dependencies.py`. Unknown requirements never become nonexistent file
objects. It contains no lookup scope and chooses no provider.

## Missing-file matrix

Each cell lists every requesting instance as `ordinal / dynamic section:index`.
All numbers are zero-based; ordinal means position among that instance's
DT_NEEDED entries, not a new global sort order. G, O, S mean exactly
`apk-2.10:libGTASA.so`, `apk-2.10:libOpenAL64.so`, `apk-2.10:libSCAnd.so`.
The ordered 25-entry table in [DEPENDENCY_EVIDENCE.md](DEPENDENCY_EVIDENCE.md#ordered-dependencies-and-association-limits)
and the local matrix preserve the full per-instance sequence.

| Required file | G requests | O requests | S requests | Relevant version evidence to obtain |
| --- | --- | --- | --- | --- |
| libandroid.so | 1 / 16:1 | — | — | No named verneed record observed; retain exact exports/attributes |
| libc.so | 2 / 16:2 | 0 / 17:0 | 0 / 17:0 | LIBC requirements G V3, O V2, S V2; exact file's definitions and versioned exports |
| libm.so | 3 / 16:3 | 1 / 17:1 | 1 / 17:1 | LIBC requirements G V2, O V3, S V3; exact file's definitions and versioned exports |
| liblog.so | 4 / 16:4 | 2 / 17:2 | 2 / 17:2 | No named verneed record observed; retain exact exports/attributes |
| libEGL.so | 5 / 16:5 | — | — | Same static inventory requirement |
| libGLESv2.so | 6 / 16:6 | — | — | Same static inventory requirement |
| libOpenSLES.so | 7 / 16:7 | 5 / 17:5 | — | Same static inventory requirement |
| libstdc++.so | 9 / 16:9 | 6 / 17:6 | 6 / 17:6 | Same static inventory requirement; identify exact Android runtime build |
| libdl.so | 10 / 16:10 | 3 / 17:3 | 3 / 17:3 | No G record; LIBC requirements O V4, S V4; exact definitions/exports |
| libz.so | — | 4 / 17:4 | 4 / 17:4 | No named verneed record observed; retain exact exports/attributes |
| libGLESv1_CM.so | — | — | 5 / 17:5 | Same static inventory requirement |

For **each row**, supply the actual Android ARM64 file at an explicit local path,
permission to audit that path, source device/package/build, extraction method,
and any independent trusted reference hash with its authority. All file content
must pass the unchanged native and metadata validators. Static inventory will
retain exports, symbol table/index, versions, SONAME, DT_NEEDED order, relocation
formats, TLS/IFUNC and special attributes, without executing anything. New
transitive requirements remain unknown until the supplied file passes audit.
A named verneed absence does not assign unversioned imports to that library or
prove that a future file has no version/special requirements.

Version indices are local to requesters. The exact eight records are:

| Requester | Dependency | Verneed section:index | Auxiliary index | Name / flags / ELF hash | Local version index | Import entries |
| --- | --- | --- | ---: | --- | ---: | ---: |
| G | libc.so | 5:0 | 0 | LIBC / 0 / 331107 | 3 | 131 |
| G | libm.so | 5:1 | 0 | LIBC / 0 / 331107 | 2 | 25 |
| O | libdl.so | 5:0 | 0 | LIBC / 0 / 331107 | 4 | 1 |
| O | libm.so | 5:1 | 0 | LIBC / 0 / 331107 | 3 | 25 |
| O | libc.so | 5:2 | 0 | LIBC / 0 / 331107 | 2 | 158 |
| S | libdl.so | 5:0 | 0 | LIBC / 0 / 331107 | 4 | 1 |
| S | libm.so | 5:1 | 0 | LIBC / 0 / 331107 | 3 | 4 |
| S | libc.so | 5:2 | 0 | LIBC / 0 / 331107 | 2 | 137 |

Versym section 4 links symbol table 2 in each requester. The local matrix retains
each relevant import's name, table/index, raw versym, hidden bit and record
reference. G/O/S respectively also have 118/7/7 imports with raw versym 0,
without a named requirement association. No name-based allocation of those
imports to missing files is made. Equal `LIBC` names or numeric indices across
objects do not prove compatible exports or provider eligibility.

## Static artifacts the user can supply without game execution

Provide an artifact ID, explicit local path, origin/build, acquisition method and
date, and coverage/limitations for every item. An observed SHA-256 pins local
bytes; a trusted reference requires an independent source and a clear statement
of what it authenticates. Preserve both separately. If no reference exists,
authenticity remains unknown; do not silently refresh old expected hashes.

- The 11 dependency files listed above, tied to the intended Android build.
  Files of different builds must be distinguished, even if SONAMEs match.
- APK provenance: original package/version identity, extraction record, signing
  certificate information and trusted package/file comparison references if
  available. These can strengthen provenance but do not alone prove runtime
  object selection. Do not submit signing private keys or credentials.
- Target SDK: decoded manifest from that exact APK (including source identity
  and decoding method); an installed-package record may corroborate it. Do not
  infer target SDK or device API from a version string or dependency names.
- Android API/device build: an identified device-build artifact, API declaration,
  build fingerprint/ID and relevant system/vendor/module provenance tied to the
  supplied files. Files from an unrelated build cannot establish the target
  process's environment.
- Namespace configuration from the same build, public-library lists and related
  configuration artifacts, if available. These are static configuration evidence,
  not proof of which namespace or visibility applied to this process.

## Process evidence from an external capture

This worktree will not launch the game or collect a runtime trace. Supply
existing externally obtained artifacts, with device/build, APK identity, process
ID/session, UTC timestamps, capture mechanism and coverage interval. Redact
unrelated sensitive data while retaining attribution. Never treat a missing
capture entry as an observed empty value.

| Slot or association | Required external evidence | What static input cannot establish |
| --- | --- | --- |
| android_api / device_build | Captured platform identity tied to that process/session and the supplied build artifacts | That static build files describe the actual device used |
| target_sdk | Installed package/manifest identity tied to that APK and session, where available | That an unrelated manifest applies to the captured process |
| namespace | Requesting object's namespace membership, namespace links/visibility and applicable configuration at capture time | Effective visibility from names or static configuration alone |
| main_executable | Identified process executable, path/content identity, process context and relevant mappings | That libGTASA is the main executable or which process launched it |
| preload | Observed preload/global objects and relevant launch environment/configuration with capture coverage | Absence of preload from absence in DT_NEEDED; empty requires positive evidence |
| load_order | Ordered loader events, object identities, namespaces and initiating loads with timestamps/sequence | Chronology or lookup scope from a maps snapshot or DT_NEEDED alone |
| G 0 / 16:0 → SCAnd candidate | Requester identity plus selected object's path/hash, namespace and attributed loader/capture record | Association from matching filename/SONAME or co-packaging |
| G 8 / 16:8 → OpenAL candidate | Same evidence for the separate entry and exact OpenAL instance | Association from matching filename/SONAME or co-packaging |

A maps snapshot can corroborate mapped objects/addresses at one instant; it
does not by itself prove per-entry selection, load chronology or full namespace
visibility. Partial captures must retain unknown portions and their limitations.
Candidate attribution should identify both endpoint instances and each exact
DT_NEEDED section/index. A static caller declaration can be recorded as such,
but must not be relabeled as an observed Android selection. File association
still does not resolve any import or provide an implementation.

## Next audit gate and method

No new audit is scheduled on guessed files. First the user supplies explicit
paths, origin/build, permission, reference identities if available, candidate
attribution and platform artifacts. Check whether each path is covered by the
existing authorization; new locations need explicit permission. Do not search
for missing files elsewhere or download substitutes.

Review supplied artifacts before making a separate ignored audit manifest.
Add an object only for an existing explicitly supplied file, with a reviewed
expected identity and explicit isolated analysis bias/page parameters. Preserve
the old manifest as the baseline; document whether new identity expectations are
trusted references or local pins. Process load biases remain unknown unless
supported by capture; analysis parameters must never be relabeled as observations.
Only evidence-backed per-entry edges may be added, with their source and limits;
unknown edges stay unspecified/null and unknown platform slots stay unknown.

Run `tools/audit_dependencies.py --manifest <reviewed-local-manifest> --output
<new-local-report>` using existing capture/hash/native/metadata/configuration
validators. Reject unsupported supplied inputs without widening acceptance
rules. Publication occurs only after complete validation; a failed command may
leave an older report, so check command status and reconcile fresh results.
No resolution planner, new fixup, provider selection, guest execution or
scope/version-policy design belongs to this evidence milestone.

## Official platform references verified 2026-11-06

- [ELF dynamic linking ABI](https://gabi.xinuos.com/elf/08-dynamic.html), DT_NEEDED:
  relative dependency order is significant. It is preserved here, without
  interpreting it as a captured Android process order.
- [AOSP linker changes](https://android.googlesource.com/platform/bionic/+/refs/heads/main/android-changes-for-ndk-developers.md):
  lookup ordering/groups, SONAME handling, version support and compatibility
  depend on Android API/target behavior. This motivates separate platform slots,
  not any inferred policy for these files.
- [AOSP namespaces](https://source.android.com/docs/core/architecture/vndk/linker-namespace):
  isolation and cross-namespace visibility matter; runtime dependencies can
  escape static analysis. Static dependency metadata cannot establish visibility.
- [Android uses-sdk](https://developer.android.com/guide/topics/manifest/uses-sdk-element):
  targetSdkVersion is an application manifest API-level declaration distinct
  from the device's API. Obtain both identities rather than guessing either.

These current official references establish reasons to request evidence, not the
historical configuration of this APK. The seven platform facts remain unknown.

## Verification

Pinned dependency sync, CMake/Ninja build and all four CTest cases passed.
The three-file audit passed unchanged validators, and independent assertions
matched the complete historical report, all 25 missing associations, eight
version requirement records and the GTASA baseline. Local worksheet checks
retain null absent paths/hashes/biases and all seven unknown envelopes. No source
code changed; separate original-instruction differential commands were not
rerun and their prior results remain historical. Full Python regression results
are recorded with the milestone in [DEPENDENCY_EVIDENCE.md](DEPENDENCY_EVIDENCE.md).

## Subsequent connected-device evidence

After this request package was committed, the user authorized broader access
and connected an ADB device. The [device acquisition record](DEPENDENCY_EVIDENCE.md#connected-device-acquisition-and-validation-2026-11-06)
documents all 11 files obtained without root from an SM-A155F reporting API 36.
One libc file passed unchanged audit validators; ten files were rejected for
unsupported packed relocation sections. Thus these names now have acquired
device candidates, while original dependency associations remain unknown.
The earlier matrix and empty worksheet remain the historical request baseline;
the separate ignored device ledger records the new acquisition and validation
status. No old pin or unknown game-process fact was overwritten.

The subsequent [relocation diagnosis and proposal](RELOCATION_FORMAT_PROPOSAL.md)
distinguishes APS2 RELA from Android-numbered RELR using the unchanged local
pins and official source revisions. It proposes inventory support and synthetic
acceptance gates without implementing support or attributing dependencies.
