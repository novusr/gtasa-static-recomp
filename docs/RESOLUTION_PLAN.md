# Read-only two-object resolution plan

Implemented against `d5a1563`, checked 2026-11-06. This milestone selects symbol
identities in two synthetic AArch64 ET_DYN objects. It neither resolves the
original game's dependencies nor implements an Android linker. No constructor,
JNI_OnLoad, initializer, guest function or IFUNC resolver is called. No plan
fixup, host provider, import stub, bridge, dependency search or dispatch is added.

## Reproduce

After the normal sync, inspect/lift and native build:

```bash
uv run python tests/make_resolution_demo.py
uv run python tools/plan_resolution.py \
  --config generated/resolution-demo/config.json \
  --output generated/resolution-plan.json
```

The fixture generator writes only synthetic data to ignored `generated/`. The
result has one `planned` selection: A's dynamic OBJECT import `(A,2,1)` selects
B's definition `(B,2,1)` at guest address `0x200009010`. A's ABS64 relocation
remains unresolved in its prepared-image snapshot. Nothing applies the plan.
All objects retain `ready_to_execute=false`, as does the overall report.

## Input and identity contract

The JSON configuration has these required fields (numbers are decimal JSON
integers, including load biases):

```json
{
  "objects": [
    {"object_id": "A", "input": "generated/resolution-demo/A.elf",
     "sha256": "<64 lowercase hexadecimal characters>", "load_bias": 4294967296},
    {"object_id": "B", "input": "generated/resolution-demo/B.elf",
     "sha256": "<64 lowercase hexadecimal characters>", "load_bias": 8589934592}
  ],
  "lookup_scope": ["A", "B"],
  "guest_page_size": 4096,
  "references": [{"object_id": "A", "table_section": 2, "index": 1}]
}
```

Paths are explicit and relative to the project root unless absolute. IDs are
nonempty, distinct instance IDs, independent of SONAME, path, hash and symbol
name. Loading identical bytes twice still produces two different instances.
Each input is captured, bounded and SHA-256 verified before decoding, then the
same captured bytes pass the existing native validation and inventory checks.
An existing report is never accepted as file-validation evidence.

Exactly two instances are required. Scope must list both IDs once, in caller
order; omission, duplication and unknown IDs fail validation. The objects'
nonempty PT_LOAD guest mappings must not overlap. References are an explicit,
nonempty list of unique `(object_id, table_section, index)` identities with a
nonzero index present in the native inventory. A reference is a symbol query,
not an instruction, relocation expression, or authorization to execute it.
Names only compare candidates during eligible external lookup; they never
merge identities across instances, tables or indices. There is one shared
caller-declared scope for this prototype's queries, with no inferred ordering.

## Preparation and pure planner boundary

`prepare_plan` reuses `audit_linker.audit` for each file. Separate temporary
native images undergo the existing supported transactional RELA application and
explicit RELRO sealing, with byte/permission checks. This is preparation, not
application of any resolution plan. The audit now additionally retains section
headers (index/type/flags/address/size/link) for symbol-range eligibility checks.
All previous native inventories and rejection gates remain in force.

`compose_plan` is a pure transformation over these trusted snapshots. It does
not receive an image handle, reopen inputs, invoke a runner, apply relocations,
seal memory or call guest code. It does not change bytes, permissions,
applied/unresolved inventories, import status or sealing. Snapshots remain
owned by the caller; the report contains independent copies. An explicit
unsealed snapshot is also left unsealed by pure composition. This API is not
a replacement validation entry point for untrusted JSON or files.

## Supported rules and conservative exclusions

- Ordinary unversioned FUNC and OBJECT symbols are supported. A defined LOCAL
  symbol, or a GLOBAL definition with HIDDEN/INTERNAL/PROTECTED visibility,
  binds to its exact internal identity, independent of scope order. LOCAL plus
  PROTECTED and undefined internal references are unsupported.
- External queries require SHT_DYNSYM and default visibility. GLOBAL definitions
  with default visibility undergo scope lookup even when the reference itself
  is defined: an earlier object can preempt them. Undefined GLOBAL and WEAK
  references can select ordinary GLOBAL providers. WEAK definitions are outside
  this profile, including internal ones.
- External providers must be defined GLOBAL dynamic symbols with default or
  PROTECTED visibility. LOCAL and HIDDEN/INTERNAL symbols, undefined entries and
  every SHT_SYMTAB entry are rejected as external providers, with trace reasons.
  PROTECTED remains eligible externally and binds internally to itself.
- Search visits objects in explicit scope order. The first object with a unique
  eligible provider wins. Multiple potentially eligible dynamic definitions in
  one object are unsupported, including across dynamic tables; symbol index or
  table order is not guessed as hash-chain precedence. FUNC/OBJECT type mismatch
  is unsupported rather than an inferred platform type-matching policy.
- An unsupported potentially decisive candidate stops lookup. It cannot be
  skipped to reach a supported later provider. Lookup stops at the selected
  scope position; later objects' symbol candidates cannot change that selection
  and are not listed in the trace. Rejected same-name entries in visited objects
  retain their full table/index provenance and rejection reasons.
- Any versym association, including raw indices 0/1, is unsupported. Versioning,
  TLS (including defining TLS sections), IFUNC, COMMON, extra st_other bits
  (including VARIANT_PCS), special/reserved section indices (including SHN_ABS),
  unsupported bindings/types, section flags beyond WRITE/ALLOC/EXECINSTR,
  overflowing section extents, nonallocated definitions and out-of-section values
  produce explicit diagnostics. No IFUNC resolver is run.
- DT_SYMBOLIC, policy-affecting FLAGS/FLAGS_1 and unknown dynamic tags block
  external lookup across the declared scope. Only DF_BIND_NOW and DF_1_NOW flag
  bits are accepted. Known inventory/address tags are retained; NEEDED,
  RPATH/RUNPATH and initializer metadata cause no dependency search or calls.
  The profile does not derive scope from any of these tags.
- Ordinary candidate addresses use checked `load_bias + st_value`, with the
  entire symbol extent inside its allocated defining section and a PT_LOAD
  mapping; zero-size end markers are allowed. Overflow and unmapped symbols
  are unsupported. All addresses remain numeric guest addresses. No host pointer,
  relocation addend expression, target permission or callable entry is inferred.

These exclusions are tooling limits, not declarations that the ABI forbids
those ELF forms. This profile does not implement weak-definition precedence,
version matching, Android namespace/global/local group construction, process
main/preload rules, symbolic lookup, TLS allocation or platform relocation policy.

## Output and failure contract

Schema version 1 records profile, facts (every instance's hash/bias and full
prepared audit, explicit scope and references), assumptions and unknowns
separately. Each query records the referenced symbol, selected identity and
symbol if any, traced candidates, reasons and unsupported policy diagnostics.
The only candidate address is the validated selected guest address.

| Status | Meaning |
| --- | --- |
| `planned` | Supported symbol selection; no fixup or implementation supplied |
| `missing_strong` | No eligible provider for an undefined GLOBAL reference |
| `missing_weak` | No eligible provider for an undefined WEAK reference |
| `unsupported` | Reference, decisive candidate or scope policy needs unsupported semantics |

Missing weak has no selected address, implementation or success stub. Potential
zero-value weak relocation behavior is deferred. Every query has implementation
and bridge `unknown`, and `plan_applied=false`; overall readiness is always false.
Symbol selection never changes an audit's unresolved import or relocation state.

Unsupported queries are valid diagnostic report data. Hash/native/metadata,
configuration, missing identity or mapping-overlap validation failures instead
return nonzero before publication. JSON replacement uses the audit's atomic
publisher only after both inputs and the complete plan succeed. Failed runs
neither create an output report nor replace an existing one; an old report may
therefore remain. All binaries and reports stay ignored outside Git.

## Official evidence checked 2026-11-06

The prior [linker audit sources](LINKER_AUDIT.md#official-rules-and-platform-boundaries)
remain applicable. The following official pages were reopened for this milestone:

- [Generic ELF symbol table ABI](https://gabi.xinuos.com/elf/05-symtab.html),
  sections 5.2–5.4: binding, symbol types and visibility underpin internal binding,
  preemption and provider eligibility. PROTECTED permits exports while preventing
  internal preemption. Missing weak does not imply a callable implementation.
- [Generic dynamic linking ABI](https://gabi.xinuos.com/elf/08-dynamic.html):
  dependency metadata and symbolic lookup require process policy. This prototype's
  complete caller-ordered two-instance scope and strict type/ambiguity exclusions
  are an explicit profile, not a reconstruction of that process.
- [Arm AAELF64 2026Q3](https://github.com/ARM-software/abi-aa/blob/2026Q3/aaelf64/aaelf64.rst),
  sections 5.5–5.6: AArch64 ordinary visibility and VARIANT_PCS attributes justify
  retaining all st_other bits and rejecting unsupported calling conventions.
- [Android linker changes](https://android.googlesource.com/platform/bionic/+/refs/heads/main/android-changes-for-ndk-developers.md):
  API-dependent lookup groups, ordering and version support remain separate Android
  work. Current AOSP behavior is not evidence of this game's device/process setup.

## Verification and next milestone

The 16 new synthetic test methods cover two-file imports, both scope orders,
default preemption, LOCAL/HIDDEN/INTERNAL/PROTECTED internal binding, nonexports,
protected exports, weak/strong misses, same names and identical hashes across
instances, independent tables, ambiguity, unsupported references and decisive
providers, versions including indices 0/1, TLS/IFUNC/COMMON/attributes/policy,
address overflow/mapping/section bounds, invalid scopes/IDs/references, overlapping
images, deterministic read-only snapshots and CLI publication failures. A snapshot
with both applied and unresolved relocations and sealed RELRO stays unchanged;
the existing native probe checks preparation's entire readable bytes and mapped
permissions. No planner gains write access to an image.

Next capture exact dependency/hash and Android process/API/namespace evidence,
then design a separately named scope/version/weak-definition policy with explicit
unsupported diagnostics. Plan application needs its own transactional relocation
contract, target validation, platform addend policy and RELRO ordering tests.
No application or bridge work is implied by this milestone.

Validation on 2026-11-06 passed `uv sync --locked`, hash-verified inspect/lift,
the C++11 CMake/Ninja build, all four CTest cases and all 103 Python tests
(including the 16 new planner methods). Existing bounded semantic regressions
also passed: FP leaf 2,048 calls / 6,144 result words, integer 760 calls, memory
1,216 calls and control flow 760 calls. These existing test harnesses are
separate from planning and do not perform game startup.

The original input was re-audited at bias `0x100000000`, guest page size `0x1000`:
5,252 RELATIVE applied; 21,458 unresolved (21,072 `preemptible_symbol`, 386
`undefined_symbol`); 274 unresolved imports. RELRO remains sealed and readiness
false. Independent assertions reconciled the ignored original audit and the
synthetic plan. No original dependency is claimed resolved. Original metadata,
fixtures and generated output remain outside Git.
