# Pure Android APS2 RELA decoding

Implemented on 2026-11-06 from clean HEAD `077466e` in `static-recomp`.
This is byte decoding only. It does not make the ten device libraries acceptable
to ElfImage, the dependency audit or the resolution planner. Their packed
relocation rejection guards and all relocation application code remain unchanged.
Android packed REL and both Android/standard RELR remain unsupported here.

## API and boundary

`include/recomp/aps2_rela.h` declares:

```cpp
void decode_android_aps2_rela(const uint8_t* data, std::size_t length,
                              Aps2RelaResult& output,
                              const Aps2RelaLimits& limits = Aps2RelaLimits());
```

The caller supplies a readable byte range with explicit length and selects RELA
semantics by choosing this API. The decoder checks the APS2 signature, but cannot
infer REL versus RELA from that signature. It receives no ELF descriptor, mutable
Memory, resolver, fixup handle or guest executable address. It does not open a
file, inspect a symbol table, read a relocation target, add load bias, validate
target mapping/alignment, or apply a relocation. Successful decoding establishes
only the byte/state contract below, not ELF validity or application eligibility.

`Aps2RelaResult` contains `initial_offset`, `encoded_size`, `group_count`, and
`records`. Each `Aps2RelaRecord` contains the raw unsigned offset/info, signed
explicit RELA addend, decoded ordinal, group ordinal/flags, and byte spans:

- `group_begin` through `group_header_end` covers the group header and shared
  fields; `group_end` ends the complete encoded group.
- `entry_begin` through `entry_end` covers just that record's unshared fields.
  A fully grouped entry legitimately has an empty span.
- All spans are half open and relative to the supplied buffer, including the
  four signature bytes. Shared fields therefore remain attributable even when
  no per-entry bytes exist. Result metadata preserves the empty stream too.

`symbol_index()` and `type()` split the raw 64-bit info into its two uint32
halves, preserving bit 63. Records deliberately have no conversion to
`ImageRelocation`, definition, biased address or applied status. Future ELF
integration must attach section/table/file identity and check linked symbol
indices separately; same-name symbols do not establish identity.

`Aps2DecodeError` identifies a byte offset and reason. Field-level malformed
SLEB errors identify the field start (truncation identifies the missing byte);
state/flag/group errors identify their relevant encoded group or field. Grouped
offset arithmetic failures identify the group start. Allocation failures propagate
as standard allocation exceptions. Output, including previous metadata, vector
contents, capacity and storage address, stays unchanged on every exception.
All decoding and allocation use a temporary result; publication uses vector swap
and nonthrowing scalar assignments only after exact consumption validates.

## Supported state and conservative profile

The implementation was independently checked against the official
[Bionic iterator](https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/linker/linker_reloc_iterators.h),
[Bionic SLEB reader](https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/linker/linker_sleb128.h)
and [LLVM 20.1.0 writer](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.0/lld/ELF/SyntheticSections.cpp).
The [reviewed proposal](RELOCATION_FORMAT_PROPOSAL.md) records revisions and
separates decoding from subsequent structural/application stages.

- Count and initial offset must be nonnegative signed-64 SLEB values. Zero
  count is valid, including nonzero nonnegative initial offset at this pure
  layer; canonical orphan-section restrictions are future ELF policy.
- Groups have positive size no larger than remaining count. Flags are info=1,
  offset-delta=2, grouped-addend=4, has-addend=8. Unknown bits and grouped-addend
  without has-addend reject. All 12 remaining combinations are supported.
- Group fields and record fields follow offset/info/addend order. Signed offset
  deltas may move backwards within or between groups; each unsigned result must
  fit uint64 without wrapping. Nonnegative initial offset limits initial state
  to INT64_MAX, but accumulation can reach UINT64_MAX.
- Addend begins at zero. A group without has-addend resets it to zero; this
  remains an explicit RELA zero, never an implicit target addend. Ungrouped
  addend deltas accumulate for each record. Grouped addend delta accumulates
  **once on entry to the group**, retaining the value for every record, exactly
  as the inspected Bionic iterator does. Signed accumulator overflow rejects.
- SLEB uses at most ten bytes, unsigned shifts and explicit two's-complement
  conversion. Byte ten must terminate and have payload 0x00 or 0x7f, extending
  bit 63 correctly. Truncation, excess continuation and out-of-range terminal
  bits reject. Valid nonminimal encodings remain accepted.
- Exact record count and exact byte consumption are mandatory. All trailing
  bytes, including zeros, reject. LLVM can pad its section **inside sh_size**
  to avoid shrinkage during convergence; Bionic stops at count. Such padded
  input is intentionally outside this requested conservative profile, rather
  than invalid under every Android implementation. No padding is trimmed.
- Duplicate targets, relocation types and symbol index values are returned
  without target/symbol validation. They confer no fixup eligibility. Address
  and signed addend wraparound accepted by some Bionic machine arithmetic is
  deliberately excluded from this nonwrapping profile.

## Expansion and storage limits

Defaults per call are **1,000,000 records** and **256 MiB storage**. Callers may
explicitly adjust either limit. Storage accounts for `sizeof(Aps2RelaResult)`
plus `count * sizeof(Aps2RelaRecord)`; the record is 88 bytes including all
provenance, with size and each field offset statically asserted. One vector is
allocated once from the declared count, with no separate group allocations or
incremental growth. Group spans repeat in records, so groups cannot hide
additional storage. The million-record default expands to 88,000,000 record
bytes even if the entire stream occupies only 14 bytes.

Division guards precede multiplication and conversion to size_t; the decoder
also checks vector max_size before allocating. Limits reject instead of
clamping or returning a prefix. They bound decoded inventory, not allocator
bookkeeping, caller-owned input, error strings, or an existing output retained
while the temporary is validated. Peak live memory includes old and new output.
Future per-object integration must deduct cumulative records/storage across all
tables (including future RELR); repeatedly calling with default limits does not
provide the proposal's aggregate object budget.

## Validation and reproduction

```bash
uv sync --locked
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure -R '^(aps2_rela_data_only|original_image_load)$'
uv run python -m unittest discover -s tests -p 'test_aps2_rela.py'
```

CMake builds the decoder as separate `recomp_aps2_rela`, not linked by the
runtime/loader. The Python test builds just the decoder and synthetic executable
with strict C++11, independently of generated lifted output or any original
binary. The existing CMake project still requires its previously generated
lifted sources to configure; no fresh lifting is needed for this stage.

The synthetic executable passes **636 checks**, using literal streams and
independently written expected tuples rather than encoder round trips. Coverage
includes every valid flag combination, shared/unshared byte provenance, multiple
groups, backward deltas, grouped nonzero addends, addend reset, explicit zero,
raw info high bits, signed/unsigned boundaries, zero count and nonminimal SLEB.
Rejection checks include every truncated prefix of a multiple-group stream,
bad signature, invalid counts/groups/flags, arithmetic overflow/underflow,
SLEB continuation/terminal overflow, trailing bytes and storage/count expansion
limits. Each rejection checks both prior and initially absent output. A test-only
allocator fails every allocation along successful decoding and late-error
construction paths, checking preservation before retry. Production has no
allocator hook. The same executable passes UndefinedBehaviorSanitizer with
`-fsanitize=undefined -fno-sanitize-recover=all`.

The build and two selected data-only CTests passed. Python data-only suites
passed: APS2 (1 method), image (25), linker audit (14), RELRO (10), dependency
manifest (11), resolution plan (16): **77 methods**. Tests that execute lifted
or original guest instructions, including other CTests and full instruction
Python discovery, were deliberately not run in this task.

All 11 acquired device files were rehashed against unchanged acquisition pins.
Native load-only validation still accepts libc and rejects all ten other files
with `unsupported packed ELF relocation section`. A separate ignored byte-only
probe compared every decoded APS2 tuple against the historical diagnostic data:
**796 records across ten streams**, including four empty streams, matched.
These comparisons add no acceptance path and do not use the diagnostic script
as production validation. Reports remain ignored in `generated/` and `build/`.

The fresh original three-file dependency audit is structurally identical to the
historical report. GTASA remains **5,252 RELATIVE applied; 21,458 unresolved
(21,072 preemptible, 386 undefined); 274 unresolved imports; RELRO sealed;
readiness false**. No device operation, guest function, initializer, constructor,
JNI_OnLoad, game startup or IFUNC resolver ran. No commit or push was made.

The next bounded step is a **pure RELR decoder** with address/bitmap provenance,
expansion bounds and atomic synthetic tests. Structural inventory integration,
format acceptance, cross-table budgets, target/symbol binding and any new
relocation application require later work. Dependency scope/version policy and
original resolution planning remain unchanged.
