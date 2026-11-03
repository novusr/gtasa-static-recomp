# AI Agent & Contributor Guidelines — GTA:SA 2.10 Android ARM64 Decompilation

This document establishes the official technical protocol, code style rules, and workflow loop for AI agents (Antigravity CLI, Claude Code, API models) and human contributors working on the byte-matching decompilation of `libGTASA.so`.

---

## 1. Absolute Rules

1. **100% Binary Match Requirement**:
   * A function is considered complete ONLY when `objdiff-cli` reports **100.0% matched code**.
   * No heuristic, approximate, or "fuzzy" matching is acceptable.
   * Do NOT use inline assembly (`__asm__`), raw opcode injection, or pragma hacks to force a match. The code must be clean, idiomatic standard C++11 that naturally compiles to identical bytecode.

2. **Clean C++11 Portability**:
   * All code in `src/` and `include/` must be standard C++11.
   * FORBIDDEN: Android-specific headers (`<android/*>`, `<jni.h>`), POSIX syscalls (`<sys/*>`, `<dlfcn.h>`), or raw hexadecimal memory addresses (`0x00538...`).
   * Use fixed-width integer types from `<cstdint>` (`int32_t`, `uint32_t`, `int16_t`, `uint8_t`, etc.) and standard `float`/`double`.

3. **Struct Layout and Memory Verification**:
   * Every structure declared in `include/` must verify its size and field offsets using compile-time assertions:
     ```cpp
     static_assert(sizeof(CVector) == 0xC, "Invalid CVector size");
     static_assert(offsetof(CMatrix, at) == 0x20, "Invalid CMatrix::at offset");
     ```
   * Structures must mirror the original RenderWare and GTA layouts precisely, taking 64-bit alignment and padding rules into account.

4. **Formatting and Communication**:
   * Zero emojis in source code, comments, commit messages, or logs.
   * Preserve all existing comments and documentation unless explicitly instructed otherwise.

---

## 2. Compiler Toolchain & Flags

All compilation must strictly use the verified Android NDK r16b Clang compiler:
* **Toolchain Path**: `/home/novusr/Android/Sdk/ndk/android-ndk-r16b`
* **Compiler**: `$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++`
* **Target Flag Set**:
  ```bash
  -target aarch64-linux-android \
  -std=c++11 \
  -O3 \
  -ffp-contract=fast \
  -fno-math-errno \
  -fno-strict-aliasing \
  -fno-exceptions \
  -fno-rtti \
  -fPIC \
  -Iinclude
  ```

### Critical Flag Rationales:
* `-ffp-contract=fast`: Required to generate AArch64 fused multiply-add/subtract instructions (`fmadd`, `fnmsub`). Without this flag, Clang emits separate `fmul` and `fsub` instructions, failing the match.
* `-fno-math-errno`: Required for math functions like `sqrtf`. Prevents Clang from generating unnecessary stack frames (`stp x29, x30, [sp, #16]`) and fallback library calls (`bl sqrtf`).

---

## 3. AAPCS64 Calling Convention Quirks

Keep these AArch64 ABI characteristics in mind when analyzing decompilation drafts:

1. **Homogeneous Floating-Point Aggregates (HFA)**:
   * Structs containing 1 to 4 floats/doubles (e.g. `CVector` with 3 floats: `x, y, z`) are treated as HFAs.
   * They are passed directly in SIMD/FP registers (`s0..s7`) or vector registers (`v0..v7`).
   * When returned by value, `CVector` is returned directly across `s0`, `s1`, and `s2`. There is NO memory pointer or stack allocation involved.
2. **Callee-Saved Registers**:
   * Registers `x19`–`x28` and `d8`–`d15` are callee-saved.
   * If your compiled function spills to `sp` or uses `x19`, but the original binary only used temporary registers (`x0`–`x7`, `s0`–`s7`, `s16`), adjust variable scopes or expression sequencing to prevent unnecessary register spills.

---

## 4. Step-by-Step Matching Protocol

Follow this exact workflow for each target function:

### Step 1: Claim and Inspect
1. Identify a target function from the todo list (prioritize leaf functions and math utilities first).
2. Query the live Ghidra instance for decompiler output and assembly:
   ```bash
   python3 tools/matcher.py fetch <GHIDRA_HEX_ADDR>
   ```
   *Example*: `python3 tools/matcher.py fetch 006390c8`
3. Note the function signature, mangled symbol name, parameter registers, and return convention.

### Step 2: Declare Types and Headers
1. If the function belongs to a class or operates on structures, declare the types in `include/<Class>.h`.
2. Ensure size and field offsets match the binary with `static_assert`.

### Step 3: Implement in `src/`
1. Write the clean C++11 implementation in `src/<Class>.cpp` (or `src/<Function>.cpp`).
2. Express the mathematical or algorithmic operations cleanly based on Ghidra's decompile and the original PC reference logic if available.

### Step 4: Test and Diff
1. Run the matcher tool to extract the target binary slice, compile your implementation, and run `objdiff-cli`:
   ```bash
   python3 tools/matcher.py test <GHIDRA_HEX_ADDR> --symbol <MANGLED_SYMBOL>
   ```
   *Example*:
   ```bash
   python3 tools/matcher.py test 006390c8 --symbol _ZN7CVector9NormaliseEv
   ```
2. Review the diff report. If mismatch instructions or register allocations appear:
   * Reorder sub-expressions (e.g. `(a * b) + (c * d)` vs `(c * d) + (a * b)`).
   * Check for ternary operator vs `if-else` branching.
   * Check whether constants are float literals (`1.0f`) or double literals (`1.0`).

### Step 5: Verify and Commit
1. Ensure `objdiff-cli` reports `fuzzy_match_percent: 100.0` and `matched_code_percent: 100.0`.
2. Add the unit to `objdiff.json`.
3. Update `docs/PROGRESS.md`.
4. Commit the change with a clear, concise Git commit message (e.g., `decomp: match CVector::Normalise 100%`).
