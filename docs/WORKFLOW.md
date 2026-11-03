# Decompilation Workflow Guide

This document outlines the standard operational procedure for deconstructing and matching functions in `libGTASA.so`.

---

## 1. Prerequisites

1. Ensure the Ghidra GUI instance is running with `libGTASA.so` analyzed and the MCP/HTTP server listening on port `8089`:
   ```bash
   curl -s http://127.0.0.1:8089/ -I
   # Expected: HTTP/1.1 404 Not Found (server is alive)
   ```
2. Verify that Android NDK r16b is located at `/home/novusr/Android/Sdk/ndk/android-ndk-r16b`.
3. Verify that `objdiff-cli` is accessible in PATH:
   ```bash
   objdiff-cli --version
   ```

---

## 2. The Iterative Matching Loop

```text
[1. Fetch from Ghidra] ──> [2. Write C++ in src/] ──> [3. Test with matcher.py]
                                                                  │
                                                        [4. 100% Match?]
                                                           ├── Yes ──> [Commit & Log]
                                                           └── No  ──> [Refine AST/Math]
```

### Step 1: Query Function Details
Run `tools/matcher.py fetch` with the target's Ghidra hex address:
```bash
python3 tools/matcher.py fetch 006390c8
```
This prints:
* Function name and mangled symbol.
* Ghidra's decompiler draft.
* Exact AArch64 disassembly with address offsets.

### Step 2: Write or Update C++
Locate or create the implementation file in `src/<Unit>.cpp`. Ensure all referenced structures are declared in `include/<Class>.h`.

### Step 3: Run the Matcher Test
Run:
```bash
python3 tools/matcher.py test <GHIDRA_ADDR> --symbol <MANGLED_SYMBOL>
```
The script will automatically:
1. Extract the exact byte slice from `libGTASA.so` into `expected/<Unit>.bin` and wrap it into `expected/<Unit>.o`.
2. Compile your `src/<Unit>.cpp` into `build/<Unit>.o` using NDK r16b Clang with calibrated flags.
3. Invoke `objdiff-cli` and output diff results.

---

## 3. Troubleshooting Common Diff Issues

### Issue 1: Register Allocation Mismatch
* **Symptom**: `objdiff` shows matching instructions (`fmul`, `fadd`), but registers are swapped (e.g. `s0, s1` instead of `s1, s0`).
* **Fix**: Reorder commutative operations in C++. If `a * b + c * d` produced the reverse register order, try `c * d + a * b` or store intermediate sub-expressions in local variables.

### Issue 2: Spurious Stack Frames (`stp x29, x30, [sp, #-16]!`)
* **Symptom**: A leaf function emits prologue/epilogue stack frame instructions that do not exist in the original binary.
* **Causes**:
  * Missing `-fno-math-errno` flag when calling `sqrtf`.
  * Passing a non-trivial struct by value that does not satisfy HFA conditions.
  * Inadvertently creating a local variable whose address is taken (`&var`).

### Issue 3: Inlining Discrepancies
* **Symptom**: The function calls an external sub-function that was supposed to be inlined, or vice versa.
* **Fix**: Use `inline` or `__attribute__((always_inline))` / `__attribute__((noinline))` on helper methods.
