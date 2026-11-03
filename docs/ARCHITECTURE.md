# Architecture & Memory Layout

This document details the architectural conventions, Application Binary Interface (ABI), and core data structures of the GTA San Andreas 2.10 Android ARM64 target.

---

## 1. Target Architecture & ABI

* **Architecture**: AArch64 (ARMv8-A 64-bit).
* **Endianness**: Little-Endian (LSB).
* **ABI**: Procedure Call Standard for the ARM 64-bit Architecture (AAPCS64).

### Key ABI Rules for Matching:

1. **General Purpose Registers**:
   * `x0`–`x7`: Parameter registers and return values.
   * `x8`: Indirect result location register (structs larger than 16 bytes).
   * `x9`–`x15`: Temporary / scratch registers (caller-saved).
   * `x16`, `x17`: Intra-procedure-call scratch registers (used by PLT and trampolines).
   * `x19`–`x28`: Callee-saved registers. Must be preserved across function calls.
   * `x29`: Frame pointer (FP).
   * `x30`: Link register (LR).
   * `sp`: Stack pointer (must remain 16-byte aligned at all times).

2. **SIMD & Floating-Point Registers**:
   * `v0`–`v7` (or `s0`–`s7`, `d0`–`d7`): Parameter registers and return values.
   * `v8`–`v15`: Callee-saved (lower 64 bits `d8`–`d15` must be preserved).
   * `v16`–`v31`: Temporary / scratch registers.

3. **Homogeneous Floating-Point Aggregates (HFA)**:
   * Any struct consisting of 1 to 4 identical floating-point elements (`float` or `double`) is treated as an HFA.
   * `CVector` (3 floats: `x, y, z`) is an HFA.
   * When passed by value: passed in consecutive registers `s0`, `s1`, `s2`.
   * When returned by value: returned directly in `s0`, `s1`, `s2`.

---

## 2. Core RenderWare & Engine Structures

### A. `CVector` (RenderWare `RwV3d`)
Size: `12` bytes (`0x0C`). Alignment: `4` bytes.
```cpp
struct CVector {
    float x; // offset 0x00
    float y; // offset 0x04
    float z; // offset 0x08
};
static_assert(sizeof(CVector) == 0x0C, "Invalid CVector size");
```

### B. `CMatrix` (RenderWare `RwMatrix`)
Size: `64` bytes (`0x40`). Alignment: `16` bytes (`0x10`).
Each vector component is aligned to 16 bytes with a trailing 4-byte padding/flags field:
```cpp
struct CMatrix {
    CVector      right;    // offset 0x00 (12 bytes)
    unsigned int flags;    // offset 0x0C (4 bytes)
    CVector      up;       // offset 0x10 (12 bytes)
    unsigned int pad1;     // offset 0x1C (4 bytes)
    CVector      at;       // offset 0x20 (12 bytes)
    unsigned int pad2;     // offset 0x2C (4 bytes)
    CVector      pos;      // offset 0x30 (12 bytes)
    unsigned int pad3;     // offset 0x3C (4 bytes)
};
static_assert(sizeof(CMatrix) == 0x40, "Invalid CMatrix size");
```

---

## 3. ELF Section Mapping

In `libGTASA.so`, section `.text` starts at ELF virtual address `0x00231aa0` and ends at `0x0070bd84`.

Because the image base in ELF shared objects matches the file offset:
$$\text{File Offset} = \text{Virtual Address (vaddr)}$$
$$\text{Ghidra Address} = \text{Virtual Address} + 0x100000$$

*Example*:
* Function: `CrossProduct`
* Ghidra Address: `0x00638ec4`
* ELF Virtual Address: `0x00538ec4`
* File Offset in `libGTASA.so`: `0x00538ec4`
