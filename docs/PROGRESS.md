# Verified Matching Progress

This log tracks every function in `libGTASA.so` that has been decompiled and confirmed to produce a **100.0% binary match** against the original binary using `objdiff`.

---

## Overall Statistics

* **Total Code Size in Binary**: ~5,087,972 bytes (`.text` section)
* **Total Functions**: ~24,061
* **Current Matched Functions**: 3
* **Current Matched Code**: 192 bytes (100.0% match across verified units)

---

## Log of Matched Functions

| Unit / Class | Function Signature | Mangled Symbol | ELF Address | Ghidra Address | Size | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `CVector` | `CrossProduct(const CVector&, const CVector&)` | `_Z12CrossProductRK7CVectorS1_` | `0x00538ec4` | `0x00638ec4` | 44 B | **100.0% MATCH** |
| `CMatrix` | `Multiply3x3(const CMatrix&, const CVector&)` | `_Z11Multiply3x3RK7CMatrixRK7CVector` | `0x00538ef0` | `0x00638ef0` | 72 B | **100.0% MATCH** |
| `CVector` | `CVector::Normalise()` | `_ZN7CVector9NormaliseEv` | `0x005390c8` | `0x006390c8` | 76 B | **100.0% MATCH** |

---

## Next Priority Targets (In CVector Block: 0x00538f80 - 0x00539168)

* [ ] `Multiply3x3(const CVector&, const CMatrix&)` (`0x00538f38`, 72 B)
* [ ] `CVector::FromMultiply(const CMatrix&, const CVector&)` (`0x00538f80`, 124 B)
* [ ] `CVector::FromMultiply3X3(const CMatrix&, const CVector&)` (`0x00538ffc`, 112 B)
* [ ] `operator*(const CMatrix&, const CVector&)` (`0x0053906c`, 92 B)
* [ ] `CVector::NormaliseAndMag()` (`0x00539114`, 84 B)
