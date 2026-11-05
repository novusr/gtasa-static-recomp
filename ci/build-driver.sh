#!/usr/bin/env bash
set -euo pipefail
: "${CI_WORK_ROOT:?}" "${CI_PREFIX:?}" "${CI_SCRIPTS:?}"
export CC=/usr/bin/clang-21 CXX=/usr/bin/clang++-21
cmake -S "$CI_SCRIPTS/driver" -B "$CI_WORK_ROOT/build/driver" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$CI_PREFIX;$CI_PREFIX/xed" \
  -DLLVM_DIR=/usr/lib/llvm-21/lib/cmake/llvm
cmake --build "$CI_WORK_ROOT/build/driver" --parallel 2
"$CI_WORK_ROOT/build/driver/proof-lift" --toolchain-check
mkdir -p "$CI_WORK_ROOT/driver-artifacts"
cp "$CI_WORK_ROOT/build/driver/proof-lift" "$CI_WORK_ROOT/driver-artifacts/"
cp "$CI_SCRIPTS/driver/lift.cpp" "$CI_SCRIPTS/driver/CMakeLists.txt" "$CI_WORK_ROOT/driver-artifacts/"
(cd "$CI_WORK_ROOT/driver-artifacts" && sha256sum proof-lift lift.cpp CMakeLists.txt > SHA256SUMS)
ldd "$CI_WORK_ROOT/driver-artifacts/proof-lift" > "$CI_WORK_ROOT/logs/driver-ldd.txt"
