#!/usr/bin/env bash
set -euo pipefail
: "${CI_WORK_ROOT:?}" "${CI_PREFIX:?}"
export CC=/usr/bin/clang-21 CXX=/usr/bin/clang++-21
export CMAKE_BUILD_PARALLEL_LEVEL=2
src="$CI_WORK_ROOT/sources"
bld="$CI_WORK_ROOT/build"
mkdir -p "$bld" "$CI_PREFIX"
# Only public upstream patches, applied in the same order as the pinned recipe.
mapfile -t ghidra_patches < <(find "$src/sleigh/src/patches/HEAD" -name '*.patch' -print | sort)
mapfile -t remill_patches < <(find "$src/remill/dependencies/sleigh_patches" -name '*.patch' -print | sort)
git -C "$src/ghidra" -c user.name='Toolchain CI' -c user.email='toolchain-ci@users.noreply.github.com' am --ignore-space-change --ignore-whitespace --no-gpg-sign "${ghidra_patches[@]}" "${remill_patches[@]}"
git -C "$src/ghidra" log --format='%H %s' --max-count=16 > "$CI_WORK_ROOT/logs/ghidra-patched-history.txt"
common=(-G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$CI_PREFIX" -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_PREFIX_PATH="$CI_PREFIX;$CI_PREFIX/xed" -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_SHARED_LIBS=OFF)
cmake -S "$src/gflags" -B "$bld/gflags" "${common[@]}" -DBUILD_TESTING=OFF -DBUILD_STATIC_LIBS=ON
cmake --build "$bld/gflags" --parallel 2
cmake --install "$bld/gflags"
cmake -S "$src/glog" -B "$bld/glog" "${common[@]}" -DBUILD_TESTING=OFF -DWITH_UNWIND=OFF -DWITH_GFLAGS=ON
cmake --build "$bld/glog" --parallel 2
cmake --install "$bld/glog"
# XED replaces its kit destination; isolate it from the other dependencies.
# Its own builder uses the sibling mbuild checkout; no CMake superbuild.
(cd "$src/xed" && python3 mfile.py install --install-dir="$CI_PREFIX/xed" --cc="$CC" --cxx="$CXX" --compiler=clang --static --extra-ccflags=-fPIC --extra-cxxflags=-fPIC -j2)
mkdir -p "$CI_PREFIX/xed/lib/cmake/XED"
cp "$src/remill/dependencies/XEDConfig.cmake.in" "$CI_PREFIX/xed/lib/cmake/XED/XEDConfig.cmake"
# FetchContent is supplied complete local source overrides. Network is disabled
# for this entire script; no superbuild or automatic source acquisition runs.
cmake -S "$src/remill" -B "$bld/remill" "${common[@]}" \
  -DLLVM_DIR=/usr/lib/llvm-21/lib/cmake/llvm \
  -DREMILL_ENABLE_TESTING=OFF -DREMILL_BUILD_SPARC32_RUNTIME=OFF \
  -DFETCHCONTENT_SOURCE_DIR_SLEIGH="$src/sleigh" \
  -DFETCHCONTENT_SOURCE_DIR_GHIDRASOURCE="$src/ghidra" \
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON -DFETCHCONTENT_UPDATES_DISCONNECTED=ON \
  -Dsleigh_BUILD_EXAMPLE=OFF -Dsleigh_BUILD_EXTRATOOLS=OFF
cmake --build "$bld/remill" --parallel 2
cmake --install "$bld/remill"
# Synthetic RET smoke exercises toolchain lifting only; no GTA bytes are present.
"$CI_PREFIX/bin/remill-lift-21" --arch aarch64 --ir_out "$CI_WORK_ROOT/logs/synthetic-ret.ll" --address 0x1000 --bytes c0035fd6
/usr/lib/llvm-21/bin/opt -passes=verify -disable-output "$CI_WORK_ROOT/logs/synthetic-ret.ll"
# Verify installed CMake exports can build a separate custom API consumer.
cmake -S "$CI_SCRIPTS/consumer" -B "$bld/consumer" "${common[@]}" -DLLVM_DIR=/usr/lib/llvm-21/lib/cmake/llvm
cmake --build "$bld/consumer" --parallel 2
"$bld/consumer/remill-installed-consumer" | tee "$CI_WORK_ROOT/logs/installed-consumer.txt"
# Include dependencies and their notices in the experimental prefix.
mkdir -p "$CI_PREFIX/share/toolchain-proof/notices"
cp -r "$CI_SCRIPTS/consumer" "$CI_PREFIX/share/toolchain-proof/consumer"
for name in remill xed mbuild sleigh ghidra gflags glog; do
  mkdir -p "$CI_PREFIX/share/toolchain-proof/notices/$name"
  while IFS= read -r -d '' f; do cp "$f" "$CI_PREFIX/share/toolchain-proof/notices/$name/"; done < <(find "$src/$name" -maxdepth 1 -type f \( -iname 'license*' -o -iname 'copying*' -o -iname 'notice*' -o -iname 'copyright*' \) -print0)
done
cp "$CI_WORK_ROOT/logs/source-pins.txt" "$CI_WORK_ROOT/logs/patch-hashes.json" "$CI_PREFIX/share/toolchain-proof/"
ldd "$CI_PREFIX/bin/remill-lift-21" > "$CI_WORK_ROOT/logs/remill-lift-ldd.txt"
if grep -q 'not found' "$CI_WORK_ROOT/logs/remill-lift-ldd.txt"; then exit 1; fi
# Keep the build/install prefix exactly the same path on the eventual local host;
# private semantics-location constants may embed it. No system install locally.
python3 - <<'PY'
import hashlib,json,os,platform,subprocess
from pathlib import Path
root=Path(os.environ['CI_WORK_ROOT']);p=Path(os.environ['CI_PREFIX'])
files={str(f.relative_to(p)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(p.rglob('*')) if f.is_file() and not f.is_symlink()}
manifest={'remill_commit':'56918a8c2554088e93389e97d292f4035286506c','prefix':str(p),'llvm':subprocess.check_output(['/usr/lib/llvm-21/bin/llvm-config','--version'],text=True).strip(),'platform':platform.platform(),'source_pins':(root/'logs/source-pins.txt').read_text(),'file_sha256':files,'scope':'toolchain acquisition only; no game input or target lifting','synthetic_ret_lift':'passed','network_during_build':'disabled by network namespace'}
(p/'share/toolchain-proof/manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
(root/'artifacts/manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
PY
tar -C "$CI_PREFIX" -czf "$CI_WORK_ROOT/artifacts/remill-llvm21-toolchain.tar.gz" .
(cd "$CI_WORK_ROOT/artifacts" && sha256sum remill-llvm21-toolchain.tar.gz > SHA256SUMS)
