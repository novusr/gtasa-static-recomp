#!/usr/bin/env bash
set -euo pipefail
: "${CI_WORK_ROOT:?}"
mkdir -p "$CI_WORK_ROOT/sources" "$CI_WORK_ROOT/logs" "$CI_WORK_ROOT/artifacts"
fetch_source() {
  local name="$1" repository="$2" commit="$3"
  local directory="$CI_WORK_ROOT/sources/$name"
  git init -q "$directory"
  git -C "$directory" remote add origin "https://github.com/$repository.git"
  if [[ "$name" == ghidra ]]; then
    git -C "$directory" config core.sparseCheckout true
    mkdir -p "$directory/.git/info"
    printf '%s\n' '/Ghidra/Features/Decompiler/src/decompile/cpp/' '/Ghidra/Processors/' '/LICENSE' '/NOTICE' > "$directory/.git/info/sparse-checkout"
    git -C "$directory" fetch --filter=blob:none --depth=1 origin "$commit"
  else
    git -C "$directory" fetch --depth=1 origin "$commit"
  fi
  git -C "$directory" checkout -q --detach FETCH_HEAD
  test "$(git -C "$directory" rev-parse HEAD)" = "$commit"
  printf '%s %s %s\n' "$name" "$repository" "$commit" >> "$CI_WORK_ROOT/logs/source-pins.txt"
}
fetch_source remill lifting-bits/remill 56918a8c2554088e93389e97d292f4035286506c
fetch_source xed intelxed/xed dc6bdbe036515c7ef55d3b2d50bafc5232bfe534
fetch_source mbuild intelxed/mbuild 7c4497f41f576b43a80bb0f8d8452bbcfd58b6e2
fetch_source sleigh lifting-bits/sleigh 7c6b7424467d0382a1303c278633e99b0d094d5b
fetch_source ghidra NationalSecurityAgency/ghidra 80ccdadeba79cd42fb0b85796b55952e0f79f323
fetch_source gflags gflags/gflags 52e94563eba1968783864942fedf6e87e3c611f4
fetch_source glog google/glog 7b134a5c82c0c0b5698bb6bf7a835b230c5638e4
# Materialize every selected sparse-source blob while acquisition is online.
# Build will run in a network namespace with no network interfaces.
find "$CI_WORK_ROOT/sources/ghidra/Ghidra" -type f -exec cat {} + > /dev/null
python3 - <<'PY'
import hashlib,json,os
from pathlib import Path
root=Path(os.environ['CI_WORK_ROOT'])
patches=sorted((root/'sources/sleigh/src/patches/HEAD').glob('*.patch'))+sorted((root/'sources/remill/dependencies/sleigh_patches').glob('*.patch'))
(root/'logs/patch-hashes.json').write_text(json.dumps({str(p.relative_to(root/'sources')):hashlib.sha256(p.read_bytes()).hexdigest() for p in patches},indent=2)+'\n')
PY
