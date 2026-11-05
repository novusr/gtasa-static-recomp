# Isolated Remill LLVM21 toolchain acquisition

This CI-only branch builds pinned public open-source toolchain dependencies.
It contains no GTA executable, assets, target bytes, generated game code, or
production backend implementation. Source acquisition is explicit; compilation
runs in a network namespace without external networking and never invokes the
upstream dependency superbuild. A synthetic RET is lifted as a toolchain smoke
check. Passing CI is not semantic verification of the GTA target.

The private repository's standard Actions runner is used for at most 60 minutes
per run. Artifacts expire after one day. No billing settings are changed.
The install prefix is an ignored experimental path matching the local worktree;
no local system installation is intended.
