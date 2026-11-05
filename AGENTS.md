# Contributor Guidelines — Static Recompilation

This branch targets GTA:SA 2.10 Android ARM64 machine code recompiled ahead of
time for Linux x86_64. The byte-matching decompilation remains on `main`.

## Rules

- Work in this worktree only. Do not stop or change the decompdecomp agents in
  the original worktree. Do not point those agents at this branch.
- Guest instruction semantics and runtime behavior are the correctness gates.
  Host x86_64 bytes are not expected to match guest ARM64 bytes. objdiff scores
  are not static recompilation progress.
- Keep `src/` and `include/` standard C++11. Use fixed-width integers, explicit
  guest addresses and checked guest memory. Guest pointers are never host pointers.
- Assert the sizes and offsets of runtime state structures. Never use inline
  assembly, raw opcode injection, or host casts to emulate guest pointer access.
- Emit code ahead of time; do not add an interpreter or JIT fallback silently.
  Reject every unsupported instruction and addressing mode before writing output.
- Never invent an import's behavior or silently replace it with a success stub.
- No game binaries, assets, lifted output or credentials in Git. Inputs and
  generated files are ignored. No emojis in source, comments, commits or logs.
- Preserve existing documentation/comments unless the task explicitly changes
  them. Historical byte-matching material is available in `main` and Git history.

## Workflow

1. `uv sync --locked` installs the pinned analysis dependencies.
2. `uv run python tools/recomp.py inspect --output generated/inventory.json`
   validates the configured ELF and inventories segments, symbols and relocations.
3. `uv run python tools/recomp.py lift --output generated` validates and lifts
   the explicitly selected functions. Ghidra may clarify control flow and types;
   original ELF bytes and ISA semantics remain authoritative.
4. `cmake -S . -B build -G Ninja && cmake --build build`
5. `ctest --test-dir build --output-on-failure`
6. `uv run python -m unittest discover -s tests -p 'test_*.py'`

Run checks relevant to any change. Extending instruction support requires semantic
and rejection tests. Report the supported subset and unresolved platform work
honestly; the leaf-function demo is not the game.
